"use strict";
/**
 * Live cache test exercising lib/cache.js with both backends:
 *   - memory  — pure in-process, no docker dependency, but live to
 *               confirm the framework's primitives don't drift
 *   - cluster — operator-supplied backend object built on top of
 *               lib/redis-client against the docker Redis fixture
 *
 * The cluster backend wires Redis through the operator-facing API the
 * framework documents — get / set / delete / etc — so this catches the
 * same drift a real production-Redis-backed cache would.
 */
var helpers = require("../helpers");
var check = helpers.check;
var services = require("../helpers/services");
var redisClient = require("../../lib/redis-client");
var b = require("../../");

function _redisClusterBackend(client, namespace) {
  // Operator-supplied "cluster" backend shape per lib/cache.js docs:
  //   get(key, opts?) -> Promise<value | undefined>
  //   set(key, value, opts?) -> Promise<void>
  //   delete(key, opts?) -> Promise<void>
  //   has(key) -> Promise<boolean>
  //   clear() -> Promise<void>
  //   close() -> Promise<void>
  // Values stored as Buffer; ttlMs honored via Redis PEXPIRE.
  function _k(key) { return namespace + ":" + key; }
  return {
    get: async function (key) {
      var v = await client.command("GET", _k(key));
      if (v === null || v === undefined) return undefined;
      var s = Buffer.isBuffer(v) ? v.toString("utf8") : String(v);
      // Round-trip arbitrary JS values via JSON, matching the framework's
      // built-in _clusterBackend pattern.
      try { return JSON.parse(s); }
      catch (_e) { return undefined; }
    },
    set: async function (key, value, expiresAt, meta) {
      var json = JSON.stringify(value);
      // The framework's cache passes expiresAt (absolute epoch ms) when it
      // wants ttl honored, Infinity when no TTL. Translate into PX ms.
      if (typeof expiresAt === "number" && isFinite(expiresAt)) {
        var ttlMs = expiresAt - Date.now();
        if (ttlMs > 0) {
          await client.command("SET", _k(key), json, "PX", String(Math.floor(ttlMs)));
          return;
        }
      }
      await client.command("SET", _k(key), json);
    },
    del: async function (key) {
      await client.command("DEL", _k(key));
    },
    clear: async function () {
      var cursor = "0";
      do {
        var rv = await client.command("SCAN", cursor, "MATCH", namespace + ":*", "COUNT", "200");
        cursor = Buffer.isBuffer(rv[0]) ? rv[0].toString("utf8") : String(rv[0]);
        var keys = (rv[1] || []).map(function (k) {
          return Buffer.isBuffer(k) ? k.toString("utf8") : String(k);
        });
        if (keys.length > 0) await client.command.apply(client, ["DEL"].concat(keys));
      } while (cursor !== "0");
    },
    size: async function () {
      // Best-effort size — SCAN-and-count.
      var cursor = "0";
      var n = 0;
      do {
        var rv = await client.command("SCAN", cursor, "MATCH", namespace + ":*", "COUNT", "200");
        cursor = Buffer.isBuffer(rv[0]) ? rv[0].toString("utf8") : String(rv[0]);
        n += (rv[1] || []).length;
      } while (cursor !== "0");
      return n;
    },
    close: async function () { /* outer cache's close handles client */ },
  };
}

async function run() {
  // ---- memory backend ----
  var mem = b.cache.create({
    backend:    "memory",
    namespace:  "test-mem",
    ttlMs:      60000,
    maxEntries: 1000,
  });
  await mem.set("k1", "v1");
  check("memory: set + get round-trip",
        (await mem.get("k1")) === "v1");
  check("memory: has returns true",
        (await mem.has("k1")) === true);
  await mem.del("k1");
  check("memory: del removes key",
        (await mem.get("k1")) === undefined);
  check("memory: has returns false post-delete",
        (await mem.has("k1")) === false);

  // wrap (memoize): sees cache-miss, calls fn, second call skips fn
  var calls = 0;
  var fn = function () { calls += 1; return "computed"; };
  var v1 = await mem.wrap("memo", fn);
  var v2 = await mem.wrap("memo", fn);
  check("memory: wrap cache-miss invokes fn",  v1 === "computed");
  check("memory: wrap cache-hit reuses value", v2 === "computed" && calls === 1);

  // tag invalidation
  await mem.set("a", "1", { tags: ["group-x"] });
  await mem.set("b", "2", { tags: ["group-x"] });
  await mem.set("c", "3", { tags: ["group-y"] });
  await mem.invalidateTag("group-x");
  check("memory: invalidateTag drops tagged entries",
        (await mem.get("a")) === undefined && (await mem.get("b")) === undefined);
  check("memory: invalidateTag preserves untagged-other entries",
        (await mem.get("c")) === "3");

  await mem.close();

  // ---- cluster backend (Redis-backed) ----
  var svc = await services.requireService("redis");
  if (!svc.ok) throw new Error("redis unreachable: " + svc.reason);
  var client = redisClient.create({ url: svc.url + "/14" });
  await client.connect();
  var ns = "blamejs:test-cache:" + Date.now();
  var clusterBackend = _redisClusterBackend(client, ns);
  var cluster = b.cache.create({
    backend:   clusterBackend,
    namespace: "test-cluster",
    ttlMs:     60000,
  });

  await cluster.set("k1", "v-from-cluster");
  var got = await cluster.get("k1");
  check("cluster: set + get round-trip through Redis",
        got === "v-from-cluster");
  check("cluster: has returns true",
        (await cluster.has("k1")) === true);
  await cluster.del("k1");
  check("cluster: del removes key (verified through Redis)",
        (await cluster.get("k1")) === undefined);

  // ttl honored — Redis PEXPIRE actually expires
  await cluster.set("ttlk", "expires-soon", { ttlMs: 200 });
  check("cluster: short-ttl set works",
        (await cluster.get("ttlk")) === "expires-soon");
  await new Promise(function (res) { setTimeout(res, 350); });
  check("cluster: post-ttl get returns undefined (Redis expired the key)",
        (await cluster.get("ttlk")) === undefined);

  // wrap also works through cluster
  var clusterCalls = 0;
  var clusterFn = function () { clusterCalls += 1; return "from-fn"; };
  var cv1 = await cluster.wrap("memo", clusterFn);
  var cv2 = await cluster.wrap("memo", clusterFn);
  check("cluster: wrap cache-miss invokes fn",  cv1 === "from-fn");
  check("cluster: wrap cache-hit reuses through Redis", cv2 === "from-fn" && clusterCalls === 1);

  // cleanup
  await clusterBackend.clear();
  await cluster.close();
  await client.close();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); process.exit(0); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
