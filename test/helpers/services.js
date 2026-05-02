"use strict";
/**
 * Service config + readiness helpers for integration tests that
 * connect to the docker-compose.test.yml stack.
 *
 * The compose file owns the deterministic ports and credentials;
 * this module mirrors them so tests have a single source of truth
 * without re-reading YAML. Operators running their own infra can
 * override any URL via BLAMEJS_<SVC>_URL env vars.
 *
 * Public API:
 *   var svcs = require("./services");
 *
 *   svcs.URLS.redis           // "redis://127.0.0.1:6379"
 *   svcs.URLS.postgres        // "postgres://blamejs:blamejs_test@127.0.0.1:5432/blamejs_test"
 *   svcs.URLS.mysql, .mongodb, .minio, .rabbitmq, .nats, .syslog
 *
 *   await svcs.requireService("redis")
 *     // { ok: true, url, host, port }
 *     // { ok: false, reason } when unreachable
 *
 *   await svcs.requireAll()
 *     // throws when any service is unreachable, with a concise list
 *
 * Test-side usage pattern:
 *   var svc = await svcs.requireService("redis");
 *   if (!svc.ok) {
 *     console.log("[skip] redis: " + svc.reason);
 *     return;
 *   }
 *   // svc.url is safe to pass to b.redisClient.create({ url: ... }) etc.
 */
var net = require("node:net");

var DEFAULTS = {
  redis:    "redis://127.0.0.1:6379",
  postgres: "postgres://blamejs:blamejs_test@127.0.0.1:5432/blamejs_test",
  mysql:    "mysql://blamejs:blamejs_test@127.0.0.1:3306/blamejs_test",
  mongodb:  "mongodb://blamejs:blamejs_test@127.0.0.1:27017/?authSource=admin",
  minio:    "http://blamejs:blamejs_test_password@127.0.0.1:9000",
  rabbitmq: "amqp://blamejs:blamejs_test@127.0.0.1:5672",
  nats:     "nats://127.0.0.1:4222",
  syslog:   "tcp://127.0.0.1:5514",
};

function _envOverride(name) {
  var key = "BLAMEJS_" + name.toUpperCase() + "_URL";
  var v = process.env[key];
  return (typeof v === "string" && v.length > 0) ? v : null;
}

var URLS = {};
Object.keys(DEFAULTS).forEach(function (name) {
  URLS[name] = _envOverride(name) || DEFAULTS[name];
});

// Parse a URL down to { host, port } for TCP probing without hauling
// in node:url quirks for non-standard schemes (amqp:, nats:, etc.).
function _hostPort(name, urlStr) {
  // Cheap regex over the authority section — enough for fixture URLs
  // we own. Anything weirder belongs in a per-service parser.
  var m = /^[a-z][a-z0-9+.-]*:\/\/(?:[^@/]*@)?([^/:?#]+)(?::(\d+))?/i.exec(urlStr);
  if (!m) {
    return { ok: false, reason: "services: cannot parse URL for " + name + ": " + urlStr };
  }
  var host = m[1];
  var port = m[2] ? Number(m[2]) : _defaultPort(urlStr);
  if (!Number.isFinite(port)) {
    return { ok: false, reason: "services: no port for " + name + " in " + urlStr };
  }
  return { ok: true, host: host, port: port };
}

function _defaultPort(urlStr) {
  if (urlStr.indexOf("redis://")    === 0) return 6379;
  if (urlStr.indexOf("rediss://")   === 0) return 6379;
  if (urlStr.indexOf("postgres://") === 0) return 5432;
  if (urlStr.indexOf("mysql://")    === 0) return 3306;
  if (urlStr.indexOf("mongodb://")  === 0) return 27017;
  if (urlStr.indexOf("amqp://")     === 0) return 5672;
  if (urlStr.indexOf("nats://")     === 0) return 4222;
  if (urlStr.indexOf("http://")     === 0) return 80;
  if (urlStr.indexOf("https://")    === 0) return 443;
  if (urlStr.indexOf("tcp://")      === 0) return null;
  return null;
}

function _probeTcp(host, port, timeoutMs) {
  return new Promise(function (resolve) {
    var sock = net.connect({ host: host, port: port });
    var done = false;
    var timer = setTimeout(function () {
      if (done) return;
      done = true;
      try { sock.destroy(); } catch (_e) {}
      resolve({ ok: false, reason: "tcp connect timeout after " + timeoutMs + "ms" });
    }, timeoutMs);
    sock.once("connect", function () {
      if (done) return;
      done = true;
      clearTimeout(timer);
      try { sock.end(); } catch (_e) {}
      resolve({ ok: true });
    });
    sock.once("error", function (err) {
      if (done) return;
      done = true;
      clearTimeout(timer);
      var msg = (err && err.code) || (err && err.message) || String(err);
      resolve({ ok: false, reason: "tcp connect failed: " + msg });
    });
  });
}

async function requireService(name, opts) {
  opts = opts || {};
  var timeoutMs = Number(opts.timeoutMs) || 2000;
  var url = URLS[name];
  if (!url) {
    return { ok: false, reason: "services: unknown service '" + name +
      "' (valid: " + Object.keys(URLS).join(", ") + ")" };
  }
  var hp = _hostPort(name, url);
  if (!hp.ok) return hp;
  var probe = await _probeTcp(hp.host, hp.port, timeoutMs);
  if (!probe.ok) {
    return { ok: false, reason: name + " unreachable at " + hp.host + ":" + hp.port +
      " (" + probe.reason + ")", url: url, host: hp.host, port: hp.port };
  }
  return { ok: true, url: url, host: hp.host, port: hp.port };
}

async function requireAll(opts) {
  var names = Object.keys(URLS);
  var results = await Promise.all(names.map(function (n) {
    return requireService(n, opts).then(function (r) { return { name: n, result: r }; });
  }));
  var failed = results.filter(function (r) { return !r.result.ok; });
  if (failed.length === 0) return results.map(function (r) { return r.result; });
  var msg = "services: " + failed.length + " of " + names.length + " unreachable: " +
    failed.map(function (f) { return f.name + " (" + f.result.reason + ")"; }).join("; ") +
    " — bring the stack up with `docker compose -f docker-compose.test.yml up --wait`";
  var err = new Error(msg);
  err.code = "BLAMEJS_SERVICES_UNREACHABLE";
  err.failed = failed.map(function (f) { return f.name; });
  throw err;
}

module.exports = {
  URLS:           URLS,
  DEFAULTS:       DEFAULTS,
  requireService: requireService,
  requireAll:     requireAll,
};
