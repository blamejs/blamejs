// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The Redis client refuses a compromised key: a `redisCa` / `ca` holding a
 * certificate with a compromised key is refused when b.cache or b.pubsub is
 * configured, and a server whose verified chain carries a
 * compromised key fails the connection with redis-client/compromised-key
 * before any command (AUTH included) is written. The loopback servers present
 * a chain whose intermediate's private key is 1; the control chain differs
 * only in that key.
 *
 * A compromised anchor in the default CA store is refused even when the
 * server sends a decoy in its place, a `redisCa` is screened under every PEM
 * label OpenSSL trusts, and a `redisCa` with no certificate in it is accepted
 * as node accepts it.
 */

var helpers  = require("../helpers");
var check    = helpers.check;
var b        = helpers.b;
var nodeTls  = require("node:tls");
var ck       = require("../helpers/compromised-keys");
var anchors  = require("../helpers/compromised-anchor");

var COMPROMISED_CA = ck.certPem(ck.P384_COMPROMISED_CA_DER);
var CONTROL_CA     = ck.certPem(ck.P384_CONTROL_CA_DER);

function _code(fn) {
  try { fn(); return "NO-THROW"; } catch (e) { return e.code || e.message; }
}

function _startRedis(which) {
  var chain = typeof which === "string" ? ck.tlsChain(which) : which;
  var handle = { bytes: 0, received: "" };
  return new Promise(function (resolve) {
    var srv = nodeTls.createServer({ key: chain.key, cert: chain.cert }, function (sock) {
      sock.on("error", function () { /* the client tears down on refusal */ });
      sock.on("data", function (chunk) {
        handle.bytes += chunk.length;
        handle.received += chunk.toString("latin1");
        sock.write("$-1\r\n");
      });
    });
    srv.on("error", function () { /* fixture best-effort */ });
    srv.on("tlsClientError", function () { /* the client refused the chain */ });
    srv.listen(0, "127.0.0.1", function () {
      handle.server = srv;
      handle.port = srv.address().port;
      handle.rootCa = chain.rootCa;
      resolve(handle);
    });
  });
}

function _cacheOpts(port, ca) {
  return {
    backend: "redis", namespace: "ck",
    redisUrl: "rediss://:s3cret@127.0.0.1:" + port, redisServername: "localhost",
    redisCa: ca, redisMaxReconnectAttempts: 0, redisConnectTimeoutMs: 4000,
  };
}

function testConfigRefusesCompromisedCa() {
  var cacheCtl = null;
  check("redis compromised ca control: b.cache.create accepts a redisCa bundle with an ordinary CA",
        _code(function () { cacheCtl = b.cache.create(_cacheOpts(1, [CONTROL_CA])); }) === "NO-THROW");
  if (cacheCtl) cacheCtl.close().catch(function () { /* never connected */ });
  check("redis compromised ca: b.cache.create refuses a redisCa bundle holding a CA whose private key is 1",
        _code(function () { b.cache.create(_cacheOpts(1, [CONTROL_CA, COMPROMISED_CA])); }) ===
          "redis-client/compromised-key");

  var psCtl = null;
  check("redis compromised ca control: b.pubsub.create accepts an ordinary redisCa",
        _code(function () {
          psCtl = b.pubsub.create({ backend: "redis", redisUrl: "rediss://127.0.0.1:1", redisCa: CONTROL_CA });
        }) === "NO-THROW");
  if (psCtl) psCtl.close().catch(function () { /* never connected */ });
  check("redis compromised ca: b.pubsub.create refuses a redisCa that is the listed eDellRoot certificate",
        _code(function () {
          b.pubsub.create({ backend: "redis", redisUrl: "rediss://127.0.0.1:1", redisCa: ck.EDELLROOT_CERT_PEM });
        }) === "redis-client/compromised-key");
}

async function testConnectionRefusesCompromisedChain() {
  var ctl = await _startRedis("control");
  var cache = b.cache.create(_cacheOpts(ctl.port, ctl.rootCa));
  var okErr = null;
  var okVal = "unset";
  try { okVal = await cache.get("k"); } catch (e) { okErr = e; }
  await cache.close();
  ctl.server.close();
  check("redis compromised chain control: b.cache reads through a chain of ordinary keys",
        okErr === null && okVal === undefined && ctl.received.indexOf("s3cret") !== -1 &&
          ctl.received.indexOf("ck:e:k") !== -1,
        okErr && (okErr.code + " " + okErr.message));

  var bad = await _startRedis("compromised");
  var badCache = b.cache.create(_cacheOpts(bad.port, bad.rootCa));
  var code = "NO-THROW";
  try { await badCache.get("k"); } catch (e) { code = e.code || e.message; }
  await badCache.close();
  bad.server.close();
  check("redis compromised chain: the connection fails with redis-client/compromised-key and no AUTH is sent",
        code === "redis-client/compromised-key" && bad.bytes === 0, code + " bytes=" + bad.bytes);
}

function _createCode(ca) {
  var cache = null;
  var code = _code(function () { cache = b.cache.create(_cacheOpts(1, ca)); });
  if (cache) cache.close().catch(function () { /* never connected */ });
  return code;
}

function testConfigReadsEveryCertificateLabel() {
  var bad = anchors.caLabels(ck.P384_COMPROMISED_CA_DER);
  var ok = anchors.caLabels(ck.P384_CONTROL_CA_DER);
  Object.keys(bad).forEach(function (label) {
    check("redis ca label control: b.cache.create accepts an ordinary redisCa under the " + label + " label",
          _createCode(ok[label]) === "NO-THROW");
    check("redis ca label: b.cache.create refuses a redisCa whose private key is 1 under the " + label + " label",
          _createCode([CONTROL_CA, bad[label]]) === "redis-client/compromised-key");
  });
}

function testConfigAcceptsACaWithoutACertificate() {
  [["an empty Buffer", Buffer.alloc(0)], ["a Buffer of comments", Buffer.from("# no certificate here\n")]]
    .forEach(function (f) {
      check("redis ca without a certificate: b.cache.create accepts " + f[0] + " as node does",
            _createCode(f[1]) === "NO-THROW");
    });
}

async function testDecoyForACompromisedDefaultAnchorIsRefused() {
  for (var w = 0; w < 2; w += 1) {
    var which = w === 0 ? "control" : "compromised";
    var chain = anchors.decoyChain(which);
    var srv = await _startRedis(chain);
    var outcome = await anchors.withDefaultAnchor(chain.anchor, async function () {
      var cache = b.cache.create(_cacheOpts(srv.port, undefined));
      var result;
      try { result = (await cache.get("k")) === undefined ? "read" : "unexpected-value"; }
      catch (e) { result = (e.code || "no-code") + ": " + e.message; }
      await cache.close();
      return result;
    });
    srv.server.close();
    if (which === "control") {
      check("redis default-store anchor control: b.cache reads through an ordinary anchor",
            outcome === "read" && srv.received.indexOf("s3cret") !== -1, outcome);
    } else {
      check("redis default-store anchor: an anchor whose private key is 1 is not trusted, so a server that sends " +
            "a decoy for it fails certificate verification with redis-client/connect and no AUTH is sent",
            outcome.indexOf("redis-client/connect: ") === 0 && /certificate/i.test(outcome) && srv.bytes === 0,
            outcome + " bytes=" + srv.bytes);
    }
  }
}

function _queueBackend(port, ca) {
  return {
    protocol: "redis", url: "rediss://:s3cret@127.0.0.1:" + port, servername: "localhost", ca: ca,
    maxReconnectAttempts: 0, connectTimeoutMs: 4000,
    retry: { maxAttempts: 1 },
  };
}

async function _queueOutcome(port, ca, enqueue) {
  var code = _code(function () { b.queue.init({ backends: { r: _queueBackend(port, ca) }, sweepIntervalMs: 0 }); });
  if (code === "NO-THROW" && enqueue) {
    try { await b.queue.enqueue("ck-q", { n: 1 }, { backend: "r" }); code = "enqueued"; }
    catch (e) { code = e.code || e.message; }
  }
  try { await b.queue.shutdown({ timeoutMs: 500 }); } catch (_e) { /* never connected */ }
  b.queue._resetForTest();
  return code;
}

async function testQueueRedisBackendRefusesCompromisedKey() {
  var tmpDir = helpers.fs.mkdtempSync(helpers.path.join(helpers.os.tmpdir(), "blamejs-q-ck-"));
  await helpers.setupTestDb(tmpDir);
  try {
    check("redis queue compromised ca control: b.queue.init accepts a redis backend ca bundle with an ordinary CA",
          await _queueOutcome(1, [CONTROL_CA], false) === "NO-THROW");
    check("redis queue compromised ca: b.queue.init refuses a redis backend ca bundle holding a CA whose private " +
          "key is 1",
          await _queueOutcome(1, [CONTROL_CA, COMPROMISED_CA], false) === "redis-client/compromised-key");

    var ctl = await _startRedis("control");
    var ok = await _queueOutcome(ctl.port, ctl.rootCa, true);
    ctl.server.close();
    check("redis queue compromised chain control: an enqueue reaches a server with a chain of ordinary keys",
          ctl.received.indexOf("s3cret") !== -1, ok + " received=" + JSON.stringify(ctl.received.slice(0, 60)));

    var bad = await _startRedis("compromised");
    var code = await _queueOutcome(bad.port, bad.rootCa, true);
    bad.server.close();
    check("redis queue compromised chain: an enqueue to a server whose chain carries a compromised key fails with " +
          "redis-client/compromised-key and no AUTH is sent",
          code === "redis-client/compromised-key" && bad.bytes === 0, code + " bytes=" + bad.bytes);
  } finally {
    await helpers.teardownTestDb(tmpDir);
  }
}

async function run() {
  testConfigRefusesCompromisedCa();
  testConfigReadsEveryCertificateLabel();
  testConfigAcceptsACaWithoutACertificate();
  await testConnectionRefusesCompromisedChain();
  await testDecoyForACompromisedDefaultAnchorIsRefused();
  await testQueueRedisBackendRefusesCompromisedKey();
}

module.exports = {
  run:                                   run,
  testConfigRefusesCompromisedCa:        testConfigRefusesCompromisedCa,
  testConfigReadsEveryCertificateLabel:  testConfigReadsEveryCertificateLabel,
  testConfigAcceptsACaWithoutACertificate: testConfigAcceptsACaWithoutACertificate,
  testConnectionRefusesCompromisedChain: testConnectionRefusesCompromisedChain,
  testDecoyForACompromisedDefaultAnchorIsRefused: testDecoyForACompromisedDefaultAnchorIsRefused,
  testQueueRedisBackendRefusesCompromisedKey:     testQueueRedisBackendRefusesCompromisedKey,
};

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); process.exit(0); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
