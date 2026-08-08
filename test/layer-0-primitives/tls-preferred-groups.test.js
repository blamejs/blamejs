// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.network.tls.preferredGroups + b.network.tls.pqc.* — RFC 9794
 * named-group ordering surface tests.
 *
 * Validates that the framework default puts X25519MLKEM768 first
 * (RFC 9794 default), SecP256r1MLKEM768 second (RFC 9794 optional),
 * SecP384r1MLKEM1024 third, and X25519 fourth (classical fallback).
 * Operator opt-out via setKeyShares / preferredGroups.set replaces
 * the list.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function testPreferredGroupsSurface() {
  check("network.tls.preferredGroups.set is a function",
        typeof b.network.tls.preferredGroups.set === "function");
  check("network.tls.preferredGroups.get is a function",
        typeof b.network.tls.preferredGroups.get === "function");
  check("network.tls.preferredGroups.reset is a function",
        typeof b.network.tls.preferredGroups.reset === "function");
}

function testRfc9794DefaultOrdering() {
  b.network.tls.preferredGroups.reset();
  var groups = b.network.tls.preferredGroups.get();
  check("default is array with at least 4 groups",
        Array.isArray(groups) && groups.length >= 4);
  check("default group[0] is X25519MLKEM768 (RFC 9794 default)",
        groups[0] === "X25519MLKEM768");
  check("default group[1] is SecP256r1MLKEM768 (RFC 9794 optional)",
        groups[1] === "SecP256r1MLKEM768");
  check("default contains SecP384r1MLKEM1024",
        groups.indexOf("SecP384r1MLKEM1024") !== -1);
  check("default contains X25519 fallback",
        groups.indexOf("X25519") !== -1);
}

function testOperatorOptOut() {
  var prior = b.network.tls.preferredGroups.get();
  try {
    b.network.tls.preferredGroups.set(["X25519"]);
    check("operator opt-out leaves only X25519",
          b.network.tls.preferredGroups.get().join(",") === "X25519");
  } finally {
    b.network.tls.preferredGroups.reset();
  }
  check("reset restores default ordering with X25519MLKEM768 first",
        b.network.tls.preferredGroups.get()[0] === "X25519MLKEM768");
  check("reset restored default length",
        b.network.tls.preferredGroups.get().length === prior.length);
}

function testPqcAliasMatchesPreferredGroups() {
  b.network.tls.preferredGroups.reset();
  var viaPqc = b.network.tls.pqc.getKeyShares();
  var viaPref = b.network.tls.preferredGroups.get();
  check("pqc.getKeyShares matches preferredGroups.get",
        viaPqc.join(",") === viaPref.join(","));
}

function testApplyToContextEmitsGroups() {
  b.network.tls.preferredGroups.reset();
  var ctx = b.network.tls.applyToContext({ base: {} });
  check("applyToContext emits groups string",
        typeof ctx.groups === "string" && ctx.groups.indexOf("X25519MLKEM768") === 0);
  check("applyToContext groups string contains SecP256r1MLKEM768",
        ctx.groups.indexOf("SecP256r1MLKEM768") !== -1);
}

// ---- The outbound TLS posture is applied by every client, not per-caller ----
//
// Each protocol client the framework ships assembles its own tls.connect
// options. When each one hand-listed the posture keys, they drifted: the
// Redis client pinned neither the TLS floor nor the hybrid groups, the syslog
// sink pinned the floor but no groups, and the WebSocket client set `curves`
// — which node:tls does not recognize (`tls.createSecureContext({ curves })`
// is accepted and ignored, while a bad `ecdhCurve` throws), so its groups
// never reached the handshake. One posture object closes the class: these
// assertions fail for ANY outbound client that stops merging it.
function _postureKeysPresent(opts) {
  if (!opts) return false;
  if (opts.minVersion !== "TLSv1.3") return false;
  if (typeof opts.ecdhCurve !== "string" || opts.ecdhCurve.indexOf("MLKEM") === -1) return false;
  var expected = b.constants.TLS_CERT_COMPRESSION();
  if (expected.length === 0) return true;                   // runtime predates RFC 8879 support
  return Array.isArray(opts.certificateCompression) &&
         opts.certificateCompression.join(",") === expected.join(",");
}

// Capture the options handed to tls.connect by `drive`, without letting a
// real connection out. Returns the captured options (or null).
async function _captureTlsConnectOpts(label, drive) {
  var nodeTls = require("node:tls");
  var orig = nodeTls.connect;
  var captured = null;
  nodeTls.connect = function (opts) {
    if (captured === null && opts && typeof opts === "object") captured = opts;
    // Hand back a socket aimed at a closed port so the caller's error path
    // runs normally instead of reaching the intended host.
    var s = orig.call(nodeTls, { host: "127.0.0.1", port: 1 });
    s.on("error", function () { /* expected — nothing listens on port 1 */ });
    return s;
  };
  try {
    await drive();
    await helpers.waitUntil(function () { return captured !== null; },
      { timeoutMs: 5000, label: "tls posture: " + label + " called tls.connect" });
  } finally {
    nodeTls.connect = orig;
  }
  return captured;
}

function testOutboundPostureShape() {
  b.network.tls.preferredGroups.reset();
  var posture = b.network.tls.outboundPosture();
  check("outboundPosture pins the TLS 1.3 floor",
        posture.minVersion === "TLSv1.3");
  check("outboundPosture carries the hybrid group preference",
        posture.ecdhCurve === b.constants.TLS_GROUP_CURVE_STR);
  check("outboundPosture returns a fresh object each call",
        b.network.tls.outboundPosture() !== posture);
  var algs = b.constants.TLS_CERT_COMPRESSION();
  check("TLS_CERT_COMPRESSION is frozen (callers cannot mutate the shared list)",
        Object.isFrozen(algs));
  var reported = b.network.tls.certificateCompressionAlgorithms();
  check("certificateCompressionAlgorithms reports the same algorithms",
        reported.join(",") === algs.join(","));
  check("certificateCompressionAlgorithms hands back a copy the caller owns",
        reported !== algs && !Object.isFrozen(reported) &&
        b.network.tls.certificateCompressionAlgorithms() !== reported);
  if (algs.length > 0) {
    check("outboundPosture advertises certificate compression",
          posture.certificateCompression.join(",") === algs.join(","));
  } else {
    check("outboundPosture omits certificateCompression when unsupported",
          posture.certificateCompression === undefined);
  }
}

// The posture exists so one edit reaches every outbound path. That only holds
// if it reads LIVE state: an operator narrowing the groups for a FIPS policy
// must not keep offering the ones they removed on Redis / syslog / DNS / NTS /
// proxy / ECH / OCSP / h2 while a couple of paths honor the narrowing. Reading
// the compiled-in default instead of the live list is exactly that failure, so
// assert on the options each client BUILDS, not on the posture alone.
async function testNarrowedGroupsReachEveryOutboundClient() {
  var NARROWED = ["SecP256r1MLKEM768", "SecP384r1MLKEM1024"];
  var expected = NARROWED.join(":");
  var generationBefore = b.network.tls.postureGeneration();
  b.network.tls.preferredGroups.set(NARROWED);
  try {
    check("outboundPosture reports the operator's narrowed list",
          b.network.tls.outboundPosture().ecdhCurve === expected);
    check("the narrowed list drops the classical fallback the operator removed",
          b.network.tls.outboundPosture().ecdhCurve.indexOf("X25519MLKEM768") === -1);

    var redis = require("../../lib/redis-client");
    var redisOpts = await _captureTlsConnectOpts("redis", function () {
      var c = redis.create({
        url: "rediss://localhost:1/0", connectTimeoutMs: 200, maxReconnectAttempts: 0,
      });
      return c.connect().then(function () { return c.close(); },
                              function () { return c.close(); });
    });
    check("redis dials with the narrowed groups",
          redisOpts && redisOpts.ecdhCurve === expected);

    var syslog = require("../../lib/log-stream-syslog");
    var sink = null;
    var syslogOpts = await _captureTlsConnectOpts("syslog", function () {
      sink = syslog.create({ url: "tls://localhost:1", onDrop: function () {} });
      return Promise.resolve();
    });
    if (sink) { try { await sink.close(); } catch (_e) { /* teardown */ } }
    check("the syslog sink dials with the narrowed groups",
          syslogOpts && syslogOpts.ecdhCurve === expected);

    var wsClient = require("../../lib/ws-client");
    var conn = null;
    var wsOpts = await _captureTlsConnectOpts("ws-client", function () {
      conn = wsClient.connect("wss://127.0.0.1:1/", {
        reconnect: false, audit: false, allowInternal: true, handshakeTimeoutMs: 200,
      });
      conn.on("error", function () { /* expected — nothing listens on port 1 */ });
      return Promise.resolve();
    });
    if (conn) { try { conn.close(); } catch (_e) { /* teardown */ } }
    check("wss:// dials with the narrowed groups",
          wsOpts && wsOpts.ecdhCurve === expected);

    // DNS-over-TLS builds its own connect options on the same posture.
    var dnsModule = require("../../lib/network-dns");
    var dotOpts = await _captureTlsConnectOpts("dns-over-tls", function () {
      dnsModule.useDnsOverTls({ host: "127.0.0.1", port: 1, servername: "localhost" });
      return dnsModule.resolve4("example.com").then(
        function () {}, function () { /* nothing listens on port 1 */ });
    });
    dnsModule._resetForTest();
    check("DNS-over-TLS dials with the narrowed groups",
          dotOpts && dotOpts.ecdhCurve === expected);

    // The HTTP client picks its transport by ALPN, so the h1 agent and the h2
    // session must agree on the posture — otherwise which groups an origin
    // sees depends on whether it speaks HTTP/2, and the narrowing silently
    // applies to some peers and not others.
    var agent = b.pqcAgent.create();
    try {
      check("the HTTP/1.1 agent offers the narrowed groups",
            agent.options.ecdhCurve === expected);
      check("the HTTP/1.1 agent's TLS groups list matches its ecdhCurve",
            agent.options.groups === expected);
    } finally { agent.destroy(); }

    // "The change applies on the next dial" has to hold for POOLED
    // connections too, or it is true only for callers that never pool. An
    // Agent copies its options at construction and an h2 session negotiates
    // at connect, so neither notices a later narrowing on its own — the pool
    // is rebuilt when the preference moves, which the generation counter is
    // what makes observable.
    check("changing the preference advances the posture generation, so a " +
          "pooled transport can tell its options are stale",
          b.network.tls.postureGeneration() > generationBefore);
  } finally {
    b.network.tls.preferredGroups.reset();
  }

  // Reset counts as a change too — an operator restoring the default must not
  // be left with a pool still narrowed.
  var afterReset = b.network.tls.postureGeneration();
  b.network.tls.preferredGroups.set(NARROWED);
  try {
    check("re-narrowing after a reset advances the generation again",
          b.network.tls.postureGeneration() > afterReset);
  } finally {
    b.network.tls.preferredGroups.reset();
  }
}

function testBuildOptionsCarriesCertCompression() {
  var algs = b.constants.TLS_CERT_COMPRESSION();
  var out = b.network.tls.buildOptions({});
  if (algs.length > 0) {
    check("buildOptions defaults certificateCompression to the runtime list",
          Array.isArray(out.certificateCompression) &&
          out.certificateCompression.join(",") === algs.join(","));
    check("buildOptions lets an operator narrow the algorithm list",
          b.network.tls.buildOptions({ certificateCompression: ["brotli"] })
            .certificateCompression.join(",") === "brotli");
    check("buildOptions lets an operator advertise none via []",
          b.network.tls.buildOptions({ certificateCompression: [] })
            .certificateCompression === undefined);
    var unknownErr = null;
    try { b.network.tls.buildOptions({ certificateCompression: ["lzma"] }); }
    catch (e) { unknownErr = e; }
    check("buildOptions refuses an algorithm this runtime cannot decompress",
          unknownErr && unknownErr.code === "network-tls/bad-tls-options");
    var shapeErr = null;
    try { b.network.tls.buildOptions({ certificateCompression: "brotli" }); }
    catch (e) { shapeErr = e; }
    check("buildOptions refuses the string form (node:tls requires an array)",
          shapeErr && shapeErr.code === "network-tls/bad-tls-options");
  } else {
    check("buildOptions omits certificateCompression on a runtime without it",
          out.certificateCompression === undefined);
  }
  var ctx = b.network.tls.applyToContext({ base: {} });
  check("applyToContext carries the same certificate-compression posture",
        (algs.length === 0 && ctx.certificateCompression === undefined) ||
        (algs.length > 0 && ctx.certificateCompression.join(",") === algs.join(",")));
  check("applyToContext keeps an operator's certificateCompression override",
        b.network.tls.applyToContext({ base: { certificateCompression: [] } })
          .certificateCompression.length === 0);
}

async function testRedisClientAppliesThePosture() {
  var redis = require("../../lib/redis-client");
  var opts = await _captureTlsConnectOpts("redis", function () {
    var c = redis.create({
      url: "rediss://localhost:1/0", connectTimeoutMs: 200, maxReconnectAttempts: 0,
    });
    return c.connect().then(
      function () { return c.close(); },
      function () { return c.close(); }
    );
  });
  check("redis rediss:// dial applies the framework outbound TLS posture",
        _postureKeysPresent(opts));
}

async function testSyslogSinkAppliesThePosture() {
  var syslog = require("../../lib/log-stream-syslog");
  var sink = null;
  var opts = await _captureTlsConnectOpts("syslog", function () {
    sink = syslog.create({ url: "tls://localhost:1", onDrop: function () {} });
    return Promise.resolve();
  });
  if (sink) { try { await sink.close(); } catch (_e) { /* teardown */ } }
  check("syslog tls:// sink applies the framework outbound TLS posture",
        _postureKeysPresent(opts));
}

async function testWsClientAppliesThePosture() {
  var wsClient = require("../../lib/ws-client");
  var conn = null;
  var opts = await _captureTlsConnectOpts("ws-client", function () {
    conn = wsClient.connect("wss://127.0.0.1:1/", {
      reconnect: false, audit: false, allowInternal: true, handshakeTimeoutMs: 200,
    });
    conn.on("error", function () { /* expected — nothing listens on port 1 */ });
    return Promise.resolve();
  });
  if (conn) { try { conn.close(); } catch (_e) { /* teardown */ } }
  check("wss:// dial applies the framework outbound TLS posture",
        _postureKeysPresent(opts));
  check("wss:// dial pins groups via ecdhCurve, not the ignored `curves` alias",
        opts && typeof opts.ecdhCurve === "string" && opts.curves === undefined);
}

// ---- The two group lists are one list ----
//
// `C.TLS_GROUP_PREFERENCE` feeds every protocol client's ecdhCurve;
// `b.network.tls.preferredGroups` feeds the HTTP client and the operator
// surface. They drifted into different orders, and order is not cosmetic:
// Node sends a key share for the FIRST group only, so leading with a hybrid
// the peer does not implement forces a HelloRetryRequest on every handshake.
function testGroupOrderIsSingleSourced() {
  b.network.tls.preferredGroups.reset();
  check("constants and preferredGroups agree on the outbound group order",
        b.constants.TLS_GROUP_PREFERENCE.join(",") ===
        b.network.tls.preferredGroups.get().join(","));
  check("the leading group is the widely-implemented hybrid",
        b.constants.TLS_GROUP_PREFERENCE[0] === "X25519MLKEM768");
}

// A HelloRetryRequest is invisible to the TLS surface — the connection still
// succeeds and still reports the negotiated hybrid — but Node hands the
// client an EMPTY stapled OCSP response across the retried handshake. That
// makes `ocsp.requireStapled` refuse a peer that DID staple. Drive a real
// loopback handshake with the framework's own group string and require the
// staple to arrive: this fails for any group order that provokes a retry.
async function testFrameworkGroupsDoNotForceHelloRetry() {
  var nodeTls = require("node:tls");
  var pair = helpers.selfSignedPair({ commonName: "localhost" });
  var STAPLE = Buffer.from([0x30, 0x00]);
  var srv = nodeTls.createServer({ key: pair.key, cert: pair.cert },
    function (s) { s.on("error", function () { /* peer reset */ }); });
  srv.on("OCSPRequest", function (_cert, _issuer, cb) { cb(null, STAPLE); });
  srv.on("error", function () { /* listen/accept best-effort */ });
  srv.unref();
  await new Promise(function (r) { srv.listen(0, "127.0.0.1", r); });
  var staple = await new Promise(function (resolve) {
    var seen = null;
    var sock = nodeTls.connect({
      // Trust the fixture's own certificate rather than switching
      // verification off — the handshake under test is a real, verified one.
      ca: [pair.cert], requestOCSP: true,
      host: "127.0.0.1", port: srv.address().port, servername: "localhost",
      minVersion: "TLSv1.3", ecdhCurve: b.constants.TLS_GROUP_CURVE_STR,
    });
    sock.on("OCSPResponse", function (r) { seen = r; });
    sock.on("secureConnect", function () { sock.destroy(); resolve(seen); });
    sock.on("error", function () { resolve(null); });
  });
  srv.close();
  check("the framework group order delivers a peer's stapled OCSP response " +
        "(no HelloRetryRequest)",
        Buffer.isBuffer(staple) && staple.length === STAPLE.length);
}

async function run() {
  testPreferredGroupsSurface();
  testRfc9794DefaultOrdering();
  testOperatorOptOut();
  testPqcAliasMatchesPreferredGroups();
  testApplyToContextEmitsGroups();
  testGroupOrderIsSingleSourced();
  await testFrameworkGroupsDoNotForceHelloRetry();
  testOutboundPostureShape();
  await testNarrowedGroupsReachEveryOutboundClient();
  testBuildOptionsCarriesCertCompression();
  await testRedisClientAppliesThePosture();
  await testSyslogSinkAppliesThePosture();
  await testWsClientAppliesThePosture();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[tls-preferred-groups] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
