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

var tls     = require("node:tls");
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
  check("applyToContext emits the group preference",
        typeof ctx.ecdhCurve === "string" &&
        ctx.ecdhCurve.indexOf("X25519MLKEM768") === 0);
  check("applyToContext group string contains SecP256r1MLKEM768",
        ctx.ecdhCurve.indexOf("SecP256r1MLKEM768") !== -1);
}

// applyToContext is the documented way to put the framework's posture onto an
// operator's own https.Server / https.Agent, so what matters is which group
// the handshake actually settles on. Reading a key back off the returned
// object cannot show that: node:tls accepts a key it does not implement and
// ignores it, which is how the preference came to be emitted under a name the
// TLS layer never reads. Narrow the preference to the classical group and let
// a client that PREFERS the hybrid negotiate against it — the server has to
// be the thing that turns it down.
async function testApplyToContextRestrictsTheNegotiatedGroup() {
  var pair = helpers.selfSignedPair();
  b.network.tls.preferredGroups.set(["X25519"]);
  var server = null;
  try {
    var ctx = b.network.tls.applyToContext({
      base: { key: pair.key, cert: pair.cert },
    });
    server = tls.createServer(ctx, function (sock) { sock.end(); });
    await new Promise(function (resolve, reject) {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });

    var negotiated = await new Promise(function (resolve, reject) {
      var sock = tls.connect({
        port:       server.address().port,
        host:       "127.0.0.1",
        ca:         [pair.cert],
        servername: pair.commonName,
        minVersion: "TLSv1.3",
        ecdhCurve:  "X25519MLKEM768:X25519",
      }, function () {
        var info = sock.getEphemeralKeyInfo();
        resolve((info && info.name) || "");
        sock.destroy();
      });
      sock.on("error", reject);
    });

    check("a narrowed preference reaches the server's handshake",
          negotiated === "X25519");
  } finally {
    b.network.tls.preferredGroups.reset();
    if (server) await new Promise(function (r) { server.close(r); });
  }
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
  // Force the process-wide default agent to exist BEFORE the narrowing, so the
  // assertion below has a stale cache to catch. Without this the first access
  // happens after the change and would build correctly either way.
  var staleDefault = b.pqcAgent.agent;
  // Watch for a destructive refresh. Agent.destroy() resets sockets that are
  // mid-response, so refreshing the shared default because someone changed the
  // posture must NOT call it — an unrelated download running on that agent
  // would die. Retirement is non-destructive: stop pooling, close idle sockets,
  // let in-flight work finish.
  var staleDestroyed = false;
  var staleOrigDestroy = staleDefault.destroy;
  staleDefault.destroy = function () {
    staleDestroyed = true;
    return staleOrigDestroy.apply(this, arguments);
  };
  b.network.tls.preferredGroups.set(NARROWED);
  try {
    check("outboundPosture reports the operator's narrowed list",
          b.network.tls.outboundPosture().ecdhCurve === expected);
    check("the narrowed list drops the groups the operator removed",
          b.network.tls.outboundPosture().ecdhCurve.indexOf("X25519MLKEM768") === -1 &&
          b.network.tls.outboundPosture().ecdhCurve.indexOf("X25519") === -1);

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
    // applies to some peers and not others. The h1 agent is checked here; the
    // h2 side is covered where it is observable, by the h2c dial in
    // testNarrowedGroupsReachEveryOutboundClient's DNS-over-TLS case and by
    // http-client.test.js's transport tests.
    var agent = b.pqcAgent.create();
    try {
      // ecdhCurve is the option node:tls actually honours — a `groups` value it
      // cannot negotiate is accepted and ignored (verified on this runtime: a
      // groups-only pin to a group the peer lacks still completes on another).
      // So this is the assertion that means anything about the wire.
      check("the HTTP/1.1 agent offers the narrowed groups",
            agent.options.ecdhCurve === expected);
      // Nothing is carried alongside under a name the TLS layer ignores: a
      // second key holding the same list reads as a second handle on the
      // preference, and an operator narrowing THAT one would change nothing.
      check("the agent carries no inert second copy of the group list",
            agent.options.groups === undefined);
    } finally { agent.destroy(); }

    // The process-wide default agent is cached, so it has the same staleness
    // problem as the transport pool: an Agent copies its TLS options at
    // construction and would keep offering the removed groups for the life of
    // the process. Reading it after the change must give an agent built under
    // the new preference — without the operator having to call reload().
    var afterDefault = b.pqcAgent.agent;
    check("the cached default agent is rebuilt for the narrowed preference",
          afterDefault !== staleDefault &&
          afterDefault.options.ecdhCurve === expected);
    check("the retired default agent is not destroyed, so a request already " +
          "running on it is not reset",
          staleDestroyed === false);
    check("the retired default agent stops pooling, so its sockets are closed " +
          "as they are released rather than parked unreachable",
          staleDefault.keepAlive === false);

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
  var pair = helpers.selfSignedPair();
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
  await testApplyToContextRestrictsTheNegotiatedGroup();
  testGroupOrderIsSingleSourced();
  await testFrameworkGroupsDoNotForceHelloRetry();
  testOutboundPostureShape();
  testEveryPreferredGroupIsKnownToTheRuntime();
  testExplainOutboundFailure();
  testAnnotateOutboundFailure();
  await testNarrowedGroupsReachEveryOutboundClient();
  testBuildOptionsCarriesCertCompression();
  await testRedisClientAppliesThePosture();
  await testSyslogSinkAppliesThePosture();
  await testWsClientAppliesThePosture();
}


// ---- A refused handshake is explained, not just reported ----
//
// OpenSSL reports a rejected ClientHello as a bare alert. Two of those alerts
// are routinely the posture doing its job, and they are NOT the same cause:
// protocol_version means the peer has no TLS 1.3, handshake_failure means it
// shares none of the offered groups. Conflating them sends an operator after
// the post-quantum groups for a failure the groups had no part in, which is
// exactly what happened in the field.
function _alert(code, text) {
  var e = new Error(text);
  e.code = code;
  return e;
}

function testExplainOutboundFailure() {
  b.network.tls.preferredGroups.reset();

  var version = b.network.tls.explainOutboundFailure(
    _alert("ERR_SSL_TLSV1_ALERT_PROTOCOL_VERSION", "ssl3_read_bytes:tlsv1 alert protocol version"),
    { host: "peer.example", port: 443 });
  check("a protocol-version alert is attributed to the TLS 1.3 floor",
        typeof version === "string" && version.indexOf("TLS 1.3") !== -1);
  check("the explanation names the peer",
        version.indexOf("peer.example:443") !== -1);
  check("the explanation clears the group preference of blame",
        /unrelated to the post-quantum group preference/.test(version));
  check("the original alert text survives in the explanation",
        version.indexOf("tlsv1 alert protocol version") !== -1);

  // Alert 40 is generic: a disjoint TLS 1.3 cipher list produces this exact
  // code with a group both sides support, so it must not be reported as a
  // group mismatch. It still names the peer and what was pinned.
  var generic = b.network.tls.explainOutboundFailure(
    _alert("ERR_SSL_SSL/TLS_ALERT_HANDSHAKE_FAILURE", "ssl/tls alert handshake failure"),
    { host: "peer.example" });
  check("a generic failure alert is still explained", typeof generic === "string");
  check("a generic failure alert is described as ambiguous",
        /does not say what it objected to/.test(generic));
  check("a generic failure alert does not assert the group list as the cause",
        !/supports none of the key-exchange groups/.test(generic));
  check("a generic failure alert still lists the cipher suite as a candidate",
        /cipher suite/.test(generic));

  // The codes that DO mean the group specifically are reported as such, and a
  // classical group in the list is not proof the peer can pick one -- a TLS
  // 1.3 peer restricted to secp256r1 shares nothing with the hybrids plus
  // X25519 -- so a fallback does not suppress them.
  var definitive = b.network.tls.explainOutboundFailure(
    _alert("ERR_SSL_NO_SHARED_GROUP", "no shared group"), { host: "peer.example" });
  check("the definitive no-shared-group code names the group list",
        typeof definitive === "string" &&
        /supports none of the key-exchange groups/.test(definitive));
  var wrongCurve = b.network.tls.explainOutboundFailure(
    _alert("ERR_SSL_WRONG_CURVE", "wrong curve"), { host: "peer.example" });
  check("the wrong-curve code names the group list",
        typeof wrongCurve === "string" &&
        /supports none of the key-exchange groups/.test(wrongCurve));

  // A caller naming what THIS dial used is authoritative for it. A request on
  // a caller-supplied agent that pins neither setting must not be diagnosed
  // against the shared posture -- an agent capped at TLS 1.2 talking to a
  // 1.3-only peer would otherwise be reported as the peer lacking 1.3.
  var unpinned = b.network.tls.explainOutboundFailure(
    _alert("ERR_SSL_TLSV1_ALERT_PROTOCOL_VERSION", "tlsv1 alert protocol version"),
    { host: "peer.example", minVersion: undefined, ecdhCurve: undefined });
  check("a dial that pinned no floor is not blamed on the shared floor",
        unpinned === null);

  var unpinnedGroups = b.network.tls.explainOutboundFailure(
    _alert("ERR_SSL_NO_SHARED_GROUP", "no shared group"),
    { host: "peer.example", minVersion: undefined, ecdhCurve: undefined });
  check("a dial that pinned no group list is not blamed on the shared list",
        unpinnedGroups === null);

  var narrowed = b.network.tls.explainOutboundFailure(
    _alert("ERR_SSL_SSL/TLS_ALERT_HANDSHAKE_FAILURE", "ssl/tls alert handshake failure"),
    { host: "peer.example", ecdhCurve: "X25519MLKEM768:SecP256r1MLKEM768" });
  check("the offered list is quoted so an operator can see what was pinned",
        typeof narrowed === "string" &&
        narrowed.indexOf("X25519MLKEM768:SecP256r1MLKEM768") !== -1);
  check("a hybrid-only list is called out wherever the groups are in frame",
        /names only post-quantum hybrids/.test(narrowed));

  check("an unrelated error gets no invented explanation",
        b.network.tls.explainOutboundFailure(_alert("ECONNREFUSED", "connect ECONNREFUSED")) === null);
  check("a non-error argument is handled without throwing",
        b.network.tls.explainOutboundFailure(null) === null);
}

function testAnnotateOutboundFailure() {
  b.network.tls.preferredGroups.reset();
  var err = _alert("ERR_SSL_TLSV1_ALERT_PROTOCOL_VERSION", "tlsv1 alert protocol version");
  var returned = b.network.tls.annotateOutboundFailure(err, { host: "peer.example", port: 443 });

  check("annotate hands back the same error object", returned === err);
  check("annotate leaves the code alone for callers branching on it",
        err.code === "ERR_SSL_TLSV1_ALERT_PROTOCOL_VERSION");
  check("annotate rewrites the message", err.message.indexOf("TLS 1.3") !== -1);
  // A caller that capped the dial below TLS 1.3 — a WebSocket tlsOpts override,
  // or their own agent — never attempted 1.3, so naming its cipher list would
  // send them after a setting that had no part in the failure.
  var generic = _alert("ERR_SSL_SSL/TLS_ALERT_HANDSHAKE_FAILURE", "alert handshake failure");
  var wide = b.network.tls.explainOutboundFailure(generic, { host: "peer.example", port: 443 });
  check("generic alert names the TLS 1.3 cipher list when 1.3 was reachable",
        /no shared TLS 1.3 cipher suite/.test(wide));
  var capped = b.network.tls.explainOutboundFailure(
    _alert("ERR_SSL_SSL/TLS_ALERT_HANDSHAKE_FAILURE", "alert handshake failure"),
    { host: "peer.example", port: 443, maxVersion: "TLSv1.2" });
  check("a dial capped below TLS 1.3 is not sent after its cipher list",
        /no shared cipher suite/.test(capped) && /TLS 1\.3 cipher/.test(capped) === false);
  check("the capped explanation still names the group list and the peer",
        capped.indexOf("peer.example") !== -1 && /key-exchange group/.test(capped));

  // The stack has to be read BEFORE annotating for this to test anything. V8
  // formats Error.stack on first access, so an untouched error renders its
  // stack from whatever the message is by then — the rewrite could be absent
  // entirely and the stack would still show the new text. An error that a
  // logger or an outer handler has already stringified is the case where the
  // stack holds the OLD message and the rewrite is what refreshes it.
  var eager = _alert("ERR_SSL_TLSV1_ALERT_PROTOCOL_VERSION", "tlsv1 alert protocol version");
  var stackBefore = eager.stack;
  check("the stack was materialised before annotating (else the next check is vacuous)",
        typeof stackBefore === "string" && stackBefore.indexOf("TLS 1.3") === -1);
  b.network.tls.annotateOutboundFailure(eager, { host: "peer.example", port: 443 });
  check("annotate refreshes the stack's copy of the message",
        eager.stack.indexOf("TLS 1.3") !== -1);

  // An error can reach more than one handler on its way out; a second pass
  // must not nest one explanation inside the next one's "Underlying error:".
  var before = err.message;
  b.network.tls.annotateOutboundFailure(err, { host: "peer.example", port: 443 });
  check("annotating twice leaves the message unchanged", err.message === before);
  check("annotating twice does not nest explanations",
        (err.message.match(/TLS handshake refused/g) || []).length === 1);

  // The leg that owns the peer claims the error, so an outer handler cannot
  // relabel it with a different peer. A proxy-leg handshake failure travels
  // out through the agent callback of the request to the DESTINATION; without
  // the claim, that handler would report the destination as refusing a
  // handshake that never reached it.
  var proxyLeg = _alert("ERR_SSL_TLSV1_ALERT_PROTOCOL_VERSION", "tlsv1 alert protocol version");
  b.network.tls.annotateOutboundFailure(proxyLeg, { host: "proxy.internal", port: 8443 });
  b.network.tls.annotateOutboundFailure(proxyLeg, { host: "destination.example", port: 443 });
  check("the peer named is the one whose handshake actually failed",
        proxyLeg.message.indexOf("proxy.internal:8443") !== -1);
  check("a later leg cannot substitute its own peer",
        proxyLeg.message.indexOf("destination.example") === -1);

  // Silence from the owning leg does not license an outer guess: an error it
  // had nothing to say about must not pick up a different peer's name later.
  var quiet = _alert("ECONNRESET", "socket hang up");
  b.network.tls.annotateOutboundFailure(quiet, { host: "proxy.internal", port: 8443 });
  b.network.tls.annotateOutboundFailure(quiet, {
    host: "destination.example", port: 443, ecdhCurve: "X25519MLKEM768",
  });
  check("an error the owning leg could not explain is left alone by later legs",
        quiet.message === "socket hang up");

  var untouched = _alert("ECONNREFUSED", "connect ECONNREFUSED 10.0.0.1:443");
  b.network.tls.annotateOutboundFailure(untouched, { host: "peer.example" });
  check("annotate leaves an error it cannot explain exactly as it was",
        untouched.message === "connect ECONNREFUSED 10.0.0.1:443");
}


// Every group in the preference has to be a name THIS runtime's OpenSSL
// knows. The list is now applied as `ecdhCurve`, and an unrecognised name
// there throws rather than being skipped -- so a group added to the
// preference that the runtime lacks would not degrade gracefully, it would
// fail every server and agent built through applyToContext at construction.
// The bogus control keeps this honest: if createSecureContext ever stopped
// rejecting unknown names, the assertions above it would pass vacuously.
function testEveryPreferredGroupIsKnownToTheRuntime() {
  b.network.tls.preferredGroups.reset();
  var bogus = false;
  try { tls.createSecureContext({ ecdhCurve: "definitely-not-a-real-group" }); }
  catch (_e) { bogus = true; }
  check("the runtime rejects an unknown group name (control)", bogus);

  var groups = b.network.tls.preferredGroups.get();
  for (var i = 0; i < groups.length; i += 1) {
    var ok = true;
    try { tls.createSecureContext({ ecdhCurve: groups[i] }); }
    catch (_e2) { ok = false; }
    check("preferred group '" + groups[i] + "' is known to this runtime", ok);
  }

  var whole = true;
  try { tls.createSecureContext({ ecdhCurve: groups.join(":") }); }
  catch (_e3) { whole = false; }
  check("the whole preference is accepted as one ecdhCurve string", whole);

  // The hybrid the framework leads with must survive a real handshake, not
  // merely be a name the context accepts.
  check("the preference leads with X25519MLKEM768",
        groups[0] === "X25519MLKEM768");
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[tls-preferred-groups] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
