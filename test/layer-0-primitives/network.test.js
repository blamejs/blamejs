// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var nodeCrypto = require("node:crypto");
var nodeNet    = require("node:net");

var helpers = require("../helpers");
var check   = helpers.check;
var b       = helpers.b;
var C       = b.constants;

var network    = b.network;
var dnsModule  = network.dns;
var proxy      = network.proxy;
var trust      = network.tls;
var heartbeat  = network.heartbeat;
var ntp        = network.ntp;
var nts        = b.network.ntp.nts;
var ntpCheck   = b.ntpCheck;

async function _makeRealCaPem() {
  var ca = await b.mtlsEngine.generateCa({ generation: 1 });
  return ca.caCertPem;
}

function _resetAll() {
  if (typeof network._resetForTest === "function") network._resetForTest();
}

function _listenTcp(host) {
  return new Promise(function (resolve) {
    var server = nodeNet.createServer(function (sock) { sock.destroy(); });
    server.once("error", function (e) { resolve({ server: null, error: e }); });
    server.listen(0, host, function () { resolve({ server: server, error: null }); });
  });
}

// A tcp target written as a bracketed IPv6 literal ("[::1]", the form a URL
// authority carries) reaches the listener, as the bare form does.
async function _testHeartbeatTcpBracketedIpv6() {
  var l = await _listenTcp("::1");
  if (l.server === null) {
    helpers.unavailable("heartbeat tcp [::1]", "cannot listen on ::1: " + (l.error && l.error.code));
    return;
  }
  var port = l.server.address().port;
  try {
    var hosts = [["bare", "::1"], ["bracketed", "[::1]"]];
    for (var i = 0; i < hosts.length; i += 1) {
      var name = "probe-v6-" + hosts[i][0];
      heartbeat.start({
        targets: [{ name: name, type: "tcp", host: hosts[i][1], port: port, intervalMs: 50, timeoutMs: 2000, threshold: 1 }],
      });
      var st = await helpers.waitUntil(function () {
        var s = heartbeat.status(name);
        return (s && s.lastResult) ? s : false;
      }, { label: "network heartbeat: " + name + " recorded a first probe" });
      heartbeat.stop(name);
      check("heartbeat tcp probe reaches a " + hosts[i][0] + " IPv6 host (" + hosts[i][1] + ")",
        st.lastResult.ok === true, JSON.stringify(st.lastResult));
    }
  } finally {
    l.server.close();
  }
}

// A tcp target host that is empty, or brackets anything but an IPv6 address,
// is refused at start(). Dialing "" or "[]" connects to localhost, so the
// probe would report a typo as a healthy target.
function _testHeartbeatTcpBadHost() {
  var bad = ["", "[]", "[localhost]", "[127.0.0.1]", "[::1", "::1]"];
  for (var i = 0; i < bad.length; i += 1) {
    var err = null;
    try {
      heartbeat.start({ targets: [{ name: "bad-host-" + i, type: "tcp", host: bad[i], port: 1 }] });
    } catch (e) { err = e; }
    if (err === null) heartbeat.stop("bad-host-" + i);
    check("heartbeat.start refuses tcp host " + JSON.stringify(bad[i]) + " with heartbeat/bad-tcp",
      err !== null && err.code === "heartbeat/bad-tcp", err ? err.code : "no throw");
  }
  var good = ["localhost", "127.0.0.1", "::1", "[::1]", "[fe80::1]"];
  for (var j = 0; j < good.length; j += 1) {
    var gErr = null;
    try {
      heartbeat.start({ targets: [{ name: "good-host-" + j, type: "tcp", host: good[j], port: 1, intervalMs: C.TIME.hours(1) }] });
      heartbeat.stop("good-host-" + j);
    } catch (e) { gErr = e; }
    check("heartbeat.start accepts tcp host " + JSON.stringify(good[j]), gErr === null, gErr && gErr.message);
  }
}

async function run() {
  _resetAll();

  // ---- DNS ----
  check("dns.setServers throws on empty array",
    _throws(function () { dnsModule.setServers([]); }, "dns/bad-servers"));
  dnsModule.setServers(["1.1.1.1", "8.8.8.8"]);
  check("dns.getServers returns set list",
    JSON.stringify(dnsModule.getServers().slice(0, 2)) === JSON.stringify(["1.1.1.1", "8.8.8.8"]));
  check("dns.setResultOrder throws on bad value",
    _throws(function () { dnsModule.setResultOrder("descending"); }, "dns/bad-result-order"));
  dnsModule.setResultOrder("ipv6first");
  dnsModule.setFamily(6);
  check("dns.setLookupTimeoutMs accepts positive number", (function () {
    dnsModule.setLookupTimeoutMs(1500);
    return true;
  })());
  check("dns.setLookupTimeoutMs throws on negative",
    _throws(function () { dnsModule.setLookupTimeoutMs(-1); }, "dns/bad-timeout"));
  dnsModule.setCacheTtlMs(60_000, 5_000);

  // IP literal lookup short-circuits
  var lit = await dnsModule.lookup("127.0.0.1");
  check("dns.lookup of IPv4 literal returns address+family",
    lit.address === "127.0.0.1" && lit.family === 4);
  var lit6 = await dnsModule.lookup("::1");
  check("dns.lookup of IPv6 literal returns family=6",
    lit6.address === "::1" && lit6.family === 6);

  // DoH provider validation
  check("dns.useDnsOverHttps unknown provider throws",
    _throws(function () { dnsModule.useDnsOverHttps({ provider: "wibble" }); }, "dns/bad-doh-provider"));
  check("dns.useDnsOverHttps non-https url throws",
    _throws(function () { dnsModule.useDnsOverHttps({ url: "http://insecure/dns" }); }, "dns/bad-doh-url"));
  check("dns.useDnsOverTls bare host throws",
    _throws(function () { dnsModule.useDnsOverTls({}); }, "dns/bad-dot-host"));
  _resetAll();

  // ---- Proxy ----
  proxy.set({ http: "http://proxy.corp:3128", https: "http://proxy.corp:3128", no: ".internal,10.0.0.0/8,localhost" });
  check("proxy.shouldProxy true for external https",
    proxy.shouldProxy(new URL("https://api.partner.com/x")) === true);
  check("proxy.shouldProxy false for NO_PROXY suffix",
    proxy.shouldProxy(new URL("https://svc.internal/x")) === false);
  check("proxy.shouldProxy false for NO_PROXY exact host",
    proxy.shouldProxy(new URL("https://localhost/x")) === false);
  check("proxy.shouldProxy false for NO_PROXY CIDR match",
    proxy.shouldProxy(new URL("http://10.5.6.7/x")) === false);
  // The URL parser writes [::ffff:10.5.6.7] as [::ffff:a05:607]; it is the
  // address 10.5.6.7 and goes direct under the same rule.
  check("proxy.shouldProxy false for the IPv4-mapped spelling of a NO_PROXY CIDR host",
    proxy.shouldProxy(new URL("http://[::ffff:10.5.6.7]/x")) === false);
  proxy.set({ no: "::ffff:10.0.0.0/104,192.0.2.7,::ffff:198.51.100.9" });
  check("proxy.shouldProxy false for an IPv4 host under an IPv4-mapped NO_PROXY CIDR",
    proxy.shouldProxy(new URL("http://10.5.6.7/x")) === false);
  check("proxy.shouldProxy false for the mapped spelling of a NO_PROXY address",
    proxy.shouldProxy(new URL("http://[::ffff:192.0.2.7]/x")) === false);
  check("proxy.shouldProxy false for an IPv4 host listed by its mapped spelling",
    proxy.shouldProxy(new URL("http://198.51.100.9/x")) === false);
  check("proxy.shouldProxy true for an IPv4 host outside every NO_PROXY entry",
    proxy.shouldProxy(new URL("http://11.5.6.7/x")) === true);
  proxy.set({ no: ".internal,10.0.0.0/8,localhost" });
  var snap = proxy.snapshot();
  check("proxy.snapshot exposes resolved settings",
    snap.http && snap.https && snap.noProxy.length === 3);
  var agentExternal = proxy.agentFor(new URL("https://api.partner.com/x"));
  check("proxy.agentFor returns agent for external URL", agentExternal != null);
  var agentInternal = proxy.agentFor(new URL("https://svc.internal/x"));
  check("proxy.agentFor returns null for NO_PROXY URL", agentInternal == null);
  check("proxy.set bad URL throws",
    _throws(function () { proxy.set({ http: "::not a url::" }); }, "proxy/bad-url"));
  check("proxy.fromEnv reads HTTP_PROXY", (function () {
    proxy._resetForTest();
    var changed = proxy.fromEnv({ HTTP_PROXY: "http://proxy:8080", NO_PROXY: ".internal" });
    return changed && proxy.snapshot().http;
  })());
  _resetAll();

  // ---- TLS trust store ----
  check("tls.addCa rejects garbage", _throws(function () { trust.addCa("not a pem"); }, "tls/empty-pem"));
  check("tls.getTrustStore is empty after reset", trust.getTrustStore().length === 0);
  var x509Pem = await _makeRealCaPem();
  trust.addCa(x509Pem, { label: "unit-test-mitm" });
  check("tls.addCa adds + getTrustStore reflects",
    trust.getTrustStore().length === 1 && trust.getTrustStore()[0].label === "unit-test-mitm");
  trust.useSystemTrust(true);
  check("tls.isSystemTrustEnabled flips true", trust.isSystemTrustEnabled() === true);
  var ctxOpts = trust.applyToContext({ base: { servername: "x" } });
  check("tls.applyToContext adds operator CAs",
    Array.isArray(ctxOpts.ca) && ctxOpts.ca.length >= 1 && ctxOpts.servername === "x");
  trust.captureBaselineFingerprints();
  var x509Pem2 = await _makeRealCaPem();
  trust.addCa(x509Pem2, { label: "second-add" });
  var drift = trust.detectBaselineDrift();
  check("tls.detectBaselineDrift catches new CA after baseline",
    drift && drift.drifted === true && drift.added.length === 1);
  _resetAll();

  // ---- Heartbeat ----
  check("heartbeat.start rejects bad target",
    _throws(function () { heartbeat.start({ targets: [{ name: "x", type: "bogus" }] }); }, "heartbeat/bad-type"));
  check("heartbeat.start rejects empty targets",
    _throws(function () { heartbeat.start({ targets: [] }); }, "heartbeat/no-targets"));
  // Start a TCP probe against a port nothing should be listening on so the
  // first probe records "down" — covers the consecutive-failure / state path.
  var stateChanges = [];
  heartbeat.start({
    targets: [{ name: "probe-test", type: "tcp", host: "127.0.0.1", port: 1, intervalMs: 50, timeoutMs: 100, threshold: 1 }],
    onStateChange: function (e) { stateChanges.push(e); },
  });
  // Wait until the probe has recorded at least one failure (down / degraded
  // state, or consecutiveFailures > 0).
  var st = await helpers.waitUntil(function () {
    var s = heartbeat.status("probe-test");
    if (s && (s.state === "down" || s.state === "degraded" || s.consecutiveFailures > 0)) return s;
    return false;
  }, { label: "network heartbeat: probe-test recorded first failure" });
  check("heartbeat.status returns shape",
    st && (st.state === "down" || st.state === "degraded" || st.consecutiveFailures > 0));
  heartbeat.stop("probe-test");
  check("heartbeat.stop returns true on existing", heartbeat.status("probe-test") === null);
  _resetAll();
  await _testHeartbeatTcpBracketedIpv6();
  _resetAll();
  _testHeartbeatTcpBadHost();
  _resetAll();

  // ---- Socket defaults ----
  network.socket.setDefaultNoDelay(false);
  network.socket.setDefaultKeepAlive({ enable: true, initialDelayMs: 30_000 });
  var defaults = network.socket.defaults();
  check("socket defaults reflect setters",
    defaults.noDelay === false && defaults.keepAlive === true && defaults.keepAliveInitialDelayMs === 30_000);
  check("socket setDefaultNoDelay rejects non-boolean",
    _throws(function () { network.socket.setDefaultNoDelay("yes"); }, "socket/bad-no-delay"));
  check("socket setDefaultLinger throws (Node has no public setLinger)",
    _throws(function () { network.socket.setDefaultLinger({ enable: true }); }, "socket/linger-not-supported"));
  _resetAll();

  // ---- Socket applyToSocket (per-socket default tuner) ----
  // After _resetAll the SOCKET_DEFAULTS are back to noDelay:true /
  // keepAlive:true / initialDelay:0. applyToSocket pushes those onto a
  // freshly-created socket and returns the same socket.
  var applied2 = [];
  var spySocket = {
    setNoDelay:   function (v) { applied2.push(["noDelay", v]); },
    setKeepAlive: function (enable, delay) { applied2.push(["keepAlive", enable, delay]); },
  };
  var ret = b.network.socket.applyToSocket(spySocket);
  check("applyToSocket returns the same socket", ret === spySocket);
  check("applyToSocket applies TCP_NODELAY default (true)",
    applied2.some(function (c) { return c[0] === "noDelay" && c[1] === true; }));
  check("applyToSocket applies SO_KEEPALIVE default (true, 0)",
    applied2.some(function (c) { return c[0] === "keepAlive" && c[1] === true && c[2] === 0; }));
  // Best-effort: a socket lacking the setter methods is returned untouched.
  var bareSock = { destroyed: true };
  check("applyToSocket tolerates a socket without setters",
    b.network.socket.applyToSocket(bareSock) === bareSock);
  // Best-effort: a setter that throws is swallowed; the socket is still returned.
  var throwingSock = { setNoDelay: function () { throw new Error("errored socket"); } };
  check("applyToSocket swallows a throwing setter",
    b.network.socket.applyToSocket(throwingSock) === throwingSock);
  // null / undefined pass straight through.
  check("applyToSocket returns null unchanged", b.network.socket.applyToSocket(null) === null);
  // Real net.Socket round-trip — never connected, destroyed immediately.
  var realSock = new (require("node:net").Socket)();
  check("applyToSocket returns a real net.Socket unchanged",
    b.network.socket.applyToSocket(realSock) === realSock);
  realSock.destroy();
  _resetAll();

  // ---- TLS trust-store lifecycle (remove / clear / purgeExpired) ----
  var pemA = await _makeRealCaPem();
  var pemB = await _makeRealCaPem();
  trust.addCa(pemA, { label: "lifecycle-A" });
  trust.addCa(pemB, { label: "lifecycle-B" });
  check("trust-store has 2 CAs after add", trust.getTrustStore().length === 2);
  var fpA = trust.getTrustStore()[0].fingerprint256;
  var removed1 = trust.removeCa(fpA, { audit: false });
  check("removeCa returns 1 + drops one CA", removed1 === 1 && trust.getTrustStore().length === 1);
  check("removeCa returns 0 when fingerprint unknown",
    trust.removeCa("AA:BB:CC", { audit: false }) === 0);
  check("removeCa throws on empty fingerprint",
    _throws(function () { trust.removeCa(""); }, "tls/bad-fingerprint"));
  trust.addCa(pemA, { label: "label-test" });
  var removedByLabel = trust.removeCaByLabel("lifecycle-B", { audit: false });
  check("removeCaByLabel removes by label", removedByLabel === 1);
  check("expiringSoon returns CAs whose validTo is past threshold",
    trust.expiringSoon(C.TIME.days(36500)).length === trust.getTrustStore().length);
  trust.purgeExpired({ audit: false });
  check("purgeExpired no-ops when nothing expired (CA generated just now)",
    trust.getTrustStore().length >= 1);
  trust.clearAll({ audit: false });
  check("clearAll empties the trust store", trust.getTrustStore().length === 0);
  _resetAll();

  // ---- DNS real resolve4 / resolve6 (uses dns.promises.resolve4) ----
  // Resolve a known stable hostname (cloudflare.com always has A + AAAA).
  // Skip the network test if DNS resolution fails offline — keep the
  // test deterministic by also exercising IP-literal short-circuit.
  check("dns.resolve4 returns array on IP literal short-circuit",
    (await dnsModule.resolve4("1.1.1.1"))[0] === "1.1.1.1");
  check("dns.resolve6 wrong-family throws on IPv4 literal",
    await _throwsAsync(function () { return dnsModule.resolve6("1.1.1.1"); }, "dns/wrong-family"));
  check("dns.resolveAaaa is alias for resolve6",
    typeof dnsModule.resolveAaaa === "function");

  // ---- DNS resultOrder ipv6first reaches DoH/DoT path too ----
  dnsModule.setResultOrder("ipv6first");
  dnsModule.setCacheTtlMs(60_000);
  var dnsState = dnsModule._stateForTest();
  check("setResultOrder ipv6first reflected in state", dnsState.resultOrder === "ipv6first");
  _resetAll();

  // ---- NTP thresholds ----
  ntpCheck.setThresholds({ warnMs: 1000, fatalMs: 60000 });
  var thr = ntpCheck.getThresholds();
  check("ntpCheck thresholds tunable", thr.warnMs === 1000 && thr.fatalMs === 60000);
  check("ntpCheck setThresholds rejects warn > fatal",
    _throws(function () { ntpCheck.setThresholds({ warnMs: 99999, fatalMs: 1000 }); }));
  ntpCheck._resetThresholdsForTest();
  ntp.setServers(["nts1.example.com", "nts2.example.com"]);
  check("ntp.getServers reflects override",
    ntp.getServers().length === 2 && ntp.getServers()[0] === "nts1.example.com");

  // ---- NTS AES-SIV-CMAC-256 round-trip ----
  var k = nodeCrypto.randomBytes(32);
  var pt = Buffer.from("authenticated-time", "utf8");
  var aad = [Buffer.from("ad-1"), Buffer.from("ad-2")];
  var ct = nts.aesSivEncrypt(k, pt, aad);
  var rt = nts.aesSivDecrypt(k, ct, aad);
  check("nts AES-SIV round-trip yields plaintext", Buffer.compare(rt, pt) === 0);
  check("nts AES-SIV detects tampered AAD", _throws(function () {
    nts.aesSivDecrypt(k, ct, [Buffer.from("ad-1"), Buffer.from("ad-3")]);
  }, "nts/auth-failed"));
  check("nts AES-SIV detects tampered ciphertext", _throws(function () {
    var tampered = Buffer.from(ct);
    tampered[tampered.length - 1] ^= 1;
    nts.aesSivDecrypt(k, tampered, aad);
  }, "nts/auth-failed"));

  // ---- bootFromEnv ----
  _resetAll();
  var applied = network.bootFromEnv({
    env: {
      BLAMEJS_NTP_SERVERS:           "ntp1.example.com,ntp2.example.com",
      BLAMEJS_NTP_TIMEOUT_MS:        "1500",
      BLAMEJS_NTP_DRIFT_WARN_MS:     "30000",
      BLAMEJS_NTP_DRIFT_FATAL_MS:    "120000",
      BLAMEJS_DNS_SERVERS:           "10.0.0.53",
      BLAMEJS_DNS_RESULT_ORDER:      "ipv4first",
      BLAMEJS_DNS_FAMILY:            "4",
      BLAMEJS_DNS_LOOKUP_TIMEOUT_MS: "2000",
      BLAMEJS_DNS_CACHE_TTL_MS:      "10000",
      HTTP_PROXY:                    "http://proxy.corp:3128",
      NO_PROXY:                      ".internal",
      BLAMEJS_SOCKET_NO_DELAY:       "1",
      BLAMEJS_SOCKET_KEEPALIVE:      "true",
    },
    audit: false,
  });
  check("bootFromEnv applied ntp servers", applied.ntp.servers === 2);
  check("bootFromEnv applied dns resolver", applied.dns.servers === 1 && applied.dns.resultOrder === "ipv4first");
  check("bootFromEnv applied proxy", applied.proxy === true);
  check("bootFromEnv applied socket defaults",
    applied.socket.noDelay === true && applied.socket.keepAlive === true);
  ntpCheck._resetThresholdsForTest();
  _resetAll();

  // ---- snapshot shape ----
  var s = network.snapshot();
  check("snapshot exposes ntp/dns/proxy/tls/heartbeat/socket buckets",
    !!s.ntp && !!s.dns && !!s.proxy && !!s.tls && Array.isArray(s.heartbeat) && !!s.socket);

  // ---- Password policy: bundled top-10000 dictionary ----
  var policy = b.auth.password.policy({ minLength: 4 });
  var weak = await policy.check("password");
  check("password.policy rejects 'password' via bundled top-10000",
    weak.ok === false && weak.code === "policy/forbidden-common");
  var weak2 = await policy.check("dragon");
  check("password.policy rejects 'dragon' via bundled top-10000",
    weak2.ok === false && weak2.code === "policy/forbidden-common");
  var strong = await policy.check("Tr0ub4dor&3-correct-horse");
  check("password.policy accepts strong plaintext", strong.ok === true);
  var sum = policy.describe();
  check("password.policy describe reports bundled count >= 10000",
    sum.bundledCommonCount >= 10000);
  var noBundle = b.auth.password.policy({ minLength: 4, useBundledCommon: false });
  var bypassed = await noBundle.check("password");
  check("password.policy useBundledCommon:false bypasses bundled dictionary",
    bypassed.ok === true);
  var bypassSum = noBundle.describe();
  check("password.policy describe reports 0 bundled when disabled",
    bypassSum.bundledCommonCount === 0);

  // ---- Azure presigned policy: now throws NOT_SUPPORTED (was silent PUT URL) ----
  var azureBackend = null;
  try {
    var azureMod = require("./../../lib/object-store/azure-blob");
    azureBackend = azureMod.create({
      accountName:  "testacct",
      accountKey:   "dGVzdGtleS1hdC1sZWFzdC0zMi1ieXRlcy1sb25nLXBhZHBhZA==",
      container:    "c",
    });
  } catch (_e) { azureBackend = null; }
  if (azureBackend && typeof azureBackend.presignedUploadPolicy === "function") {
    check("azure-blob.presignedUploadPolicy throws PRESIGN_NOT_SUPPORTED",
      _throws(function () { azureBackend.presignedUploadPolicy({ maxBytes: 100 }); }, "objectstore/presign-not-supported"));
  } else {
    helpers.unavailable("azure-blob backend constructible (skipped if not)");
  }

  // ---- NTS auth: server reply without AUTHENTICATOR_AND_ENC must fail closed ----
  // A spoofed UDP server mirrors the request's unique identifier in an
  // NTPv4 reply that carries no authenticator extension. RFC 8915 section
  // 5.7 has the client discard an unauthenticated datagram and keep
  // waiting, so the query runs to its timeout and then rejects with the
  // reason the datagram was discarded (nts/no-authenticator) rather than
  // nts/timeout. A short timeout keeps the wait small; the reply arrives
  // over loopback well inside it.
  var ntsTestKey = nodeCrypto.randomBytes(32);
  var dgram = require("node:dgram");
  var ntsTimeoutMs = 300;
  var ntsReplied = false;
  await new Promise(function (resolveT) {
    var srv = dgram.createSocket("udp4");
    srv.bind(0, "127.0.0.1", async function () {
      var port = srv.address().port;
      srv.on("message", function (msg, rinfo) {
        if (msg.length < 48 + 36) { srv.close(); return; }
        var unique = msg.slice(52, 84);
        var reply = Buffer.alloc(48 + 36);
        reply[0] = 0x24;
        reply.writeUInt32BE(0xe10dee30, 40);
        reply.writeUInt32BE(0, 44);
        reply.writeUInt16BE(0x0104, 48);
        reply.writeUInt16BE(36, 50);
        unique.copy(reply, 52);
        srv.send(reply, 0, reply.length, rinfo.port, rinfo.address, function (sendErr) {
          if (!sendErr) ntsReplied = true;
          srv.close();
        });
      });
      var startedAt = Date.now();
      try {
        await nts.querySingle({
          host:     "127.0.0.1",
          port:     port,
          aeadId:   nts.AEAD_AES_SIV_CMAC_256,
          c2sKey:   ntsTestKey,
          s2cKey:   ntsTestKey,
          cookies:  [Buffer.from("c1")],
          timeoutMs: ntsTimeoutMs,
        });
        check("NTS rejects reply without AUTHENTICATOR_AND_ENC", false);
      } catch (e) {
        var waitedMs = Date.now() - startedAt;
        check("NTS: the spoofed reply was sent before the query settled", ntsReplied);
        check("NTS rejects reply without AUTHENTICATOR_AND_ENC",
          (e.code || "").indexOf("nts/no-authenticator") !== -1, e.code + " " + e.message);
        check("NTS keeps waiting after discarding the unauthenticated reply",
          waitedMs >= ntsTimeoutMs - 20, waitedMs + "ms");
      }
      resolveT();
    });
  });
  check("NTS querySingle requires non-empty s2cKey",
    _throws(function () {
      nts.querySingle({ host: "x", port: 123, aeadId: 15, c2sKey: ntsTestKey, s2cKey: null, cookies: [Buffer.from("a")] });
    }, "nts/no-s2c-key"));
}

function _throws(fn, expectedCodeSubstr) {
  try { fn(); }
  catch (e) {
    if (!expectedCodeSubstr) return true;
    var hay = (e.code || "") + " " + (e.message || "");
    return hay.indexOf(expectedCodeSubstr) !== -1;
  }
  return false;
}

async function _throwsAsync(fn, expectedCodeSubstr) {
  try { await fn(); return false; }
  catch (e) {
    if (!expectedCodeSubstr) return true;
    var hay = (e.code || "") + " " + (e.message || "");
    return hay.indexOf(expectedCodeSubstr) !== -1;
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[network] OK"); },
    function (e) { console.error(e); process.exit(1); }
  );
}
