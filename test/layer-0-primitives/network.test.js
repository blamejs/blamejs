"use strict";

var nodeCrypto = require("node:crypto");

var helpers = require("../helpers");
var check   = helpers.check;
var b       = helpers.b;

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
  await _sleep(250);
  var st = heartbeat.status("probe-test");
  check("heartbeat.status returns shape",
    st && (st.state === "down" || st.state === "degraded" || st.consecutiveFailures > 0));
  heartbeat.stop("probe-test");
  check("heartbeat.stop returns true on existing", heartbeat.status("probe-test") === null);
  _resetAll();

  // ---- Socket defaults ----
  network.socket.setDefaultNoDelay(false);
  network.socket.setDefaultKeepAlive({ enable: true, initialDelayMs: 30_000 });
  var defaults = network.socket.defaults();
  check("socket defaults reflect setters",
    defaults.noDelay === false && defaults.keepAlive === true && defaults.keepAliveInitialDelayMs === 30_000);
  check("socket setDefaultNoDelay rejects non-boolean",
    _throws(function () { network.socket.setDefaultNoDelay("yes"); }, "socket/bad-no-delay"));
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

function _sleep(ms) {
  return new Promise(function (resolve) { setTimeout(resolve, ms); });
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[network] OK"); },
    function (e) { console.error(e); process.exit(1); }
  );
}
