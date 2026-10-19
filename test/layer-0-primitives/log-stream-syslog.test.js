// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Syslog sink address handling.
 *
 * The UDP sink resolves the URL host before it opens its socket, and the
 * socket family follows the address the name resolves to: a name that has
 * only an AAAA record is delivered over udp6, and a name with an A record
 * over udp4. A bracketed IPv6 literal in the URL is dialed without its
 * brackets on every transport. A TLS sink sends the host as SNI when it is
 * a name and sends no SNI for an IP literal.
 *
 * Name resolution goes through node:dns `lookup`, which the test replaces
 * for two reserved `.test` names so the AAAA-only and A-only cases do not
 * depend on the host's resolver.
 */

var dgram   = require("node:dgram");
var dns     = require("node:dns");
var net     = require("node:net");
var nodeTls = require("node:tls");
var os      = require("node:os");
var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

var syslog = require("../../lib/log-stream-syslog");

var V6_ONLY = "syslog-v6-only.test";
var V4_ONLY = "syslog-v4-only.test";

function _hasIpv6Loopback() {
  var ifaces = os.networkInterfaces();
  return Object.keys(ifaces).some(function (name) {
    return (ifaces[name] || []).some(function (a) {
      return (a.family === "IPv6" || a.family === 6) && a.address === "::1";
    });
  });
}

// Answers the two test names from a fixed table; every other name goes to
// the real resolver. `failNext` makes the next lookup of a test name fail.
function _stubLookup() {
  var orig = dns.lookup;
  var state = { calls: 0, failNext: false };
  var table = {};
  table[V6_ONLY] = [{ address: "::1", family: 6 }];
  table[V4_ONLY] = [{ address: "127.0.0.1", family: 4 }];
  dns.lookup = function (host, opts, cb) {
    if (typeof opts === "function") { cb = opts; opts = {}; }
    if (typeof opts === "number") opts = { family: opts };
    opts = opts || {};
    if (!Object.prototype.hasOwnProperty.call(table, host)) return orig.apply(dns, arguments);
    state.calls += 1;
    var addrs = table[host];
    if (opts.family === 4 || opts.family === 6) {
      addrs = addrs.filter(function (a) { return a.family === opts.family; });
    }
    var failing = state.failNext;
    state.failNext = false;
    process.nextTick(function () {
      if (failing || addrs.length === 0) {
        var e = new Error("getaddrinfo ENOTFOUND " + host);
        e.code = "ENOTFOUND";
        return cb(e);
      }
      if (opts.all) return cb(null, addrs.slice());
      cb(null, addrs[0].address, addrs[0].family);
    });
  };
  state.restore = function () { dns.lookup = orig; };
  return state;
}

function _udpListen(type, address) {
  return new Promise(function (resolve, reject) {
    var sock = dgram.createSocket(type);
    var got = [];
    sock.on("message", function (m) { got.push(m.toString("utf8")); });
    sock.once("error", reject);
    sock.bind(0, address, function () {
      resolve({
        port: sock.address().port, got: got,
        close: function () { return new Promise(function (r) { sock.close(r); }); },
      });
    });
  });
}

function _tcpListen(host) {
  return new Promise(function (resolve) {
    var got = [];
    var sockets = [];
    var server = net.createServer(function (s) {
      sockets.push(s);
      s.on("data", function (d) { got.push(d.toString("utf8")); });
      s.on("error", function () { /* client teardown */ });
    });
    server.listen(0, host, function () {
      resolve({
        port: server.address().port, got: got,
        close: function () {
          sockets.forEach(function (s) { try { s.destroy(); } catch (_e) { /* best-effort */ } });
          return new Promise(function (r) { server.close(r); });
        },
      });
    });
  });
}

function _tlsListen(leaf, host) {
  return new Promise(function (resolve) {
    var got = [];
    var sni = [];
    var sockets = [];
    var server = nodeTls.createServer({ key: leaf.key, cert: leaf.cert }, function (s) {
      sni.push(s.servername || null);
      s.on("data", function (d) { got.push(d.toString("utf8")); });
      s.on("error", function () { /* client teardown */ });
    });
    server.on("connection", function (raw) { sockets.push(raw); });
    server.on("tlsClientError", function () { /* the delivery check reports it */ });
    server.listen(0, host, function () {
      resolve({
        port: server.address().port, got: got, sni: sni,
        close: function () {
          sockets.forEach(function (s) { try { s.destroy(); } catch (_e) { /* best-effort */ } });
          return new Promise(function (r) { server.close(r); });
        },
      });
    });
  });
}

function _record(message) {
  return { ts: Date.now(), level: "info", message: message, meta: {} };
}

// b.logStream redacts the message text before a sink sees it, and a long
// digit run can match a card-number pattern. The markers sent through
// b.logStream below therefore carry no digits; each case has its own
// listener, so a fixed marker is enough to identify its datagram.
async function testUdpFamilyFollowsTheResolvedAddress(v6) {
  var stub = _stubLookup();
  try {
    if (v6) {
      var srv6 = await _udpListen("udp6", "::1");
      var marker6 = "aaaa-only-delivery";
      try {
        b.logStream.init({ sinks: { s: { protocol: "syslog", url: "udp://" + V6_ONLY + ":" + srv6.port } } });
        b.logStream.info(marker6);
        await helpers.waitUntil(function () {
          return srv6.got.some(function (m) { return m.indexOf(marker6) !== -1; });
        }, { timeoutMs: 5000, label: "syslog udp: a datagram to an AAAA-only name arrives on ::1" });
        check("syslog udp: an AAAA-only host name is delivered over IPv6", true);
      } finally {
        await b.logStream.shutdown();
        await srv6.close();
      }
    }

    var srv4 = await _udpListen("udp4", "127.0.0.1");
    var marker4 = "a-only-delivery";
    try {
      b.logStream.init({ sinks: { s: { protocol: "syslog", url: "udp://" + V4_ONLY + ":" + srv4.port } } });
      b.logStream.info(marker4);
      await helpers.waitUntil(function () {
        return srv4.got.some(function (m) { return m.indexOf(marker4) !== -1; });
      }, { timeoutMs: 5000, label: "syslog udp: a datagram to an A-only name arrives on 127.0.0.1" });
      check("syslog udp: an A-only host name is delivered over IPv4", true);
    } finally {
      await b.logStream.shutdown();
      await srv4.close();
    }

    // A failed lookup drops that record through onDrop; the next emit
    // resolves again and is delivered.
    var srvR = await _udpListen("udp4", "127.0.0.1");
    var drops = [];
    var sink = syslog.create({
      url: "udp://" + V4_ONLY + ":" + srvR.port,
      onDrop: function (info) { drops.push(info); },
    });
    try {
      stub.failNext = true;
      var first = await sink.emit(_record("lost-" + Date.now()));
      check("syslog udp: a failed lookup reports the record as not accepted",
        first && first.accepted === false, JSON.stringify(first));
      await helpers.waitUntil(function () { return drops.length >= 1; },
        { timeoutMs: 5000, label: "syslog udp: the failed lookup reaches onDrop" });
      check("syslog udp: the failed lookup is reported as udp-resolve-error",
        drops[0] && drops[0].reason === "udp-resolve-error", JSON.stringify(drops[0]));
      var markerR = "after-retry-" + Date.now();
      var second = await sink.emit(_record(markerR));
      check("syslog udp: the next emit resolves again and is accepted",
        second && second.accepted === true, JSON.stringify(second));
      await helpers.waitUntil(function () {
        return srvR.got.some(function (m) { return m.indexOf(markerR) !== -1; });
      }, { timeoutMs: 5000, label: "syslog udp: the retried datagram arrives" });
    } finally {
      await sink.close();
      await srvR.close();
    }

    var closedSink = syslog.create({ url: "udp://" + V4_ONLY + ":9" });
    await closedSink.close();
    var afterClose = await closedSink.emit(_record("after-close"));
    check("syslog udp: emit after close is not accepted",
      afterClose && afterClose.accepted === false && afterClose.reason === "closed", JSON.stringify(afterClose));
  } finally {
    stub.restore();
  }
}

async function testBracketedIpv6LiteralIsDialed() {
  var udp = await _udpListen("udp6", "::1");
  var markerU = "v6-literal-udp-" + Date.now();
  var sinkU = syslog.create({ url: "udp://[::1]:" + udp.port });
  try {
    var r = await sinkU.emit(_record(markerU));
    check("syslog udp: a bracketed IPv6 literal is accepted", r && r.accepted === true, JSON.stringify(r));
    await helpers.waitUntil(function () {
      return udp.got.some(function (m) { return m.indexOf(markerU) !== -1; });
    }, { timeoutMs: 5000, label: "syslog udp: the datagram to [::1] arrives" });
  } finally {
    await sinkU.close();
    await udp.close();
  }

  var tcp = await _tcpListen("::1");
  var markerT = "v6-literal-tcp-" + Date.now();
  var sinkT = syslog.create({ url: "tcp://[::1]:" + tcp.port, reconnectBaseMs: 50 });
  try {
    await sinkT.emit(_record(markerT));
    await helpers.waitUntil(function () {
      return tcp.got.join("").indexOf(markerT) !== -1;
    }, { timeoutMs: 5000, label: "syslog tcp: the frame to [::1] arrives" });
    check("syslog tcp: a bracketed IPv6 literal is dialed", true);
  } finally {
    await sinkT.close();
    await tcp.close();
  }
}

async function testTlsServerNameFollowsTheHost(v6) {
  var ca = await b.mtlsEngine.generateCa({ name: "syslog-sni-test-ca" });
  var leaf = await b.mtlsEngine.signClientCert({
    cn: "localhost", caCertPem: ca.caCertPem, caKeyPem: ca.caKeyPem,
    usage: "server", sans: ["DNS:localhost", "IP:127.0.0.1", "IP:::1"], validityDays: 1,
  });
  var cases = [
    { label: "host name",           bind: "127.0.0.1", host: "localhost", sni: "localhost" },
    { label: "IPv4 host",           bind: "127.0.0.1", host: "127.0.0.1", sni: null },
    { label: "IPv4 servername",     bind: "127.0.0.1", host: "127.0.0.1", servername: "127.0.0.1", sni: null },
    { label: "explicit name",       bind: "127.0.0.1", host: "127.0.0.1", servername: "localhost", sni: "localhost" },
  ];
  if (v6) cases.push({ label: "bracketed IPv6 host", bind: "::1", host: "[::1]", sni: null });
  for (var i = 0; i < cases.length; i += 1) {
    var tc = cases[i];
    var srv = await _tlsListen(leaf, tc.bind);
    var marker = "tls-" + i + "-" + Date.now();
    var cfg = { url: "tls://" + tc.host + ":" + srv.port, ca: ca.caCertPem, reconnectBaseMs: 50 };
    if (tc.servername !== undefined) cfg.servername = tc.servername;
    var sink = syslog.create(cfg);
    try {
      await sink.emit(_record(marker));
      await helpers.waitUntil(function () {
        return srv.got.join("").indexOf(marker) !== -1;
      }, { timeoutMs: 5000, label: "syslog tls: " + tc.label + ": the frame arrives" });
      check("syslog tls: " + tc.label + " sends SNI " + JSON.stringify(tc.sni),
        srv.sni.length >= 1 && srv.sni[0] === tc.sni, JSON.stringify(srv.sni));
    } finally {
      await sink.close();
      await srv.close();
    }
  }
}

// An IP-literal `servername` cannot be sent as SNI, and Node then checks the
// certificate against the URL host. A servername naming an address other than
// the host is refused at create, so the certificate is never checked against
// an identity the operator did not name. A servername that is not a non-empty
// string is refused too. The listener presents a certificate valid only for
// the DNS name `localhost`.
async function testIpServernameMustNameTheHost() {
  var ca = await b.mtlsEngine.generateCa({ name: "syslog-ip-sni-test-ca" });
  var leaf = await b.mtlsEngine.signClientCert({
    cn: "localhost", caCertPem: ca.caCertPem, caKeyPem: ca.caKeyPem,
    usage: "server", sans: ["DNS:localhost"], validityDays: 1,
  });
  var refused = [
    { label: "IPv4 servername on a host name",    host: "localhost", servername: "127.0.0.1" },
    { label: "bracketed IPv6 servername on IPv4", host: "127.0.0.1", servername: "[::1]" },
    { label: "different IPv4 servername",         host: "127.0.0.1", servername: "127.0.0.2" },
    { label: "non-string servername",             host: "localhost", servername: 7 },
  ];
  for (var i = 0; i < refused.length; i += 1) {
    var tc = refused[i];
    var srv = await _tlsListen(leaf, "127.0.0.1");
    var sink = null, err = null;
    var marker = "ip-sni-" + i + "-" + Date.now();
    try {
      sink = syslog.create({
        url: "tls://" + tc.host + ":" + srv.port, servername: tc.servername,
        ca: ca.caCertPem, reconnectBaseMs: 50,
      });
      await sink.emit(_record(marker));
      await helpers.passiveObserve(300, "syslog tls: " + tc.label + ": no frame arrives");
    } catch (e) { err = e; }
    try {
      check("syslog tls: " + tc.label + " is refused at create",
        sink === null && err && err.code === "log-stream-syslog/bad-opt" && /servername/.test(err.message),
        err ? ((err.code || "") + " " + err.message) : "delivered=" + (srv.got.join("").indexOf(marker) !== -1));
      check("syslog tls: " + tc.label + " completes no handshake",
        srv.sni.length === 0, JSON.stringify(srv.sni));
    } finally {
      if (sink) await sink.close();
      await srv.close();
    }
  }
  var same = syslog.create({ url: "tls://[::1]:6514", servername: "[::1]" });
  check("syslog tls: the host's own IPv6 address in brackets is accepted",
    typeof same.emit === "function");
  await same.close();
  // The comparison is by address, not by spelling.
  var spelled = null;
  try { spelled = syslog.create({ url: "tls://[::1]:6514", servername: "0:0:0:0:0:0:0:1" }); }
  catch (e) { spelled = e; }
  check("syslog tls: the host's own IPv6 address written out in full is accepted",
    spelled && typeof spelled.emit === "function", spelled && spelled.message);
  if (spelled && typeof spelled.close === "function") await spelled.close();
}

// The UDP target resolver lives in b.network.dns: the system resolver, an
// IPv4 answer preferred, and an IP literal (bracketed or not) returned
// without a lookup.
async function testUdpTargetResolver() {
  var networkDns = require("../../lib/network-dns");
  check("network-dns carries the UDP target resolver",
    typeof networkDns._resolveUdpTarget === "function");
  if (typeof networkDns._resolveUdpTarget !== "function") return;
  var stub = _stubLookup();
  var table = null;
  try {
    var v6lit = await networkDns._resolveUdpTarget("[::1]");
    var v4lit = await networkDns._resolveUdpTarget("127.0.0.1");
    var callsBefore = stub.calls;
    var named = await networkDns._resolveUdpTarget(V4_ONLY);
    table = { v6lit: v6lit, v4lit: v4lit, named: named, lookups: stub.calls - callsBefore };
  } finally { stub.restore(); }
  check("the UDP resolver returns a bracketed IPv6 literal without its brackets",
    table.v6lit.address === "::1" && table.v6lit.family === 6, JSON.stringify(table.v6lit));
  check("the UDP resolver returns an IPv4 literal as given",
    table.v4lit.address === "127.0.0.1" && table.v4lit.family === 4, JSON.stringify(table.v4lit));
  check("the UDP resolver asks the system resolver for a name",
    table.lookups === 1 && table.named.address === "127.0.0.1" && table.named.family === 4,
    JSON.stringify(table));
  var origLookup = dns.lookup;
  dns.lookup = function (host, opts, cb) {
    if (typeof opts === "function") cb = opts;
    process.nextTick(function () {
      cb(null, [{ address: "::1", family: 6 }, { address: "127.0.0.1", family: 4 }]);
    });
  };
  var preferred;
  try { preferred = await networkDns._resolveUdpTarget("dual-stack.test"); }
  finally { dns.lookup = origLookup; }
  check("the UDP resolver prefers an IPv4 answer",
    preferred.address === "127.0.0.1" && preferred.family === 4, JSON.stringify(preferred));
}

async function run() {
  var v6 = _hasIpv6Loopback();
  if (!v6) helpers.unavailable("syslog: IPv6 delivery cases", "no ::1 loopback on this host");
  await testUdpFamilyFollowsTheResolvedAddress(v6);
  if (v6) await testBracketedIpv6LiteralIsDialed();
  await testTlsServerNameFollowsTheHost(v6);
  await testIpServernameMustNameTheHost();
  await testUdpTargetResolver();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[log-stream-syslog] OK: " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
