// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * network-dns — error / defensive / adversarial branch coverage.
 *
 * The happy-path wire round-trips (DoH / DoT / system A+AAAA) live in the
 * live integration suite (test/integration/network-dns.test.js). This file
 * drives the PUBLIC b.network.dns surface offline to reach the config-time
 * throws, malformed-reply parse branches, classifier edge cases, cache
 * hit/miss paths, IP-literal short-circuits, transport-selection errors,
 * and the raw-query transport failure branches — using loopback fake TCP
 * responders + closed-port fault injection, never a real external endpoint
 * and never rejectUnauthorized:false.
 */

var net = require("node:net");

var helpers = require("../helpers");
var b = helpers.b;
var check = helpers.check;

var dnsModule = b.network.dns;

// ---- local throw helpers (per-file, matching sibling tests) ----------
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

// ---- DNS wire-format builders (test-side) ----------------------------
function _qname(name) {
  if (name === "" || name === ".") return Buffer.from([0]);
  var parts = name.split(".").filter(Boolean);
  var len = 1;
  for (var i = 0; i < parts.length; i++) len += 1 + parts[i].length;
  var buf = Buffer.alloc(len);
  var off = 0;
  for (var p = 0; p < parts.length; p++) {
    var lab = parts[p];
    buf.writeUInt8(lab.length, off++);
    buf.write(lab, off, "ascii");
    off += lab.length;
  }
  buf.writeUInt8(0, off);
  return buf;
}

function _buildReply(qname, qtype, answers, flags) {
  var qn = _qname(qname);
  var qtail = Buffer.alloc(4);
  qtail.writeUInt16BE(qtype, 0);
  qtail.writeUInt16BE(1, 2);
  var hdr = Buffer.alloc(12);
  hdr.writeUInt16BE(0xabcd, 0);
  hdr.writeUInt16BE(flags === undefined ? 0x8180 : flags, 2);
  hdr.writeUInt16BE(1, 4);
  hdr.writeUInt16BE(answers.length, 6);
  var parts = [hdr, qn, qtail];
  for (var a = 0; a < answers.length; a++) {
    var ans = answers[a];
    parts.push(_qname(ans.name || qname));
    var ah = Buffer.alloc(10);
    ah.writeUInt16BE(ans.type, 0);
    ah.writeUInt16BE(1, 2);
    ah.writeUInt32BE(ans.ttl || 60, 4);
    ah.writeUInt16BE(ans.rdata.length, 8);
    parts.push(ah, ans.rdata);
  }
  return Buffer.concat(parts);
}

function _svcbRd(priority, target, params) {
  var prio = Buffer.alloc(2);
  prio.writeUInt16BE(priority, 0);
  var pieces = [prio, _qname(target)];
  for (var i = 0; i < params.length; i++) {
    var h = Buffer.alloc(4);
    h.writeUInt16BE(params[i].key, 0);
    h.writeUInt16BE(params[i].value.length, 2);
    pieces.push(h, params[i].value);
  }
  return Buffer.concat(pieces);
}

function _alpn(protos) {
  var pieces = [];
  for (var i = 0; i < protos.length; i++) {
    pieces.push(Buffer.from([protos[i].length]));
    pieces.push(Buffer.from(protos[i], "ascii"));
  }
  return Buffer.concat(pieces);
}

// ---- loopback fixtures -----------------------------------------------
function _startTcpResponder(replyBytes) {
  return new Promise(function (resolve) {
    var srv = net.createServer(function (sock) {
      var got = [];
      var expected = -1;
      sock.on("data", function (chunk) {
        got.push(chunk);
        var all = Buffer.concat(got);
        if (expected === -1 && all.length >= 2) expected = all.readUInt16BE(0);
        if (expected >= 0 && all.length >= expected + 2) {
          var rlen = Buffer.alloc(2);
          rlen.writeUInt16BE(replyBytes.length, 0);
          sock.write(rlen);
          sock.write(replyBytes);
          sock.end();
        }
      });
      sock.on("error", function () { /* fixture best-effort */ });
    });
    srv.unref();
    srv.listen(0, "127.0.0.1", function () {
      resolve({ srv: srv, port: srv.address().port });
    });
  });
}

// Accepts the TCP connection then immediately tears it down — models an
// upstream that closes before sending any reply.
function _startCloseImmediately() {
  return new Promise(function (resolve) {
    var srv = net.createServer(function (sock) {
      sock.on("error", function () { /* fixture best-effort */ });
      sock.destroy();
    });
    srv.unref();
    srv.listen(0, "127.0.0.1", function () {
      resolve({ srv: srv, port: srv.address().port });
    });
  });
}

// A 127.0.0.1 port with nothing listening (bind → capture → close).
function _probeClosedPort() {
  return new Promise(function (resolve) {
    var s = net.createServer();
    s.unref();
    s.listen(0, "127.0.0.1", function () {
      var p = s.address().port;
      s.close(function () { resolve(p); });
    });
  });
}

function _reset() {
  if (typeof dnsModule._resetForTest === "function") dnsModule._resetForTest();
}

// Reset, then poll until every TCP client/server handle the DNS primitive
// opened has actually closed (socket.destroy finalizes asynchronously).
async function _drainTcpHandles() {
  _reset();
  if (typeof process.getActiveResourcesInfo !== "function") return;
  await helpers.waitUntil(function () {
    return process.getActiveResourcesInfo().filter(function (t) {
      return t === "TCPSocketWrap" || t === "TCPServerWrap";
    }).length === 0;
  }, { timeoutMs: 5000, label: "network-dns-coverage: TCP handle drain" });
}

// ======================================================================
// Config setters — throw-on-bad-input + success branches
// ======================================================================
function testSetServers() {
  _reset();
  check("setServers: non-array throws dns/bad-servers",
    _throws(function () { dnsModule.setServers(null); }, "dns/bad-servers"));
  check("setServers: empty array throws dns/bad-servers",
    _throws(function () { dnsModule.setServers([]); }, "dns/bad-servers"));
  check("setServers: non-string element throws dns/bad-server",
    _throws(function () { dnsModule.setServers(["1.2.3.4", 123]); }, "dns/bad-server"));
  check("setServers: empty-string element throws dns/bad-server",
    _throws(function () { dnsModule.setServers(["1.2.3.4", ""]); }, "dns/bad-server"));
  check("setServers: invalid resolver address throws dns/setservers-failed",
    _throws(function () { dnsModule.setServers(["not-an-ip-at-all"]); }, "dns/setservers-failed"));

  _reset();
  dnsModule.setServers(["127.0.0.1", "9.9.9.9"]);
  var got = dnsModule.getServers();
  check("setServers: valid list persists + getServers returns a copy",
    Array.isArray(got) && got.indexOf("127.0.0.1") !== -1 && got.indexOf("9.9.9.9") !== -1);
  got.push("mutation");
  check("getServers: returns a defensive copy (mutation does not leak)",
    dnsModule.getServers().indexOf("mutation") === -1);
  _reset();
  check("getServers: falls back to OS resolvers (array) when unset",
    Array.isArray(dnsModule.getServers()));
}

function testSetResultOrder() {
  _reset();
  check("setResultOrder: bad value throws dns/bad-result-order",
    _throws(function () { dnsModule.setResultOrder("random"); }, "dns/bad-result-order"));
  dnsModule.setResultOrder("ipv4first");
  check("setResultOrder: ipv4first stored", dnsModule._stateForTest().resultOrder === "ipv4first");
  dnsModule.setResultOrder("verbatim");
  check("setResultOrder: verbatim stored", dnsModule._stateForTest().resultOrder === "verbatim");
  dnsModule.setResultOrder("ipv6first");
  check("setResultOrder: ipv6first stored (mapped to verbatim in node)",
    dnsModule._stateForTest().resultOrder === "ipv6first");
  _reset();
}

function testSetFamily() {
  _reset();
  check("setFamily: bad value throws dns/bad-family",
    _throws(function () { dnsModule.setFamily(5); }, "dns/bad-family"));
  dnsModule.setFamily(0);
  check("setFamily: 0 accepted", dnsModule._stateForTest().family === 0);
  dnsModule.setFamily(4);
  check("setFamily: 4 accepted", dnsModule._stateForTest().family === 4);
  dnsModule.setFamily(6);
  check("setFamily: 6 accepted", dnsModule._stateForTest().family === 6);
  _reset();
}

function testSetLookupTimeout() {
  _reset();
  check("setLookupTimeoutMs: non-number throws dns/bad-timeout",
    _throws(function () { dnsModule.setLookupTimeoutMs("5s"); }, "dns/bad-timeout"));
  check("setLookupTimeoutMs: NaN throws dns/bad-timeout",
    _throws(function () { dnsModule.setLookupTimeoutMs(NaN); }, "dns/bad-timeout"));
  check("setLookupTimeoutMs: Infinity throws dns/bad-timeout",
    _throws(function () { dnsModule.setLookupTimeoutMs(Infinity); }, "dns/bad-timeout"));
  check("setLookupTimeoutMs: negative throws dns/bad-timeout",
    _throws(function () { dnsModule.setLookupTimeoutMs(-1); }, "dns/bad-timeout"));
  dnsModule.setLookupTimeoutMs(1234);
  check("setLookupTimeoutMs: valid value stored", dnsModule._stateForTest().lookupTimeoutMs === 1234);
  _reset();
}

function testSetCacheTtl() {
  _reset();
  check("setCacheTtlMs: non-number throws dns/bad-cache-ttl",
    _throws(function () { dnsModule.setCacheTtlMs("nope"); }, "dns/bad-cache-ttl"));
  check("setCacheTtlMs: negative throws dns/bad-cache-ttl",
    _throws(function () { dnsModule.setCacheTtlMs(-5); }, "dns/bad-cache-ttl"));
  check("setCacheTtlMs: bad negativeMs throws dns/bad-cache-ttl",
    _throws(function () { dnsModule.setCacheTtlMs(1000, -1); }, "dns/bad-cache-ttl"));
  dnsModule.setCacheTtlMs(5000, 2500);
  check("setCacheTtlMs: positive ms + negativeMs stored",
    dnsModule._stateForTest().cacheTtlMs === 5000 &&
    dnsModule._stateForTest().cacheNegativeTtlMs === 2500);
  dnsModule.setCacheTtlMs(0);
  check("setCacheTtlMs: 0 disables + clears (cacheTtlMs=0)",
    dnsModule._stateForTest().cacheTtlMs === 0);
  _reset();
}

function testUseDnsOverHttps() {
  _reset();
  dnsModule.useDnsOverHttps({ provider: "cloudflare" });
  check("useDnsOverHttps: provider=cloudflare resolves url",
    dnsModule._stateForTest().doh.url.indexOf("cloudflare-dns.com") !== -1);
  _reset();
  dnsModule.useDnsOverHttps({ provider: "google" });
  check("useDnsOverHttps: provider=google resolves url",
    dnsModule._stateForTest().doh.url.indexOf("dns.google") !== -1);
  _reset();
  dnsModule.useDnsOverHttps({ provider: "quad9" });
  check("useDnsOverHttps: provider=quad9 resolves url",
    dnsModule._stateForTest().doh.url.indexOf("quad9") !== -1);
  _reset();
  check("useDnsOverHttps: unknown provider throws dns/bad-doh-provider",
    _throws(function () { dnsModule.useDnsOverHttps({ provider: "myisp" }); }, "dns/bad-doh-provider"));
  check("useDnsOverHttps: non-https url throws dns/bad-doh-url",
    _throws(function () { dnsModule.useDnsOverHttps({ url: "http://insecure/dns" }); }, "dns/bad-doh-url"));
  check("useDnsOverHttps: bad method throws dns/bad-doh-method",
    _throws(function () { dnsModule.useDnsOverHttps({ url: "https://x/dns", method: "PUT" }); }, "dns/bad-doh-method"));
  check("useDnsOverHttps: bad ca type throws dns/bad-doh-ca",
    _throws(function () { dnsModule.useDnsOverHttps({ url: "https://x/dns", ca: 123 }); }, "dns/bad-doh-ca"));
  check("useDnsOverHttps: unknown opt key throws (validate-opts)",
    _throws(function () { dnsModule.useDnsOverHttps({ url: "https://x/dns", bogus: 1 }); }));
  _reset();
  dnsModule.useDnsOverHttps({ url: "https://doh.example/dns-query", method: "POST" });
  check("useDnsOverHttps: explicit url+method configured",
    dnsModule._stateForTest().doh.url === "https://doh.example/dns-query" &&
    dnsModule._stateForTest().doh.method === "POST");
  _reset();
}

function testUseDnsOverTls() {
  _reset();
  check("useDnsOverTls: missing host throws dns/bad-dot-host",
    _throws(function () { dnsModule.useDnsOverTls({ port: 853 }); }, "dns/bad-dot-host"));
  check("useDnsOverTls: bad port throws dns/bad-dot-port",
    _throws(function () { dnsModule.useDnsOverTls({ host: "1.1.1.1", port: -5 }); }, "dns/bad-dot-port"));
  check("useDnsOverTls: bad ca type throws dns/bad-dot-ca",
    _throws(function () { dnsModule.useDnsOverTls({ host: "1.1.1.1", ca: 42 }); }, "dns/bad-dot-ca"));
  check("useDnsOverTls: unknown opt key throws (validate-opts)",
    _throws(function () { dnsModule.useDnsOverTls({ host: "1.1.1.1", nope: 1 }); }));
  _reset();
  dnsModule.useDnsOverTls({ host: "1.1.1.1" });
  var st = dnsModule._stateForTest();
  check("useDnsOverTls: defaults port 853 + servername=host",
    st.dot.host === "1.1.1.1" && st.dot.port === 853 && st.dot.servername === "1.1.1.1");
  _reset();
}

function testUseSystemResolver() {
  _reset();
  dnsModule.useDnsOverHttps({ url: "https://x/dns" });
  dnsModule.useSystemResolver();
  var st = dnsModule._stateForTest();
  check("useSystemResolver: clears doh/dot + sets systemResolver",
    st.doh === null && st.dot === null && st.systemResolver === true);
  _reset();
}

// ======================================================================
// Classifiers — pure, never throw
// ======================================================================
function testIsNullMx() {
  check("isNullMx: non-array is false", dnsModule.isNullMx(null) === false);
  check("isNullMx: empty array is false", dnsModule.isNullMx([]) === false);
  check("isNullMx: two records is false",
    dnsModule.isNullMx([{ priority: 0, exchange: "." }, { priority: 1, exchange: "mx" }]) === false);
  check("isNullMx: non-object element is false", dnsModule.isNullMx([null]) === false);
  check("isNullMx: non-zero priority is false",
    dnsModule.isNullMx([{ priority: 10, exchange: "." }]) === false);
  check("isNullMx: priority 0 + exchange '' is null-mx (node shape)",
    dnsModule.isNullMx([{ priority: 0, exchange: "" }]) === true);
  check("isNullMx: priority 0 + exchange '.' is null-mx (literal root)",
    dnsModule.isNullMx([{ priority: 0, exchange: "." }]) === true);
  check("isNullMx: real exchange is not null-mx",
    dnsModule.isNullMx([{ priority: 0, exchange: "mail.example.com" }]) === false);
}

function testClassifyDnskeyAlgorithm() {
  check("classifyDnskeyAlgorithm: non-integer returns null",
    dnsModule.classifyDnskeyAlgorithm(1.5) === null);
  check("classifyDnskeyAlgorithm: string returns null",
    dnsModule.classifyDnskeyAlgorithm("13") === null);
  check("classifyDnskeyAlgorithm: NaN returns null",
    dnsModule.classifyDnskeyAlgorithm(NaN) === null);
  var sha1 = dnsModule.classifyDnskeyAlgorithm(5);
  check("classifyDnskeyAlgorithm: 5 RSASHA1 deprecated+known",
    sha1 && sha1.deprecated === true && sha1.known === true && sha1.name === "RSASHA1");
  var ec = dnsModule.classifyDnskeyAlgorithm(13);
  check("classifyDnskeyAlgorithm: 13 ECDSAP256SHA256 current",
    ec && ec.deprecated === false && ec.known === true);
  var reserved = dnsModule.classifyDnskeyAlgorithm(4);
  check("classifyDnskeyAlgorithm: 4 Reserved is deprecated+known",
    reserved && reserved.deprecated === true && reserved.known === true);
  var unassigned = dnsModule.classifyDnskeyAlgorithm(17);
  check("classifyDnskeyAlgorithm: 17 unassigned → known:false",
    unassigned && unassigned.known === false && unassigned.deprecated === false);
  var priv = dnsModule.classifyDnskeyAlgorithm(253);
  check("classifyDnskeyAlgorithm: 253 PRIVATEDNS known+not-deprecated",
    priv && priv.known === true && priv.deprecated === false);
}

function testClassifyDsDigestType() {
  check("classifyDsDigestType: non-integer returns null",
    dnsModule.classifyDsDigestType(2.2) === null);
  var sha1 = dnsModule.classifyDsDigestType(1);
  check("classifyDsDigestType: 1 SHA-1 deprecated+known",
    sha1 && sha1.deprecated === true && sha1.known === true);
  var sha256 = dnsModule.classifyDsDigestType(2);
  check("classifyDsDigestType: 2 SHA-256 current",
    sha256 && sha256.deprecated === false && sha256.known === true);
  var reserved = dnsModule.classifyDsDigestType(0);
  check("classifyDsDigestType: 0 Reserved deprecated+known",
    reserved && reserved.deprecated === true && reserved.known === true);
  var unassigned = dnsModule.classifyDsDigestType(7);
  check("classifyDsDigestType: 7 unassigned → known:false",
    unassigned && unassigned.known === false);
}

// ======================================================================
// SVCB rdata parse — malformed + valid variants (direct call)
// ======================================================================
function _parseAt0(rd) { return dnsModule._parseSvcbRdata(rd, 0, rd.length); }

function testParseSvcbMalformed() {
  var parse = dnsModule._parseSvcbRdata;
  check("parseSvcb: rdlen < 2 throws (truncated before priority)",
    _throws(function () { parse(Buffer.alloc(4), 0, 1); }, "dns/svcb-malformed"));

  // priority(2) + root name(0x00) + 3 dangling bytes → SvcParam header truncated
  var hdrTrunc = Buffer.concat([Buffer.from([0, 1]), Buffer.from([0]), Buffer.from([0, 0, 0])]);
  check("parseSvcb: dangling SvcParam header throws (header truncated)",
    _throws(function () { return _parseAt0(hdrTrunc); }, "dns/svcb-malformed"));

  // key present but paramLen overflows rdata
  var overflow = Buffer.concat([Buffer.from([0, 1]), Buffer.from([0]),
    Buffer.from([0, 1]), Buffer.from([0, 5])]);
  check("parseSvcb: SvcParam value overflow throws",
    _throws(function () { return _parseAt0(overflow); }, "dns/svcb-malformed"));

  check("parseSvcb: mandatory odd length throws",
    _throws(function () {
      return _parseAt0(_svcbRd(1, ".", [{ key: 0, value: Buffer.from([0]) }]));
    }, "dns/svcb-malformed"));
  check("parseSvcb: no-default-alpn with non-zero length throws",
    _throws(function () {
      return _parseAt0(_svcbRd(1, ".", [{ key: 2, value: Buffer.from([0]) }]));
    }, "dns/svcb-malformed"));
  check("parseSvcb: port wrong length throws",
    _throws(function () {
      return _parseAt0(_svcbRd(1, ".", [{ key: 3, value: Buffer.from([1]) }]));
    }, "dns/svcb-malformed"));
  check("parseSvcb: ipv4hint length not multiple of 4 throws",
    _throws(function () {
      return _parseAt0(_svcbRd(1, ".", [{ key: 4, value: Buffer.from([1, 2, 3]) }]));
    }, "dns/svcb-malformed"));
  check("parseSvcb: ipv6hint length not multiple of 16 throws",
    _throws(function () {
      return _parseAt0(_svcbRd(1, ".", [{ key: 6, value: Buffer.alloc(15) }]));
    }, "dns/svcb-malformed"));
  check("parseSvcb: alpn char-string overflow throws",
    _throws(function () {
      return _parseAt0(_svcbRd(1, ".", [{ key: 1, value: Buffer.from([5]) }]));
    }, "dns/svcb-malformed"));
}

function testParseSvcbValidVariants() {
  // no-default-alpn (key 2, zero length) → noDefaultAlpn true
  var ndAlpn = _parseAt0(_svcbRd(1, "svc.example.net", [{ key: 2, value: Buffer.alloc(0) }]));
  check("parseSvcb: no-default-alpn (zero length) → noDefaultAlpn true",
    ndAlpn.params.noDefaultAlpn === true);

  // AliasMode with root target "." → target "."
  var rootAlias = _parseAt0(Buffer.concat([Buffer.from([0, 0]), _qname(".")]));
  check("parseSvcb: root target renders as '.'",
    rootAlias.priority === 0 && rootAlias.target === ".");

  // dohpath (key 7) utf8
  var dp = _parseAt0(_svcbRd(2, "svc.example.net",
    [{ key: 7, value: Buffer.from("/dns-query{?dns}", "utf8") }]));
  check("parseSvcb: dohpath decodes utf8", dp.params.dohpath === "/dns-query{?dns}");

  // ech (key 5) opaque buffer
  var ech = _parseAt0(_svcbRd(3, "svc.example.net",
    [{ key: 5, value: Buffer.from([0xfe, 0x0d, 0x00]) }]));
  check("parseSvcb: ech surfaced as opaque buffer",
    Buffer.isBuffer(ech.params.ech) && ech.params.ech.length === 3);
}

// ======================================================================
// _decodeDnsAnswerRaw — adversarial reply framing (direct call)
// ======================================================================
function testDecodeAnswerRaw() {
  var dec = dnsModule._decodeDnsAnswerRaw;
  check("_decodeDnsAnswerRaw: non-buffer throws dns/bad-reply",
    _throws(function () { dec("notabuffer"); }, "dns/bad-reply"));
  check("_decodeDnsAnswerRaw: <12 bytes throws dns/bad-reply",
    _throws(function () { dec(Buffer.alloc(6)); }, "dns/bad-reply"));

  // rcode != 0 (SERVFAIL=2) → dns/no-result
  var servfail = Buffer.alloc(12);
  servfail.writeUInt8(0x02, 3);
  check("_decodeDnsAnswerRaw: non-zero rcode throws dns/no-result",
    _throws(function () { dec(servfail); }, "dns/no-result"));

  // ancount claims 1 but no answer bytes follow the question → record truncated
  var recTrunc = _buildReply("example.com", 1, []);
  recTrunc.writeUInt16BE(1, 6); // lie: ancount = 1
  check("_decodeDnsAnswerRaw: answer record header truncated throws dns/bad-reply",
    _throws(function () { dec(recTrunc); }, "dns/bad-reply"));

  // valid A answer but rdlen lies past buffer end → rdata truncated
  var okReply = _buildReply("example.com", 1,
    [{ name: "example.com", type: 1, rdata: Buffer.from([1, 2, 3, 4]) }]);
  // bump the last answer's rdlen (offset = length-2-4) to overflow
  okReply.writeUInt16BE(0x00ff, okReply.length - 6);
  check("_decodeDnsAnswerRaw: answer rdata truncated throws dns/bad-reply",
    _throws(function () { dec(okReply); }, "dns/bad-reply"));

  // clean decode of a well-formed reply
  var clean = dec(_buildReply("example.com", 1,
    [{ name: "example.com", type: 1, rdata: Buffer.from([9, 9, 9, 9]) }]));
  check("_decodeDnsAnswerRaw: well-formed reply yields one answer + ad=false",
    clean.answers.length === 1 && clean.ad === false);
}

// ======================================================================
// _readDnsName — pointer + termination adversarial branches (direct call)
// ======================================================================
function testReadDnsName() {
  var rd = dnsModule._readDnsName;

  // compression pointer as the very last byte → truncated at pointer
  var ptrTrunc = Buffer.from([0xc0]);
  check("_readDnsName: pointer truncated at last byte throws",
    _throws(function () { rd(ptrTrunc, 0); }, "dns/svcb-malformed"));

  // pointer target beyond buffer length → out of bounds
  var ptrOob = Buffer.from([0xc0, 0x40]); // points to offset 64, buf len 2
  check("_readDnsName: pointer out of bounds throws",
    _throws(function () { rd(ptrOob, 0); }, "dns/svcb-malformed"));

  // labels with no terminating 0 and no pointer → not terminated
  var noTerm = Buffer.from([3, 0x61, 0x62, 0x63]); // "abc" then EOF
  check("_readDnsName: unterminated name throws",
    _throws(function () { rd(noTerm, 0); }, "dns/svcb-malformed"));

  // valid: two labels then root
  var ok = Buffer.concat([_qname("a.bc")]);
  var res = rd(ok, 0);
  check("_readDnsName: valid name decodes labels + nextOff",
    res.name === "a.bc" && res.nextOff === ok.length);

  // valid forward compression pointer: name at 0 = "x" + pointer to a
  // root label sitting later in the buffer.
  var buf = Buffer.alloc(8);
  buf[0] = 1; buf[1] = 0x78;          // label "x"
  buf[2] = 0xc0; buf[3] = 0x05;       // pointer to offset 5
  buf[5] = 0;                         // root at offset 5
  var pres = rd(buf, 0);
  check("_readDnsName: forward pointer resolves + nextOff after pointer",
    pres.name === "x" && pres.nextOff === 4);
}

// ======================================================================
// lookup — IP literal short-circuit + cache + local-form system path
// ======================================================================
async function testLookupIpLiteral() {
  _reset();
  var v4 = await dnsModule.lookup("203.0.113.7");
  check("lookup: IPv4 literal returns {address,family:4} without resolution",
    v4.address === "203.0.113.7" && v4.family === 4);
  var v4all = await dnsModule.lookup("203.0.113.7", { all: true });
  check("lookup: IPv4 literal all:true returns single-element array",
    Array.isArray(v4all) && v4all.length === 1 && v4all[0].family === 4);
  var v6 = await dnsModule.lookup("2001:db8::1");
  check("lookup: IPv6 literal returns family 6", v6.family === 6);
  _reset();
}

async function testLookupLocalFormAndCache() {
  _reset();
  dnsModule.setCacheTtlMs(60000);
  dnsModule.setLookupTimeoutMs(4000);
  var first = await dnsModule.lookup("localhost");
  check("lookup: localhost resolves via system path (loopback)",
    typeof first.address === "string" && (first.family === 4 || first.family === 6));
  var second = await dnsModule.lookup("localhost");
  check("lookup: second localhost lookup returns same address (positive cache hit)",
    first.address === second.address);
  var allForm = await dnsModule.lookup("localhost", { all: true });
  check("lookup: all:true from cache returns array", Array.isArray(allForm));
  dnsModule.clearCache();
  var third = await dnsModule.lookup("localhost");
  check("lookup: resolves again after clearCache", typeof third.address === "string");
  _reset();
}

async function testLookupNegativeCache() {
  _reset();
  dnsModule.useSystemResolver();
  dnsModule.setCacheTtlMs(60000, 60000);
  dnsModule.setLookupTimeoutMs(4000);
  var e1 = null;
  try { await dnsModule.lookup("no-such-host-zzz.invalid"); }
  catch (e) { e1 = e; }
  if (e1) {
    var e2 = null;
    try { await dnsModule.lookup("no-such-host-zzz.invalid"); }
    catch (e) { e2 = e; }
    check("lookup: negative cache re-throws the SAME error instance (cache hit)",
      e2 !== null && e2 === e1);
  } else {
    check("lookup: negative-cache path (host unexpectedly resolved; skipped)", true);
  }
  _reset();
}

async function testLookupOrderingBranches() {
  // Drive _orderAddrs ipv6first + ipv4first sort branches through the
  // local-form system path (localhost may return >=1 address).
  _reset();
  dnsModule.setResultOrder("ipv6first");
  dnsModule.setLookupTimeoutMs(4000);
  var a = await dnsModule.lookup("localhost", { all: true });
  check("lookup: ipv6first ordering path returns array", Array.isArray(a) && a.length >= 1);
  _reset();
  dnsModule.setResultOrder("ipv4first");
  dnsModule.setLookupTimeoutMs(4000);
  var c = await dnsModule.lookup("localhost", { all: true });
  check("lookup: ipv4first ordering path returns array", Array.isArray(c) && c.length >= 1);
  _reset();
}

async function testLookupDohDotNoResult() {
  // DoH configured but pointed at a closed port: _dualStack catches both
  // family failures → normalized empty → dns/no-result.
  _reset();
  var closed = await _probeClosedPort();
  dnsModule.useDnsOverHttps({ url: "https://127.0.0.1:" + closed + "/dns-query" });
  dnsModule.setLookupTimeoutMs(1500);
  check("lookup(DoH, dead upstream): both families fail → dns/no-result",
    await _throwsAsync(function () { return dnsModule.lookup("public.example.com"); }, "dns/no-result"));
  _reset();

  // DoT configured at a closed port: handshake failure per family → empty → no-result.
  var closed2 = await _probeClosedPort();
  dnsModule.useDnsOverTls({ host: "127.0.0.1", port: closed2, servername: "localhost" });
  dnsModule.setLookupTimeoutMs(1500);
  check("lookup(DoT, dead upstream): handshake fails → dns/no-result",
    await _throwsAsync(function () { return dnsModule.lookup("public.example.com"); }, "dns/no-result"));
  await _drainTcpHandles();
}

// ======================================================================
// resolve / _resolveProtocol — IP literal, wrong-family, transport errors
// ======================================================================
async function testResolveProtocol() {
  _reset();
  check("resolve4: bad host throws dns/bad-host",
    await _throwsAsync(function () { return dnsModule.resolve4(""); }, "dns/bad-host"));
  var r4 = await dnsModule.resolve4("198.51.100.9");
  check("resolve4: IPv4 literal short-circuits to [literal]",
    Array.isArray(r4) && r4[0] === "198.51.100.9");
  check("resolve4: IPv6 literal is wrong family",
    await _throwsAsync(function () { return dnsModule.resolve4("2001:db8::5"); }, "dns/wrong-family"));
  var r6 = await dnsModule.resolve6("2001:db8::5");
  check("resolve6: IPv6 literal short-circuits", Array.isArray(r6) && r6[0] === "2001:db8::5");
  check("resolve6: IPv4 literal is wrong family",
    await _throwsAsync(function () { return dnsModule.resolve6("198.51.100.9"); }, "dns/wrong-family"));
  var r6a = await dnsModule.resolveAaaa("2001:db8::9");
  check("resolveAaaa: IPv6 literal short-circuits", Array.isArray(r6a) && r6a[0] === "2001:db8::9");
  _reset();
}

async function testResolveTransportErrors() {
  _reset();
  var closed = await _probeClosedPort();
  dnsModule.useDnsOverHttps({ url: "https://127.0.0.1:" + closed + "/dns-query" });
  dnsModule.setLookupTimeoutMs(1500);
  check("resolve4(auto DoH, dead upstream): surfaces DnsError",
    await _throwsAsync(function () { return dnsModule.resolve4("public.example.com"); }));
  _reset();

  var closed2 = await _probeClosedPort();
  dnsModule.useDnsOverTls({ host: "127.0.0.1", port: closed2, servername: "localhost" });
  dnsModule.setLookupTimeoutMs(1500);
  check("resolve4(auto DoT, dead upstream): surfaces DnsError",
    await _throwsAsync(function () { return dnsModule.resolve4("public.example.com"); }));
  await _drainTcpHandles();
}

async function testResolveDispatch() {
  _reset();
  // lowercase type is uppercased; A dispatch via IP literal (offline).
  var a = await dnsModule.resolve("192.0.2.10", "a");
  check("resolve: lowercase 'a' dispatches to A + short-circuits literal",
    Array.isArray(a) && a[0] === "192.0.2.10");
  var aaaa = await dnsModule.resolve("2001:db8::7", "aaaa");
  check("resolve: 'aaaa' dispatches to AAAA literal",
    Array.isArray(aaaa) && aaaa[0] === "2001:db8::7");
  check("resolve: unsupported type throws dns/unsupported-type",
    await _throwsAsync(function () { return dnsModule.resolve("example.com", "TXT"); }, "dns/unsupported-type"));

  // HTTPS dispatch → queryHttps, exercised via a system TCP responder.
  var reply = _buildReply("example.com", 65, [{
    name: "example.com", type: 65,
    rdata: _svcbRd(1, "svc.example.net", [{ key: 1, value: _alpn(["h2"]) }]),
  }]);
  var fix = await _startTcpResponder(reply);
  dnsModule.useSystemResolver();
  dnsModule.setServers(["127.0.0.1:" + fix.port]);
  dnsModule.setLookupTimeoutMs(5000);
  var https = await dnsModule.resolve("example.com", "HTTPS", { transport: "system" });
  check("resolve: 'HTTPS' dispatches to queryHttps (system transport)",
    Array.isArray(https) && https.length === 1 && https[0].params.alpn[0] === "h2");
  fix.srv.close();
  await _drainTcpHandles();
}

// ======================================================================
// resolveSecure — validation branches + DoH error path
// ======================================================================
async function testResolveSecure() {
  _reset();
  dnsModule.useSystemResolver();
  check("resolveSecure: no DoH transport throws dns/secure-requires-doh",
    await _throwsAsync(function () { return dnsModule.resolveSecure("example.com"); }, "dns/secure-requires-doh"));
  _reset();
  dnsModule.useDnsOverHttps({ url: "https://x.example/dns-query" });
  check("resolveSecure: empty host throws dns/bad-host",
    await _throwsAsync(function () { return dnsModule.resolveSecure(""); }, "dns/bad-host"));
  check("resolveSecure: >253 char host throws dns/bad-host",
    await _throwsAsync(function () {
      return dnsModule.resolveSecure(("a".repeat(60) + ".").repeat(5) + "example.com");
    }, "dns/bad-host"));
  check("resolveSecure: oversize label throws dns/bad-host",
    await _throwsAsync(function () {
      return dnsModule.resolveSecure("a".repeat(64) + ".example.com");
    }, "dns/bad-host"));
  check("resolveSecure: non-LDH label (underscore) throws dns/bad-host",
    await _throwsAsync(function () {
      return dnsModule.resolveSecure("bad_label.example.com");
    }, "dns/bad-host"));
  check("resolveSecure: unsupported type throws dns/secure-unsupported-type",
    await _throwsAsync(function () {
      return dnsModule.resolveSecure("example.com", "TXT");
    }, "dns/secure-unsupported-type"));
  _reset();

  // Valid host + type but dead DoH upstream → DoH error path executes.
  var closed = await _probeClosedPort();
  dnsModule.useDnsOverHttps({ url: "https://127.0.0.1:" + closed + "/dns-query" });
  dnsModule.setLookupTimeoutMs(1500);
  check("resolveSecure: valid A query against dead upstream surfaces DnsError",
    await _throwsAsync(function () { return dnsModule.resolveSecure("example.com", "A"); }));
  check("resolveSecure: valid AAAA query against dead upstream surfaces DnsError",
    await _throwsAsync(function () { return dnsModule.resolveSecure("example.com", "AAAA"); }));
  await _drainTcpHandles();
}

// ======================================================================
// reverse — input validation
// ======================================================================
async function testReverse() {
  _reset();
  check("reverse: non-string throws dns/bad-ip",
    await _throwsAsync(function () { return dnsModule.reverse(12345); }, "dns/bad-ip"));
  check("reverse: empty string throws dns/bad-ip",
    await _throwsAsync(function () { return dnsModule.reverse(""); }, "dns/bad-ip"));
  check("reverse: non-IP string throws dns/bad-ip",
    await _throwsAsync(function () { return dnsModule.reverse("definitely-not-an-ip"); }, "dns/bad-ip"));
  _reset();
}

// ======================================================================
// nodeLookup — callback adapter (offline via IP literal + local form)
// ======================================================================
function _nodeLookupP(host, options) {
  return new Promise(function (resolve, reject) {
    function cb(err) {
      if (err) return reject(err);
      resolve(Array.prototype.slice.call(arguments, 1));
    }
    if (options === undefined) dnsModule.nodeLookup(host, cb);
    else dnsModule.nodeLookup(host, options, cb);
  });
}

async function testNodeLookup() {
  _reset();
  var single = await _nodeLookupP("192.0.2.55"); // options omitted → function-as-options branch
  check("nodeLookup: options-omitted callback yields (address, family)",
    single[0] === "192.0.2.55" && single[1] === 4);
  var all = await _nodeLookupP("192.0.2.55", { all: true });
  check("nodeLookup: all:true yields an array in first callback arg",
    Array.isArray(all[0]) && all[0][0].address === "192.0.2.55");

  // error path via callback (local-form NXDOMAIN)
  dnsModule.useSystemResolver();
  dnsModule.setLookupTimeoutMs(4000);
  var errored = false;
  try { await _nodeLookupP("no-host-abc-xyz.invalid"); }
  catch (e) { errored = !!e; }
  check("nodeLookup: resolution failure surfaces via callback(err)", errored);
  _reset();
}

// ======================================================================
// _systemRawQuery — transport failure branches (loopback fixtures)
// ======================================================================
async function testSystemRawQueryErrors() {
  // Upstream closes before replying → dns/system-failed.
  _reset();
  var closer = await _startCloseImmediately();
  dnsModule.useSystemResolver();
  dnsModule.setServers(["127.0.0.1:" + closer.port]);
  dnsModule.setLookupTimeoutMs(3000);
  check("querySvcb(system): upstream close-before-reply → dns/system-failed",
    await _throwsAsync(function () {
      return dnsModule.querySvcb("example.com", { transport: "system" });
    }, "dns/system-failed"));
  closer.srv.close();
  await _drainTcpHandles();

  // Connection refused → dns/system-failed.
  _reset();
  var refused = await _probeClosedPort();
  dnsModule.useSystemResolver();
  dnsModule.setServers(["127.0.0.1:" + refused]);
  dnsModule.setLookupTimeoutMs(3000);
  check("querySvcb(system): connection refused → dns/system-failed",
    await _throwsAsync(function () {
      return dnsModule.querySvcb("example.com", { transport: "system" });
    }, "dns/system-failed"));
  await _drainTcpHandles();
}

async function testSystemRawQueryV6Bracket() {
  // Exercise the "[ipv6]:port" server-address parsing branch. Best-effort:
  // skips cleanly when the runner lacks IPv6 loopback.
  _reset();
  var port = null;
  try {
    port = await new Promise(function (resolve, reject) {
      var s = net.createServer();
      s.unref();
      s.on("error", reject);
      s.listen(0, "::1", function () {
        var p = s.address().port;
        s.close(function () { resolve(p); });
      });
    });
  } catch (_e) { port = null; }
  if (port === null) {
    check("querySvcb(system): [::1]:port bracket parse (skipped — no IPv6 loopback)", true);
    _reset();
    return;
  }
  dnsModule.useSystemResolver();
  dnsModule.setServers(["[::1]:" + port]);
  dnsModule.setLookupTimeoutMs(2000);
  // Nothing listening on that ::1 port → connect refused → system-failed,
  // but the bracket-parse branch runs on the way there.
  check("querySvcb(system): [::1]:port bracket address parsed (refused → DnsError)",
    await _throwsAsync(function () {
      return dnsModule.querySvcb("example.com", { transport: "system" });
    }));
  await _drainTcpHandles();
}

// ======================================================================
// discoverEncrypted — mapping + no-transport + alias-skip branches
// ======================================================================
async function testDiscoverEncryptedBranches() {
  // name must be a string.
  _reset();
  check("discoverEncrypted: non-string name throws dns/bad-host",
    await _throwsAsync(function () { return dnsModule.discoverEncrypted({ name: 12345 }); }, "dns/bad-host"));

  // NXDOMAIN (rcode 3) upstream → mapped to dns/ddr-not-discovered.
  _reset();
  var nx = _buildReply("_dns.resolver.arpa", 64, [], 0x8183);
  var nxFix = await _startTcpResponder(nx);
  dnsModule.useSystemResolver();
  dnsModule.setServers(["127.0.0.1:" + nxFix.port]);
  dnsModule.setLookupTimeoutMs(5000);
  check("discoverEncrypted: NXDOMAIN mapped to dns/ddr-not-discovered",
    await _throwsAsync(function () { return dnsModule.discoverEncrypted(); }, "dns/ddr-not-discovered"));
  nxFix.srv.close();
  await _drainTcpHandles();

  // Only an AliasMode (priority 0) record present → all skipped → not-discovered.
  _reset();
  var aliasOnly = _buildReply("_dns.resolver.arpa", 64, [{
    name: "_dns.resolver.arpa", type: 64, rdata: _svcbRd(0, "alias.example.net", []),
  }]);
  var aliasFix = await _startTcpResponder(aliasOnly);
  dnsModule.useSystemResolver();
  dnsModule.setServers(["127.0.0.1:" + aliasFix.port]);
  dnsModule.setLookupTimeoutMs(5000);
  check("discoverEncrypted: alias-only records skipped → dns/ddr-not-discovered",
    await _throwsAsync(function () { return dnsModule.discoverEncrypted(); }, "dns/ddr-not-discovered"));
  aliasFix.srv.close();
  await _drainTcpHandles();

  // ServiceMode with an unrecognized alpn (no dot/h2/h3, no dohpath) → skipped.
  _reset();
  var noTransport = _buildReply("_dns.resolver.arpa", 64, [{
    name: "_dns.resolver.arpa", type: 64,
    rdata: _svcbRd(1, "svc.example.net", [{ key: 1, value: _alpn(["ftp"]) }]),
  }]);
  var ntFix = await _startTcpResponder(noTransport);
  dnsModule.useSystemResolver();
  dnsModule.setServers(["127.0.0.1:" + ntFix.port]);
  dnsModule.setLookupTimeoutMs(5000);
  check("discoverEncrypted: no recognized transport → dns/ddr-not-discovered",
    await _throwsAsync(function () { return dnsModule.discoverEncrypted(); }, "dns/ddr-not-discovered"));
  ntFix.srv.close();
  await _drainTcpHandles();

  // insecureSystemResolverOnly:false → transport auto (system here) still works.
  _reset();
  var good = _buildReply("_dns.resolver.arpa", 64, [{
    name: "_dns.resolver.arpa", type: 64,
    rdata: _svcbRd(1, "doh.example.net", [
      { key: 1, value: _alpn(["h2"]) },
      { key: 7, value: Buffer.from("/dns-query", "utf8") },
    ]),
  }]);
  var goodFix = await _startTcpResponder(good);
  dnsModule.useSystemResolver();
  dnsModule.setServers(["127.0.0.1:" + goodFix.port]);
  dnsModule.setLookupTimeoutMs(5000);
  var res = await dnsModule.discoverEncrypted({ insecureSystemResolverOnly: false });
  check("discoverEncrypted: insecureSystemResolverOnly:false auto transport returns a DoH descriptor",
    Array.isArray(res) && res.length === 1 && res[0].transport === "doh" && res[0].dohpath === "/dns-query");
  goodFix.srv.close();
  await _drainTcpHandles();
}

// ======================================================================
// useDesignatedResolvers — config-loop fallback branches
// ======================================================================
function testDesignatedResolversFallback() {
  // First entry passes pre-loop validation (https url) but fails to
  // configure (invalid method rejected by useDnsOverHttps) → caught,
  // second valid entry wins (active=1).
  _reset();
  var r = dnsModule.useDesignatedResolvers([
    { transport: "doh", url: "https://primary.example.net/dns-query", method: "PUT" },
    { transport: "doh", url: "https://secondary.example.net/dns-query" },
  ]);
  check("useDesignatedResolvers: first entry fails to configure → second wins (active=1)",
    r.active === 1 && r.count === 2 &&
    dnsModule._stateForTest().doh.url.indexOf("secondary") !== -1);
  _reset();

  // Every entry fails to configure → dns/dnr-no-resolvers with last error.
  check("useDesignatedResolvers: all entries fail → dns/dnr-no-resolvers",
    _throws(function () {
      dnsModule.useDesignatedResolvers([
        { transport: "doh", url: "https://only.example.net/dns-query", method: "PATCH" },
      ]);
    }, "dns/dnr-no-resolvers"));
  _reset();

  // A dot entry that passes host validation but fails port validation in
  // useDnsOverTls → caught → dnr-no-resolvers.
  check("useDesignatedResolvers: dot entry bad port → dnr-no-resolvers",
    _throws(function () {
      dnsModule.useDesignatedResolvers([
        { transport: "dot", host: "dot.example.net", port: -9 },
      ]);
    }, "dns/dnr-no-resolvers"));
  _reset();
}

async function run() {
  try {
    // sync config + classifier + parse branches
    testSetServers();
    testSetResultOrder();
    testSetFamily();
    testSetLookupTimeout();
    testSetCacheTtl();
    testUseDnsOverHttps();
    testUseDnsOverTls();
    testUseSystemResolver();
    testIsNullMx();
    testClassifyDnskeyAlgorithm();
    testClassifyDsDigestType();
    testParseSvcbMalformed();
    testParseSvcbValidVariants();
    testDecodeAnswerRaw();
    testReadDnsName();
    testDesignatedResolversFallback();

    // async / transport branches
    await testLookupIpLiteral();
    await testLookupLocalFormAndCache();
    await testLookupNegativeCache();
    await testLookupOrderingBranches();
    await testLookupDohDotNoResult();
    await testResolveProtocol();
    await testResolveTransportErrors();
    await testResolveDispatch();
    await testResolveSecure();
    await testReverse();
    await testNodeLookup();
    await testSystemRawQueryErrors();
    await testSystemRawQueryV6Bracket();
    await testDiscoverEncryptedBranches();
  } finally {
    await _drainTcpHandles();
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[network-dns-coverage] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
