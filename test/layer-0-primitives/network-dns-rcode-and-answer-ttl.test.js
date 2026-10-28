// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.network.dns against a loopback DNS-over-HTTPS server.
 *
 * Response codes: a SERVFAIL or REFUSED reply is a resolver failure and rejects
 * with the transient `dns/server-failure`; NXDOMAIN and a NOERROR reply with no
 * records of the queried type reject with the permanent `dns/no-result`; any
 * other non-zero RCODE rejects with the permanent `dns/query-failed`. A
 * transient failure is not held in the negative cache.
 *
 * Connections and caching: the A and AAAA queries of a lookup, and the queries
 * of later lookups, share one HTTP/2 connection to a DoH server that speaks
 * HTTP/2. A lookup answer is cached for the answer's TTL by default, bounded
 * by `b.network.dns.setCacheTtlBounds`, and a changed record is returned once
 * that TTL has passed. A DoH server that speaks only HTTP/1.1 is answered on
 * the connection that found that out.
 */

var dgram = require("node:dgram");
var http2 = require("node:http2");
var net = require("node:net");
var nodeHttps = require("node:https");
var nodeTls = require("node:tls");

var helpers = require("../helpers");
var check = helpers.check;
var b = helpers.b;
var ck = require("../helpers/compromised-keys");

var dns = b.network.dns;

var RCODE_NOERROR  = 0;
var RCODE_FORMERR  = 1;
var RCODE_SERVFAIL = 2;
var RCODE_NXDOMAIN = 3;
var RCODE_NOTIMP   = 4;
var RCODE_REFUSED  = 5;

function _questionOf(query) {
  var labels = [];
  var off = 12;
  while (off < query.length && query[off] !== 0) {
    labels.push(query.toString("ascii", off + 1, off + 1 + query[off]));
    off += query[off] + 1;
  }
  return { name: labels.join(".").toLowerCase(), qtype: query.readUInt16BE(off + 1), end: off + 5 };
}

function _reply(query, answer) {
  var q = _questionOf(query);
  var hdr = Buffer.from(query.subarray(0, 12));
  hdr.writeUInt16BE(0x8180 | (answer.rcode || 0), 2);
  var records = answer.records || [];
  hdr.writeUInt16BE(records.length, 6);
  hdr.writeUInt16BE(0, 8);
  hdr.writeUInt16BE(0, 10);
  var parts = [hdr, query.subarray(12, q.end)];
  for (var i = 0; i < records.length; i++) {
    var rr = Buffer.alloc(12);
    rr.writeUInt16BE(0xc00c, 0);
    rr.writeUInt16BE(records[i].type, 2);
    rr.writeUInt16BE(1, 4);
    rr.writeUInt32BE(records[i].ttl, 6);
    rr.writeUInt16BE(records[i].rdata.length, 10);
    parts.push(rr, records[i].rdata);
  }
  return Buffer.concat(parts);
}

function _v4(text) { return Buffer.from(text.split(".").map(Number)); }
function _v6Last(n) { var v = Buffer.alloc(16); v[0] = 0x20; v[1] = 0x01; v[2] = 0x0d; v[3] = 0xb8; v[15] = n; return v; }

function _answerHandler(zone, stats) {
  return function (query) {
    var q = _questionOf(query);
    stats.queries.push(q.name + "/" + q.qtype);
    var entry = zone[q.name];
    if (!entry) return _reply(query, { rcode: RCODE_NXDOMAIN });
    if (typeof entry.rcode === "number" && entry.rcode !== RCODE_NOERROR) return _reply(query, { rcode: entry.rcode });
    if (q.qtype === 28 && typeof entry.aaaaRcode === "number") return _reply(query, { rcode: entry.aaaaRcode });
    var records = [];
    if (q.qtype === 1 && entry.a) records.push({ type: 1, ttl: entry.ttl, rdata: _v4(entry.a) });
    if (q.qtype === 28 && entry.aaaa !== undefined) records.push({ type: 28, ttl: entry.ttl, rdata: _v6Last(entry.aaaa) });
    return _reply(query, { rcode: RCODE_NOERROR, records: records });
  };
}

function _readQuery(req, cb) {
  var u = new URL(req.url, "https://localhost");
  var param = u.searchParams.get("dns");
  if (param) { cb(Buffer.from(param, "base64url")); return; }
  var body = [];
  req.on("data", function (c) { body.push(c); });
  req.on("end", function () { cb(Buffer.concat(body)); });
}

function _listen(server, stats) {
  var sockets = new Set();
  server.on("secureConnection", function (sock) {
    stats.connections += 1;
    sockets.add(sock);
    sock.on("close", function () { sockets.delete(sock); });
  });
  server.on("tlsClientError", function () { /* the client refused the chain */ });
  server.on("error", function () { /* fixture best-effort */ });
  return new Promise(function (resolve) {
    server.listen(0, "127.0.0.1", function () {
      stats.port = server.address().port;
      stats.openSockets = function () { return sockets.size; };
      stats.close = function () {
        sockets.forEach(function (s) { try { s.destroy(); } catch (_e) { /* teardown */ } });
        try { server.close(); } catch (_e) { /* teardown */ }
      };
      resolve(stats);
    });
  });
}

function _startH2Doh(chain, zone) {
  var stats = { connections: 0, queries: [], versions: [] };
  var answer = _answerHandler(zone, stats);
  var server = http2.createSecureServer({ key: chain.key, cert: chain.cert, allowHTTP1: true }, function (req, res) {
    stats.versions.push(req.httpVersion);
    _readQuery(req, function (query) {
      res.setHeader("content-type", "application/dns-message");
      res.end(answer(query));
    });
  });
  return _listen(server, stats);
}

function _startH1Doh(chain, zone) {
  var stats = { connections: 0, queries: [], versions: [] };
  var answer = _answerHandler(zone, stats);
  var server = nodeHttps.createServer({ key: chain.key, cert: chain.cert }, function (req, res) {
    stats.versions.push(req.httpVersion);
    _readQuery(req, function (query) {
      res.setHeader("content-type", "application/dns-message");
      res.end(answer(query));
    });
  });
  return _listen(server, stats);
}

function _startDot(chain, zone) {
  var stats = { connections: 0, queries: [], versions: [] };
  var answer = _answerHandler(zone, stats);
  var server = nodeTls.createServer({ key: chain.key, cert: chain.cert }, function (sock) {
    var got = Buffer.alloc(0);
    sock.on("error", function () { /* fixture best-effort */ });
    sock.on("data", function (chunk) {
      got = Buffer.concat([got, chunk]);
      while (got.length >= 2 && got.length >= got.readUInt16BE(0) + 2) {
        var len = got.readUInt16BE(0);
        var out = answer(got.subarray(2, 2 + len));
        var prefix = Buffer.alloc(2);
        prefix.writeUInt16BE(out.length, 0);
        sock.write(Buffer.concat([prefix, out]));
        got = got.subarray(2 + len);
      }
    });
  });
  return _listen(server, stats);
}

async function _failure(fn) {
  try { await fn(); return { code: "no-throw", permanent: undefined }; }
  catch (e) { return { code: e && e.code, permanent: e && e.permanent, error: e }; }
}

function _addrs(list) {
  return list.map(function (a) {
    return a.family === 6 ? new URL("http://[" + a.address + "]/").hostname.slice(1, -1) : a.address;
  }).sort().join(",");
}

async function testResponseCodes(chain) {
  var zone = {
    "sf.example.com":     { rcode: RCODE_SERVFAIL },
    "ref.example.com":    { rcode: RCODE_REFUSED },
    "form.example.com":   { rcode: RCODE_FORMERR },
    "notimp.example.com": { rcode: RCODE_NOTIMP },
    "nodata.example.com": { ttl: 60 },
    "v6sf.example.com":   { rcode: RCODE_SERVFAIL },
    "okdot.example.com":  { a: "192.0.2.50", ttl: 60 },
  };
  var srv = await _startH2Doh(chain, zone);
  dns._resetForTest();
  dns.useDnsOverHttps({ url: "https://127.0.0.1:" + srv.port + "/dns-query", ca: chain.rootCa });
  dns.setLookupTimeoutMs(5000);
  try {
    var cases = [
      ["SERVFAIL", "sf.example.com",   "dns/server-failure", false],
      ["REFUSED",  "ref.example.com",  "dns/server-failure", false],
      ["NXDOMAIN", "nx.example.com",   "dns/no-result",      true],
      ["NODATA",   "nodata.example.com", "dns/no-result",    true],
      ["FORMERR",  "form.example.com", "dns/query-failed",   true],
      ["NOTIMP",   "notimp.example.com", "dns/query-failed", true],
    ];
    for (var i = 0; i < cases.length; i++) {
      var c = cases[i];
      var viaLookup = await _failure(function () { return dns.lookup(c[1], { family: 4 }); });
      check("lookup (DoH): a " + c[0] + " reply rejects with " + c[2] + " (got " + viaLookup.code + ")",
            viaLookup.code === c[2]);
      check("lookup (DoH): the " + c[0] + " rejection is " + (c[3] ? "permanent" : "transient"),
            viaLookup.permanent === c[3], String(viaLookup.permanent));
      var viaResolve = await _failure(function () { return dns.resolve4(c[1]); });
      check("resolve4 (DoH): a " + c[0] + " reply rejects with " + c[2] + " (got " + viaResolve.code + ")",
            viaResolve.code === c[2]);
      if (c[0] !== "NODATA") {
        var viaSvcb = await _failure(function () { return dns.querySvcb(c[1], { transport: "doh" }); });
        check("querySvcb (DoH): a " + c[0] + " reply rejects with " + c[2] + " (got " + viaSvcb.code + ")",
              viaSvcb.code === c[2]);
      }
      if (c[0] === "NODATA") {
        var empty = await dns.resolveSecure(c[1], "A");
        check("resolveSecure (DoH): a NODATA reply answers with no records",
              Array.isArray(empty.rrs) && empty.rrs.length === 0);
      } else {
        var viaSecure = await _failure(function () { return dns.resolveSecure(c[1], "A"); });
        check("resolveSecure (DoH): a " + c[0] + " reply rejects with " + c[2] + " (got " + viaSecure.code + ")",
              viaSecure.code === c[2]);
      }
    }

    var dual = await _failure(function () { return dns.lookup("v6sf.example.com", { all: true }); });
    check("lookup (DoH, both families): a SERVFAIL on both queries rejects with the transient dns/server-failure (got " +
          dual.code + ")", dual.code === "dns/server-failure" && dual.permanent === false);

    check("a SERVFAIL rejection is retryable by b.retry",
          b.retry.isRetryable((await _failure(function () { return dns.resolve4("sf.example.com"); })).error) === true);
    check("an NXDOMAIN rejection is not retryable by b.retry",
          b.retry.isRetryable((await _failure(function () { return dns.resolve4("nx.example.com"); })).error) === false);

    dns.setCacheTtlMs(60000, 60000);
    var before = srv.queries.length;
    await _failure(function () { return dns.lookup("sf.example.com", { family: 4 }); });
    await _failure(function () { return dns.lookup("sf.example.com", { family: 4 }); });
    check("lookup: a transient SERVFAIL is not held in the negative cache (each lookup asks again)",
          srv.queries.length - before === 2, String(srv.queries.length - before));
    before = srv.queries.length;
    await _failure(function () { return dns.lookup("nx.example.com", { family: 4 }); });
    await _failure(function () { return dns.lookup("nx.example.com", { family: 4 }); });
    check("lookup: a permanent NXDOMAIN is held in the negative cache (the second lookup does not ask)",
          srv.queries.length - before === 1, String(srv.queries.length - before));
  } finally { srv.close(); dns._resetForTest(); }

  var dot = await _startDot(chain, zone);
  dns.useDnsOverTls({ host: "127.0.0.1", port: dot.port, servername: "localhost", ca: chain.rootCa });
  dns.setLookupTimeoutMs(5000);
  try {
    var dotSf = await _failure(function () { return dns.resolve4("sf.example.com"); });
    check("resolve4 (DoT): a SERVFAIL reply rejects with the transient dns/server-failure (got " + dotSf.code + ")",
          dotSf.code === "dns/server-failure" && dotSf.permanent === false);
    var dotRaw = await _failure(function () { return dns.querySvcb("ref.example.com", { transport: "dot" }); });
    check("querySvcb (DoT): a REFUSED reply rejects with dns/server-failure (got " + dotRaw.code + ")",
          dotRaw.code === "dns/server-failure");
    var dotNx = await _failure(function () { return dns.resolve4("nx.example.com"); });
    check("resolve4 (DoT): an NXDOMAIN reply rejects with the permanent dns/no-result (got " + dotNx.code + ")",
          dotNx.code === "dns/no-result" && dotNx.permanent === true);
    var asked = dot.queries.length;
    var after = await _failure(function () { return dns.resolve4("okdot.example.com"); });
    check("resolve4 (DoT): a query after a failed one on the same connection is sent and answered (got " +
          after.code + ", queries sent " + (dot.queries.length - asked) + ")",
          after.code === "no-throw" && dot.queries.length - asked === 1);
    check("DoT: every query above went to the server (queries=" + dot.queries.length + ")", dot.queries.length === 4);
  } finally { dot.close(); dns._resetForTest(); }

  var raw = dns._decodeDnsAnswerRaw;
  var hdr = Buffer.alloc(12);
  hdr.writeUInt16BE(0x8180 | RCODE_SERVFAIL, 2);
  check("_decodeDnsAnswerRaw: a SERVFAIL header raises dns/server-failure",
        (function () { try { raw(hdr); return "no-throw"; } catch (e) { return e.code; } })() === "dns/server-failure");
}

async function testOneConnectionAndAnswerTtl(chain) {
  var zone = {
    "pool.example.com":  { a: "192.0.2.10", aaaa: 10, ttl: 1 },
    "other.example.com": { a: "192.0.2.11", aaaa: 11, ttl: 300 },
    "zero.example.com":  { a: "192.0.2.12", ttl: 0 },
    "long.example.com":  { a: "192.0.2.13", ttl: 3600 },
  };
  var srv = await _startH2Doh(chain, zone);
  dns._resetForTest();
  dns.useDnsOverHttps({ url: "https://127.0.0.1:" + srv.port + "/dns-query", ca: chain.rootCa });
  dns.setLookupTimeoutMs(5000);
  try {
    var first = await dns.lookup("pool.example.com", { all: true });
    check("lookup (DoH, both families): returns the A and AAAA answers (got " + _addrs(first) + ")",
          _addrs(first) === "192.0.2.10,2001:db8::a");
    check("lookup (DoH, both families): the A and AAAA queries share one connection (connections=" +
          srv.connections + ", queries=" + srv.queries.length + ")",
          srv.connections === 1 && srv.queries.length === 2);
    check("the queries go over HTTP/2 when the DoH server speaks it (versions=" + srv.versions.join(",") + ")",
          srv.versions.length === 2 && srv.versions.every(function (v) { return v === "2.0"; }));

    await dns.lookup("other.example.com", { all: true });
    check("a later lookup reuses the same connection (connections=" + srv.connections + ")",
          srv.connections === 1 && srv.queries.length === 4);

    var cached = await dns.lookup("pool.example.com", { all: true });
    check("a repeat lookup inside the answer TTL is served from the cache by default (queries=" + srv.queries.length + ")",
          srv.queries.length === 4 && _addrs(cached) === "192.0.2.10,2001:db8::a");

    zone["pool.example.com"] = { a: "192.0.2.20", aaaa: 20, ttl: 1 };
    var stale = await dns.lookup("pool.example.com", { all: true });
    check("a changed record is not seen before the answer TTL has passed (got " + _addrs(stale) + ")",
          _addrs(stale) === "192.0.2.10,2001:db8::a");
    var fresh = null;
    await helpers.waitUntil(async function () {
      fresh = await dns.lookup("pool.example.com", { all: true });
      return _addrs(fresh) === "192.0.2.20,2001:db8::14";
    }, { timeoutMs: 5000, label: "network-dns: changed record seen after the 1s answer TTL" });
    check("a changed record is returned once the answer TTL has passed (got " + (fresh && _addrs(fresh)) + ")",
          fresh !== null && _addrs(fresh) === "192.0.2.20,2001:db8::14");

    var zeroBefore = srv.queries.length;
    await dns.lookup("zero.example.com", { family: 4 });
    await dns.lookup("zero.example.com", { family: 4 });
    check("an answer with TTL 0 is not cached by default (queries=" + (srv.queries.length - zeroBefore) + ")",
          srv.queries.length - zeroBefore === 2);

    dns.setCacheTtlBounds({ minMs: 60000 });
    zeroBefore = srv.queries.length;
    await dns.lookup("zero.example.com", { family: 4 });
    await dns.lookup("zero.example.com", { family: 4 });
    check("setCacheTtlBounds minMs caches an answer whose TTL is below it (queries=" +
          (srv.queries.length - zeroBefore) + ")", srv.queries.length - zeroBefore === 1);

    dns.setCacheTtlBounds({ maxMs: 50 });
    await dns.lookup("long.example.com", { family: 4 });
    zone["long.example.com"] = { a: "192.0.2.23", ttl: 3600 };
    var capped = null;
    await helpers.waitUntil(async function () {
      capped = await dns.lookup("long.example.com", { family: 4 });
      return capped.address === "192.0.2.23";
    }, { timeoutMs: 5000, label: "network-dns: maxMs caps a 3600s answer TTL" });
    check("setCacheTtlBounds maxMs caps a long answer TTL (got " + (capped && capped.address) + ")",
          capped !== null && capped.address === "192.0.2.23");

    dns.setCacheTtlMs(0);
    var offBefore = srv.queries.length;
    await dns.lookup("other.example.com", { family: 4 });
    await dns.lookup("other.example.com", { family: 4 });
    check("setCacheTtlMs(0) turns the cache off (queries=" + (srv.queries.length - offBefore) + ")",
          srv.queries.length - offBefore === 2);

    dns.setCacheTtlMs(60000);
    zone["pool.example.com"] = { a: "192.0.2.30", ttl: 0 };
    await dns.lookup("pool.example.com", { family: 4 });
    var fixedBefore = srv.queries.length;
    await dns.lookup("pool.example.com", { family: 4 });
    check("setCacheTtlMs(ms) caches for that fixed time, whatever the answer TTL (queries=" +
          (srv.queries.length - fixedBefore) + ")", srv.queries.length - fixedBefore === 0);

    check("setCacheTtlBounds: a negative minMs throws dns/bad-cache-ttl",
          (function () { try { dns.setCacheTtlBounds({ minMs: -1 }); return "no-throw"; } catch (e) { return e.code; } })() ===
          "dns/bad-cache-ttl");
    check("setCacheTtlBounds: minMs above maxMs throws dns/bad-cache-ttl",
          (function () { try { dns.setCacheTtlBounds({ minMs: 10, maxMs: 5 }); return "no-throw"; } catch (e) { return e.code; } })() ===
          "dns/bad-cache-ttl");
    check("setCacheTtlBounds: an unknown option throws",
          (function () { try { dns.setCacheTtlBounds({ maxTtl: 5 }); return "no-throw"; } catch (_e) { return "threw"; } })() ===
          "threw");
    check("connections over the whole run (connections=" + srv.connections + ")", srv.connections === 1);
  } finally { srv.close(); dns._resetForTest(); }
}

async function testHttp1OnlyServer(chain) {
  var zone = { "h1.example.com": { a: "192.0.2.40", aaaa: 40, ttl: 60 } };
  var srv = await _startH1Doh(chain, zone);
  dns._resetForTest();
  dns.useDnsOverHttps({ url: "https://127.0.0.1:" + srv.port + "/dns-query", ca: chain.rootCa });
  dns.setLookupTimeoutMs(5000);
  try {
    var r = await dns.resolve4("h1.example.com");
    check("resolve4 (DoH, HTTP/1.1-only server): answers (got " + r.join(",") + ")", r.join(",") === "192.0.2.40");
    check("an HTTP/1.1-only DoH server is asked on the connection that found it out (connections=" +
          srv.connections + ")", srv.connections === 1);
    var all = await dns.lookup("h1.example.com", { all: true });
    check("lookup (DoH, HTTP/1.1-only server): both families answer (got " + _addrs(all) + ")",
          _addrs(all) === "192.0.2.40,2001:db8::28");
  } finally { srv.close(); dns._resetForTest(); }
}

async function testPartialAnswerAfterTransientFailure(chain) {
  var zone = { "half.example.com": { a: "192.0.2.60", aaaa: 60, ttl: 300, aaaaRcode: RCODE_SERVFAIL } };
  var srv = await _startH2Doh(chain, zone);
  dns._resetForTest();
  dns.useDnsOverHttps({ url: "https://127.0.0.1:" + srv.port + "/dns-query", ca: chain.rootCa });
  dns.setLookupTimeoutMs(5000);
  try {
    var partial = await dns.lookup("half.example.com", { all: true });
    check("lookup (DoH, both families): the A answer is returned when the AAAA query gets SERVFAIL (got " +
          _addrs(partial) + ")", _addrs(partial) === "192.0.2.60");
    delete zone["half.example.com"].aaaaRcode;
    var before = srv.queries.length;
    var whole = await dns.lookup("half.example.com", { all: true });
    check("lookup: an answer missing a family after a transient failure is not cached, so the next lookup asks " +
          "again (queries=" + (srv.queries.length - before) + ")", srv.queries.length - before === 2);
    check("lookup: the next lookup returns both families once the resolver recovers (got " + _addrs(whole) + ")",
          _addrs(whole) === "192.0.2.60,2001:db8::3c");
  } finally { srv.close(); dns._resetForTest(); }
}

async function testCachedLookupIsACopy(chain) {
  var zone = { "copy.example.com": { a: "192.0.2.70", aaaa: 70, ttl: 300 } };
  var srv = await _startH2Doh(chain, zone);
  dns._resetForTest();
  dns.useDnsOverHttps({ url: "https://127.0.0.1:" + srv.port + "/dns-query", ca: chain.rootCa });
  dns.setLookupTimeoutMs(5000);
  try {
    var first = await dns.lookup("copy.example.com", { all: true });
    first.length = 0;
    first.push({ address: "10.0.0.1", family: 4 });
    var second = await dns.lookup("copy.example.com", { all: true });
    check("lookup: emptying the array a lookup returned does not change the next cached answer (got " +
          _addrs(second) + ")", _addrs(second) === "192.0.2.70,2001:db8::46");
    second[0].address = "10.0.0.2";
    var third = await dns.lookup("copy.example.com", { all: true });
    check("lookup: changing an entry of a cached answer does not change the next one (got " + _addrs(third) + ")",
          _addrs(third) === "192.0.2.70,2001:db8::46");
    var one = await dns.lookup("copy.example.com", { family: 0 });
    one.address = "10.0.0.3";
    var again = await dns.lookup("copy.example.com", { family: 0 });
    check("lookup: changing the single address a cached lookup returned does not change the next one (got " +
          again.address + ")", again.address !== "10.0.0.3");
    check("lookup: every answer above after the first came from the cache (queries=" + srv.queries.length + ")",
          srv.queries.length === 2);
  } finally { srv.close(); dns._resetForTest(); }
}

async function testDiscoverEncryptedOnLegacyResolver(chain) {
  var zone = { "_dns.resolver.arpa": { rcode: RCODE_NOTIMP } };
  var srv = await _startH2Doh(chain, zone);
  dns._resetForTest();
  dns.useDnsOverHttps({ url: "https://127.0.0.1:" + srv.port + "/dns-query", ca: chain.rootCa });
  dns.setLookupTimeoutMs(5000);
  try {
    var cases = [
      ["NOTIMP",   RCODE_NOTIMP,   "dns/ddr-not-discovered"],
      ["FORMERR",  RCODE_FORMERR,  "dns/ddr-not-discovered"],
      ["REFUSED",  RCODE_REFUSED,  "dns/ddr-not-discovered"],
      ["NXDOMAIN", RCODE_NXDOMAIN, "dns/ddr-not-discovered"],
      ["SERVFAIL", RCODE_SERVFAIL, "dns/server-failure"],
    ];
    for (var i = 0; i < cases.length; i++) {
      zone["_dns.resolver.arpa"] = { rcode: cases[i][1] };
      var got = await _failure(function () { return dns.discoverEncrypted({ insecureSystemResolverOnly: false }); });
      check("discoverEncrypted: a resolver answering " + cases[i][0] + " to the DDR query rejects with " +
            cases[i][2] + " (got " + got.code + ")", got.code === cases[i][2]);
      check("discoverEncrypted: the " + cases[i][0] + " rejection is transient",
            got.permanent === false, String(got.permanent));
    }
  } finally { srv.close(); dns._resetForTest(); }
}

function _startDroppingH2Doh(chain, zone, mode) {
  var stats = { connections: 0, queries: [], versions: [], drops: 0 };
  var answer = _answerHandler(zone, stats);
  var server = http2.createSecureServer({ key: chain.key, cert: chain.cert });
  var rawByPort = new Map();
  server.on("secureConnection", function (sock) { rawByPort.set(sock.remotePort, sock); });
  server.on("session", function (session) {
    var streams = 0;
    session.on("error", function () { /* fixture best-effort */ });
    session.on("stream", function (stream, headers) {
      streams += 1;
      stream.on("error", function () { /* fixture best-effort */ });
      var dropThis = mode === "always" || (mode !== "never" && streams >= 2);
      if (dropThis) {
        stats.drops += 1;
        var raw = rawByPort.get(session.socket.remotePort);
        if (mode === "destroy") raw.destroy();
        else raw.end();
        return;
      }
      _readQuery({ url: headers[":path"], on: stream.on.bind(stream) }, function (query) {
        stream.respond({ ":status": 200, "content-type": "application/dns-message" });
        stream.end(answer(query));
      });
    });
  });
  return _listen(server, stats);
}

async function testReusedSessionClosedByServer(chain) {
  var zone = { "ok.example.com": { a: "192.0.2.80", ttl: 60 } };
  var modes = ["destroy", "end"];
  for (var m = 0; m < modes.length; m++) {
    var srv = await _startDroppingH2Doh(chain, zone, modes[m]);
    dns._resetForTest();
    dns.useDnsOverHttps({ url: "https://127.0.0.1:" + srv.port + "/dns-query", ca: chain.rootCa });
    dns.setLookupTimeoutMs(5000);
    dns.setCacheTtlMs(0);
    try {
      var results = [];
      for (var i = 0; i < 4; i++) {
        results.push(await _failure(function () { return dns.resolve4("ok.example.com"); }));
      }
      var codes = results.map(function (r) { return r.code; }).join(",");
      check("resolve4 (DoH, server " + modes[m] + "s the reused connection as a query arrives): each query is " +
            "answered on a new connection (codes=" + codes + ", drops=" + srv.drops + ")",
            results.every(function (r) { return r.code === "no-throw"; }) && srv.drops === 3);
    } finally { srv.close(); dns._resetForTest(); }
  }

  var dead = await _startDroppingH2Doh(chain, zone, "always");
  dns._resetForTest();
  dns.useDnsOverHttps({ url: "https://127.0.0.1:" + dead.port + "/dns-query", ca: chain.rootCa });
  dns.setLookupTimeoutMs(5000);
  try {
    var noReply = await _failure(function () { return dns.resolve4("ok.example.com"); });
    check("resolve4 (DoH): a stream the server ends without a response rejects with dns/doh-failed (got " +
          noReply.code + ": " + (noReply.error && noReply.error.message) + ")",
          noReply.code === "dns/doh-failed" && !/HTTP 0/.test(String(noReply.error && noReply.error.message)));
    check("resolve4 (DoH): a query on a new connection is not retried (drops=" + dead.drops + ")", dead.drops === 1);
  } finally { dead.close(); dns._resetForTest(); }
}

function _startPolicyH2Doh(chain, zone, policy) {
  var stats = { connections: 0, queries: [], versions: [], streams: 0, resets: 0 };
  var answer = _answerHandler(zone, stats);
  var server = http2.createSecureServer({ key: chain.key, cert: chain.cert });
  var sessionIndex = 0;
  server.on("session", function (session) {
    sessionIndex += 1;
    var thisSession = sessionIndex;
    var streams = 0;
    session.on("error", function () { /* fixture best-effort */ });
    session.on("stream", function (stream, headers) {
      streams += 1;
      stats.streams += 1;
      stream.on("error", function () { /* fixture best-effort */ });
      var action = policy(thisSession, streams);
      if (typeof action === "number") {
        stats.resets += 1;
        stream.close(action);
        return;
      }
      _readQuery({ url: headers[":path"], on: stream.on.bind(stream) }, function (query) {
        stream.respond({ ":status": 200, "content-type": "application/dns-message" });
        stream.end(answer(query));
        if (action === "goaway") session.goaway(http2.constants.NGHTTP2_NO_ERROR);
      });
    });
  });
  return _listen(server, stats);
}

async function testStreamResetOnLiveSession(chain) {
  var zone = { "ok.example.com": { a: "192.0.2.95", ttl: 60 } };
  var limited = await _startPolicyH2Doh(chain, zone, function (_session, n) {
    return n > 2 ? http2.constants.NGHTTP2_ENHANCE_YOUR_CALM : null;
  });
  dns._resetForTest();
  dns.useDnsOverHttps({ url: "https://127.0.0.1:" + limited.port + "/dns-query", ca: chain.rootCa });
  dns.setLookupTimeoutMs(3000);
  dns.setCacheTtlMs(0);
  try {
    var codes = [];
    for (var i = 0; i < 5; i++) {
      codes.push((await _failure(function () { return dns.resolve4("ok.example.com"); })).code);
    }
    check("resolve4 (DoH, server resets every stream after the 2nd on a connection): the first two are answered " +
          "and the rest reject with dns/doh-failed (codes=" + codes.join(",") + ")",
          codes.join(",") === "no-throw,no-throw,dns/doh-failed,dns/doh-failed,dns/doh-failed");
    check("resolve4 (DoH): a stream reset on a live connection keeps that connection (connections=" +
          limited.connections + ")", limited.connections === 1);
    check("resolve4 (DoH): a query whose stream was reset is sent once more on the same connection (streams=" +
          limited.streams + ", resets=" + limited.resets + ")", limited.streams === 8 && limited.resets === 6);
  } finally { limited.close(); dns._resetForTest(); }

  var refusedOnce = await _startPolicyH2Doh(chain, zone, function (session, n) {
    return session === 1 && n === 2 ? http2.constants.NGHTTP2_REFUSED_STREAM : null;
  });
  dns._resetForTest();
  dns.useDnsOverHttps({ url: "https://127.0.0.1:" + refusedOnce.port + "/dns-query", ca: chain.rootCa });
  dns.setLookupTimeoutMs(3000);
  dns.setCacheTtlMs(0);
  try {
    var first = await _failure(function () { return dns.resolve4("ok.example.com"); });
    var second = await _failure(function () { return dns.resolve4("ok.example.com"); });
    check("resolve4 (DoH): a query whose stream the server refused once is answered on retry (codes=" +
          first.code + "," + second.code + ")", first.code === "no-throw" && second.code === "no-throw");
    check("resolve4 (DoH): the retry after a refused stream uses the same connection (connections=" +
          refusedOnce.connections + ", streams=" + refusedOnce.streams + ")",
          refusedOnce.connections === 1 && refusedOnce.streams === 3);
  } finally { refusedOnce.close(); dns._resetForTest(); }
}

async function testGoawayClosesSession(chain) {
  var zone = { "ok.example.com": { a: "192.0.2.96", ttl: 60 } };
  var srv = await _startPolicyH2Doh(chain, zone, function (session, n) {
    return session === 1 && n === 1 ? "goaway" : null;
  });
  var dialed = [];
  var realConnect = nodeTls.connect;
  nodeTls.connect = function () {
    var sock = realConnect.apply(nodeTls, arguments);
    dialed.push(sock);
    return sock;
  };
  dns._resetForTest();
  dns.useDnsOverHttps({ url: "https://127.0.0.1:" + srv.port + "/dns-query", ca: chain.rootCa });
  dns.setLookupTimeoutMs(3000);
  dns.setCacheTtlMs(0);
  try {
    var codes = [];
    codes.push((await _failure(function () { return dns.resolve4("ok.example.com"); })).code);
    await helpers.waitUntil(function () { return dialed.length === 1 && dialed[0].destroyed; }, {
      timeoutMs: 5000,
      label: "dns: the client closes its DoH socket after the server sent GOAWAY, without waiting for the server",
    });
    for (var i = 0; i < 3; i++) {
      codes.push((await _failure(function () { return dns.resolve4("ok.example.com"); })).code);
    }
    check("resolve4 (DoH): queries after a GOAWAY are answered (codes=" + codes.join(",") + ")",
          codes.every(function (c) { return c === "no-throw"; }));
    check("resolve4 (DoH): the queries after a GOAWAY share one new connection (connections=" + srv.connections +
          ", dialed=" + dialed.length + ", open=" + dialed.filter(function (s) { return !s.destroyed; }).length + ")",
          srv.connections === 2 && dialed.length === 2 && !dialed[1].destroyed);
  } finally { nodeTls.connect = realConnect; srv.close(); dns._resetForTest(); }
}

function _startSilencingProxy(targetPort) {
  var stats = { connections: 0, links: [] };
  var server = net.createServer(function (client) {
    stats.connections += 1;
    var upstream = net.connect(targetPort, "127.0.0.1");
    var link = { silent: false, client: client, upstream: upstream };
    stats.links.push(link);
    client.on("data", function (d) { if (!link.silent) upstream.write(d); });
    upstream.on("data", function (d) { if (!link.silent) client.write(d); });
    client.on("error", function () { /* fixture best-effort */ });
    upstream.on("error", function () { /* fixture best-effort */ });
    client.on("close", function () { upstream.destroy(); });
    upstream.on("close", function () { client.destroy(); });
  });
  stats.silenceAll = function () { stats.links.forEach(function (l) { l.silent = true; }); };
  return new Promise(function (resolve) {
    server.listen(0, "127.0.0.1", function () {
      stats.port = server.address().port;
      stats.close = function () {
        stats.links.forEach(function (l) { l.client.destroy(); l.upstream.destroy(); });
        server.close();
      };
      resolve(stats);
    });
  });
}

async function testSilentPooledSession(chain) {
  var zone = { "ok.example.com": { a: "192.0.2.90", aaaa: 9, ttl: 60 } };
  var srv = await _startH2Doh(chain, zone);
  var proxy = await _startSilencingProxy(srv.port);
  dns._resetForTest();
  dns.useDnsOverHttps({ url: "https://127.0.0.1:" + proxy.port + "/dns-query", ca: chain.rootCa });
  dns.setLookupTimeoutMs(3000);
  dns.setCacheTtlMs(0);
  try {
    var first = await _failure(function () { return dns.resolve4("ok.example.com"); });
    check("resolve4 (DoH): the first query is answered (got " + first.code + ")", first.code === "no-throw");
    proxy.silenceAll();
    var codes = [];
    for (var i = 0; i < 4; i++) {
      var r = await _failure(function () { return dns.resolve4("ok.example.com"); });
      codes.push(r.code);
    }
    check("resolve4 (DoH): after the pooled connection stops passing traffic without closing, every query is " +
          "answered (codes=" + codes.join(",") + ")",
          codes.every(function (c) { return c === "no-throw"; }));
    check("resolve4 (DoH): the silent connection is replaced by one new connection (connections=" +
          proxy.connections + ")", proxy.connections === 2);

    proxy.silenceAll();
    var both = null;
    var dual = await _failure(async function () { both = await dns.lookup("ok.example.com", { all: true }); });
    check("lookup (DoH, both families): both queries are answered after the pooled connection goes silent " +
          "(got " + dual.code + ", " + (both ? _addrs(both) : "none") + ")",
          dual.code === "no-throw" && both !== null && _addrs(both) === "192.0.2.90,2001:db8::9");
    check("lookup (DoH, both families): the A and AAAA retries share one new connection (connections=" +
          proxy.connections + ")", proxy.connections === 3);
  } finally { proxy.close(); srv.close(); dns._resetForTest(); }
}

function _startSlowH2Doh(chain, zone, delayMs) {
  var stats = { connections: 0, queries: [], versions: [] };
  var answer = _answerHandler(zone, stats);
  var server = http2.createSecureServer({ key: chain.key, cert: chain.cert }, function (req, res) {
    _readQuery(req, function (query) {
      var q = _questionOf(query);
      if (zone[q.name] && zone[q.name].hang) { stats.queries.push(q.name + "/" + q.qtype); return; }
      var delay = zone[q.name] && zone[q.name].slow ? delayMs : 0;
      var t = setTimeout(function () {
        res.setHeader("content-type", "application/dns-message");
        res.end(answer(query));
      }, delay);
      t.unref();
    });
  });
  return _listen(server, stats);
}

async function testSlowAnswerAndStreamTimeout(chain) {
  var zone = {
    "ok.example.com":   { a: "192.0.2.91", ttl: 60 },
    "slow.example.com": { a: "192.0.2.92", ttl: 60, slow: true },
    "hang.example.com": { a: "192.0.2.93", ttl: 60, hang: true },
  };
  var srv = await _startSlowH2Doh(chain, zone, 2000);
  dns._resetForTest();
  dns.useDnsOverHttps({ url: "https://127.0.0.1:" + srv.port + "/dns-query", ca: chain.rootCa });
  dns.setLookupTimeoutMs(3000);
  dns.setCacheTtlMs(0);
  try {
    await dns.resolve4("ok.example.com");
    var slow = await _failure(function () { return dns.resolve4("slow.example.com"); });
    check("resolve4 (DoH): a reused connection that answers after 2s, inside the 3s timeout, is kept " +
          "(got " + slow.code + ", connections=" + srv.connections + ", queries=" + srv.queries.length + ")",
          slow.code === "no-throw" && srv.connections === 1 && srv.queries.length === 2);

    dns.setLookupTimeoutMs(500);
    var hang = await _failure(function () { return dns.resolve4("hang.example.com"); });
    check("resolve4 (DoH): a query the server never answers rejects with dns/lookup-timeout (got " + hang.code + ")",
          hang.code === "dns/lookup-timeout");
    await helpers.waitUntil(function () { return srv.openSockets() === 0; }, {
      timeoutMs: 5000, label: "dns: the client closes the connection whose stream timed out",
    });
    var after = await _failure(function () { return dns.resolve4("ok.example.com"); });
    check("resolve4 (DoH): after a stream timed out before its response, the next query dials a new connection " +
          "(got " + after.code + ", connections=" + srv.connections + ")",
          after.code === "no-throw" && srv.connections === 2);
  } finally { srv.close(); dns._resetForTest(); }
}

async function _startPlainDns(zone) {
  for (var attempt = 1; ; attempt++) {
    try { return await _bindPlainDns(zone); }
    catch (e) {
      if (attempt >= 20) throw e;
    }
  }
}

async function _bindPlainDns(zone) {
  var stats = { queries: [] };
  var answer = _answerHandler(zone, stats);
  var udp = dgram.createSocket("udp4");
  udp.on("message", function (msg, rinfo) { udp.send(answer(msg), rinfo.port, rinfo.address); });
  await new Promise(function (resolve) { udp.bind(0, "127.0.0.1", resolve); });
  stats.port = udp.address().port;
  var tcp = net.createServer(function (sock) {
    var got = Buffer.alloc(0);
    sock.on("error", function () { /* fixture best-effort */ });
    sock.on("data", function (chunk) {
      got = Buffer.concat([got, chunk]);
      if (got.length >= 2 && got.length >= got.readUInt16BE(0) + 2) {
        var out = answer(got.subarray(2, 2 + got.readUInt16BE(0)));
        var prefix = Buffer.alloc(2);
        prefix.writeUInt16BE(out.length, 0);
        sock.end(Buffer.concat([prefix, out]));
      }
    });
  });
  try {
    await new Promise(function (resolve, reject) {
      tcp.once("error", reject);
      tcp.listen(stats.port, "127.0.0.1", function () { tcp.removeListener("error", reject); resolve(); });
    });
  } catch (e) {
    udp.close();
    throw e;
  }
  stats.close = function () { udp.close(); tcp.close(); };
  return stats;
}

async function testSystemTransportResponseCodes() {
  var zone = {
    "sf.example.com":     { rcode: RCODE_SERVFAIL },
    "ref.example.com":    { rcode: RCODE_REFUSED },
    "form.example.com":   { rcode: RCODE_FORMERR },
    "notimp.example.com": { rcode: RCODE_NOTIMP },
    "v4only.example.com": { a: "192.0.2.70", ttl: 60 },
  };
  var srv = await _startPlainDns(zone);
  dns._resetForTest();
  dns.useSystemResolver();
  dns.setServers(["127.0.0.1:" + srv.port]);
  dns.setLookupTimeoutMs(5000);
  var cases = [
    ["SERVFAIL", "sf.example.com",     4, "dns/server-failure", false, RCODE_SERVFAIL],
    ["REFUSED",  "ref.example.com",    4, "dns/server-failure", false, RCODE_REFUSED],
    ["NXDOMAIN", "nx.example.com",     4, "dns/no-result",      true,  RCODE_NXDOMAIN],
    ["NODATA",   "v4only.example.com", 6, "dns/no-result",      true,  undefined],
    ["FORMERR",  "form.example.com",   4, "dns/query-failed",   true,  RCODE_FORMERR],
    ["NOTIMP",   "notimp.example.com", 4, "dns/query-failed",   true,  RCODE_NOTIMP],
  ];
  try {
    for (var i = 0; i < cases.length; i++) {
      var c = cases[i];
      var got = await _failure(function () { return c[2] === 6 ? dns.resolve6(c[1]) : dns.resolve4(c[1]); });
      check("resolve" + c[2] + " (system resolver): a " + c[0] + " reply rejects with " + c[3] +
            " (got " + got.code + ")", got.code === c[3]);
      check("resolve" + c[2] + " (system resolver): the " + c[0] + " rejection has permanent=" + c[4] +
            " (got " + got.permanent + ")", got.permanent === c[4]);
      check("resolve" + c[2] + " (system resolver): the " + c[0] + " rejection carries rcode " + c[5] +
            " (got " + (got.error && got.error.rcode) + ")", (got.error && got.error.rcode) === c[5]);
    }
    var ok = await dns.resolve4("v4only.example.com");
    check("resolve4 (system resolver): an answer is returned (got " + ok.join(",") + ")", ok.join(",") === "192.0.2.70");
  } finally { srv.close(); dns._resetForTest(); }
}

async function run() {
  var chain = ck.tlsChain("control");
  await testGoawayClosesSession(chain);
  await testStreamResetOnLiveSession(chain);
  await testSystemTransportResponseCodes();
  await testSilentPooledSession(chain);
  await testSlowAnswerAndStreamTimeout(chain);
  await testResponseCodes(chain);
  await testOneConnectionAndAnswerTtl(chain);
  await testHttp1OnlyServer(chain);
  await testPartialAnswerAfterTransientFailure(chain);
  await testCachedLookupIsACopy(chain);
  await testDiscoverEncryptedOnLegacyResolver(chain);
  await testReusedSessionClosedByServer(chain);
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[network-dns-rcode-and-answer-ttl] OK: " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error(e && e.stack || e); process.exit(1); }
  );
}
