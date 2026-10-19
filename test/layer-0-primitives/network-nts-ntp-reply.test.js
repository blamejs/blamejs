// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The NTP reply header and timestamp decoding that b.ntpCheck.querySingle
 * (plain SNTP) and b.network.ntp.nts.querySingle (authenticated NTPv4)
 * share, plus the plain client's handling of datagrams that are not the
 * reply it is waiting for.
 *
 *   - The header validator refuses a reply that is not a synchronized
 *     server answer (mode, version, leap indicator, stratum, zero
 *     transmit time) and reports which field failed.
 *   - The timestamp converter reads NTP era 1 (from 2036-02-07T06:28:16Z,
 *     RFC 4330 section 3) instead of refusing it as pre-1970.
 *   - b.ntpCheck.querySingle discards a short datagram, one that does not
 *     echo the request's origin, and one from another source, and keeps
 *     waiting for the genuine reply.
 *
 * Every server is a loopback listener.
 */

var dgram   = require("node:dgram");
var nodeDns = require("node:dns");
var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

var ntpCheck = require("../../lib/ntp-check");

var NTP_EPOCH_OFFSET = 2208988800;
var NTP_ERA_SECONDS  = 4294967296;

function _ntpSecondsFor(ms) {
  return (Math.floor(ms / 1000) + NTP_EPOCH_OFFSET) % NTP_ERA_SECONDS;
}

// 48-byte server reply. Defaults: LI 0, VN 4, mode 4, stratum 2, transmit
// time now, origin echoing the request when one is given.
function _reply(o) {
  o = o || {};
  var r = Buffer.alloc(48);
  r[0] = o.b0 !== undefined ? o.b0 : 0x24;
  r[1] = o.stratum !== undefined ? o.stratum : 2;
  if (o.request) o.request.copy(r, 24, 40, 48);
  r.writeUInt32BE((o.txSecs !== undefined ? o.txSecs : _ntpSecondsFor(o.nowMs || Date.now())) >>> 0, 40);
  r.writeUInt32BE((o.txFrac || 0) >>> 0, 44);
  return r;
}

function _hasIpv6Loopback() {
  var ifaces = require("node:os").networkInterfaces();
  return Object.keys(ifaces).some(function (name) {
    return (ifaces[name] || []).some(function (a) {
      return (a.family === "IPv6" || a.family === 6) && a.address === "::1";
    });
  });
}

function testHeaderValidator() {
  var decode = ntpCheck._decodeServerReply;
  check("ntp-check exports the shared reply decoder", typeof decode === "function");
  if (typeof decode !== "function") return;

  var ok = decode(_reply(), { versions: [4] });
  check("a synchronized VN4 mode-4 reply decodes", ok.ok === true && typeof ok.serverTimeMs === "number");

  var refused = [
    ["LI=3",          { b0: 0xE4 }],
    ["stratum 0",     { stratum: 0 }],
    ["stratum 16",    { stratum: 16 }],
    ["mode 3",        { b0: 0x23 }],
    ["version 2",     { b0: 0x14 }],
    ["a zero transmit time", { txSecs: 0 }],
  ];
  refused.forEach(function (c) {
    var r = decode(_reply(c[1]), { versions: [3, 4] });
    check("the reply decoder refuses " + c[0], r.ok === false && typeof r.reason === "string", JSON.stringify(r));
  });

  // The version allowance belongs to the caller: SNTP accepts a VN3 server,
  // NTS (RFC 8915 is NTPv4 only) does not.
  check("a VN3 reply is accepted where version 3 is allowed",
        decode(_reply({ b0: 0x1C }), { versions: [3, 4] }).ok === true);
  check("a VN3 reply is refused where only version 4 is allowed",
        decode(_reply({ b0: 0x1C }), { versions: [4] }).ok === false);
}

function testEraAwareConverter() {
  var toMs = ntpCheck._ntpToUnixMs;
  check("ntp-check exports the era-aware converter", typeof toMs === "function");
  if (typeof toMs !== "function") return;

  check("an era-0 timestamp decodes as before",
        toMs(_ntpSecondsFor(Date.UTC(2026, 0, 1)), 0) === Date.UTC(2026, 0, 1));
  check("an era-1 timestamp decodes past 2036",
        toMs(_ntpSecondsFor(Date.UTC(2036, 2, 1)), 0) === Date.UTC(2036, 2, 1));
  // The wrap: 0xFFFFFFFF is the last era-0 second, 0 is the first of era 1.
  var wrapMs = Date.UTC(2036, 1, 7, 6, 28, 16);
  check("the last era-0 second is one second before the wrap", toMs(0xFFFFFFFF, 0) === wrapMs - 1000);
  check("seconds 0 with a non-zero fraction falls after the wrap",
        toMs(0, 0x80000000) === wrapMs + 500, String(toMs(0, 0x80000000) - wrapMs));
  check("the fraction rounds to milliseconds", toMs(_ntpSecondsFor(Date.UTC(2026, 0, 1)), 0x40000000) === Date.UTC(2026, 0, 1) + 250);
}

function _startServer(onMessage, family, address) {
  return new Promise(function (resolve) {
    var s = dgram.createSocket(family || "udp4");
    s.on("error", function () { /* best-effort loopback listener */ });
    s.on("message", function (msg, rinfo) { onMessage(msg, rinfo, s); });
    s.bind(0, address || "127.0.0.1", function () { resolve({ sock: s, port: s.address().port }); });
  });
}

function _closeAll(list) {
  list.forEach(function (h) { try { h.sock.close(); } catch (_e) { /* best-effort */ } });
}

async function _query(host, port, timeoutMs) {
  try { return { res: await b.ntpCheck.querySingle(host, { port: port, timeoutMs: timeoutMs || 3000 }) }; }
  catch (e) { return { err: e }; }
}

function _describe(r) {
  return r.err ? (r.err.code + " :: " + r.err.message) : JSON.stringify(r.res);
}

// RFC 5905 / RFC 4330: a reply that does not echo the origin, or that is not
// an NTP packet at all, is discarded. Taking the first datagram as the answer
// let any source that reaches the ephemeral port end the query.
async function testPlainQueryDiscardsAndKeepsWaiting() {
  var srv = await _startServer(function (msg, rinfo, s) {
    s.send(Buffer.alloc(10), rinfo.port, rinfo.address);
    s.send(_reply({ request: Buffer.alloc(48) }), rinfo.port, rinfo.address);
    setTimeout(function () {
      try { s.send(_reply({ request: msg }), rinfo.port, rinfo.address); } catch (_e) { /* closed */ }
    }, 20);
  });
  var r = await _query("127.0.0.1", srv.port);
  _closeAll([srv]);
  check("ntpCheck.querySingle keeps waiting past junk and a wrong-origin reply",
        r.res && typeof r.res.driftMs === "number" && Math.abs(r.res.driftMs) < 60000, _describe(r));

  // A valid-looking reply from another port is not the server's answer.
  var other = await _startServer(function () { /* sends only */ });
  var srv2 = await _startServer(function (msg, rinfo, s) {
    other.sock.send(_reply({ request: msg, nowMs: Date.now() + 86400000 }), rinfo.port, rinfo.address);
    setTimeout(function () {
      try { s.send(_reply({ request: msg }), rinfo.port, rinfo.address); } catch (_e) { /* closed */ }
    }, 20);
  });
  var r2 = await _query("127.0.0.1", srv2.port);
  _closeAll([srv2, other]);
  check("ntpCheck.querySingle ignores a reply from another source port",
        r2.res && Math.abs(r2.res.driftMs) < 60000, _describe(r2));

  // When nothing acceptable arrives, the timeout reports the last reason a
  // datagram was discarded.
  var srv3 = await _startServer(function (msg, rinfo, s) {
    s.send(_reply({ request: Buffer.alloc(48) }), rinfo.port, rinfo.address);
  });
  var r3 = await _query("127.0.0.1", srv3.port, 300);
  _closeAll([srv3]);
  check("ntpCheck.querySingle reports the discarded wrong-origin reply at the timeout",
        r3.err && r3.err.code === "ntp/origin-mismatch", _describe(r3));
}

async function testPlainQueryReadsEraOne() {
  var whenMs = Date.UTC(2036, 2, 1);
  var srv = await _startServer(function (msg, rinfo, s) {
    s.send(_reply({ request: msg, txSecs: _ntpSecondsFor(whenMs) }), rinfo.port, rinfo.address);
  });
  var r = await _query("127.0.0.1", srv.port);
  _closeAll([srv]);
  check("ntpCheck.querySingle reads a 2036-03-01 transmit time",
        r.res && r.res.serverTimeMs === whenMs, _describe(r));
}

async function testPlainQueryHeaderAnswers() {
  var srv = await _startServer(function (msg, rinfo, s) {
    s.send(_reply({ request: msg, b0: 0x1C }), rinfo.port, rinfo.address);
  });
  var r = await _query("127.0.0.1", srv.port);
  _closeAll([srv]);
  check("ntpCheck.querySingle accepts a VN3 server", r.res && typeof r.res.driftMs === "number", _describe(r));

  var srv2 = await _startServer(function (msg, rinfo, s) {
    s.send(_reply({ request: msg, b0: 0xE4, stratum: 0 }), rinfo.port, rinfo.address);
  });
  var r2 = await _query("127.0.0.1", srv2.port);
  _closeAll([srv2]);
  check("ntpCheck.querySingle reports an unsynchronized server",
        r2.err && r2.err.code === "ntp/unsynchronized", _describe(r2));

  var srv3 = await _startServer(function (msg, rinfo, s) {
    s.send(_reply({ request: msg, txSecs: 0 }), rinfo.port, rinfo.address);
  });
  var r3 = await _query("127.0.0.1", srv3.port);
  _closeAll([srv3]);
  check("ntpCheck.querySingle reports a zero transmit time as unsynchronized",
        r3.err && r3.err.code === "ntp/unsynchronized", _describe(r3));
}

// The socket family follows the address the name resolves to.
async function testPlainQueryResolvesBeforeChoosingAFamily() {
  if (!_hasIpv6Loopback()) {
    helpers.unavailable("ntpCheck.querySingle AAAA-only name", "no ::1 loopback on this host");
    return;
  }
  var srv = await _startServer(function (msg, rinfo, s) {
    s.send(_reply({ request: msg }), rinfo.port, rinfo.address);
  }, "udp6", "::1");
  var origLookup = nodeDns.lookup;
  nodeDns.lookup = function (host, opts, cb) {
    if (typeof opts === "function") { cb = opts; opts = {}; }
    if (host === "ntp-aaaa-only.invalid") {
      if (opts && opts.all) return process.nextTick(cb, null, [{ address: "::1", family: 6 }]);
      return process.nextTick(cb, null, "::1", 6);
    }
    return origLookup.call(nodeDns, host, opts, cb);
  };
  var r;
  try { r = await _query("ntp-aaaa-only.invalid", srv.port); }
  finally { nodeDns.lookup = origLookup; _closeAll([srv]); }
  check("ntpCheck.querySingle reaches a name that resolves only to IPv6",
        r.res && typeof r.res.driftMs === "number", _describe(r));
}

// The kernel reports a reply's source in RFC 5952 form. A server written in
// another valid spelling of the same address is still the queried address.
async function testPlainQueryAcceptsAnyAddressSpelling() {
  check("ntp-check: two spellings of one IPv6 address compare equal",
        ntpCheck._sameAddress("0:0:0:0:0:0:0:1", "::1") === true &&
        ntpCheck._sameAddress("64:ff9b::192.0.2.1", "64:ff9b::c000:201") === true &&
        ntpCheck._sameAddress("FE80::1%eth0", "fe80::1%2") === true);
  check("ntp-check: different addresses do not compare equal",
        ntpCheck._sameAddress("::1", "::2") === false &&
        ntpCheck._sameAddress("127.0.0.1", "127.0.0.2") === false &&
        ntpCheck._sameAddress("::1", null) === false);
  if (!_hasIpv6Loopback()) {
    helpers.unavailable("ntpCheck.querySingle non-canonical IPv6 literal", "no ::1 loopback on this host");
    return;
  }
  var spellings = ["0:0:0:0:0:0:0:1", "0000:0000::0001", "[0:0:0:0:0:0:0:1]"];
  for (var i = 0; i < spellings.length; i++) {
    var srv = await _startServer(function (msg, rinfo, s) {
      s.send(_reply({ request: msg }), rinfo.port, rinfo.address);
    }, "udp6", "::1");
    var r = await _query(spellings[i], srv.port, 1000);
    _closeAll([srv]);
    check("ntpCheck.querySingle accepts the reply to " + spellings[i],
          r.res && typeof r.res.driftMs === "number", _describe(r));
  }
}

// A timeout past setTimeout's range fires after 1 ms, so every query would
// time out at once. It is refused where it is configured.
async function testTimeoutBound() {
  var codes = {};
  function ignore(p) { if (p && typeof p.catch === "function") p.catch(function () { /* settled elsewhere */ }); }
  try { ignore(b.ntpCheck.querySingle("127.0.0.1", { port: 1, timeoutMs: 1e12 })); } catch (e) { codes.qs = e && e.code; }
  try { ignore(b.ntpCheck.querySingle("", { port: 1 })); } catch (e) { codes.server = e && e.code; }
  try { await b.ntpCheck.checkDrift({ servers: ["127.0.0.1"], port: 1, timeoutMs: 1e12 }); }
  catch (e) { codes.drift = e && e.code; }
  try { await b.ntpCheck.bootCheck({ servers: ["127.0.0.1"], port: 1, timeoutMs: 1e12 }); }
  catch (e) { codes.boot = e && e.code; }
  var mon = null;
  try { mon = b.ntpCheck.monitor({ servers: ["127.0.0.1"], port: 1, timeoutMs: 1e12, audit: false }); }
  catch (e) { codes.monitor = e && e.code; }
  if (mon) mon.stop();
  check("ntpCheck.querySingle refuses a timeoutMs past the timer range", codes.qs === "ntp/bad-timeout", String(codes.qs));
  check("ntpCheck.querySingle refuses an empty server", codes.server === "ntp/bad-server", String(codes.server));
  check("ntpCheck.checkDrift refuses a timeoutMs past the timer range", codes.drift === "ntp/bad-timeout", String(codes.drift));
  check("ntpCheck.bootCheck refuses a timeoutMs past the timer range", codes.boot === "ntp/bad-timeout", String(codes.boot));
  check("ntpCheck.monitor refuses a timeoutMs past the timer range", codes.monitor === "ntp/bad-timeout", String(codes.monitor));
}

async function run() {
  await helpers.withDrain("network-nts-ntp-reply", async function () {
    testHeaderValidator();
    testEraAwareConverter();
    await testTimeoutBound();
    await testPlainQueryDiscardsAndKeepsWaiting();
    await testPlainQueryReadsEraOne();
    await testPlainQueryHeaderAnswers();
    await testPlainQueryResolvesBeforeChoosingAFamily();
    await testPlainQueryAcceptsAnyAddressSpelling();
  });
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
