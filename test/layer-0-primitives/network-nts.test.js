// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.network.ntp.nts — NTS (RFC 8915) key-establishment + protected NTPv4
 * exchange. This canonical suite drives the error / adversarial /
 * defensive / option-default branches of the primitive through its real
 * consumer path:
 *
 *   - AES-SIV-CMAC (RFC 5297) known-answer vectors, roundtrip, bad-key and
 *     tamper detection for 32/48/64 byte keys.
 *   - performKeHandshake against a loopback TLS "ntske/1" server that
 *     returns each adversarial record shape (error / warning records,
 *     Next Protocol, AEAD choice, unknown critical records, Server and Port
 *     records, truncation, a response split across writes) plus the
 *     success path (real TLS exporter keys) and the fail-closed guards
 *     (bad ALPN, wall-clock timeout, socket reset, early close).
 *   - querySingle against a loopback UDP server that crafts each hostile
 *     reply, including hostile datagrams that arrive BEFORE the genuine
 *     one, unsynchronized and Kiss-o'-Death headers, era-1 timestamps and
 *     padded nonces, for BOTH AEADs.
 *   - query end-to-end: a loopback KE server exports the same TLS keying
 *     material its sibling UDP server uses to authenticate the reply.
 *
 * AEAD ids are written as the IANA AEAD registry numbers (15 and 29), not
 * read from the module, so a wrong constant in the module cannot agree with
 * a wrong constant here.
 *
 * No real network is touched: every server is a loopback listener and
 * every key is injected.
 */

var helpers    = require("../helpers");
var check      = helpers.check;
var b          = helpers.b;
var nodeTls    = require("node:tls");
var dgram      = require("node:dgram");
var net        = require("node:net");
var nodeDns    = require("node:dns");
var nodeCrypto = require("node:crypto");

var nts = b.network.ntp.nts;

// IANA AEAD Algorithms registry (RFC 5116 section 6, RFC 8439 section 9).
var AEAD_SIV    = 15;   // AEAD_AES_SIV_CMAC_256
var AEAD_CHACHA = 29;   // AEAD_CHACHA20_POLY1305
var AEAD_GCMSIV = 30;   // AEAD_AES_128_GCM_SIV, which the client does not implement

// NTS-KE record types (RFC 8915 section 4) and NTPv4 extension-field types
// (sections 5.3-5.7). Mirrored here so the test constructs on-wire bytes
// without reaching into the module's private encoders.
var REC_END           = 0;
var REC_NEXT_PROTOCOL = 1;
var REC_ERROR         = 2;
var REC_WARNING       = 3;
var REC_AEAD          = 4;
var REC_NEW_COOKIE    = 5;
var REC_NTPV4_SERVER  = 6;
var REC_NTPV4_PORT    = 7;

var EXT_UNIQUE = 0x0104;
var EXT_COOKIE = 0x0204;
var EXT_AUTH   = 0x0404;

var NTP_HEADER_BYTES  = 48;
var NTP_EPOCH_OFFSET  = 2208988800;
var NTP_ERA_SECONDS   = 4294967296;
var EXPORTER_LABEL    = "EXPORTER-network-time-security";

// ---------------------------------------------------------------------------
// On-wire byte builders (test-local; the lib's encoders are private).
// ---------------------------------------------------------------------------

function _u16(v) { var buf = Buffer.alloc(2); buf.writeUInt16BE(v, 0); return buf; }
function _u16s(list) { return Buffer.concat(list.map(_u16)); }

// NTS-KE record: u16 (critical<<15 | type) || u16 body-len || body.
function _rec(critical, type, body) {
  var hdr = Buffer.alloc(4);
  var tf = type & 0x7fff;
  if (critical) tf |= 0x8000;
  hdr.writeUInt16BE(tf, 0);
  hdr.writeUInt16BE(body.length, 2);
  return Buffer.concat([hdr, body]);
}
function _end() { return _rec(true, REC_END, Buffer.alloc(0)); }
function _np()  { return _rec(true, REC_NEXT_PROTOCOL, _u16(0)); }
function _aead(id) { return _rec(true, REC_AEAD, _u16(id)); }
function _cookie(n) { return _rec(false, REC_NEW_COOKIE, nodeCrypto.randomBytes(n || 32)); }

// Parse the records a client sent, so a test can read the offer.
function _parseRecords(buf) {
  var out = [];
  var off = 0;
  while (off + 4 <= buf.length) {
    var t = buf.readUInt16BE(off);
    var len = buf.readUInt16BE(off + 2);
    out.push({ critical: (t & 0x8000) !== 0, type: t & 0x7fff, body: buf.slice(off + 4, off + 4 + len) });
    off += 4 + len;
  }
  return out;
}

// NTPv4 extension field, RFC 7822 4-byte alignment: u16 type || u16
// (paddedBody+4) || body.
function _ext(type, body) {
  var padLen = (4 - (body.length % 4)) % 4;
  var padded = padLen === 0 ? body : Buffer.concat([body, Buffer.alloc(padLen)]);
  var hdr = Buffer.alloc(4);
  hdr.writeUInt16BE(type, 0);
  hdr.writeUInt16BE(padded.length + 4, 2);
  return Buffer.concat([hdr, padded]);
}

// Raw extension with a caller-chosen length field, for adversarial replies
// whose declared length disagrees with the body (truncated / overrun).
function _rawExt(type, len, body) {
  var hdr = Buffer.alloc(4);
  hdr.writeUInt16BE(type, 0);
  hdr.writeUInt16BE(len, 2);
  return Buffer.concat([hdr, body]);
}

// Locate an extension body inside a request/reply, walking from startOff.
function _findExtBody(msg, startOff, type) {
  var off = startOff;
  while (off + 4 <= msg.length) {
    var t = msg.readUInt16BE(off);
    var len = msg.readUInt16BE(off + 2);
    if (len < 4 || off + len > msg.length) break;
    if (t === type) return msg.slice(off + 4, off + len);
    off += len;
  }
  return null;
}

// A test-side AEAD keyed by the literal IANA ids. AES-SIV uses the public
// primitive (pinned separately by the RFC 5297 vectors below).
function _aeadEncryptMirror(aeadId, key, nonce, plaintext, aad) {
  if (aeadId === AEAD_SIV) return nts.aesSivEncrypt(key, plaintext, [aad, nonce]);
  if (aeadId === AEAD_CHACHA) {
    var c = nodeCrypto.createCipheriv("chacha20-poly1305", key, nonce, { authTagLength: 16 });
    c.setAAD(aad, { plaintextLength: plaintext.length });
    var ct = Buffer.concat([c.update(plaintext), c.final()]);
    return Buffer.concat([ct, c.getAuthTag()]);
  }
  throw new Error("test mirror: no AEAD " + aeadId);
}

function _ntpSecondsFor(ms) {
  return (Math.floor(ms / 1000) + NTP_EPOCH_OFFSET) % NTP_ERA_SECONDS;
}

// Build a fully-formed protected NTPv4 reply: NTP header || unique-id ext ||
// authenticator ext, with the authenticator computed over the packet prefix
// exactly as the client recomputes its AAD (msg up to the authenticator).
//   b0 / stratum / refid    header overrides (default LI 0, VN 4, mode 4, stratum 2)
//   txSecs / txFrac         raw transmit timestamp (default: now)
//   nonceLen                nonce length; the field is padded to 4 octets
//   omitAuth                no authenticator (an NTS NAK shape)
function _buildReply(opts) {
  var ntp = Buffer.alloc(NTP_HEADER_BYTES);
  ntp[0] = opts.b0 !== undefined ? opts.b0 : 0x24;
  ntp[1] = opts.stratum !== undefined ? opts.stratum : 2;
  if (opts.refid) Buffer.from(opts.refid, "ascii").copy(ntp, 12);
  var secs = opts.txSecs !== undefined ? opts.txSecs : _ntpSecondsFor(opts.nowMs || Date.now());
  ntp.writeUInt32BE(secs >>> 0, 40);
  ntp.writeUInt32BE((opts.txFrac || 0) >>> 0, 44);
  var uniqueExt = _ext(EXT_UNIQUE, opts.uniqueId);
  var prefix = Buffer.concat([ntp, uniqueExt]);
  if (opts.omitAuth) return prefix;
  var nonceLen = opts.nonceLen || (opts.aeadId === AEAD_SIV ? 16 : 12);
  var nonce = nodeCrypto.randomBytes(nonceLen);
  var nonceField = (nonceLen + 3) & ~3;
  var plaintext = opts.plaintext || Buffer.alloc(0);
  var ct = _aeadEncryptMirror(opts.aeadId, opts.s2cKey, nonce, plaintext, prefix);
  if (opts.corruptCt) { ct = Buffer.from(ct); ct[ct.length - 1] ^= 0xff; }
  var authBody = Buffer.alloc(4 + nonceField + ct.length);
  authBody.writeUInt16BE(nonceLen, 0);
  authBody.writeUInt16BE(ct.length, 2);
  nonce.copy(authBody, 4);
  ct.copy(authBody, 4 + nonceField);
  return Buffer.concat([prefix, _ext(EXT_AUTH, authBody)]);
}

// ---------------------------------------------------------------------------
// Loopback listeners.
// ---------------------------------------------------------------------------

function _hasIpv6Loopback() {
  var ifaces = require("node:os").networkInterfaces();
  return Object.keys(ifaces).some(function (name) {
    return (ifaces[name] || []).some(function (a) {
      return (a.family === "IPv6" || a.family === 6) && a.address === "::1";
    });
  });
}

async function _makeCert() {
  var ca = await b.mtlsEngine.generateCa({ name: "nts-test-ca" });
  var leaf = await b.mtlsEngine.signClientCert({
    cn:           "localhost",
    caCertPem:    ca.caCertPem,
    caKeyPem:     ca.caKeyPem,
    usage:        "server",
    sans:         ["DNS:localhost", "IP:127.0.0.1", "IP:::1"],
    validityDays: 1,
  });
  return { ca: ca, leaf: leaf };
}

// cfg.onData(sock, request) returns a Buffer to write back, an array of
// { data, delayMs } chunks to write in order, or null to stay silent.
// cfg.endAfter ends the connection after the last chunk. cfg.setAlpn false
// omits ALPNProtocols so the client sees a non-"ntske/1" negotiation. The
// handle records the SNI each connection carried and each request.
function _startKeServer(cert, cfg) {
  return new Promise(function (resolve) {
    var tlsOpts = {
      key:        cert.leaf.key,
      cert:       cert.leaf.cert,
      minVersion: "TLSv1.3",
      maxVersion: "TLSv1.3",
    };
    if (cfg.setAlpn !== false) tlsOpts.ALPNProtocols = ["ntske/1"];
    var handle = { servernames: [], requests: [], connections: 0 };
    var server = nodeTls.createServer(tlsOpts, function (sock) {
      handle.servernames.push(sock.servername);
      sock.on("error", function () { /* client tears down on the reject path */ });
      sock.once("data", function (request) {
        handle.requests.push(Buffer.from(request));
        var resp = cfg.onData ? cfg.onData(sock, request) : null;
        if (!resp) return;
        var chunks = Array.isArray(resp) ? resp : [{ data: resp, delayMs: 0 }];
        var i = 0;
        (function next() {
          if (i >= chunks.length) {
            if (cfg.endAfter) { try { sock.end(); } catch (_e) { /* raced teardown */ } }
            return;
          }
          var c = chunks[i++];
          setTimeout(function () {
            try { if (c.data && c.data.length) sock.write(c.data); } catch (_e) { /* raced teardown */ }
            next();
          }, c.delayMs || 0);
        })();
      });
    });
    server.on("connection", function () { handle.connections += 1; });
    server.on("error", function () { /* best-effort loopback listener */ });
    server.on("tlsClientError", function () { /* the client refused the handshake */ });
    server.listen(0, cfg.listenHost || "127.0.0.1", function () {
      handle.server = server;
      handle.port = server.address().port;
      resolve(handle);
    });
  });
}

function _startUdpServer(onMessage, family, address) {
  return new Promise(function (resolve) {
    var sock = dgram.createSocket(family || "udp4");
    sock.on("error", function () { /* best-effort loopback listener */ });
    sock.on("message", function (msg, rinfo) { onMessage(msg, rinfo, sock); });
    sock.bind(0, address || "127.0.0.1", function () {
      resolve({ sock: sock, port: sock.address().port });
    });
  });
}

function _close(h) {
  if (!h) return;
  try { if (h.server) h.server.close(); } catch (_e) { /* best-effort */ }
  try { if (h.sock) h.sock.close(); } catch (_e) { /* best-effort */ }
}

// ---------------------------------------------------------------------------
// AES-SIV-CMAC (RFC 5297).
// ---------------------------------------------------------------------------

function _hex(s) { return Buffer.from(s.replace(/\s+/g, ""), "hex"); }

function testAesSivKnownAnswers() {
  // RFC 5297 Appendix A.1, deterministic authenticated encryption.
  var k1  = _hex("fffefdfc fbfaf9f8 f7f6f5f4 f3f2f1f0 f0f1f2f3 f4f5f6f7 f8f9fafb fcfdfeff");
  var ad1 = _hex("10111213 14151617 18191a1b 1c1d1e1f 20212223 24252627");
  var pt1 = _hex("11223344 55667788 99aabbcc ddee");
  var out1 = _hex("85632d07 c6e8f37f 950acd32 0a2ecc93 40c02b96 90c4dc04 daef7f6a fe5c");
  check("SIV RFC 5297 A.1 encrypt", nts.aesSivEncrypt(k1, pt1, [ad1]).equals(out1));
  check("SIV RFC 5297 A.1 decrypt", nts.aesSivDecrypt(k1, out1, [ad1]).equals(pt1));

  // RFC 5297 Appendix A.2, nonce-based: the nonce is the last AD component.
  var k2  = _hex("7f7e7d7c 7b7a7978 77767574 73727170 40414243 44454647 48494a4b 4c4d4e4f");
  var a21 = _hex("00112233 44556677 8899aabb ccddeeff deaddada deaddada ffeeddcc bbaa9988 77665544 33221100");
  var a22 = _hex("10203040 50607080 90a0");
  var n2  = _hex("09f91102 9d74e35b d84156c5 635688c0");
  var pt2 = _hex("74686973 20697320 736f6d65 20706c61 696e7465 78742074 6f20656e 63727970 74207573 696e6720 5349562d 414553");
  var out2 = _hex("7bdb6e3b 432667eb 06f4d14b ff2fbd0f cb900f2f ddbe4043 26601965 c889bf17 dba77ceb 094fa663 b7a3f748 ba8af829 ea64ad54 4a272e9c 485b62a3 fd5c0d");
  check("SIV RFC 5297 A.2 encrypt", nts.aesSivEncrypt(k2, pt2, [a21, a22, n2]).equals(out2));
  check("SIV RFC 5297 A.2 decrypt", nts.aesSivDecrypt(k2, out2, [a21, a22, n2]).equals(pt2));

  // Control: one changed AD byte must change the synthetic IV, so the vectors
  // above cannot pass on an implementation that ignores the AD.
  var ad1b = Buffer.from(ad1); ad1b[0] ^= 1;
  check("SIV A.1 with a changed AD byte does not reproduce the vector",
        !nts.aesSivEncrypt(k1, pt1, [ad1b]).equals(out1));
}

function testAesSivRoundtrip() {
  var K = nodeCrypto.randomBytes(32);
  var ad = [Buffer.from("associated-one"), Buffer.from("associated-two")];
  var longPt = Buffer.from("the quick brown fox jumps over the lazy dog twice");
  var ct = nts.aesSivEncrypt(K, longPt, ad);
  check("SIV roundtrip 32-byte key, multi-block plaintext", nts.aesSivDecrypt(K, ct, ad).equals(longPt));
  var shortPt = Buffer.from("hi");
  check("SIV roundtrip sub-block plaintext",
        nts.aesSivDecrypt(K, nts.aesSivEncrypt(K, shortPt, ad), ad).equals(shortPt));
  var K48 = nodeCrypto.randomBytes(48);
  check("SIV roundtrip 48-byte key",
        nts.aesSivDecrypt(K48, nts.aesSivEncrypt(K48, longPt, ad), ad).equals(longPt));
  var K64 = nodeCrypto.randomBytes(64);
  check("SIV roundtrip 64-byte key",
        nts.aesSivDecrypt(K64, nts.aesSivEncrypt(K64, longPt, ad), ad).equals(longPt));
  check("SIV roundtrip with no associated data",
        nts.aesSivDecrypt(K, nts.aesSivEncrypt(K, longPt)).equals(longPt));
}

function _codeOf(fn) {
  try { fn(); } catch (e) { return { code: e && e.code, nts: e instanceof nts.NtsError }; }
  return { code: null, nts: false };
}

function testAesSivBadKey() {
  var cases = [
    ["encrypt with a 31-byte key",   function () { nts.aesSivEncrypt(nodeCrypto.randomBytes(31), Buffer.from("x"), []); }, "nts/bad-key"],
    ["encrypt with a string key",    function () { nts.aesSivEncrypt("a".repeat(32), Buffer.from("x"), []); },             "nts/bad-key"],
    ["encrypt with a null key",      function () { nts.aesSivEncrypt(null, Buffer.from("x"), []); },                       "nts/bad-key"],
    ["decrypt with a 16-byte key",   function () { nts.aesSivDecrypt(nodeCrypto.randomBytes(16), nodeCrypto.randomBytes(40), []); }, "nts/bad-key"],
    ["decrypt with a null key",      function () { nts.aesSivDecrypt(null, nodeCrypto.randomBytes(40), []); },             "nts/bad-key"],
    ["decrypt of an 8-byte input",   function () { nts.aesSivDecrypt(nodeCrypto.randomBytes(32), nodeCrypto.randomBytes(8), []); }, "nts/auth-failed"],
    ["decrypt of an empty input",    function () { nts.aesSivDecrypt(nodeCrypto.randomBytes(32), Buffer.alloc(0), []); }, "nts/auth-failed"],
    ["encrypt of a string plaintext", function () { nts.aesSivEncrypt(nodeCrypto.randomBytes(32), "string pt", []); },    "nts/bad-input"],
    ["encrypt of a null plaintext",  function () { nts.aesSivEncrypt(nodeCrypto.randomBytes(32), null, []); },             "nts/bad-input"],
    ["encrypt with a string AD component", function () { nts.aesSivEncrypt(nodeCrypto.randomBytes(32), Buffer.from("x"), ["ad"]); }, "nts/bad-input"],
    ["encrypt with a Buffer as the AD list", function () { nts.aesSivEncrypt(nodeCrypto.randomBytes(32), Buffer.from("x"), Buffer.from("ad")); }, "nts/bad-input"],
    ["encrypt with 127 AD components", function () {
      var many = []; for (var i = 0; i < 127; i++) many.push(Buffer.alloc(1));
      nts.aesSivEncrypt(nodeCrypto.randomBytes(32), Buffer.from("x"), many);
    }, "nts/bad-input"],
    ["decrypt with a Buffer as the AD list", function () { nts.aesSivDecrypt(nodeCrypto.randomBytes(32), nodeCrypto.randomBytes(32), Buffer.from("ad")); }, "nts/bad-input"],
    ["decrypt with a null AD component", function () { nts.aesSivDecrypt(nodeCrypto.randomBytes(32), nodeCrypto.randomBytes(32), [null]); }, "nts/bad-input"],
  ];
  cases.forEach(function (c) {
    var r = _codeOf(c[1]);
    check("SIV " + c[0] + " is " + c[2], r.code === c[2] && r.nts, JSON.stringify(r));
  });
}

function testAesSivTamperFailsClosed() {
  var K = nodeCrypto.randomBytes(32);
  var ct = Buffer.from(nts.aesSivEncrypt(K, Buffer.from("authenticate me if you can"), []));
  ct[0] ^= 0xff;
  var r = _codeOf(function () { nts.aesSivDecrypt(K, ct, []); });
  check("SIV tamper code is nts/auth-failed", r.code === "nts/auth-failed");
}

// ---------------------------------------------------------------------------
// AEAD identifiers.
// ---------------------------------------------------------------------------

function testAeadIdsAreIanaIds() {
  check("AEAD_AES_SIV_CMAC_256 is the IANA id 15", nts.AEAD_AES_SIV_CMAC_256 === AEAD_SIV);
  check("AEAD_CHACHA20_POLY1305 is the IANA id 29 (30 is AES-128-GCM-SIV)",
        nts.AEAD_CHACHA20_POLY1305 === AEAD_CHACHA, String(nts.AEAD_CHACHA20_POLY1305));
}

// ---------------------------------------------------------------------------
// Synchronous input validation.
// ---------------------------------------------------------------------------

function _syncOrAsyncCode(fn) {
  var out = { code: null, sync: false };
  try {
    var p = fn();
    if (p && typeof p.then === "function") p.catch(function () { /* settled below or ignored */ });
  } catch (e) { out.code = e && e.code; out.sync = true; }
  return out;
}

function testKeInputValidation() {
  check("KE missing host is nts/bad-host", _codeOf(function () { nts.performKeHandshake({}); }).code === "nts/bad-host");
  check("KE out-of-range port is nts/bad-ke-port",
        _codeOf(function () { nts.performKeHandshake({ host: "h", port: 70000 }); }).code === "nts/bad-ke-port");
  var e3 = null;
  try { nts.performKeHandshake({ host: "h", bogus: 1 }); } catch (e) { e3 = e; }
  check("KE unknown opt rejected", e3 && /unknown option/.test(e3.message));

  // The AEAD offer is caller input written onto the wire, so a value the
  // client cannot use is refused before a socket opens.
  var circular = {}; circular.self = circular;
  var badAeads = [
    ["[70000]", [70000]], ["[-1]", [-1]], ["\"xyz\"", "xyz"], ["[16]", [16]], ["[30]", [AEAD_GCMSIV]],
    ["[15, 15]", [15, 15]], ["[15.5]", [15.5]], ["[]", []], ["[null]", [null]],
    ["[15n]", [BigInt(15)]], ["[a circular object]", [circular]],
  ];
  badAeads.forEach(function (c) {
    var r = _syncOrAsyncCode(function () { return nts.performKeHandshake({ host: "h", aead: c[1] }); });
    check("KE aead " + c[0] + " throws nts/bad-aead synchronously",
          r.sync && r.code === "nts/bad-aead", JSON.stringify(r));
  });

  // servername is config-time input: a wrong type is refused rather than
  // dialed without SNI.
  [42, {}, ""].forEach(function (sn) {
    var r = _syncOrAsyncCode(function () { return nts.performKeHandshake({ host: "h", servername: sn }); });
    check("KE servername " + JSON.stringify(sn) + " throws nts/bad-servername synchronously",
          r.sync && r.code === "nts/bad-servername", JSON.stringify(r));
  });
  var ok = _syncOrAsyncCode(function () { return nts.performKeHandshake({ host: "h.invalid", aead: [AEAD_CHACHA, AEAD_SIV], timeoutMs: 50 }); });
  check("KE aead [29, 15] is accepted", ok.code === null, JSON.stringify(ok));

  ["x", -5, 0, Infinity, 1e12].forEach(function (t) {
    var r = _syncOrAsyncCode(function () { return nts.performKeHandshake({ host: "h", timeoutMs: t }); });
    check("KE timeoutMs " + String(t) + " throws nts/bad-timeout", r.sync && r.code === "nts/bad-timeout", JSON.stringify(r));
  });
}

async function testQueryInputValidation() {
  var codes = {};
  await nts.query({ host: "h", aead: "xyz" }).catch(function (e) { codes.aead = e && e.code; });
  await nts.query({ host: "h", timeoutMs: -1 }).catch(function (e) { codes.timeout = e && e.code; });
  await nts.query({ host: "h", servername: 42 }).catch(function (e) { codes.servername = e && e.code; });
  check("query refuses a non-string servername with nts/bad-servername",
        codes.servername === "nts/bad-servername", String(codes.servername));
  check("query refuses a bad aead offer with nts/bad-aead", codes.aead === "nts/bad-aead", String(codes.aead));
  check("query refuses a bad timeoutMs with nts/bad-timeout", codes.timeout === "nts/bad-timeout", String(codes.timeout));
}

function testQuerySingleInputValidation() {
  var k = Buffer.alloc(32);
  var buf = Buffer.alloc(4);
  check("querySingle out-of-range port is nts/bad-ntp-port",
        _codeOf(function () { nts.querySingle({ host: "h", port: 99999, c2sKey: buf, s2cKey: buf, cookies: [buf] }); }).code === "nts/bad-ntp-port");
  check("querySingle missing c2sKey", _codeOf(function () { nts.querySingle({ host: "h" }); }).code === "nts/no-c2s-key");
  check("querySingle missing s2cKey", _codeOf(function () { nts.querySingle({ host: "h", c2sKey: buf }); }).code === "nts/no-s2c-key");
  check("querySingle missing cookies",
        _codeOf(function () { nts.querySingle({ host: "h", c2sKey: buf, s2cKey: buf }); }).code === "nts/no-cookies");

  var cases = [
    ["no host",                     { aeadId: AEAD_SIV, c2sKey: k, s2cKey: k, cookies: [k] },                         "nts/bad-host"],
    ["an empty host",               { host: "", aeadId: AEAD_SIV, c2sKey: k, s2cKey: k, cookies: [k] },               "nts/bad-host"],
    ["ChaCha with a 16-byte key",   { host: "h", aeadId: AEAD_CHACHA, c2sKey: Buffer.alloc(16), s2cKey: k, cookies: [k] }, "nts/bad-key"],
    ["SIV with a 48-byte s2c key",  { host: "h", aeadId: AEAD_SIV, c2sKey: k, s2cKey: Buffer.alloc(48), cookies: [k] }, "nts/bad-key"],
    ["an unknown aeadId",           { host: "h", aeadId: 999, c2sKey: k, s2cKey: k, cookies: [k] },                   "nts/unsupported-aead"],
    ["the GCM-SIV aeadId",          { host: "h", aeadId: AEAD_GCMSIV, c2sKey: k, s2cKey: k, cookies: [k] },           "nts/unsupported-aead"],
    ["no aeadId",                   { host: "h", c2sKey: k, s2cKey: k, cookies: [k] },                                "nts/unsupported-aead"],
    ["a BigInt aeadId",             { host: "h", aeadId: BigInt(15), c2sKey: k, s2cKey: k, cookies: [k] },            "nts/unsupported-aead"],
    ["a circular aeadId",           { host: "h", aeadId: (function () { var o = {}; o.self = o; return o; })(), c2sKey: k, s2cKey: k, cookies: [k] }, "nts/unsupported-aead"],
    ["a string timeoutMs",          { host: "h", aeadId: AEAD_SIV, c2sKey: k, s2cKey: k, cookies: [k], timeoutMs: "x" }, "nts/bad-timeout"],
    ["a negative timeoutMs",        { host: "h", aeadId: AEAD_SIV, c2sKey: k, s2cKey: k, cookies: [k], timeoutMs: -5 },  "nts/bad-timeout"],
    ["a timeoutMs past the timer range", { host: "h", aeadId: AEAD_SIV, c2sKey: k, s2cKey: k, cookies: [k], timeoutMs: 1e12 }, "nts/bad-timeout"],
  ];
  cases.forEach(function (c) {
    var r = _syncOrAsyncCode(function () { return nts.querySingle(c[1]); });
    check("querySingle " + c[0] + " throws " + c[2] + " synchronously", r.sync && r.code === c[2], JSON.stringify(r));
  });
}

// ---------------------------------------------------------------------------
// performKeHandshake network paths.
// ---------------------------------------------------------------------------

async function _connectKe(cert, ke, extra) {
  return helpers.withTestTimeout("nts KE", function () {
    return nts.performKeHandshake(Object.assign({
      host:       "127.0.0.1",
      port:       ke.port,
      servername: "localhost",
      ca:         cert.ca.caCertPem,
      timeoutMs:  4000,
    }, extra || {}));
  }, { timeoutMs: 9000 });
}

async function _connectKeExpectReject(cert, ke, expectedCode, label, extra) {
  var caught = null;
  try { await _connectKe(cert, ke, extra); } catch (e) { caught = e; }
  check(label + " code=" + expectedCode, caught && caught.code === expectedCode,
        caught ? (caught.code + " :: " + caught.message) : "resolved");
  check(label + " is an NtsError", caught instanceof nts.NtsError);
  return caught;
}

async function testKeBadAlpn(cert) {
  var ke = await _startKeServer(cert, { setAlpn: false, onData: null });
  try { await _connectKeExpectReject(cert, ke, "nts/bad-alpn", "KE non-ntske ALPN"); }
  finally { _close(ke); }
}

// The default offer goes on the wire, so every id in it has to be one the
// client implements, and the one RFC 8915 makes mandatory has to lead.
async function testKeDefaultOffer(cert) {
  var ke = await _startKeServer(cert, { onData: function () {
    return Buffer.concat([_np(), _aead(AEAD_SIV), _cookie(), _end()]);
  } });
  try {
    await _connectKe(cert, ke);
    var recs = _parseRecords(ke.requests[0] || Buffer.alloc(0));
    var aeadRec = recs.find(function (r) { return r.type === REC_AEAD; });
    var ids = [];
    for (var i = 0; aeadRec && i + 1 < aeadRec.body.length; i += 2) ids.push(aeadRec.body.readUInt16BE(i));
    check("default offer leads with AES-SIV-CMAC-256", ids[0] === AEAD_SIV, JSON.stringify(ids));
    check("default offer names only AEADs the client implements",
          ids.length > 0 && ids.every(function (id) { return id === AEAD_SIV || id === AEAD_CHACHA; }), JSON.stringify(ids));
    check("default offer does not advertise AES-128-GCM-SIV", ids.indexOf(AEAD_GCMSIV) === -1, JSON.stringify(ids));
    var npRec = recs.find(function (r) { return r.type === REC_NEXT_PROTOCOL; });
    check("request carries one critical Next Protocol record for NTPv4",
          npRec && npRec.critical && npRec.body.length === 2 && npRec.body.readUInt16BE(0) === 0);
  } finally { _close(ke); }
}

async function testKeAdversarialRecords(cert) {
  var cases = [
    // Error and Warning records.
    { label: "KE server error record", code: "nts/ke-error", body: function () {
        return Buffer.concat([_rec(true, REC_ERROR, _u16(1)), _end()]); },
      after: function (e) { check("KE error record carries the server's error code", e && e.ntsErrorCode === 1); } },
    { label: "KE error record with an empty body", code: "nts/bad-record", body: function () {
        return Buffer.concat([_rec(true, REC_ERROR, Buffer.alloc(0)), _end()]); } },
    { label: "KE error record with a 1-byte body", code: "nts/bad-record", body: function () {
        return Buffer.concat([_rec(true, REC_ERROR, Buffer.alloc(1)), _end()]); } },
    { label: "KE critical warning record", code: "nts/ke-warning", body: function () {
        return Buffer.concat([_np(), _aead(AEAD_SIV), _rec(true, REC_WARNING, _u16(7)), _cookie(), _end()]); } },
    { label: "KE non-critical warning record", code: "nts/ke-warning", body: function () {
        return Buffer.concat([_np(), _aead(AEAD_SIV), _rec(false, REC_WARNING, _u16(0)), _cookie(), _end()]); } },
    { label: "KE warning record with a 1-byte body", code: "nts/bad-record", body: function () {
        return Buffer.concat([_np(), _aead(AEAD_SIV), _rec(true, REC_WARNING, Buffer.alloc(1)), _cookie(), _end()]); } },
    // Unknown critical record.
    { label: "KE unrecognized critical record", code: "nts/unrecognized-critical", body: function () {
        return Buffer.concat([_np(), _aead(AEAD_SIV), _cookie(), _rec(true, 0x1234, Buffer.from("x")), _end()]); } },
    // Next Protocol.
    { label: "KE no Next Protocol record", code: "nts/bad-next-protocol", body: function () {
        return Buffer.concat([_aead(AEAD_SIV), _cookie(), _end()]); } },
    { label: "KE empty Next Protocol record", code: "nts/no-ntpv4", body: function () {
        return Buffer.concat([_rec(true, REC_NEXT_PROTOCOL, Buffer.alloc(0)), _aead(AEAD_SIV), _cookie(), _end()]); } },
    { label: "KE Next Protocol naming a protocol not offered", code: "nts/bad-next-protocol", body: function () {
        return Buffer.concat([_rec(true, REC_NEXT_PROTOCOL, _u16(0x8001)), _aead(AEAD_SIV), _cookie(), _end()]); } },
    { label: "KE odd-length Next Protocol record", code: "nts/bad-next-protocol", body: function () {
        return Buffer.concat([_rec(true, REC_NEXT_PROTOCOL, Buffer.alloc(1)), _aead(AEAD_SIV), _cookie(), _end()]); } },
    { label: "KE non-critical Next Protocol record", code: "nts/bad-next-protocol", body: function () {
        return Buffer.concat([_rec(false, REC_NEXT_PROTOCOL, _u16(0)), _aead(AEAD_SIV), _cookie(), _end()]); } },
    { label: "KE two Next Protocol records", code: "nts/bad-next-protocol", body: function () {
        return Buffer.concat([_np(), _np(), _aead(AEAD_SIV), _cookie(), _end()]); } },
    // AEAD choice.
    { label: "KE missing AEAD record", code: "nts/no-aead", body: function () {
        return Buffer.concat([_np(), _cookie(), _end()]); } },
    { label: "KE empty AEAD record", code: "nts/no-aead", body: function () {
        return Buffer.concat([_np(), _rec(true, REC_AEAD, Buffer.alloc(0)), _cookie(), _end()]); } },
    { label: "KE 1-byte AEAD body", code: "nts/bad-aead-response", body: function () {
        return Buffer.concat([_np(), _rec(true, REC_AEAD, Buffer.alloc(1)), _cookie(), _end()]); } },
    { label: "KE AEAD the client did not offer (99)", code: "nts/bad-aead-response", body: function () {
        return Buffer.concat([_np(), _aead(99), _cookie(), _end()]); } },
    { label: "KE AEAD body naming two ids", code: "nts/bad-aead-response", body: function () {
        return Buffer.concat([_np(), _rec(true, REC_AEAD, _u16s([AEAD_SIV, AEAD_CHACHA])), _cookie(), _end()]); } },
    { label: "KE two AEAD records", code: "nts/bad-record", body: function () {
        return Buffer.concat([_np(), _aead(AEAD_SIV), _aead(AEAD_CHACHA), _cookie(), _end()]); } },
    { label: "KE AEAD outside an offer of [15] (ChaCha)", code: "nts/bad-aead-response", extra: { aead: [AEAD_SIV] }, body: function () {
        return Buffer.concat([_np(), _aead(AEAD_CHACHA), _cookie(), _end()]); } },
    { label: "KE AEAD outside an offer of [15] (GCM-SIV)", code: "nts/bad-aead-response", extra: { aead: [AEAD_SIV] }, body: function () {
        return Buffer.concat([_np(), _aead(AEAD_GCMSIV), _cookie(), _end()]); } },
    // Cookies.
    { label: "KE no cookies", code: "nts/no-cookies", body: function () {
        return Buffer.concat([_np(), _aead(AEAD_SIV), _end()]); } },
    // NTPv4 Server and Port records.
    { label: "KE empty NTPv4 Server record", code: "nts/bad-ntp-server", body: function () {
        return Buffer.concat([_np(), _aead(AEAD_SIV), _cookie(), _rec(true, REC_NTPV4_SERVER, Buffer.alloc(0)), _end()]); } },
    { label: "KE NTPv4 Server record with a zone id", code: "nts/bad-ntp-server", body: function () {
        return Buffer.concat([_np(), _aead(AEAD_SIV), _cookie(), _rec(true, REC_NTPV4_SERVER, Buffer.from("fe80::1%eth0")), _end()]); } },
    { label: "KE NTPv4 Server record with a non-ASCII byte", code: "nts/bad-ntp-server", body: function () {
        return Buffer.concat([_np(), _aead(AEAD_SIV), _cookie(), _rec(true, REC_NTPV4_SERVER, Buffer.from([0x61, 0xff])), _end()]); } },
    { label: "KE two NTPv4 Server records", code: "nts/bad-ntp-server", body: function () {
        return Buffer.concat([_np(), _aead(AEAD_SIV), _cookie(),
          _rec(true, REC_NTPV4_SERVER, Buffer.from("127.0.0.1")), _rec(true, REC_NTPV4_SERVER, Buffer.from("127.0.0.2")), _end()]); } },
    { label: "KE NTPv4 Port record of 0", code: "nts/bad-ntp-port", body: function () {
        return Buffer.concat([_np(), _aead(AEAD_SIV), _cookie(), _rec(true, REC_NTPV4_PORT, _u16(0)), _end()]); } },
    { label: "KE 1-byte NTPv4 Port record", code: "nts/bad-ntp-port", body: function () {
        return Buffer.concat([_np(), _aead(AEAD_SIV), _cookie(), _rec(true, REC_NTPV4_PORT, Buffer.alloc(1)), _end()]); } },
    { label: "KE two NTPv4 Port records", code: "nts/bad-ntp-port", body: function () {
        return Buffer.concat([_np(), _aead(AEAD_SIV), _cookie(), _rec(true, REC_NTPV4_PORT, _u16(123)), _rec(true, REC_NTPV4_PORT, _u16(124)), _end()]); } },
    // Framing.
    { label: "KE record header claiming more than the handshake cap", code: "nts/ke-too-large", body: function () {
        var h = Buffer.alloc(4);
        h.writeUInt16BE(REC_NEW_COOKIE & 0x7fff, 0);
        h.writeUInt16BE(0xffff, 2);
        return Buffer.concat([_np(), _aead(AEAD_SIV), h]); } },
    { label: "KE connection closed inside a record", code: "nts/ke-closed", endAfter: true, body: function () {
        var h = Buffer.alloc(4);
        h.writeUInt16BE(REC_NEW_COOKIE & 0x7fff, 0);
        h.writeUInt16BE(0x0100, 2);
        return Buffer.concat([_np(), _aead(AEAD_SIV), h, Buffer.alloc(10)]); } },
    { label: "KE connection closed before End of Message", code: "nts/ke-closed", endAfter: true, body: function () {
        return _np(); } },
  ];

  for (var i = 0; i < cases.length; i++) {
    var c = cases[i];
    var ke = await _startKeServer(cert, { onData: c.body, endAfter: !!c.endAfter });
    try {
      var err = await _connectKeExpectReject(cert, ke, c.code, c.label, c.extra);
      if (c.after) c.after(err);
    } finally { _close(ke); }
  }
}

async function testKeSuccess(cert) {
  // No NTPv4 Server / Port records: the NTP server defaults to the address
  // the KE connection reached and the port to 123. A non-critical record of
  // an unknown type is ignored.
  var ke = await _startKeServer(cert, { onData: function () {
    return Buffer.concat([
      _np(),
      _aead(AEAD_SIV),
      _rec(false, 0x1234, Buffer.alloc(4)),
      _cookie(32),
      _end(),
    ]);
  } });
  try {
    var res = await _connectKe(cert, ke);
    check("KE success negotiates SIV", res.aeadId === AEAD_SIV);
    check("KE success exports 32-byte c2sKey", Buffer.isBuffer(res.c2sKey) && res.c2sKey.length === 32);
    check("KE success exports 32-byte s2cKey", Buffer.isBuffer(res.s2cKey) && res.s2cKey.length === 32);
    check("KE success returns one cookie", res.cookies.length === 1);
    check("KE success defaults ntpServer to the KE address", res.ntpServer === "127.0.0.1");
    check("KE success defaults ntpPort to 123", res.ntpPort === 123);
    check("KE success carries no warnings field", !("warnings" in res));
  } finally { _close(ke); }
}

// RFC 8915 section 4.1.7: with no Server record the client associates with
// the address the KE connection used, not a fresh resolution of the name.
async function testKeNtpServerIsTheKeAddress(cert) {
  var ke = await _startKeServer(cert, { onData: function () {
    return Buffer.concat([_np(), _aead(AEAD_SIV), _cookie(), _end()]);
  } });
  try {
    var res = await _connectKe(cert, ke, { host: "localhost", servername: undefined });
    check("KE dialed by name reports the address it reached as ntpServer",
          res.ntpServer === "127.0.0.1", String(res.ntpServer));
  } finally { _close(ke); }
}

// An IP-literal KE host carries no SNI (RFC 6066 section 3), and the server
// certificate is checked against its IP SANs instead.
async function testKeIpLiteralSendsNoSni(cert) {
  var hosts = [["127.0.0.1", "127.0.0.1"]];
  if (_hasIpv6Loopback()) hosts.push(["::1", "::1"]);
  else helpers.unavailable("KE IPv6 literal", "no ::1 loopback on this host");
  for (var i = 0; i < hosts.length; i++) {
    var ke = await _startKeServer(cert, { listenHost: hosts[i][1], onData: function () {
      return Buffer.concat([_np(), _aead(AEAD_SIV), _cookie(), _end()]);
    } });
    try {
      var res = null; var err = null;
      try {
        res = await helpers.withTestTimeout("KE IP literal", function () {
          return nts.performKeHandshake({ host: hosts[i][0], port: ke.port, ca: cert.ca.caCertPem, timeoutMs: 4000 });
        }, { timeoutMs: 9000 });
      } catch (e) { err = e; }
      check("KE to IP literal " + hosts[i][0] + " with no servername resolves",
            res && res.aeadId === AEAD_SIV, err ? (err.code + " :: " + err.message) : "");
      check("KE to IP literal " + hosts[i][0] + " sent no SNI",
            ke.servernames.length === 1 && ke.servernames[0] === false, JSON.stringify(ke.servernames));
    } finally { _close(ke); }
  }

  // The hostname control: a name still goes out as SNI.
  var keName = await _startKeServer(cert, { onData: function () {
    return Buffer.concat([_np(), _aead(AEAD_SIV), _cookie(), _end()]);
  } });
  try {
    await _connectKe(cert, keName, { host: "localhost", servername: undefined });
    check("KE to a hostname sends it as SNI", keName.servernames[0] === "localhost", JSON.stringify(keName.servernames));
  } finally { _close(keName); }
}

// The ntp-check consumer has no servername option, so an IP-literal NTS
// endpoint reaches the KE dial with the bare address.
async function testCheckDriftDialsAnIpLiteralNtsEndpoint(cert) {
  var ke = await _startKeServer(cert, { onData: null });
  try {
    var result = await b.ntpCheck.checkDrift({
      ntsServers: ["127.0.0.1:" + ke.port], requireNts: true, timeoutMs: 2000,
    });
    var code = result && result.error && result.error.code;
    check("checkDrift to an IP-literal NTS endpoint opens the TLS connection",
          ke.connections >= 1, "connections=" + ke.connections + " error=" + code);
    check("checkDrift to an IP-literal NTS endpoint fails as an NTS error, not a TypeError",
          typeof code === "string" && code.indexOf("nts/") === 0, String(code));
  } finally { _close(ke); }
}

async function testKeResponseSplitAcrossWrites(cert) {
  var resp = Buffer.concat([_np(), _aead(AEAD_SIV), _rec(false, REC_NEW_COOKIE, Buffer.alloc(100, 0x41)), _end()]);
  var ke = await _startKeServer(cert, { onData: function () {
    return [{ data: resp.slice(0, 20), delayMs: 0 }, { data: resp.slice(20), delayMs: 50 }];
  } });
  try {
    var res = null; var err = null;
    try { res = await _connectKe(cert, ke); } catch (e) { err = e; }
    check("KE response split inside a record body resolves", res && res.cookies.length === 1,
          err ? (err.code + " :: " + err.message) : "");
  } finally { _close(ke); }

  // A response larger than one TLS record (16 KiB) arrives in several reads.
  var big = [_np(), _aead(AEAD_SIV)];
  for (var i = 0; i < 20; i++) big.push(_rec(false, REC_NEW_COOKIE, Buffer.alloc(1000, 0x42)));
  big.push(_end());
  var ke2 = await _startKeServer(cert, { onData: function () { return Buffer.concat(big); } });
  try {
    var res2 = null; var err2 = null;
    try { res2 = await _connectKe(cert, ke2); } catch (e) { err2 = e; }
    check("KE response spanning several TLS records resolves", res2 && res2.cookies.length === 20,
          err2 ? (err2.code + " :: " + err2.message) : "");
  } finally { _close(ke2); }
}

async function testKeTimeout(cert) {
  var ke = await _startKeServer(cert, { onData: null });
  try { await _connectKeExpectReject(cert, ke, "nts/ke-timeout", "KE wall-clock timeout", { timeoutMs: 300 }); }
  finally { _close(ke); }
}

async function testKeByteCapFailsClosed(cert) {
  // 128 KB of well-formed non-END cookie records, sized so they do not tile
  // TLS records evenly: the read accumulator must fail closed at the 64 KiB
  // ceiling, not hang until the wall-clock timer fires.
  var one = _rec(false, REC_NEW_COOKIE, Buffer.alloc(996, 0x41)); // 1000 bytes
  var chunks = [];
  for (var i = 0; i < 128; i++) chunks.push(one);
  var big = Buffer.concat(chunks);
  var ke = await _startKeServer(cert, { onData: function () { return big; } });
  try { await _connectKeExpectReject(cert, ke, "nts/ke-too-large", "KE handshake byte cap"); }
  finally { _close(ke); }
}

async function testKeSocketError() {
  var srv = net.createServer(function (s) { s.destroy(); });
  await new Promise(function (res) { srv.listen(0, "127.0.0.1", res); });
  var port = srv.address().port;
  var caught = null;
  try {
    await helpers.withTestTimeout("KE socket reset", function () {
      return nts.performKeHandshake({ host: "127.0.0.1", port: port, servername: "localhost", timeoutMs: 4000 });
    }, { timeoutMs: 9000 });
  } catch (e) { caught = e; }
  try { srv.close(); } catch (_e) { /* best-effort */ }
  check("KE socket reset code is nts/ke-socket", caught && caught.code === "nts/ke-socket");
}

// ---------------------------------------------------------------------------
// querySingle network paths.
// ---------------------------------------------------------------------------

function _qsOpts(port, extra) {
  return Object.assign({
    host: "127.0.0.1", port: port, aeadId: AEAD_SIV,
    c2sKey: nodeCrypto.randomBytes(32), s2cKey: nodeCrypto.randomBytes(32),
    cookies: [nodeCrypto.randomBytes(32)], timeoutMs: 300,
  }, extra || {});
}

async function _udpExpectReject(makeReply, expectedCode, label, extra) {
  var udp = await _startUdpServer(function (msg, rinfo, s) {
    var reply = makeReply(msg);
    if (reply) s.send(reply, 0, reply.length, rinfo.port, rinfo.address);
  });
  var caught = null;
  try {
    await helpers.withTestTimeout(label, function () { return nts.querySingle(_qsOpts(udp.port, extra)); }, { timeoutMs: 9000 });
  } catch (e) { caught = e; }
  _close(udp);
  check(label + " code=" + expectedCode, caught && caught.code === expectedCode,
        caught ? (caught.code + " :: " + caught.message) : "resolved");
  return caught;
}

// Each of these is discarded, and the query reports the reason it saw when
// nothing acceptable arrives before the timeout.
async function testQuerySingleAdversarialReplies() {
  await _udpExpectReject(function () { return Buffer.alloc(10); }, "nts/bad-reply", "querySingle short reply");
  await _udpExpectReject(function () { return Buffer.alloc(NTP_HEADER_BYTES); }, "nts/unique-mismatch", "querySingle no unique-id");
  await _udpExpectReject(function () {
    return Buffer.concat([Buffer.alloc(NTP_HEADER_BYTES), _rawExt(EXT_UNIQUE, 2, Buffer.alloc(0))]);
  }, "nts/bad-extension", "querySingle extension len<4");
  await _udpExpectReject(function () {
    return Buffer.concat([Buffer.alloc(NTP_HEADER_BYTES), _rawExt(EXT_UNIQUE, 40, Buffer.alloc(0))]);
  }, "nts/bad-extension", "querySingle extension overrun");
  await _udpExpectReject(function (msg) {
    var u = _findExtBody(msg, NTP_HEADER_BYTES, EXT_UNIQUE);
    return Buffer.concat([Buffer.alloc(NTP_HEADER_BYTES), _ext(EXT_UNIQUE, u)]);
  }, "nts/no-authenticator", "querySingle missing authenticator");
  await _udpExpectReject(function (msg) {
    var u = _findExtBody(msg, NTP_HEADER_BYTES, EXT_UNIQUE);
    return Buffer.concat([Buffer.alloc(NTP_HEADER_BYTES), _ext(EXT_UNIQUE, u), _rawExt(EXT_AUTH, 6, Buffer.from([0xaa, 0xbb]))]);
  }, "nts/bad-authenticator", "querySingle truncated authenticator");
  await _udpExpectReject(function (msg) {
    var u = _findExtBody(msg, NTP_HEADER_BYTES, EXT_UNIQUE);
    var ab = Buffer.alloc(8);
    ab.writeUInt16BE(100, 0);
    ab.writeUInt16BE(100, 2);
    return Buffer.concat([Buffer.alloc(NTP_HEADER_BYTES), _ext(EXT_UNIQUE, u), _ext(EXT_AUTH, ab)]);
  }, "nts/bad-authenticator", "querySingle overlong authenticator lengths");
}

async function testQuerySingleAuthFailed() {
  var s2cKey = nodeCrypto.randomBytes(32);
  await _udpExpectReject(function (msg) {
    var u = _findExtBody(msg, NTP_HEADER_BYTES, EXT_UNIQUE);
    return u ? _buildReply({ aeadId: AEAD_SIV, s2cKey: s2cKey, uniqueId: u, corruptCt: true }) : null;
  }, "nts/auth-failed", "querySingle forged authenticator", { s2cKey: s2cKey });
}

// RFC 8915 section 5.7: a reply that fails the unique-id or authenticator
// checks is discarded and the client keeps waiting. A hostile datagram that
// arrives first must not decide the query.
async function testQuerySingleDiscardsHostileDatagramsAndKeepsWaiting() {
  var s2cKey = nodeCrypto.randomBytes(32);
  var hostile = [
    ["ten junk bytes",                     function () { return Buffer.alloc(10); }],
    ["a wrong unique identifier",          function () { return _buildReply({ aeadId: AEAD_SIV, s2cKey: s2cKey, uniqueId: nodeCrypto.randomBytes(32) }); }],
    ["the right uid with no authenticator", function (u) { return _buildReply({ uniqueId: u, omitAuth: true }); }],
    ["a forged authenticator",             function (u) { return _buildReply({ aeadId: AEAD_SIV, s2cKey: s2cKey, uniqueId: u, corruptCt: true }); }],
    ["an NTS NAK",                         function (u) { return _buildReply({ uniqueId: u, omitAuth: true, stratum: 0, refid: "NTSN" }); }],
  ];
  for (var i = 0; i < hostile.length; i++) {
    var h = hostile[i];
    var udp = await _startUdpServer(function (msg, rinfo, s) {
      var u = _findExtBody(msg, NTP_HEADER_BYTES, EXT_UNIQUE);
      if (!u) return;
      var first = h[1](u);
      s.send(first, 0, first.length, rinfo.port, rinfo.address);
      setTimeout(function () {
        var good = _buildReply({ aeadId: AEAD_SIV, s2cKey: s2cKey, uniqueId: u });
        try { s.send(good, 0, good.length, rinfo.port, rinfo.address); } catch (_e) { /* closed */ }
      }, 20);
    });
    var res = null; var err = null;
    try {
      res = await helpers.withTestTimeout("querySingle discard", function () {
        return nts.querySingle(_qsOpts(udp.port, { s2cKey: s2cKey, timeoutMs: 3000 }));
      }, { timeoutMs: 9000 });
    } catch (e) { err = e; }
    _close(udp);
    check("querySingle keeps waiting past " + h[0] + " and accepts the genuine reply",
          res && res.authenticated === true, err ? (err.code + " :: " + err.message) : "");
  }

  // A fully valid reply sent from a different source port is not a reply
  // to this request.
  var other = await _startUdpServer(function () { /* sends only */ });
  var udp2 = await _startUdpServer(function (msg, rinfo, s) {
    var u = _findExtBody(msg, NTP_HEADER_BYTES, EXT_UNIQUE);
    if (!u) return;
    var stray = _buildReply({ aeadId: AEAD_SIV, s2cKey: s2cKey, uniqueId: u, nowMs: Date.now() + 86400000 });
    other.sock.send(stray, 0, stray.length, rinfo.port, rinfo.address);
    setTimeout(function () {
      var good = _buildReply({ aeadId: AEAD_SIV, s2cKey: s2cKey, uniqueId: u });
      try { s.send(good, 0, good.length, rinfo.port, rinfo.address); } catch (_e) { /* closed */ }
    }, 20);
  });
  var res2 = null; var err2 = null;
  try {
    res2 = await helpers.withTestTimeout("querySingle source", function () {
      return nts.querySingle(_qsOpts(udp2.port, { s2cKey: s2cKey, timeoutMs: 3000 }));
    }, { timeoutMs: 9000 });
  } catch (e) { err2 = e; }
  _close(udp2); _close(other);
  check("querySingle ignores a reply from another source port",
        res2 && Math.abs(res2.serverTimeMs - Date.now()) < 60000,
        err2 ? (err2.code + " :: " + err2.message) : (res2 && String(res2.serverTimeMs - Date.now())));

  // A genuine NAK and nothing else: the timeout reports it as a NAK, which a
  // caller can tell apart from a missing or forged authenticator.
  await _udpExpectReject(function (msg) {
    var u = _findExtBody(msg, NTP_HEADER_BYTES, EXT_UNIQUE);
    return u ? _buildReply({ uniqueId: u, omitAuth: true, stratum: 0, refid: "NTSN" }) : null;
  }, "nts/nak", "querySingle NTS NAK");
  // The control: stratum 0 without the NTSN refid is not a NAK.
  await _udpExpectReject(function (msg) {
    var u = _findExtBody(msg, NTP_HEADER_BYTES, EXT_UNIQUE);
    return u ? _buildReply({ uniqueId: u, omitAuth: true, stratum: 0 }) : null;
  }, "nts/no-authenticator", "querySingle stratum-0 reply without NTSN");
}

// An authenticated reply whose header says the server is not a synchronized
// NTPv4 server is not a time source.
async function testQuerySingleRefusesUnsynchronizedHeaders() {
  var s2cKey = nodeCrypto.randomBytes(32);
  var headers = [
    ["LI=3 (alarm)",            { b0: 0xE4 }],
    ["stratum 0 refid RATE",    { stratum: 0, refid: "RATE" }],
    ["stratum 16",              { stratum: 16 }],
    ["mode 3",                  { b0: 0x23 }],
    ["version 2",               { b0: 0x14 }],
    ["version 3",               { b0: 0x1C }],
    ["a zero transmit time",    { txSecs: 0 }],
  ];
  for (var i = 0; i < headers.length; i++) {
    var h = headers[i];
    var err = await _udpExpectReject(function (msg) {
      var u = _findExtBody(msg, NTP_HEADER_BYTES, EXT_UNIQUE);
      return u ? _buildReply(Object.assign({ aeadId: AEAD_SIV, s2cKey: s2cKey, uniqueId: u }, h[1])) : null;
    }, "nts/unsynchronized", "querySingle authenticated reply with " + h[0], { s2cKey: s2cKey, timeoutMs: 2000 });
    if (h[0] === "a zero transmit time") {
      check("an unsynchronized refusal does not quote an internal message",
            err && String(err.message).indexOf("C.TIME") === -1, err && err.message);
    }
  }

  // The reply was authenticated, so its cookie is taken and the sent one is
  // spent even though the time is refused.
  var newCookie = nodeCrypto.randomBytes(32);
  var sent = nodeCrypto.randomBytes(32);
  var pool = [sent];
  var udp = await _startUdpServer(function (msg, rinfo, s) {
    var u = _findExtBody(msg, NTP_HEADER_BYTES, EXT_UNIQUE);
    if (!u) return;
    var r = _buildReply({ aeadId: AEAD_SIV, s2cKey: s2cKey, uniqueId: u, b0: 0xE4, plaintext: _ext(EXT_COOKIE, newCookie) });
    s.send(r, 0, r.length, rinfo.port, rinfo.address);
  });
  try { await nts.querySingle(_qsOpts(udp.port, { s2cKey: s2cKey, cookies: pool, timeoutMs: 2000 })); }
  catch (_e) { /* expected */ }
  _close(udp);
  check("after an unsynchronized refusal the sent cookie is gone and the new one is pooled",
        pool.length === 1 && pool[0].equals(newCookie), String(pool.length));
}

async function _udpResolve(makeReply, extra, label) {
  var udp = await _startUdpServer(function (msg, rinfo, s) {
    var u = _findExtBody(msg, NTP_HEADER_BYTES, EXT_UNIQUE);
    if (!u) return;
    var r = makeReply(u, msg);
    if (r) s.send(r, 0, r.length, rinfo.port, rinfo.address);
  });
  var res = null; var err = null;
  try {
    res = await helpers.withTestTimeout(label, function () {
      return nts.querySingle(_qsOpts(udp.port, Object.assign({ timeoutMs: 3000 }, extra)));
    }, { timeoutMs: 9000 });
  } catch (e) { err = e; }
  _close(udp);
  return { res: res, err: err };
}

// NTP seconds wrap on 2036-02-07T06:28:16Z (RFC 4330 section 3).
async function testQuerySingleReadsEraOneTimestamps() {
  var s2cKey = nodeCrypto.randomBytes(32);
  var whenMs = Date.UTC(2036, 2, 1);
  var r = await _udpResolve(function (u) {
    return _buildReply({ aeadId: AEAD_SIV, s2cKey: s2cKey, uniqueId: u, txSecs: _ntpSecondsFor(whenMs) });
  }, { s2cKey: s2cKey }, "querySingle era 1");
  check("querySingle reads a 2036-03-01 transmit time as 2036-03-01",
        r.res && r.res.serverTimeMs === whenMs, r.err ? (r.err.code + " :: " + r.err.message) : String(r.res && r.res.serverTimeMs));
}

// RFC 8915 section 5.6: the Nonce field is padded to a word boundary and
// Nonce Length excludes the padding.
async function testQuerySingleAcceptsAPaddedShortNonce() {
  var s2cKey = nodeCrypto.randomBytes(32);
  var r = await _udpResolve(function (u) {
    return _buildReply({ aeadId: AEAD_SIV, s2cKey: s2cKey, uniqueId: u, nonceLen: 13, plaintext: _ext(EXT_COOKIE, nodeCrypto.randomBytes(32)) });
  }, { s2cKey: s2cKey }, "querySingle 13-byte nonce");
  check("querySingle accepts a 13-byte SIV nonce padded to 16",
        r.res && r.res.authenticated === true && r.res.newCookieCount === 1,
        r.err ? (r.err.code + " :: " + r.err.message) : "");
}

// A cookie is sent once (RFC 8915 section 5.7), and the server returns no
// more cookies than the request had cookie and placeholder fields.
async function testQuerySingleCookiePool() {
  var s2cKey = nodeCrypto.randomBytes(32);

  // (a) A query that times out has still spent the cookie it sent.
  var c1 = nodeCrypto.randomBytes(32);
  var c2 = nodeCrypto.randomBytes(32);
  var pool = [c1, c2];
  var silent = await _startUdpServer(function () { /* never reply */ });
  var code = null;
  try { await nts.querySingle(_qsOpts(silent.port, { cookies: pool, timeoutMs: 300 })); }
  catch (e) { code = e && e.code; }
  _close(silent);
  check("a timed-out query reports nts/timeout", code === "nts/timeout", String(code));
  check("a timed-out query removed the cookie it sent from the pool",
        pool.length === 1 && pool[0].equals(c2), String(pool.length));

  // (b) Three cookies in the reply: only one is taken.
  var three = Buffer.concat([_ext(EXT_COOKIE, nodeCrypto.randomBytes(32)), _ext(EXT_COOKIE, nodeCrypto.randomBytes(32)), _ext(EXT_COOKIE, nodeCrypto.randomBytes(32))]);
  var r = await _udpResolve(function (u) {
    return _buildReply({ aeadId: AEAD_SIV, s2cKey: s2cKey, uniqueId: u, plaintext: three });
  }, { s2cKey: s2cKey }, "querySingle three cookies");
  check("a reply carrying three cookies adds one", r.res && r.res.newCookieCount === 1 && r.res.cookiesRemaining === 1,
        r.err ? (r.err.code + " :: " + r.err.message) : JSON.stringify(r.res && { n: r.res.newCookieCount, left: r.res.cookiesRemaining }));

  // (c) Two queries whose replies carry no cookie do not send the same one.
  var seen = [];
  var shared = [nodeCrypto.randomBytes(32), nodeCrypto.randomBytes(32)];
  var udp = await _startUdpServer(function (msg, rinfo, s) {
    var u = _findExtBody(msg, NTP_HEADER_BYTES, EXT_UNIQUE);
    seen.push(_findExtBody(msg, NTP_HEADER_BYTES, EXT_COOKIE));
    var rep = _buildReply({ aeadId: AEAD_SIV, s2cKey: s2cKey, uniqueId: u });
    s.send(rep, 0, rep.length, rinfo.port, rinfo.address);
  });
  try {
    await nts.querySingle(_qsOpts(udp.port, { s2cKey: s2cKey, cookies: shared, timeoutMs: 3000 }));
    await nts.querySingle(_qsOpts(udp.port, { s2cKey: s2cKey, cookies: shared, timeoutMs: 3000 }));
  } catch (_e) { /* asserted below */ }
  _close(udp);
  check("two queries send two different cookies",
        seen.length === 2 && seen[0] && seen[1] && !seen[0].equals(seen[1]), String(seen.length));
}

// A request that cannot be built is refused before any socket is opened, so
// the refusal leaves no handle behind and spends no cookie.
function _udpHandleCount() {
  if (typeof process.getActiveResourcesInfo !== "function") return 0;
  return process.getActiveResourcesInfo().filter(function (t) { return t === "UDPWrap"; }).length;
}

async function testQuerySingleRefusesAnUnbuildableRequestBeforeOpeningASocket() {
  var before = _udpHandleCount();
  var pool = [nodeCrypto.randomBytes(32)];
  var r = _syncOrAsyncCode(function () {
    return nts.querySingle({
      host: "127.0.0.1", port: 65000, aeadId: 99,
      c2sKey: nodeCrypto.randomBytes(32), s2cKey: nodeCrypto.randomBytes(32),
      cookies: pool, timeoutMs: 1000,
    });
  });
  check("querySingle: an unknown aeadId is refused synchronously with nts/unsupported-aead",
        r.sync && r.code === "nts/unsupported-aead", JSON.stringify(r));
  check("querySingle: the refused request spent no cookie", pool.length === 1);
  check("querySingle: the refused request opened no udp handle", _udpHandleCount() <= before);
}

async function testQuerySingleTimeout() {
  var udp = await _startUdpServer(function () { /* never reply */ });
  var caught = null;
  try { await nts.querySingle(_qsOpts(udp.port, { timeoutMs: 300 })); } catch (e) { caught = e; }
  _close(udp);
  check("querySingle timeout code is nts/timeout", caught && caught.code === "nts/timeout");
}

async function testQuerySingleAddressesIpv6() {
  if (!_hasIpv6Loopback()) {
    helpers.unavailable("querySingle IPv6", "no ::1 loopback on this host");
    return;
  }
  var udp = await _startUdpServer(function () { /* never reply */ }, "udp6", "::1");
  var caught = null;
  try { await nts.querySingle(_qsOpts(udp.port, { host: "::1" })); } catch (e) { caught = e; }
  _close(udp);
  check("querySingle reaches an IPv6 server rather than failing to send",
    caught && caught.code === "nts/timeout", caught && (caught.code + " :: " + caught.message));
}

// The kernel reports a reply's source in RFC 5952 form, so a host written in
// another spelling of the same address still matches the reply's source.
async function testQuerySingleAcceptsAnyAddressSpelling() {
  if (!_hasIpv6Loopback()) {
    helpers.unavailable("querySingle non-canonical IPv6 literal", "no ::1 loopback on this host");
    return;
  }
  var s2cKey = nodeCrypto.randomBytes(32);
  var spellings = ["0:0:0:0:0:0:0:1", "0000:0000::0001"];
  for (var i = 0; i < spellings.length; i++) {
    var udp = await _startUdpServer(function (msg, rinfo, s) {
      var u = _findExtBody(msg, NTP_HEADER_BYTES, EXT_UNIQUE);
      if (!u) return;
      var r = _buildReply({ aeadId: AEAD_SIV, s2cKey: s2cKey, uniqueId: u });
      s.send(r, 0, r.length, rinfo.port, rinfo.address);
    }, "udp6", "::1");
    var res = null; var err = null;
    try {
      res = await nts.querySingle(_qsOpts(udp.port, { host: spellings[i], s2cKey: s2cKey, timeoutMs: 1000 }));
    } catch (e) { err = e; }
    _close(udp);
    check("querySingle accepts the reply to " + spellings[i],
          res && res.authenticated === true, err ? (err.code + " :: " + err.message) : "");
  }
}

// A hostname is resolved before the socket is created, so a name with only
// an IPv6 address is reached over udp6.
async function testQuerySingleResolvesTheHostBeforeChoosingAFamily() {
  if (!_hasIpv6Loopback()) {
    helpers.unavailable("querySingle AAAA-only name", "no ::1 loopback on this host");
    return;
  }
  var s2cKey = nodeCrypto.randomBytes(32);
  var udp = await _startUdpServer(function (msg, rinfo, s) {
    var u = _findExtBody(msg, NTP_HEADER_BYTES, EXT_UNIQUE);
    if (!u) return;
    var r = _buildReply({ aeadId: AEAD_SIV, s2cKey: s2cKey, uniqueId: u });
    s.send(r, 0, r.length, rinfo.port, rinfo.address);
  }, "udp6", "::1");
  var origLookup = nodeDns.lookup;
  nodeDns.lookup = function (host, opts, cb) {
    if (typeof opts === "function") { cb = opts; opts = {}; }
    if (host === "nts-aaaa-only.invalid") {
      if (opts && opts.all) return process.nextTick(cb, null, [{ address: "::1", family: 6 }]);
      return process.nextTick(cb, null, "::1", 6);
    }
    return origLookup.call(nodeDns, host, opts, cb);
  };
  var res = null; var err = null;
  try {
    res = await nts.querySingle(_qsOpts(udp.port, { host: "nts-aaaa-only.invalid", s2cKey: s2cKey, timeoutMs: 2000 }));
  } catch (e) { err = e; }
  finally { nodeDns.lookup = origLookup; _close(udp); }
  check("querySingle reaches a name that resolves only to IPv6",
        res && res.authenticated === true, err ? (err.code + " :: " + err.message) : "");
}

async function testQuerySingleSivSuccess() {
  var s2cKey = nodeCrypto.randomBytes(32);
  var plaintext = Buffer.concat([_ext(EXT_UNIQUE, Buffer.alloc(4, 0xaa)), _ext(EXT_COOKIE, nodeCrypto.randomBytes(32))]);
  // Cookie length 30 (not 4-aligned) exercises the extension padding path.
  var r = await _udpResolve(function (u) {
    return _buildReply({ aeadId: AEAD_SIV, s2cKey: s2cKey, uniqueId: u, plaintext: plaintext });
  }, { s2cKey: s2cKey, cookies: [nodeCrypto.randomBytes(30)] }, "querySingle SIV success");
  check("SIV querySingle authenticated", r.res && r.res.authenticated === true, r.err && r.err.message);
  check("SIV querySingle drift is numeric", r.res && typeof r.res.driftMs === "number" && isFinite(r.res.driftMs));
  check("SIV querySingle rotated one new cookie", r.res && r.res.newCookieCount === 1);
  check("SIV querySingle cookie pool stays at one", r.res && r.res.cookiesRemaining === 1);
}

async function testQuerySingleChaChaSuccess() {
  var s2cKey = nodeCrypto.randomBytes(32);
  // A 4-byte-but-malformed encrypted extension: the inner walk refuses it,
  // so no cookie is extracted.
  var plaintext = Buffer.from([0x02, 0x04, 0x00, 0x02]);
  var r = await _udpResolve(function (u) {
    return _buildReply({ aeadId: AEAD_CHACHA, s2cKey: s2cKey, uniqueId: u, plaintext: plaintext });
  }, { aeadId: AEAD_CHACHA, s2cKey: s2cKey }, "querySingle ChaCha success");
  check("ChaCha querySingle authenticated", r.res && r.res.authenticated === true, r.err ? (r.err.code + " :: " + r.err.message) : "");
  check("ChaCha querySingle extracts no cookie from malformed exts", r.res && r.res.newCookieCount === 0);
  check("ChaCha querySingle spent the one cookie it sent", r.res && r.res.cookiesRemaining === 0);
}

// ---------------------------------------------------------------------------
// query: end-to-end KE + protected query, keyed off the shared TLS exporter.
// ---------------------------------------------------------------------------

async function _queryFullFlow(cert, aeadId, label) {
  var shared = { s2cKey: null };
  var udp = await _startUdpServer(function (msg, rinfo, s) {
    if (!shared.s2cKey) return;
    var u = _findExtBody(msg, NTP_HEADER_BYTES, EXT_UNIQUE);
    if (!u) return;
    var reply = _buildReply({ aeadId: aeadId, s2cKey: shared.s2cKey, uniqueId: u, plaintext: _ext(EXT_COOKIE, nodeCrypto.randomBytes(32)) });
    s.send(reply, 0, reply.length, rinfo.port, rinfo.address);
  });
  var ke = await _startKeServer(cert, { onData: function (sock) {
    // The KE server exports the SAME s2c keying material the client derives
    // (symmetric TLS 1.3 exporter), keyed by the AEAD it selected.
    var ctxS2C = Buffer.from([0x00, 0x00, (aeadId >> 8) & 0xff, aeadId & 0xff, 0x01]);
    shared.s2cKey = sock.exportKeyingMaterial(32, EXPORTER_LABEL, ctxS2C);
    return Buffer.concat([
      _np(),
      _aead(aeadId),
      _rec(false, REC_NEW_COOKIE, nodeCrypto.randomBytes(30)),
      _rec(false, REC_NTPV4_SERVER, Buffer.from("127.0.0.1", "ascii")),
      _rec(false, REC_NTPV4_PORT, _u16(udp.port)),
      _end(),
    ]);
  } });
  try {
    var res = null; var err = null;
    try {
      res = await helpers.withTestTimeout(label, function () {
        return nts.query({ host: "127.0.0.1", kePort: ke.port, servername: "localhost", ca: cert.ca.caCertPem, timeoutMs: 4000 });
      });
    } catch (e) { err = e; }
    check(label + " resolves authenticated", res && res.authenticated === true, err ? (err.code + " :: " + err.message) : "");
    check(label + " surfaces the negotiated aeadId", res && res.aeadId === aeadId);
    check(label + " drift is numeric", res && typeof res.driftMs === "number" && isFinite(res.driftMs));
    check(label + " routed to the KE-advertised NTP server", res && res.server === "127.0.0.1");
  } finally { _close(ke); _close(udp); }
}

async function testQueryFullFlow(cert) {
  await _queryFullFlow(cert, AEAD_SIV, "nts query end-to-end (AES-SIV)");
  // A server that selects ChaCha20-Poly1305 from the default offer.
  await _queryFullFlow(cert, AEAD_CHACHA, "nts query end-to-end (ChaCha20-Poly1305)");
}

async function _body() {
  testAesSivKnownAnswers();
  testAesSivRoundtrip();
  testAesSivBadKey();
  testAesSivTamperFailsClosed();
  testAeadIdsAreIanaIds();
  testKeInputValidation();
  await testQueryInputValidation();
  testQuerySingleInputValidation();

  var cert = await _makeCert();

  await testKeBadAlpn(cert);
  await testKeDefaultOffer(cert);
  await testKeAdversarialRecords(cert);
  await testKeSuccess(cert);
  await testKeNtpServerIsTheKeAddress(cert);
  await testKeIpLiteralSendsNoSni(cert);
  await testCheckDriftDialsAnIpLiteralNtsEndpoint(cert);
  await testKeResponseSplitAcrossWrites(cert);
  await testKeByteCapFailsClosed(cert);
  await testKeTimeout(cert);
  await testKeSocketError();

  await testQuerySingleAdversarialReplies();
  await testQuerySingleAuthFailed();
  await testQuerySingleDiscardsHostileDatagramsAndKeepsWaiting();
  await testQuerySingleRefusesUnsynchronizedHeaders();
  await testQuerySingleReadsEraOneTimestamps();
  await testQuerySingleAcceptsAPaddedShortNonce();
  await testQuerySingleCookiePool();
  await testQuerySingleRefusesAnUnbuildableRequestBeforeOpeningASocket();
  await testQuerySingleTimeout();
  await testQuerySingleAddressesIpv6();
  await testQuerySingleResolvesTheHostBeforeChoosingAFamily();
  await testQuerySingleAcceptsAnyAddressSpelling();
  await testQuerySingleSivSuccess();
  await testQuerySingleChaChaSuccess();

  await testQueryFullFlow(cert);
}

async function run() {
  await helpers.withDrain("network-nts", _body);
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
