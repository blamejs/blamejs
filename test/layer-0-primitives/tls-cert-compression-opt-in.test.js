// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * RFC 8879 certificate compression is off unless the operator lists the
 * algorithms. With it off, OpenSSL never runs a decompressor over a peer's
 * Certificate message, which it would otherwise do before the chain is
 * verified.
 *
 * Covers, on loopback sockets the test owns:
 *   - an outbound dial (b.httpClient.request, b.pqcAgent.create,
 *     b.network.tls.outboundPosture, b.network.tls.ocsp.connect) sends a
 *     ClientHello without the
 *     compress_certificate extension, and an explicit list puts it back;
 *   - b.httpClient.configurePool sets a client-wide list, and a request's
 *     own [] overrides it;
 *   - a b.router listener with requestCert takes the client's certificate
 *     uncompressed and sends its own uncompressed, and
 *     tlsOptions.certificateCompression turns both back on;
 *   - b.mail.server.tls.context sends its certificate uncompressed unless
 *     opts.certificateCompression lists an algorithm;
 *   - the context b.cert.create's sniCallback returns does the same with
 *     opts.certificateCompression;
 *   - bad lists are refused with tls/bad-cert-compression (and
 *     network-tls/bad-tls-options from buildOptions) at every entry point:
 *     a non-array, an unknown name, a non-string entry, and a name listed
 *     twice, which OpenSSL would otherwise refuse later with a raw
 *     ERR_CRYPTO_OPERATION_FAILED.
 *
 * Run standalone: `node test/layer-0-primitives/tls-cert-compression-opt-in.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var fs      = require("node:fs");
var http2   = require("node:http2");
var https   = require("node:https");
var net     = require("node:net");
var nodeTls = require("node:tls");
var os      = require("node:os");
var path    = require("node:path");
var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

var httpClientLib = require("../../lib/http-client");

var COMPRESS_CERTIFICATE_EXT = 27;
var ZLIB_ID = 1;
var C_DAY_MS = b.constants.TIME.days(1);

function _runtimeHasZlib() {
  return b.constants.TLS_CERT_COMPRESSION().indexOf("zlib") !== -1;
}

// The algorithm ids a ClientHello's compress_certificate extension lists,
// null when the ClientHello carries no such extension, or undefined while the
// bytes do not yet hold a complete ClientHello.
function _clientHelloCompression(buf) {
  var hs = Buffer.alloc(0);
  var off = 0;
  while (off + 5 <= buf.length) {
    if (buf[off] !== 22) return null;
    var len = buf.readUInt16BE(off + 3);
    if (off + 5 + len > buf.length) return undefined;
    hs = Buffer.concat([hs, buf.subarray(off + 5, off + 5 + len)]);
    off += 5 + len;
    if (hs.length >= 4 && hs.length >= 4 + hs.readUIntBE(1, 3)) break;
  }
  if (hs.length < 4) return undefined;
  if (hs[0] !== 1) return null;
  if (hs.length < 4 + hs.readUIntBE(1, 3)) return undefined;
  var p = 4 + 2 + 32;
  p += 1 + hs[p];
  p += 2 + hs.readUInt16BE(p);
  p += 1 + hs[p];
  var extEnd = p + 2 + hs.readUInt16BE(p);
  p += 2;
  while (p + 4 <= extEnd) {
    var type = hs.readUInt16BE(p);
    var extLen = hs.readUInt16BE(p + 2);
    if (type === COMPRESS_CERTIFICATE_EXT) {
      var ids = [];
      var n = hs[p + 4];
      for (var i = 0; i + 1 < n; i += 2) ids.push(hs.readUInt16BE(p + 5 + i));
      return ids;
    }
    p += 4 + extLen;
  }
  return null;
}

// A TCP listener that reads one ClientHello, records what it offers for
// certificate compression, and closes the connection.
async function _helloCatcher() {
  var seen = [];
  var sockets = [];
  var srv = net.createServer(function (sock) {
    sockets.push(sock);
    var buf = Buffer.alloc(0);
    sock.on("error", function () { /* the dial fails once this side closes */ });
    sock.on("data", function (chunk) {
      buf = Buffer.concat([buf, chunk]);
      var found = _clientHelloCompression(buf);
      if (found === undefined) return;
      seen.push(found);
      sock.destroy();
    });
  });
  await new Promise(function (r) { srv.listen(0, "127.0.0.1", r); });
  return {
    port: srv.address().port,
    seen: seen,
    close: function () {
      sockets.forEach(function (s) { try { s.destroy(); } catch (_e) { /* already closed */ } });
      return new Promise(function (r) { srv.close(function () { r(); }); });
    },
  };
}

async function _offerOf(catcher, dial) {
  var before = catcher.seen.length;
  try { await dial(); } catch (_e) { /* the catcher closes every connection */ }
  await helpers.waitUntil(function () { return catcher.seen.length > before; },
    { timeoutMs: 5000, label: "cert compression: ClientHello read" });
  return catcher.seen[before];
}

function _describe(offer) {
  return offer === null ? "no compress_certificate extension" : JSON.stringify(offer);
}

async function testOutboundDialsOfferNoCompressionByDefault() {
  if (!_runtimeHasZlib()) {
    helpers.unavailable("outbound certificate compression", "this Node build reports no zlib");
    return;
  }
  var catcher = await _helloCatcher();
  var url = "https://localhost:" + catcher.port + "/";
  try {
    httpClientLib._resetForTest();
    var h2Default = await _offerOf(catcher, function () {
      return b.httpClient.request({ url: url, allowInternal: true, timeoutMs: 5000 });
    });
    check("httpClient.request: the default dial offers no certificate compression (" +
          _describe(h2Default) + ")", h2Default === null);

    httpClientLib._resetForTest();
    var h2OptIn = await _offerOf(catcher, function () {
      return b.httpClient.request({ url: url, allowInternal: true, timeoutMs: 5000,
        certificateCompression: ["zlib"] });
    });
    check("httpClient.request: certificateCompression [\"zlib\"] offers zlib (" + _describe(h2OptIn) + ")",
          Array.isArray(h2OptIn) && h2OptIn.length === 1 && h2OptIn[0] === ZLIB_ID);

    httpClientLib._resetForTest();
    var h2Empty = await _offerOf(catcher, function () {
      return b.httpClient.request({ url: url, allowInternal: true, timeoutMs: 5000,
        certificateCompression: [] });
    });
    check("httpClient.request: certificateCompression [] offers none (" + _describe(h2Empty) + ")",
          h2Empty === null);

    httpClientLib._resetForTest();
    b.httpClient.configurePool({ certificateCompression: ["zlib"] });
    try {
      var pooled = await _offerOf(catcher, function () {
        return b.httpClient.request({ url: url, allowInternal: true, timeoutMs: 5000 });
      });
      check("httpClient.configurePool: certificateCompression [\"zlib\"] reaches the next dial (" +
            _describe(pooled) + ")", Array.isArray(pooled) && pooled[0] === ZLIB_ID);
      httpClientLib._resetForTest();
      var overridden = await _offerOf(catcher, function () {
        return b.httpClient.request({ url: url, allowInternal: true, timeoutMs: 5000,
          certificateCompression: [] });
      });
      check("httpClient.request: certificateCompression [] overrides the pool list (" +
            _describe(overridden) + ")", overridden === null);
    } finally {
      b.httpClient.configurePool({ certificateCompression: [] });
      httpClientLib._resetForTest();
    }
    var poolOff = await _offerOf(catcher, function () {
      return b.httpClient.request({ url: url, allowInternal: true, timeoutMs: 5000 });
    });
    check("httpClient.configurePool: certificateCompression [] turns the pool list off (" +
          _describe(poolOff) + ")", poolOff === null);

    var agent = b.pqcAgent.create({ keepAlive: false });
    var agentDefault = await _offerOf(catcher, function () {
      return new Promise(function (resolve, reject) {
        var req = https.get({ host: "127.0.0.1", port: catcher.port, servername: "localhost", agent: agent });
        req.on("error", reject);
        req.on("response", resolve);
      });
    });
    agent.destroy();
    check("pqcAgent.create: the default agent offers no certificate compression (" +
          _describe(agentDefault) + ")", agentDefault === null);

    var optAgent = b.pqcAgent.create({ keepAlive: false, certificateCompression: ["zlib"] });
    var agentOptIn = await _offerOf(catcher, function () {
      return new Promise(function (resolve, reject) {
        var req = https.get({ host: "127.0.0.1", port: catcher.port, servername: "localhost", agent: optAgent });
        req.on("error", reject);
        req.on("response", resolve);
      });
    });
    optAgent.destroy();
    check("pqcAgent.create: certificateCompression [\"zlib\"] offers zlib (" + _describe(agentOptIn) + ")",
          Array.isArray(agentOptIn) && agentOptIn[0] === ZLIB_ID);

    var postureOffer = await _offerOf(catcher, function () {
      return new Promise(function (resolve, reject) {
        var s = nodeTls.connect(Object.assign({ host: "127.0.0.1", port: catcher.port, servername: "localhost" },
          b.network.tls.outboundPosture()));
        s.on("error", reject);
        s.on("secureConnect", resolve);
      });
    });
    check("network.tls.outboundPosture: a dial built from it offers no certificate compression (" +
          _describe(postureOffer) + ")", postureOffer === null);

    var ocspDefault = await _offerOf(catcher, function () {
      return b.network.tls.ocsp.connect({ host: "127.0.0.1", port: catcher.port, servername: "localhost" });
    });
    check("network.tls.ocsp.connect: the default dial offers no certificate compression (" +
          _describe(ocspDefault) + ")", ocspDefault === null);
    var ocspOptIn = await _offerOf(catcher, function () {
      return b.network.tls.ocsp.connect({ host: "127.0.0.1", port: catcher.port, servername: "localhost",
        certificateCompression: ["zlib"] });
    });
    check("network.tls.ocsp.connect: certificateCompression [\"zlib\"] offers zlib (" + _describe(ocspOptIn) + ")",
          Array.isArray(ocspOptIn) && ocspOptIn.length === 1 && ocspOptIn[0] === ZLIB_ID);
  } finally {
    httpClientLib._resetForTest();
    await catcher.close();
  }
}

function testPostureObjectsCarryNoListByDefault() {
  var nt = b.network.tls;
  check("network.tls.outboundPosture has no certificateCompression",
        nt.outboundPosture().certificateCompression === undefined);
  check("network.tls.applyToContext (client) adds no certificateCompression",
        nt.applyToContext({ base: {}, role: "client" }).certificateCompression === undefined);
  check("network.tls.applyToContext (server) adds no certificateCompression",
        nt.applyToContext({ base: {} }).certificateCompression === undefined);
  check("network.tls.buildOptions adds no certificateCompression",
        nt.buildOptions({}).certificateCompression === undefined);
  if (_runtimeHasZlib()) {
    check("network.tls.applyToContext keeps an explicit [\"zlib\"]",
          (nt.applyToContext({ base: { certificateCompression: ["zlib"] }, role: "client" })
            .certificateCompression || []).join(",") === "zlib");
  }
}

function _codeOf(fn) {
  try { fn(); return null; } catch (e) { return (e && e.code) || String(e); }
}

async function testBadListsAreRefused() {
  var nt = b.network.tls;
  check("applyToContext refuses an unknown algorithm with tls/bad-cert-compression",
        _codeOf(function () { nt.applyToContext({ base: { certificateCompression: ["lzma"] } }); }) ===
          "tls/bad-cert-compression");
  check("applyToContext refuses a non-array with tls/bad-cert-compression",
        _codeOf(function () { nt.applyToContext({ base: { certificateCompression: "zlib" } }); }) ===
          "tls/bad-cert-compression");
  check("pqcAgent.create refuses an unknown algorithm with tls/bad-cert-compression",
        _codeOf(function () { b.pqcAgent.create({ certificateCompression: ["lzma"] }); }) ===
          "tls/bad-cert-compression");
  check("httpClient.configurePool refuses an unknown algorithm with tls/bad-cert-compression",
        _codeOf(function () { b.httpClient.configurePool({ certificateCompression: ["lzma"] }); }) ===
          "tls/bad-cert-compression");
  var reqCode = null;
  try {
    await b.httpClient.request({ url: "https://localhost:1/", allowInternal: true,
      certificateCompression: ["lzma"] });
  } catch (e) { reqCode = e && e.code; }
  check("httpClient.request rejects an unknown algorithm with tls/bad-cert-compression (" + reqCode + ")",
        reqCode === "tls/bad-cert-compression");
  if (_runtimeHasZlib()) {
    var agentCode = null;
    var ownAgent = b.pqcAgent.create({ keepAlive: false });
    try {
      await b.httpClient.request({ url: "https://localhost:1/", allowInternal: true, agent: ownAgent,
        certificateCompression: ["zlib"] });
    } catch (e) { agentCode = e && e.code; }
    ownAgent.destroy();
    check("httpClient.request rejects a list it cannot apply through opts.agent with http-client/bad-opts (" +
          agentCode + ")", agentCode === "http-client/bad-opts");
  }
  check("router listen refuses an unknown algorithm with tls/bad-cert-compression",
        _codeOf(function () {
          var pair = helpers.selfSignedPair();
          var s = b.router.create().listen(0, function () {}, {
            key: pair.key, cert: pair.cert, certificateCompression: ["lzma"],
          }, "127.0.0.1");
          if (s) s.close();
        }) === "tls/bad-cert-compression");
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "cc-mail-"));
  try {
    var pair = helpers.selfSignedPair();
    fs.writeFileSync(path.join(dir, "cert.pem"), pair.cert);
    fs.writeFileSync(path.join(dir, "key.pem"), pair.key);
    check("mail.server.tls.context refuses an unknown algorithm with tls/bad-cert-compression",
          _codeOf(function () {
            b.mail.server.tls.context({ certFile: path.join(dir, "cert.pem"),
              keyFile: path.join(dir, "key.pem"), certificateCompression: ["lzma"] });
          }) === "tls/bad-cert-compression");
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  }
}

// Each entry point that takes a certificateCompression list, as a function of
// the list. A function returns a promise when the entry point rejects rather
// than throws, and returns what it built so the caller can release it.
function _entryPoints(mailDir) {
  var routerPair = helpers.selfSignedPair();
  var noChallenge = { type: "http-01", provision: function () {}, cleanup: function () {} };
  return [
    { name: "network.tls.buildOptions", code: "network-tls/bad-tls-options",
      call: function (list) { return b.network.tls.buildOptions({ certificateCompression: list }); } },
    { name: "network.tls.applyToContext", code: "tls/bad-cert-compression",
      call: function (list) { return b.network.tls.applyToContext({ base: { certificateCompression: list } }); } },
    { name: "network.tls.applyToContext role client", code: "tls/bad-cert-compression",
      call: function (list) {
        return b.network.tls.applyToContext({ base: { certificateCompression: list }, role: "client" });
      } },
    { name: "pqcAgent.create", code: "tls/bad-cert-compression",
      call: function (list) {
        var agent = b.pqcAgent.create({ certificateCompression: list, keepAlive: false });
        agent.destroy();
      } },
    { name: "httpClient.configurePool", code: "tls/bad-cert-compression",
      call: function (list) {
        try { b.httpClient.configurePool({ certificateCompression: list }); }
        finally { b.httpClient.configurePool({ certificateCompression: [] }); }
      } },
    { name: "httpClient.request", code: "tls/bad-cert-compression",
      call: function (list) {
        return b.httpClient.request({ url: "https://localhost:1/", allowInternal: true,
          timeoutMs: 2000, certificateCompression: list });
      } },
    { name: "wsClient.connect", code: "tls/bad-cert-compression",
      call: function (list) {
        var c = b.wsClient.connect("wss://localhost:1/", { allowInternal: true,
          tlsOpts: { certificateCompression: list } });
        if (c && typeof c.on === "function") c.on("error", function () { /* refused dial */ });
        if (c && typeof c.close === "function") { try { c.close(); } catch (_e) { /* not open */ } }
      } },
    { name: "router listen", code: "tls/bad-cert-compression",
      call: function (list) {
        var s = b.router.create().listen(0, function () {}, {
          key: routerPair.key, cert: routerPair.cert, certificateCompression: list,
        }, "127.0.0.1");
        if (s) s.close();
      } },
    { name: "mail.server.tls.context", code: "tls/bad-cert-compression",
      call: function (list) {
        b.mail.server.tls.context({ certFile: path.join(mailDir, "cert.pem"),
          keyFile: path.join(mailDir, "key.pem"), certificateCompression: list });
      } },
    { name: "cert.create", code: "tls/bad-cert-compression",
      call: function (list) {
        b.cert.create({
          storage: { type: "sealed-disk", rootDir: os.tmpdir() },
          acme:    { directory: "https://example/" },
          certs:   [{ name: "main", domains: ["localhost"], challenge: noChallenge }],
          certificateCompression: list,
        });
      } },
    { name: "network.tls.ocsp.connect", code: "tls/bad-cert-compression",
      call: function (list) {
        return b.network.tls.ocsp.connect({ host: "127.0.0.1", port: 1, servername: "localhost",
          certificateCompression: list });
      } },
    { name: "network.tls.ocsp.requireStapled", code: "tls/bad-cert-compression",
      call: function (list) {
        return b.network.tls.ocsp.requireStapled({ host: "127.0.0.1", port: 1, servername: "localhost",
          certificateCompression: list });
      } },
    { name: "network.tls.ocsp.requireGood", code: "tls/bad-cert-compression",
      call: function (list) {
        return b.network.tls.ocsp.requireGood({ host: "127.0.0.1", port: 1, servername: "localhost",
          issuerPem: routerPair.cert, certificateCompression: list });
      } },
  ];
}

async function _codeOfAsync(fn) {
  try {
    var out = fn();
    if (out && typeof out.then === "function") await out;
    return null;
  } catch (e) { return (e && e.code) || String(e); }
}

// A list that names an algorithm twice reaches OpenSSL, which refuses it with
// a raw ERR_CRYPTO_OPERATION_FAILED when the context is built: at listen()
// for b.router, at the first dial for b.httpClient and b.pqcAgent, and at
// every SNI lookup for b.cert. Each entry point refuses it, and every other
// malformed entry, at configuration with its documented code.
async function testEveryEntryPointRefusesMalformedLists() {
  var supported = b.constants.TLS_CERT_COMPRESSION();
  var name = supported.length > 0 ? supported[0] : "zlib";
  var bad = [
    { label: "a duplicate algorithm", list: [name, name] },
    { label: "a non-string entry", list: [1] },
    { label: "a null entry", list: [null] },
    { label: "an unknown algorithm", list: ["lzma"] },
    { label: "an empty-string entry", list: [""] },
    { label: "a non-array", list: name },
  ];
  if (supported.length > 1) {
    bad.push({ label: "a duplicate after another algorithm", list: [supported[0], supported[1], supported[0]] });
  }
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "cc-entry-"));
  try {
    var pair = helpers.selfSignedPair();
    fs.writeFileSync(path.join(dir, "cert.pem"), pair.cert);
    fs.writeFileSync(path.join(dir, "key.pem"), pair.key);
    var entries = _entryPoints(dir);
    for (var e = 0; e < entries.length; e += 1) {
      for (var i = 0; i < bad.length; i += 1) {
        var code = await _codeOfAsync(entries[e].call.bind(null, bad[i].list));
        check(entries[e].name + " refuses " + bad[i].label + " " + JSON.stringify(bad[i].list) +
              " with " + entries[e].code + " (" + code + ")", code === entries[e].code);
      }
    }
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  }
}

// Handshake bytes in each direction through a relay the test owns. `listen`
// starts the server and resolves { port, close, secured } where `secured`
// counts handshakes the server finished. The client presents `clientCert`
// and offers zlib, so any difference in size comes from the server's
// compression setting.
async function _handshakeBytes(listen, pair, fat) {
  var open = [];
  var server = await listen();
  var up = 0;
  var down = 0;
  var relay = net.createServer(function (sock) {
    open.push(sock);
    var upstream = net.connect({ host: "127.0.0.1", port: server.port });
    open.push(upstream);
    upstream.on("data", function (c) { down += c.length; sock.write(c); });
    sock.on("data", function (c) { up += c.length; upstream.write(c); });
    upstream.on("error", function () {}); sock.on("error", function () {});
  });
  await new Promise(function (r) { relay.listen(0, "127.0.0.1", r); });
  var completed = false;
  var failure = null;
  await new Promise(function (resolve) {
    var c = nodeTls.connect({
      host: "127.0.0.1", port: relay.address().port, servername: "localhost",
      ca: [pair.cert], cert: fat, key: pair.key, certificateCompression: ["zlib"],
    });
    open.push(c);
    c.on("secureConnect", function () { completed = true; resolve(); });
    c.on("error", function (e) { failure = (e && e.message) || String(e); resolve(); });
  });
  if (completed) {
    await helpers.waitUntil(function () { return server.secured() > 0; },
      { timeoutMs: 5000, label: "cert compression: server finished the handshake" });
  }
  open.forEach(function (s) { try { s.destroy(); } catch (_e) { /* already closed */ } });
  await new Promise(function (r) { relay.close(function () { r(); }); });
  await server.close();
  if (!completed) throw new Error("cert compression: handshake did not complete" + (failure ? " (" + failure + ")" : ""));
  return { up: up, down: down };
}

function _nodeServer(pair, fat, list) {
  return function () {
    var secured = 0;
    var o = { cert: fat, key: pair.key, requestCert: true, rejectUnauthorized: false, ca: [pair.cert] };
    if (list !== undefined) o.certificateCompression = list;
    var srv = nodeTls.createServer(o, function (s) { secured += 1; s.on("error", function () {}); });
    srv.on("tlsClientError", function () {});
    return new Promise(function (r) {
      srv.listen(0, "127.0.0.1", function () {
        r({ port: srv.address().port, secured: function () { return secured; },
            close: function () { return new Promise(function (rr) { srv.close(function () { rr(); }); }); } });
      });
    });
  };
}

function _routerServer(pair, fat, list) {
  return function () {
    var secured = 0;
    var tlsOptions = { cert: fat, key: pair.key, requestCert: true, rejectUnauthorized: false, ca: [pair.cert] };
    if (list !== undefined) tlsOptions.certificateCompression = list;
    return new Promise(function (r) {
      var srv = b.router.create().listen(0, function () {
        r({ port: srv.address().port, secured: function () { return secured; },
            close: function () {
              if (typeof srv.closeAllConnections === "function") srv.closeAllConnections();
              return new Promise(function (rr) { srv.close(function () { rr(); }); });
            } });
      }, tlsOptions, "127.0.0.1");
      srv.on("secureConnection", function () { secured += 1; });
      srv.on("tlsClientError", function () {});
    });
  };
}

// A compressed certificate here is about a quarter of the uncompressed
// handshake. Other handshake messages (session tickets, which a listener with
// requestCert does not send) move the total by far less than that.
function _uncompressed(control, measured) {
  return measured > control * 0.75;
}

async function testRouterListenerWithRequestCert() {
  if (!_runtimeHasZlib()) {
    helpers.unavailable("router certificate compression", "this Node build reports no zlib");
    return;
  }
  var pair = helpers.selfSignedPair();
  var fat = new Array(24).join(pair.cert) + pair.cert;
  var plain = await _handshakeBytes(_nodeServer(pair, fat, undefined), pair, fat);
  var compressed = await _handshakeBytes(_nodeServer(pair, fat, ["zlib"]), pair, fat);
  check("premise: a node:tls server listing zlib takes the client certificate compressed (" +
        compressed.up + " vs " + plain.up + " bytes)", compressed.up < plain.up * 0.5);
  check("premise: a node:tls server listing zlib sends its certificate compressed (" +
        compressed.down + " vs " + plain.down + " bytes)", compressed.down < plain.down * 0.5);

  var routerDefault = await _handshakeBytes(_routerServer(pair, fat, undefined), pair, fat);
  check("router listen with requestCert takes the client certificate uncompressed by default (" +
        routerDefault.up + " vs " + plain.up + " bytes uncompressed)", _uncompressed(plain.up, routerDefault.up));
  check("router listen sends its certificate uncompressed by default (" +
        routerDefault.down + " vs " + plain.down + " bytes uncompressed)", _uncompressed(plain.down, routerDefault.down));

  var routerOptIn = await _handshakeBytes(_routerServer(pair, fat, ["zlib"]), pair, fat);
  check("router listen with tlsOptions.certificateCompression [\"zlib\"] takes the client certificate " +
        "compressed (" + routerOptIn.up + " vs " + plain.up + " bytes)", routerOptIn.up < plain.up * 0.5);
  check("router listen with tlsOptions.certificateCompression [\"zlib\"] sends its certificate " +
        "compressed (" + routerOptIn.down + " vs " + plain.down + " bytes)", routerOptIn.down < plain.down * 0.5);
}

function _mailServer(ctx) {
  return function () {
    var secured = 0;
    var open = [];
    var srv = net.createServer(function (sock) {
      open.push(sock);
      var t = new nodeTls.TLSSocket(sock, { isServer: true, secureContext: ctx });
      open.push(t);
      t.on("secure", function () { secured += 1; });
      t.on("error", function () { /* the client closes after the handshake */ });
    });
    return new Promise(function (r) {
      srv.listen(0, "127.0.0.1", function () {
        r({ port: srv.address().port, secured: function () { return secured; },
            close: function () {
              open.forEach(function (s) { try { s.destroy(); } catch (_e) { /* already closed */ } });
              return new Promise(function (rr) { srv.close(function () { rr(); }); });
            } });
      });
    });
  };
}

async function testMailServerContext() {
  if (!_runtimeHasZlib()) {
    helpers.unavailable("mail certificate compression", "this Node build reports no zlib");
    return;
  }
  var pair = helpers.selfSignedPair();
  var fat = new Array(24).join(pair.cert) + pair.cert;
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "cc-mail-"));
  var certFile = path.join(dir, "cert.pem");
  var keyFile = path.join(dir, "key.pem");
  fs.writeFileSync(certFile, fat);
  fs.writeFileSync(keyFile, pair.key);
  try {
    var plain = await _handshakeBytes(_mailServer(nodeTls.createSecureContext({ cert: fat, key: pair.key })),
      pair, pair.cert);
    var byDefault = b.mail.server.tls.context({ certFile: certFile, keyFile: keyFile });
    var defaultBytes = await _handshakeBytes(_mailServer(byDefault.secureContext), pair, pair.cert);
    byDefault.stop();
    check("mail.server.tls.context sends its certificate uncompressed by default (" +
          defaultBytes.down + " vs " + plain.down + " bytes uncompressed)", _uncompressed(plain.down, defaultBytes.down));
    var optIn = b.mail.server.tls.context({ certFile: certFile, keyFile: keyFile, certificateCompression: ["zlib"] });
    var optInBytes = await _handshakeBytes(_mailServer(optIn.secureContext), pair, pair.cert);
    optIn.stop();
    check("mail.server.tls.context with certificateCompression [\"zlib\"] sends its certificate compressed (" +
          optInBytes.down + " vs " + plain.down + " bytes)", optInBytes.down < plain.down * 0.5);
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  }
}

// A b.cert manager over sealed-disk storage holding one certificate, sealed
// with a pass-through vault. Returns the context its sniCallback serves.
async function _certSniContext(fat, pair, extra) {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "cc-cert-"));
  var vault = {
    seal:   function (buf) { return Buffer.from(buf); },
    unseal: function (buf) { return Buffer.from(buf); },
  };
  fs.mkdirSync(path.join(dir, "main"), { recursive: true });
  fs.writeFileSync(path.join(dir, "main", "cert.pem.sealed"), vault.seal(Buffer.from(fat)));
  fs.writeFileSync(path.join(dir, "main", "key.pem.sealed"), vault.seal(Buffer.from(pair.key)));
  fs.writeFileSync(path.join(dir, "main", "meta.json"), JSON.stringify({
    expiresAt: Date.now() + C_DAY_MS * 90, issuedAt: Date.now(), fingerprintSha256: "main",
    subject: "CN=localhost", lastRenewedAt: Date.now(), keyAlg: "ecdsa-p256",
  }));
  var noChallenge = { type: "http-01", provision: async function () {}, cleanup: async function () {} };
  var mgr = b.cert.create(Object.assign({
    storage: { type: "sealed-disk", rootDir: dir, vault: vault },
    acme:    { directory: "https://example/", accountKey: "auto" },
    certs:   [{ name: "main", domains: ["localhost"], challenge: noChallenge }],
    ocsp:    { stapling: false },
    audit:   false,
  }, extra || {}));
  await mgr.start();
  var ctx = await new Promise(function (resolve, reject) {
    mgr.sniCallback("localhost", function (err, c) { if (err) reject(err); else resolve(c); });
  });
  await mgr.stop();
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  return ctx;
}

async function testCertSniCallbackContext() {
  if (!_runtimeHasZlib()) {
    helpers.unavailable("b.cert certificate compression", "this Node build reports no zlib");
    return;
  }
  var pair = helpers.selfSignedPair();
  var fat = new Array(24).join(pair.cert) + pair.cert;
  var plain = await _handshakeBytes(_mailServer(nodeTls.createSecureContext({ cert: fat, key: pair.key })),
    pair, pair.cert);
  var byDefault = await _certSniContext(fat, pair);
  var defaultBytes = await _handshakeBytes(_mailServer(byDefault), pair, pair.cert);
  check("cert.create sniCallback serves its certificate uncompressed by default (" +
        defaultBytes.down + " vs " + plain.down + " bytes uncompressed)", _uncompressed(plain.down, defaultBytes.down));
  var optIn = await _certSniContext(fat, pair, { certificateCompression: ["zlib"] });
  var optInBytes = await _handshakeBytes(_mailServer(optIn), pair, pair.cert);
  check("cert.create with certificateCompression [\"zlib\"] serves its certificate compressed (" +
        optInBytes.down + " vs " + plain.down + " bytes)", optInBytes.down < plain.down * 0.5);
  check("cert.create refuses an unknown algorithm with tls/bad-cert-compression",
        _codeOf(function () {
          b.cert.create({
            storage: { type: "sealed-disk", rootDir: os.tmpdir() },
            acme:    { directory: "https://example/" },
            certs:   [{ name: "main", domains: ["localhost"],
              challenge: { type: "http-01", provision: function () {}, cleanup: function () {} } }],
            certificateCompression: ["lzma"],
          });
        }) === "tls/bad-cert-compression");
}

// b.httpClient caches one transport per origin. A request whose list differs
// from the pool's must open its own connection rather than reuse one whose
// handshake advertised something else, and a later request with the pool's
// list must go back to the first connection.
async function testHttpClientTransportPerList() {
  if (!_runtimeHasZlib()) {
    helpers.unavailable("httpClient transport per certificate-compression list", "this Node build reports no zlib");
    return;
  }
  var ca = await b.mtlsEngine.generateCa({ name: "cert-compression-opt-in-test-ca" });
  var leaf = await b.mtlsEngine.signClientCert({
    cn: "loopback", caCertPem: ca.caCertPem, caKeyPem: ca.caKeyPem,
    usage: "server", sans: ["IP:127.0.0.1"], validityDays: 1,
  });
  var label = "cert-compression-opt-in-test-ca";
  b.network.tls.addCa(ca.caCertPem, { label: label });
  var handshakes = 0;
  var sockets = [];
  var srv = http2.createSecureServer({ key: leaf.key, cert: leaf.cert, allowHTTP1: true,
    certificateCompression: ["zlib"] }, function (req, res) { res.end("ok"); });
  srv.on("secureConnection", function (s) { handshakes += 1; sockets.push(s); });
  srv.on("error", function () { /* loopback listener */ });
  await new Promise(function (r) { srv.listen(0, "127.0.0.1", r); });
  var url = "https://127.0.0.1:" + srv.address().port + "/";
  httpClientLib._resetForTest();
  try {
    var first = await b.httpClient.request({ url: url, allowInternal: true, timeoutMs: 5000 });
    var second = await b.httpClient.request({ url: url, allowInternal: true, timeoutMs: 5000,
      certificateCompression: ["zlib"] });
    var third = await b.httpClient.request({ url: url, allowInternal: true, timeoutMs: 5000 });
    var fourth = await b.httpClient.request({ url: url, allowInternal: true, timeoutMs: 5000,
      certificateCompression: ["zlib"] });
    check("httpClient: all four requests reach the loopback server",
          [first, second, third, fourth].every(function (r) { return r && r.statusCode === 200; }));
    check("httpClient: a request listing zlib opens its own connection, and each list reuses its own (" +
          handshakes + " handshakes for 4 requests)", handshakes === 2);
    check("httpClient: one cached transport per certificate-compression list (" +
          httpClientLib._getCachedTransportCount() + ")", httpClientLib._getCachedTransportCount() === 2);
  } finally {
    httpClientLib._resetForTest();
    b.network.tls.removeCaByLabel(label);
    sockets.forEach(function (s) { try { s.destroy(); } catch (_e) { /* already closed */ } });
    await new Promise(function (r) { srv.close(function () { r(); }); });
  }
}

async function run() {
  testPostureObjectsCarryNoListByDefault();
  await testBadListsAreRefused();
  await testEveryEntryPointRefusesMalformedLists();
  await testOutboundDialsOfferNoCompressionByDefault();
  await testRouterListenerWithRequestCert();
  await testMailServerContext();
  await testCertSniCallbackContext();
  await testHttpClientTransportPerList();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
