// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A TLS listener that requests client certificates refuses a client whose
 * certificate chain carries a compromised key, including when the client
 * reconnects with the session it was given on the first connection: b.router
 * listeners, listeners built from b.network.tls.applyToContext with
 * b.network.tls.checkClientChains attached, and the requireMtls and
 * requireBoundKey gates on a listener the framework did not build. Every
 * client here presents a leaf with an ordinary key; the compromised key is the
 * intermediate the client sends (private key 1), and each control sends the
 * intermediate with an ordinary key instead.
 *
 * Node 24 does not expose the certificates a client sends to the listener
 * (getPeerCertificate(true) holds only the leaf), and Node 26 does. Where the
 * listener cannot see them, a chain the listener's ca cannot complete is
 * refused as tls/client-chain-unverifiable instead. The listeners below list
 * the control intermediate in their ca so the control client is authorized on
 * every supported Node; testRootOnlyCa covers a ca holding only the root.
 */

var tls     = require("node:tls");
var https   = require("node:https");
var crypto  = require("node:crypto");
var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var ck      = require("../helpers/compromised-keys");
var paths   = require("../helpers/chain-path");
var cryptoLib = require("../../lib/crypto");

var CLIENT_UNDER_COMPROMISED_INTERMEDIATE_DER = ck.TLS_CLIENT_UNDER_COMPROMISED_INTERMEDIATE_DER;
var CLIENT_UNDER_CONTROL_INTERMEDIATE_DER = ck.TLS_CLIENT_UNDER_CONTROL_INTERMEDIATE_DER;

var VERSIONS = ["TLSv1.3", "TLSv1.2"];

// Whether this Node shows a listener the intermediate a client sends, and the
// refusal a client chain under the compromised intermediate gets on a listener
// whose ca does not hold that intermediate.
var LISTENER = { seesClientChain: null };

function _compromisedCode() {
  return LISTENER.seesClientChain ? "tls/compromised-key" : "tls/client-chain-unverifiable";
}

function _compromisedReason() {
  return LISTENER.seesClientChain ? "compromised-key" : "client-chain-unverifiable";
}

function _serverCa() {
  return [ck.certPem(ck.TLS_ROOT_DER), ck.certPem(ck.TLS_CONTROL_INTERMEDIATE_DER)];
}

function _clientMaterial(which) {
  return ck.tlsClient(which);
}

// Nothing but the certificate DER followed by an X509_CERT_AUX that trusts the
// certificate for serverAuth, which is what `openssl x509 -trustout` writes.
var TRUST_AUX = Buffer.from("300c300a06082b06010505070301", "hex");

function _pemBlock(label, der) {
  return "-----BEGIN " + label + "-----\n" + der.toString("base64").match(/.{1,64}/g).join("\n") +
    "\n-----END " + label + "-----\n";
}

function _close(server) {
  if (typeof server.closeAllConnections === "function") server.closeAllConnections();
  return new Promise(function (resolve) { server.close(function () { resolve(); }); });
}

function _listening(server) {
  return new Promise(function (resolve) {
    if (server.listening) resolve();
    else server.once("listening", resolve);
  });
}

function _jsonIn(text) {
  var start = text.indexOf("{");
  var end = text.lastIndexOf("}");
  if (start === -1 || end < start) return null;
  try { return JSON.parse(text.slice(start, end + 1)); } catch (_e) { return null; }
}

// One TLS connection that sends `request` (or nothing, for a raw TLS server)
// and resolves with the reply, whether the session was resumed, and the
// sessions the server issued.
function _dial(port, client, version, session, request) {
  return new Promise(function (resolve) {
    var sessions = [];
    var reused = null;
    var out = "";
    var s = tls.connect({
      host: "127.0.0.1", port: port, servername: "localhost", ca: ck.certPem(ck.TLS_ROOT_DER),
      cert: client.cert, key: client.key, ALPNProtocols: ["http/1.1"],
      minVersion: version, maxVersion: version, session: session || undefined,
    });
    s.on("session", function (x) { sessions.push(x); });
    s.on("secureConnect", function () {
      reused = s.isSessionReused();
      if (request) s.write(request);
    });
    s.on("data", function (c) { out += c; });
    s.on("error", function () { /* a refused connection resolves on close */ });
    s.on("close", function () {
      resolve({ reused: reused, sessions: sessions, reply: _jsonIn(out), raw: out });
    });
  });
}

function _httpGet(path) {
  return "GET " + path + " HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer bound-key\r\nConnection: close\r\n\r\n";
}

// The first connection, then a second one offering the last session the first
// was given (or none, when it was given none).
async function _dialTwice(port, client, version, request) {
  var first = await _dial(port, client, version, null, request);
  var offered = first.sessions.length > 0 ? first.sessions[first.sessions.length - 1] : null;
  var second = await _dial(port, client, version, offered, request);
  return { first: first, second: second, offered: offered !== null };
}

function _authorizedReply(r) {
  return r.reply !== null && r.reply.authorized === true;
}

// A plain listener with no blamejs check reports what getPeerCertificate(true)
// holds for the control client.
async function _ensureProbe() {
  if (LISTENER.seesClientChain !== null) return;
  var serverChain = ck.tlsChain("control");
  var seen = null;
  var server = tls.createServer({ key: serverChain.key, cert: serverChain.cert, ca: serverChain.rootCa,
    requestCert: true, rejectUnauthorized: false }, function (sock) {
    var peer = sock.getPeerCertificate(true);
    var issuer = peer && peer.issuerCertificate;
    seen = !!(issuer && issuer !== peer && issuer.raw &&
              Buffer.from(issuer.raw).equals(ck.TLS_CONTROL_INTERMEDIATE_DER));
    sock.end("{}");
  });
  await new Promise(function (resolve) { server.listen(0, "127.0.0.1", resolve); });
  try {
    await _dial(server.address().port, _clientMaterial("control"), "TLSv1.3", null, null);
  } finally {
    await _close(server);
  }
  LISTENER.seesClientChain = seen === true;
}

async function _routerListener(version, rejectUnauthorized, ca) {
  var serverChain = ck.tlsChain("control");
  var r = b.router.create();
  r.get("/who", function (req, res) {
    res.json({ authorized: req.socket.authorized === true, err: req.socket.authorizationError || null });
  });
  r.get("/mtls", b.middleware.requireMtls({ audit: false }), function (req, res) {
    res.json({ authorized: true, passedRequireMtls: true });
  });
  var server = r.listen(0, function () {}, {
    key: serverChain.key, cert: serverChain.cert, ca: ca || _serverCa(),
    requestCert: true, rejectUnauthorized: rejectUnauthorized,
    minVersion: version, maxVersion: version,
  }, "127.0.0.1");
  server.on("tlsClientError", function () { /* the listener refused the chain */ });
  await _listening(server);
  return server;
}

async function testRouterRefusesAResumedSession() {
  await _ensureProbe();
  for (var vi = 0; vi < VERSIONS.length; vi += 1) {
    var version = VERSIONS[vi];
    for (var mode = 0; mode < 2; mode += 1) {
      var rejectUnauthorized = mode === 0;
      var label = "router listen (" + version + ", rejectUnauthorized " + rejectUnauthorized + ")";
      var server = await _routerListener(version, rejectUnauthorized);
      var port = server.address().port;
      try {
        var ok = await _dialTwice(port, _clientMaterial("control"), version, _httpGet("/who"));
        check(label + " control: a client chain under an ordinary intermediate is authorized on both connections",
              _authorizedReply(ok.first) && _authorizedReply(ok.second), JSON.stringify([ok.first.reply, ok.second.reply]));
        check(label + " control: the listener issues no session a client can resume",
              ok.second.reused === false, JSON.stringify({ offered: ok.offered, reused: ok.second.reused }));
        var bad = await _dialTwice(port, _clientMaterial("compromised"), version, _httpGet("/who"));
        check(label + ": a client chain under an intermediate whose private key is 1 is not authorized",
              !_authorizedReply(bad.first), JSON.stringify(bad.first.reply));
        check(label + ": reconnecting with the session from that connection is not authorized either",
              !_authorizedReply(bad.second),
              JSON.stringify({ offered: bad.offered, reused: bad.second.reused, reply: bad.second.reply }));
        var gate = await _dialTwice(port, _clientMaterial("compromised"), version, _httpGet("/mtls"));
        check(label + ": requireMtls refuses the resumed connection of that client",
              !(gate.second.reply && gate.second.reply.passedRequireMtls === true),
              JSON.stringify({ offered: gate.offered, reused: gate.second.reused, reply: gate.second.reply }));
        var gateOk = await _dialTwice(port, _clientMaterial("control"), version, _httpGet("/mtls"));
        check(label + " control: requireMtls serves the control client on both connections",
              !!(gateOk.first.reply && gateOk.first.reply.passedRequireMtls === true &&
                 gateOk.second.reply && gateOk.second.reply.passedRequireMtls === true),
              JSON.stringify([gateOk.first.reply, gateOk.second.reply]));
      } finally {
        await _close(server);
      }
    }
  }
}

// A listener the framework did not build: Node's https server with session
// tickets on, and for TLS 1.2 a session cache as well. requireMtls and
// requireBoundKey run in its handler. The server trusts the root and the
// ordinary intermediate, so a resumed control session rebuilds its chain to
// the root from the server's own store; the compromised intermediate is not in
// that store.
async function _operatorListener(version, handler) {
  var serverChain = ck.tlsChain("control");
  var server = https.createServer({
    key: serverChain.key, cert: serverChain.cert,
    ca: [serverChain.rootCa, ck.certPem(ck.TLS_CONTROL_INTERMEDIATE_DER)],
    requestCert: true, rejectUnauthorized: false, minVersion: version, maxVersion: version,
  }, handler);
  var store = new Map();
  server.on("newSession", function (id, data, cb) { store.set(id.toString("hex"), data); cb(); });
  server.on("resumeSession", function (id, cb) { cb(null, store.get(id.toString("hex")) || null); });
  server.on("tlsClientError", function () { /* refused */ });
  await new Promise(function (resolve) { server.listen(0, "127.0.0.1", resolve); });
  return server;
}

async function testRequireMtlsOnAResumedSession() {
  await _ensureProbe();
  var mw = b.middleware.requireMtls({ audit: false });
  for (var vi = 0; vi < VERSIONS.length; vi += 1) {
    var version = VERSIONS[vi];
    var label = "requireMtls on an operator listener (" + version + ")";
    var server = await _operatorListener(version, function (req, res) {
      mw(req, res, function () {
        res.setHeader("Content-Type", "application/json");
        res.end(JSON.stringify({ passed: true, reused: req.socket.isSessionReused() }));
      });
    });
    var port = server.address().port;
    try {
      var ok = await _dialTwice(port, _clientMaterial("control"), version, _httpGet("/"));
      check(label + " control: the control client passes on a full handshake",
            !!(ok.first.reply && ok.first.reply.passed === true), JSON.stringify(ok.first.reply));
      check(label + " control: the control client's resumed session passes, its chain rebuilt to the root",
            ok.second.reused === true && !!(ok.second.reply && ok.second.reply.passed === true),
            JSON.stringify({ reused: ok.second.reused, reply: ok.second.reply }));
      var bad = await _dialTwice(port, _clientMaterial("compromised"), version, _httpGet("/"));
      check(label + ": a client chain under an intermediate whose private key is 1 is refused as " + _compromisedReason(),
            !!(bad.first.reply && bad.first.reply.reason === _compromisedReason()), JSON.stringify(bad.first.reply));
      check(label + ": the same client resuming its session is refused as resumed-chain-unverifiable",
            bad.second.reused === true && !!(bad.second.reply && bad.second.reply.reason === "resumed-chain-unverifiable"),
            JSON.stringify({ reused: bad.second.reused, reply: bad.second.reply }));
    } finally {
      await _close(server);
    }
  }
}

async function testRequireBoundKeyOnAResumedSession() {
  await _ensureProbe();
  var pinned = [b.crypto.hashCertFingerprint(CLIENT_UNDER_COMPROMISED_INTERMEDIATE_DER).hex,
                b.crypto.hashCertFingerprint(CLIENT_UNDER_CONTROL_INTERMEDIATE_DER).hex];
  var mw = b.middleware.requireBoundKey({
    audit: false,
    resolver: async function (key) {
      return key === "bound-key" ? { id: "k1", scopes: [], peerCertFingerprints: pinned } : null;
    },
  });
  for (var vi = 0; vi < VERSIONS.length; vi += 1) {
    var version = VERSIONS[vi];
    var label = "requireBoundKey on an operator listener (" + version + ")";
    var server = await _operatorListener(version, function (req, res) {
      req.peerCert = req.socket.getPeerCertificate(true);
      mw(req, res, function () {
        res.setHeader("Content-Type", "application/json");
        res.end(JSON.stringify({ passed: true }));
      });
    });
    var port = server.address().port;
    try {
      var ok = await _dialTwice(port, _clientMaterial("control"), version, _httpGet("/"));
      check(label + " control: a key pinned to the control client is served on both connections",
            !!(ok.first.reply && ok.first.reply.passed === true && ok.second.reply && ok.second.reply.passed === true),
            JSON.stringify([ok.first.reply, ok.second.reply]));
      var bad = await _dialTwice(port, _clientMaterial("compromised"), version, _httpGet("/"));
      check(label + ": a key pinned to a client under an intermediate whose private key is 1 is refused as " +
            _compromisedReason(),
            !!(bad.first.reply && bad.first.reply.reason === _compromisedReason()), JSON.stringify(bad.first.reply));
      check(label + ": the resumed session of that client is refused as resumed-chain-unverifiable",
            bad.second.reused === true && !!(bad.second.reply && bad.second.reply.reason === "resumed-chain-unverifiable"),
            JSON.stringify({ reused: bad.second.reused, reply: bad.second.reply }));
    } finally {
      await _close(server);
    }
  }
}

// A listener that does not request client certificates, behind which the
// operator sets req.peerCert from a certificate a TLS-terminating proxy
// forwarded. A resumed session on that listener says nothing about the
// forwarded certificate, so requireBoundKey judges it the same on both
// connections: the control certificate passes twice, and the certificate
// under the compromised intermediate, forwarded with that intermediate as its
// issuer, is refused twice as compromised-key.
async function testForwardedCertificateOnAResumedSession() {
  var serverChain = ck.tlsChain("control");
  function forwardedCert(which) {
    var leaf = which === "control" ? CLIENT_UNDER_CONTROL_INTERMEDIATE_DER : CLIENT_UNDER_COMPROMISED_INTERMEDIATE_DER;
    var issuer = which === "control" ? ck.TLS_CONTROL_INTERMEDIATE_DER : ck.TLS_COMPROMISED_INTERMEDIATE_DER;
    var issuerNode = { raw: issuer, subject: { CN: "blamejs TLS fixture intermediate" } };
    return { raw: leaf, subject: { CN: "blamejs TLS fixture client" }, issuerCertificate: issuerNode };
  }
  var pinned = [b.crypto.hashCertFingerprint(CLIENT_UNDER_CONTROL_INTERMEDIATE_DER).hex,
                b.crypto.hashCertFingerprint(CLIENT_UNDER_COMPROMISED_INTERMEDIATE_DER).hex];
  var bound = b.middleware.requireBoundKey({
    audit: false,
    resolver: async function (key) {
      return key === "bound-key" ? { id: "k1", scopes: [], peerCertFingerprints: pinned } : null;
    },
  });
  for (var vi = 0; vi < VERSIONS.length; vi += 1) {
    var version = VERSIONS[vi];
    var server = https.createServer({
      key: serverChain.key, cert: serverChain.cert, minVersion: version, maxVersion: version,
    }, function (req, res) {
      req.peerCert = forwardedCert(req.url === "/control" ? "control" : "compromised");
      bound(req, res, function () {
        res.setHeader("Content-Type", "application/json");
        res.end(JSON.stringify({ passed: true }));
      });
    });
    await new Promise(function (resolve) { server.listen(0, "127.0.0.1", resolve); });
    var port = server.address().port;
    var noClientCert = { cert: undefined, key: undefined };
    var label = "requireBoundKey with a forwarded client certificate on a listener without requestCert (" + version + ")";
    try {
      var ok = await _dialTwice(port, noClientCert, version, _httpGet("/control"));
      check(label + " control: the first request passes", !!(ok.first.reply && ok.first.reply.passed === true),
            JSON.stringify(ok.first.reply));
      check(label + " control: the request on the resumed session passes too",
            ok.second.reused === true && !!(ok.second.reply && ok.second.reply.passed === true),
            JSON.stringify({ reused: ok.second.reused, reply: ok.second.reply }));
      var bad = await _dialTwice(port, noClientCert, version, _httpGet("/compromised"));
      check(label + ": a forwarded certificate under an intermediate whose private key is 1 is refused on both connections",
            !!(bad.first.reply && bad.first.reply.reason === "compromised-key" &&
               bad.second.reply && bad.second.reply.reason === "compromised-key"),
            JSON.stringify([bad.first.reply, bad.second.reply]));
    } finally {
      await _close(server);
    }
  }
}

async function _serverRoleListener(version, rejectUnauthorized) {
  var serverChain = ck.tlsChain("control");
  var server = tls.createServer(b.network.tls.applyToContext({ role: "server", base: {
    key: serverChain.key, cert: serverChain.cert, ca: _serverCa(),
    requestCert: true, rejectUnauthorized: rejectUnauthorized, minVersion: version, maxVersion: version,
  } }), function (sock) {
    sock.end(JSON.stringify({ authorized: sock.authorized === true, err: sock.authorizationError || null }));
  });
  server.on("tlsClientError", function () { /* refused */ });
  b.network.tls.checkClientChains(server);
  await new Promise(function (resolve) { server.listen(0, "127.0.0.1", resolve); });
  return server;
}

async function testServerRoleListener() {
  await _ensureProbe();
  for (var vi = 0; vi < VERSIONS.length; vi += 1) {
    var version = VERSIONS[vi];
    for (var mode = 0; mode < 2; mode += 1) {
      var rejectUnauthorized = mode === 0;
      var label = "applyToContext role server + checkClientChains (" + version + ", rejectUnauthorized " +
        rejectUnauthorized + ")";
      var server = await _serverRoleListener(version, rejectUnauthorized);
      var port = server.address().port;
      try {
        var ok = await _dialTwice(port, _clientMaterial("control"), version, null);
        check(label + " control: a client chain under an ordinary intermediate is authorized on both connections",
              _authorizedReply(ok.first) && _authorizedReply(ok.second), JSON.stringify([ok.first.reply, ok.second.reply]));
        check(label + " control: the listener issues no session a client can resume",
              ok.second.reused === false, JSON.stringify({ offered: ok.offered, reused: ok.second.reused }));
        var bad = await _dialTwice(port, _clientMaterial("compromised"), version, null);
        check(label + ": a client chain under an intermediate whose private key is 1 is not authorized",
              !_authorizedReply(bad.first), JSON.stringify(bad.first.reply));
        check(label + ": reconnecting with the session from that connection is not authorized either",
              !_authorizedReply(bad.second), JSON.stringify({ reused: bad.second.reused, reply: bad.second.reply }));
        if (!rejectUnauthorized) {
          check(label + ": the refusal names " + _compromisedCode(),
                !!(bad.first.reply && bad.first.reply.err === _compromisedCode()), JSON.stringify(bad.first.reply));
        }
      } finally {
        await _close(server);
      }
    }
  }
}

// A listener built without applyToContext, so its context issues session
// tickets. checkClientChains stops the listener from issuing them, so the
// control client connects with a full handshake every time and stays
// authorized, and the compromised client cannot resume a session.
async function _ticketListener(version, rejectUnauthorized) {
  var serverChain = ck.tlsChain("control");
  var server = tls.createServer({
    key: serverChain.key, cert: serverChain.cert, ca: _serverCa(),
    requestCert: true, rejectUnauthorized: rejectUnauthorized, minVersion: version, maxVersion: version,
  }, function (sock) {
    sock.end(JSON.stringify({ authorized: sock.authorized === true, err: sock.authorizationError || null }));
  });
  server.on("tlsClientError", function () { /* refused */ });
  b.network.tls.checkClientChains(server);
  await new Promise(function (resolve) { server.listen(0, "127.0.0.1", resolve); });
  return server;
}

async function testCheckClientChainsOnAListenerWithTickets() {
  for (var vi = 0; vi < VERSIONS.length; vi += 1) {
    var version = VERSIONS[vi];
    for (var mode = 0; mode < 2; mode += 1) {
      var rejectUnauthorized = mode === 0;
      var label = "tls.createServer + checkClientChains (" + version + ", rejectUnauthorized " + rejectUnauthorized + ")";
      var server = await _ticketListener(version, rejectUnauthorized);
      var port = server.address().port;
      try {
        var ok = await _dialTwice(port, _clientMaterial("control"), version, null);
        check(label + " control: a client chain under an ordinary intermediate is authorized on both connections",
              _authorizedReply(ok.first) && _authorizedReply(ok.second), JSON.stringify([ok.first.reply, ok.second.reply]));
        check(label + " control: the listener issues no session a client can resume",
              ok.second.reused === false, JSON.stringify({ offered: ok.offered, reused: ok.second.reused }));
        var bad = await _dialTwice(port, _clientMaterial("compromised"), version, null);
        check(label + ": a client chain under an intermediate whose private key is 1 is not authorized",
              !_authorizedReply(bad.first), JSON.stringify(bad.first.reply));
        check(label + ": reconnecting with the session from that connection is not authorized either",
              !_authorizedReply(bad.second), JSON.stringify({ reused: bad.second.reused, reply: bad.second.reply }));
      } finally {
        await _close(server);
      }
    }
  }
}

// A router listener whose ca holds only the root, so the intermediate exists
// only in what the client sends. Where the listener sees that intermediate,
// the control client is authorized and the compromised one is refused as
// tls/compromised-key; where it does not, both are refused as
// tls/client-chain-unverifiable, because neither chain can be checked.
async function testRootOnlyCa() {
  await _ensureProbe();
  var rootOnly = ck.tlsChain("control").rootCa;
  for (var vi = 0; vi < VERSIONS.length; vi += 1) {
    var version = VERSIONS[vi];
    var label = "router listen with only the root as ca (" + version + ", sees the client's intermediate: " +
      LISTENER.seesClientChain + ")";
    var server = await _routerListener(version, false, rootOnly);
    var port = server.address().port;
    try {
      var ok = await _dial(port, _clientMaterial("control"), version, null, _httpGet("/who"));
      if (LISTENER.seesClientChain) {
        check(label + " control: a client chain under an ordinary intermediate is authorized",
              !!(ok.reply && ok.reply.authorized === true), JSON.stringify(ok.reply));
      } else {
        check(label + " control: a client chain the listener cannot see is refused as tls/client-chain-unverifiable",
              !!(ok.reply && ok.reply.authorized === false && ok.reply.err === "tls/client-chain-unverifiable"),
              JSON.stringify(ok.reply));
      }
      var bad = await _dial(port, _clientMaterial("compromised"), version, null, _httpGet("/who"));
      check(label + ": a client chain under an intermediate whose private key is 1 is refused as " + _compromisedCode(),
            !!(bad.reply && bad.reply.authorized === false && bad.reply.err === _compromisedCode()),
            JSON.stringify(bad.reply));
    } finally {
      await _close(server);
    }
  }
}

// A socket shaped like the one Node 24 gives a listener: authorized, with a
// peer certificate that holds only the leaf. The listener's ca completes the
// chain, and the completed chain is checked: an intermediate in that ca with
// private key 1 is refused, and a chain the ca cannot complete is refused as
// unverifiable, or as resumed-chain-unverifiable on a resumed session.
function testChainCompletedFromTheListenerCa() {
  function sock(leafDer, resumed) {
    return {
      authorized: true,
      isSessionReused: function () { return resumed; },
      getPeerCertificate: function () { return { raw: leafDer, subject: { CN: "blamejs TLS fixture client" } }; },
    };
  }
  function peer(leafDer) { return { raw: leafDer, subject: { CN: "blamejs TLS fixture client" } }; }
  function code(leafDer, ca, resumed) {
    var e = b.network.tls._clientChainError(sock(leafDer, resumed), peer(leafDer), { ca: ca });
    return e ? e.code : null;
  }
  var root = ck.certPem(ck.TLS_ROOT_DER);
  var controlCa = [root, ck.certPem(ck.TLS_CONTROL_INTERMEDIATE_DER)];
  var compromisedCa = [root, ck.certPem(ck.TLS_COMPROMISED_INTERMEDIATE_DER)];
  check("chain completion control: a leaf under an intermediate in the listener's ca passes",
        code(CLIENT_UNDER_CONTROL_INTERMEDIATE_DER, controlCa, false) === null);
  check("chain completion control: the same leaf on a resumed session passes",
        code(CLIENT_UNDER_CONTROL_INTERMEDIATE_DER, controlCa, true) === null);
  check("chain completion: an intermediate in the listener's ca with private key 1 is refused as tls/compromised-key",
        code(CLIENT_UNDER_COMPROMISED_INTERMEDIATE_DER, compromisedCa, false) === "tls/compromised-key");
  check("chain completion: a leaf the listener's ca cannot complete is refused as tls/client-chain-unverifiable",
        code(CLIENT_UNDER_COMPROMISED_INTERMEDIATE_DER, controlCa, false) === "tls/client-chain-unverifiable");
  check("chain completion: the same leaf on a resumed session is refused as tls/resumed-chain-unverifiable",
        code(CLIENT_UNDER_COMPROMISED_INTERMEDIATE_DER, controlCa, true) === "tls/resumed-chain-unverifiable");
  check("chain completion control: a leaf under an ordinary intermediate is not completed through a different " +
        "intermediate of the same name",
        code(CLIENT_UNDER_CONTROL_INTERMEDIATE_DER, compromisedCa, false) === "tls/client-chain-unverifiable");
  var unauthorized = sock(CLIENT_UNDER_COMPROMISED_INTERMEDIATE_DER, false);
  unauthorized.authorized = false;
  check("chain completion: a socket that is not authorized is not completed",
        b.network.tls._clientChainError(unauthorized, peer(CLIENT_UNDER_COMPROMISED_INTERMEDIATE_DER),
          { ca: controlCa }) === undefined);
}

function _shownChain(ders) {
  var nodes = ders.map(function (der) {
    var x = new crypto.X509Certificate(der);
    var m = /CN=([^\n,]+)/.exec(x.subject);
    return { raw: der, subject: { CN: m ? m[1] : "" } };
  });
  for (var i = 0; i < nodes.length; i += 1) nodes[i].issuerCertificate = nodes[i + 1] || nodes[i];
  return nodes[0];
}

// The chain Node shows a listener is linked in the order the client sent its
// certificates, which need not be the path OpenSSL verified. The check walks
// that chain to the first certificate the listener's ca trusts and refuses a
// chain that reaches none.
function testTheShownChainIsWalkedToAListenerAnchor() {
  function code(ders, ca) {
    var peer = _shownChain(ders);
    var sock = {
      authorized: true,
      isSessionReused: function () { return false; },
      getPeerCertificate: function () { return peer; },
    };
    var e = b.network.tls._clientChainError(sock, peer, { ca: ca });
    return e ? e.code : null;
  }
  var root = [ck.certPem(ck.TLS_ROOT_DER)];
  var newRoot = [ck.certPem(paths.NEW_ROOT_DER)];
  check("listener chain walk: leaf <- expired alternate <- fake root is refused as tls/client-chain-unverifiable",
        code([paths.PATH_LEAF_DER, paths.ATTACKER_CA_EXPIRED_ALTERNATE_DER, paths.FAKE_ROOT_DER], root) ===
          "tls/client-chain-unverifiable");
  check("listener chain walk control: leaf <- attacker CA <- ordinary issuing CA <- root passes",
        code([paths.PATH_LEAF_DER, paths.ATTACKER_CA_UNDER_CONTROL_DER, paths.ISSUING_CA_CONTROL_DER,
              ck.TLS_ROOT_DER], root) === null);
  check("listener chain walk: an issuing CA whose private key is 1 is refused as tls/compromised-key",
        code([paths.PATH_LEAF_DER, paths.ATTACKER_CA_UNDER_COMPROMISED_DER, paths.ISSUING_CA_COMPROMISED_DER,
              ck.TLS_ROOT_DER], root) === "tls/compromised-key");
  check("listener chain walk control: a client chain ending in an expired cross-certificate of the anchor passes",
        code([paths.NEW_ROOT_LEAF_DER, paths.NEW_ROOT_INTERMEDIATE_DER, paths.NEW_ROOT_CROSS_EXPIRED_DER], newRoot) ===
          null);
}

// A client whose chain hides the compromised issuing CA behind an expired
// alternate and a decoy root, and clients sending a cross-signed chain, to a
// listener with checkClientChains. Where this Node shows the listener only the
// leaf, a chain whose issuer the ca does not hold is refused as
// tls/client-chain-unverifiable.
async function _pathListener(ca) {
  var serverChain = ck.tlsChain("control");
  var server = tls.createServer({
    key: serverChain.key, cert: serverChain.cert, ca: ca, requestCert: true, rejectUnauthorized: false,
  }, function (sock) {
    sock.end(JSON.stringify({ authorized: sock.authorized === true, err: sock.authorizationError || null }));
  });
  server.on("tlsClientError", function () { /* refused */ });
  b.network.tls.checkClientChains(server);
  await new Promise(function (resolve) { server.listen(0, "127.0.0.1", resolve); });
  return server;
}

async function testPathEvasionAndCrossSignedClients() {
  await _ensureProbe();
  var sees = LISTENER.seesClientChain;
  var groups = [
    [[ck.certPem(ck.TLS_ROOT_DER)], [
      ["control", paths.evasionChain("control"), sees ? null : "tls/client-chain-unverifiable"],
      ["compromised", paths.evasionChain("compromised"), sees ? "tls/compromised-key" : "tls/client-chain-unverifiable"],
      ["compromised-evasion", paths.evasionChain("compromised-evasion"), "tls/client-chain-unverifiable"],
    ]],
    [[ck.certPem(paths.NEW_ROOT_DER)], [
      ["cross", paths.crossChain("cross"), sees ? null : "tls/client-chain-unverifiable"],
      ["intermediate", paths.crossChain("intermediate"), sees ? null : "tls/client-chain-unverifiable"],
      ["direct", paths.crossChain("direct"), null],
    ]],
  ];
  for (var g = 0; g < groups.length; g += 1) {
    var server = await _pathListener(groups[g][0]);
    try {
      for (var i = 0; i < groups[g][1].length; i += 1) {
        var c = groups[g][1][i];
        var r = await _dial(server.address().port, { cert: c[1].cert, key: c[1].key }, "TLSv1.3", null, null);
        var label = "checkClientChains " + c[0] + " client chain (sees the client's chain: " + sees + ")";
        if (c[2] === null) {
          check(label + " control: authorized", !!(r.reply && r.reply.authorized === true), JSON.stringify(r.reply));
        } else {
          check(label + ": refused as " + c[2], !!(r.reply && r.reply.authorized === false && r.reply.err === c[2]),
                JSON.stringify(r.reply));
        }
      }
    } finally {
      await _close(server);
    }
  }
}

async function testRouterRequireMtlsRefusesThePathEvasion() {
  var server = await _routerListener("TLSv1.3", true, [ck.certPem(ck.TLS_ROOT_DER)]);
  try {
    var bad = paths.evasionChain("compromised-evasion");
    var r = await _dial(server.address().port, { cert: bad.cert, key: bad.key }, "TLSv1.3", null, _httpGet("/mtls"));
    check("router + requireMtls: a client chain hiding the compromised issuing CA does not pass",
          !(r.reply && r.reply.passedRequireMtls === true), JSON.stringify({ reply: r.reply, raw: r.raw.slice(0, 200) }));
  } finally {
    await _close(server);
  }
}

// Keep-alive requests on one connection: requireMtls judges the socket's own
// peer certificate once, and later requests on that socket reuse the result.
async function testRequireMtlsJudgesASocketOnce() {
  var server = await _routerListener("TLSv1.3", true);
  var connections = 0;
  server.on("secureConnection", function () { connections += 1; });
  var client = _clientMaterial("control");
  var agent = new https.Agent({ keepAlive: true, maxSockets: 1, ca: ck.certPem(ck.TLS_ROOT_DER),
    cert: client.cert, key: client.key, servername: "localhost" });
  function get() {
    return new Promise(function (resolve) {
      var req = https.request({ host: "127.0.0.1", port: server.address().port, path: "/mtls", agent: agent,
        servername: "localhost" }, function (res) {
        var body = "";
        res.setEncoding("utf8");
        res.on("data", function (d) { body += d; });
        res.on("end", function () { resolve(_jsonIn(body)); });
      });
      req.on("error", function (e) { resolve({ error: e.code || e.message }); });
      req.end();
    });
  }
  var original = cryptoLib.compromisedKey;
  var calls = 0;
  cryptoLib.compromisedKey = function () { calls += 1; return original.apply(this, arguments); };
  try {
    var first = await get();
    var afterFirst = calls;
    var second = await get();
    var third = await get();
    check("requireMtls control: three keep-alive requests pass on one connection",
          !!(first && first.passedRequireMtls && second && second.passedRequireMtls && third && third.passedRequireMtls) &&
            connections === 1, JSON.stringify({ first: first, second: second, third: third, connections: connections }));
    check("requireMtls: requests after the first on the same socket do not walk the chain again",
          calls === afterFirst, JSON.stringify({ afterFirst: afterFirst, afterThird: calls }));
  } finally {
    cryptoLib.compromisedKey = original;
    agent.destroy();
    await _close(server);
  }
}

function testCheckClientChainsRefusesANonServer() {
  var code = null;
  try { b.network.tls.checkClientChains({}); } catch (e) { code = e && e.code; }
  check("checkClientChains: a value with no prependListener throws tls/bad-server", code === "tls/bad-server", code);
}

// A client chain that failed verification is already unauthorized, and the
// listener keeps the verification error rather than replacing it.
async function testUnverifiedChainKeepsItsError() {
  var serverChain = ck.tlsChain("control");
  var r = b.router.create();
  r.get("/who", function (req, res) {
    res.json({ authorized: req.socket.authorized === true, err: req.socket.authorizationError || null });
  });
  var server = r.listen(0, function () {}, {
    key: serverChain.key, cert: serverChain.cert, ca: ck.p384ControlCa().caCertPem,
    requestCert: true, rejectUnauthorized: false,
  }, "127.0.0.1");
  server.on("tlsClientError", function () { /* refused */ });
  await _listening(server);
  try {
    var ok = await _dial(server.address().port, _clientMaterial("control"), "TLSv1.3", null, _httpGet("/who"));
    var bad = await _dial(server.address().port, _clientMaterial("compromised"), "TLSv1.3", null, _httpGet("/who"));
    check("router listen control: a client chain no configured CA issued keeps the verification error",
          !!(ok.reply && ok.reply.authorized === false && typeof ok.reply.err === "string" &&
             ok.reply.err.indexOf("tls/") !== 0), JSON.stringify(ok.reply));
    check("router listen: the same unverified chain with an intermediate whose private key is 1 keeps that error too",
          !!(bad.reply && ok.reply && bad.reply.authorized === false && bad.reply.err === ok.reply.err),
          JSON.stringify([ok.reply, bad.reply]));
  } finally {
    await _close(server);
  }
}

function _codeOf(fn) {
  try { var v = fn(); if (v && typeof v.close === "function") v.close(); return null; }
  catch (e) { return (e && e.code) || String(e); }
}

// Node accepts a CA under the TRUSTED CERTIFICATE and X509 CERTIFICATE labels,
// so a compromised CA under either label is refused like one under CERTIFICATE.
function testCaUnderEveryLabel() {
  var serverChain = ck.tlsChain("control");
  var labels = ["TRUSTED CERTIFICATE", "X509 CERTIFICATE"];
  labels.forEach(function (label) {
    function pem(der) { return _pemBlock(label, label === "TRUSTED CERTIFICATE" ? Buffer.concat([der, TRUST_AUX]) : der); }
    var bad = pem(ck.P384_COMPROMISED_CA_DER);
    var good = pem(ck.P384_CONTROL_CA_DER);
    var sites = [
      ["router.listen tlsOptions.ca", "router/compromised-key", function (ca) {
        return b.router.create().listen(0, function () {}, { key: serverChain.key, cert: serverChain.cert,
          ca: ca, requestCert: true }, "127.0.0.1");
      }],
      ["applyToContext role server base.ca", "tls/compromised-key", function (ca) {
        return b.network.tls.applyToContext({ role: "server", base: { ca: ca } });
      }],
      ["applyToContext role client base.ca", "tls/compromised-key", function (ca) {
        return b.network.tls.applyToContext({ role: "client", base: { ca: ca } });
      }],
      ["buildOptions ca", "tls/compromised-key", function (ca) { return b.network.tls.buildOptions({ ca: ca }); }],
      ["pqcAgent.create ca", "pqcagent/compromised-key", function (ca) { return b.pqcAgent.create({ ca: ca }); }],
    ];
    sites.forEach(function (s) {
      var badCode = _codeOf(function () { return s[2](bad); });
      check(s[0] + ": a compromised CA under the " + label + " label is refused with " + s[1], badCode === s[1], badCode);
      var goodCode = _codeOf(function () { return s[2](good); });
      check(s[0] + " control: an ordinary CA under the " + label + " label is accepted", goodCode === null, goodCode);
    });
  });
}

var TESTS = [
  testRouterRefusesAResumedSession,
  testRequireMtlsOnAResumedSession,
  testRequireBoundKeyOnAResumedSession,
  testForwardedCertificateOnAResumedSession,
  testServerRoleListener,
  testCheckClientChainsOnAListenerWithTickets,
  testRootOnlyCa,
  testChainCompletedFromTheListenerCa,
  testTheShownChainIsWalkedToAListenerAnchor,
  testPathEvasionAndCrossSignedClients,
  testRouterRequireMtlsRefusesThePathEvasion,
  testRequireMtlsJudgesASocketOnce,
  testCheckClientChainsRefusesANonServer,
  testUnverifiedChainKeepsItsError,
  testCaUnderEveryLabel,
];

async function run() {
  for (var i = 0; i < TESTS.length; i += 1) await TESTS[i]();
}

module.exports = { run: run, TESTS: TESTS };

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
