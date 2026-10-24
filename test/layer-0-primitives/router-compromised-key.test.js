// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.router listen() refuses a compromised key on a listener that trusts client
 * certificates: a `tlsOptions.ca` whose key anyone can hold throws
 * router/compromised-key, and a client whose certificate chain carries a
 * compromised key is not authorized, over a real loopback handshake. Each
 * refusal has a control that differs only in the key.
 */

var https   = require("node:https");
var crypto  = require("node:crypto");
var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var ck      = require("../helpers/compromised-keys");

var COMPROMISED_CA_PEM = ck.certPem(ck.P384_COMPROMISED_CA_DER);

// P-256 client certificates (CN "blamejs TLS fixture client", EKU clientAuth,
// 2026-01-01 .. 2099-12-31) issued by the TLS fixture root in
// test/helpers/compromised-keys.js, minted with @blamejs/pki 0.9.5. The
// compromised certificate's private scalar is 1; the control's is
// SHA-256("blamejs tls fixture client").
var TLS_COMPROMISED_CLIENT_DER = Buffer.from(
  "MIIBrjCCAVSgAwIBAgIBBDAKBggqhkjOPQQDAjAjMSEwHwYDVQQDDBhibGFtZWpz" +
  "IFRMUyBmaXh0dXJlIHJvb3QwIBcNMjYwMTAxMDAwMDAwWhgPMjA5OTEyMzEwMDAw" +
  "MDBaMCUxIzAhBgNVBAMMGmJsYW1lanMgVExTIGZpeHR1cmUgY2xpZW50MFkwEwYH" +
  "KoZIzj0CAQYIKoZIzj0DAQcDQgAEaxfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5" +
  "RdiYwpZP40Li/hp/m47n60p8D54WK84zV2sxXs7LtkBoN79R9aN1MHMwHQYDVR0O" +
  "BBYEFLRno5mete+mcd4AMvCKnJ5e/aDhMB8GA1UdIwQYMBaAFPJtSuBdKpki5ZX6" +
  "uv1XNOBB+kgjMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAjAM" +
  "BgNVHRMBAf8EAjAAMAoGCCqGSM49BAMCA0gAMEUCIQDV/d3MPe00O5HZk9r/VrEg" +
  "YmdJiBSZe/B2n9RNGDwGGQIgOvljpKMczEgbofqb1z/5/bLCZUZ5fkQY9K5Hc/sJ" +
  "DKU=", "base64");
var TLS_CONTROL_CLIENT_DER = Buffer.from(
  "MIIBrjCCAVSgAwIBAgIBBTAKBggqhkjOPQQDAjAjMSEwHwYDVQQDDBhibGFtZWpz" +
  "IFRMUyBmaXh0dXJlIHJvb3QwIBcNMjYwMTAxMDAwMDAwWhgPMjA5OTEyMzEwMDAw" +
  "MDBaMCUxIzAhBgNVBAMMGmJsYW1lanMgVExTIGZpeHR1cmUgY2xpZW50MFkwEwYH" +
  "KoZIzj0CAQYIKoZIzj0DAQcDQgAEU9N9EQ+94WIiOq7MJahGBEFiOVGV0ItYI70O" +
  "Bqrfk49DEocNyjiy/S2XvIgX5C72nXkMKk1RR6NZWLhscIHZaaN1MHMwHQYDVR0O" +
  "BBYEFLJzv1c6Wh8eXwqG+TU0m6jrVFHmMB8GA1UdIwQYMBaAFPJtSuBdKpki5ZX6" +
  "uv1XNOBB+kgjMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAjAM" +
  "BgNVHRMBAf8EAjAAMAoGCCqGSM49BAMCA0gAMEUCIFmSkNVMW02zwzlxHzTokOTv" +
  "HRkHdZ5Y3Y1cVVG4QMl+AiEAl4PbRGA4KNa6lzSXVFeNzNAd/uAwz8oVYTeQfqps" +
  "P+4=", "base64");

function _clientMaterial(which) {
  var d = which === "compromised" ? 1n
    : BigInt("0x" + crypto.createHash("sha256").update("blamejs tls fixture client", "utf8").digest("hex"));
  return {
    cert: ck.certPem(which === "compromised" ? TLS_COMPROMISED_CLIENT_DER : TLS_CONTROL_CLIENT_DER),
    key:  ck.ecKeyPair("prime256v1", d).privateKey.export({ type: "pkcs8", format: "pem" }),
  };
}

function _codeOf(fn) {
  try { fn(); return null; } catch (e) { return (e && e.code) || String(e); }
}

function _listening(server) {
  return new Promise(function (resolve) {
    if (server.listening) resolve();
    else server.once("listening", resolve);
  });
}

function _close(server) {
  return new Promise(function (resolve) { server.close(function () { resolve(); }); });
}

function testListenRefusesACompromisedCa() {
  var serverChain = ck.tlsChain("control");
  var r = b.router.create();
  var server = null;
  var code = _codeOf(function () {
    server = r.listen(0, function () {}, { key: serverChain.key, cert: serverChain.cert,
      ca: [serverChain.rootCa, COMPROMISED_CA_PEM], requestCert: true }, "127.0.0.1");
  });
  if (server) server.close();
  check("router listen: a tlsOptions.ca whose private key is 1 throws router/compromised-key",
        code === "router/compromised-key", code);
}

function _get(port, client, rootCa) {
  return new Promise(function (resolve) {
    var req = https.request({ host: "127.0.0.1", servername: "localhost", port: port, path: "/who",
      ca: rootCa, cert: client.cert, key: client.key, agent: false }, function (res) {
      var body = "";
      res.setEncoding("utf8");
      res.on("data", function (c) { body += c; });
      res.on("end", function () { resolve({ status: res.statusCode, body: body, code: null }); });
    });
    req.on("error", function (e) { resolve({ status: null, body: null, code: (e && e.code) || e.message }); });
    req.end();
  });
}

async function _listener(extra) {
  var serverChain = ck.tlsChain("control");
  var r = b.router.create();
  r.get("/who", function (req, res) {
    res.json({ authorized: req.socket.authorized === true });
  });
  var server = r.listen(0, function () {}, Object.assign({ key: serverChain.key, cert: serverChain.cert,
    ca: serverChain.rootCa, requestCert: true }, extra), "127.0.0.1");
  server.on("tlsClientError", function () { /* the listener refused the chain */ });
  await _listening(server);
  return { server: server, port: server.address().port, rootCa: serverChain.rootCa };
}

async function testClientChainOptional() {
  var l = await _listener({ rejectUnauthorized: false });
  try {
    var ok = await _get(l.port, _clientMaterial("control"), l.rootCa);
    check("router listen control (rejectUnauthorized false): a client certificate with an ordinary key is authorized",
          ok.status === 200 && ok.body === "{\"authorized\":true}", JSON.stringify(ok));
    var bad = await _get(l.port, _clientMaterial("compromised"), l.rootCa);
    check("router listen (rejectUnauthorized false): a client certificate whose private key is 1 is not authorized",
          bad.status === 200 && bad.body === "{\"authorized\":false}", JSON.stringify(bad));
  } finally {
    if (typeof l.server.closeAllConnections === "function") l.server.closeAllConnections();
    await _close(l.server);
  }
}

async function testClientChain() {
  var l = await _listener({});
  var server = l.server;
  var port = l.port;
  var serverChain = { rootCa: l.rootCa };
  try {
    var ok = await _get(port, _clientMaterial("control"), serverChain.rootCa);
    check("router listen control: a client certificate with an ordinary key is authorized",
          ok.status === 200 && ok.body === "{\"authorized\":true}", JSON.stringify(ok));
    var bad = await _get(port, _clientMaterial("compromised"), serverChain.rootCa);
    check("router listen: a client certificate whose private key is 1 is not authorized",
          bad.status === null || bad.body === "{\"authorized\":false}", JSON.stringify(bad));
    check("router listen: the connection from a client certificate whose private key is 1 is closed",
          bad.status === null, JSON.stringify(bad));
  } finally {
    if (typeof server.closeAllConnections === "function") server.closeAllConnections();
    await _close(server);
  }
}

var TESTS = [testListenRefusesACompromisedCa, testClientChain, testClientChainOptional];

async function run() {
  for (var i = 0; i < TESTS.length; i += 1) await TESTS[i]();
}

module.exports = { run: run, TESTS: TESTS };

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
