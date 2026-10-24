// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.network.ntp.nts refuses a compromised key: a `ca` holding a certificate
 * with a compromised key is refused before any connection is made, and an
 * NTS-KE server whose verified chain carries a compromised key fails the
 * handshake with nts/compromised-key before any key material is exported.
 * The loopback servers present a chain whose intermediate's private key is 1;
 * the control chain differs only in that key.
 *
 * A compromised anchor in the default CA store is refused even when the
 * server sends a decoy in its place, a `ca` is screened under every PEM label
 * OpenSSL trusts, and a `ca` with no certificate in it is accepted as node
 * accepts it.
 */

var helpers    = require("../helpers");
var check      = helpers.check;
var b          = helpers.b;
var nodeTls    = require("node:tls");
var nodeCrypto = require("node:crypto");
var ck         = require("../helpers/compromised-keys");
var anchors    = require("../helpers/compromised-anchor");

var nts = b.network.ntp.nts;

var COMPROMISED_CA = ck.certPem(ck.P384_COMPROMISED_CA_DER);
var CONTROL_CA     = ck.certPem(ck.P384_CONTROL_CA_DER);

function _rec(critical, type, body) {
  var hdr = Buffer.alloc(4);
  hdr.writeUInt16BE((critical ? 0x8000 : 0) | type, 0);
  hdr.writeUInt16BE(body.length, 2);
  return Buffer.concat([hdr, body]);
}
function _u16(v) { var buf = Buffer.alloc(2); buf.writeUInt16BE(v, 0); return buf; }

function _keReply() {
  return Buffer.concat([
    _rec(true, 1, _u16(0)),
    _rec(true, 4, _u16(15)),
    _rec(false, 5, nodeCrypto.randomBytes(32)),
    _rec(true, 0, Buffer.alloc(0)),
  ]);
}

function _startKe(which) {
  var chain = typeof which === "string" ? ck.tlsChain(which) : which;
  var handle = { requests: 0 };
  return new Promise(function (resolve) {
    var srv = nodeTls.createServer({
      key: chain.key, cert: chain.cert, ALPNProtocols: ["ntske/1"],
    }, function (sock) {
      sock.on("error", function () { /* the client tears down on refusal */ });
      sock.once("data", function () {
        handle.requests += 1;
        sock.write(_keReply());
      });
    });
    srv.on("error", function () { /* fixture best-effort */ });
    srv.on("tlsClientError", function () { /* the client refused the chain */ });
    srv.listen(0, "127.0.0.1", function () {
      handle.server = srv;
      handle.port = srv.address().port;
      handle.rootCa = chain.rootCa;
      resolve(handle);
    });
  });
}

function _code(fn) {
  try { fn(); return "NO-THROW"; } catch (e) { return e.code || e.message; }
}
async function _codeAsync(fn) {
  try { await fn(); return "NO-THROW"; } catch (e) { return e.code || e.message; }
}

async function testConfigRefusesCompromisedCa() {
  var ctl = await _startKe("control");
  try {
    var ke = await nts.performKeHandshake({
      host: "127.0.0.1", port: ctl.port, servername: "localhost", ca: [ctl.rootCa, CONTROL_CA],
    });
    check("nts compromised ca control: a ca bundle with an ordinary extra CA completes the handshake",
          ke && ke.aeadId === 15 && ke.cookies.length === 1);
  } finally { ctl.server.close(); }

  check("nts compromised ca: performKeHandshake refuses a ca bundle holding a CA whose private key is 1",
        _code(function () {
          nts.performKeHandshake({ host: "127.0.0.1", port: 1, servername: "localhost", ca: [CONTROL_CA, COMPROMISED_CA] })
            .catch(function () { /* the refusal is synchronous */ });
        }) === "nts/compromised-key");
  check("nts compromised ca: query rejects a ca that is the listed eDellRoot certificate",
        await _codeAsync(function () {
          return nts.query({ host: "127.0.0.1", kePort: 1, servername: "localhost", ca: ck.EDELLROOT_CERT_PEM });
        }) === "nts/compromised-key");
}

async function testHandshakeRefusesCompromisedChain() {
  var ctl = await _startKe("control");
  var ok = null;
  var okErr = null;
  try {
    ok = await nts.performKeHandshake({ host: "127.0.0.1", port: ctl.port, servername: "localhost", ca: ctl.rootCa });
  } catch (e) { okErr = e; }
  ctl.server.close();
  check("nts compromised chain control: the handshake completes through a chain of ordinary keys",
        okErr === null && ok && Buffer.isBuffer(ok.c2sKey) && ok.c2sKey.length === 32,
        okErr && (okErr.code + " " + okErr.message));

  var bad = await _startKe("compromised");
  var code = await _codeAsync(function () {
    return nts.performKeHandshake({ host: "127.0.0.1", port: bad.port, servername: "localhost", ca: bad.rootCa });
  });
  bad.server.close();
  check("nts compromised chain: the handshake fails with nts/compromised-key and no request is sent",
        code === "nts/compromised-key" && bad.requests === 0, code + " requests=" + bad.requests);
}

function _configCode(caValue) {
  return _code(function () {
    nts.performKeHandshake({ host: "127.0.0.1", port: 1, servername: "localhost", ca: caValue, timeoutMs: 2000 })
      .catch(function () { /* nothing listens on port 1 */ });
  });
}

function testConfigReadsEveryCertificateLabel() {
  var bad = anchors.caLabels(ck.P384_COMPROMISED_CA_DER);
  var ok = anchors.caLabels(ck.P384_CONTROL_CA_DER);
  Object.keys(bad).forEach(function (label) {
    check("nts ca label control: performKeHandshake accepts an ordinary CA under the " + label + " label",
          _configCode(ok[label]) === "NO-THROW");
    check("nts ca label: performKeHandshake refuses a CA whose private key is 1 under the " + label + " label",
          _configCode([CONTROL_CA, bad[label]]) === "nts/compromised-key");
  });
}

function testConfigAcceptsACaWithoutACertificate() {
  [["an empty Buffer", Buffer.alloc(0)], ["a Buffer of comments", Buffer.from("# no certificate here\n")]]
    .forEach(function (f) {
      check("nts ca without a certificate: performKeHandshake accepts " + f[0] + " as node does",
            _configCode(f[1]) === "NO-THROW");
    });
}

async function testDecoyForACompromisedDefaultAnchorIsRefused() {
  for (var w = 0; w < 2; w += 1) {
    var which = w === 0 ? "control" : "compromised";
    var chain = anchors.decoyChain(which);
    var srv = await _startKe(chain);
    var outcome = await anchors.withDefaultAnchor(chain.anchor, async function () {
      try {
        var ke = await nts.performKeHandshake({ host: "127.0.0.1", port: srv.port, servername: "localhost" });
        return ke && ke.aeadId === 15 ? "completed" : "no-result";
      } catch (e) { return (e.code || "no-code") + ": " + e.message; }
    });
    srv.server.close();
    if (which === "control") {
      check("nts default-store anchor control: the handshake completes through an ordinary anchor",
            outcome === "completed" && srv.requests === 1, outcome + " requests=" + srv.requests);
    } else {
      check("nts default-store anchor: an anchor whose private key is 1 is not trusted, so a server that sends a " +
            "decoy for it fails certificate verification with nts/ke-socket and no request is sent",
            outcome.indexOf("nts/ke-socket: ") === 0 && /certificate/i.test(outcome) && srv.requests === 0,
            outcome + " requests=" + srv.requests);
    }
  }
}

async function run() {
  await testConfigRefusesCompromisedCa();
  testConfigReadsEveryCertificateLabel();
  testConfigAcceptsACaWithoutACertificate();
  await testHandshakeRefusesCompromisedChain();
  await testDecoyForACompromisedDefaultAnchorIsRefused();
}

module.exports = {
  run:                                  run,
  testConfigRefusesCompromisedCa:       testConfigRefusesCompromisedCa,
  testConfigReadsEveryCertificateLabel: testConfigReadsEveryCertificateLabel,
  testConfigAcceptsACaWithoutACertificate: testConfigAcceptsACaWithoutACertificate,
  testHandshakeRefusesCompromisedChain: testHandshakeRefusesCompromisedChain,
  testDecoyForACompromisedDefaultAnchorIsRefused: testDecoyForACompromisedDefaultAnchorIsRefused,
};

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); process.exit(0); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
