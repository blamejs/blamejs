// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.crypto.spkiPinVerifier refuses a server whose verified chain carries a
 * compromised key even when the leaf matches a pin. Both fixture chains share
 * the leaf key, so the pin matches in both; the compromised chain's
 * intermediate has private key 1. A server that hides the compromised issuing
 * CA behind an expired alternate issuer and a self-signed decoy root is
 * refused too, because the chain it sends reaches no trust anchor of the dial.
 */

var nodeTls = require("node:tls");
var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var ck      = require("../helpers/compromised-keys");
var paths   = require("../helpers/chain-path");

function _tlsMaterial(which) {
  var chain = ck.tlsChain(which);
  return { key: chain.key, cert: chain.cert, anchor: chain.rootCa };
}

function _handshake(material, identity) {
  return new Promise(function (resolve) {
    var server = nodeTls.createServer({ key: material.key, cert: material.cert }, function (s) {
      s.on("error", function () { /* the client closed */ });
      s.end();
    });
    server.on("tlsClientError", function () { /* the client refused the chain */ });
    server.listen(0, "127.0.0.1", function () {
      var settled = false;
      function done(result) {
        if (settled) return;
        settled = true;
        server.close();
        resolve(result);
      }
      var sock = nodeTls.connect({
        host: "127.0.0.1", port: server.address().port, servername: "localhost",
        ca: [material.anchor], checkServerIdentity: identity,
      }, function () { sock.end(); done({ ok: true, code: null }); });
      sock.on("error", function (e) { done({ ok: false, code: e.code || e.message }); });
    });
  });
}

async function testPinnedLeafUnderACompromisedIntermediate() {
  var leafPin = b.crypto.spkiPin(ck.TLS_CONTROL_LEAF_DER).sha256;
  var backupPin = b.crypto.spkiPin(ck.TLS_ROOT_DER).sha256;
  check("spkiPinVerifier fixture: both chains carry the pinned leaf key",
        b.crypto.spkiPin(ck.TLS_COMPROMISED_LEAF_DER).sha256 === leafPin);
  var verify = b.crypto.spkiPinVerifier({ pins: [leafPin, backupPin], hostname: "localhost" });
  var control = await _handshake(_tlsMaterial("control"), verify);
  check("spkiPinVerifier control: a pinned leaf under an ordinary chain is accepted",
        control.ok === true, JSON.stringify(control));
  var bad = await _handshake(_tlsMaterial("compromised"), verify);
  check("spkiPinVerifier: a pinned leaf under an intermediate whose private key is 1 is refused with tls/compromised-key",
        bad.ok === false && bad.code === "tls/compromised-key", JSON.stringify(bad));
}

async function testPinnedLeafBehindADecoyRoot() {
  var leafPin = b.crypto.spkiPin(paths.PATH_LEAF_DER).sha256;
  var backupPin = b.crypto.spkiPin(ck.TLS_ROOT_DER).sha256;
  var verify = b.crypto.spkiPinVerifier({ pins: [leafPin, backupPin], hostname: "localhost" });
  var control = await _handshake(paths.evasionChain("control"), verify);
  check("spkiPinVerifier control: a pinned leaf whose chain reaches the dial's ca is accepted",
        control.ok === true, JSON.stringify(control));
  var evasion = await _handshake(paths.evasionChain("compromised-evasion"), verify);
  check("spkiPinVerifier: a chain that hides the compromised issuing CA behind a decoy root is refused",
        evasion.ok === false && evasion.code === "tls/server-chain-unverifiable", JSON.stringify(evasion));
}

var TESTS = [testPinnedLeafUnderACompromisedIntermediate, testPinnedLeafBehindADecoyRoot];

async function run() {
  for (var i = 0; i < TESTS.length; i += 1) await TESTS[i]();
}

module.exports = { run: run, TESTS: TESTS };

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
