// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.a2a refuses a compromised key: signCard throws a2a/compromised-key for a
 * signing key anyone can hold, and verifyCard returns { valid: false, reason:
 * "compromised-key" } for a card signed by one. Every refusal is paired with
 * a control key that differs only in its private scalar. A key PEM followed or
 * preceded by an ordinary certificate PEM is judged by its key, and a public
 * key given as a Buffer PEM or a { key: pem } object verifies as a string does.
 */

var helpers    = require("../helpers");
var b          = helpers.b;
var check      = helpers.check;
var nodeCrypto = require("node:crypto");
var ck         = require("../helpers/compromised-keys");

var CURVES = ["prime256v1", "secp384r1"];

function _pems(pair) {
  return {
    priv: pair.privateKey.export({ type: "pkcs8", format: "pem" }),
    pub:  pair.publicKey.export({ type: "spki", format: "pem" }),
  };
}
function _code(fn) {
  try { fn(); return "NO-THROW"; } catch (e) { return e.code || e.message; }
}
function _card() {
  return b.a2a.createCard({
    issuer: "agent.example.com", agentId: "ops-bot-1", version: "1.0.0",
    capabilities: ["admin.everything"],
  });
}

// The envelope signCard produces, signed directly with node:crypto so a test
// can hold a card signed by a key signCard refuses.
function _envelopeSignedBy(card, privateKey) {
  var signedAt = Date.now();
  var expiresAt = signedAt + 60000;
  var canonical = b.a2a.canonicalize({ card: card, signedAt: signedAt, expiresAt: expiresAt });
  return {
    card: card, signedAt: signedAt, expiresAt: expiresAt,
    signature: nodeCrypto.sign(null, Buffer.from(canonical, "utf8"), privateKey).toString("base64"),
  };
}

function testSignCardRefusesCompromisedKey() {
  CURVES.forEach(function (curve) {
    var control = _pems(ck.ecKeyPair(curve, ck.labelScalar(curve, "a2a control")));
    var env = b.a2a.signCard(_card(), control.priv, { audit: false });
    check("a2a compromised key control: signCard signs with a " + curve + " control key",
          typeof env.signature === "string" && env.signature.length > 0);
    var bad = _pems(ck.ecKeyPair(curve, 1n));
    check("a2a compromised key: signCard refuses a " + curve + " key whose private scalar is 1",
          _code(function () { b.a2a.signCard(_card(), bad.priv, { audit: false }); }) === "a2a/compromised-key");
  });
}

function testVerifyCardRefusesCompromisedKey() {
  CURVES.forEach(function (curve) {
    var controlPair = ck.ecKeyPair(curve, ck.labelScalar(curve, "a2a control"));
    var control = _pems(controlPair);
    var good = b.a2a.verifyCard(_envelopeSignedBy(_card(), controlPair.privateKey), control.pub,
      { expectedIssuer: "agent.example.com", audit: false });
    check("a2a compromised key control: verifyCard accepts a card signed by a " + curve + " control key",
          good.valid === true && good.reason === null);

    var badPair = ck.ecKeyPair(curve, 1n);
    var bad = _pems(badPair);
    var r = b.a2a.verifyCard(_envelopeSignedBy(_card(), badPair.privateKey), bad.pub,
      { expectedIssuer: "agent.example.com", audit: false });
    check("a2a compromised key: verifyCard refuses a card signed by a " + curve + " key whose scalar is 1",
          r.valid === false && r.claims === null);
    check("a2a compromised key: the " + curve + " refusal reason names the compromised key",
          r.reason === "compromised-key");
  });
}

// A key PEM and an ordinary certificate PEM in one string, in either order.
// node:crypto signs and verifies with the key block, so the key decides.
var ORDINARY_CERT_PEM = ck.certPem(ck.P256_CONTROL_CA_DER);
function _withCertificate(keyPem, order) {
  return order === "key-first" ? keyPem + ORDINARY_CERT_PEM : ORDINARY_CERT_PEM + keyPem;
}

function testMixedKeyAndCertificatePem() {
  ["key-first", "certificate-first"].forEach(function (order) {
    var controlPair = ck.ecKeyPair("prime256v1", ck.labelScalar("prime256v1", "a2a control"));
    var control = _pems(controlPair);
    var badPair = ck.ecKeyPair("prime256v1", 1n);
    var bad = _pems(badPair);

    var signed = b.a2a.signCard(_card(), _withCertificate(control.priv, order), { audit: false });
    check("a2a mixed PEM control (" + order + "): signCard signs with a control key and an ordinary certificate",
          typeof signed.signature === "string" && signed.signature.length > 0);
    check("a2a mixed PEM (" + order + "): signCard refuses a scalar-1 key followed by an ordinary certificate",
          _code(function () { b.a2a.signCard(_card(), _withCertificate(bad.priv, order), { audit: false }); }) ===
            "a2a/compromised-key");

    var good = b.a2a.verifyCard(_envelopeSignedBy(_card(), controlPair.privateKey),
      _withCertificate(control.pub, order), { audit: false });
    check("a2a mixed PEM control (" + order + "): verifyCard accepts a control key with an ordinary certificate",
          good.valid === true && good.reason === null);
    var r = b.a2a.verifyCard(_envelopeSignedBy(_card(), badPair.privateKey),
      _withCertificate(bad.pub, order), { audit: false });
    check("a2a mixed PEM (" + order + "): verifyCard refuses a scalar-1 key with an ordinary certificate",
          r.valid === false && r.reason === "compromised-key");
  });
}

function testVerifyCardKeyInputForms() {
  var controlPair = ck.ecKeyPair("prime256v1", ck.labelScalar("prime256v1", "a2a control"));
  var control = _pems(controlPair);
  var badPair = ck.ecKeyPair("prime256v1", 1n);
  var bad = _pems(badPair);
  var forms = {
    "Buffer PEM":   function (pem) { return Buffer.from(pem, "utf8"); },
    "{ key: pem }": function (pem) { return { key: pem }; },
  };
  Object.keys(forms).forEach(function (label) {
    var good;
    try {
      good = b.a2a.verifyCard(_envelopeSignedBy(_card(), controlPair.privateKey), forms[label](control.pub),
        { audit: false });
    } catch (e) { good = { valid: "THREW " + (e.code || e.message) }; }
    check("a2a key input: verifyCard accepts a valid card when the public key is a " + label,
          good.valid === true && good.reason === null);
    var r;
    try {
      r = b.a2a.verifyCard(_envelopeSignedBy(_card(), badPair.privateKey), forms[label](bad.pub), { audit: false });
    } catch (e) { r = { valid: "THREW " + (e.code || e.message) }; }
    check("a2a key input: verifyCard refuses a scalar-1 key given as a " + label,
          r.valid === false && r.reason === "compromised-key");

    var badPriv = bad.priv;
    check("a2a key input: signCard takes a PEM string only, so a scalar-1 key given as a " + label +
          " throws a2a/bad-key and signs nothing",
          _code(function () { b.a2a.signCard(_card(), forms[label](badPriv), { audit: false }); }) === "a2a/bad-key");
  });
}

// A key PEM followed by a certificate block that cannot be read: node:crypto
// verifies with the key, and the compromised-key lookup on the failure path
// cannot read the text. verifyCard still returns a reason instead of throwing.
var UNREADABLE_TAILS = {
  "an empty TRUSTED CERTIFICATE block":
    "-----BEGIN TRUSTED CERTIFICATE-----\n\n-----END TRUSTED CERTIFICATE-----\n",
  "a one-byte TRUSTED CERTIFICATE block":
    "-----BEGIN TRUSTED CERTIFICATE-----\n/w==\n-----END TRUSTED CERTIFICATE-----\n",
};

function testVerifyCardNeverThrowsOnUnreadableTail() {
  var signer = nodeCrypto.generateKeyPairSync("ed25519");
  var stranger = nodeCrypto.generateKeyPairSync("ed25519");
  var pub = signer.publicKey.export({ type: "spki", format: "pem" });
  Object.keys(UNREADABLE_TAILS).forEach(function (label) {
    var key = pub + UNREADABLE_TAILS[label];
    var good;
    try { good = b.a2a.verifyCard(_envelopeSignedBy(_card(), signer.privateKey), key, { audit: false }); }
    catch (e) { good = { valid: "THREW " + (e.code || e.message) }; }
    check("a2a never throws control: verifyCard accepts a valid card under a key with " + label,
          good.valid === true && good.reason === null);
    var r;
    try { r = b.a2a.verifyCard(_envelopeSignedBy(_card(), stranger.privateKey), key, { audit: false }); }
    catch (e) { r = { valid: "THREW " + (e.code || e.message) }; }
    check("a2a never throws: verifyCard returns signature-mismatch for a wrong signer under a key with " + label,
          r.valid === false && r.reason === "signature-mismatch");
  });
}

async function run() {
  testSignCardRefusesCompromisedKey();
  testVerifyCardRefusesCompromisedKey();
  testMixedKeyAndCertificatePem();
  testVerifyCardKeyInputForms();
  testVerifyCardNeverThrowsOnUnreadableTail();
}

module.exports = {
  run:                                  run,
  testSignCardRefusesCompromisedKey:    testSignCardRefusesCompromisedKey,
  testVerifyCardRefusesCompromisedKey:  testVerifyCardRefusesCompromisedKey,
  testMixedKeyAndCertificatePem:        testMixedKeyAndCertificatePem,
  testVerifyCardKeyInputForms:          testVerifyCardKeyInputForms,
  testVerifyCardNeverThrowsOnUnreadableTail: testVerifyCardNeverThrowsOnUnreadableTail,
};

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
