// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.ai.modelManifest and b.compliance.aiAct.gpai refuse a compromised key:
 * sign / declareAdherence throw for a signing key anyone can hold, and
 * verify / verifyAdherence return { valid: false, reason: "compromised-key" }
 * for an envelope signed by one. Every refusal is paired with a control key
 * that differs only in its private scalar. A key PEM preceded or followed by
 * an ordinary certificate PEM is judged by its key, a key given as a Buffer
 * PEM or a { key: pem } object is refused by the PEM-string type check, and
 * verify / verifyAdherence return a reason instead of throwing.
 */

var helpers    = require("../helpers");
var b          = helpers.b;
var check      = helpers.check;
var nodeCrypto = require("node:crypto");
var canonical  = require("../../lib/canonical-json");
var ck         = require("../helpers/compromised-keys");

var CURVES = ["prime256v1", "secp384r1"];
var ARTICLES = ["Art. 53(1)(a)", "Art. 53(1)(b)", "Art. 53(1)(c)", "Art. 53(1)(d)"];

function _pems(pair) {
  return {
    priv: pair.privateKey.export({ type: "pkcs8", format: "pem" }),
    pub:  pair.publicKey.export({ type: "spki", format: "pem" }),
  };
}
function _code(fn) {
  try { fn(); return "NO-THROW"; } catch (e) { return e.code || e.message; }
}
function _bom() {
  return b.ai.modelManifest.build({ model: { name: "acme-classifier", version: "1.2.3" } });
}
function _declareOpts(privateKeyPem) {
  return {
    modelId: "acme-llm-7b", modelVersion: "1.0", privateKeyPem: privateKeyPem, audit: false,
    commitments: ARTICLES.map(function (a) {
      return { article: a, statement: "maintained", evidenceHash: b.crypto.sha3Hash("evidence " + a) };
    }),
  };
}

// The envelope b.ai.modelManifest.sign produces, signed directly with
// node:crypto so a test can hold an envelope signed by a key sign refuses.
function _envelopeSignedBy(bom, privateKey) {
  var bytes = Buffer.from(canonical.stringify(bom), "utf8");
  return { bom: bom, signature: nodeCrypto.sign(null, bytes, privateKey).toString("base64") };
}

function _curveKeys(curve) {
  var controlPair = ck.ecKeyPair(curve, ck.labelScalar(curve, "aibom control"));
  var badPair = ck.ecKeyPair(curve, 1n);
  return { controlPair: controlPair, control: _pems(controlPair), badPair: badPair, bad: _pems(badPair) };
}

function testSignRefusesCompromisedKey() {
  CURVES.forEach(function (curve) {
    var k = _curveKeys(curve);
    check("aibom compromised key control: modelManifest.sign signs with a " + curve + " control key",
          typeof b.ai.modelManifest.sign(_bom(), { privateKeyPem: k.control.priv, audit: false }).signature === "string");
    check("aibom compromised key: modelManifest.sign refuses a " + curve + " key whose private scalar is 1",
          _code(function () { b.ai.modelManifest.sign(_bom(), { privateKeyPem: k.bad.priv, audit: false }); }) ===
            "aibom/compromised-key");
  });
}

function testVerifyRefusesCompromisedKey() {
  CURVES.forEach(function (curve) {
    var k = _curveKeys(curve);
    var good = b.ai.modelManifest.verify(_envelopeSignedBy(_bom(), k.controlPair.privateKey), k.control.pub,
      { audit: false });
    check("aibom compromised key control: modelManifest.verify accepts a " + curve + " control signature",
          good.valid === true);
    var r = b.ai.modelManifest.verify(_envelopeSignedBy(_bom(), k.badPair.privateKey), k.bad.pub, { audit: false });
    check("aibom compromised key: modelManifest.verify refuses a " + curve + " signature by a scalar-1 key",
          r.valid === false && r.bom === null);
    check("aibom compromised key: the " + curve + " refusal reason names the compromised key",
          r.reason === "compromised-key");
  });
}

function testDeclareAdherenceRefusesCompromisedKey() {
  CURVES.forEach(function (curve) {
    var k = _curveKeys(curve);
    var env = b.compliance.aiAct.gpai.declareAdherence(_declareOpts(k.control.priv));
    check("gpai compromised key control: declareAdherence signs with a " + curve + " control key",
          typeof env.signature === "string");
    check("gpai compromised key: declareAdherence refuses a " + curve + " key whose private scalar is 1",
          _code(function () { b.compliance.aiAct.gpai.declareAdherence(_declareOpts(k.bad.priv)); }) ===
            "compliance-ai-act/compromised-key");
  });
}

function testVerifyAdherenceRefusesCompromisedKey() {
  CURVES.forEach(function (curve) {
    var k = _curveKeys(curve);
    var env = b.compliance.aiAct.gpai.declareAdherence(_declareOpts(k.control.priv));
    var good = b.compliance.aiAct.gpai.verifyAdherence(env, k.control.pub, { audit: false });
    check("gpai compromised key control: verifyAdherence accepts a " + curve + " control declaration",
          good.valid === true);
    var forged = _envelopeSignedBy(env.bom, k.badPair.privateKey);
    var r = b.compliance.aiAct.gpai.verifyAdherence(forged, k.bad.pub, { audit: false });
    check("gpai compromised key: verifyAdherence refuses a " + curve + " declaration signed by a scalar-1 key",
          r.valid === false && r.adherence === null);
    check("gpai compromised key: the " + curve + " refusal reason names the compromised key",
          r.reason === "compromised-key");
  });
}

// A key PEM and an ordinary certificate PEM in one string, in either order.
var ORDINARY_CERT_PEM = ck.certPem(ck.P256_CONTROL_CA_DER);
function _withCertificate(keyPem, order) {
  return order === "key-first" ? keyPem + ORDINARY_CERT_PEM : ORDINARY_CERT_PEM + keyPem;
}

function testMixedKeyAndCertificatePem() {
  ["key-first", "certificate-first"].forEach(function (order) {
    var k = _curveKeys("prime256v1");
    check("aibom mixed PEM control (" + order + "): modelManifest.sign signs with a control key and a certificate",
          typeof b.ai.modelManifest.sign(_bom(),
            { privateKeyPem: _withCertificate(k.control.priv, order), audit: false }).signature === "string");
    check("aibom mixed PEM (" + order + "): modelManifest.sign refuses a scalar-1 key with an ordinary certificate",
          _code(function () {
            b.ai.modelManifest.sign(_bom(), { privateKeyPem: _withCertificate(k.bad.priv, order), audit: false });
          }) === "aibom/compromised-key");

    var good = b.ai.modelManifest.verify(_envelopeSignedBy(_bom(), k.controlPair.privateKey),
      _withCertificate(k.control.pub, order), { audit: false });
    check("aibom mixed PEM control (" + order + "): modelManifest.verify accepts a control key with a certificate",
          good.valid === true);
    var r = b.ai.modelManifest.verify(_envelopeSignedBy(_bom(), k.badPair.privateKey),
      _withCertificate(k.bad.pub, order), { audit: false });
    check("aibom mixed PEM (" + order + "): modelManifest.verify refuses a scalar-1 key with an ordinary certificate",
          r.valid === false && r.reason === "compromised-key");

    check("gpai mixed PEM (" + order + "): declareAdherence refuses a scalar-1 key with an ordinary certificate",
          _code(function () {
            b.compliance.aiAct.gpai.declareAdherence(_declareOpts(_withCertificate(k.bad.priv, order)));
          }) === "compliance-ai-act/compromised-key");
    var env = b.compliance.aiAct.gpai.declareAdherence(_declareOpts(k.control.priv));
    var forged = _envelopeSignedBy(env.bom, k.badPair.privateKey);
    var ra = b.compliance.aiAct.gpai.verifyAdherence(forged, _withCertificate(k.bad.pub, order), { audit: false });
    check("gpai mixed PEM (" + order + "): verifyAdherence refuses a scalar-1 key with an ordinary certificate",
          ra.valid === false && ra.reason === "compromised-key");
  });
}

// modelManifest.sign and verify take the key as a PEM string. A Buffer PEM or
// a { key: pem } object is refused by that type check before any signing or
// verifying, so a scalar-1 key in either form is never signed with and never
// reported valid, and verify still returns a reason instead of throwing.
function testKeyInputForms() {
  var k = _curveKeys("prime256v1");
  var forms = {
    "Buffer PEM":   function (pem) { return Buffer.from(pem, "utf8"); },
    "{ key: pem }": function (pem) { return { key: pem }; },
  };
  Object.keys(forms).forEach(function (label) {
    check("aibom key input: modelManifest.sign refuses a scalar-1 key given as a " + label + " with aibom/bad-key",
          _code(function () {
            b.ai.modelManifest.sign(_bom(), { privateKeyPem: forms[label](k.bad.priv), audit: false });
          }) === "aibom/bad-key");
    check("aibom key input: modelManifest.verify returns public-key-required for a scalar-1 key given as a " + label,
          _outcome(function () {
            return b.ai.modelManifest.verify(_envelopeSignedBy(_bom(), k.badPair.privateKey), forms[label](k.bad.pub),
              { audit: false });
          }) === "false:public-key-required");
    check("aibom key input control: modelManifest.verify returns public-key-required for a control key given as a " +
          label,
          _outcome(function () {
            return b.ai.modelManifest.verify(_envelopeSignedBy(_bom(), k.controlPair.privateKey),
              forms[label](k.control.pub), { audit: false });
          }) === "false:public-key-required");
  });
}

// A public key PEM followed by a certificate block that cannot be read. Node
// verifies with the key block; b.crypto.compromisedKey cannot read the block.
var UNREADABLE_TAILS = {
  "an empty TRUSTED CERTIFICATE block":
    "-----BEGIN TRUSTED CERTIFICATE-----\n\n-----END TRUSTED CERTIFICATE-----\n",
  "a one-byte TRUSTED CERTIFICATE block":
    "-----BEGIN TRUSTED CERTIFICATE-----\n/w==\n-----END TRUSTED CERTIFICATE-----\n",
};

function _outcome(fn) {
  try { var r = fn(); return r.valid + ":" + r.reason; } catch (e) { return "THREW " + (e.code || e.message); }
}

function testVerifyNeverThrows() {
  var signer = nodeCrypto.generateKeyPairSync("ed25519");
  var stranger = nodeCrypto.generateKeyPairSync("ed25519");
  var pub = signer.publicKey.export({ type: "spki", format: "pem" });
  var privPem = signer.privateKey.export({ type: "pkcs8", format: "pem" });
  Object.keys(UNREADABLE_TAILS).forEach(function (label) {
    var key = pub + UNREADABLE_TAILS[label];
    check("aibom never throws control: modelManifest.verify accepts a valid signature under a key with " + label,
          _outcome(function () {
            return b.ai.modelManifest.verify(_envelopeSignedBy(_bom(), signer.privateKey), key, { audit: false });
          }) === "true:null");
    check("aibom never throws: modelManifest.verify returns signature-invalid for a wrong signer under a key with " +
          label,
          _outcome(function () {
            return b.ai.modelManifest.verify(_envelopeSignedBy(_bom(), stranger.privateKey), key, { audit: false });
          }) === "false:signature-invalid");
    var env = b.compliance.aiAct.gpai.declareAdherence(_declareOpts(privPem));
    check("gpai never throws: verifyAdherence returns signature-invalid for a wrong signer under a key with " + label,
          _outcome(function () {
            return b.compliance.aiAct.gpai.verifyAdherence(_envelopeSignedBy(env.bom, stranger.privateKey), key,
              { audit: false });
          }) === "false:signature-invalid");
  });

  var cyclic = _bom();
  cyclic.metadata.self = cyclic;
  check("aibom never throws: modelManifest.verify returns envelope-shape for a BOM that cannot be canonicalized",
        _outcome(function () {
          return b.ai.modelManifest.verify({ bom: cyclic, signature: "AA" }, pub, { audit: false });
        }) === "false:envelope-shape");
  check("gpai never throws: verifyAdherence returns envelope-shape for a BOM that cannot be canonicalized",
        _outcome(function () {
          return b.compliance.aiAct.gpai.verifyAdherence({ bom: cyclic, signature: "AA" }, pub, { audit: false });
        }) === "false:envelope-shape");
}

async function run() {
  testSignRefusesCompromisedKey();
  testVerifyRefusesCompromisedKey();
  testDeclareAdherenceRefusesCompromisedKey();
  testVerifyAdherenceRefusesCompromisedKey();
  testMixedKeyAndCertificatePem();
  testKeyInputForms();
  testVerifyNeverThrows();
}

module.exports = {
  run:                                         run,
  testSignRefusesCompromisedKey:               testSignRefusesCompromisedKey,
  testVerifyRefusesCompromisedKey:             testVerifyRefusesCompromisedKey,
  testDeclareAdherenceRefusesCompromisedKey:   testDeclareAdherenceRefusesCompromisedKey,
  testVerifyAdherenceRefusesCompromisedKey:    testVerifyAdherenceRefusesCompromisedKey,
  testMixedKeyAndCertificatePem:               testMixedKeyAndCertificatePem,
  testKeyInputForms:                           testKeyInputForms,
  testVerifyNeverThrows:                      testVerifyNeverThrows,
};

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
