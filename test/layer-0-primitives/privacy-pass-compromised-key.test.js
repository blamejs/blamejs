// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.privacyPass refuses a listed issuer key: the eDellRoot RSA key, whose
 * private half Dell shipped in 2015, as a KeyObject, SPKI DER or PEM in
 * verifyToken, and as buildChallenge's tokenKey. The private key is not
 * stored here, so the refused token carries a placeholder authenticator and
 * the refusal is checked by its code; the control is an RSA issuer key whose
 * token verifies.
 */

var helpers    = require("../helpers");
var b          = helpers.b;
var check      = helpers.check;
var nodeCrypto = require("node:crypto");
var ck         = require("../helpers/compromised-keys");

var LISTED = new nodeCrypto.X509Certificate(ck.EDELLROOT_CERT_PEM).publicKey;
var CONTROL = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });

function _code(fn) {
  try { fn(); return "NO-THROW"; } catch (e) { return e.code || e.message; }
}

function _token(publicKey, privateKey) {
  var spki = publicKey.export({ format: "der", type: "spki" });
  var input = Buffer.concat([Buffer.from([0x00, 0x02]), nodeCrypto.randomBytes(32), Buffer.alloc(32, 7),
    nodeCrypto.createHash("sha256").update(spki).digest()]);
  var authenticator = privateKey
    ? nodeCrypto.sign("sha384", input, { key: privateKey, padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 48 })
    : Buffer.alloc(256, 1);
  return Buffer.concat([input, authenticator]);
}

function _forms(publicKey) {
  return [["KeyObject", publicKey], ["SPKI DER", publicKey.export({ format: "der", type: "spki" })],
    ["PEM", publicKey.export({ format: "pem", type: "spki" })]];
}

function testVerifyTokenRefusesAListedIssuerKey() {
  var good = _token(CONTROL.publicKey, CONTROL.privateKey);
  _forms(CONTROL.publicKey).forEach(function (f) {
    check("privacy pass compromised key control: verifyToken accepts the control issuer key as " + f[0],
          b.privacyPass.verifyToken({ token: good, issuerPublicKey: f[1] }).ok === true);
  });
  var bad = _token(LISTED, null);
  _forms(LISTED).forEach(function (f) {
    check("privacy pass compromised key: verifyToken refuses the listed eDellRoot issuer key as " + f[0],
          _code(function () { b.privacyPass.verifyToken({ token: bad, issuerPublicKey: f[1] }); }) ===
          "privacy-pass/compromised-key");
  });
}

function testBuildChallengeRefusesAListedTokenKey() {
  check("privacy pass compromised key control: buildChallenge advertises the control token key",
        _code(function () { b.privacyPass.buildChallenge({ issuerName: "issuer.example", tokenKey: CONTROL.publicKey }); }) ===
        "NO-THROW");
  _forms(LISTED).slice(0, 2).forEach(function (f) {
    check("privacy pass compromised key: buildChallenge refuses the listed eDellRoot token key as " + f[0],
          _code(function () { b.privacyPass.buildChallenge({ issuerName: "issuer.example", tokenKey: f[1] }); }) ===
          "privacy-pass/compromised-key");
  });
}

function _p384Element(d) {
  var ecdh = nodeCrypto.createECDH("secp384r1");
  ecdh.setPrivateKey(ck.scalarBytes("secp384r1", d));
  return ecdh.getPublicKey(null, "compressed");
}

function testBuildChallengeReadsATokenKeyByItsTokenType() {
  var control = _p384Element(ck.labelScalar("secp384r1", "blamejs privacy pass voprf issuer"));
  var c = null;
  var code = _code(function () {
    c = b.privacyPass.buildChallenge({ issuerName: "issuer.example", tokenType: 0x0001, tokenKey: control });
  });
  check("privacy pass compromised key control: buildChallenge advertises a type 0x0001 compressed P-384 token key",
        code === "NO-THROW" && c.wwwAuthenticate.indexOf('token-key="' + control.toString("base64url")) !== -1, code);
  check("privacy pass compromised key: buildChallenge refuses a type 0x0001 token key whose private key is 1",
        _code(function () {
          b.privacyPass.buildChallenge({ issuerName: "issuer.example", tokenType: 0x0001, tokenKey: _p384Element(1n) });
        }) === "privacy-pass/compromised-key");
  check("privacy pass: buildChallenge refuses a type 0x0001 token key that is not a P-384 element",
        _code(function () {
          b.privacyPass.buildChallenge({ issuerName: "issuer.example", tokenType: 0x0001, tokenKey: Buffer.alloc(49, 7) });
        }) === "privacy-pass/bad-key");
  check("privacy pass: buildChallenge refuses a type 0x0001 token key whose x-coordinate is not on P-384",
        _code(function () {
          b.privacyPass.buildChallenge({ issuerName: "issuer.example", tokenType: 0x0001,
            tokenKey: Buffer.concat([Buffer.from([0x02]), Buffer.alloc(48, 0xff)]) });
        }) === "privacy-pass/bad-key");
  check("privacy pass: buildChallenge refuses a type 0x0002 token key that is not an SPKI",
        _code(function () {
          b.privacyPass.buildChallenge({ issuerName: "issuer.example", tokenKey: Buffer.from("not an spki") });
        }) === "privacy-pass/bad-key");
  check("privacy pass: buildChallenge passes another token type's key encoding through unchanged",
        _code(function () {
          b.privacyPass.buildChallenge({ issuerName: "issuer.example", tokenType: 0xda7a, tokenKey: Buffer.from("opaque key") });
        }) === "NO-THROW");
  check("privacy pass compromised key: buildChallenge refuses a listed SPKI under another token type",
        _code(function () {
          b.privacyPass.buildChallenge({ issuerName: "issuer.example", tokenType: 0xda7a,
            tokenKey: LISTED.export({ format: "der", type: "spki" }) });
        }) === "privacy-pass/compromised-key");
}

async function run() {
  testVerifyTokenRefusesAListedIssuerKey();
  testBuildChallengeRefusesAListedTokenKey();
  testBuildChallengeReadsATokenKeyByItsTokenType();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
