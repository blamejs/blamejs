// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.contentCredentials.verifyIdentityAssertion reports `verified:true` for an
 * x509 identity only when the certificate chain vouches for the claim: the
 * leaf certificate carries the key that signed the assertion, and every
 * claimed subject field is an attribute of the leaf certificate's subject.
 * Each refusal is paired with a control that differs only in the signing key
 * or in the claimed subject.
 */

var helpers    = require("../helpers");
var b          = helpers.b;
var check      = helpers.check;
var nodeCrypto = require("node:crypto");
var ck         = require("../helpers/compromised-keys");

var ASSERTIONS = [{ label: "c2pa.actions", data: { action: "c2pa.created" } }];
var LEAF_KEY   = ck.p256AttestationLeafKey();
var OTHER_KEY  = ck.ecKeyPair("prime256v1", ck.labelScalar("prime256v1", "blamejs identity binding unrelated signer")).privateKey;

function _verify(signingKey, subject) {
  var ia = b.contentCredentials.attachIdentityAssertion({
    binding: "x509", subject: subject, referencedAssertions: ASSERTIONS,
    privateKeyPem: signingKey.export({ type: "pkcs8", format: "pem" }), audit: false,
  });
  var pub = nodeCrypto.createPublicKey(signingKey).export({ type: "spki", format: "pem" });
  return b.contentCredentials.verifyIdentityAssertion(ia, pub, {
    referencedAssertions: ASSERTIONS, audit: false,
    identityCertChainPem: ck.certPem(ck.P256_CONTROL_LEAF_DER),
    identityTrustAnchorsPem: ck.certPem(ck.P256_CONTROL_CA_DER),
  });
}

function _summary(res) {
  return JSON.stringify({ valid: res.valid, verified: res.verified, reason: res.reason });
}

function testTheClaimKeyMustBeTheLeafKey() {
  var good = _verify(LEAF_KEY, { name: "Test Authenticator" });
  check("identity binding control: an assertion signed by the leaf certificate's key is verified",
        good.valid === true && good.verified === true && good.reason === "x509-chain-verified", _summary(good));
  var bad = _verify(OTHER_KEY, { name: "Test Authenticator" });
  check("identity binding: an assertion signed by a key the leaf certificate does not carry is not verified",
        bad.valid === true && bad.verified === false && bad.reason === "leaf-key-mismatch", _summary(bad));
}

function testTheClaimedSubjectMustBeCertified() {
  var good = _verify(LEAF_KEY, { name: "Test Authenticator", org: "Test", orgUnit: "Authenticator Attestation",
    country: "US" });
  check("identity binding control: a subject the leaf certificate certifies field by field is verified",
        good.verified === true && good.reason === "x509-chain-verified", _summary(good));
  var forged = _verify(LEAF_KEY, { name: "Forged Newsroom" });
  check("identity binding: a name the leaf certificate does not carry is not verified",
        forged.valid === true && forged.verified === false && forged.reason === "subject-not-certified", _summary(forged));
  var wrongOrg = _verify(LEAF_KEY, { name: "Test Authenticator", org: "Acme Media" });
  check("identity binding: an organization the leaf certificate does not carry is not verified",
        wrongOrg.verified === false && wrongOrg.reason === "subject-not-certified", _summary(wrongOrg));
  var uncertified = _verify(LEAF_KEY, { name: "Test Authenticator", id: "acme-001" });
  check("identity binding: a field the leaf certificate has no attribute for is not verified",
        uncertified.verified === false && uncertified.reason === "subject-not-certified", _summary(uncertified));
  var crossField = _verify(LEAF_KEY, { name: "US" });
  check("identity binding: a value certified under a different attribute is not verified",
        crossField.verified === false && crossField.reason === "subject-not-certified", _summary(crossField));
  var nonString = _verify(LEAF_KEY, { name: ["Test Authenticator"] });
  check("identity binding: a subject field that is not a string is not verified",
        nonString.verified === false && nonString.reason === "subject-not-certified", _summary(nonString));
}

async function run() {
  testTheClaimKeyMustBeTheLeafKey();
  testTheClaimedSubjectMustBeCertified();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
