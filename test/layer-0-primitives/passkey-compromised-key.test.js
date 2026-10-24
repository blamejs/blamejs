// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.auth.passkey refuses a compromised key wherever one enters a ceremony:
 * the credential public key a registration presents, the stored credential
 * key an assertion is checked against, the attestation / SafetyNet roots the
 * operator configures, and every certificate of a `packed` or
 * `android-safetynet` attestation chain. Every refusal is paired with a
 * control that differs only in the key. The shipped attestation roots carry
 * no compromised key.
 *
 * The chain check runs before the toolkit parses the chain, so it is bounded
 * at the toolkit's own limit of ten certificates: a longer chain is refused
 * before any certificate in it is examined.
 */

var helpers    = require("../helpers");
var b          = helpers.b;
var check      = helpers.check;
var nodeCrypto = require("node:crypto");
var ck         = require("../helpers/compromised-keys");
var webauthn   = require("../helpers/webauthn");
var composite  = require("../helpers/composite-key-cert");
var asn1       = require("../../lib/asn1-der");
var bCrypto    = require("../../lib/crypto");
var pki        = require("../../lib/vendor/blamejs-pki.cjs");
var attestationRoots = require("../../lib/auth/webauthn-attestation-roots");

var COMPROMISED = ck.ecKeyPair("prime256v1", 1n);
var CONTROL     = ck.ecKeyPair("prime256v1", ck.labelScalar("prime256v1", "blamejs passkey compromised-key control"));
var CA_SCALAR   = BigInt("0x" + nodeCrypto.createHash("sha256")
  .update("blamejs passkey attestation fixture CA", "utf8").digest("hex"));
var X5C_LIMIT   = pki.constants.LIMITS.WEBAUTHN_X5C_MAX_CERTS;

function _registerArgs(reg, extra) {
  return Object.assign({
    response: reg.response, expectedChallenge: reg.challenge,
    expectedOrigin: reg.origin, expectedRPID: reg.rpId,
  }, extra || {});
}

async function _outcome(fn) {
  try { return { ok: true, rv: await fn() }; }
  catch (e) { return { ok: false, code: e.code || e.message, name: e.constructor && e.constructor.name }; }
}

function _register(opts, extra) {
  var reg = helpers.registerCredential(Object.assign({ rpId: "example.test" }, opts));
  return _outcome(function () { return b.auth.passkey.verifyRegistration(_registerArgs(reg, extra)); });
}

// Counts the compromised-key checks run on attestation chain certificates
// while fn runs. The configured roots are checked under their own label and
// are not counted.
async function _countChecks(fn) {
  var original = bCrypto.assertNotCompromised;
  var calls = 0;
  bCrypto.assertNotCompromised = function (key, opts) {
    if (opts && /certificate \[/.test(String(opts.label))) calls += 1;
    return original.apply(this, arguments);
  };
  try { return { outcome: await fn(), calls: calls }; }
  finally { bCrypto.assertNotCompromised = original; }
}

// The certificate `der` with its signature replaced by one from `privateKey`
// over the same TBSCertificate.
function _resign(der, privateKey) {
  var outer = asn1.readNode(der, 0);
  var parts = asn1.readSequence(outer.value);
  var tbs = outer.value.subarray(0, parts[0].totalLength);
  var algId = outer.value.subarray(parts[0].totalLength, parts[0].totalLength + parts[1].totalLength);
  var sig = nodeCrypto.sign("sha256", tbs, { key: privateKey, dsaEncoding: "der" });
  return asn1.writeSequence([tbs, algId, asn1.writeBitString(sig)]);
}

// An RSA leaf for attest.android.com issued by the P-256 control CA, the same
// leaf re-signed by the CA key whose private scalar is 1, and the leaf key.
async function _safetyNetLeaves() {
  var leafPair = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });         // allow:raw-byte-literal — RSA key size
  var caKey = await pki.webcrypto.subtle.importKey("jwk",
    ck.ecKeyPair("prime256v1", CA_SCALAR).privateKey.export({ format: "jwk" }),
    { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  var controlLeaf = Buffer.from(await pki.x509.sign({
    subject:          [{ commonName: "attest.android.com" }],
    subjectPublicKey: leafPair.publicKey.export({ type: "spki", format: "der" }),
    serialNumber:     "0x03",
    notBefore:        new Date(Date.now() - b.constants.TIME.days(1)),
    notAfter:         new Date(Date.now() + b.constants.TIME.days(365)),
    extensions:       { basicConstraints: { cA: false } },
  }, { cert: ck.P256_CONTROL_CA_DER, key: caKey }));
  return {
    signingKey:      leafPair.privateKey,
    controlLeaf:     controlLeaf,
    compromisedLeaf: _resign(controlLeaf, COMPROMISED.privateKey),
  };
}

async function testRegistrationRefusesACompromisedCredentialKey() {
  var control = await _register({ keyPair: CONTROL });
  check("passkey compromised key control: a registration with an ordinary credential key verifies",
        control.ok === true && control.rv.verified === true, JSON.stringify(control.code));
  var bad = await _register({ keyPair: COMPROMISED });
  check("passkey compromised key: a registration whose credential key has private key 1 is refused",
        bad.ok === false && bad.code === "auth-passkey/compromised-key", JSON.stringify(bad));
}

async function testAuthenticationRefusesACompromisedStoredKey() {
  var controlReg = helpers.registerCredential({ rpId: "example.test", keyPair: CONTROL });
  var enrolled = await b.auth.passkey.verifyRegistration(_registerArgs(controlReg));
  var storedControl = Buffer.from(enrolled.registrationInfo.credential.publicKey);
  var storedCompromised = webauthn.coseEc2PublicKey(COMPROMISED.publicKey);
  var badReg = Object.assign({}, controlReg, { keyPair: COMPROMISED });
  check("passkey compromised key: the helper's COSE key bytes are the bytes registration stores",
        webauthn.coseEc2PublicKey(CONTROL.publicKey).equals(storedControl));

  function _assert(reg, stored) {
    var a = helpers.assertCredential(reg, { signCount: 3 });
    return _outcome(function () {
      return b.auth.passkey.verifyAuthentication({
        response: a.response, expectedChallenge: a.challenge,
        expectedOrigin: reg.origin, expectedRPID: reg.rpId,
        credential: { id: enrolled.registrationInfo.credential.id, publicKey: stored, counter: 0 },
      });
    });
  }

  var control = await _assert(controlReg, storedControl);
  check("passkey compromised key control: an assertion under an ordinary stored key verifies",
        control.ok === true && control.rv.verified === true, JSON.stringify(control.code));
  var bad = await _assert(badReg, storedCompromised);
  check("passkey compromised key: an assertion under a stored key whose private key is 1 is refused",
        bad.ok === false && bad.code === "auth-passkey/compromised-key", JSON.stringify(bad));

  var jwk = COMPROMISED.publicKey.export({ format: "jwk" });
  var decoded = { kty: 2, alg: -7, crv: 1, x: Buffer.from(jwk.x, "base64url"), y: Buffer.from(jwk.y, "base64url") };
  var badObject = await _assert(badReg, decoded);
  check("passkey compromised key: a stored key passed as a decoded COSE object is refused the same way",
        badObject.ok === false && badObject.code === "auth-passkey/compromised-key", JSON.stringify(badObject));
}

async function testConfiguredRootsAreRefused() {
  var controlCa = ck.certPem(ck.P256_CONTROL_CA_DER);
  var compromisedCa = ck.certPem(ck.P256_COMPROMISED_CA_DER);
  function withRoots(field, roots) {
    var extra = {};
    extra[field] = roots;
    return _register({ keyPair: CONTROL }, extra);
  }
  var fields = ["attestationRoots", "safetyNetRoots"];
  for (var i = 0; i < fields.length; i += 1) {
    var control = await withRoots(fields[i], [controlCa]);
    check("passkey compromised key control: " + fields[i] + " with an ordinary CA is accepted",
          control.ok === true && control.rv.verified === true, JSON.stringify(control.code));
    var small = await withRoots(fields[i], [controlCa, compromisedCa]);
    check("passkey compromised key: " + fields[i] + " containing a CA whose private key is 1 is refused",
          small.ok === false && small.code === "auth-passkey/compromised-key", JSON.stringify(small));
    var listed = await withRoots(fields[i], [ck.EDELLROOT_CERT_PEM]);
    check("passkey compromised key: " + fields[i] + " containing the eDellRoot certificate is refused",
          listed.ok === false && listed.code === "auth-passkey/compromised-key", JSON.stringify(listed));
  }
}

function _packed(x5c) {
  return { fmt: "packed", x5c: x5c, signingKey: ck.p256AttestationLeafKey() };
}

async function testPackedChainScanIsBounded() {
  var full = [ck.P256_CONTROL_LEAF_DER];
  for (var i = 1; i < X5C_LIMIT; i += 1) full.push(ck.P256_CONTROL_CA_DER);
  var atLimit = await _countChecks(function () { return _register({ attestation: _packed(full) }); });
  check("passkey compromised key control: a packed chain of " + X5C_LIMIT + " certificates is scanned " +
        "certificate by certificate",
        atLimit.calls >= X5C_LIMIT, JSON.stringify({ calls: atLimit.calls, outcome: atLimit.outcome }));

  var over = full.concat([ck.P256_CONTROL_CA_DER]);
  var flood = await _countChecks(function () { return _register({ attestation: _packed(over) }); });
  check("passkey compromised key: a packed chain of " + (X5C_LIMIT + 1) + " certificates is refused " +
        "before any certificate in it is examined",
        flood.outcome.ok === false && flood.outcome.code === "auth-passkey/bad-att-stmt" && flood.calls === 0,
        JSON.stringify({ calls: flood.calls, outcome: flood.outcome }));

  var badOver = [ck.P256_COMPROMISED_LEAF_DER].concat(over.slice(1));
  var badFlood = await _countChecks(function () { return _register({ attestation: _packed(badOver) }); });
  check("passkey compromised key: an over-long chain is refused for its length whatever key it carries",
        badFlood.outcome.ok === false && badFlood.outcome.code === "auth-passkey/bad-att-stmt" &&
        badFlood.calls === 0, JSON.stringify({ calls: badFlood.calls, outcome: badFlood.outcome }));
}

async function testPackedChainRefusesACompromisedCertificate() {
  var control = await _register({ attestation: _packed([ck.P256_CONTROL_LEAF_DER, ck.P256_CONTROL_CA_DER]) });
  check("passkey compromised key control: a packed chain under an ordinary CA key verifies",
        control.ok === true && control.rv.verified === true, JSON.stringify(control.code));
  var bad = await _register({ attestation: _packed([ck.P256_COMPROMISED_LEAF_DER, ck.P256_COMPROMISED_CA_DER]) });
  check("passkey compromised key: a packed chain whose CA has private key 1 is refused",
        bad.ok === false && bad.code === "auth-passkey/compromised-key", JSON.stringify(bad));
}

async function testUnreadableChainCertificateKeepsTheVerifierCode() {
  var garbage = Buffer.from("this is not a certificate", "utf8");
  var rv = await _register({ attestation: _packed([ck.P256_CONTROL_LEAF_DER, garbage]) });
  check("passkey compromised key: an x5c entry that is not a certificate is refused as a malformed " +
        "attestation statement, as the verifier refuses it",
        rv.ok === false && rv.code === "auth-passkey/bad-att-stmt" && rv.name === "AuthError", JSON.stringify(rv));
}

async function testChainCertificateNodeCannotLoadStillVerifies() {
  check("passkey compromised key: node parses the composite-key certificate but cannot load its key",
        (function () {
          var cert = new nodeCrypto.X509Certificate(composite.COMPOSITE_CERT_DER);
          try { return cert.publicKey === null; } catch (_e) { return true; }
        })());
  var control = await _register({ attestation: _packed([ck.P256_CONTROL_LEAF_DER, ck.P256_CONTROL_CA_DER]) });
  check("passkey compromised key control: a packed chain of ordinary certificates verifies",
        control.ok === true && control.rv.verified === true, JSON.stringify(control.code));
  var rv = await _register({ attestation: _packed([ck.P256_CONTROL_LEAF_DER, composite.COMPOSITE_CERT_DER]) });
  check("passkey compromised key: a packed chain carrying a certificate whose key node cannot load " +
        "verifies as it does without the key check",
        rv.ok === true && rv.rv.verified === true, JSON.stringify(rv.ok ? rv.rv.verified : rv));
}

async function testSafetyNetChainRefusesACompromisedKey() {
  var leaves = await _safetyNetLeaves();
  var controlCa = new nodeCrypto.X509Certificate(ck.P256_CONTROL_CA_DER);
  var compromisedCa = new nodeCrypto.X509Certificate(ck.P256_COMPROMISED_CA_DER);
  check("passkey compromised key: each SafetyNet fixture leaf verifies under its own CA and not the other",
        new nodeCrypto.X509Certificate(leaves.controlLeaf).verify(controlCa.publicKey) &&
        new nodeCrypto.X509Certificate(leaves.compromisedLeaf).verify(compromisedCa.publicKey) &&
        !new nodeCrypto.X509Certificate(leaves.compromisedLeaf).verify(controlCa.publicKey));

  function safetyNet(x5c) {
    return _register({ attestation: { fmt: "android-safetynet", x5c: x5c, signingKey: leaves.signingKey } },
      { safetyNetRoots: [ck.certPem(ck.P256_CONTROL_CA_DER)] });
  }
  var control = await safetyNet([leaves.controlLeaf, ck.P256_CONTROL_CA_DER]);
  check("passkey compromised key control: a SafetyNet chain under an ordinary CA key verifies",
        control.ok === true && control.rv.verified === true &&
        control.rv.registrationInfo.fmt === "android-safetynet", JSON.stringify(control.code));
  var bad = await safetyNet([leaves.compromisedLeaf, ck.P256_COMPROMISED_CA_DER]);
  check("passkey compromised key: a SafetyNet chain whose CA has private key 1 is refused",
        bad.ok === false && bad.code === "auth-passkey/compromised-key", JSON.stringify(bad));
  var badIntermediate = await safetyNet([leaves.controlLeaf, ck.P256_COMPROMISED_CA_DER, ck.P256_CONTROL_CA_DER]);
  check("passkey compromised key: a SafetyNet chain carrying the compromised CA anywhere is refused",
        badIntermediate.ok === false && badIntermediate.code === "auth-passkey/compromised-key",
        JSON.stringify(badIntermediate));

  var garbage = await safetyNet([leaves.controlLeaf, Buffer.from("this is not a certificate", "utf8")]);
  check("passkey compromised key: a SafetyNet x5c entry that is not a certificate keeps the verifier's " +
        "code for an undecodable certificate",
        garbage.ok === false && garbage.code === "auth-passkey/bad-att-cert", JSON.stringify(garbage));

  var over = [leaves.controlLeaf];
  while (over.length <= X5C_LIMIT) over.push(ck.P256_CONTROL_CA_DER);
  var flood = await _countChecks(function () { return safetyNet(over); });
  check("passkey compromised key: a SafetyNet chain of " + over.length + " certificates is refused before " +
        "any certificate in it is examined",
        flood.outcome.ok === false && flood.outcome.code === "auth-passkey/bad-att-stmt" && flood.calls === 0,
        JSON.stringify({ calls: flood.calls, outcome: flood.outcome }));
}

function testShippedRootsAreNotCompromised() {
  check("passkey compromised key: every shipped attestation root carries an ordinary key",
        attestationRoots.ALL_ROOTS.length > 0 &&
        attestationRoots.ALL_ROOTS.every(function (pem) { return b.crypto.compromisedKey(pem) === null; }));
  check("passkey compromised key: the fixture key really is the P-256 generator",
        nodeCrypto.createPublicKey(ck.certPem(ck.P256_COMPROMISED_CA_DER))
          .export({ type: "spki", format: "der" })
          .equals(COMPROMISED.publicKey.export({ type: "spki", format: "der" })));
}

async function run() {
  await testRegistrationRefusesACompromisedCredentialKey();
  await testAuthenticationRefusesACompromisedStoredKey();
  await testConfiguredRootsAreRefused();
  await testPackedChainScanIsBounded();
  await testPackedChainRefusesACompromisedCertificate();
  await testUnreadableChainCertificateKeepsTheVerifierCode();
  await testChainCertificateNodeCannotLoadStillVerifies();
  await testSafetyNetChainRefusesACompromisedKey();
  testShippedRootsAreNotCompromised();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
