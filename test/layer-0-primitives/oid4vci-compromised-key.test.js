// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.auth.oid4vci refuses to bind a credential to a compromised holder key: a
 * key anyone can hold the private half of. The compromised key is the P-256
 * key whose private scalar is 1; the controls are P-256 keys derived from
 * labels, and every refusal is paired with the same proof under a control key.
 *
 * Each route a proof JWT names its key through is driven: an inline `jwk`, a
 * `kid` that resolveKid answers with a JWK or a KeyObject, an `x5c` whose
 * leaf carries the compromised key, and an `x5c` whose leaf key is ordinary
 * but whose issuing CA key is compromised.
 */

var helpers    = require("../helpers");
var b          = helpers.b;
var check      = helpers.check;
var nodeCrypto = require("node:crypto");
var ck         = require("../helpers/compromised-keys");

var BAD    = ck.ecKeyPair("prime256v1", 1n);
var GOOD   = ck.ecKeyPair("prime256v1", ck.labelScalar("prime256v1", "blamejs oid4vci compromised-key control"));
var CONTROL_CA = ck.ecKeyPair("prime256v1", BigInt("0x" +
  nodeCrypto.createHash("sha256").update("blamejs passkey attestation fixture CA", "utf8").digest("hex")));
var ATTESTATION_LEAF_KEY = ck.p256AttestationLeafKey();

var P256_GENERATOR_X = "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY";
var ISSUER_URL = "https://issuer.example.com";

function _b64uJson(o) { return Buffer.from(JSON.stringify(o), "utf8").toString("base64url"); }

function _proof(privateKey, headerKey, nonce) {
  var header = Object.assign({ typ: "openid4vci-proof+jwt", alg: "ES256" }, headerKey);
  var input = _b64uJson(header) + "." +
    _b64uJson({ aud: ISSUER_URL, nonce: nonce, iat: Math.floor(Date.now() / 1000) });
  var sig = nodeCrypto.sign("sha256", Buffer.from(input, "ascii"), { key: privateKey, dsaEncoding: "ieee-p1363" });
  return input + "." + sig.toString("base64url");
}

function _issuer(extra) {
  var signing = ck.ecKeyPair("prime256v1", ck.labelScalar("prime256v1", "blamejs oid4vci compromised-key issuer"));
  return b.auth.oid4vci.issuer.create(Object.assign({
    credentialIssuerUrl: ISSUER_URL,
    credentialEndpoint:  ISSUER_URL + "/credential",
    tokenEndpoint:       ISSUER_URL + "/token",
    sdJwtIssuer: b.auth.sdJwtVc.issuer.create({ issuerUrl: ISSUER_URL,
      keys: [{ kid: "k1", privateKey: signing.privateKey, algorithm: "ES256" }] }),
    supportedCredentials: { "id-card-1": { format: "vc+sd-jwt", vct: "https://example.com/vct/id",
      claims: { given_name: {} } } },
  }, extra || {}));
}

async function _issueWith(issuer, makeProof) {
  var offer = await issuer.createCredentialOffer({ subject: "user-1", credentialIds: ["id-card-1"] });
  var tokens = await issuer.exchangePreAuthorizedCode({ preAuthCode: offer.preAuthCode });
  try {
    await issuer.issueCredential({ accessToken: tokens.access_token, credentialIdentifier: "id-card-1",
      proof: makeProof(tokens.c_nonce), claims: { given_name: "Alice" } });
    return "NO-THROW";
  } catch (e) { return e.code || e.message; }
}

function testFixturesCarryTheKeysTheyClaim() {
  check("oid4vci compromised key: the fixture public key is the P-256 generator",
        BAD.publicKey.export({ format: "jwk" }).x === P256_GENERATOR_X);
  check("oid4vci compromised key control: the control public key is not the generator",
        GOOD.publicKey.export({ format: "jwk" }).x !== P256_GENERATOR_X);
  check("oid4vci compromised key: the compromised CA certificate carries the generator",
        new nodeCrypto.X509Certificate(ck.P256_COMPROMISED_CA_DER).publicKey.export({ format: "jwk" }).x ===
          P256_GENERATOR_X);
  check("oid4vci compromised key control: the control CA certificate carries the derived control CA key",
        new nodeCrypto.X509Certificate(ck.P256_CONTROL_CA_DER).publicKey.export({ format: "jwk" }).x ===
          CONTROL_CA.publicKey.export({ format: "jwk" }).x);
}

async function testInlineJwkIsRefused() {
  var issuer = _issuer();
  check("oid4vci compromised key control: a proof with the control inline jwk is accepted",
        (await _issueWith(issuer, function (n) {
          return _proof(GOOD.privateKey, { jwk: GOOD.publicKey.export({ format: "jwk" }) }, n);
        })) === "NO-THROW");
  check("oid4vci compromised key: a proof with a compromised inline jwk is refused",
        (await _issueWith(issuer, function (n) {
          return _proof(BAD.privateKey, { jwk: BAD.publicKey.export({ format: "jwk" }) }, n);
        })) === "auth-oid4vci/compromised-key");
}

async function testResolvedKidIsRefused() {
  var forms = [
    ["JWK",       function (kp) { return kp.publicKey.export({ format: "jwk" }); }],
    ["KeyObject", function (kp) { return kp.publicKey; }],
  ];
  for (var i = 0; i < forms.length; i += 1) {
    var f = forms[i];
    var resolved = { good: f[1](GOOD), bad: f[1](BAD) };
    var issuer = _issuer({ resolveKid: async function (kid) { return resolved[kid]; } });
    check("oid4vci compromised key control: resolveKid returning the control " + f[0] + " is accepted",
          (await _issueWith(issuer, function (n) { return _proof(GOOD.privateKey, { kid: "good" }, n); })) ===
            "NO-THROW");
    check("oid4vci compromised key: resolveKid returning a compromised " + f[0] + " is refused",
          (await _issueWith(issuer, function (n) { return _proof(BAD.privateKey, { kid: "bad" }, n); })) ===
            "auth-oid4vci/compromised-key");
  }
}

async function testX5cIsRefused() {
  var issuer = _issuer();
  function x5c(ders) { return ders.map(function (d) { return d.toString("base64"); }); }
  check("oid4vci compromised key control: an x5c leaf carrying the control key is accepted",
        (await _issueWith(issuer, function (n) {
          return _proof(CONTROL_CA.privateKey, { x5c: x5c([ck.P256_CONTROL_CA_DER]) }, n);
        })) === "NO-THROW");
  check("oid4vci compromised key: an x5c leaf carrying a compromised key is refused",
        (await _issueWith(issuer, function (n) {
          return _proof(BAD.privateKey, { x5c: x5c([ck.P256_COMPROMISED_CA_DER]) }, n);
        })) === "auth-oid4vci/compromised-key");
  check("oid4vci compromised key control: an x5c chain under the control CA is accepted",
        (await _issueWith(issuer, function (n) {
          return _proof(ATTESTATION_LEAF_KEY, { x5c: x5c([ck.P256_CONTROL_LEAF_DER, ck.P256_CONTROL_CA_DER]) }, n);
        })) === "NO-THROW");
  check("oid4vci compromised key: an x5c chain whose CA key is compromised is refused",
        (await _issueWith(issuer, function (n) {
          return _proof(ATTESTATION_LEAF_KEY, { x5c: x5c([ck.P256_COMPROMISED_LEAF_DER, ck.P256_COMPROMISED_CA_DER]) }, n);
        })) === "auth-oid4vci/compromised-key");
}

// The certificate with its id-ecPublicKey OID replaced: it still parses, but
// node cannot load its key.
function _unloadableKeyCert(der) {
  var out = Buffer.from(der);
  var oid = Buffer.from("2a8648ce3d0201", "hex");
  Buffer.from("2a030405060708", "hex").copy(out, out.indexOf(oid));
  return out;
}

async function testX5cWithUnloadableKeyIsAnAuthError() {
  function x5c(ders) { return ders.map(function (d) { return d.toString("base64"); }); }
  var badCa = _unloadableKeyCert(ck.P256_CONTROL_CA_DER);
  var badLeaf = _unloadableKeyCert(ck.P256_CONTROL_LEAF_DER);
  var keyLoads = true;
  try { new nodeCrypto.X509Certificate(badCa).publicKey.export({ format: "jwk" }); } catch (_e) { keyLoads = false; }
  check("oid4vci x5c: the modified CA certificate still parses and its key does not load",
        new nodeCrypto.X509Certificate(badCa).subject.length > 0 && keyLoads === false);

  var issuer = _issuer();
  var leafErr = null;
  var offer = await issuer.createCredentialOffer({ subject: "user-1", credentialIds: ["id-card-1"] });
  var tokens = await issuer.exchangePreAuthorizedCode({ preAuthCode: offer.preAuthCode });
  try {
    await issuer.issueCredential({ accessToken: tokens.access_token, credentialIdentifier: "id-card-1",
      proof: _proof(ATTESTATION_LEAF_KEY, { x5c: x5c([badLeaf, ck.P256_CONTROL_CA_DER]) }, tokens.c_nonce),
      claims: { given_name: "Alice" } });
  } catch (e) { leafErr = e; }
  check("oid4vci x5c: a leaf certificate whose key node cannot load is refused with auth-oid4vci/bad-x5c",
        leafErr !== null && leafErr.name === "AuthError" && leafErr.code === "auth-oid4vci/bad-x5c",
        leafErr && (leafErr.name + " " + leafErr.code));

  var seen = null;
  var withPolicy = _issuer({ validateX5c: async function (ders) { seen = ders.length; } });
  check("oid4vci x5c: a CA certificate whose key node cannot load is passed to validateX5c",
        (await _issueWith(withPolicy, function (n) {
          return _proof(ATTESTATION_LEAF_KEY, { x5c: x5c([ck.P256_CONTROL_LEAF_DER, badCa]) }, n);
        })) === "NO-THROW" && seen === 2, seen);
}

async function run() {
  testFixturesCarryTheKeysTheyClaim();
  await testInlineJwkIsRefused();
  await testResolvedKidIsRefused();
  await testX5cIsRefused();
  await testX5cWithUnloadableKeyIsAnAuthError();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
