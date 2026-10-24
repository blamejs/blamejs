// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.auth.sdJwtVc and b.auth.oid4vp refuse a compromised key: a key anyone can
 * hold the private half of. The compromised key is the P-256 key whose
 * private scalar is 1; the controls are P-256 keys derived from labels, and
 * every refusal is paired with the same input under a control key.
 *
 * Configuration: issuer.create, rotateKey and holder.create refuse a
 * compromised key when it is configured. Signing: issue() refuses a
 * compromised issuer key and refuses to bind a compromised holder key in
 * `cnf`, and present() refuses to sign a key-binding JWT with a compromised
 * holder key. Verification: a credential under a compromised issuer key (as a
 * JWK, a PEM or a KeyObject from issuerKeyResolver) and a key-binding JWT
 * under a compromised `cnf` key are refused, directly and through the OID4VP
 * verifier. A credential whose `cnf` key is compromised is refused even when
 * no key-binding JWT is presented.
 */

var helpers    = require("../helpers");
var b          = helpers.b;
var check      = helpers.check;
var nodeCrypto = require("node:crypto");
var ck         = require("../helpers/compromised-keys");

var BAD    = ck.ecKeyPair("prime256v1", 1n);
var ISSUER = ck.ecKeyPair("prime256v1", ck.labelScalar("prime256v1", "blamejs sd-jwt-vc compromised-key issuer"));
var HOLDER = ck.ecKeyPair("prime256v1", ck.labelScalar("prime256v1", "blamejs sd-jwt-vc compromised-key holder"));

var P256_GENERATOR_X = "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY";
var ISS = "https://issuer.example";
var VCT = "urn:eu.europa.ec.eudi:pid:1";
var VERIFIER = "https://verifier.example";

function _jwk(kp) { return kp.publicKey.export({ format: "jwk" }); }
function _b64uJson(o) { return Buffer.from(JSON.stringify(o), "utf8").toString("base64url"); }

function _es256(header, payload, privateKey) {
  var input = _b64uJson(header) + "." + _b64uJson(payload);
  var sig = nodeCrypto.sign("sha256", Buffer.from(input, "ascii"), { key: privateKey, dsaEncoding: "ieee-p1363" });
  return input + "." + sig.toString("base64url");
}

function _credential(issuerKp, holderKp) {
  var now = Math.floor(Date.now() / 1000);
  var payload = { iss: ISS, iat: now, exp: now + 3600, vct: VCT, _sd: [], _sd_alg: "sha-256", age_over_18: true };
  if (holderKp) payload.cnf = { jwk: _jwk(holderKp) };
  return _es256({ alg: "ES256", typ: "vc+sd-jwt" }, payload, issuerKp.privateKey) + "~";
}

function _presentation(issuerKp, holderKp, nonce) {
  var sdJwt = _credential(issuerKp, holderKp);
  var sdHash = nodeCrypto.createHash("sha256").update(sdJwt, "ascii").digest().toString("base64url");
  return sdJwt + _es256({ alg: "ES256", typ: "kb+jwt" },
    { nonce: nonce, aud: VERIFIER, iat: Math.floor(Date.now() / 1000), sd_hash: sdHash }, holderKp.privateKey);
}

async function _code(fn) {
  try { await fn(); return "NO-THROW"; } catch (e) { return e.code || e.message; }
}

function _syncCode(fn) {
  try { fn(); return "NO-THROW"; } catch (e) { return e.code || e.message; }
}

function testFixtureIsTheScalarOneKey() {
  check("sd-jwt-vc compromised key: the fixture public key is the P-256 generator",
        BAD.publicKey.export({ format: "jwk" }).x === P256_GENERATOR_X);
  check("sd-jwt-vc compromised key control: the control public keys are not the generator",
        ISSUER.publicKey.export({ format: "jwk" }).x !== P256_GENERATOR_X &&
        HOLDER.publicKey.export({ format: "jwk" }).x !== P256_GENERATOR_X);
}

function testConfiguredKeysAreRefused() {
  function issuerWith(kp) {
    return function () {
      b.auth.sdJwtVc.issuer.create({ issuerUrl: ISS, keys: [{ kid: "k1", privateKey: kp.privateKey, algorithm: "ES256" }] });
    };
  }
  check("sd-jwt-vc compromised key control: issuer.create accepts the control key",
        _syncCode(issuerWith(ISSUER)) === "NO-THROW");
  check("sd-jwt-vc compromised key: issuer.create refuses a compromised signing key",
        _syncCode(issuerWith(BAD)) === "auth-sd-jwt-vc/compromised-key");

  var issuer = b.auth.sdJwtVc.issuer.create({
    issuerUrl: ISS, keys: [{ kid: "k1", privateKey: ISSUER.privateKey, algorithm: "ES256" }] });
  check("sd-jwt-vc compromised key control: rotateKey accepts the control key",
        _syncCode(function () { issuer.rotateKey({ kid: "k2", privateKey: HOLDER.privateKey, algorithm: "ES256" }); }) ===
          "NO-THROW");
  check("sd-jwt-vc compromised key: rotateKey refuses a compromised signing key",
        _syncCode(function () { issuer.rotateKey({ kid: "k3", privateKey: BAD.privateKey, algorithm: "ES256" }); }) ===
          "auth-sd-jwt-vc/compromised-key");
  check("sd-jwt-vc compromised key: the refused rotation leaves the previous key active",
        issuer.stats().activeKid === "k2");

  function holderWith(kp) {
    return function () {
      b.auth.sdJwtVc.holder.create({ storage: b.auth.sdJwtVc.holder.memoryStorage(), holderKey: kp.privateKey });
    };
  }
  check("sd-jwt-vc compromised key control: holder.create accepts the control key",
        _syncCode(holderWith(HOLDER)) === "NO-THROW");
  check("sd-jwt-vc compromised key: holder.create refuses a compromised holder key",
        _syncCode(holderWith(BAD)) === "auth-sd-jwt-vc/compromised-key");
}

function testSigningWithCompromisedKeysIsRefused() {
  function issueWith(issuerKp, holderKp) {
    return function () {
      b.auth.sdJwtVc.issue({ issuer: ISS, vct: VCT, claims: { age_over_18: true },
        issuerKey: issuerKp.privateKey, algorithm: "ES256", holderKey: _jwk(holderKp) });
    };
  }
  check("sd-jwt-vc compromised key control: issue signs with control keys",
        _syncCode(issueWith(ISSUER, HOLDER)) === "NO-THROW");
  check("sd-jwt-vc compromised key: issue refuses a compromised issuer key",
        _syncCode(issueWith(BAD, HOLDER)) === "auth-sd-jwt-vc/compromised-key");
  check("sd-jwt-vc compromised key: issue refuses to bind a compromised holder key in cnf",
        _syncCode(issueWith(ISSUER, BAD)) === "auth-sd-jwt-vc/compromised-key");

  var sdJwt = _credential(ISSUER, HOLDER);
  function presentWith(kp) {
    return function () {
      b.auth.sdJwtVc.present({ sdJwt: sdJwt, audience: VERIFIER, nonce: "n-1", holderKey: kp.privateKey, algorithm: "ES256" });
    };
  }
  check("sd-jwt-vc compromised key control: present signs a key-binding JWT with the control key",
        _syncCode(presentWith(HOLDER)) === "NO-THROW");
  check("sd-jwt-vc compromised key: present refuses a compromised holder key",
        _syncCode(presentWith(BAD)) === "auth-sd-jwt-vc/compromised-key");
}

async function testVerifyRefusesCompromisedIssuerKey() {
  var forms = [
    ["JWK",       function (kp) { return _jwk(kp); }],
    ["PEM",       function (kp) { return kp.publicKey.export({ type: "spki", format: "pem" }); }],
    ["KeyObject", function (kp) { return kp.publicKey; }],
  ];
  for (var i = 0; i < forms.length; i += 1) {
    var f = forms[i];
    var goodKey = f[1](ISSUER);
    var badKey = f[1](BAD);
    check("sd-jwt-vc compromised key control: a credential under the control issuer " + f[0] + " verifies",
          (await _code(function () {
            return b.auth.sdJwtVc.verify(_credential(ISSUER), { issuerKeyResolver: async function () { return goodKey; } });
          })) === "NO-THROW");
    check("sd-jwt-vc compromised key: a credential under a compromised issuer " + f[0] + " is refused",
          (await _code(function () {
            return b.auth.sdJwtVc.verify(_credential(BAD), { issuerKeyResolver: async function () { return badKey; } });
          })) === "auth-sd-jwt-vc/compromised-key");
  }
}

async function testVerifyRefusesCompromisedHolderKey() {
  var vopts = { issuerKeyResolver: async function () { return _jwk(ISSUER); },
    audience: VERIFIER, nonce: "n-1", requireKeyBinding: true };
  check("sd-jwt-vc compromised key control: a key-binding JWT under the control cnf key verifies",
        (await _code(function () { return b.auth.sdJwtVc.verify(_presentation(ISSUER, HOLDER, "n-1"), vopts); })) ===
          "NO-THROW");
  check("sd-jwt-vc compromised key: a key-binding JWT under a compromised cnf key is refused",
        (await _code(function () { return b.auth.sdJwtVc.verify(_presentation(ISSUER, BAD, "n-1"), vopts); })) ===
          "auth-sd-jwt-vc/compromised-key");
}

async function testVerifyRefusesCompromisedCnfKeyWithoutKeyBinding() {
  var vopts = { issuerKeyResolver: async function () { return _jwk(ISSUER); } };
  var ok = null;
  try { ok = await b.auth.sdJwtVc.verify(_credential(ISSUER, HOLDER), vopts); } catch (_e) { ok = null; }
  check("sd-jwt-vc compromised key control: a credential with a control cnf key verifies without a key-binding JWT",
        ok !== null && ok.valid === true && ok.kbValidated === false && ok.holderKey.x === _jwk(HOLDER).x);
  check("sd-jwt-vc compromised key: a credential binding a compromised cnf key is refused without a key-binding JWT",
        (await _code(function () { return b.auth.sdJwtVc.verify(_credential(ISSUER, BAD), vopts); })) ===
          "auth-sd-jwt-vc/compromised-key");
}

async function testOid4vpRefusesCompromisedKeys() {
  var dcql = { credentials: [{ id: "pid", format: "vc+sd-jwt", meta: { vct_values: [VCT] },
    claims: [{ path: ["age_over_18"] }] }] };
  function verifier(issuerKp) {
    return b.auth.oid4vp.verifier.create({ clientId: VERIFIER, responseUri: VERIFIER + "/vp",
      issuerKeyResolver: function () { return _jwk(issuerKp); } });
  }
  var ok = await verifier(ISSUER).verifyResponse({ vpToken: { pid: _presentation(ISSUER, HOLDER, "n-2") },
    dcql: dcql, nonce: "n-2" });
  check("oid4vp compromised key control: a presentation under control keys is valid", ok.valid === true);

  var badIssuer = await verifier(BAD).verifyResponse({ vpToken: { pid: _presentation(BAD, HOLDER, "n-2") },
    dcql: dcql, nonce: "n-2" });
  check("oid4vp compromised key: a credential under a compromised issuer key is not valid",
        badIssuer.valid === false && /compromised key/.test(badIssuer.errors.join(" ")), badIssuer.errors.join(" | "));

  var badHolder = await verifier(ISSUER).verifyResponse({ vpToken: { pid: _presentation(ISSUER, BAD, "n-2") },
    dcql: dcql, nonce: "n-2" });
  check("oid4vp compromised key: a presentation under a compromised holder key is not valid",
        badHolder.valid === false && /compromised key/.test(badHolder.errors.join(" ")), badHolder.errors.join(" | "));
}

async function run() {
  testFixtureIsTheScalarOneKey();
  testConfiguredKeysAreRefused();
  testSigningWithCompromisedKeysIsRefused();
  await testVerifyRefusesCompromisedIssuerKey();
  await testVerifyRefusesCompromisedHolderKey();
  await testVerifyRefusesCompromisedCnfKeyWithoutKeyBinding();
  await testOid4vpRefusesCompromisedKeys();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
