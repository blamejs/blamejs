// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.auth.jwt.verifyExternal, b.auth.jws.sign and b.auth.jar refuse a
 * compromised key: a key anyone can hold the private half of. The
 * compromised key is the P-256 key whose private scalar is 1; the control is
 * a P-256 key derived from a label, so each refusal is paired with the same
 * input under an ordinary key.
 *
 * verifyExternal is driven through every key source that hands it a key in a
 * different form: an in-memory JWKS, and a keyResolver returning a JWK, a PEM
 * string, a PEM Buffer and a KeyObject. jwksUri goes through the same JWK
 * import as the in-memory JWKS.
 */

var helpers    = require("../helpers");
var b          = helpers.b;
var check      = helpers.check;
var nodeCrypto = require("node:crypto");
var ck         = require("../helpers/compromised-keys");

var BAD  = ck.ecKeyPair("prime256v1", 1n);
var GOOD = ck.ecKeyPair("prime256v1", ck.labelScalar("prime256v1", "blamejs jwt-external compromised-key control"));

var ISS = "https://idp.example";
var AUD = "rp-1";

function _jwk(kp, kid) {
  var j = kp.publicKey.export({ format: "jwk" });
  j.kid = kid;
  return j;
}

function _b64uJson(o) { return Buffer.from(JSON.stringify(o), "utf8").toString("base64url"); }

function _es256(header, payload, privateKey) {
  var input = _b64uJson(header) + "." + _b64uJson(payload);
  var sig = nodeCrypto.sign("sha256", Buffer.from(input, "ascii"), { key: privateKey, dsaEncoding: "ieee-p1363" });
  return input + "." + sig.toString("base64url");
}

function _token(kp, kid, extraHeader, extraClaims) {
  var now = Math.floor(Date.now() / 1000);
  return _es256(Object.assign({ alg: "ES256", kid: kid }, extraHeader || {}),
    Object.assign({ iss: ISS, aud: AUD, sub: "admin", iat: now, exp: now + 300 }, extraClaims || {}),
    kp.privateKey);
}

async function _code(fn) {
  try { await fn(); return "NO-THROW"; } catch (e) { return e.code || e.message; }
}

function _syncCode(fn) {
  try { fn(); return "NO-THROW"; } catch (e) { return e.code || e.message; }
}

var P256_GENERATOR_X = "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY";

function testFixtureIsTheScalarOneKey() {
  check("jwt-external compromised key: the fixture public key is the P-256 generator",
        BAD.publicKey.export({ format: "jwk" }).x === P256_GENERATOR_X);
  check("jwt-external compromised key control: the control public key is not the generator",
        GOOD.publicKey.export({ format: "jwk" }).x !== P256_GENERATOR_X);
}

async function testVerifyExternalRefusesCompromisedJwks() {
  var opts = function (kp, kid) { return { algorithms: ["ES256"], jwks: [_jwk(kp, kid)], issuer: ISS, audience: AUD }; };
  check("jwt-external compromised key control: a token under the control JWKS verifies",
        (await _code(function () { return b.auth.jwt.verifyExternal(_token(GOOD, "g"), opts(GOOD, "g")); })) === "NO-THROW");
  check("jwt-external compromised key: a token under a compromised JWKS key is refused",
        (await _code(function () { return b.auth.jwt.verifyExternal(_token(BAD, "k"), opts(BAD, "k")); })) ===
          "auth-jwt-external/compromised-key");

  var published = function (kp, kid) {
    return { algorithms: ["ES256"], jwks: { keys: [_jwk(kp, kid)] }, issuer: ISS, audience: AUD };
  };
  check("jwt-external jwks: a token verifies against a JWKS in its published { keys: [...] } shape",
        (await _code(function () { return b.auth.jwt.verifyExternal(_token(GOOD, "g"), published(GOOD, "g")); })) ===
          "NO-THROW");
  check("jwt-external compromised key: a compromised key in a published-shape JWKS is refused",
        (await _code(function () { return b.auth.jwt.verifyExternal(_token(BAD, "k"), published(BAD, "k")); })) ===
          "auth-jwt-external/compromised-key");
  var malformed = [["an object without keys", {}], ["keys that is not an array", { keys: "k" }], ["a string", "jwks"]];
  for (var i = 0; i < malformed.length; i += 1) {
    var jwks = malformed[i][1];
    check("jwt-external jwks: a JWKS given as " + malformed[i][0] + " is refused",
          (await _code(function () {
            return b.auth.jwt.verifyExternal(_token(GOOD, "g"), { algorithms: ["ES256"], jwks: jwks });
          })) === "auth-jwt-external/bad-jwks");
  }
}

async function testVerifyExternalRefusesCompromisedResolverKey() {
  var forms = [
    ["JWK",        function (kp) { return _jwk(kp, "r"); }],
    ["PEM string", function (kp) { return kp.publicKey.export({ type: "spki", format: "pem" }); }],
    ["PEM Buffer", function (kp) { return Buffer.from(kp.publicKey.export({ type: "spki", format: "pem" })); }],
    ["KeyObject",  function (kp) { return kp.publicKey; }],
  ];
  for (var i = 0; i < forms.length; i += 1) {
    var label = forms[i][0];
    var make = forms[i][1];
    var good = make(GOOD);
    var bad = make(BAD);
    check("jwt-external compromised key control: keyResolver returning the control " + label + " verifies",
          (await _code(function () {
            return b.auth.jwt.verifyExternal(_token(GOOD, "r"), {
              algorithms: ["ES256"], keyResolver: function () { return good; }, issuer: ISS, audience: AUD });
          })) === "NO-THROW");
    check("jwt-external compromised key: keyResolver returning a compromised " + label + " is refused",
          (await _code(function () {
            return b.auth.jwt.verifyExternal(_token(BAD, "r"), {
              algorithms: ["ES256"], keyResolver: function () { return bad; }, issuer: ISS, audience: AUD });
          })) === "auth-jwt-external/compromised-key");
  }
}

function testJwsSignRefusesCompromisedKey() {
  var forms = [
    ["KeyObject", function (kp) { return kp.privateKey; }],
    ["PEM",       function (kp) { return kp.privateKey.export({ type: "pkcs8", format: "pem" }); }],
    ["JWK",       function (kp) { return kp.privateKey.export({ format: "jwk" }); }],
  ];
  forms.forEach(function (f) {
    check("jwt-external compromised key control: jws.sign with the control " + f[0] + " signs",
          _syncCode(function () { b.auth.jws.sign({ iss: "c" }, { privateKey: f[1](GOOD) }); }) === "NO-THROW");
    check("jwt-external compromised key: jws.sign refuses a compromised " + f[0],
          _syncCode(function () { b.auth.jws.sign({ iss: "c" }, { privateKey: f[1](BAD) }); }) ===
            "auth-jwt-external/compromised-key");
  });
}

async function testJarRefusesCompromisedKey() {
  var params = { response_type: "code", client_id: "s6", redirect_uri: "https://attacker.example/cb", scope: "openid" };
  function jarOf(kp) {
    var now = Math.floor(Date.now() / 1000);
    return _es256({ alg: "ES256", kid: "c", typ: "oauth-authz-req+jwt" },
      Object.assign({ iss: "s6", aud: "https://as.example", iat: now, exp: now + 300 }, params), kp.privateKey);
  }
  function parseOpts(kp) {
    return { clientId: "s6", audience: "https://as.example", algorithms: ["ES256"], jwks: [_jwk(kp, "c")] };
  }
  check("jar compromised key control: jar.parse accepts a request object under the control key",
        (await _code(function () { return b.auth.jar.parse(jarOf(GOOD), parseOpts(GOOD)); })) === "NO-THROW");
  check("jar compromised key: jar.parse refuses a request object under a compromised client key",
        (await _code(function () { return b.auth.jar.parse(jarOf(BAD), parseOpts(BAD)); })) ===
          "auth-jwt-external/compromised-key");
  function publishedOpts(kp) {
    return { clientId: "s6", audience: "https://as.example", algorithms: ["ES256"], jwks: { keys: [_jwk(kp, "c")] } };
  }
  check("jar compromised key control: jar.parse accepts the client's JWKS in its published shape",
        (await _code(function () { return b.auth.jar.parse(jarOf(GOOD), publishedOpts(GOOD)); })) === "NO-THROW");
  check("jar compromised key: jar.parse refuses a compromised key in a published-shape JWKS",
        (await _code(function () { return b.auth.jar.parse(jarOf(BAD), publishedOpts(BAD)); })) ===
          "auth-jwt-external/compromised-key");

  var buildOpts = function (kp) { return { clientId: "s6", audience: "https://as.example", key: kp.privateKey }; };
  check("jar compromised key control: jar.build signs with the control key",
        _syncCode(function () { b.auth.jar.build(params, buildOpts(GOOD)); }) === "NO-THROW");
  check("jar compromised key: jar.build refuses a compromised signing key",
        _syncCode(function () { b.auth.jar.build(params, buildOpts(BAD)); }) === "auth-jwt-external/compromised-key");
}

async function run() {
  testFixtureIsTheScalarOneKey();
  await testVerifyExternalRefusesCompromisedJwks();
  await testVerifyExternalRefusesCompromisedResolverKey();
  testJwsSignRefusesCompromisedKey();
  await testJarRefusesCompromisedKey();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
