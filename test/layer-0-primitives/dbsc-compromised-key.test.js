// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.dbsc.verifyBindingAssertion and b.middleware.protectedResourceMetadata
 * refuse a compromised key: a key anyone can hold the private half of. The
 * compromised key is the P-256 key whose private scalar is 1; the control is a
 * P-256 key derived from a label, and every refusal is paired with the same
 * input under the control key.
 *
 * A DBSC binding assertion whose embedded `jwk` is compromised is refused with
 * `dbsc/compromised-key`. A protected-resource metadata document is not signed
 * with a compromised `signMetadata.key`: create() throws
 * `middleware/protected-resource-metadata/compromised-key`.
 */

var helpers    = require("../helpers");
var b          = helpers.b;
var check      = helpers.check;
var nodeCrypto = require("node:crypto");
var ck         = require("../helpers/compromised-keys");

var BAD  = ck.ecKeyPair("prime256v1", 1n);
var GOOD = ck.ecKeyPair("prime256v1", ck.labelScalar("prime256v1", "blamejs dbsc compromised-key control"));

var P256_GENERATOR_X = "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY";
var RP = "https://rp.example";

function _b64uJson(o) { return Buffer.from(JSON.stringify(o), "utf8").toString("base64url"); }

function _assertion(kp) {
  var jwk = kp.publicKey.export({ format: "jwk" });
  var input = _b64uJson({ alg: "ES256", typ: "dbsc+jwt", jwk: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y } }) +
    "." + _b64uJson({ aud: RP, iat: Math.floor(Date.now() / 1000) });
  var sig = nodeCrypto.sign("sha256", Buffer.from(input, "ascii"), { key: kp.privateKey, dsaEncoding: "ieee-p1363" });
  return input + "." + sig.toString("base64url");
}

function _code(fn) {
  try { fn(); return "NO-THROW"; } catch (e) { return e.code || e.message; }
}

function testFixtureIsTheScalarOneKey() {
  check("dbsc compromised key: the fixture public key is the P-256 generator",
        BAD.publicKey.export({ format: "jwk" }).x === P256_GENERATOR_X);
  check("dbsc compromised key control: the control public key is not the generator",
        GOOD.publicKey.export({ format: "jwk" }).x !== P256_GENERATOR_X);
}

function testBindingAssertionWithCompromisedKeyIsRefused() {
  var secretKey = nodeCrypto.randomBytes(32);
  var vopts = { secretKey: secretKey, expectedAud: RP };
  var ok = null;
  try { ok = b.dbsc.verifyBindingAssertion(_assertion(GOOD), vopts); } catch (_e) { ok = null; }
  check("dbsc compromised key control: an assertion under the control key verifies",
        ok !== null && ok.valid === true);
  check("dbsc compromised key: an assertion whose embedded jwk is compromised is refused",
        _code(function () { b.dbsc.verifyBindingAssertion(_assertion(BAD), vopts); }) === "dbsc/compromised-key");
}

function testSignedMetadataWithCompromisedKeyIsRefused() {
  var forms = [
    ["KeyObject", function (kp) { return kp.privateKey; }],
    ["PEM",       function (kp) { return kp.privateKey.export({ type: "pkcs8", format: "pem" }); }],
    ["JWK",       function (kp) { return kp.privateKey.export({ format: "jwk" }); }],
  ];
  function create(key) {
    return function () {
      b.middleware.protectedResourceMetadata({
        resource:             "https://api.example.com",
        authorizationServers: ["https://idp.example.com"],
        signMetadata:         { key: key, alg: "ES256", kid: "rs1" },
      });
    };
  }
  for (var i = 0; i < forms.length; i += 1) {
    check("protected-resource-metadata compromised key control: a control " + forms[i][0] + " signs the document",
          _code(create(forms[i][1](GOOD))) === "NO-THROW");
    check("protected-resource-metadata compromised key: a compromised " + forms[i][0] + " is refused",
          _code(create(forms[i][1](BAD))) === "middleware/protected-resource-metadata/compromised-key");
  }
}

async function run() {
  testFixtureIsTheScalarOneKey();
  testBindingAssertionWithCompromisedKeyIsRefused();
  testSignedMetadataWithCompromisedKeyIsRefused();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
