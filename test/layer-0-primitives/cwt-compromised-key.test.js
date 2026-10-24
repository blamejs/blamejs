// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.cwt refuses a CWT signed by a compromised key, and refuses to sign with
 * one. Each refusal is paired with a control key that differs only in its
 * private scalar.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var ck      = require("../helpers/compromised-keys");
var rawCose = require("../helpers/raw-cose-sign1");

var BAD     = ck.ecKeyPair("prime256v1", 1n);
var CONTROL = ck.ecKeyPair("prime256v1", ck.labelScalar("prime256v1", "blamejs cwt compromised-key control"));

async function _code(fn) {
  try { await fn(); return "NO-THROW"; } catch (e) { return e.code || e.message; }
}

function _claims() {
  return b.cbor.encode(new Map([[1, "issuer.example"], [2, "admin"], [4, Math.floor(Date.now() / 1000) + 3600]]));
}

async function testVerifyRefusesACompromisedKey() {
  var good = rawCose.sign1(_claims(), { alg: "ES256", privateKey: CONTROL.privateKey });
  var out = await b.cwt.verify(good, { algorithms: ["ES256"], publicKey: CONTROL.publicKey, expectedIssuer: "issuer.example" });
  check("cwt compromised key control: verify accepts a CWT signed by the control key", out.claims.sub === "admin");
  var bad = rawCose.sign1(_claims(), { alg: "ES256", privateKey: BAD.privateKey });
  check("cwt compromised key: verify refuses a CWT signed by a key whose private key is 1",
        (await _code(function () {
          return b.cwt.verify(bad, { algorithms: ["ES256"], publicKey: BAD.publicKey, expectedIssuer: "issuer.example" });
        })) === "cose/compromised-key");
  check("cwt compromised key: verify refuses it through a keyResolver too",
        (await _code(function () {
          return b.cwt.verify(bad, { algorithms: ["ES256"], keyResolver: function () { return BAD.publicKey; } });
        })) === "cose/compromised-key");
}

async function testSignRefusesACompromisedKey() {
  var claims = { iss: "issuer.example", sub: "admin" };
  check("cwt compromised key control: sign with the control key succeeds",
        (await _code(function () { return b.cwt.sign(claims, { alg: "ES256", privateKey: CONTROL.privateKey }); })) === "NO-THROW");
  check("cwt compromised key: sign refuses a key whose private key is 1",
        (await _code(function () { return b.cwt.sign(claims, { alg: "ES256", privateKey: BAD.privateKey }); })) === "cose/compromised-key");
}

async function run() {
  await testVerifyRefusesACompromisedKey();
  await testSignRefusesACompromisedKey();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
