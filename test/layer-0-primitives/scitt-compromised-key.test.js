// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.scitt refuses a signed statement from a compromised issuer key, even
 * when the issuer and subject match, and refuses to sign with one. Each
 * refusal is paired with a control key that differs only in its private
 * scalar.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var ck      = require("../helpers/compromised-keys");
var rawCose = require("../helpers/raw-cose-sign1");

var BAD     = ck.ecKeyPair("prime256v1", 1n);
var CONTROL = ck.ecKeyPair("prime256v1", ck.labelScalar("prime256v1", "blamejs scitt compromised-key control"));
var ISSUER  = "did:web:builder.example";
var SUBJECT = "pkg:npm/widget@1.2.3";

async function _code(fn) {
  try { await fn(); return "NO-THROW"; } catch (e) { return e.code || e.message; }
}

function _statement(key) {
  return rawCose.sign1(Buffer.from("release attestation"), {
    alg: "ES256", privateKey: key,
    protectedHeaders: new Map([[15, new Map([[1, ISSUER], [2, SUBJECT]])]]),
  });
}

function _opts(publicKey) {
  return { algorithms: ["ES256"], publicKey: publicKey, expectedIssuer: ISSUER, expectedSubject: SUBJECT };
}

async function testVerifyRefusesACompromisedIssuerKey() {
  var out = await b.scitt.verifyStatement(_statement(CONTROL.privateKey), _opts(CONTROL.publicKey));
  check("scitt compromised key control: verifyStatement accepts a statement from the control key",
        out.subject === SUBJECT);
  check("scitt compromised key: verifyStatement refuses a statement from a key whose private key is 1",
        (await _code(function () {
          return b.scitt.verifyStatement(_statement(BAD.privateKey), _opts(BAD.publicKey));
        })) === "cose/compromised-key");
}

async function testSignRefusesACompromisedKey() {
  function sign(key) {
    return b.scitt.signStatement(Buffer.from("x"), { alg: "ES256", privateKey: key, issuer: ISSUER, subject: SUBJECT });
  }
  check("scitt compromised key control: signStatement with the control key succeeds",
        (await _code(function () { return sign(CONTROL.privateKey); })) === "NO-THROW");
  check("scitt compromised key: signStatement refuses a key whose private key is 1",
        (await _code(function () { return sign(BAD.privateKey); })) === "cose/compromised-key");
}

async function run() {
  await testVerifyRefusesACompromisedIssuerKey();
  await testSignRefusesACompromisedKey();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
