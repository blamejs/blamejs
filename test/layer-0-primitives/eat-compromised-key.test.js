// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.eat refuses an attestation signed by a compromised attester key, even
 * with a fresh nonce and debugging disabled, and refuses to sign with one.
 * Each refusal is paired with a control key that differs only in its private
 * scalar.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var ck      = require("../helpers/compromised-keys");
var rawCose = require("../helpers/raw-cose-sign1");

var BAD     = ck.ecKeyPair("secp384r1", 1n);
var CONTROL = ck.ecKeyPair("secp384r1", ck.labelScalar("secp384r1", "blamejs eat compromised-key control"));
var NONCE   = Buffer.from("0123456789abcdef0123456789abcdef", "hex");

async function _code(fn) {
  try { await fn(); return "NO-THROW"; } catch (e) { return e.code || e.message; }
}

function _token(key) {
  var claims = new Map([[10, NONCE], [263, 3], [6, Math.floor(Date.now() / 1000)]]);
  return rawCose.sign1(b.cbor.encode(claims), { alg: "ES384", privateKey: key });
}

function _opts(publicKey) {
  return { algorithms: ["ES384"], publicKey: publicKey, expectedNonce: NONCE, requireDebugDisabled: true };
}

async function testVerifyRefusesACompromisedAttesterKey() {
  var out = await b.eat.verify(_token(CONTROL.privateKey), _opts(CONTROL.publicKey));
  check("eat compromised key control: verify accepts an attestation from the control key",
        out.claims.dbgstat === "disabled-permanently");
  check("eat compromised key: verify refuses an attestation from a key whose private key is 1",
        (await _code(function () { return b.eat.verify(_token(BAD.privateKey), _opts(BAD.publicKey)); })) ===
        "cose/compromised-key");
}

async function testSignRefusesACompromisedKey() {
  var claims = { nonce: NONCE, dbgstat: "disabled-permanently" };
  check("eat compromised key control: sign with the control key succeeds",
        (await _code(function () { return b.eat.sign(claims, { alg: "ES384", privateKey: CONTROL.privateKey }); })) === "NO-THROW");
  check("eat compromised key: sign refuses a key whose private key is 1",
        (await _code(function () { return b.eat.sign(claims, { alg: "ES384", privateKey: BAD.privateKey }); })) ===
        "cose/compromised-key");
}

async function run() {
  await testVerifyRefusesACompromisedAttesterKey();
  await testSignRefusesACompromisedKey();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
