// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.cose refuses a compromised key on every path: verify (publicKey and
 * keyResolver), importKey (a COSE_Key map) and sign. Each refusal is paired
 * with a control key on the same curve that differs only in its private
 * scalar.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var ck      = require("../helpers/compromised-keys");
var rawCose = require("../helpers/raw-cose-sign1");

var CASES = [
  ["ES256", "prime256v1", 1n],
  ["ES256", "prime256v1", ck.CURVES.prime256v1[2] - 1n],
  ["ES384", "secp384r1",  1n],
  ["ES512", "secp521r1",  1n],
];

function _pairs(curve, d) {
  return {
    bad:     ck.ecKeyPair(curve, d),
    control: ck.ecKeyPair(curve, ck.labelScalar(curve, "blamejs cose compromised-key control")),
  };
}

async function _code(fn) {
  try { await fn(); return "NO-THROW"; } catch (e) { return e.code || e.message; }
}

function _coseKey(publicKey) {
  return b.cbor.decode(b.cose.exportKey(publicKey));
}

async function testVerifyRefusesACompromisedKey() {
  for (var i = 0; i < CASES.length; i += 1) {
    var alg = CASES[i][0];
    var label = alg + " d=" + (CASES[i][2] === 1n ? "1" : "n-1");
    var p = _pairs(CASES[i][1], CASES[i][2]);
    var payload = Buffer.from("cose compromised-key " + label);
    var good = rawCose.sign1(payload, { alg: alg, privateKey: p.control.privateKey });
    var out = await b.cose.verify(good, { algorithms: [alg], publicKey: p.control.publicKey });
    check("cose compromised key control: verify accepts the control " + label + " signature",
          Buffer.from(out.payload).equals(payload));
    var bad = rawCose.sign1(payload, { alg: alg, privateKey: p.bad.privateKey });
    check("cose compromised key: verify refuses a " + label + " signature (publicKey)",
          (await _code(function () {
            return b.cose.verify(bad, { algorithms: [alg], publicKey: p.bad.publicKey });
          })) === "cose/compromised-key");
    check("cose compromised key: verify refuses a " + label + " signature (keyResolver PEM)",
          (await _code(function () {
            return b.cose.verify(bad, { algorithms: [alg], keyResolver: function () {
              return p.bad.publicKey.export({ type: "spki", format: "pem" });
            } });
          })) === "cose/compromised-key");
  }
}

async function testImportKeyRefusesACompromisedCoseKey() {
  var p = _pairs("prime256v1", 1n);
  var control = b.cose.importKey(_coseKey(p.control.publicKey));
  check("cose compromised key control: importKey imports the control COSE_Key",
        control && control.asymmetricKeyType === "ec");
  check("cose compromised key: importKey refuses a COSE_Key whose private key is 1",
        (await _code(function () { return b.cose.importKey(_coseKey(p.bad.publicKey)); })) === "cose/compromised-key");
}

async function testSignRefusesACompromisedKey() {
  for (var i = 0; i < CASES.length; i += 1) {
    var alg = CASES[i][0];
    var p = _pairs(CASES[i][1], CASES[i][2]);
    check("cose compromised key control: sign with the control " + alg + " key succeeds",
          (await _code(function () {
            return b.cose.sign(Buffer.from("x"), { alg: alg, privateKey: p.control.privateKey });
          })) === "NO-THROW");
    check("cose compromised key: sign refuses a compromised " + alg + " key",
          (await _code(function () {
            return b.cose.sign(Buffer.from("x"), { alg: alg, privateKey: p.bad.privateKey });
          })) === "cose/compromised-key");
  }
}

async function run() {
  await testVerifyRefusesACompromisedKey();
  await testImportKeyRefusesACompromisedCoseKey();
  await testSignRefusesACompromisedKey();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
