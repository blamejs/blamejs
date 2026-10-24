// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.vc refuses a compromised issuer or holder key in both securing forms:
 * verify (JOSE and COSE, publicKey and keyResolver), verifyPresentation (the
 * holder signature and each enveloped credential), and issue / present.
 * Each refusal is paired with a control key that differs only in its private
 * scalar.
 */

var helpers    = require("../helpers");
var b          = helpers.b;
var check      = helpers.check;
var nodeCrypto = require("node:crypto");
var ck         = require("../helpers/compromised-keys");
var rawCose    = require("../helpers/raw-cose-sign1");

var BAD     = ck.ecKeyPair("prime256v1", 1n);
var CONTROL = ck.ecKeyPair("prime256v1", ck.labelScalar("prime256v1", "blamejs vc compromised-key control"));
var ISSUER  = "did:example:issuer";
var HOLDER  = "did:example:holder";

function _credential() {
  return {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    type: ["VerifiableCredential"],
    issuer: ISSUER,
    credentialSubject: { id: HOLDER, role: "admin" },
  };
}

async function _code(fn) {
  try { await fn(); return "NO-THROW"; } catch (e) { return e.code || e.message; }
}

function _b64(obj) { return Buffer.from(JSON.stringify(obj), "utf8").toString("base64url"); }

function _jws(doc, typ, key) {
  var input = _b64({ alg: "ES256", typ: typ }) + "." + _b64(doc);
  var sig = nodeCrypto.sign("sha256", Buffer.from(input, "ascii"), { key: key, dsaEncoding: "ieee-p1363" });
  return input + "." + sig.toString("base64url");
}

function _coseVc(doc, key) {
  return rawCose.sign1(Buffer.from(JSON.stringify(doc), "utf8"), {
    alg: "ES256", privateKey: key,
    protectedHeaders: new Map([[3, "application/vc"], [16, "application/vc+cose"]]),
  });
}

function _vp(credentials) {
  return {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    type: ["VerifiablePresentation"],
    holder: HOLDER,
    verifiableCredential: credentials.map(function (c) {
      return { "@context": ["https://www.w3.org/ns/credentials/v2"], type: "EnvelopedVerifiableCredential",
        id: "data:application/vc+jwt," + c };
    }),
    nonce: "n-1",
  };
}

async function testVerifyRefusesACompromisedIssuerKey() {
  var forms = [["jose", _jws(_credential(), "vc+jwt", CONTROL.privateKey), _jws(_credential(), "vc+jwt", BAD.privateKey)],
               ["cose", _coseVc(_credential(), CONTROL.privateKey), _coseVc(_credential(), BAD.privateKey)]];
  var want = { jose: "vc/compromised-key", cose: "cose/compromised-key" };
  for (var i = 0; i < forms.length; i += 1) {
    var form = forms[i][0];
    var out = await b.vc.verify(forms[i][1], { algorithms: ["ES256"], publicKey: CONTROL.publicKey, expectedIssuer: ISSUER });
    check("vc compromised key control: verify accepts a " + form + " credential from the control issuer key",
          out.issuer === ISSUER && out.securing === form);
    var bad = forms[i][2];
    check("vc compromised key: verify refuses a " + form + " credential from an issuer key whose private key is 1",
          (await _code(function () {
            return b.vc.verify(bad, { algorithms: ["ES256"], publicKey: BAD.publicKey, expectedIssuer: ISSUER });
          })) === want[form]);
    check("vc compromised key: verify refuses the " + form + " credential through a keyResolver too",
          (await _code(function () {
            return b.vc.verify(bad, { algorithms: ["ES256"], keyResolver: function () {
              return BAD.publicKey.export({ type: "spki", format: "pem" });
            } });
          })) === want[form]);
  }
}

async function testVerifyPresentationRefusesACompromisedKey() {
  var goodVc = _jws(_credential(), "vc+jwt", CONTROL.privateKey);
  var badVc = _jws(_credential(), "vc+jwt", BAD.privateKey);
  var credOptsGood = { algorithms: ["ES256"], publicKey: CONTROL.publicKey, expectedIssuer: ISSUER };
  var out = await b.vc.verifyPresentation(_jws(_vp([goodVc]), "vp+jwt", CONTROL.privateKey), {
    algorithms: ["ES256"], publicKey: CONTROL.publicKey, expectedHolder: HOLDER, nonce: "n-1",
    verifyCredentials: true, credentialOpts: credOptsGood,
  });
  check("vc compromised key control: verifyPresentation accepts the control holder and issuer",
        out.holder === HOLDER && out.credentials.length === 1);
  check("vc compromised key: verifyPresentation refuses a holder key whose private key is 1",
        (await _code(function () {
          return b.vc.verifyPresentation(_jws(_vp([goodVc]), "vp+jwt", BAD.privateKey), {
            algorithms: ["ES256"], publicKey: BAD.publicKey, expectedHolder: HOLDER, nonce: "n-1",
          });
        })) === "vc/compromised-key");
  check("vc compromised key: verifyPresentation refuses an enveloped credential from a compromised issuer key",
        (await _code(function () {
          return b.vc.verifyPresentation(_jws(_vp([badVc]), "vp+jwt", CONTROL.privateKey), {
            algorithms: ["ES256"], publicKey: CONTROL.publicKey, expectedHolder: HOLDER, nonce: "n-1",
            verifyCredentials: true,
            credentialOpts: { algorithms: ["ES256"], publicKey: BAD.publicKey, expectedIssuer: ISSUER },
          });
        })) === "vc/compromised-key");
}

async function testIssueAndPresentRefuseACompromisedKey() {
  var forms = [["jose", "vc/compromised-key"], ["cose", "cose/compromised-key"]];
  for (var i = 0; i < forms.length; i += 1) {
    var securing = forms[i][0];
    check("vc compromised key control: issue (" + securing + ") with the control key succeeds",
          (await _code(function () {
            return b.vc.issue(_credential(), { securing: securing, alg: "ES256", privateKey: CONTROL.privateKey });
          })) === "NO-THROW");
    check("vc compromised key: issue (" + securing + ") refuses a key whose private key is 1",
          (await _code(function () {
            return b.vc.issue(_credential(), { securing: securing, alg: "ES256", privateKey: BAD.privateKey });
          })) === forms[i][1]);
    var vcToken = _jws(_credential(), "vc+jwt", CONTROL.privateKey);
    check("vc compromised key control: present (" + securing + ") with the control holder key succeeds",
          (await _code(function () {
            return b.vc.present({ credentials: [vcToken], holder: HOLDER, securing: securing, alg: "ES256",
              privateKey: CONTROL.privateKey });
          })) === "NO-THROW");
    check("vc compromised key: present (" + securing + ") refuses a holder key whose private key is 1",
          (await _code(function () {
            return b.vc.present({ credentials: [vcToken], holder: HOLDER, securing: securing, alg: "ES256",
              privateKey: BAD.privateKey });
          })) === forms[i][1]);
  }
}

async function run() {
  await testVerifyRefusesACompromisedIssuerKey();
  await testVerifyPresentationRefusesACompromisedKey();
  await testIssueAndPresentRefuseACompromisedKey();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
