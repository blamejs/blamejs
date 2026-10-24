// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.auth.dpop refuses a compromised key: a key anyone can hold the private
 * half of. The compromised key is the P-256 key whose private scalar is 1;
 * the control is a P-256 key derived from a label, and every refusal is
 * paired with the same input under the control key.
 *
 * verify() refuses a proof whose embedded `jwk` is compromised, and
 * buildProof() refuses to sign with a compromised key in every form it
 * accepts (KeyObject, PEM, private JWK).
 */

var helpers    = require("../helpers");
var b          = helpers.b;
var check      = helpers.check;
var nodeCrypto = require("node:crypto");
var ck         = require("../helpers/compromised-keys");

var BAD  = ck.ecKeyPair("prime256v1", 1n);
var GOOD = ck.ecKeyPair("prime256v1", ck.labelScalar("prime256v1", "blamejs dpop compromised-key control"));

var P256_GENERATOR_X = "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY";
var HTU = "https://rs.example/resource";

function _b64uJson(o) { return Buffer.from(JSON.stringify(o), "utf8").toString("base64url"); }

function _proof(kp) {
  var input = _b64uJson({ typ: "dpop+jwt", alg: "ES256", jwk: kp.publicKey.export({ format: "jwk" }) }) + "." +
    _b64uJson({ jti: nodeCrypto.randomUUID(), htm: "GET", htu: HTU, iat: Math.floor(Date.now() / 1000) });
  var sig = nodeCrypto.sign("sha256", Buffer.from(input, "ascii"), { key: kp.privateKey, dsaEncoding: "ieee-p1363" });
  return input + "." + sig.toString("base64url");
}

async function _code(fn) {
  try { await fn(); return "NO-THROW"; } catch (e) { return e.code || e.message; }
}

function testFixtureIsTheScalarOneKey() {
  check("dpop compromised key: the fixture public key is the P-256 generator",
        BAD.publicKey.export({ format: "jwk" }).x === P256_GENERATOR_X);
  check("dpop compromised key control: the control public key is not the generator",
        GOOD.publicKey.export({ format: "jwk" }).x !== P256_GENERATOR_X);
}

async function testVerifyRefusesCompromisedProofKey() {
  var vopts = { htm: "GET", htu: HTU, algorithms: ["ES256"] };
  check("dpop compromised key control: a proof under the control key verifies",
        (await _code(function () { return b.auth.dpop.verify(_proof(GOOD), vopts); })) === "NO-THROW");
  check("dpop compromised key: a proof whose jwk is compromised is refused",
        (await _code(function () { return b.auth.dpop.verify(_proof(BAD), vopts); })) === "auth-dpop/compromised-key");
}

async function testBuildProofRefusesCompromisedKey() {
  var forms = [
    ["KeyObject", function (kp) { return kp.privateKey; }],
    ["PEM",       function (kp) { return kp.privateKey.export({ type: "pkcs8", format: "pem" }); }],
    ["JWK",       function (kp) { return kp.privateKey.export({ format: "jwk" }); }],
  ];
  for (var i = 0; i < forms.length; i += 1) {
    var f = forms[i];
    var goodKey = f[1](GOOD);
    var badKey = f[1](BAD);
    check("dpop compromised key control: buildProof signs with the control " + f[0],
          (await _code(function () { return b.auth.dpop.buildProof({ htm: "GET", htu: HTU, privateKey: goodKey }); })) ===
            "NO-THROW");
    check("dpop compromised key: buildProof refuses a compromised " + f[0],
          (await _code(function () { return b.auth.dpop.buildProof({ htm: "GET", htu: HTU, privateKey: badKey }); })) ===
            "auth-dpop/compromised-key");
  }
}

async function testMiddlewareAnswers401ForCompromisedProofKey() {
  var audits = [];
  var mw = b.middleware.dpop({
    replayStore: b.nonceStore.create({ backend: "memory" }),
    getHtu:      function () { return HTU; },
    audit:       true,
  });
  var original = b.audit.safeEmit;
  async function call(kp) {
    var req = b.testing.mockReq({ method: "GET", url: "/resource", headers: { host: "rs.example", dpop: _proof(kp) },
      socket: { remoteAddress: "203.0.113.9", encrypted: true } });
    var res = b.testing.mockRes();
    var nextCalled = false;
    await mw(req, res, function () { nextCalled = true; });
    return { cap: res._captured(), nextCalled: nextCalled, req: req };
  }
  var good, bad;
  b.audit.safeEmit = function (event) { audits.push(event); return original.apply(this, arguments); };
  try {
    good = await call(GOOD);
    bad = await call(BAD);
  } finally {
    b.audit.safeEmit = original;
  }
  check("dpop middleware compromised key control: a proof under the control key reaches the handler",
        good.nextCalled === true && good.req.dpop && typeof good.req.dpop.jkt === "string");
  check("dpop middleware compromised key: a proof whose jwk is compromised is answered 401",
        bad.cap.status === 401 && bad.nextCalled === false && bad.req.dpop === undefined, bad.cap.status);
  check("dpop middleware compromised key: the 401 is an invalid_dpop_proof challenge",
        /invalid_dpop_proof/.test(bad.cap.body) &&
          /invalid_dpop_proof/.test(String(bad.cap.headers["www-authenticate"])), bad.cap.body);
  check("dpop middleware compromised key: the audit row names auth-dpop/compromised-key",
        audits.some(function (a) {
          return a.action === "auth.bearer.failure" && a.metadata && a.metadata.reason === "auth-dpop/compromised-key";
        }), JSON.stringify(audits.map(function (a) { return a.metadata && a.metadata.reason; })));
}

async function run() {
  testFixtureIsTheScalarOneKey();
  await testVerifyRefusesCompromisedProofKey();
  await testBuildProofRefusesCompromisedKey();
  await testMiddlewareAnswers401ForCompromisedProofKey();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
