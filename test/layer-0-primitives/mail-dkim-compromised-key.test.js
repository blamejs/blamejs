// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.mail.dkim.verify fails a signature whose selector publishes a compromised
 * key: the eDellRoot RSA key, whose private half Dell shipped in 2015. The
 * result is "fail" and its error names the compromised key.
 *
 * The test has no copy of the eDellRoot private key, so it stands in for a
 * signer who holds it: while a case runs, node:crypto's verify reports a
 * valid signature for the one key the case names. The control does the same
 * for a fresh RSA key and passes, so the refusal comes from the key and not
 * from the signature bytes. The compromised case also shows that verify is
 * never called with the compromised key.
 *
 * b.mail.dkim.create refuses a compromised signing key with
 * dkim/compromised-key. create accepts RSA and Ed25519 keys only, and the
 * compromised RSA keys are listed keys whose private halves the test does not
 * hold, so the case gives create an RSA private key whose public half reads as
 * the eDellRoot key.
 */

var helpers    = require("../helpers");
var b          = helpers.b;
var check      = helpers.check;
var nodeCrypto = require("node:crypto");
var ck         = require("../helpers/compromised-keys");

var MSG = "From: ceo@victim.example\r\nTo: a@b.example\r\nSubject: wire\r\n" +
          "Date: Thu, 22 Oct 2026 10:00:00 +0000\r\nMessage-ID: <1@victim.example>\r\n\r\nPay now.\r\n";

function _spkiB64(publicKey) {
  return publicKey.export({ type: "spki", format: "der" }).toString("base64");
}

var EDELLROOT_PUBLIC = new nodeCrypto.X509Certificate(ck.EDELLROOT_CERT_PEM).publicKey;

async function _verifyForged(signed, publicKey) {
  var origVerify = nodeCrypto.verify;
  var calls = 0;
  nodeCrypto.verify = function (alg, data, key) {
    if (key instanceof nodeCrypto.KeyObject && key.type === "public" && key.equals(publicKey)) {
      calls += 1;
      return true;
    }
    return origVerify.apply(nodeCrypto, arguments);
  };
  try {
    b.mail.dkim._resetDkimKeyCacheForTest();
    var res = await b.mail.dkim.verify(signed, {
      audit: false,
      dnsLookup: async function () { return [["v=DKIM1; k=rsa; p=" + _spkiB64(publicKey)]]; },
    });
    return { res: res, calls: calls };
  } finally {
    nodeCrypto.verify = origVerify;
  }
}

async function testAListedSelectorKeyFailsAForgedSignature() {
  var kp = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  var signer = b.mail.dkim.create({
    domain: "victim.example", selector: "s1", privateKey: kp.privateKey, algorithm: "rsa-sha256", audit: false,
  });
  var signed = await signer.sign(MSG);

  var other = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  var good = await _verifyForged(signed, other.publicKey);
  check("dkim compromised key control: a signature that verifies under an ordinary selector key passes",
        good.res.length === 1 && good.res[0].result === "pass" && good.calls === 1, JSON.stringify(good));

  var bad = await _verifyForged(signed, EDELLROOT_PUBLIC);
  check("dkim compromised key: a signature that verifies under the eDellRoot key fails as a compromised key",
        bad.res.length === 1 && bad.res[0].result === "fail" &&
        bad.res[0].errors.some(function (e) { return /compromised key/.test(e); }),
        JSON.stringify(bad));
  check("dkim compromised key: verify is never called with the eDellRoot key", bad.calls === 0, String(bad.calls));
}

function _asEdellRoot(rsaPublic, fn) {
  var origCreatePublicKey = nodeCrypto.createPublicKey;
  nodeCrypto.createPublicKey = function (input) {
    var real = origCreatePublicKey.apply(nodeCrypto, arguments);
    if (input instanceof nodeCrypto.KeyObject && input.type === "private" && real.equals(rsaPublic)) {
      return EDELLROOT_PUBLIC;
    }
    return real;
  };
  try { return fn(); }
  finally { nodeCrypto.createPublicKey = origCreatePublicKey; }
}

function _create(privateKey) {
  try {
    b.mail.dkim.create({
      domain: "victim.example", selector: "s1", privateKey: privateKey, algorithm: "rsa-sha256", audit: false,
    });
    return "created";
  } catch (e) { return e.code || String(e); }
}

function testCreateRefusesACompromisedSigningKey() {
  var control = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  var controlCode = _asEdellRoot(nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey,
    function () { return _create(control.privateKey); });
  check("dkim create control: an ordinary RSA signing key is accepted", controlCode === "created", controlCode);

  var listed = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  var listedCode = _asEdellRoot(listed.publicKey, function () { return _create(listed.privateKey); });
  check("dkim create: a signing key whose public half is the eDellRoot key is refused",
        listedCode === "dkim/compromised-key", listedCode);

  var listedPem = nodeCrypto.generateKeyPairSync("rsa", {
    modulusLength: 2048, privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });
  var listedPemCode = _asEdellRoot(nodeCrypto.createPublicKey(listedPem.publicKey),
    function () { return _create(listedPem.privateKey); });
  check("dkim create: the same refusal holds for a PEM signing key",
        listedPemCode === "dkim/compromised-key", listedPemCode);
}

async function run() {
  await testAListedSelectorKeyFailsAForgedSignature();
  testCreateRefusesACompromisedSigningKey();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
