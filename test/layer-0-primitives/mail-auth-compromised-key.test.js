// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.mail.arc.verify and b.mail.arc.evaluate fail an ARC set whose sealer
 * selector publishes a compromised key (the eDellRoot RSA key): the ARC-Seal
 * and the ARC-Message-Signature each fail with an error naming the compromised
 * key, and a trusted sealer is not trusted.
 *
 * The test has no copy of the eDellRoot private key, so it stands in for a
 * sealer who holds it: while a case runs, node:crypto's verify reports a valid
 * signature for the one key the case names. The control does the same for a
 * fresh RSA key and passes, so the refusal comes from the key and not from the
 * signature bytes.
 *
 * b.mail.arc.sign refuses a compromised signing key with
 * arc-sign/compromised-key. sign accepts RSA and Ed25519 keys only, so the case
 * gives it an RSA private key whose public half reads as the eDellRoot key.
 */

var helpers    = require("../helpers");
var b          = helpers.b;
var check      = helpers.check;
var nodeCrypto = require("node:crypto");
var ck         = require("../helpers/compromised-keys");

var MSG = "From: ceo@victim.example\r\nTo: bob@example.com\r\nSubject: wire\r\n" +
          "Date: Wed, 06 May 2026 12:00:00 +0000\r\nMessage-ID: <p@x>\r\n\r\nhi\r\n";

function _spkiB64(publicKey) {
  return publicKey.export({ type: "spki", format: "der" }).toString("base64");
}

var EDELLROOT_PUBLIC = new nodeCrypto.X509Certificate(ck.EDELLROOT_CERT_PEM).publicKey;

function _dns(p) {
  return async function (qname) {
    if (qname === "arc._domainkey.relay.example") return [["v=DKIM1; k=rsa; p=" + p]];
    var e = new Error("ENOTFOUND " + qname); e.code = "ENOTFOUND"; throw e;
  };
}

function _named(errors) {
  return Array.isArray(errors) && errors.some(function (e) { return /compromised key/.test(e); });
}

function _seal(privateKey) {
  return b.mail.arc.sign({
    rfc822: MSG, instance: 1, authservId: "relay.example", domain: "relay.example",
    selector: "arc", privateKey: privateKey,
    algorithm: "rsa-sha256", cv: "none", authResults: "dmarc=pass",
    headersToSign: ["From", "To", "Subject", "Date", "Message-ID"],
  }).rfc822;
}

async function _forged(publicKey, fn) {
  var origVerify = nodeCrypto.verify;
  var state = { calls: 0 };
  nodeCrypto.verify = function (alg, data, key) {
    if (key instanceof nodeCrypto.KeyObject && key.type === "public" && key.equals(publicKey)) {
      state.calls += 1;
      return true;
    }
    return origVerify.apply(nodeCrypto, arguments);
  };
  try {
    b.mail.dkim._resetDkimKeyCacheForTest();
    state.verdict = await fn("verify");
    b.mail.dkim._resetDkimKeyCacheForTest();
    state.evaluated = await fn("evaluate");
    return state;
  } finally {
    nodeCrypto.verify = origVerify;
  }
}

async function _run(sealed, publicKey) {
  return _forged(publicKey, function (which) {
    var dns = _dns(_spkiB64(publicKey));
    return which === "verify"
      ? b.mail.arc.verify(sealed, { dnsLookup: dns })
      : b.mail.arc.evaluate(sealed, { dnsLookup: dns, trustedSealers: ["relay.example"] });
  });
}

async function testAListedSealerKeyFailsAForgedArcSet() {
  var kp = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  var sealed = _seal(kp.privateKey.export({ format: "pem", type: "pkcs8" }));

  var other = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  var good = await _run(sealed, other.publicKey);
  check("arc compromised key control: a seal that verifies under an ordinary sealer key passes",
        good.verdict.chainStatus === "pass" && good.verdict.hops[0].asResult === "pass" &&
        good.verdict.hops[0].amsResult === "pass", JSON.stringify(good.verdict.hops[0]));
  check("arc compromised key control: evaluate trusts the control sealer",
        good.evaluated.trusted === true && good.evaluated.trustedDomain === "relay.example",
        JSON.stringify(good.evaluated));

  var bad = await _run(sealed, EDELLROOT_PUBLIC);
  check("arc compromised key: an ARC-Seal that verifies under the eDellRoot key fails as a compromised key",
        bad.verdict.chainStatus === "fail" && bad.verdict.hops[0].asResult === "fail" &&
        _named(bad.verdict.hops[0].asErrors), JSON.stringify(bad.verdict.hops[0]));
  check("arc compromised key: an ARC-Message-Signature that verifies under the eDellRoot key fails as a compromised key",
        bad.verdict.hops[0].amsResult === "fail" && _named(bad.verdict.hops[0].amsErrors),
        JSON.stringify(bad.verdict.hops[0]));
  check("arc compromised key: evaluate does not trust a sealer whose key is compromised",
        bad.evaluated.chainStatus === "fail" && bad.evaluated.trusted !== true, JSON.stringify(bad.evaluated));
  check("arc compromised key: verify is never called with the eDellRoot key", bad.calls === 0, String(bad.calls));
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

function _sealCode(privateKey) {
  try { _seal(privateKey); return "sealed"; }
  catch (e) { return e.code || String(e); }
}

function testSignRefusesACompromisedSigningKey() {
  var control = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  var controlCode = _asEdellRoot(nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey,
    function () { return _sealCode(control.privateKey); });
  check("arc sign control: an ordinary RSA sealer key seals", controlCode === "sealed", controlCode);

  var listed = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  var listedCode = _asEdellRoot(listed.publicKey, function () { return _sealCode(listed.privateKey); });
  check("arc sign: a sealer key whose public half is the eDellRoot key is refused",
        listedCode === "arc-sign/compromised-key", listedCode);

  var listedPem = nodeCrypto.generateKeyPairSync("rsa", {
    modulusLength: 2048, privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });
  var listedPemCode = _asEdellRoot(nodeCrypto.createPublicKey(listedPem.publicKey),
    function () { return _sealCode(listedPem.privateKey); });
  check("arc sign: the same refusal holds for a PEM sealer key",
        listedPemCode === "arc-sign/compromised-key", listedPemCode);
}

async function run() {
  await testAListedSealerKeyFailsAForgedArcSet();
  testSignRefusesACompromisedSigningKey();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
