// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.mail.dkim.verify and b.mail.arc.verify require the selector key to be the
 * type the signature's a= tag names: an RSA key for rsa-sha256 and an Ed25519
 * key for ed25519-sha256. A record whose k= tag agrees with a= but whose p=
 * holds another key type is a permerror, so a P-256 key published under k=rsa
 * cannot make an ECDSA signature pass as rsa-sha256, and an RSA key published
 * under k=ed25519 cannot make an RSA signature pass as ed25519-sha256. The RSA
 * size floor applies to the ARC-Seal as it does to the DKIM signature and the
 * ARC-Message-Signature.
 *
 * Each case signs the message with the key that does the work and publishes
 * that key, so the signature bytes are valid for it. The control repeats the
 * case with a key of the type a= names.
 */

var helpers    = require("../helpers");
var b          = helpers.b;
var check      = helpers.check;
var nodeCrypto = require("node:crypto");
var ck         = require("../helpers/compromised-keys");

var MSG = "From: ceo@victim.example\r\nTo: a@b.example\r\nSubject: wire\r\n" +
          "Date: Thu, 22 Oct 2026 10:00:00 +0000\r\nMessage-ID: <1@victim.example>\r\n\r\nPay now.\r\n";

var KEY_TYPE_FOR = { "rsa-sha256": "rsa", "ed25519-sha256": "ed25519" };

function _spkiB64(publicKey) {
  return publicKey.export({ type: "spki", format: "der" }).toString("base64");
}

function _labelKey(algorithm) {
  return KEY_TYPE_FOR[algorithm] === "rsa"
    ? nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 })
    : nodeCrypto.generateKeyPairSync("ed25519");
}

async function _signingWith(workKey, fn) {
  var origCreateSign = nodeCrypto.createSign;
  var origSign = nodeCrypto.sign;
  nodeCrypto.createSign = function (alg) {
    var s = origCreateSign(alg);
    var realSign = s.sign.bind(s);
    s.sign = function () { return realSign(workKey); };
    return s;
  };
  nodeCrypto.sign = function (alg, data) {
    return origSign(workKey.asymmetricKeyType === "rsa" ? "sha256" : alg, data, workKey);
  };
  try { return await fn(); }
  finally {
    nodeCrypto.createSign = origCreateSign;
    nodeCrypto.sign = origSign;
  }
}

async function _dkimCase(algorithm, work) {
  var signer = b.mail.dkim.create({
    domain: "victim.example", selector: "s1", privateKey: _labelKey(algorithm).privateKey,
    algorithm: algorithm, audit: false,
  });
  var signed = await _signingWith(work.privateKey, function () { return signer.sign(MSG); });
  b.mail.dkim._resetDkimKeyCacheForTest();
  return b.mail.dkim.verify(signed, {
    audit: false,
    dnsLookup: async function () {
      return [["v=DKIM1; k=" + KEY_TYPE_FOR[algorithm] + "; p=" + _spkiB64(work.publicKey)]];
    },
  });
}

async function _arcCase(algorithm, work) {
  var sealed = await _signingWith(work.privateKey, function () {
    return b.mail.arc.sign({
      rfc822: MSG, instance: 1, authservId: "relay.example", domain: "relay.example",
      selector: "arc", privateKey: _labelKey(algorithm).privateKey,
      algorithm: algorithm, cv: "none", authResults: "dmarc=pass",
      headersToSign: ["From", "To", "Subject", "Date", "Message-ID"],
    }).rfc822;
  });
  var dns = async function (qname) {
    if (qname === "arc._domainkey.relay.example") {
      return [["v=DKIM1; k=" + KEY_TYPE_FOR[algorithm] + "; p=" + _spkiB64(work.publicKey)]];
    }
    var e = new Error("ENOTFOUND " + qname); e.code = "ENOTFOUND"; throw e;
  };
  b.mail.dkim._resetDkimKeyCacheForTest();
  var verdict = await b.mail.arc.verify(sealed, { dnsLookup: dns });
  b.mail.dkim._resetDkimKeyCacheForTest();
  var evaluated = await b.mail.arc.evaluate(sealed, { dnsLookup: dns, trustedSealers: ["relay.example"] });
  return { verdict: verdict, evaluated: evaluated };
}

function _mentions(errors, re) {
  return Array.isArray(errors) && errors.some(function (e) { return re.test(e); });
}

function _rsa(bits) { return nodeCrypto.generateKeyPairSync("rsa", { modulusLength: bits }); }

var EC_CONTROL = ck.ecKeyPair("prime256v1", ck.labelScalar("prime256v1", "mail key binding"));

async function testDkimRequiresTheKeyTypeTheAlgorithmNames() {
  var rsaControl = await _dkimCase("rsa-sha256", _rsa(2048));
  check("dkim key binding control: an RSA key under k=rsa signing rsa-sha256 passes",
        rsaControl.length === 1 && rsaControl[0].result === "pass", JSON.stringify(rsaControl));
  var ecUnderRsa = await _dkimCase("rsa-sha256", EC_CONTROL);
  check("dkim key binding: a P-256 key under k=rsa does not pass an rsa-sha256 signature",
        ecUnderRsa.length === 1 && ecUnderRsa[0].result === "permerror" &&
        _mentions(ecUnderRsa[0].errors, /type ec does not match a=rsa-sha256/), JSON.stringify(ecUnderRsa));

  var edControl = await _dkimCase("ed25519-sha256", nodeCrypto.generateKeyPairSync("ed25519"));
  check("dkim key binding control: an Ed25519 key under k=ed25519 signing ed25519-sha256 passes",
        edControl.length === 1 && edControl[0].result === "pass", JSON.stringify(edControl));
  var rsaUnderEd = await _dkimCase("ed25519-sha256", _rsa(2048));
  check("dkim key binding: an RSA key under k=ed25519 does not pass an ed25519-sha256 signature",
        rsaUnderEd.length === 1 && rsaUnderEd[0].result === "permerror" &&
        _mentions(rsaUnderEd[0].errors, /type rsa does not match a=ed25519-sha256/), JSON.stringify(rsaUnderEd));
  var rsa1024UnderEd = await _dkimCase("ed25519-sha256", _rsa(1024));
  check("dkim key binding: a 1024-bit RSA key under k=ed25519 does not pass an ed25519-sha256 signature",
        rsa1024UnderEd.length === 1 && rsa1024UnderEd[0].result === "permerror", JSON.stringify(rsa1024UnderEd));
}

function _hop(rv) { return rv.verdict.hops[0] || {}; }

async function testArcRequiresTheKeyTypeTheAlgorithmNames() {
  var rsaControl = await _arcCase("rsa-sha256", _rsa(2048));
  check("arc key binding control: an RSA sealer key under k=rsa passes the seal and the message signature",
        rsaControl.verdict.chainStatus === "pass" && _hop(rsaControl).asResult === "pass" &&
        _hop(rsaControl).amsResult === "pass" && rsaControl.evaluated.trusted === true,
        JSON.stringify(_hop(rsaControl)));

  var ecUnderRsa = await _arcCase("rsa-sha256", EC_CONTROL);
  check("arc key binding: a P-256 key under k=rsa does not pass an rsa-sha256 ARC-Seal",
        _hop(ecUnderRsa).asResult === "permerror" &&
        _mentions(_hop(ecUnderRsa).asErrors, /type ec does not match a=rsa-sha256/), JSON.stringify(_hop(ecUnderRsa)));
  check("arc key binding: a P-256 key under k=rsa does not pass an rsa-sha256 ARC-Message-Signature",
        _hop(ecUnderRsa).amsResult === "permerror", JSON.stringify(_hop(ecUnderRsa)));
  check("arc key binding: evaluate does not trust a sealer whose P-256 key sits under k=rsa",
        ecUnderRsa.verdict.chainStatus === "fail" && ecUnderRsa.evaluated.trusted !== true,
        JSON.stringify(ecUnderRsa.evaluated));

  var edControl = await _arcCase("ed25519-sha256", nodeCrypto.generateKeyPairSync("ed25519"));
  check("arc key binding control: an Ed25519 sealer key under k=ed25519 passes",
        edControl.verdict.chainStatus === "pass" && _hop(edControl).asResult === "pass" &&
        _hop(edControl).amsResult === "pass", JSON.stringify(_hop(edControl)));
  var rsaUnderEd = await _arcCase("ed25519-sha256", _rsa(2048));
  check("arc key binding: an RSA key under k=ed25519 does not pass an ed25519-sha256 ARC-Seal",
        _hop(rsaUnderEd).asResult === "permerror" &&
        _mentions(_hop(rsaUnderEd).asErrors, /type rsa does not match a=ed25519-sha256/), JSON.stringify(_hop(rsaUnderEd)));
  check("arc key binding: an RSA key under k=ed25519 does not pass an ed25519-sha256 ARC-Message-Signature",
        _hop(rsaUnderEd).amsResult === "permerror", JSON.stringify(_hop(rsaUnderEd)));
  check("arc key binding: evaluate does not trust a sealer whose RSA key sits under k=ed25519",
        rsaUnderEd.verdict.chainStatus === "fail" && rsaUnderEd.evaluated.trusted !== true,
        JSON.stringify(rsaUnderEd.evaluated));
}

async function testArcSealAppliesTheRsaSizeFloor() {
  var small = await _arcCase("rsa-sha256", _rsa(1024));
  check("arc rsa floor: a 1024-bit RSA sealer key fails the ARC-Seal as too small",
        _hop(small).asResult === "fail" && _mentions(_hop(small).asErrors, /too small/),
        JSON.stringify(_hop(small)));
  check("arc rsa floor: a 1024-bit RSA sealer key fails the ARC-Message-Signature as too small",
        _hop(small).amsResult === "fail" && _mentions(_hop(small).amsErrors, /too small/),
        JSON.stringify(_hop(small)));
}

async function run() {
  await testDkimRequiresTheKeyTypeTheAlgorithmNames();
  await testArcRequiresTheKeyTypeTheAlgorithmNames();
  await testArcSealAppliesTheRsaSizeFloor();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
