// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.mail.crypto.pgp.verify refuses a verification key that is compromised
 * (the eDellRoot RSA key, whose private half Dell shipped in 2015) with
 * `mail-crypto/pgp/compromised-key`, before it looks at the signature.
 * b.mail.crypto.pgp.sign refuses a compromised signing key with the same code.
 *
 * The test has no copy of the eDellRoot private key, so it stands in for a
 * signer who holds it. EDELLROOT_SIGNATURE is a detached signature whose
 * Issuer Fingerprint is the eDellRoot key's, and while the verify case runs,
 * node:crypto's verify reports a valid signature for that key. The control
 * builds the same kind of signature for a fresh RSA key and passes, so the
 * refusal comes from the key and not from the signature bytes.
 *
 * sign accepts RSA and Ed25519 keys only, so the sign case gives it an RSA
 * private key whose public half reads as the eDellRoot key.
 */

var helpers    = require("../helpers");
var b          = helpers.b;
var check      = helpers.check;
var nodeCrypto = require("node:crypto");
var ck         = require("../helpers/compromised-keys");

var pgp = b.mail.crypto.pgp;
var QUIET = { safeEmit: function () {} };
var MESSAGE = "Pay invoice 4411 to the new account.";
var CREATION_TIME = 1790000000;

var EDELLROOT_PUBLIC = new nodeCrypto.X509Certificate(ck.EDELLROOT_CERT_PEM).publicKey;
var EDELLROOT_PUBLIC_PEM = EDELLROOT_PUBLIC.export({ type: "spki", format: "pem" });

var EDELLROOT_SIGNATURE =
  "-----BEGIN PGP SIGNATURE-----\r\n\r\n" +
  "wsBpBAABCAAdBQJqsTuAFiEEiWWP7Zg7OFYxs3jwRQb5TiBE12oAAOVLB/4210pl\r\n" +
  "GhWUAtTaemg6m7Jr6BAwtpB0Am7BxZMsHASo8oeU67qOtKiXk4e/N+o0lP4WWSCW\r\n" +
  "M9wyDgjy9f5LimrrURUXsFF7zO/bH9nQH2zb06yffSAw2hKp99v7y/7EDEWJrkx0\r\n" +
  "DGn1nbm05elfV0M0CT8S24TF/BD7YP+55PZMhpUjk0ZMhMQSL1OFGZDgFrkD/3tV\r\n" +
  "mZUUrt1OkxKZnE7P7K0HwPUI+7VV8QrF3HdHlzmJVoR7H2TTiviZLwMao1Oh3DYd\r\n" +
  "YxIsUYl3VBmBO8whfuXb+NKAghKxBuq0rBSXiapPQSijfefZKKXGBpKlWC45lRMm\r\n" +
  "rlthXJCNUMtyFkaY\r\n" +
  "=OEUG\r\n" +
  "-----END PGP SIGNATURE-----\r\n";

function _rsaPem() {
  return nodeCrypto.generateKeyPairSync("rsa", {
    modulusLength: 2048, privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });
}

function _publicHalfReadsAs(standIn, privatePem, fn) {
  var origCreatePublicKey = nodeCrypto.createPublicKey;
  var mine = origCreatePublicKey(privatePem);
  nodeCrypto.createPublicKey = function (input) {
    var real = origCreatePublicKey.apply(nodeCrypto, arguments);
    if (input instanceof nodeCrypto.KeyObject && input.type === "private" && real.equals(mine)) return standIn;
    return real;
  };
  try { return fn(); }
  finally { nodeCrypto.createPublicKey = origCreatePublicKey; }
}

function _verifyForged(armored, publicKey) {
  var origVerify = nodeCrypto.verify;
  var state = { calls: 0 };
  nodeCrypto.verify = function (alg, data, key) {
    var k = key instanceof nodeCrypto.KeyObject ? key : (key && key.key);
    if (k instanceof nodeCrypto.KeyObject && k.type === "public" && k.equals(publicKey)) {
      state.calls += 1;
      return true;
    }
    return origVerify.apply(nodeCrypto, arguments);
  };
  try {
    state.rv = pgp.verify({
      message: MESSAGE, armored: armored, audit: QUIET,
      publicKeyPem: publicKey.export({ type: "spki", format: "pem" }),
    });
    return state;
  } finally {
    nodeCrypto.verify = origVerify;
  }
}

function testAListedVerificationKeyIsRefusedForAForgedSignature() {
  var control = nodeCrypto.createPublicKey(_rsaPem().publicKey);
  var controlSigner = _rsaPem();
  var controlArmored = _publicHalfReadsAs(control, controlSigner.privateKey, function () {
    return pgp.sign({
      message: MESSAGE, privateKeyPem: controlSigner.privateKey, creationTime: CREATION_TIME, audit: QUIET,
    }).armored;
  });
  var good = _verifyForged(controlArmored, control);
  check("pgp compromised key control: a signature that verifies under an ordinary key is accepted",
        good.rv.ok === true && good.calls === 1, JSON.stringify(good));

  var bad = _verifyForged(EDELLROOT_SIGNATURE, EDELLROOT_PUBLIC);
  check("pgp compromised key: verify refuses a signature that verifies under the eDellRoot key",
        bad.rv.ok === false && bad.rv.code === "mail-crypto/pgp/compromised-key", JSON.stringify(bad));
  check("pgp compromised key: verify is never called with the eDellRoot key", bad.calls === 0, String(bad.calls));

  var plain = pgp.verify({
    message: MESSAGE, armored: EDELLROOT_SIGNATURE, publicKeyPem: EDELLROOT_PUBLIC_PEM, audit: QUIET,
  });
  check("pgp compromised key: verify refuses the eDellRoot key with the signature bytes left alone",
        plain.ok === false && plain.code === "mail-crypto/pgp/compromised-key", JSON.stringify(plain));
}

function _signCode(privatePem) {
  try {
    pgp.sign({ message: MESSAGE, privateKeyPem: privatePem, creationTime: CREATION_TIME, audit: QUIET });
    return "signed";
  } catch (e) { return e.code || String(e); }
}

function testSignRefusesACompromisedSigningKey() {
  var control = _rsaPem();
  var controlCode = _publicHalfReadsAs(nodeCrypto.createPublicKey(_rsaPem().publicKey), control.privateKey,
    function () { return _signCode(control.privateKey); });
  check("pgp sign control: an ordinary RSA signing key signs", controlCode === "signed", controlCode);

  var listed = _rsaPem();
  var listedCode = _publicHalfReadsAs(EDELLROOT_PUBLIC, listed.privateKey,
    function () { return _signCode(listed.privateKey); });
  check("pgp sign: a signing key whose public half is the eDellRoot key is refused",
        listedCode === "mail-crypto/pgp/compromised-key", listedCode);
}

async function run() {
  testAListedVerificationKeyIsRefusedForAForgedSignature();
  testSignRefusesACompromisedSigningKey();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
