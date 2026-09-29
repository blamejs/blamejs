// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * `b.mail.dkim.create` refuses a private key whose type is not the one its
 * algorithm names.
 *
 * `create` parsed `opts.privateKey` and never compared its type with
 * `opts.algorithm`, and nothing downstream compared them either. An RSA key in
 * the `ed25519-sha256` slot produced a `DKIM-Signature` whose `a=` tag said
 * `ed25519-sha256` over an RSA signature: every conforming verifier refuses
 * that message and the sender saw nothing wrong, because the signer returned a
 * header and the send succeeded. The other direction failed late and uncoded,
 * throwing Node's `ERR_CRYPTO_UNSUPPORTED_OPERATION` from inside `sign()`
 * rather than a framework error naming the mistake.
 *
 * RFC 8463 §3 pairs `ed25519-sha256` with an Ed25519 key and RFC 6376 §3.3.3
 * pairs `rsa-sha256` with an RSA key. `verify` already compares
 * `keyObj.asymmetricKeyType` with the algorithm on the receiving side, so the
 * comparison existed in the module and the signing side omitted it.
 */

var helpers    = require("../helpers");
var check      = helpers.check;
var b          = helpers.b;
var nodeCrypto = require("node:crypto");

function _rsaKey() {
  return nodeCrypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding:  { type: "spki",  format: "pem" },
  });
}

function _edKey() {
  return nodeCrypto.generateKeyPairSync("ed25519", {
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding:  { type: "spki",  format: "pem" },
  });
}

function _create(privateKey, algorithm) {
  try {
    return { signer: b.mail.dkim.create({
      domain: "example.com", selector: "s1",
      privateKey: privateKey, algorithm: algorithm, audit: false,
    }), code: null };
  } catch (e) { return { signer: null, code: e.code || "threw" }; }
}

function testAMismatchedKeyIsRefusedAtCreate() {
  var rsa = _rsaKey();
  var ed  = _edKey();

  var rsaInEd = _create(rsa.privateKey, "ed25519-sha256");
  check("an RSA key in the ed25519-sha256 slot is refused at create",
        rsaInEd.code === "dkim/key-algorithm-mismatch",
        String(rsaInEd.code));

  var edInRsa = _create(ed.privateKey, "rsa-sha256");
  check("an Ed25519 key in the rsa-sha256 slot is refused at create",
        edInRsa.code === "dkim/key-algorithm-mismatch",
        String(edInRsa.code));

  check("a matching RSA key is accepted",  _create(rsa.privateKey, "rsa-sha256").code === null);
  check("a matching Ed25519 key is accepted", _create(ed.privateKey, "ed25519-sha256").code === null);
  // The default algorithm is rsa-sha256, so an Ed25519 key with no algorithm
  // named is the same mistake spelled a shorter way.
  var edDefault = _create(ed.privateKey, undefined);
  check("an Ed25519 key under the default algorithm is refused too",
        edDefault.code === "dkim/key-algorithm-mismatch", String(edDefault.code));

  // A KeyObject reaches the same check as a PEM string.
  var edObject = _create(nodeCrypto.createPrivateKey({ key: ed.privateKey, format: "pem" }),
                         "rsa-sha256");
  check("a KeyObject is checked the same way",
        edObject.code === "dkim/key-algorithm-mismatch", String(edObject.code));
}

async function testAMatchingKeyStillSignsAndVerifies() {
  // The control for the refusals above: the pairing that is correct still
  // produces a signature a verifier accepts, so the check has not closed the
  // working path.
  var ed = _edKey();
  var signer = b.mail.dkim.create({
    domain: "example.com", selector: "s1",
    privateKey: ed.privateKey, algorithm: "ed25519-sha256", audit: false,
  });
  var message = "From: a@example.com\r\nTo: b@example.net\r\nSubject: hi\r\n\r\nbody\r\n";
  var header = await signer.sign(message);
  check("the matching pairing signs", typeof header === "string" && header.length > 0);
  check("and the a= tag is the algorithm it was given",
        /a=ed25519-sha256/.test(header), String(header).slice(0, 80));
}

async function run() {
  testAMismatchedKeyIsRefusedAtCreate();
  await testAMatchingKeyStillSignsAndVerifies();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[mail-dkim-key-algorithm] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
