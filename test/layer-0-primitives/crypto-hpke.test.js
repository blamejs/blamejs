// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.crypto.hpke: the blamejs ML-KEM-1024 + HKDF-SHA3-512 +
 * XChaCha20-Poly1305 sealing format. It does not interoperate with
 * RFC 9180; b.crypto.hpke.pq carries the RFC 9180 suites.
 *
 * Round-trip + AAD binding + info binding (a different info string derives
 * a different key) + tampered-ciphertext rejection.
 */

var nodeCrypto = require("node:crypto");
var helpers    = require("../helpers");
var b          = helpers.b;
var check      = helpers.check;

function testSurface() {
  check("crypto.hpke namespace exposed",
        b.crypto.hpke && typeof b.crypto.hpke === "object");
  check("crypto.hpke.seal is a function",
        typeof b.crypto.hpke.seal === "function");
  check("crypto.hpke.open is a function",
        typeof b.crypto.hpke.open === "function");
  check("crypto.hpke.generateKeyPair is a function",
        typeof b.crypto.hpke.generateKeyPair === "function");
  check("crypto.hpke.SUPPORTED_SUITE describes ML-KEM-1024",
        b.crypto.hpke.SUPPORTED_SUITE.kem === "ML-KEM-1024");
  check("crypto.hpke.HpkeError is a class",
        typeof b.crypto.hpke.HpkeError === "function");
}

// The envelope's AEAD is XChaCha20-Poly1305 with a 24-byte nonce, which has
// no HPKE AEAD id; the suite description names the cipher that runs.
function testSuiteDescribesTheCipherThatRuns() {
  check("SUPPORTED_SUITE.aead names XChaCha20-Poly1305",
        b.crypto.hpke.SUPPORTED_SUITE.aead === "XChaCha20-Poly1305",
        b.crypto.hpke.SUPPORTED_SUITE.aead);
  check("SUPPORTED_SUITE.kdf names HKDF-SHA3-512",
        b.crypto.hpke.SUPPORTED_SUITE.kdf === "HKDF-SHA3-512");
  check("SUPPORTED_SUITE.label is the blamejs format label",
        b.crypto.hpke.SUPPORTED_SUITE.label === "blamejs/hpke/v1");

  // A 24-byte-nonce AEAD: the ciphertext is the plaintext plus a 16-byte
  // Poly1305 tag, and the envelope carries no nonce of its own.
  var pair = b.crypto.hpke.generateKeyPair();
  var sealed = b.crypto.hpke.seal({ recipientPubKey: pair.publicKey, plaintext: "abc" });
  check("ciphertext is plaintext + 16-byte tag", sealed.ciphertext.length === 3 + 16);
}

function testRoundTrip() {
  var pair = b.crypto.hpke.generateKeyPair();
  check("generateKeyPair returns ML-KEM-1024 PEMs",
        typeof pair.publicKey === "string" &&
        /^-----BEGIN PUBLIC KEY-----/.test(pair.publicKey) &&
        typeof pair.privateKey === "string" &&
        /^-----BEGIN PRIVATE KEY-----/.test(pair.privateKey));

  var pt = "hello hpke";
  var sealed = b.crypto.hpke.seal({
    recipientPubKey: pair.publicKey,
    plaintext:       pt,
    info:            "session-1",
    aad:             "tenant-acme",
  });
  check("seal returns Buffer enc + ciphertext",
        Buffer.isBuffer(sealed.enc) && Buffer.isBuffer(sealed.ciphertext));

  var recovered = b.crypto.hpke.open({
    privateKey:  pair.privateKey,
    enc:         sealed.enc,
    ciphertext:  sealed.ciphertext,
    info:        "session-1",
    aad:         "tenant-acme",
  });
  check("round-trip recovers the plaintext",
        recovered.toString("utf8") === pt);
}

function testAadBinding() {
  var pair = b.crypto.hpke.generateKeyPair();
  var sealed = b.crypto.hpke.seal({
    recipientPubKey: pair.publicKey,
    plaintext:       "secret",
    info:            "info-x",
    aad:             "aad-1",
  });

  var threwAad = null;
  try {
    b.crypto.hpke.open({
      privateKey:  pair.privateKey,
      enc:         sealed.enc,
      ciphertext:  sealed.ciphertext,
      info:        "info-x",
      aad:         "aad-DIFFERENT",
    });
  } catch (e) { threwAad = e; }
  check("AAD mismatch refuses decrypt",
        threwAad && threwAad.code === "crypto-hpke/aead-decrypt-failed");

  var threwInfo = null;
  try {
    b.crypto.hpke.open({
      privateKey:  pair.privateKey,
      enc:         sealed.enc,
      ciphertext:  sealed.ciphertext,
      info:        "info-DIFFERENT",
      aad:         "aad-1",
    });
  } catch (e) { threwInfo = e; }
  check("info-string mismatch refuses decrypt (info binding)",
        threwInfo && threwInfo.code === "crypto-hpke/aead-decrypt-failed");
}

function testTamperedCiphertext() {
  var pair = b.crypto.hpke.generateKeyPair();
  var sealed = b.crypto.hpke.seal({
    recipientPubKey: pair.publicKey,
    plaintext:       "tampered-test",
    info:            "i",
    aad:             "a",
  });
  var tampered = Buffer.from(sealed.ciphertext);
  tampered[tampered.length - 1] ^= 0x01;
  var threw = null;
  try {
    b.crypto.hpke.open({
      privateKey:  pair.privateKey,
      enc:         sealed.enc,
      ciphertext:  tampered,
      info:        "i",
      aad:         "a",
    });
  } catch (e) { threw = e; }
  check("tampered ciphertext refuses decrypt",
        threw && threw.code === "crypto-hpke/aead-decrypt-failed");
}

function testValidation() {
  var threwOpts = null;
  try { b.crypto.hpke.seal(null); } catch (e) { threwOpts = e; }
  check("seal(null) throws", threwOpts && threwOpts.code === "validate-opts/bad-object");

  var threwPub = null;
  try { b.crypto.hpke.seal({ recipientPubKey: 123, plaintext: "x" }); }
  catch (e) { threwPub = e; }
  check("non-string recipientPubKey throws",
        threwPub && threwPub.code === "crypto-hpke/bad-opt");

  var threwPt = null;
  try { b.crypto.hpke.seal({ recipientPubKey: "PEM", plaintext: 42 }); }
  catch (e) { threwPt = e; }
  check("non-string/Buffer plaintext throws",
        threwPt && threwPt.code === "crypto-hpke/bad-opt");

  var threwBadPem = null;
  try { b.crypto.hpke.seal({ recipientPubKey: "not a pem", plaintext: "x" }); }
  catch (e) { threwBadPem = e; }
  check("unreadable recipientPubKey throws crypto-hpke/bad-key",
        threwBadPem && threwBadPem.code === "crypto-hpke/bad-key",
        threwBadPem && (threwBadPem.code + " " + threwBadPem.message));

  var threwBadPriv = null;
  try { b.crypto.hpke.open({ privateKey: "not a pem", enc: Buffer.alloc(1568), ciphertext: Buffer.alloc(16) }); }
  catch (e) { threwBadPriv = e; }
  check("unreadable privateKey throws crypto-hpke/bad-key",
        threwBadPriv && threwBadPriv.code === "crypto-hpke/bad-key",
        threwBadPriv && (threwBadPriv.code + " " + threwBadPriv.message));

  var threwOpenEnc = null;
  try { b.crypto.hpke.open({ privateKey: "x", enc: "not-a-buffer", ciphertext: Buffer.alloc(0) }); }
  catch (e) { threwOpenEnc = e; }
  check("open with non-Buffer enc throws",
        threwOpenEnc && threwOpenEnc.code === "crypto-hpke/bad-opt");
}

// node:crypto encapsulates to any KEM-capable key: RSA, EC, X25519, X448 and
// the smaller ML-KEM parameter sets. The envelope is ML-KEM-1024 only, so a
// key of any other type is refused on both sides before it is used.
function testRefusesKeysThatAreNotMlKem1024() {
  var pemEncoding = {
    publicKeyEncoding:  { type: "spki",  format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  };
  [["x25519", {}], ["x448", {}], ["ec", { namedCurve: "P-256" }],
   ["rsa", { modulusLength: 2048 }], ["ml-kem-512", {}], ["ml-kem-768", {}]].forEach(function (row) {
    var pair = nodeCrypto.generateKeyPairSync(row[0], Object.assign({}, row[1], pemEncoding));
    var sealErr = null;
    try { b.crypto.hpke.seal({ recipientPubKey: pair.publicKey, plaintext: "x" }); }
    catch (e) { sealErr = e; }
    check("seal refuses a " + row[0] + " public key with crypto-hpke/bad-key",
          sealErr && sealErr.code === "crypto-hpke/bad-key",
          sealErr ? (sealErr.code + " " + sealErr.message) : "sealed without error");
    var openErr = null;
    try { b.crypto.hpke.open({ privateKey: pair.privateKey, enc: Buffer.alloc(1568), ciphertext: Buffer.alloc(16) }); }
    catch (e) { openErr = e; }
    check("open refuses a " + row[0] + " private key with crypto-hpke/bad-key",
          openErr && openErr.code === "crypto-hpke/bad-key",
          openErr ? (openErr.code + " " + openErr.message) : "opened without error");
  });
}

async function run() {
  testSurface();
  testSuiteDescribesTheCipherThatRuns();
  testRoundTrip();
  testAadBinding();
  testTamperedCiphertext();
  testValidation();
  testRefusesKeysThatAreNotMlKem1024();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
