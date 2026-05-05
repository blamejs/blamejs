"use strict";
/**
 * b.crypto.encryptMlkem768X25519 + b.crypto.decrypt — round-trip
 * test for the IETF / Cloudflare / Chrome TLS-interop hybrid
 * (codepoint 0x11EC). Same envelope-format dispatch as the framework's
 * default ML-KEM-1024+P-384 hybrid, just using the 768+X25519 keys
 * for cross-system interop.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function testSurface() {
  check("crypto.generateMlkem768X25519KeyPair is a function",
        typeof b.crypto.generateMlkem768X25519KeyPair === "function");
  check("crypto.encryptMlkem768X25519 is a function",
        typeof b.crypto.encryptMlkem768X25519 === "function");
  check("crypto.SUPPORTED_KEM_ALGORITHMS is exposed",
        Array.isArray(b.crypto.SUPPORTED_KEM_ALGORITHMS) &&
        Object.isFrozen(b.crypto.SUPPORTED_KEM_ALGORITHMS));
  check("ml-kem-768-x25519 is in SUPPORTED_KEM_ALGORITHMS",
        b.crypto.SUPPORTED_KEM_ALGORITHMS.some(function (a) {
          return a.id === "ml-kem-768-x25519";
        }));
}

function testGenerateKeypair() {
  var pair = b.crypto.generateMlkem768X25519KeyPair();
  check("generateMlkem768X25519KeyPair returns 4 keys",
        pair && pair.mlkemPublicKey && pair.mlkemPrivateKey &&
        pair.x25519PublicKey && pair.x25519PrivateKey);
  check("ML-KEM-768 public key is PEM",
        typeof pair.mlkemPublicKey === "string" &&
        /^-----BEGIN PUBLIC KEY-----/.test(pair.mlkemPublicKey));
  check("X25519 public key is PEM",
        typeof pair.x25519PublicKey === "string" &&
        /^-----BEGIN PUBLIC KEY-----/.test(pair.x25519PublicKey));
}

function testRoundTrip() {
  var pair = b.crypto.generateMlkem768X25519KeyPair();
  var plaintext = "hello from ml-kem-768 + x25519 hybrid envelope";
  var envelope = b.crypto.encryptMlkem768X25519(plaintext, {
    mlkemPublicKey:   pair.mlkemPublicKey,
    x25519PublicKey:  pair.x25519PublicKey,
  });
  check("envelope is base64 string",
        typeof envelope === "string" && envelope.length > 0);
  // Decrypt via the existing decrypt() — dispatches on KEM ID 0x04.
  var decrypted = b.crypto.decrypt(envelope, {
    privateKey:       pair.mlkemPrivateKey,    // ML-KEM-768 PEM
    x25519PrivateKey: pair.x25519PrivateKey,
  });
  check("round-trip recovers the plaintext",
        decrypted === plaintext);
}

function testRecipientShape() {
  var threw = null;
  try { b.crypto.encryptMlkem768X25519("x", {}); }
  catch (e) { threw = e; }
  check("encrypt without recipient keys throws",
        threw && /requires.*mlkemPublicKey.*x25519PublicKey/.test(threw.message));
}

async function run() {
  testSurface();
  testGenerateKeypair();
  testRoundTrip();
  testRecipientShape();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
