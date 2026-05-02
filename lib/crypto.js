"use strict";
/**
 * Centralized crypto module — envelope-versioned PQC primitives.
 *
 * Algorithm suite (modernity bar, per blamejs principle #8):
 *   KEM:        ML-KEM-1024 + P-384 ECDH hybrid (FIPS 203 + classical defense in depth)
 *   Symmetric:  XChaCha20-Poly1305 (24-byte nonce — no nonce-reuse risk under volume)
 *   KDF:        SHAKE256 (FIPS 202)
 *   Hash:       SHA3-512
 *   HMAC:       HMAC-SHA3-512
 *   Signatures: ML-DSA-87 / SLH-DSA-SHAKE-256f (auto-detected from key PEM)
 *
 * Argon2id lives in lib/vault-wrap.js (used to derive vault and
 * audit-signing key passphrases), not here.
 *
 * Envelope versioning (lib/constants.js → ENVELOPE_MAGIC, KEM_IDS, etc.):
 *   byte 0: ENVELOPE_MAGIC (0xE1)
 *   byte 1: KEM ID
 *   byte 2: CIPHER ID
 *   byte 3: KDF ID
 *
 * Old data decrypts under whichever IDs were written into its envelope; new
 * writes use ACTIVE.{KEM, CIPHER, KDF}. Algorithm rotation is forward-only —
 * see roadmap "Modernity posture" for the rotation policy.
 */
var nodeCrypto = require("crypto");
var { xchacha20poly1305 } = require("./vendor/noble-ciphers.cjs");
var C = require("./constants");

// ===========================================================
// Core primitives — everything else is built from these
// ===========================================================

function hash(data, algorithm, outputLength) {
  var opts = outputLength ? { outputLength: outputLength } : undefined;
  return nodeCrypto.createHash(algorithm, opts).update(data).digest();
}

function hmac(key, data, algorithm) {
  return nodeCrypto.createHmac(algorithm, key).update(data).digest("hex");
}

function random(byteLength) {
  var n = byteLength || 32;
  // SHAKE256 over OS-RNG bytes. The OS RNG (nodeCrypto.randomBytes) is
  // already cryptographically secure on modern platforms; passing
  // through a hash adds defense-in-depth (stops a hypothetical
  // randomBytes weakness from being directly observable downstream)
  // without measurable cost. SHAKE256 is the right XOF here because it
  // supports arbitrary output length — the previous implementation
  // used SHA3-512 + subarray, which silently truncated to 64 bytes
  // when callers requested more. SHAKE256 is also already the
  // framework's KDF / browser-side derivation primitive, so the same
  // hash family does double duty.
  return nodeCrypto.createHash("shake256", { outputLength: n })
    .update(nodeCrypto.randomBytes(n))
    .digest();
}

function generateKeyPair(algorithm, options) {
  var pair = nodeCrypto.generateKeyPairSync(algorithm, Object.assign({
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  }, options || {}));
  return { publicKey: pair.publicKey, privateKey: pair.privateKey };
}

function timingSafeEqual(a, b) {
  var bufA = Buffer.isBuffer(a) ? a : Buffer.from(String(a));
  var bufB = Buffer.isBuffer(b) ? b : Buffer.from(String(b));
  if (bufA.length !== bufB.length) return false;
  return nodeCrypto.timingSafeEqual(bufA, bufB);
}

// ===========================================================
// Public API — built on core primitives
// ===========================================================

// ---- Hashing ----
function sha3Hash(data) { return hash(data, "sha3-512").toString("hex"); }
function hmacSha3(key, data) { return hmac(key, data, "sha3-512"); }

// (SHA-1 is intentionally NOT exported from b.crypto. The framework's
//  only legitimate SHA-1 use is the HaveIBeenPwned k-anonymity API in
//  lib/auth/password.js, which imports lib/internal-sha1-hibp.js
//  directly. Public b.crypto.sha1* is permanently off the table — a
//  future caller wanting SHA-1 for storage / signing / fingerprinting
//  would re-introduce a broken primitive into the crypto surface this
//  framework spent every other line keeping out.)

// ---- KDF ----
function kdf(input, outputLength) { return hash(input, "shake256", outputLength); }

// ---- Random ----
function generateBytes(byteLength) { return Buffer.from(random(byteLength)); }
function generateToken(byteLength) { return random(byteLength || 32).toString("hex"); }

// ---- Key generation ----
function generateEncryptionKeyPair() {
  var mlkem = generateKeyPair("ml-kem-1024");
  var ec = generateKeyPair("ec", { namedCurve: "P-384" });
  return {
    publicKey:    mlkem.publicKey,
    privateKey:   mlkem.privateKey,
    ecPublicKey:  ec.publicKey,
    ecPrivateKey: ec.privateKey,
  };
}

function generateSigningKeyPair(algorithm) {
  return generateKeyPair(algorithm || "ml-dsa-87");
}

// ---- Signatures (auto-detect algorithm from key PEM) ----
function sign(data, privateKeyPem) {
  return nodeCrypto.sign(null, Buffer.from(data), privateKeyPem);
}

function verify(data, signature, publicKeyPem) {
  return nodeCrypto.verify(null, Buffer.from(data), publicKeyPem, signature);
}

// ---- Envelope encrypt (ML-KEM-1024 + P-384 ECDH hybrid + SHAKE256 + XChaCha20) ----
function encrypt(plaintext, publicKeys) {
  var mlkemPubPem = typeof publicKeys === "string" ? publicKeys : publicKeys.publicKey;
  var ecPubPem = typeof publicKeys === "string" ? null : publicKeys.ecPublicKey;
  if (!ecPubPem) return encryptMlkemOnly(plaintext, mlkemPubPem);

  var mlkemPub = nodeCrypto.createPublicKey(mlkemPubPem);
  var kem = nodeCrypto.encapsulate(mlkemPub);
  var ephEc = generateKeyPair("ec", {
    namedCurve: "P-384",
    publicKeyEncoding:  { type: "spki",  format: "der" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  var ecSs = nodeCrypto.diffieHellman({
    privateKey: nodeCrypto.createPrivateKey(ephEc.privateKey),
    publicKey:  nodeCrypto.createPublicKey(ecPubPem),
  });
  var key = kdf(Buffer.concat([kem.sharedKey, ecSs]), 32);
  var nonce = generateBytes(24);
  var ct = xchacha20poly1305(key, nonce).encrypt(Buffer.from(plaintext, "utf8"));

  var kemCtLen = Buffer.alloc(2); kemCtLen.writeUInt16BE(kem.ciphertext.length);
  var ecEphDer = ephEc.publicKey;
  var ecEphLen = Buffer.alloc(2); ecEphLen.writeUInt16BE(ecEphDer.length);

  return Buffer.concat([
    Buffer.from([C.ENVELOPE_MAGIC, C.ACTIVE.KEM, C.ACTIVE.CIPHER, C.ACTIVE.KDF]),
    kemCtLen, kem.ciphertext, ecEphLen, ecEphDer, nonce, Buffer.from(ct),
  ]).toString("base64");
}

function encryptMlkemOnly(plaintext, publicKeyPem) {
  var kem = nodeCrypto.encapsulate(nodeCrypto.createPublicKey(publicKeyPem));
  var key = kdf(kem.sharedKey, 32);
  var nonce = generateBytes(24);
  var ct = xchacha20poly1305(key, nonce).encrypt(Buffer.from(plaintext, "utf8"));
  var kemCtLen = Buffer.alloc(2); kemCtLen.writeUInt16BE(kem.ciphertext.length);
  return Buffer.concat([
    Buffer.from([C.ENVELOPE_MAGIC, C.KEM_IDS.ML_KEM_1024, C.ACTIVE.CIPHER, C.ACTIVE.KDF]),
    kemCtLen, kem.ciphertext, nonce, Buffer.from(ct),
  ]).toString("base64");
}

// ---- Envelope decrypt (dispatches on envelope IDs, supports both KEM IDs) ----
function decrypt(ciphertext, privateKeys) {
  var packed = Buffer.from(ciphertext, "base64");
  if (packed[0] !== C.ENVELOPE_MAGIC) {
    throw new Error("Invalid envelope: unsupported format");
  }
  return decryptEnvelope(packed, privateKeys);
}

function decryptEnvelope(packed, privateKeys) {
  var kemId = packed[1], cipherId = packed[2], kdfId = packed[3], pos = 4;

  if (cipherId !== C.CIPHER_IDS.XCHACHA20_POLY1305) {
    throw new Error("Invalid envelope: unsupported cipher (only XChaCha20-Poly1305 supported)");
  }
  if (kdfId !== C.KDF_IDS.SHAKE256) {
    throw new Error("Invalid envelope: unsupported KDF (only SHAKE256 supported)");
  }

  var kemCtLen = packed.readUInt16BE(pos); pos += 2;
  var kemCt = packed.subarray(pos, pos + kemCtLen); pos += kemCtLen;

  var mlkemPriv = nodeCrypto.createPrivateKey(
    typeof privateKeys === "string" ? privateKeys : privateKeys.privateKey
  );
  var mlkemSs = nodeCrypto.decapsulate(mlkemPriv, kemCt);
  var symmetricKey;

  if (kemId === C.KEM_IDS.ML_KEM_1024_P384) {
    var ecEphLen = packed.readUInt16BE(pos); pos += 2;
    var ecEphDer = packed.subarray(pos, pos + ecEphLen); pos += ecEphLen;
    var ecPrivPem = typeof privateKeys === "string" ? null : privateKeys.ecPrivateKey;
    if (!ecPrivPem) throw new Error("Hybrid KEM requires EC private key");
    var ecSs = nodeCrypto.diffieHellman({
      privateKey: nodeCrypto.createPrivateKey(ecPrivPem),
      publicKey:  nodeCrypto.createPublicKey({ key: ecEphDer, type: "spki", format: "der" }),
    });
    symmetricKey = kdf(Buffer.concat([mlkemSs, ecSs]), 32);
  } else if (kemId === C.KEM_IDS.ML_KEM_1024) {
    symmetricKey = kdf(mlkemSs, 32);
  } else {
    throw new Error("Invalid envelope: unsupported KEM ID " + kemId);
  }

  var nonce = packed.subarray(pos, pos + 24); pos += 24;
  return Buffer.from(
    xchacha20poly1305(symmetricKey, nonce).decrypt(packed.subarray(pos))
  ).toString("utf8");
}

// ---- Symmetric buffer encrypt/decrypt (for storage) ----
//
// Optional `aad` (additional authenticated data) is mixed into the
// Poly1305 tag — encrypt-time and decrypt-time AAD must match exactly
// or decrypt fails. Used by primitives that want encryption-context
// binding (b.breakGlass.encryptCell binds (table, rowId, column) so a
// ciphertext from row A literally cannot decrypt as row B even with
// the same key).
function encryptPacked(buffer, key, aad) {
  var nonce = random(24);
  var ct = xchacha20poly1305(key, nonce, aad ? Buffer.from(aad) : undefined).encrypt(buffer);
  return Buffer.concat([
    Buffer.from([C.FORMAT.XCHACHA20_POLY1305]),
    Buffer.from(nonce),
    Buffer.from(ct),
  ]);
}

function decryptPacked(packed, key, aad) {
  if (packed[0] !== C.FORMAT.XCHACHA20_POLY1305) {
    throw new Error("Invalid packed format: unsupported version");
  }
  return Buffer.from(
    xchacha20poly1305(key, packed.subarray(1, 25), aad ? Buffer.from(aad) : undefined)
      .decrypt(packed.subarray(25))
  );
}

module.exports = {
  // Hashing
  sha3Hash:                    sha3Hash,
  hmacSha3:                    hmacSha3,
  kdf:                         kdf,
  // Comparison
  timingSafeEqual:             timingSafeEqual,
  // Random
  generateBytes:               generateBytes,
  generateToken:               generateToken,
  // Keys
  generateEncryptionKeyPair:   generateEncryptionKeyPair,
  generateSigningKeyPair:      generateSigningKeyPair,
  // Signatures
  sign:                        sign,
  verify:                      verify,
  // Envelope encrypt/decrypt
  encrypt:                     encrypt,
  decrypt:                     decrypt,
  // Symmetric buffer encrypt/decrypt
  encryptPacked:               encryptPacked,
  decryptPacked:               decryptPacked,
};
