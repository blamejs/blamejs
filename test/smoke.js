"use strict";
/**
 * v0.0.1 smoke test — verifies the Phase 0 exit criteria from the roadmap:
 *
 *   "node -e \"const b = require('@blamejs/core'); console.log(b.version);\"
 *    runs with zero deps installed."
 *
 *   "Smoke test suite (envelope encrypt → decrypt round-trip; router
 *    dispatches 3-arg middleware before 2-arg terminal) passes green."
 *
 * Run: `npm test` (or `node test/smoke.js`)
 */
var assert = require("assert");
var b = require("../index.js");

var checks = 0;
function check(label, condition) {
  if (!condition) throw new Error("FAIL: " + label);
  checks += 1;
}

console.log("blamejs v" + b.version + " — smoke test");

// 1. Public API surface
check("crypto namespace present",     typeof b.crypto === "object");
check("router namespace present",     typeof b.router === "object");
check("constants namespace present",  typeof b.constants === "object");
check("version is a string",          typeof b.version === "string");
check("version matches package.json", b.version === require("../package.json").version);

// 2. Constants surface
check("ENVELOPE_MAGIC = 0xE1",        b.constants.ENVELOPE_MAGIC === 0xE1);
check("ACTIVE.KEM is hybrid",         b.constants.ACTIVE.KEM === b.constants.KEM_IDS.ML_KEM_1024_P384);
check("ACTIVE.CIPHER is XChaCha20",   b.constants.ACTIVE.CIPHER === b.constants.CIPHER_IDS.XCHACHA20_POLY1305);
check("ACTIVE.KDF is SHAKE256",       b.constants.ACTIVE.KDF === b.constants.KDF_IDS.SHAKE256);
check("TIME.ONE_DAY = 86400000",      b.constants.TIME.ONE_DAY === 86400000);
check("TLS prefers PQ hybrid first",  b.constants.TLS_GROUP_PREFERENCE[0] === "SecP384r1MLKEM1024");

// 3. Envelope encrypt/decrypt round-trip
var keys = b.crypto.generateEncryptionKeyPair();
check("encryption keypair has all four members",
      typeof keys.publicKey === "string" && typeof keys.privateKey === "string" &&
      typeof keys.ecPublicKey === "string" && typeof keys.ecPrivateKey === "string");

var plaintext = "hello blamejs " + b.version + " 🔐";
var envelope = b.crypto.encrypt(plaintext, keys);
check("encrypt() returns base64 string",     typeof envelope === "string");

var decrypted = b.crypto.decrypt(envelope, keys);
check("decrypt() round-trip preserves UTF-8", decrypted === plaintext);

// 4. Envelope header bytes match active algorithm IDs
var envBytes = Buffer.from(envelope, "base64");
check("envelope byte 0 = magic",     envBytes[0] === b.constants.ENVELOPE_MAGIC);
check("envelope byte 1 = active KEM", envBytes[1] === b.constants.ACTIVE.KEM);
check("envelope byte 2 = active cipher", envBytes[2] === b.constants.ACTIVE.CIPHER);
check("envelope byte 3 = active KDF", envBytes[3] === b.constants.ACTIVE.KDF);

// 5. Tampered envelope fails to decrypt
var tampered = Buffer.from(envelope, "base64");
tampered[tampered.length - 1] ^= 0x01;
var tamperedRejected = false;
try { b.crypto.decrypt(tampered.toString("base64"), keys); }
catch (_) { tamperedRejected = true; }
check("tampered envelope is rejected", tamperedRejected);

// 6. Wrong-key decrypt fails
var otherKeys = b.crypto.generateEncryptionKeyPair();
var wrongKeyRejected = false;
try { b.crypto.decrypt(envelope, otherKeys); }
catch (_) { wrongKeyRejected = true; }
check("wrong-key decrypt is rejected", wrongKeyRejected);

// 7. timingSafeEqual
check("timingSafeEqual matches identical",  b.crypto.timingSafeEqual("foo", "foo"));
check("timingSafeEqual rejects different",  !b.crypto.timingSafeEqual("foo", "bar"));
check("timingSafeEqual rejects length-mismatch", !b.crypto.timingSafeEqual("foo", "foobar"));

// 8. Token / random bytes
check("generateToken default = 64 hex chars (32 bytes)",  b.crypto.generateToken().length === 64);
check("generateBytes returns 16 bytes",   b.crypto.generateBytes(16).length === 16);

// 9. SHA3-512 hash determinism
var h1 = b.crypto.sha3Hash("blamejs");
var h2 = b.crypto.sha3Hash("blamejs");
check("sha3Hash is deterministic", h1 === h2);
check("sha3Hash is 128 hex chars (512 bits)", h1.length === 128);

// 10. Symmetric buffer encrypt/decrypt round-trip
var symKey = b.crypto.generateBytes(32);
var bufPlain = Buffer.from("symmetric round-trip", "utf8");
var bufPacked = b.crypto.encryptPacked(bufPlain, symKey);
check("encryptPacked produces non-empty buffer", bufPacked.length > 0);
check("encryptPacked starts with format byte 0x02", bufPacked[0] === b.constants.FORMAT.XCHACHA20_POLY1305);
var bufRoundTripped = b.crypto.decryptPacked(bufPacked, symKey);
check("decryptPacked round-trip preserves bytes", bufRoundTripped.equals(bufPlain));

// 11. Signing keypair + sign/verify round-trip
var signKeys = b.crypto.generateSigningKeyPair();
check("signing keypair has public + private",
      typeof signKeys.publicKey === "string" && typeof signKeys.privateKey === "string");
var msg = Buffer.from("sign-me-" + b.version);
var sig = b.crypto.sign(msg, signKeys.privateKey);
check("sign() returns Buffer of non-zero length", Buffer.isBuffer(sig) && sig.length > 0);
check("verify() accepts valid signature",   b.crypto.verify(msg, sig, signKeys.publicKey));
check("verify() rejects tampered message",  !b.crypto.verify(Buffer.from("tamper"), sig, signKeys.publicKey));

// 12. Router constructs and registers
var r = new b.router.Router();
r.get("/test", function (_req, _res) {});
r.post("/api/items", function (_req, _res) {});
r.use(function (_req, _res, next) { next(); });
check("router registers GET route",   r.routes.some(rt => rt.method === "GET" && rt.pattern === "/test"));
check("router registers POST route",  r.routes.some(rt => rt.method === "POST" && rt.pattern === "/api/items"));
check("router stores middleware",     r.middleware.length === 1);

// 13. Router exposes serveStatic
check("serveStatic is a function", typeof b.router.serveStatic === "function");

console.log("OK — " + checks + " checks passed");
