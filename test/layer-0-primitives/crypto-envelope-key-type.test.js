// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.crypto.encrypt / decrypt / encryptMlkem768X25519 / decryptMlkem768X25519
 * bind the envelope's KEM id to the key that runs the KEM.
 *
 * node:crypto encapsulate() accepts RSA, X25519 and every ML-KEM parameter
 * set, so a key of the wrong type still produced an envelope whose header
 * named ML-KEM-1024. Each wrong key type must be refused with
 * crypto/key-type-mismatch at encrypt and at decrypt, and the right keys must
 * still round-trip.
 */

var nodeCrypto = require("node:crypto");
var { xchacha20poly1305 } = require("../../lib/vendor/noble-ciphers.cjs");
var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var C       = require("../../lib/constants");

var PEM = { publicKeyEncoding: { type: "spki", format: "pem" },
            privateKeyEncoding: { type: "pkcs8", format: "pem" } };

function _pair(type, extra) {
  return nodeCrypto.generateKeyPairSync(type, Object.assign({}, extra || {}, PEM));
}

function _codeOf(fn) {
  try { fn(); return "no-throw"; }
  catch (e) { return e && e.code ? e.code : "untyped:" + ((e && e.message) || String(e)).slice(0, 80); }
}

function _fixedInfo(kemId) {
  return Buffer.concat([
    Buffer.from(C.ENVELOPE_FIXED_INFO_LABEL, "utf8"),
    Buffer.from([0x00, kemId, C.CIPHER_IDS.XCHACHA20_POLY1305, C.KDF_IDS.SHAKE256, 0x00]),
  ]);
}

function _u16(n) { var x = Buffer.alloc(2); x.writeUInt16BE(n); return x; }

// Mints an envelope the way a sender without the key-type check would: the
// KEM runs on whatever key is passed and the header carries `kemId`.
function _mintUnchecked(kemId, kemPublicPem, classical) {
  var kem = nodeCrypto.encapsulate(nodeCrypto.createPublicKey(kemPublicPem));
  var parts = [kem.sharedKey];
  var tail = [];
  if (classical) {
    var eph = nodeCrypto.generateKeyPairSync(classical.type, Object.assign({}, classical.gen || {}, {
      publicKeyEncoding: { type: "spki", format: "der" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    }));
    parts.push(nodeCrypto.diffieHellman({
      privateKey: nodeCrypto.createPrivateKey(eph.privateKey),
      publicKey:  nodeCrypto.createPublicKey(classical.publicKey),
    }));
    tail = [_u16(eph.publicKey.length), eph.publicKey];
  }
  parts.push(_fixedInfo(kemId));
  var key = b.crypto.kdf(Buffer.concat(parts), C.BYTES.bytes(32));
  var nonce = b.crypto.generateBytes(C.BYTES.bytes(24));
  var header = Buffer.from([C.ENVELOPE_MAGIC, kemId, C.CIPHER_IDS.XCHACHA20_POLY1305, C.KDF_IDS.SHAKE256]);
  var ct = xchacha20poly1305(key, nonce, header).encrypt(Buffer.from("payload", "utf8"));
  return Buffer.concat([header, _u16(kem.ciphertext.length), kem.ciphertext]
    .concat(tail, [nonce, Buffer.from(ct)])).toString("base64");
}

var WRONG_KEM_TYPES = [
  ["rsa", { modulusLength: 2048 }],
  ["x25519", {}],
  ["ml-kem-512", {}],
];

function testEncryptRefusesWrongKemKey() {
  var good = b.crypto.generateEncryptionKeyPair();
  var wrong1024 = WRONG_KEM_TYPES.concat([["ml-kem-768", {}]]);
  wrong1024.forEach(function (row) {
    var p = _pair(row[0], row[1]);
    var hybrid = _codeOf(function () {
      b.crypto.encrypt("x", { publicKey: p.publicKey, ecPublicKey: good.ecPublicKey });
    });
    check("encrypt (ML-KEM-1024 + P-384) refuses a " + row[0] + " KEM key", hybrid === "crypto/key-type-mismatch", hybrid);
    var kemOnly = _codeOf(function () { b.crypto.encrypt("x", p.publicKey); });
    check("encrypt (ML-KEM-1024 only) refuses a " + row[0] + " KEM key", kemOnly === "crypto/key-type-mismatch", kemOnly);
  });
  var x = _pair("x25519");
  WRONG_KEM_TYPES.concat([["ml-kem-1024", {}]]).forEach(function (row) {
    var p = _pair(row[0], row[1]);
    var code = _codeOf(function () {
      b.crypto.encryptMlkem768X25519("x", { mlkemPublicKey: p.publicKey, x25519PublicKey: x.publicKey });
    });
    check("encryptMlkem768X25519 refuses a " + row[0] + " KEM key", code === "crypto/key-type-mismatch", code);
  });
}

function testEncryptRefusesWrongClassicalKey() {
  var good = b.crypto.generateEncryptionKeyPair();
  [["ec", { namedCurve: "P-256" }], ["x25519", {}], ["rsa", { modulusLength: 2048 }]].forEach(function (row) {
    var p = _pair(row[0], row[1]);
    var code = _codeOf(function () {
      b.crypto.encrypt("x", { publicKey: good.publicKey, ecPublicKey: p.publicKey });
    });
    check("encrypt refuses a " + row[0] + " key as ecPublicKey", code === "crypto/key-type-mismatch", code);
  });
  var m = _pair("ml-kem-768");
  [["x448", {}], ["ec", { namedCurve: "P-256" }]].forEach(function (row) {
    var p = _pair(row[0], row[1]);
    var code = _codeOf(function () {
      b.crypto.encryptMlkem768X25519("x", { mlkemPublicKey: m.publicKey, x25519PublicKey: p.publicKey });
    });
    check("encryptMlkem768X25519 refuses a " + row[0] + " key as x25519PublicKey", code === "crypto/key-type-mismatch", code);
  });
}

function testDecryptRefusesWrongKemKey() {
  WRONG_KEM_TYPES.concat([["ml-kem-768", {}]]).forEach(function (row) {
    var p = _pair(row[0], row[1]);
    var env = _mintUnchecked(C.KEM_IDS.ML_KEM_1024, p.publicKey, null);
    var code = _codeOf(function () { b.crypto.decrypt(env, p.privateKey); });
    check("decrypt refuses an ML-KEM-1024 envelope opened with a " + row[0] + " key",
      code === "crypto/key-type-mismatch", code);
  });
  var good = b.crypto.generateEncryptionKeyPair();
  var m768 = _pair("ml-kem-768");
  var hybridEnv = _mintUnchecked(C.KEM_IDS.ML_KEM_1024_P384, m768.publicKey,
    { type: "ec", gen: { namedCurve: "P-384" }, publicKey: good.ecPublicKey });
  var hybridCode = _codeOf(function () {
    b.crypto.decrypt(hybridEnv, { privateKey: m768.privateKey, ecPrivateKey: good.ecPrivateKey });
  });
  check("decrypt refuses an ML-KEM-1024 + P-384 envelope opened with an ml-kem-768 key",
    hybridCode === "crypto/key-type-mismatch", hybridCode);

  var m1024 = _pair("ml-kem-1024");
  var x = _pair("x25519");
  var env768 = _mintUnchecked(C.KEM_IDS.ML_KEM_768_X25519, m1024.publicKey,
    { type: "x25519", publicKey: x.publicKey });
  var code768 = _codeOf(function () {
    b.crypto.decrypt(env768, { privateKey: m1024.privateKey, x25519PrivateKey: x.privateKey });
  });
  check("decrypt refuses an ML-KEM-768 + X25519 envelope opened with an ml-kem-1024 key",
    code768 === "crypto/key-type-mismatch", code768);
  var named768 = _codeOf(function () {
    b.crypto.decryptMlkem768X25519(env768, { privateKey: m1024.privateKey, x25519PrivateKey: x.privateKey });
  });
  check("decryptMlkem768X25519 refuses an ml-kem-1024 key",
    named768 === "crypto/key-type-mismatch", named768);
}

function testDecryptRefusesWrongClassicalKey() {
  var good = b.crypto.generateEncryptionKeyPair();
  var env = b.crypto.encrypt("x", good);
  var p256 = _pair("ec", { namedCurve: "P-256" });
  var code = _codeOf(function () {
    b.crypto.decrypt(env, { privateKey: good.privateKey, ecPrivateKey: p256.privateKey });
  });
  check("decrypt refuses a P-256 ecPrivateKey for a P-384 envelope", code === "crypto/key-type-mismatch", code);

  var pair768 = b.crypto.generateMlkem768X25519KeyPair();
  var env768 = b.crypto.encryptMlkem768X25519("x", pair768);
  var x448 = _pair("x448");
  var code768 = _codeOf(function () {
    b.crypto.decrypt(env768, { privateKey: pair768.mlkemPrivateKey, x25519PrivateKey: x448.privateKey });
  });
  check("decrypt refuses an X448 x25519PrivateKey", code768 === "crypto/key-type-mismatch", code768);
}

function testRightKeysRoundTrip() {
  var good = b.crypto.generateEncryptionKeyPair();
  check("hybrid envelope round-trips", b.crypto.decrypt(b.crypto.encrypt("h", good), good) === "h");
  check("KEM-only envelope round-trips",
    b.crypto.decrypt(b.crypto.encrypt("k", good.publicKey), good.privateKey) === "k");
  var p = b.crypto.generateMlkem768X25519KeyPair();
  var env = b.crypto.encryptMlkem768X25519("m", p);
  check("ML-KEM-768 + X25519 envelope round-trips through decrypt",
    b.crypto.decrypt(env, { privateKey: p.mlkemPrivateKey, x25519PrivateKey: p.x25519PrivateKey }) === "m");
  check("ML-KEM-768 + X25519 envelope round-trips through decryptMlkem768X25519",
    b.crypto.decryptMlkem768X25519(env, { privateKey: p.mlkemPrivateKey, x25519PrivateKey: p.x25519PrivateKey }) === "m");
}

function testAssertKeyType() {
  var ec = nodeCrypto.createPrivateKey(_pair("ec", { namedCurve: "P-384" }).privateKey);
  check("assertKeyType returns the key when the type matches",
    b.crypto.assertKeyType(ec, { type: "ec", curve: "P-384" }) === ec);
  check("assertKeyType accepts a curve given by its OpenSSL name",
    b.crypto.assertKeyType(ec, { type: "ec", curve: "secp384r1" }) === ec);
  check("assertKeyType accepts any member of a list",
    b.crypto.assertKeyType(ec, ["ed25519", { type: "ec", curve: "P-384" }]) === ec);
  var wrongCurve = _codeOf(function () { b.crypto.assertKeyType(ec, { type: "ec", curve: "P-256" }); });
  check("assertKeyType refuses the wrong curve", wrongCurve === "crypto/key-type-mismatch", wrongCurve);
  var wrongType = _codeOf(function () { b.crypto.assertKeyType(ec, "ml-kem-1024"); });
  check("assertKeyType refuses the wrong type", wrongType === "crypto/key-type-mismatch", wrongType);
  var notKey = _codeOf(function () { b.crypto.assertKeyType("-----BEGIN PUBLIC KEY-----", "ed25519"); });
  check("assertKeyType refuses a value that is not a KeyObject", notKey === "crypto/key-type-mismatch", notKey);
  function OwnError(code, message) { this.code = code; this.message = message; }
  var own;
  try { b.crypto.assertKeyType(ec, "ed25519", { errorClass: OwnError, code: "own/bad-key", label: "own.sign: key" }); }
  catch (e) { own = e; }
  check("assertKeyType throws the caller's error class and code",
    own instanceof OwnError && own.code === "own/bad-key" && /own\.sign: key/.test(own.message), own && own.message);
  var badSpec = _codeOf(function () { b.crypto.assertKeyType(ec, []); });
  check("assertKeyType refuses an empty accepted list at the call site", badSpec === "crypto/bad-key-spec", badSpec);
  ["__proto__", "toString", "constructor", "hasOwnProperty"].forEach(function (name) {
    var inherited = _codeOf(function () { b.crypto.assertKeyType(ec, { type: "ec", curve: name }); });
    check("assertKeyType refuses the inherited property name " + name + " as a curve",
      inherited === "crypto/bad-key-spec", inherited);
  });
  var nonString = _codeOf(function () { b.crypto.assertKeyType(ec, { type: "ec", curve: 384 }); });
  check("assertKeyType refuses a curve that is not a string", nonString === "crypto/bad-key-spec", nonString);
}

async function run() {
  testEncryptRefusesWrongKemKey();
  testEncryptRefusesWrongClassicalKey();
  testDecryptRefusesWrongKemKey();
  testDecryptRefusesWrongClassicalKey();
  testRightKeysRoundTrip();
  testAssertKeyType();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[crypto-envelope-key-type] OK"); },
    function (e) { console.error(e); process.exit(1); }
  );
}
