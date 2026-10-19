// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.crypto.hpke.pq.connolly / .wg: ML-KEM-1024 HPKE under the registered
 * RFC 9180 codepoints of draft-connolly-cfrg-hpke-mlkem-04 and
 * draft-ietf-hpke-pq-05.
 *
 * The published draft-ietf-hpke-pq-05 vectors in
 * test/fixtures/hpke-pq-vectors.json pin the recipient side: every
 * encryption in a vector opens in sequence order and every exported value
 * matches. A ciphertext from the sender side that the pinned recipient
 * opens is a valid HPKE ciphertext for that suite, because the AEAD tag
 * covers the key, nonce, aad and plaintext the key schedule produced.
 *
 * draft-connolly-cfrg-hpke-mlkem-04 publishes no vectors (its Appendix C
 * sections are empty). Its ML-KEM-1024 suite under a two-stage KDF is the
 * construction the draft-ietf-hpke-pq-05 vector for KEM 0x0042 with
 * HKDF-SHA384 and AES-256-GCM exercises, so that vector pins `connolly` too.
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");
var helpers  = require("../helpers");
var pki      = require("../../lib/vendor/blamejs-pki.cjs");
var b        = helpers.b;
var check    = helpers.check;

var FIXTURE = JSON.parse(nodeFs.readFileSync(
  nodePath.join(__dirname, "..", "fixtures", "hpke-pq-vectors.json"), "utf8"));

function _hex(h) { return Buffer.from(h, "hex"); }

function _vector(name) {
  for (var i = 0; i < FIXTURE.vectors.length; i++) {
    if (FIXTURE.vectors[i].name === name) return FIXTURE.vectors[i];
  }
  throw new Error("fixture has no vector named " + name);
}

var V_MLKEM1024  = _vector("ML-KEM-1024, HKDF-SHA384, AES-256-GCM");
var V_HYBRID     = _vector("MLKEM1024-P384, HKDF-SHA384, AES-256-GCM");
var V_ONE_STAGE  = _vector("DHKEM(P-384, HKDF-SHA384), SHAKE256, AES-256-GCM");

function _codeOf(fn) {
  try { fn(); } catch (e) { return e.code || ("(no code) " + e.message); }
  return null;
}

function _openEveryEncryption(ns, vector, suite) {
  var ctx = ns.setupRecipient(Object.assign({
    privateKey: _hex(vector.skRm),
    enc:        _hex(vector.enc),
    info:       _hex(vector.info),
  }, suite));
  var opened = 0;
  vector.encryptions.forEach(function (e) {
    var pt = ctx.open(_hex(e.ct), _hex(e.aad));
    if (pt.equals(_hex(e.pt))) opened += 1;
  });
  var exported = 0;
  vector.exports.forEach(function (x) {
    if (ctx.export(_hex(x.exporter_context), x.L).equals(_hex(x.exported_value))) exported += 1;
  });
  return { opened: opened, exported: exported };
}

function testConnollyOpensPublishedVector() {
  var e0 = V_MLKEM1024.encryptions[0];
  var pt = null, err = null;
  try {
    pt = b.crypto.hpke.pq.connolly.open({
      privateKey: _hex(V_MLKEM1024.skRm),
      enc:        _hex(V_MLKEM1024.enc),
      ciphertext: _hex(e0.ct),
      info:       _hex(V_MLKEM1024.info),
      aad:        _hex(e0.aad),
      kdf:        "HKDF-SHA384",
      aead:       "AES-256-GCM",
    });
  } catch (e) { err = e; }
  check("connolly.open recovers the published ML-KEM-1024 vector plaintext",
    pt !== null && pt.equals(_hex(e0.pt)), err && (err.code + " " + err.message));
}

function testConnollyContextMatchesVector() {
  var r = _openEveryEncryption(b.crypto.hpke.pq.connolly, V_MLKEM1024,
    { kdf: "HKDF-SHA384", aead: "AES-256-GCM" });
  check("connolly recipient context opens all 10 published encryptions in sequence",
    r.opened === V_MLKEM1024.encryptions.length, r.opened);
  check("connolly recipient context reproduces all 5 published exports",
    r.exported === V_MLKEM1024.exports.length, r.exported);
}

function testWgContextMatchesVectors() {
  var r = _openEveryEncryption(b.crypto.hpke.pq.wg, V_MLKEM1024,
    { kdf: "HKDF-SHA384", aead: "AES-256-GCM" });
  check("wg recipient context opens all 10 ML-KEM-1024 encryptions",
    r.opened === V_MLKEM1024.encryptions.length, r.opened);
  check("wg recipient context reproduces all 5 ML-KEM-1024 exports",
    r.exported === V_MLKEM1024.exports.length, r.exported);

  var h = _openEveryEncryption(b.crypto.hpke.pq.wg, V_HYBRID,
    { kem: "MLKEM1024-P384", kdf: "HKDF-SHA384", aead: "AES-256-GCM" });
  check("wg recipient context opens all 10 MLKEM1024-P384 encryptions",
    h.opened === V_HYBRID.encryptions.length, h.opened);
  check("wg recipient context reproduces all 5 MLKEM1024-P384 exports",
    h.exported === V_HYBRID.exports.length, h.exported);
}

// The wg default suite uses the single-stage SHAKE256 key schedule. The
// published vectors carry that schedule under DHKEM(P-384), so this pins
// the vendored implementation both wrappers delegate to.
function testSingleStageKeySchedulePinned() {
  var ctx = pki.hpke.setupR({ kem: V_ONE_STAGE.kem_id, kdf: V_ONE_STAGE.kdf_id, aead: V_ONE_STAGE.aead_id },
    _hex(V_ONE_STAGE.enc), { skm: _hex(V_ONE_STAGE.skRm) }, { info: _hex(V_ONE_STAGE.info) });
  var opened = 0;
  V_ONE_STAGE.encryptions.forEach(function (e) {
    if (ctx.open(_hex(e.aad), _hex(e.ct)).equals(_hex(e.pt))) opened += 1;
  });
  var exported = 0;
  V_ONE_STAGE.exports.forEach(function (x) {
    if (ctx.export(_hex(x.exporter_context), x.L).equals(_hex(x.exported_value))) exported += 1;
  });
  check("SHAKE256 single-stage key schedule opens all 10 published encryptions",
    opened === V_ONE_STAGE.encryptions.length, opened);
  check("SHAKE256 single-stage key schedule reproduces all 5 published exports",
    exported === V_ONE_STAGE.exports.length, exported);
}

function testSealToPublishedKeyOpensUnderPublishedKey() {
  [["connolly", {}], ["wg", {}], ["connolly", { kdf: "HKDF-SHA384", aead: "AES-256-GCM" }],
   ["wg", { kdf: "HKDF-SHA384", aead: "AES-256-GCM" }]].forEach(function (row) {
    var ns = b.crypto.hpke.pq[row[0]];
    var sealed = ns.seal(Object.assign({
      recipientPubKey: _hex(V_MLKEM1024.pkRm),
      plaintext:       "to the published key",
      info:            "app/topic",
      aad:             "context",
    }, row[1]));
    var pt = ns.open(Object.assign({
      privateKey: _hex(V_MLKEM1024.skRm),
      enc:        sealed.enc,
      ciphertext: sealed.ciphertext,
      info:       "app/topic",
      aad:        "context",
    }, row[1]));
    check(row[0] + " seal to the published pkRm opens with the published skRm " + JSON.stringify(row[1]),
      pt.toString("utf8") === "to the published key");
    check(row[0] + " enc is the 1568-byte ML-KEM-1024 ciphertext", sealed.enc.length === 1568, sealed.enc.length);
  });

  var hybrid = b.crypto.hpke.pq.wg.seal({
    recipientPubKey: _hex(V_HYBRID.pkRm),
    plaintext:       "hybrid",
    kem:             "MLKEM1024-P384",
  });
  var hpt = b.crypto.hpke.pq.wg.open({
    privateKey: _hex(V_HYBRID.skRm),
    enc:        hybrid.enc,
    ciphertext: hybrid.ciphertext,
    kem:        "MLKEM1024-P384",
  });
  check("wg MLKEM1024-P384 seal to the published key opens with the published seed",
    hpt.toString("utf8") === "hybrid");
  check("wg MLKEM1024-P384 enc is 1665 bytes", hybrid.enc.length === 1665, hybrid.enc.length);
}

// The registered suite ids are what a peer implementation reads. Opening a
// wrapper's default output through the vendored RFC 9180 implementation
// under the stated ids proves which ids went on the wire.
function testDefaultSuitesUseRegisteredIds() {
  check("connolly default suite is ML-KEM-1024 + HKDF-SHA512 + ChaCha20Poly1305",
    JSON.stringify(b.crypto.hpke.pq.connolly.DEFAULT_SUITE) ===
      JSON.stringify({ kem: "ML-KEM-1024", kdf: "HKDF-SHA512", aead: "ChaCha20Poly1305" }),
    JSON.stringify(b.crypto.hpke.pq.connolly.DEFAULT_SUITE));
  check("wg default suite is ML-KEM-1024 + SHAKE256 + ChaCha20Poly1305",
    JSON.stringify(b.crypto.hpke.pq.wg.DEFAULT_SUITE) ===
      JSON.stringify({ kem: "ML-KEM-1024", kdf: "SHAKE256", aead: "ChaCha20Poly1305" }),
    JSON.stringify(b.crypto.hpke.pq.wg.DEFAULT_SUITE));

  [["connolly", { kem: 0x0042, kdf: 0x0003, aead: 0x0003 }],
   ["wg",       { kem: 0x0042, kdf: 0x0011, aead: 0x0003 }]].forEach(function (row) {
    var sealed = b.crypto.hpke.pq[row[0]].seal({
      recipientPubKey: _hex(V_MLKEM1024.pkRm),
      plaintext:       "ids",
      info:            "i",
      aad:             "a",
    });
    var pt = null, err = null;
    try {
      pt = pki.hpke.open(row[1], sealed.enc, { skm: _hex(V_MLKEM1024.skRm) },
        { info: Buffer.from("i") }, Buffer.from("a"), sealed.ciphertext);
    } catch (e) { err = e; }
    check(row[0] + " default seal opens as RFC 9180 suite " + JSON.stringify(row[1]),
      pt !== null && pt.toString("utf8") === "ids", err && err.message);
  });
}

function testSuiteRefusals() {
  var pair = b.crypto.hpke.pq.wg.generateKeyPair();
  function sealWith(ns, extra) {
    return function () {
      b.crypto.hpke.pq[ns].seal(Object.assign({ recipientPubKey: pair.publicKey, plaintext: "x" }, extra));
    };
  }
  check("connolly refuses the single-stage SHAKE256 KDF, which RFC 9180 does not define",
    _codeOf(sealWith("connolly", { kdf: "SHAKE256" })) === "crypto-hpke-pq/unsupported-suite");
  check("connolly refuses a kem option",
    _codeOf(sealWith("connolly", { kem: "MLKEM1024-P384" })) === "crypto-hpke-pq/bad-opt");
  check("wg refuses TurboSHAKE256",
    _codeOf(sealWith("wg", { kdf: "TurboSHAKE256" })) === "crypto-hpke-pq/unsupported-suite");
  check("wg refuses AES-128-GCM",
    _codeOf(sealWith("wg", { aead: "AES-128-GCM" })) === "crypto-hpke-pq/unsupported-suite");
  check("wg refuses HKDF-SHA256",
    _codeOf(sealWith("wg", { kdf: "HKDF-SHA256" })) === "crypto-hpke-pq/unsupported-suite");
  check("wg refuses ML-KEM-768",
    _codeOf(sealWith("wg", { kem: "ML-KEM-768" })) === "crypto-hpke-pq/unsupported-suite");
  check("wg refuses an unknown option",
    _codeOf(sealWith("wg", { nonce: "x" })) === "crypto-hpke-pq/bad-opt");
  check("seal refuses the export-only AEAD",
    _codeOf(sealWith("wg", { aead: "Export-only" })) === "crypto-hpke-pq/export-only");
  check("seal refuses a missing plaintext",
    _codeOf(function () { b.crypto.hpke.pq.wg.seal({ recipientPubKey: pair.publicKey }); }) ===
      "crypto-hpke-pq/bad-opt");
  check("seal refuses null opts",
    _codeOf(function () { b.crypto.hpke.pq.wg.seal(null); }) === "crypto-hpke-pq/bad-opt");
  check("open refuses a non-Buffer enc",
    _codeOf(function () {
      b.crypto.hpke.pq.wg.open({ privateKey: pair.privateKey, enc: "x", ciphertext: Buffer.alloc(16) });
    }) === "crypto-hpke-pq/bad-opt");
  check("seal refuses a public key of the wrong length",
    _codeOf(function () {
      b.crypto.hpke.pq.wg.seal({ recipientPubKey: Buffer.alloc(32), plaintext: "x" });
    }) === "crypto-hpke-pq/bad-key");
}

function testTamperedCiphertextRefused() {
  var pair = b.crypto.hpke.pq.connolly.generateKeyPair();
  var sealed = b.crypto.hpke.pq.connolly.seal({ recipientPubKey: pair.publicKey, plaintext: "t", aad: "a" });
  var tampered = Buffer.from(sealed.ciphertext);
  tampered[0] ^= 0x01;
  check("a tampered ciphertext is refused with crypto-hpke-pq/open-failed",
    _codeOf(function () {
      b.crypto.hpke.pq.connolly.open({ privateKey: pair.privateKey, enc: sealed.enc, ciphertext: tampered, aad: "a" });
    }) === "crypto-hpke-pq/open-failed");
  check("a different aad is refused with crypto-hpke-pq/open-failed",
    _codeOf(function () {
      b.crypto.hpke.pq.connolly.open({ privateKey: pair.privateKey, enc: sealed.enc, ciphertext: sealed.ciphertext, aad: "b" });
    }) === "crypto-hpke-pq/open-failed");
}

function testPskMode() {
  var pair = b.crypto.hpke.pq.wg.generateKeyPair();
  var psk = Buffer.alloc(32, 7);
  var sealed = b.crypto.hpke.pq.wg.seal({
    recipientPubKey: pair.publicKey, plaintext: "psk", psk: psk, pskId: "id-1",
  });
  var pt = b.crypto.hpke.pq.wg.open({
    privateKey: pair.privateKey, enc: sealed.enc, ciphertext: sealed.ciphertext, psk: psk, pskId: "id-1",
  });
  check("psk mode round-trips", pt.toString("utf8") === "psk");
  check("psk-mode ciphertext does not open in base mode",
    _codeOf(function () {
      b.crypto.hpke.pq.wg.open({ privateKey: pair.privateKey, enc: sealed.enc, ciphertext: sealed.ciphertext });
    }) === "crypto-hpke-pq/open-failed");
  check("psk without pskId is refused",
    _codeOf(function () {
      b.crypto.hpke.pq.wg.seal({ recipientPubKey: pair.publicKey, plaintext: "x", psk: psk });
    }) === "crypto-hpke-pq/inconsistent-psk");

  // RFC 9180 sec. 5.1.2: the PSK MUST have at least 32 bytes of entropy.
  var shortPsk = Buffer.alloc(31, 7);
  [["connolly", "seal", { recipientPubKey: pair.publicKey, plaintext: "x" }],
   ["wg", "seal", { recipientPubKey: pair.publicKey, plaintext: "x" }],
   ["wg", "open", { privateKey: pair.privateKey, enc: sealed.enc, ciphertext: sealed.ciphertext }],
   ["wg", "setupSender", { recipientPubKey: pair.publicKey }],
   ["connolly", "setupRecipient", { privateKey: pair.privateKey, enc: sealed.enc }],
   ["wg", "setupRecipient", { privateKey: pair.privateKey, enc: sealed.enc }]].forEach(function (row) {
    var code = _codeOf(function () {
      b.crypto.hpke.pq[row[0]][row[1]](Object.assign({ psk: shortPsk, pskId: "id-1" }, row[2]));
    });
    check(row[0] + "." + row[1] + " refuses a 31-byte psk with crypto-hpke-pq/weak-psk",
      code === "crypto-hpke-pq/weak-psk", code);
  });
  check("a 31-character string psk is refused by its byte length",
    _codeOf(function () {
      b.crypto.hpke.pq.wg.seal({ recipientPubKey: pair.publicKey, plaintext: "x",
        psk: "a".repeat(31), pskId: "id-1" });
    }) === "crypto-hpke-pq/weak-psk");
  var stringPsk = "é".repeat(16);
  var sealedStr = b.crypto.hpke.pq.wg.seal({
    recipientPubKey: pair.publicKey, plaintext: "s", psk: stringPsk, pskId: "id-2",
  });
  check("a string psk of 32 UTF-8 bytes round-trips",
    b.crypto.hpke.pq.wg.open({ privateKey: pair.privateKey, enc: sealedStr.enc,
      ciphertext: sealedStr.ciphertext, psk: stringPsk, pskId: "id-2" }).toString("utf8") === "s");
}

function testSenderContextSequence() {
  var pair = b.crypto.hpke.pq.wg.generateKeyPair();
  var sender = b.crypto.hpke.pq.wg.setupSender({ recipientPubKey: pair.publicKey, info: "stream" });
  var c0 = sender.seal("m0", "a0");
  var c1 = sender.seal("m1", "a1");
  var c2 = sender.seal("m2", "a2");
  var recip = b.crypto.hpke.pq.wg.setupRecipient({ privateKey: pair.privateKey, enc: sender.enc, info: "stream" });
  check("recipient opens message 0", recip.open(c0, "a0").toString("utf8") === "m0");
  check("recipient opens message 1", recip.open(c1, "a1").toString("utf8") === "m1");
  check("recipient opens message 2", recip.open(c2, "a2").toString("utf8") === "m2");
  check("sender and recipient export the same secret",
    sender.export("ctx", 48).equals(recip.export("ctx", 48)));

  var outOfOrder = b.crypto.hpke.pq.wg.setupRecipient({ privateKey: pair.privateKey, enc: sender.enc, info: "stream" });
  check("a message opened out of sequence order is refused",
    _codeOf(function () { outOfOrder.open(c1, "a1"); }) === "crypto-hpke-pq/open-failed");
  check("a failed open does not advance the sequence number",
    outOfOrder.open(c0, "a0").toString("utf8") === "m0");

  // A missing plaintext is refused, the same as single-shot seal, and does
  // not use up a sequence number.
  var s2 = b.crypto.hpke.pq.connolly.setupSender({ recipientPubKey: pair.publicKey });
  check("context seal refuses a missing plaintext",
    _codeOf(function () { s2.seal(); }) === "crypto-hpke-pq/bad-opt");
  check("context seal refuses a null plaintext",
    _codeOf(function () { s2.seal(null); }) === "crypto-hpke-pq/bad-opt");
  var e0 = s2.seal("", "a");
  var r2 = b.crypto.hpke.pq.connolly.setupRecipient({ privateKey: pair.privateKey, enc: s2.enc });
  check("an empty-string plaintext seals as sequence number 0 after the refusals",
    r2.open(e0, "a").length === 0);
}

function testGenerateKeyPair() {
  var p = b.crypto.hpke.pq.wg.generateKeyPair();
  check("wg ML-KEM-1024 public key is 1568 bytes", Buffer.isBuffer(p.publicKey) && p.publicKey.length === 1568);
  check("wg ML-KEM-1024 private key is the 64-byte seed", Buffer.isBuffer(p.privateKey) && p.privateKey.length === 64);
  var h = b.crypto.hpke.pq.wg.generateKeyPair({ kem: "MLKEM1024-P384" });
  check("wg MLKEM1024-P384 public key is 1665 bytes", h.publicKey.length === 1665);
  check("wg MLKEM1024-P384 private key is the 32-byte seed", h.privateKey.length === 32);
  var sealed = b.crypto.hpke.pq.wg.seal({ recipientPubKey: h.publicKey, plaintext: "h", kem: "MLKEM1024-P384" });
  check("wg MLKEM1024-P384 generated pair round-trips",
    b.crypto.hpke.pq.wg.open({ privateKey: h.privateKey, enc: sealed.enc, ciphertext: sealed.ciphertext,
      kem: "MLKEM1024-P384" }).toString("utf8") === "h");
  var c = b.crypto.hpke.pq.connolly.generateKeyPair();
  check("connolly public key is 1568 bytes", c.publicKey.length === 1568);
  check("connolly private key is the 64-byte seed", c.privateKey.length === 64);
  check("wg generateKeyPair refuses an unknown option",
    _codeOf(function () { b.crypto.hpke.pq.wg.generateKeyPair({ kdf: "SHAKE256" }); }) ===
      "crypto-hpke-pq/bad-opt");
  check("wg generateKeyPair refuses ML-KEM-768",
    _codeOf(function () { b.crypto.hpke.pq.wg.generateKeyPair({ kem: "ML-KEM-768" }); }) ===
      "crypto-hpke-pq/unsupported-suite");
  check("connolly generateKeyPair refuses a kem option",
    _codeOf(function () { b.crypto.hpke.pq.connolly.generateKeyPair({ kem: "MLKEM1024-P384" }); }) ===
      "crypto-hpke-pq/bad-opt");
  check("connolly generateKeyPair refuses any argument",
    _codeOf(function () { b.crypto.hpke.pq.connolly.generateKeyPair({}); }) === "crypto-hpke-pq/bad-opt");
}

// The vendored single-shot seal / open release the context key material and
// the KEM shared secret when they return. The wrappers run the setup steps
// themselves, so they must release the same material, on the open-failed
// path as well.
function _allZero(buf) {
  for (var i = 0; i < buf.length; i++) if (buf[i] !== 0) return false;
  return buf.length > 0;
}

function _spySetup(fn) {
  var realS = pki.hpke.setupS, realR = pki.hpke.setupR;
  var sender = [], recipient = [];
  pki.hpke.setupS = function () { var s = realS.apply(this, arguments); sender.push(s); return s; };
  pki.hpke.setupR = function () { var c = realR.apply(this, arguments); recipient.push(c); return c; };
  try { fn(); }
  finally { pki.hpke.setupS = realS; pki.hpke.setupR = realR; }
  return { sender: sender, recipient: recipient };
}

function _released(ctx) {
  return _allZero(ctx._key) && _allZero(ctx._baseNonce) && _allZero(ctx._exporterSecret);
}

function testKeyMaterialReleased() {
  var pair = b.crypto.hpke.pq.wg.generateKeyPair();
  var sealed = null;
  var seen = _spySetup(function () {
    sealed = b.crypto.hpke.pq.wg.seal({ recipientPubKey: pair.publicKey, plaintext: "z", aad: "a" });
    b.crypto.hpke.pq.wg.open({ privateKey: pair.privateKey, enc: sealed.enc, ciphertext: sealed.ciphertext, aad: "a" });
    try {
      b.crypto.hpke.pq.wg.open({ privateKey: pair.privateKey, enc: sealed.enc, ciphertext: sealed.ciphertext, aad: "b" });
    } catch (_e) { /* the failed open's context is what this asserts */ }
  });
  check("single-shot seal ran one sender setup", seen.sender.length === 1, seen.sender.length);
  check("single-shot seal releases the context key material", _released(seen.sender[0].context));
  check("single-shot seal releases the KEM shared secret", _allZero(seen.sender[0].sharedSecret));
  check("single-shot open ran two recipient setups", seen.recipient.length === 2, seen.recipient.length);
  check("single-shot open releases the context key material", _released(seen.recipient[0]));
  check("a failed single-shot open releases the context key material", _released(seen.recipient[1]));

  var sender = null;
  var seenCtx = _spySetup(function () {
    sender = b.crypto.hpke.pq.connolly.setupSender({ recipientPubKey: pair.publicKey });
  });
  check("setupSender releases the KEM shared secret once the key schedule has run",
    _allZero(seenCtx.sender[0].sharedSecret));
  var c0 = sender.seal("still usable");
  var recip = b.crypto.hpke.pq.connolly.setupRecipient({ privateKey: pair.privateKey, enc: sender.enc });
  check("the sender context still seals after the shared secret is released",
    recip.open(c0).toString("utf8") === "still usable");
}

function testAuditRows() {
  var captured = [];
  var realSafe = b.audit.safeEmit;
  b.audit.safeEmit = function (e) { captured.push(e); };
  try {
    var pair = b.crypto.hpke.pq.wg.generateKeyPair();
    var sealed = b.crypto.hpke.pq.wg.seal({ recipientPubKey: pair.publicKey, plaintext: "audited" });
    b.crypto.hpke.pq.wg.open({ privateKey: pair.privateKey, enc: sealed.enc, ciphertext: sealed.ciphertext });
    try {
      b.crypto.hpke.pq.wg.open({ privateKey: pair.privateKey, enc: sealed.enc, ciphertext: sealed.ciphertext, aad: "x" });
    } catch (_e) { /* the failure row is what this asserts */ }
    b.crypto.hpke.pq.connolly.setupSender({ recipientPubKey: pair.publicKey });
  } finally {
    b.audit.safeEmit = realSafe;
  }
  function find(action, outcome) {
    return captured.filter(function (e) { return e.action === action && e.outcome === outcome; })[0];
  }
  var s = find("system.hpke.pq.seal", "success");
  check("seal emits system.hpke.pq.seal naming the draft and suite",
    !!s && s.metadata.draft === "draft-ietf-hpke-pq-05" && s.metadata.suite.kdf === "SHAKE256",
    JSON.stringify(captured.map(function (e) { return e.action + ":" + e.outcome; })));
  check("open emits system.hpke.pq.open success", !!find("system.hpke.pq.open", "success"));
  var f = find("system.hpke.pq.open", "failure");
  check("a tag failure emits system.hpke.pq.open failure with reason aead-tag", !!f && f.reason === "aead-tag");
  var st = find("system.hpke.pq.setup", "success");
  check("setupSender emits system.hpke.pq.setup with the sender role",
    !!st && st.metadata.role === "sender" && st.metadata.draft === "draft-connolly-cfrg-hpke-mlkem-04");
}

function testConnollyRoundTrip() {
  var pair = b.crypto.hpke.generateKeyPair();
  var sealed = b.crypto.hpke.pq.connolly.seal({
    recipientPubKey: pair.publicKey,
    plaintext:       "msg",
    info:            "topic/a",
    aad:             "context",
  });
  check("connolly seal returns enc",        Buffer.isBuffer(sealed.enc));
  check("connolly seal returns ciphertext", Buffer.isBuffer(sealed.ciphertext));

  var pt = b.crypto.hpke.pq.connolly.open({
    privateKey: pair.privateKey,
    enc:        sealed.enc,
    ciphertext: sealed.ciphertext,
    info:       "topic/a",
    aad:        "context",
  });
  check("connolly round-trip", pt.toString("utf8") === "msg");
}

function testWgRoundTrip() {
  var pair = b.crypto.hpke.generateKeyPair();
  var sealed = b.crypto.hpke.pq.wg.seal({
    recipientPubKey: pair.publicKey,
    plaintext:       "wg msg",
    info:            "topic/b",
  });
  var pt = b.crypto.hpke.pq.wg.open({
    privateKey: pair.privateKey,
    enc:        sealed.enc,
    ciphertext: sealed.ciphertext,
    info:       "topic/b",
  });
  check("wg round-trip", pt.toString("utf8") === "wg msg");
}

// The two default suites differ in their KDF, so the suite_id each binds
// into the key schedule differs and an envelope sealed under one default
// does not open under the other. Under one explicit suite the two drafts
// specify the same construction, so the envelopes interoperate.
function testCrossDraftDefaults() {
  var pair = b.crypto.hpke.generateKeyPair();
  var sealedConnolly = b.crypto.hpke.pq.connolly.seal({
    recipientPubKey: pair.publicKey,
    plaintext:       "secret",
    info:            "ctx",
  });
  var threw = false;
  try {
    b.crypto.hpke.pq.wg.open({
      privateKey: pair.privateKey,
      enc:        sealedConnolly.enc,
      ciphertext: sealedConnolly.ciphertext,
      info:       "ctx",
    });
  } catch (_e) { threw = true; }
  check("connolly default envelope does not open under the wg default suite", threw);

  var sealedWg = b.crypto.hpke.pq.wg.seal({
    recipientPubKey: pair.publicKey,
    plaintext:       "secret",
    info:            "ctx",
  });
  threw = false;
  try {
    b.crypto.hpke.pq.connolly.open({
      privateKey: pair.privateKey,
      enc:        sealedWg.enc,
      ciphertext: sealedWg.ciphertext,
      info:       "ctx",
    });
  } catch (_e) { threw = true; }
  check("wg default envelope does not open under the connolly default suite", threw);

  var shared = b.crypto.hpke.pq.connolly.seal({
    recipientPubKey: pair.publicKey, plaintext: "same suite", kdf: "HKDF-SHA512",
  });
  var pt = b.crypto.hpke.pq.wg.open({
    privateKey: pair.privateKey, enc: shared.enc, ciphertext: shared.ciphertext, kdf: "HKDF-SHA512",
  });
  check("connolly and wg interoperate under one explicit suite", pt.toString("utf8") === "same suite");
}

function testEmptyInfoEquivalentToOmitted() {
  var pair = b.crypto.hpke.generateKeyPair();
  // Seal without info, open with info: "". The two MUST round-trip.
  var sealed = b.crypto.hpke.pq.connolly.seal({
    recipientPubKey: pair.publicKey,
    plaintext:       "neutral",
  });
  var pt = b.crypto.hpke.pq.connolly.open({
    privateKey: pair.privateKey,
    enc:        sealed.enc,
    ciphertext: sealed.ciphertext,
    info:       "",
  });
  check("empty info round-trips with omitted info", pt.toString("utf8") === "neutral");

  // Reverse: seal with info: "", open without info.
  var sealed2 = b.crypto.hpke.pq.wg.seal({
    recipientPubKey: pair.publicKey,
    plaintext:       "back",
    info:            "",
  });
  var pt2 = b.crypto.hpke.pq.wg.open({
    privateKey: pair.privateKey,
    enc:        sealed2.enc,
    ciphertext: sealed2.ciphertext,
  });
  check("omitted info round-trips with empty info on seal", pt2.toString("utf8") === "back");
}

function testLabelsExported() {
  check("connolly label names the draft revision it implements",
    b.crypto.hpke.pq.connolly.label === "draft-connolly-cfrg-hpke-mlkem-04",
    b.crypto.hpke.pq.connolly.label);
  check("wg label names the draft revision it implements",
    b.crypto.hpke.pq.wg.label === "draft-ietf-hpke-pq-05",
    b.crypto.hpke.pq.wg.label);
}

function run() {
  testConnollyOpensPublishedVector();
  testConnollyContextMatchesVector();
  testWgContextMatchesVectors();
  testSingleStageKeySchedulePinned();
  testSealToPublishedKeyOpensUnderPublishedKey();
  testDefaultSuitesUseRegisteredIds();
  testSuiteRefusals();
  testTamperedCiphertextRefused();
  testPskMode();
  testSenderContextSequence();
  testGenerateKeyPair();
  testKeyMaterialReleased();
  testAuditRows();
  testConnollyRoundTrip();
  testWgRoundTrip();
  testCrossDraftDefaults();
  testEmptyInfoEquivalentToOmitted();
  testLabelsExported();
}

if (require.main === module) run();
module.exports = { run: run };
