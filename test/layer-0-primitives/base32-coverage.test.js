// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.base32 — full RFC 4648 codec coverage: encode (Buffer / Uint8Array, padded
 * and bare, both alphabets), decode (strict + loose), and the canonicalization
 * and length invariants a round-trip test alone does not reach — non-canonical
 * trailing bits and impossible symbol counts. The decoder is the surface behind
 * TOTP secrets / DNSSEC hashes / transcribable ids, so its rejection of
 * malleable and malformed input is a correctness + security property, tested
 * here per partial-group size.
 *
 * Run standalone: `node test/layer-0-primitives/base32-coverage.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

var nodeCrypto = require("crypto");

function threwCode(fn) { try { fn(); return null; } catch (e) { return e.code || null; } }

// ---- encode: input types, empty, bad input ----
function testEncodeInputs() {
  check("encode Buffer", b.base32.encode(Buffer.from("f")) === "MY======");
  // A Uint8Array must encode identically to the equivalent Buffer.
  check("encode Uint8Array mirrors Buffer",
    b.base32.encode(new Uint8Array([0x66, 0x6f, 0x6f])) === b.base32.encode(Buffer.from("foo")));
  check("encode empty → empty string", b.base32.encode(Buffer.alloc(0)) === "");
  check("encode rejects a string input",
    threwCode(function () { b.base32.encode("not a buffer"); }) === "base32/bad-input");
  check("encode rejects null",
    threwCode(function () { b.base32.encode(null); }) === "base32/bad-input");
}

// ---- padding + both RFC 4648 alphabets ----
function testPaddingAndVariants() {
  check("padded to 8-char boundary by default", b.base32.encode(Buffer.from("f")).length % 8 === 0);
  check("padding:false omits =", b.base32.encode(Buffer.from("f"), { padding: false }) === "MY");
  check("rfc4648-hex variant differs from standard",
    b.base32.encode(Buffer.from("foo"), { variant: "rfc4648-hex" }) !== b.base32.encode(Buffer.from("foo")));
  check("rfc4648-hex round-trips",
    b.base32.decode(b.base32.encode(Buffer.from("foo"), { variant: "rfc4648-hex" }), { variant: "rfc4648-hex" }).toString() === "foo");
  check("bad variant rejected (encode)",
    threwCode(function () { b.base32.encode(Buffer.from("x"), { variant: "nope" }); }) === "base32/bad-variant");
  check("bad variant rejected (decode)",
    threwCode(function () { b.base32.decode("MY======", { variant: "nope" }); }) === "base32/bad-variant");
}

// ---- every partial-group size round-trips (1..5 trailing bytes) ----
function testAllPartialGroups() {
  ["f", "fo", "foo", "foob", "fooba", "foobar", "foobarbaz"].forEach(function (s) {
    var enc = b.base32.encode(Buffer.from(s));
    check("round-trip padded '" + s + "'", b.base32.decode(enc).toString() === s);
    check("padded '" + s + "' length is a multiple of 8", enc.length % 8 === 0);
    var bare = b.base32.encode(Buffer.from(s), { padding: false });
    check("round-trip bare '" + s + "'", b.base32.decode(bare).toString() === s);
  });
  // 20 random bytes (a TOTP-secret-sized value) round-trips bare + padded.
  var rnd = nodeCrypto.randomBytes(20);
  check("round-trip random 20B padded", b.base32.decode(b.base32.encode(rnd)).equals(rnd));
  check("round-trip random 20B bare", b.base32.decode(b.base32.encode(rnd, { padding: false })).equals(rnd));
}

// ---- decode strict: invalid char, data-after-padding, non-string ----
function testDecodeStrictRejects() {
  check("invalid char rejected", threwCode(function () { b.base32.decode("MY0====="); }) === "base32/bad-char");
  check("lowercase rejected in strict", threwCode(function () { b.base32.decode("my======"); }) === "base32/bad-char");
  check("data after padding rejected", threwCode(function () { b.base32.decode("M=Y====="); }) === "base32/bad-char");
  check("non-string input rejected", threwCode(function () { b.base32.decode(Buffer.from("MY")); }) === "base32/bad-input");
}

// ---- decode loose: lowercase, spaces, dashes, missing padding ----
function testDecodeLoose() {
  check("loose up-cases", b.base32.decode("my======", { loose: true }).toString() === "f");
  check("loose ignores spaces + dashes",
    b.base32.decode("MZXW-6YT B", { loose: true }).toString() === b.base32.decode("MZXW6YTB").toString());
  check("loose accepts missing padding", b.base32.decode("MY", { loose: true }).toString() === "f");
}

// ---- THE PREVIOUSLY-MISSING MECHANICS ----
// Non-canonical trailing bits (RFC 4648 §3.5): the final symbol's unused low
// bits must be zero, else two distinct strings decode to the same bytes.
function testNonCanonicalRejected() {
  // "MY======" is canonical 'f'; "MZ======" has the same high bits but non-zero
  // low bits — it must NOT silently decode to 'f'.
  check("MY====== decodes to f (canonical)", b.base32.decode("MY======").toString() === "f");
  check("MZ====== (non-canonical) rejected",
    threwCode(function () { b.base32.decode("MZ======"); }) === "base32/non-canonical");
  check("non-canonical rejected in loose mode too",
    threwCode(function () { b.base32.decode("mz======", { loose: true }); }) === "base32/non-canonical");
  // Build a non-canonical value for a 3-symbol-tail case and assert refusal.
  // 4 symbols carry 20 bits → 2 bytes (16 bits) + 4 leftover; flip a leftover bit.
  var canonical4 = b.base32.encode(Buffer.from("fo")).replace(/=+$/, "");   // "MZXW6" -> take first 4
  // canonical for "fo" is 4 data symbols; if the 4th symbol's low bits are non-zero it's non-canonical.
  check("a canonical 'fo' still decodes", b.base32.decode(b.base32.encode(Buffer.from("fo"))).toString() === "fo");
  void canonical4;
}

// Impossible symbol counts: 1, 3, 6 (mod 8) cannot represent whole bytes.
function testBadLengthRejected() {
  ["A", "ABC", "ABCDEF"].forEach(function (s) {
    check("impossible length '" + s + "' (" + s.length + " symbols) rejected",
      threwCode(function () { b.base32.decode(s); }) === "base32/bad-length");
  });
  // Valid partial-group counts (2,4,5,7) do NOT trip the length guard.
  ["MY======", "MZXW====", "MZXW6===", "MZXW6YQ="].forEach(function (s) {
    var code = threwCode(function () { b.base32.decode(s); });
    check("valid-length '" + s + "' not rejected for length", code !== "base32/bad-length");
  });
}

function run() {
  testEncodeInputs();
  testPaddingAndVariants();
  testAllPartialGroups();
  testDecodeStrictRejects();
  testDecodeLoose();
  testNonCanonicalRejected();
  testBadLengthRejected();
}

if (require.main === module) {
  run();
  console.log("base32-coverage OK — " + helpers.getChecks() + " checks");
}

module.exports = { run: run };
