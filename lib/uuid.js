"use strict";
/**
 * uuid — RFC 4122 v4 (random) + RFC 9562 v7 (time-ordered).
 *
 * Two flavors:
 *
 *   b.uuid.v4()           — fully random 128-bit UUID. Standard, portable,
 *                           the default choice when ordering doesn't matter.
 *
 *   b.uuid.v7()           — Unix-millisecond timestamp prefix + 74 random
 *                           bits. Time-ordered (sorts by creation time even
 *                           lexicographically), ideal as a database PK
 *                           because B-tree inserts stay near the right edge
 *                           — no random scattering across the index.
 *
 *   b.uuid.parse(str)     — { ok, version, bytes }. Validates the canonical
 *                           8-4-4-4-12 hex form and the version + variant
 *                           bits. Returns ok:false (no throw) on bad input.
 *
 *   b.uuid.isValid(str)   — boolean shorthand. No version/variant check
 *                           beyond shape — operators who care use parse().
 *
 * All entropy comes from `b.crypto.generateBytes`, which routes through
 * `node:crypto.randomBytes` — same source as `crypto.randomUUID()`.
 *
 * Why ship v7 ourselves? Native `crypto.randomUUID()` only emits v4.
 * v7 is the modern recommendation for any UUID landing in a sortable
 * column (jobs queue, audit chain extensions, anything where insertion
 * order matters for index locality).
 */
var { generateBytes } = require("./crypto");

// Canonical UUID layout: 8-4-4-4-12 hex digits, version nibble at byte
// 6 high-nibble, variant bits at byte 8 high two bits (must be 10).
var UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-7][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
// Loose form for `isValid` shape-only check — accepts any version 1-8 and
// any variant top-2-bit value. Operators wanting strict version+variant
// gating use `parse()`.
var UUID_LOOSE_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function _bytesToString(bytes) {
  var hex = bytes.toString("hex");
  return hex.slice(0, 8) + "-" +
         hex.slice(8, 12) + "-" +
         hex.slice(12, 16) + "-" +
         hex.slice(16, 20) + "-" +
         hex.slice(20, 32);
}

function v4() {
  var b = generateBytes(16);
  // version = 4 (0100): high nibble of byte 6
  b[6] = (b[6] & 0x0f) | 0x40;
  // variant = RFC 4122 (10xx): top two bits of byte 8
  b[8] = (b[8] & 0x3f) | 0x80;
  return _bytesToString(b);
}

function v7(opts) {
  // RFC 9562 §5.7 layout:
  //   bytes 0-5  : 48-bit big-endian Unix timestamp in milliseconds
  //   bytes 6-7  : version nibble (7) + 12 bits random_a
  //   bytes 8-15 : variant bits + 62 bits random_b
  var ms = (opts && typeof opts.now === "number") ? opts.now : Date.now();
  var b = generateBytes(16);
  // 48-bit ms timestamp (big-endian) into bytes 0-5
  // ms can exceed 2^32 (we're in 2026, ms is ~1.78e12), so use Math + bit ops carefully
  var msHi = Math.floor(ms / 0x100000000);    // top 16 bits live in low 16 of msHi
  var msLo = ms >>> 0;                        // bottom 32 bits unsigned
  b[0] = (msHi >> 8) & 0xff;
  b[1] = msHi & 0xff;
  b[2] = (msLo >>> 24) & 0xff;
  b[3] = (msLo >>> 16) & 0xff;
  b[4] = (msLo >>> 8) & 0xff;
  b[5] = msLo & 0xff;
  // version = 7 (0111) in high nibble of byte 6, random_a in low nibble + byte 7
  b[6] = (b[6] & 0x0f) | 0x70;
  // variant = RFC 4122 (10xx) in top two bits of byte 8
  b[8] = (b[8] & 0x3f) | 0x80;
  return _bytesToString(b);
}

function parse(str) {
  if (typeof str !== "string") return { ok: false, reason: "not-a-string" };
  if (!UUID_RE.test(str))      return { ok: false, reason: "malformed" };
  var hex = str.replace(/-/g, "");
  var bytes = Buffer.from(hex, "hex");
  // Version is the high nibble of byte 6.
  var version = (bytes[6] >> 4) & 0x0f;
  // Variant: top two bits of byte 8 must be 10 for RFC 4122 / 9562.
  var variant = (bytes[8] >> 6) & 0x03;
  if (variant !== 0b10) return { ok: false, reason: "bad-variant" };
  return { ok: true, version: version, bytes: bytes };
}

function isValid(str) {
  return typeof str === "string" && UUID_LOOSE_RE.test(str);
}

module.exports = {
  v4:      v4,
  v7:      v7,
  parse:   parse,
  isValid: isValid,
};
