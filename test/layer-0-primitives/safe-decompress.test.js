// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.safeDecompress — bomb-resistant decompression.
 *
 * Covers: algorithm allowlist, maxOutputBytes refusal, maxRatio
 * refusal (the post-decompress check that defeats compressed
 * input < absolute-cap but ratio > maxRatio), audit emission on
 * refusal, bad-arg refusal paths.
 *
 * Run standalone: `node test/layer-0-primitives/safe-decompress.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

var zlib = require("node:zlib");
var C    = b.constants;

// ---- Surface ----

function testSurface() {
  check("b.safeDecompress is a function",
        typeof b.safeDecompress === "function");
}

// ---- Algorithm allowlist ----

function testAlgorithmRequired() {
  var threw = null;
  try { b.safeDecompress(Buffer.from("x"), { maxOutputBytes: 1024 }); }
  catch (e) { threw = e; }
  check("missing algorithm → refused",
        threw && /safe-decompress\/unsupported-algorithm/.test(threw.code || ""));
}

function testAlgorithmAllowlistRefusesUnknown() {
  var threw = null;
  try { b.safeDecompress(Buffer.from("x"), { algorithm: "zstd", maxOutputBytes: 1024 }); }
  catch (e) { threw = e; }
  check("unknown algorithm → refused (zstd not in allowlist)",
        threw && /unsupported-algorithm/.test(threw.code || ""));
}

// A non-own Object.prototype key ("constructor", "toString", …) is NOT in
// the allowlist and MUST refuse exactly like any other typo'd algorithm.
// A truthiness/`in`-style lookup (`!_algorithms[algo]`) inherits
// Object.prototype members, so `algorithm: "constructor"` resolves to the
// `Object` function and gets INVOKED — `Object(buf)` returns the raw
// compressed buffer, so the primitive silently returns un-decompressed
// bytes with no error (allowlist fail-open). The guard must use an
// own-property check.
function testAlgorithmAllowlistRefusesPrototypeKeys() {
  var gz = zlib.gzipSync(Buffer.from("hello world hello world", "utf8"));
  var protoKeys = [
    "constructor", "__proto__", "hasOwnProperty", "toString",
    "valueOf", "isPrototypeOf", "toLocaleString", "propertyIsEnumerable",
  ];
  for (var i = 0; i < protoKeys.length; i++) {
    var algo = protoKeys[i];
    var threw = null;
    var returned = null;
    try {
      returned = b.safeDecompress(gz, { algorithm: algo, maxOutputBytes: C.BYTES.kib(64) });
    } catch (e) { threw = e; }
    check("prototype-key algorithm '" + algo + "' → refused (unsupported-algorithm), not silently accepted",
          threw !== null && /safe-decompress\/unsupported-algorithm/.test(threw.code || "") &&
          returned === null);
  }
}

// ---- Happy path ----

function testGzipRoundTrip() {
  var plain = "hello world ".repeat(50);
  var gz = zlib.gzipSync(Buffer.from(plain, "utf8"));
  var out = b.safeDecompress(gz, {
    algorithm: "gzip", maxOutputBytes: C.BYTES.kib(64),
  });
  check("gzip round-trip preserves bytes", out.toString("utf8") === plain);
}

function testDeflateRawRoundTrip() {
  var plain = "hello world ".repeat(50);
  var def = zlib.deflateRawSync(Buffer.from(plain, "utf8"));
  var out = b.safeDecompress(def, {
    algorithm: "deflate-raw", maxOutputBytes: C.BYTES.kib(64),
  });
  check("deflate-raw round-trip preserves bytes", out.toString("utf8") === plain);
}

function testBrotliRoundTrip() {
  if (!C._brotliDecoderPatched(process.versions.node)) return;
  var plain = "hello world ".repeat(50);
  var br = zlib.brotliCompressSync(Buffer.from(plain, "utf8"));
  var out = b.safeDecompress(br, {
    algorithm: "brotli", maxOutputBytes: C.BYTES.kib(64),
  });
  check("brotli round-trip preserves bytes", out.toString("utf8") === plain);
}

// CVE-2026-111497: the Brotli decoder bundled with Node before 22.23.4,
// 24.22.1 and 26.12.1 writes past an 8-byte input buffer on an invalid block
// switch. On such a runtime the "brotli" algorithm refuses before any byte
// reaches the decoder; on a fixed runtime it decompresses. The RED proof runs
// this file under node:24.21.0.
function testBrotliRefusedOnUnfixedRuntime() {
  var br = zlib.brotliCompressSync(Buffer.from("hello world ".repeat(50), "utf8"));
  var threw = null;
  var out = null;
  try {
    out = b.safeDecompress(br, { algorithm: "brotli", maxOutputBytes: C.BYTES.kib(64) });
  } catch (e) { threw = e; }
  if (C._brotliDecoderPatched(process.versions.node)) {
    check("fixed runtime " + process.versions.node + ": brotli decompresses",
          threw === null && out !== null && out.length === 600,
          threw && threw.code);
  } else {
    check("unfixed runtime " + process.versions.node +
          ": brotli refuses with safe-decompress/unsafe-runtime",
          threw && threw.code === "safe-decompress/unsafe-runtime",
          threw ? threw.code + " " + threw.message : "decompressed " + (out && out.length) + " bytes");
    check("unfixed runtime: the refusal names the CVE",
          threw && /CVE-2026-111497/.test(threw.message));
  }
}

// The refusal reads process.versions.node at call time, so a test can report
// an unfixed release on any host. The input is refused before it reaches the
// decoder, so no byte is decoded under the reported version.
function _asNodeVersion(version, fn) {
  var descriptor = Object.getOwnPropertyDescriptor(process.versions, "node");
  Object.defineProperty(process.versions, "node",
    { value: version, configurable: true, enumerable: true, writable: false });
  try { return fn(); }
  finally { Object.defineProperty(process.versions, "node", descriptor); }
}

function testUnsafeRuntimeRefusalIsAudited() {
  var br = zlib.brotliCompressSync(Buffer.from("hello world ".repeat(50), "utf8"));
  ["24.21.0", "26.12.0", "24.22.1-pre", "27.0.0-nightly20260101abc"].forEach(function (v) {
    var captured = [];
    var threw = null;
    _asNodeVersion(v, function () {
      try {
        b.safeDecompress(br, {
          algorithm: "brotli", maxOutputBytes: C.BYTES.kib(64), ctx: "unsafe-runtime-test",
          audit: { safeEmit: function (e) { captured.push(e); } },
        });
      } catch (e) { threw = e; }
    });
    check("Node " + v + ": brotli refuses with safe-decompress/unsafe-runtime",
          threw && threw.code === "safe-decompress/unsafe-runtime",
          threw ? threw.code + " " + threw.message : "no refusal");
    check("Node " + v + ": the refusal emits one safe_decompress.refused audit event",
          captured.length === 1 &&
          captured[0].action === "system.safe_decompress.refused" &&
          captured[0].outcome === "denied" &&
          captured[0].metadata.code === "safe-decompress/unsafe-runtime" &&
          captured[0].metadata.algorithm === "brotli" &&
          captured[0].metadata.ctx === "unsafe-runtime-test",
          JSON.stringify(captured));
    check("Node " + v + ": the refusal names the CVE and the reported version",
          threw && /CVE-2026-111497/.test(threw.message) &&
          threw.message.indexOf(v) !== -1, threw && threw.message);
    check("Node " + v + ": the upgrade advice names 24.22.1 and 26.12.1 only",
          threw && /24\.22\.1/.test(threw.message) && /26\.12\.1/.test(threw.message) &&
          !/22\.23\.4/.test(threw.message), threw && threw.message);
  });
  var gz = zlib.gzipSync(Buffer.from("hello world ".repeat(50), "utf8"));
  var gzOut = _asNodeVersion("24.21.0", function () {
    return b.safeDecompress(gz, { algorithm: "gzip", maxOutputBytes: C.BYTES.kib(64) });
  });
  check("Node 24.21.0: gzip is unaffected", gzOut.length === 600);
}

// ---- maxOutputBytes refusal (pre-allocation, via zlib's maxOutputLength) ----

function testMaxOutputBytesRefusal() {
  // 100 KB of zeros → ~100 bytes compressed → expands far past a 1 KB cap
  var plain = Buffer.alloc(C.BYTES.kib(100), 0);
  var gz = zlib.gzipSync(plain);
  var threw = null;
  try {
    b.safeDecompress(gz, { algorithm: "gzip", maxOutputBytes: C.BYTES.kib(1) });
  } catch (e) { threw = e; }
  // Its own code, distinct from a malformed stream. A caller acts differently
  // on the two -- amplification says something about the sender, a malformed
  // stream says something about the transfer -- and the alternative is every
  // caller walking the `.cause` chain and matching zlib's wording, which has
  // changed across Node releases.
  check("output > maxOutputBytes → refused before allocation",
        threw && threw.code === "safe-decompress/output-cap-exceeded",
        String(threw && threw.code));
  check("and the refusal keeps zlib's own error for diagnosis",
        threw && threw.cause && typeof threw.cause.message === "string",
        String(threw && threw.cause && threw.cause.code));

  // A stream that is not a bomb but is not gzip either keeps the other code,
  // so the two cannot be told apart only by which one happened to be checked.
  var malformed = null;
  try {
    b.safeDecompress(Buffer.from([0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xFF, 0xFF]),
      { algorithm: "gzip", maxOutputBytes: C.BYTES.mib(1) });
  } catch (e) { malformed = e; }
  check("a malformed stream is not reported as amplification",
        malformed && malformed.code === "safe-decompress/decompress-failed",
        String(malformed && malformed.code));
}

// ---- maxRatio refusal (post-decompress, the new defense vs status quo) ----

function testMaxRatioRefusal() {
  // 50 KB of zeros compresses to a few hundred bytes → ratio ~200:1.
  // With maxRatio: 50 the framework refuses even though the output
  // size is well under any reasonable absolute cap.
  var plain = Buffer.alloc(C.BYTES.kib(50), 0);
  var gz = zlib.gzipSync(plain);
  var threw = null;
  try {
    b.safeDecompress(gz, {
      algorithm:      "gzip",
      maxOutputBytes: C.BYTES.mib(1),                          // absolute cap is generous
      maxRatio:       50,                                       // ratio cap refuses
    });
  } catch (e) { threw = e; }
  check("ratio > maxRatio → refused even when output fits maxOutputBytes",
        threw && /safe-decompress\/ratio-exceeded/.test(threw.code || ""));
}

function testMaxRatioZeroUnlimited() {
  // maxRatio: 0 (unlimited) — same payload that tripped above passes.
  var plain = Buffer.alloc(C.BYTES.kib(50), 0);
  var gz = zlib.gzipSync(plain);
  var out = b.safeDecompress(gz, {
    algorithm: "gzip", maxOutputBytes: C.BYTES.mib(1), maxRatio: 0,
  });
  check("maxRatio: 0 → unlimited expansion accepted",
        out.length === plain.length);
}

// ---- Input cap ----

function testMaxCompressedBytesRefusal() {
  var plain = Buffer.alloc(C.BYTES.kib(50), "x");                                    // text compresses less
  var gz = zlib.gzipSync(plain);
  var threw = null;
  try {
    b.safeDecompress(gz, {
      algorithm:          "gzip",
      maxOutputBytes:     C.BYTES.mib(1),
      maxCompressedBytes: 10,                                                         // far below the actual compressed size
    });
  } catch (e) { threw = e; }
  check("compressed input > maxCompressedBytes → refused",
        threw && /oversized-input/.test(threw.code || ""));
}

// ---- Bad-arg refusal paths ----

function testEmptyInput() {
  var threw = null;
  try {
    b.safeDecompress(Buffer.alloc(0), { algorithm: "gzip", maxOutputBytes: 1024 });
  } catch (e) { threw = e; }
  check("empty input → refused", threw && /empty-input/.test(threw.code || ""));
}

function testBadInputShape() {
  var threw = null;
  try {
    b.safeDecompress("not a buffer", { algorithm: "gzip", maxOutputBytes: 1024 });
  } catch (e) { threw = e; }
  check("non-Buffer input → refused", threw && /bad-input/.test(threw.code || ""));
}

function testBadMaxOutputBytes() {
  var threw = null;
  try {
    b.safeDecompress(Buffer.from("x"), { algorithm: "gzip", maxOutputBytes: -1 });
  } catch (e) { threw = e; }
  check("negative maxOutputBytes → refused", threw && /bad-arg/.test(threw.code || ""));
}

function testMissingMaxOutputBytes() {
  var threw = null;
  try { b.safeDecompress(Buffer.from("x"), { algorithm: "gzip" }); }
  catch (e) { threw = e; }
  check("missing maxOutputBytes → refused", threw && /bad-arg/.test(threw.code || ""));
}

// ---- maxCompressedBytes alignment for caller-configurable caps ----

function testMaxCompressedBytesAlignsWithMaxOutputBytes() {
  // Codex P1 regression check (PR #110): if a caller's
  // `maxOutputBytes` exceeds the safeDecompress default
  // `maxCompressedBytes` of 4 MiB AND the caller forgets to pass
  // `maxCompressedBytes`, the silent 4 MiB cap refuses legitimate
  // large inputs. Verify the explicit-pass shape used by WS works.
  //
  // 5 MiB of zeros → ~5 KB compressed (~1000:1 ratio). Fits under
  // a 6 MiB maxOutputBytes; compressed bytes well under any cap.
  var plain = Buffer.alloc(C.BYTES.mib(5), 0);
  var gz = zlib.gzipSync(plain);
  var out = b.safeDecompress(gz, {
    algorithm:          "gzip",
    maxOutputBytes:     C.BYTES.mib(6),
    maxCompressedBytes: C.BYTES.mib(6),                              // explicit alignment
    maxRatio:           0,                                            // unlimited (legitimate high compression)
  });
  check("5 MiB compressed roundtrip with aligned caller bound", out.length === plain.length);
}

// ---- Audit emission on refusal ----

function testAuditEmittedOnRatioRefusal() {
  var captured = [];
  var auditFake = {
    safeEmit: function (e) { captured.push(e); },
  };
  var plain = Buffer.alloc(C.BYTES.kib(50), 0);
  var gz = zlib.gzipSync(plain);
  try {
    b.safeDecompress(gz, {
      algorithm:      "gzip",
      maxOutputBytes: C.BYTES.mib(1),
      maxRatio:       50,
      audit:          auditFake,
      ctx:            "test-ctx",
    });
  } catch (_e) { /* expected */ }

  check("audit event captured on ratio refusal", captured.length === 1);
  if (captured.length === 1) {
    var ev = captured[0];
    check("audit event action is system.safe_decompress.refused",
          ev.action === "system.safe_decompress.refused");
    check("audit event outcome is denied", ev.outcome === "denied");
    check("audit metadata names the ratio code",
          ev.metadata && ev.metadata.code === "safe-decompress/ratio-exceeded");
    check("audit metadata carries operator ctx",
          ev.metadata && ev.metadata.ctx === "test-ctx");
  }
}

// requireFullInput refuses input bytes left over after the compressed stream
// ends; without it the leftover bytes are ignored.
function testRequireFullInput() {
  var plain = Buffer.from("hello world ".repeat(20), "utf8");
  var cases = [
    ["deflate-raw", zlib.deflateRawSync(plain)],
    ["deflate",     zlib.deflateSync(plain)],
  ];
  if (C._brotliDecoderPatched(process.versions.node)) cases.push(["brotli", zlib.brotliCompressSync(plain)]);
  cases.forEach(function (c) {
    var trailing = Buffer.concat([c[1], Buffer.from("PK\u0003\u0004trailing")]);
    var loose = b.safeDecompress(trailing, { algorithm: c[0], maxOutputBytes: C.BYTES.kib(64) });
    check("requireFullInput: " + c[0] + " ignores trailing bytes when the option is off", loose.equals(plain));
    var captured = [];
    var threw = null;
    try {
      b.safeDecompress(trailing, {
        algorithm: c[0], maxOutputBytes: C.BYTES.kib(64), requireFullInput: true,
        audit: { safeEmit: function (e) { captured.push(e); } },
      });
    } catch (e) { threw = e; }
    check("requireFullInput: " + c[0] + " refuses trailing bytes",
      threw && threw.code === "safe-decompress/trailing-input", threw ? threw.code : "no error");
    check("requireFullInput: " + c[0] + " refusal is audited",
      captured.length === 1 && captured[0].metadata.code === "safe-decompress/trailing-input");
    var exact = b.safeDecompress(c[1], { algorithm: c[0], maxOutputBytes: C.BYTES.kib(64), requireFullInput: true });
    check("requireFullInput: " + c[0] + " accepts a stream that ends at the last input byte", exact.equals(plain));
  });
  var gz = zlib.gzipSync(plain);
  var twoMembers = b.safeDecompress(Buffer.concat([gz, gz]), {
    algorithm: "gzip", maxOutputBytes: C.BYTES.kib(64), requireFullInput: true,
  });
  check("requireFullInput: two concatenated gzip members are read in full",
    twoMembers.equals(Buffer.concat([plain, plain])));
  var badFlag = null;
  try { b.safeDecompress(gz, { algorithm: "gzip", maxOutputBytes: 1024, requireFullInput: "yes" }); }
  catch (e) { badFlag = e; }
  check("requireFullInput: a non-boolean value is refused",
    badFlag && badFlag.code === "safe-decompress/bad-arg", badFlag ? badFlag.code : "no error");
}

async function run() {
  testSurface();
  testRequireFullInput();
  testAlgorithmRequired();
  testAlgorithmAllowlistRefusesUnknown();
  testAlgorithmAllowlistRefusesPrototypeKeys();
  testGzipRoundTrip();
  testDeflateRawRoundTrip();
  testBrotliRoundTrip();
  testBrotliRefusedOnUnfixedRuntime();
  testUnsafeRuntimeRefusalIsAudited();
  testMaxOutputBytesRefusal();
  testMaxRatioRefusal();
  testMaxRatioZeroUnlimited();
  testMaxCompressedBytesRefusal();
  testEmptyInput();
  testBadInputShape();
  testBadMaxOutputBytes();
  testMissingMaxOutputBytes();
  testMaxCompressedBytesAlignsWithMaxOutputBytes();
  testAuditEmittedOnRatioRefusal();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
