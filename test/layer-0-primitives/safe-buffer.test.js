// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.safeBuffer.stripCrlf — remove every CR and LF from a string,
 * substituting the replacement argument (default ""). Used to
 * neutralize header-injection / smuggling vectors when the framework
 * must serialize an operator-supplied string into a CRLF-delimited
 * protocol line and prefers silent stripping over rejecting. Non-string
 * input passes through unchanged.
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

function run() {
  var sb = b.safeBuffer;

  // ---- default replacement drops CR/LF entirely ----
  check("b.safeBuffer.stripCrlf: CRLF removed with the empty-string default",
    b.safeBuffer.stripCrlf("ok\r\nbad") === "okbad");
  check("stripCrlf: a bare CR is removed", sb.stripCrlf("a\rb") === "ab");
  check("stripCrlf: a bare LF is removed", sb.stripCrlf("a\nb") === "ab");
  check("stripCrlf: every CR/LF in a run is removed",
    sb.stripCrlf("h\r\ni\rj\nk") === "hijk");

  // ---- header-injection scenario the primitive exists for ----
  // An operator value carrying a CRLF + a forged header must collapse
  // onto one line so it can't smuggle a second header.
  check("stripCrlf: neutralizes a CRLF header-injection payload",
    b.safeBuffer.stripCrlf("value\r\nX-Injected: evil") === "valueX-Injected: evil");

  // ---- custom replacement ----
  check("stripCrlf: custom replacement substitutes each CR/LF",
    b.safeBuffer.stripCrlf("a\nb\nc", " ") === "a b c");
  check("stripCrlf: each CR and LF is replaced individually",
    sb.stripCrlf("h\r\ni", "-") === "h--i");
  check("stripCrlf: an explicit empty replacement matches the default",
    sb.stripCrlf("a\nb", "") === "ab");

  // ---- no CR/LF present → unchanged ----
  check("stripCrlf: a clean string is returned unchanged",
    sb.stripCrlf("no-newlines-here") === "no-newlines-here");
  check("stripCrlf: an empty string stays empty", sb.stripCrlf("") === "");

  // ---- non-string passthrough (advertised) ----
  check("stripCrlf: a number passes through unchanged", b.safeBuffer.stripCrlf(42) === 42);
  check("stripCrlf: undefined passes through unchanged", sb.stripCrlf(undefined) === undefined);
  check("stripCrlf: null passes through unchanged", sb.stripCrlf(null) === null);
  var obj = { a: 1 };
  check("stripCrlf: a non-string object passes through by identity", sb.stripCrlf(obj) === obj);

  // ---- byteLengthOfIfMeasurable: measures byte-carriers, null for the rest ----
  check("byteLengthOfIfMeasurable: string → UTF-8 byte length",
    b.safeBuffer.byteLengthOfIfMeasurable("中") === 3);
  check("byteLengthOfIfMeasurable: Buffer → length",
    b.safeBuffer.byteLengthOfIfMeasurable(Buffer.from([1, 2, 3, 4])) === 4);
  check("byteLengthOfIfMeasurable: Uint8Array → length",
    b.safeBuffer.byteLengthOfIfMeasurable(new Uint8Array(5)) === 5);
  // The non-byte-carrier cases the guard-family byte cap must skip rather than
  // crash on — a plain Array, an array-like object, a number, null/undefined.
  check("byteLengthOfIfMeasurable: plain Array → null",
    b.safeBuffer.byteLengthOfIfMeasurable([1, 2, 3]) === null);
  check("byteLengthOfIfMeasurable: array-like object → null",
    b.safeBuffer.byteLengthOfIfMeasurable({ length: 1e9 }) === null);
  check("byteLengthOfIfMeasurable: number → null",
    b.safeBuffer.byteLengthOfIfMeasurable(42) === null);
  check("byteLengthOfIfMeasurable: null → null",
    b.safeBuffer.byteLengthOfIfMeasurable(null) === null);
  check("byteLengthOfIfMeasurable: undefined → null",
    b.safeBuffer.byteLengthOfIfMeasurable(undefined) === null);

  testShapePredicatesAgreeWithThePatternsTheyReplaced();
}

// The byte-shape catalog used to be exported as PATTERNS, which every consumer
// then ran itself — one of them with `.replace`, several against values it had
// not capped, and one behind a condition that could never be false. Each is now
// a character walk behind a function. These are the patterns they replaced.
function testShapePredicatesAgreeWithThePatternsTheyReplaced() {
  var sb = b.safeBuffer;

  var HEX_RE           = /^[0-9a-fA-F]+$/;
  var LOWER_HEX_RE     = /^[0-9a-f]+$/;
  var BASE64URL_RE     = /^[A-Za-z0-9_-]+$/;
  var BASE64_RE        = /^[A-Za-z0-9+/]*={0,2}$/;
  var TRACE_ID_HEX_RE  = /^[0-9a-f]{32}$/;
  var SPAN_ID_HEX_RE   = /^[0-9a-f]{16}$/;
  var IPV6_HEXTET_RE   = /^[0-9a-fA-F]{1,4}$/;
  var RFC7230_TCHAR_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
  var CRLF_RE          = /[\r\n]/;

  var VALUES = [
    "", "a", "0", "deadbeef", "DeadBeef", "DEADBEEF", "dead beef", "dead-beef",
    "0123456789abcdef", "0123456789ABCDEF", "0123456789abcdeg", "ffff", "fffff",
    "f", "FFFF", "0000", "00f067aa0ba902b7", "00F067AA0BA902B7",
    "4bf92f3577b34da6a3ce929d0e0e4736", "4bf92f3577b34da6a3ce929d0e0e473",
    "4bf92f3577b34da6a3ce929d0e0e47366", "4BF92F3577B34DA6A3CE929D0E0E4736",
    "eyJhbGciOiJFZERTQSJ9", "a-b_c", "a+b/c", "a+b/c=", "aGVsbG8=", "aGVsbG8==",
    "aGVsbG8===", "=", "==", "===", "=a", "a=b", "a==b", "ab=", "ab==",
    "x-request-id", "X-Request-ID", "bad header", "bad\theader", "a,b", "a;b",
    "!#$%&'*+-.^_`|~", "a(b", "a)b", "a/b", "a:b", "a@b", "a[b", "a{b",
    "a\rb", "a\nb", "a\r\nb", "no breaks", "trailing\n", "\rleading",
    // A character above U+FFFF arrives as two surrogate halves; neither is a
    // member of any of these sets, and a walk that reads code UNITS could
    // read one of them as though it were.
    "de\u{1F600}ad", "\u{1F600}", "a\u{10000}b", "é", "café",
    // Built from codepoints rather than typed: a dotted capital I whose
    // lower-case form is TWO characters, a full-width Latin a, and a
    // zero-width space — the last of which is invisible in a source file.
    String.fromCharCode(0x0130), String.fromCharCode(0xFF41),
    String.fromCharCode(0x200B) + "ab",
  ];

  var diffs = [];
  VALUES.forEach(function (v) {
    function compare(label, expected, actual) {
      if (expected !== actual) diffs.push(label + " " + JSON.stringify(v) +
                                          " want " + expected + " got " + actual);
    }
    compare("isHex",        HEX_RE.test(v),           sb.isHex(v));
    compare("isLowerHex",   LOWER_HEX_RE.test(v),     sb.isLowerHex(v));
    compare("isBase64Url",  BASE64URL_RE.test(v),     sb.isBase64Url(v));
    compare("isBase64",     BASE64_RE.test(v),        sb.isBase64(v));
    compare("isTraceIdHex", TRACE_ID_HEX_RE.test(v),  sb.isTraceIdHex(v));
    compare("isSpanIdHex",  SPAN_ID_HEX_RE.test(v),   sb.isSpanIdHex(v));
    compare("isIpv6Hextet", IPV6_HEXTET_RE.test(v),   sb.isIpv6Hextet(v));
    compare("isHttpToken",  RFC7230_TCHAR_RE.test(v), sb.isHttpToken(v));
    compare("hasCrlf",      CRLF_RE.test(v),          sb.hasCrlf(v));
    compare("stripCrlf",    v.replace(/[\r\n]/g, ""), sb.stripCrlf(v));
    compare("isHex(len)",   HEX_RE.test(v) && v.length === 8, sb.isHex(v, 8));
  });
  check("every byte-shape predicate agrees with the pattern it replaced (" +
        VALUES.length + " values)", diffs.length === 0, diffs.slice(0, 5).join(" | "));

  // Every predicate takes whatever a defensive reader hands it.
  [null, undefined, 42, {}, [], Buffer.from("ab"), true].forEach(function (v) {
    var name = Object.prototype.toString.call(v);
    check("non-string " + name + " is refused by every shape predicate",
          sb.isHex(v) === false && sb.isLowerHex(v) === false &&
          sb.isBase64(v) === false && sb.isBase64Url(v) === false &&
          sb.isIpv6Hextet(v) === false && sb.isTraceIdHex(v) === false &&
          sb.isSpanIdHex(v) === false && sb.isHttpToken(v) === false &&
          sb.hasCrlf(v) === false);
  });

  // Two sequential replacements are not one pass: escaping the backslashes
  // first produces backslashes the quote pass would then escape again.
  check("quoteString escapes each backslash and quote exactly once",
        sb.quoteString("a\\\"b") === "\"a\\\\\\\"b\"");
  check("quoteString leaves an unescaped value alone",
        sb.quoteString("cache miss") === "\"cache miss\"");
  check("quoteString coerces a non-string", sb.quoteString(42) === "\"42\"");

  // The lstrip half of the pair. Compared against the pattern rather than
  // asserted by hand, because the interesting question is what it does NOT
  // strip: a leading line break stays, so a folded header keeps its fold.
  var LEADING_HSPACE_RE = /^[ \t]+/;
  var stripDiffs = [];
  ["", " ", "  a", "\ta", " \t a", "a  ", "\na", " \na", "\n a", "no-leading",
   "\r\n a", "  \u00a0a"].forEach(function (v) {
    var want = v.replace(LEADING_HSPACE_RE, "");
    var got = b.safeBuffer.stripLeadingHspace(v);
    if (want !== got) {
      stripDiffs.push(JSON.stringify(v) + " want " + JSON.stringify(want) +
                      " got " + JSON.stringify(got));
    }
  });
  check("b.safeBuffer.stripLeadingHspace agrees with /^[ \\t]+/ on every case",
        stripDiffs.length === 0, stripDiffs.join(" | "));
  check("stripLeadingHspace leaves a leading line break alone",
        b.safeBuffer.stripLeadingHspace("\n  x") === "\n  x");
  check("stripLeadingHspace passes a non-string through",
        b.safeBuffer.stripLeadingHspace(42) === 42);

  testRemovedPatternExportsSignpostTheirReplacement();
  testConsolidatedCallersKeptTheirAcceptanceSets();
}

// Where ONE shared primitive replaced SEVERAL callers' patterns, each of those
// callers had its own accidental contract, and the shared version follows the
// spec. That gap is where a consolidation silently widens or narrows a screen
// — `b.time.parseISO` lost three separate arguments to it. This restates each
// caller's ORIGINAL pattern and asserts the shared primitive still answers the
// same way, so a future change to the primitive cannot move any of them
// without saying so.
function testConsolidatedCallersKeptTheirAcceptanceSets() {
  var VALUES = [
    "", "a", "x-request-id", "X-Request-ID", "bad header", "a,b", "a;b",
    "!#$%&'*+-.^_`|~", "a(b", "a/b", "a:b", "a@b", "a[b", "a{b", "a\"b",
    "a\\b", "a=b", "a?b", "aGVsbG8=", "aGVsbG8", "deadbeef", "DEADBEEF",
    "audit_log", "_x", "1x", "col-1", "sqlite_x", "ffff", "fffff", "==",
    "2026-08-16", "2026-8-16", "a\rb", "a\nb", "no breaks", "café",
    // The grouping cases that separate `isBase64` from `isCanonicalBase64`:
    // an alphabet-and-padding check passes all of these and a decoder then
    // drops what it cannot use.
    "A", "AA", "AAA", "AAAA", "AA==", "AAA=", "A===", "====", "AAAAA",
  ];

  var CASES = [
    // The RFC 7230 tchar set — five call sites had spelled it three ways
    // (guard-mime, middleware/headers, observability baggage, request-helpers,
    // and cookies, whose class listed the same characters in another order).
    ["the tchar set, as guard-mime / headers / baggage / request-helpers had it",
     /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/, function (v) { return b.safeBuffer.isHttpToken(v); }],
    ["the tchar set, as cookies had it",
     /^[!#$%&'*+\-.0-9A-Z^_`a-z|~]+$/, function (v) { return b.safeBuffer.isHttpToken(v); }],
    ["the SQL identifier shape, as five db primitives had it",
     /^[A-Za-z_][A-Za-z0-9_]*$/, function (v) { return b.safeSql.isDefaultIdentifier(v); }],
    ["hex, as the digest and manifest callers had it",
     /^[0-9a-fA-F]+$/, function (v) { return b.safeBuffer.isHex(v); }],
    ["base64url, as the JOSE / WebAuthn / ini / agent callers had it",
     /^[A-Za-z0-9_-]+$/, function (v) { return b.safeBuffer.isBase64Url(v); }],
    ["base64, as the manifest and CloudEvents callers had it",
     /^[A-Za-z0-9+/]*={0,2}$/, function (v) { return b.safeBuffer.isBase64(v); }],
    ["canonical base64, as safe-schema had it",
     /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/,
     function (v) { return b.safeBuffer.isCanonicalBase64(v); }],
    ["the IPv6 hextet, as cidr / network-tls / safe-json had it",
     /^[0-9a-fA-F]{1,4}$/, function (v) { return b.safeBuffer.isIpv6Hextet(v); }],
    ["the CRLF check, as the header builders had it",
     /[\r\n]/, function (v) { return b.safeBuffer.hasCrlf(v); }],
    ["the full-date shape, as safe-schema had it",
     /^\d{4}-\d{2}-\d{2}$/, function (v) { return b.safeSchema.isDate(v); }],
  ];

  var diffs = [];
  CASES.forEach(function (c) {
    VALUES.forEach(function (v) {
      var want = c[1].test(v);
      var got = c[2](v);
      if (want !== got) {
        diffs.push(c[0] + " " + JSON.stringify(v) + " want " + want + " got " + got);
      }
    });
  });
  check("every consolidated caller keeps the acceptance set it had (" +
        CASES.length + " shapes x " + VALUES.length + " values)",
        diffs.length === 0, diffs.slice(0, 5).join(" | "));

  // The line splitters: guard-dsn normalized CRLF then bare CR before
  // splitting; safe-vcard and safe-ical split on one alternation. Both must
  // still equal `splitLinesAny`, or a folded line moves.
  var lineDiffs = [];
  ["", "a", "a\nb", "a\r\nb", "a\rb", "a\r\rb", "a\n\nb", "a\r\n\r\nb",
   "x\r", "x\n", "x\r\n", "\ra", "\na"].forEach(function (v) {
    var viaDsn = v.split("\r\n").join("\n").split("\r").join("\n").split("\n");
    var viaVcard = v.split(/\r\n?|\n/);
    var got = b.codepointClass.splitLinesAny(v);
    if (JSON.stringify(viaDsn) !== JSON.stringify(got) ||
        JSON.stringify(viaVcard) !== JSON.stringify(got)) {
      lineDiffs.push(JSON.stringify(v) + " walk " + JSON.stringify(got));
    }
  });
  check("the wire-format line splitters agree with both spellings they replaced",
        lineDiffs.length === 0, lineDiffs.slice(0, 3).join(" | "));

  // The distinction the two base64 checks exist for. An alphabet-and-padding
  // check accepts a value no decoder can turn into bytes; Node's decoder then
  // DROPS what it cannot use rather than failing, so a caller that treated
  // the two as interchangeable reports a malformed field as a failed
  // verification and sends the operator looking at keys.
  check("isBase64 accepts a value that carries no whole byte; " +
        "isCanonicalBase64 does not",
        b.safeBuffer.isBase64("A") === true &&
        b.safeBuffer.isCanonicalBase64("A") === false);
  check("...and the same for a padding-only value",
        b.safeBuffer.isBase64("=") === true &&
        b.safeBuffer.isCanonicalBase64("=") === false);
  check("Node's decoder is the reason: it drops what it cannot use",
        Buffer.from("A", "base64").length === 0 &&
        Buffer.from("=", "base64").length === 0);

  // Canonical also means the bits that encode nothing are zero (RFC 4648
  // §3.5). A padded group carries fewer bits than its characters can express,
  // and a decoder discards the rest — so `AB==` and `AA==` are two spellings
  // of one byte, which is what a canonical encoding rules out. The reference
  // is Node itself: decode then re-encode, and a canonical value is unchanged.
  var A = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  var padDiffs = [];
  for (var hi = 0; hi < 64; hi += 1) {
    for (var lo = 0; lo < 64; lo += 1) {
      var twoPad = A.charAt(hi) + A.charAt(lo) + "==";
      var wantTwo = Buffer.from(twoPad, "base64").toString("base64") === twoPad;
      if (b.safeBuffer.isCanonicalBase64(twoPad) !== wantTwo) padDiffs.push(twoPad);
      var onePad = A.charAt(hi) + A.charAt(lo) + A.charAt((hi + lo) % 64) + "=";
      var wantOne = Buffer.from(onePad, "base64").toString("base64") === onePad;
      if (b.safeBuffer.isCanonicalBase64(onePad) !== wantOne) padDiffs.push(onePad);
    }
  }
  check("every padded encoding agrees with a decode/re-encode round-trip " +
        "(spare bits must be zero)", padDiffs.length === 0,
        padDiffs.slice(0, 5).join(" "));
  check("the named non-canonical pairs are refused",
        b.safeBuffer.isCanonicalBase64("AB==") === false &&
        b.safeBuffer.isCanonicalBase64("AA==") === true &&
        b.safeBuffer.isCanonicalBase64("AAB=") === false &&
        b.safeBuffer.isCanonicalBase64("AAA=") === true);
}

// The pattern exports are gone rather than aliased: an alias would hand back a
// runnable pattern, which is the hazard the removal exists to close. What an
// upgrading operator gets instead is a throw that names the replacement,
// rather than `undefined` and a "Cannot read properties of undefined" at
// whatever line happened to touch it.
function testRemovedPatternExportsSignpostTheirReplacement() {
  var REMOVED = [
    ["safeBuffer", "HEX_RE",                "isHex"],
    ["safeBuffer", "BASE64URL_RE",          "isBase64Url"],
    ["safeBuffer", "BASE64_RE",             "isBase64"],
    ["safeBuffer", "IPV6_HEXTET_RE",        "isIpv6Hextet"],
    ["safeBuffer", "TRACE_ID_HEX_RE",       "isTraceIdHex"],
    ["safeBuffer", "SPAN_ID_HEX_RE",        "isSpanIdHex"],
    ["safeBuffer", "RFC7230_TCHAR_RE",      "isHttpToken"],
    ["safeBuffer", "CRLF_RE",               "hasCrlf"],
    ["safeBuffer", "TRAILING_HSPACE_RE",    "stripTrailingHspace"],
    ["safeSchema", "EMAIL_RE",              "isEmail"],
    ["safeSchema", "URL_RE",                "isUrl"],
    ["safeSchema", "UUID_RE",               "isUuid"],
    ["safeSchema", "DATE_RE",               "isDate"],
    ["safeSchema", "DATETIME_RE",           "isDatetime"],
    ["safeSchema", "IPV4_RE",               "isIpv4"],
    ["safeSchema", "IPV6_RE",               "isIpv6"],
    ["safeSchema", "CUID_RE",               "isCuid"],
    ["safeSchema", "ULID_RE",               "isUlid"],
    ["safeSql",    "DEFAULT_IDENTIFIER_RE", "isDefaultIdentifier"],
  ];

  var bad = [];
  REMOVED.forEach(function (entry) {
    var namespace = entry[0];
    var key = entry[1];
    var replacement = entry[2];
    var thrown = null;
    try { void b[namespace][key]; }
    catch (e) { thrown = e; }
    if (thrown === null) {
      bad.push("b." + namespace + "." + key + " is still readable");
      return;
    }
    if (thrown.code !== "deprecate/removed") {
      bad.push("b." + namespace + "." + key + " threw " + thrown.code);
      return;
    }
    if (thrown.message.indexOf(replacement) === -1) {
      bad.push("b." + namespace + "." + key + " does not name " + replacement);
    }
    if (typeof b[namespace][replacement] !== "function") {
      bad.push("b." + namespace + "." + replacement + " is not a function");
    }
  });
  check("every removed pattern export throws naming its replacement (" +
        REMOVED.length + " exports)", bad.length === 0, bad.slice(0, 5).join(" | "));

  // Non-enumerable, so a removed name cannot reappear in `Object.keys` or a
  // JSON dump of the namespace — which would make it look present again.
  check("a removed export does not enumerate",
        Object.keys(b.safeBuffer).indexOf("HEX_RE") === -1 &&
        Object.keys(b.safeSchema).indexOf("EMAIL_RE") === -1 &&
        Object.keys(b.safeSql).indexOf("DEFAULT_IDENTIFIER_RE") === -1);

  // Writing is refused too — a caller "restoring" the old name would get a
  // pattern back into circulation.
  var restored = null;
  try { b.safeBuffer.HEX_RE = /^[0-9a-f]+$/; }
  catch (e) { restored = e; }
  check("a removed export cannot be written back",
        restored !== null && restored.code === "deprecate/removed");
}

module.exports = { run: run };

if (require.main === module) {
  try { run(); console.log("OK — " + helpers.getChecks() + " checks passed"); }
  catch (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
}
