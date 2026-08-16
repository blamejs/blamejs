// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.codepointClass — control-char predicate helpers
 * (isForbiddenControlChar / firstControlCharOffset).
 */
var helpers = require("../helpers");
var check = helpers.check;
var codepointClass = require("../../lib/codepoint-class");

function testIsForbiddenControlChar() {
  var f = codepointClass.isForbiddenControlChar;
  // NUL and other C0 controls are forbidden by default.
  check("isForbiddenControlChar: NUL forbidden", f(0x00) === true);
  check("isForbiddenControlChar: 0x01 forbidden", f(0x01) === true);
  check("isForbiddenControlChar: 0x1f forbidden", f(0x1f) === true);
  // TAB always permitted.
  check("isForbiddenControlChar: TAB permitted", f(0x09) === false);
  // DEL always forbidden, regardless of opts.
  check("isForbiddenControlChar: DEL forbidden", f(0x7f) === true);
  check("isForbiddenControlChar: DEL forbidden even with allowLf/allowCr",
        f(0x7f, { allowLf: true, allowCr: true }) === true);
  // Printable + high-bit are not control chars.
  check("isForbiddenControlChar: space ok", f(0x20) === false);
  check("isForbiddenControlChar: 'A' ok", f(0x41) === false);
  check("isForbiddenControlChar: 0xff ok", f(0xff) === false);
  // LF / CR forbidden by default, permitted only when opted in.
  check("isForbiddenControlChar: LF forbidden by default", f(0x0a) === true);
  check("isForbiddenControlChar: CR forbidden by default", f(0x0d) === true);
  check("isForbiddenControlChar: LF permitted with allowLf", f(0x0a, { allowLf: true }) === false);
  check("isForbiddenControlChar: CR still forbidden with allowLf only", f(0x0d, { allowLf: true }) === true);
  check("isForbiddenControlChar: CR permitted with allowCr", f(0x0d, { allowCr: true }) === false);
  check("isForbiddenControlChar: LF still forbidden with allowCr only", f(0x0a, { allowCr: true }) === true);
  // forbidTab — the stricter identifier / key / name contexts forbid TAB too,
  // making the predicate exactly `code < 0x20 || code === 0x7f`.
  check("isForbiddenControlChar: TAB forbidden with forbidTab", f(0x09, { forbidTab: true }) === true);
  check("isForbiddenControlChar: NUL still forbidden with forbidTab", f(0x00, { forbidTab: true }) === true);
  check("isForbiddenControlChar: DEL still forbidden with forbidTab", f(0x7f, { forbidTab: true }) === true);
  check("isForbiddenControlChar: space ok with forbidTab", f(0x20, { forbidTab: true }) === false);
  check("isForbiddenControlChar: 'A' ok with forbidTab", f(0x41, { forbidTab: true }) === false);
  // forbidTab is byte-equivalent to the open-coded `code < 0x20 || code === 0x7f`
  // across every codepoint (the routed name/key validators rely on this).
  var forbidTabParity = true;
  for (var cp = 0; cp <= 0x200; cp += 1) {
    if (f(cp, { forbidTab: true }) !== (cp < 0x20 || cp === 0x7f)) { forbidTabParity = false; break; }
  }
  check("isForbiddenControlChar: forbidTab === (code < 0x20 || code === 0x7f)", forbidTabParity);
  check("firstControlCharOffset: TAB forbidden with forbidTab → offset",
        codepointClass.firstControlCharOffset("a\tb", { forbidTab: true }) === 1);
  check("firstControlCharOffset: TAB allowed by default → -1",
        codepointClass.firstControlCharOffset("a\tb") === -1);
}

function testFirstControlCharOffset() {
  var g = codepointClass.firstControlCharOffset;
  check("firstControlCharOffset: clean string → -1", g("hello world") === -1);
  check("firstControlCharOffset: TAB ok → -1", g("a\tb\tc") === -1);
  check("firstControlCharOffset: empty → -1", g("") === -1);
  check("firstControlCharOffset: NUL at 1", g("a\x00b") === 1);
  check("firstControlCharOffset: DEL at 2", g("ab\x7fc") === 2);
  check("firstControlCharOffset: first of multiple", g("ok\x01\x02") === 2);
  check("firstControlCharOffset: LF found by default", g("a\nb") === 1);
  check("firstControlCharOffset: LF skipped with allowLf", g("a\nb", { allowLf: true }) === -1);
  check("firstControlCharOffset: CRLF skipped with allowLf+allowCr",
        g("a\r\nb", { allowLf: true, allowCr: true }) === -1);
  check("firstControlCharOffset: CR found when only allowLf", g("a\rb", { allowLf: true }) === 1);
}

// #332 — the catalog is now exported on the public b. surface so a consumer
// can build a custom free-text screen without reaching into the internal
// module path or re-rolling the bidi / control / zero-width regexes.
function testPublicSurface() {
  var b = helpers.b;
  check("b.codepointClass is on the public surface", typeof b.codepointClass === "object");
  // The detectors / classifier the issue names are reachable + functional.
  check("b.codepointClass.detectCharThreats is a function", typeof b.codepointClass.detectCharThreats === "function");
  check("b.codepointClass.assertNoCharThreats is a function", typeof b.codepointClass.assertNoCharThreats === "function");
  check("b.codepointClass.applyCharStripPolicies is a function", typeof b.codepointClass.applyCharStripPolicies === "function");
  check("b.codepointClass.scriptFor is a function", typeof b.codepointClass.scriptFor === "function");
  check("b.codepointClass.detectMixedScripts is a function", typeof b.codepointClass.detectMixedScripts === "function");
  // The range tables and the scanners that read them are reachable; the class
  // regexes they replaced are gone, so a consumer cannot reintroduce one by
  // reaching for a compiled export.
  check("b.codepointClass.BIDI_RANGES is a table", Array.isArray(b.codepointClass.BIDI_RANGES));
  check("b.codepointClass.C0_CTRL_RANGES is a table", Array.isArray(b.codepointClass.C0_CTRL_RANGES));
  check("b.codepointClass.ZERO_WIDTH_RANGES is a table", Array.isArray(b.codepointClass.ZERO_WIDTH_RANGES));
  check("b.codepointClass.TAG_RANGES is a table", Array.isArray(b.codepointClass.TAG_RANGES));
  check("b.codepointClass.inRanges is a function", typeof b.codepointClass.inRanges === "function");
  check("b.codepointClass.firstInRanges is a function", typeof b.codepointClass.firstInRanges === "function");
  check("b.codepointClass.stripRanges is a function", typeof b.codepointClass.stripRanges === "function");
  check("the compiled class regexes are no longer exported",
        b.codepointClass.BIDI_RE === undefined &&
        b.codepointClass.BIDI_RE_G === undefined &&
        b.codepointClass.C0_CTRL_RE === undefined &&
        b.codepointClass.C0_CTRL_RE_G === undefined &&
        b.codepointClass.ZERO_WIDTH_RE === undefined &&
        b.codepointClass.ZW_RE_G === undefined &&
        b.codepointClass.NULL_RE_G === undefined &&
        b.codepointClass.TAG_RE === undefined &&
        b.codepointClass.TAG_RE_G === undefined);
  check("b.codepointClass.NULL_BYTE is the NUL char", b.codepointClass.NULL_BYTE === "\x00");

  // Functional smoke: a bidi-override Trojan-source payload is detected; a
  // Cyrillic confusable mixed into a Latin label is flagged.
  var bidi = "abc" + codepointClass.fromCp(0x202E) + "def";
  var issues = b.codepointClass.detectCharThreats(bidi, { bidiPolicy: "reject" }, "free-text");
  check("public detectCharThreats flags a bidi override", issues.length >= 1 && issues[0].kind === "bidi-override");

  var spoof = "pa" + codepointClass.fromCp(0x0443) + "pal";   // Cyrillic u (U+0443)
  var scripts = b.codepointClass.detectMixedScripts(spoof);
  check("public detectMixedScripts flags a Latin/Cyrillic confusable",
        Array.isArray(scripts) && scripts.indexOf("latin") !== -1 && scripts.indexOf("cyrillic") !== -1);

  // strip policy removes the override (sanitize path).
  var cleaned = b.codepointClass.applyCharStripPolicies(bidi, { bidiPolicy: "strip" });
  check("public applyCharStripPolicies strips the override", cleaned === "abcdef");

  // The composition helpers are reachable + correct on the public surface too,
  // so a consumer building its own screen doesn't reach into the internal path.
  check("b.codepointClass.hex4", b.codepointClass.hex4(0x202E) === "\\u202E");
  check("b.codepointClass.charClass",
        b.codepointClass.charClass([0x200E, [0x202A, 0x202E]]) === "\\u200E\\u202A-\\u202E");
  check("b.codepointClass.fromCp", codepointClass.fromCp(0x41) === "A");
  check("b.codepointClass.escapeRegExp",
        b.codepointClass.escapeRegExp("a.b*c") === "a\\.b\\*c");
  check("b.codepointClass.isAsciiAlnum",
        b.codepointClass.isAsciiAlnum(0x5a) === true && b.codepointClass.isAsciiAlnum(0x2d) === false);
  check("b.codepointClass.isUnreserved",
        b.codepointClass.isUnreserved(0x7e) === true && b.codepointClass.isUnreserved(0x2f) === false);
  check("b.codepointClass.isForbiddenControlChar",
        b.codepointClass.isForbiddenControlChar(0x00) === true && b.codepointClass.isForbiddenControlChar(0x41) === false);
  check("b.codepointClass.firstControlCharOffset",
        b.codepointClass.firstControlCharOffset("ok\x00bad") === 2 && b.codepointClass.firstControlCharOffset("clean") === -1);
  check("b.codepointClass.decodeNumericEntities",
        b.codepointClass.decodeNumericEntities("&#106;avascript:") === "javascript:" &&
        b.codepointClass.decodeNumericEntities("&#106avascript:") === "javascript:");
  check("b.codepointClass.decodeMarkupEntities",
        b.codepointClass.decodeMarkupEntities("ex&#x70;ression(") === "expression(" &&
        b.codepointClass.decodeMarkupEntities("behavior&colon;url(") === "behavior:url(" &&
        b.codepointClass.decodeMarkupEntities("a&Tab;b").charCodeAt(1) === 0x09);
  check("b.codepointClass.stripUrlSchemeWhitespace",
        b.codepointClass.stripUrlSchemeWhitespace("  javascript:x") === "javascript:x" &&
        b.codepointClass.stripUrlSchemeWhitespace(
          "java" + codepointClass.fromCp(0x09) + "script:") === "javascript:");
  // The remaining catalog constants the issue lists are reachable.
  check("b.codepointClass.BOM_CHAR",
        typeof b.codepointClass.BOM_CHAR === "string" && b.codepointClass.BOM_CHAR.charCodeAt(0) === 0xFEFF);
}

// The threat scans are unbounded, so on untrusted input the size refusal has
// to come first — otherwise they run in full over whatever an attacker sends
// and the ceiling only applies afterwards. scrubCharThreats owns that
// ordering; assertNoCharThreats deliberately does NOT apply a ceiling of its
// own, because callers reach it having already refused or repaired an
// oversized input under their own rule and a second ceiling would override
// their error with a different one.
// The Tags policy inherits the zero-width one, but only when the guard names
// none of its own. Every scrub path resolves it here rather than re-reading
// `zeroWidthPolicy` — a second reading silently overrides an explicit
// `tagsPolicy: "allow"`, so validate reports nothing while the scrub strips.
function testResolveTagsPolicy() {
  check("resolveTagsPolicy inherits zeroWidthPolicy when tagsPolicy is unset",
        codepointClass.resolveTagsPolicy({ zeroWidthPolicy: "strip" }) === "strip");
  check("an explicit tagsPolicy wins over the inherited one",
        codepointClass.resolveTagsPolicy({ zeroWidthPolicy: "strip", tagsPolicy: "allow" }) === "allow");
  check("an explicit reject wins the same way",
        codepointClass.resolveTagsPolicy({ zeroWidthPolicy: "allow", tagsPolicy: "reject" }) === "reject");
  check("neither set resolves to undefined",
        codepointClass.resolveTagsPolicy({}) === undefined);
  check("no opts at all resolves to undefined",
        codepointClass.resolveTagsPolicy(null) === undefined);
}

function testCharThreatCeilingOrdering() {
  var factory = function (code, msg) { var e = new Error(msg); e.code = code; return e; };
  var oversized = "a".repeat(4096) + codepointClass.fromCp(0x202E);

  var err = null;
  try {
    codepointClass.assertWithinMaxBytes(oversized, { maxBytes: 64 }, factory, "probe");
  } catch (e) { err = e; }
  check("assertWithinMaxBytes refuses past the ceiling",
        err !== null && err.code === "probe.too-large");
  check("assertWithinMaxBytes passes under the ceiling",
        codepointClass.assertWithinMaxBytes("short", { maxBytes: 64 }, factory, "probe") === undefined);
  check("assertWithinMaxBytes without maxBytes is a no-op",
        codepointClass.assertWithinMaxBytes(oversized, {}, factory, "probe") === undefined);

  // Oversized AND carrying a reject-class threat: the size refusal wins, which
  // is only possible if the ceiling runs before the scans.
  var err2 = null;
  try {
    codepointClass.scrubCharThreats(oversized,
      { maxBytes: 64, bidiPolicy: "reject" }, factory, "probe");
  } catch (e) { err2 = e; }
  check("scrubCharThreats refuses on SIZE before scanning for threats",
        err2 !== null && err2.code === "probe.too-large");

  // Under the ceiling the threat scan still decides, and strip still strips.
  var err3 = null;
  try {
    codepointClass.scrubCharThreats("ok" + codepointClass.fromCp(0x202E),
      { maxBytes: 4096, bidiPolicy: "reject" }, factory, "probe");
  } catch (e) { err3 = e; }
  check("scrubCharThreats still refuses a threat under the ceiling",
        err3 !== null && err3.code === "probe.bidi");
  check("scrubCharThreats strips a strip-class char under the ceiling",
        codepointClass.scrubCharThreats("a" + codepointClass.fromCp(0x200B) + "b",
          { maxBytes: 4096, zeroWidthPolicy: "strip" }, factory, "probe") === "ab");

  // assertNoCharThreats imposes no ceiling of its own — a guard that applies
  // its own length rule keeps it.
  var err4 = null;
  try {
    codepointClass.assertNoCharThreats("a".repeat(4096), { maxBytes: 8 }, factory, "probe");
  } catch (e) { err4 = e; }
  check("assertNoCharThreats does not impose a ceiling of its own", err4 === null);
}

// Every reference pattern in this file is compiled from the shared range
// tables rather than typed as a literal, so no attack character appears in the
// source and a table change cannot leave a stale reference behind.
function referenceClassRe(ranges, flags) {
  var astral = ranges.some(function (r) {
    return (typeof r === "number" ? r : r[1]) > 0xFFFF;
  });
  return new RegExp("[" + codepointClass.charClass(ranges) + "]",
                    (flags || "") + (astral ? "u" : ""));
}

// `charClass` builds the body of a character class from a range table. For a
// codepoint above U+FFFF a `\uXXXX` escape cannot express it — `0`
// re-parses as `` followed by a literal `0`, which inside a range turns
// the class into nearly everything. The astral form has to be `\u{...}`.
function testCharClassHandlesAstralCodepoints() {
  var body = codepointClass.charClass(codepointClass.TAG_RANGES);
  check("charClass emits the \\u{...} form for an astral codepoint",
        body.indexOf("\\u{E0000}") !== -1 && body.indexOf("\\u{E007F}") !== -1);
  check("charClass does not truncate an astral codepoint to \\uXXXX",
        body.indexOf("\\uE000") === -1);

  // The defect stated behaviorally: compiled and applied, the class must match
  // a Tags character and nothing else.
  var re = referenceClassRe(codepointClass.TAG_RANGES);
  check("the compiled astral class matches a Tags codepoint",
        re.test(String.fromCodePoint(0xE0041)) === true);
  check("the compiled astral class does not match an ordinary letter",
        re.test("A") === false);
  check("the compiled astral class does not match a BMP private-use char",
        re.test(String.fromCharCode(0xE000)) === false);

  // The BMP tables keep the compact escape.
  check("charClass keeps \\uXXXX for BMP codepoints",
        codepointClass.charClass([0x200E, [0x202A, 0x202E]]) ===
        "\\u200E\\u202A-\\u202E");
}

// The scanners replaced regexes. This compares them against a reference
// compiled from the same tables, over a corpus built from every range
// boundary, so a scanner that walks code units instead of codepoints or misses
// an edge shows up as a disagreement rather than as a silent gap.
function testRangeScannersMatchARegexReference() {
  var CLASSES = [
    ["BIDI",       codepointClass.BIDI_RANGES],
    ["C0_CTRL",    codepointClass.C0_CTRL_RANGES],
    ["ZERO_WIDTH", codepointClass.ZERO_WIDTH_RANGES],
    ["TAGS",       codepointClass.TAG_RANGES],
  ];

  var corpus = ["", "plain ascii", "你好", "a".repeat(200)];
  CLASSES.forEach(function (c) {
    c[1].forEach(function (r) {
      var cps = typeof r === "number" ? [r]
              : [r[0], r[1], Math.floor((r[0] + r[1]) / 2)];
      cps.forEach(function (cp) {
        var ch = String.fromCodePoint(cp);
        corpus.push(ch, "x" + ch, ch + "x", "pre " + ch + " post", ch + ch,
                    "a" + ch + "b" + ch + "c");
      });
    });
  });
  corpus.push(String.fromCodePoint(0x1F600), "a" + String.fromCodePoint(0x1F600) + "b",
              String.fromCodePoint(0x10FFFF), "\uD800", "\uDFFF",
              "ok" + String.fromCodePoint(0x202E) + String.fromCodePoint(0xE0041) +
              String.fromCharCode(0x200B));

  var compared = 0;
  var matchDiffs = 0, indexDiffs = 0, stripDiffs = 0;
  corpus.forEach(function (s) {
    CLASSES.forEach(function (c) {
      var ranges = c[1];
      var re  = referenceClassRe(ranges);
      var reG = referenceClassRe(ranges, "g");
      compared += 1;

      var refHit  = s.match(re);
      var refIdx  = refHit ? refHit.index : -1;
      var scanIdx = codepointClass.firstInRanges(s, ranges);
      if ((refIdx === -1) !== (scanIdx === -1)) matchDiffs += 1;
      else if (refIdx !== -1 && refIdx !== scanIdx) indexDiffs += 1;

      if (s.replace(reG, "") !== codepointClass.stripRanges(s, ranges)) stripDiffs += 1;
    });
  });

  check("range scanners compared against the reference on a real corpus",
        compared >= 400);
  check("firstInRanges agrees with the reference on whether there is a match",
        matchDiffs === 0);
  check("firstInRanges agrees with the reference on WHERE the match is",
        indexDiffs === 0);
  check("stripRanges agrees with the reference regex replace", stripDiffs === 0);

  // The astral case stated directly, since it is the one a code-unit walk
  // silently gets wrong.
  var TAG = String.fromCodePoint(0xE0041);
  check("firstInRanges finds an astral Tags codepoint",
        codepointClass.firstInRanges("ok" + TAG, codepointClass.TAG_RANGES) === 2);
  check("stripRanges removes an astral codepoint whole, leaving no lone surrogate",
        codepointClass.stripRanges("ok" + TAG, codepointClass.TAG_RANGES) === "ok");
  check("a non-member astral codepoint is left alone",
        codepointClass.stripRanges("a" + String.fromCodePoint(0x1F600) + "b",
          codepointClass.TAG_RANGES) === "a" + String.fromCodePoint(0x1F600) + "b");

  // Allocation: a clean string is returned as-is rather than rebuilt.
  var clean = "no threats here";
  check("stripRanges returns the original string when nothing matched",
        codepointClass.stripRanges(clean, codepointClass.BIDI_RANGES) === clean);

  // The membership predicate the other two are built on.
  check("inRanges matches a bare-codepoint entry",
        codepointClass.inRanges(0x200E, codepointClass.BIDI_RANGES) === true);
  check("inRanges matches inside a [lo, hi] pair",
        codepointClass.inRanges(0x202C, codepointClass.BIDI_RANGES) === true);
  check("inRanges matches both ends of a pair",
        codepointClass.inRanges(0x202A, codepointClass.BIDI_RANGES) === true &&
        codepointClass.inRanges(0x202E, codepointClass.BIDI_RANGES) === true);
  check("inRanges rejects just outside a pair",
        codepointClass.inRanges(0x2029, codepointClass.BIDI_RANGES) === false &&
        codepointClass.inRanges(0x202F, codepointClass.BIDI_RANGES) === false);
  check("inRanges rejects an ordinary letter",
        codepointClass.inRanges(0x61, codepointClass.BIDI_RANGES) === false);
  check("inRanges works on an astral table",
        codepointClass.inRanges(0xE0041, codepointClass.TAG_RANGES) === true &&
        codepointClass.inRanges(0x1F600, codepointClass.TAG_RANGES) === false);
}

// The character-set scanners the guards use where they used to compile a
// character class. Compared against the pattern each replaced, over a corpus
// that includes the characters a class has to escape — `]`, `-`, `^`, `\` —
// since getting one of those wrong still compiles and quietly matches the
// wrong set.
function testCharSetScanners() {
  var SETS = [
    ["<>:\"/\\|?*", "reserved filename characters"],
    [" .",          "space and dot"],
    ["-",           "a bare hyphen"],
    ["]",           "a bare close bracket"],
    ["^",           "a bare caret"],
    ["\\",          "a bare backslash"],
    ["a-z",         "characters that look like a range"],
    ["",            "the empty set"],
  ];
  var CORPUS = ["", "plain", "a-z", "a]b", "x^y", "back\\slash", "  pad  ",
                "report<final>.csv", "...", " . . ", "]]]", "-a-b-",
                "tab\there", "caf" + String.fromCharCode(0xE9),
                String.fromCodePoint(0x1F600) + "]"];

  function escapeForClass(s) {
    var out = "";
    for (var i = 0; i < s.length; i += 1) {
      out += "\\" + s.charAt(i);   // every char escaped, so no class syntax survives
    }
    return out;
  }

  var idxDiffs = [], repDiffs = [], trimDiffs = [];
  SETS.forEach(function (entry) {
    var chars = entry[0];
    if (chars.length === 0) return;   // an empty class is not expressible
    var body = escapeForClass(chars);
    CORPUS.forEach(function (s) {
      var first = s.search(new RegExp("[" + body + "]"));
      if (codepointClass.indexOfAny(s, chars) !== first) {
        idxDiffs.push(entry[1] + " / " + JSON.stringify(s));
      }
      var replaced = s.replace(new RegExp("[" + body + "]", "g"), "_");
      if (codepointClass.replaceAny(s, chars, "_") !== replaced) {
        repDiffs.push(entry[1] + " / " + JSON.stringify(s));
      }
      var trimmed = s.replace(new RegExp("^[" + body + "]+|[" + body + "]+$", "g"), "");
      if (codepointClass.trimChars(s, chars) !== trimmed) {
        trimDiffs.push(entry[1] + " / " + JSON.stringify(s));
      }
    });
  });
  check("indexOfAny agrees with the character class it replaced",
        idxDiffs.length === 0, idxDiffs.slice(0, 3).join(" | "));
  check("replaceAny agrees with the global class replace it replaced",
        repDiffs.length === 0, repDiffs.slice(0, 3).join(" | "));
  check("trimChars agrees with the anchored trim it replaced",
        trimDiffs.length === 0, trimDiffs.slice(0, 3).join(" | "));

  // replaceRanges is the range-table form. One replacement per CODEPOINT, so
  // an astral character becomes one, not one per surrogate.
  check("b.codepointClass.replaceRanges replaces a BMP class member",
        codepointClass.replaceRanges("a" + String.fromCharCode(0x202E) + "b",
          codepointClass.BIDI_RANGES, "_") === "a_b");
  check("b.codepointClass.replaceRanges replaces an astral member once",
        codepointClass.replaceRanges("a" + String.fromCodePoint(0xE0041) + "b",
          codepointClass.TAG_RANGES, "_") === "a_b");
  check("b.codepointClass.replaceRanges returns the original when nothing matched",
        codepointClass.replaceRanges("abc", codepointClass.BIDI_RANGES, "_") === "abc");
  check("b.codepointClass.replaceRanges with an empty replacement equals stripRanges",
        codepointClass.replaceRanges("a" + String.fromCharCode(0x200B) + "b",
          codepointClass.ZERO_WIDTH_RANGES, "") ===
        codepointClass.stripRanges("a" + String.fromCharCode(0x200B) + "b",
          codepointClass.ZERO_WIDTH_RANGES));

  // Every one of the four reads the set AND the subject as codepoints. A
  // code-unit walk lets a set holding one astral character match half of an
  // unrelated pair, and replaces one character with two replacements.
  var GRIN = String.fromCodePoint(0x1F600);
  var TAG_A = String.fromCodePoint(0xE0041);
  check("indexOfAny finds an astral member of the set",
        codepointClass.indexOfAny("ab" + GRIN, GRIN) === 2);
  check("indexOfAny does not match a lone surrogate against a different pair",
        codepointClass.indexOfAny(TAG_A, "\uDB40") === -1);
  check("indexOfAny skips over an astral non-member",
        codepointClass.indexOfAny(GRIN + "x", "x") === 2);
  check("indexOfAny honors `from`",
        codepointClass.indexOfAny("axbx", "x", 2) === 3);
  // A `from` inside a surrogate pair belongs to a character starting BEFORE
  // it, so that character is not at or after `from` and must not be returned:
  // an index below `from` makes a caller that advances `from` in a loop run
  // forever.
  check("indexOfAny never returns an index below `from`",
        codepointClass.indexOfAny(GRIN + "x", GRIN, 1) === -1);
  check("indexOfAny with `from` inside a pair still finds a later member",
        codepointClass.indexOfAny(GRIN + "x" + GRIN, GRIN, 1) === 3);
  check("indexOfAny with `from` at the start of a pair finds it",
        codepointClass.indexOfAny("x" + GRIN, GRIN, 1) === 1);
  // The answer is a string index, so it is always an integer whatever the
  // caller passed.
  check("a fractional `from` still returns the character's real offset",
        codepointClass.firstInRanges("ab", [0x62], 1.5) === 1);
  check("a fractional `from` past the match still finds the next one",
        codepointClass.firstInRanges("aba", [0x62], 0.5) === 1);
  check("a negative `from` scans from the start",
        codepointClass.firstInRanges("ab", [0x62], -5) === 1);
  check("replaceAny replaces an astral member once",
        codepointClass.replaceAny("a" + GRIN + "b", GRIN, "_") === "a_b");
  check("replaceAny leaves an unrelated pair intact when the set holds a surrogate",
        codepointClass.replaceAny(GRIN, "\uD83D", "_") === GRIN);

  // replaceAny replaces EVERY occurrence — the incomplete-sanitization defect
  // a non-global pattern ships.
  check("replaceAny replaces every occurrence, not the first",
        codepointClass.replaceAny("a<b>c<d>", "<>", "_") === "a_b_c_d_");
  check("replaceAny with an empty replacement removes",
        codepointClass.replaceAny("a<b>c", "<>", "") === "abc");
  check("replaceAny returns the original when nothing matched",
        codepointClass.replaceAny("abc", "<>", "_") === "abc");

  // trimChars ends
  check("trimChars leading only",
        codepointClass.trimChars("..a..", ".", { trailing: false }) === "a..");
  check("trimChars trailing only",
        codepointClass.trimChars("..a..", ".", { leading: false }) === "..a");
  check("trimChars on an all-members string returns empty",
        codepointClass.trimChars("....", ".") === "");

  // WHITESPACE_RANGES has to be exactly what `\s` means, or a trim that used
  // to run over `\s` now leaves characters behind.
  var wsDiffs = [];
  for (var cp = 0; cp <= 0xFFFF; cp += 1) {
    var isWs = /\s/.test(String.fromCharCode(cp));
    if (codepointClass.inRanges(cp, codepointClass.WHITESPACE_RANGES) !== isWs) {
      wsDiffs.push("U+" + cp.toString(16).toUpperCase());
    }
  }
  check("WHITESPACE_RANGES equals \\s across the whole BMP",
        wsDiffs.length === 0, wsDiffs.slice(0, 8).join(" "));

  var trimRangeDiffs = [];
  ["", "  a  ", "a", String.fromCharCode(0x00A0) + "a" + String.fromCharCode(0x3000),
   "\t\r\n a \n", String.fromCharCode(0xFEFF) + "x", "   ",
   String.fromCharCode(0x2028) + "y" + String.fromCharCode(0x205F)].forEach(function (s) {
    if (codepointClass.trimRanges(s, codepointClass.WHITESPACE_RANGES) !==
        s.replace(/^\s+|\s+$/g, "")) {
      trimRangeDiffs.push(JSON.stringify(s));
    }
  });
  check("trimRanges over WHITESPACE_RANGES agrees with the \\s trim it replaced",
        trimRangeDiffs.length === 0, trimRangeDiffs.join(" | "));

  // Both trims step whole codepoints. A code-unit walk reads an astral member
  // as two unrelated surrogates and trims neither end.
  var TAG = String.fromCodePoint(0xE0001);
  check("trimRanges removes a leading astral member",
        codepointClass.trimRanges(TAG + "a", codepointClass.TAG_RANGES) === "a");
  check("trimRanges removes a trailing astral member",
        codepointClass.trimRanges("a" + TAG, codepointClass.TAG_RANGES) === "a");
  check("trimRanges removes an astral run at both ends",
        codepointClass.trimRanges(TAG + TAG + "a" + TAG, codepointClass.TAG_RANGES) === "a");
  check("trimRanges leaves a non-member astral character alone",
        codepointClass.trimRanges(String.fromCodePoint(0x1F600) + "a",
          codepointClass.TAG_RANGES) === String.fromCodePoint(0x1F600) + "a");
  check("trimChars handles an astral character in the set",
        codepointClass.trimChars(String.fromCodePoint(0x1F600) + "a" +
          String.fromCodePoint(0x1F600), String.fromCodePoint(0x1F600)) === "a");
  check("trimChars does not trim half of a surrogate pair",
        codepointClass.trimChars(String.fromCodePoint(0x1F600) + "a", "\uD83D") ===
        String.fromCodePoint(0x1F600) + "a");

  // containsFolded
  check("containsFolded matches across ASCII case",
        codepointClass.containsFolded("dir/%2E%2E/etc", "%2e%2e") === true);
  check("containsFolded matches an exact-case needle",
        codepointClass.containsFolded("dir/%2e%2e/etc", "%2e%2e") === true);
  check("containsFolded rejects a needle that is not there",
        codepointClass.containsFolded("dir/etc", "%2e%2e") === false);
  check("containsFolded does not fold non-ASCII",
        codepointClass.containsFolded(String.fromCharCode(0x0130), "i") === false);
  check("containsFolded on an empty needle is true",
        codepointClass.containsFolded("abc", "") === true);
  check("containsFolded with a needle longer than the subject is false",
        codepointClass.containsFolded("ab", "abc") === false);

  // A folded search over a corpus, against the case-insensitive pattern it
  // replaced. Only ASCII subjects, since that is where the two agree by
  // definition.
  var NEEDLES = ["%2e%2e", "%c0%af", "abc", "A", "//"];
  var foldDiffs = [];
  ["", "abc", "ABC", "%2E%2E", "%2e%2E", "x%C0%AFy", "a//b", "AaAbC",
   "no match here"].forEach(function (s) {
    NEEDLES.forEach(function (n) {
      var ref = new RegExp(n.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&"), "i").test(s);
      if (codepointClass.containsFolded(s, n) !== ref) {
        foldDiffs.push(JSON.stringify(s) + " ~ " + n);
      }
    });
  });
  check("containsFolded agrees with the case-insensitive pattern it replaced",
        foldDiffs.length === 0, foldDiffs.slice(0, 3).join(" | "));

  // Non-string arguments do not throw — these run on request-shaped input.
  check("indexOfAny on a non-string returns -1",
        codepointClass.indexOfAny(null, "abc") === -1 &&
        codepointClass.indexOfAny("abc", null) === -1);
  check("replaceAny on a non-string returns the input",
        codepointClass.replaceAny(null, "abc", "_") === null);
  check("trimChars on a non-string returns the input",
        codepointClass.trimChars(undefined, "abc") === undefined);
  check("containsFolded on a non-string is false",
        codepointClass.containsFolded(null, "a") === false &&
        codepointClass.containsFolded("a", null) === false);
}

// The entity decoders are character walks too. This states the grammar a
// SECOND time as a regex and compares the two over generated input: the walk
// and the reference share no code, so a disagreement is a real defect in one
// of them rather than a typo they both inherited.
function testEntityDecodersMatchARegexReference() {
  function referenceNumeric(s) {
    return String(s == null ? "" : s).replace(/&#(?:x([0-9a-f]+)|(\d+));?/gi,
      function (m, hex, dec) {
        var cp = hex !== undefined ? parseInt(hex, 16) : parseInt(dec, 10);
        if (!isFinite(cp) || cp < 0 || cp > 0x10FFFF) return m;
        try { return String.fromCodePoint(cp); } catch (_e) { return m; }
      });
  }

  // What is written twice here is the GRAMMAR — where a reference starts, how
  // far it runs, whether the semicolon is optional. The name-to-character
  // table is read from the module rather than retyped: a second copy of a
  // 29-entry table tests the typing, and the walk and the pattern would
  // disagree on a typo rather than on a defect.
  var NAMED_ASCII = codepointClass.NAMED_ENTITY_ASCII;
  function referenceMarkup(value) {
    var s = referenceNumeric(String(value == null ? "" : value));
    s = s.replace(/&([A-Za-z][A-Za-z0-9]+);/g, function (m, name) {
      return Object.prototype.hasOwnProperty.call(NAMED_ASCII, name)
        ? NAMED_ASCII[name] : m;
    });
    return s.replace(referenceClassRe(codepointClass.C0_CTRL_RANGES, "g"), "")
            .replace(referenceClassRe(codepointClass.ZERO_WIDTH_RANGES, "g"), "");
  }

  // Every shape the grammar distinguishes, plus the ones that historically
  // slipped past a decoder: no semicolon, uppercase X, an out-of-range value,
  // a bare ampersand, a lone surrogate, a name one character too short.
  var NUMERIC = [
    "", "plain", "&", "&&", "&#", "&#;", "&#x", "&#x;", "&#xg", "&#z",
    "&#106;avascript:", "&#106avascript:", "&#X6A;avascript:", "&#x6A;x",
    "&#0000106;colon", "&#65;&#66;&#67;", "a&#65b&#66;c",
    "&#1114111;", "&#1114112;", "&#x110000;", "&#x10FFFF;",
    "&#55296;", "&#xD800;", "&#0;", "&#00;", "&#-5;", "&#9999999999999;",
    "&amp;#65;", "&#38;#65;", "&#38;amp;", "&#x26;#x41;",
    "&#x41&#x42", "&#" + "9".repeat(40) + ";", "&#x" + "f".repeat(40) + ";",
    "text with no entity at all", "&#32;javascript:", "&#x09;javascript:",
  ];
  var numericDiffs = [];
  NUMERIC.forEach(function (s) {
    if (codepointClass.decodeNumericEntities(s) !== referenceNumeric(s)) {
      numericDiffs.push(JSON.stringify(s));
    }
  });
  check("decodeNumericEntities agrees with an independent reference (" +
        NUMERIC.length + " inputs)",
        numericDiffs.length === 0, numericDiffs.slice(0, 3).join(" | "));

  var NAMED = [
    "", "&", "&;", "&a;", "&ab;", "&Tab;", "&tab;", "&colon;", "&colon",
    "java&Tab;script:", "behavior&colon;", "&NewLine;x", "&amp;", "&amp;amp;",
    "&nbsp;x", "&unknownentity;", "&a1;", "&1a;", "&A9B;", "&Tab;&colon;&sol;",
    "x&Tab", "&&Tab;", "&#38;Tab;", "&Tab&colon;", "&lt;script&gt;",
    "&" + "a".repeat(80) + ";", "&Tab;" + String.fromCharCode(0x200B),
    String.fromCharCode(0x0001) + "&colon;",
  ].concat(NUMERIC);
  var namedDiffs = [];
  NAMED.forEach(function (s) {
    if (codepointClass.decodeMarkupEntities(s) !== referenceMarkup(s)) {
      namedDiffs.push(JSON.stringify(s));
    }
  });
  check("decodeMarkupEntities agrees with an independent reference (" +
        NAMED.length + " inputs)",
        namedDiffs.length === 0, namedDiffs.slice(0, 3).join(" | "));

  // Generated fragments, so the comparison is not limited to the cases I
  // thought of. Fixed ordering, no randomness — a flake here would be worse
  // than a gap.
  var PARTS = ["&", "#", "x", "X", ";", "6", "A", "a", "0", "z", "Tab",
               "colon", "amp", "\t", " ", "j"];
  var generated = 0, genDiffs = [];
  for (var i = 0; i < PARTS.length; i++) {
    for (var j = 0; j < PARTS.length; j++) {
      for (var k = 0; k < PARTS.length; k++) {
        var s = PARTS[i] + PARTS[j] + PARTS[k];
        generated += 2;
        if (codepointClass.decodeNumericEntities(s) !== referenceNumeric(s)) {
          genDiffs.push("numeric:" + JSON.stringify(s));
        }
        if (codepointClass.decodeMarkupEntities(s) !== referenceMarkup(s)) {
          genDiffs.push("markup:" + JSON.stringify(s));
        }
      }
    }
  }
  check("generated entity fragments compared against the reference (" +
        generated + " comparisons)", generated >= 8000);
  check("no generated fragment decodes differently", genDiffs.length === 0,
        genDiffs.slice(0, 5).join(" | "));

  // stripUrlSchemeWhitespace is the third walk in the same family: tab/LF/CR
  // from anywhere, then a leading and trailing C0-or-space run.
  var TAB = String.fromCharCode(0x09), LF = String.fromCharCode(0x0A),
      CR  = String.fromCharCode(0x0D), NUL = String.fromCharCode(0x00);
  var URLS = ["", "javascript:x", "  javascript:x", "java" + TAB + "script:x",
              "java" + LF + "script:x", "java" + CR + "script:x",
              " " + TAB + CR + LF + " javascript:x " + TAB + " ",
              NUL + "javascript:x", "js:x", "a b", "  ",
              "  " + TAB + "end" + TAB + "  ", TAB + LF + CR];
  var urlDiffs = [];
  var trimRe = new RegExp("^(?:[" + codepointClass.charClass([[0x0000, 0x0020]]) +
                          "])+|(?:[" + codepointClass.charClass([[0x0000, 0x0020]]) +
                          "])+$", "g");
  URLS.forEach(function (s) {
    var ref = s.replace(referenceClassRe([0x0009, 0x000A, 0x000D], "g"), "")
               .replace(trimRe, "");
    if (codepointClass.stripUrlSchemeWhitespace(s) !== ref) {
      urlDiffs.push(JSON.stringify(s));
    }
  });
  check("stripUrlSchemeWhitespace agrees with an independent reference",
        urlDiffs.length === 0, urlDiffs.join(" | "));
}

async function run() {
  testIsForbiddenControlChar();
  testFirstControlCharOffset();
  testPublicSurface();
  testCharClassHandlesAstralCodepoints();
  testRangeScannersMatchARegexReference();
  testCharSetScanners();
  testEntityDecodersMatchARegexReference();
  testResolveTagsPolicy();
  testCharThreatCeilingOrdering();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
