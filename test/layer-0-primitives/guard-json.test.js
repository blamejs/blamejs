// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * guard-json — JSON content-safety primitive (b.guardJson).
 *
 * Covers: surface; registry parity; prototype-pollution detection at
 * source level (catches __proto__ / constructor / prototype keys
 * BEFORE parse — JSON.parse silently routes __proto__ through the
 * prototype setter so post-parse Object.keys misses it); duplicate-key
 * detection; NaN / Infinity / undefined refusal; comment refusal
 * (line + block); trailing comma refusal; JSON5 syntax refusal
 * (single-quoted keys, hex literals); BOM detection; bidi / null /
 * control char detection; numeric precision-loss; depth + breadth +
 * array-length + string-length + node-count caps; top-level-key
 * allowlist; sanitize round-trip (strip pollution); gate decision
 * shapes; profile + posture vocabulary.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function testGuardJsonSurface() {
  check("guardJson is an object",                    typeof b.guardJson === "object");
  check("guardJson.NAME === 'json'",                 b.guardJson.NAME === "json");
  check("guardJson.KIND === 'content'",              b.guardJson.KIND === "content");
  check("guardJson.MIME_TYPES has application/json", b.guardJson.MIME_TYPES.indexOf("application/json") !== -1);
  check("guardJson.EXTENSIONS has .json",            b.guardJson.EXTENSIONS.indexOf(".json") !== -1);
  check("guardJson.PROFILES has strict",             !!b.guardJson.PROFILES["strict"]);
  check("guardJson.PROFILES has balanced",           !!b.guardJson.PROFILES["balanced"]);
  check("guardJson.PROFILES has permissive",         !!b.guardJson.PROFILES["permissive"]);
  check("guardJson.COMPLIANCE_POSTURES has hipaa",   !!b.guardJson.COMPLIANCE_POSTURES["hipaa"]);
  check("guardJson.validate is a function",          typeof b.guardJson.validate === "function");
  check("guardJson.parse is a function",             typeof b.guardJson.parse === "function");
  check("guardJson.gate is a function",              typeof b.guardJson.gate === "function");
  check("guardJson.GuardJsonError is a function",    typeof b.guardJson.GuardJsonError === "function");
  check("frameworkError.GuardJsonError exposed",     typeof b.frameworkError.GuardJsonError === "function");
}

function testGuardJsonRegistryParity() {
  check("guardJson registered in guardAll",
        b.guardAll.list().some(function (g) { return g.name === "json"; }));
  var entry = b.guardAll.list().filter(function (g) { return g.name === "json"; })[0];
  b.guardAll.SHARED_PROFILES.forEach(function (p) {
    check("registry: json supports shared profile " + p,
          entry.profiles.indexOf(p) !== -1);
  });
  b.guardAll.SHARED_POSTURES.forEach(function (p) {
    check("registry: json supports shared posture " + p,
          entry.postures.indexOf(p) !== -1);
  });
}

function testGuardJsonPrototypePollution() {
  // Plain __proto__ at top level. After JSON.parse, this is invisible
  // to Object.keys() — the source-level scan is the only reliable
  // detection (CVE-2025-55182 React Server Functions class).
  var rv1 = b.guardJson.validate('{"__proto__":{"polluted":true}}',
                                 { profile: "strict" });
  check("source-level __proto__ detected (strict)",
        rv1.ok === false &&
        rv1.issues.some(function (i) { return i.kind === "prototype-pollution-key"; }));

  // constructor / prototype at any depth.
  var rv2 = b.guardJson.validate('{"x":{"constructor":{"y":1}}}',
                                 { profile: "strict" });
  check("nested constructor key detected",
        rv2.issues.some(function (i) { return i.kind === "prototype-pollution-key"; }));

  var rv3 = b.guardJson.validate('{"a":{"prototype":1}}',
                                 { profile: "strict" });
  check("nested prototype key detected",
        rv3.issues.some(function (i) { return i.kind === "prototype-pollution-key"; }));

  // Audit-level under permissive.
  var rv4 = b.guardJson.validate('{"__proto__":{"x":1}}',
                                 { profile: "permissive" });
  check("permissive: pollution audited (high severity, ok=false because high counts)",
        rv4.issues.some(function (i) { return i.kind === "prototype-pollution-key"; }));
}

function testGuardJsonParseStripPollution() {
  // strict throws on pollution.
  var threw = null;
  try { b.guardJson.parse('{"__proto__":{"x":1}}', { profile: "strict" }); }
  catch (e) { threw = e; }
  check("parse strict: throws on __proto__",
        threw && /prototype-pollution/.test(threw.code || threw.message || ""));

  // balanced strips and returns clean object.
  var clean = b.guardJson.parse('{"__proto__":{"x":1},"a":2,"b":3}',
                                { profile: "balanced" });
  check("parse balanced: strips __proto__",
        Object.keys(clean).length === 2 && clean.a === 2 && clean.b === 3);
  check("parse balanced: prototype not polluted via stripped __proto__",
        Object.prototype.x === undefined);
}

function testGuardJsonDuplicateKeys() {
  var rv = b.guardJson.validate('{"a":1,"a":2}', { profile: "strict" });
  check("duplicate-key detected (RFC 8259 SHOULD-unique violation)",
        rv.issues.some(function (i) { return i.kind === "duplicate-key"; }));

  var rvNested = b.guardJson.validate('{"x":{"a":1,"a":2}}', { profile: "strict" });
  check("nested duplicate-key detected",
        rvNested.issues.some(function (i) { return i.kind === "duplicate-key"; }));

  // Same key at DIFFERENT scopes — not a duplicate.
  var rvOk = b.guardJson.validate('{"x":{"a":1},"y":{"a":2}}', { profile: "strict" });
  check("same key at different scopes NOT flagged",
        !rvOk.issues.some(function (i) { return i.kind === "duplicate-key"; }));
}

function testGuardJsonNanInfinity() {
  var rv1 = b.guardJson.validate('{"x":NaN}', { profile: "strict" });
  check("NaN detected (RFC 8259 forbids)",
        rv1.issues.some(function (i) { return i.kind === "nan-infinity"; }));

  var rv2 = b.guardJson.validate('{"x":Infinity}', { profile: "strict" });
  check("Infinity detected",
        rv2.issues.some(function (i) { return i.kind === "nan-infinity"; }));

  var rv3 = b.guardJson.validate('{"x":-Infinity}', { profile: "strict" });
  check("-Infinity detected",
        rv3.issues.some(function (i) { return i.kind === "nan-infinity"; }));

  var rv4 = b.guardJson.validate('{"x":undefined}', { profile: "strict" });
  check("undefined token detected",
        rv4.issues.some(function (i) { return i.kind === "nan-infinity"; }));
}

function testGuardJsonComments() {
  var rvLine = b.guardJson.validate('// comment\n{"x":1}', { profile: "strict" });
  check("line comment detected (RFC 8259 forbids; JSON5 / JSONC accept)",
        rvLine.issues.some(function (i) { return i.kind === "comment-line"; }));

  var rvBlock = b.guardJson.validate('/* note */ {"x":1}', { profile: "strict" });
  check("block comment detected",
        rvBlock.issues.some(function (i) { return i.kind === "comment-block"; }));
}

function testGuardJsonTrailingComma() {
  var rv = b.guardJson.validate('{"x":1,}', { profile: "strict" });
  check("trailing comma detected (RFC 8259 forbids)",
        rv.issues.some(function (i) { return i.kind === "trailing-comma"; }));
}

function testGuardJsonJson5Syntax() {
  // Single-quoted key — JSON5 / JSONC only.
  var rvSq = b.guardJson.validate("{'x':1}", { profile: "strict" });
  check("single-quoted key detected (JSON5-only)",
        rvSq.issues.some(function (i) { return i.kind === "single-quoted-key"; }));

  // Hex literal.
  var rvHex = b.guardJson.validate('{"x":0xFF}', { profile: "strict" });
  check("hex literal detected (JSON5-only)",
        rvHex.issues.some(function (i) { return i.kind === "hex-literal"; }));
}

function testGuardJsonBom() {
  var bom = String.fromCharCode(0xFEFF);
  var rvLead = b.guardJson.validate(bom + '{"x":1}', { profile: "strict" });
  check("leading BOM detected",
        rvLead.issues.some(function (i) { return i.kind === "bom-leading"; }));

  var rvMid = b.guardJson.validate('{"x":' + bom + '1}', { profile: "strict" });
  check("mid-stream BOM detected",
        rvMid.issues.some(function (i) { return i.kind === "bom-mid-stream"; }));
}

function testGuardJsonDepthCap() {
  // Build deeply nested JSON exceeding strict maxDepth=8.
  var deep = "";
  for (var i = 0; i < 20; i++) deep += '{"x":';
  deep += "1";
  for (var j = 0; j < 20; j++) deep += "}";
  var rv = b.guardJson.validate(deep, { profile: "strict" });
  check("depth-cap detected",
        rv.issues.some(function (i) { return i.kind === "depth-cap" ||
                                              i.kind === "parse-failed"; }));
}

function testGuardJsonKeyCountCap() {
  var keys = [];
  for (var i = 0; i < 1000; i++) keys.push('"k' + i + '":' + i);
  var rv = b.guardJson.validate("{" + keys.join(",") + "}", { profile: "strict" });
  check("key-count cap detected (strict 256 cap)",
        rv.issues.some(function (i) { return i.kind === "key-count-cap"; }));
}

function testGuardJsonArrayLengthCap() {
  var elems = [];
  for (var i = 0; i < 5000; i++) elems.push(String(i));
  var rv = b.guardJson.validate("[" + elems.join(",") + "]", { profile: "strict" });
  check("array-length cap detected (strict 1024 cap)",
        rv.issues.some(function (i) { return i.kind === "array-length-cap"; }));
}

function testGuardJsonStringLengthCap() {
  // Strict maxStringLength = 8 KiB.
  var bigStr = '"' + "x".repeat(10000) + '"';
  var rv = b.guardJson.validate('{"k":' + bigStr + '}', { profile: "strict" });
  check("string-length cap detected",
        rv.issues.some(function (i) { return i.kind === "string-too-long"; }));
}

function testGuardJsonStringLengthByteCap() {
  // maxStringLength is a per-string BYTE cap (strict 8 KiB). A multibyte string
  // whose UTF-16 code-unit count is UNDER the cap but whose UTF-8 byte length
  // EXCEEDS it must still be refused — value.length (code units) under-enforces.
  // 4100 'é' = 4100 code units (< 8192) but 8200 UTF-8 bytes (> 8192).
  var multibyte = "é".repeat(4100);
  var rv = b.guardJson.validate('{"k":"' + multibyte + '"}', { profile: "strict" });
  check("per-string maxStringLength measured in UTF-8 bytes (multibyte not under-enforced)",
        rv.issues.some(function (i) { return i.kind === "string-too-long"; }));
}

function testGuardJsonByteCap() {
  // maxBytes is a BYTE cap — multibyte input must be measured by UTF-8
  // byte length, not UTF-16 code-unit count (.length). "é" is one code
  // unit but two bytes, so a string under the char count can still
  // exceed the byte cap.
  var inner = "é".repeat(25);
  var s     = JSON.stringify(inner);               // .length ~27, bytes ~52
  var byteLen = Buffer.byteLength(s, "utf8");
  // Cap sits between the code-unit count and the byte length so a
  // char-length check would (wrongly) pass while a byte check refuses.
  var cap = s.length + 5;
  check("byte-cap fixture: bytes exceed cap but code units do not",
        byteLen > cap && s.length <= cap);
  var rv = b.guardJson.validate(s, { maxBytes: cap });
  check("multibyte input over the byte cap is refused (too-large by bytes)",
        rv.issues.some(function (i) {
          return i.kind === "too-large" && i.ruleId === "json.too-large";
        }));

  // ASCII inputs (one byte per code unit) are unaffected — a byte-length
  // cap that exactly admits the string must still pass.
  var ascii = '"' + "x".repeat(20) + '"';           // 22 bytes, 22 code units
  var rvAscii = b.guardJson.validate(ascii, { maxBytes: 64 });
  check("ASCII input within the byte cap is not flagged too-large",
        !rvAscii.issues.some(function (i) { return i.kind === "too-large"; }));

  // Non-string input keeps the bad-input shape and now carries a ruleId.
  var rvBad = b.guardJson.validate(12345, { maxBytes: 64 });
  check("non-string input → bad-input with json.bad-input ruleId",
        rvBad.issues.some(function (i) {
          return i.kind === "bad-input" && i.ruleId === "json.bad-input";
        }));
}

function testGuardJsonNumericPrecision() {
  var rv = b.guardJson.validate('{"id":99999999999999999999}', { profile: "strict" });
  check("numeric precision-loss detected (above MAX_SAFE_INTEGER)",
        rv.issues.some(function (i) { return i.kind === "numeric-precision-loss"; }));
}

function testGuardJsonTopLevelKeyAllowlist() {
  var rv = b.guardJson.validate('{"a":1,"b":2,"unauthorized":3}', {
    profile:                      "strict",
    requireTopLevelKeyAllowlist:  true,
    topLevelKeyAllowlist:         ["a", "b"],
  });
  check("top-level-key allowlist refuses unauthorized key",
        rv.issues.some(function (i) {
          return i.kind === "top-level-key-not-allowlisted";
        }));

  var rvOk = b.guardJson.validate('{"a":1,"b":2}', {
    profile:               "strict",
    topLevelKeyAllowlist:  ["a", "b"],
  });
  check("top-level allowlist passes when keys all allowed",
        !rvOk.issues.some(function (i) {
          return i.kind === "top-level-key-not-allowlisted";
        }));
}

function testGuardJsonBidi() {
  var bidi = String.fromCharCode(0x202E);   // RLO
  var rv = b.guardJson.validate('{"x":"a' + bidi + 'b"}', { profile: "strict" });
  check("bidi override detected in JSON string value",
        rv.issues.some(function (i) { return i.kind === "bidi-override"; }));
}

function testGuardJsonNullByte() {
  var nb = String.fromCharCode(0);
  var rv = b.guardJson.validate('{"x":"a' + nb + 'b"}', { profile: "strict" });
  check("null byte detected in JSON string",
        rv.issues.some(function (i) { return i.kind === "null-byte"; }));
}

// The source-shape detectors look for JSON5 / JSONC syntax a downstream parser
// would accept — comments, bare NaN, a trailing comma, a hex literal, a
// single-quoted key. All of those are STRUCTURE. The same characters inside a
// string value are ordinary text: a URL contains `//`, prose contains `NaN`,
// and a message contains `, }`. Refusing a document for its content is an
// outage, not a defense — and it lands on exactly the documents most likely to
// carry a URL.
function testValidJsonIsNotRefusedForTheContentOfItsStrings() {
  var CLEAN = [
    ["a URL in a value",            { url: "http://example.com/a/b" }],
    ["a protocol-relative URL",     { url: "//cdn.example.com/x" }],
    ["block-comment text",          { s: "/* not a comment */" }],
    ["line-comment text",           { s: "// not a comment" }],
    ["the word NaN in prose",       { s: "the value is NaN here" }],
    ["Infinity in prose",           { s: "approaches Infinity" }],
    ["undefined in prose",          { s: "left undefined" }],
    ["a comma before a bracket",    { s: "one, ] two" }],
    ["a comma before a brace",      { s: "one, } two" }],
    ["single quotes around a word", { s: "set 'key' : value" }],
    ["a hex literal in prose",      { s: "color 0xFF00FF" }],
    ["a long digit run in prose",   { s: "order 123456789012345678" }],
    ["a Windows path with slashes", { p: "C:/a/b//c" }],
  ];
  CLEAN.forEach(function (row) {
    var doc = JSON.stringify(row[1]);
    var rv = b.guardJson.validate(doc, { profile: "strict" });
    check("valid JSON with " + row[0] + " is clean",
          rv.ok === true && rv.issues.length === 0,
          JSON.stringify(rv.issues.map(function (i) { return i.kind; })));
  });

  // Number shapes, written as source rather than built from JS values: a long
  // run of digits AFTER a decimal point or in an exponent is part of a double
  // the author wrote, not an integer past 2^53. Reading only the leading run
  // and stepping over the separator reports the fraction as its own integer.
  var CLEAN_NUMBERS = [
    ["a long fractional part",        '{"a":0.1234567890123456789}'],
    ["a long fraction after digits",  '{"a":1.234567890123456789}'],
    ["a signed long exponent",        '{"a":1e-123456789012345678}'],
    ["a fraction and an exponent",    '{"a":1.234567890123456789e5}'],
    ["the largest finite double",     '{"a":1.7976931348623157e308}'],
    ["an ordinary integer",           '{"a":42}'],
    ["a 16-digit integer",            '{"a":1234567890123456}'],
  ];
  CLEAN_NUMBERS.forEach(function (row) {
    var rv = b.guardJson.validate(row[1], { profile: "strict" });
    check("valid JSON with " + row[0] + " is clean",
          rv.ok === true && rv.issues.length === 0,
          JSON.stringify(rv.issues.map(function (i) { return i.kind; })));
  });

  // A negative hex literal is finite. Reading the sign as part of the token
  // makes the conversion NaN, which is not an overflow — a JSON5 document
  // with hex allowed would then be refused for a value of -1.
  var negHex = b.guardJson.validate('{"a":-0x1}',
    { profile: "strict", json5SyntaxPolicy: "allow" }).issues;
  check("a negative hex literal is not reported as non-finite",
        negHex.every(function (i) { return i.kind !== "nan-infinity"; }),
        JSON.stringify(negHex.map(function (i) { return i.kind; })));
  var bigNegHex = b.guardJson.validate('{"a":-0x' + "f".repeat(300) + '}',
    { profile: "strict", json5SyntaxPolicy: "allow" }).issues;
  check("a negative hex literal past the double range IS reported",
        bigNegHex.some(function (i) { return i.kind === "nan-infinity"; }),
        JSON.stringify(bigNegHex.map(function (i) { return i.kind; })));

  // JSON5 accepts a trailing decimal point where RFC 8259 does not, so this
  // document fails the parse — but a decimal point makes the token a float
  // either way, and the precision check must not call it an integer.
  var trailingPoint = b.guardJson.validate('{"a":12345678901234567.}',
                                           { profile: "strict" }).issues;
  check("a trailing decimal point is not reported as an integer past 2^53",
        trailingPoint.every(function (i) { return i.kind !== "numeric-precision-loss"; }),
        JSON.stringify(trailingPoint.map(function (i) { return i.kind; })));

  // And the same documents pass the gate rather than being refused.
  return Promise.all(CLEAN.map(function (row) {
    return b.guardJson.gate({ profile: "strict" })
      .check({ bytes: Buffer.from(JSON.stringify(row[1]), "utf8") })
      .then(function (d) {
        check("the gate serves valid JSON with " + row[0], d.action === "serve",
              d.action);
      });
  }));
}

// The other half of the same root: a shape the detector cannot see because it
// sits where the pattern's fixed prefix cannot match. A line comment straight
// after a string value is the case — the pattern needed a non-quote character
// in front of the slashes.
function testJson5ShapesAreFoundWhereverTheySit() {
  var HOSTILE = [
    ["line comment after a string value",  '{"a":"b"// c\n}',      "comment-line"],
    ["line comment after a number",        '{"a":1 // c\n}',       "comment-line"],
    ["line comment at the start",          '// c\n{"a":1}',        "comment-line"],
    ["line comment after a brace",         '{// c\n"a":1}',        "comment-line"],
    ["block comment after a string value", '{"a":"b"/* c */}',     "comment-block"],
    ["bare NaN after a string value",      '{"a":"b","c":NaN}',    "nan-infinity"],
    ["bare Infinity",                      '{"a":Infinity}',       "nan-infinity"],
    ["negative Infinity",                  '{"a":-Infinity}',      "nan-infinity"],
    ["bare undefined",                     '{"a":undefined}',      "nan-infinity"],
    ["trailing comma before a brace",      '{"a":"b",}',           "trailing-comma"],
    ["trailing comma before a bracket",    '["a",]',               "trailing-comma"],
    ["a hex literal value",                '{"a":0xFF}',           "hex-literal"],
    ["a negative hex literal",             '{"a":-0x1f}',          "hex-literal"],
    ["a single-quoted key",                "{'a':1}",              "single-quoted-key"],
    ["a single-quoted key after a value",  "{\"a\":1,'b':2}",      "single-quoted-key"],
    ["a single-quoted key with an escaped quote", "{'a\\'b':1}",   "single-quoted-key"],
    ["a single-quoted key after an escaped one",  "{'a\\'b':1,'c':2}", "single-quoted-key"],
    ["an integer past 2^53",               '{"a":123456789012345678}', "numeric-precision-loss"],
    ["a negative integer past 2^53",       '{"a":-123456789012345678}', "numeric-precision-loss"],
    ["a big integer beside a long float",  '{"a":0.1234567890123456789,"b":123456789012345678}',
                                           "numeric-precision-loss"],
    // A magnitude no double can hold reaches the consumer as Infinity, which
    // is what nanInfinityPolicy refuses — written as an exponent rather than
    // as the word, so a scan for the word alone never sees it.
    ["an exponent that overflows to Infinity", '{"a":1e123456789012345678}', "nan-infinity"],
    ["a negative overflowing exponent",        '{"a":-1e400}',               "nan-infinity"],
    ["the first double past the maximum",      '{"a":1.8e308}',              "nan-infinity"],
    ["a __proto__ key",                    '{"__proto__":{"x":1}}', "prototype-pollution-key"],
  ];
  HOSTILE.forEach(function (row) {
    var kinds = b.guardJson.validate(row[1], { profile: "strict" }).issues
      .map(function (i) { return i.kind; });
    check("flagged: " + row[0], kinds.indexOf(row[2]) !== -1,
          "want " + row[2] + " got " + JSON.stringify(kinds));
  });
}

function testGuardJsonClean() {
  var rv = b.guardJson.validate('{"name":"alice","age":30,"tags":["a","b"]}',
                                { profile: "strict" });
  check("clean JSON → ok=true with no issues", rv.ok === true && rv.issues.length === 0);
}

async function testGuardJsonGate() {
  var g = b.guardJson.gate({ profile: "strict" });
  var clean = await g.check({
    contentType: "application/json",
    bytes:       Buffer.from('{"x":1}', "utf8"),
  });
  check("gate clean → action=serve",
        clean.ok === true && clean.action === "serve");

  var hostile = await g.check({
    contentType: "application/json",
    bytes:       Buffer.from('{"__proto__":{"polluted":true}}', "utf8"),
  });
  check("gate hostile pollution → action !== serve",
        hostile.action !== "serve");
}

async function testGuardJsonGateSanitizeByPolicy() {
  // The gate decides sanitize-vs-refuse from the finding's OWN policy, not a
  // global "is any policy reject?" guess that wrongly blocked sanitize for
  // unrelated findings. So the SAME __proto__ input REFUSES under
  // pollutionPolicy=reject and SANITIZES under pollutionPolicy=strip (the
  // parse drops __proto__) — independent of the other policies' reject state.
  var pollute = Buffer.from('{"__proto__":{"x":1},"keep":2}', "utf8");
  var reject = await b.guardJson.gate({ profile: "strict", pollutionPolicy: "reject" })
    .check({ bytes: pollute });
  check("pollutionPolicy=reject → refuse", reject.action === "refuse");
  var strip = await b.guardJson.gate({ profile: "strict", pollutionPolicy: "strip" })
    .check({ bytes: pollute });
  check("pollutionPolicy=strip → sanitize (__proto__ dropped per policy)",
        strip.action === "sanitize" &&
        strip.sanitized.toString("utf8").indexOf("__proto__") === -1 &&
        strip.sanitized.toString("utf8").indexOf("keep") !== -1);
}

function testGuardJsonCompliancePosture() {
  var hipaa = b.guardJson.compliancePosture("hipaa");
  check("compliancePosture('hipaa') sets reject policies",
        hipaa.pollutionPolicy === "reject" &&
        hipaa.bidiPolicy === "reject" &&
        hipaa.duplicateKeyPolicy === "reject");

  var threw = null;
  try { b.guardJson.compliancePosture("unknown"); }
  catch (e) { threw = e; }
  check("compliancePosture: unknown name throws",
        threw && /unknown/.test(threw.message));
}

function testGuardJsonBadProfile() {
  var threw = null;
  try { b.guardJson.validate('{"x":1}', { profile: "made-up" }); }
  catch (e) { threw = e; }
  check("validate: unknown profile throws",
        threw && /unknown profile/i.test(threw.message));
}

// Each policy is a CONFIG-TIME entry point, so a value outside its vocabulary
// is a boot error rather than a runtime surprise. Read leniently, a typo takes
// whichever branch is not the strict one: `duplicateKeyPolicy: "rejct"` is not
// "allow", so the check runs, and it is not "reject" either, so the finding
// drops to a warning — the operator asked to refuse a duplicate key and
// silently got an audit.
//
// The character policies are deliberately absent: they are derived centrally
// for the whole family, and listing them here would override that derivation
// with a narrower copy.
function testPolicyVocabularyIsEnforced() {
  var LEGAL = {
    pollutionPolicy:        ["reject", "strip", "audit", "audit-only", "allow"],
    duplicateKeyPolicy:     ["reject", "audit", "audit-only", "allow"],
    nanInfinityPolicy:      ["reject", "audit", "audit-only", "allow"],
    commentPolicy:          ["reject", "audit", "audit-only", "allow"],
    trailingCommaPolicy:    ["reject", "audit", "audit-only", "allow"],
    json5SyntaxPolicy:      ["reject", "audit", "audit-only", "allow"],
    bomPolicy:              ["reject", "strip", "allow"],
    numericPrecisionPolicy: ["reject", "audit", "audit-only", "allow"],
  };
  helpers.assertPolicyVocabulary(b.guardJson, LEGAL, { label: "json", sample: '{"k":1}' });
}

async function run() {
  testGuardJsonSurface();
  testGuardJsonRegistryParity();
  testGuardJsonPrototypePollution();
  testGuardJsonParseStripPollution();
  testGuardJsonDuplicateKeys();
  testGuardJsonNanInfinity();
  testGuardJsonComments();
  testGuardJsonTrailingComma();
  testGuardJsonJson5Syntax();
  testGuardJsonBom();
  testGuardJsonDepthCap();
  testGuardJsonKeyCountCap();
  testGuardJsonArrayLengthCap();
  testGuardJsonStringLengthCap();
  testGuardJsonStringLengthByteCap();
  testGuardJsonByteCap();
  testGuardJsonNumericPrecision();
  testGuardJsonTopLevelKeyAllowlist();
  testGuardJsonBidi();
  testGuardJsonNullByte();
  testGuardJsonClean();
  await testValidJsonIsNotRefusedForTheContentOfItsStrings();
  testJson5ShapesAreFoundWhereverTheySit();
  testGuardJsonCompliancePosture();
  testGuardJsonBadProfile();
  await testGuardJsonGate();
  await testGuardJsonGateSanitizeByPolicy();
  testByteCapBindsBeforeAnyStrip();
  testBomIsRepairedUnderItsOwnPolicy();
  testPolicyVocabularyIsEnforced();
}

// The byte ceiling has to bind the input the CALLER sent. `parse` strips the
// classes set to a mitigation and only then reaches the cap inside
// safeJson.parse, so a small value padded with invisible characters shrank
// under the limit on the way through and was accepted — a resource cap an
// attacker removes by adding more input, which is the wrong direction for a
// cap to move. Every strip-able class is checked because the hole was open for
// zero-width and Tags before bidi joined them.
function testByteCapBindsBeforeAnyStrip() {
  var guardJson = b.guardJson;
  var PADDING = [
    ["bidiPolicy",      String.fromCharCode(0x202E), "bidi controls"],
    ["zeroWidthPolicy", String.fromCharCode(0x200B), "zero-width characters"],
    ["controlPolicy",   String.fromCharCode(0x0001), "control characters"],
    ["tagsPolicy",      String.fromCodePoint(0xE0041), "Tags characters"],
  ];
  PADDING.forEach(function (row) {
    var pad = new Array(300).join(row[1]);
    var src = '{"x":1,"p":' + JSON.stringify(pad) + "}";
    var opts = { maxBytes: 16 };
    opts[row[0]] = "strip";
    var threw = null;
    try { guardJson.parse(src, opts); } catch (e) { threw = e; }
    check("guardJson.parse: " + row[2] + " cannot pad a document under maxBytes",
      threw !== null && threw.code === "json.too-large",
      "got " + (threw ? threw.code : "no throw") +
      " for " + Buffer.byteLength(src, "utf8") + " bytes against a 16-byte cap");
  });
  // The cap still lets a document that genuinely fits through.
  var ok = null;
  try { ok = guardJson.parse('{"x":1}', { maxBytes: 64 }); } catch (_e) { ok = null; }
  check("guardJson.parse: a document within the cap still parses", ok && ok.x === 1);
}

// U+FEFF reaches the strip table only as a zero-width character, and `parse`
// removes only a LEADING one — so `bomPolicy: "strip"` with zero-width left on
// `allow` reported `bom-mid-stream` and handed the document back still carrying
// it. The repair follows the BOM's own policy now.
function testBomIsRepairedUnderItsOwnPolicy() {
  var guardJson = b.guardJson;
  var BOM = String.fromCharCode(0xFEFF);
  var src = '{"x":"a' + BOM + 'b"}';

  var out = null;
  try { out = guardJson.sanitize(src, { bomPolicy: "strip", zeroWidthPolicy: "allow" }); }
  catch (_e) { out = null; }
  check("guardJson.sanitize: a mid-stream BOM is removed under bomPolicy strip " +
        "even when zero-width is allowed",
    out !== null && out.indexOf(BOM) === -1, JSON.stringify(out));

  var threw = null;
  try { guardJson.sanitize(src, { bomPolicy: "reject", zeroWidthPolicy: "allow" }); }
  catch (e) { threw = e; }
  check("guardJson.sanitize: bomPolicy reject still refuses it",
    threw !== null, threw && threw.code);

  var kept = null;
  try { kept = guardJson.sanitize(src, { bomPolicy: "allow", zeroWidthPolicy: "allow" }); }
  catch (_e) { kept = null; }
  check("guardJson.sanitize: bomPolicy allow keeps it — allow means allow",
    kept !== null && kept.indexOf(BOM) !== -1, JSON.stringify(kept));
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[guard-json] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
