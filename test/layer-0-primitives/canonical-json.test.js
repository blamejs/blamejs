// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — b.canonicalJson (RFC 8785 JSON Canonicalization Scheme).
 * The oracle is the official cyberphone/json-canonicalization conformance
 * suite: the structures / french / values vectors (nested key sort,
 * locale-independent UTF-16 ordering, and the ECMAScript number format)
 * must serialize byte-for-byte to the published output.
 */

var b = require("../../index");
var helpers = require("../helpers");
var check = helpers.check;
var cj = b.canonicalJson;
function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code || e.message; } }

function testSurface() {
  check("b.canonicalJson.stringifyJcs is a function", typeof cj.stringifyJcs === "function");
  check("b.canonicalJson.stringify is a function", typeof cj.stringify === "function");
  check("b.canonicalJson.sortKeys returns the UTF-16 sorted keys", cj.sortKeys({ b: 1, a: 2, c: 3 }).join() === "a,b,c");
}

function testJcsConformance() {
  // cyberphone/json-canonicalization testdata — "structures": nested
  // key sort at every depth, 56.0 → 56.
  var structures = { "1": { "f": { "f": "hi", "F": 5 }, "\n": 56.0 }, "10": {}, "": "empty", "a": {}, "111": [{ "e": "yes", "E": "no" }], "A": {} };
  check("JCS: nested structures vector", cj.stringifyJcs(structures) === '{"":"empty","1":{"\\n":56,"f":{"F":5,"f":"hi"}},"10":{},"111":[{"E":"no","e":"yes"}],"A":{},"a":{}}');

  // "french": sorting ignores locale (UTF-16 code-unit order).
  var french = { "peach": "This sorting order", "péché": "is wrong according to French", "pêche": "but canonicalization MUST", "sin": "ignore locale" };
  check("JCS: locale-independent french vector", cj.stringifyJcs(french) === '{"peach":"This sorting order","péché":"is wrong according to French","pêche":"but canonicalization MUST","sin":"ignore locale"}');

  // "values" numbers: the ECMAScript Number-to-string format JCS §3.2.2.3 references.
  // Number("…") avoids a loss-of-precision lint on the deliberately
  // over-precise vector value (333333333.33333329 → 333333333.3333333).
  check("JCS: number formatting vector", cj.stringifyJcs([Number("333333333.33333329"), 1e30, 4.50, 2e-3, Number("0.000000000000000000000000001")]) === "[333333333.3333333,1e+30,4.5,0.002,1e-27]");

  // Astral key sorts by UTF-16 code unit: "$"(U+0024) < "€"(U+20AC) <
  // "😂"(lead surrogate U+D83D).
  check("JCS: astral key UTF-16 ordering", cj.stringifyJcs({ "€": 1, "$": 2, "😂": 3 }) === '{"$":2,"€":1,"😂":3}');

  // Unnormalized Unicode is preserved, NOT normalized (A + combining ring
  // stays two code points).
  check("JCS: no Unicode normalization", cj.stringifyJcs({ k: "Å" }) === '{"k":"Å"}');
}

function testSparseArrays() {
  // Sparse-array holes serialize as null, not invalid JSON elisions ([,1]).
  var sparse = [1, , 3]; // eslint-disable-line no-sparse-arrays
  check("JCS: sparse array holes → null", cj.stringifyJcs(sparse) === "[1,null,3]");
  check("JCS: explicit undefined in array → null", cj.stringifyJcs([1, undefined, 3]) === "[1,null,3]");
}

function testStrictRefusals() {
  check("JCS: BigInt refused", /BigInt/.test(code(function () { cj.stringifyJcs({ n: 1n }); })));
  check("JCS: Buffer refused", /Buffer/.test(code(function () { cj.stringifyJcs({ b: Buffer.from("x") }); })));
  check("JCS: Date refused", /Date/.test(code(function () { cj.stringifyJcs({ d: new Date() }); })));
  check("JCS: Map refused", /Map/.test(code(function () { cj.stringifyJcs({ m: new Map() }); })));
  check("JCS: circular reference refused", /circular/.test(code(function () { var o = {}; o.self = o; cj.stringifyJcs(o); })));
}

// The canonical bytes are what a signature commits to, so the same value has
// to canonicalize the same way whichever realm built it. Type dispatch by
// `instanceof` compares against this realm's constructors, so a value from a
// `node:vm` context missed every branch and fell through to the plain-object
// walk, which has no own enumerable keys to write: a Date became `{}` in the
// signed bytes, and a Map, Set or RegExp became `{}` where the same value
// built here is refused outright.
function testCrossRealmValuesCanonicalizeTheSameWay() {
  var vm = require("node:vm");
  var ctx = vm.createContext({ out: {} });
  vm.runInContext(
    "out.date = new Date(Date.UTC(2026, 0, 2));" +
    "out.map  = new Map([[1, 2]]);" +
    "out.set  = new Set([1]);" +
    "out.re   = /x/;" +
    "out.bytes = new Uint8Array([1, 2]);" +
    "out.plain = { b: 1, a: 2 };",
    ctx);

  check("cross-realm Date canonicalizes to its ISO string, as a local one does",
        cj.stringify({ v: ctx.out.date }) === cj.stringify({ v: new Date(Date.UTC(2026, 0, 2)) }));
  check("cross-realm Date is not written as an empty object",
        cj.stringify({ v: ctx.out.date }).indexOf("{}") === -1);

  check("cross-realm Map is refused, as a local one is",
        /Map/.test(code(function () { cj.stringify({ v: ctx.out.map }); })));
  check("cross-realm Set is refused, as a local one is",
        /Set/.test(code(function () { cj.stringify({ v: ctx.out.set }); })));
  check("cross-realm RegExp is refused, as a local one is",
        /RegExp/.test(code(function () { cj.stringify({ v: ctx.out.re }); })));

  check("cross-realm Uint8Array canonicalizes to hex, as a local one does",
        cj.stringify({ v: ctx.out.bytes }) === cj.stringify({ v: new Uint8Array([1, 2]) }));
  check("cross-realm Uint8Array is refused under bufferAs reject, as a local one is",
        /reject/.test(code(function () {
          cj.stringify({ v: ctx.out.bytes }, { bufferAs: "reject" });
        })));

  check("cross-realm plain object still sorts its keys",
        cj.stringify(ctx.out.plain) === '{"a":2,"b":1}');

  check("JCS refuses a cross-realm Date, as it refuses a local one",
        /Date/.test(code(function () { cj.stringifyJcs({ v: ctx.out.date }); })));
  check("JCS refuses a cross-realm Map, as it refuses a local one",
        /Map/.test(code(function () { cj.stringifyJcs({ v: ctx.out.map }); })));
}

function testLenientStringify() {
  // The lenient framework variant serializes Buffers (hex), Dates (ISO),
  // and BigInts (decimal) while still sorting keys.
  check("stringify: sorts keys", cj.stringify({ b: 1, a: 2 }) === '{"a":2,"b":1}');
  check("stringify: Buffer → hex", cj.stringify({ k: Buffer.from("ab") }) === '{"k":"6162"}');
  check("stringify: bufferAs reject throws", /reject/.test(code(function () { cj.stringify({ k: Buffer.from("x") }, { bufferAs: "reject" }); })));
}

function testDepthCap() {
  // The walk is recursive; without a depth cap a deeply-nested input would
  // overflow the V8 stack with an uncaught RangeError before any throw —
  // a pre-signature-verify DoS, since content-credentials.verify
  // canonicalises an attacker-supplied manifest before verifying it. Both
  // serializers now throw a typed nesting-depth error well short of native
  // overflow, and the circular-reference guard is unaffected.
  function deepObj(n) { var o = {}, c = o; for (var i = 0; i < n; i++) { c.x = {}; c = c.x; } return o; }
  function deepArr(n) { var a = [], c = a; for (var i = 0; i < n; i++) { var n2 = []; c.push(n2); c = n2; } return a; }
  check("stringify: deep object throws typed nesting-depth (not RangeError)",
    /nesting depth/.test(code(function () { cj.stringify(deepObj(9000)); })));
  check("stringify: deep array throws typed nesting-depth (not RangeError)",
    /nesting depth/.test(code(function () { cj.stringify(deepArr(9000)); })));
  check("stringifyJcs: deep object throws typed nesting-depth (not RangeError)",
    /nesting depth/.test(code(function () { cj.stringifyJcs(deepObj(9000)); })));
  // Legit shallow nesting still serializes; the cap is far above any real
  // signed document.
  check("stringify: shallow nesting still serializes", cj.stringify(deepObj(10)).indexOf("{") === 0);
  // The cycle guard still wins for a self-referential object (depth never
  // reaches the cap).
  var cyc = {}; cyc.self = cyc;
  check("stringify: circular reference still throws its own error",
    /circular/.test(code(function () { cj.stringify(cyc); })));
}

async function run() {
  testSurface();
  testJcsConformance();
  testSparseArrays();
  testStrictRefusals();
  testCrossRealmValuesCanonicalizeTheSameWay();
  testLenientStringify();
  testDepthCap();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[canonical-json] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
