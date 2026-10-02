// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * No serializer answers a value it cannot represent with the encoding of an
 * empty one.
 *
 * Every type listed here keeps its data in an internal slot rather than in own
 * enumerable properties, so a walker that reads `Object.keys` finds nothing and
 * writes the empty form: `{}` for JSON, `a0` for CBOR. Nothing raises, and the
 * value is gone. Callers sign that output, so a signature covered a document
 * carrying none of what it was handed.
 *
 * Each serializer was fixed one at a time, each by its own named list, and each
 * list was missing a different member. This asserts the property instead: for
 * every serializer and every such value, the answer must be a refusal, and it
 * must never be the byte-for-byte encoding of the empty container. A serializer
 * added later is covered by adding one line to SERIALIZERS.
 *
 * Run standalone: `node test/layer-0-primitives/serializer-empty-form.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

// Each entry serializes one value and returns a string for comparison, so an
// empty-form answer is detectable whatever the wire shape. `alsoRefuses` is what
// the format cannot represent beyond the shared set: JSON has no form for a Map,
// CBOR has one, and CBOR has no bare form for a Date while JSON reaches its
// toJSON. Both facts are correct, and neither licenses the empty form.
var SERIALIZERS = [
  { name: "b.canonicalJson.stringify",
    run: function (v) { return b.canonicalJson.stringify(v); },
    empty: "{}", alsoRefuses: "map" },
  { name: "b.canonicalJson.stringifyJcs",
    run: function (v) { return b.canonicalJson.stringifyJcs(v); },
    empty: "{}", alsoRefuses: "map" },
  { name: "b.safeJson.stringify",
    run: function (v) { return b.safeJson.stringify(v); },
    empty: "{}", alsoRefuses: "map" },
  { name: "b.cbor.encode",
    run: function (v) { return b.cbor.encode(v).toString("hex"); },
    empty: "a0", alsoRefuses: "date" },
];

// Shared across every format: the data lives in an internal slot, and no format
// here has a representation for the container itself.
function _noFormValues(alsoRefuses) {
  var base = [
    ["a Set", new Set([1, 2])],
    ["a WeakMap", new WeakMap()],
    ["a WeakSet", new WeakSet()],
    ["a Promise", Promise.resolve(1)],
    ["a RegExp", /abc/],
    ["an ArrayBuffer", new ArrayBuffer(8)],
    ["a DataView", new DataView(new ArrayBuffer(8))],
  ];
  if (alsoRefuses === "map") {
    base.push(["a Map", new Map([["a", 1]])]);
    // Own properties on a Map do not rescue it for JSON: a key-count check
    // passes this one while every entry is still dropped.
    base.push(["a Map carrying an own property", (function () {
      var m = new Map([["entry", 1]]);
      m.decoy = 2;
      return m;
    })()]);
  }
  if (alsoRefuses === "date") base.push(["a bare Date", new Date(0)]);
  return base;
}

function _attempt(serializer, value) {
  try { return { ok: true, out: serializer.run(value) }; }
  catch (e) { return { ok: false, code: e && e.code, message: e && e.message }; }
}

function testNoSerializerWritesTheEmptyFormForAValueItCannotRepresent() {
  SERIALIZERS.forEach(function (s) {
    _noFormValues(s.alsoRefuses).forEach(function (row) {
      var label = row[0];
      var r = _attempt(s, row[1]);
      check(s.name + " does not answer " + label + " with the empty form",
            !r.ok || r.out !== s.empty,
            r.ok ? "wrote " + r.out : "refused (" + r.code + ")");
      // A refusal is the expected answer for all of these; a faithful encoding
      // would also satisfy the property above, so say which one happened.
      check(s.name + " refuses " + label,
            !r.ok, r.ok ? "accepted, wrote " + r.out : String(r.code));
    });
  });
}

// A Map is representable in CBOR and not in JSON, so the two answer differently
// and both answers are correct. What is not allowed is the empty form.
function testAMapIsEncodedByCborAndRefusedByJson() {
  var m = new Map([["a", 1]]);
  check("b.cbor.encode writes a Map as a map, not as an empty one",
        b.cbor.encode(m).toString("hex") === "a1616101",
        b.cbor.encode(m).toString("hex"));
  var jsonAttempt = _attempt(SERIALIZERS[2], m);
  check("b.safeJson.stringify refuses a Map, since JSON has no form for it",
        !jsonAttempt.ok, jsonAttempt.ok ? jsonAttempt.out : String(jsonAttempt.code));
}

// The values every serializer must still accept, so the refusal above cannot be
// satisfied by refusing everything.
function testTheRepresentableValuesStillSerialize() {
  var KEEP = [
    ["an empty plain object", {}],
    ["a populated plain object", { a: 1 }],
    ["an empty array", []],
    ["a populated array", [1, 2]],
    ["a null-prototype object", Object.assign(Object.create(null), { a: 1 })],
    ["a nested plain object", { a: { b: [1, { c: 2 }] } }],
    ["a boxed Number", new Number(7)],
    ["a boxed String", new String("s")],
  ];
  SERIALIZERS.forEach(function (s) {
    KEEP.forEach(function (row) {
      var r = _attempt(s, row[1]);
      check(s.name + " still serializes " + row[0],
            r.ok, r.ok ? r.out : "refused (" + r.code + "): " + r.message);
    });
  });

  // A boxed primitive carries a value, so the answer must be that value rather
  // than the empty form its own properties would produce.
  check("b.canonicalJson.stringify unwraps a boxed Number",
        b.canonicalJson.stringify(new Number(7)) === "7");
  check("b.canonicalJson.stringify unwraps a boxed String",
        b.canonicalJson.stringify(new String("s")) === '"s"');
  check("b.cbor.encode unwraps a boxed Number",
        b.cbor.encode(new Number(7)).toString("hex") === "07");
}

// A Date is representable in JSON through toJSON and has no bare CBOR form, so
// the two must answer differently and neither may write the empty form.
function testADateIsNeverTheEmptyForm() {
  check("b.safeJson.stringify writes a Date as its ISO string",
        b.safeJson.stringify(new Date(0)) === '"1970-01-01T00:00:00.000Z"',
        b.safeJson.stringify(new Date(0)));
  check("b.canonicalJson.stringify writes a Date as its ISO string",
        b.canonicalJson.stringify(new Date(0)) === '"1970-01-01T00:00:00.000Z"');
  var cborAttempt = _attempt(SERIALIZERS[3], new Date(0));
  check("b.cbor.encode refuses a bare Date rather than writing an empty map",
        !cborAttempt.ok && cborAttempt.code === "cbor/unencodable",
        cborAttempt.ok ? cborAttempt.out : String(cborAttempt.code));
  check("and the tag form encodes",
        b.cbor.encode(new b.cbor.Tag(1, 0)).toString("hex") === "c100");
}

// Whichever realm built the value, the answer is the same one.
function testTheSameHoldsForAValueFromAnotherRealm() {
  var vm = require("node:vm");
  var ctx = vm.createContext({ out: {} });
  vm.runInContext("out.set = new Set([1]); out.re = /x/; out.promise = Promise.resolve(1);", ctx);
  SERIALIZERS.forEach(function (s) {
    ["set", "re", "promise"].forEach(function (key) {
      var r = _attempt(s, ctx.out[key]);
      check(s.name + " refuses a cross-realm " + key + " as it does a local one",
            !r.ok, r.ok ? "wrote " + r.out : String(r.code));
    });
  });
}

async function run() {
  testNoSerializerWritesTheEmptyFormForAValueItCannotRepresent();
  testAMapIsEncodedByCborAndRefusedByJson();
  testTheRepresentableValuesStillSerialize();
  testADateIsNeverTheEmptyForm();
  testTheSameHoldsForAValueFromAnotherRealm();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("[serializer-empty-form] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
