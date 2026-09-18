// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A value nested deeper than a primitive can walk is refused by name.
 *
 * Every primitive that recurses over a caller-supplied value meets a value
 * deeper than the JavaScript stack can carry. What the caller sees decides
 * whether the refusal is usable: a framework error names the limit and the
 * value that hit it, while a raw RangeError names neither and reaches a
 * request handler as an internal error. b.safeSchema and b.jtd threw
 * RangeError, b.cbor.encode threw RangeError past 6,000 levels,
 * b.jsonSchema.validate reported a legitimate 300-level value as a cyclic
 * $ref, and b.safeJson.parse reported a well-formed 2,000-level document as
 * invalid JSON syntax, because its own prototype-stripping reviver is what
 * JSON.parse failed inside.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function nest(depth, leaf) {
  var v = leaf === undefined ? { leaf: 1 } : leaf;
  for (var i = 0; i < depth; i += 1) v = { child: v };
  return v;
}

function outcome(fn) {
  try {
    var value = fn();
    return { ok: true, value: value };
  } catch (e) {
    return { ok: false, name: e.name, code: e.code || null, message: String(e.message) };
  }
}

function testDeepValuesAreRefusedByName() {
  var s = b.safeSchema;
  var node = s.lazy(function () { return s.object({ child: s.union([node, s.string()]) }); });
  var jtdSchema = { definitions: { n: { properties: { child: { ref: "n", nullable: true } } } }, ref: "n" };
  var refSchema = {
    $defs: { n: { type: "object", properties: { child: { $ref: "#/$defs/n" } } } },
    $ref: "#/$defs/n",
  };

  // Each row states a depth no framework primitive can walk on any platform,
  // so the refusal is the only correct answer at that depth.
  var ROWS = [
    { name: "safeSchema.parse", code: "safe-schema/value-too-deep",
      run: function () { return node.parse(nest(20000)); } },
    { name: "safeSchema.safeParse", code: "safe-schema/value-too-deep",
      run: function () {
        var r = node.safeParse(nest(20000));
        if (r.ok !== false) throw new Error("safeParse reported ok for a 20,000-level value");
        throw Object.assign(new Error(r.errors[0].message), { code: r.errors[0].code, name: "SafeSchemaError" });
      } },
    { name: "jtd.validate", code: "jtd/too-deep",
      run: function () { return b.jtd.validate(jtdSchema, nest(20000, { child: null })); } },
    { name: "jsonSchema.validate", code: "json-schema/value-too-deep",
      run: function () { return b.jsonSchema.validate(refSchema, nest(20000)); } },
    { name: "safeJson.parse", code: "json/too-deep",
      run: function () {
        // The text is built by repetition rather than by stringifying a
        // 20,000-level object: JSON.stringify walks the value recursively
        // and exhausts a small thread stack before the parser is reached.
        var text = '{"child":'.repeat(20000) + "{}" + "}".repeat(20000);
        return b.safeJson.parse(text, { maxBytes: 1 << 26, maxDepth: 1 << 20 });
      } },
    { name: "cbor.encode", code: "cbor/too-deep",
      run: function () { return b.cbor.encode(nest(20000)); } },
  ];

  var wrong = [];
  for (var i = 0; i < ROWS.length; i += 1) {
    var got = outcome(ROWS[i].run);
    if (got.ok) { wrong.push(ROWS[i].name + " accepted a 20,000-level value"); continue; }
    if (got.name === "RangeError") { wrong.push(ROWS[i].name + " threw a raw RangeError"); continue; }
    if (got.code !== ROWS[i].code) {
      wrong.push(ROWS[i].name + " refused as " + JSON.stringify(got.code) +
        " (want " + JSON.stringify(ROWS[i].code) + "): " + got.message.slice(0, 70));
    }
  }
  check("a value nested past the depth a primitive can walk is refused by name" +
        (wrong.length ? " (" + wrong.join("; ") + ")" : ""), wrong.length === 0);
}

function testALegitimateDeepValueIsNotReportedAsCyclic() {
  // 300 levels is an ordinary document. jsonSchema counted every descent
  // into the VALUE against MAX_REF_DEPTH, the cap on $ref resolution, so a
  // schema with one non-cyclic $ref was reported as "cyclic $ref?".
  var refSchema = {
    $defs: { n: { type: "object", properties: { child: { $ref: "#/$defs/n" } } } },
    $ref: "#/$defs/n",
  };
  var wrong = [];
  [10, 100, 250].forEach(function (depth) {
    var got = outcome(function () { return b.jsonSchema.validate(refSchema, nest(depth)); });
    if (!got.ok) wrong.push(depth + " levels -> " + got.code + " " + got.message.slice(0, 60));
  });
  // Past the documented limit the refusal names the value, not the schema.
  var past = outcome(function () { return b.jsonSchema.validate(refSchema, nest(400)); });
  if (past.ok || past.code !== "json-schema/value-too-deep") {
    wrong.push("400 levels reported " + (past.ok ? "ok" : past.code));
  }
  // A cycle that dips into a child value on each turn is still a cycle: the
  // reference counter is restored when a reference returns, so visiting
  // `properties.x` cannot reset the count the loop is accumulating.
  var cyclicViaChild = {
    $defs: {
      loop: { allOf: [{ $ref: "#/$defs/loop" }], properties: { x: { $ref: "#/$defs/num" } } },
      num:  { type: "number" },
    },
    $ref: "#/$defs/loop",
  };
  var viaChild = outcome(function () { return b.jsonSchema.validate(cyclicViaChild, { x: 1 }); });
  if (viaChild.ok || viaChild.code !== "json-schema/ref-loop") {
    wrong.push("a cycle that visits a child reported " + (viaChild.ok ? "ok" : viaChild.code));
  }

  // A cycle padded with keyword wrappers costs stack per turn without
  // resolving a reference or descending into the value, so neither counter
  // reaches its cap first. The refusal comes from translating the stack
  // exhaustion, which covers padding shapes no counter enumerates.
  function _wrapInAllOf(times, inner) {
    var out = inner;
    for (var i = 0; i < times; i += 1) out = { allOf: [out] };
    return out;
  }
  var padded = { $defs: { loop: _wrapInAllOf(5, { $ref: "#/$defs/loop" }) }, $ref: "#/$defs/loop" };
  var paddedOutcome = outcome(function () { return b.jsonSchema.validate(padded, {}); });
  if (paddedOutcome.ok || paddedOutcome.name === "RangeError" ||
      !/^json-schema\/(ref-loop|value-too-deep)$/.test(paddedOutcome.code || "")) {
    wrong.push("a cycle padded with allOf reported " +
      (paddedOutcome.ok ? "ok" : (paddedOutcome.code || paddedOutcome.name)));
  }

  // A schema whose $ref chain really is cyclic still reports the ref loop.
  var cyclic = { $defs: { a: { $ref: "#/$defs/b" }, b: { $ref: "#/$defs/a" } }, $ref: "#/$defs/a" };
  var loop = outcome(function () { return b.jsonSchema.validate(cyclic, { any: "value" }); });
  if (loop.ok || loop.code !== "json-schema/ref-loop") {
    wrong.push("a cyclic $ref chain reported " + (loop.ok ? "ok" : loop.code));
  }
  check("jsonSchema validates a deep value and keeps the ref-loop refusal for a cyclic schema" +
        (wrong.length ? " (" + wrong.join("; ") + ")" : ""), wrong.length === 0);
}

function testTheDepthBelowEachCapStillValidates() {
  // A cap that refuses ordinary documents is its own defect, so each
  // primitive is asked for a value one order of magnitude below the depth
  // the row above refuses.
  var s = b.safeSchema;
  var node = s.lazy(function () { return s.object({ child: s.union([node, s.string()]) }); });
  var wrong = [];
  var accepted = [
    { name: "safeSchema.safeParse at 200", run: function () { return node.safeParse(nest(200, "leaf")).ok === true; } },
    { name: "jtd.validate at 200", run: function () {
      return b.jtd.validate({ definitions: { n: { properties: { child: { ref: "n", nullable: true } } } }, ref: "n" },
        nest(200, { child: null })).length === 0; } },
    { name: "safeJson.parse at 200", run: function () {
      return typeof b.safeJson.parse(JSON.stringify(nest(200)), { maxBytes: 1 << 24, maxDepth: 1000 }) === "object"; } },
    { name: "cbor round-trip at 200", run: function () {
      return b.cbor.decode(b.cbor.encode(nest(200)), { maxDepth: 256 }) !== null; } },
  ];
  for (var i = 0; i < accepted.length; i += 1) {
    var got = outcome(accepted[i].run);
    if (!got.ok) wrong.push(accepted[i].name + " -> " + (got.code || got.name) + " " + got.message.slice(0, 60));
    else if (got.value !== true) wrong.push(accepted[i].name + " reported " + JSON.stringify(got.value));
  }
  check("a 200-level value is still accepted by every primitive that caps depth" +
        (wrong.length ? " (" + wrong.join("; ") + ")" : ""), wrong.length === 0);
}

function testAnUnrelatedRangeErrorIsNotReportedAsDepth() {
  // The stack-exhaustion translation reads the error's message, so a
  // RangeError a default factory or a refinement raises for its own reason
  // reaches the caller unchanged rather than arriving as a depth refusal.
  var s = b.safeSchema;
  var schema = s.number().default(function () { return Buffer.alloc(-1); });
  var got = outcome(function () { return schema.safeParse(undefined); });
  check("an unrelated RangeError is not reported as a depth refusal",
        got.ok || got.code !== "safe-schema/value-too-deep",
        got.ok ? "no throw" : got.code + " " + got.message.slice(0, 70));

  var thrown = outcome(function () {
    return s.string().refine(function () { throw new RangeError("offset is out of bounds"); }).parse("x");
  });
  check("a RangeError a refinement raises does not become a depth refusal",
        thrown.ok || thrown.code !== "safe-schema/value-too-deep",
        thrown.ok ? "no throw" : thrown.code + " " + thrown.message.slice(0, 70));
}

function testTheTextDepthScanAgreesWithTheWalker() {
  // safeJson.parse reads nesting off the text before parsing, and that
  // count has to match the walker that runs after it, which counts the root
  // container at depth zero. Counting the root as one tightened every
  // caller's maxDepth by a level: `{"x":{}}` was refused at maxDepth 1.
  var ROWS = [
    { text: '{"x":1}',          maxDepth: 1, want: "ok" },
    { text: '{"x":{}}',         maxDepth: 1, want: "ok" },
    { text: '{"x":[]}',         maxDepth: 1, want: "ok" },
    { text: '{"x":{"y":1}}',    maxDepth: 1, want: "json/too-deep" },
    { text: '{"x":{"y":1}}',    maxDepth: 2, want: "ok" },
    { text: '[[[1]]]',          maxDepth: 2, want: "json/too-deep" },
    { text: '[[[1]]]',          maxDepth: 3, want: "ok" },
    { text: '{"s":"{{{{{{{{"}', maxDepth: 1, want: "ok" },
  ];
  var wrong = [];
  ROWS.forEach(function (row) {
    var got = outcome(function () { return b.safeJson.parse(row.text, { maxDepth: row.maxDepth }); });
    var answer = got.ok ? "ok" : (got.code || got.name);
    if (answer !== row.want) {
      wrong.push(row.text + " at maxDepth " + row.maxDepth + " -> " + answer);
    }
  });
  check("the text depth scan refuses exactly what the walker refuses" +
        (wrong.length ? " (" + wrong.join("; ") + ")" : ""), wrong.length === 0);
}

function run() {
  testTheTextDepthScanAgreesWithTheWalker();
  testAnUnrelatedRangeErrorIsNotReportedAsDepth();
  testDeepValuesAreRefusedByName();
  testALegitimateDeepValueIsNotReportedAsCyclic();
  testTheDepthBelowEachCapStillValidates();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(function () { console.log("OK"); })
    .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
