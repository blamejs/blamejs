// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — b.jsonSchema (JSON Schema 2020-12).
 * Oracle: the official json-schema-org/JSON-Schema-Test-Suite draft2020-12
 * (1292 of 1295 cases pass during development; the 3 skipped require the
 * bundled dialect metaschema or $vocabulary selection — both opt-in). This
 * file embeds a representative slice across the vocabulary plus the surface
 * + reference-resolution + annotation cases that exercise the tricky paths.
 */

var b = require("../../index");
var helpers = require("../helpers");
var check = helpers.check;
function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }

function testSurface() {
  check("b.jsonSchema.validate is a function", typeof b.jsonSchema.validate === "function");
  check("b.jsonSchema.compile is a function", typeof b.jsonSchema.compile === "function");
  check("b.jsonSchema.isValid is a function", typeof b.jsonSchema.isValid === "function");
  check("b.jsonSchema.DIALECT is 2020-12", b.jsonSchema.DIALECT === "https://json-schema.org/draft/2020-12/schema");
  check("b.jsonSchema.JsonSchemaError is a class", typeof b.jsonSchema.JsonSchemaError === "function");
  check("compile rejects non-schema", code(function () { b.jsonSchema.compile(42); }) === "json-schema/bad-schema");
  var v = b.jsonSchema.compile({ type: "integer" });
  check("compiled validator has validate + isValid", typeof v.validate === "function" && typeof v.isValid === "function");
}

function testAssertions() {
  check("type integer accepts int", b.jsonSchema.isValid({ type: "integer" }, 3));
  check("type integer rejects float", !b.jsonSchema.isValid({ type: "integer" }, 3.5));
  check("type rejects wrong type", !b.jsonSchema.isValid({ type: "string" }, 1));
  check("enum", b.jsonSchema.isValid({ enum: ["a", "b"] }, "b") && !b.jsonSchema.isValid({ enum: ["a"] }, "z"));
  check("const deep-equal", b.jsonSchema.isValid({ const: { a: [1, 2] } }, { a: [1, 2] }) && !b.jsonSchema.isValid({ const: { a: [1] } }, { a: [2] }));
  check("multipleOf", b.jsonSchema.isValid({ multipleOf: 3 }, 9) && !b.jsonSchema.isValid({ multipleOf: 3 }, 10));
  check("maximum/exclusiveMaximum", b.jsonSchema.isValid({ maximum: 5 }, 5) && !b.jsonSchema.isValid({ exclusiveMaximum: 5 }, 5));
  check("minLength counts code points", !b.jsonSchema.isValid({ minLength: 2 }, "😀") && b.jsonSchema.isValid({ maxLength: 1 }, "😀"));
  check("pattern", b.jsonSchema.isValid({ pattern: "^a+$" }, "aaa") && !b.jsonSchema.isValid({ pattern: "^a+$" }, "b"));
}

function testArrays() {
  check("prefixItems + items", b.jsonSchema.isValid({ prefixItems: [{ type: "number" }], items: { type: "string" } }, [1, "a", "b"]));
  check("items rejects bad tail", !b.jsonSchema.isValid({ prefixItems: [{ type: "number" }], items: { type: "string" } }, [1, 2]));
  check("uniqueItems", b.jsonSchema.isValid({ uniqueItems: true }, [1, 2, 3]) && !b.jsonSchema.isValid({ uniqueItems: true }, [1, 1]));
  check("contains + minContains", b.jsonSchema.isValid({ contains: { const: 2 }, minContains: 2 }, [2, 2, 3]) && !b.jsonSchema.isValid({ contains: { const: 2 }, minContains: 2 }, [2, 3]));
  check("maxItems/minItems", !b.jsonSchema.isValid({ maxItems: 1 }, [1, 2]) && !b.jsonSchema.isValid({ minItems: 2 }, [1]));
}

function testObjects() {
  var s = { type: "object", properties: { n: { type: "integer" } }, required: ["n"], additionalProperties: false };
  check("properties + required pass", b.jsonSchema.isValid(s, { n: 1 }));
  check("required missing fails", !b.jsonSchema.isValid(s, {}));
  check("additionalProperties:false rejects extra", !b.jsonSchema.isValid(s, { n: 1, x: 2 }));
  check("patternProperties", b.jsonSchema.isValid({ patternProperties: { "^x": { type: "number" } } }, { x1: 1 }) && !b.jsonSchema.isValid({ patternProperties: { "^x": { type: "number" } } }, { x1: "a" }));
  check("propertyNames", !b.jsonSchema.isValid({ propertyNames: { pattern: "^a" } }, { b: 1 }));
  check("dependentRequired", !b.jsonSchema.isValid({ dependentRequired: { a: ["b"] } }, { a: 1 }));
  check("dependentSchemas", !b.jsonSchema.isValid({ dependentSchemas: { a: { required: ["b"] } } }, { a: 1 }));
}

function testApplicators() {
  check("allOf", b.jsonSchema.isValid({ allOf: [{ type: "number" }, { minimum: 0 }] }, 5) && !b.jsonSchema.isValid({ allOf: [{ type: "number" }, { minimum: 0 }] }, -1));
  check("anyOf", b.jsonSchema.isValid({ anyOf: [{ type: "string" }, { type: "number" }] }, 1) && !b.jsonSchema.isValid({ anyOf: [{ type: "string" }] }, 1));
  check("oneOf exactly one", b.jsonSchema.isValid({ oneOf: [{ multipleOf: 2 }, { multipleOf: 3 }] }, 4) && !b.jsonSchema.isValid({ oneOf: [{ multipleOf: 2 }, { multipleOf: 3 }] }, 6));
  check("not", b.jsonSchema.isValid({ not: { type: "string" } }, 1) && !b.jsonSchema.isValid({ not: { type: "string" } }, "x"));
  check("if/then/else", b.jsonSchema.isValid({ if: { type: "number" }, then: { minimum: 0 }, else: { type: "string" } }, 5) && b.jsonSchema.isValid({ if: { type: "number" }, then: { minimum: 0 }, else: { type: "string" } }, "x") && !b.jsonSchema.isValid({ if: { type: "number" }, then: { minimum: 0 } }, -1));
  check("boolean schema true/false", b.jsonSchema.isValid(true, 42) && !b.jsonSchema.isValid(false, 42));
}

function testUnevaluated() {
  // unevaluatedProperties sees annotations from $ref inside allOf.
  var s = {
    $defs: { one: { properties: { a: true } } },
    allOf: [{ $ref: "#/$defs/one" }, { properties: { b: true } }],
    unevaluatedProperties: false,
  };
  check("unevaluatedProperties + ref-in-allOf accepts evaluated", b.jsonSchema.isValid(s, { a: 1, b: 2 }));
  check("unevaluatedProperties + ref-in-allOf rejects unevaluated", !b.jsonSchema.isValid(s, { a: 1, c: 3 }));
  check("unevaluatedItems", b.jsonSchema.isValid({ prefixItems: [{ type: "number" }], unevaluatedItems: false }, [1]) && !b.jsonSchema.isValid({ prefixItems: [{ type: "number" }], unevaluatedItems: false }, [1, 2]));
}

function testRefs() {
  // $ref to $defs + $anchor.
  check("$ref to $defs", b.jsonSchema.isValid({ $defs: { pos: { minimum: 0 } }, $ref: "#/$defs/pos" }, 5));
  check("$anchor ref", b.jsonSchema.isValid({ $defs: { p: { $anchor: "pos", minimum: 0 } }, $ref: "#pos" }, 5));
  // External schema via opts.schemas (no network).
  var ext = { "https://example.com/int": { type: "integer" } };
  check("external $ref via opts.schemas", b.jsonSchema.isValid({ $ref: "https://example.com/int" }, 3, { schemas: ext }));
  check("external $ref rejects", !b.jsonSchema.isValid({ $ref: "https://example.com/int" }, "x", { schemas: ext }));
  // $dynamicRef / $dynamicAnchor (the recursive bookend pattern).
  var dyn = {
    $id: "https://example.com/tree",
    $dynamicAnchor: "node",
    type: "object",
    properties: { data: true, children: { type: "array", items: { $dynamicRef: "#node" } } },
  };
  check("$dynamicRef recursion validates", b.jsonSchema.isValid(dyn, { data: 1, children: [{ data: 2, children: [] }] }));
}

function testErrorsShape() {
  var r = b.jsonSchema.validate({ type: "object", properties: { n: { type: "integer" } } }, { n: "bad" });
  check("validate returns {valid, errors}", r.valid === false && Array.isArray(r.errors) && r.errors.length >= 1);
  check("error names instancePath + keyword", r.errors[0].instancePath === "/n" && r.errors[0].keyword === "type");
}

function testFormat() {
  // format is an annotation by default (does not assert).
  check("format annotation by default", b.jsonSchema.isValid({ type: "string", format: "email" }, "not-an-email"));
  // assertFormat:true turns it into an assertion.
  check("assertFormat rejects bad email", !b.jsonSchema.isValid({ type: "string", format: "email" }, "nope", { assertFormat: true }));
  check("assertFormat accepts good date-time", b.jsonSchema.isValid({ type: "string", format: "date-time" }, "2020-01-01T00:00:00Z", { assertFormat: true }));
  // time requires an offset and valid ranges (RFC 3339 full-time).
  check("time rejects missing offset", !b.jsonSchema.isValid({ format: "time" }, "12:00:00", { assertFormat: true }));
  check("time rejects out-of-range", !b.jsonSchema.isValid({ format: "time" }, "25:61:61Z", { assertFormat: true }));
  check("time accepts offset form", b.jsonSchema.isValid({ format: "time" }, "12:00:00+05:30", { assertFormat: true }));
  // date enforces real field ranges.
  check("date rejects month 13", !b.jsonSchema.isValid({ format: "date" }, "2020-13-01", { assertFormat: true }));
  check("date accepts valid", b.jsonSchema.isValid({ format: "date" }, "2020-02-29", { assertFormat: true }));
  // uri rejects raw spaces and relative refs.
  check("uri rejects raw space", !b.jsonSchema.isValid({ format: "uri" }, "http://e xample.com", { assertFormat: true }));
  check("uri rejects relative", !b.jsonSchema.isValid({ format: "uri" }, "/relative/path", { assertFormat: true }));
  check("uri accepts absolute", b.jsonSchema.isValid({ format: "uri" }, "https://example.com/x", { assertFormat: true }));
}

function testDepthCap() {
  // validate(schema, instance) recurses one level per nested subschema
  // application. A recursive schema (items:{$ref:"#"}) against a deeply
  // nested instance — both attacker-controlled when validating a request
  // body — would overflow the V8 stack with an uncaught RangeError before
  // the depth guard fired (its cap was set above native overflow). The cap
  // is now well under overflow so the typed json-schema/ref-loop error
  // surfaces instead of a crash, while legitimate nesting (deep or wide)
  // still validates.
  var recursive = { $schema: b.jsonSchema.DIALECT, type: "array", items: { $ref: "#" } };
  function deepArr(n) { var a = [], c = a; for (var i = 0; i < n; i++) { var n2 = []; c.push(n2); c = n2; } return a; }
  check("validate: deeply nested instance throws typed ref-loop (not RangeError)",
    code(function () { b.jsonSchema.validate(recursive, deepArr(1500)); }) === "json-schema/ref-loop");
  // Legit shallow nesting validates clean.
  check("validate: shallow nesting still validates", b.jsonSchema.validate(recursive, deepArr(40)).valid === true);
  // Breadth must not trip the nesting cap (sibling properties do not
  // accumulate depth).
  var wide = { type: "object", properties: {} }; var obj = {};
  for (var k = 0; k < 400; k++) { wide.properties["p" + k] = { type: "integer" }; obj["p" + k] = k; }
  check("validate: wide-but-shallow object does not trip the depth cap",
    b.jsonSchema.validate(wide, obj).valid === true);
}

function testInstanceTypes() {
  // _typeOf across every JSON type + the "unknown" fallback (undefined).
  check("null instance matches type:null", b.jsonSchema.isValid({ type: "null" }, null));
  check("null rejected by type:string", !b.jsonSchema.isValid({ type: "string" }, null));
  check("boolean instance matches type:boolean", b.jsonSchema.isValid({ type: "boolean" }, true));
  check("array instance matches type:array", b.jsonSchema.isValid({ type: "array" }, [1, 2]));
  check("object instance matches type:object", b.jsonSchema.isValid({ type: "object" }, { a: 1 }));
  // undefined has no JSON type ("unknown"); an empty schema accepts it but a
  // typed schema rejects it (the type never matches "unknown").
  check("undefined accepted by empty schema", b.jsonSchema.isValid({}, undefined));
  check("undefined rejected by type:string", !b.jsonSchema.isValid({ type: "string" }, undefined));
  // type as an array — a match plus the joined mismatch message.
  check("type array matches a member", b.jsonSchema.isValid({ type: ["string", "number"] }, 5));
  var r = b.jsonSchema.validate({ type: ["string", "number"] }, true);
  check("type array mismatch names both", !r.valid && r.errors[0].keyword === "type" && r.errors[0].message.indexOf("string/number") >= 0);
}

function testDeepEqualEdges() {
  // const uses JSON deep-equality — exercise each early-out branch.
  check("const type-mismatch fails", !b.jsonSchema.isValid({ const: 5 }, "5"));
  check("const array length-mismatch fails", !b.jsonSchema.isValid({ const: [1, 2] }, [1, 2, 3]));
  check("const object key-count mismatch fails", !b.jsonSchema.isValid({ const: { a: 1 } }, { a: 1, b: 2 }));
  check("const object same-count different-keys fails", !b.jsonSchema.isValid({ const: { a: 1 } }, { b: 1 }));
  check("const deep-equal object passes", b.jsonSchema.isValid({ const: { a: 1 } }, { a: 1 }));
}

function testNumericBounds() {
  check("maximum rejects over", !b.jsonSchema.isValid({ maximum: 5 }, 6));
  check("maximum accepts at bound", b.jsonSchema.isValid({ maximum: 5 }, 5));
  check("exclusiveMaximum rejects at bound", !b.jsonSchema.isValid({ exclusiveMaximum: 5 }, 5));
  check("exclusiveMaximum accepts under", b.jsonSchema.isValid({ exclusiveMaximum: 5 }, 4));
  check("minimum rejects under", !b.jsonSchema.isValid({ minimum: 5 }, 4));
  check("minimum accepts at bound", b.jsonSchema.isValid({ minimum: 5 }, 5));
  check("exclusiveMinimum rejects at bound", !b.jsonSchema.isValid({ exclusiveMinimum: 5 }, 5));
  check("exclusiveMinimum accepts over", b.jsonSchema.isValid({ exclusiveMinimum: 5 }, 6));
}

function testStringBounds() {
  check("maxLength rejects longer", !b.jsonSchema.isValid({ maxLength: 2 }, "abc"));
  check("maxLength accepts equal", b.jsonSchema.isValid({ maxLength: 3 }, "abc"));
  // A surrogate-pair emoji counts as one code point, not two UTF-16 units.
  check("maxLength counts astral code points once", b.jsonSchema.isValid({ maxLength: 1 }, String.fromCodePoint(0x1F600)));
}

function testRegexFallback() {
  // A pattern valid without the /u flag but invalid with it — the compiler
  // falls back to a non-unicode RegExp rather than dropping the constraint.
  check("pattern retries without /u flag", b.jsonSchema.isValid({ pattern: "a\\-z" }, "a-z") && !b.jsonSchema.isValid({ pattern: "a\\-z" }, "qqq"));
  // A pattern invalid under both flags compiles to null → constraint skipped.
  check("uncompilable pattern is skipped", b.jsonSchema.isValid({ pattern: "[" }, "anything"));
  check("uncompilable patternProperties key is skipped", b.jsonSchema.isValid({ patternProperties: { "[": { type: "number" } } }, { x: "str" }));
}

function testArrayApplicatorEdges() {
  check("prefixItems mismatch fails", !b.jsonSchema.isValid({ prefixItems: [{ type: "string" }] }, [5]));
  check("minContains not met fails", !b.jsonSchema.isValid({ contains: { type: "number" }, minContains: 2 }, [1, "a"]));
  check("minContains met passes", b.jsonSchema.isValid({ contains: { type: "number" }, minContains: 2 }, [1, 2, "a"]));
  check("maxContains exceeded fails", !b.jsonSchema.isValid({ contains: { type: "number" }, maxContains: 1 }, [1, 2, 3]));
}

function testObjectApplicatorEdges() {
  check("maxProperties exceeded fails", !b.jsonSchema.isValid({ maxProperties: 1 }, { a: 1, b: 2 }));
  check("minProperties not met fails", !b.jsonSchema.isValid({ minProperties: 2 }, { a: 1 }));
  // additionalProperties skips keys owned by properties even when that
  // property's own schema failed — no double-count as an additional prop.
  var r1 = b.jsonSchema.validate({ properties: { a: { type: "string" } }, additionalProperties: false }, { a: 123 });
  check("addlProps ignores properties-owned key", !r1.valid && r1.errors.length === 1 && r1.errors[0].keyword === "type");
  // ...and keys matched by patternProperties, even when that pattern failed.
  var r2 = b.jsonSchema.validate({ patternProperties: { "^x": { type: "string" } }, additionalProperties: false }, { xa: 123 });
  check("addlProps ignores pattern-matched key", !r2.valid && r2.errors.length === 1 && r2.errors[0].keyword === "type");
  // An additionalProperties schema that passes marks the key evaluated.
  check("addlProps success accepts", b.jsonSchema.isValid({ additionalProperties: { type: "number" } }, { x: 5 }));
  check("addlProps failure rejects", !b.jsonSchema.isValid({ additionalProperties: { type: "number" } }, { x: "no" }));
  // A key matching NO patternProperties pattern falls through to
  // additionalProperties (here false → rejected).
  var r3 = b.jsonSchema.validate({ patternProperties: { "^x": { type: "number" } }, additionalProperties: false }, { y: 1 });
  check("addlProps applies to non-pattern-matched key", !r3.valid && r3.errors[0].keyword === "false");
}

function testUnevaluatedSuccess() {
  // An unevaluated property/item that VALIDATES against the unevaluated*
  // schema is accepted (and recorded as evaluated).
  var so = { properties: { a: true }, unevaluatedProperties: { type: "string" } };
  check("unevaluatedProperties accepts matching extra", b.jsonSchema.isValid(so, { a: 1, b: "ok" }));
  check("unevaluatedProperties rejects non-matching extra", !b.jsonSchema.isValid(so, { a: 1, b: 2 }));
  var sa = { prefixItems: [{ type: "number" }], unevaluatedItems: { type: "number" } };
  check("unevaluatedItems accepts matching tail", b.jsonSchema.isValid(sa, [1, 2]));
  check("unevaluatedItems rejects non-matching tail", !b.jsonSchema.isValid(sa, [1, "x"]));
}

function testConditionalElse() {
  var s = { if: { type: "string" }, else: { type: "number" } };
  check("if-fails-else-fails rejects", !b.jsonSchema.isValid(s, true));
  check("if-fails-else-passes accepts", b.jsonSchema.isValid(s, 5));
  check("if-passes accepts", b.jsonSchema.isValid(s, "hi"));
}

function testRefResolution() {
  // Empty $ref points at the current schema; a root that is only {$ref:""}
  // is an infinite self-reference caught fail-closed by the depth cap —
  // both with no base and with a resolved $id base.
  check("empty self-$ref caught by depth cap", code(function () { b.jsonSchema.validate({ $ref: "" }, 1); }) === "json-schema/ref-loop");
  check("empty $ref under a base still self-loops", code(function () { b.jsonSchema.validate({ $id: "https://ex/x", allOf: [{ $ref: "" }] }, 5); }) === "json-schema/ref-loop");
  // A $id that is a bare name carrying a fragment: relative fragment refs
  // resolve against the fragment-stripped base (an unusual, discouraged
  // shape — child refs do not cleanly resolve, reported fail-closed).
  var r125 = b.jsonSchema.validate({ $id: "mybase#sec", $defs: { foo: { type: "string" } }, $ref: "#/$defs/foo" }, "hi");
  check("bare-name $id with fragment reports unresolved child ref", !r125.valid && r125.errors[0].keyword === "$ref");
  // A boolean schema is registerable and referenceable by an external URI.
  check("boolean schema addressable by URI", b.jsonSchema.isValid({ $ref: "https://ex/bool" }, 42, { schemas: { "https://ex/bool": true } }) && !b.jsonSchema.isValid({ $ref: "https://ex/bool" }, 42, { schemas: { "https://ex/bool": false } }));
  // A $id that is a bare name (not a URL): a fragment $ref resolves by
  // fragment-aware concatenation against that base.
  var bare = { $id: "mybase", $defs: { foo: { type: "string" } }, $ref: "#/$defs/foo" };
  check("bare-name base fragment $ref resolves", b.jsonSchema.isValid(bare, "hi") && !b.jsonSchema.isValid(bare, 5));
  // A relative nested $id under a urn: base (URL resolution throws → falls
  // back to keeping the relative name).
  check("urn base + relative nested $id validates", b.jsonSchema.isValid({ $id: "urn:ex:root", $defs: { leaf: { $id: "leaf", type: "string" } }, $ref: "#/$defs/leaf" }, "hi"));
  // A document is addressable by its retrieval URI even when its own $id is
  // a different canonical URI.
  var ext = { "https://retrieval.example/x": { $id: "https://canonical.example/y", type: "integer" } };
  check("retrieval URI addressable", b.jsonSchema.isValid({ $ref: "https://retrieval.example/x" }, 3, { schemas: ext }) && !b.jsonSchema.isValid({ $ref: "https://retrieval.example/x" }, "no", { schemas: ext }));
  check("canonical $id addressable", b.jsonSchema.isValid({ $ref: "https://canonical.example/y" }, 3, { schemas: ext }));
  // A schema keyed by "base#" is reachable by a $ref written without the #.
  var hk = { "https://ex/x#": { type: "string" } };
  check("base#-keyed schema reachable without fragment", b.jsonSchema.isValid({ $ref: "https://ex/x" }, "hi", { schemas: hk }) && !b.jsonSchema.isValid({ $ref: "https://ex/x" }, 5, { schemas: hk }));
}

function testRefUnresolvable() {
  function err(schema, inst, opts) {
    var r = b.jsonSchema.validate(schema, inst, opts);
    return !r.valid && r.errors.length === 1 && r.errors[0].keyword === "$ref";
  }
  check("fragment-less unknown $ref reports unresolved", err({ $ref: "https://nowhere.example/x" }, 1));
  check("pointer past a primitive reports unresolved", err({ xdata: [10, 20, 30], $ref: "#/xdata/0/toodeep" }, "x"));
  check("pointer array-index OOB reports unresolved", err({ xdata: [10, 20, 30], $ref: "#/xdata/9" }, "x"));
  check("pointer missing object key reports unresolved", err({ xmap: { a: 1 }, $ref: "#/nope" }, "x"));
  check("unknown plain-name anchor reports unresolved", err({ $defs: { p: { $anchor: "pos" } }, $ref: "#nonexistent" }, 1));
}

function testRefIntoNonSchema() {
  // A JSON Pointer into non-schema data (arrays, maps, escaped tokens)
  // resolves the raw value; a non-object value imposes no constraint.
  check("$ref into a data array index imposes no constraint", b.jsonSchema.isValid({ xdata: [10, 20, 30], $ref: "#/xdata/1" }, "anything"));
  check("$ref into a data map is an empty schema", b.jsonSchema.isValid({ xmap: { a: 1 }, $ref: "#/xmap" }, "anything"));
  var esc = { xmap: { "a/b": { type: "string" } }, $ref: "#/xmap/a~1b" };
  check("$ref pointer with ~1 escape resolves", b.jsonSchema.isValid(esc, "hi") && !b.jsonSchema.isValid(esc, 5));
  // A pointed-to object carrying a $id exercises the base-resolution
  // fallback for a node the registry did not index as a schema.
  check("$ref into a data object carrying $id", b.jsonSchema.isValid({ xmap: { $id: "http://x/y", a: 1 }, $ref: "#/xmap" }, "anything"));
}

function testWalkNonSchemaValues() {
  // A schema keyword whose value is not a schema (a bare number) imposes no
  // constraint rather than crashing the walker/validator.
  check("items:<number> imposes no constraint", b.jsonSchema.isValid({ items: 5 }, [1, 2, 3]));
  // not:<non-schema> — the non-schema is treated as always-pass, so 'not'
  // always fails.
  check("not:<number> always fails (non-schema is always-pass)", !b.jsonSchema.isValid({ not: 5 }, "x"));
  // A $id carrying a fragment still validates.
  check("$id with fragment validates", b.jsonSchema.isValid({ $id: "https://ex.example/a#sec", type: "string" }, "hi"));
}

function testDynamicRefEdges() {
  // Unresolvable $dynamicRef reports a located error (fail-closed).
  var r = b.jsonSchema.validate({ $dynamicRef: "#nope" }, 1);
  check("unresolvable $dynamicRef reports error", !r.valid && r.errors[0].keyword === "$dynamicRef");
  // $dynamicRef to a plain $anchor (no $dynamicAnchor) behaves like $ref,
  // resolving with an empty base.
  var s = { $defs: { x: { $anchor: "a", type: "string" } }, properties: { p: { $dynamicRef: "#a" } } };
  check("$dynamicRef to plain $anchor validates", b.jsonSchema.isValid(s, { p: "hi" }) && !b.jsonSchema.isValid(s, { p: 5 }));
  // A resolved $dynamicRef target that rejects the instance propagates fail.
  var tree = { $id: "https://ex/tree", $dynamicAnchor: "node", type: "object", properties: { children: { type: "array", items: { $dynamicRef: "#node" } } } };
  check("$dynamicRef recursion rejects bad child", !b.jsonSchema.isValid(tree, { children: ["notobject"] }));
}

function testMaxErrorsOpt() {
  // A valid maxErrors caps error collection; the option is honored.
  var v = b.jsonSchema.compile({ type: "object", properties: {}, additionalProperties: false }, { maxErrors: 2 });
  check("maxErrors caps collected errors", v.validate({ a: 1, b: 2, c: 3, d: 4 }).errors.length === 2);
  // An out-of-range maxErrors falls back to the default (does not throw).
  check("invalid maxErrors falls back to default", b.jsonSchema.validate({ type: "string" }, "x", { maxErrors: -1 }).valid === true);
}

function testFormatAssertions() {
  var af = { assertFormat: true };
  // format only asserts on strings — a non-string instance passes.
  check("format assertion skips non-string", b.jsonSchema.isValid({ format: "email" }, 123, af));
  check("uri rejects malformed percent-escape", !b.jsonSchema.isValid({ format: "uri" }, "http://x/%zz", af));
  check("uri rejects scheme-valid-but-unparseable", !b.jsonSchema.isValid({ format: "uri" }, "http://[", af));
  check("uuid accepts canonical", b.jsonSchema.isValid({ format: "uuid" }, "12345678-1234-1234-1234-123456789abc", af));
  check("uuid rejects non-uuid", !b.jsonSchema.isValid({ format: "uuid" }, "not-a-uuid", af));
  check("ipv4 accepts dotted-quad", b.jsonSchema.isValid({ format: "ipv4" }, "1.2.3.4", af));
  check("ipv4 rejects out-of-range octet", !b.jsonSchema.isValid({ format: "ipv4" }, "999.1.1.1", af));
  check("regex accepts valid pattern", b.jsonSchema.isValid({ format: "regex" }, "[a-z]+", af));
  check("regex rejects invalid pattern", !b.jsonSchema.isValid({ format: "regex" }, "[", af));
  check("unknown format is annotation-valid", b.jsonSchema.isValid({ format: "totally-unknown" }, "x", af));
}

// A `pattern` keyword is compiled and then run against the instance, so the
// schema author picks how much CPU each validation costs. `(a+)+$` against a
// run of `a` that ends in anything else measured 1.5 seconds at 28 characters,
// doubling with every two more.
//
// The marker on the compile site used to read "the JSON Schema pattern is part
// of the (operator-trusted) schema, not instance data". The framework does not
// actually hold that assumption elsewhere: b.mcp screens the pattern in a tool
// schema for exactly this shape before matching it against request input. A
// schema arrives from a registry, a tool manifest, an upload or a config file
// as readily as from the operator's own source.
//
// Driven with a subject that FAILS: one that matches returns on the first path
// through and hides the blow-up entirely.
function testPatternIsScreenedForRedos() {
  // Control first — the `pattern` keyword has to be deciding something, or a
  // guard that refused every schema would pass this test.
  var plain = { type: "string", pattern: "^abc$" };
  check("jsonSchema: control — pattern accepts its match",
        b.jsonSchema.isValid(plain, "abc") === true);
  check("jsonSchema: control — pattern rejects a non-match",
        b.jsonSchema.isValid(plain, "zzz") === false);

  var hostile = { type: "string", pattern: "(a+)+$" };
  var subject = "a".repeat(28) + "!";
  var refused = null;
  var started = process.hrtime.bigint();
  try { b.jsonSchema.isValid(hostile, subject); }
  catch (e) { refused = e; }
  var ms = Number(process.hrtime.bigint() - started) / 1e6;

  check("jsonSchema: a catastrophic pattern is refused rather than run" +
        (refused ? "" : " (ran for " + ms.toFixed(0) + "ms)"),
        refused !== null, refused ? String(refused.code) : ms.toFixed(0) + "ms");

  // compile() is the other door into the same cache and must refuse there too,
  // where the author is still looking, rather than on the first instance.
  var compileRefused = null;
  try { b.jsonSchema.compile({ type: "string", pattern: "(b+)+$" }); }
  catch (e2) { compileRefused = e2; }
  check("jsonSchema: compile() refuses it as well", compileRefused !== null);

  // A schema also carries DATA. `const`, `enum`, `default` and `examples` hold
  // instance values, so a `pattern` key inside one of them is a data key that
  // happens to be spelled like a keyword — refusing the schema for the shape of
  // its own example data would break a legal schema for no gain.
  var dataNotSchema = {
    type: "object",
    properties: {
      cfg: { const: { pattern: "(a+)+$" } },
      alt: { enum: [{ patternProperties: { "(b+)+$": true } }] },
      dflt: { type: "object", default: { pattern: "(c+)+$" } },
    },
  };
  var falseRefusal = null;
  try { b.jsonSchema.compile(dataNotSchema); }
  catch (e3) { falseRefusal = e3; }
  check("jsonSchema: a `pattern` inside const / enum / default is data, not a keyword" +
        (falseRefusal ? " (refused: " + falseRefusal.code + ")" : ""),
        falseRefusal === null);

  // And a pattern in a real subschema position is still reached, or the
  // narrowing above would have discharged the finding by looking away.
  var nested = { type: "object", properties: { inner: { type: "string", pattern: "(d+)+$" } } };
  var nestedRefused = null;
  try { b.jsonSchema.compile(nested); }
  catch (e4) { nestedRefused = e4; }
  check("jsonSchema: a pattern nested under `properties` is still screened",
        nestedRefused !== null);
}

// The screen exists so a pattern cannot make the validator hang, and SECURITY.md
// promises a screen "costs the length of the input, never a function of its
// shape". The walk that keeps that promise was itself a function of shape: it
// was bounded only by depth and kept no record of the objects it had visited, so
// a graph reaching one object through a branching position was walked once per
// PATH rather than once per object.
//
// The reproducer is a SHARED, acyclic graph — every level's `anyOf` holds two
// references to the SAME next-level object, so N levels are N+1 objects. A walk
// that tracks identity is O(N); one bounded only by depth performs 2^N visits.
// Measured before the fix: 21 objects took 2,659ms, doubling per added level,
// and the depth cap allows 256.
//
// A depth bound cannot substitute for identity tracking — it limits how far one
// path runs and says nothing about how many paths there are.
function testSharedSchemaGraphIsWalkedOncePerObject() {
  function buildShared(depth) {
    var node = { type: "string", pattern: "^a$" };
    for (var i = 0; i < depth; i += 1) {
      var next = node;
      node = { anyOf: [next, next] };            // two references to ONE object
    }
    return node;
  }

  function ms(depth) {
    var schema = buildShared(depth);
    var t0 = process.hrtime.bigint();
    try { b.jsonSchema.compile(schema); } catch (_e) { /* a refusal is fine; a hang is not */ }
    return Number(process.hrtime.bigint() - t0) / 1e6;
  }

  // Anchored to a shallow reading rather than a wall-clock budget: 24 levels is
  // 25 objects, and identity tracking keeps that within a small factor of 12.
  // The pre-fix walk is 2^12 times the work of the shallow one, so the two are
  // separated by an enormous margin and the threshold does not have to be tight.
  //
  // Re-measured before it fails anything. A single reading on each side is what
  // a contended runner moves: this failed a 64-way container run at x52 against
  // a x50 ceiling, four percent over, while the shape itself is nowhere near
  // exponential — measured best-of-5, depth 30 costs 19x depth 12, where the
  // pre-fix walk would have cost 2^18 times as much.
  var deep = helpers.bestMs(function () { ms(24); }, 3);
  var walkedPerPath = helpers.looksSuperlinear(ms, {
    small: 12, large: 24, threshold: 50, floorMs: 2,
  });
  check("jsonSchema: a shared subschema graph is walked once per object, not " +
        "once per path (" + deep.toFixed(1) + "ms at 25 objects)",
        !walkedPerPath, deep.toFixed(1) + "ms re-measured as walked per path");

  // A cyclic schema did not return at all before the fix.
  var cyclic = { type: "object" };
  cyclic.anyOf = [cyclic, cyclic];
  var cyclicMs = (function () {
    var t0 = process.hrtime.bigint();
    try { b.jsonSchema.compile(cyclic); } catch (_e) { /* refusal is fine */ }
    return Number(process.hrtime.bigint() - t0) / 1e6;
  }());
  check("jsonSchema: a cyclic schema terminates (" + cyclicMs.toFixed(1) + "ms)",
        cyclicMs < 1000, cyclicMs.toFixed(1) + "ms");

  // A cycle with ONE reference per level does not branch, so it never reaches a
  // ceiling counted in nodes — it just recurses until the JavaScript stack is
  // gone. That surfaces as a RangeError from the engine rather than as the
  // refusal this validator documents, which is the difference between a schema
  // the caller is told to fix and a crash they have to guess at. The branching
  // cycle above cannot catch it: it reaches the node ceiling almost at once.
  var linearCycle = {};
  linearCycle.anyOf = [linearCycle];
  var linearErr = null;
  try { b.jsonSchema.compile(linearCycle); } catch (e) { linearErr = e; }
  check("jsonSchema: a non-branching cyclic schema is refused with a typed " +
        "error rather than a stack overflow",
        linearErr !== null && linearErr instanceof Error &&
        !(linearErr instanceof RangeError) && typeof linearErr.code === "string",
        String(linearErr && (linearErr.code || linearErr.name)));

  // Deep is not the same as cyclic, and refusing the first to catch the second
  // would break schemas that compile today. This one nests well past the
  // reference-depth ceiling and has no cycle and no $ref, so it must still
  // compile — a cycle check that is really a depth cap fails here.
  var deepAcyclic = { type: "string" };
  for (var d2 = 0; d2 < 400; d2 += 1) {
    deepAcyclic = { type: "object", properties: { nested: deepAcyclic } };
  }
  var deepErr = null;
  try { b.jsonSchema.compile(deepAcyclic); } catch (e5) { deepErr = e5; }
  check("jsonSchema: a deeply nested ACYCLIC schema still compiles (400 levels, " +
        "no $ref)", deepErr === null, String(deepErr && (deepErr.code || deepErr.name)));

  // Visiting each object once is only safe if the first visit was COMPLETE. A
  // depth ceiling on the screen makes some visits partial: the node itself is
  // examined and its descendants are skipped. Marking such a node as done means
  // a later, shallower path — where those descendants would have been reachable
  // — skips it, and a catastrophic pattern below it is never screened. The
  // shared node is what carries the bypass from the deep path to the shallow
  // one, so this cannot be caught without sharing.
  //
  // The wrap count is swept rather than guessed, because the bypass only opens
  // when the first visit lands exactly at the ceiling.
  var missed = [];
  [250, 254, 255, 256, 257, 260].forEach(function (wraps) {
    var bad = { type: "string", pattern: "(a+)+$" };
    var shared = { type: "object", properties: { deep: bad } };
    var chain = shared;
    for (var w = 0; w < wraps; w += 1) {
      chain = { type: "object", properties: { n: chain } };
    }
    var refusedHere = null;
    try { b.jsonSchema.compile({ allOf: [chain, shared] }); }
    catch (e6) { refusedHere = e6; }
    if (refusedHere === null) missed.push(wraps);
  });
  check("jsonSchema: a catastrophic pattern under a shared node is screened " +
        "however deep the first path to that node was" +
        (missed.length ? " (missed at wraps " + missed.join(", ") + ")" : ""),
        missed.length === 0);

  // Nesting far past anything anyone authors must be REFUSED, and refused with
  // this validator's own error rather than the engine's. Recursion that simply
  // runs out of stack reports `RangeError: Maximum call stack size exceeded`,
  // which tells the caller nothing about their schema and is not catchable as a
  // JsonSchemaError.
  //
  // The cap has to THROW rather than stop walking. Silently returning at the
  // ceiling is what opened the screening bypass above: a node whose descendants
  // were skipped looks identical to one that was fully examined.
  var tooDeep = { type: "string" };
  for (var d3 = 0; d3 < 5000; d3 += 1) {
    tooDeep = { type: "object", properties: { n: tooDeep } };
  }
  var tooDeepErr = null;
  try { b.jsonSchema.compile(tooDeep); } catch (e7) { tooDeepErr = e7; }
  check("jsonSchema: nesting past the ceiling is refused with a typed error, " +
        "not a stack overflow",
        tooDeepErr !== null && !(tooDeepErr instanceof RangeError) &&
        typeof tooDeepErr.code === "string",
        String(tooDeepErr && (tooDeepErr.code || tooDeepErr.name)));

  // The legacy tuple form of `items` is an ARRAY of subschemas. The index
  // treated `items` as a single schema, so an array-valued one fell out at the
  // object test and was never walked — its subschemas were unregistered and
  // uncounted, on a branch the pattern screen does walk.
  //
  // This asserts the POINTER resolves, not that tuple items are validated:
  // `_validate` implements the 2020-12 single-schema `items` and not the
  // draft-07 tuple form, so the `$ref` is used from `properties`, which is a
  // position the validator does evaluate.
  var tupleRef = b.jsonSchema.compile({
    type: "object",
    properties: { a: { $ref: "#/$defs/tuple/items/0" } },
    $defs: { tuple: { items: [{ type: "string" }] } },
  });
  check("jsonSchema: a $ref naming a subschema inside a legacy tuple `items` " +
        "resolves",
        tupleRef.isValid({ a: "x" }) === true &&
        tupleRef.isValid({ a: 5 }) === false);

  // And a tuple nested deeply is bounded by the same ceiling rather than
  // running off the stack through a branch the index does not walk.
  var deepTuple = { type: "string" };
  for (var d4 = 0; d4 < 5000; d4 += 1) {
    deepTuple = { type: "array", items: [deepTuple] };
  }
  var deepTupleErr = null;
  try { b.jsonSchema.compile(deepTuple); } catch (e8) { deepTupleErr = e8; }
  check("jsonSchema: deep tuple-style `items` is refused with a typed error too",
        deepTupleErr !== null && !(deepTupleErr instanceof RangeError) &&
        typeof deepTupleErr.code === "string",
        String(deepTupleErr && (deepTupleErr.code || deepTupleErr.name)));

  // The screen must still SCREEN. Identity tracking that skipped real work would
  // pass every timing assertion above.
  var sharedBad = { type: "string", pattern: "(a+)+$" };
  var reachedThroughSharing = { anyOf: [{ anyOf: [sharedBad, sharedBad] }, sharedBad] };
  var refused = null;
  try { b.jsonSchema.compile(reachedThroughSharing); } catch (e) { refused = e; }
  check("jsonSchema: a catastrophic pattern reached only through a shared node " +
        "is still refused", refused !== null, String(refused && refused.code));
}

async function run() {
  testPatternIsScreenedForRedos();
  testSharedSchemaGraphIsWalkedOncePerObject();
  testSurface();
  testAssertions();
  testArrays();
  testObjects();
  testApplicators();
  testUnevaluated();
  testRefs();
  testErrorsShape();
  testFormat();
  testDepthCap();
  testInstanceTypes();
  testDeepEqualEdges();
  testNumericBounds();
  testStringBounds();
  testRegexFallback();
  testArrayApplicatorEdges();
  testObjectApplicatorEdges();
  testUnevaluatedSuccess();
  testConditionalElse();
  testRefResolution();
  testRefUnresolvable();
  testRefIntoNonSchema();
  testWalkNonSchemaValues();
  testDynamicRefEdges();
  testMaxErrorsOpt();
  testFormatAssertions();
}
module.exports = { run: run };
if (require.main === module) { run().then(function () { console.log("[json-schema] OK — " + helpers.getChecks() + " checks passed"); }, function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }); }
