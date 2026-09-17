// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// SMOKE_RUN_SOLO: growth checks here compare wall-clock time across input sizes, which a CPU shared with the smoke pool distorts.
/**
 * b.safeSchema.SafeSchemaError + b.safeSchema.undefined_ — the schema
 * error class and the undefined-only leaf schema.
 *
 * SafeSchemaError is thrown by every construction-time misuse (bad
 * union, poisoned shape key) AND by schema.parse() on validation
 * failure, carrying the full per-field .issues array so one 400 can
 * report every failing field. It is marked alwaysPermanent so a
 * validation failure never round-trips through retry / transient-error
 * logic. undefined_() is the leaf schema that accepts only `undefined`
 * (implicitly optional) and rejects everything else with an issue code
 * of "type".
 */

var childProcess = require("child_process");
var path         = require("path");
var helpers      = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

function run() {
  var s = b.safeSchema;

  // ---- SafeSchemaError: thrown by parse() on validation failure ----
  var threw = false;
  var caught = null;
  try { s.string().min(3).parse("ab"); }
  catch (e) { threw = true; caught = e; }
  check("b.safeSchema.SafeSchemaError: parse() of an invalid value throws", threw);
  check("SafeSchemaError: instanceof the exported class",
    caught instanceof b.safeSchema.SafeSchemaError);
  check("SafeSchemaError: name is SafeSchemaError", caught && caught.name === "SafeSchemaError");
  check("SafeSchemaError: carries an .issues array", Array.isArray(caught.issues));
  check("SafeSchemaError: issue[0] has the { path, code, message } shape",
    caught.issues.length === 1 &&
    Array.isArray(caught.issues[0].path) &&
    typeof caught.issues[0].code === "string" &&
    typeof caught.issues[0].message === "string");
  check("SafeSchemaError: issue code reflects the failed check (string/too-short)",
    caught.issues[0].code === "string/too-short");

  // alwaysPermanent — a validation failure must never be retried as if
  // it were a transient fault. defineClass({ alwaysPermanent: true })
  // stamps `.permanent = true` on every instance.
  check("SafeSchemaError: marked permanent so it never round-trips retry",
    caught.permanent === true);

  // The advertised aggregation guarantee: one throw surfaces EVERY
  // failing field so HTTP middleware can answer with a single 400.
  var multiThrew = null;
  try { s.object({ a: s.string().min(3), b: s.number() }).parse({ a: "x", b: "nope" }); }
  catch (e) { multiThrew = e; }
  check("SafeSchemaError: aggregates all failing fields into one .issues array",
    multiThrew instanceof b.safeSchema.SafeSchemaError && multiThrew.issues.length === 2);
  check("SafeSchemaError: each aggregated issue carries its field path",
    multiThrew.issues[0].path[0] === "a" && multiThrew.issues[1].path[0] === "b");

  // ---- SafeSchemaError: also thrown on construction-time misuse ----
  var badUnion = null;
  try { s.union([]); }
  catch (e) { badUnion = e; }
  check("SafeSchemaError: construction-time misuse (empty union) throws it",
    badUnion instanceof b.safeSchema.SafeSchemaError && badUnion.code === "safe-schema/bad-union");

  // A prototype-pollution shape key is rejected at construction, not at
  // parse, so an operator schema can never define one.
  var poisoned = null;
  try { s.object({ "constructor": s.string() }); }
  catch (e) { poisoned = e; }
  check("SafeSchemaError: a poisoned shape key ('constructor') is refused at construction",
    poisoned instanceof b.safeSchema.SafeSchemaError && poisoned.code === "safe-schema/poisoned-shape-key");

  // ---- undefined_(): accepts only undefined; implicitly optional ----
  check("b.safeSchema.undefined_: parse(undefined) returns undefined",
    b.safeSchema.undefined_().parse(undefined) === undefined);

  var nullThrew = null;
  try { s.undefined_().parse(null); }
  catch (e) { nullThrew = e; }
  check("undefined_: parse(null) throws SafeSchemaError with a type issue",
    nullThrew instanceof b.safeSchema.SafeSchemaError && nullThrew.issues[0].code === "type");

  var valThrew = null;
  try { s.undefined_().parse(0); }
  catch (e) { valThrew = e; }
  check("undefined_: parse(0) rejects a defined value with a type issue",
    valThrew instanceof b.safeSchema.SafeSchemaError && valThrew.issues[0].code === "type");

  // safeParse mirrors parse without throwing — the non-throwing consumer
  // path an operator uses to fold errors into a response body.
  check("undefined_: safeParse(undefined) is ok:true",
    s.undefined_().safeParse(undefined).ok === true);
  var spBad = s.undefined_().safeParse(1);
  check("undefined_: safeParse(1) is ok:false with the type error code",
    spBad.ok === false && spBad.errors[0].code === "type");

  testSafeSchemaBranches(s);
}

// Construction-time misuse throws, validation _fail arms, and the
// success/boundary paths across the builder API — driven only through the
// public `b.safeSchema.*` surface (`.parse` / `.safeParse`).
function testSafeSchemaBranches(s) {
  function ctorCode(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }
  function issue(schema, value) { var r = schema.safeParse(value); return r.ok ? "OK" : r.errors[0].code; }

  // ---- construction-time misuse ----
  check("pipe: non-schema arg → bad-pipe", ctorCode(function () { s.string().pipe("x"); }) === "safe-schema/bad-pipe");
  check("enum_: empty array → bad-enum", ctorCode(function () { s.enum_([]); }) === "safe-schema/bad-enum");
  check("object: non-object shape → bad-shape", ctorCode(function () { s.object("x"); }) === "safe-schema/bad-shape");
  check("object: non-schema shape value → bad-shape", ctorCode(function () { s.object({ a: "x" }); }) === "safe-schema/bad-shape");
  check("extend: non-object arg → bad-extend", ctorCode(function () { s.object({ a: s.string() }).extend("x"); }) === "safe-schema/bad-extend");
  check("array: non-schema item → bad-item", ctorCode(function () { s.array("x"); }) === "safe-schema/bad-item");
  check("tuple: empty array → bad-tuple", ctorCode(function () { s.tuple([]); }) === "safe-schema/bad-tuple");
  check("tuple: non-schema item → bad-tuple", ctorCode(function () { s.tuple(["x"]); }) === "safe-schema/bad-tuple");
  check("tuple.rest: non-schema arg → bad-tuple-rest", ctorCode(function () { s.tuple([s.string()]).rest("x"); }) === "safe-schema/bad-tuple-rest");
  check("union: non-array arg → bad-union", ctorCode(function () { s.union("x"); }) === "safe-schema/bad-union");
  check("union: non-schema option → bad-union", ctorCode(function () { s.union([s.string(), "x"]); }) === "safe-schema/bad-union");
  check("record: non-schema value → bad-value-schema", ctorCode(function () { s.record("x"); }) === "safe-schema/bad-value-schema");
  check("record: non-schema key → bad-key-schema", ctorCode(function () { s.record("x", s.string()); }) === "safe-schema/bad-key-schema");
  check("discriminatedUnion: empty options → bad-union", ctorCode(function () { s.discriminatedUnion("kind", []); }) === "safe-schema/bad-union");
  check("discriminatedUnion: non-schema option → bad-discriminated-option", ctorCode(function () { s.discriminatedUnion("kind", ["x"]); }) === "safe-schema/bad-discriminated-option");
  check("preprocess: non-fn first arg → bad-preprocess", ctorCode(function () { s.preprocess("x", s.string()); }) === "safe-schema/bad-preprocess");
  check("preprocess: non-schema second arg → bad-preprocess", ctorCode(function () { s.preprocess(function (v) { return v; }, "x"); }) === "safe-schema/bad-preprocess");
  check("lazy: non-fn arg → bad-lazy", ctorCode(function () { s.lazy("x"); }) === "safe-schema/bad-lazy");

  // ---- validation failure arms ----
  check("string.max: too long → string/too-long", issue(s.string().max(3), "toolong") === "string/too-long");
  check("string.email: overlong → string/email-too-long", issue(s.string().email(), "a".repeat(255) + "@x.io") === "string/email-too-long");
  check("string.ip: bad → string/ip", issue(s.string().ip(), "not-an-ip") === "string/ip");
  check("string.ulid: bad → string/ulid", issue(s.string().ulid(), "not-a-ulid") === "string/ulid");
  check("string.base64: bad → string/base64", issue(s.string().base64(), "!!not base64!!") === "string/base64");
  check("number.finite: Infinity → number/not-finite", issue(s.number().finite(), Infinity) === "number/not-finite");
  check("object: non-object value → type", issue(s.object({ a: s.string() }), "x") === "type");
  check("array.max: too long → array/too-long", issue(s.array(s.string()).max(2), ["a", "b", "c"]) === "array/too-long");
  check("array.length: wrong count → array/wrong-length", issue(s.array(s.string()).length(2), ["a"]) === "array/wrong-length");
  check("tuple: non-array value → type", issue(s.tuple([s.string()]), "x") === "type");
  check("record: non-object value → type", issue(s.record(s.string()), "x") === "type");
  check("discriminatedUnion: non-object value → type",
        issue(s.discriminatedUnion("kind", [s.object({ kind: s.literal("a") })]), "x") === "type");
  check("lazy: fn returning a non-schema → lazy issue", issue(s.lazy(function () { return "x"; }), "y") === "lazy");

  // ---- success / boundary arms ----
  check("string.max: within limit passes", s.string().max(5).parse("ok") === "ok");
  check("number.finite: a finite number passes", s.number().finite().parse(5) === 5);
  check("array.max: within limit passes", s.array(s.string()).max(3).parse(["a"]).length === 1);
  check("union: matches one of the options", s.union([s.string(), s.number()]).parse(42) === 42);

  // ---- catch: static default + function default ----
  check("catch: static default on failure", s.string().catch("D").parse(123) === "D");
  check("catch: function default on failure", s.string().catch(function () { return "F"; }).parse(123) === "F");

  // ---- transform: success + thrown error ----
  check("transform: maps a valid value", s.string().transform(function (v) { return v.toUpperCase(); }).parse("hi") === "HI");
  check("transform: a thrown error becomes a transform issue",
        issue(s.string().transform(function () { throw new Error("boom"); }), "x") === "transform");

  // ---- strict object rejects unknown keys ----
  check("object.strict: an unknown key is rejected",
        s.object({ a: s.string() }).strict().safeParse({ a: "x", extra: 1 }).ok === false);

  testShapeChecksAgreeWithThePatternsTheyReplaced();
}

// The shape checks were exported as PATTERNS, which handed an operator
// something they would run themselves against a value this module had already
// length-capped and they had not. Each is now a character walk behind a
// predicate. These are the patterns they replaced.
function testShapeChecksAgreeWithThePatternsTheyReplaced() {
  var s = b.safeSchema;

  var EMAIL_RE    = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  var URL_RE      = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^\s]+$/;
  var UUID_RE     = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/;
  var DATE_RE     = /^\d{4}-\d{2}-\d{2}$/;
  var DATETIME_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;
  var CUID_RE     = /^c[a-z0-9]{24}$/;
  var ULID_RE     = /^[0-9A-HJKMNP-TV-Z]{26}$/;
  var BASE64_RE   = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

  var VALUES = [
    "", " ", "a", "@", "a@", "@a", "a@b", "a@b.c", "a@b.", "a@.b", "a@b..c",
    "a@@b.c", "a b@c.d", "a@b c.d", "a@b.c ", " a@b.c", "a@b.c.d", "x@a.b",
    // A pattern's `\s` covers far more than the ASCII five, and an address
    // ending in one of the others is a different address than the one screened.
    "a\u00a0@b.c", "a@b.c\u3000", "a@b.c\u2028",
    "http://x", "https://x/y", "HTTP://X", "h://x", "://x", "x://", "1http://x",
    "a+b-c.d://x", "a_b://x", "http:/x", "http:///", "http://a b", "http://a\tb",
    "ftp://x", "x://y z", "ws://a", "://",
    "123e4567-e89b-12d3-a456-426614174000", "123E4567-E89B-12D3-A456-426614174000",
    // The version and variant nibbles are part of the shape.
    "123e4567-e89b-62d3-a456-426614174000", "123e4567-e89b-12d3-c456-426614174000",
    "123e4567-e89b-12d3-b456-426614174000", "123e4567-e89b-12d3-9456-426614174000",
    "123e4567e89b12d3a456426614174000", "123e4567-e89b-12d3-a456-42661417400",
    "123e4567-e89b-12d3-a456-4266141740000", "g23e4567-e89b-12d3-a456-426614174000",
    "123e4567_e89b-12d3-a456-426614174000",
    "2026-08-16", "2026-8-16", "26-08-16", "2026-08-1", "2026-08-166",
    "x026-08-16", "2026/08/16", "2026-08-16 ",
    "2026-08-16T12:34:56Z", "2026-08-16T12:34:56.1Z", "2026-08-16T12:34:56.123456Z",
    "2026-08-16T12:34:56+01:00", "2026-08-16T12:34:56-05:30", "2026-08-16T12:34:56",
    "2026-08-16T12:34:56.Z", "2026-08-16T12:34:56Zx", "2026-08-16T12:34:56+0100",
    "2026-08-16T12:34:56+01:0", "2026-08-16t12:34:56Z", "2026-08-16T12:34:5",
    "2026-08-16T12:34:56.123+01:00", "2026-08-16T12:34:56.123",
    "c" + "a".repeat(24), "c" + "a".repeat(23), "c" + "a".repeat(25),
    "d" + "a".repeat(24), "c" + "A".repeat(24), "c" + "0".repeat(24), "c",
    "01ARZ3NDEKTSV4RRFFQ69G5FAV", "01ARZ3NDEKTSV4RRFFQ69G5FAI",
    "01ARZ3NDEKTSV4RRFFQ69G5FAL", "01ARZ3NDEKTSV4RRFFQ69G5FAO",
    "01ARZ3NDEKTSV4RRFFQ69G5FAU", "01arz3ndektsv4rrffq69g5fav",
    "01ARZ3NDEKTSV4RRFFQ69G5FA",
    "aGVsbG8=", "aGVsbG8", "aGVsbG8==", "aGVsbG9ybGQ=", "abcd", "abc", "ab", "a",
    "====", "a===", "ab==", "abc=", "a=bc", "ab=c", "abcd====", "abcdab==",
    "a+b/c===", "a-b_c", "AAAA", "AAA=", "AA==", "A===",
  ];

  var CHECKS = [
    ["isEmail",    EMAIL_RE,    function (v) { return b.safeSchema.isEmail(v); }],
    ["isUrl",      URL_RE,      function (v) { return b.safeSchema.isUrl(v); }],
    ["isUuid",     UUID_RE,     function (v) { return b.safeSchema.isUuid(v); }],
    ["isDate",     DATE_RE,     function (v) { return b.safeSchema.isDate(v); }],
    ["isDatetime", DATETIME_RE, function (v) { return b.safeSchema.isDatetime(v); }],
    ["isCuid",     CUID_RE,     function (v) { return b.safeSchema.isCuid(v); }],
    ["isUlid",     ULID_RE,     function (v) { return b.safeSchema.isUlid(v); }],
    ["isBase64",   BASE64_RE,   function (v) { return b.safeSchema.isBase64(v); }],
  ];
  void s;

  // The one deliberate tightening, asserted below rather than waved through:
  // the pattern accepted a padded group whose spare bits were non-zero, which
  // is a SECOND spelling of bytes that already have one.
  var NON_CANONICAL_PAD_BITS = ["AB==", "AAB=", "ab==", "abcdab=="];

  var diffs = [];
  VALUES.forEach(function (v) {
    CHECKS.forEach(function (c) {
      if (c[0] === "isBase64" && NON_CANONICAL_PAD_BITS.indexOf(v) !== -1) return;
      var want = c[1].test(v);
      var got = c[2](v);
      if (want !== got) {
        diffs.push(c[0] + " " + JSON.stringify(v) + " want " + want + " got " + got);
      }
    });
  });
  check("every schema shape check agrees with the pattern it replaced (" +
        VALUES.length + " values across " + CHECKS.length + " shapes)",
        diffs.length === 0, diffs.slice(0, 5).join(" | "));

  // Every one takes whatever a caller hands it.
  [null, undefined, 42, {}, []].forEach(function (v) {
    var refused = CHECKS.every(function (c) { return c[2](v) === false; });
    check("non-string " + Object.prototype.toString.call(v) +
          " is refused by every shape check", refused);
  });

  // The tightening, stated: a padded base64 group carries fewer bits than its
  // characters can express, and a decoder discards the rest — so `AB==` and
  // `AA==` decode to the same byte. RFC 4648 §3.5 requires the spare bits be
  // zero; the pattern never looked at them, so a schema accepted a second
  // spelling of a value it had already accepted.
  NON_CANONICAL_PAD_BITS.forEach(function (v) {
    var canonical = Buffer.from(v, "base64").toString("base64");
    check("isBase64 refuses " + v + ", a non-canonical spelling of " + canonical,
          b.safeSchema.isBase64(v) === false &&
          b.safeSchema.isBase64(canonical) === true &&
          Buffer.from(v, "base64").equals(Buffer.from(canonical, "base64")));
  });

  // The IP checks are the algorithmic ones, which is what `.ipv4()` /
  // `.ipv6()` have always used — the exported pattern was the odd one out.
  check("isIpv4 accepts a dotted quad and refuses a leading zero",
        b.safeSchema.isIpv4("192.168.1.1") === true &&
        b.safeSchema.isIpv4("01.2.3.4") === false);
  check("isIpv6 accepts a compressed address and refuses a zone id",
        b.safeSchema.isIpv6("2001:db8::1") === true &&
        b.safeSchema.isIpv6("fe80::1%eth0") === false);

  // The timezone marker is upper case here, as the pattern this replaced had
  // it. RFC 3339 §5.6 permits a lower-case `z` and `b.time.readDateTime` takes
  // it — this check does not, because widening what a validator accepts admits
  // values the schema previously refused.
  check("isDatetime keeps its upper-case-only timezone marker",
        b.safeSchema.isDatetime("2026-08-16T12:34:56Z") === true &&
        b.safeSchema.isDatetime("2026-08-16T12:34:56z") === false &&
        b.safeSchema.isDatetime("2026-08-16t12:34:56Z") === false);

  testRegexPatternsAreScreened(s);
  testRecursiveLazyFactoryParsesSmallValues();
  testRepeatedValidationOfOneValueCostsItsSize(s);
  testFreshRecursiveSchemaValidatesLikeAResolvedOne(s);
  testFrozenSchemasValidate(s);
}

// Validation reads a schema and never writes to it, so a schema the caller
// froze or sealed validates the same way as one left open. Nested unions take
// the probing path, which analyses each option's callbacks.
// A recursive union whose lazy references have not been resolved yet gives the
// same result as one an earlier parse resolved. In a fresh schema the lazy
// getters run during the first descent, so the option that matches at each
// level on the way back up must not validate the subtree below it again.
function testFreshRecursiveSchemaValidatesLikeAResolvedOne(s) {
  function build(optionCount) {
    var Expr;
    var options = [];
    function bin(op) {
      return s.object({ op: s.literal(op), left: s.lazy(function () { return Expr; }), right: s.lazy(function () { return Expr; }) });
    }
    for (var i = 0; i < optionCount; i += 1) options.push(bin("op" + i));
    Expr = s.union(options.concat([s.number()]));
    return Expr;
  }
  function body(depth, op) {
    var x = 1;
    for (var i = 0; i < depth; i += 1) x = { op: op, left: x, right: 1 };
    return x;
  }
  var wrong = [];
  [[3, 90], [3, 300], [20, 90], [20, 300]].forEach(function (c) {
    var value = body(c[1], "op" + (c[0] - 1));
    var fresh = build(c[0]).safeParse(value);
    var resolved = build(c[0]);
    resolved.safeParse(body(2, "op0"));
    var warm = resolved.safeParse(value);
    var label = c[0] + " options, depth " + c[1];
    if (fresh.ok !== true) wrong.push(label + " fresh -> " + (fresh.errors && fresh.errors[0] && fresh.errors[0].code));
    else if (JSON.stringify(fresh.value) !== JSON.stringify(value)) wrong.push(label + " fresh value differs");
    if (warm.ok !== true) wrong.push(label + " resolved -> " + (warm.errors && warm.errors[0] && warm.errors[0].code));
  });
  check("safeSchema: a recursive union validates a deep value the same before and after its lazy references resolve" +
        (wrong.length ? " (" + wrong.join("; ") + ")" : ""), wrong.length === 0);
}

function testFrozenSchemasValidate(s) {
  function freezeDeep(o) {
    Object.getOwnPropertyNames(o).forEach(function (k) {
      var v = o[k];
      if (v && typeof v === "object" && !Object.isFrozen(v)) freezeDeep(v);
    });
    return Object.freeze(o);
  }
  var CASES = [
    ["frozen string inside a nested union's array", function () {
      return s.union([s.union([s.array(Object.freeze(s.string()))])]); }, ["ok"]],
    ["sealed object option inside a nested union", function () {
      return s.union([s.union([Object.seal(s.object({ a: s.string() })), s.number()])]); }, { a: "x" }],
    ["deep-frozen tuple and record options", function () {
      return s.union([s.union([freezeDeep(s.tuple([s.string(), s.number()])),
                               freezeDeep(s.record(s.string(), s.number()))])]); }, { k: 1 }],
    ["frozen lazy option", function () {
      var node = Object.freeze(s.lazy(function () { return s.object({ v: s.number() }); }));
      return s.union([s.union([s.object({ child: node }), s.string()])]); }, { child: { v: 1 } }],
  ];
  var wrong = [];
  CASES.forEach(function (c) {
    try {
      var r = c[1]().safeParse(c[2]);
      if (!r || r.ok !== true) wrong.push(c[0] + " -> " + JSON.stringify(r && r.errors).slice(0, 120));
    } catch (e) {
      wrong.push(c[0] + " threw " + (e && e.name) + ": " + String(e && e.message).slice(0, 80));
    }
  });
  check("safeSchema validates frozen and sealed schemas inside nested unions" +
        (wrong.length ? " (" + wrong.join("; ") + ")" : ""), wrong.length === 0);
}

// A lazy getter may build a fresh schema, holding a fresh lazy, every time it
// is called. Only the part of such a schema that a value reaches is built.
// Runs in a child process with a small heap and a time limit, so a schema that
// is built without end fails this check rather than the whole run.
function testRecursiveLazyFactoryParsesSmallValues() {
  var schemaPath = path.resolve(__dirname, "..", "..", "lib", "safe-schema.js");
  var script = [
    "var s = require(" + JSON.stringify(schemaPath) + ");",
    "function node() { return s.object({ children: s.array(s.lazy(node)).optional() }); }",
    "function strictNode() { return s.object({ children: s.array(s.lazy(strictNode)) }); }",
    "var results = [",
    "  s.lazy(node).safeParse({ children: [{}] }).ok,",
    "  s.lazy(strictNode).safeParse({ children: [] }).ok,",
    "  s.union([s.lazy(node), s.number()]).safeParse({ children: [{ children: [{}] }] }).ok,",
    "  s.lazy(node).safeParse({ children: [{ children: 5 }] }).ok,",
    "];",
    "process.stdout.write(JSON.stringify(results));",
  ].join("\n");
  var out = childProcess.spawnSync(process.execPath, ["--max-old-space-size=128", "-e", script],
    { encoding: "utf8", timeout: 20000 });
  check("safeSchema: a lazy getter that builds a fresh recursive schema parses small values",
        out.status === 0 && out.stdout === "[true,true,true,false]",
        "status " + out.status + " signal " + out.signal + " stdout " + out.stdout +
        " stderr " + String(out.stderr || "").slice(0, 200));
}

// `.regex()` runs its RegExp against every value the schema validates, which
// for a router body schema is request data. The pattern is screened for ReDoS
// when the schema is built, and a g or y flag is refused there: such a regex
// carries lastIndex from one parse to the next.
function testRegexPatternsAreScreened(s) {
  function regexCode(re) {
    try { s.string().regex(re); return null; } catch (e) { return e.code; }
  }
  check("safeSchema: .regex() refuses a nested-quantifier pattern with safe-schema/unsafe-pattern",
        regexCode(/^(a+)+$/) === "safe-schema/unsafe-pattern", regexCode(/^(a+)+$/));
  check("safeSchema: .regex() refuses a g-flagged pattern with safe-schema/stateful-pattern",
        regexCode(/^alice$/g) === "safe-schema/stateful-pattern", regexCode(/^alice$/g));
  check("safeSchema: .regex() refuses a y-flagged pattern with safe-schema/stateful-pattern",
        regexCode(/^alice$/y) === "safe-schema/stateful-pattern", regexCode(/^alice$/y));
  check("safeSchema: .regex() refuses a string pattern with safe-schema/bad-regex",
        regexCode("^alice$") === "safe-schema/bad-regex", regexCode("^alice$"));
  check("safeSchema: .regex() refuses an object with a test method with safe-schema/bad-regex",
        regexCode({ test: function () { return true; } }) === "safe-schema/bad-regex");
  var alice = s.string().regex(/^alice$/);
  var answers = [1, 2, 3, 4].map(function () { return alice.safeParse("alice").ok; });
  check("safeSchema: a .regex() schema gives the same answer on every parse",
        answers.join(",") === "true,true,true,true", answers.join(","));
}

// A union's options, and every reference a lazy schema resolves, can reach the
// same value by more than one path. Validating it once per path costs
// options^depth; these shapes are a few objects each.
function testRepeatedValidationOfOneValueCostsItsSize(s) {
  var Node;
  Node = s.object({
    a: s.lazy(function () { return Node; }).optional(),
    b: s.lazy(function () { return Node; }).optional(),
    v: s.number(),
  });
  function sharedInput(d) {
    var x = { v: 1 };
    for (var i = 0; i < d; i += 1) x = { a: x, b: x, v: 1 };
    return x;
  }
  function sharedOptions(d) {
    var u = s.string();
    for (var i = 0; i < d; i += 1) u = s.union([u, u]);
    return u;
  }
  // Every occurrence of a value is its own position in the output: a transform
  // or a default factory runs for each one, even when two occurrences are equal.
  var n = 0;
  var item = s.union([s.string().transform(function (v) { n += 1; return { v: v, id: n }; })]);
  var twice = s.union([s.array(item)]).parse(["a", "a"]);
  check("safeSchema: a transform inside a union runs once per occurrence of an equal value",
        twice[0].id !== twice[1].id && twice[0] !== twice[1], JSON.stringify(twice));
  var base = s.object({ n: s.number() });
  var baseRef = s.lazy(function () { return base; });
  var mutated = s.union([
    baseRef.transform(function (v) { v.n = "bad"; return v; }).refine(function () { return false; }),
    baseRef,
  ]).safeParse({ n: 1 });
  check("safeSchema: a transform in a rejected union option does not change the value a later option returns",
        mutated.ok === true && mutated.value.n === 1, JSON.stringify(mutated));
  // A callback can change the value it is given, so a failure must not be
  // reused after a callback could change the value it was computed from.
  var checkN = s.any().refine(function (v) { return v.n === 1; });
  var mutateN = s.any().transform(function (v) { v.n = 1; return v; }).refine(function () { return false; });
  var afterMutation = s.union([checkN, mutateN, checkN]).safeParse({ n: 0 });
  check("safeSchema: a union option that changes the value before failing leaves no stale failure behind",
        afterMutation.ok === true, JSON.stringify(afterMutation));
  // A failure recorded without operator code is reused only until operator
  // code runs: here the second option changes the value the first option
  // failed on.
  var nIsOne = s.object({ n: s.literal(1) });
  var setsNToOne = s.any().transform(function (v) { v.n = 1; return v; }).refine(function () { return false; });
  var recordedThenChanged = s.union([nIsOne, setsNToOne, nIsOne]).safeParse({ n: 0 });
  check("safeSchema: a failure recorded before a transform changed the value is not reused",
        recordedThenChanged.ok === true, JSON.stringify(recordedThenChanged));
  var MUTATORS = [
    { kind: "refine", build: function (v) {
      return s.any().refine(function () { v.n = 1; return false; });
    } },
    { kind: "preprocess", build: function (v) {
      return s.preprocess(function (x) { v.n = 1; return x; }, s.literal("never"));
    } },
    { kind: "default factory", build: function (v) {
      return s.object({ missing: s.any().default(function () { v.n = 1; return 0; }), never: s.literal(1) }).passthrough();
    } },
    { kind: "catch factory", build: function (v) {
      return s.object({ n: s.literal("x").catch(function () { v.n = 1; return 0; }), never: s.literal(1) });
    } },
    { kind: "lazy getter", build: function (v) {
      return s.lazy(function () { v.n = 1; return s.literal("never"); });
    } },
  ];
  // Inside a union nested in another union's option, an object's fields are
  // still validated in shape order when an earlier field runs operator code
  // that changes a later one.
  var flipInput = { flip: 0, n: 1 };
  var flipToZero = s.object({
    flip: s.any().transform(function () { flipInput.n = 0; return 0; }),
    n:    s.literal(1),
  });
  var orderedReject = s.union([s.union([flipToZero])]).safeParse(flipInput);
  check("safeSchema: in a nested union, a transform that invalidates a later field still rejects the object",
        orderedReject.ok === false, JSON.stringify(orderedReject));
  var fixInput = { first: 0, second: 0 };
  var fixesSecond = s.object({
    first:  s.any().transform(function () { fixInput.second = 1; return 0; }),
    second: s.literal(1),
  });
  var orderedAccept = s.union([s.union([fixesSecond])]).safeParse(fixInput);
  check("safeSchema: in a nested union, a transform that makes a later field valid still accepts the object",
        orderedAccept.ok === true && orderedAccept.value.second === 1, JSON.stringify(orderedAccept));
  // An object reads its input's keys after its fields have been validated, so
  // a field callback that adds or removes a key is seen by the unknown-key
  // check, at the top level and inside a nested union.
  function deletesExtra(input) {
    return s.object({ a: s.any().transform(function (v) { delete input.extra; return v; }) });
  }
  function addsExtra(input) {
    return { a: s.any().transform(function (v) { input.extra = 2; return v; }) };
  }
  var deleteInput = { a: 0, extra: 1 };
  var deleted = deletesExtra(deleteInput).safeParse(deleteInput);
  var nestedDeleteInput = { a: 0, extra: 1 };
  var nestedDeleted = s.union([s.union([deletesExtra(nestedDeleteInput)])]).safeParse(nestedDeleteInput);
  var strictAddInput = { a: 0 };
  var strictAdded = s.object(addsExtra(strictAddInput)).safeParse(strictAddInput);
  var passAddInput = { a: 0 };
  var passAdded = s.object(addsExtra(passAddInput)).passthrough().safeParse(passAddInput);
  var keyResults = [deleted.ok, nestedDeleted.ok, strictAdded.ok, passAdded.ok && passAdded.value.extra === 2];
  check("safeSchema: an object sees keys a field callback added or removed",
        keyResults.join(",") === "true,true,false,true", keyResults.join(","));
  // A failing option still runs its later fields' callbacks when it has any,
  // so a later option that returns the input sees what those callbacks did.
  var laterCatchInput = { a: 0, b: true };
  var laterCatch = s.object({
    a: s.literal("A"),
    b: s.literal(1).catch(function () { laterCatchInput.a = 1; return 0; }),
  }).passthrough();
  var afterLaterCatch = s.union([s.union([laterCatch, s.any()])]).safeParse(laterCatchInput);
  check("safeSchema: in a nested union, a failing option still runs the callbacks of its later fields",
        afterLaterCatch.ok === true && afterLaterCatch.value.a === 1, JSON.stringify(afterLaterCatch));
  function markingItem(target) {
    return s.object({ ok: s.literal(true), c: s.literal(1).catch(function () { target.mark = 1; return 0; }) });
  }
  var CONTAINERS = [
    { kind: "array", run: function () {
      var input = [{ ok: false }, { ok: true, c: "x" }];
      return { input: input, result: s.union([s.union([s.array(markingItem(input)), s.any()])]).safeParse(input) };
    } },
    { kind: "tuple", run: function () {
      var input = [{ ok: false }, { ok: true, c: "x" }];
      var item = markingItem(input);
      return { input: input, result: s.union([s.union([s.tuple([item, item]), s.any()])]).safeParse(input) };
    } },
    { kind: "record", run: function () {
      var input = { first: { ok: false }, second: { ok: true, c: "x" } };
      return { input: input, result: s.union([s.union([s.record(markingItem(input)), s.any()])]).safeParse(input) };
    } },
  ];
  var skippedLater = CONTAINERS.filter(function (c) {
    var got = c.run();
    return !(got.result.ok === true && got.input.mark === 1);
  }).map(function (c) { return c.kind; });
  check("safeSchema: in a nested union, a failing container still runs its later elements' callbacks" +
        (skippedLater.length ? " (skipped in: " + skippedLater.join(", ") + ")" : ""), skippedLater.length === 0);
  var lazyFixInput = { first: 0, second: 0 };
  var lazyFixesSecond = s.object({
    first:  s.lazy(function () {
      return s.any().transform(function () { lazyFixInput.second = 1; return 0; });
    }),
    second: s.literal(1),
  });
  var lazyOrderedAccept = s.union([s.union([lazyFixesSecond])]).safeParse(lazyFixInput);
  check("safeSchema: in a nested union, a not-yet-resolved lazy field is validated before the fields after it",
        lazyOrderedAccept.ok === true, JSON.stringify(lazyOrderedAccept));
  var staleAfter = MUTATORS.filter(function (m) {
    var v = { n: 0 };
    return s.union([nIsOne, m.build(v), nIsOne]).safeParse(v).ok !== true;
  }).map(function (m) { return m.kind; });
  check("safeSchema: a failure is not reused after any operator callback changed the value" +
        (staleAfter.length ? " (reused after: " + staleAfter.join(", ") + ")" : ""), staleAfter.length === 0);
  // A failure computed while operator code ran is not recorded: the same
  // schema run again sees what that code does the next time.
  var flipped = { flip: 0, n: 1 };
  var flipper = s.object({
    flip: s.any().transform(function () { flipped.n = flipped.n === 1 ? 0 : 1; return 0; }),
    n:    s.literal(1),
  });
  var flipResult = s.union([flipper, flipper]).safeParse(flipped);
  check("safeSchema: a failure computed while a transform ran is not reused",
        flipResult.ok === true, JSON.stringify(flipResult));
  var nested = 0;
  var inner = s.union([s.string().transform(function (v) { nested += 1; return v + nested; })]);
  var outer = s.union([s.string().refine(function (v) { return inner.parse(v) === v + nested; })]);
  check("safeSchema: a parse nested inside a union check runs its own transforms",
        s.union([s.array(outer)]).parse(["q", "q"]).length === 2 && nested === 2, "nested=" + nested);

  var grew = [];
  if (helpers.looksSuperlinear(function (d) { Node.safeParse(sharedInput(d)); },
      { small: 15, large: 19, threshold: 8, floorMs: 5 })) grew.push("an input that reuses one object at every level");
  if (helpers.looksSuperlinear(function (d) { sharedOptions(d).safeParse(12345); },
      { small: 8, large: 16, threshold: 8, floorMs: 5 })) grew.push("a union whose two options are the same schema");
  check("safeSchema: validation cost follows the size of the value and schema" +
        (grew.length ? " (grew: " + grew.join("; ") + ")" : ""), grew.length === 0);
  if (grew.length) return;

  var deep = Node.safeParse(sharedInput(40));
  check("safeSchema: a 40-level input reusing one object is refused with safe-schema/evaluation-limit",
        deep.ok === false && deep.errors.length === 1 && deep.errors[0].code === "safe-schema/evaluation-limit",
        JSON.stringify(deep.errors && deep.errors.slice(0, 2)));
  var thrown = null;
  try { Node.parse(sharedInput(40)); } catch (e) { thrown = e; }
  check("safeSchema: parse() of that input throws SafeSchemaError safe-schema/evaluation-limit",
        thrown instanceof s.SafeSchemaError && thrown.code === "safe-schema/evaluation-limit",
        thrown && (thrown.code || thrown.message));
  var wideTree = [];
  for (var wt = 0; wt < 20000; wt += 1) wideTree.push({ v: wt });
  check("safeSchema: a large ordinary value is not refused by the limit",
        s.array(Node).safeParse(wideTree).ok === true);
  var deepFail = sharedOptions(40).safeParse(12345);
  check("safeSchema: a 40-level shared-option union refuses a non-string", deepFail.ok === false);
  check("safeSchema: that refusal carries a bounded issue list (" + deepFail.errors.length + " issues)",
        deepFail.errors.length <= 256, deepFail.errors.length);

  var wide = [];
  for (var w = 0; w < 150; w += 1) wide.push(s.object({ ["k" + w]: s.string() }));
  var wideFail = s.union(wide).safeParse({});
  var omittedIssue = wideFail.errors.filter(function (e) { return e.code === "union/issues-omitted"; })[0];
  check("safeSchema: a union keeps its first 100 option issues and names how many it omitted",
        wideFail.ok === false && wideFail.errors.length === 102 && omittedIssue &&
        /^50 further issues/.test(omittedIssue.message), wideFail.errors.length);

  // `num` and `num.catch(7)` run the same check; only the catch differs. A
  // remembered result must be the check's own answer, never the caught one.
  var num = s.number();
  check("safeSchema: a catch on one option is not shared with the same schema without it",
        s.union([num, num.catch(7)]).parse("x") === 7);
  check("safeSchema: a catch on the first option still wins when it comes first",
        s.union([num.catch(7), num]).parse("x") === 7);
  var caughtNull = num.catch(function () { return 7; }).safeParse(null);
  check("safeSchema: a catch factory supplies the value for null as it does for a failed check",
        caughtNull.ok === true && caughtNull.value === 7 && num.catch(function () { return 7; }).parse("x") === 7,
        typeof caughtNull.value);
  var refused = s.union([num, num]).safeParse("x");
  check("safeSchema: the same schema twice without a catch still refuses", refused.ok === false);
  var caughtThenPlain = s.union([
    s.object({ a: s.union([num.catch(7)]), b: s.literal("never") }),
    s.object({ a: s.union([num]) }),
  ]).safeParse({ a: "x" });
  check("safeSchema: a value caught under one option is still refused under an option without the catch",
        caughtThenPlain.ok === false, JSON.stringify(caughtThenPlain));

  var Tree;
  Tree = s.object({ id: s.string(), kids: s.array(s.lazy(function () { return Tree; })) });
  var tree = Tree.safeParse({ id: "r", kids: [{ id: "a", kids: [] }, { id: 5, kids: [] }] });
  check("safeSchema: a lazy tree still reports the failing node's path",
        tree.ok === false && tree.errors.some(function (e) {
          return e.path.join(".") === "kids.1.id";
        }), JSON.stringify(tree.errors));

  function errorPaths(result) {
    return result.ok ? [] : result.errors.map(function (e) { return e.path.join("."); });
  }
  // A failure remembered for one value is reported at the position where the
  // value is found again, with the issues that position's run would report.
  var Leaf = s.lazy(function () { return s.object({ n: s.number() }); });
  var sharedLeaf = { n: "x" };
  var pairPaths = errorPaths(s.union([s.object({ left: Leaf, right: Leaf })])
    .safeParse({ left: sharedLeaf, right: sharedLeaf }));
  check("safeSchema: one failing object under two keys is reported at both keys",
        pairPaths.indexOf("left.n") !== -1 && pairPaths.indexOf("right.n") !== -1, JSON.stringify(pairPaths));
  var Inner = s.lazy(function () {
    return s.object({ p: s.union([s.object({ x: s.string(), y: s.string() })]) });
  });
  var twoBad = { p: { x: 1, y: 1 } };
  var modePaths = errorPaths(s.lazy(function () {
    return s.object({ first: s.union([Inner, s.boolean()]), second: Inner });
  }).safeParse({ first: twoBad, second: twoBad }));
  check("safeSchema: a value that failed inside a union's options reports every issue outside the union",
        modePaths.indexOf("second.p.x") !== -1 && modePaths.indexOf("second.p.y") !== -1, JSON.stringify(modePaths));
  var requiredUnion = s.string();
  var requiredValue = 12345;
  for (var ru = 0; ru < 30; ru += 1) {
    requiredUnion = s.union([s.object({ k: requiredUnion }).required(), s.object({ k: requiredUnion }).required()]);
    requiredValue = { k: requiredValue };
  }
  var requiredFail = requiredUnion.safeParse(requiredValue);
  check("safeSchema: a 30-level union of required() objects sharing one child refuses a bad leaf with its union issues",
        requiredFail.ok === false && requiredFail.errors[0].code === "union",
        requiredFail.ok ? "ok" : requiredFail.errors[0].code);
  var failingDag = { v: "x" };
  for (var fd = 0; fd < 21; fd += 1) failingDag = { a: failingDag, b: failingDag, v: 1 };
  var failingDeep = Node.safeParse(failingDag);
  check("safeSchema: a 21-level input reusing one failing object is refused with safe-schema/evaluation-limit",
        failingDeep.ok === false && failingDeep.errors.length === 1 &&
        failingDeep.errors[0].code === "safe-schema/evaluation-limit",
        failingDeep.ok ? "ok" : failingDeep.errors.length + " errors, first " + failingDeep.errors[0].code);
}

module.exports = { run: run };

if (require.main === module) {
  try { run(); console.log("OK — " + helpers.getChecks() + " checks passed"); }
  catch (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
}
