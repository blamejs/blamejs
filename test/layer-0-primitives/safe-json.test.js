// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.safeJson parse caps — the six documented limit constants and the fact
 * that b.safeJson.parse actually enforces them.
 *
 * These are not typeof assertions: each test drives the real parse consumer
 * path so the constant's advertised value is proven to be the boundary the
 * primitive honors. The DEFAULT_* trio is exercised end-to-end (a payload one
 * step past the cap refuses with the documented .code; a payload at/under it
 * parses). The ABSOLUTE_* trio is the ceiling opts.max* clamps down to — the
 * depth ceiling is exercised via a real clamp (a huge maxDepth request is
 * pinned back to 1000), and the byte / key ceilings are exercised as the higher
 * working cap that changes a parse outcome the default refuses. Fixtures are
 * sized from the constants themselves so a value drift breaks the test.
 */

var { check, b } = require("../helpers");

function _nest(n) {
  return "[".repeat(n) + "1" + "]".repeat(n);
}

function _objectWithKeys(n) {
  var pairs = [];
  for (var i = 0; i < n; i += 1) pairs.push('"k' + i + '":0');
  return "{" + pairs.join(",") + "}";
}

function _code(fn) {
  try { fn(); return "OK"; }
  catch (e) { return e && e.code; }
}

// ---- DEFAULT_MAX_BYTES ----

function testDefaultMaxBytes() {
  check("b.safeJson.DEFAULT_MAX_BYTES is the advertised 1 MiB",
        b.safeJson.DEFAULT_MAX_BYTES === 1048576);

  // A JSON string body just past the default cap refuses BEFORE the parser
  // sees it — the whole point of the byte cap is DoS-avoidance on the parse
  // thread. Sizing the payload off the constant means a value drift flips it.
  var overDefault = '"' + "x".repeat(b.safeJson.DEFAULT_MAX_BYTES + 100) + '"';
  check("parse refuses a body larger than DEFAULT_MAX_BYTES with json/too-large",
        _code(function () { b.safeJson.parse(overDefault); }) === "json/too-large");

  // A small body sails through under the same default cap.
  var underDefault = '"' + "x".repeat(64) + '"';
  check("parse accepts a body well under DEFAULT_MAX_BYTES",
        b.safeJson.parse(underDefault) === "x".repeat(64));

  // Proof the DEFAULT is what applied above: raising maxBytes past the body
  // size accepts the same over-default payload the default rejected.
  check("raising opts.maxBytes above the body accepts what the default refused",
        typeof b.safeJson.parse(overDefault, {
          maxBytes: b.safeJson.DEFAULT_MAX_BYTES + 200,
        }) === "string");
}

// ---- DEFAULT_MAX_DEPTH ----

function testDefaultMaxDepth() {
  check("b.safeJson.DEFAULT_MAX_DEPTH is the advertised 100",
        b.safeJson.DEFAULT_MAX_DEPTH === 100);

  // Nesting one level past the default bound refuses; nesting exactly at the
  // bound parses. Bounds stack-overflow risk for downstream clone/merge walks.
  var tooDeep = _nest(b.safeJson.DEFAULT_MAX_DEPTH + 1);
  check("parse refuses nesting past DEFAULT_MAX_DEPTH with json/too-deep",
        _code(function () { b.safeJson.parse(tooDeep); }) === "json/too-deep");

  var atDepth = _nest(b.safeJson.DEFAULT_MAX_DEPTH);
  check("parse accepts nesting at DEFAULT_MAX_DEPTH",
        Array.isArray(b.safeJson.parse(atDepth)));
}

// ---- DEFAULT_MAX_KEYS ----

function testDefaultMaxKeys() {
  check("b.safeJson.DEFAULT_MAX_KEYS is the advertised 10 000",
        b.safeJson.DEFAULT_MAX_KEYS === 10000);

  // One key past the default per-object cap refuses (CVE-2026-21717 HashDoS
  // guard); exactly at the cap parses.
  var tooMany = _objectWithKeys(b.safeJson.DEFAULT_MAX_KEYS + 1);
  check("parse refuses an object past DEFAULT_MAX_KEYS with json/too-many-keys",
        _code(function () { b.safeJson.parse(tooMany); }) === "json/too-many-keys");

  var atKeys = _objectWithKeys(b.safeJson.DEFAULT_MAX_KEYS);
  check("parse accepts an object at DEFAULT_MAX_KEYS",
        Object.keys(b.safeJson.parse(atKeys)).length === b.safeJson.DEFAULT_MAX_KEYS);
}

// ---- ABSOLUTE_MAX_BYTES ----

function testAbsoluteMaxBytes() {
  check("b.safeJson.ABSOLUTE_MAX_BYTES is the advertised 64 MiB",
        b.safeJson.ABSOLUTE_MAX_BYTES === 67108864);
  check("ABSOLUTE_MAX_BYTES sits above the default (real headroom ceiling)",
        b.safeJson.ABSOLUTE_MAX_BYTES > b.safeJson.DEFAULT_MAX_BYTES);

  // Exercised as the higher working cap: a body the default refuses is
  // accepted when maxBytes is raised to the absolute ceiling. The full clamp
  // at 64 MiB is asserted by value only — allocating a 64 MiB body per process
  // is unsuitable for the parallel smoke harness.
  var overDefault = '"' + "x".repeat(b.safeJson.DEFAULT_MAX_BYTES + 100) + '"';
  check("default cap refuses the over-default body",
        _code(function () { b.safeJson.parse(overDefault); }) === "json/too-large");
  check("maxBytes = ABSOLUTE_MAX_BYTES accepts the over-default body",
        typeof b.safeJson.parse(overDefault, {
          maxBytes: b.safeJson.ABSOLUTE_MAX_BYTES,
        }) === "string");
}

// ---- ABSOLUTE_MAX_DEPTH ----

function testAbsoluteMaxDepth() {
  check("b.safeJson.ABSOLUTE_MAX_DEPTH is the advertised 1000",
        b.safeJson.ABSOLUTE_MAX_DEPTH === 1000);
  check("ABSOLUTE_MAX_DEPTH sits above the default",
        b.safeJson.ABSOLUTE_MAX_DEPTH > b.safeJson.DEFAULT_MAX_DEPTH);

  // A caller asking for a maxDepth far above the ceiling is silently clamped
  // to ABSOLUTE_MAX_DEPTH — so nesting one past the ceiling still refuses even
  // with the inflated request, and nesting at the ceiling still parses.
  var hugeRequest = b.safeJson.ABSOLUTE_MAX_DEPTH * 100;
  var pastCeiling = _nest(b.safeJson.ABSOLUTE_MAX_DEPTH + 1);
  check("an inflated maxDepth is clamped to ABSOLUTE_MAX_DEPTH (refuses past it)",
        _code(function () {
          b.safeJson.parse(pastCeiling, { maxDepth: hugeRequest });
        }) === "json/too-deep");

  var atCeiling = _nest(b.safeJson.ABSOLUTE_MAX_DEPTH);
  check("nesting at ABSOLUTE_MAX_DEPTH parses under the clamped cap",
        Array.isArray(b.safeJson.parse(atCeiling, { maxDepth: hugeRequest })));
}

// ---- ABSOLUTE_MAX_KEYS ----

function testAbsoluteMaxKeys() {
  check("b.safeJson.ABSOLUTE_MAX_KEYS is the advertised 1 000 000",
        b.safeJson.ABSOLUTE_MAX_KEYS === 1000000);
  check("ABSOLUTE_MAX_KEYS sits above the default (real headroom ceiling)",
        b.safeJson.ABSOLUTE_MAX_KEYS > b.safeJson.DEFAULT_MAX_KEYS);

  // Exercised as the higher working cap: an object the default refuses is
  // accepted when maxKeys is raised to the absolute ceiling. The full clamp at
  // 1 000 000 keys is asserted by value only — allocating a million-key object
  // per process is unsuitable for the parallel smoke harness.
  var overDefault = _objectWithKeys(b.safeJson.DEFAULT_MAX_KEYS + 1);
  check("default cap refuses the over-default object",
        _code(function () { b.safeJson.parse(overDefault); }) === "json/too-many-keys");
  check("maxKeys = ABSOLUTE_MAX_KEYS accepts the over-default object",
        Object.keys(b.safeJson.parse(overDefault, {
          maxKeys: b.safeJson.ABSOLUTE_MAX_KEYS,
        })).length === b.safeJson.DEFAULT_MAX_KEYS + 1);
}

// ---- json/syntax must not echo the parsed input (CWE-532) ----

function _thrown(fn) {
  try { fn(); return null; }
  catch (e) { return e; }
}

function testSyntaxErrorDoesNotLeakInputBytes() {
  // A syntax error on secret-bearing input must NOT reflect a window of the
  // parsed bytes back in the thrown message. `parse` sits at a trust boundary;
  // a consumer that logs the error (directly, or via an unhandled rejection
  // stack) would otherwise re-emit the secret (CWE-532). b.redact does not
  // mitigate this: it deliberately excludes the high-entropy detector, so a
  // raw key-byte snippet passes through unredacted.
  var secret = "MIIJSECRETBYTES1234567890";
  var caught = _thrown(function () { b.safeJson.parse('{"k": ' + secret + '}'); });

  check("parse throws on the malformed secret-bearing body",
        caught !== null);
  check("the syntax error keeps the stable json/syntax code",
        caught && caught.code === "json/syntax");
  // V8 echoes a leading window of the offending input (here "MIIJSECRET…");
  // the sanitized message must contain none of it.
  check("the thrown message does NOT echo a window of the parsed input",
        caught && typeof caught.message === "string" &&
        caught.message.indexOf(secret) === -1 &&
        caught.message.indexOf("MIIJSECRET") === -1);

  // A position-bearing V8 error keeps the (non-secret) numeric offset while
  // still hiding the input snippet.
  var posSecret = "TOPSECRETVALUE";
  var posCaught = _thrown(function () {
    b.safeJson.parse('{"a":1 "' + posSecret + '":2}');
  });
  check("a position-bearing syntax error still hides the input snippet",
        posCaught && posCaught.code === "json/syntax" &&
        typeof posCaught.message === "string" &&
        posCaught.message.indexOf(posSecret) === -1);
}

// ---- SafeJsonError constructor defaults ----

function testSafeJsonErrorDefaults() {
  // Constructed directly (a public export) with no code / path — the
  // `code || "json/invalid"` and `path || null` fallbacks only fire here,
  // since every internal throw passes an explicit code.
  var e1 = new b.safeJson.SafeJsonError("boom");
  check("SafeJsonError with no code defaults to json/invalid", e1.code === "json/invalid");
  check("SafeJsonError with no path defaults to null", e1.path === null);
  check("SafeJsonError carries its identity flags",
        e1.isSafeJsonError === true && e1.name === "SafeJsonError");

  var e2 = new b.safeJson.SafeJsonError("boom", "json/x", "$.a");
  check("SafeJsonError honors an explicit code and path",
        e2.code === "json/x" && e2.path === "$.a");
}

// ---- parse: allowProto ternary + reviver proto-strip ----

function testParseAllowProtoAndProtoStrip() {
  // Reviver strips poisoned keys during JSON.parse (the `? undefined :
  // _stripProtoKeys` false arm + the isPoisonedKey true arm).
  var stripped = b.safeJson.parse('{"constructor":{"x":1},"prototype":9,"id":5}');
  check("parse strips a constructor key via the reviver",
        !Object.prototype.hasOwnProperty.call(stripped, "constructor"));
  check("parse strips a prototype key via the reviver",
        !Object.prototype.hasOwnProperty.call(stripped, "prototype"));
  check("parse keeps the benign key alongside stripped ones", stripped.id === 5);

  // allowProto:true selects the `? undefined` reviver arm (no stripping) and
  // skips the walk-time strip, so the poisoned own key survives.
  var kept = b.safeJson.parse('{"constructor":7,"id":5}', { allowProto: true });
  check("parse allowProto:true keeps the constructor own key",
        Object.prototype.hasOwnProperty.call(kept, "constructor") && kept.constructor === 7);
}

// ---- parse: schema (throw + collectErrors) ----

function testParseWithSchema() {
  var schema = { type: "object", required: ["a"], properties: { a: { type: "integer" } } };

  var ok = b.safeJson.parse('{"a":3}', { schema: schema });
  check("parse with schema returns the parsed value on success", ok.a === 3);

  check("parse with schema throws json/validation on mismatch",
        _code(function () { b.safeJson.parse('{"a":"nope"}', { schema: schema }); }) === "json/validation");

  var report = b.safeJson.parse('{"a":"nope"}', { schema: schema, collectErrors: true });
  check("parse with schema + collectErrors returns an error report instead of throwing",
        report && report.ok === false && Array.isArray(report.errors) && report.errors.length >= 1);

  var goodReport = b.safeJson.parse('{"a":3}', { schema: schema, collectErrors: true });
  check("parse with schema + collectErrors returns an ok report on valid input",
        goodReport.ok === true && goodReport.errors.length === 0);
}

// ---- parse: legacy expectType + requiredKeys ----

function testParseExpectTypeAndRequiredKeys() {
  check("parse expectType matching returns the value",
        b.safeJson.parse("[1,2]", { expectType: "array" }).length === 2);
  check("parse expectType mismatch throws json/type-mismatch",
        _code(function () { b.safeJson.parse('{"a":1}', { expectType: "array" }); }) === "json/type-mismatch");

  // requiredKeys on an object drives all four operands of the guard true and
  // enters the missing-key loop.
  check("parse requiredKeys all-present returns the value",
        b.safeJson.parse('{"a":1,"b":2}', { requiredKeys: ["a", "b"] }).b === 2);
  check("parse requiredKeys with a missing key throws json/missing-key",
        _code(function () { b.safeJson.parse('{"a":1}', { requiredKeys: ["a", "zzz"] }); }) === "json/missing-key");
  // A non-object root short-circuits the `!Array.isArray(parsed)` operand.
  check("parse requiredKeys is ignored when the root is an array",
        Array.isArray(b.safeJson.parse("[1,2]", { requiredKeys: ["a"] })));
}

// ---- parseOrDefault ----

function testParseOrDefault() {
  check("parseOrDefault returns the parsed value on success",
        b.safeJson.parseOrDefault('{"x":1}', {}).x === 1);
  check("parseOrDefault returns the fallback on a syntax error",
        b.safeJson.parseOrDefault("{not json", { fb: 1 }).fb === 1);
  check("parseOrDefault returns the fallback on a non-string input",
        Array.isArray(b.safeJson.parseOrDefault(null, [])));
}

// ---- parseStringOrObject ----

function _makeCustomErr() {
  // An operator-supplied error class as parseStringOrObject documents it:
  // `new errorClass(code, message)`.
  function CustomErr(code, message) {
    var e = new Error(message);
    e.name = "CustomErr";
    e.code = code;
    return e;
  }
  return CustomErr;
}

function testParseStringOrObject() {
  var CustomErr = _makeCustomErr();

  // JSON string routes through parse (poisoned key stripped, caps applied).
  var v = b.safeJson.parseStringOrObject('{"__proto__":{"x":1},"a":1}');
  check("parseStringOrObject parses a JSON string and strips poisoned keys",
        v.a === 1 && !Object.prototype.hasOwnProperty.call(v, "__proto__"));

  // An already-decoded value comes back as its JSON form, read once and
  // handed over. Returning the caller's own object instead made the cap a
  // statement about a value somebody else still held and could answer
  // differently the next time it was read.
  var obj = { a: 1 };
  var back = b.safeJson.parseStringOrObject(obj);
  check("parseStringOrObject answers a decoded object with its JSON form",
        back !== obj && back.a === 1 && Object.keys(back).length === 1,
        JSON.stringify(back));
  var poisoned = JSON.parse('{"__proto__":{"x":1},"a":1}');
  var cleaned = b.safeJson.parseStringOrObject(poisoned);
  check("and the same key strip applies to it as to the string form",
        cleaned.a === 1 && !Object.prototype.hasOwnProperty.call(cleaned, "__proto__"),
        JSON.stringify(Object.keys(cleaned)));

  // Invalid JSON, no errorClass → rethrows the underlying SafeJsonError.
  var e1 = _thrown(function () { b.safeJson.parseStringOrObject("{not json"); });
  check("parseStringOrObject rethrows SafeJsonError on bad JSON without an errorClass",
        e1 && e1.isSafeJsonError === true);

  // Invalid JSON, with errorClass → wraps in that class with jsonCode.
  var e2 = _thrown(function () {
    b.safeJson.parseStringOrObject("{not json", {
      errorClass: CustomErr, jsonCode: "x/bad-json", label: "x.parse",
    });
  });
  check("parseStringOrObject wraps bad JSON in the operator errorClass with jsonCode",
        e2 && e2.name === "CustomErr" && e2.code === "x/bad-json");

  // Non-string / non-object (number), no errorClass → SafeJsonError.
  var e3 = _thrown(function () { b.safeJson.parseStringOrObject(42); });
  check("parseStringOrObject rejects a number with json/wrong-input-type",
        e3 && e3.code === "json/wrong-input-type");

  // Buffer input (own object-but-binary branch), with errorClass → inputCode.
  var e4 = _thrown(function () {
    b.safeJson.parseStringOrObject(Buffer.from("x"), {
      errorClass: CustomErr, inputCode: "x/bad-input",
    });
  });
  check("parseStringOrObject rejects a Buffer via the operator errorClass with inputCode",
        e4 && e4.name === "CustomErr" && e4.code === "x/bad-input");

  // A non-Buffer Uint8Array also fails the plain-object gate.
  var e5 = _thrown(function () { b.safeJson.parseStringOrObject(new Uint8Array([1, 2])); });
  check("parseStringOrObject rejects a Uint8Array with json/wrong-input-type",
        e5 && e5.code === "json/wrong-input-type");

  // null is neither a string nor a plain object.
  var e6 = _thrown(function () { b.safeJson.parseStringOrObject(null); });
  check("parseStringOrObject rejects null with json/wrong-input-type",
        e6 && e6.code === "json/wrong-input-type");
}

function testParseStringOrObjectCapsTheObjectBranch() {
  var CustomErr = _makeCustomErr();
  var big = { pad: "x".repeat(4096) };

  var e1 = _thrown(function () { b.safeJson.parseStringOrObject(big, { maxBytes: 256 }); });
  check("parseStringOrObject applies maxBytes to a pre-parsed object",
        e1 && e1.code === "json/too-large");

  var e2 = _thrown(function () {
    b.safeJson.parseStringOrObject(big, {
      maxBytes: 256, errorClass: CustomErr, jsonCode: "x/bad-json", label: "x.parse",
    });
  });
  check("an over-cap object routes through the operator errorClass",
        e2 && e2.name === "CustomErr" && e2.code === "x/bad-json");

  var under = { pad: "x".repeat(64) };
  var served = b.safeJson.parseStringOrObject(under, { maxBytes: 256 });
  check("an object under the cap is served as its JSON form, not as itself",
        served !== under && served.pad === under.pad,
        JSON.stringify({ same: served === under, padLength: served.pad.length }));

  // An object whose JSON form is not an object is answered the way any other
  // input that is not a document is, rather than handed to a consumer that
  // then reads members off null.
  var notADocument = _thrown(function () {
    b.safeJson.parseStringOrObject({ toJSON: function () { return null; } }, { maxBytes: 256 });
  });
  check("an object whose JSON form is not one is refused as bad input",
        notADocument && notADocument.code === "json/wrong-input-type",
        JSON.stringify({ code: notADocument && notADocument.code }));
  var notADocumentTyped = _thrown(function () {
    b.safeJson.parseStringOrObject({ toJSON: function () { return "text"; } }, {
      maxBytes: 256, errorClass: CustomErr, inputCode: "x/bad-input", label: "x.parse",
    });
  });
  check("and through the operator's own input code when it supplies one",
        notADocumentTyped && notADocumentTyped.code === "x/bad-input",
        JSON.stringify({ code: notADocumentTyped && notADocumentTyped.code }));
}

function testJsonCopyUnderCap() {
  // A cap on a value the caller goes on to use has to be a statement about
  // the value they end up holding. Measuring and handing back the original
  // is a statement about a different object: a getter, a proxy or a toJSON
  // hook answers the measurement and the caller separately, a property that
  // is not enumerable, is inherited, or is named so that it falls outside an
  // array's elements is skipped by the walk and read by name afterwards, and
  // each of those is a way to report one method call to a cap and hand ten
  // thousand to a handler. Serializing once and reading back leaves no
  // second reading to differ from the first.
  var reads = 0;
  var live = {};
  Object.defineProperty(live, "calls", {
    enumerable: true,
    get: function () {
      reads += 1;
      return reads === 1 ? ["small"] : new Array(1000).fill("x".repeat(1024));                        // allow:raw-byte-literal — test-only payload
    },
  });
  var copy = b.safeJson.jsonCopyUnderCap(live, { maxBytes: 65536 });                                  // allow:raw-byte-literal — test-only cap
  check("a getter is read once, and the caller is handed that reading",
        reads === 1 && JSON.stringify(copy) === '{"calls":["small"]}',
        JSON.stringify({ reads: reads, copy: copy }));
  check("reading the copy again cannot reach the getter",
        JSON.stringify(copy) === '{"calls":["small"]}' && reads === 1, String(reads));

  // Every shape that answers a second read differently is answered the same
  // way: by what its JSON form said the first time.
  var aliased = [];
  aliased.length = 2;
  aliased["1.0"] = { pad: "S".repeat(4096) };                                                         // allow:raw-byte-literal — test-only payload
  var aliasCopy = b.safeJson.jsonCopyUnderCap({ paths: aliased }, { maxBytes: 65536 });               // allow:raw-byte-literal — test-only cap
  check("a property named outside an array's elements is not in the copy",
        aliasCopy.paths["1.0"] === undefined && aliasCopy.paths.length === 2,
        JSON.stringify(aliasCopy));

  var withFunction = function () {};
  withFunction.payload = "x".repeat(4096);
  var funcCopy = b.safeJson.jsonCopyUnderCap({ blob: withFunction }, { maxBytes: 65536 });            // allow:raw-byte-literal — test-only cap
  check("a function member is not in the copy either",
        Object.keys(funcCopy).length === 0, JSON.stringify(funcCopy));

  var proxied = new Proxy({ a: 1 }, { get: function () { return "y"; } });
  check("a proxy is read through once and copied",
        JSON.stringify(b.safeJson.jsonCopyUnderCap({ p: proxied }, { maxBytes: 4096 })) ===           // allow:raw-byte-literal — test-only cap
        '{"p":{"a":"y"}}');

  var hiddenHolder = {};
  Object.defineProperty(hiddenHolder, "big", { enumerable: false, value: "x".repeat(4096) });
  check("a member that is not enumerable is not in the copy",
        Object.keys(b.safeJson.jsonCopyUnderCap(hiddenHolder, { maxBytes: 4096 })).length === 0);     // allow:raw-byte-literal — test-only cap

  // The values a document legitimately carries survive, as JSON.stringify
  // writes them. An earlier attempt at this refused a Date outright.
  var kept = b.safeJson.jsonCopyUnderCap(
    { when: new Date(0), nested: { a: [1, 2, { b: null }] }, n: -0, big: 1e21 },
    { maxBytes: 4096 });                                                                              // allow:raw-byte-literal — test-only cap
  check("an ordinary document keeps what JSON.stringify writes for it",
        kept.when === "1970-01-01T00:00:00.000Z" && kept.nested.a[2].b === null &&
        kept.n === 0 && kept.big === 1e21, JSON.stringify(kept));

  // A caller whose own layer refuses a prototype key by name needs the key to
  // reach it. Dropping it here answers the request with one member deleted and
  // the client told it succeeded, which is weaker than the refusal it replaced,
  // so `allowProto` carries the key through both halves of the copy. The copy
  // is still an ordinary object: JSON.parse writes `__proto__` as an own data
  // property, so nothing is assigned through the setter.
  var namedLikeTheProto =
    JSON.parse('{"__proto__":{"polluted":1},"constructor":"c","prototype":"p","ok":1}');
  var faithful = b.safeJson.jsonCopyUnderCap(namedLikeTheProto,
    { maxBytes: 4096, allowProto: true });                                                            // allow:raw-byte-literal — test-only cap
  check("allowProto carries __proto__, constructor and prototype into the copy",
        Object.prototype.hasOwnProperty.call(faithful, "__proto__") &&
        faithful.constructor === "c" && faithful.prototype === "p" && faithful.ok === 1,
        JSON.stringify(Object.keys(faithful)));
  check("and the copy's own prototype is untouched",
        Object.getPrototypeOf(faithful) === Object.prototype &&
        ({}).polluted === undefined && faithful.polluted === undefined);
  var stripped = b.safeJson.jsonCopyUnderCap(namedLikeTheProto, { maxBytes: 4096 });                   // allow:raw-byte-literal — test-only cap
  check("without it the copy drops them, as parse and stringify do",
        Object.keys(stripped).join(",") === "ok", JSON.stringify(Object.keys(stripped)));

  // Keeping the names a protocol admits is not the same as keeping the one
  // that moves a prototype. A caller that admits `constructor` and
  // `prototype` by name still has no use for `__proto__`, and handing it back
  // as an own key puts the request author in control of whatever the caller
  // merges it into. `refuseProtoMover` refuses the value instead.
  ["parse", "copy", "stringify"].forEach(function (route) {
    var threwMover = null;
    try {
      if (route === "parse") {
        b.safeJson.parse('{"__proto__":{"x":1},"ok":1}', { allowProto: true, refuseProtoMover: true });
      } else if (route === "copy") {
        b.safeJson.jsonCopyUnderCap(JSON.parse('{"__proto__":{"x":1},"ok":1}'),
          { maxBytes: 4096, allowProto: true, refuseProtoMover: true });                              // allow:raw-byte-literal — test-only cap
      } else {
        b.safeJson.stringify(JSON.parse('{"__proto__":{"x":1},"ok":1}'),
          { allowProto: true, refuseProtoMover: true });
      }
    } catch (e) { threwMover = e; }
    check("refuseProtoMover refuses a __proto__ key (" + route + ")",
          threwMover !== null && threwMover.code === "json/proto-key",
          JSON.stringify({ code: threwMover && threwMover.code }));
  });
  var keptSafe = b.safeJson.jsonCopyUnderCap(
    JSON.parse('{"constructor":"c","prototype":"p","nested":{"constructor":"d"},"ok":1}'),
    { maxBytes: 4096, allowProto: true, refuseProtoMover: true });                                    // allow:raw-byte-literal — test-only cap
  check("and it keeps the names that move nothing, at every depth",
        keptSafe.constructor === "c" && keptSafe.prototype === "p" &&
        keptSafe.nested.constructor === "d" && keptSafe.ok === 1,
        JSON.stringify(Object.keys(keptSafe)));
  // The option says it throws on a `__proto__` key, and says nothing about
  // needing `allowProto` alongside. `parse` stripped the key in its reviver
  // before the check could see it, so the same value and option threw through
  // `stringify` and passed through `parse`.
  var aloneThrew = null;
  try { b.safeJson.parse('{"__proto__":{"x":1},"ok":1}', { refuseProtoMover: true }); }
  catch (e) { aloneThrew = e; }
  check("refuseProtoMover fires without allowProto too",
        aloneThrew !== null && aloneThrew.code === "json/proto-key",
        JSON.stringify({ code: aloneThrew && aloneThrew.code }));
  var aloneStringify = null;
  try {
    b.safeJson.stringify(JSON.parse('{"__proto__":{"x":1},"ok":1}'), { refuseProtoMover: true });
  } catch (e) { aloneStringify = e; }
  check("and the two primitives answer the same value the same way",
        aloneStringify !== null && aloneStringify.code === "json/proto-key",
        JSON.stringify({ code: aloneStringify && aloneStringify.code }));

  // `onCircular: "replace"` builds its cycle-free copy before any of these
  // rules are read, and that copy is built by assignment, which for
  // `__proto__` runs the prototype setter instead of making an own key. The
  // refusal could not fire and the member was gone either way.
  var replaceThrew = null;
  try {
    var cyc = JSON.parse('{"__proto__":{"polluted":1},"ok":1}');
    cyc.self = cyc;
    b.safeJson.stringify(cyc, { onCircular: "replace", refuseProtoMover: true });
  } catch (e) { replaceThrew = e; }
  check("refuseProtoMover with onCircular replace is refused at the call",
        replaceThrew !== null &&
        (replaceThrew instanceof TypeError || replaceThrew.code === "json/proto-key"),
        JSON.stringify({ name: replaceThrew && replaceThrew.name,
                         code: replaceThrew && replaceThrew.code }));
  check("and nothing was polluted by the attempt", ({}).polluted === undefined);

  // The caps this primitive hands `stringify` go through `_capInt`, which
  // substitutes the default for anything that is not a non-negative finite
  // number. So the TypeError `stringify` raises for a mistyped cap could not
  // be reached through the primitive callers are told to use, and a cap read
  // from config or a computation silently became 1 MiB instead of failing at
  // the call site.
  [["maxBytes", "not-a-number"], ["maxBytes", -1], ["maxBytes", NaN],
   ["maxDepth", "3"], ["maxDepth", -2], ["maxDepth", Infinity]].forEach(function (c) {
    var opts = { maxBytes: 4096 };                                                                   // allow:raw-byte-literal — test-only cap
    opts[c[0]] = c[1];
    var threwCap = null;
    try { b.safeJson.jsonCopyUnderCap({ a: 1 }, opts); } catch (e) { threwCap = e; }
    check("jsonCopyUnderCap refuses a " + c[0] + " of " + String(c[1]),
          threwCap instanceof TypeError,
          JSON.stringify({ name: threwCap && threwCap.name,
                           message: threwCap && String(threwCap.message).slice(0, 60) }));
  });
  check("and a cap it can honor still works",
        b.safeJson.jsonCopyUnderCap({ a: 1 }, { maxBytes: 4096, maxDepth: 3 }).a === 1);            // allow:raw-byte-literal — test-only cap

  // A misspelled cap is the whole risk this primitive exists to remove, so it
  // is refused by name rather than falling through to the 1 MiB default, the
  // way `measureBytes` next to it already refused one.
  var wide = { pad: "x".repeat(900000) };                                                            // allow:raw-byte-literal — test-only payload
  var threwName = null;
  try { b.safeJson.jsonCopyUnderCap(wide, { maxBytess: 64 }); } catch (e) { threwName = e; }        // allow:raw-byte-literal — test-only cap
  check("jsonCopyUnderCap refuses a misspelled option by name",
        threwName !== null && threwName.code === "json/bad-opts" &&
        threwName.message.indexOf("maxBytess") !== -1,
        JSON.stringify({ code: threwName && threwName.code }));
  var threwReal = null;
  try { b.safeJson.jsonCopyUnderCap(wide, { maxBytes: 64 }); } catch (e) { threwReal = e; }         // allow:raw-byte-literal — test-only cap
  check("and the correctly spelled one refuses the value",
        threwReal !== null && threwReal.code === "json/too-large",
        JSON.stringify({ code: threwReal && threwReal.code }));

  // A consumer whose own documented cap is a byte count carries its member
  // cap with it, and then the copy serves what that consumer promised: the
  // default refused `b.mcp.parseRequest` bodies at a fraction of the 1 MiB
  // its documentation advertises, blaming the client's encoding.
  var manyKeys = {};
  for (var mk = 0; mk < 20000; mk += 1) manyKeys["k" + mk] = 1;                                     // allow:raw-byte-literal — test-only member count
  var wideCopy = null;
  try {
    wideCopy = b.safeJson.jsonCopyUnderCap(manyKeys,
      { maxBytes: b.constants.BYTES.mib(1), maxKeys: 250000 });                                     // allow:raw-byte-literal — test-only member cap
  } catch (e) { wideCopy = e; }
  check("a copy under the member cap its caller named is served whole",
        wideCopy !== null && !(wideCopy instanceof Error) &&
        Object.keys(wideCopy).length === 20000,                                                      // allow:raw-byte-literal — test-only member count
        JSON.stringify({ code: wideCopy && wideCopy.code }));
  var tightKeys = null;
  try { b.safeJson.jsonCopyUnderCap(manyKeys, { maxBytes: b.constants.BYTES.mib(1), maxKeys: 10 }); }
  catch (e) { tightKeys = e; }
  check("and a caller that names maxKeys still gets it",
        tightKeys !== null && tightKeys.code === "json/too-many-keys",
        JSON.stringify({ code: tightKeys && tightKeys.code }));

  // `stringifyForScript` turns each `<`, `>`, `&`, U+2028 and U+2029 into six
  // bytes AFTER the count, so a cap measured on the JSON it wrapped handed the
  // caller several times what it asked for.
  var scripty = { s: "<".repeat(100) };                                                             // allow:raw-byte-literal — test-only length
  var scriptEscapedBytes = Buffer.byteLength(b.safeJson.stringifyForScript(scripty), "utf8");
  var scriptPlainBytes = Buffer.byteLength(b.safeJson.stringify(scripty), "utf8");
  var threwScript = null;
  try { b.safeJson.stringifyForScript(scripty, { maxBytes: scriptPlainBytes }); }
  catch (e) { threwScript = e; }
  check("stringifyForScript measures the cap against the form it returns",
        scriptEscapedBytes > scriptPlainBytes && threwScript !== null &&
        threwScript.code === "json/too-large",
        JSON.stringify({ plain: scriptPlainBytes, escaped: scriptEscapedBytes,
                         code: threwScript && threwScript.code }));
  check("and it still returns the escaped form when that fits",
        Buffer.byteLength(b.safeJson.stringifyForScript(
          scripty, { maxBytes: scriptEscapedBytes }), "utf8") === scriptEscapedBytes);

  // A value with no JSON form leaves `stringify` returning undefined, and the
  // cap check measured that as though it were the string. Whether the cap is
  // named decides between a returned undefined and a TypeError out of the byte
  // counter, on a value the caller cannot see is different.
  [["undefined", undefined], ["a function", function () {}], ["a symbol", Symbol("s")]]
    .forEach(function (pair) {
      var uncapped, capped, threwRootless = null;
      uncapped = b.safeJson.stringifyForScript(pair[1]);
      try { capped = b.safeJson.stringifyForScript(pair[1], { maxBytes: 100 }); }                     // allow:raw-byte-literal — test-only cap
      catch (e) { threwRootless = e; }
      check("a cap does not change what stringifyForScript does with " + pair[0],
            uncapped === undefined && threwRootless === null && capped === undefined,
            JSON.stringify({ uncapped: String(uncapped),
                             threw: threwRootless && threwRootless.message }));
    });

  // The two options are documented side by side, and the cap is measured on
  // the finished string, which already carries the newlines and padding.
  var pretty = null, threwPretty = null;
  try { pretty = b.safeJson.stringifyForScript({ a: "</script>" }, { indent: 2, maxBytes: 4096 }); }  // allow:raw-byte-literal — test-only cap
  catch (e) { threwPretty = e; }
  check("stringifyForScript accepts indent together with its own maxBytes",
        threwPretty === null && typeof pretty === "string" &&
        pretty.indexOf("\n") !== -1 && pretty.indexOf("</script>") === -1,
        JSON.stringify({ threw: threwPretty && threwPretty.message, pretty: pretty }));
  var threwPrettyCap = null;
  try { b.safeJson.stringifyForScript({ a: "</script>" }, { indent: 2, maxBytes: 8 }); }              // allow:raw-byte-literal — test-only cap
  catch (e) { threwPrettyCap = e; }
  check("and the cap still bounds the indented form",
        threwPrettyCap !== null && threwPrettyCap.code === "json/too-large",
        JSON.stringify({ code: threwPrettyCap && threwPrettyCap.code }));
  // A cap that is not a number compares false against every size, so a
  // computed or configured one that came out wrong is no cap at all. The
  // indented form takes the cap out of the options `stringify` checks, so
  // this has to be checked before it is taken out, not after.
  [["NaN", NaN], ["a string", "4096"], ["negative", -1], ["null", null]].forEach(function (pair) {
    ["with indent", "without indent"].forEach(function (shape) {
      var opts = { maxBytes: pair[1] };
      if (shape === "with indent") opts.indent = 2;                                                   // allow:raw-byte-literal — test-only indent
      var threwCap = null;
      try { b.safeJson.stringifyForScript({ a: "abc" }, opts); } catch (e) { threwCap = e; }
      check("stringifyForScript refuses a maxBytes of " + pair[0] + " " + shape,
            threwCap instanceof TypeError &&
            /maxBytes must be a non-negative finite number/.test(threwCap.message),
            JSON.stringify({ threw: threwCap && threwCap.message }));
    });
  });

  // The gate's own message says the JSON form must be an object, and
  // `typeof [] === "object"`, so a top-level array walked through a refusal
  // written to stop exactly that.
  ["[]", "[1,2]"].forEach(function (text) {
    var threwArr = null;
    try { b.safeJson.parseStringOrObject(text); } catch (e) { threwArr = e; }
    check("parseStringOrObject refuses a top-level array as text: " + text,
          threwArr !== null && threwArr.code === "json/wrong-input-type",
          JSON.stringify({ code: threwArr && threwArr.code }));
  });
  var threwArrObj = null;
  try { b.safeJson.parseStringOrObject([1, 2]); } catch (e) { threwArrObj = e; }
  check("and refuses one handed over pre-parsed",
        threwArrObj !== null && threwArrObj.code === "json/wrong-input-type",
        JSON.stringify({ code: threwArrObj && threwArrObj.code }));

  // `parse` and `jsonCopyUnderCap` are the two halves of reading one body:
  // one for the text a transport carries, one for the object a body-parser
  // hands on. A caller who names no number has to get the same bound from
  // both, and they disagreed on how many members one object may carry —
  // 10,000 for the text, a million for the object — so the same body was
  // served or refused by the form it arrived in. Named on the two primitives
  // rather than on one of their callers: every dual-form consumer inherits
  // the answer from here.
  var atDefault = {}, overDefault = {};
  for (var dk = 0; dk < b.safeJson.DEFAULT_MAX_KEYS; dk += 1) {
    atDefault["k" + dk] = 1;
    overDefault["k" + dk] = 1;
  }
  overDefault.oneMore = 1;
  function _codeOfBoth(value) {
    var text = JSON.stringify(value);
    function outcome(fn) {
      try { fn(); return null; } catch (e) { return (e && e.code) || String(e); }
    }
    return {
      parse: outcome(function () { b.safeJson.parse(text, { maxBytes: b.constants.BYTES.mib(8) }); }),
      copy:  outcome(function () {
        b.safeJson.jsonCopyUnderCap(value, { maxBytes: b.constants.BYTES.mib(8) });
      }),
    };
  }
  var atBoth = _codeOfBoth(atDefault);
  var overBoth = _codeOfBoth(overDefault);
  check("parse and jsonCopyUnderCap serve the same object at the default key cap",
        atBoth.parse === null && atBoth.copy === null, JSON.stringify(atBoth));
  check("and refuse the same object one member past it",
        overBoth.parse === "json/too-many-keys" && overBoth.copy === "json/too-many-keys",
        JSON.stringify(overBoth));

  // `parseStringOrObject` is where that pairing is consumed: it routes text
  // through `parse` and an object through `jsonCopyUnderCap`, so a caller who
  // never chose a number got whichever of the two the form happened to reach.
  var wideMembers = {};
  for (var wi = 0; wi < 20000; wi += 1) wideMembers["k" + wi] = 1;                                    // allow:raw-byte-literal — test-only member count
  var wideMembersText = JSON.stringify(wideMembers);
  function _readBothWays(opts) {
    var answers = ["text", "pre-parsed"].map(function (form) {
      try {
        var got = b.safeJson.parseStringOrObject(
          form === "text" ? wideMembersText : wideMembers, opts);
        return { ok: true, keys: Object.keys(got).length };
      } catch (e) { return { ok: false, code: e && e.code }; }
    });
    return { text: answers[0], object: answers[1] };
  }
  var unnamed = _readBothWays({ maxBytes: b.constants.BYTES.mib(1) });
  check("parseStringOrObject answers a wide object the same in both forms",
        unnamed.text.ok === unnamed.object.ok && unnamed.text.code === unnamed.object.code,
        JSON.stringify(unnamed));
  check("and with no number named it takes the stricter of the two",
        unnamed.text.ok === false && unnamed.text.code === "json/too-many-keys",
        JSON.stringify(unnamed));
  var named = _readBothWays({ maxBytes: b.constants.BYTES.mib(1), maxKeys: 50000 });                  // allow:raw-byte-literal — test-only member cap
  check("and a caller that names one gets it on both",
        named.text.ok === true && named.object.ok === true &&
        named.text.keys === 20000 && named.object.keys === 20000,                                     // allow:raw-byte-literal — test-only member count
        JSON.stringify(named));

  var deepMover = null;
  try {
    b.safeJson.parse('{"a":{"b":[{"__proto__":{"x":1}}]}}',
      { allowProto: true, refuseProtoMover: true });
  } catch (e) { deepMover = e; }
  check("and it finds one nested inside an array",
        deepMover !== null && deepMover.code === "json/proto-key",
        JSON.stringify({ code: deepMover && deepMover.code }));

  // Over the cap, and refused while it is being written rather than after:
  // a getter is free to answer with a gigabyte however small the value
  // looked beforehand, and the refusal must not wait for that to be built.
  var runaway = {};
  Object.defineProperty(runaway, "k", {
    enumerable: true,
    get: function () { return "x".repeat(32 * 1024 * 1024); },                                        // allow:raw-byte-literal — test-only payload
  });
  var overThrew = null;
  try { b.safeJson.jsonCopyUnderCap(runaway, { maxBytes: 1024 }); }                                   // allow:raw-byte-literal — test-only cap
  catch (e) { overThrew = e; }
  check("a value whose form runs past the cap is refused",
        overThrew !== null && overThrew.code === "json/too-large",
        JSON.stringify({ code: overThrew && overThrew.code }));

  // Refused while it is being written, not after. A wall-clock reading would
  // pass on a fast machine whatever the code did, so the assertion is on how
  // much of the value was reached: each element answers when it is read, and
  // an unbounded write reads all ten thousand.
  var touched = 0;
  var manyBig = [];
  for (var big = 0; big < 10000; big += 1) {                                                          // allow:raw-byte-literal — test-only element count
    Object.defineProperty(manyBig, String(big), {
      enumerable: true, configurable: true,
      get: function () { touched += 1; return "x".repeat(256); },                                     // allow:raw-byte-literal — test-only payload
    });
  }
  manyBig.length = 10000;                                                                             // allow:raw-byte-literal — test-only element count
  var earlyThrew = null;
  try { b.safeJson.jsonCopyUnderCap(manyBig, { maxBytes: 4096 }); }                                   // allow:raw-byte-literal — test-only cap
  catch (e) { earlyThrew = e; }
  check("a runaway array is refused",
        earlyThrew !== null && earlyThrew.code === "json/too-large",
        JSON.stringify({ code: earlyThrew && earlyThrew.code }));
  check("and only the elements the cap paid for were read",
        touched > 0 && touched < 40, String(touched));

  // The cap is the number it says it is, in both directions. The count taken
  // while writing charges each member the FEWEST bytes it can occupy, so a
  // document under the cap is never refused by it: an earlier attempt billed
  // eight bytes plus an index string for every array element and refused
  // bodies at a third of their published cap.
  var numbers = [];
  for (var n = 0; n < 2000; n += 1) numbers.push(n % 10);                                             // allow:raw-byte-literal — test-only element count
  var exact = Buffer.byteLength(JSON.stringify({ n: numbers }), "utf8");
  check("a document at exactly its own size is served",
        b.safeJson.jsonCopyUnderCap({ n: numbers }, { maxBytes: exact }).n.length === 2000,           // allow:raw-byte-literal — test-only element count
        String(exact));
  var oneUnder = null;
  try { b.safeJson.jsonCopyUnderCap({ n: numbers }, { maxBytes: exact - 1 }); }
  catch (e) { oneUnder = e; }
  check("and one byte under it is refused",
        oneUnder !== null && oneUnder.code === "json/too-large",
        JSON.stringify({ code: oneUnder && oneUnder.code }));

  // Escaping makes a string cost more than its characters, and the finished
  // form is what the cap is held against, so the count taken while writing
  // cannot be the last word.
  var escaped = { s: "\u0001".repeat(500) };                                                          // allow:raw-byte-literal — test-only length
  var escapedBytes = Buffer.byteLength(JSON.stringify(escaped), "utf8");
  var escapedThrew = null;
  try { b.safeJson.jsonCopyUnderCap(escaped, { maxBytes: 1000 }); }                                   // allow:raw-byte-literal — test-only cap
  catch (e) { escapedThrew = e; }
  check("a string whose escaped form is over the cap is refused",
        escapedBytes > 1000 && escapedThrew !== null &&                                               // allow:raw-byte-literal — test-only cap
        escapedThrew.code === "json/too-large",
        JSON.stringify({ escapedBytes: escapedBytes, code: escapedThrew && escapedThrew.code }));
  check("and served once the cap covers that form",
        b.safeJson.jsonCopyUnderCap(escaped, { maxBytes: escapedBytes }).s.length === 500);           // allow:raw-byte-literal — test-only length

  // A raw-JSON member writes its own text, so it is counted by that text
  // rather than as one more object.
  var rawThrew = null;
  try {
    b.safeJson.jsonCopyUnderCap({ r: JSON.rawJSON('"' + "x".repeat(5000) + '"') },                    // allow:raw-byte-literal — test-only length
                                { maxBytes: 1000 });                                                  // allow:raw-byte-literal — test-only cap
  } catch (e) { rawThrew = e; }
  check("a raw-JSON member is counted by what it writes",
        rawThrew !== null && rawThrew.code === "json/too-large",
        JSON.stringify({ code: rawThrew && rawThrew.code }));

  // The count is a lower bound only if it charges for what is written and
  // nothing else. A document whose form is exactly the cap is served: an
  // earlier count billed three bytes for the root's key, which is never
  // written, and refused `{"a":"xxxx"}` at twelve.
  [{}, { a: "xxxx" }, { a: 1, b: 2 }, [1, 2, 3], "hello", 12345].forEach(function (value) {
    var exactBytes = Buffer.byteLength(JSON.stringify(value), "utf8");
    var servedAtExact = null;
    try { servedAtExact = b.safeJson.jsonCopyUnderCap(value, { maxBytes: exactBytes }); }
    catch (e) { servedAtExact = e; }
    check("a value whose form is exactly the cap is served: " + JSON.stringify(value),
          JSON.stringify(servedAtExact) === JSON.stringify(value),
          JSON.stringify({ bytes: exactBytes, got: servedAtExact }));
  });

  // The count is what stops a value that runs away, so the string it stops at
  // is the bound a caller gets. Separators were not counted at all and a
  // member `JSON.stringify` writes as `null` inside an ARRAY was charged one
  // byte for four, so a value made of them returned a string several times the
  // cap: `jsonCopyUnderCap` caught it on the finished string, but only after
  // that string had been built, which is the peak the cap is there to bound.
  [
    { name: "dropped array elements", value: new Array(4000).fill(undefined) },                       // allow:raw-byte-literal — test-only element count
    { name: "false",                  value: new Array(4000).fill(false) },                           // allow:raw-byte-literal — test-only element count
    { name: "empty objects",          value: new Array(4000).fill({}) },                              // allow:raw-byte-literal — test-only element count
    { name: "short strings",          value: new Array(4000).fill("ab") },                            // allow:raw-byte-literal — test-only element count
    { name: "object members",         value: (function () {
        var o = {};
        for (var m = 0; m < 4000; m += 1) o["k" + m] = false;                                         // allow:raw-byte-literal — test-only member count
        return o;
      }()) },
  ].forEach(function (shape) {
    var CAP = 4096;                                                                                   // allow:raw-byte-literal — test-only cap
    var text = null;
    try { text = b.safeJson.stringify(shape.value, { maxBytes: CAP }); }
    catch (e) { text = e && e.code === "json/too-large" ? "" : e; }
    check("stringify never returns more than maxBytes: " + shape.name,
          typeof text === "string" && Buffer.byteLength(text, "utf8") <= CAP,
          JSON.stringify({ got: typeof text === "string" ? Buffer.byteLength(text, "utf8") : text,
                           cap: CAP }));
  });

  // An option this primitive once read and no longer does is refused by name.
  // `followToJson: false` used to make the count skip a `toJSON` hook, for a
  // caller sizing the work it was about to do rather than the JSON it was
  // about to write; that job belongs to `jsonCopyUnderCap` now. Accepting the
  // option and ignoring it answers such a caller with a number about a
  // different value: measured, a 2 MB payload behind a hook counted as 11
  // bytes with nothing to distinguish that from a caller who never passed it.
  var threwOpt = null;
  try { b.safeJson.measureBytes({ a: 1 }, { followToJson: false }); }
  catch (e) { threwOpt = e; }
  check("measureBytes refuses an option it no longer honors, by name",
        threwOpt !== null && threwOpt.code === "json/bad-opts" &&
        threwOpt.message.indexOf("followToJson") !== -1,
        JSON.stringify({ code: threwOpt && threwOpt.code,
                         message: threwOpt && threwOpt.message }));
  check("and the options it does honor are unaffected",
        b.safeJson.measureBytes({ a: 1 }, { limit: 4096, maxDepth: 5 }).bytes === 7);          // allow:raw-byte-literal — test-only cap

  // `JSON.rawJSON` holds the verbatim text `JSON.stringify` emits, and that
  // text is written as UTF-8. Counting its UTF-16 code units charges one for a
  // character that occupies three, which is the same question `measureBytes`
  // answers in bytes one screen away.
  var rawWide = { r: JSON.rawJSON('"' + "€".repeat(2000) + '"') };                               // allow:raw-byte-literal — test-only length
  var rawWideBytes = Buffer.byteLength(JSON.stringify(rawWide), "utf8");
  var rawWideText = null;
  try { rawWideText = b.safeJson.stringify(rawWide, { maxBytes: rawWideBytes - 1 }); }
  catch (e) { rawWideText = e && e.code === "json/too-large" ? "" : e; }
  check("a raw-JSON member is charged the bytes its text occupies",
        rawWideText === "",
        JSON.stringify({ wrote: typeof rawWideText === "string" ? rawWideText.length : rawWideText,
                         cap: rawWideBytes - 1 }));
  check("and the same member at exactly its size is still written",
        b.safeJson.stringify(rawWide, { maxBytes: rawWideBytes }) === JSON.stringify(rawWide));

  // `JSON.stringify` drops an undefined, function or symbol member of an
  // OBJECT and writes `null` for one inside an ARRAY. The array form is
  // written, so it sits at a nesting level, and `parse` refuses the identical
  // text at that depth.
  [["[undefined]", [undefined], 0], ["[[[undefined]]]", [[[undefined]]], 2]].forEach(function (c) {
    var threwDeep = null;
    try { b.safeJson.stringify(c[1], { maxDepth: c[2] }); }
    catch (e) { threwDeep = e; }
    check("a member an array writes as null is held to maxDepth: " + c[0],
          threwDeep !== null && threwDeep.code === "json/too-deep",
          JSON.stringify({ code: threwDeep && threwDeep.code }));
  });
  check("while the same member in an OBJECT is dropped, so it is no level at all",
        b.safeJson.stringify({ a: undefined }, { maxDepth: 0 }) === "{}");

  // And a value that fits is still served whole, so the separator charge did
  // not become an over-charge.
  [[1, 2, 3], { a: 1, b: 2 }, [false, null, true], [], {}, [[], {}], ["a", "bb"]].forEach(
    function (fits) {
      var exact = Buffer.byteLength(JSON.stringify(fits), "utf8");
      var served = null;
      try { served = b.safeJson.stringify(fits, { maxBytes: exact }); }
      catch (e) { served = e; }
      check("a value whose form is exactly the cap is written: " + JSON.stringify(fits),
            served === JSON.stringify(fits), JSON.stringify({ bytes: exact, got: served }));
    });

  // And `JSON.stringify` drops an object member whose value is undefined, a
  // function or a symbol, so those cost nothing: charging for them turned a
  // sixty-eight byte envelope into a refusal under a one-megabyte cap.
  var sparseObject = { a: 1 };
  for (var u = 0; u < 20000; u += 1) sparseObject["unset-" + u] = undefined;                          // allow:raw-byte-literal — test-only member count
  check("members JSON.stringify drops are not charged",
        JSON.stringify(b.safeJson.jsonCopyUnderCap(sparseObject, { maxBytes: 64 })) ===              // allow:raw-byte-literal — test-only cap
        '{"a":1}',
        JSON.stringify(Buffer.byteLength(JSON.stringify(sparseObject), "utf8")));

  // Indentation writes a newline and a level of padding per member, and how
  // much padding depends on a nesting depth the count does not see: at ten
  // spaces a hundred levels deep the abort came a megabyte late. A cap that
  // cannot bound the string is refused at the call instead.
  var nested = [];
  var tip = nested;
  for (var deep = 0; deep < 100; deep += 1) { var below = []; tip.push(below); tip = below; }        // allow:raw-byte-literal — test-only depth
  for (var leaf = 0; leaf < 2000; leaf += 1) tip.push(leaf);                                         // allow:raw-byte-literal — test-only element count
  var indentThrew = null;
  try { b.safeJson.stringify(nested, { maxBytes: 1024, indent: 10 }); }                              // allow:raw-byte-literal — test-only cap
  catch (e) { indentThrew = e; }
  check("a cap cannot be combined with indentation",
        indentThrew instanceof TypeError, String(indentThrew && indentThrew.name));
  check("and the same value without indentation is written",
        typeof b.safeJson.stringify(nested) === "string");
  check("while the cap alone still refuses it",
        _thrown(function () { b.safeJson.stringify(nested, { maxBytes: 1024 }); })                   // allow:raw-byte-literal — test-only cap
          .code === "json/too-large");

  // A member JSON.stringify drops is not a level of nesting, because it is
  // not in the document being measured. Counting it made the object form of
  // a document one level stricter than the same document as text, so the
  // two ways in disagreed about a spec whose deepest member was left unset.
  check("a dropped member is not a level of nesting",
        JSON.stringify(b.safeJson.jsonCopyUnderCap({ a: { b: undefined } },
                                                   { maxBytes: 100, maxDepth: 1 })) ===             // allow:raw-byte-literal — test-only cap
        JSON.stringify(b.safeJson.parse('{"a":{}}', { maxDepth: 1 })));
  check("and a level that IS written is still counted",
        _thrown(function () {
          b.safeJson.jsonCopyUnderCap({ a: { b: { c: 1 } } }, { maxBytes: 100, maxDepth: 1 });      // allow:raw-byte-literal — test-only cap
        }).code === "json/too-deep");

  // A value nested deeper than the copy allows is refused where it is met.
  // Serializing it first put the whole descent on the JavaScript stack, and
  // a twenty-thousand-deep value died of stack exhaustion reported as
  // json/stringify before the depth cap was ever consulted.
  var chain = {};
  var link = chain;
  for (var rung = 0; rung < 20000; rung += 1) { link.n = {}; link = link.n; }                        // allow:raw-byte-literal — test-only depth
  var deepThrown = _thrown(function () {
    b.safeJson.jsonCopyUnderCap(chain, { maxBytes: 1024 * 1024 });                                   // allow:raw-byte-literal — test-only cap
  });
  check("a value nested past the copy's depth is refused as too deep",
        deepThrown && deepThrown.code === "json/too-deep",
        JSON.stringify({ code: deepThrown && deepThrown.code }));

  // `JSON.stringify` writes `null` for a number that is not finite, so those
  // cost four bytes and not the eight or nine their text would: charging the
  // text refused a document at sixty percent of its own cap.
  [{ a: Infinity }, { a: -Infinity }, { a: NaN }, { a: [Infinity, NaN] }].forEach(function (v) {
    var formBytes = Buffer.byteLength(JSON.stringify(v), "utf8");
    var served = null;
    try { served = b.safeJson.jsonCopyUnderCap(v, { maxBytes: formBytes }); }
    catch (e) { served = e; }
    check("a non-finite number costs what null costs: " + JSON.stringify(v),
          JSON.stringify(served) === JSON.stringify(v),
          JSON.stringify({ bytes: formBytes, got: served }));
  });

  // The other members each cost what their shortest form costs, so the count
  // stays close to the string being written rather than admitting several
  // times the cap before the refusal: `true` and `null` write four bytes, an
  // empty object two, and a boxed primitive writes the primitive.
  [{ a: true }, { a: false }, { a: null }, { a: {} }, { a: [] },
   { a: new String("hello") }, { a: new Number(1234) }].forEach(function (v) {                        // allow:raw-byte-literal — test-only values
    var formBytes = Buffer.byteLength(JSON.stringify(v), "utf8");
    var served = null;
    try { served = b.safeJson.jsonCopyUnderCap(v, { maxBytes: formBytes }); }
    catch (e) { served = e; }
    check("a member costs its shortest form: " + JSON.stringify(v),
          JSON.stringify(served) === JSON.stringify(v),
          JSON.stringify({ bytes: formBytes, got: served }));
  });
  var wrapperThrew = null;
  try {
    b.safeJson.jsonCopyUnderCap({ a: new String("x".repeat(8192)) }, { maxBytes: 1024 });            // allow:raw-byte-literal — test-only cap
  } catch (e) { wrapperThrew = e; }
  check("and a boxed primitive past the cap is refused for what it writes",
        wrapperThrew !== null && wrapperThrew.code === "json/too-large",
        JSON.stringify({ code: wrapperThrew && wrapperThrew.code }));

  // A cap that is not a number is a mistake at the call site, not a value to
  // guess at, so it is refused there, and so is a cap beside an option that
  // does work before the count can begin.
  [-1, NaN, Infinity, "1024", null].forEach(function (bad) {
    var badThrew = null;
    try { b.safeJson.stringify({ a: 1 }, { maxBytes: bad }); }
    catch (e) { badThrew = e; }
    check("stringify refuses maxBytes " + String(bad),
          badThrew instanceof TypeError, String(badThrew && badThrew.name));
    var badDepth = null;
    try { b.safeJson.stringify({ a: 1 }, { maxDepth: bad }); }
    catch (e) { badDepth = e; }
    check("stringify refuses maxDepth " + String(bad),
          badDepth instanceof TypeError, String(badDepth && badDepth.name));
  });
  ["maxBytes", "maxDepth"].forEach(function (capName) {
    var opts = { onCircular: "replace" };
    opts[capName] = 100;                                                                             // allow:raw-byte-literal — test-only cap
    var comboThrew = null;
    try { b.safeJson.stringify({ a: 1 }, opts); }
    catch (e) { comboThrew = e; }
    check("a cycle-replacing stringify refuses " + capName,
          comboThrew instanceof TypeError, String(comboThrew && comboThrew.name));
  });
  var cyclic = { name: "root" };
  cyclic.self = cyclic;
  check("and cycle replacement alone still works",
        b.safeJson.stringify(cyclic, { onCircular: "replace" }) ===
        '{"name":"root","self":"[Circular]"}');

  // The copy is built by parse, so the caps that apply to a body arriving as
  // text apply to one arriving decoded.
  var poisoned = JSON.parse('{"__proto__":{"x":1},"a":1}');
  var cleaned = b.safeJson.jsonCopyUnderCap(poisoned, { maxBytes: 4096 });                            // allow:raw-byte-literal — test-only cap
  check("a poisoned key does not survive the copy",
        cleaned.a === 1 && !Object.prototype.hasOwnProperty.call(cleaned, "__proto__"),
        JSON.stringify(Object.keys(cleaned)));
  var deepThrew = null;
  try {
    b.safeJson.jsonCopyUnderCap({ a: { b: { c: { d: 1 } } } }, { maxBytes: 4096, maxDepth: 2 });      // allow:raw-byte-literal — test-only cap
  } catch (e) { deepThrew = e; }
  check("and maxDepth applies to it as it does to a string body",
        deepThrew !== null && deepThrew.code === "json/too-deep",
        JSON.stringify({ code: deepThrew && deepThrew.code }));
}

function testMeasureBytes() {
  // The count is a claim about what JSON.stringify writes, so every case is
  // read off JSON.stringify rather than off a number written here by hand.
  // A hook that reports one size and a serializer that writes another is how
  // a byte cap admits a body past it.
  var cases = [
    ["a small object",                  { a: 1 }],
    ["a mixed nesting",                 { a: [1, "two", null, true], b: { c: -1.5 } }],
    ["a bare string",                   "hello"],
    ["a multi-byte string",             "é中😀"],
    ["a lone high surrogate",           "\ud800"],
    ["every short escape",              "\b\t\n\f\r\"\\"],
    ["a control character",             "\u0001"],
    ["DEL, which JSON leaves raw",      "\u007f"],
    ["a negative exponent",             1e-7],
    ["a large exponent",                1e21],
    ["negative zero",                   -0],
    ["NaN",                             NaN],
    ["Infinity",                        Infinity],
    ["an empty array",                  []],
    ["an empty object",                 {}],
    ["an array hole",                   [, 1]],                                                      // eslint-disable-line no-sparse-arrays
    ["an array of dropped values",      [undefined, function () {}, Symbol("s")]],
    ["an object of dropped values",     { a: undefined, b: function () {}, c: Symbol("s"), d: 1 }],
    ["a Date, which carries toJSON",    { when: new Date(0) }],
    ["a boxed Number",                  { a: new Number(123456789) }],
    ["a boxed String",                  { a: new String("hello") }],
    ["a boxed Boolean",                 { a: new Boolean(false) }],
    ["a boxed String in an array",      [new String("hi")]],
    ["a toJSON reading its key",        { a: { toJSON: function (k) { return k === "a" ? "long value" : "x"; } } }],
    ["a toJSON returning a toJSON",     { a: { toJSON: function () { return { pad: "x".repeat(100), toJSON: function () { return 0; } }; } } }],
    ["a toJSON returning undefined",    { a: { toJSON: function () { return undefined; } }, b: 1 }],
    ["a toJSON inside an array",        [{ toJSON: function (k) { return k; } }, { toJSON: function (k) { return k; } }]],
    ["a key needing an escape",         { "a\"b\nc": 1 }],
    ["a multi-byte key",                { "é": 1 }],
    // Symbol.toStringTag is writable, so a value can name itself "Number"
    // while holding a kilobyte of string. Reading the tag rather than the
    // internal slot measured that as the four bytes of NaN.
    ["an object claiming to be Number", { pad: "x".repeat(1000), [Symbol.toStringTag]: "Number" }],
    ["an object claiming to be String", { pad: "x".repeat(1000), [Symbol.toStringTag]: "String" }],
    ["an object claiming to be BigInt", { pad: "x".repeat(16), [Symbol.toStringTag]: "BigInt" }],
    ["a null-prototype object",         Object.assign(Object.create(null), { a: 1 })],
    // JSON.stringify unboxes a wrapper with ToString / ToNumber, which run the
    // overridable coercion. Reading the internal slot instead measured the
    // original three bytes for a wrapper that serializes a kilobyte.
    ["a boxed String overriding toString",
      Object.assign(new String("x"), { toString: function () { return "y".repeat(1000); } })],
    ["a boxed Number overriding valueOf",
      Object.assign(new Number(1), { valueOf: function () { return 123456789012; } })],
    ["a boxed Number coercing to NaN",
      Object.assign(new Number(1), { valueOf: function () { return NaN; } })],
    ["a boxed Boolean overriding toString",
      Object.assign(new Boolean(true), { toString: function () { return "z".repeat(50); } })],
    ["a boxed Boolean overriding valueOf",
      Object.assign(new Boolean(false), { valueOf: function () { return true; } })],
    // A wrapper keeps its internal slot when its prototype is replaced, so a
    // prototype-shaped shortcut walked these as ordinary objects.
    ["a re-prototyped boxed Number",    Object.setPrototypeOf(new Number(5), Object.prototype)],
    ["a re-prototyped boxed String",    Object.setPrototypeOf(new String("abc"), Object.prototype)],
    ["a null-prototype boxed Boolean",  Object.setPrototypeOf(new Boolean(true), null)],
    // JSON.rawJSON holds a literal that JSON.stringify writes verbatim.
    // Walking it as an ordinary object counted its wrapper property instead,
    // which refused a value that fits.
    ["a rawJSON literal",               { n: JSON.rawJSON("12345678901234567890") }],
    ["a bare rawJSON literal",          JSON.rawJSON("12345678901234567890")],
    ["a rawJSON string literal",        { s: JSON.rawJSON("\"hello\"") }],
    ["a rawJSON in an array",           [JSON.rawJSON("1"), JSON.rawJSON("2")]],
  ];
  cases.forEach(function (row) {
    var expected = Buffer.byteLength(JSON.stringify(row[1]), "utf8");
    var actual   = b.safeJson.measureBytes(row[1]).bytes;
    check("measureBytes matches JSON.stringify for " + row[0],
          actual === expected, "measured " + actual + ", stringify " + expected);
  });

  // JSON.stringify reads toJSON once and calls what that read returned. An
  // accessor handing out a large serializer first and a small one after
  // reported the small one's size, so each side gets its own instance and
  // both see the first read.
  function accessorHook() {
    var served = 0;
    return Object.defineProperty({}, "toJSON", {
      get: function () {
        served += 1;
        var length = served === 1 ? 1000 : 1;
        return function () { return "q".repeat(length); };
      },
    });
  }
  check("measureBytes reads a toJSON accessor once, as JSON.stringify does",
        b.safeJson.measureBytes(accessorHook()).bytes ===
        Buffer.byteLength(JSON.stringify(accessorHook()), "utf8"),
        String(b.safeJson.measureBytes(accessorHook()).bytes));

  // A value JSON.stringify cannot serialize is one measureBytes cannot size.
  // A boxed Number whose valueOf hands back a BigInt is the case: reading it
  // through a conversion that accepts a BigInt reported a size for a value
  // that has none, and the cap then admitted it.
  [
    ["a boxed Number whose valueOf returns a BigInt",
      Object.assign(new Number(1), { valueOf: function () { return BigInt(1); } })],
    ["a boxed String whose toString returns a symbol",
      Object.assign(new String("x"), { toString: function () { return Symbol("q"); } })],
    ["a toJSON that throws",
      { a: { toJSON: function () { throw new RangeError("no"); } } }],
  ].forEach(function (row) {
    var stringifyThrew = false, measureThrew = false;
    try { JSON.stringify(row[1]); } catch (_s) { stringifyThrew = true; }
    try { b.safeJson.measureBytes(row[1]); } catch (_m) { measureThrew = true; }
    check("measureBytes refuses " + row[0] + " exactly as JSON.stringify does",
          stringifyThrew === true && measureThrew === true,
          JSON.stringify({ stringifyThrew: stringifyThrew, measureThrew: measureThrew }));
  });

  check("measureBytes counts a value JSON drops at the top as zero",
        b.safeJson.measureBytes(undefined).bytes === 0);
  check("measureBytes counts a function at the top as zero",
        b.safeJson.measureBytes(function () {}).bytes === 0);

  var hidden = { pad: "x".repeat(4096), toJSON: function () { return {}; } };
  check("the count follows toJSON, as JSON.stringify does",
        b.safeJson.measureBytes(hidden).bytes ===
        Buffer.byteLength(JSON.stringify(hidden), "utf8"));

  // The cost follows the cap rather than the value. A wall-clock reading
  // would pass whatever the walk did, since even an unbounded one finishes
  // in tens of milliseconds here, so the assertion is on how far into the
  // value it reached: each element answers when it is read.
  var reached = 0;
  var manyRead = [];
  for (var m = 0; m < 20000; m += 1) {                                                                // allow:raw-byte-literal — test-only element count
    Object.defineProperty(manyRead, String(m), {
      enumerable: true, configurable: true,
      get: function () { reached += 1; return "abcdefgh"; },
    });
  }
  manyRead.length = 20000;                                                                            // allow:raw-byte-literal — test-only element count
  var capped = b.safeJson.measureBytes(manyRead, { limit: 4096 });                                    // allow:raw-byte-literal — test-only cap
  check("a twenty-thousand-element array under a small cap stops at the cap",
        capped.exceeded === true, JSON.stringify(capped));
  check("and it read only the elements the cap paid for",
        reached > 0 && reached < 1000, String(reached));

  // A caller's limit is the caller's, not silently lowered to the parse
  // ceiling: b.guardJmap publishes its profile's maxSizeRequest to clients,
  // so a clamp here would refuse a body the published number admits.
  check("measureBytes honors a limit above the parse ceiling",
        b.safeJson.measureBytes({ pad: "x".repeat(4096) },
          { limit: b.safeJson.ABSOLUTE_MAX_BYTES * 2 }).exceeded === false);

  var big = b.safeJson.measureBytes({ pad: "x".repeat(4096) }, { limit: 128 });
  check("measureBytes stops at the limit", big.exceeded === true);
  check("measureBytes reports a lower bound once it stops", big.bytes >= 128);
  check("measureBytes stops inside one long string too",
        b.safeJson.measureBytes("x".repeat(4096), { limit: 128 }).exceeded === true);

  var cyclic = { name: "root" };
  cyclic.self = cyclic;
  check("measureBytes throws json/circular on a cycle",
        _code(function () { b.safeJson.measureBytes(cyclic); }) === "json/circular");

  check("measureBytes throws json/wrong-input-type on a BigInt",
        _code(function () { b.safeJson.measureBytes({ a: BigInt(1) }); }) === "json/wrong-input-type");
  check("measureBytes throws on a boxed BigInt as JSON.stringify does",
        _code(function () { b.safeJson.measureBytes({ a: Object(BigInt(1)) }); }) === "json/wrong-input-type");

  var deep = {};
  var cursor = deep;
  for (var i = 0; i < 40; i += 1) { cursor.next = {}; cursor = cursor.next; }
  check("measureBytes throws json/too-deep past maxDepth",
        _code(function () { b.safeJson.measureBytes(deep, { maxDepth: 8 }); }) === "json/too-deep");

  // The string branch of parseStringOrObject enforces depth through
  // _walkAndCheck, which charges a level for every value including the
  // primitive at the bottom. A chain ending in an empty object is one level
  // shallower than the same chain ending in a number, so both terminators are
  // walked: a check that only nests containers reads the two branches as
  // agreeing while they part company one level in.
  function chain(levels, leaf) {
    var root = {}, tip = root;
    for (var n = 1; n < levels; n += 1) { tip.next = {}; tip = tip.next; }
    if (leaf !== undefined) tip.leaf = leaf;
    return root;
  }
  [["an empty object", undefined], ["a number", 1], ["a string", "x"], ["an array", [1]]]
    .forEach(function (terminator) {
      var sawAccepted = false, sawRefused = false;
      [1, 2, 3, 4, 5, 6, 7, 8].forEach(function (levels) {
        var viaObject = _code(function () {
          b.safeJson.parseStringOrObject(chain(levels, terminator[1]),
            { maxDepth: 5, maxBytes: 4096 });
        });
        var viaString = _code(function () {
          b.safeJson.parseStringOrObject(JSON.stringify(chain(levels, terminator[1])),
            { maxDepth: 5, maxBytes: 4096 });
        });
        if (viaObject === "OK") sawAccepted = true;
        if (viaObject === "json/too-deep") sawRefused = true;
        check("both parseStringOrObject branches answer the same at " + levels +
              " levels ending in " + terminator[0],
              viaObject === viaString,
              JSON.stringify({ viaObject: viaObject, viaString: viaString }));
      });
      check("the depth parity check ending in " + terminator[0] + " crosses its boundary",
            sawAccepted && sawRefused);
    });

  check("measureBytes charges a level for a primitive leaf as _walkAndCheck does",
        _code(function () {
          b.safeJson.measureBytes({ a: { b: 1 } }, { maxDepth: 1 });
        }) === "json/too-deep");
  check("measureBytes counts a function carrying toJSON",
        b.safeJson.measureBytes({ f: Object.assign(function () {},
          { toJSON: function () { return "x".repeat(1000); } }) }).bytes === 1008);
}

// ---- stringify ----

function testStringify() {
  check("stringify encodes a plain object",
        b.safeJson.stringify({ a: 1, b: 2 }) === '{"a":1,"b":2}');

  var cyclic = { name: "root" };
  cyclic.self = cyclic;
  check("stringify throws json/circular on a cycle by default",
        _code(function () { b.safeJson.stringify(cyclic); }) === "json/circular");

  var c2 = { name: "root" };
  c2.self = c2;
  check("stringify onCircular:replace substitutes the default placeholder",
        b.safeJson.stringify(c2, { onCircular: "replace" }) === '{"name":"root","self":"[Circular]"}');

  var c3 = { name: "x" };
  c3.self = c3;
  check("stringify honors a custom circularReplacement",
        b.safeJson.stringify(c3, { onCircular: "replace", circularReplacement: "CYC" }) === '{"name":"x","self":"CYC"}');

  // Poisoned own keys are dropped by the replacer on the way out.
  check("stringify suppresses poisoned keys on output",
        b.safeJson.stringify({ a: 1, constructor: 9, prototype: 8 }) === '{"a":1}');

  // allowProto keeps them.
  check("stringify allowProto:true keeps poisoned keys",
        b.safeJson.stringify({ a: 1, constructor: 9 }, { allowProto: true }).indexOf('"constructor":9') !== -1);

  // indent forwarded to JSON.stringify.
  check("stringify forwards a numeric indent",
        b.safeJson.stringify({ a: 1 }, { indent: 2 }) === '{\n  "a": 1\n}');

  // A SafeJsonError raised during serialization is rethrown unchanged.
  var boom = { toJSON: function () { throw new b.safeJson.SafeJsonError("nope", "json/custom"); } };
  check("stringify rethrows a SafeJsonError raised during serialization",
        _code(function () { b.safeJson.stringify(boom); }) === "json/custom");

  // A non-circular serialization failure maps to json/stringify.
  check("stringify wraps a non-circular serialization failure as json/stringify",
        _code(function () { b.safeJson.stringify({ n: BigInt(10) }); }) === "json/stringify");
}

// ---- stringify replace-mode cycle cleaning ----

function testStringifyReplaceCleaning() {
  // Self-referential array.
  var arr = [1];
  arr.push(arr);
  check("stringify replace-mode handles a self-referential array",
        b.safeJson.stringify(arr, { onCircular: "replace" }) === '[1,"[Circular]"]');

  // Shared non-cyclic subtree preserved (stack-discipline, not falsely flagged).
  var shared = { x: 1 };
  check("stringify replace-mode preserves a shared non-cyclic subtree",
        b.safeJson.stringify({ a: shared, b: shared }, { onCircular: "replace" }) ===
        '{"a":{"x":1},"b":{"x":1}}');

  // Poisoned keys stripped during the cleaning walk.
  var cp = { a: 1, constructor: 9 };
  cp.self = cp;
  check("stringify replace-mode strips poisoned keys while cleaning cycles",
        b.safeJson.stringify(cp, { onCircular: "replace" }) === '{"a":1,"self":"[Circular]"}');

  // allowProto keeps poisoned keys through the cleaning walk.
  check("stringify replace-mode + allowProto keeps poisoned keys",
        b.safeJson.stringify({ a: 1, constructor: 9 }, { onCircular: "replace", allowProto: true })
          .indexOf('"constructor":9') !== -1);

  // Scalar / null roots pass straight through the cleaning walk.
  check("stringify replace-mode passes through a scalar root",
        b.safeJson.stringify(5, { onCircular: "replace" }) === "5");
  check("stringify replace-mode passes through a null root",
        b.safeJson.stringify(null, { onCircular: "replace" }) === "null");

  // An inherited enumerable key is skipped by the own-property gate in the walk.
  var proto = { inherited: 1 };
  var withChain = Object.create(proto);
  withChain.own = 2;
  withChain.self = withChain;
  check("stringify replace-mode copies only own keys (skips inherited enumerable)",
        b.safeJson.stringify(withChain, { onCircular: "replace" }) === '{"own":2,"self":"[Circular]"}');
}

// ---- stringifyForScript ----

function testStringifyForScript() {
  var BS = String.fromCharCode(92); // single backslash, matching the escapes emitted
  var out = b.safeJson.stringifyForScript({ html: "</script><!--&" });
  check("stringifyForScript escapes < to \\u003c", out.indexOf(BS + "u003c") !== -1);
  check("stringifyForScript escapes > to \\u003e", out.indexOf(BS + "u003e") !== -1);
  check("stringifyForScript escapes & to \\u0026", out.indexOf(BS + "u0026") !== -1);
  check("stringifyForScript leaves no raw </script> substring", out.indexOf("</script>") === -1);
  check("stringifyForScript round-trips to the original value",
        JSON.parse(out).html === "</script><!--&");

  var sepInput = "a" + String.fromCharCode(0x2028) + "b" + String.fromCharCode(0x2029) + "c";
  var sep = b.safeJson.stringifyForScript({ s: sepInput });
  check("stringifyForScript escapes U+2028", sep.indexOf(BS + "u2028") !== -1);
  check("stringifyForScript escapes U+2029", sep.indexOf(BS + "u2029") !== -1);
}

// ---- canonical ----

function testCanonical() {
  check("canonical undefined root serializes to null", b.safeJson.canonical(undefined) === "null");
  check("canonical null", b.safeJson.canonical(null) === "null");
  check("canonical boolean", b.safeJson.canonical(true) === "true");
  check("canonical finite number", b.safeJson.canonical(3.5) === "3.5");
  check("canonical string", b.safeJson.canonical("hi") === '"hi"');
  check("canonical sorts object keys at every depth",
        b.safeJson.canonical({ b: 2, a: { d: 4, c: 3 } }) === '{"a":{"c":3,"d":4},"b":2}');
  check("canonical serializes arrays in order", b.safeJson.canonical([3, 1, 2]) === "[3,1,2]");
  check("canonical strips poisoned keys",
        b.safeJson.canonical({ constructor: 9, a: 1 }) === '{"a":1}');
  check("canonical refuses a non-finite number nested in an object",
        _code(function () { b.safeJson.canonical({ r: Infinity }); }) === "json/non-finite");
  check("canonical refuses a NaN root",
        _code(function () { b.safeJson.canonical(NaN); }) === "json/non-finite");
  check("canonical refuses an uncanonicalizable type (function)",
        _code(function () { b.safeJson.canonical({ f: function () {} }); }) === "json/uncanonical");
}

// ---- validate: modes + bad schema ----

function testValidateModes() {
  check("validate throws json/bad-schema when the schema is not an object",
        _code(function () { b.safeJson.validate({}, null); }) === "json/bad-schema");
  check("validate throw-mode returns the value on success",
        b.safeJson.validate({ a: 1 }, { type: "object" }).a === 1);

  var okReport = b.safeJson.validate(5, { type: "integer" }, { collectErrors: true });
  check("validate collectErrors returns an ok report on success",
        okReport.ok === true && okReport.errors.length === 0);

  var badReport = b.safeJson.validate("x", { type: "integer" }, { collectErrors: true });
  check("validate collectErrors returns an error report on failure",
        badReport.ok === false && badReport.errors.length >= 1);

  check("validate throw-mode throws json/validation on the first failure",
        _code(function () { b.safeJson.validate("x", { type: "integer" }); }) === "json/validation");
}

// ---- _validateNode: type keyword ----

function testValidateTypes() {
  check("validate integer accepts an integer",
        b.safeJson.validate(5, { type: "integer" }) === 5);
  check("validate integer rejects a non-number",
        _code(function () { b.safeJson.validate("x", { type: "integer" }); }) === "json/validation");
  check("validate integer rejects a non-integer number",
        _code(function () { b.safeJson.validate(1.5, { type: "integer" }); }) === "json/validation");
  check("validate string accepts a string",
        b.safeJson.validate("s", { type: "string" }) === "s");
  check("validate non-integer type mismatch reports json/validation",
        _code(function () { b.safeJson.validate(5, { type: "string" }); }) === "json/validation");
  // A null value against a string type drives _typeName(null) -> "null".
  check("validate names a null value as 'null' on a type mismatch",
        _code(function () { b.safeJson.validate(null, { type: "string" }); }) === "json/validation");
}

// ---- _validateNode: enum ----

function testValidateEnum() {
  check("validate enum accepts an in-set value",
        b.safeJson.validate("a", { enum: ["a", "b"] }) === "a");
  check("validate enum rejects an out-of-set value",
        _code(function () { b.safeJson.validate("z", { enum: ["a", "b"] }); }) === "json/validation");
}

// ---- _validateNode: string constraints ----

function testValidateStringConstraints() {
  check("validate minLength failure",
        _code(function () { b.safeJson.validate("a", { type: "string", minLength: 3 }); }) === "json/validation");
  check("validate minLength pass",
        b.safeJson.validate("abc", { type: "string", minLength: 3 }) === "abc");
  check("validate maxLength failure",
        _code(function () { b.safeJson.validate("abcd", { type: "string", maxLength: 2 }); }) === "json/validation");
  check("validate pattern (RegExp) failure",
        _code(function () { b.safeJson.validate("xyz", { type: "string", pattern: /^a/ }); }) === "json/validation");
  check("validate pattern (RegExp) pass",
        b.safeJson.validate("abc", { type: "string", pattern: /^a/ }) === "abc");
  check("validate pattern (string) compiles and matches",
        b.safeJson.validate("abc", { type: "string", pattern: "^a" }) === "abc");
  check("validate format known + matching",
        b.safeJson.validate("a@b.com", { type: "string", format: "email" }) === "a@b.com");
  check("validate format known + failing",
        _code(function () { b.safeJson.validate("nope", { type: "string", format: "email" }); }) === "json/validation");
  check("validate format unknown reports json/unknown-format",
        _code(function () { b.safeJson.validate("x", { type: "string", format: "does-not-exist" }); }) === "json/unknown-format");
}

// ---- _validateNode: number constraints ----

function testValidateNumberConstraints() {
  check("validate minimum failure",
        _code(function () { b.safeJson.validate(1, { minimum: 5 }); }) === "json/validation");
  check("validate exclusiveMinimum failure (equal)",
        _code(function () { b.safeJson.validate(5, { exclusiveMinimum: 5 }); }) === "json/validation");
  check("validate maximum failure",
        _code(function () { b.safeJson.validate(10, { maximum: 5 }); }) === "json/validation");
  check("validate exclusiveMaximum failure (equal)",
        _code(function () { b.safeJson.validate(5, { exclusiveMaximum: 5 }); }) === "json/validation");
  check("validate number within all bounds passes",
        b.safeJson.validate(5, { minimum: 0, maximum: 10, exclusiveMinimum: 0, exclusiveMaximum: 10 }) === 5);
}

// ---- _validateNode: array constraints ----

function testValidateArrayConstraints() {
  check("validate minItems failure",
        _code(function () { b.safeJson.validate([1], { minItems: 3 }); }) === "json/validation");
  check("validate maxItems failure",
        _code(function () { b.safeJson.validate([1, 2, 3], { maxItems: 2 }); }) === "json/validation");
  check("validate items recurses into elements",
        _code(function () { b.safeJson.validate([1, "x"], { items: { type: "integer" } }); }) === "json/validation");
  check("validate items pass",
        Array.isArray(b.safeJson.validate([1, 2], { items: { type: "integer" } })));
}

// ---- _validateNode: object constraints ----

function testValidateObjectConstraints() {
  check("validate required-key missing",
        _code(function () { b.safeJson.validate({}, { required: ["a"] }); }) === "json/validation");
  check("validate properties recurses into a known key",
        _code(function () {
          b.safeJson.validate({ a: "x" }, { properties: { a: { type: "integer" } } });
        }) === "json/validation");
  check("validate additionalProperties:false rejects an unknown key",
        _code(function () {
          b.safeJson.validate({ a: 1, b: 2 }, { properties: { a: {} }, additionalProperties: false });
        }) === "json/validation");
  // Default additionalProperties (allowed) leaves an extra key alone.
  check("validate allows extra keys when additionalProperties is not false",
        b.safeJson.validate({ a: 1, b: 2 }, { properties: { a: { type: "integer" } } }).b === 2);

  // An inherited enumerable property is skipped by the own-property gate.
  var vproto = { inh: 1 };
  var vval = Object.create(vproto);
  vval.a = 5;
  check("validate iterates only own properties (skips inherited enumerable)",
        b.safeJson.validate(vval, { properties: { a: { type: "integer" } } }).a === 5);

  // Collect mode surfaces multiple errors from one object.
  var schema = {
    type: "object",
    required: ["email", "age"],
    properties: {
      email: { type: "string", format: "email" },
      age:   { type: "integer", minimum: 0 },
    },
    additionalProperties: false,
  };
  var report = b.safeJson.validate({ email: "nope", age: -1, extra: 1 }, schema, { collectErrors: true });
  check("validate collect mode surfaces every failure at once",
        report.ok === false && report.errors.length >= 3);
}

// ---- formats registry ----

function testFormats() {
  var f = b.safeJson.formats;

  check("email valid", f.email("a@b.com") === true);
  check("email non-string", f.email(5) === false);
  check("email over 254 chars", f.email("a".repeat(250) + "@b.com") === false);
  check("email bad shape", f.email("nope") === false);

  check("url valid https", f.url("https://example.com") === true);
  check("url non-string", f.url(5) === false);
  check("url disallowed protocol", f.url("file:///etc/passwd") === false);

  check("uuid valid", f.uuid("f47ac10b-58cc-4372-a567-0e02b2c3d479") === true);
  check("uuid invalid", f.uuid("not-a-uuid") === false);
  check("uuid non-string", f.uuid(5) === false);

  check("ulid valid", f.ulid("01ARZ3NDEKTSV4RRFFQ69G5FAV") === true);
  check("ulid invalid", f.ulid("zzz") === false);

  check("iso8601-date valid", f["iso8601-date"]("2020-01-15") === true);
  check("iso8601-date bad shape", f["iso8601-date"]("2020/01/15") === false);
  check("iso8601-date impossible date", f["iso8601-date"]("2020-13-45") === false);
  check("iso8601-date non-string", f["iso8601-date"](5) === false);

  check("iso8601-datetime valid", f["iso8601-datetime"]("2020-01-15T00:00:00.000Z") === true);
  check("iso8601-datetime non-string", f["iso8601-datetime"](5) === false);
  check("iso8601-datetime mismatch", f["iso8601-datetime"]("not-a-date") === false);

  check("ipv4 valid", f.ipv4("192.168.1.1") === true);
  check("ipv4 non-string", f.ipv4(5) === false);
  check("ipv4 wrong part count", f.ipv4("1.2.3") === false);
  check("ipv4 non-numeric part", f.ipv4("1.2.3.x") === false);
  check("ipv4 out of range", f.ipv4("256.0.0.1") === false);
  check("ipv4 leading zero", f.ipv4("01.2.3.4") === false);

  check("ipv6 full 8 groups", f.ipv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334") === true);
  check("ipv6 compressed", f.ipv6("2001:db8::1") === true);
  check("ipv6 loopback", f.ipv6("::1") === true);
  check("ipv6 all-zero ::", f.ipv6("::") === true);
  check("ipv6 ipv4-mapped", f.ipv6("::ffff:192.168.1.1") === true);
  check("ipv6 non-string", f.ipv6(5) === false);
  check("ipv6 empty", f.ipv6("") === false);
  check("ipv6 too long", f.ipv6("a".repeat(46)) === false);
  check("ipv6 zone id rejected", f.ipv6("fe80::1%eth0") === false);
  check("ipv6 triple colon rejected", f.ipv6("2001:::1") === false);
  check("ipv6 multiple :: rejected", f.ipv6("2001::db8::1") === false);
  check("ipv6 too many groups rejected", f.ipv6("1:2:3:4:5:6:7:8:9") === false);
  check("ipv6 redundant :: (8 groups) rejected", f.ipv6("1:2:3:4:5:6:7:8::") === false);
  check("ipv6 bad hextet rejected", f.ipv6("2001:db8::zzzz") === false);
  check("ipv6 bad ipv4 tail rejected", f.ipv6("::ffff:999.1.1.1") === false);

  check("ip accepts an ipv4", f.ip("10.0.0.1") === true);
  check("ip accepts an ipv6", f.ip("::1") === true);
  check("ip rejects garbage", f.ip("nope") === false);

  check("hex valid", f.hex("deadbeef") === true);
  check("hex invalid", f.hex("xyz") === false);

  check("slug valid", f.slug("my-slug-1") === true);
  check("slug invalid (spaces)", f.slug("Not Slug") === false);
  check("slug non-string", f.slug(5) === false);
}

// ---- registerFormat + isJsonObject ----

function testRegisterFormatAndIsJsonObject() {
  b.safeJson.registerFormat("test-region", function (v) {
    return typeof v === "string" && /^[a-z]{2}-\d$/.test(v);
  });
  check("registerFormat installs a working validator",
        b.safeJson.formats["test-region"]("us-1") === true &&
        b.safeJson.formats["test-region"]("nope") === false);
  check("registerFormat rejects a non-string name",
        _code(function () { b.safeJson.registerFormat(5, function () {}); }) === "json/bad-format-name");
  check("registerFormat rejects an uppercase name",
        _code(function () { b.safeJson.registerFormat("BadName", function () {}); }) === "json/bad-format-name");
  check("registerFormat rejects a non-function validator",
        _code(function () { b.safeJson.registerFormat("ok-name", "not-fn"); }) === "json/bad-format-validator");

  check("isJsonObject true for a plain object", b.safeJson.isJsonObject({ a: 1 }) === true);
  check("isJsonObject false for null", b.safeJson.isJsonObject(null) === false);
  check("isJsonObject false for an array", b.safeJson.isJsonObject([1]) === false);
  check("isJsonObject false for a scalar", b.safeJson.isJsonObject(5) === false);
}

async function run() {
  testDefaultMaxBytes();
  testDefaultMaxDepth();
  testDefaultMaxKeys();
  testAbsoluteMaxBytes();
  testAbsoluteMaxDepth();
  testAbsoluteMaxKeys();
  testSyntaxErrorDoesNotLeakInputBytes();
  testSafeJsonErrorDefaults();
  testParseAllowProtoAndProtoStrip();
  testParseWithSchema();
  testParseExpectTypeAndRequiredKeys();
  testParseOrDefault();
  testParseStringOrObject();
  testParseStringOrObjectCapsTheObjectBranch();
  testMeasureBytes();
  testJsonCopyUnderCap();
  testStringify();
  testStringifyReplaceCleaning();
  testStringifyForScript();
  testCanonical();
  testValidateModes();
  testValidateTypes();
  testValidateEnum();
  testValidateStringConstraints();
  testValidateNumberConstraints();
  testValidateArrayConstraints();
  testValidateObjectConstraints();
  testFormats();
  testRegisterFormatAndIsJsonObject();
  testFormatsAgreeWithThePatternsTheyReplaced();
  testSchemaPatternRunsInLinearTime();
}

// The format table was a set of patterns run against values that arrived over
// the wire. Each is now a character walk. These are the patterns they replaced.
function testFormatsAgreeWithThePatternsTheyReplaced() {
  var f = b.safeJson.formats;

  var EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  var UUID_RE  = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  var ULID_RE  = /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/;
  var DATE_RE  = /^\d{4}-\d{2}-\d{2}$/;
  var SLUG_RE  = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
  var OCTET_RE = /^\d{1,3}$/;

  var VALUES = [
    "", " ", "a@b.c", "a@b", "a b@c.d", "a@@b.c", "a@b.c.d", "a@.b", "a@b.",
    // The pair below is the same case, built from codepoints so no
    // invisible character sits in this file.
    // Built from codepoints: a pattern's `\s` is much wider than the ASCII
    // five, so an address padded with one of the others is not the address
    // that was screened.
    "a@b.c" + String.fromCharCode(0x3000),
    "a" + String.fromCharCode(0x00A0) + "@b.c",
    "x".repeat(255) + "@b.c",
    "123e4567-e89b-12d3-a456-426614174000", "123E4567-E89B-12D3-A456-426614174000",
    "123e4567e89b12d3a456426614174000", "123e4567-e89b-12d3-a456-42661417400",
    "g23e4567-e89b-12d3-a456-426614174000",
    "01ARZ3NDEKTSV4RRFFQ69G5FAV", "81ARZ3NDEKTSV4RRFFQ69G5FAV",
    "01ARZ3NDEKTSV4RRFFQ69G5FAI", "01arz3ndektsv4rrffq69g5fav",
    "2026-08-16", "2026-8-16", "2026-13-01", "2026-02-30", "2026-02-28",
    "a-b", "a-b-c", "-a", "a-", "a--b", "A-b", "a_b", "1-2", "--", "a1-b2",
    "192.168.1.1", "0.0.0.0", "255.255.255.255", "256.0.0.1", "1.2.3",
    "1.2.3.4.5", "01.2.3.4", "1.2.3.04", "1.2.3.", ".1.2.3", "a.b.c.d",
  ];

  var diffs = [];
  VALUES.forEach(function (v) {
    function compare(label, expected, actual) {
      if (expected !== actual) diffs.push(label + " " + JSON.stringify(v.slice(0, 40)) +
                                          " want " + expected + " got " + actual);
    }
    compare("email", v.length <= 254 && EMAIL_RE.test(v), f.email(v));
    compare("uuid",  UUID_RE.test(v),                     f.uuid(v));
    compare("ulid",  ULID_RE.test(v),                     f.ulid(v));
    compare("slug",  SLUG_RE.test(v),                     f.slug(v));
    var d = new Date(v);
    compare("iso8601-date",
            DATE_RE.test(v) && !isNaN(d.getTime()) && d.toISOString().slice(0, 10) === v,
            f["iso8601-date"](v));
    var parts = v.split(".");
    var wantIpv4 = parts.length === 4;
    for (var i = 0; wantIpv4 && i < 4; i += 1) {
      var n = Number(parts[i]);
      if (!OCTET_RE.test(parts[i]) || n < 0 || n > 255 || parts[i] !== String(n)) wantIpv4 = false;
    }
    compare("ipv4", wantIpv4, f.ipv4(v));
  });
  check("every JSON format agrees with the pattern it replaced (" +
        VALUES.length + " values)", diffs.length === 0, diffs.slice(0, 5).join(" | "));

  // The script-escape is one pass over the five characters that can close or
  // reinterpret the surrounding inline <script>.
  check("stringifyForScript escapes the characters that close a script block",
        b.safeJson.stringifyForScript({ u: "/a</script>&x" }) ===
        "{\"u\":\"/a\\u003c/script\\u003e\\u0026x\"}");
  // Built from codepoints rather than typed, so this file carries neither
  // separator as a literal — an invisible line break in a source file is the
  // thing being defended against, not a thing to spell out.
  var separators = "a" + String.fromCharCode(0x2028) + "b" +
                   String.fromCharCode(0x2029) + "c";
  check("stringifyForScript escapes the two line separators",
        b.safeJson.stringifyForScript(separators) === "\"a\\u2028b\\u2029c\"");
  check("stringifyForScript leaves a value with none of them untouched",
        b.safeJson.stringifyForScript({ a: 1 }) === "{\"a\":1}");
}

// A schema's `pattern` is operator-written and runs against a value that
// arrived over the wire — the arrangement catastrophic backtracking needs.
function testSchemaPatternRunsInLinearTime() {
  function verdict(value, pattern) {
    try { b.safeJson.validate(value, { type: "string", pattern: pattern }); return "ok"; }
    catch (e) { return e.code; }
  }

  var PATTERN_BUDGET_MS = 2000;
  var started = Date.now();
  var got = verdict("a".repeat(60) + "!", "(a+)+$");
  var elapsed = Date.now() - started;
  check("a catastrophic pattern against a hostile value returns rather than " +
        "hangs (" + elapsed + "ms)",
        got === "json/validation" && elapsed < PATTERN_BUDGET_MS);

  // A construct the linear matcher cannot take falls back to the platform
  // engine — but only after the ReDoS screen has passed it.
  check("a backreference still matches", verdict("aa", "^(a)\\1$") === "ok");
  check("a backreference still refuses a non-match",
        verdict("ab", "^(a)\\1$") === "json/validation");
  check("a lookahead still matches", verdict("abc", "^(?=a)abc$") === "ok");
  check("a catastrophic pattern the linear matcher cannot take is refused",
        verdict("x", "^(a+)+\\1$") === "json/bad-pattern");

  // The flags decide what the source MEANS. `(a|A)+` reads as two disjoint
  // branches on its own and as one branch twice under `i`, which is the
  // overlap the alternation rule exists to catch — so a screen that reads the
  // source alone passes this and then runs it, under those flags, against a
  // value from the wire.
  var flagRedosStarted = Date.now();
  var flagRedos = verdict("a".repeat(30) + "!", /^(?=(a|A)+$)a+$/i);
  var flagRedosMs = Date.now() - flagRedosStarted;
  check("a pattern that is catastrophic only under its flags is refused (" +
        flagRedosMs + "ms)",
        flagRedos === "json/bad-pattern" && flagRedosMs < PATTERN_BUDGET_MS,
        flagRedos);
  check("...and honest patterns still carry their flags",
        verdict("ABC", /^(?=a)abc$/i) === "ok" &&
        verdict("abc", /^(?=a)abc$/) === "ok");
  check("an unparseable pattern is reported as a bad pattern, not a mismatch",
        verdict("abc", "([a-") === "json/bad-pattern");

  // A RegExp instance brings its own flags.
  check("a RegExp pattern keeps its flags", verdict("AB", /^ab$/i) === "ok");

  // `g` is dropped, because a `g`-flagged RegExp carries `lastIndex` between
  // calls: a compiled matcher held in the cache would resume mid-subject on
  // the next request and report a mismatch that is really a leftover cursor.
  //
  // Three things have to line up for this to test anything. The pattern needs
  // a construct the linear matcher cannot take — a lookahead — because only
  // the platform-engine fallback has a `lastIndex` at all. The instance has to
  // be held in a variable, since two `/b/g` literals are two objects. And it
  // takes THREE calls: `lastIndex` cycles 0 → 1 → 2 → 0, so the first two
  // agree and the third is the one that reports a match as a mismatch.
  var stateful = /(?=a)a/g;
  var verdicts = [verdict("aa", stateful), verdict("aa", stateful), verdict("aa", stateful)];
  check("a RegExp pattern with g does not carry match state between requests",
        verdicts.every(function (r) { return r === "ok"; }), verdicts.join(", "));

  // `y` is the other stateful flag and advances `lastIndex` the same way, so a
  // cached sticky matcher alternates between matching and not.
  var sticky = /(?=a)a/y;
  var stickyVerdicts = [verdict("a", sticky), verdict("a", sticky), verdict("a", sticky)];
  check("a RegExp pattern with y does not carry match state between requests",
        stickyVerdicts.every(function (r) { return r === "ok"; }),
        stickyVerdicts.join(", "));
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
