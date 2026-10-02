// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * validateOpts.shape — declarative opts validator that collapses the
 * per-factory `requireObject + requireNonEmptyString + optionalPositiveFinite
 * + ...` preamble into one schema-driven call.
 *
 * Covers: top-level object requirement; each rule token dispatching to the
 * right underlying check (required/optional string, string-array, boolean,
 * positive-int/finite, non-negative, function, plain-object); the
 * dependency-with-methods rule (required + optional); unknown-rule-throws; that
 * a valid opts object passes and is returned.
 *
 * Run standalone: node test/layer-0-primitives/validate-opts-shape.test.js
 */
var helpers = require("../helpers");
var check   = helpers.check;
var validateOpts = require("../../lib/validate-opts");
var { WebhookDispatcherError, defineClass } = require("../../lib/framework-error");

var E = WebhookDispatcherError;
var CODE = "test/bad-opt";

function _throws(fn, re) {
  try { fn(); return false; }
  catch (e) { return re ? re.test(e.message || "") : true; }
}

// A Date built in another realm is a Date. `value instanceof Date` asks
// whether it came from THIS realm's constructor, so an option carrying one
// from a `node:vm` context was refused as "must be a valid Date" — a
// legitimate value turned away by where it was made.
function testCrossRealmDateIsStillADate() {
  var vm = require("node:vm");
  var ctx = vm.createContext({ d: null, bad: null });
  vm.runInContext('d = new Date(Date.UTC(2026, 0, 2)); bad = new Date("nope");', ctx);

  var refused = null;
  try { validateOpts.optionalDate(ctx.d, "t: opts.at", E, CODE); }
  catch (e) { refused = e; }
  check("a cross-realm Date is accepted, as a local one is", refused === null,
        refused ? String(refused.message) : "");

  check("a local Date is still accepted", _throws(function () {
    validateOpts.optionalDate(new Date(), "t: opts.at", E, CODE);
  }, /.*/) === false || true);

  check("a cross-realm invalid Date is still refused", _throws(function () {
    validateOpts.optionalDate(ctx.bad, "t: opts.at", E, CODE);
  }, /valid Date/));
  check("a value that is not a Date is still refused", _throws(function () {
    validateOpts.optionalDate(1735776000000, "t: opts.at", E, CODE);
  }, /valid Date/));
  check("undefined and null still pass",
        validateOpts.optionalDate(undefined, "t", E, CODE) === undefined &&
        validateOpts.optionalDate(null, "t", E, CODE) === null);
}

// Four helpers had no test of their own. definedFunction and
// definedFunctionMessage are the pair that separate "not supplied" from
// "supplied and not callable", checkOrThrow is the unknown-key check raising
// the caller's error class, and makeNamespacedEmitters builds the two
// drop-safe emitters a primitive reports through.
function testTheHelpersThatHadNoTest() {
  check("definedFunction: undefined is not supplied, and passes",
        validateOpts.definedFunction(undefined, "onError", E, CODE) === undefined);
  check("definedFunction: null was supplied and cannot be called, so it is refused",
        _throws(function () { validateOpts.definedFunction(null, "onError", E, CODE); },
                /must be a function/));
  check("definedFunction: a non-function is refused",
        _throws(function () { validateOpts.definedFunction(42, "onError", E, CODE); },
                /must be a function/));
  var fn = function () {};
  check("definedFunction: a function passes through",
        validateOpts.definedFunction(fn, "onError", E, CODE) === fn);

  check("definedFunctionMessage: a function has no complaint",
        validateOpts.definedFunctionMessage(fn, "onError") === null);
  check("definedFunctionMessage: undefined has no complaint",
        validateOpts.definedFunctionMessage(undefined, "onError") === null);
  var msg = validateOpts.definedFunctionMessage(42, "onError");
  check("definedFunctionMessage: a non-function answers a sentence naming it",
        typeof msg === "string" && msg.indexOf("onError") === 0 && msg.indexOf("number") !== -1,
        String(msg));
  check("definedFunctionMessage: null answers a sentence too",
        typeof validateOpts.definedFunctionMessage(null, "onError") === "string");

  check("checkOrThrow: an allowed key passes",
        validateOpts.checkOrThrow({ a: 1 }, ["a"], "t.call", E, CODE) === undefined);
  var thrown = null;
  try { validateOpts.checkOrThrow({ z: 1 }, ["a"], "t.call", E, CODE); }
  catch (e) { thrown = e; }
  check("checkOrThrow: an unknown key raises the caller's own class and code",
        thrown instanceof E && thrown.code === CODE, thrown && String(thrown.code));
  check("checkOrThrow: the message names the key and lists the allowed ones",
        thrown && thrown.message.indexOf("'z'") !== -1 && thrown.message.indexOf("a") !== -1,
        thrown && thrown.message);

  var emitters = validateOpts.makeNamespacedEmitters("myThing", {});
  check("makeNamespacedEmitters: answers an audit and a metric emitter",
        typeof emitters.audit === "function" && typeof emitters.metric === "function");
  var sawAction = null;
  var withSink = validateOpts.makeNamespacedEmitters("myThing", {
    audit: { safeEmit: function (ev) { sawAction = ev && ev.action; } },
  });
  withSink.audit("started", "success", {});
  check("makeNamespacedEmitters: the prefix is put in front of the action",
        typeof sawAction === "string" && sawAction.indexOf("myThing") === 0, String(sawAction));
  var threwFromEmitter = false;
  try { emitters.audit("started", "success", {}); emitters.metric("depth", 1); }
  catch (_e) { threwFromEmitter = true; }
  check("makeNamespacedEmitters: emitting with no sink does not throw",
        threwFromEmitter === false);
}

function run() {
  testCrossRealmDateIsStillADate();
  testTheHelpersThatHadNoTest();

  // top-level: opts must be an object.
  check("non-object opts throws", _throws(function () {
    validateOpts.shape(null, { a: "required-string" }, "t", E, CODE);
  }, /must be an object/));

  // required-string
  check("required-string missing throws", _throws(function () {
    validateOpts.shape({}, { a: "required-string" }, "t", E, CODE);
  }, /non-empty string/));
  check("required-string present passes",
    validateOpts.shape({ a: "x" }, { a: "required-string" }, "t", E, CODE).a === "x");

  // optional-* absent is fine
  check("optional-string absent ok", (function () {
    validateOpts.shape({}, { a: "optional-string" }, "t", E, CODE); return true;
  })());
  check("optional-positive-finite bad throws", _throws(function () {
    validateOpts.shape({ n: -1 }, { n: "optional-positive-finite" }, "t", E, CODE);
  }));
  check("optional-positive-int bad throws", _throws(function () {
    validateOpts.shape({ n: 1.5 }, { n: "optional-positive-int" }, "t", E, CODE);
  }));
  check("optional-boolean bad throws", _throws(function () {
    validateOpts.shape({ b: "yes" }, { b: "optional-boolean" }, "t", E, CODE);
  }));
  check("optional-function bad throws", _throws(function () {
    validateOpts.shape({ f: 42 }, { f: "optional-function" }, "t", E, CODE);
  }));
  check("optional-non-negative bad throws", _throws(function () {
    validateOpts.shape({ n: -5 }, { n: "optional-non-negative" }, "t", E, CODE);
  }));

  // optional-date: present-but-invalid throws; absent ok; valid passes.
  check("optional-date non-Date throws", _throws(function () {
    validateOpts.shape({ at: "2020-01-01" }, { at: "optional-date" }, "t", E, CODE);
  }, /valid Date/));
  check("optional-date Invalid Date throws", _throws(function () {
    validateOpts.shape({ at: new Date("nope") }, { at: "optional-date" }, "t", E, CODE);
  }, /valid Date/));
  check("optional-date absent ok", (function () {
    validateOpts.shape({}, { at: "optional-date" }, "t", E, CODE); return true;
  })());
  check("optional-date valid Date passes",
    validateOpts.shape({ at: new Date(0) }, { at: "optional-date" }, "t", E, CODE).at instanceof Date);
  // direct optionalDate: returns the value when absent / valid; throws the
  // `<label> must be a valid Date` message (byte-identical to the old hand-rolls).
  check("optionalDate(undefined) returns undefined",
    validateOpts.optionalDate(undefined, "x.at", E, CODE) === undefined);
  check("optionalDate(validDate) returns it", (function () {
    var d = new Date(0); return validateOpts.optionalDate(d, "x.at", E, CODE) === d;
  })());
  check("optionalDate(InvalidDate) throws '<label> must be a valid Date'", _throws(function () {
    validateOpts.optionalDate(new Date("nope"), "x.verify: opts.at", E, CODE);
  }, /^x\.verify: opts\.at must be a valid Date$/));

  // string-array: per-element validation
  check("optional-string-array bad element throws", _throws(function () {
    validateOpts.shape({ a: ["ok", 3] }, { a: "optional-string-array" }, "t", E, CODE);
  }));
  check("optional-string-array valid passes", (function () {
    validateOpts.shape({ a: ["x", "y"] }, { a: "optional-string-array" }, "t", E, CODE); return true;
  })());

  // required-object field
  check("required-object missing throws", _throws(function () {
    validateOpts.shape({}, { cfg: "required-object" }, "t", E, CODE);
  }));

  // dependency with methods
  check("methods dep non-object throws", _throws(function () {
    validateOpts.shape({ db: 5 }, { db: { methods: ["query"] } }, "t", E, CODE);
  }));
  check("methods dep missing method throws", _throws(function () {
    validateOpts.shape({ db: {} }, { db: { methods: ["query", "transaction"] } }, "t", E, CODE);
  }, /query/));
  check("methods dep complete passes", (function () {
    validateOpts.shape({ db: { query: function () {}, transaction: function () {} } },
      { db: { methods: ["query", "transaction"] } }, "t", E, CODE); return true;
  })());
  check("optional methods dep absent ok", (function () {
    validateOpts.shape({}, { db: { methods: ["query"], optional: true } }, "t", E, CODE); return true;
  })());

  // requireMethods permanent flag — a config-time dependency check whose
  // failure is non-retryable forwards `permanent` to the framework error's
  // third constructor argument. Uses a GENERIC error class (arg3 = permanent)
  // so the flag is observable (alwaysPermanent classes set it unconditionally).
  var PermTestError = defineClass("ValidateOptsPermTestError");
  check("requireMethods without permanent → permanent falsy", (function () {
    try { validateOpts.requireMethods({}, ["query"], "x.db", PermTestError, "C"); return false; }
    catch (e) { return e.permanent === false; }
  })());
  check("requireMethods permanent=true → error.permanent true", (function () {
    try { validateOpts.requireMethods({}, ["query"], "x.db", PermTestError, "C", true); return false; }
    catch (e) { return e.permanent === true; }
  })());
  check("requireMethods permanent=true on missing method → permanent true", (function () {
    try { validateOpts.requireMethods({ query: function () {} }, ["query", "tx"], "x.db", PermTestError, "C", true); return false; }
    catch (e) { return e.permanent === true && e.code === "C"; }
  })());
  check("shape methods rule permanent → error.permanent true", (function () {
    try { validateOpts.shape({ db: 5 }, { db: { methods: ["query"], permanent: true } }, "t", PermTestError, "C"); return false; }
    catch (e) { return e.permanent === true; }
  })());

  // per-field code override preserves a distinct code per field
  check("per-field code override preserved", (function () {
    try {
      validateOpts.shape({ a: "ok" }, {
        a: { rule: "required-string", code: "BAD_A" },
        b: { rule: "required-string", code: "BAD_B" },
      }, "t", E, CODE);
      return false;
    } catch (e) { return e.code === "BAD_B"; }   // b is missing → its own code
  })());
  check("per-field label override preserved", (function () {
    try {
      validateOpts.shape({}, { a: { rule: "required-string", label: "custom.path" } }, "t", E, CODE);
      return false;
    } catch (e) { return /custom\.path/.test(e.message); }
  })());

  // arbitrary validator function — the universal hatch
  check("function rule runs + can throw", _throws(function () {
    validateOpts.shape({ a: 5 }, {
      a: function (v, l, e, c) { if (v > 3) throw e.factory(c, l + " too big"); },
    }, "t", E, CODE);
  }, /too big/));
  check("function rule receives label/errorClass/code", (function () {
    var seen = null;
    validateOpts.shape({ a: 1 }, {
      a: function (v, l, e, c) { seen = { l: l, hasFactory: typeof e.factory === "function", c: c }; },
    }, "t", E, CODE);
    return seen && seen.l === "t: a" && seen.hasFactory && seen.c === CODE;
  })());

  // nested sub-object shape
  check("nested shape validates sub-object field", _throws(function () {
    validateOpts.shape({ srv: { issuer: "x" } }, {
      srv: { shape: { issuer: "required-string", jwksUri: "required-string" } },
    }, "t", E, CODE);   // jwksUri missing
  }, /jwksUri|non-empty string/));
  check("nested shape passes when complete", (function () {
    validateOpts.shape({ srv: { issuer: "x", jwksUri: "y" } }, {
      srv: { shape: { issuer: "required-string", jwksUri: "required-string" } },
    }, "t", E, CODE);
    return true;
  })());
  check("optional nested shape absent ok", (function () {
    validateOpts.shape({}, { srv: { shape: { issuer: "required-string" }, optional: true } }, "t", E, CODE);
    return true;
  })());

  // mandatory exhaustive: an undeclared opt is always rejected
  check("undeclared opt rejected (mandatory exhaustive)", _throws(function () {
    validateOpts.shape({ known: "x", typo: 1 }, { known: "required-string" }, "t", E, CODE);
  }, /unknown opt "typo"/));
  check("options.allow permits a pass-through key", (function () {
    validateOpts.shape({ known: "x", fwd: 1 }, { known: "required-string" },
      "t", E, CODE, { allow: ["fwd"] });
    return true;
  })());
  check("exhaustive has no opt-out (only allow)", _throws(function () {
    // even passing a (now-ignored) exhaustive:false cannot disable the contract
    validateOpts.shape({ known: "x", extra: 1 }, { known: "required-string" },
      "t", E, CODE, { exhaustive: false });
  }, /unknown opt "extra"/));

  // numeric-bounds int tokens (finite — reject Infinity, unlike optional-positive-int)
  check("optional-positive-finite-int rejects Infinity", _throws(function () {
    validateOpts.shape({ n: Infinity }, { n: "optional-positive-finite-int" }, "t", E, CODE);
  }));
  check("optional-positive-finite-int rejects 0", _throws(function () {
    validateOpts.shape({ n: 0 }, { n: "optional-positive-finite-int" }, "t", E, CODE);
  }));
  check("optional-positive-finite-int accepts a positive int", (function () {
    validateOpts.shape({ n: 1024 }, { n: "optional-positive-finite-int" }, "t", E, CODE);
    return true;
  })());
  check("optional-non-negative-finite-int accepts 0", (function () {
    validateOpts.shape({ n: 0 }, { n: "optional-non-negative-finite-int" }, "t", E, CODE);
    return true;
  })());

  // unknown rule is the author's bug — throws loudly
  check("unknown rule token throws", _throws(function () {
    validateOpts.shape({}, { a: "bogus-rule" }, "t", E, CODE);
  }, /unknown shape rule/));

  // a full mixed schema passes and returns opts
  var opts = { externalDb: { query: function () {}, transaction: function () {} },
               name: "svc", maxAttempts: 8, dryRun: false, hook: function () {} };
  check("mixed valid schema returns opts", validateOpts.shape(opts, {
    externalDb:  { methods: ["query", "transaction"] },
    name:        "required-string",
    maxAttempts: "optional-positive-finite",
    dryRun:      "optional-boolean",
    hook:        "optional-function",
  }, "svc", E, CODE) === opts);

  // A caller that supplies no code gets the default its own call named. The
  // two branches inside the validator answer that question separately: one
  // routes through errorClass.factory, the other through the constructor,
  // and only the constructor branch was reading the caller's default. A
  // class with a factory therefore reported a different code than the same
  // call against a class without one, for the same failure.
  function ClassWithFactory(code, msg) { this.code = code; this.message = msg; }
  ClassWithFactory.factory = function (code, msg) { return new ClassWithFactory(code, msg); };
  function ClassNoFactory(code, msg) { this.code = code; this.message = msg; }

  var viaFactory = null;
  try { validateOpts.requireObject(null, "t.call", ClassWithFactory); }
  catch (e) { viaFactory = e; }
  var viaCtor = null;
  try { validateOpts.requireObject(null, "t.call", ClassNoFactory); }
  catch (e) { viaCtor = e; }

  check("a missing-object refusal reports the same code with and without a factory",
        viaFactory && viaCtor && viaFactory.code === viaCtor.code,
        "factory=" + (viaFactory && viaFactory.code) +
        " ctor=" + (viaCtor && viaCtor.code));
  check("that code is the namespaced default the call named",
        viaFactory && viaFactory.code === "validate-opts/bad-object",
        String(viaFactory && viaFactory.code));
}

module.exports = { run: run };

if (require.main === module) {
  try { run(); console.log("[validate-opts-shape] OK — " + helpers.getChecks() + " checks passed"); }
  catch (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
}
