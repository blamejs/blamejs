"use strict";
/**
 * Layer 0 — pure primitive smoke tests.
 *
 * These tests exercise primitives with NO framework state and NO I/O
 * dependencies (or I/O confined to tmpdir round-trips). They run FIRST
 * in the smoke-test ordering: a broken primitive should surface here,
 * not as a downstream consumer crash that hides the root cause (per
 * .claude/memory/feedback_test_dependency_order.md).
 *
 * This file is being populated incrementally — each commit moves one
 * functional group from test/smoke.js. When all Layer 0 groups have
 * been migrated, smoke.js's runner block will call ONLY this file's
 * `run()` for Layer 0 work.
 *
 * Currently shipped here:
 *   - sql-safe (identifier validation, quoting, allowlist)
 *   - chain-writer (rejects non-chain-table; race-safety under
 *     concurrent appends)
 *   - async-safe (withTimeout / safeAwait / Mutex / Semaphore /
 *     Once / CircuitBreaker)
 *   - handlers (emit/drain, retry, breaker, DLQ, shutdown, stats,
 *     backpressure, recursion-safe emit-during-flush)
 *   - json-safe (parse / stringify / canonical / validate /
 *     validateCollect / formats — incl. the IPv6 detail tests)
 *
 * Pending migration (still in smoke.js):
 *   - atomic-file / parsers (xml, csv, toml, yaml, env-parse) /
 *     redact (v0.1.19)
 */

var helpers = require("./_helpers");
var b           = helpers.b;
var fs          = helpers.fs;
var os          = helpers.os;
var path        = helpers.path;
var check       = helpers.check;
var setupTestDb = helpers.setupTestDb;
var teardownTestDb = helpers.teardownTestDb;

// ---- sql-safe ----

function testSqlSafeIdentifierValidation() {
  // Good shape
  check("sqlSafe.validateIdentifier accepts valid name",
        b.sqlSafe.validateIdentifier("audit_log") === "audit_log");
  check("sqlSafe.validateIdentifier accepts leading underscore",
        b.sqlSafe.validateIdentifier("_blamejs_audit_log") === "_blamejs_audit_log");
  // Bad shape
  var badRejects = [
    ["empty",            ""],
    ["leading digit",    "1foo"],
    ["embedded space",   "foo bar"],
    ["punctuation",      "foo.bar"],
    ["semicolon",        "foo;DROP"],
    ["quote",            'foo"bar'],
    ["backslash",        "foo\\bar"],
    ["null byte",        "foo\0bar"],
  ];
  for (var i = 0; i < badRejects.length; i++) {
    var label = badRejects[i][0];
    var input = badRejects[i][1];
    var threw = false;
    try { b.sqlSafe.validateIdentifier(input); }
    catch (e) { threw = !!e.isSqlSafeError; }
    check("sqlSafe rejects bad identifier (" + label + ")", threw);
  }
  // Reserved word
  var threwReserved = false;
  try { b.sqlSafe.validateIdentifier("SELECT"); }
  catch (e) { threwReserved = e.code === "sql/reserved-word"; }
  check("sqlSafe rejects SQL reserved word",                threwReserved);
  // sqlite_ prefix
  var threwInternal = false;
  try { b.sqlSafe.validateIdentifier("sqlite_master"); }
  catch (e) { threwInternal = e.code === "sql/internal-prefix"; }
  check("sqlSafe rejects sqlite_-prefixed identifier",      threwInternal);
  // Length cap
  var threwLong = false;
  try { b.sqlSafe.validateIdentifier("a".repeat(70)); }
  catch (e) { threwLong = e.code === "sql/too-long"; }
  check("sqlSafe rejects over-long identifier",             threwLong);
}

function testSqlSafeQuoteIdentifier() {
  check("quoteIdentifier sqlite uses double-quote",
        b.sqlSafe.quoteIdentifier("audit_log", "sqlite") === '"audit_log"');
  check("quoteIdentifier postgres uses double-quote",
        b.sqlSafe.quoteIdentifier("audit_log", "postgres") === '"audit_log"');
  check("quoteIdentifier mysql uses backtick",
        b.sqlSafe.quoteIdentifier("audit_log", "mysql") === "`audit_log`");
  var threw = false;
  try { b.sqlSafe.quoteIdentifier("foo;DROP"); }
  catch (e) { threw = !!e.isSqlSafeError; }
  check("quoteIdentifier rejects bad name",                 threw);
}

function testSqlSafeAssertOneOf() {
  var allow = new Set(["audit_log", "consent_log"]);
  check("assertOneOf passes when in allowlist",
        b.sqlSafe.assertOneOf("audit_log", allow) === "audit_log");
  var threw = false;
  try { b.sqlSafe.assertOneOf("users", allow); }
  catch (e) { threw = e.code === "sql/not-allowed"; }
  check("assertOneOf rejects non-allowlisted",              threw);
  check("assertOneOf accepts array allowlist",
        b.sqlSafe.assertOneOf("a", ["a", "b"]) === "a");
}

// ---- chain-writer ----

async function testChainWriterRejectsBadTable() {
  var threw = null;
  try {
    b.chainWriter.create({
      table: "users",
      columnsForInsert: ["_id"],
      hashableColumns:  ["_id"],
    });
  } catch (e) { threw = e; }
  check("chainWriter rejects non-chain table",
        threw && (threw.code === "sql/not-allowed" || threw.code === "chain-writer/invalid-config" ||
                  /not in allowlist/.test(threw.message)));
}

async function testChainWriterRaceSafetyConcurrentAppends() {
  // Concurrent appends through chain-writer should produce a chain
  // with no forks — every row's prevHash matches the predecessor's
  // rowHash, monotonicCounter strictly increases by 1.
  //
  // This is technically Layer 3 work (needs db) but is included with
  // the chain-writer primitive tests because it's the canonical
  // resilience claim for the primitive. The cost of running setupTestDb
  // here is acceptable; the alternative is splitting the chain-writer
  // tests across two layer files which obscures the intent.
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cw-"));
  try {
    b.cluster._resetForTest();
    await setupTestDb(tmpDir);
    b.audit.registerNamespace("test");

    var promises = [];
    for (var i = 0; i < 10; i++) {
      promises.push(b.audit.record({
        actor:   { userId: "u-" + i },
        action:  "test.concurrent",
        outcome: "success",
      }));
    }
    var results = await Promise.all(promises);

    var verified = await b.audit.verify();
    check("chain-writer race test: chain verifies after 10 concurrent appends",
          verified.ok === true);
    var counters = results.map(function (r) { return r.monotonicCounter; }).sort(function (a, b) { return a - b; });
    var allUnique = counters.every(function (c, idx, arr) { return idx === 0 || c === arr[idx - 1] + 1; });
    check("chain-writer race test: counters strictly monotonic, no duplicates",
          allUnique && counters.length === 10);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- async-safe ----

async function testAsyncSafeWithTimeoutResolves() {
  var v = await b.asyncSafe.withTimeout(Promise.resolve("ok"), 100);
  check("withTimeout: resolves with value when fast",       v === "ok");
}

async function testAsyncSafeWithTimeoutRejects() {
  var threw = null;
  try {
    await b.asyncSafe.withTimeout(new Promise(function () {}), 20, { name: "test-op" });
  } catch (e) { threw = e; }
  check("withTimeout: rejects on timeout",                  threw && threw.code === "async/timeout");
  check("withTimeout: timeout error names operation",       threw && threw.message.indexOf("test-op") >= 0);
}

async function testAsyncSafeWithTimeoutAbort() {
  var ctrl = new AbortController();
  var p = b.asyncSafe.withTimeout(new Promise(function () {}), 10000, { signal: ctrl.signal });
  setTimeout(function () { ctrl.abort(); }, 10);
  var threw = null;
  try { await p; } catch (e) { threw = e; }
  check("withTimeout: AbortSignal aborts cleanly",          threw && threw.code === "async/aborted");
}

async function testAsyncSafeWithTimeoutPropagatesError() {
  var threw = null;
  try {
    await b.asyncSafe.withTimeout(Promise.reject(new Error("boom")), 100);
  } catch (e) { threw = e; }
  check("withTimeout: propagates underlying rejection",     threw && threw.message === "boom");
}

async function testAsyncSafeSafeAwait() {
  var ok = await b.asyncSafe.safeAwait(Promise.resolve(42));
  check("safeAwait: success returns [null, value]",         ok[0] === null && ok[1] === 42);
  var fail = await b.asyncSafe.safeAwait(Promise.reject(new Error("nope")));
  check("safeAwait: failure returns [error, null]",         fail[0] && fail[0].message === "nope" && fail[1] === null);
}

async function testAsyncSafeMutexSerializes() {
  var m = new b.asyncSafe.Mutex();
  var order = [];
  async function task(label, durMs) {
    return m.runExclusive(async function () {
      order.push(label + ":enter");
      await new Promise(function (r) { setTimeout(r, durMs); });
      order.push(label + ":exit");
    });
  }
  await Promise.all([task("A", 30), task("B", 5), task("C", 5)]);
  check("Mutex: A enters first",       order[0] === "A:enter");
  check("Mutex: A exits before B/C enter",
        order.indexOf("A:exit") < order.indexOf("B:enter") &&
        order.indexOf("A:exit") < order.indexOf("C:enter"));
  check("Mutex: B and C don't interleave",
        Math.abs(order.indexOf("B:enter") - order.indexOf("B:exit")) === 1);
}

async function testAsyncSafeMutexReleaseOnThrow() {
  var m = new b.asyncSafe.Mutex();
  var threw = null;
  try {
    await m.runExclusive(async function () { throw new Error("inner"); });
  } catch (e) { threw = e; }
  check("Mutex: runExclusive propagates thrown error",      threw && threw.message === "inner");
  check("Mutex: lock released after throw",                 !m.isHeld());
}

async function testAsyncSafeMutexAbortableAcquire() {
  var m = new b.asyncSafe.Mutex();
  await m.acquire();
  var ctrl = new AbortController();
  var p = m.acquire({ signal: ctrl.signal });
  setTimeout(function () { ctrl.abort(); }, 10);
  var threw = null;
  try { await p; } catch (e) { threw = e; }
  check("Mutex: aborted acquire rejects",                   threw && threw.code === "async/aborted");
  check("Mutex: aborted acquirer no longer queued",         m.pendingCount() === 0);
  m.release();
}

async function testAsyncSafeSemaphoreBoundedConcurrency() {
  var s = new b.asyncSafe.Semaphore(2);
  var concurrent = 0;
  var maxConcurrent = 0;
  async function task() {
    return s.runWith(async function () {
      concurrent += 1;
      if (concurrent > maxConcurrent) maxConcurrent = concurrent;
      await new Promise(function (r) { setTimeout(r, 10); });
      concurrent -= 1;
    });
  }
  await Promise.all([task(), task(), task(), task(), task()]);
  check("Semaphore: max concurrency respected",             maxConcurrent === 2);
}

async function testAsyncSafeSemaphoreAbortableAcquire() {
  var s = new b.asyncSafe.Semaphore(1);
  await s.acquire();
  var ctrl = new AbortController();
  var p = s.acquire({ signal: ctrl.signal });
  setTimeout(function () { ctrl.abort(); }, 10);
  var threw = null;
  try { await p; } catch (e) { threw = e; }
  check("Semaphore: aborted acquire rejects",               threw && threw.code === "async/aborted");
  s.release();
}

async function testAsyncSafeOnceSingleFlight() {
  var calls = 0;
  var once = new b.asyncSafe.Once(async function () {
    calls += 1;
    await new Promise(function (r) { setTimeout(r, 10); });
    return "result-" + calls;
  });
  var results = await Promise.all([once.invoke(), once.invoke(), once.invoke()]);
  check("Once: function invoked exactly once",              calls === 1);
  check("Once: all callers see same result",
        results[0] === "result-1" && results[1] === "result-1" && results[2] === "result-1");
}

async function testAsyncSafeOnceCachesFailure() {
  var once = new b.asyncSafe.Once(async function () { throw new Error("init failed"); });
  var first = null, second = null;
  try { await once.invoke(); } catch (e) { first = e; }
  try { await once.invoke(); } catch (e) { second = e; }
  check("Once: failure caches; both callers see same rejection",
        first && second && first.message === "init failed" && second.message === "init failed");
}

async function testAsyncSafeOnceReset() {
  var calls = 0;
  var once = new b.asyncSafe.Once(async function () {
    calls += 1;
    if (calls === 1) throw new Error("transient");
    return "ok";
  });
  var failed = null;
  try { await once.invoke(); } catch (e) { failed = e; }
  check("Once: first call fails as expected",               failed && failed.message === "transient");
  once.reset();
  var second = await once.invoke();
  check("Once: reset enables retry; second call succeeds",  second === "ok" && calls === 2);
}

async function testAsyncSafeCircuitBreakerStateTransitions() {
  var br = new b.asyncSafe.CircuitBreaker("test", { failureThreshold: 2, cooldownMs: 30, successThreshold: 1 });
  check("CircuitBreaker: starts closed",                    br.getState() === "closed");
  for (var i = 0; i < 2; i++) {
    try { await br.wrap(async function () { throw new Error("fail"); }); } catch (_e) {}
  }
  check("CircuitBreaker: opens after failureThreshold",     br.getState() === "open");
  var fastFail = null;
  try { await br.wrap(async function () { return "ok"; }); }
  catch (e) { fastFail = e; }
  check("CircuitBreaker: open state fast-fails",            fastFail && fastFail.code === "CIRCUIT_OPEN");
  await new Promise(function (r) { setTimeout(r, 50); });
  var probe = await br.wrap(async function () { return "ok"; });
  check("CircuitBreaker: half-open probe success",          probe === "ok");
  check("CircuitBreaker: closes after success threshold",   br.getState() === "closed");
}

// ---- handlers ----

async function testHandlerEmitAndDrain() {
  var flushed = [];
  var h = b.handlers.create({
    name:  "test",
    flush: async function (batch) { flushed.push.apply(flushed, batch); },
  });
  h.emit({ id: 1 });
  h.emit({ id: 2 });
  h.emit({ id: 3 });
  check("handler: emit returns nothing (sync)",             h.emit({ id: 4 }) === undefined);
  await h.drain();
  check("handler: drain flushes all buffered items",        flushed.length === 4);
  check("handler: items delivered in order",                flushed[0].id === 1 && flushed[3].id === 4);
  check("handler: buffer empty post-drain",                 h.size() === 0);
}

async function testHandlerEmitDuringFlushNextCycle() {
  var phase1 = [];
  var phase2 = [];
  var emitDuring = true;
  var h;
  h = b.handlers.create({
    name:  "test-recursion",
    flush: async function (batch) {
      if (emitDuring) {
        emitDuring = false;
        h.emit({ id: 99 });
        phase1.push.apply(phase1, batch);
      } else {
        phase2.push.apply(phase2, batch);
      }
    },
  });
  h.emit({ id: 1 });
  h.emit({ id: 2 });
  await h.drain();
  check("handler: emit-during-flush lands in next cycle",
        phase1.length === 2 && phase2.length === 1 && phase2[0].id === 99);
}

async function testHandlerRetryOnFlushFailure() {
  var attempts = 0;
  var seen = null;
  var h = b.handlers.create({
    name:  "test-retry",
    flush: async function (batch) {
      attempts += 1;
      if (attempts < 3) throw new Error("transient");
      seen = batch;
    },
    retry: { maxAttempts: 5, baseDelayMs: 1 },
  });
  h.emit({ id: 1 });
  await h.drain();
  check("handler: retries on flush failure",                attempts >= 3);
  check("handler: eventually succeeds",                     seen && seen.length === 1);
}

async function testHandlerCircuitBreakerOpensOnPersistentFailure() {
  var dlqCalls = 0;
  var h = b.handlers.create({
    name:  "test-breaker",
    flush: async function () { throw new Error("always fails"); },
    retry: { maxAttempts: 1, baseDelayMs: 1 },
    breaker: { failureThreshold: 2, cooldownMs: 10000, successThreshold: 1 },
    deadLetter: function () { dlqCalls += 1; },
    onError: function () { /* swallow expected errors */ },
  });
  h.emit({ id: 1 });
  await h.drain();
  h.emit({ id: 2 });
  await h.drain();
  h.emit({ id: 3 });
  await h.drain();
  var stats = h.getStats();
  check("handler: breaker tripped after consecutive failures",
        stats.breakerState === "open" || stats.breakerState === "half-open");
  check("handler: dead-lettered items on persistent failure", dlqCalls >= 1);
}

async function testHandlerBoundedShutdown() {
  var h = b.handlers.create({
    name:  "test-shutdown",
    flush: async function () {
      await new Promise(function (r) { setTimeout(r, 100); });
    },
    retry: { maxAttempts: 1, baseDelayMs: 1 },
    onError: function () { /* swallow */ },
  });
  h.emit({ id: 1 });
  var t0 = Date.now();
  await h.shutdown({ timeoutMs: 20 });
  var dur = Date.now() - t0;
  check("handler: shutdown bounded by timeout (< 100ms)",   dur < 80);
}

async function testHandlerStats() {
  var h = b.handlers.create({
    name:  "test-stats",
    flush: async function () { await new Promise(function (r) { setTimeout(r, 5); }); },
  });
  for (var i = 0; i < 5; i++) h.emit({ id: i });
  await h.drain();
  var s = h.getStats();
  check("handler.getStats: totalEmitted",                   s.totalEmitted === 5);
  check("handler.getStats: totalFlushed",                   s.totalFlushed === 5);
  check("handler.getStats: bufferSize=0 post-drain",        s.bufferSize === 0);
  check("handler.getStats: lastFlushDurationMs > 0",        s.lastFlushDurationMs > 0);
  check("handler.getStats: breakerState exposed",           s.breakerState === "closed");
}

async function testHandlerBackpressureDrop() {
  var dropped = [];
  var h = b.handlers.create({
    name:          "test-backpressure",
    flush:         async function () { await new Promise(function () {}); /* hang */ },
    maxBufferSize: 3,
    deadLetter:    function (items) { dropped.push.apply(dropped, items); },
    onError:       function () { /* swallow */ },
  });
  for (var i = 0; i < 10; i++) h.emit({ id: i });
  await new Promise(function (r) { setImmediate(r); });
  check("handler: maxBufferSize drops over-cap items to DLQ", dropped.length >= 5);
}

// ---- json-safe ----

function testJsonModuleSurface() {
  check("jsonSafe namespace present",        typeof b.jsonSafe === "object");
  check("jsonSafe.parse is a function",      typeof b.jsonSafe.parse === "function");
  check("jsonSafe.validate is a function",   typeof b.jsonSafe.validate === "function");
  check("jsonSafe.canonical is a function",  typeof b.jsonSafe.canonical === "function");
  check("jsonSafe.JsonSafeError exists",     typeof b.jsonSafe.JsonSafeError === "function");
}

function testJsonParse() {
  // Basic round-trip
  var v = b.jsonSafe.parse('{"a":1,"b":"hello","c":null,"d":[1,2,3],"e":true}');
  check("parse round-trips object",   v.a === 1 && v.b === "hello" && v.c === null);
  check("parse round-trips array",    Array.isArray(v.d) && v.d.length === 3);

  // BOM tolerated
  var bom = b.jsonSafe.parse("﻿{\"x\":1}");
  check("parse strips BOM",           bom.x === 1);

  // Size limit
  var bigInput = '{"x":"' + "a".repeat(200) + '"}';
  var sizeRejected = false;
  try { b.jsonSafe.parse(bigInput, { maxBytes: 100 }); }
  catch (e) { sizeRejected = e.code === "json/too-large"; }
  check("parse rejects oversized input",                  sizeRejected);

  // Depth limit
  var deep = '{"a":'.repeat(10) + 'null' + '}'.repeat(10);
  var depthRejected = false;
  try { b.jsonSafe.parse(deep, { maxDepth: 3 }); }
  catch (e) { depthRejected = e.code === "json/too-deep"; }
  check("parse rejects too-deep input",                   depthRejected);

  // Proto pollution
  var poisoned = b.jsonSafe.parse('{"__proto__":{"isAdmin":true},"name":"alice"}');
  check("parse strips __proto__ key",                     !("__proto__" in poisoned) || poisoned.__proto__ === Object.prototype);
  check("parse does not pollute Object.prototype",        !({}.isAdmin));

  var ctorPoisoned = b.jsonSafe.parse('{"constructor":{"prototype":{"x":1}}}');
  check("parse strips constructor key",                   !("constructor" in ctorPoisoned) || ctorPoisoned.constructor === Object);

  // Syntax error
  var syntaxRejected = false;
  try { b.jsonSafe.parse("{not-json}"); }
  catch (e) { syntaxRejected = e.code === "json/syntax"; }
  check("parse reports syntax errors with code",          syntaxRejected);

  // Wrong input type
  var typeRejected = false;
  try { b.jsonSafe.parse(123); }
  catch (e) { typeRejected = e.code === "json/wrong-input-type"; }
  check("parse rejects non-string/Buffer input",          typeRejected);

  // parseOrDefault
  check("parseOrDefault returns fallback on bad input",   b.jsonSafe.parseOrDefault("not-json", { fallback: true }).fallback === true);
  check("parseOrDefault returns parsed on good input",    b.jsonSafe.parseOrDefault('{"x":1}', null).x === 1);

  // Buffer input
  var fromBuf = b.jsonSafe.parse(Buffer.from('{"y":2}', "utf8"));
  check("parse accepts Buffer input",                     fromBuf.y === 2);
}

function testJsonStringify() {
  var s = b.jsonSafe.stringify({ a: 1, b: [1, 2, 3] });
  check("stringify produces valid JSON",                  JSON.parse(s).a === 1);

  var stripped = JSON.parse(b.jsonSafe.stringify({ __proto__: { x: 1 }, name: "alice" }));
  check("stringify strips __proto__",                     !("__proto__" in stripped) || stripped.__proto__ === Object.prototype);

  var circular = { a: 1 };
  circular.self = circular;
  var circRejected = false;
  try { b.jsonSafe.stringify(circular); }
  catch (e) { circRejected = e.code === "json/circular"; }
  check("stringify throws on circular ref",               circRejected);

  // Replace mode
  var replaced = b.jsonSafe.stringify(circular, { onCircular: "replace", circularReplacement: "<circular>" });
  check("stringify circular replace mode works",          /<circular>/.test(replaced));
}

function testJsonCanonical() {
  var c1 = b.jsonSafe.canonical({ b: 2, a: 1, c: 3 });
  var c2 = b.jsonSafe.canonical({ a: 1, c: 3, b: 2 });
  check("canonical: identical content same key order → identical bytes",  c1 === c2);
  check("canonical: keys sorted alphabetically",          c1 === '{"a":1,"b":2,"c":3}');

  var nested = b.jsonSafe.canonical({ z: { y: 1, x: 2 }, a: [3, 1, 2] });
  check("canonical: nested objects also sorted",          nested === '{"a":[3,1,2],"z":{"x":2,"y":1}}');

  var nfRejected = false;
  try { b.jsonSafe.canonical({ x: NaN }); }
  catch (e) { nfRejected = e.code === "json/non-finite"; }
  check("canonical: NaN rejected",                        nfRejected);
}

function testJsonValidate() {
  b.jsonSafe.validate("hello", { type: "string" });
  check("validate type-pass returns silently", true);
  var typeRejected = false;
  try { b.jsonSafe.validate(42, { type: "string" }); }
  catch (e) { typeRejected = e.code === "json/validation" && /expected string/.test(e.message); }
  check("validate type mismatch throws with path",         typeRejected);

  var schema = {
    type: "object",
    required: ["email", "age"],
    properties: {
      email: { type: "string", format: "email", maxLength: 254 },
      age:   { type: "integer", minimum: 0, maximum: 150 },
      role:  { type: "string", enum: ["admin", "user", "guest"] },
    },
    additionalProperties: false,
  };

  b.jsonSafe.validate({ email: "alice@example.com", age: 30, role: "admin" }, schema);
  check("validate good object passes silently", true);

  var emailRejected = false;
  try { b.jsonSafe.validate({ email: "not-email", age: 30 }, schema); }
  catch (e) { emailRejected = e.code === "json/validation" && /format 'email'/.test(e.message); }
  check("validate bad email format throws",                emailRejected);

  var requiredRejected = false;
  try { b.jsonSafe.validate({ email: "a@b.com" }, schema); }
  catch (e) { requiredRejected = /missing required key 'age'/.test(e.message); }
  check("validate missing required throws",                requiredRejected);

  var rangeRejected = false;
  try { b.jsonSafe.validate({ email: "a@b.com", age: -1 }, schema); }
  catch (e) { rangeRejected = /minimum/.test(e.message); }
  check("validate range violation throws",                 rangeRejected);

  var enumRejected = false;
  try { b.jsonSafe.validate({ email: "a@b.com", age: 30, role: "superuser" }, schema); }
  catch (e) { enumRejected = /not in enum/.test(e.message); }
  check("validate enum violation throws",                  enumRejected);

  var unknownKeyRejected = false;
  try { b.jsonSafe.validate({ email: "a@b.com", age: 30, hax: 1 }, schema); }
  catch (e) { unknownKeyRejected = /unknown key 'hax'/.test(e.message); }
  check("validate unknown key with additionalProperties:false throws", unknownKeyRejected);

  var arrSchema = { type: "array", minItems: 1, items: { type: "integer" } };
  b.jsonSafe.validate([1, 2, 3], arrSchema);
  var arrItemRejected = false;
  try { b.jsonSafe.validate([1, "two", 3], arrSchema); }
  catch (e) { arrItemRejected = e.path === "$[1]" && /expected integer/.test(e.message); }
  check("validate array item path is reported",            arrItemRejected);
}

function testJsonValidateCollect() {
  var schema = {
    type: "object",
    required: ["email", "age", "name"],
    properties: {
      email: { type: "string", format: "email" },
      age:   { type: "integer", minimum: 0 },
      name:  { type: "string", minLength: 1, maxLength: 100 },
      role:  { type: "string", enum: ["admin", "user"] },
    },
  };
  var bad = { email: "not-email", age: -5, name: "", role: "superuser" };
  var result = b.jsonSafe.validate(bad, schema, { collectErrors: true });
  check("collectErrors returns { ok, value, errors }",      typeof result === "object" && result.ok === false);
  check("collectErrors collects multiple errors",           result.errors.length >= 4);
  check("collectErrors errors have .path",                  result.errors.every(function (e) { return typeof e.path === "string"; }));
  check("collectErrors errors include format failure",      result.errors.some(function (e) { return /format 'email'/.test(e.message); }));
  check("collectErrors errors include range failure",       result.errors.some(function (e) { return /minimum/.test(e.message); }));
  check("collectErrors errors include length failure",      result.errors.some(function (e) { return /minLength/.test(e.message); }));
  check("collectErrors errors include enum failure",        result.errors.some(function (e) { return /not in enum/.test(e.message); }));

  var good = { email: "a@b.com", age: 30, name: "Alice" };
  var goodResult = b.jsonSafe.validate(good, schema, { collectErrors: true });
  check("collectErrors ok=true on valid input",             goodResult.ok === true && goodResult.errors.length === 0);

  var parseResult = b.jsonSafe.parse(JSON.stringify(bad), { schema: schema, collectErrors: true });
  check("parse + collectErrors returns { ok, value, errors[] }",
        typeof parseResult === "object" && parseResult.ok === false && parseResult.errors.length >= 4);
}

function testJsonFormats() {
  check("format email: valid passes",        b.jsonSafe.formats.email("alice@example.com"));
  check("format email: missing @ fails",     !b.jsonSafe.formats.email("not-email"));
  check("format url: https passes",          b.jsonSafe.formats.url("https://example.com/path"));
  check("format url: ftp fails (not in allowlist)", !b.jsonSafe.formats.url("ftp://example.com"));
  check("format uuid: valid passes",         b.jsonSafe.formats.uuid("550e8400-e29b-41d4-a716-446655440000"));
  check("format uuid: too-short fails",      !b.jsonSafe.formats.uuid("550e8400"));
  check("format ulid: valid passes",         b.jsonSafe.formats.ulid("01ARZ3NDEKTSV4RRFFQ69G5FAV"));
  check("format ipv4: valid passes",         b.jsonSafe.formats.ipv4("192.168.1.1"));
  check("format ipv4: out of range fails",   !b.jsonSafe.formats.ipv4("192.168.1.256"));
  check("format ipv4: leading zero fails",   !b.jsonSafe.formats.ipv4("192.168.001.1"));
  check("ipv6: full 8 groups",                          b.jsonSafe.formats.ipv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334"));
  check("ipv6: lowercase",                              b.jsonSafe.formats.ipv6("2001:db8::1"));
  check("ipv6: mixed case",                             b.jsonSafe.formats.ipv6("2001:DB8::1"));
  check("ipv6: loopback ::1",                           b.jsonSafe.formats.ipv6("::1"));
  check("ipv6: unspecified ::",                         b.jsonSafe.formats.ipv6("::"));
  check("ipv6: trailing :: (1::)",                      b.jsonSafe.formats.ipv6("1::"));
  check("ipv6: link-local fe80::1",                     b.jsonSafe.formats.ipv6("fe80::1"));
  check("ipv6: IPv4-mapped ::ffff:192.168.1.1",         b.jsonSafe.formats.ipv6("::ffff:192.168.1.1"));
  check("ipv6: IPv4-mapped uppercase",                  b.jsonSafe.formats.ipv6("::FFFF:192.168.1.1"));
  check("ipv6: longer IPv4-mapped form",                b.jsonSafe.formats.ipv6("2001:db8::192.0.2.1"));
  check("ipv6: rejects > 8 groups",                     !b.jsonSafe.formats.ipv6("1:2:3:4:5:6:7:8:9"));
  check("ipv6: rejects multiple ::",                    !b.jsonSafe.formats.ipv6("1::2::3"));
  check("ipv6: rejects non-hex chars",                  !b.jsonSafe.formats.ipv6("g::"));
  check("ipv6: rejects > 4 hex per group",              !b.jsonSafe.formats.ipv6("12345::"));
  check("ipv6: rejects zone IDs",                       !b.jsonSafe.formats.ipv6("fe80::1%eth0"));
  check("ipv6: rejects empty string",                   !b.jsonSafe.formats.ipv6(""));
  check("ipv6: rejects too long",                       !b.jsonSafe.formats.ipv6("a".repeat(46)));
  check("ipv6: rejects bad IPv4-mapped",                !b.jsonSafe.formats.ipv6("::ffff:999.168.1.1"));
  check("format hex: valid passes",          b.jsonSafe.formats.hex("dead beef".replace(" ", "")));
  check("format slug: valid passes",         b.jsonSafe.formats.slug("my-blog-post"));
  check("format slug: uppercase fails",      !b.jsonSafe.formats.slug("MyBlogPost"));
  check("format iso8601-date: valid passes", b.jsonSafe.formats["iso8601-date"]("2026-04-25"));
  check("format iso8601-date: invalid fails",!b.jsonSafe.formats["iso8601-date"]("2026-13-01"));

  b.jsonSafe.registerFormat("us-zip", function (v) { return /^\d{5}(-\d{4})?$/.test(v); });
  check("custom format registered + works",  b.jsonSafe.formats["us-zip"]("12345"));
  b.jsonSafe.validate("90210", { type: "string", format: "us-zip" });
  var customRejected = false;
  try { b.jsonSafe.validate("ABCDE", { type: "string", format: "us-zip" }); }
  catch (e) { customRejected = /format 'us-zip'/.test(e.message); }
  check("custom format used by validate",    customRejected);
}

// ---- run() ----

async function run() {
  // async-safe primitives
  await testAsyncSafeWithTimeoutResolves();
  await testAsyncSafeWithTimeoutRejects();
  await testAsyncSafeWithTimeoutAbort();
  await testAsyncSafeWithTimeoutPropagatesError();
  await testAsyncSafeSafeAwait();
  await testAsyncSafeMutexSerializes();
  await testAsyncSafeMutexReleaseOnThrow();
  await testAsyncSafeMutexAbortableAcquire();
  await testAsyncSafeSemaphoreBoundedConcurrency();
  await testAsyncSafeSemaphoreAbortableAcquire();
  await testAsyncSafeOnceSingleFlight();
  await testAsyncSafeOnceCachesFailure();
  await testAsyncSafeOnceReset();
  await testAsyncSafeCircuitBreakerStateTransitions();
  // handlers primitive
  await testHandlerEmitAndDrain();
  await testHandlerEmitDuringFlushNextCycle();
  await testHandlerRetryOnFlushFailure();
  await testHandlerCircuitBreakerOpensOnPersistentFailure();
  await testHandlerBoundedShutdown();
  await testHandlerStats();
  await testHandlerBackpressureDrop();
  // sql-safe primitive
  testSqlSafeIdentifierValidation();
  testSqlSafeQuoteIdentifier();
  testSqlSafeAssertOneOf();
  // chain-writer primitive (cross-layer; documented in test header)
  await testChainWriterRejectsBadTable();
  await testChainWriterRaceSafetyConcurrentAppends();
  // json-safe primitive
  testJsonModuleSurface();
  testJsonParse();
  testJsonStringify();
  testJsonCanonical();
  testJsonValidate();
  testJsonValidateCollect();
  testJsonFormats();
}

module.exports = {
  name: "Layer 0 — primitives (async-safe, handlers, sql-safe, chain-writer, json-safe)",
  run:  run,
  // Exported individually so smoke.js (or future selective-run tooling)
  // can reach them by name without going through run().
  testAsyncSafeWithTimeoutResolves:          testAsyncSafeWithTimeoutResolves,
  testAsyncSafeWithTimeoutRejects:           testAsyncSafeWithTimeoutRejects,
  testAsyncSafeWithTimeoutAbort:             testAsyncSafeWithTimeoutAbort,
  testAsyncSafeWithTimeoutPropagatesError:   testAsyncSafeWithTimeoutPropagatesError,
  testAsyncSafeSafeAwait:                    testAsyncSafeSafeAwait,
  testAsyncSafeMutexSerializes:              testAsyncSafeMutexSerializes,
  testAsyncSafeMutexReleaseOnThrow:          testAsyncSafeMutexReleaseOnThrow,
  testAsyncSafeMutexAbortableAcquire:        testAsyncSafeMutexAbortableAcquire,
  testAsyncSafeSemaphoreBoundedConcurrency:  testAsyncSafeSemaphoreBoundedConcurrency,
  testAsyncSafeSemaphoreAbortableAcquire:    testAsyncSafeSemaphoreAbortableAcquire,
  testAsyncSafeOnceSingleFlight:             testAsyncSafeOnceSingleFlight,
  testAsyncSafeOnceCachesFailure:            testAsyncSafeOnceCachesFailure,
  testAsyncSafeOnceReset:                    testAsyncSafeOnceReset,
  testAsyncSafeCircuitBreakerStateTransitions: testAsyncSafeCircuitBreakerStateTransitions,
  testHandlerEmitAndDrain:                   testHandlerEmitAndDrain,
  testHandlerEmitDuringFlushNextCycle:       testHandlerEmitDuringFlushNextCycle,
  testHandlerRetryOnFlushFailure:            testHandlerRetryOnFlushFailure,
  testHandlerCircuitBreakerOpensOnPersistentFailure: testHandlerCircuitBreakerOpensOnPersistentFailure,
  testHandlerBoundedShutdown:                testHandlerBoundedShutdown,
  testHandlerStats:                          testHandlerStats,
  testHandlerBackpressureDrop:               testHandlerBackpressureDrop,
  testSqlSafeIdentifierValidation:           testSqlSafeIdentifierValidation,
  testSqlSafeQuoteIdentifier:                testSqlSafeQuoteIdentifier,
  testSqlSafeAssertOneOf:                    testSqlSafeAssertOneOf,
  testChainWriterRejectsBadTable:            testChainWriterRejectsBadTable,
  testChainWriterRaceSafetyConcurrentAppends: testChainWriterRaceSafetyConcurrentAppends,
  testJsonModuleSurface:                     testJsonModuleSurface,
  testJsonParse:                             testJsonParse,
  testJsonStringify:                         testJsonStringify,
  testJsonCanonical:                         testJsonCanonical,
  testJsonValidate:                          testJsonValidate,
  testJsonValidateCollect:                   testJsonValidateCollect,
  testJsonFormats:                           testJsonFormats,
};
