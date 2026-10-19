// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.middleware.composePipeline — order-aware middleware composer.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function _passMw(tag) {
  return function (req, res, next) {
    req._tags = (req._tags || []);
    req._tags.push(tag);
    next();
  };
}

function _bailMw(err) {
  return function (req, res, next) { next(err); };
}

function _throwMw(err) {
  return function (req, res, next) { throw err; };
}

function _expectCode(label, fn, code) {
  var threw = null;
  try { fn(); } catch (e) { threw = e; }
  check(label, threw && (threw.code || "").indexOf(code) !== -1);
}

function testSurface() {
  check("composePipeline is fn",
        typeof b.middleware.composePipeline === "function");
  check("composePipeline.CANONICAL_POSITIONS exposed",
        typeof b.middleware.composePipeline.CANONICAL_POSITIONS === "object");
  check("composePipeline.ComposePipelineError exposed",
        typeof b.middleware.composePipeline.ComposePipelineError === "function");
}

function testSequentialDispatch() {
  var pipe = b.middleware.composePipeline([
    { name: "first",  mw: _passMw("a") },
    { name: "second", mw: _passMw("b") },
    { name: "third",  mw: _passMw("c") },
  ]);
  var req = {}; var res = {};
  var finalCalled = false;
  pipe(req, res, function (err) { finalCalled = !err; });
  check("3 middlewares dispatched in order",
        req._tags && req._tags.join("") === "abc");
  check("finalNext called",  finalCalled === true);
}

function testCanonicalPositionsAutoOrder() {
  // No explicit positions; canonical names → canonical buckets.
  var pipe = b.middleware.composePipeline([
    { name: "apiEncrypt",  mw: _passMw("e") },
    { name: "bodyParser",  mw: _passMw("b") },
    { name: "csrf",        mw: _passMw("c") },
  ]);
  var req = {}; var res = {};
  pipe(req, res, function () {});
  check("canonical order preserved", req._tags.join("") === "ebc");
}

function testNonMonotonicRefused() {
  // Operator supplies explicit positions out of order.
  _expectCode("non-monotonic refused",
    function () {
      b.middleware.composePipeline([
        { name: "a", mw: _passMw("a"), position: 50 },
        { name: "b", mw: _passMw("b"), position: 30 },
      ]);
    },
    "compose-pipeline/non-monotonic");
}

function testDuplicateNameRefused() {
  _expectCode("duplicate name refused",
    function () {
      b.middleware.composePipeline([
        { name: "csrf", mw: _passMw("a") },
        { name: "csrf", mw: _passMw("b") },
      ]);
    },
    "compose-pipeline/duplicate-name");
}

function testDuplicatePositionExplicitRefused() {
  _expectCode("duplicate explicit position refused",
    function () {
      b.middleware.composePipeline([
        { name: "a", mw: _passMw("a"), position: 30 },
        { name: "b", mw: _passMw("b"), position: 30 },
      ]);
    },
    "compose-pipeline/duplicate-position");
}

function testCanonicalDuplicatePositionAllowed() {
  // csrf + idempotency both have canonical position 30 — same
  // position from canonical defaults is ALLOWED (operator didn't
  // explicitly conflict).
  var pipe = b.middleware.composePipeline([
    { name: "csrf",        mw: _passMw("c") },
    { name: "idempotency", mw: _passMw("i") },
  ]);
  var req = {}; var res = {};
  pipe(req, res, function () {});
  check("canonical duplicate position allowed", req._tags.join("") === "ci");
}

function testStrictModeRefusesCanonicalMismatch() {
  // Operator supplies csrf with position 999 (canonical is 30);
  // strict=true refuses.
  _expectCode("strict canonical mismatch refused",
    function () {
      b.middleware.composePipeline([
        { name: "csrf", mw: _passMw("c"), position: 999 },
      ], { strict: true });
    },
    "compose-pipeline/canonical-mismatch");
}

function testNonStrictModeWarnsButRuns() {
  // Same supply with strict=false — runs (audit warning emitted).
  var pipe = b.middleware.composePipeline([
    { name: "csrf", mw: _passMw("c"), position: 999 },
  ]);
  var req = {}; var res = {};
  pipe(req, res, function () {});
  check("non-strict mismatch runs",  req._tags.join("") === "c");
}

function testErrorPropagation() {
  var sentinel = new Error("boom-async");
  var pipe = b.middleware.composePipeline([
    { name: "first", mw: _passMw("a") },
    { name: "fail",  mw: _bailMw(sentinel) },
    { name: "third", mw: _passMw("c") },  // should NOT execute
  ]);
  var req = {}; var res = {};
  var capturedErr = null;
  pipe(req, res, function (err) { capturedErr = err; });
  check("error propagated to finalNext", capturedErr === sentinel);
  check("middlewares after error skipped", req._tags.join("") === "a");
}

function testSyncThrowPropagation() {
  var sentinel = new Error("boom-sync");
  var pipe = b.middleware.composePipeline([
    { name: "first",   mw: _passMw("a") },
    { name: "thrower", mw: _throwMw(sentinel) },
  ]);
  var req = {}; var res = {};
  var capturedErr = null;
  pipe(req, res, function (err) { capturedErr = err; });
  check("sync throw caught + propagated", capturedErr === sentinel);
}

function testBadEntriesRefused() {
  _expectCode("non-array refused",
    function () { b.middleware.composePipeline("not-an-array"); },
    "compose-pipeline/bad-entries");

  _expectCode("empty array refused",
    function () { b.middleware.composePipeline([]); },
    "compose-pipeline/bad-entries");

  _expectCode("missing mw refused",
    function () { b.middleware.composePipeline([{ name: "x" }]); },
    "compose-pipeline/bad-entry");

  _expectCode("missing name refused",
    function () { b.middleware.composePipeline([{ mw: _passMw("a") }]); },
    "compose-pipeline/bad-entry");

  _expectCode("empty name refused",
    function () { b.middleware.composePipeline([{ name: "", mw: _passMw("a") }]); },
    "compose-pipeline/bad-entry");

  _expectCode("non-function mw refused",
    function () { b.middleware.composePipeline([{ name: "x", mw: "not-a-fn" }]); },
    "compose-pipeline/bad-entry");

  _expectCode("negative position refused",
    function () { b.middleware.composePipeline([{ name: "x", mw: _passMw("a"), position: -1 }]); },
    "compose-pipeline/bad-position");
}

async function testAsyncMiddlewareAwaited() {
  // Async middleware MUST be awaited so the router sees the next-flag
  // set before composedPipeline's promise resolves. Without awaiting,
  // composedPipeline returns undefined synchronously and the router
  // exits the request early before async middleware (e.g. bodyParser
  // reading the request body) have actually called next().
  var pipe = b.middleware.composePipeline([
    { name: "asyncA", mw: async function (req, res, next) {
      await helpers.passiveObserve(10, "compose-pipeline: asyncA simulated work");
      req._tags = (req._tags || "") + "A";
      next();
    } },
    { name: "asyncB", mw: async function (req, res, next) {
      await helpers.passiveObserve(10, "compose-pipeline: asyncB simulated work");
      req._tags = (req._tags || "") + "B";
      next();
    } },
  ]);
  var req = {}; var res = {};
  var finalCalled = false;
  // composedPipeline must return a promise that resolves AFTER the
  // entire chain has run.
  await pipe(req, res, function () { finalCalled = true; });
  check("async chain ran to completion", req._tags === "AB");
  check("finalNext called after async chain", finalCalled === true);
}

async function testErrorMiddlewareReceivesError() {
  // When next(err) fires, the chain should skip 3-arg middleware and
  // dispatch to the first 4-arg "error handler" middleware. This is
  // the Express convention the framework's b.middleware.errorHandler
  // is built around.
  var capturedErr = null;
  var sentinel = new Error("boom");
  var pipe = b.middleware.composePipeline([
    { name: "first",        mw: _passMw("a"),       position: 10 },
    { name: "failing",      mw: _bailMw(sentinel),  position: 20 },
    { name: "shouldSkip",   mw: _passMw("z"),       position: 30 }, // 3-arg, should be skipped
    { name: "errorHandler", mw: function (err, req, res, _next) {
      capturedErr = err;
    }, position: 40 },
  ]);
  var req = {}; var res = {};
  await pipe(req, res, function () {});
  check("3-arg middleware skipped on error path",
    req._tags && req._tags.indexOf("z") === -1);
  check("4-arg error handler received the error", capturedErr === sentinel);
}

async function testFinalNextFallbackOnUnhandledError() {
  // If no error-handler entry exists, the error propagates to
  // finalNext so the framework router can handle it.
  var capturedErr = null;
  var sentinel = new Error("unhandled");
  var pipe = b.middleware.composePipeline([
    { name: "first",   mw: _passMw("a") },
    { name: "failing", mw: _bailMw(sentinel) },
  ]);
  var req = {}; var res = {};
  await pipe(req, res, function (err) { capturedErr = err; });
  check("error propagates to finalNext when no error-handler in chain",
    capturedErr === sentinel);
}

async function testHaltingMiddlewareSettlesPromise() {
  // A regular (3-arg) middleware that writes the response and returns
  // WITHOUT calling next() halts the chain — the documented "this
  // middleware handled the request" pattern (auth/rate-limit/bot block).
  // The composed promise MUST still settle; a permanently-pending
  // promise retains its req/res closure forever (memory leak under
  // sustained blocked traffic). finalNext must NOT fire — the chain was
  // halted, so the caller's next-flag stays false and the router does
  // not proceed to the route handler.
  var finalCalled = false;
  var pipe = b.middleware.composePipeline([
    { name: "pass", mw: _passMw("a") },
    { name: "halt", mw: function (req, res, next) { res.writableEnded = true; /* ended response, no next() */ } },
    { name: "after", mw: _passMw("z") },
  ]);
  var req = {}; var res = {};
  var settled = false;
  pipe(req, res, function () { finalCalled = true; }).then(function () { settled = true; });
  try {
    await helpers.waitUntil(function () { return settled; },
      { timeoutMs: 2000, label: "compose-pipeline: halting middleware settles the composed promise" });
  } catch (_e) { /* stays false on the buggy tree → check fails RED */ }
  check("halting middleware settles the composed promise", settled === true);
  check("downstream middleware not run after a halt",
    !req._tags || req._tags.indexOf("z") === -1);
  check("finalNext NOT called when a middleware halts the chain", finalCalled === false);
}

async function testHandledErrorSettlesWithoutFinalNext() {
  // An error handler that consumes the error WITHOUT calling next has
  // handled the request (same halt contract as a 3-arg middleware): the
  // promise settles but finalNext must not fire, so the caller does not
  // proceed to the route handler on top of an already-sent error page.
  var finalCalled = false;
  var sentinel = new Error("boom");
  var pipe = b.middleware.composePipeline([
    { name: "failing",      mw: _bailMw(sentinel),                                                            position: 10 },
    { name: "errorHandler", mw: function (err, req, res, _next) { res._handled = err; res.writableEnded = true; }, position: 20 },
  ]);
  var req = {}; var res = {};
  var settled = false;
  pipe(req, res, function () { finalCalled = true; }).then(function () { settled = true; });
  try {
    await helpers.waitUntil(function () { return settled; },
      { timeoutMs: 2000, label: "compose-pipeline: handled error settles the composed promise" });
  } catch (_e) { /* RED if it hangs */ }
  check("handled error settles the composed promise", settled === true);
  check("error handler consumed the error", res._handled === sentinel);
  check("finalNext NOT called when an error handler halts the chain", finalCalled === false);
}

async function testDeferredNextContinuesChain() {
  // A callback-style middleware that calls next() LATER (from a timer, stream,
  // or legacy callback) returns before next() runs. The pipeline must NOT treat
  // that bare return as a halt: the chain continues when the deferred next()
  // fires, downstream middleware run, and finalNext is called.
  var finalCalled = false;
  var pipe = b.middleware.composePipeline([
    { name: "a", mw: _passMw("a") },
    { name: "deferred", mw: function (req, res, next) {
      setTimeout(function () { req._tags.push("deferred"); next(); }, 5);
    } },
    { name: "c", mw: _passMw("c") },
  ]);
  var req = {}; var res = {};
  await pipe(req, res, function (err) { finalCalled = !err; });
  check("deferred next() continues the chain (callback-style middleware)",
    req._tags && req._tags.join("") === "adeferredc");
  check("finalNext called after a deferred next()", finalCalled === true);
}

async function testNextIsSingleUsePerInvocation() {
  // Entry one calls next() once, then keeps the callback and calls it
  // again later. The gate after it never calls next(). The stored second
  // call must not move the request past the gate.
  var storedNext = null;
  var finalCalled = false;
  var pipe = b.middleware.composePipeline([
    { name: "first", mw: function (req, res, next) {
      req._tags = ["first"];
      storedNext = next;
      next();
    } },
    { name: "gate", mw: function (req, res, _next) {
      req._tags.push("gate");
    } },
    { name: "after", mw: _passMw("after") },
  ]);
  var req = {}; var res = {};
  pipe(req, res, function () { finalCalled = true; });
  check("compose-pipeline: the gate ran once", req._tags.join(",") === "first,gate");
  storedNext();
  await helpers.passiveObserve(20, "compose-pipeline: a stored next() call settles");
  check("compose-pipeline: a duplicate next() does not run the entry after the gate",
    req._tags.indexOf("after") === -1);
  check("compose-pipeline: a duplicate next() does not reach finalNext", finalCalled === false);
  check("compose-pipeline: a duplicate next() does not run the gate again",
    req._tags.join(",") === "first,gate");
}

async function testThrowAfterNextDoesNotAdvance() {
  // Entry one calls next() and then throws. The gate never calls next().
  // The throw must not move the request past the gate or reach the
  // error-handler slot behind it; the composed promise rejects with it.
  var sentinel = new Error("after-next");
  var finalCalled = false;
  var handlerSaw = null;
  var pipe = b.middleware.composePipeline([
    { name: "first", mw: function (req, res, next) {
      req._tags = ["first"];
      next();
      throw sentinel;
    } },
    { name: "gate", mw: function (req, res, _next) { req._tags.push("gate"); } },
    { name: "after", mw: _passMw("after") },
    { name: "lateErrors", mw: function (err, req, res, _next) { handlerSaw = err; } },
  ]);
  var req = {}; var res = {};
  var rejected = null;
  await pipe(req, res, function () { finalCalled = true; }).then(null, function (e) { rejected = e; });
  check("compose-pipeline: a throw after next() rejects the composed promise", rejected === sentinel);
  check("compose-pipeline: a throw after next() does not run the entries after the gate",
    req._tags.join(",") === "first,gate");
  check("compose-pipeline: a throw after next() does not reach the error handler", handlerSaw === null);
  check("compose-pipeline: a throw after next() does not reach finalNext", finalCalled === false);
}

async function _runCapturingStderr(fn) {
  var lines = [];
  var origConsoleError = console.error;
  console.error = function () {
    lines.push(Array.prototype.slice.call(arguments).map(String).join(" "));
  };
  try { await fn(); }
  finally { console.error = origConsoleError; }
  return lines;
}

async function testThrowAfterChainFinishedIsReported() {
  // Entry one calls next(), the rest of the chain runs synchronously and
  // reaches finalNext inside that call, and entry one then throws. The
  // composed promise has already resolved and finalNext has already run,
  // so the throw cannot change the outcome; it is written to the log
  // naming the entry and the error code.
  var shapes = [
    { label: "sync", mw: function (req, res, next) {
      next();
      var e = new Error("thrown-after-next"); e.code = "app/late-sync"; throw e;
    } },
    { label: "async", mw: async function (req, res, next) {
      next();
      var e = new Error("async-thrown-after-next"); e.code = "app/late-async"; throw e;
    } },
  ];
  for (var i = 0; i < shapes.length; i++) {
    var shape = shapes[i];
    var finalCalls = 0;
    var outcome = "pending";
    var lines = await _runCapturingStderr(async function () {
      var pipe = b.middleware.composePipeline([
        { name: "first",  mw: shape.mw },
        { name: "second", mw: function (req, res, next) { next(); } },
      ]);
      await pipe({}, {}, function () { finalCalls += 1; })
        .then(function () { outcome = "resolved"; }, function (e) { outcome = "rejected:" + e.message; });
      await helpers.passiveObserve(20, "compose-pipeline: a late throw is reported in this window");
    });
    var code = shape.label === "sync" ? "app/late-sync" : "app/late-async";
    check("compose-pipeline (" + shape.label + "): finalNext ran once before the late throw", finalCalls === 1);
    check("compose-pipeline (" + shape.label + "): the composed promise keeps its resolved outcome",
      outcome === "resolved");
    check("compose-pipeline (" + shape.label + "): a throw after the chain finished is logged with the entry and code",
      lines.some(function (l) { return l.indexOf("'first'") !== -1 && l.indexOf(code) !== -1; }));
    check("compose-pipeline (" + shape.label + "): the late-throw log line does not carry the error message",
      lines.every(function (l) { return l.indexOf("thrown-after-next") === -1; }));
  }
}

async function testThrowAfterResponseClosedIsReported() {
  // The client disconnects (res emits close) while a middleware is still
  // running, and the middleware then throws without calling next. The
  // composed promise has already settled, so the throw is logged.
  var EventEmitter = require("node:events");
  var res = new EventEmitter();
  var lines = await _runCapturingStderr(async function () {
    var pipe = b.middleware.composePipeline([
      { name: "slow", mw: async function (req, r, _next) {
        await null;
        r.emit("close");
        var e = new Error("after-close"); e.code = "app/after-close"; throw e;
      } },
    ]);
    await pipe({}, res, function () {});
    await helpers.passiveObserve(20, "compose-pipeline: a throw after close is reported in this window");
  });
  check("compose-pipeline: a throw after the response closed is logged",
    lines.some(function (l) { return l.indexOf("'slow'") !== -1 && l.indexOf("app/after-close") !== -1; }));
}

async function run() {
  testSurface();
  testSequentialDispatch();
  testCanonicalPositionsAutoOrder();
  testNonMonotonicRefused();
  testDuplicateNameRefused();
  testDuplicatePositionExplicitRefused();
  testCanonicalDuplicatePositionAllowed();
  testStrictModeRefusesCanonicalMismatch();
  testNonStrictModeWarnsButRuns();
  testErrorPropagation();
  testSyncThrowPropagation();
  testBadEntriesRefused();
  await testAsyncMiddlewareAwaited();
  await testErrorMiddlewareReceivesError();
  await testFinalNextFallbackOnUnhandledError();
  await testHaltingMiddlewareSettlesPromise();
  await testHandledErrorSettlesWithoutFinalNext();
  await testDeferredNextContinuesChain();
  await testNextIsSingleUsePerInvocation();
  await testThrowAfterNextDoesNotAdvance();
  await testThrowAfterChainFinishedIsReported();
  await testThrowAfterResponseClosedIsReported();
}

module.exports = { run: run };

if (require.main === module) {
  run().catch(function (e) { process.stderr.write("FAIL: " + (e && e.stack || e) + "\n"); process.exit(1); });
}
