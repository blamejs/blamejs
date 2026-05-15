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

function run() {
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
}

module.exports = { run: run };

if (require.main === module) {
  try { run(); }
  catch (e) { process.stderr.write("FAIL: " + (e && e.stack || e) + "\n"); process.exit(1); }
}
