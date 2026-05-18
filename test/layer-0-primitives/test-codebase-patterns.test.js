"use strict";
/**
 * test-side codebase-patterns — enforces test-discipline rules over
 * `test/` files the way `codebase-patterns.test.js` enforces them
 * over `lib/`. Keeps the test-side catalog separated so production
 * antipatterns and test antipatterns don't fight for space in one
 * file and the path-domain of each scan is unambiguous.
 *
 * Discipline (mirrors codebase-patterns.test.js):
 *   1. Every entry registers an inline shape with a regex, a primitive
 *      pointer, an allowlist (defaults to []), and a `reason` field.
 *   2. Adding an allowlist entry later requires a documented reason
 *      in the entry's `reason` field; the pre-ship rules audit calls
 *      out every allowlist change.
 *   3. Entries are scanned against the full repository's `test/` tree.
 *
 * Why this gate exists: the v0.10.13 PR #102 macOS hang on
 * stream-throttle.test.js (a setTimeout-based rate test interacting
 * badly with node:stream.pipeline on macOS) burned >2h of CI before
 * surfacing — by the time the smoke runner gave up, the wall-clock
 * cost dwarfed the actual signal. A per-test wall-clock ceiling
 * surfaces hangs as `test timed out: <label>` in seconds. The
 * detector below enforces that every NEW test using real-time
 * primitives wraps each test body with `helpers.withTestTimeout`.
 */

var fs = require("fs");
var path = require("path");
var helpers = require("../helpers");
var check = helpers.check;

var TEST_ROOT = path.resolve(__dirname, "..");

function _walk(dir, files) {
  files = files || [];
  var entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
  catch (_e) { return files; }
  for (var i = 0; i < entries.length; i++) {
    var e = entries[i];
    var full = path.join(dir, e.name);
    if (e.isDirectory()) _walk(full, files);
    else if (e.isFile() && e.name.endsWith(".js")) files.push(full);
  }
  return files;
}

function _relPath(absPath) {
  return path.relative(path.resolve(__dirname, "..", ".."), absPath).replace(/\\/g, "/");
}

// KNOWN_TEST_ANTIPATTERNS — n=1 gate over `test/` files.
//
// Each entry: { id, primitive, regex, allowlist, reason }. The runner
// scans every test file (recursively) and fails the gate if a regex
// matches a file not in its allowlist.
var KNOWN_TEST_ANTIPATTERNS = [
  {
    // v0.10.13 PR #102 macOS hang — stream-throttle.test.js used
    // `setTimeout`-based rate enforcement plus `node:stream.pipeline`
    // and hung the macOS GitHub Actions runner for >2h on two
    // separate commit SHAs of the same branch. Identical runs on the
    // same SHA succeeded in 15 min. The hang's symptom is opaque on
    // a remote runner (no partial logs surface until completion), so
    // the only diagnostic is a per-test wall-clock ceiling.
    //
    // Rule: any test file using `setTimeout` for synchronization OR
    // any `node:stream.pipeline` call MUST also import
    // `withTestTimeout` from `test/helpers` and wrap each affected
    // test body. The wait helpers (`waitUntil` / `waitUntilEqual`)
    // are exempt because they already enforce their own bound.
    id: "test-uses-stream-pipeline-without-withtesttimeout",
    primitive: "wrap stream.pipeline-using test bodies with helpers.withTestTimeout(label, async function () { ... })",
    // Narrow to `stream.pipeline` (the specific shape that hung
    // macOS); plain `setTimeout` use is broad enough that the
    // existing waitUntil discipline already handles the noisy cases.
    regex: /\b(?:stream\.pipeline|nodeStream\.pipeline|streamPipeline)\s*\(/,
    allowlist: [
      // Tests intentionally exercising the timing helpers themselves
      // can't wrap themselves with the helper they're testing.
      "test/helpers/wait.js",
    ],
    reason: "Real-time-dependent tests using node:stream.pipeline without a per-test wall-clock ceiling can hang the smoke runner for the full GH Actions 6h timeout — see the v0.10.13 PR #102 macOS hang on stream-throttle's setTimeout-based rate test. New tests using stream.pipeline MUST import `withTestTimeout` from `test/helpers` and wrap each test body so a hang surfaces as `test timed out: <label>` in seconds instead of an opaque stuck job.",
  },
];

function _testFiles() {
  var all = _walk(TEST_ROOT);
  return all.filter(function (f) {
    var rel = _relPath(f);
    if (rel.indexOf("test/.test-output") === 0) return false;
    return /\.test\.js$|^test\/helpers\/|^test\/smoke\.js$/.test(rel);
  });
}

function testKnownTestAntipatterns() {
  var files = _testFiles();
  var allBad = [];
  for (var ai = 0; ai < KNOWN_TEST_ANTIPATTERNS.length; ai++) {
    var ap = KNOWN_TEST_ANTIPATTERNS[ai];
    var allowSet = Object.create(null);
    for (var k = 0; k < ap.allowlist.length; k++) allowSet[ap.allowlist[k]] = true;
    // Self-exemption — this catalog file contains the regex source
    // itself, which trips its own detector. Always exempts itself.
    allowSet["test/layer-0-primitives/test-codebase-patterns.test.js"] = true;
    var bad = [];
    for (var fi = 0; fi < files.length; fi++) {
      var rel = _relPath(files[fi]);
      if (allowSet[rel]) continue;
      var content;
      try { content = fs.readFileSync(files[fi], "utf8"); }
      catch (_e) { continue; }
      if (!ap.regex.test(content)) continue;
      // The file matched. If it ALSO names `withTestTimeout` the
      // discipline is satisfied (the file imports + uses the helper).
      if (/\bwithTestTimeout\b/.test(content)) continue;
      var firstMatch = content.match(ap.regex);
      var lineNum = firstMatch
        ? content.slice(0, content.indexOf(firstMatch[0])).split(/\r?\n/).length
        : 1;
      bad.push({
        file: rel,
        line: lineNum,
        content: "test-antipattern '" + ap.id + "' — use " + ap.primitive,
      });
    }
    if (bad.length) {
      allBad = allBad.concat(bad);
      console.log("FAIL: test-antipattern '" + ap.id + "' — use " + ap.primitive);
      for (var bi = 0; bi < bad.length; bi++) {
        console.log("  " + bad[bi].file + ":" + bad[bi].line + ": " + bad[bi].content);
      }
      console.log("  why: " + ap.reason);
    }
  }
  check("known-test-antipattern catalog (n=1 gate)", allBad.length === 0);
}

async function run() {
  testKnownTestAntipatterns();
}

if (require.main === module) {
  try { run(); }
  catch (e) { console.error(e); process.exit(1); }
}
module.exports = { run: run };
