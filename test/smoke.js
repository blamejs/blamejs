"use strict";
/**
 * Smoke test — orchestrator only.
 *
 * Run: `npm test` (or `node test/smoke.js`)
 *
 * Tests run in dependency order:
 *
 *   Layer 0 — pure primitives                test/00-primitives.js
 *                                            + test/layer-0-primitives/*.test.js
 *   Layer 1 — framework-state primitives     test/10-state.js
 *                                            + test/layer-1-state/*.test.js
 *   Layer 2 — db + framework-schema          test/20-db.js
 *                                            + test/layer-2-db/*.test.js
 *   Layer 3 — chain-writing + cluster-stg    test/30-chain.js
 *                                            + test/layer-3-chain/*.test.js
 *   Layer 4 — consumer modules               test/40-consumers.js
 *                                            + test/layer-4-consumers/*.test.js
 *   Layer 5 — operator-facing integration    test/50-integration.js
 *                                            + test/layer-5-integration/*.test.js
 *
 * Per-file layout (preferred for new tests):
 *   - One file per primitive / module, named `<thing>.test.js`.
 *   - Lives under `test/layer-N-<name>/`.
 *   - Exports `run()` (and optionally `groups[]`).
 *   - Has a CLI entry: `node test/layer-0-primitives/safe-schema.test.js`
 *     runs that file's tests standalone.
 *
 * The legacy single-layer files (00-primitives.js etc.) continue to
 * work alongside the per-file split during the migration window. The
 * orchestrator runs the legacy file FIRST, then walks the per-file
 * directory for the same layer.
 *
 * Shared infrastructure: test/helpers/ — db, mocks, drivers, cluster,
 * http, check. Re-exported from test/helpers/index.js for one-import
 * ergonomics.
 *
 * Per-test timing reported on stdout — drift detection without extra
 * tooling. Format:
 *
 *   <layer>
 *     <test-file>                              (totalMs)
 *
 * Failures throw with attribution: "<layer> / <file>" so the FIRST red
 * light points at the right test file.
 */

var fs   = require("node:fs");
var path = require("node:path");
var helpers = require("./helpers");
var b       = helpers.b;

console.log("blamejs v" + b.version + " — smoke test");

// Optional: HS_ONLY=safe-schema.test.js,pagination.test.js — run only
// those per-file tests across all layers (sequential, in arg order).
// Legacy layer files are skipped when HS_ONLY is set so the operator
// gets the iterate-on-one-file flow without re-running the monolith.
var ONLY = (process.env.HS_ONLY || "")
  .split(",").map(function (s) { return s.trim(); }).filter(Boolean);

function _padRight(s, n) {
  if (s.length >= n) return s;
  return s + " ".repeat(n - s.length);
}

function _layerDirFor(layerNum) {
  // Layer 0 → test/layer-0-primitives, Layer 1 → test/layer-1-state, etc.
  var names = ["primitives", "state", "db", "chain", "consumers", "integration"];
  var dir = path.join(__dirname, "layer-" + layerNum + "-" + names[layerNum]);
  if (!fs.existsSync(dir)) return null;
  return dir;
}

// Run a single test file. Backward compat with the legacy
// run() / groups[] export shapes; new files only need run().
async function _runTestModule(modulePath, displayName) {
  var mod = require(modulePath);
  var fileStart = Date.now();
  if (typeof mod.run === "function") {
    try { await mod.run(); }
    catch (err) {
      err.message = displayName + ": " + err.message;
      throw err;
    }
  }
  if (Array.isArray(mod.groups) && mod.groups.length > 0) {
    for (var i = 0; i < mod.groups.length; i++) {
      var group = mod.groups[i];
      var ctx = null;
      try {
        if (typeof group.setup === "function") ctx = await group.setup();
        for (var j = 0; j < group.tests.length; j++) {
          var t = group.tests[j];
          try { await t.run(ctx); }
          catch (err) {
            err.message = displayName + " / " + group.name + " / " + t.name + ": " + err.message;
            throw err;
          }
        }
      } finally {
        if (typeof group.teardown === "function") {
          try { await group.teardown(ctx); }
          catch (_e) { /* teardown errors don't mask test failures */ }
        }
      }
    }
  }
  return Date.now() - fileStart;
}

async function _runLayer(layerNum, legacyPath, layerName) {
  // Legacy single-layer file (run only when HS_ONLY isn't set).
  if (ONLY.length === 0 && fs.existsSync(legacyPath)) {
    var legacyMs = await _runTestModule(legacyPath, layerName + " / " + path.basename(legacyPath));
    console.log("  " + _padRight(path.basename(legacyPath), 40) + " (" + legacyMs + "ms)");
  }

  // Per-file tests under layer-N-*/ directory.
  var dir = _layerDirFor(layerNum);
  if (!dir) return;
  var files = fs.readdirSync(dir)
    .filter(function (f) { return f.endsWith(".test.js"); })
    .filter(function (f) { return ONLY.length === 0 || ONLY.indexOf(f) !== -1; })
    .sort();
  for (var i = 0; i < files.length; i++) {
    var fullPath = path.join(dir, files[i]);
    var ms = await _runTestModule(fullPath, layerName + " / " + files[i]);
    console.log("  " + _padRight(files[i], 40) + " (" + ms + "ms)");
  }
}

(async function () {
  var smokeStart = Date.now();
  console.log("Layer 0");
  await _runLayer(0, path.join(__dirname, "00-primitives.js"), "Layer 0");
  console.log("Layer 1");
  await _runLayer(1, path.join(__dirname, "10-state.js"),       "Layer 1");
  console.log("Layer 2");
  await _runLayer(2, path.join(__dirname, "20-db.js"),          "Layer 2");
  console.log("Layer 3");
  await _runLayer(3, path.join(__dirname, "30-chain.js"),       "Layer 3");
  console.log("Layer 4");
  await _runLayer(4, path.join(__dirname, "40-consumers.js"),   "Layer 4");
  console.log("Layer 5");
  await _runLayer(5, path.join(__dirname, "50-integration.js"), "Layer 5");

  console.log("OK — " + helpers.getChecks() + " checks passed (" + (Date.now() - smokeStart) + "ms total)");
})().catch(function (err) {
  console.error("SMOKE TEST FAILED:", err.message);
  console.error(err.stack);
  process.exit(1);
});
