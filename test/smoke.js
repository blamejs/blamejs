"use strict";
/**
 * Smoke test — orchestrator only.
 *
 * Run: `npm test` (or `node test/smoke.js`)
 *
 * Tests run in dependency order (per
 * .claude/memory/feedback_test_dependency_order.md):
 *
 *   Layer 0 — pure primitives                test/00-primitives.js
 *   Layer 1 — framework-state primitives     test/10-state.js
 *   Layer 2 — db + framework-schema          test/20-db.js
 *   Layer 3 — chain-writing + cluster-stg    test/30-chain.js
 *   Layer 4 — consumer modules               test/40-consumers.js
 *   Layer 5 — operator-facing integration    test/50-integration.js
 *
 * Shared infrastructure (b binding, check(), setup/teardown helpers,
 * fake drivers, mock req/res, cluster-gate fixture) lives in
 * test/_helpers.js. Each layer file imports it independently.
 *
 * Layer file shape — each file may export:
 *   run()    — backward-compat. Sequential test invocation. Always
 *              ran first if present.
 *   groups[] — fixture-aware groups. Each group is:
 *              { name, setup?(): ctx, teardown?(ctx), tests: [
 *                  { name, run(ctx) }, ...
 *              ] }
 *              Setup runs once per group; each test receives the
 *              context object. Failures are attributed by
 *              "<layer> / <group> / <test>" path so the FIRST red
 *              light points at the exact named subtest.
 */

var helpers = require("./_helpers");
var b       = helpers.b;

var primitivesLayer  = require("./00-primitives");
var stateLayer       = require("./10-state");
var dbLayer          = require("./20-db");
var chainLayer       = require("./30-chain");
var consumersLayer   = require("./40-consumers");
var integrationLayer = require("./50-integration");

console.log("blamejs v" + b.version + " — smoke test");

// Run a single layer's content. Calls layer.run() first (legacy
// path, backward-compat) then walks layer.groups[] if present.
//
// Per-test timing is reported on stdout — drift detection without
// extra tooling. Format:
//
//   <layer>
//     <group>                                   (totalMs)
//       <test>                                   testMs
//
// Failures throw with attribution: "<layer> / <group> / <test>" so
// the error message points at the exact named subtest.
async function _runLayer(layerName, layer) {
  if (typeof layer.run === "function") {
    await layer.run();
  }
  if (Array.isArray(layer.groups) && layer.groups.length > 0) {
    console.log(layerName);
    for (var i = 0; i < layer.groups.length; i++) {
      var group = layer.groups[i];
      var ctx = null;
      var groupStart = Date.now();
      var testTimings = [];
      try {
        if (typeof group.setup === "function") ctx = await group.setup();
        for (var j = 0; j < group.tests.length; j++) {
          var t = group.tests[j];
          var testStart = Date.now();
          try {
            await t.run(ctx);
          } catch (err) {
            err.message = layerName + " / " + group.name + " / " + t.name + ": " + err.message;
            throw err;
          }
          testTimings.push({ name: t.name, ms: Date.now() - testStart });
        }
      } finally {
        if (typeof group.teardown === "function") {
          try { await group.teardown(ctx); }
          catch (_e) { /* teardown errors don't mask test failures */ }
        }
      }
      // Print group + per-test timings in a compact table. The exact
      // formatting columns are tuned for typical names (~40-char
      // test labels). Long names overflow but never wrap silently —
      // legibility over alignment.
      var groupTotal = Date.now() - groupStart;
      console.log("  " + _padRight(group.name, 40) + " (" + groupTotal + "ms)");
      for (var k = 0; k < testTimings.length; k++) {
        console.log("    " + _padRight(testTimings[k].name, 38) + " " + testTimings[k].ms + "ms");
      }
    }
  }
}

function _padRight(s, n) {
  if (s.length >= n) return s;
  return s + " ".repeat(n - s.length);
}

(async function () {
  var smokeStart = Date.now();
  await _runLayer("Layer 0", primitivesLayer);
  await _runLayer("Layer 1", stateLayer);
  await _runLayer("Layer 2", dbLayer);
  await _runLayer("Layer 3", chainLayer);
  await _runLayer("Layer 4", consumersLayer);
  await _runLayer("Layer 5", integrationLayer);

  console.log("OK — " + helpers.getChecks() + " checks passed (" + (Date.now() - smokeStart) + "ms total)");
})().catch(function (err) {
  console.error("SMOKE TEST FAILED:", err.message);
  console.error(err.stack);
  process.exit(1);
});
