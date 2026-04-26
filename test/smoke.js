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

(async function () {
  await primitivesLayer.run();   // Layer 0
  await stateLayer.run();        // Layer 1
  await dbLayer.run();           // Layer 2
  await chainLayer.run();        // Layer 3
  await consumersLayer.run();    // Layer 4
  await integrationLayer.run();  // Layer 5

  console.log("OK — " + helpers.getChecks() + " checks passed");
})().catch(function (err) {
  console.error("SMOKE TEST FAILED:", err.message);
  console.error(err.stack);
  process.exit(1);
});
