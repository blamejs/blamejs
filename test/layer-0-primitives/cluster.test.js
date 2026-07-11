// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * cluster — leader election + write-side gates.
 *
 * Covers b.cluster.externalDbBackend (the wired shared-DB handle getter)
 * and b.cluster.onTransition (role-transition callback registration +
 * firing). The transition path is exercised through a real single-node
 * init/shutdown so the lease-acquired / lease-released events fire for
 * real, against a live in-process SQLite coordination backend.
 *
 * Run standalone: `node test/layer-0-primitives/cluster.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b                 = helpers.b;
var fs                = helpers.fs;
var os                = helpers.os;
var path              = helpers.path;
var check             = helpers.check;
var setupTestDb       = helpers.setupTestDb;
var teardownTestDb    = helpers.teardownTestDb;
var _makeSqliteDriver = helpers._makeSqliteDriver;
var C                 = b.constants;

async function testExternalDbBackendAndOnTransition() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cluster-"));
  b.cluster._resetForTest();
  await setupTestDb(tmpDir);

  var dbPath = path.join(tmpDir, "ha-coord.db");
  var driver = _makeSqliteDriver(dbPath);
  b.externalDb.init({
    backends: {
      ops: { connect: driver.connect, query: driver.query, close: driver.close },
    },
  });

  var events = [];
  var order  = [];
  try {
    // Pre-init contract: nothing wired yet.
    check("cluster.externalDbBackend null before init", b.cluster.externalDbBackend() === null);
    check("cluster.isClusterMode false before init",    b.cluster.isClusterMode() === false);

    // Config-time tier: a non-function handler throws synchronously.
    var badThrew = null;
    try { b.cluster.onTransition("not-a-fn"); } catch (e) { badThrew = e; }
    check("cluster.onTransition rejects a non-function handler",
          badThrew && badThrew.code === "INVALID_HANDLER");

    // Register two handlers BEFORE init; both must fire in registration order.
    b.cluster.onTransition(function (ev) { order.push("a"); events.push(ev); });
    b.cluster.onTransition(function (ev) { order.push("b"); });

    await b.cluster.init({
      nodeId:            "cluster-domain-node",
      externalDbBackend: "ops",
      dialect:           "sqlite",
      leaseTtl:          C.TIME.seconds(30),
      heartbeatInterval: C.TIME.seconds(10),
    });

    // externalDbBackend now returns the wired handle name.
    check("cluster.externalDbBackend returns the configured backend after init",
          b.cluster.externalDbBackend() === "ops");
    check("cluster.isClusterMode true once wired", b.cluster.isClusterMode() === true);

    // Single node → immediate leader → a lease-acquired transition fired.
    await helpers.waitUntil(function () {
      return events.some(function (e) { return e.kind === "lease-acquired"; });
    }, { timeoutMs: 5000, label: "cluster.onTransition: lease-acquired fired" });
    var acq = events.find(function (e) { return e.kind === "lease-acquired"; });
    check("transition event carries the nodeId",       acq.nodeId === "cluster-domain-node");
    check("transition event carries a numeric fencingToken",
          typeof acq.fencingToken === "number" && acq.fencingToken >= 1);
    check("transition event carries a timestamp",      typeof acq.at === "number");
    check("both handlers ran, in registration order",
          order.length >= 2 && order[0] === "a" && order[1] === "b");

    // shutdown releases the lease + emits a lease-released transition.
    await b.cluster.shutdown();
    await helpers.waitUntil(function () {
      return events.some(function (e) { return e.kind === "lease-released"; });
    }, { timeoutMs: 5000, label: "cluster.onTransition: lease-released fired" });
    check("cluster.externalDbBackend null again after shutdown",
          b.cluster.externalDbBackend() === null);
  } finally {
    try { await b.cluster.shutdown(); } catch (_e) { /* idempotent */ }
    try { await b.externalDb.shutdown(); } catch (_e) { /* best-effort */ }
    try { driver._close(); } catch (_e) { /* best-effort */ }
    await teardownTestDb(tmpDir);
  }
}

async function run() {
  await testExternalDbBackendAndOnTransition();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[cluster] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e); process.exit(1); }
  );
}
