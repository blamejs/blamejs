// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.chainWriter consumer-owned + multi-chain (chainKey) support, and
 * b.auditChain.verifyChain / getChainTip per-partition scoping (#326).
 *
 * Drives the real consumer path: register an app table, build a keyed writer,
 * append to two partitions, and verify each sub-chain independently. RED on the
 * current tree (chainWriter.registerTable + the chainKey opt did not exist).
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;
var setupTestDb = helpers.setupTestDb;
var teardownTestDb = helpers.teardownTestDb;
var fs   = require("fs");
var os   = require("os");
var path = require("path");

var CONSUMER_SCHEMA = [{
  name: "device_event_log",
  columns: {
    _id:              "TEXT PRIMARY KEY",
    deviceId:         "TEXT NOT NULL",
    monotonicCounter: "INTEGER NOT NULL",
    recordedAt:       "INTEGER NOT NULL",
    kind:             "TEXT",
    payload:          "TEXT",
    prevHash:         "TEXT",
    rowHash:          "TEXT",
    nonce:            "BLOB",
    fencingToken:     "TEXT",
  },
  // A keyed chain's uniqueness is the composite (deviceId, monotonicCounter),
  // never monotonicCounter alone (it restarts at 1 per key).
  indexes: [{ name: "idx_dev_chain", columns: ["deviceId", "monotonicCounter"], unique: true }],
  sealedFields: [],
}];

var COLS = ["_id", "deviceId", "monotonicCounter", "recordedAt", "kind", "payload",
            "prevHash", "rowHash", "nonce", "fencingToken"];
var HASHABLE = ["_id", "deviceId", "monotonicCounter", "recordedAt", "kind", "payload"];

async function run() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cwmc-"));
  try {
    await setupTestDb(tmpDir, CONSUMER_SCHEMA);
    var queryAll = b.clusterStorage.executeAll;

    // A consumer table must be registered before create() accepts it — the
    // ALLOWED_CHAIN_TABLES allowlist is never bypassed.
    check("create() refuses an unregistered consumer table",
      (function () { try { b.chainWriter.create({ table: "device_event_log", columnsForInsert: COLS, hashableColumns: HASHABLE }); return false; } catch (_e) { return true; } })());

    b.chainWriter.registerTable("device_event_log");
    var w = b.chainWriter.create({
      table: "device_event_log", chainKey: "deviceId",
      columnsForInsert: COLS, hashableColumns: HASHABLE,
    });
    check("keyed writer exposes its chainKey", w.chainKey === "deviceId");

    // Append to two independent partitions; counters restart per key.
    var a1 = await w.append({ deviceId: "dev-A", kind: "boot", payload: "1" });
    var a2 = await w.append({ deviceId: "dev-A", kind: "tick", payload: "2" });
    var b1 = await w.append({ deviceId: "dev-B", kind: "boot", payload: "1" });
    check("dev-A first row counter is 1", a1.monotonicCounter === 1);
    check("dev-A second row counter is 2", a2.monotonicCounter === 2);
    check("dev-B first row counter restarts at 1 (independent chain)", b1.monotonicCounter === 1);
    check("dev-A row 2 links to row 1's rowHash (per-key tip)", a2.prevHash === a1.rowHash);
    check("dev-B row 1 starts a fresh chain (ZERO_HASH prev)", b1.prevHash === b.auditChain.ZERO_HASH);

    // A keyed writer fails closed on a missing partition key.
    var threwKey = false;
    try { await w.append({ kind: "no-device" }); } catch (e) { threwKey = /chain-writer/.test(e.code || ""); }
    check("append refuses a row missing the chainKey", threwKey);

    // verifyChain scopes per key: each sub-chain verifies clean independently.
    var ok = await b.auditChain.verifyChain(queryAll, "device_event_log", { chainKey: "deviceId" });
    check("verifyChain({chainKey}) reports ok across all partitions", ok.ok === true);
    check("verifyChain counts both partitions", ok.chains === 2);
    check("verifyChain totals every row across sub-chains", ok.rowsVerified === 3);

    // getChainTip scoped to one partition returns that key's tip.
    var tipA = await b.auditChain.getChainTip(b.clusterStorage.executeOne, "device_event_log",
      { chainKey: "deviceId", keyValue: "dev-A" });
    check("getChainTip({chainKey}) returns dev-A's tip (counter 2)", tipA.counter === 2 && tipA.prevHash === a2.rowHash);
    var tipB = await b.auditChain.getChainTip(b.clusterStorage.executeOne, "device_event_log",
      { chainKey: "deviceId", keyValue: "dev-B" });
    check("getChainTip({chainKey}) returns dev-B's tip (counter 1)", tipB.counter === 1);

    // Tamper a row in dev-A and confirm verify breaks on THAT key.
    await b.clusterStorage.execute(
      'UPDATE device_event_log SET payload = ? WHERE deviceId = ? AND monotonicCounter = ?',
      ["tampered", "dev-A", 2]);
    var bad = await b.auditChain.verifyChain(queryAll, "device_event_log", { chainKey: "deviceId" });
    check("verifyChain detects a tampered row", bad.ok === false);
    check("verifyChain reports the broken chainKey", bad.chainKey === "dev-A");

    // maxChains fails closed when the partition fan-out exceeds the cap.
    var capped = await b.auditChain.verifyChain(queryAll, "device_event_log", { chainKey: "deviceId", maxChains: 1 });
    check("verifyChain fails closed past maxChains", capped.ok === false && /too many chains/.test(capped.reason));

    // withChainLock serializes against append on the same key. A checkpoint
    // signs a statement about the tip, so it has to observe one that existed:
    // reading unlocked can land between an append's insert and its counter
    // advancing, pairing a counter with a hash that were never the tip
    // together — and the signature over that pair is valid, self-consistent,
    // and describes a state the chain was never in.
    //
    // Last, because it appends rows the row-count assertions above pin.
    var order = [];
    var releaseHold = null;
    var held = new Promise(function (resolve) { releaseHold = resolve; });
    var holding = w.withChainLock("dev-A", function () {
      order.push("lock-enter");
      return held.then(function () { order.push("lock-exit"); });
    });
    await helpers.passiveObserve(30, "chain-writer: lock taken before the racing append");
    var racing = w.append({ deviceId: "dev-A", kind: "raced", payload: "3" })
      .then(function (r) { order.push("append-done"); return r; });
    await helpers.passiveObserve(60, "chain-writer: append must not proceed under a held lock");
    check("chain-writer: an append waits while the chain lock is held",
      order.indexOf("append-done") === -1, JSON.stringify(order));

    releaseHold();
    await holding;
    await racing;
    check("chain-writer: the append completes once the lock is released",
      order.indexOf("append-done") > order.indexOf("lock-exit"), JSON.stringify(order));

    // A different partition is a different lock, so it is never blocked by one
    // held elsewhere — otherwise a checkpoint would serialize every chain in
    // the process behind itself.
    var releaseB = null;
    var heldB = new Promise(function (resolve) { releaseB = resolve; });
    var holdingB = w.withChainLock("dev-A", function () { return heldB; });
    await helpers.passiveObserve(30, "chain-writer: dev-A lock held before the dev-B append");
    var otherDone = false;
    await w.append({ deviceId: "dev-B", kind: "unblocked", payload: "2" })
      .then(function () { otherDone = true; });
    check("chain-writer: an append on another key is not blocked", otherDone === true);
    releaseB();
    await holdingB;
  } finally {
    try { await teardownTestDb(tmpDir); } catch (_e) { /* best-effort */ }
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[chain-writer-multichain] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
