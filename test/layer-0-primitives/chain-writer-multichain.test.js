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

    // A counter is primed from MAX(monotonicCounter) BEFORE the mutex is
    // taken, and has to be: the read reports its own outcome through the audit
    // chain in cluster mode, so an append that primes while holding the mutex
    // queues an append that waits for that same mutex. Priming outside means
    // concurrent appends share one in-flight read instead of each starting a
    // new one behind the lock.
    //
    // The cost is that a read CAN land midway through a sanctioned deletion
    // and answer zero. What stops a stale answer from surviving is
    // invalidateOrigin: whoever changed the state discards what was primed
    // from the half-finished version of it, while still holding the lock, so
    // the next append re-derives from the finished state.
    await w.append({ deviceId: "dev-D", kind: "first", payload: "1" });
    await b.clusterStorage.execute(
      "INSERT INTO device_event_log (_id, deviceId, monotonicCounter, recordedAt, " +
      "kind, payload, prevHash, rowHash, nonce, fencingToken) " +
      "VALUES ('seed-d-50', 'dev-D', 50, 1750000000000, 'seed', 'x', '" +
      "0".repeat(128) + "', '" + "a".repeat(128) + "', NULL, NULL)");

    var stale = await w.append({ deviceId: "dev-D", kind: "stale", payload: "2" });
    check("chain-writer: a primed counter is reused without re-reading",
      Number(stale.monotonicCounter) === 2, "counter=" + stale.monotonicCounter);

    w.invalidateOrigin("dev-D");
    var rederived = await w.append({ deviceId: "dev-D", kind: "rederived", payload: "3" });
    check("chain-writer: invalidateOrigin makes the next append re-derive it",
      Number(rederived.monotonicCounter) === 51,
      "counter=" + rederived.monotonicCounter + " (3 means the stale value survived)");

    var otherKey = await w.append({ deviceId: "dev-A", kind: "after", payload: "4" });
    check("chain-writer: and invalidating one key leaves another alone",
      Number(otherKey.monotonicCounter) > 1, "counter=" + otherKey.monotonicCounter);

    // Re-derivation is a FLOOR, never a replacement. It re-reads
    // MAX(monotonicCounter), and the whole reason invalidation exists is that
    // rows can have been REMOVED — so that maximum can be lower than what this
    // process already handed out. Replacing rather than raising would then
    // reissue counters that rows in flight are already using. Emptying the
    // key's rows below is what a purge does to the chain it anchors.
    var beforeInvalidate = Number(rederived.monotonicCounter);
    await b.clusterStorage.execute("DELETE FROM device_event_log WHERE deviceId = 'dev-D'");
    w.invalidateOrigin("dev-D");
    var afterInvalidate = await w.append({ deviceId: "dev-D", kind: "floor", payload: "5" });
    check("chain-writer: re-derivation never sends a counter backwards",
      Number(afterInvalidate.monotonicCounter) > beforeInvalidate,
      "before=" + beforeInvalidate + " after=" + afterInvalidate.monotonicCounter +
      " (a lower value means the re-read replaced instead of raising)");

    // And it happens BEFORE the lock: a key marked stale while another holder
    // has the lock must not do its re-read inside it. Holding dev-D's lock and
    // invalidating it, the queued append still completes rather than wedging
    // on a read that waits for the lock it is holding.
    var releaseE;
    var heldE = new Promise(function (resolve) { releaseE = resolve; });
    var holdingE = w.withChainLock("dev-D", function () {
      w.invalidateOrigin("dev-D");
      return heldE;
    });
    var queued = w.append({ deviceId: "dev-D", kind: "queued", payload: "6" });
    await helpers.passiveObserve(150, "chain-writer: append queued behind an invalidating holder");
    releaseE();
    await holdingE;
    var queuedRow = await queued;
    check("chain-writer: an append queued behind an invalidation still completes",
      Number(queuedRow.monotonicCounter) > Number(afterInvalidate.monotonicCounter),
      "counter=" + queuedRow.monotonicCounter);
  } finally {
    try { await teardownTestDb(tmpDir); } catch (_e) { /* best-effort */ }
  }

  await testOriginFloorAppliesToAnAlreadyPrimedAppend();
}

// A writer WITH an origin resolver, which is what `b.audit` uses so a purged
// chain resumes above the boundary instead of restarting inside it.
//
// The floor is checked on every append, not only when priming answered 1,
// because priming runs BEFORE the append lock: an invalidation that arrives
// after an append primed and before it reached the lock is invisible to that
// append any other way, and the value it primed is then the pre-invalidation
// answer. Re-reading the origin here is what makes the new boundary reach it.
async function testOriginFloorAppliesToAnAlreadyPrimedAppend() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cworigin-"));
  try {
    await setupTestDb(tmpDir, CONSUMER_SCHEMA);
    b.chainWriter.registerTable("device_event_log");

    var boundary = 0;
    var w = b.chainWriter.create({
      table: "device_event_log", chainKey: "deviceId",
      columnsForInsert: COLS, hashableColumns: HASHABLE,
      resolveOrigin: function () {
        return boundary === 0 ? null
          : { hash: "b".repeat(128), counter: boundary };
      },
    });

    // Nothing came before: the resolver says so and the chain starts at 1,
    // which is what every table that has never had rows removed looks like.
    var first = await w.append({ deviceId: "dev-Z", kind: "first", payload: "1" });
    check("chain-writer: a resolver returning nothing starts a fresh chain",
      Number(first.monotonicCounter) === 1 &&
      String(first.prevHash) === "0".repeat(128),
      "counter=" + first.monotonicCounter);

    // Now a boundary appears — a purge — and this key's counter was primed
    // before it. The next append must clear the boundary and link to it.
    boundary = 80;
    w.invalidateOrigin("dev-Z");
    var after = await w.append({ deviceId: "dev-Z", kind: "after", payload: "2" });
    check("chain-writer: an already-primed counter is raised past a new boundary",
      Number(after.monotonicCounter) > boundary,
      "counter=" + after.monotonicCounter + " boundary=" + boundary);

    // And with the key's rows gone, as a purge leaves them, it links to the
    // boundary's hash rather than restarting the chain.
    await b.clusterStorage.execute("DELETE FROM device_event_log WHERE deviceId = 'dev-Z'");
    w.invalidateOrigin("dev-Z");
    var resumed = await w.append({ deviceId: "dev-Z", kind: "resumed", payload: "3" });
    check("chain-writer: and an emptied key links to the boundary hash",
      String(resumed.prevHash) === "b".repeat(128), String(resumed.prevHash));
    check("chain-writer: still above the boundary after the rows went",
      Number(resumed.monotonicCounter) > boundary,
      "counter=" + resumed.monotonicCounter);

    // monotonicCounter is a BIGINT, and above 2^53 two distinct stored values
    // land on the same Number — a floor taken from up there would silently
    // equal a different counter, and the writer would reuse or skip one. The
    // purge anchor refuses that range for the same reason; a resolver reaching
    // this writer has to answer to it too.
    boundary = Number.MAX_SAFE_INTEGER + 2;
    w.invalidateOrigin("dev-Z");
    var unsafeErr = null;
    try { await w.append({ deviceId: "dev-Z", kind: "unsafe", payload: "4" }); }
    catch (e) { unsafeErr = e; }
    check("chain-writer: an origin counter beyond the safe range is refused",
      unsafeErr !== null && unsafeErr.code === "chain-writer/bad-origin",
      String(unsafeErr && (unsafeErr.code || unsafeErr.message)));
    check("chain-writer: and says what the bound is",
      unsafeErr !== null && /2\^53/.test(unsafeErr.message || ""),
      String(unsafeErr && unsafeErr.message));
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
