// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.time.monotonicClock / b.time.monotonicNow, and the append-only chain
 * defect they exist to close.
 *
 * `Date.now()` is not monotonic. It repeats under fast writes and it moves
 * BACKWARDS when NTP steps the clock — the very correction `b.ntpCheck`
 * exists to detect. `b.chainWriter` stamps `recordedAt` from it while
 * `monotonicCounter` advances under a mutex, so the two columns can disagree
 * on order. That is not cosmetic: `b.auditTools.exportSlice` selects rows by
 * `recordedAt` and then requires the selection to be CONTIGUOUS in
 * `monotonicCounter`. One backwards step drops a row out of the window its
 * neighbours are in, and the compliance export is refused with
 * `audit-tools/non-contiguous` — telling the operator to widen the date
 * range, which cannot help, because the row is not where its counter says it
 * should be.
 *
 * RED on the current tree: `b.time.monotonicNow` does not exist, and an audit
 * chain written across a backwards clock step exports as non-contiguous.
 *
 * Run standalone: `node test/layer-0-primitives/time-monotonic.test.js`
 */

var helpers = require("../helpers");
var b              = helpers.b;
var check          = helpers.check;
var fs             = helpers.fs;
var os             = helpers.os;
var path           = helpers.path;
var setupTestDb    = helpers.setupTestDb;
var teardownTestDb = helpers.teardownTestDb;

var PASS = Buffer.from("time-monotonic-test-passphrase-value");

// A scripted clock source. Hands back each value in turn, then pins to the
// last one — so a test can express "the clock stepped back 5 seconds and
// stayed there" without racing real time.
function _scriptedSource(values) {
  var i = 0;
  return function () {
    var v = values[Math.min(i, values.length - 1)];
    i += 1;
    return v;
  };
}

// ---------------------------------------------------------------------------
// The primitive itself.
// ---------------------------------------------------------------------------

function testNeverRepeatsOrGoesBackwards() {
  // The whole point: the same millisecond read twice, and a source that
  // rewinds, must both come out strictly increasing.
  var clock = b.time.monotonicClock({
    source: _scriptedSource([1000, 1000, 1000, 900, 800, 1000, 1001]),
  });
  var seen = [];
  for (var i = 0; i < 7; i++) seen.push(clock.now());

  var strictlyIncreasing = true;
  for (var j = 1; j < seen.length; j++) {
    if (seen[j] <= seen[j - 1]) strictlyIncreasing = false;
  }
  check("monotonicClock: a repeating source still yields strictly increasing values",
    strictlyIncreasing);
  check("monotonicClock: a rewinding source never yields a value below the last",
    Math.min.apply(null, seen) === seen[0]);
  check("monotonicClock: the first value is the source's own reading",
    seen[0] === 1000);
  check("monotonicClock: lastValue() reports what it last handed out",
    clock.lastValue() === seen[seen.length - 1]);
}

function testEachClockIsIsolated() {
  // Two callers that each want their own sequence must not share a floor —
  // the isolated-source form is the reason monotonicClock exists alongside
  // monotonicNow.
  var a = b.time.monotonicClock({ source: _scriptedSource([5000]) });
  var bb = b.time.monotonicClock({ source: _scriptedSource([1000]) });
  a.now();
  check("monotonicClock: a second clock is not dragged up by the first",
    bb.now() === 1000);
}

function testSharedNowIsMonotonic() {
  var first = b.time.monotonicNow();
  var second = b.time.monotonicNow();
  var third = b.time.monotonicNow();
  check("monotonicNow: the shared source is strictly increasing",
    second > first && third > second);
  check("monotonicNow: the shared source tracks wall-clock magnitude",
    Math.abs(first - Date.now()) < 60000);
}

function testPersistedFloorSurvivesRestart() {
  // A process-memory floor resets to zero on restart or failover, which is
  // exactly when a backwards clock step is most likely (a fresh node syncing
  // NTP). observeFloor seeds the guarantee from a value read back out of
  // storage.
  var persisted = 1700000000000;
  var restarted = b.time.monotonicClock({ source: _scriptedSource([persisted - 5000]) });
  restarted.observeFloor(persisted);
  var afterRestart = restarted.now();
  check("monotonicClock: observeFloor lifts a restarted clock above the persisted tip",
    afterRestart > persisted);

  // A floor BELOW where the clock already is must not drag it back down.
  var ahead = b.time.monotonicClock({ source: _scriptedSource([persisted]) });
  var high = ahead.now();
  ahead.observeFloor(persisted - 100000);
  check("monotonicClock: a lower floor is ignored, never a rewind",
    ahead.now() > high);
}

function testDriftAheadOfWallClockIsCappedAndSignalled() {
  // A burst inside one millisecond walks the returned value ahead of the
  // source. Unbounded, that is a silently wrong timestamp; the cap is what
  // makes it not silent.
  var drifted = [];
  var clock = b.time.monotonicClock({
    source:     _scriptedSource([1000]),
    maxDriftMs: 5,
    onDrift:    function (info) { drifted.push(info); },
  });
  for (var i = 0; i < 10; i++) clock.now();

  check("monotonicClock: exceeding maxDriftMs reports through onDrift",
    drifted.length > 0);
  check("monotonicClock: the drift report carries the lead and the cap",
    drifted.length > 0 && drifted[0].driftMs > 5 && drifted[0].maxDriftMs === 5);
  check("monotonicClock: driftMs() reports the current lead over the source",
    clock.driftMs() === clock.lastValue() - 1000);

  // Reporting does NOT break the guarantee. A caller whose property is
  // completeness (an append-only chain) would rather record a timestamp a few
  // milliseconds optimistic than drop the row.
  var beforeMore = clock.lastValue();
  var afterMore = clock.now();
  check("monotonicClock: a drift report does not suspend the monotonic guarantee",
    afterMore > beforeMore);

  // A caller whose property is timestamp ACCURACY asks for the throw instead.
  var strict = b.time.monotonicClock({
    source: _scriptedSource([1000]), maxDriftMs: 2, strict: true,
  });
  var threw = null;
  try { for (var k = 0; k < 20; k++) strict.now(); } catch (e) { threw = e; }
  check("monotonicClock: strict mode throws once the cap is passed",
    threw !== null && threw.code === "time/monotonic-drift-cap");
}

function testDriftCapIsNotTrippedBySlowCalls() {
  // The cap measures lead over the SOURCE, not elapsed time. A clock read
  // once a second must never report drift.
  var reported = 0;
  var t = 1000;
  var clock = b.time.monotonicClock({
    source:     function () { t += 1000; return t; },
    maxDriftMs: 5,
    onDrift:    function () { reported += 1; },
  });
  for (var i = 0; i < 20; i++) clock.now();
  check("monotonicClock: an advancing source never reports drift", reported === 0);
  check("monotonicClock: an advancing source is passed through unchanged",
    clock.driftMs() === 0);
}

// The whole primitive is one promise: now() never returns a value less than or
// equal to the last. Above Number.MAX_SAFE_INTEGER that promise cannot be kept
// by `last + 1`, because 2^53 + 1 is not representable and the addition
// SATURATES - two calls return the same number and the guarantee fails
// silently, which is the exact failure mode monotonicNow exists to prevent.
//
// Not reachable from a sane wall clock (2^53 ms is the year 285428). It IS
// reachable through observeFloor, whose value comes from storage: b.chainWriter
// seeds the floor from a persisted recordedAt column. So the boundary is
// refused at the door rather than trusted to be unreachable.
function testSafeIntegerCeilingIsRefusedNotSaturated() {
  var clock = b.time.monotonicClock({ source: _scriptedSource([1000]) });
  var floorErr = null;
  try { clock.observeFloor(Number.MAX_SAFE_INTEGER); } catch (e) { floorErr = e; }
  check("monotonicClock: observeFloor refuses a value past the safe-integer range",
    floorErr !== null && typeof floorErr.code === "string");
  check("monotonicClock: refusing the floor leaves the clock usable",
    clock.now() === 1000);

  // Same for a source that hands back an unsafe integer directly.
  var unsafe = b.time.monotonicClock({
    source: _scriptedSource([Number.MAX_SAFE_INTEGER + 2]),
  });
  var srcErr = null;
  try { unsafe.now(); } catch (e) { srcErr = e; }
  check("monotonicClock: a source past the safe-integer range is refused",
    srcErr !== null && typeof srcErr.code === "string");

  // And the invariant itself, at the boundary: whatever the clock does there,
  // it must never hand out the same value twice.
  var atEdge = b.time.monotonicClock({
    source: _scriptedSource([Number.MAX_SAFE_INTEGER - 2]),
  });
  var seen = [];
  var edgeErr = null;
  try { for (var i = 0; i < 6; i++) seen.push(atEdge.now()); }
  catch (e) { edgeErr = e; }
  var strictlyIncreasing = true;
  for (var j = 1; j < seen.length; j++) {
    if (seen[j] <= seen[j - 1]) strictlyIncreasing = false;
  }
  check("monotonicClock: at the ceiling it refuses rather than repeating a value",
    strictlyIncreasing && (edgeErr === null || typeof edgeErr.code === "string"));
}

function testConfigRefusals() {
  function code(opts) {
    try { b.time.monotonicClock(opts); return null; }
    catch (e) { return e.code || e.message; }
  }
  check("monotonicClock: refuses a non-function source",
    code({ source: 12345 }) !== null);
  check("monotonicClock: refuses a negative maxDriftMs",
    code({ maxDriftMs: -1 }) !== null);
  check("monotonicClock: refuses a non-numeric maxDriftMs",
    code({ maxDriftMs: "1s" }) !== null);
  check("monotonicClock: refuses a non-function onDrift",
    code({ onDrift: "log" }) !== null);
  check("monotonicClock: refuses an unknown option",
    code({ maxDriftMSec: 5 }) !== null);

  var clock = b.time.monotonicClock({ source: _scriptedSource([1000]) });
  function floorCode(v) {
    try { clock.observeFloor(v); return null; }
    catch (e) { return e.code || e.message; }
  }
  check("monotonicClock: observeFloor refuses a non-finite value",
    floorCode(NaN) !== null && floorCode(Infinity) !== null);
  check("monotonicClock: observeFloor refuses a negative value",
    floorCode(-1) !== null);
  check("monotonicClock: observeFloor accepts a millisecond epoch",
    floorCode(1700000000000) === null);
}

// A source that a clock source itself throws from must not take the caller
// down silently with a wrong timestamp.
function testBadSourceReadingIsRefused() {
  var clock = b.time.monotonicClock({ source: function () { return "nope"; } });
  var threw = null;
  try { clock.now(); } catch (e) { threw = e; }
  check("monotonicClock: a source returning a non-number is refused, not coerced",
    threw !== null && threw.code === "time/monotonic-bad-source");
}

// ---------------------------------------------------------------------------
// The defect: an audit chain written across a backwards clock step.
// ---------------------------------------------------------------------------

// Run `fn` with Date.now stepped to `at`, then restore. Scoped as tightly as
// possible so nothing else in the process sees the stepped clock.
async function _withSteppedClock(at, fn) {
  var real = Date.now;
  Date.now = function () { return at; };
  try { return await fn(); }
  finally { Date.now = real; }
}

async function testAuditChainSurvivesABackwardsClockStep(root) {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-tmono-"));
  var tornDown = false;
  try {
    await setupTestDb(dir);
    b.audit.registerNamespace("test");

    // Row 1 at real time.
    await b.audit.record({ action: "test.before", outcome: "success" });
    await b.audit.flush();
    var afterFirst = await b.clusterStorage.executeAll(
      "SELECT recordedAt FROM audit_log ORDER BY monotonicCounter ASC");
    var t0 = Number(afterFirst[afterFirst.length - 1].recordedAt);

    // NTP steps the clock five seconds backwards. Row 2 is written under it.
    await _withSteppedClock(t0 - 5000, async function () {
      await b.audit.record({ action: "test.during", outcome: "success" });
      await b.audit.flush();
    });

    // The step is corrected; row 3 is written at real time again.
    await b.audit.record({ action: "test.after", outcome: "success" });
    await b.audit.flush();

    var rows = await b.clusterStorage.executeAll(
      "SELECT monotonicCounter, recordedAt, action FROM audit_log ORDER BY monotonicCounter ASC");
    check("audit chain: three rows were appended across the step", rows.length >= 3);

    // The invariant. recordedAt must order the same way monotonicCounter
    // does, because every reader that selects by one and proves with the
    // other depends on it.
    var nonDecreasing = true;
    var offender = null;
    for (var i = 1; i < rows.length; i++) {
      if (Number(rows[i].recordedAt) < Number(rows[i - 1].recordedAt)) {
        nonDecreasing = false;
        offender = Number(rows[i - 1].recordedAt) + " → " + Number(rows[i].recordedAt);
      }
    }
    check("audit chain: recordedAt never moves backwards in counter order" +
      (offender ? " (saw " + offender + ")" : ""), nonDecreasing);

    // The operator-visible failure. A time-window export anchored at the
    // first row must not lose an intermediate row to the clock step — the
    // contiguity proof is what refuses.
    var exportDir = path.join(root, "mono-export");
    var exported = null;
    var exportErr = null;
    try {
      exported = await b.auditTools.exportSlice({
        out:        exportDir,
        from:       Number(rows[0].recordedAt),
        to:         Date.now() + 3600000,
        passphrase: PASS,
      });
    } catch (e) { exportErr = e; }

    check("exportSlice: a window covering the whole chain is not refused as non-contiguous",
      exportErr === null || exportErr.code !== "audit-tools/non-contiguous");
    check("exportSlice: the window exported every row in the chain",
      exported !== null && exported.rowCount === rows.length);

    await teardownTestDb(dir);
    tornDown = true;
  } finally {
    if (!tornDown) { try { await teardownTestDb(dir); } catch (_e) { /* best effort */ } }
  }
}

// A chain tip whose recordedAt cannot serve as a floor must REFUSE the append,
// not skip the floor and carry on. Skipping would append beneath the row the
// new row links to, which is exactly the disorder the floor exists to prevent,
// and it would do so silently on a chain that is already corrupt.
async function testCorruptTipRefusesTheAppend(root) {
  void root;
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-tmono-tip-"));
  var tornDown = false;
  var SCHEMA = [{
    name: "tip_probe_log",
    columns: {
      _id:              "TEXT PRIMARY KEY",
      monotonicCounter: "INTEGER NOT NULL",
      recordedAt:       "INTEGER NOT NULL",
      payload:          "TEXT",
      prevHash:         "TEXT",
      rowHash:          "TEXT",
      nonce:            "BLOB",
      fencingToken:     "TEXT",
    },
    indexes: [{ name: "idx_tip_probe", columns: "monotonicCounter", unique: true }],
    sealedFields: [],
  }];
  var COLS = ["_id", "monotonicCounter", "recordedAt", "payload",
              "prevHash", "rowHash", "nonce", "fencingToken"];

  try {
    await setupTestDb(dir, SCHEMA);
    b.chainWriter.registerTable("tip_probe_log");
    var w = b.chainWriter.create({
      table: "tip_probe_log", columnsForInsert: COLS, hashableColumns: COLS.slice(0, 4),
    });

    var first = await w.append({ payload: "one" });
    check("corrupt-tip: a normal append works before the tip is damaged",
      first.monotonicCounter === 1);

    // Damage the tip's timestamp the way an out-of-framework write would.
    await b.clusterStorage.executeAll(
      "UPDATE tip_probe_log SET recordedAt = ? WHERE monotonicCounter = ?",
      [Number.MAX_SAFE_INTEGER, 1]);

    var threw = null;
    try { await w.append({ payload: "two" }); } catch (e) { threw = e; }
    check("corrupt-tip: an unusable tip timestamp refuses the append",
      threw !== null);
    check("corrupt-tip: the refusal names the chain, not the clock internals",
      threw !== null && threw.code === "chain-writer/bad-tip-timestamp");

    // And it must not have written a row anyway.
    var rows = await b.clusterStorage.executeAll(
      "SELECT monotonicCounter FROM tip_probe_log ORDER BY monotonicCounter ASC");
    check("corrupt-tip: no row was appended past the damaged tip", rows.length === 1);

    // CONTROL. Without this the refusal above could be caused by anything in
    // the scenario - an unregistered table, a malformed writer, a broken query
    // - and the assertion would pass while never reaching the check it names.
    // Repair only the timestamp and the same append must now succeed.
    await b.clusterStorage.executeAll(
      "UPDATE tip_probe_log SET recordedAt = ? WHERE monotonicCounter = ?",
      [Date.now(), 1]);
    var repaired = null;
    var repairErr = null;
    try { repaired = await w.append({ payload: "two" }); } catch (e) { repairErr = e; }
    check("corrupt-tip CONTROL: repairing only the timestamp lets the append through" +
      (repairErr ? " (still threw " + (repairErr.code || repairErr.message) + ")" : ""),
      repairErr === null && repaired !== null);
    // And it lands on counter 2, not 3: the refused append gave its counter
    // back. A burned counter is a permanent hole in monotonicCounter, and a
    // hole is what exportSlice refuses as non-contiguous - so one refused
    // write would break every later export of a range spanning it.
    check("corrupt-tip: the refused append did not burn its counter" +
      (repaired ? " (landed on " + repaired.monotonicCounter + ")" : ""),
      repaired !== null && repaired.monotonicCounter === 2);

    // THE AMBIGUOUS FAILURE. A timeout cannot distinguish "the insert did not
    // commit" from "it committed and the acknowledgement was lost". Restoring
    // the counter unconditionally is right in the first case and WEDGES the
    // chain in the second: the next append reuses a counter that is already in
    // the table, hits the unique index, rolls back again, and every audit write
    // for this chain fails from then until restart. A permanent write outage is
    // far worse than the contiguity gap the rollback exists to avoid.
    //
    // Sequence matters. The ghost row has to appear while the writer's counter
    // is UNPRIMED — that is, after a failed append — or the test is simulating
    // an external writer inserting behind the writer's back rather than the
    // ambiguous timeout. So: fail an append (which must discard the in-memory
    // counter), THEN plant the row that "landed", then append again.
    await b.clusterStorage.executeAll(
      "UPDATE tip_probe_log SET recordedAt = ? WHERE monotonicCounter = ?",
      [Number.MAX_SAFE_INTEGER, 2]);
    var secondFailure = null;
    try { await w.append({ payload: "fails-ambiguously" }); }
    catch (e) { secondFailure = e; }
    check("ambiguous insert: the setup append failed as intended",
      secondFailure !== null);

    var landed = await b.clusterStorage.executeAll(
      "SELECT MAX(monotonicCounter) AS m FROM tip_probe_log");
    var nextCounter = Number(landed[0].m) + 1;
    // Well-formed hash columns: a row that really landed carries them, and
    // without them the next append fails on a malformed TIP instead of on the
    // counter collision this is testing — a fixture in a shape the system
    // never produces tests the wrong thing.
    var ghostPrev = await b.clusterStorage.executeAll(
      "SELECT rowHash FROM tip_probe_log ORDER BY monotonicCounter DESC LIMIT 1");
    await b.clusterStorage.executeAll(
      "INSERT INTO tip_probe_log (_id, monotonicCounter, recordedAt, payload, prevHash, rowHash) " +
      "VALUES (?, ?, ?, ?, ?, ?)",
      ["ghost-row", nextCounter, Date.now(), "landed-but-unacked",
       ghostPrev[0].rowHash, "b".repeat(128)]);

    // Repair the damaged row so the only obstacle left is the counter.
    await b.clusterStorage.executeAll(
      "UPDATE tip_probe_log SET recordedAt = ? WHERE monotonicCounter = ?",
      [Date.now(), 2]);

    var afterGhost = null;
    var ghostErr = null;
    try { afterGhost = await w.append({ payload: "after-ghost" }); }
    catch (e) { ghostErr = e; }
    check("ambiguous insert: the writer is not wedged by a row that landed " +
      "without an acknowledgement" +
      (ghostErr ? " (threw " + (ghostErr.code || ghostErr.message) + ")" : ""),
      ghostErr === null && afterGhost !== null);
    check("ambiguous insert: the next append continues AFTER the landed row " +
      (afterGhost ? "(landed on " + afterGhost.monotonicCounter +
        ", expected " + (nextCounter + 1) + ")" : ""),
      afterGhost !== null && afterGhost.monotonicCounter === nextCounter + 1);

    // A CONCURRENT append must not read the counter its sibling's failure
    // discarded. append() clears _ensureCounterInit before taking the mutex,
    // so a call already queued behind a failing one would otherwise find the
    // primed value gone and stamp NaN. Both of these fail (the tip is damaged
    // again), but the point is that BOTH fail for the stated reason rather
    // than one of them on a malformed counter.
    await b.clusterStorage.executeAll(
      "UPDATE tip_probe_log SET recordedAt = ? WHERE monotonicCounter = ?",
      [Number.MAX_SAFE_INTEGER, nextCounter + 1]);
    var pair = await Promise.allSettled([
      w.append({ payload: "concurrent-a" }),
      w.append({ payload: "concurrent-b" }),
    ]);
    var pairCodes = pair.map(function (r) {
      return r.status === "rejected" ? (r.reason && r.reason.code) : "FULFILLED";
    });
    check("concurrent append: neither sibling fails on a discarded counter " +
      "(" + JSON.stringify(pairCodes) + ")",
      pairCodes.every(function (c) { return c === "chain-writer/bad-tip-timestamp"; }));

    // And the writer still works afterwards, on a real integer counter.
    await b.clusterStorage.executeAll(
      "UPDATE tip_probe_log SET recordedAt = ? WHERE monotonicCounter = ?",
      [Date.now(), nextCounter + 1]);
    var recovered = await w.append({ payload: "recovered" });
    check("concurrent append: the writer recovers with an integer counter " +
      (recovered ? "(landed on " + recovered.monotonicCounter + ")" : ""),
      recovered !== null && Number.isSafeInteger(recovered.monotonicCounter) &&
      recovered.monotonicCounter === nextCounter + 2);

    await teardownTestDb(dir);
    tornDown = true;
  } finally {
    if (!tornDown) { try { await teardownTestDb(dir); } catch (_e) { /* best effort */ } }
  }
}

// ---------------------------------------------------------------------------

async function run() {
  testNeverRepeatsOrGoesBackwards();
  testEachClockIsIsolated();
  testSharedNowIsMonotonic();
  testPersistedFloorSurvivesRestart();
  testDriftAheadOfWallClockIsCappedAndSignalled();
  testDriftCapIsNotTrippedBySlowCalls();
  testSafeIntegerCeilingIsRefusedNotSaturated();
  testConfigRefusals();
  testBadSourceReadingIsRefused();

  var root = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-tmono-out-"));
  await testAuditChainSurvivesABackwardsClockStep(root);
  await testCorruptTipRefusesTheAppend(root);
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[time-monotonic] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL: " + helpers.formatErr(e)); process.exit(1); }
  );
}
