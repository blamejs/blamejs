// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.audit.query self-logging (PCI DSS 10.2.3) — every read of audit_log
 * is itself recorded as an `audit.read` event.
 *
 * The self-log suppression is decided per-invocation from the call's own
 * `criteria.action`, never from shared module state. A prior design used a
 * module-global `_selfLogging` boolean toggled across record()'s await
 * (chain mutex + SQL yield); a CONCURRENT query() racing a mid-flight
 * self-log observed the flag set and silently skipped emitting its own
 * audit.read — under-logging reads exactly when load is highest. These
 * tests pin: two concurrent reads BOTH log, a single read logs exactly
 * once (no double/recursive log), and a query targeting `audit.read`
 * itself does not auto-log.
 *
 * The write path has the same shape. In cluster mode the chain write goes
 * through b.externalDb, which audits every query it runs, so appending a
 * row emits an event that appends a row. The last test here pins one
 * record to one row, and a chain that is not recorded to not growing.
 *
 * Run standalone: `node test/layer-0-primitives/audit-query-self-log.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b              = helpers.b;
var fs             = helpers.fs;
var os             = helpers.os;
var path           = helpers.path;
var check          = helpers.check;
var waitUntil      = helpers.waitUntil;
var setupTestDb    = helpers.setupTestDb;
var teardownTestDb = helpers.teardownTestDb;

function _tmp() { return fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-audit-self-")); }

// Count audit.read rows directly via the query path that does NOT auto-log
// (criteria.action === "audit.read"), so counting never perturbs the count.
async function _readCount() {
  var rows = await b.audit.query({ action: "audit.read" });
  return rows.length;
}

// ---- Concurrent reads each emit their own audit.read ----

async function testConcurrentReadsBothLog() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    // Seed a non-read row so the concurrent queries return something and,
    // more importantly, so each emits its own self-log.
    await b.audit.record({ action: "consent.granted", outcome: "success" });

    var before = await _readCount();

    // Fire two concurrent reads. Pre-fix, the second to enter would see the
    // module-global flag set by the first (mid-record) and skip its self-log,
    // so only ONE audit.read would land. Post-fix, BOTH land.
    var qA = b.audit.query({ action: "consent.granted", actorUserId: "reader-a" });
    var qB = b.audit.query({ action: "consent.granted", actorUserId: "reader-b" });
    await Promise.all([qA, qB]);

    await waitUntil(async function () {
      return (await _readCount()) >= before + 2;
    }, { timeoutMs: 5000, label: "M3: both concurrent reads emit audit.read" });

    var after = await _readCount();
    check("two concurrent reads emit two audit.read rows (no under-logging)",
          after === before + 2);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- A single read emits exactly one audit.read (no double/recursion) ----

async function testSingleReadLogsExactlyOnce() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    await b.audit.record({ action: "consent.granted", outcome: "success" });

    var before = await _readCount();
    await b.audit.query({ action: "consent.granted" });
    var after = await _readCount();

    check("a single read emits exactly one audit.read (no double/recursive log)",
          after === before + 1);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- Querying audit.read itself does not auto-log (no Russell spiral) ----

async function testAuditReadQueryDoesNotSelfLog() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    // Generate at least one audit.read so the table is non-empty.
    await b.audit.query({ action: "consent.granted" });

    var before = await _readCount();
    // Querying for audit.read must NOT emit another audit.read.
    await b.audit.query({ action: "audit.read" });
    var after = await _readCount();

    check("querying action='audit.read' does not auto-log a new audit.read",
          after === before);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- The WRITE path does not audit itself either ----

// Count out-of-band, through the driver rather than through clusterStorage, so
// the measurement does not issue the very kind of query under test.
async function _chainRows(driver) {
  var client = await driver.connect();
  var r = await driver.query(client, "SELECT count(*) AS n FROM _blamejs_audit_log", []);
  await driver.close(client);
  return Number(r.rows[0].n);
}

async function _chainMax(driver) {
  var client = await driver.connect();
  var r = await driver.query(client,
    "SELECT COALESCE(MAX(monotonicCounter), 0) AS m FROM _blamejs_audit_log", []);
  await driver.close(client);
  return Number(r.rows[0].m);
}

async function testChainWriteDoesNotAuditItself() {
  var tmpDir = _tmp();
  b.cluster._resetForTest();
  await setupTestDb(tmpDir);
  var driver = helpers._makeSqliteDriver(path.join(tmpDir, "ops.db"));
  try {
    b.externalDb.init({
      backends: {
        ops: {
          connect: driver.connect, query: driver.query, close: driver.close,
          dialect: "sqlite",
        },
      },
    });
    await b.frameworkSchema.ensureSchema({
      externalDbBackend: "ops", dialect: "sqlite",
    });
    await b.cluster.init({
      nodeId:            "audit-selflog-node",
      role:              "leader",
      externalDbBackend: "ops",
      dialect:           "sqlite",
    });

    // Settle what booting buffered, so the measurement starts from a quiet chain.
    await b.audit.flush();
    var before = await _chainRows(driver);

    await b.audit.record({ action: "consent.granted", outcome: "success" });
    await b.audit.flush();
    var afterOne = await _chainRows(driver);
    check("recording one event in cluster mode appends exactly one chain row",
          afterOne === before + 1,
          "before=" + before + " after=" + afterOne);

    // Nothing records now. A chain whose own writes are audited keeps writing,
    // because each append emits an event that becomes the next append.
    await helpers.passiveObserve(800,
      "audit chain: no row appears while nothing records");
    await b.audit.flush();
    var afterQuiet = await _chainRows(driver);
    check("the chain does not grow while nothing records to it",
          afterQuiet === afterOne,
          "afterOne=" + afterOne + " afterQuiet=" + afterQuiet);

    // A checkpoint anchors a counter. Rows appended by the checkpoint's own
    // queries would land past it, leaving the anchor stale as it was written.
    var maxBeforeCk = await _chainMax(driver);
    var ck = await b.audit.checkpoint({});
    await b.audit.flush();
    var maxAfterCk = await _chainMax(driver);
    check("a checkpoint appends no row past the counter it anchors",
          ck && ck.atMonotonicCounter === maxBeforeCk && maxAfterCk === maxBeforeCk,
          "anchored=" + (ck && ck.atMonotonicCounter) +
          " maxBefore=" + maxBeforeCk + " maxAfter=" + maxAfterCk);

    // Verifying the chain walks it, so a row written per internal query would
    // grow what is being verified while the walk is running.
    var v = await b.audit.verify({});
    await b.audit.flush();
    var maxAfterVerify = await _chainMax(driver);
    check("verifying the chain appends no row to it",
          v.ok === true && maxAfterVerify === maxAfterCk,
          "ok=" + v.ok + " rowsVerified=" + v.rowsVerified +
          " maxBefore=" + maxAfterCk + " maxAfter=" + maxAfterVerify);
  } finally {
    try { await b.cluster.shutdown(); } catch (_e) {}
    try { await b.externalDb.shutdown(); } catch (_e) {}
    b.cluster._resetForTest();
    driver._close();
    await teardownTestDb(tmpDir);
  }
}

// A redirect store is operator code, and the suppression scope wraps the call to
// it. A store that lazily arms a keepalive, a listener or a retry timer on its
// first write captured that scope, so every audit event it emitted afterwards was
// dropped for the life of the process, with no error and no row.
async function testARedirectStoreKeepaliveStillAudits() {
  var tmpDir = _tmp();
  b.cluster._resetForTest();
  await setupTestDb(tmpDir);
  var armed = null;
  try {
    var recorded = [];
    var resolveFired = null;
    var fired = new Promise(function (resolve) { resolveFired = resolve; });
    b.audit.useStore({
      replaceChain: true,
      record: function (row) {
        recorded.push(row.action);
        if (armed === null) {
          armed = setTimeout(function () {
            b.audit.safeEmit({ action: "consent.revoked", outcome: "success" });
            resolveFired();
          }, 10);
        }
        return Promise.resolve();
      },
    });

    await b.audit.record({ action: "consent.granted", outcome: "success" });
    await b.audit.flush();
    check("the redirect store received the event that armed its keepalive",
          recorded.indexOf("consent.granted") !== -1, JSON.stringify(recorded));

    await fired;
    await b.audit.flush();
    // `record` runs inside the suppression, because a store that persists
    // through b.externalDb would otherwise feed itself: each write emits
    // system.externaldb.query, which is handed back to the store, which writes
    // again. So a timer the store arms in there inherits the suppression, and
    // its events are dropped. That is the trap, and the next block is the way
    // out of it.
    check("a timer armed inside record inherits the suppression",
          recorded.indexOf("consent.revoked") === -1, JSON.stringify(recorded));
  } finally {
    if (armed !== null) clearTimeout(armed);
    b.audit.useStore(null);
    b.cluster._resetForTest();
    await teardownTestDb(tmpDir);
  }
}

// The way out: arm the long-lived resource through
// b.audit.outsideSelfEmitSuppression, so what it emits later is recorded while
// the store's own persistence stays suppressed.
async function testAStoreCanArmAKeepaliveThatStillAudits() {
  var tmpDir = _tmp();
  b.cluster._resetForTest();
  await setupTestDb(tmpDir);
  var armed = null;
  try {
    var recorded = [];
    var resolveFired = null;
    var fired = new Promise(function (resolve) { resolveFired = resolve; });
    b.audit.useStore({
      replaceChain: true,
      record: function (row) {
        recorded.push(row.action);
        if (armed === null) {
          armed = b.audit.outsideSelfEmitSuppression(function () {
            return setTimeout(function () {
              b.audit.safeEmit({ action: "consent.revoked", outcome: "success" });
              resolveFired();
            }, 10);
          });
        }
        return Promise.resolve();
      },
    });

    await b.audit.record({ action: "consent.granted", outcome: "success" });
    await b.audit.flush();
    await fired;
    await b.audit.flush();
    check("a keepalive armed through the escape hatch still audits",
          recorded.indexOf("consent.revoked") !== -1, JSON.stringify(recorded));

    var refused = null;
    try { b.audit.outsideSelfEmitSuppression("not-a-function"); }
    catch (e) { refused = e; }
    check("and the hatch refuses anything that is not a function, naming itself",
          refused !== null && refused instanceof TypeError &&
          /b\.audit\.outsideSelfEmitSuppression/.test(refused.message),
          refused && refused.message);
  } finally {
    if (armed !== null) clearTimeout(armed);
    b.audit.useStore(null);
    b.cluster._resetForTest();
    await teardownTestDb(tmpDir);
  }
}

// ---- The write-path suppression is scoped, not a module-global flag ----

// Deterministic by microtask ordering. The outside function runs its synchronous
// part and suspends at `await null`, queueing its continuation first; the scope
// then opens and its own function suspends, queueing second; the queue drains, so
// the outside continuation resumes WHILE the scope is open. A module-global
// boolean is set for that whole window and the outside work would read it as set,
// which is the under-logging described at the top of this file, reached on the
// write path instead of the read path. An AsyncLocalStorage scope is invisible
// there.
async function testSuppressionIsScopedToItsOwnCallTree() {
  var ctx = require("../../lib/db-role-context");
  var insideSaw = null;
  var outsideSaw = null;

  var outside = (async function () {
    await null;
    outsideSaw = ctx.isAuditChainWrite();
  })();

  var guarded = ctx.runAsAuditChainWrite(async function () {
    await null;
    insideSaw = ctx.isAuditChainWrite();
  });

  await Promise.all([outside, guarded]);

  check("audit's own storage work is marked inside its own call tree",
        insideSaw === true, "insideSaw=" + insideSaw);
  check("and is invisible to work running outside it, so an emission from a " +
        "request running at the same time is not dropped",
        outsideSaw === false, "outsideSaw=" + outsideSaw);
  check("the mark is gone once that work finishes",
        ctx.isAuditChainWrite() === false);

  // A resource built inside the scope must not inherit it, because it outlives the
  // call that opened it. A pooled connection opened while the chain was being
  // written carried the suppression for its whole life, so every keepalive its
  // operator hook emitted afterwards was dropped: in a one-second idle window that
  // connection logged nothing while its siblings logged nine events each.
  var tickFlags = [];
  var timer = null;
  await ctx.runAsAuditChainWrite(async function () {
    await ctx.outsideAuditChainWrite(async function () {
      await null;
      timer = setInterval(function () { tickFlags.push(ctx.isAuditChainWrite()); }, 5);
    });
    check("work run outside the scope does not see it", ctx.isAuditChainWrite() === true);
  });
  await helpers.waitUntil(function () { return tickFlags.length >= 3; },
    { timeoutMs: 2000, label: "scope capture: timer ticks" });
  clearInterval(timer);
  check("a timer registered outside the scope never inherits it, however long it runs",
        tickFlags.length >= 3 && tickFlags.every(function (f) { return f === false; }),
        JSON.stringify(tickFlags.slice(0, 6)));

  // The scope deliberately OUTLIVES the call tree it opens, and the
  // `testClusterAuditFlushNoRecursionHang` regression in test/30-chain.js is
  // why: the chain write's own `externalDb.query` emits back into the handler
  // buffer, so if those emissions stop being suppressed the drain loop refills
  // as fast as it empties and `audit.flush()` spins. Ending the scope when the
  // call settles reproduces that hang deterministically.
  //
  // So a resource built inside the scope DOES inherit it, and that is why
  // anything FOREIGN the scope invokes is called through
  // `outsideAuditChainWrite`: `Pool.connect`, and the operator's own
  // `record` on an external store. Those two are the places a long-lived
  // resource gets built, and the wrapper is what keeps the inheritance from
  // reaching them.
  var inheritedFlags = [];
  var inheritedTimer = null;
  await ctx.runAsAuditChainWrite(async function () {
    await null;
    inheritedTimer = setInterval(function () {
      inheritedFlags.push(ctx.isAuditChainWrite());
    }, 5);
  });
  await helpers.waitUntil(function () { return inheritedFlags.length >= 3; },
    { timeoutMs: 2000, label: "scope capture: unwrapped timer ticks" });
  clearInterval(inheritedTimer);
  check("a resource built inside the scope inherits it, which the framework's " +
        "own storage work depends on",
        inheritedFlags.length >= 3 && inheritedFlags.every(function (f) { return f === true; }),
        JSON.stringify(inheritedFlags.slice(0, 6)));

  // And the wrapper is what a foreign callable gets, so what IT builds is
  // outside the scope for the rest of its life.
  var foreignFlags = [];
  var foreignTimer = null;
  await ctx.runAsAuditChainWrite(async function () {
    await ctx.outsideAuditChainWrite(async function () {
      await null;
      foreignTimer = setInterval(function () {
        foreignFlags.push(ctx.isAuditChainWrite());
      }, 5);
    });
  });
  await helpers.waitUntil(function () { return foreignFlags.length >= 3; },
    { timeoutMs: 2000, label: "scope capture: foreign-callable timer ticks" });
  clearInterval(foreignTimer);
  check("a resource a foreign callable builds does not, however long it runs",
        foreignFlags.length >= 3 && foreignFlags.every(function (f) { return f === false; }),
        JSON.stringify(foreignFlags.slice(0, 6)));
}

async function run() {
  await testConcurrentReadsBothLog();
  await testSingleReadLogsExactlyOnce();
  await testAuditReadQueryDoesNotSelfLog();
  await testChainWriteDoesNotAuditItself();
  await testARedirectStoreKeepaliveStillAudits();
  await testAStoreCanArmAKeepaliveThatStillAudits();
  await testSuppressionIsScopedToItsOwnCallTree();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       // Re-throw rather than console.error the error object: a DB-setup
       // failure can carry passphrase-derived material on the error, and
       // logging it would be clear-text logging of sensitive data
       // (CWE-312). The non-zero exit + thrown stack still surface the
       // failure to the runner.
       .catch(function (e) { process.exitCode = 1; throw e; });
}
