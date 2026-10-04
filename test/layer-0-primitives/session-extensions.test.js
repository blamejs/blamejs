// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.session — v0.8.61 extensions:
 *   - clientIpPrefix fingerprint field (auto /24 IPv4 + /64 IPv6 mask)
 *   - PQC-sealed sid cookie default (token = vault.seal(sid))
 *   - Pluggable session store via b.session.useStore + stores.localDbThin
 */

var helpers = require("../helpers");
var b              = helpers.b;
var fs             = helpers.fs;
var os             = helpers.os;
var path           = helpers.path;
var check          = helpers.check;
var setupTestDb    = helpers.setupTestDb;
var teardownTestDb = helpers.teardownTestDb;

function _makeReq(headers) {
  return {
    headers: headers || {},
    socket:  { remoteAddress: (headers && headers["x-forwarded-for"]) || "" },
  };
}

async function testSealedCookieDefault() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ses-sealed-"));
  try {
    await setupTestDb(tmpDir);
    var s = await b.session.create({ userId: "u-1", data: { role: "user" } });
    check("create returns string token",                typeof s.token === "string");
    check("token is sealed (vault: prefix)",            s.token.indexOf("vault:") === 0);

    var info = await b.session.verify(s.token);
    check("verify accepts sealed token",                info && info.userId === "u-1");

    // Pre-v0.8.61 raw-sid format: a 64-char hex string (64 random
    // bytes hex-encoded). The sealed-cookie default refuses it cleanly.
    var raw = "deadbeefcafef00d".repeat(4);
    var nullInfo = await b.session.verify(raw);
    check("verify refuses pre-v0.8.61 raw-format token", nullInfo === null);

    // A garbage sealed envelope (right prefix, wrong ciphertext) also
    // returns null rather than throwing — caller's re-auth flow.
    var bogus = await b.session.verify("vault:not-real-ciphertext");
    check("verify refuses tampered sealed envelope",     bogus === null);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testSealedCookieRotateAndDestroy() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ses-sealed-r-"));
  try {
    await setupTestDb(tmpDir);
    var s = await b.session.create({ userId: "u-2" });
    var rotated = await b.session.rotate(s.token);
    check("rotate returns sealed token",                 rotated && rotated.token.indexOf("vault:") === 0);
    check("rotate token differs from original",          rotated.token !== s.token);
    var oldStill = await b.session.verify(s.token);
    check("old token no longer verifies",                oldStill === null);
    var newOk = await b.session.verify(rotated.token);
    check("new token verifies",                          newOk && newOk.userId === "u-2");

    var destroyed = await b.session.destroy(rotated.token);
    check("destroy unseals + deletes",                   destroyed === true);
    var afterDestroy = await b.session.verify(rotated.token);
    check("verify returns null after destroy",           afterDestroy === null);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testClientIpPrefixV4() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ses-prefix-v4-"));
  try {
    await setupTestDb(tmpDir);
    // Same /24, different last octet — should NOT drift.
    var req1 = _makeReq({ "x-forwarded-for": "203.0.113.10", "user-agent": "ua1" });
    var s = await b.session.create({
      userId:            "u-1",
      req:               req1,
      fingerprintFields: ["clientIpPrefix", "userAgent"],
    });
    var req2 = _makeReq({ "x-forwarded-for": "203.0.113.250", "user-agent": "ua1" });
    var info = await b.session.verify(s.token, {
      req: req2,
      fingerprintFields: ["clientIpPrefix", "userAgent"],
    });
    check("clientIpPrefix v4: same /24 — no drift", info && info.fingerprintDrift === false);

    // Different /24 — should drift.
    var req3 = _makeReq({ "x-forwarded-for": "198.51.100.1", "user-agent": "ua1" });
    var info2 = await b.session.verify(s.token, {
      req: req3,
      fingerprintFields: ["clientIpPrefix", "userAgent"],
    });
    check("clientIpPrefix v4: cross-/24 — drift detected", info2 && info2.fingerprintDrift === true);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testClientIpPrefixV6() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ses-prefix-v6-"));
  try {
    await setupTestDb(tmpDir);
    // Same /64, different host bits.
    var req1 = _makeReq({ "x-forwarded-for": "2001:db8:1234:5678::1", "user-agent": "ua1" });
    var s = await b.session.create({
      userId:            "u-1",
      req:               req1,
      fingerprintFields: ["clientIpPrefix", "userAgent"],
    });
    var req2 = _makeReq({ "x-forwarded-for": "2001:db8:1234:5678:abcd:ef01:2345:6789", "user-agent": "ua1" });
    var info = await b.session.verify(s.token, {
      req: req2,
      fingerprintFields: ["clientIpPrefix", "userAgent"],
    });
    check("clientIpPrefix v6: same /64 — no drift", info && info.fingerprintDrift === false);

    // Different /64 — should drift.
    var req3 = _makeReq({ "x-forwarded-for": "2001:db8:1234:9999::1", "user-agent": "ua1" });
    var info2 = await b.session.verify(s.token, {
      req: req3,
      fingerprintFields: ["clientIpPrefix", "userAgent"],
    });
    check("clientIpPrefix v6: cross-/64 — drift detected", info2 && info2.fingerprintDrift === true);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testClientIpPrefixV4MappedV6() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ses-prefix-mapped-"));
  try {
    await setupTestDb(tmpDir);
    // ::ffff:1.2.3.4 (v4-mapped-v6) is bucketed as v4 /24.
    var req1 = _makeReq({ "x-forwarded-for": "::ffff:203.0.113.5", "user-agent": "ua1" });
    var s = await b.session.create({
      userId:            "u-1",
      req:               req1,
      fingerprintFields: ["clientIpPrefix"],
    });
    var req2 = _makeReq({ "x-forwarded-for": "203.0.113.99", "user-agent": "ua1" });
    var info = await b.session.verify(s.token, {
      req: req2,
      fingerprintFields: ["clientIpPrefix"],
    });
    check("clientIpPrefix: ::ffff: maps to v4 /24 bucket", info && info.fingerprintDrift === false);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// A request whose immediate peer is a reverse proxy: the socket peer is the
// proxy, the real client arrives in X-Forwarded-For.
function _makeProxiedReq(proxyAddr, clientIp) {
  return {
    headers: { "x-forwarded-for": clientIp, "user-agent": "ua1" },
    socket:  { remoteAddress: proxyAddr },
  };
}

async function testFingerprintPeerGatedClientIp() {
  // Behind a trusted proxy the client IP arrives in X-Forwarded-For while the
  // socket peer is the proxy. The bare-socket default binds the fingerprint to
  // the PROXY, so two different real clients behind the same proxy share a
  // fingerprint — the IP component is silently defeated. The { trustedProxies }
  // option peer-gates the resolve (consistent with trustedClientIp) so the real
  // client is bound. Both halves are proven here: the default still binds the
  // proxy (a different real client does NOT drift), and the opt makes a
  // different real client DRIFT.
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ses-peergate-"));
  try {
    await setupTestDb(tmpDir);
    var PROXY = "10.0.0.7";
    var TP = ["10.0.0.0/8"];

    // --- Legacy default (no trustedProxies): binds to the proxy address, so a
    // different real client behind the same proxy does NOT drift.
    var sLegacy = await b.session.create({
      userId: "u-legacy", req: _makeProxiedReq(PROXY, "203.0.113.10"),
      fingerprintFields: ["clientIp"],
    });
    var legacy = await b.session.verify(sLegacy.token, {
      req: _makeProxiedReq(PROXY, "198.51.100.9"), fingerprintFields: ["clientIp"],
    });
    check("bare-socket default: different real client behind proxy does NOT drift (proxy-bound)",
      legacy && legacy.fingerprintDrift === false);

    // --- Peer-gated (trustedProxies): resolves the real client from XFF.
    var sGated = await b.session.create({
      userId: "u-gated", req: _makeProxiedReq(PROXY, "203.0.113.10"),
      fingerprintFields: ["clientIp"], trustedProxies: TP,
    });
    var sameClient = await b.session.verify(sGated.token, {
      req: _makeProxiedReq(PROXY, "203.0.113.10"),
      fingerprintFields: ["clientIp"], trustedProxies: TP,
    });
    check("peer-gated: same real client behind proxy does not drift",
      sameClient && sameClient.fingerprintDrift === false);
    var diffClient = await b.session.verify(sGated.token, {
      req: _makeProxiedReq(PROXY, "198.51.100.9"),
      fingerprintFields: ["clientIp"], trustedProxies: TP,
    });
    check("peer-gated: different real client behind proxy DRIFTS (real client bound)",
      diffClient && diffClient.fingerprintDrift === true);

    // A forged XFF from a NON-trusted peer must be ignored (peer-gating) — the
    // resolve falls back to the untrusted socket address, so a forged header
    // can't make the real-client binding drift on its own.
    var sDirect = await b.session.create({
      userId: "u-direct", req: _makeProxiedReq("203.0.113.50", "203.0.113.10"),
      fingerprintFields: ["clientIp"], trustedProxies: TP,
    });
    var forged = await b.session.verify(sDirect.token, {
      // same untrusted socket peer, attacker varies the forgeable XFF.
      req: _makeProxiedReq("203.0.113.50", "8.8.8.8"),
      fingerprintFields: ["clientIp"], trustedProxies: TP,
    });
    check("peer-gated: forged XFF from an untrusted peer is ignored (no drift on header alone)",
      forged && forged.fingerprintDrift === false);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testPluggableStore() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ses-store-"));
  try {
    await setupTestDb(tmpDir);
    var storeFile = path.join(tmpDir, "thin-sessions.db");
    var store = b.session.stores.localDbThin({ file: storeFile });
    b.session.useStore(store);

    var s = await b.session.create({ userId: "u-1", data: { team: "a" } });
    var info = await b.session.verify(s.token);
    check("pluggable store: create + verify round-trip", info && info.userId === "u-1");
    check("pluggable store: data round-trips",           info.data && info.data.team === "a");

    var n = await b.session.count();
    check("pluggable store: count reads from thin DB",   n === 1);

    // Both purges read and delete through the documented store contract, which
    // is `execute` + `executeOne`. Reaching for anything else threw
    // TypeError: store.executeAll is not a function on every store-backed
    // deployment, this first-party adapter included.
    var expired = await b.session.purgeExpired({ batchSize: 2 });
    check("pluggable store: purgeExpired runs on execute/executeOne alone",
      expired === 0, "removed=" + expired);
    check("pluggable store: and leaves a live session in place",
      (await b.session.count()) === 1);

    await helpers.passiveObserve(20,
      "session purge: age the row past a 1ms idle window");
    var stale = await b.session.purgeStale({
      idleTimeoutMs: 1, absoluteTimeoutMs: 0, batchSize: 2,
    });
    check("pluggable store: purgeStale removes a session past its idle limit",
      stale === 1, "removed=" + stale);
    check("pluggable store: and the row is gone",
      (await b.session.count()) === 0);

    var again = await b.session.create({ userId: "u-1", data: { team: "a" } });
    check("pluggable store: a session created after the purge still verifies",
      !!(await b.session.verify(again.token)));

    var revoked = await b.session.destroyAllForUser("u-1");
    check("pluggable store: destroyAllForUser drops 1",  revoked === 1);

    // Revert to default so subsequent tests don't carry the override.
    b.session.useStore(null);
    store.close();
    check("pluggable store: useStore(null) reverts",     true);
  } finally {
    b.session.useStore(null);
    await teardownTestDb(tmpDir);
  }
}

// A purge selects the keys it will remove and then deletes them. A session
// refreshed in between no longer matches the condition that picked it, and the
// delete used to match on the key alone, so the sweep revoked an active
// session. The store wrapper below performs that refresh at exactly that point.
async function testPurgeDoesNotRevokeARefreshedSession() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ses-purge-race-"));
  var store = null;
  try {
    await setupTestDb(tmpDir);
    store = b.session.stores.localDbThin({ file: path.join(tmpDir, "race.db") });
    var refreshedOnce = false;
    var deletes = [];
    b.session.useStore({
      execute: async function (text, params) {
        if (/^\s*delete/i.test(text)) deletes.push(text);
        var res = await store.execute(text, params);
        if (!refreshedOnce && /select/i.test(text) && text.indexOf("lastActivity") !== -1) {
          refreshedOnce = true;
          await store.execute(
            "UPDATE _blamejs_sessions SET lastActivity = ?", [Date.now() + 60000]);
        }
        return res;
      },
      executeOne: function (text, params) { return store.executeOne(text, params); },
    });

    var s = await b.session.create({ userId: "u-race" });
    check("purge race: the session starts out verifiable",
      !!(await b.session.verify(s.token)));

    await helpers.passiveObserve(20,
      "session purge race: age the row past a 1ms idle window");
    var removed = await b.session.purgeStale({
      idleTimeoutMs: 1, absoluteTimeoutMs: 0, batchSize: 10,
    });
    check("purge race: the refresh happened at the select", refreshedOnce);
    check("purge race: the refreshed session is not deleted",
      removed === 0, "removed=" + removed);
    check("purge race: and its row is still there", (await b.session.count()) === 1);
    check("purge race: and it still verifies",
      !!(await b.session.verify(s.token)));
    check("purge race: the idle sweep's DELETE carries the idle condition",
      deletes.some(function (t) { return t.indexOf("lastActivity") !== -1; }),
      deletes.join(" ~~ "));
  } finally {
    b.session.useStore(null);
    try { if (store && store.close) store.close(); } catch (_e) { /* best-effort */ }
    await teardownTestDb(tmpDir);
  }
}

// Batching bounds what one statement WRITES; it has to bound what each pass
// READS too. Each pass re-runs the select, so ordering by the primary key made
// every pass walk the whole table to find the matching rows: on the first-party
// SQLite store the plan was `SCAN sessions USING INDEX sqlite_autoindex_sessions_1`
// rather than a range over the expiry index, and a 200,000-row table with 10%
// expired took 1,574ms to sweep in batches of 500 against 44ms ordered by
// `expiresAt`. Ordering by the column the sweep filters on is what makes the
// read work proportional to the rows being removed, so each sweep asserts it.
async function testEachSweepOrdersByTheColumnItFilters() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ses-purge-order-"));
  var store = null;
  try {
    await setupTestDb(tmpDir);
    store = b.session.stores.localDbThin({ file: path.join(tmpDir, "order.db") });
    var selects = [];
    b.session.useStore({
      execute: function (text, params) {
        if (/^\s*select/i.test(text)) selects.push(text);
        return store.execute(text, params);
      },
      executeOne: function (text, params) { return store.executeOne(text, params); },
    });

    await b.session.create({ userId: "u-order" });

    selects.length = 0;
    await b.session.purgeExpired({ batchSize: 5 });
    check("the expiry sweep orders by expiresAt, which the table indexes",
      selects.some(function (t) { return /order\s+by[^)]*expiresAt/i.test(t); }),
      selects.join(" ~~ "));
    check("and no sweep orders by the primary key, which ignores that index",
      !selects.some(function (t) { return /order\s+by[^)]*sidHash/i.test(t); }),
      selects.join(" ~~ "));

    selects.length = 0;
    await b.session.purgeStale({ idleTimeoutMs: 1, absoluteTimeoutMs: 0, batchSize: 5 });
    check("the idle sweep orders by lastActivity",
      selects.some(function (t) { return /order\s+by[^)]*lastActivity/i.test(t); }),
      selects.join(" ~~ "));

    selects.length = 0;
    await b.session.purgeStale({ idleTimeoutMs: 0, absoluteTimeoutMs: 1, batchSize: 5 });
    check("the absolute sweep orders by createdAt",
      selects.some(function (t) { return /order\s+by[^)]*createdAt/i.test(t); }),
      selects.join(" ~~ "));
  } finally {
    b.session.useStore(null);
    try { if (store && store.close) store.close(); } catch (_e) { /* best-effort */ }
    await teardownTestDb(tmpDir);
  }
}

// A batched sweep has to clear the table, not stop at a batch count and report
// success over what it left behind. With a cap of 10000 passes, a batchSize of
// 1 left every row past the 10000th in place and returned as though it had
// finished.
async function testPurgeClearsTheTableAcrossPassesOrSaysItCannot() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ses-purge-batches-"));
  var store = null;
  try {
    await setupTestDb(tmpDir);
    store = b.session.stores.localDbThin({ file: path.join(tmpDir, "batches.db") });
    // Wrapped from the start: `useStore` closes the store it replaces, so
    // installing the real one first and the wrapper second leaves the wrapper
    // delegating to a closed handle.
    var swallowDeletes = false;
    b.session.useStore({
      execute: async function (text, params) {
        if (swallowDeletes && /^\s*delete/i.test(text)) return { rows: [], rowCount: 0 };
        return await store.execute(text, params);
      },
      executeOne: function (text, params) { return store.executeOne(text, params); },
    });

    for (var i = 0; i < 5; i += 1) await b.session.create({ userId: "u-batch-" + i });
    check("batched purge: five sessions are stored", (await b.session.count()) === 5);

    await helpers.passiveObserve(20,
      "session purge: age the rows past a 1ms idle window");
    var removed = await b.session.purgeStale({
      idleTimeoutMs: 1, absoluteTimeoutMs: 0, batchSize: 1,
    });
    check("batched purge: one row per pass still clears every row",
      removed === 5, "removed=" + removed);
    check("batched purge: the table is empty", (await b.session.count()) === 0);

    // A sweep that cannot delete what it keeps matching says so rather than
    // returning a count that looks like a completed sweep.
    await b.session.create({ userId: "u-stall" });
    swallowDeletes = true;
    await helpers.passiveObserve(20,
      "session purge: age the stalled row past a 1ms idle window");
    var stalled = null;
    try {
      await b.session.purgeStale({ idleTimeoutMs: 1, absoluteTimeoutMs: 0, batchSize: 1 });
    } catch (e) { stalled = e; }
    check("batched purge: a sweep that deletes nothing it matches raises",
      stalled !== null && stalled.code === "session/purge-stalled",
      "code=" + (stalled && stalled.code));

    // The same, with a batch larger than the matching set. A batch shorter than
    // `batchSize` used to end the sweep before a second pass could see that the
    // delete had removed nothing, so one undeletable row returned 0 as success.
    var stalledShort = null;
    try {
      await b.session.purgeStale({ idleTimeoutMs: 1, absoluteTimeoutMs: 0, batchSize: 500 });
    } catch (e) { stalledShort = e; }
    check("batched purge: a short batch that deletes nothing also raises",
      stalledShort !== null && stalledShort.code === "session/purge-stalled",
      "code=" + (stalledShort && stalledShort.code));
    check("batched purge: and the stalled sweep names what it did remove",
      stalledShort !== null && /0 row\(s\) were removed/.test(stalledShort.message || ""),
      stalledShort && stalledShort.message);

    swallowDeletes = false;
    var finished = await b.session.purgeStale({
      idleTimeoutMs: 1, absoluteTimeoutMs: 0, batchSize: 500,
    });
    check("batched purge: once the delete works the sweep finishes",
      finished === 1 && (await b.session.count()) === 0, "removed=" + finished);
  } finally {
    b.session.useStore(null);
    try { if (store && store.close) store.close(); } catch (_e) { /* best-effort */ }
    await teardownTestDb(tmpDir);
  }
}

// The stall guard compared this pass's keys to the last pass's POSITIONALLY,
// and the SELECT carried no ORDER BY, so a store free to return the same
// matching set in a different order reset the guard on every pass. The sweep
// then ran to its pass cap: measured at 1,000,001 passes and 6.2 seconds with
// the event loop never yielding once. Three things have to hold: the order is
// fixed, the guard reads the key SET, and the loop gives the event loop a turn.
async function testPurgeStallGuardSurvivesRowOrderAndYields() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ses-purge-order-"));
  var store = null;
  try {
    await setupTestDb(tmpDir);
    store = b.session.stores.localDbThin({ file: path.join(tmpDir, "order.db") });
    var rotate = false;
    var selects = 0;
    var sawOrderBy = false;
    b.session.useStore({
      execute: async function (text, params) {
        if (/^\s*delete/i.test(text)) return { rows: [], rowCount: 0 };
        var res = await store.execute(text, params);
        if (/select/i.test(text) && text.indexOf("sidHash") !== -1) {
          selects += 1;
          if (/order\s+by/i.test(text)) sawOrderBy = true;
          rotate = !rotate;
          if (rotate && res && res.rows) {
            return { rows: res.rows.slice().reverse(), rowCount: res.rowCount };
          }
        }
        return res;
      },
      executeOne: function (text, params) { return store.executeOne(text, params); },
    });

    await b.session.create({ userId: "u-order-1" });
    await b.session.create({ userId: "u-order-2" });
    await b.session.create({ userId: "u-order-3" });

    var ticks = 0;
    var ticker = setInterval(function () { ticks += 1; }, 10);
    await helpers.passiveObserve(20, "session purge: age the rows past a 1ms idle window");
    var started = Date.now();
    var stalled = null;
    try {
      await b.session.purgeStale({ idleTimeoutMs: 1, absoluteTimeoutMs: 0, batchSize: 2 });
    } catch (e) { stalled = e; }
    var elapsedMs = Date.now() - started;
    clearInterval(ticker);

    check("a sweep whose rows come back in a rotating order still reports the stall",
      stalled !== null && stalled.code === "session/purge-stalled",
      "code=" + (stalled && stalled.code));
    check("and reaches that conclusion in a handful of passes, not a million",
      selects <= 12, "selects=" + selects + " elapsedMs=" + elapsedMs);
    check("the select fixes the row order itself", sawOrderBy);
    check("and the sweep leaves the event loop turns to take",
      ticks >= 1, "ticks=" + ticks + " elapsedMs=" + elapsedMs);
  } finally {
    b.session.useStore(null);
    try { if (store && store.close) store.close(); } catch (_e) { /* best-effort */ }
    await teardownTestDb(tmpDir);
  }
}

// A store that simply omits rowCount on a DELETE is terse, not broken. Counting
// every such pass as a full batch both invented a total and removed the only
// signal that could stop the loop, so the sweep ran to the pass cap and then
// reported millions of rows removed from a table it had not touched.
async function testPurgeDoesNotInventARemovalCount() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ses-purge-count-"));
  var store = null;
  try {
    await setupTestDb(tmpDir);
    store = b.session.stores.localDbThin({ file: path.join(tmpDir, "count.db") });
    var deletes = 0;
    b.session.useStore({
      execute: async function (text, params) {
        if (/^\s*delete/i.test(text)) { deletes += 1; return { rows: [] }; }
        return await store.execute(text, params);
      },
      executeOne: function (text, params) { return store.executeOne(text, params); },
    });

    await b.session.create({ userId: "u-count-1" });
    await b.session.create({ userId: "u-count-2" });
    await helpers.passiveObserve(20, "session purge: age the rows past a 1ms idle window");

    var stalled = null;
    try {
      await b.session.purgeStale({ idleTimeoutMs: 1, absoluteTimeoutMs: 0, batchSize: 500 });
    } catch (e) { stalled = e; }
    check("a store that omits rowCount and deletes nothing still reports the stall",
      stalled !== null && stalled.code === "session/purge-stalled",
      "code=" + (stalled && stalled.code));
    check("in a couple of passes rather than the pass cap",
      deletes <= 4, "deletes=" + deletes);
    check("and the message does not claim rows it never removed",
      stalled !== null && /\b0 row\(s\) were removed/.test(stalled.message || ""),
      stalled && stalled.message);
  } finally {
    b.session.useStore(null);
    try { if (store && store.close) store.close(); } catch (_e) { /* best-effort */ }
    await teardownTestDb(tmpDir);
  }
}

// The other half of that store: one that omits rowCount and DOES delete. An
// unknown count is not a zero, and treating it as one made every pass look like
// no progress, so the consecutive-idle guard stopped the sweep partway and left
// rows behind. The repeated-key check is what covers a stall here, since a pass
// that deleted nothing matches the same keys again.
async function testPurgeFinishesWhenAStoreOmitsRowCountButDeletes() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ses-purge-silent-"));
  var store = null;
  try {
    await setupTestDb(tmpDir);
    store = b.session.stores.localDbThin({ file: path.join(tmpDir, "silent.db") });
    b.session.useStore({
      execute: async function (text, params) {
        var res = await store.execute(text, params);
        // Terse but correct: the delete happened, the count is not reported.
        if (/^\s*delete/i.test(text)) return { rows: [] };
        return res;
      },
      executeOne: function (text, params) { return store.executeOne(text, params); },
    });

    for (var i = 0; i < 20; i += 1) {
      await b.session.create({ userId: "u-silent-" + i });
    }
    check("twenty sessions exist before the sweep", (await b.session.count()) === 20);
    await helpers.passiveObserve(20, "session purge: age the rows past a 1ms idle window");

    var failed = null;
    var removed = 0;
    try {
      removed = await b.session.purgeStale({
        idleTimeoutMs: 1, absoluteTimeoutMs: 0, batchSize: 1,
      });
    } catch (e) { failed = e; }
    check("a sweep in batches of 1 clears the table rather than stalling partway",
      failed === null, failed && failed.code + ": " + failed.message);
    check("and every row is gone", (await b.session.count()) === 0);
    check("while the total stays at what the deletes reported, which is nothing",
      removed === 0, "removed=" + removed);
  } finally {
    b.session.useStore(null);
    try { if (store && store.close) store.close(); } catch (_e) { /* best-effort */ }
    await teardownTestDb(tmpDir);
  }
}

// batchSize binds one parameter per picked key plus the narrowing cutoff, and
// node:sqlite refuses more than 32766 bound parameters. The option was bounded
// below and not above, so an operator raising it to cut round trips got the
// driver's own untyped error and a table that had not been touched.
async function testPurgeBatchSizeHasADocumentedCeiling() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ses-purge-batchmax-"));
  var store = null;
  try {
    await setupTestDb(tmpDir);
    store = b.session.stores.localDbThin({ file: path.join(tmpDir, "batchmax.db") });
    b.session.useStore(store);
    await b.session.create({ userId: "u-batchmax" });

    var tooBig = null;
    try { await b.session.purgeExpired({ batchSize: 40000 }); }
    catch (e) { tooBig = e; }
    check("a batchSize past the ceiling is refused with the session's own code",
      tooBig !== null && tooBig.code === "session/bad-batch-size",
      "code=" + (tooBig && tooBig.code));
    check("and the refusal names the ceiling",
      tooBig !== null && /10000/.test(tooBig.message || ""), tooBig && tooBig.message);

    var staleTooBig = null;
    try { await b.session.purgeStale({ batchSize: 40000 }); }
    catch (e) { staleTooBig = e; }
    check("purgeStale refuses it the same way",
      staleTooBig !== null && staleTooBig.code === "session/bad-batch-size",
      "code=" + (staleTooBig && staleTooBig.code));

    // The control: the ceiling itself is accepted and sweeps normally.
    var atCeiling = await b.session.purgeExpired({ batchSize: 10000 });
    check("the ceiling value itself is accepted", typeof atCeiling === "number",
      "removed=" + atCeiling);
  } finally {
    b.session.useStore(null);
    try { if (store && store.close) store.close(); } catch (_e) { /* best-effort */ }
    await teardownTestDb(tmpDir);
  }
}

async function testDestroyAllForUserPluggableNoDb() {
  // #340: a pluggable-store consumer who never ran b.db.init() must get a
  // clear, actionable error from destroyAllForUser — not the opaque
  // db/not-initialized that bubbled out of the stateless valid-from bump
  // (which writes to the framework db, not the pluggable session store).
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ses-nodb-"));
  try {
    await helpers.setupVaultOnly(tmpDir);   // vault up; b.db deliberately NOT initialized
    b.session.useStore({
      execute:    function () { return Promise.resolve({ rowCount: 1 }); },
      executeOne: function () { return Promise.resolve(null); },
    });
    var err = null;
    try { await b.session.destroyAllForUser("u-1"); }
    catch (e) { err = e; }
    check("destroyAllForUser (pluggable store, no b.db) → clear error, not db/not-initialized",
      err !== null && err.code !== "db/not-initialized" && /b\.db\.init\(\)/.test(err.message || ""));
  } finally {
    b.session.useStore(null);
    helpers.teardownVaultOnly(tmpDir);
  }
}

async function testPluggableStoreValidation() {
  var threw = false;
  try { b.session.useStore({ execute: function () {} }); }
  catch (e) { threw = /executeOne/.test(e.message); }
  check("useStore: missing executeOne refused", threw);

  threw = false;
  try { b.session.useStore("not-an-object"); }
  catch (e) { threw = /must be an object exposing/.test(e.message) && e.code === "session/invalid-arg" && e.permanent === true; }
  check("useStore: non-object refused", threw);

  threw = false;
  try { b.session.stores.localDbThin({}); }
  catch (e) { threw = /session-stores\/bad-file/.test(e.message) && e instanceof TypeError; }
  check("stores.localDbThin: missing file refused", threw);
}

async function testUpdateDataReplaceAndMerge() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ses-update-"));
  try {
    await setupTestDb(tmpDir);
    var s = await b.session.create({
      userId: "u-1",
      data:   { theme: "light", roles: ["user"], counter: 1 },
    });

    // Default = full replace. counter / roles drop; only `theme` lands.
    var ok = await b.session.updateData(s.token, { theme: "dark" });
    check("updateData: returns true on hit",                ok === true);
    var v1 = await b.session.verify(s.token);
    check("updateData: replaced payload — theme=dark",      v1.data.theme === "dark");
    check("updateData: replaced payload — counter dropped", v1.data.counter === undefined);
    check("updateData: replaced payload — roles dropped",   v1.data.roles === undefined);

    // Merge mode preserves existing keys, replaces named keys.
    await b.session.updateData(s.token, { roles: ["admin"], counter: 2 }, { merge: true });
    var v2 = await b.session.verify(s.token);
    check("updateData merge: theme preserved",              v2.data.theme === "dark");
    check("updateData merge: roles updated",                Array.isArray(v2.data.roles) && v2.data.roles[0] === "admin");
    check("updateData merge: counter updated",              v2.data.counter === 2);

    // Setting data: null clears the payload.
    await b.session.updateData(s.token, null);
    var v3 = await b.session.verify(s.token);
    check("updateData null: data cleared",                  v3.data === null);

    // Unknown / invalid token returns false (no throw).
    var miss = await b.session.updateData("vault:not-a-real-token", { x: 1 });
    check("updateData: unknown token returns false",        miss === false);

    var pre = await b.session.updateData("not-sealed-prefix", { x: 1 });
    check("updateData: pre-v0.8.61 raw token returns false", pre === false);

    // Bad shape refused at config time.
    var threw = false;
    try { await b.session.updateData(s.token, [1, 2, 3]); }
    catch (e) { threw = /must be a plain object or null/.test(e.message); }
    check("updateData: array refused",                      threw);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// updateData({ merge: true }) documents "Inner objects merge ONE LEVEL DEEP;
// arrays REPLACE". Only a codebase-patterns detector asserted that, and a
// detector reads the shape of the code rather than what it does. These drive
// the behaviour, including the shapes that must NOT merge: Object.assign over
// a Buffer produces byte-index keys, and over a Date produces nothing at all,
// so either one merged would destroy the value the caller wrote.
async function testUpdateDataMergeDepthAndValueShapes() {
  var vm = require("node:vm");
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ses-merge-shapes-"));
  try {
    await setupTestDb(tmpDir);

    // An inner plain object merges one level deep: the keys already inside it
    // survive alongside the ones written.
    var s1 = await b.session.create({
      userId: "u-depth", data: { prefs: { theme: "light", lang: "en" } },
    });
    await b.session.updateData(s1.token, { prefs: { theme: "dark" } }, { merge: true });
    var d1 = (await b.session.verify(s1.token)).data;
    check("merge depth: the written inner key lands",      d1.prefs.theme === "dark");
    check("merge depth: the existing inner key survives",  d1.prefs.lang === "en");

    // The same, when the inner object was built in another realm. Deciding
    // plainness by comparing against this realm's Object.prototype read it as
    // not-plain and replaced the whole inner object, dropping `lang`.
    var s2 = await b.session.create({
      userId: "u-realm", data: { prefs: { theme: "light", lang: "en" } },
    });
    var ctx = vm.createContext({ made: null });
    vm.runInContext('made = { theme: "dark" };', ctx);
    await b.session.updateData(s2.token, { prefs: ctx.made }, { merge: true });
    var d2 = (await b.session.verify(s2.token)).data;
    check("merge depth: a cross-realm inner object lands its key",
          d2.prefs.theme === "dark");
    check("merge depth: a cross-realm inner object still merges one level deep",
          d2.prefs.lang === "en");

    // An array replaces rather than merging, as documented.
    var s3 = await b.session.create({ userId: "u-arr", data: { roles: ["a", "b"] } });
    await b.session.updateData(s3.token, { roles: ["c"] }, { merge: true });
    var d3 = (await b.session.verify(s3.token)).data;
    check("merge shapes: an array replaces",
          Array.isArray(d3.roles) && d3.roles.length === 1 && d3.roles[0] === "c");

    // A Date replaces. Merging one would run Object.assign over a value with
    // no own enumerable keys, so the old object would be kept and the Date
    // lost entirely.
    var s4 = await b.session.create({ userId: "u-date", data: { at: { old: 1 } } });
    var when = new Date(Date.UTC(2026, 0, 2, 3, 4, 5));
    await b.session.updateData(s4.token, { at: when }, { merge: true });
    var d4 = (await b.session.verify(s4.token)).data;
    check("merge shapes: a Date replaces rather than vanishing",
          d4.at === when.toISOString() &&
          !(d4.at && typeof d4.at === "object" && d4.at.old === 1));

    // A Buffer replaces. Merging one would spread it into byte-index keys.
    var s5 = await b.session.create({ userId: "u-buf", data: { blob: { old: 1 } } });
    await b.session.updateData(s5.token, { blob: Buffer.from([7, 8]) }, { merge: true });
    var d5 = (await b.session.verify(s5.token)).data;
    check("merge shapes: a Buffer does not merge into byte-index keys",
          !(d5.blob && typeof d5.blob === "object" && d5.blob["0"] === 7 && d5.blob.old === 1));
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testUpdateDataPreservesFingerprint() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ses-update-fp-"));
  try {
    await setupTestDb(tmpDir);
    var req = {
      headers: { "user-agent": "ua-fp-1", "x-forwarded-for": "203.0.113.10" },
      socket:  { remoteAddress: "203.0.113.10" },
    };
    var s = await b.session.create({
      userId:            "u-1",
      data:              { roles: ["user"] },
      req:               req,
      fingerprintFields: ["clientIp", "userAgent"],
    });

    // updateData replaces operator data wholesale BUT must preserve the
    // reserved __bj_fingerprint binding so verify() with the same req
    // still surfaces fingerprintDrift: false.
    await b.session.updateData(s.token, { roles: ["admin"] });
    var info = await b.session.verify(s.token, {
      req: req, fingerprintFields: ["clientIp", "userAgent"],
    });
    check("updateData preserves fingerprint binding",       info && info.fingerprintDrift === false);
    check("updateData payload reflects the write",           info.data.roles[0] === "admin");
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testRotateRekeysFingerprint() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ses-rotate-fp-"));
  try {
    await setupTestDb(tmpDir);
    var req = _makeReq({ "user-agent": "ua-rot-1", "x-forwarded-for": "203.0.113.10" });
    var s = await b.session.create({
      userId:            "u-rot",
      data:              { roles: ["user"] },
      req:               req,
      fingerprintFields: ["clientIp", "userAgent"],
    });
    var pre = await b.session.verify(s.token, { req: req, fingerprintFields: ["clientIp", "userAgent"] });
    check("rotate-fp: pre-rotation no drift", pre && pre.fingerprintDrift === false);

    // Rotation (login transition / role escalation) moves the sid. __bj_fingerprint
    // is sid-keyed, so the new session must RE-KEY the binding to the new sid from
    // the live request — otherwise verify(newToken, sameReq) recomputes against the
    // new sid and falsely reports drift (logout under strict operators), or the
    // binding silently breaks.
    var rotated = await b.session.rotate(s.token, {
      req: req, fingerprintFields: ["clientIp", "userAgent"],
    });
    check("rotate-fp: rotation returns a new token", rotated && typeof rotated.token === "string");

    var sameDevice = await b.session.verify(rotated.token, {
      req: req, fingerprintFields: ["clientIp", "userAgent"],
    });
    check("rotate-fp: same device → no drift after rotation (binding re-keyed)",
          sameDevice && sameDevice.fingerprintDrift === false);
    check("rotate-fp: operator data carried across rotation",
          sameDevice && sameDevice.data && sameDevice.data.roles && sameDevice.data.roles[0] === "user");

    // A different device must still drift — proves the binding is live, not dropped.
    var otherReq = _makeReq({ "user-agent": "ua-OTHER", "x-forwarded-for": "198.51.100.7" });
    var otherDevice = await b.session.verify(rotated.token, {
      req: otherReq, fingerprintFields: ["clientIp", "userAgent"],
    });
    check("rotate-fp: different device → drift after rotation (binding still enforced)",
          otherDevice && otherDevice.fingerprintDrift === true);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testLogoutEmitsClearSiteData() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ses-logout-"));
  try {
    await setupTestDb(tmpDir);
    var s = await b.session.create({ userId: "u-logout" });
    check("session created", typeof s.token === "string");

    // A real http.ServerResponse can be read as well as written, and the
    // cookie appender requires that — it has to see what is already queued
    // before it can add to it. _makeRes models both halves.
    var loRes = _makeRes();
    var headers = loRes.headers;
    var destroyed = await b.session.logout(loRes, s.token);

    check("logout returns true (session destroyed)", destroyed === true);
    check("logout emits Clear-Site-Data header",
      typeof headers["Clear-Site-Data"] === "string" &&
      headers["Clear-Site-Data"].indexOf('"cookies"') !== -1 &&
      headers["Clear-Site-Data"].indexOf('"storage"') !== -1);
    // Set-Cookie is the one legitimately-repeated response header, so logout
    // appends an array rather than overwriting whatever was already queued.
    check("logout queues Set-Cookie as a header array",
      Array.isArray(headers["Set-Cookie"]) && headers["Set-Cookie"].length === 1);
    var expiry = headers["Set-Cookie"][0];
    check("logout expires the session cookie",
      /(^|;)\s*Max-Age=0/.test(expiry) && expiry.indexOf("sid=;") === 0);
    check("logout cookie is Secure + HttpOnly",
      /HttpOnly/.test(expiry) && /Secure/.test(expiry));

    // The session is gone cluster-wide.
    var after = await b.session.verify(s.token);
    check("logout destroyed the session (verify returns null)", after === null);

    // Custom cookie name + an unknown Clear-Site-Data directive throws.
    var s2 = await b.session.create({ userId: "u-logout-2" });
    var res2 = _makeRes(); var h2 = res2.headers;
    await b.session.logout(res2, s2.token, { cookieName: "__Host-sid" });
    check("logout honors custom cookieName", h2["Set-Cookie"][0].indexOf("__Host-sid=;") === 0);

    // An unknown directive throws BEFORE any side effect — the session is NOT
    // destroyed and no client-wipe headers are queued (validate-before-revoke).
    var s3 = await b.session.create({ userId: "u-logout-3" });
    var res3 = _makeRes(); var h3 = res3.headers;
    var threw = null;
    try { await b.session.logout(res3, s3.token, { types: ["bogus"] }); }
    catch (e) { threw = e; }
    check("logout rejects an unknown Clear-Site-Data directive", threw !== null);
    check("logout did NOT queue headers on the bad-directive throw",
      h3["Clear-Site-Data"] === undefined && h3["Set-Cookie"] === undefined);
    check("logout did NOT destroy the session on the bad-directive throw",
      (await b.session.verify(s3.token)) !== null);

    var badRes = null;
    try { await b.session.logout({}, "x"); } catch (e) { badRes = e; }
    check("logout rejects a res without setHeader", badRes && badRes.code === "session/bad-res");
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// A response double that behaves like http.ServerResponse for the headers
// logout touches: Set-Cookie accumulates, everything else is last-write-wins.
function _makeRes(preset) {
  var headers = Object.create(null);
  if (preset) Object.keys(preset).forEach(function (k) { headers[k] = preset[k]; });
  return {
    headers:   headers,
    setHeader: function (k, v) { headers[k] = v; },
    getHeader: function (k) { return headers[k]; },
  };
}

// Every Set-Cookie logout queued, as a flat array of header strings.
function _setCookies(res) {
  var raw = res.headers["Set-Cookie"];
  if (raw === undefined) return [];
  return Array.isArray(raw) ? raw.slice() : [raw];
}

// The one Set-Cookie whose name is `cookieName`.
function _cookieNamed(res, cookieName) {
  var all = _setCookies(res);
  for (var i = 0; i < all.length; i++) {
    if (all[i].indexOf(cookieName + "=") === 0) return all[i];
  }
  return null;
}

function _hasAttr(header, attr) {
  var parts = String(header).split(";");
  for (var i = 0; i < parts.length; i++) {
    if (parts[i].trim().toLowerCase() === attr.toLowerCase()) return true;
  }
  return false;
}

function _attrValue(header, name) {
  var parts = String(header).split(";");
  var prefix = name.toLowerCase() + "=";
  for (var i = 0; i < parts.length; i++) {
    var p = parts[i].trim();
    if (p.toLowerCase().indexOf(prefix) === 0) return p.slice(prefix.length);
  }
  return null;
}

// #606 — the expiry cookie logout emits is built by hand: Secure and
// SameSite are hardcoded, no Path/Domain override reaches it, the header is
// set rather than appended, and nothing routes through b.cookies.serialize,
// so the RFC 6265bis prefix invariants are never enforced on it.
async function testLogoutCookieAttributes() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ses-logout-attrs-"));
  try {
    await setupTestDb(tmpDir);

    // --- Secure resolves from the request scheme, not a constant -----------
    // A plain-HTTP origin cannot set a Secure cookie: the browser discards
    // the header, so the session cookie survives the logout it was supposed
    // to clear.
    var s1 = await b.session.create({ userId: "u-606-http" });
    var httpRes = _makeRes();
    await b.session.logout(httpRes, s1.token, { req: _makeReq() });
    var httpCookie = _cookieNamed(httpRes, "sid");
    check("logout over plain HTTP omits Secure (browser would drop it)",
      httpCookie !== null && !_hasAttr(httpCookie, "Secure"));

    var s2 = await b.session.create({ userId: "u-606-https" });
    var tlsRes = _makeRes();
    var tlsReq = _makeReq();
    tlsReq.socket = { encrypted: true, remoteAddress: "203.0.113.9" };
    await b.session.logout(tlsRes, s2.token, { req: tlsReq });
    var tlsCookie = _cookieNamed(tlsRes, "sid");
    check("logout over TLS keeps Secure",
      tlsCookie !== null && _hasAttr(tlsCookie, "Secure"));

    // A forwarded scheme is NOT honored from an untrusted peer — the
    // trustedProtocol contract. An attacker-supplied X-Forwarded-Proto must
    // not talk logout into marking the cookie Secure on a cleartext hop.
    var s3 = await b.session.create({ userId: "u-606-spoof" });
    var spoofRes = _makeRes();
    await b.session.logout(spoofRes, s3.token, {
      req: _makeReq({ "x-forwarded-proto": "https" }),
    });
    check("logout ignores X-Forwarded-Proto from an untrusted peer",
      !_hasAttr(_cookieNamed(spoofRes, "sid"), "Secure"));

    // ...and IS honored once the operator declares the proxy trusted.
    var s4 = await b.session.create({ userId: "u-606-trusted" });
    var proxRes = _makeRes();
    var proxReq = _makeReq({ "x-forwarded-proto": "https" });
    proxReq.socket = { remoteAddress: "10.0.0.4" };
    await b.session.logout(proxRes, s4.token, {
      req: proxReq, trustedProxies: ["10.0.0.0/8"],
    });
    check("logout honors X-Forwarded-Proto from a trusted proxy",
      _hasAttr(_cookieNamed(proxRes, "sid"), "Secure"));

    // Explicit opts.secure overrides the resolver in both directions.
    var s5 = await b.session.create({ userId: "u-606-explicit-off" });
    var offRes = _makeRes();
    await b.session.logout(offRes, s5.token, { secure: false });
    check("logout honors an explicit secure: false",
      !_hasAttr(_cookieNamed(offRes, "sid"), "Secure"));

    var s6 = await b.session.create({ userId: "u-606-explicit-on" });
    var onRes = _makeRes();
    await b.session.logout(onRes, s6.token, { req: _makeReq(), secure: true });
    check("an explicit secure: true beats a plain-HTTP req",
      _hasAttr(_cookieNamed(onRes, "sid"), "Secure"));

    // Neither given → the secure default stands, unchanged.
    var s7 = await b.session.create({ userId: "u-606-default" });
    var defRes = _makeRes();
    await b.session.logout(defRes, s7.token);
    check("logout defaults to Secure when neither req nor secure is given",
      _hasAttr(_cookieNamed(defRes, "sid"), "Secure"));

    // --- the clear must be able to MATCH the cookie that was set ----------
    // A browser deletes on name + path + domain. A session cookie written
    // with Domain=.example.com and Path=/app is untouched by a bare
    // Path=/ expiry, so logout has to be able to describe it.
    var s8 = await b.session.create({ userId: "u-606-scope" });
    var scopeRes = _makeRes();
    await b.session.logout(scopeRes, s8.token, {
      path: "/app", domain: "example.com", sameSite: "Lax",
    });
    var scoped = _cookieNamed(scopeRes, "sid");
    check("logout honors opts.path",     _attrValue(scoped, "Path") === "/app");
    check("logout honors opts.domain",   _attrValue(scoped, "Domain") === "example.com");
    check("logout honors opts.sameSite", _attrValue(scoped, "SameSite") === "Lax");

    // --- it must not clobber a Set-Cookie the route already queued --------
    var s9 = await b.session.create({ userId: "u-606-append" });
    var appendRes = _makeRes({ "Set-Cookie": "csrf=abc; Path=/" });
    await b.session.logout(appendRes, s9.token);
    var queued = _setCookies(appendRes);
    check("logout preserves an already-queued Set-Cookie",
      queued.length === 2 && queued.indexOf("csrf=abc; Path=/") !== -1);
    check("logout still queued its own expiry cookie",
      _cookieNamed(appendRes, "sid") !== null);

    // --- RFC 6265bis prefix invariants reach the expiry cookie ------------
    // __Host- REQUIRES Secure. Once Secure is conditional, a hand-rolled
    // string would happily emit an invalid __Host- cookie over HTTP that the
    // browser silently drops; routing through b.cookies.serialize refuses it.
    var s10 = await b.session.create({ userId: "u-606-prefix" });
    var prefixRes = _makeRes();
    var prefixErr = null;
    try {
      await b.session.logout(prefixRes, s10.token, {
        cookieName: "__Host-sid", secure: false,
      });
    } catch (e) { prefixErr = e; }
    check("logout refuses __Host-* without Secure",
      prefixErr !== null && prefixErr.code === "cookies/prefix-host-secure-required");
    check("the refused __Host-* logout queued no headers",
      prefixRes.headers["Set-Cookie"] === undefined &&
      prefixRes.headers["Clear-Site-Data"] === undefined);
    check("the refused __Host-* logout left the session intact",
      (await b.session.verify(s10.token)) !== null);

    // __Host- also forbids Domain, and requires Path=/.
    var s11 = await b.session.create({ userId: "u-606-prefix-domain" });
    var domErr = null;
    try {
      await b.session.logout(_makeRes(), s11.token, {
        cookieName: "__Host-sid", domain: "example.com",
      });
    } catch (e) { domErr = e; }
    check("logout refuses __Host-* with a Domain",
      domErr !== null && domErr.code === "cookies/prefix-host-no-domain");

    // --- a bad attribute is refused BEFORE the session is revoked ---------
    // Same validate-before-revoke ordering the Clear-Site-Data directive
    // check already has: a throw after destroy() would leave the row gone
    // and the browser still holding its cookie.
    var s12 = await b.session.create({ userId: "u-606-order" });
    var orderRes = _makeRes();
    var orderErr = null;
    try {
      await b.session.logout(orderRes, s12.token, { sameSite: "Sideways" });
    } catch (e) { orderErr = e; }
    check("logout refuses an invalid sameSite", orderErr !== null);
    check("the invalid-sameSite logout did NOT revoke the session",
      (await b.session.verify(s12.token)) !== null);
    check("the invalid-sameSite logout queued no headers",
      orderRes.headers["Set-Cookie"] === undefined &&
      orderRes.headers["Clear-Site-Data"] === undefined);

    // --- a prefixed name outranks the request scheme ----------------------
    // A __Host- cookie only ever exists on a secure origin, so a plain-HTTP
    // request has nothing of that name to clear. Resolving `secure` to false
    // from the request would make serialize() refuse the prefix — and since the
    // cookie is built BEFORE the row is revoked, that refusal would abort the
    // logout, letting whoever chose the scheme decide whether the session died.
    var s14 = await b.session.create({ userId: "u-606-prefix-http" });
    var prefixHttpRes = _makeRes();
    var destroyed14 = await b.session.logout(prefixHttpRes, s14.token, {
      req: _makeReq(), cookieName: "__Host-sid",
    });
    check("a __Host- name keeps Secure on a plain-HTTP request",
      _hasAttr(_cookieNamed(prefixHttpRes, "__Host-sid"), "Secure"));
    check("a plain-HTTP request cannot stop a __Host- logout revoking the session",
      destroyed14 === true && (await b.session.verify(s14.token)) === null);

    var s15 = await b.session.create({ userId: "u-606-secure-prefix-http" });
    var securePrefixRes = _makeRes();
    var destroyed15 = await b.session.logout(securePrefixRes, s15.token, {
      req: _makeReq(), cookieName: "__Secure-sid",
    });
    check("a __Secure- name keeps Secure on a plain-HTTP request",
      _hasAttr(_cookieNamed(securePrefixRes, "__Secure-sid"), "Secure"));
    check("...and that logout revokes the session too",
      destroyed15 === true && (await b.session.verify(s15.token)) === null);

    // --- a mistyped req must not silently drop Secure ----------------------
    // trustedProtocol answers "http" for a non-request rather than throwing, so
    // an unchecked `req` would quietly produce a non-Secure cookie.
    var s16 = await b.session.create({ userId: "u-606-bad-req" });
    var badReqErr = null;
    try { await b.session.logout(_makeRes(), s16.token, { req: null }); }
    catch (e) { badReqErr = e; }
    check("logout refuses a null req rather than resolving it to http",
      badReqErr !== null && badReqErr.code === "session/bad-req");
    check("the refused-req logout left the session intact",
      (await b.session.verify(s16.token)) !== null);

    var strReqErr = null;
    try { await b.session.logout(_makeRes(), s16.token, { req: "https" }); }
    catch (e) { strReqErr = e; }
    check("logout refuses a non-object req",
      strReqErr !== null && strReqErr.code === "session/bad-req");

    // --- an unappendable response is refused BEFORE the row is revoked -----
    // The expiry cookie is queued through b.cookies.appendSetCookie, which has
    // to read the response as well as write it. A response carrying only
    // setHeader cannot satisfy that — and discovering it after destroy() would
    // leave the session revoked, Clear-Site-Data queued, no expiry cookie, and
    // a 500. The response shape is the caller's, fixed for the life of the
    // process, so it is checked with the other option validation up front.
    var s17 = await b.session.create({ userId: "u-606-writeonly" });
    var writeOnlyRes = { setHeader: function () {} };
    var writeOnlyErr = null;
    try { await b.session.logout(writeOnlyRes, s17.token); } catch (e) { writeOnlyErr = e; }
    check("logout refuses a write-only response",
      writeOnlyErr !== null && writeOnlyErr.code === "cookies/unreadable-response");
    check("the refused write-only logout did NOT revoke the session",
      (await b.session.verify(s17.token)) !== null);

    // --- an unknown option is a typo, not a silent no-op -------------------
    var s13 = await b.session.create({ userId: "u-606-typo" });
    var typoErr = null;
    try {
      await b.session.logout(_makeRes(), s13.token, { cookiename: "sid" });
    } catch (e) { typoErr = e; }
    check("logout rejects an unknown option key", typoErr !== null);
    check("the rejected-typo logout left the session intact",
      (await b.session.verify(s13.token)) !== null);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function run() {
  await testLogoutEmitsClearSiteData();
  await testLogoutCookieAttributes();
  await testSealedCookieDefault();
  await testSealedCookieRotateAndDestroy();
  await testClientIpPrefixV4();
  await testClientIpPrefixV6();
  await testClientIpPrefixV4MappedV6();
  await testFingerprintPeerGatedClientIp();
  await testPluggableStore();
  await testPurgeDoesNotRevokeARefreshedSession();
  await testEachSweepOrdersByTheColumnItFilters();
  await testPurgeClearsTheTableAcrossPassesOrSaysItCannot();
  await testPurgeStallGuardSurvivesRowOrderAndYields();
  await testPurgeDoesNotInventARemovalCount();
  await testPurgeFinishesWhenAStoreOmitsRowCountButDeletes();
  await testPurgeBatchSizeHasADocumentedCeiling();
  await testDestroyAllForUserPluggableNoDb();
  await testPluggableStoreValidation();
  await testUpdateDataReplaceAndMerge();
  await testUpdateDataMergeDepthAndValueShapes();
  await testUpdateDataPreservesFingerprint();
  await testRotateRekeysFingerprint();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.message, e.stack); process.exit(1); }
  );
}
