// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.sessionDeviceBinding — bind sessions to a device fingerprint and
 * refuse on drift.
 *
 * Run standalone: `node test/layer-0-primitives/session-device-binding.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b      = helpers.b;
var check  = helpers.check;
var setupTestDb    = helpers.setupTestDb;
var teardownTestDb = helpers.teardownTestDb;
var fs   = require("fs");
var os   = require("os");
var path = require("path");

function _captureAudit() {
  var captured = [];
  return {
    safeEmit: function (e) { captured.push(e); },
    captured: captured,
    byAction: function (action) {
      return captured.filter(function (e) { return e.action === action; });
    },
  };
}

function _memoryStore() {
  var data = new Map();
  return {
    data: data,
    get:  function (k) { return Promise.resolve(data.get(k)); },
    set:  function (k, v) { data.set(k, v); return Promise.resolve(); },
    del:  function (k) { data.delete(k); return Promise.resolve(); },
  };
}

function _mockReq(overrides) {
  var base = {
    url: "/x",
    method: "GET",
    headers: {
      "user-agent":      "Mozilla/5.0 (Macintosh; Intel)",
      "accept-language": "en-US,en;q=0.9",
      "accept-encoding": "gzip, br",
    },
    socket: { remoteAddress: "192.0.2.7" },
  };
  if (overrides && overrides.headers) {
    overrides.headers = Object.assign({}, base.headers, overrides.headers);
  }
  return Object.assign({}, base, overrides || {});
}

function testSurface() {
  check("b.sessionDeviceBinding namespace", typeof b.sessionDeviceBinding === "object");
  check("b.sessionDeviceBinding.create is fn", typeof b.sessionDeviceBinding.create === "function");
  check("DEFAULTS frozen", Object.isFrozen(b.sessionDeviceBinding.DEFAULTS));
  check("DEFAULTS.ipV4Prefix 24", b.sessionDeviceBinding.DEFAULTS.ipV4Prefix === 24);
  check("DEFAULTS.fingerprintBytes 32", b.sessionDeviceBinding.DEFAULTS.fingerprintBytes === 32);
  check("sessionDeviceBinding.SessionDeviceBindingError is fn",
        typeof b.sessionDeviceBinding.SessionDeviceBindingError === "function");
}

async function testCreateRejectsBadOpts() {
  var threw;

  // #330 — a no-store create() (no opts, or {} with neither bindingStore nor
  // storeInSession) now returns an INSTANCE whose stateless fingerprint() works
  // (the soft device-binding building block for self-validating tokens), while
  // the persisted bind()/verify()/unbind() lifecycle throws a clear
  // "no store configured" — instead of refusing to construct at all.
  var noStore = b.sessionDeviceBinding.create();
  check("create() with no opts returns a no-store instance", noStore && typeof noStore.fingerprint === "function");
  var noStoreFp = noStore.fingerprint(_mockReq());
  check("no-store instance fingerprint(req) returns a digest", Buffer.isBuffer(noStoreFp) && noStoreFp.length > 0);
  var noStore2 = b.sessionDeviceBinding.create({});
  check("create({}) returns a no-store instance", noStore2 && typeof noStore2.fingerprint === "function");
  // bind() is async, so the no-store guard surfaces as a rejection.
  var bindErr = null;
  try { await noStore2.bind("tok_x", _mockReq()); } catch (e) { bindErr = e; }
  check("no-store bind() fails closed with session-device-binding/no-store",
        bindErr && bindErr.code === "session-device-binding/no-store");

  threw = false;
  try {
    b.sessionDeviceBinding.create({
      bindingStore:    _memoryStore(),
      requireBoundKey: true,
      // missing boundKeyResolver
    });
  } catch (_e) { threw = true; }
  check("create() rejects requireBoundKey without boundKeyResolver", threw);

  threw = false;
  try {
    b.sessionDeviceBinding.create({
      bindingStore: { get: function () {} },  // missing set/del
    });
  } catch (_e) { threw = true; }
  check("create() rejects bad bindingStore shape", threw);

  threw = false;
  try {
    b.sessionDeviceBinding.create({
      bindingStore: _memoryStore(),
      ttlMs:        -1,
    });
  } catch (_e) { threw = true; }
  check("create() rejects negative ttlMs", threw);
}

async function testBindAndVerifyHappyPath() {
  var auditMock = _captureAudit();
  var binding = b.sessionDeviceBinding.create({
    bindingStore: _memoryStore(),
    audit:        auditMock,
  });
  var token = "tok_" + Date.now();
  var req = _mockReq();
  var fp = await binding.bind(token, req);
  check("bind returns 32-byte fingerprint", Buffer.isBuffer(fp) && fp.length === 32);
  check("audit emitted device.bound",
    auditMock.byAction("session.device.bound").length === 1);

  var verdict = await binding.verify(token, req);
  check("verify returns ok on same fingerprint", verdict.ok === true);
}

async function testVerifyDriftRefuses() {
  var auditMock = _captureAudit();
  var binding = b.sessionDeviceBinding.create({
    bindingStore: _memoryStore(),
    audit:        auditMock,
  });
  var token = "tok_drift";
  var req1 = _mockReq();
  await binding.bind(token, req1);

  // Different UA → fingerprint drifts.
  var req2 = _mockReq({ headers: { "user-agent": "curl/8" } });
  var verdict = await binding.verify(token, req2);
  check("verify returns ok=false on drift", verdict.ok === false);
  check("verify reason is drift", verdict.reason === "drift");
  check("audit emitted device.drift",
    auditMock.byAction("session.device.drift").length === 1);
  check("audit emitted device.refused",
    auditMock.byAction("session.device.refused").length >= 1);
}

async function testVerifyMissingBindRefuses() {
  var binding = b.sessionDeviceBinding.create({
    bindingStore: _memoryStore(),
  });
  var verdict = await binding.verify("never-bound", _mockReq());
  check("verify refuses unbound token", verdict.ok === false);
  check("reason missing-bind", verdict.reason === "missing-bind");
}

async function testIpToleranceAcrossSubnet() {
  var binding = b.sessionDeviceBinding.create({
    bindingStore: _memoryStore(),
  });
  var token = "tok_ip";
  await binding.bind(token, _mockReq({ socket: { remoteAddress: "192.0.2.10" } }));
  // Same /24 → still ok.
  var same24 = await binding.verify(token,
    _mockReq({ socket: { remoteAddress: "192.0.2.99" } }));
  check("verify ok on same /24", same24.ok === true);
  // Different /24 → drift.
  var diff = await binding.verify(token,
    _mockReq({ socket: { remoteAddress: "203.0.113.5" } }));
  check("verify drift on different /24", diff.ok === false);
}

async function testRequireBoundKeyEnforces() {
  var auditMock = _captureAudit();
  var key = Buffer.from("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
  var binding = b.sessionDeviceBinding.create({
    bindingStore:     _memoryStore(),
    requireBoundKey:  true,
    boundKeyResolver: function (req) { return req.boundKey || null; },
    audit:            auditMock,
  });
  var token = "tok_bk";
  var req = _mockReq({ boundKey: key });
  await binding.bind(token, req);

  // Verify with same key → ok.
  var ok = await binding.verify(token, _mockReq({ boundKey: key }));
  check("verify ok with same bound key", ok.ok === true);

  // Verify without key → refuse.
  var noKey = await binding.verify(token, _mockReq({ boundKey: null }));
  check("verify refuses missing bound key", noKey.ok === false);
  check("reason missing-bound-key", noKey.reason === "missing-bound-key");

  // Verify with different key → drift.
  var differentKey = Buffer.from("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
  var diff = await binding.verify(token, _mockReq({ boundKey: differentKey }));
  check("verify drift on different bound key", diff.ok === false);
  check("reason drift on key change", diff.reason === "drift");
}

async function testBindRefusesWithoutBoundKey() {
  var binding = b.sessionDeviceBinding.create({
    bindingStore:     _memoryStore(),
    requireBoundKey:  true,
    boundKeyResolver: function () { return null; },
  });
  var threw = false;
  try { await binding.bind("tok_nokey", _mockReq()); }
  catch (_e) { threw = true; }
  check("bind throws when requireBoundKey but no key", threw);
}

async function testFingerprintIsStable() {
  var binding = b.sessionDeviceBinding.create({
    bindingStore: _memoryStore(),
  });
  var fp1 = binding.fingerprint(_mockReq());
  var fp2 = binding.fingerprint(_mockReq());
  check("fingerprint stable across identical requests",
    Buffer.isBuffer(fp1) && Buffer.isBuffer(fp2) && fp1.equals(fp2));
}

async function testUnbind() {
  var store = _memoryStore();
  var binding = b.sessionDeviceBinding.create({ bindingStore: store });
  var token = "tok_u";
  await binding.bind(token, _mockReq());
  check("store has token", store.data.has(token));
  await binding.unbind(token);
  check("store cleared after unbind", !store.data.has(token));
}

function testNamespaceFingerprint() {
  // The namespace-level b.sessionDeviceBinding.fingerprint(req, opts?) is the
  // stateless device-hash helper (distinct from an instance's bound method):
  // deterministic for identical request shape, divergent when a bound
  // component changes.
  check("b.sessionDeviceBinding.fingerprint is a function",
    typeof b.sessionDeviceBinding.fingerprint === "function");
  var fp1 = b.sessionDeviceBinding.fingerprint(_mockReq());
  var fp2 = b.sessionDeviceBinding.fingerprint(_mockReq());
  check("namespace fingerprint: returns a Buffer", Buffer.isBuffer(fp1));
  check("namespace fingerprint: deterministic for identical requests", fp1.equals(fp2));
  var other = _mockReq();
  other.headers = Object.assign({}, other.headers, { "user-agent": "Totally-Different/9.9" });
  var fp3 = b.sessionDeviceBinding.fingerprint(other);
  check("namespace fingerprint: diverges when a bound component changes", !fp1.equals(fp3));
}

// ---------------------------------------------------------------------------
// b.session device-binding (lib/session.js) — the persisted, sid-keyed
// fingerprint binding on b.session.create / verify / rotate. Distinct from the
// stateless b.sessionDeviceBinding helper above; these drive the real
// b.session.<method>() consumer path against a live test DB.
// ---------------------------------------------------------------------------

// A request whose client-IP + UA drive the b.session fingerprint. The bare
// socket peer (no trustedProxies) is what b.session hashes by default, so a
// different remoteAddress / user-agent is a genuine device drift.
function _dev(remoteAddress, ua) {
  return {
    headers: { "user-agent": ua || "deviceA", "accept-language": "en-US,en;q=0.9" },
    socket:  { remoteAddress: remoteAddress || "203.0.113.10" },
  };
}

// The strict "maxAnomalyScore" binding policy must FAIL CLOSED when a real
// drift occurs but no decisive anomaly score can be produced (operator set the
// threshold but supplied no scorer, or the scorer can't return a number). The
// pre-fix path left fingerprintAnomalyScore = null and skipped the refusal, so
// a session bound to device A was accepted from device B under a declared
// strict threshold — the exact "binding check that fails open accepts a
// relocated session" this suite guards. Mirrors the existing bindingUnreadable
// fail-closed rule, extended to the uncomputable-score branch.
async function testSessionMaxAnomalyScoreFailsClosedWithoutScore() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ses-maxscore-"));
  try {
    await setupTestDb(tmpDir);
    var devA = _dev("203.0.113.10", "deviceA");
    var s = await b.session.create({ userId: "u-score", req: devA });

    // Bound device under the same strict policy still verifies (no drift).
    var same = await b.session.verify(s.token, { req: devA, maxAnomalyScore: 0.5 });
    check("maxAnomalyScore: bound device still verifies", same && same.userId === "u-score");

    // Drift from a different device under maxAnomalyScore with NO scorer: the
    // score is uncomputable, so a strict threshold must refuse (null).
    var devB = _dev("198.51.100.9", "deviceB");
    var verdict = await b.session.verify(s.token, { req: devB, maxAnomalyScore: 0.5 });
    check("maxAnomalyScore + drift + no scorer -> FAILS CLOSED (null)", verdict === null);

    // Same root: a scorer that returns a non-number yields no score either.
    var badScorer = await b.session.verify(s.token, {
      req: devB, maxAnomalyScore: 0.5, scorer: function () { return "not-a-number"; },
    });
    check("maxAnomalyScore + drift + non-numeric scorer -> FAILS CLOSED (null)", badScorer === null);

    // A scorer that THROWS is swallowed (best-effort) -> score null -> refuse.
    var threwScorer = await b.session.verify(s.token, {
      req: devB, maxAnomalyScore: 0.5, scorer: function () { throw new Error("boom"); },
    });
    check("maxAnomalyScore + drift + throwing scorer -> FAILS CLOSED (null)", threwScorer === null);

    // A scorer that returns a non-finite number (Infinity/NaN) yields no score.
    var infScorer = await b.session.verify(s.token, {
      req: devB, maxAnomalyScore: 0.5, scorer: function () { return Infinity; },
    });
    check("maxAnomalyScore + drift + non-finite scorer -> FAILS CLOSED (null)", infScorer === null);

    // The refusals above must NOT have destroyed the row (fingerprint refusal is
    // not row cleanup) — the bound device still verifies.
    var still = await b.session.verify(s.token, { req: devA, maxAnomalyScore: 0.5 });
    check("maxAnomalyScore: strict refusal left the session row intact", still && still.userId === "u-score");
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// The scorer path itself: a computed score below the threshold admits the
// (drifted) session, above the threshold refuses it, and out-of-range scores
// clamp to [0,1]. Locks the legitimate maxAnomalyScore behavior so the
// fail-closed fix above doesn't over-refuse the benign-drift case.
async function testSessionMaxAnomalyScoreScorerBands() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ses-scorer-"));
  try {
    await setupTestDb(tmpDir);
    var devA = _dev("203.0.113.10", "deviceA");
    var s = await b.session.create({ userId: "u-sc", req: devA });
    var devB = _dev("198.51.100.9", "deviceB");

    // Benign drift (score below threshold) -> accepted, drift + score surfaced.
    var benign = await b.session.verify(s.token, {
      req: devB, maxAnomalyScore: 0.8, scorer: function () { return 0.2; },
    });
    check("maxAnomalyScore: score below threshold -> accepted with drift",
      benign && benign.fingerprintDrift === true && benign.fingerprintAnomalyScore === 0.2);

    // Malicious drift (score above threshold) -> refused.
    var refused = await b.session.verify(s.token, {
      req: devB, maxAnomalyScore: 0.5, scorer: function () { return 0.9; },
    });
    check("maxAnomalyScore: score above threshold -> refused (null)", refused === null);

    // Out-of-range score clamps to 1 -> above 0.99 -> refused.
    var clamp = await b.session.verify(s.token, {
      req: devB, maxAnomalyScore: 0.99, scorer: function () { return 5; },
    });
    check("maxAnomalyScore: score clamps to 1 -> above threshold -> refused (null)", clamp === null);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// requireFingerprintMatch: any drift on a readable binding refuses the session
// (returns null) without destroying the row; default mode surfaces drift but
// returns the session. Covers the strict-refuse and default-drift branches of
// verify() that the unreadable-binding test does not exercise.
async function testSessionRequireFingerprintMatchDrift() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ses-reqfp-"));
  try {
    await setupTestDb(tmpDir);
    var devA = _dev("203.0.113.10", "deviceA");
    var s = await b.session.create({ userId: "u-strict2", req: devA });

    var ok = await b.session.verify(s.token, { req: devA, requireFingerprintMatch: true });
    check("requireFingerprintMatch: same device verifies", ok && ok.userId === "u-strict2");

    var devB = _dev("198.51.100.9", "deviceB");
    var refused = await b.session.verify(s.token, { req: devB, requireFingerprintMatch: true });
    check("requireFingerprintMatch: drift refuses (null)", refused === null);

    var stillOk = await b.session.verify(s.token, { req: devA, requireFingerprintMatch: true });
    check("requireFingerprintMatch: refusal did not destroy the row", stillOk && stillOk.userId === "u-strict2");

    // Default mode (no strict opt) surfaces the drift but still returns it.
    var lax = await b.session.verify(s.token, { req: devB });
    check("default mode: drift surfaced, session returned", lax && lax.fingerprintDrift === true);
    check("default mode: fingerprintAnomalyScore is null without a scorer", lax.fingerprintAnomalyScore === null);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// rotate() on a fingerprint-bound session without { req } throws (the sid-keyed
// binding cannot follow the new sid otherwise) and leaves the old session
// intact; an unbound session rotates without req. Covers the
// ROTATE_FINGERPRINT_REQ_REQUIRED guard.
async function testSessionRotateRequiresReqOnBound() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ses-rotreq-"));
  try {
    await setupTestDb(tmpDir);
    var devA = _dev("203.0.113.10", "deviceA");
    var s = await b.session.create({ userId: "u-rotreq", req: devA });

    var err = null;
    try { await b.session.rotate(s.token); } catch (e) { err = e; }
    check("rotate on a bound session without req throws",
      err && err.code === "session/rotate-fingerprint-req-required");

    // The throw happened before the UPDATE — the bound session is untouched.
    var still = await b.session.verify(s.token, { req: devA, requireFingerprintMatch: true });
    check("rotate throw left the bound session intact", still && still.userId === "u-rotreq");

    // An unbound session rotates fine without req.
    var s2 = await b.session.create({ userId: "u-unbound" });
    var r2 = await b.session.rotate(s2.token);
    check("rotate on an unbound session without req succeeds", r2 && typeof r2.token === "string");
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// Anonymous session minting + isAnonymous + destroyAllForUser's anon refusal.
async function testSessionAnonymousLifecycle() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ses-anon-"));
  try {
    await setupTestDb(tmpDir);
    var s = await b.session.create({ anonymous: true });
    check("anonymous create returns a token", s && typeof s.token === "string");

    var info = await b.session.verify(s.token);
    check("anonymous session verifies", info && typeof info.userId === "string");
    check("anonymous userId carries the anon: prefix", info.userId.indexOf(b.session.ANON_PREFIX) === 0);
    check("b.session.isAnonymous true for an anon userId", b.session.isAnonymous(info.userId) === true);
    check("b.session.isAnonymous false for a normal userId", b.session.isAnonymous("user-42") === false);

    var both = null;
    try { await b.session.create({ anonymous: true, userId: "u-x" }); } catch (e) { both = e; }
    check("create rejects anonymous:true + userId together", both && both.code === "session/invalid-arg");

    var refuseAnon = null;
    try { await b.session.destroyAllForUser(info.userId); } catch (e) { refuseAnon = e; }
    check("destroyAllForUser refuses an anon-prefix id", refuseAnon && refuseAnon.code === "session/invalid-arg");
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// bind() falls back to the session when an external bindingStore.set() fails,
// so the fresh session is not lost. _readBound returned the external store's
// answer whenever a bindingStore was configured and never looked at the
// session, so the fallback was written somewhere nothing reads: every later
// verify answered missing-bind and the operator saw a session refused
// immediately after being bound.
//
// A write path and a read path that disagree about where a value lives is the
// defect, so both directions are driven here rather than asserting the write
// landed.
async function testSessionFallbackIsReadableWhenTheExternalStoreFailedTheWrite() {
  var req = _mockReq();
  var rows = { "tok-fallback": {} };
  var fakeSession = {
    updateData: function (tok, data, opts) {
      if (!rows[tok]) return Promise.resolve(false);
      if (opts && opts.merge) {
        Object.keys(data).forEach(function (k) { rows[tok][k] = data[k]; });
      } else { rows[tok] = data; }
      return Promise.resolve(true);
    },
    verify: function (tok) { return Promise.resolve(rows[tok] ? { data: rows[tok] } : null); },
  };
  // Writes fail; reads succeed and report the entry as absent — a store that
  // is up but lost the write, which is the case the fallback exists for.
  var writeFailStore = {
    get: function () { return Promise.resolve(null); },
    set: function () { return Promise.reject(new Error("store write failed")); },
    del: function () { return Promise.resolve(); },
  };
  var sdb = b.sessionDeviceBinding.create({
    bindingStore: writeFailStore, session: fakeSession, storeInSession: true,
  });

  await sdb.bind("tok-fallback", req);
  check("[setup] a failed external write falls back to the session",
    rows["tok-fallback"].__bj_deviceBinding &&
    typeof rows["tok-fallback"].__bj_deviceBinding.fingerprint === "string",
    JSON.stringify(rows["tok-fallback"]));
  var v = await sdb.verify("tok-fallback", req);
  check("verify reads the session fallback when the external store has no entry",
    v.ok === true, JSON.stringify(v));

  // The external store still WINS when it has an answer: the fallback is a
  // second place to look, not a second opinion. A drifted device must still be
  // refused on the external value even with a matching session binding.
  var otherFp = sdb.fingerprint(_mockReq({ socket: { remoteAddress: "203.0.113.9" } }));
  check("[setup] the other device fingerprints differently",
    Buffer.isBuffer(otherFp) && !otherFp.equals(sdb.fingerprint(req)),
    otherFp && otherFp.toString("hex").slice(0, 16));
  var presentStore = {
    get: function () { return Promise.resolve(otherFp); },
    set: function () { return Promise.resolve(); },
    del: function () { return Promise.resolve(); },
  };
  var sdb2 = b.sessionDeviceBinding.create({
    bindingStore: presentStore, session: fakeSession, storeInSession: true,
  });
  var vDrift = await sdb2.verify("tok-fallback", req);
  check("an external value still decides when it is present, session or not",
    vDrift.ok === false && vDrift.reason === "drift", JSON.stringify(vDrift));

  // A store that cannot answer at all stays fail-closed. Reading the session
  // here would turn an unreachable store into a silent downgrade to whatever
  // the session happens to carry.
  var errStore = {
    get: function () { return Promise.reject(new Error("store down")); },
    set: function () { return Promise.resolve(); },
    del: function () { return Promise.resolve(); },
  };
  var sdb3 = b.sessionDeviceBinding.create({
    bindingStore: errStore, session: fakeSession, storeInSession: true,
  });
  var vErr = await sdb3.verify("tok-fallback", req);
  check("an unreadable external store still fails closed, not into the session",
    vErr.ok === false && vErr.reason === "store-error", JSON.stringify(vErr));

  // Making the fallback readable makes a STALE fallback dangerous. A bind whose
  // external write failed leaves the old device in the session; a later bind
  // that succeeds externally must not leave it there, or the moment the
  // external entry expires the session hands back the device that was replaced
  // — accepting the old one and refusing the new.
  rows["tok-rebind"] = {};
  var external = { value: null, failWrites: true };
  var flakyStore = {
    get: function () { return Promise.resolve(external.value); },
    set: function (tok, val) {
      if (external.failWrites) return Promise.reject(new Error("store write failed"));
      external.value = val;
      return Promise.resolve();
    },
    del: function () { external.value = null; return Promise.resolve(); },
  };
  var sdb4 = b.sessionDeviceBinding.create({
    bindingStore: flakyStore, session: fakeSession, storeInSession: true,
  });
  var oldDevice = req;
  var newDevice = _mockReq({ socket: { remoteAddress: "203.0.113.9" } });

  await sdb4.bind("tok-rebind", oldDevice);                     // external fails → session holds the old device
  check("[setup] the failed external write left the old device in the session",
    rows["tok-rebind"].__bj_deviceBinding &&
    rows["tok-rebind"].__bj_deviceBinding.fingerprint ===
      sdb4.fingerprint(oldDevice).toString("hex"),
    JSON.stringify(rows["tok-rebind"]));

  external.failWrites = false;
  await sdb4.bind("tok-rebind", newDevice);                     // external succeeds this time
  check("[setup] the external store now holds the new device",
    Buffer.isBuffer(external.value) && external.value.equals(sdb4.fingerprint(newDevice)),
    external.value && external.value.toString("hex").slice(0, 16));

  // The external entry expires or is evicted; the fallback is consulted again.
  external.value = null;
  var vStale = await sdb4.verify("tok-rebind", oldDevice);
  check("an expired external entry does not resurrect the device a later bind replaced",
    vStale.ok === false, JSON.stringify(vStale));

  // Clearing the superseded copy is a WRITE, and a write can fail. What makes
  // the stale copy unusable rather than merely unlikely is that the session
  // fallback ages out on the same ttlMs the external store was given: a copy
  // written before the bind that replaced it has already expired by the time
  // that bind's own entry does. ttlMs was accepted on this path and never
  // enforced, so the session-backed store outlived the external one.
  var ttlRows = { "tok-ttl": {} };
  var ttlSession = {
    updateData: function (tok, data, opts) {
      if (!ttlRows[tok]) return Promise.resolve(false);
      if (opts && opts.merge) {
        Object.keys(data).forEach(function (k) { ttlRows[tok][k] = data[k]; });
      } else { ttlRows[tok] = data; }
      return Promise.resolve(true);
    },
    verify: function (tok) { return Promise.resolve(ttlRows[tok] ? { data: ttlRows[tok] } : null); },
  };
  var now = 1000000;
  var sdbTtl = b.sessionDeviceBinding.create({
    session: ttlSession, storeInSession: true,
    ttlMs: 60000, clock: function () { return now; },                                                  // allow:raw-time-literal — fixture clock, not a runtime budget
  });
  await sdbTtl.bind("tok-ttl", oldDevice);
  check("[setup] the session-backed binding verifies while it is fresh",
    (await sdbTtl.verify("tok-ttl", oldDevice)).ok === true);
  now += 59000;                                                                                        // allow:raw-time-literal — fixture clock, not a runtime budget
  check("a session-backed binding still verifies inside its ttl",
    (await sdbTtl.verify("tok-ttl", oldDevice)).ok === true);
  now += 2000;                                                                                         // allow:raw-time-literal — fixture clock, not a runtime budget
  var vExpired = await sdbTtl.verify("tok-ttl", oldDevice);
  check("a session-backed binding past its ttl reads as unbound, as the external store would",
    vExpired.ok === false && vExpired.reason === "missing-bind", JSON.stringify(vExpired));

  // A clear that fails leaves the two stores disagreeing until the older copy
  // ages out. That is survivable, but it must not be invisible.
  var audits = _captureAudit();
  var clearFailSession = {
    updateData: function (tok, data) {
      if (data && Object.prototype.hasOwnProperty.call(data, "__bj_deviceBinding") &&
          data.__bj_deviceBinding === null) {
        return Promise.reject(new Error("session write failed"));
      }
      return Promise.resolve(true);
    },
    verify: function () { return Promise.resolve({ data: {} }); },
  };
  var okStore = {
    get: function () { return Promise.resolve(null); },
    set: function () { return Promise.resolve(); },
    del: function () { return Promise.resolve(); },
  };
  var sdb5 = b.sessionDeviceBinding.create({
    bindingStore: okStore, session: clearFailSession, storeInSession: true,
    audit: audits,
  });
  await sdb5.bind("tok-clearfail", oldDevice);
  check("a clear that fails is audited rather than swallowed",
    audits.byAction("session.device.stale_fallback").length === 1,
    JSON.stringify(audits.captured.map(function (e) { return e.action; })));

  // A clear that reports false did not throw, but it did not confirm either.
  // `session` is operator-supplied, so what its false means is not something
  // this primitive can reason about — unproven is reported, not assumed clean.
  var quietAudits = _captureAudit();
  var sdb6 = b.sessionDeviceBinding.create({
    bindingStore: okStore,
    session: {
      updateData: function () { return Promise.resolve(false); },
      verify:     function () { return Promise.resolve(null); },
    },
    storeInSession: true,
    audit: quietAudits,
  });
  await sdb6.bind("tok-clearfalse", oldDevice);
  check("a clear that reports false is treated as unproven, not as cleared",
    quietAudits.byAction("session.device.stale_fallback").length === 1,
    JSON.stringify(quietAudits.captured.map(function (e) { return e.action; })));

  // The control: a clear that confirms says nothing.
  var cleanAudits = _captureAudit();
  var sdb7 = b.sessionDeviceBinding.create({
    bindingStore: okStore,
    session: {
      updateData: function () { return Promise.resolve(true); },
      verify:     function () { return Promise.resolve(null); },
    },
    storeInSession: true,
    audit: cleanAudits,
  });
  await sdb7.bind("tok-clearok", oldDevice);
  check("a confirmed clear raises nothing",
    cleanAudits.byAction("session.device.stale_fallback").length === 0,
    JSON.stringify(cleanAudits.captured.map(function (e) { return e.action; })));

  // A binding stamped in the FUTURE makes `clock() - boundAt` negative, which
  // is below any ttl and so passes a bare upper-bound check forever — the one
  // shape that turns a TTL into no TTL at all. Reachable without an attacker:
  // the wall clock stepping back after a bind does it, and `boundAt` arrives
  // from a session object the operator supplies. Unprovable freshness is
  // treated as stale, the same as a record carrying no boundAt.
  ttlRows["tok-future"] = {
    __bj_deviceBinding: {
      fingerprint: sdbTtl.fingerprint(oldDevice).toString("hex"),
      boundAt:     now + 3600000,                                                                      // allow:raw-time-literal — fixture clock, not a runtime budget
    },
  };
  var vFuture = await sdbTtl.verify("tok-future", oldDevice);
  check("a session-backed binding stamped in the future is not trusted",
    vFuture.ok === false, JSON.stringify(vFuture));

  // A record with no usable boundAt cannot be shown to be fresh, so it is not
  // trusted — the same direction as every other unprovable case here.
  ttlRows["tok-noage"] = { __bj_deviceBinding: { fingerprint: sdbTtl.fingerprint(oldDevice).toString("hex") } };
  var vNoAge = await sdbTtl.verify("tok-noage", oldDevice);
  check("a session-backed binding with no boundAt is not trusted",
    vNoAge.ok === false, JSON.stringify(vNoAge));
}

// The device binding decides whether a session is accepted, so the ordinary
// payload path must not be able to write it — the same reason __bj_fingerprint
// has always been stripped there. It was not: a payload carrying the key won
// over the stored value on both the merge and the replace path, so an
// application could null its own binding, or install one computed from the
// public fingerprint helper, and strict verification would agree. The accident
// is likelier than the abuse — one payload write with a key of that name
// destroys the binding silently.
//
// Driven through the REAL b.session, because the reservation lives there and a
// fake would only restate the test's own assumption.
async function testPayloadWritesCannotTouchTheReservedBindingKey() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ses-reserved-"));
  try {
    await setupTestDb(tmpDir);
    var req = _mockReq();
    var s = await b.session.create({ userId: "u-reserved", req: _dev("203.0.113.10", "deviceA") });
    var sdb = b.sessionDeviceBinding.create({ session: b.session, storeInSession: true });

    await sdb.bind(s.token, req);
    check("[setup] the framework's own writer binds the session",
      (await sdb.verify(s.token, req)).ok === true);

    // Null it through the payload path.
    await b.session.updateData(s.token, { __bj_deviceBinding: null }, { merge: true });
    check("a payload write cannot null the device binding",
      (await sdb.verify(s.token, req)).ok === true);

    // Replace the whole payload with a forged binding for another device.
    var other = _mockReq({ socket: { remoteAddress: "203.0.113.99" } });
    await b.session.updateData(s.token, {
      __bj_deviceBinding: {
        fingerprint: sdb.fingerprint(other).toString("hex"),
        boundAt:     Date.now(),
      },
    });
    check("a payload replace cannot install a binding of the caller's choosing",
      (await sdb.verify(s.token, other)).ok === false,
      JSON.stringify(await sdb.verify(s.token, other)));
    check("and the real binding is still the one that was bound",
      (await sdb.verify(s.token, req)).ok === true);

    // The control: ordinary payload keys still round-trip, so the reservation
    // has not simply broken updateData.
    await b.session.updateData(s.token, { cart: ["x"] }, { merge: true });
    var sess = await b.session.verify(s.token);
    check("ordinary payload keys are unaffected by the reservation",
      sess && sess.data && sess.data.cart && sess.data.cart[0] === "x",
      JSON.stringify(sess && sess.data));

    // rotate REPLACES the payload and is public, so it is the same door by
    // another name. Login is a rotation, which is exactly when a bound session
    // would be handed a caller-chosen binding.
    var rotated = await b.session.rotate(s.token, {
      req:  _dev("203.0.113.10", "deviceA"),
      data: {
        __bj_deviceBinding: {
          fingerprint: sdb.fingerprint(other).toString("hex"),
          boundAt:     Date.now(),
        },
      },
    });
    check("[setup] the session rotated", rotated && typeof rotated.token === "string",
      JSON.stringify(rotated && Object.keys(rotated)));
    check("a rotation cannot install a binding of the caller's choosing",
      (await sdb.verify(rotated.token, other)).ok === false,
      JSON.stringify(await sdb.verify(rotated.token, other)));
    check("and the binding carried across the rotation intact",
      (await sdb.verify(rotated.token, req)).ok === true);

    // create() builds the same column from caller data. A session that arrives
    // already bound to a device that never bound is the same bypass.
    var seeded = await b.session.create({
      userId: "u-seeded",
      req:    _dev("203.0.113.10", "deviceA"),
      data:   {
        __bj_deviceBinding: {
          fingerprint: sdb.fingerprint(other).toString("hex"),
          boundAt:     Date.now(),
        },
      },
    });
    check("a session cannot be created already carrying a device binding",
      (await sdb.verify(seeded.token, other)).ok === false,
      JSON.stringify(await sdb.verify(seeded.token, other)));

    // And unbind still works, because it goes through the framework's writer.
    await sdb.unbind(rotated.token);
    check("unbind still removes the binding through the framework's own writer",
      (await sdb.verify(rotated.token, req)).ok === false);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// `clock` and `storeInSession` are accepted opts whose TYPE was never checked.
// Both fail in the direction that hides: a non-function `clock` throws from
// `boundAt: clock()`, which sits inside bind()'s drop-silent catch, so bind
// records `stored: false`, writes nothing, and every later verify answers
// missing-bind — the same silent lockout #687 was about, reached by a typo in
// an option instead. `storeInSession` was coerced with `!!`, so the string
// "false" enabled the session-backed store the operator had just turned off.
//
// Refused at create(), where the caller is still on the stack, rather than at
// the first bind on a live session.
function testCreateRefusesMistypedClockAndStoreInSession() {
  var BAD = [
    ["a non-function clock",       { session: { updateData: function () {}, verify: function () {} },
                                     storeInSession: true, clock: 12345 }],
    ["a string clock",             { session: { updateData: function () {}, verify: function () {} },
                                     storeInSession: true, clock: "Date.now" }],
    ["a string storeInSession",    { session: { updateData: function () {}, verify: function () {} },
                                     storeInSession: "false" }],
    ["a numeric storeInSession",   { session: { updateData: function () {}, verify: function () {} },
                                     storeInSession: 1 }],
  ];
  BAD.forEach(function (c) {
    var threw = null;
    try { b.sessionDeviceBinding.create(c[1]); } catch (e) { threw = e; }
    check("create: " + c[0] + " is refused at config time",
      threw !== null, "create() returned an instance instead of throwing");
  });

  // The controls: the documented types still build, and omitting them still
  // builds. Without these the assertions above would pass on a create() that
  // refused everything.
  var withClock = b.sessionDeviceBinding.create({
    session: { updateData: function () {}, verify: function () {} },
    storeInSession: true, clock: function () { return 1; },
  });
  check("create: a function clock and a boolean storeInSession still build",
    withClock && typeof withClock.bind === "function");
  var plain = b.sessionDeviceBinding.create({ bindingStore: _memoryStore() });
  check("create: omitting both still builds",
    plain && typeof plain.bind === "function");
}

async function run() {
  testSurface();
  testCreateRefusesMistypedClockAndStoreInSession();
  testNamespaceFingerprint();
  await testCreateRejectsBadOpts();
  await testBindAndVerifyHappyPath();
  await testVerifyDriftRefuses();
  await testVerifyMissingBindRefuses();
  await testIpToleranceAcrossSubnet();
  await testRequireBoundKeyEnforces();
  await testBindRefusesWithoutBoundKey();
  await testFingerprintIsStable();
  await testUnbind();
  // b.session (lib/session.js) persisted device-binding paths.
  await testSessionMaxAnomalyScoreFailsClosedWithoutScore();
  await testSessionMaxAnomalyScoreScorerBands();
  await testSessionRequireFingerprintMatchDrift();
  await testSessionRotateRequiresReqOnBound();
  await testSessionAnonymousLifecycle();
  await testSessionDeviceBindingStoreInSessionAndStoreError();
  await testSessionFallbackIsReadableWhenTheExternalStoreFailedTheWrite();
  await testPayloadWritesCannotTouchTheReservedBindingKey();
}

if (require.main === module) {
  run().then(function () {
    console.log("OK session-device-binding — " + helpers.getChecks() + " checks");
  }).catch(function (e) {
    console.error("FAIL:", e && e.stack || e);
    process.exit(1);
  });
}

// The storeInSession fallback (bind via session.touch, read via session.verify)
// and the fail-closed store-error path — the existing tests only drive the
// bindingStore backend, leaving the session-backed store and the get()-throws
// branch uncovered.
async function testSessionDeviceBindingStoreInSessionAndStoreError() {
  var req = _mockReq();

  // A bindingStore whose get() throws must fail CLOSED with reason "store-error".
  var errStore = {
    get: function () { throw new Error("store down"); },
    set: function () { return Promise.resolve(); },
    del: function () { return Promise.resolve(); },
  };
  var sdbErr = b.sessionDeviceBinding.create({ bindingStore: errStore });
  var vErr = await sdbErr.verify("tok-err", req);
  check("verify: bindingStore.get error fails closed (store-error)",
        vErr.ok === false && vErr.reason === "store-error");

  // storeInSession: bind writes the fingerprint into the session's sealed data
  // payload, and verify reads it back through session.verify.
  //
  // The fake below mirrors the REAL session contract, and that is the whole
  // point of this test. It used to give touch() a metadata parameter it
  // records — a shape b.session.touch does not have: touch reads opts.extendBy
  // and nothing else, both its SQL paths carry a static SET list, and
  // opts.metadata was accepted and discarded. So this test passed while the
  // feature wrote nothing, every verify answered missing-bind, and the audit
  // row said stored: true. A mock that can do what production cannot is a test
  // that cannot fail.
  var rows = {};
  var fakeSession = {
    // Accepts opts and ignores everything but extendBy, exactly as the real
    // one does — including returning TRUE, which is what made the failure
    // silent: nothing threw, so the write was recorded as having happened.
    touch: function (tok, opts) {
      if (opts && opts.extendBy) rows[tok] = rows[tok] || {};
      return Promise.resolve(!!rows[tok]);
    },
    updateData: function (tok, data, opts) {
      if (!rows[tok]) return Promise.resolve(false);            // unknown / expired
      if (opts && opts.merge) {
        Object.keys(data).forEach(function (k) { rows[tok][k] = data[k]; });
      } else { rows[tok] = data; }
      return Promise.resolve(true);
    },
    verify: function (tok) { return Promise.resolve(rows[tok] ? { data: rows[tok] } : null); },
  };
  rows["tok-sess"] = {};                                        // a live session
  var sdbSess = b.sessionDeviceBinding.create({ session: fakeSession, storeInSession: true });
  var fp = await sdbSess.bind("tok-sess", req);
  check("bind via storeInSession writes the fingerprint to the session data",
        Buffer.isBuffer(fp) && rows["tok-sess"] &&
        rows["tok-sess"].__bj_deviceBinding &&
        typeof rows["tok-sess"].__bj_deviceBinding.fingerprint === "string",
        JSON.stringify(rows["tok-sess"]));
  var vSess = await sdbSess.verify("tok-sess", req);
  check("verify via session.verify matches the stored fingerprint", vSess.ok === true,
        JSON.stringify(vSess));

  // The merge must not discard what the application already keeps there.
  rows["tok-keep"] = { cart: ["a"] };
  await sdbSess.bind("tok-keep", req);
  check("binding a session preserves the payload already on it",
        rows["tok-keep"].cart && rows["tok-keep"].cart[0] === "a" &&
        rows["tok-keep"].__bj_deviceBinding &&
        typeof rows["tok-keep"].__bj_deviceBinding.fingerprint === "string",
        JSON.stringify(rows["tok-keep"]));

  // A write that did not land must not be recorded as one. updateData reports
  // false for an unknown or expired token, and the previous path could not
  // tell the difference because touch answered true for any live row.
  var vGone = await sdbSess.verify("tok-never-created", req);
  check("an unbound token still reports missing-bind rather than a match",
        vGone.ok === false, JSON.stringify(vGone));

  // The constructor has to check for the capability the feature actually uses.
  // It checked for touch(), which every session object has and which cannot
  // persist a fingerprint — so the documented wiring validated and did nothing.
  var threwTouchOnly = null;
  try {
    b.sessionDeviceBinding.create({
      session: { touch: function () { return Promise.resolve(true); } },
      storeInSession: true,
    });
  } catch (e) { threwTouchOnly = e; }
  check("storeInSession refuses a session that can only touch()",
        threwTouchOnly !== null, threwTouchOnly && threwTouchOnly.message);

  // Both halves, because this store is a read AND a write. An adapter that can
  // only write would report the fingerprint stored — truthfully — while every
  // later check answered missing-bind: the same silent lockout by another route.
  var threwWriteOnly = null;
  try {
    b.sessionDeviceBinding.create({
      session: { updateData: function () { return Promise.resolve(true); } },
      storeInSession: true,
    });
  } catch (e) { threwWriteOnly = e; }
  check("storeInSession refuses a session that cannot read back",
        threwWriteOnly !== null, threwWriteOnly && threwWriteOnly.message);

  // unbind has to remove what bind wrote. Removing it only from a bindingStore
  // left a session-backed binding live while reporting success, so the next
  // verify still matched a device the operator had just unbound.
  rows["tok-unbind"] = {};
  await sdbSess.bind("tok-unbind", req);
  check("[setup] the session-backed binding is written",
        rows["tok-unbind"].__bj_deviceBinding &&
        typeof rows["tok-unbind"].__bj_deviceBinding.fingerprint === "string");
  await sdbSess.unbind("tok-unbind");
  var vUnbound = await sdbSess.verify("tok-unbind", req);
  check("unbind removes a session-backed binding, so verify stops matching",
        vUnbound.ok === false, JSON.stringify(vUnbound));

  // A caller who chose an EXTERNAL store may pass `session` for other reasons.
  // Their session payload is theirs: an unbind that never wrote a fingerprint
  // there must not null fields of the same name that the application owns.
  rows["tok-external"] = { deviceFingerprint: "app-owned-value", cart: ["b"] };
  var extStore = {
    get: function () { return Promise.resolve(null); },
    set: function () { return Promise.resolve(); },
    del: function () { return Promise.resolve(); },
  };
  var sdbExternal = b.sessionDeviceBinding.create({
    bindingStore: extStore, session: fakeSession,
  });
  await sdbExternal.unbind("tok-external");
  check("an external-store unbind leaves the application's session payload alone",
        rows["tok-external"].deviceFingerprint === "app-owned-value" &&
        rows["tok-external"].cart[0] === "b",
        JSON.stringify(rows["tok-external"]));
}

module.exports = { run: run };
