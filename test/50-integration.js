"use strict";
/**
 * Layer 5 — operator-facing integration / cross-module flows.
 *
 * Per feedback_test_dependency_order.md (Layer 5: operator-facing
 * integration). Cluster gates verify that write-side framework calls
 * fail with NotLeaderError when the local node is a follower.
 *
 *   cluster-gates: audit + consent / session / subject / queue /
 *                  object-store-local
 *
 * All previous layers must run first. Each test relies on
 * _setupClusterGateFixture() which initializes cluster + immediately
 * shuts it down so the node becomes a follower.
 *
 * Usage from smoke.js:
 *   var integrationLayer = require("./50-integration");
 *   await integrationLayer.run();
 */

var helpers = require("./_helpers");
var b      = helpers.b;
var fs     = helpers.fs;
var os     = helpers.os;
var path   = helpers.path;
var check  = helpers.check;
var setupTestDb               = helpers.setupTestDb;
var teardownTestDb            = helpers.teardownTestDb;
var _setupClusterGateFixture  = helpers._setupClusterGateFixture;
var _expectNotLeaderError     = helpers._expectNotLeaderError;

async function testClusterGatesAuditAndConsent() {
  var fx = await _setupClusterGateFixture();
  try {
    _expectNotLeaderError("audit.record on follower", async function () {
      await b.audit.record({
        actor: { kind: "user", id: "u1" },
        action: "auth.login",
        outcome: "success",
      });
    });
    _expectNotLeaderError("audit.checkpoint on follower", async function () {
      await b.audit.checkpoint();
    });
    _expectNotLeaderError("consent.grant on follower", async function () {
      await b.consent.grant({
        subjectId:   "subj-1",
        purpose:     "marketing",
        lawfulBasis: "consent",
        channel:     "web-form",
      });
    });
    _expectNotLeaderError("consent.withdraw on follower", async function () {
      await b.consent.withdraw({ subjectId: "subj-1", purpose: "marketing" });
    });
  } finally {
    await fx.teardown();
  }
}

async function testClusterGatesSession() {
  var fx = await _setupClusterGateFixture();
  try {
    _expectNotLeaderError("session.create on follower", function () {
      b.session.create({ userId: "u1" });
    });
    _expectNotLeaderError("session.destroy on follower", function () {
      b.session.destroy("any-token");
    });
    _expectNotLeaderError("session.purgeExpired on follower", function () {
      b.session.purgeExpired();
    });
  } finally {
    await fx.teardown();
  }
}

async function testClusterGatesSubject() {
  var fx = await _setupClusterGateFixture();
  try {
    _expectNotLeaderError("subject.rectify on follower", function () {
      b.subject.rectify("subj-1", {
        table: "users", id: "u1", changes: { email: "a@b.c" }, reason: "test",
      });
    });
    _expectNotLeaderError("subject.erase on follower", function () {
      b.subject.erase("subj-1", {
        reason: "test",
        acknowledgements: ["no-litigation-hold", "no-statutory-retention-required"],
      });
    });
    _expectNotLeaderError("subject.restrict on follower", function () {
      b.subject.restrict("subj-1", { on: true, reason: "test" });
    });
    _expectNotLeaderError("subject.recordObjection on follower", function () {
      b.subject.recordObjection("subj-1", { purpose: "marketing", reason: "test" });
    });
  } finally {
    await fx.teardown();
  }
}

async function testClusterGatesQueue() {
  var fx = await _setupClusterGateFixture();
  try {
    b.queue.init({ backends: { "default": { protocol: "local" } } });
    var threwEnqueue = null;
    try { await b.queue.enqueue("test-q", { x: 1 }); }
    catch (e) { threwEnqueue = e; }
    check("queue.enqueue on follower throws NotLeaderError",
          threwEnqueue && threwEnqueue.code === "NOT_LEADER");

    var threwPurge = null;
    try { await b.queue.purge("test-q"); }
    catch (e) { threwPurge = e; }
    check("queue.purge on follower throws NotLeaderError",
          threwPurge && threwPurge.code === "NOT_LEADER");
    try { await b.queue.shutdown(); } catch (_e) {}
  } finally {
    await fx.teardown();
  }
}

async function testClusterGatesObjectStoreLocal() {
  var fx = await _setupClusterGateFixture();
  try {
    var localProto = require(path.join(__dirname, "..", "lib", "object-store-local"));
    var rootDir = path.join(fx.tmpDir, "obj");
    var backend = localProto.create({ rootDir: rootDir });

    var threwPut = null;
    try { await backend.put("foo/bar", Buffer.from("hi")); }
    catch (e) { threwPut = e; }
    check("object-store-local.put on follower throws",
          threwPut && threwPut.code === "NOT_LEADER");

    var threwDelete = null;
    try { await backend.delete("foo/bar"); }
    catch (e) { threwDelete = e; }
    check("object-store-local.delete on follower throws",
          threwDelete && threwDelete.code === "NOT_LEADER");

    // Reads remain anywhere — no gate. Set up a non-existent key for
    // a clean error type comparison (NOT_FOUND, not NOT_LEADER).
    var threwGet = null;
    try { await backend.get("nope"); }
    catch (e) { threwGet = e; }
    check("object-store-local.get not gated by cluster",
          threwGet && threwGet.code === "NOT_FOUND");
  } finally {
    await fx.teardown();
  }
}

// ---- run() ----

async function run() {
  // Cluster gates — write-side gates across framework subsystems
  await testClusterGatesAuditAndConsent();
  await testClusterGatesSession();
  await testClusterGatesSubject();
  await testClusterGatesQueue();
  await testClusterGatesObjectStoreLocal();
}

module.exports = {
  name: "Layer 5 — integration (cluster-gates: audit/consent/session/subject/queue/object-store)",
  run:  run,
  testClusterGatesAuditAndConsent:    testClusterGatesAuditAndConsent,
  testClusterGatesSession:            testClusterGatesSession,
  testClusterGatesSubject:            testClusterGatesSubject,
  testClusterGatesQueue:              testClusterGatesQueue,
  testClusterGatesObjectStoreLocal:   testClusterGatesObjectStoreLocal,
};
