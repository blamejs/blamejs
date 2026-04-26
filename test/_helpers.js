"use strict";
/**
 * Shared smoke-test infrastructure.
 *
 * Layered smoke tests (per `feedback_test_dependency_order.md`) share
 * setup/teardown helpers + the `check()` assertion + the framework `b`
 * binding via this module. Each layer file requires _helpers.js and
 * imports what it needs.
 *
 * Public exports:
 *   b                 — the framework's public API (the `index.js` export)
 *   fs / os / path    — re-exported Node stdlib (saves callers a require)
 *
 *   check(label, cond)        assertion + counter increment
 *   getChecks()               total checks-so-far across all layers
 *   resetChecksForTest()      diagnostic — not used by smoke runner
 *
 *   setupTestDb(tmpDir, schemaOverrides?)     full vault + db init
 *   teardownTestDb(tmpDir)                    drain audit, close db, cleanup
 *
 *   setupTestDbForMW()        minimal db (no schema) for middleware tests
 *   teardownMW()              cleanup middleware fixture
 *
 *   _makeFakeDriver(opts?)               in-memory KV "DB driver" for
 *                                        external-db dispatcher tests
 *   _makeSqliteDriver(dbPath)            real node:sqlite-backed driver
 *                                        for cluster + chain-writer tests
 *   _makeFakeServiceAccount()            RSA keypair for GCS adapter tests
 *
 *   _mockReq(opts?)                      HTTP request shape for middleware
 *   _mockRes()                           HTTP response capture for middleware
 *
 *   _setupClusterGateFixture()           cluster-mode init + immediate
 *                                        shutdown (becomes a follower) so
 *                                        write-side gate tests can verify
 *                                        NotLeaderError
 *   _expectNotLeaderError(label, fn)     assertion helper for the above
 */

var fs = require("fs");
var os = require("os");
var path = require("path");
var b = require("../index.js");

// ---- assertion + counter ----

var _checks = 0;
function check(label, condition) {
  if (!condition) throw new Error("FAIL: " + label);
  _checks += 1;
}
function getChecks() { return _checks; }
function resetChecksForTest() { _checks = 0; }

// ---- full framework setup/teardown ----

async function setupTestDb(tmpDir, schemaOverrides) {
  process.env.BLAMEJS_SKIP_NTP_CHECK = "1";
  b.cluster._resetForTest();
  b.audit._resetForTest();
  b.vault._resetForTest();
  b.db._resetForTest();
  await b.vault.init({ dataDir: tmpDir, mode: "plaintext" });
  process.env.BLAMEJS_AUDIT_SIGNING_MODE = "plaintext";
  await b.db.init({
    dataDir:  tmpDir,
    atRest:   "plain",
    schema:   schemaOverrides || [
      {
        name: "users",
        columns: {
          _id:       "TEXT PRIMARY KEY",
          email:     "TEXT",
          emailHash: "TEXT",
          name:      "TEXT",
          status:    "TEXT DEFAULT 'active'",
          createdAt: "TEXT",
        },
        indexes: ["emailHash", "status"],
        sealedFields:  ["email", "name"],
        derivedHashes: { emailHash: { from: "email", normalize: function (v) { return String(v).toLowerCase(); } } },
      },
    ],
  });
}

async function teardownTestDb(tmpDir) {
  // Drain the audit handler's buffered emissions BEFORE close, so the
  // pending audit rows (from middleware/storage/external-db emits during
  // the test) land in audit_log and don't leak into the next test's
  // database.
  try { await b.audit.flush(); } catch (_e) {}
  try { b.db.close(); } catch (_e) {}
  b.audit._resetForTest();
  b.db._resetForTest();
  b.vault._resetForTest();
  b.cluster._resetForTest();
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
}

// ---- middleware-fixture setup (lightweight DB; no app schema) ----

async function setupTestDbForMW() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-mw-"));
  process.env.BLAMEJS_SKIP_NTP_CHECK = "1";
  process.env.BLAMEJS_AUDIT_SIGNING_MODE = "plaintext";
  b.vault._resetForTest();
  b.db._resetForTest();
  await b.vault.init({ dataDir: tmpDir, mode: "plaintext" });
  await b.db.init({
    dataDir: tmpDir,
    atRest:  "plain",
    auditSigning: { mode: "plaintext" },
    schema:  [],
  });
  global._mwTmpDir = tmpDir;
}
function teardownMW() {
  try { b.db.close(); } catch (_e) {}
  b.db._resetForTest();
  b.vault._resetForTest();
  if (global._mwTmpDir) {
    try { fs.rmSync(global._mwTmpDir, { recursive: true, force: true }); } catch (_e) {}
  }
}

// ---- in-memory KV "DB driver" for external-db dispatcher tests ----
//
// Tiny SQL "parser" handles the kv-table SELECT/INSERT/DELETE +
// BEGIN/COMMIT/ROLLBACK only. Tests focus on the dispatcher's pooling /
// retry / classification / transaction / audit semantics, not real SQL.

function _makeFakeDriver(opts) {
  opts = opts || {};
  var connectCount = 0;
  var queryCount = 0;
  var store = {};
  var failNextN = opts.failNextN || 0;
  var failPermanent = opts.failPermanent || false;

  return {
    connect: async function () {
      connectCount += 1;
      return { id: "client-" + connectCount, store: store };
    },
    query: async function (client, sql, params) {
      queryCount += 1;
      if (failNextN > 0) {
        failNextN -= 1;
        var e = new Error("simulated failure");
        e.code = failPermanent ? "PERMANENT" : "ECONNRESET";
        e.permanent = failPermanent;
        throw e;
      }
      if (/^SELECT 1$/i.test(sql)) return { rows: [{ "?column?": 1 }], rowCount: 1 };
      if (/^BEGIN/i.test(sql) || /^COMMIT/i.test(sql) || /^ROLLBACK/i.test(sql)) {
        return { rows: [], rowCount: 0 };
      }
      var insertMatch = sql.match(/^INSERT INTO kv \(id, value\) VALUES \(\$1, \$2\)/i);
      if (insertMatch) {
        client.store[params[0]] = params[1];
        return { rows: [], rowCount: 1 };
      }
      var selectMatch = sql.match(/^SELECT id, value FROM kv WHERE id = \$1/i);
      if (selectMatch) {
        var v = client.store[params[0]];
        if (v === undefined) return { rows: [], rowCount: 0 };
        return { rows: [{ id: params[0], value: v }], rowCount: 1 };
      }
      var deleteMatch = sql.match(/^DELETE FROM kv WHERE id = \$1/i);
      if (deleteMatch) {
        var existed = params[0] in client.store;
        delete client.store[params[0]];
        return { rows: [], rowCount: existed ? 1 : 0 };
      }
      throw new Error("fake driver: unknown SQL: " + sql);
    },
    close: async function () { /* no-op */ },
    ping:  async function () { return true; },
    getStats: function () { return { connectCount: connectCount, queryCount: queryCount }; },
  };
}

// ---- real node:sqlite-backed driver for cluster + chain-writer tests ----

function _makeSqliteDriver(dbPath) {
  var sqlite = require("node:sqlite");
  var dbHandle = new sqlite.DatabaseSync(dbPath);
  return {
    connect: async function () { return { db: dbHandle }; },
    query: async function (client, sql, params) {
      params = params || [];
      // SQLite uses ?-placeholders natively; the cluster provider's
      // prepared SQL uses $N. Translate.
      var translated = sql.replace(/\$([0-9]+)/g, "?");
      var stmt = client.db.prepare(translated);
      var trimmed = sql.trim().toUpperCase();
      if (trimmed.startsWith("SELECT") || /\sRETURNING\s/i.test(sql)) {
        var rows = stmt.all.apply(stmt, params);
        return { rows: rows, rowCount: rows.length };
      }
      var info = stmt.run.apply(stmt, params);
      return { rows: [], rowCount: info.changes };
    },
    close: async function () { /* shared handle, closed by test teardown */ },
    _close: function () { try { dbHandle.close(); } catch (_e) {} },
  };
}

// ---- throwaway RSA keypair for GCS adapter tests ----

function _makeFakeServiceAccount() {
  var nodeCrypto = require("crypto");
  var pair = nodeCrypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding:  { type: "spki",  format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return {
    type:         "service_account",
    project_id:   "test-project",
    client_email: "test-sa@test-project.iam.gserviceaccount.com",
    private_key:  pair.privateKey,
    private_key_id: "test-key-id-001",
  };
}

// ---- HTTP request/response mocks for middleware tests ----

function _mockReq(opts) {
  opts = opts || {};
  return {
    method:    opts.method || "GET",
    url:       opts.url || "/",
    pathname:  opts.pathname || (opts.url || "/").split("?")[0],
    headers:   Object.assign({}, opts.headers || {}),
    socket:    opts.socket || { remoteAddress: "127.0.0.1" },
  };
}

function _mockRes() {
  var headers = {};
  var statusCode = null;
  var bodyParts = [];
  var ended = false;
  return {
    statusCode:    null,
    writableEnded: false,
    setHeader:     function (k, v) { headers[k.toLowerCase()] = v; },
    getHeader:     function (k) { return headers[k.toLowerCase()]; },
    writeHead:     function (s, h) {
      statusCode = s;
      if (h) for (var k in h) headers[k.toLowerCase()] = h[k];
    },
    end:           function (b) { if (b !== undefined) bodyParts.push(b); ended = true; this.writableEnded = true; },
    _captured:     function () { return { status: statusCode, headers: headers, body: bodyParts.join(""), ended: ended }; },
  };
}

// ---- cluster gate fixture ----
//
// Init cluster + immediately shut it down so isLeader() returns false.
// Write-side gate tests then verify NotLeaderError on framework writes.

async function _setupClusterGateFixture() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cluster-gate-"));
  b.cluster._resetForTest();
  await setupTestDb(tmpDir);

  var dbPath = path.join(tmpDir, "ha-coord.db");
  var driver = _makeSqliteDriver(dbPath);
  b.externalDb.init({
    backends: {
      "ops": { connect: driver.connect, query: driver.query, close: driver.close },
    },
  });
  await b.cluster.init({
    nodeId:            "gate-test-node",
    externalDbBackend: "ops",
    dialect:           "sqlite",
    leaseTtl:          b.constants.TIME.seconds(30),
    heartbeatInterval: b.constants.TIME.seconds(10),
  });
  await b.cluster.shutdown();

  return {
    tmpDir: tmpDir,
    teardown: async function () {
      try { await b.externalDb.shutdown(); } catch (_e) {}
      driver._close();
      await teardownTestDb(tmpDir);
    },
  };
}

function _expectNotLeaderError(label, fn) {
  var threw = null;
  try {
    var maybePromise = fn();
    if (maybePromise && typeof maybePromise.then === "function") {
      return maybePromise.then(function () {
        check(label + " — should have thrown", false);
      }, function (e) {
        check(label + " — throws NotLeaderError", e && e.code === "NOT_LEADER");
      });
    }
  } catch (e) { threw = e; }
  check(label + " — throws NotLeaderError", threw && threw.code === "NOT_LEADER");
}

module.exports = {
  b:                          b,
  fs:                         fs,
  os:                         os,
  path:                       path,
  check:                      check,
  getChecks:                  getChecks,
  resetChecksForTest:         resetChecksForTest,
  setupTestDb:                setupTestDb,
  teardownTestDb:             teardownTestDb,
  setupTestDbForMW:           setupTestDbForMW,
  teardownMW:                 teardownMW,
  _makeFakeDriver:            _makeFakeDriver,
  _makeSqliteDriver:          _makeSqliteDriver,
  _makeFakeServiceAccount:    _makeFakeServiceAccount,
  _mockReq:                   _mockReq,
  _mockRes:                   _mockRes,
  _setupClusterGateFixture:   _setupClusterGateFixture,
  _expectNotLeaderError:      _expectNotLeaderError,
};
