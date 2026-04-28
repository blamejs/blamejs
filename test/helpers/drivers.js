"use strict";
/**
 * Test driver fakes — in-memory + sqlite-backed shapes that match the
 * external-db dispatcher contract. Tests verify dispatcher logic
 * (pooling, retry, classification, transaction, audit) without
 * standing up a real Postgres.
 */

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

function _makeSqliteDriver(dbPath) {
  var sqlite = require("node:sqlite");
  var dbHandle = new sqlite.DatabaseSync(dbPath);
  return {
    connect: async function () { return { db: dbHandle }; },
    query: async function (client, sql, params) {
      params = params || [];
      // Cluster provider's prepared SQL uses $N placeholders; SQLite
      // takes ?-placeholders. Translate.
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

function _makeFakeServiceAccount() {
  var nodeCrypto = require("crypto");
  var pair = nodeCrypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding:  { type: "spki",  format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return {
    type:           "service_account",
    project_id:     "test-project",
    client_email:   "test-sa@test-project.iam.gserviceaccount.com",
    private_key:    pair.privateKey,
    private_key_id: "test-key-id-001",
  };
}

module.exports = {
  _makeFakeDriver:         _makeFakeDriver,
  _makeSqliteDriver:       _makeSqliteDriver,
  _makeFakeServiceAccount: _makeFakeServiceAccount,
};
