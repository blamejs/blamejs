// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.session.verify must FAIL CLOSED when a store returns a non-finite timing
 * value. The hard-expiry check (`expiresAt`) and the idle/absolute floors
 * (`lastActivity`/`createdAt`) coerce the stored value with a NaN-blind
 * comparison: a raw `Number(x) < now` is `false` when `Number(x)` is NaN
 * (a missing key, or a non-numeric value such as an ISO date string from a
 * custom store), so a session with no enforceable expiry was ACCEPTED. A real
 * SQL NULL is caught (`Number(null) === 0`), which is why a missing/non-numeric
 * value slipped. The shipped stores store these as NOT-NULL integers; the public
 * b.session.useStore() extension point makes a contract-deviating row shape
 * reachable, so the guard is routed through numericBounds.finiteTimestamp
 * (non-finite → -Infinity → always past → expired).
 */

var helpers = require("../helpers");
var b = helpers.b;
var check = helpers.check;
var setupTestDb = helpers.setupTestDb;
var teardownTestDb = helpers.teardownTestDb;
var fs = require("fs");
var os = require("os");
var path = require("path");

function _makeReq(headers) {
  return { headers: headers || {}, socket: {}, connection: {} };
}

async function run() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ses-nonfinite-"));
  try {
    await setupTestDb(tmpDir);

    var real = b.session.stores.localDbThin({ file: path.join(tmpDir, "ses.db"), audit: false });
    var mode = null; // null | "strip-expires" | "iso-expires" | "nan-lastActivity" | "nan-createdAt"
    var wrap = Object.assign({}, real, {
      executeOne: async function (sql, p) {
        var row = await real.executeOne(sql, p);
        if (mode && row && row.expiresAt !== undefined) {
          row = Object.assign({}, row);
          if (mode === "strip-expires")   { delete row.expiresAt; }
          else if (mode === "iso-expires") { row.expiresAt = new Date(Number(row.expiresAt)).toISOString(); }
          else if (mode === "nan-lastActivity") { row.lastActivity = "not-a-number"; }
          else if (mode === "nan-createdAt")    { row.createdAt = "not-a-number"; }
        }
        return row;
      },
    });
    b.session.useStore(wrap);

    var req = _makeReq({ "x-forwarded-for": "203.0.113.10", "user-agent": "devA" });
    var s = await b.session.create({ userId: "u-1", req: req, data: { role: "admin" } });

    // Sanity: an untouched row verifies.
    var ok = await b.session.verify(s.token, { req: req });
    check("sanity: a well-formed session verifies", ok && ok.userId === "u-1");

    // Hard-expiry guard: a non-numeric expiresAt must read as expired, not live.
    mode = "iso-expires";
    check("non-numeric (ISO) expiresAt → verify fails closed",
          (await b.session.verify(s.token, { req: req })) === null);

    // Re-create (the expired one was deleted on the failed verify).
    mode = null;
    var s2 = await b.session.create({ userId: "u-2", req: req, data: {} });
    mode = "strip-expires";
    check("missing expiresAt key → verify fails closed",
          (await b.session.verify(s2.token, { req: req })) === null);

    // Idle floor: a non-finite lastActivity must read as breached.
    mode = null;
    var s3 = await b.session.create({ userId: "u-3", req: req, data: {} });
    mode = "nan-lastActivity";
    check("non-finite lastActivity → idle floor fails closed",
          (await b.session.verify(s3.token, { req: req, idleTimeoutMs: 1000 })) === null);

    // Absolute floor: a non-finite createdAt must read as breached.
    mode = null;
    var s4 = await b.session.create({ userId: "u-4", req: req, data: {} });
    mode = "nan-createdAt";
    check("non-finite createdAt → absolute floor fails closed",
          (await b.session.verify(s4.token, { req: req, absoluteTimeoutMs: 1000 })) === null);
  } finally {
    b.session.useStore(null);
    await teardownTestDb(tmpDir);
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); });
}
