"use strict";
/**
 * b.breakGlass — column-policy / row-enforcement step-up auth (v0.5.0).
 *
 * Covers: surface, policy CRUD, TOTP factor verification, grant
 * lifecycle (expiry / exhaustion / revoke), error codes, IP/session
 * pinning data flow, audit emission per row, sweep.
 *
 * Run standalone: `node test/layer-0-primitives/break-glass.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b              = helpers.b;
var fs             = helpers.fs;
var os             = helpers.os;
var path           = helpers.path;
var check          = helpers.check;
var setupTestDb    = helpers.setupTestDb;
var teardownTestDb = helpers.teardownTestDb;

var C = b.constants;

function _tmp() { return fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-bg-")); }

// Build a test "patient" record table that mimics the operator-facing
// shape: a glass-locked column (ssn) sealed via cryptoField. We don't
// need a custom table schema — _blamejs_jobs has sealed columns we
// can repurpose for the unsealRow test (payload field is sealed). For
// the policy tests we use arbitrary table names since policy.set
// doesn't validate the table exists in the DB.

function _validTotp() {
  var secret = b.auth.totp.generateSecret();
  var code = b.auth.totp.generate(secret);
  return { secret: secret, code: code };
}

function _fakeReq(overrides) {
  var base = {
    user:    { id: "user-test-1" },
    session: { id: "sess-test-1" },
    socket:  { remoteAddress: "127.0.0.1" },
    headers: { "user-agent": "test-agent" },
    method:  "POST",
    url:     "/admin/break-glass",
  };
  return Object.assign(base, overrides || {});
}

// ---- Surface ----

function testSurface() {
  check("b.breakGlass namespace present",          typeof b.breakGlass === "object");
  check("breakGlass.init is fn",                   typeof b.breakGlass.init === "function");
  check("breakGlass.policy.set is fn",             typeof b.breakGlass.policy.set === "function");
  check("breakGlass.policy.get is fn",             typeof b.breakGlass.policy.get === "function");
  check("breakGlass.policy.list is fn",            typeof b.breakGlass.policy.list === "function");
  check("breakGlass.policy.delete is fn",          typeof b.breakGlass.policy.delete === "function");
  check("breakGlass.grant is fn",                  typeof b.breakGlass.grant === "function");
  check("breakGlass.unsealRow is fn",              typeof b.breakGlass.unsealRow === "function");
  check("breakGlass.revoke is fn",                 typeof b.breakGlass.revoke === "function");
  check("breakGlass.listActive is fn",             typeof b.breakGlass.listActive === "function");
  check("breakGlass.BreakGlassError is class",     typeof b.breakGlass.BreakGlassError === "function");
}

// ---- Policy CRUD ----

async function testPolicyCRUD() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();

    // No policy → null
    var p0 = await b.breakGlass.policy.get("patients");
    check("policy.get unset returns null", p0 === null);

    // Set
    await b.breakGlass.policy.set("patients", {
      columns: ["ssn", "diagnosis"],
      factors: ["totp"],
    });
    var p1 = await b.breakGlass.policy.get("patients");
    check("policy.get returns the saved policy",
          p1 && p1.table === "patients");
    check("policy.set defaults maxRowsPerGrant = 1",
          p1 && p1.maxRowsPerGrant === 1);
    check("policy.set defaults grantTtl = 15 min",
          p1 && p1.grantTtl === C.TIME.minutes(15));
    check("policy.set defaults reasonRequired = true",
          p1 && p1.reasonRequired === true);
    check("policy.set defaults pinIp = true",
          p1 && p1.pinIp === true);
    check("policy.set defaults sessionPin = true",
          p1 && p1.sessionPin === true);
    check("policy.set defaults onLockedAccess = throw",
          p1 && p1.onLockedAccess === "throw");
    check("policy.set defaults auditReasonStorage = cleartext",
          p1 && p1.auditReasonStorage === "cleartext");
    check("policy.set columns round-trip",
          p1 && Array.isArray(p1.columns) && p1.columns[0] === "ssn" && p1.columns[1] === "diagnosis");

    // List
    var all = await b.breakGlass.policy.list();
    check("policy.list returns 1 entry",  all.length === 1 && all[0].table === "patients");

    // Update (UPSERT)
    await b.breakGlass.policy.set("patients", {
      columns: ["ssn"],
      factors: ["totp"],
      grantTtl: C.TIME.minutes(5),
      maxRowsPerGrant: 10,
      reasonMinLength: 20,
    });
    var p2 = await b.breakGlass.policy.get("patients");
    check("policy.set is idempotent UPSERT (columns updated)",
          p2.columns.length === 1 && p2.columns[0] === "ssn");
    check("policy.set updates grantTtl",      p2.grantTtl === C.TIME.minutes(5));
    check("policy.set updates maxRowsPerGrant", p2.maxRowsPerGrant === 10);
    check("policy.set updates reasonMinLength", p2.reasonMinLength === 20);

    // Delete
    await b.breakGlass.policy.delete("patients");
    var p3 = await b.breakGlass.policy.get("patients");
    check("policy.delete removes the policy",  p3 === null);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- Tier-A validation ----

async function testPolicyValidation() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    function reject(label, table, opts, codeRe) {
      return b.breakGlass.policy.set(table, opts).then(
        function () { check("policy.validate: " + label + " (should throw)", false); },
        function (e) { check("policy.validate: " + label, codeRe.test(e.code || "")); }
      );
    }
    await reject("rejects bad table",          "", { columns: ["x"], factors: ["totp"] }, /breakglass\/bad-policy/);
    await reject("rejects missing columns",    "t", { factors: ["totp"] }, /breakglass\/bad-policy/);
    await reject("rejects empty columns",      "t", { columns: [], factors: ["totp"] }, /breakglass\/bad-policy/);
    await reject("rejects missing factors",    "t", { columns: ["x"] }, /breakglass\/bad-policy/);
    await reject("rejects unknown factor",     "t", { columns: ["x"], factors: ["sms"] }, /breakglass\/bad-policy/);
    await reject("rejects passkey in 0.5.0",   "t", { columns: ["x"], factors: ["passkey"] }, /breakglass\/bad-policy/);
    await reject("rejects cryptographic in 0.5.0",
                                               "t", { columns: ["x"], factors: ["totp"], cryptographic: true }, /breakglass\/bad-policy/);
    await reject("rejects bad onLockedAccess", "t", { columns: ["x"], factors: ["totp"], onLockedAccess: "panic" }, /breakglass\/bad-policy/);
    await reject("rejects bad maxRowsPerGrant","t", { columns: ["x"], factors: ["totp"], maxRowsPerGrant: 0 }, /breakglass\/bad-policy/);
    await reject("rejects negative grantTtl",  "t", { columns: ["x"], factors: ["totp"], grantTtl: -1 }, /breakglass\/bad-policy/);
    await reject("rejects bad auditReasonStorage",
                                               "t", { columns: ["x"], factors: ["totp"], auditReasonStorage: "raw" }, /breakglass\/bad-policy/);
    await reject("rejects serviceAccountBypass in 0.5.0",
                                               "t", { columns: ["x"], factors: ["totp"], serviceAccountBypass: { enabled: true } }, /breakglass\/bad-policy/);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- Grant — happy path ----

async function testGrantHappyPath() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    await b.breakGlass.policy.set("patients", {
      columns: ["ssn"],
      factors: ["totp"],
    });
    var totp = _validTotp();
    var grant = await b.breakGlass.grant({
      req:     _fakeReq(),
      table:   "patients",
      reason:  "investigating ticket #12345 for compliance review",
      factor:  { type: "totp", code: totp.code, secret: totp.secret },
    });
    check("grant: returns id",               typeof grant.id === "string" && grant.id.indexOf("bg-") === 0);
    check("grant: returns expiresAt",        typeof grant.expiresAt === "number" && grant.expiresAt > Date.now());
    check("grant: rowsRemaining = 1 (default)", grant.rowsRemaining === 1);
    check("grant: scopeTable echoed",        grant.scopeTable === "patients");
    check("grant: scopeColumns echoed",      grant.scopeColumns.length === 1 && grant.scopeColumns[0] === "ssn");
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- Grant — refused paths ----

async function testGrantRefusalPaths() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    await b.breakGlass.policy.set("patients", {
      columns: ["ssn"],
      factors: ["totp"],
      reasonMinLength: 12,
    });

    function reject(label, opts, codeRe) {
      return b.breakGlass.grant(opts).then(
        function () { check("grant.refusal: " + label + " (should throw)", false); },
        function (e) { check("grant.refusal: " + label, codeRe.test(e.code || "")); }
      );
    }
    var totp = _validTotp();

    await reject("policy-not-set",
      { req: _fakeReq(), table: "no-such-table", reason: "x".repeat(12),
        factor: { type: "totp", code: totp.code, secret: totp.secret } },
      /breakglass\/policy-not-set/);

    await reject("missing-reason",
      { req: _fakeReq(), table: "patients", reason: "",
        factor: { type: "totp", code: totp.code, secret: totp.secret } },
      /breakglass\/missing-reason/);

    await reject("short-reason",
      { req: _fakeReq(), table: "patients", reason: "short",
        factor: { type: "totp", code: totp.code, secret: totp.secret } },
      /breakglass\/short-reason/);

    await reject("grant-column-mismatch",
      { req: _fakeReq(), table: "patients", reason: "this is a long enough reason",
        columns: ["nonexistent-column"],
        factor: { type: "totp", code: totp.code, secret: totp.secret } },
      /breakglass\/grant-column-mismatch/);

    await reject("bad-factor (wrong code)",
      { req: _fakeReq(), table: "patients", reason: "this is a long enough reason",
        factor: { type: "totp", code: "000000", secret: totp.secret } },
      /breakglass\/bad-factor/);

    await reject("unauthorized (no actor on req)",
      { req: { socket: { remoteAddress: "127.0.0.1" }, headers: {} },
        table: "patients", reason: "this is a long enough reason",
        factor: { type: "totp", code: totp.code, secret: totp.secret } },
      /breakglass\/unauthorized/);

    await reject("bad factor type",
      { req: _fakeReq(), table: "patients", reason: "this is a long enough reason",
        factor: { type: "magic-link" } },
      /breakglass\/bad-factor/);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- Grant + unseal — full lifecycle on a real sealed table ----

async function testUnsealRowLifecycle() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    // Use _blamejs_jobs as the test target: payload is sealed by
    // cryptoField.sealRow per FRAMEWORK_SCHEMA.
    b.queue.init({ backends: { primary: { protocol: "local" } } });
    var jid = await b.queue.enqueue("test-q", { secret: "alice's diagnosis" });

    await b.breakGlass.policy.set("_blamejs_jobs", {
      columns:         ["payload"],
      factors:         ["totp"],
      maxRowsPerGrant: 3,   // raise from default-1 so we can test exhaustion + a normal read
    });

    var totp = _validTotp();
    var grant = await b.breakGlass.grant({
      req:    _fakeReq(),
      table:  "_blamejs_jobs",
      reason: "diagnostic spot-check on queue payloads",
      factor: { type: "totp", code: totp.code, secret: totp.secret },
    });
    check("grant: maxRowsPerGrant honored from policy", grant.rowsRemaining === 3);

    // Use grant once
    var unsealed = await b.breakGlass.unsealRow(grant, "_blamejs_jobs", jid.jobId);
    check("unsealRow: returns the row",                 unsealed && unsealed._id === jid.jobId);
    check("unsealRow: payload column is decrypted",
          unsealed.payload && unsealed.payload.indexOf("alice") !== -1);

    // listActive shows 2 remaining
    var active = await b.breakGlass.listActive({ req: _fakeReq() });
    check("listActive: 1 grant",                        active.length === 1);
    check("listActive: rowsRemaining decremented",      active[0].rowsRemaining === 2);

    try { await b.queue.shutdown({ timeoutMs: 200 }); } catch (_e) {}
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- Exhaustion ----

async function testGrantExhaustion() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    b.queue.init({ backends: { primary: { protocol: "local" } } });
    var jid = await b.queue.enqueue("ex-q", { kind: "row-1" });

    await b.breakGlass.policy.set("_blamejs_jobs", {
      columns:         ["payload"],
      factors:         ["totp"],
      maxRowsPerGrant: 1,    // strict default
    });
    var totp = _validTotp();
    var grant = await b.breakGlass.grant({
      req:    _fakeReq(),
      table:  "_blamejs_jobs",
      reason: "compliance spot-check on queue row",
      factor: { type: "totp", code: totp.code, secret: totp.secret },
    });
    await b.breakGlass.unsealRow(grant, "_blamejs_jobs", jid.jobId);

    var threw = null;
    try { await b.breakGlass.unsealRow(grant, "_blamejs_jobs", jid.jobId); }
    catch (e) { threw = e; }
    check("exhaustion: second use of 1-row grant rejects",
          threw && /breakglass\/grant-exhausted/.test(threw.code));

    try { await b.queue.shutdown({ timeoutMs: 200 }); } catch (_e) {}
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- Revoke ----

async function testGrantRevoke() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    b.queue.init({ backends: { primary: { protocol: "local" } } });
    var jid = await b.queue.enqueue("rv-q", { kind: "row-1" });

    await b.breakGlass.policy.set("_blamejs_jobs", {
      columns: ["payload"], factors: ["totp"], maxRowsPerGrant: 5,
    });
    var totp = _validTotp();
    var grant = await b.breakGlass.grant({
      req:    _fakeReq(),
      table:  "_blamejs_jobs",
      reason: "compliance spot-check on queue row",
      factor: { type: "totp", code: totp.code, secret: totp.secret },
    });
    await b.breakGlass.revoke(grant.id, { reason: "task complete" });
    var threw = null;
    try { await b.breakGlass.unsealRow(grant, "_blamejs_jobs", jid.jobId); }
    catch (e) { threw = e; }
    check("revoke: unseal after revoke rejects",
          threw && /breakglass\/grant-revoked/.test(threw.code));

    try { await b.queue.shutdown({ timeoutMs: 200 }); } catch (_e) {}
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- Table mismatch ----

async function testTableMismatch() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    await b.breakGlass.policy.set("patients", { columns: ["ssn"], factors: ["totp"] });
    var totp = _validTotp();
    var grant = await b.breakGlass.grant({
      req:    _fakeReq(),
      table:  "patients",
      reason: "investigating ticket #12345 for compliance review",
      factor: { type: "totp", code: totp.code, secret: totp.secret },
    });
    var threw = null;
    try { await b.breakGlass.unsealRow(grant, "doctors", "doc-1"); }
    catch (e) { threw = e; }
    check("table-mismatch: unseal on wrong table rejects",
          threw && /breakglass\/grant-table-mismatch/.test(threw.code));
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- Sweep ----

async function testSweepExpiredGrants() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    await b.breakGlass.policy.set("patients", {
      columns: ["ssn"], factors: ["totp"],
      grantTtl: 10,    // 10 ms — guaranteed expired by sweep time
    });
    var totp = _validTotp();
    await b.breakGlass.grant({
      req:    _fakeReq(),
      table:  "patients",
      reason: "soak-test with 10ms ttl for sweep coverage",
      factor: { type: "totp", code: totp.code, secret: totp.secret },
    });
    await new Promise(function (r) { setTimeout(r, 50); });
    var swept = await b.breakGlass._sweepExpiredForTest();
    check("sweep: marks expired grants revoked", swept.expired >= 1);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function run() {
  testSurface();
  await testPolicyCRUD();
  await testPolicyValidation();
  await testGrantHappyPath();
  await testGrantRefusalPaths();
  await testUnsealRowLifecycle();
  await testGrantExhaustion();
  await testGrantRevoke();
  await testTableMismatch();
  await testSweepExpiredGrants();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
