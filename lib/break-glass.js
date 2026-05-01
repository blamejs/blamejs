"use strict";
/**
 * break-glass — column-policy / row-enforcement step-up auth.
 *
 * Operator declares which columns of which tables are GLASS-LOCKED.
 * Reading the encrypted value on any row of a glass-locked column
 * requires the calling operator to:
 *
 *   1. Prove identity with a second factor (TOTP / passkey).
 *   2. Provide an operator-supplied REASON the audit chain captures.
 *   3. Hold a short-lived, scope-bounded GRANT.
 *
 * Each row read under a grant emits a per-row audit event. Default
 * `maxRowsPerGrant: 1` enforces row-by-row auth — each row access is
 * its own discrete authenticated event, compliance-defensible by
 * construction. Operators with batch workflows raise the cap per-table.
 *
 * Spec: memory/specs/blamejs-break-glass-spec.md
 *
 * v0.5.0 ships Model A (policy gate) + TOTP factor + Tier-A validation +
 * 14 error codes + audit chain integration. Model B (cryptographic
 * gate via per-row K_row), passkey factor, service-account bypass,
 * and admin tools land in v0.5.1 / v0.5.2 per the phasing plan.
 *
 * Public API:
 *
 *   b.breakGlass.init({ now? })             — boot once
 *   b.breakGlass.policy.set(table, opts)
 *   b.breakGlass.policy.get(table)          — null if unset
 *   b.breakGlass.policy.list()
 *   b.breakGlass.policy.delete(table)
 *
 *   b.breakGlass.grant({ req, table, reason, factor, columns? })
 *   b.breakGlass.unsealRow(grant, table, rowId)
 *   b.breakGlass.revoke(grantId, { reason })
 *   b.breakGlass.listActive({ req })
 *
 *   b.breakGlass.BreakGlassError
 */
var audit = require("./audit");
var C = require("./constants");
var clusterStorage = require("./cluster-storage");
var { generateToken, sha3Hash } = require("./crypto");
var cryptoField = require("./crypto-field");
var lazyRequire = require("./lazy-require");
var observability = require("./observability");
var requestHelpers = require("./request-helpers");
var safeAsync = require("./safe-async");
var safeJson = require("./safe-json");
var totp = require("./totp");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var lockout = lazyRequire(function () { return require("./auth/lockout"); });

// Errors — all 14 codes documented in the spec. `permanent: true`
// means caller's input is bad (Tier-A); `permanent: false` means
// transient (factor failed, rate-limited) — caller may retry.
var BreakGlassError = defineClass("BreakGlassError", { alwaysPermanent: false });

// ---- Defaults (matched to operator-locked decisions) ----

var DEFAULT_GRANT_TTL_MS    = C.TIME.minutes(15);
var DEFAULT_MAX_ROWS        = 1;       // operator-locked: row-by-row auth
var DEFAULT_REASON_MIN_LEN  = 12;
var DEFAULT_LOCKED_BEHAVIOR = "throw"; // or "redact"
var DEFAULT_AUDIT_REASON    = "cleartext";
var ALLOWED_FACTORS         = ["totp"]; // passkey added in v0.5.2
var ALLOWED_REASON_STORAGE  = ["cleartext", "hmac", "both"];

// In-memory policy cache. Cluster-shared via the policies table; the
// cache short-circuits the DB roundtrip on the unsealRow hot path.
// Populated on first access per-table; invalidated on policy.set/delete.
var policyCache = new Map();    // table -> policy
var initialized = false;

// Factor lockout — wrap auth.lockout so a hostile actor brute-forcing
// TOTP codes against break-glass gets shut out after a few failures.
// Lazy-init on first grant attempt so init() doesn't require the
// cache primitive to be wired before break-glass loads.
var _factorLockout = null;
var _factorLockoutCache = null;
function _ensureFactorLockout() {
  if (_factorLockout) return _factorLockout;
  var cache = require("./cache");
  _factorLockoutCache = cache.create({
    namespace: "breakglass.factor",
    backend:   "memory",
  });
  _factorLockout = lockout().create({
    namespace:   "breakglass.factor",
    cache:       _factorLockoutCache,
    maxAttempts: 5,
    windowMs:    C.TIME.minutes(15),
    audit:       audit,
  });
  return _factorLockout;
}

// ---- init ----

function init(opts) {
  opts = opts || {};
  validateOpts(opts, ["now"], "breakGlass.init");
  initialized = true;
  policyCache.clear();
  _factorLockout = null;
}

function _resetForTest() {
  initialized = false;
  policyCache.clear();
  if (_factorLockoutCache && typeof _factorLockoutCache.close === "function") {
    try { _factorLockoutCache.close(); } catch (_e) { /* best-effort */ }
  }
  _factorLockout = null;
  _factorLockoutCache = null;
}

function _requireInit() {
  if (!initialized) {
    throw new BreakGlassError("breakglass/not-initialized",
      "b.breakGlass.init() must be called before use");
  }
}

// ---- Policy CRUD ----

function _validatePolicySet(table, opts) {
  if (typeof table !== "string" || table.length === 0) {
    throw new BreakGlassError("breakglass/bad-policy",
      "policy.set: table must be a non-empty string");
  }
  if (!opts || typeof opts !== "object") {
    throw new BreakGlassError("breakglass/bad-policy",
      "policy.set: opts is required");
  }
  validateOpts(opts, [
    "columns", "factors", "cryptographic", "grantTtl", "maxRowsPerGrant",
    "reasonRequired", "reasonMinLength", "pinIp", "sessionPin",
    "onLockedAccess", "requireScope", "serviceAccountBypass",
    "auditReasonStorage",
  ], "breakglass.policy.set");
  if (!Array.isArray(opts.columns) || opts.columns.length === 0) {
    throw new BreakGlassError("breakglass/bad-policy",
      "policy.set: columns must be a non-empty array");
  }
  for (var i = 0; i < opts.columns.length; i++) {
    if (typeof opts.columns[i] !== "string" || opts.columns[i].length === 0) {
      throw new BreakGlassError("breakglass/bad-policy",
        "policy.set: columns[" + i + "] must be a non-empty string");
    }
  }
  if (!Array.isArray(opts.factors) || opts.factors.length === 0) {
    throw new BreakGlassError("breakglass/bad-policy",
      "policy.set: factors must be a non-empty array");
  }
  for (var j = 0; j < opts.factors.length; j++) {
    if (ALLOWED_FACTORS.indexOf(opts.factors[j]) === -1) {
      throw new BreakGlassError("breakglass/bad-policy",
        "policy.set: factors[" + j + "] '" + opts.factors[j] +
        "' not in v0.5.0 allowed factors [" + ALLOWED_FACTORS.join(",") + "]" +
        " (passkey lands in v0.5.2)");
    }
  }
  if (opts.cryptographic === true) {
    throw new BreakGlassError("breakglass/bad-policy",
      "policy.set: cryptographic mode (Model B) ships in v0.5.1 — " +
      "set cryptographic: false (default) or omit for v0.5.0");
  }
  var grantTtl = opts.grantTtl != null ? opts.grantTtl : DEFAULT_GRANT_TTL_MS;
  if (typeof grantTtl !== "number" || !isFinite(grantTtl) || grantTtl <= 0) {
    throw new BreakGlassError("breakglass/bad-policy",
      "policy.set: grantTtl must be a positive number of milliseconds");
  }
  var maxRows = opts.maxRowsPerGrant != null ? opts.maxRowsPerGrant : DEFAULT_MAX_ROWS;
  if (!Number.isInteger(maxRows) || maxRows < 1) {
    throw new BreakGlassError("breakglass/bad-policy",
      "policy.set: maxRowsPerGrant must be a positive integer (default 1 — row-by-row auth)");
  }
  if (opts.onLockedAccess != null &&
      opts.onLockedAccess !== "throw" && opts.onLockedAccess !== "redact") {
    throw new BreakGlassError("breakglass/bad-policy",
      "policy.set: onLockedAccess must be 'throw' or 'redact'");
  }
  if (opts.auditReasonStorage != null &&
      ALLOWED_REASON_STORAGE.indexOf(opts.auditReasonStorage) === -1) {
    throw new BreakGlassError("breakglass/bad-policy",
      "policy.set: auditReasonStorage must be one of " + ALLOWED_REASON_STORAGE.join("/"));
  }
  if (opts.serviceAccountBypass != null && opts.serviceAccountBypass !== false) {
    throw new BreakGlassError("breakglass/bad-policy",
      "policy.set: serviceAccountBypass ships in v0.5.2 — leave unset for v0.5.0");
  }
  return {
    grantTtl:        grantTtl,
    maxRowsPerGrant: maxRows,
    reasonRequired:  opts.reasonRequired !== false,
    reasonMinLength: opts.reasonMinLength != null ? opts.reasonMinLength : DEFAULT_REASON_MIN_LEN,
    pinIp:           opts.pinIp !== false,
    sessionPin:      opts.sessionPin !== false,
    onLockedAccess:  opts.onLockedAccess || DEFAULT_LOCKED_BEHAVIOR,
    requireScope:    opts.requireScope != null ? opts.requireScope : null,
    auditReasonStorage: opts.auditReasonStorage || DEFAULT_AUDIT_REASON,
  };
}

async function policySet(table, opts, callerOpts) {
  _requireInit();
  var validated = _validatePolicySet(table, opts);
  var policyRow = {
    tableName:                table,
    columnsJson:              JSON.stringify(opts.columns),
    factorsJson:              JSON.stringify(opts.factors),
    cryptographic:            0,
    grantTtlMs:               validated.grantTtl,
    maxRowsPerGrant:          validated.maxRowsPerGrant,
    reasonRequired:           validated.reasonRequired ? 1 : 0,
    reasonMinLength:          validated.reasonMinLength,
    pinIp:                    validated.pinIp ? 1 : 0,
    sessionPin:               validated.sessionPin ? 1 : 0,
    onLockedAccess:           validated.onLockedAccess,
    requireScope:             validated.requireScope,
    serviceAccountBypassJson: null,
    auditReasonStorage:       validated.auditReasonStorage,
    updatedAt:                Date.now(),
  };
  var sealed = cryptoField.sealRow("_blamejs_break_glass_policies", policyRow);
  // UPSERT — both Postgres and SQLite support ON CONFLICT.
  var keys   = Object.keys(sealed);
  var cols   = keys.join(", ");
  var qs     = keys.map(function () { return "?"; }).join(", ");
  var setSql = keys.filter(function (k) { return k !== "tableName"; })
    .map(function (k) { return k + " = excluded." + k; }).join(", ");
  var sql = "INSERT INTO _blamejs_break_glass_policies (" + cols + ") " +
            "VALUES (" + qs + ") " +
            "ON CONFLICT (tableName) DO UPDATE SET " + setSql;
  await clusterStorage.execute(sql, keys.map(function (k) { return sealed[k]; }));
  policyCache.delete(table);

  audit.safeEmit({
    action:   "breakglass.policy.set",
    outcome:  "success",
    actor:    requestHelpers.resolveActorWithOverride(callerOpts),
    metadata: {
      table:           table,
      columnCount:     opts.columns.length,
      factors:         opts.factors,
      grantTtlMs:      validated.grantTtl,
      maxRowsPerGrant: validated.maxRowsPerGrant,
    },
  });
  observability.event("breakglass.policy.set", { table: table });
  return { applied: true, table: table };
}

async function policyGet(table) {
  _requireInit();
  if (typeof table !== "string" || table.length === 0) return null;
  if (policyCache.has(table)) return policyCache.get(table);
  var rows = await clusterStorage.executeAll(
    "SELECT * FROM _blamejs_break_glass_policies WHERE tableName = ?",
    [table]
  );
  if (!rows || rows.length === 0) {
    policyCache.set(table, null);
    return null;
  }
  var unsealed = cryptoField.unsealRow("_blamejs_break_glass_policies", rows[0]);
  var policy = {
    table:              unsealed.tableName,
    columns:            safeJson.parse(unsealed.columnsJson, { maxBytes: C.BYTES.kib(64) }),
    factors:            safeJson.parse(unsealed.factorsJson, { maxBytes: C.BYTES.kib(8) }),
    cryptographic:      unsealed.cryptographic === 1,
    grantTtl:           Number(unsealed.grantTtlMs),
    maxRowsPerGrant:    Number(unsealed.maxRowsPerGrant),
    reasonRequired:     unsealed.reasonRequired === 1,
    reasonMinLength:    Number(unsealed.reasonMinLength),
    pinIp:              unsealed.pinIp === 1,
    sessionPin:         unsealed.sessionPin === 1,
    onLockedAccess:     unsealed.onLockedAccess,
    requireScope:       unsealed.requireScope,
    auditReasonStorage: unsealed.auditReasonStorage,
    updatedAt:          Number(unsealed.updatedAt),
  };
  policyCache.set(table, policy);
  return policy;
}

async function policyList() {
  _requireInit();
  var rows = await clusterStorage.executeAll(
    "SELECT tableName FROM _blamejs_break_glass_policies ORDER BY tableName"
  );
  var out = [];
  for (var i = 0; i < (rows || []).length; i++) {
    var p = await policyGet(rows[i].tableName);
    if (p) out.push(p);
  }
  return out;
}

async function policyDelete(table, callerOpts) {
  _requireInit();
  if (typeof table !== "string" || table.length === 0) {
    throw new BreakGlassError("breakglass/bad-policy",
      "policy.delete: table must be a non-empty string");
  }
  await clusterStorage.execute(
    "DELETE FROM _blamejs_break_glass_policies WHERE tableName = ?",
    [table]
  );
  policyCache.delete(table);
  audit.safeEmit({
    action:   "breakglass.policy.delete",
    outcome:  "success",
    actor:    requestHelpers.resolveActorWithOverride(callerOpts),
    metadata: { table: table },
  });
  return { deleted: true, table: table };
}

// ---- Grant issuance ----

function _verifyTotpFactor(factor) {
  if (!factor || typeof factor !== "object") return { ok: false };
  if (typeof factor.secret !== "string" || factor.secret.length === 0) return { ok: false };
  if (typeof factor.code !== "string" || factor.code.length === 0)     return { ok: false };
  var verified = totp.verify(factor.secret, factor.code);
  return { ok: verified !== false, step: verified };
}

async function grant(opts) {
  _requireInit();
  if (!opts || typeof opts !== "object") {
    throw new BreakGlassError("breakglass/bad-grant-opts",
      "grant: opts is required");
  }
  validateOpts(opts, ["req", "table", "columns", "reason", "factor"], "breakGlass.grant");

  var table = opts.table;
  var policy = await policyGet(table);
  if (!policy) {
    throw new BreakGlassError("breakglass/policy-not-set",
      "no break-glass policy is configured for table '" + table + "'", true);
  }

  // Reason validation
  var reason = typeof opts.reason === "string" ? opts.reason : "";
  if (policy.reasonRequired && reason.length === 0) {
    throw new BreakGlassError("breakglass/missing-reason",
      "grant: reason is required for table '" + table + "'", true);
  }
  if (policy.reasonRequired && reason.length < policy.reasonMinLength) {
    throw new BreakGlassError("breakglass/short-reason",
      "grant: reason must be at least " + policy.reasonMinLength + " characters", true);
  }

  // Column scoping
  var requestedColumns = Array.isArray(opts.columns) && opts.columns.length > 0
    ? opts.columns.slice()
    : policy.columns.slice();
  for (var i = 0; i < requestedColumns.length; i++) {
    if (policy.columns.indexOf(requestedColumns[i]) === -1) {
      throw new BreakGlassError("breakglass/grant-column-mismatch",
        "grant: requested column '" + requestedColumns[i] +
        "' is not glass-locked on table '" + table + "'", true);
    }
  }

  // Actor identity
  var actor = requestHelpers.extractActorContext(opts.req);
  var actorId = actor.userId || (opts.req && opts.req.apiKey && opts.req.apiKey.id) || null;
  if (!actorId) {
    throw new BreakGlassError("breakglass/unauthorized",
      "grant: no authenticated actor on request (req.user.id / req.apiKey.id required)", true);
  }

  // Factor verification + lockout
  var factorType = opts.factor && opts.factor.type;
  if (!factorType || policy.factors.indexOf(factorType) === -1) {
    throw new BreakGlassError("breakglass/bad-factor",
      "grant: factor.type must be one of [" + policy.factors.join(",") + "]");
  }
  var fl = _ensureFactorLockout();
  var lockKey = actorId;
  var locked = await fl.check(lockKey);
  if (locked && locked.locked) {
    audit.safeEmit({
      action:   "breakglass.grant.requested",
      outcome:  "denied",
      actor:    actor,
      reason:   "factor-rate-limited",
      metadata: { table: table, factorType: factorType, lockUntil: locked.lockedUntil },
    });
    throw new BreakGlassError("breakglass/factor-rate-limited",
      "grant: too many recent factor failures; locked until " +
      new Date(locked.lockedUntil).toISOString());
  }

  var factorOk = false;
  if (factorType === "totp") {
    factorOk = _verifyTotpFactor(opts.factor).ok;
  }

  if (!factorOk) {
    await fl.recordFailure(lockKey, { reason: factorType + "-bad" });
    audit.safeEmit({
      action:   "breakglass.grant.requested",
      outcome:  "denied",
      actor:    actor,
      reason:   "bad-factor",
      metadata: { table: table, factorType: factorType, columns: requestedColumns },
    });
    throw new BreakGlassError("breakglass/bad-factor",
      "grant: " + factorType + " factor verification failed");
  }
  await fl.recordSuccess(lockKey);

  // Build + persist the grant row
  var nowMs    = Date.now();
  var grantId  = "bg-" + generateToken(16);
  var sessionId = (opts.req && opts.req.session && opts.req.session.id) || null;
  var ipFromReq = (opts.req && opts.req.socket && opts.req.socket.remoteAddress) || null;

  var grantRow = {
    _id:                grantId,
    issuedToActorId:    actorId,
    factorType:         factorType,
    reasonSealed:       reason,
    scopeTable:         table,
    scopeColumnsJson:   JSON.stringify(requestedColumns),
    issuedAt:           nowMs,
    expiresAt:          nowMs + policy.grantTtl,
    maxRowsPerGrant:    policy.maxRowsPerGrant,
    rowsConsumed:       0,
    revokedAt:          null,
    sessionId:          sessionId,
    ip:                 ipFromReq,
    kwGrantHalf:        null,
  };
  var sealed = cryptoField.sealRow("_blamejs_break_glass_grants", grantRow);
  var keys = Object.keys(sealed);
  var cols = keys.join(", ");
  var qs   = keys.map(function () { return "?"; }).join(", ");
  await clusterStorage.execute(
    "INSERT INTO _blamejs_break_glass_grants (" + cols + ") VALUES (" + qs + ")",
    keys.map(function (k) { return sealed[k]; })
  );

  // Audit
  var reasonForAudit = _reasonForAudit(reason, policy.auditReasonStorage);
  audit.safeEmit({
    action:   "breakglass.grant.requested",
    outcome:  "success",
    actor:    actor,
    reason:   reasonForAudit.cleartext,
    metadata: {
      grantId:           grantId,
      table:             table,
      columns:           requestedColumns,
      factorType:        factorType,
      ttlMs:             policy.grantTtl,
      maxRowsPerGrant:   policy.maxRowsPerGrant,
      reasonHmac:        reasonForAudit.hmac,
    },
  });
  observability.event("breakGlass.grant", { table: table });

  return {
    id:             grantId,
    expiresAt:      grantRow.expiresAt,
    rowsRemaining:  policy.maxRowsPerGrant,
    scopeTable:     table,
    scopeColumns:   requestedColumns,
  };
}

function _reasonForAudit(reason, mode) {
  // HMAC variant uses SHA3-512 keyed by a stable framework-wide tag —
  // operators with multiple deployments can correlate via the hash
  // without re-deriving from the same secret. Cleartext is the default
  // (compliance reviewers WANT to read the reason).
  var out = { cleartext: null, hmac: null };
  if (mode === "cleartext" || mode === "both") out.cleartext = reason;
  if (mode === "hmac" || mode === "both") {
    out.hmac = sha3Hash("breakGlass.reason:" + reason);
  }
  return out;
}

// ---- Use a grant ----

async function unsealRow(grantHandle, table, rowId) {
  _requireInit();
  if (!grantHandle || typeof grantHandle !== "object" || typeof grantHandle.id !== "string") {
    throw new BreakGlassError("breakglass/bad-grant-opts",
      "unsealRow: grant handle is required (returned from b.breakGlass.grant())");
  }
  if (typeof table !== "string" || table.length === 0) {
    throw new BreakGlassError("breakglass/bad-grant-opts",
      "unsealRow: table must be a non-empty string");
  }
  if (rowId === undefined || rowId === null || rowId === "") {
    throw new BreakGlassError("breakglass/bad-grant-opts",
      "unsealRow: rowId is required");
  }
  var grantRows = await clusterStorage.executeAll(
    "SELECT * FROM _blamejs_break_glass_grants WHERE _id = ?",
    [grantHandle.id]
  );
  if (!grantRows || grantRows.length === 0) {
    throw new BreakGlassError("breakglass/grant-revoked",
      "unsealRow: grant " + grantHandle.id + " not found (deleted or never issued)", true);
  }
  var sealedGrant = grantRows[0];
  var grantRow = cryptoField.unsealRow("_blamejs_break_glass_grants", sealedGrant);

  // Table mismatch
  if (grantRow.scopeTable !== table) {
    audit.safeEmit({
      action:   "breakglass.unsealrow",
      outcome:  "denied",
      actor:    { userId: grantRow.issuedToActorId },
      reason:   "grant-table-mismatch",
      metadata: { grantId: grantRow._id, expectedTable: grantRow.scopeTable, gotTable: table, rowId: String(rowId) },
    });
    throw new BreakGlassError("breakglass/grant-table-mismatch",
      "unsealRow: grant " + grantHandle.id + " is scoped to '" +
      grantRow.scopeTable + "', not '" + table + "'", true);
  }

  // Revoked
  if (grantRow.revokedAt) {
    throw new BreakGlassError("breakglass/grant-revoked",
      "unsealRow: grant " + grantHandle.id + " was revoked at " +
      new Date(Number(grantRow.revokedAt)).toISOString(), true);
  }

  // Expired
  if (Number(grantRow.expiresAt) <= Date.now()) {
    audit.safeEmit({
      action:   "breakglass.grant.expired",
      outcome:  "success",
      actor:    { userId: grantRow.issuedToActorId },
      metadata: { grantId: grantRow._id, table: table, rowsConsumed: Number(grantRow.rowsConsumed) },
    });
    throw new BreakGlassError("breakglass/grant-expired",
      "unsealRow: grant " + grantHandle.id + " expired at " +
      new Date(Number(grantRow.expiresAt)).toISOString(), true);
  }

  // Exhausted
  if (Number(grantRow.rowsConsumed) >= Number(grantRow.maxRowsPerGrant)) {
    audit.safeEmit({
      action:   "breakglass.grant.exhausted",
      outcome:  "success",
      actor:    { userId: grantRow.issuedToActorId },
      metadata: { grantId: grantRow._id, table: table, rowsConsumed: Number(grantRow.rowsConsumed) },
    });
    throw new BreakGlassError("breakglass/grant-exhausted",
      "unsealRow: grant " + grantHandle.id + " has consumed all " +
      grantRow.maxRowsPerGrant + " allowed rows", true);
  }

  // Increment rowsConsumed (atomic UPDATE with WHERE rowsConsumed < cap
  // so concurrent unseals can't both pass the runtime check above).
  var updateRes = await clusterStorage.execute(
    "UPDATE _blamejs_break_glass_grants " +
    "SET rowsConsumed = rowsConsumed + 1 " +
    "WHERE _id = ? AND rowsConsumed < maxRowsPerGrant AND " +
    "(revokedAt IS NULL) AND expiresAt > ?",
    [grantHandle.id, Date.now()]
  );
  // executeAll-style result; some backends return rowsAffected, others a count.
  // Re-query to confirm the increment landed and get the post-increment counter.
  var postRows = await clusterStorage.executeAll(
    "SELECT rowsConsumed, revokedAt, expiresAt FROM _blamejs_break_glass_grants WHERE _id = ?",
    [grantHandle.id]
  );
  if (!postRows || postRows.length === 0) {
    throw new BreakGlassError("breakglass/grant-revoked",
      "unsealRow: grant " + grantHandle.id + " disappeared during unseal", true);
  }
  var postRowsConsumed = Number(postRows[0].rowsConsumed);
  // If the UPDATE didn't actually increment (race lost — another unseal
  // exhausted the grant or it was revoked / expired between our check
  // and the UPDATE), refuse this read.
  if (postRowsConsumed === Number(grantRow.rowsConsumed)) {
    throw new BreakGlassError("breakglass/grant-exhausted",
      "unsealRow: grant " + grantHandle.id + " was exhausted by a concurrent read", true);
  }
  void updateRes;

  // Fetch + unseal the target row through cryptoField
  var rows = await clusterStorage.executeAll(
    "SELECT * FROM " + table + " WHERE _id = ?",
    [String(rowId)]
  );
  if (!rows || rows.length === 0) {
    throw new BreakGlassError("breakglass/row-not-found",
      "unsealRow: " + table + "[" + rowId + "] not found", true);
  }
  var unsealedRow = cryptoField.unsealRow(table, rows[0]);

  // Per-row audit. The grant's reasonSealed is already cleartext after
  // unsealRow on the grant; pass it into the audit row honoring the
  // policy's auditReasonStorage mode.
  var policy = await policyGet(table);
  var reasonForAudit = _reasonForAudit(grantRow.reasonSealed || "",
    policy ? policy.auditReasonStorage : DEFAULT_AUDIT_REASON);
  audit.safeEmit({
    action:    "breakglass.unsealrow",
    outcome:   "success",
    actor:     { userId: grantRow.issuedToActorId },
    reason:    reasonForAudit.cleartext,
    metadata:  {
      grantId:        grantRow._id,
      table:          table,
      rowId:          String(rowId),
      columns:        safeJson.parse(grantRow.scopeColumnsJson || "[]", { maxBytes: C.BYTES.kib(64) }),
      rowsRemaining:  Number(grantRow.maxRowsPerGrant) - postRowsConsumed,
      reasonHmac:     reasonForAudit.hmac,
    },
  });
  observability.event("breakglass.unsealrow", { table: table });

  return unsealedRow;
}

// ---- Revoke ----

async function revoke(grantId, opts) {
  _requireInit();
  if (typeof grantId !== "string" || grantId.length === 0) {
    throw new BreakGlassError("breakglass/bad-grant-opts",
      "revoke: grantId is required");
  }
  opts = opts || {};
  var nowMs = Date.now();
  await clusterStorage.execute(
    "UPDATE _blamejs_break_glass_grants SET revokedAt = ? " +
    "WHERE _id = ? AND revokedAt IS NULL",
    [nowMs, grantId]
  );
  audit.safeEmit({
    action:   "breakglass.grant.revoked",
    outcome:  "success",
    actor:    requestHelpers.resolveActorWithOverride(opts),
    reason:   typeof opts.reason === "string" ? opts.reason : null,
    metadata: { grantId: grantId },
  });
  return { revoked: true, grantId: grantId };
}

// ---- listActive ----

async function listActive(opts) {
  _requireInit();
  opts = opts || {};
  var actor = requestHelpers.extractActorContext(opts.req);
  var actorId = actor.userId || (opts.req && opts.req.apiKey && opts.req.apiKey.id) || null;
  if (!actorId) return [];
  // Use cryptoField's computeDerived so the hash matches the table's
  // hashNamespace prefix — raw sha3Hash would produce a different value.
  var derived = cryptoField.computeDerived(
    "_blamejs_break_glass_grants", "issuedToActorId", actorId
  );
  if (!derived) return [];
  var nowMs = Date.now();
  var rows = await clusterStorage.executeAll(
    "SELECT * FROM _blamejs_break_glass_grants " +
    "WHERE issuedToActorHash = ? AND (revokedAt IS NULL) AND expiresAt > ? AND rowsConsumed < maxRowsPerGrant " +
    "ORDER BY issuedAt DESC",
    [derived.value, nowMs]
  );
  var out = [];
  for (var i = 0; i < (rows || []).length; i++) {
    var u = cryptoField.unsealRow("_blamejs_break_glass_grants", rows[i]);
    out.push({
      id:             u._id,
      scopeTable:     u.scopeTable,
      scopeColumns:   safeJson.parse(u.scopeColumnsJson || "[]", { maxBytes: C.BYTES.kib(64) }),
      issuedAt:       Number(u.issuedAt),
      expiresAt:      Number(u.expiresAt),
      rowsRemaining:  Number(u.maxRowsPerGrant) - Number(u.rowsConsumed),
      factorType:     u.factorType,
    });
  }
  return out;
}

// ---- Sweep (best-effort cleanup of expired grants) ----

async function _sweepExpired(opts) {
  opts = opts || {};
  var nowMs = Date.now();
  var expired = await clusterStorage.executeAll(
    "SELECT _id, issuedToActorId, scopeTable, rowsConsumed FROM _blamejs_break_glass_grants " +
    "WHERE revokedAt IS NULL AND expiresAt <= ?",
    [nowMs]
  );
  for (var i = 0; i < (expired || []).length; i++) {
    var row = expired[i];
    audit.safeEmit({
      action:   "breakglass.grant.expired",
      outcome:  "success",
      actor:    { userId: row.issuedToActorId },
      metadata: { grantId: row._id, table: row.scopeTable, rowsConsumed: Number(row.rowsConsumed) },
    });
  }
  await clusterStorage.execute(
    "UPDATE _blamejs_break_glass_grants SET revokedAt = ? " +
    "WHERE revokedAt IS NULL AND expiresAt <= ?",
    [nowMs, nowMs]
  );
  return { expired: (expired || []).length };
}

void safeAsync;   // kept import for future grant-async ops in v0.5.1+

module.exports = {
  init:             init,
  policy: {
    set:    policySet,
    get:    policyGet,
    list:   policyList,
    delete: policyDelete,
  },
  grant:            grant,
  unsealRow:        unsealRow,
  revoke:           revoke,
  listActive:       listActive,
  BreakGlassError:  BreakGlassError,

  // Test-only / sweep — operators with active grant volume wire this
  // into a scheduler; the framework doesn't auto-start the timer so
  // boot doesn't depend on anything firing in the background.
  _sweepExpiredForTest: _sweepExpired,
  _resetForTest:        _resetForTest,
};
