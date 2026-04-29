"use strict";
/**
 * b.apiKey — operator-facing API-key issuance, verification, revocation,
 * and rotation.
 *
 *   var keys = b.apiKey.create({
 *     namespace:        "live",
 *     audit:            b.audit,                  // optional
 *     trackLastUsedAt:  false,                    // default
 *   });
 *
 *   var issued = await keys.issue({
 *     ownerId:   "user-42",
 *     scopes:    ["read:users", "write:posts"],
 *     metadata:  { name: "Mobile app v3" },
 *     expiresAt: Date.now() + 90 * 86400 * 1000,
 *   });
 *   // issued.key  — "bk_live_<idHex>_<secretHex>"  (returned ONCE)
 *   // issued.id   — "<idHex>"
 *
 *   var record = await keys.verify(req.headers["x-api-key"]);
 *   // → { id, ownerId, scopes, metadata, ... } or null
 *
 *   await keys.revoke(id);
 *   var rotated = await keys.rotate(id);          // new secret; old stops working
 *   var owned   = await keys.listForOwner("user-42");
 *
 * Token format (Stripe-style, prefix-recognizable):
 *
 *     <prefix>_<namespace>_<idHex>_<secretHex>
 *
 * Example: `bk_live_5b9e7c8a4f2d1e3a_8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d`
 *
 * - prefix    operator-supplied; default "bk". Visual marker.
 * - namespace operator-supplied; lets multiple key registries coexist
 *             (e.g. "live"/"test", "v1"/"v2") without collision.
 * - idHex     opaque random hex; PRIMARY KEY component (DB lookup).
 * - secretHex opaque random hex; never re-derivable. Stored as
 *             SHA3-512 hash, constant-time-compared on verify.
 *
 * Storage: framework table `_blamejs_api_keys` (sealed columns:
 * ownerId/scopes/metadata; ownerIdHash for indexed listForOwner).
 * Same dual-storage pattern as sessions — local SQLite in single-node
 * mode, external-db in cluster mode, dispatched via cluster-storage.
 *
 * Validation tiers:
 *
 *   - apiKey.create opts                    → Tier A (throw)
 *   - registry.issue opts                   → Tier A (throw ApiKeyError)
 *   - registry.rotate(id) on missing/revoked → Tier A (throw)
 *   - registry.verify(token) on any failure → Tier C (return null)
 *   - registry.revoke(id) on missing        → Tier C (return false)
 *   - registry.getById(id) on missing       → Tier C (return null)
 */

var crypto = require("./crypto");
var credentialHash = require("./credential-hash");
var safeJson = require("./safe-json");
var lazyRequire = require("./lazy-require");
var clusterStorage = require("./cluster-storage");
var cluster = require("./cluster");
var cryptoField = require("./crypto-field");
var requestHelpers = require("./request-helpers");
var validateOpts = require("./validate-opts");
var C = require("./constants");
var { ApiKeyError } = require("./framework-error");

var observability = lazyRequire(function () { return require("./observability"); });

function _emitEvent(name, value, labels) {
  try { observability().event(name, value, labels || {}); }
  catch (_e) { /* Tier B: hot-path observability sink */ }
}

var _err = ApiKeyError.factory;

var TABLE = "_blamejs_api_keys";

// Column order used for INSERT — kept as a constant so the placeholders
// list and the values list stay in sync. Must match _blamejs_api_keys'
// schema in db.js (single-node) and framework-schema.js (cluster mode).
var COLS = [
  "id", "namespace", "ownerId", "ownerIdHash", "secretHash",
  "secondarySecretHash", "secondaryExpiresAt",
  "scopes", "metadata", "createdAt", "expiresAt", "revokedAt",
  "lastUsedAt", "prefix",
];

// Default rotate grace period when caller passes { graceful: true }
// without an explicit gracePeriodMs. 7 days is enough to migrate the
// vast majority of clients without paging anyone, short enough that
// a forgotten old secret stops working before it becomes a long-tail
// liability.
var DEFAULT_ROTATE_GRACE_MS = C.TIME.days(7);

// Visibility defaults are ON. When an operator wires `audit: b.audit`,
// they're declaring "I want to know what happens with these credentials"
// — that includes verify success (every access to a credential), reads
// (listForOwner/getById), and all state changes. The compliance trail
// (HIPAA §164.312(b), PCI-DSS 10.2.1, GDPR Art. 32) needs WHO + WHAT +
// WHEN on every access, not just on writes.
//
// Operators with extreme verify-rate volume opt OUT explicitly via
// `auditSuccess: false`. Failures stay on regardless.
var DEFAULTS = Object.freeze({
  prefix:           "bk",
  idBytes:          8,        // 16 hex chars
  secretBytes:      16,       // 32 hex chars
  trackLastUsedAt:  true,     // visibility on dormant / leaked keys
  auditFailures:    true,     // failure events are actionable signals
  auditSuccess:     true,     // compliance trail — opt out at extreme volume
  purgeAfterMs:     C.TIME.days(90),
  // Credential hash algorithm for new issues. Falls through to
  // credentialHash defaults; SHAKE256 is the active per-framework
  // because api-key secrets are 128-bit random (memory-hard property
  // buys nothing at that entropy) and SHAKE256 is an XOF — the
  // envelope payload length itself drives the digest size, so a
  // future operator can request 96-byte digests without an algorithm
  // rotation. Operators with low-entropy or paranoia-mode storage
  // pin "argon2id" per registry. The envelope ensures historical
  // credentials always remain verifiable.
  hashAlgo:         "shake256",
});

// ---- Tier-A validation helpers ----

function _isPositiveInt(n) {
  return typeof n === "number" && isFinite(n) && n >= 1 && Math.floor(n) === n;
}

function _validateIdentifier(name, value) {
  if (typeof value !== "string" || value.length === 0) {
    throw _err("BAD_OPT", name + " must be a non-empty string, got " + typeof value);
  }
  if (/[_\s]/.test(value)) {
    throw _err("BAD_OPT", name + " must not contain underscores or whitespace (collides with format separator), got " +
      JSON.stringify(value));
  }
}

function _validateCreateOpts(opts) {
  if (!opts || typeof opts !== "object") {
    throw _err("BAD_OPT", "apiKey.create: opts must be an object");
  }
  _validateIdentifier("apiKey.create: namespace", opts.namespace);
  if (opts.prefix !== undefined) _validateIdentifier("apiKey.create: prefix", opts.prefix);
  if (opts.idBytes !== undefined && !_isPositiveInt(opts.idBytes)) {
    throw _err("BAD_OPT", "apiKey.create: idBytes must be a positive integer");
  }
  if (opts.secretBytes !== undefined && !_isPositiveInt(opts.secretBytes)) {
    throw _err("BAD_OPT", "apiKey.create: secretBytes must be a positive integer");
  }
  if (opts.trackLastUsedAt !== undefined && typeof opts.trackLastUsedAt !== "boolean") {
    throw _err("BAD_OPT", "apiKey.create: trackLastUsedAt must be a boolean");
  }
  if (opts.auditFailures !== undefined && typeof opts.auditFailures !== "boolean") {
    throw _err("BAD_OPT", "apiKey.create: auditFailures must be a boolean");
  }
  if (opts.auditSuccess !== undefined && typeof opts.auditSuccess !== "boolean") {
    throw _err("BAD_OPT", "apiKey.create: auditSuccess must be a boolean");
  }
  if (opts.purgeAfterMs !== undefined &&
      (typeof opts.purgeAfterMs !== "number" || !isFinite(opts.purgeAfterMs) || opts.purgeAfterMs < 0)) {
    throw _err("BAD_OPT", "apiKey.create: purgeAfterMs must be a non-negative finite number");
  }
  if (opts.hashAlgo !== undefined) {
    if (typeof opts.hashAlgo !== "string" ||
        (opts.hashAlgo !== "shake256" && opts.hashAlgo !== "argon2id")) {
      throw _err("BAD_OPT", "apiKey.create: hashAlgo must be 'shake256' or 'argon2id', got " +
        JSON.stringify(opts.hashAlgo));
    }
  }
  if (opts.audit !== undefined && opts.audit !== null) {
    if (typeof opts.audit !== "object" || typeof opts.audit.safeEmit !== "function") {
      throw _err("BAD_OPT", "apiKey.create: audit must be a b.audit-shaped object (safeEmit fn)");
    }
  }
  if (opts.clock !== undefined && typeof opts.clock !== "function") {
    throw _err("BAD_OPT", "apiKey.create: clock must be a function or undefined");
  }
}

function _validateIssueOpts(opts) {
  if (!opts || typeof opts !== "object") {
    throw _err("BAD_OPT", "apiKey.issue: opts must be an object");
  }
  if (typeof opts.ownerId !== "string" || opts.ownerId.length === 0) {
    throw _err("MISSING_OWNER", "apiKey.issue: ownerId must be a non-empty string");
  }
  if (opts.scopes !== undefined) {
    if (!Array.isArray(opts.scopes)) {
      throw _err("BAD_SCOPES", "apiKey.issue: scopes must be an array of strings");
    }
    for (var i = 0; i < opts.scopes.length; i++) {
      if (typeof opts.scopes[i] !== "string" || opts.scopes[i].length === 0) {
        throw _err("BAD_SCOPES", "apiKey.issue: scopes[" + i + "] must be a non-empty string");
      }
    }
  }
  if (opts.metadata !== undefined && opts.metadata !== null) {
    if (typeof opts.metadata !== "object" || Array.isArray(opts.metadata)) {
      throw _err("BAD_METADATA", "apiKey.issue: metadata must be a plain object or null");
    }
  }
  if (opts.expiresAt !== undefined && opts.expiresAt !== null) {
    if (typeof opts.expiresAt !== "number" || !isFinite(opts.expiresAt) || opts.expiresAt < 0) {
      throw _err("BAD_OPT", "apiKey.issue: expiresAt must be a non-negative finite number (unix ms) or null");
    }
  }
}

// ---- Token format ----

// Format: <prefix>_<namespace>_<idHex>_<secretHex>
// Each part is alphanumeric so split-by-underscore is unambiguous as long
// as prefix/namespace are validated to contain no underscores. We verify
// that during create.
function parseFormat(token) {
  if (typeof token !== "string" || token.length === 0) return null;
  var parts = token.split("_");
  if (parts.length !== 4) return null;
  var prefix = parts[0], ns = parts[1], idHex = parts[2], secretHex = parts[3];
  if (!prefix || !ns || !idHex || !secretHex) return null;
  if (!/^[0-9a-f]+$/i.test(idHex) || !/^[0-9a-f]+$/i.test(secretHex)) return null;
  return { prefix: prefix, namespace: ns, idHex: idHex, secretHex: secretHex };
}

function _composeKey(prefix, namespace, idHex, secretHex) {
  return prefix + "_" + namespace + "_" + idHex + "_" + secretHex;
}

function _composedId(namespace, idHex) {
  return namespace + ":" + idHex;
}

// ---- Sealed-row helpers ----

function _sealForInsert(row) {
  var sealed = cryptoField.sealRow(TABLE, row);
  for (var i = 0; i < COLS.length; i++) {
    if (!(COLS[i] in sealed)) sealed[COLS[i]] = null;
  }
  return sealed;
}

// ---- Registry factory ----

function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "namespace", "prefix", "idBytes", "secretBytes",
    "trackLastUsedAt", "auditFailures", "auditSuccess",
    "purgeAfterMs", "hashAlgo", "audit", "clock",
  ], "apiKey");
  _validateCreateOpts(opts);
  var prefix          = opts.prefix          || DEFAULTS.prefix;
  var namespace       = opts.namespace;
  var idBytes         = opts.idBytes         || DEFAULTS.idBytes;
  var secretBytes     = opts.secretBytes     || DEFAULTS.secretBytes;
  var trackLastUsedAt = (opts.trackLastUsedAt === undefined) ? DEFAULTS.trackLastUsedAt : opts.trackLastUsedAt;
  var auditFailures   = (opts.auditFailures   === undefined) ? DEFAULTS.auditFailures   : opts.auditFailures;
  var auditSuccess    = (opts.auditSuccess    === undefined) ? DEFAULTS.auditSuccess    : opts.auditSuccess;
  var purgeAfterMs    = (opts.purgeAfterMs    === undefined) ? DEFAULTS.purgeAfterMs    : opts.purgeAfterMs;
  var hashAlgo        = opts.hashAlgo         || DEFAULTS.hashAlgo;
  var audit           = opts.audit || null;
  var clock           = opts.clock || function () { return Date.now(); };

  function _emit(action, info) {
    if (!audit) return;
    try { audit.safeEmit(Object.assign({ action: action }, info)); }
    catch (_e) { /* audit best-effort */ }
  }

  // Build the audit actor by extracting the 5 W's from the supplied
  // request (WHO/WHERE/HOW), then layering caller-supplied context
  // and an explicit userId on top so the most specific value wins.
  // The audit chain treats null fields as "unknown", so partial
  // context is always safe.
  function _actor(callerOpts, userId) {
    var override = {};
    if (userId) override.userId = userId;
    if (callerOpts && callerOpts.context && typeof callerOpts.context === "object") {
      for (var k in callerOpts.context) {
        if (Object.prototype.hasOwnProperty.call(callerOpts.context, k)) {
          override[k] = callerOpts.context[k];
        }
      }
    }
    return requestHelpers.extractActorContext(callerOpts && callerOpts.req, override);
  }

  function _selectAll() {
    return "SELECT id, namespace, ownerId, ownerIdHash, secretHash, " +
           "secondarySecretHash, secondaryExpiresAt, " +
           "scopes, metadata, createdAt, expiresAt, revokedAt, lastUsedAt, prefix FROM " + TABLE;
  }

  function _scrubRecord(row) {
    if (!row) return null;
    var unsealed = cryptoField.unsealRow(TABLE, row);
    var scopes = null;
    if (unsealed.scopes) {
      try { scopes = safeJson.parse(unsealed.scopes); } catch (_e) { scopes = null; }
    }
    var metadata = null;
    if (unsealed.metadata) {
      try { metadata = safeJson.parse(unsealed.metadata); } catch (_e) { metadata = null; }
    }
    var idParts = String(unsealed.id).split(":");
    var idHexOnly = idParts.length === 2 ? idParts[1] : unsealed.id;
    return {
      id:                  idHexOnly,
      namespace:           unsealed.namespace,
      ownerId:             unsealed.ownerId,
      scopes:              scopes || [],
      metadata:            metadata || null,
      createdAt:           Number(unsealed.createdAt),
      expiresAt:           unsealed.expiresAt == null ? null : Number(unsealed.expiresAt),
      revokedAt:           unsealed.revokedAt == null ? null : Number(unsealed.revokedAt),
      lastUsedAt:          unsealed.lastUsedAt == null ? null : Number(unsealed.lastUsedAt),
      // secondaryExpiresAt is operator-visible signal that a graceful
      // rotation is in flight; secondarySecretHash itself is NEVER
      // exposed.
      secondaryExpiresAt:  unsealed.secondaryExpiresAt == null ? null : Number(unsealed.secondaryExpiresAt),
      prefix:              unsealed.prefix,
    };
  }

  async function issue(issueOpts) {
    cluster.requireLeader();
    _validateIssueOpts(issueOpts);
    var idHex     = crypto.generateToken(idBytes);
    var secretHex = crypto.generateToken(secretBytes);
    var compositeId = _composedId(namespace, idHex);
    var nowMs     = clock();
    var scopes    = issueOpts.scopes || [];
    var metadata  = issueOpts.metadata || null;
    var expiresAt = (issueOpts.expiresAt === undefined) ? null : issueOpts.expiresAt;

    var secretEnvelope = await credentialHash.hash(secretHex, { algo: hashAlgo });
    var sealed = _sealForInsert({
      id:                  compositeId,
      namespace:           namespace,
      ownerId:             issueOpts.ownerId,
      secretHash:          secretEnvelope,
      secondarySecretHash: null,
      secondaryExpiresAt:  null,
      scopes:              JSON.stringify(scopes),
      metadata:            metadata ? JSON.stringify(metadata) : null,
      createdAt:           nowMs,
      expiresAt:           expiresAt,
      revokedAt:           null,
      lastUsedAt:          null,
      prefix:              prefix,
    });
    var values = COLS.map(function (c) { return sealed[c]; });
    var placeholders = COLS.map(function () { return "?"; }).join(", ");
    var quoted = COLS.map(function (c) { return '"' + c + '"'; }).join(", ");

    await clusterStorage.execute(
      "INSERT INTO " + TABLE + " (" + quoted + ") VALUES (" + placeholders + ")",
      values
    );

    _emit("apikey.issue", {
      actor:    _actor(issueOpts, issueOpts.ownerId),
      resource: { kind: "apikey", id: compositeId },
      metadata: { namespace: namespace, scopes: scopes, expiresAt: expiresAt },
    });
    _emitEvent("apikey.issue", 1, { namespace: namespace });

    return {
      id:        idHex,
      secret:    secretHex,
      key:       _composeKey(prefix, namespace, idHex, secretHex),
      scopes:    scopes,
      metadata:  metadata,
      createdAt: nowMs,
      expiresAt: expiresAt,
    };
  }

  async function verify(token, verifyOpts) {
    var parsed = parseFormat(token);
    if (!parsed) return null;
    if (parsed.prefix !== prefix || parsed.namespace !== namespace) return null;

    var compositeId = _composedId(namespace, parsed.idHex);
    var row = await clusterStorage.executeOne(
      _selectAll() + " WHERE id = ?",
      [compositeId]
    );
    if (!row) {
      if (auditFailures) {
        _emit("apikey.verify", {
          actor:    _actor(verifyOpts),
          resource: { kind: "apikey", id: compositeId },
          outcome:  "failure",
          reason:   "not-found",
        });
      }
      _emitEvent("apikey.verify", 1, { namespace: namespace, outcome: "failure", reason: "not-found" });
      return null;
    }

    var nowMs = clock();
    var rowOwnerId = null;
    try {
      var unsealedOwner = cryptoField.unsealRow(TABLE, row);
      rowOwnerId = unsealedOwner.ownerId;
    } catch (_e) { rowOwnerId = null; }

    if (row.revokedAt != null) {
      if (auditFailures) {
        _emit("apikey.verify", {
          actor:    _actor(verifyOpts, rowOwnerId),
          resource: { kind: "apikey", id: compositeId },
          outcome:  "failure", reason: "revoked",
        });
      }
      _emitEvent("apikey.verify", 1, { namespace: namespace, outcome: "failure", reason: "revoked" });
      return null;
    }
    if (row.expiresAt != null && Number(row.expiresAt) < nowMs) {
      if (auditFailures) {
        _emit("apikey.verify", {
          actor:    _actor(verifyOpts, rowOwnerId),
          resource: { kind: "apikey", id: compositeId },
          outcome:  "failure", reason: "expired",
        });
      }
      _emitEvent("apikey.verify", 1, { namespace: namespace, outcome: "failure", reason: "expired" });
      return null;
    }

    // Hash dispatch goes through credentialHash so the persisted byte
    // controls the verification algorithm. Both primary and secondary
    // (graceful-rotation) slots are envelope-encoded.
    var primaryMatch = await credentialHash.verify(parsed.secretHex, row.secretHash);
    var secondaryMatch = false;
    var secondaryActive = row.secondarySecretHash != null &&
                          row.secondaryExpiresAt != null &&
                          Number(row.secondaryExpiresAt) >= nowMs;
    if (!primaryMatch && secondaryActive) {
      secondaryMatch = await credentialHash.verify(parsed.secretHex, row.secondarySecretHash);
    }
    if (!primaryMatch && !secondaryMatch) {
      if (auditFailures) {
        _emit("apikey.verify", {
          actor:    _actor(verifyOpts, rowOwnerId),
          resource: { kind: "apikey", id: compositeId },
          outcome:  "failure", reason: "bad-secret",
        });
      }
      _emitEvent("apikey.verify", 1, { namespace: namespace, outcome: "failure", reason: "bad-secret" });
      return null;
    }

    if (trackLastUsedAt && cluster.isLeader()) {
      try {
        await clusterStorage.execute(
          "UPDATE " + TABLE + " SET lastUsedAt = ? WHERE id = ?",
          [nowMs, compositeId]
        );
      } catch (_e) { /* best-effort; verify success not blocked by lastUsed update */ }
    }

    if (auditSuccess) {
      _emit("apikey.verify", {
        actor:    _actor(verifyOpts, rowOwnerId),
        resource: { kind: "apikey", id: compositeId },
        outcome:  "success",
        metadata: { secondary: secondaryMatch },
      });
    }
    _emitEvent("apikey.verify", 1,
      { namespace: namespace, outcome: "success", secondary: secondaryMatch });
    var record = _scrubRecord(row);
    record.usedSecondary = secondaryMatch;       // operator can detect grace-period usage
    return record;
  }

  async function revoke(idHex, revokeOpts) {
    cluster.requireLeader();
    if (typeof idHex !== "string" || idHex.length === 0) return false;
    var compositeId = _composedId(namespace, idHex);
    var nowMs = clock();
    var result = await clusterStorage.execute(
      "UPDATE " + TABLE + " SET revokedAt = ? WHERE id = ? AND revokedAt IS NULL",
      [nowMs, compositeId]
    );
    var changed = (result.rowCount || 0) > 0;
    if (changed) {
      _emit("apikey.revoke", {
        actor:    _actor(revokeOpts),
        resource: { kind: "apikey", id: compositeId },
      });
      _emitEvent("apikey.revoke", 1, { namespace: namespace });
    }
    return changed;
  }

  async function rotate(idHex, rotateOpts) {
    cluster.requireLeader();
    if (typeof idHex !== "string" || idHex.length === 0) {
      throw _err("BAD_OPT", "apiKey.rotate: id must be a non-empty string");
    }
    rotateOpts = rotateOpts || {};
    // Graceful rotation: the previous hash stays valid in the
    // secondarySecretHash slot until secondaryExpiresAt. Operators
    // pass either { graceful: true } (default DEFAULT_ROTATE_GRACE_MS)
    // or { gracePeriodMs: <ms> } for an explicit window. Without
    // either, rotation is immediate (old secret invalidated) — this
    // preserves the original semantics for callers that explicitly
    // want a hard cutover.
    var gracePeriodMs = 0;
    if (typeof rotateOpts.gracePeriodMs === "number") {
      if (!isFinite(rotateOpts.gracePeriodMs) || rotateOpts.gracePeriodMs < 0) {
        throw _err("BAD_OPT", "apiKey.rotate: gracePeriodMs must be a non-negative finite number");
      }
      gracePeriodMs = rotateOpts.gracePeriodMs;
    } else if (rotateOpts.graceful === true) {
      gracePeriodMs = DEFAULT_ROTATE_GRACE_MS;
    } else if (rotateOpts.graceful !== undefined && rotateOpts.graceful !== false) {
      throw _err("BAD_OPT", "apiKey.rotate: graceful must be a boolean");
    }

    var compositeId = _composedId(namespace, idHex);
    var existing = await clusterStorage.executeOne(
      _selectAll() + " WHERE id = ?",
      [compositeId]
    );
    if (!existing) {
      throw _err("NOT_FOUND", "apiKey.rotate: id '" + idHex + "' not found in namespace '" + namespace + "'");
    }
    if (existing.revokedAt != null) {
      throw _err("REVOKED", "apiKey.rotate: id '" + idHex + "' is revoked");
    }
    var newSecretHex = crypto.generateToken(secretBytes);
    var newHash = await credentialHash.hash(newSecretHex, { algo: hashAlgo });
    var nowMs = clock();

    if (gracePeriodMs > 0) {
      // Move current hash → secondary slot, install new hash as primary.
      await clusterStorage.execute(
        "UPDATE " + TABLE + " SET secretHash = ?, " +
        "secondarySecretHash = ?, secondaryExpiresAt = ? WHERE id = ?",
        [newHash, existing.secretHash, nowMs + gracePeriodMs, compositeId]
      );
    } else {
      // Hard cutover — old secret stops working immediately. Clears
      // any prior secondary slot too.
      await clusterStorage.execute(
        "UPDATE " + TABLE + " SET secretHash = ?, " +
        "secondarySecretHash = NULL, secondaryExpiresAt = NULL WHERE id = ?",
        [newHash, compositeId]
      );
    }

    _emit("apikey.rotate", {
      actor:    _actor(rotateOpts),
      resource: { kind: "apikey", id: compositeId },
      metadata: { gracePeriodMs: gracePeriodMs },
    });
    _emitEvent("apikey.rotate", 1, { namespace: namespace, graceful: gracePeriodMs > 0 });
    return {
      key:                _composeKey(prefix, namespace, idHex, newSecretHex),
      secret:             newSecretHex,
      secretHash:         newHash,
      gracePeriodMs:      gracePeriodMs,
      secondaryExpiresAt: gracePeriodMs > 0 ? (nowMs + gracePeriodMs) : null,
    };
  }

  async function listForOwner(ownerId, listOpts) {
    if (typeof ownerId !== "string" || ownerId.length === 0) {
      throw _err("BAD_OPT", "apiKey.listForOwner: ownerId must be a non-empty string");
    }
    listOpts = listOpts || {};
    var includeRevoked = !!listOpts.includeRevoked;
    var includeExpired = !!listOpts.includeExpired;
    var lookup = cryptoField.lookupHash(TABLE, "ownerId", ownerId);
    if (!lookup) {
      throw _err("MISCONFIGURED",
        "_blamejs_api_keys schema is missing the ownerIdHash derived hash — framework misconfigured");
    }
    var sql = _selectAll() + " WHERE namespace = ? AND ownerIdHash = ?";
    var params = [namespace, lookup.value];
    if (!includeRevoked) sql += " AND revokedAt IS NULL";
    if (!includeExpired) {
      sql += " AND (expiresAt IS NULL OR expiresAt >= ?)";
      params.push(clock());
    }
    sql += " ORDER BY createdAt DESC";
    var rows = await clusterStorage.execute(sql, params);
    var list = (rows.rows || []).map(_scrubRecord);
    _emitEvent("apikey.list", 1, { namespace: namespace, count: list.length });
    // Read-access audit: "who listed whose keys at time T" — gated by
    // auditSuccess so operators with admin tooling that polls heavily
    // can opt out. ownerId is the audit subject; the listed IDs are
    // included in metadata so a compliance auditor can reconstruct
    // exactly which records were observed.
    if (auditSuccess) {
      _emit("apikey.list", {
        actor:    _actor(listOpts),
        resource: { kind: "apikey-namespace", id: namespace },
        metadata: {
          ownerId:    ownerId,
          count:      list.length,
          observedIds: list.map(function (r) { return r.id; }),
          includeRevoked: includeRevoked,
          includeExpired: includeExpired,
        },
      });
    }
    return list;
  }

  async function getById(idHex, getOpts) {
    if (typeof idHex !== "string" || idHex.length === 0) return null;
    var compositeId = _composedId(namespace, idHex);
    var row = await clusterStorage.executeOne(
      _selectAll() + " WHERE id = ?",
      [compositeId]
    );
    var record = _scrubRecord(row);
    _emitEvent("apikey.get", 1,
      { namespace: namespace, found: record !== null });
    if (auditSuccess) {
      _emit("apikey.get", {
        actor:    _actor(getOpts),
        resource: { kind: "apikey", id: compositeId },
        metadata: { found: record !== null },
      });
    }
    return record;
  }

  async function purgeExpired(purgeOpts) {
    cluster.requireLeader();
    var threshold = clock() - purgeAfterMs;
    // SELECT-then-DELETE so we can audit the specific IDs being purged.
    // Compliance auditors expect "key X was purged at time T" — a count-
    // only audit is too coarse for forensic reconstruction. Cost is one
    // extra round-trip per purge call which runs on a schedule (not
    // request-rate), so the cost is irrelevant.
    var idRows = await clusterStorage.execute(
      "SELECT id FROM " + TABLE + " WHERE namespace = ? AND " +
      "((revokedAt IS NOT NULL AND revokedAt < ?) OR " +
      " (expiresAt IS NOT NULL AND expiresAt < ?))",
      [namespace, threshold, threshold]
    );
    var purgedCompositeIds = (idRows.rows || []).map(function (r) { return r.id; });

    if (purgedCompositeIds.length === 0) {
      _emitEvent("apikey.purge", 1, { namespace: namespace, count: 0 });
      return 0;
    }

    var result = await clusterStorage.execute(
      "DELETE FROM " + TABLE + " WHERE namespace = ? AND " +
      "((revokedAt IS NOT NULL AND revokedAt < ?) OR " +
      " (expiresAt IS NOT NULL AND expiresAt < ?))",
      [namespace, threshold, threshold]
    );
    var count = result.rowCount || purgedCompositeIds.length;

    _emit("apikey.purge", {
      actor:    _actor(purgeOpts),
      resource: { kind: "apikey-namespace", id: namespace },
      metadata: {
        count: count,
        // Strip the namespace prefix so the audit payload contains
        // bare idHex values consistent with what callers receive
        // from issue/verify/getById.
        purgedIds: purgedCompositeIds.map(function (cid) {
          var parts = cid.split(":");
          return parts.length === 2 ? parts[1] : cid;
        }),
        thresholdMs: threshold,
      },
    });
    _emitEvent("apikey.purge", 1, { namespace: namespace, count: count });
    return count;
  }

  return {
    issue:         issue,
    verify:        verify,
    revoke:        revoke,
    rotate:        rotate,
    listForOwner:  listForOwner,
    getById:       getById,
    purgeExpired:  purgeExpired,
    namespace:     namespace,
    prefix:        prefix,
  };
}

module.exports = {
  create:       create,
  parseFormat:  parseFormat,
  ApiKeyError:  ApiKeyError,
  DEFAULTS:     DEFAULTS,
};
