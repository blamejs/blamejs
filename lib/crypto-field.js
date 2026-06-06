"use strict";
/**
 * @module b.cryptoField
 * @nav    Crypto
 * @title  Field-Level Crypto
 *
 * @intro
 *   Per-column field-level encryption with AAD-bound envelopes. Apps
 *   declare which columns hold PHI / PCI / personal data via
 *   `b.db.init({ schema })`; the framework then auto-protects those
 *   columns on every write (`sealRow`) and reverses on every read
 *   (`unsealRow`). Sealed values are produced by `b.vault.seal`, which
 *   wraps an XChaCha20-Poly1305 ciphertext under the framework's PQC
 *   envelope (ML-KEM + ECDH hybrid) — every encryption uses a fresh
 *   random nonce, so two seals of the same plaintext never collide.
 *
 *   Per-row key (K_row) derivation is opt-in via `declarePerRowKey`.
 *   Tables that opt in get a fresh K_row per INSERT, stored sealed in
 *   `_blamejs_per_row_keys`. AAD on the K_row binds (table, rowId,
 *   info-label) — copying a wrapped K_row from one row to another
 *   fails Poly1305 verification, so a DB-write attacker cannot move
 *   ciphertext between rows to bypass row-scoped erasure. This is the
 *   crypto-shred substrate for `b.subject.eraseHard`: deleting the
 *   K_row entry leaves WAL / replica residual ciphertext mathematically
 *   undecryptable.
 *
 *   Derived hashes (`derivedHashes`) provide indexed lookup for sealed
 *   columns: a normalized SHA3 of the plaintext, salted by the vault's
 *   per-deployment salt + a per-field namespace, so dictionary /
 *   rainbow attacks across fields and across deployments fail. Sealed
 *   columns without a derived hash are unindexable — queries on them
 *   silently return zero rows.
 *
 *   Per-column residency (`declareColumnResidency`) declares EU / US /
 *   global tags; the storage-write gate (`assertColumnResidency`)
 *   refuses writes to a backend whose tag doesn't satisfy the column
 *   under gdpr / dpdp / pipl-cn / uk-gdpr postures.
 *
 *   No mutation of the input row — every operation returns a new
 *   object, suitable for direct insertion into the audit chain.
 *
 * @card
 *   Per-column field-level encryption with AAD-bound envelopes.
 */
var lazyRequire = require("./lazy-require");
var vault = require("./vault");
var vaultAad = require("./vault-aad");
var validateOpts = require("./validate-opts");
var numericBounds = require("./numeric-bounds");
var { defineClass } = require("./framework-error");
var { sha3Hash, kdf } = require("./crypto");
var { HASH_PREFIX, VAULT_PREFIX, TIME } = require("./constants");

// Typed refusal raised when a (actor, table, column) tuple exceeds the
// opt-in unseal-failure rate cap and is in cooldown. alwaysPermanent —
// the caller does not retry; the cooldown is a deliberate, time-bounded
// circuit-breaker, not a transient backend hiccup.
var CryptoFieldRateError = defineClass("CryptoFieldRateError", { alwaysPermanent: true });
var CryptoFieldError     = defineClass("CryptoFieldError", { alwaysPermanent: true });

var compliance    = lazyRequire(function () { return require("./compliance"); });
var db            = lazyRequire(function () { return require("./db"); });
var audit         = lazyRequire(function () { return require("./audit"); });

// Posture cascade hook + erase-vacuum integration. Recording the
// posture lets eraseRow call b.db.vacuumAfterErase({ mode: "full" })
// automatically under postures whose POSTURE_DEFAULTS sets
// requireVacuumAfterErase: true (gdpr / dpdp / pipl-cn / lgpd-br /
// hipaa). Without the vacuum, freed B-tree index pages keep sealed-
// column ciphertext readable from a forensic disk image — defeats the
// "right to erasure" the regulatory regime guarantees.
var _activePosture = null;

/**
 * @primitive b.cryptoField.applyPosture
 * @signature b.cryptoField.applyPosture(posture)
 * @since     0.7.27
 * @compliance gdpr, hipaa
 * @related   b.cryptoField.getActivePosture, b.cryptoField.eraseRow
 *
 * Records the active compliance posture so `eraseRow` can cascade into
 * `b.db.vacuumAfterErase({ mode: "full" })` under regimes whose
 * `POSTURE_DEFAULTS` sets `requireVacuumAfterErase: true` (gdpr / dpdp /
 * pipl-cn / lgpd-br / hipaa). Without the vacuum, freed B-tree index
 * pages keep sealed-column ciphertext readable from a forensic disk
 * image — defeating the "right to erasure" the regime guarantees.
 * Returns null when posture is empty/non-string; otherwise returns
 * `{ posture, requireVacuumAfterErase }`.
 *
 * @example
 *   var info = b.cryptoField.applyPosture("gdpr");
 *   info.posture;                   // → "gdpr"
 *   info.requireVacuumAfterErase;   // → true
 *
 *   b.cryptoField.applyPosture("");   // → null (no-op)
 */
function applyPosture(posture) {
  if (typeof posture !== "string" || posture.length === 0) return null;
  _activePosture = posture;
  var requireVacuum = false;
  try {
    requireVacuum = compliance().postureDefault(posture, "requireVacuumAfterErase") === true;
  } catch (_e) { /* compliance not loaded — record posture only */ }
  return { posture: posture, requireVacuumAfterErase: requireVacuum };
}

/**
 * @primitive b.cryptoField.getActivePosture
 * @signature b.cryptoField.getActivePosture()
 * @since     0.7.27
 * @related   b.cryptoField.applyPosture
 *
 * Returns the posture string most recently recorded via `applyPosture`,
 * or null when no posture has been applied. Read-only — does not
 * mutate state. Used by storage backends to gate cross-border writes.
 *
 * @example
 *   b.cryptoField.applyPosture("hipaa");
 *   b.cryptoField.getActivePosture();   // → "hipaa"
 */
function getActivePosture() { return _activePosture; }

// Per-table registry, populated by db.init()
var schemas = Object.create(null);

// Per-COLUMN data residency registry. Real GDPR / DPDP
// deployments have row-level mixed residency: a `users.name` column
// may be global, but `users.addressLine1` must stay in EU storage.
// db.init({ schema }) carries the operator's residency declaration
// per table; this registry stores it for cross-region check at the
// storage-write boundary.
//
//   { tableName: { columnName: "eu" | "us" | "global" | <tag> } }
var columnResidency = Object.create(null);
// Per-ROW residency registry — table → { residencyColumn, allowedTags }.
// The row-level sibling of columnResidency: one plaintext column on each
// row carries that row's residency tag; write gates refuse a tagged row
// landing on an incompatible backend.
var perRowResidency = Object.create(null);

// Per-row key declaration registry. For tables that opt
// into per-row keying, b.subject.eraseHard deletes the wrapped K_row
// from _blamejs_per_row_keys, leaving WAL/replica residual ciphertext
// undecryptable.
//
//   { tableName: { keySize, info, residencyTag } }
var perRowKeyTables = Object.create(null);

/**
 * @primitive b.cryptoField.registerTable
 * @signature b.cryptoField.registerTable(name, opts)
 * @since     0.4.0
 * @related   b.cryptoField.getSchema, b.cryptoField.sealRow
 *
 * Registers a table's sealed-column declaration. Called from
 * `b.db.init({ schema })` at boot — operators rarely call directly.
 * Stores the per-table list of sealed fields, the derived-hash specs
 * (mapping `derivedField -> { from, normalize }`), and any per-field
 * hash namespaces. Subsequent `sealRow` / `unsealRow` / `eraseRow`
 * calls dispatch through this registry.
 *
 * @opts
 *   sealedFields:   string[],              // column names sealed via vault.seal
 *   derivedHashes:  { [hashCol]: { from: string, normalize?: fn } },
 *   hashNamespaces: { [field]: string },   // override default rainbow-defense ns
 *   aad:            boolean,               // when true, route seal/unseal through
 *                                          // b.vault.aad — AEAD-binds the ciphertext
 *                                          // to (table, rowIdField=primary key, column)
 *                                          // so a DB-write attacker can't copy a
 *                                          // sealed value between rows.
 *   rowIdField:     string,                // when aad=true, the column name carrying
 *                                          // the row identity. Default "id". The row
 *                                          // passed to sealRow MUST already have this
 *                                          // column populated; sealRow refuses when
 *                                          // missing (an AAD bound to a placeholder
 *                                          // would silently fail every unseal).
 *   schemaVersion:  string|number,         // when aad=true, the schema version
 *                                          // threaded into AAD. Default "1". Bump
 *                                          // when the column layout changes to
 *                                          // invalidate all prior ciphertext.
 *
 * @example
 *   b.cryptoField.registerTable("patients", {
 *     sealedFields: ["ssn", "diagnosis"],
 *     derivedHashes: {
 *       ssnHash: { from: "ssn", normalize: function (s) { return String(s).replace(/-/g, ""); } }
 *     }
 *   });
 *   b.cryptoField.getSealedFields("patients");   // → ["ssn", "diagnosis"]
 *
 *   // AAD-bound table (recommended for new schemas).
 *   b.cryptoField.registerTable("idempotency_keys", {
 *     sealedFields: ["headers", "body"],
 *     aad:          true,
 *     rowIdField:   "k",       // primary key column
 *   });
 */
function registerTable(name, opts) {
  var aadOn = opts.aad === true;
  var rowIdField = typeof opts.rowIdField === "string" && opts.rowIdField.length > 0
    ? opts.rowIdField : "id";
  var schemaVersion = opts.schemaVersion != null ? String(opts.schemaVersion) : "1";
  var derivedHashMode = opts.derivedHashMode || "salted-sha3";
  if (derivedHashMode !== "salted-sha3" && derivedHashMode !== "hmac-shake256") {
    throw new CryptoFieldError("crypto-field/bad-derived-hash-mode",
      "registerTable: derivedHashMode must be 'salted-sha3' (default) or " +
      "'hmac-shake256', got " + JSON.stringify(derivedHashMode));
  }
  var derivedHashes = Object.assign({}, opts.derivedHashes || {});
  for (var col in derivedHashes) {
    if (!Object.prototype.hasOwnProperty.call(derivedHashes, col)) continue;
    var colMode = derivedHashes[col] && derivedHashes[col].mode;
    if (colMode !== undefined && colMode !== "salted-sha3" && colMode !== "hmac-shake256") {
      throw new CryptoFieldError("crypto-field/bad-derived-hash-col-mode",
        "registerTable: derivedHashes." + col + ".mode must be " +
        "'salted-sha3' or 'hmac-shake256', got " + JSON.stringify(colMode));
    }
  }
  schemas[name] = {
    sealedFields:    Array.isArray(opts.sealedFields)   ? opts.sealedFields.slice()   : [],
    derivedHashes:   derivedHashes,
    hashNamespaces:  Object.assign({}, opts.hashNamespaces || {}),
    aad:             aadOn,
    rowIdField:      rowIdField,
    schemaVersion:   schemaVersion,
    derivedHashMode: derivedHashMode,
  };
}

// Derived-hash digest width for the keyed (hmac-shake256) mode: 32
// bytes -> 64 hex chars.
var DERIVED_HASH_BYTES = 32;

// Compute the indexed-lookup digest for a derived-hash column.
//   - "salted-sha3" (default): SHA3-512 over <per-deployment salt> + ns
//     + value (128 hex). Deterministic per deployment.
//   - "hmac-shake256": SHAKE256(<vault-sealed MAC key> || ns + value)
//     truncated to 32 bytes (64 hex). The key is a vault-derived secret,
//     NOT a static salt, so an attacker who recovers the salt alone
//     can't correlate two low-entropy plaintexts; the sponge has no
//     length-extension weakness. (b.crypto.hmacSha3 (HMAC-SHA3-512) was
//     considered; SHAKE256(key||msg) is chosen for the fixed-width keyed
//     digest with the same MAC-grade guarantee.) FIPS 202; NIST SP
//     800-185; GDPR Art. 4(5) pseudonymisation; HIPAA 45 CFR 164.514(b).
function _computeDerivedHash(spec, tableMode, ns, normalized) {
  var mode = (spec && spec.mode) || tableMode || "salted-sha3";
  if (mode === "hmac-shake256") {
    var macKey = vault.getDerivedHashMacKey();
    return kdf(Buffer.concat([macKey, Buffer.from(ns + normalized, "utf8")]),
      DERIVED_HASH_BYTES).toString("hex");
  }
  return sha3Hash(vault.getDerivedHashSalt().toString("hex") + ns + normalized);
}

/**
 * @primitive b.cryptoField.computeNamespacedHash
 * @signature b.cryptoField.computeNamespacedHash(ns, value, opts?)
 * @since     0.14.10
 * @compliance gdpr, hipaa
 * @related   b.cryptoField.computeDerived, b.cryptoField.lookupHash
 *
 * Computes a namespaced indexed-lookup digest of `value` for a
 * pseudo-field that is NOT backed by a registered derived-hash column
 * (e.g. the sealed-token FTS index in `b.mailStore.fts`). The caller
 * supplies the full namespace string directly — there is no schema
 * lookup — so the same keyed/salted hash machinery that protects
 * registered derived hashes also covers ad-hoc indexed tokens. This is
 * the canonical entry point: hand-rolling
 * `sha3Hash(vault.getDerivedHashSalt() + ns + value)` at a call site
 * bypasses the keyed-MAC mode (`hmac-shake256` off
 * `vault.getDerivedHashMacKey`) and the per-deployment salt policy.
 *
 * `opts.mode` selects the digest:
 *   - `"salted-sha3"` (default): SHA3-512 over `<salt-hex> + ns + value`
 *     (deterministic per deployment; byte-identical to the legacy
 *     hand-rolled scheme).
 *   - `"hmac-shake256"`: SHAKE256(`<vault MAC key> || ns + value`) — a
 *     keyed MAC so an attacker who recovers the salt alone cannot
 *     correlate two low-entropy plaintexts.
 *
 * `opts.truncateBytes` truncates the hex digest to that many BYTES
 * (the hex string is sliced to `truncateBytes * 2` characters). Throws
 * (config-time / entry-point tier) on an unknown `mode` or a
 * non-positive-integer `truncateBytes` so an operator catches the typo
 * at boot rather than silently indexing under a malformed digest.
 *
 * @opts
 *   mode:          string,   // "salted-sha3" (default) | "hmac-shake256"
 *   truncateBytes: number,   // optional; positive integer byte width to slice to
 *
 * @example
 *   var ns = "bj-mail_messages-body:fts:";
 *   var h = b.cryptoField.computeNamespacedHash(ns, "kubernetes", {
 *     mode: "hmac-shake256", truncateBytes: 8
 *   });
 *   /^[0-9a-f]{16}$/.test(h);   // → true
 *
 *   // Default mode is byte-identical to the legacy salted-sha3 hash.
 *   b.cryptoField.computeNamespacedHash(ns, "kubernetes").length;   // → 128
 */
function computeNamespacedHash(ns, value, opts) {
  opts = opts || {};
  var mode = opts.mode || "salted-sha3";
  if (mode !== "salted-sha3" && mode !== "hmac-shake256") {
    throw new CryptoFieldError("crypto-field/bad-namespaced-hash-mode",
      "computeNamespacedHash: opts.mode must be 'salted-sha3' " +
      "(default) or 'hmac-shake256', got " + JSON.stringify(mode));
  }
  var truncateBytes = opts.truncateBytes;
  if (truncateBytes !== undefined) {
    if (typeof truncateBytes !== "number" || !isFinite(truncateBytes) ||
        truncateBytes <= 0 || Math.floor(truncateBytes) !== truncateBytes) {
      throw new CryptoFieldError("crypto-field/bad-truncate-bytes",
        "computeNamespacedHash: opts.truncateBytes must be a " +
        "positive integer (bytes), got " + JSON.stringify(truncateBytes));
    }
  }
  var hex = _computeDerivedHash({ mode: mode }, mode, ns, String(value));
  if (truncateBytes !== undefined) {
    return hex.slice(0, truncateBytes * 2);
  }
  return hex;
}

/**
 * @primitive b.cryptoField.getSchema
 * @signature b.cryptoField.getSchema(table)
 * @since     0.4.0
 * @related   b.cryptoField.registerTable, b.cryptoField.getSealedFields
 *
 * Returns the registered schema record for `table` — `{ sealedFields,
 * derivedHashes, hashNamespaces }` — or null when the table was never
 * registered. Read-only; mutations to the returned object do not
 * affect future calls (the inner arrays/objects are shared, so
 * operators should treat the result as read-only).
 *
 * @example
 *   b.cryptoField.registerTable("patients", { sealedFields: ["ssn"] });
 *   var schema = b.cryptoField.getSchema("patients");
 *   schema.sealedFields;   // → ["ssn"]
 *
 *   b.cryptoField.getSchema("unknown");   // → null
 */
function getSchema(table) {
  return schemas[table] || null;
}

/**
 * @primitive b.cryptoField.getSealedFields
 * @signature b.cryptoField.getSealedFields(table)
 * @since     0.4.0
 * @related   b.cryptoField.getSchema, b.cryptoField.sealRow
 *
 * Returns the array of sealed column names for `table`, or an empty
 * array when the table is unregistered. Convenience accessor used by
 * storage backends to know which columns to wrap in `vault.seal` on
 * write and `vault.unseal` on read.
 *
 * @example
 *   b.cryptoField.registerTable("patients", { sealedFields: ["ssn", "diagnosis"] });
 *   b.cryptoField.getSealedFields("patients");   // → ["ssn", "diagnosis"]
 *   b.cryptoField.getSealedFields("public");     // → []
 */
function getSealedFields(table) {
  var s = schemas[table];
  return s ? s.sealedFields : [];
}

/**
 * @primitive b.cryptoField.clearForTest
 * @signature b.cryptoField.clearForTest()
 * @since     0.4.0
 * @status    experimental
 * @related   b.cryptoField.registerTable
 *
 * Test-only helper. Drops every entry from the per-table schema
 * registry so a test fixture can re-register tables under different
 * sealed-field declarations between cases. Operator code never calls
 * this — production schemas come from `b.db.init({ schema })` once at
 * boot.
 *
 * @example
 *   b.cryptoField.registerTable("patients", { sealedFields: ["ssn"] });
 *   b.cryptoField.clearForTest();
 *   b.cryptoField.getSchema("patients");   // → null
 */
function clearForTest() {
  for (var k in schemas) delete schemas[k];
}

// ---- Hash helpers ----

// Default hash namespace lookup — falls back to the framework's HASH_PREFIX
// registry, then to a per-table `bj-<table>-<field>:` namespace if neither is
// registered. The namespace prevents rainbow attacks across fields.
function namespaceFor(table, field, registered) {
  if (registered && registered[field]) return registered[field];
  var fieldUpper = field.toUpperCase();
  if (HASH_PREFIX[fieldUpper]) return HASH_PREFIX[fieldUpper];
  return "bj-" + table + "-" + field + ":";
}

/**
 * @primitive b.cryptoField.computeDerived
 * @signature b.cryptoField.computeDerived(table, sourceField, sourceValue)
 * @since     0.4.0
 * @related   b.cryptoField.lookupHash, b.cryptoField.sealRow
 *
 * Computes the derived hash for a (table, sourceField) pair when the
 * schema declares a derived-hash mirror of that source. Returns
 * `{ field, value }` naming the derived column and its hash, or null
 * when no derived hash is declared. Hashes are SHA3 of
 * `vaultSalt + namespace + normalizedValue`, where the per-deployment
 * vault salt prevents cross-deployment correlation and the per-field
 * namespace prevents cross-field rainbow attacks.
 *
 * @example
 *   b.cryptoField.registerTable("users", {
 *     sealedFields: ["email"],
 *     derivedHashes: { emailHash: { from: "email" } }
 *   });
 *   var d = b.cryptoField.computeDerived("users", "email", "alice@example.com");
 *   d.field;          // → "emailHash"
 *   typeof d.value;   // → "string"
 *
 *   b.cryptoField.computeDerived("users", "email", null);   // → null
 */
function computeDerived(table, sourceField, sourceValue) {
  if (sourceValue === undefined || sourceValue === null) return null;
  var s = schemas[table];
  if (!s || !s.derivedHashes) return null;

  for (var derivedField in s.derivedHashes) {
    var spec = s.derivedHashes[derivedField];
    if (spec.from === sourceField) {
      var ns = namespaceFor(table, sourceField, s.hashNamespaces);
      var normalized = spec.normalize ? spec.normalize(sourceValue) : String(sourceValue);
      return { field: derivedField, value: _computeDerivedHash(spec, s.derivedHashMode, ns, normalized) };
    }
  }
  return null;
}

// ---- Unseal-failure rate cap (CWE-307) ----
//
// Opt-in brute-force / decryption-oracle throttle for the unsealRow read
// path. A DB-write attacker who can write `vault:<crafted>` /
// `vault.aad:<crafted>` payloads to sealed columns can force KEM
// decapsulation / AEAD verify on attacker-controlled bytes on every read.
// unsealRow already nulls the field + emits system.crypto.unseal_failed,
// but absent a cap the attacker can hammer the oracle indefinitely and
// only an off-band operator alert rule catches the burst. This adds an
// in-process per-(actor, table, column) sliding-window failure cap: past
// `threshold` failures inside `windowMs`, further unseal attempts for that
// tuple are refused for `cooldownMs` with a typed CryptoFieldRateError and
// a distinct system.crypto.unseal_rate_exceeded audit row.
//
// Default OFF — when no cap is configured, unsealRow behaves exactly as
// before (null-the-field + audit-only). Composes the same timestamp-array
// sliding-window shape used by b.mail.server.rateLimit (_pruneWindow):
// count-based, lazily pruned on read, no background timer.
//
// CWE-307 (Improper Restriction of Excessive Authentication Attempts —
// generalized here to excessive decryption-oracle attempts); OWASP ASVS
// v5 §2.2.1 (anti-automation); NIST SP 800-63B §5.2.2 (rate limiting).
var _rateCap = null;                          // null = disabled
var _rateFailWindows = new Map();             // "actor\x00table\x00column" → [tsMs, ...]
var _rateCooldowns = new Map();               // same key → cooldownUntilMs

// Tuple key. \x00 is not a legal column / table identifier byte and is
// vanishingly unlikely in an actor id, so the join is unambiguous; the
// composite is only ever a Map key (never an object property), so no
// prototype-pollution surface.
function _rateKey(actor, table, column) {
  return String(actor) + "\x00" + table + "\x00" + column;
}

/**
 * @primitive b.cryptoField.configureUnsealRateCap
 * @signature b.cryptoField.configureUnsealRateCap(opts)
 * @since     0.14.20
 * @compliance hipaa, gdpr, pci-dss
 * @related   b.cryptoField.unsealRow, b.cryptoField.clearRateCapForTest
 *
 * Opt into a per-(actor, table, column) cap on sealed-column unseal
 * FAILURES. By default (unconfigured) `unsealRow` only nulls the field
 * and emits `system.crypto.unseal_failed` on a forged-ciphertext read —
 * an attacker who can write `vault:<crafted>` payloads can hammer the
 * KEM-decapsulation / AEAD-verify oracle indefinitely, and only an
 * off-band operator alert rule catches the burst. With a cap configured,
 * once a single tuple accrues `threshold` failures inside `windowMs`,
 * every subsequent `unsealRow` touching that tuple is REFUSED for
 * `cooldownMs` with a `CryptoFieldRateError` and a distinct
 * `system.crypto.unseal_rate_exceeded` audit row, bounding the oracle.
 *
 * Pass `null` (or `{ disabled: true }`) to turn the cap back off. This is
 * a behaviour-changing refusal gate, so it is opt-in: unconfigured
 * deployments keep today's audit-only behaviour with full back-compat.
 * Validation is config-time / entry-point tier — bad `threshold` /
 * `windowMs` / `cooldownMs` THROW so an operator catches the typo at
 * boot rather than silently disabling the cap.
 *
 * CWE-307 (excessive-attempt restriction); OWASP ASVS v5 §2.2.1;
 * NIST SP 800-63B §5.2.2.
 *
 * @opts
 *   threshold: number,    // failures within the window before refusal kicks in (positive int)
 *   windowMs:  number,    // sliding-window width in ms (positive int; default 60000)
 *   cooldownMs: number,   // refusal duration once tripped (positive int; default windowMs)
 *   disabled:  boolean,   // pass true to turn the cap off (same as configureUnsealRateCap(null))
 *   now:       function,  // injected clock returning epoch ms; default Date.now (test seam)
 *   onAudit:   function,  // optional sink({ action, outcome, metadata }) for the rate audit (test seam)
 *
 * @example
 *   b.cryptoField.configureUnsealRateCap({ threshold: 5, windowMs: 60000, cooldownMs: 300000 });
 *   // ...after 5 forged-ciphertext unseal failures for one (actor, table, column):
 *   try { b.cryptoField.unsealRow("patients", forgedRow, "actor-42"); }
 *   catch (e) { e.code; }   // → "crypto-field/unseal-rate-exceeded"
 *
 *   b.cryptoField.configureUnsealRateCap(null);   // → disable again
 */
function configureUnsealRateCap(opts) {
  if (opts === null || opts === undefined || opts.disabled === true) {
    _rateCap = null;
    _rateFailWindows.clear();
    _rateCooldowns.clear();
    return null;
  }
  validateOpts(opts, ["threshold", "windowMs", "cooldownMs", "disabled", "now", "onAudit"],
    "cryptoField.configureUnsealRateCap");
  // threshold is required (no default); presence-guard first, then validate
  // the three positive-int bounds through the shared batch helper so the
  // get-or-default and the bound checks each live in one place.
  if (opts.threshold === undefined) {
    throw new CryptoFieldRateError("crypto-field/bad-threshold",
      "cryptoField.configureUnsealRateCap: opts.threshold is required and must be a positive finite integer");
  }
  numericBounds.requireAllPositiveFiniteIntIfPresent(opts,
    ["threshold", "windowMs", "cooldownMs"],
    "cryptoField.configureUnsealRateCap", CryptoFieldRateError, "crypto-field/bad-rate-cap-opt");
  validateOpts.optionalFunction(opts.now,
    "cryptoField.configureUnsealRateCap: opts.now", CryptoFieldRateError,
    "crypto-field/bad-now");
  validateOpts.optionalFunction(opts.onAudit,
    "cryptoField.configureUnsealRateCap: opts.onAudit", CryptoFieldRateError,
    "crypto-field/bad-on-audit");

  var windowMs = opts.windowMs === undefined ? TIME.minutes(1) : opts.windowMs;
  _rateCap = {
    threshold:  opts.threshold,
    windowMs:   windowMs,
    cooldownMs: opts.cooldownMs === undefined ? windowMs : opts.cooldownMs,
    now:        typeof opts.now === "function" ? opts.now : function () { return Date.now(); },
    onAudit:    typeof opts.onAudit === "function" ? opts.onAudit : null,
  };
  // Re-arming with a fresh config drops any in-flight windows/cooldowns
  // so a config change can't leave a tuple stuck in an old cooldown.
  _rateFailWindows.clear();
  _rateCooldowns.clear();
  return { threshold: _rateCap.threshold, windowMs: _rateCap.windowMs, cooldownMs: _rateCap.cooldownMs };
}

// Emit the distinct rate-exceeded audit. Drop-silent (hot-path sink): a
// throwing audit on the read path must not crash the request that
// triggered it. Honors the injected onAudit test sink when present,
// otherwise routes through the framework audit chain.
function _emitRateAudit(metadata) {
  try {
    if (_rateCap && _rateCap.onAudit) {
      _rateCap.onAudit({ action: "system.crypto.unseal_rate_exceeded", outcome: "denied", metadata: metadata });
      return;
    }
    audit().safeEmit({ action: "system.crypto.unseal_rate_exceeded", outcome: "denied", metadata: metadata });
  } catch (_e) { /* drop-silent — audit best-effort */ }
}

// Pre-unseal gate. Returns true when the tuple is currently in cooldown
// (caller must refuse). No-op (returns false) when the cap is disabled.
// Prunes an expired cooldown lazily so the Map can't grow unbounded.
function _rateInCooldown(actor, table, column) {
  if (!_rateCap) return false;
  var key = _rateKey(actor, table, column);
  var until = _rateCooldowns.get(key);
  if (until === undefined) return false;
  if (_rateCap.now() >= until) {
    _rateCooldowns.delete(key);
    _rateFailWindows.delete(key);
    return false;
  }
  return true;
}

// Post-failure accounting. Records one failure timestamp for the tuple,
// prunes the sliding window, and arms a cooldown when the count reaches
// the threshold. Returns true when this failure tripped the cap (so the
// caller can emit the rate audit exactly once on the transition).
function _rateNoteFailure(actor, table, column) {
  if (!_rateCap) return false;
  var nowMs = _rateCap.now();
  var key = _rateKey(actor, table, column);
  var arr = _rateFailWindows.get(key);
  if (!arr) { arr = []; _rateFailWindows.set(key, arr); }
  // Prune entries older than the window (sliding-window via timestamp
  // array — same shape as b.mail.server.rateLimit._pruneWindow).
  var cutoff = nowMs - _rateCap.windowMs;
  var drop = 0;
  while (drop < arr.length && arr[drop] < cutoff) drop += 1;
  if (drop > 0) arr.splice(0, drop);
  arr.push(nowMs);
  if (arr.length >= _rateCap.threshold) {
    _rateCooldowns.set(key, nowMs + _rateCap.cooldownMs);
    return true;
  }
  return false;
}

/**
 * @primitive b.cryptoField.clearRateCapForTest
 * @signature b.cryptoField.clearRateCapForTest()
 * @since     0.14.20
 * @status    experimental
 * @related   b.cryptoField.configureUnsealRateCap
 *
 * Test-only helper. Disables the unseal-failure rate cap and drops every
 * in-flight sliding-window + cooldown entry so a fixture can re-configure
 * the cap between cases. Operator code never calls this — production
 * deployments configure the cap once at boot.
 *
 * @example
 *   b.cryptoField.configureUnsealRateCap({ threshold: 3 });
 *   b.cryptoField.clearRateCapForTest();
 *   // cap is off again; windows + cooldowns cleared
 */
function clearRateCapForTest() {
  _rateCap = null;
  _rateFailWindows.clear();
  _rateCooldowns.clear();
}

// ---- Row sealing / unsealing ----

/**
 * @primitive b.cryptoField.sealRow
 * @signature b.cryptoField.sealRow(table, row)
 * @since     0.4.0
 * @compliance hipaa, gdpr, pci-dss
 * @related   b.cryptoField.unsealRow, b.cryptoField.eraseRow, b.vault.seal
 *
 * Returns a copy of `row` with every sealed column wrapped in
 * `vault.seal()` and every derived-hash mirror computed from the
 * pre-seal plaintext. The input row is never mutated. `vault.seal` is
 * idempotent — already-sealed values pass through unchanged so
 * round-trips through the storage layer are safe. Derived hashes are
 * computed BEFORE sealing the source so the indexed lookup column
 * captures the plaintext digest.
 *
 * @example
 *   b.cryptoField.registerTable("patients", {
 *     sealedFields: ["ssn"],
 *     derivedHashes: { ssnHash: { from: "ssn" } }
 *   });
 *   var row = { id: 1, name: "Alice", ssn: "123-45-6789" };
 *   var sealed = b.cryptoField.sealRow("patients", row);
 *   String(sealed.ssn).startsWith("vault:");   // → true
 *   typeof sealed.ssnHash;                     // → "string"
 *   row.ssn;                                   // → "123-45-6789" (input untouched)
 */
function sealRow(table, row) {
  if (!row) return row;
  var s = schemas[table];
  if (!s) return row;
  var out = Object.assign({}, row);

  // Compute derived hashes from plaintext source values BEFORE sealing those
  // sources. If a source value arrives already sealed (e.g. from an internal
  // call passing through), unseal it to get the plaintext for hashing.
  if (s.derivedHashes) {
    for (var derivedField in s.derivedHashes) {
      var spec = s.derivedHashes[derivedField];
      var raw = out[spec.from];
      if (raw === undefined || raw === null) continue;
      var plain;
      if (typeof raw === "string" && raw.startsWith(VAULT_PREFIX)) {
        plain = vault.unseal(raw);
      } else if (typeof raw === "string" && vaultAad.isAadSealed(raw)) {
        plain = vaultAad.unseal(raw, _aadParts(s, table, spec.from, out));
      } else {
        plain = raw;
      }
      var ns = namespaceFor(table, spec.from, s.hashNamespaces);
      var normalized = spec.normalize ? spec.normalize(plain) : String(plain);
      out[derivedField] = _computeDerivedHash(spec, s.derivedHashMode, ns, normalized);
    }
  }

  // AAD-bound table requires the row's identity column to
  // be populated BEFORE sealRow runs. Sealing under a placeholder /
  // missing rowId produces ciphertext that no later unseal can open
  // because the AAD on read is computed against the row's actual id.
  if (s.aad) {
    var rowId = out[s.rowIdField];
    if (rowId === undefined || rowId === null || String(rowId).length === 0) {
      throw new CryptoFieldError("crypto-field/seal-row-aad-rowid-missing",
        "cryptoField.sealRow: table '" + table +
        "' is AAD-bound (registerTable({aad:true})); the row's identity " +
        "column '" + s.rowIdField + "' must be populated BEFORE sealRow. " +
        "Generate the primary key first (e.g. uuid / sequence INSERT … RETURNING), " +
        "set row." + s.rowIdField + ", then sealRow.");
    }
  }

  // Seal fields. Plain mode: vault.seal (idempotent — already-sealed
  // values pass through). AAD mode: vault.aad.seal binds the AEAD tag
  // to (table, rowId, column, schemaVersion) — cross-row copy of a
  // ciphertext fails Poly1305 on read.
  for (var i = 0; i < s.sealedFields.length; i++) {
    var field = s.sealedFields[i];
    if (out[field] !== undefined && out[field] !== null) {
      if (s.aad) {
        // Idempotent: already-AAD-sealed values pass through unchanged.
        if (typeof out[field] === "string" && vaultAad.isAadSealed(out[field])) {
          continue;
        }
        out[field] = vaultAad.seal(String(out[field]),
          _aadParts(s, table, field, out));
      } else {
        // allow:seal-without-aad — plain-mode legacy table; operator
        // opts into AAD via registerTable({aad:true})
        out[field] = vault.seal(String(out[field]));
      }
    }
  }

  return out;
}

// _aadParts — build the canonical AAD object for an AAD-bound table.
// Threads (table, rowId, column, schemaVersion) so seal + unseal
// produce the same AAD bytes. Centralized so the seal path and the
// unseal path can never drift.
function _aadParts(schema, table, column, row) {
  return {
    table:         table,
    rowId:         String(row[schema.rowIdField]),
    column:        column,
    schemaVersion: schema.schemaVersion,
  };
}

/**
 * @primitive b.cryptoField.unsealRow
 * @signature b.cryptoField.unsealRow(table, row, actor?)
 * @since     0.4.0
 * @compliance hipaa, gdpr, pci-dss
 * @related   b.cryptoField.sealRow, b.vault.unseal, b.cryptoField.configureUnsealRateCap
 *
 * Returns a copy of `row` with every sealed column unwrapped via
 * `vault.unseal()`. Round-trips with `sealRow`. When `vault.unseal`
 * throws (DB-write attacker forging a `vault:<crafted>` payload to
 * force ML-KEM decapsulation on attacker-controlled bytes), the
 * failure is recorded on the audit chain as
 * `system.crypto.unseal_failed` and the field is replaced with null
 * so downstream code sees "no value" instead of crashing the request.
 * The input row is never mutated.
 *
 * When an unseal-failure rate cap is configured via
 * `configureUnsealRateCap` (default off), repeated forged-ciphertext
 * failures for a single `(actor, table, column)` tuple trip a cooldown:
 * once tripped, this call THROWS `CryptoFieldRateError` and emits a
 * distinct `system.crypto.unseal_rate_exceeded` audit instead of
 * exercising the decryption oracle again (CWE-307). `actor` identifies
 * the caller for that tuple (e.g. session subject / API key id); it
 * defaults to an anonymous bucket when omitted, and is ignored entirely
 * when no cap is configured (full back-compat for the 2-arg call).
 *
 * @example
 *   b.cryptoField.registerTable("patients", { sealedFields: ["ssn"] });
 *   var sealed = b.cryptoField.sealRow("patients", { id: 1, ssn: "123-45-6789" });
 *   var clear  = b.cryptoField.unsealRow("patients", sealed);
 *   clear.ssn;   // → "123-45-6789"
 */
function unsealRow(table, row, actor) {
  if (!row) return row;
  var s = schemas[table];
  if (!s || s.sealedFields.length === 0) return row;
  var out = Object.assign({}, row);
  var capActor = (actor === undefined || actor === null || String(actor).length === 0)
    ? "_anon" : String(actor);

  for (var i = 0; i < s.sealedFields.length; i++) {
    var field = s.sealedFields[i];
    if (out[field]) {
      // Opt-in cap: if this (actor, table, column) tuple is in cooldown
      // from prior forged-ciphertext failures, refuse before touching the
      // decryption oracle again (CWE-307). No-op when the cap is disabled.
      if (_rateInCooldown(capActor, table, field)) {
        _emitRateAudit({
          table: table, field: field, actor: capActor, shape: s.aad ? "aad" : "plain",
          threshold: _rateCap.threshold, windowMs: _rateCap.windowMs, cooldownMs: _rateCap.cooldownMs,
        });
        throw new CryptoFieldRateError("crypto-field/unseal-rate-exceeded",
          "cryptoField.unsealRow: unseal-failure rate cap tripped for (actor, '" + table +
          "', '" + field + "') — refusing further unseal attempts during cooldown");
      }
      var unsealed;
      try {
        // Auto-detect the envelope shape so an AAD-bound table that
        // contains pre-migration plain-vault rows still reads. Read-
        // side migration is lazy; the next sealRow re-emits AAD-bound.
        if (typeof out[field] === "string" && vaultAad.isAadSealed(out[field])) {
          unsealed = vaultAad.unseal(out[field],
            _aadParts(s, table, field, out));
        } else if (typeof out[field] === "string" && out[field].startsWith(VAULT_PREFIX)) {
          unsealed = vault.unseal(out[field]);
        } else {
          // Not a sealed value — pass through.
          unsealed = out[field];
        }
      } catch (e) {
        // A DB-write attacker who can write `vault:<crafted>` /
        // `vault.aad:<crafted>` payloads to sealed columns can force
        // KEM decapsulation / AEAD verify on attacker-controlled
        // bytes via this read path. Surface the failure as a chain
        // row so operators alert on burst patterns; null the field
        // so downstream code sees "no value" instead of crashing the
        // request. AAD-shape failures additionally indicate cross-
        // row copy attempts — the audit metadata flags the shape so
        // operators can write alert rules.
        try {
          audit().safeEmit({
            action:   "system.crypto.unseal_failed",
            outcome:  "failure",
            metadata: {
              table:   table,
              field:   field,
              rowId:   out[s.rowIdField] || out._id || null,
              shape:   s.aad ? "aad" : "plain",
              reason:  (e && e.message) || String(e),
            },
          });
        } catch (_e) { /* drop-silent */ }
        // Opt-in rate cap: account this failure against the (actor,
        // table, column) tuple. When it trips the threshold, arm the
        // cooldown + emit the distinct rate-exceeded audit once on the
        // transition. No-op when the cap is disabled.
        if (_rateNoteFailure(capActor, table, field)) {
          _emitRateAudit({
            table: table, field: field, actor: capActor, shape: s.aad ? "aad" : "plain",
            threshold: _rateCap.threshold, windowMs: _rateCap.windowMs, cooldownMs: _rateCap.cooldownMs,
          });
        }
        unsealed = null;
      }
      // Assign unconditionally. `unsealed` already carries the right value
      // for every branch: the plaintext on success, the original value on
      // the not-actually-sealed pass-through (set above), and `null` on an
      // unseal failure. The failure case MUST null the column so downstream
      // sees "no value" rather than the attacker-crafted `vault:<…>` string
      // (a prior `... ? unsealed : out[field]` guard silently kept the
      // forged ciphertext on failure, defeating the documented defense).
      out[field] = unsealed;
    }
  }

  return out;
}

// ---- Erasure (GDPR Art. 17 / "right to be forgotten") ----
//
// eraseRow(table, row) returns a tombstoned copy of the row: every
// sealed column is replaced with NULL, every derived hash column
// (computed from a sealed source) is replaced with NULL, and a
// `__erasedAt` field is added carrying the erasure timestamp. The
// row itself stays in the table (referential integrity), but the
// sealed cleartext is unrecoverable — even with the vault key, NULL
// decrypts to NULL.
//
// Callers that need the row removed entirely should DELETE; eraseRow
// is for the case where downstream FKs / audit references make
// outright deletion infeasible.

/**
 * @primitive b.cryptoField.eraseRow
 * @signature b.cryptoField.eraseRow(table, row)
 * @since     0.7.10
 * @compliance gdpr, hipaa
 * @related   b.cryptoField.sealRow, b.subject.eraseHard, b.db.vacuumAfterErase
 *
 * Returns a tombstoned copy of `row`: every sealed column NULLed,
 * every derived-hash mirror NULLed, and `__erasedAt` set to a
 * 1-day-bucketed UTC ms timestamp (sub-day timing is intentionally
 * fuzzed to defeat audit-log exfiltration + cross-tenant correlation
 * attacks like "this row was erased 2.3s before that one"). Under
 * regulatory postures whose `POSTURE_DEFAULTS` sets
 * `requireVacuumAfterErase: true` (gdpr / dpdp / pipl-cn / lgpd-br /
 * hipaa), automatically schedules `b.db.vacuumAfterErase({ mode:
 * "full" })` so freed B-tree pages don't linger with sealed-column
 * ciphertext readable from a forensic disk image. The row stays in
 * the table for referential integrity; outright DELETE remains the
 * caller's choice when FKs allow.
 *
 * @example
 *   b.cryptoField.registerTable("patients", {
 *     sealedFields: ["ssn"],
 *     derivedHashes: { ssnHash: { from: "ssn" } }
 *   });
 *   var sealed = b.cryptoField.sealRow("patients", { id: 1, ssn: "123-45-6789" });
 *   var erased = b.cryptoField.eraseRow("patients", sealed);
 *   erased.ssn;        // → null
 *   erased.ssnHash;    // → null
 *   typeof erased.__erasedAt;   // → "number"
 */
function eraseRow(table, row) {
  if (!row) return row;
  var s = schemas[table];
  if (!s) return row;
  var out = Object.assign({}, row);
  // Erase sealed columns — set to null. After this, unsealRow on the
  // erased row returns null for these columns; no key recovers them
  // because there's no ciphertext to decrypt.
  for (var i = 0; i < s.sealedFields.length; i++) {
    out[s.sealedFields[i]] = null;
  }
  // Erase derived hashes — they're indexed lookup mirrors of sealed
  // sources and would otherwise let an attacker reverse the cleartext
  // via dictionary enumeration of the hash.
  if (s.derivedHashes) {
    for (var derivedField in s.derivedHashes) {
      out[derivedField] = null;
    }
  }
  // `__erasedAt` was previously a plaintext UTC ms integer.
  // That value alone fingerprints the erasure event (audit-log
  // exfiltration + cross-tenant correlation: "this row was erased
  // 2.3s before that one"). Bucket the timestamp to a 1-day floor so
  // the event still surfaces "erased before / after this date" for
  // operational use without leaking sub-day timing. Operators who
  // genuinely need the precise instant pull the audit-chain row
  // (which is itself sealed under the audit-sign keypair).
  var dayMs = TIME.days(1);
  out.__erasedAt = Math.floor(Date.now() / dayMs) * dayMs;

  // Under regulatory postures whose POSTURE_DEFAULTS sets
  // requireVacuumAfterErase: true (gdpr / dpdp / pipl-cn / lgpd-br /
  // hipaa), the B-tree index pages freed by the upcoming UPDATE/DELETE
  // would otherwise linger with sealed-column ciphertext readable
  // from a forensic disk image. The cascade-installed posture (set by
  // b.compliance.set) drives an automatic VACUUM after the in-memory
  // tombstone — the actual write happens at the operator's call site,
  // and the framework only schedules the vacuum AFTER the next write.
  // Each erase emits cryptofield.erase.row + (when vacuum runs)
  // db.vacuum_after_erase so the audit trail covers both halves.
  if (_activePosture) {
    var requireVacuum = false;
    try {
      requireVacuum = compliance().postureDefault(
        _activePosture, "requireVacuumAfterErase") === true;
    } catch (_e) { /* compliance lookup best-effort */ }
    if (requireVacuum) {
      try {
        var dbInst = db();
        if (dbInst && typeof dbInst.vacuumAfterErase === "function") {
          dbInst.vacuumAfterErase({ mode: "full" });
        }
      } catch (_vacErr) {
        // VACUUM is best-effort at the eraseRow seam — DB might not be
        // initialized yet (cluster mode, test fixture). The cascade row
        // captures the skip; operators on regulated postures wire the
        // sweep through b.retention which gates erasure on db.init().
        try {
          audit().safeEmit({
            action:  "cryptofield.vacuum.skipped",
            outcome: "failure",
            metadata: {
              posture: _activePosture,
              reason:  (_vacErr && _vacErr.message) ? _vacErr.message : String(_vacErr),
            },
          });
        } catch (_ae) { /* audit best-effort */ }
      }
    }
  }
  return out;
}

// ---- Lookup translation ----

/**
 * @primitive b.cryptoField.lookupHash
 * @signature b.cryptoField.lookupHash(table, field, value)
 * @since     0.4.0
 * @related   b.cryptoField.computeDerived, b.cryptoField.sealRow
 *
 * Translates a plaintext-keyed lookup (e.g. `where({ email: "..." })`)
 * into the derived-hash form (`where({ emailHash: hash(...) })`).
 * Returns `{ field, value }` naming the derived column and its hash,
 * or null when no derived hash is declared for that source field.
 * Sealed columns without a declared derived hash are unindexable —
 * every encryption uses a fresh random nonce, so the ciphertext alone
 * cannot anchor a query.
 *
 * @example
 *   b.cryptoField.registerTable("users", {
 *     sealedFields: ["email"],
 *     derivedHashes: { emailHash: { from: "email" } }
 *   });
 *   var lookup = b.cryptoField.lookupHash("users", "email", "alice@example.com");
 *   lookup.field;          // → "emailHash"
 *   typeof lookup.value;   // → "string"
 *
 *   b.cryptoField.lookupHash("users", "name", "Alice");   // → null (no derived hash)
 */
function lookupHash(table, field, value) {
  var s = schemas[table];
  if (!s || !s.derivedHashes) return null;
  for (var derivedField in s.derivedHashes) {
    var spec = s.derivedHashes[derivedField];
    if (spec.from === field) {
      var ns = namespaceFor(table, field, s.hashNamespaces);
      var normalized = spec.normalize ? spec.normalize(value) : String(value);
      return { field: derivedField, value: _computeDerivedHash(spec, s.derivedHashMode, ns, normalized) };
    }
  }
  return null;
}

/**
 * @primitive b.cryptoField.declareColumnResidency
 * @signature b.cryptoField.declareColumnResidency(table, opts)
 * @since     0.7.27
 * @compliance gdpr
 * @related   b.cryptoField.assertColumnResidency, b.cryptoField.getColumnResidency
 *
 * Declares per-column data residency for `table`. Real GDPR / DPDP /
 * pipl-cn deployments have row-level mixed residency: a `users.name`
 * column may be globally replicable, but `users.addressLine1` must
 * stay in EU storage. At write time
 * (`b.db.set` / `b.db.from(...).insert` / `.update`), the framework
 * consults this registry; if the storage backend's tag doesn't satisfy
 * the column's tag, the write is refused under gdpr / dpdp / pipl-cn /
 * uk-gdpr postures. Throws on bad input (config-time fail-loud).
 *
 * @opts
 *   columnResidency: { [columnName]: "eu" | "us" | "global" | <tag> },
 *
 * @example
 *   b.cryptoField.declareColumnResidency("users", {
 *     columnResidency: {
 *       name:         "global",
 *       addressLine1: "eu",
 *       addressLine2: "eu"
 *     }
 *   });
 *   var got = b.cryptoField.getColumnResidency("users");
 *   got.addressLine1;   // → "eu"
 */
function declareColumnResidency(table, opts) {
  if (typeof table !== "string" || table.length === 0) {
    throw new CryptoFieldError("crypto-field/residency-table-empty",
      "declareColumnResidency: table must be a non-empty string");
  }
  if (opts === null || opts === undefined || typeof opts !== "object" || Array.isArray(opts)) {
    throw new CryptoFieldError("crypto-field/residency-opts-not-object",
      "declareColumnResidency: opts must be a plain object");
  }
  var map = opts.columnResidency;
  if (!map || typeof map !== "object" || Array.isArray(map)) {
    throw new CryptoFieldError("crypto-field/residency-map-not-object",
      "declareColumnResidency: opts.columnResidency must be an object");
  }
  var entry = Object.create(null);
  for (var col in map) {
    if (!Object.prototype.hasOwnProperty.call(map, col)) continue;
    var tag = map[col];
    if (typeof tag !== "string" || tag.length === 0) {
      throw new CryptoFieldError("crypto-field/residency-tag-empty",
        "declareColumnResidency: column '" + col +
        "' residency tag must be a non-empty string");
    }
    entry[col] = tag;
  }
  columnResidency[table] = entry;
  return { table: table, columnResidency: Object.assign({}, entry) };
}

/**
 * @primitive b.cryptoField.getColumnResidency
 * @signature b.cryptoField.getColumnResidency(table)
 * @since     0.7.27
 * @related   b.cryptoField.declareColumnResidency
 *
 * Returns the residency map declared for `table`, or null when the
 * table has no residency declaration. Read-only — does not mutate
 * state. Storage backends use this to inspect residency at the
 * write boundary.
 *
 * @example
 *   b.cryptoField.declareColumnResidency("users", {
 *     columnResidency: { addressLine1: "eu" }
 *   });
 *   b.cryptoField.getColumnResidency("users");      // → { addressLine1: "eu" }
 *   b.cryptoField.getColumnResidency("unknown");    // → null
 */
function getColumnResidency(table) {
  return columnResidency[table] || null;
}

/**
 * @primitive b.cryptoField.assertColumnResidency
 * @signature b.cryptoField.assertColumnResidency(table, row, args)
 * @since     0.7.27
 * @compliance gdpr
 * @related   b.cryptoField.declareColumnResidency, b.cryptoField.declarePerRowResidency
 *
 * Storage-write gate. Storage backends call this with the proposed
 * row before the SQL hits the wire; refusal under regulated postures
 * surfaces a config-time error rather than a silent cross-border leak.
 * Returns null on pass; returns
 * `{ error, table, column, want, got }` on refusal so the storage
 * backend can wrap it in its own error class. Columns tagged "global"
 * or "unrestricted" pass any backend; columns tagged with a region
 * (e.g. "eu") refuse mismatched backends.
 *
 * @opts
 *   backendTag: string,   // tag of the storage backend ("eu" | "us" | "unrestricted")
 *
 * @example
 *   b.cryptoField.declareColumnResidency("users", {
 *     columnResidency: { addressLine1: "eu" }
 *   });
 *   var refusal = b.cryptoField.assertColumnResidency(
 *     "users",
 *     { id: 1, addressLine1: "10 Rue de Rivoli" },
 *     { backendTag: "us" }
 *   );
 *   refusal.error;    // → "column-residency-mismatch"
 *   refusal.column;   // → "addressLine1"
 *   refusal.want;     // → "eu"
 *   refusal.got;      // → "us"
 *
 *   b.cryptoField.assertColumnResidency(
 *     "users",
 *     { id: 1, addressLine1: "10 Rue de Rivoli" },
 *     { backendTag: "eu" }
 *   );   // → null (pass)
 */
function assertColumnResidency(table, row, args) {
  var entry = columnResidency[table];
  if (!entry || !row || !args) return null;
  var backendTag = args.backendTag || "unrestricted";
  for (var col in entry) {
    var want = entry[col];
    if (row[col] === undefined || row[col] === null) continue;
    if (want === "global" || want === "unrestricted") continue;
    if (backendTag === "unrestricted") continue;
    if (backendTag !== want) {
      return {
        error:   "column-residency-mismatch",
        table:   table,
        column:  col,
        want:    want,
        got:     backendTag,
      };
    }
  }
  return null;
}

/**
 * @primitive b.cryptoField.declarePerRowResidency
 * @signature b.cryptoField.declarePerRowResidency(table, opts)
 * @since     0.14.24
 * @compliance gdpr
 * @related   b.cryptoField.getPerRowResidency, b.cryptoField.declareColumnResidency
 *
 * Declares per-ROW data residency for `table`: one plaintext column on
 * each row carries that row's residency tag, and the write gates
 * refuse a tagged row landing on an incompatible backend. The sibling
 * of `declareColumnResidency` — columns answer "which fields are
 * region-bound", rows answer "which region does THIS record belong
 * to" (an EU user's row next to a US user's row in the same table).
 * Local writes (`b.db.from(...).insertOne` / `.update`) enforce the
 * tag against the deployment's `dataResidency` region set under
 * cross-border regulated postures; external writes
 * (`b.externalDb.query`) take the tag per call via
 * `opts.rowResidencyTag` because raw SQL carries no row object. Rows
 * tagged "global" or "unrestricted" pass any backend. Throws on bad
 * input (config-time fail-loud).
 *
 * @opts
 *   residencyColumn: string,    // plaintext column carrying the row's tag
 *   allowedTags:     string[],  // whitelist of valid tag values ("eu", "us", "global", region names)
 *
 * @example
 *   b.cryptoField.declarePerRowResidency("users", {
 *     residencyColumn: "dataRegion",
 *     allowedTags:     ["eu-west-1", "us-east-1", "global"],
 *   });
 *   var spec = b.cryptoField.getPerRowResidency("users");
 *   spec.residencyColumn;   // → "dataRegion"
 */
function declarePerRowResidency(table, opts) {
  validateOpts.requireNonEmptyString(table, "declarePerRowResidency: table",
    CryptoFieldError, "crypto-field/per-row-residency-table-empty");
  validateOpts.requireObject(opts, "declarePerRowResidency",
    CryptoFieldError, "crypto-field/per-row-residency-opts-not-object");
  validateOpts(opts, ["residencyColumn", "allowedTags"], "cryptoField.declarePerRowResidency");
  validateOpts.requireNonEmptyString(opts.residencyColumn,
    "declarePerRowResidency: opts.residencyColumn",
    CryptoFieldError, "crypto-field/per-row-residency-column-invalid");
  if (!Array.isArray(opts.allowedTags) || opts.allowedTags.length === 0) {
    throw new CryptoFieldError("crypto-field/per-row-residency-tags-invalid",
      "declarePerRowResidency: opts.allowedTags must be a non-empty array of tag strings");
  }
  validateOpts.optionalNonEmptyStringArray(opts.allowedTags,
    "declarePerRowResidency: opts.allowedTags",
    CryptoFieldError, "crypto-field/per-row-residency-tag-empty");
  // The residency tag column MUST stay plaintext — the write gate reads
  // it on every INSERT / UPDATE before sealRow, and reads return it
  // verbatim. A sealed residency column would be ciphertext the gate
  // can't compare and reads can't surface. Refuse the misconfiguration
  // at declaration time when the table's sealed-field set is already
  // known (registration order permitting).
  var sealed = getSealedFields(table);
  if (Array.isArray(sealed) && sealed.indexOf(opts.residencyColumn) !== -1) {
    throw new CryptoFieldError("crypto-field/per-row-residency-sealed-conflict",
      "declarePerRowResidency: residencyColumn '" + opts.residencyColumn +
      "' is a sealed field on table '" + table + "' — the residency tag must " +
      "stay plaintext so the write gate can read it. Choose a non-sealed column");
  }
  perRowResidency[table] = {
    residencyColumn: opts.residencyColumn,
    allowedTags:     opts.allowedTags.slice(),
  };
  return {
    table:           table,
    residencyColumn: opts.residencyColumn,
    allowedTags:     opts.allowedTags.slice(),
  };
}

/**
 * @primitive b.cryptoField.getPerRowResidency
 * @signature b.cryptoField.getPerRowResidency(table)
 * @since     0.14.24
 * @related   b.cryptoField.declarePerRowResidency
 *
 * Returns the per-row residency spec declared for `table`
 * (`{ residencyColumn, allowedTags }`), or null when the table has no
 * declaration. Read-only — storage backends call this at the write
 * boundary to decide whether the row-residency gate applies.
 *
 * @example
 *   b.cryptoField.declarePerRowResidency("users", {
 *     residencyColumn: "dataRegion",
 *     allowedTags:     ["eu-west-1", "global"],
 *   });
 *   b.cryptoField.getPerRowResidency("users").allowedTags;   // → ["eu-west-1", "global"]
 *   b.cryptoField.getPerRowResidency("unknown");             // → null
 */
function getPerRowResidency(table) {
  var spec = perRowResidency[table];
  if (!spec) return null;
  return { residencyColumn: spec.residencyColumn, allowedTags: spec.allowedTags.slice() };
}

/**
 * @primitive b.cryptoField.declarePerRowKey
 * @signature b.cryptoField.declarePerRowKey(table, opts)
 * @since     0.7.27
 * @compliance gdpr, hipaa
 * @related   b.cryptoField.materializePerRowKey, b.cryptoField.destroyPerRowKey, b.subject.eraseHard
 *
 * Opts a table into per-row keying (K_row crypto-shred substrate).
 * After registration, every INSERT generates a fresh K_row and stores
 * it sealed in `_blamejs_per_row_keys (table, rowId, wrapped)`. AAD on
 * the K_row binds (table, rowId, info-label) — copy-row attacks fail
 * Poly1305 verification. `b.subject.eraseHard(subjectId)` deletes the
 * per-row key entries for the subject's rows; WAL / replica residual
 * ciphertext becomes mathematically undecryptable because K_row is
 * gone everywhere it ever lived. Throws on bad input (config-time
 * fail-loud).
 *
 * @opts
 *   keySize: number,   // bytes; default 32 (XChaCha20-Poly1305 key length); minimum 16
 *   info:    string,   // HKDF info label; default "blamejs-per-row-key:<table>"
 *
 * @example
 *   var spec = b.cryptoField.declarePerRowKey("orders", {
 *     keySize: 32,
 *     info:    "blamejs-per-row-key:orders"
 *   });
 *   spec.keySize;                          // → 32
 *   b.cryptoField.hasPerRowKey("orders");  // → true
 */
function declarePerRowKey(table, opts) {
  if (typeof table !== "string" || table.length === 0) {
    throw new CryptoFieldError("crypto-field/per-row-key-table-empty",
      "declarePerRowKey: table must be a non-empty string");
  }
  opts = opts || {};
  var keySize = opts.keySize === undefined ? 32 : opts.keySize; // XChaCha20-Poly1305 key length in bytes
  if (typeof keySize !== "number" || !isFinite(keySize) ||
      keySize < 16 || Math.floor(keySize) !== keySize) { // minimum AES-128 key length in bytes
    throw new CryptoFieldError("crypto-field/per-row-key-bad-size",
      "declarePerRowKey: opts.keySize must be an integer >= 16 (bytes)");
  }
  var info = opts.info || ("blamejs-per-row-key:" + table);
  if (typeof info !== "string" || info.length === 0) {
    throw new CryptoFieldError("crypto-field/per-row-key-info-empty",
      "declarePerRowKey: opts.info must be a non-empty string");
  }
  perRowKeyTables[table] = { keySize: keySize, info: info };
  return { table: table, keySize: keySize, info: info };
}

/**
 * @primitive b.cryptoField.hasPerRowKey
 * @signature b.cryptoField.hasPerRowKey(table)
 * @since     0.7.27
 * @related   b.cryptoField.declarePerRowKey
 *
 * Returns `true` when `table` has been registered for per-row keying
 * via `declarePerRowKey`, `false` otherwise. Storage backends gate
 * the K_row materialize/destroy paths through this check.
 *
 * @example
 *   b.cryptoField.hasPerRowKey("orders");   // → false
 *   b.cryptoField.declarePerRowKey("orders", { keySize: 32 });
 *   b.cryptoField.hasPerRowKey("orders");   // → true
 */
function hasPerRowKey(table) {
  return !!perRowKeyTables[table];
}

/**
 * @primitive b.cryptoField.materializePerRowKey
 * @signature b.cryptoField.materializePerRowKey(table, rowId, dbHandle)
 * @since     0.7.27
 * @compliance gdpr, hipaa
 * @related   b.cryptoField.declarePerRowKey, b.cryptoField.destroyPerRowKey
 *
 * Derive-and-store: called by the storage backend on INSERT. Generates
 * `K_row = SHAKE256(vaultSalt + table + rowId + info, keySize)`, seals
 * it via `vault.seal`, and inserts into `_blamejs_per_row_keys`.
 * Returns the unwrapped K_row Buffer for the caller to use to encrypt
 * sealed columns under the row-scoped key. Idempotent on UPSERT — if
 * a K_row already exists for (table, rowId), returns the unwrapped
 * existing key. The AAD-bound envelope rejects copy-row attacks: a
 * wrapped K_row pasted under a different rowId fails Poly1305
 * verification at unseal time.
 *
 * @example
 *   b.cryptoField.declarePerRowKey("orders", { keySize: 32 });
 *   var dbHandle = b.db.handle();
 *   var kRow = b.cryptoField.materializePerRowKey("orders", "ord-42", dbHandle);
 *   Buffer.isBuffer(kRow);   // → true
 *   kRow.length;             // → 32
 *
 *   // Idempotent — second call returns the same key.
 *   var kRowAgain = b.cryptoField.materializePerRowKey("orders", "ord-42", dbHandle);
 *   kRow.equals(kRowAgain);  // → true
 */
function materializePerRowKey(table, rowId, dbHandle) {
  var spec = perRowKeyTables[table];
  if (!spec) return null;
  if (!dbHandle || typeof dbHandle.prepare !== "function") {
    throw new CryptoFieldError("crypto-field/materialize-per-row-key-no-db",
      "materializePerRowKey: dbHandle (b.db) is required");
  }
  // Existing key? Re-use to support idempotent UPSERTs.
  var existing = dbHandle.prepare(
    'SELECT wrappedKey FROM "_blamejs_per_row_keys" WHERE tableName = ? AND rowId = ?'
  ).get(table, rowId);
  if (existing) {
    return vault.unseal(existing.wrappedKey);
  }
  // Derive K_row from the table-level vault key salt + rowId via
  // SHAKE256 expand. This is a one-shot derivation (HKDF-shaped) that
  // matches the framework's PQC-first kdf — no HMAC-SHA3 dependency.
  var saltHex = vault.getDerivedHashSalt().toString("hex");
  var ikm = Buffer.from(saltHex + ":" + table + ":" + rowId + ":" + spec.info, "utf8");
  var kRow = kdf(ikm, spec.keySize);
  // allow:seal-without-aad — per-row K_row wrap; row identity is the
  // K_row KDF input, not the AEAD AAD on the wrap. Copy-attacks fail
  // because the wrapped K_row only decrypts data sealed under it.
  var sealed = vault.seal(kRow.toString("base64"));
  dbHandle.prepare(
    'INSERT INTO "_blamejs_per_row_keys" (tableName, rowId, wrappedKey, createdAt) ' +
    'VALUES (?, ?, ?, ?)'
  ).run(table, rowId, sealed, Date.now());
  return kRow;
}

/**
 * @primitive b.cryptoField.destroyPerRowKey
 * @signature b.cryptoField.destroyPerRowKey(table, rowId, dbHandle)
 * @since     0.7.27
 * @compliance gdpr, hipaa
 * @related   b.cryptoField.materializePerRowKey, b.subject.eraseHard
 *
 * Crypto-shred: drops the per-row K_row entry from
 * `_blamejs_per_row_keys`. Called by `b.subject.eraseHard` for each
 * row mapped to the erased subject. Returns
 * `{ destroyed: <rowsAffected> }`. After destruction, any WAL /
 * replica residual ciphertext for the row is mathematically
 * undecryptable — even with the vault root key — because K_row is
 * gone everywhere it ever lived. No-op when the table is not
 * registered for per-row keying.
 *
 * @example
 *   b.cryptoField.declarePerRowKey("orders", { keySize: 32 });
 *   var dbHandle = b.db.handle();
 *   b.cryptoField.materializePerRowKey("orders", "ord-42", dbHandle);
 *
 *   var result = b.cryptoField.destroyPerRowKey("orders", "ord-42", dbHandle);
 *   result.destroyed;   // → 1
 *
 *   // Subsequent destroy is a no-op.
 *   b.cryptoField.destroyPerRowKey("orders", "ord-42", dbHandle).destroyed;   // → 0
 */
function destroyPerRowKey(table, rowId, dbHandle) {
  if (!perRowKeyTables[table]) return { destroyed: 0 };
  if (!dbHandle || typeof dbHandle.prepare !== "function") {
    throw new CryptoFieldError("crypto-field/destroy-per-row-key-no-db",
      "destroyPerRowKey: dbHandle (b.db) is required");
  }
  var result = dbHandle.prepare(
    'DELETE FROM "_blamejs_per_row_keys" WHERE tableName = ? AND rowId = ?'
  ).run(table, rowId);
  return { destroyed: (result && result.changes) || 0 };
}

/**
 * @primitive b.cryptoField.clearResidencyForTest
 * @signature b.cryptoField.clearResidencyForTest()
 * @since     0.7.27
 * @status    experimental
 * @related   b.cryptoField.declareColumnResidency, b.cryptoField.declarePerRowKey
 *
 * Test-only helper. Drops every entry from the per-column residency
 * registry, the per-row residency registry, and the per-row-key
 * registry so a test fixture can re-declare them between cases.
 * Operator code never calls this — production declarations come from
 * `b.db.init({ schema })` once at boot.
 *
 * @example
 *   b.cryptoField.declareColumnResidency("users", {
 *     columnResidency: { addressLine1: "eu" }
 *   });
 *   b.cryptoField.clearResidencyForTest();
 *   b.cryptoField.getColumnResidency("users");   // → null
 */
function clearResidencyForTest() {
  for (var t in columnResidency) delete columnResidency[t];
  for (var u in perRowKeyTables) delete perRowKeyTables[u];
  for (var v in perRowResidency) delete perRowResidency[v];
}

module.exports = {
  registerTable:    registerTable,
  getSchema:        getSchema,
  getSealedFields:  getSealedFields,
  sealRow:          sealRow,
  unsealRow:        unsealRow,
  configureUnsealRateCap: configureUnsealRateCap,
  clearRateCapForTest:    clearRateCapForTest,
  CryptoFieldRateError:   CryptoFieldRateError,
  // _aadParts — the column-AAD builder the seal/unseal path uses. Exported
  // (internal) so the vault-key rotation pipeline reconstructs the IDENTICAL
  // AAD tuple a cell was sealed under — one source of truth, no drift
  // between the seal side and the rotate side.
  _aadParts:        _aadParts,
  // Doc-shaped aliases — operators / tests preparing a JS document
  // object (vs. a SQL row) reach for sealDoc / unsealDoc naming. Same
  // function, identical shape, returns a new object (input untouched).
  sealDoc:          sealRow,
  unsealDoc:        unsealRow,
  eraseRow:         eraseRow,
  applyPosture:     applyPosture,
  getActivePosture: getActivePosture,
  computeDerived:   computeDerived,
  computeNamespacedHash: computeNamespacedHash,
  lookupHash:       lookupHash,
  clearForTest:     clearForTest,
  declareColumnResidency: declareColumnResidency,
  getColumnResidency:     getColumnResidency,
  assertColumnResidency:  assertColumnResidency,
  declarePerRowResidency: declarePerRowResidency,
  getPerRowResidency:     getPerRowResidency,
  declarePerRowKey:       declarePerRowKey,
  hasPerRowKey:           hasPerRowKey,
  materializePerRowKey:   materializePerRowKey,
  destroyPerRowKey:       destroyPerRowKey,
  clearResidencyForTest:  clearResidencyForTest,
};
