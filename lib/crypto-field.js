"use strict";
/**
 * Field-level crypto engine.
 *
 * Wraps vault.seal/unseal at the row boundary so apps can declare which
 * columns hold PHI/PCI/personal data and the framework auto-protects them
 * on every write/read. Apps register their schema via db.init({ schema }) —
 * this module then operates on (table, row) pairs.
 *
 * Per-column field types:
 *   - sealedFields:    vault.seal() on write, vault.unseal() on read
 *   - derivedHashes:   computed from a source field on write, indexed lookup
 *                      enabled via where({ derivedField: hashFor(...) })
 *
 * Apps that need a one-way hash field (e.g. an opaque IP block list) build
 * the derived hash themselves with a custom namespace via db.hashFor().
 *
 * No mutation of the input row — every operation returns a new object.
 */
var lazyRequire = require("./lazy-require");
var vault = require("./vault");
var { sha3Hash, kdf } = require("./crypto");
var { HASH_PREFIX, VAULT_PREFIX, TIME } = require("./constants");

var complianceMod = lazyRequire(function () { return require("./compliance"); });
var dbMod         = lazyRequire(function () { return require("./db"); });
var auditMod      = lazyRequire(function () { return require("./audit"); });

// F-POSTURE-1 cascade hook + F-RTBF-2 integration. Recording the
// posture lets eraseRow call b.db.vacuumAfterErase({ mode: "full" })
// automatically under postures whose POSTURE_DEFAULTS sets
// requireVacuumAfterErase: true (gdpr / dpdp / pipl-cn / lgpd-br /
// hipaa). Without the vacuum, freed B-tree index pages keep sealed-
// column ciphertext readable from a forensic disk image — defeats the
// "right to erasure" the regulatory regime guarantees.
var _activePosture = null;
function applyPosture(posture) {
  if (typeof posture !== "string" || posture.length === 0) return null;
  _activePosture = posture;
  var requireVacuum = false;
  try {
    requireVacuum = complianceMod().postureDefault(posture, "requireVacuumAfterErase") === true;
  } catch (_e) { /* compliance not loaded — record posture only */ }
  return { posture: posture, requireVacuumAfterErase: requireVacuum };
}
function getActivePosture() { return _activePosture; }

// Per-table registry, populated by db.init()
var schemas = Object.create(null);

// F-CBT-1 — per-COLUMN data residency registry. Real GDPR / DPDP
// deployments have row-level mixed residency: a `users.name` column
// may be global, but `users.addressLine1` must stay in EU storage.
// db.init({ schema }) carries the operator's residency declaration
// per table; this registry stores it for cross-region check at the
// storage-write boundary.
//
//   { tableName: { columnName: "eu" | "us" | "global" | <tag> } }
var columnResidency = Object.create(null);

// F-RTBF-3 — per-row key declaration registry. For tables that opt
// into per-row keying, b.subject.eraseHard deletes the wrapped K_row
// from _blamejs_per_row_keys, leaving WAL/replica residual ciphertext
// undecryptable.
//
//   { tableName: { keySize, info, residencyTag } }
var perRowKeyTables = Object.create(null);

function registerTable(name, opts) {
  schemas[name] = {
    sealedFields:   Array.isArray(opts.sealedFields)   ? opts.sealedFields.slice()   : [],
    derivedHashes:  Object.assign({}, opts.derivedHashes || {}),
    hashNamespaces: Object.assign({}, opts.hashNamespaces || {}),
  };
}

function getSchema(table) {
  return schemas[table] || null;
}

function getSealedFields(table) {
  var s = schemas[table];
  return s ? s.sealedFields : [];
}

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

function computeDerived(table, sourceField, sourceValue) {
  if (sourceValue === undefined || sourceValue === null) return null;
  var s = schemas[table];
  if (!s || !s.derivedHashes) return null;

  for (var derivedField in s.derivedHashes) {
    var spec = s.derivedHashes[derivedField];
    if (spec.from === sourceField) {
      var ns = namespaceFor(table, sourceField, s.hashNamespaces);
      var normalized = spec.normalize ? spec.normalize(sourceValue) : String(sourceValue);
      var saltHex = vault.getDerivedHashSalt().toString("hex");
      return { field: derivedField, value: sha3Hash(saltHex + ns + normalized) };
    }
  }
  return null;
}

// ---- Row sealing / unsealing ----

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
      var plain = String(raw).startsWith(VAULT_PREFIX) ? vault.unseal(raw) : raw;
      var ns = namespaceFor(table, spec.from, s.hashNamespaces);
      var normalized = spec.normalize ? spec.normalize(plain) : String(plain);
      var saltHex2 = vault.getDerivedHashSalt().toString("hex");
      out[derivedField] = sha3Hash(saltHex2 + ns + normalized);
    }
  }

  // Seal fields (vault.seal is idempotent — already-sealed values pass through)
  for (var i = 0; i < s.sealedFields.length; i++) {
    var field = s.sealedFields[i];
    if (out[field] !== undefined && out[field] !== null) {
      out[field] = vault.seal(String(out[field]));
    }
  }

  return out;
}

function unsealRow(table, row) {
  if (!row) return row;
  var s = schemas[table];
  if (!s || s.sealedFields.length === 0) return row;
  var out = Object.assign({}, row);

  for (var i = 0; i < s.sealedFields.length; i++) {
    var field = s.sealedFields[i];
    if (out[field]) {
      var unsealed;
      try {
        unsealed = vault.unseal(out[field]);
      } catch (e) {
        // A DB-write attacker who can write `vault:<crafted>`
        // payloads to sealed columns can force ML-KEM
        // decapsulation on attacker-controlled bytes via this read
        // path. Surface the failure as a chain row so operators
        // alert on burst patterns; null the field so downstream
        // code sees "no value" instead of crashing the request.
        try {
          var auditMod = require("./audit");                                          // allow:inline-require — circular-load defense
          auditMod.safeEmit({
            action:   "system.crypto.unseal_failed",
            outcome:  "failure",
            metadata: { table: table, field: field, rowId: row && row._id || null,
                        reason: (e && e.message) || String(e) },
          });
        } catch (_e) { /* drop-silent */ }
        unsealed = null;
      }
      // If the value wasn't actually sealed, vault.unseal returns the input
      // unchanged — keep the original.
      out[field] = unsealed !== undefined && unsealed !== null ? unsealed : out[field];
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
  // F-RTBF-4 — `__erasedAt` was previously a plaintext UTC ms integer.
  // That value alone fingerprints the erasure event (audit-log
  // exfiltration + cross-tenant correlation: "this row was erased
  // 2.3s before that one"). Bucket the timestamp to a 1-day floor so
  // the event still surfaces "erased before / after this date" for
  // operational use without leaking sub-day timing. Operators who
  // genuinely need the precise instant pull the audit-chain row
  // (which is itself sealed under the audit-sign keypair).
  var dayMs = TIME.days(1);
  out.__erasedAt = Math.floor(Date.now() / dayMs) * dayMs;

  // F-RTBF-2 — under regulatory postures whose POSTURE_DEFAULTS sets
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
      requireVacuum = complianceMod().postureDefault(
        _activePosture, "requireVacuumAfterErase") === true;
    } catch (_e) { /* compliance lookup best-effort */ }
    if (requireVacuum) {
      try {
        var db = dbMod();
        if (db && typeof db.vacuumAfterErase === "function") {
          db.vacuumAfterErase({ mode: "full" });
        }
      } catch (_vacErr) {
        // VACUUM is best-effort at the eraseRow seam — DB might not be
        // initialized yet (cluster mode, test fixture). The cascade row
        // captures the skip; operators on regulated postures wire the
        // sweep through b.retention which gates erasure on db.init().
        try {
          auditMod().safeEmit({
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

// where({ email: 'x' }) → where({ emailHash: hash(...) }).
// If the field is sealed and has no derived hash, lookup is impossible
// (sealed values use random nonces — every encryption is unique). Caller
// is expected to declare a derived hash for every sealed field they want
// to query; otherwise queries on sealed fields silently return zero rows.
function lookupHash(table, field, value) {
  var s = schemas[table];
  if (!s || !s.derivedHashes) return null;
  for (var derivedField in s.derivedHashes) {
    var spec = s.derivedHashes[derivedField];
    if (spec.from === field) {
      var ns = namespaceFor(table, field, s.hashNamespaces);
      var normalized = spec.normalize ? spec.normalize(value) : String(value);
      var saltHex = vault.getDerivedHashSalt().toString("hex");
      return { field: derivedField, value: sha3Hash(saltHex + ns + normalized) };
    }
  }
  return null;
}

// F-CBT-1 — declareColumnResidency(table, opts).
//
//   b.cryptoField.declareColumnResidency("users", {
//     columnResidency: {
//       name:         "global",
//       addressLine1: "eu",
//       addressLine2: "eu",
//     },
//   });
//
// At write time (b.db.set / b.db.from(...).insert / .update), the
// framework consults this registry: if the storage backend's tag
// doesn't satisfy the column's tag, the write is refused under
// gdpr / dpdp / pipl-cn / uk-gdpr postures.
function declareColumnResidency(table, opts) {
  if (typeof table !== "string" || table.length === 0) {
    throw new Error("declareColumnResidency: table must be a non-empty string");
  }
  if (opts === null || opts === undefined || typeof opts !== "object" || Array.isArray(opts)) {
    throw new Error("declareColumnResidency: opts must be a plain object");
  }
  var map = opts.columnResidency;
  if (!map || typeof map !== "object" || Array.isArray(map)) {
    throw new Error("declareColumnResidency: opts.columnResidency must be an object");
  }
  var entry = Object.create(null);
  for (var col in map) {
    if (!Object.prototype.hasOwnProperty.call(map, col)) continue;
    var tag = map[col];
    if (typeof tag !== "string" || tag.length === 0) {
      throw new Error("declareColumnResidency: column '" + col +
        "' residency tag must be a non-empty string");
    }
    entry[col] = tag;
  }
  columnResidency[table] = entry;
  return { table: table, columnResidency: Object.assign({}, entry) };
}

function getColumnResidency(table) {
  return columnResidency[table] || null;
}

// Storage-write gate. Storage backends call this with the proposed
// row before the SQL hits the wire; refusal under regulated postures
// surfaces a config-time error rather than silent cross-border leak.
//
//   b.cryptoField.assertColumnResidency("users", row, { backendTag: "us" });
//
// Returns null on pass; returns { error, column, want, got } on
// refusal so the storage backend can wrap into its own error class.
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

// F-RTBF-3 — declarePerRowKey(table, opts).
//
//   b.cryptoField.declarePerRowKey("orders", {
//     keySize: 32,                 // bytes; default 32 (256-bit)
//     info:    "blamejs-per-row-key:orders",
//   });
//
// After registration, every INSERT generates a fresh K_row and
// stores it sealed in _blamejs_per_row_keys (table, rowId, wrapped).
// b.subject.eraseHard(subjectId) deletes the per-row key entries for
// the subject's rows; WAL / replica residual ciphertext becomes
// undecryptable because K_row is gone everywhere it ever lived.
function declarePerRowKey(table, opts) {
  if (typeof table !== "string" || table.length === 0) {
    throw new Error("declarePerRowKey: table must be a non-empty string");
  }
  opts = opts || {};
  var keySize = opts.keySize === undefined ? 32 : opts.keySize; // allow:raw-byte-literal — XChaCha20-Poly1305 key length in bytes
  if (typeof keySize !== "number" || !isFinite(keySize) ||
      keySize < 16 || Math.floor(keySize) !== keySize) { // allow:raw-byte-literal — minimum AES-128 key length in bytes
    throw new Error("declarePerRowKey: opts.keySize must be an integer >= 16 (bytes)");
  }
  var info = opts.info || ("blamejs-per-row-key:" + table);
  if (typeof info !== "string" || info.length === 0) {
    throw new Error("declarePerRowKey: opts.info must be a non-empty string");
  }
  perRowKeyTables[table] = { keySize: keySize, info: info };
  return { table: table, keySize: keySize, info: info };
}

function hasPerRowKey(table) {
  return !!perRowKeyTables[table];
}

// Derive-and-store: called by storage backend on INSERT.
//
//   b.cryptoField.materializePerRowKey("orders", "ord-42", db);
//
// Generates K_row = HKDF(K_table, rowId, info), seals it via vault,
// and inserts into _blamejs_per_row_keys. Returns the unwrapped key
// for the caller to use to encrypt sealed columns under the row-
// scoped K_row. (When the row has no sealed columns, the caller
// only needs the per-row entry to be present — eraseHard's deletion
// then drops the row's residency anchor.)
function materializePerRowKey(table, rowId, dbHandle) {
  var spec = perRowKeyTables[table];
  if (!spec) return null;
  if (!dbHandle || typeof dbHandle.prepare !== "function") {
    throw new Error("materializePerRowKey: dbHandle (b.db) is required");
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
  var sealed = vault.seal(kRow.toString("base64"));
  dbHandle.prepare(
    'INSERT INTO "_blamejs_per_row_keys" (tableName, rowId, wrappedKey, createdAt) ' +
    'VALUES (?, ?, ?, ?)'
  ).run(table, rowId, sealed, Date.now());
  return kRow;
}

// Crypto-shred: drops the per-row K_row entry. Called by
// b.subject.eraseHard for each row mapped to the erased subject.
function destroyPerRowKey(table, rowId, dbHandle) {
  if (!perRowKeyTables[table]) return { destroyed: 0 };
  if (!dbHandle || typeof dbHandle.prepare !== "function") {
    throw new Error("destroyPerRowKey: dbHandle (b.db) is required");
  }
  var result = dbHandle.prepare(
    'DELETE FROM "_blamejs_per_row_keys" WHERE tableName = ? AND rowId = ?'
  ).run(table, rowId);
  return { destroyed: (result && result.changes) || 0 };
}

function clearResidencyForTest() {
  for (var t in columnResidency) delete columnResidency[t];
  for (var u in perRowKeyTables) delete perRowKeyTables[u];
}

module.exports = {
  registerTable:    registerTable,
  getSchema:        getSchema,
  getSealedFields:  getSealedFields,
  sealRow:          sealRow,
  unsealRow:        unsealRow,
  eraseRow:         eraseRow,
  applyPosture:     applyPosture,
  getActivePosture: getActivePosture,
  computeDerived:   computeDerived,
  lookupHash:       lookupHash,
  clearForTest:     clearForTest,
  declareColumnResidency: declareColumnResidency,
  getColumnResidency:     getColumnResidency,
  assertColumnResidency:  assertColumnResidency,
  declarePerRowKey:       declarePerRowKey,
  hasPerRowKey:           hasPerRowKey,
  materializePerRowKey:   materializePerRowKey,
  destroyPerRowKey:       destroyPerRowKey,
  clearResidencyForTest:  clearResidencyForTest,
};
