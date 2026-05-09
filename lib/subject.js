"use strict";
/**
 * Data subject rights primitives — GDPR Articles 15–22, AU Privacy Act
 * Privacy Act Review (right to erasure), and HIPAA §164.524.
 *
 * App schema declares per-table `subjectField` (the column that points to
 * the subject) and `personalDataCategories` (semantic tag for RoPA). This
 * module then walks every table that knows about a given subject without
 * the app having to plumb subject IDs through repository code.
 *
 * Public API:
 *   subject.export(subjectId, opts) → { tableName: [unsealed rows] }
 *   subject.rectify(subjectId, { table, id, changes, reason })
 *   subject.erase(subjectId, { reason, acknowledgements })
 *   subject.restrict(subjectId, { on, reason })
 *   subject.recordObjection(subjectId, { purpose, reason })
 *   subject.isRestricted(subjectId) → boolean
 *
 * Erasure model: physical row deletion with the audit chain preserved
 * (the subject's data rows are gone; the audit_log entries about them
 * remain hash-linked). This satisfies GDPR Art. 17 in the strict sense
 * (subject data is erased) at the cost of the more granular
 * cryptographic-erasure property (per-subject key destruction) the spec
 * aspires to — that variant requires per-subject derivation keys, which
 * the framework does not currently maintain.
 */
var { sha3Hash } = require("./crypto");
var cryptoField = require("./crypto-field");
var audit = require("./audit");
var cluster = require("./cluster");
var lazyRequire = require("./lazy-require");

var db = lazyRequire(function () { return require("./db"); });
var legalHold = lazyRequire(function () { return require("./legal-hold"); });

// Required acknowledgements before subject.erase will run. Operator must
// explicitly attest each one to confirm no statutory retention or active
// litigation hold blocks the deletion.
var REQUIRED_ERASE_ACKS = ["no-litigation-hold", "no-statutory-retention-required"];

// ---- Export (Art. 15, Art. 20) ----

function exportData(subjectId, opts) {
  if (!subjectId) throw new Error("subject.export requires a subjectId");
  opts = opts || {};
  var include = opts.include || "all";

  var tables = db()._getSubjectTables();
  if (tables.length === 0) {
    return _writeAudit("subject.export", subjectId, "success", { reason: opts.reason || null }, {});
  }

  var dump = {};
  for (var i = 0; i < tables.length; i++) {
    var t = tables[i];
    if (include !== "all" && include.indexOf(t.name) === -1) continue;

    // Look up via derivedHash if the subjectField is sealed; otherwise raw equality.
    var rows = _findRowsForSubject(t.name, t.subjectField, subjectId);
    if (rows.length > 0) dump[t.name] = rows;
  }

  _writeAudit("subject.export", subjectId, "success", { reason: opts.reason || null, tables: Object.keys(dump) });
  return dump;
}

function _findRowsForSubject(tableName, subjectField, subjectId) {
  var hash = db().hashFor(tableName, subjectField, subjectId);
  if (hash) {
    // The schema has a derived hash for the subjectField — look up via that
    var derivedFieldName = _getDerivedFieldName(tableName, subjectField);
    if (derivedFieldName) {
      var pred = {};
      pred[derivedFieldName] = hash;
      return db().from(tableName).where(pred).all();
    }
  }
  // No derived hash — assume subjectField is raw, do direct equality
  var rawPred = {};
  rawPred[subjectField] = subjectId;
  return db().from(tableName).where(rawPred).all();
}

function _getDerivedFieldName(tableName, sourceField) {
  var schema = cryptoField.getSchema(tableName);
  if (!schema || !schema.derivedHashes) return null;
  for (var derivedField in schema.derivedHashes) {
    if (schema.derivedHashes[derivedField].from === sourceField) return derivedField;
  }
  return null;
}

// ---- Rectify (Art. 16) ----

function rectify(subjectId, opts) {
  cluster.requireLeader();
  if (!subjectId) throw new Error("subject.rectify requires a subjectId");
  if (!opts || !opts.table || !opts.id || !opts.changes) {
    throw new Error("subject.rectify requires { table, id, changes }");
  }

  // Read current values for audit metadata
  var before = db().from(opts.table).where({ _id: opts.id }).first();
  if (!before) {
    _writeAudit("subject.rectify", subjectId, "failure", {
      reason:     "row not found",
      table:      opts.table,
      rowId:      opts.id,
      requestReason: opts.reason,
    });
    throw new Error("subject.rectify: row not found in '" + opts.table + "' with _id '" + opts.id + "'");
  }

  var changedKeys = Object.keys(opts.changes);
  var beforeValues = {};
  for (var i = 0; i < changedKeys.length; i++) beforeValues[changedKeys[i]] = before[changedKeys[i]];

  var ok = db().from(opts.table).where({ _id: opts.id }).updateOne(opts.changes);

  _writeAudit("subject.rectify", subjectId, ok ? "success" : "failure", {
    table:         opts.table,
    rowId:         opts.id,
    fieldsChanged: changedKeys,
    requestReason: opts.reason,
    // before/after values are sealed in the audit metadata too (sealing
    // happens at the audit_log boundary because metadata is in the seal list)
    before:        beforeValues,
    after:         opts.changes,
  });

  return ok;
}

// ---- Erase (Art. 17 right to be forgotten) ----

function erase(subjectId, opts) {
  cluster.requireLeader();
  if (!subjectId) throw new Error("subject.erase requires a subjectId");
  if (!opts || !opts.reason) {
    throw new Error("subject.erase requires { reason } — e.g. 'GDPR Art. 17 request 2026-04-25 ticket #4471'");
  }
  if (!Array.isArray(opts.acknowledgements)) {
    throw new Error("subject.erase requires { acknowledgements: [...] } — see REQUIRED_ERASE_ACKS");
  }
  for (var i = 0; i < REQUIRED_ERASE_ACKS.length; i++) {
    if (opts.acknowledgements.indexOf(REQUIRED_ERASE_ACKS[i]) === -1) {
      throw new Error(
        "subject.erase: missing required acknowledgement '" + REQUIRED_ERASE_ACKS[i] + "'. " +
        "Operator must attest no litigation hold and no statutory retention before erasure."
      );
    }
  }

  // Authoritative legal-hold gate. Even when the operator passed the
  // "no-litigation-hold" attestation, the central registry is the
  // source of truth — a stale attestation cannot override an active
  // hold. Per FRCP Rule 26/37(e), GDPR Art 17(3)(e), SEC Rule 17a-4,
  // HIPAA §164.530(j)(2).
  var holds = legalHold._getSingleton();
  if (holds && holds.isHeld(subjectId)) {
    var holdInfo = holds.get(subjectId) || {};
    _writeAudit("subject.erase", subjectId, "denied", {
      requestReason: opts.reason,
      reason:        "legal-hold-active",
      heldSince:     holdInfo.placedAt,
      citation:      holdInfo.citation,
    });
    throw new Error(
      "subject.erase: subject '" + subjectId + "' is on legal hold (" +
      (holdInfo.citation || "operator-defined") + "; placed " +
      new Date(holdInfo.placedAt).toISOString() +
      "). Release the hold before erasure."
    );
  }

  var tables = db()._getSubjectTables();
  var totalDeleted = 0;
  var perTable = {};

  for (var t = 0; t < tables.length; t++) {
    var spec = tables[t];
    var hash = db().hashFor(spec.name, spec.subjectField, subjectId);
    var pred;
    if (hash) {
      var derivedField = _getDerivedFieldName(spec.name, spec.subjectField);
      if (derivedField) {
        pred = {}; pred[derivedField] = hash;
      } else {
        pred = {}; pred[spec.subjectField] = subjectId;
      }
    } else {
      pred = {}; pred[spec.subjectField] = subjectId;
    }
    var deleted = db().from(spec.name).where(pred).deleteMany();
    totalDeleted += deleted;
    perTable[spec.name] = deleted;
  }

  // Mark subject as erased (so future writes refuse to mention them)
  _markErased(subjectId);

  _writeAudit("subject.erase", subjectId, "success", {
    requestReason:  opts.reason,
    rowsDeleted:    totalDeleted,
    perTable:       perTable,
    acknowledgements: opts.acknowledgements,
  });

  return { rowsDeleted: totalDeleted, perTable: perTable };
}

// ---- Crypto-shred erase (Art. 17 + WAL/replica residual closure) ----
//
// F-RTBF-3 — when a table opts into per-row keying via
// b.cryptoField.declarePerRowKey, this primitive deletes the
// per-row K_row entries from _blamejs_per_row_keys, leaving any
// residual ciphertext in WAL / replica / backup storage
// undecryptable even if the operator's vault key is later
// recovered. Combined with a row DELETE + REINDEX, this is the
// strongest GDPR Art. 17 erasure shape the framework offers.

function eraseHard(subjectId, opts) {
  cluster.requireLeader();
  if (!subjectId) throw new Error("subject.eraseHard requires a subjectId");
  opts = opts || {};
  if (!opts.reason) {
    throw new Error("subject.eraseHard requires { reason } — e.g. 'GDPR Art. 17 ticket #4471'");
  }
  if (!Array.isArray(opts.acknowledgements)) {
    throw new Error("subject.eraseHard requires { acknowledgements: [...] } — see REQUIRED_ERASE_ACKS");
  }
  for (var i = 0; i < REQUIRED_ERASE_ACKS.length; i++) {
    if (opts.acknowledgements.indexOf(REQUIRED_ERASE_ACKS[i]) === -1) {
      throw new Error(
        "subject.eraseHard: missing required acknowledgement '" +
        REQUIRED_ERASE_ACKS[i] + "'");
    }
  }
  // Authoritative legal-hold gate.
  var holds = legalHold._getSingleton();
  if (holds && holds.isHeld(subjectId)) {
    var holdInfo = holds.get(subjectId) || {};
    _writeAudit("subject.erase_hard", subjectId, "denied", {
      requestReason: opts.reason,
      reason:        "legal-hold-active",
      heldSince:     holdInfo.placedAt,
      citation:      holdInfo.citation,
    });
    throw new Error(
      "subject.eraseHard: subject '" + subjectId + "' is on legal hold (" +
      (holdInfo.citation || "operator-defined") + "). Release the hold first.");
  }

  var tables = db()._getSubjectTables();
  var perTable = {};
  var perRowKeysDestroyed = 0;
  var totalDeleted = 0;

  db().transaction(function () {
    for (var t = 0; t < tables.length; t++) {
      var spec = tables[t];
      var hash = db().hashFor(spec.name, spec.subjectField, subjectId);
      var pred;
      if (hash) {
        var derivedField = _getDerivedFieldName(spec.name, spec.subjectField);
        if (derivedField) {
          pred = {}; pred[derivedField] = hash;
        } else {
          pred = {}; pred[spec.subjectField] = subjectId;
        }
      } else {
        pred = {}; pred[spec.subjectField] = subjectId;
      }
      // Find rows so we can destroy their per-row keys before delete.
      var rows = db().from(spec.name).where(pred).all();
      if (cryptoField.hasPerRowKey(spec.name)) {
        for (var r = 0; r < rows.length; r++) {
          var rowId = rows[r]._id;
          if (rowId) {
            var dr = cryptoField.destroyPerRowKey(spec.name, rowId, db());
            perRowKeysDestroyed += (dr && dr.destroyed) || 0;
          }
        }
      }
      var deleted = db().from(spec.name).where(pred).deleteMany();
      totalDeleted += deleted;
      perTable[spec.name] = deleted;
      // REINDEX the table so B-tree pages holding the deleted row's
      // index entries are rebuilt — closes the F-RTBF-2 residual class.
      try { db().runSql('REINDEX "' + spec.name + '"'); }                                        // allow:identifier-from-schema — table name comes from FRAMEWORK_SCHEMA
      catch (_e) { /* cluster mode / unsupported dialect */ }
    }
    _markErased(subjectId);
  });

  _writeAudit("subject.erase_hard", subjectId, "success", {
    requestReason:       opts.reason,
    rowsDeleted:         totalDeleted,
    perRowKeysDestroyed: perRowKeysDestroyed,
    perTable:            perTable,
    acknowledgements:    opts.acknowledgements,
  });
  return {
    rowsDeleted:         totalDeleted,
    perRowKeysDestroyed: perRowKeysDestroyed,
    perTable:            perTable,
  };
}

// ---- Restrict (Art. 18) ----

function restrict(subjectId, opts) {
  cluster.requireLeader();
  if (!subjectId) throw new Error("subject.restrict requires a subjectId");
  if (!opts || typeof opts.on !== "boolean") {
    throw new Error("subject.restrict requires { on: true|false }");
  }
  var existing = db().prepare(
    "SELECT subjectIdHash FROM _blamejs_subject_restrictions WHERE subjectIdHash = ?"
  ).get(_subjectHash(subjectId));

  if (opts.on) {
    if (!existing) {
      db().prepare(
        "INSERT INTO _blamejs_subject_restrictions (subjectIdHash, since, reason) VALUES (?, ?, ?)"
      ).run(_subjectHash(subjectId), Date.now(), opts.reason || null);
    }
  } else if (existing) {
    db().prepare(
      "DELETE FROM _blamejs_subject_restrictions WHERE subjectIdHash = ?"
    ).run(_subjectHash(subjectId));
  }

  _writeAudit("subject.restrict", subjectId, "success", {
    on:     opts.on,
    reason: opts.reason || null,
  });
  return true;
}

function isRestricted(subjectId) {
  if (!subjectId) return false;
  var row = db().prepare(
    "SELECT 1 FROM _blamejs_subject_restrictions WHERE subjectIdHash = ?"
  ).get(_subjectHash(subjectId));
  return !!row;
}

// ---- Object (Art. 21) ----

function recordObjection(subjectId, opts) {
  cluster.requireLeader();
  if (!subjectId) throw new Error("subject.recordObjection requires a subjectId");
  if (!opts || !opts.purpose) throw new Error("subject.recordObjection requires { purpose }");
  _writeAudit("subject.objection", subjectId, "success", {
    purpose: opts.purpose,
    reason:  opts.reason || null,
  });
  return true;
}

// ---- Internal helpers ----

function _markErased(subjectId) {
  db().prepare(
    "INSERT OR REPLACE INTO _blamejs_subject_erasures (subjectIdHash, erasedAt) VALUES (?, ?)"
  ).run(_subjectHash(subjectId), Date.now());
}

function _subjectHash(subjectId) {
  // Use the framework's email-style namespace; the consistent thing matters,
  // not which prefix. Subject IDs are typically opaque already.
  return sha3Hash("bj-subject:" + String(subjectId));
}

function _writeAudit(action, subjectId, outcome, metadata) {
  // recordSafe — audit failure must not roll back the subject mutation
  // that already touched the database. Best-effort emission with errors
  // swallowed; operators see them in stderr if they fire.
  audit.emit({
    actor:    {},
    action:   action,
    resource: { kind: "subject", id: subjectId },
    outcome:  outcome,
    reason:   metadata && metadata.requestReason ? metadata.requestReason : null,
    metadata: metadata || null,
  });
}

function _resetForTest() { db.reset(); }

module.exports = {
  export:               exportData,
  exportData:           exportData,  // alias — `export` is a reserved word in some toolchains
  rectify:              rectify,
  erase:                erase,
  eraseHard:            eraseHard,
  restrict:             restrict,
  isRestricted:         isRestricted,
  recordObjection:      recordObjection,
  REQUIRED_ERASE_ACKS:  REQUIRED_ERASE_ACKS,
  _resetForTest:        _resetForTest,
};
