"use strict";
/**
 * b.compliance — top-level compliance-posture coordinator.
 *
 * Sets a global posture (`hipaa` / `pci-dss` / `gdpr` / `soc2` /
 * `dora`) that primitives with a `compliancePosture` opt fall back to
 * when the operator hasn't passed one explicitly. Single source of
 * truth for "what regulatory posture is this deployment running
 * under?".
 *
 *   b.compliance.set("hipaa");
 *   b.compliance.current();        // → "hipaa"
 *   b.compliance.assert("hipaa");  // throws if not the named posture
 *
 *   // Every primitive with a compliancePosture opt now picks "hipaa"
 *   // by default:
 *   var gate = b.guardCsv.gate({});               // hipaa overlay applied
 *   var ttl  = b.retention.complianceFloor("hipaa", customTtl);
 *
 * Boot-time only — `set()` MUST run before the primitives it
 * coordinates are first used. Runtime switches are forbidden because
 * they would create a half-set state across primitives that have
 * already initialized.
 *
 * Audit emission: `compliance.posture.set` on every successful
 * `set()`, `compliance.posture.cleared` on `clear()`. Operators
 * tracking deploys can grep audit for these to reconstruct posture
 * history per deployment.
 */

var lazyRequire = require("./lazy-require");
var { ComplianceError } = require("./framework-error");

var audit = lazyRequire(function () { return require("./audit"); });

// Recognised posture names. Aligns with the compliance-posture
// vocabulary every guard / retention floor / etc. accepts. Operators
// passing an unknown name get a typo-surfacing throw at set-time, not
// silent fall-through to no-op.
var KNOWN_POSTURES = Object.freeze([
  "hipaa", "pci-dss", "gdpr", "soc2", "dora", "sox",
]);

var STATE = { posture: null, setAt: null };

function _emitAudit(action, metadata) {
  try {
    audit().safeEmit({
      action:   action,
      outcome:  "success",
      metadata: metadata,
    });
  } catch (_e) { /* audit best-effort */ }
}

function set(posture) {
  if (typeof posture !== "string" || posture.length === 0) {
    throw new ComplianceError("compliance/bad-posture",
      "compliance.set: posture must be a non-empty string, got " +
      JSON.stringify(posture));
  }
  if (KNOWN_POSTURES.indexOf(posture) === -1) {
    throw new ComplianceError("compliance/unknown-posture",
      "compliance.set: unknown posture '" + posture + "'; expected one of " +
      KNOWN_POSTURES.join(", "));
  }
  if (STATE.posture && STATE.posture !== posture) {
    throw new ComplianceError("compliance/already-set",
      "compliance.set: posture is already '" + STATE.posture + "' (set at " +
      new Date(STATE.setAt).toISOString() + "). Runtime switches are " +
      "forbidden — they create half-set state across already-initialized " +
      "primitives. Set once at boot.");
  }
  STATE.posture = posture;
  STATE.setAt   = Date.now();
  _emitAudit("compliance.posture.set", { posture: posture });
}

function current() {
  return STATE.posture;
}

function assert(posture) {
  if (STATE.posture !== posture) {
    throw new ComplianceError("compliance/assertion-failed",
      "compliance.assert('" + posture + "'): current posture is " +
      JSON.stringify(STATE.posture));
  }
}

function clear() {
  // Reserved for tests + operator-controlled tear-down. Emits an audit
  // row so the chain shows the posture was intentionally cleared.
  if (STATE.posture) {
    _emitAudit("compliance.posture.cleared", { previous: STATE.posture });
  }
  STATE.posture = null;
  STATE.setAt   = null;
}

function _resetForTest() {
  STATE.posture = null;
  STATE.setAt   = null;
}

module.exports = {
  set:              set,
  current:          current,
  assert:           assert,
  clear:            clear,
  KNOWN_POSTURES:   KNOWN_POSTURES,
  ComplianceError:  ComplianceError,
  _resetForTest:    _resetForTest,
};
