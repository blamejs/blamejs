// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.mtlsCa
 * @nav    Crypto
 * @title  mTLS CA
 *
 * @intro
 *   Mutual TLS Certificate Authority — internal CA cert issuance,
 *   mTLS gate setup, fingerprint pinning.
 *
 *   The framework owns storage, sealed-loading dispatch, generation
 *   tagging, and atomic commit. Cert issuance (CA generation, client
 *   cert signing, PKCS#12 packaging) delegates to a pluggable engine
 *   so the operator chooses the X.509 toolchain. The default pure-JS
 *   engine lives in `lib/mtls-engine-default.js` (backed by the vendored
 *   zero-dep @blamejs/pki toolkit); operators with custom requirements
 *   pass their own via `opts.engine`.
 *
 *   Files relative to `dataDir`: `ca.crt` (PEM cert, plaintext),
 *   `ca.key` (PEM key, plaintext — refused under `caKeySealedMode:
 *   "required"`), `ca.key.sealed` (vault.seal of the PEM bytes — the
 *   default at-rest shape), `revocations.json` (revocation registry),
 *   `ca.crl` (signed CRL derived from the registry).
 *
 *   `caKeySealedMode` defaults to "required" — sealed file required,
 *   plaintext refused. The legacy "auto" fallback was removed; it
 *   defaulted to writing plaintext on a fresh install, which is the
 *   inverse of the framework's security-defaults-on posture for
 *   at-rest key material. The "disabled" mode is a dev-only opt-out
 *   (operator must justify with audited reason).
 *
 *   Generation tagging: every CA cert issued by the framework embeds
 *   an `OU=CAv{N}` RDN in its subject DN. `parseGeneration` reads that
 *   back so an upgrade flow can detect legacy CAs and prompt
 *   regeneration without breaking active mTLS clients.
 *
 *   Engine contract:
 *     async generateCa({ generation }) -> { caCertPem, caKeyPem }
 *     async signClientCert({ cn, validityDays, caCertPem, caKeyPem })
 *       -> { cert, key, ca, issuedAt, expiresAt }
 *     async packageP12({ cn, password, validityDays, caCertPem, caKeyPem })
 *       -> { p12, certPem, issuedAt, expiresAt }
 *
 *   The engine returns the cert PEM but does NOT compute a
 *   fingerprint — the framework hashes the certificate's DER via
 *   `b.crypto.hashCertFingerprint(certPem)` (the same value the
 *   require-mtls gate pins) so the SHA3-512 posture stays
 *   consistent across the stack. Operators who need the X.509-
 *   conventional SHA-256 fingerprint (browser cert-details panels,
 *   openssl interop) compute it separately from the cert PEM.
 *
 * @card
 *   Mutual TLS Certificate Authority — internal CA cert issuance, mTLS gate setup, fingerprint pinning.
 */

var nodeFs = require("node:fs");
var nodePath = require("node:path");
var nodeCrypto = require("node:crypto");
var atomicFile = require("./atomic-file");
var C = require("./constants");
var lazyRequire = require("./lazy-require");
// Lazy — the SHA3-512 fingerprint surfaced from issuance must match the one
// the require-mtls gate pins (b.crypto.hashCertFingerprint of the cert DER).
var bCrypto = lazyRequire(function () { return require("./crypto"); });
var { boot } = require("./log");
var safeBuffer = require("./safe-buffer");
var safeJson = require("./safe-json");
var validateOpts = require("./validate-opts");
var { FrameworkError } = require("./framework-error");

// The default engine carries a vendored X.509 toolkit (@blamejs/pki).
// Lazy-require it so operators wiring a custom engine never pay the cost.
// The lazyRequire wrapper keeps the require at top-of-file declaration
// shape — no indented inline calls.
var mtlsEngineDefault = lazyRequire(function () { return require("./mtls-engine-default"); });

var caLog = boot("mtls-ca");

class MtlsCaError extends FrameworkError {
  constructor(code, message) {
    super(message, code);
    this.name = "MtlsCaError";
    this.permanent = true;
    this.isMtlsCaError = true;
  }
}

var DEFAULT_PATHS = {
  caKey:        "ca.key",
  caKeySealed:  "ca.key.sealed",
  caCert:       "ca.crt",
  // Revocation registry — JSON file under dataDir tracking revoked
  // serial numbers. Operators export this as a CRL via
  // ca.generateCrl() (engine.generateCrl signs the list with the CA
  // key). Persisted as JSON rather than a stored CRL because the
  // signed CRL is a derivative artifact — the registry survives CA
  // rotation, the CRL doesn't.
  revocations:  "revocations.json",
  crl:          "ca.crl",
  // Superseded-CA snapshot for a re-enrollment grace window. `commit({
  // retainPrevious: true })` copies the outgoing ca.crt here before the new
  // one lands; `loadTrustBundle()` returns [current, ...retained] so live
  // clients holding a cert from the old CA still verify while they re-enroll;
  // `dropRetained()` ends the window.
  caCertPrev:   "ca.prev.crt",
  // Issuance ledger — append-only JSON index of every leaf this CA has signed
  // ({ serialNumber, fingerprint, generation, issuedAt }). `revokeGeneration(n)`
  // reads it to revoke every cert issued under a CA generation < n.
  issuance:     "issuance.json",
};

var VALID_SEAL_MODES = { required: 1, disabled: 1 };

// Resolve relative path entries under `dataDir`; pass absolute paths
// through unchanged. The pre-v0.8.58 shape always joined under
// dataDir, which silently overrode an operator-supplied absolute
// path (e.g. `MTLS_CA_KEY=/etc/ssl/ca.key` → `<dataDir>/etc/ssl/ca.key`).
// Standard Node `nodePath.join` semantics already preserve absolute
// arguments — the always-join was an oversight, not by design.
function _absoluteOrUnderDataDir(dataDir, p) {
  return nodePath.isAbsolute(p) ? p : nodePath.join(dataDir, p);
}

function _resolvePaths(dataDir, paths) {
  var p = Object.assign({}, DEFAULT_PATHS, paths || {});
  return {
    caKey:        _absoluteOrUnderDataDir(dataDir, p.caKey),
    caKeySealed:  _absoluteOrUnderDataDir(dataDir, p.caKeySealed),
    caCert:       _absoluteOrUnderDataDir(dataDir, p.caCert),
    revocations:  _absoluteOrUnderDataDir(dataDir, p.revocations),
    crl:          _absoluteOrUnderDataDir(dataDir, p.crl),
    caCertPrev:   _absoluteOrUnderDataDir(dataDir, p.caCertPrev),
    issuance:     _absoluteOrUnderDataDir(dataDir, p.issuance),
  };
}

/**
 * @primitive b.mtlsCa.parseGeneration
 * @signature b.mtlsCa.parseGeneration(certPem)
 * @since     0.7.68
 * @related   b.mtlsCa.create
 *
 * Read the `OU=CAv{N}` generation tag from a PEM CA certificate's
 * subject DN. Returns the integer `N`, defaulting to `1` for untagged
 * legacy CAs (so the first regen lifts a legacy CA to generation 2
 * without misidentifying it as fresh) or `0` when the cert is
 * unreadable. Operators wire this into upgrade flows that detect
 * pre-rotation CAs whose key parameters are below the current bar.
 *
 * @example
 *   var pem = "-----BEGIN CERTIFICATE-----\n(invalid)\n-----END CERTIFICATE-----\n";
 *   b.mtlsCa.parseGeneration(pem);
 *   // → 0
 *
 *   b.mtlsCa.parseGeneration(null);
 *   // → 0
 */
function parseGeneration(certPem) {
  if (typeof certPem !== "string" && !Buffer.isBuffer(certPem)) return 0;
  try {
    var cert = new nodeCrypto.X509Certificate(certPem);
    /* c8 ignore next -- defensive: a successfully-parsed X.509 certificate always exposes a subject DN */
    var subj = cert.subject || "";
    var m = /OU=CAv(\d+)/.exec(subj);
    return m ? parseInt(m[1], 10) : 1;
  } catch (_e) {
    return 0;
  }
}

/**
 * @primitive b.mtlsCa.create
 * @signature b.mtlsCa.create(opts)
 * @since     0.7.68
 * @related   b.mtlsCa.parseGeneration, b.crypto.sha3Hash
 *
 * Build an mTLS CA handle bound to `opts.dataDir`. The handle owns
 * sealed-loading of the CA private key, generation tagging on issued
 * certs, atomic commit of newly generated material, and a pluggable
 * engine for the X.509 work itself. Returns an object with
 * `initCA()`, `generateClientCert({ cn, validityDays })`,
 * `generateClientP12({ cn, password, validityDays })`, plus
 * revocation helpers.
 *
 * Throws `MtlsCaError` at config-time on bad opts (missing dataDir,
 * sealed-mode mismatch, missing vault when seal required).
 *
 * @opts
 *   dataDir:          string,                                  // required — base for cert / key / revocation files
 *   paths:            { caKey, caKeySealed, caCert, revocations, crl },  // override defaults
 *   vault:            object,                                  // b.vault — required when caKeySealedMode = "required"
 *   caKeySealedMode:  string,                                  // "required" (default) | "disabled"
 *   generation:       number,                                  // current CA generation for OU=CAv{N}
 *   engine:           object,                                  // pluggable X.509 engine; default lib/mtls-engine-default
 *   algorithm:        string,                                  // pin CA + leaf key algorithm; default ML-DSA-87. Pass "ECDSA-P384-SHA384" for a classical CA when a peer predates OpenSSL 3.5
 *   issuanceStore:    object,                                  // bring-your-own { list(), add(entry) } for the issuance ledger revokeGeneration reads; default is a JSON file under dataDir
 *
 * The handle also supports a non-breaking CA algorithm migration: status()
 * reports the stored CA's algorithm / keyType; rotate({ generation, algorithm })
 * generates and atomically commits a new CA (returning { caCertPem,
 * previousCaCertPem }) without the algorithm-mismatch initCA raises;
 * commit({ retainPrevious:true }) + loadTrustBundle() + dropRetained() keep the
 * superseded CA trusted during a re-enrollment grace window; canVerifyInTls()
 * runs a loopback mTLS self-test proving node:tls verifies the CA's algorithm on
 * this runtime; and revokeGeneration(n) revokes every cert the issuance ledger
 * recorded under a CA generation below n.
 *
 * @example
 *   var fs   = require("fs");
 *   var os   = require("os");
 *   var path = require("path");
 *   var dir  = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-mtls-"));
 *   var ca   = b.mtlsCa.create({
 *     dataDir:         dir,
 *     caKeySealedMode: "disabled",
 *     generation:      1,
 *   });
 *   typeof ca.initCA;
 *   // → "function"
 */
// Map an algorithm-pin label to the node KeyObject.asymmetricKeyType a stored CA
// key of that algorithm reports, so a pin can be checked against an on-disk CA.
// Returns null for a label this file can't map (a custom engine's own naming) —
// the check is then skipped and the engine owns the semantics.
// The OpenSSL curve name node reports for the framework's sole classical pin
// (ECDSA-P384-SHA384). A stored EC CA must report this curve to satisfy that pin.
var CLASSICAL_CA_CURVE = "secp384r1";

function _expectedKeyTypeForPin(label) {
  var l = String(label).toLowerCase();
  if (l.indexOf("ecdsa") !== -1) return "ec";
  var m = l.match(/ml-dsa-(\d+)/);
  return m ? ("ml-dsa-" + m[1]) : null;
}

// Map a node asymmetricKeyType (from a key OR a cert public key) to the
// framework algorithm label. "ec" -> ECDSA-P384-SHA384 (the sole classical
// pin), "ml-dsa-N" -> ML-DSA-N. undefined for a type this file doesn't map
// (a custom engine's own naming) — the engine then owns the semantics.
function _labelForKeyType(type) {
  var t = String(type || "").toLowerCase();
  if (t === "ec") return "ECDSA-P384-SHA384";
  if (/^ml-dsa-\d+$/.test(t)) return t.toUpperCase();
  return undefined;
}

function _labelForCaKeyType(caKeyPem) {
  var type;
  /* c8 ignore next -- the "" fallback is defensive: a parsed KeyObject always reports a non-empty asymmetricKeyType, so it is never reached */
  try { type = String(nodeCrypto.createPrivateKey(caKeyPem).asymmetricKeyType || "").toLowerCase(); }
  catch (_e) { return undefined; }
  return _labelForKeyType(type);
}

// Derive { keyType, algorithm } from a CA CERT's public key — the shape
// status() exposes. Uses only the public key (no vault / private-key load),
// so it works regardless of caKeySealedMode. keyType is the raw node
// asymmetricKeyType ("ec" / "ml-dsa-87" / ...); algorithm is the mapped label
// (null for a type this file doesn't recognize, e.g. a custom engine's).
function _certAlgorithm(certPem) {
  try {
    var pub = new nodeCrypto.X509Certificate(certPem).publicKey;
    var type = String(pub.asymmetricKeyType || "").toLowerCase();
    if (type === "ec") {
      // The framework's sole classical label (ECDSA-P384-SHA384) is P-384 /
      // secp384r1. A custom engine may issue a P-256 / P-521 EC CA that node
      // still reports as "ec"; labeling it ECDSA-P384-SHA384 would misreport
      // status() AND feed a wrong label to a custom engine's canVerifyInTls().
      // Confirm the curve before labeling; return null when it can't be.
      var curve = pub.asymmetricKeyDetails && pub.asymmetricKeyDetails.namedCurve
        ? String(pub.asymmetricKeyDetails.namedCurve).toLowerCase() : null;
      return { keyType: type,
               algorithm: curve === CLASSICAL_CA_CURVE ? "ECDSA-P384-SHA384" : null };
    }
    return { keyType: type || null, algorithm: _labelForKeyType(type) || null };
  } catch (_e) {
    return { keyType: null, algorithm: null };
  }
}

function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "dataDir", "paths", "vault",
    "caKeySealedMode", "generation", "engine", "revocationStore", "issuanceStore", "algorithm",
  ], "b.mtlsCa");
  validateOpts.requireNonEmptyString(opts.dataDir, "mtlsCa.create: opts.dataDir", MtlsCaError, "mtls-ca/no-datadir");
  // Auto-create the dataDir with restrictive perms (CA keys live here).
  // Matches the behaviour of other framework primitives that own a
  // dataDir — log-stream-local, backup, restore-bundle. Without this
  // the first initCA() / generateClientCert() call fails with ENOENT
  // on `ca.key.tmp` because the atomic-file write expects the parent
  // dir to exist.
  if (!nodeFs.existsSync(opts.dataDir)) {
    nodeFs.mkdirSync(opts.dataDir, { recursive: true, mode: 0o700 });
  }
  var paths = _resolvePaths(opts.dataDir, opts.paths);
  var vault = opts.vault || null;
  var caKeySealedMode = (opts.caKeySealedMode || "required").toLowerCase();
  if (!Object.prototype.hasOwnProperty.call(VALID_SEAL_MODES, caKeySealedMode)) {
    throw new MtlsCaError("mtls-ca/bad-mode",
      "caKeySealedMode must be 'required' or 'disabled' " +
      "(legacy 'auto' was removed — it defaulted to plaintext-on-disk)");
  }
  var generation = typeof opts.generation === "number" && opts.generation >= 1
    ? Math.floor(opts.generation) : 1;
  // The default engine is lazy-loaded at top-of-file; resolve it only
  // when no custom engine was passed. Whether the bundled engine is in use
  // gates the CA-following algorithm inference below: _labelForCaKeyType maps a
  // key to the BUNDLED engine's label set, which is meaningless (or wrong) for a
  // custom engine's own labels / key curves. A falsy engine (null / undefined)
  // selects the bundled engine, so the flag must match the `opts.engine || ...`
  // fallback exactly — an explicit engine: null is the bundled engine, not custom.
  var usesDefaultEngine = !opts.engine;
  var engine = opts.engine || mtlsEngineDefault();

  // Optional algorithm pin. When set, it is threaded into BOTH CA generation
  // (initCA) and every leaf/PKCS#12 issuance so the whole chain shares one
  // algorithm — the operator opt-in for a classical (ECDSA-P384-SHA384) CA when
  // a peer predates the OpenSSL 3.5 that verifies the ML-DSA-87 default. The
  // label set is the engine's to validate (a custom engine may define its own),
  // so this is a config-time type guard only; an unknown label surfaces from the
  // engine at issuance.
  var caAlgorithm = opts.algorithm;
  if (caAlgorithm !== undefined && (typeof caAlgorithm !== "string" || caAlgorithm.length === 0)) {
    throw new MtlsCaError("mtls-ca/bad-algorithm",
      "opts.algorithm must be a non-empty string label " +
      "(e.g. \"ECDSA-P384-SHA384\") when set");
  }

  function _requireVault(reason) {
    if (!vault || typeof vault.seal !== "function" || typeof vault.unseal !== "function") {
      throw new MtlsCaError("mtls-ca/no-vault",
        reason + " requires opts.vault (with seal/unseal). Pass b.vault " +
        "or use caKeySealedMode='disabled' to keep the CA key on disk in plaintext.");
    }
  }

  function keyExists() {
    return nodeFs.existsSync(paths.caKey) || nodeFs.existsSync(paths.caKeySealed);
  }
  function exists() {
    return keyExists() && nodeFs.existsSync(paths.caCert);
  }

  function status() {
    if (!exists()) {
      return {
        exists:     false,
        generation: 0,
        isLegacy:   false,
        current:    generation,
        algorithm:  null,
        keyType:    null,
      };
    }
    var pem = atomicFile.fdSafeReadSync(paths.caCert, { maxBytes: C.BYTES.mib(1) });
    var gen = parseGeneration(pem);
    // Algorithm / keyType are read from the stored cert's PUBLIC key, so a
    // consumer deciding whether to migrate a classical CA no longer has to
    // re-parse loadCert() with node:crypto to learn ECDSA-vs-ML-DSA.
    var alg = _certAlgorithm(pem);
    return {
      exists:     true,
      generation: gen,
      isLegacy:   gen < generation,
      current:    generation,
      algorithm:  alg.algorithm,
      keyType:    alg.keyType,
    };
  }

  // Load the CA key in whichever form is on disk, applying the
  // caKeySealedMode dispatch. Returns Buffer of PEM bytes, or throws
  // with a precise reason when the mode rejects the on-disk form.
  function loadKey() {
    var hasPlain  = nodeFs.existsSync(paths.caKey);
    var hasSealed = nodeFs.existsSync(paths.caKeySealed);
    if (!hasPlain && !hasSealed) {
      throw new MtlsCaError("mtls-ca/missing-key",
        "no CA key on disk at " + paths.caKey + " or " + paths.caKeySealed);
    }
    if (caKeySealedMode === "required") {
      if (!hasSealed) {
        throw new MtlsCaError("mtls-ca/sealed-required",
          "CA_KEY_SEALED='required' but " + paths.caKeySealed + " does not exist");
      }
      _requireVault("sealed CA key load");
      // Cap + fd-bound CA-private-key read. NO refuseSymlink: caKeySealed may be
      // an operator-absolute path on a k8s/KMS secret volume that symlinks it.
      var sealedBytes = atomicFile.fdSafeReadSync(paths.caKeySealed, { maxBytes: C.BYTES.kib(64), encoding: "utf8" }).trim();
      var pem = vault.unseal(sealedBytes);
      if (!pem) {
        throw new MtlsCaError("mtls-ca/unseal-failed",
          "vault.unseal of " + paths.caKeySealed + " returned empty — vault key mismatch?");
      }
      return Buffer.from(pem, "utf8");
    }
    // disabled: plaintext only.
    if (!hasPlain) {
      throw new MtlsCaError("mtls-ca/plain-required",
        "caKeySealedMode='disabled' but " + paths.caKey + " does not exist");
    }
    // Cap + fd-bound plaintext CA-private-key read (disabled mode = dev opt-out).
    // NO refuseSymlink (operator-absolute path may symlink).
    return atomicFile.fdSafeReadSync(paths.caKey, { maxBytes: C.BYTES.kib(64) });
  }

  function loadCert() {
    if (!nodeFs.existsSync(paths.caCert)) {
      throw new MtlsCaError("mtls-ca/missing-cert",
        "no CA cert on disk at " + paths.caCert);
    }
    return atomicFile.fdSafeReadSync(paths.caCert, { maxBytes: C.BYTES.mib(1) });
  }

  // Atomic commit: write .tmp + atomic rename for both key and cert.
  // Honors caKeySealedMode — when 'required' (the default), the key is
  // vault-sealed before the on-disk write so plaintext PEM never touches
  // the filesystem; when 'disabled', it goes to disk as PEM with the
  // operator's audited reason on record.
  function commit(opts2) {
    if (!opts2 || typeof opts2.caKeyPem !== "string" || typeof opts2.caCertPem !== "string") {
      throw new MtlsCaError("mtls-ca/bad-commit",
        "commit requires opts.caKeyPem and opts.caCertPem (PEM strings)");
    }
    // Grace-window retention: capture the OUTGOING cert now (before the new one
    // overwrites it), but do NOT touch the retained-root file until the commit
    // below SUCCEEDS. If sealing / tmp-write / rename fails, the active CA is
    // unchanged, so the retained root must stay intact — otherwise a client still
    // using it is stranded by a rotation that never landed.
    var outgoingCaCert = (opts2.retainPrevious && nodeFs.existsSync(paths.caCert))
      ? atomicFile.fdSafeReadSync(paths.caCert, { maxBytes: C.BYTES.mib(1) })
      : null;
    var sealed = caKeySealedMode === "required";
    var keyDest = sealed ? paths.caKeySealed : paths.caKey;
    var keyTmp = keyDest + ".tmp";
    var certTmp = paths.caCert + ".tmp";

    // CodeQL js/insecure-temporary-file defense — exclusive-create ("wx")
    // refuses to write through a pre-existing path (symlink or regular
    // file). keyTmp / certTmp live under the operator-supplied dataDir
    // (owner-only 0o700 framework dir established by atomicFile.ensureDir
    // upstream), but exclusive-create hardens against a residual tmp file
    // from a crashed prior commit or an attacker who pre-creates the
    // path as a symlink. EEXIST surfaces as the commit-failed error.
    function _writeExclusive(path, data, mode) {
      var fd = nodeFs.openSync(path, "wx", mode);
      try {
        var buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
        var w = 0;
        while (w < buf.length) {
          w += nodeFs.writeSync(fd, buf, w, buf.length - w, null);
        }
        /* c8 ignore next -- best-effort: fsync on a freshly-opened, still-valid fd does not throw here */
        try { nodeFs.fsyncSync(fd); } catch (_fe) { /* fsync best-effort */ }
      } finally {
        /* c8 ignore next -- best-effort: closeSync on the just-written fd does not throw here */
        try { nodeFs.closeSync(fd); } catch (_ce) { /* close best-effort */ }
      }
    }
    try {
      if (sealed) {
        _requireVault("sealed CA key commit");
        _writeExclusive(keyTmp, vault.seal(opts2.caKeyPem), 0o600);
      } else {
        _writeExclusive(keyTmp, opts2.caKeyPem, 0o600);
      }
      _writeExclusive(certTmp, opts2.caCertPem, 0o644);
      atomicFile.renameWithRetry(keyTmp, keyDest);
      atomicFile.renameWithRetry(certTmp, paths.caCert);
    } catch (e) {
      // Best-effort cleanup of half-written tmp files; the original
      // commit error is what we re-raise. Log cleanup failures at debug
      // so a genuinely-broken filesystem state surfaces in operator logs
      // rather than getting silently swallowed.
      try { if (nodeFs.existsSync(keyTmp))  nodeFs.unlinkSync(keyTmp); }
      /* c8 ignore next -- best-effort cleanup: unlink of a tmp file we just created does not throw here */
      catch (cleanupErr) { caLog.debug("cleanup-failed", { op: "fs.unlinkSync", path: keyTmp, error: cleanupErr.message }); }
      try { if (nodeFs.existsSync(certTmp)) nodeFs.unlinkSync(certTmp); }
      /* c8 ignore next -- best-effort cleanup: unlink of a tmp file we just created does not throw here */
      catch (cleanupErr) { caLog.debug("cleanup-failed", { op: "fs.unlinkSync", path: certTmp, error: cleanupErr.message }); }
      throw new MtlsCaError("mtls-ca/commit-failed",
        "atomic CA commit failed: " + ((e && e.message) || String(e)));
    }
    // The CA commit landed. Settling the retained root — snapshot the outgoing
    // cert for the grace window, or (explicit retainPrevious:false) clear a root
    // a prior retained rotation left behind — is a SECONDARY artifact, done
    // best-effort: a snapshot/clear failure (full or read-only filesystem) must
    // NOT report the already-committed rotation as failed nor block the handle's
    // post-commit algorithm update. A failure degrades the grace window and is
    // logged; loadTrustBundle()/dropRetained() remain the operator's recovery.
    try {
      if (outgoingCaCert !== null) {
        atomicFile.writeSync(paths.caCertPrev, outgoingCaCert, { mode: 0o644 });
      } else if (opts2.retainPrevious === false && nodeFs.existsSync(paths.caCertPrev)) {
        nodeFs.unlinkSync(paths.caCertPrev);
      }
    } catch (retainErr) {
      caLog.error("retained-root-update-failed",
        { path: paths.caCertPrev, error: (retainErr && retainErr.message) || String(retainErr) });
    }
    return {
      keyPath:  keyDest,
      certPath: paths.caCert,
      sealed:   sealed,
    };
  }

  async function initCA() {
    if (exists()) {
      var existingCertPem = loadCert().toString("utf8");
      var existingKeyPem  = loadKey().toString("utf8");
      // A stored CA is returned as-is (initCA never silently rotates). But an
      // algorithm pin that DISAGREES with the stored CA cannot be honored: the
      // CA's own signature over every leaf is what a peer verifies, so issuing an
      // ECDSA leaf pinned for a legacy peer under a stored ML-DSA CA still yields
      // an ML-DSA-signed chain that peer cannot verify. Refuse the mismatch and
      // tell the operator to rotate, rather than issue an unusable credential.
      if (caAlgorithm !== undefined) {
        var expectedType = _expectedKeyTypeForPin(caAlgorithm);
        var actualType   = null;
        var actualCurve  = null;
        // A custom engine may store a key node cannot parse — skip the check then.
        try {
          var caKeyObj = nodeCrypto.createPrivateKey(existingKeyPem);
          /* c8 ignore next -- the "" fallback is defensive: a parsed KeyObject always reports a non-empty asymmetricKeyType, so it is never reached */
          actualType  = String(caKeyObj.asymmetricKeyType || "").toLowerCase();
          actualCurve = caKeyObj.asymmetricKeyDetails && caKeyObj.asymmetricKeyDetails.namedCurve
            ? String(caKeyObj.asymmetricKeyDetails.namedCurve).toLowerCase() : null;
        } catch (_e) { actualType = null; }
        if (expectedType !== null && actualType && actualType !== expectedType) {
          throw new MtlsCaError("mtls-ca/algorithm-mismatch",
            "the CA at this dataDir was generated under " + actualType + ", but algorithm " +
            JSON.stringify(caAlgorithm) + " (" + expectedType + ") was requested. A leaf issued " +
            "under the pin would be signed by the mismatched CA and fail chain verification at a " +
            "peer. Rotate to a new CA (a fresh dataDir, or a higher generation) to change algorithms.");
        }
        // Every ECDSA label maps to the generic "ec" type, so the type check alone
        // would accept a P-256/P-521 stored CA under the ECDSA-P384 pin — leaving
        // the operator believing they hold P-384 posture. The framework's sole
        // classical pin is ECDSA-P384-SHA384 (secp384r1), so enforce the curve for
        // it; a custom-engine label (unrecognized here) owns its own curve.
        if (actualType === "ec" && /ecdsa-p384/i.test(String(caAlgorithm)) && actualCurve !== CLASSICAL_CA_CURVE) {
          throw new MtlsCaError("mtls-ca/algorithm-mismatch",
            "the CA at this dataDir uses EC curve " + actualCurve + ", but algorithm " +
            JSON.stringify(caAlgorithm) + " requires P-384 (" + CLASSICAL_CA_CURVE + "). Rotate to a new " +
            "CA (a fresh dataDir, or a higher generation) to change the curve.");
        }
      }
      return { caCertPem: existingCertPem, caKeyPem: existingKeyPem };
    }
    // Build the args conditionally so an `algorithm` key is present ONLY when the
    // operator pinned one — a strict custom engine that validates its generateCa
    // option shape would reject an own `algorithm: undefined` key on an unpinned
    // first-time init (matching the conditional custom leaf-engine handling).
    var caGenArgs = { generation: generation };
    if (caAlgorithm !== undefined) caGenArgs.algorithm = caAlgorithm;
    var fresh = await engine.generateCa(caGenArgs);
    if (!fresh || typeof fresh.caCertPem !== "string" || typeof fresh.caKeyPem !== "string") {
      throw new MtlsCaError("mtls-ca/bad-engine-output",
        "engine.generateCa must return { caCertPem, caKeyPem }");
    }
    commit(fresh);
    return fresh;
  }

  // Recover the issued certificate's identity from its PEM so issuance and
  // any later revocation/indexing share identifiers without a round-trip back
  // through an X.509 parser. serialNumber is normalized to the same hex form
  // revoke() stores; fingerprint is the SHA3-512 the require-mtls gate pins.
  function _certIdentity(certPem) {
    // serialNumber comes from an X.509 parse, which is best-effort: a custom
    // engine (or a test double) may return a cert in a shape this Node build
    // cannot parse as X.509. The fingerprint is a hash of the returned bytes,
    // so it is always available and is what the require-mtls gate pins —
    // revoke()/isRevoked() by fingerprint keep working even when the serial
    // can't be recovered. Never let optional identity enrichment crash issuance.
    var serialNumber = null;
    try {
      serialNumber = _normalizeSerial(new nodeCrypto.X509Certificate(certPem).serialNumber);
    } catch (_e) {
      serialNumber = null;
    }
    // Hash the certificate's DER — exactly what the require-mtls gate pins
    // (b.crypto.hashCertFingerprint decodes the PEM envelope first). Hashing the
    // PEM TEXT instead (b.crypto.sha3Hash(certPem)) yields a value that never
    // matches the gate, so revoke()/revokeGeneration() by it could not be
    // enforced by a revocationSource-wired gate. A custom engine may return a
    // cert with no decodable PEM/DER envelope — that cert can't reach a standard
    // TLS gate either, so fall back to a stable hash of the returned bytes:
    // issuance always surfaces a revocable id and never crashes.
    var fingerprint;
    try {
      fingerprint = bCrypto().hashCertFingerprint(certPem).hex;
    } catch (_fpErr) {
      fingerprint = bCrypto().sha3Hash(certPem);
    }
    return {
      serialNumber: serialNumber,
      fingerprint:  fingerprint,
    };
  }

  // Build the engine call args for a leaf/PKCS#12 issuance. The leaf follows the
  // CA's algorithm: the pin when set (initCA already verified it matches the
  // stored CA), otherwise — for the BUNDLED engine only — the stored CA's own
  // algorithm, so an unpinned upgrade over an existing classical CA keeps issuing
  // classical leaves instead of the engine's ML-DSA process default. A custom
  // engine gets no inferred algorithm (its label set / key curve is its own to
  // resolve; the bundled ECDSA-P384-SHA384 label would break it). An explicit
  // opts2.algorithm always wins.
  function _leafEngineArgs(ca, opts2) {
    var leafAlg = caAlgorithm;
    if (leafAlg === undefined) {
      // The stored CA's own key type maps to the BUNDLED engine's label set, so
      // the inference is USED only for that engine — a custom engine resolves its
      // own algorithm from its own key (injecting the bundled ECDSA-P384-SHA384
      // label would break a P-256/P-521 or custom-labeled engine that validates
      // its option shape).
      var caKeyLabel = _labelForCaKeyType(ca.caKeyPem);
      if (usesDefaultEngine) leafAlg = caKeyLabel;
    }
    var args = Object.assign({}, opts2, { caCertPem: ca.caCertPem, caKeyPem: ca.caKeyPem });
    if (leafAlg !== undefined) {
      // The resolved CA algorithm (a pin verified against the stored CA, or the
      // bundled engine's stored-CA inference) is AUTHORITATIVE and wins over a
      // per-issuance opts.algorithm: silently honoring a conflicting one would let
      // a classical ECDSA CA issue an ML-DSA leaf its legacy peers can't
      // authenticate (and mis-select the P12 MAC tier). Refuse a conflict outright
      // rather than issue a leaf that doesn't match the CA the operator pinned.
      if (opts2.algorithm !== undefined && opts2.algorithm !== leafAlg) {
        throw new MtlsCaError("mtls-ca/algorithm-conflict",
          "generateClientCert/generateClientP12: opts.algorithm " + JSON.stringify(opts2.algorithm) +
          " conflicts with the CA's algorithm " + JSON.stringify(leafAlg) +
          " (the leaf must match the CA; rotate to a fresh CA to change algorithms)");
      }
      args.algorithm = leafAlg;
    }
    // When leafAlg is undefined (a custom engine), opts2.algorithm passes through
    // for the engine to resolve; caCertPem/caKeyPem are forced last so opts2 can't
    // shadow them.
    return args;
  }

  async function generateClientCert(opts2) {
    opts2 = opts2 || {};
    var ca = await initCA();
    var args = _leafEngineArgs(ca, opts2);
    var result = await engine.signClientCert(args);
    if (!result || typeof result.cert !== "string" || typeof result.key !== "string") {
      throw new MtlsCaError("mtls-ca/bad-engine-output",
        "engine.signClientCert must return { cert, key, ca?, issuedAt?, expiresAt? }");
    }
    // Surface the issued serial + fingerprint so the caller can track/revoke
    // the cert by the same identifiers without re-parsing the PEM.
    var id = _certIdentity(result.cert);
    _recordIssuance(ca.caCertPem, id);
    return Object.assign({}, result, { serialNumber: id.serialNumber, fingerprint: id.fingerprint });
  }

  async function generateClientP12(opts2) {
    opts2 = opts2 || {};
    if (!opts2.password || typeof opts2.password !== "string") {
      throw new MtlsCaError("mtls-ca/no-password",
        "generateClientP12 requires opts.password (the PKCS#12 encryption password)");
    }
    var ca = await initCA();
    // Leaf (and its P12 MAC tier) follows the CA's algorithm via the shared
    // arg-builder — the pin when set, else the bundled engine's stored-CA
    // inference, never a custom engine's inferred label or the process default.
    var args = _leafEngineArgs(ca, opts2);
    var result = await engine.packageP12(args);
    if (!result || !Buffer.isBuffer(result.p12)) {
      throw new MtlsCaError("mtls-ca/bad-engine-output",
        "engine.packageP12 must return { p12: Buffer, certPem, issuedAt, expiresAt }");
    }
    // certPem is required engine output: it is the identity _recordIssuance
    // writes to the ledger. Without it the archive would be untracked and
    // revokeGeneration() could never deny it — refuse rather than return it.
    if (typeof result.certPem !== "string") {
      throw new MtlsCaError("mtls-ca/bad-engine-output",
        "engine.packageP12 must return a certPem string so the archive is recorded in the issuance " +
        "ledger — an unrecorded P12 could not be revoked by revokeGeneration()");
    }
    var id12 = _certIdentity(result.certPem);
    _recordIssuance(ca.caCertPem, id12);
    return Object.assign({}, result, { serialNumber: id12.serialNumber, fingerprint: id12.fingerprint });
  }

  // ---- Revocation registry + CRL ----

  // Revocation entries are read + written through a store so the registry can
  // live somewhere other than the default plaintext revocations.json — e.g. an
  // operator-supplied encrypted / clustered store (the bring-your-own-store
  // precedent b.queue's config.db set). Contract (sync):
  //   list()     -> array of revocation entries
  //   add(entry) -> append one entry (the caller has already deduped)
  function _defaultFileStore() {
    function _list() {
      if (!nodeFs.existsSync(paths.revocations)) return [];
      try {
        // safeJson.parse caps depth + size + protects against
        // proto-pollution; a tampered or truncated file shouldn't be able to
        // corrupt the rotator process.
        var json = safeJson.parse(atomicFile.fdSafeReadSync(paths.revocations, { maxBytes: C.BYTES.mib(16), encoding: "utf8" }),
          { maxBytes: C.BYTES.mib(16) });
        return (json && Array.isArray(json.revocations)) ? json.revocations : [];
      } catch (e) {
        /* c8 ignore next 2 -- defensive: safeJson.parse throws an Error with a message, so the String(e) fallback is unreachable */
        throw new MtlsCaError("mtls-ca/revocation-corrupt",
          "could not parse " + paths.revocations + ": " + ((e && e.message) || String(e)));
      }
    }
    return {
      list: _list,
      add:  function (entry) {
        var entries = _list();
        entries.push(entry);
        atomicFile.writeSync(paths.revocations,
          JSON.stringify({ revocations: entries }, null, 2) + "\n", { mode: 0o600 });
      },
    };
  }
  var revocationStore = opts.revocationStore || _defaultFileStore();
  validateOpts.requireMethods(revocationStore, ["list", "add"],
    "opts.revocationStore", MtlsCaError, "mtls-ca/bad-revocation-store");

  // Issuance ledger — same bring-your-own-store contract as revocationStore
  // ({ list(), add(entry) }). Every generateClientCert/generateClientP12
  // appends { serialNumber, fingerprint, generation, issuedAt } so
  // revokeGeneration(n) can find the certs a superseded CA generation signed.
  function _defaultIssuanceStore() {
    function _list() {
      if (!nodeFs.existsSync(paths.issuance)) return [];
      try {
        var json = safeJson.parse(atomicFile.fdSafeReadSync(paths.issuance, { maxBytes: C.BYTES.mib(16), encoding: "utf8" }),
          { maxBytes: C.BYTES.mib(16) });
        return (json && Array.isArray(json.issued)) ? json.issued : [];
      } catch (e) {
        /* c8 ignore next 2 -- defensive: safeJson.parse throws an Error with a message, so the String(e) fallback is unreachable */
        throw new MtlsCaError("mtls-ca/issuance-corrupt",
          "could not parse " + paths.issuance + ": " + ((e && e.message) || String(e)));
      }
    }
    return {
      list: _list,
      add:  function (entry) {
        var entries = _list();
        entries.push(entry);
        atomicFile.writeSync(paths.issuance,
          JSON.stringify({ issued: entries }, null, 2) + "\n", { mode: 0o600 });
      },
    };
  }
  var issuanceStore = opts.issuanceStore || _defaultIssuanceStore();
  validateOpts.requireMethods(issuanceStore, ["list", "add"],
    "opts.issuanceStore", MtlsCaError, "mtls-ca/bad-issuance-store");

  // Record an issued leaf in the ledger. Fail-closed: the ledger is the SOLE
  // index revokeGeneration() consults, so a cert absent from it can never be
  // revoked by generation and would stay accepted by fingerprint-based
  // enforcement. A write failure (disk full, the 16 MiB cap crossed, a custom
  // store throwing) therefore FAILS issuance rather than returning an untracked
  // credential — the caller must resolve the persistence fault and re-issue.
  function _recordIssuance(caCertPem, id) {
    try {
      issuanceStore.add({
        serialNumber: id.serialNumber,
        fingerprint:  id.fingerprint,
        generation:   parseGeneration(caCertPem),
        issuedAt:     Date.now(),
      });
    } catch (e) {
      throw new MtlsCaError("mtls-ca/issuance-ledger-write-failed",
        "certificate " + id.serialNumber + " was signed but could not be recorded in the issuance " +
        "ledger (" + paths.issuance + "): " + ((e && e.message) || String(e)) +
        " — refusing to return an untracked credential revokeGeneration() could not later revoke");
    }
  }

  // A fingerprint is the SHA3-512 hex the require-mtls gate pins. Normalize it
  // like a serial (strip 0x / separators / whitespace, lowercase, hex-validate)
  // so a consumer can revoke by the same value the gate compares against.
  function _normalizeFingerprint(fp) {
    if (!fp || typeof fp !== "string") {
      throw new MtlsCaError("mtls-ca/bad-fingerprint", "fingerprint must be a non-empty string");
    }
    var stripped = fp.replace(/^0x/i, "").replace(/[:\-\s]/g, "");
    if (!safeBuffer.isHex(stripped)) {
      throw new MtlsCaError("mtls-ca/bad-fingerprint",
        "fingerprint contains non-hex characters: " + JSON.stringify(fp));
    }
    return stripped.toLowerCase();
  }

  function _normalizeSerial(s) {
    if (!s || typeof s !== "string") {
      throw new MtlsCaError("mtls-ca/bad-serial",
        "serial number must be a non-empty string");
    }
    // Strip the optional leading `0x` and any common separators
    // (`:` or `-` or whitespace). What remains MUST be hex — otherwise
    // we silently accept gibberish like "xyz-not-hex" (which previously
    // normalised to a single "e" because the strip-non-hex regex left
    // exactly one valid char). Operators pasting an openssl-printed
    // serial use any of: "0xABC123", "AB:C1:23", "AB-C1-23", "abc 123";
    // a typo or non-serial string fails fast instead of registering a
    // phantom revocation row.
    var stripped = s.replace(/^0x/i, "").replace(/[:\-\s]/g, "");
    if (!safeBuffer.isHex(stripped)) {
      throw new MtlsCaError("mtls-ca/bad-serial",
        "serial number contains non-hex characters " +
        "(allowed shapes: hex with optional 0x prefix, ':', '-', or whitespace " +
        "as separators): " + JSON.stringify(s));
    }
    return stripped.toLowerCase();
  }

  // Map operator-friendly reason codes to RFC 5280 numeric codes used by X.509
  // CRLs. Default "unspecified" (0) when omitted. removeFromCRL (code 8) is
  // deliberately absent: it is a DELTA-CRL directive to UN-revoke a cert from the
  // base CRL, not a revocation reason, and is invalid in a full CRL (all this CA
  // issues) — the toolkit refuses it at sign time, so a persisted code-8 entry
  // would poison every later generateCrl(). revoke() rejects it explicitly below.
  var CRL_REASON_BY_NAME = {
    "unspecified":          0,
    "keyCompromise":        1,
    "key-compromise":       1,
    "caCompromise":         2,
    "ca-compromise":        2,
    "affiliationChanged":   3,
    "superseded":           4,
    "cessationOfOperation": 5,
    "cessation-of-operation": 5,
    "certificateHold":      6,
    "privilegeWithdrawn":   9,
    "aACompromise":         10,
  };

  function revoke(idOrOpts, opts3) {
    // Accept either revoke(serialString, { reason, fingerprint }) — the
    // backward-compatible serial-keyed form — or revoke({ serial?,
    // fingerprint?, reason? }). The require-mtls gate denies by fingerprint,
    // so a fingerprint-indexed consumer can revoke by the same value it pins
    // on; serial-keyed behavior stays the default. At least one key required.
    var spec = (idOrOpts && typeof idOrOpts === "object") ? idOrOpts : null;
    opts3 = opts3 || {};
    var serialIn      = spec ? spec.serial      : idOrOpts;
    var fingerprintIn = spec ? spec.fingerprint : opts3.fingerprint;
    var reasonName    = (spec ? spec.reason : opts3.reason) || "unspecified";

    var serial = (serialIn !== undefined && serialIn !== null) ? _normalizeSerial(serialIn) : null;
    var fingerprint = (fingerprintIn !== undefined && fingerprintIn !== null)
      ? _normalizeFingerprint(fingerprintIn) : null;
    if (!serial && !fingerprint) {
      throw new MtlsCaError("mtls-ca/no-revocation-key",
        "revoke requires a serial number or a fingerprint " +
        "(revoke(serial, opts) or revoke({ serial, fingerprint }))");
    }
    if (reasonName === "removeFromCRL") {
      throw new MtlsCaError("mtls-ca/bad-reason",
        "revoke: 'removeFromCRL' (RFC 5280 code 8) is a delta-CRL un-revocation " +
        "directive, not a revocation reason — this CA issues full CRLs only, and a " +
        "persisted code-8 entry would make every generateCrl() fail");
    }
    var reasonCode = CRL_REASON_BY_NAME[reasonName];
    if (reasonCode === undefined) {
      throw new MtlsCaError("mtls-ca/bad-reason",
        "revoke: unknown reason '" + reasonName + "' (valid: " +
        Object.keys(CRL_REASON_BY_NAME).join(", ") + ")");
    }
    var existing = revocationStore.list().find(function (r) {
      var serialMatch = serial && r.serialNumber === serial;
      var fingerprintMatch = fingerprint && r.fingerprint === fingerprint;
      if (!serialMatch && !fingerprintMatch) return false;
      // A TRUE duplicate already carries every identifier this call supplies.
      // A serial-only entry matched by a revoke({ serial, fingerprint }) call
      // (the shape revokeGeneration uses) is NOT a duplicate — its fingerprint
      // is missing, so the require-mtls gate (fingerprint-keyed) would still
      // admit the cert. Fall through and record the fingerprint-bearing entry.
      var coversSerial = !serial || r.serialNumber === serial;
      var coversFingerprint = !fingerprint || r.fingerprint === fingerprint;
      return coversSerial && coversFingerprint;
    });
    if (existing) {
      // Idempotent — repeated revoke() of the same serial/fingerprint doesn't
      // shift the revokedAt timestamp.
      return existing;
    }
    var entry = {
      serialNumber: serial,
      fingerprint:  fingerprint,
      reason:       reasonName,
      reasonCode:   reasonCode,
      revokedAt:    Date.now(),
    };
    revocationStore.add(entry);
    return entry;
  }

  function isRevoked(serialOrFingerprint) {
    // Accept a serial number OR a SHA3-512 fingerprint — both are hex, so one
    // normalized form is matched against either key each entry carries.
    if (!serialOrFingerprint || typeof serialOrFingerprint !== "string") {
      throw new MtlsCaError("mtls-ca/bad-revocation-key",
        "isRevoked requires a serial number or a fingerprint (hex string)");
    }
    var norm = _normalizeFingerprint(serialOrFingerprint);
    return revocationStore.list().some(function (r) {
      return r.serialNumber === norm || r.fingerprint === norm;
    });
  }

  function getRevocations() {
    return revocationStore.list().slice();
  }

  // Generate a signed X.509 CRL covering every entry in the registry.
  // RFC 5280 — issuer = CA subject, signed by the CA private key.
  // Operators publish the resulting PEM at a CRL distribution point
  // referenced from issued certs (cert extension support is on the
  // engine roadmap; for now operators set up the URL externally).
  async function generateCrl(opts3) {
    opts3 = opts3 || {};
    if (typeof engine.generateCrl !== "function") {
      throw new MtlsCaError("mtls-ca/engine-no-crl",
        "configured engine does not implement generateCrl(); use the " +
        "framework's bundled CA engine, which supports it");
    }
    var ca = await initCA();
    var allRevocations = revocationStore.list();
    // A standard X.509 CRL (RFC 5280 §5.1) is keyed by certificate serial
    // number. revoke({ fingerprint }) — a first-class revocation mode, and the
    // value the require-mtls gate pins on — stores no serial (serialNumber is
    // null). Such an entry cannot be represented in a CRL, so project it out
    // here rather than handing a null serial to the CRL encoder: the encoder
    // throws on it, which would break CRL generation for the ENTIRE registry,
    // dropping the serial-keyed certs that CAN be published from every fresh
    // CRL (a fail-open for those certs' published revocation). Fingerprint-only
    // revocations stay enforced through isRevoked()/the mTLS gate, which is
    // fingerprint-aware; the count that could not be represented is surfaced.
    // Dedup by serial: one certificate can carry two registry entries (a
    // serial-only revocation plus a later serial+fingerprint one added when
    // revokeGeneration backfills the fingerprint), but a CRL must list each
    // serial once.
    var seenSerials = new Set();
    var revocations = allRevocations.filter(function (r) {
      if (!(r && r.serialNumber != null)) return false;
      if (seenSerials.has(r.serialNumber)) return false;
      seenSerials.add(r.serialNumber);
      return true;
    });
    // Count ONLY entries that genuinely lack a serial (fingerprint-only, thus
    // unrepresentable in an X.509 CRL). Deriving this from allRevocations.length
    // - revocations.length would wrongly fold in the serial DUPLICATES the dedup
    // above dropped, over-reporting the CRL as incomplete when those serials are
    // in fact published.
    var fingerprintOnlyOmitted = allRevocations.filter(function (r) {
      return r && r.serialNumber == null;
    }).length;
    var nowMs = Date.now();
    var thisUpdate = opts3.thisUpdate || new Date(nowMs);
    var nextUpdate = opts3.nextUpdate ||
                     new Date(nowMs + C.TIME.days(7));   // 7d default
    var crlPem = await engine.generateCrl({
      caCertPem:   ca.caCertPem,
      caKeyPem:    ca.caKeyPem,
      revocations: revocations,
      thisUpdate:  thisUpdate,
      nextUpdate:  nextUpdate,
    });
    if (typeof crlPem !== "string" || crlPem.length === 0) {
      throw new MtlsCaError("mtls-ca/bad-engine-output",
        "engine.generateCrl must return a non-empty PEM string");
    }
    if (opts3.persist !== false) {
      atomicFile.writeSync(paths.crl, crlPem, { mode: 0o644 });
    }
    return { crlPem: crlPem, thisUpdate: thisUpdate, nextUpdate: nextUpdate,
             entryCount: revocations.length,
             fingerprintOnlyOmitted: fingerprintOnlyOmitted,
             path: paths.crl };
  }

  // ---- Algorithm migration (issue #532) ----

  async function rotate(rotateOpts) {
    rotateOpts = rotateOpts || {};
    var st = status();
    var previousCaCertPem = st.exists ? loadCert().toString("utf8") : null;
    var curGen = st.exists ? st.generation : 0;
    // Validate the ORIGINAL value before any normalization: Math.floor would
    // silently accept 1.9 / 2.9 as generation 1 / 2, committing the CA under a
    // different generation than requested and mis-assigning its revocation cohort.
    if (rotateOpts.generation !== undefined && rotateOpts.generation !== null &&
        (typeof rotateOpts.generation !== "number" || !Number.isInteger(rotateOpts.generation))) {
      throw new MtlsCaError("mtls-ca/bad-generation",
        "rotate: generation must be a positive integer, got " + JSON.stringify(rotateOpts.generation));
    }
    var newGen = (rotateOpts.generation !== undefined && rotateOpts.generation !== null)
      ? rotateOpts.generation : curGen + 1;
    if (typeof newGen !== "number" || !isFinite(newGen) || newGen < 1) {
      throw new MtlsCaError("mtls-ca/bad-generation",
        "rotate: generation must be a positive integer, got " + JSON.stringify(rotateOpts.generation));
    }
    if (st.exists && newGen <= curGen) {
      throw new MtlsCaError("mtls-ca/bad-generation",
        "rotate: generation " + newGen + " must be greater than the current CA generation " +
        curGen + " — a rotation moves forward (use a fresh dataDir to reset generations)");
    }
    // The pin threads into generateCa exactly as create({ algorithm }) / initCA
    // do; a per-call rotate({ algorithm }) overrides the create-time pin so an
    // operator can flip a stored classical CA to the ML-DSA default (or back)
    // WITHOUT the mtls-ca/algorithm-mismatch initCA raises — rotation is the
    // sanctioned path to change a CA's algorithm.
    var genArgs = { generation: newGen };
    var pin = rotateOpts.algorithm !== undefined ? rotateOpts.algorithm : caAlgorithm;
    if (pin !== undefined) genArgs.algorithm = pin;
    var fresh = await engine.generateCa(genArgs);
    if (!fresh || typeof fresh.caCertPem !== "string" || typeof fresh.caKeyPem !== "string") {
      throw new MtlsCaError("mtls-ca/bad-engine-output",
        "engine.generateCa must return { caCertPem, caKeyPem }");
    }
    // retainPrevious defaults ON for a rotation (the grace window is the point);
    // pass retainPrevious:false to overwrite without retaining the old CA.
    var retain = rotateOpts.retainPrevious !== false && previousCaCertPem !== null;
    commit({ caKeyPem: fresh.caKeyPem, caCertPem: fresh.caCertPem, retainPrevious: retain });
    // Persist the effective algorithm on the handle. Without this, a handle
    // created with an algorithm pin that then rotate({ algorithm })s to a
    // different one keeps the stale closed-over pin, so the next initCA() (via
    // generateClientCert / generateClientP12) compares it against the new stored
    // CA and throws mtls-ca/algorithm-mismatch — the handle would be unusable
    // immediately after a successful rotation.
    if (rotateOpts.algorithm !== undefined) caAlgorithm = rotateOpts.algorithm;
    caLog.info("rotated CA", { generation: newGen, retainedPrevious: retain });
    return {
      caCertPem:         fresh.caCertPem,
      previousCaCertPem: previousCaCertPem,
      generation:        newGen,
      algorithm:         _certAlgorithm(fresh.caCertPem).algorithm,
    };
  }

  function loadTrustBundle() {
    var bundle = [];
    if (nodeFs.existsSync(paths.caCert)) {
      bundle.push(loadCert().toString("utf8"));
    }
    if (nodeFs.existsSync(paths.caCertPrev)) {
      bundle.push(atomicFile.fdSafeReadSync(paths.caCertPrev, { maxBytes: C.BYTES.mib(1) }).toString("utf8"));
    }
    return bundle;
  }

  function dropRetained() {
    var had = nodeFs.existsSync(paths.caCertPrev);
    if (had) nodeFs.unlinkSync(paths.caCertPrev);
    return { dropped: had };
  }

  // Revoke every cert the issuance ledger recorded under a CA generation < n.
  // Enforcement is fingerprint-keyed through the revocation registry —
  // isRevoked() and a require-mtls gate wired with `revocationSource: caHandle`
  // deny these certs regardless of which CA generation issued them. A standard
  // X.509 CRL cannot: generateCrl() signs with the CURRENT CA, which a peer will
  // not accept as revoking a cert issued by a superseded generation. For a CRL-
  // consuming deployment, publish generateCrl() for a generation while it is
  // still current (before rotate() supersedes its signing key); the registry
  // path above needs no such ordering.
  function revokeGeneration(n, opts3) {
    if (typeof n !== "number" || !isFinite(n) || n < 1 || Math.floor(n) !== n) {
      throw new MtlsCaError("mtls-ca/bad-generation",
        "revokeGeneration: n must be a positive integer (revokes every cert issued under a CA generation < n)");
    }
    opts3 = opts3 || {};
    var reason = opts3.reason || "superseded";
    var before = revocationStore.list().length;
    issuanceStore.list().forEach(function (e) {
      if (e && typeof e.generation === "number" && e.generation < n && (e.serialNumber || e.fingerprint)) {
        revoke({ serial: e.serialNumber || null, fingerprint: e.fingerprint || null, reason: reason });
      }
    });
    return { revoked: revocationStore.list().length - before };
  }

  // CA-handle convenience over the engine probe: can node:tls VERIFY a chain
  // under THIS CA's algorithm on this runtime? Delegates to engine.canVerifyInTls
  // with the stored CA's algorithm label (or the create-time pin / engine
  // default when no CA is stored yet).
  async function canVerifyInTls() {
    if (typeof engine.canVerifyInTls !== "function") {
      throw new MtlsCaError("mtls-ca/no-tls-probe",
        "the configured engine does not implement canVerifyInTls(label)");
    }
    var st = status();
    return engine.canVerifyInTls(st.algorithm || caAlgorithm);
  }

  return {
    exists:               exists,
    keyExists:            keyExists,
    status:               status,
    loadKey:              loadKey,
    loadCert:             loadCert,
    loadTrustBundle:      loadTrustBundle,
    commit:               commit,
    initCA:               initCA,
    rotate:               rotate,
    dropRetained:         dropRetained,
    canVerifyInTls:       canVerifyInTls,
    revokeGeneration:     revokeGeneration,
    generateClientCert:   generateClientCert,
    generateClientP12:    generateClientP12,
    revoke:               revoke,
    isRevoked:            isRevoked,
    getRevocations:       getRevocations,
    generateCrl:          generateCrl,
    paths:                paths,
    generation:           generation,
    caKeySealedMode:      caKeySealedMode,
  };
}

module.exports = {
  create:           create,
  parseGeneration:  parseGeneration,
  MtlsCaError:      MtlsCaError,
  DEFAULT_PATHS:    DEFAULT_PATHS,
};
