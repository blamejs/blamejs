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
var safeAsync = require("./safe-async");
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
  // Revoked-generation watermark — the highest n passed to revokeGeneration().
  // A leaf whose signing straddled a rotate()+revokeGeneration() is recorded in
  // the ledger AFTER the sweep read it, so at record time issuance compares its
  // generation against this watermark and revokes itself if the generation has
  // already been swept — closing the issuance-vs-generation-revocation race.
  revokedGeneration: "revoked-generation",
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
    revokedGeneration: _absoluteOrUnderDataDir(dataDir, p.revokedGeneration),
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
 *   revocationStore:  object,                                  // bring-your-own { list(), add(entry) } for the revocation registry; default is a JSON file under dataDir. For a CLUSTERED deployment (shared store, per-host dataDir) also expose { readGenerationWatermark(), bumpGenerationWatermark(n) } so the issuance-supersede watermark is shared across hosts
 *
 * The handle also supports a non-breaking CA algorithm migration: status()
 * reports the stored CA's algorithm / keyType; rotate({ generation, algorithm })
 * generates and atomically commits a new CA (returning { caCertPem,
 * previousCaCertPem }) without the algorithm-mismatch initCA raises;
 * commit({ retainPrevious:true }) + loadTrustBundle() + dropRetained() keep the
 * superseded CA trusted during a re-enrollment grace window; canVerifyInTls(algorithm?)
 * runs a loopback mTLS self-test proving node:tls verifies a given algorithm on
 * this runtime (pass the prospective algorithm to pre-flight a migration before
 * rotating to it); revokeGeneration(n) revokes every cert the issuance ledger
 * recorded under a CA generation below n; and importIssuance(entries) backfills
 * leaf identities the ledger lacks (a pre-upgrade dataDir or out-of-band certs)
 * so revokeGeneration can sweep them.
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
    var cert = new nodeCrypto.X509Certificate(certPem);
    var pub = cert.publicKey;
    var type = String(pub.asymmetricKeyType || "").toLowerCase();
    if (type === "ec") {
      // The framework's sole classical label (ECDSA-P384-SHA384) is P-384 /
      // secp384r1 signed with SHA-384. A custom engine may issue a P-256 / P-521
      // EC CA, or a P-384 CA signed with SHA-256 — node still reports "ec", so
      // require BOTH the curve AND the SHA-384 signature before labeling;
      // otherwise return null (a wrong label misreports status() and feeds a bad
      // label to a custom engine's canVerifyInTls()).
      var curve = pub.asymmetricKeyDetails && pub.asymmetricKeyDetails.namedCurve
        ? String(pub.asymmetricKeyDetails.namedCurve).toLowerCase() : null;
      var sigAlg = String(cert.signatureAlgorithm || "").toLowerCase();
      var isP384Sha384 = curve === CLASSICAL_CA_CURVE && /sha-?384/.test(sigAlg);
      return { keyType: type, algorithm: isP384Sha384 ? "ECDSA-P384-SHA384" : null };
    }
    return { keyType: type || null, algorithm: _labelForKeyType(type) || null };
  } catch (_e) {
    return { keyType: null, algorithm: null };
  }
}

// Does this CA cert's public key correspond to this CA private key? A rotation
// renames the key and cert as two separate steps, so an issuer reading the pair
// mid-rotation can combine the old cert with the new key. initCA re-reads until
// this holds. Returns true for a cert/key node can't parse (a custom engine owns
// its own pairing; the two-file rename race is specific to the default store).
function _caPairConsistent(certPem, keyPem) {
  try {
    var certSpki = new nodeCrypto.X509Certificate(certPem).publicKey.export({ type: "spki", format: "der" });
    var keySpki = nodeCrypto.createPublicKey(keyPem).export({ type: "spki", format: "der" });
    return Buffer.from(certSpki).equals(Buffer.from(keySpki));
  } catch (_e) {
    return true;
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
  // Ensure the parent directory of every managed path exists. atomicFile.lock()
  // opens `<path>.lock` directly and does NOT create the parent, so a nested
  // operator path (e.g. paths.revocations = "state/revocations.json") would make
  // the first locked revoke()/issuance/rotation fail ENOENT before the store's
  // own writeSync (which used to create it). Create the parents up front.
  [paths.caKey, paths.caKeySealed, paths.caCert, paths.caCertPrev,
   paths.revocations, paths.crl, paths.issuance, paths.revokedGeneration].forEach(function (p) {
    var dir = nodePath.dirname(p);
    if (!nodeFs.existsSync(dir)) nodeFs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  });
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
  // The commit body. MUST run under atomicFile.lock(paths.caCert): the journal
  // write, key/cert renames, retained-root update, and journal delete are a single
  // critical section — two unlocked commits over one dataDir would race the staged
  // temp files and each other's renames, clobbering the CA. rotate() already holds
  // the lock; the public commit() below acquires it.
  function _commitLocked(opts2) {
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
    // Capture the PRIOR retained root so a rollback can restore it if the final
    // cert rename fails after we overwrote/removed ca.prev.crt — a failed rotation
    // must not strand clients still enrolled under the previously-retained CA.
    var priorPrevExisted = nodeFs.existsSync(paths.caCertPrev);
    var priorPrev = null;
    if (priorPrevExisted) {
      try { priorPrev = atomicFile.fdSafeReadSync(paths.caCertPrev, { maxBytes: C.BYTES.mib(1) }); }
      catch (_e) { priorPrev = null; }
    }
    // Single retained grace window at a time — enforced HERE so EVERY retention
    // entry point is covered (rotate() AND the public commit(), which calls
    // _commitLocked directly). ca.prev.crt holds one prior root; a second retained
    // commit would overwrite it and strand clients still enrolled under the first
    // retained generation. End the existing window explicitly (dropRetained(), or a
    // retainPrevious:false commit that hard-cuts) before retaining again.
    if (outgoingCaCert !== null && priorPrevExisted) {
      throw new MtlsCaError("mtls-ca/retained-root-exists",
        "a retained root from a prior rotation is still present at " + paths.caCertPrev + " — a second " +
        "retained rotation would drop it and reject clients still enrolled under it. End the existing grace " +
        "window with dropRetained(), or rotate({ retainPrevious: false }) to hard-cut, before rotating again");
    }
    // A commit while a grace window is open MUST state its retention intent. With
    // retainPrevious OMITTED, outgoingCaCert is null (so the single-window guard above
    // does not fire) AND the hard-cut branch below (retainPrevious === false) does not
    // fire either — so the outgoing retained root is left untouched while the active
    // cert is replaced, silently dropping trust for the just-superseded generation (its
    // cert becomes neither the new current nor the retained root). Refuse an ambiguous
    // commit: rotate()/first-init always pass a boolean, so this binds only the public
    // commit() legacy form. End the window (dropRetained() / rotate({ retainPrevious:
    // false })), or pass retainPrevious explicitly.
    if (priorPrevExisted && typeof opts2.retainPrevious !== "boolean") {
      throw new MtlsCaError("mtls-ca/retention-intent-required",
        "a retained root from a prior rotation is present at " + paths.caCertPrev + " — a commit that omits " +
        "retainPrevious would replace the active CA while leaving that root, dropping trust for the just-" +
        "superseded generation. Pass retainPrevious explicitly (false to hard-cut), or dropRetained() first");
    }
    var sealed = caKeySealedMode === "required";
    var keyDest = sealed ? paths.caKeySealed : paths.caKey;
    // Random-token temp names (not fixed ".tmp"): an O_EXCL create through a fixed
    // name would EEXIST against a crash residue OR a concurrent writer's staged
    // file — a spurious commit-failed, or a cross-process clobber. A per-commit
    // token makes both impossible (matches atomicFile.writeSync's tmp scheme).
    var commitTok = bCrypto().generateToken(C.BYTES.bytes(8));
    var keyTmp = keyDest + ".tmp-" + commitTok;
    var certTmp = paths.caCert + ".tmp-" + commitTok;
    // Capture the PRIOR key bytes so a failed cert publish can restore them too —
    // the key rename runs before the cert rename, so without this a rotation that
    // fails at the cert step would leave the new key beside the OLD cert (a
    // permanently mismatched, unusable pair). Raw on-disk bytes (sealed or plain).
    var priorKeyExisted = nodeFs.existsSync(keyDest);
    var priorKey = null;
    if (priorKeyExisted) {
      try { priorKey = atomicFile.fdSafeReadSync(keyDest, { maxBytes: C.BYTES.mib(1) }); }
      catch (_e) { priorKey = null; }
    }
    // The current cert BEFORE this rotation republishes it. Recorded in the journal
    // so recovery (and loadTrustBundle) can tell an INTERRUPTED rotation — the live
    // cert still equals this prior one, so the cert was never republished and the
    // journal's saved retained root must be trusted / restored — from a COMPLETED
    // one — the live cert differs, so the journal is spent and its old retained
    // root must NOT be re-trusted (which would defeat a hard cutoff).
    var priorCert = null;
    if (nodeFs.existsSync(paths.caCert)) {
      try { priorCert = atomicFile.fdSafeReadSync(paths.caCert, { maxBytes: C.BYTES.mib(1) }); }
      catch (_e) { priorCert = null; }
    }
    // Abort if ANY existing prior artifact could not be captured for the journal.
    // The rollback journal must hold a complete snapshot of the pre-rotation state:
    //   - the KEY, or a failed publish strands the CA on a new-key/old-cert pair;
    //   - the CERT, or the interrupted-vs-completed comparison (live cert == prior
    //     cert) cannot run, so reconcile could delete a newly-established grace root
    //     or restore a hard-cut one;
    //   - the RETAINED ROOT, or a failed hard-cut rotation cannot restore it.
    // A transient read fault on any of these must not silently produce a partial
    // journal that later mis-reconciles — refuse to mutate the CA and let the
    // operator resolve the fault and retry.
    if (priorKeyExisted && priorKey === null) {
      throw new MtlsCaError("mtls-ca/prior-key-unreadable",
        "the existing CA key at " + keyDest + " could not be read to capture a rollback copy — refusing to " +
        "overwrite it (a failed publish would otherwise strand the CA); resolve the read fault and retry");
    }
    if (nodeFs.existsSync(paths.caCert) && priorCert === null) {
      throw new MtlsCaError("mtls-ca/prior-cert-unreadable",
        "the existing CA certificate at " + paths.caCert + " could not be read to capture the rollback " +
        "journal's prior-cert marker — refusing to rotate (a partial journal could mis-reconcile the " +
        "retained root after a crash); resolve the read fault and retry");
    }
    if (priorPrevExisted && priorPrev === null) {
      throw new MtlsCaError("mtls-ca/prior-retained-root-unreadable",
        "the existing retained root at " + paths.caCertPrev + " could not be read to capture a rollback " +
        "copy — refusing to rotate (a failed rotation could otherwise permanently lose it, stranding clients " +
        "in the existing grace window); resolve the read fault and retry");
    }
    // Crash-recovery rollback journal. The CA key, current cert, and retained root
    // (ca.prev.crt) are separate files, so the renames/writes below cannot be one
    // atomic swap: if the process dies mid-publish, the in-memory catch rollback
    // never runs and BOTH the prior key (already overwritten) and the prior
    // retained root (already replaced or removed) are otherwise unrecoverable —
    // stranding the CA (mtls-ca/ca-pair-inconsistent) AND dropping trust for
    // clients still enrolled under the formerly-retained generation. Persist both
    // prior artifacts durably (fsync'd) BEFORE mutating them; the journal's
    // presence is the "rotation in progress" marker _reconcileCommitJournalLocked()
    // rolls back from, and a clean commit removes it once the new state is durably
    // consistent. Manifest: key = base64 prior key bytes; prevAction/prevData
    // capture the prior ca.prev.crt (restore its bytes, delete a prev this rotation
    // created, or leave an unreadable prior untouched — mirroring the catch).
    var keyJournal = keyDest + ".rollback";
    var keyJournalWritten = false;
    // The stale CRL is invalidated by moving it ASIDE to a fixed rollback name BEFORE
    // the cert publish, then deleting it once the new cert lands (see the CRL block
    // below). Capturing crlExisted + crlRollback here (function scope) lets the catch
    // restore it: the CA it rolled back to is still active, so its CRL is still valid
    // and must keep being served. reconcile() drives the same fixed name.
    var crlRollback = _crlRollbackPath();
    var crlExisted = nodeFs.existsSync(paths.crl);

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
      // The NEW key in its on-disk form (sealed or plain) — written to the temp AND
      // recorded in the journal so recovery can complete a rotation whose key rename
      // was lost (a Windows/FUSE fsyncDir no-op) as byte-exactly as it can roll one
      // back, without depending on node being able to parse the key.
      var newKeyOnDisk = Buffer.from(sealed
        ? (_requireVault("sealed CA key commit"), vault.seal(opts2.caKeyPem))
        : opts2.caKeyPem);
      _writeExclusive(keyTmp, newKeyOnDisk, 0o600);
      _writeExclusive(certTmp, opts2.caCertPem, 0o644);
      // Persist a COMPLETE snapshot of the pre-rotation state AND the intended
      // post-rotation state before mutating anything, so recovery can drive the CA
      // to whichever state the rotation reached — byte-exact, engine-agnostic:
      //   key/cert       — the prior key + prior cert (the interrupted discriminator);
      //   newKey         — the new key, to finish a completed rotation whose key
      //                    rename didn't stick;
      //   retainAfter    — whether a COMPLETED rotation should retain the outgoing
      //                    root (= the prior cert) or hard-cut it;
      //   newCert        — the intended NEW cert, the completed-vs-interrupted
      //                    discriminator when there is NO prior cert (a key-only cold
      //                    start: ca.key present, ca.crt absent). Without it, reconcile
      //                    could not classify a completed key-only init (manifest.cert
      //                    is null) and would restore the orphaned prior key beside the
      //                    newly published cert, leaving the CA an unusable pair;
      //   prevAction/prevData — how to roll the retained root BACK on an interrupted
      //                    rotation ("restore" prior bytes / "delete" a prev this
      //                    rotation created / "leave" an unreadable prior).
      if (priorKeyExisted && priorKey !== null) {
        var prevAction = !priorPrevExisted ? "delete" : (priorPrev !== null ? "restore" : "leave");
        atomicFile.writeSync(keyJournal, JSON.stringify({
          key:         priorKey.toString("base64"),
          newKey:      newKeyOnDisk.toString("base64"),
          cert:        priorCert !== null ? priorCert.toString("base64") : null,
          newCert:     Buffer.from(opts2.caCertPem).toString("base64"),
          retainAfter: outgoingCaCert !== null,
          prevAction:  prevAction,
          prevData:    prevAction === "restore" ? priorPrev.toString("base64") : null,
        }), { fileMode: 0o600 });
        keyJournalWritten = true;
      }
      atomicFile.renameWithRetry(keyTmp, keyDest);
      // Make the KEY rename durable BEFORE publishing the cert. renameSync alone is
      // not crash-durable and keyDest/caCert can have distinct operator-configured
      // parents, so without this a power loss could persist the LATER cert rename
      // while losing the key rename — leaving an old-key/new-cert pair the journal
      // (which holds only the OLD key) cannot repair. Ordering the durability this
      // way means at every crash point the on-disk pair is either consistent or
      // recoverable from the OLD-key journal. fsyncDir is best-effort (Windows
      // rejects directory fsync), matching atomicFile's own durability contract.
      atomicFile.fsyncDir(nodePath.dirname(keyDest));
      // Publish the retained root BEFORE the new current cert, so a concurrent
      // loadTrustBundle() that observes the new ca.crt already sees the outgoing
      // root in ca.prev.crt — closing the window where only the new root would be
      // trusted. Both the retain write AND the retain:false removal are REQUIRED
      // parts of the commit: a failure throws to the outer catch, which rolls the
      // whole rotation back. Retaining but omitting the outgoing root breaks the
      // no-outage migration (clients under the superseded CA are rejected); failing
      // to remove the old root under retainPrevious:false silently keeps trusting a
      // root the operator asked to hard-cut, admitting certs chained to it. Never
      // publish a new CA whose trust bundle contradicts the requested retention.
      if (outgoingCaCert !== null) {
        // writeSync fsyncs its own file + directory, so the retain write is durable.
        atomicFile.writeSync(paths.caCertPrev, outgoingCaCert, { fileMode: 0o644 });
      } else if (opts2.retainPrevious === false && nodeFs.existsSync(paths.caCertPrev)) {
        nodeFs.unlinkSync(paths.caCertPrev);
        // Make the removal durable: ca.prev.crt may live in a different parent than
        // ca.crt (whose fsync below would not cover it), so without this a power
        // loss could resurrect the stale root after the rotation reported success,
        // leaving loadTrustBundle() trusting a root the operator hard-cut.
        atomicFile.fsyncDir(nodePath.dirname(paths.caCertPrev));
      }
      // Invalidate a persisted CRL as a REQUIRED part of the commit, but tie its fate
      // ATOMICALLY to the cert publication: this commit republishes the CA cert, so a
      // CRL persisted under the OLD cert becomes signed by a superseded issuer, yet if
      // the publish fails (or a crash intervenes) the OLD CA stays active and its CRL
      // is STILL VALID and must keep being served. So MOVE the CRL aside to a fixed
      // rollback name here (before the cert rename, the point of no return) rather than
      // deleting it: a failure to move it (e.g. paths.crl in a separately-configured
      // read-only directory) throws to the outer catch, which rolls the whole commit
      // back — the rename is a required precondition. Only AFTER the new cert lands is
      // the moved-aside CRL truly stale (its issuer is superseded), so it is deleted
      // then. A rollback (catch) or an interrupted-rotation reconcile renames it back;
      // a completed-rotation reconcile deletes it. fsyncDir is best-effort (it swallows
      // platform errors); only the rename can fail the commit.
      if (crlExisted) {
        atomicFile.renameWithRetry(paths.crl, crlRollback);
        atomicFile.fsyncDir(nodePath.dirname(paths.crl));
      }
      atomicFile.renameWithRetry(certTmp, paths.caCert);   // publish the new current LAST
      // Make the cert rename durable too (see the key-rename fsync note) before
      // removing the recovery journal below — else a power loss could persist the
      // journal deletion while losing the cert rename.
      atomicFile.fsyncDir(nodePath.dirname(paths.caCert));
      // The new cert is published — the moved-aside CRL is now signed by a superseded
      // issuer, so delete it for good (best-effort: a leftover is an unserved orphan at
      // the .rollback name, and a completed-rotation reconcile deletes it on next open).
      // A consumer regenerates the CRL under the new CA via generateCrl().
      if (crlExisted && nodeFs.existsSync(crlRollback)) {
        try {
          nodeFs.unlinkSync(crlRollback);
          atomicFile.fsyncDir(nodePath.dirname(crlRollback));
          caLog.info("invalidated stale CRL on CA change (regenerate with generateCrl)", { path: paths.crl });
        }
        /* c8 ignore next -- best-effort: unlink of the CRL we just moved aside does not throw here */
        catch (_ce) { caLog.debug("cleanup-failed", { op: "fs.unlinkSync", path: crlRollback, error: _ce.message }); }
      }
      // The new key/cert pair is durably published and consistent on disk — the
      // rollback journal has served its purpose; remove it (the commit point).
      if (keyJournalWritten) {
        try {
          nodeFs.unlinkSync(keyJournal);
          atomicFile.fsyncDir(nodePath.dirname(keyJournal));   // make the deletion durable
        }
        /* c8 ignore next -- best-effort: unlink of the journal we just wrote does not throw here */
        catch (_je) { caLog.debug("cleanup-failed", { op: "fs.unlinkSync", path: keyJournal, error: _je.message }); }
      }
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
      // The rotation FAILED (the new cert was not published). Roll back the two
      // artifacts the key rename + retained-root update already replaced, so the
      // previously-active CA survives intact: restore the prior KEY (else the new
      // key sits beside the old cert — a mismatched, unusable pair), and restore
      // the prior retained root (or remove a prev created for this failed attempt).
      var keyRolledBack = false;
      try {
        if (priorKeyExisted && priorKey !== null) {
          atomicFile.writeSync(keyDest, priorKey, { fileMode: 0o600 });
        }
        keyRolledBack = true;
      } catch (keyRbErr) {
        caLog.error("ca-key-rollback-failed",
          { path: keyDest, error: (keyRbErr && keyRbErr.message) || String(keyRbErr) });
      }
      var prevRolledBack = false;
      try {
        if (priorPrevExisted && priorPrev !== null) {
          atomicFile.writeSync(paths.caCertPrev, priorPrev, { fileMode: 0o644 });
        } else if (!priorPrevExisted && nodeFs.existsSync(paths.caCertPrev)) {
          // Remove the retained root THIS failed rotation created, and fsync its
          // parent so the removal is durable: else a power loss could preserve the
          // root creation while preserving the journal deletion, leaving a phantom
          // ca.prev.crt that _commitLocked() reads as an existing grace window and
          // rejects every later retained rotation (mtls-ca/retained-root-exists).
          nodeFs.unlinkSync(paths.caCertPrev);
          atomicFile.fsyncDir(nodePath.dirname(paths.caCertPrev));
        }
        prevRolledBack = true;
      } catch (rbErr) {
        caLog.error("retained-root-rollback-failed",
          { path: paths.caCertPrev, error: (rbErr && rbErr.message) || String(rbErr) });
      }
      // Restore the CRL the commit moved aside: the CA rolled back to is still active,
      // so its CRL is still valid and must keep being served. A no-op when the move
      // never ran (a failure before it left paths.crl untouched) or already restored.
      var crlRolledBack = false;
      try {
        if (nodeFs.existsSync(crlRollback) && !nodeFs.existsSync(paths.crl)) {
          atomicFile.renameWithRetry(crlRollback, paths.crl);
          atomicFile.fsyncDir(nodePath.dirname(paths.crl));
        }
        crlRolledBack = true;
      } catch (crlRbErr) {
        caLog.error("crl-rollback-failed",
          { path: paths.crl, error: (crlRbErr && crlRbErr.message) || String(crlRbErr) });
      }
      // The in-memory rollback restored the live key, the retained root, AND the CRL,
      // so the journal is spent — remove it. If ANY restore FAILED, keep the journal so
      // the next _reconcileCommitJournalLocked() completes the rollback: it holds the
      // prior key AND the retained root (prevData), and the fixed-name crl.rollback lets
      // reconcile finish the CRL restore too. Deleting it on a partial rollback would
      // permanently lose whichever the in-memory restore could not write (e.g. a hard-
      // cut rotation whose key rollback succeeds but whose retained-root restore fails).
      if (keyJournalWritten && keyRolledBack && prevRolledBack && crlRolledBack) {
        try { nodeFs.unlinkSync(keyJournal); }
        /* c8 ignore next -- best-effort: unlink of the journal we just wrote does not throw here */
        catch (_je) { caLog.debug("cleanup-failed", { op: "fs.unlinkSync", path: keyJournal, error: _je.message }); }
      }
      throw new MtlsCaError("mtls-ca/commit-failed",
        "atomic CA commit failed: " + ((e && e.message) || String(e)));
    }
    return {
      keyPath:  keyDest,
      certPath: paths.caCert,
      sealed:   sealed,
    };
  }

  // Public commit — the LOCKED commit primitive (the migration docs direct
  // operators here, so it must be safe against a concurrent rotate/init over the
  // same dataDir). It acquires the rotation lock so its key/cert renames and
  // rollback-journal writes cannot interleave with another commit/rotation and
  // leave a mixed pair or a lost journal. rotate() and first-time creation call
  // _commitLocked directly (they already hold the lock; atomicFile.lock is
  // non-reentrant). Returns a PROMISE — await it.
  function commit(opts2) {
    // Validate the argument shape SYNCHRONOUSLY (a config-time typo), before taking
    // the lock, so a caller sees a synchronous TypeError-style throw for bad input;
    // the durable work (and its runtime aborts) happens under the lock.
    if (!opts2 || typeof opts2.caKeyPem !== "string" || typeof opts2.caCertPem !== "string") {
      throw new MtlsCaError("mtls-ca/bad-commit",
        "commit requires opts.caKeyPem and opts.caCertPem (PEM strings)");
    }
    return atomicFile.lock(paths.caCert, function () {
      // Reconcile a leftover journal FIRST (as rotate() does): a crash that left a
      // new-key/old-cert state plus a journal would otherwise be overwritten by this
      // commit, which would record the ORPHANED new key as its prior key and, on a
      // failed publish, roll back to that orphan and delete the journal — losing the
      // actual matching old key. Safe here: the lock excludes any live commit.
      _reconcileCommitJournalLocked();
      var result = _commitLocked(opts2);
      // Refresh the handle's effective algorithm pin to the committed CA's algorithm
      // (as rotate() does on rotate({ algorithm })). Without this, a handle created with
      // an algorithm pin that migrates to a different-algorithm CA via this documented
      // public commit() path keeps the stale pin, so the next initCA() (via
      // generateClientCert/P12) compares it against the new stored CA and throws
      // mtls-ca/algorithm-mismatch — unusable right after a successful commit. Only when
      // the handle is pinned AND the committed algorithm is determinable: an unpinned
      // handle follows the stored CA already, and an opaque/custom cert leaves the pin
      // (its parseable-key validation in initCA is skipped anyway).
      if (caAlgorithm !== undefined) {
        var committedAlg = _certAlgorithm(opts2.caCertPem).algorithm;
        if (committedAlg !== null && committedAlg !== undefined) caAlgorithm = committedAlg;
      }
      return result;
    });
  }

  // Reconcile a rotation that crashed mid-publish. commit() writes a durable copy
  // of the prior CA key (keyDest + ".rollback") before overwriting the live key,
  // and removes it only once the new key/cert pair is durably consistent. So a
  // lingering journal means a rotation died between the key rename and the cert
  // rename: the on-disk key is the NEW key but the cert is still the OLD one (an
  // unusable, otherwise-unrecoverable pair). Roll the live key back to the prior
  // copy so the previously-active CA (still able to issue leaves and CRLs during
  // the grace window) survives; if the pair is already consistent (the crash
  // landed after the cert rename, or the key was never overwritten), the journal
  // is simply spent and dropped.
  //
  // MUST hold the rotation lock (atomicFile.lock(paths.caCert)) across this call.
  // commit() runs UNDER that lock, so holding it here guarantees no rotation is
  // mid-publish — an inconsistent pair with a journal is then definitively a
  // CRASHED rotation, not the transient NEW-key/OLD-cert window a live commit
  // briefly shows. Reconciling lock-free would let a concurrent issuance clobber
  // an in-flight rotation's new key. Idempotent under the lock.
  function _reconcileCommitJournalLocked() {
    var keyDest = (caKeySealedMode === "required") ? paths.caKeySealed : paths.caKey;
    var keyJournal = keyDest + ".rollback";
    if (!nodeFs.existsSync(keyJournal)) return;
    var manifest;
    try {
      manifest = safeJson.parse(atomicFile.fdSafeReadSync(keyJournal, { maxBytes: C.BYTES.mib(2), encoding: "utf8" }),
        { maxBytes: C.BYTES.mib(2) });
    } catch (_je) {
      // A rollback journal exists but cannot be read/parsed — the "rotation in
      // progress / crashed" marker, so we CANNOT tell whether the live key/cert pair
      // is mid-rotation. Continuing would let the caller (commit/rotate) overwrite the
      // ONLY durable copy of the prior key while snapshotting a possibly-orphaned live
      // key; a later failed publish could then restore the orphan and permanently lose
      // the matching key (and an opaque custom engine would issue from the mixed pair
      // node cannot verify). Fail closed: refuse to mutate until the fault is resolved.
      // Reconcile is idempotent, so the operator restores/removes the journal and
      // retries. A read-only trust read (_journalRetainedRoot) still tolerates it.
      throw new MtlsCaError("mtls-ca/rollback-journal-corrupt",
        "the CA rollback journal at " + keyJournal + " exists but could not be parsed (" +
        ((_je && _je.message) || String(_je)) + ") — refusing to mutate the CA while an unresolved rotation " +
        "journal is present; restore or remove it, then retry");
    }
    if (!manifest || typeof manifest.key !== "string") {
      // Present, valid JSON, but not a rollback manifest (missing the prior-key field):
      // a truncated / externally-rewritten journal. Same hazard as an unparseable one —
      // fail closed rather than overwrite an unresolved rotation marker.
      throw new MtlsCaError("mtls-ca/rollback-journal-corrupt",
        "the CA rollback journal at " + keyJournal + " is present but is not a valid rollback manifest " +
        "(missing the prior-key field) — refusing to mutate the CA while an unresolved rotation journal is " +
        "present; restore or remove it, then retry");
    }
    var curCertBuf = nodeFs.existsSync(paths.caCert)
      ? atomicFile.fdSafeReadSync(paths.caCert, { maxBytes: C.BYTES.mib(1) }) : null;
    var priorCertBuf = (typeof manifest.cert === "string") ? Buffer.from(manifest.cert, "base64") : null;
    // The rotation is COMPLETED (roll-forward) iff it republished the cert — the live
    // cert differs (BYTE-exact; a custom engine may emit non-UTF-8 cert bytes) from
    // the journal's recorded prior cert. Otherwise it is INTERRUPTED (roll-back): the
    // cert was never republished (a crash before the cert rename, or a partial catch
    // rollback). Both drive the CA to an authoritative on-disk state recorded in the
    // journal, byte-exact and engine-agnostic — no _caPairConsistent heuristic, which
    // is blind to custom-engine keys node cannot parse and would skip the key restore.
    var newCertBuf = (typeof manifest.newCert === "string") ? Buffer.from(manifest.newCert, "base64") : null;
    var completed;
    if (priorCertBuf !== null) {
      completed = curCertBuf !== null && !Buffer.from(curCertBuf).equals(priorCertBuf);
    } else {
      // No PRIOR cert (a key-only cold start: the retry's _commitLocked captured an
      // orphaned prior key with no cert). The "cert changed from prior" discriminator
      // cannot run, so classify by the intended NEW cert: completed iff the live cert IS
      // the one this commit meant to publish. Without this a completed key-only init
      // would be misread as interrupted and restore the orphaned key beside the new cert.
      completed = curCertBuf !== null && newCertBuf !== null && Buffer.from(curCertBuf).equals(newCertBuf);
    }
    var wantKeyBuf, wantPrevBuf;   // wantPrevBuf: Buffer=write it, null=remove prev, undefined=leave untouched
    if (completed) {
      // Finish the rotation: the new key, and the retained root it intended (the
      // outgoing/prior cert if it retained, else removed). Closes a completed
      // rotation whose key rename or prev unlink didn't durably stick.
      wantKeyBuf  = (typeof manifest.newKey === "string") ? Buffer.from(manifest.newKey, "base64") : null;
      wantPrevBuf = manifest.retainAfter ? priorCertBuf : null;
    } else {
      // Roll back to the prior key, and the prior retained root per prevAction
      // ("restore" bytes / "delete" a prev this rotation created / "leave" untouched).
      wantKeyBuf  = Buffer.from(manifest.key, "base64");
      wantPrevBuf = (manifest.prevAction === "restore" && typeof manifest.prevData === "string")
        ? Buffer.from(manifest.prevData, "base64")
        : (manifest.prevAction === "delete" ? null : undefined);
    }
    // Drive the live key to the authoritative bytes (idempotent — a no-op when it
    // already matches). Byte comparison so it works for a custom engine too.
    if (wantKeyBuf !== null) {
      var curKeyRaw = nodeFs.existsSync(keyDest)
        ? atomicFile.fdSafeReadSync(keyDest, { maxBytes: C.BYTES.mib(1) }) : null;
      if (curKeyRaw === null || !Buffer.from(curKeyRaw).equals(wantKeyBuf)) {
        atomicFile.writeSync(keyDest, wantKeyBuf, { fileMode: 0o600 });
      }
    }
    // Drive the retained root to the authoritative state (write bytes / remove /
    // leave). Repairs a resurrected hard-cut root or a lost retained-root write.
    if (wantPrevBuf !== undefined) {
      var curPrev = nodeFs.existsSync(paths.caCertPrev)
        ? atomicFile.fdSafeReadSync(paths.caCertPrev, { maxBytes: C.BYTES.mib(1) }) : null;
      if (wantPrevBuf === null) {
        if (curPrev !== null) { nodeFs.unlinkSync(paths.caCertPrev); atomicFile.fsyncDir(nodePath.dirname(paths.caCertPrev)); }
      } else if (curPrev === null || !Buffer.from(curPrev).equals(wantPrevBuf)) {
        atomicFile.writeSync(paths.caCertPrev, wantPrevBuf, { fileMode: 0o644 });
        atomicFile.fsyncDir(nodePath.dirname(paths.caCertPrev));
      }
    }
    // Drive the moved-aside CRL to its authoritative state (BEFORE the journal delete,
    // so a failure keeps the journal for a retry — matching the key/prev drives). A
    // commit moves the stale CRL to crl.rollback before publishing the new cert; if
    // this rotation COMPLETED (the cert republished), that CRL is signed by the
    // superseded issuer — delete it. If it was INTERRUPTED (rolled back), the CA it
    // reverts to is still active, so its CRL is still valid — rename it back so the
    // documented path keeps serving it.
    var crlRollback = _crlRollbackPath();
    if (nodeFs.existsSync(crlRollback)) {
      if (completed) {
        nodeFs.unlinkSync(crlRollback);
        atomicFile.fsyncDir(nodePath.dirname(crlRollback));
      } else if (!nodeFs.existsSync(paths.crl)) {
        atomicFile.renameWithRetry(crlRollback, paths.crl);
        atomicFile.fsyncDir(nodePath.dirname(paths.crl));
      }
    }
    // Delete the journal durably, and PROPAGATE a failure — this is NOT best-effort.
    // A surviving journal would let _journalRetainedRoot()/loadTrustBundle() keep
    // treating it as authoritative and re-trust its saved root, undoing a completed
    // cutoff. Throwing here fails the caller closed (dropRetained/initCA/rotate),
    // so a cutoff never "completes" while its interrupted journal is still live; the
    // operator resolves the fault (e.g. a read-only journal dir) and retries — the
    // restore above is idempotent, so re-running reconcile is safe. The fsync (best-
    // effort per platform) makes the deletion durable across a power loss.
    nodeFs.unlinkSync(keyJournal);
    atomicFile.fsyncDir(nodePath.dirname(keyJournal));
    caLog.warn("recovered-interrupted-rotation",
      { path: keyDest, detail: (completed ? "finished" : "rolled back") +
        " an interrupted rotation from the rollback journal (byte-exact)" });
  }

  function _commitJournalPath() {
    return ((caKeySealedMode === "required") ? paths.caKeySealed : paths.caKey) + ".rollback";
  }

  // Fixed name a CA-changing commit moves the stale CRL aside to before publishing the
  // new cert. A fixed (untokenized) name is safe because reconcile runs first on every
  // mutating open, so no stale crl.rollback survives into a later rotation; presence +
  // the completed/interrupted discriminator drive whether reconcile deletes it (stale)
  // or renames it back (still valid), so it needs no journal field.
  function _crlRollbackPath() {
    return paths.crl + ".rollback";
  }

  // Refuse to RETURN a stored CA that disagrees with the handle's algorithm pin: the
  // CA's own signature over every leaf is what a peer verifies, so issuing an ECDSA
  // leaf pinned for a legacy peer under a stored ML-DSA CA still yields an ML-DSA chain
  // that peer cannot verify. Shared by initCA()'s existing-CA path AND the fresh-init
  // adoption branch (a concurrent process may have created the CA under a different
  // recognized algorithm while this handle awaited generateCa) so every path that
  // adopts a stored CA enforces the pin identically. A custom engine may store a key
  // node cannot parse — the check is skipped then (the engine owns leaf issuance).
  function _assertPinMatchesStoredCa(certPem, keyPem) {
    if (caAlgorithm === undefined) return;
    var expectedType = _expectedKeyTypeForPin(caAlgorithm);
    var actualType   = null;
    var actualCurve  = null;
    try {
      var caKeyObj = nodeCrypto.createPrivateKey(keyPem);
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
    // Every ECDSA label maps to the generic "ec" type, so the type check alone would
    // accept a P-256/P-521 stored CA under the ECDSA-P384 pin — leaving the operator
    // believing they hold P-384 posture. The framework's sole classical pin is
    // ECDSA-P384-SHA384 (secp384r1), so enforce the curve for it; a custom-engine label
    // (unrecognized here) owns its own curve.
    if (actualType === "ec" && /ecdsa-p384/i.test(String(caAlgorithm)) && actualCurve !== CLASSICAL_CA_CURVE) {
      throw new MtlsCaError("mtls-ca/algorithm-mismatch",
        "the CA at this dataDir uses EC curve " + actualCurve + ", but algorithm " +
        JSON.stringify(caAlgorithm) + " requires P-384 (" + CLASSICAL_CA_CURVE + "). Rotate to a new " +
        "CA (a fresh dataDir, or a higher generation) to change the curve.");
    }
  }

  var _initChain = Promise.resolve();
  // Serialized first-time creation (see initCA's fresh path). Re-checks exists() at
  // the start (a prior chained init may have created it, avoiding a wasted keygen)
  // and again UNDER the rotation lock (a separate process may have created it while
  // we awaited generateCa) — adopting the committed CA instead of clobbering it.
  async function _freshCreateSerialized() {
    if (exists()) {
      var adoptedCert = loadCert().toString("utf8");
      var adoptedKey  = loadKey().toString("utf8");
      // Validate the ADOPTED CA against the pin too — a concurrent process may have
      // created it under a different algorithm than this pinned handle expects.
      _assertPinMatchesStoredCa(adoptedCert, adoptedKey);
      return { caCertPem: adoptedCert, caKeyPem: adoptedKey };
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
    return atomicFile.lock(paths.caCert, function () {
      if (exists()) {
        // A separate process committed a CA under the shared dataDir while we awaited
        // generateCa. Adopt it rather than clobber it — but validate it against the pin
        // (same as initCA's existing-CA path), else a pinned handle silently adopts and
        // then issues under an incompatible-algorithm CA.
        var adoptedCert = loadCert().toString("utf8");
        var adoptedKey  = loadKey().toString("utf8");
        _assertPinMatchesStoredCa(adoptedCert, adoptedKey);
        return { caCertPem: adoptedCert, caKeyPem: adoptedKey };
      }
      _commitLocked(fresh);
      return fresh;
    });
  }

  async function initCA() {
    if (exists()) {
      var existingCertPem = loadCert().toString("utf8");
      var existingKeyPem  = loadKey().toString("utf8");
      // A concurrent rotation renames the key and the cert as two steps, so this
      // read can transiently pair the OLD cert with the NEW key and make signing
      // fail. Re-read until the pair corresponds (the renames complete in
      // microseconds); bounded so a genuinely inconsistent store still returns.
      var pairTries = 0;
      while (!_caPairConsistent(existingCertPem, existingKeyPem) && pairTries < 8) {
        pairTries += 1;
        await safeAsync.sleep(10);
        existingCertPem = loadCert().toString("utf8");
        existingKeyPem  = loadKey().toString("utf8");
      }
      // A persistent mismatch (survived the re-read window, so NOT a transient
      // in-flight rotation) or a leftover journal (a crash between the cert rename
      // and the journal delete) means an interrupted rotation to reconcile. Do it
      // UNDER the rotation lock so a live commit can't be clobbered, then re-read.
      // A CUSTOM engine ALSO reads under the lock: _caPairConsistent cannot verify a
      // cert/key node can't parse (it returns "consistent"), so the re-read loop
      // above can't detect a rotation mid-publish (old cert + new key) — only the
      // lock guarantees the pair the engine signs under actually corresponds.
      if (!_caPairConsistent(existingCertPem, existingKeyPem) ||
          nodeFs.existsSync(_commitJournalPath()) || !usesDefaultEngine) {
        await atomicFile.lock(paths.caCert, function () {
          _reconcileCommitJournalLocked();
          // Re-read the pair UNDER the lock: reading it after releasing the lock
          // would let a new rotation reopen the transient new-key/old-cert window
          // and surface a spurious ca-pair-inconsistent on a healthy store.
          existingCertPem = loadCert().toString("utf8");
          existingKeyPem  = loadKey().toString("utf8");
        });
      }
      // Still inconsistent after reconciling — refuse rather than sign with a
      // mismatched pair (which would fail confusingly). A slow rotation or a
      // corrupt store surfaces here as a clear, retry-able error.
      if (!_caPairConsistent(existingCertPem, existingKeyPem)) {
        throw new MtlsCaError("mtls-ca/ca-pair-inconsistent",
          "the stored CA certificate and private key did not become a matching pair after re-reading " +
          "(a rotation may still be publishing, or the store is corrupt) — retry issuance");
      }
      // A stored CA is returned as-is (initCA never silently rotates), but an
      // algorithm pin that DISAGREES with it cannot be honored — refuse the mismatch.
      _assertPinMatchesStoredCa(existingCertPem, existingKeyPem);
      return { caCertPem: existingCertPem, caKeyPem: existingKeyPem };
    }
    // First-time creation. Serialize it (like rotation) so two concurrent cold-start
    // callers — the normal generateClientCert()-before-a-CA-exists path, same handle
    // or two processes over one dataDir — cannot each generate a CA and clobber one
    // another (the loser's just-issued leaf would chain to a CA that no longer
    // exists). _initChain serializes same-handle creation; the lock + double-check
    // handles cross-process.
    var next = _initChain.then(function () { return _freshCreateSerialized(); });
    _initChain = next.then(function () {}, function () {});
    return next;
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
    await _recordIssuance(ca.caCertPem, id);
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
    // writes to the ledger. It must be a non-empty PARSEABLE X.509 certificate —
    // an empty or bogus string would let _certIdentity record a fallback hash
    // unrelated to the archive's real cert, so revokeGeneration() would revoke a
    // phantom while the gate keeps accepting the actual client certificate.
    //
    // ENGINE CONTRACT: certPem MUST be the leaf certificate contained in the
    // returned p12 — that pairing is the packageP12 engine's responsibility. The
    // bundled engine builds both from one signing operation so they always agree;
    // the framework cannot re-verify it for an arbitrary engine because the p12's
    // certificate bag is encrypted under the operator's password in an
    // engine-defined format. A custom engine returning a mismatched certPem
    // violates its own contract, exactly as returning a non-Buffer p12 would.
    if (typeof result.certPem !== "string" || result.certPem.length === 0) {
      throw new MtlsCaError("mtls-ca/bad-engine-output",
        "engine.packageP12 must return a non-empty certPem so the archive is recorded in the issuance " +
        "ledger — an unrecorded P12 could not be revoked by revokeGeneration()");
    }
    try { new nodeCrypto.X509Certificate(result.certPem); }
    catch (_pe) {
      throw new MtlsCaError("mtls-ca/bad-engine-output",
        "engine.packageP12's certPem must be a parseable X.509 certificate (the identity revokeGeneration() " +
        "records) — a bogus certPem would record a fingerprint unrelated to the archive's real certificate");
    }
    var id12 = _certIdentity(result.certPem);
    await _recordIssuance(ca.caCertPem, id12);
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
      // Cheap change signal for isRevoked()'s index — the append-only file's byte
      // length grows on every add (mtime disambiguates a same-size rewrite), so a
      // revocation written by ANOTHER handle / process over this file bumps it and
      // the index rebuilds on the next lookup. O(1) statSync, not an O(n) parse.
      version: function () {
        try { var st = nodeFs.statSync(paths.revocations); return st.size + ":" + st.mtimeMs; }
        catch (_e) { return "0:0"; }
      },
    };
  }
  var usesDefaultRevocationStore = !opts.revocationStore;
  var revocationStore = opts.revocationStore || _defaultFileStore();
  validateOpts.requireMethods(revocationStore, ["list", "add"],
    "opts.revocationStore", MtlsCaError, "mtls-ca/bad-revocation-store");
  // The clustered-watermark methods are all-or-nothing: providing only one would
  // SPLIT the watermark (one operation shared, the other on the local file), so a
  // revoked generation could still issue on another host — a fail-open. Refuse it.
  if ((typeof revocationStore.readGenerationWatermark === "function") !==
      (typeof revocationStore.bumpGenerationWatermark === "function")) {
    throw new MtlsCaError("mtls-ca/bad-revocation-store",
      "a revocationStore providing one of readGenerationWatermark() / bumpGenerationWatermark() must " +
      "provide BOTH — a split watermark would let a revoked generation still issue on another host");
  }

  // Revoked-generation watermark — the highest n passed to revokeGeneration(),
  // read by issuance to catch a leaf whose signing straddled a generation
  // revocation (see _recordIssuance). Stored in the LOCAL dataDir file by default,
  // which coordinates same-host processes. A CLUSTERED custom store (shared across
  // hosts, per-host dataDir) must instead expose { readGenerationWatermark(),
  // bumpGenerationWatermark(n) } so the watermark lives in the shared store; when
  // present those win. bumpGenerationWatermark(n) must be a monotonic max and own
  // its own atomicity.
  function _readRevokedWatermark() {
    if (typeof revocationStore.readGenerationWatermark === "function") {
      var v = revocationStore.readGenerationWatermark();
      // Fail CLOSED: a store that can't return a valid watermark must not let a
      // revoked generation slip through as 0. Only a genuine "never set" (0/absent)
      // is a valid zero.
      if (typeof v === "number" && isFinite(v) && v >= 0) return v;
      throw new MtlsCaError("mtls-ca/watermark-unreadable",
        "revocationStore.readGenerationWatermark() returned a non-numeric value — refusing issuance rather " +
        "than treating a revoked generation as unrevoked");
    }
    // ONLY an absent file is a real zero. A present-but-unreadable/malformed file
    // must ABORT issuance — reporting 0 would let a below-n generation issued
    // during the sweep pass the _recordIssuance() check (the race this closes).
    if (!nodeFs.existsSync(paths.revokedGeneration)) return 0;
    var raw;
    try {
      raw = atomicFile.fdSafeReadSync(paths.revokedGeneration, { maxBytes: 64, encoding: "utf8" });
    } catch (e) {
      throw new MtlsCaError("mtls-ca/watermark-unreadable",
        "the revoked-generation watermark (" + paths.revokedGeneration + ") exists but is unreadable (" +
        ((e && e.message) || String(e)) + ") — refusing issuance rather than treating it as unrevoked");
    }
    // Require the WHOLE trimmed content to be digits — parseInt would accept
    // "1junk"/"1.5" and take a lower prefix, letting a below-watermark generation
    // slip through. Any non-integer content fails closed.
    var trimmed = String(raw).trim();
    if (!/^\d+$/.test(trimmed)) {
      throw new MtlsCaError("mtls-ca/watermark-unreadable",
        "the revoked-generation watermark (" + paths.revokedGeneration + ") is malformed — refusing issuance");
    }
    var n = parseInt(trimmed, 10);
    return n;
  }
  // Returns a PROMISE: the shared-store bump owns its atomicity; the local-file
  // bump takes a cross-process lock on the watermark file for its read-modify-write.
  function _bumpRevokedWatermark(n) {
    if (typeof revocationStore.bumpGenerationWatermark === "function") {
      return Promise.resolve(revocationStore.bumpGenerationWatermark(n));
    }
    return atomicFile.lock(paths.revokedGeneration, function () {
      if (n > _readRevokedWatermark()) {
        atomicFile.writeSync(paths.revokedGeneration, String(n) + "\n", { mode: 0o600 });
      }
    });
  }

  // In-memory revocation index — a Set of every revoked serial + fingerprint —
  // so isRevoked() (called PER REQUEST by a revocationSource-wired require-mtls
  // gate) is O(1) with no filesystem read/JSON-parse on the event-loop hot path.
  // Built lazily from the store on first use, then kept in sync by revoke().
  // Reflects revocations made through THIS handle; the default file store is
  // single-process, so a store mutated out-of-band is not re-read here.
  var _revIndex = null;
  var _revIndexVersion = null;
  // Return a fresh-enough Set of revoked serials + fingerprints. When the store
  // exposes version(), the index is rebuilt only when that signal changes — so a
  // revocation written by another handle / process is picked up (cache coherence)
  // while an unchanged store costs one version() call + a Set lookup, not an O(n)
  // reparse. A store with no version() signal owns its own coherence, so it is
  // read fresh each call rather than risk serving a stale cached view.
  function _revIndexFor() {
    var hasVersion = typeof revocationStore.version === "function";
    var storeVersion = hasVersion ? revocationStore.version() : null;
    if (_revIndex === null || !hasVersion || storeVersion !== _revIndexVersion) {
      _revIndex = new Set();
      revocationStore.list().forEach(function (r) {
        if (r && r.serialNumber) _revIndex.add(r.serialNumber);
        if (r && r.fingerprint) _revIndex.add(r.fingerprint);
      });
      _revIndexVersion = storeVersion;
    }
    return _revIndex;
  }

  // Issuance ledger — same bring-your-own-store contract as revocationStore
  // ({ list(), add(entry) }). Every generateClientCert/generateClientP12
  // appends { serialNumber, fingerprint, generation, issuedAt } so
  // revokeGeneration(n) can find the certs a superseded CA generation signed.
  function _defaultIssuanceStore() {
    function _list() {
      if (!nodeFs.existsSync(paths.issuance)) return [];
      var json;
      try {
        json = safeJson.parse(atomicFile.fdSafeReadSync(paths.issuance, { maxBytes: C.BYTES.mib(16), encoding: "utf8" }),
          { maxBytes: C.BYTES.mib(16) });
      } catch (e) {
        /* c8 ignore next 2 -- defensive: safeJson.parse throws an Error with a message, so the String(e) fallback is unreachable */
        throw new MtlsCaError("mtls-ca/issuance-corrupt",
          "could not parse " + paths.issuance + ": " + ((e && e.message) || String(e)));
      }
      // A PRESENT ledger MUST carry an `issued` array. Missing / non-array `issued`
      // (an accidental `{}`, a truncated or externally-rewritten file) is
      // corruption, not an empty ledger — silently treating it as [] would let the
      // next add() overwrite the file with only its own entry, dropping every prior
      // certificate from the SOLE index revokeGeneration() consults, so those certs
      // would survive a later generation revocation. Fail closed, as malformed JSON
      // does; the operator must restore or remove the file.
      if (!json || !Array.isArray(json.issued)) {
        throw new MtlsCaError("mtls-ca/issuance-corrupt",
          paths.issuance + " is present but has no `issued` array (ledger schema corruption) — " +
          "refusing to treat a corrupt issuance ledger as empty");
      }
      return json.issued;
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
  var usesDefaultIssuanceStore = !opts.issuanceStore;
  var issuanceStore = opts.issuanceStore || _defaultIssuanceStore();
  validateOpts.requireMethods(issuanceStore, ["list", "add"],
    "opts.issuanceStore", MtlsCaError, "mtls-ca/bad-issuance-store");
  // Clustered operation (a shared revocationStore with the watermark methods, but
  // per-host dataDirs) REQUIRES a shared issuanceStore too. revokeGeneration()
  // sweeps the issuance ledger to find the certs a superseded generation signed;
  // with the DEFAULT local-file ledger each host records only its own issuances,
  // so a cert fully issued on host B before host A calls revokeGeneration() is
  // absent from A's sweep and stays accepted by the shared live gate — a fail-open
  // the shared watermark can't close (it only supersedes FUTURE appends). Refuse
  // the split at construction rather than silently under-revoking in a cluster.
  if (typeof revocationStore.readGenerationWatermark === "function" && usesDefaultIssuanceStore) {
    throw new MtlsCaError("mtls-ca/bad-issuance-store",
      "a clustered revocationStore (readGenerationWatermark/bumpGenerationWatermark) requires a shared " +
      "issuanceStore as well — the default per-host ledger would let revokeGeneration() miss certificates " +
      "issued on another host, leaving them accepted by the shared revocation gate");
  }

  // Record an issued leaf in the ledger. Fail-closed: the ledger is the SOLE
  // index revokeGeneration() consults, so a cert absent from it can never be
  // revoked by generation and would stay accepted by fingerprint-based
  // enforcement. A write failure (disk full, the 16 MiB cap crossed, a custom
  // store throwing) therefore FAILS issuance rather than returning an untracked
  // credential — the caller must resolve the persistence fault and re-issue.
  async function _recordIssuance(caCertPem, id) {
    // parseGeneration() returns 0 when node:crypto cannot parse the CA cert (a custom
    // engine's opaque / post-quantum cert). 0 is NOT a real generation (they are >= 1),
    // so record it as UNDETERMINABLE (null), never 0: recording 0 would make
    // revokeGeneration(1) sweep these CURRENT-generation leaves (0 < 1) and, via the
    // bumped watermark, self-revoke every future issuance under the CA. A null-generation
    // entry is skipped by revokeGeneration()'s numeric sweep (it stays revocable by
    // serial/fingerprint); a custom engine that wants generation-based revocation must
    // embed a node-parseable generation (OU=CAv<n>) in its cert.
    var parsedGen = parseGeneration(caCertPem);
    var gen = parsedGen >= 1 ? parsedGen : null;
    var entry = {
      serialNumber: id.serialNumber,
      fingerprint:  id.fingerprint,
      generation:   gen,
      issuedAt:     Date.now(),
    };
    try {
      if (usesDefaultIssuanceStore) {
        // Serialize the ledger's read-modify-write across processes: two issuers
        // over the same dataDir must not both read the ledger, append locally,
        // and clobber each other's entry (a lost entry is invisible to
        // revokeGeneration(), so the cert would survive a generation revocation).
        // A custom store owns its own concurrency, so it is written directly.
        await atomicFile.lock(paths.issuance, function () { issuanceStore.add(entry); });
      } else {
        issuanceStore.add(entry);
      }
    } catch (e) {
      throw new MtlsCaError("mtls-ca/issuance-ledger-write-failed",
        "certificate " + id.serialNumber + " was signed but could not be recorded in the issuance " +
        "ledger (" + paths.issuance + "): " + ((e && e.message) || String(e)) +
        " — refusing to return an untracked credential revokeGeneration() could not later revoke");
    }
    // Issuance-vs-generation-revocation race: this leaf's signing may have
    // straddled a rotate()+revokeGeneration(gen'>gen), whose sweep read the
    // ledger BEFORE the append above. revokeGeneration bumps the watermark before
    // sweeping, so having recorded FIRST then reading it here guarantees the leaf
    // is caught by one side or the other. Applies to ALL stores — the watermark is
    // a separate file, so a custom store (list()/add() only) is covered too. If
    // this generation is already revoked, revoke the leaf and refuse it. An
    // undeterminable (null) generation is never below the watermark — an opaque
    // custom cert can't be classified as superseded, so it is not self-revoked here.
    if (typeof gen === "number" && gen < _readRevokedWatermark()) {
      await revoke({ serial: id.serialNumber || null, fingerprint: id.fingerprint || null, reason: "superseded" });
      throw new MtlsCaError("mtls-ca/issuance-superseded",
        "certificate for CA generation " + gen + " was issued while revokeGeneration() revoked that " +
        "generation (a concurrent rotation) — the certificate has been revoked; re-issue under the current generation");
    }
    // Issuance-vs-root-removal race: a hard-cut rotate({ retainPrevious:false }) or a
    // dropRetained() can remove the root this leaf was signed under while its signing
    // was in flight, leaving a leaf that chains to a root no longer in loadTrustBundle().
    // Having recorded the leaf FIRST, then checking membership here, a leaf whose
    // issuing root was dropped mid-flight is caught and revoked instead of returned
    // un-verifiable — covering both the hard cut and dropRetained without a watermark
    // bump that races the removal or wrongly supersedes on a failed rotation. (A root
    // removed AFTER this check is the operator's intended cut of that generation,
    // which cuts this leaf along with its cohort; a RETAINED rotation keeps the old
    // root in the bundle, so its straddling leaf still chains and is NOT revoked.)
    if ((await loadTrustBundle()).indexOf(caCertPem) === -1) {
      await revoke({ serial: id.serialNumber || null, fingerprint: id.fingerprint || null, reason: "superseded" });
      throw new MtlsCaError("mtls-ca/issuance-superseded",
        "the CA root this certificate was signed under was removed (a concurrent hard-cut rotation or " +
        "dropRetained()) before issuance completed — the certificate has been revoked; re-issue under the current CA");
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

  // Unlocked registry read/dedupe/add. Callers hold the revocation lock (default
  // store) or own their own concurrency (custom store) before invoking this.
  function _revokeCore(serial, fingerprint, reasonName, reasonCode) {
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

  // revoke() validates its input SYNCHRONOUSLY (entry-point tier: a bad serial /
  // fingerprint / reason throws before any work) but returns a PROMISE for the
  // result, because the default store's read/dedupe/add runs under a cross-process
  // lock. Await the returned promise for the recorded entry.
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
    if (usesDefaultRevocationStore) {
      // Serialize the registry read/dedupe/add across processes (same rationale
      // as the issuance ledger) so a concurrent revoke() / revokeGeneration() in
      // another process cannot read the same file, append locally, and clobber
      // this entry — a lost revocation would let the live gate admit the cert.
      return atomicFile.lock(paths.revocations, function () {
        return _revokeCore(serial, fingerprint, reasonName, reasonCode);
      });
    }
    return Promise.resolve(_revokeCore(serial, fingerprint, reasonName, reasonCode));
  }

  function isRevoked(serialOrFingerprint) {
    // Accept a serial number OR a SHA3-512 fingerprint — both are hex, so one
    // normalized form is matched against either key each entry carries.
    if (!serialOrFingerprint || typeof serialOrFingerprint !== "string") {
      throw new MtlsCaError("mtls-ca/bad-revocation-key",
        "isRevoked requires a serial number or a fingerprint (hex string)");
    }
    var norm = _normalizeFingerprint(serialOrFingerprint);
    return _revIndexFor().has(norm);
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
    var persisted = false;
    if (opts3.persist !== false) {
      // The CA may have ROTATED while we awaited engine.generateCrl() — the signed
      // CRL is then for the SUPERSEDED CA, and persisting it would recreate the
      // stale-issuer artifact a rotation just invalidated. Under the rotation lock
      // (so no rotation is in flight), re-check that the CA we signed under is still
      // current; persist only then. If it rotated, skip — the caller regenerates
      // under the new CA (persisted=false signals it).
      await atomicFile.lock(paths.caCert, function () {
        if (nodeFs.existsSync(paths.caCert) &&
            atomicFile.fdSafeReadSync(paths.caCert, { maxBytes: C.BYTES.mib(1) }).toString("utf8") === ca.caCertPem) {
          atomicFile.writeSync(paths.crl, crlPem, { fileMode: 0o644 });
          persisted = true;
        }
      });
    }
    return { crlPem: crlPem, thisUpdate: thisUpdate, nextUpdate: nextUpdate,
             entryCount: revocations.length,
             fingerprintOnlyOmitted: fingerprintOnlyOmitted,
             persisted: persisted,
             path: paths.crl };
  }

  // ---- Algorithm migration (issue #532) ----

  // Serialize rotations on this handle. Two concurrent rotate() calls must not
  // both read the same current generation, both mint the next one, and clobber
  // each other's CA + retained root (the second commit would overwrite the first
  // and snapshot a short-lived intermediate as ca.prev.crt, dropping the original
  // root from loadTrustBundle()). Each call waits for the prior to settle, THEN
  // re-reads state inside _rotateImpl, so generations advance monotonically.
  var _rotateChain = Promise.resolve();
  function rotate(rotateOpts) {
    var next = _rotateChain.then(function () { return _rotateImpl(rotateOpts); },
                                 function () { return _rotateImpl(rotateOpts); });
    // Keep the chain alive past a rejection so one failed rotation doesn't wedge
    // every later one; the caller still awaits `next` for the real outcome.
    _rotateChain = next.then(function () {}, function () {});
    return next;
  }

  async function _rotateImpl(rotateOpts) {
    rotateOpts = rotateOpts || {};
    // A defined algorithm must be a non-empty label (matching create({ algorithm })).
    // An empty string would be treated as a pin here yet as "no pin" by the engine
    // (selecting the process default) and as "omitted" by canVerifyInTls(), letting
    // a pre-flight pass for the stored algorithm while rotation activates the default.
    if (rotateOpts.algorithm !== undefined &&
        (typeof rotateOpts.algorithm !== "string" || rotateOpts.algorithm.length === 0)) {
      throw new MtlsCaError("mtls-ca/bad-algorithm",
        "rotate: algorithm must be a non-empty string label when set (e.g. \"ECDSA-P384-SHA384\")");
    }
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
    if (pin === undefined && usesDefaultEngine && previousCaCertPem !== null) {
      // An UNPINNED rotation (no rotate({algorithm}) and no create-time pin) over an
      // existing CA must PRESERVE the stored algorithm, not silently adopt the engine
      // default (ML-DSA-87). Otherwise a bare rotate({generation}) to advance a cohort
      // would flip a classical ECDSA CA to ML-DSA and reject legacy peers — mirroring
      // the stored-CA inference _leafEngineArgs does for unpinned leaf issuance.
      // Changing algorithm stays explicit via rotate({algorithm}).
      pin = _certAlgorithm(previousCaCertPem).algorithm || undefined;
    }
    if (pin !== undefined) genArgs.algorithm = pin;
    var fresh = await engine.generateCa(genArgs);
    if (!fresh || typeof fresh.caCertPem !== "string" || typeof fresh.caKeyPem !== "string") {
      throw new MtlsCaError("mtls-ca/bad-engine-output",
        "engine.generateCa must return { caCertPem, caKeyPem }");
    }
    // retainPrevious defaults ON for a rotation (the grace window is the point);
    // pass retainPrevious:false to overwrite without retaining the old CA.
    var retain = rotateOpts.retainPrevious !== false && previousCaCertPem !== null;
    // Cross-process compare-and-swap. _rotateChain serializes rotations on THIS
    // handle, but a separate handle over the same dataDir (or another process)
    // owns a different chain and could have committed a new generation while we
    // awaited generateCa. Hold the dataDir rotation lock, re-read the on-disk
    // generation UNDER it, and refuse if it moved — so the revalidation and the
    // commit are atomic and the loser cannot overwrite the winner's CA or
    // snapshot its transient intermediate as ca.prev.crt (dropping the root
    // clients still trust). The caller retries against the current generation.
    await atomicFile.lock(paths.caCert, function () {
      // Heal a prior rotation that crashed mid-publish BEFORE re-reading the
      // generation — otherwise this rotation would snapshot a new-key/old-cert
      // state and journal the orphaned new key, permanently losing the
      // recoverable prior. Safe here: the lock excludes any live commit.
      _reconcileCommitJournalLocked();
      var nowSt = status();
      var nowGen = nowSt.exists ? nowSt.generation : 0;
      // Compare cert IDENTITY, not only the generation number: a public commit()
      // could have replaced the CA with a DIFFERENT cert at the SAME generation
      // while we awaited generateCa(), which a gen-only check would miss — letting
      // this older rotation overwrite that later commit. Refuse if the current cert
      // is not the one we snapshotted before generating.
      var nowCert = nowSt.exists ? loadCert().toString("utf8") : null;
      if (nowGen !== curGen || nowCert !== previousCaCertPem) {
        throw new MtlsCaError("mtls-ca/rotation-conflict",
          "the CA changed (generation " + curGen + " -> " + nowGen + ", or a same-generation replacement) " +
          "during rotation — a concurrent rotate/commit on another handle or process. Retry against the " +
          "current CA");
      }
      // The single-retained-window invariant (refuse a second retained rotation
      // while a root is still retained) is enforced inside _commitLocked, so every
      // retention entry point — rotate() and the public commit() — is covered.
      _commitLocked({ caKeyPem: fresh.caKeyPem, caCertPem: fresh.caCertPem, retainPrevious: retain });
    });
    // A hard cut (retainPrevious:false) removes the old root, so a leaf whose signing
    // straddled this rotation would chain to a root now gone from the trust bundle.
    // That is handled where the removal races the issuance — _recordIssuance re-checks
    // trust-bundle membership of its issuing root after recording (covering both this
    // hard cut and dropRetained), rather than a post-commit watermark bump that would
    // both race the removal and wrongly supersede a generation on a FAILED rotation.
    // Persist the effective algorithm on the handle. Without this, a handle
    // created with an algorithm pin that then rotate({ algorithm })s to a
    // different one keeps the stale closed-over pin, so the next initCA() (via
    // generateClientCert / generateClientP12) compares it against the new stored
    // CA and throws mtls-ca/algorithm-mismatch — the handle would be unusable
    // immediately after a successful rotation.
    if (rotateOpts.algorithm !== undefined) caAlgorithm = rotateOpts.algorithm;
    // A persisted CRL signed by the superseded CA is invalidated inside _commitLocked
    // (under the lock, covering rotate() and the public commit() alike) — regenerate
    // it under the new CA with generateCrl().
    caLog.info("rotated CA", { generation: newGen, retainedPrevious: retain });
    return {
      caCertPem:         fresh.caCertPem,
      previousCaCertPem: previousCaCertPem,
      generation:        newGen,
      algorithm:         _certAlgorithm(fresh.caCertPem).algorithm,
    };
  }

  function _readCurrentCert() {
    return nodeFs.existsSync(paths.caCert) ? loadCert().toString("utf8") : null;
  }
  function _readRetainedRoot() {
    // Read the retained root without a lock, tolerating a concurrent removal: a
    // dropRetained() / rotate({ retainPrevious:false }) in another process can
    // unlink ca.prev.crt between this existsSync and the read, so an ENOENT here
    // just means the grace window ended.
    if (!nodeFs.existsSync(paths.caCertPrev)) return null;
    try {
      return atomicFile.fdSafeReadSync(paths.caCertPrev, { maxBytes: C.BYTES.mib(1) }).toString("utf8");
    } catch (e) {
      if (!e || e.code !== "ENOENT") throw e;
      return null;
    }
  }
  // The retained root a crashed rotation saved ONLY in its rollback journal (no
  // initCA()/rotate() has reconciled it back to ca.prev.crt yet). Returned so a
  // restart that calls only loadTrustBundle() still trusts clients enrolled under
  // the formerly-retained generation. Best-effort: an unreadable journal is left
  // for the locked reconcile to handle.
  function _journalRetainedRoot() {
    var keyJournal = ((caKeySealedMode === "required") ? paths.caKeySealed : paths.caKey) + ".rollback";
    if (!nodeFs.existsSync(keyJournal)) return null;
    try {
      var m = safeJson.parse(atomicFile.fdSafeReadSync(keyJournal, { maxBytes: C.BYTES.mib(2), encoding: "utf8" }),
        { maxBytes: C.BYTES.mib(2) });
      if (m && m.prevAction === "restore" && typeof m.prevData === "string" && typeof m.cert === "string") {
        // Only trust the journal's retained root when it represents an INTERRUPTED
        // rotation: the live cert still equals the prior cert the journal recorded,
        // so the rotation never republished and the old root is still the operative
        // one. A SPENT journal (rotation COMPLETED — including a hard cutoff — but
        // its delete failed) has a different live cert; re-trusting its old root
        // would defeat the completed cutoff, and dropRetained() cannot clear it.
        // Byte comparison (a custom engine may emit non-UTF-8 cert bytes).
        var priorCertBuf = Buffer.from(m.cert, "base64");
        var curBuf = nodeFs.existsSync(paths.caCert)
          ? atomicFile.fdSafeReadSync(paths.caCert, { maxBytes: C.BYTES.mib(1) }) : null;
        if (curBuf !== null && Buffer.from(curBuf).equals(priorCertBuf)) {
          return Buffer.from(m.prevData, "base64").toString("utf8");
        }
      }
    } catch (_e) { /* unreadable journal — the locked reconcile handles it */ }
    return null;
  }
  // Lock-free trust-root snapshot. The double-read makes the snapshot internally
  // consistent; the PUBLIC loadTrustBundle() wraps this in the rotation lock so a
  // completed dropRetained()/rotation cannot precede delivery of a stale bundle.
  // _recordIssuance's root-drop check uses the LOCKED loadTrustBundle(), not this,
  // so a hard-cut/dropRetained that completes is seen and the leaf self-revokes.
  function _trustRoots() {
    // A retained rotation publishes ca.prev.crt = old THEN ca.crt = new as two
    // steps, so a naive read can interleave: read the OLD current, then read the
    // just-written ca.prev.crt (also old), returning [old, old] and OMITTING the
    // new active root — a TLS context reloaded from that rejects newly-enrolled
    // clients until another reload. Read a STABLE snapshot: re-read the current
    // cert after the retained one and retry if it changed mid-read (a rotation
    // published between the reads). Bounded — a rotation completes in microseconds;
    // sustained churn still returns the last current snapshot rather than looping.
    var cur = null;
    var bundle = null;
    for (var attempt = 0; attempt < 8 && bundle === null; attempt += 1) {
      cur = _readCurrentCert();
      var prev = _readRetainedRoot();
      // Accept only a snapshot where BOTH the current cert AND the retained root
      // are unchanged across the read. Re-checking only `cur` would let a
      // dropRetained() that unlinks ca.prev.crt between the prev read and here slip
      // through — returning a root the operator just cut. Re-reading prev too means
      // that removal is seen as prev-changed and retried (next pass reads prev=null).
      if (cur === _readCurrentCert() && prev === _readRetainedRoot()) {
        bundle = [];
        if (cur) bundle.push(cur);
        if (prev && prev !== cur) bundle.push(prev);    // dedup — never return [old, old]
      }
    }
    if (bundle === null) bundle = cur ? [cur] : [];
    // Include a retained root held ONLY in an unreconciled rollback journal (a
    // crash left it there before any initCA()/rotate() reconciled) so a restart
    // that loads trust without first reconciling does not drop that cohort.
    var journalRoot = _journalRetainedRoot();
    if (journalRoot && bundle.indexOf(journalRoot) === -1) bundle.push(journalRoot);
    return bundle;
  }
  // Public trust bundle. Returns a PROMISE: it takes the rotation lock so the read
  // is serialized with dropRetained()/rotation — a cutoff that has COMPLETED (held
  // then released the lock) cannot be preceded by delivery of a bundle that still
  // trusts the cut root, closing the residual window a lock-free read leaves after
  // its last comparison. Under the lock no rotation/removal is in flight, so the
  // snapshot is both consistent and current. Await it.
  function loadTrustBundle() {
    return atomicFile.lock(paths.caCert, function () { return _trustRoots(); });
  }

  // Ends the retained-root grace window. Returns a PROMISE: it takes the rotation
  // lock (paths.caCert) so it cannot unlink ca.prev.crt in the middle of a
  // concurrent retained rotation (which writes prev, then renames the new cert) —
  // that interleaving would leave the rotation with no retained root, stranding
  // clients on the outgoing CA. Await it.
  function dropRetained() {
    return atomicFile.lock(paths.caCert, function () {
      // Reconcile an interrupted rotation FIRST. A crashed hard-cut rotation can
      // remove ca.prev.crt yet leave a journal whose recorded root loadTrustBundle()
      // still trusts (its prior cert matches the live cert). Without reconciling,
      // dropRetained() would see no live retained file, remove nothing, and the
      // journal would keep serving the "dropped" root — so the window never ends.
      // Under this lock, reconcile restores that root (or drops a spent journal);
      // the removal below then actually ends the grace window.
      _reconcileCommitJournalLocked();
      var had = nodeFs.existsSync(paths.caCertPrev);
      if (had) {
        nodeFs.unlinkSync(paths.caCertPrev);
        // Durable removal — see the commit-path note; ca.prev.crt's parent may
        // differ from ca.crt's, so a power loss must not resurrect the dropped root.
        atomicFile.fsyncDir(nodePath.dirname(paths.caCertPrev));
      }
      return { dropped: had };
    });
  }

  // Backfill leaf identities the issuance ledger does not have — certificates
  // issued by a PRE-#532 release (whose runs never recorded issuance) or issued
  // out of band. revokeGeneration(n) can only sweep what the ledger records, so an
  // upgraded dataDir's older cohort must be imported first: each entry is
  // { fingerprint, generation, serialNumber? }. `generation` is the ISSUING CA's
  // generation (the OU=CAvN tag lives on the CA cert's subject, NOT the leaf), so
  // derive it from the ISSUER cert — parseGeneration(<issuing CA cert>), or the
  // known cohort number — never parseGeneration(<leaf>), which would fall back to 1
  // and mislabel a gen-2+ leaf (revokeGeneration could then revoke a current cert).
  // Returns { imported }. SYNC-throws on bad input.
  function importIssuance(entries) {
    if (!Array.isArray(entries)) {
      throw new MtlsCaError("mtls-ca/bad-import",
        "importIssuance requires an array of { fingerprint, generation, serialNumber? } entries");
    }
    var normalized = entries.map(function (e) {
      if (!e || typeof e !== "object") {
        throw new MtlsCaError("mtls-ca/bad-import", "each importIssuance entry must be an object");
      }
      if (typeof e.generation !== "number" || !Number.isInteger(e.generation) || e.generation < 1) {
        throw new MtlsCaError("mtls-ca/bad-import", "importIssuance entry.generation must be a positive integer");
      }
      var fp = (e.fingerprint !== undefined && e.fingerprint !== null) ? _normalizeFingerprint(e.fingerprint) : null;
      var serial = (e.serialNumber !== undefined && e.serialNumber !== null) ? _normalizeSerial(e.serialNumber) : null;
      if (!fp && !serial) {
        throw new MtlsCaError("mtls-ca/bad-import", "importIssuance entry requires a fingerprint or serialNumber");
      }
      return { serialNumber: serial, fingerprint: fp, generation: e.generation, issuedAt: e.issuedAt || Date.now() };
    });
    var add = function () { normalized.forEach(function (n) { issuanceStore.add(n); }); };
    var run = usesDefaultIssuanceStore ? atomicFile.lock(paths.issuance, add) : Promise.resolve(add());
    return run.then(function () {
      // Read the watermark AFTER the append (matching _recordIssuance's ordering,
      // fail-closed on a malformed value): a concurrent revokeGeneration that
      // bumps the watermark and finishes its sweep before our append lands would,
      // with a pre-read stale value, be missed by BOTH the sweep and this check —
      // reading here guarantees one side catches the entry. An imported leaf whose
      // generation is already revoked is revoked here.
      var wm = _readRevokedWatermark();
      var superseded = normalized.filter(function (n) { return n.generation < wm; });
      return Promise.all(superseded.map(function (n) {
        return revoke({ serial: n.serialNumber || null, fingerprint: n.fingerprint || null, reason: "superseded" });
      })).then(function () { return { imported: normalized.length, revoked: superseded.length }; });
    });
  }

  // Revoke every cert the issuance ledger recorded under a CA generation < n.
  // (Pre-#532 / out-of-band certs are unindexed until importIssuance() backfills
  // them — see above.) Enforcement is fingerprint-keyed through the revocation
  // registry —
  // isRevoked() and a require-mtls gate wired with `revocationSource: caHandle`
  // deny these certs regardless of which CA generation issued them. A standard
  // X.509 CRL cannot: generateCrl() signs with the CURRENT CA, which a peer will
  // not accept as revoking a cert issued by a superseded generation. For a CRL-
  // consuming deployment, publish generateCrl() for a generation while it is
  // still current (before rotate() supersedes its signing key); the registry
  // path above needs no such ordering.
  // Like revoke(): SYNC-throws on bad input, returns a PROMISE for { revoked }.
  function revokeGeneration(n, opts3) {
    if (typeof n !== "number" || !isFinite(n) || n < 1 || Math.floor(n) !== n) {
      throw new MtlsCaError("mtls-ca/bad-generation",
        "revokeGeneration: n must be a positive integer (revokes every cert issued under a CA generation < n)");
    }
    opts3 = opts3 || {};
    var reason = opts3.reason || "superseded";
    var reasonCode = CRL_REASON_BY_NAME[reason];
    if (reasonCode === undefined) {
      throw new MtlsCaError("mtls-ca/bad-reason",
        "revokeGeneration: unknown reason '" + reason + "' (valid: " +
        Object.keys(CRL_REASON_BY_NAME).join(", ") + ")");
    }
    var sweep = function () {
      // Uses _revokeCore directly — for the default store we already hold the
      // revocation lock here, so calling revoke() would re-enter it.
      var before = revocationStore.list().length;
      issuanceStore.list().forEach(function (e) {
        if (e && typeof e.generation === "number" && e.generation < n && (e.serialNumber || e.fingerprint)) {
          _revokeCore(e.serialNumber || null, e.fingerprint || null, reason, reasonCode);
        }
      });
      return { revoked: revocationStore.list().length - before };
    };
    // Bump the watermark (atomic for ALL stores — a shared custom store's
    // bumpGenerationWatermark, else a locked local-file RMW) BEFORE sweeping, so
    // an in-flight issuance that records after the sweep-read still self-revokes
    // (see _recordIssuance).
    return _bumpRevokedWatermark(n).then(function () {
      return usesDefaultRevocationStore ? atomicFile.lock(paths.revocations, sweep) : Promise.resolve(sweep());
    });
  }

  // CA-handle convenience over the engine probe: can node:tls VERIFY a chain
  // under a given algorithm on this runtime? Pass the PROSPECTIVE algorithm to
  // pre-flight a migration — canVerifyInTls("ML-DSA-87") before
  // rotate({ algorithm: "ML-DSA-87" }) probes the TARGET, not the current CA, so
  // an ECDSA-stored handle does not falsely pass when the runtime cannot verify
  // the ML-DSA chain it is about to activate. With no argument it probes the
  // stored CA's algorithm (or the create-time pin / engine default when none is
  // stored yet). Delegates to engine.canVerifyInTls(label).
  async function canVerifyInTls(algorithm) {
    if (typeof engine.canVerifyInTls !== "function") {
      throw new MtlsCaError("mtls-ca/no-tls-probe",
        "the configured engine does not implement canVerifyInTls(label)");
    }
    var st = status();
    // For a CUSTOM engine, prefer the create-time pin (caAlgorithm) over status()'s
    // inferred label: status() infers a BUNDLED label (e.g. ML-DSA-87) from the
    // cert's key type, but a custom engine may use its own label for that key type,
    // which only its create-time pin carries — passing the bundled label could make
    // the engine reject or misinterpret the probe. The default engine's inferred
    // label matches its own label set, so status() wins there.
    var label = (typeof algorithm === "string" && algorithm.length > 0)
      ? algorithm
      : (usesDefaultEngine ? (st.algorithm || caAlgorithm) : (caAlgorithm || st.algorithm));
    // Refuse an undeterminable label ONLY when a CA is STORED whose algorithm this
    // runtime cannot classify (status().algorithm === null — e.g. a P-256 custom
    // engine — with no create-time pin): passing undefined to the engine would then
    // let one that reads an omitted label as "current default" probe a DIFFERENT
    // algorithm than the stored CA, reporting on the wrong chain. With NO CA stored
    // yet, an omitted label is unambiguous — the engine resolves its default, which
    // is exactly the intended pre-flight probe on a fresh deployment — so pass it
    // through rather than forcing the operator to name a label they may not know.
    if ((typeof label !== "string" || label.length === 0) && st.exists) {
      throw new MtlsCaError("mtls-ca/algorithm-undeterminable",
        "canVerifyInTls() cannot derive the stored CA's algorithm (a custom-engine CA this runtime does " +
        "not classify, with no create-time pin) — pass the algorithm explicitly, e.g. canVerifyInTls(\"ML-DSA-87\")");
    }
    return engine.canVerifyInTls(label);
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
    importIssuance:       importIssuance,
    generateClientCert:   generateClientCert,
    generateClientP12:    generateClientP12,
    revoke:               revoke,
    isRevoked:            isRevoked,
    // isRevoked already matches a serial OR fingerprint; this alias signals to a
    // require-mtls gate that this source supports serial-number lookups (so it may
    // check the peer cert's serial), without changing isRevoked's contract.
    isSerialRevoked:      isRevoked,
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
