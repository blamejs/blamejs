"use strict";
/**
 * Audit signing key — separate PQC keypair for periodic checkpoint
 * signatures over the audit chain.
 *
 * Algorithm: SLH-DSA-SHAKE-256f (FIPS 205) by default. ML-DSA-87
 * (FIPS 204) supported as an opt-in alternative for throughput-
 * sensitive deployments. Both are NIST PQC Category 5 (~256-bit
 * symmetric security). SLH-DSA-SHAKE-256f is hash-only — its
 * security depends solely on the underlying hash function, with no
 * lattice / module-hardness assumptions — and matches the framework's
 * SHAKE256 KDF + SHA3-512 hash family. Audit checkpoints are long-
 * lived integrity attestations (must verify for the data retention
 * period — years for HIPAA / SOX), so the conservative-PQC posture
 * carries more weight here than the smaller ML-DSA-87 signature
 * (~5 KB) and faster sign (0.6 ms vs 76 ms).
 *
 * The algorithm is recorded in the on-disk key file's `algorithm`
 * field. Older key files that predate the algorithm field are loaded
 * as ML-DSA-87 (the previous implicit default) and continue to verify
 * their checkpoint history. Operators who want to migrate rotate
 * their audit-signing key.
 *
 * Design:
 *   - Different keypair from the vault encryption keys. Compromise of the
 *     vault DOES NOT let an attacker forge audit checkpoints.
 *   - Stored at <dataDir>/audit-sign.key.sealed (default 'wrapped' mode)
 *     or <dataDir>/audit-sign.key (opt-out 'plaintext' mode with warning).
 *   - Wrapped under its OWN passphrase, sourced via:
 *       BLAMEJS_AUDIT_SIGNING_PASSPHRASE         (env)
 *       BLAMEJS_AUDIT_SIGNING_PASSPHRASE_FILE    (file)
 *       BLAMEJS_AUDIT_SIGNING_PASSPHRASE_SOURCE  (selector: auto|env|file|stdin)
 *     These are intentionally distinct from BLAMEJS_VAULT_PASSPHRASE so
 *     operator-error reuse of the same passphrase is at least explicit.
 *   - First-run generates the keypair automatically.
 *
 * Threat model:
 *   - Vault key compromised + DB write access:
 *       attacker can read sealed values + rewrite audit_log rows + recompute
 *       per-row chain hashes. They CANNOT forge new audit_checkpoint rows
 *       because each checkpoint requires the audit-signing private key.
 *   - Audit signing key compromised:
 *       attacker can forge new checkpoints but cannot read sealed values.
 *       Existing checkpoints still anchor history that pre-dated the
 *       compromise (operator should rotate signing key on detection).
 *   - Both compromised:
 *       framework cannot defend against this — by design, the operator's
 *       physical / administrative controls (HIPAA §164.310, GDPR Art. 32(1)(d))
 *       cover this case.
 *
 * Public API:
 *   await auditSign.init({ dataDir, mode? })   ← call at db.init()
 *   auditSign.sign(payload)                    ← Buffer/string → Buffer signature
 *   auditSign.verify(payload, signature, publicKey?) ← bool
 *   auditSign.getPublicKey()                   ← PEM string
 *   auditSign.getPublicKeyFingerprint()        ← sha3 hex (stable id)
 *   auditSign.getMode()                        ← 'wrapped' | 'plaintext'
 */
var fs = require("fs");
var path = require("path");
var nodeCrypto = require("crypto");
var atomicFile = require("./atomic-file");
var { sha3Hash } = require("./crypto");
var { boot } = require("./log");
var safeBuffer = require("./safe-buffer");
var safeJson = require("./safe-json");
var vaultPassphraseSource = require("./vault/passphrase-source");
var vaultWrap = require("./vault/wrap");

// Default for newly-generated keys. Operators can override at init
// via opts.algorithm — e.g. `auditSigning: { algorithm: "ml-dsa-87" }`
// for throughput-sensitive deployments. Existing key files determine
// their own algorithm via the on-disk `algorithm` field; legacy key
// files that predate the algorithm field load as "ml-dsa-87" (the
// previous implicit default).
var DEFAULT_SIGNING_ALG = "slh-dsa-shake-256f";
var LEGACY_DEFAULT_ALG  = "ml-dsa-87";
var SUPPORTED_SIGNING_ALGS = Object.freeze(["slh-dsa-shake-256f", "ml-dsa-87"]);

var SIGNING_KEY_SCHEMA = {
  type: "object",
  required: ["publicKey", "privateKey"],
  properties: {
    publicKey:  { type: "string" },
    privateKey: { type: "string" },
    algorithm:  { type: "string" },     // optional; missing = legacy ml-dsa-87
  },
};

var ENV_VARS = {
  value:  "BLAMEJS_AUDIT_SIGNING_PASSPHRASE",
  file:   "BLAMEJS_AUDIT_SIGNING_PASSPHRASE_FILE",
  source: "BLAMEJS_AUDIT_SIGNING_PASSPHRASE_SOURCE",
};

var keys = null;            // { publicKey: PEM, privateKey: PEM, fingerprint }
var initialized = false;
var currentMode = null;
var paths = null;

var log = boot("audit-sign");

function resolvePaths(dataDir) {
  return {
    dataDir:    dataDir,
    plaintext:  path.join(dataDir, "audit-sign.key"),
    sealed:     path.join(dataDir, "audit-sign.key.sealed"),
  };
}

function _computeFingerprint(publicKeyPem) {
  return sha3Hash(publicKeyPem);
}

// ---- Passphrase sourcing (delegates to lib/passphrase-source.js with
// audit-signing-specific env var names) ----

function _getPassphrase(promptText) {
  return vaultPassphraseSource.getPassphrase({
    envVars: ENV_VARS,
    prompt:  promptText || "Audit-signing passphrase: ",
  });
}

// ---- Init ----

// Algorithm chosen for newly-generated keypairs. Set once per init()
// call and read by _initPlaintext / _initFirstRunWrapped. Existing key
// files take their algorithm from the file itself, ignoring this.
var pendingNewKeyAlg = null;

async function init(opts) {
  if (initialized) return;
  if (!opts || !opts.dataDir) throw new Error("auditSign.init({ dataDir }) is required");

  var mode = (opts.mode || "wrapped").toLowerCase();
  if (mode !== "wrapped" && mode !== "plaintext") {
    throw new Error("auditSign.init: mode must be 'wrapped' or 'plaintext'");
  }
  // Algorithm-on-generate. Validated against the supported list so
  // typos surface here, not as an opaque "key generation failed"
  // deeper in nodeCrypto.
  var alg = (opts.algorithm || DEFAULT_SIGNING_ALG).toLowerCase();
  if (SUPPORTED_SIGNING_ALGS.indexOf(alg) === -1) {
    throw new Error("auditSign.init: algorithm must be one of " +
      SUPPORTED_SIGNING_ALGS.join(", ") + " (got: " + alg + ")");
  }
  pendingNewKeyAlg = alg;
  currentMode = mode;
  paths = resolvePaths(opts.dataDir);

  if (!fs.existsSync(paths.dataDir)) fs.mkdirSync(paths.dataDir, { recursive: true });
  // Sweep tmp files from any prior crashed write
  atomicFile.cleanOrphans(paths.sealed);
  atomicFile.cleanOrphans(paths.plaintext);

  var hasPlaintext = fs.existsSync(paths.plaintext);
  var hasSealed    = fs.existsSync(paths.sealed);
  if (hasPlaintext && hasSealed) {
    log.error("FATAL: both audit-sign.key and audit-sign.key.sealed exist; resolve manually.");
    process.exit(1);
  }
  if (hasSealed && mode === "plaintext") {
    log.error("FATAL: audit-sign.key.sealed exists but mode='plaintext' requested.");
    process.exit(1);
  }
  if (hasPlaintext && mode === "wrapped") {
    log.error("FATAL: audit-sign.key (plaintext) exists but mode='wrapped' requested.");
    process.exit(1);
  }

  if (mode === "wrapped") {
    if (hasSealed) await _initWrapped();
    else await _initFirstRunWrapped();
  } else {
    log.warn("WARNING: PLAINTEXT mode — audit-sign.key is unprotected on disk.");
    log.warn("         Use mode: 'wrapped' (default) for any deployment that holds real data.");
    _initPlaintext();
  }

  initialized = true;
}

function _initPlaintext() {
  if (fs.existsSync(paths.plaintext)) {
    var loaded;
    try { loaded = safeJson.parse(atomicFile.readSync(paths.plaintext), { schema: SIGNING_KEY_SCHEMA }); }
    catch (e) { log.error("FATAL: audit-sign.key corrupted or schema-invalid at " + paths.plaintext + " — " + e.message); process.exit(1); }
    var loadedAlg = loaded.algorithm || LEGACY_DEFAULT_ALG;
    keys = {
      publicKey:  loaded.publicKey,
      privateKey: loaded.privateKey,
      algorithm:  loadedAlg,
      fingerprint: _computeFingerprint(loaded.publicKey),
    };
    return;
  }
  // First run, plaintext — generate with the operator-selected (or default) alg
  var alg = pendingNewKeyAlg || DEFAULT_SIGNING_ALG;
  var pair = nodeCrypto.generateKeyPairSync(alg, {
    publicKeyEncoding:  { type: "spki",  format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  keys = {
    publicKey:  pair.publicKey,
    privateKey: pair.privateKey,
    algorithm:  alg,
    fingerprint: _computeFingerprint(pair.publicKey),
  };
  atomicFile.writeSync(
    paths.plaintext,
    JSON.stringify({ algorithm: alg, publicKey: keys.publicKey, privateKey: keys.privateKey }, null, 2),
    { fileMode: 0o600 }
  );
  log("plaintext audit-signing keypair generated at " + paths.plaintext + " (alg=" + alg + ")");
}

async function _initWrapped() {
  log("unsealing audit-sign.key.sealed...");
  var sealedBytes = atomicFile.readSync(paths.sealed);
  var passphrase = await _getPassphrase("Audit-signing passphrase: ");
  var plaintextBuf;
  try {
    try { plaintextBuf = await vaultWrap.unwrap(sealedBytes, passphrase); }
    catch (e) { log.error("FATAL: audit-signing passphrase rejected (" + e.message + ")"); process.exit(1); }
    var loaded;
    try { loaded = safeJson.parse(plaintextBuf, { schema: SIGNING_KEY_SCHEMA }); }
    catch (e) { log.error("FATAL: unwrapped audit-sign.key invalid: " + e.message); process.exit(1); }
    var loadedAlg = loaded.algorithm || LEGACY_DEFAULT_ALG;
    keys = {
      publicKey:  loaded.publicKey,
      privateKey: loaded.privateKey,
      algorithm:  loadedAlg,
      fingerprint: _computeFingerprint(loaded.publicKey),
    };
    log("audit-signing keypair unsealed (alg=" + loadedAlg + ").");
  } finally {
    // The audit-signing passphrase is single-use at boot — no re-wrap path
    // keeps it alive (unlike vault.currentPassphrase). Zero on the way out.
    safeBuffer.secureZero(passphrase);
    if (plaintextBuf) safeBuffer.secureZero(plaintextBuf);
  }
}

async function _initFirstRunWrapped() {
  var alg = pendingNewKeyAlg || DEFAULT_SIGNING_ALG;
  log("first-run wrapped — generating audit-signing keypair (alg=" + alg + ")...");
  var passphrase = await _getPassphrase("Choose an audit-signing passphrase: ");
  try {
    var pair = nodeCrypto.generateKeyPairSync(alg, {
      publicKeyEncoding:  { type: "spki",  format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    keys = {
      publicKey:  pair.publicKey,
      privateKey: pair.privateKey,
      algorithm:  alg,
      fingerprint: _computeFingerprint(pair.publicKey),
    };

    var sealed = await vaultWrap.wrap(
      JSON.stringify({ algorithm: alg, publicKey: keys.publicKey, privateKey: keys.privateKey }, null, 2),
      passphrase
    );
    atomicFile.writeSync(paths.sealed, sealed, { fileMode: 0o600 });
    log("generated and sealed audit-signing keypair (alg=" + alg + ")");
  } finally {
    safeBuffer.secureZero(passphrase);
  }
}

// ---- Public API ----

function _requireInit() {
  if (!initialized) throw new Error("auditSign.init() must be awaited before sign/verify");
}

function sign(payload) {
  _requireInit();
  var buf = Buffer.isBuffer(payload) ? payload : Buffer.from(String(payload), "utf8");
  return nodeCrypto.sign(null, buf, keys.privateKey);
}

function verify(payload, signature, publicKeyPem) {
  _requireInit();
  var buf = Buffer.isBuffer(payload) ? payload : Buffer.from(String(payload), "utf8");
  var sigBuf = Buffer.isBuffer(signature) ? signature : Buffer.from(signature);
  var pub = publicKeyPem || keys.publicKey;
  return nodeCrypto.verify(null, buf, pub, sigBuf);
}

function getPublicKey() { _requireInit(); return keys.publicKey; }
function getPublicKeyFingerprint() { _requireInit(); return keys.fingerprint; }
function getMode() { return currentMode; }
function getAlgorithm() { _requireInit(); return keys.algorithm; }

function _resetForTest() {
  keys = null;
  initialized = false;
  currentMode = null;
  paths = null;
  pendingNewKeyAlg = null;
}

module.exports = {
  init:                     init,
  sign:                     sign,
  verify:                   verify,
  getPublicKey:             getPublicKey,
  getPublicKeyFingerprint:  getPublicKeyFingerprint,
  getMode:                  getMode,
  getAlgorithm:             getAlgorithm,
  DEFAULT_SIGNING_ALG:      DEFAULT_SIGNING_ALG,
  SUPPORTED_SIGNING_ALGS:   SUPPORTED_SIGNING_ALGS,
  ENV_PASSPHRASE:           ENV_VARS.value,
  ENV_PASSPHRASE_FILE:      ENV_VARS.file,
  ENV_PASSPHRASE_SRC:       ENV_VARS.source,
  _resetForTest:            _resetForTest,
};
