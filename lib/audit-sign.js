"use strict";
/**
 * Audit signing key — separate ML-DSA-87 keypair for periodic checkpoint
 * signatures over the audit chain.
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
var { sha3Hash } = require("./crypto");
var atomicFile = require("./atomic-file");
var vaultWrap = require("./vault-wrap");
var jsonSafe = require("./json-safe");
var passphraseSource = require("./passphrase-source");
var bufferSafe = require("./buffer-safe");

var SIGNING_KEY_SCHEMA = {
  type: "object",
  required: ["publicKey", "privateKey"],
  properties: {
    publicKey:  { type: "string" },
    privateKey: { type: "string" },
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

function log(msg)    { console.log("[blamejs:audit-sign] " + msg); }
function logErr(msg) { console.error("[blamejs:audit-sign] " + msg); }

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
  return passphraseSource.getPassphrase({
    envVars: ENV_VARS,
    prompt:  promptText || "Audit-signing passphrase: ",
  });
}

// ---- Init ----

async function init(opts) {
  if (initialized) return;
  if (!opts || !opts.dataDir) throw new Error("auditSign.init({ dataDir }) is required");

  var mode = (opts.mode || "wrapped").toLowerCase();
  if (mode !== "wrapped" && mode !== "plaintext") {
    throw new Error("auditSign.init: mode must be 'wrapped' or 'plaintext'");
  }
  currentMode = mode;
  paths = resolvePaths(opts.dataDir);

  if (!fs.existsSync(paths.dataDir)) fs.mkdirSync(paths.dataDir, { recursive: true });
  // Sweep tmp files from any prior crashed write
  atomicFile.cleanOrphans(paths.sealed);
  atomicFile.cleanOrphans(paths.plaintext);

  var hasPlaintext = fs.existsSync(paths.plaintext);
  var hasSealed    = fs.existsSync(paths.sealed);
  if (hasPlaintext && hasSealed) {
    logErr("FATAL: both audit-sign.key and audit-sign.key.sealed exist; resolve manually.");
    process.exit(1);
  }
  if (hasSealed && mode === "plaintext") {
    logErr("FATAL: audit-sign.key.sealed exists but mode='plaintext' requested.");
    process.exit(1);
  }
  if (hasPlaintext && mode === "wrapped") {
    logErr("FATAL: audit-sign.key (plaintext) exists but mode='wrapped' requested.");
    process.exit(1);
  }

  if (mode === "wrapped") {
    if (hasSealed) await _initWrapped();
    else await _initFirstRunWrapped();
  } else {
    console.warn(
      "[blamejs:audit-sign] WARNING: PLAINTEXT mode — audit-sign.key is unprotected on disk.\n" +
      "                     Use mode: 'wrapped' (default) for any deployment that holds real data."
    );
    _initPlaintext();
  }

  initialized = true;
}

function _initPlaintext() {
  if (fs.existsSync(paths.plaintext)) {
    var loaded;
    try { loaded = jsonSafe.parse(atomicFile.readSync(paths.plaintext), { schema: SIGNING_KEY_SCHEMA }); }
    catch (e) { logErr("FATAL: audit-sign.key corrupted or schema-invalid at " + paths.plaintext + " — " + e.message); process.exit(1); }
    keys = { publicKey: loaded.publicKey, privateKey: loaded.privateKey, fingerprint: _computeFingerprint(loaded.publicKey) };
    return;
  }
  // First run, plaintext
  var pair = nodeCrypto.generateKeyPairSync("ml-dsa-87", {
    publicKeyEncoding:  { type: "spki",  format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  keys = { publicKey: pair.publicKey, privateKey: pair.privateKey, fingerprint: _computeFingerprint(pair.publicKey) };
  atomicFile.writeSync(paths.plaintext, JSON.stringify({ publicKey: keys.publicKey, privateKey: keys.privateKey }, null, 2), { fileMode: 0o600 });
  log("plaintext audit-signing keypair generated at " + paths.plaintext);
}

async function _initWrapped() {
  log("unsealing audit-sign.key.sealed...");
  var sealedBytes = atomicFile.readSync(paths.sealed);
  var passphrase = await _getPassphrase("Audit-signing passphrase: ");
  var plaintextBuf;
  try {
    try { plaintextBuf = await vaultWrap.unwrap(sealedBytes, passphrase); }
    catch (e) { logErr("FATAL: audit-signing passphrase rejected (" + e.message + ")"); process.exit(1); }
    var loaded;
    try { loaded = jsonSafe.parse(plaintextBuf, { schema: SIGNING_KEY_SCHEMA }); }
    catch (e) { logErr("FATAL: unwrapped audit-sign.key invalid: " + e.message); process.exit(1); }
    keys = { publicKey: loaded.publicKey, privateKey: loaded.privateKey, fingerprint: _computeFingerprint(loaded.publicKey) };
    log("audit-signing keypair unsealed.");
  } finally {
    // The audit-signing passphrase is single-use at boot — no re-wrap path
    // keeps it alive (unlike vault.currentPassphrase). Zero on the way out.
    bufferSafe.secureZero(passphrase);
    if (plaintextBuf) bufferSafe.secureZero(plaintextBuf);
  }
}

async function _initFirstRunWrapped() {
  log("first-run wrapped — generating audit-signing keypair...");
  var passphrase = await _getPassphrase("Choose an audit-signing passphrase: ");
  try {
    var pair = nodeCrypto.generateKeyPairSync("ml-dsa-87", {
      publicKeyEncoding:  { type: "spki",  format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    keys = { publicKey: pair.publicKey, privateKey: pair.privateKey, fingerprint: _computeFingerprint(pair.publicKey) };

    var sealed = await vaultWrap.wrap(JSON.stringify({ publicKey: keys.publicKey, privateKey: keys.privateKey }, null, 2), passphrase);
    atomicFile.writeSync(paths.sealed, sealed, { fileMode: 0o600 });
    log("generated and sealed audit-signing keypair (ML-DSA-87)");
  } finally {
    bufferSafe.secureZero(passphrase);
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

function _resetForTest() {
  keys = null;
  initialized = false;
  currentMode = null;
  paths = null;
}

module.exports = {
  init:                     init,
  sign:                     sign,
  verify:                   verify,
  getPublicKey:             getPublicKey,
  getPublicKeyFingerprint:  getPublicKeyFingerprint,
  getMode:                  getMode,
  ENV_PASSPHRASE:           ENV_VARS.value,
  ENV_PASSPHRASE_FILE:      ENV_VARS.file,
  ENV_PASSPHRASE_SRC:       ENV_VARS.source,
  _resetForTest:            _resetForTest,
};
