"use strict";
/**
 * Vault — sealed keystore for the framework's encryption keys.
 *
 * Holds the ML-KEM-1024 + P-384 hybrid keypair used by every other framework
 * subsystem that calls vault.seal() / vault.unseal() (db field encryption,
 * session storage, audit log signing, etc.). Keys never leave the process
 * after init() in any decrypted form except via the vault.seal/unseal API.
 *
 * Modes (default is 'wrapped' — highest-security; 'plaintext' is opt-out
 * with explicit boot warning per the framework's modernity stance):
 *
 *   wrapped    — vault.key.sealed file, passphrase-derived AEAD wrap (lib/vault-wrap.js).
 *                Argon2id → SHAKE256 → XChaCha20-Poly1305. Default.
 *   plaintext  — vault.key file (JSON, mode 0o600). For development only.
 *                Emits console.warn at boot. Opt-out only.
 *
 * Two-API contract (sync seal/unseal, async init):
 *
 *   await vault.init({ dataDir, mode? })   ← call once at app bootstrap
 *   vault.seal(value)                      ← sync, post-init
 *   vault.unseal(value)                    ← sync, post-init
 *
 * Why two APIs: seal/unseal have hundreds of call sites across a typical app,
 * many at module-require time. Making them async would require an invasive
 * refactor of every consumer. Instead, the bootstrap awaits init() once, then
 * everything runs synchronously against the in-process key cache.
 *
 * Sealed-value format: "vault:" prefix + base64 envelope from lib/crypto.js.
 * Old envelopes always remain readable (envelope versioning); new writes use
 * the active KEM/CIPHER/KDF.
 */
var fs = require("fs");
var path = require("path");
var { generateEncryptionKeyPair, encrypt, decrypt, sha3Hash } = require("./crypto");
var atomicFile = require("./atomic-file");
var jsonSafe = require("./json-safe");
var passphraseSource = require("./passphrase-source");
var vaultWrap = require("./vault-wrap");
var bufferSafe = require("./buffer-safe");
var C = require("./constants");

var VAULT_PREFIX = C.VAULT_PREFIX;

// Module-local cache populated by init().
var keys = null;
var initialized = false;
// Passphrase retained post-init (best-effort) for operations that need it
// later — vault rotation, backup re-wrap. Already in JS heap during unwrap;
// retaining doesn't change the threat model meaningfully.
var currentPassphrase = null;
// Resolved paths (set by init based on dataDir option)
var paths = null;
var currentMode = null;

function log(msg) { console.log("[blamejs:vault] " + msg); }
function logErr(msg) { console.error("[blamejs:vault] " + msg); }

function resolvePaths(dataDir) {
  return {
    dataDir:    dataDir,
    plaintext:  path.join(dataDir, "vault.key"),
    sealed:     path.join(dataDir, "vault.key.sealed"),
  };
}

// ---- Init dispatch ----

async function init(opts) {
  if (initialized) return;
  opts = opts || {};

  if (!opts.dataDir) {
    throw new Error("vault.init({ dataDir }) is required");
  }

  var mode = (opts.mode || "wrapped").toLowerCase();
  if (mode !== "wrapped" && mode !== "plaintext") {
    throw new Error("vault.init: mode must be 'wrapped' or 'plaintext', got: " + opts.mode);
  }
  currentMode = mode;
  paths = resolvePaths(opts.dataDir);

  if (!fs.existsSync(paths.dataDir)) {
    fs.mkdirSync(paths.dataDir, { recursive: true });
  }

  // Sweep tmp files left behind by a previously-crashed write
  atomicFile.cleanOrphans(paths.sealed);
  atomicFile.cleanOrphans(paths.plaintext);

  var hasPlaintext = fs.existsSync(paths.plaintext);
  var hasSealed    = fs.existsSync(paths.sealed);

  // Refuse to guess when both files coexist
  if (hasPlaintext && hasSealed) {
    logErr("FATAL: both vault.key and vault.key.sealed exist in " + paths.dataDir);
    logErr("Delete the one you do NOT want to keep, then restart.");
    process.exit(1);
  }

  // Mode-vs-state mismatches
  if (hasSealed && mode === "plaintext") {
    logErr("FATAL: vault.key.sealed exists but vault.init({ mode: 'plaintext' }) was requested.");
    logErr("Either run with mode: 'wrapped', or remove the sealed file (after migration).");
    process.exit(1);
  }
  if (hasPlaintext && mode === "wrapped") {
    logErr("FATAL: vault.key (plaintext) exists but vault.init({ mode: 'wrapped' }) was requested.");
    logErr("Either run with mode: 'plaintext', or migrate the key to a wrapped form.");
    process.exit(1);
  }

  if (mode === "wrapped") {
    if (hasSealed) await initWrapped();
    else await initFirstRunWrapped();
  } else {
    // mode === "plaintext"
    console.warn(
      "[blamejs:vault] WARNING: running in PLAINTEXT mode — vault.key is unprotected on disk.\n" +
      "                Use mode: 'wrapped' (default) for any deployment that holds real data.\n" +
      "                See https://github.com/blamejs/blamejs#vault-modes for details."
    );
    initPlaintext();
  }

  initialized = true;
}

function initPlaintext() {
  if (fs.existsSync(paths.plaintext)) {
    var loaded;
    try {
      loaded = jsonSafe.parse(atomicFile.readSync(paths.plaintext), {
        schema: {
          type: "object",
          required: ["publicKey", "privateKey", "ecPublicKey", "ecPrivateKey"],
          properties: {
            publicKey:    { type: "string" },
            privateKey:   { type: "string" },
            ecPublicKey:  { type: "string" },
            ecPrivateKey: { type: "string" },
          },
        },
      });
    } catch (e) {
      logErr("FATAL: vault.key corrupted, unreadable, or schema-invalid at " + paths.plaintext + " — " + e.message);
      logErr("All sealed data requires the original key. Restore from backup, then restart.");
      process.exit(1);
    }
    keys = loaded;
    return;
  }
  // First run, plaintext mode
  keys = generateEncryptionKeyPair();
  atomicFile.writeSync(paths.plaintext, JSON.stringify(keys, null, 2), { fileMode: 0o600 });
  log("plaintext vault keypair generated at " + paths.plaintext);
}

async function initWrapped() {
  log("unsealing vault.key.sealed...");
  var sealedBytes;
  try {
    sealedBytes = atomicFile.readSync(paths.sealed);
  } catch (e) {
    logErr("FATAL: cannot read " + paths.sealed + ": " + e.message);
    process.exit(1);
  }

  var passphrase;
  try {
    passphrase = await passphraseSource.getPassphrase({ prompt: "Vault passphrase: " });
  } catch (e) {
    logErr("FATAL: " + e.message);
    process.exit(1);
  }

  var plaintextJson;
  var plaintextBuf;
  try {
    plaintextBuf = await vaultWrap.unwrap(sealedBytes, passphrase);
    plaintextJson = plaintextBuf.toString("utf8");
  } catch (e) {
    logErr("FATAL: passphrase rejected or sealed file corrupted (" + e.message + ")");
    process.exit(1);
  } finally {
    // The Buffer holding the unwrapped key JSON is no longer needed once
    // toString has copied the bytes into plaintextJson. The string itself
    // is referenced by the JSON parser below; can't be zeroed (V8 strings
    // are GC-managed). secureZero on the Buffer at least removes one
    // copy of the secret from the heap.
    if (plaintextBuf) bufferSafe.secureZero(plaintextBuf);
  }
  currentPassphrase = passphrase;

  try {
    keys = jsonSafe.parse(plaintextJson, {
      schema: {
        type: "object",
        required: ["publicKey", "privateKey", "ecPublicKey", "ecPrivateKey"],
        properties: {
          publicKey:    { type: "string" },
          privateKey:   { type: "string" },
          ecPublicKey:  { type: "string" },
          ecPrivateKey: { type: "string" },
        },
      },
    });
  } catch (e) {
    logErr("FATAL: unwrapped vault key invalid: " + e.message);
    process.exit(1);
  }
  log("unsealed successfully.");
}

async function initFirstRunWrapped() {
  log("first run with mode: 'wrapped' — generating wrapped keypair...");

  var passphrase;
  try {
    passphrase = await passphraseSource.getPassphrase({
      prompt: "Choose a vault passphrase (loss = data loss, store it safely): ",
    });
  } catch (e) {
    logErr("FATAL: " + e.message);
    process.exit(1);
  }
  currentPassphrase = passphrase;

  keys = generateEncryptionKeyPair();
  var plaintextJson = JSON.stringify(keys, null, 2);
  var sealed;
  try {
    sealed = await vaultWrap.wrap(plaintextJson, passphrase);
  } catch (e) {
    logErr("FATAL: failed to wrap new vault key: " + e.message);
    process.exit(1);
  }

  // Atomic write via the framework's atomic-file primitive (temp + fsync +
  // rename + dir fsync — same flow this code used to inline manually).
  atomicFile.writeSync(paths.sealed, sealed, { fileMode: 0o600 });

  log("generated and sealed new vault keypair (ML-KEM-1024 + P-384 hybrid)");
}

// ---- Sync API — operates against the populated cache ----

function _requireInit() {
  if (!initialized) {
    throw new Error("vault.init() must be awaited before vault.seal/unseal/getKeysJson");
  }
}

function seal(plaintext) {
  if (!plaintext) return plaintext;
  if (String(plaintext).startsWith(VAULT_PREFIX)) return plaintext;
  _requireInit();
  return VAULT_PREFIX + encrypt(String(plaintext), keys);
}

function unseal(value) {
  if (!value || !String(value).startsWith(VAULT_PREFIX)) return value;
  _requireInit();
  var payload = String(value).substring(VAULT_PREFIX.length);
  return decrypt(payload, keys);
}

function getKeysJson() {
  _requireInit();
  return JSON.stringify(keys, null, 2);
}

function getCurrentPassphrase() {
  return currentPassphrase;
}

function getMode() {
  return currentMode;
}

module.exports = {
  init:                  init,
  seal:                  seal,
  unseal:                unseal,
  getKeysJson:           getKeysJson,
  getCurrentPassphrase:  getCurrentPassphrase,
  getMode:               getMode,
  // Testing helpers — not part of the public contract
  _resetForTest:         function () {
    if (currentPassphrase) bufferSafe.secureZero(currentPassphrase);
    keys = null; initialized = false; currentPassphrase = null; paths = null; currentMode = null;
  },
  _getKeysForTest:       function () { return keys; },
  _getPathsForTest:      function () { return paths; },
};
