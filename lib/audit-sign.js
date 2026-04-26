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
var readline = require("readline");
var nodeCrypto = require("crypto");
var { sha3Hash } = require("./crypto");

var ENV_PASSPHRASE      = "BLAMEJS_AUDIT_SIGNING_PASSPHRASE";
var ENV_PASSPHRASE_FILE = "BLAMEJS_AUDIT_SIGNING_PASSPHRASE_FILE";
var ENV_PASSPHRASE_SRC  = "BLAMEJS_AUDIT_SIGNING_PASSPHRASE_SOURCE";
var MAX_PASSPHRASE_BYTES = 4096;

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
    sealedTmp:  path.join(dataDir, "audit-sign.key.sealed.tmp"),
  };
}

function _computeFingerprint(publicKeyPem) {
  return sha3Hash(publicKeyPem);
}

// ---- Passphrase sourcing (parallel to lib/passphrase-source.js but with
// audit-signing-specific env var names) ----

async function _getPassphrase(promptText) {
  var src = (process.env[ENV_PASSPHRASE_SRC] || "auto").toLowerCase();
  if (src === "auto") {
    if (process.env[ENV_PASSPHRASE_FILE]) src = "file";
    else if (process.env[ENV_PASSPHRASE]) src = "env";
    else if (process.stdin.isTTY) src = "stdin";
    else throw new Error(
      "no audit-signing passphrase source. Set " + ENV_PASSPHRASE + ", " +
      ENV_PASSPHRASE_FILE + ", or run with a TTY on stdin."
    );
  }
  if (src === "env") {
    var v = process.env[ENV_PASSPHRASE];
    if (!v) throw new Error(ENV_PASSPHRASE + " is empty");
    var buf = Buffer.from(v, "utf8");
    if (buf.length > MAX_PASSPHRASE_BYTES) throw new Error("passphrase exceeds " + MAX_PASSPHRASE_BYTES + " byte limit");
    delete process.env[ENV_PASSPHRASE];
    return buf;
  }
  if (src === "file") {
    var fp = process.env[ENV_PASSPHRASE_FILE];
    var raw = fs.readFileSync(fp);
    var end = raw.length;
    while (end > 0) { var b = raw[end - 1]; if (b === 0x0A || b === 0x0D) end--; else break; }
    var trimmed = end === raw.length ? raw : raw.subarray(0, end);
    if (trimmed.length === 0) throw new Error(fp + " contains an empty passphrase");
    if (trimmed.length > MAX_PASSPHRASE_BYTES) throw new Error("passphrase file exceeds " + MAX_PASSPHRASE_BYTES + " byte limit");
    return trimmed;
  }
  if (src === "stdin") {
    return new Promise(function (resolve, reject) {
      var rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
      process.stdout.write(promptText || "Audit-signing passphrase: ");
      var chunks = [];
      var onData = function (chunk) {
        for (var i = 0; i < chunk.length; i++) {
          var b = chunk[i];
          if (b === 0x03) { cleanup(); process.stdout.write("\n"); reject(new Error("cancelled")); return; }
          if (b === 0x0A || b === 0x0D) {
            cleanup(); process.stdout.write("\n");
            var buf = Buffer.concat(chunks);
            if (buf.length === 0) return reject(new Error("empty passphrase"));
            return resolve(buf);
          }
          if (b === 0x7F || b === 0x08) { if (chunks.length) chunks.pop(); continue; }
          chunks.push(Buffer.from([b]));
        }
      };
      var cleanup = function () { try { process.stdin.setRawMode(false); } catch (_e) {} process.stdin.removeListener("data", onData); rl.close(); };
      process.stdin.setRawMode(true); process.stdin.resume(); process.stdin.on("data", onData);
    });
  }
  throw new Error("unknown source: " + src);
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
  if (fs.existsSync(paths.sealedTmp)) {
    try { fs.unlinkSync(paths.sealedTmp); log("cleaned orphan audit-sign.key.sealed.tmp"); } catch (_e) {}
  }

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
    try { loaded = JSON.parse(fs.readFileSync(paths.plaintext, "utf8")); }
    catch (e) { logErr("FATAL: audit-sign.key corrupted: " + e.message); process.exit(1); }
    if (!loaded || !loaded.publicKey || !loaded.privateKey) {
      logErr("FATAL: audit-sign.key missing required fields"); process.exit(1);
    }
    keys = { publicKey: loaded.publicKey, privateKey: loaded.privateKey, fingerprint: _computeFingerprint(loaded.publicKey) };
    return;
  }
  // First run, plaintext
  var pair = nodeCrypto.generateKeyPairSync("ml-dsa-87", {
    publicKeyEncoding:  { type: "spki",  format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  keys = { publicKey: pair.publicKey, privateKey: pair.privateKey, fingerprint: _computeFingerprint(pair.publicKey) };
  fs.writeFileSync(paths.plaintext, JSON.stringify({ publicKey: keys.publicKey, privateKey: keys.privateKey }, null, 2), { mode: 0o600 });
  log("plaintext audit-signing keypair generated at " + paths.plaintext);
}

async function _initWrapped() {
  var vaultWrap = require("./vault-wrap");
  log("unsealing audit-sign.key.sealed...");
  var sealedBytes = fs.readFileSync(paths.sealed);
  var passphrase = await _getPassphrase("Audit-signing passphrase: ");
  var plaintextBuf;
  try { plaintextBuf = await vaultWrap.unwrap(sealedBytes, passphrase); }
  catch (e) { logErr("FATAL: audit-signing passphrase rejected (" + e.message + ")"); process.exit(1); }
  var loaded;
  try { loaded = JSON.parse(plaintextBuf.toString("utf8")); }
  catch (e) { logErr("FATAL: unwrapped audit-sign.key not valid JSON"); process.exit(1); }
  if (!loaded || !loaded.publicKey || !loaded.privateKey) {
    logErr("FATAL: unwrapped audit-sign.key missing fields"); process.exit(1);
  }
  keys = { publicKey: loaded.publicKey, privateKey: loaded.privateKey, fingerprint: _computeFingerprint(loaded.publicKey) };
  log("audit-signing keypair unsealed.");
}

async function _initFirstRunWrapped() {
  var vaultWrap = require("./vault-wrap");
  log("first-run wrapped — generating audit-signing keypair...");
  var passphrase = await _getPassphrase("Choose an audit-signing passphrase: ");
  var pair = nodeCrypto.generateKeyPairSync("ml-dsa-87", {
    publicKeyEncoding:  { type: "spki",  format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  keys = { publicKey: pair.publicKey, privateKey: pair.privateKey, fingerprint: _computeFingerprint(pair.publicKey) };

  var sealed = await vaultWrap.wrap(JSON.stringify({ publicKey: keys.publicKey, privateKey: keys.privateKey }, null, 2), passphrase);
  fs.writeFileSync(paths.sealedTmp, sealed, { mode: 0o600 });
  try {
    var fd = fs.openSync(paths.sealedTmp, "r+");
    try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  } catch (_e) {}
  fs.renameSync(paths.sealedTmp, paths.sealed);
  log("generated and sealed audit-signing keypair (ML-DSA-87)");
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
  ENV_PASSPHRASE:           ENV_PASSPHRASE,
  ENV_PASSPHRASE_FILE:      ENV_PASSPHRASE_FILE,
  ENV_PASSPHRASE_SRC:       ENV_PASSPHRASE_SRC,
  _resetForTest:            _resetForTest,
};
