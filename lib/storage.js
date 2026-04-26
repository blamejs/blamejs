"use strict";
/**
 * Storage abstraction — file bytes-on-disk with per-file encryption.
 *
 * Every file gets a fresh random XChaCha20 key; the key is vault-sealed and
 * returned to the caller as `encryptionKey`. The on-disk blob is opaque
 * without that key. Apps persist the sealed key in their own DB row alongside
 * other file metadata (size, mime, owner) and pass it back on retrieval.
 *
 * Backends in v0.0.5: 'local' only.
 *   's3' is reserved for v0.0.6 (Phase 1d-2) — calling storage.init with
 *   backend: 's3' throws a clear "not yet implemented" error.
 *
 * Path discipline:
 *   - All file operations resolve relative paths under uploadDir.
 *   - Resolved paths are checked to remain within uploadDir (no traversal
 *     via .. segments or absolute paths).
 *   - saveRaw / getRawBuffer skip encryption — reserved for blobs that are
 *     ALREADY encrypted by a higher layer (vault files, audit exports).
 *     Never use for user file content.
 *
 * Public API (all sync):
 *   storage.init({ backend: 'local', uploadDir, scratchDir? })
 *   storage.saveFile(buffer, relativePath)         → { storedPath, encryptionKey }
 *   storage.getFileBuffer(storedPath, sealedKey)   → Buffer (decrypted)
 *   storage.getFileStream(storedPath, sealedKey)   → Readable
 *   storage.saveRaw(buffer, relativePath)          → { storedPath }
 *   storage.getRawBuffer(storedPath)               → Buffer
 *   storage.deleteFile(storedPath)                 → boolean
 *   storage.exists(storedPath)                     → boolean
 *   storage.getUploadDir()                         → absolute path
 */
var fs = require("fs");
var path = require("path");
var { Readable } = require("stream");
var { generateBytes, encryptPacked, decryptPacked } = require("./crypto");

// Lazy vault require — avoids ordering issues if storage is required before
// vault.init runs (init time errors are fine; saveFile errors at call time
// would not be).
var _vault = null;
function vault() { if (!_vault) _vault = require("./vault"); return _vault; }

var initialized = false;
var backend = null;       // 'local' (S3 in v0.0.6+)
var uploadDir = null;     // resolved absolute path
var scratchDir = null;    // resolved absolute path; transient files
var SAFE_COMPONENT = /^[A-Za-z0-9_\-./]+$/;

function init(opts) {
  if (initialized) return;
  if (!opts) throw new Error("storage.init() requires options");

  backend = (opts.backend || "local").toLowerCase();
  if (backend === "s3") {
    throw new Error(
      "storage backend 's3' is not yet implemented (deferred to v0.0.6 / Phase 1d-2). " +
      "Use backend: 'local' for now."
    );
  }
  if (backend !== "local") {
    throw new Error("storage.init: unknown backend '" + opts.backend + "' (expected 'local')");
  }

  if (!opts.uploadDir) throw new Error("storage.init({ uploadDir }) is required for local backend");
  uploadDir = path.resolve(opts.uploadDir);
  if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

  scratchDir = opts.scratchDir
    ? path.resolve(opts.scratchDir)
    : path.join(uploadDir, ".scratch");
  if (!fs.existsSync(scratchDir)) fs.mkdirSync(scratchDir, { recursive: true });

  initialized = true;
}

// ---- Path safety ----

function _resolveSafe(relativePath) {
  if (typeof relativePath !== "string" || relativePath.length === 0) {
    throw new Error("storage path must be a non-empty string");
  }
  if (relativePath.includes("\0")) {
    throw new Error("storage path contains null byte");
  }
  if (path.isAbsolute(relativePath)) {
    throw new Error("storage path must be relative to uploadDir, got absolute: " + relativePath);
  }
  if (!SAFE_COMPONENT.test(relativePath)) {
    throw new Error("storage path contains invalid characters: " + relativePath);
  }
  var full = path.resolve(uploadDir, relativePath);
  // Boundary check — resolve normalizes '..' and the prefix must still be uploadDir
  var withSep = uploadDir.endsWith(path.sep) ? uploadDir : uploadDir + path.sep;
  if (full !== uploadDir && !full.startsWith(withSep)) {
    throw new Error("storage path escapes uploadDir: " + relativePath);
  }
  return full;
}

// ---- File encryption ----

function _encryptBuffer(buffer) {
  var key = generateBytes(32);
  var packed = encryptPacked(buffer, key);
  var sealedKey = vault().seal(key.toString("base64"));
  return { data: packed, encryptionKey: sealedKey };
}

function _decryptBuffer(packed, sealedKey) {
  if (!sealedKey) {
    throw new Error("getFileBuffer: encryptionKey is required (no legacy plaintext support)");
  }
  var key = Buffer.from(vault().unseal(sealedKey), "base64");
  return decryptPacked(packed, key);
}

// ---- Public API ----

function saveFile(buffer, relativePath) {
  _requireInit();
  if (!Buffer.isBuffer(buffer)) {
    throw new Error("saveFile: first arg must be a Buffer");
  }
  var enc = _encryptBuffer(buffer);
  var fullPath = _resolveSafe(relativePath);
  var dir = path.dirname(fullPath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(fullPath, enc.data);
  return { storedPath: relativePath, encryptionKey: enc.encryptionKey };
}

function getFileBuffer(relativePath, sealedKey) {
  _requireInit();
  var fullPath = _resolveSafe(relativePath);
  if (!fs.existsSync(fullPath)) {
    throw new Error("storage: file not found: " + relativePath);
  }
  var packed = fs.readFileSync(fullPath);
  return _decryptBuffer(packed, sealedKey);
}

function getFileStream(relativePath, sealedKey) {
  // For v0.0.5, decryption is whole-file (loaded into memory then wrapped
  // as a Readable). Chunked-stream decryption lands later — large file
  // optimisation isn't blocking the framework's compliance bar.
  var buffer = getFileBuffer(relativePath, sealedKey);
  return Readable.from(buffer);
}

function saveRaw(buffer, relativePath) {
  _requireInit();
  if (!Buffer.isBuffer(buffer)) {
    throw new Error("saveRaw: first arg must be a Buffer");
  }
  var fullPath = _resolveSafe(relativePath);
  var dir = path.dirname(fullPath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(fullPath, buffer);
  return { storedPath: relativePath };
}

function getRawBuffer(relativePath) {
  _requireInit();
  var fullPath = _resolveSafe(relativePath);
  if (!fs.existsSync(fullPath)) {
    throw new Error("storage: file not found: " + relativePath);
  }
  return fs.readFileSync(fullPath);
}

function deleteFile(relativePath) {
  _requireInit();
  var fullPath = _resolveSafe(relativePath);
  if (!fs.existsSync(fullPath)) return false;
  fs.unlinkSync(fullPath);
  return true;
}

function exists(relativePath) {
  _requireInit();
  return fs.existsSync(_resolveSafe(relativePath));
}

function getUploadDir() { return uploadDir; }
function getScratchDir() { return scratchDir; }
function getBackend()  { return backend; }

function _requireInit() {
  if (!initialized) throw new Error("storage.init() must be called before any file operation");
}

function _resetForTest() {
  initialized = false;
  backend = null;
  uploadDir = null;
  scratchDir = null;
  _vault = null;
}

module.exports = {
  init:            init,
  saveFile:        saveFile,
  getFileBuffer:   getFileBuffer,
  getFileStream:   getFileStream,
  saveRaw:         saveRaw,
  getRawBuffer:    getRawBuffer,
  deleteFile:      deleteFile,
  exists:          exists,
  getUploadDir:    getUploadDir,
  getScratchDir:   getScratchDir,
  getBackend:      getBackend,
  _resetForTest:   _resetForTest,
};
