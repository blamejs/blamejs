"use strict";
/**
 * Atomic file I/O with integrity verification, retry on transient errors,
 * and cross-process locking.
 *
 * The framework already does atomic writes for vault.key.sealed (lib/vault.js)
 * and audit.tip (lib/db.js). This module exposes the same primitives for
 * any caller that needs:
 *
 *   - Crash-safe writes via temp + fsync + atomic rename + dir fsync
 *   - Optional integrity hash (SHA3-512) computed on write, verified on read
 *   - Retry on EBUSY / EAGAIN / ENFILE with exponential backoff
 *   - Cross-process locking for read-modify-write sequences
 *   - JSON convenience wrappers using b.json's security defaults
 *
 * The framework's "fail closed" stance applies: a partially-written file
 * NEVER survives a crash to the caller — either the new contents are
 * fully on disk (atomic rename succeeded) or the original (or absence)
 * remains. fsync calls are best-effort across platforms (Windows rejects
 * directory fsync, etc.); the rename remains atomic at the FS level
 * regardless.
 *
 * Public API:
 *   atomicFile.write(filepath, data, opts?)        → { bytesWritten, hash? }
 *   atomicFile.read(filepath, opts?)               → Buffer (or string if encoding)
 *   atomicFile.writeJson(filepath, value, opts?)   → { bytesWritten, hash? }
 *   atomicFile.readJson(filepath, opts?)           → parsed value
 *   atomicFile.copy(src, dst, opts?)               → { bytesWritten, hash? }
 *   atomicFile.exists(filepath)                    → boolean
 *   atomicFile.lock(filepath, fn, opts?)           → fn's return value
 *   atomicFile.AtomicFileError                     → error class
 */
var fs = require("fs");
var path = require("path");
var nodeCrypto = require("crypto");
var { generateToken, sha3Hash } = require("./crypto");

var DEFAULTS = {
  maxBytes:        64 * 1024 * 1024,    // 64 MiB ceiling on read
  retryAttempts:   5,
  retryBaseMs:     50,
  retryMaxMs:      2000,
  fileMode:        0o600,
  computeHash:     false,
  lockTimeoutMs:   30000,
  lockPollMs:      50,
};

class AtomicFileError extends Error {
  constructor(message, code) {
    super(message);
    this.name = "AtomicFileError";
    this.code = code || "atomic-file/error";
    this.isAtomicFileError = true;
  }
}

// ---- Retry helper for transient FS errors ----

var TRANSIENT_FS_ERRNOS = new Set(["EBUSY", "EAGAIN", "ENFILE", "EMFILE", "EPERM"]);

async function _withRetry(fn, opts) {
  opts = Object.assign({}, DEFAULTS, opts || {});
  var lastErr;
  for (var attempt = 1; attempt <= opts.retryAttempts; attempt++) {
    try {
      return await fn();
    } catch (e) {
      lastErr = e;
      if (!TRANSIENT_FS_ERRNOS.has(e.code) || attempt === opts.retryAttempts) {
        throw e;
      }
      var delay = Math.min(opts.retryMaxMs, opts.retryBaseMs * Math.pow(2, attempt - 1));
      delay = Math.floor(delay * (0.5 + Math.random() / 2));   // jitter
      await new Promise(function (r) { setTimeout(r, delay); });
    }
  }
  throw lastErr;
}

// ---- Sync helpers (best effort) ----

function _fsync(fd) {
  try { fs.fsyncSync(fd); } catch (_e) { /* not all platforms support fsync on every fd type */ }
}

function _fsyncDir(dirPath) {
  try {
    var fd = fs.openSync(dirPath, "r");
    try { fs.fsyncSync(fd); } catch (_e) { /* Windows rejects */ }
    finally { fs.closeSync(fd); }
  } catch (_e) { /* dir fsync best effort */ }
}

// ---- write ----

async function write(filepath, data, opts) {
  opts = Object.assign({}, DEFAULTS, opts || {});
  var buf;
  if (Buffer.isBuffer(data))             buf = data;
  else if (typeof data === "string")     buf = Buffer.from(data, "utf8");
  else if (data instanceof Uint8Array)   buf = Buffer.from(data);
  else throw new AtomicFileError("data must be Buffer, Uint8Array, or string", "atomic-file/invalid-data");

  return await _withRetry(function () {
    return new Promise(function (resolve, reject) {
      try {
        var dir = path.dirname(filepath);
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true, mode: 0o700 });

        var tmpPath = filepath + ".tmp-" + generateToken(8);
        var fd = fs.openSync(tmpPath, "w", opts.fileMode);
        try {
          var pos = 0;
          while (pos < buf.length) {
            pos += fs.writeSync(fd, buf, pos, buf.length - pos, null);
          }
          _fsync(fd);
        } finally {
          try { fs.closeSync(fd); } catch (_e) { /* already closed? */ }
        }

        // Atomic rename — the OS guarantees this is either fully visible
        // or not at all. POSIX rename is atomic for files on the same FS;
        // on Windows, fs.renameSync uses MoveFileEx with REPLACE_EXISTING.
        fs.renameSync(tmpPath, filepath);
        _fsyncDir(dir);

        var hash = opts.computeHash ? sha3Hash(buf) : null;
        resolve({ bytesWritten: buf.length, hash: hash });
      } catch (e) { reject(e); }
    });
  }, opts);
}

// ---- read ----

async function read(filepath, opts) {
  opts = Object.assign({}, DEFAULTS, opts || {});
  return await _withRetry(function () {
    return new Promise(function (resolve, reject) {
      try {
        if (!fs.existsSync(filepath)) {
          var e = new AtomicFileError("file not found: " + filepath, "atomic-file/not-found");
          e.code = "ENOENT";
          return reject(e);
        }
        var stat = fs.statSync(filepath);
        if (stat.size > opts.maxBytes) {
          return reject(new AtomicFileError(
            "file size " + stat.size + " > maxBytes " + opts.maxBytes,
            "atomic-file/too-large"
          ));
        }
        var buf = fs.readFileSync(filepath);
        if (opts.expectedHash) {
          var actual = sha3Hash(buf);
          if (actual !== opts.expectedHash) {
            return reject(new AtomicFileError(
              "integrity check failed: expected " + opts.expectedHash + " got " + actual,
              "atomic-file/integrity"
            ));
          }
        }
        if (opts.encoding) resolve(buf.toString(opts.encoding));
        else resolve(buf);
      } catch (e) { reject(e); }
    });
  }, opts);
}

// ---- writeJson / readJson ----

async function writeJson(filepath, value, opts) {
  opts = opts || {};
  var json = require("./json-safe");
  var serialized = opts.canonical
    ? json.canonical(value)
    : json.stringify(value, { indent: opts.indent || 0 });
  return await write(filepath, serialized, opts);
}

async function readJson(filepath, opts) {
  opts = opts || {};
  var json = require("./json-safe");
  var buf = await read(filepath, opts);
  var input = Buffer.isBuffer(buf) ? buf : Buffer.from(buf, "utf8");
  return json.parse(input, opts);
}

// ---- copy ----

async function copy(src, dst, opts) {
  opts = Object.assign({}, DEFAULTS, opts || {});
  var srcOpts = Object.assign({}, opts);
  delete srcOpts.expectedHash;     // hash check applies to dst, not src
  var buf = await read(src, srcOpts);
  if (!Buffer.isBuffer(buf)) buf = Buffer.from(buf, "utf8");
  return await write(dst, buf, opts);
}

// ---- exists ----

function exists(filepath) {
  return fs.existsSync(filepath);
}

// ---- lock (cross-process file mutex) ----

async function lock(filepath, fn, opts) {
  opts = Object.assign({}, DEFAULTS, opts || {});
  var lockPath = filepath + ".lock";
  var deadline = Date.now() + opts.lockTimeoutMs;
  var fd = null;

  while (Date.now() < deadline) {
    try {
      // O_CREAT | O_EXCL — fails if file exists
      fd = fs.openSync(lockPath, "wx", opts.fileMode);
      break;
    } catch (e) {
      if (e.code !== "EEXIST") throw e;
      // Stale lock detection: if the .lock file is older than 5 minutes,
      // assume the holding process crashed and remove it.
      try {
        var stat = fs.statSync(lockPath);
        if (Date.now() - stat.mtimeMs > 5 * 60 * 1000) {
          try { fs.unlinkSync(lockPath); } catch (_e) {}
          continue;
        }
      } catch (_e) { /* stat raced with another process — keep waiting */ }
      await new Promise(function (r) { setTimeout(r, opts.lockPollMs); });
    }
  }
  if (fd === null) {
    throw new AtomicFileError(
      "lock timeout after " + opts.lockTimeoutMs + "ms on " + filepath,
      "atomic-file/lock-timeout"
    );
  }
  try {
    fs.writeSync(fd, Buffer.from(JSON.stringify({
      pid:        process.pid,
      acquiredAt: Date.now(),
    }), "utf8"));
    _fsync(fd);
  } catch (_e) { /* lock content best-effort */ }

  try {
    return await fn();
  } finally {
    try { fs.closeSync(fd); } catch (_e) {}
    try { fs.unlinkSync(lockPath); } catch (_e) {}
  }
}

module.exports = {
  write:           write,
  read:            read,
  writeJson:       writeJson,
  readJson:        readJson,
  copy:            copy,
  exists:          exists,
  lock:            lock,
  AtomicFileError: AtomicFileError,
  DEFAULTS:        DEFAULTS,
};
