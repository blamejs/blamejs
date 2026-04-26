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
 *   atomicFile.readSync(filepath, opts?)           → same, sync (for boot paths)
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
var jsonSafe = require("./json-safe");
var C = require("./constants");
var bufferSafe = require("./buffer-safe");
var asyncSafe = require("./async-safe");
var { FrameworkError } = require("./framework-error");

var DEFAULTS = {
  maxBytes:        C.BYTES.mib(64),     // 64 MiB ceiling on read
  retryAttempts:   5,
  retryBaseMs:     50,
  retryMaxMs:      C.TIME.seconds(2),
  fileMode:        0o600,
  computeHash:     false,
  lockTimeoutMs:   C.TIME.seconds(30),
  lockPollMs:      50,
};

class AtomicFileError extends FrameworkError {
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
      await asyncSafe.sleep(delay, { signal: opts.signal });
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

// ---- writeSync ----
// Synchronous atomic write — same temp+fsync+rename+dirfsync flow as
// async write(), but without the retry loop (which requires awaits).
// Use this from sync code paths (process exit handlers, module-load-time
// bootstraps). For everything else, prefer the async write().
//
// Transactional guarantee: either the rename completes (new contents fully
// visible) or the tmp file is removed (no state change). The caller never
// sees a half-written file at `filepath` and never leaves a tmp orphan
// from the current call's failure path.
function writeSync(filepath, data, opts) {
  opts = Object.assign({}, DEFAULTS, opts || {});
  var buf = bufferSafe.toBuffer(data, {
    errorClass: AtomicFileError,
    typeCode:   "atomic-file/invalid-data",
    typeMessage: "data must be Buffer, Uint8Array, or string",
  });

  var dir = path.dirname(filepath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true, mode: 0o700 });

  var tmpPath = filepath + ".tmp-" + generateToken(8);
  var renamed = false;
  try {
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
    fs.renameSync(tmpPath, filepath);
    renamed = true;
    _fsyncDir(dir);
  } finally {
    if (!renamed) {
      // Either the write or the rename failed — remove the tmp so the next
      // boot doesn't see a leaked partial file.
      try { fs.unlinkSync(tmpPath); } catch (_e) { /* may not exist */ }
    }
  }

  return {
    bytesWritten: buf.length,
    hash:         opts.computeHash ? sha3Hash(buf) : null,
  };
}

// Clean up orphan tmp files left behind by a previously-crashed process.
// Atomic writes use random tmp names (filepath + ".tmp-" + token), so a
// crash leaves a file with a name we can't predict on next boot — only
// glob and prune by age. Default: prune anything older than 5 minutes.
//
// Operators should call this at boot for every "important" filepath
// (vault.key.sealed, audit-sign.key.sealed, db.enc, etc.) BEFORE they
// start their first atomic write to that path.
function cleanOrphans(filepath, opts) {
  opts = opts || {};
  var olderThanMs = opts.olderThanMs != null ? opts.olderThanMs : C.TIME.minutes(5);
  var dir = path.dirname(filepath);
  var basename = path.basename(filepath);
  var prefix = basename + ".tmp-";
  var nowMs = Date.now();
  var removed = 0;
  var entries = listDir(dir, {
    filter:      function (name) { return name.startsWith(prefix); },
    includeStat: true,
  });
  for (var i = 0; i < entries.length; i++) {
    var entry = entries[i];
    try {
      if (nowMs - entry.mtimeMs >= olderThanMs) {
        fs.unlinkSync(entry.fullPath);
        removed += 1;
      }
    } catch (_e) { /* concurrent cleanup or permission — best effort */ }
  }
  return removed;
}

// ---- write ----

async function write(filepath, data, opts) {
  opts = Object.assign({}, DEFAULTS, opts || {});
  var buf = bufferSafe.toBuffer(data, {
    errorClass: AtomicFileError,
    typeCode:   "atomic-file/invalid-data",
    typeMessage: "data must be Buffer, Uint8Array, or string",
  });

  return await _withRetry(function () {
    return new Promise(function (resolve, reject) {
      var dir = path.dirname(filepath);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
      var tmpPath = filepath + ".tmp-" + generateToken(8);
      var renamed = false;
      try {
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
        // Atomic rename — POSIX rename is atomic on the same FS; on Windows,
        // fs.renameSync uses MoveFileEx with REPLACE_EXISTING.
        fs.renameSync(tmpPath, filepath);
        renamed = true;
        _fsyncDir(dir);
        var hash = opts.computeHash ? sha3Hash(buf) : null;
        resolve({ bytesWritten: buf.length, hash: hash });
      } catch (e) {
        reject(e);
      } finally {
        if (!renamed) {
          try { fs.unlinkSync(tmpPath); } catch (_e) { /* may not exist */ }
        }
      }
    });
  }, opts);
}

// ---- read ----

async function read(filepath, opts) {
  opts = Object.assign({}, DEFAULTS, opts || {});
  return await _withRetry(function () {
    return new Promise(function (resolve, reject) {
      try { resolve(_readSyncCore(filepath, opts)); }
      catch (e) { reject(e); }
    });
  }, opts);
}

// Sync variant for callers in module-init / boot paths that can't
// `await` (vault.initPlaintext, audit-sign._initPlaintext,
// db._checkRollback, db.loadOrCreateDbKey). Same semantics as
// async read: size cap, optional integrity-hash verification, ENOENT
// translation. No retry loop — sync paths can't usefully back off.
function readSync(filepath, opts) {
  opts = Object.assign({}, DEFAULTS, opts || {});
  return _readSyncCore(filepath, opts);
}

function _readSyncCore(filepath, opts) {
  if (!fs.existsSync(filepath)) {
    var e = new AtomicFileError("file not found: " + filepath, "atomic-file/not-found");
    e.code = "ENOENT";
    throw e;
  }
  var stat = fs.statSync(filepath);
  if (stat.size > opts.maxBytes) {
    throw new AtomicFileError(
      "file size " + stat.size + " > maxBytes " + opts.maxBytes,
      "atomic-file/too-large"
    );
  }
  var buf = fs.readFileSync(filepath);
  if (opts.expectedHash) {
    var actual = sha3Hash(buf);
    if (actual !== opts.expectedHash) {
      throw new AtomicFileError(
        "integrity check failed: expected " + opts.expectedHash + " got " + actual,
        "atomic-file/integrity"
      );
    }
  }
  return opts.encoding ? buf.toString(opts.encoding) : buf;
}

// ---- writeJson / readJson ----

async function writeJson(filepath, value, opts) {
  opts = opts || {};
  var serialized = opts.canonical
    ? jsonSafe.canonical(value)
    : jsonSafe.stringify(value, { indent: opts.indent || 0 });
  return await write(filepath, serialized, opts);
}

async function readJson(filepath, opts) {
  opts = opts || {};
  var buf = await read(filepath, opts);
  var input = Buffer.isBuffer(buf) ? buf : Buffer.from(buf, "utf8");
  return jsonSafe.parse(input, opts);
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
        if (Date.now() - stat.mtimeMs > C.TIME.minutes(5)) {
          try { fs.unlinkSync(lockPath); } catch (_e) {}
          continue;
        }
      } catch (_e) { /* stat raced with another process — keep waiting */ }
      await asyncSafe.sleep(opts.lockPollMs, { signal: opts.signal });
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

// Single-directory listing primitive. Wraps fs.readdirSync with the
// optional-stat pattern + missing-dir tolerance + filter that callers
// across the framework were re-implementing.
//
//   opts:
//     filter:      function(name) => boolean   — name-only predicate
//     includeStat: bool — adds mtimeMs / sizeBytes / isDirectory /
//                  isFile per entry (one fs.statSync call each).
//                  Skip when the caller only needs names — saves a
//                  syscall per entry.
//     missingOk:   bool — default true. Returns [] when the dir
//                  doesn't exist (ENOENT). Other errors throw.
//
//   Returns: array of { name, fullPath } (plus stat fields when
//   includeStat is true). Entries that vanish between readdir and
//   stat (concurrent cleanup) are silently dropped.
//
// For recursive directory walks, callers compose listDir per
// subdirectory — the primitive doesn't recurse, so callers can apply
// per-iteration limits / filters / stop conditions cleanly.
function listDir(dir, opts) {
  opts = opts || {};
  var missingOk   = opts.missingOk !== false;
  var includeStat = opts.includeStat === true;
  var filter      = typeof opts.filter === "function" ? opts.filter : null;

  var entries;
  try {
    entries = fs.readdirSync(dir);
  } catch (e) {
    if (missingOk && e.code === "ENOENT") return [];
    throw new AtomicFileError(
      "failed to list directory " + dir + ": " + e.message,
      "atomic-file/list-failed"
    );
  }

  var out = [];
  for (var i = 0; i < entries.length; i++) {
    var name = entries[i];
    if (filter && !filter(name)) continue;
    var fullPath = path.join(dir, name);
    var entry = { name: name, fullPath: fullPath };
    if (includeStat) {
      try {
        var stat = fs.statSync(fullPath);
        entry.mtimeMs    = stat.mtimeMs;
        entry.sizeBytes  = stat.size;
        entry.isDirectory = stat.isDirectory();
        entry.isFile     = stat.isFile();
      } catch (_e) {
        // Entry vanished between readdir and stat — concurrent cleanup
        // by another process. Skip silently; caller asked for stat
        // info that no longer exists.
        continue;
      }
    }
    out.push(entry);
  }
  return out;
}

module.exports = {
  write:           write,
  writeSync:       writeSync,
  read:            read,
  readSync:        readSync,
  writeJson:       writeJson,
  readJson:        readJson,
  copy:            copy,
  exists:          exists,
  lock:            lock,
  listDir:         listDir,
  cleanOrphans:    cleanOrphans,
  AtomicFileError: AtomicFileError,
  DEFAULTS:        DEFAULTS,
};
