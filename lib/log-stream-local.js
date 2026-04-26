"use strict";
/**
 * Local file-based log sink with append-only journaling + rotation.
 *
 * Each event is written as one JSON line (jsonl format — one row per
 * event). Files rotate by size (default 100 MiB) and/or age (default
 * 7 days). Old rotations are gzip-compressed automatically and capped at
 * a configured count (default 30) — older rotations are deleted.
 *
 * The active log file is opened in append mode and never updated in place.
 * Operators can apply OS-level immutability (Linux chattr +a) to the
 * directory if they want stronger tamper-resistance — the framework
 * doesn't fight that; appends still work.
 *
 * Config:
 *   {
 *     dir:                './logs/operational'
 *     maxFileBytes:       100 * 1024 * 1024
 *     maxFileAgeMs:       7 * 24 * 60 * 60 * 1000
 *     keepRotations:      30
 *     compressRotations:  true
 *     fileMode:           0o600
 *     fileNamePrefix:     'blamejs'
 *   }
 */
var fs = require("fs");
var path = require("path");
var zlib = require("zlib");

var DEFAULTS = {
  maxFileBytes:      100 * 1024 * 1024,
  maxFileAgeMs:      7 * 24 * 60 * 60 * 1000,
  keepRotations:     30,
  compressRotations: true,
  fileMode:          0o600,
  fileNamePrefix:    "blamejs",
};

function _err(code, message, permanent) {
  var e = new Error(message);
  e.code = code;
  e.permanent = !!permanent;
  e.isLogStreamError = true;
  return e;
}

function create(config) {
  if (!config || !config.dir) throw new Error("log-stream local requires { dir }");
  var cfg = Object.assign({}, DEFAULTS, config);
  var dir = path.resolve(cfg.dir);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true, mode: 0o700 });

  var activePath = path.join(dir, cfg.fileNamePrefix + ".log");
  var fd = null;
  var openedAt = 0;
  var bytesWritten = 0;

  function _open() {
    fd = fs.openSync(activePath, "a", cfg.fileMode);
    openedAt = Date.now();
    try {
      var stat = fs.fstatSync(fd);
      bytesWritten = stat.size;
    } catch (_e) {
      bytesWritten = 0;
    }
  }
  _open();

  function _shouldRotate() {
    if (cfg.maxFileBytes && bytesWritten >= cfg.maxFileBytes) return true;
    if (cfg.maxFileAgeMs && (Date.now() - openedAt) >= cfg.maxFileAgeMs) return true;
    return false;
  }

  function _rotate() {
    try {
      if (fd != null) { try { fs.closeSync(fd); } catch (_e) {} fd = null; }
      // Build rotated filename: blamejs-YYYYMMDDTHHMMSSZ.log
      var stamp = new Date().toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z");
      var rotated = path.join(dir, cfg.fileNamePrefix + "-" + stamp + ".log");
      if (fs.existsSync(activePath)) {
        fs.renameSync(activePath, rotated);
        if (cfg.compressRotations) {
          var data = fs.readFileSync(rotated);
          var gz = zlib.gzipSync(data);
          fs.writeFileSync(rotated + ".gz", gz, { mode: cfg.fileMode });
          fs.unlinkSync(rotated);
        }
      }
      _pruneOld();
    } finally {
      _open();
    }
  }

  function _pruneOld() {
    if (!cfg.keepRotations || cfg.keepRotations <= 0) return;
    var entries = fs.readdirSync(dir)
      .filter(function (f) {
        return f.startsWith(cfg.fileNamePrefix + "-") &&
          (f.endsWith(".log") || f.endsWith(".log.gz"));
      })
      .map(function (f) {
        var full = path.join(dir, f);
        var stat;
        try { stat = fs.statSync(full); } catch (_e) { return null; }
        return { name: f, full: full, mtime: stat.mtimeMs };
      })
      .filter(Boolean)
      .sort(function (a, b) { return b.mtime - a.mtime; });   // newest first
    for (var i = cfg.keepRotations; i < entries.length; i++) {
      try { fs.unlinkSync(entries[i].full); } catch (_e) { /* best effort */ }
    }
  }

  function emit(record) {
    if (_shouldRotate()) _rotate();
    var line = JSON.stringify(record) + "\n";
    var buf = Buffer.from(line, "utf8");
    fs.writeSync(fd, buf, 0, buf.length, null);
    bytesWritten += buf.length;
    return Promise.resolve({ bytes: buf.length });
  }

  function close() {
    if (fd != null) {
      try { fs.fsyncSync(fd); } catch (_e) { /* best effort */ }
      try { fs.closeSync(fd); } catch (_e) {}
      fd = null;
    }
    return Promise.resolve();
  }

  function getActivePath() { return activePath; }

  return {
    protocol:      "local",
    emit:          emit,
    close:         close,
    rotate:        function () { _rotate(); return Promise.resolve(); },
    getActivePath: getActivePath,
  };
}

module.exports = { create: create };
