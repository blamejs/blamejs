"use strict";
/**
 * bundler — content-hashed asset pipeline + manifest.
 *
 * What this primitive does today:
 *   - Reads each named entry from disk
 *   - Computes a content hash (SHA3-512, first 16 hex chars)
 *   - Writes the entry to outdir/<name>.<hash>.<ext> for cache-busting
 *   - Emits manifest.json mapping logical name → hashed filename
 *   - Optionally watches entries and rebuilds on change
 *
 * What it does NOT do today (deliberately deferred):
 *   - Module-graph resolution (esbuild-style multi-file bundling)
 *   - Tree shaking, dead-code elimination, AST transforms
 *   - Source maps
 *   - Minification (a regex-based pass mishandles comments inside
 *     string and regex literals; AST-based minification waits for the
 *     esbuild-wasm vendoring slice)
 *
 * Operators with multi-file ESM source either pre-concat manually and
 * point bundler at the result, or use an external tool today; the
 * bundler primitive's interface stays stable when full bundling lands.
 *
 *   var bundler = b.bundler.create({
 *     entries:   { app: "./public/js/app.js", styles: "./public/css/app.css" },
 *     outdir:    "./public/dist",
 *     manifest:  "manifest.json",   // false to skip; default "manifest.json"
 *     hashLen:   16,                // hex chars in filename hash (default 16)
 *     hash:      true,              // include hash in filename; false → name.ext
 *     cwd:       process.cwd(),
 *   });
 *
 *   var result = await bundler.build();
 *   //  { outputs: [{ name, entry, path, hash, bytes, ext }], manifestPath, durationMs }
 *
 *   bundler.watch(function (rebuild) { ... });    // rebuild on entry change
 *   await bundler.close();                        // stop watchers
 *
 * Manifest format (manifest.json under outdir):
 *   { "app": "app.4a8c2f1d9e3b7062.js", "styles": "styles.b29f1e7c.css" }
 *
 * Integrates with lib/static.js: serve `outdir` as a static directory;
 * lib/static.js's hashed-path detection sets long-cache headers on
 * files that look hashed, and integrity() reads the manifest to
 * generate Subresource Integrity attributes.
 */

var path = require("path");
var fs = require("fs");
var crypto = require("./crypto");
var atomicFile = require("./atomic-file");
var { defineClass } = require("./framework-error");
var safeJson = require("./safe-json");

var BundlerError = defineClass("BundlerError", { alwaysPermanent: true });

function _hashContent(buf, hexLen) {
  // SHA3-512 → take the first hexLen hex chars. Same family as the
  // framework's other content fingerprints (no SHA-256 for new code).
  return crypto.sha3Hash(buf).slice(0, hexLen);
}

function _hashedName(baseName, hash, ext) {
  return baseName + "." + hash + ext;
}

// outDir mode is 0o755 (world-readable) because the bundler emits
// assets a public HTTP server reads. Other framework dirs default to
// 0o700 via atomicFile.ensureDir.
function _ensureOutDir(p) {
  try { atomicFile.ensureDir(p, 0o755); }
  catch (e) {
    if (e && e.code !== "EEXIST") {
      throw new BundlerError("bundler/mkdir-failed",
        "could not create outdir '" + p + "': " + ((e && e.message) || String(e)));
    }
  }
}

function _validateEntries(entries) {
  if (!entries || typeof entries !== "object" || Array.isArray(entries)) {
    throw new BundlerError("bundler/no-entries",
      "bundler.create requires opts.entries (a { name: path } map)");
  }
  var names = Object.keys(entries);
  if (names.length === 0) {
    throw new BundlerError("bundler/no-entries",
      "bundler.create: opts.entries map must have at least one entry");
  }
  // Reject names with path separators or '..' so operator-supplied
  // logical names can't escape the outdir on write.
  for (var i = 0; i < names.length; i++) {
    var n = names[i];
    if (typeof n !== "string" || n.length === 0 ||
        /[\\/]/.test(n) || n === ".." || n === ".") {
      throw new BundlerError("bundler/bad-entry-name",
        "entry name '" + n + "' must be a non-empty string without path separators");
    }
    var p = entries[n];
    if (typeof p !== "string" || p.length === 0) {
      throw new BundlerError("bundler/bad-entry-path",
        "entry '" + n + "' must map to a non-empty source path");
    }
  }
}

function create(opts) {
  opts = opts || {};
  _validateEntries(opts.entries);
  if (typeof opts.outdir !== "string" || opts.outdir.length === 0) {
    throw new BundlerError("bundler/no-outdir",
      "bundler.create requires opts.outdir");
  }

  var entries     = Object.assign({}, opts.entries);
  var cwd         = opts.cwd || process.cwd();
  var outdir      = path.isAbsolute(opts.outdir) ? opts.outdir : path.resolve(cwd, opts.outdir);
  var manifestName = (opts.manifest === false || opts.manifest === null)
    ? null
    : (typeof opts.manifest === "string" && opts.manifest.length > 0
        ? opts.manifest
        : "manifest.json");
  var hashOn   = opts.hash !== false;
  var hashLen  = typeof opts.hashLen === "number" && opts.hashLen >= 4 && opts.hashLen <= 64
    ? Math.floor(opts.hashLen) : 16;
  var log      = opts.log || null;

  // Test seam: tests pass a fake watcher so we don't actually fs.watch
  var watchFn = opts._watch || function (dirOrFile, wopts, listener) {
    return fs.watch(dirOrFile, wopts, listener);
  };
  var setTimeoutFn  = opts._setTimeout  || setTimeout;
  var clearTimeoutFn = opts._clearTimeout || clearTimeout;
  var graceMs = typeof opts.graceMs === "number" && opts.graceMs >= 0 ? opts.graceMs : 100;

  var watchers      = [];
  var debounceTimer = null;
  var watching      = false;

  function _resolveEntry(p) {
    return path.isAbsolute(p) ? p : path.resolve(cwd, p);
  }

  function _logVia(level, message, fields) {
    if (log && typeof log[level] === "function") {
      try { log[level](message, fields); } catch (_e) { /* logger best-effort */ }
      return;
    }
    var line = "[blamejs:bundler] " + message + (fields ? " " + JSON.stringify(fields) : "");
    if (level === "error" || level === "warn" || level === "fatal") console.error(line);
    else console.log(line);
  }

  async function build() {
    var t0 = Date.now();
    _ensureOutDir(outdir);

    var outputs = [];
    var manifest = {};
    var names = Object.keys(entries);

    for (var i = 0; i < names.length; i++) {
      var name = names[i];
      var entryPath = _resolveEntry(entries[name]);
      var ext = path.extname(entryPath);
      var content;
      try { content = fs.readFileSync(entryPath); }
      catch (e) {
        throw new BundlerError("bundler/read-failed",
          "could not read entry '" + name + "' at " + entryPath +
          ": " + ((e && e.message) || String(e)));
      }
      var hash = hashOn ? _hashContent(content, hashLen) : null;
      var outName = hashOn ? _hashedName(name, hash, ext) : (name + ext);
      var outPath = path.join(outdir, outName);
      // atomic-file write so a concurrent reader (the http server
      // serving outdir) never sees a partial file
      atomicFile.writeSync(outPath, content, { mode: 0o644 });
      outputs.push({
        name:  name,
        entry: entryPath,
        path:  outPath,
        hash:  hash,
        bytes: content.length,
        ext:   ext,
      });
      manifest[name] = outName;
    }

    var manifestPath = null;
    if (manifestName) {
      manifestPath = path.join(outdir, manifestName);
      atomicFile.writeSync(
        manifestPath,
        safeJson.stringify(manifest, null, 2) + "\n",
        { mode: 0o644 }
      );
    }

    var result = {
      outputs:      outputs,
      manifestPath: manifestPath,
      manifest:     manifest,
      durationMs:   Date.now() - t0,
    };
    _logVia("info", "build complete",
      { entries: outputs.length, durationMs: result.durationMs });
    return result;
  }

  function _scheduleRebuild(reason, callback) {
    if (debounceTimer) {
      try { clearTimeoutFn(debounceTimer); } catch (_e) {}
    }
    debounceTimer = setTimeoutFn(function () {
      debounceTimer = null;
      _logVia("info", "rebuilding", { reason: reason });
      build().then(
        function (r) { if (callback) try { callback(null, r); } catch (_e) {} },
        function (e) {
          _logVia("error", "rebuild failed", { error: (e && e.message) || String(e) });
          if (callback) try { callback(e, null); } catch (_e) {}
        }
      );
    }, graceMs);
    if (debounceTimer && typeof debounceTimer.unref === "function") debounceTimer.unref();
  }

  function watch(callback) {
    if (watching) return;
    watching = true;
    var names = Object.keys(entries);
    for (var i = 0; i < names.length; i++) {
      (function (name) {
        var entryPath = _resolveEntry(entries[name]);
        // Watch the entry's directory (single-file watches are flaky
        // across editors that write-then-rename). Filter events to the
        // entry's basename only.
        var dir = path.dirname(entryPath);
        var base = path.basename(entryPath);
        var w;
        try {
          w = watchFn(dir, { persistent: false }, function (eventType, filename) {
            if (filename && String(filename) === base) {
              _scheduleRebuild(name, callback);
            }
          });
        } catch (e) {
          _logVia("warn", "could not watch " + dir,
            { error: (e && e.message) || String(e) });
          return;
        }
        if (w && typeof w.on === "function") {
          w.on("error", function (err) {
            _logVia("warn", "watcher error",
              { dir: dir, error: (err && err.message) || String(err) });
          });
        }
        watchers.push(w);
      })(names[i]);
    }
  }

  async function close() {
    watching = false;
    if (debounceTimer) {
      try { clearTimeoutFn(debounceTimer); } catch (_e) {}
      debounceTimer = null;
    }
    for (var i = 0; i < watchers.length; i++) {
      try { if (watchers[i] && typeof watchers[i].close === "function") watchers[i].close(); }
      catch (_e) { /* close best-effort */ }
    }
    watchers = [];
  }

  return {
    build:    build,
    watch:    watch,
    close:    close,
    entries:  entries,
    outdir:   outdir,
  };
}

module.exports = {
  create:        create,
  BundlerError:  BundlerError,
};
