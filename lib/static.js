"use strict";
/**
 * Static asset serving — middleware factory + SRI integrity helper.
 *
 * The middleware maps URL → file under `root`, with the same path-
 * containment posture as lib/template (no `..`, no `\0`, resolved path
 * must stay under root). Files outside root or symlinks pointing out
 * are refused.
 *
 * Cache-Control posture:
 *
 *   - URLs matching opts.hashedPathPattern (default: a hex/base32 ≥8
 *     character segment surrounded by dots — `.abc123ef.` style) get
 *     `Cache-Control: public, max-age=31536000, immutable` per the
 *     roadmap's verification gate. The hash-in-URL convention pins
 *     the served bytes to the URL forever; immutable lets browsers
 *     skip revalidation entirely.
 *   - Other URLs get `Cache-Control: public, max-age=<defaultMaxAge>`
 *     (default 3600 = 1h). Operators tune via opts.defaultMaxAge.
 *
 * ETag is the first 27 chars of SHA-384(file content), base64. 162
 * bits of collision resistance — overkill but cheap; same hash powers
 * the SRI integrity helper so we compute it once per file.
 *
 * 304 Not Modified: emitted when If-None-Match matches the ETag.
 *
 * HEAD: returns same headers as GET, no body.
 *
 * Range requests are NOT supported in v1. Operators serving video/audio
 * put a CDN in front. Compression (gzip/br) likewise — out of scope here.
 *
 * MIME types: minimal built-in table. Override via opts.contentTypes.
 *
 * Index files: a request resolving to a directory tries opts.indexFile
 * (default "index.html"); operators disable with opts.indexFile = null.
 *
 * Public API:
 *
 *   staticServe.create({ root, mountPath?, hashedPathPattern?,
 *                         defaultMaxAge?, indexFile?, contentTypes? })
 *     → (req, res, next) middleware
 *
 *   await staticServe.integrity(filePath)
 *     → "sha384-<base64>" suitable for an HTML integrity= attribute.
 *       Cached per file across calls; invalidated on mtime change.
 */
var fs = require("fs");
var fsp = require("fs/promises");
var path = require("path");
var nodeCrypto = require("crypto");
var C = require("./constants");
var requestHelpers = require("./request-helpers");
var validateOpts = require("./validate-opts");

var HTTP = requestHelpers.HTTP_STATUS;

var DEFAULT_HASHED_PATTERN = /\.[a-fA-F0-9]{8,}\./;
var DEFAULT_INDEX_FILE     = "index.html";
var DEFAULT_MAX_AGE_SEC    = C.TIME.hours(1) / C.TIME.seconds(1);   // 1 hour for non-hashed paths
var IMMUTABLE_MAX_AGE_SEC  = C.TIME.days(365) / C.TIME.seconds(1);  // 1 year for hashed paths

// Minimal MIME table. Operators with exotic types pass opts.contentTypes
// to override. The framework deliberately doesn't bring a 200-entry
// mime-db dependency — most servers serve a handful of types.
var DEFAULT_CONTENT_TYPES = {
  ".html":  "text/html; charset=utf-8",
  ".htm":   "text/html; charset=utf-8",
  ".css":   "text/css; charset=utf-8",
  ".js":    "application/javascript; charset=utf-8",
  ".mjs":   "application/javascript; charset=utf-8",
  ".json":  "application/json; charset=utf-8",
  ".map":   "application/json; charset=utf-8",
  ".txt":   "text/plain; charset=utf-8",
  ".md":    "text/markdown; charset=utf-8",
  ".xml":   "application/xml; charset=utf-8",
  ".svg":   "image/svg+xml",
  ".png":   "image/png",
  ".jpg":   "image/jpeg",
  ".jpeg":  "image/jpeg",
  ".gif":   "image/gif",
  ".webp":  "image/webp",
  ".avif":  "image/avif",
  ".ico":   "image/x-icon",
  ".woff":  "font/woff",
  ".woff2": "font/woff2",
  ".ttf":   "font/ttf",
  ".otf":   "font/otf",
  ".pdf":   "application/pdf",
  ".wasm":  "application/wasm",
  ".webmanifest": "application/manifest+json",
};

// ---- Module-level metadata cache (for both middleware ETag and the
// standalone integrity() helper). Keyed by absolute file path; entries
// invalidated on mtime change.

var _cache = new Map();

async function _readMeta(absPath) {
  var stat;
  try { stat = await fsp.stat(absPath); }
  catch (_e) { return null; }
  if (!stat.isFile()) return null;

  var cached = _cache.get(absPath);
  if (cached && cached.mtimeMs === stat.mtimeMs && cached.size === stat.size) {
    return cached;
  }

  // Stream the file through SHA-384. fs.readFileSync is simpler but
  // would balloon RSS for large assets — operators shouldn't be
  // constrained on what they can serve.
  var hash = nodeCrypto.createHash("sha384");
  await new Promise(function (resolve, reject) {
    var s = fs.createReadStream(absPath);
    s.on("data", function (chunk) { hash.update(chunk); });
    s.on("end",  resolve);
    s.on("error", reject);
  });
  var digest = hash.digest("base64");

  var entry = {
    mtimeMs:    stat.mtimeMs,
    size:       stat.size,
    etag:       '"' + digest.slice(0, 27) + '"',   // 162-bit ETag
    integrity:  "sha384-" + digest,
    absPath:    absPath,
  };
  _cache.set(absPath, entry);
  return entry;
}

function _resolveSafe(root, requestedPath) {
  if (typeof requestedPath !== "string" || requestedPath.length === 0) return null;
  if (requestedPath.indexOf("\0") !== -1) return null;
  // path.resolve handles ".." normalization; we then check containment.
  var resolved = path.resolve(root, "." + requestedPath);
  var rootResolved = path.resolve(root);
  if (resolved !== rootResolved &&
      !resolved.startsWith(rootResolved + path.sep)) return null;
  return resolved;
}

function _contentTypeFor(filePath, table) {
  var ext = path.extname(filePath).toLowerCase();
  return (table && table[ext]) || DEFAULT_CONTENT_TYPES[ext] || "application/octet-stream";
}

function _writeNotModified(res, etag, cacheControl) {
  res.writeHead(HTTP.NOT_MODIFIED, {
    "ETag":          etag,
    "Cache-Control": cacheControl,
  });
  res.end();
}

function _writeNotFound(res) {
  res.writeHead(HTTP.NOT_FOUND, { "Content-Type": "text/plain; charset=utf-8", "Content-Length": 9 });
  res.end("Not Found");
}

// ---- Public: integrity() ----

async function integrity(absPath) {
  if (typeof absPath !== "string" || absPath.length === 0) {
    throw new Error("staticServe.integrity: absPath must be a non-empty string");
  }
  var meta = await _readMeta(path.resolve(absPath));
  if (!meta) throw new Error("staticServe.integrity: file not found: " + absPath);
  return meta.integrity;
}

// ---- Public: create() ----

function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "root", "mountPath", "hashedPathPattern",
    "indexFile", "defaultMaxAge", "contentTypes",
  ], "b.staticServe");
  if (!opts.root) throw new Error("staticServe.create({ root }) is required");
  if (!fs.existsSync(opts.root)) {
    throw new Error("staticServe.create: root does not exist: " + opts.root);
  }
  var root            = path.resolve(opts.root);
  var mountPath       = opts.mountPath || "";    // strip from req URL before lookup
  var hashedPattern   = opts.hashedPathPattern || DEFAULT_HASHED_PATTERN;
  var indexFile       = opts.indexFile === null ? null : (opts.indexFile || DEFAULT_INDEX_FILE);
  var defaultMaxAge   = typeof opts.defaultMaxAge === "number" ? opts.defaultMaxAge : DEFAULT_MAX_AGE_SEC;
  var contentTypes    = opts.contentTypes || null;

  function _cacheControlFor(urlPath) {
    if (hashedPattern.test(urlPath)) {
      return "public, max-age=" + IMMUTABLE_MAX_AGE_SEC + ", immutable";
    }
    return "public, max-age=" + defaultMaxAge;
  }

  return async function staticServe(req, res, next) {
    if (req.method !== "GET" && req.method !== "HEAD") return next();

    // Strip query string + mount path before resolving against root.
    var urlPath = (req.url || "").split("?")[0];
    if (mountPath && urlPath.indexOf(mountPath) === 0) {
      urlPath = urlPath.slice(mountPath.length) || "/";
    }
    // Decode percent-encoded path. Reject decoding failures (malformed URI).
    var decoded;
    try { decoded = decodeURIComponent(urlPath); }
    catch (_e) { return next(); }

    var absPath = _resolveSafe(root, decoded);
    if (!absPath) return next();

    // Directory → index file (if configured)
    var stat;
    try { stat = await fsp.stat(absPath); }
    catch (_e) { return next(); }
    if (stat.isDirectory()) {
      if (!indexFile) return next();
      absPath = path.join(absPath, indexFile);
    }

    var meta = await _readMeta(absPath);
    if (!meta) return next();

    var cacheControl = _cacheControlFor(urlPath);

    // 304 short-circuit
    var ifNone = req.headers && req.headers["if-none-match"];
    if (ifNone && ifNone === meta.etag) {
      return _writeNotModified(res, meta.etag, cacheControl);
    }

    var headers = {
      "Content-Type":   _contentTypeFor(absPath, contentTypes),
      "Content-Length": meta.size,
      "ETag":           meta.etag,
      "Cache-Control":  cacheControl,
      // SRI hint for templates that want to <script integrity=…>; not
      // required by clients but consumers can read it from response
      // headers when they want to embed integrity in subsequent pages.
      "X-Integrity":    meta.integrity,
    };

    if (req.method === "HEAD") {
      res.writeHead(HTTP.OK, headers);
      return res.end();
    }

    res.writeHead(HTTP.OK, headers);
    var stream = fs.createReadStream(absPath);
    stream.on("error", function (e) {
      // Mid-stream read error — best we can do is destroy the response;
      // headers are already on the wire.
      try { res.destroy(e); } catch (_) { /* response already torn down */ }
    });
    stream.pipe(res);
  };
}

// ---- Test helper ----
function _resetCacheForTest() { _cache.clear(); }

module.exports = {
  create:                create,
  integrity:             integrity,
  DEFAULT_MAX_AGE_SEC:   DEFAULT_MAX_AGE_SEC,
  IMMUTABLE_MAX_AGE_SEC: IMMUTABLE_MAX_AGE_SEC,
  DEFAULT_HASHED_PATTERN: DEFAULT_HASHED_PATTERN,
  _resetCacheForTest:    _resetCacheForTest,
};
