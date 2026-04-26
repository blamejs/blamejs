"use strict";
/**
 * Local-filesystem protocol adapter for object-store.
 *
 * Implements the uniform protocol surface (put / get / getStream / delete /
 * head / list) against a directory tree. Streaming is via Node's native
 * fs.createReadStream / createWriteStream — no in-memory buffering of
 * full files.
 *
 * Path safety: every key resolves under the configured rootDir, with an
 * alphanumeric + `_-./` charset whitelist and explicit rejection of any
 * path that escapes rootDir after resolution.
 */
var fs = require("fs");
var path = require("path");
var atomicFile = require("./atomic-file");
var cluster = require("./cluster");

var SAFE_KEY = /^[A-Za-z0-9_\-./]+$/;

function _resolveSafe(rootDir, key) {
  if (typeof key !== "string" || key.length === 0) {
    throw _err("INVALID_KEY", "key must be a non-empty string", true);
  }
  if (key.includes("\0")) throw _err("INVALID_KEY", "null byte in key", true);
  if (path.isAbsolute(key)) throw _err("INVALID_KEY", "absolute key not allowed", true);
  if (!SAFE_KEY.test(key)) throw _err("INVALID_KEY", "invalid characters in key", true);
  var full = path.resolve(rootDir, key);
  var withSep = rootDir.endsWith(path.sep) ? rootDir : rootDir + path.sep;
  if (full !== rootDir && !full.startsWith(withSep)) {
    throw _err("INVALID_KEY", "key escapes rootDir", true);
  }
  return full;
}

function _err(code, message, permanent) {
  var e = new Error(message);
  e.code = code;
  e.permanent = !!permanent;
  e.isObjectStoreError = true;
  return e;
}

function create(config) {
  if (!config || !config.rootDir) {
    throw new Error("local protocol requires { rootDir }");
  }
  var rootDir = path.resolve(config.rootDir);
  if (!fs.existsSync(rootDir)) fs.mkdirSync(rootDir, { recursive: true });

  function put(key, body, _opts) {
    cluster.requireLeader();
    var full = _resolveSafe(rootDir, key);
    var dir = path.dirname(full);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

    if (Buffer.isBuffer(body)) {
      atomicFile.writeSync(full, body);
      return Promise.resolve({ size: body.length });
    }
    if (body && typeof body.pipe === "function") {
      // Streaming put — pipe directly to disk
      return new Promise(function (resolve, reject) {
        var ws = fs.createWriteStream(full);
        var bytes = 0;
        body.on("data", function (chunk) { bytes += chunk.length; });
        body.pipe(ws);
        ws.on("finish", function () { resolve({ size: bytes }); });
        ws.on("error", reject);
        body.on("error", reject);
      });
    }
    if (typeof body === "string") {
      var buf = Buffer.from(body, "utf8");
      atomicFile.writeSync(full, buf);
      return Promise.resolve({ size: buf.length });
    }
    return Promise.reject(_err("INVALID_BODY", "put body must be Buffer, Readable, or string", true));
  }

  function get(key) {
    var full = _resolveSafe(rootDir, key);
    if (!fs.existsSync(full)) {
      return Promise.reject(_err("NOT_FOUND", "key not found: " + key, true));
    }
    return Promise.resolve(fs.readFileSync(full));
  }

  function getStream(key) {
    var full = _resolveSafe(rootDir, key);
    if (!fs.existsSync(full)) {
      throw _err("NOT_FOUND", "key not found: " + key, true);
    }
    return fs.createReadStream(full);
  }

  function head(key) {
    var full = _resolveSafe(rootDir, key);
    if (!fs.existsSync(full)) {
      return Promise.reject(_err("NOT_FOUND", "key not found: " + key, true));
    }
    var stat = fs.statSync(full);
    return Promise.resolve({
      size:         stat.size,
      lastModified: stat.mtimeMs,
    });
  }

  function deleteKey(key) {
    cluster.requireLeader();
    var full = _resolveSafe(rootDir, key);
    if (!fs.existsSync(full)) return Promise.resolve(false);
    fs.unlinkSync(full);
    return Promise.resolve(true);
  }

  function list(prefix, opts) {
    opts = opts || {};
    var max = opts.maxResults || 1000;
    var prefixDir = prefix ? _resolveSafe(rootDir, prefix.replace(/\/$/, "")) : rootDir;
    var results = [];
    function walk(dir, base) {
      if (results.length >= max) return;
      if (!fs.existsSync(dir)) return;
      var entries = fs.readdirSync(dir);
      for (var i = 0; i < entries.length; i++) {
        if (results.length >= max) break;
        var name = entries[i];
        var full = path.join(dir, name);
        var rel = base ? base + "/" + name : name;
        var stat = fs.statSync(full);
        if (stat.isDirectory()) walk(full, rel);
        else results.push({ key: rel, size: stat.size, lastModified: stat.mtimeMs });
      }
    }
    var basePrefix = prefix ? prefix.replace(/\/$/, "") : "";
    walk(prefixDir, basePrefix);
    return Promise.resolve({ items: results, truncated: results.length >= max });
  }

  return {
    protocol:  "local",
    rootDir:   rootDir,
    put:       put,
    get:       get,
    getStream: getStream,
    head:      head,
    delete:    deleteKey,
    list:      list,
  };
}

module.exports = { create: create };
