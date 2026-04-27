"use strict";
/**
 * csrf-protect — middleware that rejects state-changing requests
 * whose CSRF token doesn't match the expected one.
 *
 * Mount AFTER attachUser (the operator-supplied tokenLookup typically
 * reads from req.session, which attachUser populates) and BEFORE the
 * routes that mutate state. Safe methods (GET / HEAD / OPTIONS) pass
 * through unchanged; the gate only fires on the configured methods
 * (default POST / PUT / DELETE / PATCH).
 *
 * Token sources tried in order:
 *   1. Header `X-CSRF-Token` (or opts.headerName)
 *   2. Body field `_csrf` (or opts.fieldName) — only when Content-Type
 *      is application/x-www-form-urlencoded; the middleware buffers
 *      the body, populates req.body with the parsed URLSearchParams
 *      object, and routes downstream see it pre-parsed.
 *
 * Operators using JSON request bodies + a header are well served by
 * the default. Operators using multipart/form-data (file uploads
 * etc.) must put the CSRF token in the header — multipart parsing is
 * out of scope for this middleware.
 *
 * On mismatch:
 *   - Audit emit (auth.csrf.denied) with method + path + IP
 *   - 403 application/json: { error: "CSRF token mismatch." }
 *   - next() NOT called
 *
 * Options:
 *   {
 *     tokenLookup: (req) => string|null      REQUIRED — returns the
 *                                            expected token (typically
 *                                            req.session.data.csrfToken)
 *     fieldName:   "_csrf"                   form-body field name
 *     headerName:  "X-CSRF-Token"            header name
 *     methods:     ["POST", "PUT", "DELETE", "PATCH"]
 *     bodyMaxBytes: 1 MiB                    body buffer cap
 *     audit:        true
 *   }
 */
var lazyRequire = require("../lazy-require");
var forms = require("../forms");
var audit = lazyRequire(function () { return require("../audit"); });

var DEFAULT_FIELD_NAME   = "_csrf";
var DEFAULT_HEADER_NAME  = "X-CSRF-Token";
var DEFAULT_METHODS      = Object.freeze(["POST", "PUT", "DELETE", "PATCH"]);
var DEFAULT_BODY_MAX     = 1024 * 1024;

function _bufferUrlencodedBody(req, maxBytes) {
  return new Promise(function (resolve, reject) {
    var chunks = [];
    var total = 0;
    req.on("data", function (chunk) {
      total += chunk.length;
      if (total > maxBytes) {
        req.destroy();
        reject(new Error("CSRF body buffer cap exceeded (" + maxBytes + " bytes)"));
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", function () { resolve(Buffer.concat(chunks).toString("utf8")); });
    req.on("error", reject);
  });
}

function _parseUrlencoded(body) {
  // URLSearchParams doesn't return a plain object — convert it so
  // route handlers can do `req.body.fieldName` naturally.
  var sp = new URLSearchParams(body);
  var out = {};
  // For repeated keys (e.g. multi-select), we keep the last one. Operators
  // who need full multi-value access can use sp.getAll() via a different
  // path — kept simple here because that's the common case.
  sp.forEach(function (value, key) { out[key] = value; });
  return out;
}

function _writeReject(res, message) {
  if (typeof res.writeHead === "function") {
    var body = JSON.stringify({ error: message });
    res.writeHead(403, {
      "Content-Type":   "application/json; charset=utf-8",
      "Content-Length": Buffer.byteLength(body),
    });
    res.end(body);
  }
}

function create(opts) {
  opts = opts || {};
  if (typeof opts.tokenLookup !== "function") {
    throw new Error("middleware.csrfProtect: opts.tokenLookup is required " +
      "(function (req) → expected token | null)");
  }
  var fieldName  = opts.fieldName  || DEFAULT_FIELD_NAME;
  var headerName = (opts.headerName || DEFAULT_HEADER_NAME).toLowerCase();
  var methods    = (opts.methods || DEFAULT_METHODS).map(function (m) { return m.toUpperCase(); });
  var bodyMax    = typeof opts.bodyMaxBytes === "number" ? opts.bodyMaxBytes : DEFAULT_BODY_MAX;
  var auditOn    = opts.audit !== false;

  function _emitDenied(req, reason) {
    if (!auditOn) return;
    try {
      audit().emit({
        action:   "auth.csrf.denied",
        outcome:  "denied",
        actor:    { ip: req.socket && req.socket.remoteAddress, userAgent: req.headers && req.headers["user-agent"] },
        reason:   reason,
        metadata: { method: req.method, path: (req.url || "").split("?")[0] },
      });
    } catch (_e) { /* audit best-effort */ }
  }

  return async function csrfProtect(req, res, next) {
    if (methods.indexOf(req.method) === -1) return next();

    var expected = opts.tokenLookup(req);
    if (!expected) {
      _emitDenied(req, "no expected token in session");
      return _writeReject(res, "CSRF token mismatch.");
    }

    // Header path first — covers JSON / AJAX / multipart cases.
    var submitted = req.headers && req.headers[headerName];
    if (typeof submitted !== "string" || submitted.length === 0) {
      // Fall back to urlencoded body if the Content-Type matches.
      var ct = req.headers && req.headers["content-type"] || "";
      if (ct.indexOf("application/x-www-form-urlencoded") === 0) {
        var rawBody;
        try { rawBody = await _bufferUrlencodedBody(req, bodyMax); }
        catch (_e) {
          _emitDenied(req, "body buffering failed");
          return _writeReject(res, "CSRF token mismatch.");
        }
        var parsed = _parseUrlencoded(rawBody);
        // Make the parsed body available to downstream handlers — they
        // can't read req again, we already consumed the stream.
        req.body = parsed;
        submitted = parsed[fieldName];
      }
    }

    if (!forms.verifyCsrfToken(submitted || "", expected)) {
      _emitDenied(req, "submitted token does not match expected");
      return _writeReject(res, "CSRF token mismatch.");
    }

    return next();
  };
}

module.exports = { create: create };
