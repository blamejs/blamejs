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

// csrf-protect does NOT buffer or parse the request body itself.
// Operators who use form-urlencoded POSTs MUST register
// `b.middleware.bodyParser()` before csrf-protect so that
// `req.body[fieldName]` is populated. Header-token submissions
// (X-CSRF-Token) work without bodyParser. The body-parser primitive
// owns size caps, content-type dispatch, and prototype-pollution
// defense; csrf-protect just reads the validated value.

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

  return function csrfProtect(req, res, next) {
    if (methods.indexOf(req.method) === -1) return next();

    var expected = opts.tokenLookup(req);
    if (!expected) {
      _emitDenied(req, "no expected token in session");
      return _writeReject(res, "CSRF token mismatch.");
    }

    // Header path first — covers JSON / AJAX / multipart cases.
    var submitted = req.headers && req.headers[headerName];
    if (typeof submitted !== "string" || submitted.length === 0) {
      // Fall back to body field if bodyParser already populated req.body.
      // Operators with form-urlencoded POSTs are expected to register
      // bodyParser before csrf-protect; body buffering / parsing lives
      // in bodyParser, not here.
      if (req.body && typeof req.body === "object") {
        var v = req.body[fieldName];
        if (typeof v === "string") submitted = v;
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
