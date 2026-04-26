"use strict";
/**
 * Error-handler middleware — converts thrown errors into HTTP responses
 * without leaking implementation details to the client.
 *
 * Pattern (matching the existing project error-handling convention):
 *   - AppError-shaped throws (objects with statusCode + isAppError) →
 *     emit that statusCode + a sanitized JSON body
 *   - Validation errors from b.json (code starting 'json/') →  400 with
 *     the validation path in the response (path is safe to expose)
 *   - Storage / queue / external-db errors with permanent flag → 4xx
 *     status code
 *   - Anything else → 500 Internal Server Error with a generic body;
 *     full error details audit-logged for the operator's investigation
 *
 * The handler ALWAYS audit-records the error (system.http.error) with the
 * request id, path, method, sanitized error code, and the stack trace
 * (sealed in metadata, not in the response).
 *
 * Mount AFTER all other middleware + routes so it catches downstream throws.
 *
 * Options:
 *   {
 *     exposeStackInDev:   process.env.NODE_ENV !== 'production'
 *     genericMessage:     'Internal Server Error'
 *     audit:              true                                 // emit system.http.error
 *   }
 */
var envSafe = require("../parsers/env-safe");
var _audit = null;
function audit() { if (!_audit) _audit = require("../audit"); return _audit; }

function _statusFromError(err) {
  if (!err) return 500;
  if (typeof err.statusCode === "number") return err.statusCode;
  if (err.isAppError && err.status) return err.status;
  if (err.isJsonSafeError) return 400;
  if (err.isStorageError && err.permanent) return 400;
  if (err.isQueueError && err.permanent) return 400;
  if (err.isExternalDbError && err.permanent) return 400;
  return 500;
}

function _sanitizedBody(err, status, exposeStack) {
  var body = {
    error: {
      code:    err.code || (status === 400 ? "bad_request" : "internal_error"),
      message: status >= 500 ? "Internal Server Error" : (err.message || "Bad Request"),
    },
  };
  if (err.path)     body.error.path = err.path;
  if (err.errors && Array.isArray(err.errors)) {
    body.error.details = err.errors.map(function (e) {
      return { path: e.path, code: e.code, message: e.message };
    });
  }
  if (exposeStack && err.stack && status >= 500) body.error.stack = err.stack;
  return body;
}

function create(opts) {
  opts = opts || {};
  var exposeStack = opts.exposeStackInDev !== false &&
                    envSafe.readVar("NODE_ENV", { default: "" }) !== "production";
  var auditOn = opts.audit !== false;

  return function errorHandler(err, req, res, _next) {
    var status = _statusFromError(err);
    var body = _sanitizedBody(err, status, exposeStack);

    if (auditOn) {
      try {
        audit().emit({
          actor:    {
            ip:        req.headers && req.headers["x-forwarded-for"] || (req.socket && req.socket.remoteAddress),
            userAgent: req.headers && req.headers["user-agent"],
            sessionId: req.session && req.session.sid,
          },
          action:   "system.http.error",
          outcome:  status >= 500 ? "failure" : "denied",
          reason:   err.message || String(err),
          metadata: {
            method:    req.method,
            path:      req.pathname || req.url,
            status:    status,
            errorCode: err.code || null,
            stack:     err.stack || null,
            requestId: req.requestId || null,
          },
          requestId: req.requestId || null,
        });
      } catch (_e) { /* audit unavailable — best effort */ }
    }

    if (res.writableEnded) return;
    if (typeof res.writeHead === "function") {
      res.writeHead(status, { "Content-Type": "application/json" });
    }
    if (typeof res.end === "function") {
      res.end(JSON.stringify(body));
    }
  };
}

module.exports = { create: create };
