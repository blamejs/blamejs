"use strict";
/**
 * require-auth middleware — gates routes that require an authenticated
 * user. Mount AFTER attachUser; this middleware reads `req.user` and
 * either lets the request through or rejects it.
 *
 * Rejection shape:
 *   - JSON-preferring caller (Accept: application/json, or X-Requested-With:
 *     XMLHttpRequest, or content-type starts application/json):
 *     401 application/json with { error: "Authentication required." }
 *   - Browser-preferring caller, when opts.redirectTo is set:
 *     302 with Location header
 *   - Otherwise:
 *     401 text/plain
 *
 * Always emits `auth.required.denied` audit event on rejection (when
 * opts.audit !== false). The event records request method + path +
 * client IP — keys-only, no body content.
 *
 * Options:
 *   {
 *     redirectTo:    null         (optional URL for browser redirects;
 *                                   when set, prefersJson()=false rejections
 *                                   produce 302 instead of 401 text/plain)
 *     prefersJson:   function     (optional override; defaults to checking
 *                                   Accept / X-Requested-With / Content-Type)
 *     errorMessage:  'Authentication required.'
 *     audit:         true         (emit auth.required.denied on reject)
 *   }
 */
var lazyRequire = require("../lazy-require");
var audit = lazyRequire(function () { return require("../audit"); });

function _defaultPrefersJson(req) {
  var h = req.headers || {};
  if (typeof h.accept === "string" && h.accept.indexOf("application/json") !== -1) return true;
  if (h["x-requested-with"] === "XMLHttpRequest") return true;
  if (typeof h["content-type"] === "string" &&
      h["content-type"].indexOf("application/json") === 0) return true;
  return false;
}

function create(opts) {
  opts = opts || {};
  var redirectTo  = opts.redirectTo  || null;
  var prefersJson = typeof opts.prefersJson === "function"
    ? opts.prefersJson
    : _defaultPrefersJson;
  var msg     = opts.errorMessage || "Authentication required.";
  var auditOn = opts.audit !== false;

  return function requireAuth(req, res, next) {
    if (req.user) return next();

    if (auditOn) {
      try {
        audit().emit({
          action:   "auth.required.denied",
          outcome:  "denied",
          actor:    { ip: req.socket && req.socket.remoteAddress, userAgent: req.headers && req.headers["user-agent"] },
          reason:   "no authenticated user on request",
          metadata: { method: req.method, path: req.pathname || (req.url || "").split("?")[0] },
        });
      } catch (_e) { /* audit best-effort */ }
    }

    if (prefersJson(req)) {
      if (typeof res.writeHead === "function") {
        res.writeHead(401, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: msg }));
      }
      return;
    }
    if (redirectTo) {
      if (typeof res.writeHead === "function") {
        res.writeHead(302, { "Location": redirectTo });
        res.end();
      }
      return;
    }
    if (typeof res.writeHead === "function") {
      res.writeHead(401, { "Content-Type": "text/plain" });
      res.end(msg);
    }
  };
}

module.exports = {
  create:               create,
  _defaultPrefersJson:  _defaultPrefersJson,
};
