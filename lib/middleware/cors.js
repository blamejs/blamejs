"use strict";
/**
 * CORS middleware — allow-list-only by default. No '*' wildcard support
 * for credentialed requests (which spec disallows anyway). Operators must
 * explicitly enumerate origins they trust.
 *
 * Options:
 *   {
 *     origins:        [ 'https://app.example.com', /^https:\/\/.+\.example\.com$/ ]
 *     methods:        [ 'GET', 'POST', 'PUT', 'DELETE', 'PATCH' ]
 *     headers:        [ 'Content-Type', 'Authorization', 'X-Request-Id' ]
 *     exposeHeaders:  [ 'X-Request-Id', 'X-Response-Time' ]
 *     credentials:    true     (sets Access-Control-Allow-Credentials: true)
 *     maxAgeSeconds:  600
 *     refuseUnknown:  true     (refuse cross-origin requests from unlisted
 *                                origins instead of just omitting CORS headers)
 *   }
 *
 * Audit: refuseUnknown blocks emit system.cors.block with the offending Origin.
 */
var _audit = null;
function audit() { if (!_audit) _audit = require("../audit"); return _audit; }

function _matchOrigin(origin, allowList) {
  if (!origin) return null;
  for (var i = 0; i < allowList.length; i++) {
    var entry = allowList[i];
    if (typeof entry === "string" && entry === origin) return origin;
    if (entry instanceof RegExp && entry.test(origin)) return origin;
  }
  return null;
}

function create(opts) {
  opts = opts || {};
  var origins = opts.origins || [];
  var methods = (opts.methods || ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]).join(", ");
  var headers = (opts.headers || ["Content-Type", "Authorization", "X-Request-Id"]).join(", ");
  var exposeHeaders = (opts.exposeHeaders || ["X-Request-Id"]).join(", ");
  var credentials = !!opts.credentials;
  var maxAge = String(opts.maxAgeSeconds || 600);
  var refuseUnknown = opts.refuseUnknown !== false;

  return function cors(req, res, next) {
    var origin = req.headers && req.headers.origin;
    if (!origin) return next();   // not a cross-origin request

    var matched = _matchOrigin(origin, origins);
    if (!matched) {
      if (refuseUnknown) {
        try {
          audit().emit({
            actor:    { ip: (req.headers && req.headers["x-forwarded-for"]) || (req.socket && req.socket.remoteAddress) },
            action:   "system.cors.block",
            outcome:  "denied",
            reason:   "origin not in allow-list",
            metadata: { origin: origin, method: req.method, path: req.pathname || req.url, requestId: req.requestId },
            requestId: req.requestId,
          });
        } catch (_e) {}
        if (typeof res.writeHead === "function") {
          res.writeHead(403, { "Content-Type": "text/plain" });
          res.end("CORS: origin not allowed");
          return;
        }
      }
      return next();   // permissive mode: just don't set CORS headers
    }

    if (typeof res.setHeader === "function") {
      res.setHeader("Access-Control-Allow-Origin", matched);
      res.setHeader("Vary", "Origin");
      if (credentials) res.setHeader("Access-Control-Allow-Credentials", "true");
      res.setHeader("Access-Control-Expose-Headers", exposeHeaders);
    }

    if (req.method === "OPTIONS" && req.headers["access-control-request-method"]) {
      // Preflight
      if (typeof res.setHeader === "function") {
        res.setHeader("Access-Control-Allow-Methods", methods);
        res.setHeader("Access-Control-Allow-Headers", headers);
        res.setHeader("Access-Control-Max-Age", maxAge);
      }
      if (typeof res.writeHead === "function") {
        res.writeHead(204);
        res.end();
      }
      return;
    }

    next();
  };
}

module.exports = { create: create };
