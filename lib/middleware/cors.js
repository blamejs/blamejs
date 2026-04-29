"use strict";
/**
 * CORS middleware — allow-list-only by default. No '*' wildcard support
 * for credentialed requests (which spec disallows anyway). Operators must
 * explicitly enumerate origins they trust.
 *
 * Same-origin requests pass through without consulting the allow-list:
 * the Fetch spec instructs browsers to send an Origin header on every
 * POST / PUT / PATCH / DELETE — even same-origin ones — so an empty
 * allow-list would otherwise refuse the operator's own login form.
 * Same-origin is detected by comparing the request's Origin header
 * against either:
 *   - opts.siteOrigin (explicit, recommended — works behind TLS-
 *     terminating proxies where the framework can't infer scheme), or
 *   - the request's own scheme/host/port (inferred from req.socket and
 *     req.headers.host — correct for direct deployments).
 *
 * Options:
 *   {
 *     origins:        [ 'https://app.example.com', /^https:\/\/.+\.example\.com$/ ]
 *     siteOrigin:     'https://wiki.example.com'    // string OR array
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
 *
 * Validation tier: Tier A (config-time throw) — opts.siteOrigin must
 * parse as an http(s) URL, opts.origins entries must be strings or
 * RegExp. Bad config surfaces at create() not at first cross-origin
 * request.
 */
var lazyRequire = require("../lazy-require");
var audit = lazyRequire(function () { return require("../audit"); });
var safeUrl = require("../safe-url");
var { defineClass } = require("../framework-error");

var CorsError = defineClass("CorsError", { alwaysPermanent: true });

function _matchOrigin(origin, allowList) {
  if (!origin) return null;
  for (var i = 0; i < allowList.length; i++) {
    var entry = allowList[i];
    if (typeof entry === "string" && entry === origin) return origin;
    if (entry instanceof RegExp && entry.test(origin)) return origin;
  }
  return null;
}

// Normalize an origin string by parsing it through safeUrl and
// returning `protocol//host[:port]` with no trailing slash. Used for
// equality checks that have to handle case differences and the URL
// parser's auto-port-omission for default ports (80/443).
//
// safeUrl defaults to ALLOW_HTTP_TLS (https only). CORS origins
// legitimately include http for local dev; pass ALLOW_HTTP_ALL.
function _canonicalOrigin(input) {
  if (!input || typeof input !== "string") return null;
  try {
    var parsed = safeUrl.parse(input, { allowedProtocols: safeUrl.ALLOW_HTTP_ALL });
    var proto  = parsed.protocol;          // "http:" or "https:"
    var host   = parsed.hostname.toLowerCase();
    var port   = parsed.port;              // "" when default
    return proto + "//" + host + (port ? ":" + port : "");
  } catch (_e) {
    return null;
  }
}

// Build the request's own origin from req when opts.siteOrigin isn't
// supplied. Works for direct deployments (no proxy); operators behind
// a TLS-terminating proxy that doesn't forward correct Host should set
// opts.siteOrigin explicitly.
function _inferRequestOrigin(req) {
  if (!req || !req.headers) return null;
  var host = req.headers.host;
  if (!host) return null;
  // X-Forwarded-Proto wins when present (operator behind a TLS-
  // terminator, intermediate set the header). Otherwise infer from
  // the socket — req.socket.encrypted is set by node:tls.
  var fwdProto = req.headers["x-forwarded-proto"];
  var proto;
  if (typeof fwdProto === "string" && fwdProto.length > 0) {
    proto = fwdProto.split(",")[0].trim().toLowerCase();
  } else if (req.socket && req.socket.encrypted) {
    proto = "https";
  } else {
    proto = "http";
  }
  return _canonicalOrigin(proto + "://" + host);
}

function _isSameOrigin(req, originHeader, configuredSiteOrigins) {
  var canonOrigin = _canonicalOrigin(originHeader);
  if (!canonOrigin) return false;
  // Operator-supplied site origins take priority — they're the
  // authoritative source for "this request is one of mine".
  if (configuredSiteOrigins && configuredSiteOrigins.length > 0) {
    for (var i = 0; i < configuredSiteOrigins.length; i++) {
      if (configuredSiteOrigins[i] === canonOrigin) return true;
    }
    return false;
  }
  // Fall back to inferring from the request itself.
  var reqOrigin = _inferRequestOrigin(req);
  return reqOrigin !== null && reqOrigin === canonOrigin;
}

function create(opts) {
  opts = opts || {};
  var origins = opts.origins || [];

  // Tier A validation on opts.origins — strings or RegExp only.
  for (var oi = 0; oi < origins.length; oi++) {
    var entry = origins[oi];
    if (typeof entry !== "string" && !(entry instanceof RegExp)) {
      throw new CorsError("cors/bad-origin",
        "origins[" + oi + "] must be a string or RegExp (got " + typeof entry + ")");
    }
  }

  // Tier A validation on opts.siteOrigin — must parse as http(s) URL.
  // Accept string OR array of strings.
  var siteOrigins = [];
  if (opts.siteOrigin !== undefined && opts.siteOrigin !== null) {
    var rawList = Array.isArray(opts.siteOrigin) ? opts.siteOrigin : [opts.siteOrigin];
    for (var si = 0; si < rawList.length; si++) {
      var raw = rawList[si];
      if (typeof raw !== "string" || raw.length === 0) {
        throw new CorsError("cors/bad-site-origin",
          "siteOrigin[" + si + "] must be a non-empty string (got " + typeof raw + ")");
      }
      var canon = _canonicalOrigin(raw);
      if (!canon) {
        throw new CorsError("cors/bad-site-origin",
          "siteOrigin[" + si + "]='" + raw + "' is not a parseable http(s) URL");
      }
      siteOrigins.push(canon);
    }
  }

  var methods = (opts.methods || ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]).join(", ");
  var headers = (opts.headers || ["Content-Type", "Authorization", "X-Request-Id"]).join(", ");
  var exposeHeaders = (opts.exposeHeaders || ["X-Request-Id"]).join(", ");
  var credentials = !!opts.credentials;
  var maxAge = String(opts.maxAgeSeconds || 600);
  var refuseUnknown = opts.refuseUnknown !== false;

  return function cors(req, res, next) {
    var origin = req.headers && req.headers.origin;
    if (!origin) return next();   // not a cross-origin request

    // Same-origin POST/PUT/etc. carry an Origin header per the Fetch
    // spec but should not be subject to CORS allow-listing — they're
    // the operator's own site talking to itself.
    if (_isSameOrigin(req, origin, siteOrigins)) return next();

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

module.exports = {
  create:    create,
  CorsError: CorsError,
};
