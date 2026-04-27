"use strict";
/**
 * attach-user middleware — populates req.user (and req.session) from a
 * verified session token.
 *
 * Token sources, tried in order:
 *   1. Cookie named opts.cookieName (default "blamejs_session")
 *   2. Authorization: Bearer <token> header
 * The first one that produces a verified session wins. Operators who
 * want only one path can disable the other via opts.tokenFrom.
 *
 * The framework can't know the application's user schema, so the
 * middleware delegates user-record loading to opts.userLoader — an
 * async function `(verifiedSession) => user | null`. The verified
 * session contains { userId, data, createdAt, expiresAt, lastActivity }
 * (whatever session.verify returns). Operators typically look up by
 * userId in their own users table.
 *
 * Failure modes (none of which throw):
 *   - No token in either source → req.user = null, next()
 *   - Token present but session.verify rejects → req.user = null, next()
 *   - Session valid but userLoader returns null/undefined (user
 *     deleted/suspended) → req.user = null, next() + audit emit
 *
 * Always calls next() — the gating decision is downstream's job (use
 * middleware.requireAuth for that). This middleware only ATTACHES.
 *
 * Options:
 *   {
 *     cookieName:     'blamejs_session'                 (cookie name to look at)
 *     tokenFrom:      'both' | 'cookie' | 'header'      (default 'both')
 *     userLoader:     async (verifiedSession) => user   (REQUIRED)
 *     audit:          true                              (emit 'auth.session.user_unloadable'
 *                                                        when verify ok but userLoader nulls)
 *   }
 */
var lazyRequire = require("../lazy-require");
var session = lazyRequire(function () { return require("../session"); });
var audit = lazyRequire(function () { return require("../audit"); });

// Minimal RFC 6265 cookie parser. Returns the named cookie's value or
// null. Does not URL-decode — session tokens are 64 hex chars (no
// reserved characters), so the value comes through as-is. Callers
// passing arbitrary cookie values would need their own parser.
function _readCookie(cookieHeader, name) {
  if (!cookieHeader || typeof cookieHeader !== "string") return null;
  var pairs = cookieHeader.split(/;\s*/);
  for (var i = 0; i < pairs.length; i++) {
    var eq = pairs[i].indexOf("=");
    if (eq === -1) continue;
    var k = pairs[i].slice(0, eq).trim();
    if (k === name) return pairs[i].slice(eq + 1).trim();
  }
  return null;
}

function _readBearer(authHeader) {
  if (!authHeader || typeof authHeader !== "string") return null;
  // case-insensitive scheme match
  var m = authHeader.match(/^Bearer\s+(.+)$/i);
  return m ? m[1].trim() : null;
}

function create(opts) {
  opts = opts || {};
  if (typeof opts.userLoader !== "function") {
    throw new Error("middleware.attachUser: opts.userLoader is required " +
      "(async function (verifiedSession) → user | null)");
  }
  var cookieName = opts.cookieName || "blamejs_session";
  var tokenFrom  = opts.tokenFrom  || "both";
  var auditOn    = opts.audit !== false;

  return async function attachUser(req, res, next) {
    req.user = null;
    req.session = null;

    var token = null;
    if (tokenFrom === "cookie" || tokenFrom === "both") {
      token = _readCookie(req.headers && req.headers.cookie, cookieName);
    }
    if (!token && (tokenFrom === "header" || tokenFrom === "both")) {
      token = _readBearer(req.headers && req.headers.authorization);
    }
    if (!token) return next();

    var verified;
    try {
      verified = await session().verify(token);
    } catch (_e) {
      // session.verify is tolerant — shouldn't normally throw, but if it
      // does (DB hiccup), don't propagate; treat as "no user" and let
      // downstream require-auth produce a 401.
      return next();
    }
    if (!verified) return next();

    var user;
    try {
      user = await opts.userLoader(verified);
    } catch (e) {
      // userLoader threw — treat as "no user" but record so the
      // operator can investigate. Don't surface to the response.
      if (auditOn) {
        try {
          audit().emit({
            action:   "auth.session.user_loader_threw",
            outcome:  "failure",
            actor:    { userId: verified.userId, ip: req.socket && req.socket.remoteAddress },
            reason:   (e && e.message) || String(e),
          });
        } catch (_ignored) { /* audit best-effort */ }
      }
      return next();
    }
    if (!user) {
      // Session valid but user record is gone (deleted) or rejected
      // (suspended, etc.). Record + don't attach.
      if (auditOn) {
        try {
          audit().emit({
            action:   "auth.session.user_unloadable",
            outcome:  "failure",
            actor:    { userId: verified.userId, ip: req.socket && req.socket.remoteAddress },
          });
        } catch (_ignored) { /* audit best-effort */ }
      }
      return next();
    }

    req.user = user;
    req.session = verified;
    return next();
  };
}

module.exports = {
  create:       create,
  // Exported for tests and operator-side cookie reading
  _readCookie:  _readCookie,
  _readBearer:  _readBearer,
};
