"use strict";
/**
 * request-helpers — small shared utilities for HTTP request middleware.
 *
 * The framework's metrics + tracing requestMiddleware both label by
 * route TEMPLATE and capture the final response status. They had
 * identical implementations of:
 *
 *   1. Reading req.routePattern with a URL-fallback
 *   2. Wrapping res.writeHead + reading res.statusCode at res.end
 *
 * This module owns the two helpers so the duplication doesn't drift —
 * if either pattern changes (e.g. handle res.statusMessage), it changes
 * once.
 *
 * Public API:
 *
 *   resolveRoute(req)
 *     Returns req.routePattern when the router populated it,
 *     otherwise the URL with query string stripped.
 *
 *   captureResponseStatus(res, onEnd)
 *     Wraps res.writeHead + res.end. Calls onEnd(status) once when the
 *     response ends, with the final status pulled from writeHead's
 *     argument OR from res.statusCode (modern Node handlers set it
 *     directly without going through writeHead). Operators wrap their
 *     own pre-end logic by passing it as onEnd.
 *
 *     Returns the original (unwrapped) `res.end`. Useful for unit tests
 *     that need to assert against the original behavior.
 */

// extractActorContext(req) — pull the 5 W's from a request for audit
// chain emission. WHO/WHERE/HOW columns on _blamejs_audit_log are
// populated from this shape:
//
//   { ip, userAgent, sessionId, requestId, method, route, userId }
//
// Every field is best-effort: missing or non-request inputs return
// an object with whatever could be inferred plus null elsewhere.
// Audit chain treats null as "unknown", so partial context is safe.
//
// Caller-supplied actor (existing actor.userId, actor.ip, etc.) is
// merged on top of the request-derived fields — explicit operator
// override always wins.
function extractActorContext(req, override) {
  var ctx = {
    ip:        null,
    userAgent: null,
    sessionId: null,
    requestId: null,
    method:    null,
    route:     null,
    userId:    null,
  };
  if (req && typeof req === "object") {
    // Direct properties first (Express-shaped frameworks set req.ip).
    if (typeof req.ip === "string") ctx.ip = req.ip;
    else if (req.connection && typeof req.connection.remoteAddress === "string") {
      ctx.ip = req.connection.remoteAddress;
    } else if (req.socket && typeof req.socket.remoteAddress === "string") {
      ctx.ip = req.socket.remoteAddress;
    }
    if (req.headers && typeof req.headers["user-agent"] === "string") {
      ctx.userAgent = req.headers["user-agent"];
    }
    if (req.session && typeof req.session.id === "string") ctx.sessionId = req.session.id;
    else if (typeof req.sessionId === "string") ctx.sessionId = req.sessionId;
    if (typeof req.requestId === "string") ctx.requestId = req.requestId;
    else if (req.headers && typeof req.headers["x-request-id"] === "string") {
      ctx.requestId = req.headers["x-request-id"];
    }
    if (typeof req.method === "string") ctx.method = req.method;
    ctx.route = resolveRoute(req);
    // userId from common shapes the framework's auth surfaces produce
    if (req.user && typeof req.user.id === "string") ctx.userId = req.user.id;
    else if (req.user && typeof req.user.userId === "string") ctx.userId = req.user.userId;
    else if (req.apiKey && typeof req.apiKey.ownerId === "string") ctx.userId = req.apiKey.ownerId;
  }
  if (override && typeof override === "object") {
    for (var k in override) {
      if (Object.prototype.hasOwnProperty.call(override, k) && override[k] != null) {
        ctx[k] = override[k];
      }
    }
  }
  return ctx;
}

function resolveRoute(req) {
  if (req && typeof req.routePattern === "string" && req.routePattern.length > 0) {
    return req.routePattern;
  }
  var url = req && req.url;
  if (typeof url !== "string" || url.length === 0) return "/";
  var qIdx = url.indexOf("?");
  return qIdx === -1 ? url : url.slice(0, qIdx);
}

function captureResponseStatus(res, onEnd) {
  if (!res || typeof onEnd !== "function") {
    throw new Error("captureResponseStatus: requires (res, onEnd)");
  }
  var origEnd = res.end;
  var origWriteHead = res.writeHead;
  var statusFromWriteHead = null;
  res.writeHead = function (s) {
    statusFromWriteHead = s;
    return origWriteHead.apply(res, arguments);
  };
  res.end = function () {
    var status = statusFromWriteHead != null
                   ? statusFromWriteHead
                   : (typeof res.statusCode === "number" ? res.statusCode : 200);
    try { onEnd(status); }
    catch (_e) { /* onEnd never breaks the response — caller's instrumentation issue */ }
    return origEnd.apply(res, arguments);
  };
  return origEnd;
}

module.exports = {
  resolveRoute:          resolveRoute,
  captureResponseStatus: captureResponseStatus,
  extractActorContext:   extractActorContext,
};
