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
};
