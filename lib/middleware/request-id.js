"use strict";
/**
 * Request-ID middleware. Propagates an existing X-Request-Id header (or
 * trace ID from upstream) when present and well-formed; otherwise
 * generates a fresh 32-hex value. Sets req.requestId AND emits the same
 * value as a response header so downstream services + auditors can
 * correlate.
 *
 * Threading the request ID into audit.record() metadata is what makes
 * the cross-event correlation traceable; apps should pass this through
 * to every audit.record() they call within the request lifecycle.
 *
 * Options:
 *   {
 *     headerName:    'X-Request-Id'
 *     trustUpstream: true         // propagate upstream id if it matches
 *                                 //   the format check; false → always
 *                                 //   generate fresh
 *     formatRegex:   /^[A-Za-z0-9._-]{8,128}$/
 *   }
 */
var { generateToken } = require("../crypto");
var validateOpts = require("../validate-opts");

var DEFAULT_FORMAT = /^[A-Za-z0-9._-]{8,128}$/;

function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "headerName", "trustUpstream", "formatRegex",
  ], "middleware.requestId");
  var headerName = (opts.headerName || "X-Request-Id");
  var headerNameLower = headerName.toLowerCase();
  var trustUpstream = opts.trustUpstream !== false;
  var format = opts.formatRegex || DEFAULT_FORMAT;

  return function requestId(req, res, next) {
    var inbound = req.headers && req.headers[headerNameLower];
    var id;
    if (trustUpstream && inbound && format.test(inbound)) {
      id = inbound;
    } else {
      id = generateToken(16);  // 32 hex chars
    }
    req.requestId = id;
    if (typeof res.setHeader === "function") {
      res.setHeader(headerName, id);
    }
    next();
  };
}

module.exports = { create: create };
