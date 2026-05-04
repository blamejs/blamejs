"use strict";
/**
 * HTTP middleware — request-lifecycle hardening primitives.
 *
 * Exposed as b.middleware.{requestId, securityHeaders, errorHandler,
 * botGuard, cors, rateLimit}. Each export is a `create(opts)` factory
 * that returns a 3-arg `(req, res, next)` middleware function compatible
 * with the framework's Router.
 *
 * Recommended mount order:
 *   1. requestId        — every later middleware should be able to log requestId
 *   2. securityHeaders  — set headers before any response could be partially sent
 *   3. cors             — handle preflights before deeper logic
 *   4. botGuard         — cheap rejection of obviously-bot traffic
 *   5. rateLimit        — slow down anything still here
 *   6. (your auth + business middleware + routes)
 *   7. errorHandler     — must be LAST so it catches everything that throws
 */
var apiEncrypt = require("./api-encrypt");
var attachUser = require("./attach-user");
var bodyParser = require("./body-parser");
var botGuard = require("./bot-guard");
var compression = require("./compression");
var cors = require("./cors");
var cspNonce = require("./csp-nonce");
var csrfProtect = require("./csrf-protect");
var dbRoleFor = require("./db-role-for");
var errorHandler = require("./error-handler");
var health = require("./health");
var networkAllowlist = require("./network-allowlist");
var rateLimit = require("./rate-limit");
var requestId = require("./request-id");
var requestLog = require("./request-log");
var requireAuth = require("./require-auth");
var securityHeaders = require("./security-headers");
var sse = require("./sse");

module.exports = {
  requestId:        requestId.create,
  securityHeaders:  securityHeaders.create,
  errorHandler:     errorHandler.create,
  botGuard:         botGuard.create,
  cors:             cors.create,
  rateLimit:        rateLimit.create,
  attachUser:       attachUser.create,
  requireAuth:      requireAuth.create,
  csrfProtect:      csrfProtect.create,
  bodyParser:       bodyParser.create,
  health:           health.create,
  compression:      compression.create,
  cspNonce:         cspNonce.create,
  sse:              sse.create,
  requestLog:       requestLog.create,
  apiEncrypt:       apiEncrypt,
  dbRoleFor:        dbRoleFor.create,
  networkAllowlist: networkAllowlist.create,

  // Module exports for advanced use (constants, raw factory access)
  _modules: {
    requestId:        requestId,
    securityHeaders:  securityHeaders,
    errorHandler:     errorHandler,
    botGuard:         botGuard,
    cors:             cors,
    rateLimit:        rateLimit,
    attachUser:       attachUser,
    requireAuth:      requireAuth,
    csrfProtect:      csrfProtect,
    bodyParser:       bodyParser,
    health:           health,
    compression:      compression,
    cspNonce:         cspNonce,
    sse:              sse,
    requestLog:       requestLog,
    apiEncrypt:       apiEncrypt,
    dbRoleFor:        dbRoleFor,
    networkAllowlist: networkAllowlist,
  },
};
