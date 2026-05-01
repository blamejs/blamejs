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
module.exports = {
  requestId:       require("./request-id").create,
  securityHeaders: require("./security-headers").create,
  errorHandler:    require("./error-handler").create,
  botGuard:        require("./bot-guard").create,
  cors:            require("./cors").create,
  rateLimit:       require("./rate-limit").create,
  attachUser:      require("./attach-user").create,
  requireAuth:     require("./require-auth").create,
  csrfProtect:     require("./csrf-protect").create,
  bodyParser:      require("./body-parser").create,
  health:          require("./health").create,
  compression:     require("./compression").create,
  cspNonce:        require("./csp-nonce").create,
  sse:             require("./sse").create,
  apiEncrypt:      require("./api-encrypt"),

  // Module exports for advanced use (constants, raw factory access)
  _modules: {
    requestId:       require("./request-id"),
    securityHeaders: require("./security-headers"),
    errorHandler:    require("./error-handler"),
    botGuard:        require("./bot-guard"),
    cors:            require("./cors"),
    rateLimit:       require("./rate-limit"),
    attachUser:      require("./attach-user"),
    requireAuth:     require("./require-auth"),
    csrfProtect:     require("./csrf-protect"),
    bodyParser:      require("./body-parser"),
    health:          require("./health"),
    compression:     require("./compression"),
    cspNonce:        require("./csp-nonce"),
    sse:             require("./sse"),
    apiEncrypt:      require("./api-encrypt"),
  },
};
