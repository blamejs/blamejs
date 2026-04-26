"use strict";
/**
 * blamejs — public API entry point.
 *
 * The Node framework that owns its stack.
 *
 * v0.0.1 (Phase 0 — foundation): exposes envelope-versioned PQC crypto
 * primitives, a zero-dependency HTTP router, and framework constants. No
 * runtime dependencies; all crypto either uses node:crypto natively or
 * vendored bundles under lib/vendor/.
 *
 * See LICENSE (Apache-2.0) and NOTICE for vendored attribution.
 * See ROADMAP (in `.claude/memory/specs/blamejs-roadmap.md`) for what
 * each subsequent phase adds to this surface.
 */

var crypto = require("./lib/crypto");
var router = require("./lib/router");
var constants = require("./lib/constants");

module.exports = {
  crypto:     crypto,
  router:     router,
  constants:  constants,
  version:    constants.version,
};
