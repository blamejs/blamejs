"use strict";
/**
 * auth.totp — auth-namespace bridge to lib/totp.js.
 *
 * The TOTP primitive itself is in lib/totp.js so it can be used for
 * non-auth time-based codes (idempotency tokens, signed-link freshness
 * windows, etc.). This file exposes the same surface under the
 * framework's `auth.*` namespace so application code reaches it via
 * the natural auth-feature path: `b.auth.totp.generateSecret()`.
 *
 * No additional logic — this is a re-export. Keeping it as a separate
 * module (rather than `auth.totp = require("../totp")`) makes the
 * dependency graph explicit and gives a place to layer auth-specific
 * defaults later (e.g. an auth-namespace-only step/algorithm policy)
 * without touching the underlying primitive.
 */
module.exports = require("../totp");
