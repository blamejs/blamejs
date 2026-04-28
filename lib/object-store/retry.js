"use strict";
/**
 * Thin re-export of the top-level `lib/retry.js` primitive.
 *
 * The retry + circuit breaker primitive used to live here for historical
 * reasons (it was built alongside the object-store dispatcher). It graduated
 * to a top-level primitive in v0.2.24 so other framework consumers (queue,
 * external-db, log-stream-webhook, atomic-file, handlers) and operator code
 * via `b.retry` share one canonical implementation.
 *
 * This module is preserved as a re-export so existing internal requires
 * keep working without churn.
 */

module.exports = require("../retry");
