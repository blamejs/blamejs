"use strict";
/**
 * Per-module log channel — `[blamejs:<name>] ` prefix on every line.
 *
 * **Deprecated alias.** The boot/operational chatter primitive moved
 * into `lib/log.js` as `log.boot(name)` so the framework has a single
 * logging module instead of two. This file remains as a thin forward
 * to the new location for backwards compatibility — operators get a
 * runtime deprecation warning (one-shot per name) on the first call
 * to nudge migration.
 *
 * Migration:
 *
 *   // before
 *   var { createLogger } = require("./logger");
 *   var log = createLogger("vault");
 *
 *   // after
 *   var { boot } = require("./log");
 *   var log = boot("vault");
 *
 * The returned shape is identical (callable info path + .warn /
 * .error / .prefix). The only behavioral difference: boot output is
 * now TTY-aware — when stdout is piped (production / log aggregator)
 * the line is emitted as JSON instead of a prefixed text line. In a
 * terminal the output is unchanged.
 *
 * Set BLAMEJS_DEPRECATIONS=silent if the warning is too noisy during
 * a migration window; set =error to fail-fast on first use.
 */

var { boot } = require("./log");
var deprecate = require("./deprecate");

// Internal callers of createLogger live across the framework's own
// modules — they go through this same alias so the warning fires
// uniformly. Once the framework's internal callers are migrated to
// `boot` directly (a sweep tracked separately), this file can be
// deleted in the next minor.
function _createLogger(name) {
  return boot(name);
}

var createLogger = deprecate.wrap(_createLogger, "b.logger.createLogger", {
  since:    "0.2.4",
  removeIn: "0.4.0",
  hint:     "Replace with: var { boot } = require('blamejs').log; var log = boot(name);",
});

module.exports = { createLogger: createLogger };
