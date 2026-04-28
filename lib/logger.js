"use strict";
/**
 * Per-module log channel — `[blamejs:<name>] ` prefix on every line.
 *
 * **Deprecated alias.** The boot/operational chatter primitive moved
 * into `lib/log.js` as `log.boot(name)` so the framework has a single
 * logging module instead of two. This file remains as a thin forward
 * to the new location for backwards compatibility and is scheduled for
 * removal — operators should migrate to `b.log.boot` at their leisure.
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
 */

var { boot } = require("./log");

function createLogger(name) {
  return boot(name);
}

module.exports = { createLogger: createLogger };
