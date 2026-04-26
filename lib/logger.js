"use strict";
/**
 * Per-module log channel — `[blamejs:<name>] ` prefix on every line.
 *
 * Centralizes the pattern used by 4+ framework modules:
 *
 *   function log(msg)    { console.log("[blamejs:db] " + msg); }
 *   function logErr(msg) { console.error("[blamejs:db] " + msg); }
 *
 * `createLogger(name)` returns a callable `log` whose default invocation
 * is the info path (matches existing `log(msg)` call sites mechanically),
 * with `.warn(msg)` and `.error(msg)` methods for stderr-bound severity.
 *
 * Usage:
 *
 *   var { createLogger } = require("./logger");
 *   var log = createLogger("vault");
 *
 *   log("unsealing vault.key.sealed...");      // [blamejs:vault] unsealing ...
 *   log.warn("plaintext mode — unprotected");  // stderr
 *   log.error("FATAL: cannot read sealed");    // stderr
 *
 * Output goes to stdout (info) or stderr (warn/error). The framework
 * deliberately uses console.{log,error} rather than process.stdout/err
 * directly so test runners that capture console output behave as
 * operators expect.
 *
 * The destructure-import shape (`{ createLogger }`) avoids local-var
 * shadow conflicts with `var logger` instances per the lib-naming
 * convention's import-name rule.
 */

function createLogger(name) {
  if (typeof name !== "string" || name.length === 0) {
    throw new Error("createLogger(name) requires a non-empty name");
  }
  var prefix = "[blamejs:" + name + "] ";

  function info(msg)  { console.log(prefix + msg); }
  function warn(msg)  { console.error(prefix + msg); }
  function error(msg) { console.error(prefix + msg); }

  // The returned function is the info path so `log(msg)` matches the
  // existing log() shape mechanically across the sweep.
  info.info  = info;
  info.warn  = warn;
  info.error = error;
  // Expose the prefix so callers building multi-line console output
  // (e.g. console.warn(prefix + line1 + "\n" + prefix + line2)) don't
  // re-derive it.
  info.prefix = prefix;
  return info;
}

module.exports = { createLogger: createLogger };
