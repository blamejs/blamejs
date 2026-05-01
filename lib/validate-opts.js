"use strict";
/**
 * validate-opts — shared call-site helper for primitive create() functions
 * that throws on unknown / bad-shape opts at config time.
 *
 * Catches silent operator typos: `cors({ allowedOrigins: [] })` (wrong
 * key name) currently looks like config but does nothing — the primitive
 * sees opts.origins as undefined and falls back to defaults. With this
 * helper the create() throws at boot with a clear message instead of
 * the typo silently weakening the operator's setup.
 *
 *   var validateOpts = require("./validate-opts");
 *
 *   function create(opts) {
 *     opts = opts || {};
 *     validateOpts(opts, [
 *       "origins", "siteOrigin", "methods", "headers",
 *       "exposeHeaders", "credentials", "maxAgeSeconds", "refuseUnknown",
 *     ], "middleware.cors");
 *     ...
 *   }
 *
 * The exported `optional(...)` form lets a primitive accept a
 * sparsely-populated opts object and only validate keys that ARE present.
 *
 * Throws a plain Error with a code-shaped message — primitives that want
 * a typed error wrap the call.
 */

function _format(primitive, unknownKey, allowedKeys) {
  return primitive + ": unknown option '" + unknownKey + "'. " +
    "Allowed keys: " + allowedKeys.slice().sort().join(", ") + ".";
}

function check(opts, allowedKeys, primitive) {
  if (opts == null) return;
  if (typeof opts !== "object") {
    throw new Error(primitive + ": opts must be an object (got " + typeof opts + ")");
  }
  if (!Array.isArray(allowedKeys) || allowedKeys.length === 0) {
    throw new Error("validate-opts: allowedKeys must be a non-empty array");
  }
  if (typeof primitive !== "string" || primitive.length === 0) {
    throw new Error("validate-opts: primitive name must be a non-empty string");
  }
  var allowSet = Object.create(null);
  for (var i = 0; i < allowedKeys.length; i++) allowSet[allowedKeys[i]] = true;
  var keys = Object.keys(opts);
  for (var j = 0; j < keys.length; j++) {
    if (!allowSet[keys[j]]) {
      throw new Error(_format(primitive, keys[j], allowedKeys));
    }
  }
}

module.exports = check;
module.exports.check = check;
