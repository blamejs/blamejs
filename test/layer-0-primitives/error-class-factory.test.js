// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Every framework error class carries its code in .code when a shared
 * validator builds it.
 *
 * Two constructor conventions exist: the classes b.frameworkError.defineClass
 * generates take (code, message), and seventeen hand-written subclasses of
 * FrameworkError take (message, code). The shared validators in
 * b.validateOpts and b.numericBounds build the caller's class for it, so a
 * class of the second kind came back with the message in .code and the code
 * in .message, and an operator matching on err.code matched nothing.
 * FrameworkError.factory(code, message) is the one construction both kinds
 * answer, and both validators go through it.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

var frameworkError = require("../../lib/framework-error");
var numericBounds  = require("../../lib/numeric-bounds");
var validateOpts   = require("../../lib/validate-opts");

function _errorClasses() {
  var found = [];
  var seen = new Set();
  Object.keys(b).forEach(function (ns) {
    var value = b[ns];
    if (!value || (typeof value !== "object" && typeof value !== "function")) return;
    var keys;
    try { keys = Object.keys(value); } catch (_e) { return; }
    keys.forEach(function (k) {
      if (!/Error$/.test(k)) return;
      var cls = value[k];
      if (typeof cls !== "function" || seen.has(cls)) return;
      if (!(cls.prototype instanceof frameworkError.FrameworkError)) return;
      seen.add(cls);
      found.push({ name: ns + "." + k, cls: cls });
    });
  });
  return found;
}

function testEveryErrorClassBuiltByAValidatorCarriesItsCode() {
  var classes = _errorClasses();
  check("the sweep found framework error classes to check", classes.length >= 20, classes.length);

  // NotLeaderError states one condition and hardcodes its code, so it
  // cannot carry a caller's. No primitive hands it to a validator.
  var FIXED_CODE = { "cluster.NotLeaderError": "cluster/not-leader" };

  var wrong = [];
  classes.forEach(function (row) {
    if (FIXED_CODE[row.name] !== undefined) {
      var fixed = null;
      try {
        validateOpts.requireNonEmptyString(undefined, "probe.opt", row.cls, "probe/bad-opt");
      } catch (e) { fixed = e; }
      if (!fixed || fixed.code !== FIXED_CODE[row.name]) {
        wrong.push(row.name + ": expected the fixed code " + FIXED_CODE[row.name] +
          ", got " + (fixed && fixed.code));
      }
      return;
    }
    // requireNonEmptyString and requirePositiveFiniteInt are the two shared
    // validators every primitive reaches for; both build the caller's class.
    var built = null;
    try {
      validateOpts.requireNonEmptyString(undefined, "probe.opt", row.cls, "probe/bad-opt");
    } catch (e) { built = e; }
    if (!built) { wrong.push(row.name + ": requireNonEmptyString did not throw"); return; }
    if (built.code !== "probe/bad-opt") {
      wrong.push(row.name + ": code is " + JSON.stringify(built.code));
      return;
    }
    if (typeof built.message !== "string" || built.message.indexOf("probe.opt") === -1) {
      wrong.push(row.name + ": message is " + JSON.stringify(built.message));
      return;
    }
    var builtNum = null;
    try {
      numericBounds.requirePositiveFiniteInt(0, "probe.count", row.cls, "probe/bad-count");
    } catch (e) { builtNum = e; }
    if (!builtNum) { wrong.push(row.name + ": requirePositiveFiniteInt did not throw"); return; }
    if (builtNum.code !== "probe/bad-count") {
      wrong.push(row.name + ": numeric code is " + JSON.stringify(builtNum.code));
    }
    if (typeof builtNum.message !== "string" || builtNum.message.indexOf("probe.count") === -1) {
      wrong.push(row.name + ": numeric message is " + JSON.stringify(builtNum.message));
    }
  });

  check("every framework error class built by a shared validator carries the code in .code" +
        (wrong.length ? " (" + wrong.slice(0, 8).join("; ") +
          (wrong.length > 8 ? "; +" + (wrong.length - 8) + " more" : "") + ")" : ""),
        wrong.length === 0);
}

function testTheBaseFactoryTakesCodeFirst() {
  // messageFirstFactory is what a class whose constructor reads
  // (message, code) attaches so every caller can build it code-first.
  var Probe = class extends frameworkError.FrameworkError {
    constructor(message, code) { super(message); this.code = code || "probe/none"; }
  };
  frameworkError.messageFirstFactory(Probe);
  var e = Probe.factory("probe/code", "probe message");
  check("a message-first class builds with the code in .code", e.code === "probe/code", e.code);
  check("a message-first class builds with the message in .message",
        e.message === "probe message", e.message);
  var built = b.atomicFile.AtomicFileError.factory("atomic-file/probe", "probe message");
  check("a hand-written subclass builds through the inherited factory",
        built instanceof b.atomicFile.AtomicFileError && built.code === "atomic-file/probe" &&
        built.message === "probe message", built.code + " / " + built.message);
}

function run() {
  testTheBaseFactoryTakesCodeFirst();
  testEveryErrorClassBuiltByAValidatorCarriesItsCode();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(function () { console.log("OK"); })
    .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
