// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Shared assertion for a guard's policy vocabulary.
 *
 * Every `*Policy` opt is a config-time entry point, so a value outside its
 * vocabulary belongs at boot rather than at the first hostile input. The
 * failure it guards against is quiet: policies are read leniently, so a typo
 * takes whichever branch is not the strict one. `duplicateKeyPolicy: "rejct"`
 * is not "allow", so the check still runs, and it is not "reject" either, so
 * the finding drops from critical to warn — the operator asked to refuse a
 * duplicate key and silently got an audit line.
 *
 * The check has to reach all three doors. `resolveOpts` is where the
 * validation lives, but an operator arrives through `gate` and `validate` too,
 * and a guard that resolves in only some of them leaves the others open.
 *
 * The character policies (bidi / control / nullByte / zeroWidth / tags) belong
 * to no single guard: they are derived for the whole family from the profile
 * defaults, so a caller listing them here would shadow that derivation with a
 * narrower copy. Pass the guard's own policies only.
 */

// Guards build their tables with `b.gateContract.policyVocabulary(names,
// values, overrides)`; this asserts the result holds at every door.
var _check = require("./check");

/**
 * @param {object} guard  the guard namespace (b.guardJson, b.guardSvg, ...)
 * @param {object} legal  { policyName: [ ...every value the guard accepts ] }
 * @param {object} opts
 *   label:  string  — guard name for the check text (default guard.NAME)
 *   sample: any     — an input `validate` accepts (default a benign string)
 */
function assertPolicyVocabulary(guard, legal, opts) {
  opts = opts || {};
  var label  = opts.label || (guard && guard.NAME) || "guard";
  var sample = Object.prototype.hasOwnProperty.call(opts, "sample") ? opts.sample : "x";
  var BOGUS  = "definitely-not-a-policy-value";

  var accepted = [], refusedLegal = [];
  Object.keys(legal).forEach(function (key) {
    var bad = {};
    bad[key] = BOGUS;
    var doors = [
      ["resolveOpts", function () { guard.resolveOpts(bad); }],
      ["gate",        function () { guard.gate(bad); }],
      ["validate",    function () { guard.validate(sample, bad); }],
    ];
    doors.forEach(function (door) {
      var threw = false;
      try { door[1](); } catch (_e) { threw = true; }
      if (!threw) accepted.push(key + " via " + door[0]);
    });
    legal[key].forEach(function (value) {
      var ok = {};
      ok[key] = value;
      try { guard.resolveOpts(ok); }
      catch (_e2) { refusedLegal.push(key + "=" + JSON.stringify(value)); }
    });
  });

  _check.check(label + ": a policy value outside the vocabulary is refused at every door" +
    (accepted.length ? " (accepted on " + accepted.slice(0, 6).join(", ") + ")" : ""),
    accepted.length === 0);
  _check.check(label + ": and every documented value is still accepted" +
    (refusedLegal.length ? " (refused " + refusedLegal.join(", ") + ")" : ""),
    refusedLegal.length === 0);
}

module.exports = { assertPolicyVocabulary: assertPolicyVocabulary };
