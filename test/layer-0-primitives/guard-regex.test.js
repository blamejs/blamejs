// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.guardRegex — ReDoS screening for operator-supplied patterns. Covers the
 * nested-quantifier detector's true positives AND the linear shapes it must NOT
 * false-refuse (#432 / #429): a quantified non-capturing group (`(?:…)?`,
 * `(?:…)*`) and an OPTIONAL quantified group (`(X+)?`, `(?:X+)?`) repeat the
 * group at most once, so they are linear, not catastrophic. The catastrophic
 * class requires the OUTER quantifier to be unbounded (`*`/`+`/`{n,}`).
 *
 * Run standalone: `node test/layer-0-primitives/guard-regex.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function assertSafeAccepts(src) {
  try { b.guardRegex.assertSafe(new RegExp(src), "x"); return true; } catch (_e) { return false; }
}
function sanitizeAccepts(src) {
  try { b.guardRegex.sanitize(src); return true; } catch (_e) { return false; }
}

// ---- #432 / #429: linear shapes must be ACCEPTED (were false-refused) ----
function testLinearShapesAccepted() {
  var linear = [
    "^(?:/page/\\d+)?$",            // optional non-capturing group
    "^foo(?:bar)*$",               // quantified non-capturing group
    "^foo(?:bar)?$",
    "^(a+)?$",                     // optional quantified group — repeats 0..1
    "(?:[-+][0-9A-Za-z.-]+)?",     // optional group with inner quantifier (#429)
    "(?:[-+][0-9A-Za-z.-]{1,64})?",
    "v\\d+\\.\\d+\\.\\d+(?:[-+][0-9A-Za-z.-]+)?-linux-x64",
  ];
  linear.forEach(function (src) {
    check("assertSafe accepts linear " + JSON.stringify(src), assertSafeAccepts(src));
    check("sanitize accepts linear " + JSON.stringify(src), sanitizeAccepts(src));
  });
}

// ---- genuine nested-UNBOUNDED shapes must still be REFUSED ----
function testCatastrophicShapesRefused() {
  var bad = ["^(a+)+$", "(a+)*", "((a)+)+", "(([a-z]+)*)*", "(a+){2,}"];
  bad.forEach(function (src) {
    check("assertSafe refuses catastrophic " + JSON.stringify(src), assertSafeAccepts(src) === false);
  });
}

// ---- other ReDoS classes the guard covers stay covered ----
function testOtherClasses() {
  check("alternation-with-quantifier refused", assertSafeAccepts("^(a|b|c)+$") === false);
  check("plain linear pattern accepted", assertSafeAccepts("^[a-z0-9_-]{1,64}$"));
  check("anchored alternation without group-quantifier accepted", assertSafeAccepts("^(?:cat|dog|bird)$"));
}

function run() {
  testLinearShapesAccepted();
  testCatastrophicShapesRefused();
  testOtherClasses();
}

if (require.main === module) {
  run();
  console.log("guard-regex OK — " + helpers.getChecks() + " checks");
}

module.exports = { run: run };
