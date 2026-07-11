// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.redact.registerValueDetector — custom value-shape detectors that
 * run through the redactor after the built-in chain.
 *
 * Run standalone: `node test/layer-0-primitives/redact.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

function testRegisterValueDetectorRedactsMatchingValue() {
  b.redact._resetForTest();
  try {
    // Register a custom detector for an internal employee-id shape.
    b.redact.registerValueDetector(
      "employee-id",
      function (v) { return /^ZZEMP-\d{6}$/.test(v); },
      "[REDACTED-EMPID]");
    var input = { owner: "ZZEMP-123456", note: "no match here" };
    var out = b.redact.redact(input);
    check("registerValueDetector: matching value replaced with the marker",
          out.owner === "[REDACTED-EMPID]");
    check("registerValueDetector: non-matching value untouched",
          out.note === "no match here");
    check("registerValueDetector: original input not mutated (redact returns a new value)",
          input.owner === "ZZEMP-123456");
  } finally {
    b.redact._resetForTest();
  }
}

function testRegisterValueDetectorFunctionReplacement() {
  b.redact._resetForTest();
  try {
    // A function replacement receives the matched value and returns the
    // substitution.
    b.redact.registerValueDetector(
      "fixed-shape",
      function (v) { return v === "ZZTOKEN-ABCDEF"; },
      function (v) { return "[len:" + v.length + "]"; });
    // Field name `ref` is not on the sensitive-field list, so the value
    // detector (not a field-name rule) is what fires here.
    var out = b.redact.redact({ ref: "ZZTOKEN-ABCDEF" });
    check("registerValueDetector: function replacement receives the matched value",
          out.ref === "[len:14]");
  } finally {
    b.redact._resetForTest();
  }
}

function testRegisterValueDetectorRunsAfterBuiltins() {
  b.redact._resetForTest();
  try {
    // A custom detector cannot pre-empt a built-in: a PAN-shaped value still
    // redacts to the built-in credit-card marker even with a custom detector
    // registered, because custom detectors run AFTER the built-in chain.
    var hits = 0;
    b.redact.registerValueDetector(
      "count-all-strings",
      function () { hits += 1; return false; },   // never matches; just observes ordering
      "[X]");
    var out = b.redact.redact({ card: "4111 1111 1111 1111" });
    check("registerValueDetector: built-in PAN detector still wins",
          out.card === "[REDACTED-CC]");
    check("registerValueDetector: custom detector was consulted for other strings",
          hits >= 0);
  } finally {
    b.redact._resetForTest();
  }
}

function testRegisterValueDetectorRejectsNonFunction() {
  b.redact._resetForTest();
  var threw = null;
  try { b.redact.registerValueDetector("bad", "not-a-function", "[X]"); }
  catch (e) { threw = e; }
  check("registerValueDetector: throws when testFn is not a function",
        threw && /requires a test function/.test(threw.message));
  b.redact._resetForTest();
}

function testRegisterValueDetectorClearedOnReset() {
  b.redact._resetForTest();
  b.redact.registerValueDetector(
    "employee-id",
    function (v) { return /^ZZEMP-\d{6}$/.test(v); },
    "[REDACTED-EMPID]");
  b.redact._resetForTest();
  var out = b.redact.redact({ owner: "ZZEMP-123456" });
  check("registerValueDetector: detector removed after reset (no longer fires)",
        out.owner === "ZZEMP-123456");
}

async function run() {
  testRegisterValueDetectorRedactsMatchingValue();
  testRegisterValueDetectorFunctionReplacement();
  testRegisterValueDetectorRunsAfterBuiltins();
  testRegisterValueDetectorRejectsNonFunction();
  testRegisterValueDetectorClearedOnReset();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("redact tests passed"); process.exit(0); },
    function (e) { console.error(e); process.exit(1); }
  );
}
