// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Tests for helpers.waitUntil's TIMEOUT DIAGNOSTIC (test/helpers/wait.js).
 *
 * Whether it eventually returns is exercised by every suite that polls. What
 * nothing exercised is the message it throws when it does not — and that
 * message is the entire value of a timeout, since "the condition never came
 * true" and "the condition could not be evaluated" send a reader to different
 * places.
 */

var helpers = require("../helpers");

var failed = 0;
var passed = 0;
function check(label, condition) {
  if (condition) { passed += 1; return; }
  failed += 1;
  console.error("  FAIL: " + label);
}

async function timeoutMessageOf(predicate) {
  try {
    await helpers.waitUntil(predicate, { timeoutMs: 60, intervalMs: 10, label: "wait-self-test" });
  } catch (e) { return (e && e.message) || String(e); }
  return null;
}

async function testPlainTimeoutSaysNothingAboutThrowing() {
  var msg = await timeoutMessageOf(function () { return false; });
  check("a condition that never comes true times out", msg !== null);
  check("and the message does not invent a throw",
    msg !== null && !/last predicate threw/.test(msg));
}

async function testAThrowIsNamed() {
  var msg = await timeoutMessageOf(function () { throw new Error("the predicate blew up"); });
  check("a throwing predicate is named in the timeout",
    msg !== null && /the predicate blew up/.test(msg));
}

async function testAFalsyThrowIsStillAThrow() {
  // `if (lastError)` asked whether the thrown value was truthy, so a predicate
  // that threw null reported as one that simply never came true.
  // eslint-disable-next-line no-throw-literal -- throwing a non-Error IS the case under test
  var msg = await timeoutMessageOf(function () { throw null; });
  check("a falsy throw is still reported as a throw",
    msg !== null && /last predicate threw/.test(msg));
}

async function testAThrowThatStoppedIsNotReportedAsTheReason() {
  // Threw throughout the polling loop, then answered cleanly. Reporting the old
  // exception as "last predicate threw" sends the reader after something the
  // predicate has stopped doing.
  //
  // Timed rather than counted, deliberately: it has to be the FINAL attempt
  // after the deadline that answers, because the loop already clears the state
  // on every answer and a count-based fixture only ever exercises that path —
  // it passes whether or not the final attempt clears anything.
  var start = Date.now();
  var calls = 0;
  var answeredAfterDeadline = false;
  var msg = await timeoutMessageOf(function () {
    calls += 1;
    if (Date.now() < start + 60) throw new Error("a transient blow-up");
    answeredAfterDeadline = true;
    return false;
  });
  check("the predicate threw during the loop and answered after it",
    calls > 1 && answeredAfterDeadline === true);
  check("a throw that stopped is not reported as the reason for the timeout",
    msg !== null && !/a transient blow-up/.test(msg));
}

async function run() {
  await testPlainTimeoutSaysNothingAboutThrowing();
  await testAThrowIsNamed();
  await testAFalsyThrowIsStillAThrow();
  await testAThrowThatStoppedIsNotReportedAsTheReason();

  if (failed > 0) {
    console.error("\n" + failed + " check(s) FAILED, " + passed + " passed");
    process.exit(1);
  }
  console.log("OK — " + passed + " checks passed");
}

if (require.main === module) {
  run().catch(function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); });
}
module.exports = { run: run };
