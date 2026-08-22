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

async function testAThrowDuringPollingIsNotTheReason() {
  // Threw while polling, answered when asked at the deadline. Reporting the
  // old exception sends the reader after something the predicate has stopped
  // doing.
  //
  // Deterministic by construction rather than by timing: the LAST call answers,
  // whenever that happens to be. An earlier version keyed the switch on elapsed
  // time so the clean answer would land specifically after the deadline, which
  // is not something a wall clock can be made to promise — under preemption the
  // switch could fall inside the loop instead, and the case would pass without
  // exercising what it names. What actually has to hold is simpler: a throw
  // that is not the last thing the predicate did must not be reported.
  var calls = 0;
  var msg = await timeoutMessageOf(function () {
    calls += 1;
    if (calls === 1) throw new Error("a transient blow-up");
    return false;
  });
  check("the predicate was polled more than once", calls > 1);
  check("a throw that is not the last thing the predicate did is not reported",
    msg !== null && !/a transient blow-up/.test(msg));
}

async function testAThrowAtTheDeadlineIsTheReason() {
  // The other side of the same rule, and the one that keeps the case above from
  // passing for the wrong reason: a predicate still throwing when the wait gives
  // up IS reported. Without this, a helper that simply never mentioned an
  // exception would satisfy the test above.
  var msg = await timeoutMessageOf(function () {
    throw new Error("still broken at the deadline");
  });
  check("a predicate still throwing at the deadline is named",
    msg !== null && /still broken at the deadline/.test(msg));
}

async function run() {
  await testPlainTimeoutSaysNothingAboutThrowing();
  await testAThrowIsNamed();
  await testAFalsyThrowIsStillAThrow();
  await testAThrowDuringPollingIsNotTheReason();
  await testAThrowAtTheDeadlineIsTheReason();

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
