// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The shared growth measurement, tested.
 *
 * `test/helpers/growth.js` is test infrastructure rather than shipped code,
 * which is exactly why it needs this: every suite that asserts a scan does not
 * blow up on a hostile input now routes its verdict through here, so a defect
 * in the measurement is a defect in all of them AT ONCE, and it shows up as a
 * test that passes rather than one that fails.
 *
 * The work under measurement is a spin loop keyed to the size argument, so the
 * curve is known in advance and the assertions are about the measurement, not
 * about anything's performance.
 */
var helpers = require("../helpers");
var check   = helpers.check;
var growth  = require("../helpers/growth");

// Burn approximately `ms` of wall clock. A sleep would measure the timer.
function _spin(ms) {
  var t0 = process.hrtime.bigint();
  while (Number(process.hrtime.bigint() - t0) / 1e6 < ms) { /* burn */ }
}

// The SMALL reading is the denominator of the ratio, and it is sized above the
// scheduler's noise rather than as small as the floor allows. A spin loop
// checks the wall clock, so a descheduled process resumes past its deadline and
// overshoots by however long it was away -- a fixed overshoot that is a few
// percent of a 100ms reading and tens of percent of a 10ms one. At
// SMOKE_PARALLEL=64 that compressed a quadratic curve's ratio from 16 to 8.6
// and the helper correctly declined to call it superlinear, so the test failed
// while nothing it tests was wrong.
//
// The overshoot is ADDITIVE, so what matters is its size against the
// denominator. A true ratio of 16 survives an overshoot of d only while
// (16S + d) / (S + d) stays above the threshold of 9, which rearranges to
// 7S > 8d, so d must stay under 0.875 of the small reading. At 25ms that was
// 22ms of scheduler noise, and a run at SMOKE_PARALLEL=64 on a loaded box
// exceeded it. At 50ms it is 44ms, which held across six runs against six
// processes spinning on the same cores.
//
// Small 50ms, large 200ms linear and 800ms quadratic.
var SMALL = 1000;
var LARGE = 4000;

// 4x the input for 4x the time.
function _linear(n) { _spin(n / 20); }
// 4x the input for 16x the time.
function _quadratic(n) { var k = n / SMALL; _spin(k * k * 50); }

// Two samples, because the tolerance above comes from the denominator rather
// than the sample count and four of them cost four times as long for the same
// verdict. The helper keeps the lowest of the two and the second pass re-takes
// it, which is what rejects a reading the machine disturbed.
var FAST = { small: SMALL, large: LARGE, threshold: 9, reps: 2, confirmReps: 2 };

function testSyncSeparatesLinearFromQuadratic() {
  check("growth: a linear curve is not superlinear at a 4x step",
        growth.looksSuperlinear(_linear, FAST) === false);
  check("growth: a quadratic curve is superlinear at a 4x step",
        growth.looksSuperlinear(_quadratic, FAST) === true);
}

function testBelowTheFloorThereIsNoVerdict() {
  // A run that finishes far inside the floor rules the shape out on size
  // alone: a quadratic scan at a real input size would take seconds.
  check("growth: work under the floor is not judged",
        growth.looksSuperlinear(function () { _spin(0.05); }, FAST) === false);
}

async function testAsyncSeparatesLinearFromQuadratic() {
  var lin = await growth.looksSuperlinearAsync(async function (n) { _linear(n); }, FAST);
  check("growth async: a linear curve is not superlinear",
        lin.superlinear === false, JSON.stringify(lin));
  check("growth async: and it reports the ratio it measured",
        typeof lin.ratio === "number" && lin.ratio > 2 && lin.ratio < 9, JSON.stringify(lin));

  var quad = await growth.looksSuperlinearAsync(async function (n) { _quadratic(n); }, FAST);
  check("growth async: a quadratic curve is superlinear",
        quad.superlinear === true, JSON.stringify(quad));
}

// The one answer this must never give by accident. A rejected sample means the
// work did not happen -- a closed socket, a listener that died -- and swallowing
// it makes every later sample reject in about no time, which puts the large
// reading under the floor and returns "not superlinear". The regression the
// caller is guarding against would read as fast enough.
async function testARejectedSampleIsNotMeasuredAsFast() {
  var calls = 0;
  var threw = null;
  try {
    await growth.looksSuperlinearAsync(async function () {
      calls += 1;
      throw new Error("socket closed");
    }, FAST);
  } catch (e) { threw = e; }

  check("growth async: a rejected sample propagates rather than reading as fast",
        threw !== null && /socket closed/.test(threw.message), String(threw && threw.message));
  check("growth async: and it stops at the first rejection",
        calls === 1, String(calls));
}

async function run() {
  testSyncSeparatesLinearFromQuadratic();
  testBelowTheFloorThereIsNoVerdict();
  await testAsyncSeparatesLinearFromQuadratic();
  await testARejectedSampleIsNotMeasuredAsFast();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); process.exit(0); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
