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
 *
 * SMOKE_RUN_SOLO. A spin loop reads the wall clock, so a descheduled process
 * resumes past its deadline and the reading carries however long it was away.
 * That overshoot is additive, and against a 50ms baseline it compresses the
 * ratio: measured in a cold process against a saturated box, a quadratic
 * curve's ratio of 16 came back between 4 and 6, and the verdict was false on
 * 2 runs in 10. The suites that call the helper on real work hold up under the
 * same load, because their baselines are seconds rather than milliseconds.
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
// scheduler's noise rather than as small as the floor allows. A true ratio of
// 16 survives an overshoot of d only while (16S + d) / (S + d) stays above the
// threshold of 9, which rearranges to 7S > 8d, so d must stay under 0.875 of
// the small reading. At 50ms that is 44ms. A box running more processes than
// it has cores exceeds that, which is what the solo marker above answers.
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

// A ratio divides a reading at the large size by a reading at the small one.
// Taken in two blocks -- every large sample, then every small one -- the two
// occupy different windows, so a load that is heavy during the first and light
// during the second is carried into the ratio as if it were growth. That is
// what failed a release gate: a folded DKIM tag scanned linearly measured
// 10.05x for 4x the input, under 64-way parallelism against the docker stack,
// and re-measuring did not rule it out because the load was sustained across
// both attempts.
//
// Modelled here without a real load: the overhead is heavy for the first two
// calls of every group of four and absent for the next two. Read in two blocks
// at two reps, that is exactly heavy for both large samples and absent for both
// small ones, and it repeats on the confirming pass, so re-measuring returns
// the same wrong answer. Sustained load is what the note above records
// defeating re-measurement. Interleaved, one large and one small sample fall
// in each half, and the pair from the quiet half is the pair the minimum keeps.
function _loadOnTheFirstHalfOfEachGroup(heavyMs) {
  var seen = 0;
  return function (n) {
    var extra = (seen % 4) < 2 ? heavyMs : 0;
    seen += 1;
    _spin(n / 20 + extra);                            // linear work plus the load
  };
}

function testALoadExcursionIsNotReadAsGrowth() {
  // Linear work: 200ms at the large size, 50ms at the small, a true ratio of 4.
  // 400ms of load on the large readings alone lifts it to 12, over the
  // threshold of 9, and lands the same way on the confirming pass.
  var verdict = growth.looksSuperlinear(_loadOnTheFirstHalfOfEachGroup(400), FAST);
  check("growth: a load that falls on one size only is not growth",
        verdict === false, "verdict=" + verdict);
}

// ...and the interleaving must not cost the true positive it exists to find.
function testInterleavingStillCatchesACurve() {
  check("growth: a quadratic curve under the same fading load is still caught",
        growth.looksSuperlinear(function (n) {
          var k = n / SMALL;
          _spin(k * k * 50);
        }, FAST) === true);
}

// The order is the fix, so it is asserted directly: a caller sees the sizes
// alternate rather than arrive in two blocks.
function testTheSizesAreInterleaved() {
  var order = [];
  growth.looksSuperlinear(function (n) { order.push(n); _spin(n / 20); }, FAST);
  var blocks = 0;
  for (var i = 1; i < order.length; i += 1) {
    if (order[i] !== order[i - 1]) blocks += 1;
  }
  check("growth: the two sizes alternate rather than arriving in blocks",
        order.length >= 4 && blocks >= order.length - 2,
        JSON.stringify(order));
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
  testALoadExcursionIsNotReadAsGrowth();
  testInterleavingStillCatchesACurve();
  testTheSizesAreInterleaved();
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
