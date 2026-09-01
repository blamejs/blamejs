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

// Both curves are sized so the LARGE reading clears the helper's 25ms floor
// and nothing else: what is under test is the measurement, not any particular
// implementation's speed, so a production-scale input would only spend CPU.
// Small 10ms, large 40ms linear and 160ms quadratic.
var SMALL = 1000;
var LARGE = 4000;

// 4x the input for 4x the time.
function _linear(n) { _spin(n / 100); }
// 4x the input for 16x the time.
function _quadratic(n) { var k = n / SMALL; _spin(k * k * 10); }

// Two samples is enough for a spin loop, which has no variance worth averaging
// away. The point of the second pass is that the verdict is RE-TAKEN, and that
// happens at any rep count.
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
