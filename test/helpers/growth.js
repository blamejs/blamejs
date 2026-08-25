// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Measuring whether work grows superlinearly with input size.
 *
 * Several suites assert that a scan does not blow up on a hostile input, and
 * each had grown its own copy of the same measurement: best-of-N timing, a
 * noise floor below which the answer is already "fast enough", and a ratio
 * between two sizes. Three copies of a measurement are three places for the
 * flake threshold to drift apart, and they did — the copies disagreed on reps,
 * on the floor, and on whether a single reading could fail the build.
 *
 * The property that makes this measurable at all: **contention adds time and
 * never subtracts it**, so the minimum of several runs is the reading closest
 * to the work actually done. And a real curve REPRODUCES while contention does
 * not, which is why a verdict here is re-measured before it fails anything.
 */

// Minimum milliseconds across `reps` runs of `fn`. A thrown error is a fine
// answer — a refusal is a legitimate result for a hostile input; what this is
// looking for is time, and a hang shows up as time either way.
function bestMs(fn, reps) {
  var lowest = Infinity;
  for (var i = 0; i < (reps || 3); i += 1) {
    var t0 = process.hrtime.bigint();
    try { fn(); } catch (_e) { /* a refusal is an answer; a hang is not */ }
    var ms = Number(process.hrtime.bigint() - t0) / 1e6;
    if (ms < lowest) lowest = ms;
  }
  return lowest;
}

/**
 * Does the work grow faster than `threshold` between two input sizes?
 *
 *   run          function (x) — do the work once at that point on the varying
 *                dimension. Usually an input SIZE, but the dimension is
 *                whatever the claim is about: a wildcard COUNT, a nesting
 *                DEPTH, or which of two inputs to classify. The arithmetic is
 *                the same and so is the reason for re-measuring.
 *   opts.small   the baseline point
 *   opts.large   the point being judged (conventionally 2x small when it is a
 *                size, but nothing requires that)
 *   opts.threshold   ratio above which growth counts as superlinear (default 3
 *                    — linear doubles, quadratic quadruples, so 3 separates
 *                    them with room on both sides)
 *   opts.floorMs several implementations finish so far inside the floor that
 *                the shape is already ruled out; below it, no ratio is taken.
 *                Default 25ms. A quadratic scan at the sizes these tests use
 *                takes seconds, so finishing in 25ms IS the answer.
 *   opts.reps        samples per size for the first look (default 3)
 *   opts.confirmReps samples per size when confirming (default 9)
 *
 * Returns true only when the growth reproduces on a second, longer measurement.
 * A contended runner preempted between two samples reads superlinear on an
 * implementation that is not; a real curve reads superlinear every time.
 */
function looksSuperlinear(run, opts) {
  opts = opts || {};
  var threshold = opts.threshold === undefined ? 3 : opts.threshold;
  var floorMs   = opts.floorMs === undefined ? 25 : opts.floorMs;
  var reps      = opts.reps || 3;
  var confirm   = opts.confirmReps || 9;

  function ratio(n) {
    var large = bestMs(function () { run(opts.large); }, n);
    if (large < floorMs) return null;                 // fast enough to rule out
    var small = bestMs(function () { run(opts.small); }, n);
    return large / Math.max(small, 0.05);             // 0.05ms: timer floor
  }

  var first = ratio(reps);
  if (first === null || first <= threshold) return false;
  // Looks superlinear. Confirm before failing anything.
  var second = ratio(confirm);
  return second !== null && second > threshold;
}

module.exports = {
  bestMs:           bestMs,
  looksSuperlinear: looksSuperlinear,
};
