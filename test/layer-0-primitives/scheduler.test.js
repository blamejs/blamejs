// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * scheduler.nextBaselineFire — earliest UTC ms strictly after `after`
 * whose wall-clock in a timezone matches an HH:MM baseline.
 *
 * Pure function: known-answer vectors (UTC + a non-UTC zone + local
 * clock), the strictly-after / next-day rollover semantics, and the
 * malformed-input throws.
 *
 * Run standalone: `node test/layer-0-primitives/scheduler.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

function _iso(ms) { return new Date(ms).toISOString(); }

function testNextBaselineFireKnownAnswerUtc() {
  var when = b.scheduler.nextBaselineFire("02:30", "UTC", new Date("2026-05-09T01:00:00Z"));
  check("nextBaselineFire UTC known-answer",
        _iso(when) === "2026-05-09T02:30:00.000Z");
}

function testNextBaselineFireStrictlyAfter() {
  // `after` sitting exactly on the target minute must roll to the NEXT day.
  var when = b.scheduler.nextBaselineFire("02:30", "UTC", new Date("2026-05-09T02:30:00.000Z"));
  check("nextBaselineFire is strictly-after (rolls a day when at target)",
        _iso(when) === "2026-05-10T02:30:00.000Z");
}

function testNextBaselineFireRollsWhenPast() {
  var when = b.scheduler.nextBaselineFire("02:30", "UTC", new Date("2026-05-09T05:00:00Z"));
  check("nextBaselineFire rolls to next day when time already passed today",
        _iso(when) === "2026-05-10T02:30:00.000Z");
}

function testNextBaselineFireNonUtcZone() {
  // America/New_York on 2026-05-09 is EDT (UTC-4): 02:30 local = 06:30 UTC.
  var when = b.scheduler.nextBaselineFire("02:30", "America/New_York", new Date("2026-05-09T00:00:00Z"));
  check("nextBaselineFire honors a non-UTC timeZone",
        _iso(when) === "2026-05-09T06:30:00.000Z");
}

function testNextBaselineFireLocalClock() {
  // null timeZone follows the server's local clock — assert the local
  // wall-clock of the result matches the requested HH:MM (TZ-independent).
  var after = new Date("2026-05-09T00:00:00Z");
  var when  = b.scheduler.nextBaselineFire("13:45", null, after);
  var d     = new Date(when);
  check("nextBaselineFire local-clock matches requested HH:MM",
        d.getHours() === 13 && d.getMinutes() === 45);
  check("nextBaselineFire local-clock result is strictly after `after`",
        when > after.getTime());
}

function testNextBaselineFireRejectsBadInput() {
  var t1 = null;
  try { b.scheduler.nextBaselineFire("2:3", "UTC", new Date()); } catch (e) { t1 = e; }
  check("nextBaselineFire rejects malformed HH:MM",
        t1 && t1.code === "scheduler/invalid-baseline");
  var t2 = null;
  try { b.scheduler.nextBaselineFire("25:00", "UTC", new Date()); } catch (e) { t2 = e; }
  check("nextBaselineFire rejects out-of-range hour",
        t2 && t2.code === "scheduler/invalid-baseline");
  var t3 = null;
  try { b.scheduler.nextBaselineFire("12:60", "UTC", new Date()); } catch (e) { t3 = e; }
  check("nextBaselineFire rejects out-of-range minute",
        t3 && t3.code === "scheduler/invalid-baseline");
}

async function run() {
  testNextBaselineFireKnownAnswerUtc();
  testNextBaselineFireStrictlyAfter();
  testNextBaselineFireRollsWhenPast();
  testNextBaselineFireNonUtcZone();
  testNextBaselineFireLocalClock();
  testNextBaselineFireRejectsBadInput();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[scheduler] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e); process.exit(1); }
  );
}
