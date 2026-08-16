// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.time — timezone-aware datetime arithmetic + formatting.
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

async function run() {
  // ---- Surface ----
  check("b.time namespace present",        typeof b.time === "object");
  check("b.time.toParts is fn",            typeof b.time.toParts === "function");
  check("b.time.format is fn",             typeof b.time.format === "function");
  check("b.time.startOfDay is fn",         typeof b.time.startOfDay === "function");
  check("b.time.endOfDay is fn",           typeof b.time.endOfDay === "function");
  check("b.time.addDays is fn",            typeof b.time.addDays === "function");
  check("b.time.addMonths is fn",          typeof b.time.addMonths === "function");
  check("b.time.diffDays is fn",           typeof b.time.diffDays === "function");
  check("b.time.parseISO is fn",           typeof b.time.parseISO === "function");
  check("b.time.tzOffsetMs is fn",         typeof b.time.tzOffsetMs === "function");

  // ---- toParts ----
  // Anchor: 2026-04-30T14:32:00Z (a Thursday).
  var anchor = new Date(Date.UTC(2026, 3, 30, 14, 32, 0));
  var pUtc = b.time.toParts(anchor);
  check("toParts UTC: year",                pUtc.year === 2026);
  check("toParts UTC: month",               pUtc.month === 4);
  check("toParts UTC: day",                 pUtc.day === 30);
  check("toParts UTC: hour",                pUtc.hour === 14);
  check("toParts UTC: minute",              pUtc.minute === 32);
  check("toParts UTC: weekday is Thursday", pUtc.weekday === 4);
  check("toParts UTC: weekdayName Thu",     pUtc.weekdayName === "Thu");

  // Same instant in America/New_York → 14:32 UTC = 10:32 EDT (DST in April)
  var pNyc = b.time.toParts(anchor, { timezone: "America/New_York" });
  check("toParts NYC: hour shifted to 10",  pNyc.hour === 10);
  check("toParts NYC: same day (April)",    pNyc.day === 30);

  // ---- format (default + dateStyle) ----
  var fDefault = b.time.format(anchor, { timezone: "UTC" });
  check("format: returns a string",          typeof fDefault === "string" && fDefault.length > 0);
  var fLong = b.time.format(anchor, { timezone: "UTC", dateStyle: "full" });
  check("format dateStyle:full mentions year",  /2026/.test(fLong));

  // ---- tzOffsetMs ----
  var offUtc = b.time.tzOffsetMs(anchor, "UTC");
  check("tzOffsetMs UTC = 0",                offUtc === 0);
  var offNyc = b.time.tzOffsetMs(anchor, "America/New_York");
  // April 30 = EDT = UTC-4 = -14400000 ms
  check("tzOffsetMs NYC EDT = -4h",          offNyc === -14400000);
  // January 30 = EST = UTC-5
  var winter = new Date(Date.UTC(2026, 0, 30, 14, 32, 0));
  var offNycWinter = b.time.tzOffsetMs(winter, "America/New_York");
  check("tzOffsetMs NYC EST = -5h",          offNycWinter === -18000000);

  // ---- startOfDay / endOfDay ----
  var sodUtc = b.time.startOfDay(anchor, { timezone: "UTC" });
  check("startOfDay UTC: midnight",         sodUtc.getUTCHours() === 0 && sodUtc.getUTCMinutes() === 0);
  check("startOfDay UTC: same calendar day",sodUtc.getUTCDate() === 30);

  var eodUtc = b.time.endOfDay(anchor, { timezone: "UTC" });
  check("endOfDay UTC: 23:59:59.999",
        eodUtc.getUTCHours() === 23 && eodUtc.getUTCMinutes() === 59 &&
        eodUtc.getUTCSeconds() === 59 && eodUtc.getUTCMilliseconds() === 999);

  var sodNyc = b.time.startOfDay(anchor, { timezone: "America/New_York" });
  // 14:32 UTC on Apr 30 → 10:32 EDT Apr 30. Start of NYC day = 04:00 UTC Apr 30.
  check("startOfDay NYC: 04:00 UTC (DST)",
        sodNyc.getUTCHours() === 4 && sodNyc.getUTCDate() === 30);

  // ---- addDays ----
  var plus1 = b.time.addDays(anchor, 1, { timezone: "UTC" });
  check("addDays +1: day+1",                 plus1.getUTCDate() === 1 && plus1.getUTCMonth() === 4);
  var minus1 = b.time.addDays(anchor, -1, { timezone: "UTC" });
  check("addDays -1: day-1",                 minus1.getUTCDate() === 29);

  // DST-safe: adding 1 day across an EDT-EST boundary preserves
  // the local wall-clock hour. America/New_York: 2026-11-01 02:00
  // EDT → EST (fall back). Pick a date around the boundary.
  var preFallBack = new Date(Date.UTC(2026, 10, 1, 2, 0, 0));   // Nov 1 02:00 UTC
  var nextDayNyc  = b.time.addDays(preFallBack, 1, { timezone: "America/New_York" });
  var pPlus = b.time.toParts(preFallBack, { timezone: "America/New_York" });
  var pNext = b.time.toParts(nextDayNyc,  { timezone: "America/New_York" });
  check("addDays DST: same wall-clock hour preserved",
        pPlus.hour === pNext.hour && pPlus.minute === pNext.minute);

  // ---- addMonths ----
  // Jan 31 + 1 month = Feb 28 (or 29 in leap year). 2026 not a leap year.
  var jan31 = new Date(Date.UTC(2026, 0, 31, 12, 0, 0));
  var feb = b.time.addMonths(jan31, 1, { timezone: "UTC" });
  check("addMonths Jan31 + 1mo = Feb 28 (clamped)",
        feb.getUTCMonth() === 1 && feb.getUTCDate() === 28);

  // ---- diffDays ----
  var d1 = new Date(Date.UTC(2026, 3, 1, 0, 0, 0));
  var d2 = new Date(Date.UTC(2026, 3, 30, 0, 0, 0));
  check("diffDays: 29 calendar days",        b.time.diffDays(d1, d2, { timezone: "UTC" }) === 29);

  // ---- parseISO ----
  var iso1 = b.time.parseISO("2026-04-30T14:32:00Z");
  check("parseISO: Z timezone parsed",       iso1.getTime() === anchor.getTime());

  var iso2 = b.time.parseISO("2026-04-30T10:32:00-04:00");
  check("parseISO: -04:00 offset parsed",    iso2.getTime() === anchor.getTime());

  var iso3 = b.time.parseISO("2026-04-30");
  check("parseISO: date-only → UTC midnight",
        iso3.getUTCFullYear() === 2026 && iso3.getUTCMonth() === 3 && iso3.getUTCDate() === 30);

  // Fractional seconds
  var iso4 = b.time.parseISO("2026-04-30T14:32:00.123Z");
  check("parseISO: fractional seconds",      iso4.getUTCMilliseconds() === 123);

  // ---- parseISO: rejects ----
  function rejects(label, fn, codeRe) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check("parseISO reject: " + label, threw && codeRe.test(threw.code || ""));
  }
  rejects("non-string",     function () { b.time.parseISO(42); }, /time\/bad-iso/);
  rejects("malformed",      function () { b.time.parseISO("not-a-date"); }, /time\/bad-iso/);
  rejects("bad month (13)", function () { b.time.parseISO("2026-13-01"); }, /time\/bad-iso/);
  rejects("bad day (32)",   function () { b.time.parseISO("2026-04-32"); }, /time\/bad-iso/);

  // ---- _toDate variants ----
  rejects("invalid Date",  function () { b.time.toParts(new Date("nope")); }, /time\/invalid-date/);
  rejects("non-finite ms", function () { b.time.toParts(Infinity); }, /time\/invalid-ms/);

  // String input flows through parseISO
  var pStr = b.time.toParts("2026-04-30T14:32:00Z", { timezone: "UTC" });
  check("toParts: ISO string input",        pStr.year === 2026 && pStr.hour === 14);

  // Number (ms) input
  var pNum = b.time.toParts(anchor.getTime(), { timezone: "UTC" });
  check("toParts: ms-epoch input",          pNum.year === 2026);

  // ---- Bad timezone ----
  rejects("bad timezone", function () {
    b.time.toParts(anchor, { timezone: "Not/A_Real_TZ" });
  }, /time\/bad-timezone-or-locale/);

  // ---- toIso8601NoMs ----
  check("b.time.toIso8601NoMs is fn", typeof b.time.toIso8601NoMs === "function");
  check("toIso8601NoMs: strips .sssZ from an ISO string",
        b.time.toIso8601NoMs("2026-05-09T14:30:00.789Z") === "2026-05-09T14:30:00Z");
  check("toIso8601NoMs: Date input → one-second-resolution Z",
        b.time.toIso8601NoMs(new Date(Date.UTC(2026, 4, 9, 14, 30, 0))) === "2026-05-09T14:30:00Z");
  check("toIso8601NoMs: ms-epoch input drops sub-second precision",
        b.time.toIso8601NoMs(Date.UTC(2026, 4, 9, 14, 30, 0, 500)) === "2026-05-09T14:30:00Z");
  check("toIso8601NoMs: an already-second-resolution string round-trips",
        b.time.toIso8601NoMs("2026-05-09T14:30:00Z") === "2026-05-09T14:30:00Z");

  testIso8601ReadersAgreeWithThePatternTheyReplaced();
}

// The ISO 8601 grammar used to be spelled as a pattern in five places, which
// agreed on the easy cases and diverged on the ones that matter. These three
// readers are the grammar; every caller supplies the policy.
function _parseIsoCode(s) {
  try { b.time.parseISO(s); return "OK"; }
  catch (e) { return e && e.code; }
}

function testIso8601ReadersAgreeWithThePatternTheyReplaced() {
  check("b.time.readDate is fn",     typeof b.time.readDate === "function");
  check("b.time.readTime is fn",     typeof b.time.readTime === "function");
  check("b.time.readDateTime is fn", typeof b.time.readDateTime === "function");

  // The pattern parseISO used to run, restated.
  var ISO_RE = /^(\d{4})-(\d{2})-(\d{2})(?:[T\s](\d{2}):(\d{2})(?::(\d{2})(?:\.(\d+))?)?(Z|[+-]\d{2}:?\d{2})?)?$/;

  var VALUES = [
    "2026-08-16", "2026-08-16T12:34:56Z", "2026-08-16 12:34:56Z",
    "2026-08-16T12:34:56", "2026-08-16T12:34:56.789Z", "2026-08-16T12:34:56+01:00",
    "2026-08-16T12:34:56+0100", "2026-08-16T12:34:56-05:30", "2026-08-16T12:34",
    "2026-08-16t12:34:56Z", "2026-08-16T12:34:56.Z", "2026-08-16T12:34:56ZZ",
    "2026-8-16", "26-08-16", "2026-08-16T", "T12:34:56Z", "", " ",
    "2026-08-16T12:34:56.123456789+01:00", "2026-08-16X12:34:56Z",
    // A time with no seconds, which ISO 8601 permits and RFC 3339 does not.
    "2026-08-16T12:34Z", "2026-08-16T12:34+01:00", "2026-08-16T12:34.5Z",
    "2026-08-16T12:3", "2026-08-16 12:34",
  ];

  // The acceptance set parseISO has always had, asserted through parseISO
  // itself rather than through the reader — the contract belongs to the
  // public function, and every option it passes exists to hold it.
  var diffs = [];
  VALUES.forEach(function (v) {
    var want = ISO_RE.test(v);
    var got = _parseIsoCode(v) === "OK";
    if (want !== got) diffs.push(JSON.stringify(v) + " pattern=" + want + " parseISO=" + got);
  });
  check("parseISO accepts exactly what the pattern it replaced accepted (" +
        VALUES.length + " values)", diffs.length === 0, diffs.slice(0, 5).join(" | "));

  // The shapes a NEW caller gets by default are stricter, because RFC 3339
  // §5.6 is stricter. Both directions are pinned: the reader refuses what the
  // spec refuses, and parseISO keeps taking what its callers already send.
  check("a seconds-less time: parseISO takes it, the reader's default does not",
        _parseIsoCode("2026-08-16T12:34Z") === "OK" &&
        b.time.readDateTime("2026-08-16T12:34Z") === null &&
        b.time.readDateTime("2026-08-16T12:34Z", { requireSeconds: false }) !== null);
  // Without seconds there is no fraction either — a fraction hangs off the
  // seconds. `readTime` is positional, so it reads `12:34` and reports that it
  // stopped at index 5; the caller decides whether the remainder is allowed,
  // and `readDateTime` (which must consume the whole string) refuses.
  var noSeconds = b.time.readTime("12:34.5Z", 0, { requireSeconds: false });
  check("without seconds there is no fraction either, as the pattern had it",
        _parseIsoCode("2026-08-16T12:34.5Z") === "time/bad-iso" &&
        noSeconds.fraction === "" && noSeconds.end === 5 &&
        b.time.readDateTime("2026-08-16T12:34.5Z", { requireSeconds: false }) === null);
  check("a seconds-less time reports an empty second rather than a wrong one",
        b.time.readTime("12:34Z", 0, { requireSeconds: false }).second === "" &&
        b.time.readTime("12:34Z", 0, { requireSeconds: false }).minute === "34");

  // RFC 3339 §5.6 permits a lower-case `z`, so the reader takes it — but a
  // caller that BRANCHES on the returned offset has to say which spellings it
  // handles. Three in this framework only ever handled `Z`; `parseISO` used to
  // fall into its numeric-offset branch on a `z` and throw an internal
  // arithmetic error with no code, which is neither a parse nor a refusal.
  check("the reader takes a lower-case z by default and refuses it on request",
        b.time.readTime("12:34:56z") !== null &&
        b.time.readTime("12:34:56z", 0, { offsetCase: "upper" }) === null);
  check("parseISO refuses a lower-case z with its own code, as it always did",
        _parseIsoCode("2026-08-16T12:34:56z") === "time/bad-iso" &&
        _parseIsoCode("2026-08-16T12:34:56Z") === "OK");

  // Fail closed: no input may leave this function as an Invalid Date, which
  // reads as an object and fails much later at whatever first formats it.
  var NEVER_A_DATE = [
    "2026-13-01T00:00:00Z", "2026-00-01T00:00:00Z", "2026-01-32T00:00:00Z",
    "2026-01-01T24:00:00Z", "2026-01-01T00:60:00Z", "2026-01-01T00:00:60Z",
    "2026-08-16T12:34:56z", "275760-09-14T00:00:00Z",
  ];
  var leaked = NEVER_A_DATE.filter(function (v) {
    try { return !isNaN(b.time.parseISO(v).getTime()) ? false : true; }
    catch (e) { return e.code !== "time/bad-iso"; }
  });
  check("parseISO never returns an Invalid Date and never throws without its " +
        "own code", leaked.length === 0, JSON.stringify(leaked));

  // The fields come back as TEXT, so a caller that reports on its input has
  // the characters it was given rather than a number it has to re-render.
  var read = b.time.readDateTime("2026-08-16T12:34:56.789+01:00");
  check("readDateTime returns each field as text",
        read.year === "2026" && read.month === "08" && read.day === "16" &&
        read.hour === "12" && read.minute === "34" && read.second === "56" &&
        read.fraction === ".789" && read.offset === "+01:00");
  check("readDate reports where it stopped",
        b.time.readDate("2026-08-16T00:00:00Z").end === 10);
  check("readTime reads a bare time and its offset",
        b.time.readTime("12:34:56Z").offset === "Z" &&
        b.time.readTime("12:34:56").offset === "");
  check("readTime refuses a fraction with no digits",
        b.time.readTime("12:34:56.Z") === null);
  check("readTime refuses a colon-less offset unless asked",
        b.time.readTime("12:34:56+0100") === null &&
        b.time.readTime("12:34:56+0100", 0, { offsetColon: "optional" }).offset === "+0100");
  check("readDateTime requires the offset when asked",
        b.time.readDateTime("2026-08-16T12:34:56") !== null &&
        b.time.readDateTime("2026-08-16T12:34:56", { requireOffset: true }) === null);
  check("readDateTime refuses a separator outside the allowed set",
        b.time.readDateTime("2026-08-16 12:34:56Z") !== null &&
        b.time.readDateTime("2026-08-16 12:34:56Z", { separators: "T" }) === null);
  // RFC 3339 §5.6 permits a lower-case `t`, and the reader defaults to taking
  // it — but parseISO stays on the set it has always accepted, because
  // widening what an existing parser accepts changes every caller below it.
  check("the reader takes a lower-case t by default; parseISO still does not",
        b.time.readDateTime("2026-08-16t12:34:56Z") !== null &&
        _parseIsoCode("2026-08-16t12:34:56Z") === "time/bad-iso");
  check("readDateTime refuses trailing text rather than ignoring it",
        b.time.readDateTime("2026-08-16T12:34:56Z trailing") === null);
  check("the readers refuse a non-string",
        b.time.readDate(null) === null && b.time.readTime(null) === null &&
        b.time.readDateTime(null) === null);

  // The millisecond strip, against the pattern it replaced. It runs on a value
  // that arrived over the wire (safe-json compares two timestamps at
  // one-second resolution), so it is a walk like everything else that does.
  var ISO_MS_RE = /\.\d{3}Z$/;
  var msDiffs = [];
  ["2026-05-09T14:30:00.789Z", "2026-05-09T14:30:00Z", "2026-05-09T14:30:00.7Z",
   "2026-05-09T14:30:00.7890Z", "2026-05-09T14:30:00.789", ".789Z", "789Z",
   "Z", "", ".abcZ", "x.789Z"].forEach(function (v) {
    var want = v.replace(ISO_MS_RE, "Z");
    var got = b.time.stripIsoMilliseconds(v);
    if (want !== got) {
      msDiffs.push(JSON.stringify(v) + " want " + JSON.stringify(want) +
                   " got " + JSON.stringify(got));
    }
  });
  check("b.time.stripIsoMilliseconds agrees with /\\.\\d{3}Z$/ on every case",
        msDiffs.length === 0, msDiffs.join(" | "));
  check("stripIsoMilliseconds passes a non-string through",
        b.time.stripIsoMilliseconds(42) === 42);
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
