// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * guard-time — RFC 3339 / ISO 8601 datetime identifier-safety primitive
 * (b.guardTime).
 *
 * Covers the inspect-vs-throw split: `validate` returns `{ ok, issues }`
 * without throwing (non-string input yields a `time.bad-input` issue),
 * while `sanitize` normalizes the string (legacy-space → `T`, trailing
 * `z` → `Z`) and throws GuardTimeError on any critical / high finding.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function _code(fn) { try { fn(); return null; } catch (e) { return e && e.code; } }
function _hasKind(rv, kind) {
  return rv.issues.some(function (i) { return i.kind === kind; });
}

function testGuardTimeSurface() {
  check("guardTime is an object",           typeof b.guardTime === "object");
  check("guardTime.NAME === 'time'",        b.guardTime.NAME === "time");
  check("guardTime.validate is a function", typeof b.guardTime.validate === "function");
  check("guardTime.sanitize is a function", typeof b.guardTime.sanitize === "function");
  check("guardTime registered in guardAll",
    b.guardAll.allGuards().some(function (g) { return (g.name || g.NAME) === "time"; }));
}

function testValidateAcceptsUtcDatetime() {
  var rv = b.guardTime.validate("2026-05-05T12:34:56Z", { profile: "strict" });
  check("well-formed UTC datetime → ok:true", rv.ok === true && rv.issues.length === 0);
}

function testValidatePreEpochYearWindow() {
  // 1969 is before the Unix-epoch floor (minYear default 1970).
  var rv = b.guardTime.validate("1969-12-31T23:59:59Z", { profile: "strict" });
  check("pre-epoch year → ok:false", rv.ok === false);
  check("pre-epoch year → year-window issue", _hasKind(rv, "year-window"));
}

function testValidateNaiveDatetimeStrict() {
  // No offset — strict refuses (cross-region ambiguity class).
  var rv = b.guardTime.validate("2026-05-05T12:34:56", { profile: "strict" });
  check("naive datetime under strict → ok:false", rv.ok === false);
  check("naive datetime → naive-datetime issue", _hasKind(rv, "naive-datetime"));
}

function testValidateNonStringReturnsBadInput() {
  // validate never throws on hostile input — it returns a bad-input issue.
  var rv = b.guardTime.validate(1234567890, { profile: "strict" });
  check("non-string input → ok:false, no throw", rv.ok === false);
  check("non-string input → bad-input issue", _hasKind(rv, "bad-input"));
}

function testSanitizeNormalizes() {
  // Legacy space separator + lowercase `z` are normalized to `T` / `Z`.
  var out = b.guardTime.sanitize("2026-05-05 12:34:56z", { profile: "balanced" });
  check("sanitize normalizes space+z → T+Z", out === "2026-05-05T12:34:56Z");
}

function testSanitizeCleanPassthrough() {
  var out = b.guardTime.sanitize("2026-05-05T12:34:56Z", { profile: "strict" });
  check("already-canonical UTC datetime passes through", out === "2026-05-05T12:34:56Z");
}

function testSanitizeThrowsOnLeapSecondStrict() {
  // Second field 60 is RFC 3339 §5.6 valid but refused under strict.
  check("leap-second refused under strict sanitize",
    _code(function () { b.guardTime.sanitize("9999-12-31T23:59:60Z", { profile: "strict" }); })
      === "time.leap-second");
}

// The RFC 3339 grammar was three patterns run in priority order — full-date,
// partial-time, then the whole date-time. It is now three readers that return
// the fields they read, so the guard reports which half is missing rather than
// which pattern happened to fail.
function testRfc3339ReadersAgreeWithThePatternsTheyReplaced() {
  var RFC3339_RE   = /^(\d{4})-(\d{2})-(\d{2})[Tt ](\d{2}):(\d{2}):(\d{2})(\.\d+)?([Zz]|[+-]\d{2}:\d{2})?$/;
  var DATE_ONLY_RE = /^\d{4}-\d{2}-\d{2}$/;
  var TIME_ONLY_RE = /^\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?$/;

  var VALUES = [
    "2026-08-16T12:34:56Z", "2026-08-16t12:34:56z", "2026-08-16 12:34:56Z",
    "2026-08-16T12:34:56", "2026-08-16T12:34:56+01:00", "2026-08-16T12:34:56-05:30",
    "2026-08-16T12:34:56.1Z", "2026-08-16T12:34:56.123456789Z",
    "2026-08-16T12:34:56.Z", "2026-08-16T12:34:56.", "2026-08-16T12:34:60Z",
    "2026-08-16", "2026-8-16", "2026-08-1", "26-08-16", "2026-08-166",
    "12:34:56", "12:34:56Z", "12:34:56.5Z", "12:34:56+01:00", "12:34:5",
    "2026-08-16T12:34:56Zx", "x2026-08-16T12:34:56Z", "2026-08-16T12:34:56+0100",
    "2026-08-16T12:34:56+01:0", "2026-08-16X12:34:56Z", "2026-08-16T12:34:56ZZ",
    " ", "2026-08-16T", "T12:34:56Z", "9999-12-31T23:59:59Z",
    "0000-01-01T00:00:00Z", "2026-08-16 12:34:56", "2026-08-16  12:34:56Z",
  ];

  function fromPatterns(v) {
    if (DATE_ONLY_RE.test(v)) return "date-only";
    if (TIME_ONLY_RE.test(v)) return "time-only";
    return RFC3339_RE.test(v) ? "shape-ok" : "datetime-shape";
  }

  function fromGuard(v) {
    var kinds = b.guardTime.validate(v, { profile: "strict" }).issues
      .map(function (i) { return i.kind; });
    if (kinds.indexOf("date-only") !== -1) return "date-only";
    if (kinds.indexOf("time-only") !== -1) return "time-only";
    if (kinds.indexOf("datetime-shape") !== -1) return "datetime-shape";
    return "shape-ok";
  }

  var diffs = [];
  VALUES.forEach(function (v) {
    // "shape-ok" from the patterns says only that the grammar parsed; the
    // guard applies calendar, year-window and offset rules on top, which
    // report under their own kinds.
    var want = fromPatterns(v);
    var got = fromGuard(v);
    if (want !== got) diffs.push(JSON.stringify(v) + " want " + want + " got " + got);
  });
  check("the RFC 3339 readers agree with the patterns they replaced (" +
        VALUES.length + " values)", diffs.length === 0, diffs.slice(0, 5).join(" | "));

  // The sanitize normalization is the same two substitutions: the legacy
  // space separator becomes `T`, a trailing lower-case `z` becomes `Z`.
  [["2026-08-16 12:34:56z", "2026-08-16T12:34:56Z"],
   ["2026-08-16T12:34:56z", "2026-08-16T12:34:56Z"],
   ["2026-08-16 12:34:56Z", "2026-08-16T12:34:56Z"],
   ["2026-08-16T12:34:56Z", "2026-08-16T12:34:56Z"]].forEach(function (c) {
    var got = b.guardTime.sanitize(c[0], { profile: "permissive" });
    var value = got && typeof got === "object" ? got.value : got;
    check("sanitize normalizes " + JSON.stringify(c[0]), value === c[1],
          JSON.stringify(value));
  });
}

function run() {
  testRfc3339ReadersAgreeWithThePatternsTheyReplaced();
  testGuardTimeSurface();
  testValidateAcceptsUtcDatetime();
  testValidatePreEpochYearWindow();
  testValidateNaiveDatetimeStrict();
  testValidateNonStringReturnsBadInput();
  testSanitizeNormalizes();
  testSanitizeCleanPassthrough();
  testSanitizeThrowsOnLeapSecondStrict();
}

module.exports = { run: run };

if (require.main === module) {
  try { run(); console.log("[guard-time] OK — " + helpers.getChecks() + " checks passed"); }
  catch (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
}
