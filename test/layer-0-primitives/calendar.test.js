"use strict";

var helpers = require("../helpers");
var check = helpers.check;
var b = helpers.b;

function testSurface() {
  check("b.calendar namespace",            typeof b.calendar === "object");
  check("validate is fn",                  typeof b.calendar.validate === "function");
  check("fromIcal is fn",                  typeof b.calendar.fromIcal === "function");
  check("toIcal is fn",                    typeof b.calendar.toIcal === "function");
  check("expandRecurrence is fn",          typeof b.calendar.expandRecurrence === "function");
  check("CalendarError is class",          typeof b.calendar.CalendarError === "function");
  check("JSCAL_TYPES.Event",               b.calendar.JSCAL_TYPES.Event === "Event");
  check("JSCAL_FREQUENCIES.daily",         b.calendar.JSCAL_FREQUENCIES.daily === 1);
}

function testValidateHappyPath() {
  var ev = {
    "@type":  "Event",
    uid:      "0e612e8b-1c4f-4e30-8e6a-4adc4e8b1c4f",
    updated:  "2026-05-21T10:00:00Z",
    title:    "Sprint planning",
    start:    "2026-05-22T09:00:00",
    duration: "PT1H",
    timeZone: "America/Los_Angeles",
  };
  var rv = b.calendar.validate(ev);
  check("validate returns input on success", rv === ev);
}

function testValidateRefusalCases() {
  function expectCode(label, jsCal, codeFragment) {
    var threw = null;
    try { b.calendar.validate(jsCal); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf(codeFragment) !== -1);
  }
  expectCode("non-object refused",             null,                                    "calendar/bad-input");
  expectCode("bad @type refused",              { "@type": "Foo", uid: "x", updated: "2026-05-21T10:00:00Z" }, "calendar/bad-type");
  expectCode("missing uid refused",
    { "@type": "Event", updated: "2026-05-21T10:00:00Z" },                              "calendar/no-uid");
  expectCode("missing updated refused",
    { "@type": "Event", uid: "x" },                                                      "calendar/bad-updated");
  expectCode("non-UTC updated refused",
    { "@type": "Event", uid: "x", updated: "2026-05-21 10:00:00" },                     "calendar/bad-updated");
  expectCode("non-RecurrenceRule @type refused",
    { "@type": "Event", uid: "x", updated: "2026-05-21T10:00:00Z", recurrenceRules: [{ "@type": "X" }] }, "calendar/bad-recurrence");
  expectCode("unknown frequency refused",
    { "@type": "Event", uid: "x", updated: "2026-05-21T10:00:00Z",
      recurrenceRules: [{ "@type": "RecurrenceRule", frequency: "fortnightly" }] },     "calendar/bad-recurrence");
  expectCode("bad duration refused",
    { "@type": "Event", uid: "x", updated: "2026-05-21T10:00:00Z", duration: "1h30m" }, "calendar/bad-duration");
  expectCode("alerts as array refused",
    { "@type": "Event", uid: "x", updated: "2026-05-21T10:00:00Z", alerts: [] },        "calendar/bad-alerts");
}

function testFromIcalRoundTrip() {
  var ical =
    "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//EN\r\n" +
    "BEGIN:VEVENT\r\nUID:abc@example.com\r\n" +
    "DTSTAMP:20260521T100000Z\r\n" +
    "DTSTART:20260522T090000\r\n" +
    "DURATION:PT1H\r\n" +
    "SUMMARY:Sprint planning\r\n" +
    "DESCRIPTION:Review last week + plan next\r\n" +
    "LOCATION:Meeting Room A\r\n" +
    "END:VEVENT\r\n" +
    "END:VCALENDAR\r\n";
  var ev = b.calendar.fromIcal(ical);
  check("fromIcal Event @type",            ev["@type"] === "Event");
  check("fromIcal uid preserved",          ev.uid === "abc@example.com");
  check("fromIcal updated → UTCDateTime",  ev.updated === "2026-05-21T10:00:00Z");
  check("fromIcal start → LocalDateTime",  ev.start === "2026-05-22T09:00:00");
  check("fromIcal title from SUMMARY",     ev.title === "Sprint planning");
  check("fromIcal description preserved",  ev.description === "Review last week + plan next");
  check("fromIcal location → locations[]", ev.locations && ev.locations.L1 &&
                                            ev.locations.L1.name === "Meeting Room A");
  // Round-trip back.
  var back = b.calendar.toIcal(ev);
  check("toIcal produces VCALENDAR envelope", /BEGIN:VCALENDAR/.test(back) && /END:VCALENDAR/.test(back));
  check("toIcal preserves UID",            /UID:abc@example\.com/.test(back));
  check("toIcal preserves SUMMARY",        /SUMMARY:Sprint planning/.test(back));
  check("toIcal preserves DTSTART",        /DTSTART:20260522T090000/.test(back));
}

function testFromIcalNoVevent() {
  var threw = null;
  try { b.calendar.fromIcal("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//x//EN\r\nEND:VCALENDAR\r\n"); }
  catch (e) { threw = e; }
  check("fromIcal with zero VEVENTs throws", threw && (threw.code || "").indexOf("calendar/no-vevent") !== -1);
}

function testRrulePreserved() {
  var ical =
    "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//x//EN\r\n" +
    "BEGIN:VEVENT\r\nUID:r@x\r\nDTSTAMP:20260521T100000Z\r\n" +
    "DTSTART:20260522T090000\r\n" +
    "RRULE:FREQ=WEEKLY;COUNT=5;BYDAY=MO,WE,FR\r\n" +
    "SUMMARY:Standup\r\n" +
    "END:VEVENT\r\nEND:VCALENDAR\r\n";
  var ev = b.calendar.fromIcal(ical);
  check("RRULE → recurrenceRules[0]",       Array.isArray(ev.recurrenceRules) && ev.recurrenceRules.length === 1);
  check("frequency mapped to lower-case",   ev.recurrenceRules[0].frequency === "weekly");
  check("COUNT mapped",                     ev.recurrenceRules[0].count === 5);
  check("BYDAY mapped to NDay[]",           Array.isArray(ev.recurrenceRules[0].byDay) &&
                                             ev.recurrenceRules[0].byDay[0].day === "mo");
}

function testExpandRecurrenceDaily() {
  var ev = {
    "@type":  "Event",
    uid:      "expand-daily",
    updated:  "2026-05-21T10:00:00Z",
    start:    "2026-05-22T09:00:00",
    recurrenceRules: [{ "@type": "RecurrenceRule", frequency: "daily", count: 5 }],
  };
  var instances = b.calendar.expandRecurrence(ev, { from: "2026-05-22T00:00:00Z", to: "2026-06-01T00:00:00Z" });
  check("daily expand emits 5 instances",   instances.length === 5);
  check("first instance at start",          instances[0] === "2026-05-22T09:00:00Z");
  check("fifth instance at start+4 days",   instances[4] === "2026-05-26T09:00:00Z");
}

function testExpandRecurrenceWeeklyInterval() {
  var ev = {
    "@type":  "Event",
    uid:      "expand-weekly",
    updated:  "2026-05-21T10:00:00Z",
    start:    "2026-05-22T09:00:00",
    recurrenceRules: [{ "@type": "RecurrenceRule", frequency: "weekly", interval: 2, count: 3 }],
  };
  var instances = b.calendar.expandRecurrence(ev, { from: "2026-05-22T00:00:00Z", to: "2026-07-31T00:00:00Z" });
  check("weekly interval=2 emits 3",        instances.length === 3);
  check("second instance +14 days",         instances[1] === "2026-06-05T09:00:00Z");
  check("third instance +28 days",          instances[2] === "2026-06-19T09:00:00Z");
}

function testExpandRecurrenceUntil() {
  var ev = {
    "@type":  "Event",
    uid:      "expand-until",
    updated:  "2026-05-21T10:00:00Z",
    start:    "2026-05-22T09:00:00",
    recurrenceRules: [{ "@type": "RecurrenceRule", frequency: "daily", until: "2026-05-25T00:00:00Z" }],
  };
  var instances = b.calendar.expandRecurrence(ev, { from: "2026-05-22T00:00:00Z", to: "2026-06-01T00:00:00Z" });
  // Days 22, 23, 24 fire (the UNTIL stamp is inclusive of the start time but 25T00 cuts off the 25-09-00 instance).
  check("UNTIL bounds the expansion",       instances.length === 3);
  check("last instance is 2026-05-24",      instances[instances.length - 1] === "2026-05-24T09:00:00Z");
}

function testExpandRecurrenceCapEnforced() {
  var ev = {
    "@type":  "Event",
    uid:      "bomb",
    updated:  "2026-05-21T10:00:00Z",
    start:    "2026-05-22T09:00:00",
    recurrenceRules: [{ "@type": "RecurrenceRule", frequency: "daily", count: 99999 }],                // allow:raw-byte-literal — recurrence-bomb attempt
  };
  var threw = null;
  try { b.calendar.expandRecurrence(ev, { from: "2026-05-22T00:00:00Z", to: "2200-01-01T00:00:00Z" }); }
  catch (e) { threw = e; }
  check("oversize expansion span refused",  threw && (threw.code || "").indexOf("calendar/oversize-expansion-span") !== -1);

  // With a tight window the expansion completes but is capped by
  // MAX_EXPAND_INSTANCES.
  var instances = b.calendar.expandRecurrence(ev, { from: "2026-05-22T00:00:00Z", to: "2030-05-22T00:00:00Z", max: 50 });
  check("instance count cap honoured",      instances.length <= 50);
}

function testUtcDtstartRoundTripPreserved() {
  // Codex P1 — DTSTART:...Z must produce a JSCalendar Event with
  // timeZone="Etc/UTC" so the round-trip back to iCalendar preserves
  // the `Z` suffix instead of emitting floating local time.
  var ical =
    "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//x//EN\r\n" +
    "BEGIN:VEVENT\r\nUID:u@x\r\nDTSTAMP:20260521T100000Z\r\n" +
    "DTSTART:20260522T090000Z\r\nDURATION:PT1H\r\nSUMMARY:UTC test\r\n" +
    "END:VEVENT\r\nEND:VCALENDAR\r\n";
  var ev = b.calendar.fromIcal(ical);
  check("UTC DTSTART → timeZone Etc/UTC",   ev.timeZone === "Etc/UTC");
  var back = b.calendar.toIcal(ev);
  check("toIcal preserves Z suffix",        /DTSTART:20260522T090000Z/.test(back));
  check("toIcal does NOT emit floating DTSTART", !/DTSTART:20260522T090000\r\n/.test(back));
  check("toIcal does NOT emit TZID for Etc/UTC", !/TZID=Etc\/UTC/.test(back));
}

function testFractionalSecondsStrippedInToIcal() {
  // Codex P2 — validate accepts fractional-second UTCDateTime but
  // toIcal MUST emit RFC 5545 form (no fractional seconds).
  var ev = {
    "@type":  "Event",
    uid:      "frac",
    updated:  "2026-05-21T10:00:00.123Z",
    title:    "frac",
    start:    "2026-05-22T09:00:00.456",
    duration: "PT1H",
    timeZone: "Etc/UTC",
  };
  var ical = b.calendar.toIcal(ev);
  check("fractional updated stripped in DTSTAMP", /DTSTAMP:20260521T100000Z/.test(ical));
  check("DTSTAMP does NOT carry fractional",     !/DTSTAMP:[^\r\n]*\.\d/.test(ical));
  check("fractional start stripped in DTSTART",   /DTSTART:20260522T090000Z/.test(ical));
  check("DTSTART does NOT carry fractional",     !/DTSTART:[^\r\n]*\.\d/.test(ical));
}

function testExpandRecurrenceByDayFilter() {
  // Codex P1 — FREQ=DAILY;BYDAY=MO must only emit Mondays.
  var ev = {
    "@type":  "Event",
    uid:      "mondays-only",
    updated:  "2026-05-21T10:00:00Z",
    start:    "2026-05-18T09:00:00",                                                                   // 2026-05-18 is a Monday
    timeZone: "Etc/UTC",
    recurrenceRules: [{ "@type": "RecurrenceRule", frequency: "daily",
                        byDay: [{ "@type": "NDay", day: "mo" }], count: 3 }],
  };
  var instances = b.calendar.expandRecurrence(ev, { from: "2026-05-18T00:00:00Z", to: "2026-07-01T00:00:00Z" });
  check("BYDAY=MO emits 3 instances",      instances.length === 3);
  // 2026-05-18 (Mon), 2026-05-25 (Mon), 2026-06-01 (Mon).
  check("first Monday",                     instances[0] === "2026-05-18T09:00:00Z");
  check("second Monday is +7 days",         instances[1] === "2026-05-25T09:00:00Z");
  check("third Monday is +14 days",         instances[2] === "2026-06-01T09:00:00Z");
}

function testExpandRecurrenceByMonthFilter() {
  // FREQ=YEARLY;BYMONTH=1 — January-only birthday-class.
  var ev = {
    "@type":  "Event",
    uid:      "yearly-jan",
    updated:  "2026-05-21T10:00:00Z",
    start:    "2026-01-15T09:00:00",
    timeZone: "Etc/UTC",
    recurrenceRules: [{ "@type": "RecurrenceRule", frequency: "yearly",
                        byMonth: ["1"], count: 3 }],
  };
  var instances = b.calendar.expandRecurrence(ev, { from: "2026-01-01T00:00:00Z", to: "2030-01-01T00:00:00Z" });
  check("BYMONTH=1 yearly emits 3 Januaries", instances.length === 3);
  check("first January 2026",               instances[0] === "2026-01-15T09:00:00Z");
  check("third January 2028",               instances[2] === "2028-01-15T09:00:00Z");
}

function testJmapCatalogueCarriesCalendarMethods() {
  var reg = b.mail.serverRegistry.create({
    protocol:  "jmap",
    defaults:  {
      "CalendarEvent/get": { fn: function () {}, maxHandlerBytes: 1024, maxHandlerMs: 100 },          // allow:raw-byte-literal
    },
  });
  check("CalendarEvent/get accepted in JMAP catalogue", reg && typeof reg.dispatch === "function");
}

function run() {
  testSurface();
  testValidateHappyPath();
  testValidateRefusalCases();
  testFromIcalRoundTrip();
  testFromIcalNoVevent();
  testRrulePreserved();
  testExpandRecurrenceDaily();
  testExpandRecurrenceWeeklyInterval();
  testExpandRecurrenceUntil();
  testExpandRecurrenceCapEnforced();
  testUtcDtstartRoundTripPreserved();
  testFractionalSecondsStrippedInToIcal();
  testExpandRecurrenceByDayFilter();
  testExpandRecurrenceByMonthFilter();
  testJmapCatalogueCarriesCalendarMethods();
}

module.exports = { run: run };

if (require.main === module) {
  try { run(); console.log("[calendar] OK"); }
  catch (e) { process.stderr.write("FAIL: " + (e && e.stack || e) + "\n"); process.exit(1); }
}
