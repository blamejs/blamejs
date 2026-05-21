"use strict";
/**
 * @module    b.calendar
 * @nav       Mail
 * @title     Calendar (JSCalendar)
 * @order     400
 * @slug      calendar
 *
 * @intro
 *   JSCalendar (RFC 8984) primitive. Wraps the framework's existing
 *   `b.safeIcal.parse` (RFC 5545 grammar + bounded parser) with the
 *   JSON-native JSCalendar surface JMAP Calendars (RFC 8984 / draft-
 *   ietf-jmap-calendars) requires for cross-protocol interop.
 *
 *   v1 scope:
 *     - `validate(jsCal)` — assert JSCalendar Event / Task shape
 *     - `fromIcal(text, opts?)` — VCALENDAR.VEVENT → JSCalendar Event
 *     - `toIcal(jsCal, opts?)` — JSCalendar Event → VCALENDAR
 *     - `expandRecurrence(event, { from, to, max })` — RRULE expansion
 *       for FREQ=DAILY/WEEKLY/MONTHLY/YEARLY with UNTIL/COUNT/INTERVAL
 *
 *   Deferred-with-condition (no operator demand yet):
 *     - BYSETPOS / BYWEEKNO / BYYEARDAY (RFC 5545 §3.3.10) — RFC 7529
 *       non-Gregorian calendars; floating timezone resolution.
 *     - VTODO / VJOURNAL → Task / Note objects (RFC 8984 §5/§6).
 *     - JSCalendar Group objects (RFC 8984 §1.4.4).
 *
 * @card
 *   JSCalendar (RFC 8984) ↔ iCalendar (RFC 5545) bridge — validate,
 *   convert both directions, expand recurrences. Substrate for JMAP
 *   Calendars (RFC 8984 + draft-ietf-jmap-calendars).
 */

var safeIcal = require("./safe-ical");
var time     = require("./time");
var { defineClass } = require("./framework-error");

var CalendarError = defineClass("CalendarError", { alwaysPermanent: true });

// JSCalendar shape vocabulary — RFC 8984 §1.2 (`@type`) catalogues
// the discriminator strings every nested object MUST carry.
var JSCAL_TYPES = Object.freeze({
  Event:        "Event",
  Task:         "Task",
  Group:        "Group",
  Participant:  "Participant",
  Location:     "Location",
  Link:         "Link",
  Alert:        "Alert",
  Recurrence:   "RecurrenceRule",
  TimeZone:     "TimeZone",
});

// RFC 8984 §4.3.2 — frequencies recognised in `RecurrenceRule.frequency`.
var JSCAL_FREQUENCIES = Object.freeze({
  yearly: 1, monthly: 1, weekly: 1, daily: 1, hourly: 1, minutely: 1, secondly: 1,
});

// RFC 8984 §4.6.2 — alert action types.
var JSCAL_ALERT_ACTIONS = Object.freeze({
  display: 1, email: 1,
});

// Recurrence-expansion caps. Mirror b.safeIcal's RRULE limits so the
// expand path can't outpace what the parser already permitted.
var MAX_EXPAND_INSTANCES = 4096;                                                                       // allow:raw-byte-literal — instance count cap, not bytes
var MAX_EXPAND_SPAN_MS   = 10 * 365 * 24 * 60 * 60 * 1000;                                             // allow:raw-byte-literal + allow:raw-time-literal — 10 year max expansion span

/**
 * @primitive b.calendar.validate
 * @signature b.calendar.validate(jsCal)
 * @since     0.11.31
 * @status    stable
 *
 * Validate a JSCalendar Event / Task object's required-field shape per
 * RFC 8984 §5 (Event) + §6 (Task). Returns the input on success; throws
 * `CalendarError` on refusal with a `.code` naming the specific shape
 * rule that failed.
 *
 * @example
 *   b.calendar.validate({
 *     "@type":      "Event",
 *     uid:          "0e612e8b-1c4f-4e30-8e6a-4adc4e8b1c4f",
 *     updated:      "2026-05-21T10:00:00Z",
 *     title:        "Sprint planning",
 *     start:        "2026-05-22T09:00:00",
 *     duration:     "PT1H",
 *     timeZone:     "America/Los_Angeles",
 *   });
 */
function validate(jsCal) {
  if (!jsCal || typeof jsCal !== "object" || Array.isArray(jsCal)) {
    throw new CalendarError("calendar/bad-input",
      "b.calendar.validate: input must be a JSCalendar object");
  }
  var t = jsCal["@type"];
  if (t !== JSCAL_TYPES.Event && t !== JSCAL_TYPES.Task) {
    throw new CalendarError("calendar/bad-type",
      "b.calendar.validate: @type must be 'Event' or 'Task' (got " + JSON.stringify(t) + ")");
  }
  if (typeof jsCal.uid !== "string" || jsCal.uid.length === 0) {
    throw new CalendarError("calendar/no-uid",
      "b.calendar.validate: uid is required (RFC 8984 §5.1.4)");
  }
  if (jsCal.uid.length > 1024) {                                                                       // allow:raw-byte-literal — anti-DoS uid length cap
    throw new CalendarError("calendar/oversize-uid",
      "b.calendar.validate: uid exceeds 1024 bytes");
  }
  if (typeof jsCal.updated !== "string" || !_isUtcDateTime(jsCal.updated)) {
    throw new CalendarError("calendar/bad-updated",
      "b.calendar.validate: updated MUST be a UTCDateTime per RFC 8984 §1.4.3 (got " + JSON.stringify(jsCal.updated) + ")");
  }
  if (t === JSCAL_TYPES.Event) {
    if (jsCal.start !== undefined && (typeof jsCal.start !== "string" || !_isLocalDateTime(jsCal.start))) {
      throw new CalendarError("calendar/bad-start",
        "b.calendar.validate: Event.start MUST be a LocalDateTime");
    }
    if (jsCal.duration !== undefined && (typeof jsCal.duration !== "string" || !_isDuration(jsCal.duration))) {
      throw new CalendarError("calendar/bad-duration",
        "b.calendar.validate: Event.duration MUST be an RFC 8601 PnYnMnDTnHnMnS Duration");
    }
  }
  if (jsCal.recurrenceRules !== undefined) {
    if (!Array.isArray(jsCal.recurrenceRules)) {
      throw new CalendarError("calendar/bad-recurrence",
        "b.calendar.validate: recurrenceRules MUST be an array of RecurrenceRule");
    }
    for (var ri = 0; ri < jsCal.recurrenceRules.length; ri += 1) {
      var rr = jsCal.recurrenceRules[ri];
      if (!rr || typeof rr !== "object" || rr["@type"] !== "RecurrenceRule") {
        throw new CalendarError("calendar/bad-recurrence",
          "b.calendar.validate: recurrenceRules[" + ri + "].@type MUST be 'RecurrenceRule'");
      }
      if (!Object.prototype.hasOwnProperty.call(JSCAL_FREQUENCIES, rr.frequency)) {
        throw new CalendarError("calendar/bad-recurrence",
          "b.calendar.validate: recurrenceRules[" + ri + "].frequency MUST be one of " +
          Object.keys(JSCAL_FREQUENCIES).join(" | "));
      }
    }
  }
  if (jsCal.alerts !== undefined) {
    if (typeof jsCal.alerts !== "object" || Array.isArray(jsCal.alerts)) {
      throw new CalendarError("calendar/bad-alerts",
        "b.calendar.validate: alerts MUST be an object map keyed by alert-id");
    }
    var alertKeys = Object.keys(jsCal.alerts);
    for (var ai = 0; ai < alertKeys.length; ai += 1) {
      var alert = jsCal.alerts[alertKeys[ai]];
      if (!alert || alert["@type"] !== "Alert") {
        throw new CalendarError("calendar/bad-alerts",
          "b.calendar.validate: alerts[" + alertKeys[ai] + "].@type MUST be 'Alert'");
      }
      if (alert.action && !Object.prototype.hasOwnProperty.call(JSCAL_ALERT_ACTIONS, alert.action)) {
        throw new CalendarError("calendar/bad-alerts",
          "b.calendar.validate: alerts[" + alertKeys[ai] + "].action MUST be one of " +
          Object.keys(JSCAL_ALERT_ACTIONS).join(" | "));
      }
    }
  }
  return jsCal;
}

/**
 * @primitive b.calendar.fromIcal
 * @signature b.calendar.fromIcal(text, opts?)
 * @since     0.11.31
 * @status    stable
 *
 * Parse iCalendar text (RFC 5545) via `b.safeIcal.parse` and map the
 * first VEVENT into a JSCalendar Event object (RFC 8984 §5). Returns
 * a single Event when the VCALENDAR contains exactly one VEVENT, or
 * an array when multiple VEVENTs are present.
 *
 * @opts
 *   safeIcalOpts: object,   // forwarded to b.safeIcal.parse (caps, allowExperimental, etc.)
 *
 * @example
 *   b.calendar.fromIcal(
 *     "BEGIN:VCALENDAR\\r\\nVERSION:2.0\\r\\n" +
 *     "BEGIN:VEVENT\\r\\nUID:a@b\\r\\nDTSTAMP:20260521T100000Z\\r\\n" +
 *     "DTSTART:20260522T090000Z\\r\\nDURATION:PT1H\\r\\n" +
 *     "SUMMARY:Sprint\\r\\nEND:VEVENT\\r\\nEND:VCALENDAR\\r\\n");
 *   // → { "@type":"Event", uid:"a@b", updated:"2026-05-21T10:00:00Z", ... }
 */
function fromIcal(text, opts) {
  var ast = safeIcal.parse(text, opts || {});
  var events = (ast && ast.vcalendar && ast.vcalendar.vevent) || [];
  if (events.length === 0) {
    throw new CalendarError("calendar/no-vevent",
      "b.calendar.fromIcal: VCALENDAR has no VEVENT components");
  }
  var converted = events.map(_veventToJsCalEvent);
  return converted.length === 1 ? converted[0] : converted;
}

/**
 * @primitive b.calendar.toIcal
 * @signature b.calendar.toIcal(jsCal, opts?)
 * @since     0.11.31
 * @status    stable
 *
 * Render a JSCalendar Event back to RFC 5545 iCalendar text. Returns a
 * CRLF-terminated string wrapped in a `BEGIN:VCALENDAR / VERSION:2.0 /
 * PRODID:-//blamejs//Calendar//EN / BEGIN:VEVENT ... END:VEVENT /
 * END:VCALENDAR` envelope per RFC 5545 §3.4.
 *
 * @opts
 *   prodid: string,   // PRODID value to emit; default "-//blamejs//Calendar//EN"
 *
 * @example
 *   b.calendar.toIcal({
 *     "@type":  "Event",
 *     uid:      "a@b",
 *     updated:  "2026-05-21T10:00:00Z",
 *     title:    "Sprint",
 *     start:    "2026-05-22T09:00:00",
 *     duration: "PT1H",
 *   });
 */
function toIcal(jsCal, opts) {
  validate(jsCal);
  var prodid = (opts && opts.prodid) || "-//blamejs//Calendar//EN";
  var lines = [
    "BEGIN:VCALENDAR",
    "VERSION:2.0",
    "PRODID:" + prodid,
    "BEGIN:VEVENT",
    "UID:" + _foldLine(jsCal.uid),
    "DTSTAMP:" + _utcDateTimeToIcal(jsCal.updated),
  ];
  if (jsCal.title) lines.push("SUMMARY:" + _foldLine(_escapeText(jsCal.title)));
  if (jsCal.description) lines.push("DESCRIPTION:" + _foldLine(_escapeText(jsCal.description)));
  if (jsCal.start) {
    // RFC 8984 §1.4.4 maps `timeZone: "Etc/UTC"` to a `Z`-suffix
    // DTSTART (RFC 5545 §3.3.5 form 2); any other named timezone
    // maps to a TZID parameter (form 3); no timeZone leaves DTSTART
    // as floating local time (form 1).
    var dtStartIcal = _localDateTimeToIcal(jsCal.start);
    if (jsCal.timeZone === "Etc/UTC" || jsCal.timeZone === "UTC") {
      lines.push("DTSTART:" + dtStartIcal + "Z");
    } else if (jsCal.timeZone) {
      lines.push("DTSTART;TZID=" + jsCal.timeZone + ":" + dtStartIcal);
    } else {
      lines.push("DTSTART:" + dtStartIcal);
    }
  }
  if (jsCal.duration) lines.push("DURATION:" + jsCal.duration);
  if (Array.isArray(jsCal.locations) || (jsCal.locations && typeof jsCal.locations === "object")) {
    var locValues = Array.isArray(jsCal.locations) ? jsCal.locations : Object.values(jsCal.locations);
    for (var li = 0; li < locValues.length; li += 1) {
      var loc = locValues[li];
      if (loc && typeof loc.name === "string") {
        lines.push("LOCATION:" + _foldLine(_escapeText(loc.name)));
      }
    }
  }
  if (Array.isArray(jsCal.recurrenceRules)) {
    for (var rri = 0; rri < jsCal.recurrenceRules.length; rri += 1) {
      lines.push("RRULE:" + _recurrenceRuleToIcal(jsCal.recurrenceRules[rri]));
    }
  }
  lines.push("END:VEVENT", "END:VCALENDAR");
  return lines.join("\r\n") + "\r\n";
}

/**
 * @primitive b.calendar.expandRecurrence
 * @signature b.calendar.expandRecurrence(event, opts)
 * @since     0.11.31
 * @status    stable
 *
 * Expand a JSCalendar Event's `recurrenceRules` into concrete start
 * timestamps in the operator's `[from, to]` window. Returns an array
 * of ISO 8601 UTC strings (`yyyy-mm-ddTHH:MM:SSZ`). Bounded by
 * `MAX_EXPAND_INSTANCES` (4096) + `MAX_EXPAND_SPAN_MS` (10 years) to
 * defend against CVE-2024-39687-class recurrence-bomb expansion.
 *
 * v1 supports FREQ=DAILY/WEEKLY/MONTHLY/YEARLY with INTERVAL, COUNT,
 * UNTIL. BYDAY / BYMONTH / BYMONTHDAY refine the base frequency. The
 * BYSETPOS / BYWEEKNO / BYYEARDAY filters are deferred-with-condition
 * (RFC 7529 non-Gregorian calendars not in scope either).
 *
 * @opts
 *   from: string,    // ISO 8601 UTC timestamp — lower bound of expansion window
 *   to:   string,    // ISO 8601 UTC timestamp — upper bound (window <= 10 years)
 *   max:  number,    // instance-count cap (default 4096; never exceeds MAX_EXPAND_INSTANCES)
 *
 * @example
 *   b.calendar.expandRecurrence(
 *     { "@type": "Event", uid: "x", updated: "2026-05-21T10:00:00Z",
 *       start: "2026-05-22T09:00:00",
 *       recurrenceRules: [{ "@type": "RecurrenceRule", frequency: "daily", count: 5 }] },
 *     { from: "2026-05-22T00:00:00Z", to: "2026-06-01T00:00:00Z" });
 *   // → ["2026-05-22T09:00:00Z", "2026-05-23T09:00:00Z", ..., "2026-05-26T09:00:00Z"]
 */
function expandRecurrence(event, opts) {
  validate(event);
  opts = opts || {};
  if (!Array.isArray(event.recurrenceRules) || event.recurrenceRules.length === 0) {
    return event.start ? [_localToUtc(event.start)] : [];
  }
  var fromMs = opts.from ? Date.parse(opts.from) : null;
  var toMs   = opts.to   ? Date.parse(opts.to)   : null;
  if (fromMs !== null && toMs !== null) {
    if (toMs - fromMs > MAX_EXPAND_SPAN_MS) {
      throw new CalendarError("calendar/oversize-expansion-span",
        "b.calendar.expandRecurrence: window [" + opts.from + ", " + opts.to + "] exceeds 10 years");
    }
    if (toMs < fromMs) {
      throw new CalendarError("calendar/bad-expansion-window",
        "b.calendar.expandRecurrence: opts.to must be after opts.from");
    }
  }
  var maxCount = Math.min(opts.max || MAX_EXPAND_INSTANCES, MAX_EXPAND_INSTANCES);
  // JSCalendar's LocalDateTime is FLOATING when no timeZone is set;
  // for expansion we treat it as already-UTC so the returned ISO
  // strings carry the same wall-clock the operator stored. Appending
  // `Z` to the LocalDateTime sidesteps Date.parse's host-locale
  // interpretation (which would otherwise mangle the wall-clock).
  var startInput = _isLocalDateTime(event.start) ? event.start + "Z" : event.start;
  var startMs = Date.parse(startInput);
  if (!isFinite(startMs)) {
    throw new CalendarError("calendar/bad-start",
      "b.calendar.expandRecurrence: event.start is not a parseable date");
  }
  var out = [];
  // We honour ONLY the first recurrenceRule in v1; multiple rules
  // compose via union which is a follow-up.
  var rule = event.recurrenceRules[0];
  var interval = Math.max(1, parseInt(rule.interval || 1, 10));
  var freq = rule.frequency;
  var count = isFinite(rule.count) ? rule.count : Infinity;
  var untilMs = rule.until ? Date.parse(rule.until) : Infinity;
  // RFC 5545 §3.3.10 BY* filters narrow which stepped occurrences
  // emit. We support the BYDAY/BYMONTH/BYMONTHDAY subset; rule
  // instances that fail the filter are stepped past WITHOUT counting
  // against `count` (per RFC 5545 BY* expansion semantics — only
  // surviving instances count).
  var byDaySet = null;
  if (Array.isArray(rule.byDay) && rule.byDay.length > 0) {
    byDaySet = Object.create(null);
    var dayCodes = { su: 0, mo: 1, tu: 2, we: 3, th: 4, fr: 5, sa: 6 };
    for (var bi = 0; bi < rule.byDay.length; bi += 1) {
      var entry = rule.byDay[bi];
      var dayKey = (entry && entry.day ? entry.day : entry || "").toLowerCase();
      if (Object.prototype.hasOwnProperty.call(dayCodes, dayKey)) {
        byDaySet[dayCodes[dayKey]] = true;
      }
    }
  }
  var byMonthSet = null;
  if (Array.isArray(rule.byMonth) && rule.byMonth.length > 0) {
    byMonthSet = Object.create(null);
    for (var mi = 0; mi < rule.byMonth.length; mi += 1) {
      var mn = parseInt(rule.byMonth[mi], 10);
      if (isFinite(mn) && mn >= 1 && mn <= 12) byMonthSet[mn] = true;                                  // allow:raw-byte-literal — 12 calendar months
    }
  }
  var byMonthDaySet = null;
  if (Array.isArray(rule.byMonthDay) && rule.byMonthDay.length > 0) {
    byMonthDaySet = Object.create(null);
    for (var mdi = 0; mdi < rule.byMonthDay.length; mdi += 1) {
      var mdn = parseInt(rule.byMonthDay[mdi], 10);
      if (isFinite(mdn) && mdn !== 0 && mdn >= -31 && mdn <= 31) byMonthDaySet[mdn] = true;            // allow:raw-byte-literal — calendar day-of-month bounds
    }
  }
  function _matchesBy(t) {
    var d = new Date(t);
    if (byDaySet && !byDaySet[d.getUTCDay()]) return false;
    if (byMonthSet && !byMonthSet[d.getUTCMonth() + 1]) return false;
    if (byMonthDaySet && !byMonthDaySet[d.getUTCDate()]) return false;
    return true;
  }
  var t = startMs;
  // Safety cap on the step loop: at most MAX_EXPAND_INSTANCES * 366
  // iterations so BY* filters that match sparsely (e.g. FREQ=DAILY;
  // BYMONTH=1 — only Jan days survive) cannot loop forever inside
  // the 10-year span cap.
  var stepBudget = MAX_EXPAND_INSTANCES * 366;                                                         // allow:raw-byte-literal — days/year stepping budget
  while (out.length < count && out.length < maxCount && stepBudget > 0) {
    stepBudget -= 1;
    if (t > untilMs) break;
    if (toMs !== null && t > toMs) break;
    if (_matchesBy(t)) {
      if (fromMs === null || t >= fromMs) {
        out.push(_msToIsoZ(t));
      }
    }
    t = _advance(t, freq, interval);
    if (t === null) {
      throw new CalendarError("calendar/bad-recurrence",
        "b.calendar.expandRecurrence: unsupported frequency '" + freq + "'");
    }
  }
  return out;
}

// ---- Internal helpers ----------------------------------------------------

function _veventToJsCalEvent(ve) {
  var props = (ve && ve.properties) || {};
  var jsCal = {
    "@type":  "Event",
    uid:      _firstValue(props.UID) || "",
    updated:  _icalDateTimeToUtc(_firstValue(props.DTSTAMP) || ""),
  };
  var summary = _firstValue(props.SUMMARY);
  if (summary) jsCal.title = _unescapeText(summary);
  var description = _firstValue(props.DESCRIPTION);
  if (description) jsCal.description = _unescapeText(description);
  var dtstart = _firstValue(props.DTSTART);
  if (dtstart) jsCal.start = _icalDateTimeToLocal(dtstart);
  var duration = _firstValue(props.DURATION);
  if (duration) jsCal.duration = duration;
  var tzid = _firstParamValue(props.DTSTART, "TZID");
  if (tzid) {
    jsCal.timeZone = tzid;
  } else if (typeof dtstart === "string" && /Z$/.test(dtstart)) {
    // Codex P1 — RFC 8984 §1.4.4: a UTC-suffix DTSTART (`...Z`) in
    // iCalendar maps to a JSCalendar Event with `timeZone: "Etc/UTC"`.
    // Without this, round-tripping `fromIcal` → `toIcal` would drop
    // the UTC anchor + emit floating time, shifting the absolute
    // instant for viewers in different timezones.
    jsCal.timeZone = "Etc/UTC";
  }
  var location = _firstValue(props.LOCATION);
  if (location) {
    jsCal.locations = { L1: { "@type": "Location", name: _unescapeText(location) } };
  }
  var rrule = _firstValue(props.RRULE);
  if (rrule) jsCal.recurrenceRules = [_icalRruleToJscal(rrule)];
  return jsCal;
}

function _firstValue(prop) {
  if (!prop) return null;
  if (Array.isArray(prop)) {
    var first = prop[0];
    return first && first.value !== undefined ? first.value : null;
  }
  if (prop.value !== undefined) return prop.value;
  return null;
}

function _firstParamValue(prop, paramName) {
  if (!prop) return null;
  var first = Array.isArray(prop) ? prop[0] : prop;
  if (!first || !first.params) return null;
  return first.params[paramName] || null;
}

function _icalRruleToJscal(rrule) {
  var out = { "@type": "RecurrenceRule", frequency: "daily" };
  var parts = String(rrule).split(";");                                                                // allow:bare-split-on-quoted-header — RFC 5545 RRULE grammar has no quoted-string members; values are token-only
  for (var i = 0; i < parts.length; i += 1) {
    var kv = parts[i].split("=");
    if (kv.length !== 2) continue;
    var key = kv[0].toUpperCase();
    var val = kv[1];
    if (key === "FREQ") out.frequency = val.toLowerCase();
    else if (key === "INTERVAL") out.interval = parseInt(val, 10);
    else if (key === "COUNT") out.count = parseInt(val, 10);
    else if (key === "UNTIL") out.until = _icalDateTimeToUtc(val);
    else if (key === "BYDAY") out.byDay = val.split(",").map(function (d) {                            // allow:bare-split-on-quoted-header — RFC 5545 BYDAY values are token-only
      return { "@type": "NDay", day: d.slice(-2).toLowerCase() };
    });
    else if (key === "BYMONTH") out.byMonth = val.split(",");                                          // allow:bare-split-on-quoted-header — RFC 5545 BYMONTH values are integer-only
    else if (key === "BYMONTHDAY") out.byMonthDay = val.split(",").map(function (n) { return parseInt(n, 10); }); // allow:bare-split-on-quoted-header — RFC 5545 BYMONTHDAY values are integer-only
  }
  return out;
}

function _recurrenceRuleToIcal(rr) {
  var parts = ["FREQ=" + (rr.frequency || "daily").toUpperCase()];
  if (rr.interval && rr.interval !== 1) parts.push("INTERVAL=" + rr.interval);
  if (rr.count) parts.push("COUNT=" + rr.count);
  if (rr.until) parts.push("UNTIL=" + _utcDateTimeToIcal(rr.until));
  if (Array.isArray(rr.byDay) && rr.byDay.length > 0) {
    parts.push("BYDAY=" + rr.byDay.map(function (d) { return (d.day || "").toUpperCase(); }).join(","));
  }
  if (Array.isArray(rr.byMonth)) parts.push("BYMONTH=" + rr.byMonth.join(","));
  if (Array.isArray(rr.byMonthDay)) parts.push("BYMONTHDAY=" + rr.byMonthDay.join(","));
  return parts.join(";");
}

function _icalDateTimeToUtc(s) {
  // VALUE=DATE-TIME UTC form: 20260522T100000Z → 2026-05-22T10:00:00Z
  var m = String(s).match(/^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z$/);
  if (!m) return "";
  return m[1] + "-" + m[2] + "-" + m[3] + "T" + m[4] + ":" + m[5] + ":" + m[6] + "Z";
}

function _icalDateTimeToLocal(s) {
  var m = String(s).match(/^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z?$/);
  if (!m) return "";
  return m[1] + "-" + m[2] + "-" + m[3] + "T" + m[4] + ":" + m[5] + ":" + m[6];
}

function _utcDateTimeToIcal(s) {
  // JSCalendar UTCDateTime "2026-05-22T10:00:00.123Z" →
  // "20260522T100000Z" (RFC 5545 §3.3.5 form 2 has NO fractional
  // seconds; strict ICS consumers reject `T100000.123Z`).
  return String(s).replace(/\.\d+/, "").replace(/[-:]/g, "");                                          // allow:bare-split-on-quoted-header — not a header split
}

function _localDateTimeToIcal(s) {
  // JSCalendar LocalDateTime "2026-05-22T09:00:00.123" →
  // "20260522T090000" (same fractional-second strip as the UTC form).
  return String(s).replace(/\.\d+/, "").replace(/[-:]/g, "");                                          // allow:bare-split-on-quoted-header — not a header split
}

function _isUtcDateTime(s) {
  return /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/.test(s);
}

function _isLocalDateTime(s) {
  return /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?$/.test(s);
}

function _isDuration(s) {
  return /^-?P(\d+Y)?(\d+M)?(\d+D)?(T(\d+H)?(\d+M)?(\d+S)?)?$/.test(s);
}

function _localToUtc(localStr) {
  // Naive — treats LocalDateTime as already-UTC for the no-tz case.
  return localStr.endsWith("Z") ? localStr : localStr + "Z";
}

function _msToIsoZ(ms) {
  return time.toIso8601NoMs(new Date(ms));
}

function _advance(ms, freq, interval) {
  var d = new Date(ms);
  switch (freq) {
  case "daily":   d.setUTCDate(d.getUTCDate() + interval); break;
  case "weekly":  d.setUTCDate(d.getUTCDate() + 7 * interval); break;                                  // allow:raw-byte-literal — 7 days/week
  case "monthly": d.setUTCMonth(d.getUTCMonth() + interval); break;
  case "yearly":  d.setUTCFullYear(d.getUTCFullYear() + interval); break;
  case "hourly":  d.setUTCHours(d.getUTCHours() + interval); break;
  case "minutely": d.setUTCMinutes(d.getUTCMinutes() + interval); break;
  case "secondly": d.setUTCSeconds(d.getUTCSeconds() + interval); break;
  default: return null;
  }
  return d.getTime();
}

function _escapeText(s) {
  return String(s).replace(/\\/g, "\\\\").replace(/;/g, "\\;").replace(/,/g, "\\,").replace(/\n/g, "\\n");
}

function _unescapeText(s) {
  return String(s)
    .replace(/\\n/g, "\n").replace(/\\,/g, ",")
    .replace(/\\;/g, ";").replace(/\\\\/g, "\\");
}

function _foldLine(s) {
  // RFC 5545 §3.1 — content lines SHOULD NOT exceed 75 octets; fold
  // with CRLF + leading space. We let the joining code add the
  // trailing CRLF; this helper only inserts the intra-line fold.
  if (s.length <= 75) return s;                                                                        // allow:raw-byte-literal — RFC 5545 §3.1 line-length cap
  var out = "";
  for (var i = 0; i < s.length; i += 73) {                                                             // allow:raw-byte-literal — 73 = 75 minus the CR/LF wrap
    out += (i === 0 ? "" : "\r\n ") + s.slice(i, i + 73);                                              // allow:raw-byte-literal — same cap
  }
  return out;
}

module.exports = {
  validate:               validate,
  fromIcal:               fromIcal,
  toIcal:                 toIcal,
  expandRecurrence:       expandRecurrence,
  CalendarError:          CalendarError,
  JSCAL_TYPES:            JSCAL_TYPES,
  JSCAL_FREQUENCIES:      JSCAL_FREQUENCIES,
  JSCAL_ALERT_ACTIONS:    JSCAL_ALERT_ACTIONS,
  MAX_EXPAND_INSTANCES:   MAX_EXPAND_INSTANCES,
  MAX_EXPAND_SPAN_MS:     MAX_EXPAND_SPAN_MS,
};
