// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
var helpers = require("../helpers");
var b = helpers.b;
var check = helpers.check;

async function run() {
  var now = Date.now();
  var d = b.breach.deadline.forStates(["CA", "TX"], now);
  check("forStates returns 2", d.length === 2);
  var ca = d.filter(function (e) { return e.state === "CA"; })[0];
  var tx = d.filter(function (e) { return e.state === "TX"; })[0];
  check("CA is asap kind", ca.kind === "as-soon-as-possible");
  check("TX is hard-deadline kind", tx.kind === "hard-deadline");
  check("TX 60-day deadline", tx.dueBy === now + 60 * 24 * 60 * 60 * 1000);

  var threwUnknown = false;
  try { b.breach.deadline.forStates(["XX"], now); }
  catch (e) { threwUnknown = e.code === "breach/unknown-state"; }
  check("forStates refuses unknown state", threwUnknown);

  var reporter = b.breach.report.create({ audit: false });
  var rec = reporter.open({
    detectedAt: now,
    affectedStates: ["CA", "NY"],
    impact: { individualsAffected: 5000 },
  });
  check("report.open returns id", typeof rec.id === "string");
  check("report tracks two states", rec.affectedStates.length === 2);

  // The register handed its own record back unfrozen, so a caller could assign
  // to any field after `open` had validated it: writing `closedAt`, or
  // emptying `deadlines`, edited the register's view of a statutory clock and
  // the next roll-up read the edited value. `open`, `get`, `list` and
  // `fileNotice` answer with a frozen copy, and `fileNotice` stays the only way
  // to add a filing. The two sibling registers, b.gdpr.ropa and
  // b.incident.report, are sealed the same way.
  try { rec.closedAt = 1; } catch (_e) { /* frozen in strict mode */ }
  check("assigning closedAt on the returned record does not reach the register",
    reporter.get(rec.id).closedAt === null,
    String(reporter.get(rec.id).closedAt));
  try { rec.deadlines.length = 0; } catch (_e) { /* frozen */ }
  check("and the deadlines array cannot be emptied through it",
    reporter.get(rec.id).deadlines.length === 2,
    String(reporter.get(rec.id).deadlines.length));
  try { rec.deadlines[0].days = 999; } catch (_e) { /* frozen */ }
  check("nor can a single deadline be rewritten",
    reporter.get(rec.id).deadlines[0].days !== 999,
    String(reporter.get(rec.id).deadlines[0].days));
  try { reporter.get(rec.id).filings.CA = { forged: true }; } catch (_e) { /* frozen */ }
  check("nor a filing forged into what get() answers",
    Object.keys(reporter.get(rec.id).filings).length === 0,
    JSON.stringify(Object.keys(reporter.get(rec.id).filings)));

  // A filing carries whatever the operator recorded. A generic deep walk
  // turned a Date into {} and a Buffer into numeric keys, and a value
  // referring back to itself recursed until it threw, after the filing had
  // already been recorded.
  // `filedAt` is the register's own stamp, so the operator's Date goes in a
  // field of its own.
  var ackedAt = new Date("2026-05-24T01:15:00.000Z");
  var evidence = Buffer.from("receipt-bytes");
  var cyclic = { label: "chain" };
  cyclic.self = cyclic;
  // ArrayBuffer.isView covers DataView, which has no slice(), so a DataView
  // threw out of the copy after the filing had been recorded and left get()
  // and list() throwing too. A bare ArrayBuffer is not a view at all, so the
  // generic object walk read no keys off it and stored an empty object.
  var view = new DataView(new ArrayBuffer(4));
  view.setUint32(0, 0x01020304);
  var rawBytes = Uint8Array.from([9, 8, 7]).buffer;
  // A value built in another realm, which is what a vm context or a worker
  // hands back, has a different constructor, so `instanceof` answers no for it
  // and the generic object walk read no keys off it.
  var elsewhere = require("node:vm").runInNewContext(
    "({ when: new Date(1700000000000), bytes: new Uint8Array([4, 5, 6]) })");
  // An own `__proto__` key, which a JSON-parsed filing can carry, must stay an
  // own key: assigning it on the copy would set the prototype instead.
  var injected = JSON.parse('{"__proto__": {"injected": true}, "keep": 1}');
  await reporter.fileNotice(rec.id, "CA", {
    method: "email", ackedAt: ackedAt, evidence: evidence, chain: cyclic,
    view: view, rawBytes: rawBytes, elsewhere: elsewhere, injected: injected,
  });
  // The operator's own fields are kept under `payload`.
  var caPayload = reporter.get(rec.id).filings.CA.payload;
  check("a Date in a filing survives the copy",
    caPayload.ackedAt instanceof Date &&
    caPayload.ackedAt.getTime() === ackedAt.getTime(),
    JSON.stringify(caPayload.ackedAt));
  check("and a Buffer survives it as bytes",
    Buffer.isBuffer(caPayload.evidence) &&
    caPayload.evidence.toString() === "receipt-bytes",
    JSON.stringify(caPayload.evidence));
  check("and a DataView survives it rather than failing the filing",
    caPayload.view instanceof DataView && caPayload.view.getUint32(0) === 0x01020304,
    String(caPayload.view && caPayload.view.constructor.name));
  check("and an ArrayBuffer survives it as bytes",
    caPayload.rawBytes instanceof ArrayBuffer &&
    new Uint8Array(caPayload.rawBytes).join(",") === "9,8,7",
    JSON.stringify(caPayload.rawBytes));
  check("an own __proto__ key survives the copy as an own key",
    Object.prototype.hasOwnProperty.call(caPayload.injected, "__proto__") &&
    caPayload.injected.keep === 1,
    JSON.stringify(caPayload.injected));
  check("and it did not become the copy's prototype",
    Object.getPrototypeOf(caPayload.injected) === Object.prototype &&
    caPayload.injected.injected === undefined,
    String(caPayload.injected.injected));
  check("a Date from another realm survives as a Date",
    caPayload.elsewhere.when instanceof Date &&
    caPayload.elsewhere.when.getTime() === 1700000000000,
    JSON.stringify(caPayload.elsewhere.when));
  check("and bytes from another realm survive as bytes",
    Array.from(caPayload.elsewhere.bytes || []).join(",") === "4,5,6",
    JSON.stringify(caPayload.elsewhere.bytes));
  view.setUint32(0, 0);
  check("and the stored view is a copy rather than an alias",
    caPayload.view.getUint32(0) === 0x01020304,
    String(caPayload.view.getUint32(0)));
  check("and a self-referring value is readable rather than throwing",
    caPayload.chain.label === "chain" && caPayload.chain.self === caPayload.chain,
    String(caPayload.chain && caPayload.chain.label));
  check("the copy is still frozen",
    Object.isFrozen(caPayload.chain), String(Object.isFrozen(caPayload.chain)));
  check("get() and list() still answer after a cyclic filing",
    reporter.get(rec.id) !== null && reporter.list().length >= 1);
  check("after one filing, one pending", reporter.pending(rec.id).length === 1);
  // The control: filing through the sanctioned path does reach the register,
  // so the seal above is not refusing every write.
  check("and fileNotice is still the path that records one",
    Object.keys(reporter.get(rec.id).filings).join(",") === "CA",
    JSON.stringify(Object.keys(reporter.get(rec.id).filings)));

  await reporter.fileNotice(rec.id, "NY", { method: "email" });
  check("after both filings, none pending", reporter.pending(rec.id).length === 0);
  check("breach closed after all filed",   reporter.get(rec.id).closedAt !== null);

  // ---- running clock (composes incident.report.createDeadlineClock) ----
  // Injected clock so escalation timing is deterministic, no wall-clock sleep.
  var detectedAt = 0;
  var clockNow = detectedAt;
  var events = [];

  var clockReporter = b.breach.report.create({ audit: false, now: function () { return clockNow; } });
  var clockRec = clockReporter.open({
    detectedAt: detectedAt,
    affectedStates: ["CA", "TX"],   // CA = asap-ceiling 60d, TX = hard 60d
    impact: { individualsAffected: 9000 },
  });

  var clock = b.breach.deadline.createClock({
    audit:    false,
    autoStart: false,
    approachThresholds: [0.5, 0.9],
    notify:   { send: function (p) { events.push(p); } },
    now:      function () { return clockNow; },
  });

  var trackedId = clock.trackReport(clockRec);
  check("trackReport returns the breach id", trackedId === clockRec.id);
  check("clock tracks both states", clock.status().tracked === 2);
  check("clock counts one breach",  clock.status().breaches === 1);

  // Day 0: nothing has elapsed, no escalation.
  clock.tick();
  check("no escalation at detection time", events.length === 0);

  // Advance past the 50% threshold of the 60-day window (31 days).
  clockNow = detectedAt + 31 * 24 * 60 * 60 * 1000;
  clock.tick();
  var approaching = events.filter(function (e) { return e.kind === "deadline_approaching"; });
  check("approaching fired for both states at 50%", approaching.length === 2);

  // Re-ticking at the same proportion must NOT re-fire (once per phase).
  var beforeReTick = events.length;
  clock.tick();
  check("approaching does not re-fire on repeat tick", events.length === beforeReTick);

  // Acknowledge CA's filing — CA must go silent even past its deadline.
  clock.acknowledgeSubmission(clockRec.id, "ca");

  // Advance past the deadline (61 days). TX should fire "passed"; CA must not.
  clockNow = detectedAt + 61 * 24 * 60 * 60 * 1000;
  clock.tick();
  var passed = events.filter(function (e) { return e.kind === "deadline_passed"; });
  check("exactly one state fired passed (TX, not acked CA)", passed.length === 1);
  check("passed carries the statute regime", typeof passed[0].regime === "string" && passed[0].regime.length > 0);

  var ackUnknownThrew = false;
  try { clock.acknowledgeSubmission(clockRec.id, "NY"); }
  catch (e) { ackUnknownThrew = e.code === "breach-clock/unknown-tracked-state"; }
  check("acknowledgeSubmission refuses an untracked state", ackUnknownThrew);

  var badReportThrew = false;
  try { clock.trackReport({ id: 42 }); }
  catch (e) { badReportThrew = e.code === "breach-clock/bad-report"; }
  check("trackReport refuses a non-record", badReportThrew);

  check("untrack removes the breach", clock.untrack(clockRec.id) === true);
  check("clock empty after untrack", clock.status().tracked === 0);

  // Auto-start timer path: poll the notify sink (no fixed-budget sleep).
  var autoEvents = [];
  var autoNow = 0;
  var autoReporter = b.breach.report.create({ audit: false, now: function () { return autoNow; } });
  var autoRec = autoReporter.open({ detectedAt: 0, affectedStates: ["TX"], impact: {} });
  autoNow = 61 * 24 * 60 * 60 * 1000;   // already past TX's 60-day wall
  var autoClock = b.breach.deadline.createClock({
    audit:    false,
    autoStart: true,
    intervalMs: 10,
    notify:   { send: function (p) { autoEvents.push(p); } },
    now:      function () { return autoNow; },
  });
  autoClock.trackReport(autoRec);
  await helpers.waitUntil(function () {
    return autoEvents.some(function (e) { return e.kind === "deadline_passed"; });
  }, { timeoutMs: 5000, label: "breach-clock: auto-tick fires deadline_passed" });
  check("auto-tick timer fired the passed alert", true);
  autoClock.stop();
  check("clock stops cleanly", autoClock.status().running === false);
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK — breach-deadline tests"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
