// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
var helpers = require("../helpers");
var b = helpers.b;
var check = helpers.check;

async function run() {
  var ir = b.incident.report.create({ audit: false });
  var rec = await ir.open({ regime: "gdpr", detectedAt: Date.now() });
  check("incident.open returns id", typeof rec.id === "string");
  check("incident.open sets dueBy",  typeof rec.dueBy.initial === "number");
  check("incident.open uses regime deadlines", rec.dueBy.intermediate === rec.detectedAt + 72 * 60 * 60 * 1000);
  await ir.recordInitial(rec.id, { foo: "bar" });
  await ir.recordIntermediate(rec.id, { foo: "bar" });
  await ir.recordFinal(rec.id, { foo: "bar" });
  check("incident.list returns one", ir.list().length === 1);
  check("incident.status reports closed", ir.status().closed === 1);

  var threwBadStage = false;
  try { await ir.recordInitial(rec.id, {}); }
  catch (e) { threwBadStage = e.code === "incident-report/stage-already-filed"; }
  check("incident refuses double-file", threwBadStage);

  var ir2 = b.incident.report.create({ audit: false });
  var threwBadSpec = false;
  try { await ir2.open({}); } catch (e) { threwBadSpec = e.code === "incident-report/bad-regime"; }
  check("incident.open refuses bad spec", threwBadSpec);

  // ---- createDeadlineClock — running-clock approaching/passed alerts ----
  // Manual-tick mode (autoStart:false) keeps the test deterministic and
  // sleep-free; thresholds fire as the injected "now" crosses fractions
  // of each stage deadline.
  check("createDeadlineClock is fn", typeof b.incident.report.createDeadlineClock === "function");

  var sent = [];
  var clk = b.incident.report.createDeadlineClock({
    notify: { send: function (m) { sent.push(m); } },
    autoStart: false,
    approachThresholds: [0.5, 0.9],
  });
  // detectedAt=0; stage deadlines initial=100, intermediate=200, final=300.
  clk.track({ id: "inc-1", detectedAt: 0, regime: "gdpr", dueBy: { initial: 100, intermediate: 200, final: 300 } });
  check("deadline clock: tracked=1", clk.status().tracked === 1);

  clk.tick(50);   // 50% of initial → approaching@0.5
  check("tick@50: one approaching@0.5 (initial)",
    sent.length === 1 && sent[0].kind === "deadline_approaching" &&
    sent[0].stage === "initial" && sent[0].threshold === 0.5);

  clk.tick(55);   // still <0.9 of initial → dedupe, no new alert
  check("tick@55: dedupe (no new alert)", sent.length === 1);

  clk.tick(95);   // 95% of initial → approaching@0.9
  check("tick@95: approaching@0.9 fires", sent.length === 2 && sent[1].threshold === 0.9);

  clk.tick(150);  // initial(100) passed
  check("tick@150: initial passed fires once",
    sent.filter(function (m) { return m.kind === "deadline_passed" && m.stage === "initial"; }).length === 1);

  clk.tick(160);  // no duplicate passed for initial
  check("tick@160: no duplicate passed",
    sent.filter(function (m) { return m.kind === "deadline_passed" && m.stage === "initial"; }).length === 1);

  // Acknowledging a stage suppresses its further alerts.
  clk.acknowledgeSubmission("inc-1", "intermediate");
  clk.tick(250);  // intermediate(200) would be passed, but acked → suppressed
  check("acknowledged stage: no passed alert",
    sent.filter(function (m) { return m.stage === "intermediate" && m.kind === "deadline_passed"; }).length === 0);

  // Construction-time + track-time input validation.
  var badThresh = false;
  try { b.incident.report.createDeadlineClock({ approachThresholds: [1.5] }); }
  catch (e) { badThresh = /between 0 and 1/.test(e.message); }
  check("createDeadlineClock rejects threshold > 1", badThresh);

  var badTrack = false;
  try { clk.track({ id: "x" }); } catch (e) { badTrack = /dueBy/.test(e.message); }
  check("deadline clock: track without dueBy rejected", badTrack);

  // Faster regime crosses before slower one on the same tick
  // (registry windows differ — DORA vs GDPR here).
  var sent2 = [];
  var clk2 = b.incident.report.createDeadlineClock({
    notify: { send: function (m) { sent2.push(m); } }, autoStart: false,
  });
  clk2.track({ id: "dora-1", detectedAt: 0, regime: "dora", dueBy: { initial: 4, intermediate: 8, final: 12 } });
  clk2.track({ id: "gdpr-1", detectedAt: 0, regime: "gdpr", dueBy: { initial: 72, intermediate: 100, final: 200 } });
  clk2.tick(5);  // DORA initial(4) passed; GDPR initial(72) only ~7% → nothing
  check("deadline clock: faster regime crosses first",
    sent2.filter(function (m) { return m.incidentId === "dora-1" && m.kind === "deadline_passed"; }).length === 1 &&
    sent2.filter(function (m) { return m.incidentId === "gdpr-1"; }).length === 0);
  clk2.stop();

  // ================================================================
  // Branch-coverage extension — reporter + deadline-clock paths.
  // Deterministic: injected `now` for all deadline math, manual
  // `tick(nowMs)` for the clock, no real timers except one clock we
  // stop() immediately. Operator callbacks (persist / onStage /
  // notify.send) are passed as real functions — including ones that
  // throw / reject — to exercise the drop-silent catches.
  // ================================================================

  var H = 60 * 60 * 1000;                                                       // one hour (ms)
  var D = 24 * H;                                                               // one day  (ms)

  // Capture sink for the reporter's audit stream — b.audit.namespaced
  // routes to opts.audit.sink when it exposes safeEmit(evt).
  function makeSink() {
    return { events: [], safeEmit: function (e) { this.events.push(e); } };
  }
  // Async-throw asserter: resolves true iff fn() rejects with .code === code.
  async function expectCode(fn, code) {
    try { await fn(); return false; }
    catch (e) { return !!e && e.code === code; }
  }
  // Sync-throw asserter for the clock's synchronous validators.
  function expectSyncCode(fn, code) {
    try { fn(); return false; }
    catch (e) { return !!e && e.code === code; }
  }

  // ---- open() spec validation (bad-spec / bad-regime / bad-detected-at) ----
  var irV = b.incident.report.create({ audit: false });
  check("open(null) -> bad-spec",
    await expectCode(function () { return irV.open(null); }, "incident-report/bad-spec"));
  check("open(42) -> bad-spec",
    await expectCode(function () { return irV.open(42); }, "incident-report/bad-spec"));
  check("open() undefined -> bad-spec",
    await expectCode(function () { return irV.open(); }, "incident-report/bad-spec"));
  check("open regime empty string -> bad-regime",
    await expectCode(function () { return irV.open({ regime: "", detectedAt: 0 }); }, "incident-report/bad-regime"));
  check("open regime non-string -> bad-regime",
    await expectCode(function () { return irV.open({ regime: 5, detectedAt: 0 }); }, "incident-report/bad-regime"));
  check("open detectedAt non-number -> bad-detected-at",
    await expectCode(function () { return irV.open({ regime: "gdpr", detectedAt: "nope" }); }, "incident-report/bad-detected-at"));
  check("open detectedAt Infinity -> bad-detected-at",
    await expectCode(function () { return irV.open({ regime: "gdpr", detectedAt: Infinity }); }, "incident-report/bad-detected-at"));
  check("recordInitial unknown id -> unknown-incident",
    await expectCode(function () { return irV.recordInitial("no-such-incident", {}); }, "incident-report/unknown-incident"));

  // ---- deadline override merge (per-field number vs regime base) + stored fields ----
  var irD = b.incident.report.create({ audit: false, deadlines: { initial: 1000, intermediate: "nope", final: 2000 } });
  var dRec = await irD.open({ regime: "gdpr", detectedAt: 0, scope: "confidentiality", summary: "s", impact: { dataSubjects: 5 } });
  check("deadline override: numeric initial overrides base", dRec.dueBy.initial === 1000);
  check("deadline override: non-number intermediate falls to regime base", dRec.dueBy.intermediate === 72 * H);
  check("deadline override: numeric final overrides base", dRec.dueBy.final === 2000);
  check("open stores provided scope/summary/impact (truthy defaults)",
    dRec.scope === "confidentiality" && dRec.summary === "s" && dRec.impact.dataSubjects === 5);

  // Non-object deadlines override -> regime base used verbatim.
  var irND = b.incident.report.create({ audit: false, deadlines: 42 });
  var ndRec = await irND.open({ regime: "gdpr", detectedAt: 0 });
  check("non-object deadlines override -> regime base used",
    ndRec.dueBy.initial === 24 * H && ndRec.dueBy.final === 30 * D);
  // The seal walks the record, so a chain of nested containers used to exhaust
  // the stack. The RangeError came out of the copy AFTER the stage had been
  // assigned, and because the register copies on every read, that one filing
  // left every later get() and list() raising it too: the whole register was
  // unreadable for the life of the process.
  var deepRopa = b.incident.report.create({ audit: false });
  var deepRec = await deepRopa.open({ regime: "gdpr", detectedAt: 0 });
  var chain = {};
  var tip = chain;
  for (var dd = 0; dd < 12000; dd++) { tip.next = {}; tip = tip.next; }
  var deepErr = null;
  try { await deepRopa.recordInitial(deepRec.id, { chain: chain }); }
  catch (e) { deepErr = e; }
  check("a record nested past the seal's bound is refused with a code",
    deepErr !== null && deepErr.code === "incident-report/record-too-deep",
    deepErr ? String(deepErr.code || deepErr.constructor.name) : "accepted");
  var stillReadable = true;
  try { deepRopa.list(); deepRopa.get(deepRec.id); }
  catch (_e) { stillReadable = false; }
  check("and the register is still readable afterwards", stillReadable);
  var afterDeep = await deepRopa.recordInitial(deepRec.id, { note: "ok" });
  check("and the stage it refused is still free to file",
    afterDeep !== null && afterDeep.stages.initial.payload.note === "ok");

  // The 12,000-level case above flies past the bound by so far that it cannot
  // see the boundary, where the first fix was wrong: it measured the stage
  // ENTRY, but a read copies the whole record, which wraps that entry under
  // `stages` two levels deeper. A payload in the band between the two depths
  // therefore passed the check, was stored, and poisoned every later read.
  // Walk the band: each depth either files and stays readable, or refuses and
  // stays readable, and neither leaves the register unreadable.
  function _chainOf(n) {
    var head = {};
    var t = head;
    for (var i = 0; i < n; i++) { t.next = {}; t = t.next; }
    return head;
  }
  // open() stores the record and then sealed it for the return, so a deep
  // `scope` poisoned the register the same way a deep stage payload did. The
  // bound is 512, measured against a real ceiling of 5858 for this copy shape,
  // so an ordinary deeply-nested record still files: a 70-level scope is
  // accepted, which is what it did before the bound existed.
  var openRep = b.incident.report.create({ audit: false });
  var openErr = null;
  try { await openRep.open({ regime: "gdpr", detectedAt: 0, scope: _chainOf(700) }); }
  catch (e) { openErr = e; }
  check("open() refuses a scope past the bound before storing it",
    openErr !== null && openErr.code === "incident-report/record-too-deep",
    openErr ? String(openErr.code) : "accepted");
  var openReadable = true;
  try { openRep.list(); } catch (_e) { openReadable = false; }
  check("and the register is still readable after that refusal", openReadable);
  var ordinary = await openRep.open({ regime: "gdpr", detectedAt: 0, scope: _chainOf(70) });
  check("while an ordinary nested scope still opens", ordinary !== null && !!ordinary.id);

  // open() made the copy for the depth check and then stored the original, so
  // the register still held references reachable from the caller's spec: an
  // incident could drift after it was opened, and a later persistence call
  // carried the drifted values.
  var driftRep = b.incident.report.create({ audit: false });
  var systems = ["billing"];
  var driftRec = await driftRep.open({
    regime: "gdpr", detectedAt: 0, scope: { systems: systems }, impact: { subjects: 5 },
  });
  systems.push("injected");
  check("a scope array passed to open cannot be grown afterwards",
    driftRep.get(driftRec.id).scope.systems.length === 1,
    JSON.stringify(driftRep.get(driftRec.id).scope.systems));

  // The stage snapshot used structuredClone, which turns a Buffer into a
  // Uint8Array. The two have different JSON forms, so a filing submitted once
  // and then resubmitted from the stored payload sent `{"type":"Buffer",...}`
  // the first time and `{"0":97,...}` the second, for the same evidence, and a
  // persist callback saw whichever it happened to be handed.
  var bufRep = b.incident.report.create({ audit: false });
  var bufInc = await bufRep.open({ regime: "nis2", detectedAt: 0 });
  var filedBuf = await bufRep.recordInitial(bufInc.id, { evidence: Buffer.from("abc") });
  var storedBuf = bufRep.get(bufInc.id).stages.initial.payload.evidence;
  check("a Buffer in a filing is still a Buffer when read back",
    Buffer.isBuffer(storedBuf), Object.prototype.toString.call(storedBuf));
  check("and its JSON form matches what the first submission sent",
    JSON.stringify(storedBuf) === JSON.stringify(filedBuf.stages.initial.payload.evidence),
    JSON.stringify(storedBuf).slice(0, 60));
  check("and the bytes are intact",
    Buffer.from(storedBuf).toString("utf8") === "abc",
    Buffer.from(storedBuf).toString("utf8"));

  // A RegExp was the one type the copy returned by reference. structuredClone
  // had been detaching it, so taking that out left the caller holding the
  // stored evidence: compile() rewrites the pattern the record says was filed,
  // and an ordinary exec() moves its lastIndex.
  var reRep = b.incident.report.create({ audit: false });
  var reInc = await reRep.open({ regime: "gdpr", detectedAt: 0 });
  var callerRe = /secret/g;
  await reRep.recordInitial(reInc.id, { pattern: callerRe });
  var storedRe = reRep.get(reInc.id).stages.initial.payload.pattern;
  check("a RegExp in a filing comes back as a RegExp, not the caller's own",
    storedRe instanceof RegExp && storedRe !== callerRe,
    Object.prototype.toString.call(storedRe));
  callerRe.compile("replaced", "i");
  var afterCompile = reRep.get(reInc.id).stages.initial.payload.pattern;
  check("recompiling the caller's expression does not rewrite the filing",
    afterCompile.source === "secret" && afterCompile.flags === "g",
    "/" + afterCompile.source + "/" + afterCompile.flags);
  callerRe.lastIndex = 99;
  check("and its lastIndex is not shared with the record",
    reRep.get(reInc.id).stages.initial.payload.pattern.lastIndex !== 99,
    String(reRep.get(reInc.id).stages.initial.payload.pattern.lastIndex));

  for (var depth = 58; depth <= 66; depth++) {
    var bRep = b.incident.report.create({ audit: false });
    var bInc = await bRep.open({ regime: "gdpr", detectedAt: 0 });
    var bErr = null;
    try { await bRep.recordInitial(bInc.id, { chain: _chainOf(depth) }); }
    catch (e) { bErr = e; }
    check("depth " + depth + ": either filed or refused with a code, never a RangeError",
      bErr === null || bErr.code === "incident-report/record-too-deep",
      bErr ? String(bErr.code || bErr.constructor.name) : "filed");
    var bReadable = true;
    try { bRep.list(); bRep.get(bInc.id); } catch (_e) { bReadable = false; }
    check("depth " + depth + ": the register is readable either way", bReadable);
  }

  // get() answered with the stored record, so a caller holding one could
  // assign to any field and change the register's view of a statutory clock.
  var fetched = irND.get(ndRec.id);
  check("get(existing) answers with an equal record",
    fetched !== null && fetched.id === ndRec.id &&
    fetched.dueBy.initial === ndRec.dueBy.initial);
  check("and it is a frozen copy rather than the stored record",
    fetched !== ndRec && Object.isFrozen(fetched) && Object.isFrozen(fetched.dueBy),
    "same=" + (fetched === ndRec) + " frozen=" + Object.isFrozen(fetched));
  try { fetched.closedAt = 1; } catch (_e) { /* frozen under strict mode */ }
  check("so editing the answer does not close the incident",
    irND.get(ndRec.id).closedAt === null,
    String(irND.get(ndRec.id).closedAt));
  check("list() answers with copies too",
    irND.list().every(function (r) { return Object.isFrozen(r); }));
  check("get(unknown) returns null", irND.get("nope") === null);

  // `audit` takes false, true, or a configuration object carrying a sink. A
  // string or a number read as "not false" and left the events on while the
  // configuration said they were off, so those are refused. The sink-object
  // form above is the reason this is not a plain boolean check.
  [["a string", "false"], ["a number", 0], ["an array", []]].forEach(function (bad) {
    var refused = null;
    try { b.incident.report.create({ audit: bad[1] }); } catch (e) { refused = e; }
    check("incident.report.create refuses an audit option given " + bad[0],
      !!refused && refused.code === "incident-report/bad-opt",
      bad[0] + " -> " + (refused ? refused.code : "accepted"));
  });

  // ---- persist reject: drop-silent, emits persist_failed audit (open + stage) ----
  var pSink = makeSink();
  var irP = b.incident.report.create({
    audit:   { sink: pSink },
    persist: async function () { throw new Error("db down"); },
  });
  var pRec = await irP.open({ regime: "nis2", detectedAt: 1000 });
  check("persist reject on open does not throw (drop-silent)", !!pRec && typeof pRec.id === "string");
  check("persist_failed audit on open (no stage in metadata)",
    pSink.events.some(function (e) {
      return e.action === "incident.report.persist_failed" && e.outcome === "failure" && !e.metadata.stage;
    }));
  var pRec2 = await irP.recordInitial(pRec.id, { x: 1 });
  check("persist reject on stage does not throw (drop-silent)", !!pRec2 && !!pRec2.stages.initial);
  check("persist_failed audit on stage (metadata.stage set)",
    pSink.events.some(function (e) {
      return e.action === "incident.report.persist_failed" && e.metadata.stage === "initial";
    }));

  // ---- persist + onStage success paths (both callbacks invoked) ----
  var persistCalls = [];
  var onStageEvents = [];
  var irOk = b.incident.report.create({
    audit:   false,
    persist: async function (r) { persistCalls.push(r.id); },
    onStage: function (ev) { onStageEvents.push(ev); },
  });
  var okRec = await irOk.open({ regime: "gdpr", detectedAt: 0 });
  await irOk.recordInitial(okRec.id, { a: 1 });
  check("persist invoked on open + stage (success path)",
    persistCalls.length === 2 && persistCalls[0] === okRec.id && persistCalls[1] === okRec.id);
  check("onStage invoked with full event shape",
    onStageEvents.length === 1 && onStageEvents[0].incidentId === okRec.id &&
    onStageEvents[0].stage === "initial" && typeof onStageEvents[0].dueBy === "number" &&
    onStageEvents[0].regime === "gdpr" && onStageEvents[0].fields.a === 1);
  // Omitted payload defaults to {} in the stored stage record.
  var noPayloadRec = await irOk.recordIntermediate(okRec.id);
  check("stage payload defaults to {} when omitted",
    !!noPayloadRec.stages.intermediate && typeof noPayloadRec.stages.intermediate.payload === "object" &&
    Object.keys(noPayloadRec.stages.intermediate.payload).length === 0);

  // ---- onStage throw is drop-silent (record still succeeds) ----
  var irThrow = b.incident.report.create({
    audit:   false,
    onStage: function () { throw new Error("hook boom"); },
  });
  var tRec = await irThrow.open({ regime: "gdpr", detectedAt: 0 });
  var onStageThrowOk = true;
  try { await irThrow.recordInitial(tRec.id, {}); } catch (_e) { onStageThrowOk = false; }
  check("onStage throw is drop-silent (record still filed)",
    onStageThrowOk && !!irThrow.get(tRec.id).stages.initial);

  // ---- deadline math (late vs on-time) + audit outcome + status() counting ----
  var sSink = makeSink();
  var nowRef = { v: 1000 };
  var irC = b.incident.report.create({ audit: { sink: sSink }, now: function () { return nowRef.v; } });

  // On-time filing: now well before the initial deadline.
  var onTime = await irC.open({ regime: "gdpr", detectedAt: 0 });               // dueBy.initial = 24h
  nowRef.v = 1000;
  var otRec = await irC.recordInitial(onTime.id, { note: "early" });
  check("on-time stage: late=false, lateBy=0",
    otRec.stages.initial.late === false && otRec.stages.initial.lateBy === 0);
  check("on-time stage: audit outcome success",
    sSink.events.some(function (e) {
      return e.action === "incident.report.stage_recorded" && e.outcome === "success" && e.metadata.late === false;
    }));

  // Late filing: advance now past the initial deadline.
  var lateInc = await irC.open({ regime: "gdpr", detectedAt: 0 });
  nowRef.v = 90000000;                                                          // > 24h (86400000)
  var lateRec = await irC.recordInitial(lateInc.id, { note: "late" });
  check("late stage: late=true, lateBy = now - dueBy",
    lateRec.stages.initial.late === true && lateRec.stages.initial.lateBy === (90000000 - 24 * H));
  check("late stage: audit outcome late",
    sSink.events.some(function (e) {
      return e.action === "incident.report.stage_recorded" && e.outcome === "late" && e.metadata.late === true;
    }));

  // status(): open counting + late[stage] counting across both incidents.
  // Advance now past the intermediate deadline (259.2M) but before final.
  nowRef.v = 300000000;
  var st = irC.status();
  check("status: 2 open, 0 closed (no final filed)", st.open === 2 && st.closed === 0);
  check("status: late.initial counts the late filing", st.late.initial === 1);
  check("status: late.intermediate counts unfiled past-due (both)", st.late.intermediate === 2);
  check("status: late.final not yet late", st.late.final === 0);

  // ================================================================
  // createDeadlineClock — remaining branch coverage.
  // ================================================================

  // Injected now: tick() with no arg uses now(); tick(n) uses n.
  var nowRefK = { v: 0 };
  var sentK = [];
  var clkNow = b.incident.report.createDeadlineClock({
    notify:             { send: function (m) { sentK.push(m); } },
    autoStart:          false,
    approachThresholds: [0.5],
    now:                function () { return nowRefK.v; },
  });
  clkNow.track({ id: "cn-1", detectedAt: 0, regime: "gdpr", dueBy: { initial: 100, intermediate: 200, final: 300 } });
  nowRefK.v = 60;                                                               // 60% of initial -> approaching@0.5
  clkNow.tick();                                                               // no arg -> uses now()
  check("clock injected now: tick() uses now() (approaching fired)",
    sentK.length === 1 && sentK[0].kind === "deadline_approaching" && sentK[0].stage === "initial");
  clkNow.stop();

  // Clock without notify: tick past a deadline must not throw (_notify no-op).
  var clkNoNotify = b.incident.report.createDeadlineClock({ audit: false, autoStart: false });
  clkNoNotify.track({ id: "nn-1", detectedAt: 0, dueBy: { initial: 100, intermediate: 200, final: 300 } });
  var noNotifyOk = true;
  try { clkNoNotify.tick(150); } catch (_e) { noNotifyOk = false; }
  check("clock without notify: tick past deadline does not throw", noNotifyOk);
  clkNoNotify.stop();

  // track() without regime -> payload regime is null.
  var sentR = [];
  var clkNoRegime = b.incident.report.createDeadlineClock({
    notify: { send: function (m) { sentR.push(m); } }, autoStart: false,
  });
  clkNoRegime.track({ id: "nr-1", detectedAt: 0, dueBy: { initial: 100, intermediate: 200, final: 300 } });
  clkNoRegime.tick(150);
  check("clock track without regime: notify payload regime is null",
    sentR.some(function (m) { return m.incidentId === "nr-1" && m.regime === null; }));
  clkNoRegime.stop();

  // track() bad-record: bad / missing / empty id.
  var clkT = b.incident.report.createDeadlineClock({ autoStart: false });
  check("track(null) -> bad-record",
    expectSyncCode(function () { clkT.track(null); }, "incident-report/bad-record"));
  check("track({}) missing id -> bad-record",
    expectSyncCode(function () { clkT.track({}); }, "incident-report/bad-record"));
  check("track({ id: '' }) empty id -> bad-record",
    expectSyncCode(function () { clkT.track({ id: "" }); }, "incident-report/bad-record"));
  clkT.stop();

  // acknowledgeSubmission bad-stage / unknown-incident / success.
  var clkA = b.incident.report.createDeadlineClock({ autoStart: false });
  clkA.track({ id: "ack-1", detectedAt: 0, regime: "gdpr", dueBy: { initial: 100, intermediate: 200, final: 300 } });
  check("acknowledgeSubmission bad stage -> bad-stage",
    expectSyncCode(function () { clkA.acknowledgeSubmission("ack-1", "bogus"); }, "incident-report/bad-stage"));
  check("acknowledgeSubmission unknown incident -> unknown-incident",
    expectSyncCode(function () { clkA.acknowledgeSubmission("no-such", "initial"); }, "incident-report/unknown-incident"));
  check("acknowledgeSubmission success returns true", clkA.acknowledgeSubmission("ack-1", "initial") === true);
  clkA.stop();

  // _notify drop-silent: notify.send throws synchronously.
  var clkThrow = b.incident.report.createDeadlineClock({
    notify: { send: function () { throw new Error("notify boom"); } }, autoStart: false,
  });
  clkThrow.track({ id: "th-1", detectedAt: 0, regime: "gdpr", dueBy: { initial: 100, intermediate: 200, final: 300 } });
  var notifyThrowOk = true;
  try { clkThrow.tick(150); } catch (_e) { notifyThrowOk = false; }
  check("notify.send throw is drop-silent (tick does not throw)", notifyThrowOk);
  clkThrow.stop();

  // _notify drop-silent: notify.send returns a rejected thenable (rejection swallowed).
  var clkRej = b.incident.report.createDeadlineClock({
    notify: { send: function () { return Promise.reject(new Error("async notify boom")); } }, autoStart: false,
  });
  clkRej.track({ id: "rj-1", detectedAt: 0, regime: "gdpr", dueBy: { initial: 100, intermediate: 200, final: 300 } });
  var notifyRejOk = true;
  try { clkRej.tick(150); } catch (_e) { notifyRejOk = false; }
  check("notify.send rejected thenable is swallowed (tick does not throw)", notifyRejOk);
  clkRej.stop();

  // tick loop skips: zero-span stage (due == detectedAt) and missing-dueBy stage.
  var sentSpan = [];
  var clkSpan = b.incident.report.createDeadlineClock({
    notify: { send: function (m) { sentSpan.push(m); } }, autoStart: false, approachThresholds: [0.5],
  });
  clkSpan.track({ id: "sp-1", detectedAt: 100, regime: "gdpr", dueBy: { initial: 100, final: 300 } });
  clkSpan.tick(100);   // initial: span 0 -> skipped; intermediate: due undefined -> skipped
  check("clock: zero-span stage skipped (no initial alert despite now>=due)",
    sentSpan.filter(function (m) { return m.stage === "initial"; }).length === 0);
  check("clock: missing-dueBy stage skipped (no intermediate alert)",
    sentSpan.filter(function (m) { return m.stage === "intermediate"; }).length === 0);
  clkSpan.tick(300);   // final: normal stage still fires
  check("clock: normal stage still fires (final passed)",
    sentSpan.filter(function (m) { return m.stage === "final" && m.kind === "deadline_passed"; }).length === 1);
  clkSpan.stop();

  // Real-timer clock: default autoStart runs an (unref'd) interval; start()
  // is a no-op when already running; stop() clears it. 1h interval never
  // ticks during the test, and stop() releases the timer.
  var clkReal = b.incident.report.createDeadlineClock({ audit: false, intervalMs: 60 * 60 * 1000 });
  check("createDeadlineClock autoStart default: running", clkReal.status().running === true);
  clkReal.start();                                                             // timer already set -> if (timer) return
  check("start() when already running is a no-op (still running)", clkReal.status().running === true);
  clkReal.stop();                                                              // clearInterval -> timer null
  check("stop() clears the interval (not running)", clkReal.status().running === false);

  // ---- residual branch coverage ----

  // Unknown-but-valid regime string -> DEFAULT_DEADLINES fallback (not registry).
  var irUnknown = b.incident.report.create({ audit: false });
  var uRec = await irUnknown.open({ regime: "operator-custom", detectedAt: 0 });
  check("unknown regime falls back to DEFAULT_DEADLINES",
    uRec.dueBy.initial === 24 * H && uRec.dueBy.intermediate === 72 * H && uRec.dueBy.final === 30 * D);

  // Override merge, complementary sides: non-number initial/final fall to base,
  // number intermediate overrides.
  var irMix = b.incident.report.create({ audit: false, deadlines: { initial: "x", intermediate: 500, final: "y" } });
  var mRec = await irMix.open({ regime: "gdpr", detectedAt: 0 });
  check("override complementary: non-number->base (initial/final), number->override (intermediate)",
    mRec.dueBy.initial === 24 * H && mRec.dueBy.intermediate === 500 && mRec.dueBy.final === 30 * D);

  // No-args constructors resolve opts to {}.
  var irBare = b.incident.report.create();
  check("create() with no opts returns a reporter", !!irBare && typeof irBare.open === "function");
  var clkBare = b.incident.report.createDeadlineClock();
  check("createDeadlineClock() with no opts returns a clock", !!clkBare && typeof clkBare.track === "function");
  clkBare.stop();

  // persist throwing a non-Error value -> String(e) branch of the error extractor
  // (both the open catch and the stage catch).
  var strSink = makeSink();
  var irStr = b.incident.report.create({
    audit:   { sink: strSink },
    // Deliberate non-Error throw to exercise the audit's `String(e)` fallback.
    persist: async function () { throw "raw-string-error"; },   // eslint-disable-line no-throw-literal
  });
  var strRec = await irStr.open({ regime: "gdpr", detectedAt: 1000 });
  check("persist non-Error on open: String(e) captured",
    strSink.events.some(function (e) {
      return e.action === "incident.report.persist_failed" && e.metadata.error === "raw-string-error" && !e.metadata.stage;
    }));
  var strRec2 = await irStr.recordInitial(strRec.id, { z: 1 });
  check("persist non-Error on stage: String(e) captured",
    !!strRec2.stages.initial &&
    strSink.events.some(function (e) {
      return e.action === "incident.report.persist_failed" && e.metadata.error === "raw-string-error" && e.metadata.stage === "initial";
    }));

  // A stage keeps a copy of the fields it was filed with. Retaining the
  // caller's object let a report change after the filing that recorded it,
  // and the record is what says the stage was filed with those fields.
  var snapReg = b.incident.report.create({ audit: false });
  var snapInc = await snapReg.open({ regime: "gdpr", detectedAt: Date.now() });
  var fields = { summary: "as filed", affected: { rows: 10 } };
  await snapReg.recordInitial(snapInc.id, fields);
  fields.summary = "mutated after filing";
  fields.affected.rows = 99;
  var filed = snapReg.get(snapInc.id).stages.initial.payload;
  check("a mutated top-level field does not change the filed record",
    filed.summary === "as filed", String(filed.summary));
  check("and neither does a mutated nested one",
    filed.affected.rows === 10, String(filed.affected.rows));
  // The control: the fields really were recorded, so the two checks above are
  // not passing against an empty payload.
  check("the filed record carries the fields it was given",
    Object.keys(filed).length === 2, JSON.stringify(Object.keys(filed)));
  // The copy holds the data, not the classes around it: Dates and cycles
  // survive, and a Buffer arrives as a Uint8Array over the same bytes. A
  // hand-rolled per-key copy was tried instead and lost an own `__proto__`
  // key while assigning its value onto the destination's prototype, so the
  // copy is the one structured clone the rest of the framework uses.
  var typedFields = {
    evidence: Buffer.from("abc"),
    at:       new Date(1700000000000),
    nested:   { more: Buffer.from("de") },
  };
  typedFields.self = typedFields;
  var typedInc = await snapReg.open({ regime: "gdpr", detectedAt: Date.now() });
  await snapReg.recordInitial(typedInc.id, typedFields);
  var typedFiled = snapReg.get(typedInc.id).stages.initial.payload;
  check("the bytes of a Buffer field survive the copy",
    Buffer.from(typedFiled.evidence).toString("utf8") === "abc" &&
    Buffer.from(typedFiled.nested.more).toString("utf8") === "de");
  check("a Date stays a Date", typedFiled.at instanceof Date &&
    typedFiled.at.getTime() === 1700000000000);
  check("a cyclic payload is filed with the cycle intact",
    typedFiled.self === typedFiled);
  typedFields.evidence.write("zz");
  check("and it is a copy, so writing into the caller's Buffer does not reach it",
    Buffer.from(typedFiled.evidence).toString("utf8") === "abc",
    Buffer.from(typedFiled.evidence).toString("utf8"));

  // An own `__proto__` key, which a JSON-parsed report can carry, is kept as
  // an own key and its value does not become inherited state.
  var protoFields = JSON.parse('{"__proto__": {"injected": true}, "keep": 1}');
  var protoInc = await snapReg.open({ regime: "gdpr", detectedAt: Date.now() });
  await snapReg.recordInitial(protoInc.id, protoFields);
  var protoFiled = snapReg.get(protoInc.id).stages.initial.payload;
  check("an own __proto__ key survives the copy",
    Object.prototype.hasOwnProperty.call(protoFiled, "__proto__") &&
    protoFiled.keep === 1,
    JSON.stringify(protoFiled));
  check("and its value is not read back as an inherited field",
    protoFiled.injected === undefined);

  // A payload holding something that cannot be copied is kept by reference
  // rather than emptied, since losing a filing's contents is worse.
  var fnFields = { summary: "with a function", hook: function () {} };
  var fnInc = await snapReg.open({ regime: "gdpr", detectedAt: Date.now() });
  await snapReg.recordInitial(fnInc.id, fnFields);
  check("a payload carrying a function still files with its contents",
    snapReg.get(fnInc.id).stages.initial.payload.summary === "with a function" &&
    typeof snapReg.get(fnInc.id).stages.initial.payload.hook === "function");

  console.log("OK — incident.report " + helpers.getChecks() + " checks passed");
}

module.exports = { run: run };
if (require.main === module) run().catch(function (e) { console.error(e); process.exit(1); });
