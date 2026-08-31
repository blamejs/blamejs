// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * queue.bootFromEnv — env-driven queue init mirroring
 * network.bootFromEnv. Reads BLAMEJS_QUEUE_* from a supplied fixture env
 * and wires a single `default` backend; idempotent; throws INVALID_CONFIG
 * on an unknown protocol or a redis selection with no URL.
 *
 * Run standalone: `node test/layer-0-primitives/queue.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b              = helpers.b;
var fs             = helpers.fs;
var os             = helpers.os;
var path           = helpers.path;
var check          = helpers.check;
var setupTestDb    = helpers.setupTestDb;
var teardownTestDb = helpers.teardownTestDb;

function _tmp() { return fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-q-cov-")); }

function testBootFromEnvRejectsUnknownProtocol() {
  b.queue._resetForTest();
  var threw = null;
  try { b.queue.bootFromEnv({ env: { BLAMEJS_QUEUE_PROTOCOL: "wibble" } }); } catch (e) { threw = e; }
  check("queue.bootFromEnv rejects an unknown protocol", threw && threw.code === "queue/invalid-config");
  // The failed boot left the queue uninitialized (the throw was pre-init).
  var listThrew = null;
  try { b.queue.listBackends(); } catch (e) { listThrew = e; }
  check("queue stays uninitialized after a rejected boot",
        listThrew && listThrew.code === "queue/not-initialized");
}

function testBootFromEnvRedisRequiresUrl() {
  b.queue._resetForTest();
  var threw = null;
  try { b.queue.bootFromEnv({ env: { BLAMEJS_QUEUE_PROTOCOL: "redis" } }); } catch (e) { threw = e; }
  check("queue.bootFromEnv redis without URL throws INVALID_CONFIG",
        threw && threw.code === "queue/invalid-config");
}

function testBootFromEnvLocalDefault() {
  b.queue._resetForTest();
  try {
    b.queue.bootFromEnv({ env: { BLAMEJS_QUEUE_PROTOCOL: "local" } });
    var backends = b.queue.listBackends();
    check("queue.bootFromEnv local wires exactly one backend", backends.length === 1);
    check("queue.bootFromEnv local backend is named 'default' with protocol 'local'",
          backends[0].name === "default" && backends[0].protocol === "local");

    // Idempotent — a second boot after init is a no-op.
    b.queue.bootFromEnv({ env: { BLAMEJS_QUEUE_PROTOCOL: "local" } });
    check("queue.bootFromEnv is idempotent after init",
          b.queue.listBackends().length === 1);
  } finally {
    b.queue._resetForTest();
  }
}

function testBootFromEnvDefaultsToLocal() {
  b.queue._resetForTest();
  try {
    // No BLAMEJS_QUEUE_PROTOCOL → defaults to the local protocol.
    b.queue.bootFromEnv({ env: {} });
    var backends = b.queue.listBackends();
    check("queue.bootFromEnv defaults to the local protocol when unset",
          backends.length === 1 && backends[0].protocol === "local");
  } finally {
    b.queue._resetForTest();
  }
}

// ---- init: idempotency + required backends ----

function testInitRequiresBackends() {
  b.queue._resetForTest();
  var threw = null;
  try { b.queue.init(); } catch (e) { threw = e; }
  check("init() with no opts throws INVALID_CONFIG", threw && threw.code === "queue/invalid-config");

  threw = null;
  try { b.queue.init({}); } catch (e) { threw = e; }
  check("init({}) without backends throws INVALID_CONFIG", threw && threw.code === "queue/invalid-config");
  b.queue._resetForTest();
}

async function testInitIsIdempotent() {
  var tmpDir = _tmp();
  b.queue._resetForTest();
  await setupTestDb(tmpDir);
  try {
    b.queue.init({ backends: { primary: { protocol: "local" } }, defaultBackend: "primary" });
    check("init wires one backend", b.queue.listBackends().length === 1);
    check("init defaultBackend honored", b.queue.listBackends()[0].name === "primary");
    check("init: breakerState reported closed at boot",
          b.queue.listBackends()[0].breakerState === "closed");
    // A second init with a DIFFERENT config is a no-op (already initialized).
    b.queue.init({ backends: { other: { protocol: "local" } } });
    var names = b.queue.listBackends().map(function (r) { return r.name; });
    check("init is idempotent — second init does not replace backends",
          names.length === 1 && names[0] === "primary");
  } finally {
    try { await b.queue.shutdown({ timeoutMs: 500 }); } catch (_e) {}
    await teardownTestDb(tmpDir);
    b.queue._resetForTest();
  }
}

// ---- enqueue → consume → size → purge (the mutating-op wrappers) ----

async function testEnqueueConsumeLifecycle() {
  var tmpDir = _tmp();
  b.queue._resetForTest();
  await setupTestDb(tmpDir);
  try {
    // No defaultBackend given → _backendFor falls back to the first key.
    b.queue.init({ backends: { primary: { protocol: "local" } } });

    var r1 = await b.queue.enqueue("life-q", { id: "a" });
    check("enqueue resolves with a jobId", typeof r1.jobId === "string" && r1.jobId.length > 0);
    await b.queue.enqueue("life-q", { id: "b" });
    await b.queue.enqueue("life-q", { id: "c" });

    check("size reports pending backlog", (await b.queue.size("life-q")) === 3);

    var seen = [];
    // concurrency 1 forces the slots<=0 fast-poll branch between jobs.
    var consumer = b.queue.consume("life-q",
      async function (job) { seen.push(job.payload.id); },
      { concurrency: 1, pollIntervalMs: 25, fastPollMs: 5 });
    await helpers.waitUntil(function () { return seen.length >= 3; }, {
      timeoutMs: 5000, label: "queue lifecycle: all 3 jobs processed",
    });
    consumer.cancel();

    check("consume ran the handler for every job", seen.length === 3 &&
          seen.indexOf("a") !== -1 && seen.indexOf("b") !== -1 && seen.indexOf("c") !== -1);
    check("size drops to 0 after drain", (await b.queue.size("life-q")) === 0);

    // Enqueue more without a consumer, then purge.
    await b.queue.enqueue("purge-q", { id: 1 });
    await b.queue.enqueue("purge-q", { id: 2 });
    var deleted = await b.queue.purge("purge-q");
    check("purge returns the deleted count", deleted === 2);
    check("size is 0 after purge", (await b.queue.size("purge-q")) === 0);
  } finally {
    try { await b.queue.shutdown({ timeoutMs: 500 }); } catch (_e) {}
    await teardownTestDb(tmpDir);
    b.queue._resetForTest();
  }
}

// ---- consume: failure → retry (willRetry true) → DLQ (willRetry false) ----

async function testConsumeFailureRetryAndDlq() {
  var tmpDir = _tmp();
  b.queue._resetForTest();
  await setupTestDb(tmpDir);
  try {
    b.queue.init({ backends: { primary: { protocol: "local" } } });

    var attempts = 0;
    var consumer = b.queue.consume("doomed-q",
      async function () { attempts++; throw new Error("boom #" + attempts); },
      { concurrency: 1, pollIntervalMs: 20, fastPollMs: 10, leaseDurationMs: 5000 });

    // maxAttempts 2 → attempt 1 re-pends (willRetry true, deterministic
    // backoff), attempt 2 exhausts the budget (willRetry false → DLQ write).
    await b.queue.enqueue("doomed-q", { id: 1 }, { maxAttempts: 2 });

    await helpers.waitUntil(function () { return attempts >= 2; }, {
      timeoutMs: 8000, label: "queue failure: handler retried (willRetry-true path)",
    });
    await helpers.waitUntil(function () {
      var row = b.db.prepare("SELECT status FROM _blamejs_jobs WHERE queueName = 'doomed-q'").get();
      return row && row.status === "failed";
    }, { timeoutMs: 8000, label: "queue failure: job reached failed status" });
    consumer.cancel();

    check("consume retried before exhausting attempts (willRetry-true branch)", attempts >= 2);
    check("dlqSize reports the exhausted job", (await b.queue.dlqSize("doomed-q")) === 1);

    var dead = await b.queue.dlqList("doomed-q");
    check("dlqList returns the failed job", dead.length === 1 && dead[0].payload.id === 1);
    check("dlqList surfaces the last error", typeof dead[0].lastError === "string" &&
          dead[0].lastError.indexOf("boom") !== -1);

    var ok = await b.queue.dlqRetry(dead[0].jobId);
    check("dlqRetry resets the job to pending (returns true)", ok === true);
    check("dlqSize is 0 after retry", (await b.queue.dlqSize("doomed-q")) === 0);

    // dlqRetry on an unknown id returns false (no audit emit).
    check("dlqRetry unknown id returns false",
          (await b.queue.dlqRetry("no-such-job")) === false);
  } finally {
    try { await b.queue.shutdown({ timeoutMs: 500 }); } catch (_e) {}
    await teardownTestDb(tmpDir);
    b.queue._resetForTest();
  }
}

// ---- consume ctx: extendLease + progress ----

async function testConsumeCtxExtendLeaseAndProgress() {
  var tmpDir = _tmp();
  b.queue._resetForTest();
  await setupTestDb(tmpDir);
  try {
    b.queue.init({ backends: { primary: { protocol: "local" } } });
    await b.queue.enqueue("ctx-q", { id: "x" });

    var extended = null;
    var done = false;
    var consumer = b.queue.consume("ctx-q",
      async function (_job, ctx) {
        ctx.progress(0);            // start marker (always emits)
        ctx.progress(50);           // may throttle — allowed
        extended = await ctx.extendLease(60 * 1000);
        ctx.progress(100);          // done marker (always emits)
        done = true;
      },
      { concurrency: 1, pollIntervalMs: 25, fastPollMs: 5, leaseDurationMs: 2000 });

    await helpers.waitUntil(function () { return done; }, {
      timeoutMs: 4000, label: "queue ctx: handler completed",
    });
    consumer.cancel();
    check("ctx.extendLease returns true while inflight", extended === true);
  } finally {
    try { await b.queue.shutdown({ timeoutMs: 500 }); } catch (_e) {}
    await teardownTestDb(tmpDir);
    b.queue._resetForTest();
  }
}

// ---- consume rate-limit: the wait>0 throttle path ----

async function testConsumeRateLimitThrottles() {
  var tmpDir = _tmp();
  b.queue._resetForTest();
  await setupTestDb(tmpDir);
  try {
    b.queue.init({ backends: { primary: { protocol: "local" } } });
    await b.queue.enqueue("rl-cov-q", { id: 1 });
    await b.queue.enqueue("rl-cov-q", { id: 2 });

    var startedAt = Date.now();
    var doneAt = [];
    var consumer = b.queue.consume("rl-cov-q",
      async function () { doneAt.push(Date.now() - startedAt); },
      { concurrency: 4, rateLimit: { max: 1, perSeconds: 1 },
        pollIntervalMs: 25, fastPollMs: 5 });

    await helpers.waitUntil(function () { return doneAt.length >= 2; }, {
      timeoutMs: 6000, label: "queue rate-limit: both jobs drained",
    });
    consumer.cancel();
    check("rateLimit: both jobs eventually processed", doneAt.length === 2);
    // max 1 per second → the second handler starts a full window later.
    check("rateLimit: second job deferred past the window (wait>0 branch)",
          doneAt[1] >= 900);
  } finally {
    try { await b.queue.shutdown({ timeoutMs: 500 }); } catch (_e) {}
    await teardownTestDb(tmpDir);
    b.queue._resetForTest();
  }
}

// ---- enqueue / consume input validation + unknown backend ----

async function testMutatingOpsValidation() {
  var tmpDir = _tmp();
  b.queue._resetForTest();
  await setupTestDb(tmpDir);
  try {
    b.queue.init({ backends: { primary: { protocol: "local" } } });

    var threw = null;
    try { await b.queue.enqueue(); } catch (e) { threw = e; }
    check("enqueue without queueName throws MISSING_QUEUE", threw && threw.code === "queue/missing-queue");

    threw = null;
    try { b.queue.enqueue("q", {}, { backend: "ghost" }); } catch (e) { threw = e; }
    check("enqueue with unknown backend throws UNKNOWN_BACKEND",
          threw && threw.code === "queue/unknown-backend");

    threw = null;
    try { b.queue.consume(); } catch (e) { threw = e; }
    check("consume without queueName throws MISSING_QUEUE", threw && threw.code === "queue/missing-queue");

    threw = null;
    try { b.queue.consume("q", "not-a-fn"); } catch (e) { threw = e; }
    check("consume with a non-function handler throws INVALID_HANDLER",
          threw && threw.code === "queue/invalid-handler");
  } finally {
    try { await b.queue.shutdown({ timeoutMs: 500 }); } catch (_e) {}
    await teardownTestDb(tmpDir);
    b.queue._resetForTest();
  }
}

// ---- shutdown: pre-init no-op + drains in-flight ----

async function testShutdownBeforeInitIsNoop() {
  b.queue._resetForTest();
  // Not initialized → shutdown returns immediately without throwing.
  await b.queue.shutdown();
  check("shutdown before init is a no-op", true);
}

async function testShutdownDrainsInFlight() {
  var tmpDir = _tmp();
  b.queue._resetForTest();
  await setupTestDb(tmpDir);
  try {
    b.queue.init({ backends: { primary: { protocol: "local" } } });
    await b.queue.enqueue("drain-q", { id: 1 });

    var started = false;
    var finished = false;
    b.queue.consume("drain-q",
      async function () {
        started = true;
        await helpers.passiveObserve(120, "queue shutdown: handler in flight during shutdown");
        finished = true;
      },
      { concurrency: 1, pollIntervalMs: 20, fastPollMs: 5 });

    await helpers.waitUntil(function () { return started; }, {
      timeoutMs: 4000, label: "queue shutdown: handler started",
    });
    // shutdown cancels consumers and waits for the in-flight handler to drain.
    await b.queue.shutdown({ timeoutMs: 3000 });
    check("shutdown waited for the in-flight handler to finish", finished === true);
  } finally {
    try { await b.queue.shutdown({ timeoutMs: 500 }); } catch (_e) {}
    await teardownTestDb(tmpDir);
    b.queue._resetForTest();
  }
}

// ---- enqueueFlow: happy chain + validation surface ----

async function testEnqueueFlowLinearChain() {
  var tmpDir = _tmp();
  b.queue._resetForTest();
  await setupTestDb(tmpDir);
  try {
    b.queue.init({ backends: { primary: { protocol: "local" } } });

    var ord = [];
    var consumer = b.queue.consume("flow-cov-q",
      async function (job) { ord.push(job.payload.tag); },
      { concurrency: 4, pollIntervalMs: 25, fastPollMs: 5 });

    var flow = await b.queue.enqueueFlow({
      queueName: "flow-cov-q",
      children: [
        { name: "fetch",     payload: { tag: "fetch" } },
        { name: "transform", payload: { tag: "transform" }, dependsOn: ["fetch"], priority: 1 },
        { name: "publish",   payload: { tag: "publish" }, dependsOn: ["transform"],
          maxAttempts: 3, classification: "c", traceId: "t" },
      ],
    });
    check("enqueueFlow returns a flowId", typeof flow.flowId === "string" &&
          flow.flowId.indexOf("flow-") === 0);
    check("enqueueFlow returns one entry per child", flow.jobs.length === 3);

    await helpers.waitUntil(function () { return ord.length === 3; }, {
      timeoutMs: 6000, label: "queue flow: chain drained",
    });
    consumer.cancel();
    check("enqueueFlow honors dependency order",
          ord[0] === "fetch" && ord[1] === "transform" && ord[2] === "publish");
  } finally {
    try { await b.queue.shutdown({ timeoutMs: 500 }); } catch (_e) {}
    await teardownTestDb(tmpDir);
    b.queue._resetForTest();
  }
}

async function testEnqueueFlowValidation() {
  var tmpDir = _tmp();
  b.queue._resetForTest();
  await setupTestDb(tmpDir);
  try {
    b.queue.init({ backends: { primary: { protocol: "local" } } });

    async function code(label, spec, expectFragment) {
      var threw = null;
      try { await b.queue.enqueueFlow(spec); } catch (e) { threw = e; }
      check(label, threw && threw.code === "queue/bad-flow" &&
            (!expectFragment || threw.message.indexOf(expectFragment) !== -1));
    }
    await code("flow: rejects a non-object spec", "nope");
    await code("flow: rejects a missing queueName", { children: [] });
    await code("flow: rejects empty children", { queueName: "q", children: [] });
    await code("flow: rejects a non-object child", { queueName: "q", children: ["x"] });
    await code("flow: rejects a child with no name",
               { queueName: "q", children: [{ payload: {} }] });
    await code("flow: rejects a duplicate child name",
               { queueName: "q", children: [{ name: "a", payload: {} }, { name: "a", payload: {} }] },
               "duplicate");
    await code("flow: rejects a non-array dependsOn",
               { queueName: "q", children: [{ name: "a", payload: {}, dependsOn: "b" }] });
    await code("flow: rejects a non-string dependsOn element",
               { queueName: "q", children: [{ name: "a", payload: {}, dependsOn: [42] }] });

    // Cycle + unknown-dep detection.
    var threw = null;
    try {
      await b.queue.enqueueFlow({ queueName: "q", children: [
        { name: "a", payload: {}, dependsOn: ["b"] },
        { name: "b", payload: {}, dependsOn: ["a"] },
      ]});
    } catch (e) { threw = e; }
    check("flow: detects a cycle (FLOW_CYCLE)", threw && threw.code === "queue/flow-cycle");

    threw = null;
    try {
      await b.queue.enqueueFlow({ queueName: "q", children: [
        { name: "a", payload: {}, dependsOn: ["ghost"] },
      ]});
    } catch (e) { threw = e; }
    check("flow: rejects an unknown dependency (FLOW_UNKNOWN_DEP)",
          threw && threw.code === "queue/flow-unknown-dep");
  } finally {
    try { await b.queue.shutdown({ timeoutMs: 500 }); } catch (_e) {}
    await teardownTestDb(tmpDir);
    b.queue._resetForTest();
  }
}

// ---- sqs backend: the "unsupported" ternary-falsy + reject branches ----
// The sqs adapter creates without network (no connect at create), and it
// deliberately omits sweepExpired / dlqList / dlqRetry / dlqSize /
// patchFlowDeps — driving the falsy side of init's ternaries plus the
// DLQ_UNSUPPORTED / FLOW_UNSUPPORTED reject paths.

async function testSqsBackendUnsupportedSurfaces() {
  b.queue._resetForTest();
  try {
    b.queue.init({ backends: { s: {
      protocol:        "sqs",
      region:          "us-east-1",
      accessKeyId:     "AKIAEXAMPLE",
      secretAccessKey: "secretExampleKey",
      accountId:       "123456789012",
    } } });
    check("sqs backend registers and reports its protocol",
          b.queue.listBackends()[0].protocol === "sqs");

    async function rejectsCode(label, p, expectedCode) {
      var threw = null;
      try { await p; } catch (e) { threw = e; }
      check(label, threw && threw.code === expectedCode);
    }
    await rejectsCode("sqs: dlqList rejects DLQ_UNSUPPORTED",
                      b.queue.dlqList("q"), "queue/dlq-unsupported");
    await rejectsCode("sqs: dlqRetry rejects DLQ_UNSUPPORTED",
                      b.queue.dlqRetry("job-1"), "queue/dlq-unsupported");
    await rejectsCode("sqs: dlqSize rejects DLQ_UNSUPPORTED",
                      b.queue.dlqSize("q"), "queue/dlq-unsupported");
    await rejectsCode("sqs: enqueueFlow rejects FLOW_UNSUPPORTED",
                      b.queue.enqueueFlow({ queueName: "q", children: [{ name: "a", payload: {} }] }),
                      "queue/flow-unsupported");
    // tick drives the framework-side lifecycle — lease by count, complete/fail
    // by jobId, framework backoff and DLQ. SQS completes by receiptHandle and
    // owns redelivery server-side, so tick would call complete/fail without the
    // receipt and let SQS redeliver messages the handler already processed.
    // It refuses for the same reason consume does not drive sqs either.
    await rejectsCode("sqs: tick rejects TICK_UNSUPPORTED",
                      b.queue.tick({ queue: "q", handler: function () {} }),
                      "queue/tick-unsupported");
  } finally {
    b.queue._resetForTest();
  }
}

// ---- bootFromEnv: redis wiring (the redis config-build branch) ----

function testBootFromEnvRedisWiresBackend() {
  b.queue._resetForTest();
  try {
    b.queue.bootFromEnv({ env: {
      BLAMEJS_QUEUE_PROTOCOL:       "redis",
      BLAMEJS_QUEUE_REDIS_URL:      "redis://localhost:6379/0",
      BLAMEJS_QUEUE_REDIS_PASSWORD: "pw",
      BLAMEJS_QUEUE_REDIS_USERNAME: "user",
      BLAMEJS_QUEUE_REDIS_TLS:      "1",
      BLAMEJS_QUEUE_REDIS_KEY_PREFIX: "myapp:q",
    } });
    var backends = b.queue.listBackends();
    check("bootFromEnv redis wires one backend", backends.length === 1);
    check("bootFromEnv redis backend has protocol 'redis'", backends[0].protocol === "redis");
  } finally {
    b.queue._resetForTest();
  }
}

// #576 — b.queue.tick: drain what is due, then return. The shape a scheduled
// invocation needs, where a resident consumer and a background timer are the
// two things the runtime cannot host.
async function testTickDrainsAndReturns() {
  var tmpDir = _tmp();
  b.queue._resetForTest();
  await setupTestDb(tmpDir);
  try {
    b.queue.init({ backends: { primary: { protocol: "local" } } });
    for (var i = 0; i < 5; i++) await b.queue.enqueue("tick-q", { id: i });

    var seen = [];
    var r = await b.queue.tick({
      queue:   "tick-q",
      max:     3,
      handler: async function (job) { seen.push(job.payload.id); },
    });

    check("tick: leases at most max", r.leased === 3 && seen.length === 3);
    check("tick: counts successes", r.succeeded === 3 && r.failed === 0);
    check("tick: reports the queue depth", r.queueDepth === 2);
    // The batch came back full, so more may be due — this is the tick-again
    // signal, not the depth, which also counts jobs that are not yet available.
    check("tick: a full batch signals there may be more", r.mayHaveMore === true);

    // Nothing resident: no consumer was registered, so a shutdown has nothing
    // to drain and returns immediately. This is the property the issue is
    // about — consume() would have left a loop and a sweep timer behind.
    var second = await b.queue.tick({
      queue:   "tick-q",
      max:     10,
      handler: async function (job) { seen.push(job.payload.id); },
    });
    check("tick: a second tick drains the rest", second.leased === 2 && second.succeeded === 2);
    check("tick: the depth reaches zero", second.queueDepth === 0);
    check("tick: a short batch signals no more", second.mayHaveMore === false);
    check("tick: every job ran exactly once",
      seen.slice().sort().join(",") === "0,1,2,3,4");

    var empty = await b.queue.tick({
      queue: "tick-q", handler: async function () {},
    });
    check("tick: an empty queue is not an error",
      empty.leased === 0 && empty.succeeded === 0 &&
      empty.queueDepth === 0 && empty.mayHaveMore === false);
  } finally {
    await b.queue.shutdown({ timeoutMs: 2000 });
    await teardownTestDb(tmpDir);
  }
}

// A delayed job is counted by the queue's depth but is not leasable yet. A
// caller looping on depth would spin through empty ticks until it came due, so
// the tick-again signal is whether the batch came back FULL, not the depth.
// A backend that REFUSES to record the outcome — complete or fail rejecting
// after its own retries — leaves the job inflight and this tick not knowing
// whether the handler succeeded. Counting that as an ordinary handler failure
// would report a terminal state the job never reached AND bury an
// infrastructure problem in a routine tally.
async function testTickReportsAnUnsettledJob() {
  var tmpDir = _tmp();
  b.queue._resetForTest();
  await setupTestDb(tmpDir);
  try {
    b.queue.init({ backends: { primary: { protocol: "local" } } });
    await b.queue.enqueue("tick-unsettled-q", { id: 1 });

    // Break the settle path underneath the driver, the way an exhausted
    // breaker or a dead database does.
    var backend = b.queue._backendForTest({});
    var realComplete = backend.complete;
    backend.complete = function () { return Promise.reject(new Error("store unreachable")); };
    var r;
    try {
      r = await b.queue.tick({
        queue: "tick-unsettled-q", handler: async function () { /* succeeds */ },
      });
    } finally { backend.complete = realComplete; }

    check("unsettled: the tick still resolves", r && r.leased === 1);
    check("unsettled: it is not counted as a handler failure", r.failed === 0);
    check("unsettled: it is reported as unsettled", r.unsettled === 1);
    check("unsettled: and not as a success", r.succeeded === 0);
  } finally {
    await b.queue.shutdown({ timeoutMs: 2000 });
    await teardownTestDb(tmpDir);
  }
}

// tick promises to leave nothing running, but init starts a 30-second sweep
// timer of its own. In a frozen isolate that timer either never fires or fires
// inside a LATER invocation, touching the backend outside any request the
// platform accounts for — so a scheduled runtime needs to turn it off, and
// tick's own per-invocation sweep means nothing is lost by doing so.
async function testInitCanRunWithoutASweepTimer() {
  var tmpDir = _tmp();
  b.queue._resetForTest();
  await setupTestDb(tmpDir);
  try {
    b.queue.init({
      backends:        { primary: { protocol: "local" } },
      sweepIntervalMs: 0,
    });
    await b.queue.enqueue("no-timer-q", { id: 1 });
    var r = await b.queue.tick({ queue: "no-timer-q", handler: async function () {} });
    check("timerless init: tick still drains the queue", r.leased === 1 && r.succeeded === 1);
  } finally {
    await b.queue.shutdown({ timeoutMs: 2000 });
    await teardownTestDb(tmpDir);
  }

  b.queue._resetForTest();
  var bad = null;
  try {
    b.queue.init({ backends: { primary: { protocol: "local" } }, sweepIntervalMs: -1 });
  } catch (e) { bad = e; }
  check("timerless init: a negative sweep interval is refused",
    bad && bad.code === "queue/invalid-config");
  b.queue._resetForTest();
  var frac = null;
  try {
    b.queue.init({ backends: { primary: { protocol: "local" } }, sweepIntervalMs: 1.5 });
  } catch (e) { frac = e; }
  check("timerless init: a fractional sweep interval is refused",
    frac && frac.code === "queue/invalid-config");

  // The refusal must leave NOTHING behind. `backends` and `defaultBackend` are
  // module-level and a later init does not clear them, so validating after
  // assignment would leave the rejected configuration's queues visible through
  // listBackends() and selectable by name.
  var leaked = null;
  try { b.queue.listBackends(); } catch (e) { leaked = e; }
  check("timerless init: a refused init registered no backends",
    leaked && leaked.code === "queue/not-initialized");
  b.queue._resetForTest();
}

async function testTickDelayedJobDoesNotLoop() {
  var tmpDir = _tmp();
  b.queue._resetForTest();
  await setupTestDb(tmpDir);
  try {
    b.queue.init({ backends: { primary: { protocol: "local" } } });
    await b.queue.enqueue("tick-delay-q", { id: "now" });
    await b.queue.enqueue("tick-delay-q", { id: "later" }, { delaySeconds: 3600 });

    var r = await b.queue.tick({
      queue: "tick-delay-q", max: 10, handler: async function () {},
    });
    check("delayed: the due job ran", r.leased === 1 && r.succeeded === 1);
    check("delayed: the depth still counts the delayed job", r.queueDepth === 1);
    // The signal that matters: the batch was NOT full, so there is nothing
    // more to take right now even though the depth is non-zero.
    check("delayed: mayHaveMore is false despite a non-zero depth",
      r.mayHaveMore === false);
  } finally {
    await b.queue.shutdown({ timeoutMs: 2000 });
    await teardownTestDb(tmpDir);
  }
}

// An invocation that dies between leasing a job and settling it leaves that
// job inflight. What normally re-pends it is the 30-second sweep timer started
// at init — and that timer never fires in the runtime tick exists for, because
// the isolate is frozen between invocations. So tick has to sweep for itself,
// or a killed invocation strands its job permanently.
async function testTickRecoversAnAbandonedLease() {
  var tmpDir = _tmp();
  b.queue._resetForTest();
  await setupTestDb(tmpDir);
  try {
    b.queue.init({ backends: { primary: { protocol: "local" } } });
    await b.queue.enqueue("tick-abandon-q", { id: "stranded" });

    // Strand the job the way a killed invocation does: lease it with a lease
    // that expires almost immediately and never settle it. A consumer whose
    // handler never resolves, then cancelled, leaves exactly that row state —
    // inflight, lease expired, nothing coming to complete or fail it.
    var never = new Promise(function () { /* deliberately never settles */ });
    var consumer = b.queue.consume("tick-abandon-q",
      function () { return never; },
      { concurrency: 1, leaseDurationMs: 1, pollIntervalMs: 10, fastPollMs: 5 });
    await helpers.waitUntil(function () { return consumer.inFlight.size === 1; }, {
      timeoutMs: 4000, label: "tick abandon: the job was leased",
    });
    consumer.cancel();
    // Past the 1ms lease — the row is now an expired inflight with no owner.
    await helpers.passiveObserve(60, "tick abandon: the lease expires unsettled");

    // The sweep timer would recover this after 30s, but a scheduled runtime is
    // frozen between invocations and never runs it. tick sweeps for itself, so
    // the abandoned job is leasable again on the next invocation.
    var handled = [];
    var r = await b.queue.tick({
      queue:   "tick-abandon-q",
      handler: async function (job) { handled.push(job.payload.id); },
    });
    check("abandon: tick recovers a job whose lease expired unsettled",
      r.leased === 1 && r.succeeded === 1 && handled[0] === "stranded");
    check("abandon: nothing is left behind", r.queueDepth === 0);
  } finally {
    await b.queue.shutdown({ timeoutMs: 2000 });
    await teardownTestDb(tmpDir);
  }
}

// A failing handler must take the same route consume() takes: attempt
// accounting, deterministic backoff, and the DLQ once the attempts run out.
// That machinery is the reason the issue exists — a caller who cannot reach it
// reimplements it.
async function testTickAppliesRetryAndDlq() {
  var tmpDir = _tmp();
  b.queue._resetForTest();
  await setupTestDb(tmpDir);
  try {
    b.queue.init({ backends: { primary: { protocol: "local" } } });
    await b.queue.enqueue("tick-fail-q", { id: "boom" }, { maxAttempts: 1 });

    var r = await b.queue.tick({
      queue:   "tick-fail-q",
      handler: async function () { throw new Error("handler exploded"); },
    });
    check("tick: a throwing handler counts as failed", r.leased === 1 && r.failed === 1);
    check("tick: an exhausted job moves to the DLQ", r.movedToDlq === 1);

    var dlq = await b.queue.dlqList("tick-fail-q");
    check("tick: the failed job is queryable in the DLQ", dlq.length === 1);
  } finally {
    await b.queue.shutdown({ timeoutMs: 2000 });
    await teardownTestDb(tmpDir);
  }
}

// tick is async, so its refusals REJECT rather than throw synchronously.
async function testTickValidation() {
  b.queue._resetForTest();
  var uninit = null;
  try { await b.queue.tick({ queue: "q", handler: function () {} }); } catch (e) { uninit = e; }
  check("tick: refuses before init", uninit && uninit.code === "queue/not-initialized");
}

async function testTickOptionRefusals() {
  var tmpDir = _tmp();
  b.queue._resetForTest();
  await setupTestDb(tmpDir);
  try {
    b.queue.init({ backends: { primary: { protocol: "local" } } });
    async function code(opts) {
      try { await b.queue.tick(opts); return null; } catch (e) { return e.code; }
    }
    check("tick: refuses a missing queue",
      (await code({ handler: function () {} })) === "queue/missing-queue");
    check("tick: refuses a missing handler",
      (await code({ queue: "q" })) === "queue/invalid-handler");
    check("tick: refuses a non-integer max",
      (await code({ queue: "q", handler: function () {}, max: 1.5 })) === "queue/bad-max");
    check("tick: refuses a zero max",
      (await code({ queue: "q", handler: function () {}, max: 0 })) === "queue/bad-max");
    check("tick: refuses a negative leaseMs",
      (await code({ queue: "q", handler: function () {}, leaseMs: -1 })) === "queue/bad-lease");
    check("tick: refuses a zero concurrency",
      (await code({ queue: "q", handler: function () {}, concurrency: 0 })) === "queue/bad-concurrency");
  } finally {
    await b.queue.shutdown({ timeoutMs: 2000 });
    await teardownTestDb(tmpDir);
  }
}

async function run() {
  await testTickDrainsAndReturns();
  await testTickReportsAnUnsettledJob();
  await testInitCanRunWithoutASweepTimer();
  await testTickDelayedJobDoesNotLoop();
  await testTickRecoversAnAbandonedLease();
  await testTickAppliesRetryAndDlq();
  await testTickValidation();
  await testTickOptionRefusals();
  testBootFromEnvRejectsUnknownProtocol();
  testBootFromEnvRedisRequiresUrl();
  testBootFromEnvLocalDefault();
  testBootFromEnvDefaultsToLocal();
  testBootFromEnvRedisWiresBackend();
  testInitRequiresBackends();
  await testInitIsIdempotent();
  await testEnqueueConsumeLifecycle();
  await testConsumeFailureRetryAndDlq();
  await testConsumeCtxExtendLeaseAndProgress();
  await testConsumeRateLimitThrottles();
  await testMutatingOpsValidation();
  await testShutdownBeforeInitIsNoop();
  await testShutdownDrainsInFlight();
  await testEnqueueFlowLinearChain();
  await testEnqueueFlowValidation();
  await testSqsBackendUnsupportedSurfaces();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[queue] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e); process.exit(1); }
  );
}
