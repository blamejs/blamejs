// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.promisePool — bounded-concurrency promise pool.
 */

var helpers = require("../helpers");
var b      = helpers.b;
var check  = helpers.check;

async function testRunsConcurrent() {
  var pool = b.promisePool.create({ concurrency: 3 });
  var observed = 0;
  var peak = 0;
  var tasks = [];
  for (var i = 0; i < 12; i += 1) {
    tasks.push(pool.run(async function () {
      observed += 1;
      if (observed > peak) peak = observed;
      await helpers.passiveObserve(20, "promise-pool: simulated task duration for concurrency-bound test");
      observed -= 1;
      return 1;
    }));
  }
  var results = await Promise.all(tasks);
  check("all 12 tasks completed",         results.length === 12);
  check("results all === 1",              results.every(function (v) { return v === 1; }));
  check("peak in-flight bounded by concurrency", peak <= 3);
  await pool.drain({ close: true });
  check("pool closed",                    pool.closed() === true);
}

async function testDrainWaitsForInFlight() {
  var pool = b.promisePool.create({ concurrency: 2 });
  var resolved = 0;
  for (var i = 0; i < 5; i += 1) {
    pool.run(async function () {
      await helpers.passiveObserve(15, "promise-pool: simulated in-flight work for drain test");
      resolved += 1;
    });
  }
  await pool.drain();
  check("drain waits for everything", resolved === 5);
}

async function testEnqueueOnClosedThrows() {
  var pool = b.promisePool.create({ concurrency: 1 });
  await pool.drain({ close: true });
  var threw = false;
  try { await pool.run(async function () { return 1; }); }
  catch (_e) { threw = true; }
  check("closed pool refuses enqueue", threw);
}

async function testQueueLimitRefuses() {
  var pool = b.promisePool.create({ concurrency: 1, queueLimit: 2 });
  pool.run(async function () {
    await helpers.passiveObserve(40, "promise-pool: simulated slow task for queueLimit test");
    return 1;
  });
  pool.run(async function () { return 1; });
  pool.run(async function () { return 1; });
  var threw = false;
  try { pool.run(async function () { return 1; }); }
  catch (_e) { threw = true; }
  check("queueLimit refuses 4th enqueue", threw);
  await pool.drain({ close: true });
}

// `queueLimit` bounds the WAIT, not the pool. Every task is queued before `_pump`
// starts it, so `queueLimit: 0` made `queue.length >= 0` true on the first call
// and refused every task, including one an idle slot could have run at once,
// while `inFlight()` and `queued()` both read 0. `create` accepts 0, so it has to
// mean something: run it when a slot is free, refuse it when none is.
async function testQueueLimitZeroRunsWhenASlotIsFree() {
  var pool = b.promisePool.create({ concurrency: 2, queueLimit: 0 });
  var ran = await pool.run(function () { return 7; });
  check("queueLimit 0 runs a task while the pool is idle", ran === 7);

  var release = null;
  var held = new Promise(function (r) { release = r; });
  var first  = pool.run(function () { return held; });
  var second = pool.run(function () { return held; });
  var threw = null;
  try { await pool.run(function () { return 1; }); }
  catch (e) { threw = e; }
  check("queueLimit 0 refuses a task when every slot is busy",
    threw !== null && threw.code === "promise-pool/queue-full",
    "code=" + (threw && threw.code));
  release(1);
  await Promise.all([first, second]);

  var after = await pool.run(function () { return 9; });
  check("a freed slot takes a task again", after === 9);
  await pool.drain({ close: true });
}

function testConcurrencyValidation() {
  var threw;
  threw = false; try { b.promisePool.create({ concurrency: 0 }); } catch (_e) { threw = true; }
  check("concurrency=0 throws", threw);

  threw = false; try { b.promisePool.create({ concurrency: 1.5 }); } catch (_e) { threw = true; }
  check("concurrency=1.5 throws", threw);

  threw = false; try { b.promisePool.create({ concurrency: 100000 }); } catch (_e) { threw = true; }
  check("concurrency>65536 throws", threw);

  // The refusal quotes the value the caller passed. It used to be checked as
  // `queueLimit + 1`, so a queueLimit of -1 was reported as 0 and a "3" as "31".
  [[-1, "-1"], [0.5, "0.5"], ["3", '"3"'], [NaN, "NaN"]].forEach(function (row) {
    var err = null;
    try { b.promisePool.create({ concurrency: 2, queueLimit: row[0] }); }
    catch (e) { err = e; }
    check("queueLimit " + String(row[0]) + " is refused, naming that value",
      err !== null && err.code === "promise-pool/bad-queue-limit" &&
      err.message.indexOf("got ") !== -1 &&
      err.message.slice(err.message.indexOf("got ")).indexOf(row[1]) !== -1,
      "message=" + (err && err.message));
  });
  check("queueLimit Infinity is accepted",
    typeof b.promisePool.create({ concurrency: 2, queueLimit: Infinity }).run === "function");

  // PromisePoolError class is reachable as a typed error.
  check("PromisePoolError exported", typeof b.promisePool.PromisePoolError === "function");
}

// `fire` is documented as the fire-and-forget variant for event handlers, so
// the documented call shape discards the promise it returns. It was `run` under
// another name, so one rejecting background task reached unhandledRejection and
// took the process down.
async function testFireContainsARejectingTask() {
  var pool = b.promisePool.create({ concurrency: 2 });
  var unhandled = [];
  function onUnhandled(e) { unhandled.push(e); }
  process.on("unhandledRejection", onUnhandled);
  try {
    var seen = [];
    var pool2 = b.promisePool.create({ concurrency: 2, onFireError: function (e) {
      seen.push((e && e.message) || String(e));
    } });

    pool.fire(function () { throw new Error("sync task blew up"); });
    pool.fire(function () { return Promise.reject(new Error("async task blew up")); });
    pool2.fire(function () { throw new Error("reported task blew up"); });

    await helpers.waitUntil(function () { return seen.length >= 1; },
      { timeoutMs: 2000, label: "promise-pool: onFireError receives the rejection" });
    await pool.drain({ close: true });
    await pool2.drain({ close: true });
    await helpers.passiveObserve(60, "promise-pool: no unhandled rejection follows");

    check("fire does not let a rejecting task reach unhandledRejection",
      unhandled.length === 0,
      unhandled.map(function (e) { return (e && e.message) || String(e); }).join(" ~~ "));
    check("and an onFireError hook is given the error",
      seen.indexOf("reported task blew up") !== -1, JSON.stringify(seen));

    // The reporter is operator code too, so its own failure cannot escape. An
    // async hook that rejects had nowhere to land and took the process down,
    // which is the thing `fire` had just been taught to prevent.
    var asyncHookRan = 0;
    var pool3 = b.promisePool.create({ concurrency: 1, onFireError: async function () {
      asyncHookRan += 1;
      throw new Error("reporter itself failed");
    } });
    pool3.fire(function () { throw new Error("task for the failing reporter"); });
    await helpers.waitUntil(function () { return asyncHookRan >= 1; },
      { timeoutMs: 2000, label: "promise-pool: the async reporter ran" });
    await pool3.drain({ close: true });
    await helpers.passiveObserve(80, "promise-pool: a failing reporter stays contained");
    check("a reporter that rejects asynchronously is contained too",
      unhandled.length === 0,
      unhandled.map(function (e) { return (e && e.message) || String(e); }).join(" ~~ "));

    var syncHookRan = 0;
    var pool4 = b.promisePool.create({ concurrency: 1, onFireError: function () {
      syncHookRan += 1;
      throw new Error("reporter threw synchronously");
    } });
    pool4.fire(function () { throw new Error("task for the throwing reporter"); });
    await helpers.waitUntil(function () { return syncHookRan >= 1; },
      { timeoutMs: 2000, label: "promise-pool: the throwing reporter ran" });
    await pool4.drain({ close: true });
    check("and one that throws synchronously is too",
      unhandled.length === 0,
      unhandled.map(function (e) { return (e && e.message) || String(e); }).join(" ~~ "));

    // The control: run still rejects, because its caller is holding the promise.
    var ran = null;
    try { await b.promisePool.create({ concurrency: 1 }).run(function () { throw new Error("held"); }); }
    catch (e) { ran = e; }
    check("run still rejects for a caller that awaits it",
      ran !== null && /held/.test(ran.message));
  } finally {
    process.removeListener("unhandledRejection", onUnhandled);
  }
}

async function run() {
  await testFireContainsARejectingTask();
  await testRunsConcurrent();
  await testDrainWaitsForInFlight();
  await testEnqueueOnClosedThrows();
  await testQueueLimitRefuses();
  await testQueueLimitZeroRunsWhenASlotIsFree();
  testConcurrencyValidation();
}

if (require.main === module) run().catch(function (e) { console.error(e); process.exit(1); });
module.exports = { run: run };
