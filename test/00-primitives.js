"use strict";
/**
 * Layer 0 — pure primitive smoke tests.
 *
 * These tests exercise primitives with NO framework state and NO I/O
 * dependencies (or I/O confined to tmpdir round-trips). They run FIRST
 * in the smoke-test ordering: a broken primitive should surface here,
 * not as a downstream consumer crash that hides the root cause (per
 * .claude/memory/feedback_test_dependency_order.md).
 *
 * This file is being populated incrementally — each commit moves one
 * functional group from test/smoke.js. When all Layer 0 groups have
 * been migrated, smoke.js's runner block will call ONLY this file's
 * `run()` for Layer 0 work.
 *
 * Currently shipped here:
 *   - sql-safe (identifier validation, quoting, allowlist)
 *   - chain-writer (rejects non-chain-table; race-safety under
 *     concurrent appends)
 *   - async-safe (withTimeout / safeAwait / Mutex / Semaphore /
 *     Once / CircuitBreaker)
 *   - handlers (emit/drain, retry, breaker, DLQ, shutdown, stats,
 *     backpressure, recursion-safe emit-during-flush)
 *   - json-safe (parse / stringify / canonical / validate /
 *     validateCollect / formats — incl. the IPv6 detail tests)
 *
 * Pending migration (still in smoke.js):
 *   - atomic-file / parsers (xml, csv, toml, yaml, env-parse) /
 *     redact (v0.1.19)
 */

var helpers = require("./_helpers");
var b           = helpers.b;
var fs          = helpers.fs;
var os          = helpers.os;
var path        = helpers.path;
var check       = helpers.check;
var setupTestDb = helpers.setupTestDb;
var teardownTestDb = helpers.teardownTestDb;
var listenOnRandomPort = helpers.listenOnRandomPort;

// httpClient tests stand up local http://127.0.0.1 mock servers. The
// framework default is HTTPS-only; tests opt in to cleartext the same
// way an operator with an internal cleartext endpoint would —
// `allowedProtocols: urlSafe.ALLOW_HTTP_ALL`. Wrapping it in this thin
// helper keeps the tests focused on what they're verifying without
// repeating the opt-in 18 times.
function httpReq(opts) {
  return b.httpClient.request(Object.assign(
    { allowedProtocols: b.urlSafe.ALLOW_HTTP_ALL },
    opts
  ));
}

// ---- sql-safe ----

function testSqlSafeIdentifierValidation() {
  // Good shape
  check("sqlSafe.validateIdentifier accepts valid name",
        b.sqlSafe.validateIdentifier("audit_log") === "audit_log");
  check("sqlSafe.validateIdentifier accepts leading underscore",
        b.sqlSafe.validateIdentifier("_blamejs_audit_log") === "_blamejs_audit_log");
  // Bad shape
  var badRejects = [
    ["empty",            ""],
    ["leading digit",    "1foo"],
    ["embedded space",   "foo bar"],
    ["punctuation",      "foo.bar"],
    ["semicolon",        "foo;DROP"],
    ["quote",            'foo"bar'],
    ["backslash",        "foo\\bar"],
    ["null byte",        "foo\0bar"],
  ];
  for (var i = 0; i < badRejects.length; i++) {
    var label = badRejects[i][0];
    var input = badRejects[i][1];
    var threw = false;
    try { b.sqlSafe.validateIdentifier(input); }
    catch (e) { threw = !!e.isSqlSafeError; }
    check("sqlSafe rejects bad identifier (" + label + ")", threw);
  }
  // Reserved word
  var threwReserved = false;
  try { b.sqlSafe.validateIdentifier("SELECT"); }
  catch (e) { threwReserved = e.code === "sql/reserved-word"; }
  check("sqlSafe rejects SQL reserved word",                threwReserved);
  // sqlite_ prefix
  var threwInternal = false;
  try { b.sqlSafe.validateIdentifier("sqlite_master"); }
  catch (e) { threwInternal = e.code === "sql/internal-prefix"; }
  check("sqlSafe rejects sqlite_-prefixed identifier",      threwInternal);
  // Length cap
  var threwLong = false;
  try { b.sqlSafe.validateIdentifier("a".repeat(70)); }
  catch (e) { threwLong = e.code === "sql/too-long"; }
  check("sqlSafe rejects over-long identifier",             threwLong);
}

function testSqlSafeQuoteIdentifier() {
  check("quoteIdentifier sqlite uses double-quote",
        b.sqlSafe.quoteIdentifier("audit_log", "sqlite") === '"audit_log"');
  check("quoteIdentifier postgres uses double-quote",
        b.sqlSafe.quoteIdentifier("audit_log", "postgres") === '"audit_log"');
  check("quoteIdentifier mysql uses backtick",
        b.sqlSafe.quoteIdentifier("audit_log", "mysql") === "`audit_log`");
  var threw = false;
  try { b.sqlSafe.quoteIdentifier("foo;DROP"); }
  catch (e) { threw = !!e.isSqlSafeError; }
  check("quoteIdentifier rejects bad name",                 threw);
}

function testSqlSafeAssertOneOf() {
  var allow = new Set(["audit_log", "consent_log"]);
  check("assertOneOf passes when in allowlist",
        b.sqlSafe.assertOneOf("audit_log", allow) === "audit_log");
  var threw = false;
  try { b.sqlSafe.assertOneOf("users", allow); }
  catch (e) { threw = e.code === "sql/not-allowed"; }
  check("assertOneOf rejects non-allowlisted",              threw);
  check("assertOneOf accepts array allowlist",
        b.sqlSafe.assertOneOf("a", ["a", "b"]) === "a");
}

// ---- chain-writer ----

async function testChainWriterRejectsBadTable() {
  var threw = null;
  try {
    b.chainWriter.create({
      table: "users",
      columnsForInsert: ["_id"],
      hashableColumns:  ["_id"],
    });
  } catch (e) { threw = e; }
  check("chainWriter rejects non-chain table",
        threw && (threw.code === "sql/not-allowed" || threw.code === "chain-writer/invalid-config" ||
                  /not in allowlist/.test(threw.message)));
}

async function testChainWriterRaceSafetyConcurrentAppends() {
  // Concurrent appends through chain-writer should produce a chain
  // with no forks — every row's prevHash matches the predecessor's
  // rowHash, monotonicCounter strictly increases by 1.
  //
  // This is technically Layer 3 work (needs db) but is included with
  // the chain-writer primitive tests because it's the canonical
  // resilience claim for the primitive. The cost of running setupTestDb
  // here is acceptable; the alternative is splitting the chain-writer
  // tests across two layer files which obscures the intent.
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cw-"));
  try {
    b.cluster._resetForTest();
    await setupTestDb(tmpDir);
    b.audit.registerNamespace("test");

    var promises = [];
    for (var i = 0; i < 10; i++) {
      promises.push(b.audit.record({
        actor:   { userId: "u-" + i },
        action:  "test.concurrent",
        outcome: "success",
      }));
    }
    var results = await Promise.all(promises);

    var verified = await b.audit.verify();
    check("chain-writer race test: chain verifies after 10 concurrent appends",
          verified.ok === true);
    var counters = results.map(function (r) { return r.monotonicCounter; }).sort(function (a, b) { return a - b; });
    var allUnique = counters.every(function (c, idx, arr) { return idx === 0 || c === arr[idx - 1] + 1; });
    check("chain-writer race test: counters strictly monotonic, no duplicates",
          allUnique && counters.length === 10);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- async-safe ----

async function testAsyncSafeWithTimeoutResolves() {
  var v = await b.asyncSafe.withTimeout(Promise.resolve("ok"), 100);
  check("withTimeout: resolves with value when fast",       v === "ok");
}

async function testAsyncSafeWithTimeoutRejects() {
  var threw = null;
  try {
    await b.asyncSafe.withTimeout(new Promise(function () {}), 20, { name: "test-op" });
  } catch (e) { threw = e; }
  check("withTimeout: rejects on timeout",                  threw && threw.code === "async/timeout");
  check("withTimeout: timeout error names operation",       threw && threw.message.indexOf("test-op") >= 0);
}

async function testAsyncSafeWithTimeoutAbort() {
  var ctrl = new AbortController();
  var p = b.asyncSafe.withTimeout(new Promise(function () {}), 10000, { signal: ctrl.signal });
  setTimeout(function () { ctrl.abort(); }, 10);
  var threw = null;
  try { await p; } catch (e) { threw = e; }
  check("withTimeout: AbortSignal aborts cleanly",          threw && threw.code === "async/aborted");
}

async function testAsyncSafeWithTimeoutPropagatesError() {
  var threw = null;
  try {
    await b.asyncSafe.withTimeout(Promise.reject(new Error("boom")), 100);
  } catch (e) { threw = e; }
  check("withTimeout: propagates underlying rejection",     threw && threw.message === "boom");
}

async function testAsyncSafeSafeAwait() {
  var ok = await b.asyncSafe.safeAwait(Promise.resolve(42));
  check("safeAwait: success returns [null, value]",         ok[0] === null && ok[1] === 42);
  var fail = await b.asyncSafe.safeAwait(Promise.reject(new Error("nope")));
  check("safeAwait: failure returns [error, null]",         fail[0] && fail[0].message === "nope" && fail[1] === null);
}

async function testAsyncSafeMutexSerializes() {
  var m = new b.asyncSafe.Mutex();
  var order = [];
  async function task(label, durMs) {
    return m.runExclusive(async function () {
      order.push(label + ":enter");
      await new Promise(function (r) { setTimeout(r, durMs); });
      order.push(label + ":exit");
    });
  }
  await Promise.all([task("A", 30), task("B", 5), task("C", 5)]);
  check("Mutex: A enters first",       order[0] === "A:enter");
  check("Mutex: A exits before B/C enter",
        order.indexOf("A:exit") < order.indexOf("B:enter") &&
        order.indexOf("A:exit") < order.indexOf("C:enter"));
  check("Mutex: B and C don't interleave",
        Math.abs(order.indexOf("B:enter") - order.indexOf("B:exit")) === 1);
}

async function testAsyncSafeMutexReleaseOnThrow() {
  var m = new b.asyncSafe.Mutex();
  var threw = null;
  try {
    await m.runExclusive(async function () { throw new Error("inner"); });
  } catch (e) { threw = e; }
  check("Mutex: runExclusive propagates thrown error",      threw && threw.message === "inner");
  check("Mutex: lock released after throw",                 !m.isHeld());
}

async function testAsyncSafeMutexAbortableAcquire() {
  var m = new b.asyncSafe.Mutex();
  await m.acquire();
  var ctrl = new AbortController();
  var p = m.acquire({ signal: ctrl.signal });
  setTimeout(function () { ctrl.abort(); }, 10);
  var threw = null;
  try { await p; } catch (e) { threw = e; }
  check("Mutex: aborted acquire rejects",                   threw && threw.code === "async/aborted");
  check("Mutex: aborted acquirer no longer queued",         m.pendingCount() === 0);
  m.release();
}

async function testAsyncSafeSemaphoreBoundedConcurrency() {
  var s = new b.asyncSafe.Semaphore(2);
  var concurrent = 0;
  var maxConcurrent = 0;
  async function task() {
    return s.runWith(async function () {
      concurrent += 1;
      if (concurrent > maxConcurrent) maxConcurrent = concurrent;
      await new Promise(function (r) { setTimeout(r, 10); });
      concurrent -= 1;
    });
  }
  await Promise.all([task(), task(), task(), task(), task()]);
  check("Semaphore: max concurrency respected",             maxConcurrent === 2);
}

async function testAsyncSafeSemaphoreAbortableAcquire() {
  var s = new b.asyncSafe.Semaphore(1);
  await s.acquire();
  var ctrl = new AbortController();
  var p = s.acquire({ signal: ctrl.signal });
  setTimeout(function () { ctrl.abort(); }, 10);
  var threw = null;
  try { await p; } catch (e) { threw = e; }
  check("Semaphore: aborted acquire rejects",               threw && threw.code === "async/aborted");
  s.release();
}

async function testAsyncSafeOnceSingleFlight() {
  var calls = 0;
  var once = new b.asyncSafe.Once(async function () {
    calls += 1;
    await new Promise(function (r) { setTimeout(r, 10); });
    return "result-" + calls;
  });
  var results = await Promise.all([once.invoke(), once.invoke(), once.invoke()]);
  check("Once: function invoked exactly once",              calls === 1);
  check("Once: all callers see same result",
        results[0] === "result-1" && results[1] === "result-1" && results[2] === "result-1");
}

async function testAsyncSafeOnceCachesFailure() {
  var once = new b.asyncSafe.Once(async function () { throw new Error("init failed"); });
  var first = null, second = null;
  try { await once.invoke(); } catch (e) { first = e; }
  try { await once.invoke(); } catch (e) { second = e; }
  check("Once: failure caches; both callers see same rejection",
        first && second && first.message === "init failed" && second.message === "init failed");
}

async function testAsyncSafeOnceReset() {
  var calls = 0;
  var once = new b.asyncSafe.Once(async function () {
    calls += 1;
    if (calls === 1) throw new Error("transient");
    return "ok";
  });
  var failed = null;
  try { await once.invoke(); } catch (e) { failed = e; }
  check("Once: first call fails as expected",               failed && failed.message === "transient");
  once.reset();
  var second = await once.invoke();
  check("Once: reset enables retry; second call succeeds",  second === "ok" && calls === 2);
}

async function testAsyncSafeCircuitBreakerStateTransitions() {
  var br = new b.asyncSafe.CircuitBreaker("test", { failureThreshold: 2, cooldownMs: 30, successThreshold: 1 });
  check("CircuitBreaker: starts closed",                    br.getState() === "closed");
  for (var i = 0; i < 2; i++) {
    try { await br.wrap(async function () { throw new Error("fail"); }); } catch (_e) {}
  }
  check("CircuitBreaker: opens after failureThreshold",     br.getState() === "open");
  var fastFail = null;
  try { await br.wrap(async function () { return "ok"; }); }
  catch (e) { fastFail = e; }
  check("CircuitBreaker: open state fast-fails",            fastFail && fastFail.code === "CIRCUIT_OPEN");
  await new Promise(function (r) { setTimeout(r, 50); });
  var probe = await br.wrap(async function () { return "ok"; });
  check("CircuitBreaker: half-open probe success",          probe === "ok");
  check("CircuitBreaker: closes after success threshold",   br.getState() === "closed");
}

async function testAsyncSafeSleepBasic() {
  var t0 = Date.now();
  await b.asyncSafe.sleep(40);
  var elapsed = Date.now() - t0;
  check("sleep: resolves after delay", elapsed >= 35 && elapsed < 200);
}

async function testAsyncSafeSleepZeroResolvesImmediately() {
  var t0 = Date.now();
  await b.asyncSafe.sleep(0);
  await b.asyncSafe.sleep(-5);
  var elapsed = Date.now() - t0;
  check("sleep: ms<=0 resolves immediately", elapsed < 20);
}

async function testAsyncSafeSleepBadArg() {
  var threw = null;
  try { await b.asyncSafe.sleep("nope"); }
  catch (e) { threw = e; }
  check("sleep: non-numeric ms rejects", threw && threw.code === "async/bad-arg");
  threw = null;
  try { await b.asyncSafe.sleep(Infinity); }
  catch (e) { threw = e; }
  check("sleep: non-finite ms rejects",  threw && threw.code === "async/bad-arg");
}

async function testAsyncSafeSleepAbort() {
  var ac = new AbortController();
  var t0 = Date.now();
  setTimeout(function () { ac.abort(new Error("user cancel")); }, 20);
  var threw = null;
  try { await b.asyncSafe.sleep(5000, { signal: ac.signal }); }
  catch (e) { threw = e; }
  var elapsed = Date.now() - t0;
  check("sleep: abort cancels mid-sleep",  threw && threw.code === "async/aborted");
  check("sleep: abort short-circuits the wait", elapsed < 200);

  // Pre-aborted signal rejects immediately (no waiting).
  var preAborted = new AbortController();
  preAborted.abort(new Error("already gone"));
  var threwPre = null;
  try { await b.asyncSafe.sleep(5000, { signal: preAborted.signal }); }
  catch (e) { threwPre = e; }
  check("sleep: pre-aborted signal rejects", threwPre && threwPre.code === "async/aborted");
}

async function testAsyncSafeSleepUnrefOptIn() {
  // sleep(ms, { unref: true }) MUST NOT keep the process alive. Spawn a
  // child that requires async-safe directly (avoiding the framework boot,
  // which schedules its own intervals that would mask the unref check)
  // and starts an unref'd sleep without awaiting it. The script body's
  // last line is a synchronous console.log — when the script function
  // returns, node's loop has only the unref'd timer, so it should exit
  // cleanly within ~100ms. 5s wall clock fails fast on regression.
  var { spawn } = require("child_process");
  var asyncSafePath = path.resolve(__dirname, "..", "lib", "async-safe.js").replace(/\\/g, "\\\\");
  var script =
    'var as = require("' + asyncSafePath + '");' +
    'as.sleep(60000, { unref: true });' +    // pending unref'd sleep, no await
    'console.log("script-end");';
  var child = spawn(process.execPath, ["-e", script], { stdio: ["ignore", "pipe", "pipe"] });
  var stdout = "";
  child.stdout.on("data", function (c) { stdout += c.toString(); });

  var exited = await new Promise(function (resolve) {
    var killed = false;
    var t = setTimeout(function () { killed = true; child.kill("SIGKILL"); resolve("timeout"); }, 5000);
    child.once("exit", function (code) { clearTimeout(t); resolve(killed ? "killed" : "exit:" + code); });
  });
  check("sleep: { unref:true } lets process exit during pending sleep", exited === "exit:0");
  check("sleep: script body ran before exit",                            stdout.indexOf("script-end") !== -1);
}

async function testAsyncSafeSleepDefaultRefd() {
  // The natural `await sleep(ms)` pattern keeps the loop alive for the
  // duration. A bug in the previous draft made sleep unconditionally
  // unref the timer, which deadlocked otherwise-idle processes (loop
  // exits because nothing keeps it alive, awaiting Promise never
  // resolves). Verify by running a child whose ONLY work is `await
  // sleep(150)` then a final console.log — without the ref, node exits
  // before sleep completes and "post-sleep" never prints.
  var { spawn } = require("child_process");
  var asyncSafePath = path.resolve(__dirname, "..", "lib", "async-safe.js").replace(/\\/g, "\\\\");
  var script =
    'var as = require("' + asyncSafePath + '");' +
    '(async function() { await as.sleep(150); console.log("post-sleep"); })()' +
    '  .catch(function (e) { console.error("FAIL", e.message); process.exit(2); });';
  var child = spawn(process.execPath, ["-e", script], { stdio: ["ignore", "pipe", "pipe"] });
  var stdout = "";
  child.stdout.on("data", function (c) { stdout += c.toString(); });
  var exited = await new Promise(function (resolve) {
    var t = setTimeout(function () { child.kill("SIGKILL"); resolve("timeout"); }, 5000);
    child.once("exit", function (code) { clearTimeout(t); resolve("exit:" + code); });
  });
  check("sleep: default keeps loop alive for await pattern",  exited === "exit:0");
  check("sleep: post-sleep continuation actually ran",        stdout.indexOf("post-sleep") !== -1);
}

function testAsyncSafeWithTimeoutSignalCases() {
  var as = b.asyncSafe;

  // 1. null + no ms → null (caller's "no signal needed" path)
  check("withTimeoutSignal: null+0 returns null", as.withTimeoutSignal(null, 0) === null);
  check("withTimeoutSignal: null+undefined returns null",
        as.withTimeoutSignal(null) === null);

  // 2. null signal + positive ms → AbortSignal.timeout
  var sig = as.withTimeoutSignal(null, 50);
  check("withTimeoutSignal: only timeout returns an AbortSignal",
        sig instanceof AbortSignal && sig.aborted === false);

  // 3. user signal + 0 ms → user signal unchanged
  var ac = new AbortController();
  var passthrough = as.withTimeoutSignal(ac.signal, 0);
  check("withTimeoutSignal: user-only returns user signal unchanged",
        passthrough === ac.signal);

  // 4. both → composes (firing user signal aborts the composed)
  var ac2 = new AbortController();
  var combined = as.withTimeoutSignal(ac2.signal, 5000);
  check("withTimeoutSignal: composed signal exists",
        combined instanceof AbortSignal && combined.aborted === false);
  ac2.abort(new Error("user"));
  check("withTimeoutSignal: composed aborts when user aborts",
        combined.aborted === true);
}

async function testAsyncSafeWithTimeoutSignalTimeoutFires() {
  var sig = b.asyncSafe.withTimeoutSignal(null, 30);
  await new Promise(function (r) { setTimeout(r, 80); });
  check("withTimeoutSignal: timeout-only signal fires after ms", sig.aborted === true);
}

// ---- auth-header ----

function testAuthHeaderBearer() {
  var ah = b.authHeader;
  var h = ah.bearer("abc-123");
  check("authHeader.bearer: Authorization shape", h.Authorization === "Bearer abc-123");

  var threw = null;
  try { ah.bearer(""); }
  catch (e) { threw = e; }
  check("authHeader.bearer: rejects empty token", threw instanceof ah.AuthHeaderError);

  threw = null;
  try { ah.bearer(null); }
  catch (e) { threw = e; }
  check("authHeader.bearer: rejects null token", threw instanceof ah.AuthHeaderError);
}

function testAuthHeaderBasic() {
  var ah = b.authHeader;
  var h = ah.basic("alice", "s3cret");
  // RFC 7617: "alice:s3cret" base64-encoded
  var expected = Buffer.from("alice:s3cret", "utf8").toString("base64");
  check("authHeader.basic: Authorization shape",
        h.Authorization === "Basic " + expected);

  // Empty password permitted (legacy endpoints sometimes want this)
  var emptyPwd = ah.basic("alice", "");
  check("authHeader.basic: empty password permitted",
        emptyPwd.Authorization === "Basic " + Buffer.from("alice:", "utf8").toString("base64"));

  var threw = null;
  try { ah.basic(undefined, "x"); }
  catch (e) { threw = e; }
  check("authHeader.basic: rejects undefined username",
        threw instanceof ah.AuthHeaderError);
}

function testAuthHeaderFromConfig() {
  var ah = b.authHeader;
  check("authHeader.fromConfig: undefined → {}",
        Object.keys(ah.fromConfig()).length === 0);
  check("authHeader.fromConfig: {auth:none} → {}",
        Object.keys(ah.fromConfig({ auth: "none" })).length === 0);

  var bearerH = ah.fromConfig({ auth: "bearer", token: "tok" });
  check("authHeader.fromConfig: bearer returns Bearer header",
        bearerH.Authorization === "Bearer tok");

  var basicH = ah.fromConfig({ auth: "basic", username: "u", password: "p" });
  check("authHeader.fromConfig: basic returns Basic header",
        basicH.Authorization.indexOf("Basic ") === 0);

  var threw = null;
  try { ah.fromConfig({ auth: "ntlm" }); }
  catch (e) { threw = e; }
  check("authHeader.fromConfig: rejects unknown method",
        threw && threw.code === "auth-header/unknown-method");
}

// ---- handlers ----

async function testHandlerEmitAndDrain() {
  var flushed = [];
  var h = b.handlers.create({
    name:  "test",
    flush: async function (batch) { flushed.push.apply(flushed, batch); },
  });
  h.emit({ id: 1 });
  h.emit({ id: 2 });
  h.emit({ id: 3 });
  check("handler: emit returns nothing (sync)",             h.emit({ id: 4 }) === undefined);
  await h.drain();
  check("handler: drain flushes all buffered items",        flushed.length === 4);
  check("handler: items delivered in order",                flushed[0].id === 1 && flushed[3].id === 4);
  check("handler: buffer empty post-drain",                 h.size() === 0);
}

async function testHandlerEmitDuringFlushNextCycle() {
  // Recursion-safety contract (per handlers.js docstring): items emitted
  // BY a flush() call MUST land in the buffer for the NEXT drain cycle,
  // not the current one. This test exists because in cluster mode, the
  // audit handler's flush() writes through external-db, which itself
  // emits a system.externaldb.query audit event back into the same
  // handler — without a per-drain bound, drain refills as fast as it
  // empties and never returns. The bound here is the structural fix.
  var phase1 = [];
  var phase2 = [];
  var emitDuring = true;
  var h;
  h = b.handlers.create({
    name:  "test-recursion",
    flush: async function (batch) {
      if (emitDuring) {
        emitDuring = false;
        h.emit({ id: 99 });
        phase1.push.apply(phase1, batch);
      } else {
        phase2.push.apply(phase2, batch);
      }
    },
  });
  h.emit({ id: 1 });
  h.emit({ id: 2 });
  await h.drain();
  check("handler: first drain flushes only originally-buffered items",
        phase1.length === 2);
  check("handler: emit-during-flush did NOT land in current drain",
        phase2.length === 0);
  check("handler: emit-during-flush still in buffer after first drain",
        h.size() === 1);
  await h.drain();
  check("handler: second drain picks up the emit-during-flush item",
        phase2.length === 1 && phase2[0].id === 99);
  check("handler: buffer empty after second drain",
        h.size() === 0);
}

async function testHandlerRetryOnFlushFailure() {
  var attempts = 0;
  var seen = null;
  var h = b.handlers.create({
    name:  "test-retry",
    flush: async function (batch) {
      attempts += 1;
      if (attempts < 3) throw new Error("transient");
      seen = batch;
    },
    retry: { maxAttempts: 5, baseDelayMs: 1 },
  });
  h.emit({ id: 1 });
  await h.drain();
  check("handler: retries on flush failure",                attempts >= 3);
  check("handler: eventually succeeds",                     seen && seen.length === 1);
}

async function testHandlerCircuitBreakerOpensOnPersistentFailure() {
  var dlqCalls = 0;
  var h = b.handlers.create({
    name:  "test-breaker",
    flush: async function () { throw new Error("always fails"); },
    retry: { maxAttempts: 1, baseDelayMs: 1 },
    breaker: { failureThreshold: 2, cooldownMs: 10000, successThreshold: 1 },
    deadLetter: function () { dlqCalls += 1; },
    onError: function () { /* swallow expected errors */ },
  });
  h.emit({ id: 1 });
  await h.drain();
  h.emit({ id: 2 });
  await h.drain();
  h.emit({ id: 3 });
  await h.drain();
  var stats = h.getStats();
  check("handler: breaker tripped after consecutive failures",
        stats.breakerState === "open" || stats.breakerState === "half-open");
  check("handler: dead-lettered items on persistent failure", dlqCalls >= 1);
}

async function testHandlerBoundedShutdown() {
  var h = b.handlers.create({
    name:  "test-shutdown",
    flush: async function () {
      await new Promise(function (r) { setTimeout(r, 100); });
    },
    retry: { maxAttempts: 1, baseDelayMs: 1 },
    onError: function () { /* swallow */ },
  });
  h.emit({ id: 1 });
  var t0 = Date.now();
  await h.shutdown({ timeoutMs: 20 });
  var dur = Date.now() - t0;
  check("handler: shutdown bounded by timeout (< 100ms)",   dur < 80);
}

async function testHandlerStats() {
  var h = b.handlers.create({
    name:  "test-stats",
    flush: async function () { await new Promise(function (r) { setTimeout(r, 5); }); },
  });
  for (var i = 0; i < 5; i++) h.emit({ id: i });
  await h.drain();
  var s = h.getStats();
  check("handler.getStats: totalEmitted",                   s.totalEmitted === 5);
  check("handler.getStats: totalFlushed",                   s.totalFlushed === 5);
  check("handler.getStats: bufferSize=0 post-drain",        s.bufferSize === 0);
  check("handler.getStats: lastFlushDurationMs > 0",        s.lastFlushDurationMs > 0);
  check("handler.getStats: breakerState exposed",           s.breakerState === "closed");
}

async function testHandlerBackpressureDrop() {
  var dropped = [];
  var h = b.handlers.create({
    name:          "test-backpressure",
    flush:         async function () { await new Promise(function () {}); /* hang */ },
    maxBufferSize: 3,
    deadLetter:    function (items) { dropped.push.apply(dropped, items); },
    onError:       function () { /* swallow */ },
  });
  for (var i = 0; i < 10; i++) h.emit({ id: i });
  await new Promise(function (r) { setImmediate(r); });
  check("handler: maxBufferSize drops over-cap items to DLQ", dropped.length >= 5);
}

// ---- json-safe ----

function testJsonModuleSurface() {
  check("jsonSafe namespace present",        typeof b.jsonSafe === "object");
  check("jsonSafe.parse is a function",      typeof b.jsonSafe.parse === "function");
  check("jsonSafe.validate is a function",   typeof b.jsonSafe.validate === "function");
  check("jsonSafe.canonical is a function",  typeof b.jsonSafe.canonical === "function");
  check("jsonSafe.JsonSafeError exists",     typeof b.jsonSafe.JsonSafeError === "function");
}

function testJsonParse() {
  // Basic round-trip
  var v = b.jsonSafe.parse('{"a":1,"b":"hello","c":null,"d":[1,2,3],"e":true}');
  check("parse round-trips object",   v.a === 1 && v.b === "hello" && v.c === null);
  check("parse round-trips array",    Array.isArray(v.d) && v.d.length === 3);

  // BOM tolerated
  var bom = b.jsonSafe.parse("﻿{\"x\":1}");
  check("parse strips BOM",           bom.x === 1);

  // Size limit
  var bigInput = '{"x":"' + "a".repeat(200) + '"}';
  var sizeRejected = false;
  try { b.jsonSafe.parse(bigInput, { maxBytes: 100 }); }
  catch (e) { sizeRejected = e.code === "json/too-large"; }
  check("parse rejects oversized input",                  sizeRejected);

  // Depth limit
  var deep = '{"a":'.repeat(10) + 'null' + '}'.repeat(10);
  var depthRejected = false;
  try { b.jsonSafe.parse(deep, { maxDepth: 3 }); }
  catch (e) { depthRejected = e.code === "json/too-deep"; }
  check("parse rejects too-deep input",                   depthRejected);

  // Proto pollution
  var poisoned = b.jsonSafe.parse('{"__proto__":{"isAdmin":true},"name":"alice"}');
  check("parse strips __proto__ key",                     !("__proto__" in poisoned) || poisoned.__proto__ === Object.prototype);
  check("parse does not pollute Object.prototype",        !({}.isAdmin));

  var ctorPoisoned = b.jsonSafe.parse('{"constructor":{"prototype":{"x":1}}}');
  check("parse strips constructor key",                   !("constructor" in ctorPoisoned) || ctorPoisoned.constructor === Object);

  // Syntax error
  var syntaxRejected = false;
  try { b.jsonSafe.parse("{not-json}"); }
  catch (e) { syntaxRejected = e.code === "json/syntax"; }
  check("parse reports syntax errors with code",          syntaxRejected);

  // Wrong input type
  var typeRejected = false;
  try { b.jsonSafe.parse(123); }
  catch (e) { typeRejected = e.code === "json/wrong-input-type"; }
  check("parse rejects non-string/Buffer input",          typeRejected);

  // parseOrDefault
  check("parseOrDefault returns fallback on bad input",   b.jsonSafe.parseOrDefault("not-json", { fallback: true }).fallback === true);
  check("parseOrDefault returns parsed on good input",    b.jsonSafe.parseOrDefault('{"x":1}', null).x === 1);

  // Buffer input
  var fromBuf = b.jsonSafe.parse(Buffer.from('{"y":2}', "utf8"));
  check("parse accepts Buffer input",                     fromBuf.y === 2);
}

function testJsonStringify() {
  var s = b.jsonSafe.stringify({ a: 1, b: [1, 2, 3] });
  check("stringify produces valid JSON",                  JSON.parse(s).a === 1);

  var stripped = JSON.parse(b.jsonSafe.stringify({ __proto__: { x: 1 }, name: "alice" }));
  check("stringify strips __proto__",                     !("__proto__" in stripped) || stripped.__proto__ === Object.prototype);

  var circular = { a: 1 };
  circular.self = circular;
  var circRejected = false;
  try { b.jsonSafe.stringify(circular); }
  catch (e) { circRejected = e.code === "json/circular"; }
  check("stringify throws on circular ref",               circRejected);

  // Replace mode
  var replaced = b.jsonSafe.stringify(circular, { onCircular: "replace", circularReplacement: "<circular>" });
  check("stringify circular replace mode works",          /<circular>/.test(replaced));
}

function testJsonCanonical() {
  var c1 = b.jsonSafe.canonical({ b: 2, a: 1, c: 3 });
  var c2 = b.jsonSafe.canonical({ a: 1, c: 3, b: 2 });
  check("canonical: identical content same key order → identical bytes",  c1 === c2);
  check("canonical: keys sorted alphabetically",          c1 === '{"a":1,"b":2,"c":3}');

  var nested = b.jsonSafe.canonical({ z: { y: 1, x: 2 }, a: [3, 1, 2] });
  check("canonical: nested objects also sorted",          nested === '{"a":[3,1,2],"z":{"x":2,"y":1}}');

  var nfRejected = false;
  try { b.jsonSafe.canonical({ x: NaN }); }
  catch (e) { nfRejected = e.code === "json/non-finite"; }
  check("canonical: NaN rejected",                        nfRejected);
}

function testJsonValidate() {
  b.jsonSafe.validate("hello", { type: "string" });
  check("validate type-pass returns silently", true);
  var typeRejected = false;
  try { b.jsonSafe.validate(42, { type: "string" }); }
  catch (e) { typeRejected = e.code === "json/validation" && /expected string/.test(e.message); }
  check("validate type mismatch throws with path",         typeRejected);

  var schema = {
    type: "object",
    required: ["email", "age"],
    properties: {
      email: { type: "string", format: "email", maxLength: 254 },
      age:   { type: "integer", minimum: 0, maximum: 150 },
      role:  { type: "string", enum: ["admin", "user", "guest"] },
    },
    additionalProperties: false,
  };

  b.jsonSafe.validate({ email: "alice@example.com", age: 30, role: "admin" }, schema);
  check("validate good object passes silently", true);

  var emailRejected = false;
  try { b.jsonSafe.validate({ email: "not-email", age: 30 }, schema); }
  catch (e) { emailRejected = e.code === "json/validation" && /format 'email'/.test(e.message); }
  check("validate bad email format throws",                emailRejected);

  var requiredRejected = false;
  try { b.jsonSafe.validate({ email: "a@b.com" }, schema); }
  catch (e) { requiredRejected = /missing required key 'age'/.test(e.message); }
  check("validate missing required throws",                requiredRejected);

  var rangeRejected = false;
  try { b.jsonSafe.validate({ email: "a@b.com", age: -1 }, schema); }
  catch (e) { rangeRejected = /minimum/.test(e.message); }
  check("validate range violation throws",                 rangeRejected);

  var enumRejected = false;
  try { b.jsonSafe.validate({ email: "a@b.com", age: 30, role: "superuser" }, schema); }
  catch (e) { enumRejected = /not in enum/.test(e.message); }
  check("validate enum violation throws",                  enumRejected);

  var unknownKeyRejected = false;
  try { b.jsonSafe.validate({ email: "a@b.com", age: 30, hax: 1 }, schema); }
  catch (e) { unknownKeyRejected = /unknown key 'hax'/.test(e.message); }
  check("validate unknown key with additionalProperties:false throws", unknownKeyRejected);

  var arrSchema = { type: "array", minItems: 1, items: { type: "integer" } };
  b.jsonSafe.validate([1, 2, 3], arrSchema);
  var arrItemRejected = false;
  try { b.jsonSafe.validate([1, "two", 3], arrSchema); }
  catch (e) { arrItemRejected = e.path === "$[1]" && /expected integer/.test(e.message); }
  check("validate array item path is reported",            arrItemRejected);
}

function testJsonValidateCollect() {
  var schema = {
    type: "object",
    required: ["email", "age", "name"],
    properties: {
      email: { type: "string", format: "email" },
      age:   { type: "integer", minimum: 0 },
      name:  { type: "string", minLength: 1, maxLength: 100 },
      role:  { type: "string", enum: ["admin", "user"] },
    },
  };
  var bad = { email: "not-email", age: -5, name: "", role: "superuser" };
  var result = b.jsonSafe.validate(bad, schema, { collectErrors: true });
  check("collectErrors returns { ok, value, errors }",      typeof result === "object" && result.ok === false);
  check("collectErrors collects multiple errors",           result.errors.length >= 4);
  check("collectErrors errors have .path",                  result.errors.every(function (e) { return typeof e.path === "string"; }));
  check("collectErrors errors include format failure",      result.errors.some(function (e) { return /format 'email'/.test(e.message); }));
  check("collectErrors errors include range failure",       result.errors.some(function (e) { return /minimum/.test(e.message); }));
  check("collectErrors errors include length failure",      result.errors.some(function (e) { return /minLength/.test(e.message); }));
  check("collectErrors errors include enum failure",        result.errors.some(function (e) { return /not in enum/.test(e.message); }));

  var good = { email: "a@b.com", age: 30, name: "Alice" };
  var goodResult = b.jsonSafe.validate(good, schema, { collectErrors: true });
  check("collectErrors ok=true on valid input",             goodResult.ok === true && goodResult.errors.length === 0);

  var parseResult = b.jsonSafe.parse(JSON.stringify(bad), { schema: schema, collectErrors: true });
  check("parse + collectErrors returns { ok, value, errors[] }",
        typeof parseResult === "object" && parseResult.ok === false && parseResult.errors.length >= 4);
}

function testJsonFormats() {
  check("format email: valid passes",        b.jsonSafe.formats.email("alice@example.com"));
  check("format email: missing @ fails",     !b.jsonSafe.formats.email("not-email"));
  check("format url: https passes",          b.jsonSafe.formats.url("https://example.com/path"));
  check("format url: ftp fails (not in allowlist)", !b.jsonSafe.formats.url("ftp://example.com"));
  check("format uuid: valid passes",         b.jsonSafe.formats.uuid("550e8400-e29b-41d4-a716-446655440000"));
  check("format uuid: too-short fails",      !b.jsonSafe.formats.uuid("550e8400"));
  check("format ulid: valid passes",         b.jsonSafe.formats.ulid("01ARZ3NDEKTSV4RRFFQ69G5FAV"));
  check("format ipv4: valid passes",         b.jsonSafe.formats.ipv4("192.168.1.1"));
  check("format ipv4: out of range fails",   !b.jsonSafe.formats.ipv4("192.168.1.256"));
  check("format ipv4: leading zero fails",   !b.jsonSafe.formats.ipv4("192.168.001.1"));
  check("ipv6: full 8 groups",                          b.jsonSafe.formats.ipv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334"));
  check("ipv6: lowercase",                              b.jsonSafe.formats.ipv6("2001:db8::1"));
  check("ipv6: mixed case",                             b.jsonSafe.formats.ipv6("2001:DB8::1"));
  check("ipv6: loopback ::1",                           b.jsonSafe.formats.ipv6("::1"));
  check("ipv6: unspecified ::",                         b.jsonSafe.formats.ipv6("::"));
  check("ipv6: trailing :: (1::)",                      b.jsonSafe.formats.ipv6("1::"));
  check("ipv6: link-local fe80::1",                     b.jsonSafe.formats.ipv6("fe80::1"));
  check("ipv6: IPv4-mapped ::ffff:192.168.1.1",         b.jsonSafe.formats.ipv6("::ffff:192.168.1.1"));
  check("ipv6: IPv4-mapped uppercase",                  b.jsonSafe.formats.ipv6("::FFFF:192.168.1.1"));
  check("ipv6: longer IPv4-mapped form",                b.jsonSafe.formats.ipv6("2001:db8::192.0.2.1"));
  check("ipv6: rejects > 8 groups",                     !b.jsonSafe.formats.ipv6("1:2:3:4:5:6:7:8:9"));
  check("ipv6: rejects multiple ::",                    !b.jsonSafe.formats.ipv6("1::2::3"));
  check("ipv6: rejects non-hex chars",                  !b.jsonSafe.formats.ipv6("g::"));
  check("ipv6: rejects > 4 hex per group",              !b.jsonSafe.formats.ipv6("12345::"));
  check("ipv6: rejects zone IDs",                       !b.jsonSafe.formats.ipv6("fe80::1%eth0"));
  check("ipv6: rejects empty string",                   !b.jsonSafe.formats.ipv6(""));
  check("ipv6: rejects too long",                       !b.jsonSafe.formats.ipv6("a".repeat(46)));
  check("ipv6: rejects bad IPv4-mapped",                !b.jsonSafe.formats.ipv6("::ffff:999.168.1.1"));
  check("format hex: valid passes",          b.jsonSafe.formats.hex("dead beef".replace(" ", "")));
  check("format slug: valid passes",         b.jsonSafe.formats.slug("my-blog-post"));
  check("format slug: uppercase fails",      !b.jsonSafe.formats.slug("MyBlogPost"));
  check("format iso8601-date: valid passes", b.jsonSafe.formats["iso8601-date"]("2026-04-25"));
  check("format iso8601-date: invalid fails",!b.jsonSafe.formats["iso8601-date"]("2026-13-01"));

  b.jsonSafe.registerFormat("us-zip", function (v) { return /^\d{5}(-\d{4})?$/.test(v); });
  check("custom format registered + works",  b.jsonSafe.formats["us-zip"]("12345"));
  b.jsonSafe.validate("90210", { type: "string", format: "us-zip" });
  var customRejected = false;
  try { b.jsonSafe.validate("ABCDE", { type: "string", format: "us-zip" }); }
  catch (e) { customRejected = /format 'us-zip'/.test(e.message); }
  check("custom format used by validate",    customRejected);
}

// =====================================================================
// atomic-file + parsers (xml, csv, toml, yaml, env-parse) + redact
//
// All Layer 0: pure / file-IO primitives with no framework state.
// =====================================================================

async function testAtomicFileListDir() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-listdir-"));
  try {
    fs.writeFileSync(path.join(tmpDir, "a.log"), "alpha");
    fs.writeFileSync(path.join(tmpDir, "b.log"), "beta");
    fs.writeFileSync(path.join(tmpDir, "c.txt"), "carrot");
    fs.mkdirSync(path.join(tmpDir, "sub"));

    // Default — no filter, no stat
    var all = b.atomicFile.listDir(tmpDir);
    check("listDir: returns all entries by default", all.length === 4);
    check("listDir: each entry has name + fullPath",
          all[0].name && all[0].fullPath && all[0].fullPath.indexOf(tmpDir) === 0);
    check("listDir: no stat fields when includeStat off", all[0].mtimeMs === undefined);

    // Filter
    var logs = b.atomicFile.listDir(tmpDir, {
      filter: function (n) { return n.endsWith(".log"); },
    });
    check("listDir: filter narrows to .log", logs.length === 2);

    // includeStat populates size, mtime, isDirectory, isFile
    var withStat = b.atomicFile.listDir(tmpDir, { includeStat: true });
    var byName = {};
    withStat.forEach(function (e) { byName[e.name] = e; });
    check("listDir: includeStat — size of a.log", byName["a.log"].sizeBytes === 5);
    check("listDir: includeStat — a.log isFile",  byName["a.log"].isFile === true);
    check("listDir: includeStat — a.log not dir", byName["a.log"].isDirectory === false);
    check("listDir: includeStat — sub isDirectory", byName["sub"].isDirectory === true);
    check("listDir: includeStat — mtimeMs is a number",
          typeof byName["a.log"].mtimeMs === "number");

    // Missing dir — default missingOk: true returns []
    var missing = b.atomicFile.listDir(path.join(tmpDir, "nope"));
    check("listDir: missing dir returns [] by default", Array.isArray(missing) && missing.length === 0);

    // missingOk: false throws
    var threwMissing = false;
    try { b.atomicFile.listDir(path.join(tmpDir, "nope"), { missingOk: false }); }
    catch (e) { threwMissing = e.code === "atomic-file/list-failed"; }
    check("listDir: missingOk: false throws", threwMissing);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

async function testAtomicFile() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-atomicfile-"));
  try {
    check("atomicFile namespace present",            typeof b.atomicFile === "object");

    // Basic write + read round-trip
    var p = path.join(tmpDir, "data.bin");
    var content = Buffer.from("hello atomic " + Date.now(), "utf8");
    var w = await b.atomicFile.write(p, content, { computeHash: true });
    check("atomicFile write returns bytesWritten",   w.bytesWritten === content.length);
    check("atomicFile write returns hash",           typeof w.hash === "string" && w.hash.length === 128);

    var r = await b.atomicFile.read(p);
    check("atomicFile read returns Buffer",          Buffer.isBuffer(r));
    check("atomicFile read content matches",         r.equals(content));

    // Hash verification
    var rOk = await b.atomicFile.read(p, { expectedHash: w.hash });
    check("atomicFile hash verify accepts good hash", rOk.equals(content));

    var hashRejected = false;
    try { await b.atomicFile.read(p, { expectedHash: "0".repeat(128) }); }
    catch (e) { hashRejected = e.code === "atomic-file/integrity"; }
    check("atomicFile hash verify rejects bad hash", hashRejected);

    // Size limit
    var bigPath = path.join(tmpDir, "big.bin");
    await b.atomicFile.write(bigPath, Buffer.alloc(2048));
    var sizeRejected = false;
    try { await b.atomicFile.read(bigPath, { maxBytes: 1024 }); }
    catch (e) { sizeRejected = e.code === "atomic-file/too-large"; }
    check("atomicFile read maxBytes enforced",       sizeRejected);

    // readSync: same semantics as async read, for boot-path callers
    var rSync = b.atomicFile.readSync(p);
    check("atomicFile readSync returns Buffer",      Buffer.isBuffer(rSync));
    check("atomicFile readSync content matches",     rSync.equals(content));
    var rSyncStr = b.atomicFile.readSync(p, { encoding: "utf8" });
    check("atomicFile readSync encoding option",     rSyncStr === content.toString("utf8"));
    var syncSizeRejected = false;
    try { b.atomicFile.readSync(bigPath, { maxBytes: 1024 }); }
    catch (e) { syncSizeRejected = e.code === "atomic-file/too-large"; }
    check("atomicFile readSync maxBytes enforced",   syncSizeRejected);
    var syncMissingRejected = false;
    try { b.atomicFile.readSync(path.join(tmpDir, "no-such-file")); }
    catch (e) { syncMissingRejected = e.code === "ENOENT"; }
    check("atomicFile readSync ENOENT on missing",   syncMissingRejected);

    // Crash safety: tmp file should NOT remain after success
    var tmpFiles = fs.readdirSync(tmpDir).filter(function (f) { return /\.tmp-/.test(f); });
    check("atomicFile cleans up tmp on success",     tmpFiles.length === 0);

    // JSON convenience
    var jsonPath = path.join(tmpDir, "data.json");
    await b.atomicFile.writeJson(jsonPath, { a: 1, b: [2, 3] });
    var parsed = await b.atomicFile.readJson(jsonPath);
    check("atomicFile writeJson/readJson round-trip", parsed.a === 1 && parsed.b[1] === 3);

    // readJson with schema
    var schemaPath = path.join(tmpDir, "schema.json");
    await b.atomicFile.writeJson(schemaPath, { name: "alice", age: 30 });
    var validated = await b.atomicFile.readJson(schemaPath, {
      schema: { type: "object", required: ["name", "age"], properties: { name: { type: "string" }, age: { type: "integer" } } },
    });
    check("atomicFile readJson + schema validates",  validated.name === "alice");

    // copy
    var copyPath = path.join(tmpDir, "copy.bin");
    var c = await b.atomicFile.copy(p, copyPath, { computeHash: true });
    check("atomicFile copy returns hash",            c.hash === w.hash);
    check("atomicFile copy file exists",             b.atomicFile.exists(copyPath));

    // Read missing file → ENOENT
    var missingRejected = false;
    try { await b.atomicFile.read(path.join(tmpDir, "nope")); }
    catch (e) { missingRejected = e.code === "ENOENT" || e.code === "atomic-file/not-found"; }
    check("atomicFile read missing → ENOENT",         missingRejected);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

async function testAtomicFileLock() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-atlock-"));
  try {
    var p = path.join(tmpDir, "shared.txt");
    var counter = 0;

    // Two concurrent locks — they should serialize
    async function increment() {
      await b.atomicFile.lock(p, async function () {
        var current;
        try { current = parseInt((await b.atomicFile.read(p)).toString("utf8"), 10) || 0; }
        catch (_e) { current = 0; }
        await new Promise(function (r) { setTimeout(r, 20); });   // simulate work
        await b.atomicFile.write(p, String(current + 1));
        counter += 1;
      });
    }

    await Promise.all([increment(), increment(), increment(), increment(), increment()]);
    var finalValue = parseInt((await b.atomicFile.read(p)).toString("utf8"), 10);
    check("atomicFile.lock serializes concurrent access",  finalValue === 5);
    check("counter agrees",                                counter === 5);

    // Lock file is gone after lock body finishes
    check("lock sentinel cleaned up",                      !b.atomicFile.exists(p + ".lock"));
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

function testXmlParse() {
  check("parsers namespace present",                  typeof b.parsers === "object");
  check("parsers.xml present",                        typeof b.parsers.xml === "object");

  // Simple element
  var simple = b.parsers.xml.parse("<root>hello</root>");
  check("xml: simple text element",                   simple.root === "hello");

  // Attributes + nested
  var attr = b.parsers.xml.parse('<root id="x"><child>text</child></root>');
  check("xml: attributes preserved at @attrs",        attr.root["@attrs"].id === "x");
  check("xml: nested child element",                  attr.root.child === "text");

  // Multiple children with same name → array
  var multi = b.parsers.xml.parse('<root><item>a</item><item>b</item><item>c</item></root>');
  check("xml: repeated children become array",        Array.isArray(multi.root.item) && multi.root.item.length === 3);
  check("xml: array preserves order",                 multi.root.item[0] === "a" && multi.root.item[2] === "c");

  // XML declaration tolerated
  var withDecl = b.parsers.xml.parse('<?xml version="1.0" encoding="UTF-8"?><root>x</root>');
  check("xml: XML decl ignored",                      withDecl.root === "x");

  // Built-in entities decoded
  var entities = b.parsers.xml.parse("<root>&lt;ok&gt; &amp; &quot;quoted&quot;</root>");
  check("xml: built-in entities decoded",             entities.root === "<ok> & \"quoted\"");

  // Numeric character refs
  var numref = b.parsers.xml.parse("<root>&#65;&#x42;</root>");
  check("xml: numeric character refs decoded",        numref.root === "AB");

  // Self-closing
  var selfClose = b.parsers.xml.parse("<root><br/></root>");
  check("xml: self-closing element parses",           selfClose.root.br === "");

  // CDATA
  var cdata = b.parsers.xml.parse("<root><![CDATA[<not parsed>]]></root>");
  check("xml: CDATA preserved literally",             cdata.root === "<not parsed>");
}

function testXmlSecurityRejections() {
  // DOCTYPE rejected by default
  var doctypeRejected = false;
  try { b.parsers.xml.parse('<!DOCTYPE foo SYSTEM "http://evil.com/foo.dtd"><root/>'); }
  catch (e) { doctypeRejected = e.code === "xml/doctype"; }
  check("xml: DOCTYPE rejected by default (XXE)",     doctypeRejected);

  // External entity reference rejected
  var entityRejected = false;
  try { b.parsers.xml.parse('<root>&customEntity;</root>'); }
  catch (e) { entityRejected = e.code === "xml/external-entity"; }
  check("xml: custom entity ref rejected",            entityRejected);

  // Processing instruction rejected
  var piRejected = false;
  try { b.parsers.xml.parse('<root><?php echo $secret; ?></root>'); }
  catch (e) { piRejected = e.code === "xml/processing"; }
  check("xml: processing instruction rejected",        piRejected);

  // Mismatched tags
  var mismatchedRejected = false;
  try { b.parsers.xml.parse("<a><b></a></b>"); }
  catch (e) { mismatchedRejected = e.code === "xml/mismatched-tag"; }
  check("xml: mismatched tags rejected",              mismatchedRejected);

  // Depth limit
  var deep = "<a>".repeat(20) + "x" + "</a>".repeat(20);
  var depthRejected = false;
  try { b.parsers.xml.parse(deep, { maxDepth: 5 }); }
  catch (e) { depthRejected = e.code === "xml/too-deep"; }
  check("xml: maxDepth enforced",                     depthRejected);

  // Element count limit
  var manyKids = "<root>" + "<x/>".repeat(50) + "</root>";
  var countRejected = false;
  try { b.parsers.xml.parse(manyKids, { maxElements: 10 }); }
  catch (e) { countRejected = e.code === "xml/too-many-elements"; }
  check("xml: maxElements enforced",                  countRejected);

  // Attribute count limit
  var manyAttrs = "<root " + Array.from({ length: 20 }, function (_, i) { return "a" + i + "=\"v\""; }).join(" ") + "/>";
  var attrRejected = false;
  try { b.parsers.xml.parse(manyAttrs, { maxAttributes: 5 }); }
  catch (e) { attrRejected = e.code === "xml/too-many-attrs"; }
  check("xml: maxAttributes enforced",                attrRejected);

  // Size limit
  var sizeRejected = false;
  try { b.parsers.xml.parse("<r>" + "a".repeat(10000) + "</r>", { maxBytes: 1000 }); }
  catch (e) { sizeRejected = e.code === "xml/too-large"; }
  check("xml: maxBytes enforced",                     sizeRejected);

  // Duplicate attributes
  var dupRejected = false;
  try { b.parsers.xml.parse('<r id="a" id="b"/>'); }
  catch (e) { dupRejected = e.code === "xml/duplicate-attr"; }
  check("xml: duplicate attribute rejected",           dupRejected);

  // < in attribute value
  var ltRejected = false;
  try { b.parsers.xml.parse('<r x="<bad"/>'); }
  catch (e) { ltRejected = e.code === "xml/bad-attr"; }
  check("xml: '<' in attribute value rejected",        ltRejected);
}

function testCsvParse() {
  check("parsers.csv present",                        typeof b.parsers.csv === "object");

  // Simple round-trip
  var simple = b.parsers.csv.parse("name,age\nalice,30\nbob,25");
  check("csv: header+rows → object array",            simple.length === 2);
  check("csv: object has header keys",                simple[0].name === "alice" && simple[0].age === "30");

  // Without header
  var noHeader = b.parsers.csv.parse("a,b,c\n1,2,3", { header: false });
  check("csv: no header → array of arrays",           Array.isArray(noHeader[0]));
  check("csv: 2 rows",                                noHeader.length === 2);

  // Quoted fields
  var quoted = b.parsers.csv.parse('name,note\n"alice","says ""hi"""\n"bob","comma, inside"', { header: true });
  check("csv: quoted field with escaped quote",       quoted[0].note === 'says "hi"');
  check("csv: quoted field with comma",               quoted[1].note === "comma, inside");

  // CRLF
  var crlf = b.parsers.csv.parse("a,b\r\n1,2\r\n3,4", { header: false });
  check("csv: CRLF line endings",                     crlf.length === 3);

  // Custom delimiter
  var tsv = b.parsers.csv.parse("a\tb\n1\t2", { delimiter: "\t", header: false });
  check("csv: custom delimiter",                      tsv[1][0] === "1" && tsv[1][1] === "2");

  // BOM stripped
  var bom = b.parsers.csv.parse("﻿a,b\n1,2", { header: false });
  check("csv: BOM stripped",                          bom[0][0] === "a");

  // Size limit
  var sizeRejected = false;
  try { b.parsers.csv.parse("a,".repeat(100), { maxBytes: 50, header: false }); }
  catch (e) { sizeRejected = e.code === "csv/too-large"; }
  check("csv: maxBytes enforced",                     sizeRejected);

  // Row count limit
  var manyRows = Array.from({ length: 10 }, function (_, i) { return i + ",x"; }).join("\n");
  var rowsRejected = false;
  try { b.parsers.csv.parse(manyRows, { maxRows: 3, header: false }); }
  catch (e) { rowsRejected = e.code === "csv/too-many-rows"; }
  check("csv: maxRows enforced",                      rowsRejected);

  // Unterminated quote
  var unterminatedRejected = false;
  try { b.parsers.csv.parse('a,b\n"unclosed,1\n2,3', { header: false }); }
  catch (e) { unterminatedRejected = e.code === "csv/unterminated-quote"; }
  check("csv: unterminated quote rejected",            unterminatedRejected);
}

function testCsvFormulaInjection() {
  // Default: injection-prone cells get a '-prefix
  var dangerous = b.parsers.csv.stringify([
    { name: "=SUM(A1:A10)", value: "ok" },
    { name: "+CMD|/c calc",  value: "ok" },
    { name: "-1+2",          value: "ok" },
    { name: "@SUM(1,2)",     value: "ok" },
    { name: "normal",        value: "ok" },
  ]);
  check("csv stringify: =formula gets '-prefix",        /'\=SUM/.test(dangerous));
  check("csv stringify: +formula gets '-prefix",        /'\+CMD/.test(dangerous));
  check("csv stringify: -formula gets '-prefix",        /'\-1\+2/.test(dangerous));
  check("csv stringify: @formula gets '-prefix",        /'\@SUM/.test(dangerous));
  check("csv stringify: normal cell unchanged",         /(^|\n|\r)normal,ok/.test(dangerous));

  // Disabled mode (RFC 4180 strict)
  var raw = b.parsers.csv.stringify([{ name: "=SUM(A1:A10)" }], { preventFormulaInjection: false });
  check("csv stringify: preventFormulaInjection:false leaves =formula", /^name\r\n=SUM/.test(raw));

  // Round-trip via parse + stringify
  var rows = [{ a: "1", b: "two, three" }, { a: "x\nnewline", b: "with \"quote\"" }];
  var serialized = b.parsers.csv.stringify(rows);
  var parsed = b.parsers.csv.parse(serialized);
  check("csv round-trip preserves comma in field",       parsed[0].b === "two, three");
  check("csv round-trip preserves newline in field",     parsed[1].a === "x\nnewline");
  check("csv round-trip preserves quote in field",       parsed[1].b === "with \"quote\"");
}

function testTomlBasicTypes() {
  var src =
    "title = \"blamejs\"\n" +
    "active = true\n" +
    "disabled = false\n" +
    "answer = 42\n" +
    "ratio = 3.14\n" +
    "neg = -17\n" +
    "biginthex = 0xDEADbeef\n" +
    "octal = 0o755\n" +
    "binary = 0b1010\n" +
    "underscored = 1_000_000\n" +
    "infinity = inf\n" +
    "negInf = -inf\n" +
    "notNum = nan\n" +
    "literal = 'no \\n escapes here'\n" +
    "stamp = 1979-05-27T07:32:00Z\n" +
    "localDate = 1979-05-27\n" +
    "localTime = 07:32:00\n";
  var doc = b.parsers.toml.parse(src);
  check("toml: string value",                      doc.title === "blamejs");
  check("toml: bool true",                         doc.active === true);
  check("toml: bool false",                        doc.disabled === false);
  check("toml: integer",                           doc.answer === 42);
  check("toml: float",                             Math.abs(doc.ratio - 3.14) < 1e-9);
  check("toml: negative integer",                  doc.neg === -17);
  check("toml: hex with underscore-camelcase digits", doc.biginthex === 0xDEADbeef);
  check("toml: octal",                             doc.octal === 0o755);
  check("toml: binary",                            doc.binary === 10);
  check("toml: underscored decimal",               doc.underscored === 1000000);
  check("toml: inf",                               doc.infinity === Infinity);
  check("toml: -inf",                              doc.negInf === -Infinity);
  check("toml: nan",                               Number.isNaN(doc.notNum));
  check("toml: literal string preserves backslash-n",  doc.literal === "no \\n escapes here");
  check("toml: offset date-time → Date",           doc.stamp instanceof Date);
  check("toml: offset date-time correct epoch",    doc.stamp.getTime() === Date.UTC(1979, 4, 27, 7, 32, 0));
  check("toml: local date as ISO string",          doc.localDate === "1979-05-27");
  check("toml: local time as ISO string",          doc.localTime === "07:32:00");
}

function testTomlTablesAndArrays() {
  var src =
    "tags = [\"a\", \"b\", \"c\"]\n" +
    "\n" +
    "[server]\n" +
    "host = \"localhost\"\n" +
    "port = 8080\n" +
    "\n" +
    "[server.tls]\n" +
    "cert = \"/etc/ssl/cert.pem\"\n" +
    "\n" +
    "[[products]]\n" +
    "name = \"widget\"\n" +
    "price = 9.99\n" +
    "\n" +
    "[[products]]\n" +
    "name = \"gizmo\"\n" +
    "price = 19.99\n";
  var doc = b.parsers.toml.parse(src);
  check("toml: array of strings (top-level)",      Array.isArray(doc.tags) && doc.tags.length === 3);
  check("toml: array element 0",                   doc.tags[0] === "a");
  check("toml: nested table",                      doc.server.host === "localhost");
  check("toml: integer in nested table",           doc.server.port === 8080);
  check("toml: deeper nested table",               doc.server.tls.cert === "/etc/ssl/cert.pem");
  check("toml: array of tables length",            doc.products.length === 2);
  check("toml: AoT first element",                 doc.products[0].name === "widget");
  check("toml: AoT second element",                doc.products[1].name === "gizmo");
  check("toml: AoT prices",                        doc.products[1].price === 19.99);
}

function testTomlInlineTablesAndDottedKeys() {
  var src =
    "point = { x = 1, y = 2 }\n" +
    "name.first = \"Tom\"\n" +
    "name.last = \"Preston-Werner\"\n";
  var doc = b.parsers.toml.parse(src);
  check("toml: inline table",                      doc.point.x === 1 && doc.point.y === 2);
  check("toml: dotted-key creates nested object",  doc.name.first === "Tom" && doc.name.last === "Preston-Werner");
}

function testTomlSecurityRejections() {
  // Prototype pollution via dotted key
  var threwProto = false;
  try { b.parsers.toml.parse("__proto__.polluted = true"); }
  catch (e) { threwProto = e.code === "toml/poisoned-key"; }
  check("toml: __proto__ rejected",                threwProto);

  var threwConstructor = false;
  try { b.parsers.toml.parse("a.constructor = 1"); }
  catch (e) { threwConstructor = e.code === "toml/poisoned-key"; }
  check("toml: constructor rejected",              threwConstructor);

  // Duplicate key
  var threwDup = false;
  try { b.parsers.toml.parse("a = 1\na = 2"); }
  catch (e) { threwDup = e.code === "toml/duplicate-key"; }
  check("toml: duplicate key rejected",            threwDup);

  // Inline table mutation
  var threwInlineMutate = false;
  try { b.parsers.toml.parse("x = { a = 1 }\nx.b = 2"); }
  catch (e) { threwInlineMutate = e.code === "toml/inline-table-mutated"; }
  check("toml: inline-table mutation rejected",    threwInlineMutate);

  // Table redefinition
  var threwRedefine = false;
  try { b.parsers.toml.parse("[a]\nb = 1\n[a]\nc = 2"); }
  catch (e) { threwRedefine = e.code === "toml/redefine"; }
  check("toml: table redefinition rejected",       threwRedefine);

  // Size cap
  var threwSize = false;
  try { b.parsers.toml.parse("a = \"" + "x".repeat(2000) + "\"", { maxBytes: 1000 }); }
  catch (e) { threwSize = e.code === "toml/too-large"; }
  check("toml: maxBytes enforced",                 threwSize);

  // Integer overflow
  var threwOverflow = false;
  try { b.parsers.toml.parse("big = 9223372036854775807"); }
  catch (e) { threwOverflow = e.code === "toml/integer-overflow"; }
  check("toml: integer-overflow on > MAX_SAFE_INTEGER", threwOverflow);

  // Unterminated string
  var threwUnterm = false;
  try { b.parsers.toml.parse("a = \"unterminated\nb = 1"); }
  catch (e) { threwUnterm = !!e.isTomlSafeError; }
  check("toml: unterminated string rejected",      threwUnterm);

  // Multi-line basic string
  var doc = b.parsers.toml.parse("greeting = \"\"\"\nhello,\nworld\n\"\"\"");
  check("toml: multi-line basic string trims first newline + preserves rest",
        doc.greeting === "hello,\nworld\n");
}

function testYamlBasic() {
  var src =
    "title: blamejs\n" +
    "version: 0.1.6\n" +
    "active: true\n" +
    "disabled: false\n" +
    "answer: 42\n" +
    "ratio: 3.14\n" +
    "absent: null\n" +
    "implicit_null: ~\n" +
    "list:\n" +
    "  - a\n" +
    "  - b\n" +
    "  - c\n" +
    "nested:\n" +
    "  host: localhost\n" +
    "  port: 8080\n" +
    "  tls:\n" +
    "    cert: /etc/ssl/cert.pem\n" +
    "flow_seq: [1, 2, 3]\n" +
    "flow_map: { x: 1, y: 2 }\n";
  var doc = b.parsers.yaml.parse(src);
  check("yaml: string scalar",                     doc.title === "blamejs");
  check("yaml: version string (mixed digits/dots)", doc.version === "0.1.6" || doc.version === 0.1);
  check("yaml: bool true",                         doc.active === true);
  check("yaml: bool false",                        doc.disabled === false);
  check("yaml: integer",                           doc.answer === 42);
  check("yaml: float",                             Math.abs(doc.ratio - 3.14) < 1e-9);
  check("yaml: explicit null",                     doc.absent === null);
  check("yaml: tilde null",                        doc.implicit_null === null);
  check("yaml: block sequence length",             doc.list.length === 3);
  check("yaml: block sequence elements",           doc.list[0] === "a" && doc.list[2] === "c");
  check("yaml: nested mapping host",               doc.nested.host === "localhost");
  check("yaml: deeply-nested mapping",             doc.nested.tls.cert === "/etc/ssl/cert.pem");
  check("yaml: flow sequence",                     Array.isArray(doc.flow_seq) && doc.flow_seq.length === 3);
  check("yaml: flow mapping",                      doc.flow_map.x === 1 && doc.flow_map.y === 2);
}

function testYamlNorwayProblem() {
  // YAML 1.1 parsed `NO` / `OFF` / `YES` as booleans — the "Norway
  // problem". YAML 1.2 core schema uses ONLY true/True/TRUE/false/False/FALSE.
  var doc = b.parsers.yaml.parse("country: NO\nstate: ON\nflag: YES\n");
  check("yaml: 'NO' is string (Norway problem fixed)", doc.country === "NO");
  check("yaml: 'ON' is string",                          doc.state === "ON");
  check("yaml: 'YES' is string",                         doc.flag === "YES");
}

function testYamlBlockScalars() {
  var literal = b.parsers.yaml.parse(
    "msg: |\n" +
    "  line one\n" +
    "  line two\n"
  );
  check("yaml: literal block scalar preserves newlines",  literal.msg === "line one\nline two\n");

  var folded = b.parsers.yaml.parse(
    "msg: >\n" +
    "  paragraph one\n" +
    "  continues here\n" +
    "\n" +
    "  paragraph two\n"
  );
  check("yaml: folded block scalar collapses lines",
        folded.msg === "paragraph one continues here\nparagraph two\n");

  var stripped = b.parsers.yaml.parse(
    "msg: |-\n" +
    "  no trailing newline"
  );
  check("yaml: literal-strip removes trailing newline",  stripped.msg === "no trailing newline");
}

function testYamlQuotedStrings() {
  var doc = b.parsers.yaml.parse(
    "double: \"hello\\nworld\"\n" +
    "single: 'literal \\n stays'\n" +
    "embedded: 'it''s great'\n"
  );
  check("yaml: double-quoted decodes \\n",          doc.double === "hello\nworld");
  check("yaml: single-quoted preserves backslash",  doc.single === "literal \\n stays");
  check("yaml: single-quoted '' becomes apostrophe", doc.embedded === "it's great");
}

function testYamlSecurityRejections() {
  var threwAnchor = false;
  try { b.parsers.yaml.parse("a: &anchor 1\nb: *anchor"); }
  catch (e) { threwAnchor = e.code === "yaml/anchors-banned" || e.code === "yaml/aliases-banned"; }
  check("yaml: anchors/aliases rejected",          threwAnchor);

  var threwTag = false;
  try { b.parsers.yaml.parse("a: !!str 42"); }
  catch (e) { threwTag = e.code === "yaml/tags-banned"; }
  check("yaml: !!tag rejected",                    threwTag);

  var threwDirective = false;
  try { b.parsers.yaml.parse("%YAML 1.2\n---\nfoo: bar"); }
  catch (e) { threwDirective = e.code === "yaml/directives-banned"; }
  check("yaml: %YAML directive rejected",          threwDirective);

  var threwMultiDoc = false;
  try { b.parsers.yaml.parse("a: 1\n---\nb: 2"); }
  catch (e) { threwMultiDoc = e.code === "yaml/multi-document"; }
  check("yaml: multi-document streams rejected",   threwMultiDoc);

  var threwTab = false;
  try { b.parsers.yaml.parse("a:\n\tb: 1"); }
  catch (e) { threwTab = e.code === "yaml/tab-indent"; }
  check("yaml: tab in indent rejected",            threwTab);

  var threwProto = false;
  try { b.parsers.yaml.parse("__proto__: pwn"); }
  catch (e) { threwProto = e.code === "yaml/poisoned-key"; }
  check("yaml: __proto__ rejected",                threwProto);

  var threwMerge = false;
  try { b.parsers.yaml.parse("base: { a: 1 }\nderived:\n  <<: base\n  b: 2"); }
  catch (e) { threwMerge = e.code === "yaml/merge-key-banned"; }
  check("yaml: merge key '<<' rejected",           threwMerge);

  var threwDup = false;
  try { b.parsers.yaml.parse("a: 1\na: 2"); }
  catch (e) { threwDup = e.code === "yaml/duplicate-key"; }
  check("yaml: duplicate key rejected",            threwDup);

  var threwSize = false;
  try { b.parsers.yaml.parse("a: \"" + "x".repeat(2000) + "\"", { maxBytes: 1000 }); }
  catch (e) { threwSize = e.code === "yaml/too-large"; }
  check("yaml: maxBytes enforced",                 threwSize);

  var threwUnterm = false;
  try { b.parsers.yaml.parse("a: \"unterminated"); }
  catch (e) { threwUnterm = !!e.isYamlSafeError; }
  check("yaml: unterminated string rejected",      threwUnterm);
}

function testEnvParseBasic() {
  var src =
    "# comment\n" +
    "DATABASE_URL=postgres://localhost\n" +
    "PORT=8080\n" +
    "FEATURE_FLAG=true\n" +
    "EMPTY=\n" +
    "QUOTED=\"hello world\"\n" +
    "QUOTED_NL=\"line1\\nline2\"\n" +
    "LITERAL='no \\n escapes'\n" +
    "WITH_SPACES = trimmed\n" +
    "export EXPORTED=ok\n" +
    "INLINE=value # trailing comment\n";
  var values = b.parsers.env.parse(src);
  check("env: simple key/value",                   values.DATABASE_URL === "postgres://localhost");
  check("env: numeric stays a string by default",  values.PORT === "8080");
  check("env: bool stays a string by default",     values.FEATURE_FLAG === "true");
  check("env: empty value",                        values.EMPTY === "");
  check("env: double-quoted",                      values.QUOTED === "hello world");
  check("env: double-quoted decodes \\n",          values.QUOTED_NL === "line1\nline2");
  check("env: single-quoted preserves backslash",  values.LITERAL === "no \\n escapes");
  check("env: spaces around = stripped",           values.WITH_SPACES === "trimmed");
  check("env: 'export' prefix accepted",           values.EXPORTED === "ok");
  check("env: trailing # comment stripped",        values.INLINE === "value");
}

function testEnvParseSecurityRejections() {
  // $VAR expansion banned
  var threwExpand = false;
  try { b.parsers.env.parse("KEY=$OTHER"); }
  catch (e) { threwExpand = e.code === "env/expansion-banned"; }
  check("env: $VAR expansion rejected",            threwExpand);

  var threwExpandQuoted = false;
  try { b.parsers.env.parse("KEY=\"hello $WORLD\""); }
  catch (e) { threwExpandQuoted = e.code === "env/expansion-banned"; }
  check("env: $VAR in double-quoted rejected",     threwExpandQuoted);

  // \$ literal works
  var literal = b.parsers.env.parse("KEY=\"\\$LITERAL\"");
  check("env: \\$ literal escape works",           literal.KEY === "$LITERAL");

  // Bad key shape
  var threwShape = false;
  try { b.parsers.env.parse("lowercase=value"); }
  catch (e) { threwShape = e.code === "env/bad-key-shape"; }
  check("env: lowercase key rejected by default",  threwShape);

  // Hyphen rejected
  var threwHyphen = false;
  try { b.parsers.env.parse("MY-KEY=value"); }
  catch (e) { threwHyphen = e.code === "env/bad-key-shape"; }
  check("env: hyphenated key rejected by default", threwHyphen);

  // __proto__ rejected
  var threwProto = false;
  try { b.parsers.env.parse("__proto__=pwn"); }
  catch (e) { threwProto = e.code === "env/poisoned-key" || e.code === "env/bad-key-shape"; }
  check("env: __proto__ rejected",                 threwProto);

  // Duplicate key
  var threwDup = false;
  try { b.parsers.env.parse("KEY=1\nKEY=2"); }
  catch (e) { threwDup = e.code === "env/duplicate-key"; }
  check("env: duplicate key rejected",             threwDup);

  // Missing =
  var threwMissingEq = false;
  try { b.parsers.env.parse("KEY value"); }
  catch (e) { threwMissingEq = e.code === "env/bad-line"; }
  check("env: missing '=' rejected",               threwMissingEq);

  // Tab in unquoted value
  var threwTab = false;
  try { b.parsers.env.parse("KEY=\tvalue"); }
  catch (e) { threwTab = e.code === "env/tab-in-value"; }
  check("env: tab at start of value rejected",     threwTab);

  // Size cap
  var threwSize = false;
  try { b.parsers.env.parse("KEY=" + "x".repeat(2000), { maxBytes: 1000 }); }
  catch (e) { threwSize = e.code === "env/too-large"; }
  check("env: maxBytes enforced",                  threwSize);

  // Unterminated string
  var threwUnterm = false;
  try { b.parsers.env.parse("KEY=\"unterminated"); }
  catch (e) { threwUnterm = e.code === "env/unterminated-string"; }
  check("env: unterminated quoted rejected",       threwUnterm);
}

function testBufferSafeNormalizeText() {
  var bs = b.bufferSafe;
  check("bufferSafe.normalizeText is a function", typeof bs.normalizeText === "function");

  // string passthrough
  check("normalizeText: string passthrough", bs.normalizeText("hello") === "hello");

  // Buffer → string
  check("normalizeText: Buffer → string",
        bs.normalizeText(Buffer.from("héllo", "utf8")) === "héllo");

  // Uint8Array → string
  var u8 = new Uint8Array([0x68, 0x69]);
  check("normalizeText: Uint8Array → string", bs.normalizeText(u8) === "hi");

  // BOM stripped by default
  check("normalizeText: strips leading BOM",
        bs.normalizeText("﻿withBom") === "withBom");

  // BOM preserved when stripBom: false
  check("normalizeText: stripBom:false keeps BOM",
        bs.normalizeText("﻿withBom", { stripBom: false }) === "﻿withBom");

  // maxBytes enforced
  var threwSize = false;
  try { bs.normalizeText("x".repeat(2000), { maxBytes: 100 }); }
  catch (e) { threwSize = e.code === "buffer/too-large"; }
  check("normalizeText: maxBytes enforced", threwSize);

  // Wrong type rejected
  var threwType = false;
  try { bs.normalizeText(123); }
  catch (e) { threwType = e.code === "buffer/wrong-input-type"; }
  check("normalizeText: number rejected", threwType);

  // errorClass override
  function CustomErr(message, code) {
    Error.call(this, message);
    this.message = message;
    this.code = code;
    this.name = "CustomErr";
  }
  CustomErr.prototype = Object.create(Error.prototype);
  var threwCustom = false;
  try { bs.normalizeText(123, { errorClass: CustomErr, typeCode: "x/wrong-input-type" }); }
  catch (e) {
    threwCustom = e instanceof CustomErr && e.code === "x/wrong-input-type";
  }
  check("normalizeText: errorClass override", threwCustom);
}

function testBufferSafeToBuffer() {
  var bs = b.bufferSafe;
  check("bufferSafe.toBuffer is a function", typeof bs.toBuffer === "function");

  // Buffer passthrough (same instance)
  var orig = Buffer.from("hello", "utf8");
  check("toBuffer: Buffer passthrough", bs.toBuffer(orig) === orig);

  // string → Buffer
  var b1 = bs.toBuffer("héllo");
  check("toBuffer: string → Buffer", Buffer.isBuffer(b1) && b1.toString("utf8") === "héllo");

  // Uint8Array → Buffer
  var u8 = new Uint8Array([0x42, 0x43]);
  var b2 = bs.toBuffer(u8);
  check("toBuffer: Uint8Array → Buffer", Buffer.isBuffer(b2) && b2[0] === 0x42 && b2[1] === 0x43);

  // maxBytes cap
  var threwSize = false;
  try { bs.toBuffer("x".repeat(2000), { maxBytes: 100 }); }
  catch (e) { threwSize = e.code === "buffer/too-large"; }
  check("toBuffer: maxBytes enforced", threwSize);

  // Wrong type
  var threwType = false;
  try { bs.toBuffer(123); }
  catch (e) { threwType = e.code === "buffer/wrong-input-type"; }
  check("toBuffer: number rejected", threwType);
}

function testBufferSafeBoundedChunkCollector() {
  var bs = b.bufferSafe;
  check("bufferSafe.boundedChunkCollector is a function",
        typeof bs.boundedChunkCollector === "function");

  // Happy path
  var c = bs.boundedChunkCollector({ maxBytes: 100 });
  c.push(Buffer.from("hello "));
  c.push(Buffer.from("world"));
  check("collector: bytesCollected after pushes", c.bytesCollected() === 11);
  var out = c.result();
  check("collector: result joins chunks",
        Buffer.isBuffer(out) && out.toString("utf8") === "hello world");

  // String + Uint8Array also accepted
  var c2 = bs.boundedChunkCollector({ maxBytes: 100 });
  c2.push("foo");
  c2.push(new Uint8Array([0x62, 0x61, 0x72]));
  check("collector: accepts string + Uint8Array",
        c2.result().toString("utf8") === "foobar");

  // Cap enforced AT push time (the OOM defense)
  var c3 = bs.boundedChunkCollector({ maxBytes: 10 });
  c3.push(Buffer.alloc(8));
  var threwOverflow = false;
  try { c3.push(Buffer.alloc(5)); }  // 8 + 5 = 13 > 10
  catch (e) { threwOverflow = e.code === "buffer/too-large"; }
  check("collector: rejects at push when overflow", threwOverflow);
  // After overflow the collector retains the previously-pushed bytes —
  // intentional, callers expect to inspect partial state on error.
  check("collector: state preserved on overflow", c3.bytesCollected() === 8);

  // maxBytes required
  var threwBadArg = false;
  try { bs.boundedChunkCollector({}); }
  catch (e) { threwBadArg = e.code === "buffer/bad-arg"; }
  check("collector: requires maxBytes", threwBadArg);
}

// ---- url-safe ----

function testUrlSafeDefaultIsHttpsOnly() {
  var u = b.urlSafe;
  // Default allowlist = ALLOW_HTTP_TLS (https only). http:// rejected.
  var rejected = null;
  try { u.parse("http://example.com/x"); }
  catch (e) { rejected = e; }
  check("url-safe: http rejected by default",         rejected !== null);
  check("url-safe: rejection is UrlSafeError",        rejected instanceof u.UrlSafeError);
  check("url-safe: rejection code = protocol-disallowed",
        rejected.code === "url-safe/protocol-disallowed");

  // https:// accepted by default
  var ok = u.parse("https://example.com/x");
  check("url-safe: https accepted by default",        ok.protocol === "https:");
}

function testUrlSafeCustomAllowlist() {
  var u = b.urlSafe;
  // ALLOW_HTTP_ALL accepts both http: and https:
  var http  = u.parse("http://example.com/",  { allowedProtocols: u.ALLOW_HTTP_ALL });
  var https = u.parse("https://example.com/", { allowedProtocols: u.ALLOW_HTTP_ALL });
  check("url-safe: ALLOW_HTTP_ALL accepts http",  http.protocol === "http:");
  check("url-safe: ALLOW_HTTP_ALL accepts https", https.protocol === "https:");

  // ALLOW_WS_TLS rejects http: even with same host
  var rejected = null;
  try { u.parse("https://example.com/", { allowedProtocols: u.ALLOW_WS_TLS }); }
  catch (e) { rejected = e; }
  check("url-safe: WS_TLS rejects https (category error)", rejected !== null);

  var ws = u.parse("wss://example.com/sock", { allowedProtocols: u.ALLOW_WS_TLS });
  check("url-safe: ALLOW_WS_TLS accepts wss", ws.protocol === "wss:");
}

function testUrlSafeMalformed() {
  var u = b.urlSafe;
  var malformed = null;
  try { u.parse("not-a-url"); }
  catch (e) { malformed = e; }
  check("url-safe: malformed rejects",       malformed !== null);
  check("url-safe: malformed code",          malformed.code === "url-safe/malformed");

  var missing = null;
  try { u.parse(""); }
  catch (e) { missing = e; }
  check("url-safe: empty rejects",           missing !== null);
  check("url-safe: empty code = missing",    missing.code === "url-safe/missing");

  var nullMissing = null;
  try { u.parse(null); }
  catch (e) { nullMissing = e; }
  check("url-safe: null rejects",            nullMissing !== null);
}

function testUrlSafeUrlInstancePassThrough() {
  var u = b.urlSafe;
  var { URL } = require("url");
  var input = new URL("https://example.com/already-parsed");
  var out = u.parse(input);
  check("url-safe: URL instance returned as-is", out === input);
}

function testUrlSafeErrorClassInjection() {
  var u = b.urlSafe;
  var rejected = null;
  try {
    u.parse("ftp://example.com/", { errorClass: b.frameworkError.ObjectStoreError });
  } catch (e) { rejected = e; }
  check("url-safe: errorClass injection returns custom class",
        rejected instanceof b.frameworkError.ObjectStoreError);
  check("url-safe: injected error carries protocol-disallowed code",
        rejected.code === "url-safe/protocol-disallowed");
  // Operational errors get permanent=true (retry won't help fix a bad URL)
  check("url-safe: injected error is permanent",
        rejected.permanent === true);
}

function testUrlSafeAllowAny() {
  var u = b.urlSafe;
  var schemes = ["http://h/", "https://h/", "ws://h/", "wss://h/"];
  for (var i = 0; i < schemes.length; i++) {
    var ok = u.parse(schemes[i], { allowedProtocols: u.ALLOW_ANY });
    check("url-safe: ALLOW_ANY accepts " + schemes[i],
          ok.protocol === schemes[i].split("://")[0] + ":");
  }
  // ftp:// still blocked even by ALLOW_ANY
  var rejected = null;
  try { u.parse("ftp://h/", { allowedProtocols: u.ALLOW_ANY }); }
  catch (e) { rejected = e; }
  check("url-safe: ALLOW_ANY still rejects ftp:", rejected !== null);
}

async function testHttpClientBasic() {
  var http = require("http");
  // Local mock server — listens on a random port, captures method+path.
  var server = http.createServer(function (req, res) {
    var chunks = [];
    req.on("data", function (c) { chunks.push(c); });
    req.on("end", function () {
      var body = Buffer.concat(chunks).toString("utf8");
      res.writeHead(200, { "Content-Type": "text/plain", "X-Method": req.method });
      res.end("got " + req.method + " " + req.url + " body=" + body);
    });
  });
  var port = await listenOnRandomPort(server);
  try {
    b.httpClient._resetForTest();

    // GET
    var got = await httpReq({ url: "http://127.0.0.1:" + port + "/foo" });
    check("httpClient: GET status",          got.statusCode === 200);
    check("httpClient: GET body buffered",   Buffer.isBuffer(got.body));
    check("httpClient: GET body content",    got.body.toString("utf8").indexOf("got GET /foo") === 0);
    check("httpClient: GET headers",         got.headers["x-method"] === "GET");

    // POST with Buffer body
    var posted = await httpReq({
      method: "POST", url: "http://127.0.0.1:" + port + "/bar",
      body: Buffer.from("hello", "utf8"),
    });
    check("httpClient: POST body sent", posted.body.toString("utf8").indexOf("body=hello") !== -1);

    // Connection pooling — same origin reuses the cached agent
    check("httpClient: transport cached after first call",
          b.httpClient._getCachedTransportCount() >= 1);
    await httpReq({ url: "http://127.0.0.1:" + port + "/baz" });
    check("httpClient: same origin reuses transport",
          b.httpClient._getCachedTransportCount() === 1);
  } finally {
    server.close();
    b.httpClient._resetForTest();
  }
}

async function testHttpClientErrorStatus() {
  var http = require("http");
  var server = http.createServer(function (req, res) {
    if (req.url === "/notfound") { res.writeHead(404); res.end("missing"); }
    else if (req.url === "/throttle") { res.writeHead(429); res.end("slow down"); }
    else if (req.url === "/boom") { res.writeHead(500); res.end("oops"); }
    else { res.writeHead(200); res.end("ok"); }
  });
  var port = await listenOnRandomPort(server);
  try {
    b.httpClient._resetForTest();

    // 404 → permanent
    var threw404 = null;
    try { await httpReq({ url: "http://127.0.0.1:" + port + "/notfound", errorClass: b.frameworkError.ObjectStoreError }); }
    catch (e) { threw404 = e; }
    check("httpClient: 404 rejects",            threw404 !== null);
    check("httpClient: 404 ObjectStoreError",   threw404 instanceof b.frameworkError.ObjectStoreError);
    check("httpClient: 404 statusCode",         threw404.statusCode === 404);
    check("httpClient: 404 permanent",          threw404.permanent === true);

    // 429 → transient
    var threw429 = null;
    try { await httpReq({ url: "http://127.0.0.1:" + port + "/throttle", errorClass: b.frameworkError.ObjectStoreError }); }
    catch (e) { threw429 = e; }
    check("httpClient: 429 transient (not permanent)", threw429.permanent === false);

    // 500 → transient
    var threw500 = null;
    try { await httpReq({ url: "http://127.0.0.1:" + port + "/boom", errorClass: b.frameworkError.ObjectStoreError }); }
    catch (e) { threw500 = e; }
    check("httpClient: 500 transient", threw500.permanent === false);
  } finally {
    server.close();
    b.httpClient._resetForTest();
  }
}

async function testHttpClientWallClockTimeout() {
  var http = require("http");
  var server = http.createServer(function (req, res) {
    // Slow responder — write headers, dribble bytes well past timeout.
    res.writeHead(200);
    var i = 0;
    var iv = setInterval(function () {
      if (i++ >= 50) { clearInterval(iv); res.end(); return; }
      res.write("x");
    }, 50);
    req.on("close", function () { clearInterval(iv); });
  });
  var port = await listenOnRandomPort(server);
  try {
    b.httpClient._resetForTest();
    var threw = null;
    var t0 = Date.now();
    try {
      await httpReq({
        url: "http://127.0.0.1:" + port + "/slow",
        timeoutMs: 200,                 // wall-clock — must fire even if data IS flowing
        idleTimeoutMs: 5000,            // generous idle so wall-clock is what fires
      });
    } catch (e) { threw = e; }
    var elapsed = Date.now() - t0;
    check("httpClient: wall-clock timeout fires",     threw !== null);
    check("httpClient: timeout error code ETIMEDOUT", threw && threw.code === "ETIMEDOUT");
    check("httpClient: wall-clock fired within 1s",    elapsed < 1000);
  } finally {
    server.close();
    b.httpClient._resetForTest();
  }
}

async function testHttpClientAbortSignal() {
  var http = require("http");
  var server = http.createServer(function (req, res) {
    // Hang forever — only cancellation can free this.
    res.writeHead(200);
    // Don't end; wait for client disconnect.
    req.on("close", function () { try { res.end(); } catch (_e) {} });
  });
  var port = await listenOnRandomPort(server);
  try {
    b.httpClient._resetForTest();
    var ac = new AbortController();
    setTimeout(function () { ac.abort(); }, 100);
    var threw = null;
    try {
      await httpReq({
        url: "http://127.0.0.1:" + port + "/hang",
        signal: ac.signal,
        idleTimeoutMs: 60000,
      });
    } catch (e) { threw = e; }
    check("httpClient: AbortSignal cancels request",  threw !== null);
    check("httpClient: abort code ABORT",             threw && threw.code === "ABORT");
  } finally {
    server.close();
    b.httpClient._resetForTest();
  }
}

async function testHttpClientStreamResponse() {
  var http = require("http");
  var server = http.createServer(function (req, res) {
    res.writeHead(200, { "Content-Type": "application/octet-stream" });
    res.write("part1-");
    res.write("part2-");
    res.end("end");
  });
  var port = await listenOnRandomPort(server);
  try {
    b.httpClient._resetForTest();
    var got = await httpReq({
      url: "http://127.0.0.1:" + port + "/stream",
      responseMode: "stream",
    });
    check("httpClient: stream mode returns Readable",
          got.body && typeof got.body.on === "function");
    var collected = await new Promise(function (resolve, reject) {
      var chunks = [];
      got.body.on("data", function (c) { chunks.push(c); });
      got.body.on("end",  function ()  { resolve(Buffer.concat(chunks).toString("utf8")); });
      got.body.on("error", reject);
    });
    check("httpClient: stream content", collected === "part1-part2-end");
  } finally {
    server.close();
    b.httpClient._resetForTest();
  }
}

async function testHttpClientH2Basic() {
  var http2 = require("http2");
  // h2c (cleartext h2) mock server
  var server = http2.createServer();
  server.on("stream", function (stream, headers) {
    var method = headers[":method"];
    var path   = headers[":path"];
    var chunks = [];
    stream.on("data", function (c) { chunks.push(c); });
    stream.on("end", function () {
      var bodyIn = Buffer.concat(chunks).toString("utf8");
      stream.respond({ ":status": 200, "x-method": method, "content-type": "text/plain" });
      stream.end("h2 got " + method + " " + path + " body=" + bodyIn);
    });
  });
  var port = await listenOnRandomPort(server);
  try {
    b.httpClient._resetForTest();
    var url = "http://127.0.0.1:" + port + "/foo";

    // GET via h2c — preferH2 flag opts in (no ALPN over cleartext)
    var got = await httpReq({ url: url, preferH2: true });
    check("httpClient h2: GET status",       got.statusCode === 200);
    check("httpClient h2: GET body",         got.body.toString("utf8").indexOf("h2 got GET /foo") === 0);
    check("httpClient h2: GET headers",      got.headers["x-method"] === "GET");

    // Transport cache shows h2 kind
    check("httpClient h2: cached as h2",     b.httpClient._getCachedTransportKind(url) === "h2");

    // POST with body — same h2 session multiplexes
    var posted = await httpReq({
      method: "POST", url: url, body: Buffer.from("hello-h2"), preferH2: true,
    });
    check("httpClient h2: POST body sent",   posted.body.toString("utf8").indexOf("body=hello-h2") !== -1);

    // Transport count = 1 (multiplexed over single session)
    check("httpClient h2: single session",   b.httpClient._getCachedTransportCount() === 1);
  } finally {
    server.close();
    b.httpClient._resetForTest();
  }
}

async function testHttpClientH2AbortSignal() {
  var http2 = require("http2");
  var server = http2.createServer();
  server.on("stream", function (stream, _headers) {
    stream.respond({ ":status": 200 });
    // Hang — only client cancellation closes this stream.
    stream.on("close", function () {});
  });
  var port = await listenOnRandomPort(server);
  try {
    b.httpClient._resetForTest();
    var url = "http://127.0.0.1:" + port + "/hang";
    var ac = new AbortController();
    setTimeout(function () { ac.abort(); }, 100);
    var threw = null;
    try {
      await httpReq({ url: url, preferH2: true, signal: ac.signal, idleTimeoutMs: 60000 });
    } catch (e) { threw = e; }
    check("httpClient h2: AbortSignal cancels stream", threw !== null);
    check("httpClient h2: abort code ABORT",           threw && threw.code === "ABORT");
  } finally {
    server.close();
    b.httpClient._resetForTest();
  }
}

async function testHttpClientH2ErrorStatus() {
  var http2 = require("http2");
  var server = http2.createServer();
  server.on("stream", function (stream, headers) {
    if (headers[":path"] === "/notfound") {
      stream.respond({ ":status": 404 }); stream.end("missing");
    } else if (headers[":path"] === "/throttle") {
      stream.respond({ ":status": 429 }); stream.end("slow down");
    } else {
      stream.respond({ ":status": 500 }); stream.end("oops");
    }
  });
  var port = await listenOnRandomPort(server);
  try {
    b.httpClient._resetForTest();

    var threw404 = null;
    try { await httpReq({ url: "http://127.0.0.1:" + port + "/notfound", preferH2: true, errorClass: b.frameworkError.ObjectStoreError }); }
    catch (e) { threw404 = e; }
    check("httpClient h2: 404 rejects",           threw404 !== null);
    check("httpClient h2: 404 ObjectStoreError",  threw404 instanceof b.frameworkError.ObjectStoreError);
    check("httpClient h2: 404 statusCode",        threw404.statusCode === 404);
    check("httpClient h2: 404 permanent",         threw404.permanent === true);

    var threw429 = null;
    try { await httpReq({ url: "http://127.0.0.1:" + port + "/throttle", preferH2: true, errorClass: b.frameworkError.ObjectStoreError }); }
    catch (e) { threw429 = e; }
    check("httpClient h2: 429 transient", threw429.permanent === false);

    var threw500 = null;
    try { await httpReq({ url: "http://127.0.0.1:" + port + "/boom", preferH2: true, errorClass: b.frameworkError.ObjectStoreError }); }
    catch (e) { threw500 = e; }
    check("httpClient h2: 500 transient", threw500.permanent === false);
  } finally {
    server.close();
    b.httpClient._resetForTest();
  }
}

async function testHttpClientH2Multiplex() {
  var http2 = require("http2");
  var server = http2.createServer();
  server.on("stream", function (stream, headers) {
    // Tag response with the request path so we can verify each request
    // landed independently — they share the session, not the response.
    setTimeout(function () {
      stream.respond({ ":status": 200 });
      stream.end("path=" + headers[":path"]);
    }, 10);
  });
  var port = await listenOnRandomPort(server);
  try {
    b.httpClient._resetForTest();
    // Fire 5 concurrent requests over the same h2 session.
    var promises = [];
    for (var i = 0; i < 5; i++) {
      promises.push(httpReq({
        url: "http://127.0.0.1:" + port + "/p" + i,
        preferH2: true,
      }));
    }
    var results = await Promise.all(promises);
    var bodies = results.map(function (r) { return r.body.toString("utf8"); }).sort();
    check("httpClient h2: 5 multiplexed responses", bodies.length === 5);
    check("httpClient h2: each response carries its path",
          bodies[0] === "path=/p0" && bodies[4] === "path=/p4");
    // All 5 sharing one cached session
    check("httpClient h2: still one cached session", b.httpClient._getCachedTransportCount() === 1);
  } finally {
    server.close();
    b.httpClient._resetForTest();
  }
}

async function testHttpClientH2Stream() {
  var http2 = require("http2");
  var server = http2.createServer();
  server.on("stream", function (stream) {
    stream.respond({ ":status": 200 });
    stream.write("part1-");
    stream.write("part2-");
    stream.end("end");
  });
  var port = await listenOnRandomPort(server);
  try {
    b.httpClient._resetForTest();
    var got = await httpReq({
      url: "http://127.0.0.1:" + port + "/stream",
      preferH2: true,
      responseMode: "stream",
    });
    check("httpClient h2: stream returns Readable",
          got.body && typeof got.body.on === "function");
    var collected = await new Promise(function (resolve, reject) {
      var chunks = [];
      got.body.on("data", function (c) { chunks.push(c); });
      got.body.on("end",  function ()  { resolve(Buffer.concat(chunks).toString("utf8")); });
      got.body.on("error", reject);
    });
    check("httpClient h2: stream content", collected === "part1-part2-end");
  } finally {
    server.close();
    b.httpClient._resetForTest();
  }
}

function testWebSocketHandshake() {
  var ws = b.websocket;

  // Sec-WebSocket-Accept derivation — RFC 6455 §1.3 example
  // key "dGhlIHNhbXBsZSBub25jZQ==" should produce
  // "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
  check("computeAcceptKey: RFC 6455 example",
        ws.computeAcceptKey("dGhlIHNhbXBsZSBub25jZQ==") === "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");

  // validateUpgradeRequest happy path
  var goodReq = {
    method: "GET",
    headers: {
      "upgrade": "websocket",
      "connection": "Upgrade",
      "sec-websocket-key": "dGhlIHNhbXBsZSBub25jZQ==",
      "sec-websocket-version": "13",
    },
  };
  check("validateUpgradeRequest: happy path",
        ws.validateUpgradeRequest(goodReq).ok === true);

  // Missing headers — each rejection
  var badMethod = Object.assign({}, goodReq, { method: "POST" });
  check("validateUpgradeRequest: rejects POST",
        ws.validateUpgradeRequest(badMethod).ok === false);

  var badVersion = { method: "GET", headers: Object.assign({}, goodReq.headers, { "sec-websocket-version": "8" }) };
  check("validateUpgradeRequest: rejects version != 13",
        ws.validateUpgradeRequest(badVersion).ok === false);

  // Connection header with multiple tokens
  var multiConn = { method: "GET", headers: Object.assign({}, goodReq.headers, { "connection": "keep-alive, Upgrade" }) };
  check("validateUpgradeRequest: accepts multi-token Connection",
        ws.validateUpgradeRequest(multiConn).ok === true);

  // Origin policy
  var browserReq = { method: "GET", headers: Object.assign({}, goodReq.headers, { "origin": "https://app.example.com" }) };
  check("isOriginAllowed: undefined origins accepts all", ws.isOriginAllowed(browserReq, null) === true);
  check("isOriginAllowed: '*' accepts all",               ws.isOriginAllowed(browserReq, "*") === true);
  check("isOriginAllowed: allowlist match",
        ws.isOriginAllowed(browserReq, ["https://app.example.com"]) === true);
  check("isOriginAllowed: allowlist miss",
        ws.isOriginAllowed(browserReq, ["https://other.example.com"]) === false);
  // Non-browser client (no Origin header) bypasses origin policy
  check("isOriginAllowed: no Origin header bypasses (non-browser)",
        ws.isOriginAllowed(goodReq, ["https://app.example.com"]) === true);

  // Subprotocol negotiation
  var protoReq = { method: "GET", headers: Object.assign({}, goodReq.headers, { "sec-websocket-protocol": "chat, foo, graphql-ws" }) };
  check("negotiateSubprotocol: picks first match",
        ws.negotiateSubprotocol(protoReq, ["graphql-ws", "chat"]) === "chat");
  check("negotiateSubprotocol: returns null on no match",
        ws.negotiateSubprotocol(protoReq, ["other"]) === null);
  check("negotiateSubprotocol: empty supported returns null",
        ws.negotiateSubprotocol(protoReq, []) === null);
}

function testWebSocketFrames() {
  var ws = b.websocket;

  // Round-trip: serialize → parse → same data, opcode preserved.
  var payload = Buffer.from("hello websocket", "utf8");
  var frame = ws.serializeFrame(ws.OPCODE_TEXT, payload);
  // Mask the frame so the parser (which expects client-side frames)
  // accepts it. Use the parser via the FrameParser API.
  // Build a masked variant by hand for the parser test.
  // The serializer's mask:true path produces a client-shaped frame.
  var masked = ws.serializeFrame(ws.OPCODE_TEXT, payload, { mask: true });
  var parser = new ws.FrameParser({ maxFrameBytes: 1024 });
  var frames = parser.push(masked);
  check("FrameParser: parses single masked frame", frames.length === 1);
  check("FrameParser: opcode preserved",            frames[0].opcode === ws.OPCODE_TEXT);
  check("FrameParser: payload preserved",           frames[0].payload.equals(payload));
  check("FrameParser: masked flag set",             frames[0].masked === true);
  check("FrameParser: fin flag set",                frames[0].fin === true);

  // Extended length encoding — 16-bit (126)
  var medPayload = Buffer.alloc(200);
  for (var i = 0; i < 200; i++) medPayload[i] = i & 0xFF;
  var medMasked = ws.serializeFrame(ws.OPCODE_BINARY, medPayload, { mask: true });
  parser = new ws.FrameParser({ maxFrameBytes: 65536 });
  frames = parser.push(medMasked);
  check("FrameParser: 16-bit length frame", frames[0].payload.equals(medPayload));

  // Extended length encoding — 64-bit (127). Use a payload >65535.
  var largePayload = Buffer.alloc(70000);
  largePayload.fill(0x42);
  var largeMasked = ws.serializeFrame(ws.OPCODE_BINARY, largePayload, { mask: true });
  parser = new ws.FrameParser({ maxFrameBytes: 1024 * 1024 });
  frames = parser.push(largeMasked);
  check("FrameParser: 64-bit length frame", frames[0].payload.length === 70000 && frames[0].payload[0] === 0x42);

  // Incremental parsing — split a frame across two pushes
  var split1 = masked.subarray(0, 5);
  var split2 = masked.subarray(5);
  parser = new ws.FrameParser({ maxFrameBytes: 1024 });
  var part1 = parser.push(split1);
  var part2 = parser.push(split2);
  check("FrameParser: partial first push yields nothing",  part1.length === 0);
  check("FrameParser: completing push yields the frame",   part2.length === 1);
  check("FrameParser: split frame payload intact",         part2[0].payload.equals(payload));

  // Frame size cap rejection
  var threwTooLarge = false;
  try {
    var tinyParser = new ws.FrameParser({ maxFrameBytes: 100 });
    tinyParser.push(largeMasked);
  } catch (e) {
    threwTooLarge = e.code === "ws/frame-too-large";
  }
  check("FrameParser: rejects oversized frame", threwTooLarge);
}

function testRouterWsValidation() {
  var router = new b.router.Router();

  // Bad path
  var threw1 = false;
  try { router.ws("", function () {}); } catch (_e) { threw1 = true; }
  check("router.ws: rejects empty path", threw1);

  // Bad handler
  var threw2 = false;
  try { router.ws("/foo", "not-a-function"); } catch (_e) { threw2 = true; }
  check("router.ws: rejects non-function handler", threw2);

  // Bad transport
  var threw3 = false;
  try { router.ws("/foo", function () {}, { transport: "h3" }); } catch (_e) { threw3 = true; }
  check("router.ws: rejects unknown transport", threw3);

  // All valid transports accepted
  var ok = true;
  try {
    router.ws("/auto",     function () {}, { origins: "*", transport: "auto" });
    router.ws("/h1",       function () {}, { origins: "*", transport: "h1-only" });
    router.ws("/h2",       function () {}, { origins: "*", transport: "h2-only" });
  } catch (_e) { ok = false; }
  check("router.ws: accepts auto / h1-only / h2-only", ok);
  check("router.ws: registered routes counted",
        router._wsRoutes.size === 3);
}

async function testWebSocketConnection() {
  var net = require("net");
  var ws = b.websocket;

  // Mock TCP server that hand-rolls handshake validation + WebSocketConnection
  var connections = [];
  var server = net.createServer(function (socket) {
    var headerBuffer = "";
    var headersDone = false;
    socket.on("data", function (chunk) {
      if (headersDone) return;
      headerBuffer += chunk.toString("utf8");
      var idx = headerBuffer.indexOf("\r\n\r\n");
      if (idx === -1) return;
      headersDone = true;
      // Parse HTTP headers (very crude — enough for tests).
      var headerLines = headerBuffer.substring(0, idx).split("\r\n");
      var requestLine = headerLines[0].split(" ");
      var headers = {};
      for (var i = 1; i < headerLines.length; i++) {
        var p = headerLines[i].indexOf(":");
        if (p === -1) continue;
        var k = headerLines[i].substring(0, p).trim().toLowerCase();
        var v = headerLines[i].substring(p + 1).trim();
        headers[k] = v;
      }
      var req = { method: requestLine[0], url: requestLine[1], headers: headers };
      var head = Buffer.from(headerBuffer.substring(idx + 4), "binary");
      var conn = ws.handleUpgrade(req, socket, head, { closeGraceMs: 50 });
      if (conn) {
        connections.push(conn);
        // Echo handler
        conn.on("message", function (data, isBinary) {
          conn.send(isBinary ? data : "echo:" + data);
        });
      }
    });
  });
  var port = await listenOnRandomPort(server);

  try {
    // Open a raw TCP socket, send the upgrade handshake, then exchange frames.
    var client = net.connect(port, "127.0.0.1");
    await new Promise(function (r) { client.once("connect", r); });

    var key = nodeCryptoForTest().randomBytes(16).toString("base64");
    var handshakeRequest =
      "GET / HTTP/1.1\r\n" +
      "Host: 127.0.0.1:" + port + "\r\n" +
      "Upgrade: websocket\r\n" +
      "Connection: Upgrade\r\n" +
      "Sec-WebSocket-Key: " + key + "\r\n" +
      "Sec-WebSocket-Version: 13\r\n" +
      "\r\n";
    client.write(handshakeRequest);

    // Read the 101 response + check the Sec-WebSocket-Accept matches.
    var responseBuf = await _readUntil(client, "\r\n\r\n");
    var responseStr = responseBuf.toString("utf8");
    check("WebSocketConnection: 101 response sent",
          responseStr.indexOf("HTTP/1.1 101") === 0);
    var expectedAccept = ws.computeAcceptKey(key);
    check("WebSocketConnection: Sec-WebSocket-Accept correct",
          responseStr.toLowerCase().indexOf("sec-websocket-accept: " + expectedAccept.toLowerCase()) !== -1);

    // Send a masked text frame "ping-test"
    var clientFrame = ws.serializeFrame(ws.OPCODE_TEXT, Buffer.from("ping-test", "utf8"), { mask: true });
    client.write(clientFrame);

    // Read the server's echo (unmasked) — buffered until we have at least one frame.
    var echoBuf = await _readNBytes(client, 2);   // header at minimum
    // Use FrameParser on the response
    var parser = new ws.FrameParser({ maxFrameBytes: 1024 });
    var echoChunks = [echoBuf];
    var echoFrames = parser.push(echoBuf);
    while (echoFrames.length === 0) {
      var more = await _readSome(client);
      echoChunks.push(more);
      echoFrames = parser.push(more);
    }
    check("WebSocketConnection: server echoed frame",
          echoFrames[0].payload.toString("utf8") === "echo:ping-test");
    check("WebSocketConnection: server echo unmasked",
          echoFrames[0].masked === false);

    // Close handshake — client sends close, server echoes.
    var closePayload = Buffer.alloc(2);
    closePayload.writeUInt16BE(1000, 0);
    var clientClose = ws.serializeFrame(ws.OPCODE_CLOSE, closePayload, { mask: true });
    client.write(clientClose);

    // Read server's close echo.
    var closeRead = await _readSome(client);
    var closeFrames = parser.push(closeRead);
    var closeFrame = closeFrames.find(function (f) { return f.opcode === ws.OPCODE_CLOSE; });
    check("WebSocketConnection: server echoed close",
          closeFrame !== undefined);
    check("WebSocketConnection: close code 1000",
          closeFrame && closeFrame.payload.readUInt16BE(0) === 1000);

    // Verified at protocol level — close frame received. TCP teardown
    // is incidental; don't block the test on it. closeGraceMs:50 on
    // the server side keeps the actual TCP teardown fast anyway.
  } finally {
    try { server.closeAllConnections(); } catch (_e) {}
    await new Promise(function (r) { server.close(function () { r(); }); });
  }
}

// Test helpers — local to the websocket suite. nodeCrypto for the
// random key, _readUntil/_readNBytes/_readSome for incremental client
// socket reads.
function nodeCryptoForTest() { return require("crypto"); }
function _readUntil(socket, marker) {
  return new Promise(function (resolve) {
    var buf = Buffer.alloc(0);
    function onData(chunk) {
      buf = Buffer.concat([buf, chunk]);
      if (buf.toString("binary").indexOf(marker) !== -1) {
        socket.removeListener("data", onData);
        resolve(buf);
      }
    }
    socket.on("data", onData);
  });
}
function _readNBytes(socket, n) {
  return new Promise(function (resolve) {
    var chunks = [];
    var have = 0;
    function onData(chunk) {
      chunks.push(chunk);
      have += chunk.length;
      if (have >= n) {
        socket.removeListener("data", onData);
        resolve(Buffer.concat(chunks));
      }
    }
    socket.on("data", onData);
  });
}
function _readSome(socket) {
  return new Promise(function (resolve) {
    socket.once("data", resolve);
  });
}

async function testHttpClientObserver() {
  var http = require("http");
  var server = http.createServer(function (req, res) { res.writeHead(200); res.end("ok"); });
  var port = await listenOnRandomPort(server);
  try {
    b.httpClient._resetForTest();
    var stages = [];
    var observer = function (stage, info) { stages.push({ stage: stage, info: info }); };
    await httpReq({ url: "http://127.0.0.1:" + port + "/obs", observer: observer });
    check("httpClient: observer saw request:start",     stages[0].stage === "request:start");
    check("httpClient: observer saw response:headers",  stages[1].stage === "response:headers");
    check("httpClient: observer saw response:end",      stages[2].stage === "response:end");
    check("httpClient: observer info has durationMs",   typeof stages[2].info.durationMs === "number");
  } finally {
    server.close();
    b.httpClient._resetForTest();
  }
}

function testConstantsReferenceIntegrity() {
  // Static scan: walks lib/ for `C.TIME.X` / `C.BYTES.X` references and
  // verifies every X resolves to a known function. Catches the class of
  // bug where a stale all-caps constant (e.g. C.TIME.FIVE_MIN) silently
  // evaluates to `undefined` and propagates into setInterval / setTimeout
  // / server.timeout call sites — Node coerces undefined to a small
  // positive integer for those, so the bug shows up as 1ms-tight loops
  // instead of a noisy crash. Live evidence: a stale FIVE_MIN reference
  // in db.js + router.js sat undetected because neither call site
  // throws when the constant is missing.
  //
  // File reads go through b.atomicFile.readSync (framework primitive,
  // size-capped + error-classed). Directory listing uses fs.readdirSync
  // — the framework lacks a list-dir primitive today (atomic-file owns
  // single-file ops); 5+ other lib/ sites use fs.readdirSync the same
  // way, so this matches existing convention pending a future
  // atomicFile.listDir primitive.
  var TIME_FNS  = new Set(Object.keys(b.constants.TIME));
  var BYTES_FNS = new Set(Object.keys(b.constants.BYTES));

  function _walk(dir, out) {
    var entries = fs.readdirSync(dir, { withFileTypes: true });
    for (var i = 0; i < entries.length; i++) {
      var ent = entries[i];
      if (ent.name === "vendor") continue;            // skip vendored libs
      if (ent.name === "node_modules") continue;
      var full = path.join(dir, ent.name);
      if (ent.isDirectory()) _walk(full, out);
      else if (ent.isFile() && ent.name.endsWith(".js")) out.push(full);
    }
  }

  var libRoot = path.join(__dirname, "..", "lib");
  var files = [];
  _walk(libRoot, files);

  var pattern = /\b(?:C\.)?(TIME|BYTES)\.([A-Za-z_][A-Za-z0-9_]*)\b/g;

  var bad = [];
  for (var f = 0; f < files.length; f++) {
    var src = b.atomicFile.readSync(files[f]).toString("utf8");
    var stripped = src
      .replace(/\/\*[\s\S]*?\*\//g, "")
      .replace(/\/\/[^\n]*/g, "");
    var m;
    while ((m = pattern.exec(stripped)) !== null) {
      var ns = m[1];
      var ident = m[2];
      var known = ns === "TIME" ? TIME_FNS : BYTES_FNS;
      if (!known.has(ident)) {
        bad.push(files[f].replace(libRoot, "lib") + " : C." + ns + "." + ident);
      }
    }
    pattern.lastIndex = 0;
  }

  check("constants integrity: every C.TIME.X / C.BYTES.X resolves to a known function",
        bad.length === 0);
  if (bad.length > 0) {
    console.error("Stale constant references:");
    for (var i = 0; i < bad.length; i++) console.error("  " + bad[i]);
  }
}

function testLogger() {
  check("logger namespace present",        typeof b.logger === "object");
  check("logger.createLogger is function", typeof b.logger.createLogger === "function");

  // Capture console output by stubbing
  var origLog = console.log;
  var origErr = console.error;
  var captured = { log: [], error: [] };
  console.log   = function (msg) { captured.log.push(msg); };
  console.error = function (msg) { captured.error.push(msg); };

  try {
    var log = b.logger.createLogger("testmod");

    // Default invocation = info → console.log
    log("hello");
    check("logger: default invocation logs to stdout", captured.log[0] === "[blamejs:testmod] hello");

    // .info path
    log.info("info msg");
    check("logger: .info logs to stdout", captured.log[1] === "[blamejs:testmod] info msg");

    // .warn → stderr
    log.warn("warn msg");
    check("logger: .warn logs to stderr", captured.error[0] === "[blamejs:testmod] warn msg");

    // .error → stderr
    log.error("err msg");
    check("logger: .error logs to stderr", captured.error[1] === "[blamejs:testmod] err msg");

    // .prefix exposed
    check("logger: .prefix exposes the namespace", log.prefix === "[blamejs:testmod] ");

    // Empty / non-string name rejected
    var threw = false;
    try { b.logger.createLogger(""); } catch (_e) { threw = true; }
    check("logger: rejects empty name", threw);

    var threw2 = false;
    try { b.logger.createLogger(null); } catch (_e) { threw2 = true; }
    check("logger: rejects non-string name", threw2);
  } finally {
    console.log = origLog;
    console.error = origErr;
  }
}

function testFrameworkError() {
  var fe = b.frameworkError;
  check("frameworkError namespace present", typeof fe === "object");
  check("FrameworkError class present",     typeof fe.FrameworkError === "function");

  // Base class shape
  var base = new fe.FrameworkError("oops", "test/err");
  check("FrameworkError: name",        base.name === "FrameworkError");
  check("FrameworkError: code",        base.code === "test/err");
  check("FrameworkError: isFrameworkError flag",  base.isFrameworkError === true);
  check("FrameworkError: instanceof Error",       base instanceof Error);

  // Cross-module subclasses
  var oserr = new fe.ObjectStoreError("BUCKET_NOT_FOUND", "missing", true, 404);
  check("ObjectStoreError: extends FrameworkError", oserr instanceof fe.FrameworkError);
  check("ObjectStoreError: extends Error",          oserr instanceof Error);
  check("ObjectStoreError: code",       oserr.code === "BUCKET_NOT_FOUND");
  check("ObjectStoreError: permanent",  oserr.permanent === true);
  check("ObjectStoreError: statusCode", oserr.statusCode === 404);
  check("ObjectStoreError: legacy flag", oserr.isObjectStoreError === true);

  var qerr = new fe.QueueError("JOB_NOT_FOUND", "no such job", true);
  check("QueueError: instanceof FrameworkError", qerr instanceof fe.FrameworkError);
  check("QueueError: legacy flag",               qerr.isQueueError === true);

  // Existing *SafeError classes now also pass instanceof FrameworkError
  try { b.jsonSafe.parse("{not-json}"); }
  catch (e) {
    check("JsonSafeError: extends FrameworkError",  e instanceof fe.FrameworkError);
    check("JsonSafeError: legacy flag preserved",   e.isJsonSafeError === true);
  }
  try { b.sqlSafe.validateIdentifier("123"); }
  catch (e) {
    check("SqlSafeError: extends FrameworkError",   e instanceof fe.FrameworkError);
  }
}

function testLazyRequire() {
  check("lazyRequire is a function", typeof b.lazyRequire === "function");

  // Loader is invoked exactly once on first call
  var loadCount = 0;
  var loader = function () {
    loadCount += 1;
    return { hello: "world", n: loadCount };
  };
  var lazy = b.lazyRequire(loader);

  check("lazyRequire: not invoked until called",  loadCount === 0);
  var v1 = lazy();
  check("lazyRequire: first call resolves",       v1.hello === "world" && loadCount === 1);
  var v2 = lazy();
  check("lazyRequire: second call returns cache", v2 === v1 && loadCount === 1);

  // reset() clears the cache so the next call re-runs the loader
  lazy.reset();
  var v3 = lazy();
  check("lazyRequire: reset re-runs loader",      loadCount === 2 && v3 !== v1);

  // Non-function loader is rejected
  var threw = false;
  try { b.lazyRequire("./db"); }
  catch (_e) { threw = true; }
  check("lazyRequire: rejects non-function loader", threw);

  // Loader returning falsy values is still cached after first call —
  // separate `loaded` flag distinguishes "not yet loaded" from "loaded
  // with a null/undefined/0/false value".
  var falsyCount = 0;
  var falsyLoader = b.lazyRequire(function () { falsyCount += 1; return 0; });
  falsyLoader(); falsyLoader(); falsyLoader();
  check("lazyRequire: falsy (0) return value cached", falsyCount === 1);

  var nullCount = 0;
  var nullLoader = b.lazyRequire(function () { nullCount += 1; return null; });
  nullLoader(); nullLoader();
  check("lazyRequire: null return value cached", nullCount === 1);
}

function testBufferSafeSecureZero() {
  var bs = b.bufferSafe;
  check("bufferSafe.secureZero is a function", typeof bs.secureZero === "function");

  var buf = Buffer.from("secret-passphrase", "utf8");
  bs.secureZero(buf);
  var allZero = true;
  for (var i = 0; i < buf.length; i++) if (buf[i] !== 0) { allZero = false; break; }
  check("secureZero: zeroes Buffer contents", allZero);

  // Uint8Array also handled
  var u8 = new Uint8Array([1, 2, 3, 4]);
  bs.secureZero(u8);
  check("secureZero: zeroes Uint8Array",
        u8[0] === 0 && u8[1] === 0 && u8[2] === 0 && u8[3] === 0);

  // Non-Buffer no-ops (doesn't throw)
  bs.secureZero("not-a-buffer");
  bs.secureZero(null);
  bs.secureZero(undefined);
  check("secureZero: non-Buffer is a no-op", true);
}

function testEnvReadVar() {
  var env = b.parsers.env;
  check("env.readVar is a function", typeof env.readVar === "function");

  // Save + clean a unique env namespace for this test
  var KEYS = ["BLAMEJS_TEST_VAR1", "BLAMEJS_TEST_VAR2", "BLAMEJS_TEST_VAR3", "BLAMEJS_TEST_VAR4"];
  var saved = {};
  for (var i = 0; i < KEYS.length; i++) { saved[KEYS[i]] = process.env[KEYS[i]]; delete process.env[KEYS[i]]; }

  try {
    // Missing + no default → undefined
    check("readVar: missing without default returns undefined", env.readVar("BLAMEJS_TEST_VAR1") === undefined);

    // Missing + default → default
    check("readVar: missing with default returns default",
          env.readVar("BLAMEJS_TEST_VAR1", { default: "fallback" }) === "fallback");

    // Missing + required → throws
    var threwReq = false;
    try { env.readVar("BLAMEJS_TEST_VAR1", { required: true }); }
    catch (e) { threwReq = e.code === "env/missing-required"; }
    check("readVar: missing + required throws", threwReq);

    // Plain string read
    process.env.BLAMEJS_TEST_VAR1 = "hello";
    check("readVar: string round-trip", env.readVar("BLAMEJS_TEST_VAR1") === "hello");

    // type:number coerces
    process.env.BLAMEJS_TEST_VAR2 = "42";
    check("readVar: number coercion", env.readVar("BLAMEJS_TEST_VAR2", { type: "number" }) === 42);

    // type:boolean strict spelling
    process.env.BLAMEJS_TEST_VAR2 = "true";
    check("readVar: boolean true",  env.readVar("BLAMEJS_TEST_VAR2", { type: "boolean" }) === true);
    process.env.BLAMEJS_TEST_VAR2 = "false";
    check("readVar: boolean false", env.readVar("BLAMEJS_TEST_VAR2", { type: "boolean" }) === false);
    process.env.BLAMEJS_TEST_VAR2 = "yes";
    var threwBool = false;
    try { env.readVar("BLAMEJS_TEST_VAR2", { type: "boolean" }); }
    catch (e) { threwBool = e.code === "env/bad-type"; }
    check("readVar: boolean rejects 'yes'", threwBool);

    // type:buffer + strip
    process.env.BLAMEJS_TEST_VAR3 = "secret-passphrase";
    var buf = env.readVar("BLAMEJS_TEST_VAR3", { type: "buffer", strip: true, maxBytes: 4096 });
    check("readVar: buffer round-trip",  Buffer.isBuffer(buf) && buf.toString("utf8") === "secret-passphrase");
    check("readVar: strip deletes env",  !("BLAMEJS_TEST_VAR3" in process.env));

    // maxBytes cap
    process.env.BLAMEJS_TEST_VAR4 = "x".repeat(5000);
    var threwSize = false;
    try { env.readVar("BLAMEJS_TEST_VAR4", { maxBytes: 1024 }); }
    catch (e) { threwSize = e.code === "env/too-large"; }
    check("readVar: maxBytes enforced", threwSize);

    // enum constraint
    process.env.BLAMEJS_TEST_VAR1 = "wrapped";
    check("readVar: enum allows valid",
          env.readVar("BLAMEJS_TEST_VAR1", { enum: ["wrapped", "plaintext"] }) === "wrapped");
    process.env.BLAMEJS_TEST_VAR1 = "garbage";
    var threwEnum = false;
    try { env.readVar("BLAMEJS_TEST_VAR1", { enum: ["wrapped", "plaintext"] }); }
    catch (e) { threwEnum = e.code === "env/bad-value"; }
    check("readVar: enum rejects invalid", threwEnum);

    // Empty string treated as missing (operator clearing the var)
    process.env.BLAMEJS_TEST_VAR1 = "";
    check("readVar: empty string is treated as missing",
          env.readVar("BLAMEJS_TEST_VAR1", { default: "fallback" }) === "fallback");
  } finally {
    // Restore original env
    for (var j = 0; j < KEYS.length; j++) {
      if (saved[KEYS[j]] === undefined) delete process.env[KEYS[j]];
      else process.env[KEYS[j]] = saved[KEYS[j]];
    }
  }
}

function testRedact() {
  check("redact module present",                 typeof b.redact === "object");
  check("redact.MARKER is '[REDACTED]'",         b.redact.MARKER === "[REDACTED]");

  // Field-name redaction
  var r1 = b.redact.redact({ user: "alice", password: "secret123", apiKey: "AKIAEXAMPLE" });
  check("password field redacted by name",       r1.password === "[REDACTED]");
  check("apiKey field redacted by name",         r1.apiKey === "[REDACTED]");
  check("non-sensitive field preserved",         r1.user === "alice");

  // Nested
  var r2 = b.redact.redact({ outer: { innerPassword: "x", normal: "y" } });
  check("nested sensitive redacted",             r2.outer.innerPassword === "[REDACTED]");
  check("nested normal preserved",               r2.outer.normal === "y");

  // Substring match
  var r3 = b.redact.redact({ userPassword: "pw", emailToken: "t" });
  check("substring 'password' triggers redaction", r3.userPassword === "[REDACTED]");
  check("substring 'token' triggers redaction",    r3.emailToken === "[REDACTED]");

  // Value-shape detectors
  var ccRedacted = b.redact.redact({ note: "card 4111-1111-1111-1111 here" });
  // Note: value detector only fires on STRING values that are EXACTLY a CC; embedded won't trigger
  // Test exact match:
  var ccExact = b.redact.redact({ field: "4111111111111111" });
  check("credit-card-shaped value redacted",     ccExact.field === "[REDACTED-CC]");

  var jwtExact = b.redact.redact({ field: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U" });
  check("JWT-shaped value redacted",             jwtExact.field === "[REDACTED-JWT]");

  var pemExact = b.redact.redact({ field: "-----BEGIN PRIVATE KEY-----\nABCD\n-----END PRIVATE KEY-----" });
  check("PEM-shaped value redacted",             pemExact.field === "[REDACTED-PEM]");

  var awsExact = b.redact.redact({ field: "AKIAIOSFODNN7EXAMPLE" });
  check("AWS access key redacted",               awsExact.field === "[REDACTED-AWS-KEY]");

  var sealExact = b.redact.redact({ field: "vault:abcdefxyz" });
  check("vault-sealed value redacted",           sealExact.field === "[REDACTED-SEALED]");

  var ssnExact = b.redact.redact({ field: "123-45-6789" });
  check("SSN-shaped value redacted",             ssnExact.field === "[REDACTED-SSN]");

  // Custom rule
  b.redact.registerFieldRule("internal_token");
  var custom = b.redact.redact({ internal_token: "x", other: "y" });
  check("custom field rule applies",             custom.internal_token === "[REDACTED]");

  // Array redaction
  var arr = b.redact.redact({ creds: [{ password: "a" }, { password: "b" }] });
  check("array elements redacted",               arr.creds[0].password === "[REDACTED]" && arr.creds[1].password === "[REDACTED]");

  // Mutation — original unchanged
  var orig = { password: "before" };
  b.redact.redact(orig);
  check("redact does NOT mutate input",          orig.password === "before");
  void ccRedacted;
}

// =====================================================================
// Module-surface — entrypoint sanity (crypto + router + namespace pres.)
// =====================================================================

/**
 * Crypto + router + module-surface checks (smoke entrypoint).
 *
 * The framework's "is the API even loaded?" sanity bar. Runs first so a
 * missing namespace or broken envelope shows up as the FIRST red light,
 * not as a downstream NPE. Was previously inlined at the top of smoke.js.
 */
function testCryptoAndModuleSurface() {
  // Public API surface
  check("crypto namespace present",     typeof b.crypto === "object");
  check("router namespace present",     typeof b.router === "object");
  check("constants namespace present",  typeof b.constants === "object");
  check("vault namespace present",      typeof b.vault === "object");
  check("vaultWrap namespace present",  typeof b.vaultWrap === "object");
  check("passphraseSource present",     typeof b.passphraseSource === "object");
  check("version is a string",          typeof b.version === "string");
  check("version matches package.json", b.version === require("../package.json").version);
  check("db namespace present",         typeof b.db === "object");
  check("db.from is a function",        typeof b.db.from === "function");
  check("db.transaction is a function", typeof b.db.transaction === "function");
  check("db.hashFor is a function",     typeof b.db.hashFor === "function");
  check("fieldCrypto namespace present", typeof b.fieldCrypto === "object");
  check("audit namespace present",      typeof b.audit === "object");
  check("auditChain namespace present", typeof b.auditChain === "object");
  check("consent namespace present",    typeof b.consent === "object");
  check("subject namespace present",    typeof b.subject === "object");
  check("db.getDataResidency present",  typeof b.db.getDataResidency === "function");
  check("session namespace present",    typeof b.session === "object");
  check("storage namespace present",    typeof b.storage === "object");
  check("session.create is a function", typeof b.session.create === "function");
  check("storage.saveFile is a function", typeof b.storage.saveFile === "function");
  check("urlSafe namespace present",    typeof b.urlSafe === "object");
  check("urlSafe.parse is a function",  typeof b.urlSafe.parse === "function");
  check("urlSafe.ALLOW_HTTP_TLS frozen", Object.isFrozen(b.urlSafe.ALLOW_HTTP_TLS));
  check("authHeader namespace present", typeof b.authHeader === "object");
  check("authHeader.bearer is a function",     typeof b.authHeader.bearer === "function");
  check("authHeader.basic is a function",      typeof b.authHeader.basic === "function");
  check("authHeader.fromConfig is a function", typeof b.authHeader.fromConfig === "function");
  check("asyncSafe.sleep is a function",       typeof b.asyncSafe.sleep === "function");
  check("asyncSafe.withTimeoutSignal is a function",
        typeof b.asyncSafe.withTimeoutSignal === "function");

  // Constants surface
  check("ENVELOPE_MAGIC = 0xE1",        b.constants.ENVELOPE_MAGIC === 0xE1);
  check("ACTIVE.KEM is hybrid",         b.constants.ACTIVE.KEM === b.constants.KEM_IDS.ML_KEM_1024_P384);
  check("ACTIVE.CIPHER is XChaCha20",   b.constants.ACTIVE.CIPHER === b.constants.CIPHER_IDS.XCHACHA20_POLY1305);
  check("ACTIVE.KDF is SHAKE256",       b.constants.ACTIVE.KDF === b.constants.KDF_IDS.SHAKE256);
  check("TIME.days(1) = 86400000",      b.constants.TIME.days(1) === 86400000);
  check("TIME.minutes(45) = 2700000",   b.constants.TIME.minutes(45) === 2700000);
  check("TIME.hours(2) = 7200000",      b.constants.TIME.hours(2) === 7200000);
  check("BYTES.mib(64) = 67108864",     b.constants.BYTES.mib(64) === 67108864);
  check("BYTES.kib(4) = 4096",          b.constants.BYTES.kib(4) === 4096);
  check("TLS prefers PQ hybrid first",  b.constants.TLS_GROUP_PREFERENCE[0] === "SecP384r1MLKEM1024");

  // vault-wrap format constants
  check("vault-wrap MAGIC = 0xE2",       b.vaultWrap.MAGIC === 0xE2);
  check("vault-wrap FORMAT_VERSION = 1", b.vaultWrap.FORMAT_VERSION === 0x01);
  check("vault-wrap NONCE_LENGTH = 24",  b.vaultWrap.NONCE_LENGTH === 24);
  check("vault-wrap default Argon2 params present",
        b.vaultWrap.DEFAULT_ARGON2 && b.vaultWrap.DEFAULT_ARGON2.memoryCost > 0);

  // passphrase-source env var names follow BLAMEJS_ prefix
  check("passphraseSource ENV_PASSPHRASE = BLAMEJS_VAULT_PASSPHRASE",
        b.passphraseSource.ENV_PASSPHRASE === "BLAMEJS_VAULT_PASSPHRASE");
  check("passphraseSource ENV_PASSPHRASE_FILE = BLAMEJS_VAULT_PASSPHRASE_FILE",
        b.passphraseSource.ENV_PASSPHRASE_FILE === "BLAMEJS_VAULT_PASSPHRASE_FILE");
  check("passphraseSource ENV_PASSPHRASE_SRC = BLAMEJS_VAULT_PASSPHRASE_SOURCE",
        b.passphraseSource.ENV_PASSPHRASE_SRC === "BLAMEJS_VAULT_PASSPHRASE_SOURCE");

  // Envelope encrypt/decrypt round-trip
  var keys = b.crypto.generateEncryptionKeyPair();
  check("encryption keypair has all four members",
        typeof keys.publicKey === "string" && typeof keys.privateKey === "string" &&
        typeof keys.ecPublicKey === "string" && typeof keys.ecPrivateKey === "string");

  var plaintext = "hello blamejs " + b.version + " 🔐";
  var envelope = b.crypto.encrypt(plaintext, keys);
  check("encrypt() returns base64 string",     typeof envelope === "string");

  var decrypted = b.crypto.decrypt(envelope, keys);
  check("decrypt() round-trip preserves UTF-8", decrypted === plaintext);

  // Envelope header bytes match active algorithm IDs
  var envBytes = Buffer.from(envelope, "base64");
  check("envelope byte 0 = magic",         envBytes[0] === b.constants.ENVELOPE_MAGIC);
  check("envelope byte 1 = active KEM",    envBytes[1] === b.constants.ACTIVE.KEM);
  check("envelope byte 2 = active cipher", envBytes[2] === b.constants.ACTIVE.CIPHER);
  check("envelope byte 3 = active KDF",    envBytes[3] === b.constants.ACTIVE.KDF);

  // Tampered envelope fails to decrypt
  var tampered = Buffer.from(envelope, "base64");
  tampered[tampered.length - 1] ^= 0x01;
  var tamperedRejected = false;
  try { b.crypto.decrypt(tampered.toString("base64"), keys); }
  catch (_) { tamperedRejected = true; }
  check("tampered envelope is rejected", tamperedRejected);

  // Wrong-key decrypt fails
  var otherKeys = b.crypto.generateEncryptionKeyPair();
  var wrongKeyRejected = false;
  try { b.crypto.decrypt(envelope, otherKeys); }
  catch (_) { wrongKeyRejected = true; }
  check("wrong-key decrypt is rejected", wrongKeyRejected);

  // timingSafeEqual
  check("timingSafeEqual matches identical",       b.crypto.timingSafeEqual("foo", "foo"));
  check("timingSafeEqual rejects different",      !b.crypto.timingSafeEqual("foo", "bar"));
  check("timingSafeEqual rejects length-mismatch", !b.crypto.timingSafeEqual("foo", "foobar"));

  // Token / random bytes
  check("generateToken default = 64 hex chars (32 bytes)", b.crypto.generateToken().length === 64);
  check("generateBytes returns 16 bytes",                  b.crypto.generateBytes(16).length === 16);

  // SHA3-512 hash determinism
  var h1 = b.crypto.sha3Hash("blamejs");
  var h2 = b.crypto.sha3Hash("blamejs");
  check("sha3Hash is deterministic",            h1 === h2);
  check("sha3Hash is 128 hex chars (512 bits)", h1.length === 128);

  // Symmetric buffer encrypt/decrypt round-trip
  var symKey = b.crypto.generateBytes(32);
  var bufPlain = Buffer.from("symmetric round-trip", "utf8");
  var bufPacked = b.crypto.encryptPacked(bufPlain, symKey);
  check("encryptPacked produces non-empty buffer",    bufPacked.length > 0);
  check("encryptPacked starts with format byte 0x02", bufPacked[0] === b.constants.FORMAT.XCHACHA20_POLY1305);
  var bufRoundTripped = b.crypto.decryptPacked(bufPacked, symKey);
  check("decryptPacked round-trip preserves bytes",   bufRoundTripped.equals(bufPlain));

  // Signing keypair + sign/verify round-trip
  var signKeys = b.crypto.generateSigningKeyPair();
  check("signing keypair has public + private",
        typeof signKeys.publicKey === "string" && typeof signKeys.privateKey === "string");
  var msg = Buffer.from("sign-me-" + b.version);
  var sig = b.crypto.sign(msg, signKeys.privateKey);
  check("sign() returns Buffer of non-zero length", Buffer.isBuffer(sig) && sig.length > 0);
  check("verify() accepts valid signature",         b.crypto.verify(msg, sig, signKeys.publicKey));
  check("verify() rejects tampered message",        !b.crypto.verify(Buffer.from("tamper"), sig, signKeys.publicKey));

  // Router constructs and registers
  var r = new b.router.Router();
  r.get("/test", function (_req, _res) {});
  r.post("/api/items", function (_req, _res) {});
  r.use(function (_req, _res, next) { next(); });
  check("router registers GET route",  r.routes.some(function (rt) { return rt.method === "GET"  && rt.pattern === "/test"; }));
  check("router registers POST route", r.routes.some(function (rt) { return rt.method === "POST" && rt.pattern === "/api/items"; }));
  check("router stores middleware",    r.middleware.length === 1);
  check("serveStatic is a function",   typeof b.router.serveStatic === "function");
}

// ---- run() ----

async function run() {
  // entrypoint module-surface sanity
  testCryptoAndModuleSurface();
  // async-safe primitives
  await testAsyncSafeWithTimeoutResolves();
  await testAsyncSafeWithTimeoutRejects();
  await testAsyncSafeWithTimeoutAbort();
  await testAsyncSafeWithTimeoutPropagatesError();
  await testAsyncSafeSafeAwait();
  await testAsyncSafeMutexSerializes();
  await testAsyncSafeMutexReleaseOnThrow();
  await testAsyncSafeMutexAbortableAcquire();
  await testAsyncSafeSemaphoreBoundedConcurrency();
  await testAsyncSafeSemaphoreAbortableAcquire();
  await testAsyncSafeOnceSingleFlight();
  await testAsyncSafeOnceCachesFailure();
  await testAsyncSafeOnceReset();
  await testAsyncSafeCircuitBreakerStateTransitions();
  // sleep + withTimeoutSignal — primitives lifted out of ad-hoc patterns
  await testAsyncSafeSleepBasic();
  await testAsyncSafeSleepZeroResolvesImmediately();
  await testAsyncSafeSleepBadArg();
  await testAsyncSafeSleepAbort();
  await testAsyncSafeSleepUnrefOptIn();
  await testAsyncSafeSleepDefaultRefd();
  testAsyncSafeWithTimeoutSignalCases();
  await testAsyncSafeWithTimeoutSignalTimeoutFires();
  // auth-header — primitive replacing 3x duplicated _authHeaders()
  testAuthHeaderBearer();
  testAuthHeaderBasic();
  testAuthHeaderFromConfig();
  // handlers primitive
  await testHandlerEmitAndDrain();
  await testHandlerEmitDuringFlushNextCycle();
  await testHandlerRetryOnFlushFailure();
  await testHandlerCircuitBreakerOpensOnPersistentFailure();
  await testHandlerBoundedShutdown();
  await testHandlerStats();
  await testHandlerBackpressureDrop();
  // sql-safe primitive
  testSqlSafeIdentifierValidation();
  testSqlSafeQuoteIdentifier();
  testSqlSafeAssertOneOf();
  // chain-writer primitive (cross-layer; documented in test header)
  await testChainWriterRejectsBadTable();
  await testChainWriterRaceSafetyConcurrentAppends();
  // buffer-safe primitive (used by parsers, atomic-file, object-store)
  testBufferSafeNormalizeText();
  testBufferSafeToBuffer();
  testBufferSafeBoundedChunkCollector();
  testBufferSafeSecureZero();
  // logger primitive (per-module log channel)
  testLogger();
  // static-scan integrity check — guards against stale all-caps constants
  // silently evaluating to undefined in setInterval / setTimeout / etc.
  testConstantsReferenceIntegrity();
  // framework-error base + cross-module operational classes
  testFrameworkError();
  // url-safe primitive (validates scheme + shape at outbound boundary —
  // declared as a prerequisite for httpClient since httpClient routes
  // every URL through urlSafe.parse)
  testUrlSafeDefaultIsHttpsOnly();
  testUrlSafeCustomAllowlist();
  testUrlSafeMalformed();
  testUrlSafeUrlInstancePassThrough();
  testUrlSafeErrorClassInjection();
  testUrlSafeAllowAny();
  // http-client primitive (used by 5 protocol adapters)
  await testHttpClientBasic();
  await testHttpClientErrorStatus();
  await testHttpClientWallClockTimeout();
  await testHttpClientAbortSignal();
  await testHttpClientStreamResponse();
  await testHttpClientObserver();
  await testHttpClientH2Basic();
  await testHttpClientH2AbortSignal();
  await testHttpClientH2ErrorStatus();
  await testHttpClientH2Multiplex();
  await testHttpClientH2Stream();
  // websocket primitive (RFC 6455 + RFC 8441) — fixture-needing
  // tests (h2c suite + router suite) live in module.exports.groups[]
  // so each group's setup runs once and per-test timing is reported.
  testWebSocketHandshake();
  testWebSocketFrames();
  await testWebSocketConnection();
  testRouterWsValidation();
  // lazy-require primitive (used by 12 modules to break circular loads)
  testLazyRequire();
  // json-safe primitive
  testJsonModuleSurface();
  testJsonParse();
  testJsonStringify();
  testJsonCanonical();
  testJsonValidate();
  testJsonValidateCollect();
  testJsonFormats();
  // atomic-file primitive (depends on crypto + json-safe)
  await testAtomicFile();
  await testAtomicFileLock();
  await testAtomicFileListDir();
  // parsers/* primitives (independent of framework state)
  testXmlParse();
  testXmlSecurityRejections();
  testCsvParse();
  testCsvFormulaInjection();
  testTomlBasicTypes();
  testTomlTablesAndArrays();
  testTomlInlineTablesAndDottedKeys();
  testTomlSecurityRejections();
  testYamlBasic();
  testYamlNorwayProblem();
  testYamlBlockScalars();
  testYamlQuotedStrings();
  testYamlSecurityRejections();
  testEnvParseBasic();
  testEnvParseSecurityRejections();
  testEnvReadVar();
  // redact primitive
  testRedact();
}

module.exports = {
  testCryptoAndModuleSurface:                testCryptoAndModuleSurface,
  name: "Layer 0 — primitives (module-surface, async-safe, handlers, sql-safe, chain-writer, json-safe, atomic-file, parsers, redact)",
  run:  run,
  // Exported individually so smoke.js (or future selective-run tooling)
  // can reach them by name without going through run().
  testAsyncSafeWithTimeoutResolves:          testAsyncSafeWithTimeoutResolves,
  testAsyncSafeWithTimeoutRejects:           testAsyncSafeWithTimeoutRejects,
  testAsyncSafeWithTimeoutAbort:             testAsyncSafeWithTimeoutAbort,
  testAsyncSafeWithTimeoutPropagatesError:   testAsyncSafeWithTimeoutPropagatesError,
  testAsyncSafeSafeAwait:                    testAsyncSafeSafeAwait,
  testAsyncSafeMutexSerializes:              testAsyncSafeMutexSerializes,
  testAsyncSafeMutexReleaseOnThrow:          testAsyncSafeMutexReleaseOnThrow,
  testAsyncSafeMutexAbortableAcquire:        testAsyncSafeMutexAbortableAcquire,
  testAsyncSafeSemaphoreBoundedConcurrency:  testAsyncSafeSemaphoreBoundedConcurrency,
  testAsyncSafeSemaphoreAbortableAcquire:    testAsyncSafeSemaphoreAbortableAcquire,
  testAsyncSafeOnceSingleFlight:             testAsyncSafeOnceSingleFlight,
  testAsyncSafeOnceCachesFailure:            testAsyncSafeOnceCachesFailure,
  testAsyncSafeOnceReset:                    testAsyncSafeOnceReset,
  testAsyncSafeCircuitBreakerStateTransitions: testAsyncSafeCircuitBreakerStateTransitions,
  testAsyncSafeSleepBasic:                   testAsyncSafeSleepBasic,
  testAsyncSafeSleepZeroResolvesImmediately: testAsyncSafeSleepZeroResolvesImmediately,
  testAsyncSafeSleepBadArg:                  testAsyncSafeSleepBadArg,
  testAsyncSafeSleepAbort:                   testAsyncSafeSleepAbort,
  testAsyncSafeSleepUnrefOptIn:              testAsyncSafeSleepUnrefOptIn,
  testAsyncSafeSleepDefaultRefd:             testAsyncSafeSleepDefaultRefd,
  testAsyncSafeWithTimeoutSignalCases:       testAsyncSafeWithTimeoutSignalCases,
  testAsyncSafeWithTimeoutSignalTimeoutFires: testAsyncSafeWithTimeoutSignalTimeoutFires,
  testAuthHeaderBearer:                      testAuthHeaderBearer,
  testAuthHeaderBasic:                       testAuthHeaderBasic,
  testAuthHeaderFromConfig:                  testAuthHeaderFromConfig,
  testHandlerEmitAndDrain:                   testHandlerEmitAndDrain,
  testHandlerEmitDuringFlushNextCycle:       testHandlerEmitDuringFlushNextCycle,
  testHandlerRetryOnFlushFailure:            testHandlerRetryOnFlushFailure,
  testHandlerCircuitBreakerOpensOnPersistentFailure: testHandlerCircuitBreakerOpensOnPersistentFailure,
  testHandlerBoundedShutdown:                testHandlerBoundedShutdown,
  testHandlerStats:                          testHandlerStats,
  testHandlerBackpressureDrop:               testHandlerBackpressureDrop,
  testSqlSafeIdentifierValidation:           testSqlSafeIdentifierValidation,
  testSqlSafeQuoteIdentifier:                testSqlSafeQuoteIdentifier,
  testSqlSafeAssertOneOf:                    testSqlSafeAssertOneOf,
  testChainWriterRejectsBadTable:            testChainWriterRejectsBadTable,
  testChainWriterRaceSafetyConcurrentAppends: testChainWriterRaceSafetyConcurrentAppends,
  testBufferSafeNormalizeText:               testBufferSafeNormalizeText,
  testBufferSafeToBuffer:                    testBufferSafeToBuffer,
  testBufferSafeBoundedChunkCollector:       testBufferSafeBoundedChunkCollector,
  testBufferSafeSecureZero:                  testBufferSafeSecureZero,
  testLogger:                                testLogger,
  testConstantsReferenceIntegrity:           testConstantsReferenceIntegrity,
  testUrlSafeDefaultIsHttpsOnly:             testUrlSafeDefaultIsHttpsOnly,
  testUrlSafeCustomAllowlist:                testUrlSafeCustomAllowlist,
  testUrlSafeMalformed:                      testUrlSafeMalformed,
  testUrlSafeUrlInstancePassThrough:         testUrlSafeUrlInstancePassThrough,
  testUrlSafeErrorClassInjection:            testUrlSafeErrorClassInjection,
  testUrlSafeAllowAny:                       testUrlSafeAllowAny,
  testHttpClientBasic:                       testHttpClientBasic,
  testHttpClientErrorStatus:                 testHttpClientErrorStatus,
  testHttpClientWallClockTimeout:            testHttpClientWallClockTimeout,
  testHttpClientAbortSignal:                 testHttpClientAbortSignal,
  testHttpClientStreamResponse:              testHttpClientStreamResponse,
  testHttpClientObserver:                    testHttpClientObserver,
  testHttpClientH2Basic:                     testHttpClientH2Basic,
  testHttpClientH2AbortSignal:               testHttpClientH2AbortSignal,
  testHttpClientH2ErrorStatus:               testHttpClientH2ErrorStatus,
  testHttpClientH2Multiplex:                 testHttpClientH2Multiplex,
  testHttpClientH2Stream:                    testHttpClientH2Stream,
  testWebSocketHandshake:                    testWebSocketHandshake,
  testWebSocketFrames:                       testWebSocketFrames,
  testWebSocketConnection:                   testWebSocketConnection,
  testRouterWsValidation:                    testRouterWsValidation,
  testFrameworkError:                        testFrameworkError,
  testLazyRequire:                           testLazyRequire,
  testJsonModuleSurface:                     testJsonModuleSurface,
  testJsonParse:                             testJsonParse,
  testJsonStringify:                         testJsonStringify,
  testJsonCanonical:                         testJsonCanonical,
  testJsonValidate:                          testJsonValidate,
  testJsonValidateCollect:                   testJsonValidateCollect,
  testJsonFormats:                           testJsonFormats,
  testAtomicFile:                            testAtomicFile,
  testAtomicFileLock:                        testAtomicFileLock,
  testAtomicFileListDir:                     testAtomicFileListDir,
  testXmlParse:                              testXmlParse,
  testXmlSecurityRejections:                 testXmlSecurityRejections,
  testCsvParse:                              testCsvParse,
  testCsvFormulaInjection:                   testCsvFormulaInjection,
  testTomlBasicTypes:                        testTomlBasicTypes,
  testTomlTablesAndArrays:                   testTomlTablesAndArrays,
  testTomlInlineTablesAndDottedKeys:         testTomlInlineTablesAndDottedKeys,
  testTomlSecurityRejections:                testTomlSecurityRejections,
  testYamlBasic:                             testYamlBasic,
  testYamlNorwayProblem:                     testYamlNorwayProblem,
  testYamlBlockScalars:                      testYamlBlockScalars,
  testYamlQuotedStrings:                     testYamlQuotedStrings,
  testYamlSecurityRejections:                testYamlSecurityRejections,
  testEnvParseBasic:                         testEnvParseBasic,
  testEnvParseSecurityRejections:            testEnvParseSecurityRejections,
  testEnvReadVar:                            testEnvReadVar,
  testRedact:                                testRedact,

  // ---- Fixture-aware groups ----
  //
  // Each group has setup (runs once) + tests (run sequentially against
  // the shared context) + teardown. Smoke runner reports per-test
  // timing for drift detection. Tests stay individually named so
  // failure attribution is "Layer 0 / <group> / <test>".
  groups: [
    {
      name: "websocket-h2c",
      setup: async function () {
        var http2 = require("http2");
        var ws = b.websocket;
        var server = http2.createServer({ settings: { enableConnectProtocol: true } });
        server.on("stream", function (stream, headers) {
          if (headers[":method"] !== "CONNECT" || headers[":protocol"] !== "websocket") {
            try { stream.respond({ ":status": 404 }); stream.end(); } catch (_e) {}
            return;
          }
          var conn = ws.handleExtendedConnect(stream, headers, { closeGraceMs: 50 });
          if (!conn) return;
          if (headers[":path"] === "/echo") {
            conn.on("message", function (data, isBinary) {
              conn.send(isBinary ? data : "h2-echo:" + data);
            });
          }
          // /strict path: no message handler — masked-frame rejection
          // path closes the connection on its own.
        });
        var port = await listenOnRandomPort(server);
        // Open one h2 client up front; reuse across the group's tests
        // so each test pays only its own request RTT, not the
        // connect+SETTINGS handshake overhead.
        var client = http2.connect("http://127.0.0.1:" + port);
        await new Promise(function (resolve, reject) {
          client.once("connect", resolve);
          client.once("error", reject);
        });
        await new Promise(function (resolve) {
          if (client.remoteSettings && client.remoteSettings.enableConnectProtocol) return resolve();
          client.once("remoteSettings", resolve);
        });
        return { server: server, client: client, port: port };
      },
      teardown: async function (ctx) {
        if (!ctx) return;
        try { ctx.client.destroy(); } catch (_e) {}
        try { ctx.server.closeAllConnections(); } catch (_e) {}
        await new Promise(function (resolve) {
          try { ctx.server.close(function () { resolve(); }); }
          catch (_e) { resolve(); }
        });
      },
      tests: [
        {
          name: "advertises enableConnectProtocol",
          run: async function (ctx) {
            check("h2 WebSocket: server advertises enableConnectProtocol",
                  ctx.client.remoteSettings.enableConnectProtocol === true);
          },
        },
        {
          name: "echo round-trip",
          run: async function (ctx) {
            var ws = b.websocket;
            var stream = ctx.client.request({
              ":method":   "CONNECT",
              ":protocol": "websocket",
              ":path":     "/echo",
              ":scheme":   "http",
              ":authority": "127.0.0.1:" + ctx.port,
            });
            var responseHeaders = await new Promise(function (resolve, reject) {
              stream.once("response", resolve);
              stream.once("error", reject);
            });
            check("h2 WebSocket: server responds 200 (not 101)",
                  responseHeaders[":status"] === 200);

            stream.write(ws.serializeFrame(ws.OPCODE_TEXT, Buffer.from("hello-h2", "utf8")));

            var parser = new ws.FrameParser({ maxFrameBytes: 64 * 1024 });
            var echoFrames = await new Promise(function (resolve, reject) {
              var collected = [];
              stream.on("data", function (chunk) {
                try {
                  var fs = parser.push(chunk);
                  for (var i = 0; i < fs.length; i++) collected.push(fs[i]);
                  if (collected.length > 0) resolve(collected);
                } catch (e) { reject(e); }
              });
              stream.on("error", reject);
            });
            check("h2 WebSocket: server echoed text frame",
                  echoFrames[0].payload.toString("utf8") === "h2-echo:hello-h2");
            check("h2 WebSocket: server frame unmasked (h2 rule)",
                  echoFrames[0].masked === false);

            // Clean close on this stream only — group fixture stays alive.
            var closePayload = Buffer.alloc(2);
            closePayload.writeUInt16BE(1000, 0);
            stream.write(ws.serializeFrame(ws.OPCODE_CLOSE, closePayload));
            await new Promise(function (resolve) {
              stream.once("close", resolve);
              setTimeout(resolve, 200);
            });
          },
        },
        {
          name: "rejects masked client frame",
          run: async function (ctx) {
            var ws = b.websocket;
            var stream = ctx.client.request({
              ":method":   "CONNECT",
              ":protocol": "websocket",
              ":path":     "/strict",
              ":scheme":   "http",
              ":authority": "127.0.0.1:" + ctx.port,
            });
            await new Promise(function (resolve, reject) {
              stream.once("response", resolve);
              stream.once("error", reject);
            });
            stream.write(ws.serializeFrame(ws.OPCODE_TEXT, Buffer.from("nope", "utf8"), { mask: true }));

            var parser = new ws.FrameParser({ maxFrameBytes: 1024 });
            var closeSeen = await new Promise(function (resolve) {
              var collected = [];
              stream.on("data", function (chunk) {
                try {
                  var fs = parser.push(chunk);
                  collected = collected.concat(fs);
                  var closeFrame = collected.find(function (f) { return f.opcode === ws.OPCODE_CLOSE; });
                  if (closeFrame) resolve(closeFrame);
                } catch (_e) { /* server send-and-destroy */ }
              });
              stream.once("close", function () { resolve(null); });
              setTimeout(function () { resolve(null); }, 500);
            });
            check("h2 WebSocket: masked client frame rejected with close",
                  closeSeen !== null && closeSeen.payload.readUInt16BE(0) === ws.CLOSE_PROTOCOL_ERROR);
          },
        },
      ],
    },
    {
      name: "websocket-router-h1",
      setup: async function () {
        var router = new b.router.Router();
        var receivedMessages = [];
        router.ws("/realtime", function (conn, _req) {
          conn.on("message", function (data, isBinary) {
            receivedMessages.push({ data: isBinary ? data : data.toString(), isBinary: isBinary });
            conn.send(isBinary ? data : "router-echo:" + data);
          });
        }, { origins: "*", closeGraceMs: 50 });
        router.ws("/h2only", function (_conn) { /* never reached on h1 */ },
          { origins: "*", transport: "h2-only" });
        var server = await new Promise(function (resolve) {
          var s = router.listen(0, function () { resolve(s); }, null, "127.0.0.1");
        });
        return {
          router: router,
          server: server,
          port: server.address().port,
          receivedMessages: receivedMessages,
        };
      },
      teardown: async function (ctx) {
        if (!ctx) return;
        // Operator API closes all active WS connections via the
        // proper close handshake (or force-destroys after timeout).
        // Same primitive operators use for graceful rolling deploy.
        try { await ctx.router.closeWebSockets({ timeoutMs: 200 }); } catch (_e) {}
        await new Promise(function (resolve) {
          try { ctx.server.close(function () { resolve(); }); }
          catch (_e) { resolve(); }
        });
      },
      tests: [
        {
          name: "auto path: 101 + echo round-trip",
          run: async function (ctx) {
            var net = require("net");
            var ws = b.websocket;
            var client = net.connect(ctx.port, "127.0.0.1");
            await new Promise(function (r) { client.once("connect", r); });
            var key = require("crypto").randomBytes(16).toString("base64");
            client.write(
              "GET /realtime HTTP/1.1\r\n" +
              "Host: 127.0.0.1:" + ctx.port + "\r\n" +
              "Upgrade: websocket\r\n" +
              "Connection: Upgrade\r\n" +
              "Sec-WebSocket-Key: " + key + "\r\n" +
              "Sec-WebSocket-Version: 13\r\n" +
              "\r\n"
            );
            var responseBuf = await _readUntil(client, "\r\n\r\n");
            check("router.ws h1: 101 Switching Protocols",
                  responseBuf.toString("utf8").indexOf("HTTP/1.1 101") === 0);
            client.write(ws.serializeFrame(ws.OPCODE_TEXT,
              Buffer.from("via-router", "utf8"), { mask: true }));
            var parser = new ws.FrameParser({ maxFrameBytes: 1024 });
            var echoFrames = [];
            while (echoFrames.length === 0) {
              var more = await _readSome(client);
              echoFrames = parser.push(more);
            }
            check("router.ws h1: handler echoed message",
                  echoFrames[0].payload.toString("utf8") === "router-echo:via-router");
            check("router.ws h1: handler received the message",
                  ctx.receivedMessages.length === 1 && ctx.receivedMessages[0].data === "via-router");
            client.destroy();
          },
        },
        {
          name: "h2-only path: 426 Upgrade Required",
          run: async function (ctx) {
            var net = require("net");
            var client = net.connect(ctx.port, "127.0.0.1");
            await new Promise(function (r) { client.once("connect", r); });
            var key = require("crypto").randomBytes(16).toString("base64");
            client.write(
              "GET /h2only HTTP/1.1\r\n" +
              "Host: 127.0.0.1:" + ctx.port + "\r\n" +
              "Upgrade: websocket\r\n" +
              "Connection: Upgrade\r\n" +
              "Sec-WebSocket-Key: " + key + "\r\n" +
              "Sec-WebSocket-Version: 13\r\n" +
              "\r\n"
            );
            var responseBuf = await _readUntil(client, "\r\n\r\n");
            var responseStr = responseBuf.toString("utf8");
            check("router.ws h2-only: returns 426",
                  responseStr.indexOf("HTTP/1.1 426") === 0);
            check("router.ws h2-only: advisory Upgrade: h2c header",
                  /Upgrade: h2c/i.test(responseStr));
            client.destroy();
          },
        },
      ],
    },
  ],
};
