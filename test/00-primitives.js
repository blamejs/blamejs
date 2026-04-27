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

// ---- auth.password (Argon2id) ----
//
// All tests below use deliberately weak Argon2 params (memoryCost=1024
// KiB / timeCost=1 / parallelism=1) so each hash/verify takes ~10ms
// instead of ~250-500ms with defaults. The defaults are exercised
// indirectly by the surface check (DEFAULT_PARAMS) and by the integration
// path (vault-wrap uses comparable params). The point of these tests is
// behavior + boundaries, not benchmarking.

var FAST_ARGON_PARAMS = { memoryCost: 1024, timeCost: 1, parallelism: 1 };

async function testAuthPasswordHashShape() {
  var p = b.auth.password;
  var h = await p.hash("hunter2", FAST_ARGON_PARAMS);
  check("auth.password.hash returns string",        typeof h === "string");
  check("auth.password.hash starts with $argon2id$", h.indexOf("$argon2id$") === 0);
  check("auth.password.hash includes m/t/p params",
        /\$m=1024,t=1,p=1\$/.test(h));

  // Same plain → different hash (random salt)
  var h2 = await p.hash("hunter2", FAST_ARGON_PARAMS);
  check("auth.password.hash uses random salt (hashes differ)",  h !== h2);
}

async function testAuthPasswordVerifyRoundTrip() {
  var p = b.auth.password;
  var stored = await p.hash("correct horse battery staple", FAST_ARGON_PARAMS);
  check("verify accepts correct password",
        (await p.verify(stored, "correct horse battery staple")) === true);
  check("verify rejects wrong password",
        (await p.verify(stored, "wrong horse battery staple")) === false);
  check("verify rejects empty plain",       (await p.verify(stored, "")) === false);
  check("verify rejects null plain",        (await p.verify(stored, null)) === false);
}

async function testAuthPasswordVerifyTamperedHash() {
  var p = b.auth.password;
  var stored = await p.hash("hunter2", FAST_ARGON_PARAMS);
  // Flip one base64 char in the hash portion (after the last $)
  var lastDollar = stored.lastIndexOf("$");
  var head = stored.slice(0, lastDollar + 1);
  var tail = stored.slice(lastDollar + 1);
  var tampered = head + (tail[0] === "A" ? "B" : "A") + tail.slice(1);
  check("verify rejects tampered hash",     (await p.verify(tampered, "hunter2")) === false);
}

async function testAuthPasswordVerifyMalformedHash() {
  var p = b.auth.password;
  check("verify rejects empty hash",        (await p.verify("", "hunter2")) === false);
  check("verify rejects null hash",         (await p.verify(null, "hunter2")) === false);
  check("verify rejects non-id variant",
        (await p.verify("$argon2i$v=19$m=1024,t=1,p=1$AAAA$BBBB", "x")) === false);
  check("verify rejects garbage hash",
        (await p.verify("not-a-hash", "x")) === false);
  check("verify rejects truncated PHC",
        (await p.verify("$argon2id$v=19", "x")) === false);
}

async function testAuthPasswordHashRejectsBadInput() {
  var p = b.auth.password;
  var threw = null;
  try { await p.hash("", FAST_ARGON_PARAMS); }
  catch (e) { threw = e; }
  check("hash rejects empty plain",         threw && threw.code === "auth-password/invalid-plain");
  check("hash error is AuthError",          threw && threw.isAuthError === true);
  check("hash error is permanent",          threw && threw.permanent === true);

  threw = null;
  try { await p.hash(123, FAST_ARGON_PARAMS); }
  catch (e) { threw = e; }
  check("hash rejects non-string plain",    threw && threw.code === "auth-password/invalid-plain");

  threw = null;
  // 5000-byte string > 4096 cap
  var huge = "x".repeat(5000);
  try { await p.hash(huge, FAST_ARGON_PARAMS); }
  catch (e) { threw = e; }
  check("hash rejects oversize plain",      threw && threw.code === "auth-password/plain-too-large");

  threw = null;
  try { await p.hash("ok", { memoryCost: 0 }); }
  catch (e) { threw = e; }
  check("hash rejects bad memoryCost param", threw && threw.code === "auth-password/bad-params");
}

async function testAuthPasswordNeedsRehash() {
  var p = b.auth.password;
  var stored = await p.hash("hunter2", FAST_ARGON_PARAMS);

  // Same params → no rehash needed
  check("needsRehash false for same params",
        p.needsRehash(stored, FAST_ARGON_PARAMS) === false);

  // Stronger params → rehash needed
  check("needsRehash true when memory bumped",
        p.needsRehash(stored, { memoryCost: 4096, timeCost: 1, parallelism: 1 }) === true);
  check("needsRehash true when time bumped",
        p.needsRehash(stored, { memoryCost: 1024, timeCost: 5, parallelism: 1 }) === true);

  // Malformed / non-id hashes always need rehash
  check("needsRehash true for empty hash",        p.needsRehash("") === true);
  check("needsRehash true for argon2i hash",      p.needsRehash("$argon2i$...") === true);
  check("needsRehash true for garbage hash",      p.needsRehash("not-a-hash") === true);
}

function testAuthPasswordSurface() {
  var p = b.auth.password;
  check("auth namespace present",                  typeof b.auth === "object");
  check("auth.password.hash is a function",        typeof p.hash === "function");
  check("auth.password.verify is a function",      typeof p.verify === "function");
  check("auth.password.needsRehash is a function", typeof p.needsRehash === "function");
  check("auth.password.DEFAULT_PARAMS frozen",     Object.isFrozen(p.DEFAULT_PARAMS));
  check("DEFAULT_PARAMS.memoryCost = 64 MiB-in-KiB", p.DEFAULT_PARAMS.memoryCost === 65536);
}

// ---- auth.totp (RFC 6238) ----
//
// RFC 6238 Appendix B publishes test vectors for HMAC-SHA1, HMAC-SHA256,
// and HMAC-SHA512. SHA-1 is NOT supported by this framework (see
// lib/totp.js docstring), so the test below covers the SHA-256 and
// SHA-512 vectors only — confirming the implementation matches the RFC
// for both supported algorithms.
//
// Per RFC, each algorithm uses a different key (the test K is
// "12345678…" repeated to fill the algorithm's HMAC block size):
//   SHA-256: K = ASCII("12345678901234567890123456789012") (32 bytes)
//   SHA-512: K = ASCII("1234567890…1234") (64 bytes)
// Below are the precomputed base32 encodings of those keys.

var RFC6238_KEY_B32_SHA256 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA";
var RFC6238_KEY_B32_SHA512 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA";

function _stepFromT(tSec, stepSec) {
  return Math.floor(tSec / (stepSec || 30));
}

function testAuthTotpRfc6238Vectors() {
  // Appendix B vectors at 8 digits — matches the RFC reference
  // implementation AND the framework's new 8-digit default. The
  // explicit `digits: 8` is redundant under the v0.1.57 default but
  // kept here so the test stays valid even if the default ever shifts.
  var t = b.auth.totp;
  var sha256Vectors = [
    { T:          59, code: "46119246" },
    { T:  1111111109, code: "68084774" },
    { T:  1111111111, code: "67062674" },
    { T:  1234567890, code: "91819424" },
    { T:  2000000000, code: "90698825" },
    { T: 20000000000, code: "77737706" },
  ];
  var sha512Vectors = [
    { T:          59, code: "90693936" },
    { T:  1111111109, code: "25091201" },
    { T:  1111111111, code: "99943326" },
    { T:  1234567890, code: "93441116" },
    { T:  2000000000, code: "38618901" },
    { T: 20000000000, code: "47863826" },
  ];
  for (var i = 0; i < sha256Vectors.length; i++) {
    var v = sha256Vectors[i];
    var got = t.compute(RFC6238_KEY_B32_SHA256, _stepFromT(v.T, 30),
                        { digits: 8, algorithm: "sha256" });
    check("RFC 6238 SHA-256 vector T=" + v.T + " → " + v.code,  got === v.code);
  }
  for (var j = 0; j < sha512Vectors.length; j++) {
    var w = sha512Vectors[j];
    var got2 = t.compute(RFC6238_KEY_B32_SHA512, _stepFromT(w.T, 30),
                         { digits: 8, algorithm: "sha512" });
    check("RFC 6238 SHA-512 vector T=" + w.T + " → " + w.code,  got2 === w.code);
  }
}

function testAuthTotpGenerateSecret() {
  var t = b.auth.totp;
  var s = t.generateSecret();
  check("generateSecret returns string",                      typeof s === "string");
  // 128 bytes → 1024 bits → ceil(1024/5) = 205 base32 characters
  check("generateSecret default = 205 base32 chars (128 bytes / SHA-512 block size)",
        s.length === 205);
  check("generateSecret is base32 (A-Z 2-7)",                 /^[A-Z2-7]+$/.test(s));

  // Two secrets are different (random source)
  var s2 = t.generateSecret();
  check("generateSecret produces unique secrets",             s !== s2);

  // Operators can opt down to RFC 4226 §4 floor (20 bytes) for
  // manual-entry-friendly authenticators
  var sMin = t.generateSecret({ bytes: 20 });
  check("generateSecret honors opts.bytes=20 (RFC 4226 floor)", sMin.length === 32);

  // bytes < MIN_SECRET_BYTES rejected
  var threw = null;
  try { t.generateSecret({ bytes: 10 }); }
  catch (e) { threw = e; }
  check("generateSecret rejects bytes < 20",                  threw && threw.code === "auth-totp/bad-secret-length");
}

function testAuthTotpGenerateAndVerifyRoundTrip() {
  var t = b.auth.totp;
  var secret = t.generateSecret();
  var code = t.generate(secret);
  check("generate returns 8-digit string by default",         /^[0-9]{8}$/.test(code));

  var step = t.verify(secret, code);
  check("verify returns the matched step number (truthy)",    typeof step === "number" && step > 0);
  check("verify rejects wrong code",                          t.verify(secret, "00000000") === false);
}

function testAuthTotpDriftWindow() {
  var t = b.auth.totp;
  var secret = t.generateSecret();
  var nowMs = Date.now();
  var stepNow = Math.floor(nowMs / 1000 / 30);

  // Compute the codes the authenticator would have shown 30s and 60s ago,
  // and the codes for now and 30s in the future.
  var codeMinus2 = t.compute(secret, stepNow - 2);
  var codeMinus1 = t.compute(secret, stepNow - 1);
  var codeNow    = t.compute(secret, stepNow);
  var codePlus1  = t.compute(secret, stepNow + 1);
  var codePlus2  = t.compute(secret, stepNow + 2);

  // Default driftSteps = 1: ±1 step accepted, ±2 rejected
  check("verify accepts current code",        t.verify(secret, codeNow,    { now: nowMs }) === stepNow);
  check("verify accepts -1 step (drift=1)",   t.verify(secret, codeMinus1, { now: nowMs }) === stepNow - 1);
  check("verify accepts +1 step (drift=1)",   t.verify(secret, codePlus1,  { now: nowMs }) === stepNow + 1);
  check("verify rejects -2 step (default drift=1)",
        t.verify(secret, codeMinus2, { now: nowMs }) === false);
  check("verify rejects +2 step (default drift=1)",
        t.verify(secret, codePlus2,  { now: nowMs }) === false);

  // driftSteps=2 widens the window
  check("verify accepts -2 step with driftSteps=2",
        t.verify(secret, codeMinus2, { now: nowMs, driftSteps: 2 }) === stepNow - 2);
}

function testAuthTotpReplayProtection() {
  var t = b.auth.totp;
  var secret = t.generateSecret();
  var nowMs = Date.now();
  var stepNow = Math.floor(nowMs / 1000 / 30);
  var codeNow = t.compute(secret, stepNow);

  // First verify succeeds
  var matched = t.verify(secret, codeNow, { now: nowMs });
  check("first verify accepts code",                          matched === stepNow);

  // Second verify with lastUsedStep=matched rejects (replay defense)
  check("verify rejects replay at the same step",
        t.verify(secret, codeNow, { now: nowMs, lastUsedStep: matched }) === false);

  // Drift-window codes that are ALSO at-or-below lastUsedStep get rejected
  var codeMinus1 = t.compute(secret, stepNow - 1);
  check("verify rejects prior-step code under replay guard",
        t.verify(secret, codeMinus1, { now: nowMs, lastUsedStep: matched }) === false);
}

function testAuthTotpVerifyMalformedInput() {
  var t = b.auth.totp;
  var secret = t.generateSecret();
  // verify is tolerant — never throws on bad input, just returns false
  check("verify(empty secret) → false",       t.verify("", "123456") === false);
  check("verify(null secret) → false",        t.verify(null, "123456") === false);
  check("verify(secret, null) → false",       t.verify(secret, null) === false);
  check("verify(secret, undefined) → false",  t.verify(secret, undefined) === false);
  // Non-numeric code that's the right length still doesn't match → false
  check("verify(secret, 'abcdef') → false",   t.verify(secret, "abcdef") === false);
}

function testAuthTotpUriShape() {
  var t = b.auth.totp;
  var u = t.uri("JBSWY3DPEHPK3PXP", "alice@example.com", { issuer: "BlameJS" });
  check("uri starts with otpauth://totp/",                   u.indexOf("otpauth://totp/") === 0);
  check("uri label has Issuer:Account",                      u.indexOf("BlameJS:alice%40example.com") !== -1);
  check("uri carries secret as query param",                 /[?&]secret=JBSWY3DPEHPK3PXP/.test(u));
  check("uri carries issuer as query param",                 /[?&]issuer=BlameJS/.test(u));
  check("uri carries algorithm=SHA512 (framework default)",  /[?&]algorithm=SHA512/.test(u));
  check("uri does NOT carry algorithm=SHA1",                 /[?&]algorithm=SHA1[^256512]/.test(u) === false);
  check("uri carries digits=8 (framework default)",          /[?&]digits=8/.test(u));
  check("uri carries period=30 (default stepSeconds)",       /[?&]period=30/.test(u));

  // Operators with SHA-256 authenticators opt in explicitly
  var u256 = t.uri("JBSWY3DPEHPK3PXP", "alice@example.com",
                   { issuer: "BlameJS", algorithm: "sha256" });
  check("uri honors explicit algorithm=sha256 opt-in",       /[?&]algorithm=SHA256/.test(u256));

  // Required-field errors
  var threw = null;
  try { t.uri("SECRET", "alice", {}); }
  catch (e) { threw = e; }
  check("uri without issuer throws AuthError",
        threw && threw.code === "auth-totp/missing-issuer");

  threw = null;
  try { t.uri("", "alice", { issuer: "X" }); }
  catch (e) { threw = e; }
  check("uri with empty secret throws",
        threw && threw.code === "auth-totp/missing-secret");
}

function testAuthTotpBackupCodes() {
  var t = b.auth.totp;
  var codes = t.generateBackupCodes();
  check("default backup codes count = 10",      codes.length === 10);
  check("default backup code length = 8 hex",   /^[0-9a-f]{8}$/.test(codes[0]));
  // Codes are unique within the batch (random source)
  var uniq = {};
  for (var i = 0; i < codes.length; i++) uniq[codes[i]] = true;
  check("default backup codes are unique",       Object.keys(uniq).length === 10);

  // Configurable count + length
  var custom = t.generateBackupCodes({ count: 3, bytesPerCode: 8 });
  check("custom count honored",                  custom.length === 3);
  check("custom bytesPerCode honored (8 → 16 hex chars)",
        /^[0-9a-f]{16}$/.test(custom[0]));
}

function testAuthTotpBadAlgorithmRejected() {
  var t = b.auth.totp;
  var threw = null;
  try { t.compute("ABCDEFGH", 0, { algorithm: "md5" }); }
  catch (e) { threw = e; }
  check("compute with unsupported alg throws",
        threw && threw.code === "auth-totp/bad-alg");

  // SHA-1 is explicitly rejected — framework posture deviates from
  // RFC 6238's default to enforce stronger HMAC. See lib/totp.js
  // docstring for rationale.
  var threwSha1 = null;
  try { t.compute("ABCDEFGH", 0, { algorithm: "sha1" }); }
  catch (e) { threwSha1 = e; }
  check("compute with sha1 is rejected (framework posture)",
        threwSha1 && threwSha1.code === "auth-totp/bad-alg");
}

function testAuthTotpSurface() {
  var t = b.auth.totp;
  check("auth.totp namespace present",                   typeof b.auth.totp === "object");
  check("auth.totp.generateSecret is a function",        typeof t.generateSecret === "function");
  check("auth.totp.generate is a function",              typeof t.generate === "function");
  check("auth.totp.compute is a function",               typeof t.compute === "function");
  check("auth.totp.verify is a function",                typeof t.verify === "function");
  check("auth.totp.uri is a function",                   typeof t.uri === "function");
  check("auth.totp.generateBackupCodes is a function",   typeof t.generateBackupCodes === "function");
  check("auth.totp.DEFAULT_STEP_SECONDS = 30",           t.DEFAULT_STEP_SECONDS === 30);
  check("auth.totp.DEFAULT_DIGITS = 8",                  t.DEFAULT_DIGITS === 8);
  check("auth.totp.DEFAULT_ALGORITHM = sha512",          t.DEFAULT_ALGORITHM === "sha512");
  check("auth.totp.DEFAULT_SECRET_BYTES = 128 (SHA-512 block size)",
        t.DEFAULT_SECRET_BYTES === 128);
  check("auth.totp.MIN_SECRET_BYTES = 20 (RFC 4226 §4 floor)",
        t.MIN_SECRET_BYTES === 20);
  check("auth.totp.SUPPORTED_ALGORITHMS excludes sha1",
        t.SUPPORTED_ALGORITHMS.indexOf("sha1") === -1);
  check("auth.totp.SUPPORTED_ALGORITHMS = [sha256, sha512]",
        t.SUPPORTED_ALGORITHMS.length === 2 &&
        t.SUPPORTED_ALGORITHMS.indexOf("sha256") !== -1 &&
        t.SUPPORTED_ALGORITHMS.indexOf("sha512") !== -1);
}

// ---- auth.passkey (WebAuthn) ----
//
// Registration and authentication are end-to-end ceremonies between
// the server and a real authenticator (Touch ID / YubiKey / 1Password
// /etc.) — no built-in mock authenticator ships with the framework.
// These tests cover what we CAN cover without one:
//
//   - module surface (exports + auth namespace wiring)
//   - input validation (each required field surfaces as AuthError
//     with a code that matches the framework's other auth.* primitives)
//   - generated registration / authentication options have RFC-shaped
//     fields the browser API needs (challenge, rp, user, pubKeyCredParams,
//     timeout)
//   - hints default ["client-device", "hybrid"] so platform AND
//     cross-device authenticators surface
//
// The verify* paths rely on real signed assertions; round-tripping
// without an authenticator would mean stubbing the simplewebauthn
// internals, which would test our stub more than our wrapper.
// Operators get full ceremony coverage at the integration layer.

async function testAuthPasskeySurface() {
  var p = b.auth.passkey;
  check("auth.passkey namespace present",                typeof b.auth.passkey === "object");
  check("auth.passkey.startRegistration is a function",  typeof p.startRegistration === "function");
  check("auth.passkey.verifyRegistration is a function", typeof p.verifyRegistration === "function");
  check("auth.passkey.startAuthentication is a function", typeof p.startAuthentication === "function");
  check("auth.passkey.verifyAuthentication is a function", typeof p.verifyAuthentication === "function");

  // Vendor bundle loads + exports the four core entry points
  var v = require("../lib/vendor/simplewebauthn-server.cjs");
  check("vendor exports generateRegistrationOptions",    typeof v.generateRegistrationOptions === "function");
  check("vendor exports verifyRegistrationResponse",     typeof v.verifyRegistrationResponse === "function");
  check("vendor exports generateAuthenticationOptions",  typeof v.generateAuthenticationOptions === "function");
  check("vendor exports verifyAuthenticationResponse",   typeof v.verifyAuthenticationResponse === "function");
}

async function testAuthPasskeyStartRegistrationOptions() {
  var p = b.auth.passkey;
  var opts = await p.startRegistration({
    rpName:           "BlameJS",
    rpId:             "example.com",
    userName:         "alice@example.com",
    userDisplayName:  "Alice",
  });
  check("registration options has challenge",            typeof opts.challenge === "string" && opts.challenge.length > 0);
  check("registration options has rp.name",              opts.rp && opts.rp.name === "BlameJS");
  check("registration options has rp.id",                opts.rp && opts.rp.id === "example.com");
  check("registration options has user.name",            opts.user && opts.user.name === "alice@example.com");
  check("registration options has user.displayName",     opts.user && opts.user.displayName === "Alice");
  check("registration options has user.id (random)",     typeof opts.user.id === "string" && opts.user.id.length > 0);
  check("registration options has pubKeyCredParams",     Array.isArray(opts.pubKeyCredParams) && opts.pubKeyCredParams.length > 0);
  check("registration options has timeout",              typeof opts.timeout === "number" && opts.timeout > 0);
  check("registration options attestation = 'none'",     opts.attestation === "none");
  check("registration options residentKey = 'preferred'",
        opts.authenticatorSelection && opts.authenticatorSelection.residentKey === "preferred");
  check("registration options userVerification = 'preferred'",
        opts.authenticatorSelection.userVerification === "preferred");
  check("registration options hints = client-device + hybrid",
        Array.isArray(opts.hints) &&
        opts.hints.indexOf("client-device") !== -1 &&
        opts.hints.indexOf("hybrid") !== -1);

  // Two consecutive calls produce different challenges (random)
  var opts2 = await p.startRegistration({
    rpName: "BlameJS", rpId: "example.com", userName: "alice@example.com",
  });
  check("registration challenge is non-deterministic",   opts.challenge !== opts2.challenge);
}

async function testAuthPasskeyStartAuthenticationOptions() {
  var p = b.auth.passkey;
  var opts = await p.startAuthentication({
    rpId: "example.com",
  });
  check("auth options has challenge",                    typeof opts.challenge === "string" && opts.challenge.length > 0);
  check("auth options has rpId",                         opts.rpId === "example.com");
  check("auth options has timeout",                      typeof opts.timeout === "number");
  check("auth options userVerification = 'preferred'",   opts.userVerification === "preferred");
  check("auth options hints = client-device + hybrid",
        Array.isArray(opts.hints) &&
        opts.hints.indexOf("client-device") !== -1 &&
        opts.hints.indexOf("hybrid") !== -1);
}

async function testAuthPasskeyValidationErrors() {
  var p = b.auth.passkey;

  // startRegistration — missing fields
  var threw = null;
  try { await p.startRegistration({}); }
  catch (e) { threw = e; }
  check("startRegistration({}) throws missing-rpName",
        threw && threw.code === "auth-passkey/missing-rpName");

  threw = null;
  try { await p.startRegistration({ rpName: "X" }); }
  catch (e) { threw = e; }
  check("startRegistration without rpId throws missing-rpId",
        threw && threw.code === "auth-passkey/missing-rpId");

  threw = null;
  try { await p.startRegistration({ rpName: "X", rpId: "x.test" }); }
  catch (e) { threw = e; }
  check("startRegistration without userName throws missing-userName",
        threw && threw.code === "auth-passkey/missing-userName");

  // startAuthentication — missing rpId
  threw = null;
  try { await p.startAuthentication({}); }
  catch (e) { threw = e; }
  check("startAuthentication({}) throws missing-rpId",
        threw && threw.code === "auth-passkey/missing-rpId");

  // verifyRegistration — missing fields
  threw = null;
  try { await p.verifyRegistration({}); }
  catch (e) { threw = e; }
  check("verifyRegistration({}) throws missing-response",
        threw && threw.code === "auth-passkey/missing-response");

  threw = null;
  try { await p.verifyRegistration({ response: {} }); }
  catch (e) { threw = e; }
  check("verifyRegistration without expectedChallenge throws",
        threw && threw.code === "auth-passkey/missing-expectedChallenge");

  // verifyAuthentication — missing credential
  threw = null;
  try {
    await p.verifyAuthentication({
      response: {},
      expectedChallenge: "c",
      expectedOrigin:    "https://x.test",
      expectedRPID:      "x.test",
    });
  } catch (e) { threw = e; }
  check("verifyAuthentication without credential throws",
        threw && threw.code === "auth-passkey/missing-credential");

  // All errors are AuthError with permanent=true
  check("auth-passkey errors are AuthError",             threw && threw.isAuthError === true);
  check("auth-passkey errors are permanent",             threw && threw.permanent === true);
}

async function testAuthPasskeyExcludeCredentials() {
  // Registration options can carry an excludeCredentials list so the
  // browser refuses to register a key that's already enrolled.
  var p = b.auth.passkey;
  var opts = await p.startRegistration({
    rpName: "BlameJS",
    rpId:   "example.com",
    userName: "alice@example.com",
    excludeCredentials: [
      { id: "AAAA", transports: ["internal"] },
      { id: "BBBB" },
    ],
  });
  check("excludeCredentials propagates",
        Array.isArray(opts.excludeCredentials) &&
        opts.excludeCredentials.length === 2);
  check("excludeCredentials preserves transports",
        opts.excludeCredentials[0].transports &&
        opts.excludeCredentials[0].transports.indexOf("internal") !== -1);
}

async function testAuthPasskeyCustomHints() {
  // Operators can override the default hints (e.g. force platform-only)
  var p = b.auth.passkey;
  var opts = await p.startRegistration({
    rpName: "BlameJS",
    rpId: "example.com",
    userName: "alice@example.com",
    hints: ["client-device"],
  });
  check("custom hints override default",
        opts.hints.length === 1 && opts.hints[0] === "client-device");
}

// ---- auth.jwt (PQC-signed JWT) ----
//
// Most tests below use ML-DSA-87 keys so each sign/verify is sub-millisecond
// — SLH-DSA-SHAKE-256f signs in ~76 ms, which would balloon test time
// across the 25+ assertions. One round-trip uses the SLH-DSA default
// to prove the default path works end-to-end; everything else exercises
// behavior with the smaller-signature alg.

function _jwtMlDsaKeypair() {
  return require("crypto").generateKeyPairSync("ml-dsa-87", {
    publicKeyEncoding:  { type: "spki",  format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
}

function _jwtSlhDsaKeypair() {
  return require("crypto").generateKeyPairSync("slh-dsa-shake-256f", {
    publicKeyEncoding:  { type: "spki",  format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
}

function testAuthJwtSurface() {
  var j = b.auth.jwt;
  check("auth.jwt namespace present",                typeof b.auth.jwt === "object");
  check("auth.jwt.sign is a function",               typeof j.sign === "function");
  check("auth.jwt.verify is a function",             typeof j.verify === "function");
  check("auth.jwt.decode is a function",             typeof j.decode === "function");
  check("auth.jwt.DEFAULT_ALGORITHM = SLH-DSA-SHAKE-256f",
        j.DEFAULT_ALGORITHM === "SLH-DSA-SHAKE-256f");
  check("auth.jwt.SUPPORTED_ALGORITHMS includes SLH-DSA-SHAKE-256f",
        j.SUPPORTED_ALGORITHMS.indexOf("SLH-DSA-SHAKE-256f") !== -1);
  check("auth.jwt.SUPPORTED_ALGORITHMS includes ML-DSA-87",
        j.SUPPORTED_ALGORITHMS.indexOf("ML-DSA-87") !== -1);
  check("auth.jwt.SUPPORTED_ALGORITHMS does NOT include classical algs",
        j.SUPPORTED_ALGORITHMS.indexOf("RS256") === -1 &&
        j.SUPPORTED_ALGORITHMS.indexOf("ES256") === -1 &&
        j.SUPPORTED_ALGORITHMS.indexOf("HS256") === -1);
}

async function testAuthJwtSignVerifyRoundTripDefault() {
  // Default algorithm = SLH-DSA-SHAKE-256f. Run one full round-trip
  // to prove the default end-to-end despite the per-sign cost.
  var j = b.auth.jwt;
  var k = _jwtSlhDsaKeypair();
  var token = await j.sign({ sub: "user-1", role: "admin" }, { privateKey: k.privateKey });
  check("default-alg sign returns 3-part dotted string",
        typeof token === "string" && token.split(".").length === 3);

  var payload = await j.verify(token, { publicKey: k.publicKey });
  check("default-alg verify returns payload",        payload && payload.sub === "user-1");
  check("default-alg verify preserves custom claims", payload.role === "admin");
  check("default-alg auto-adds iat",                 typeof payload.iat === "number");

  // Decode (no-verify) returns header + payload + signature
  var decoded = j.decode(token);
  check("decode returns header.alg",                 decoded.header.alg === "SLH-DSA-SHAKE-256f");
  check("decode returns header.typ",                 decoded.header.typ === "JWT");
  check("decode returns payload.sub",                decoded.payload.sub === "user-1");
  check("decode returns signature buffer",           Buffer.isBuffer(decoded.signature));
  // SLH-DSA-SHAKE-256f signature size is ~50 KB
  check("default-alg signature size matches FIPS 205 (~50 KB)",
        decoded.signature.length > 49000 && decoded.signature.length < 51000);
}

async function testAuthJwtMlDsaOptIn() {
  // ML-DSA-87 opt-in for throughput-sensitive paths.
  var j = b.auth.jwt;
  var k = _jwtMlDsaKeypair();
  var token = await j.sign({ sub: "u-2" },
                           { privateKey: k.privateKey, algorithm: "ML-DSA-87" });
  var decoded = j.decode(token);
  check("ML-DSA-87 token header carries alg",        decoded.header.alg === "ML-DSA-87");
  check("ML-DSA-87 signature size matches FIPS 204 (~5 KB)",
        decoded.signature.length > 4000 && decoded.signature.length < 6000);

  var payload = await j.verify(token, { publicKey: k.publicKey, algorithms: ["ML-DSA-87"] });
  check("ML-DSA-87 verify round-trip",               payload.sub === "u-2");
}

async function testAuthJwtAlgorithmAllowlist() {
  // verify() defaults to allowing ONLY DEFAULT_ALGORITHM. A token
  // signed with ML-DSA-87 must therefore be rejected unless the
  // allowlist explicitly opts in.
  var j = b.auth.jwt;
  var k = _jwtMlDsaKeypair();
  var token = await j.sign({ sub: "u" },
                           { privateKey: k.privateKey, algorithm: "ML-DSA-87" });

  var threw = null;
  try { await j.verify(token, { publicKey: k.publicKey }); }
  catch (e) { threw = e; }
  check("verify default allowlist rejects ML-DSA-87 token",
        threw && threw.code === "auth-jwt/algorithm-not-allowed");

  // Explicit opt-in works
  var ok = await j.verify(token, { publicKey: k.publicKey, algorithms: ["ML-DSA-87"] });
  check("verify with ML-DSA-87 in allowlist accepts the token",  ok && ok.sub === "u");

  // Typo in allowlist surfaces at verify time
  var threwTypo = null;
  try { await j.verify(token, { publicKey: k.publicKey, algorithms: ["MD5"] }); }
  catch (e) { threwTypo = e; }
  check("verify with typoed alg in allowlist throws unsupported-algorithm",
        threwTypo && threwTypo.code === "auth-jwt/unsupported-algorithm");
}

async function testAuthJwtExpiration() {
  var j = b.auth.jwt;
  var k = _jwtMlDsaKeypair();
  var nowMs = Date.now();

  // expiresInSec=10 — token is valid now, expired 11s later
  var token = await j.sign({ sub: "u" }, {
    privateKey: k.privateKey, algorithm: "ML-DSA-87",
    expiresInSec: 10, now: nowMs,
  });
  var decoded = j.decode(token);
  check("expiresInSec sets exp claim",
        typeof decoded.payload.exp === "number" &&
        decoded.payload.exp === Math.floor(nowMs / 1000) + 10);

  // Verify within window passes
  var ok = await j.verify(token, {
    publicKey: k.publicKey, algorithms: ["ML-DSA-87"], now: nowMs,
  });
  check("verify within exp window passes",          ok.sub === "u");

  // Verify after exp throws expired
  var threw = null;
  try {
    await j.verify(token, {
      publicKey: k.publicKey, algorithms: ["ML-DSA-87"], now: nowMs + 11000,
    });
  } catch (e) { threw = e; }
  check("verify past exp throws auth-jwt/expired",   threw && threw.code === "auth-jwt/expired");

  // clockToleranceSec gives leeway
  var ok2 = await j.verify(token, {
    publicKey: k.publicKey, algorithms: ["ML-DSA-87"], now: nowMs + 11000,
    clockToleranceSec: 5,
  });
  check("clockToleranceSec lets a barely-expired token through",  ok2.sub === "u");
}

async function testAuthJwtNotBefore() {
  var j = b.auth.jwt;
  var k = _jwtMlDsaKeypair();
  var nowMs = Date.now();

  // notBeforeSec=60 — token isn't valid until 60s from now
  var token = await j.sign({ sub: "u" }, {
    privateKey: k.privateKey, algorithm: "ML-DSA-87",
    notBeforeSec: 60, now: nowMs,
  });

  // Verify before nbf throws
  var threw = null;
  try {
    await j.verify(token, {
      publicKey: k.publicKey, algorithms: ["ML-DSA-87"], now: nowMs,
    });
  } catch (e) { threw = e; }
  check("verify before nbf throws auth-jwt/not-yet-valid",
        threw && threw.code === "auth-jwt/not-yet-valid");

  // Verify after nbf passes
  var ok = await j.verify(token, {
    publicKey: k.publicKey, algorithms: ["ML-DSA-87"], now: nowMs + 61000,
  });
  check("verify after nbf passes",                   ok.sub === "u");
}

async function testAuthJwtIssuerAudienceSubject() {
  var j = b.auth.jwt;
  var k = _jwtMlDsaKeypair();
  var token = await j.sign({}, {
    privateKey: k.privateKey, algorithm: "ML-DSA-87",
    issuer:   "https://blamejs.example.com",
    audience: ["api-a", "api-b"],
    subject:  "user-42",
  });
  var decoded = j.decode(token);
  check("issuer claim recorded",                     decoded.payload.iss === "https://blamejs.example.com");
  check("audience claim recorded as array",          Array.isArray(decoded.payload.aud) &&
                                                     decoded.payload.aud.length === 2);
  check("subject claim recorded",                    decoded.payload.sub === "user-42");

  var verifyOpts = { publicKey: k.publicKey, algorithms: ["ML-DSA-87"] };

  // Matching expectations pass
  var ok = await j.verify(token, Object.assign({}, verifyOpts, {
    issuer: "https://blamejs.example.com", audience: "api-a", subject: "user-42",
  }));
  check("matching iss/aud/sub passes",               ok.sub === "user-42");

  // aud accepts string-OR-array on both sides; any-of match
  var okMulti = await j.verify(token, Object.assign({}, verifyOpts, {
    audience: ["api-c", "api-b"],
  }));
  check("audience any-of match passes",              okMulti.sub === "user-42");

  // Issuer mismatch
  var threw = null;
  try { await j.verify(token, Object.assign({}, verifyOpts, { issuer: "evil.com" })); }
  catch (e) { threw = e; }
  check("issuer mismatch throws auth-jwt/iss-mismatch",
        threw && threw.code === "auth-jwt/iss-mismatch");

  // Audience mismatch
  threw = null;
  try { await j.verify(token, Object.assign({}, verifyOpts, { audience: "api-c" })); }
  catch (e) { threw = e; }
  check("audience mismatch throws auth-jwt/aud-mismatch",
        threw && threw.code === "auth-jwt/aud-mismatch");

  // Subject mismatch
  threw = null;
  try { await j.verify(token, Object.assign({}, verifyOpts, { subject: "user-99" })); }
  catch (e) { threw = e; }
  check("subject mismatch throws auth-jwt/sub-mismatch",
        threw && threw.code === "auth-jwt/sub-mismatch");
}

async function testAuthJwtSignatureTampering() {
  var j = b.auth.jwt;
  var k = _jwtMlDsaKeypair();
  var token = await j.sign({ sub: "u" }, { privateKey: k.privateKey, algorithm: "ML-DSA-87" });
  var parts = token.split(".");

  // Flip a character in the signature
  var sigChar = parts[2][0] === "A" ? "B" : "A";
  var tamperedSig = parts[0] + "." + parts[1] + "." + sigChar + parts[2].slice(1);
  var threwSig = null;
  try { await j.verify(tamperedSig, { publicKey: k.publicKey, algorithms: ["ML-DSA-87"] }); }
  catch (e) { threwSig = e; }
  check("tampered signature → auth-jwt/invalid-signature",
        threwSig && threwSig.code === "auth-jwt/invalid-signature");

  // Tamper the payload — re-encode a different sub claim, keep the
  // original signature. Verify should still fail because the signature
  // was over the original signing input.
  var alteredPayload = Buffer.from(JSON.stringify({ sub: "evil" })).toString("base64")
    .replace(/=+$/g, "").replace(/\+/g, "-").replace(/\//g, "_");
  var tamperedPayload = parts[0] + "." + alteredPayload + "." + parts[2];
  var threwPayload = null;
  try { await j.verify(tamperedPayload, { publicKey: k.publicKey, algorithms: ["ML-DSA-87"] }); }
  catch (e) { threwPayload = e; }
  check("tampered payload → auth-jwt/invalid-signature",
        threwPayload && threwPayload.code === "auth-jwt/invalid-signature");

  // Wrong public key → verify rejects (different ML-DSA-87 keypair)
  var k2 = _jwtMlDsaKeypair();
  var threwKey = null;
  try { await j.verify(token, { publicKey: k2.publicKey, algorithms: ["ML-DSA-87"] }); }
  catch (e) { threwKey = e; }
  check("wrong public key → auth-jwt/invalid-signature",
        threwKey && threwKey.code === "auth-jwt/invalid-signature");
}

async function testAuthJwtMalformedTokens() {
  var j = b.auth.jwt;
  var k = _jwtMlDsaKeypair();

  // decode + verify both reject malformed shapes
  var bad = ["", "no-dots", "one.dot", "a.b.c.d", "🌶."];
  for (var i = 0; i < bad.length; i++) {
    var threw = null;
    try { j.decode(bad[i]); }
    catch (e) { threw = e; }
    check("decode rejects '" + bad[i] + "' → malformed",
          threw && threw.code === "auth-jwt/malformed");
  }

  // verify on garbage signing input → malformed (decode fails first)
  var threwV = null;
  try { await j.verify("garbage", { publicKey: k.publicKey }); }
  catch (e) { threwV = e; }
  check("verify on garbage → auth-jwt/malformed",
        threwV && threwV.code === "auth-jwt/malformed");
}

async function testAuthJwtCritHeaderRejected() {
  // RFC 7515 §4.1.11: any unrecognized critical header MUST cause the
  // verifier to reject the token. We don't define any extensions, so
  // any `crit` header → rejection.
  var j = b.auth.jwt;
  var k = _jwtMlDsaKeypair();

  // Build a token with a crit header by bypassing the framework's sign.
  // Header/payload encoded by hand; signature still produced by Node.
  var header = { alg: "ML-DSA-87", typ: "JWT", crit: ["urn:example:future"] };
  var headerB64 = Buffer.from(JSON.stringify(header)).toString("base64")
    .replace(/=+$/g, "").replace(/\+/g, "-").replace(/\//g, "_");
  var payload = { sub: "u" };
  var payloadB64 = Buffer.from(JSON.stringify(payload)).toString("base64")
    .replace(/=+$/g, "").replace(/\+/g, "-").replace(/\//g, "_");
  var signingInput = headerB64 + "." + payloadB64;
  var sig = require("crypto").sign(null, Buffer.from(signingInput, "ascii"),
                                   require("crypto").createPrivateKey({ key: k.privateKey, format: "pem" }));
  var sigB64 = sig.toString("base64").replace(/=+$/g, "").replace(/\+/g, "-").replace(/\//g, "_");
  var token = signingInput + "." + sigB64;

  var threw = null;
  try { await j.verify(token, { publicKey: k.publicKey, algorithms: ["ML-DSA-87"] }); }
  catch (e) { threw = e; }
  check("verify rejects unknown crit header (RFC 7515 §4.1.11)",
        threw && threw.code === "auth-jwt/unknown-crit");
}

async function testAuthJwtKidPropagation() {
  var j = b.auth.jwt;
  var k = _jwtMlDsaKeypair();
  var token = await j.sign({ sub: "u" }, {
    privateKey: k.privateKey, algorithm: "ML-DSA-87",
    kid: "key-2026-04-26",
  });
  var decoded = j.decode(token);
  check("kid embedded in header",                    decoded.header.kid === "key-2026-04-26");
}

async function testAuthJwtMissingKey() {
  var j = b.auth.jwt;
  var k = _jwtMlDsaKeypair();

  // sign without privateKey
  var threwS = null;
  try { await j.sign({ sub: "u" }, { algorithm: "ML-DSA-87" }); }
  catch (e) { threwS = e; }
  check("sign without privateKey throws missing-key",
        threwS && threwS.code === "auth-jwt/missing-key");

  // verify without publicKey — sign a token first
  var token = await j.sign({ sub: "u" }, { privateKey: k.privateKey, algorithm: "ML-DSA-87" });
  var threwV = null;
  try { await j.verify(token, { algorithms: ["ML-DSA-87"] }); }
  catch (e) { threwV = e; }
  check("verify without publicKey throws missing-key",
        threwV && threwV.code === "auth-jwt/missing-key");
}

// ---- template (Phase 4 slice 1 — eval-free interpreter) ----
//
// Each test sets up its own tmpdir + writes the views by hand so the
// fixtures are inline + readable. No global state — every test creates
// its own engine via template.create({ viewsDir }).

function _writeView(dir, name, content) {
  fs.mkdirSync(path.dirname(path.join(dir, name + ".html")), { recursive: true });
  fs.writeFileSync(path.join(dir, name + ".html"), content);
}

function testTemplateEscapeHtml() {
  var t = b.template;
  check("escapeHtml: ampersand",                t.escapeHtml("a & b") === "a &amp; b");
  check("escapeHtml: lt/gt",                    t.escapeHtml("<x>") === "&lt;x&gt;");
  check("escapeHtml: double-quote",             t.escapeHtml('"x"') === "&quot;x&quot;");
  check("escapeHtml: single-quote",             t.escapeHtml("'x'") === "&#x27;x&#x27;");
  check("escapeHtml: null/undefined → empty",   t.escapeHtml(null) === "" && t.escapeHtml(undefined) === "");
  check("escapeHtml: number → string-escaped",  t.escapeHtml(42) === "42");
}

function testTemplateBasicRender() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-tpl-"));
  try {
    _writeView(dir, "hello", "<h1>{{ greeting }}, {{ name }}!</h1>");
    var eng = b.template.create({ viewsDir: dir });
    var out = eng.render("hello", { greeting: "Hi", name: "Alice" });
    check("basic render substitutes + escapes",   out === "<h1>Hi, Alice!</h1>");

    // Hostile input is escaped by default
    var hostile = eng.render("hello", { greeting: "<script>alert(1)</script>", name: 'A"B' });
    check("user values escaped in {{ }}",
          hostile.indexOf("<script>") === -1 &&
          hostile.indexOf("&lt;script&gt;alert(1)&lt;/script&gt;") !== -1 &&
          hostile.indexOf("&quot;") !== -1);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

function testTemplateRawExpression() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-tpl-"));
  try {
    _writeView(dir, "raw", "<div>{{{ trustedHtml }}}</div>");
    var eng = b.template.create({ viewsDir: dir });
    var out = eng.render("raw", { trustedHtml: "<em>ok</em>" });
    check("{{{ raw }}} bypasses escape",          out === "<div><em>ok</em></div>");

    // null/undefined raw → empty (not "null"/"undefined")
    var nullOut = eng.render("raw", { trustedHtml: null });
    check("{{{ null }}} renders empty",           nullOut === "<div></div>");
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

function testTemplateIfElse() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-tpl-"));
  try {
    _writeView(dir, "cond",
      "{% if loggedIn %}Welcome, {{ name }}{% else %}Please sign in{% endif %}");
    var eng = b.template.create({ viewsDir: dir });
    check("if-true branch",       eng.render("cond", { loggedIn: true, name: "A" }) === "Welcome, A");
    check("if-false → else branch", eng.render("cond", { loggedIn: false }) === "Please sign in");

    // Nested if
    _writeView(dir, "nested",
      "{% if a %}{% if b %}AB{% else %}A!B{% endif %}{% else %}!A{% endif %}");
    check("nested if-true-true",  eng.render("nested", { a: true, b: true }) === "AB");
    check("nested if-true-false", eng.render("nested", { a: true, b: false }) === "A!B");
    check("nested if-false",      eng.render("nested", { a: false, b: true }) === "!A");

    // if without else
    _writeView(dir, "noelse", "[{% if v %}yes{% endif %}]");
    check("if without else, true",  eng.render("noelse", { v: 1 }) === "[yes]");
    check("if without else, false", eng.render("noelse", { v: 0 }) === "[]");
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

function testTemplateForLoop() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-tpl-"));
  try {
    _writeView(dir, "list", "<ul>{% for it in items %}<li>{{ it }}</li>{% endfor %}</ul>");
    var eng = b.template.create({ viewsDir: dir });
    var out = eng.render("list", { items: ["a", "b", "c"] });
    check("for loop iterates array",
          out === "<ul><li>a</li><li>b</li><li>c</li></ul>");

    var empty = eng.render("list", { items: [] });
    check("for over empty array yields no body",  empty === "<ul></ul>");

    // Loop body has access to outer scope too
    _writeView(dir, "list2",
      "{% for x in xs %}{{ prefix }}-{{ x }} {% endfor %}");
    var out2 = eng.render("list2", { xs: [1, 2], prefix: "id" });
    check("loop body sees outer scope",            out2 === "id-1 id-2 ");

    // Object iteration is NOT supported (operators map to entries first)
    var nonIter = eng.render("list", { items: { a: 1 } });
    check("non-array source renders no body (no iteration)",
          nonIter === "<ul></ul>");
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

function testTemplateExpressionGrammar() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-tpl-"));
  try {
    var eng = b.template.create({ viewsDir: dir });

    // Member access + index
    _writeView(dir, "member", "{{ user.name }} ({{ tags[0] }})");
    check("dot-access + index",
          eng.render("member", { user: { name: "A" }, tags: ["x", "y"] }) === "A (x)");

    // Comparison + logical
    _writeView(dir, "cmp", "{% if n > 0 && n < 10 %}small{% else %}other{% endif %}");
    check("&& + comparison true",   eng.render("cmp", { n: 5 }) === "small");
    check("&& + comparison false",  eng.render("cmp", { n: 50 }) === "other");

    // Equality (=== and ==)
    _writeView(dir, "eq", "{% if a === 'x' %}strict{% else %}other{% endif %}");
    check("=== matches strictly",   eng.render("eq", { a: "x" }) === "strict");
    check("=== rejects coercion",   eng.render("eq", { a: 1 }) === "other");

    // Ternary
    _writeView(dir, "tern", "{{ on ? 'YES' : 'NO' }}");
    check("ternary true",           eng.render("tern", { on: true }) === "YES");
    check("ternary false",          eng.render("tern", { on: false }) === "NO");

    // Unary not
    _writeView(dir, "neg", "{% if !done %}working{% else %}done{% endif %}");
    check("unary !",                eng.render("neg", { done: false }) === "working");

    // Function call (operator-supplied helper)
    _writeView(dir, "call", "{{ helpers.upper(name) }}");
    var helpers = { upper: function (s) { return String(s).toUpperCase(); } };
    check("function call invokes operator-supplied helper",
          eng.render("call", { helpers: helpers, name: "alice" }) === "ALICE");

    // String + number literals
    _writeView(dir, "lit", "{{ 'fixed-' + n }}");
    check("literal + numeric concat",   eng.render("lit", { n: 7 }) === "fixed-7");
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

function testTemplatePartialInclusion() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-tpl-"));
  try {
    fs.mkdirSync(path.join(dir, "partials"), { recursive: true });
    fs.writeFileSync(path.join(dir, "partials", "header.html"), "<header>{{ title }}</header>");
    fs.writeFileSync(path.join(dir, "partials", "footer.html"), "<footer>©</footer>");
    _writeView(dir, "page", "{{> header }}<main>{{ body }}</main>{{> footer }}");
    var eng = b.template.create({ viewsDir: dir });
    var out = eng.render("page", { title: "T", body: "B" });
    check("partials inlined + interpolated",
          out === "<header>T</header><main>B</main><footer>©</footer>");

    // Missing partial → silent empty (forgiving render, no exception)
    _writeView(dir, "missing", "[{{> nope }}]");
    check("missing partial silently empty",  eng.render("missing", {}) === "[]");
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

function testTemplateLayoutInheritance() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-tpl-"));
  try {
    _writeView(dir, "base",
      "<html><head><title>{% block title %}Default{% endblock %}</title></head>" +
      "<body><div id='content'>{% block content %}<p>Default body</p>{% endblock %}</div></body></html>");
    _writeView(dir, "child",
      "{% extends \"base\" %}" +
      "{% block title %}{{ pageTitle }}{% endblock %}" +
      "{% block content %}<h1>{{ heading }}</h1>{% endblock %}");
    var eng = b.template.create({ viewsDir: dir });
    var out = eng.render("child", { pageTitle: "Hi", heading: "Welcome" });
    check("child overrides title block",
          out.indexOf("<title>Hi</title>") !== -1);
    check("child overrides content block",
          out.indexOf("<h1>Welcome</h1>") !== -1);
    check("base wraps the child blocks",
          out.indexOf("<html>") === 0 && out.indexOf("</html>") !== -1);

    // Child that overrides only one block — other block keeps default
    _writeView(dir, "partialOverride",
      "{% extends \"base\" %}{% block title %}Only Title{% endblock %}");
    var partial = eng.render("partialOverride", {});
    check("child with partial override keeps base default for non-overridden block",
          partial.indexOf("<title>Only Title</title>") !== -1 &&
          partial.indexOf("<p>Default body</p>") !== -1);

    // Multi-level: grandchild → child → base
    _writeView(dir, "mid",
      "{% extends \"base\" %}{% block content %}<p>mid</p>{% endblock %}");
    _writeView(dir, "leaf",
      "{% extends \"mid\" %}{% block title %}Leaf Title{% endblock %}");
    var multi = eng.render("leaf", {});
    check("multi-level inheritance: leaf title + mid content + base wrap",
          multi.indexOf("<title>Leaf Title</title>") !== -1 &&
          multi.indexOf("<p>mid</p>") !== -1 &&
          multi.indexOf("<html>") === 0);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

function testTemplateContainmentDefenses() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-tpl-"));
  try {
    _writeView(dir, "safe", "ok");
    var eng = b.template.create({ viewsDir: dir });
    check("clean view name renders",        eng.render("safe", {}) === "ok");

    // Path-traversal markers rejected
    var rejected = [
      "../etc/passwd",
      "../../../../etc/passwd",
      "safe/../../escape",
      "with\0null",
    ];
    for (var i = 0; i < rejected.length; i++) {
      var threw = false;
      try { eng.render(rejected[i], {}); } catch (_e) { threw = true; }
      check("rejects path '" + rejected[i] + "'",   threw);
    }

    // Empty / non-string view name rejected
    var threwEmpty = false;
    try { eng.render("", {}); } catch (_e) { threwEmpty = true; }
    check("rejects empty view name",         threwEmpty);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

function testTemplatePrototypeSafety() {
  // Member access must NOT walk the prototype chain — `{{ x.constructor }}`
  // and `{{ x.__proto__ }}` should resolve to undefined, not Function/Object.
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-tpl-"));
  try {
    _writeView(dir, "proto", "[{{ x.constructor }}][{{ x.__proto__ }}][{{ x.toString }}]");
    var eng = b.template.create({ viewsDir: dir });
    var out = eng.render("proto", { x: { y: 1 } });
    // Each prototype-chain access renders empty
    check("prototype-chain access yields undefined → empty escape",
          out === "[][][]");
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

function testTemplateCacheAndReset() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-tpl-"));
  try {
    _writeView(dir, "v", "<p>v1: {{ x }}</p>");
    var eng = b.template.create({ viewsDir: dir });
    check("first render uses v1",            eng.render("v", { x: 1 }) === "<p>v1: 1</p>");

    // Mutate the source on disk — cached engine still serves the old AST
    _writeView(dir, "v", "<p>v2: {{ x }}</p>");
    check("second render still uses cached v1 AST (cache=on default)",
          eng.render("v", { x: 1 }) === "<p>v1: 1</p>");

    // reset() drops the cache
    eng.reset();
    check("after reset, engine picks up v2",
          eng.render("v", { x: 1 }) === "<p>v2: 1</p>");

    // cache: false → always re-read
    var engNoCache = b.template.create({ viewsDir: dir, cache: false });
    _writeView(dir, "v", "<p>v3: {{ x }}</p>");
    check("cache:false reflects latest source",
          engNoCache.render("v", { x: 1 }) === "<p>v3: 1</p>");
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

function testTemplateMissingViewsDir() {
  var threw = null;
  try { b.template.create({ viewsDir: path.join(os.tmpdir(), "blamejs-nope-" + Date.now()) }); }
  catch (e) { threw = e; }
  check("create() rejects missing viewsDir",   threw && /viewsDir does not exist/.test(threw.message));

  threw = null;
  try { b.template.create({}); }
  catch (e) { threw = e; }
  check("create() requires viewsDir",          threw && /viewsDir.*required/.test(threw.message));
}

function testTemplateSurface() {
  check("b.template namespace present",        typeof b.template === "object");
  check("b.template.create is a function",     typeof b.template.create === "function");
  check("b.template.render is a function",     typeof b.template.render === "function");
  check("b.template.escapeHtml is a function", typeof b.template.escapeHtml === "function");
}

// ---- render (Phase 4 slice 2 — response helpers) ----

function _captureRes() {
  // Mock res with the same shape b.middleware.errorHandler / cors etc.
  // expect: writeHead(status, headers), end(body), writableEnded.
  // _captured() returns { status, headers, body, ended }.
  var headers = {};
  var status = null;
  var body = "";
  var ended = false;
  return {
    writableEnded: false,
    writeHead: function (s, h) { status = s; if (h) for (var k in h) headers[k.toLowerCase()] = h[k]; },
    setHeader: function (k, v) { headers[k.toLowerCase()] = v; },
    end:       function (b) { if (b !== undefined && b !== null) body += b; ended = true; this.writableEnded = true; },
    _captured: function () { return { status: status, headers: headers, body: body, ended: ended }; },
  };
}

function testRenderJson() {
  var res = _captureRes();
  b.render.json(res, { ok: true, n: 42 });
  var c = res._captured();
  check("render.json: 200 default",                  c.status === 200);
  check("render.json: Content-Type application/json",
        c.headers["content-type"].indexOf("application/json") === 0);
  check("render.json: body is JSON-stringified",     c.body === '{"ok":true,"n":42}');
  check("render.json: Content-Length matches body",
        Number(c.headers["content-length"]) === Buffer.byteLength(c.body));

  // Custom status + extra headers
  var res2 = _captureRes();
  b.render.json(res2, { error: "bad" }, { status: 400, headers: { "X-Custom": "v" } });
  var c2 = res2._captured();
  check("render.json: custom status",                c2.status === 400);
  check("render.json: extra headers merged",         c2.headers["x-custom"] === "v");
}

function testRenderText() {
  var res = _captureRes();
  b.render.text(res, "hello");
  var c = res._captured();
  check("render.text: 200 default",                  c.status === 200);
  check("render.text: Content-Type text/plain",
        c.headers["content-type"].indexOf("text/plain") === 0);
  check("render.text: body is the string",           c.body === "hello");

  // Null/undefined body is empty string, not "null"/"undefined"
  var res2 = _captureRes();
  b.render.text(res2, null);
  check("render.text: null → empty body",            res2._captured().body === "");
}

function testRenderHtmlString() {
  var res = _captureRes();
  b.render.htmlString(res, "<h1>Hi</h1>");
  var c = res._captured();
  check("render.htmlString: Content-Type text/html",
        c.headers["content-type"].indexOf("text/html") === 0);
  check("render.htmlString: body intact",            c.body === "<h1>Hi</h1>");
}

function testRenderRedirect() {
  var res = _captureRes();
  b.render.redirect(res, "/login");
  var c = res._captured();
  check("render.redirect: 302 default",              c.status === 302);
  check("render.redirect: Location header",          c.headers.location === "/login");
  check("render.redirect: empty body",               c.body === "");

  // Permanent redirect (301) opt-in
  var res2 = _captureRes();
  b.render.redirect(res2, "/new-home", { status: 301 });
  check("render.redirect: 301 status honored",       res2._captured().status === 301);

  // Non-3xx status rejected
  var threw = false;
  try { b.render.redirect(_captureRes(), "/x", { status: 200 }); }
  catch (_e) { threw = true; }
  check("render.redirect: rejects non-3xx status",   threw);

  // Empty location rejected
  threw = false;
  try { b.render.redirect(_captureRes(), ""); }
  catch (_e) { threw = true; }
  check("render.redirect: rejects empty location",   threw);
}

function testRenderDoesNotDoubleWrite() {
  // Mid-stream double-writes (route already responded then a stray
  // helper fires) must NOT corrupt the wire — second write is a no-op.
  var res = _captureRes();
  b.render.json(res, { ok: 1 });
  var firstStatus = res._captured().status;
  b.render.json(res, { ok: 2 });    // should be a no-op
  var c = res._captured();
  check("render: silent no-op when res already finished",
        c.status === firstStatus && c.body === '{"ok":1}');
}

function testRenderCreateWithEngine() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-render-"));
  try {
    fs.writeFileSync(path.join(dir, "page.html"), "<h1>{{ title }}</h1>");
    var engine = b.template.create({ viewsDir: dir });
    var r = b.render.create({ engine: engine });
    check("create returns html method",                typeof r.html === "function");
    check("create returns json/text/redirect too",
          typeof r.json === "function" && typeof r.text === "function" && typeof r.redirect === "function");
    check("create exposes the engine",                 r.engine === engine);

    var res = _captureRes();
    r.html(res, "page", { title: "Hi" });
    var c = res._captured();
    check("instance.html renders + writes correct body",
          c.body === "<h1>Hi</h1>" && c.headers["content-type"].indexOf("text/html") === 0);

    // Render error from a missing view propagates (operator catches via
    // middleware.errorHandler downstream)
    var threw = false;
    try { r.html(_captureRes(), "nope-not-real", {}); }
    catch (_e) { threw = true; }
    check("instance.html propagates render errors",    threw);

    // Custom status (e.g. 404 page render)
    var res2 = _captureRes();
    r.html(res2, "page", { title: "404" }, { status: 404 });
    check("instance.html honors opts.status",           res2._captured().status === 404);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

function testRenderCreateValidation() {
  var threw = null;
  try { b.render.create({}); }
  catch (e) { threw = e; }
  check("create({}) requires engine",                  threw && /engine\.render/.test(threw.message));

  threw = null;
  try { b.render.create({ engine: { not: "an engine" } }); }
  catch (e) { threw = e; }
  check("create with non-engine object rejected",      threw && /engine\.render/.test(threw.message));
}

function testRenderSurface() {
  check("b.render namespace present",                  typeof b.render === "object");
  check("b.render.create is a function",               typeof b.render.create === "function");
  check("b.render.json is a function",                 typeof b.render.json === "function");
  check("b.render.text is a function",                 typeof b.render.text === "function");
  check("b.render.htmlString is a function",           typeof b.render.htmlString === "function");
  check("b.render.redirect is a function",             typeof b.render.redirect === "function");
}

// ---- staticServe (Phase 4 slice 3) ----
//
// Each test sets up its own root dir with fixture files; ends-to-end
// via a real http server + the framework's listenOnRandomPort helper.

async function _httpGet(port, urlPath, headers) {
  return await b.httpClient.request({
    url: "http://127.0.0.1:" + port + urlPath,
    headers: headers || {},
    allowedProtocols: b.urlSafe.ALLOW_HTTP_ALL,
  });
}

async function _httpReq(port, method, urlPath, headers) {
  return await b.httpClient.request({
    method: method,
    url: "http://127.0.0.1:" + port + urlPath,
    headers: headers || {},
    allowedProtocols: b.urlSafe.ALLOW_HTTP_ALL,
  });
}

function _writeFile(dir, name, content) {
  fs.mkdirSync(path.dirname(path.join(dir, name)), { recursive: true });
  fs.writeFileSync(path.join(dir, name), content);
}

async function testStaticServeBasic() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-static-"));
  _writeFile(dir, "hello.txt", "hello world");
  _writeFile(dir, "page.html", "<h1>X</h1>");
  b.staticServe._resetCacheForTest();

  var http = require("http");
  var mw = b.staticServe.create({ root: dir });
  var server = http.createServer(function (req, res) {
    mw(req, res, function () {
      res.writeHead(404, { "Content-Type": "text/plain" });
      res.end("not found");
    });
  });
  var port = await listenOnRandomPort(server);
  try {
    var got = await _httpGet(port, "/hello.txt");
    check("static: GET 200",                            got.statusCode === 200);
    check("static: body bytes intact",                  got.body.toString("utf8") === "hello world");
    check("static: Content-Type from extension",
          got.headers["content-type"].indexOf("text/plain") === 0);
    check("static: Cache-Control public + max-age",
          /public, max-age=\d+/.test(got.headers["cache-control"]));
    check("static: ETag is a quoted string",            /^"[^"]+"$/.test(got.headers["etag"]));
    check("static: X-Integrity is sha384-…",
          /^sha384-[A-Za-z0-9+/=]+$/.test(got.headers["x-integrity"]));

    // HTML extension picks up text/html
    var html = await _httpGet(port, "/page.html");
    check("static: .html → text/html",
          html.headers["content-type"].indexOf("text/html") === 0);
  } finally {
    server.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

async function testStaticServeImmutableForHashedPaths() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-static-"));
  _writeFile(dir, "app.css", "body { color: red; }");
  _writeFile(dir, "app.abc123ef.css", "body { color: blue; }");
  b.staticServe._resetCacheForTest();

  var http = require("http");
  var mw = b.staticServe.create({ root: dir });
  var server = http.createServer(function (req, res) {
    mw(req, res, function () { res.writeHead(404); res.end(); });
  });
  var port = await listenOnRandomPort(server);
  try {
    var plain = await _httpGet(port, "/app.css");
    check("static: non-hashed path uses default max-age",
          /max-age=3600/.test(plain.headers["cache-control"]) &&
          plain.headers["cache-control"].indexOf("immutable") === -1);

    var hashed = await _httpGet(port, "/app.abc123ef.css");
    check("static: hashed path uses immutable cache",
          /max-age=31536000/.test(hashed.headers["cache-control"]) &&
          /immutable/.test(hashed.headers["cache-control"]));
  } finally {
    server.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

async function testStaticServeEtagAnd304() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-static-"));
  _writeFile(dir, "f.txt", "hello");
  b.staticServe._resetCacheForTest();

  var http = require("http");
  var mw = b.staticServe.create({ root: dir });
  var server = http.createServer(function (req, res) { mw(req, res, function () { res.writeHead(404); res.end(); }); });
  var port = await listenOnRandomPort(server);
  try {
    var first = await _httpGet(port, "/f.txt");
    check("static: 200 first request",                 first.statusCode === 200);
    var etag = first.headers["etag"];

    // Conditional GET with matching If-None-Match → 304. httpClient
    // rejects on non-2xx (treats 3xx/4xx/5xx alike), so the 304 path
    // surfaces as a thrown error with statusCode 304.
    var second = null;
    try {
      await b.httpClient.request({
        url: "http://127.0.0.1:" + port + "/f.txt",
        headers: { "If-None-Match": etag },
        allowedProtocols: b.urlSafe.ALLOW_HTTP_ALL,
        errorClass: b.frameworkError.ObjectStoreError,
      });
    } catch (e) { second = e; }
    check("static: matching If-None-Match → 304",      second && second.statusCode === 304);

    // Conditional GET with mismatched If-None-Match → 200
    var third = await _httpGet(port, "/f.txt", { "If-None-Match": '"not-the-real-etag"' });
    check("static: mismatched If-None-Match → 200",    third.statusCode === 200);
  } finally {
    server.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

async function testStaticServeHead() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-static-"));
  _writeFile(dir, "f.txt", "hello world");
  b.staticServe._resetCacheForTest();

  var http = require("http");
  var mw = b.staticServe.create({ root: dir });
  var server = http.createServer(function (req, res) { mw(req, res, function () { res.writeHead(404); res.end(); }); });
  var port = await listenOnRandomPort(server);
  try {
    var head = await _httpReq(port, "HEAD", "/f.txt");
    check("static: HEAD returns 200",                   head.statusCode === 200);
    check("static: HEAD body is empty",                 head.body.length === 0);
    check("static: HEAD carries Content-Length",
          Number(head.headers["content-length"]) === Buffer.byteLength("hello world"));
    check("static: HEAD carries ETag",                  /^"[^"]+"$/.test(head.headers["etag"]));
  } finally {
    server.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

async function testStaticServeContainmentDefenses() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-static-"));
  _writeFile(dir, "ok.txt", "ok");
  // Sibling directory outside root that we might leak via traversal
  var siblingDir = dir + "-sibling";
  fs.mkdirSync(siblingDir, { recursive: true });
  fs.writeFileSync(path.join(siblingDir, "secret.txt"), "secret");
  b.staticServe._resetCacheForTest();

  var http = require("http");
  var mw = b.staticServe.create({ root: dir });
  var server = http.createServer(function (req, res) { mw(req, res, function () {
    res.writeHead(404); res.end("not found");
  }); });
  var port = await listenOnRandomPort(server);
  try {
    var rejected = [
      "/../" + path.basename(siblingDir) + "/secret.txt",
      "/..%2f..%2fetc%2fpasswd",
      "/ok.txt%00.png",   // null byte
    ];
    for (var i = 0; i < rejected.length; i++) {
      var resp = null;
      try {
        resp = await b.httpClient.request({
          url: "http://127.0.0.1:" + port + rejected[i],
          allowedProtocols: b.urlSafe.ALLOW_HTTP_ALL,
          errorClass: b.frameworkError.ObjectStoreError,
        });
      } catch (e) { resp = e; }
      // Either falls through to the operator's 404 OR errors at HTTP layer.
      // Either way, the secret file content must not appear in the body.
      var body = resp && resp.body ? resp.body.toString("utf8") : "";
      check("static: rejects '" + rejected[i] + "' (no leak of secret content)",
            body.indexOf("secret") === -1);
    }

    // Sanity: legitimate request still works
    var ok = await _httpGet(port, "/ok.txt");
    check("static: legitimate request still served",   ok.body.toString("utf8") === "ok");
  } finally {
    server.close();
    fs.rmSync(dir, { recursive: true, force: true });
    fs.rmSync(siblingDir, { recursive: true, force: true });
  }
}

async function testStaticServeIndexFile() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-static-"));
  _writeFile(dir, "index.html", "<h1>root</h1>");
  _writeFile(dir, "sub/index.html", "<h1>sub</h1>");
  b.staticServe._resetCacheForTest();

  var http = require("http");
  var mw = b.staticServe.create({ root: dir });
  var server = http.createServer(function (req, res) { mw(req, res, function () {
    res.writeHead(404); res.end();
  }); });
  var port = await listenOnRandomPort(server);
  try {
    var rootGet = await _httpGet(port, "/");
    check("static: dir / serves indexFile",            rootGet.body.toString("utf8") === "<h1>root</h1>");

    var subGet = await _httpGet(port, "/sub/");
    check("static: nested dir serves its indexFile",    subGet.body.toString("utf8") === "<h1>sub</h1>");

    // Disable indexFile → directory falls through to next()
    b.staticServe._resetCacheForTest();
    var mw2 = b.staticServe.create({ root: dir, indexFile: null });
    var server2 = http.createServer(function (req, res) { mw2(req, res, function () {
      res.writeHead(404); res.end("no index");
    }); });
    var port2 = await listenOnRandomPort(server2);
    try {
      var noIdx = await b.httpClient.request({
        url: "http://127.0.0.1:" + port2 + "/",
        allowedProtocols: b.urlSafe.ALLOW_HTTP_ALL,
        errorClass: b.frameworkError.ObjectStoreError,
      }).catch(function (e) { return e; });
      check("static: indexFile=null → falls through to next()",
            (noIdx.statusCode || noIdx.statusCode) === 404);
    } finally { server2.close(); }
  } finally {
    server.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

async function testStaticServeMethodGuard() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-static-"));
  _writeFile(dir, "f.txt", "x");
  b.staticServe._resetCacheForTest();

  var http = require("http");
  var nextCalls = 0;
  var mw = b.staticServe.create({ root: dir });
  var server = http.createServer(function (req, res) { mw(req, res, function () {
    nextCalls += 1;
    res.writeHead(405, { "Content-Type": "text/plain", "Allow": "GET, HEAD" });
    res.end("method not allowed");
  }); });
  var port = await listenOnRandomPort(server);
  try {
    var post = await b.httpClient.request({
      method: "POST",
      url: "http://127.0.0.1:" + port + "/f.txt",
      body: Buffer.from("nope"),
      allowedProtocols: b.urlSafe.ALLOW_HTTP_ALL,
      errorClass: b.frameworkError.ObjectStoreError,
    }).catch(function (e) { return e; });
    check("static: POST falls through (next() called)",  nextCalls === 1);
    check("static: POST returns operator's 405",         post.statusCode === 405);
  } finally {
    server.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

async function testStaticServeIntegrityHelper() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-static-"));
  _writeFile(dir, "asset.css", "body { color: green; }");
  b.staticServe._resetCacheForTest();
  try {
    var sri = await b.staticServe.integrity(path.join(dir, "asset.css"));
    check("integrity returns sha384- prefix",          /^sha384-/.test(sri));
    check("integrity is base64-shaped",                /^sha384-[A-Za-z0-9+/=]+$/.test(sri));
    // Same file → same hash (cached or not)
    var sri2 = await b.staticServe.integrity(path.join(dir, "asset.css"));
    check("integrity is deterministic on same content", sri === sri2);

    // Modified file → different hash
    fs.writeFileSync(path.join(dir, "asset.css"), "body { color: red; }");
    // Bump mtime so cache invalidates
    var future = (Date.now() + 5000) / 1000;
    fs.utimesSync(path.join(dir, "asset.css"), future, future);
    var sri3 = await b.staticServe.integrity(path.join(dir, "asset.css"));
    check("integrity reflects content change",          sri3 !== sri);

    // Missing file
    var threw = null;
    try { await b.staticServe.integrity(path.join(dir, "missing.css")); }
    catch (e) { threw = e; }
    check("integrity throws on missing file",          threw && /not found/i.test(threw.message));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function testStaticServeSurface() {
  check("b.staticServe namespace present",             typeof b.staticServe === "object");
  check("b.staticServe.create is a function",          typeof b.staticServe.create === "function");
  check("b.staticServe.integrity is a function",       typeof b.staticServe.integrity === "function");
  check("b.staticServe.IMMUTABLE_MAX_AGE_SEC = 1y",
        b.staticServe.IMMUTABLE_MAX_AGE_SEC === 31536000);
  check("b.staticServe.DEFAULT_MAX_AGE_SEC = 1h",
        b.staticServe.DEFAULT_MAX_AGE_SEC === 3600);

  // create() validation
  var threw = null;
  try { b.staticServe.create({}); }
  catch (e) { threw = e; }
  check("create({}) requires root",                     threw && /root/.test(threw.message));

  threw = null;
  try { b.staticServe.create({ root: path.join(os.tmpdir(), "blamejs-nope-" + Date.now()) }); }
  catch (e) { threw = e; }
  check("create() rejects missing root",                threw && /does not exist/.test(threw.message));
}

// ---- forms (Phase 4 slice 4) ----

function testFormsCsrfTokenGeneration() {
  var f = b.forms;
  var t = f.generateCsrfToken();
  check("generateCsrfToken: 64 hex chars (32 bytes)",
        typeof t === "string" && /^[0-9a-f]{64}$/.test(t));
  // Two consecutive calls produce different tokens (random)
  check("generateCsrfToken: non-deterministic",      f.generateCsrfToken() !== t);
}

function testFormsCsrfTokenVerify() {
  var f = b.forms;
  var t = f.generateCsrfToken();
  check("verifyCsrfToken: same string accepts",      f.verifyCsrfToken(t, t) === true);
  check("verifyCsrfToken: different strings reject", f.verifyCsrfToken(t, f.generateCsrfToken()) === false);
  // Length-mismatch rejected (defense against length-oracle attacks)
  check("verifyCsrfToken: length mismatch → false",  f.verifyCsrfToken(t, t + "X") === false);
  // Empty / null / wrong-type → false (no throw)
  check("verifyCsrfToken: empty → false",            f.verifyCsrfToken("", t) === false);
  check("verifyCsrfToken: null → false",             f.verifyCsrfToken(null, t) === false);
  check("verifyCsrfToken: number → false",           f.verifyCsrfToken(42, t) === false);
}

function testFormsEscapeAttribute() {
  var f = b.forms;
  // Escapes the same set as escapeHtml + ` and =
  check("escapeAttribute: <, >, &",                  f.escapeAttribute("<&>") === "&lt;&amp;&gt;");
  check("escapeAttribute: double-quote",             f.escapeAttribute('"x"') === "&quot;x&quot;");
  check("escapeAttribute: single-quote",             f.escapeAttribute("'x'") === "&#x27;x&#x27;");
  check("escapeAttribute: backtick",                 f.escapeAttribute("`x`") === "&#x60;x&#x60;");
  check("escapeAttribute: equals sign",              f.escapeAttribute("a=b") === "a&#x3D;b");
  check("escapeAttribute: null/undefined → empty",
        f.escapeAttribute(null) === "" && f.escapeAttribute(undefined) === "");
}

function testFormsRenderBasic() {
  var f = b.forms;
  var html = f.render({
    action: "/contact",
    csrfToken: "abc123",
    fields: [
      { name: "email", type: "email", required: true, label: "Email" },
      { name: "msg",   type: "textarea", label: "Message" },
    ],
  });
  check("render: <form> wraps content",                html.indexOf("<form ") === 0 && html.indexOf("</form>") !== -1);
  check("render: action attribute",                    html.indexOf('action="/contact"') !== -1);
  check("render: method defaults to POST",             html.indexOf('method="POST"') !== -1);
  check("render: hidden CSRF input",
        html.indexOf('<input type="hidden" name="_csrf" value="abc123">') !== -1);
  check("render: email input present",                 html.indexOf('type="email"') !== -1);
  check("render: required attribute",                  html.indexOf("required") !== -1);
  check("render: textarea element",                    html.indexOf("<textarea") !== -1);
  check("render: auto-appended submit button",         html.indexOf("<button type=\"submit\">Submit</button>") !== -1);
  check("render: label wraps non-hidden field",        html.indexOf("<label>Email") !== -1);
}

function testFormsRenderEscapesHostileInput() {
  var f = b.forms;
  // Operator (or attacker) tries to slip an attribute-breaking value
  // into an action or option label
  var html = f.render({
    action: '/safe" onsubmit="alert(1)',
    fields: [
      { name: "color", type: "select", options: [
        { value: 'red"><script>alert(1)</script>', label: '"label' },
      ]},
    ],
  });
  // The attacker payload must NOT appear as raw HTML
  check("render: hostile action escaped",              html.indexOf('onsubmit="alert(1)') === -1);
  check("render: hostile option value escaped",        html.indexOf("<script>") === -1);
  check("render: option label HTML-escaped",
        html.indexOf("&quot;label") !== -1);
}

function testFormsRenderSelectAndPreselection() {
  var f = b.forms;
  var html = f.render({
    action: "/x",
    csrfToken: "T",
    fields: [{
      name: "country",
      type: "select",
      value: "FR",
      options: [
        { value: "US", label: "United States" },
        { value: "FR", label: "France" },
      ],
    }],
  });
  check("select renders all options",
        html.indexOf("United States") !== -1 && html.indexOf("France") !== -1);
  check("select pre-selects via value match",
        /<option[^>]*value="FR"[^>]*selected[^>]*>France<\/option>/.test(html) === true);
}

function testFormsRenderSubmitOverride() {
  var f = b.forms;
  // When operator includes a submit field, no auto-button
  var html = f.render({
    action: "/x",
    fields: [
      { name: "n", type: "text" },
      { name: "go", type: "submit", value: "Send Now" },
    ],
  });
  check("explicit submit overrides auto-button",
        html.indexOf('type="submit"') !== -1 &&
        html.indexOf('value="Send Now"') !== -1 &&
        html.indexOf("<button") === -1);
}

function testFormsRenderRejectsInvalidSpec() {
  var f = b.forms;
  var threw = null;
  try { f.render({ fields: [] }); }
  catch (e) { threw = e; }
  check("render rejects missing action",               threw && /action is required/.test(threw.message));

  threw = null;
  try { f.render({ action: "/x" }); }
  catch (e) { threw = e; }
  check("render rejects missing fields",               threw && /fields must be an array/.test(threw.message));

  threw = null;
  try { f.render({ action: "/x", fields: [{ type: "text" }] }); }
  catch (e) { threw = e; }
  check("render rejects field without name",           threw && /name/.test(threw.message));

  threw = null;
  try { f.render({ action: "/x", fields: [{ name: "x", type: "wat" }] }); }
  catch (e) { threw = e; }
  check("render rejects unknown field type",           threw && /unsupported field type/.test(threw.message));
}

function testFormsValidateRequired() {
  var f = b.forms;
  var spec = { fields: [
    { name: "email", type: "email", required: true, label: "Email" },
    { name: "name",  type: "text" },
  ]};

  var r1 = f.validate(spec, {});
  check("validate: missing required produces error",   r1.valid === false && r1.errors.email);
  check("validate: error references field label",      /Email is required/.test(r1.errors.email));
  check("validate: optional field not required",       !r1.errors.name);

  var r2 = f.validate(spec, { email: "alice@example.com", name: "Alice" });
  check("validate: all-present passes",                r2.valid === true && Object.keys(r2.errors).length === 0);
  check("validate: values reflected back",             r2.values.email === "alice@example.com" && r2.values.name === "Alice");
}

function testFormsValidateTypes() {
  var f = b.forms;

  // Number
  var r = f.validate({ fields: [{ name: "n", type: "number", min: 1, max: 10 }]}, { n: "5" });
  check("validate: number coerces string → number",    r.valid === true && r.values.n === 5);

  r = f.validate({ fields: [{ name: "n", type: "number" }]}, { n: "abc" });
  check("validate: non-numeric number → error",        r.valid === false && /must be a number/.test(r.errors.n));

  r = f.validate({ fields: [{ name: "n", type: "number", min: 5 }]}, { n: "1" });
  check("validate: number below min → error",          r.valid === false && /≥ 5/.test(r.errors.n));

  r = f.validate({ fields: [{ name: "n", type: "number", max: 10 }]}, { n: "100" });
  check("validate: number above max → error",          r.valid === false && /≤ 10/.test(r.errors.n));

  // Email
  r = f.validate({ fields: [{ name: "e", type: "email" }]}, { e: "not-an-email" });
  check("validate: bad email → error",                 r.valid === false && /valid email/.test(r.errors.e));

  r = f.validate({ fields: [{ name: "e", type: "email" }]}, { e: "alice@example.com" });
  check("validate: good email passes",                 r.valid === true);

  // URL
  r = f.validate({ fields: [{ name: "u", type: "url" }]}, { u: "not a url" });
  check("validate: bad URL → error",                   r.valid === false && /valid URL/.test(r.errors.u));

  r = f.validate({ fields: [{ name: "u", type: "url" }]}, { u: "https://example.com/x" });
  check("validate: good URL passes",                   r.valid === true);

  // Checkbox
  r = f.validate({ fields: [{ name: "c", type: "checkbox" }]}, { c: "on" });
  check("validate: checkbox 'on' → true",              r.valid === true && r.values.c === true);
  r = f.validate({ fields: [{ name: "c", type: "checkbox" }]}, {});
  check("validate: checkbox missing → false",          r.valid === true && r.values.c === false);

  // Length bounds
  r = f.validate({ fields: [{ name: "p", type: "text", minlength: 8, maxlength: 64 }]}, { p: "short" });
  check("validate: text below minlength → error",      r.valid === false && /at least 8/.test(r.errors.p));
  r = f.validate({ fields: [{ name: "p", type: "text", maxlength: 5 }]}, { p: "way too long" });
  check("validate: text above maxlength → error",      r.valid === false && /at most 5/.test(r.errors.p));

  // Pattern
  r = f.validate({ fields: [{ name: "code", type: "text", pattern: "[A-Z]{3}-[0-9]{4}" }]}, { code: "ABC-1234" });
  check("validate: pattern match passes",              r.valid === true);
  r = f.validate({ fields: [{ name: "code", type: "text", pattern: "[A-Z]{3}-[0-9]{4}" }]}, { code: "abc-12" });
  check("validate: pattern mismatch → error",          r.valid === false && /invalid format/.test(r.errors.code));

  // Select / radio enum
  r = f.validate({ fields: [
    { name: "c", type: "select", options: [{ value: "US" }, { value: "FR" }]},
  ]}, { c: "ZZ" });
  check("validate: out-of-enum select → error",        r.valid === false && /invalid value/.test(r.errors.c));
}

function testFormsSurface() {
  var f = b.forms;
  check("b.forms namespace present",                   typeof b.forms === "object");
  check("b.forms.generateCsrfToken is a function",     typeof f.generateCsrfToken === "function");
  check("b.forms.verifyCsrfToken is a function",       typeof f.verifyCsrfToken === "function");
  check("b.forms.render is a function",                typeof f.render === "function");
  check("b.forms.validate is a function",              typeof f.validate === "function");
  check("b.forms.escapeAttribute is a function",       typeof f.escapeAttribute === "function");
  check("b.forms.escapeHtml === template.escapeHtml",  f.escapeHtml === b.template.escapeHtml);
  check("b.forms.CSRF_TOKEN_BYTES = 32",                f.CSRF_TOKEN_BYTES === 32);
}

// ---- mail (Phase 5 slice 4) ----
//
// memory transport is the pattern for tests; it captures every
// message into transport.sent[] without touching disk or network.

async function testMailSendRoundTripViaMemoryTransport() {
  var memory = b.mail.transports.memory();
  var mailer = b.mail.create({
    transport: memory,
    defaults:  { from: "noreply@example.com" },
    audit:     false,    // skip audit for layer-0 (no audit module init)
  });
  var result = await mailer.send({
    to:      "alice@example.com",
    subject: "Welcome",
    text:    "Hi Alice",
  });
  check("mail.send returns transport result",        result && result.transport === "memory");
  check("memory transport captures the message",     memory.sent.length === 1);
  check("captured message has merged from",          memory.sent[0].from === "noreply@example.com");
  check("captured message has subject",              memory.sent[0].subject === "Welcome");
  check("captured message has body",                 memory.sent[0].text === "Hi Alice");

  memory.reset();
  check("memory.reset clears sent[]",                memory.sent.length === 0);
}

async function testMailDefaultsAndOverrides() {
  var memory = b.mail.transports.memory();
  var mailer = b.mail.create({
    transport: memory,
    defaults:  {
      from:    "default@example.com",
      replyTo: "support@example.com",
      headers: { "X-App": "blamejs", "X-Env": "dev" },
    },
    audit: false,
  });

  // Defaults applied
  await mailer.send({ to: "x@y.com", subject: "S", text: "T" });
  check("from default applied",                      memory.sent[0].from === "default@example.com");
  check("replyTo default applied",                   memory.sent[0].replyTo === "support@example.com");
  check("headers default applied",                   memory.sent[0].headers["X-App"] === "blamejs");

  // Per-message override
  memory.reset();
  await mailer.send({
    to: "x@y.com", subject: "S", text: "T",
    from: "override@example.com",
    headers: { "X-App": "test", "X-Custom": "v" },
  });
  check("from override wins",                        memory.sent[0].from === "override@example.com");
  check("replyTo default still applied",             memory.sent[0].replyTo === "support@example.com");
  check("headers merged shallow (override beats default)",
        memory.sent[0].headers["X-App"] === "test");
  check("headers merged shallow (default still present)",
        memory.sent[0].headers["X-Env"] === "dev");
  check("headers merged shallow (override-only key)",
        memory.sent[0].headers["X-Custom"] === "v");
}

async function testMailValidation() {
  var memory = b.mail.transports.memory();
  var mailer = b.mail.create({ transport: memory, audit: false });

  var threw = null;
  try { await mailer.send({ from: "a@b.com", text: "x" }); }
  catch (e) { threw = e; }
  check("missing to → mail/missing-to",
        threw && threw.code === "mail/missing-to" && threw.isMailError === true);

  threw = null;
  try { await mailer.send({ to: "a@b.com", text: "x" }); }
  catch (e) { threw = e; }
  check("missing from → mail/missing-from",          threw && threw.code === "mail/missing-from");

  threw = null;
  try { await mailer.send({ to: "a@b.com", from: "c@d.com" }); }
  catch (e) { threw = e; }
  check("missing body → mail/missing-body",          threw && threw.code === "mail/missing-body");

  threw = null;
  try { await mailer.send({ to: "not-an-email", from: "c@d.com", text: "x" }); }
  catch (e) { threw = e; }
  check("invalid recipient → mail/invalid-recipient", threw && threw.code === "mail/invalid-recipient");

  threw = null;
  try { await mailer.send({ to: "a@b.com", from: "garbage", text: "x" }); }
  catch (e) { threw = e; }
  check("invalid from → mail/invalid-from",          threw && threw.code === "mail/invalid-from");

  // Bracketed-form recipient is valid
  await mailer.send({
    to:   "Alice <alice@example.com>",
    from: "Bob <bob@example.com>",
    text: "hi",
  });
  check("bracketed Name <addr> form accepted",       memory.sent.length === 1);
}

async function testMailRecipientArrayAndCcBcc() {
  var memory = b.mail.transports.memory();
  var mailer = b.mail.create({ transport: memory, audit: false });
  await mailer.send({
    to:      ["a@x.com", "b@x.com"],
    cc:      "c@x.com",
    bcc:     ["d@x.com", "e@x.com"],
    from:    "noreply@x.com",
    subject: "Multi",
    text:    "body",
  });
  check("multiple to addresses preserved",
        Array.isArray(memory.sent[0].to) && memory.sent[0].to.length === 2);
  check("cc string preserved",                       memory.sent[0].cc === "c@x.com");
  check("bcc array preserved",
        Array.isArray(memory.sent[0].bcc) && memory.sent[0].bcc.length === 2);
}

async function testMailTransportFailureWraps() {
  // A transport that throws → mail/transport-failed wrapper
  var failingTransport = {
    name: "broken",
    send: async function () { throw new Error("smtp connection refused"); },
  };
  var mailer = b.mail.create({ transport: failingTransport, audit: false });

  var threw = null;
  try {
    await mailer.send({ to: "a@b.com", from: "c@d.com", text: "x" });
  } catch (e) { threw = e; }
  check("transport throw → mail/transport-failed",   threw && threw.code === "mail/transport-failed");
  check("wrapped error is MailError",                threw && threw.isMailError === true);
  check("wrapped error preserves cause",
        threw && threw.cause && /smtp connection refused/.test(threw.cause.message));

  // A transport throwing a MailError passes through unchanged
  var explicitMailError = {
    name: "direct",
    send: async function () { throw new b.mail.MailError("custom-code", "explicit failure", true); },
  };
  var mailer2 = b.mail.create({ transport: explicitMailError, audit: false });

  threw = null;
  try { await mailer2.send({ to: "a@b.com", from: "c@d.com", text: "x" }); }
  catch (e) { threw = e; }
  check("upstream MailError preserved (code unchanged)",
        threw && threw.code === "custom-code" && threw.message === "explicit failure");
}

async function testMailFunctionAsTransport() {
  // A bare function counts as a transport
  var calls = [];
  var mailer = b.mail.create({
    transport: async function (message) {
      calls.push(message);
      return { transport: "fn", at: Date.now() };
    },
    audit: false,
  });
  var result = await mailer.send({
    to: "a@b.com", from: "c@d.com", subject: "S", text: "T",
  });
  check("function transport invoked",                calls.length === 1);
  check("function transport result returned",        result && result.transport === "fn");
}

function testMailConsoleTransportShape() {
  // Capture stderr to a buffer; the console transport writes there.
  var stream = {
    written: "",
    write: function (s) { this.written += s; },
  };
  var t = b.mail.transports.console({ stream: stream });
  check("console transport has a name",              t.name === "console");
  check("console transport exposes send",            typeof t.send === "function");
  // Smoke-call it
  return t.send({
    to: "a@b.com", from: "c@d.com", subject: "Hi", text: "body line",
  }).then(function (r) {
    check("console transport returns deliveredAt",   typeof r.deliveredAt === "number");
    check("console transport stream got the body",
          stream.written.indexOf("body line") !== -1 &&
          stream.written.indexOf("c@d.com") !== -1);
  });
}

function testMailCreateValidation() {
  var threw = null;
  try { b.mail.create({ transport: { wrong: "shape" } }); }
  catch (e) { threw = e; }
  check("create rejects transport without .send",    threw && threw.code === "mail/bad-transport");

  threw = null;
  try { b.mail.create({ transport: 42 }); }
  catch (e) { threw = e; }
  check("create rejects non-function/non-object transport", threw && threw.code === "mail/bad-transport");
}

function testMailSurface() {
  check("b.mail namespace present",                  typeof b.mail === "object");
  check("b.mail.create is a function",               typeof b.mail.create === "function");
  check("b.mail.MailError is a class",               typeof b.mail.MailError === "function");
  check("b.mail.transports.console is a function",   typeof b.mail.transports.console === "function");
  check("b.mail.transports.memory is a function",    typeof b.mail.transports.memory === "function");
  check("b.mail.transports.smtp is a function",      typeof b.mail.transports.smtp === "function");
  check("b.mail.transports.http is a function",      typeof b.mail.transports.http === "function");
  check("b.mail.transports.resend is a function",    typeof b.mail.transports.resend === "function");
}

function testMailHttpFactoryValidation() {
  var threw = null;
  try { b.mail.transports.http(); }
  catch (e) { threw = e; }
  check("http factory rejects missing endpoint",
        threw && threw.code === "mail/http-misconfigured" && threw.isMailError === true);

  threw = null;
  try { b.mail.transports.http({ endpoint: "https://x" }); }
  catch (e) { threw = e; }
  check("http factory rejects missing serialize",
        threw && threw.code === "mail/http-misconfigured");

  var t = b.mail.transports.http({
    endpoint:  "https://example.test/mail",
    name:      "postmark",
    serialize: function () { return { body: "{}" }; },
  });
  check("http factory honors custom name",            t && t.name === "postmark");
  check("http factory returns send",                  typeof t.send === "function");

  // Default name is "http" when not supplied
  var t2 = b.mail.transports.http({
    endpoint:  "https://example.test/",
    serialize: function () { return { body: "{}" }; },
  });
  check("http factory defaults name to http",         t2 && t2.name === "http");
}

async function testMailHttpRoundTripWithCustomVendor() {
  // Simulate a "Postmark-style" API: header X-Server-Token, body
  // {From,To,Subject,HtmlBody,TextBody}, response {MessageID,ErrorCode}.
  // Verifies that the generic http transport can drive any vendor that
  // speaks JSON-over-HTTP without needing a framework-level preset.
  var http = require("http");
  var seen = null;
  var server = http.createServer(function (req, res) {
    var chunks = [];
    req.on("data", function (c) { chunks.push(c); });
    req.on("end", function () {
      seen = {
        method:  req.method,
        url:     req.url,
        headers: req.headers,
        body:    JSON.parse(Buffer.concat(chunks).toString("utf8")),
      };
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ MessageID: "pm_test_xyz", ErrorCode: 0 }));
    });
  });
  var port = await listenOnRandomPort(server);

  try {
    var transport = b.mail.transports.http({
      name:             "postmark",
      endpoint:         "http://127.0.0.1:" + port + "/email",
      timeoutMs:        2000,
      allowedProtocols: b.urlSafe.ALLOW_HTTP_ALL,
      headers: {
        "X-Postmark-Server-Token": "tok_test",
        "Content-Type":            "application/json",
        "Accept":                  "application/json",
      },
      serialize: function (message) {
        var payload = {
          From:     message.from,
          To:       Array.isArray(message.to) ? message.to.join(", ") : message.to,
          Subject:  message.subject,
          HtmlBody: message.html,
          TextBody: message.text,
        };
        return { body: JSON.stringify(payload) };
      },
      interpret: function (res) {
        var data = JSON.parse(res.body.toString("utf8"));
        if (data.ErrorCode !== 0) return { ok: false, reason: data.Message || ("err " + data.ErrorCode) };
        return { ok: true, id: data.MessageID };
      },
    });

    var result = await transport.send({
      from: "sender@test.local", to: "rcpt@test.local",
      subject: "Hi", html: "<p>Hi</p>", text: "Hi",
    });
    check("http transport happy path returns id from interpret",
          result && result.transport === "postmark" && result.id === "pm_test_xyz");
    check("http transport surfaces statusCode in result",
          result && result.statusCode === 200);
    check("http transport sent vendor-specific header",
          seen && seen.headers["x-postmark-server-token"] === "tok_test");
    check("http transport sent vendor-specific body shape",
          seen && seen.body.From === "sender@test.local" &&
          seen.body.HtmlBody === "<p>Hi</p>" && seen.body.TextBody === "Hi");
  } finally {
    await new Promise(function (resolve) { server.close(function () { resolve(); }); });
  }
}

async function testMailHttpInterpretRejection() {
  // interpret() returning {ok:false} surfaces as mail/<name>-rejected
  // with the vendor's reason in the message.
  var http = require("http");
  var server = http.createServer(function (_req, res) {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ ErrorCode: 422, Message: "Invalid recipient" }));
  });
  var port = await listenOnRandomPort(server);

  try {
    var transport = b.mail.transports.http({
      name:             "postmark",
      endpoint:         "http://127.0.0.1:" + port + "/",
      timeoutMs:        1500,
      allowedProtocols: b.urlSafe.ALLOW_HTTP_ALL,
      headers:   { "Content-Type": "application/json" },
      serialize: function () { return { body: "{}" }; },
      interpret: function (res) {
        var data = JSON.parse(res.body.toString("utf8"));
        if (data.ErrorCode !== 0) return { ok: false, reason: data.Message };
        return { ok: true, id: data.MessageID };
      },
    });
    var err = null;
    try { await transport.send({ from: "a@b.com", to: "c@d.com", subject: "S", text: "T" }); }
    catch (e) { err = e; }
    check("http interpret-rejection surfaces mail/<name>-rejected",
          err && err.code === "mail/postmark-rejected" && err.isMailError === true);
    check("http interpret-rejection includes vendor reason",
          err && /Invalid recipient/.test(err.message || ""));
  } finally {
    await new Promise(function (r) { server.close(function () { r(); }); });
  }
}

async function testMailHttpInterpretThrows() {
  // interpret() throwing a non-MailError surfaces as mail/<name>-interpret-failed.
  var http = require("http");
  var server = http.createServer(function (_req, res) {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end("not json at all");
  });
  var port = await listenOnRandomPort(server);

  try {
    var transport = b.mail.transports.http({
      name:             "vendor",
      endpoint:         "http://127.0.0.1:" + port + "/",
      timeoutMs:        1500,
      allowedProtocols: b.urlSafe.ALLOW_HTTP_ALL,
      headers:   { "Content-Type": "application/json" },
      serialize: function () { return { body: "{}" }; },
      interpret: function (res) { return { ok: !!JSON.parse(res.body.toString("utf8")).id }; },
    });
    var err = null;
    try { await transport.send({ from: "a@b.com", to: "c@d.com", subject: "S", text: "T" }); }
    catch (e) { err = e; }
    check("http interpret-throws surfaces mail/<name>-interpret-failed",
          err && err.code === "mail/vendor-interpret-failed" && err.isMailError === true);
  } finally {
    await new Promise(function (r) { server.close(function () { r(); }); });
  }
}

function testMailHttpBadSerializer() {
  // serialize() returning a non-object surfaces as mail/<name>-bad-serializer.
  // (Async — but we can test the synchronous validation path via the
  //  promise.) No network needed since the error happens before request.
  var transport = b.mail.transports.http({
    name:      "vendor",
    endpoint:  "https://example.test/",
    serialize: function () { return null; },
  });
  return transport.send({ from: "a@b.com", to: "c@d.com", subject: "S", text: "T" }).then(
    function () { check("http bad-serializer should reject", false); },
    function (err) {
      check("http bad-serializer returns mail/<name>-bad-serializer",
            err && err.code === "mail/vendor-bad-serializer" && err.isMailError === true);
    }
  );
}

function testMailSmtpFactoryValidation() {
  var threw = null;
  try { b.mail.transports.smtp(); }
  catch (e) { threw = e; }
  check("smtp factory rejects missing opts.host",
        threw && threw.code === "mail/smtp-misconfigured" && threw.isMailError === true);

  var t = b.mail.transports.smtp({ host: "smtp.example.com" });
  check("smtp factory returns a transport with name=smtp", t && t.name === "smtp");
  check("smtp factory returns a transport with .send",     typeof t.send === "function");
}

function testMailResendFactoryValidation() {
  var threw = null;
  try { b.mail.transports.resend(); }
  catch (e) { threw = e; }
  check("resend factory rejects missing apiKey",
        threw && threw.code === "mail/resend-misconfigured" && threw.isMailError === true);

  threw = null;
  try { b.mail.transports.resend({ apiKey: 42 }); }
  catch (e) { threw = e; }
  check("resend factory rejects non-string apiKey",
        threw && threw.code === "mail/resend-misconfigured");

  var t = b.mail.transports.resend({ apiKey: "re_test_xxx" });
  check("resend factory returns a transport with name=resend", t && t.name === "resend");
  check("resend factory returns a transport with .send",       typeof t.send === "function");
}

async function testMailSmtpRoundTrip() {
  // Stand up a fake SMTP server in-process and walk the protocol the
  // transport speaks. We don't exercise STARTTLS here — that path needs
  // a real cert. The auth-disabled branch (no opts.user) covers the
  // EHLO → MAIL FROM → RCPT TO → DATA path including dot-stuffing.
  var net = require("net");
  var lines = [];
  var dataBuf = "";
  var inData = false;
  var server = net.createServer(function (sock) {
    sock.setEncoding("utf8");
    sock.write("220 fake.local ESMTP\r\n");
    sock.on("data", function (chunk) {
      if (inData) {
        dataBuf += chunk;
        var endIdx = dataBuf.indexOf("\r\n.\r\n");
        if (endIdx !== -1) {
          inData = false;
          dataBuf = dataBuf.slice(0, endIdx);
          sock.write("250 OK queued\r\n");
        }
        return;
      }
      var parts = chunk.split("\r\n");
      for (var i = 0; i < parts.length; i++) {
        var line = parts[i];
        if (!line) continue;
        lines.push(line);
        var u = line.toUpperCase();
        if (u.indexOf("EHLO") === 0)         sock.write("250-fake.local\r\n250 OK\r\n");
        else if (u.indexOf("MAIL FROM") === 0) sock.write("250 OK\r\n");
        else if (u.indexOf("RCPT TO") === 0)   sock.write("250 OK\r\n");
        else if (u === "DATA")               { inData = true; sock.write("354 send body\r\n"); }
        else if (u === "QUIT")               { sock.write("221 bye\r\n"); sock.end(); }
        else                                  sock.write("250 OK\r\n");
      }
    });
    sock.on("error", function () { /* ignore — client will report */ });
  });
  var port = await listenOnRandomPort(server);

  try {
    var transport = b.mail.transports.smtp({
      host:     "127.0.0.1",
      port:     port,
      ehloName: "test.local",
      // No user/pass → skips AUTH path, also skips STARTTLS since we
      // never advertise it; the transport sees a plain socket and goes
      // straight to MAIL FROM after EHLO. Implicit TLS off.
    });
    // The transport defaults to STARTTLS for non-465 ports — bypass by
    // forcing implicitTls=false AND skipping auth, which means the
    // transport flow expects STARTTLS. We need a different shape: tell
    // the transport this socket is already TLS by using port 465 +
    // implicitTls true... but that requires real TLS. The cleanest way
    // is to test via a custom plain-text override path. The transport's
    // current shape is: non-implicit always issues STARTTLS. Skip TLS
    // testing here — that needs cert plumbing — and instead verify that
    // the state machine refuses to send data when STARTTLS is rejected.
    var result = null;
    var err = null;
    try { result = await transport.send({
      from: "sender@test.local", to: "rcpt@test.local",
      subject: "S", text: "T",
    }); }
    catch (e) { err = e; }

    // Server doesn't advertise STARTTLS; client sends STARTTLS anyway
    // because the transport always issues it on cleartext ports. Server
    // replies "250 OK" (default branch above) — not 220. Transport
    // fails closed with starttls-rejected.
    check("smtp transport refuses to send cleartext when STARTTLS not honored",
          err && err.code === "mail/smtp-failed" &&
          /starttls-rejected/.test(err.message || ""));
    check("smtp state-machine wrote EHLO before failing",
          lines.indexOf("EHLO test.local") !== -1);
    check("smtp state-machine never sent MAIL FROM in cleartext",
          !lines.some(function (l) { return /^MAIL FROM/i.test(l); }));
  } finally {
    await new Promise(function (resolve) { server.close(function () { resolve(); }); });
  }
}

async function testMailSmtpStarttlsAccept() {
  // Verify the happy-path STARTTLS handshake reaches the upgrade step
  // without us needing a full TLS cert: server accepts STARTTLS with
  // 220, then client tries to upgrade and fails on the cert exchange.
  // What we're checking is that the transport DID issue STARTTLS and
  // attempt the upgrade — i.e. it doesn't leak plaintext credentials.
  var net = require("net");
  var lines = [];
  var server = net.createServer(function (sock) {
    sock.setEncoding("utf8");
    sock.write("220 fake.local ESMTP\r\n");
    sock.on("data", function (chunk) {
      var parts = chunk.split("\r\n");
      for (var i = 0; i < parts.length; i++) {
        var line = parts[i];
        if (!line) continue;
        lines.push(line);
        var u = line.toUpperCase();
        if (u.indexOf("EHLO") === 0)         sock.write("250-fake.local\r\n250-STARTTLS\r\n250 OK\r\n");
        else if (u === "STARTTLS")           {
          sock.write("220 ready for tls\r\n");
          // Don't actually complete TLS — just hang. Client will error
          // on TLS handshake or timeout.
          setTimeout(function () { try { sock.destroy(); } catch (_e) {} }, 50);
        }
      }
    });
    sock.on("error", function () { /* expected — TLS handshake will tear down */ });
  });
  var port = await listenOnRandomPort(server);

  try {
    var transport = b.mail.transports.smtp({
      host: "127.0.0.1", port: port, ehloName: "test.local",
      timeoutMs: 1000,
      // user/pass set so we'd attempt AUTH after upgrade — verifies
      // the AUTH credentials never reach the wire pre-TLS.
      user: "u", pass: "p",
    });
    var err = null;
    try {
      await transport.send({
        from: "sender@test.local", to: "rcpt@test.local",
        subject: "S", text: "T",
      });
    } catch (e) { err = e; }

    check("smtp transport issued STARTTLS",            lines.indexOf("STARTTLS") !== -1);
    check("smtp transport never sent AUTH LOGIN before TLS",
          !lines.some(function (l) { return /^AUTH LOGIN/i.test(l); }));
    check("smtp transport never base64-encoded credentials in cleartext",
          !lines.some(function (l) { return l === Buffer.from("u").toString("base64"); }));
    check("smtp transport surfaced a MailError for failed TLS upgrade",
          err && err.isMailError === true);
  } finally {
    await new Promise(function (resolve) { server.close(function () { resolve(); }); });
  }
}

async function testMailResendRoundTrip() {
  // Spin up a local HTTP server that pretends to be the Resend API.
  // The transport uses lib/http-client which is HTTPS-by-default; we
  // pass urlSafe.ALLOW_HTTP_ALL via opts.allowedProtocols so the
  // request reaches our cleartext fixture.
  var http = require("http");
  var seen = null;
  var server = http.createServer(function (req, res) {
    var chunks = [];
    req.on("data", function (c) { chunks.push(c); });
    req.on("end", function () {
      seen = {
        method:  req.method,
        url:     req.url,
        headers: req.headers,
        body:    JSON.parse(Buffer.concat(chunks).toString("utf8")),
      };
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ id: "rsnd_test_abc123" }));
    });
  });
  var port = await listenOnRandomPort(server);

  try {
    var transport = b.mail.transports.resend({
      apiKey:           "re_test_secret",
      endpoint:         "http://127.0.0.1:" + port + "/emails",
      timeoutMs:        2000,
      allowedProtocols: b.urlSafe.ALLOW_HTTP_ALL,
    });
    var result = await transport.send({
      from: "Sender <sender@test.local>",
      to: ["a@b.com", "c@d.com"],
      cc: "e@f.com",
      subject: "Hello",
      html: "<p>Hi</p>",
      text: "Hi",
      replyTo: "reply@test.local",
    });
    check("resend transport returns deliveredAt + id",
          result && result.transport === "resend" && result.id === "rsnd_test_abc123");
    check("resend transport sent POST",                seen && seen.method === "POST");
    check("resend transport set Authorization header",
          seen && seen.headers.authorization === "Bearer re_test_secret");
    check("resend transport sent content-type json",
          seen && /application\/json/.test(seen.headers["content-type"] || ""));
    check("resend transport mapped to as array",
          seen && Array.isArray(seen.body.to) && seen.body.to.length === 2);
    check("resend transport mapped cc as array",
          seen && Array.isArray(seen.body.cc) && seen.body.cc[0] === "e@f.com");
    check("resend transport mapped replyTo to reply_to (snake_case)",
          seen && seen.body.reply_to === "reply@test.local");
    check("resend transport forwarded subject + html + text",
          seen && seen.body.subject === "Hello" &&
          seen.body.html === "<p>Hi</p>" && seen.body.text === "Hi");
  } finally {
    await new Promise(function (resolve) { server.close(function () { resolve(); }); });
  }
}

async function testMailResendErrorPaths() {
  var http = require("http");

  // Case 1 — server returns 200 with non-JSON body
  var s1 = http.createServer(function (_req, res) {
    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end("not json");
  });
  var p1 = await listenOnRandomPort(s1);
  try {
    var t1 = b.mail.transports.resend({
      apiKey: "re_x", endpoint: "http://127.0.0.1:" + p1 + "/",
      allowedProtocols: b.urlSafe.ALLOW_HTTP_ALL, timeoutMs: 1500,
    });
    var err1 = null;
    try { await t1.send({ from: "a@b.com", to: "c@d.com", subject: "S", text: "T" }); }
    catch (e) { err1 = e; }
    check("resend non-JSON body surfaces mail/resend-bad-response",
          err1 && err1.code === "mail/resend-bad-response");
  } finally {
    await new Promise(function (r) { s1.close(function () { r(); }); });
  }

  // Case 2 — server returns 200 JSON with no `id`
  var s2 = http.createServer(function (_req, res) {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ message: "rate limited" }));
  });
  var p2 = await listenOnRandomPort(s2);
  try {
    var t2 = b.mail.transports.resend({
      apiKey: "re_x", endpoint: "http://127.0.0.1:" + p2 + "/",
      allowedProtocols: b.urlSafe.ALLOW_HTTP_ALL, timeoutMs: 1500,
    });
    var err2 = null;
    try { await t2.send({ from: "a@b.com", to: "c@d.com", subject: "S", text: "T" }); }
    catch (e) { err2 = e; }
    check("resend JSON without id surfaces mail/resend-rejected",
          err2 && err2.code === "mail/resend-rejected" &&
          /rate limited/.test(err2.message || ""));
  } finally {
    await new Promise(function (r) { s2.close(function () { r(); }); });
  }

  // Case 3 — server returns non-2xx
  var s3 = http.createServer(function (_req, res) {
    res.writeHead(401, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ message: "Invalid API key" }));
  });
  var p3 = await listenOnRandomPort(s3);
  try {
    var t3 = b.mail.transports.resend({
      apiKey: "re_x", endpoint: "http://127.0.0.1:" + p3 + "/",
      allowedProtocols: b.urlSafe.ALLOW_HTTP_ALL, timeoutMs: 1500,
    });
    var err3 = null;
    try { await t3.send({ from: "a@b.com", to: "c@d.com", subject: "S", text: "T" }); }
    catch (e) { err3 = e; }
    check("resend HTTP error wraps to mail/resend-failed",
          err3 && err3.code === "mail/resend-failed" && err3.isMailError === true);
    check("resend HTTP error preserves statusCode",
          err3 && err3.statusCode === 401);
  } finally {
    await new Promise(function (r) { s3.close(function () { r(); }); });
  }
}

// ---- deprecate ----
//
// Tests manipulate process.env.BLAMEJS_DEPRECATIONS and
// process.env.NODE_ENV directly, with cleanup in finally{} blocks so
// they don't leak across tests.

function _withEnv(overrides, fn) {
  var saved = {};
  var keys = Object.keys(overrides);
  for (var i = 0; i < keys.length; i++) {
    saved[keys[i]] = process.env[keys[i]];
    if (overrides[keys[i]] === null) delete process.env[keys[i]];
    else process.env[keys[i]] = overrides[keys[i]];
  }
  try { return fn(); }
  finally {
    for (var j = 0; j < keys.length; j++) {
      if (saved[keys[j]] === undefined) delete process.env[keys[j]];
      else process.env[keys[j]] = saved[keys[j]];
    }
  }
}

// Capture stderr writes during fn(), restore after.
function _captureStderr(fn) {
  var captured = [];
  var orig = process.stderr.write;
  process.stderr.write = function (chunk) {
    captured.push(typeof chunk === "string" ? chunk : chunk.toString());
    return true;
  };
  try { fn(); }
  finally { process.stderr.write = orig; }
  return captured.join("");
}

function testDeprecateSurface() {
  check("b.deprecate namespace present",          typeof b.deprecate === "object");
  check("warn is a function",                     typeof b.deprecate.warn === "function");
  check("wrap is a function",                     typeof b.deprecate.wrap === "function");
  check("alias is a function",                    typeof b.deprecate.alias === "function");
  check("list is a function",                     typeof b.deprecate.list === "function");
  check("reset is a function",                    typeof b.deprecate.reset === "function");
  check("getMode is a function",                  typeof b.deprecate.getMode === "function");
  check("DeprecationError is a class",            typeof b.deprecate.DeprecationError === "function");
}

function testDeprecateModeResolution() {
  _withEnv({ BLAMEJS_DEPRECATIONS: null, NODE_ENV: null }, function () {
    check("default (no env) → warn",                b.deprecate.getMode() === "warn");
  });
  _withEnv({ BLAMEJS_DEPRECATIONS: null, NODE_ENV: "production" }, function () {
    check("NODE_ENV=production → silent",            b.deprecate.getMode() === "silent");
  });
  _withEnv({ BLAMEJS_DEPRECATIONS: "warn", NODE_ENV: "production" }, function () {
    check("BLAMEJS_DEPRECATIONS overrides production", b.deprecate.getMode() === "warn");
  });
  _withEnv({ BLAMEJS_DEPRECATIONS: "ERROR" }, function () {
    check("env value case-insensitive",              b.deprecate.getMode() === "error");
  });
  _withEnv({ BLAMEJS_DEPRECATIONS: "garbage" }, function () {
    check("unrecognized env value falls back to default",
          b.deprecate.getMode() === "silent" || b.deprecate.getMode() === "warn");
  });
}

function testDeprecateWarnEmitsOnce() {
  b.deprecate.reset();
  _withEnv({ BLAMEJS_DEPRECATIONS: "warn" }, function () {
    var stderr = _captureStderr(function () {
      b.deprecate.warn("oldThing", {
        since: "0.2.0", removeIn: "0.4.0",
        message: "use newThing()",
      });
      b.deprecate.warn("oldThing", { since: "0.2.0", removeIn: "0.4.0" });
      b.deprecate.warn("oldThing", { since: "0.2.0", removeIn: "0.4.0" });
    });
    check("warn writes one line for repeated calls",
          (stderr.match(/blamejs:deprecated/g) || []).length === 1);
    check("warn line contains name",                  /oldThing/.test(stderr));
    check("warn line contains since",                  /since 0\.2\.0/.test(stderr));
    check("warn line contains removeIn",               /removed in 0\.4\.0/.test(stderr));
    check("warn line contains message",                /use newThing/.test(stderr));

    var listed = b.deprecate.list();
    check("list shows the deprecation",                listed.length === 1 && listed[0].name === "oldThing");
    check("list reports correct callCount",            listed[0].callCount === 3);
  });
}

function testDeprecateSilentMode() {
  b.deprecate.reset();
  _withEnv({ BLAMEJS_DEPRECATIONS: "silent" }, function () {
    var stderr = _captureStderr(function () {
      b.deprecate.warn("x", { since: "0.1.0", removeIn: "0.2.0" });
    });
    check("silent mode emits nothing on stderr",       stderr === "");
    // But list() still tracks the call
    check("silent mode still tracks call in list()",   b.deprecate.list().length === 1);
  });
}

function testDeprecateErrorMode() {
  b.deprecate.reset();
  _withEnv({ BLAMEJS_DEPRECATIONS: "error" }, function () {
    var threw = null;
    try { b.deprecate.warn("oldX", { since: "0.1.0", removeIn: "0.2.0" }); }
    catch (e) { threw = e; }
    check("error mode throws on first use",            threw && threw.code === "deprecate/used-in-error-mode");
    check("error mode error includes name",            threw && /oldX/.test(threw.message));
  });
}

function testDeprecateDifferentSinceProducesNewLine() {
  b.deprecate.reset();
  _withEnv({ BLAMEJS_DEPRECATIONS: "warn" }, function () {
    var stderr = _captureStderr(function () {
      b.deprecate.warn("x", { since: "0.1.0", removeIn: "0.3.0" });
      b.deprecate.warn("x", { since: "0.1.0", removeIn: "0.3.0" });    // dedup
      b.deprecate.warn("x", { since: "0.2.0", removeIn: "0.4.0" });    // new since
    });
    check("dedupe is per (name, since)",                (stderr.match(/blamejs:deprecated/g) || []).length === 2);
    check("list has two entries",                        b.deprecate.list().length === 2);
  });
}

function testDeprecateWarnArgValidation() {
  var threw;
  threw = null; try { b.deprecate.warn(); } catch (e) { threw = e; }
  check("warn rejects missing name",                   threw && threw.code === "deprecate/bad-name");

  threw = null; try { b.deprecate.warn("x"); } catch (e) { threw = e; }
  check("warn rejects missing opts",                   threw && threw.code === "deprecate/bad-opts");

  threw = null; try { b.deprecate.warn("x", { since: "0.1.0" }); } catch (e) { threw = e; }
  check("warn rejects missing removeIn",               threw && threw.code === "deprecate/bad-opts");

  threw = null; try { b.deprecate.warn("x", { removeIn: "0.2.0" }); } catch (e) { threw = e; }
  check("warn rejects missing since",                  threw && threw.code === "deprecate/bad-opts");
}

function testDeprecateWrap() {
  b.deprecate.reset();
  _withEnv({ BLAMEJS_DEPRECATIONS: "warn" }, function () {
    var calls = [];
    var newFn = function (a, b2) { calls.push([a, b2]); return a + b2; };
    var oldFn = b.deprecate.wrap(newFn, "oldFn", {
      since: "0.2.0", removeIn: "0.4.0", message: "renamed to newFn",
    });

    var stderr = _captureStderr(function () {
      var r1 = oldFn(1, 2);
      var r2 = oldFn(3, 4);
      check("wrap delegates return value",                r1 === 3 && r2 === 7);
      check("wrap delegates arguments",                   calls.length === 2 && calls[0][0] === 1 && calls[0][1] === 2);
    });
    check("wrap warns once for repeated calls",          (stderr.match(/blamejs:deprecated/g) || []).length === 1);
    check("wrap warning carries new name",               /renamed to newFn/.test(stderr));
  });
}

function testDeprecateWrapValidation() {
  var threw;
  threw = null; try { b.deprecate.wrap("not-a-function", "x", { since: "0.1.0", removeIn: "0.2.0" }); } catch (e) { threw = e; }
  check("wrap rejects non-function target",            threw && threw.code === "deprecate/bad-target");

  threw = null; try { b.deprecate.wrap(function () {}, "", { since: "0.1.0", removeIn: "0.2.0" }); } catch (e) { threw = e; }
  check("wrap rejects empty name",                     threw && threw.code === "deprecate/bad-name");
}

function testDeprecateAlias() {
  b.deprecate.reset();
  _withEnv({ BLAMEJS_DEPRECATIONS: "warn" }, function () {
    var target = { newKey: "value-via-new-key" };
    b.deprecate.alias(target, "oldKey", "newKey", {
      since: "0.2.0", removeIn: "0.4.0",
    });
    var stderr = _captureStderr(function () {
      var v = target.oldKey;
      check("alias get returns newKey value",            v === "value-via-new-key");
      // Setter writes through to newKey
      target.oldKey = "now-set-via-old";
      check("alias set writes through to newKey",        target.newKey === "now-set-via-old");
    });
    check("alias warning emitted on access",             /blamejs:deprecated/.test(stderr));
    check("alias message points to new key",             /'newKey' instead/.test(stderr));
  });
}

function testDeprecateListAndReset() {
  b.deprecate.reset();
  _withEnv({ BLAMEJS_DEPRECATIONS: "silent" }, function () {
    b.deprecate.warn("a", { since: "0.1.0", removeIn: "0.2.0" });
    b.deprecate.warn("a", { since: "0.1.0", removeIn: "0.2.0" });
    b.deprecate.warn("a", { since: "0.1.0", removeIn: "0.2.0" });
    b.deprecate.warn("b", { since: "0.1.0", removeIn: "0.2.0" });
    var listed = b.deprecate.list();
    check("list returns all unique deprecations",        listed.length === 2);
    check("list sorted by callCount desc",               listed[0].name === "a" && listed[0].callCount === 3 &&
                                                          listed[1].name === "b" && listed[1].callCount === 1);
    b.deprecate.reset();
    check("reset clears everything",                      b.deprecate.list().length === 0);
  });
}

// ---- restore + restore-rollback ----

function _restoreFixture() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-rs-"));
  var dataDir = path.join(dir, "data");
  var storageRoot = path.join(dir, "backups");
  var rollbackRoot = path.join(dir, "rollbacks");
  fs.mkdirSync(dataDir, { recursive: true });
  // Seed dataDir with the same files we'll back up
  fs.writeFileSync(path.join(dataDir, "db.enc"),     Buffer.from("ORIG-DB"));
  fs.writeFileSync(path.join(dataDir, "db.key.enc"), "vault:orig-dbkey");
  fs.writeFileSync(path.join(dataDir, "vault.key"),  '{"vault":"orig"}');
  return {
    root:         dir,
    dataDir:      dataDir,
    storageRoot:  storageRoot,
    rollbackRoot: rollbackRoot,
    cleanup: function () {
      try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) {}
    },
  };
}

function testRestoreRollbackSurface() {
  check("b.restoreRollback namespace present",   typeof b.restoreRollback === "object");
  check("swap is a function",                    typeof b.restoreRollback.swap === "function");
  check("rollback is a function",                typeof b.restoreRollback.rollback === "function");
  check("list is a function",                    typeof b.restoreRollback.list === "function");
  check("purge is a function",                   typeof b.restoreRollback.purge === "function");
  check("RestoreRollbackError is a class",       typeof b.restoreRollback.RestoreRollbackError === "function");
}

function testRestoreRollbackSwap() {
  var fx = _restoreFixture();
  try {
    // Build a staging dir
    var stagingDir = path.join(fx.root, "staging");
    fs.mkdirSync(stagingDir);
    fs.writeFileSync(path.join(stagingDir, "db.enc"), Buffer.from("NEW-DB"));

    var r = b.restoreRollback.swap({
      stagingDir:   stagingDir,
      dataDir:      fx.dataDir,
      rollbackRoot: fx.rollbackRoot,
      marker:       { bundleId: "test-bundle", reason: "test" },
    });
    check("swap returned a rollbackPath",         typeof r.rollbackPath === "string");
    check("dataDir was replaced by staging",
          fs.readFileSync(path.join(fx.dataDir, "db.enc")).toString() === "NEW-DB");
    check("dataDir does NOT have the original db.enc",
          fs.readFileSync(path.join(fx.dataDir, "db.enc")).toString() !== "ORIG-DB");
    check("rollback path holds the original dataDir",
          fs.readFileSync(path.join(r.rollbackPath, "db.enc")).toString() === "ORIG-DB");
    check("marker file written",                  fs.existsSync(r.markerPath));
    var marker = JSON.parse(fs.readFileSync(r.markerPath, "utf8"));
    check("marker carries bundleId + reason",
          marker.operator && marker.operator.bundleId === "test-bundle" &&
          marker.operator.reason === "test");
    check("staging dir consumed by swap",         !fs.existsSync(stagingDir));
  } finally { fx.cleanup(); }
}

async function testRestoreRollbackRoundTrip() {
  var fx = _restoreFixture();
  try {
    var stagingDir = path.join(fx.root, "staging");
    fs.mkdirSync(stagingDir);
    fs.writeFileSync(path.join(stagingDir, "db.enc"), Buffer.from("NEW-DB"));

    var r = b.restoreRollback.swap({
      stagingDir:   stagingDir,
      dataDir:      fx.dataDir,
      rollbackRoot: fx.rollbackRoot,
    });

    // Roll back — should restore the original dataDir
    var rb = await b.restoreRollback.rollback({
      dataDir:      fx.dataDir,
      rollbackPath: r.rollbackPath,
      rollbackRoot: fx.rollbackRoot,
    });
    check("rollback returns restoredFrom",         rb.restoredFrom === r.rollbackPath);
    check("rolled-back dataDir has original bytes",
          fs.readFileSync(path.join(fx.dataDir, "db.enc")).toString() === "ORIG-DB");
    check("rollback path is consumed (no longer at original location)",
          !fs.existsSync(r.rollbackPath));
    check("rollback removed marker file",          !fs.existsSync(r.markerPath));
  } finally { fx.cleanup(); }
}

function testRestoreRollbackListAndPurge() {
  var fx = _restoreFixture();
  try {
    // Create three rollback dirs by repeated swap+restore
    var ids = [];
    for (var i = 0; i < 3; i++) {
      var stagingDir = path.join(fx.root, "stg-" + i);
      fs.mkdirSync(stagingDir);
      fs.writeFileSync(path.join(stagingDir, "db.enc"), Buffer.from("NEW-" + i));
      var r = b.restoreRollback.swap({
        stagingDir:   stagingDir,
        dataDir:      fx.dataDir,
        rollbackRoot: fx.rollbackRoot,
      });
      ids.push(r.rollbackPath);
      // Yield enough time for unique ms timestamp
      var end = Date.now() + 5;
      while (Date.now() < end) { /* spin briefly */ }
    }
    var listed = b.restoreRollback.list({ rollbackRoot: fx.rollbackRoot });
    check("list returns 3 rollback points",        listed.length === 3);
    check("list newest first",                     listed[0].rollbackPath === ids[2]);

    // Purge keeping 1
    var purgeR = b.restoreRollback.purge({ rollbackRoot: fx.rollbackRoot, keep: 1 });
    check("purge kept 1 newest, deleted 2",        purgeR.deleted.length === 2);
    var listed2 = b.restoreRollback.list({ rollbackRoot: fx.rollbackRoot });
    check("only the newest remains",               listed2.length === 1 && listed2[0].rollbackPath === ids[2]);
  } finally { fx.cleanup(); }
}

function testRestoreRollbackHandlesEmptyDataDir() {
  // First-ever restore: dataDir doesn't exist yet → swap should still work
  var fx = _restoreFixture();
  try {
    fs.rmSync(fx.dataDir, { recursive: true, force: true });
    var stagingDir = path.join(fx.root, "stg");
    fs.mkdirSync(stagingDir);
    fs.writeFileSync(path.join(stagingDir, "db.enc"), "FIRST-DB");

    var r = b.restoreRollback.swap({
      stagingDir:   stagingDir,
      dataDir:      fx.dataDir,
      rollbackRoot: fx.rollbackRoot,
    });
    check("swap with no existing dataDir: rollbackPath null",
          r.rollbackPath === null);
    check("dataDir created from staging",          fs.existsSync(path.join(fx.dataDir, "db.enc")));
  } finally { fx.cleanup(); }
}

// --- restore (orchestrator) ---

async function _seedBundle(fx, passphrase) {
  var backup = b.backup.create({
    dataDir:    fx.dataDir,
    storage:    b.backup.localStorage({ root: fx.storageRoot }),
    passphrase: passphrase,
    files: [
      { relativePath: "db.enc",       kind: "raw",          required: true },
      { relativePath: "db.key.enc",   kind: "raw",          required: true },
      { relativePath: "vault.key",    kind: "raw",          required: false },
    ],
    vaultKeyJson: '{"vault":"orig"}',
    audit:        false,
  });
  var r = await backup.run();
  return r.bundleId;
}

function testRestoreSurface() {
  check("b.restore namespace present",            typeof b.restore === "object");
  check("b.restore.create is a function",         typeof b.restore.create === "function");
  check("RestoreError is a class",                typeof b.restore.RestoreError === "function");
}

function testRestoreCreateValidation() {
  var fx = _restoreFixture();
  try {
    var threw;
    threw = null; try { b.restore.create({}); } catch (e) { threw = e; }
    check("missing dataDir rejected",               threw && threw.code === "restore/no-datadir");

    threw = null;
    try { b.restore.create({ dataDir: fx.dataDir }); } catch (e) { threw = e; }
    check("missing storage rejected",               threw && threw.code === "restore/bad-storage");

    threw = null;
    try {
      b.restore.create({
        dataDir: fx.dataDir,
        storage: { listBundles: function () {} },   // missing methods
      });
    } catch (e) { threw = e; }
    check("incomplete storage rejected",            threw && threw.code === "restore/bad-storage");

    threw = null;
    try {
      b.restore.create({
        dataDir: fx.dataDir,
        storage: b.backup.localStorage({ root: fx.storageRoot }),
      });
    } catch (e) { threw = e; }
    check("missing passphrase rejected",            threw && threw.code === "restore/no-passphrase");
  } finally { fx.cleanup(); }
}

async function testRestoreRunRoundTrip() {
  var fx = _restoreFixture();
  try {
    var passphrase = Buffer.from("pp");
    var bundleId = await _seedBundle(fx, passphrase);

    // Mutate dataDir so we can prove restore actually replaced it
    fs.writeFileSync(path.join(fx.dataDir, "db.enc"), "MUTATED");

    var restore = b.restore.create({
      dataDir:      fx.dataDir,
      storage:      b.backup.localStorage({ root: fx.storageRoot }),
      passphrase:   passphrase,
      rollbackRoot: fx.rollbackRoot,
      audit:        false,
    });

    var r = await restore.run({ bundleId: bundleId, marker: { reason: "test" } });
    check("run returns bundleId",                    r.bundleId === bundleId);
    check("run reports fileCount",                   r.fileCount === 3);
    check("run reports rollbackPath",                typeof r.rollbackPath === "string");
    check("run returns vaultKeyJson",                r.vaultKeyJson === '{"vault":"orig"}');

    // dataDir was replaced — the bytes match the seeded ORIGINAL,
    // not the post-mutation MUTATED value
    check("dataDir restored to bundle bytes",
          fs.readFileSync(path.join(fx.dataDir, "db.enc")).toString() === "ORIG-DB");
    // Mutation was preserved in the rollback
    check("rollback holds the pre-restore (mutated) dataDir",
          fs.readFileSync(path.join(r.rollbackPath, "db.enc")).toString() === "MUTATED");

    // List + inspect work
    var listed = await restore.list();
    check("list shows the seeded bundle",            listed.some(function (e) { return e.bundleId === bundleId; }));
    var manifest = await restore.inspect(bundleId);
    check("inspect returns parsed manifest",         manifest && manifest.version === 1);
  } finally { fx.cleanup(); }
}

async function testRestoreRollbackUndoesRun() {
  var fx = _restoreFixture();
  try {
    var passphrase = Buffer.from("pp");
    var bundleId = await _seedBundle(fx, passphrase);
    fs.writeFileSync(path.join(fx.dataDir, "db.enc"), "MUTATED");

    var restore = b.restore.create({
      dataDir:      fx.dataDir,
      storage:      b.backup.localStorage({ root: fx.storageRoot }),
      passphrase:   passphrase,
      rollbackRoot: fx.rollbackRoot,
      audit:        false,
    });
    await restore.run({ bundleId: bundleId });

    // Roll back: dataDir should now hold the MUTATED bytes (the
    // pre-restore state we stashed in the rollback)
    await restore.rollback();
    check("rollback restored MUTATED dataDir",
          fs.readFileSync(path.join(fx.dataDir, "db.enc")).toString() === "MUTATED");
  } finally { fx.cleanup(); }
}

async function testRestoreRunWithMissingBundle() {
  var fx = _restoreFixture();
  try {
    fs.mkdirSync(fx.storageRoot);
    var restore = b.restore.create({
      dataDir:      fx.dataDir,
      storage:      b.backup.localStorage({ root: fx.storageRoot }),
      passphrase:   Buffer.from("pp"),
      rollbackRoot: fx.rollbackRoot,
      audit:        false,
    });
    var threw = null;
    try { await restore.run({ bundleId: "2026-04-27T00-00-00-000Z-aaaaaaaa" }); }
    catch (e) { threw = e; }
    check("missing bundle surfaces bundle-not-found",
          threw && threw.code === "restore/bundle-not-found");
  } finally { fx.cleanup(); }
}

async function testRestoreRunWithWrongPassphrase() {
  var fx = _restoreFixture();
  try {
    var bundleId = await _seedBundle(fx, Buffer.from("right"));
    var restore = b.restore.create({
      dataDir:      fx.dataDir,
      storage:      b.backup.localStorage({ root: fx.storageRoot }),
      passphrase:   Buffer.from("wrong"),
      rollbackRoot: fx.rollbackRoot,
      audit:        false,
    });
    var threw = null;
    try { await restore.run({ bundleId: bundleId }); } catch (e) { threw = e; }
    check("wrong passphrase surfaces decrypt-failed",
          threw && threw.code === "restore/decrypt-failed");
    // dataDir should remain untouched on failure
    check("failed restore did NOT replace dataDir",
          fs.readFileSync(path.join(fx.dataDir, "db.enc")).toString() === "ORIG-DB");
  } finally { fx.cleanup(); }
}

async function testRestoreListRollbacksAndPurge() {
  var fx = _restoreFixture();
  try {
    var passphrase = Buffer.from("pp");
    var bundleId = await _seedBundle(fx, passphrase);
    var restore = b.restore.create({
      dataDir:      fx.dataDir,
      storage:      b.backup.localStorage({ root: fx.storageRoot }),
      passphrase:   passphrase,
      rollbackRoot: fx.rollbackRoot,
      audit:        false,
    });
    // Two restores to create two rollback points
    await restore.run({ bundleId: bundleId });
    await new Promise(function (r) { setTimeout(r, 5); });
    await restore.run({ bundleId: bundleId });

    var rb = restore.listRollbacks();
    check("listRollbacks shows 2 entries",          rb.length === 2);

    var purged = restore.purgeRollbacks({ keep: 1 });
    check("purgeRollbacks deleted the older one",   purged.deleted.length === 1);
    check("only newest rollback remains",           restore.listRollbacks().length === 1);
  } finally { fx.cleanup(); }
}

async function testRestoreInspectWithoutDecrypt() {
  var fx = _restoreFixture();
  try {
    var bundleId = await _seedBundle(fx, Buffer.from("pp"));
    var restore = b.restore.create({
      dataDir:      fx.dataDir,
      storage:      b.backup.localStorage({ root: fx.storageRoot }),
      passphrase:   Buffer.from("any"),    // not used by inspect
      rollbackRoot: fx.rollbackRoot,
      audit:        false,
    });
    var manifest = await restore.inspect(bundleId);
    check("inspect surfaces manifest without decrypting",
          manifest.version === 1 && manifest.files.length === 3);

    var threw = null;
    try { await restore.inspect("2026-04-27T00-00-00-000Z-aaaaaaaa"); } catch (e) { threw = e; }
    check("inspect of missing bundle rejects",     threw && threw.code === "restore/bundle-not-found");
  } finally { fx.cleanup(); }
}

// ---- backup (orchestrator) ----

function _backupFixture() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-bk-"));
  var dataDir = path.join(dir, "data");
  var storageRoot = path.join(dir, "backups");
  fs.mkdirSync(dataDir, { recursive: true });
  // Seed a tiny dataDir
  fs.writeFileSync(path.join(dataDir, "db.enc"),     Buffer.from("ENCRYPTED-DB"));
  fs.writeFileSync(path.join(dataDir, "db.key.enc"), "vault:dbkey");
  fs.writeFileSync(path.join(dataDir, "vault.key"),  '{"vault":"keypair"}');
  return {
    root:        dir,
    dataDir:     dataDir,
    storageRoot: storageRoot,
    cleanup: function () {
      try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) {}
    },
  };
}

function _backupOpts(fx, override) {
  return Object.assign({
    dataDir:    fx.dataDir,
    storage:    b.backup.localStorage({ root: fx.storageRoot }),
    passphrase: Buffer.from("operator-passphrase"),
    files: [
      { relativePath: "db.enc",       kind: "raw",          required: true },
      { relativePath: "db.key.enc",   kind: "raw",          required: true },
      { relativePath: "vault.key",    kind: "raw",          required: false },
    ],
    vaultKeyJson: '{"vault":"keypair"}',
    audit:        false,
  }, override || {});
}

function testBackupSurface() {
  check("b.backup namespace present",             typeof b.backup === "object");
  check("b.backup.create is a function",          typeof b.backup.create === "function");
  check("b.backup.localStorage is a function",    typeof b.backup.localStorage === "function");
  check("b.backup.BUNDLE_ID_RE is a RegExp",      b.backup.BUNDLE_ID_RE instanceof RegExp);
  check("BackupError is a class",                 typeof b.backup.BackupError === "function");
}

function testBackupCreateValidation() {
  var fx = _backupFixture();
  try {
    var threw;
    threw = null; try { b.backup.create({}); } catch (e) { threw = e; }
    check("missing dataDir rejected",               threw && threw.code === "backup/no-datadir");

    threw = null;
    try { b.backup.create({ dataDir: fx.dataDir }); } catch (e) { threw = e; }
    check("missing storage rejected",               threw && threw.code === "backup/bad-storage");

    threw = null;
    try {
      b.backup.create({
        dataDir: fx.dataDir,
        storage: { writeBundle: function () {} },  // missing other methods
        passphrase: Buffer.from("p"),
        files: [{ relativePath: "x" }],
        vaultKeyJson: "{}",
      });
    } catch (e) { threw = e; }
    check("incomplete storage rejected",            threw && threw.code === "backup/bad-storage");

    threw = null;
    try {
      b.backup.create({
        dataDir: fx.dataDir,
        storage: b.backup.localStorage({ root: fx.storageRoot }),
        files: [{ relativePath: "x" }],
        vaultKeyJson: "{}",
      });
    } catch (e) { threw = e; }
    check("missing passphrase rejected",            threw && threw.code === "backup/no-passphrase");

    threw = null;
    try {
      b.backup.create({
        dataDir: fx.dataDir,
        storage: b.backup.localStorage({ root: fx.storageRoot }),
        passphrase: Buffer.from("p"),
        files: [],
        vaultKeyJson: "{}",
      });
    } catch (e) { threw = e; }
    check("empty files list rejected",              threw && threw.code === "backup/no-files");

    threw = null;
    try {
      b.backup.create({
        dataDir: fx.dataDir,
        storage: b.backup.localStorage({ root: fx.storageRoot }),
        passphrase: Buffer.from("p"),
        files: [{ relativePath: "x" }],
        // no vaultKeyJson
      });
    } catch (e) { threw = e; }
    check("missing vaultKeyJson rejected",          threw && threw.code === "backup/no-vault-key-json");
  } finally { fx.cleanup(); }
}

async function testBackupRunListReadDelete() {
  var fx = _backupFixture();
  try {
    var backup = b.backup.create(_backupOpts(fx));
    var r1 = await backup.run({ metadata: { reason: "first" } });
    check("run returns bundleId in framework format",
          b.backup.BUNDLE_ID_RE.test(r1.bundleId));
    check("run reports fileCount = 3",              r1.fileCount === 3);
    check("run reports bundleSize > 0",             r1.bundleSize > 0);
    check("run reports durationMs",                 typeof r1.durationMs === "number");

    // list
    var listed = await backup.list();
    check("list shows the new bundle",              listed.length === 1 && listed[0].bundleId === r1.bundleId);
    check("list entry has size + createdAt",        listed[0].size > 0 && typeof listed[0].createdAt === "string");

    // read pulls the bundle out without decrypting
    var pullDir = path.join(fx.root, "pull");
    await backup.read(r1.bundleId, pullDir);
    check("read pulls manifest.json",               fs.existsSync(path.join(pullDir, "manifest.json")));
    check("read pulls files/ subdir",               fs.existsSync(path.join(pullDir, "files")));

    // The pulled bundle is a real bundle: restore-bundle.extract
    // recovers it (end-to-end backup → storage → restore loop)
    var restoreDir = path.join(fx.root, "restored");
    var rr = await b.restoreBundle.extract({
      bundleDir:  pullDir,
      stagingDir: restoreDir,
      passphrase: Buffer.from("operator-passphrase"),
    });
    check("backup → restore round-trip recovers all 3 files",
          rr.fileCount === 3);
    check("restore recovered db.enc bytes",
          fs.readFileSync(path.join(restoreDir, "db.enc")).toString() === "ENCRYPTED-DB");

    // delete
    await backup.delete(r1.bundleId);
    var listed2 = await backup.list();
    check("delete removed the bundle",              listed2.length === 0);
  } finally { fx.cleanup(); }
}

async function testBackupVaultKeyJsonAsFunction() {
  var fx = _backupFixture();
  try {
    var calls = 0;
    var backup = b.backup.create(_backupOpts(fx, {
      vaultKeyJson: function () { calls++; return '{"from":"function"}'; },
    }));
    await backup.run();
    await backup.run();
    check("vaultKeyJson function called per run",   calls === 2);
  } finally { fx.cleanup(); }
}

async function testBackupVaultKeyJsonAsAsyncFunction() {
  var fx = _backupFixture();
  try {
    var backup = b.backup.create(_backupOpts(fx, {
      vaultKeyJson: async function () { return '{"async":"works"}'; },
    }));
    var r = await backup.run();
    check("async vaultKeyJson resolves",            typeof r.bundleId === "string");

    // Verify the async-resolved JSON ended up in the bundle
    var pullDir = path.join(fx.root, "pull-async");
    await backup.read(r.bundleId, pullDir);
    var rr = await b.restoreBundle.extract({
      bundleDir:  pullDir,
      stagingDir: path.join(fx.root, "restored-async"),
      passphrase: Buffer.from("operator-passphrase"),
    });
    check("async vaultKeyJson surfaced in restore", rr.vaultKeyJson === '{"async":"works"}');
  } finally { fx.cleanup(); }
}

async function testBackupRetentionPurgeOlder() {
  var fx = _backupFixture();
  try {
    var backup = b.backup.create(_backupOpts(fx));
    // Run 4 backups with small delay so timestamps differ
    var ids = [];
    for (var i = 0; i < 4; i++) {
      var r = await backup.run();
      ids.push(r.bundleId);
      await new Promise(function (rr) { setTimeout(rr, 5); });
    }
    var listed = await backup.list();
    check("4 bundles before purge",                 listed.length === 4);
    check("list returns newest first",              listed[0].bundleId === ids[3]);

    var purged = await backup.purgeOlder({ keep: 2 });
    check("purgeOlder kept 2 newest",               purged.kept === 2);
    check("purgeOlder deleted 2 oldest",            purged.deleted.length === 2);
    var afterList = await backup.list();
    check("list shows 2 remaining",                 afterList.length === 2);
    check("retained bundles are the 2 newest",
          afterList[0].bundleId === ids[3] && afterList[1].bundleId === ids[2]);
  } finally { fx.cleanup(); }
}

async function testBackupRetentionAutoSweepOnRun() {
  var fx = _backupFixture();
  try {
    var backup = b.backup.create(_backupOpts(fx, { retention: { keep: 2 } }));
    var ids = [];
    for (var i = 0; i < 4; i++) {
      var r = await backup.run();
      ids.push(r.bundleId);
      await new Promise(function (rr) { setTimeout(rr, 5); });
    }
    // After 4 runs with retention=2, only the 2 newest should remain
    var listed = await backup.list();
    check("retention auto-sweep keeps only 2",      listed.length === 2);
  } finally { fx.cleanup(); }
}

async function testBackupBundleIdValidation() {
  var fx = _backupFixture();
  try {
    var backup = b.backup.create(_backupOpts(fx));
    var threw;
    threw = null;
    try { await backup.delete("not-a-valid-id"); } catch (e) { threw = e; }
    check("delete rejects bad bundleId",            threw && threw.code === "backup/bad-bundle-id");

    threw = null;
    try { await backup.read("not-a-valid-id", path.join(fx.root, "x")); } catch (e) { threw = e; }
    check("read rejects bad bundleId",              threw && threw.code === "backup/bad-bundle-id");
  } finally { fx.cleanup(); }
}

async function testBackupLocalStorageRejectsExistingDest() {
  var fx = _backupFixture();
  try {
    var backup = b.backup.create(_backupOpts(fx));
    var r = await backup.run();
    var dest = path.join(fx.root, "exists-pre");
    fs.mkdirSync(dest);
    var threw = null;
    try { await backup.read(r.bundleId, dest); } catch (e) { threw = e; }
    check("read rejects existing destDir",          threw && threw.code === "backup/dest-exists");
  } finally { fx.cleanup(); }
}

// ---- restore-bundle ----
//
// Reuses _bundleFixture + builds an actual encrypted bundle via
// backupBundle.create, then restores it through restoreBundle.extract.
// This verifies the two halves of the round-trip in concert.

async function _buildSampleBundle(fx, passphrase, files) {
  var outDir = path.join(fx.root, "bundle-" + Math.random().toString(36).slice(2, 8));
  for (var i = 0; i < files.length; i++) {
    if (files[i].content !== undefined) fx.write(files[i].relativePath, files[i].content);
  }
  await b.backupBundle.create({
    dataDir:      fx.dataDir,
    outDir:       outDir,
    passphrase:   passphrase,
    vaultKeyJson: '{"vault":"sample-keypair"}',
    files:        files.filter(function (f) { return f.content !== undefined; }).map(function (f) {
      return { relativePath: f.relativePath, kind: f.kind || "raw", required: true };
    }),
  });
  return outDir;
}

function testRestoreBundleSurface() {
  check("b.restoreBundle namespace present",      typeof b.restoreBundle === "object");
  check("extract is a function",                  typeof b.restoreBundle.extract === "function");
  check("inspect is a function",                  typeof b.restoreBundle.inspect === "function");
  check("RestoreBundleError is a class",          typeof b.restoreBundle.RestoreBundleError === "function");
}

async function testRestoreBundleRoundTrip() {
  var fx = _bundleFixture();
  try {
    var passphrase = Buffer.from("operator-passphrase");
    var bundleDir = await _buildSampleBundle(fx, passphrase, [
      { relativePath: "db.enc",          content: Buffer.from("ENCRYPTED-DB"),  kind: "raw" },
      { relativePath: "db.key.enc",      content: "vault:wrapped",              kind: "raw" },
      { relativePath: "tls/privkey.pem", content: "PEM-BYTES",                  kind: "vault-sealed" },
    ]);
    var stagingDir = path.join(fx.root, "staging");
    var events = [];
    var r = await b.restoreBundle.extract({
      bundleDir:        bundleDir,
      stagingDir:       stagingDir,
      passphrase:       passphrase,
      progressCallback: function (e) { events.push(e.phase); },
    });
    check("extract.fileCount = 3",                  r.fileCount === 3);
    check("extract returned vaultKeyJson",          r.vaultKeyJson === '{"vault":"sample-keypair"}');
    check("staging has db.enc",                     fs.existsSync(path.join(stagingDir, "db.enc")));
    check("staging has db.key.enc",                 fs.existsSync(path.join(stagingDir, "db.key.enc")));
    check("staging recreated tls/ subdir",          fs.existsSync(path.join(stagingDir, "tls/privkey.pem")));
    check("restored db.enc matches original",
          fs.readFileSync(path.join(stagingDir, "db.enc")).toString() === "ENCRYPTED-DB");
    check("restored db.key.enc matches original",
          fs.readFileSync(path.join(stagingDir, "db.key.enc"), "utf8") === "vault:wrapped");
    check("restored tls/privkey.pem matches original",
          fs.readFileSync(path.join(stagingDir, "tls/privkey.pem"), "utf8") === "PEM-BYTES");
    check("progress phases include unwrap_vault_key + decrypt + done",
          events.indexOf("unwrap_vault_key") !== -1 &&
          events.indexOf("decrypt") !== -1 &&
          events.indexOf("done") !== -1);
  } finally { fx.cleanup(); }
}

async function testRestoreBundleFilterSubset() {
  var fx = _bundleFixture();
  try {
    var passphrase = Buffer.from("p");
    var bundleDir = await _buildSampleBundle(fx, passphrase, [
      { relativePath: "db.enc",          content: "DB" },
      { relativePath: "tls/privkey.pem", content: "PEM" },
    ]);
    var stagingDir = path.join(fx.root, "staging");
    var r = await b.restoreBundle.extract({
      bundleDir:  bundleDir,
      stagingDir: stagingDir,
      passphrase: passphrase,
      filter: function (entry) { return entry.relativePath === "db.enc"; },
    });
    check("filter restored only matching entries",   r.fileCount === 1);
    check("staging has db.enc",                       fs.existsSync(path.join(stagingDir, "db.enc")));
    check("staging does NOT have tls/privkey.pem",   !fs.existsSync(path.join(stagingDir, "tls/privkey.pem")));
    // Vault key still recovered even when filter rejects everything
    check("filter still recovers vaultKeyJson",      typeof r.vaultKeyJson === "string");
  } finally { fx.cleanup(); }
}

async function testRestoreBundleWrongPassphrase() {
  var fx = _bundleFixture();
  try {
    var p = Buffer.from("right");
    var bundleDir = await _buildSampleBundle(fx, p, [
      { relativePath: "db.enc", content: "DB" },
    ]);
    var threw = null;
    try {
      await b.restoreBundle.extract({
        bundleDir:  bundleDir,
        stagingDir: path.join(fx.root, "staging-wrong"),
        passphrase: Buffer.from("wrong"),
      });
    } catch (e) { threw = e; }
    check("wrong passphrase surfaces decrypt-failed",
          threw && threw.code === "restore-bundle/decrypt-failed");
    check("staging dir cleaned up after failure",
          !fs.existsSync(path.join(fx.root, "staging-wrong")));
  } finally { fx.cleanup(); }
}

async function testRestoreBundleTamperedBlobDetected() {
  var fx = _bundleFixture();
  try {
    var p = Buffer.from("p");
    var bundleDir = await _buildSampleBundle(fx, p, [
      { relativePath: "db.enc", content: "DB-BYTES" },
    ]);
    // Locate the encrypted blob and flip a byte AFTER the nonce
    var blobPath = path.join(bundleDir, "files/db.enc.enc");
    var b2 = fs.readFileSync(blobPath);
    b2[b.backupCrypto.NONCE_BYTES + 1] ^= 0x01;
    fs.writeFileSync(blobPath, b2);

    var threw = null;
    try {
      await b.restoreBundle.extract({
        bundleDir:  bundleDir,
        stagingDir: path.join(fx.root, "staging-tamper"),
        passphrase: p,
      });
    } catch (e) { threw = e; }
    check("tampered blob surfaces decrypt-failed",  threw && threw.code === "restore-bundle/decrypt-failed");
  } finally { fx.cleanup(); }
}

async function testRestoreBundleChecksumMismatchDetected() {
  // Tampering with a blob fails the AEAD check first. To exercise the
  // checksum-mismatch path, we modify the manifest's declared checksum
  // for a blob whose contents are still intact — the post-decrypt
  // sha3 will then disagree with the manifest.
  var fx = _bundleFixture();
  try {
    var p = Buffer.from("p");
    var bundleDir = await _buildSampleBundle(fx, p, [
      { relativePath: "db.enc", content: "DB" },
    ]);
    var manifestPath = path.join(bundleDir, "manifest.json");
    var m = b.backupManifest.parse(fs.readFileSync(manifestPath, "utf8"));
    m.files[0].checksum = "0".repeat(128);   // wrong but valid-shape
    fs.writeFileSync(manifestPath, b.backupManifest.serialize(m));

    var threw = null;
    try {
      await b.restoreBundle.extract({
        bundleDir:  bundleDir,
        stagingDir: path.join(fx.root, "staging-checksum"),
        passphrase: p,
      });
    } catch (e) { threw = e; }
    check("checksum mismatch surfaces clearly",     threw && threw.code === "restore-bundle/checksum-mismatch");
    check("staging cleaned up after checksum failure",
          !fs.existsSync(path.join(fx.root, "staging-checksum")));
  } finally { fx.cleanup(); }
}

async function testRestoreBundleMissingBlobDetected() {
  var fx = _bundleFixture();
  try {
    var p = Buffer.from("p");
    var bundleDir = await _buildSampleBundle(fx, p, [
      { relativePath: "db.enc", content: "DB" },
    ]);
    // Delete the blob the manifest references
    fs.unlinkSync(path.join(bundleDir, "files/db.enc.enc"));

    var threw = null;
    try {
      await b.restoreBundle.extract({
        bundleDir:  bundleDir,
        stagingDir: path.join(fx.root, "staging-missing"),
        passphrase: p,
      });
    } catch (e) { threw = e; }
    check("missing blob surfaces missing-blob",     threw && threw.code === "restore-bundle/missing-blob");
  } finally { fx.cleanup(); }
}

async function testRestoreBundleEncryptedSizeMismatchDetected() {
  var fx = _bundleFixture();
  try {
    var p = Buffer.from("p");
    var bundleDir = await _buildSampleBundle(fx, p, [
      { relativePath: "db.enc", content: "DB" },
    ]);
    // Append junk bytes to the blob — encryptedSize will mismatch
    var blobPath = path.join(bundleDir, "files/db.enc.enc");
    fs.appendFileSync(blobPath, Buffer.from([0xAA, 0xBB]));

    var threw = null;
    try {
      await b.restoreBundle.extract({
        bundleDir:  bundleDir,
        stagingDir: path.join(fx.root, "staging-size"),
        passphrase: p,
      });
    } catch (e) { threw = e; }
    check("encryptedSize mismatch surfaces size-mismatch",
          threw && threw.code === "restore-bundle/size-mismatch");
  } finally { fx.cleanup(); }
}

function testRestoreBundleInspectReturnsManifest() {
  var fx = _bundleFixture();
  try {
    // Build a minimal valid bundle manually so inspect doesn't need the encrypt path
    var bundleDir = path.join(fx.root, "inspect-bundle");
    fs.mkdirSync(bundleDir);
    fs.mkdirSync(path.join(bundleDir, "files"));
    var m = b.backupManifest.create({
      vaultKeySalt: "11".repeat(32),
      vaultKeyEnc:  Buffer.from("x").toString("base64"),
      files: [{
        relativePath:  "db.enc",
        encryptedPath: "files/db.enc.enc",
        size:          10,
        encryptedSize: 50,
        checksum:      "a".repeat(128),
        salt:          "ff".repeat(32),
        kind:          "raw",
      }],
    });
    fs.writeFileSync(path.join(bundleDir, "manifest.json"), b.backupManifest.serialize(m));
    var inspected = b.restoreBundle.inspect({ bundleDir: bundleDir });
    check("inspect returns parsed manifest",        inspected && inspected.version === 1);
    check("inspect doesn't need passphrase",        inspected.files.length === 1);
  } finally { fx.cleanup(); }
}

async function testRestoreBundleArgValidation() {
  var fx = _bundleFixture();
  try {
    var threw;
    threw = null; try { await b.restoreBundle.extract({}); } catch (e) { threw = e; }
    check("missing bundleDir rejected",             threw && threw.code === "restore-bundle/no-bundle");

    threw = null;
    try { await b.restoreBundle.extract({ bundleDir: fx.root }); } catch (e) { threw = e; }
    check("missing stagingDir rejected",            threw && threw.code === "restore-bundle/no-staging");

    fs.mkdirSync(path.join(fx.root, "exists-stag"));
    threw = null;
    try {
      await b.restoreBundle.extract({
        bundleDir:  fx.root,
        stagingDir: path.join(fx.root, "exists-stag"),
        passphrase: Buffer.from("p"),
      });
    } catch (e) { threw = e; }
    check("existing stagingDir rejected",           threw && threw.code === "restore-bundle/staging-exists");

    threw = null;
    try {
      await b.restoreBundle.extract({
        bundleDir:  fx.root,
        stagingDir: path.join(fx.root, "fresh-stag"),
      });
    } catch (e) { threw = e; }
    check("missing passphrase rejected",            threw && threw.code === "restore-bundle/no-passphrase");

    threw = null;
    try {
      await b.restoreBundle.extract({
        bundleDir:  fx.dataDir,
        stagingDir: path.join(fx.root, "fresh-stag-2"),
        passphrase: Buffer.from("p"),
      });
    } catch (e) { threw = e; }
    check("bundleDir without manifest rejected",    threw && threw.code === "restore-bundle/missing-manifest");
  } finally { fx.cleanup(); }
}

// ---- backup-bundle ----
//
// End-to-end fixture: build a tmp dataDir with a few files, encrypt
// the bundle, verify each blob round-trips through backup-crypto.

function _bundleFixture() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-bundle-"));
  var dataDir = path.join(dir, "data");
  fs.mkdirSync(dataDir, { recursive: true });
  return {
    root:    dir,
    dataDir: dataDir,
    cleanup: function () {
      try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) {}
    },
    write: function (rel, content) {
      var full = path.join(dataDir, rel);
      fs.mkdirSync(path.dirname(full), { recursive: true });
      fs.writeFileSync(full, content);
      return full;
    },
  };
}

function testBackupBundleSurface() {
  check("b.backupBundle namespace present",       typeof b.backupBundle === "object");
  check("b.backupBundle.create is a function",    typeof b.backupBundle.create === "function");
  check("BackupBundleError is a class",           typeof b.backupBundle.BackupBundleError === "function");
}

async function testBackupBundleCreateEndToEnd() {
  var fx = _bundleFixture();
  try {
    fx.write("db.enc",        Buffer.from("ENCRYPTED-DB-BYTES"));
    fx.write("db.key.enc",    "vault:wrapped-db-key");
    fx.write("vault.key",     '{"keypair":"json"}');
    fx.write("tls/privkey.pem", "PEM-BYTES");

    var passphrase = Buffer.from("operator-passphrase");
    var vaultKeyJson = '{"vault":"keypair-bytes"}';
    var outDir = path.join(fx.root, "bundle");

    var events = [];
    var result = await b.backupBundle.create({
      dataDir:      fx.dataDir,
      outDir:       outDir,
      passphrase:   passphrase,
      vaultKeyJson: vaultKeyJson,
      files: [
        { relativePath: "db.enc",          kind: "raw",          required: true },
        { relativePath: "db.key.enc",      kind: "raw",          required: true },
        { relativePath: "vault.key",       kind: "raw",          required: false },
        { relativePath: "tls/privkey.pem", kind: "vault-sealed", required: false },
        { relativePath: "missing-optional",kind: "raw",          required: false },
      ],
      metadata:     { reason: "test-end-to-end" },
      progressCallback: function (e) { events.push(e.phase); },
    });

    check("result.fileCount = 4 (missing skipped)", result.fileCount === 4);
    check("result.manifestPath under outDir",
          result.manifestPath === path.join(outDir, "manifest.json"));
    check("manifest exists on disk",                fs.existsSync(result.manifestPath));
    check("progress fired wrap_vault_key + done",
          events.indexOf("wrap_vault_key") !== -1 && events.indexOf("done") !== -1);
    check("progress fired skip_missing for optional",
          events.indexOf("skip_missing") !== -1);

    // Manifest is parseable + structurally valid
    var raw = fs.readFileSync(result.manifestPath, "utf8");
    var m = b.backupManifest.parse(raw);
    check("emitted manifest is parse-valid",        m.version === 1);
    check("manifest has 4 file entries",            m.files.length === 4);
    check("manifest carries operator metadata",     m.metadata && m.metadata.reason === "test-end-to-end");

    // Vault key round-trip — decrypt with passphrase + bundled salt
    var vkBytes = await b.backupCrypto.decryptWithPassphrase(
      Buffer.from(m.vaultKeyEnc, "base64"), passphrase, m.vaultKeySalt);
    check("vaultKeyEnc decrypts to original JSON",  vkBytes.toString("utf8") === vaultKeyJson);

    // Each file's blob exists and decrypts to the original bytes
    // matching the manifest's plaintext checksum.
    for (var i = 0; i < m.files.length; i++) {
      var entry = m.files[i];
      var blobPath = path.join(outDir, entry.encryptedPath);
      check("blob exists for " + entry.relativePath,  fs.existsSync(blobPath));
      var blob = fs.readFileSync(blobPath);
      check("blob size matches manifest.encryptedSize for " + entry.relativePath,
            blob.length === entry.encryptedSize);
      var dec = await b.backupCrypto.decryptWithPassphrase(blob, passphrase, entry.salt);
      var origPath = path.join(fx.dataDir, entry.relativePath);
      var orig = fs.readFileSync(origPath);
      check("decrypted blob matches original plaintext for " + entry.relativePath,
            Buffer.compare(dec, orig) === 0);
      check("plaintext sha3-512 matches manifest checksum for " + entry.relativePath,
            b.backupCrypto.checksum(orig) === entry.checksum);
    }
  } finally { fx.cleanup(); }
}

async function testBackupBundlePathTraversalRejected() {
  var fx = _bundleFixture();
  try {
    var threw = null;
    try {
      await b.backupBundle.create({
        dataDir:      fx.dataDir,
        outDir:       path.join(fx.root, "bundle"),
        passphrase:   Buffer.from("p"),
        vaultKeyJson: "{}",
        files: [{ relativePath: "../escape", kind: "raw", required: true }],
      });
    } catch (e) { threw = e; }
    check("'..' in relativePath rejected",          threw && threw.code === "backup-bundle/bad-include");

    threw = null;
    try {
      await b.backupBundle.create({
        dataDir:      fx.dataDir,
        outDir:       path.join(fx.root, "bundle2"),
        passphrase:   Buffer.from("p"),
        vaultKeyJson: "{}",
        files: [{ relativePath: "/abs/path", kind: "raw", required: true }],
      });
    } catch (e) { threw = e; }
    check("absolute path in relativePath rejected", threw && threw.code === "backup-bundle/bad-include");
  } finally { fx.cleanup(); }
}

async function testBackupBundleRequiredMissing() {
  var fx = _bundleFixture();
  try {
    var threw = null;
    try {
      await b.backupBundle.create({
        dataDir:      fx.dataDir,
        outDir:       path.join(fx.root, "bundle"),
        passphrase:   Buffer.from("p"),
        vaultKeyJson: "{}",
        files: [{ relativePath: "not-here", kind: "raw", required: true }],
      });
    } catch (e) { threw = e; }
    check("missing required file surfaces missing-required",
          threw && threw.code === "backup-bundle/missing-required");
  } finally { fx.cleanup(); }
}

async function testBackupBundleEmptyBundleRejected() {
  var fx = _bundleFixture();
  try {
    // All entries optional and missing → no files written → reject
    var threw = null;
    try {
      await b.backupBundle.create({
        dataDir:      fx.dataDir,
        outDir:       path.join(fx.root, "bundle"),
        passphrase:   Buffer.from("p"),
        vaultKeyJson: "{}",
        files: [{ relativePath: "absent", kind: "raw", required: false }],
      });
    } catch (e) { threw = e; }
    check("empty bundle rejected",                  threw && threw.code === "backup-bundle/empty");
  } finally { fx.cleanup(); }
}

async function testBackupBundleArgValidation() {
  var fx = _bundleFixture();
  try {
    var threw;

    threw = null;
    try { await b.backupBundle.create({}); } catch (e) { threw = e; }
    check("missing dataDir rejected",               threw && threw.code === "backup-bundle/no-datadir");

    threw = null;
    try { await b.backupBundle.create({ dataDir: fx.dataDir }); } catch (e) { threw = e; }
    check("missing outDir rejected",                threw && threw.code === "backup-bundle/no-outdir");

    fs.mkdirSync(path.join(fx.root, "exists"));
    threw = null;
    try {
      await b.backupBundle.create({
        dataDir: fx.dataDir, outDir: path.join(fx.root, "exists"),
        passphrase: Buffer.from("p"), vaultKeyJson: "{}",
        files: [{ relativePath: "x" }],
      });
    } catch (e) { threw = e; }
    check("existing outDir rejected",               threw && threw.code === "backup-bundle/outdir-exists");

    threw = null;
    try {
      await b.backupBundle.create({
        dataDir: fx.dataDir, outDir: path.join(fx.root, "bundle"),
        vaultKeyJson: "{}", files: [{ relativePath: "x" }],
      });
    } catch (e) { threw = e; }
    check("missing passphrase rejected",            threw && threw.code === "backup-bundle/no-passphrase");

    threw = null;
    try {
      await b.backupBundle.create({
        dataDir: fx.dataDir, outDir: path.join(fx.root, "bundle2"),
        passphrase: Buffer.from("p"), files: [{ relativePath: "x" }],
      });
    } catch (e) { threw = e; }
    check("missing vaultKeyJson rejected",          threw && threw.code === "backup-bundle/no-vault-key-json");

    threw = null;
    try {
      await b.backupBundle.create({
        dataDir: fx.dataDir, outDir: path.join(fx.root, "bundle3"),
        passphrase: Buffer.from("p"), vaultKeyJson: "{}", files: [],
      });
    } catch (e) { threw = e; }
    check("empty files list rejected",              threw && threw.code === "backup-bundle/no-files");
  } finally { fx.cleanup(); }
}

// ---- backup-manifest ----

function _validFileEntry(over) {
  return Object.assign({
    relativePath:  "db.enc",
    encryptedPath: "files/db.enc.bin",
    size:          12345,
    encryptedSize: 12369,
    checksum:      "a".repeat(128),     // sha3-512 hex
    salt:          "ff".repeat(32),
    kind:          "raw",
  }, over || {});
}

function _validManifestArgs() {
  return {
    vaultKeySalt: "11".repeat(32),
    vaultKeyEnc:  Buffer.from("fakekey").toString("base64"),
    files:        [_validFileEntry()],
    metadata:     { reason: "test" },
  };
}

function testBackupManifestSurface() {
  check("b.backupManifest namespace present",     typeof b.backupManifest === "object");
  check("create is a function",                   typeof b.backupManifest.create === "function");
  check("validate is a function",                 typeof b.backupManifest.validate === "function");
  check("serialize is a function",                typeof b.backupManifest.serialize === "function");
  check("parse is a function",                    typeof b.backupManifest.parse === "function");
  check("FORMAT_VERSION = 1",                     b.backupManifest.FORMAT_VERSION === 1);
  check("FRAMEWORK_NAME = blamejs",               b.backupManifest.FRAMEWORK_NAME === "blamejs");
  check("VALID_KINDS includes raw/vault-sealed/plaintext",
        b.backupManifest.VALID_KINDS["raw"] === 1 &&
        b.backupManifest.VALID_KINDS["vault-sealed"] === 1 &&
        b.backupManifest.VALID_KINDS["plaintext"] === 1);
}

function testBackupManifestCreateAndSerialize() {
  var m = b.backupManifest.create(_validManifestArgs());
  check("create assigns version 1",               m.version === 1);
  check("create assigns framework=blamejs",       m.framework === "blamejs");
  check("create assigns frameworkVersion from constants",
        typeof m.frameworkVersion === "string" && m.frameworkVersion === b.constants.version);
  check("create assigns ISO createdAt",           /^\d{4}-\d{2}-\d{2}T/.test(m.createdAt));
  check("create copies metadata",                 m.metadata && m.metadata.reason === "test");
  check("create files length matches input",      m.files.length === 1);

  var s = b.backupManifest.serialize(m);
  check("serialize returns string",               typeof s === "string");
  check("serialize ends with newline",            s.charAt(s.length - 1) === "\n");
  // Round-trip via parse
  var parsed = b.backupManifest.parse(s);
  check("parse + serialize round-trips key fields",
        parsed.version === m.version &&
        parsed.framework === m.framework &&
        parsed.frameworkVersion === m.frameworkVersion &&
        parsed.files.length === 1 &&
        parsed.files[0].relativePath === "db.enc");
}

function testBackupManifestValidateRejectsBadFields() {
  var bad;

  // Missing version
  bad = _validManifestArgs();
  delete bad.vaultKeySalt;
  var threw = null;
  try { b.backupManifest.create(bad); } catch (e) { threw = e; }
  check("create without vaultKeySalt rejected",   threw && threw.code === "backup-manifest/invalid");

  // Bad checksum length
  var m = b.backupManifest.create(_validManifestArgs());
  m.files[0].checksum = "short";
  var v = b.backupManifest.validate(m);
  check("validate flags short checksum",          v.ok === false &&
        v.errors.some(function (e) { return /checksum/.test(e); }));

  // Path traversal
  m = b.backupManifest.create(_validManifestArgs());
  m.files[0].relativePath = "../escape";
  v = b.backupManifest.validate(m);
  check("validate flags '..' in relativePath",    v.ok === false &&
        v.errors.some(function (e) { return /relativePath/.test(e) && /\.\./.test(e); }));

  // Leading separator
  m = b.backupManifest.create(_validManifestArgs());
  m.files[0].relativePath = "/abs";
  v = b.backupManifest.validate(m);
  check("validate flags absolute relativePath",   v.ok === false);

  // Bad kind
  m = b.backupManifest.create(_validManifestArgs());
  m.files[0].kind = "wat";
  v = b.backupManifest.validate(m);
  check("validate flags unknown kind",            v.ok === false &&
        v.errors.some(function (e) { return /kind/.test(e); }));

  // Negative size
  m = b.backupManifest.create(_validManifestArgs());
  m.files[0].size = -1;
  v = b.backupManifest.validate(m);
  check("validate flags negative size",           v.ok === false);

  // Non-base64 vaultKeyEnc
  m = b.backupManifest.create(_validManifestArgs());
  m.vaultKeyEnc = "not base64 !@#$";
  v = b.backupManifest.validate(m);
  check("validate flags non-base64 vaultKeyEnc",  v.ok === false);

  // Bad ISO createdAt
  m = b.backupManifest.create(_validManifestArgs());
  m.createdAt = "yesterday";
  v = b.backupManifest.validate(m);
  check("validate flags non-ISO createdAt",       v.ok === false);

  // Wrong format version
  m = b.backupManifest.create(_validManifestArgs());
  m.version = 2;
  v = b.backupManifest.validate(m);
  check("validate flags wrong version",           v.ok === false);

  // Wrong framework name
  m = b.backupManifest.create(_validManifestArgs());
  m.framework = "elsewhere";
  v = b.backupManifest.validate(m);
  check("validate flags wrong framework name",    v.ok === false);
}

function testBackupManifestRejectsDuplicatePaths() {
  var args = _validManifestArgs();
  args.files = [
    _validFileEntry({ relativePath: "a", encryptedPath: "files/a.bin" }),
    _validFileEntry({ relativePath: "a", encryptedPath: "files/b.bin" }),
  ];
  var threw = null;
  try { b.backupManifest.create(args); } catch (e) { threw = e; }
  check("duplicate relativePath rejected",        threw && /duplicate/.test(threw.message));

  args.files = [
    _validFileEntry({ relativePath: "a", encryptedPath: "files/x.bin" }),
    _validFileEntry({ relativePath: "b", encryptedPath: "files/x.bin" }),
  ];
  threw = null;
  try { b.backupManifest.create(args); } catch (e) { threw = e; }
  check("duplicate encryptedPath rejected",       threw && /duplicate/.test(threw.message));
}

function testBackupManifestParseRejectsCorruption() {
  var threw;

  // Not JSON
  threw = null; try { b.backupManifest.parse("not json"); } catch (e) { threw = e; }
  check("parse non-JSON rejects",                 threw && threw.code === "backup-manifest/bad-json");

  // Wrong type for argument
  threw = null; try { b.backupManifest.parse(42); } catch (e) { threw = e; }
  check("parse non-string non-Buffer rejects",    threw && threw.code === "backup-manifest/bad-input");

  // Valid JSON but wrong shape
  threw = null;
  try { b.backupManifest.parse(JSON.stringify({ random: "garbage" })); }
  catch (e) { threw = e; }
  check("parse valid-JSON-but-wrong-shape rejects", threw && threw.code === "backup-manifest/invalid");

  // Buffer input also accepted
  var ok = b.backupManifest.parse(Buffer.from(b.backupManifest.serialize(b.backupManifest.create(_validManifestArgs()))));
  check("parse accepts Buffer input",             ok && ok.version === 1);
}

function testBackupManifestSerializeIsCanonical() {
  // Same logical manifest serializes to the same bytes regardless of
  // how the input object was assembled (key insertion order).
  var m1 = b.backupManifest.create(_validManifestArgs());
  // Build a manifest with the same values via direct assignment in
  // different key order, then validate + serialize via the public API.
  var m2 = {
    metadata:         { reason: "test" },
    files:            [_validFileEntry()],
    createdAt:        m1.createdAt,
    vaultKeyEnc:      m1.vaultKeyEnc,
    vaultKeySalt:     m1.vaultKeySalt,
    frameworkVersion: m1.frameworkVersion,
    framework:        "blamejs",
    version:          1,
  };
  check("serialize is order-independent",         b.backupManifest.serialize(m1) === b.backupManifest.serialize(m2));
}

// ---- backup-crypto ----

function testBackupCryptoSurface() {
  check("b.backupCrypto namespace present",       typeof b.backupCrypto === "object");
  check("deriveKey is a function",                typeof b.backupCrypto.deriveKey === "function");
  check("encryptWithPassphrase is a function",    typeof b.backupCrypto.encryptWithPassphrase === "function");
  check("decryptWithPassphrase is a function",    typeof b.backupCrypto.decryptWithPassphrase === "function");
  check("encryptWithFreshSalt is a function",     typeof b.backupCrypto.encryptWithFreshSalt === "function");
  check("checksum is a function",                 typeof b.backupCrypto.checksum === "function");
  check("BackupCryptoError is a class",           typeof b.backupCrypto.BackupCryptoError === "function");
  check("ARGON2_OPTS is frozen with type=2 (argon2id)",
        b.backupCrypto.ARGON2_OPTS.type === 2 &&
        Object.isFrozen(b.backupCrypto.ARGON2_OPTS));
  check("SALT_BYTES is 32",                       b.backupCrypto.SALT_BYTES === 32);
  check("NONCE_BYTES is 24",                      b.backupCrypto.NONCE_BYTES === 24);
}

async function testBackupCryptoDeriveKeyDeterministic() {
  // Same passphrase + same salt → same key (across calls).
  // Use a small salt for speed; argon2 with default opts is slow.
  var salt = "0011223344556677889900112233445566778899001122334455667788990011";
  var k1 = await b.backupCrypto.deriveKey(Buffer.from("hunter2"), salt);
  var k2 = await b.backupCrypto.deriveKey(Buffer.from("hunter2"), salt);
  check("deriveKey deterministic across calls",   Buffer.compare(k1, k2) === 0);
  check("deriveKey produces 32-byte key",         k1.length === 32);

  // Different passphrase → different key
  var k3 = await b.backupCrypto.deriveKey(Buffer.from("different"), salt);
  check("deriveKey differs on different passphrase", Buffer.compare(k1, k3) !== 0);
}

async function testBackupCryptoRoundTrip() {
  var salt = "ff".repeat(32);
  var passphrase = Buffer.from("correct horse battery staple");
  var plain = Buffer.from("the secret data");
  var enc = await b.backupCrypto.encryptWithPassphrase(plain, passphrase, salt);
  check("encrypted length = nonce + ciphertext + 16-byte tag",
        enc.length === b.backupCrypto.NONCE_BYTES + plain.length + 16);
  var dec = await b.backupCrypto.decryptWithPassphrase(enc, passphrase, salt);
  check("decrypt round-trip recovers plaintext bytes",
        Buffer.compare(dec, plain) === 0);
}

async function testBackupCryptoStringPlaintext() {
  // String plaintext should be UTF-8 encoded
  var salt = "aa".repeat(32);
  var passphrase = Buffer.from("p");
  var enc = await b.backupCrypto.encryptWithPassphrase("hello — utf8 ñ", passphrase, salt);
  var dec = await b.backupCrypto.decryptWithPassphrase(enc, passphrase, salt);
  check("string plaintext round-trips as utf8",
        dec.toString("utf8") === "hello — utf8 ñ");
}

async function testBackupCryptoWrongPassphraseFails() {
  var salt = "11".repeat(32);
  var enc = await b.backupCrypto.encryptWithPassphrase(
    Buffer.from("data"), Buffer.from("right"), salt);
  var threw = null;
  try {
    await b.backupCrypto.decryptWithPassphrase(enc, Buffer.from("wrong"), salt);
  } catch (e) { threw = e; }
  check("wrong passphrase surfaces decrypt-failed",
        threw && threw.code === "backup-crypto/decrypt-failed");
}

async function testBackupCryptoTamperedCiphertextFails() {
  var salt = "22".repeat(32);
  var enc = await b.backupCrypto.encryptWithPassphrase(
    Buffer.from("data"), Buffer.from("p"), salt);
  // Flip one byte after the nonce
  var tampered = Buffer.from(enc);
  tampered[b.backupCrypto.NONCE_BYTES + 2] ^= 0x01;
  var threw = null;
  try { await b.backupCrypto.decryptWithPassphrase(tampered, Buffer.from("p"), salt); }
  catch (e) { threw = e; }
  check("tampered ciphertext surfaces decrypt-failed",
        threw && threw.code === "backup-crypto/decrypt-failed");
}

async function testBackupCryptoFreshSaltUnique() {
  // Two encryptWithFreshSalt calls produce DIFFERENT salts and
  // DIFFERENT ciphertexts even with identical plaintext + passphrase.
  var p = Buffer.from("p");
  var r1 = await b.backupCrypto.encryptWithFreshSalt("x", p);
  var r2 = await b.backupCrypto.encryptWithFreshSalt("x", p);
  check("encryptWithFreshSalt: salts unique across calls",
        r1.salt !== r2.salt);
  check("encryptWithFreshSalt: ciphertexts unique across calls",
        Buffer.compare(r1.encrypted, r2.encrypted) !== 0);
  check("encryptWithFreshSalt: salt is 64 hex chars (32 bytes)",
        r1.salt.length === 64 && /^[0-9a-f]{64}$/.test(r1.salt));

  // Round-trip via the bundled salt
  var dec = await b.backupCrypto.decryptWithPassphrase(r1.encrypted, p, r1.salt);
  check("encryptWithFreshSalt + decrypt with bundled salt round-trips",
        dec.toString("utf8") === "x");
}

function testBackupCryptoChecksumIsSha3_512() {
  // SHA3-512 of "abc" is a known test vector (FIPS 202 Appendix B):
  // "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e
  //  10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
  var v = b.backupCrypto.checksum("abc");
  check("checksum('abc') matches SHA3-512 test vector",
        v === "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0");

  // Buffer input also accepted
  var v2 = b.backupCrypto.checksum(Buffer.from("abc"));
  check("checksum accepts Buffer input",          v2 === v);

  var threw = null;
  try { b.backupCrypto.checksum(123); } catch (e) { threw = e; }
  check("checksum rejects non-Buffer/non-string", threw && threw.code === "backup-crypto/bad-input");
}

async function testBackupCryptoArgValidation() {
  var threw;
  threw = null; try { await b.backupCrypto.deriveKey("p", "not-hex"); } catch (e) { threw = e; }
  check("deriveKey rejects non-hex salt",         threw && threw.code === "backup-crypto/bad-salt");

  threw = null; try { await b.backupCrypto.deriveKey("p", "abc"); } catch (e) { threw = e; }
  check("deriveKey rejects odd-length hex salt",  threw && threw.code === "backup-crypto/bad-salt");

  threw = null; try { await b.backupCrypto.deriveKey("", "ab"); } catch (e) { threw = e; }
  check("deriveKey rejects empty passphrase",     threw && threw.code === "backup-crypto/bad-passphrase");

  threw = null; try { await b.backupCrypto.encryptWithPassphrase(123, "p", "ab"); } catch (e) { threw = e; }
  check("encryptWithPassphrase rejects non-Buffer/non-string plaintext",
        threw && threw.code === "backup-crypto/bad-plaintext");

  threw = null; try { await b.backupCrypto.decryptWithPassphrase("not-a-buffer", "p", "ab"); } catch (e) { threw = e; }
  check("decryptWithPassphrase rejects non-Buffer encrypted arg",
        threw && threw.code === "backup-crypto/bad-input");

  // Encrypted buffer too short to contain nonce + tag
  threw = null;
  try {
    await b.backupCrypto.decryptWithPassphrase(
      Buffer.from([1,2,3]), Buffer.from("p"), "ab".repeat(16));
  } catch (e) { threw = e; }
  check("decryptWithPassphrase rejects short buffers",
        threw && threw.code === "backup-crypto/bad-input");
}

// ---- mtls-ca ----

function _mtlsCaFixture() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-mtlsca-"));
  return {
    dir: dir,
    cleanup: function () {
      try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) {}
    },
  };
}

// Mock vault for sealed-mode tests — round-trip via base64 plus a
// constant prefix marker. Honest enough for the file-handling tests
// since the real vault-seal format is opaque to mtls-ca anyway.
function _mockVault() {
  var prefix = "mockseal:";
  return {
    seal:   function (s) { return prefix + Buffer.from(s).toString("base64"); },
    unseal: function (s) {
      if (typeof s !== "string" || s.indexOf(prefix) !== 0) return null;
      return Buffer.from(s.substring(prefix.length), "base64").toString("utf8");
    },
  };
}

function testMtlsCaSurface() {
  check("b.mtlsCa namespace present",            typeof b.mtlsCa === "object");
  check("b.mtlsCa.create is a function",         typeof b.mtlsCa.create === "function");
  check("b.mtlsCa.parseGeneration is a function", typeof b.mtlsCa.parseGeneration === "function");
  check("b.mtlsCa.MtlsCaError is a class",       typeof b.mtlsCa.MtlsCaError === "function");
  check("DEFAULT_PATHS exposes ca.key/ca.crt names",
        b.mtlsCa.DEFAULT_PATHS.caKey === "ca.key" &&
        b.mtlsCa.DEFAULT_PATHS.caCert === "ca.crt");
}

function testMtlsCaCreateValidation() {
  var threw;
  threw = null; try { b.mtlsCa.create({}); } catch (e) { threw = e; }
  check("create rejects missing dataDir",         threw && threw.code === "mtls-ca/no-datadir");

  threw = null;
  try { b.mtlsCa.create({ dataDir: "/tmp/x", caKeySealedMode: "loud" }); } catch (e) { threw = e; }
  check("create rejects bad caKeySealedMode",     threw && threw.code === "mtls-ca/bad-mode");
}

function testMtlsCaParseGeneration() {
  check("parseGeneration empty → 0",              b.mtlsCa.parseGeneration("") === 0);
  check("parseGeneration null → 0",               b.mtlsCa.parseGeneration(null) === 0);
  check("parseGeneration non-PEM → 0",            b.mtlsCa.parseGeneration("not a cert") === 0);
  check("parseGeneration malformed PEM → 0",
        b.mtlsCa.parseGeneration("-----BEGIN CERTIFICATE-----\nINVALID\n-----END CERTIFICATE-----") === 0);
}

function testMtlsCaExistsAndStatusWhenAbsent() {
  var fx = _mtlsCaFixture();
  try {
    var ca = b.mtlsCa.create({ dataDir: fx.dir });
    check("keyExists false on empty dir",          ca.keyExists() === false);
    check("exists false on empty dir",             ca.exists() === false);
    var s = ca.status();
    check("status: exists=false",                  s.exists === false);
    check("status: generation=0",                  s.generation === 0);
    check("status: current=create's generation",   s.current === 1);
    check("status: isLegacy=false (no CA → no legacy concern)",
          s.isLegacy === false);
  } finally { fx.cleanup(); }
}

function testMtlsCaLoadFailures() {
  var fx = _mtlsCaFixture();
  try {
    var ca = b.mtlsCa.create({ dataDir: fx.dir });
    var threw;
    threw = null; try { ca.loadKey(); } catch (e) { threw = e; }
    check("loadKey on empty dir throws missing-key",
          threw && threw.code === "mtls-ca/missing-key");

    threw = null; try { ca.loadCert(); } catch (e) { threw = e; }
    check("loadCert on empty dir throws missing-cert",
          threw && threw.code === "mtls-ca/missing-cert");
  } finally { fx.cleanup(); }
}

function testMtlsCaCommitAndLoadPlaintext() {
  var fx = _mtlsCaFixture();
  try {
    var ca = b.mtlsCa.create({ dataDir: fx.dir, caKeySealedMode: "disabled" });
    var keyPem  = "-----BEGIN PRIVATE KEY-----\nFAKE-CA-KEY-BYTES\n-----END PRIVATE KEY-----\n";
    var certPem = "-----BEGIN CERTIFICATE-----\nFAKE-CA-CERT-BYTES\n-----END CERTIFICATE-----\n";

    var r = ca.commit({ caKeyPem: keyPem, caCertPem: certPem });
    check("commit returned keyPath ending in ca.key",  /ca\.key$/.test(r.keyPath));
    check("commit returned certPath ending in ca.crt", /ca\.crt$/.test(r.certPath));
    check("commit sealed=false in 'disabled' mode",     r.sealed === false);
    check("ca.key file exists post-commit",             fs.existsSync(path.join(fx.dir, "ca.key")));
    check("ca.crt file exists post-commit",             fs.existsSync(path.join(fx.dir, "ca.crt")));
    check("no .tmp files leftover",
          !fs.existsSync(path.join(fx.dir, "ca.key.tmp")) &&
          !fs.existsSync(path.join(fx.dir, "ca.crt.tmp")));

    var loadedKey  = ca.loadKey().toString("utf8");
    var loadedCert = ca.loadCert().toString("utf8");
    check("loadKey returns committed PEM",              loadedKey  === keyPem);
    check("loadCert returns committed PEM",             loadedCert === certPem);

    check("exists=true after commit",                   ca.exists() === true);
  } finally { fx.cleanup(); }
}

function testMtlsCaSealedRequiredMode() {
  var fx = _mtlsCaFixture();
  try {
    var v = _mockVault();
    var ca = b.mtlsCa.create({ dataDir: fx.dir, caKeySealedMode: "required", vault: v });
    var keyPem  = "-----BEGIN PRIVATE KEY-----\nSEALED-KEY\n-----END PRIVATE KEY-----\n";
    var certPem = "-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----\n";

    var r = ca.commit({ caKeyPem: keyPem, caCertPem: certPem });
    check("required mode: sealed=true",                r.sealed === true);
    check("required mode: keyPath ends in ca.key.sealed",
          /ca\.key\.sealed$/.test(r.keyPath));
    // Plaintext key file must NOT be created
    check("required mode: ca.key NOT written",
          !fs.existsSync(path.join(fx.dir, "ca.key")));
    check("required mode: ca.key.sealed written",
          fs.existsSync(path.join(fx.dir, "ca.key.sealed")));

    // Round-trip: loadKey unseals via vault
    var loaded = ca.loadKey().toString("utf8");
    check("required mode: loadKey returns unsealed PEM bytes", loaded === keyPem);

    // Without vault, sealed-required mode rejects
    var caNoVault = b.mtlsCa.create({ dataDir: fx.dir, caKeySealedMode: "required" });
    var threw = null;
    try { caNoVault.loadKey(); } catch (e) { threw = e; }
    check("required mode without vault: load throws no-vault",
          threw && threw.code === "mtls-ca/no-vault");
  } finally { fx.cleanup(); }
}

function testMtlsCaSealedDisabledRefusesSealedFile() {
  var fx = _mtlsCaFixture();
  try {
    // Pre-place a sealed file but caKeySealedMode='disabled'
    fs.writeFileSync(path.join(fx.dir, "ca.key.sealed"), "mockseal:abc");
    fs.writeFileSync(path.join(fx.dir, "ca.crt"), "cert");
    var ca = b.mtlsCa.create({ dataDir: fx.dir, caKeySealedMode: "disabled" });
    var threw = null;
    try { ca.loadKey(); } catch (e) { threw = e; }
    check("disabled mode: refuses to load with no plaintext key",
          threw && threw.code === "mtls-ca/plain-required");
  } finally { fx.cleanup(); }
}

function testMtlsCaSealedRequiredRefusesPlaintextFile() {
  var fx = _mtlsCaFixture();
  try {
    fs.writeFileSync(path.join(fx.dir, "ca.key"), "plain-key");
    fs.writeFileSync(path.join(fx.dir, "ca.crt"), "cert");
    var ca = b.mtlsCa.create({ dataDir: fx.dir, caKeySealedMode: "required", vault: _mockVault() });
    var threw = null;
    try { ca.loadKey(); } catch (e) { threw = e; }
    check("required mode: refuses to load when only plaintext present",
          threw && threw.code === "mtls-ca/sealed-required");
  } finally { fx.cleanup(); }
}

function testMtlsCaIssuanceRequiresEngine() {
  var fx = _mtlsCaFixture();
  try {
    var ca = b.mtlsCa.create({ dataDir: fx.dir });
    var threw;
    threw = null;
    ca.initCA().catch(function (e) { threw = e; }).then(function () {
      check("initCA without engine throws no-engine",
            threw && threw.code === "mtls-ca/no-engine");
    });
    return ca.initCA().then(
      function () { check("initCA without engine should have rejected", false); },
      function (e) {
        check("initCA without engine throws no-engine",
              e && e.code === "mtls-ca/no-engine" &&
              /vendored/.test(e.message));
      }
    );
  } finally { fx.cleanup(); }
}

async function testMtlsCaInitCaWithEngineGeneratesAndCommits() {
  var fx = _mtlsCaFixture();
  try {
    var generated = false;
    var engine = {
      generateCa: async function (opts) {
        generated = true;
        return {
          caCertPem: "-----BEGIN CERTIFICATE-----\nENGINE-CA-CERT-gen=" + opts.generation +
            "\n-----END CERTIFICATE-----\n",
          caKeyPem:  "-----BEGIN PRIVATE KEY-----\nENGINE-CA-KEY\n-----END PRIVATE KEY-----\n",
        };
      },
    };
    var ca = b.mtlsCa.create({ dataDir: fx.dir, generation: 2, engine: engine });
    var first = await ca.initCA();
    check("first initCA called engine.generateCa",      generated === true);
    check("first initCA returned engine output",        /ENGINE-CA-CERT-gen=2/.test(first.caCertPem));
    check("first initCA wrote ca.key",                  fs.existsSync(path.join(fx.dir, "ca.key")));
    check("first initCA wrote ca.crt",                  fs.existsSync(path.join(fx.dir, "ca.crt")));

    // Second call should NOT regenerate — existing CA is returned
    generated = false;
    var second = await ca.initCA();
    check("second initCA reused existing CA (no regen)", generated === false);
    check("second initCA returned same cert",            second.caCertPem === first.caCertPem);
  } finally { fx.cleanup(); }
}

async function testMtlsCaInitCaRejectsBadEngineOutput() {
  var fx = _mtlsCaFixture();
  try {
    var ca = b.mtlsCa.create({
      dataDir: fx.dir,
      engine: { generateCa: async function () { return { caCertPem: "ok" /* missing key */ }; } },
    });
    var threw = null;
    try { await ca.initCA(); } catch (e) { threw = e; }
    check("initCA rejects engine output missing caKeyPem",
          threw && threw.code === "mtls-ca/bad-engine-output");
  } finally { fx.cleanup(); }
}

async function testMtlsCaGenerateClientCertDelegates() {
  var fx = _mtlsCaFixture();
  try {
    var seenArgs = null;
    var engine = {
      generateCa: async function () {
        return {
          caCertPem: "-----BEGIN CERTIFICATE-----\nENGINE-CA\n-----END CERTIFICATE-----\n",
          caKeyPem:  "-----BEGIN PRIVATE KEY-----\nENGINE-KEY\n-----END PRIVATE KEY-----\n",
        };
      },
      signClientCert: async function (args) {
        seenArgs = args;
        return {
          cert:      "-----BEGIN CERTIFICATE-----\nCLIENT-CERT-cn=" + args.cn + "\n-----END CERTIFICATE-----\n",
          key:       "-----BEGIN PRIVATE KEY-----\nCLIENT-KEY\n-----END PRIVATE KEY-----\n",
          ca:        args.caCertPem,
          issuedAt:  "now", expiresAt: "later",
        };
      },
    };
    var ca = b.mtlsCa.create({ dataDir: fx.dir, engine: engine });
    var client = await ca.generateClientCert({ cn: "alice", validityDays: 90 });
    check("signClientCert called with cn forwarded",   seenArgs && seenArgs.cn === "alice");
    check("signClientCert received caCertPem",          /ENGINE-CA/.test(seenArgs.caCertPem));
    check("signClientCert received caKeyPem",           /ENGINE-KEY/.test(seenArgs.caKeyPem));
    check("client cert returned with cn embedded",      /cn=alice/.test(client.cert));
  } finally { fx.cleanup(); }
}

async function testMtlsCaGenerateClientP12Validation() {
  var fx = _mtlsCaFixture();
  try {
    var ca = b.mtlsCa.create({ dataDir: fx.dir, engine: { generateCa: async function () { return { caCertPem: "x", caKeyPem: "y" }; } } });
    var threw = null;
    try { await ca.generateClientP12({ cn: "alice" }); } catch (e) { threw = e; }
    check("generateClientP12 without password rejected",
          threw && threw.code === "mtls-ca/no-password");
  } finally { fx.cleanup(); }
}

// ---- vault-passphrase-ops ----
//
// Real on-disk fixtures because the primitive's whole job is filesystem
// hygiene (atomic rename + fsync + round-trip verify). Each test gets
// a fresh tmp dataDir.

function _passphraseOpsFixture() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-vps-"));
  return {
    dir: dir,
    cleanup: function () {
      try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) {}
    },
    writePlaintext: function (content) {
      fs.writeFileSync(path.join(dir, "vault.key"), content || JSON.stringify({ test: "keypair" }), { mode: 0o600 });
    },
  };
}

function testVaultPassphraseOpsSurface() {
  check("b.vaultPassphraseOps namespace present",  typeof b.vaultPassphraseOps === "object");
  check("preflightSealable is a function",         typeof b.vaultPassphraseOps.preflightSealable === "function");
  check("preflightUnsealable is a function",       typeof b.vaultPassphraseOps.preflightUnsealable === "function");
  check("seal is a function",                      typeof b.vaultPassphraseOps.seal === "function");
  check("unseal is a function",                    typeof b.vaultPassphraseOps.unseal === "function");
  check("rotate is a function",                    typeof b.vaultPassphraseOps.rotate === "function");
  check("VaultPassphraseError is a class",         typeof b.vaultPassphraseOps.VaultPassphraseError === "function");
}

function testVaultPassphraseOpsPreflightChecks() {
  var fx = _passphraseOpsFixture();
  try {
    // Sealable: needs plaintext present + sealed absent
    var pre1 = b.vaultPassphraseOps.preflightSealable({ dataDir: fx.dir });
    check("seal preflight without plaintext: not ok",
          pre1.ok === false && /nothing to seal/.test(pre1.reason));

    fx.writePlaintext();
    var pre2 = b.vaultPassphraseOps.preflightSealable({ dataDir: fx.dir });
    check("seal preflight with plaintext present: ok",  pre2.ok === true);

    // Unsealable: needs sealed present + plaintext absent
    var pre3 = b.vaultPassphraseOps.preflightUnsealable({ dataDir: fx.dir });
    check("unseal preflight without sealed: not ok",
          pre3.ok === false && /nothing to unseal/.test(pre3.reason));

    // Stale .tmp blocks both
    fs.writeFileSync(path.join(fx.dir, "vault.key.sealed.tmp"), "stale");
    var pre4 = b.vaultPassphraseOps.preflightSealable({ dataDir: fx.dir });
    check("stale sealed.tmp blocks seal preflight",
          pre4.ok === false && /stale/.test(pre4.reason));
  } finally { fx.cleanup(); }
}

async function testVaultPassphraseOpsSealUnsealRoundTrip() {
  var fx = _passphraseOpsFixture();
  try {
    var keypairJson = JSON.stringify({ test: "keypair", version: 1 });
    fx.writePlaintext(keypairJson);

    var passphrase = Buffer.from("correct horse battery staple", "utf8");
    var sealResult = await b.vaultPassphraseOps.seal({
      dataDir: fx.dir, passphrase: passphrase,
    });
    check("seal returns sealedPath",                 typeof sealResult.sealedPath === "string");
    check("seal: plaintext deleted by default",      sealResult.plaintextDeleted === true);
    check("seal: vault.key removed",                 !fs.existsSync(path.join(fx.dir, "vault.key")));
    check("seal: vault.key.sealed exists",           fs.existsSync(path.join(fx.dir, "vault.key.sealed")));
    check("seal: no .tmp leftover",                  !fs.existsSync(path.join(fx.dir, "vault.key.sealed.tmp")));

    var unsealResult = await b.vaultPassphraseOps.unseal({
      dataDir: fx.dir, passphrase: passphrase,
    });
    check("unseal returns plaintextPath",            typeof unsealResult.plaintextPath === "string");
    check("unseal: vault.key.sealed removed",        !fs.existsSync(path.join(fx.dir, "vault.key.sealed")));
    check("unseal: vault.key restored",              fs.existsSync(path.join(fx.dir, "vault.key")));

    var restored = fs.readFileSync(path.join(fx.dir, "vault.key"), "utf8");
    check("unseal: plaintext bytes match original", restored === keypairJson);
  } finally { fx.cleanup(); }
}

async function testVaultPassphraseOpsKeepPlaintext() {
  var fx = _passphraseOpsFixture();
  try {
    fx.writePlaintext("keep-me");
    var passphrase = Buffer.from("p", "utf8");
    var r = await b.vaultPassphraseOps.seal({
      dataDir: fx.dir, passphrase: passphrase, keepPlaintext: true,
    });
    check("seal keepPlaintext: returns plaintextDeleted=false",
          r.plaintextDeleted === false);
    check("seal keepPlaintext: plaintext still present",
          fs.existsSync(path.join(fx.dir, "vault.key")));
    check("seal keepPlaintext: sealed exists",
          fs.existsSync(path.join(fx.dir, "vault.key.sealed")));
  } finally { fx.cleanup(); }
}

async function testVaultPassphraseOpsWrongPassphraseRejected() {
  var fx = _passphraseOpsFixture();
  try {
    fx.writePlaintext("data");
    var p1 = Buffer.from("right", "utf8");
    var p2 = Buffer.from("wrong", "utf8");
    await b.vaultPassphraseOps.seal({ dataDir: fx.dir, passphrase: p1 });

    var threw = null;
    try { await b.vaultPassphraseOps.unseal({ dataDir: fx.dir, passphrase: p2 }); }
    catch (e) { threw = e; }
    check("unseal with wrong passphrase rejected",
          threw && threw.code === "vault-passphrase/passphrase-rejected");
    check("rejected unseal: vault.key.sealed unchanged",
          fs.existsSync(path.join(fx.dir, "vault.key.sealed")));
    check("rejected unseal: no plaintext leak",
          !fs.existsSync(path.join(fx.dir, "vault.key")));
  } finally { fx.cleanup(); }
}

async function testVaultPassphraseOpsRotate() {
  var fx = _passphraseOpsFixture();
  try {
    var content = "secret-keypair-bytes";
    fx.writePlaintext(content);
    var oldP = Buffer.from("old passphrase", "utf8");
    var newP = Buffer.from("new passphrase v2", "utf8");
    await b.vaultPassphraseOps.seal({ dataDir: fx.dir, passphrase: oldP });

    var rotResult = await b.vaultPassphraseOps.rotate({
      dataDir: fx.dir, oldPassphrase: oldP, newPassphrase: newP,
    });
    check("rotate returns sealedPath",               typeof rotResult.sealedPath === "string");

    // Old passphrase no longer unwraps
    var threwOld = null;
    try { await b.vaultPassphraseOps.unseal({ dataDir: fx.dir, passphrase: oldP }); }
    catch (e) { threwOld = e; }
    check("rotate: old passphrase rejected post-rotate",
          threwOld && threwOld.code === "vault-passphrase/passphrase-rejected");

    // New passphrase unwraps to original bytes
    var unseal = await b.vaultPassphraseOps.unseal({ dataDir: fx.dir, passphrase: newP });
    check("rotate: new passphrase unwraps to original bytes",
          fs.readFileSync(unseal.plaintextPath, "utf8") === content);
  } finally { fx.cleanup(); }
}

async function testVaultPassphraseOpsRotateRejectsBadOldPassphrase() {
  var fx = _passphraseOpsFixture();
  try {
    fx.writePlaintext("x");
    var p = Buffer.from("right", "utf8");
    await b.vaultPassphraseOps.seal({ dataDir: fx.dir, passphrase: p });

    var threw = null;
    try {
      await b.vaultPassphraseOps.rotate({
        dataDir: fx.dir,
        oldPassphrase: Buffer.from("wrong", "utf8"),
        newPassphrase: Buffer.from("new", "utf8"),
      });
    } catch (e) { threw = e; }
    check("rotate with wrong old passphrase rejected",
          threw && threw.code === "vault-passphrase/passphrase-rejected");
    check("rotate: sealed file unchanged after rejection",
          fs.existsSync(path.join(fx.dir, "vault.key.sealed")));
  } finally { fx.cleanup(); }
}

function testVaultPassphraseOpsArgValidation() {
  var threw;
  threw = null;
  try { b.vaultPassphraseOps.preflightSealable({}); }
  catch (e) { threw = e; }
  check("missing dataDir rejected",                threw && threw.code === "vault-passphrase/no-datadir");

  threw = null;
  try { b.vaultPassphraseOps.preflightSealable({ dataDir: "/nonexistent-blamejs" }); }
  catch (e) { threw = e; }
  check("nonexistent dataDir rejected",            threw && threw.code === "vault-passphrase/no-datadir");
}

async function testVaultPassphraseOpsRequiresBufferPassphrase() {
  var fx = _passphraseOpsFixture();
  try {
    fx.writePlaintext("x");
    var threw = null;
    try { await b.vaultPassphraseOps.seal({ dataDir: fx.dir, passphrase: "string-not-buffer" }); }
    catch (e) { threw = e; }
    check("string passphrase rejected (must be Buffer)",
          threw && threw.code === "vault-passphrase/no-passphrase");
  } finally { fx.cleanup(); }
}

// ---- vault-rotate (diagnostics) ----

function _vaultRotateFixture() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-vrot-"));
  var dbPath = path.join(dir, "test.db");
  var { DatabaseSync } = require("node:sqlite");
  var db = new DatabaseSync(dbPath);
  return {
    dir: dir,
    db:  db,
    cleanup: function () {
      try { db.close(); } catch (_e) {}
      try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) {}
      // Each test resets the field-crypto registry so they don't leak
      // table registrations into each other.
      b.fieldCrypto.clearForTest();
    },
  };
}

// Build a real vault keypair for verify() round-trip tests. cryptoLib
// is exposed via b.crypto.
function _genKeys() { return b.crypto.generateEncryptionKeyPair(); }

// Build a vault-prefixed value by encrypting plaintext with the
// supplied keypair. Avoids needing vault.init for tests.
function _seal(plaintext, keys) {
  return b.constants.VAULT_PREFIX + b.crypto.encrypt(plaintext, keys);
}

function testVaultRotateSurface() {
  check("b.vaultRotate namespace present",        typeof b.vaultRotate === "object");
  check("validateSchemaMatch is a function",      typeof b.vaultRotate.validateSchemaMatch === "function");
  check("formatValidationResult is a function",   typeof b.vaultRotate.formatValidationResult === "function");
  check("verify is a function",                   typeof b.vaultRotate.verify === "function");
  check("VaultRotateError is a class",            typeof b.vaultRotate.VaultRotateError === "function");
}

function testVaultRotateValidateSchemaCleanCase() {
  var fx = _vaultRotateFixture();
  try {
    fx.db.exec("CREATE TABLE users (_id TEXT PRIMARY KEY, email TEXT, emailHash TEXT, createdAt TEXT)");
    b.fieldCrypto.registerTable("users", {
      sealedFields:  ["email"],
      derivedHashes: { emailHash: { from: "email" } },
    });
    // Seed one row with a properly-sealed email
    var keys = _genKeys();
    fx.db.prepare("INSERT INTO users (_id, email, emailHash, createdAt) VALUES (?, ?, ?, ?)").run(
      "u-1", _seal("a@b.com", keys), "hash-of-email", new Date().toISOString());

    var r = b.vaultRotate.validateSchemaMatch(fx.db);
    check("clean schema: 0 errors",                 r.errors.length === 0);
    check("clean schema: 0 warnings",               r.warnings.length === 0);
    check("formatValidationResult: OK",
          /schema match: OK/.test(b.vaultRotate.formatValidationResult(r)));
  } finally { fx.cleanup(); }
}

function testVaultRotateValidateMissingTable() {
  var fx = _vaultRotateFixture();
  try {
    // Schema declares 'users' but live DB has no such table
    b.fieldCrypto.registerTable("users", { sealedFields: ["email"] });
    var r = b.vaultRotate.validateSchemaMatch(fx.db, { tables: ["users"] });
    check("missing table → warning",                r.warnings.length === 1);
    check("warning kind = table_missing",           r.warnings[0].kind === "table_missing");
    check("missing table is non-fatal (no errors)", r.errors.length === 0);
  } finally { fx.cleanup(); }
}

function testVaultRotateValidateSealedColMissing() {
  var fx = _vaultRotateFixture();
  try {
    // Live table has no 'phone' column even though schema declares it sealed
    fx.db.exec("CREATE TABLE users (_id TEXT PRIMARY KEY, email TEXT)");
    b.fieldCrypto.registerTable("users", { sealedFields: ["email", "phone"] });
    var r = b.vaultRotate.validateSchemaMatch(fx.db);
    var miss = r.warnings.find(function (w) { return w.kind === "sealed_col_missing"; });
    check("sealed-col-missing surfaces as warning", miss && miss.column === "phone");
    check("non-fatal: 0 errors",                    r.errors.length === 0);
  } finally { fx.cleanup(); }
}

function testVaultRotateValidateDriftDetection() {
  var fx = _vaultRotateFixture();
  try {
    // 'secret' is NOT declared sealed in schema, but rows have a vault-prefixed value
    fx.db.exec("CREATE TABLE rec (_id TEXT PRIMARY KEY, name TEXT, secret TEXT)");
    b.fieldCrypto.registerTable("rec", { sealedFields: ["name"] });

    var keys = _genKeys();
    fx.db.prepare("INSERT INTO rec (_id, name, secret) VALUES (?, ?, ?)").run(
      "r-1", _seal("Alice", keys), _seal("ssn-123-45-6789", keys));

    var r = b.vaultRotate.validateSchemaMatch(fx.db);
    var drift = r.errors.find(function (e) { return e.kind === "drift" && e.column === "secret"; });
    check("drift detected on undeclared sealed column",
          drift && drift.table === "rec" && drift.column === "secret");
    check("formatValidationResult marks rotation refused",
          /rotation refused/.test(b.vaultRotate.formatValidationResult(r)));
  } finally { fx.cleanup(); }
}

function testVaultRotateValidateInfraColumnsAllowlist() {
  var fx = _vaultRotateFixture();
  try {
    // 'audit_meta' is a framework column that legitimately holds vault-prefixed
    // values without being in sealedFields. Operator passes infraColumns.
    fx.db.exec("CREATE TABLE _blamejs_audit (_id TEXT PRIMARY KEY, audit_meta TEXT)");
    b.fieldCrypto.registerTable("_blamejs_audit", { sealedFields: [] });

    var keys = _genKeys();
    fx.db.prepare("INSERT INTO _blamejs_audit (_id, audit_meta) VALUES (?, ?)").run(
      "a-1", _seal("framework-internal", keys));

    var rNo = b.vaultRotate.validateSchemaMatch(fx.db);
    check("without infraColumns: drift error raised",
          rNo.errors.some(function (e) { return e.kind === "drift" && e.column === "audit_meta"; }));

    var rWith = b.vaultRotate.validateSchemaMatch(fx.db, { infraColumns: ["audit_meta"] });
    check("with infraColumns: drift error suppressed",
          !rWith.errors.some(function (e) { return e.kind === "drift" && e.column === "audit_meta"; }));
  } finally { fx.cleanup(); }
}

function testVaultRotateVerifyRoundTrip() {
  var fx = _vaultRotateFixture();
  try {
    var keys = _genKeys();
    fx.db.exec("CREATE TABLE users (_id TEXT PRIMARY KEY, email TEXT)");
    b.fieldCrypto.registerTable("users", { sealedFields: ["email"] });
    for (var i = 0; i < 10; i++) {
      fx.db.prepare("INSERT INTO users (_id, email) VALUES (?, ?)").run(
        "u-" + i, _seal("user" + i + "@b.com", keys));
    }
    var r = b.vaultRotate.verify({ keys: keys, db: fx.db });
    check("verify ok with correct keys",            r.ok === true);
    check("verify reports passed entries",          r.passed.length === 1 && r.passed[0].table === "users");
    check("verify shows sampled rows verified",     r.passed[0].verified === r.passed[0].sampled);
    check("verify: 0 failures",                      r.failures.length === 0);
  } finally { fx.cleanup(); }
}

function testVaultRotateVerifyDetectsTampering() {
  var fx = _vaultRotateFixture();
  try {
    var keys     = _genKeys();
    var wrongKeys = _genKeys();
    fx.db.exec("CREATE TABLE users (_id TEXT PRIMARY KEY, email TEXT)");
    b.fieldCrypto.registerTable("users", { sealedFields: ["email"] });
    for (var i = 0; i < 10; i++) {
      fx.db.prepare("INSERT INTO users (_id, email) VALUES (?, ?)").run(
        "u-" + i, _seal("user" + i + "@b.com", keys));
    }
    // Verifying with wrong keys → all rows fail to decrypt
    var r = b.vaultRotate.verify({ keys: wrongKeys, db: fx.db, sampleMin: 10 });
    check("verify with wrong keys: not ok",         r.ok === false);
    check("verify with wrong keys: failures recorded",
          r.failures.length > 0);
    check("verify failure rows include table+column+_id",
          r.failures[0].table === "users" && r.failures[0].column === "email" &&
          typeof r.failures[0]._id === "string");
  } finally { fx.cleanup(); }
}

function testVaultRotateVerifyRegressionWithOldKeys() {
  // Simulate a partial rotation: insert some rows under newKeys, others
  // still under oldKeys. Verify with newKeys + oldKeys passed should
  // record regressions for the unrotated rows.
  var fx = _vaultRotateFixture();
  try {
    var oldKeys = _genKeys();
    var newKeys = _genKeys();
    fx.db.exec("CREATE TABLE users (_id TEXT PRIMARY KEY, email TEXT)");
    b.fieldCrypto.registerTable("users", { sealedFields: ["email"] });

    // 5 unrotated rows — still encrypted with oldKeys
    for (var i = 0; i < 5; i++) {
      fx.db.prepare("INSERT INTO users (_id, email) VALUES (?, ?)").run(
        "old-" + i, _seal("user" + i + "@b.com", oldKeys));
    }
    // 5 rotated rows — encrypted with newKeys
    for (var j = 0; j < 5; j++) {
      fx.db.prepare("INSERT INTO users (_id, email) VALUES (?, ?)").run(
        "new-" + j, _seal("user-new" + j + "@b.com", newKeys));
    }
    var r = b.vaultRotate.verify({ keys: newKeys, db: fx.db, oldKeys: oldKeys, sampleMin: 10 });
    // The 5 old-rotation rows fail to decrypt with newKeys → failures
    check("partial rotation: failures recorded for unrotated rows",
          r.failures.length === 5);
    check("ok=false because failures present",      r.ok === false);
  } finally { fx.cleanup(); }
}

async function testVaultRotateRotateEndToEnd() {
  // Build a real on-disk dataDir layout that the rotate primitive
  // recognizes, run rotate(), then assert the staged copy reads back
  // under the new keys and the source dataDir is untouched.
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-vrot-rot-"));
  try {
    var dataDir   = path.join(dir, "data");
    var stagingDir = path.join(dir, "staging");
    fs.mkdirSync(dataDir, { recursive: true });

    var oldKeys = b.crypto.generateEncryptionKeyPair();
    var newKeys = b.crypto.generateEncryptionKeyPair();

    // 32-byte XChaCha20 key for the at-rest DB envelope
    var dbKey = b.crypto.generateBytes(32);

    // vault.key: plaintext JSON of the keypair (matches plaintext mode)
    fs.writeFileSync(path.join(dataDir, "vault.key"), JSON.stringify(oldKeys, null, 2));
    // db.key.enc: vault-sealed base64(dbKey)
    fs.writeFileSync(path.join(dataDir, "db.key.enc"),
      b.constants.VAULT_PREFIX + b.crypto.encrypt(dbKey.toString("base64"), oldKeys));

    // Build a small SQLite DB with sealed rows
    var { DatabaseSync } = require("node:sqlite");
    var plainDbPath = path.join(dir, "build.db");
    var bdb = new DatabaseSync(plainDbPath);
    bdb.exec("CREATE TABLE users (_id TEXT PRIMARY KEY, email TEXT, name TEXT)");
    var ins = bdb.prepare("INSERT INTO users (_id, email, name) VALUES (?, ?, ?)");
    for (var i = 0; i < 10; i++) {
      ins.run(
        "u-" + i,
        b.constants.VAULT_PREFIX + b.crypto.encrypt("user" + i + "@b.com", oldKeys),
        b.constants.VAULT_PREFIX + b.crypto.encrypt("Name " + i, oldKeys));
    }
    bdb.close();
    var plainBytes = fs.readFileSync(plainDbPath);
    fs.writeFileSync(path.join(dataDir, "db.enc"),
      b.crypto.encryptPacked(plainBytes, dbKey));

    // Register the schema before rotation so the rotator knows which columns are sealed
    b.fieldCrypto.clearForTest();
    b.fieldCrypto.registerTable("users", { sealedFields: ["email", "name"] });

    var ageBefore = fs.statSync(path.join(dataDir, "db.enc")).mtimeMs;

    // Rotate
    var progressEvents = [];
    var result = await b.vaultRotate.rotate({
      oldKeys: oldKeys, newKeys: newKeys,
      dataDir: dataDir, stagingDir: stagingDir,
      mode: "plaintext",
      progressCallback: function (e) { progressEvents.push(e.phase); },
    });

    check("rotate returns durationMs",              typeof result.durationMs === "number");
    check("rotate processed users table",           result.tablesProcessed === 1);
    check("rotate processed all 10 rows × 2 cols",  result.totalRowsProcessed >= 20);
    check("rotate verify passed",                   result.verifyResult && result.verifyResult.ok === true);
    check("progress phases include init/done",
          progressEvents.indexOf("init") !== -1 &&
          progressEvents.indexOf("done") !== -1);

    // Staging should hold the new vault key
    var stagedVaultKey = JSON.parse(fs.readFileSync(path.join(stagingDir, "vault.key"), "utf8"));
    check("staged vault.key is the new keypair",
          stagedVaultKey.encryptionMlkem === newKeys.encryptionMlkem ||
          stagedVaultKey.encryption === newKeys.encryption ||
          // shape varies but the staged keypair must NOT equal oldKeys
          JSON.stringify(stagedVaultKey) !== JSON.stringify(oldKeys));

    // Staged db.key.enc should decrypt under newKeys to the SAME dbKey
    var stagedSealedKey = fs.readFileSync(path.join(stagingDir, "db.key.enc"), "utf8").trim();
    var dbKeyAfterB64 = b.crypto.decrypt(stagedSealedKey.substring(b.constants.VAULT_PREFIX.length), newKeys);
    check("staged db.key.enc decrypts under newKeys",
          Buffer.from(dbKeyAfterB64, "base64").equals(dbKey));

    // Staged db.enc should decrypt with dbKey, contain the same rows, and
    // every email/name column should now be sealed under newKeys.
    var stagedPacked = fs.readFileSync(path.join(stagingDir, "db.enc"));
    var stagedPlain = b.crypto.decryptPacked(stagedPacked, dbKey);
    var verifyDbPath = path.join(dir, "verify.db");
    fs.writeFileSync(verifyDbPath, stagedPlain);
    var vdb = new DatabaseSync(verifyDbPath);
    try {
      var rows = vdb.prepare("SELECT _id, email, name FROM users ORDER BY _id").all();
      check("staged db has same row count",         rows.length === 10);
      // Each row's sealed columns decrypt under newKeys
      var allDecrypt = true;
      for (var j = 0; j < rows.length; j++) {
        var emailPayload = rows[j].email.substring(b.constants.VAULT_PREFIX.length);
        var namePayload = rows[j].name.substring(b.constants.VAULT_PREFIX.length);
        try {
          if (b.crypto.decrypt(emailPayload, newKeys) !== "user" + j + "@b.com") allDecrypt = false;
          if (b.crypto.decrypt(namePayload, newKeys) !== "Name " + j) allDecrypt = false;
        } catch (_e) { allDecrypt = false; }
      }
      check("every staged sealed value decrypts under newKeys + plaintext matches",
            allDecrypt);

      // And NO row still decrypts under oldKeys
      var anyOldDecrypt = false;
      for (var k = 0; k < rows.length; k++) {
        try {
          b.crypto.decrypt(rows[k].email.substring(b.constants.VAULT_PREFIX.length), oldKeys);
          anyOldDecrypt = true; break;
        } catch (_e) { /* expected */ }
      }
      check("no staged row decrypts under oldKeys",  anyOldDecrypt === false);
    } finally { vdb.close(); }

    // dataDir is untouched (mtime unchanged)
    var ageAfter = fs.statSync(path.join(dataDir, "db.enc")).mtimeMs;
    check("rotate did NOT mutate dataDir/db.enc",   ageAfter === ageBefore);

    b.fieldCrypto.clearForTest();
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) {}
  }
}

async function testVaultRotateRotateValidation() {
  var oldKeys = b.crypto.generateEncryptionKeyPair();
  var newKeys = b.crypto.generateEncryptionKeyPair();
  var threw;

  threw = null;
  try { await b.vaultRotate.rotate({}); } catch (e) { threw = e; }
  check("rotate without keys throws",             threw && threw.code === "vault-rotate/no-keys");

  threw = null;
  try { await b.vaultRotate.rotate({ oldKeys: oldKeys, newKeys: newKeys, dataDir: "/nonexistent-blamejs-test", stagingDir: "/tmp/x" }); }
  catch (e) { threw = e; }
  check("rotate with missing dataDir throws",     threw && threw.code === "vault-rotate/no-datadir");

  // staging exists → reject
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-vrot-val-"));
  try {
    fs.mkdirSync(path.join(dir, "staging"));
    threw = null;
    try {
      await b.vaultRotate.rotate({
        oldKeys: oldKeys, newKeys: newKeys,
        dataDir: dir, stagingDir: path.join(dir, "staging"),
      });
    } catch (e) { threw = e; }
    check("rotate with existing stagingDir throws", threw && threw.code === "vault-rotate/staging-exists");

    // wrapped mode without passphrase → reject
    threw = null;
    try {
      await b.vaultRotate.rotate({
        oldKeys: oldKeys, newKeys: newKeys,
        dataDir: dir, stagingDir: path.join(dir, "staging-2"),
        mode: "wrapped",
      });
    } catch (e) { threw = e; }
    check("rotate wrapped without passphrase throws",
          threw && threw.code === "vault-rotate/no-passphrase");
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) {}
  }
}

function testVaultRotateVerifyRequiresKeysAndDb() {
  var threw;
  threw = null; try { b.vaultRotate.verify({}); } catch (e) { threw = e; }
  check("verify without keys throws",             threw && threw.code === "vault-rotate/no-keys");

  threw = null; try { b.vaultRotate.verify({ keys: {} }); } catch (e) { threw = e; }
  check("verify without db throws",               threw && threw.code === "vault-rotate/no-db");
}

// ---- pqc-agent ----

function testPqcAgentSurface() {
  check("b.pqcAgent namespace present",          typeof b.pqcAgent === "object");
  check("b.pqcAgent.create is a function",       typeof b.pqcAgent.create === "function");
  check("b.pqcAgent.createHttp is a function",   typeof b.pqcAgent.createHttp === "function");
  check("b.pqcAgent.enforced flag set",          b.pqcAgent.enforced === true);
  check("DEFAULT_OPTS exposes keepAlive defaults",
        b.pqcAgent.DEFAULT_OPTS.keepAlive === true &&
        b.pqcAgent.DEFAULT_OPTS.maxSockets > 0);
}

function testPqcAgentCreateHasPqcPosture() {
  var a = b.pqcAgent.create();
  check("create returned an https.Agent",         a && a.constructor && a.constructor.name === "Agent");
  check("agent's TLS opts pin TLS 1.3",            a.options.minVersion === "TLSv1.3");
  check("agent's TLS opts pin PQC group preference",
        a.options.ecdhCurve === b.constants.TLS_GROUP_CURVE_STR);
  check("agent has keepAlive on by default",       a.keepAlive === true);
}

function testPqcAgentCannotWeakenCryptoPosture() {
  // Operator passes weakened opts; the primitive ignores them and the
  // framework defaults win. This is the primitive's whole point — it
  // makes "accidentally shipped a downgraded agent" structurally
  // impossible at the create() boundary.
  var weakened = b.pqcAgent.create({
    minVersion: "TLSv1.0",
    ecdhCurve:  "P-256",
    keepAlive:  false,    // pool tuning IS overridable
  });
  check("operator-supplied minVersion ignored",    weakened.options.minVersion === "TLSv1.3");
  check("operator-supplied ecdhCurve ignored",     weakened.options.ecdhCurve === b.constants.TLS_GROUP_CURVE_STR);
  check("operator-supplied keepAlive honored (pool tuning IS overridable)",
        weakened.keepAlive === false);
}

function testPqcAgentDefaultIsLazy() {
  // The default agent is a getter — accessing it builds the agent.
  // Multiple accesses return the same instance.
  var first  = b.pqcAgent.agent;
  var second = b.pqcAgent.agent;
  check("agent getter returns a non-null https.Agent",
        first && first.constructor && first.constructor.name === "Agent");
  check("agent getter is memoized (same instance on repeated access)",
        first === second);
  check("default agent has framework PQC posture",
        first.options.minVersion === "TLSv1.3" &&
        first.options.ecdhCurve === b.constants.TLS_GROUP_CURVE_STR);
}

function testPqcAgentCreateHttpHasNoTlsPosture() {
  // createHttp returns an http.Agent (cleartext) — there's no TLS
  // surface to enforce. Pool tuning still applies.
  var hAgent = b.pqcAgent.createHttp({ maxSockets: 5 });
  check("createHttp returns an http.Agent",        hAgent && hAgent.constructor && hAgent.constructor.name === "Agent");
  check("createHttp honors pool opts",             hAgent.maxSockets === 5);
  // http.Agent's options doesn't carry ecdhCurve/minVersion at all
  check("createHttp has no minVersion / ecdhCurve",
        hAgent.options.minVersion === undefined &&
        hAgent.options.ecdhCurve === undefined);
}

// ---- pqc-gate ----
//
// Build a synthetic ClientHello buffer with a configurable supported_groups
// list. Lets us exercise the parser without standing up real TLS.

function _makeClientHello(groupIds) {
  // Body layout we control:
  //   version(2) random(32) sessionId(0+1) cipherSuites(2+2) comp(1+1)
  //     extensions(2 + supported_groups extension)
  //
  // supported_groups extension:
  //   type=0x000A length(2)  list_length(2)  group_ids(2 each)
  var groupsBytes = Buffer.alloc(2 + groupIds.length * 2);
  groupsBytes.writeUInt16BE(groupIds.length * 2, 0);
  for (var i = 0; i < groupIds.length; i++) {
    groupsBytes.writeUInt16BE(groupIds[i], 2 + i * 2);
  }
  var extInner = Buffer.concat([
    Buffer.from([0x00, 0x0A]),                          // type
    (function () { var b = Buffer.alloc(2); b.writeUInt16BE(groupsBytes.length, 0); return b; })(),
    groupsBytes,
  ]);
  var extensions = Buffer.concat([
    (function () { var b = Buffer.alloc(2); b.writeUInt16BE(extInner.length, 0); return b; })(),
    extInner,
  ]);

  var ciphers = Buffer.concat([
    Buffer.from([0x00, 0x02]), // 2 bytes of cipher data
    Buffer.from([0x13, 0x01]), // TLS_AES_128_GCM_SHA256 (one cipher)
  ]);
  var compression = Buffer.from([0x01, 0x00]); // 1 method, null

  var body = Buffer.concat([
    Buffer.from([0x03, 0x03]),                  // version: TLS 1.2 record-level
    Buffer.alloc(32, 0xAA),                     // random: 32 bytes
    Buffer.from([0x00]),                        // session id length 0
    ciphers,
    compression,
    extensions,
  ]);

  // Handshake header: type=0x01 (ClientHello), length=body.length (3 bytes)
  var hsHeader = Buffer.alloc(4);
  hsHeader[0] = 0x01;
  hsHeader.writeUIntBE(body.length, 1, 3);

  // Record header: type=0x16 (handshake), version=0x0303, length=hsHeader.length+body.length
  var recordPayload = Buffer.concat([hsHeader, body]);
  var recordHeader = Buffer.alloc(5);
  recordHeader[0] = 0x16;
  recordHeader[1] = 0x03;
  recordHeader[2] = 0x03;
  recordHeader.writeUInt16BE(recordPayload.length, 3);

  return Buffer.concat([recordHeader, recordPayload]);
}

function testPqcGateSurface() {
  check("b.pqcGate namespace present",            typeof b.pqcGate === "object");
  check("b.pqcGate.create is a function",         typeof b.pqcGate.create === "function");
  check("b.pqcGate.clientHelloHasPQC is a function",
        typeof b.pqcGate.clientHelloHasPQC === "function");
  check("PQC_GROUP_IDS is a Set with framework groups",
        b.pqcGate.PQC_GROUP_IDS instanceof Set &&
        b.pqcGate.PQC_GROUP_IDS.has(b.constants.PQC_GROUPS.X25519MLKEM768) &&
        b.pqcGate.PQC_GROUP_IDS.has(b.constants.PQC_GROUPS.SecP384r1MLKEM1024));

  var threw = null;
  try { b.pqcGate.create({}); } catch (e) { threw = e; }
  check("create rejects missing internalPort",   threw && /internalPort/.test(threw.message));

  threw = null;
  try { b.pqcGate.create({ internalPort: 99999 }); } catch (e) { threw = e; }
  check("create rejects out-of-range port",      threw && /internalPort/.test(threw.message));
}

function testClientHelloPqcDetection() {
  // A ClientHello with ONLY PQC hybrid groups → accepted
  var heroPQ = _makeClientHello([b.constants.PQC_GROUPS.SecP384r1MLKEM1024]);
  check("ClientHello with PQC group → accepted",  b.pqcGate.clientHelloHasPQC(heroPQ) === true);

  // A ClientHello with both PQC + classical → accepted (PQC present is what matters)
  var heroMix = _makeClientHello([0x0017 /* secp256r1 */, b.constants.PQC_GROUPS.X25519MLKEM768]);
  check("ClientHello with mixed groups → accepted (PQC present)",
        b.pqcGate.clientHelloHasPQC(heroMix) === true);

  // A ClientHello with ONLY classical groups → rejected
  var heroClassical = _makeClientHello([0x0017, 0x0018, 0x001D /* x25519 */]);
  check("ClientHello with only classical groups → rejected",
        b.pqcGate.clientHelloHasPQC(heroClassical) === false);

  // Empty supported_groups (degenerate but well-formed) → rejected
  var heroEmpty = _makeClientHello([]);
  check("ClientHello with empty supported_groups → rejected",
        b.pqcGate.clientHelloHasPQC(heroEmpty) === false);

  // Garbage / non-handshake → rejected
  check("non-handshake first byte → rejected",   b.pqcGate.clientHelloHasPQC(Buffer.from([0x14, 0x03, 0x03, 0x00, 0x05])) === false);
  check("too-short buffer → rejected",            b.pqcGate.clientHelloHasPQC(Buffer.alloc(10)) === false);
  check("null input → rejected",                  b.pqcGate.clientHelloHasPQC(null) === false);
}

function testPqcGateSocketLifecycle() {
  // Drive the connection handler with a fake socket — verifies the
  // pause/resume + accept-vs-reject logic without standing up a real TCP server.
  var dataListeners = [];
  var emittedWrites = [];
  var destroyed = false;
  var socket = {
    remoteAddress: "203.0.113.5",
    paused: true,
    resume:  function () { this.paused = false; },
    pause:   function () { this.paused = true; },
    pipe:    function (other) { return other; },
    write:   function (chunk, cb) { emittedWrites.push(chunk); if (cb) cb(); return true; },
    destroy: function () { destroyed = true; },
    on:      function (ev, fn) { if (ev === "data") dataListeners.push(fn); return this; },
    removeListener: function (ev, fn) {
      if (ev === "data") {
        var idx = dataListeners.indexOf(fn);
        if (idx !== -1) dataListeners.splice(idx, 1);
      }
    },
  };

  // Capture the on-connection handler the gate would register
  var connectionHandler;
  var fakeServer = {
    listen:  function () {},
    close:   function (cb) { if (cb) cb(); },
    on:      function () { return this; },
  };
  var pendingTimers = [];
  var gate = b.pqcGate.create({
    internalPort: 1234,
    bypass:       [], // no localhost bypass for this test
    _server: function (sopts, cb) { connectionHandler = cb; return fakeServer; },
    _connect: function () {
      // Return a dummy 'internal' socket — we never actually pipe in this test
      var internal = { destroy: function () {}, write: function () {}, on: function () { return this; }, pipe: function () { return internal; } };
      return internal;
    },
    _setTimeout:   function (fn) { var t = { fn: fn, active: true }; pendingTimers.push(t); return t; },
    _clearTimeout: function (t) { if (t) t.active = false; },
  });
  check("create returns a server-shaped object",  gate === fakeServer);

  connectionHandler(socket);
  check("gate resumes the socket after attach",   socket.paused === false);

  // Feed a non-PQC ClientHello — should write the TLS alert and destroy
  var classical = _makeClientHello([0x0017, 0x001D]);
  dataListeners.forEach(function (fn) { fn(classical); });
  check("non-PQC ClientHello triggers TLS alert", emittedWrites.length === 1 &&
                                                  emittedWrites[0][0] === 0x15 &&
                                                  emittedWrites[0][6] === 0x28);
  check("non-PQC ClientHello destroys socket",    destroyed === true);
}

function testPqcGateBypassesLocalhost() {
  var localSocket = {
    remoteAddress: "127.0.0.1",
    resumed: false,
    resume: function () { this.resumed = true; },
    pause:  function () {},
    pipe:   function () {},
    on:     function () { return this; },
    destroy: function () {},
    write:   function () {},
  };
  var connectionHandler;
  var fakeServer = { on: function () { return this; } };
  var connectArgs = null;
  // Defer the connect cb to next tick so the parent's `internal`
  // assignment happens first (mirrors real net.createConnection).
  var deferredCb = null;
  b.pqcGate.create({
    internalPort: 5555,
    _server: function (s, cb) { connectionHandler = cb; return fakeServer; },
    _connect: function (cOpts, cb) {
      connectArgs = cOpts;
      deferredCb = cb;
      return {
        destroy: function () {},
        write:   function () {},
        on:      function () { return this; },
        pipe:    function () { return this; },
      };
    },
  });

  connectionHandler(localSocket);
  check("localhost bypass: connectFn called with internalPort",
        connectArgs && connectArgs.port === 5555);
  // Now fire the connect callback — after the gate has finished setting
  // up `internal`. The bypass path calls socket.resume() inside the cb.
  if (deferredCb) deferredCb();
  check("localhost bypass: socket resumed after pipe setup",
        localSocket.resumed === true);
}

// ---- bundler ----

function _makeBundlerFixture() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-bundler-"));
  var src = path.join(dir, "src");
  var out = path.join(dir, "dist");
  fs.mkdirSync(src, { recursive: true });
  return {
    dir: dir,
    src: src,
    out: out,
    write: function (rel, content) {
      var full = path.join(src, rel);
      fs.mkdirSync(path.dirname(full), { recursive: true });
      fs.writeFileSync(full, content);
      return full;
    },
    cleanup: function () {
      try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) {}
    },
  };
}

function testBundlerSurface() {
  check("b.bundler namespace present",            typeof b.bundler === "object");
  check("b.bundler.create is a function",         typeof b.bundler.create === "function");
  check("b.bundler.BundlerError is a class",      typeof b.bundler.BundlerError === "function");
}

function testBundlerCreateValidation() {
  var threw;
  threw = null; try { b.bundler.create({}); } catch (e) { threw = e; }
  check("missing entries rejected",               threw && threw.code === "bundler/no-entries");

  threw = null; try { b.bundler.create({ entries: {} }); } catch (e) { threw = e; }
  check("empty entries rejected",                 threw && threw.code === "bundler/no-entries");

  threw = null;
  try { b.bundler.create({ entries: { app: "./x.js" } }); } catch (e) { threw = e; }
  check("missing outdir rejected",                threw && threw.code === "bundler/no-outdir");

  threw = null;
  try { b.bundler.create({ entries: { "../escape": "./x.js" }, outdir: "/tmp/x" }); }
  catch (e) { threw = e; }
  check("entry name with '..' rejected",          threw && threw.code === "bundler/bad-entry-name");

  threw = null;
  try { b.bundler.create({ entries: { "a/b": "./x.js" }, outdir: "/tmp/x" }); }
  catch (e) { threw = e; }
  check("entry name with separator rejected",     threw && threw.code === "bundler/bad-entry-name");
}

async function testBundlerBuildHashedOutput() {
  var fx = _makeBundlerFixture();
  try {
    fx.write("app.js",    "console.log('hello bundler');\n");
    fx.write("style.css", "body { color: red; }\n");

    var bundler = b.bundler.create({
      entries: {
        app:   path.join(fx.src, "app.js"),
        style: path.join(fx.src, "style.css"),
      },
      outdir: fx.out,
    });
    var result = await bundler.build();
    check("build returned outputs",               result.outputs.length === 2);
    check("each output has hash",                 result.outputs.every(function (o) { return /^[0-9a-f]{16}$/.test(o.hash); }));
    check("each output file exists",              result.outputs.every(function (o) { return fs.existsSync(o.path); }));
    check("output filename includes hash + ext",  /app\.[0-9a-f]{16}\.js$/.test(result.outputs[0].path) ||
                                                  /app\.[0-9a-f]{16}\.js$/.test(result.outputs[1].path));
    check("manifest written to outdir",           fs.existsSync(result.manifestPath));
    var mf = JSON.parse(fs.readFileSync(result.manifestPath, "utf8"));
    check("manifest maps name → hashed filename",
          /app\.[0-9a-f]{16}\.js$/.test(mf.app) &&
          /style\.[0-9a-f]{16}\.css$/.test(mf.style));

    // Same content → same hash on rebuild (deterministic, content-addressed)
    var r2 = await bundler.build();
    check("rebuild with unchanged content reuses hash",
          r2.outputs[0].hash === result.outputs[0].hash);
  } finally { fx.cleanup(); }
}

async function testBundlerHashChangesWithContent() {
  var fx = _makeBundlerFixture();
  try {
    var srcPath = fx.write("app.js", "console.log('v1');\n");
    var bundler = b.bundler.create({
      entries: { app: srcPath },
      outdir:  fx.out,
    });
    var r1 = await bundler.build();
    var hash1 = r1.outputs[0].hash;

    fs.writeFileSync(srcPath, "console.log('v2');\n");
    var r2 = await bundler.build();
    var hash2 = r2.outputs[0].hash;
    check("changed content → new hash",            hash1 !== hash2);
    check("new output filename has new hash",      r2.outputs[0].path.indexOf(hash2) !== -1);
  } finally { fx.cleanup(); }
}

async function testBundlerHashOff() {
  var fx = _makeBundlerFixture();
  try {
    fx.write("app.js", "noop");
    var bundler = b.bundler.create({
      entries:  { app: path.join(fx.src, "app.js") },
      outdir:   fx.out,
      hash:     false,
      manifest: false,
    });
    var r = await bundler.build();
    check("hash:false → no hash in filename",     r.outputs[0].path.endsWith("app.js"));
    check("manifest:false → no manifest written", r.manifestPath === null);
  } finally { fx.cleanup(); }
}

async function testBundlerCustomHashLen() {
  var fx = _makeBundlerFixture();
  try {
    fx.write("app.js", "x");
    var bundler = b.bundler.create({
      entries: { app: path.join(fx.src, "app.js") },
      outdir:  fx.out,
      hashLen: 8,
    });
    var r = await bundler.build();
    check("hashLen:8 → 8-char hash",              r.outputs[0].hash.length === 8);
    check("output filename uses 8-char hash",     /app\.[0-9a-f]{8}\.js$/.test(r.outputs[0].path));
  } finally { fx.cleanup(); }
}

async function testBundlerReadFailure() {
  var fx = _makeBundlerFixture();
  try {
    var bundler = b.bundler.create({
      entries: { app: path.join(fx.src, "does-not-exist.js") },
      outdir:  fx.out,
    });
    var threw = null;
    try { await bundler.build(); } catch (e) { threw = e; }
    check("missing entry surfaces bundler/read-failed",
          threw && threw.code === "bundler/read-failed");
  } finally { fx.cleanup(); }
}

async function testBundlerWatchRebuilds() {
  // Use the test seam to drive rebuild without real fs.watch.
  var fx = _makeBundlerFixture();
  try {
    var entryPath = fx.write("app.js", "console.log('v1');\n");

    // Capture watcher fires
    var watcherListeners = [];
    function fakeWatch(dirOrFile, wopts, listener) {
      watcherListeners.push({ dir: dirOrFile, listener: listener });
      return { close: function () {} };
    }
    var pendingTimers = [];
    function fakeSetTimeout(fn) {
      var t = { fn: fn, active: true };
      pendingTimers.push(t);
      return t;
    }
    function fakeClearTimeout(t) { if (t) t.active = false; }

    var bundler = b.bundler.create({
      entries: { app: entryPath },
      outdir:  fx.out,
      _watch:        fakeWatch,
      _setTimeout:   fakeSetTimeout,
      _clearTimeout: fakeClearTimeout,
      graceMs:       50,
    });
    var initial = await bundler.build();
    var hash1 = initial.outputs[0].hash;

    var rebuilds = [];
    bundler.watch(function (err, result) {
      rebuilds.push({ err: err, result: result });
    });
    check("watch armed one watcher per entry",      watcherListeners.length === 1);

    // Change content + fire the watcher
    fs.writeFileSync(entryPath, "console.log('v2');\n");
    watcherListeners[0].listener("change", path.basename(entryPath));
    check("change fires a debounce timer",          pendingTimers.filter(function (t) { return t.active; }).length === 1);

    // Drive the timer
    var firedTimer = pendingTimers.find(function (t) { return t.active; });
    firedTimer.active = false;
    firedTimer.fn();
    // wait for the async build to settle
    await new Promise(function (r) { setImmediate(r); });
    await new Promise(function (r) { setImmediate(r); });
    await new Promise(function (r) { setImmediate(r); });
    check("watch callback fired",                   rebuilds.length === 1);
    check("rebuild produced new hash",
          rebuilds[0].result && rebuilds[0].result.outputs[0].hash !== hash1);

    // Events for unrelated filenames in the watched dir should be ignored
    pendingTimers.length = 0;
    watcherListeners[0].listener("change", "unrelated.txt");
    check("unrelated filename does not schedule rebuild",
          pendingTimers.filter(function (t) { return t.active; }).length === 0);

    await bundler.close();
  } finally { fx.cleanup(); }
}

// ---- dev ----
//
// Engine tests use fake spawn/watch/timer seams so we never actually
// fork processes. The engine logic — debounce, restart sequencing,
// queue coalescing, watcher-event filtering — is what we want to
// verify; integration with real child_process is out of scope here.

function _makeDevHarness() {
  // Fake child: emits an exit event when .kill() is called. The test
  // can drive an unexpected exit by calling fakeChild.crash().
  function makeChild(pid) {
    var listeners = {};
    var killed = false;
    return {
      pid: pid,
      kill: function (_signal) {
        if (killed) return;
        killed = true;
        // Emit on next tick so the kill() caller can attach listeners
        setImmediate(function () {
          (listeners.exit || []).forEach(function (cb) { cb(0, null); });
        });
      },
      on:   function (ev, cb) { (listeners[ev] = listeners[ev] || []).push(cb); return this; },
      once: function (ev, cb) {
        var wrap = function (a, b) {
          listeners[ev] = (listeners[ev] || []).filter(function (x) { return x !== wrap; });
          cb(a, b);
        };
        return this.on(ev, wrap);
      },
      crash: function (code) {
        (listeners.exit || []).forEach(function (cb) { cb(code, null); });
      },
    };
  }

  var spawnCalls = [];
  var pidCounter = 1000;
  function spawnFn(cmd, args, sopts) {
    var c = makeChild(++pidCounter);
    spawnCalls.push({ cmd: cmd, args: args.slice(), sopts: sopts, child: c });
    return c;
  }

  // Fake watcher: each call returns an emitter the test can fire events into
  var watchers = [];
  function watchFn(dir, wopts, listener) {
    var w = {
      dir: dir,
      closed: false,
      _listener: listener,
      on:    function () { return this; },
      close: function () { this.closed = true; },
      fire:  function (eventType, filename) { listener(eventType, filename); },
    };
    watchers.push(w);
    return w;
  }

  // Fake timers — tests drive ticks explicitly
  var timers = [];
  function setTimeoutFn(fn, ms) {
    var t = { fn: fn, ms: ms, active: true, unref: function () { return this; } };
    timers.push(t);
    return t;
  }
  function clearTimeoutFn(t) { if (t) t.active = false; }
  function fireTimers() {
    var fired = 0;
    var pending = timers.slice();
    timers.length = 0;
    for (var i = 0; i < pending.length; i++) {
      if (pending[i].active) { pending[i].fn(); fired++; }
    }
    return fired;
  }

  return {
    spawnCalls: spawnCalls,
    watchers:   watchers,
    timers:     timers,
    fireTimers: fireTimers,
    fakes: {
      _spawn:        spawnFn,
      _watch:        watchFn,
      _setTimeout:   setTimeoutFn,
      _clearTimeout: clearTimeoutFn,
    },
  };
}

function testDevSurface() {
  check("b.dev namespace present",                typeof b.dev === "object");
  check("b.dev.create is a function",             typeof b.dev.create === "function");
  check("b.dev.DevError is a class",              typeof b.dev.DevError === "function");
  check("DEFAULT_IGNORE includes node_modules",
        Array.isArray(b.dev.DEFAULT_IGNORE) &&
        b.dev.DEFAULT_IGNORE.some(function (p) { return p instanceof RegExp && p.test("node_modules"); }));

  var threw = null;
  try { b.dev.create({}); } catch (e) { threw = e; }
  check("create rejects missing command",         threw && threw.code === "dev/no-command");
}

async function testDevStartSpawnsChildAndArmsWatchers() {
  var h = _makeDevHarness();
  var d = b.dev.create({
    command: "node",
    args:    ["./server.js"],
    watch:   ["./routes", "./views"],
    cwd:     "/repo",
    _spawn:        h.fakes._spawn,
    _watch:        h.fakes._watch,
    _setTimeout:   h.fakes._setTimeout,
    _clearTimeout: h.fakes._clearTimeout,
  });
  await d.start();
  check("start spawns child once",                h.spawnCalls.length === 1);
  check("spawn args forwarded",                   h.spawnCalls[0].cmd === "node" &&
                                                  h.spawnCalls[0].args[0] === "./server.js");
  check("watchers armed for each dir",            h.watchers.length === 2);
  check("stats reports running + pid",
        d.stats().running === true && typeof d.stats().pid === "number" &&
        d.stats().restarts === 0);
  await d.stop();
  check("stop clears watchers",                   h.watchers.every(function (w) { return w.closed; }));
}

async function testDevDebouncesBurstOfEventsToOneRestart() {
  var h = _makeDevHarness();
  var d = b.dev.create({
    command: "node", args: ["./s.js"],
    watch:   ["./routes"],
    cwd:     "/repo",
    graceMs: 250,
    _spawn:        h.fakes._spawn,
    _watch:        h.fakes._watch,
    _setTimeout:   h.fakes._setTimeout,
    _clearTimeout: h.fakes._clearTimeout,
  });
  await d.start();
  check("baseline: 1 spawn after start",          h.spawnCalls.length === 1);

  // Five events in rapid succession before the debounce window fires
  var w = h.watchers[0];
  for (var i = 0; i < 5; i++) w.fire("change", "route" + i + ".js");
  check("debounce schedules exactly 1 active timer",
        h.timers.filter(function (t) { return t.active; }).length === 1);

  // Fire the debounce timer → triggers restart
  h.fireTimers();
  // Wait for the kill+respawn to complete
  await new Promise(function (r) { setImmediate(r); });
  await new Promise(function (r) { setImmediate(r); });
  await new Promise(function (r) { setImmediate(r); });
  // The kill timer (if any) is harmless; restart also fires after kill.
  check("after debounce: child respawned exactly once",
        h.spawnCalls.length === 2);
  check("stats.restarts incremented",             d.stats().restarts === 1);
  check("lastRestartAt set",                      typeof d.stats().lastRestartAt === "string");
  await d.stop();
}

async function testDevIgnoresMatchingPaths() {
  var h = _makeDevHarness();
  var d = b.dev.create({
    command: "node", args: ["./s.js"],
    watch:   ["./routes"],
    cwd:     "/repo",
    graceMs: 50,
    ignore:  [/should-ignore/],
    _spawn:        h.fakes._spawn,
    _watch:        h.fakes._watch,
    _setTimeout:   h.fakes._setTimeout,
    _clearTimeout: h.fakes._clearTimeout,
  });
  await d.start();
  var w = h.watchers[0];

  // node_modules in DEFAULT_IGNORE — ignored
  w.fire("change", "node_modules/x/index.js");
  check("DEFAULT_IGNORE: node_modules events drop",
        h.timers.filter(function (t) { return t.active; }).length === 0);

  // Custom ignore pattern
  w.fire("change", "should-ignore-me.js");
  check("Custom ignore pattern drops events",
        h.timers.filter(function (t) { return t.active; }).length === 0);

  // .db file ignored by default (sqlite WAL files would otherwise loop)
  w.fire("change", "blamejs.db");
  w.fire("change", "blamejs.db-wal");
  check("DEFAULT_IGNORE: .db files drop",
        h.timers.filter(function (t) { return t.active; }).length === 0);

  // Real source change → debounce armed
  w.fire("change", "routes/users.js");
  check("source-file change schedules a restart",
        h.timers.filter(function (t) { return t.active; }).length === 1);

  await d.stop();
}

async function testDevRestartCoalescesQueuedRestart() {
  // Restart-while-already-restarting queues one more, never more.
  // Easier to drive via the public restart() method which short-
  // circuits the debounce path.
  var h = _makeDevHarness();
  var d = b.dev.create({
    command: "node", args: ["./s.js"],
    watch:   ["./routes"],
    cwd:     "/repo",
    _spawn:        h.fakes._spawn,
    _watch:        h.fakes._watch,
    _setTimeout:   h.fakes._setTimeout,
    _clearTimeout: h.fakes._clearTimeout,
  });
  await d.start();

  // Three concurrent restart() calls. The first runs to completion; the
  // 2nd and 3rd both arrive while it's restarting, but they coalesce to
  // a single queued followup.
  var p1 = d.restart();
  var p2 = d.restart();
  var p3 = d.restart();
  await Promise.all([p1, p2, p3]);
  // Wait for the queued tail-call to drain
  await new Promise(function (r) { setImmediate(r); });
  await new Promise(function (r) { setImmediate(r); });

  // Initial spawn + 1st restart + 1 coalesced follow-up = 3 total
  check("3 concurrent restarts collapse to 2 respawns",
        h.spawnCalls.length === 3);
  check("stats.restarts = 2",                     d.stats().restarts === 2);
  await d.stop();
}

async function testDevStopKillsAndDisarms() {
  var h = _makeDevHarness();
  var d = b.dev.create({
    command: "node", args: ["./s.js"],
    watch:   ["./routes", "./views"],
    cwd:     "/repo",
    _spawn:        h.fakes._spawn,
    _watch:        h.fakes._watch,
    _setTimeout:   h.fakes._setTimeout,
    _clearTimeout: h.fakes._clearTimeout,
  });
  await d.start();
  await d.stop();
  check("stats.running false after stop",         d.stats().running === false);
  check("watchers closed",                        h.watchers.every(function (w) { return w.closed; }));
  // Subsequent stop is idempotent (no throw)
  await d.stop();
  check("second stop() is a no-op",               d.stats().running === false);
}

async function testDevUnexpectedExitDoesNotRespawn() {
  var h = _makeDevHarness();
  var d = b.dev.create({
    command: "node", args: ["./s.js"],
    watch:   ["./routes"],
    cwd:     "/repo",
    _spawn:        h.fakes._spawn,
    _watch:        h.fakes._watch,
    _setTimeout:   h.fakes._setTimeout,
    _clearTimeout: h.fakes._clearTimeout,
  });
  await d.start();
  // Simulate the child crashing on its own (not via kill())
  h.spawnCalls[0].child.crash(1);
  await new Promise(function (r) { setImmediate(r); });
  // No new spawn — operator must edit a file to retry
  check("crash without restart context: no respawn",
        h.spawnCalls.length === 1);
  await d.stop();
}

// ---- cli ----

function _cliCtx() {
  var out = "", err = "";
  return {
    captured: function () { return { out: out, err: err }; },
    ctx: {
      stdout: { write: function (s) { out += s; } },
      stderr: { write: function (s) { err += s; } },
      env:    {},
      cwd:    os.tmpdir(),
    },
  };
}

function testCliSurface() {
  check("b.cli namespace present",                typeof b.cli === "object");
  check("b.cli.main is a function",               typeof b.cli.main === "function");
  check("b.cli._parseArgs is a function",         typeof b.cli._parseArgs === "function");
  check("TOP_USAGE present",                      typeof b.cli.TOP_USAGE === "string" && b.cli.TOP_USAGE.length > 0);
}

function testCliArgParser() {
  var p1 = b.cli._parseArgs(["a", "b", "--flag", "value"]);
  check("parser collects positional args",        p1.pos.length === 2 && p1.pos[0] === "a" && p1.pos[1] === "b");
  check("parser parses --flag value",             p1.flags.flag === "value");

  // Trailing flag with no value → boolean
  var pBool = b.cli._parseArgs(["--only-flag"]);
  check("parser treats trailing flag as boolean", pBool.flags["only-flag"] === true);

  var p2 = b.cli._parseArgs(["--key=val", "--num=5"]);
  check("parser parses --key=val form",           p2.flags.key === "val");
  check("parser parses --key=val with numbers",   p2.flags.num === "5");

  var p3 = b.cli._parseArgs(["--", "--ignored", "x"]);
  check("parser stops at --",                     p3.pos.length === 2 && p3.pos[0] === "--ignored" && p3.flags["--ignored"] === undefined);

  var p4 = b.cli._parseArgs(["-v"]);
  check("parser handles short flags as boolean",  p4.flags.v === true);
}

async function testCliVersionAndHelp() {
  var t1 = _cliCtx();
  var rc1 = await b.cli.main(["version"], t1.ctx);
  check("version exits 0",                        rc1 === 0);
  check("version prints constants.version",       t1.captured().out.trim() === b.constants.version);

  var t2 = _cliCtx();
  var rc2 = await b.cli.main(["--version"], t2.ctx);
  check("--version flag also prints version",     rc2 === 0 && t2.captured().out.trim() === b.constants.version);

  var t3 = _cliCtx();
  var rc3 = await b.cli.main(["help"], t3.ctx);
  check("help exits 0",                           rc3 === 0);
  check("help prints top usage",                  t3.captured().out.indexOf("blamejs <command>") !== -1);

  var t4 = _cliCtx();
  var rc4 = await b.cli.main([], t4.ctx);
  check("no args prints help and exits 0",        rc4 === 0 && t4.captured().out.indexOf("blamejs <command>") !== -1);

  var t5 = _cliCtx();
  var rc5 = await b.cli.main(["help", "migrate"], t5.ctx);
  check("help <subcommand> prints subcommand usage",
        rc5 === 0 && t5.captured().out.indexOf("blamejs migrate") !== -1);

  var t6 = _cliCtx();
  var rc6 = await b.cli.main(["unknown-cmd"], t6.ctx);
  check("unknown command exits 2",                rc6 === 2);
  check("unknown command writes to stderr",       t6.captured().err.indexOf("unknown command") !== -1);
}

async function testCliMigrateStatus() {
  var fx = _makeMigrationsFixture();
  try {
    fx.write("0001-x.js", "module.exports = { up: function (db) { db['exec'](\"CREATE TABLE t1 (id INTEGER)\"); }, down: function (db) { db['exec'](\"DROP TABLE t1\"); } };");
    fx.write("0002-y.js", "module.exports = { up: function (db) { db['exec'](\"CREATE TABLE t2 (id INTEGER)\"); }, down: function (db) { db['exec'](\"DROP TABLE t2\"); } };");
    fx.db.close(); // CLI opens its own handle

    var t = _cliCtx();
    var rc = await b.cli.main([
      "migrate", "status",
      "--db", path.join(fx.dir, "test.db"),
      "--dir", fx.migDir,
    ], t.ctx);
    check("status exits 0",                       rc === 0);
    check("status reports 0 applied initially",   /applied: 0 \/ 2/.test(t.captured().out));
    check("status lists pending migrations",
          t.captured().out.indexOf("0001-x.js") !== -1 &&
          t.captured().out.indexOf("0002-y.js") !== -1);
  } finally { fx.cleanup(); }
}

async function testCliMigrateUpDown() {
  var fx = _makeMigrationsFixture();
  try {
    fx.write("0001-create-foo.js", "module.exports = { up: function (db) { db['exec'](\"CREATE TABLE foo (id INTEGER)\"); }, down: function (db) { db['exec'](\"DROP TABLE foo\"); } };");
    fx.write("0002-create-bar.js", "module.exports = { up: function (db) { db['exec'](\"CREATE TABLE bar (id INTEGER)\"); }, down: function (db) { db['exec'](\"DROP TABLE bar\"); } };");
    fx.db.close();

    // up
    var t1 = _cliCtx();
    var rc1 = await b.cli.main([
      "migrate", "up",
      "--db", path.join(fx.dir, "test.db"),
      "--dir", fx.migDir,
    ], t1.ctx);
    check("up exits 0",                           rc1 === 0);
    check("up reports applied count",             /applied 2 migration/.test(t1.captured().out));

    // up again → no-op
    var t2 = _cliCtx();
    var rc2 = await b.cli.main([
      "migrate", "up",
      "--db", path.join(fx.dir, "test.db"),
      "--dir", fx.migDir,
    ], t2.ctx);
    check("up again exits 0",                     rc2 === 0);
    check("up again reports no pending",          /no pending migrations/.test(t2.captured().out));

    // down --steps 1
    var t3 = _cliCtx();
    var rc3 = await b.cli.main([
      "migrate", "down",
      "--db", path.join(fx.dir, "test.db"),
      "--dir", fx.migDir,
      "--steps", "1",
    ], t3.ctx);
    check("down --steps 1 exits 0",               rc3 === 0);
    check("down --steps 1 reverts most recent",
          /reverted 1 migration/.test(t3.captured().out) &&
          t3.captured().out.indexOf("0002-create-bar.js") !== -1);

    // down without --steps → defaults to 1
    var t4 = _cliCtx();
    var rc4 = await b.cli.main([
      "migrate", "down",
      "--db", path.join(fx.dir, "test.db"),
      "--dir", fx.migDir,
    ], t4.ctx);
    check("down default --steps reverts 1 more", rc4 === 0 &&
          t4.captured().out.indexOf("0001-create-foo.js") !== -1);
  } finally { fx.cleanup(); }
}

async function testCliMigrateValidationErrors() {
  // Missing --db
  var t1 = _cliCtx();
  var rc1 = await b.cli.main(["migrate", "status"], t1.ctx);
  check("missing --db exits 2",                   rc1 === 2);
  check("missing --db error mentions flag",       t1.captured().err.indexOf("--db") !== -1);

  // Unknown subcommand
  var t2 = _cliCtx();
  var rc2 = await b.cli.main(["migrate", "fly"], t2.ctx);
  check("unknown migrate subcommand exits 2",     rc2 === 2);
  check("unknown subcommand writes usage to stderr", t2.captured().err.indexOf("Usage: blamejs migrate") !== -1);

  // No subcommand (just `blamejs migrate`)
  var t3 = _cliCtx();
  var rc3 = await b.cli.main(["migrate"], t3.ctx);
  check("bare `migrate` exits 2",                 rc3 === 2);
  check("bare `migrate` writes usage",            t3.captured().err.indexOf("Usage: blamejs migrate") !== -1);

  // --steps validation in down
  var fx = _makeMigrationsFixture();
  try {
    fx.db.close();
    var t4 = _cliCtx();
    var rc4 = await b.cli.main([
      "migrate", "down",
      "--db", path.join(fx.dir, "test.db"),
      "--dir", fx.migDir,
      "--steps", "0",
    ], t4.ctx);
    check("invalid --steps exits 2",              rc4 === 2);
    check("invalid --steps writes error",         t4.captured().err.indexOf("--steps") !== -1);
  } finally { fx.cleanup(); }
}

async function testCliMigrateDownReportsNoOpCleanly() {
  // Empty migrations dir + clean db → down is a no-op, exit 0.
  var fx = _makeMigrationsFixture();
  try {
    fx.db.close();
    var t = _cliCtx();
    var rc = await b.cli.main([
      "migrate", "down",
      "--db", path.join(fx.dir, "test.db"),
      "--dir", fx.migDir,
    ], t.ctx);
    check("no-op down exits 0",                   rc === 0);
    check("no-op down reports nothing to revert", /nothing to revert/.test(t.captured().out));
  } finally { fx.cleanup(); }
}

async function testCliDevValidation() {
  // Missing --command exits 2 with usage on stderr
  var t = _cliCtx();
  var rc = await b.cli.main(["dev"], t.ctx);
  check("dev without --command exits 2",          rc === 2);
  check("dev usage written on missing --command", t.captured().err.indexOf("--command") !== -1);

  // help dev prints usage
  var t2 = _cliCtx();
  var rc2 = await b.cli.main(["help", "dev"], t2.ctx);
  check("help dev exits 0",                       rc2 === 0);
  check("help dev prints usage",                  t2.captured().out.indexOf("blamejs dev") !== -1);
}

async function testCliMigrateUpFailureExits1() {
  var fx = _makeMigrationsFixture();
  try {
    fx.write("0001-broken.js", "module.exports = { up: function () { throw new Error('intentional'); } };");
    fx.db.close();
    var t = _cliCtx();
    var rc = await b.cli.main([
      "migrate", "up",
      "--db", path.join(fx.dir, "test.db"),
      "--dir", fx.migDir,
    ], t.ctx);
    check("failing up exits 1",                   rc === 1);
    check("failing up surfaces error code+message",
          /migrations\/up-failed/.test(t.captured().err) &&
          /intentional/.test(t.captured().err));
  } finally { fx.cleanup(); }
}

// ---- migrations ----

function _makeMigrationsFixture() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-mig-"));
  var dbPath = path.join(dir, "test.db");
  var migDir = path.join(dir, "migrations");
  fs.mkdirSync(migDir, { recursive: true });
  var { DatabaseSync } = require("node:sqlite");
  var db = new DatabaseSync(dbPath);
  return {
    dir:    dir,
    migDir: migDir,
    db:     db,
    cleanup: function () {
      try { db.close(); } catch (_e) {}
      try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) {}
    },
    write: function (file, content) {
      fs.writeFileSync(path.join(migDir, file), content);
    },
  };
}

function testMigrationsSurface() {
  check("b.migrations namespace present",         typeof b.migrations === "object");
  check("b.migrations.create is a function",      typeof b.migrations.create === "function");
  check("b.migrations.MigrationError is a class", typeof b.migrations.MigrationError === "function");
  check("b.migrations.MIGRATIONS_TABLE constant",
        b.migrations.MIGRATIONS_TABLE === "_blamejs_migrations");

  var threw;
  threw = null;
  try { b.migrations.create({}); } catch (e) { threw = e; }
  check("create rejects missing dir",             threw && threw.code === "migrations/no-dir");
}

function testMigrationsUpAppliesPending() {
  var fx = _makeMigrationsFixture();
  try {
    fx.write("0001-create-widgets.js", [
      "module.exports = {",
      "  description: 'create widgets',",
      "  up:   function (db) { db['exec'](\"CREATE TABLE widgets (id INTEGER PRIMARY KEY, name TEXT)\"); },",
      "  down: function (db) { db['exec'](\"DROP TABLE widgets\"); },",
      "};",
    ].join("\n"));
    fx.write("0002-add-color.js", [
      "module.exports = {",
      "  up:   function (db) { db['exec'](\"ALTER TABLE widgets ADD COLUMN color TEXT\"); },",
      "  down: function (db) { db['exec'](\"ALTER TABLE widgets DROP COLUMN color\"); },",
      "};",
    ].join("\n"));

    var migs = b.migrations.create({ db: fx.db, dir: fx.migDir });
    var r1 = migs.up();
    check("up applied both migrations in order",
          r1.applied.length === 2 &&
          r1.applied[0] === "0001-create-widgets.js" &&
          r1.applied[1] === "0002-add-color.js");
    check("up returned no skipped on first run",  r1.skipped.length === 0);

    // Verify the schema actually changed
    var cols = fx.db.prepare("PRAGMA table_info(widgets)").all();
    var colNames = cols.map(function (c) { return c.name; });
    check("up created widgets table",             colNames.indexOf("id") !== -1 && colNames.indexOf("name") !== -1);
    check("up added the color column",            colNames.indexOf("color") !== -1);

    // Re-run is idempotent
    var r2 = migs.up();
    check("re-run applied nothing",                r2.applied.length === 0);
    check("re-run skipped both",                   r2.skipped.length === 2);
  } finally { fx.cleanup(); }
}

function testMigrationsStatus() {
  var fx = _makeMigrationsFixture();
  try {
    fx.write("0001-a.js", "module.exports = { up: function (db) { db['exec'](\"CREATE TABLE a (id INTEGER)\"); } };");
    fx.write("0002-b.js", "module.exports = { up: function (db) { db['exec'](\"CREATE TABLE b (id INTEGER)\"); } };");
    fx.write("0003-c.js", "module.exports = { up: function (db) { db['exec'](\"CREATE TABLE c (id INTEGER)\"); } };");

    var migs = b.migrations.create({ db: fx.db, dir: fx.migDir });
    var pre = migs.status();
    check("status before up: 0 applied",          pre.applied.length === 0);
    check("status before up: 3 pending",          pre.pending.length === 3);
    check("status total reflects all files",      pre.total === 3);

    migs.up();
    var post = migs.status();
    check("status after up: 3 applied",           post.applied.length === 3);
    check("status after up: 0 pending",           post.pending.length === 0);
    check("applied rows carry name + appliedAt",
          post.applied[0].name === "0001-a.js" &&
          typeof post.applied[0].appliedAt === "string" &&
          /^\d{4}-/.test(post.applied[0].appliedAt));
  } finally { fx.cleanup(); }
}

function testMigrationsDownRollback() {
  var fx = _makeMigrationsFixture();
  try {
    fx.write("0001-create-x.js", [
      "module.exports = {",
      "  up:   function (db) { db['exec'](\"CREATE TABLE x (id INTEGER)\"); },",
      "  down: function (db) { db['exec'](\"DROP TABLE x\"); },",
      "};",
    ].join("\n"));
    fx.write("0002-create-y.js", [
      "module.exports = {",
      "  up:   function (db) { db['exec'](\"CREATE TABLE y (id INTEGER)\"); },",
      "  down: function (db) { db['exec'](\"DROP TABLE y\"); },",
      "};",
    ].join("\n"));

    var migs = b.migrations.create({ db: fx.db, dir: fx.migDir });
    migs.up();

    // Roll back the most recent (y)
    var r1 = migs.down();
    check("default steps=1 reverts one migration", r1.reverted.length === 1 && r1.reverted[0] === "0002-create-y.js");

    // y is gone, x is still here
    var tbls = fx.db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('x','y')").all();
    var tblNames = tbls.map(function (t) { return t.name; });
    check("y dropped after rollback",              tblNames.indexOf("y") === -1);
    check("x still present after partial rollback", tblNames.indexOf("x") !== -1);

    // status reflects the partial rollback
    var st = migs.status();
    check("status: x applied, y pending",
          st.applied.length === 1 && st.applied[0].name === "0001-create-x.js" &&
          st.pending.length === 1 && st.pending[0] === "0002-create-y.js");

    // Roll back x as well, with explicit steps
    var r2 = migs.down({ steps: 1 });
    check("rollback the remaining migration",      r2.reverted.length === 1 && r2.reverted[0] === "0001-create-x.js");
    var st2 = migs.status();
    check("status: nothing applied, both pending",
          st2.applied.length === 0 && st2.pending.length === 2);
  } finally { fx.cleanup(); }
}

function testMigrationsDownMultiSteps() {
  var fx = _makeMigrationsFixture();
  try {
    for (var i = 1; i <= 3; i++) {
      var n = i;
      fx.write("000" + n + "-step.js", [
        "module.exports = {",
        "  up:   function (db) { db['exec'](\"CREATE TABLE t" + n + " (id INTEGER)\"); },",
        "  down: function (db) { db['exec'](\"DROP TABLE t" + n + "\"); },",
        "};",
      ].join("\n"));
    }
    var migs = b.migrations.create({ db: fx.db, dir: fx.migDir });
    migs.up();

    var r = migs.down({ steps: 2 });
    check("steps=2 reverts 2 migrations in reverse order",
          r.reverted.length === 2 &&
          r.reverted[0] === "0003-step.js" &&
          r.reverted[1] === "0002-step.js");

    var st = migs.status();
    check("only oldest still applied",             st.applied.length === 1 && st.applied[0].name === "0001-step.js");
  } finally { fx.cleanup(); }
}

function testMigrationsDownRejectsBadSteps() {
  var fx = _makeMigrationsFixture();
  try {
    var migs = b.migrations.create({ db: fx.db, dir: fx.migDir });
    var threw;
    threw = null; try { migs.down({ steps: 0 }); }    catch (e) { threw = e; }
    check("steps=0 rejected",                      threw && threw.code === "migrations/bad-steps");
    threw = null; try { migs.down({ steps: -1 }); }   catch (e) { threw = e; }
    check("negative steps rejected",               threw && threw.code === "migrations/bad-steps");
    threw = null; try { migs.down({ steps: 1.5 }); }  catch (e) { threw = e; }
    check("non-integer steps rejected",            threw && threw.code === "migrations/bad-steps");
    threw = null; try { migs.down({ steps: "x" }); }  catch (e) { threw = e; }
    check("non-numeric steps rejected",            threw && threw.code === "migrations/bad-steps");
  } finally { fx.cleanup(); }
}

function testMigrationsRejectsRollbackWithoutDown() {
  var fx = _makeMigrationsFixture();
  try {
    fx.write("0001-no-down.js",
      "module.exports = { up: function (db) { db['exec'](\"CREATE TABLE z (id INTEGER)\"); } };");
    var migs = b.migrations.create({ db: fx.db, dir: fx.migDir });
    migs.up();
    var threw = null;
    try { migs.down(); } catch (e) { threw = e; }
    check("missing down() surfaces clear error",
          threw && threw.code === "migrations/no-down" &&
          /no `down\(db\)` function/.test(threw.message));
    // The migration should still be marked applied (rollback aborted before delete)
    check("aborted rollback leaves migration applied",
          migs.status().applied.length === 1);
  } finally { fx.cleanup(); }
}

function testMigrationsUpFailureRollsBackTransaction() {
  var fx = _makeMigrationsFixture();
  try {
    fx.write("0001-good.js",
      "module.exports = { up: function (db) { db['exec'](\"CREATE TABLE good (id INTEGER)\"); }, down: function (db) { db['exec'](\"DROP TABLE good\"); } };");
    fx.write("0002-bad.js", [
      "module.exports = {",
      "  up: function (db) {",
      "    db['exec'](\"CREATE TABLE bad (id INTEGER)\");",
      "    throw new Error('intentional failure');",
      "  },",
      "};",
    ].join("\n"));

    var migs = b.migrations.create({ db: fx.db, dir: fx.migDir });
    var threw = null;
    try { migs.up(); } catch (e) { threw = e; }
    check("failing up surfaces MigrationError",
          threw && threw.code === "migrations/up-failed" && /intentional failure/.test(threw.message));

    // good migration applied; bad migration's table NOT created (rolled back)
    var tbls = fx.db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('good','bad')").all();
    var tblNames = tbls.map(function (t) { return t.name; });
    check("first (good) migration applied",        tblNames.indexOf("good") !== -1);
    check("failed migration's CREATE was rolled back", tblNames.indexOf("bad") === -1);

    // Status: 1 applied, 1 pending (the bad one)
    var st = migs.status();
    check("status reflects partial apply",         st.applied.length === 1 && st.pending.length === 1);
  } finally { fx.cleanup(); }
}

function testMigrationsRejectsMalformedFiles() {
  var fx = _makeMigrationsFixture();
  try {
    // No matching file pattern → just ignored (not an error)
    fs.writeFileSync(path.join(fx.migDir, "README.md"), "ignore me");
    fs.writeFileSync(path.join(fx.migDir, "no-prefix.js"),
      "module.exports = { up: function () {} };");

    var migs = b.migrations.create({ db: fx.db, dir: fx.migDir });
    var st = migs.status();
    check("non-matching files ignored",            st.total === 0);

    // Matching file without up() → load-time error
    fx.write("0001-noup.js", "module.exports = { description: 'oops' };");
    var threw = null;
    try { migs.up(); } catch (e) { threw = e; }
    check("missing up() surfaces missing-up error",
          threw && threw.code === "migrations/missing-up");
  } finally { fx.cleanup(); }
}

// ---- cookies ----

function _cookieFakeRes() {
  var headers = {};
  return {
    headers: headers,
    setHeader: function (k, v) { headers[k] = v; },
    getHeader: function (k) { return headers[k]; },
  };
}

function testCookiesSurface() {
  check("b.cookies namespace present",            typeof b.cookies === "object");
  check("b.cookies.create is a function",         typeof b.cookies.create === "function");
  check("b.cookies.parse is a function",          typeof b.cookies.parse === "function");
  check("b.cookies.serialize is a function",      typeof b.cookies.serialize === "function");
  check("b.cookies.CookieError is a class",       typeof b.cookies.CookieError === "function");
}

function testCookiesParse() {
  var jar1 = b.cookies.parse("a=1; b=2; c=3");
  check("parse simple",                           jar1.a === "1" && jar1.b === "2" && jar1.c === "3");

  // = inside a value
  var jar2 = b.cookies.parse("session=abc=def=ghi; flag=on");
  check("parse value containing =",               jar2.session === "abc=def=ghi" && jar2.flag === "on");

  // URL-encoded value decoded
  var jar3 = b.cookies.parse("greet=" + encodeURIComponent("hi there!"));
  check("parse url-decodes value",                jar3.greet === "hi there!");

  // Quoted value strips surrounding quotes
  var jar4 = b.cookies.parse('q="quoted value"');
  check("parse strips surrounding quotes",        jar4.q === "quoted value");

  // Empty / malformed inputs
  check("parse null → empty object",              Object.keys(b.cookies.parse(null)).length === 0);
  check("parse '' → empty object",                Object.keys(b.cookies.parse("")).length === 0);
  check("parse 'no-equals' ignored",              Object.keys(b.cookies.parse("noequals")).length === 0);

  // Last write wins (RFC 6265 §5.4 fixup)
  var jar5 = b.cookies.parse("a=1; a=2");
  check("parse last-write-wins on duplicate",     jar5.a === "2");
}

function testCookiesSerialize() {
  // Defaults: just name=value
  var s1 = b.cookies.serialize("a", "1");
  check("serialize bare cookie",                   s1 === "a=1");

  // All attributes
  var s2 = b.cookies.serialize("session", "abc", {
    maxAge: 3600, path: "/", httpOnly: true, secure: true, sameSite: "Lax",
  });
  check("serialize includes Max-Age",              /Max-Age=3600/.test(s2));
  check("serialize includes Path",                 /Path=\//.test(s2));
  check("serialize includes HttpOnly",             /HttpOnly/.test(s2));
  check("serialize includes Secure",               /Secure/.test(s2));
  check("serialize includes SameSite=Lax",         /SameSite=Lax/.test(s2));

  // Expires Date conversion
  var s3 = b.cookies.serialize("a", "1", { expires: new Date("2030-01-01T00:00:00Z") });
  check("serialize includes Expires UTC",          /Expires=.*GMT/.test(s3));

  // SameSite normalization
  var s4 = b.cookies.serialize("a", "1", { sameSite: "strict" });
  check("serialize normalizes SameSite=Strict",    /SameSite=Strict/.test(s4));

  // SameSite=None forces Secure
  var s5 = b.cookies.serialize("a", "1", { sameSite: "None" });
  check("SameSite=None forces Secure",             /SameSite=None/.test(s5) && /Secure/.test(s5));

  // Value gets percent-encoded on the wire
  var s6 = b.cookies.serialize("a", "hi there!");
  check("serialize percent-encodes value",         s6 === "a=hi%20there!");

  // Reject CRLF in value (header injection defense)
  var threw;
  threw = null; try { b.cookies.serialize("a", "x\r\ny"); } catch (e) { threw = e; }
  check("serialize rejects CRLF in value",         threw && threw.code === "cookies/invalid-value");
  threw = null; try { b.cookies.serialize("a", "x;y"); } catch (e) { threw = e; }
  check("serialize rejects semicolon in value",    threw && threw.code === "cookies/invalid-value");
  threw = null; try { b.cookies.serialize("bad name", "v"); } catch (e) { threw = e; }
  check("serialize rejects space in name",         threw && threw.code === "cookies/invalid-name");
  threw = null; try { b.cookies.serialize("a\r\nb", "v"); } catch (e) { threw = e; }
  check("serialize rejects CRLF in name",          threw && threw.code === "cookies/invalid-name");

  // Invalid attr values
  threw = null; try { b.cookies.serialize("a", "1", { sameSite: "Loose" }); } catch (e) { threw = e; }
  check("serialize rejects unknown sameSite",      threw && threw.code === "cookies/invalid-attr");
  threw = null; try { b.cookies.serialize("a", "1", { maxAge: "forever" }); } catch (e) { threw = e; }
  check("serialize rejects non-integer maxAge",    threw && threw.code === "cookies/invalid-attr");

  // CRLF in domain/path is stripped (defense in depth, since these are
  // operator-controlled but could come from config)
  var s7 = b.cookies.serialize("a", "1", { domain: "evil.com\r\nX-Hack: 1", path: "/" });
  check("serialize strips CRLF from domain",
        s7.indexOf("\r") === -1 && s7.indexOf("\n") === -1 && /Domain=evil\.com/.test(s7));
}

function testCookiesInstanceDefaults() {
  var jar = b.cookies.create({
    defaults: { httpOnly: true, secure: true, sameSite: "Strict", path: "/", maxAge: 600 },
  });
  var s = jar.serialize("session", "abc");
  check("instance applies defaults",
        /HttpOnly/.test(s) && /Secure/.test(s) && /SameSite=Strict/.test(s) &&
        /Path=\//.test(s) && /Max-Age=600/.test(s));

  // Per-call attrs override defaults
  var s2 = jar.serialize("session", "abc", { sameSite: "Lax", maxAge: 60 });
  check("per-call attrs override defaults",
        /SameSite=Lax/.test(s2) && /Max-Age=60/.test(s2));

  // create's own defaults override the framework's bare defaults
  // (framework default is httpOnly=true, secure=true, sameSite=Lax, path=/)
  var jar2 = b.cookies.create({ defaults: { secure: false, sameSite: "None" } });
  var s3 = jar2.serialize("a", "1");
  // SameSite=None forces Secure regardless — verifies that path
  check("SameSite=None forces Secure even when default secure=false",
        /SameSite=None/.test(s3) && /Secure/.test(s3));
}

function testCookiesReadWrite() {
  var jar = b.cookies.create({
    defaults: { httpOnly: true, secure: false, sameSite: "Lax", path: "/" },
  });
  var req = { headers: { cookie: "blamejs_session=abc; theme=dark" } };
  check("read returns cookie value",               jar.read(req, "blamejs_session") === "abc");
  check("read missing cookie → null",              jar.read(req, "nope") === null);
  check("read req without headers → null",         jar.read({}, "x") === null);

  // Write builds the Set-Cookie array, preserving any existing entries
  var res = _cookieFakeRes();
  res.headers["Set-Cookie"] = ["existing=1; Path=/"];
  jar.write(res, "blamejs_session", "newtoken", { maxAge: 60 });
  var setCookie = res.headers["Set-Cookie"];
  check("write appends to existing Set-Cookie",    Array.isArray(setCookie) && setCookie.length === 2);
  check("written cookie has name+value",           /blamejs_session=newtoken/.test(setCookie[1]));
  check("written cookie has Max-Age",              /Max-Age=60/.test(setCookie[1]));

  // Clear → Max-Age=0
  var res2 = _cookieFakeRes();
  jar.clear(res2, "blamejs_session");
  check("clear emits Max-Age=0",                   /Max-Age=0/.test(res2.headers["Set-Cookie"][0]));
}

function testCookiesSealedRoundTrip() {
  // Real vault round-trip via the framework's own vault module. We use
  // a temp dir so the key isn't shared with other tests.
  var prevDataDir = process.env.BLAMEJS_DATA_DIR;
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cookies-test-"));
  process.env.BLAMEJS_DATA_DIR = dir;
  try {
    b.vault._resetForTest();
    b.vault.init({ mode: "plaintext", dataDir: dir });
    var jar = b.cookies.create({
      vault: b.vault,
      defaults: { httpOnly: true, secure: false, sameSite: "Lax", path: "/" },
    });

    // writeSealed → cookie carries vault.seal of value (prefix stripped)
    var res = _cookieFakeRes();
    var sid = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    jar.writeSealed(res, "blamejs_session", sid, { maxAge: 600 });
    var setCookie = res.headers["Set-Cookie"][0];
    check("sealed cookie wire format does not contain raw sid",
          setCookie.indexOf(sid) === -1);
    check("sealed cookie wire format does not contain vault: prefix",
          setCookie.indexOf("vault:") === -1);

    // Pull the cookie value off the Set-Cookie line and round-trip via readSealed
    var nameEqValue = setCookie.split(";")[0];
    var enc = nameEqValue.split("=")[1]; // url-encoded form
    var req = { headers: { cookie: "blamejs_session=" + enc } };
    var unsealed = jar.readSealed(req, "blamejs_session");
    check("readSealed recovers the original sid",  unsealed === sid);

    // Two seals of the same value produce DIFFERENT ciphertexts
    // (XChaCha20 nonce randomization). The framework's encryption-as-
    // access-gate posture relies on this — even an attacker who sees
    // many cookies can't distill the wire format into a guessable value.
    var resB = _cookieFakeRes();
    jar.writeSealed(resB, "blamejs_session", sid, { maxAge: 600 });
    var encB = resB.headers["Set-Cookie"][0].split(";")[0].split("=")[1];
    check("two seals of same value produce different ciphertext",
          enc !== encB);

    // Tampered sealed cookie → readSealed returns null (no throw)
    var tampered = enc.slice(0, -4) + "AAAA"; // mutate last 4 base64 chars
    var reqT = { headers: { cookie: "blamejs_session=" + tampered } };
    check("tampered sealed cookie → null (auth tag fails)",
          jar.readSealed(reqT, "blamejs_session") === null);

    // Sealed cookie carries the vault envelope intact — first byte of
    // the decoded payload is the envelope magic (0xE1).
    var decoded = Buffer.from(decodeURIComponent(enc), "base64");
    check("sealed cookie payload starts with envelope magic 0xE1",
          decoded[0] === b.constants.ENVELOPE_MAGIC);
    // The 4-byte envelope header (magic + KEM + cipher + KDF) is the
    // version-agility seam — algorithm rotation works even on cookies
    // because vault.unseal dispatches on these bytes, not the active
    // defaults.
    check("envelope KEM byte matches ACTIVE.KEM",   decoded[1] === b.constants.ACTIVE.KEM);
    check("envelope cipher byte matches ACTIVE.CIPHER",
          decoded[2] === b.constants.ACTIVE.CIPHER);
    check("envelope KDF byte matches ACTIVE.KDF",   decoded[3] === b.constants.ACTIVE.KDF);

    // Sealed methods without a vault → throw
    var noVault = b.cookies.create({});
    var threw = null;
    try { noVault.writeSealed(_cookieFakeRes(), "x", "y"); } catch (e) { threw = e; }
    check("writeSealed without vault throws",      threw && threw.code === "cookies/no-vault");

    b.vault._resetForTest();
  } finally {
    if (prevDataDir === undefined) delete process.env.BLAMEJS_DATA_DIR;
    else process.env.BLAMEJS_DATA_DIR = prevDataDir;
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) {}
  }
}

// ---- errors-page ----
//
// A fake-res helper captures statusCode + Content-Type + body so each
// test can assert the response shape without a real http.Server.

function _makeFakeRes() {
  var res = {
    statusCode:    null,
    headers:       {},
    body:          "",
    writableEnded: false,
    setHeader:     function (k, v) { this.headers[k] = v; },
    end:           function (chunk) { if (chunk !== undefined) this.body += chunk; this.writableEnded = true; },
    writeHead:     function (status, hdrs) {
      this.statusCode = status;
      if (hdrs) for (var k in hdrs) this.headers[k] = hdrs[k];
    },
  };
  return res;
}

function testErrorsPageSurface() {
  check("b.errorsPage namespace present",         typeof b.errorsPage === "object");
  check("b.errorsPage.create is a function",      typeof b.errorsPage.create === "function");
  check("b.errorsPage.STATUS_REASONS map present",
        b.errorsPage.STATUS_REASONS[404] === "Not Found" &&
        b.errorsPage.STATUS_REASONS[500] === "Internal Server Error");
}

function testErrorsPageProdHidesStackAndOriginalMessage() {
  var handler = b.errorsPage.create({ mode: "prod", audit: false });
  var req = { method: "GET", url: "/x", headers: { accept: "text/html" } };
  var res = _makeFakeRes();
  // Generic Error — operator-private message must NOT leak.
  handler(new Error("DB pwd: hunter2"), req, res);
  check("prod 500 → 500 status",                   res.statusCode === 500);
  check("prod 500 → text/html",                    /text\/html/.test(res.headers["Content-Type"]));
  check("prod 500 hides operator message",         res.body.indexOf("hunter2") === -1);
  check("prod 500 shows generic message",          res.body.indexOf("Internal Server Error") !== -1);
  check("prod page does not include any stack",    res.body.indexOf(".js:") === -1 && res.body.indexOf("at ") === -1);
}

function testErrorsPageDevShowsStackAndRequestInfo() {
  var handler = b.errorsPage.create({ mode: "dev", audit: false, brand: "blamejs-test" });
  var req = {
    method: "POST", url: "/api/widget?id=42",
    headers: { accept: "text/html", "user-agent": "ua/1", cookie: "session=secret123" },
    id: "req-zzz",
  };
  var res = _makeFakeRes();
  handler(new Error("widget exploded"), req, res);
  check("dev 500 → 500 status",                    res.statusCode === 500);
  check("dev 500 shows operator message",          res.body.indexOf("widget exploded") !== -1);
  check("dev 500 shows request method+url",
        res.body.indexOf("POST") !== -1 && res.body.indexOf("/api/widget") !== -1);
  check("dev 500 redacts cookie header",           res.body.indexOf("secret123") === -1);
  check("dev 500 shows requestId when set",        res.body.indexOf("req-zzz") !== -1);
  check("dev 500 includes a stack trace block",    res.body.indexOf("Stack") !== -1);
  check("dev page brand reflects opts.brand",      res.body.indexOf("blamejs-test") !== -1);
}

function testErrorsPageJsonNegotiation() {
  var handler = b.errorsPage.create({ mode: "prod", audit: false });
  var req = { method: "POST", url: "/api/x", headers: { accept: "application/json" } };
  var res = _makeFakeRes();
  var err = Object.assign(new Error("bad input"), {
    isAppError: true, statusCode: 400, code: "VALIDATION_ERROR",
  });
  handler(err, req, res);
  check("json 400 → 400 status",                   res.statusCode === 400);
  check("json content-type",                       /application\/json/.test(res.headers["Content-Type"]));
  var payload = JSON.parse(res.body);
  check("json error message preserved on 4xx",     payload.error.message === "bad input");
  check("json carries error code",                 payload.error.code === "VALIDATION_ERROR");
  check("prod json 4xx has no stack",              payload.error.stack === undefined);
}

function testErrorsPageDevJsonIncludesStack() {
  var handler = b.errorsPage.create({ mode: "dev", audit: false });
  var req = { method: "POST", url: "/api/x", headers: { accept: "application/json" } };
  var res = _makeFakeRes();
  handler(new Error("kaboom"), req, res);
  var payload = JSON.parse(res.body);
  check("dev json 500 includes stack",             typeof payload.error.stack === "string" && /kaboom/.test(payload.error.stack));
}

function testErrorsPageAppErrorClassification() {
  var handler = b.errorsPage.create({ mode: "prod", audit: false });
  var req = { method: "GET", url: "/x", headers: { accept: "text/html" } };

  // 404
  var res404 = _makeFakeRes();
  handler(Object.assign(new Error("nothing here"), {
    isAppError: true, statusCode: 404, code: "NOT_FOUND",
  }), req, res404);
  check("AppError 404 routes to 404 status",       res404.statusCode === 404);
  check("AppError 404 message preserved on 4xx",   res404.body.indexOf("nothing here") !== -1);

  // 401 — security code path
  var res401 = _makeFakeRes();
  handler(Object.assign(new Error("auth fail"), {
    isAppError: true, statusCode: 401, code: "UNAUTH",
  }), req, res401);
  check("AppError 401 routes to 401 status",       res401.statusCode === 401);

  // statusCode without isAppError still classifies
  var res403 = _makeFakeRes();
  handler({ statusCode: 403, code: "FORBID", message: "denied" }, req, res403);
  check("statusCode-only error classified",        res403.statusCode === 403);
  check("classified 4xx message preserved",        res403.body.indexOf("denied") !== -1);
}

function testErrorsPageNeverWritesWhenAlreadyEnded() {
  var handler = b.errorsPage.create({ mode: "prod", audit: false });
  var req = { method: "GET", url: "/x", headers: { accept: "text/html" } };
  var res = _makeFakeRes();
  res.writableEnded = true;
  res.end = function () { check("end called after writableEnded — must not happen", false); };
  // Should NOT throw and NOT call res.end
  handler(new Error("late"), req, res);
  check("no write happens when writableEnded",     res.statusCode === null);
}

function testErrorsPageOnErrorHookCanTakeOver() {
  var taken = [];
  var handler = b.errorsPage.create({
    mode: "prod", audit: false,
    onError: function (err, req, res, info) {
      taken.push({ status: info.status, code: info.code });
      res.statusCode = 418;
      res.end("im a teapot");
      return true;
    },
  });
  var req = { method: "GET", url: "/x", headers: { accept: "text/html" } };
  var res = _makeFakeRes();
  handler(Object.assign(new Error("bad"), { isAppError: true, statusCode: 400, code: "X" }), req, res);
  check("onError hook ran",                        taken.length === 1 && taken[0].status === 400);
  check("onError hook took over response",         res.statusCode === 418 && res.body === "im a teapot");
}

function testErrorsPageLogsViaInjectedLogger() {
  var captured = [];
  var fakeLog = {
    warn:  function (msg, fields) { captured.push({ level: "warn", msg: msg, fields: fields }); },
    error: function (msg, fields) { captured.push({ level: "error", msg: msg, fields: fields }); },
  };
  var handler = b.errorsPage.create({ mode: "prod", audit: false, log: fakeLog });
  var req = { method: "GET", url: "/x", headers: {} };
  var res500 = _makeFakeRes();
  handler(new Error("kaboom"), req, res500);
  check("500 logged at error level",               captured.length === 1 && captured[0].level === "error");
  check("500 log fields include status + url",
        captured[0].fields.status === 500 &&
        captured[0].fields.url === "/x" &&
        typeof captured[0].fields.stack === "string");

  captured.length = 0;
  var res404 = _makeFakeRes();
  handler(Object.assign(new Error("missing"), { isAppError: true, statusCode: 404 }), req, res404);
  check("404 logged at warn level",                captured.length === 1 && captured[0].level === "warn");
  check("404 log has no stack noise",              captured[0].fields.stack === undefined);
}

function testErrorsPageDevEnvVarsHonorOptIn() {
  var handler = b.errorsPage.create({ mode: "dev", audit: false }); // showEnvVars defaults false
  var req = { method: "GET", url: "/x", headers: { accept: "text/html" } };
  var res = _makeFakeRes();
  handler(new Error("e"), req, res);
  check("dev page omits Environment section by default",
        res.body.indexOf("Environment") === -1);

  var prevSecret = process.env.BLAMEJS_FAKE_SECRET;
  var prevHarmless = process.env.BLAMEJS_FAKE_HARMLESS;
  process.env.BLAMEJS_FAKE_SECRET = "leakme";
  process.env.BLAMEJS_FAKE_HARMLESS = "publicvalue";
  try {
    var handlerOn = b.errorsPage.create({ mode: "dev", audit: false, showEnvVars: true });
    var resOn = _makeFakeRes();
    handlerOn(new Error("e"), req, resOn);
    check("opt-in env shows non-secret keys",
          resOn.body.indexOf("BLAMEJS_FAKE_HARMLESS") !== -1);
    check("opt-in env still redacts SECRET-shaped keys",
          resOn.body.indexOf("BLAMEJS_FAKE_SECRET") === -1 &&
          resOn.body.indexOf("leakme") === -1);
  } finally {
    if (prevSecret === undefined) delete process.env.BLAMEJS_FAKE_SECRET;
    else process.env.BLAMEJS_FAKE_SECRET = prevSecret;
    if (prevHarmless === undefined) delete process.env.BLAMEJS_FAKE_HARMLESS;
    else process.env.BLAMEJS_FAKE_HARMLESS = prevHarmless;
  }
}

function testErrorsPageModeAutoDetectsFromNodeEnv() {
  var prev = process.env.NODE_ENV;
  try {
    process.env.NODE_ENV = "production";
    var prodHandler = b.errorsPage.create({ audit: false });
    check("NODE_ENV=production → prod mode",         prodHandler.mode === "prod");

    process.env.NODE_ENV = "development";
    var devHandler = b.errorsPage.create({ audit: false });
    check("NODE_ENV=development → dev mode",         devHandler.mode === "dev");

    delete process.env.NODE_ENV;
    var defaultHandler = b.errorsPage.create({ audit: false });
    check("no NODE_ENV → dev mode (safe local default)", defaultHandler.mode === "dev");
  } finally {
    if (prev === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = prev;
  }
}

// ---- log ----
//
// Each test creates an instance with a captured-buffer destination so
// the global log stream stays clean and assertions are deterministic.

function _makeCapturingLog(extraOpts) {
  var captured = { stdout: [], stderr: [] };
  var log = b.log.create(Object.assign({
    destination:      { write: function (line) { captured.stdout.push(line); } },
    errorDestination: { write: function (line) { captured.stderr.push(line); } },
    base:             {},
    redact:           false, // tests bypass redaction unless they opt in
  }, extraOpts || {}));
  return { log: log, captured: captured };
}

function _parseLines(arr) { return arr.map(function (l) { return JSON.parse(l); }); }

function testLogSurface() {
  check("b.log namespace present",                typeof b.log === "object");
  check("b.log.create is a function",             typeof b.log.create === "function");
  check("b.log.LogError is a class",              typeof b.log.LogError === "function");
  check("b.log.LEVELS exposes 5 levels",
        b.log.LEVELS.debug === 0 && b.log.LEVELS.fatal === 4);
  check("b.log.getRequestId is a function",       typeof b.log.getRequestId === "function");
  check("b.log.runWithRequestId is a function",   typeof b.log.runWithRequestId === "function");
}

function testLogEmitsJsonLineToStdout() {
  var t = _makeCapturingLog();
  t.log.info("user logged in", { userId: "u-1" });
  check("info writes one line to stdout",           t.captured.stdout.length === 1);
  check("info does not touch stderr",               t.captured.stderr.length === 0);
  var entry = JSON.parse(t.captured.stdout[0]);
  check("entry has level=info",                     entry.level === "info");
  check("entry has message",                        entry.message === "user logged in");
  check("entry has timestamp ISO-8601",
        typeof entry.timestamp === "string" &&
        /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(entry.timestamp));
  check("entry merged extras",                      entry.userId === "u-1");
  check("line ends with newline",                   /\n$/.test(t.captured.stdout[0]));
}

function testLogRoutesErrorAndFatalToStderr() {
  var t = _makeCapturingLog();
  t.log.warn("approaching limit");
  t.log.error("payment failed");
  t.log.fatal("oom");
  var stdout = _parseLines(t.captured.stdout);
  var stderr = _parseLines(t.captured.stderr);
  check("warn routes to stdout",                    stdout.length === 1 && stdout[0].level === "warn");
  check("error routes to stderr",                   stderr.length === 2);
  check("fatal routes to stderr",                   stderr[1].level === "fatal");
}

function testLogLevelGate() {
  var t = _makeCapturingLog({ level: "warn" });
  t.log.debug("d");
  t.log.info("i");
  t.log.warn("w");
  t.log.error("e");
  check("level=warn drops debug",                   t.captured.stdout.every(function (l) { return JSON.parse(l).level !== "debug"; }));
  check("level=warn drops info",                    t.captured.stdout.every(function (l) { return JSON.parse(l).level !== "info"; }));
  check("level=warn keeps warn",                    _parseLines(t.captured.stdout).filter(function (e) { return e.level === "warn"; }).length === 1);
  check("level=warn keeps error",                   _parseLines(t.captured.stderr).filter(function (e) { return e.level === "error"; }).length === 1);
  check("isLevelEnabled('warn') = true",            t.log.isLevelEnabled("warn") === true);
  check("isLevelEnabled('info') = false",           t.log.isLevelEnabled("info") === false);

  // Dynamic level change
  t.log.setLevel("debug");
  check("getLevel reflects setLevel",               t.log.getLevel() === "debug");
  t.captured.stdout.length = 0;
  t.log.debug("now-allowed");
  check("setLevel('debug') unblocks debug emits",   t.captured.stdout.length === 1);
}

function testLogBindAddsBoundContext() {
  var t = _makeCapturingLog({ base: { service: "myapp" } });
  var auth = t.log.bind({ component: "auth" });
  var detail = auth.bind({ subcomponent: "totp" });

  t.log.info("root msg");
  auth.info("auth msg");
  detail.info("detail msg", { extra: "x" });

  var lines = _parseLines(t.captured.stdout);
  check("root has base context",                    lines[0].service === "myapp" && lines[0].component === undefined);
  check("auth child adds component",                lines[1].component === "auth" && lines[1].service === "myapp");
  check("nested child preserves ancestor context",
        lines[2].component === "auth" && lines[2].subcomponent === "totp" && lines[2].service === "myapp");
  check("nested child still merges extras",         lines[2].extra === "x");

  // bind validation
  var threw = null;
  try { t.log.bind(null); } catch (e) { threw = e; }
  check("bind(null) rejects",                       threw && threw.code === "log/bad-bind");
}

function testLogCoreFieldsCannotBeOverwritten() {
  var t = _makeCapturingLog();
  t.log.info("hi", { level: "STOLEN", message: "STOLEN", timestamp: "STOLEN", userId: "u-1" });
  var entry = JSON.parse(t.captured.stdout[0]);
  check("extras cannot overwrite level",            entry.level === "info");
  check("extras cannot overwrite message",          entry.message === "hi");
  check("extras cannot overwrite timestamp",        entry.timestamp !== "STOLEN");
  check("non-core extras still merged",             entry.userId === "u-1");
  check("clobber attempt flagged",                  entry._overwriteAttempt === true);
}

async function testLogRequestIdViaAls() {
  var t = _makeCapturingLog();
  await t.log.runWithRequestId("req-abc", async function () {
    t.log.info("inside");
    check("getRequestId returns bound id",          t.log.getRequestId() === "req-abc");
    await new Promise(function (r) { setImmediate(r); });
    t.log.info("after-microtask");
  });
  t.log.info("outside");
  var lines = _parseLines(t.captured.stdout);
  check("inside-request line carries requestId",     lines[0].requestId === "req-abc");
  check("requestId persists across microtask",       lines[1].requestId === "req-abc");
  check("outside-request line has no requestId",     lines[2].requestId === undefined);
}

async function testLogMiddlewareSetsRequestId() {
  var t = _makeCapturingLog();
  var mw = t.log.middleware();

  // Simulate a request without an inbound X-Request-Id — middleware
  // generates one and binds it for the entire request callback.
  var setHeaderCalls = [];
  var req1 = { headers: {} };
  var res1 = { setHeader: function (k, v) { setHeaderCalls.push([k, v]); } };
  var calledNext1 = false;
  await new Promise(function (resolve) {
    mw(req1, res1, function () {
      calledNext1 = true;
      t.log.info("during req1");
      resolve();
    });
  });
  check("middleware called next",                   calledNext1);
  check("middleware set req.id",                    typeof req1.id === "string" && req1.id.length === 16);
  check("middleware set X-Request-Id header",
        setHeaderCalls.length === 1 && setHeaderCalls[0][0] === "X-Request-Id" && setHeaderCalls[0][1] === req1.id);
  var entry1 = JSON.parse(t.captured.stdout[0]);
  check("log line during request carries requestId", entry1.requestId === req1.id);

  // Inbound X-Request-Id header is honored
  t.captured.stdout.length = 0;
  var req2 = { headers: { "x-request-id": "client-supplied-id" } };
  var res2 = { setHeader: function () {} };
  await new Promise(function (resolve) {
    mw(req2, res2, function () { t.log.info("during req2"); resolve(); });
  });
  check("middleware honors inbound x-request-id",   req2.id === "client-supplied-id");
  var entry2 = JSON.parse(t.captured.stdout[0]);
  check("inbound id propagates to log line",        entry2.requestId === "client-supplied-id");

  // CRLF in inbound header is stripped (header injection defense)
  t.captured.stdout.length = 0;
  var req3 = { headers: { "x-request-id": "ev\r\nil" } };
  var res3 = { setHeader: function () {} };
  await new Promise(function (resolve) {
    mw(req3, res3, function () { t.log.info("during req3"); resolve(); });
  });
  check("middleware strips CRLF from inbound id",   req3.id === "evil");
}

function testLogRedactsExtras() {
  var t = _makeCapturingLog({ redact: true });
  t.log.info("login", {
    userId:   "u-1",
    password: "should-be-hidden",
    token:    "should-be-hidden",
  });
  var entry = JSON.parse(t.captured.stdout[0]);
  check("redact masks password field",              entry.password === "[REDACTED]");
  check("redact masks token field",                 entry.token === "[REDACTED]");
  check("redact preserves non-sensitive field",     entry.userId === "u-1");
}

function testLogEnvLevelOverride() {
  // When LOG_LEVEL is set, it overrides opts.level. Restore after.
  var prev = process.env.LOG_LEVEL;
  process.env.LOG_LEVEL = "error";
  try {
    var t = _makeCapturingLog({ level: "debug" });
    t.log.info("dropped");
    t.log.error("kept");
    check("env LOG_LEVEL beats opts.level",
          t.captured.stdout.length === 0 &&
          t.captured.stderr.length === 1);
  } finally {
    if (prev === undefined) delete process.env.LOG_LEVEL;
    else process.env.LOG_LEVEL = prev;
  }
}

function testLogConfigValidation() {
  var threw;
  threw = null; try { b.log.create({ level: "loud" }); } catch (e) { threw = e; }
  check("bad level rejects",                        threw && threw.code === "log/bad-level");
  threw = null; try { b.log.create({ level: 99 }); } catch (e) { threw = e; }
  check("numeric level out of range rejects",       threw && threw.code === "log/bad-level");
  threw = null; try { b.log.create({ format: "logfmt" }); } catch (e) { threw = e; }
  check("unsupported format rejects",               threw && threw.code === "log/bad-format");
  threw = null; try { b.log.create({ destination: 42 }); } catch (e) { threw = e; }
  check("non-stream destination rejects",           threw && threw.code === "log/bad-destination");
}

function testLogHandlesUnserializableExtras() {
  var t = _makeCapturingLog();
  var circular = {}; circular.self = circular;
  t.log.info("trouble", { circular: circular });
  var entry = JSON.parse(t.captured.stdout[0]);
  check("circular extras surface as _logError",     entry._logError === "extras not serializable");
  check("core fields still emitted",                entry.message === "trouble" && entry.level === "info");
}

// ---- scheduler ----

function testSchedulerSurface() {
  check("b.scheduler namespace present",          typeof b.scheduler === "object");
  check("b.scheduler.create is a function",       typeof b.scheduler.create === "function");
  check("b.scheduler.parseCron is a function",    typeof b.scheduler.parseCron === "function");
  check("b.scheduler.nextCronFire is a function", typeof b.scheduler.nextCronFire === "function");
  check("b.scheduler.SchedulerError is a class",  typeof b.scheduler.SchedulerError === "function");
}

function testSchedulerCronParser() {
  var p1 = b.scheduler.parseCron("0 2 * * *");
  check("cron parses minute=0",                   p1.minute.has(0) && p1.minute.size === 1);
  check("cron parses hour=2",                     p1.hour.has(2) && p1.hour.size === 1);
  check("cron expands * for dom",                 p1.dom.size === 31);
  check("cron expands * for month",               p1.month.size === 12);
  check("cron expands * for dow",                 p1.dow.size === 7);

  var p2 = b.scheduler.parseCron("*/15 9-17 * * 1-5");
  check("cron */15 expands to 0,15,30,45",
        p2.minute.has(0) && p2.minute.has(15) && p2.minute.has(30) && p2.minute.has(45) && p2.minute.size === 4);
  check("cron 9-17 expands inclusively",          p2.hour.size === 9 && p2.hour.has(9) && p2.hour.has(17));
  check("cron 1-5 dow expands to weekdays",       p2.dow.size === 5 && !p2.dow.has(0) && !p2.dow.has(6));
  check("cron dowRestricted set",                 p2.dowRestricted === true);
  check("cron domRestricted unset on *",          p2.domRestricted === false);

  var p3 = b.scheduler.parseCron("@daily");
  check("@daily shorthand → 0 0 * * *",
        p3.minute.has(0) && p3.minute.size === 1 &&
        p3.hour.has(0) && p3.hour.size === 1);

  var p4 = b.scheduler.parseCron("0,30 * * * 7"); // 7 = Sunday alias
  check("cron dow=7 normalized to 0",             p4.dow.has(0) && !p4.dow.has(7));
  check("cron list 0,30",                         p4.minute.has(0) && p4.minute.has(30) && p4.minute.size === 2);

  // Errors
  var threw;
  threw = null; try { b.scheduler.parseCron(""); } catch (e) { threw = e; }
  check("cron empty rejects",                     threw && threw.code === "scheduler/invalid-cron");
  threw = null; try { b.scheduler.parseCron("0 0 0 0 0"); } catch (e) { threw = e; }
  check("cron value out of range rejects",        threw && threw.code === "scheduler/invalid-cron");
  threw = null; try { b.scheduler.parseCron("60 * * * *"); } catch (e) { threw = e; }
  check("cron minute=60 rejects",                 threw && threw.code === "scheduler/invalid-cron");
  threw = null; try { b.scheduler.parseCron("0 0 * *"); } catch (e) { threw = e; }
  check("cron 4-field rejects",                   threw && threw.code === "scheduler/invalid-cron");
  threw = null; try { b.scheduler.parseCron("*/0 * * * *"); } catch (e) { threw = e; }
  check("cron */0 step rejects",                  threw && threw.code === "scheduler/invalid-cron");
}

function testSchedulerNextCronFire() {
  // 02:00 every day — with no timezone, server-local
  var cron = b.scheduler.parseCron("0 2 * * *");
  var anchor = new Date("2026-04-15T01:30:00Z");
  // Find next fire — server-local; just verify it lands on minute=0, hour=2
  var t = b.scheduler.nextCronFire(cron, anchor, null);
  var d = new Date(t);
  check("cron next-fire lands on minute=0",       d.getMinutes() === 0);
  check("cron next-fire lands on hour=2",         d.getHours() === 2);
  check("cron next-fire is in the future",        t > anchor.getTime());

  // */15 means within the next 15 minutes, there must be a fire
  var cron2 = b.scheduler.parseCron("*/15 * * * *");
  var t2 = b.scheduler.nextCronFire(cron2, anchor, null);
  check("cron */15 next-fire within 15min",       t2 - anchor.getTime() <= 15 * 60 * 1000 + 60000);

  // Timezone-aware: 09:00 in UTC
  var cron3 = b.scheduler.parseCron("0 9 * * *");
  var anchorUtc = new Date("2026-04-15T08:30:00Z");
  var t3 = b.scheduler.nextCronFire(cron3, anchorUtc, "UTC");
  // Wall-clock in UTC at t3 must be 09:00
  var fmt = new Intl.DateTimeFormat("en-US", { timeZone: "UTC", hour: "2-digit", minute: "2-digit", hour12: false });
  var parts = {}; fmt.formatToParts(new Date(t3)).forEach(function (p) { parts[p.type] = p.value; });
  var hr = parseInt(parts.hour, 10); if (hr === 24) hr = 0;
  check("cron tz-aware fires at 09:00 UTC wall-clock",
        hr === 9 && parseInt(parts.minute, 10) === 0);

  // Timezone validation
  var threw = null;
  try {
    var sched = b.scheduler.create();
    sched.schedule({ name: "x", cron: "0 0 * * *", timezone: "Not/A_Zone", run: function () {} });
  } catch (e) { threw = e; }
  check("scheduler rejects invalid IANA timezone",
        threw && threw.code === "scheduler/invalid-timezone");
}

async function testSchedulerScheduleValidation() {
  var sched = b.scheduler.create();
  var threw;

  threw = null; try { sched.schedule(); } catch (e) { threw = e; }
  check("schedule rejects missing spec",          threw && threw.code === "INVALID_SPEC");

  threw = null; try { sched.schedule({}); } catch (e) { threw = e; }
  check("schedule rejects missing name",          threw && threw.code === "INVALID_NAME");

  threw = null;
  try { sched.schedule({ name: "x" }); } catch (e) { threw = e; }
  check("schedule rejects missing cron+every",    threw && threw.code === "INVALID_SPEC");

  threw = null;
  try { sched.schedule({ name: "x", cron: "0 0 * * *", every: 60000, run: function () {} }); }
  catch (e) { threw = e; }
  check("schedule rejects both cron and every",   threw && threw.code === "INVALID_SPEC");

  threw = null;
  try { sched.schedule({ name: "x", every: 60000 }); } catch (e) { threw = e; }
  check("schedule rejects missing job+run",       threw && threw.code === "INVALID_SPEC");

  threw = null;
  try { sched.schedule({ name: "x", every: 500, run: function () {} }); }
  catch (e) { threw = e; }
  check("schedule rejects every<1000ms",          threw && threw.code === "INVALID_SPEC");

  threw = null;
  try { sched.schedule({ name: "x", every: 60000, job: "needs-jobs" }); }
  catch (e) { threw = e; }
  check("schedule with job= rejects when jobs unwired",
        threw && threw.code === "INVALID_SPEC" && /requires opts.jobs/.test(threw.message));

  // Happy path — sets up a task
  sched.schedule({ name: "ok", every: 60000, run: function () {} });
  var listed = sched.list();
  check("schedule populates list()",              listed.length === 1 && listed[0].name === "ok");
  check("listed task has nextRun",                typeof listed[0].nextRun === "string");

  // Duplicate name rejected
  threw = null;
  try { sched.schedule({ name: "ok", every: 60000, run: function () {} }); }
  catch (e) { threw = e; }
  check("schedule rejects duplicate name",        threw && threw.code === "DUPLICATE_NAME");

  await sched.stop();
}

async function testSchedulerDirectFnFires() {
  // Use _fireOnce to drive a deterministic single fire — start() arms a
  // setTimeout we'd otherwise have to wait for. The test verifies the
  // dispatch path (run callback invoked, lastRun set, success audited).
  var fired = 0;
  var sched = b.scheduler.create({ audit: false });
  sched.schedule({
    name:  "tick",
    every: 60000,
    run:   async function () { fired++; },
  });
  sched._fireOnce("tick");
  // Wait one microtask cycle for the promise to settle
  await new Promise(function (r) { setImmediate(r); });
  await new Promise(function (r) { setImmediate(r); });
  check("direct-fn fire ran",                     fired === 1);
  var listed = sched.list();
  check("fire updates lastRun",                   typeof listed[0].lastRun === "string");
  check("fire updates lastFinish",                typeof listed[0].lastFinish === "string");
  check("fire counted in fires",                  listed[0].fires === 1);
  check("running=false after settle",             listed[0].running === false);
  await sched.stop();
}

async function testSchedulerJobDispatch() {
  // Plug a fake jobs-shaped object — schedule { job: "name", payload }
  // should call jobs.enqueue with the right args.
  var calls = [];
  var fakeJobs = {
    enqueue: async function (name, payload, opts) {
      calls.push({ name: name, payload: payload, opts: opts });
      return { jobId: "j-1" };
    },
  };
  var sched = b.scheduler.create({ jobs: fakeJobs, audit: false });
  sched.schedule({
    name:        "nightly",
    every:       60000,
    job:         "cleanup",
    payload:     { scope: "all" },
    enqueueOpts: { maxAttempts: 5 },
  });
  sched._fireOnce("nightly");
  await new Promise(function (r) { setImmediate(r); });
  await new Promise(function (r) { setImmediate(r); });
  check("scheduler dispatched via jobs.enqueue",  calls.length === 1);
  check("dispatched job name correct",            calls[0].name === "cleanup");
  check("dispatched payload forwarded",           calls[0].payload && calls[0].payload.scope === "all");
  check("enqueueOpts forwarded",                  calls[0].opts && calls[0].opts.maxAttempts === 5);
  await sched.stop();
}

async function testSchedulerSkipsWhenStillRunning() {
  // If a previous fire is still in-flight, the next fire should be
  // skipped (counted as a miss) rather than running concurrently.
  var concurrent = 0;
  var maxConcurrent = 0;
  var release;
  var releasePromise = new Promise(function (r) { release = r; });
  var sched = b.scheduler.create({ audit: false });
  sched.schedule({
    name:  "slow",
    every: 60000,
    run:   async function () {
      concurrent++;
      if (concurrent > maxConcurrent) maxConcurrent = concurrent;
      await releasePromise;
      concurrent--;
    },
  });
  sched._fireOnce("slow"); // arm — promise pending until release()
  await new Promise(function (r) { setImmediate(r); });
  sched._fireOnce("slow"); // should skip
  sched._fireOnce("slow"); // should skip
  var listed = sched.list();
  check("overlap fires counted as misses",        listed[0].misses === 2);
  check("max concurrent in-flight stays at 1",    maxConcurrent === 1);
  release(); // let the in-flight finish
  await new Promise(function (r) { setImmediate(r); });
  await new Promise(function (r) { setImmediate(r); });
  await sched.stop();
}

async function testSchedulerLeaderGate() {
  // When opts.cluster reports non-leader, fires must be skipped
  // (counted as nonLeaderSkips) and the run callback must not execute.
  var fired = 0;
  var leader = false;
  var fakeCluster = { isLeader: function () { return leader; } };
  var sched = b.scheduler.create({ cluster: fakeCluster, audit: false });
  sched.schedule({
    name:  "leader-only",
    every: 60000,
    run:   async function () { fired++; },
  });

  sched._fireOnce("leader-only");
  await new Promise(function (r) { setImmediate(r); });
  check("non-leader fire skipped",                fired === 0);
  check("non-leader skip counted",                sched.list()[0].nonLeaderSkips === 1);

  leader = true;
  sched._fireOnce("leader-only");
  await new Promise(function (r) { setImmediate(r); });
  await new Promise(function (r) { setImmediate(r); });
  check("leader fire ran",                        fired === 1);
  check("fires counter reflects leader run",      sched.list()[0].fires === 1);
  await sched.stop();
}

async function testSchedulerErrorRecorded() {
  var sched = b.scheduler.create({ audit: false });
  sched.schedule({
    name:  "boom",
    every: 60000,
    run:   async function () { throw new Error("kaboom"); },
  });
  sched._fireOnce("boom");
  await new Promise(function (r) { setImmediate(r); });
  await new Promise(function (r) { setImmediate(r); });
  var listed = sched.list();
  check("failed fire records lastError",          listed[0].lastError === "kaboom");
  check("failed fire still clears running",       listed[0].running === false);
  await sched.stop();
}

function testSchedulerStartStopIdempotent() {
  var sched = b.scheduler.create({ audit: false });
  sched.schedule({ name: "x", every: 60000, run: function () {} });
  // start/stop pair completes without throwing
  return sched.start().then(function () {
    return sched.start(); // idempotent
  }).then(function () {
    return sched.stop();
  }).then(function () {
    return sched.stop(); // idempotent
  }).then(function () {
    check("scheduler start/stop idempotent",      true);
  });
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
  // Regression for the v0.1.57 fix: pre-fix, random() ran randomBytes
  // through SHA3-512 (fixed 64-byte output) + subarray, which silently
  // truncated requests > 64 bytes. The TOTP 128-byte secret surfaced
  // it. Fixed by switching to SHAKE256 (XOF; arbitrary output length).
  check("generateBytes(128) returns 128 bytes (no SHA3-512 cap)",
        b.crypto.generateBytes(128).length === 128);
  check("generateBytes(256) returns 256 bytes",
        b.crypto.generateBytes(256).length === 256);
  // Two calls produce different bytes (RNG, not deterministic)
  check("generateBytes is non-deterministic",
        !b.crypto.generateBytes(64).equals(b.crypto.generateBytes(64)));

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
  // auth.password — Argon2id app-password hashing (Phase 3 slice 1)
  testAuthPasswordSurface();
  await testAuthPasswordHashShape();
  await testAuthPasswordVerifyRoundTrip();
  await testAuthPasswordVerifyTamperedHash();
  await testAuthPasswordVerifyMalformedHash();
  await testAuthPasswordHashRejectsBadInput();
  await testAuthPasswordNeedsRehash();
  // auth.totp — RFC 6238 TOTP (Phase 3 slice 2)
  testAuthTotpSurface();
  testAuthTotpRfc6238Vectors();
  testAuthTotpGenerateSecret();
  testAuthTotpGenerateAndVerifyRoundTrip();
  testAuthTotpDriftWindow();
  testAuthTotpReplayProtection();
  testAuthTotpVerifyMalformedInput();
  testAuthTotpUriShape();
  testAuthTotpBackupCodes();
  testAuthTotpBadAlgorithmRejected();
  // auth.passkey — WebAuthn (Phase 3 slice 3)
  await testAuthPasskeySurface();
  await testAuthPasskeyStartRegistrationOptions();
  await testAuthPasskeyStartAuthenticationOptions();
  await testAuthPasskeyValidationErrors();
  await testAuthPasskeyExcludeCredentials();
  await testAuthPasskeyCustomHints();
  // template — eval-free server-side HTML template engine (Phase 4 slice 1)
  testTemplateSurface();
  testTemplateEscapeHtml();
  testTemplateBasicRender();
  testTemplateRawExpression();
  testTemplateIfElse();
  testTemplateForLoop();
  testTemplateExpressionGrammar();
  testTemplatePartialInclusion();
  testTemplateLayoutInheritance();
  testTemplateContainmentDefenses();
  testTemplatePrototypeSafety();
  testTemplateCacheAndReset();
  testTemplateMissingViewsDir();
  // render — response helpers paired with the template engine (Phase 4 slice 2)
  testRenderSurface();
  testRenderJson();
  testRenderText();
  testRenderHtmlString();
  testRenderRedirect();
  testRenderDoesNotDoubleWrite();
  testRenderCreateWithEngine();
  testRenderCreateValidation();
  // staticServe — file serving + ETag + SRI (Phase 4 slice 3)
  testStaticServeSurface();
  await testStaticServeBasic();
  await testStaticServeImmutableForHashedPaths();
  await testStaticServeEtagAnd304();
  await testStaticServeHead();
  await testStaticServeContainmentDefenses();
  await testStaticServeIndexFile();
  await testStaticServeMethodGuard();
  await testStaticServeIntegrityHelper();
  // mail — message contract + pluggable transport (Phase 5 slice 4)
  testMailSurface();
  testMailCreateValidation();
  await testMailSendRoundTripViaMemoryTransport();
  await testMailDefaultsAndOverrides();
  await testMailValidation();
  await testMailRecipientArrayAndCcBcc();
  await testMailTransportFailureWraps();
  await testMailFunctionAsTransport();
  await testMailConsoleTransportShape();
  testMailSmtpFactoryValidation();
  testMailResendFactoryValidation();
  testMailHttpFactoryValidation();
  await testMailSmtpRoundTrip();
  await testMailSmtpStarttlsAccept();
  await testMailHttpRoundTripWithCustomVendor();
  await testMailHttpInterpretRejection();
  await testMailHttpInterpretThrows();
  await testMailHttpBadSerializer();
  await testMailResendRoundTrip();
  await testMailResendErrorPaths();
  // deprecate — runtime deprecation warnings + LTS-contract enforcement (Phase 8 slice 8a)
  testDeprecateSurface();
  testDeprecateModeResolution();
  testDeprecateWarnEmitsOnce();
  testDeprecateSilentMode();
  testDeprecateErrorMode();
  testDeprecateDifferentSinceProducesNewLine();
  testDeprecateWarnArgValidation();
  testDeprecateWrap();
  testDeprecateWrapValidation();
  testDeprecateAlias();
  testDeprecateListAndReset();
  // restore-rollback + restore — atomic dataDir swap + storage-backed orchestrator (Phase 7 slice 7e)
  testRestoreRollbackSurface();
  testRestoreRollbackSwap();
  await testRestoreRollbackRoundTrip();
  testRestoreRollbackListAndPurge();
  testRestoreRollbackHandlesEmptyDataDir();
  testRestoreSurface();
  testRestoreCreateValidation();
  await testRestoreRunRoundTrip();
  await testRestoreRollbackUndoesRun();
  await testRestoreRunWithMissingBundle();
  await testRestoreRunWithWrongPassphrase();
  await testRestoreListRollbacksAndPurge();
  await testRestoreInspectWithoutDecrypt();
  // backup — operator-facing orchestration + retention + storage backend (Phase 7 slice 7d)
  testBackupSurface();
  testBackupCreateValidation();
  await testBackupRunListReadDelete();
  await testBackupVaultKeyJsonAsFunction();
  await testBackupVaultKeyJsonAsAsyncFunction();
  await testBackupRetentionPurgeOlder();
  await testBackupRetentionAutoSweepOnRun();
  await testBackupBundleIdValidation();
  await testBackupLocalStorageRejectsExistingDest();
  // restore-bundle — extract an encrypted backup bundle to staging (Phase 7 slice 7c)
  testRestoreBundleSurface();
  await testRestoreBundleRoundTrip();
  await testRestoreBundleFilterSubset();
  await testRestoreBundleWrongPassphrase();
  await testRestoreBundleTamperedBlobDetected();
  await testRestoreBundleChecksumMismatchDetected();
  await testRestoreBundleMissingBlobDetected();
  await testRestoreBundleEncryptedSizeMismatchDetected();
  testRestoreBundleInspectReturnsManifest();
  await testRestoreBundleArgValidation();
  // backup-bundle — encrypted backup bundle producer (Phase 7 slice 7b)
  testBackupBundleSurface();
  await testBackupBundleCreateEndToEnd();
  await testBackupBundlePathTraversalRejected();
  await testBackupBundleRequiredMissing();
  await testBackupBundleEmptyBundleRejected();
  await testBackupBundleArgValidation();
  // backup-manifest — bundle schema + create/validate/parse/serialize (Phase 7 slice 7a)
  testBackupManifestSurface();
  testBackupManifestCreateAndSerialize();
  testBackupManifestValidateRejectsBadFields();
  testBackupManifestRejectsDuplicatePaths();
  testBackupManifestParseRejectsCorruption();
  testBackupManifestSerializeIsCanonical();
  // backup-crypto — Argon2id KDF + XChaCha20-Poly1305 for backup files (Phase 7 slice 7)
  testBackupCryptoSurface();
  await testBackupCryptoDeriveKeyDeterministic();
  await testBackupCryptoRoundTrip();
  await testBackupCryptoStringPlaintext();
  await testBackupCryptoWrongPassphraseFails();
  await testBackupCryptoTamperedCiphertextFails();
  await testBackupCryptoFreshSaltUnique();
  testBackupCryptoChecksumIsSha3_512();
  await testBackupCryptoArgValidation();
  // mtls-ca — CA file-management primitives + engine-pluggable issuance (Phase 7 slice 6)
  testMtlsCaSurface();
  testMtlsCaCreateValidation();
  testMtlsCaParseGeneration();
  testMtlsCaExistsAndStatusWhenAbsent();
  testMtlsCaLoadFailures();
  testMtlsCaCommitAndLoadPlaintext();
  testMtlsCaSealedRequiredMode();
  testMtlsCaSealedDisabledRefusesSealedFile();
  testMtlsCaSealedRequiredRefusesPlaintextFile();
  await testMtlsCaIssuanceRequiresEngine();
  await testMtlsCaInitCaWithEngineGeneratesAndCommits();
  await testMtlsCaInitCaRejectsBadEngineOutput();
  await testMtlsCaGenerateClientCertDelegates();
  await testMtlsCaGenerateClientP12Validation();
  // vault-passphrase-ops — seal / unseal / rotate the vault passphrase wrap (Phase 7 slice 5)
  testVaultPassphraseOpsSurface();
  testVaultPassphraseOpsPreflightChecks();
  await testVaultPassphraseOpsSealUnsealRoundTrip();
  await testVaultPassphraseOpsKeepPlaintext();
  await testVaultPassphraseOpsWrongPassphraseRejected();
  await testVaultPassphraseOpsRotate();
  await testVaultPassphraseOpsRotateRejectsBadOldPassphrase();
  testVaultPassphraseOpsArgValidation();
  await testVaultPassphraseOpsRequiresBufferPassphrase();
  // vault-rotate (diagnostics) — schema drift + round-trip verify (Phase 7 slice 3)
  testVaultRotateSurface();
  testVaultRotateValidateSchemaCleanCase();
  testVaultRotateValidateMissingTable();
  testVaultRotateValidateSealedColMissing();
  testVaultRotateValidateDriftDetection();
  testVaultRotateValidateInfraColumnsAllowlist();
  testVaultRotateVerifyRoundTrip();
  testVaultRotateVerifyDetectsTampering();
  testVaultRotateVerifyRegressionWithOldKeys();
  testVaultRotateVerifyRequiresKeysAndDb();
  await testVaultRotateRotateEndToEnd();
  await testVaultRotateRotateValidation();
  // pqc-agent — outbound HTTPS agent locked to PQC group preference (Phase 7 slice 2)
  testPqcAgentSurface();
  testPqcAgentCreateHasPqcPosture();
  testPqcAgentCannotWeakenCryptoPosture();
  testPqcAgentDefaultIsLazy();
  testPqcAgentCreateHttpHasNoTlsPosture();
  // pqc-gate — TCP-level PQC enforcement on ClientHello (Phase 7 slice 1)
  testPqcGateSurface();
  testClientHelloPqcDetection();
  testPqcGateSocketLifecycle();
  testPqcGateBypassesLocalhost();
  // bundler — content-hashed asset pipeline + manifest (Phase 6 slice 7)
  testBundlerSurface();
  testBundlerCreateValidation();
  await testBundlerBuildHashedOutput();
  await testBundlerHashChangesWithContent();
  await testBundlerHashOff();
  await testBundlerCustomHashLen();
  await testBundlerReadFailure();
  await testBundlerWatchRebuilds();
  // dev — file-watch + child-process restart engine (Phase 6 slice 6)
  testDevSurface();
  await testDevStartSpawnsChildAndArmsWatchers();
  await testDevDebouncesBurstOfEventsToOneRestart();
  await testDevIgnoresMatchingPaths();
  await testDevRestartCoalescesQueuedRestart();
  await testDevStopKillsAndDisarms();
  await testDevUnexpectedExitDoesNotRespawn();
  // cli — `blamejs <cmd>` dispatch + migrate subcommand (Phase 6 slice 5)
  testCliSurface();
  testCliArgParser();
  await testCliVersionAndHelp();
  await testCliMigrateStatus();
  await testCliMigrateUpDown();
  await testCliMigrateValidationErrors();
  await testCliMigrateDownReportsNoOpCleanly();
  await testCliMigrateUpFailureExits1();
  await testCliDevValidation();
  // migrations — public migration runner with up/down/status (Phase 6 slice 4)
  testMigrationsSurface();
  testMigrationsUpAppliesPending();
  testMigrationsStatus();
  testMigrationsDownRollback();
  testMigrationsDownMultiSteps();
  testMigrationsDownRejectsBadSteps();
  testMigrationsRejectsRollbackWithoutDown();
  testMigrationsUpFailureRollsBackTransaction();
  testMigrationsRejectsMalformedFiles();
  // cookies — RFC 6265 cookie primitive + sealed-value access gate (Phase 6 slice 3)
  testCookiesSurface();
  testCookiesParse();
  testCookiesSerialize();
  testCookiesInstanceDefaults();
  testCookiesReadWrite();
  testCookiesSealedRoundTrip();
  // errors-page — router error handler with rich dev page + safe prod page (Phase 6 slice 2)
  testErrorsPageSurface();
  testErrorsPageProdHidesStackAndOriginalMessage();
  testErrorsPageDevShowsStackAndRequestInfo();
  testErrorsPageJsonNegotiation();
  testErrorsPageDevJsonIncludesStack();
  testErrorsPageAppErrorClassification();
  testErrorsPageNeverWritesWhenAlreadyEnded();
  testErrorsPageOnErrorHookCanTakeOver();
  testErrorsPageLogsViaInjectedLogger();
  testErrorsPageDevEnvVarsHonorOptIn();
  testErrorsPageModeAutoDetectsFromNodeEnv();
  // log — structured JSON logging with request-id correlation (Phase 6 slice 1)
  testLogSurface();
  testLogEmitsJsonLineToStdout();
  testLogRoutesErrorAndFatalToStderr();
  testLogLevelGate();
  testLogBindAddsBoundContext();
  testLogCoreFieldsCannotBeOverwritten();
  await testLogRequestIdViaAls();
  await testLogMiddlewareSetsRequestId();
  testLogRedactsExtras();
  testLogEnvLevelOverride();
  testLogConfigValidation();
  testLogHandlesUnserializableExtras();
  // scheduler — cron + interval over jobs (Phase 5 slice 5)
  testSchedulerSurface();
  testSchedulerCronParser();
  testSchedulerNextCronFire();
  await testSchedulerScheduleValidation();
  await testSchedulerDirectFnFires();
  await testSchedulerJobDispatch();
  await testSchedulerSkipsWhenStillRunning();
  await testSchedulerLeaderGate();
  await testSchedulerErrorRecorded();
  await testSchedulerStartStopIdempotent();
  // forms — CSRF tokens + HTML render + validation (Phase 4 slice 4)
  testFormsSurface();
  testFormsCsrfTokenGeneration();
  testFormsCsrfTokenVerify();
  testFormsEscapeAttribute();
  testFormsRenderBasic();
  testFormsRenderEscapesHostileInput();
  testFormsRenderSelectAndPreselection();
  testFormsRenderSubmitOverride();
  testFormsRenderRejectsInvalidSpec();
  testFormsValidateRequired();
  testFormsValidateTypes();
  // auth.jwt — PQC-signed JWT (Phase 3 slice 5, final)
  testAuthJwtSurface();
  await testAuthJwtSignVerifyRoundTripDefault();
  await testAuthJwtMlDsaOptIn();
  await testAuthJwtAlgorithmAllowlist();
  await testAuthJwtExpiration();
  await testAuthJwtNotBefore();
  await testAuthJwtIssuerAudienceSubject();
  await testAuthJwtSignatureTampering();
  await testAuthJwtMalformedTokens();
  await testAuthJwtCritHeaderRejected();
  await testAuthJwtKidPropagation();
  await testAuthJwtMissingKey();
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
  testAuthPasswordSurface:                   testAuthPasswordSurface,
  testAuthPasswordHashShape:                 testAuthPasswordHashShape,
  testAuthPasswordVerifyRoundTrip:           testAuthPasswordVerifyRoundTrip,
  testAuthPasswordVerifyTamperedHash:        testAuthPasswordVerifyTamperedHash,
  testAuthPasswordVerifyMalformedHash:       testAuthPasswordVerifyMalformedHash,
  testAuthPasswordHashRejectsBadInput:       testAuthPasswordHashRejectsBadInput,
  testAuthPasswordNeedsRehash:               testAuthPasswordNeedsRehash,
  testAuthTotpSurface:                       testAuthTotpSurface,
  testAuthTotpRfc6238Vectors:                testAuthTotpRfc6238Vectors,
  testAuthTotpGenerateSecret:                testAuthTotpGenerateSecret,
  testAuthTotpGenerateAndVerifyRoundTrip:    testAuthTotpGenerateAndVerifyRoundTrip,
  testAuthTotpDriftWindow:                   testAuthTotpDriftWindow,
  testAuthTotpReplayProtection:              testAuthTotpReplayProtection,
  testAuthTotpVerifyMalformedInput:          testAuthTotpVerifyMalformedInput,
  testAuthTotpUriShape:                      testAuthTotpUriShape,
  testAuthTotpBackupCodes:                   testAuthTotpBackupCodes,
  testAuthTotpBadAlgorithmRejected:          testAuthTotpBadAlgorithmRejected,
  testAuthPasskeySurface:                    testAuthPasskeySurface,
  testAuthPasskeyStartRegistrationOptions:   testAuthPasskeyStartRegistrationOptions,
  testAuthPasskeyStartAuthenticationOptions: testAuthPasskeyStartAuthenticationOptions,
  testAuthPasskeyValidationErrors:           testAuthPasskeyValidationErrors,
  testAuthPasskeyExcludeCredentials:         testAuthPasskeyExcludeCredentials,
  testAuthPasskeyCustomHints:                testAuthPasskeyCustomHints,
  testAuthJwtSurface:                        testAuthJwtSurface,
  testAuthJwtSignVerifyRoundTripDefault:     testAuthJwtSignVerifyRoundTripDefault,
  testAuthJwtMlDsaOptIn:                     testAuthJwtMlDsaOptIn,
  testAuthJwtAlgorithmAllowlist:             testAuthJwtAlgorithmAllowlist,
  testAuthJwtExpiration:                     testAuthJwtExpiration,
  testAuthJwtNotBefore:                      testAuthJwtNotBefore,
  testAuthJwtIssuerAudienceSubject:          testAuthJwtIssuerAudienceSubject,
  testAuthJwtSignatureTampering:             testAuthJwtSignatureTampering,
  testAuthJwtMalformedTokens:                testAuthJwtMalformedTokens,
  testAuthJwtCritHeaderRejected:             testAuthJwtCritHeaderRejected,
  testAuthJwtKidPropagation:                 testAuthJwtKidPropagation,
  testAuthJwtMissingKey:                     testAuthJwtMissingKey,
  testTemplateSurface:                       testTemplateSurface,
  testTemplateEscapeHtml:                    testTemplateEscapeHtml,
  testTemplateBasicRender:                   testTemplateBasicRender,
  testTemplateRawExpression:                 testTemplateRawExpression,
  testTemplateIfElse:                        testTemplateIfElse,
  testTemplateForLoop:                       testTemplateForLoop,
  testTemplateExpressionGrammar:             testTemplateExpressionGrammar,
  testTemplatePartialInclusion:              testTemplatePartialInclusion,
  testTemplateLayoutInheritance:             testTemplateLayoutInheritance,
  testTemplateContainmentDefenses:           testTemplateContainmentDefenses,
  testTemplatePrototypeSafety:               testTemplatePrototypeSafety,
  testTemplateCacheAndReset:                 testTemplateCacheAndReset,
  testTemplateMissingViewsDir:               testTemplateMissingViewsDir,
  testRenderSurface:                         testRenderSurface,
  testRenderJson:                            testRenderJson,
  testRenderText:                            testRenderText,
  testRenderHtmlString:                      testRenderHtmlString,
  testRenderRedirect:                        testRenderRedirect,
  testRenderDoesNotDoubleWrite:              testRenderDoesNotDoubleWrite,
  testRenderCreateWithEngine:                testRenderCreateWithEngine,
  testRenderCreateValidation:                testRenderCreateValidation,
  testStaticServeSurface:                    testStaticServeSurface,
  testStaticServeBasic:                      testStaticServeBasic,
  testStaticServeImmutableForHashedPaths:    testStaticServeImmutableForHashedPaths,
  testStaticServeEtagAnd304:                 testStaticServeEtagAnd304,
  testStaticServeHead:                       testStaticServeHead,
  testStaticServeContainmentDefenses:        testStaticServeContainmentDefenses,
  testStaticServeIndexFile:                  testStaticServeIndexFile,
  testStaticServeMethodGuard:                testStaticServeMethodGuard,
  testStaticServeIntegrityHelper:            testStaticServeIntegrityHelper,
  testMailSurface:                           testMailSurface,
  testMailCreateValidation:                  testMailCreateValidation,
  testMailSendRoundTripViaMemoryTransport:   testMailSendRoundTripViaMemoryTransport,
  testMailDefaultsAndOverrides:              testMailDefaultsAndOverrides,
  testMailValidation:                        testMailValidation,
  testMailRecipientArrayAndCcBcc:            testMailRecipientArrayAndCcBcc,
  testMailTransportFailureWraps:             testMailTransportFailureWraps,
  testMailFunctionAsTransport:               testMailFunctionAsTransport,
  testMailConsoleTransportShape:             testMailConsoleTransportShape,
  testMailSmtpFactoryValidation:             testMailSmtpFactoryValidation,
  testMailResendFactoryValidation:           testMailResendFactoryValidation,
  testMailHttpFactoryValidation:             testMailHttpFactoryValidation,
  testMailSmtpRoundTrip:                     testMailSmtpRoundTrip,
  testMailSmtpStarttlsAccept:                testMailSmtpStarttlsAccept,
  testMailHttpRoundTripWithCustomVendor:     testMailHttpRoundTripWithCustomVendor,
  testMailHttpInterpretRejection:            testMailHttpInterpretRejection,
  testMailHttpInterpretThrows:               testMailHttpInterpretThrows,
  testMailHttpBadSerializer:                 testMailHttpBadSerializer,
  testMailResendRoundTrip:                   testMailResendRoundTrip,
  testMailResendErrorPaths:                  testMailResendErrorPaths,
  testDeprecateSurface:                      testDeprecateSurface,
  testDeprecateModeResolution:               testDeprecateModeResolution,
  testDeprecateWarnEmitsOnce:                testDeprecateWarnEmitsOnce,
  testDeprecateSilentMode:                   testDeprecateSilentMode,
  testDeprecateErrorMode:                    testDeprecateErrorMode,
  testDeprecateDifferentSinceProducesNewLine: testDeprecateDifferentSinceProducesNewLine,
  testDeprecateWarnArgValidation:            testDeprecateWarnArgValidation,
  testDeprecateWrap:                         testDeprecateWrap,
  testDeprecateWrapValidation:               testDeprecateWrapValidation,
  testDeprecateAlias:                        testDeprecateAlias,
  testDeprecateListAndReset:                 testDeprecateListAndReset,
  testRestoreRollbackSurface:                testRestoreRollbackSurface,
  testRestoreRollbackSwap:                   testRestoreRollbackSwap,
  testRestoreRollbackRoundTrip:              testRestoreRollbackRoundTrip,
  testRestoreRollbackListAndPurge:           testRestoreRollbackListAndPurge,
  testRestoreRollbackHandlesEmptyDataDir:    testRestoreRollbackHandlesEmptyDataDir,
  testRestoreSurface:                        testRestoreSurface,
  testRestoreCreateValidation:               testRestoreCreateValidation,
  testRestoreRunRoundTrip:                   testRestoreRunRoundTrip,
  testRestoreRollbackUndoesRun:              testRestoreRollbackUndoesRun,
  testRestoreRunWithMissingBundle:           testRestoreRunWithMissingBundle,
  testRestoreRunWithWrongPassphrase:         testRestoreRunWithWrongPassphrase,
  testRestoreListRollbacksAndPurge:          testRestoreListRollbacksAndPurge,
  testRestoreInspectWithoutDecrypt:          testRestoreInspectWithoutDecrypt,
  testBackupSurface:                         testBackupSurface,
  testBackupCreateValidation:                testBackupCreateValidation,
  testBackupRunListReadDelete:               testBackupRunListReadDelete,
  testBackupVaultKeyJsonAsFunction:          testBackupVaultKeyJsonAsFunction,
  testBackupVaultKeyJsonAsAsyncFunction:     testBackupVaultKeyJsonAsAsyncFunction,
  testBackupRetentionPurgeOlder:             testBackupRetentionPurgeOlder,
  testBackupRetentionAutoSweepOnRun:         testBackupRetentionAutoSweepOnRun,
  testBackupBundleIdValidation:              testBackupBundleIdValidation,
  testBackupLocalStorageRejectsExistingDest: testBackupLocalStorageRejectsExistingDest,
  testRestoreBundleSurface:                  testRestoreBundleSurface,
  testRestoreBundleRoundTrip:                testRestoreBundleRoundTrip,
  testRestoreBundleFilterSubset:             testRestoreBundleFilterSubset,
  testRestoreBundleWrongPassphrase:          testRestoreBundleWrongPassphrase,
  testRestoreBundleTamperedBlobDetected:     testRestoreBundleTamperedBlobDetected,
  testRestoreBundleChecksumMismatchDetected: testRestoreBundleChecksumMismatchDetected,
  testRestoreBundleMissingBlobDetected:      testRestoreBundleMissingBlobDetected,
  testRestoreBundleEncryptedSizeMismatchDetected: testRestoreBundleEncryptedSizeMismatchDetected,
  testRestoreBundleInspectReturnsManifest:   testRestoreBundleInspectReturnsManifest,
  testRestoreBundleArgValidation:            testRestoreBundleArgValidation,
  testBackupBundleSurface:                   testBackupBundleSurface,
  testBackupBundleCreateEndToEnd:            testBackupBundleCreateEndToEnd,
  testBackupBundlePathTraversalRejected:     testBackupBundlePathTraversalRejected,
  testBackupBundleRequiredMissing:           testBackupBundleRequiredMissing,
  testBackupBundleEmptyBundleRejected:       testBackupBundleEmptyBundleRejected,
  testBackupBundleArgValidation:             testBackupBundleArgValidation,
  testBackupManifestSurface:                 testBackupManifestSurface,
  testBackupManifestCreateAndSerialize:      testBackupManifestCreateAndSerialize,
  testBackupManifestValidateRejectsBadFields: testBackupManifestValidateRejectsBadFields,
  testBackupManifestRejectsDuplicatePaths:   testBackupManifestRejectsDuplicatePaths,
  testBackupManifestParseRejectsCorruption:  testBackupManifestParseRejectsCorruption,
  testBackupManifestSerializeIsCanonical:    testBackupManifestSerializeIsCanonical,
  testBackupCryptoSurface:                   testBackupCryptoSurface,
  testBackupCryptoDeriveKeyDeterministic:    testBackupCryptoDeriveKeyDeterministic,
  testBackupCryptoRoundTrip:                 testBackupCryptoRoundTrip,
  testBackupCryptoStringPlaintext:           testBackupCryptoStringPlaintext,
  testBackupCryptoWrongPassphraseFails:      testBackupCryptoWrongPassphraseFails,
  testBackupCryptoTamperedCiphertextFails:   testBackupCryptoTamperedCiphertextFails,
  testBackupCryptoFreshSaltUnique:           testBackupCryptoFreshSaltUnique,
  testBackupCryptoChecksumIsSha3_512:        testBackupCryptoChecksumIsSha3_512,
  testBackupCryptoArgValidation:             testBackupCryptoArgValidation,
  testMtlsCaSurface:                         testMtlsCaSurface,
  testMtlsCaCreateValidation:                testMtlsCaCreateValidation,
  testMtlsCaParseGeneration:                 testMtlsCaParseGeneration,
  testMtlsCaExistsAndStatusWhenAbsent:       testMtlsCaExistsAndStatusWhenAbsent,
  testMtlsCaLoadFailures:                    testMtlsCaLoadFailures,
  testMtlsCaCommitAndLoadPlaintext:          testMtlsCaCommitAndLoadPlaintext,
  testMtlsCaSealedRequiredMode:              testMtlsCaSealedRequiredMode,
  testMtlsCaSealedDisabledRefusesSealedFile: testMtlsCaSealedDisabledRefusesSealedFile,
  testMtlsCaSealedRequiredRefusesPlaintextFile: testMtlsCaSealedRequiredRefusesPlaintextFile,
  testMtlsCaIssuanceRequiresEngine:          testMtlsCaIssuanceRequiresEngine,
  testMtlsCaInitCaWithEngineGeneratesAndCommits: testMtlsCaInitCaWithEngineGeneratesAndCommits,
  testMtlsCaInitCaRejectsBadEngineOutput:    testMtlsCaInitCaRejectsBadEngineOutput,
  testMtlsCaGenerateClientCertDelegates:     testMtlsCaGenerateClientCertDelegates,
  testMtlsCaGenerateClientP12Validation:     testMtlsCaGenerateClientP12Validation,
  testVaultPassphraseOpsSurface:             testVaultPassphraseOpsSurface,
  testVaultPassphraseOpsPreflightChecks:     testVaultPassphraseOpsPreflightChecks,
  testVaultPassphraseOpsSealUnsealRoundTrip: testVaultPassphraseOpsSealUnsealRoundTrip,
  testVaultPassphraseOpsKeepPlaintext:       testVaultPassphraseOpsKeepPlaintext,
  testVaultPassphraseOpsWrongPassphraseRejected: testVaultPassphraseOpsWrongPassphraseRejected,
  testVaultPassphraseOpsRotate:              testVaultPassphraseOpsRotate,
  testVaultPassphraseOpsRotateRejectsBadOldPassphrase: testVaultPassphraseOpsRotateRejectsBadOldPassphrase,
  testVaultPassphraseOpsArgValidation:       testVaultPassphraseOpsArgValidation,
  testVaultPassphraseOpsRequiresBufferPassphrase: testVaultPassphraseOpsRequiresBufferPassphrase,
  testVaultRotateSurface:                    testVaultRotateSurface,
  testVaultRotateValidateSchemaCleanCase:    testVaultRotateValidateSchemaCleanCase,
  testVaultRotateValidateMissingTable:       testVaultRotateValidateMissingTable,
  testVaultRotateValidateSealedColMissing:   testVaultRotateValidateSealedColMissing,
  testVaultRotateValidateDriftDetection:     testVaultRotateValidateDriftDetection,
  testVaultRotateValidateInfraColumnsAllowlist: testVaultRotateValidateInfraColumnsAllowlist,
  testVaultRotateVerifyRoundTrip:            testVaultRotateVerifyRoundTrip,
  testVaultRotateVerifyDetectsTampering:     testVaultRotateVerifyDetectsTampering,
  testVaultRotateVerifyRegressionWithOldKeys: testVaultRotateVerifyRegressionWithOldKeys,
  testVaultRotateVerifyRequiresKeysAndDb:    testVaultRotateVerifyRequiresKeysAndDb,
  testVaultRotateRotateEndToEnd:             testVaultRotateRotateEndToEnd,
  testVaultRotateRotateValidation:           testVaultRotateRotateValidation,
  testPqcAgentSurface:                       testPqcAgentSurface,
  testPqcAgentCreateHasPqcPosture:           testPqcAgentCreateHasPqcPosture,
  testPqcAgentCannotWeakenCryptoPosture:     testPqcAgentCannotWeakenCryptoPosture,
  testPqcAgentDefaultIsLazy:                 testPqcAgentDefaultIsLazy,
  testPqcAgentCreateHttpHasNoTlsPosture:     testPqcAgentCreateHttpHasNoTlsPosture,
  testPqcGateSurface:                        testPqcGateSurface,
  testClientHelloPqcDetection:               testClientHelloPqcDetection,
  testPqcGateSocketLifecycle:                testPqcGateSocketLifecycle,
  testPqcGateBypassesLocalhost:              testPqcGateBypassesLocalhost,
  testBundlerSurface:                        testBundlerSurface,
  testBundlerCreateValidation:               testBundlerCreateValidation,
  testBundlerBuildHashedOutput:              testBundlerBuildHashedOutput,
  testBundlerHashChangesWithContent:         testBundlerHashChangesWithContent,
  testBundlerHashOff:                        testBundlerHashOff,
  testBundlerCustomHashLen:                  testBundlerCustomHashLen,
  testBundlerReadFailure:                    testBundlerReadFailure,
  testBundlerWatchRebuilds:                  testBundlerWatchRebuilds,
  testDevSurface:                            testDevSurface,
  testDevStartSpawnsChildAndArmsWatchers:    testDevStartSpawnsChildAndArmsWatchers,
  testDevDebouncesBurstOfEventsToOneRestart: testDevDebouncesBurstOfEventsToOneRestart,
  testDevIgnoresMatchingPaths:               testDevIgnoresMatchingPaths,
  testDevRestartCoalescesQueuedRestart:      testDevRestartCoalescesQueuedRestart,
  testDevStopKillsAndDisarms:                testDevStopKillsAndDisarms,
  testDevUnexpectedExitDoesNotRespawn:       testDevUnexpectedExitDoesNotRespawn,
  testCliSurface:                            testCliSurface,
  testCliArgParser:                          testCliArgParser,
  testCliVersionAndHelp:                     testCliVersionAndHelp,
  testCliMigrateStatus:                      testCliMigrateStatus,
  testCliMigrateUpDown:                      testCliMigrateUpDown,
  testCliMigrateValidationErrors:            testCliMigrateValidationErrors,
  testCliMigrateDownReportsNoOpCleanly:      testCliMigrateDownReportsNoOpCleanly,
  testCliMigrateUpFailureExits1:             testCliMigrateUpFailureExits1,
  testCliDevValidation:                      testCliDevValidation,
  testMigrationsSurface:                     testMigrationsSurface,
  testMigrationsUpAppliesPending:            testMigrationsUpAppliesPending,
  testMigrationsStatus:                      testMigrationsStatus,
  testMigrationsDownRollback:                testMigrationsDownRollback,
  testMigrationsDownMultiSteps:              testMigrationsDownMultiSteps,
  testMigrationsDownRejectsBadSteps:         testMigrationsDownRejectsBadSteps,
  testMigrationsRejectsRollbackWithoutDown:  testMigrationsRejectsRollbackWithoutDown,
  testMigrationsUpFailureRollsBackTransaction: testMigrationsUpFailureRollsBackTransaction,
  testMigrationsRejectsMalformedFiles:       testMigrationsRejectsMalformedFiles,
  testCookiesSurface:                        testCookiesSurface,
  testCookiesParse:                          testCookiesParse,
  testCookiesSerialize:                      testCookiesSerialize,
  testCookiesInstanceDefaults:               testCookiesInstanceDefaults,
  testCookiesReadWrite:                      testCookiesReadWrite,
  testCookiesSealedRoundTrip:                testCookiesSealedRoundTrip,
  testErrorsPageSurface:                     testErrorsPageSurface,
  testErrorsPageProdHidesStackAndOriginalMessage: testErrorsPageProdHidesStackAndOriginalMessage,
  testErrorsPageDevShowsStackAndRequestInfo: testErrorsPageDevShowsStackAndRequestInfo,
  testErrorsPageJsonNegotiation:             testErrorsPageJsonNegotiation,
  testErrorsPageDevJsonIncludesStack:        testErrorsPageDevJsonIncludesStack,
  testErrorsPageAppErrorClassification:      testErrorsPageAppErrorClassification,
  testErrorsPageNeverWritesWhenAlreadyEnded: testErrorsPageNeverWritesWhenAlreadyEnded,
  testErrorsPageOnErrorHookCanTakeOver:      testErrorsPageOnErrorHookCanTakeOver,
  testErrorsPageLogsViaInjectedLogger:       testErrorsPageLogsViaInjectedLogger,
  testErrorsPageDevEnvVarsHonorOptIn:        testErrorsPageDevEnvVarsHonorOptIn,
  testErrorsPageModeAutoDetectsFromNodeEnv:  testErrorsPageModeAutoDetectsFromNodeEnv,
  testLogSurface:                            testLogSurface,
  testLogEmitsJsonLineToStdout:              testLogEmitsJsonLineToStdout,
  testLogRoutesErrorAndFatalToStderr:        testLogRoutesErrorAndFatalToStderr,
  testLogLevelGate:                          testLogLevelGate,
  testLogBindAddsBoundContext:               testLogBindAddsBoundContext,
  testLogCoreFieldsCannotBeOverwritten:      testLogCoreFieldsCannotBeOverwritten,
  testLogRequestIdViaAls:                    testLogRequestIdViaAls,
  testLogMiddlewareSetsRequestId:            testLogMiddlewareSetsRequestId,
  testLogRedactsExtras:                      testLogRedactsExtras,
  testLogEnvLevelOverride:                   testLogEnvLevelOverride,
  testLogConfigValidation:                   testLogConfigValidation,
  testLogHandlesUnserializableExtras:        testLogHandlesUnserializableExtras,
  testSchedulerSurface:                      testSchedulerSurface,
  testSchedulerCronParser:                   testSchedulerCronParser,
  testSchedulerNextCronFire:                 testSchedulerNextCronFire,
  testSchedulerScheduleValidation:           testSchedulerScheduleValidation,
  testSchedulerDirectFnFires:                testSchedulerDirectFnFires,
  testSchedulerJobDispatch:                  testSchedulerJobDispatch,
  testSchedulerSkipsWhenStillRunning:        testSchedulerSkipsWhenStillRunning,
  testSchedulerLeaderGate:                   testSchedulerLeaderGate,
  testSchedulerErrorRecorded:                testSchedulerErrorRecorded,
  testSchedulerStartStopIdempotent:          testSchedulerStartStopIdempotent,
  testFormsSurface:                          testFormsSurface,
  testFormsCsrfTokenGeneration:              testFormsCsrfTokenGeneration,
  testFormsCsrfTokenVerify:                  testFormsCsrfTokenVerify,
  testFormsEscapeAttribute:                  testFormsEscapeAttribute,
  testFormsRenderBasic:                      testFormsRenderBasic,
  testFormsRenderEscapesHostileInput:        testFormsRenderEscapesHostileInput,
  testFormsRenderSelectAndPreselection:      testFormsRenderSelectAndPreselection,
  testFormsRenderSubmitOverride:             testFormsRenderSubmitOverride,
  testFormsRenderRejectsInvalidSpec:         testFormsRenderRejectsInvalidSpec,
  testFormsValidateRequired:                 testFormsValidateRequired,
  testFormsValidateTypes:                    testFormsValidateTypes,
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
