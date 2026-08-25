// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * release.js fail-closed lookups.
 *
 * The orchestrator asks `git` and `gh` questions and gates the release on the
 * answers. Its capture helper returns `stdout: ""` for BOTH "the command
 * succeeded and printed nothing" and "the command never ran" — and every gate
 * that resolved that ambiguity by reading `.stdout` directly resolved it the
 * permissive way:
 *
 *   - a failed `git status`   read as a CLEAN working tree
 *   - a failed `git diff`     read as NO backend touched, skipping the
 *                             non-skippable live-integration gate
 *   - a failed `git diff`     read as the wiki being untouched, skipping e2e
 *   - a failed `gh pr list`   read as "no open PR for branch X"
 *   - a failed `gh pr view`   read as "Codex has not reviewed", burning the
 *                             full 10-minute wait and then blaming Codex
 *   - a failed `gh run list`  read as "workflow may not be configured"
 *   - a failed `git tag -l`   read as the tag not existing
 *
 * Every one of those lets the release proceed past a gate that never ran.
 * These tests drive the real functions with a capture stub that fails, and
 * assert each refuses. The companion structural gate is
 * `release-script-capture-status-unchecked` in codebase-patterns.
 *
 * Hermetic: no network, no git invocation, no docker. The `_setCaptureForTest`
 * and `_setRunForTest` seams replace the shell-out entirely.
 */

var helpers = require("../helpers");
var check   = helpers.check;

var release = require("../../scripts/release.js");

// ---- stub harness --------------------------------------------------------

// A capture result the way spawnSync reports each failure mode.
function _okResult(stdout) {
  return { status: 0, stdout: stdout || "", stderr: "", spawnError: null };
}
function _failResult(stderr, status) {
  return { status: status === undefined ? 1 : status, stdout: "", stderr: stderr || "", spawnError: null };
}
function _spawnFailResult(code) {
  return { status: null, stdout: "", stderr: "", spawnError: code || "ENOENT" };
}

// Install a capture stub for the duration of `body`, always restoring the real
// one. `handler(cmd, args)` returns a result; `calls` records every invocation
// so a test can assert on retry counts.
function withCapture(handler, body) {
  var calls = [];
  release._setCaptureForTest(function (cmd, args) {
    calls.push({ cmd: cmd, args: (args || []).slice() });
    return handler(cmd, args || [], calls.length);
  });
  try { return body(calls); }
  finally { release._setCaptureForTest(null); }
}

// Same, for the mutating half — so a cmd* function under test never actually
// runs a gate, a commit or a push.
function withRun(handler, body) {
  var calls = [];
  release._setRunForTest(function (cmd, args, opts) {
    calls.push({ cmd: cmd, args: (args || []).slice() });
    return handler ? handler(cmd, args || [], opts) : { status: 0 };
  });
  try { return body(calls); }
  finally { release._setRunForTest(null); }
}

// Capture console output so a test can assert what the operator was told.
function withQuietConsole(body) {
  var lines = [];
  var realLog = console.log, realErr = console.error;
  console.log   = function () { lines.push(Array.prototype.join.call(arguments, " ")); };
  console.error = function () { lines.push(Array.prototype.join.call(arguments, " ")); };
  try { return body(lines); }
  finally { console.log = realLog; console.error = realErr; }
}

function threw(fn) {
  try { fn(); return null; }
  catch (e) { return (e && e.message) || String(e); }
}

// Collapse the retry backoff so a case that exhausts the attempt budget costs
// microseconds rather than the real four seconds.
function withFastRetry(body) {
  var saved = release.QUERY_BACKOFF_MS.slice();
  for (var i = 0; i < release.QUERY_BACKOFF_MS.length; i += 1) release.QUERY_BACKOFF_MS[i] = 0;
  try { return body(); }
  finally { saved.forEach(function (v, i) { release.QUERY_BACKOFF_MS[i] = v; }); }
}

// ---- _captureOk ----------------------------------------------------------

function testCaptureOkPassesThroughSuccess() {
  withCapture(function () { return _okResult("the answer"); }, function () {
    var rv = release._captureOk("a question", "git", ["status"]);
    check("_captureOk returns the result on exit 0", rv.stdout === "the answer");
  });
}

function testCaptureOkThrowsOnNonZero() {
  withCapture(function () { return _failResult("fatal: not a git repository"); }, function () {
    var msg = threw(function () { release._captureOk("working-tree status", "git", ["status", "--porcelain"]); });
    check("_captureOk throws on a non-zero exit", msg !== null);
    check("...naming what was being asked", msg.indexOf("working-tree status") !== -1);
    check("...naming the command line", msg.indexOf("git status --porcelain") !== -1);
    check("...quoting the tool's own error", msg.indexOf("not a git repository") !== -1);
    check("...stating the principle", msg.indexOf("An unreadable result is not an empty one") !== -1);
  });
}

// A binary that is not installed reports status null with BOTH streams empty.
// That is the case most easily mistaken for "succeeded, printed nothing".
function testCaptureOkDescribesASpawnFailure() {
  withCapture(function () { return _spawnFailResult("ENOENT"); }, function () {
    var msg = threw(function () { release._captureOk("open PR", "gh", ["pr", "list"]); });
    check("_captureOk throws when the binary could not be spawned", msg !== null);
    check("...saying it could not be spawned", msg.indexOf("could not be spawned") !== -1);
    check("...carrying the spawn error code", msg.indexOf("ENOENT") !== -1);
    check("...not reporting a bare `exited null`", msg.indexOf("exited null") === -1);
  });
}

// ---- transient classification -------------------------------------------

// Grounded in what the tools actually print — every string here was captured
// from a real failure, not invented.
function testTransientClassification() {
  var transient = [
    "error connecting to api.github.com\ncheck your internet connection or https://githubstatus.com",
    "remote error: tls: handshake failure",
    "read tcp 10.0.0.2:52134->140.82.121.6:443: connection reset by peer",
    "Post \"https://api.github.com/graphql\": net/http: TLS handshake timeout",
    "gh: You have exceeded a secondary rate limit (HTTP 403)",
    "gh: Server Error (HTTP 502)",
    "dial tcp: lookup api.github.com: no such host",
    "npm ERR! network request to https://registry.npmjs.org/ failed, reason: socket hang up",
    "npm ERR! code ETIMEDOUT",
  ];
  transient.forEach(function (stderr) {
    check("transient: " + stderr.slice(0, 42),
      release._isTransientQueryFailure(_failResult(stderr)) === true);
  });

  var stable = [
    "gh: Bad credentials (HTTP 401)",
    "gh: Not Found (HTTP 404)",
    "GraphQL: Could not resolve to a Repository with the name 'blamejs/nope'.",
    "fatal: not a git repository (or any of the parent directories): .git",
    "gh: Resource not accessible by integration (HTTP 403)",
  ];
  stable.forEach(function (stderr) {
    check("stable: " + stderr.slice(0, 42),
      release._isTransientQueryFailure(_failResult(stderr)) === false);
  });

  // A missing binary never heals — retrying it is pure latency.
  check("a spawn failure is never transient",
    release._isTransientQueryFailure(_spawnFailResult("ENOENT")) === false);
}

// ---- _captureQuery retry -------------------------------------------------

function testQueryRetriesATransientFailure() {
  withQuietConsole(function () {
    withFastRetry(function () {
      withCapture(function (cmd, args, nth) {
        return nth === 1 ? _failResult("error connecting to api.github.com") : _okResult("42");
      }, function (calls) {
        var rv = release._captureQuery("open PR", "gh", ["pr", "list"]);
        check("a transient failure is retried and succeeds", rv.stdout === "42");
        check("...on the second attempt", calls.length === 2);
      });
    });
  });
}

function testQueryDoesNotRetryAStableFailure() {
  withQuietConsole(function () {
    withFastRetry(function () {
      withCapture(function () { return _failResult("gh: Bad credentials (HTTP 401)"); }, function (calls) {
        var msg = threw(function () { release._captureQuery("open PR", "gh", ["pr", "list"]); });
        check("a stable failure throws", msg !== null);
        check("...without burning retries", calls.length === 1);
        check("...surfacing the real cause", msg.indexOf("Bad credentials") !== -1);
      });
    });
  });
}

function testQueryGivesUpAfterTheAttemptBudget() {
  withQuietConsole(function () {
    withFastRetry(function () {
      withCapture(function () { return _failResult("error connecting to api.github.com"); }, function (calls) {
        var msg = threw(function () { release._captureQuery("open PR", "gh", ["pr", "list"]); });
        check("a persistent transient failure eventually throws", msg !== null);
        check("...after exactly the attempt budget", calls.length === release.QUERY_ATTEMPTS);
      });
    });
  });
}

// The tagging the polling caller branches on: a give-up after transient
// failures is marked transient, a stable rejection is not.
function testQueryFailuresAreTagged() {
  withQuietConsole(function () {
    withFastRetry(function () {
      withCapture(function () { return _failResult("error connecting to api.github.com"); }, function () {
        var e = null;
        try { release._captureQuery("open PR", "gh", ["pr", "list"]); } catch (err) { e = err; }
        check("a transient give-up is tagged lookupFailed", e && e.lookupFailed === true);
        check("...and tagged transient", e && e.transient === true);
      });
      withCapture(function () { return _failResult("gh: Bad credentials (HTTP 401)"); }, function () {
        var e2 = null;
        try { release._captureQuery("open PR", "gh", ["pr", "list"]); } catch (err) { e2 = err; }
        check("a stable failure is tagged lookupFailed", e2 && e2.lookupFailed === true);
        check("...but NOT transient", e2 && e2.transient === false);
      });
    });
  });
}

// ---- _openPrNumber — the reported symptom --------------------------------

function testOpenPrNumberFailsClosedOnAnUnreadableLookup() {
  withQuietConsole(function () {
    withCapture(function () { return _failResult("gh: Bad credentials (HTTP 401)"); }, function () {
      var msg = threw(function () { release._openPrNumber("release/v9.9.9"); });
      check("an unreadable PR lookup throws", msg !== null);
      check("...NOT as 'no open PR'", msg.indexOf("no open PR") === -1);
      check("...but naming the gh failure", msg.indexOf("Bad credentials") !== -1);
    });
  });
}

// The genuine empty answer must still read as "no PR" — `gh pr list --jq
// '.[0].number'` exits 0 with empty stdout when the branch has none, so
// failing closed must not swallow that case.
function testOpenPrNumberStillReportsAGenuineAbsence() {
  withCapture(function () { return _okResult(""); }, function () {
    var msg = threw(function () { release._openPrNumber("release/v9.9.9"); });
    check("exit 0 + empty stdout still means no open PR",
      msg !== null && msg.indexOf("no open PR") !== -1);
  });
}

function testOpenPrNumberReturnsTheNumber() {
  withCapture(function () { return _okResult("588"); }, function () {
    check("a found PR number is returned", release._openPrNumber("release/v0.18.31") === "588");
  });
}

// ---- live-integration backend detection ----------------------------------

// The worst of the fail-opens: the changed-file set feeds backend detection,
// and an empty set means "no backend touched" — which skips the live
// integration gate, the one gate a release that changes a backend protocol is
// not allowed to skip.
function testBackendDetectionFailsClosedOnAFailedDiff() {
  withCapture(function (cmd, args) {
    // The base-ref existence probe legitimately answers with a non-zero exit.
    if (args[0] === "rev-parse") return _okResult("");
    return _failResult("fatal: bad revision");
  }, function () {
    var msg = threw(function () { release._changedFilesForBackendDetection(); });
    check("a failed changed-file lookup throws", msg !== null);
    check("...rather than reporting an empty change set", msg.indexOf("bad revision") !== -1);
  });
}

function testBackendDetectionStillReadsARealDiff() {
  withCapture(function (cmd, args) {
    if (args[0] === "rev-parse") return _okResult("");
    if (args[0] === "diff" && args.indexOf("--cached") === -1 && args.length === 3) {
      return _okResult("lib/redis-client.js\nlib/queue-redis.js");
    }
    return _okResult("");
  }, function () {
    var changed = release._changedFilesForBackendDetection();
    check("a real diff is read", changed.indexOf("lib/redis-client.js") !== -1);
    var touched = release._detectTouchedBackends(changed);
    check("...and maps onto the redis backend",
      touched.some(function (t) { return t.backend === "redis"; }));
  });
}

// The base-ref probe is the one git call whose non-zero exit IS an answer
// (origin/main not fetched -> fall back to local main). Failing closed must
// not break that fallback.
function testBackendDetectionFallsBackWhenOriginMainIsAbsent() {
  withCapture(function (cmd, args) {
    if (args[0] === "rev-parse") return _failResult("", 1);   // origin/main absent
    if (args[0] === "diff" && args.indexOf("main...HEAD") !== -1) return _okResult("lib/mail-send.js");
    return _okResult("");
  }, function (calls) {
    var changed = release._changedFilesForBackendDetection();
    check("an absent origin/main falls back to local main",
      calls.some(function (c) { return c.args.indexOf("main...HEAD") !== -1; }));
    check("...and still detects the backend", release._detectTouchedBackends(changed)
      .some(function (t) { return t.backend === "smtp-mail"; }));
  });
}

// ---- wiki e2e decision ---------------------------------------------------

// Driven through _wikiTouched rather than cmdSmoke on purpose: cmdSmoke wipes
// examples/wiki/data and data-e2e before running the e2e, and a test must
// never do that to the real working tree — under SMOKE_PARALLEL it could fire
// while the wiki e2e is using those directories.
function testWikiTouchedFailsClosedOnAFailedDiff() {
  withCapture(function (cmd, args) {
    if (args[0] === "rev-parse") return _okResult("");
    return _failResult("fatal: bad revision 'origin/main'");
  }, function () {
    var msg = threw(function () { release._wikiTouched(); });
    check("a failed wiki diff throws", msg !== null);
    check("...rather than silently skipping the e2e gate", msg.indexOf("bad revision") !== -1);
  });
}

function testWikiTouchedReadsBothDiffs() {
  withCapture(function (cmd, args) {
    if (args[0] === "rev-parse") return _okResult("");
    return _okResult("examples/wiki/lib/site.js");
  }, function () {
    check("a committed wiki change is detected", release._wikiTouched() === true);
  });

  // Only the working tree touched it — the committed diff is clean.
  withCapture(function (cmd, args) {
    if (args[0] === "rev-parse") return _okResult("");
    if (args.indexOf("...HEAD") !== -1 || args[2] === "origin/main...HEAD") return _okResult("lib/db.js");
    if (args.length === 2) return _okResult("examples/wiki/site.config.js");
    return _okResult("");
  }, function () {
    check("an uncommitted wiki change is detected too", release._wikiTouched() === true);
  });

  withCapture(function (cmd, args) {
    if (args[0] === "rev-parse") return _okResult("");
    return _okResult("lib/db.js\nlib/crypto.js");
  }, function () {
    check("a release that leaves the wiki alone reports untouched",
      release._wikiTouched() === false);
  });
}

// cmdSmoke's fail-closed path must abort BEFORE the data-directory wipe, so an
// unreadable diff never destroys wiki state on its way to refusing.
function testSmokeAbortsBeforeTouchingWikiData() {
  var wikiData = require("node:path").resolve(__dirname, "..", "..", "examples", "wiki", "data");
  var fs = require("node:fs");
  var existedBefore = fs.existsSync(wikiData);
  withQuietConsole(function () {
    withRun(null, function () {
      withCapture(function (cmd, args) {
        if (args[0] === "rev-parse") return _okResult("");
        return _failResult("fatal: bad revision 'origin/main'");
      }, function () {
        check("cmdSmoke refuses on an unreadable wiki diff",
          threw(function () { release.cmdSmoke(); }) !== null);
      });
    });
  });
  check("...without having wiped the wiki data directory",
    fs.existsSync(wikiData) === existedBefore);
}

// ---- Codex review wait ---------------------------------------------------

// A failed head lookup used to return false, which the 10-minute poll read as
// "Codex has not reviewed yet" — so a gh outage spent the whole budget and
// then reported it as Codex being late.
function testCodexHeadLookupFailsClosed() {
  withQuietConsole(function () {
    withCapture(function () { return _failResult("gh: Bad credentials (HTTP 401)"); }, function () {
      var msg = threw(function () { release._codexReviewedHead("588"); });
      check("an unreadable head lookup throws", msg !== null);
      check("...naming the gh failure rather than reporting 'not reviewed'",
        msg.indexOf("Bad credentials") !== -1);
    });
  });
}

// ---- the Codex wait absorbs a blip but never calls it "not reviewed" -----

// Run `body` with the poll cadence collapsed so the branching is testable
// without a ten-minute test.
// The budget is now measured against the WALL CLOCK (a tick can spend the
// query-retry budget inside the lookup, which summing stepMs never counted),
// so it has to be large enough for a few collapsed-backoff retries while still
// bounding the test. withFastRetry keeps those retries free.
function withFastCodexWait(body) {
  var step = release.CODEX_WAIT.stepMs, budget = release.CODEX_WAIT.budgetMs;
  release.CODEX_WAIT.stepMs   = 1;
  release.CODEX_WAIT.budgetMs = 250;
  try { return withFastRetry(body); }
  finally { release.CODEX_WAIT.stepMs = step; release.CODEX_WAIT.budgetMs = budget; }
}

// The poll IS a retry loop far longer than _captureQuery's, so a connection
// blip must be re-asked on the next tick rather than aborting the merge.
function testCodexWaitAbsorbsATransientBlip() {
  withQuietConsole(function () {
    withFastCodexWait(function () {
      var head = "a".repeat(40);
      var ticks = 0;
      withCapture(function (cmd, args) {
        if (args.indexOf("headRefOid") !== -1) {
          ticks += 1;
          if (ticks <= release.QUERY_ATTEMPTS) return _failResult("error connecting to api.github.com");
          return _okResult(head);
        }
        if (args[1] === "graphql") {
          return _okResult(JSON.stringify([{ author: { login: "chatgpt-codex-connector" },
                                             commit: { oid: head } }]));
        }
        return _okResult("[]");
      }, function () {
        var msg = threw(function () { release._waitForCodexReview("588"); });
        check("a transient blip does not abort the wait", msg === null);
      });
    });
  });
}

// A rejected token cannot be fixed by asking again for ten minutes.
function testCodexWaitAbortsOnAStableFailure() {
  withQuietConsole(function () {
    withFastCodexWait(function () {
      withCapture(function () { return _failResult("gh: Bad credentials (HTTP 401)"); }, function () {
        var msg = threw(function () { release._waitForCodexReview("588"); });
        check("a stable failure aborts the wait", msg !== null);
        check("...naming the real cause", msg.indexOf("Bad credentials") !== -1);
        check("...not blaming Codex for being slow", msg.indexOf("has not reviewed") === -1);
      });
    });
  });
}

// The failure this whole change exists to prevent: a lookup that never
// succeeded is UNKNOWN, and must not be reported as Codex not having reviewed.
function testCodexWaitTimeoutSaysUnknownNotNo() {
  withQuietConsole(function () {
    withFastCodexWait(function () {
      withCapture(function () { return _failResult("error connecting to api.github.com"); }, function () {
        var msg = threw(function () { release._waitForCodexReview("588"); });
        check("a wait whose lookups never succeeded throws", msg !== null);
        check("...reporting the review state as UNKNOWN", msg.indexOf("UNKNOWN") !== -1);
        check("...explicitly not as 'no'", msg.indexOf("(not 'no')") !== -1);
        check("...and not as Codex having failed to review",
          msg.indexOf("Codex has not reviewed") === -1);
      });
    });
  });
}

// A reachable API that simply has no Codex review yet still reports the
// original, correct message — failing closed must not swallow the real case.
function testCodexWaitStillReportsAGenuineAbsence() {
  withQuietConsole(function () {
    withFastCodexWait(function () {
      withCapture(function (cmd, args) {
        if (args.indexOf("headRefOid") !== -1) return _okResult("b".repeat(40));
        return _okResult("[]");
      }, function () {
        var msg = threw(function () { release._waitForCodexReview("588"); });
        check("a genuinely un-reviewed head still times out as such",
          msg !== null && msg.indexOf("Codex has not reviewed") !== -1);
      });
    });
  });
}

// Moving the loop CONDITION to the clock is only half the job: an unconditional
// full-step sleep at the end of the last pass carries the wait past the budget
// it advertises, and the retries inside a lookup push it further still. The
// sleep has to respect the same clock the condition does.
function testCodexWaitHonoursItsWallClockBudget() {
  var step = release.CODEX_WAIT.stepMs, budget = release.CODEX_WAIT.budgetMs;
  // A step far larger than the budget: one overrunning sleep is unmissable.
  //
  // The separation carries this, not the tolerance. At a 400ms step the correct
  // path finished in ~60ms and the broken one in ~460ms, so a 260ms ceiling sat
  // between two outcomes only 400ms apart — and a 64-way container run put the
  // correct path at 377ms purely in scheduling overhead, failing it. A step of
  // several seconds puts the two outcomes an order of magnitude apart, so
  // contention has nowhere near enough room to cross the line.
  release.CODEX_WAIT.stepMs   = 5000;
  release.CODEX_WAIT.budgetMs = 60;
  try {
    withQuietConsole(function () {
      withFastRetry(function () {
        withCapture(function (cmd, args) {
          if (args.indexOf("headRefOid") !== -1) return _okResult("c".repeat(40));
          return _okResult("[]");
        }, function () {
          var startedAt = Date.now();
          threw(function () { release._waitForCodexReview("588"); });
          var elapsed = Date.now() - startedAt;
          // Half a step: the point is that it cannot overshoot by a whole
          // step, not that it lands on the millisecond. A correct wait returns
          // in tens of milliseconds plus whatever the scheduler adds; one that
          // sleeps a final full step cannot come in under 5000.
          check("the wait stops within its advertised budget (elapsed " + elapsed + "ms)",
            elapsed < release.CODEX_WAIT.stepMs / 2,
            elapsed + "ms against a " + release.CODEX_WAIT.stepMs + "ms step");
        });
      });
    });
  } finally {
    release.CODEX_WAIT.stepMs = step; release.CODEX_WAIT.budgetMs = budget;
  }
}

// ---- publish / status reporting -----------------------------------------

// "no npm-publish run found (workflow may not be configured)" is a very
// different statement from "the lookup failed", and the second must not print
// as the first.
function testPublishFailsClosedOnAFailedRunLookup() {
  withQuietConsole(function () {
    withRun(null, function () {
      withCapture(function () { return _failResult("gh: Bad credentials (HTTP 401)"); }, function () {
        var msg = threw(function () { release.cmdPublish(); });
        check("a failed workflow-run lookup throws", msg !== null);
        check("...rather than claiming the workflow may not be configured",
          msg.indexOf("may not be configured") === -1);
      });
    });
  });
}

// `status` is read-only and must stay runnable when the network is down — but
// it has to SAY the lookup failed rather than print "(none)".
function testStatusReportsALookupFailureRatherThanNone() {
  withRun(null, function () {
   withFastRetry(function () {
    withCapture(function (cmd, args) {
      if (cmd === "gh") return _failResult("error connecting to api.github.com");
      if (args[0] === "status") return _okResult("");
      return _okResult("main");
    }, function () {
      withQuietConsole(function (lines) {
        release.cmdStatus();
        var text = lines.join("\n");
        check("status does not throw on an unreadable PR lookup", true);
        check("...and does not report the failure as '(none)'",
          text.indexOf("open PR:          (none)") === -1);
        check("...but says the lookup failed", text.toLowerCase().indexOf("lookup failed") !== -1);
      });
    });
   });
  });
}

// The same command with the network up and no PR must still print "(none)" —
// failing closed must not turn a real absence into a reported failure.
function testStatusStillReportsNoneWhenThereIsNoPr() {
  withRun(null, function () {
    withCapture(function (cmd, args) {
      if (cmd === "gh") return _okResult("");
      if (args[0] === "status") return _okResult("");
      return _okResult("main");
    }, function () {
      withQuietConsole(function (lines) {
        release.cmdStatus();
        check("a genuine absence still prints (none)",
          lines.join("\n").indexOf("open PR:          (none)") !== -1);
      });
    });
  });
}

// ---- tag ----------------------------------------------------------------

function testTagFailsClosedOnAFailedTagProbe() {
  withQuietConsole(function () {
    withRun(null, function () {
      withCapture(function (cmd, args) {
        if (args[0] === "rev-parse") return _okResult("main");
        if (args[0] === "tag" && args[1] === "-l") return _failResult("fatal: not a git repository");
        return _okResult("");
      }, function () {
        var msg = threw(function () { release.cmdTag(); });
        check("a failed existing-tag probe throws", msg !== null);
        check("...rather than proceeding as if the tag were absent",
          msg.indexOf("not a git repository") !== -1);
      });
    });
  });
}

// ---- the working-tree and branch reads -----------------------------------

function testGitCleanAndBranchFailClosed() {
  withCapture(function () { return _failResult("fatal: not a git repository"); }, function () {
    check("a failed `git status` does not report a clean tree",
      threw(function () { release._gitClean(); }) !== null);
    check("a failed branch read does not report an empty branch",
      threw(function () { release._gitBranch(); }) !== null);
  });
  withCapture(function () { return _okResult(""); }, function () {
    check("an actually-clean tree still reads clean", release._gitClean() === true);
  });
  withCapture(function () { return _okResult(" M lib/x.js"); }, function () {
    check("a dirty tree still reads dirty", release._gitClean() === false);
  });
}

// ---- _ghJson still fails closed -----------------------------------------

function testGhJsonFailsClosed() {
  check("_ghJson throws on a non-zero exit",
    threw(function () { release._ghJson(_failResult("boom"), "a lookup"); }) !== null);
  check("_ghJson throws on an unparseable payload",
    threw(function () { release._ghJson(_okResult("not json"), "a lookup"); }) !== null);
  check("_ghJson parses a good payload",
    release._ghJson(_okResult('{"a":1}'), "a lookup").a === 1);
}

function run() {
  testCaptureOkPassesThroughSuccess();
  testCaptureOkThrowsOnNonZero();
  testCaptureOkDescribesASpawnFailure();
  testTransientClassification();
  testQueryRetriesATransientFailure();
  testQueryDoesNotRetryAStableFailure();
  testQueryGivesUpAfterTheAttemptBudget();
  testQueryFailuresAreTagged();
  testOpenPrNumberFailsClosedOnAnUnreadableLookup();
  testOpenPrNumberStillReportsAGenuineAbsence();
  testOpenPrNumberReturnsTheNumber();
  testBackendDetectionFailsClosedOnAFailedDiff();
  testBackendDetectionStillReadsARealDiff();
  testBackendDetectionFallsBackWhenOriginMainIsAbsent();
  testWikiTouchedFailsClosedOnAFailedDiff();
  testWikiTouchedReadsBothDiffs();
  testSmokeAbortsBeforeTouchingWikiData();
  testCodexHeadLookupFailsClosed();
  testCodexWaitAbsorbsATransientBlip();
  testCodexWaitAbortsOnAStableFailure();
  testCodexWaitTimeoutSaysUnknownNotNo();
  testCodexWaitStillReportsAGenuineAbsence();
  testCodexWaitHonoursItsWallClockBudget();
  testPublishFailsClosedOnAFailedRunLookup();
  testStatusReportsALookupFailureRatherThanNone();
  testStatusStillReportsNoneWhenThereIsNoPr();
  testTagFailsClosedOnAFailedTagProbe();
  testGitCleanAndBranchFailClosed();
  testGhJsonFailsClosed();
  console.log("[release-fail-closed] OK — " + helpers.getChecks() + " checks passed");
}

module.exports = { run: run };
if (require.main === module) {
  run();
}
