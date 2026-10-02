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

// A CLEAN Codex review (no findings) posts no formal review node, only a
// summary comment citing the git-ABBREVIATED head sha (7 chars). Matching the
// comment against a fixed 10-char head prefix never hits, so the 10-minute
// wait timed out on every no-findings release. The cited sha is a PREFIX of
// the head, so a prefix match counts it.
function testCodexCleanReviewCitesAbbreviatedSha() {
  var HEAD = "4e197605e4e2cf6aa0643648fd0dff8e076f8228";
  var ABBREV = HEAD.slice(0, 7);
  function respond(cmd, args) {
    if (args.indexOf("headRefOid") !== -1) return _okResult(HEAD);
    if (args.indexOf("graphql") !== -1) return _okResult("[]");            // no formal review node
    if (args.indexOf("comments") !== -1) {
      return _okResult(JSON.stringify([{
        author: { login: "chatgpt-codex-connector" },
        body: "## Codex Review Summary\n\n| Code Review | Completed | `" + ABBREV + "` | PR opened |",
      }]));
    }
    return _failResult("unexpected call");
  }
  withQuietConsole(function () {
    withCapture(respond, function () {
      check("a clean Codex review citing the 7-char abbrev counts as reviewed",
        release._codexReviewedHead("736") === true);
    });
  });
  // A comment citing an UNRELATED 7-char hex token must NOT count.
  withQuietConsole(function () {
    withCapture(function (cmd, args) {
      if (args.indexOf("headRefOid") !== -1) return _okResult(HEAD);
      if (args.indexOf("graphql") !== -1) return _okResult("[]");
      return _okResult(JSON.stringify([{
        author: { login: "chatgpt-codex-connector" },
        body: "reviewed `deadbee` earlier",
      }]));
    }, function () {
      check("a comment citing an unrelated sha does not count as reviewing this head",
        release._codexReviewedHead("736") === false);
    });
  });
}

// Codex posts the review-summary comment the MOMENT a review starts, and that
// comment's table cites the abbreviated head sha while the status column still
// reads "Running". Counting it means the wait returns immediately and the merge
// fires while the review is in flight, which is the one thing the wait exists to
// stop. Measured on PR #806: the gate reported "Codex has reviewed the current
// PR head", squash-merged, and the review was still running afterwards.
function testARunningCodexReviewDoesNotCountAsReviewed() {
  var HEAD = "7d795e02a52f374a5fd639299262b04157c12cc5";
  var ABBREV = HEAD.slice(0, 7);
  function respondWith(body) {
    return function (cmd, args) {
      if (args.indexOf("headRefOid") !== -1) return _okResult(HEAD);
      if (args.indexOf("graphql") !== -1) return _okResult("[]");          // no formal review node
      if (args.indexOf("comments") !== -1) {
        return _okResult(JSON.stringify([{
          author: { login: "chatgpt-codex-connector" }, body: body,
        }]));
      }
      return _failResult("unexpected call");
    };
  }

  // The real comment carries this trailer, and its prose contains the word
  // "running". A guard that scans the whole body reads the vendor's own help
  // text as a review state.
  var ABOUT_BLOCK =
    "\n\n<details> <summary>About Codex in GitHub</summary>\n<br/>\n\n" +
    "Reviews are triggered when you\n- Open a pull request for review\n" +
    "Codex reacts with eyes while any review is running, comments if it has " +
    "suggestions, and reacts with thumbs up once all reviews finish with no " +
    "findings.\n\n</details>\n";

  function summary(rows) {
    return "<!-- codex-pull-request-review-summary -->\n\n## Codex Review Summary\n\n" +
      "This comment shows the latest Codex review activity on this pull request.\n\n" +
      "| Review | Status | Commit | Review trigger |\n| --- | --- | --- | --- |\n" +
      rows.join("\n") + "\n" + ABOUT_BLOCK;
  }
  var RUNNING_ROW   = "| Code Review | 🔄 **Running** since <relative-time " +
                      "datetime=\"2026-10-02T05:07:54Z\">x</relative-time> | `" +
                      ABBREV + "` | Manual request |";
  var COMPLETED_ROW = "| Code Review | ✅ **Completed** <relative-time " +
                      "datetime=\"2026-10-02T05:14:50Z\">x</relative-time> | `" +
                      ABBREV + "` | Manual request |";
  var FAILED_ROW    = "| Code Review | ⚠️ **Failed** | `" + ABBREV + "` | Manual request |";
  var SEC_RUNNING   = "| Security Review | 🔄 **Running** since <relative-time " +
                      "datetime=\"2026-10-02T05:14:50Z\">x</relative-time> | `" +
                      ABBREV + "` | Manual request |";

  function reviewed(body) {
    var out = null;
    withQuietConsole(function () {
      withCapture(respondWith(body), function () { out = release._codexReviewedHead("806"); });
    });
    return out;
  }

  check("a summary whose row for this head is RUNNING does not count as reviewed",
    reviewed(summary([RUNNING_ROW])) === false);
  check("and the About block's own prose does not decide the state",
    reviewed(summary([COMPLETED_ROW])) === true);

  // A FAILED review produced no findings and never will, so the gate must not
  // report that the head was reviewed and wave the merge through.
  check("a summary reporting a FAILED review does not count as reviewed",
    reviewed(summary([FAILED_ROW])) === false);

  // A security review posts findings too, so while one is running this head is
  // not fully reviewed and the wait is right to keep polling. What must never
  // block is static prose: the About block above says "while any review is
  // running" on every comment the reviewer ever posts, and reading the whole
  // body for that word is what would hang a release until the wait times out.
  check("a running security review still holds the merge",
    reviewed(summary([COMPLETED_ROW, SEC_RUNNING])) === false);
  check("but a finished code review and a finished security review count",
    reviewed(summary([COMPLETED_ROW,
      SEC_RUNNING.replace("🔄 **Running** since <relative-time " +
        "datetime=\"2026-10-02T05:14:50Z\">x</relative-time>", "✅ **Completed**")])) === true);

  // The marker is vendor-internal HTML the project does not control, so the
  // verdict must not depend on it.
  check("a running summary still does not count once its marker is renamed",
    reviewed(summary([RUNNING_ROW]).replace(
      "codex-pull-request-review-summary", "codex-review-summary-v2")) === false);

  // A findings comment is not a summary and must still count: it exists only
  // because a review ran.
  check("a findings comment citing the head counts as reviewed",
    reviewed("Reviewed commit `" + ABBREV + "`\n\n- [P2] something") === true);

  // But a bot notice citing the head is not a review.
  check("a notice that a review is already running does not count",
    reviewed("A review is already running for `" + ABBREV + "`.") === false);
  check("a queued notice does not count either",
    reviewed("Review queued for `" + ABBREV + "`.") === false);

  // Every body below is one an adversarial pass used to make the previous
  // version of this gate answer wrongly. The left column is what the gate must
  // say; "reviewed" is the only answer that lets a merge proceed.
  function state(body) {
    var out = null;
    withQuietConsole(function () {
      withCapture(respondWith(body), function () {
        out = release._codexReviewStateForHead("806");
      });
    });
    return out;
  }
  var row = function (name, status, commit) {
    return "| " + name + " | " + status + " | `" + commit + "` | Manual request |";
  };
  [
    // A verdict of failure, however it is spelled, is terminal and not a review.
    ["absent",   "a prose failure notice",      "Review of `" + ABBREV + "` failed. Please try again."],
    ["absent",   "a prose cancellation",        "Review of `" + ABBREV + "` was cancelled."],
    ["absent",   "a prose skip",                "Skipped `" + ABBREV + "`: no reviewable changes."],
    ["failed",   "a failed row",                summary([row("Code Review", "⚠️ **Failed**", ABBREV)])],
    // Order must not decide it: failed beside completed is terminal either way.
    ["failed",   "failed after completed",
      summary([row("Code Review", "✅ **Completed**", ABBREV),
               row("Security Review", "⚠️ **Failed**", ABBREV)])],
    ["failed",   "failed before completed",
      summary([row("Security Review", "⚠️ **Failed**", ABBREV),
               row("Code Review", "✅ **Completed**", ABBREV)])],
    // An unrecognized status is not a completion, and the About text must not
    // decide it either way.
    ["running",  "a pending status",            summary([row("Code Review", "⏳ **Pending**", ABBREV)])],
    ["running",  "an unknown status",           summary([row("Code Review", "❓ **Unknown**", ABBREV)])],
    ["running",  "an empty status cell",        summary([row("Code Review", "", ABBREV)])],
    ["running",  "a pending status with the help text reworded",
      summary([row("Code Review", "⏳ **Pending**", ABBREV)])
        .replace("while any review is running", "while a review runs")],
    // Markup inside the status cell is markup, not a state.
    ["reviewed", "a completed row whose cell carries a queued timestamp",
      summary([row("Code Review",
        "✅ **Completed** <relative-time title=\"queued 05:07:54\" datetime=\"x\">x</relative-time>",
        ABBREV)])],
    ["running",  "a cell that says completed and re-running",
      summary([row("Code Review", "✅ **Completed**, re-running security", ABBREV)])],
    // The row must be identified by its COMMIT cell, not by the line mentioning
    // the sha somewhere.
    ["absent",   "another commit's row linking this head",
      summary(["| Code Review | ✅ **Completed** | `aaaaaaa` | " +
               "[Comment](https://example.invalid/pull/806#commit-" + ABBREV + ") |"])],
    // A prose completion that is not the reviewer's own verdict form is a notice.
    ["absent",   "a gerund completion notice",
      "Codex finished reviewing `" + ABBREV + "` with no findings."],
    ["reviewed", "the reviewer's own verdict form",
      "Reviewed commit `" + ABBREV + "`: no findings."],
    // The quota notice is terminal and names itself.
    ["unavailable", "a usage-limit notice",
      "You have reached your Codex usage limits for code reviews. Add credits for `" +
      ABBREV + "`."],
  ].forEach(function (c) {
    check("review state: " + c[1] + " reads as " + c[0],
      state(c[2]) === c[0], JSON.stringify(state(c[2])));
  });

  // A quota notice is about one earlier attempt and carries no commit, so
  // evidence about THIS head has to outrank it. Otherwise restoring credits and
  // re-requesting can never satisfy the gate: the old notice refuses forever.
  function statesOf(bodies) {
    var out = null;
    withQuietConsole(function () {
      withCapture(function (cmd, args) {
        if (args.indexOf("headRefOid") !== -1) return _okResult(HEAD);
        if (args.indexOf("graphql") !== -1) return _okResult("[]");
        if (args.indexOf("comments") !== -1) {
          return _okResult(JSON.stringify(bodies.map(function (b) {
            return { author: { login: "chatgpt-codex-connector" }, body: b };
          })));
        }
        return _failResult("unexpected call");
      }, function () { out = release._codexReviewStateForHead("806"); });
    });
    return out;
  }
  var QUOTA = "You have reached your Codex usage limits for code reviews.";
  check("a completed review of this head supersedes an earlier quota notice",
    statesOf([QUOTA, summary([COMPLETED_ROW])]) === "reviewed",
    JSON.stringify(statesOf([QUOTA, summary([COMPLETED_ROW])])));
  check("and the order the comments arrive in does not change that",
    statesOf([summary([COMPLETED_ROW]), QUOTA]) === "reviewed");
  check("a running review of this head also outranks the notice, so the wait holds",
    statesOf([QUOTA, summary([RUNNING_ROW])]) === "running");
  check("the notice still stands alone when nothing reviewed this head",
    statesOf([QUOTA]) === "unavailable");
  [].forEach(function (c) {
    check("review state: " + c[1] + " reads as " + c[0],
      state(c[2]) === c[0], JSON.stringify(state(c[2])));
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
  testCodexCleanReviewCitesAbbreviatedSha();
  testARunningCodexReviewDoesNotCountAsReviewed();
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
