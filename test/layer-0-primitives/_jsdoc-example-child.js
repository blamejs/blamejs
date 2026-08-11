// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Child half of the @example gate — runs the examples the in-process pass can
 * only skip.
 *
 * An example that opens a database, starts a listener, writes a file or
 * generates a keypair cannot run in the suite's own process: it would outlive
 * the test, race the other forks over the shared data directory, or wedge the
 * run outright. So the in-process pass skips ~850 of them, and "skipped" has
 * been doing a lot of quiet work — a renamed method inside any of those is
 * exactly the drift this gate exists to catch, and none of them were executing.
 *
 * Here each batch gets its own process, its own disposable working directory
 * and its own test database, and the parent kills the whole process if it
 * stops reporting. Damage is bounded by the directory, and a wedged example
 * costs one batch rather than the suite.
 *
 * Invoked as: node _jsdoc-example-child.js <batch.json> <results.json> [baseDir]
 * where batch.json is [{ id, sig, body }, ...] and the results file receives
 * [{ id, outcome, reason?, error? }, ...].
 *
 * `baseDir` is where this child builds its per-example directories. The parent
 * passes its OWN temp tree, so everything here is removed when the parent
 * cleans up — including after a child the watchdog SIGKILLs, which by
 * definition cannot clean up after itself. These directories hold sealed
 * databases and vault keys; "the child tidies up on its way out" only covers
 * the exits the child gets to choose.
 *
 * Results go to a FILE rather than stdout on purpose: the examples boot real
 * framework machinery, which logs JSON to stdout, and those lines are
 * indistinguishable from result records to anything parsing the stream.
 */

var fs   = require("node:fs");
var os   = require("node:os");
var path = require("node:path");

var runtime = require("./_jsdoc-example-runtime.js");
var { setupTestDb, teardownTestDb, setTestPassphraseEnv } = require("../helpers/db");

var PER_EXAMPLE_MS = 4000;                                                                       // allow:raw-byte-literal // allow:raw-time-literal — real I/O is slower than the in-process pass
// Exit code meaning "process-global state is dirty; relaunch me from the index
// in <results>.resume". Distinct from 0 (finished) and 1 (the child broke).
var RESUME_EXIT    = 75;                                                                         // allow:raw-byte-literal — sysexits EX_TEMPFAIL, "try again"

// Every exit from this child goes through here — the normal one and the
// resume one both. A sealed database, its vault key and the key's sidecars
// live under `root`, so leaving it behind means that material outlives the
// process that needed it.
function _cleanup(root) {
  try { process.chdir(os.tmpdir()); } catch (_e) { /* already elsewhere */ }
  try { fs.rmSync(root, { recursive: true, force: true }); }
  catch (_e2) { /* best-effort — it is a temp dir */ }
}

async function main() {
  var batchPath  = process.argv[2];
  var resultPath = process.argv[3];
  if (!batchPath || !resultPath) {
    process.stderr.write("usage: _jsdoc-example-child.js <batch.json> <results.json>\n");
    process.exit(2);
  }
  var batch = JSON.parse(fs.readFileSync(batchPath, "utf8"));

  // Give the child the same minimal environment the suite gives every other
  // test. An example that then fails is failing on its own terms rather than
  // on a missing setup step, which is the difference between a gate and a list
  // of excuses.
  setTestPassphraseEnv();

  // These handlers exist so one example's stray async throw cannot kill the
  // process and cost the whole batch its report. But swallowing them outright
  // would hide exactly what this pass is for: the examples delegated here are
  // the ones that install listeners, timers and callbacks, so a throw from
  // inside one of those IS the example failing — just not on the awaited path.
  // Record it against whichever example is running and let the loop continue.
  //
  // It goes through the SAME classifier as a synchronous throw, so the two
  // paths agree on what counts: a host that does not resolve or a port already
  // taken is the example describing an environment it does not create, exactly
  // as it would be if it had thrown on the awaited path. Only what the
  // classifier calls a defect is recorded as one.
  var current = null;
  var asyncFailures = [];
  function noteAsyncFailure(kind, e) {
    var verdict = runtime.classify(e, { timeoutIsFailure: true });
    if (verdict.outcome !== "fail") return;
    asyncFailures.push({
      id: current ? current.id : null,
      sig: current ? current.sig : "(between examples)",
      error: kind + ": " + ((e && e.message) || String(e)),
    });
  }
  process.on("unhandledRejection", function (e) { noteAsyncFailure("unhandled rejection", e); });
  process.on("uncaughtException", function (e) { noteAsyncFailure("uncaught exception", e); });

  var out = [];
  var baseDir = process.argv[4] || os.tmpdir();
  var root = fs.mkdtempSync(path.join(baseDir, "blamejs-example-child-"));
  for (var i = 0; i < batch.length; i += 1) {
    var item = batch[i];
    current = item;
    var res;
    // A FRESH database and working directory per example, not per batch. The
    // db is a process singleton, so an example that closes it, re-opens it
    // under a different posture, or seals a column leaves the next one running
    // against whatever it left behind — and the next one then fails for a
    // reason that has nothing to do with its own documentation ("attempt to
    // write a readonly database" is the one that surfaced). Order-dependence
    // in a gate is worse than a gap: it passes or fails on batch composition.
    var dir = path.join(root, "ex" + i);
    fs.mkdirSync(dir, { recursive: true });
    process.chdir(dir);
    try {
      await setupTestDb(dir, [{ name: "widget", columns: { id: "TEXT PRIMARY KEY" } }]);
    } catch (_e) {
      // Setup failing means an EARLIER example left process-global framework
      // state behind that a fresh directory cannot undo — a pinned compliance
      // posture is the one that surfaced. The framework has such singletons by
      // design, and enumerating every reset here would be a list that silently
      // falls behind the framework.
      //
      // So the child gives up its process instead: it reports what it finished
      // and asks the parent for a new one starting here. Contamination costs a
      // process restart, which is rare, rather than a wrong verdict on the
      // example that happened to run next.
      fs.writeFileSync(resultPath, JSON.stringify(out));
      fs.writeFileSync(resultPath + ".resume", JSON.stringify({ resumeFrom: i }));
      // Take the tree with it. These directories hold sealed databases, vault
      // keys and their sidecars, and the resume path is the EXPECTED one — a
      // restart per contaminated batch, every run, on every machine. Exiting
      // without this leaves that material accumulating in the system temp
      // directory instead of lasting only as long as the child does.
      _cleanup(root);
      process.exit(RESUME_EXIT);
    }
    try {
      res = await runtime.runExampleInContext(item.body, {
        context:     runtime.makeContext({ allowAnyModule: true }),
        timeoutMs:   PER_EXAMPLE_MS,
        // This process IS the isolation, so the example runs in its own realm
        // rather than a vm one — otherwise a RegExp or Array literal it passes
        // to the framework fails every instanceof check on the way in.
        nativeRealm: true,
        // This example has a working database and directory, so running past
        // the ceiling means it hung rather than that the sandbox starved it.
        timeoutIsFailure: true,
      });
    } catch (e) { res = runtime.classify(e, { timeoutIsFailure: true }); }
    // Give a callback the example scheduled one turn to throw before the
    // verdict is written — without it, a listener that fails on the next tick
    // lands after this example has already been recorded as clean.
    await new Promise(function (r) { setImmediate(r); });
    try { await teardownTestDb(dir); } catch (_e) { /* best-effort */ }
    current = null;
    var mine = asyncFailures.filter(function (f) { return f.id === item.id; });
    if (mine.length && res.outcome !== "fail") {
      res = { outcome: "fail", error: mine[0].error };
    }
    out.push({ id: item.id, outcome: res.outcome, reason: res.reason,
               error: res.error ? String(res.error).split("\n").slice(0, 2).join(" ") : undefined });
    // Written after every example, not once at the end: a batch killed for
    // wedging still reports everything it got through, and the example it died
    // on is the first one missing.
    fs.writeFileSync(resultPath, JSON.stringify(out));
  }
  // A throw that landed with no example running still belongs to this batch —
  // reporting it against nobody would put it back in the silence this change
  // is closing.
  var orphaned = asyncFailures.filter(function (f) { return f.id === null; });
  if (orphaned.length && batch.length) {
    out.push({ id: batch[batch.length - 1].id, outcome: "fail",
               error: "after the example completed — " + orphaned[0].error });
    fs.writeFileSync(resultPath, JSON.stringify(out));
  }
  _cleanup(root);
  // Examples start listeners and timers; leaving normally would hang on them.
  process.exit(0);
}

main().then(function () { /* exits above */ }, function (e) {
  process.stderr.write("child failed: " + ((e && e.stack) || e) + "\n");
  process.exit(1);
});
