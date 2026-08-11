// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * End-to-end @example validation. The comment-block validator only PARSE-checks
 * each @example (vm.Script — never runs it), so an example can compile yet be
 * semantically dead: a renamed method, a removed API, a wrong argument shape.
 * This walks the SAME parseTree the validator uses and actually EXECUTES every
 * @example, asserting none throws for a reason that means the documentation is
 * wrong.
 *
 * Naive execution is destructive — examples start daemons, open databases,
 * generate keypairs, touch the filesystem — so the examples split by what they
 * need, and BOTH halves run:
 *
 *  - **In process**, behind a vm sandbox with no real I/O: the self-contained
 *    ones. A stray write still lands in a sacrificial temp cwd.
 *  - **In a child process** (`_jsdoc-example-child.js`), one per batch, each
 *    with its own disposable directory and its own test database: everything
 *    matching STATEFUL_OR_IO. Damage is bounded by the directory and a wedged
 *    example costs one batch rather than the run.
 *
 * The child half is what closed the gap this file used to carry: ~600 examples
 * were being counted as "skipped", and a renamed method inside any of them was
 * exactly the drift this gate exists to catch.
 *
 * What is NOT a failure: an identifier only the surrounding prose defines, a
 * module the framework doesn't ship, a framework error from a
 * precondition/input demo, a missing network, or an example that DECLARES the
 * operator environment it assumes with a leading `// requires:` line. That
 * marker lives in the documentation rather than in an allowlist here, so an
 * operator reads the prerequisite too — see _jsdoc-example-runtime.js.
 *
 * Run standalone: `node test/layer-0-primitives/jsdoc-example-execution.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var path    = require("path");
var fs      = require("node:fs");
var os      = require("node:os");
var cp      = require("node:child_process");
var helpers = require("../helpers");
var check   = helpers.check;
var runtime = require("./_jsdoc-example-runtime.js");

var ROOT   = runtime.ROOT;
var parser = require(path.join(ROOT, "examples", "wiki", "lib", "source-doc-parser"));
var { setupTestDb, teardownTestDb } = require("../helpers/db");

var CHILD       = path.join(__dirname, "_jsdoc-example-child.js");
var BATCH_SIZE  = 30;                                                                            // allow:raw-byte-literal — examples per child process
// This file is itself one of ~64 forked smoke workers, so the fan-out stays
// small: enough to keep the child pass a few seconds, not enough to multiply
// the machine's process count by the batch count.
var CONCURRENCY = 4;                                                                             // allow:raw-byte-literal — child processes at a time
var CHILD_MS    = 120000;                                                                        // allow:raw-byte-literal // allow:raw-time-literal — whole-batch ceiling
var RESUME_EXIT = 75;                                                                            // allow:raw-byte-literal — child says "state is dirty, relaunch me"
// Bounded so a pathological example cannot spin the pool: past this, the rest
// of the batch is reported unexecuted rather than retried forever.
var MAX_RESUMES = 8;                                                                             // allow:raw-byte-literal — restarts per batch

// Which permission-model flags does THIS node accept? The set has grown across
// releases — `--allow-net` exists on 26 and not on the 24 LTS floor — and a
// flag the runtime does not know is a hard "bad option" exit before any code
// runs, so every child dies and the gate reports the whole batch unexecuted.
// Probing beats a version comparison: it stays right through a backport and
// through whatever is added next.
var _flagCache = null;
function _permissionFlags(writableDirs) {
  if (_flagCache === null) {
    var probe = function (args) {
      var rv = cp.spawnSync(process.execPath, args.concat(["-e", "0"]),
        { stdio: ["ignore", "ignore", "pipe"] });
      return rv.status === 0;
    };
    _flagCache = {
      permission: probe(["--permission", "--allow-fs-read=*"]),
      net:        probe(["--permission", "--allow-fs-read=*", "--allow-net"]),
    };
  }
  if (!_flagCache.permission) return null;
  var flags = ["--permission", "--allow-fs-read=*"];
  writableDirs.forEach(function (d) { flags.push("--allow-fs-write=" + path.join(d, "*")); });
  // Where the flag exists, network has to be granted explicitly or an example
  // that binds a port is denied for doing what it documents. Where it does not,
  // the runtime does not govern network at all and the same examples run.
  if (_flagCache.net) flags.push("--allow-net");
  return flags;
}

function _collectExamples() {
  var docs = parser.parseTree(path.join(ROOT, "lib"));
  var inProcess = [], stateful = [];
  Object.keys(docs).forEach(function (file) {
    (docs[file].primitives || []).forEach(function (p) {
      var sig = (p.tags && p.tags.primitive) || file;
      ((p.tags && p.tags.examples) || []).forEach(function (body) {
        var item = { id: inProcess.length + stateful.length, sig: sig, body: body };
        if (runtime.STATEFUL_OR_IO.test(body)) stateful.push(item);
        else inProcess.push(item);
      });
    });
  });
  return { inProcess: inProcess, stateful: stateful };
}

// Run the stateful half: batches of examples, a few children at a time, each
// reporting to its own results file (stdout carries the framework's own boot
// logging, which is indistinguishable from a result record).
function _runStatefulBatches(items, dir) {
  var batches = [];
  for (var i = 0; i < items.length; i += BATCH_SIZE) batches.push(items.slice(i, i + BATCH_SIZE));
  var results = [];
  var next = 0;

  return new Promise(function (resolve) {
    var active = 0, finished = 0;
    if (batches.length === 0) { resolve(results); return; }
    function launch() {
      while (active < CONCURRENCY && next < batches.length) {
        (function (bi) {
          active += 1; next += 1;
          runBatch(bi, batches[bi], 0, function () {
            active -= 1; finished += 1;
            if (finished === batches.length) resolve(results); else launch();
          });
        })(next);
      }
    }

    // One attempt at (part of) a batch. A child that reports dirty framework
    // state gets replaced by a fresh one starting where it stopped — bounded,
    // so a pathological example cannot spin here forever.
    function runBatch(bi, items, attempt, done) {
      var tag        = bi + "-" + attempt;
      var batchPath  = path.join(dir, "batch" + tag + ".json");
      var resultPath = path.join(dir, "result" + tag + ".json");
      fs.writeFileSync(batchPath, JSON.stringify(items));
      // The child builds its per-example directories inside OUR temp tree, so
      // a child the watchdog kills — which cannot clean up after itself —
      // still leaves nothing behind once this run tears `dir` down.
      //
      // And it runs under Node's permission model, because a disposable
      // working directory is NOT containment: these examples were selected for
      // spawning processes, writing files and calling out, and several name
      // absolute paths (`/var/log/app.log`, `/opt/app/app.bin`). Changing the
      // cwd only redirects the relative ones. Writes are confined to this
      // run's own tree and `--allow-child-process` is deliberately withheld,
      // so an example that shells out is denied rather than obeyed.
      //
      // What is allowed, and why each one is not the risk:
      //   fs READ anywhere — the framework and its vendored deps must load.
      //   fs WRITE to this run's tree, and to the OS temp directory, which
      //     `b.testing.tempDir` documents itself as creating. The repository,
      //     /etc, /var, /opt and the home directory stay denied, which is
      //     where "destructive" would actually mean something.
      //   net — an example that binds a port or resolves a name is doing what
      //     it documents; the ones that reach a real external host declare it
      //     with a `// requires:` line and are never executed here.
      // child_process is NOT allowed: an example that shells out is denied.
      var flags = _permissionFlags([dir, os.tmpdir()]) || [];
      var child = cp.spawn(process.execPath, flags.concat([CHILD, batchPath, resultPath, dir]),
        { stdio: ["ignore", "ignore", "pipe"] });
      var stderr = "";
      var killed = false;
      var watchdog = setTimeout(function () {
        killed = true;
        try { child.kill("SIGKILL"); } catch (_e) { /* already gone */ }
      }, CHILD_MS);
      if (typeof watchdog.unref === "function") watchdog.unref();
      child.stderr.on("data", function (d) { stderr += d.toString("utf8"); });
      child.on("close", function (code) {
        clearTimeout(watchdog);
        var got = [];
        try { got = JSON.parse(fs.readFileSync(resultPath, "utf8")); } catch (_e) { got = []; }
        results = results.concat(got);

        var resume = null;
        try { resume = JSON.parse(fs.readFileSync(resultPath + ".resume", "utf8")); }
        catch (_e2) { resume = null; }
        if (code === RESUME_EXIT && resume && attempt < MAX_RESUMES &&
            resume.resumeFrom < items.length) {
          runBatch(bi, items.slice(resume.resumeFrom), attempt + 1, done);
          return;
        }

        // Anything still unreported is unaccounted for, and saying so beats
        // counting it as a pass.
        if (got.length < items.length) {
          var missing = items.slice(got.length);
          results.push({ id: missing[0].id, outcome: "fail",
            error: "child " + (killed ? "exceeded " + CHILD_MS + "ms" :
                               code === RESUME_EXIT ? "hit the resume limit" : "exited (code " + code + ")") +
                   " with " + missing.length + " example(s) unreported, starting at " +
                   missing[0].sig + (stderr ? " — " + stderr.split("\n")[0].slice(0, 160) : "") });
        }
        done();
      });
    }

    launch();
  });
}

async function run() {
  var all = _collectExamples();
  var byId = {};
  all.inProcess.concat(all.stateful).forEach(function (it) { byId[it.id] = it; });

  var origCwd = process.cwd();
  var tmp = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-example-exec-"));
  var onReject = function () {};
  process.on("unhandledRejection", onReject);
  process.chdir(tmp);
  await setupTestDb(tmp, [{ name: "widget", columns: { id: "TEXT PRIMARY KEY" } }]);

  var ran = 0, skipped = 0, childRan = 0, failures = [];
  function record(item, res, fromChild) {
    if (res.outcome === "ran") { ran += 1; if (fromChild) childRan += 1; }
    else if (res.outcome === "skip") skipped += 1;
    else failures.push({ sig: (item && item.sig) || "?",
                         error: String(res.error).split("\n").slice(0, 2).join(" ") });
  }

  try {
    for (var i = 0; i < all.inProcess.length; i += 1) {
      var item = all.inProcess[i];
      record(item, await runtime.runExampleInContext(item.body, {
        context: runtime.makeContext({}), timeoutMs: 1500,                                        // allow:raw-byte-literal // allow:raw-time-literal — in-process ceiling
      }));
    }
    var childResults = await _runStatefulBatches(all.stateful, tmp);
    childResults.forEach(function (r) { record(byId[r.id], r, true); });
  } finally {
    try { await teardownTestDb(tmp); } catch (_e) { /* best-effort */ }
    process.chdir(origCwd);
    process.removeListener("unhandledRejection", onReject);
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (_e2) { /* best-effort */ }
  }

  // Say it out loud when the runtime cannot confine the child, rather than
  // quietly executing spawn/write examples with the runner's full privileges.
  if (_permissionFlags([tmp]) === null) {
    console.log("[jsdoc-example-execution] WARNING: this Node has no permission model — " +
                "stateful examples ran WITHOUT write confinement or subprocess denial");
  }
  var summary = "[jsdoc-example-execution] executed " + ran + ", skipped " + skipped +
    " (illustrative + declared prerequisites), failed " + failures.length +
    "  [" + all.inProcess.length + " in process, " + all.stateful.length + " in child processes; " +
    childRan + " child example(s) actually ran]";
  console.log(summary);
  // Persist the detail: a failure under a forked smoke worker whose stdout the
  // parent does NOT fold into .test-output/smoke.log would otherwise be lost.
  var report = summary + "\n" +
    failures.map(function (f) { return "  FAIL " + f.sig + " :: " + f.error; }).join("\n") + "\n";
  try { fs.writeFileSync(path.join(ROOT, ".test-output", "jsdoc-example-execution.log"), report); }
  catch (_e3) { /* best-effort */ }
  if (failures.length) failures.slice(0, 50).forEach(function (f) { console.log("  FAIL " + f.sig + " :: " + f.error); });

  check("every @example runs without throwing (renamed/removed API, wrong shape)",
        failures.length === 0);
  // Counted separately from the in-process pass on purpose: a combined total is
  // dominated by the ~900 in-process examples, so a child pass that spawned
  // nothing at all would still satisfy it and the gate would quietly go back to
  // covering only the easy half.
  check("the child pass actually executed the stateful examples",
        all.stateful.length > 0 && childRan > all.stateful.length / 3);
}

if (require.main === module) {
  run().then(function () { console.log("jsdoc-example-execution OK — " + helpers.getChecks() + " checks"); },
    function (e) { console.error(e && e.stack || e); process.exit(1); });
}

module.exports = { run: run };
