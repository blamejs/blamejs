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
// The batch ceiling is DERIVED from the work, not a flat number. Each example
// gets a fresh database, which is deliberately expensive to create — Argon2id
// plus a sealed vault — so a fixed 120s expired mid-batch on a CPU-constrained
// runner and killed children that were making normal progress, reporting their
// remaining examples as unexecuted. A ceiling that does not scale with the
// batch is measuring the runner, not the work.
var PER_EXAMPLE_BUDGET_MS = 12000;                                                               // allow:raw-byte-literal // allow:raw-time-literal — per-example share of the batch ceiling
var CHILD_MS_FLOOR        = 120000;                                                              // allow:raw-byte-literal // allow:raw-time-literal — never below the original ceiling
function _batchCeilingMs(count) {
  return Math.max(CHILD_MS_FLOOR, count * PER_EXAMPLE_BUDGET_MS);
}
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

// Blank out everything that is not executable code — comments and string,
// template and regex literals — leaving the offsets intact so a scan over the
// result still lines up with the source. Without this, an example that WRITES
// about an API ("// do not call b.legacy()", or a message quoting a removed
// name) would be read as calling it, and the surface check below would fail a
// perfectly good example for something it only mentions.
function _codeOnly(src) {
  var out = String(src).split("");
  var i = 0, n = out.length;
  function blank(from, to) { for (var k = from; k < to && k < n; k += 1) { if (out[k] !== "\n") out[k] = " "; } }
  // Does a `/` here open a regex literal, or divide? After a VALUE — an
  // identifier, a number, `)`, `]` — it divides; anywhere a value is expected
  // it opens a pattern. A punctuation test alone is not enough: `return /x/`
  // and `typeof /x/` end in a letter, so the keyword has to be recognised or
  // the pattern's text stays searchable and its contents read as real calls.
  var EXPRESSION_KEYWORDS = ["return", "typeof", "case", "in", "of", "delete",
    "void", "instanceof", "new", "do", "else", "yield", "await", "throw"];
  var lastMeaningful = "";
  var lastWord = "";
  function opensRegex() {
    if (lastMeaningful === "") return true;
    if (/[A-Za-z0-9_$]/.test(lastMeaningful)) return EXPRESSION_KEYWORDS.indexOf(lastWord) !== -1;
    return ")]".indexOf(lastMeaningful) === -1;
  }
  while (i < n) {
    var c = src[i], d = src[i + 1];
    if (c === "/" && d === "/") { var e = src.indexOf("\n", i); e = e === -1 ? n : e; blank(i, e); i = e; continue; }
    if (c === "/" && d === "*") { var b2 = src.indexOf("*/", i + 2); b2 = b2 === -1 ? n : b2 + 2; blank(i, b2); i = b2; continue; }
    if (c === "/" && opensRegex()) {
      var r = i + 1, inClass = false, closed = false;
      while (r < n) {
        if (src[r] === "\\") { r += 2; continue; }
        if (src[r] === "\n") break;                   // unterminated — not a regex after all
        if (src[r] === "[") inClass = true;
        else if (src[r] === "]") inClass = false;
        else if (src[r] === "/" && !inClass) { closed = true; break; }
        r += 1;
      }
      if (closed) {
        while (r + 1 < n && /[a-z]/.test(src[r + 1])) r += 1;   // trailing flags
        blank(i, r + 1);
        i = r + 1;
        lastMeaningful = ")";                          // a regex is a value
        continue;
      }
    }
    if (!/\s/.test(c)) {
      lastMeaningful = c;
      // Carry the whole trailing word, so `return` can be told from `count`.
      lastWord = /[A-Za-z0-9_$]/.test(c) ? lastWord + c : "";
    }
    if (c === "\"" || c === "'") {
      var j = i + 1;
      while (j < n) {
        if (src[j] === "\\") { j += 2; continue; }
        if (src[j] === c) break;
        j += 1;
      }
      blank(i, Math.min(j + 1, n));
      i = j + 1;
      // A string is a VALUE, so a `/` after it divides. Leaving the state at
      // the opening quote would read that slash as opening a regex and blank
      // the rest of the expression — hiding any call inside it.
      lastMeaningful = ")";
      lastWord = "";
      continue;
    }
    if (c === "`") {
      // A template's static text is prose; its `${…}` interpolations are code
      // and must stay scannable — an unreachable `${b.removed()}` is exactly
      // the call the execution pass cannot reach and this check exists for.
      //
      // Order is what makes it safe: strip the template BODY first, by the
      // same rules, so nested strings, comments and regexes inside it are
      // already blanked. Brace counting over that result cannot then be thrown
      // off by a `}` living inside a string, which is what makes finding the
      // end of an interpolation reliable without a full tokenizer.
      var k = i + 1;
      while (k < n) {
        if (src[k] === "\\") { k += 2; continue; }
        if (src[k] === "`") break;
        k += 1;
      }
      var bodyStart = i + 1;
      var bodyEnd = Math.min(k, n);
      var stripped = _codeOnly(src.slice(bodyStart, bodyEnd));
      // Everything is prose unless it sits inside a `${…}`.
      var keep = new Array(stripped.length).fill(false);
      for (var s = 0; s < stripped.length - 1; s += 1) {
        if (stripped[s] !== "$" || stripped[s + 1] !== "{") continue;
        var depth = 1;
        var p2 = s + 2;
        while (p2 < stripped.length && depth > 0) {
          if (stripped[p2] === "{") depth += 1;
          else if (stripped[p2] === "}") depth -= 1;
          if (depth > 0) keep[p2] = true;
          p2 += 1;
        }
        s = p2 - 1;
      }
      out[i] = " ";
      for (var t2 = 0; t2 < stripped.length; t2 += 1) {
        var ch = keep[t2] ? stripped[t2] : (stripped[t2] === "\n" ? "\n" : " ");
        out[bodyStart + t2] = ch;
      }
      if (bodyEnd < n) out[bodyEnd] = " ";
      i = k + 1;
      // A template is a VALUE, so a `/` after it divides — same reasoning as
      // for a plain string literal above.
      lastMeaningful = ")";
      lastWord = "";
      continue;
    }
    i += 1;
  }
  return out.join("");
}

// The surface check below is only as good as the stripper feeding it, and a
// stripper is exactly the kind of code that looks right and is not. These pin
// both directions: prose must not be read as a call, and code must survive.
// Is this path, as written in the RAW example, sitting between two slashes on
// one line — the shape of a regex literal's body? Deliberately generous: it
// only ever suppresses a report, so being wrong here costs a check rather than
// failing an example that was fine all along.
function _looksLikeRegexContext(body, pathStr) {
  var needle = "b." + pathStr;
  return String(body).split("\n").some(function (line) {
    var at = line.indexOf(needle);
    if (at === -1) return false;
    var before = line.slice(0, at);
    var after = line.slice(at + needle.length);
    return before.lastIndexOf("/") !== -1 && after.indexOf("/") !== -1;
  });
}

function _checkCodeOnly() {
  var cases = [
    ["b.uuid.v7();",                                   "b.uuid.v7(",     true,  "a plain call"],
    ["// b.commented()",                               "b.commented(",   false, "a line comment"],
    ["/* b.blockCommented() */",                       "b.blockCommented(", false, "a block comment"],
    ["var s = \"b.inString()\";",                      "b.inString(",    false, "a string literal"],
    ["var re = /b\\.inRegex\\(/;",                     "b.inRegex(",     false, "a regex literal"],
    ["return /b\\.afterReturn\\(/;",                   "b.afterReturn(", false, "a regex after a keyword"],
    ["var q = count / total; b.afterDivide();",        "b.afterDivide(", true,  "a call after a division"],
    ["var t = `static b.inStatic() text`;",            "b.inStatic(",    false, "template static text"],
    ["var t = `${b.inInterp()}`;",                     "b.inInterp(",    true,  "a template interpolation"],
    ["var t = `${JSON.stringify(\"b.inNested()\")}`;", "b.inNested(",    false, "a string inside an interpolation"],
    ["var t = `${f(\"}\")}`; b.afterBraceInString();", "b.afterBraceInString(", true, "code after a brace inside a string"],
    ["var x = \"a\" / b.afterStringDivide() / 2;",     "b.afterStringDivide(", true, "a division after a string literal"],
    ["var x = `a` / b.afterTemplateDivide() / 2;",     "b.afterTemplateDivide(", true, "a division after a template"],
  ];
  cases.forEach(function (c) {
    var kept = _codeOnly(c[0]).indexOf(c[1]) !== -1;
    check("example scanner: " + c[3] + " is " + (c[2] ? "kept" : "ignored"), kept === c[2]);
  });
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
      // ONLY this run's own tree. Granting the whole system temp directory
      // would hand every stateful example write access to whatever else lives
      // there — on some hosts that includes the checkout itself — which is the
      // containment this child process exists to provide.
      var flags = _permissionFlags([dir]) || [];
      // Point the child's temp directory INSIDE the confined tree, so an
      // example that legitimately does `fs.mkdtempSync(os.tmpdir() + …)` — a
      // documented pattern, e.g. in the backup primitives — keeps working and
      // keeps its coverage, instead of being denied and quietly reclassified.
      // Confinement is preserved: os.tmpdir() now resolves to somewhere this
      // run owns and deletes.
      var childTmp = path.join(dir, "tmp");
      fs.mkdirSync(childTmp, { recursive: true });
      var child = cp.spawn(process.execPath, flags.concat([CHILD, batchPath, resultPath, dir]),
        { stdio: ["ignore", "ignore", "pipe"],
          env: Object.assign({}, process.env, { TMPDIR: childTmp, TEMP: childTmp, TMP: childTmp }) });
      var stderr = "";
      var killed = false;
      var ceilingMs = _batchCeilingMs(items.length);
      var watchdog = setTimeout(function () {
        killed = true;
        try { child.kill("SIGKILL"); } catch (_e) { /* already gone */ }
      }, ceilingMs);
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
            error: "child " + (killed ? "exceeded " + ceilingMs + "ms" :
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
  _checkCodeOnly();
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

  // Execution stops at the FIRST throw, so a placeholder the surrounding prose
  // defines — `certFile`, `req`, `myHttp01Server` — ends an example before
  // anything after it is reached, and a call to a method that does not exist
  // can sit there unexamined. Two did: `b.db.handle()` in the POP3 and
  // ManageSieve server docs, behind an undefined `certFile`.
  //
  // Reading every `b.…` path an example NAMES and resolving it against the
  // shipped surface cannot be masked that way, because it never runs anything.
  var unresolved = [];
  var seen = {};
  all.inProcess.concat(all.stateful).forEach(function (item) {
    var code = _codeOnly(item.body);
    var re = /\bb\.((?:[A-Za-z_$][\w$]*)(?:\.[A-Za-z_$][\w$]*)*)\s*\(/g;
    var m;
    while ((m = re.exec(code)) !== null) {
      var pathStr = m[1];
      var key = item.sig + "::" + pathStr;
      if (seen[key]) continue;
      seen[key] = true;
      var node = runtime.b;
      var parts = pathStr.split(".");
      var ok = true;
      for (var i = 0; i < parts.length; i += 1) {
        if (node === null || node === undefined ||
            !(typeof node === "object" || typeof node === "function") ||
            !(parts[i] in Object(node))) { ok = false; break; }
        node = node[parts[i]];
      }
      // The pattern only matches a path followed by `(`, so every match is a
      // CALL. A path that resolves to something not callable therefore fails
      // the example just as surely as a missing one — a method demoted to a
      // plain property is the same drift wearing a different hat.
      if (ok && typeof node === "function") continue;
      // Last guard before reporting. Telling a regex literal from a division
      // needs real parsing in the general case — `if (ok) /re/.test(x)` opens a
      // pattern where `(a + b) / c` divides, and the stripper cannot see the
      // difference. The two failure modes are not equal: missing a check costs
      // a check, while a false report fails a VALID example and there is
      // nothing downstream to catch that. So anything that even looks like it
      // sits inside a regex on its own line is left alone.
      if (_looksLikeRegexContext(item.body, pathStr)) continue;
      if (!ok) unresolved.push(item.sig + " calls b." + pathStr + "() — no such member");
      else unresolved.push(item.sig + " calls b." + pathStr + "() — resolves to " + typeof node);
    }
  });
  if (unresolved.length) {
    unresolved.slice(0, 25).forEach(function (u) { console.log("  MISSING " + u); });
  }
  check("every b.* method an @example calls exists on the shipped surface",
        unresolved.length === 0);
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
