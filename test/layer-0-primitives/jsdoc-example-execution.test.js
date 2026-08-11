// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

// SMOKE_RUN_SOLO — the smoke runner (test/smoke.js) runs this file ALONE with
// the whole machine instead of inside the parallel layer-0 pool. This gate is
// itself a fan-out: it spawns a child process per batch to execute the
// examples that touch real resources, so inside the pool its children compete
// with 64 sibling forks for the same cores and the file overruns the ordinary
// per-file budget. Running solo gives it the box and the multiplied solo
// budget, which it needs because its cost scales with the example corpus.

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
var BATCH_SIZE  = 12;                                                                            // allow:raw-byte-literal — examples per child; small enough that a full batch's budget fits the file watchdog
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
var PER_EXAMPLE_BUDGET_MS = 10000;                                                               // allow:raw-byte-literal // allow:raw-time-literal — each example's share of the batch ceiling
var CHILD_MS_FLOOR        = 60000;                                                               // allow:raw-byte-literal // allow:raw-time-literal — a small batch still gets a minute
// The ceiling is the batch's own budget, never truncated below it: capping it
// would kill children whose every example was still inside its allowance, on
// exactly the slow runners the allowance exists for. The batch is kept SMALL
// instead, so a full one's budget (12 x 10s) lands at the same two minutes the
// original flat ceiling gave — comfortably inside smoke's 300s per-file
// watchdog, which is the real constraint a bigger batch would collide with.
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
  // Worker threads are NOT granted, and the reason is worth writing down
  // because the opposite looks reasonable. A worker inherits the permission
  // set only while it inherits the parent's arguments: constructed with
  // `execArgv: []` — the ordinary way to keep a worker from inheriting parent
  // flags — it starts without the permission model at all and can write
  // anywhere on the host. Measured, not assumed: under
  // `--allow-fs-write=<tree>/*` a worker with inherited arguments was refused
  // and one with `execArgv: []` created a file outside the tree.
  //
  // So `--allow-worker` does not confine worker examples, it removes the
  // confinement from every OTHER example in the same child. Examples that need
  // a worker declare it instead, which costs their execution and keeps the
  // bound on the ~600 that do run — several of which name real host paths.
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
  // `)` is where the value test alone gets it wrong. It ends a value in
  // `f(a) / x` and `(a + b) / x`, but in `if (ok) /re/.test(s)` it closes a
  // CONDITION and a pattern follows. Telling them apart needs only the word in
  // front of the matching `(`, so each open paren remembers whether it was a
  // control head and the close reads it back.
  // ...and the word alone is not enough either: `obj.if(ok) / x / y` is a
  // method named like a keyword, so the `)` ends a VALUE and the slash divides.
  // A keyword reached through member access is never a control head.
  var CONTROL_HEADS = ["if", "while", "for", "with"];
  var parenIsControl = [];
  var closedControl = false;
  var wordAfterDot = false;
  var lastMeaningful = "";
  // The most recent CONTIGUOUS identifier, and the one before it. Two words
  // are needed because a control head can be two (`for await`), and they must
  // not be run together: appending across the space would read `return await`
  // as one word, match no keyword, and parse the pattern after it as division.
  var lastWord = "";
  var prevWord = "";
  function opensRegex() {
    if (lastMeaningful === "") return true;
    if (/[A-Za-z0-9_$]/.test(lastMeaningful)) return EXPRESSION_KEYWORDS.indexOf(lastWord) !== -1;
    if (lastMeaningful === ")") return closedControl;
    return "]".indexOf(lastMeaningful) === -1;
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
        closedControl = false;                         // ...not a closed condition
        continue;
      }
    }
    if (!/\s/.test(c)) {
      var isWordChar = /[A-Za-z0-9_$]/.test(c);
      if (isWordChar && !(i > 0 && /[A-Za-z0-9_$]/.test(src[i - 1]))) {
        // A new word starts here — remember the previous one and whether this
        // one was reached through member access (`obj.if` is not a control
        // head, however much the word looks like one).
        prevWord = lastWord;
        wordAfterDot = (lastMeaningful === ".");
      }
      if (c === "(") {
        parenIsControl.push(!wordAfterDot && (CONTROL_HEADS.indexOf(lastWord) !== -1 ||
          (lastWord === "await" && prevWord === "for")));
      } else if (c === ")") {
        closedControl = parenIsControl.length ? parenIsControl.pop() : false;
      }
      lastMeaningful = c;
      // Carry the trailing word, so `return` can be told from `count`.
      lastWord = isWordChar
        ? ((i > 0 && /[A-Za-z0-9_$]/.test(src[i - 1])) ? lastWord + c : c)
        : "";
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
      closedControl = false;
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
      closedControl = false;
      continue;
    }
    i += 1;
  }
  return out.join("");
}

// The surface check below is only as good as the stripper feeding it, and a
// stripper is exactly the kind of code that looks right and is not. These pin
// both directions: prose must not be read as a call, and code must survive.
// Every `b.…(` path an example NAMES, in source order, over the stripped code.
// The gate and its self-test both go through here, so a filter added between
// extraction and reporting cannot be silently untested.
function _calledPaths(body) {
  var code = _codeOnly(body);
  var re = /\bb\.((?:[A-Za-z_$][\w$]*)(?:\.[A-Za-z_$][\w$]*)*)\s*\(/g;
  var out = [];
  var m;
  while ((m = re.exec(code)) !== null) out.push(m[1]);
  return out;
}

function _checkCalledPaths() {
  var cases = [
    // A `/` after `)` is the ambiguous one, and both readings appear in real
    // examples: `if (ok) /re/.test(s)` opens a pattern, `f(a) / x / y` divides.
    // Getting either wrong is silent — a missed report, or a VALID example
    // failed for a call it never makes — so both directions are pinned here.
    ["var q = total / b.removed() / scale;", "removed", true,
     "a call between two division operators is reported"],
    ["var q = (a + b) / b.divided() / c;", "divided", true,
     "a call divided after a parenthesized expression is reported"],
    ["var q = f(a) / b.afterCall() / c;", "afterCall", true,
     "a call divided after a call is reported"],
    ["var q = arr[0] / b.afterIndex() / c;", "afterIndex", true,
     "a call divided after an index is reported"],
    ["if (ok) { } var q = f(a) / b.afterBlock() / c;", "afterBlock", true,
     "a division after an if block is reported"],
    ["var re = /b\\.inRegex\\(/;", "inRegex", false,
     "a call inside a regex literal is not reported"],
    ["if (ok) /b\\.inCond\\(/.test(x);", "inCond", false,
     "a call inside a regex after an if condition is not reported"],
    ["while (n) /b\\.inWhile\\(/.test(x);", "inWhile", false,
     "a call inside a regex after a while condition is not reported"],
    ["for (;;) /b\\.inFor\\(/.test(x);", "inFor", false,
     "a call inside a regex after a for header is not reported"],
    ["if (a) { if (b) /b\\.nested\\(/.test(x); }", "nested", false,
     "a call inside a regex after a nested condition is not reported"],
    // A method may be NAMED like a keyword; reached through a dot it is a
    // value, so the slash after it divides.
    ["obj.if(ok) / b.missing() / scale;", "missing", true,
     "a call divided after a method named like a keyword is reported"],
    ["o?.while(x) / b.missingToo() / n;", "missingToo", true,
     "a call divided after an optional-chained keyword-named method is reported"],
    // A keyword can be two words, and running them together matches neither.
    ["for await (const x of y) /b\\.inForAwait\\(/.test(s);", "inForAwait", false,
     "a call inside a regex after a for-await header is not reported"],
    ["return await /b\\.inReturnAwait\\(/.test(s);", "inReturnAwait", false,
     "a call inside a regex after return-await is not reported"],
    ["for (var k in o) /b\\.inForIn\\(/.test(k);", "inForIn", false,
     "a call inside a regex after a for-in header is not reported"],
  ];
  cases.forEach(function (c) {
    check("example surface scan: " + c[3],
          (_calledPaths(c[0]).indexOf(c[1]) !== -1) === c[2]);
  });
}

// A throw an example schedules for later belongs to the example that SCHEDULED
// it, not to whichever one happens to be running when it lands. Getting this
// wrong is silent in both directions — a clean example reported as failing, and
// the real offender reported as clean — so it is driven through the actual
// child rather than asserted against a model of it.
function _checkAsyncAttribution() {
  var tmp = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-example-attrib-"));
  try {
    var batchPath  = path.join(tmp, "batch.json");
    var resultPath = path.join(tmp, "results.json");
    var marker     = JSON.stringify(path.join(tmp, "fired.marker"));
    // The first example's timer fires while the SECOND is still running. The
    // second waits for THAT EVENT rather than for a duration — a fixed sleep
    // long enough to lose the race on a loaded runner is the flake this whole
    // gate keeps finding in other people's tests.
    fs.writeFileSync(batchPath, JSON.stringify([
      { id: "attrib-a", sig: "attribution probe (scheduler)",
        body: "setTimeout(function () {\n" +
              "  require(\"node:fs\").writeFileSync(" + marker + ", \"x\");\n" +
              "  throw new Error(\"scheduled by the first example\");\n" +
              "}, 50);\n" },
      { id: "attrib-b", sig: "attribution probe (bystander)",
        body: "var _fs = require(\"node:fs\");\n" +
              "await new Promise(function (r) {\n" +
              "  var t = setInterval(function () {\n" +
              "    if (_fs.existsSync(" + marker + ")) { clearInterval(t); r(); }\n" +
              "  }, 5);\n" +
              "});\n" },
    ]));
    cp.spawnSync(process.execPath, [CHILD, batchPath, resultPath, tmp],
      { encoding: "utf8", timeout: _batchCeilingMs(2) });
    var rows = [];
    try { rows = JSON.parse(fs.readFileSync(resultPath, "utf8")); } catch (_e) { rows = []; }
    var a = rows.filter(function (x) { return x.id === "attrib-a"; })[0];
    var b = rows.filter(function (x) { return x.id === "attrib-b"; })[0];
    check("a late throw fails the example that scheduled it",
          !!a && a.outcome === "fail" && /scheduled by the first example/.test(String(a.error)));
    check("a late throw does not fail the example that merely followed it",
          !!b && b.outcome !== "fail");
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (_e2) { /* temp */ }
  }
}

// The child decides which row a late failure lands on, and every one of those
// branches used to be reachable only by spawning a whole batch — so the ones
// that need an awkward batch to provoke were never executed at all. Driven
// directly here: it is a pure function of the rows and the failures.
function _checkApplyAsyncFailures() {
  var child = require("./_jsdoc-example-child.js");
  var apply = child.applyAsyncFailures;

  var rows = [{ id: "x", outcome: "ran" }];
  apply(rows, [{ id: "x", error: "boom" }]);
  check("a late failure turns its own row into a failure",
        rows[0].outcome === "fail" && rows[0].error === "boom");

  // A skip carries a reason; once the row fails, a stale reason would read as
  // an explanation for the failure.
  var skipped = [{ id: "x", outcome: "skip", reason: "no network" }];
  apply(skipped, [{ id: "x", error: "boom" }]);
  check("a late failure clears the reason it is overriding",
        skipped[0].outcome === "fail" && skipped[0].reason === undefined);

  // The example's own thrown error is the more useful one.
  var already = [{ id: "x", outcome: "fail", error: "thrown by the example" }];
  apply(already, [{ id: "x", error: "the straggler" }]);
  check("a row that already failed keeps its own error",
        already[0].error === "thrown by the example");

  var two = [{ id: "x", outcome: "ran" }];
  apply(two, [{ id: "x", error: "first" }, { id: "x", error: "second" }]);
  check("the first late failure for a row wins", two[0].error === "first");

  // The resume path writes rows for the examples it finished and hands the
  // rest to a new process, so a straggler can name an id no row carries.
  var absent = [{ id: "x", outcome: "ran" }];
  apply(absent, [{ id: "not-in-this-batch", error: "boom" }]);
  check("a late failure naming no row in the batch changes nothing",
        absent[0].outcome === "ran");

  // Unowned ones are the caller's business — it reports them against the
  // batch rather than silently attaching them to whichever row is handy.
  var unowned = [{ id: "x", outcome: "ran" }];
  apply(unowned, [{ id: null, error: "boom" }, { error: "no id at all" }]);
  check("an unowned late failure is left for the batch-level report",
        unowned[0].outcome === "ran");

  var untouched = [{ id: "x", outcome: "ran" }];
  apply(untouched, []);
  check("no late failures leaves every row alone", untouched[0].outcome === "ran");

  // Applied after every example AND once at the end, so it runs over rows it
  // has already folded into.
  var twice = [{ id: "x", outcome: "ran" }];
  var fs2 = [{ id: "x", error: "boom" }];
  apply(twice, fs2);
  apply(twice, fs2);
  check("folding the same failure twice is idempotent",
        twice[0].outcome === "fail" && twice[0].error === "boom");
}

// The outstanding-network counter decides whether a timeout is a hang or a
// wait, which is the difference between failing an example and excusing it.
// Driven directly: the end-to-end probes below can only reach the case they
// stage, and the ones that matter most are the ones awkward to stage.
function _checkNetworkTracking() {
  var child = require("./_jsdoc-example-child.js");

  var a = { id: "a", sig: "a", net: { n: 0 } };
  var b2 = { id: "b", sig: "b", net: { n: 0 } };

  var settleA = child.owners.run(a, function () { return child.trackNetwork(); });
  check("an operation counts against the example that started it", a.net.n === 1);
  check("and against no other example", b2.net.n === 0);

  // The straggler case: A's operation settles while B is the one running.
  child.owners.run(b2, function () { settleA(); });
  check("a settle credits the starter even when another example is running",
        a.net.n === 0 && b2.net.n === 0);

  // A request can error AND close; decrementing twice would push a later
  // reading negative, and a negative reading looks like "nothing outstanding".
  var s2 = child.owners.run(a, function () { return child.trackNetwork(); });
  s2();
  s2();
  check("settling twice only counts once", a.net.n === 0);

  // Work started outside any example has somewhere to go that is not an
  // example's tally.
  check("outside an example the tracker falls back to the shared counter",
        child.netOwner() === child.orphanNet);
  var before = child.orphanNet.n;
  var s3 = child.trackNetwork();
  check("unowned work counts on the shared counter", child.orphanNet.n === before + 1);
  s3();
  check("and settles back off it", child.orphanNet.n === before);
  check("unowned work never touches an example's counter", a.net.n === 0 && b2.net.n === 0);
}

// The solo marker is read by ONE helper that both runner paths call, and this
// file is one of the files it holds back. Asserting it here means the claim in
// this file's own header — that it gets the whole box and the longer budget —
// is checked rather than trusted.
function _checkSoloMarker() {
  var soloFile = require("../helpers/solo-file");
  check("this file declares itself solo", soloFile.isSoloFile(__filename) === true);
  check("a file with no marker is not solo",
        soloFile.isSoloFile(path.join(__dirname, "_jsdoc-example-child.js")) === false);
  check("a missing file is not solo, and does not throw",
        soloFile.isSoloFile(path.join(__dirname, "no-such-file-here.js")) === false);
  // The marker is only honoured if it is near the top; a file that buries it
  // past the window reads as an ordinary pool file, and silently so.
  var deep = path.join(os.tmpdir(), "blamejs-solo-probe-" + process.pid + ".js");
  try {
    fs.writeFileSync(deep, "//" + new Array(soloFile.HEAD_BYTES + 64).join("x") + "\n// SMOKE_RUN_SOLO\n");
    check("a marker past the head window is not read as solo",
          soloFile.isSoloFile(deep) === false);
  } finally {
    try { fs.rmSync(deep, { force: true }); } catch (_e) { /* temp */ }
  }
}

// The other half of ownership: a network operation an example STARTS late.
// A timeout is excused as "waiting on the network" only when THAT example had
// something outstanding, so a request opened by an earlier example must not
// buy the next one an excuse for hanging locally. Deterministic and offline —
// the first example runs its own server and never answers it.
function _checkNetworkAttribution() {
  var tmp = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-example-net-"));
  try {
    var batchPath  = path.join(tmp, "batch.json");
    var resultPath = path.join(tmp, "results.json");
    var marker     = JSON.stringify(path.join(tmp, "requested.marker"));
    fs.writeFileSync(batchPath, JSON.stringify([
      // The request starts from the listen callback, so it is in flight after
      // this example's own body has returned — which is the case under test.
      { id: "net-a", sig: "network attribution probe (starter)",
        body: "var _http = require(\"node:http\");\n" +
              "var _fs = require(\"node:fs\");\n" +
              "var srv = _http.createServer(function () { /* never answers */ });\n" +
              "srv.listen(0, \"127.0.0.1\", function () {\n" +
              "  _http.get({ host: \"127.0.0.1\", port: srv.address().port, path: \"/\" }, function () {});\n" +
              "  _fs.writeFileSync(" + marker + ", \"x\");\n" +
              "});\n" },
      // Waits for the previous example's request to be in flight, then hangs
      // with nothing of its own outstanding. Its ceiling must read as a hang.
      { id: "net-b", sig: "network attribution probe (local hang)",
        body: "var _fs = require(\"node:fs\");\n" +
              "await new Promise(function (r) {\n" +
              "  var t = setInterval(function () {\n" +
              "    if (_fs.existsSync(" + marker + ")) { clearInterval(t); r(); }\n" +
              "  }, 5);\n" +
              "});\n" +
              "await new Promise(function () { /* hangs locally, forever */ });\n" },
    ]));
    cp.spawnSync(process.execPath, [CHILD, batchPath, resultPath, tmp],
      { encoding: "utf8", timeout: _batchCeilingMs(2) });
    var rows = [];
    try { rows = JSON.parse(fs.readFileSync(resultPath, "utf8")); } catch (_e) { rows = []; }
    var b = rows.filter(function (x) { return x.id === "net-b"; })[0];
    check("a local hang is not excused by an earlier example's outstanding request",
          !!b && b.outcome === "fail");
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (_e2) { /* temp */ }
  }
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
  _checkCalledPaths();
  _checkApplyAsyncFailures();
  _checkNetworkTracking();
  _checkSoloMarker();
  _checkAsyncAttribution();
  _checkNetworkAttribution();
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
    _calledPaths(item.body).forEach(function (pathStr) {
      var key = item.sig + "::" + pathStr;
      if (seen[key]) return;
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
      if (ok && typeof node === "function") return;
      if (!ok) unresolved.push(item.sig + " calls b." + pathStr + "() — no such member");
      else unresolved.push(item.sig + " calls b." + pathStr + "() — resolves to " + typeof node);
    });
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
