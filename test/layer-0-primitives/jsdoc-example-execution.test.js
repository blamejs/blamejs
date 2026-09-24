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
var vm      = require("node:vm");
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
    // A keyword reached through member access is a PROPERTY, not a keyword —
    // `a.await / x / y` divides, `await /re/` does not. Same rule the control
    // heads need, and it has to be applied in both places or one of them keeps
    // reading a property name as syntax.
    if (/[A-Za-z0-9_$]/.test(lastMeaningful)) {
      return !wordAfterDot && EXPRESSION_KEYWORDS.indexOf(lastWord) !== -1;
    }
    if (lastMeaningful === ")") return closedControl;
    return "]".indexOf(lastMeaningful) === -1;
  }
  while (i < n) {
    var c = src[i], d = src[i + 1];
    // `++` and `--` are ONE token, and whichever side their operand sits on the
    // result is a value — so `counter++ / x / y` divides. Read character by
    // character instead, the trailing `+` is the last thing seen, `+` is not a
    // value, and the slash after it opens a pattern that swallows the rest of
    // the expression.
    if ((c === "+" && d === "+") || (c === "-" && d === "-")) {
      lastMeaningful = ")";
      lastWord = "";
      closedControl = false;
      i += 2;
      continue;
    }
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
    // `++`/`--` are one token and produce a value on either side of it.
    ["var q = counter++ / b.afterPostfix() / scale;", "afterPostfix", true,
     "a call divided after a postfix increment is reported"],
    ["var q = counter-- / b.afterPostfixDec() / scale;", "afterPostfixDec", true,
     "a call divided after a postfix decrement is reported"],
    ["var q = ++counter / b.afterPrefix() / scale;", "afterPrefix", true,
     "a call divided after a prefix increment is reported"],
    ["var s = a + +b + b.afterUnaryPlus();", "afterUnaryPlus", true,
     "a call after a unary plus is reported"],
    // A keyword reached through a dot is a property name, not syntax.
    ["var q = a.await / b.afterAwaitProp() / c;", "afterAwaitProp", true,
     "a call divided after a property named like an expression keyword is reported"],
    ["var q = a.return / b.afterReturnProp() / c;", "afterReturnProp", true,
     "a call divided after a property named return is reported"],
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

// A ceiling does not stop an example — an async function already in flight
// keeps running. So a timed-out example leaves the process dirty, and the
// child's contract is to report what it finished and ask for a fresh one for
// the rest. Asserted on the child directly: the batch OUTCOME looks the same
// either way, and what distinguishes them is that the remainder is handed
// over rather than run alongside the abandoned example.
function _checkTimeoutHandsOver() {
  var tmp = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-example-resume-"));
  try {
    var batchPath  = path.join(tmp, "batch.json");
    var resultPath = path.join(tmp, "results.json");
    fs.writeFileSync(batchPath, JSON.stringify([
      { id: "hangs", sig: "resume probe (hangs)",
        body: "await new Promise(function () { /* never settles */ });\n" },
      { id: "after", sig: "resume probe (the remainder)",
        body: "var _x = 1;\n" },
    ]));
    var rv = cp.spawnSync(process.execPath, [CHILD, batchPath, resultPath, tmp],
      { encoding: "utf8", timeout: _batchCeilingMs(2) });
    var rows = [];
    try { rows = JSON.parse(fs.readFileSync(resultPath, "utf8")); } catch (_e) { rows = []; }
    var resume = null;
    try { resume = JSON.parse(fs.readFileSync(resultPath + ".resume", "utf8")); } catch (_e2) { resume = null; }

    check("a timed-out example makes the child ask for a restart",
          rv.status === RESUME_EXIT);
    check("the timed-out example is still reported, as a failure",
          rows.length === 1 && rows[0].id === "hangs" && rows[0].outcome === "fail");
    // The NEXT index, not this one: the example that timed out has a verdict
    // already, and resuming at it would run it again and hang again.
    check("the restart is requested from the example after the one that hung",
          !!resume && resume.resumeFrom === 1);
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (_e3) { /* temp */ }
  }
}

// The restarts are bounded, so they are spent only where they buy something.
// A synchronous example the VM interrupted really did stop — the interpreter
// took the thread back — so there is nothing in flight to hand over, and
// restarting would burn the batch's budget on examples that need none.
function _checkSyncTimeoutStaysInProcess() {
  var tmp = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-example-synctimeout-"));
  try {
    var batchPath  = path.join(tmp, "batch.json");
    var resultPath = path.join(tmp, "results.json");
    fs.writeFileSync(batchPath, JSON.stringify([
      { id: "spins", sig: "sync-timeout probe (spins)",
        body: "for (;;) { /* interrupted by the synchronous ceiling */ }\n" },
      { id: "follows", sig: "sync-timeout probe (the remainder)",
        body: "var _x = 1;\n" },
    ]));
    var rv = cp.spawnSync(process.execPath, [CHILD, batchPath, resultPath, tmp],
      { encoding: "utf8", timeout: _batchCeilingMs(2) });
    var rows = [];
    try { rows = JSON.parse(fs.readFileSync(resultPath, "utf8")); } catch (_e) { rows = []; }
    check("an interrupted synchronous example does not spend a restart",
          rv.status !== RESUME_EXIT);
    check("and the examples after it run in the same process",
          rows.length === 2 && rows[1].id === "follows");
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (_e2) { /* temp */ }
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

// ---------------------------------------------------------------------------
// The arrow pass: an `// ->` states what the call it annotates answers with,
// and until this ran, nothing checked it. Executing an example proves the API
// still exists; it does not prove the documented answer is the one the code
// gives. Three shipped examples stated an answer the code has never given, one
// of them on a primitive added in the same release as this pass, where the fix
// had moved a profile table and left the example describing the old one.
//
// Only a claim naming a VALUE is checked. An arrow carrying prose ("integer in
// [0, 100)"), a digest written with its middle cut out ("1f3a...c08d") or a
// gloss after the value ("null (non-hex)") describes a shape, and the marker
// for that lives in the documentation, where a reader sees it too — the same
// reason `// requires:` is a line in the doc rather than an entry in a list
// here. A random draw written as a concrete literal is a doc defect: the
// example claims one answer for something that answers differently each call.
var ARROW = "// →";

// Nothing is in scope, so an identifier fails to evaluate and the arrow reads
// as prose rather than as a value this can contradict.
var NOTHING_IN_SCOPE = vm.createContext(Object.create(null));

// Bracket balance for a piece of CODE, where a quote really does open a
// string. `opts.prose` is for the text after an arrow, where an apostrophe is
// an apostrophe: reading `false (it's cloud-metadata)` as an open string made
// the reader swallow the following code lines into the expected value, so the
// statements they carried were never emitted and never checked.
function _bracketsBalanced(s, opts) {
  var prose = opts && opts.prose === true;
  var depth = 0, inStr = null;
  for (var i = 0; i < s.length; i += 1) {
    var ch = s.charAt(i);
    if (inStr) {
      if (ch === "\\") { i += 1; continue; }
      if (ch === inStr) inStr = null;
      continue;
    }
    if (ch === '"' || (ch === "'" && !prose)) { inStr = ch; continue; }
    if (ch === "{" || ch === "[" || ch === "(") depth += 1;
    else if (ch === "}" || ch === "]" || ch === ")") depth -= 1;
  }
  return depth <= 0 && inStr === null;
}

// A statement is complete when its brackets close and it is not left mid
// string.
// A line whose brackets balance can still be half a statement: a string
// concatenation, an assignment whose value is on the next line, a chained call
// broken after the dot. Emitting those halves separately produced `var x =;`
// and the example's claims were thrown away with the parse error.
var _ENDS_MID_STATEMENT =
  /(?:[=+\-*/%&|^<>!?:,.]|=>|\b(?:typeof|instanceof|new|in|of|return|case|delete|void|await|yield))$/;

function _statementComplete(s) {
  if (!_bracketsBalanced(s)) return false;
  var tail = String(s).trim();
  if (tail === "" || /[;)}\]]$/.test(tail)) return true;
  return !_ENDS_MID_STATEMENT.test(tail);
}

// A value written with its middle cut out ("1f3a...c08d") or with a stand-in
// for a part that varies ("<16hex> <16hex>") states a shape, not a value.
function _isElided(value) {
  // A stand-in reads as a name inside angle brackets: `<timestamp>`,
  // `<sha3-512 hex>`, `<id-hex>`. Markup carries a closing tag, so a value
  // that really is HTML is still compared.
  if (typeof value === "string") {
    if (/\.{3}|…/.test(value)) return true;
    return /<[^<>]+>/.test(value) && value.indexOf("</") === -1;
  }
  if (Array.isArray(value)) return value.some(_isElided);
  if (value && typeof value === "object") {
    return Object.keys(value).some(function (k) { return _isElided(value[k]); });
  }
  return false;
}

// What follows the value decides whether it is one answer or one of several. A
// parenthesised CONDITION ("(NODE_ENV=production)") or an alternative ("or 0
// (never bumped)") says the answer depends on something the example does not
// set, so there is no single value to compare against.
function _isConditional(text) {
  return /\bor\b|=/.test(text);
}

// Trim from the right at each gloss opener and take the longest prefix that is
// a literal, so "null (non-hex)" reads as null and prose reads as nothing.
function _readLiteral(text) {
  var candidates = [text];
  [" //", " (", " —", "   "].forEach(function (opener) {
    var at = text.lastIndexOf(opener);
    while (at > 0) { candidates.push(text.slice(0, at)); at = text.lastIndexOf(opener, at - 1); }
  });
  candidates.sort(function (x, y) { return y.length - x.length; });
  for (var i = 0; i < candidates.length; i += 1) {
    var c = candidates[i].trim().replace(/[,;]$/, "");
    if (c === "") continue;
    if (!/^[[{"'0-9-]|^(true|false|null|undefined)\b/.test(c)) continue;
    var value;
    try { value = vm.runInContext("(" + c + ")", NOTHING_IN_SCOPE, { timeout: 250 }); }            // allow:raw-time-literal — parsing one literal
    catch (_e) { continue; }
    if (_isElided(value)) return { ok: false };
    if (_isConditional(text.slice(c.length))) return { ok: false };
    return { ok: true, value: value };
  }
  return { ok: false };
}

function _sortDeep(v) {
  if (Array.isArray(v)) return v.map(_sortDeep);
  if (v && typeof v === "object") {
    var out = {};
    Object.keys(v).sort().forEach(function (k) { out[k] = _sortDeep(v[k]); });
    return out;
  }
  return v;
}

function _stable(v) {
  return JSON.stringify(_sortDeep(v), function (k, x) {
    return typeof x === "bigint" ? String(x) + "n" : x;
  });
}

function _render(v) {
  if (typeof v === "string") return JSON.stringify(v);
  if (v === undefined) return "undefined";
  if (typeof v === "function") return "[function]";
  if (typeof v === "bigint") return String(v) + "n";
  if (Buffer.isBuffer(v)) return "Buffer<" + v.toString("hex") + ">";
  try { return _stable(v); } catch (_e) { return String(v); }
}

function _claimHolds(actual, expected) {
  if (actual === expected) return true;
  if (Buffer.isBuffer(actual) && typeof expected === "string") {
    return actual.toString("utf8") === expected || actual.toString("hex") === expected;
  }
  try { return _stable(actual) === _stable(expected); } catch (_e) { return false; }
}

// Rewrite the body so each arrow records the value of the statement it
// annotates. The statements run in their own order, so an example that
// configures something and then reads it back reads its own configuration.
// Cut a trailing line comment, reading quotes so the `//` in a URL stays put.
function _stripTrailingComment(s) {
  var quote = null;
  for (var i = 0; i < s.length; i += 1) {
    var ch = s.charAt(i);
    if (quote !== null) {
      if (ch === "\\") { i += 1; continue; }
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === "`") { quote = ch; continue; }
    if (ch === "/" && s.charAt(i + 1) === "/") return s.slice(0, i).trim();
  }
  return s;
}

// Does the next line with code on it continue the statement that just closed?
// Either it reopens a block that is syntactically finished but not over
// (`catch`, `finally`, `else`), or it opens with something no statement can
// begin with, which is how a ternary or a concatenation broken across lines
// reads: `: ago + " days ago";` under `var label = ago === 0 ? "today"`.
var _CONTINUATION_KEYWORD = /^(?:catch\b|finally\b|else\b)/;
// Only the spellings that can begin nothing else. `/` is excluded because a
// line opening with one is a regex literal far more often than a division
// carried over, and `+` and `-` because they are unary operators.
var _CANNOT_BEGIN_A_STATEMENT = /^(?:&&|\|\||\?\?|=>|[?:.,])/;

function _continuesTheBlock(lines, from) {
  for (var i = from; i < lines.length; i += 1) {
    var arrowAt = lines[i].indexOf(ARROW);
    var code = (arrowAt === -1 ? lines[i] : lines[i].slice(0, arrowAt)).trim();
    if (code === "" || /^\/\//.test(code)) continue;
    return _CONTINUATION_KEYWORD.test(code) || _CANNOT_BEGIN_A_STATEMENT.test(code);
  }
  return false;
}

function _compileClaims(body) {
  var lines = body.split("\n");
  var prog = ["var __last;"];
  var claims = [];
  // The statement an arrow-only line annotates is the last one the EXAMPLE
  // wrote, not the last one emitted: the recorder lines this adds are not
  // statements the documentation makes a claim about.
  var lastUserStatement = null;
  // A statement may span lines — a call whose options object opens on one
  // line and closes on another is the commonest shape in lib/ — so lines are
  // gathered until the brackets close before anything is emitted. Terminating
  // each LINE turned `b.x({` into `b.x({;`, which is a syntax error, and the
  // whole example then counted as unchecked.
  var pending = null;
  // How many statements the EXAMPLE has run. Two arrows with no statement
  // between them annotate one call; two with a statement between them are a
  // before and an after.
  var emitted = 0;
  // The statement whose arrows turned out to be a list of alternatives, so
  // every later arrow against it is one too.
  var voided = null;
  function emit(statement) { _emit(prog, statement); emitted += 1; }
  for (var i = 0; i < lines.length; i += 1) {
    var line = lines[i];
    var arrowAt = line.indexOf(ARROW);
    // Per LINE, because a comment ends at its newline. Cutting the assembled
    // statement instead threw away everything after the first `//` in it,
    // closing brackets included.
    var code = _stripTrailingComment(
      (arrowAt === -1 ? line : line.slice(0, arrowAt))).trim();
    if (pending !== null) {
      // Joined on the newline the example wrote. A space instead ran a
      // trailing `//` comment on one gathered line into the code on the next
      // and commented it out.
      pending += "\n" + code;
      if (!_statementComplete(pending)) continue;
      code = pending;
      pending = null;
    } else if (code !== "" && !/^\/\//.test(code) && !_statementComplete(code)) {
      pending = code;
      continue;
    }
    // A block can be closed and still be continued: `try { … }` is balanced,
    // and the `catch` that follows it is not a statement of its own. Emitting
    // them separately produced a program that did not parse, and every claim
    // in that example was then thrown away.
    if (code !== "" && !/^\/\//.test(code) && _continuesTheBlock(lines, i + 1)) {
      pending = code;
      continue;
    }
    if (arrowAt === -1) {
      if (code !== "" && !/^\/\//.test(code)) {
        emit(code);
        lastUserStatement = code;
      }
      continue;
    }
    var expected = line.slice(arrowAt + ARROW.length).trim();
    // Only a comment line continues an expected value; a code line begins the
    // next statement and must not be eaten by an unbalanced-looking gloss.
    while (!_bracketsBalanced(expected, { prose: true }) && i + 1 < lines.length &&
           /^\s*\/\//.test(lines[i + 1])) {
      i += 1;
      expected += " " + lines[i].replace(/^\s*\/\/\s?/, "").trim();
    }
    var annotatesPrevious = code === "" || /^\/\//.test(code);
    if (annotatesPrevious && lastUserStatement === null) continue;
    if (!annotatesPrevious) {
      emit(code);
      lastUserStatement = code;
    }
    var expr = _describe(annotatesPrevious ? lastUserStatement : code);
    if (expr === null) continue;
    var want = _readLiteral(expected);
    if (!want.ok) continue;
    // Two arrows against ONE statement state alternatives, the answer under
    // one mode and under another, so neither is the single value the call
    // gives and both are dropped. The same call written twice around a
    // mutation is a before-and-after instead, and both of its answers are
    // real. What separates them is whether the example ran anything between
    // the two arrows, not whether the second one sits on its own line: both
    // shapes put it there, so keying on that discarded live claims, including
    // the first of a before-and-after, which was never in doubt.
    if (voided !== null && voided.expr === expr && voided.emitted === emitted) continue;
    if (annotatesPrevious && claims.length > 0 &&
        claims[claims.length - 1].expr === expr &&
        claims[claims.length - 1].emitted === emitted) {
      claims.pop();
      prog.pop();
      // A third alternative would otherwise find the list empty, miss the
      // comparison and be recorded as the one answer the call gives.
      voided = { expr: expr, emitted: emitted };
      continue;
    }
    claims.push({ expr: expr, expected: expected, want: want.value, emitted: emitted });
    prog.push("__claims.push(__last);");
  }
  return { source: prog.join("\n"), claims: claims };
}

// Emit one statement, keeping its value in `__last`. The value has to come
// from the statement that already ran: re-evaluating the expression to record
// it ran every call TWICE, so an example whose call has an effect — an
// enqueue, a counter, a write — reported the answer after two of them and
// contradicted a correct doc.
var _STARTS_A_BLOCK =
  /^(?:async\s+function|function|if|for|while|do|switch|try|return|throw|class)\b|^[}{]/;

function _emit(prog, code) {
  var stmt = code.replace(/;$/, "");
  // A declaration is written out as the example wrote it and the binding is
  // read back afterwards. Re-parenthesising the initialiser instead bound the
  // name to the last operand of `var lo = 1, hi = 2`, because everything after
  // the first `=` became one comma expression, and every later declarator
  // turned into a bare assignment.
  var decl = stmt.match(/^(?:var|let|const)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=/);
  if (decl) {
    prog.push(stmt + ";");
    prog.push("__last = " + decl[1] + ";");
    return;
  }
  if (_STARTS_A_BLOCK.test(stmt) || /^(?:var|let|const)\s/.test(stmt)) {
    prog.push(stmt + ";");
    prog.push("__last = undefined;");
    return;
  }
  var printed = stmt.match(/^console\.(?:log|info)\s*\(([\s\S]+)\)$/);
  prog.push("__last = (" + (printed ? printed[1].trim() : stmt) + ");");
}

// What the arrow is a claim about, for the report. A declaration's claim is
// about the value it bound.
function _describe(code) {
  var stmt = String(code).replace(/;$/, "").trim();
  if (stmt === "") return null;
  // A block statement runs for its effect and has no value to carry, so an
  // arrow on one names something inside it that this gate cannot reach. It is
  // left unsettled rather than compared against the block's own undefined.
  if (_STARTS_A_BLOCK.test(stmt)) return null;
  var decl = stmt.match(/^(?:var|let|const)\s+[A-Za-z_$][A-Za-z0-9_$]*\s*=\s*([\s\S]+)$/);
  if (decl) return decl[1].trim();
  var printed = stmt.match(/^console\.(?:log|info)\s*\(([\s\S]+)\)$/);
  return printed ? printed[1].trim() : stmt;
}

// The examples share one loaded framework, so an example that SETS a
// process-wide value (a compliance posture, a drift threshold) changes what a
// later example READS. A claim that fails on the shared instance is therefore
// re-run against a framework loaded fresh for it alone, and only a claim that
// fails there too is a claim the documentation gets wrong.
function _freshFramework() {
  var libDir = path.join(ROOT, "lib");
  var entry  = path.join(ROOT, "index.js");
  Object.keys(require.cache).forEach(function (k) {
    if (k.indexOf(libDir) === 0 || k === entry) delete require.cache[k];
  });
  return require(entry);
}

async function _runClaims(built, freshB) {
  var recorded = [];
  var globals = { __claims: recorded };
  if (freshB) globals.b = freshB;
  var res = await runtime.runExampleInContext(built.source, {
    context:   runtime.makeContext({ globals: globals }),
    timeoutMs: 1500,                                                                              // allow:raw-byte-literal // allow:raw-time-literal — in-process ceiling
  });
  return {
    ok:      res.outcome === "ran",
    skipped: res.outcome === "skip",
    values:  recorded,
    why:     String(res.outcome) + (res.error ? ": " + String(res.error).slice(0, 120) : ""),
  };
}

async function _checkArrowClaims(items) {
  var checked = 0, held = 0, unchecked = 0;
  var broken = [];
  var suspects = [];
  // An example the rewrite cannot READ is not an example that states no value.
  // Counting the two together meant a rewrite that mis-split a statement threw
  // away every claim in that example and the gate still reported none broken,
  // which is the one failure a gate must not have. A rewrite that does not
  // parse is this gate's defect and fails it; one that parses and then throws
  // is the example meeting an environment it needs, and is only reported.
  var uncompilable = [];
  var threw = [];
  for (var i = 0; i < items.length; i += 1) {
    var item = items[i];
    if (item.body.indexOf(ARROW) === -1) continue;
    // The rewrite drops comment-only lines, which would take a `// requires:`
    // marker with it, so the declaration is read from the ORIGINAL body.
    if (runtime.declaresPrerequisite(item.body)) { unchecked += 1; continue; }
    var built = _compileClaims(item.body);
    if (built.claims.length === 0) { unchecked += 1; continue; }
    // Compiled the way the runtime compiles it, inside the same async IIFE, so
    // a top-level await is as legal here as it is there. A rewrite that does
    // not parse is this gate mis-reading the example.
    try {
      new vm.Script("(async function () {\n" + built.source + "\n})();",
        { filename: "claims.js" });
    } catch (syntax) {
      uncompilable.push({ sig: item.sig, why: String(syntax.message).slice(0, 120) });
      continue;
    }
    var run = await _runClaims(built, null);
    // The runtime declines some examples by design (a declared prerequisite,
    // a shape it will not run in process). That is not the gate failing to
    // read one.
    if (run.skipped) { unchecked += 1; continue; }
    // The examples share one loaded framework, so a call that throws here may
    // be answering a posture some earlier example set rather than anything
    // about this one. It gets the same fresh-framework retry a failing claim
    // gets before it is called unreadable.
    if (!run.ok) {
      run = await _runClaims(built, _freshFramework());
      if (run.skipped) { unchecked += 1; continue; }
      if (!run.ok) { threw.push({ sig: item.sig, why: run.why }); continue; }
    }
    for (var c = 0; c < built.claims.length && c < run.values.length; c += 1) {
      checked += 1;
      if (_claimHolds(run.values[c], built.claims[c].want)) { held += 1; continue; }
      suspects.push({ item: item, built: built, index: c });
    }
  }

  for (var s = 0; s < suspects.length; s += 1) {
    var sus = suspects[s];
    var alone = await _runClaims(sus.built, _freshFramework());
    if (!alone.ok || alone.values.length <= sus.index) { unchecked += 1; continue; }
    var claim = sus.built.claims[sus.index];
    if (_claimHolds(alone.values[sus.index], claim.want)) { held += 1; continue; }
    broken.push({ sig: sus.item.sig, expr: claim.expr,
                  said: claim.expected, got: _render(alone.values[sus.index]) });
  }
  broken.slice(0, 50).forEach(function (f) {                                                      // allow:raw-byte-literal — printed detail cap
    console.log("  CLAIM " + f.sig + " :: " + f.expr);
    console.log("         said: " + f.said);
    console.log("         got:  " + f.got);
  });
  uncompilable.slice(0, 50).forEach(function (f) {                                                // allow:raw-byte-literal — printed detail cap
    console.log("  UNREAD " + f.sig + " :: " + f.why);
  });
  threw.slice(0, 50).forEach(function (f) {                                                       // allow:raw-byte-literal — printed detail cap
    console.log("  THREW  " + f.sig + " :: " + f.why);
  });
  var arrowSummary = "arrow claims: " + checked + " checked, " + held + " hold, " +
                     broken.length + " do not; " + unchecked +
                     " example(s) state no value this can settle, " +
                     threw.length + " need an environment this does not have, " +
                     uncompilable.length + " could not be read";
  console.log("[jsdoc-example-execution] " + arrowSummary);
  check("every @example states the answer the code gives", broken.length === 0,
        broken.length ? broken[0].sig + " :: said " + broken[0].said + ", got " + broken[0].got : "");
  // A claim this gate silently dropped reads exactly like a claim that held,
  // so an example it cannot read is a failure of the gate, not a pass.
  check("every @example carrying a claim can be read by this gate",
        uncompilable.length === 0,
        uncompilable.length ? uncompilable.length + " unread, first: " +
          uncompilable[0].sig + " :: " + uncompilable[0].why : "");
  return { summary: arrowSummary, broken: broken, unread: uncompilable };
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
      var finished = false;
      var ceilingMs = _batchCeilingMs(items.length);
      var watchdog = setTimeout(function () {
        killed = true;
        try { child.kill("SIGKILL"); } catch (_e) { /* already gone */ }
      }, ceilingMs);
      if (typeof watchdog.unref === "function") watchdog.unref();
      // `spawn` can fail before there is a process at all — EAGAIN or EMFILE on
      // a loaded runner, which is exactly the state this gate creates by
      // spawning a child per batch. That arrives as an `error` event, and an
      // `error` with no listener is thrown: the whole gate would die, on the
      // machines most likely to hit it, for a condition the smoke runner
      // already treats as transient. There may be no stdio to read either.
      if (child.stderr) {
        child.stderr.on("data", function (d) { stderr += d.toString("utf8"); });
      }
      child.on("error", function (e) {
        if (finished) return;
        finished = true;
        clearTimeout(watchdog);
        // Transient, so retry it — bounded by the same budget a resume uses.
        if (attempt < MAX_RESUMES) { runBatch(bi, items, attempt + 1, done); return; }
        items.forEach(function (it) {
          results.push({ id: it.id, outcome: "fail",
                         error: "batch could not start: " + ((e && e.message) || String(e)) });
        });
        done();
      });
      child.on("close", function (code) {
        if (finished) return;
        finished = true;
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
  _checkTimeoutHandsOver();
  _checkSyncTimeoutStaysInProcess();
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
  var arrows = { summary: "arrow claims: not reached", broken: [] };
  function record(item, res, fromChild) {
    if (res.outcome === "ran") { ran += 1; if (fromChild) childRan += 1; }
    else if (res.outcome === "skip") skipped += 1;
    else failures.push({ sig: (item && item.sig) || "?",
                         error: String(res.error).split("\n").slice(0, 2).join(" ") });
  }

  // The drain runs last for a reason the teardown below depends on: the final
  // batch resolves from its child's `close`, which fires before Node has
  // finished releasing the ChildProcess itself, so without waiting the file
  // returns with a handle still registered and the runner force-exits the
  // worker to get rid of it. Waiting keeps the exit clean and keeps a REAL leak
  // visible instead of buried in that same warning.
  await helpers.withDrain("jsdoc-example-execution", async function () {
    for (var i = 0; i < all.inProcess.length; i += 1) {
      var item = all.inProcess[i];
      record(item, await runtime.runExampleInContext(item.body, {
        context: runtime.makeContext({}), timeoutMs: 1500,                                        // allow:raw-byte-literal // allow:raw-time-literal — in-process ceiling
      }));
    }
    var childResults = await _runStatefulBatches(all.stateful, tmp);
    childResults.forEach(function (r) { record(byId[r.id], r, true); });
    // Both halves: the split above is about what an example NEEDS to run, and
    // a pure function can sit in a module whose name matches the stateful
    // pattern — b.mail.server.imap.legacyMUtf7Allowed is one, and its arrow
    // was wrong. An example that really does need a listener or a disk fails
    // to run under this sandbox and is counted unchecked, which is what the
    // pass already does with anything it cannot settle.
    arrows = await _checkArrowClaims(all.inProcess.concat(all.stateful));
  }, async function () {
    try { await teardownTestDb(tmp); } catch (_e) { /* best-effort */ }
    process.chdir(origCwd);
    process.removeListener("unhandledRejection", onReject);
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (_e2) { /* best-effort */ }
  });

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
  // The arrow pass goes in the file too: under a forked smoke worker its
  // stdout is not folded into smoke.log, so a broken claim would otherwise be
  // readable only by re-running the gate.
  var report = summary + "\n" +
    failures.map(function (f) { return "  FAIL " + f.sig + " :: " + f.error; }).join("\n") + "\n" +
    "[jsdoc-example-execution] " + arrows.summary + "\n" +
    arrows.broken.map(function (f) {
      return "  CLAIM " + f.sig + " :: " + f.expr + "\n" +
             "         said: " + f.said + "\n" +
             "         got:  " + f.got;
    }).join("\n") + "\n";
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
