// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Shared runtime for @example execution — used by BOTH the in-process pass and
 * the child-process pass.
 *
 * The two passes differ only in what an example is allowed to touch: in-process
 * examples run against a sandboxed require and no real I/O, child-process ones
 * run against the real thing inside a disposable directory. Everything else —
 * which examples are safe in-process, what a sandbox looks like, and above all
 * how a thrown error is CLASSIFIED — has to be identical, or the two passes
 * disagree about what counts as a defect and the gate means different things
 * depending on which side an example lands on.
 */

var path = require("path");
var vm   = require("node:vm");

var ROOT = path.resolve(__dirname, "..", "..");
var b    = require(ROOT);

// Any example that could perform real I/O or long-lived / stateful work is not
// executed IN PROCESS. Broad on purpose — a false skip is safe, a false run is
// not. These are exactly the ones the child pass picks up, where a stray write
// lands in a disposable directory and a wedged example is killed.
var STATEFUL_OR_IO = new RegExp([
  "daemon", "vault", "\\bdb\\b", "\\.open\\(", "listen", "server", "\\bmail\\b",
  "deliver", "network", "\\bhttp", "fetch", "\\bdns\\b", "audit", "queue", "cron",
  "\\.watch\\(", "spawn", "exec\\(", "writeFile", "readFile", "mkdir", "unlink",
  "upload", "\\.start\\(", "\\.stop\\(", "generateKey", "keypair", "getKeys",
  "\\.sign\\(", "\\.send\\(", "fileUpload", "static\\(", "\\.pipe\\(",
  "\\.subscribe\\(", "createServer", "\\.connect\\(", "\\.request\\(", "\\.bind\\(",
  "process\\.", "require\\(\"node:", "require\\(\"fs", "require\\(\"net",
  "require\\(\"child_process", "require\\(\"dns", "require\\(\"http",
  "hashFile", "createReadStream", "createWriteStream", "etc/hosts",
  "template", "\\brender\\b", "viewsDir", "listBackends",
  "workerThread", "makeSkipMatcher",
].join("|"), "i");

var SAFE_BUILTINS = { crypto: 1, "node:crypto": 1, path: 1, "node:path": 1,
  buffer: 1, "node:buffer": 1, util: 1, "node:util": 1, url: 1, "node:url": 1,
  querystring: 1, "node:querystring": 1, assert: 1, "node:assert": 1, zlib: 1, "node:zlib": 1 };

// require() seen by an example: framework alias → a FRESH object (never `b`
// itself, so an example writing to the export can't mutate the real surface —
// and no extra members: an example calling a method the shipped export
// doesn't have must FAIL, that drift is exactly what this test catches);
// safe builtins pass through; anything else classifies as an external
// (illustrative) module.
//
// `allowAnyModule` is the child pass: there, an example that requires a node
// builtin is the POINT rather than a reason to skip, so the whole builtin set
// is allowed. A non-builtin is still refused — an example naming a package the
// framework does not ship is illustrative wherever it runs.
function makeRequire(allowAnyModule) {
  return function exampleRequire(name) {
    if (name === "blamejs" || name === "@blamejs/core") return Object.assign({}, b);
    if (Object.prototype.hasOwnProperty.call(SAFE_BUILTINS, name)) return require(name);
    if (allowAnyModule && /^(?:node:)?[a-z_]+$/.test(name)) {
      try { return require(name); } catch (_e) { /* fall through to illustrative */ }
    }
    var e = new Error("example references external module '" + name + "'");
    e.code = "EXAMPLE_EXTERNAL_MODULE";
    throw e;
  };
}

function makeContext(opts) {
  opts = opts || {};
  var noop = function () {};
  var sandbox = {
    b: b,
    require: makeRequire(opts.allowAnyModule === true),
    console: { log: noop, error: noop, warn: noop, info: noop, debug: noop },
    Buffer: Buffer,
    JSON: JSON, Math: Math, Date: Date, Promise: Promise, Object: Object, Array: Array,
    Map: Map, Set: Set, Symbol: Symbol, RegExp: RegExp, Error: Error, TypeError: TypeError,
    URL: URL, URLSearchParams: URLSearchParams, TextEncoder: TextEncoder, TextDecoder: TextDecoder,
    structuredClone: (typeof structuredClone === "function" ? structuredClone : undefined),
  };
  if (opts.allowAnyModule) {
    // The child pass runs examples that legitimately reach the platform.
    sandbox.process    = process;
    sandbox.setTimeout = setTimeout;
    sandbox.setInterval = setInterval;
    sandbox.clearTimeout = clearTimeout;
    sandbox.clearInterval = clearInterval;
    sandbox.__dirname  = process.cwd();
    sandbox.__filename = path.join(process.cwd(), "example.js");
  }
  return vm.createContext(sandbox);
}

// An example may DECLARE the operator environment it assumes, as its first
// line: `// requires: a configured views directory`. Such an example is not
// executed, because it describes a call against an app that is already running
// rather than one it sets up itself.
//
// This is a marker in the DOCUMENTATION, not an allowlist in a test file, and
// that is the point: it renders on the primitive's page, so an operator reads
// the prerequisite too, and hiding a broken example behind it costs something
// visible. A silent skip list in here would cost nothing and mean nothing.
var DECLARES_PREREQUISITE = /^\s*\/\/\s*requires:/;

function declaresPrerequisite(body) {
  var first = String(body || "").split("\n").find(function (l) { return l.trim() !== ""; });
  return DECLARES_PREREQUISITE.test(first || "");
}

// One classifier for both passes. A throw is only a DEFECT when it says the
// documented API is wrong — a renamed method, a removed export, an argument
// shape the code no longer accepts. Everything else an example can hit
// (an identifier only the docs' surrounding prose defines, a module the
// framework does not ship, an environment the example describes rather than
// creates) is illustrative, and counting it as a failure would make the gate
// unrunnable rather than strict.
function classify(e, opts) {
  opts = opts || {};
  // No network in the gate. An example that reaches a real host is describing
  // an integration, and "fetch failed" says nothing about whether the API it
  // documents still exists.
  if (e && /^fetch failed$/i.test(String(e.message || ""))) {
    return { outcome: "skip", reason: "needs network" };
  }
  // A timeout means different things on the two sides. In process there is no
  // real I/O, so an example that awaits something never gets it and waiting is
  // uninformative. In a CHILD the example has a working environment — its own
  // database, its own directory, the platform — so running past the ceiling
  // means it hung, and a hang in a documented example is exactly what this
  // gate should refuse to pass over. Skipping it would leave the wedged
  // examples the child pass exists to reach silently unexamined.
  if (opts.timeoutIsFailure && e &&
      /^test timed out:|Script execution timed out/.test(String(e.message || ""))) {
    return { outcome: "fail",
             error: "example did not settle within its ceiling: " + ((e && e.message) || String(e)) };
  }
  // Errors thrown INSIDE the vm context are instances of the context's own
  // constructors, so cross-realm `instanceof` fails — classify by name/flag.
  var name = e && e.name;
  if (name === "ReferenceError") return { outcome: "skip", reason: "external identifier" };
  if (e && e.code === "EXAMPLE_EXTERNAL_MODULE") return { outcome: "skip", reason: "external module" };
  if (e && /^test timed out:|Script execution timed out/.test(String(e.message || ""))) return { outcome: "skip", reason: "timeout" };
  // A framework typed error means the API RESOLVED + ran + threw its own error
  // (a precondition / needs-init / input-validation demo) — the API exists, so
  // it is NOT the renamed/removed-API drift this gate targets. (Regressions where
  // the framework WRONGLY throws are the marker-convention's job, not auto-classify.)
  if (e && e.isFrameworkError) return { outcome: "skip", reason: "framework error (precondition/input demo)" };
  // Node/fs/network errors from an environment the example describes rather
  // than creates — a listener already bound, a host that does not resolve.
  if (e && /^E[A-Z]+$/.test(String(e.code || ""))) return { outcome: "skip", reason: "filesystem/OS error" };
  // The example assumes an operator-declared table/column the isolated test db
  // doesn't have (e.g. subject.rectify over a `users` table) — illustrative.
  if (e && /no such (table|column)/i.test(String(e.message || ""))) return { outcome: "skip", reason: "needs operator-specific schema" };
  return { outcome: "fail", error: (e && (e.stack || e.message)) || String(e) };
}

/**
 * runExampleInContext(body, opts) — compile and await one @example.
 *
 * @param opts.context   {object}  a vm context from makeContext()
 * @param opts.timeoutMs {number}  wall-clock ceiling for the whole example
 * @param opts.syncTimeoutMs {number} ceiling for SYNCHRONOUS execution — the vm
 *   option only caps synchronous work, so an awaiting example that never
 *   settles needs the wall-clock ceiling above as well
 * @param opts.timeoutIsFailure {boolean} an example that runs past the ceiling
 *   is a FAILURE rather than a skip — for the child pass, where the example
 *   has a real environment and a hang is therefore the example's own
 * @param opts.nativeRealm {boolean} run in THIS realm instead of a vm context.
 *   A vm context has its own intrinsics, so a RegExp / Array / Date literal
 *   written inside an example is not an instance of the framework's RegExp,
 *   and every `instanceof` the framework does on operator input fails — the
 *   example is then reported broken when it is the harness that is wrong
 *   (`makeSkipMatcher` refusing a perfectly good `/^\/webhooks\//` is what
 *   surfaced it). The child pass is already an isolated process with a
 *   disposable directory, so the vm buys it nothing and costs it that.
 * @returns {Promise<object>} { outcome: "ran" } or a classify() verdict
 */
async function runExampleInContext(body, opts) {
  if (declaresPrerequisite(body)) {
    return { outcome: "skip", reason: "declares an operator prerequisite" };
  }
  var wrapped = "(async function () {\n" + body + "\n})();";
  var timeoutMs = opts.timeoutMs || 1500;                                                        // allow:raw-byte-literal // allow:raw-time-literal — per-example ceiling
  try {
    await new Promise(function (resolve, reject) {
      var settled = false;
      var timer = setTimeout(function () {
        if (settled) return;
        settled = true;
        reject(new Error("test timed out: jsdoc @example execution (after " + timeoutMs + "ms)"));
      }, timeoutMs);
      // Deliberately NOT unref'd. An example that awaits a promise which never
      // settles and holds no handle of its own leaves this timer as the only
      // thing keeping the loop alive — unref it and the process exits 0 before
      // the timeout fires or the final checks run, turning exactly the wedged
      // example this ceiling exists to catch into a silent pass. Every settle
      // path clears it, so keeping it referenced costs nothing.
      Promise.resolve()
        .then(function () {
          if (opts.nativeRealm) {
            var ctx = opts.context;
            // The compiled string is an @example body read out of this repo's
            // OWN lib/ comment blocks — it is the code under test, not input.
            // There is no untrusted value interpolated here and no path by
            // which one could be: the parser's only source is the checked-in
            // tree, which is also what the vm branch below executes. Running
            // it is the entire point of the gate.
            var fn = new Function("b", "require", "console", "\"use strict\";\nreturn " + wrapped);
            return fn(ctx.b, ctx.require, ctx.console);
          }
          return new vm.Script(wrapped, { filename: "example.js" })
            .runInContext(opts.context, { timeout: opts.syncTimeoutMs || 1000 });                // allow:raw-byte-literal // allow:raw-time-literal — synchronous ceiling
        })
        .then(function (v) { if (!settled) { settled = true; clearTimeout(timer); resolve(v); } },
              function (e) { if (!settled) { settled = true; clearTimeout(timer); reject(e); } });
    });
    return { outcome: "ran" };
  } catch (e) { return classify(e, { timeoutIsFailure: opts.timeoutIsFailure === true }); }
}

module.exports = {
  ROOT:                  ROOT,
  b:                     b,
  STATEFUL_OR_IO:        STATEFUL_OR_IO,
  makeContext:           makeContext,
  classify:              classify,
  declaresPrerequisite:  declaresPrerequisite,
  runExampleInContext:   runExampleInContext,
};
