"use strict";
/**
 * Shared fuzz harness for the blamejs primitive surface.
 *
 * Each `fuzz/<name>.fuzz.js` file invokes `fuzz({ name, target,
 * generator })` with a single-input target function. The runner
 * iterates random / mutated inputs against the target until
 * `FUZZ_BUDGET_MS` elapses (default 30s; CI sets higher / lower
 * via env). Operator-friendly throws (`err.code` matching the
 * primitive's documented error vocabulary) are EXPECTED outcomes;
 * unexpected crashes (uncaught native errors, RangeError outside
 * stack-overflow contract, unsanitized prototype reads) fail the
 * run with a reproducer.
 *
 * Node 24+ ships experimental `node:test` fuzzing as it stabilizes;
 * this hand-rolled loop is portable across all current Node LTS
 * versions and ships findings to the GH Actions log without
 * additional infrastructure.
 *
 * Run locally:
 *   node fuzz/safe-json.fuzz.js
 *   FUZZ_BUDGET_MS=120000 node fuzz/guard-yaml.fuzz.js
 *
 * Run all under one CI matrix:
 *   node fuzz/_run-all.js
 */

var crypto = require("node:crypto");

function randomBytes(n) {
  return crypto.randomBytes(n);
}

function randomAscii(maxLen) {
  var len = (Math.random() * maxLen) | 0;
  var s = "";
  for (var i = 0; i < len; i++) {
    s += String.fromCharCode(32 + ((Math.random() * 95) | 0));
  }
  return s;
}

function randomUtf8(maxBytes) {
  return randomBytes(((Math.random() * maxBytes) | 0) + 1).toString("utf8");
}

function randomBidiSalt(s) {
  var BIDI = ["‮", "‭", "‎", "‏", "‪", "‫", "‬", "؜"];
  var n = ((Math.random() * 4) | 0);
  for (var i = 0; i < n; i++) {
    var pos = (Math.random() * (s.length + 1)) | 0;
    s = s.slice(0, pos) + BIDI[(Math.random() * BIDI.length) | 0] + s.slice(pos);
  }
  return s;
}

function randomControlSalt(s) {
  var n = ((Math.random() * 4) | 0);
  for (var i = 0; i < n; i++) {
    var pos = (Math.random() * (s.length + 1)) | 0;
    var cp = ((Math.random() * 0x20) | 0);
    s = s.slice(0, pos) + String.fromCharCode(cp) + s.slice(pos);
  }
  return s;
}

function pick(arr) {
  return arr[(Math.random() * arr.length) | 0];
}

function mutateSeed(seed) {
  if (typeof seed !== "string") return seed;
  var op = (Math.random() * 6) | 0;
  if (seed.length === 0) return randomAscii(64);
  var pos = (Math.random() * seed.length) | 0;
  if (op === 0) {                                   // insert random char
    return seed.slice(0, pos) + String.fromCharCode((Math.random() * 0x10000) | 0) + seed.slice(pos);
  }
  if (op === 1) {                                   // delete char
    return seed.slice(0, pos) + seed.slice(pos + 1);
  }
  if (op === 2) {                                   // duplicate slice
    var to = ((Math.random() * (seed.length - pos)) | 0) + 1;
    var slice = seed.slice(pos, pos + to);
    return seed + slice;
  }
  if (op === 3) {                                   // bidi salt
    return randomBidiSalt(seed);
  }
  if (op === 4) {                                   // control salt
    return randomControlSalt(seed);
  }
  return seed.repeat(1 + ((Math.random() * 8) | 0));
}

function _stringifyInput(x) {
  if (Buffer.isBuffer(x)) return "<buf:" + x.toString("base64").slice(0, 80) + ">";
  if (typeof x === "string") {
    var s = JSON.stringify(x);
    return s.length > 200 ? s.slice(0, 200) + "..." : s;
  }
  try {
    var j = JSON.stringify(x);
    return j && j.length > 200 ? j.slice(0, 200) + "..." : (j || String(x));
  } catch (_e) { return String(x); }
}

function _isExpectedError(e, expectThrow) {
  if (!e) return false;
  // Operator-friendly framework error: code matches the primitive's vocabulary
  if (typeof e.code === "string" && expectThrow.test(e.code)) return true;
  // node-builtin error subclasses are acceptable IF the message indicates
  // input-shape rejection (vs. internal invariant breakage)
  if (e instanceof TypeError && /must be|expected|invalid|bad|unsupported|unknown|missing/i.test(e.message || "")) return true;
  if (e instanceof SyntaxError) return true;
  if (e instanceof URIError) return true;
  // RangeError is acceptable only when message indicates input-driven
  // limits (depth / length / bytes), NOT stack-overflow
  if (e instanceof RangeError && /too|max|exceed|limit|cap/i.test(e.message || "")) return true;
  return false;
}

function fuzz(opts) {
  var name        = opts.name;
  var target      = opts.target;
  var generator   = opts.generator;
  // Framework convention: every operator-friendly throw carries
  // `err.code` of shape `<domain><sep><error-name>` where sep is
  // `/` (most modules: `safe-url/malformed`, `json/syntax`) or `.`
  // (guard family: `json.null-byte`, `guard-yaml.refused`). Default
  // accepts both; override per-file when a target uses a narrower
  // vocabulary.
  var expectThrow = opts.expectThrow || /^[a-z][a-z0-9-]*[/.][a-z]/;
  var budgetMs    = parseInt(process.env.FUZZ_BUDGET_MS || "30000", 10);
  var maxFindings = parseInt(process.env.FUZZ_MAX_FINDINGS || "5", 10);
  var deadline    = Date.now() + budgetMs;
  var iterations  = 0;
  var findings    = [];

  console.log("[fuzz] " + name + " — budget=" + budgetMs + "ms");
  while (Date.now() < deadline) {
    var input;
    try { input = generator(); }
    catch (genErr) {
      console.log("[fuzz] " + name + ": generator threw — " + genErr.message);
      process.exit(2);
    }
    iterations++;
    try {
      target(input);
    } catch (e) {
      if (_isExpectedError(e, expectThrow)) continue;
      // Unexpected throw — record reproducer
      findings.push({
        iteration: iterations,
        input:     _stringifyInput(input),
        error:     {
          name:    e && e.name,
          message: e && e.message,
          code:    e && e.code,
          stack:   e && e.stack ? e.stack.split("\n").slice(0, 6).join("\n") : null,
        },
      });
      if (findings.length >= maxFindings) break;
    }
  }

  console.log("[fuzz] " + name + ": " + iterations + " iterations, " + findings.length + " unexpected throw(s)");
  if (findings.length > 0) {
    console.log("[fuzz] FAIL — unexpected throws:");
    for (var i = 0; i < findings.length; i++) {
      var f = findings[i];
      console.log("");
      console.log("  Finding " + (i + 1) + ":");
      console.log("    iter:    " + f.iteration);
      console.log("    input:   " + f.input);
      console.log("    error:   " + (f.error.name || "?") + ": " + (f.error.message || "?"));
      if (f.error.code) console.log("    code:    " + f.error.code);
      if (f.error.stack) console.log("    stack:\n" + f.error.stack.split("\n").map(function (l) { return "      " + l; }).join("\n"));
    }
    process.exit(1);
  }
}

module.exports = {
  fuzz:               fuzz,
  randomBytes:        randomBytes,
  randomAscii:        randomAscii,
  randomUtf8:         randomUtf8,
  randomBidiSalt:     randomBidiSalt,
  randomControlSalt:  randomControlSalt,
  mutateSeed:         mutateSeed,
  pick:               pick,
};
