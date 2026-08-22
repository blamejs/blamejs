// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * HTTP test helpers — random-port listener + end-of-file open-handle drain.
 *
 * `listenOnRandomPort` is a thin re-export of `b.testing.listenOnRandomPort`
 * — the canonical implementation lives in lib/testing.js so operators get
 * the same helper the framework's own smoke suite uses.
 */

var b = require("../../index.js");
var wait = require("./wait");

// A handle that is CLOSING still counts, so the drain measures libuv's close
// callbacks completing rather than a JS-side flag flipping.
//
// The list is the union of what the per-file copies waited for, and the union
// is the right scope rather than an accident of which file needed what: a
// datagram socket and an in-flight file read hold the event loop open exactly
// as a stream socket does, and a file that serves static content is not
// special for having one outstanding. Anything that keeps the worker alive
// past run() belongs here.
// ProcessWrap is on the list for the same reason, and it was missing: a
// spawned child holds the event loop open exactly as a socket does, and the
// runner's end-of-pass audit already reports one — so a file could leak a
// child, be told about it by the runner, and still drain "clean" here.
//
// The name is the RESOURCE's, not the JS object's. The runner reports the
// constructor ("ChildProcess") because it reads process._getActiveHandles();
// this list is matched against getActiveResourcesInfo(), which calls the same
// thing ProcessWrap. Using the friendlier name matches nothing and drains
// green past exactly the leak it was added for.
//
// PipeWrap is deliberately absent: a process whose own stdout is a pipe — any
// run whose output is redirected — reports two of them for its own streams,
// and the IPC channel of a forked worker is a third.
var OPEN_HANDLE_TYPES = ["TCPSocketWrap", "TCPServerWrap", "UDPWrap", "FSReqCallback", "ProcessWrap"];

// Only a handle that NEVER closes should fail a file. That is the invariant
// the drain is here for — a leaked socket keeps the forked worker alive past
// its run() and turns into an unattributable watchdog kill 300s later.
//
// The ceiling is therefore a LEAK VERDICT, not a latency guess, and it is set
// far above any real close latency for the same reason a ReDoS backstop is:
// the precision comes from the predicate ("zero handles"), never from the
// clock. Measured cost with nothing leaking is 25-28ms, both on an idle box
// and with 64 network-heavy copies of the heaviest such file running at once
// on 32 cores. 30s is ~1000x that, and still well inside smoke's 300s
// per-file watchdog, so a genuine leak fails NAMED and fast rather than as a
// SIGKILL nobody can attribute.
var DEFAULT_DRAIN_MS = 30000;                                                                    // allow:raw-byte-literal // allow:raw-time-literal — leak verdict, see above

function _liveOpenHandles() {
  if (typeof process.getActiveResourcesInfo !== "function") return [];
  return process.getActiveResourcesInfo().filter(function (t) {
    return OPEN_HANDLE_TYPES.indexOf(t) !== -1;
  });
}

// Best-effort identification of what is still open, for the failure message.
// A handle already detached from its JS object is invisible here — that
// absence is itself a signal (it is mid-close rather than leaked), so the
// caller says so instead of printing nothing.
function _describeOpenHandles() {
  var out = [];
  var handles = typeof process._getActiveHandles === "function" ? process._getActiveHandles() : [];
  handles.forEach(function (h) {
    var inner = h && h._handle && h._handle.constructor && h._handle.constructor.name;
    if (inner !== "TCP" && inner !== "UDP") return;
    var parts = [inner, h.constructor && h.constructor.name];
    try {
      if (h.listening === true || inner === "UDP") parts.push("bound " + JSON.stringify(h.address()));
      else parts.push((h.localAddress || "?") + ":" + (h.localPort || "?") +
                      " -> " + (h.remoteAddress || "-") + ":" + (h.remotePort || "-"));
    } catch (_e) { parts.push("(address unavailable)"); }
    try { parts.push("destroyed=" + !!h.destroyed, "readable=" + !!h.readable, "writable=" + !!h.writable); }
    catch (_e) { /* not inspectable */ }
    out.push(parts.join(" "));
  });
  return out;
}

/**
 * drainOpenHandles(label, opts?) — retire the httpClient transport pool and
 * wait for every socket and pending file operation in the process to finish,
 * so a file's async teardown completes inside its own run() instead of in the
 * forked worker's post-run window, where a leak is attributable to nobody.
 *
 * Call it once at the end of run(), or in a `finally` around it. It is safe in
 * a file that never touched b.httpClient — clearing an empty pool is a no-op.
 *
 * Close what the file itself opened FIRST (servers, upgrade sockets, datagram
 * sockets): this waits for closes to complete, it does not issue them.
 *
 * @param label {string} — the file's name; surfaces in the failure message
 * @param opts.timeoutMs {number?} — override the leak-verdict ceiling
 * @throws Error naming what is still open when nothing ever closes
 *
 * Call it through `withDrain` rather than from a `finally` of your own: a
 * throw from a `finally` replaces the body's error, so the check that actually
 * failed is lost and the leak its skipped teardown caused is all that gets
 * reported. This example used to show that shape, which is how thirty files
 * came to be written that way.
 *
 * @example
 *   async function run() {
 *     await helpers.withDrain("http-client", testEverything);
 *   }
 */
async function drainOpenHandles(label, opts) {
  opts = opts || {};
  if (typeof label !== "string" || label.length === 0) {
    throw new TypeError("drainOpenHandles: label (string) required — names the file in a drain failure");
  }
  // Retiring the pool is what lets the sockets close at all; a file whose
  // requests are still parked in a cached agent would otherwise wait out the
  // whole ceiling and then report a "leak" of its own making.
  try { b.httpClient._resetForTest(); } catch (_e) { /* pool never built */ }
  if (typeof process.getActiveResourcesInfo !== "function") return;
  var timeoutMs = typeof opts.timeoutMs === "number" ? opts.timeoutMs : DEFAULT_DRAIN_MS;
  var started = Date.now();
  try {
    await wait.waitUntil(function () { return _liveOpenHandles().length === 0; },
      { timeoutMs: timeoutMs, label: label + ": open-handle drain after teardown" });
  } catch (_e) {
    var live = _liveOpenHandles();
    var detail = _describeOpenHandles();
    throw new Error(
      "drainOpenHandles: " + label + " — " + live.length + " open handle(s) (" + live.join(", ") +
      ") still open " + (Date.now() - started) + "ms after teardown. " +
      (detail.length
        ? "Still open: " + detail.join(" | ") + ". "
        : "None are reachable from process._getActiveHandles(): a pending FSReqCallback never appears " +
          "there (it is a request, not a handle), and a socket that does not appear there is already " +
          "detached and mid-close rather than live. Suspect an fs call whose callback never runs, or a " +
          "close that never completes. ") +
      "This is a leaked handle in the code under test or in this file's own teardown: raising the " +
      "ceiling only delays the same verdict.");
  }
}

// Run a file's tests, then drain, WITHOUT letting the drain swallow why the
// tests stopped.
//
// `try { ...tests... } finally { await drainOpenHandles(label) }` reads as
// correct and is not: when the body throws, every teardown after the throw is
// skipped, so the drain finds the servers those teardowns would have closed and
// throws too — and a throw from a `finally` REPLACES the body's error. What
// surfaces is "a handle leaked", which is a consequence; what caused it is
// discarded. That is why such a failure reads as an unexplained flake: the
// check that actually failed is never named, and the leak looks like the bug.
//
// Here the body's error wins and the drain's is appended to it, so a run that
// failed for a reason reports that reason, and a run that only leaked still
// reports the leak.
// Appending to `err.message` only works when the error IS one. A test that
// throws a string reaches this with a primitive, where assigning a property is
// a silent no-op outside strict mode — so the note it was given would simply
// vanish. Report what cannot be attached instead of dropping it.
function _note(err, text) {
  // One outer guard, not a guard per property. Everything below READS the
  // failure to describe it, and a thrown object can make reading throw: a
  // getter that raises, a Proxy that traps. Any such exception escaping from
  // here would become what the run reports, which is the masking this helper
  // exists to prevent, reached through the diagnostic path instead of through
  // a `finally`. So the invariant is stated once, at the boundary: annotating
  // never replaces what it annotates. If the note cannot be attached, the
  // original failure goes back untouched.
  try {
    return _noteOrThrow(err, text);
  } catch (_annotationFailed) {
    return err;
  }
}

// Reading a message can throw for the same reasons _note guards against, and
// every caller below reads one to build its note. Doing it here means the
// annotation text is built without any read that can take down the run.
function _describe(e) {
  try { return (e && e.message) || String(e); }
  catch (_unreadable) { return "<an error whose message could not be read>"; }
}

function _noteOrThrow(err, text) {
  // Captured BEFORE anything is mutated. The append below can half-succeed —
  // a writable `message` beside an immutable `stack` takes the note and then
  // throws — and a fallback that rebuilt from `err.message` would read the
  // already-appended text and print the note twice.
  var original = (err && typeof err === "object" && typeof err.message === "string")
    ? err.message
    : String(err);
  if (err && typeof err === "object" && typeof err.message === "string") {
    // Appending MUTATES the error, and an error can refuse to be mutated — a
    // frozen one, or a `message` defined non-writable. In strict mode that
    // assignment throws, and the throw escapes from here and replaces the
    // failure this function was called to annotate. The annotation must never
    // be able to destroy what it annotates, so a refusal to mutate falls back
    // to carrying the same information in a new error.
    try {
      err.message += text;
      // The message is not where anyone reads it — a runner prints `.stack`.
      // V8 formats that string once, on first read, and caches it, so an error
      // some assertion or logger already touched carries a stack headed by the
      // OLD message and appending to `.message` alone leaves the note invisible.
      // An untouched error formats its stack now, from the message that already
      // carries the note, so the guard is whether the note is there yet rather
      // than whether the stack was cached — checking the outcome instead of
      // guessing the state avoids printing it twice.
      if (typeof err.stack === "string" && err.stack.indexOf(text) === -1) {
        err.stack += text;
      }
      return err;
    } catch (_immutable) { /* fall through to the wrapped form */ }
  }
  var wrapped = new Error(original + text);
  // Keep the original reachable, but do NOT copy its stack over the wrapper's.
  // A stack string starts with its own error's message, and a runner prints
  // `.stack` rather than `.message` — so overwriting it puts the original's
  // message back at the top and drops the appended note from the one place
  // anybody reads. The wrapper's stack already opens with the combined
  // message; the original's frames are appended below it as context.
  if (err && typeof err === "object") {
    wrapped.cause = err;
    if (err.code !== undefined) wrapped.code = err.code;
    if (typeof err.stack === "string" && typeof wrapped.stack === "string") {
      wrapped.stack += "\n  caused by: " + err.stack;
    }
  }
  return wrapped;
}

// `teardown` is the file's own cleanup — destroying a global agent, closing
// websocket clients and their detached sockets, resetting module state. It
// belongs HERE rather than in a `finally` of the caller's own, for the reason
// this helper exists: it is throwable work, and work that throws in a `finally`
// replaces the error the run actually failed on. Six files kept theirs in a
// `finally` around a local wrapper and so had MORE ways to lose the failure,
// not fewer.
//
// Order is body, then teardown, then drain, because the drain judges what the
// teardown was supposed to have released. Each is caught; the body's error wins
// and the later ones are appended to it.
async function withDrain(label, body, teardown, drainOpts) {
  if (typeof body !== "function") {
    throw new TypeError("withDrain: body (function) required");
  }
  if (teardown !== undefined && typeof teardown !== "function") {
    throw new TypeError("withDrain: teardown must be a function when given");
  }
  // Whether something threw is tracked as a FLAG, never as the truthiness of
  // what it threw. `throw null` and `throw ""` are failures, and a helper whose
  // whole promise is "every body failure is re-thrown" cannot decide that by
  // asking whether the failure was truthy — which is the same swallowing this
  // exists to stop, one level in.
  var failed  = false;
  var failure = null;
  var teardownRan = false;
  try {
    await body();
  } catch (e) {
    failed = true;
    failure = e;
  }
  if (teardown) {
    try {
      await teardown();
      teardownRan = true;
    } catch (tearErr) {
      if (!failed) { failed = true; failure = tearErr; }
      else failure = _note(failure, "\n  [teardown then reported: " +
        _describe(tearErr) + "]");
    }
  }
  try {
    // drainOpts reaches the drain's own ceiling. A suite that knows its budget
    // can say so, and a test of this helper can ask for a short one instead of
    // waiting out the default to observe a verdict it already arranged.
    await drainOpenHandles(label, drainOpts);
  } catch (drainErr) {
    if (!failed) throw drainErr;
    // What the leak most likely MEANS depends on whether cleanup actually ran,
    // so the note says which case this is instead of asserting one of them. The
    // original wording — "teardown did not run" — was written when the only
    // cleanup was the caller's own, inline and therefore skipped by the throw.
    // With a teardown supplied here that claim is simply false, and a false
    // explanation attached to a real leak sends the reader the wrong way.
    var why = teardownRan
      ? " — the file's teardown DID run, so this may be a leak of its own rather " +
        "than a consequence of the failure above"
      : (teardown
          ? " — the file's teardown did not complete, so this may be its work left undone"
          : " — cleanup after the failure above did not run, so this is likely a " +
            "consequence of it rather than a separate leak");
    failure = _note(failure, "\n  [the open-handle drain then reported: " +
      _describe(drainErr) + why + "]");
  }
  if (failed) throw failure;
}

module.exports = {
  listenOnRandomPort: b.testing.listenOnRandomPort,
  drainOpenHandles:   drainOpenHandles,
  withDrain:          withDrain,
};
