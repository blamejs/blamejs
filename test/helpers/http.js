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
 * @example
 *   async function run() {
 *     try { await testEverything(); }
 *     finally { await helpers.drainOpenHandles("http-client"); }
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

module.exports = {
  listenOnRandomPort: b.testing.listenOnRandomPort,
  drainOpenHandles:   drainOpenHandles,
};
