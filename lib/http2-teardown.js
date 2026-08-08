// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * HTTP/2 session teardown — graceful close *then* force-destroy.
 *
 * `Http2Session.close()` is the *graceful* close: it returns synchronously
 * while letting in-flight streams complete on their own, but it does NOT
 * free the underlying TCP socket until those streams complete (or the
 * peer disconnects). On idle / error / fallback paths — where we
 * explicitly DON'T want the session anymore — that means the socket
 * lingers until the OS-level TCP timeout fires. In a test process the
 * mock-server's `server.close()` then waits for that lingering socket
 * to release, which on Linux can be tens of minutes. v0.6.58 hit
 * exactly this in the OTLP-gRPC sink and timed out the npm-publish
 * workflow on every tag from v0.6.38 → v0.6.57.
 *
 * The fix is structural: every call site that wants the session GONE
 * routes through this helper, which calls close() (best-effort drain)
 * then destroy() (force socket teardown). Used by `lib/http-client.js`
 * (h2 transport pool — fallback, error, idle-timeout, reset) and by
 * `lib/log-stream-otlp-grpc.js` (sink shutdown after final flush).
 *
 * No-op on a null / undefined session. Wraps each call in try/catch so
 * a partially-torn-down session can't throw and cancel the second call.
 */

var C = require("./constants");
var safeAsync = require("./safe-async");

function tearDownH2Session(session) {
  if (!session) return;
  try { if (typeof session.close === "function") session.close(); }
  catch (_e1) { /* best-effort graceful */ }
  try { if (typeof session.destroy === "function") session.destroy(); }
  catch (_e2) { /* best-effort socket teardown */ }
}

// drainH2Session(session, graceMs) — retire a session WITHOUT cutting off the
// streams already running on it.
//
// tearDownH2Session is the right call when the session is unwanted: it forces
// the socket down, which also kills any open stream. That is wrong when the
// session is merely no longer ELIGIBLE for new work — retiring a pooled
// transport after a TLS-posture change, say — because the requests already in
// flight on it are unrelated to the policy that changed and must be allowed
// to finish.
//
// close() alone is the graceful half: it refuses new streams and frees the
// socket once the open ones complete. On its own it is also how v0.6.58 hung
// a publish workflow — if a stream never completes, the socket lingers until
// the OS TCP timeout. So this pairs it with a bounded fallback: after the
// grace period, force the socket down. The timer is unref'd, so a process
// whose work is otherwise finished still exits promptly.
var DEFAULT_DRAIN_GRACE_MS = C.TIME.seconds(30);

function drainH2Session(session, graceMs) {
  if (!session) return;
  try { if (typeof session.close === "function") session.close(); }
  catch (_e) { /* best-effort graceful close */ }
  var grace = typeof graceMs === "number" && graceMs > 0 ? graceMs : DEFAULT_DRAIN_GRACE_MS;

  // The fallback fires only for a session that has STOPPED, not one that is
  // merely slow. A fixed deadline cannot tell those apart, and downloadStream
  // has no wall-clock limit of its own — so a one-shot timer would cut a
  // legitimate multi-minute download at the grace period because something
  // unrelated changed the TLS posture. Poll instead, and use the socket's
  // byte counters as the progress signal: while bytes keep moving the drain
  // waits, and only a window with no movement at all forces the socket down.
  var lastMoved = -1;
  var watch = safeAsync.repeating(function () {
    if (session.destroyed) { watch.stop(); return; }
    var sock = session.socket;
    var moved = sock ? (Number(sock.bytesRead) || 0) + (Number(sock.bytesWritten) || 0) : 0;
    if (moved !== lastMoved) { lastMoved = moved; return; }   // still progressing
    watch.stop();
    try { if (typeof session.destroy === "function") session.destroy(); }
    catch (_e) { /* best-effort socket teardown */ }
  }, grace, { name: "h2-drain-watch" });
}

module.exports = {
  tearDownH2Session: tearDownH2Session,
  drainH2Session:    drainH2Session,
};
