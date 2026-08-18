// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * check + counter — the framework's custom assertion + cross-file
 * counter (kept instead of node:test for now; the per-file split is
 * the modularity win, the assertion swap is orthogonal scope).
 *
 * One global counter shared by every test file via this module's
 * singleton-require semantics. The smoke runner reads getChecks()
 * after walking every layer to print the total.
 */

var _checks = 0;

// `detail` is the diagnostic a failing check wants to hand the reader — the
// offending items, the count, the name that differed. It was accepted at 1829
// call sites and discarded by every one of them, so a gate failure printed its
// label and nothing else, and the work of building the message was thrown away
// at the moment it was needed. Bounded and flattened to one line for the same
// reason formatErr is: the text can carry a fixture's bytes verbatim, and a
// newline in it would forge an extra log line.
function check(label, condition, detail) {
  if (!condition) {
    var extra = "";
    if (detail !== undefined && detail !== null && detail !== "") {
      extra = " -- " + String(detail)
        .replace(/[\r\n]+/g, " ")
        .replace(/\t+/g, " ")
        .replace(/ {2,}/g, " ");
      if (extra.length > 1000) extra = extra.slice(0, 1000) + "...";
    }
    throw new Error("FAIL: " + label + extra);
  }
  _checks += 1;
}

function getChecks()         { return _checks; }
function resetChecksForTest() { _checks = 0; }

// addExternalChecks — the parallel smoke runner forks per-file
// children; each child runs its own _checks counter in its process
// and reports it back to the parent. The parent calls this to fold
// the children's counts into the parent total so the final
// "OK — N checks passed" line aggregates correctly.
function addExternalChecks(n) {
  if (typeof n === "number" && isFinite(n) && n >= 0) _checks += n;
}

// formatErr — render a thrown error as a single-line, bounded diagnostic for a
// test runner's failure catch. A thrown error's message/stack can carry a test
// fixture's bytes verbatim; replacing CR/LF (a recognized log-injection
// barrier) keeps the "FAIL:" line on one row so a fixture value can't forge
// extra log lines. The newline .replace() is what breaks the log-injection
// data flow; the tab/run-collapse + length bound are cosmetic.
function formatErr(e) {
  var raw = (e && typeof e.stack === "string" && e.stack) ||
            (e && typeof e.message === "string" && e.message) ||
            String(e);
  var oneLine = raw
    .replace(/[\r\n]+/g, " ")
    .replace(/\t+/g, " ")
    .replace(/ {2,}/g, " ");
  return oneLine.length > 2000 ? oneLine.slice(0, 2000) + "..." : oneLine;
}

module.exports = {
  check:              check,
  getChecks:          getChecks,
  resetChecksForTest: resetChecksForTest,
  addExternalChecks:  addExternalChecks,
  formatErr:          formatErr,
};
