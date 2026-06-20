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

function check(label, condition) {
  if (!condition) throw new Error("FAIL: " + label);
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
// fixture's bytes verbatim; folding tab/CR/LF to a space and dropping the other
// C0/DEL control characters keeps the "FAIL:" line on one row so a fixture
// value can't forge extra log lines. Char-code filtering (not a control-char
// regex) keeps eslint's no-control-regex satisfied.
function formatErr(e) {
  var raw = (e && typeof e.stack === "string" && e.stack) ||
            (e && typeof e.message === "string" && e.message) ||
            String(e);
  var out = "";
  for (var i = 0; i < raw.length; i += 1) {
    var c = raw.charCodeAt(i);
    if (c === 9 || c === 10 || c === 13) { out += " "; }       // tab/LF/CR → space
    else if (c < 0x20 || c === 0x7f) { continue; }             // drop other C0 + DEL
    else { out += raw[i]; }
  }
  out = out.replace(/ {2,}/g, " ");
  if (out.length > 2000) out = out.slice(0, 2000) + "...";
  return out;
}

module.exports = {
  check:              check,
  getChecks:          getChecks,
  resetChecksForTest: resetChecksForTest,
  addExternalChecks:  addExternalChecks,
  formatErr:          formatErr,
};
