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

module.exports = {
  check:              check,
  getChecks:          getChecks,
  resetChecksForTest: resetChecksForTest,
};
