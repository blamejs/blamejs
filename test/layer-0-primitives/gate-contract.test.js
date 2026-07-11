// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — b.gateContract issue-severity vocabulary + audit projection.
 *
 *   - b.gateContract.ISSUE_SEVERITIES — the frozen severity ladder, and
 *     the advertised semantics that info/warn keep ok:true while high/
 *     critical flip ok:false (driven through aggregateIssues).
 *   - b.gateContract.summarizeIssues — projects a decision's issues down
 *     to the audit-safe { kind, severity, ruleId } shape, dropping the
 *     forensic snippet so offending bytes never reach the audit log.
 */

var helpers = require("../helpers");
var check   = helpers.check;
var b       = helpers.b;

function testIssueSeverities() {
  var sevs = b.gateContract.ISSUE_SEVERITIES;
  check("gateContract.ISSUE_SEVERITIES: exact ladder",
    JSON.stringify(sevs) === JSON.stringify(["info", "warn", "high", "critical"]));
  check("gateContract.ISSUE_SEVERITIES: frozen", Object.isFrozen(sevs) === true);
  check("gateContract.ISSUE_SEVERITIES: critical is highest (index 3)",
    b.gateContract.ISSUE_SEVERITIES.indexOf("critical") === 3);
  check("gateContract.ISSUE_SEVERITIES: info is lowest (index 0)",
    b.gateContract.ISSUE_SEVERITIES.indexOf("info") === 0);

  // Advertised semantics: info/warn are observability-only (ok stays true);
  // high/critical refuse (ok flips false). Driven through the real consumer
  // aggregateIssues so the ladder's meaning is asserted, not just its values.
  b.gateContract.ISSUE_SEVERITIES.forEach(function (sev) {
    var result = b.gateContract.aggregateIssues([{ kind: "k." + sev, severity: sev }]);
    var expectOk = (sev === "info" || sev === "warn");
    check("gateContract.ISSUE_SEVERITIES: aggregate(" + sev + ") ok=" + expectOk,
      result.ok === expectOk);
  });

  // A high severity anywhere in the list refuses even alongside info/warn.
  var mixed = b.gateContract.aggregateIssues([
    { kind: "a", severity: "info" },
    { kind: "b", severity: "high" },
    { kind: "c", severity: "warn" },
  ]);
  check("gateContract.ISSUE_SEVERITIES: mixed with high → ok false", mixed.ok === false);
  check("gateContract.ISSUE_SEVERITIES: mixed keeps all issues", mixed.issues.length === 3);
}

function testSummarizeIssues() {
  var summary = b.gateContract.summarizeIssues([
    { kind: "csv.bidi", severity: "high", ruleId: "BIDI-OVERRIDE",
      snippet: "U+202E raw bytes that must never reach the audit log" },
    { kind: "csv.trailing-whitespace", severity: "info", ruleId: "TRIM" },
  ]);
  check("gateContract.summarizeIssues: length preserved", summary.length === 2);
  check("gateContract.summarizeIssues: kind preserved", summary[0].kind === "csv.bidi");
  check("gateContract.summarizeIssues: severity preserved", summary[0].severity === "high");
  check("gateContract.summarizeIssues: ruleId preserved", summary[0].ruleId === "BIDI-OVERRIDE");
  check("gateContract.summarizeIssues: snippet stripped", summary[0].snippet === undefined);
  check("gateContract.summarizeIssues: projects to exactly 3 keys",
    Object.keys(summary[0]).sort().join(",") === "kind,ruleId,severity");
  check("gateContract.summarizeIssues: second issue snippet also absent",
    Object.prototype.hasOwnProperty.call(summary[1], "snippet") === false);

  // Missing ruleId surfaces as undefined (not thrown) — audit-friendly.
  var noRule = b.gateContract.summarizeIssues([{ kind: "x", severity: "warn" }]);
  check("gateContract.summarizeIssues: absent ruleId → undefined", noRule[0].ruleId === undefined);

  // Defensive: non-array input returns an empty array rather than throwing.
  check("gateContract.summarizeIssues: non-array → []",
    Array.isArray(b.gateContract.summarizeIssues("nope")) &&
    b.gateContract.summarizeIssues("nope").length === 0);
  check("gateContract.summarizeIssues: undefined → []",
    b.gateContract.summarizeIssues(undefined).length === 0);
}

function run() {
  testIssueSeverities();
  testSummarizeIssues();
}

module.exports = { run: run };

if (require.main === module) {
  run();
  console.log("OK — " + helpers.getChecks() + " checks passed");
}
