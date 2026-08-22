// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * audit FRAMEWORK_NAMESPACES — coverage check across lib/.
 *
 * Every framework primitive that emits an audit event MUST emit on a
 * namespace listed in audit.FRAMEWORK_NAMESPACES. This test walks the
 * lib/ source tree, extracts every action-name string literal passed
 * to safeEmit / _emit / _emitAudit / emitAudit, and asserts that the
 * leading namespace is pre-registered.
 *
 * Without this check a primitive can ship emitting on an unregistered
 * namespace; runtime drops the event with "audit namespace 'X' is not
 * registered" and the operator never knows their telemetry is empty.
 *
 * Run standalone: `node test/layer-0-primitives/audit-framework-namespaces.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var fs = require("node:fs");
var path = require("node:path");
var helpers = require("../helpers");
var b      = helpers.b;
var check  = helpers.check;

var LIB_ROOT = path.resolve(__dirname, "..", "..", "lib");

// Match the action-name string literal in any of these emission shapes:
//   _emit("ns.verb", ...)
//   _emitAudit("ns.verb", ...)
//   emitAudit("ns.verb", ...)
//   audit.safeEmit({ action: "ns.verb", ... })
//   audit().safeEmit({ action: "ns.verb", ... })
//   safeEmit({ action: "ns.verb", ... })
// Single-quoted variants too. Action shape:
// `[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+`.
var EMIT_PATTERNS = [
  /(?:_emit|_emitAudit|_auditEmit|emitAudit)\(\s*["']([a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+)["']/g,
  // audit().namespaced("ns.scope"[, auditFlag]) — the audit namespace lives in
  // the factory call now, not in each safeEmit/_emitAudit invocation. Scoped to
  // `audit().namespaced` so `observability().namespaced` metric prefixes (a
  // separate vocabulary, not FRAMEWORK_NAMESPACES) are NOT pulled in.
  /audit\(\)\.namespaced\(\s*["']([a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+)["']/g,
  /action\s*:\s*["']([a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+)["']/g,
];

function _allJsFiles(root) {
  var out = [];
  function walk(dir) {
    var entries = fs.readdirSync(dir, { withFileTypes: true });
    for (var i = 0; i < entries.length; i++) {
      var e = entries[i];
      if (e.name === "vendor" || e.name === "node_modules") continue;
      var full = path.join(dir, e.name);
      if (e.isDirectory()) walk(full);
      else if (e.isFile() && /\.js$/.test(e.name)) out.push(full);
    }
  }
  walk(root);
  return out;
}

// Strip block comments (covers JSDoc) and line comments from JS source so
// action-name extraction doesn't pick up tokens from operator-facing @example
// blocks (e.g. `orders.shipped`).
//
// Shared with the codebase-patterns gate rather than re-derived here. Two
// blind replaces cannot tell a comment from the same characters inside a
// string or a regex, and this is a COMPLETENESS check, so whatever they
// delete is a namespace that goes unregistered with nothing reporting it: an
// `Accept: */*` header contains `/*`, which opened a block comment running to
// the next `*/` and deleted the emission at lib/auth/fido-mds3.js:508 from
// this scan.
var _stripComments = require("../helpers/_shape-match").stripComments;

function _extractEmittedActions(filePath) {
  var src = _stripComments(fs.readFileSync(filePath, "utf8"));
  var found = [];
  for (var p = 0; p < EMIT_PATTERNS.length; p++) {
    var matches = src.matchAll(EMIT_PATTERNS[p]);
    for (var m of matches) {
      found.push({ action: m[1], file: filePath });
    }
  }
  return found;
}

function testEveryEmittedNamespaceIsRegistered() {
  var files = _allJsFiles(LIB_ROOT);
  check("walked at least one lib file",                files.length > 50);

  var allEmitted = [];
  for (var i = 0; i < files.length; i++) {
    var emissions = _extractEmittedActions(files[i]);
    for (var j = 0; j < emissions.length; j++) allEmitted.push(emissions[j]);
  }
  check("scan found at least 30 audit emission sites", allEmitted.length >= 30);

  var registered = new Set(b.audit.FRAMEWORK_NAMESPACES);
  var unregistered = [];
  for (var k = 0; k < allEmitted.length; k++) {
    var ns = allEmitted[k].action.split(".")[0];
    if (!registered.has(ns)) {
      unregistered.push({
        ns:     ns,
        action: allEmitted[k].action,
        file:   path.relative(LIB_ROOT, allEmitted[k].file),
      });
    }
  }

  if (unregistered.length > 0) {
    var summary = unregistered.map(function (u) {
      return u.file + " emits '" + u.action + "' (namespace: '" + u.ns + "')";
    }).join("\n  ");
    console.error("Unregistered audit namespaces emitted by framework primitives:\n  " + summary);
  }
  check("every framework-emitted namespace is in FRAMEWORK_NAMESPACES",
        unregistered.length === 0);
}

function testFrameworkNamespacesShape() {
  var ns = b.audit.FRAMEWORK_NAMESPACES;
  check("FRAMEWORK_NAMESPACES is an array",            Array.isArray(ns));
  check("FRAMEWORK_NAMESPACES has the expected core",  ns.indexOf("auth") !== -1 && ns.indexOf("system") !== -1);
  // Lowercase, underscore-friendly, dot-free per registerNamespace's regex.
  for (var i = 0; i < ns.length; i++) {
    check("FRAMEWORK_NAMESPACES[" + i + "] = " + JSON.stringify(ns[i]) + " matches namespace shape",
          /^[a-z][a-z0-9_]*$/.test(ns[i]));
  }
  // No duplicates.
  var seen = Object.create(null);
  for (var j = 0; j < ns.length; j++) {
    check("FRAMEWORK_NAMESPACES has no duplicate '" + ns[j] + "'", !seen[ns[j]]);
    seen[ns[j]] = true;
  }
}

// auditEmit.gatedReasonEmitter — the gated, reason-hoisting emitter shared by
// backup / restore / scheduler / config-drift / legal-hold.
function testGatedReasonEmitter() {
  var auditEmit = require("../../lib/audit-emit");
  var audit = require("../../lib/audit");
  var captured = [];
  var realSafe = audit.safeEmit;
  audit.safeEmit = function (e) { captured.push(e); };   // late-bound default sink
  try {
    var emit = auditEmit.gatedReasonEmitter({ audit: true });
    emit("backup.started", { jobId: 7 }, "success");
    emit("backup.failed", { jobId: 7, reason: "disk-full" }, "failure");
    check("gatedReasonEmitter: reason null when info.reason absent",
      captured[0] && captured[0].action === "backup.started" && captured[0].reason === null);
    check("gatedReasonEmitter: reason hoisted from info.reason",
      captured[1] && captured[1].reason === "disk-full" && captured[1].outcome === "failure");
    check("gatedReasonEmitter: metadata is the info object",
      captured[1] && captured[1].metadata && captured[1].metadata.jobId === 7);

    // gate OFF — drop-silent, no emit
    var n = captured.length;
    auditEmit.gatedReasonEmitter({ audit: false })("x", { reason: "y" }, "success");
    check("gatedReasonEmitter: gate off suppresses emit", captured.length === n);

    // extra(info) adds top-level fields (legal-hold's resource)
    auditEmit.gatedReasonEmitter({
      audit: true,
      extra: function (info) { return { resource: { kind: "legal-hold", id: info && info.subjectId } }; },
    })("legalhold.placed", { subjectId: "abc", reason: "litigation" }, "success");
    var last = captured[captured.length - 1];
    check("gatedReasonEmitter: extra() merges top-level fields",
      last && last.resource && last.resource.id === "abc" && last.reason === "litigation");

    // operator sink routing — goes to the supplied sink, not the framework default
    var sinkEvents = [];
    var m = captured.length;
    auditEmit.gatedReasonEmitter({ audit: true, sink: { safeEmit: function (e) { sinkEvents.push(e); } } })
      ("ns.act", { reason: "r" }, "success");
    check("gatedReasonEmitter: routes to the operator sink",
      sinkEvents.length === 1 && sinkEvents[0].reason === "r" && captured.length === m);
  } finally {
    audit.safeEmit = realSafe;
  }
}

// The scan can only report on what it can SEE, and comment stripping decides
// that. This is a completeness check, so anything the stripper deletes is a
// namespace that goes unregistered with no gate noticing — the silent
// direction, and the reason the stripper is worth a test of its own.
//
// The cases below are drawn from lib/, not invented: an `Accept` header of
// `*/*` contains the two characters `/*`, which opens a block comment that
// runs to the next `*/` anywhere in the file. That deleted the emission at
// lib/auth/fido-mds3.js:508 from this gate's view.
function testCommentStrippingKeepsEmissionsVisible() {
  var cases = [
    ["a */* media type does not open a block comment",
     'var h = { "Accept": "application/jwt, */*" };\n' +
     'audit().safeEmit({ action: "auth.fido_mds3.fetch.network" });',
     "auth.fido_mds3.fetch.network"],
    ["a // inside a string does not comment out the rest of the line",
     'var u = "https://example.test/x"; audit().safeEmit({ action: "system.probe.done" });',
     "system.probe.done"],
    ["a regex holding an escaped slash does not eat the line",
     'var re = /a\\/\\/b/; audit().safeEmit({ action: "system.probe.done" });',
     "system.probe.done"],
    ["a real comment is still removed",
     '// audit().safeEmit({ action: "system.ghost.event" });\n' +
     'audit().safeEmit({ action: "system.probe.done" });',
     "system.probe.done", "system.ghost.event"],
  ];

  cases.forEach(function (c) {
    var stripped = _stripComments(c[1]);
    var found = [];
    for (var p = 0; p < EMIT_PATTERNS.length; p++) {
      EMIT_PATTERNS[p].lastIndex = 0;
      var matches = stripped.matchAll(EMIT_PATTERNS[p]);
      for (var m of matches) found.push(m[1]);
    }
    check("comment strip keeps the emission visible: " + c[0],
      found.indexOf(c[2]) !== -1);
    if (c[3] !== undefined) {
      check("comment strip drops the commented-out emission: " + c[0],
        found.indexOf(c[3]) === -1);
    }
  });
}

async function run() {
  testFrameworkNamespacesShape();
  testEveryEmittedNamespaceIsRegistered();
  testCommentStrippingKeepsEmissionsVisible();
  testGatedReasonEmitter();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.message); process.exit(1); }
  );
}
