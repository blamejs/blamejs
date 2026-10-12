// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Every audit action literal in lib/ must be one b.audit will accept.
 *
 * b.audit.record / emit refuse an action that is not
 * `namespace.verb[.qualifier...]` in lowercase, and refuse one whose namespace
 * was never registered. safeEmit catches that refusal and returns, which is the
 * documented drop-silent contract for a hot-path sink. The two combine badly: a
 * primitive emitting a misspelled action reports success, writes no row, and
 * raises nothing, so a documented audit trail is simply absent. Fourteen rows
 * across eleven files were being dropped this way, among them
 * `fileupload.content_safety.disabled` and `staticserve.content_safety.disabled`
 * — the rows that record an operator turning a scanner off.
 *
 * The probe is b.audit.record itself, called with no outcome: it validates the
 * action before it checks the outcome and before it writes anything, so a legal
 * action fails on the outcome and an illegal one fails on the action. Reading
 * the verdict from the shipped validator means this test tracks the grammar
 * rather than restating it.
 */

var fs      = require("node:fs");
var path    = require("node:path");
var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

var LIB_ROOT = path.resolve(__dirname, "..", "..", "lib");

// An `action:` string is only an audit action when it sits inside a call to an
// audit sink. The same key names a sanitize-action in the guard family and an
// obligation in the EU AI Act tables, and neither reaches b.audit.
var SINK_RE   = /(?:safeEmit|\.emit|\.record)\s*\(/;
var ACTION_RE = /action:\s*"([^"]+)"/;
var WINDOW    = 15;

function _libFiles(dir, out) {
  var entries = fs.readdirSync(dir, { withFileTypes: true });
  for (var i = 0; i < entries.length; i++) {
    var full = path.join(dir, entries[i].name);
    if (entries[i].isDirectory()) {
      if (entries[i].name !== "vendor") _libFiles(full, out);
    } else if (/\.js$/.test(entries[i].name)) {
      out.push(full);
    }
  }
  return out;
}

// Collect (file, line, action) for every action literal within WINDOW lines
// after an audit sink call. Comment lines are skipped: the doc blocks carry
// example actions and a `@signature` grammar placeholder.
function _emittedActions() {
  var found = [];
  var files = _libFiles(LIB_ROOT, []);
  for (var f = 0; f < files.length; f++) {
    var lines = fs.readFileSync(files[f], "utf8").split("\n");
    var openUntil = -1;
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      if (/^\s*(\*|\/\/)/.test(line)) continue;
      if (SINK_RE.test(line)) openUntil = i + WINDOW;
      if (i > openUntil) continue;
      var m = ACTION_RE.exec(line);
      if (m) {
        found.push({
          file:   path.relative(path.dirname(LIB_ROOT), files[f]).replace(/\\/g, "/"),
          line:   i + 1,
          action: m[1],
        });
      }
    }
  }
  return found;
}

// `audit().namespaced("<prefix>")` composes `prefix + "." + verb`, so the
// literal above carries the namespace and every segment before the verb. The
// verb is usually a conditional expression rather than a literal, so the scan
// above never sees the composed action; the prefix alone is enough to judge the
// namespace and the segment shape.
var AUDIT_NS_RE = /(?:audit\(\)|b\.audit)\.namespaced\(\s*"([^"]+)"/;

// A third shape neither scan above can see: the action is a POSITIONAL
// argument to a per-file helper, so there is no `action:` key and no
// `namespaced` prefix. The helpers are named `_emitAudit`, `emitAudit`,
// `_safeAudit`, `_safeAuditEmit`, `_auditEmit` and `safeAudit`, they take the
// action FIRST or SECOND, and keying a scan on one of those names is what let
// 73 refused sites across five namespaces survive: a name is not the shape.
// So match on the SHAPE instead, any callee whose name contains "audit" in
// either case, and take the first dotted string literal in its arguments.
// `observability` never matches, which is what keeps a metric name out: a
// metric has no namespace grammar and no registry.
var AUDIT_CALLEE_RE = /\b[A-Za-z_$][\w$]*[Aa]udit[\w$]*\s*\(/;
var DOTTED_LITERAL_RE = /"([A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+)"/g;

function _positionalActions() {
  var found = [];
  var files = _libFiles(LIB_ROOT, []);
  for (var f = 0; f < files.length; f++) {
    var lines = fs.readFileSync(files[f], "utf8").split("\n");
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      if (/^\s*(\*|\/\/)/.test(line)) continue;
      if (!AUDIT_CALLEE_RE.test(line)) continue;
      // An audit callee on this line: the action is the first dotted literal
      // in it. A permission scope reaching `permissions.check` is not one.
      if (/permissions\s*\.\s*check\s*\(/.test(line)) continue;
      // Every literal, not the first: guard-envelope picks its action with a
      // ternary, so one line carries two.
      var args = line.slice(line.search(AUDIT_CALLEE_RE));
      DOTTED_LITERAL_RE.lastIndex = 0;
      var m;
      while ((m = DOTTED_LITERAL_RE.exec(args)) !== null) {
        found.push({
          file:   path.relative(path.dirname(LIB_ROOT), files[f]).replace(/\\/g, "/"),
          line:   i + 1,
          action: m[1],
        });
      }
    }
  }
  return found;
}

function _namespacedPrefixes() {
  var found = [];
  var files = _libFiles(LIB_ROOT, []);
  for (var f = 0; f < files.length; f++) {
    var lines = fs.readFileSync(files[f], "utf8").split("\n");
    for (var i = 0; i < lines.length; i++) {
      if (/^\s*(\*|\/\/)/.test(lines[i])) continue;
      var m = AUDIT_NS_RE.exec(lines[i]);
      if (!m) continue;
      found.push({
        file:   path.relative(path.dirname(LIB_ROOT), files[f]).replace(/\\/g, "/"),
        line:   i + 1,
        prefix: m[1],
      });
    }
  }
  return found;
}

// Ask the shipped validator. Returns null when the action is acceptable.
// record is async, so the refusal arrives as a rejected promise rather than a
// synchronous throw: awaiting it is what makes this probe able to fail at all.
async function _refusalFor(action) {
  try {
    await b.audit.record({ action: action });
  } catch (e) {
    var msg = String((e && e.message) || e);
    if (/audit action must be/.test(msg))   return "bad-shape";
    if (/is not registered/.test(msg))      return "unregistered-namespace";
    return null;   // fell through to the outcome check — the action passed
  }
  return null;
}

async function run() {
  // The controls run first. A probe that cannot fail reports every action as
  // acceptable, and the sweep below would then read as a clean pass over a
  // broken instrument. record() is async, and an un-awaited rejection is
  // exactly how that happened while this test was being written.
  check("the probe refuses a camelCase action",
    (await _refusalFor("pqcagent.reloadCerts")) === "bad-shape");
  check("the probe refuses a digit-led segment",
    (await _refusalFor("tls.0rtt.accepted")) === "bad-shape");
  check("the probe refuses an unregistered namespace",
    (await _refusalFor("notanamespace.thing")) === "unregistered-namespace");
  check("the probe accepts a legal action",
    (await _refusalFor("pqcagent.reload_certs")) === null);

  var actions = _emittedActions();
  check("the scan found audit action literals to check", actions.length > 50,
    "found=" + actions.length);

  var bad = [];
  for (var i = 0; i < actions.length; i++) {
    var why = await _refusalFor(actions[i].action);
    if (why) bad.push(actions[i].file + ":" + actions[i].line + " " +
                      actions[i].action + " (" + why + ")");
  }
  check("every audit action lib/ emits is one b.audit accepts", bad.length === 0,
    bad.length + " refused:\n  " + bad.join("\n  "));

  // guard-sql composed its gate rows under `guardSql.gate`, so every served,
  // audited and refused decision a SQL gate produced was refused for the
  // segment casing and no row was written.
  var prefixes = _namespacedPrefixes();
  check("the scan found namespaced audit prefixes to check", prefixes.length > 5,
    "found=" + prefixes.length);
  var badPrefix = [];
  for (var p = 0; p < prefixes.length; p++) {
    var pWhy = await _refusalFor(prefixes[p].prefix + ".probe");
    if (pWhy) badPrefix.push(prefixes[p].file + ":" + prefixes[p].line + " " +
                             prefixes[p].prefix + " (" + pWhy + ")");
  }
  check("every namespaced prefix composes an action b.audit accepts",
    badPrefix.length === 0,
    badPrefix.length + " refused:\n  " + badPrefix.join("\n  "));

  // The shape scan: an action passed positionally to any audit-named callee.
  // This is the one that covers `_emitAudit("fileupload.init", …)`,
  // `_safeAuditEmit("daemon.started", …)` and `agentAudit.safeAudit(impl,
  // "agent.saga.started", …)` alike.
  var positional = _positionalActions();
  check("the shape scan found positional audit actions to check",
    positional.length > 100, "found=" + positional.length);
  var badPositional = [];
  for (var q = 0; q < positional.length; q++) {
    var qWhy = await _refusalFor(positional[q].action);
    if (qWhy) badPositional.push(positional[q].file + ":" + positional[q].line + " " +
                                 positional[q].action + " (" + qWhy + ")");
  }
  check("every action passed to an audit callee is one b.audit accepts",
    badPositional.length === 0,
    badPositional.length + " refused:\n  " + badPositional.join("\n  "));

  await _testRefusedActionsAreReported();
}

// The scan above can only judge an action it can read, and safeEmit reports a
// refused action instead of absorbing it, which covers every call shape and
// anything an application adds.
//
// What this check is NOT: evidence that the framework drops nothing. The
// register is module-global and nothing clears it, so under the release gate
// (SMOKE_PARALLEL > 1 forks a process per test file) this file is the only
// code that has run, and the list is empty however many rows the framework
// drops elsewhere. Seventy-three refused sites across five namespaces survived
// this assertion for exactly that reason. The scans above are what judge the
// framework; this judges the REGISTER, so it asserts the mechanism counts and
// reports rather than asserting a population it cannot see.
async function _testRefusedActionsAreReported() {
  var before = b.audit.refusedActions();
  check("nothing this file has run so far was refused",
    before.length === 0, JSON.stringify(before));

  // The control: the report is reachable and counts attempts, so an empty list
  // above means nothing was refused rather than nothing being recorded.
  // Registering the namespace is the documented remedy, so the legal case at
  // the end exercises it: without it `orders.shipped` is refused as well, for
  // the namespace rather than the shape.
  b.audit.registerNamespace("orders");
  b.audit.safeEmit({ action: "orders.Shipped", outcome: "success" });
  b.audit.safeEmit({ action: "orders.Shipped", outcome: "success" });
  b.audit.safeEmit({ action: "notaregisterednamespace.thing", outcome: "success" });
  var after = b.audit.refusedActions();
  var shipped = after.filter(function (r) { return r.action === "orders.Shipped"; })[0];
  check("a refused action is reported rather than dropped",
    shipped !== undefined, JSON.stringify(after));
  check("and repeat attempts are counted",
    shipped !== undefined && shipped.attempts === 2,
    JSON.stringify(shipped));
  check("an unregistered namespace is reported too",
    after.some(function (r) { return r.action === "notaregisterednamespace.thing"; }),
    JSON.stringify(after));

  // The register is a diagnostic sink, so a refused action goes through the
  // same redaction accepted metadata does. An application deriving an action
  // from request data, which is the case the cap below anticipates, would
  // otherwise copy a token out of a path-shaped action into the boot log, the
  // register and an observability label, none of which a reader expects to
  // carry a secret. This runs before the flood below, which fills the cap.
  b.audit.safeEmit({
    action:  "orders.reset?token=sk_live_51H8xQ2abcdefghijklmnop",
    outcome: "success",
  });
  var leaked = b.audit.refusedActions().filter(function (r) {
    return r.action.indexOf("orders.reset") === 0;
  })[0];
  check("a refused action is redacted before it reaches the register",
    leaked !== undefined && leaked.action.indexOf("sk_live_") === -1,
    leaked ? leaked.action : "not recorded");
  check("and what is left still identifies the action for an operator",
    leaked !== undefined && leaked.action.indexOf("orders.reset") === 0,
    leaked ? leaked.action : "not recorded");

  // The register is bounded. An application that derives an action name from
  // request data would otherwise let a client grow this map and the error log
  // without bound, one entry per distinct malformed value, on a path whose
  // whole contract is to be drop-silent.
  for (var f = 0; f < 500; f++) {
    b.audit.safeEmit({ action: "Flood.Action" + f, outcome: "success" });
  }
  var flooded = b.audit.refusedActions();
  var overflow = flooded.filter(function (r) { return r.action === "(overflow)"; })[0];
  check("the refusal register stops storing distinct actions at its cap",
    flooded.length - (overflow ? 1 : 0) <= 64 + 3,
    "stored=" + (flooded.length - (overflow ? 1 : 0)));
  check("and the ones past the cap are counted rather than dropped",
    overflow !== undefined && overflow.attempts > 0,
    JSON.stringify(overflow));
  var before0 = flooded.filter(function (r) { return r.action === "Flood.Action0"; })[0];
  b.audit.safeEmit({ action: "Flood.Action0", outcome: "success" });
  var after0 = b.audit.refusedActions().filter(function (r) { return r.action === "Flood.Action0"; })[0];
  check("a repeat of an action already in the register still counts",
    before0 !== undefined && after0 !== undefined && after0.attempts === before0.attempts + 1,
    JSON.stringify({ before: before0, after: after0 }));

  // A legal action does not land in the report.
  b.audit.safeEmit({ action: "orders.shipped", outcome: "success" });
  check("a legal action is not reported as refused",
    b.audit.refusedActions().every(function (r) { return r.action !== "orders.shipped"; }),
    JSON.stringify(b.audit.refusedActions()));
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK — audit action grammar"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
