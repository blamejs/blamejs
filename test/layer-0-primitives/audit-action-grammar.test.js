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

  await _testRefusedActionsAreReported();
}

// The scan above can only judge an action it can read. Most of the framework
// emits through a per-file helper, and audit().namespaced(prefix) composes the
// action from a prefix the scan would have to resolve, so twenty-six more
// dropped rows sat outside its reach. Rather than widen the scan further,
// safeEmit reports a refused action instead of absorbing it, which covers every
// call shape and anything an application adds.
async function _testRefusedActionsAreReported() {
  var before = b.audit.refusedActions();
  check("the framework's own emits leave nothing refused",
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
