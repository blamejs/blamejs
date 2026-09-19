// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.drRunbook — disaster-recovery runbook generator.
 */

var fs = require("fs");
var os = require("os");
var path = require("path");
var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

async function run() {
  check("drRunbook.emit is fn",      typeof b.drRunbook.emit === "function");
  check("DrRunbookError is fn",      typeof b.drRunbook.DrRunbookError === "function");
  check("POSTURE_BLOCKS hipaa key",  !!b.drRunbook.POSTURE_BLOCKS.hipaa);
  check("POSTURE_BLOCKS dora key",   !!b.drRunbook.POSTURE_BLOCKS.dora);

  var outDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-dr-runbook-"));
  try {
    var result = await b.drRunbook.emit({
      outDir:  outDir,
      posture: "hipaa",
      rtoMs:   b.constants.TIME.hours(4),
      rpoMs:   b.constants.TIME.minutes(15),
      contacts: { incidentCommander: "alice@example.test" },
      services: [
        { name: "api-edge",  rtoMs: b.constants.TIME.minutes(15), rpoMs: b.constants.TIME.minutes(5) },
        { name: "billing",   rtoMs: b.constants.TIME.hours(1),    rpoMs: b.constants.TIME.minutes(15) },
      ],
      audit: false,
    });
    check("emit returns posture",     result.posture === "hipaa");
    check("emit returns paths array", Array.isArray(result.paths) && result.paths.length === 1);
    check("emit returns sectionCount", result.sectionCount > 0);

    var body = fs.readFileSync(result.paths[0], "utf8");
    check("runbook header includes posture",  body.indexOf("HIPAA") !== -1);
    check("runbook cites HIPAA Security Rule", body.indexOf("§164.308(a)(7)") !== -1);
    check("runbook lists Incident Commander", body.indexOf("incidentCommander") !== -1);
    check("runbook lists api-edge service",   body.indexOf("api-edge") !== -1);
    check("runbook references restore steps", body.indexOf("verifyManifestSignature") !== -1);

    // An operator follows the runbook literally, so every framework call it
    // prints has to exist. ENGINE_METHODS are the documented names of methods
    // on the object a create() returns, which do not resolve on `b` itself.
    var ENGINE_METHODS = ["b.backup.scheduleTest", "b.restore.rollback"];
    var referenced = {};
    var refPattern = /\bb\.([A-Za-z][A-Za-z0-9]*)\.([A-Za-z][A-Za-z0-9]*)/g;
    var found;
    while ((found = refPattern.exec(body)) !== null) referenced[found[0]] = true;
    var unresolved = Object.keys(referenced).filter(function (ref) {
      if (ENGINE_METHODS.indexOf(ref) !== -1) return false;
      return ref.split(".").slice(1).reduce(function (node, key) {
        return node === undefined || node === null ? undefined : node[key];
      }, b) === undefined;
    });
    check("every framework call the runbook prints resolves (" + Object.keys(referenced).length + " referenced)" +
          (unresolved.length ? ": " + unresolved.join(", ") : ""), unresolved.length === 0);

    // A name that resolves is not yet a call an operator can run: the
    // runbook printed `b.auditChain.verifyChain({ db: restoredDb })` while
    // the function takes (queryAllAsync, tableName, opts), so following the
    // runbook raised an argument error before any row was checked.
    var FIRST_ARGUMENT_IS_A_FUNCTION = ["b.auditChain.verifyChain"];
    var wrongShape = [];
    FIRST_ARGUMENT_IS_A_FUNCTION.forEach(function (ref) {
      var target = ref.split(".").slice(1).reduce(function (node, key) {
        return node === undefined || node === null ? undefined : node[key];
      }, b);
      if (typeof target !== "function") { wrongShape.push(ref + " does not resolve"); return; }
      var printed = new RegExp(ref.replace(/\./g, "\\.") + "\\(\\s*([^,)]*)");
      var call = printed.exec(body);
      if (call === null) return;
      if (!/^function\b|^\(|^async\b/.test(call[1].trim())) {
        wrongShape.push(ref + " is printed with " + JSON.stringify(call[1].trim()) +
          " as its first argument, but it takes a query callback");
      }
    });
    check("every printed call passes the arguments its function takes" +
          (wrongShape.length ? ": " + wrongShape.join("; ") : ""), wrongShape.length === 0);
  } finally {
    try { fs.rmSync(outDir, { recursive: true, force: true }); }
    catch (_e) { /* best-effort */ }
  }

  // Unknown posture refused
  var threwBadPosture = null;
  try {
    await b.drRunbook.emit({
      outDir: outDir, posture: "made-up-posture", audit: false,
    });
  } catch (e) { threwBadPosture = e; }
  check("emit refuses unknown posture",
    threwBadPosture && threwBadPosture.code === "dr-runbook/unknown-posture");
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[dr-runbook] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
