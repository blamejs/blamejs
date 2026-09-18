// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.restoreRollback.rollback — the rollback target is a rollback point.
 *
 * rollback() moves the live dataDir aside and moves the target into its place.
 * The target has to be a restore point that swap() wrote: a direct child
 * directory of the rollback root, named with the swap timestamp, and not a
 * `discarded-*` directory. Anything else is refused before the live dataDir
 * moves. When the second rename fails, the live dataDir is moved back, so a
 * later purge (which deletes every `discarded-*` directory) cannot delete it.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var fs      = helpers.fs;
var os      = helpers.os;
var path    = helpers.path;
var atomicFile = require("../../lib/atomic-file");

function _fixture() {
  var root = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-rbt-"));
  var dataDir = path.join(root, "data");
  var rollbackRoot = dataDir + ".rollbacks";
  fs.mkdirSync(path.join(dataDir, "keys"), { recursive: true });
  fs.writeFileSync(path.join(dataDir, "db.enc"), "LIVE-DB");
  fs.writeFileSync(path.join(dataDir, "keys", "dkim.sealed"), "LIVE-KEY");
  var staging = path.join(root, "staging");
  fs.mkdirSync(staging);
  fs.writeFileSync(path.join(staging, "db.enc"), "RESTORED-DB");
  var swapped = b.restoreRollback.swap({ stagingDir: staging, dataDir: dataDir, rollbackRoot: rollbackRoot });
  fs.writeFileSync(path.join(dataDir, "db.enc"), "CURRENT-DB");
  fs.mkdirSync(path.join(dataDir, "keys"));
  return {
    root: root, dataDir: dataDir, rollbackRoot: rollbackRoot, point: swapped.rollbackPath,
    cleanup: function () { try { fs.rmSync(root, { recursive: true, force: true }); } catch (_e) { /* best-effort */ } },
  };
}

function _liveIntact(fx) {
  try { return fs.readFileSync(path.join(fx.dataDir, "db.enc"), "utf8") === "CURRENT-DB"; }
  catch (_e) { return false; }
}

async function testRollbackRefusesATargetThatIsNotARollbackPoint() {
  var wrong = [];
  var CASES = [
    { label: "the dataDir itself", target: function (fx) { return fx.dataDir; } },
    { label: "a directory inside dataDir", target: function (fx) { return path.join(fx.dataDir, "keys"); } },
    { label: "an unrelated directory with a sibling marker", target: function (fx) {
      var dir = path.join(fx.root, "unrelated-project");
      fs.mkdirSync(dir);
      fs.writeFileSync(path.join(dir, "README.txt"), "unrelated");
      fs.writeFileSync(dir + ".marker.json", "{}");
      return dir;
    }, after: function (fx) {
      var dir = path.join(fx.root, "unrelated-project");
      return fs.existsSync(path.join(dir, "README.txt")) && fs.existsSync(dir + ".marker.json");
    } },
    { label: "a regular file", target: function (fx) {
      var file = path.join(fx.rollbackRoot, "2026-01-01T00-00-00-000Z");
      fs.writeFileSync(file, "not a directory");
      return file;
    } },
    { label: "the rollback root", target: function (fx) { return fx.rollbackRoot; } },
    { label: "a discarded-* directory", target: function (fx) {
      var dir = path.join(fx.rollbackRoot, "discarded-2026-01-01T00-00-00-000Z");
      fs.mkdirSync(dir);
      fs.writeFileSync(path.join(dir, "db.enc"), "DISCARDED");
      return dir;
    } },
    { label: "a child of the rollback root without the swap timestamp name", target: function (fx) {
      var dir = path.join(fx.rollbackRoot, "manual-copy");
      fs.mkdirSync(dir);
      return dir;
    } },
    { label: "a rollback point named through the parent directory", target: function (fx) {
      return path.join(fx.rollbackRoot, "..", path.basename(fx.dataDir));
    } },
  ];
  for (var i = 0; i < CASES.length; i += 1) {
    var fx = _fixture();
    try {
      var target = CASES[i].target(fx);
      var code = null;
      try {
        await b.restoreRollback.rollback({ dataDir: fx.dataDir, rollbackPath: target, rollbackRoot: fx.rollbackRoot });
      } catch (e) { code = e.code; }
      var discarded = !fs.existsSync(fx.rollbackRoot) ? ["(rollback root is gone)"] :
        fs.readdirSync(fx.rollbackRoot).filter(function (n) { return n.indexOf("discarded-") === 0 &&
          n !== "discarded-2026-01-01T00-00-00-000Z"; });
      var ok = code === "restore-rollback/bad-rollback-path" && _liveIntact(fx) && discarded.length === 0 &&
        (!CASES[i].after || CASES[i].after(fx));
      if (!ok) {
        wrong.push(CASES[i].label + " -> code " + code + ", live intact " + _liveIntact(fx) +
          ", discarded dirs " + discarded.length);
      }
    } finally { fx.cleanup(); }
  }

  var good = _fixture();
  try {
    var rv = await b.restoreRollback.rollback({ dataDir: good.dataDir, rollbackPath: good.point, rollbackRoot: good.rollbackRoot });
    var restored = fs.readFileSync(path.join(good.dataDir, "db.enc"), "utf8");
    if (restored !== "LIVE-DB" || typeof rv.discardedAt !== "string") {
      wrong.push("a real rollback point -> db.enc " + JSON.stringify(restored));
    }
  } catch (e) {
    wrong.push("a real rollback point threw " + e.code);
  } finally { good.cleanup(); }

  check("restoreRollback.rollback refuses a target that is not a rollback point before moving dataDir" +
        (wrong.length ? " (" + wrong.join("; ") + ")" : ""), wrong.length === 0);
}

async function testRollbackPutsDataDirBackWhenTheSecondRenameFails() {
  var fx = _fixture();
  var realRename = atomicFile.renameWithRetry;
  var calls = 0;
  atomicFile.renameWithRetry = function (from, to) {
    calls += 1;
    if (calls === 2) {
      var e = new Error("EACCES: simulated failure moving the rollback point");
      e.code = "EACCES";
      throw e;
    }
    return realRename.apply(this, arguments);
  };
  var code = null;
  try {
    try {
      await b.restoreRollback.rollback({ dataDir: fx.dataDir, rollbackPath: fx.point, rollbackRoot: fx.rollbackRoot });
    } catch (e) { code = e.code; }
  } finally { atomicFile.renameWithRetry = realRename; }
  try {
    var discarded = !fs.existsSync(fx.rollbackRoot) ? ["(rollback root is gone)"] :
      fs.readdirSync(fx.rollbackRoot).filter(function (n) { return n.indexOf("discarded-") === 0; });
    var purge =b.restoreRollback.purge({ rollbackRoot: fx.rollbackRoot, keep: 10 });
    check("a rollback whose second rename fails leaves dataDir in place, so purge cannot delete it",
          code === "restore-rollback/rollback-rename-failed" && _liveIntact(fx) &&
          discarded.length === 0 && fs.existsSync(fx.point) && purge.deleted.length === 0,
          JSON.stringify({ code: code, live: _liveIntact(fx), discarded: discarded, point: fs.existsSync(fx.point) }));
  } finally { fx.cleanup(); }
}

async function run() {
  await testRollbackRefusesATargetThatIsNotARollbackPoint();
  await testRollbackPutsDataDirBackWhenTheSecondRenameFails();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
