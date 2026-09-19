// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The pull directory keeps its heartbeat for as long as anything reads it.
 *
 * A restore pulls the bundle into a directory under `stagingRoot`, then
 * extracts out of that directory. Concurrent restores find each other's
 * leftovers by age and delete the stale ones, and a live directory says it is
 * live by holding a heartbeat marker beside it.
 *
 * The marker was released the moment `storage.readBundle` returned, while
 * extraction, which reads every byte of that same directory and is the slow
 * half for a large bundle, ran with nothing marking it. A second restore
 * starting during a long extraction could classify the directory as
 * abandoned and delete it out from under the process reading it.
 *
 * The marker is now held until the directory is finished with, which is when
 * it is removed.
 */

var fs      = require("fs");
var os      = require("os");
var path    = require("path");
var helpers = require("../helpers");
var check   = helpers.check;
var b       = helpers.b;

var HEARTBEAT_SUFFIX = ".active";
var PASSPHRASE = "restore-pull-heartbeat-passphrase-123";

function _markersUnder(root) {
  var out = [];
  var names;
  try { names = fs.readdirSync(root); } catch (_e) { return out; }
  for (var i = 0; i < names.length; i += 1) {
    if (names[i].length > HEARTBEAT_SUFFIX.length &&
        names[i].slice(-HEARTBEAT_SUFFIX.length) === HEARTBEAT_SUFFIX) {
      out.push(names[i]);
    }
  }
  return out;
}

async function testTheMarkerIsHeldWhileExtractionReadsThePullDirectory() {
  var root = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-pullbeat-"));
  try {
    var dataDir = path.join(root, "data");
    fs.mkdirSync(dataDir, { recursive: true });
    fs.writeFileSync(path.join(dataDir, "one.txt"), "ONE");
    fs.writeFileSync(path.join(dataDir, "two.txt"), "TWO");

    var storeRoot = path.join(root, "store");
    var disk = b.backup.diskStorage({ root: storeRoot });
    var made = await b.backup.create({
      dataDir:      dataDir,
      storage:      disk,
      passphrase:   PASSPHRASE,
      files: [{ relativePath: "one.txt", kind: "raw", required: true },
              { relativePath: "two.txt", kind: "raw", required: true }],
      vaultKeyJson: '{"vault":"x"}',
      audit:        false,
    }).run();

    var stagingRoot = path.join(root, "staging");
    fs.mkdirSync(stagingRoot, { recursive: true });
    var restore = b.restore.create({
      dataDir:      dataDir,
      storage:      disk,
      passphrase:   PASSPHRASE,
      stagingRoot:  stagingRoot,
      rollbackRoot: path.join(root, "rollbacks"),
      audit:        false,
    });

    // progressCallback runs inside extraction, which is exactly the window
    // the marker used to be missing from.
    var markersDuringExtract = [];
    await restore.run({
      bundleId:         made.bundleId,
      progressCallback: function () {
        markersDuringExtract.push(_markersUnder(stagingRoot).length);
      },
    });

    check("extraction reported progress, so the window was observed",
          markersDuringExtract.length > 0, String(markersDuringExtract.length));
    var everyTickHeldOne = markersDuringExtract.every(function (n) { return n >= 1; });
    check("a heartbeat marker is held at every point during extraction",
          everyTickHeldOne, JSON.stringify(markersDuringExtract));
    check("and no marker is left behind once the restore finishes",
          _markersUnder(stagingRoot).length === 0,
          JSON.stringify(_markersUnder(stagingRoot)));
    check("the restore itself succeeded",
          fs.readFileSync(path.join(dataDir, "one.txt"), "utf8") === "ONE");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

async function testTheMarkerIsReleasedWhenExtractionFails() {
  // A failed restore must not leave a marker claiming the directory is live,
  // or the leftovers it made can never be swept.
  var root = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-pullbeat-fail-"));
  try {
    var dataDir = path.join(root, "data");
    fs.mkdirSync(dataDir, { recursive: true });
    fs.writeFileSync(path.join(dataDir, "one.txt"), "ONE");

    var storeRoot = path.join(root, "store");
    var disk = b.backup.diskStorage({ root: storeRoot });
    var made = await b.backup.create({
      dataDir:      dataDir,
      storage:      disk,
      passphrase:   PASSPHRASE,
      files:        [{ relativePath: "one.txt", kind: "raw", required: true }],
      vaultKeyJson: '{"vault":"x"}',
      audit:        false,
    }).run();

    var stagingRoot = path.join(root, "staging");
    fs.mkdirSync(stagingRoot, { recursive: true });
    var restore = b.restore.create({
      dataDir:      dataDir,
      storage:      disk,
      passphrase:   "the-wrong-passphrase-entirely-000000",
      stagingRoot:  stagingRoot,
      rollbackRoot: path.join(root, "rollbacks"),
      audit:        false,
    });

    var threw = null;
    try { await restore.run({ bundleId: made.bundleId }); }
    catch (e) { threw = e; }
    check("a restore under the wrong passphrase fails", threw !== null,
          threw && threw.code);
    check("and leaves no heartbeat marker behind",
          _markersUnder(stagingRoot).length === 0,
          JSON.stringify(_markersUnder(stagingRoot)));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

async function run() {
  await testTheMarkerIsHeldWhileExtractionReadsThePullDirectory();
  await testTheMarkerIsReleasedWhenExtractionFails();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[restore-pull-heartbeat] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
