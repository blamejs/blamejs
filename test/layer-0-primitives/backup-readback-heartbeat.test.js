// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The read-back directory is held by a heartbeat while it is in use, so a
 * concurrent backup's stale sweep cannot delete it mid-verification.
 *
 * `run()` sweeps stale working directories under the temp directory at the
 * start of every backup, by both the staging and the read-back prefix. Only
 * `stagingDir` held a heartbeat. A backend whose read-back outlasts the
 * staleness window, which is what a remote backend retrying looks like, left
 * the read-back directory unprotected, and a concurrent run could delete it
 * while `readBundle` was still filling it.
 *
 * The damaging part is what follows: the interrupted comparison reports a
 * mismatch, and a mismatch makes `run()` delete the bundle it just stored. A
 * backup written correctly is removed on the strength of a difference the
 * sweep caused.
 *
 * Reproducing the deletion end to end would need a bundle id whose embedded
 * timestamp is already a day old, because the sweep judges staleness by the
 * timestamp in the directory NAME and not by its mtime. So this covers the
 * two halves separately: that the engine holds a beat on the read-back
 * directory for the whole of `readBundle`, and that a held beat is what stops
 * the sweep removing an otherwise-stale directory.
 */

var fs      = require("fs");
var os      = require("os");
var path    = require("path");
var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

var READBACK_PREFIX = "blamejs-backup-readback-";
var HEARTBEAT_SUFFIX = ".active";
var STALE_MS = 24 * 60 * 60 * 1000;

async function testTheEngineHoldsABeatForTheWholeReadBack() {
  var root = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-readback-beat-"));
  try {
    var dataDir = path.join(root, "data");
    fs.mkdirSync(dataDir, { recursive: true });
    fs.writeFileSync(path.join(dataDir, "db.enc"), "DB-BYTES");

    var disk = b.backup.diskStorage({ root: path.join(root, "store") });
    var slow = Object.create(null);
    Object.keys(disk).forEach(function (k) { slow[k] = disk[k]; });

    var beatHeldDuringReadBack = null;
    var readBackDirSeen = null;
    slow.readBundle = async function (bundleId, targetDir) {
      readBackDirSeen = targetDir;
      beatHeldDuringReadBack = fs.existsSync(targetDir + HEARTBEAT_SUFFIX);
      return disk.readBundle(bundleId, targetDir);
    };

    var result = await b.backup.create({
      dataDir:      dataDir,
      storage:      slow,
      passphrase:   "readback-heartbeat-passphrase-123456",
      files:        [{ relativePath: "db.enc", kind: "raw", required: true }],
      vaultKeyJson: '{"vault":"x"}',
      audit:        false,
    }).run();

    check("a heartbeat is held on the read-back directory while it is read",
          beatHeldDuringReadBack === true, String(beatHeldDuringReadBack));
    check("the backup verifies by read-back", result.verifiedBy === "readback",
          String(result.verifiedBy));
    check("the bundle it wrote is still stored",
          (await disk.hasBundle(result.bundleId)) === true);
    check("the beat's marker is cleaned up afterwards",
          readBackDirSeen !== null && !fs.existsSync(readBackDirSeen + HEARTBEAT_SUFFIX),
          String(readBackDirSeen));
    check("and the marker never sat among the bytes that were compared",
          readBackDirSeen !== null && !fs.existsSync(readBackDirSeen),
          String(readBackDirSeen));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

function testAHeldBeatIsWhatStopsTheSweep() {
  // The mechanism the fix leans on, with the sweep's own criteria met: the
  // name carries a timestamp older than the window, nothing has touched the
  // contents, and the only difference between the two runs is the beat.
  var oldStamp = new Date(Date.now() - STALE_MS * 2).toISOString()
    .replace(/[:.]/g, "-").slice(0, 24);
  var name = READBACK_PREFIX + oldStamp + "-deadbeef";
  var dir = path.join(os.tmpdir(), name);
  fs.rmSync(dir, { recursive: true, force: true });
  fs.rmSync(dir + HEARTBEAT_SUFFIX, { force: true });
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "payload.bin"), "BYTES");
  var past = new Date(Date.now() - STALE_MS * 2);
  fs.utimesSync(path.join(dir, "payload.bin"), past, past);
  fs.utimesSync(dir, past, past);

  var beat = b.atomicFile.heartbeat(dir);
  try {
    b.atomicFile.removeStaleDirs(os.tmpdir(), {
      prefix: READBACK_PREFIX, olderThanMs: STALE_MS, keep: [],
    });
    check("a stale-named directory with a live beat survives the sweep",
          fs.existsSync(dir), name);
  } finally { beat.stop(); }

  // The control: the same directory, same age, no beat. If this also survived
  // the row above would prove nothing about the heartbeat.
  fs.rmSync(dir + HEARTBEAT_SUFFIX, { force: true });
  fs.utimesSync(path.join(dir, "payload.bin"), past, past);
  fs.utimesSync(dir, past, past);
  b.atomicFile.removeStaleDirs(os.tmpdir(), {
    prefix: READBACK_PREFIX, olderThanMs: STALE_MS, keep: [],
  });
  check("the same directory without one is removed, so the beat is what saved it",
        !fs.existsSync(dir), name);
  fs.rmSync(dir, { recursive: true, force: true });
}

async function run() {
  await testTheEngineHoldsABeatForTheWholeReadBack();
  testAHeldBeatIsWhatStopsTheSweep();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[backup-readback-heartbeat] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
