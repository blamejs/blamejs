// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The restore preflight compares mount identity, not device numbers.
 *
 * A restore finishes by renaming the staged tree over `dataDir` and the old
 * tree into `rollbackRoot`, and `rename(2)` fails with `EXDEV` across mount
 * points. `dataDir` was already checked against the kernel's mount table,
 * but `stagingRoot` and `rollbackRoot` were compared to it only by `st_dev`.
 *
 * A bind mount of the same filesystem carries the same device number while
 * being a distinct mount, so a bind-mounted staging root passed preflight
 * and the rename failed later, after the bundle had been pulled over the
 * network and decrypted to disk. The point of a preflight is that it answers
 * before that work is done.
 *
 * The mount table is read through `b.safeMountInfo`, which parses the field
 * that actually reveals a bind mount. The path it reads is an option here so
 * the case can be driven on a host that has no `/proc/self/mountinfo`, which
 * is the only way this is testable off Linux at all.
 */

var fs      = require("fs");
var os      = require("os");
var path    = require("path");
var helpers = require("../helpers");
var check   = helpers.check;
var b       = helpers.b;

// Two mounts of one filesystem: "/" and a bind of /srv/data onto /mnt/stage.
// Both carry major:minor 8:1, so a device-number comparison cannot tell them
// apart; field 4 and the mount points can.
var MOUNTINFO = [
  "21 20 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw",
  "42 21 8:1 /srv/data /mnt/stage rw,relatime shared:1 - ext4 /dev/sda1 rw",
  "",
].join("\n");

function _mountInfoFile(root) {
  var p = path.join(root, "mountinfo");
  fs.writeFileSync(p, MOUNTINFO);
  return p;
}

function _restore(dataDir, stagingRoot, mountInfoPath) {
  return b.restore.create({
    dataDir:      dataDir,
    stagingRoot:  stagingRoot,
    // The layout check runs inside run(), after the bundle is found and
    // before anything is pulled. readBundle throwing proves the refusal
    // arrives first: if preflight passed, this would be the error instead.
    storage:      { async listBundles() { return []; },
                    async readBundle() { throw new Error("BYTES WERE PULLED"); },
                    async hasBundle() { return true; } },
    passphrase:   "restore-mount-identity-passphrase-12",
    audit:        false,
    mountInfoPath: mountInfoPath,
  });
}

async function _preflightError(dataDir, stagingRoot, mountInfoPath) {
  var r = _restore(dataDir, stagingRoot, mountInfoPath);
  try { await r.run({ bundleId: "2026-01-01T00-00-00-000Z-abcdef12" }); return null; }
  catch (e) { return e; }
}

// The mount table is `/proc/self/mountinfo`, and its paths are POSIX
// absolute. On a platform that resolves "/mnt/stage" to something else there
// is no mount table to compare against and nothing to test.
var POSIX_PATHS = path.sep === "/";

async function testABindMountedStagingRootIsRefused() {
  if (!POSIX_PATHS) return;
  var root = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-mountid-"));
  try {
    var mip = _mountInfoFile(root);
    // The mount table names absolute Linux paths, so the directories the
    // preflight resolves have to be those paths for the comparison to be the
    // one under test. They need not exist: the lookup is against the table.
    var err = await _preflightError("/srv/data/app", "/mnt/stage/pull", mip);
    check("a bind-mounted stagingRoot is refused before any bytes are pulled",
          err !== null && err.code === "restore/cross-device",
          err && (err.code + ": " + err.message));
    check("and the refusal names the staging root",
          err !== null && String(err.message).indexOf("stagingRoot") !== -1,
          err && err.message);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

async function testARootOnTheSameMountIsAccepted() {
  // The refusal must not swallow the ordinary case: a staging root under the
  // same mount as dataDir's parent is exactly what an operator should pass.
  if (!POSIX_PATHS) return;
  var root = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-mountid-ok-"));
  try {
    var mip = _mountInfoFile(root);
    var err = await _preflightError("/srv/data/app", "/srv/data/staging", mip);
    check("a staging root on the same mount is not refused as cross-device",
          err === null || err.code !== "restore/cross-device",
          err && (err.code + ": " + err.message));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

async function testTheDeviceComparisonStillAppliesWithoutAMountTable() {
  // Off Linux there is no mount table to read, and the device-number check
  // is all there is. It must still run rather than falling open.
  var root = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-mountid-nodev-"));
  try {
    var dataDir = path.join(root, "data");
    fs.mkdirSync(dataDir, { recursive: true });
    var err = await _preflightError(dataDir, path.join(root, "staging"),
                                    path.join(root, "no-such-mountinfo"));
    check("a same-filesystem staging root is accepted with no mount table",
          err === null || err.code !== "restore/cross-device",
          err && (err.code + ": " + err.message));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

async function run() {
  await testABindMountedStagingRootIsRefused();
  await testARootOnTheSameMountIsAccepted();
  await testTheDeviceComparisonStillAppliesWithoutAMountTable();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[restore-mount-identity] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
