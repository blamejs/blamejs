// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A bundle written by the previous release restores under this one.
 *
 * The fixture under test/fixtures/backup-bundle-0.20.30 was written by
 * v0.20.30 with the passphrase below, and its manifest carries no
 * `keyScheme`: that release derived one Argon2id key per file from the
 * file's own salt. This release derives one Argon2id key per bundle and an
 * HKDF subkey per file, records `keyScheme` when it does, and reads a
 * manifest without that field the old way. Changing either derivation
 * without keeping that branch makes every backup an operator already holds
 * unrestorable, which this test refuses to let happen silently.
 */

var fs      = require("fs");
var os      = require("os");
var path    = require("path");
var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

var FIXTURE_DIR  = path.resolve(__dirname, "..", "fixtures", "backup-bundle-0.20.30");
var FIXTURE_PASS = "legacy-bundle-passphrase-123456";

async function testAPreviousReleaseBundleRestores() {
  var ids = fs.readdirSync(FIXTURE_DIR).filter(function (name) {
    return fs.statSync(path.join(FIXTURE_DIR, name)).isDirectory();
  });
  check("the fixture holds one bundle", ids.length === 1, ids.join(","));

  var manifest = JSON.parse(
    fs.readFileSync(path.join(FIXTURE_DIR, ids[0], "manifest.json"), "utf8"));
  check("the fixture manifest records no keyScheme, as the previous release wrote it",
        manifest.keyScheme === undefined, String(manifest.keyScheme));

  var root = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-legacy-restore-"));
  try {
    // The storage root is a copy, so the test never writes into the fixture.
    var storageRoot = path.join(root, "store");
    b.atomicFile.copyDirRecursive(FIXTURE_DIR, storageRoot);
    var dataDir = path.join(root, "data");
    fs.mkdirSync(dataDir, { recursive: true });

    var result = await b.restore.create({
      dataDir:      dataDir,
      storage:      b.backup.diskStorage({ root: storageRoot }),
      passphrase:   FIXTURE_PASS,
      rollbackRoot: path.join(root, "rollbacks"),
      audit:        false,
    }).run({ bundleId: ids[0] });

    check("both files restore", result.fileCount === 2, String(result.fileCount));
    check("db.enc restores to the bytes the previous release backed up",
          fs.readFileSync(path.join(dataDir, "db.enc")).toString() === "ORIGINAL-DB-BYTES",
          fs.readFileSync(path.join(dataDir, "db.enc")).toString());
    check("audit.log restores to the bytes the previous release backed up",
          fs.readFileSync(path.join(dataDir, "audit.log")).toString() === "ORIGINAL-AUDIT",
          fs.readFileSync(path.join(dataDir, "audit.log")).toString());
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

async function testTheWrongPassphraseIsStillRefused() {
  var ids = fs.readdirSync(FIXTURE_DIR).filter(function (name) {
    return fs.statSync(path.join(FIXTURE_DIR, name)).isDirectory();
  });
  var root = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-legacy-refuse-"));
  try {
    var storageRoot = path.join(root, "store");
    b.atomicFile.copyDirRecursive(FIXTURE_DIR, storageRoot);
    var dataDir = path.join(root, "data");
    fs.mkdirSync(dataDir, { recursive: true });
    var threw = null;
    try {
      await b.restore.create({
        dataDir:      dataDir,
        storage:      b.backup.diskStorage({ root: storageRoot }),
        passphrase:   FIXTURE_PASS + "-wrong",
        rollbackRoot: path.join(root, "rollbacks"),
        audit:        false,
      }).run({ bundleId: ids[0] });
    } catch (e) { threw = e; }
    check("a wrong passphrase is refused rather than restoring something",
          threw !== null && /^restore\//.test(threw.code || ""),
          threw && (threw.code + " " + threw.message.slice(0, 60)));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

async function run() {
  await testAPreviousReleaseBundleRestores();
  await testTheWrongPassphraseIsStillRefused();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[restore-previous-release-bundle] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
