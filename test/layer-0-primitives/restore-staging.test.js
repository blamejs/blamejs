// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.restore stages beside dataDir and refuses a layout its rename swap cannot
 * complete.
 *
 * run() pulls and decrypts under `stagingRoot` (default: the parent directory
 * of rollbackRoot). Before pulling anything it refuses a dataDir that is a
 * mount point (restore/datadir-is-mount-point) and a stagingRoot or
 * rollbackRoot on another filesystem (restore/cross-device). When the swap
 * fails, the decrypted staging directory is removed and a rollbackRoot the
 * run created is removed while it is empty.
 *
 * A mount point cannot be created portably inside a test, so fs.statSync is
 * wrapped to report a different device for chosen paths; restore.js reads
 * devices through the same node:fs module.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var fs      = helpers.fs;
var os      = helpers.os;
var path    = helpers.path;

var PASSPHRASE = Buffer.from("restore-staging-passphrase-for-tests");

function _tmp(prefix) { return fs.mkdtempSync(path.join(os.tmpdir(), prefix)); }

async function _bundle(root) {
  var source = path.join(root, "source");
  fs.mkdirSync(source, { recursive: true });
  fs.writeFileSync(path.join(source, "db.enc"), "database AT BACKUP TIME");
  var storage = b.backup.diskStorage({ root: path.join(root, "store") });
  var run = await b.backup.create({
    dataDir: source, storage: storage, passphrase: PASSPHRASE,
    files: [{ relativePath: "db.enc", kind: "raw", required: true }],
    vaultKeyJson: '{"version":1,"kid":"k1"}',
  }).run();
  return { storage: storage, bundleId: run.bundleId };
}

function _watchingStorage(storage) {
  var pulls = [];
  return {
    pulls: pulls,
    storage: Object.assign({}, storage, {
      readBundle: async function (bundleId, destDir) { pulls.push(destDir); return storage.readBundle(bundleId, destDir); },
    }),
  };
}

function _withDeviceFor(paths, fn) {
  var original = fs.statSync;
  var targets = paths.map(function (p) { return path.resolve(p); });
  fs.statSync = function (p, o) {
    var st = original.call(fs, p, o);
    if (st && targets.indexOf(path.resolve(String(p))) !== -1) {
      var copy = Object.create(Object.getPrototypeOf(st));
      Object.assign(copy, st, { dev: st.dev + 7919 });
      return copy;
    }
    return st;
  };
  return Promise.resolve().then(fn).finally(function () { fs.statSync = original; });
}

function _restoreWorkDirs(dir) {
  try { return fs.readdirSync(dir).filter(function (n) { return n.indexOf(".blamejs-restore-") === 0; }); }
  catch (_e) { return []; }
}

async function testMountPointAndCrossDeviceAreRefusedBeforePulling() {
  var root = _tmp("rst-dev-");
  try {
    b.auditSign._resetForTest();
    var fx = await _bundle(root);
    var dataDir = path.join(root, "live", "data");
    fs.mkdirSync(dataDir, { recursive: true });
    fs.writeFileSync(path.join(dataDir, "db.enc"), "database NOW");

    var watched = _watchingStorage(fx.storage);
    var code = null;
    await _withDeviceFor([dataDir], async function () {
      try {
        await b.restore.create({ dataDir: dataDir, storage: watched.storage, passphrase: PASSPHRASE }).run({ bundleId: fx.bundleId });
      } catch (e) { code = e.code; }
    });
    check("restore refuses a dataDir on a different device from its parent before pulling the bundle",
          code === "restore/datadir-is-mount-point" && watched.pulls.length === 0 &&
          fs.readFileSync(path.join(dataDir, "db.enc"), "utf8") === "database NOW",
          JSON.stringify({ code: code, pulls: watched.pulls.length }));

    var otherStaging = path.join(root, "elsewhere");
    fs.mkdirSync(otherStaging);
    var watched2 = _watchingStorage(fx.storage);
    var code2 = null, message2 = "";
    await _withDeviceFor([otherStaging], async function () {
      try {
        await b.restore.create({ dataDir: dataDir, storage: watched2.storage, passphrase: PASSPHRASE, stagingRoot: otherStaging })
          .run({ bundleId: fx.bundleId });
      } catch (e) { code2 = e.code; message2 = e.message; }
    });
    check("restore refuses a stagingRoot on another device before pulling the bundle",
          code2 === "restore/cross-device" && /stagingRoot/.test(message2) && watched2.pulls.length === 0,
          JSON.stringify({ code: code2, pulls: watched2.pulls.length }));

    var otherRollback = path.join(root, "rollbacks-elsewhere");
    fs.mkdirSync(otherRollback);
    var code3 = null, message3 = "";
    await _withDeviceFor([otherRollback], async function () {
      try {
        await b.restore.create({ dataDir: dataDir, storage: fx.storage, passphrase: PASSPHRASE,
          rollbackRoot: path.join(otherRollback, "points"), stagingRoot: path.join(root, "live") }).run({ bundleId: fx.bundleId });
      } catch (e) { code3 = e.code; message3 = e.message; }
    });
    check("restore refuses a rollbackRoot whose nearest existing directory is on another device",
          code3 === "restore/cross-device" && /rollbackRoot/.test(message3), String(code3));

    var insideCodes = [];
    var insideOpts = [{ stagingRoot: dataDir }, { stagingRoot: path.join(dataDir, "work") },
      { rollbackRoot: path.join(dataDir, "points"), stagingRoot: path.join(root, "live") }];
    for (var io = 0; io < insideOpts.length; io += 1) {
      var watched4 = _watchingStorage(fx.storage);
      try {
        await b.restore.create(Object.assign({ dataDir: dataDir, storage: watched4.storage, passphrase: PASSPHRASE }, insideOpts[io]))
          .run({ bundleId: fx.bundleId });
        insideCodes.push("resolved");
      } catch (e) { insideCodes.push(e.code + (watched4.pulls.length ? " after a pull" : "")); }
    }
    check("restore refuses a stagingRoot or rollbackRoot that is dataDir or inside it, before pulling",
          JSON.stringify(insideCodes) === JSON.stringify(["restore/bad-staging-root", "restore/bad-staging-root", "restore/bad-rollback-root"]) &&
          fs.readFileSync(path.join(dataDir, "db.enc"), "utf8") === "database NOW",
          JSON.stringify(insideCodes));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

async function testStagingIsBesideDataDirAndStaleWorkIsRemoved() {
  var root = _tmp("rst-where-");
  try {
    b.auditSign._resetForTest();
    var fx = await _bundle(root);
    var live = path.join(root, "live");
    var dataDir = path.join(live, "data");
    fs.mkdirSync(dataDir, { recursive: true });
    var stale = path.join(live, ".blamejs-restore-staging-2000-01-01T00-00-00-000Z-deadbeef");
    fs.mkdirSync(stale);
    fs.writeFileSync(path.join(stale, "db.enc"), "decrypted leftover");
    var watched = _watchingStorage(fx.storage);
    var restorer = b.restore.create({ dataDir: dataDir, storage: watched.storage, passphrase: PASSPHRASE });
    var summary = await restorer.run({ bundleId: fx.bundleId });
    check("restore pulls into the parent directory of rollbackRoot by default",
          watched.pulls.length === 1 && path.dirname(watched.pulls[0]) === path.dirname(path.resolve(restorer.rollbackRoot)),
          JSON.stringify(watched.pulls));
    check("a successful restore leaves no working directory beside dataDir, and removes one older than 24 hours",
          summary.fileCount === 1 && _restoreWorkDirs(live).length === 0, JSON.stringify(_restoreWorkDirs(live)));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

async function testSwapFailureRemovesDecryptedStaging() {
  var root = _tmp("rst-swap-");
  var originalRename = b.atomicFile.renameWithRetry;
  try {
    b.auditSign._resetForTest();
    var fx = await _bundle(root);
    var live = path.join(root, "live");
    var dataDir = path.join(live, "data");
    fs.mkdirSync(dataDir, { recursive: true });
    fs.writeFileSync(path.join(dataDir, "db.enc"), "database NOW");
    var tmpBefore = fs.readdirSync(os.tmpdir()).filter(function (n) { return n.indexOf("blamejs-restore-") === 0; });
    b.atomicFile.renameWithRetry = function (from, to) {
      if (path.resolve(to) === path.resolve(dataDir) && path.basename(String(from)).indexOf("blamejs-restore-staging-") !== -1) {
        var err = new Error("EXDEV: cross-device link not permitted, rename '" + from + "' -> '" + to + "'");
        err.code = "EXDEV";
        throw err;
      }
      return originalRename.apply(this, arguments);
    };
    var code = null;
    try {
      await b.restore.create({ dataDir: dataDir, storage: fx.storage, passphrase: PASSPHRASE }).run({ bundleId: fx.bundleId });
    } catch (e) { code = e.code; }
    b.atomicFile.renameWithRetry = originalRename;
    var tmpAfter = fs.readdirSync(os.tmpdir()).filter(function (n) { return n.indexOf("blamejs-restore-") === 0; });
    var tmpAdded = tmpAfter.filter(function (n) { return tmpBefore.indexOf(n) === -1; });
    check("a failed swap removes the decrypted staging directory and the rollbackRoot it created, and keeps dataDir",
          code === "restore/swap-failed" && _restoreWorkDirs(live).length === 0 && tmpAdded.length === 0 &&
          !fs.existsSync(dataDir + ".rollbacks") &&
          fs.readFileSync(path.join(dataDir, "db.enc"), "utf8") === "database NOW",
          JSON.stringify({ code: code, beside: _restoreWorkDirs(live), tmpAdded: tmpAdded,
            rollbacks: fs.existsSync(dataDir + ".rollbacks") }));
  } finally {
    b.atomicFile.renameWithRetry = originalRename;
    fs.rmSync(root, { recursive: true, force: true });
  }
}

function testRemoveStaleDirs() {
  var root = _tmp("rst-stale-");
  try {
    var fresh = "work-" + b.atomicFile.pathTimestamp() + "-a";
    var names = ["work-2000-01-01T00-00-00-000Z-a", "work-2000-01-01T00-00-00-000Z-kept", fresh,
      "work-not-a-stamp", "other-2000-01-01T00-00-00-000Z-a", "work-2000-13-01T00-00-00-000Z-a"];
    names.forEach(function (n) { fs.mkdirSync(path.join(root, n)); });
    fs.writeFileSync(path.join(root, "work-2000-01-02T00-00-00-000Z-file"), "a file, not a directory");
    var removed = b.atomicFile.removeStaleDirs(root, {
      prefix: "work-", olderThanMs: b.constants.TIME.hours(24), keep: ["work-2000-01-01T00-00-00-000Z-kept"],
    });
    var left = fs.readdirSync(root).sort();
    check("atomicFile.removeStaleDirs removes only prefixed directories whose stamp is older than the limit",
          JSON.stringify(removed) === JSON.stringify(["work-2000-01-01T00-00-00-000Z-a"]) &&
          left.indexOf("work-2000-01-01T00-00-00-000Z-kept") !== -1 && left.indexOf(fresh) !== -1 &&
          left.indexOf("work-2000-13-01T00-00-00-000Z-a") !== -1 && left.indexOf("work-2000-01-02T00-00-00-000Z-file") !== -1,
          JSON.stringify({ removed: removed, left: left }));
    var codes = [{}, { prefix: "", olderThanMs: 1 }, { prefix: "w", olderThanMs: 0 }, { prefix: "w", olderThanMs: 1.5 }]
      .map(function (o) { try { b.atomicFile.removeStaleDirs(root, o); return "none"; } catch (e) { return e.code; } });
    check("atomicFile.removeStaleDirs refuses a missing prefix or a non-positive-integer age",
          codes.every(function (c) { return c === "atomic-file/bad-opts"; }), JSON.stringify(codes));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

async function run() {
  await testMountPointAndCrossDeviceAreRefusedBeforePulling();
  await testStagingIsBesideDataDirAndStaleWorkIsRemoved();
  await testSwapFailureRemovesDecryptedStaging();
  testRemoveStaleDirs();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
