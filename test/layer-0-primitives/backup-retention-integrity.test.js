// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Backup retention deletes only bundles older than a bundle that was written
 * completely and read back.
 *
 * diskStorage copies a bundle under `.partial-<bundleId>` and renames it into
 * place, and every storage listing requires `manifest.json`. run() reads the
 * new bundle back through storage and compares it with what it wrote before
 * retention runs; a mismatch rejects the run, deletes the bad bundle and
 * deletes nothing else. A bundle id that sorts after the run's own id takes no
 * keep slot and is not deleted.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var fs      = helpers.fs;
var os      = helpers.os;
var path    = helpers.path;

var PASSPHRASE = Buffer.from("backup-retention-integrity-passphrase");
var FUTURE_ID = "9999-12-31T23-59-59-999Z-00000000";
var OLD_ID = "2000-01-01T00-00-00-000Z-deadbeef";

function _tmp(prefix) { return fs.mkdtempSync(path.join(os.tmpdir(), prefix)); }

function _fixture(root, storage, retention) {
  var dataDir = path.join(root, "data");
  fs.mkdirSync(dataDir, { recursive: true });
  fs.writeFileSync(path.join(dataDir, "db.enc"), "database bytes");
  var opts = {
    dataDir: dataDir, storage: storage, passphrase: PASSPHRASE,
    files: [{ relativePath: "db.enc", kind: "raw", required: true }],
    vaultKeyJson: '{"version":1,"kid":"k1"}',
  };
  if (retention !== undefined) opts.retention = retention;
  return b.backup.create(opts);
}

async function _restores(storage, bundleId) {
  var target = _tmp("bri-restore-");
  try {
    var r = await b.restore.create({ dataDir: path.join(target, "data"), storage: storage, passphrase: PASSPHRASE })
      .run({ bundleId: bundleId });
    return r.fileCount === 1;
  } catch (_e) {
    return false;
  } finally {
    fs.rmSync(target, { recursive: true, force: true });
  }
}

async function testPlantedDirectoryTakesNoKeepSlot() {
  var root = _tmp("bri-planted-");
  try {
    b.auditSign._resetForTest();
    var storeRoot = path.join(root, "store");
    fs.mkdirSync(path.join(storeRoot, FUTURE_ID), { recursive: true });
    var storage = b.backup.diskStorage({ root: storeRoot });
    var engine = _fixture(root, storage, { keep: 1 });
    var first = await engine.run();
    var listed = (await storage.listBundles()).map(function (e) { return e.bundleId; });
    check("retention keep:1 with an empty future-dated directory keeps the bundle the run wrote",
          (await storage.hasBundle(first.bundleId)) && (await _restores(storage, first.bundleId)) &&
          (first.retentionPurged || []).length === 0,
          JSON.stringify({ purged: first.retentionPurged, listed: listed }));
    check("a bundle directory without manifest.json is neither listed nor reported by hasBundle",
          listed.indexOf(FUTURE_ID) === -1 && (await storage.hasBundle(FUTURE_ID)) === false, JSON.stringify(listed));

    var engine2 = _fixture(root, storage, { keep: 2 });
    await engine2.run();
    // A bundle id carries the millisecond it was written, so the next run
    // needs the clock to have moved for the two ids to sort apart.
    var secondAt = Date.now();
    await helpers.waitUntil(function () { return Date.now() > secondAt; },
      { timeoutMs: 1000, label: "retention: clock past the second bundle's millisecond" });
    var third = await engine2.run();
    var afterThird = (await storage.listBundles()).map(function (e) { return e.bundleId; });
    check("retention keep:2 keeps the two newest complete bundles",
          afterThird.length === 2 && afterThird[0] === third.bundleId && (third.retentionPurged || []).length === 1,
          JSON.stringify({ purged: third.retentionPurged, listed: afterThird }));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

async function testAHalfCopiedBundleTakesNoKeepSlot() {
  // A bundle copied in by hand, interrupted after the manifest and before
  // its blobs, carries a manifest that parses and names files that are not
  // there. Counting it as a bundle let it take a retention slot from one
  // that restores.
  var root = _tmp("bri-halfcopy-");
  try {
    b.auditSign._resetForTest();
    var storeRoot = path.join(root, "store");
    var storage = b.backup.diskStorage({ root: storeRoot });
    var engine = _fixture(root, storage, { keep: 2 });
    var real = await engine.run();

    // Copy the real bundle under a newer id, then remove its blobs.
    var halfId = b.atomicFile.pathTimestamp() + "-facef00d";
    b.atomicFile.copyDirRecursive(path.join(storeRoot, real.bundleId), path.join(storeRoot, halfId));
    var manifest = JSON.parse(
      fs.readFileSync(path.join(storeRoot, halfId, "manifest.json"), "utf8"));
    manifest.files.forEach(function (entry) {
      fs.rmSync(path.join(storeRoot, halfId, entry.encryptedPath), { force: true });
    });
    check("the half-copied directory still has a manifest that parses",
          fs.existsSync(path.join(storeRoot, halfId, "manifest.json")) && manifest.files.length > 0);

    var listed = (await storage.listBundles()).map(function (e) { return e.bundleId; });
    check("a bundle whose manifest names blobs that are missing is not listed",
          listed.indexOf(halfId) === -1 && (await storage.hasBundle(halfId)) === false,
          listed.join(","));

    // With keep: 2 and one real bundle plus the half copy, a second run must
    // not purge the first: the half copy never counted.
    var firstAt = Date.now();
    await helpers.waitUntil(function () { return Date.now() > firstAt; },
      { timeoutMs: 1000, label: "half-copy: clock past the first bundle's millisecond" });
    var second = await engine.run();
    check("the older restorable bundle survives the next run",
          (await storage.hasBundle(real.bundleId)) === true &&
          (second.retentionPurged || []).length === 0,
          JSON.stringify({ purged: second.retentionPurged }));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

async function testIncompleteWriteRejectsTheRunAndDeletesNothingElse() {
  var root = _tmp("bri-incomplete-");
  try {
    b.auditSign._resetForTest();
    var disk = b.backup.diskStorage({ root: path.join(root, "store") });
    var engineGood = _fixture(root, disk, { keep: 1 });
    var good = await engineGood.run();

    var lossy = Object.assign({}, disk, {
      name: "lossy",
      writeBundle: async function (bundleId, sourceDir) {
        await disk.writeBundle(bundleId, sourceDir);
        fs.rmSync(path.join(root, "store", bundleId, "files"), { recursive: true, force: true });
      },
    });
    var engineLossy = _fixture(root, lossy, { keep: 1 });
    var code = null;
    try { await engineLossy.run(); } catch (e) { code = e.code; }
    var listed = (await disk.listBundles()).map(function (e) { return e.bundleId; });
    check("a bundle that storage keeps only part of rejects the run, is deleted, and the older bundle survives",
          code === "backup/verify-after-write-failed" && listed.length === 1 && listed[0] === good.bundleId &&
          (await _restores(disk, good.bundleId)),
          JSON.stringify({ code: code, listed: listed }));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

async function testPurgeOlderSkipsIdsAfterNow() {
  var root = _tmp("bri-future-");
  try {
    b.auditSign._resetForTest();
    var storeRoot = path.join(root, "store");
    var storage = b.backup.diskStorage({ root: storeRoot });
    var engine = _fixture(root, storage);
    var a = await engine.run();
    var firstAt = Date.now();
    await helpers.waitUntil(function () { return Date.now() > firstAt; },
      { timeoutMs: 1000, label: "retention: clock past the first bundle's millisecond" });
    var c = await engine.run();
    fs.cpSync(path.join(storeRoot, a.bundleId), path.join(storeRoot, FUTURE_ID), { recursive: true });
    var purged = await engine.purgeOlder({ keep: 1 });
    var listed = (await storage.listBundles()).map(function (e) { return e.bundleId; });
    check("purgeOlder gives no keep slot to, and does not delete, a bundle id dated after now",
          JSON.stringify(purged.deleted) === JSON.stringify([a.bundleId]) &&
          listed.indexOf(FUTURE_ID) !== -1 && listed.indexOf(c.bundleId) !== -1,
          JSON.stringify({ deleted: purged.deleted, listed: listed }));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

async function testWorkingDirectories() {
  var root = _tmp("bri-partial-");
  var staleStaging = path.join(os.tmpdir(), "blamejs-backup-staging-" + OLD_ID);
  try {
    b.auditSign._resetForTest();
    var storeRoot = path.join(root, "store");
    fs.mkdirSync(path.join(storeRoot, ".partial-" + OLD_ID, "files"), { recursive: true });
    var freshPartialId = b.atomicFile.pathTimestamp() + "-0badf00d";
    fs.mkdirSync(path.join(storeRoot, ".partial-" + freshPartialId), { recursive: true });
    fs.mkdirSync(staleStaging, { recursive: true });
    // The sweep removes a leftover only when nothing inside it is recent, so
    // the abandoned partial and staging directories are aged on disk. The
    // fresh partial stays recent: a copy in progress has to survive.
    var abandonedAt = new Date(Date.now() - b.constants.TIME.hours(72));
    [path.join(storeRoot, ".partial-" + OLD_ID, "files"),
      path.join(storeRoot, ".partial-" + OLD_ID), staleStaging].forEach(function (p) {
      fs.utimesSync(p, abandonedAt, abandonedAt);
    });
    var storage = b.backup.diskStorage({ root: storeRoot });
    var copyTargets = [];
    var originalCopy = b.atomicFile.copyDirRecursive;
    b.atomicFile.copyDirRecursive = function (src, dest, o) {
      if (path.dirname(path.resolve(dest)) === path.resolve(storeRoot)) copyTargets.push(path.basename(dest));
      return originalCopy.call(this, src, dest, o);
    };
    var run;
    try { run = await _fixture(root, storage).run(); }
    finally { b.atomicFile.copyDirRecursive = originalCopy; }
    var entries = fs.readdirSync(storeRoot).sort();
    check("diskStorage copies a bundle under .partial-<bundleId>, renames it into place, and leaves no partial of its own",
          JSON.stringify(copyTargets) === JSON.stringify([".partial-" + run.bundleId]) &&
          entries.indexOf(run.bundleId) !== -1 && entries.indexOf(".partial-" + run.bundleId) === -1,
          JSON.stringify({ copyTargets: copyTargets, entries: entries }));
    check("a partial copy older than 24 hours is removed, and a recent one is left alone",
          entries.indexOf(".partial-" + OLD_ID) === -1 && entries.indexOf(".partial-" + freshPartialId) !== -1, JSON.stringify(entries));
    check("a backup staging directory older than 24 hours is removed from the temp directory",
          !fs.existsSync(staleStaging));
    check("a partial copy is not listed as a bundle",
          (await storage.listBundles()).length === 1);
  } finally {
    fs.rmSync(staleStaging, { recursive: true, force: true });
    fs.rmSync(root, { recursive: true, force: true });
  }
}

async function testAdapterDirectoryFormat() {
  var root = _tmp("bri-adapter-");
  try {
    b.auditSign._resetForTest();
    var inner = b.backup.bundleAdapterStorage.fsAdapter({ root: path.join(root, "keys") });
    var order = [];
    var recording = Object.assign({}, inner, {
      writeFile: async function (key, bytes) { order.push(key); return inner.writeFile(key, bytes); },
    });
    var storage = b.backup.bundleAdapterStorage({ adapter: recording, format: "directory" });
    var run = await _fixture(root, storage).run();
    var ownKeys = order.filter(function (k) { return k.indexOf(run.bundleId + "/") === 0; });
    var crafted = path.join(root, "crafted");
    fs.mkdirSync(path.join(crafted, "files"), { recursive: true });
    fs.writeFileSync(path.join(crafted, "files", "a.enc"), "a");
    fs.writeFileSync(path.join(crafted, "manifest.json"), "{}");
    fs.writeFileSync(path.join(crafted, "zz-after-manifest.txt"), "z");
    var craftedId = "2026-01-01T00-00-00-000Z-0000abcd";
    order.length = 0;
    await storage.writeBundle(craftedId, crafted);
    check("adapter storage in directory format writes manifest.json after every other key",
          ownKeys.length > 1 && ownKeys[ownKeys.length - 1] === run.bundleId + "/manifest.json" &&
          order.length === 3 && order[2] === craftedId + "/manifest.json", JSON.stringify({ run: ownKeys, crafted: order }));
    await storage.deleteBundle(craftedId);

    await inner.writeFile(FUTURE_ID + "/files/db.enc.enc", Buffer.from("partial"));
    var listed = (await storage.listBundles()).map(function (e) { return e.bundleId; });
    check("adapter storage in directory format does not list a bundle without manifest.json",
          listed.indexOf(FUTURE_ID) === -1 && listed.indexOf(run.bundleId) !== -1, JSON.stringify(listed));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

function testRetentionOptionIsValidated() {
  var root = _tmp("bri-opts-");
  try {
    var storage = b.backup.diskStorage({ root: path.join(root, "store") });
    var wrong = [];
    [{ keep: 0 }, { keep: 0.5 }, { keep: "2" }, { keep: -1 }, {}, 3].forEach(function (retention) {
      var code = null;
      try { _fixture(root, storage, retention); } catch (e) { code = e.code; }
      if (code !== "backup/bad-retention") wrong.push(JSON.stringify(retention) + " -> " + code);
    });
    check("backup.create refuses a retention that is not { keep: <positive integer> }" +
          (wrong.length ? " (" + wrong.join("; ") + ")" : ""), wrong.length === 0);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

async function run() {
  await testPlantedDirectoryTakesNoKeepSlot();
  await testAHalfCopiedBundleTakesNoKeepSlot();
  await testIncompleteWriteRejectsTheRunAndDeletesNothingElse();
  await testPurgeOlderSkipsIdsAfterNow();
  await testWorkingDirectories();
  await testAdapterDirectoryFormat();
  testRetentionOptionIsValidated();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
