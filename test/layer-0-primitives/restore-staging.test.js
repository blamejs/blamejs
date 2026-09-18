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
    // The sweep removes a leftover only when nothing inside it is recent, so
    // the fixture has to look abandoned rather than merely old-named.
    var abandonedAt = new Date(Date.now() - b.constants.TIME.hours(72));
    [path.join(stale, "db.enc"), stale].forEach(function (p) {
      fs.utimesSync(p, abandonedAt, abandonedAt);
    });
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
    // The sweep asks for a stale NAME and no recent activity inside, so the
    // directories that stand for abandoned work are aged, and `fresh` is
    // left recent to show a current run's directory survives.
    var abandonedAt = new Date(Date.now() - b.constants.TIME.hours(72));
    names.filter(function (n) { return n !== fresh; }).forEach(function (n) {
      fs.utimesSync(path.join(root, n), abandonedAt, abandonedAt);
    });
    var removed = b.atomicFile.removeStaleDirs(root, {
      prefix: "work-", olderThanMs: b.constants.TIME.hours(24), keep: ["work-2000-01-01T00-00-00-000Z-kept"],
    });
    var left = fs.readdirSync(root).sort();
    check("atomicFile.removeStaleDirs removes only prefixed directories whose stamp is older than the limit",
          JSON.stringify(removed) === JSON.stringify(["work-2000-01-01T00-00-00-000Z-a"]) &&
          left.indexOf("work-2000-01-01T00-00-00-000Z-kept") !== -1 && left.indexOf(fresh) !== -1 &&
          left.indexOf("work-2000-13-01T00-00-00-000Z-a") !== -1 && left.indexOf("work-2000-01-02T00-00-00-000Z-file") !== -1,
          JSON.stringify({ removed: removed, left: left }));
    // An old NAME is not evidence the work stopped: a copy still running
    // writes as it goes, so a directory with recent activity inside is left
    // alone however long ago it started.
    var active = "work-2000-01-01T00-00-00-000Z-active";
    fs.mkdirSync(path.join(root, active, "nested"), { recursive: true });
    fs.writeFileSync(path.join(root, active, "nested", "chunk.part"), "being written");
    var removedSecond = b.atomicFile.removeStaleDirs(root, {
      prefix: "work-", olderThanMs: b.constants.TIME.hours(24),
    });
    check("a directory with an old name but recent activity inside is kept",
          removedSecond.indexOf(active) === -1 && fs.existsSync(path.join(root, active, "nested", "chunk.part")),
          JSON.stringify(removedSecond));

    // With its contents aged past the window it is removed.
    var longAgo = new Date(Date.now() - b.constants.TIME.hours(72));
    [path.join(root, active, "nested", "chunk.part"), path.join(root, active, "nested"),
      path.join(root, active)].forEach(function (p) { fs.utimesSync(p, longAgo, longAgo); });
    var removedThird = b.atomicFile.removeStaleDirs(root, {
      prefix: "work-", olderThanMs: b.constants.TIME.hours(24),
    });
    check("the same directory is removed once nothing inside it is recent",
          removedThird.indexOf(active) !== -1 && !fs.existsSync(path.join(root, active)),
          JSON.stringify(removedThird));

    // A scan the sweep cannot finish is inconclusive, not idle: a directory
    // with more children than the scan budget is kept even when every
    // entry it managed to read is old, because the file being written may
    // be one of the entries it never reached.
    var crowded = "work-2000-01-01T00-00-00-000Z-crowded";
    fs.mkdirSync(path.join(root, crowded), { recursive: true });
    var aged = new Date(Date.now() - b.constants.TIME.hours(72));
    for (var ci = 0; ci < 4100; ci += 1) {
      var child = path.join(root, crowded, "c" + ci);
      fs.writeFileSync(child, "");
      fs.utimesSync(child, aged, aged);
    }
    fs.utimesSync(path.join(root, crowded), aged, aged);
    var removedCrowded = b.atomicFile.removeStaleDirs(root, {
      prefix: "work-", olderThanMs: b.constants.TIME.hours(24),
    });
    check("a directory the activity scan cannot finish is kept",
          removedCrowded.indexOf(crowded) === -1 && fs.existsSync(path.join(root, crowded)),
          JSON.stringify(removedCrowded));
    fs.rmSync(path.join(root, crowded), { recursive: true, force: true });

    // A phase that only READS what was staged, an upload, moves no
    // modification time, so the owner holds a heartbeat and the sweep sees
    // the directory as active.
    var uploading = "work-2000-01-01T00-00-00-000Z-uploading";
    fs.mkdirSync(path.join(root, uploading), { recursive: true });
    fs.writeFileSync(path.join(root, uploading, "payload.bin"), "staged bytes");
    var agedForUpload = new Date(Date.now() - b.constants.TIME.hours(72));
    [path.join(root, uploading, "payload.bin"), path.join(root, uploading)]
      .forEach(function (p) { fs.utimesSync(p, agedForUpload, agedForUpload); });
    var removedMidUpload = b.atomicFile.removeStaleDirs(root, {
      prefix: "work-", olderThanMs: b.constants.TIME.hours(24),
    });
    check("without a heartbeat an idle-looking upload directory is swept",
          removedMidUpload.indexOf(uploading) !== -1, JSON.stringify(removedMidUpload));

    fs.mkdirSync(path.join(root, uploading), { recursive: true });
    fs.writeFileSync(path.join(root, uploading, "payload.bin"), "staged bytes");
    [path.join(root, uploading, "payload.bin"), path.join(root, uploading)]
      .forEach(function (p) { fs.utimesSync(p, agedForUpload, agedForUpload); });
    var beat = b.atomicFile.heartbeat(path.join(root, uploading));
    try {
      var removedWithBeat = b.atomicFile.removeStaleDirs(root, {
        prefix: "work-", olderThanMs: b.constants.TIME.hours(24),
      });
      check("a heartbeat keeps the directory through a read-only phase",
            removedWithBeat.indexOf(uploading) === -1 &&
            fs.existsSync(path.join(root, uploading, "payload.bin")),
            JSON.stringify(removedWithBeat));
      // The marker sits BESIDE the directory: the staged bytes are copied
      // and compared, and a file appearing inside them would fail that
      // comparison on a backup slow enough to beat twice.
      check("the marker is a sibling, not part of the staged bytes",
            fs.existsSync(path.join(root, uploading + ".active")) &&
            fs.readdirSync(path.join(root, uploading)).join(",") === "payload.bin",
            fs.readdirSync(path.join(root, uploading)).join(","));
    } finally { beat.stop(); }
    check("stopping the heartbeat removes its marker",
          !fs.existsSync(path.join(root, uploading + ".active")));

    // The marker path is predictable and the staging parent is shared, so a
    // link planted there must not be followed: the heartbeat creates its
    // marker exclusively and stays silent rather than writing through
    // someone else's file.
    var victim = path.join(root, "victim.txt");
    fs.writeFileSync(victim, "the operator's own bytes");
    var planted = path.join(root, uploading + ".active");
    var plantedKind = null;
    try { fs.linkSync(victim, planted); plantedKind = "hard link"; }
    catch (_e) {
      try { fs.symlinkSync(victim, planted); plantedKind = "symbolic link"; }
      catch (_e2) { plantedKind = null; }
    }
    if (plantedKind === null) {
      helpers.unavailable("heartbeat: planted-link refusal",
        "this host does not allow creating a hard or symbolic link");
    } else {
      fs.mkdirSync(path.join(root, uploading), { recursive: true });
      var blocked = b.atomicFile.heartbeat(path.join(root, uploading));
      blocked.stop();
      check("a " + plantedKind + " at the marker path is not written through",
            fs.readFileSync(victim, "utf8") === "the operator's own bytes",
            fs.readFileSync(victim, "utf8").slice(0, 40));
      fs.rmSync(planted, { force: true });
      fs.rmSync(path.join(root, uploading), { recursive: true, force: true });
    }

    // A marker it cannot create at all leaves the heartbeat silent, and
    // stopping one is safe whether or not it ever wrote anything.
    var impossible = b.atomicFile.heartbeat(path.join(root, "no-such-parent", "work"));
    impossible.stop();
    impossible.stop();
    check("a heartbeat that cannot create its marker stays silent and stops cleanly",
          !fs.existsSync(path.join(root, "no-such-parent")));
    fs.rmSync(path.join(root, uploading), { recursive: true, force: true });

    var codes = [{}, { prefix: "", olderThanMs: 1 }, { prefix: "w", olderThanMs: 0 }, { prefix: "w", olderThanMs: 1.5 }]
      .map(function (o) { try { b.atomicFile.removeStaleDirs(root, o); return "none"; } catch (e) { return e.code; } });
    check("atomicFile.removeStaleDirs refuses a missing prefix or a non-positive-integer age",
          codes.every(function (c) { return c === "atomic-file/bad-opts"; }), JSON.stringify(codes));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

async function testASymlinkIntoDataDirIsRefusedBeforePulling() {
  // A staging or rollback root that is a SYMLINK into dataDir passes a
  // lexical containment check: the pull and the decrypted staging land
  // inside the live directory, and moving dataDir aside takes them with it,
  // so the second rename fails with the bundle already decrypted. The
  // preflight canonicalizes both sides before comparing.
  var root = _tmp("rst-symlink-");
  try {
    b.auditSign._resetForTest();
    var fx = await _bundle(root);
    var dataDir = path.join(root, "live", "data");
    fs.mkdirSync(path.join(dataDir, "inner"), { recursive: true });

    var stagingLink = path.join(root, "live", "staging-link");
    try { fs.symlinkSync(path.join(dataDir, "inner"), stagingLink, "junction"); }
    catch (_e) {
      helpers.unavailable("restore staging: symlink refusal",
        "this host does not allow creating a directory symlink");
      return;
    }

    var watcher = _watchingStorage(fx.storage);
    var refused = null;
    try {
      await b.restore.create({
        dataDir:      dataDir,
        storage:      watcher.storage,
        passphrase:   PASSPHRASE,
        stagingRoot:  stagingLink,
        rollbackRoot: path.join(root, "rollbacks"),
        audit:        false,
      }).run({ bundleId: fx.bundleId });
    } catch (e) { refused = e; }
    check("a stagingRoot symlinked into dataDir is refused",
          refused !== null && refused.code === "restore/bad-staging-root",
          refused && (refused.code + " " + refused.message.slice(0, 80)));
    check("nothing was pulled before the refusal", watcher.pulls.length === 0,
          watcher.pulls.join(","));

    // The other direction: a path lexically INSIDE dataDir whose symlink
    // target sits elsewhere. The staging bytes land outside, but the
    // pathname the swap uses is inside dataDir and disappears when dataDir
    // is renamed aside, so the second rename fails with ENOENT after the
    // bundle has been decrypted.
    var outward = path.join(root, "outside-target");
    fs.mkdirSync(outward, { recursive: true });
    var inwardName = path.join(dataDir, "stage-link");
    try { fs.symlinkSync(outward, inwardName, "junction"); }
    catch (_e) {
      helpers.unavailable("restore staging: outward symlink refusal",
        "this host does not allow creating a directory symlink");
      return;
    }
    var watcherTwo = _watchingStorage(fx.storage);
    var refusedOutward = null;
    try {
      await b.restore.create({
        dataDir:      dataDir,
        storage:      watcherTwo.storage,
        passphrase:   PASSPHRASE,
        stagingRoot:  inwardName,
        rollbackRoot: path.join(root, "rollbacks"),
        audit:        false,
      }).run({ bundleId: fx.bundleId });
    } catch (e) { refusedOutward = e; }
    check("a stagingRoot whose PATH is inside dataDir is refused, wherever it points",
          refusedOutward !== null && refusedOutward.code === "restore/bad-staging-root",
          refusedOutward && (refusedOutward.code + " " + refusedOutward.message.slice(0, 80)));
    check("nothing was pulled before that refusal either", watcherTwo.pulls.length === 0,
          watcherTwo.pulls.join(","));
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
}

async function testASymlinkedDataDirIsRefusedBeforePulling() {
  // A symlinked dataDir survives the layout checks, which follow the link,
  // and only restoreRollback.swap() catches it — after the bundle has been
  // pulled and decrypted. The preflight checks the path as written.
  var root = _tmp("rst-datadir-link-");
  try {
    b.auditSign._resetForTest();
    var fx = await _bundle(root);
    var real = path.join(root, "real-data");
    fs.mkdirSync(real, { recursive: true });
    var link = path.join(root, "data-link");
    try { fs.symlinkSync(real, link, "junction"); }
    catch (_e) {
      helpers.unavailable("restore staging: symlinked dataDir refusal",
        "this host does not allow creating a directory symlink");
      return;
    }

    var watcher = _watchingStorage(fx.storage);
    var refused = null;
    try {
      await b.restore.create({
        dataDir:      link,
        storage:      watcher.storage,
        passphrase:   PASSPHRASE,
        rollbackRoot: path.join(root, "rollbacks"),
        audit:        false,
      }).run({ bundleId: fx.bundleId });
    } catch (e) { refused = e; }
    check("a symlinked dataDir is refused",
          refused !== null && refused.code === "restore/datadir-is-symlink",
          refused && (refused.code + " " + refused.message.slice(0, 80)));
    check("nothing was pulled before that refusal", watcher.pulls.length === 0,
          watcher.pulls.join(","));
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
}

async function testANonDirectoryRoleIsRefusedBeforePulling() {
  // A file where a directory belongs used to pass the layout checks, which
  // only asked about devices and mount points: dataDir as a file swapped
  // "successfully" and left a rollback that rollback() refuses, and a
  // rollbackRoot as a file was caught by ensureDir after the bundle had
  // been pulled and decrypted.
  var ROLES = [
    { role: "dataDir",      code: "restore/datadir-not-a-directory" },
    { role: "stagingRoot",  code: "restore/bad-staging-root" },
    { role: "rollbackRoot", code: "restore/bad-rollback-root" },
  ];
  var wrong = [];
  for (var i = 0; i < ROLES.length; i += 1) {
    var root = _tmp("rst-notdir-");
    try {
      b.auditSign._resetForTest();
      var fx = await _bundle(root);
      var live = path.join(root, "live");
      fs.mkdirSync(live, { recursive: true });
      var opts = {
        dataDir:      path.join(live, "data"),
        stagingRoot:  path.join(live, "staging"),
        rollbackRoot: path.join(live, "rollbacks"),
      };
      fs.mkdirSync(opts.dataDir, { recursive: true });
      // The role under test is a regular file; the others stay directories.
      fs.rmSync(opts[ROLES[i].role], { recursive: true, force: true });
      fs.writeFileSync(opts[ROLES[i].role], "a file where a directory belongs");

      var watcher = _watchingStorage(fx.storage);
      var refused = null;
      try {
        await b.restore.create({
          dataDir:      opts.dataDir,
          storage:      watcher.storage,
          passphrase:   PASSPHRASE,
          stagingRoot:  opts.stagingRoot,
          rollbackRoot: opts.rollbackRoot,
          audit:        false,
        }).run({ bundleId: fx.bundleId });
      } catch (e) { refused = e; }
      if (refused === null || refused.code !== ROLES[i].code) {
        wrong.push(ROLES[i].role + " -> " + (refused === null ? "no refusal" : refused.code));
      } else if (watcher.pulls.length !== 0) {
        wrong.push(ROLES[i].role + " pulled before refusing");
      }
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
  }
  check("a file where dataDir, stagingRoot or rollbackRoot belongs is refused before pulling" +
        (wrong.length ? " (" + wrong.join("; ") + ")" : ""), wrong.length === 0);
}

async function testADanglingSymlinkRoleIsRefusedBeforePulling() {
  // A link that resolves to nothing reads as ENOENT through statSync, which
  // the preflight took for "absent, and I will create it". ensureDir then
  // failed on the dangling link after the bundle had been decrypted.
  var ROLES = [
    { role: "stagingRoot",  code: "restore/bad-staging-root" },
    { role: "rollbackRoot", code: "restore/bad-rollback-root" },
  ];
  var wrong = [];
  for (var i = 0; i < ROLES.length; i += 1) {
    var root = _tmp("rst-dangling-");
    try {
      b.auditSign._resetForTest();
      var fx = await _bundle(root);
      var live = path.join(root, "live");
      fs.mkdirSync(live, { recursive: true });
      var opts = {
        dataDir:      path.join(live, "data"),
        stagingRoot:  path.join(live, "staging"),
        rollbackRoot: path.join(live, "rollbacks"),
      };
      fs.mkdirSync(opts.dataDir, { recursive: true });
      try { fs.symlinkSync(path.join(root, "nowhere"), opts[ROLES[i].role], "junction"); }
      catch (_e) {
        helpers.unavailable("restore staging: dangling-symlink refusal",
          "this host does not allow creating a directory symlink");
        return;
      }

      var watcher = _watchingStorage(fx.storage);
      var refused = null;
      try {
        await b.restore.create({
          dataDir:      opts.dataDir,
          storage:      watcher.storage,
          passphrase:   PASSPHRASE,
          stagingRoot:  opts.stagingRoot,
          rollbackRoot: opts.rollbackRoot,
          audit:        false,
        }).run({ bundleId: fx.bundleId });
      } catch (e) { refused = e; }
      if (refused === null || refused.code !== ROLES[i].code) {
        wrong.push(ROLES[i].role + " -> " + (refused === null ? "no refusal" : refused.code));
      } else if (watcher.pulls.length !== 0) {
        wrong.push(ROLES[i].role + " pulled before refusing");
      }
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
  }
  check("a stagingRoot or rollbackRoot that is a dangling symlink is refused before pulling" +
        (wrong.length ? " (" + wrong.join("; ") + ")" : ""), wrong.length === 0);
}

async function run() {
  await testANonDirectoryRoleIsRefusedBeforePulling();
  await testADanglingSymlinkRoleIsRefusedBeforePulling();
  await testASymlinkedDataDirIsRefusedBeforePulling();
  await testASymlinkIntoDataDirIsRefusedBeforePulling();
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
