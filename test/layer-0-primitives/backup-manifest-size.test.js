// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The manifest writer and every manifest reader apply one size limit,
 * b.backupManifest.MAX_MANIFEST_BYTES. A manifest larger than 4 MiB written by
 * b.backup.run is read by restoreBundle.inspect, backup.verifyManifestSignature,
 * restore.run and the scheduleTest drill; a manifest above the limit is refused
 * when it is written, before storage.writeBundle. restore.run reports every
 * restore-bundle failure under a restore/ code of the same name.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var fs      = helpers.fs;
var os      = helpers.os;
var path    = helpers.path;
var C       = b.constants;

var PASSPHRASE = Buffer.from("backup-manifest-size-passphrase-for-tests");

function _tmp(prefix) { return fs.mkdtempSync(path.join(os.tmpdir(), prefix)); }

function _capturingScheduler() {
  var specs = [];
  return {
    specs: specs,
    create: function () {
      return { schedule: function (spec) { specs.push(spec); return spec; }, start: function () {}, stop: function () {} };
    },
  };
}

function _engine(root, scheduler) {
  var dataDir = path.join(root, "data");
  fs.mkdirSync(dataDir, { recursive: true });
  fs.writeFileSync(path.join(dataDir, "db.enc"), "database bytes");
  var storageRoot = path.join(root, "store");
  var storage = b.backup.diskStorage({ root: storageRoot });
  var engine = b.backup.create({
    dataDir: dataDir, storage: storage, passphrase: PASSPHRASE,
    files: [{ relativePath: "db.enc", kind: "raw", required: true }],
    vaultKeyJson: '{"version":1,"kid":"k1"}',
    scheduler: scheduler,
  });
  return { engine: engine, storage: storage, storageRoot: storageRoot };
}

async function testLargeManifestIsReadByEveryReader() {
  var root = _tmp("bms-size-");
  var wrong = [];
  try {
    b.auditSign._resetForTest();
    await b.auditSign.init({ dataDir: path.join(root, "audit"), mode: "plaintext" });
    var sched = _capturingScheduler();
    var fx = _engine(root, sched);
    var run = await fx.engine.run({ metadata: { note: "n".repeat(C.BYTES.mib(5)) } });
    var bundleDir = path.join(fx.storageRoot, run.bundleId);
    var manifestBytes = fs.statSync(path.join(bundleDir, "manifest.json")).size;
    if (!(manifestBytes > C.BYTES.mib(5))) wrong.push("precondition: manifest.json is " + manifestBytes + " bytes");

    try {
      var inspected = b.restoreBundle.inspect({ bundleDir: bundleDir });
      if (inspected.files.length !== 1) wrong.push("restoreBundle.inspect: files " + inspected.files.length);
    } catch (e) { wrong.push("restoreBundle.inspect threw " + e.code); }

    try {
      var verdict = b.backup.verifyManifestSignature(bundleDir);
      if (verdict.ok !== true) wrong.push("backup.verifyManifestSignature: " + JSON.stringify(verdict));
    } catch (e) { wrong.push("backup.verifyManifestSignature threw " + e.code); }

    var target = _tmp("bms-size-restore-");
    try {
      var restored = await b.restore.create({
        dataDir: path.join(target, "data"), storage: fx.storage, passphrase: PASSPHRASE,
      }).run({ bundleId: run.bundleId });
      if (restored.fileCount !== 1) wrong.push("restore.run: fileCount " + restored.fileCount);
    } catch (e) {
      wrong.push("restore.run threw " + e.code);
    } finally {
      fs.rmSync(target, { recursive: true, force: true });
    }

    var drillOutcome = null;
    var drillRoot = _tmp("bms-size-drill-");
    try {
      fx.engine.scheduleTest({
        cron: "0 3 * * 0", restoreTo: drillRoot,
        verify: async function () { return true; },
        notify: async function (info) { drillOutcome = info; },
      });
      await sched.specs[0].run();
    } finally {
      fs.rmSync(drillRoot, { recursive: true, force: true });
    }
    if (!drillOutcome || drillOutcome.outcome !== "success") wrong.push("scheduleTest drill: " + JSON.stringify(drillOutcome));
  } finally {
    b.auditSign._resetForTest();
    fs.rmSync(root, { recursive: true, force: true });
  }
  check("a manifest larger than 4 MiB written by backup.run is read by every manifest reader" +
        (wrong.length ? " (" + wrong.join("; ") + ")" : ""), wrong.length === 0);
}

async function testManifestAboveTheLimitIsRefusedWhenWritten() {
  var root = _tmp("bms-size-over-");
  try {
    b.auditSign._resetForTest();
    var fx = _engine(root, null);
    await fx.engine.run();
    var before = (await fx.storage.listBundles()).length;
    var code = null;
    try { await fx.engine.run({ metadata: { note: "n".repeat(b.backupManifest.MAX_MANIFEST_BYTES) } }); }
    catch (e) { code = e.code; }
    var after = (await fx.storage.listBundles()).length;
    var staged = fs.readdirSync(os.tmpdir()).filter(function (n) { return n.indexOf("blamejs-backup-staging-") === 0; });
    check("a manifest above MAX_MANIFEST_BYTES is refused before it reaches storage",
          code === "backup-manifest/too-large" && before === 1 && after === 1,
          JSON.stringify({ code: code, before: before, after: after, stagedLeftovers: staged.length }));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

async function testRestoreNamesAnInvalidManifest() {
  var root = _tmp("bms-size-invalid-");
  try {
    b.auditSign._resetForTest();
    var fx = _engine(root, null);
    var run = await fx.engine.run();
    var manifestPath = path.join(fx.storageRoot, run.bundleId, "manifest.json");
    var doc = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    doc.files = [];
    fs.writeFileSync(manifestPath, JSON.stringify(doc));
    var target = _tmp("bms-size-invalid-restore-");
    var code = null;
    try {
      await b.restore.create({ dataDir: path.join(target, "data"), storage: fx.storage, passphrase: PASSPHRASE })
        .run({ bundleId: run.bundleId });
    } catch (e) { code = e.code; }
    fs.rmSync(target, { recursive: true, force: true });
    check("restore.run reports an invalid manifest as restore/bad-manifest", code === "restore/bad-manifest", String(code));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

async function run() {
  await testLargeManifestIsReadByEveryReader();
  await testManifestAboveTheLimitIsRefusedWhenWritten();
  await testRestoreNamesAnInvalidManifest();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
