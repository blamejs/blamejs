"use strict";
/**
 * Layer 0 — bundleAdapterStorage.verifyAllBundles batch integrity
 * check with concurrency cap + stopOnFirstFailure short-circuit.
 */

var fs = require("node:fs");
var path = require("node:path");
var os = require("node:os");
var b = require("../../index");
var helpers = require("../helpers");
var check = helpers.check;

async function _makeStorageWithBundles(bundleIds, srcContent) {
  var src = fs.mkdtempSync(path.join(os.tmpdir(), "vab-src-"));
  fs.writeFileSync(path.join(src, "a"), srcContent || "x", { mode: 0o600 });
  var dest = fs.mkdtempSync(path.join(os.tmpdir(), "vab-dest-"));
  var storage = b.backup.bundleAdapterStorage({
    adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: dest }),
    format:  "tar.gz",
  });
  for (var i = 0; i < bundleIds.length; i += 1) {
    await storage.writeBundle(bundleIds[i], src);
  }
  return { storage: storage, src: src, dest: dest };
}

async function testVerifyAllBundlesAllOk() {
  var ids = [
    "2026-05-24T03-00-00-000Z-aaaa1111",
    "2026-05-24T03-15-00-000Z-bbbb2222",
    "2026-05-24T03-30-00-000Z-cccc3333",
  ];
  var ctx = await _makeStorageWithBundles(ids);
  try {
    var report = await ctx.storage.verifyAllBundles();
    check("verifyAllBundles: total matches bundle count", report.total === 3);
    check("verifyAllBundles: all bundles ok", report.ok === 3 && report.failed === 0);
    check("verifyAllBundles: results array length matches total",
      report.results.length === 3);
    check("verifyAllBundles: every result has ok=true",
      report.results.every(function (r) { return r.ok === true; }));
  } finally {
    try { fs.rmSync(ctx.src,  { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(ctx.dest, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  }
}

async function testVerifyAllBundlesMixedHealth() {
  var ids = [
    "2026-05-24T04-00-00-000Z-dddd4444",
    "2026-05-24T04-15-00-000Z-eeee5555",
    "2026-05-24T04-30-00-000Z-ffff6666",
  ];
  var ctx = await _makeStorageWithBundles(ids);
  try {
    // Corrupt the middle bundle's payload.
    var corruptPath = path.join(ctx.dest, "2026-05-24T04-15-00-000Z-eeee5555", "bundle.tar.gz");
    var bytes = fs.readFileSync(corruptPath);
    for (var i = 0; i < 16; i += 1) bytes[i] = 0xff;
    fs.writeFileSync(corruptPath, bytes, { mode: 0o600 });
    var report = await ctx.storage.verifyAllBundles();
    check("verifyAllBundles: counts split between ok + failed",
      report.ok === 2 && report.failed === 1);
    var failing = report.results.filter(function (r) { return r.ok === false; });
    check("verifyAllBundles: failing bundle isolated in results",
      failing.length === 1 && failing[0].bundleId === "2026-05-24T04-15-00-000Z-eeee5555");
    check("verifyAllBundles: failing bundle carries error code",
      failing[0].errors.length > 0);
  } finally {
    try { fs.rmSync(ctx.src,  { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(ctx.dest, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  }
}

async function testVerifyAllBundlesStopOnFirst() {
  var ids = [
    "2026-05-24T05-00-00-000Z-aabb1100",
    "2026-05-24T05-15-00-000Z-aabb1111",   // will corrupt
    "2026-05-24T05-30-00-000Z-aabb1122",
    "2026-05-24T05-45-00-000Z-aabb1133",
  ];
  var ctx = await _makeStorageWithBundles(ids);
  try {
    // Corrupt bundle 2 (will be hit early).
    var corruptPath = path.join(ctx.dest, ids[1], "bundle.tar.gz");
    var bytes = fs.readFileSync(corruptPath);
    for (var i = 0; i < 16; i += 1) bytes[i] = 0xff;
    fs.writeFileSync(corruptPath, bytes, { mode: 0o600 });
    var report = await ctx.storage.verifyAllBundles({
      stopOnFirstFailure: true,
      concurrency: 1,
    });
    check("verifyAllBundles({ stopOnFirstFailure }): walks fewer than total bundles",
      report.results.length < report.total);
    check("verifyAllBundles({ stopOnFirstFailure }): includes the failing bundle",
      report.results.some(function (r) { return r.ok === false; }));
  } finally {
    try { fs.rmSync(ctx.src,  { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(ctx.dest, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  }
}

async function testVerifyAllBundlesEmptyStorage() {
  var dest = fs.mkdtempSync(path.join(os.tmpdir(), "vab-empty-"));
  try {
    var storage = b.backup.bundleAdapterStorage({
      adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: dest }),
    });
    var report = await storage.verifyAllBundles();
    check("verifyAllBundles: empty storage returns zeroes cleanly",
      report.total === 0 && report.ok === 0 && report.failed === 0 &&
      report.results.length === 0);
  } finally {
    try { fs.rmSync(dest, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  }
}

async function run() {
  await testVerifyAllBundlesAllOk();
  await testVerifyAllBundlesMixedHealth();
  await testVerifyAllBundlesStopOnFirst();
  await testVerifyAllBundlesEmptyStorage();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[backup-verify-all-bundles] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
