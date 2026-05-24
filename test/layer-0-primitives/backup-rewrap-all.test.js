"use strict";
/**
 * Layer 0 — bundleAdapterStorage.rewrapAllBundles batch envelope
 * rotation across plaintext + recipient + passphrase + directory.
 */

var fs = require("node:fs");
var path = require("node:path");
var os = require("node:os");
var b = require("../../index");
var helpers = require("../helpers");
var check = helpers.check;

async function testRewrapAllRecipient() {
  var oldPair = b.crypto.generateEncryptionKeyPair();
  var newPair = b.crypto.generateEncryptionKeyPair();
  var src = fs.mkdtempSync(path.join(os.tmpdir(), "rwa-src-"));
  var dest = fs.mkdtempSync(path.join(os.tmpdir(), "rwa-dest-"));
  try {
    fs.writeFileSync(path.join(src, "a"), "x", { mode: 0o600 });
    var storage = b.backup.bundleAdapterStorage({
      adapter:        b.backup.bundleAdapterStorage.fsAdapter({ root: dest }),
      format:         "tar.gz",
      cryptoStrategy: "recipient",
      recipient:      oldPair,
    });
    var ids = [
      "2026-05-24T09-00-00-000Z-aabb1111",
      "2026-05-24T09-15-00-000Z-aabb2222",
      "2026-05-24T09-30-00-000Z-aabb3333",
    ];
    for (var i = 0; i < ids.length; i += 1) await storage.writeBundle(ids[i], src);
    var report = await storage.rewrapAllBundles({ newRecipient: newPair });
    check("rewrapAllBundles: rotated count matches bundle count",
      report.total === 3 && report.rotated === 3 && report.failed === 0 &&
      report.skipped === 0);
    // Verify rotation worked end-to-end
    var fresh = b.backup.bundleAdapterStorage({
      adapter:        b.backup.bundleAdapterStorage.fsAdapter({ root: dest }),
      format:         "tar.gz",
      cryptoStrategy: "recipient",
      recipient:      newPair,
    });
    var verify = await fresh.verifyAllBundles();
    check("rewrapAllBundles: every bundle verifies under new recipient",
      verify.ok === 3 && verify.failed === 0);
  } finally {
    try { fs.rmSync(src,  { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(dest, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  }
}

async function testRewrapAllMixedPlaintextAndEncrypted() {
  var oldPair = b.crypto.generateEncryptionKeyPair();
  var newPair = b.crypto.generateEncryptionKeyPair();
  var src = fs.mkdtempSync(path.join(os.tmpdir(), "rwa-mix-src-"));
  var dest = fs.mkdtempSync(path.join(os.tmpdir(), "rwa-mix-dest-"));
  try {
    fs.writeFileSync(path.join(src, "a"), "x", { mode: 0o600 });
    // Encrypted bundle
    var enc = b.backup.bundleAdapterStorage({
      adapter:        b.backup.bundleAdapterStorage.fsAdapter({ root: dest }),
      format:         "tar.gz",
      cryptoStrategy: "recipient",
      recipient:      oldPair,
    });
    await enc.writeBundle("2026-05-24T10-00-00-000Z-bbcc4444", src);
    // Plaintext bundle in the same storage root
    var pt = b.backup.bundleAdapterStorage({
      adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: dest }),
      format:  "tar.gz",
    });
    await pt.writeBundle("2026-05-24T10-15-00-000Z-bbcc5555", src);
    // Rewrap from the encrypted storage's perspective (with the
    // old key configured); plaintext should be skipped, encrypted
    // should be rotated.
    var report = await enc.rewrapAllBundles({ newRecipient: newPair });
    check("rewrapAllBundles: mixed storage reports rotated + skipped",
      report.total === 2 && report.rotated === 1 && report.skipped === 1 &&
      report.failed === 0);
    var skippedEntry = report.results.filter(function (r) { return r.status === "skipped"; })[0];
    check("rewrapAllBundles: skipped entry carries reason",
      skippedEntry && /no-envelope|format-not-wrappable/.test(skippedEntry.reason || ""));
  } finally {
    try { fs.rmSync(src,  { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(dest, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  }
}

async function testRewrapAllEmptyStorage() {
  var dest = fs.mkdtempSync(path.join(os.tmpdir(), "rwa-empty-"));
  try {
    var storage = b.backup.bundleAdapterStorage({
      adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: dest }),
    });
    var report = await storage.rewrapAllBundles({
      newRecipient: b.crypto.generateEncryptionKeyPair(),
    });
    check("rewrapAllBundles: empty storage returns zeroes",
      report.total === 0 && report.rotated === 0 &&
      report.skipped === 0 && report.failed === 0);
  } finally {
    try { fs.rmSync(dest, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  }
}

async function run() {
  await testRewrapAllRecipient();
  await testRewrapAllMixedPlaintextAndEncrypted();
  await testRewrapAllEmptyStorage();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[backup-rewrap-all] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
