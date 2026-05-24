"use strict";
/**
 * Layer 0 — b.backup.bundleAdapterStorage#bundleInfo + listBundles
 * format inference + v0.12.17 envelopeKind probe.
 */

var fs = require("node:fs");
var path = require("node:path");
var os = require("node:os");
var b = require("../../index");
var helpers = require("../helpers");
var check = helpers.check;

async function testBundleInfoTarGzRecipient() {
  var pair = b.crypto.generateEncryptionKeyPair();
  var src = fs.mkdtempSync(path.join(os.tmpdir(), "bi-src-r-"));
  var dest = fs.mkdtempSync(path.join(os.tmpdir(), "bi-dest-r-"));
  try {
    fs.writeFileSync(path.join(src, "phi.json"), "{\"id\":42}", { mode: 0o600 });
    var storage = b.backup.bundleAdapterStorage({
      adapter:        b.backup.bundleAdapterStorage.fsAdapter({ root: dest }),
      format:         "tar.gz",
      cryptoStrategy: "recipient",
      recipient:      pair,
    });
    var bid = "2026-05-23T23-00-00-000Z-deadbeef";
    await storage.writeBundle(bid, src);
    var info = await storage.bundleInfo(bid);
    check("bundleInfo: format inferred from storage layout", info.format === "tar.gz");
    check("bundleInfo: envelopeKind probed from payload magic",
      info.envelopeKind === "recipient");
    check("bundleInfo: sizeBytes carries payload length", info.sizeBytes > 0);
  } finally {
    try { fs.rmSync(src,  { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(dest, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  }
}

async function testBundleInfoTarPassphrase() {
  var src = fs.mkdtempSync(path.join(os.tmpdir(), "bi-src-p-"));
  var dest = fs.mkdtempSync(path.join(os.tmpdir(), "bi-dest-p-"));
  try {
    fs.writeFileSync(path.join(src, "data.json"), "{\"v\":1}", { mode: 0o600 });
    var storage = b.backup.bundleAdapterStorage({
      adapter:        b.backup.bundleAdapterStorage.fsAdapter({ root: dest }),
      format:         "tar",
      cryptoStrategy: "passphrase",
      passphrase:     "aLongCorrectHorseBatteryStaple9876!Phrase",
    });
    var bid = "2026-05-23T23-15-00-000Z-cafef00d";
    await storage.writeBundle(bid, src);
    var info = await storage.bundleInfo(bid);
    check("bundleInfo: tar format inferred", info.format === "tar");
    check("bundleInfo: passphrase envelope detected",
      info.envelopeKind === "passphrase");
  } finally {
    try { fs.rmSync(src,  { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(dest, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  }
}

async function testBundleInfoPlaintext() {
  var src = fs.mkdtempSync(path.join(os.tmpdir(), "bi-src-n-"));
  var dest = fs.mkdtempSync(path.join(os.tmpdir(), "bi-dest-n-"));
  try {
    fs.writeFileSync(path.join(src, "data.json"), "{\"v\":1}", { mode: 0o600 });
    var storage = b.backup.bundleAdapterStorage({
      adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: dest }),
      format:  "tar.gz",
    });
    var bid = "2026-05-23T23-30-00-000Z-ba5eba11";
    await storage.writeBundle(bid, src);
    var info = await storage.bundleInfo(bid);
    check("bundleInfo: plaintext bundle yields envelopeKind \"none\"",
      info.envelopeKind === "none");
  } finally {
    try { fs.rmSync(src,  { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(dest, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  }
}

async function testBundleInfoNotFound() {
  var dest = fs.mkdtempSync(path.join(os.tmpdir(), "bi-dest-nf-"));
  try {
    var storage = b.backup.bundleAdapterStorage({
      adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: dest }),
    });
    var refused = null;
    try {
      await storage.bundleInfo("2026-05-23T23-45-00-000Z-feedface");
    } catch (e) { refused = e; }
    check("bundleInfo: nonexistent bundle refused with bundle-not-found",
      refused && /bundle-not-found/.test(refused.code || refused.message));
  } finally {
    try { fs.rmSync(dest, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  }
}

async function testListBundlesCarriesFormat() {
  var src = fs.mkdtempSync(path.join(os.tmpdir(), "lb-src-"));
  var dest = fs.mkdtempSync(path.join(os.tmpdir(), "lb-dest-"));
  try {
    fs.writeFileSync(path.join(src, "data.json"), "{\"v\":1}", { mode: 0o600 });
    var tarStorage = b.backup.bundleAdapterStorage({
      adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: dest }),
      format:  "tar",
    });
    await tarStorage.writeBundle("2026-05-23T23-50-00-000Z-a1b2c3d4", src);
    var tarGzStorage = b.backup.bundleAdapterStorage({
      adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: dest }),
      format:  "tar.gz",
    });
    await tarGzStorage.writeBundle("2026-05-23T23-55-00-000Z-e5f6a7b8", src);
    var list = await tarStorage.listBundles();
    check("listBundles: returns 2 bundles", list.length === 2);
    var byFormat = {};
    for (var i = 0; i < list.length; i += 1) byFormat[list[i].format] = (byFormat[list[i].format] || 0) + 1;
    check("listBundles: format inferred per bundle (tar + tar.gz)",
      byFormat.tar === 1 && byFormat["tar.gz"] === 1);
  } finally {
    try { fs.rmSync(src,  { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(dest, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  }
}

async function run() {
  await testBundleInfoTarGzRecipient();
  await testBundleInfoTarPassphrase();
  await testBundleInfoPlaintext();
  await testBundleInfoNotFound();
  await testListBundlesCarriesFormat();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[backup-bundle-info] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
