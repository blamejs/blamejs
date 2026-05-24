"use strict";
/**
 * Layer 0 — b.backup.bundleAdapterStorage.objectStoreAdapter +
 * end-to-end round-trip via b.objectStore local backend +
 * combined with v0.12.10 recipient + v0.12.11 passphrase wrap.
 */

var fs = require("node:fs");
var path = require("node:path");
var os = require("node:os");
var b = require("../../index");
var helpers = require("../helpers");
var check = helpers.check;

function _mkSrc(name, contents) {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "bjs-os-src-"));
  fs.writeFileSync(path.join(dir, name), contents);
  return dir;
}

async function testObjectStoreAdapterRoundTrip() {
  var rootDir = fs.mkdtempSync(path.join(os.tmpdir(), "bjs-os-root-"));
  var src = _mkSrc("data.json", "{\"v\":1}");
  var verify = path.join(os.tmpdir(), "bjs-os-verify-" + Date.now());
  try {
    var client = b.objectStore.buildBackend({ protocol: "local", rootDir: rootDir });
    var storage = b.backup.bundleAdapterStorage({
      adapter: b.backup.bundleAdapterStorage.objectStoreAdapter(client, { prefix: "test-prefix" }),
      format:  "tar.gz",
    });
    var bundleId = "2026-05-23T22-00-00-000Z-aaaa1111";
    await storage.writeBundle(bundleId, src);
    check("objectStoreAdapter: hasBundle true after write",
      await storage.hasBundle(bundleId));
    await storage.readBundle(bundleId, verify);
    check("objectStoreAdapter: bundle round-trips after fs-backed objectStore put + get",
      fs.readFileSync(path.join(verify, "data.json"), "utf-8") === "{\"v\":1}");
    var diskKey = path.join(rootDir, "test-prefix", bundleId, "bundle.tar.gz");
    check("objectStoreAdapter: prefix applied — key lands under operator-specified root",
      fs.existsSync(diskKey));
  } finally {
    try { fs.rmSync(rootDir, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(src,     { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(verify,  { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  }
}

async function testObjectStoreAdapterWithRecipient() {
  var rootDir = fs.mkdtempSync(path.join(os.tmpdir(), "bjs-os-root-r-"));
  var src = _mkSrc("phi.json", "{\"patient\":42}");
  var verify = path.join(os.tmpdir(), "bjs-os-verify-r-" + Date.now());
  try {
    var pair = b.crypto.generateEncryptionKeyPair();
    var client = b.objectStore.buildBackend({ protocol: "local", rootDir: rootDir });
    var storage = b.backup.bundleAdapterStorage({
      adapter:        b.backup.bundleAdapterStorage.objectStoreAdapter(client),
      format:         "tar.gz",
      cryptoStrategy: "recipient",
      recipient:      pair,
    });
    var bundleId = "2026-05-23T22-15-00-000Z-aaaa2222";
    await storage.writeBundle(bundleId, src);
    var sealed = fs.readFileSync(path.join(rootDir, bundleId, "bundle.tar.gz"));
    check("objectStoreAdapter + recipient: bundle carries BAWRP envelope magic on disk",
      sealed.slice(0, 5).toString("ascii") === "BAWRP");
    await storage.readBundle(bundleId, verify);
    check("objectStoreAdapter + recipient: round-trips through unwrap + gunzip + untar",
      fs.readFileSync(path.join(verify, "phi.json"), "utf-8") === "{\"patient\":42}");
  } finally {
    try { fs.rmSync(rootDir, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(src,     { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(verify,  { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  }
}

async function testObjectStoreAdapterRefusesBadClient() {
  var refused = null;
  try {
    b.backup.bundleAdapterStorage.objectStoreAdapter({});  // missing put/get/etc
  } catch (e) { refused = e; }
  check("objectStoreAdapter: missing methods refused upfront",
    refused && /missing method/.test(refused.message || ""));
  var refused2 = null;
  try {
    b.backup.bundleAdapterStorage.objectStoreAdapter(null);
  } catch (e) { refused2 = e; }
  check("objectStoreAdapter: null client refused upfront",
    refused2 && /client is required/.test(refused2.message || ""));
}

async function testObjectStoreAdapterPrefixTraversalRefused() {
  var client = b.objectStore.buildBackend({
    protocol: "local",
    rootDir:  fs.mkdtempSync(path.join(os.tmpdir(), "bjs-os-trav-")),
  });
  var refused = null;
  try {
    b.backup.bundleAdapterStorage.objectStoreAdapter(client, { prefix: "../escape" });
  } catch (e) { refused = e; }
  check("objectStoreAdapter: prefix with traversal segment refused upfront",
    refused && /traversal/.test(refused.message || ""));
}

async function run() {
  await testObjectStoreAdapterRoundTrip();
  await testObjectStoreAdapterWithRecipient();
  await testObjectStoreAdapterRefusesBadClient();
  await testObjectStoreAdapterPrefixTraversalRefused();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[backup-object-store-adapter] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
