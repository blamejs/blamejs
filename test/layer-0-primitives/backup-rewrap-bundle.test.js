"use strict";
/**
 * Layer 0 — bundleAdapterStorage.rewrapBundle key rotation without
 * restore/rewrite of inner archive bytes.
 */

var fs = require("node:fs");
var path = require("node:path");
var os = require("node:os");
var b = require("../../index");
var helpers = require("../helpers");
var check = helpers.check;

async function testRewrapRecipientRotation() {
  var oldPair = b.crypto.generateEncryptionKeyPair();
  var newPair = b.crypto.generateEncryptionKeyPair();
  var src = fs.mkdtempSync(path.join(os.tmpdir(), "rw-src-"));
  var dest = fs.mkdtempSync(path.join(os.tmpdir(), "rw-dest-"));
  var verify = path.join(os.tmpdir(), "rw-v-" + Date.now());
  try {
    fs.writeFileSync(path.join(src, "a.json"), "{\"v\":1}", { mode: 0o600 });
    var storage = b.backup.bundleAdapterStorage({
      adapter:        b.backup.bundleAdapterStorage.fsAdapter({ root: dest }),
      format:         "tar.gz",
      cryptoStrategy: "recipient",
      recipient:      oldPair,
    });
    var bid = "2026-05-24T06-00-00-000Z-aabbccdd";
    await storage.writeBundle(bid, src);
    var rw = await storage.rewrapBundle(bid, { newRecipient: newPair });
    check("rewrapBundle: returns oldEnvelopeKind + newEnvelopeKind",
      rw.oldEnvelopeKind === "recipient" && rw.newEnvelopeKind === "recipient");
    check("rewrapBundle: bytesRewritten > 0", rw.bytesRewritten > 0);
    // Open a fresh storage with newPair + restore
    var rotated = b.backup.bundleAdapterStorage({
      adapter:        b.backup.bundleAdapterStorage.fsAdapter({ root: dest }),
      format:         "tar.gz",
      cryptoStrategy: "recipient",
      recipient:      newPair,
    });
    await rotated.readBundle(bid, verify);
    check("rewrapBundle: bundle restores under newRecipient after rotation",
      fs.readFileSync(path.join(verify, "a.json"), "utf-8") === "{\"v\":1}");
  } finally {
    try { fs.rmSync(src,    { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(dest,   { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(verify, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  }
}

async function testRewrapPassphraseRotation() {
  var oldPass = "aLongCorrectHorseBatteryStaple9876!Phrase";
  var newPass = "completelyDifferentPassphraseEvenLonger123!@#";
  var src = fs.mkdtempSync(path.join(os.tmpdir(), "rw-p-src-"));
  var dest = fs.mkdtempSync(path.join(os.tmpdir(), "rw-p-dest-"));
  var verify = path.join(os.tmpdir(), "rw-p-v-" + Date.now());
  try {
    fs.writeFileSync(path.join(src, "a.json"), "{\"v\":2}", { mode: 0o600 });
    var storage = b.backup.bundleAdapterStorage({
      adapter:        b.backup.bundleAdapterStorage.fsAdapter({ root: dest }),
      format:         "tar.gz",
      cryptoStrategy: "passphrase",
      passphrase:     oldPass,
    });
    var bid = "2026-05-24T06-30-00-000Z-eeffaabb";
    await storage.writeBundle(bid, src);
    var rw = await storage.rewrapBundle(bid, { newPassphrase: newPass });
    check("rewrapBundle: passphrase rotation reports passphrase envelope",
      rw.oldEnvelopeKind === "passphrase" && rw.newEnvelopeKind === "passphrase");
    var rotated = b.backup.bundleAdapterStorage({
      adapter:        b.backup.bundleAdapterStorage.fsAdapter({ root: dest }),
      format:         "tar.gz",
      cryptoStrategy: "passphrase",
      passphrase:     newPass,
    });
    await rotated.readBundle(bid, verify);
    check("rewrapBundle: bundle restores under newPassphrase after rotation",
      fs.readFileSync(path.join(verify, "a.json"), "utf-8") === "{\"v\":2}");
  } finally {
    try { fs.rmSync(src,    { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(dest,   { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(verify, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  }
}

async function testRewrapRefusesPlaintextBundle() {
  var src = fs.mkdtempSync(path.join(os.tmpdir(), "rw-pt-src-"));
  var dest = fs.mkdtempSync(path.join(os.tmpdir(), "rw-pt-dest-"));
  try {
    fs.writeFileSync(path.join(src, "a"), "x", { mode: 0o600 });
    var storage = b.backup.bundleAdapterStorage({
      adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: dest }),
      format:  "tar.gz",
    });
    var bid = "2026-05-24T06-45-00-000Z-99887766";
    await storage.writeBundle(bid, src);
    var refused = null;
    try {
      await storage.rewrapBundle(bid, {
        newRecipient: b.crypto.generateEncryptionKeyPair(),
      });
    } catch (e) { refused = e; }
    check("rewrapBundle: plaintext bundle refused with no-envelope-to-rewrap",
      refused && /no-envelope-to-rewrap/.test(refused.code || refused.message));
  } finally {
    try { fs.rmSync(src,  { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(dest, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  }
}

async function testRewrapRefusesMissingNewRecipient() {
  var oldPair = b.crypto.generateEncryptionKeyPair();
  var src = fs.mkdtempSync(path.join(os.tmpdir(), "rw-nr-src-"));
  var dest = fs.mkdtempSync(path.join(os.tmpdir(), "rw-nr-dest-"));
  try {
    fs.writeFileSync(path.join(src, "a"), "x", { mode: 0o600 });
    var storage = b.backup.bundleAdapterStorage({
      adapter:        b.backup.bundleAdapterStorage.fsAdapter({ root: dest }),
      format:         "tar.gz",
      cryptoStrategy: "recipient",
      recipient:      oldPair,
    });
    var bid = "2026-05-24T07-00-00-000Z-aabbcc01";
    await storage.writeBundle(bid, src);
    var refused = null;
    try { await storage.rewrapBundle(bid, {}); } catch (e) { refused = e; }
    check("rewrapBundle: missing newRecipient refused upfront",
      refused && /no-new-recipient/.test(refused.code || refused.message));
  } finally {
    try { fs.rmSync(src,  { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(dest, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  }
}

async function run() {
  await testRewrapRecipientRotation();
  await testRewrapPassphraseRotation();
  await testRewrapRefusesPlaintextBundle();
  await testRewrapRefusesMissingNewRecipient();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[backup-rewrap-bundle] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
