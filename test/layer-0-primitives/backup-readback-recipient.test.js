// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A backup to a recipient whose private key this host does not hold still
 * completes.
 *
 * b.backup.run() reads each bundle back from storage and compares it with
 * what it wrote, so retention never deletes an older bundle on the strength
 * of one that did not store. An adapter storage configured with
 * cryptoStrategy: "recipient" and only the recipient's PUBLIC keys cannot
 * read its own bundles: unwrapping needs the private key, which is the
 * point of writing to a recipient. Such a backend reports
 * canReadBundle: false, and run() confirms the bundle is stored instead.
 * The result says which check ran.
 */

var fs      = require("fs");
var os      = require("os");
var path    = require("path");
var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

// Truncates the stored payload on disk right after the write, which is the
// damage a presence check cannot see: the storage key still exists.
function _corruptingStorage(storage, storeRoot) {
  var wrapped = Object.create(null);
  Object.keys(storage).forEach(function (k) { wrapped[k] = storage[k]; });
  wrapped.canReadBundle = storage.canReadBundle;
  wrapped.verifyStoredContent = function (bundleId) { return storage.verifyStoredContent(bundleId); };
  wrapped.writeBundle = async function (bundleId, sourceDir) {
    var out = await storage.writeBundle(bundleId, sourceDir);
    var stored = path.join(storeRoot, bundleId, "bundle.tar");
    var bytes = fs.readFileSync(stored);
    fs.writeFileSync(stored, bytes.subarray(0, Math.max(0, bytes.length - 64)));
    return out;
  };
  return wrapped;
}

function _storage(root, recipient) {
  return b.backup.bundleAdapterStorage({
    adapter:        b.backup.bundleAdapterStorage.fsAdapter({ root: root }),
    format:         "tar",
    cryptoStrategy: "recipient",
    recipient:      recipient,
  });
}

async function testAPublicKeyOnlyRecipientBackupCompletes() {
  var keys = b.crypto.generateEncryptionKeyPair();
  var publicOnly = { publicKey: keys.publicKey, ecPublicKey: keys.ecPublicKey };

  var root = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-readback-recipient-"));
  try {
    var dataDir = path.join(root, "data");
    fs.mkdirSync(dataDir, { recursive: true });
    fs.writeFileSync(path.join(dataDir, "db.enc"), "DB-BYTES");

    var storeRoot = path.join(root, "store");
    var storage = _storage(storeRoot, publicOnly);
    check("a public-key-only recipient backend reports it cannot read back",
          storage.canReadBundle === false, String(storage.canReadBundle));

    var result = await b.backup.create({
      dataDir:      dataDir,
      storage:      storage,
      passphrase:   "readback-recipient-passphrase-1",
      files:        [{ relativePath: "db.enc", kind: "raw", required: true }],
      vaultKeyJson: '{"vault":"x"}',
      audit:        false,
      retention:    { keep: 2 },
    }).run();

    check("the backup completes", typeof result.bundleId === "string", String(result.bundleId));
    check("the result says the stored bytes were compared with what was written",
          result.verifiedBy === "stored-content", String(result.verifiedBy));
    check("retention ran, because the check was content-level",
          result.retentionSkipped === undefined && Array.isArray(result.retentionPurged),
          JSON.stringify({ skipped: result.retentionSkipped, purged: result.retentionPurged }));
    check("the bundle is still in storage", (await storage.hasBundle(result.bundleId)) === true);

    // A corrupt stored payload is caught without the private key.
    var corrupt = await b.backup.create({
      dataDir:      dataDir,
      storage:      _corruptingStorage(_storage(path.join(root, "store-bad"), publicOnly),
                                       path.join(root, "store-bad")),
      passphrase:   "readback-recipient-passphrase-1",
      files:        [{ relativePath: "db.enc", kind: "raw", required: true }],
      vaultKeyJson: '{"vault":"x"}',
      audit:        false,
    }).run().then(function () { return null; }, function (e) { return e; });
    check("a truncated stored payload fails verification",
          corrupt !== null && corrupt.code === "backup/verify-after-write-failed",
          corrupt && (corrupt.code + " " + corrupt.message.slice(0, 90)));

    // The bundle a host with both keys writes is still read back and compared.
    var bothRoot = path.join(root, "store-both");
    var bothStorage = _storage(bothRoot, keys);
    check("a backend holding the private key reads back",
          bothStorage.canReadBundle === true, String(bothStorage.canReadBundle));
    var bothResult = await b.backup.create({
      dataDir:      dataDir,
      storage:      bothStorage,
      passphrase:   "readback-recipient-passphrase-1",
      files:        [{ relativePath: "db.enc", kind: "raw", required: true }],
      vaultKeyJson: '{"vault":"x"}',
      audit:        false,
    }).run();
    check("that result says the bundle was read back",
          bothResult.verifiedBy === "readback", String(bothResult.verifiedBy));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

function testTheCapabilityFollowsWhatUnwrapAccepts() {
  // The capability is read off b.archive.canUnwrapFor, so every recipient
  // shape unwrap() accepts is read back byte for byte rather than skipped:
  // the static-key pair, the peer-certificate pair, and the tenant path
  // whose key the host holds in its own vault.
  var keys = b.crypto.generateEncryptionKeyPair();
  var wrong = [];
  [
    { name: "static key pair", recipient: keys, want: true },
    { name: "peer certificate pair", recipient: { certPrivateKey: "c", kemSecret: "k" }, want: true },
    { name: "tenant", recipient: "tenant", want: true },
    { name: "public material only",
      recipient: { publicKey: keys.publicKey, ecPublicKey: keys.ecPublicKey }, want: false },
    { name: "peer certificate public half",
      recipient: { peerCertDer: "d", peerKemPubkey: "p" }, want: false },
    { name: "nothing", recipient: null, want: false },
  ].forEach(function (row) {
    var got = b.archive.canUnwrapFor(row.recipient);
    if (got !== row.want) wrong.push(row.name + " -> " + got);
  });
  check("the readback capability follows what unwrap accepts" +
        (wrong.length ? " (" + wrong.join("; ") + ")" : ""), wrong.length === 0);
}

async function testPresenceOnlyVerificationDoesNotRunRetention() {
  // A storage that can neither read its bundles back nor compare the bytes
  // it stored proves only that a key exists. Deleting an older bundle on
  // that basis could leave nothing but a corrupt one, so retention is left
  // undone and the result says why.
  var root = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-presence-only-"));
  try {
    var dataDir = path.join(root, "data");
    fs.mkdirSync(dataDir, { recursive: true });
    fs.writeFileSync(path.join(dataDir, "db.enc"), "DB-BYTES");

    var disk = b.backup.diskStorage({ root: path.join(root, "store") });
    var presenceOnly = Object.create(null);
    Object.keys(disk).forEach(function (k) { presenceOnly[k] = disk[k]; });
    presenceOnly.canReadBundle = false;                  // and no verifyStoredContent

    var engine = b.backup.create({
      dataDir:      dataDir,
      storage:      presenceOnly,
      passphrase:   "presence-only-passphrase-123456",
      files:        [{ relativePath: "db.enc", kind: "raw", required: true }],
      vaultKeyJson: '{"vault":"x"}',
      audit:        false,
      retention:    { keep: 1 },
    });
    var first = await engine.run();
    var firstAt = Date.now();
    await helpers.waitUntil(function () { return Date.now() > firstAt; },
      { timeoutMs: 1000, label: "presence-only: clock past the first bundle's millisecond" });
    var second = await engine.run();

    check("verification falls back to presence when nothing better is offered",
          second.verifiedBy === "presence", String(second.verifiedBy));
    check("retention did not run", Array.isArray(second.retentionPurged) === false &&
          typeof second.retentionSkipped === "string", JSON.stringify({
            purged: second.retentionPurged, skipped: (second.retentionSkipped || "").slice(0, 40),
          }));
    var listed = (await presenceOnly.listBundles()).map(function (e) { return e.bundleId; });
    check("the older bundle is still there under keep: 1",
          listed.indexOf(first.bundleId) !== -1 && listed.indexOf(second.bundleId) !== -1,
          listed.join(","));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

async function testASlowUploadStillVerifies() {
  // A backup whose upload outlasts the heartbeat interval beats again while
  // storage is copying. A marker written inside the staged bytes would then
  // differ from the copy and fail the read-back comparison, deleting an
  // intact bundle; the marker sits beside the directory instead.
  var root = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-slow-upload-"));
  try {
    var dataDir = path.join(root, "data");
    fs.mkdirSync(dataDir, { recursive: true });
    fs.writeFileSync(path.join(dataDir, "db.enc"), "DB-BYTES");

    var disk = b.backup.diskStorage({ root: path.join(root, "store") });
    var slow = Object.create(null);
    Object.keys(disk).forEach(function (k) { slow[k] = disk[k]; });
    var stagedDuringUpload = null;
    slow.writeBundle = async function (bundleId, sourceDir) {
      // The engine holds its own heartbeat across this call, so what the
      // staged directory contains here is what storage copies. A marker
      // written among those bytes would be copied into the bundle and then
      // removed from staging when the beat stops, which is the difference
      // the read-back comparison reported.
      stagedDuringUpload = fs.readdirSync(sourceDir).sort();
      return disk.writeBundle(bundleId, sourceDir);
    };

    var result = await b.backup.create({
      dataDir:      dataDir,
      storage:      slow,
      passphrase:   "slow-upload-passphrase-123456",
      files:        [{ relativePath: "db.enc", kind: "raw", required: true }],
      vaultKeyJson: '{"vault":"x"}',
      audit:        false,
    }).run();
    check("a backup whose upload holds a heartbeat still verifies",
          result.verifiedBy === "readback" && (await slow.hasBundle(result.bundleId)) === true,
          String(result.verifiedBy));
    check("the heartbeat left no marker among the bytes storage copied",
          stagedDuringUpload !== null &&
          stagedDuringUpload.every(function (n) { return n.indexOf(".active") === -1 &&
            n.indexOf(".blamejs-active") === -1; }),
          JSON.stringify(stagedDuringUpload));
    check("and none reached the stored bundle",
          fs.readdirSync(path.join(root, "store", result.bundleId)).every(function (n) {
            return n.indexOf("active") === -1;
          }),
          fs.readdirSync(path.join(root, "store", result.bundleId)).join(","));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

async function run() {
  testTheCapabilityFollowsWhatUnwrapAccepts();
  await testASlowUploadStillVerifies();
  await testPresenceOnlyVerificationDoesNotRunRetention();
  await testAPublicKeyOnlyRecipientBackupCompletes();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[backup-readback-recipient] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
