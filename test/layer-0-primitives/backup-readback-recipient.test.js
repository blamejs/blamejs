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
    check("the result says the bundle was verified by presence",
          result.verifiedBy === "presence", String(result.verifiedBy));
    check("the bundle is still in storage", (await storage.hasBundle(result.bundleId)) === true);

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

async function run() {
  testTheCapabilityFollowsWhatUnwrapAccepts();
  await testAPublicKeyOnlyRecipientBackupCompletes();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[backup-readback-recipient] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
