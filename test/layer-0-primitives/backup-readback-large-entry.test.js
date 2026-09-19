// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A bundle whose largest file is bigger than the archive reader's default
 * per-entry cap still backs up.
 *
 * b.backup.run() reads each bundle back from storage and compares it with
 * what it wrote before retention deletes anything. The archive readers
 * default to 128 MiB per entry, while b.backup.bundleAdapterStorage accepts
 * bundles up to maxBundleBytes (8 GiB by default), so a database file past
 * that cap made the read-back fail and the run delete the bundle it had
 * just stored, leaving no backup at all. The read path now carries the
 * writer's own limits.
 *
 * The fixture writes a file past the reader's default on purpose: a smaller
 * one passes whether or not the limits are threaded through, which is how
 * the first version of this test managed to prove nothing.
 */

var fs      = require("fs");
var os      = require("os");
var path    = require("path");
var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

// The writer's entry ceiling is not exported: it is read out of the
// refusal message the writer itself produces, so the number under test is
// the one the code uses rather than a copy of it.
function _writerEntryCeiling() {
  var source = fs.readFileSync(
    path.resolve(__dirname, "..", "..", "lib", "backup", "index.js"), "utf8");
  var declared = /var MAX_BUNDLE_ENTRIES = (\d+);/.exec(source);
  return declared === null ? null : Number(declared[1]);
}

var READER_DEFAULT_ENTRY_CAP = b.constants.BYTES.mib(128);
var FIXTURE_BYTES            = b.constants.BYTES.mib(130);

async function testAnEntryOverTheReaderDefaultIsReadBack() {
  var root = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-readback-large-"));
  try {
    var dataDir = path.join(root, "data");
    fs.mkdirSync(dataDir, { recursive: true });

    // Zero bytes keep the write cheap. The format is "tar", which does not
    // compress, so the stored entry is the full size on the wire.
    var dbPath = path.join(dataDir, "db.enc");
    var handle = fs.openSync(dbPath, "w");
    try {
      var chunk = Buffer.alloc(b.constants.BYTES.mib(8));
      var written = 0;
      while (written < FIXTURE_BYTES) {
        var take = Math.min(chunk.length, FIXTURE_BYTES - written);
        fs.writeSync(handle, chunk, 0, take);
        written += take;
      }
    } finally { fs.closeSync(handle); }
    check("the fixture file is larger than the reader's default per-entry cap",
          fs.statSync(dbPath).size > READER_DEFAULT_ENTRY_CAP, String(fs.statSync(dbPath).size));

    var storage = b.backup.bundleAdapterStorage({
      adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: path.join(root, "store") }),
      format:  "tar",
    });

    var result = await b.backup.create({
      dataDir:      dataDir,
      storage:      storage,
      passphrase:   "readback-large-entry-passphrase",
      files:        [{ relativePath: "db.enc", kind: "raw", required: true }],
      vaultKeyJson: '{"vault":"x"}',
      audit:        false,
      retention:    { keep: 2 },
    }).run();

    check("the backup completes", typeof result.bundleId === "string", String(result.bundleId));
    check("the bundle was read back, not merely counted",
          result.verifiedBy === "readback", String(result.verifiedBy));
    check("the bundle is still in storage", (await storage.hasBundle(result.bundleId)) === true);

    var out = path.join(root, "read-back");
    await storage.readBundle(result.bundleId, out);
    var manifest = JSON.parse(fs.readFileSync(path.join(out, "manifest.json"), "utf8"));
    check("the read-back manifest lists the file", manifest.files.length === 1,
          String(manifest.files.length));
    check("the read-back blob carries every byte",
          fs.statSync(path.join(out, manifest.files[0].encryptedPath)).size ===
            manifest.files[0].encryptedSize,
          fs.statSync(path.join(out, manifest.files[0].encryptedPath)).size + " vs " +
            manifest.files[0].encryptedSize);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

async function testABundleNearTheWriterLimitIsReadBack() {
  // maxBundleBytes bounds the ARCHIVE, framing included, so a bundle the
  // writer accepts is one the reader accepts. A cap that leaves room for
  // the framing stores and reads back; the same payload under a cap that
  // does not is refused at write, and both formats answer the same way.
  var root = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-readback-tight-"));
  try {
    var dataDir = path.join(root, "data");
    fs.mkdirSync(dataDir, { recursive: true });
    fs.writeFileSync(path.join(dataDir, "db.enc"), Buffer.alloc(800, 0x61));
    var files = [{ relativePath: "db.enc", kind: "raw", required: true }];

    var formats = ["tar", "tar.gz"];
    for (var fi = 0; fi < formats.length; fi += 1) {
      var format = formats[fi];
      var roomy = b.backup.bundleAdapterStorage({
        adapter: b.backup.bundleAdapterStorage.fsAdapter({
          root: path.join(root, "ok-" + format),
        }),
        format:         format,
        maxBundleBytes: 64 * 1024,
      });
      var ok = await b.backup.create({
        dataDir:      dataDir,
        storage:      roomy,
        passphrase:   "readback-tight-limit-passphrase",
        files:        files,
        vaultKeyJson: '{"vault":"x"}',
        audit:        false,
      }).run();
      check(format + ": a bundle under a cap that allows the framing reads back",
            ok.verifiedBy === "readback" && (await roomy.hasBundle(ok.bundleId)) === true,
            String(ok.verifiedBy));

      var tight = b.backup.bundleAdapterStorage({
        adapter: b.backup.bundleAdapterStorage.fsAdapter({
          root: path.join(root, "tight-" + format),
        }),
        format:         format,
        maxBundleBytes: 1800,
      });
      var refused = null;
      try {
        await b.backup.create({
          dataDir:      dataDir,
          storage:      tight,
          passphrase:   "readback-tight-limit-passphrase",
          files:        files,
          vaultKeyJson: '{"vault":"x"}',
          audit:        false,
        }).run();
      } catch (e) { refused = e; }
      check(format + ": a cap the framing does not fit is refused at write, not at read-back",
            refused !== null && /exceeds maxBundleBytes/.test(refused.message),
            refused && refused.message.slice(0, 110));
      check(format + ": nothing was left in storage by the refusal",
            (await tight.listBundles()).length === 0);
    }
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

async function testManySmallFilesAreRefusedAtWriteRatherThanAtReadback() {
  // Framing can cost more than payload: 100 empty files carry no bytes but
  // 100 headers. The writer measures the archive it built, so a bundle
  // whose framing does not fit is refused before it is stored instead of
  // being stored, failing read-back, and deleting itself.
  var root = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-readback-many-"));
  try {
    var dataDir = path.join(root, "data");
    fs.mkdirSync(dataDir, { recursive: true });
    var files = [];
    for (var i = 0; i < 100; i += 1) {
      var name = "f" + i + ".enc";
      fs.writeFileSync(path.join(dataDir, name), "");
      files.push({ relativePath: name, kind: "raw", required: true });
    }

    var storage = b.backup.bundleAdapterStorage({
      adapter:        b.backup.bundleAdapterStorage.fsAdapter({ root: path.join(root, "store") }),
      format:         "tar.gz",
      maxBundleBytes: 60000,
    });
    var refused = null;
    try {
      await b.backup.create({
        dataDir:      dataDir,
        storage:      storage,
        passphrase:   "readback-many-files-passphrase",
        files:        files,
        vaultKeyJson: '{"vault":"x"}',
        audit:        false,
      }).run();
    } catch (e) { refused = e; }
    check("a bundle whose framing does not fit is refused at write",
          refused !== null && refused.code === "backup/storage-write-failed" &&
          /bundle-too-large|exceeds maxBundleBytes/.test(refused.message),
          refused && (refused.code + " " + refused.message.slice(0, 110)));
    check("the refusal names the framing cost, not only the payload size",
          refused !== null && /512-byte header/.test(refused.message),
          refused && refused.message.slice(0, 160));

    // The same bundle stores and reads back when the cap allows the framing.
    var roomy = b.backup.bundleAdapterStorage({
      adapter:        b.backup.bundleAdapterStorage.fsAdapter({ root: path.join(root, "store-ok") }),
      format:         "tar.gz",
      maxBundleBytes: 512 * 1024,
    });
    var ok = await b.backup.create({
      dataDir:      dataDir,
      storage:      roomy,
      passphrase:   "readback-many-files-passphrase",
      files:        files,
      vaultKeyJson: '{"vault":"x"}',
      audit:        false,
    }).run();
    check("100 files store and read back under a cap that allows the framing",
          ok.verifiedBy === "readback" && (await roomy.hasBundle(ok.bundleId)) === true,
          String(ok.verifiedBy));

    // The entry COUNT is bounded the same way the byte size is: the writer
    // refuses more entries than the tar reader accepts, rather than storing
    // them and failing the read-back that deletes the bundle. Creating
    // 65,536 files to see it would cost more than it proves, so the two
    // numbers are compared where they are declared.
    var tarRead = require("../../lib/archive-tar-read.js");
    var writerCeiling = _writerEntryCeiling();
    check("the writer's entry ceiling is the number the tar reader accepts",
          writerCeiling !== null && writerCeiling === tarRead.DEFAULT_BOMB_POLICY.maxEntries,
          String(writerCeiling) + " vs " + String(tarRead.DEFAULT_BOMB_POLICY.maxEntries));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

async function run() {
  await testAnEntryOverTheReaderDefaultIsReadBack();
  await testABundleNearTheWriterLimitIsReadBack();
  await testManySmallFilesAreRefusedAtWriteRatherThanAtReadback();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[backup-readback-large-entry] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
