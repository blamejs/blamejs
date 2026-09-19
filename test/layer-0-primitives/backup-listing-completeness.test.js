// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A bundle is listed only when it holds everything a restore needs.
 *
 * Listing is not a display question. Retention keeps the newest N bundles a
 * backend lists, so a bundle that is listed but cannot be restored occupies a
 * keep slot, and the next successful backup deletes an older bundle that
 * could have been restored. Every way of being listed while unrestorable is
 * therefore a way of losing the last good copy.
 *
 * Four such ways existed, and each was a different predicate answering the
 * same question:
 *
 *   - a `manifest.json` that would not parse was caught and the bundle
 *     reported complete anyway, so a truncated or over-limit manifest was
 *     indistinguishable from a good one;
 *   - `statSync` follows symbolic links, so a symlink standing in for an
 *     encrypted blob passed the size check, while the backend's own
 *     `readBundle` skips symlinks and hands back a copy with the blob
 *     missing;
 *   - a manifest declaring `encryptedSize: 0` skipped size validation
 *     entirely, although an AEAD blob always carries a nonce and a tag, so
 *     zero cannot decrypt;
 *   - `bundleAdapterStorage` listed any key set containing `manifest.json`
 *     without checking that the files that manifest declares are present.
 *
 * The four now share one predicate, which the disk backend and the adapter
 * backend each feed with their own facts.
 *
 * The adapter's facts come from `statKey`, which is what bounds the work: a
 * manifest is operator data of unknown size, and an object store hands over
 * whatever is under the key, so the declared size is checked before the
 * object is fetched. An adapter that offers no `statKey` cannot learn a size
 * short of downloading, and keeps the older presence-only answer rather than
 * reading without a bound on every listing.
 */

var fs      = require("fs");
var os      = require("os");
var path    = require("path");
var helpers = require("../helpers");
var check   = helpers.check;
var b       = helpers.b;

var PASSPHRASE = "backup-listing-completeness-passphrase-1";

async function _makeBundle(root) {
  var dataDir = path.join(root, "data");
  fs.mkdirSync(dataDir, { recursive: true });
  fs.writeFileSync(path.join(dataDir, "db.enc"), "DB-BYTES-DB-BYTES-DB-BYTES");
  var storeRoot = path.join(root, "store");
  var disk = b.backup.diskStorage({ root: storeRoot });
  var result = await b.backup.create({
    dataDir:      dataDir,
    storage:      disk,
    passphrase:   PASSPHRASE,
    files:        [{ relativePath: "db.enc", kind: "raw", required: true }],
    vaultKeyJson: '{"vault":"x"}',
    audit:        false,
  }).run();
  return { disk: disk, storeRoot: storeRoot, bundleId: result.bundleId,
           bundleDir: path.join(storeRoot, result.bundleId) };
}

function _manifestOf(bundleDir) {
  return JSON.parse(fs.readFileSync(path.join(bundleDir, "manifest.json"), "utf8"));
}

function _blobPathOf(bundleDir) {
  var manifest = _manifestOf(bundleDir);
  return path.join(bundleDir, manifest.files[0].encryptedPath);
}

async function _isListed(disk, bundleId) {
  var listed = await disk.listBundles();
  for (var i = 0; i < listed.length; i += 1) {
    if (listed[i].bundleId === bundleId) return true;
  }
  return false;
}

async function _withBundle(label, damage) {
  var root = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-listing-"));
  try {
    var made = await _makeBundle(root);
    check(label + ": the undamaged bundle is listed to begin with",
          (await _isListed(made.disk, made.bundleId)) === true);
    await damage(made, root);
    check(label + ": it is no longer listed",
          (await _isListed(made.disk, made.bundleId)) === false);
    // hasBundle answers a different question: the bundle is still THERE, and
    // a restore aimed at it must say what is wrong with it rather than that
    // it does not exist. Only listing, which feeds retention's keep slots,
    // turns on restorability.
    check(label + ": but the bundle is still reported as present",
          (await made.disk.hasBundle(made.bundleId)) === true);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

async function testAManifestThatWillNotParseIsNotListed() {
  await _withBundle("unparseable manifest", function (made) {
    fs.writeFileSync(path.join(made.bundleDir, "manifest.json"), "{ truncated");
  });
}

async function testASymlinkedBlobIsNotListed() {
  // The backend's own readBundle skips symlinks, so a bundle whose blob is
  // one reads back short however well the symlink's target matches.
  var root = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-listing-link-"));
  var linked = false;
  try {
    var made = await _makeBundle(root);
    var blob = _blobPathOf(made.bundleDir);
    var real = path.join(root, "elsewhere.bin");
    fs.copyFileSync(blob, real);
    fs.rmSync(blob);
    // Creating a symlink needs a privilege Windows withholds by default. The
    // case is a real one on every platform that has them, so it runs where
    // it can rather than being recorded as a check that passed.
    try { fs.symlinkSync(real, blob); linked = true; }
    catch (_e) { linked = false; }
    if (!linked) return;
    check("symlinked blob: the link resolves to bytes of the declared size",
          fs.statSync(blob).size === fs.lstatSync(real).size);
    check("symlinked blob: it is not listed",
          (await _isListed(made.disk, made.bundleId)) === false);
    check("symlinked blob: but the bundle is still reported as present",
          (await made.disk.hasBundle(made.bundleId)) === true);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

async function testAZeroDeclaredEncryptedSizeIsNotListed() {
  await _withBundle("zero encryptedSize", function (made) {
    var manifestPath = path.join(made.bundleDir, "manifest.json");
    var manifest = _manifestOf(made.bundleDir);
    manifest.files[0].encryptedSize = 0;
    fs.writeFileSync(manifestPath, JSON.stringify(manifest));
  });
}

async function testADeclaredBlobOfTheWrongSizeIsNotListed() {
  await _withBundle("size mismatch", function (made) {
    var blob = _blobPathOf(made.bundleDir);
    fs.appendFileSync(blob, "EXTRA");
  });
}

async function testAMissingBlobIsNotListed() {
  await _withBundle("missing blob", function (made) {
    fs.rmSync(_blobPathOf(made.bundleDir));
  });
}

async function testTheAdapterListingChecksTheManifestsDeclaredKeys() {
  // bundleAdapterStorage answers the same question from a key listing rather
  // than a filesystem, and was answering it from the presence of
  // manifest.json alone.
  var root = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-listing-adapter-"));
  try {
    var made = await _makeBundle(root);
    var manifest = _manifestOf(made.bundleDir);
    var blobKey = made.bundleId + "/" + manifest.files[0].encryptedPath;
    var manifestBytes = fs.readFileSync(path.join(made.bundleDir, "manifest.json"));
    var blobBytes = fs.readFileSync(_blobPathOf(made.bundleDir));

    var files = new Map();
    files.set(made.bundleId + "/manifest.json", manifestBytes);
    files.set(blobKey, blobBytes);

    var adapter = {
      async listKeys() { return Array.from(files.keys()); },
      async readFile(key) {
        if (!files.has(key)) throw new Error("no such key: " + key);
        return files.get(key);
      },
      async writeFile(key, bytes) { files.set(key, bytes); },
      async deleteKey(key) { files.delete(key); },
      async hasKey(key) { return files.has(key); },
      async statKey(key) {
        return files.has(key) ? { size: files.get(key).length, mtimeMs: Date.now() } : null;
      },
    };
    var store = b.backup.bundleAdapterStorage({ adapter: adapter, format: "directory" });

    var before = await store.listBundles();
    check("adapter: the complete bundle is listed", before.length === 1 &&
          before[0].bundleId === made.bundleId, JSON.stringify(before));

    files.delete(blobKey);
    var after = await store.listBundles();
    check("adapter: a bundle missing a declared blob is not listed",
          after.length === 0, JSON.stringify(after));

    // An oversized manifest must be excluded on its declared size, before
    // the object is fetched: a listing that downloads whatever an object
    // store holds under that key can be made to exhaust memory by a bundle
    // it is about to reject anyway.
    var fetched = [];
    var counting = {
      async listKeys() { return Array.from(files.keys()); },
      async readFile(key) {
        fetched.push(key);
        if (!files.has(key)) throw new Error("no such key: " + key);
        return files.get(key);
      },
      async writeFile(key, bytes) { files.set(key, bytes); },
      async deleteKey(key) { files.delete(key); },
      async hasKey(key) { return files.has(key); },
      async statKey(key) {
        if (!files.has(key)) return null;
        var size = key === made.bundleId + "/manifest.json"
          ? b.backupManifest.MAX_MANIFEST_BYTES + 1
          : files.get(key).length;
        return { size: size, mtimeMs: Date.now() };
      },
    };
    files.set(blobKey, blobBytes);
    var bounded = b.backup.bundleAdapterStorage({ adapter: counting, format: "directory" });
    var oversizeListed = await bounded.listBundles();
    check("adapter: a manifest above the limit is not listed",
          oversizeListed.length === 0, JSON.stringify(oversizeListed));
    check("adapter: and its bytes were never fetched",
          fetched.indexOf(made.bundleId + "/manifest.json") === -1,
          JSON.stringify(fetched));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

async function testARestoreAimedAtADamagedBundleSaysWhatIsWrongWithIt() {
  // This is why the two questions stay apart. restore asks hasBundle to tell
  // "no such bundle" from "this bundle is broken", and reports the precise
  // refusal only for the second. A hasBundle that answered restorability
  // would collapse both into bundle-not-found, which is the less useful
  // answer and, for a bundle that is sitting right there, the untrue one.
  var root = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-listing-diag-"));
  try {
    var made = await _makeBundle(root);
    fs.writeFileSync(path.join(made.bundleDir, "manifest.json"), "{ truncated");

    var restore = b.restore.create({
      dataDir:      path.join(root, "data"),
      storage:      made.disk,
      passphrase:   PASSPHRASE,
      stagingRoot:  path.join(root, "staging"),
      rollbackRoot: path.join(root, "rollbacks"),
      audit:        false,
    });
    var threw = null;
    try { await restore.run({ bundleId: made.bundleId }); }
    catch (e) { threw = e; }
    check("a restore aimed at the damaged bundle is refused",
          threw !== null, threw && threw.code);
    check("and says what is wrong with it rather than that it does not exist",
          threw !== null && threw.code !== "restore/bundle-not-found",
          threw && (threw.code + ": " + threw.message));

    var absent = null;
    try { await restore.run({ bundleId: "2026-01-01T00-00-00-000Z-abcdef12" }); }
    catch (e) { absent = e; }
    check("while a bundle that really is absent still reads as not found",
          absent !== null && absent.code === "restore/bundle-not-found",
          absent && absent.code);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

async function run() {
  await testAManifestThatWillNotParseIsNotListed();
  await testASymlinkedBlobIsNotListed();
  await testAZeroDeclaredEncryptedSizeIsNotListed();
  await testADeclaredBlobOfTheWrongSizeIsNotListed();
  await testAMissingBlobIsNotListed();
  await testTheAdapterListingChecksTheManifestsDeclaredKeys();
  await testARestoreAimedAtADamagedBundleSaysWhatIsWrongWithIt();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[backup-listing-completeness] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
