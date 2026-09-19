// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Backup manifest signatures are trusted by key, not by self-consistency.
 *
 * A manifest carries the public key its signature verifies under. Verifying
 * with that key alone proves only that someone signed the manifest, so a
 * writer of backup storage could edit a signed bundle (drop an entry, swap in
 * an older bundle's blob) and re-sign it with a fresh key. A signature is
 * trusted when its key is pinned by `expectedFingerprint`, or is the active or
 * a rotated audit-sign key; the key type must be one audit-sign signs with and
 * must match `signature.algorithm`. Each blob is also bound to its bundle, so
 * an unsigned bundle refuses a blob copied from another bundle.
 */

var helpers    = require("../helpers");
var b          = helpers.b;
var check      = helpers.check;
var fs         = helpers.fs;
var os         = helpers.os;
var path       = helpers.path;
var nodeCrypto = require("node:crypto");

var PASSPHRASE = Buffer.from("backup-signature-trust-passphrase-for-tests");

function _tmp(prefix) { return fs.mkdtempSync(path.join(os.tmpdir(), prefix)); }

async function _twoBundles(storageRoot, dataDir) {
  var storage = b.backup.diskStorage({ root: storageRoot });
  var engine = b.backup.create({
    dataDir: dataDir, storage: storage, passphrase: PASSPHRASE,
    files: [
      { relativePath: "db.enc",    kind: "raw", required: true },
      { relativePath: "audit.log", kind: "raw", required: true },
    ],
    vaultKeyJson: '{"version":1,"kid":"k1"}',
  });
  fs.writeFileSync(path.join(dataDir, "db.enc"), "OLD database: password-hash-before-reset");
  fs.writeFileSync(path.join(dataDir, "audit.log"), "old audit");
  var older = (await engine.run({ metadata: { reason: "older" } })).bundleId;
  // The bundle id carries the millisecond it was written, so the newer
  // bundle needs the clock to have moved to sort after this one.
  var olderAt = Date.now();
  await helpers.waitUntil(function () { return Date.now() > olderAt; },
    { timeoutMs: 1000, label: "signature trust: clock past the older bundle's millisecond" });
  fs.writeFileSync(path.join(dataDir, "db.enc"), "NEW database: password-hash-after-reset");
  fs.writeFileSync(path.join(dataDir, "audit.log"), "new audit");
  var newer = (await engine.run({ metadata: { reason: "newer" } })).bundleId;
  return { storage: storage, older: older, newer: newer };
}

function _readManifest(storageRoot, bundleId) {
  return b.backupManifest.parse(fs.readFileSync(path.join(storageRoot, bundleId, "manifest.json"), "utf8"));
}

function _writeManifest(storageRoot, bundleId, manifest) {
  fs.writeFileSync(path.join(storageRoot, bundleId, "manifest.json"), b.backupManifest.serialize(manifest));
}

// Rolls db.enc back to the older bundle's copy and drops audit.log, the edit
// the issue measured, then signs with `signer` when one is given.
function _rollBack(storageRoot, olderId, newerId, signer) {
  var older = _readManifest(storageRoot, olderId);
  var newer = _readManifest(storageRoot, newerId);
  var oldDb = older.files.filter(function (f) { return f.relativePath === "db.enc"; })[0];
  var newDb = newer.files.filter(function (f) { return f.relativePath === "db.enc"; })[0];
  fs.copyFileSync(path.join(storageRoot, olderId, oldDb.encryptedPath), path.join(storageRoot, newerId, newDb.encryptedPath));
  ["size", "encryptedSize", "checksum", "salt"].forEach(function (k) { newDb[k] = oldDb[k]; });
  newer.files = [newDb];
  if (signer) newer.signature = signer(newer);
  _writeManifest(storageRoot, newerId, newer);
}

function _signerWith(type, algorithmLabel, fingerprint) {
  var kp = nodeCrypto.generateKeyPairSync(type);
  var pem = kp.publicKey.export({ type: "spki", format: "pem" });
  return function (manifest) {
    var payload = b.backupManifest.signingPayload(manifest);
    var buf = Buffer.isBuffer(payload) ? payload : Buffer.from(payload, "utf8");
    return {
      algorithm: algorithmLabel, publicKey: pem, fingerprint: fingerprint,
      value: nodeCrypto.sign(null, buf, kp.privateKey).toString("base64"), signedAt: new Date().toISOString(),
    };
  };
}

async function _restoreCode(storage, bundleId, opts) {
  var target = _tmp("bst-restore-");
  try {
    var r = b.restore.create(Object.assign({
      dataDir: path.join(target, "data"), storage: storage, passphrase: PASSPHRASE,
    }, opts || {}));
    var summary = await r.run({ bundleId: bundleId });
    var db = fs.readFileSync(path.join(target, "data", "db.enc"), "utf8");
    return "restored " + summary.fileCount + " file(s), db.enc " + JSON.stringify(db.slice(0, 12));
  } catch (e) {
    return e.code;
  } finally {
    try { fs.rmSync(target, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  }
}

async function testSignedBundleTrustsOnlyKnownKeys() {
  var root = _tmp("bst-");
  var wrong = [];
  try {
    b.auditSign._resetForTest();
    await b.auditSign.init({ dataDir: path.join(root, "audit"), mode: "plaintext", algorithm: "ml-dsa-65" });
    var genuineFp = b.auditSign.getPublicKeyFingerprint();
    var dataDir = path.join(root, "data");
    fs.mkdirSync(dataDir);

    var CASES = [
      { label: "re-signed with an Ed25519 key", signer: _signerWith("ed25519", "ml-dsa-65", genuineFp) },
      { label: "re-signed with an Ed448 key", signer: _signerWith("ed448", "ml-dsa-65", genuineFp) },
      { label: "re-signed with a fresh ML-DSA-65 key", signer: _signerWith("ml-dsa-65", "ml-dsa-65", genuineFp) },
      { label: "re-signed with an ML-DSA-65 key labelled slh-dsa", signer: _signerWith("ml-dsa-65", "slh-dsa-shake-256f", genuineFp) },
    ];
    for (var i = 0; i < CASES.length; i += 1) {
      var storageRoot = path.join(root, "store-" + i);
      var pair = await _twoBundles(storageRoot, dataDir);
      _rollBack(storageRoot, pair.older, pair.newer, CASES[i].signer);
      var verdict = b.backup.verifyManifestSignature(path.join(storageRoot, pair.newer));
      if (verdict.ok !== false) wrong.push(CASES[i].label + ": verifyManifestSignature ok=" + verdict.ok);
      var required = await _restoreCode(pair.storage, pair.newer, { requireSignature: true });
      if (required !== "restore/bad-signature") wrong.push(CASES[i].label + ": restore requireSignature -> " + required);
      var plain = await _restoreCode(pair.storage, pair.newer);
      if (plain !== "restore/bad-signature") wrong.push(CASES[i].label + ": restore -> " + plain);
    }

    var goodRoot = path.join(root, "store-good");
    var good = await _twoBundles(goodRoot, dataDir);
    var goodVerdict = b.backup.verifyManifestSignature(path.join(goodRoot, good.newer));
    if (goodVerdict.ok !== true) wrong.push("genuine bundle: verifyManifestSignature -> " + JSON.stringify(goodVerdict));
    var goodRestore = await _restoreCode(good.storage, good.newer, { requireSignature: true });
    if (goodRestore.indexOf("restored 2 file(s)") !== 0) wrong.push("genuine bundle: restore requireSignature -> " + goodRestore);

    var relabelRoot = path.join(root, "store-relabel");
    var relabel = await _twoBundles(relabelRoot, dataDir);
    var relabelled = _readManifest(relabelRoot, relabel.newer);
    relabelled.signature.algorithm = "slh-dsa-shake-256f";
    _writeManifest(relabelRoot, relabel.newer, relabelled);
    var relabelVerdict = b.backup.verifyManifestSignature(path.join(relabelRoot, relabel.newer));
    if (relabelVerdict.ok !== false) wrong.push("genuine signature relabelled slh-dsa: verifyManifestSignature ok=" + relabelVerdict.ok);
    var relabelRestore = await _restoreCode(relabel.storage, relabel.newer, { requireSignature: true });
    if (relabelRestore !== "restore/bad-signature") wrong.push("genuine signature relabelled slh-dsa: restore requireSignature -> " + relabelRestore);
    var unverifiedRequired = await _restoreCode(good.storage, good.newer, { requireSignature: true, verifySignature: false });
    if (unverifiedRequired !== "restore/bad-opts") {
      wrong.push("requireSignature with verifySignature false -> " + unverifiedRequired);
    }

    await b.auditSign.rotateSigningKey();
    var rotated = b.backup.verifyManifestSignature(path.join(goodRoot, good.newer));
    if (rotated.ok !== true) wrong.push("bundle signed before a key rotation -> " + JSON.stringify(rotated));

    b.auditSign._resetForTest();
    var noAnchor = b.backup.verifyManifestSignature(path.join(goodRoot, good.newer));
    if (noAnchor.ok !== false || !/expectedFingerprint/.test(noAnchor.reason || "")) {
      wrong.push("no audit-sign and no pin: verifyManifestSignature -> " + JSON.stringify(noAnchor));
    }
    var pinned = b.backup.verifyManifestSignature(path.join(goodRoot, good.newer), { expectedFingerprint: genuineFp });
    if (pinned.ok !== true) wrong.push("no audit-sign, pinned: verifyManifestSignature -> " + JSON.stringify(pinned));
    var noAnchorRestore = await _restoreCode(good.storage, good.newer, { requireSignature: true });
    if (noAnchorRestore !== "restore/bad-signature") wrong.push("no audit-sign and no pin: restore requireSignature -> " + noAnchorRestore);
    var pinnedRestore = await _restoreCode(good.storage, good.newer, { requireSignature: true, expectedFingerprint: genuineFp });
    if (pinnedRestore.indexOf("restored 2 file(s)") !== 0) wrong.push("no audit-sign, pinned: restore requireSignature -> " + pinnedRestore);
  } finally {
    b.auditSign._resetForTest();
    try { fs.rmSync(root, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  }
  check("a backup manifest signature is trusted only under a pinned or audit-sign key of a supported type" +
        (wrong.length ? " (" + wrong.join("; ") + ")" : ""), wrong.length === 0);
}

async function testUnsignedBundleRefusesABlobFromAnotherBundle() {
  var root = _tmp("bst-unsigned-");
  try {
    b.auditSign._resetForTest();
    var dataDir = path.join(root, "data");
    fs.mkdirSync(dataDir);
    var storageRoot = path.join(root, "store");
    var pair = await _twoBundles(storageRoot, dataDir);
    var unsigned = _readManifest(storageRoot, pair.newer);
    _rollBack(storageRoot, pair.older, pair.newer, null);
    var code = await _restoreCode(pair.storage, pair.newer);
    check("an unsigned bundle refuses a blob copied from another bundle",
          unsigned.signature === undefined && code === "restore/decrypt-failed", JSON.stringify({ signed: !!unsigned.signature, code: code }));
  } finally {
    try { fs.rmSync(root, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  }
}

async function run() {
  await testSignedBundleTrustsOnlyKnownKeys();
  await testUnsignedBundleRefusesABlobFromAnotherBundle();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
