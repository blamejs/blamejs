// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.configDrift verifies its sidecar under the live b.auditSign key only,
 * never under the publicKeyPem the sidecar carries and never under a key the
 * unsealed audit-sign.pubkeys.json history lists. A sidecar someone rewrote
 * and re-signed with a fresh key of their own is reported as tampered, also
 * when they filed that key in the history file. A sidecar signed before a key
 * rotation is reported as tampered until resign() is handed the previous
 * public key, and resign() refuses a sidecar that key did not sign.
 */

var fs         = require("node:fs");
var os         = require("node:os");
var path       = require("node:path");
var nodeCrypto = require("node:crypto");
var helpers    = require("../helpers");
var b          = helpers.b;
var check      = helpers.check;
var canonical  = require("../../lib/canonical-json");

var SNAPSHOT = { allowedOrigins: ["https://app.example.com"], csp: "default-src 'self'" };

function _tmp(prefix) { return fs.mkdtempSync(path.join(os.tmpdir(), prefix)); }

async function _withAuditSign(fn) {
  var keyDir = _tmp("config-drift-pin-key-");
  var dataDir = _tmp("config-drift-pin-data-");
  b.auditSign._resetForTest();
  await b.auditSign.init({ dataDir: keyDir, mode: "plaintext", algorithm: "ml-dsa-65" });
  try { await fn(dataDir); }
  finally {
    b.auditSign._resetForTest();
    fs.rmSync(keyDir, { recursive: true, force: true });
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
}

// Rewrites the sidecar with `snapshot`, signed by a fresh ML-DSA-65 key whose
// public half is written into the sidecar, the way anyone who can write the
// data directory can.
function _resignWithFreshKey(sidecarPath, snapshot) {
  var parsed = JSON.parse(fs.readFileSync(sidecarPath, "utf8"));
  var pair = nodeCrypto.generateKeyPairSync("ml-dsa-65");
  var digestHex = b.crypto.sha3Hash(canonical.stringify(snapshot));
  parsed.snapshot = snapshot;
  parsed.digestHex = digestHex;
  parsed.signatureBase64 = nodeCrypto.sign(null, Buffer.from(digestHex, "utf8"), pair.privateKey).toString("base64");
  parsed.publicKeyPem = pair.publicKey.export({ type: "spki", format: "pem" });
  fs.writeFileSync(sidecarPath, JSON.stringify(parsed));
}

async function testSidecarResignedWithFreshKeyIsTamper() {
  await _withAuditSign(async function (dataDir) {
    var drift = b.configDrift.create({ dataDir: dataDir, audit: false });
    await drift.checkpoint(SNAPSHOT);
    var own = drift.read();
    check("config-drift signer pin control: a sidecar signed by b.auditSign verifies",
          own && own.verified === true && own.tamperReason === null);

    var attacker = { allowedOrigins: ["https://app.example.com", "https://attacker.example"], csp: "default-src *" };
    _resignWithFreshKey(drift.sidecarPath, attacker);
    var forged = drift.read();
    check("config-drift signer pin: read() reports a sidecar re-signed with a fresh key as unverified",
          forged && forged.verified === false);
    check("config-drift signer pin: the tamper reason names the untrusted signer",
          forged && forged.tamperReason === "signer-untrusted");
    var next = await drift.checkpoint(attacker);
    check("config-drift signer pin: checkpoint() reports the re-signed sidecar as tamper and leaves it",
          next.tamper === true && next.signed === false && next.reason === "signer-untrusted");
  });
}

// Files publicPem in the audit-sign data directory's public-key history, the
// way anyone who can write that directory can.
function _plantHistoryEntry(dir, publicPem) {
  var historyPath = path.join(dir, "audit-sign.pubkeys.json");
  var list = fs.existsSync(historyPath) ? JSON.parse(fs.readFileSync(historyPath, "utf8")) : [];
  list.push({ fingerprint: b.auditSign.fingerprintOf(publicPem), publicKey: publicPem });
  fs.writeFileSync(historyPath, JSON.stringify(list));
}

async function testForgedSidecarWithPlantedHistoryEntryIsTamper() {
  var dir = _tmp("config-drift-pin-shared-");
  b.auditSign._resetForTest();
  await b.auditSign.init({ dataDir: dir, mode: "plaintext", algorithm: "ml-dsa-65" });
  try {
    var drift = b.configDrift.create({ dataDir: dir, audit: false });
    await drift.checkpoint(SNAPSHOT);
    check("config-drift history pin control: a sidecar signed by b.auditSign in the audit-sign directory verifies",
          drift.read().verified === true);

    var attacker = { allowedOrigins: ["https://attacker.example"], csp: "default-src *" };
    _resignWithFreshKey(drift.sidecarPath, attacker);
    var forgedPem = JSON.parse(fs.readFileSync(drift.sidecarPath, "utf8")).publicKeyPem;
    _plantHistoryEntry(dir, forgedPem);
    check("config-drift history pin: the planted entry resolves through getPublicKeyByFingerprint",
          b.auditSign.getPublicKeyByFingerprint(b.auditSign.fingerprintOf(forgedPem)) === forgedPem);
    var forged = drift.read();
    check("config-drift history pin: read() reports a sidecar signed by a key only the history file lists as unverified",
          forged && forged.verified === false && forged.tamperReason === "signer-untrusted");
    var next = await drift.checkpoint(attacker);
    check("config-drift history pin: checkpoint() of the forged config reports tamper and does not re-sign it",
          next.tamper === true && next.signed === false && next.reason === "signer-untrusted");
    check("config-drift history pin: the sidecar still carries the forged key after checkpoint()",
          JSON.parse(fs.readFileSync(drift.sidecarPath, "utf8")).publicKeyPem === forgedPem);
  } finally {
    b.auditSign._resetForTest();
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

async function _code(fn) {
  try { await fn(); return "NO-THROW"; } catch (e) { return e.code || e.message; }
}

async function testSidecarSignedBeforeRotationNeedsResign() {
  await _withAuditSign(async function (dataDir) {
    var drift = b.configDrift.create({ dataDir: dataDir, audit: false });
    await drift.checkpoint(SNAPSHOT);
    var capturedAt = drift.read().capturedAt;
    var rotation = await b.auditSign.rotateSigningKey();
    var after = drift.read();
    check("config-drift rotation: a sidecar signed under the rotated-out key is unverified",
          after && after.verified === false && after.tamperReason === "signer-untrusted");
    var stalled = await drift.checkpoint(SNAPSHOT);
    check("config-drift rotation: checkpoint() before resign() reports tamper",
          stalled.tamper === true && stalled.signed === false);

    var stranger = nodeCrypto.generateKeyPairSync("ml-dsa-65").publicKey.export({ type: "spki", format: "pem" });
    check("config-drift rotation: resign() refuses a previous key that did not sign the sidecar",
          (await _code(function () { return drift.resign(stranger); })) === "config-drift/not-resignable");
    check("config-drift rotation: resign() refuses a previous key that is not a string",
          (await _code(function () { return drift.resign(null); })) === "config-drift/bad-opt");

    var done = await drift.resign(rotation.previousPublicKey);
    check("config-drift rotation control: resign() with the previous public key re-signs the sidecar",
          done && done.resigned === true);
    var resigned = drift.read();
    check("config-drift rotation control: the re-signed sidecar verifies and keeps its capturedAt",
          resigned.verified === true && resigned.capturedAt === capturedAt);
    var again = await drift.resign(rotation.previousPublicKey);
    check("config-drift rotation control: resign() on a sidecar the live key signed changes nothing",
          again.resigned === false && again.reason === "already-current");
    var next = await drift.checkpoint(SNAPSHOT);
    check("config-drift rotation control: checkpoint() after resign() is not tamper",
          next.tamper === false && next.signed === true);
  });
}

async function testResignRefusesForgedSidecar() {
  await _withAuditSign(async function (dataDir) {
    var drift = b.configDrift.create({ dataDir: dataDir, audit: false });
    await drift.checkpoint(SNAPSHOT);
    var rotation = await b.auditSign.rotateSigningKey();
    _resignWithFreshKey(drift.sidecarPath, { csp: "default-src *" });
    check("config-drift rotation: resign() with the real previous key refuses a sidecar a fresh key signed",
          (await _code(function () { return drift.resign(rotation.previousPublicKey); })) ===
            "config-drift/not-resignable");
    var tampered = JSON.parse(fs.readFileSync(drift.sidecarPath, "utf8"));
    tampered.publicKeyPem = rotation.previousPublicKey;
    tampered.snapshot = { csp: "default-src *" };
    fs.writeFileSync(drift.sidecarPath, JSON.stringify(tampered));
    check("config-drift rotation: resign() refuses a sidecar whose signature the previous key does not verify",
          (await _code(function () { return drift.resign(rotation.previousPublicKey); })) ===
            "config-drift/not-resignable");
    fs.rmSync(drift.sidecarPath);
    var none = await drift.resign(rotation.previousPublicKey);
    check("config-drift rotation: resign() without a sidecar reports no-sidecar",
          none.resigned === false && none.reason === "no-sidecar");
  });
}

async function testReadBeforeAuditSignInit() {
  var dataDir = _tmp("config-drift-pin-noinit-");
  try {
    await _withAuditSign(async function (keyedDataDir) {
      var drift = b.configDrift.create({ dataDir: keyedDataDir, audit: false });
      await drift.checkpoint(SNAPSHOT);
      fs.copyFileSync(drift.sidecarPath, path.join(dataDir, path.basename(drift.sidecarPath)));
    });
    var cold = b.configDrift.create({ dataDir: dataDir, audit: false });
    var code = null;
    try { cold.read(); } catch (e) { code = e.code; }
    check("config-drift signer pin: read() before b.auditSign.init() throws audit-sign/not-initialized",
          code === "audit-sign/not-initialized");
  } finally {
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
}

async function run() {
  await testSidecarResignedWithFreshKeyIsTamper();
  await testForgedSidecarWithPlantedHistoryEntryIsTamper();
  await testSidecarSignedBeforeRotationNeedsResign();
  await testResignRefusesForgedSidecar();
  await testReadBeforeAuditSignInit();
}

module.exports = {
  run:                                                run,
  testSidecarResignedWithFreshKeyIsTamper:            testSidecarResignedWithFreshKeyIsTamper,
  testForgedSidecarWithPlantedHistoryEntryIsTamper:   testForgedSidecarWithPlantedHistoryEntryIsTamper,
  testSidecarSignedBeforeRotationNeedsResign:         testSidecarSignedBeforeRotationNeedsResign,
  testResignRefusesForgedSidecar:                     testResignRefusesForgedSidecar,
  testReadBeforeAuditSignInit:                        testReadBeforeAuditSignInit,
};

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
