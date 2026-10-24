// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.agent.snapshot loads refuse a row that the loader's configuration would
 * never have written:
 *
 * - Without allowPlaintext, a row with no sealed wrapper is refused with
 *   agent-snapshot/plaintext-refused, even when its signature verifies. A
 *   backend writer can otherwise replace a sealed snapshot with the plaintext
 *   copy of the same signed envelope.
 * - With allowPlaintext, a signed plaintext row is refused under a regulated
 *   compliance posture, as an unsigned one is.
 * - Without opts.signer, a load before b.auditSign.init() throws
 *   agent-snapshot/signer-not-wired, as persist does.
 */

var fs         = require("node:fs");
var os         = require("node:os");
var path       = require("node:path");
var nodeCrypto = require("node:crypto");
var helpers    = require("../helpers");
var b          = helpers.b;
var check      = helpers.check;

function _orch() {
  return { health: function () { return Promise.resolve({ agents: [], elections: [], consumers: [] }); } };
}
function _backend() {
  var map = new Map();
  return {
    put:    function (k, v) { map.set(k, v); return Promise.resolve(); },
    get:    function (k)    { return Promise.resolve(map.get(k) || null); },
    delete: function (k)    { map.delete(k); return Promise.resolve(); },
    list:   function ()     { return Promise.resolve(Array.from(map.values())); },
  };
}
function _sealer() {
  return {
    seal:   function (plaintext) { return Buffer.from(plaintext, "utf8").toString("base64"); },
    unseal: function (value)     { return Buffer.from(value, "base64").toString("utf8"); },
  };
}
var SIGNING_PAIR = nodeCrypto.generateKeyPairSync("ed25519");
function _signer() {
  return {
    sign:         function (bytes) { return nodeCrypto.sign(null, bytes, SIGNING_PAIR.privateKey); },
    verify:       function (bytes, sig) { return nodeCrypto.verify(null, bytes, SIGNING_PAIR.publicKey, sig); },
    getPublicKey: function () { return null; },
  };
}
async function _code(p) {
  try { await p; return "NO-THROW"; } catch (e) { return e.code || e.message; }
}

async function testPlaintextCopyOfSealedSnapshotRefused() {
  var backend = _backend();
  var snapshot = b.agent.snapshot.create({
    orchestrator: _orch(), backend: backend, signer: _signer(), sealer: _sealer(),
  });
  var s = await snapshot.takeSnapshot({});
  await snapshot.persist(s);
  var loaded = await snapshot.loadById(s.snapshotId);
  check("agent-snapshot plaintext load control: the sealed, signed row loads",
        loaded && loaded.snapshotId === s.snapshotId);

  await backend.put(s.snapshotId, JSON.parse(JSON.stringify(s)));
  check("agent-snapshot plaintext load: the plaintext copy of the same signed envelope is refused",
        (await _code(snapshot.loadById(s.snapshotId))) === "agent-snapshot/plaintext-refused");
  check("agent-snapshot plaintext load: loadLatest refuses the plaintext copy too",
        (await _code(snapshot.loadLatest())) === "agent-snapshot/plaintext-refused");
}

async function testSignedPlaintextRefusedUnderRegulatedPosture() {
  var backend = _backend();
  var writer = b.agent.snapshot.create({
    orchestrator: _orch(), backend: backend, signer: _signer(), allowPlaintext: true,
  });
  var s = await writer.takeSnapshot({});
  await writer.persist(s);
  var dev = await writer.loadById(s.snapshotId);
  check("agent-snapshot plaintext load control: allowPlaintext loads a signed plaintext row with no posture",
        dev && dev.snapshotId === s.snapshotId);
  try {
    b.compliance.clear();
    b.compliance.set("hipaa");
    check("agent-snapshot plaintext load: allowPlaintext does not load a signed plaintext row under hipaa",
          (await _code(writer.loadById(s.snapshotId))) === "agent-snapshot/plaintext-refused-under-posture");
  } finally {
    b.compliance.clear();
  }
}

async function testLoadBeforeAuditSignInit() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-snapshot-noinit-"));
  var backend = _backend();
  b.auditSign._resetForTest();
  try {
    await b.auditSign.init({ dataDir: dir, mode: "plaintext", algorithm: "ml-dsa-65" });
    var writer = b.agent.snapshot.create({ orchestrator: _orch(), backend: backend, sealer: _sealer() });
    var s = await writer.takeSnapshot({});
    await writer.persist(s);
    b.auditSign._resetForTest();

    var cold = b.agent.snapshot.create({ orchestrator: _orch(), backend: backend, sealer: _sealer() });
    check("agent-snapshot boot order: loadById before b.auditSign.init() throws agent-snapshot/signer-not-wired",
          (await _code(cold.loadById(s.snapshotId))) === "agent-snapshot/signer-not-wired");
    check("agent-snapshot boot order: loadLatest before b.auditSign.init() throws agent-snapshot/signer-not-wired",
          (await _code(cold.loadLatest())) === "agent-snapshot/signer-not-wired");

    await b.auditSign.init({ dataDir: dir, mode: "plaintext", algorithm: "ml-dsa-65" });
    var warm = await cold.loadById(s.snapshotId);
    check("agent-snapshot boot order control: the same row loads once b.auditSign.init() has run",
          warm && warm.snapshotId === s.snapshotId);
  } finally {
    b.auditSign._resetForTest();
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

async function run() {
  await testPlaintextCopyOfSealedSnapshotRefused();
  await testSignedPlaintextRefusedUnderRegulatedPosture();
  await testLoadBeforeAuditSignInit();
}

module.exports = {
  run:                                                run,
  testPlaintextCopyOfSealedSnapshotRefused:           testPlaintextCopyOfSealedSnapshotRefused,
  testSignedPlaintextRefusedUnderRegulatedPosture:    testSignedPlaintextRefusedUnderRegulatedPosture,
  testLoadBeforeAuditSignInit:                        testLoadBeforeAuditSignInit,
};

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
