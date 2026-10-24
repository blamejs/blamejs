// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.agent.snapshot loads refuse a snapshot signed under a key the verifier
 * does not trust:
 *
 * - With the default signer (b.auditSign), a stored row verifies only under
 *   the live audit-signing key. A row signed with any other key is refused,
 *   also when that key is filed in the unsealed audit-sign.pubkeys.json
 *   history. After a key rotation, resign(previousPublicKey) re-signs the rows
 *   the previous key signed and leaves every other row refused.
 * - With an operator signer that verifies under the row's sigPubKey, a
 *   sigPubKey that is a compromised key is refused in every form
 *   b.crypto.compromisedKey reads (PEM, base64 SPKI DER, Buffer, JWK), and a
 *   sigPubKey it cannot read is refused. persist() refuses the same keys
 *   before it signs or writes anything. The control twin differs only in the
 *   private scalar and loads.
 */

var fs         = require("node:fs");
var os         = require("node:os");
var path       = require("node:path");
var nodeCrypto = require("node:crypto");
var helpers    = require("../helpers");
var b          = helpers.b;
var check      = helpers.check;
var ck         = require("../helpers/compromised-keys");

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
// A signer that signs with privateKey, reports publicPem, and verifies under
// whatever key it is handed: the shape of an operator signer that trusts the
// row's sigPubKey.
function _keyedSigner(privateKey, publicPem) {
  return {
    sign:         function (bytes) { return nodeCrypto.sign(null, bytes, privateKey); },
    verify:       function (bytes, sig, pubKey) { return nodeCrypto.verify(null, bytes, pubKey, sig); },
    getPublicKey: function () { return publicPem; },
  };
}
async function _code(p) {
  try { await p; return "NO-THROW"; } catch (e) { return e.code || e.message; }
}

// Writes a sealed row signed by privateKey with its own sigPubKey, the way
// anyone with write access to the backend and the sealer can.
async function _plantRow(backend, privateKey, publicPem) {
  var writer = b.agent.snapshot.create({
    orchestrator: _orch(), backend: backend, sealer: _sealer(),
    signer: _keyedSigner(privateKey, publicPem),
  });
  var snap = await writer.takeSnapshot({ sagas: [{ id: "injected-saga", step: 99 }] });
  await writer.persist(snap);
  return snap.snapshotId;
}

// Files publicPem in the data directory's public-key history, so
// b.auditSign.getPublicKeyByFingerprint resolves it as a rotated-out key.
function _plantHistoryEntry(dir, publicPem) {
  var historyPath = path.join(dir, "audit-sign.pubkeys.json");
  var list = fs.existsSync(historyPath) ? JSON.parse(fs.readFileSync(historyPath, "utf8")) : [];
  list.push({ fingerprint: b.auditSign.fingerprintOf(publicPem), publicKey: publicPem });
  fs.writeFileSync(historyPath, JSON.stringify(list));
}

async function testDefaultSignerRefusesForeignKey() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-snapshot-compromised-"));
  b.auditSign._resetForTest();
  await b.auditSign.init({ dataDir: dir, mode: "plaintext", algorithm: "ml-dsa-65" });
  try {
    var backend = _backend();
    var victim = b.agent.snapshot.create({ orchestrator: _orch(), backend: backend, sealer: _sealer() });
    var own = await victim.takeSnapshot({});
    await victim.persist(own);
    var loaded = await victim.loadById(own.snapshotId);
    check("agent-snapshot compromised key control: a snapshot signed by b.auditSign loads",
          loaded && loaded.snapshotId === own.snapshotId);

    var other = ck.ecKeyPair("prime256v1", ck.labelScalar("prime256v1", "agent-snapshot stranger"));
    var otherPem = other.publicKey.export({ type: "spki", format: "pem" });
    var otherId = await _plantRow(backend, other.privateKey, otherPem);
    check("agent-snapshot foreign key: loadById refuses a row signed by a key b.auditSign does not hold",
          (await _code(victim.loadById(otherId))) === "agent-snapshot/bad-signature");
    check("agent-snapshot foreign key: loadLatest refuses the newest planted row",
          (await _code(victim.loadLatest())) === "agent-snapshot/bad-signature");

    _plantHistoryEntry(dir, otherPem);
    check("agent-snapshot history pin: the planted entry resolves through getPublicKeyByFingerprint",
          b.auditSign.getPublicKeyByFingerprint(b.auditSign.fingerprintOf(otherPem)) === otherPem);
    check("agent-snapshot history pin: loadById refuses a row signed by a key only the history file lists",
          (await _code(victim.loadById(otherId))) === "agent-snapshot/bad-signature");

    var rotation = await b.auditSign.rotateSigningKey();
    check("agent-snapshot rotation: a snapshot signed before a key rotation is refused until resign()",
          (await _code(victim.loadById(own.snapshotId))) === "agent-snapshot/bad-signature");
    var stranger = ck.ecKeyPair("prime256v1", ck.labelScalar("prime256v1", "agent-snapshot resign stranger"));
    var wrong = await victim.resign(stranger.publicKey.export({ type: "spki", format: "pem" }));
    check("agent-snapshot rotation: resign() with a key that signed nothing re-signs nothing",
          wrong.resigned === 0 && wrong.refused.indexOf(own.snapshotId) !== -1);
    check("agent-snapshot rotation: resign() refuses a previous key it cannot read",
          (await _code(victim.resign("not a key"))) === "agent-snapshot/bad-previous-key");
    check("agent-snapshot rotation: resign() refuses a compromised previous key",
          (await _code(victim.resign(ck.ecKeyPair("prime256v1", 1n).publicKey.export({ type: "spki", format: "pem" })))) ===
            "agent-snapshot/compromised-key");
    var done = await victim.resign(rotation.previousPublicKey);
    check("agent-snapshot rotation control: resign() with the previous public key re-signs the snapshot it signed",
          done.resigned === 1 && done.current === 0);
    check("agent-snapshot rotation: resign() leaves the row a foreign key signed and reports it",
          done.refused.indexOf(otherId) !== -1 && done.refused.indexOf(own.snapshotId) === -1);
    var afterResign = await victim.loadById(own.snapshotId);
    check("agent-snapshot rotation control: the re-signed snapshot loads with its takenAt",
          afterResign && afterResign.snapshotId === own.snapshotId && afterResign.takenAt === own.takenAt);
    check("agent-snapshot rotation: the foreign row is still refused after resign()",
          (await _code(victim.loadById(otherId))) === "agent-snapshot/bad-signature");
    var again = await victim.resign(rotation.previousPublicKey);
    check("agent-snapshot rotation control: a second resign() counts the row as current",
          again.resigned === 0 && again.current === 1);
  } finally {
    b.auditSign._resetForTest();
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

// node:crypto reads the key block of a sigPubKey followed by a certificate
// block it cannot parse, so the scalar-1 key still verifies under an operator
// signer. The compromised-key lookup cannot read the whole text, and the key
// node:crypto reads is still judged.
var UNREADABLE_TAIL = "-----BEGIN TRUSTED CERTIFICATE-----\n/w==\n-----END TRUSTED CERTIFICATE-----\n";

// Each form an operator signer's getPublicKey() can report, and how its
// verify turns the stored value back into a key. A Buffer is stored through
// JSON, so the loader sees { type: "Buffer", data: [...] }.
var FORMS = {
  "pem": {
    repr:  function (pub) { return pub.export({ type: "spki", format: "pem" }); },
    toKey: function (v) { return nodeCrypto.createPublicKey(v); },
  },
  "pem-with-unreadable-tail": {
    repr:  function (pub) { return pub.export({ type: "spki", format: "pem" }) + UNREADABLE_TAIL; },
    toKey: function (v) { return nodeCrypto.createPublicKey(v); },
  },
  "jwk": {
    repr:  function (pub) { return pub.export({ format: "jwk" }); },
    toKey: function (v) { return nodeCrypto.createPublicKey({ key: v, format: "jwk" }); },
  },
  "base64-der": {
    repr:  function (pub) { return pub.export({ type: "spki", format: "der" }).toString("base64"); },
    toKey: function (v) { return nodeCrypto.createPublicKey({ key: Buffer.from(v, "base64"), format: "der", type: "spki" }); },
  },
  "buffer": {
    repr:  function (pub) { return pub.export({ type: "spki", format: "der" }); },
    toKey: function (v) {
      var der = Buffer.isBuffer(v) ? v : Buffer.from(v.data);
      return nodeCrypto.createPublicKey({ key: der, format: "der", type: "spki" });
    },
  },
};

function _formSigner(pair, form) {
  return {
    sign:         function (bytes) { return nodeCrypto.sign(null, bytes, pair.privateKey); },
    verify:       function (bytes, sig, pub) { return nodeCrypto.verify(null, bytes, FORMS[form].toKey(pub), sig); },
    getPublicKey: function () { return FORMS[form].repr(pair.publicKey); },
  };
}

// Persists a row signed by privateKey through a signer that reports no key,
// then writes sigPubKey into the sealed row, the way anyone with write access
// to the backend and the sealer can. sigPubKey is not part of the signed
// bytes.
async function _plantWithSigPubKey(backend, privateKey, sigPubKey) {
  var writer = b.agent.snapshot.create({
    orchestrator: _orch(), backend: backend, sealer: _sealer(),
    signer: {
      sign:         function (bytes) { return nodeCrypto.sign(null, bytes, privateKey); },
      verify:       function () { return false; },
      getPublicKey: function () { return null; },
    },
  });
  var snap = await writer.takeSnapshot({});
  await writer.persist(snap);
  var raw = await backend.get(snap.snapshotId);
  var prefix = writer.SEALED_PREFIX;
  var inner = JSON.parse(Buffer.from(raw.sealed.slice(prefix.length), "base64").toString("utf8"));
  inner.sigPubKey = JSON.parse(JSON.stringify(sigPubKey));
  await backend.put(snap.snapshotId, Object.assign({}, raw, {
    sealed: prefix + Buffer.from(JSON.stringify(inner), "utf8").toString("base64"),
  }));
  return snap.snapshotId;
}

// An operator signer that reports its key verifies every snapshot under that
// key: a row signed by another key that carries that key as its sigPubKey is
// refused, and after the signer rotates, resign(previousPublicKey) re-signs
// the rows the previous key signed.
async function testOperatorSignerVerifiesUnderItsOwnKey() {
  var a = nodeCrypto.generateKeyPairSync("ed25519");
  var bKeys = nodeCrypto.generateKeyPairSync("ed25519");
  var aPem = a.publicKey.export({ type: "spki", format: "pem" });
  var bPem = bKeys.publicKey.export({ type: "spki", format: "pem" });
  var backend = _backend();
  var writer = b.agent.snapshot.create({ orchestrator: _orch(), backend: backend, sealer: _sealer(),
    signer: _keyedSigner(a.privateKey, aPem) });
  var snap = await writer.takeSnapshot({});
  await writer.persist(snap);
  check("agent-snapshot operator signer control: the signer that wrote a snapshot loads it",
        (await _code(writer.loadById(snap.snapshotId))) === "NO-THROW");
  var rotated = b.agent.snapshot.create({ orchestrator: _orch(), backend: backend, sealer: _sealer(),
    signer: _keyedSigner(bKeys.privateKey, bPem) });
  check("agent-snapshot operator signer: a snapshot signed by the previous key is refused until resign()",
        (await _code(rotated.loadById(snap.snapshotId))) === "agent-snapshot/bad-signature");
  var foreign = nodeCrypto.generateKeyPairSync("ed25519");
  var foreignId = await _plantRow(backend, foreign.privateKey, foreign.publicKey.export({ type: "spki", format: "pem" }));
  check("agent-snapshot operator signer: a row signed by another key under that key's own sigPubKey is refused",
        (await _code(rotated.loadById(foreignId))) === "agent-snapshot/bad-signature");
  var done = await rotated.resign(aPem);
  check("agent-snapshot operator signer: resign() with the previous key re-signs the snapshot it signed",
        done.resigned === 1 && done.current === 0 && done.refused.length === 1 && done.refused[0] === foreignId,
        JSON.stringify(done));
  check("agent-snapshot operator signer: the re-signed snapshot loads under the current key",
        (await _code(rotated.loadById(snap.snapshotId))) === "NO-THROW");

  var failing = _keyedSigner(bKeys.privateKey, bPem);
  failing.getPublicKey = function () { throw new Error("key store unavailable"); };
  var outage = b.agent.snapshot.create({ orchestrator: _orch(), backend: backend, sealer: _sealer(), signer: failing });
  check("agent-snapshot operator signer: a signer whose getPublicKey() throws refuses the foreign row instead of trusting its sigPubKey",
        (await _code(outage.loadById(foreignId))) === "agent-snapshot/signer-key-unreadable");
  check("agent-snapshot operator signer: resign() reports a signer whose getPublicKey() throws",
        (await _code(outage.resign(aPem))) === "agent-snapshot/signer-key-unreadable");
}

async function testOperatorSignerJudgesEveryKeyFormAtLoad() {
  var cases = [
    ["prime256v1", "pem"], ["secp384r1", "pem"], ["prime256v1", "pem-with-unreadable-tail"],
    ["prime256v1", "jwk"], ["secp384r1", "jwk"], ["prime256v1", "base64-der"], ["prime256v1", "buffer"],
  ];
  for (var i = 0; i < cases.length; i += 1) {
    var curve = cases[i][0];
    var form = cases[i][1];
    var label = curve + " " + form;
    var control = ck.ecKeyPair(curve, ck.labelScalar(curve, "agent-snapshot control"));
    var cBackend = _backend();
    var cId = await _plantWithSigPubKey(cBackend, control.privateKey, FORMS[form].repr(control.publicKey));
    var cLoader = b.agent.snapshot.create({
      orchestrator: _orch(), backend: cBackend, sealer: _sealer(), signer: _formSigner(control, form),
    });
    check("agent-snapshot compromised key control: a stored " + label + " control sigPubKey loads",
          (await _code(cLoader.loadById(cId))) === "NO-THROW");

    var bad = ck.ecKeyPair(curve, 1n);
    var bBackend = _backend();
    var bId = await _plantWithSigPubKey(bBackend, bad.privateKey, FORMS[form].repr(bad.publicKey));
    var bLoader = b.agent.snapshot.create({
      orchestrator: _orch(), backend: bBackend, sealer: _sealer(), signer: _formSigner(bad, form),
    });
    check("agent-snapshot compromised key: a stored " + label + " scalar-1 sigPubKey is refused",
          (await _code(bLoader.loadById(bId))) === "agent-snapshot/bad-signature");
  }
}

async function testOperatorSignerRefusesCompromisedKeyAtPersist() {
  var forms = Object.keys(FORMS);
  for (var i = 0; i < forms.length; i += 1) {
    var form = forms[i];
    var control = ck.ecKeyPair("prime256v1", ck.labelScalar("prime256v1", "agent-snapshot persist control"));
    var cBackend = _backend();
    var cSnap = b.agent.snapshot.create({
      orchestrator: _orch(), backend: cBackend, sealer: _sealer(), signer: _formSigner(control, form),
    });
    var cs = await cSnap.takeSnapshot({});
    await cSnap.persist(cs);
    check("agent-snapshot persist control: a " + form + " control signer key persists and loads",
          (await _code(cSnap.loadById(cs.snapshotId))) === "NO-THROW");

    var bad = ck.ecKeyPair("prime256v1", 1n);
    var bBackend = _backend();
    var bSnap = b.agent.snapshot.create({
      orchestrator: _orch(), backend: bBackend, sealer: _sealer(), signer: _formSigner(bad, form),
    });
    var bs = await bSnap.takeSnapshot({});
    check("agent-snapshot persist: a " + form + " scalar-1 signer key throws agent-snapshot/compromised-key",
          (await _code(bSnap.persist(bs))) === "agent-snapshot/compromised-key");
    check("agent-snapshot persist: the refused " + form + " persist writes no row and leaves the snapshot unsigned",
          (await bBackend.list()).length === 0 && bs.sig === null);
  }
}

async function testOperatorSignerUnreadableKey() {
  var pair = ck.ecKeyPair("prime256v1", ck.labelScalar("prime256v1", "agent-snapshot opaque key"));
  var opaque = {
    sign:         function (bytes) { return nodeCrypto.sign(null, bytes, pair.privateKey); },
    verify:       function (bytes, sig) { return nodeCrypto.verify(null, bytes, pair.publicKey, sig); },
    getPublicKey: function () { return "kms-key-7"; },
  };
  var pBackend = _backend();
  var pSnap = b.agent.snapshot.create({ orchestrator: _orch(), backend: pBackend, sealer: _sealer(), signer: opaque });
  var ps = await pSnap.takeSnapshot({});
  check("agent-snapshot unreadable key: persist with a signer key compromisedKey cannot read throws " +
        "agent-snapshot/signer-key-unreadable",
        (await _code(pSnap.persist(ps))) === "agent-snapshot/signer-key-unreadable");
  check("agent-snapshot unreadable key: the refused persist writes no row", (await pBackend.list()).length === 0);

  var lBackend = _backend();
  var cId = await _plantWithSigPubKey(lBackend, pair.privateKey, null);
  var loader = b.agent.snapshot.create({ orchestrator: _orch(), backend: lBackend, sealer: _sealer(), signer: opaque });
  check("agent-snapshot unreadable key control: a row with no sigPubKey verifies under the operator signer",
        (await _code(loader.loadById(cId))) === "NO-THROW");
  var uId = await _plantWithSigPubKey(lBackend, pair.privateKey, "kms-key-7");
  check("agent-snapshot unreadable key: a stored sigPubKey compromisedKey cannot read is refused",
        (await _code(loader.loadById(uId))) === "agent-snapshot/bad-signature");
}

async function run() {
  await testDefaultSignerRefusesForeignKey();
  await testOperatorSignerVerifiesUnderItsOwnKey();
  await testOperatorSignerJudgesEveryKeyFormAtLoad();
  await testOperatorSignerRefusesCompromisedKeyAtPersist();
  await testOperatorSignerUnreadableKey();
}

module.exports = {
  run:                                              run,
  testDefaultSignerRefusesForeignKey:               testDefaultSignerRefusesForeignKey,
  testOperatorSignerVerifiesUnderItsOwnKey:         testOperatorSignerVerifiesUnderItsOwnKey,
  testOperatorSignerJudgesEveryKeyFormAtLoad:       testOperatorSignerJudgesEveryKeyFormAtLoad,
  testOperatorSignerRefusesCompromisedKeyAtPersist: testOperatorSignerRefusesCompromisedKeyAtPersist,
  testOperatorSignerUnreadableKey:                  testOperatorSignerUnreadableKey,
};

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
