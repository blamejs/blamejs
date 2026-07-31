// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.mtlsCa non-breaking CA algorithm-migration primitives (issue #532):
 *   - status().algorithm / .keyType (from the stored cert's public key)
 *   - rotate({ generation, algorithm }) -> { caCertPem, previousCaCertPem }
 *   - commit({ retainPrevious }) + loadTrustBundle() + dropRetained()
 *   - engine + CA-handle canVerifyInTls() loopback probe
 *   - revokeGeneration(n) over the issuance ledger
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var fs         = require("fs");
var os         = require("os");
var path       = require("path");
var nodeCrypto = require("node:crypto");
var engine     = require("../../lib/mtls-engine-default");
var pki        = require("../../lib/vendor/blamejs-pki.cjs");

var _tmpDirs = [];
function _mkTmp() { var d = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-mtls532-")); _tmpDirs.push(d); return d; }
function _newCa(extra) { return b.mtlsCa.create(Object.assign({ dataDir: _mkTmp(), caKeySealedMode: "disabled" }, extra || {})); }
function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }
// Build a rollback-journal manifest as commit() writes it (Buffers -> base64), for
// fabricating crash states. m: { key, newKey, cert, retainAfter, prevAction, prevData }.
function _journalManifest(m) {
  return JSON.stringify({
    key:         m.key.toString("base64"),
    newKey:      m.newKey != null ? m.newKey.toString("base64") : null,
    cert:        m.cert != null ? m.cert.toString("base64") : null,
    newCert:     m.newCert != null ? m.newCert.toString("base64") : null,
    retainAfter: !!m.retainAfter,
    crlMovedAside: !!m.crlMovedAside,
    prevAction:  m.prevAction,
    prevData:    m.prevData != null ? m.prevData.toString("base64") : null,
  });
}

// A minimal custom engine that issues a P-256 (not P-384) self-signed EC CA,
// to prove status() does NOT mislabel every EC CA as ECDSA-P384-SHA384.
function _p256CaEngine() {
  return {
    generateCa: async function () {
      var subtle = pki.webcrypto.subtle;
      var keys = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
      var spki = Buffer.from(await subtle.exportKey("spki", keys.publicKey));
      var now = new Date();
      var caCertPem = await pki.x509.sign({
        subject:          [{ commonName: "p256-ca" }, { organizationalUnitName: "CAv1" }],
        subjectPublicKey: spki,
        serialNumber:     "01",
        notBefore:        now,
        notAfter:         new Date(now.getTime() + 86400000),
        extensions:       { basicConstraints: { cA: true, pathLen: 0 }, keyUsage: ["keyCertSign", "cRLSign"] },
      }, { key: keys.privateKey }, { pem: true, digestAlgorithm: "sha384" });
      var caKeyPem = await pki.key.export(keys.privateKey, { format: "pem" });
      return { caCertPem: caCertPem, caKeyPem: caKeyPem };
    },
  };
}

async function testStatusAlgorithmKeyType() {
  var ca = _newCa();
  var before = ca.status();
  check("status: no CA -> algorithm/keyType null",
        before.exists === false && before.algorithm === null && before.keyType === null);
  await ca.initCA();   // default ML-DSA-87
  var s = ca.status();
  check("status: default CA reports ML-DSA-87 / ml-dsa-87",
        s.algorithm === "ML-DSA-87" && s.keyType === "ml-dsa-87");
  var caEc = _newCa({ algorithm: "ECDSA-P384-SHA384" });
  await caEc.initCA();
  var se = caEc.status();
  check("status: classical pin reports ECDSA-P384-SHA384 / ec",
        se.algorithm === "ECDSA-P384-SHA384" && se.keyType === "ec");
}

async function testRotate() {
  var ca = _newCa();
  await ca.initCA();
  var prevCert = ca.loadCert().toString("utf8");
  check("rotate: starts on ML-DSA-87 gen 1",
        ca.status().algorithm === "ML-DSA-87" && ca.status().generation === 1);
  var rot = await ca.rotate({ generation: 2, algorithm: "ECDSA-P384-SHA384" });
  check("rotate: returns caCertPem + the exact previousCaCertPem",
        typeof rot.caCertPem === "string" && rot.previousCaCertPem === prevCert);
  check("rotate: reports new generation + algorithm",
        rot.generation === 2 && rot.algorithm === "ECDSA-P384-SHA384");
  var s2 = ca.status();
  check("rotate: stored CA is now gen 2 ECDSA (mismatch-free flip)",
        s2.generation === 2 && s2.algorithm === "ECDSA-P384-SHA384");
  var leaf = await ca.generateClientCert({ cn: "post-rotate" });
  check("rotate: a leaf issues cleanly under the rotated CA", typeof leaf.cert === "string");

  var caB = _newCa(); await caB.initCA(); await caB.rotate({ generation: 5 });
  check("rotate: backward/equal generation refused",
        (await code2(function () { return caB.rotate({ generation: 3 }); })) === "mtls-ca/bad-generation");

  var caC = _newCa(); await caC.initCA();
  var rc = await caC.rotate({ algorithm: "ECDSA-P384-SHA384" });
  check("rotate: default generation is current + 1", rc.generation === 2);
}

async function testTrustBundleRetention() {
  var ca = _newCa();
  await ca.initCA();
  check("loadTrustBundle: one cert before rotation", (await ca.loadTrustBundle()).length === 1);
  var prevCert = ca.loadCert().toString("utf8");
  await ca.rotate({ generation: 2, algorithm: "ECDSA-P384-SHA384" });   // retainPrevious defaults on
  var bundle = (await ca.loadTrustBundle());
  check("loadTrustBundle: current + retained after rotate",
        bundle.length === 2 && bundle.indexOf(prevCert) !== -1);
  var d = await ca.dropRetained();
  check("dropRetained: ends the window", d.dropped === true && (await ca.loadTrustBundle()).length === 1);
  check("dropRetained: idempotent when nothing retained", (await ca.dropRetained()).dropped === false);

  var ca2 = _newCa(); await ca2.initCA();
  await ca2.rotate({ generation: 2, retainPrevious: false });
  check("rotate({retainPrevious:false}): no retained CA", (await ca2.loadTrustBundle()).length === 1);
}

async function testCanVerifyInTls() {
  check("engine.canVerifyInTls: ECDSA-P384-SHA384 -> true",
        (await engine.canVerifyInTls("ECDSA-P384-SHA384")) === true);
  check("engine.canVerifyInTls: unknown label -> false (fails closed)",
        (await engine.canVerifyInTls("NOT-A-REAL-ALGORITHM")) === false);
  var ca = _newCa();
  await ca.initCA();   // default ML-DSA-87 — the supported Node LTS verifies it
  check("ca.canVerifyInTls: the CA's own algorithm verifies in loopback mTLS",
        (await ca.canVerifyInTls()) === true);
}

async function testRevokeGeneration() {
  var ca = _newCa();
  await ca.initCA();
  var g1a = await ca.generateClientCert({ cn: "gen1-a" });
  var g1b = await ca.generateClientCert({ cn: "gen1-b" });
  await ca.rotate({ generation: 2 });
  var g2 = await ca.generateClientCert({ cn: "gen2-a" });
  var res = await ca.revokeGeneration(2);
  check("revokeGeneration(2): revokes both gen-1 leaves", res.revoked === 2);
  check("revokeGeneration: gen-1 leaves are revoked",
        ca.isRevoked(g1a.fingerprint) && ca.isRevoked(g1b.fingerprint));
  check("revokeGeneration: the gen-2 leaf is NOT revoked", ca.isRevoked(g2.fingerprint) === false);
  check("revokeGeneration: idempotent (re-run revokes 0 new)", (await ca.revokeGeneration(2)).revoked === 0);
  check("revokeGeneration: n=0 refused", code(function () { ca.revokeGeneration(0); }) === "mtls-ca/bad-generation");
  check("revokeGeneration: non-integer n refused", code(function () { ca.revokeGeneration(1.5); }) === "mtls-ca/bad-generation");
}

// A handle created with an algorithm pin that rotate({ algorithm })s to a
// different one must stay usable — the effective pin follows the rotation, so
// the next initCA()/generateClientCert() does not raise mtls-ca/algorithm-mismatch.
async function testRotatePersistsOverrideAlgorithm() {
  var ca = _newCa({ algorithm: "ECDSA-P384-SHA384" });
  await ca.initCA();
  await ca.rotate({ generation: 2, algorithm: "ML-DSA-87" });
  check("rotate flips the stored CA to ML-DSA-87", ca.status().algorithm === "ML-DSA-87");
  var leaf = await ca.generateClientCert({ cn: "post-rotate-mldsa" });
  check("ECDSA-pinned handle stays usable after rotating to ML-DSA (no algorithm-mismatch)",
        typeof leaf.cert === "string");
  // The reverse pin also sticks: default (ML-DSA) handle rotated to ECDSA issues ECDSA.
  var ca2 = _newCa();
  await ca2.initCA();
  await ca2.rotate({ generation: 2, algorithm: "ECDSA-P384-SHA384" });
  var leaf2 = await ca2.generateClientCert({ cn: "post-rotate-ecdsa" });
  check("default handle stays usable after rotating to ECDSA", typeof leaf2.cert === "string");
}

// rotate() must reject a fractional generation up front — Math.floor would
// silently accept 2.9 as generation 2 and mis-assign the revocation cohort.
async function testRotateRejectsFractionalGeneration() {
  var ca = _newCa();
  await ca.initCA();   // generation 1
  check("rotate: fractional generation 2.9 refused (not floored to 2)",
        (await code2(function () { return ca.rotate({ generation: 2.9 }); })) === "mtls-ca/bad-generation");
  // A whole-number rotation still works after the rejection.
  var r = await ca.rotate({ generation: 2 });
  check("rotate: integer generation still accepted", r.generation === 2);
}

// A custom engine may issue a P-256 / P-521 EC CA; status() must not label it
// ECDSA-P384-SHA384 (the framework's sole classical P-384 label).
async function testStatusAlgorithmNullForNonP384Ec() {
  var ca = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled", engine: _p256CaEngine() });
  await ca.initCA();
  var s = ca.status();
  check("status: a P-256 EC CA is keyType 'ec' but algorithm null (not mislabeled P-384)",
        s.keyType === "ec" && s.algorithm === null);
}

// rotate({ retainPrevious: false }) must clear a root a PRIOR retained rotation
// left behind, so loadTrustBundle() stops trusting it.
async function testRetainPreviousFalseClearsStaleRoot() {
  var ca = _newCa();
  await ca.initCA();
  await ca.rotate({ generation: 2 });                       // retains -> ca.prev.crt
  check("retained root present after a retained rotation", (await ca.loadTrustBundle()).length === 2);
  await ca.rotate({ generation: 3, retainPrevious: false });
  check("rotate({retainPrevious:false}) clears the stale retained root",
        (await ca.loadTrustBundle()).length === 1);
}

// A ledger write failure must FAIL issuance — an untracked cert can never be
// revoked by revokeGeneration(), so returning it would be a silent hole.
async function testIssuanceLedgerFailsClosed() {
  var throwingStore = { list: function () { return []; }, add: function () { throw new Error("disk full"); } };
  var ca = _newCa({ issuanceStore: throwingStore });
  await ca.initCA();
  check("generateClientCert fails closed when the issuance-ledger write throws",
        (await code2(function () { return ca.generateClientCert({ cn: "untracked" }); }))
          === "mtls-ca/issuance-ledger-write-failed");
}

// A cert revoked by SERIAL only, then swept by revokeGeneration (which supplies
// serial + fingerprint), must become revocable by fingerprint — otherwise the
// require-mtls gate (fingerprint-keyed) would still admit it.
async function testRevokeGenerationBackfillsFingerprint() {
  var ca = _newCa();
  await ca.initCA();
  var leaf = await ca.generateClientCert({ cn: "gen1" });
  await ca.revoke(leaf.serialNumber);   // serial-only revocation
  check("serial-only revocation does not yet match the fingerprint",
        ca.isRevoked(leaf.fingerprint) === false);
  await ca.rotate({ generation: 2 });
  check("revokeGeneration backfills the fingerprint onto the serial-only entry (counts 1)",
        (await ca.revokeGeneration(2)).revoked === 1);
  check("the cert is now revoked by fingerprint (gate-enforceable)",
        ca.isRevoked(leaf.fingerprint) === true);
}

// A rotation whose CA commit FAILS must not have already destroyed the retained
// root — a client still using it would be stranded by a rotation that never landed.
async function testRetainedRootSurvivesFailedCommit() {
  var atomicFile = require("../../lib/atomic-file");
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await ca.initCA();
  await ca.rotate({ generation: 2 });   // retains -> ca.prev.crt
  check("retained root present before the failing rotation", (await ca.loadTrustBundle()).length === 2);
  // Sabotage the next commit at the cert publish so it rolls back.
  var realRename = atomicFile.renameWithRetry;
  atomicFile.renameWithRetry = function (from, to) {
    if (String(to) === String(ca.paths.caCert)) throw new Error("simulated cert rename failure");
    return realRename.apply(this, arguments);
  };
  var codeSeen;
  try { codeSeen = await code2(function () { return ca.rotate({ generation: 3, retainPrevious: false }); }); }
  finally { atomicFile.renameWithRetry = realRename; }
  check("the sabotaged rotation fails", codeSeen === "mtls-ca/commit-failed");
  check("the retained root SURVIVES a failed retainPrevious:false rotation",
        (await ca.loadTrustBundle()).length === 2);
}

// A rotation whose CA commit SUCCEEDS but whose retained-root snapshot fails
// (full/read-only fs) must still succeed — the CA is committed, the algorithm
// override sticks, and the handle keeps issuing. The retained root is secondary.
async function testRotateAbortsWhenRetainedRootWriteFails() {
  var atomicFile = require("../../lib/atomic-file");
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, algorithm: "ECDSA-P384-SHA384", caKeySealedMode: "disabled" });
  await ca.initCA();
  var keyBefore  = fs.readFileSync(ca.paths.caKey);
  var certBefore = fs.readFileSync(ca.paths.caCert);
  // The required retained-root write fails (a read-only ca.prev.crt directory,
  // disk full). Retention is part of the commit, so the rotation MUST abort rather
  // than publish a new CA while silently omitting the outgoing root (which would
  // reject clients still enrolled under the just-superseded CA, breaking the
  // advertised no-outage migration).
  var realWrite = atomicFile.writeSync;
  atomicFile.writeSync = function (p) {
    if (String(p) === String(ca.paths.caCertPrev)) throw new Error("simulated retained-root write failure");
    return realWrite.apply(this, arguments);
  };
  var codeSeen;
  try { codeSeen = await code2(function () { return ca.rotate({ generation: 2, algorithm: "ML-DSA-87" }); }); }
  finally { atomicFile.writeSync = realWrite; }
  check("rotation aborts when the required retained-root write fails", codeSeen === "mtls-ca/commit-failed");
  check("the original CA survived the aborted rotation (still gen-1 ECDSA)",
        ca.status().generation === 1 && ca.status().algorithm === "ECDSA-P384-SHA384");
  check("the original CA key and cert are unchanged after the aborted rotation",
        fs.readFileSync(ca.paths.caKey).equals(keyBefore) && fs.readFileSync(ca.paths.caCert).equals(certBefore));
  check("the surviving CA still issues under its original algorithm",
        typeof (await ca.generateClientCert({ cn: "post-abort" })).cert === "string");
}

// A P12 archive with no certPem cannot be recorded in the issuance ledger, so it
// could never be revoked by generation — refuse it rather than return it.
async function testP12RequiresLedgerIdentity() {
  var noCertPem = {
    generateCa:     engine.generateCa,
    signClientCert: engine.signClientCert,
    packageP12:     async function () { return { p12: Buffer.from("fake-p12-bytes") }; },
  };
  var ca = _newCa({ engine: noCertPem });
  await ca.initCA();
  check("generateClientP12 refuses a P12 with no certPem (untracked -> unrevocable)",
        (await code2(function () { return ca.generateClientP12({ password: "pw" }); }))
          === "mtls-ca/bad-engine-output");
}

// generateCrl's fingerprint-only omission count must not fold in the serial
// DUPLICATES the CRL dedup drops — otherwise a complete CRL is reported incomplete.
async function testCrlOmissionCountExcludesSerialDupes() {
  var ca = _newCa();
  await ca.initCA();
  var leaf = await ca.generateClientCert({ cn: "z1" });
  await ca.revoke(leaf.serialNumber);                 // serial-only, recorded in the ledger
  await ca.revoke({ fingerprint: "cd".repeat(64) });  // a genuine fingerprint-only revocation
  await ca.rotate({ generation: 2 });
  await ca.revokeGeneration(2);                        // backfills leaf -> a serial-duplicate entry
  var crl = await ca.generateCrl({ persist: false });
  check("generateCrl omission count counts only genuine fingerprint-only entries (serial dupes excluded)",
        crl.fingerprintOnlyOmitted === 1);
}

// Concurrent rotate() calls must serialize, not both read the same current
// generation and clobber each other's CA + retained root. With only one retained
// grace window at a time, the first opens the window and the second is refused
// rather than silently dropping it.
async function testConcurrentRotationsSerialize() {
  var ca = _newCa();
  await ca.initCA();   // generation 1
  var results = await Promise.allSettled([ca.rotate({}), ca.rotate({})]);
  var fulfilled = results.filter(function (r) { return r.status === "fulfilled"; });
  var rejected  = results.filter(function (r) { return r.status === "rejected"; });
  check("exactly one concurrent retained rotation succeeds, the other is refused",
        fulfilled.length === 1 && rejected.length === 1);
  check("the winner is generation 2 retaining gen-1",
        fulfilled[0].value.generation === 2 && ca.status().generation === 2 && (await ca.loadTrustBundle()).length === 2);
  check("the loser is refused (the open grace window is not silently dropped)",
        rejected[0].reason && rejected[0].reason.code === "mtls-ca/retained-root-exists");
  await ca.dropRetained();
  check("after dropRetained the CA rotates to generation 3", (await ca.rotate({})).generation === 3);
}

// isRevoked() reads an in-memory index (kept in sync by revoke()) rather than
// re-parsing the store per call — assert the index stays correct across a
// build-then-update sequence.
async function testRevocationIndexStaysConsistent() {
  var ca = _newCa();
  await ca.initCA();
  var leaf = await ca.generateClientCert({ cn: "idx" });
  check("not revoked before revocation (builds the index)", ca.isRevoked(leaf.fingerprint) === false);
  await ca.revoke({ fingerprint: leaf.fingerprint });
  check("revoked after revoke (index updated incrementally, no store re-scan)",
        ca.isRevoked(leaf.fingerprint) === true);
}

// A revocation written through ANOTHER handle over the same data directory must
// be seen by this handle's gate lookup — the index refreshes on a store change.
async function testRevocationIndexRefreshesAcrossHandles() {
  var dir = _mkTmp();
  var caA = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  var caB = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await caA.initCA();
  var leaf = await caA.generateClientCert({ cn: "shared" });
  check("handle A: cert not revoked initially (builds its index)",
        caA.isRevoked(leaf.fingerprint) === false);
  await caB.revoke({ fingerprint: leaf.fingerprint });   // revoke through the OTHER handle
  check("handle A picks up a revocation written by handle B (index refreshed via store version)",
        caA.isRevoked(leaf.fingerprint) === true);
}

// Two handles over the same dataDir own separate rotation chains, so the
// pre-commit generation revalidation must refuse the loser instead of both
// committing the same generation and clobbering the retained root.
async function testRotationConflictAcrossHandles() {
  var dir = _mkTmp();
  var release; var barrier = new Promise(function (r) { release = r; });
  var slowEngine = Object.assign({}, engine, {
    generateCa: async function (o) { await barrier; return engine.generateCa(o); },
  });
  var caA = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  var caB = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", engine: slowEngine });
  await caA.initCA();                              // generation 1 on disk, shared
  var bRotate = caB.rotate({ generation: 2 });     // reads gen 1, blocks in generateCa
  await caA.rotate({ generation: 2 });             // commits generation 2 first
  release();                                        // unblock caB's generateCa
  check("a concurrent cross-handle rotation is refused with mtls-ca/rotation-conflict",
        (await code2(function () { return bRotate; })) === "mtls-ca/rotation-conflict");
  check("the CA on disk is the winner's generation 2", caA.status().generation === 2);
}

// canVerifyInTls must probe the PROSPECTIVE algorithm when given, so an
// ECDSA-stored handle pre-flighting a move to ML-DSA tests the target chain,
// not the current one (and a bogus label fails closed rather than passing on
// the stored algorithm).
async function testCanVerifyInTlsProbesTargetAlgorithm() {
  var ca = _newCa({ algorithm: "ECDSA-P384-SHA384" });
  await ca.initCA();   // stored CA is ECDSA
  check("canVerifyInTls() (no arg) probes the stored ECDSA CA",
        (await ca.canVerifyInTls()) === true);
  check("canVerifyInTls('ML-DSA-87') probes the TARGET algorithm (the migration pre-flight)",
        (await ca.canVerifyInTls("ML-DSA-87")) === true);
  check("canVerifyInTls('NOT-A-REAL-ALGORITHM') fails closed (arg is honored, not ignored)",
        (await ca.canVerifyInTls("NOT-A-REAL-ALGORITHM")) === false);
}

// Concurrent issuance against the default ledger must record every certificate
// (the cross-process-locked read-modify-write appends without losing entries).
async function testConcurrentIssuanceAllRecorded() {
  var ca = _newCa();
  await ca.initCA();
  var leaves = await Promise.all([
    ca.generateClientCert({ cn: "c1" }),
    ca.generateClientCert({ cn: "c2" }),
    ca.generateClientCert({ cn: "c3" }),
  ]);
  await ca.rotate({ generation: 2 });
  check("all 3 concurrently-issued certs are recorded (revokeGeneration revokes all 3)",
        (await ca.revokeGeneration(2)).revoked === 3);
  check("each concurrently-issued cert is revoked by fingerprint",
        leaves.every(function (l) { return ca.isRevoked(l.fingerprint); }));
}

// A P-384 EC CA signed with a non-SHA-384 digest must NOT be labeled
// ECDSA-P384-SHA384 — the digest is part of the label, not just the curve.
async function testStatusAlgorithmNullForWrongDigest() {
  var p384Sha512 = {
    generateCa: async function () {
      var subtle = pki.webcrypto.subtle;
      var keys = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-384" }, true, ["sign", "verify"]);
      var spki = Buffer.from(await subtle.exportKey("spki", keys.publicKey));
      var now = new Date();
      var caCertPem = await pki.x509.sign({
        subject:          [{ commonName: "p384-sha512" }, { organizationalUnitName: "CAv1" }],
        subjectPublicKey: spki,
        serialNumber:     "01",
        notBefore:        now,
        notAfter:         new Date(now.getTime() + 86400000),
        extensions:       { basicConstraints: { cA: true, pathLen: 0 }, keyUsage: ["keyCertSign", "cRLSign"] },
      }, { key: keys.privateKey }, { pem: true, digestAlgorithm: "sha512" });
      var caKeyPem = await pki.key.export(keys.privateKey, { format: "pem" });
      return { caCertPem: caCertPem, caKeyPem: caKeyPem };
    },
  };
  var ca = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled", engine: p384Sha512 });
  await ca.initCA();
  var s = ca.status();
  check("status: a P-384 CA signed with SHA-512 is not labeled ECDSA-P384-SHA384 (digest checked)",
        s.keyType === "ec" && s.algorithm === null);
}

// An issuance whose signing straddles a rotate()+revokeGeneration() for its
// generation must be caught and refused, not returned as a live credential the
// sweep missed (the record races the sweep-read; the watermark closes it).
async function testIssuanceSupersededByGenerationRevocation() {
  var dir = _mkTmp();
  var release; var barrier = new Promise(function (r) { release = r; });
  var slowEngine = Object.assign({}, engine, {
    signClientCert: async function (a) { await barrier; return engine.signClientCert(a); },
  });
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", engine: slowEngine });
  await ca.initCA();                            // generation 1
  var issuing = ca.generateClientCert({ cn: "in-flight" });   // blocks in signClientCert (gen-1 CA)
  await ca.rotate({ generation: 2 });
  await ca.revokeGeneration(2);                 // sweeps gen-1 — the in-flight leaf isn't in the ledger yet
  release();                                    // now _recordIssuance runs, AFTER the sweep
  check("an issuance whose generation was revoked mid-signing is refused (superseded)",
        (await code2(function () { return issuing; })) === "mtls-ca/issuance-superseded");
}

// The issuance-vs-sweep watermark must cover a CUSTOM revocation store too — it
// is a separate file, and a list()/add()-only store cannot make its own
// append+sweep atomic.
async function testIssuanceSupersededWithCustomStore() {
  var dir = _mkTmp();
  var release; var barrier = new Promise(function (r) { release = r; });
  var slowEngine = Object.assign({}, engine, {
    signClientCert: async function (a) { await barrier; return engine.signClientCert(a); },
  });
  var revoked = [];
  var customStore = { list: function () { return revoked.slice(); }, add: function (e) { revoked.push(e); } };
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", engine: slowEngine, revocationStore: customStore });
  await ca.initCA();
  var issuing = ca.generateClientCert({ cn: "in-flight-custom" });
  await ca.rotate({ generation: 2 });
  await ca.revokeGeneration(2);
  release();
  check("issuance-superseded fires with a custom revocation store (watermark applies to all stores)",
        (await code2(function () { return issuing; })) === "mtls-ca/issuance-superseded");
}

// Clustered deployment: a shared revocation store exposing the optional
// watermark methods coordinates the generation watermark across hosts that each
// have their OWN dataDir, so an issuance on host B is superseded by host A's
// revokeGeneration even though B's local watermark file was never written.
async function testClusteredWatermarkViaStoreMethods() {
  var shared = { revoked: [], wm: 0 };
  function sharedStore() {
    return {
      list: function () { return shared.revoked.slice(); },
      add:  function (e) { shared.revoked.push(e); },
      readGenerationWatermark: function () { return shared.wm; },
      bumpGenerationWatermark: function (n) { if (n > shared.wm) shared.wm = n; },
    };
  }
  // Clustered operation also requires a shared issuance ledger (per-host default
  // ledgers would let revokeGeneration() miss another host's issuances).
  var sharedIssued = [];
  function sharedIssuanceStore() {
    return { list: function () { return sharedIssued.slice(); }, add: function (e) { sharedIssued.push(e); } };
  }
  var release; var barrier = new Promise(function (r) { release = r; });
  var slowEngine = Object.assign({}, engine, {
    signClientCert: async function (a) { await barrier; return engine.signClientCert(a); },
  });
  var hostB = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled", engine: slowEngine, revocationStore: sharedStore(), issuanceStore: sharedIssuanceStore() });
  await hostB.initCA();                              // generation 1 on host B's dataDir
  var issuing = hostB.generateClientCert({ cn: "clustered" });   // blocks in signing
  var hostA = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled", revocationStore: sharedStore(), issuanceStore: sharedIssuanceStore() });
  await hostA.initCA();
  await hostA.rotate({ generation: 2 });
  await hostA.revokeGeneration(2);                   // bumps the SHARED watermark
  release();
  check("a clustered shared-store watermark supersedes an issuance on another host",
        (await code2(function () { return issuing; })) === "mtls-ca/issuance-superseded");
}

// A CA cert/key pair that stays inconsistent after re-reading must be REFUSED
// (mtls-ca/ca-pair-inconsistent), not signed with, so issuance fails clearly.
async function testInitCaRefusesPersistentPairMismatch() {
  var ca = _newCa();
  await ca.initCA();
  var other = _newCa();
  await other.initCA();
  fs.copyFileSync(other.paths.caKey, ca.paths.caKey);   // ca.key now belongs to a different CA
  check("initCA refuses a persistently mismatched CA cert/key pair (does not sign)",
        (await code2(function () { return ca.generateClientCert({ cn: "mismatch" }); }))
          === "mtls-ca/ca-pair-inconsistent");
}

// If the FINAL cert rename fails after the retained root was rewritten, the prior
// retained root must be restored — a failed rotation cannot strand old-CA clients.
async function testCommitRollsBackRetainedRootOnCertRenameFailure() {
  var atomicFile = require("../../lib/atomic-file");
  var ca = _newCa();
  await ca.initCA();                                     // gen-1, no retained root yet
  var keyBefore  = fs.readFileSync(ca.paths.caKey);
  var certBefore = fs.readFileSync(ca.paths.caCert);
  var realRename = atomicFile.renameWithRetry;
  atomicFile.renameWithRetry = function (from, to) {
    if (String(to) === String(ca.paths.caCert)) throw new Error("simulated cert rename failure");
    return realRename.apply(this, arguments);
  };
  var failed = false;
  try {
    try { await ca.rotate({ generation: 2 }); } catch (_e) { failed = true; }
  } finally { atomicFile.renameWithRetry = realRename; }
  check("a rotation whose cert publication fails is rejected", failed);
  // The prior KEY must be restored — otherwise the new key would sit beside the old
  // cert (a mismatched pair) and the handle would be permanently unusable — and the
  // retained root the failed rotation created must be rolled back (there was none
  // before a first rotation, so ca.prev.crt is removed).
  check("the CA rolls back to the prior key + cert when cert publication fails",
        fs.readFileSync(ca.paths.caKey).equals(keyBefore) && fs.readFileSync(ca.paths.caCert).equals(certBefore));
  check("no stale retained root is left behind by the failed first rotation",
        fs.existsSync(ca.paths.caCertPrev) === false);
  check("the handle still issues after the failed rotation (key + cert pair intact)",
        typeof (await ca.generateClientCert({ cn: "after-failed-rotate" })).cert === "string");
}

// The clustered-watermark methods are all-or-nothing: a store providing only one
// would split the watermark and fail open, so it is refused at construction.
async function testWatermarkMethodsMustBePaired() {
  var base = { list: function () { return []; }, add: function () {} };
  var bumpOnly = Object.assign({}, base, { bumpGenerationWatermark: function () {} });
  var readOnly = Object.assign({}, base, { readGenerationWatermark: function () { return 0; } });
  check("a revocationStore with only bumpGenerationWatermark is refused",
        code(function () { b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled", revocationStore: bumpOnly }); })
          === "mtls-ca/bad-revocation-store");
  check("a revocationStore with only readGenerationWatermark is refused",
        code(function () { b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled", revocationStore: readOnly }); })
          === "mtls-ca/bad-revocation-store");
}

// A P12 certPem must be NON-EMPTY (it is the ledger identity), but need NOT be
// node-parseable — a custom engine may package an opaque certificate this runtime cannot
// parse, exactly as generateClientCert accepts; _certIdentity still derives a stable
// fingerprint, and parsing cannot prove certPem is the cert inside the encrypted p12.
async function testP12CertPemMustBeNonEmpty() {
  function eng(certPem) {
    return { generateCa: engine.generateCa, signClientCert: engine.signClientCert,
             packageP12: async function () { return { p12: Buffer.from("x"), certPem: certPem }; } };
  }
  var caEmpty = _newCa({ engine: eng("") }); await caEmpty.initCA();
  check("generateClientP12 refuses an empty certPem",
        (await code2(function () { return caEmpty.generateClientP12({ password: "pw" }); })) === "mtls-ca/bad-engine-output");
  var caOpaque = _newCa({ engine: eng("not a parseable certificate") }); await caOpaque.initCA();
  var out = await caOpaque.generateClientP12({ password: "pw" });
  check("generateClientP12 ACCEPTS a non-parseable (opaque) certPem, deriving a fingerprint",
        Buffer.isBuffer(out.p12) && typeof out.fingerprint === "string" && out.fingerprint.length > 0);
}

// A defined rotate() algorithm must be a non-empty label (an empty string would
// be read as a pin here but as "no pin"/"omitted" by the engine and canVerifyInTls).
async function testRotateRejectsEmptyAlgorithm() {
  var ca = _newCa();
  await ca.initCA();
  check("rotate: empty-string algorithm refused",
        (await code2(function () { return ca.rotate({ generation: 2, algorithm: "" }); })) === "mtls-ca/bad-algorithm");
}

// A nested operator path must work: create() creates the lock target's parent
// dir, so the first locked revoke() does not ENOENT on <path>.lock.
async function testNestedPathParentDirsCreated() {
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", paths: { revocations: "state/revocations.json" } });
  await ca.initCA();
  var leaf = await ca.generateClientCert({ cn: "nested" });
  await ca.revoke({ fingerprint: leaf.fingerprint });
  check("revoke() with a nested paths.revocations succeeds (lock parent dir created)",
        ca.isRevoked(leaf.fingerprint) === true);
}

// A present-but-malformed generation watermark must ABORT issuance (fail closed),
// not report 0 — reporting 0 would let a below-n generation slip through unrevoked.
async function testMalformedWatermarkAbortsIssuance() {
  var ca = _newCa();
  await ca.initCA();
  fs.writeFileSync(ca.paths.revokedGeneration, "not-a-number");
  check("issuance aborts when the revoked-generation watermark is malformed (fails closed)",
        (await code2(function () { return ca.generateClientCert({ cn: "x" }); })) === "mtls-ca/watermark-unreadable");
  // A partially-numeric watermark must NOT parseInt to a lower prefix.
  fs.writeFileSync(ca.paths.revokedGeneration, "1junk");
  check("issuance aborts on a partially-numeric watermark (no parseInt prefix)",
        (await code2(function () { return ca.generateClientCert({ cn: "y" }); })) === "mtls-ca/watermark-unreadable");
}

// importIssuance() backfills leaf identities the ledger doesn't have (pre-#532 /
// out-of-band certs), so revokeGeneration() can then sweep them.
async function testImportIssuanceBackfill() {
  var ca = _newCa();
  await ca.initCA();
  var fp = "ab".repeat(64);   // a 128-hex fingerprint of a pre-existing leaf
  var res = await ca.importIssuance([{ fingerprint: fp, generation: 1 }]);
  check("importIssuance reports the imported count", res.imported === 1);
  await ca.rotate({ generation: 2 });
  check("revokeGeneration revokes an imported pre-upgrade cert", (await ca.revokeGeneration(2)).revoked === 1);
  check("the imported cert is now revoked by fingerprint", ca.isRevoked(fp) === true);
  check("importIssuance rejects a non-array", code(function () { ca.importIssuance("nope"); }) === "mtls-ca/bad-import");
  check("importIssuance rejects an entry without a generation",
        code(function () { ca.importIssuance([{ fingerprint: fp }]); }) === "mtls-ca/bad-import");
}

// loadTrustBundle() must tolerate a concurrent removal of ca.prev.crt between its
// existsSync and its read (a dropRetained()/retainPrevious:false on another
// process) and return the still-valid current CA rather than throwing ENOENT.
async function testLoadTrustBundleToleratesConcurrentPrevRemoval() {
  var atomicFile = require("../../lib/atomic-file");
  var ca = _newCa();
  await ca.initCA();
  await ca.rotate({ generation: 2 });   // ca.prev.crt exists
  var realRead = atomicFile.fdSafeReadSync;
  atomicFile.fdSafeReadSync = function (p) {
    if (String(p) === String(ca.paths.caCertPrev)) { var err = new Error("ENOENT"); err.code = "ENOENT"; throw err; }
    return realRead.apply(this, arguments);
  };
  var bundle;
  try { bundle = (await ca.loadTrustBundle()); } finally { atomicFile.fdSafeReadSync = realRead; }
  check("loadTrustBundle tolerates a concurrent retained-root removal (returns current CA, no throw)",
        bundle.length === 1);
}

// importIssuance() of a leaf whose generation is already revoked (below the
// watermark) must revoke it — the completed sweep won't see the late append.
async function testImportOfRevokedGenerationIsRevoked() {
  var ca = _newCa();
  await ca.initCA();
  await ca.generateClientCert({ cn: "gen1" });
  await ca.rotate({ generation: 2 });
  await ca.revokeGeneration(2);   // watermark = 2
  var fp = "cd".repeat(64);
  var res = await ca.importIssuance([{ fingerprint: fp, generation: 1 }]);
  check("importIssuance revokes an imported cert of an already-revoked generation",
        res.revoked === 1 && ca.isRevoked(fp) === true);
}

// A rotation publishes the CA key and cert as two separate file renames, so a
// crash BETWEEN them (or a power loss during the retained-root fsyncs) leaves
// the new key beside the old cert with the in-memory catch rollback never run —
// the prior key would be unrecoverable and the CA stuck (mtls-ca/ca-pair-
// inconsistent). commit() guards this by writing a durable rollback journal of
// the prior key before overwriting it; initCA()/_rotateImpl() reconcile from it.
async function testInterruptedRotationRecoversFromJournal() {
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await ca.initCA();
  var keyG1  = fs.readFileSync(ca.paths.caKey);
  var certG1 = fs.readFileSync(ca.paths.caCert);
  await ca.rotate({ generation: 2 });
  var keyG2  = fs.readFileSync(ca.paths.caKey);
  var certG2 = fs.readFileSync(ca.paths.caCert);
  var journal = ca.paths.caKey + ".rollback";

  // Case 1 — crash AFTER the key rename, BEFORE the cert rename: the live key is
  // the new (gen-2) key, the cert is still the old (gen-1) one, and the journal
  // holds the prior (gen-1) key. A fresh handle must roll BACK to the consistent
  // gen-1 pair so the CA (able to issue leaves and CRLs) survives.
  fs.writeFileSync(ca.paths.caCert, certG1);   // cert never got published (live == journal's prior => interrupted)
  fs.writeFileSync(journal, _journalManifest({
    key: keyG1, newKey: keyG2, cert: certG1, retainAfter: true, prevAction: "delete", prevData: null,
  }));
  var reopened = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  var leaf = await reopened.generateClientCert({ cn: "after-crash" });
  check("interrupted rotation: the handle recovers and issues after reconciling the rollback journal",
        typeof leaf.cert === "string");
  check("interrupted rotation: the live CA key is restored to the prior (gen-1) key",
        fs.readFileSync(reopened.paths.caKey).equals(keyG1));
  check("interrupted rotation: the spent rollback journal is removed",
        fs.existsSync(journal) === false);

  // Case 2 — crash AFTER the cert rename, BEFORE the journal delete: the new pair
  // is consistent on disk but a stale journal lingers. Recovery must roll FORWARD
  // (keep gen-2, drop the journal), never revert a completed rotation.
  var dir2 = _mkTmp();
  var ca2 = b.mtlsCa.create({ dataDir: dir2, caKeySealedMode: "disabled" });
  await ca2.initCA();
  var priorKey2 = fs.readFileSync(ca2.paths.caKey);
  var certG1b   = fs.readFileSync(ca2.paths.caCert);
  await ca2.rotate({ generation: 2 });
  var keyG2b  = fs.readFileSync(ca2.paths.caKey);
  var journal2 = ca2.paths.caKey + ".rollback";
  // Live cert (gen-2) differs from the journal's prior cert (gen-1) => COMPLETED.
  fs.writeFileSync(journal2, _journalManifest({
    key: priorKey2, newKey: keyG2b, cert: certG1b, retainAfter: true, prevAction: "delete", prevData: null,
  }));
  var reopened2 = b.mtlsCa.create({ dataDir: dir2, caKeySealedMode: "disabled" });
  await reopened2.initCA();
  check("stale journal over a consistent new pair rolls forward: key stays gen-2",
        fs.readFileSync(reopened2.paths.caKey).equals(keyG2b));
  check("stale journal over a consistent new pair is dropped",
        fs.existsSync(journal2) === false);
  check("roll-forward: the gen-2 CA still issues",
        typeof (await reopened2.generateClientCert({ cn: "roll-fwd" })).cert === "string");

  // Keep certG2 referenced so the fixture stays self-documenting.
  check("interrupted-rotation fixture used two distinct generations",
        !certG2.equals(certG1) && !keyG2.equals(keyG1));
}

// An interrupted rotation must recover the RETAINED ROOT too, not just the key.
// commit() overwrites ca.prev.crt with the outgoing cert before the final cert
// rename, so a crash between them (with only a key-recovery journal) would roll
// the active cert back but leave ca.prev.crt clobbered — dropping trust for
// clients still enrolled under the formerly-retained generation. The rollback
// journal is a manifest carrying the prior key AND the prior retained root.
async function testInterruptedRotationRecoversRetainedRoot() {
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await ca.initCA();
  var certG1 = fs.readFileSync(ca.paths.caCert);            // becomes the retained root after gen-2
  await ca.rotate({ generation: 2 });                        // ca.prev.crt = certG1 (retained root P)
  var keyG2  = fs.readFileSync(ca.paths.caKey);
  var certG2 = fs.readFileSync(ca.paths.caCert);
  await ca.dropRetained();                                   // end the gen-1 window (only one at a time)
  await ca.rotate({ generation: 3 });                        // gives us a real gen-3 key to pose as "new"
  var keyG3  = fs.readFileSync(ca.paths.caKey);
  var journal = ca.paths.caKey + ".rollback";

  // Fabricate a crash DURING a gen-2 -> gen-3 rotation, AFTER the retained-root
  // update (ca.prev.crt overwritten with the outgoing gen-2 cert) but BEFORE the
  // cert rename: the live key is gen-3, the cert is still gen-2, the retained root
  // was clobbered from certG1 to certG2, and the manifest journals the prior key
  // (gen-2) plus the prior retained root (certG1) to restore.
  fs.writeFileSync(ca.paths.caKey, keyG3);                   // new key published
  fs.writeFileSync(ca.paths.caCert, certG2);                 // cert never got published (live == prior => interrupted)
  fs.writeFileSync(ca.paths.caCertPrev, certG2);             // retained root clobbered (bug surface)
  fs.writeFileSync(journal, _journalManifest({
    key: keyG2, newKey: keyG3, cert: certG2, retainAfter: false, prevAction: "restore", prevData: certG1,
  }));

  var reopened = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  var leaf = await reopened.generateClientCert({ cn: "after-prev-crash" });
  check("interrupted 2nd rotation: the handle recovers and issues", typeof leaf.cert === "string");
  check("interrupted 2nd rotation: the live CA key is rolled back to gen-2",
        fs.readFileSync(reopened.paths.caKey).equals(keyG2));
  check("interrupted 2nd rotation: the retained root is restored (formerly-retained clients keep trust)",
        fs.readFileSync(reopened.paths.caCertPrev).equals(certG1));
  var bundle = (await reopened.loadTrustBundle());
  check("interrupted 2nd rotation: trust bundle is [gen-2 current, gen-1 retained]",
        bundle.length === 2 &&
        Buffer.from(bundle[0]).equals(certG2) && Buffer.from(bundle[1]).equals(certG1));
  check("interrupted 2nd rotation: the spent journal is removed",
        fs.existsSync(journal) === false);
  // keep keyG3 referenced (it is the fabricated new key)
  check("interrupted 2nd rotation fixture: gen-3 key differed from gen-2", !keyG3.equals(keyG2));
}

// A PRESENT issuance ledger with a corrupt schema (valid JSON but no `issued`
// array — an accidental `{}`) MUST fail closed, not be treated as an empty
// ledger. Silently treating it as empty would let the next issuance overwrite it
// with only the new entry, permanently dropping every prior certificate from the
// SOLE index revokeGeneration() consults (those certs would survive revocation).
async function testCorruptIssuanceLedgerSchemaFailsClosed() {
  var ca = _newCa();
  await ca.initCA();
  var first = await ca.generateClientCert({ cn: "ledger-1" });
  check("issuance ledger recorded the first cert", ca.isRevoked(first.fingerprint) === false && typeof first.cert === "string");
  var ledgerBefore = fs.readFileSync(ca.paths.issuance);

  // Corrupt: valid JSON, wrong schema (no `issued` array).
  fs.writeFileSync(ca.paths.issuance, "{}");
  check("revokeGeneration fails closed on a schema-corrupt ledger (not treated as empty)",
        (await code2(function () { return ca.revokeGeneration(2); })) === "mtls-ca/issuance-corrupt");
  check("issuance fails closed on a schema-corrupt ledger rather than overwriting it",
        (await code2(function () { return ca.generateClientCert({ cn: "ledger-2" }); }))
          === "mtls-ca/issuance-ledger-write-failed");
  check("the corrupt ledger was NOT overwritten (prior certs not silently dropped)",
        fs.readFileSync(ca.paths.issuance).toString() === "{}");

  // A non-array `issued` is also corruption, and a valid ledger still reads.
  fs.writeFileSync(ca.paths.issuance, JSON.stringify({ issued: "nope" }));
  check("a non-array `issued` is corruption too",
        (await code2(function () { return ca.revokeGeneration(2); })) === "mtls-ca/issuance-corrupt");
  fs.writeFileSync(ca.paths.issuance, ledgerBefore);
  check("restoring a well-formed ledger clears the corruption",
        (await code2(function () { return ca.revokeGeneration(2); })) === "NO-THROW");
}

// retainPrevious:false is a HARD trust cutoff: if the old retained root cannot be
// removed (a read-only / blocked ca.prev.crt), the rotation must abort rather than
// publish a new CA while loadTrustBundle() keeps trusting a root the operator
// asked to cut — which would keep admitting certs chained to it.
async function testRotateRetainFalseAbortsWhenRemovalFails() {
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await ca.initCA();
  await ca.rotate({ generation: 2 });                        // ca.prev.crt = gen-1 (a retained root exists)
  check("a retained root exists before the hard-cutoff rotation", (await ca.loadTrustBundle()).length === 2);
  var keyBefore  = fs.readFileSync(ca.paths.caKey);
  var certBefore = fs.readFileSync(ca.paths.caCert);
  // The retained-root REMOVAL fails (a read-only ca.prev.crt directory). The prev is
  // readable (captured for rollback), but its unlink fails -> the hard cutoff cannot
  // be established, so the rotation aborts rather than publishing a new CA while
  // loadTrustBundle() keeps trusting a root the operator asked to cut.
  var realUnlink = fs.unlinkSync;
  fs.unlinkSync = function (p) {
    if (String(p) === String(ca.paths.caCertPrev)) throw new Error("simulated retained-root removal failure");
    return realUnlink.apply(this, arguments);
  };
  var codeSeen;
  try { codeSeen = await code2(function () { return ca.rotate({ generation: 3, retainPrevious: false }); }); }
  finally { fs.unlinkSync = realUnlink; }
  check("rotate({retainPrevious:false}) aborts when the old root cannot be removed", codeSeen === "mtls-ca/commit-failed");
  check("the CA survived the aborted hard-cutoff rotation (still gen-2)", ca.status().generation === 2);
  check("the CA key and cert are unchanged after the aborted hard-cutoff",
        fs.readFileSync(ca.paths.caKey).equals(keyBefore) && fs.readFileSync(ca.paths.caCert).equals(certBefore));
  check("the surviving CA still issues after the aborted hard-cutoff",
        typeof (await ca.generateClientCert({ cn: "post-cutoff-abort" })).cert === "string");
}

// canVerifyInTls() with no argument derives the label from the stored CA. A custom
// CA this runtime cannot classify (status().algorithm === null) with no create-time
// pin leaves the label undefined; probing the engine with undefined would let one
// that reads an omitted label as "current default" answer for the WRONG algorithm.
// Require an explicit algorithm instead of silently probing undefined.
async function testCanVerifyInTlsRequiresLabelWhenUndeterminable() {
  var dir = _mkTmp();
  var probed = [];
  var eng = _p256CaEngine();
  eng.canVerifyInTls = async function (label) { probed.push(label); return true; };
  var ca = b.mtlsCa.create({ dataDir: dir, engine: eng, caKeySealedMode: "disabled" });
  await ca.initCA();
  check("a P-256 custom CA reports algorithm null (runtime cannot classify it)", ca.status().algorithm === null);
  check("canVerifyInTls() with no argument refuses rather than probing an undeterminable algorithm",
        (await code2(function () { return ca.canVerifyInTls(); })) === "mtls-ca/algorithm-undeterminable");
  check("the engine was NOT probed with an undefined label", probed.indexOf(undefined) === -1);
  var ok = await ca.canVerifyInTls("ECDSA-P384-SHA384");     // an explicit algorithm still delegates
  check("canVerifyInTls(explicit) still delegates to the engine",
        ok === true && probed[probed.length - 1] === "ECDSA-P384-SHA384");
}

// Clustered operation (shared revocationStore + watermark, per-host dataDirs) also
// requires a shared issuanceStore: with the default per-host ledger, revokeGeneration()
// on one host cannot see certs issued on another, leaving them accepted by the shared
// gate. Refuse the fail-open split at construction.
async function testClusteredRevocationStoreRequiresSharedIssuanceStore() {
  function clusteredRevStore() {
    return {
      list: function () { return []; }, add: function () {},
      readGenerationWatermark: function () { return 0; },
      bumpGenerationWatermark: function () {},
    };
  }
  check("a clustered revocationStore without a shared issuanceStore is refused at construction",
        code(function () {
          b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled", revocationStore: clusteredRevStore() });
        }) === "mtls-ca/bad-issuance-store");
  check("a clustered revocationStore WITH a shared issuanceStore is accepted",
        code(function () {
          b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled",
            revocationStore: clusteredRevStore(),
            issuanceStore: { list: function () { return []; }, add: function () {} } });
        }) === "NO-THROW");
  check("a non-clustered revocationStore still accepts the default per-host ledger",
        code(function () {
          b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled",
            revocationStore: { list: function () { return []; }, add: function () {} } });
        }) === "NO-THROW");
}

// loadTrustBundle() must never advertise the same root twice: a degenerate state
// where ca.prev.crt == ca.crt (a crash-recovered rollback, or the mixed-snapshot
// race this guards) must dedup to a single-entry bundle rather than [cur, cur].
async function testLoadTrustBundleDedupsIdenticalRetainedRoot() {
  var ca = _newCa();
  await ca.initCA();
  var cur = fs.readFileSync(ca.paths.caCert);
  fs.writeFileSync(ca.paths.caCertPrev, cur);           // ca.prev.crt identical to ca.crt
  var bundle = (await ca.loadTrustBundle());
  check("loadTrustBundle dedups an identical retained root (no [cur, cur])",
        bundle.length === 1 && Buffer.from(bundle[0]).equals(cur));
  fs.rmSync(ca.paths.caCertPrev, { force: true });      // clear the fabricated dup before a real rotation
  await ca.rotate({ generation: 2 });                   // a genuinely-distinct retained root still appears
  check("loadTrustBundle returns [current, retained] for a real retained rotation",
        (await ca.loadTrustBundle()).length === 2);
}

// Only ONE retained grace window at a time: ca.prev.crt holds a single prior root,
// so a second RETAINED rotation would overwrite it and strand clients still under
// the first retained generation. Refuse it until the window is ended explicitly.
async function testRefuseConsecutiveRetainedRotations() {
  var ca = _newCa();
  await ca.initCA();
  await ca.rotate({ generation: 2 });                        // retains gen-1
  check("a retained root exists after the first retained rotation", (await ca.loadTrustBundle()).length === 2);
  check("a second retained rotation is refused while a root is retained",
        (await code2(function () { return ca.rotate({ generation: 3 }); })) === "mtls-ca/retained-root-exists");
  check("the refused rotation left the CA at gen-2 with its retained root intact",
        ca.status().generation === 2 && (await ca.loadTrustBundle()).length === 2);
  // Ending the window (dropRetained) lets a retained rotation proceed.
  await ca.dropRetained();
  check("after dropRetained, a retained rotation proceeds",
        (await ca.rotate({ generation: 3 })).generation === 3);
  // rotate({ retainPrevious: false }) is always allowed (it hard-cuts the old root).
  await ca.rotate({ generation: 4, retainPrevious: false });
  check("a hard-cut rotation is allowed even while a root is retained", ca.status().generation === 4);
}

// A rotation must ABORT when an existing CA key cannot be captured for the rollback
// journal — proceeding would leave no way to restore the old key if the cert
// publish then fails, stranding the CA on a new-key/old-cert pair.
async function testRotateAbortsWhenPriorKeyUnreadable() {
  var atomicFile = require("../../lib/atomic-file");
  var ca = _newCa();
  await ca.initCA();
  var keyBefore  = fs.readFileSync(ca.paths.caKey);
  var certBefore = fs.readFileSync(ca.paths.caCert);
  var realRead = atomicFile.fdSafeReadSync;
  atomicFile.fdSafeReadSync = function (p) {
    if (String(p) === String(ca.paths.caKey)) throw new Error("simulated transient key read failure");
    return realRead.apply(this, arguments);
  };
  var codeSeen;
  try { codeSeen = await code2(function () { return ca.rotate({ generation: 2 }); }); }
  finally { atomicFile.fdSafeReadSync = realRead; }
  check("rotation aborts when the prior key cannot be captured", codeSeen === "mtls-ca/prior-key-unreadable");
  check("the original key and cert are untouched after the aborted rotation",
        fs.readFileSync(ca.paths.caKey).equals(keyBefore) && fs.readFileSync(ca.paths.caCert).equals(certBefore));
  check("the CA still issues after the aborted rotation",
        typeof (await ca.generateClientCert({ cn: "post-keyread-abort" })).cert === "string");
}

// loadTrustBundle() must include a retained root that a crashed rotation left only
// in the rollback journal (before any initCA()/rotate() reconciled it), so a
// restart that loads trust without first reconciling does not drop that cohort.
async function testLoadTrustBundleIncludesUnreconciledJournalRoot() {
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await ca.initCA();
  var certG1 = fs.readFileSync(ca.paths.caCert);
  await ca.rotate({ generation: 2 });                        // gen-2 active, gen-1 retained
  var keyG2  = fs.readFileSync(ca.paths.caKey);
  var certG2 = fs.readFileSync(ca.paths.caCert);
  await ca.dropRetained();
  await ca.rotate({ generation: 3 });
  var keyG3 = fs.readFileSync(ca.paths.caKey);
  // Fabricate a crashed retainPrevious:false rotation (gen-2 -> gen-3) that
  // journaled gen-1 as the root to restore, then unlinked ca.prev.crt, then died
  // before publishing the cert: the live cert is gen-2, ca.prev.crt is gone, and
  // the journal holds gen-1.
  fs.writeFileSync(ca.paths.caKey, keyG3);
  fs.writeFileSync(ca.paths.caCert, certG2);
  fs.rmSync(ca.paths.caCertPrev, { force: true });
  fs.writeFileSync(ca.paths.caKey + ".rollback", JSON.stringify({
    key: keyG2.toString("base64"), cert: certG2.toString("base64"),  // live cert == journal's prior cert => interrupted
    prevAction: "restore", prevData: certG1.toString("base64"),
  }));
  var reopened = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  var bundle = (await reopened.loadTrustBundle());                   // called BEFORE any initCA reconcile
  check("loadTrustBundle includes the current cert and the journal's retained root (no dropped cohort)",
        bundle.length === 2 &&
        Buffer.from(bundle[0]).equals(certG2) && Buffer.from(bundle[1]).equals(certG1));
}

// A SPENT journal — the rotation COMPLETED (including a hard cutoff) but its delete
// failed, so the live cert differs from the journal's recorded prior cert — must
// NOT re-trust its old retained root, which would defeat the completed cutoff and
// which dropRetained() cannot clear.
async function testLoadTrustBundleExcludesSpentJournalRoot() {
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await ca.initCA();
  var certG1 = fs.readFileSync(ca.paths.caCert);
  await ca.rotate({ generation: 2 });
  var certG2 = fs.readFileSync(ca.paths.caCert);
  await ca.dropRetained();
  await ca.rotate({ generation: 3 });                        // gen-3 active, gen-2 retained
  // Leftover SPENT journal from a completed hard-cut rotation: its recorded prior
  // cert is gen-2, but the live cert is gen-3, so the rotation republished
  // (completed). The key bytes are irrelevant to the trust-bundle read.
  fs.writeFileSync(ca.paths.caKey + ".rollback", JSON.stringify({
    key: fs.readFileSync(ca.paths.caKey).toString("base64"), cert: certG2.toString("base64"),
    prevAction: "restore", prevData: certG1.toString("base64"),
  }));
  var reopened = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  var bundle = (await reopened.loadTrustBundle());
  check("loadTrustBundle excludes a spent journal's old retained root (hard cutoff respected)",
        bundle.every(function (c) { return !Buffer.from(c).equals(certG1); }));
}

// A hard-cut rotation whose cert publish fails AND whose in-memory retained-root
// rollback also fails must KEEP the journal (not delete it on a successful key
// rollback alone), so a later reconcile restores the retained root from the
// journal's prevData rather than permanently losing that cohort's trust.
async function testPartialRollbackKeepsJournalForRetainedRoot() {
  var atomicFile = require("../../lib/atomic-file");
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await ca.initCA();
  var certG1 = fs.readFileSync(ca.paths.caCert);
  await ca.rotate({ generation: 2 });                        // gen-2 active, gen-1 retained (ca.prev.crt = gen-1)
  var certG2 = fs.readFileSync(ca.paths.caCert);
  // A hard-cut rotation to gen-3 that (a) fails the cert publish and (b) fails to
  // restore ca.prev.crt during rollback: key rollback succeeds, prev rollback does
  // not. The journal must survive so the retained root is recoverable.
  var realRename = atomicFile.renameWithRetry;
  var realWrite  = atomicFile.writeSync;
  atomicFile.renameWithRetry = function (from, to) {
    if (String(to) === String(ca.paths.caCert)) throw new Error("simulated cert rename failure");
    return realRename.apply(this, arguments);
  };
  atomicFile.writeSync = function (p) {
    if (String(p) === String(ca.paths.caCertPrev)) throw new Error("simulated retained-root restore failure");
    return realWrite.apply(this, arguments);
  };
  var failed = false;
  try {
    try { await ca.rotate({ generation: 3, retainPrevious: false }); } catch (_e) { failed = true; }
  } finally { atomicFile.renameWithRetry = realRename; atomicFile.writeSync = realWrite; }
  check("the hard-cut rotation with a failed cert publish is rejected", failed);
  check("the rollback journal is preserved when the retained-root restore failed",
        fs.existsSync(ca.paths.caKey + ".rollback") === true);
  // A fresh handle reconciles: the live cert still equals the journal's prior cert
  // (gen-2, never republished), so it rolls back and restores gen-1 as the root.
  var reopened = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await reopened.initCA();
  check("reconcile restored the retained root from the preserved journal",
        fs.existsSync(reopened.paths.caCertPrev) && fs.readFileSync(reopened.paths.caCertPrev).equals(certG1));
  check("the recovered CA still issues under gen-2",
        typeof (await reopened.generateClientCert({ cn: "post-partial-rollback" })).cert === "string" &&
        fs.readFileSync(reopened.paths.caCert).equals(certG2));
}

// The rollback journal must hold a COMPLETE snapshot of the pre-rotation state.
// If the existing current cert cannot be read for the journal's prior-cert marker,
// commit() aborts before mutating — otherwise a cert:null journal would break the
// interrupted-vs-completed comparison and mis-reconcile the retained root.
async function testCommitAbortsWhenPriorCertUnreadable() {
  var atomicFile = require("../../lib/atomic-file");
  var ca = _newCa();
  await ca.initCA();
  var fresh = await engine.generateCa({ generation: 2 });
  var realRead = atomicFile.fdSafeReadSync;
  atomicFile.fdSafeReadSync = function (p) {
    if (String(p) === String(ca.paths.caCert)) throw new Error("simulated prior-cert read failure");
    return realRead.apply(this, arguments);
  };
  var codeSeen;
  try { codeSeen = await code2(function () { return ca.commit({ caKeyPem: fresh.caKeyPem, caCertPem: fresh.caCertPem }); }); }
  finally { atomicFile.fdSafeReadSync = realRead; }
  check("commit aborts when the prior cert cannot be captured", codeSeen === "mtls-ca/prior-cert-unreadable");
  check("the CA still issues after the aborted commit (untouched)",
        typeof (await ca.generateClientCert({ cn: "post-cert-abort" })).cert === "string");
}

// If an existing retained root cannot be read for the rollback journal, commit()
// aborts before mutating — otherwise a failed hard-cut rotation could remove it
// with neither the catch nor a reconcile able to restore it, permanently stranding
// clients in the existing grace window.
async function testCommitAbortsWhenPriorRetainedRootUnreadable() {
  var atomicFile = require("../../lib/atomic-file");
  var ca = _newCa();
  await ca.initCA();
  await ca.rotate({ generation: 2 });                        // ca.prev.crt = gen-1
  var fresh = await engine.generateCa({ generation: 3 });
  var realRead = atomicFile.fdSafeReadSync;
  atomicFile.fdSafeReadSync = function (p) {
    if (String(p) === String(ca.paths.caCertPrev)) throw new Error("simulated prior-retained-root read failure");
    return realRead.apply(this, arguments);
  };
  // Hard-cut (retainPrevious:false) is the scenario the abort protects: it needs the
  // prior retained root for its rollback, so an unreadable one must abort before
  // mutating. (An omitted retainPrevious would be refused earlier as ambiguous.)
  var codeSeen;
  try {
    codeSeen = await code2(function () {
      return ca.commit({ caKeyPem: fresh.caKeyPem, caCertPem: fresh.caCertPem, retainPrevious: false });
    });
  }
  finally { atomicFile.fdSafeReadSync = realRead; }
  check("commit aborts when the prior retained root cannot be captured",
        codeSeen === "mtls-ca/prior-retained-root-unreadable");
  check("the retained root and CA survive the aborted commit",
        (await ca.loadTrustBundle()).length === 2 &&
        typeof (await ca.generateClientCert({ cn: "post-prev-abort" })).cert === "string");
}

// dropRetained() must reconcile an interrupted rotation's journal under its lock
// before removing the retained root — otherwise a crashed hard-cut rotation (which
// removed ca.prev.crt but left a journal whose recorded root loadTrustBundle()
// still trusts) would survive dropRetained(), so the grace window never ends.
async function testDropRetainedReconcilesInterruptedJournal() {
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await ca.initCA();
  var certG1 = fs.readFileSync(ca.paths.caCert);
  await ca.rotate({ generation: 2 });
  var certG2 = fs.readFileSync(ca.paths.caCert);
  var keyG2  = fs.readFileSync(ca.paths.caKey);
  await ca.dropRetained();
  await ca.rotate({ generation: 3 });
  // Fabricate an interrupted hard-cut rotation (gen-2 -> gen-3): a consistent gen-2
  // pair on disk, ca.prev.crt gone, and a journal (prior cert gen-2 == live cert)
  // holding gen-1 as the root to restore.
  fs.writeFileSync(ca.paths.caKey, keyG2);
  fs.writeFileSync(ca.paths.caCert, certG2);
  fs.rmSync(ca.paths.caCertPrev, { force: true });
  fs.writeFileSync(ca.paths.caKey + ".rollback", JSON.stringify({
    key: keyG2.toString("base64"), cert: certG2.toString("base64"),
    prevAction: "restore", prevData: certG1.toString("base64"),
  }));
  var reopened = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  check("interrupted journal surfaces the retained root before dropRetained",
        (await reopened.loadTrustBundle()).some(function (c) { return Buffer.from(c).equals(certG1); }));
  await reopened.dropRetained();
  check("dropRetained reconciles the journal and truly ends the grace window",
        (await reopened.loadTrustBundle()).every(function (c) { return !Buffer.from(c).equals(certG1); }) &&
        fs.existsSync(reopened.paths.caKey + ".rollback") === false);
}

// Reconcile must restore the prior key by BYTES, not gate on _caPairConsistent —
// which returns true for a custom-engine cert/key node cannot parse, so gating on
// it would skip the restore and strand (then permanently brick) a custom-engine CA.
async function testCustomEngineReconcileRestoresKeyByBytes() {
  var dir = _mkTmp();
  var opaqueEngine = {   // node cannot parse these -> _caPairConsistent would say "consistent"
    generateCa: async function (a) {
      return { caCertPem: "OPAQUE-CERT-gen" + a.generation, caKeyPem: "OPAQUE-KEY-gen" + a.generation };
    },
  };
  var ca = b.mtlsCa.create({ dataDir: dir, engine: opaqueEngine, caKeySealedMode: "disabled" });
  await ca.initCA();
  var oldKey  = fs.readFileSync(ca.paths.caKey);
  var oldCert = fs.readFileSync(ca.paths.caCert);
  var newKey  = Buffer.from("OPAQUE-KEY-gen2-NEW");
  // Crash after the key rename, before the cert rename: new key beside old cert.
  fs.writeFileSync(ca.paths.caKey, newKey);
  fs.writeFileSync(ca.paths.caKey + ".rollback", _journalManifest({
    key: oldKey, newKey: newKey, cert: oldCert, retainAfter: false, prevAction: "delete", prevData: null,
  }));
  var reopened = b.mtlsCa.create({ dataDir: dir, engine: opaqueEngine, caKeySealedMode: "disabled" });
  await reopened.initCA();   // triggers the locked reconcile
  check("custom-engine reconcile restores the prior key by BYTES (not gated on _caPairConsistent)",
        fs.readFileSync(reopened.paths.caKey).equals(oldKey));
  check("the custom-engine interrupted rotation rolled back the cert unchanged",
        fs.readFileSync(reopened.paths.caCert).equals(oldCert));
}

// An UNPINNED rotation over an existing CA must PRESERVE the stored algorithm, not
// silently adopt the engine default (ML-DSA-87) — otherwise a bare generation bump
// would flip a classical ECDSA CA to ML-DSA and reject legacy peers.
async function testUnpinnedRotatePreservesStoredAlgorithm() {
  var dir = _mkTmp();
  var pinned = b.mtlsCa.create({ dataDir: dir, algorithm: "ECDSA-P384-SHA384", caKeySealedMode: "disabled" });
  await pinned.initCA();
  check("stored CA is ECDSA before rotation", pinned.status().algorithm === "ECDSA-P384-SHA384");
  var unpinned = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });   // no create-time pin
  var r = await unpinned.rotate({ generation: 2 });                                 // unpinned rotate
  check("unpinned rotate over an ECDSA CA stays ECDSA (no silent flip to ML-DSA)",
        r.algorithm === "ECDSA-P384-SHA384" && unpinned.status().algorithm === "ECDSA-P384-SHA384");
  check("the rotated ECDSA CA still issues",
        typeof (await unpinned.generateClientCert({ cn: "post-unpinned-rotate" })).cert === "string");
}

// A hard-cut rotation supersedes the old generation like revokeGeneration: an
// issuance that straddles it (signed under the now-untrusted old generation) must
// self-revoke rather than return an un-verifiable leaf.
async function testHardCutRotationSupersedesStraddlingIssuance() {
  var release; var barrier = new Promise(function (r) { release = r; });
  var slowEngine = Object.assign({}, engine, {
    signClientCert: async function (a) { await barrier; return engine.signClientCert(a); },
  });
  var ca = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled", engine: slowEngine });
  await ca.initCA();                                          // gen-1
  var issuing = ca.generateClientCert({ cn: "straddle" });   // blocks in signing under gen-1
  await ca.rotate({ generation: 2, retainPrevious: false }); // hard cut supersedes gen-1
  release();
  check("a leaf straddling a hard-cut rotation self-revokes (issuance-superseded)",
        (await code2(function () { return issuing; })) === "mtls-ca/issuance-superseded");
}

// A leaf whose signing began under a generation that is then RETAINED-rotated and
// dropRetained() before issuance finishes chains to a root no longer in the trust
// bundle — it must self-revoke rather than return un-verifiable.
async function testDropRetainedSupersedesStraddlingIssuance() {
  var release; var barrier = new Promise(function (r) { release = r; });
  var slowEngine = Object.assign({}, engine, {
    signClientCert: async function (a) { await barrier; return engine.signClientCert(a); },
  });
  var ca = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled", engine: slowEngine });
  await ca.initCA();                                          // gen-1
  var issuing = ca.generateClientCert({ cn: "straddle-drop" }); // signs under gen-1, blocks
  await ca.rotate({ generation: 2 });                        // gen-1 becomes the retained root
  await ca.dropRetained();                                   // removes gen-1 entirely
  release();
  check("a leaf straddling a rotate + dropRetained (its root dropped) self-revokes",
        (await code2(function () { return issuing; })) === "mtls-ca/issuance-superseded");
}

// A leaf issued under the CURRENT generation with no concurrent removal is NOT
// falsely superseded (its root stays in the trust bundle).
async function testNormalIssuanceNotFalselySuperseded() {
  var ca = _newCa();
  await ca.initCA();
  check("a normal issuance under the current CA is not falsely superseded",
        typeof (await ca.generateClientCert({ cn: "normal" })).cert === "string");
  await ca.rotate({ generation: 2 });   // retained rotation keeps gen-1 in the bundle
  check("issuance under the new generation after a retained rotation is not superseded",
        typeof (await ca.generateClientCert({ cn: "normal-2" })).cert === "string");
}

// Concurrent first-time inits must converge on ONE CA (serialized), not each
// generate a CA and clobber one another (orphaning the loser's just-issued leaf).
async function testConcurrentFirstInitDoesNotClobber() {
  var release; var barrier = new Promise(function (r) { release = r; });
  var genCount = 0;
  var slowEngine = Object.assign({}, engine, {
    generateCa: async function (a) { genCount += 1; await barrier; return engine.generateCa(a); },
  });
  var ca = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled", engine: slowEngine });
  var p1 = ca.initCA();
  var p2 = ca.initCA();
  release();
  var r1 = await p1; var r2 = await p2;
  check("concurrent first inits converge on ONE CA (no clobber)", r1.caCertPem === r2.caCertPem);
  check("first-time creation is serialized (one keygen, not two)", genCount === 1);
  check("the CA issues after concurrent init",
        typeof (await ca.generateClientCert({ cn: "post-concurrent-init" })).cert === "string");
}

// A COMPLETED rotation whose key rename didn't durably stick (a Windows/FUSE
// fsyncDir no-op) must be FINISHED from the journal's new key, not left on an
// old-key/new-cert pair the OLD-key-only journal could not repair.
async function testReconcileFinishesCompletedRotationWithLostKey() {
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await ca.initCA();
  var keyG1 = fs.readFileSync(ca.paths.caKey);
  var certG1 = fs.readFileSync(ca.paths.caCert);
  await ca.rotate({ generation: 2 });
  var keyG2 = fs.readFileSync(ca.paths.caKey);
  var certG2 = fs.readFileSync(ca.paths.caCert);
  // Completed gen-1 -> gen-2 (live cert = gen-2) but the key rename was lost (old key).
  fs.writeFileSync(ca.paths.caKey, keyG1);
  fs.writeFileSync(ca.paths.caKey + ".rollback", _journalManifest({
    key: keyG1, newKey: keyG2, cert: certG1, retainAfter: true, prevAction: "delete", prevData: null,
  }));
  var reopened = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await reopened.initCA();
  check("reconcile finishes a completed rotation whose key rename was lost (restores the new key)",
        fs.readFileSync(reopened.paths.caKey).equals(keyG2) && fs.readFileSync(reopened.paths.caCert).equals(certG2));
  check("the finished CA issues",
        typeof (await reopened.generateClientCert({ cn: "post-lost-key" })).cert === "string");
}

// A COMPLETED hard-cut rotation whose ca.prev.crt unlink didn't durably stick must
// have the resurrected root REMOVED on reconcile — else loadTrustBundle keeps
// trusting a root the operator hard-cut.
async function testReconcileRemovesResurrectedHardCutRoot() {
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await ca.initCA();
  var certG1 = fs.readFileSync(ca.paths.caCert);
  await ca.rotate({ generation: 2 });
  var certG2 = fs.readFileSync(ca.paths.caCert);
  var keyG2 = fs.readFileSync(ca.paths.caKey);
  await ca.dropRetained();
  await ca.rotate({ generation: 3 });
  var keyG3 = fs.readFileSync(ca.paths.caKey);
  // Completed hard-cut gen-2 -> gen-3 (live cert = gen-3, retainAfter false) but the
  // ca.prev.crt unlink was lost: gen-1 resurrected as the retained root.
  fs.writeFileSync(ca.paths.caCertPrev, certG1);
  fs.writeFileSync(ca.paths.caKey + ".rollback", _journalManifest({
    key: keyG2, newKey: keyG3, cert: certG2, retainAfter: false, prevAction: "restore", prevData: certG1,
  }));
  var reopened = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await reopened.initCA();
  check("reconcile removes a resurrected hard-cut root on a completed rotation",
        fs.existsSync(reopened.paths.caCertPrev) === false &&
        (await reopened.loadTrustBundle()).every(function (c) { return !Buffer.from(c).equals(certG1); }));
}

// The single-retained-window invariant must hold on EVERY retention entry point,
// including the public commit() path (which calls _commitLocked directly) — not
// just rotate(). Two retained commits without ending the window between them would
// otherwise overwrite the retained root and strand the first cohort.
async function testPublicCommitEnforcesSingleRetainedWindow() {
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await ca.initCA();                                          // gen-1, no retained root
  var g2 = await engine.generateCa({ generation: 2 });
  await ca.commit({ caKeyPem: g2.caKeyPem, caCertPem: g2.caCertPem, retainPrevious: true });   // retains gen-1
  check("first retained public commit creates a retained root", (await ca.loadTrustBundle()).length === 2);
  var g3 = await engine.generateCa({ generation: 3 });
  check("a second retained public commit is refused (single window)",
        await code2(function () { return ca.commit({ caKeyPem: g3.caKeyPem, caCertPem: g3.caCertPem, retainPrevious: true }); })
          === "mtls-ca/retained-root-exists");
  check("the refused commit left the retained root intact", (await ca.loadTrustBundle()).length === 2);
}

// A default-engine handle with NO CA stored yet and no pin must probe the engine
// default on a no-argument canVerifyInTls() (the documented fresh-deployment
// pre-flight), NOT refuse with algorithm-undeterminable — an omitted label is
// unambiguous when there is no stored CA to mismatch.
async function testCanVerifyInTlsProbesDefaultBeforeInit() {
  var ca = _newCa();   // default engine, NOT initialized, no create-time pin
  check("no CA is stored yet", ca.status().exists === false);
  var codeSeen = await code2(function () { return ca.canVerifyInTls(); });
  check("canVerifyInTls() before init does not refuse with algorithm-undeterminable",
        codeSeen !== "mtls-ca/algorithm-undeterminable");
  var ok = await ca.canVerifyInTls();
  check("canVerifyInTls() before init probes the default engine (returns a boolean)", typeof ok === "boolean");
}

// The reconcile's journal deletion is NOT best-effort: if it fails, the caller
// (here dropRetained) must fail closed, because a surviving interrupted journal
// would let loadTrustBundle() re-trust its saved root and undo the cutoff.
async function testReconcileJournalDeletionFailurePropagates() {
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await ca.initCA();
  var certG1 = fs.readFileSync(ca.paths.caCert);
  await ca.rotate({ generation: 2 });
  var certG2 = fs.readFileSync(ca.paths.caCert);
  var keyG2  = fs.readFileSync(ca.paths.caKey);
  await ca.dropRetained();
  await ca.rotate({ generation: 3 });
  // Interrupted hard-cut journal: consistent gen-2 pair, ca.prev.crt gone, journal
  // holds gen-1 as the root to restore.
  fs.writeFileSync(ca.paths.caKey, keyG2);
  fs.writeFileSync(ca.paths.caCert, certG2);
  fs.rmSync(ca.paths.caCertPrev, { force: true });
  var journal = ca.paths.caKey + ".rollback";
  fs.writeFileSync(journal, _journalManifest({
    key: keyG2, newKey: keyG2, cert: certG2, retainAfter: false, prevAction: "restore", prevData: certG1,
  }));
  var reopened = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  var realUnlink = fs.unlinkSync;
  fs.unlinkSync = function (p) {
    if (String(p) === String(journal)) throw new Error("simulated journal deletion failure");
    return realUnlink.apply(this, arguments);
  };
  var codeSeen;
  try { codeSeen = await code2(function () { return reopened.dropRetained(); }); }
  finally { fs.unlinkSync = realUnlink; }
  check("dropRetained fails closed when the reconcile journal deletion fails", codeSeen !== "NO-THROW");
  check("the interrupted journal survives the failed deletion (not silently completed)",
        fs.existsSync(journal) === true);
}

// The public commit() is the LOCKED commit primitive (migration docs direct
// operators to it), so it returns a promise — it takes the rotation lock to
// serialize with a concurrent rotate/init over the same dataDir.
async function testPublicCommitIsLockedPromise() {
  var ca = _newCa();
  await ca.initCA();
  var g2 = await engine.generateCa({ generation: 2 });
  var p = ca.commit({ caKeyPem: g2.caKeyPem, caCertPem: g2.caCertPem, retainPrevious: false });
  check("public commit() returns a promise (the locked primitive)", p && typeof p.then === "function");
  await p;
  check("the committed CA issues", typeof (await ca.generateClientCert({ cn: "post-public-commit" })).cert === "string");
  // Bad input still throws synchronously (a config-time typo), before the lock.
  check("public commit() validates its argument shape synchronously",
        code(function () { ca.commit({}); }) === "mtls-ca/bad-commit");
}

// A persisted CRL is signed by the CA that produced it; after a rotation it is
// signed by the SUPERSEDED issuer, so rotation must invalidate it (a consumer
// serving the path must not publish a CRL the new CA cannot authenticate).
async function testRotationInvalidatesStaleCrl() {
  var ca = _newCa();
  await ca.initCA();
  await ca.generateCrl();                                     // persists ca.crl signed by gen-1
  check("a CRL is persisted before rotation", fs.existsSync(ca.paths.crl) === true);
  await ca.rotate({ generation: 2 });
  check("rotation invalidates the stale CRL signed by the superseded CA",
        fs.existsSync(ca.paths.crl) === false);
  await ca.generateCrl();                                     // operator regenerates under the new CA
  check("generateCrl re-signs the CRL under the new CA after rotation", fs.existsSync(ca.paths.crl) === true);
}

// The public commit() must reconcile a leftover journal FIRST (as rotate does),
// so a crash-left new-key/old-cert state is rolled back before the new commit —
// otherwise the commit records the ORPHANED new key as its prior key and a failed
// publish would roll back to that orphan, losing the actual matching old key.
async function testPublicCommitReconcilesLeftoverJournalFirst() {
  var atomicFile = require("../../lib/atomic-file");
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await ca.initCA();
  var keyG1 = fs.readFileSync(ca.paths.caKey);
  var certG1 = fs.readFileSync(ca.paths.caCert);
  await ca.rotate({ generation: 2 });
  var keyG2 = fs.readFileSync(ca.paths.caKey);
  // Crashed gen-1 -> gen-2: new key (gen-2) beside old cert (gen-1); journal holds gen-1.
  fs.writeFileSync(ca.paths.caCert, certG1);
  fs.rmSync(ca.paths.caCertPrev, { force: true });
  fs.writeFileSync(ca.paths.caKey + ".rollback", _journalManifest({
    key: keyG1, newKey: keyG2, cert: certG1, retainAfter: false, prevAction: "delete", prevData: null,
  }));
  var g3 = await engine.generateCa({ generation: 3 });
  var realRename = atomicFile.renameWithRetry;
  atomicFile.renameWithRetry = function (from, to) {
    if (String(to) === String(ca.paths.caCert)) throw new Error("simulated cert publish failure");
    return realRename.apply(this, arguments);
  };
  var codeSeen;
  try { codeSeen = await code2(function () { return ca.commit({ caKeyPem: g3.caKeyPem, caCertPem: g3.caCertPem, retainPrevious: false }); }); }
  finally { atomicFile.renameWithRetry = realRename; }
  check("public commit whose publish failed rolled back to the ACTUAL gen-1 key (reconciled first)",
        codeSeen === "mtls-ca/commit-failed" && fs.readFileSync(ca.paths.caKey).equals(keyG1));
  check("the CA still issues under the recovered gen-1",
        typeof (await ca.generateClientCert({ cn: "post-public-commit-fail" })).cert === "string");
}

// generateCrl() must not persist a CRL signed by a CA that ROTATED while it was
// signing — that would recreate the stale-issuer artifact the rotation invalidated.
async function testGenerateCrlSkipsPersistIfCaRotated() {
  var release; var barrier = new Promise(function (r) { release = r; });
  var slowEngine = Object.assign({}, engine, {
    generateCrl: async function (a) { await barrier; return engine.generateCrl(a); },
  });
  var ca = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled", engine: slowEngine });
  await ca.initCA();                                          // gen-1
  var crlPromise = ca.generateCrl();                          // signs under gen-1, blocks
  await ca.rotate({ generation: 2 });                         // CA rotates during signing
  release();
  var result = await crlPromise;
  check("generateCrl does NOT persist a CRL signed by a CA that rotated during signing",
        result.persisted === false && fs.existsSync(ca.paths.crl) === false);
}

// generateCrl() must not persist a CRL whose revocation snapshot a concurrent revoke()/
// revokeGeneration() has already superseded — a revocation that COMPLETED (returned
// success) while we awaited engine.generateCrl() would be dropped from the published CRL,
// so CRL-based clients keep accepting the revoked certificate until the next regeneration.
async function testGenerateCrlSkipsPersistIfRevocationLandedDuringSigning() {
  var duringSign = null;                                       // fires AFTER the snapshot, during signing
  var slowEngine = Object.assign({}, engine, {
    generateCrl: async function (a) {
      if (duringSign) { var f = duringSign; duringSign = null; await f(); }
      return engine.generateCrl(a);
    },
  });
  var ca = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled", engine: slowEngine });
  await ca.initCA();
  await ca.revoke("01");                                      // one revocation in the snapshot
  duringSign = async function () { await ca.revoke("02"); };  // a revocation COMPLETES during signing
  var result = await ca.generateCrl();                        // snapshots {01}, revokes 02 mid-sign
  check("generateCrl does NOT persist a CRL whose snapshot a concurrent revocation superseded",
        result.persisted === false && fs.existsSync(ca.paths.crl) === false);
  // A clean regeneration (no concurrent write) publishes a CRL covering every revocation.
  var result2 = await ca.generateCrl();
  check("a clean regeneration persists a CRL covering every completed revocation",
        result2.persisted === true && result2.entryCount === 2 && fs.existsSync(ca.paths.crl) === true);
}

// generateCrl() with a bring-your-own revocationStore (no version() signal) persists
// directly: the framework does not own that store's write lock, so there is no version to
// compare against a concurrent revoke() — the operator owns that store's concurrency. This
// exercises the custom-store snapshot and persist paths (no under-lock version re-check).
async function testGenerateCrlPersistsWithCustomRevocationStore() {
  var entries = [];
  var customStore = { list: function () { return entries.slice(); },
                      add: function (e) { entries.push(e); } };
  var ca = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled", revocationStore: customStore });
  await ca.initCA();
  await ca.revoke("0a");
  var result = await ca.generateCrl();
  check("generateCrl persists with a custom revocationStore (no version signal, operator-owned concurrency)",
        result.persisted === true && result.entryCount === 1 && fs.existsSync(ca.paths.crl) === true);
}

// A pinned ECDSA handle's in-flight generateClientCert() snapshots the ECDSA CA via
// initCA(); a public commit({ retainPrevious: true }) that installs an ML-DSA CA runs (and
// synchronously refreshes the handle's closed-over algorithm pin) BEFORE the suspended
// issuance reads that pin. The leaf MUST bind to the SNAPSHOTTED ECDSA CA — not the
// refreshed ML-DSA pin — else an ML-DSA leaf is minted under the retained ECDSA root and the
// grace window's legacy peers (the whole reason the root is retained) cannot authenticate it.
// commit()'s rename + pin refresh run synchronously inside atomicFile.lock, so the pin is
// already ML-DSA by the time the issuance's _leafEngineArgs microtask runs — a deterministic
// reproduction of the race, not a timing-dependent flake.
async function testLeafAlgorithmBindsToSnapshotNotRacingPinRefresh() {
  var ca = _newCa({ algorithm: "ECDSA-P384-SHA384" });
  await ca.initCA();
  check("precondition: the pinned handle stored an ECDSA CA",
        ca.status().algorithm === "ECDSA-P384-SHA384");
  var mldsa = await engine.generateCa({ generation: 2 });      // a default (ML-DSA-87) CA
  var certPromise = ca.generateClientCert({ cn: "legacy-peer" });   // snapshots the ECDSA pair
  await ca.commit({ caKeyPem: mldsa.caKeyPem, caCertPem: mldsa.caCertPem, retainPrevious: true });
  var result = await certPromise;
  var leafType = new nodeCrypto.X509Certificate(result.cert).publicKey.asymmetricKeyType;
  check("a leaf issued while commit() refreshes the pin binds to the snapshotted ECDSA CA (ec), not the ML-DSA pin",
        leafType === "ec");
}

// For a custom engine, canVerifyInTls() with no argument must use the create-time
// pin, not status()'s inferred bundled label — the engine may use a custom label
// for a standard key type, and only the pin carries it.
async function testCanVerifyInTlsPrefersCustomPinOverInferredLabel() {
  var dir = _mkTmp();
  var probed = [];
  var eng = {
    generateCa:     async function (a) { return engine.generateCa({ generation: a.generation }); },
    signClientCert: engine.signClientCert,
    canVerifyInTls: async function (label) { probed.push(label); return true; },
  };
  var ca = b.mtlsCa.create({ dataDir: dir, engine: eng, algorithm: "CUSTOM-PQC-LABEL", caKeySealedMode: "disabled" });
  await ca.initCA();
  check("status() infers a bundled label from the cert", ca.status().algorithm === "ML-DSA-87");
  await ca.canVerifyInTls();
  check("canVerifyInTls() passes the custom engine's create-time pin, not the inferred bundled label",
        probed[probed.length - 1] === "CUSTOM-PQC-LABEL");
}

// CRL invalidation is part of the commit (under the lock), so the public commit()
// path — not just rotate() — invalidates a persisted CRL when it republishes the CA.
async function testPublicCommitInvalidatesStaleCrl() {
  var ca = _newCa();
  await ca.initCA();
  await ca.generateCrl();                                     // persists ca.crl under gen-1
  check("a CRL is persisted before the public commit", fs.existsSync(ca.paths.crl) === true);
  var g2 = await engine.generateCa({ generation: 2 });
  await ca.commit({ caKeyPem: g2.caKeyPem, caCertPem: g2.caCertPem, retainPrevious: false });
  check("a public commit invalidates the stale CRL (the CA cert changed)",
        fs.existsSync(ca.paths.crl) === false);
}

// The rotation compare-and-swap must compare cert IDENTITY, not only the generation
// number: a public commit() that replaces the CA with a DIFFERENT cert at the SAME
// generation while rotate() awaits generateCa() must be detected, so the older
// rotation does not overwrite the later commit.
async function testRotationCasDetectsSameGenerationCommit() {
  var dir = _mkTmp();
  var release; var barrier = new Promise(function (r) { release = r; });
  var slowEngine = Object.assign({}, engine, {
    // Block only the ROTATION's keygen (gen >= 2), so initCA (gen-1) is not stalled.
    generateCa: async function (a) { if (a.generation >= 2) { await barrier; } return engine.generateCa(a); },
  });
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", engine: slowEngine });
  await ca.initCA();                                          // gen-1 (not blocked)
  var rotating = ca.rotate({ generation: 2 });               // reads gen-1, blocks in generateCa
  // A public commit (default engine) replaces the CA at the SAME generation-1 with a
  // DIFFERENT cert while the rotation is blocked.
  var handle2 = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  var g1b = await engine.generateCa({ generation: 1 });
  await handle2.commit({ caKeyPem: g1b.caKeyPem, caCertPem: g1b.caCertPem, retainPrevious: false });
  release();
  check("the rotation CAS detects a same-generation public commit and refuses",
        (await code2(function () { return rotating; })) === "mtls-ca/rotation-conflict");
  check("the same-generation public commit survives (its cert is the active CA)",
        fs.readFileSync(handle2.paths.caCert).toString("utf8") === g1b.caCertPem);
}

// While a retained grace window is open (ca.prev.crt present), a public commit()
// that OMITS retainPrevious is ambiguous: outgoingCaCert is null (so the single-
// window guard does not fire) AND the hard-cut branch (retainPrevious === false)
// does not fire either, so the old retained root would be left untouched while the
// active cert is replaced — silently dropping trust for the just-superseded
// generation (its cert becomes neither the new current nor the retained root). The
// commit must refuse until the caller states its retention intent.
async function testPublicCommitRefusesRetentionAmbiguityWhileWindowOpen() {
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await ca.initCA();
  await ca.rotate({ generation: 2 });                        // gen-2 active, gen-1 retained (window open)
  var activeBefore = fs.readFileSync(ca.paths.caCert).toString("utf8");   // the gen-2 cert
  check("a retained window is open before the ambiguous commit", (await ca.loadTrustBundle()).length === 2);
  var g3 = await engine.generateCa({ generation: 3 });
  check("a retainPrevious-omitted commit is refused while a grace window is open",
        (await code2(function () { return ca.commit({ caKeyPem: g3.caKeyPem, caCertPem: g3.caCertPem }); }))
          === "mtls-ca/retention-intent-required");
  check("the refused commit left the active CA cert unchanged (no cohort silently dropped)",
        fs.readFileSync(ca.paths.caCert).toString("utf8") === activeBefore);
  check("both roots are still trusted after the refused commit", (await ca.loadTrustBundle()).length === 2);
  // An explicit retention intent (hard-cut) is still accepted and ends the window.
  await ca.commit({ caKeyPem: g3.caKeyPem, caCertPem: g3.caCertPem, retainPrevious: false });
  check("an explicit retainPrevious:false commit hard-cuts the window",
        fs.readFileSync(ca.paths.caCert).toString("utf8") === g3.caCertPem &&
        (await ca.loadTrustBundle()).length === 1);
}

// A rollback journal that exists but cannot be parsed (or is not a valid manifest)
// is the "rotation in progress / crashed" marker. A mutating open (commit/rotate)
// must NOT continue into _commitLocked — that would overwrite the ONLY durable copy
// of the prior key while snapshotting a possibly-orphaned live key, so a later failed
// publish could restore the orphan and permanently lose the matching key. Fail closed
// (the reconcile is idempotent, so the operator resolves the fault and retries).
async function testMutatingPathFailsClosedOnCorruptRollbackJournal() {
  // (a) Unparseable journal bytes -> a commit refuses.
  var dirA = _mkTmp();
  var caA = b.mtlsCa.create({ dataDir: dirA, caKeySealedMode: "disabled" });
  await caA.initCA();
  fs.writeFileSync(caA.paths.caKey + ".rollback", "not-json{{{");
  var reopenA = b.mtlsCa.create({ dataDir: dirA, caKeySealedMode: "disabled" });
  var g2a = await engine.generateCa({ generation: 2 });
  check("a mutating commit refuses while an UNPARSEABLE rollback journal is present",
        (await code2(function () {
          return reopenA.commit({ caKeyPem: g2a.caKeyPem, caCertPem: g2a.caCertPem, retainPrevious: false });
        })) === "mtls-ca/rollback-journal-corrupt");
  check("the unparseable journal is left intact for the operator to resolve",
        fs.existsSync(reopenA.paths.caKey + ".rollback") === true);
  // (b) Valid JSON but not a rollback manifest (missing the prior-key field) -> rotate refuses.
  var dirB = _mkTmp();
  var caB = b.mtlsCa.create({ dataDir: dirB, caKeySealedMode: "disabled" });
  await caB.initCA();
  fs.writeFileSync(caB.paths.caKey + ".rollback", JSON.stringify({ not: "a manifest" }));
  var reopenB = b.mtlsCa.create({ dataDir: dirB, caKeySealedMode: "disabled" });
  check("a rotate refuses while a schema-invalid rollback journal is present",
        (await code2(function () { return reopenB.rotate({ generation: 2 }); }))
          === "mtls-ca/rollback-journal-corrupt");
}

// Invalidating a persisted CRL is a REQUIRED part of a CA-changing commit (the release
// contract: a rotation invalidates the persisted CRL). The stale CRL is MOVED ASIDE
// before the cert publish; if that move fails (a read-only / separately-configured CRL
// directory), the commit must ABORT and roll the CA back — and the surviving CA's
// still-valid CRL must be left in place, not lost.
async function testRotationAbortsWhenStaleCrlCannotBeMovedAside() {
  var atomicFile = require("../../lib/atomic-file");
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await ca.initCA();
  await ca.generateCrl();                                     // persists ca.crl under gen-1
  var crlBefore = fs.readFileSync(ca.paths.crl);
  check("a CRL is persisted before the rotation", crlBefore.length > 0);
  var keyBefore  = fs.readFileSync(ca.paths.caKey);
  var certBefore = fs.readFileSync(ca.paths.caCert);
  var realRename = atomicFile.renameWithRetry;
  atomicFile.renameWithRetry = function (from) {
    if (String(from) === String(ca.paths.crl)) throw new Error("simulated read-only CRL directory");
    return realRename.apply(this, arguments);
  };
  var codeSeen;
  try { codeSeen = await code2(function () { return ca.rotate({ generation: 2, retainPrevious: false }); }); }
  finally { atomicFile.renameWithRetry = realRename; }
  check("the rotation aborts when the stale CRL cannot be moved aside", codeSeen === "mtls-ca/commit-failed");
  check("the CA rolled back (key + cert unchanged) rather than publishing beside a stale CRL",
        fs.readFileSync(ca.paths.caKey).equals(keyBefore) && fs.readFileSync(ca.paths.caCert).equals(certBefore));
  check("the surviving CA's valid CRL is left in place after the aborted rotation",
        fs.existsSync(ca.paths.crl) === true && fs.readFileSync(ca.paths.crl).equals(crlBefore));
  check("the surviving CA still issues after the aborted rotation",
        typeof (await ca.generateClientCert({ cn: "post-crl-abort" })).cert === "string");
}

// If a rotation's cert publish fails AFTER the stale CRL was moved aside, the commit
// rolls back — and the CA it reverts to is still active, so its still-valid CRL must be
// RESTORED, not left permanently deleted (a deployment serving the documented CRL path
// must not lose its published revocation data because a rotation failed).
async function testRotationRestoresCrlWhenCertPublishFails() {
  var atomicFile = require("../../lib/atomic-file");
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await ca.initCA();
  await ca.generateCrl();
  var crlBefore = fs.readFileSync(ca.paths.crl);
  var realRename = atomicFile.renameWithRetry;
  atomicFile.renameWithRetry = function (from, to) {
    if (String(to) === String(ca.paths.caCert)) throw new Error("simulated cert publish failure");
    return realRename.apply(this, arguments);
  };
  var codeSeen;
  try { codeSeen = await code2(function () { return ca.rotate({ generation: 2, retainPrevious: false }); }); }
  finally { atomicFile.renameWithRetry = realRename; }
  check("the rotation aborts when the cert publish fails", codeSeen === "mtls-ca/commit-failed");
  check("the rolled-back CA's still-valid CRL is restored (not permanently lost)",
        fs.existsSync(ca.paths.crl) === true && fs.readFileSync(ca.paths.crl).equals(crlBefore));
  check("no orphan crl.rollback remains after the restore",
        fs.existsSync(ca.paths.crl + ".rollback") === false);
  check("the surviving CA still issues and can regenerate its CRL",
        typeof (await ca.generateClientCert({ cn: "post-crl-restore" })).cert === "string");
}

// A crash between moving the CRL aside and publishing the new cert leaves the CRL at
// crl.rollback with a journal marking an INTERRUPTED rotation. Reconcile on the next
// mutating open must restore it (the CA it rolls back to is still active).
async function testReconcileRestoresCrlForInterruptedRotation() {
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await ca.initCA();
  await ca.generateCrl();
  var crlBytes = fs.readFileSync(ca.paths.crl);
  var keyG1  = fs.readFileSync(ca.paths.caKey);
  var certG1 = fs.readFileSync(ca.paths.caCert);
  fs.renameSync(ca.paths.crl, ca.paths.crl + ".rollback");    // CRL moved aside
  fs.writeFileSync(ca.paths.caKey + ".rollback", _journalManifest({
    key: keyG1, newKey: keyG1, cert: certG1,                  // live cert == manifest.cert => interrupted
    retainAfter: false, crlMovedAside: true, prevAction: "leave", prevData: null,
  }));
  var reopened = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await reopened.initCA();                                    // reconciles under the lock
  check("reconcile restores the valid CRL an interrupted rotation moved aside",
        fs.existsSync(reopened.paths.crl) === true && fs.readFileSync(reopened.paths.crl).equals(crlBytes));
  check("the crl.rollback temp is cleared after the reconcile restore",
        fs.existsSync(reopened.paths.crl + ".rollback") === false);
  check("the reconciled CA still issues",
        typeof (await reopened.generateClientCert({ cn: "post-reconcile-crl" })).cert === "string");
}

// A supported custom engine whose CA certificate node:crypto cannot parse (an opaque /
// post-quantum cert) makes parseGeneration() fall back to 0. Recording issuances as
// generation 0 then lets revokeGeneration(1) revoke those CURRENT leaves (0 < 1) and,
// via the bumped watermark, self-revoke every future issuance. An undeterminable
// generation must be recorded as null — skipped by generation-based revocation (still
// revocable by fingerprint), never 0.
async function testOpaqueCustomEngineIssuanceGenerationNotZero() {
  var dir = _mkTmp();
  var opaqueCert = "-----BEGIN CERTIFICATE-----\nb3BhcXVlLWNhLW5vdC1wYXJzZWFibGU=\n-----END CERTIFICATE-----";
  var opaqueKey  = "-----BEGIN PRIVATE KEY-----\nb3BhcXVlLWtleQ==\n-----END PRIVATE KEY-----";
  var n = 0;
  var eng = {
    generateCa:     async function () { return { caCertPem: opaqueCert, caKeyPem: opaqueKey }; },
    signClientCert: async function () {
      n += 1;   // distinct opaque leaves -> distinct fingerprints (_certIdentity hashes the bytes)
      return { cert: "-----BEGIN CERTIFICATE-----\nbGVhZi0" + n + "=\n-----END CERTIFICATE-----", key: "leaf-key-" + n };
    },
  };
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", engine: eng });
  await ca.initCA();
  var leaf1 = await ca.generateClientCert({ cn: "opaque-1" });
  var ledger = JSON.parse(fs.readFileSync(ca.paths.issuance, "utf8"));
  check("an opaque custom CA records issuance generation as null (undeterminable), not 0",
        ledger.issued.length === 1 && ledger.issued[0].generation === null);
  var res = await ca.revokeGeneration(1);
  check("revokeGeneration(1) does not sweep an undeterminable-generation leaf",
        res.revoked === 0 && ca.isRevoked(leaf1.fingerprint) === false);
  var leaf2 = await ca.generateClientCert({ cn: "opaque-2" });
  check("a later issuance under the opaque CA does not self-revoke as superseded",
        typeof leaf2.cert === "string" && ca.isRevoked(leaf2.fingerprint) === false);
}

// The fresh-init adoption branch (a concurrent process created the CA under the shared
// dataDir while this pinned handle awaited generateCa) must run the SAME algorithm-pin
// validation as initCA()'s normal existing-CA path — else a pinned handle adopts and
// issues under an incompatible CA.
async function testFreshInitAdoptionValidatesPin() {
  var dir = _mkTmp();
  var release; var barrier = new Promise(function (r) { release = r; });
  var slowEngine = Object.assign({}, engine, {
    generateCa: async function (a) { await barrier; return engine.generateCa(a); },
  });
  var pinned = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", engine: slowEngine, algorithm: "ECDSA-P384-SHA384" });
  var issuing = pinned.generateClientCert({ cn: "adopt" });  // initCA -> _freshCreateSerialized, blocks in generateCa
  var other = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });   // ML-DSA default
  await other.initCA();                                      // publishes an ML-DSA CA at the shared dataDir
  release();
  check("the fresh-init adoption branch validates the pin (refuses adopting a different-algorithm CA)",
        (await code2(function () { return issuing; })) === "mtls-ca/algorithm-mismatch");
}

// A handle created with an algorithm pin that migrates its CA to a different algorithm
// via the public commit() path must refresh the pin (like rotate() does) — else the
// next initCA()/generateClientCert() compares the stale pin to the new CA and throws
// algorithm-mismatch, leaving the handle unusable immediately after a successful commit.
async function testPublicCommitRefreshesAlgorithmPin() {
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", algorithm: "ECDSA-P384-SHA384" });
  await ca.initCA();
  var mlSource = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled" });   // ML-DSA default
  await mlSource.initCA();
  var mlKey  = mlSource.loadKey().toString("utf8");
  var mlCert = mlSource.loadCert().toString("utf8");
  await ca.commit({ caKeyPem: mlKey, caCertPem: mlCert, retainPrevious: false });
  var leaf = await ca.generateClientCert({ cn: "post-commit-migrate" });
  check("a pinned handle stays usable after commit()ing a different-algorithm CA (pin refreshed)",
        typeof leaf.cert === "string");
}

// A key-only cold start (a crashed FIRST init left ca.key with no ca.crt, so the retry's
// _commitLocked captured it as the prior key with cert=null) must still roll a COMPLETED
// init forward: reconcile classifies by the intended NEW cert, so it keeps the published
// key/cert pair instead of restoring the orphaned prior key beside the new cert.
async function testReconcileRollsForwardKeyOnlyInit() {
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await ca.initCA();
  var key1  = fs.readFileSync(ca.paths.caKey);
  var cert1 = fs.readFileSync(ca.paths.caCert);
  var other = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled" });
  await other.initCA();
  var keyOrphan = fs.readFileSync(other.paths.caKey);        // an unrelated prior key
  // Fabricate a COMPLETED key-only init that crashed before deleting the journal: the
  // journal's prior cert is null (none existed when the commit began), its newKey/newCert
  // are the published pair, and the live pair IS that published pair.
  fs.writeFileSync(ca.paths.caKey + ".rollback", _journalManifest({
    key: keyOrphan, newKey: key1, cert: null, newCert: cert1,
    retainAfter: false, prevAction: "delete", prevData: null,
  }));
  var reopened = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await reopened.initCA();                                   // reconciles under the lock
  check("reconcile rolls a completed key-only init FORWARD (keeps the published key, not the orphan)",
        fs.readFileSync(reopened.paths.caKey).equals(key1));
  check("the reconciled key-only CA is a usable pair (issues cleanly)",
        typeof (await reopened.generateClientCert({ cn: "post-keyonly" })).cert === "string");
  check("the journal is cleared after the key-only roll-forward",
        fs.existsSync(reopened.paths.caKey + ".rollback") === false);
}

// A custom engine may use its OWN label (e.g. "CUSTOM-P384") for a standard key type.
// The public commit() pin refresh maps via _certAlgorithm(), which yields BUNDLED
// labels — so refreshing a custom-engine pin would replace its label with the bundled
// one and the next issuance would pass a label the engine rejects. Refresh the pin only
// for the default engine; a custom engine's pin is preserved.
async function testPublicCommitPreservesCustomEnginePin() {
  var dir = _mkTmp();
  var seen = [];
  var eng = {
    generateCa:     async function () { return { caCertPem: "opaque-ca", caKeyPem: "opaque-key" }; },
    signClientCert: async function (a) {
      seen.push(a.algorithm);
      if (a.algorithm !== "CUSTOM-P384") throw new Error("engine only accepts CUSTOM-P384, got " + a.algorithm);
      return { cert: "-----BEGIN CERTIFICATE-----\nbGVhZg==\n-----END CERTIFICATE-----", key: "k" };
    },
  };
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", engine: eng, algorithm: "CUSTOM-P384" });
  await ca.initCA();
  // Commit a PARSEABLE ECDSA-P384 CA (default engine) through the custom-engine handle.
  var ecSource = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled", algorithm: "ECDSA-P384-SHA384" });
  await ecSource.initCA();
  await ca.commit({ caKeyPem: ecSource.loadKey().toString("utf8"), caCertPem: ecSource.loadCert().toString("utf8"), retainPrevious: false });
  var leaf = await ca.generateClientCert({ cn: "post-commit-custom" });
  check("a custom-engine pin survives a public commit (the engine receives CUSTOM-P384, not the bundled label)",
        typeof leaf.cert === "string" && seen[seen.length - 1] === "CUSTOM-P384");
}

// canVerifyInTls() must REJECT an invalid explicit target (empty string / non-string)
// rather than silently falling back to the stored/default algorithm — else a migration
// pre-flight returns true without testing the requested target. create()/rotate() reject
// the same invalid values.
async function testCanVerifyInTlsRejectsInvalidExplicitAlgorithm() {
  var ca = _newCa();
  await ca.initCA();
  check("canVerifyInTls('') rejects an empty explicit target (no silent fallback to the stored CA)",
        (await code2(function () { return ca.canVerifyInTls(""); })) === "mtls-ca/bad-algorithm");
  check("canVerifyInTls(123) rejects a non-string explicit target",
        (await code2(function () { return ca.canVerifyInTls(123); })) === "mtls-ca/bad-algorithm");
  check("canVerifyInTls(null) rejects a null explicit target",
        (await code2(function () { return ca.canVerifyInTls(null); })) === "mtls-ca/bad-algorithm");
}

// A non-boolean retainPrevious (e.g. the string "false" from config) must be REJECTED,
// not interpreted by truthiness: "false" is truthy, so it would retain the outgoing
// root when the operator intended a hard cut (and rotate() retains for every value !==
// literal false). Validate the supplied value is a boolean at both entry points.
async function testNonBooleanRetainPreviousRejected() {
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await ca.initCA();
  var g2 = await engine.generateCa({ generation: 2 });
  check("commit() rejects a non-boolean retainPrevious (the string \"false\" would otherwise retain)",
        (await code2(function () {
          return ca.commit({ caKeyPem: g2.caKeyPem, caCertPem: g2.caCertPem, retainPrevious: "false" });
        })) === "mtls-ca/bad-retain-previous");
  check("rotate() rejects a non-boolean retainPrevious",
        (await code2(function () { return ca.rotate({ generation: 2, retainPrevious: "false" }); }))
          === "mtls-ca/bad-retain-previous");
  // A proper boolean still works (hard cut to gen 2).
  var r = await ca.rotate({ generation: 2, retainPrevious: false });
  check("rotate() still accepts a boolean retainPrevious",
        typeof r.caCertPem === "string" && ca.status().generation === 2);
  // generateCrl()'s persist is the same !== false truthiness class — a non-boolean must
  // be rejected rather than persisting when the operator meant return-only.
  check("generateCrl() rejects a non-boolean persist (the string \"false\" would otherwise persist)",
        (await code2(function () { return ca.generateCrl({ persist: "false" }); })) === "mtls-ca/bad-persist");
  var crl = await ca.generateCrl({ persist: false });   // a proper boolean still returns without persisting
  check("generateCrl() still accepts a boolean persist", typeof crl.crlPem === "string");
}

// crl.rollback is a fixed name, so an ORPHAN left by a prior commit (whose best-effort
// delete failed after publishing) must NOT be restored by a LATER commit that never
// moved it aside — that would publish a CRL signed by an earlier issuer under the
// still-active CA. The restore is gated on "did THIS commit move the CRL aside".
async function testCommitDoesNotRestoreOrphanCrlRollback() {
  var atomicFile = require("../../lib/atomic-file");
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await ca.initCA();
  var staleCrl = Buffer.from("-----BEGIN X509 CRL-----\nc3RhbGUtcm9sbGJhY2s=\n-----END X509 CRL-----\n");
  fs.writeFileSync(ca.paths.crl + ".rollback", staleCrl);          // an orphan from a prior commit
  check("setup: an orphan crl.rollback exists with no current ca.crl",
        fs.existsSync(ca.paths.crl + ".rollback") === true && fs.existsSync(ca.paths.crl) === false);
  // A CA-changing commit that fails its cert publish (its catch runs). It did NOT move a
  // CRL aside (there is no current ca.crl), so its catch must not touch the orphan.
  var g2 = await engine.generateCa({ generation: 2 });
  var realRename = atomicFile.renameWithRetry;
  atomicFile.renameWithRetry = function (from, to) {
    if (String(to) === String(ca.paths.caCert)) throw new Error("simulated cert publish failure");
    return realRename.apply(this, arguments);
  };
  var codeSeen;
  try { codeSeen = await code2(function () { return ca.commit({ caKeyPem: g2.caKeyPem, caCertPem: g2.caCertPem, retainPrevious: false }); }); }
  finally { atomicFile.renameWithRetry = realRename; }
  check("the failed commit aborts", codeSeen === "mtls-ca/commit-failed");
  check("the orphan crl.rollback is NOT restored as the current CRL (it was signed by an earlier issuer)",
        fs.existsSync(ca.paths.crl) === false);
  check("the orphan crl.rollback is left untouched (not this commit's to restore)",
        fs.existsSync(ca.paths.crl + ".rollback") === true && fs.readFileSync(ca.paths.crl + ".rollback").equals(staleCrl));
}

// Reconcile must ALSO not restore an orphan crl.rollback: a journaled commit whose
// crlMovedAside is false did not move a CRL aside, so any crl.rollback present is a
// prior commit's orphan — restoring it would publish a stale-issuer CRL.
async function testReconcileDoesNotRestoreOrphanCrlRollback() {
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await ca.initCA();
  var key1  = fs.readFileSync(ca.paths.caKey);
  var cert1 = fs.readFileSync(ca.paths.caCert);
  var staleCrl = Buffer.from("-----BEGIN X509 CRL-----\nb3JwaGFuLXJlY29uY2lsZQ==\n-----END X509 CRL-----\n");
  fs.writeFileSync(ca.paths.crl + ".rollback", staleCrl);     // orphan, no current ca.crl
  // An INTERRUPTED commit's journal that did NOT move a CRL aside (crlMovedAside false).
  fs.writeFileSync(ca.paths.caKey + ".rollback", _journalManifest({
    key: key1, newKey: key1, cert: cert1,                     // live cert == manifest.cert => interrupted
    retainAfter: false, crlMovedAside: false, prevAction: "leave", prevData: null,
  }));
  var reopened = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await reopened.initCA();                                    // reconciles under the lock
  check("reconcile does NOT restore an orphan crl.rollback for a commit that did not move a CRL",
        fs.existsSync(reopened.paths.crl) === false &&
        fs.existsSync(reopened.paths.crl + ".rollback") === true &&
        fs.readFileSync(reopened.paths.crl + ".rollback").equals(staleCrl));
}

// A completed rotation whose CRL move-aside was LOST (best-effort fsyncDir did not
// persist the rename) leaves the OLD-issuer CRL live at paths.crl with no crl.rollback,
// while the new cert IS published. Reconcile classifies it completed; it must remove the
// stale live CRL too, not just the (absent) crl.rollback — else the old-issuer CRL stays
// published under the new CA until the operator regenerates.
async function testReconcileRemovesResurrectedLiveCrlOnRollForward() {
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await ca.initCA();
  var key1  = fs.readFileSync(ca.paths.caKey);
  var cert1 = fs.readFileSync(ca.paths.caCert);
  await ca.generateCrl();
  var staleCrl = fs.readFileSync(ca.paths.crl);              // CRL signed by cert1 (gen-1 issuer)
  var g2 = await engine.generateCa({ generation: 2 });
  // Crash state: the new cert/key are published, ca.crl still holds the OLD-issuer CRL
  // (the move-aside rename was lost), there is NO crl.rollback, and the journal survived.
  fs.writeFileSync(ca.paths.caKey, g2.caKeyPem);
  fs.writeFileSync(ca.paths.caCert, g2.caCertPem);
  fs.writeFileSync(ca.paths.crl, staleCrl);
  fs.rmSync(ca.paths.crl + ".rollback", { force: true });
  fs.writeFileSync(ca.paths.caKey + ".rollback", _journalManifest({
    key: key1, newKey: Buffer.from(g2.caKeyPem), cert: cert1, newCert: Buffer.from(g2.caCertPem),
    retainAfter: false, crlMovedAside: true, prevAction: "delete", prevData: null,
  }));
  var reopened = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await reopened.initCA();                                   // reconciles: completed + crlMovedAside
  check("reconcile removes a stale live CRL a lost move-aside left under the new CA (completed roll-forward)",
        fs.existsSync(reopened.paths.crl) === false);
  check("the reconciled CA still issues after removing the resurrected stale CRL",
        typeof (await reopened.generateClientCert({ cn: "post-crl-rollforward" })).cert === "string");
}

// Completed roll-forward where the move-aside STUCK (ca.crl.rollback is present) but the
// post-publish delete of that moved-aside copy did not run before the crash. Reconcile
// must remove the leftover crl.rollback — the superseded issuer's CRL must not linger.
async function testReconcileRemovesLeftoverCrlRollbackOnRollForward() {
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await ca.initCA();
  var key1  = fs.readFileSync(ca.paths.caKey);
  var cert1 = fs.readFileSync(ca.paths.caCert);
  await ca.generateCrl();
  var staleCrl = fs.readFileSync(ca.paths.crl);              // CRL signed by cert1 (gen-1 issuer)
  var g2 = await engine.generateCa({ generation: 2 });
  // Crash state: the new cert/key are published (completed roll-forward), the stale CRL was
  // moved aside to crl.rollback and that rename STUCK, but the post-publish delete of the
  // moved-aside copy did not run; there is no live paths.crl; the journal survived.
  fs.writeFileSync(ca.paths.caKey, g2.caKeyPem);
  fs.writeFileSync(ca.paths.caCert, g2.caCertPem);
  fs.rmSync(ca.paths.crl, { force: true });
  fs.writeFileSync(ca.paths.crl + ".rollback", staleCrl);
  fs.writeFileSync(ca.paths.caKey + ".rollback", _journalManifest({
    key: key1, newKey: Buffer.from(g2.caKeyPem), cert: cert1, newCert: Buffer.from(g2.caCertPem),
    retainAfter: false, crlMovedAside: true, prevAction: "delete", prevData: null,
  }));
  var reopened = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await reopened.initCA();                                   // reconciles: completed + crlMovedAside
  check("reconcile removes a leftover moved-aside crl.rollback on a completed roll-forward",
        fs.existsSync(reopened.paths.crl + ".rollback") === false);
  check("no stale CRL is republished under the new CA after the leftover is removed",
        fs.existsSync(reopened.paths.crl) === false);
  check("the reconciled CA still issues after removing the leftover crl.rollback",
        typeof (await reopened.generateClientCert({ cn: "post-crl-leftover" })).cert === "string");
}

// An idempotent recommit of the SAME cert/key does not change the CRL's issuer, so the
// valid CRL must be preserved — not moved aside and deleted like a real rotation.
async function testIdempotentCommitPreservesCrl() {
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await ca.initCA();
  await ca.generateCrl();
  var crlBefore = fs.readFileSync(ca.paths.crl);
  var sameKey  = ca.loadKey().toString("utf8");
  var sameCert = ca.loadCert().toString("utf8");
  await ca.commit({ caKeyPem: sameKey, caCertPem: sameCert, retainPrevious: false });   // recommit the SAME CA
  check("an idempotent recommit of the same CA preserves the valid CRL (issuer unchanged)",
        fs.existsSync(ca.paths.crl) === true && fs.readFileSync(ca.paths.crl).equals(crlBefore));
  // A DIFFERENT cert still invalidates the CRL (control).
  var g2 = await engine.generateCa({ generation: 2 });
  await ca.commit({ caKeyPem: g2.caKeyPem, caCertPem: g2.caCertPem, retainPrevious: false });
  check("committing a DIFFERENT CA still invalidates the stale CRL",
        fs.existsSync(ca.paths.crl) === false);
}

// A SAME-CERT retainPrevious:false hard-cut whose rollback-journal unlink fails must fail
// CLOSED, not report success: the surviving journal has live cert == journal.cert, so the
// next reconcile classifies it INTERRUPTED and restores ca.prev.crt, AND _journalRetainedRoot()
// re-adds it — resurrecting the very root the operator cut while commit() claimed success.
async function testCommitFailsClosedWhenSameCertCutJournalUnlinkFails() {
  var ca = _newCa();
  await ca.initCA();
  await ca.rotate({ generation: 2, retainPrevious: true });   // a retained root (ca.prev.crt) now exists
  var sameKey  = ca.loadKey().toString("utf8");
  var sameCert = ca.loadCert().toString("utf8");
  var journal  = ca.paths.caKey + ".rollback";
  check("precondition: a retained root exists before the hard-cut",
        (await ca.loadTrustBundle()).length === 2);
  var realUnlink = fs.unlinkSync;
  fs.unlinkSync = function (p) {
    if (String(p) === String(journal)) { throw new Error("journal unlink blocked"); }
    return realUnlink.apply(this, arguments);
  };
  var code;
  try {
    code = await code2(function () {
      return ca.commit({ caKeyPem: sameKey, caCertPem: sameCert, retainPrevious: false });
    });
  } finally { fs.unlinkSync = realUnlink; }
  check("a same-cert hard-cut whose journal unlink fails fails CLOSED (mtls-ca/commit-failed), not a false success",
        code === "mtls-ca/commit-failed");
}

// A CERT-CHANGING commit whose journal unlink fails SELF-HEALS: the next reconcile sees live
// cert != journal.cert (COMPLETED) and rolls the leftover forward, so the failure is swallowed
// and the commit succeeds — propagating it would spuriously roll back a genuinely-published CA.
async function testCommitSwallowsJournalUnlinkFailureOnCertChange() {
  var ca = _newCa();
  await ca.initCA();
  var g2 = await engine.generateCa({ generation: 2 });        // a DIFFERENT CA (the cert changes)
  var journal = ca.paths.caKey + ".rollback";
  var realUnlink = fs.unlinkSync;
  fs.unlinkSync = function (p) {
    if (String(p) === String(journal)) { throw new Error("journal unlink blocked"); }
    return realUnlink.apply(this, arguments);
  };
  var code;
  try {
    code = await code2(function () {
      return ca.commit({ caKeyPem: g2.caKeyPem, caCertPem: g2.caCertPem, retainPrevious: false });
    });
  } finally { fs.unlinkSync = realUnlink; }
  check("a cert-changing commit whose journal unlink fails still SUCCEEDS (the leftover self-heals)",
        code === "NO-THROW");
}

// A pinned CUSTOM-engine handle migrating to a different-algorithm CA via the public commit()
// primitive must be able to supply the NEW effective label: the bundled label cannot be
// inferred from a custom cert, so without it the stale pin is passed to the newly committed
// issuer on the next issuance (reject / incompatible leaf) even though commit() succeeded.
async function testCommitUpdatesCustomEnginePinToSuppliedAlgorithm() {
  var recorded = [];
  var caA = { caCertPem: "-----BEGIN CERTIFICATE-----\nQ0EtQQ==\n-----END CERTIFICATE-----",
              caKeyPem:  "-----BEGIN PRIVATE KEY-----\na2V5LUE=\n-----END PRIVATE KEY-----" };
  var caB = { caCertPem: "-----BEGIN CERTIFICATE-----\nQ0EtQg==\n-----END CERTIFICATE-----",
              caKeyPem:  "-----BEGIN PRIVATE KEY-----\na2V5LUI=\n-----END PRIVATE KEY-----" };
  var eng = {
    generateCa:     async function () { return caA; },
    signClientCert: async function (a) {
      recorded.push(a.algorithm);
      return { cert: "-----BEGIN CERTIFICATE-----\nbGVhZg==\n-----END CERTIFICATE-----", key: "k" };
    },
  };
  var ca = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled", engine: eng, algorithm: "CUSTOM-A" });
  await ca.initCA();
  check("commit rejects a non-string algorithm",
        (await code2(function () {
          return ca.commit({ caKeyPem: caB.caKeyPem, caCertPem: caB.caCertPem, algorithm: 123 });
        })) === "mtls-ca/bad-algorithm");
  await ca.commit({ caKeyPem: caB.caKeyPem, caCertPem: caB.caCertPem, retainPrevious: false, algorithm: "CUSTOM-B" });
  await ca.generateClientCert({ cn: "after-custom-migrate" });
  check("commit({ algorithm }) updates a custom-engine pin so the next issuance uses the NEW label",
        recorded[recorded.length - 1] === "CUSTOM-B");
}

// A stored CA whose generation is UNDETERMINABLE (a custom engine's opaque cert
// node:crypto cannot parse -> status().generation === 0) cannot be rotated: a default
// rotation would mint generation 1 (mis-cohorting the leaves it revokes) and an explicit
// lower/equal generation would be accepted, violating the strictly-increasing invariant.
async function testRotateRefusesUndeterminableGeneration() {
  var dir = _mkTmp();
  var eng = {
    generateCa:     async function () { return { caCertPem: "-----BEGIN CERTIFICATE-----\nb3BhcXVlLWNh\n-----END CERTIFICATE-----", caKeyPem: "-----BEGIN PRIVATE KEY-----\nb3BhcXVlLWtleQ==\n-----END PRIVATE KEY-----" }; },
    signClientCert: async function () { return { cert: "-----BEGIN CERTIFICATE-----\nbGVhZg==\n-----END CERTIFICATE-----", key: "k" }; },
  };
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", engine: eng });
  await ca.initCA();
  check("an opaque custom CA reports generation 0 (undeterminable)", ca.status().generation === 0);
  check("rotate({generation}) refuses a CA whose current generation is undeterminable",
        (await code2(function () { return ca.rotate({ generation: 3 }); })) === "mtls-ca/generation-undeterminable");
  check("a default rotate() is refused too (cannot compute a strictly-increasing generation)",
        (await code2(function () { return ca.rotate(); })) === "mtls-ca/generation-undeterminable");
}

// A crash journal that is valid JSON but carries an EMPTY (or non-canonical) base64
// byte field must fail closed: an empty base64 `key` decodes to an empty buffer that,
// written over the live CA key on the interrupted path, permanently destroys the CA.
async function testReconcileRejectsMalformedManifestBase64() {
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await ca.initCA();
  var goodKey  = fs.readFileSync(ca.paths.caKey);
  var goodCert = fs.readFileSync(ca.paths.caCert);
  // Empty base64 key (decodes to an empty buffer). The interrupted path (live cert ==
  // manifest.cert) would write it over the live key.
  fs.writeFileSync(ca.paths.caKey + ".rollback", _journalManifest({
    key: Buffer.alloc(0), newKey: null, cert: goodCert, newCert: null,
    retainAfter: false, prevAction: "leave", prevData: null,
  }));
  var reopened = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  check("reconcile fails closed on an EMPTY base64 key (rollback-journal-corrupt)",
        (await code2(function () { return reopened.initCA(); })) === "mtls-ca/rollback-journal-corrupt");
  check("the live CA key is untouched (not destroyed by an empty-buffer overwrite)",
        fs.readFileSync(ca.paths.caKey).equals(goodKey));
  // A NON-CANONICAL base64 key ("abc" round-trips to "abc=") must also be refused.
  fs.writeFileSync(ca.paths.caKey + ".rollback", JSON.stringify({
    key: "abc", cert: goodCert.toString("base64"), retainAfter: false, prevAction: "leave", prevData: null,
  }));
  var reopened2 = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  check("reconcile fails closed on a NON-CANONICAL base64 key",
        (await code2(function () { return reopened2.initCA(); })) === "mtls-ca/rollback-journal-corrupt");
}

// generateClientP12 must accept an OPAQUE (unparseable) certPem from a custom engine —
// the same way generateClientCert does — because _certIdentity() still derives a stable
// fingerprint, and parsing cannot prove the certPem is the cert inside the encrypted P12
// anyway. Rejecting it makes the primitive unusable for a post-quantum custom engine.
async function testGenerateClientP12AcceptsOpaqueCert() {
  var dir = _mkTmp();
  var opaqueLeaf = "-----BEGIN CERTIFICATE-----\nb3BhcXVlLXAxMi1sZWFm\n-----END CERTIFICATE-----";
  var eng = {
    generateCa: async function () { return { caCertPem: "-----BEGIN CERTIFICATE-----\nb3BhcXVlLWNh\n-----END CERTIFICATE-----", caKeyPem: "opaque-key" }; },
    packageP12: async function () { return { p12: Buffer.from("p12-bytes"), certPem: opaqueLeaf, issuedAt: new Date(), expiresAt: new Date() }; },
  };
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", engine: eng });
  await ca.initCA();
  var out = await ca.generateClientP12({ cn: "opaque-p12", password: "pw" });
  check("generateClientP12 accepts an opaque certPem from a custom engine (fingerprint still derived)",
        Buffer.isBuffer(out.p12) && typeof out.fingerprint === "string" && out.fingerprint.length > 0);
}

// status() must NOT report isLegacy:true for an UNDETERMINABLE generation (an opaque
// cert -> generation 0): that would mislabel a current opaque-engine CA as legacy, and
// an isLegacy-keyed upgrade flow would then rotate() it and hit generation-undeterminable
// — status() and rotate() contradicting each other on the same cert.
async function testStatusIsLegacyFalseForUndeterminableGeneration() {
  var dir = _mkTmp();
  var eng = {
    generateCa:     async function () { return { caCertPem: "-----BEGIN CERTIFICATE-----\nb3BhcXVl\n-----END CERTIFICATE-----", caKeyPem: "opaque-key" }; },
    signClientCert: async function () { return { cert: "x", key: "k" }; },
  };
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", engine: eng, generation: 3 });
  await ca.initCA();
  var s = ca.status();
  check("status: an undeterminable generation (0) is NOT reported as legacy",
        s.generation === 0 && s.isLegacy === false && s.current === 3);
}

// _journalRetainedRoot (the read sibling of reconcile) must validate the journal's base64
// canonically: a malformed prevData would otherwise decode to a garbage NON-empty string
// returned into loadTrustBundle(), and feeding that to a node:tls `ca:` build fails —
// a DoS of the mTLS gate. A corrupt journal's root is left for the locked reconcile.
async function testJournalRetainedRootRejectsMalformedPrevData() {
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await ca.initCA();
  var certG1 = fs.readFileSync(ca.paths.caCert);
  fs.writeFileSync(ca.paths.caKey + ".rollback", JSON.stringify({
    key:  fs.readFileSync(ca.paths.caKey).toString("base64"),
    cert: certG1.toString("base64"),               // == live cert => interrupted
    prevData: "!!!not-canonical-base64",           // malformed: lenient decode -> garbage
    prevAction: "restore",
  }));
  var reopened = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  var bundle = await reopened.loadTrustBundle();
  check("loadTrustBundle excludes a malformed-prevData journal root (only the current cert)",
        bundle.length === 1 && bundle[0] === certG1.toString("utf8"));
}

// A valid restore-journal is present but the live CA cert is ABSENT (a crash window
// between the retained-root update and the new-cert publish, read before any reconcile).
// _journalRetainedRoot must not trust the journal's old root when it cannot confirm the
// live cert still equals the prior cert — loadTrustBundle returns no root, never throws.
async function testJournalRetainedRootSkippedWhenLiveCertAbsent() {
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await ca.initCA();
  var certG1 = fs.readFileSync(ca.paths.caCert);
  fs.writeFileSync(ca.paths.caKey + ".rollback", JSON.stringify({
    key:  fs.readFileSync(ca.paths.caKey).toString("base64"),
    cert: certG1.toString("base64"),               // would match — but the live cert is gone
    prevData: certG1.toString("base64"),           // canonical: a genuine retained root
    prevAction: "restore",
  }));
  fs.rmSync(ca.paths.caCert, { force: true });     // live cert absent -> the existsSync guard is false
  var reopened = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  var bundle = await reopened.loadTrustBundle();
  check("loadTrustBundle omits the journal root when the live cert is absent (no throw)",
        Array.isArray(bundle) && bundle.length === 0);
}

// Exhaustive coverage of the reachable error/edge branches accumulated across the
// migration primitives — the paths a happy-path suite skips (bad engine/store output,
// fault-injected reads, undeterminable/superseded generations, key-only/no-CA states).
async function testMtlsCaReachableBranchCoverage() {
  var atomicFile = require("../../lib/atomic-file");

  // rotate() on a FRESH handle (no CA yet): the st.exists=false arms.
  var caFresh = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled" });
  var rf = await caFresh.rotate({ generation: 1 });
  check("rotate() on a fresh handle creates a gen-1 CA",
        typeof rf.caCertPem === "string" && caFresh.status().generation === 1);

  // unpinned rotate over a custom P-256 CA: _certAlgorithm -> null -> pin || undefined.
  var caP256 = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled", engine: _p256CaEngine() });
  await caP256.initCA();
  check("unpinned rotate over a custom P-256 CA succeeds",
        typeof (await caP256.rotate({ generation: 2 })).caCertPem === "string");

  // rotate() with an engine returning bad generateCa output.
  var caBad = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled", engine: {
    generateCa: async function (a) { if (a.generation >= 2) { return { nope: true }; } return engine.generateCa(a); },
    signClientCert: engine.signClientCert } });
  await caBad.initCA();
  check("rotate() rejects an engine that returns bad generateCa output",
        (await code2(function () { return caBad.rotate({ generation: 2 }); })) === "mtls-ca/bad-engine-output");

  // canVerifyInTls with an engine lacking the method.
  var caNoProbe = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled",
    engine: { generateCa: engine.generateCa, signClientCert: engine.signClientCert } });
  await caNoProbe.initCA();
  check("canVerifyInTls refuses an engine without canVerifyInTls",
        (await code2(function () { return caNoProbe.canVerifyInTls(); })) === "mtls-ca/no-tls-probe");

  // importIssuance edges: non-object entry, neither-fp-nor-serial, serial-only + fp-only,
  // superseded-on-import, and a CUSTOM issuanceStore (the Promise.resolve(add()) arm).
  var caImp = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled" });
  await caImp.initCA();
  check("importIssuance rejects a non-object entry",
        (await code2(function () { return caImp.importIssuance([null]); })) === "mtls-ca/bad-import");
  check("importIssuance rejects an entry with neither fingerprint nor serial",
        (await code2(function () { return caImp.importIssuance([{ generation: 1 }]); })) === "mtls-ca/bad-import");
  var imp = await caImp.importIssuance([{ generation: 1, serialNumber: "0a" }, { generation: 1, fingerprint: "ab".repeat(32) }]);
  check("importIssuance imports serial-only and fingerprint-only entries", imp.imported === 2);
  await caImp.revokeGeneration(3);
  // Both a fingerprint-only and a SERIAL-ONLY below-watermark entry supersede on import:
  // the serial-only one revokes with fingerprint:null (a pre-#532 out-of-band cert
  // backfilled by serial), exercising both revoke-key fallbacks in the superseded sweep.
  check("importIssuance revokes below-watermark entries (fingerprint-only + serial-only)",
        (await caImp.importIssuance([
          { generation: 1, fingerprint: "cd".repeat(32) },
          { generation: 1, serialNumber: "0f" },
        ])).revoked === 2);
  var customIss = { _l: [], list: function () { return this._l; }, add: function (e) { this._l.push(e); } };
  var caCI = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled", issuanceStore: customIss });
  await caCI.initCA();
  check("importIssuance with a custom issuanceStore imports through it",
        (await caCI.importIssuance([{ generation: 1, serialNumber: "0b" }])).imported === 1 && customIss._l.length === 1);

  // revokeGeneration: unknown reason, and a real sweep that revokes a below-n leaf.
  var caRev = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled" });
  await caRev.initCA();
  var leaf = await caRev.generateClientCert({ cn: "gen1" });
  check("revokeGeneration rejects an unknown reason",
        (await code2(function () { return caRev.revokeGeneration(2, { reason: "bogus" }); })) === "mtls-ca/bad-reason");
  var rg = await caRev.revokeGeneration(2);
  check("revokeGeneration sweeps and revokes a below-n leaf",
        rg.revoked === 1 && caRev.isRevoked(leaf.fingerprint) === true);
  var revs = caRev.getRevocations();
  check("getRevocations returns a copy of the revocation registry",
        Array.isArray(revs) && revs.length >= 1 && revs !== caRev.getRevocations());

  // A below-watermark issuance self-revokes (issuance-superseded, the gen < watermark arm).
  var caSup = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled" });
  await caSup.initCA();
  await caSup.revokeGeneration(5);
  check("issuing under a below-watermark generation self-revokes",
        (await code2(function () { return caSup.generateClientCert({ cn: "x" }); })) === "mtls-ca/issuance-superseded");

  // A clustered revocationStore whose readGenerationWatermark returns a non-number.
  var sharedIss = { _l: [], list: function () { return this._l; }, add: function (e) { this._l.push(e); } };
  var caWm = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled", issuanceStore: sharedIss,
    revocationStore: { list: function () { return []; }, add: function () {},
      readGenerationWatermark: function () { return "nope"; }, bumpGenerationWatermark: function () {} } });
  await caWm.initCA();
  check("issuance fails closed when a clustered watermark is non-numeric",
        (await code2(function () { return caWm.generateClientCert({ cn: "x" }); })) === "mtls-ca/watermark-unreadable");

  // A versioned revocationStore: the version() rebuild arm.
  var verStore = { _l: [], _v: 1, list: function () { return this._l; },
    add: function (e) { this._l.push(e); this._v += 1; }, version: function () { return this._v; } };
  var caVer = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled", revocationStore: verStore });
  await caVer.initCA();
  var lv = await caVer.generateClientCert({ cn: "v" });
  await caVer.revoke(lv.serialNumber);
  check("a versioned revocationStore reflects a revocation via its version() signal",
        caVer.isRevoked(lv.serialNumber) === true);

  // A malformed issuance ledger (parse throws) fails closed — revokeGeneration reads the
  // ledger directly, so it surfaces issuance-corrupt (generateClientCert would wrap it).
  var caIL = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled" });
  await caIL.initCA();
  fs.writeFileSync(caIL.paths.issuance, "not json{{{");
  check("a malformed issuance ledger fails closed (issuance-corrupt)",
        (await code2(function () { return caIL.revokeGeneration(2); })) === "mtls-ca/issuance-corrupt");

  // The issuanceStore.add write throwing fails issuance closed.
  var caIW = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled",
    issuanceStore: { list: function () { return []; }, add: function () { throw new Error("disk full"); } } });
  await caIW.initCA();
  check("issuance fails closed when the ledger write throws",
        (await code2(function () { return caIW.generateClientCert({ cn: "x" }); })) === "mtls-ca/issuance-ledger-write-failed");

  // The local watermark file present-but-unreadable aborts issuance.
  var caWr = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled" });
  await caWr.initCA();
  await caWr.revokeGeneration(2);
  var realRead = atomicFile.fdSafeReadSync;
  atomicFile.fdSafeReadSync = function (p) {
    if (String(p) === String(caWr.paths.revokedGeneration)) { throw new Error("wm read fail"); }
    return realRead.apply(this, arguments);
  };
  var wmErr;
  try { wmErr = await code2(function () { return caWr.generateClientCert({ cn: "x" }); }); }
  finally { atomicFile.fdSafeReadSync = realRead; }
  check("issuance fails closed when the local watermark file is unreadable", wmErr === "mtls-ca/watermark-unreadable");

  // loadTrustBundle on a handle with NO CA (cur null -> []).
  var caNoCa = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled" });
  check("loadTrustBundle on a handle with no CA returns []", (await caNoCa.loadTrustBundle()).length === 0);

  // A malformed-JSON rollback journal is tolerated by the trust-bundle read (parse catch).
  var caJ = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled" });
  await caJ.initCA();
  fs.writeFileSync(caJ.paths.caKey + ".rollback", "not-json{{{");
  check("loadTrustBundle tolerates a malformed journal (parse catch)", (await caJ.loadTrustBundle()).length === 1);

  // A key-only commit (ca.crt absent) journals cert:null and publishes the new CA.
  var caK = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled" });
  await caK.initCA();
  fs.rmSync(caK.paths.caCert, { force: true });
  var g2 = await engine.generateCa({ generation: 2 });
  await caK.commit({ caKeyPem: g2.caKeyPem, caCertPem: g2.caCertPem, retainPrevious: false });
  check("a key-only commit (no prior cert) publishes the new CA",
        fs.readFileSync(caK.paths.caCert).toString("utf8") === g2.caCertPem);
}

// Reconcile / journal-read arms that only fire when a crash left files ABSENT: the
// current-cert / current-key reads returning null, a completed journal with no newKey,
// and the trust-read tolerating an absent current cert.
async function testReconcileFileAbsentBranches() {
  // Interrupted crash with BOTH ca.crt and ca.key removed: reconcile's curCertBuf and
  // curKeyRaw null arms, and _journalRetainedRoot's no-current-cert arm.
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await ca.initCA();
  var key1 = fs.readFileSync(ca.paths.caKey);
  var cert1 = fs.readFileSync(ca.paths.caCert);
  fs.rmSync(ca.paths.caCert, { force: true });
  fs.rmSync(ca.paths.caKey, { force: true });
  fs.writeFileSync(ca.paths.caKey + ".rollback", _journalManifest({
    key: key1, newKey: key1, cert: cert1, newCert: cert1,   // live cert absent => interrupted
    retainAfter: false, crlMovedAside: false, prevAction: "delete", prevData: null,
  }));
  check("loadTrustBundle with a journal and no ca.crt returns []", (await ca.loadTrustBundle()).length === 0);
  var g = await engine.generateCa({ generation: 2 });
  var reopened = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await reopened.commit({ caKeyPem: g.caKeyPem, caCertPem: g.caCertPem, retainPrevious: false });
  check("commit reconciles a key/cert-absent interrupted journal then publishes",
        fs.readFileSync(reopened.paths.caCert).toString("utf8") === g.caCertPem);

  // Completed key-only journal with NO newKey: the wantKeyBuf null arm (key drive skipped).
  var dir2 = _mkTmp();
  var ca2 = b.mtlsCa.create({ dataDir: dir2, caKeySealedMode: "disabled" });
  await ca2.initCA();
  var certA = fs.readFileSync(ca2.paths.caCert);
  var keyA = fs.readFileSync(ca2.paths.caKey);
  fs.writeFileSync(ca2.paths.caKey + ".rollback", _journalManifest({
    key: keyA, newKey: null, cert: null, newCert: certA,   // priorCert null, live==newCert => completed; newKey absent
    retainAfter: false, crlMovedAside: false, prevAction: "delete", prevData: null,
  }));
  var reopened2 = b.mtlsCa.create({ dataDir: dir2, caKeySealedMode: "disabled" });
  await reopened2.initCA();
  check("reconcile of a completed journal with no newKey leaves the live key",
        fs.readFileSync(reopened2.paths.caKey).equals(keyA));
}

// async variant of code() for rejected promises.
async function code2(fn) { try { await fn(); return "NO-THROW"; } catch (e) { return e.code; } }

async function run() {
  try {
    await testStatusAlgorithmKeyType();
    await testRotate();
    await testTrustBundleRetention();
    await testCanVerifyInTls();
    await testRevokeGeneration();
    await testRotatePersistsOverrideAlgorithm();
    await testRotateRejectsFractionalGeneration();
    await testStatusAlgorithmNullForNonP384Ec();
    await testRetainPreviousFalseClearsStaleRoot();
    await testIssuanceLedgerFailsClosed();
    await testRevokeGenerationBackfillsFingerprint();
    await testRetainedRootSurvivesFailedCommit();
    await testRotateAbortsWhenRetainedRootWriteFails();
    await testP12RequiresLedgerIdentity();
    await testCrlOmissionCountExcludesSerialDupes();
    await testConcurrentRotationsSerialize();
    await testRevocationIndexStaysConsistent();
    await testRevocationIndexRefreshesAcrossHandles();
    await testRotationConflictAcrossHandles();
    await testCanVerifyInTlsProbesTargetAlgorithm();
    await testConcurrentIssuanceAllRecorded();
    await testStatusAlgorithmNullForWrongDigest();
    await testIssuanceSupersededByGenerationRevocation();
    await testIssuanceSupersededWithCustomStore();
    await testClusteredWatermarkViaStoreMethods();
    await testInitCaRefusesPersistentPairMismatch();
    await testCommitRollsBackRetainedRootOnCertRenameFailure();
    await testWatermarkMethodsMustBePaired();
    await testP12CertPemMustBeNonEmpty();
    await testRotateRejectsEmptyAlgorithm();
    await testNestedPathParentDirsCreated();
    await testMalformedWatermarkAbortsIssuance();
    await testImportIssuanceBackfill();
    await testLoadTrustBundleToleratesConcurrentPrevRemoval();
    await testImportOfRevokedGenerationIsRevoked();
    await testInterruptedRotationRecoversFromJournal();
    await testInterruptedRotationRecoversRetainedRoot();
    await testCorruptIssuanceLedgerSchemaFailsClosed();
    await testRotateRetainFalseAbortsWhenRemovalFails();
    await testCanVerifyInTlsRequiresLabelWhenUndeterminable();
    await testClusteredRevocationStoreRequiresSharedIssuanceStore();
    await testLoadTrustBundleDedupsIdenticalRetainedRoot();
    await testRefuseConsecutiveRetainedRotations();
    await testRotateAbortsWhenPriorKeyUnreadable();
    await testLoadTrustBundleIncludesUnreconciledJournalRoot();
    await testLoadTrustBundleExcludesSpentJournalRoot();
    await testPartialRollbackKeepsJournalForRetainedRoot();
    await testCommitAbortsWhenPriorCertUnreadable();
    await testCommitAbortsWhenPriorRetainedRootUnreadable();
    await testDropRetainedReconcilesInterruptedJournal();
    await testCustomEngineReconcileRestoresKeyByBytes();
    await testUnpinnedRotatePreservesStoredAlgorithm();
    await testHardCutRotationSupersedesStraddlingIssuance();
    await testDropRetainedSupersedesStraddlingIssuance();
    await testNormalIssuanceNotFalselySuperseded();
    await testConcurrentFirstInitDoesNotClobber();
    await testReconcileFinishesCompletedRotationWithLostKey();
    await testReconcileRemovesResurrectedHardCutRoot();
    await testPublicCommitEnforcesSingleRetainedWindow();
    await testCanVerifyInTlsProbesDefaultBeforeInit();
    await testReconcileJournalDeletionFailurePropagates();
    await testPublicCommitIsLockedPromise();
    await testRotationInvalidatesStaleCrl();
    await testPublicCommitReconcilesLeftoverJournalFirst();
    await testGenerateCrlSkipsPersistIfCaRotated();
    await testGenerateCrlSkipsPersistIfRevocationLandedDuringSigning();
    await testGenerateCrlPersistsWithCustomRevocationStore();
    await testLeafAlgorithmBindsToSnapshotNotRacingPinRefresh();
    await testCanVerifyInTlsPrefersCustomPinOverInferredLabel();
    await testPublicCommitInvalidatesStaleCrl();
    await testRotationCasDetectsSameGenerationCommit();
    await testPublicCommitRefusesRetentionAmbiguityWhileWindowOpen();
    await testMutatingPathFailsClosedOnCorruptRollbackJournal();
    await testRotationAbortsWhenStaleCrlCannotBeMovedAside();
    await testRotationRestoresCrlWhenCertPublishFails();
    await testReconcileRestoresCrlForInterruptedRotation();
    await testOpaqueCustomEngineIssuanceGenerationNotZero();
    await testFreshInitAdoptionValidatesPin();
    await testPublicCommitRefreshesAlgorithmPin();
    await testReconcileRollsForwardKeyOnlyInit();
    await testPublicCommitPreservesCustomEnginePin();
    await testCanVerifyInTlsRejectsInvalidExplicitAlgorithm();
    await testNonBooleanRetainPreviousRejected();
    await testCommitDoesNotRestoreOrphanCrlRollback();
    await testReconcileDoesNotRestoreOrphanCrlRollback();
    await testReconcileRemovesResurrectedLiveCrlOnRollForward();
    await testReconcileRemovesLeftoverCrlRollbackOnRollForward();
    await testIdempotentCommitPreservesCrl();
    await testCommitFailsClosedWhenSameCertCutJournalUnlinkFails();
    await testCommitSwallowsJournalUnlinkFailureOnCertChange();
    await testCommitUpdatesCustomEnginePinToSuppliedAlgorithm();
    await testRotateRefusesUndeterminableGeneration();
    await testReconcileRejectsMalformedManifestBase64();
    await testGenerateClientP12AcceptsOpaqueCert();
    await testStatusIsLegacyFalseForUndeterminableGeneration();
    await testJournalRetainedRootRejectsMalformedPrevData();
    await testJournalRetainedRootSkippedWhenLiveCertAbsent();
    await testMtlsCaReachableBranchCoverage();
    await testReconcileFileAbsentBranches();
  } finally {
    for (var i = 0; i < _tmpDirs.length; i++) {
      try { fs.rmSync(_tmpDirs[i], { recursive: true, force: true }); } catch (_e) { /* best-effort cleanup */ }
    }
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
