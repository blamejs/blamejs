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
var fs       = require("fs");
var os       = require("os");
var path     = require("path");
var engine   = require("../../lib/mtls-engine-default");
var pki      = require("../../lib/vendor/blamejs-pki.cjs");

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
    retainAfter: !!m.retainAfter,
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

// A P12 certPem must be a non-empty parseable certificate — an empty/bogus string
// would record a fingerprint unrelated to the archive's real cert.
async function testP12CertPemMustBeParseable() {
  function eng(certPem) {
    return { generateCa: engine.generateCa, signClientCert: engine.signClientCert,
             packageP12: async function () { return { p12: Buffer.from("x"), certPem: certPem }; } };
  }
  var caEmpty = _newCa({ engine: eng("") }); await caEmpty.initCA();
  check("generateClientP12 refuses an empty certPem",
        (await code2(function () { return caEmpty.generateClientP12({ password: "pw" }); })) === "mtls-ca/bad-engine-output");
  var caBogus = _newCa({ engine: eng("not a certificate") }); await caBogus.initCA();
  check("generateClientP12 refuses a non-parseable certPem",
        (await code2(function () { return caBogus.generateClientP12({ password: "pw" }); })) === "mtls-ca/bad-engine-output");
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
  var codeSeen;
  try { codeSeen = await code2(function () { return ca.commit({ caKeyPem: fresh.caKeyPem, caCertPem: fresh.caCertPem }); }); }
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
    await testP12CertPemMustBeParseable();
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
