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
  check("loadTrustBundle: one cert before rotation", ca.loadTrustBundle().length === 1);
  var prevCert = ca.loadCert().toString("utf8");
  await ca.rotate({ generation: 2, algorithm: "ECDSA-P384-SHA384" });   // retainPrevious defaults on
  var bundle = ca.loadTrustBundle();
  check("loadTrustBundle: current + retained after rotate",
        bundle.length === 2 && bundle.indexOf(prevCert) !== -1);
  var d = await ca.dropRetained();
  check("dropRetained: ends the window", d.dropped === true && ca.loadTrustBundle().length === 1);
  check("dropRetained: idempotent when nothing retained", (await ca.dropRetained()).dropped === false);

  var ca2 = _newCa(); await ca2.initCA();
  await ca2.rotate({ generation: 2, retainPrevious: false });
  check("rotate({retainPrevious:false}): no retained CA", ca2.loadTrustBundle().length === 1);
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
  check("retained root present after a retained rotation", ca.loadTrustBundle().length === 2);
  await ca.rotate({ generation: 3, retainPrevious: false });
  check("rotate({retainPrevious:false}) clears the stale retained root",
        ca.loadTrustBundle().length === 1);
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
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await ca.initCA();
  await ca.rotate({ generation: 2 });   // retains -> ca.prev.crt
  check("retained root present before the failing rotation", ca.loadTrustBundle().length === 2);
  // Sabotage the next commit: pre-create the key tmp path so exclusive-create fails.
  var keyTmp = ca.paths.caKey + ".tmp";
  fs.writeFileSync(keyTmp, "blocker");
  check("the sabotaged rotation fails",
        (await code2(function () { return ca.rotate({ generation: 3, retainPrevious: false }); }))
          === "mtls-ca/commit-failed");
  check("the retained root SURVIVES a failed retainPrevious:false rotation",
        ca.loadTrustBundle().length === 2);
}

// A rotation whose CA commit SUCCEEDS but whose retained-root snapshot fails
// (full/read-only fs) must still succeed — the CA is committed, the algorithm
// override sticks, and the handle keeps issuing. The retained root is secondary.
async function testRotateSucceedsWhenRetainedRootWriteFails() {
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, algorithm: "ECDSA-P384-SHA384", caKeySealedMode: "disabled" });
  await ca.initCA();
  // A directory sits where ca.prev.crt would be written -> the snapshot fails.
  fs.mkdirSync(ca.paths.caCertPrev);
  var rot = await ca.rotate({ generation: 2, algorithm: "ML-DSA-87" });
  check("rotation succeeds even though the retained-root snapshot failed", rot.generation === 2);
  check("the algorithm override still applied despite the retained-root write failure",
        ca.status().algorithm === "ML-DSA-87");
  check("the rotated handle is still usable (issues under the new algorithm)",
        typeof (await ca.generateClientCert({ cn: "post-degraded" })).cert === "string");
  fs.rmdirSync(ca.paths.caCertPrev);
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
// generation and clobber each other's CA + retained root.
async function testConcurrentRotationsSerialize() {
  var ca = _newCa();
  await ca.initCA();   // generation 1
  var results = await Promise.all([ca.rotate({}), ca.rotate({})]);
  var gens = results.map(function (r) { return r.generation; }).sort(function (a, b) { return a - b; });
  check("concurrent rotations serialize into monotonic generations 2 and 3",
        JSON.stringify(gens) === "[2,3]");
  check("the CA ends at generation 3 with a single retained root",
        ca.status().generation === 3 && ca.loadTrustBundle().length === 2);
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
  var release; var barrier = new Promise(function (r) { release = r; });
  var slowEngine = Object.assign({}, engine, {
    signClientCert: async function (a) { await barrier; return engine.signClientCert(a); },
  });
  var hostB = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled", engine: slowEngine, revocationStore: sharedStore() });
  await hostB.initCA();                              // generation 1 on host B's dataDir
  var issuing = hostB.generateClientCert({ cn: "clustered" });   // blocks in signing
  var hostA = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled", revocationStore: sharedStore() });
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
  await ca.initCA();
  await ca.rotate({ generation: 2 });                    // ca.prev.crt = gen-1 (prior retained root)
  var priorPrev = fs.readFileSync(ca.paths.caCertPrev);
  var realRename = atomicFile.renameWithRetry;
  atomicFile.renameWithRetry = function (from, to) {
    if (String(to) === String(ca.paths.caCert)) throw new Error("simulated cert rename failure");
    return realRename.apply(this, arguments);
  };
  var failed = false;
  try {
    try { await ca.rotate({ generation: 3 }); } catch (_e) { failed = true; }
  } finally { atomicFile.renameWithRetry = realRename; }
  check("a rotation whose cert publication fails is rejected", failed);
  check("the prior retained root is restored (not lost) when cert publication fails",
        fs.existsSync(ca.paths.caCertPrev) && fs.readFileSync(ca.paths.caCertPrev).equals(priorPrev));
  // The prior KEY must also be restored — otherwise the new key would sit beside
  // the old cert (a mismatched pair) and the handle would be permanently unusable.
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
    await testRotateSucceedsWhenRetainedRootWriteFails();
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
