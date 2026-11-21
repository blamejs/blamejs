// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * PQC PKCS8 cross-version compatibility.
 *
 * Measured PKCS8 DER lengths (type=pkcs8, format=der):
 *
 *   alg                   Node <= 24.21 (seed + expanded)   Node >= 24.22.0 and 26 (seed-only)
 *   ml-kem-768            2498 bytes                        86 bytes
 *   ml-kem-1024           3266 bytes                        86 bytes
 *   ml-dsa-44             2626 bytes                        54 bytes
 *   ml-dsa-65             4098 bytes                        54 bytes
 *   ml-dsa-87             4962 bytes                        54 bytes
 *   slh-dsa-shake-256f    unchanged across versions (the private key is the seed)
 *   ed25519               48 bytes on every version
 *
 * Node 24.20 and later and Node 26 import the seed-only form, the
 * seed + expanded form and the expanded-only form. They refuse a
 * seed + expanded blob whose two halves disagree.
 *
 * This test:
 *   1. Exports a fresh key per algorithm on the running Node, checks the
 *      seed-only shape, and round-trips it through sign/verify or
 *      encapsulate/decapsulate.
 *   2. Re-imports a seed-only ML-DSA-65 key captured on Node 26.1.0.
 *   3. Re-imports the seed + expanded keys captured on Node 24.21.0 for
 *      ML-KEM-768/1024 and ML-DSA-44/65/87
 *      (test/fixtures/pqc-pkcs8-node24/fixture-raw.json).
 *   4. Loads a vault key, a sealed value and audit-sign keys that
 *      blamejs wrote on Node 24.21.0
 *      (test/fixtures/pqc-pkcs8-node24/fixture-consumer.json) through
 *      b.vault and b.auditSign.
 */

var fs         = require("node:fs");
var os         = require("node:os");
var path       = require("node:path");
var nodeCrypto = require("node:crypto");
var helpers    = require("../helpers");
var check      = helpers.check;
var b          = helpers.b;

var FIXTURE_DIR      = path.join(__dirname, "..", "fixtures", "pqc-pkcs8-node24");
var NODE24_RAW       = JSON.parse(fs.readFileSync(path.join(FIXTURE_DIR, "fixture-raw.json"), "utf8"));
var NODE24_CONSUMER  = JSON.parse(fs.readFileSync(path.join(FIXTURE_DIR, "fixture-consumer.json"), "utf8"));

// Captured on Node v26.1.0 (seed-only shape): PKCS8 DER private key + SPKI DER public key.
var FIXTURE_NODE26_MLDSA65_PRIV_B64 =
  "MDQCAQAwCwYJYIZIAWUDBAMSBCKAIHA2Y+VRD6S2jl3dfX0H5KVTQk4NjoacmIB6V8W8EkkC";
var FIXTURE_NODE26_MLDSA65_PUB_B64 =
  "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";

// seedCeiling: a seed-only export is at most this long. shapeStable: the
// export has the same length on every Node version.
var ALG_TABLE = [
  { name: "ml-kem-768",         seedCeiling: 256, shapeStable: false, kind: "kem" },
  { name: "ml-kem-1024",        seedCeiling: 256, shapeStable: false, kind: "kem" },
  { name: "ml-dsa-44",          seedCeiling: 256, shapeStable: false, kind: "sig" },
  { name: "ml-dsa-65",          seedCeiling: 256, shapeStable: false, kind: "sig" },
  { name: "ml-dsa-87",          seedCeiling: 256, shapeStable: false, kind: "sig" },
  { name: "slh-dsa-shake-256f", seedCeiling: 256, shapeStable: true,  kind: "sig" },
  { name: "ed25519",            seedCeiling: 64,  shapeStable: true,  kind: "sig" },
];

// Node 24.21 seed + expanded encodings: total DER length, seed length,
// expanded-key length and the seed-only re-export length on this Node.
var NODE24_SHAPES = {
  "ml-kem-768":  { der: 2498, seed: 64, expanded: 2400, reexport: 86, kind: "kem" },
  "ml-kem-1024": { der: 3266, seed: 64, expanded: 3168, reexport: 86, kind: "kem" },
  "ml-dsa-44":   { der: 2626, seed: 32, expanded: 2560, reexport: 54, kind: "sig" },
  "ml-dsa-65":   { der: 4098, seed: 32, expanded: 4032, reexport: 54, kind: "sig" },
  "ml-dsa-87":   { der: 4962, seed: 32, expanded: 4896, reexport: 54, kind: "sig" },
};

function _hexPrefix(buf, n) {
  return buf.subarray(0, n).toString("hex");
}

// Reads one DER TLV at `at`: { tag, len, start (content offset), end }.
function _tlv(buf, at) {
  var tag = buf[at];
  var lenByte = buf[at + 1];
  var len, start;
  if (lenByte < 0x80) { len = lenByte; start = at + 2; }
  else {
    var n = lenByte & 0x7f;
    len = 0;
    for (var i = 0; i < n; i += 1) len = (len * 256) + buf[at + 2 + i];
    start = at + 2 + n;
  }
  return { tag: tag, len: len, start: start, end: start + len };
}

function _derLength(n) {
  if (n < 0x80) return Buffer.from([n]);
  var bytes = [];
  while (n > 0) { bytes.unshift(n & 0xff); n = Math.floor(n / 256); }
  return Buffer.from([0x80 | bytes.length].concat(bytes));
}

function _derTlv(tag, content) {
  return Buffer.concat([Buffer.from([tag]), _derLength(content.length), content]);
}

// Splits a PKCS8 PrivateKeyInfo into its algorithm identifier bytes and
// the inner private-key CHOICE.
function _pkcs8Parts(der) {
  var outer = _tlv(der, 0);
  var version = _tlv(der, outer.start);
  var alg = _tlv(der, version.end);
  var octet = _tlv(der, alg.end);
  return {
    head:  der.subarray(outer.start, alg.end),
    inner: der.subarray(octet.start, octet.end),
  };
}

function _pkcs8WithInner(head, inner) {
  return _derTlv(0x30, Buffer.concat([head, _derTlv(0x04, inner)]));
}

// For a seed + expanded CHOICE (SEQUENCE { OCTET seed, OCTET expanded })
// returns the two halves.
function _bothHalves(inner) {
  var seq = _tlv(inner, 0);
  var seed = _tlv(inner, seq.start);
  var expanded = _tlv(inner, seed.end);
  return {
    seqTag:   seq.tag,
    seed:     inner.subarray(seed.start, seed.end),
    expanded: inner.subarray(expanded.start, expanded.end),
  };
}

function _importPkcs8(der) {
  return nodeCrypto.createPrivateKey({ key: der, format: "der", type: "pkcs8" });
}

function _threw(fn) {
  try { fn(); return null; } catch (e) { return e; }
}

function _proveKeyPair(label, kind, priv, pub) {
  if (kind === "kem") {
    var enc = nodeCrypto.encapsulate(pub);
    var dec = nodeCrypto.decapsulate(priv, enc.ciphertext);
    check(label + ": decapsulate recovers the shared key encapsulated to the public key",
      Buffer.isBuffer(dec) && dec.equals(enc.sharedKey));
    return;
  }
  var payload = Buffer.from(label + " payload");
  var sig = nodeCrypto.sign(null, payload, priv);
  check(label + ": a signature verifies with the public key",
    nodeCrypto.verify(null, payload, pub, sig) === true);
  check(label + ": a tampered payload does not verify",
    nodeCrypto.verify(null, Buffer.concat([payload, Buffer.from("x")]), pub, sig) === false);
}

function testCurrentNodeExport() {
  ALG_TABLE.forEach(function (spec) {
    var kp = nodeCrypto.generateKeyPairSync(spec.name);
    var der = kp.privateKey.export({ type: "pkcs8", format: "der" });
    check(spec.name + ": pkcs8 export returns a non-empty Buffer", Buffer.isBuffer(der) && der.length > 0);
    if (!spec.shapeStable) {
      check(spec.name + ": the export is seed-only (len=" + der.length + " prefix=" + _hexPrefix(der, 20) + ")",
        der.length <= spec.seedCeiling);
    }
    check(spec.name + ": pkcs8 starts with SEQUENCE tag", der[0] === 0x30);
    check(spec.name + ": pkcs8 carries INTEGER version=0", der.indexOf(Buffer.from([0x02, 0x01, 0x00])) !== -1);
    var reimported = _importPkcs8(der);
    check(spec.name + ": reimport KeyObject.asymmetricKeyType matches", reimported.asymmetricKeyType === spec.name);
    _proveKeyPair(spec.name + " (current-Node export)", spec.kind, reimported, kp.publicKey);
  });
}

function testNode26SeedOnlyFixture() {
  var fixturePriv = Buffer.from(FIXTURE_NODE26_MLDSA65_PRIV_B64, "base64");
  var fixturePub  = Buffer.from(FIXTURE_NODE26_MLDSA65_PUB_B64,  "base64");
  check("node26 fixture: ml-dsa-65 private key is the seed-only length", fixturePriv.length === 54);
  check("node26 fixture: ml-dsa-65 public key is the SPKI length", fixturePub.length === 1974);
  var priv = _importPkcs8(fixturePriv);
  var pub = nodeCrypto.createPublicKey({ key: fixturePub, format: "der", type: "spki" });
  check("node26 fixture: imports as ml-dsa-65",
    priv.asymmetricKeyType === "ml-dsa-65" && pub.asymmetricKeyType === "ml-dsa-65");
  _proveKeyPair("node26 fixture ml-dsa-65", "sig", priv, pub);
}

function testNode24RawFixturesImport() {
  check("node24 fixtures were captured on Node 24.21.0", NODE24_RAW.node === "v24.21.0");
  Object.keys(NODE24_SHAPES).forEach(function (alg) {
    var shape = NODE24_SHAPES[alg];
    var f = NODE24_RAW.fixtures[alg];
    check("node24 " + alg + ": the fixture is present", !!(f && f.priv && f.pub));
    if (!f) return;
    var der = Buffer.from(f.priv, "base64");
    var spki = Buffer.from(f.pub, "base64");
    var halves = _bothHalves(_pkcs8Parts(der).inner);
    check("node24 " + alg + ": the fixture is the " + shape.der + "-byte seed + expanded encoding",
      der.length === shape.der && halves.seqTag === 0x30 &&
      halves.seed.length === shape.seed && halves.expanded.length === shape.expanded);

    var priv = _importPkcs8(der);
    var pub = nodeCrypto.createPublicKey({ key: spki, format: "der", type: "spki" });
    check("node24 " + alg + ": imports with asymmetricKeyType " + alg, priv.asymmetricKeyType === alg);
    var derivedSpki = nodeCrypto.createPublicKey(priv).export({ type: "spki", format: "der" });
    check("node24 " + alg + ": the public key derived from the private key equals the captured one",
      derivedSpki.equals(spki));
    _proveKeyPair("node24 " + alg, shape.kind, priv, pub);

    var reexport = priv.export({ type: "pkcs8", format: "der" });
    check("node24 " + alg + ": re-export is the " + shape.reexport + "-byte seed-only form carrying the same seed",
      reexport.length === shape.reexport && reexport.subarray(reexport.length - shape.seed).equals(halves.seed));
  });
}

function testNode24InconsistentHalvesRefused() {
  Object.keys(NODE24_SHAPES).forEach(function (alg) {
    var der = Buffer.from(NODE24_RAW.fixtures[alg].priv, "base64");
    var parts = _pkcs8Parts(der);
    var halves = _bothHalves(parts.inner);
    var seed = Buffer.from(halves.seed);
    seed[0] ^= 1;
    var forged = _pkcs8WithInner(parts.head,
      _derTlv(0x30, Buffer.concat([_derTlv(0x04, seed), _derTlv(0x04, halves.expanded)])));
    check("node24 " + alg + ": the rebuilt blob differs from the fixture only in the seed",
      forged.length === der.length && !forged.equals(der));
    var err = _threw(function () { _importPkcs8(forged); });
    check("node24 " + alg + ": a seed that disagrees with the expanded key is refused with ERR_OSSL_INVALID_KEY",
      err !== null && err.code === "ERR_OSSL_INVALID_KEY", err && (err.code + " " + err.message));

    var unflipped = _pkcs8WithInner(parts.head,
      _derTlv(0x30, Buffer.concat([_derTlv(0x04, halves.seed), _derTlv(0x04, halves.expanded)])));
    check("node24 " + alg + ": the same rebuild with the original seed reproduces the fixture",
      unflipped.equals(der));
  });
}

function testNode24ExpandedOnlyImports() {
  Object.keys(NODE24_SHAPES).forEach(function (alg) {
    var f = NODE24_RAW.fixtures[alg];
    var parts = _pkcs8Parts(Buffer.from(f.priv, "base64"));
    var halves = _bothHalves(parts.inner);
    var expandedOnly = _pkcs8WithInner(parts.head, _derTlv(0x04, halves.expanded));
    var priv = _importPkcs8(expandedOnly);
    var derived = nodeCrypto.createPublicKey(priv).export({ type: "spki", format: "der" });
    check("node24 " + alg + ": the expanded-key-only encoding imports and derives the captured public key",
      priv.asymmetricKeyType === alg && derived.equals(Buffer.from(f.pub, "base64")));
  });
}

function _tmpDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

async function testVaultUnsealsNode24Key() {
  var v = NODE24_CONSUMER.vault;
  check("consumer fixture was written by blamejs on Node 24.21.0", NODE24_CONSUMER.node === "v24.21.0");
  check("consumer vault: the key file holds a " + v.privDerLen + "-byte seed + expanded ML-KEM-1024 key",
    v.privDerLen === 3266);
  var dir = _tmpDir("pkcs8-vault-");
  try {
    fs.writeFileSync(path.join(dir, "vault.key"), v.keyJson, { mode: 0o600 });
    b.vault._resetForTest();
    await b.vault.init({ dataDir: dir, mode: "plaintext" });
    check("consumer vault: b.vault.unseal reads a value sealed on Node 24.21.0",
      b.vault.unseal(v.sealed) === "node24-sealed-secret");
    var fresh = b.vault.seal("sealed-on-this-node");
    check("consumer vault: the Node 24.21.0 key seals and unseals a new value",
      b.vault.unseal(fresh) === "sealed-on-this-node");
    var tampered = v.sealed.slice(0, -4) + (v.sealed.slice(-4) === "AAAA" ? "BBBB" : "AAAA");
    check("consumer vault: a tampered sealed value is refused",
      _threw(function () { b.vault.unseal(tampered); }) !== null);
  } finally {
    b.vault._resetForTest();
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

async function testAuditSignLoadsNode24Keys() {
  var algs = Object.keys(NODE24_CONSUMER.auditSign);
  check("consumer audit-sign: fixtures cover ml-dsa-65 and ml-dsa-87", algs.sort().join(",") === "ml-dsa-65,ml-dsa-87");
  for (var i = 0; i < algs.length; i += 1) {
    var alg = algs[i];
    var f = NODE24_CONSUMER.auditSign[alg];
    var dir = _tmpDir("pkcs8-auditsign-");
    try {
      fs.writeFileSync(path.join(dir, "audit-sign.key"), f.keyJson, { mode: 0o600 });
      b.auditSign._resetForTest();
      await b.auditSign.init({ dataDir: dir, mode: "plaintext", algorithm: alg });
      var sig24 = Buffer.from(f.sigB64, "base64");
      check("consumer audit-sign " + alg + ": loads the key written on Node 24.21.0",
        b.auditSign.getAlgorithm() === alg && b.auditSign.getPublicKeyFingerprint() === f.fingerprint);
      check("consumer audit-sign " + alg + ": a signature made on Node 24.21.0 verifies",
        b.auditSign.verify(f.payload, sig24) === true);
      check("consumer audit-sign " + alg + ": that signature does not verify over a changed payload",
        b.auditSign.verify(f.payload + "x", sig24) === false);
      var payload = "signed-on-this-node " + alg;
      var sigNow = b.auditSign.sign(payload);
      check("consumer audit-sign " + alg + ": a new signature verifies against the Node 24.21.0 public key",
        b.auditSign.verify(payload, sigNow, JSON.parse(f.keyJson).publicKey) === true);
    } finally {
      b.auditSign._resetForTest();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }
}

async function run() {
  var nodeMajor = parseInt(process.versions.node.split(".")[0], 10);
  check("running on a Node version known to this test", nodeMajor >= 26 && nodeMajor < 30);
  testCurrentNodeExport();
  testNode26SeedOnlyFixture();
  testNode24RawFixturesImport();
  testNode24InconsistentHalvesRefused();
  testNode24ExpandedOnlyImports();
  await testVaultUnsealsNode24Key();
  await testAuditSignLoadsNode24Keys();
  console.log("OK — " + helpers.getChecks() + " checks passed");
}

module.exports = { run: run };

if (require.main === module) {
  run().catch(function (e) {
    console.error(e && (e.stack || e.message || String(e)));
    process.exit(1);
  });
}
