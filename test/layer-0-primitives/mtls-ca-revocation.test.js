// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.mtlsCa revocation + issuance identity (#322).
 *
 * The require-mtls gate denies by SHA3-512 fingerprint, but revocation used to
 * be keyed only by serial, the registry could only be a plaintext file, and
 * issuance discarded the serial + fingerprint. This proves the three additive
 * fixes: fingerprint-addressable revoke()/isRevoked(), a bring-your-own
 * revocation store, and serial+fingerprint surfaced from issuance.
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;
var fs   = require("fs");
var os   = require("os");
var path = require("path");
var engine = require("../../lib/mtls-engine-default");

function _mkTmp(prefix) { return fs.mkdtempSync(path.join(os.tmpdir(), prefix)); }

// Issuance variants drive the engine's leaf-signing branches through the
// b.mtlsCa consumer: the extended-key-usage arms (client / server / both),
// SAN entry mapping (DNS: / IP: / bare-IPv4 / bare-DNS / IPv6), the
// serverAuth auto-SAN, an explicit validity window, and the reject paths.
async function testIssuanceVariants() {
  var dir = _mkTmp("blamejs-mtls-issue-");
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });

  var srv = await ca.generateClientCert({ cn: "svc-1", usage: "server", validityDays: 30 });
  check("usage:'server' with an explicit validity issues a cert", typeof srv.cert === "string" && srv.usage === "server");

  var both = await ca.generateClientCert({
    cn: "svc-2",
    usage: "both",
    sans: ["DNS:api.example", "IP:10.0.0.7", "192.168.1.1", "2001:db8::5", "IP:2001:db8::9"],
  });
  check("usage:'both' with mixed DNS/IPv4/IPv6 SANs issues a cert", typeof both.cert === "string");

  var badUsage = false;
  try { await ca.generateClientCert({ cn: "x", usage: "bogus" }); }
  catch (e) { badUsage = /bad-usage/.test(e.code || ""); }
  check("a usage outside client|server|both is refused", badUsage);

  var badCn = false;
  try { await ca.generateClientCert({ cn: "@@@" }); }
  catch (e) { badCn = /bad-cn/.test(e.code || ""); }
  check("a CN of only non-identifier characters is refused", badCn);

  var emptyCn = false;
  try { await ca.generateClientCert({ cn: "" }); }
  catch (e) { emptyCn = /bad-cn/.test(e.code || ""); }
  check("an empty-string CN is refused", emptyCn);

  var badDays = false;
  try { await ca.generateClientCert({ cn: "y", validityDays: -1 }); }
  catch (e) { badDays = /bad-validity-days/.test(e.code || ""); }
  check("a negative validityDays is refused", badDays);

  var badSan = false;
  try { await ca.generateClientCert({ cn: "z", sans: ["IP:not.an.ip"] }); }
  catch (e) { badSan = /bad-san/.test(e.code || ""); }
  check("an unparseable IP SAN is refused", badSan);

  try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
}

// Revocation-key + reason validation: every reject arm of _normalizeSerial,
// _normalizeFingerprint, the unknown-reason guard, isRevoked's type guard,
// and the default file store's non-array / corrupt-registry paths.
async function testRevocationValidation() {
  var dir = _mkTmp("blamejs-mtls-revval-");
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });

  var cases = [
    ["a non-string fingerprint is refused",        function () { ca.revoke({ fingerprint: 123 }); },      /bad-fingerprint/],
    ["a non-hex fingerprint is refused",           function () { ca.revoke({ fingerprint: "zzz" }); },    /bad-fingerprint/],
    ["a non-string serial is refused",             function () { ca.revoke(123); },                       /bad-serial/],
    ["a non-hex serial is refused",                function () { ca.revoke("zz-not-hex"); },              /bad-serial/],
    ["an unknown revocation reason is refused",    function () { ca.revoke("ab", { reason: "bogus" }); }, /bad-reason/],
    ["isRevoked with a non-string key is refused", function () { ca.isRevoked(123); },                    /bad-revocation-key/],
  ];
  for (var i = 0; i < cases.length; i++) {
    var threw = false;
    try { cases[i][1](); } catch (e) { threw = cases[i][2].test(e.code || ""); }
    check(cases[i][0], threw);
  }

  // Registry file present but carrying no revocations array → empty list.
  var dirNoArr = _mkTmp("blamejs-mtls-revnoarr-");
  var caNoArr = b.mtlsCa.create({ dataDir: dirNoArr, caKeySealedMode: "disabled" });
  fs.writeFileSync(path.join(dirNoArr, "revocations.json"), '{"unrelated":1}');
  check("a revocations.json without a revocations array reads as not-revoked", caNoArr.isRevoked("ab") === false);

  // Corrupt registry file → surfaced as revocation-corrupt.
  var dirBad = _mkTmp("blamejs-mtls-revbad-");
  var caBad = b.mtlsCa.create({ dataDir: dirBad, caKeySealedMode: "disabled" });
  fs.writeFileSync(path.join(dirBad, "revocations.json"), "{ this is not json");
  var threwCorrupt = false;
  try { caBad.isRevoked("ab"); } catch (e) { threwCorrupt = /revocation-corrupt/.test(e.code || ""); }
  check("a corrupt revocations.json surfaces revocation-corrupt", threwCorrupt);

  [dir, dirNoArr, dirBad].forEach(function (d) { try { fs.rmSync(d, { recursive: true, force: true }); } catch (_e) { /* best-effort */ } });
}

// The default engine's direct contract: argument defaulting, the
// missing-argument guards on every entry point, the PKCS#12 password
// guard, and algorithm pinning (both the label and the keyAlg-name forms,
// plus the unknown-algorithm reject).
async function testEngineDirectContract() {
  // generateCa with no opts: opts defaults + generation defaults to 1.
  var ca = await engine.generateCa();
  check("engine.generateCa() defaults its options and issues a CA", typeof ca.caCertPem === "string");

  // signClientCert missing-argument arms.
  var signCases = [
    ["engine.signClientCert() with no opts throws missing-arg", undefined],
    ["engine.signClientCert missing both CA PEMs throws missing-arg", { cn: "x" }],
    ["engine.signClientCert missing the CA key throws missing-arg", { cn: "x", caCertPem: "c" }],
  ];
  for (var i = 0; i < signCases.length; i++) {
    var threwS = false;
    try { await engine.signClientCert(signCases[i][1]); } catch (e) { threwS = /missing-arg/.test(e.code || ""); }
    check(signCases[i][0], threwS);
  }

  // packageP12 password guard (no opts and empty-string password).
  var p12Cases = [
    ["engine.packageP12() with no opts throws no-password", undefined],
    ["engine.packageP12 with an empty password throws no-password", { password: "" }],
  ];
  for (var j = 0; j < p12Cases.length; j++) {
    var threwP = false;
    try { await engine.packageP12(p12Cases[j][1]); } catch (e) { threwP = /no-password/.test(e.code || ""); }
    check(p12Cases[j][0], threwP);
  }

  // Algorithm pinning: an unknown label, a match by label, and a match by
  // the underlying keyAlg.name.
  var threwUnknown = false;
  try { await engine.generateCa({ algorithm: "no-such-alg" }); }
  catch (e) { threwUnknown = /unknown-algorithm/.test(e.code || ""); }
  check("engine.generateCa pinned to an unknown algorithm is refused", threwUnknown);

  var byLabel = await engine.generateCa({ algorithm: "ML-DSA-87" });
  check("engine.generateCa pins an algorithm by its label", typeof byLabel.caCertPem === "string");

  var byName = await engine.generateCa({ algorithm: "ECDSA" });
  check("engine.generateCa pins an algorithm by its keyAlg name", typeof byName.caCertPem === "string");
}

async function run() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-mtls-revoke-"));
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", generation: 1 });

  // ---- #322 part 3: issuance surfaces serial + fingerprint ----
  var issued = await ca.generateClientCert({ cn: "client-1" });
  check("issuance surfaces a hex serialNumber",
    typeof issued.serialNumber === "string" && /^[0-9a-f]+$/.test(issued.serialNumber));
  check("issuance surfaces a 128-hex SHA3-512 fingerprint",
    typeof issued.fingerprint === "string" && issued.fingerprint.length === 128);
  check("the surfaced fingerprint equals the gate's b.crypto.sha3Hash(cert)",
    issued.fingerprint === b.crypto.sha3Hash(issued.cert));

  // ---- parseGeneration across its input arms ----
  // A framework-issued CA cert carries an OU=CAv{N} tag; a leaf does not
  // (falls back to generation 1); non-PEM inputs read as 0.
  check("parseGeneration reads the OU=CAv{N} tag off a real CA cert",
    b.mtlsCa.parseGeneration(ca.loadCert()) === 1);
  check("parseGeneration falls back to generation 1 for an untagged leaf cert",
    b.mtlsCa.parseGeneration(issued.cert) === 1);
  check("parseGeneration(null) reads 0", b.mtlsCa.parseGeneration(null) === 0);
  check("parseGeneration(number) reads 0", b.mtlsCa.parseGeneration(12345) === 0);
  check("parseGeneration of an unparseable PEM reads 0",
    b.mtlsCa.parseGeneration("-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----\n") === 0);

  // ---- #322 part 1: revoke + isRevoked by serial (backward-compat) ----
  ca.revoke(issued.serialNumber, { reason: "superseded" });
  check("revoke(serial) then isRevoked(serial) is true", ca.isRevoked(issued.serialNumber) === true);
  check("a serial that was never revoked reads false", ca.isRevoked("00ff") === false);
  var first = ca.revoke(issued.serialNumber);
  var again = ca.revoke(issued.serialNumber);
  check("revoke is idempotent (revokedAt unchanged)", first.revokedAt === again.revokedAt);

  // ---- #322 part 1: revoke + isRevoked by fingerprint (the gate's key) ----
  var issued2 = await ca.generateClientCert({ cn: "client-2" });
  ca.revoke({ fingerprint: issued2.fingerprint, reason: "keyCompromise" });
  check("revoke({fingerprint}) then isRevoked(fingerprint) is true",
    ca.isRevoked(issued2.fingerprint) === true);
  check("isRevoked tolerates separator/case formatting",
    ca.isRevoked(issued2.fingerprint.toUpperCase()) === true);

  var threwNoKey = false;
  try { ca.revoke({ reason: "x" }); } catch (e) { threwNoKey = /no-revocation-key/.test(e.code || ""); }
  check("revoke with neither serial nor fingerprint throws", threwNoKey);

  // ---- #322 part 2: bring-your-own revocation store ----
  var rows = [];
  var store = { list: function () { return rows.slice(); }, add: function (e) { rows.push(e); } };
  var dir2 = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-mtls-byostore-"));
  var ca2 = b.mtlsCa.create({ dataDir: dir2, caKeySealedMode: "disabled", revocationStore: store });
  ca2.revoke("AB:CD:EF", { reason: "cessationOfOperation" });
  check("BYO store: revoke writes through the operator store (normalized serial)",
    rows.length === 1 && rows[0].serialNumber === "abcdef");
  check("BYO store: isRevoked reads through the operator store", ca2.isRevoked("abcdef") === true);
  check("BYO store: the default revocations.json was not written",
    !fs.existsSync(path.join(dir2, "revocations.json")));

  var threwBadStore = false;
  try {
    b.mtlsCa.create({ dataDir: dir2, caKeySealedMode: "disabled", revocationStore: { list: 1 } });
  } catch (e) { threwBadStore = /bad-revocation-store/.test(e.code || ""); }
  check("a revocationStore missing list()/add() is refused at create()", threwBadStore);

  // ---- #322 part 3: a custom engine may return a non-X.509 cert shape ----
  // The serial comes from an X.509 parse (best-effort); the fingerprint is a
  // hash of the returned bytes (always available). Optional identity
  // enrichment must never crash issuance.
  var dir3 = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-mtls-stub-"));
  var stubEngine = {
    generateCa: async function () {
      return { caCertPem: "ENGINE-CA", caKeyPem: "ENGINE-KEY", generation: 1 };
    },
    signClientCert: async function (a) {
      return { cert: "-----BEGIN CERTIFICATE-----\nNOT-X509-" + a.cn + "\n-----END CERTIFICATE-----\n", key: "k" };
    },
  };
  var ca3 = b.mtlsCa.create({ dataDir: dir3, engine: stubEngine, caKeySealedMode: "disabled" });
  var stub = await ca3.generateClientCert({ cn: "stub-client" });
  check("non-X.509 engine cert does not crash issuance", typeof stub.cert === "string");
  check("unparseable cert yields serialNumber null (best-effort)", stub.serialNumber === null);
  check("fingerprint is still surfaced for a non-X.509 cert", stub.fingerprint === b.crypto.sha3Hash(stub.cert));
  ca3.revoke({ fingerprint: stub.fingerprint });
  check("a non-X.509 cert is still revocable by fingerprint", ca3.isRevoked(stub.fingerprint) === true);

  await testIssuanceVariants();
  await testRevocationValidation();
  await testEngineDirectContract();

  try {
    fs.rmSync(dir, { recursive: true, force: true });
    fs.rmSync(dir2, { recursive: true, force: true });
    fs.rmSync(dir3, { recursive: true, force: true });
  } catch (_e) { /* best-effort */ }
}

module.exports = { run: run };
