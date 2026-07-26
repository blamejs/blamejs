// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.mtlsCa.create — opts.paths resolution.
 *
 * Pre-v0.8.58 _resolvePaths always joined every entry under dataDir,
 * silently overriding an operator-supplied absolute path. v0.8.58
 * preserves absolute paths (Node `path.join` semantics) so an
 * operator can point caKey / caCert at a fixed mount outside the
 * dataDir without the framework rewriting the location.
 */

var helpers = require("../helpers");
var b      = helpers.b;
var fs     = helpers.fs;
var os     = helpers.os;
var path   = helpers.path;
var check  = helpers.check;

function _mkDir(prefix) { return fs.mkdtempSync(path.join(os.tmpdir(), prefix)); }

// A vault double whose seal() yields a Buffer (matching b.vault, whose
// sealed bytes are binary) so the required-mode commit exercises the
// Buffer arm of the exclusive-write path.
function _bufferVault() {
  return {
    seal:   function (pem) { return Buffer.from("SEAL:" + pem); },
    unseal: function (bytes) { return String(bytes).replace(/^SEAL:/, ""); },
  };
}

// Config-time validation + create-time filesystem setup.
async function testCreateTimeBranches() {
  var threwNoDataDir = false;
  try { b.mtlsCa.create(); } catch (e) { threwNoDataDir = /no-datadir/.test(e.code || ""); }
  check("create() with no opts is refused (no dataDir)", threwNoDataDir);

  var threwBadMode = false;
  try { b.mtlsCa.create({ dataDir: _mkDir("mtls-m-"), caKeySealedMode: "auto" }); }
  catch (e) { threwBadMode = /bad-mode/.test(e.code || ""); }
  check("legacy 'auto' sealed-mode is refused", threwBadMode);

  // dataDir that does not exist yet is auto-created; sealed-mode defaults
  // to "required" when the opt is omitted.
  var nested = path.join(os.tmpdir(), "mtls-mk-" + Date.now() + "-" + Math.random().toString(16).slice(2), "nested");
  var caDefault = b.mtlsCa.create({ dataDir: nested });
  check("a missing dataDir is created on demand", fs.existsSync(nested));
  check("caKeySealedMode defaults to 'required'", caDefault.caKeySealedMode === "required");
}

// status() when a CA is present on disk (the exists()==true arm) — an
// unparseable cert reads back generation 0, which is < the handle's
// current generation, so the CA reports legacy.
async function testStatusExists() {
  var dir = _mkDir("mtls-st-");
  fs.writeFileSync(path.join(dir, "ca.crt"), "TEST CRT");
  fs.writeFileSync(path.join(dir, "ca.key"), "TEST KEY");
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", generation: 3 });
  var st = ca.status();
  check("status() reports the on-disk CA as existing", st.exists === true);
  check("status() reads generation 0 from an unparseable cert", st.generation === 0);
  check("status() flags a below-current CA as legacy", st.isLegacy === true && st.current === 3);
}

// loadKey / loadCert dispatch across the sealed-mode matrix.
async function testKeyLoadBranches() {
  // No key material at all.
  var d1 = _mkDir("mtls-lk-");
  var ca1 = b.mtlsCa.create({ dataDir: d1, caKeySealedMode: "disabled" });
  var threwMissingKey = false;
  try { ca1.loadKey(); } catch (e) { threwMissingKey = /missing-key/.test(e.code || ""); }
  check("loadKey with no key on disk throws missing-key", threwMissingKey);
  var threwMissingCert = false;
  try { ca1.loadCert(); } catch (e) { threwMissingCert = /missing-cert/.test(e.code || ""); }
  check("loadCert with no cert on disk throws missing-cert", threwMissingCert);

  // required mode, only a plaintext key present → sealed form required.
  var d2 = _mkDir("mtls-lk-");
  var ca2 = b.mtlsCa.create({ dataDir: d2, caKeySealedMode: "required", vault: _bufferVault() });
  fs.writeFileSync(path.join(d2, "ca.key"), "PLAINTEXT-KEY");
  var threwSealedRequired = false;
  try { ca2.loadKey(); } catch (e) { threwSealedRequired = /sealed-required/.test(e.code || ""); }
  check("required mode with only a plaintext key throws sealed-required", threwSealedRequired);

  // required mode, a sealed key present but no vault wired → no-vault.
  var d3 = _mkDir("mtls-lk-");
  var ca3 = b.mtlsCa.create({ dataDir: d3, caKeySealedMode: "required" });
  fs.writeFileSync(path.join(d3, "ca.key.sealed"), "SEALED-BYTES");
  var threwNoVault = false;
  try { ca3.loadKey(); } catch (e) { threwNoVault = /no-vault/.test(e.code || ""); }
  check("required mode with a sealed key but no vault throws no-vault", threwNoVault);

  // disabled mode, only a sealed key present → plaintext form required.
  var d4 = _mkDir("mtls-lk-");
  var ca4 = b.mtlsCa.create({ dataDir: d4, caKeySealedMode: "disabled" });
  fs.writeFileSync(path.join(d4, "ca.key.sealed"), "SEALED-BYTES");
  var threwPlainRequired = false;
  try { ca4.loadKey(); } catch (e) { threwPlainRequired = /plain-required/.test(e.code || ""); }
  check("disabled mode with only a sealed key throws plain-required", threwPlainRequired);
}

// commit(): argument guard, the sealed (Buffer-write) arm, and the
// exclusive-create failure path that surfaces commit-failed.
async function testCommitBranches() {
  var d1 = _mkDir("mtls-cm-");
  var ca1 = b.mtlsCa.create({ dataDir: d1, caKeySealedMode: "disabled" });
  var threwBadCommit = false;
  try { ca1.commit({}); } catch (e) { threwBadCommit = /bad-commit/.test(e.code || ""); }
  check("commit() with missing PEM args throws bad-commit", threwBadCommit);

  // required mode + a vault whose seal() returns a Buffer → the sealed key
  // takes the exclusive-write Buffer arm; unseal returning empty then makes
  // loadKey surface unseal-failed.
  var d2 = _mkDir("mtls-cm-");
  var v2 = { seal: function (pem) { return Buffer.from("SEAL:" + pem); }, unseal: function () { return ""; } };
  var ca2 = b.mtlsCa.create({ dataDir: d2, caKeySealedMode: "required", vault: v2 });
  var committed = ca2.commit({ caKeyPem: "CA-KEY-PEM", caCertPem: "CA-CERT-PEM" });
  check("required-mode commit writes the sealed key form", committed.sealed === true && fs.existsSync(path.join(d2, "ca.key.sealed")));
  var threwUnseal = false;
  try { ca2.loadKey(); } catch (e) { threwUnseal = /unseal-failed/.test(e.code || ""); }
  check("a vault that unseals to empty surfaces unseal-failed", threwUnseal);

  // A residual key .tmp file makes the first exclusive-create ("wx") open
  // fail with EEXIST, exercising the commit cleanup + commit-failed wrap.
  var d3 = _mkDir("mtls-cm-");
  var ca3 = b.mtlsCa.create({ dataDir: d3, caKeySealedMode: "disabled" });
  fs.writeFileSync(path.join(d3, "ca.key.tmp"), "STALE-TMP");
  var threwCommitFailed = false;
  try { ca3.commit({ caKeyPem: "K", caCertPem: "C" }); } catch (e) { threwCommitFailed = /commit-failed/.test(e.code || ""); }
  check("a residual key .tmp file makes commit fail with commit-failed", threwCommitFailed);

  // A residual cert .tmp file lets the key write succeed but fails the cert
  // write, so cleanup finds BOTH tmp files present (the other cleanup arm).
  var d4 = _mkDir("mtls-cm-");
  var ca4 = b.mtlsCa.create({ dataDir: d4, caKeySealedMode: "disabled" });
  fs.writeFileSync(path.join(d4, "ca.crt.tmp"), "STALE-CERT-TMP");
  var threwCommitFailed2 = false;
  try { ca4.commit({ caKeyPem: "K", caCertPem: "C" }); } catch (e) { threwCommitFailed2 = /commit-failed/.test(e.code || ""); }
  check("a residual cert .tmp file makes commit fail after the key write", threwCommitFailed2);

  // A vault whose seal() throws an Error with no message: the commit
  // wrapper must still surface commit-failed, formatting the thrown value
  // through the String() fallback of its message builder.
  var d5 = _mkDir("mtls-cm-");
  var throwingVault = { seal: function () { throw new Error(""); }, unseal: function () { return "x"; } };
  var ca5 = b.mtlsCa.create({ dataDir: d5, caKeySealedMode: "required", vault: throwingVault });
  var threwFromVault = false;
  try { ca5.commit({ caKeyPem: "K", caCertPem: "C" }); } catch (e) { threwFromVault = /commit-failed/.test(e.code || ""); }
  check("a vault seal() that throws a message-less Error still surfaces commit-failed", threwFromVault);
}

// Engine-output validation on the framework side: a custom engine that
// returns a malformed shape must be rejected, and the no-arg / no-password
// default guards must fire.
async function testEngineOutputGuards() {
  var okGen = async function () { return { caCertPem: "C", caKeyPem: "K" }; };
  var stub = { generateCa: okGen, signClientCert: async function () { return { cert: "CERT-PEM", key: "KEY-PEM" }; } };

  // generateCa returns no PEMs.
  var c1 = b.mtlsCa.create({ dataDir: _mkDir("mtls-eg-"), caKeySealedMode: "disabled", engine: { generateCa: async function () { return {}; } } });
  var threwGen = false;
  try { await c1.initCA(); } catch (e) { threwGen = /bad-engine-output/.test(e.code || ""); }
  check("initCA rejects an engine that returns no CA PEMs", threwGen);

  // generateClientCert with no opts still runs (opts default) through a stub.
  var c2 = b.mtlsCa.create({ dataDir: _mkDir("mtls-eg-"), caKeySealedMode: "disabled", engine: stub });
  var r2 = await c2.generateClientCert();
  check("generateClientCert() with no opts issues through the engine", typeof r2.cert === "string");

  // signClientCert returns a malformed shape.
  var c3 = b.mtlsCa.create({ dataDir: _mkDir("mtls-eg-"), caKeySealedMode: "disabled", engine: { generateCa: okGen, signClientCert: async function () { return {}; } } });
  var threwSign = false;
  try { await c3.generateClientCert({ cn: "x" }); } catch (e) { threwSign = /bad-engine-output/.test(e.code || ""); }
  check("generateClientCert rejects a malformed engine cert", threwSign);

  // generateClientP12 requires a password (no-opts and empty-opts both).
  var c4 = b.mtlsCa.create({ dataDir: _mkDir("mtls-eg-"), caKeySealedMode: "disabled", engine: stub });
  var threwNoPass1 = false;
  try { await c4.generateClientP12(); } catch (e) { threwNoPass1 = /no-password/.test(e.code || ""); }
  check("generateClientP12() with no opts throws no-password", threwNoPass1);
  var threwNoPass2 = false;
  try { await c4.generateClientP12({}); } catch (e) { threwNoPass2 = /no-password/.test(e.code || ""); }
  check("generateClientP12({}) throws no-password", threwNoPass2);

  // packageP12 returns a non-Buffer p12.
  var c5 = b.mtlsCa.create({ dataDir: _mkDir("mtls-eg-"), caKeySealedMode: "disabled", engine: { generateCa: okGen, packageP12: async function () { return { p12: "not-a-buffer" }; } } });
  var threwP12 = false;
  try { await c5.generateClientP12({ password: "pw" }); } catch (e) { threwP12 = /bad-engine-output/.test(e.code || ""); }
  check("generateClientP12 rejects a non-Buffer p12", threwP12);

  // packageP12 returns a Buffer but a non-string certPem → identity
  // enrichment is skipped and the raw result is returned unchanged.
  var c6 = b.mtlsCa.create({ dataDir: _mkDir("mtls-eg-"), caKeySealedMode: "disabled", engine: { generateCa: okGen, packageP12: async function () { return { p12: Buffer.from("P12"), certPem: 123 }; } } });
  var r6 = await c6.generateClientP12({ password: "pw" });
  check("a p12 result without a string certPem is returned without a fingerprint",
    Buffer.isBuffer(r6.p12) && r6.fingerprint === undefined);
}

async function testAbsolutePathHonored() {
  var dataDir = _mkDir("mtls-d-");
  var certDir = _mkDir("mtls-c-");
  // Pre-create files at the absolute path so .exists() can confirm.
  fs.writeFileSync(path.join(certDir, "ca.crt"), "TEST CRT");
  fs.writeFileSync(path.join(certDir, "ca.key"), "TEST KEY");
  var ca = b.mtlsCa.create({
    dataDir:          dataDir,
    caKeySealedMode:  "disabled",
    paths: {
      caKey:  path.join(certDir, "ca.key"),
      caCert: path.join(certDir, "ca.crt"),
    },
  });
  check("absolute caCert path passes through unchanged",
    ca.paths.caCert === path.join(certDir, "ca.crt"));
  check("absolute caKey path passes through unchanged",
    ca.paths.caKey === path.join(certDir, "ca.key"));
  check("exists() returns true when CA files are at the resolved absolute paths",
    ca.exists() === true);
}

async function testRelativePathStillJoinsUnderDataDir() {
  var dataDir = _mkDir("mtls-d-");
  var ca = b.mtlsCa.create({
    dataDir:          dataDir,
    caKeySealedMode:  "disabled",
    paths: {
      caKey:  "ca.key",
      caCert: "ca.crt",
    },
  });
  check("relative caCert joins under dataDir (back-compat)",
    ca.paths.caCert === path.join(dataDir, "ca.crt"));
  check("relative caKey joins under dataDir (back-compat)",
    ca.paths.caKey === path.join(dataDir, "ca.key"));
}

async function testMixedAbsoluteRelative() {
  var dataDir = _mkDir("mtls-d-");
  var keyDir  = _mkDir("mtls-k-");
  var ca = b.mtlsCa.create({
    dataDir:          dataDir,
    caKeySealedMode:  "disabled",
    paths: {
      caKey:  path.join(keyDir, "rotated.key"),   // absolute → honored
      caCert: "ca.crt",                            // relative → joins
    },
  });
  check("absolute caKey honored",
    ca.paths.caKey === path.join(keyDir, "rotated.key"));
  check("relative caCert joined under dataDir",
    ca.paths.caCert === path.join(dataDir, "ca.crt"));
}

async function run() {
  await testAbsolutePathHonored();
  await testRelativePathStillJoinsUnderDataDir();
  await testMixedAbsoluteRelative();
  await testCreateTimeBranches();
  await testStatusExists();
  await testKeyLoadBranches();
  await testCommitBranches();
  await testEngineOutputGuards();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.message); process.exit(1); }
  );
}
