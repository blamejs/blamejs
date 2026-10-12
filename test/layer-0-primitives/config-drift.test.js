// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var fs = require("node:fs");
var os = require("node:os");
var path = require("node:path");

var helpers = require("../helpers");
var b      = helpers.b;
var check  = helpers.check;
var setupTestDb = require("../helpers/db").setupTestDb;
var teardownTestDb = require("../helpers/db").teardownTestDb;

function _tmp() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "config-drift-test-"));
}

async function run() {
  check("configDrift namespace present",   typeof b.configDrift === "object");
  check("configDrift.create is fn",        typeof b.configDrift.create === "function");

  // Boot a real framework instance so audit-sign is initialized — the
  // primitive depends on it for the signature.
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    var drift = b.configDrift.create({ dataDir: tmpDir, audit: b.audit });

    var snapshot1 = {
      allowedOrigins: ["https://app.example.com"],
      csp:            "default-src 'self'",
      vaultMode:      "wrapped",
    };
    var first = await drift.checkpoint(snapshot1);
    check("first checkpoint: signed",        first.signed === true);
    check("first checkpoint: not drifted",   first.drifted === false);
    check("first checkpoint: previousAt null", first.previousAt === null);

    // Sidecar exists on disk
    check("sidecar written to disk",        fs.existsSync(path.join(tmpDir, "config-baseline.sig")));

    // Re-checkpoint same snapshot — no drift
    var same = await drift.checkpoint(snapshot1);
    check("repeat checkpoint: not drifted",  same.drifted === false);
    check("repeat checkpoint: previousAt set", typeof same.previousAt === "number");

    // Drift detected on changed snapshot
    var snapshot2 = {
      allowedOrigins: ["https://app.example.com", "https://newbie.example.com"],
      csp:            "default-src 'self'",
      vaultMode:      "wrapped",
    };
    var drifted = await drift.checkpoint(snapshot2);
    check("changed snapshot: drifted true",   drifted.drifted === true);
    check("changed snapshot: diff names changed key",
          drifted.diff && drifted.diff.changed.indexOf("allowedOrigins") !== -1);

    // Tamper detection: corrupt the sidecar
    var sidecarPath = path.join(tmpDir, "config-baseline.sig");
    var raw = fs.readFileSync(sidecarPath, "utf8");
    var parsed = JSON.parse(raw);
    parsed.snapshot.allowedOrigins.push("https://attacker.example.com");  // tamper without re-signing
    fs.writeFileSync(sidecarPath, JSON.stringify(parsed));

    var tampered = await drift.checkpoint(snapshot2);
    check("tampered sidecar: tamper:true",   tampered.tamper === true);
    check("tampered sidecar: not auto-rewritten", tampered.signed === false);

    // read() surfaces verified=false
    var readBack = drift.read();
    check("read: surfaces verified=false on tamper", readBack && readBack.verified === false);

    // Rejects non-object snapshot
    var threwBadSnap = null;
    try { await drift.checkpoint("not-an-object"); }
    catch (e) { threwBadSnap = e; }
    check("checkpoint rejects non-object snapshot", threwBadSnap !== null);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function _testVerifyVendorIntegrity() {
  var result = b.configDrift.verifyVendorIntegrity();
  check("configDrift.verifyVendorIntegrity returns ok shape",
    result && typeof result.ok === "boolean" && Array.isArray(result.mismatches));
  check("configDrift.verifyVendorIntegrity: vendored files match manifest",
    result.ok === true && result.mismatches.length === 0);

  // #321: the check must be cwd-INDEPENDENT — per-file manifest paths resolve
  // under the framework's vendor dir (or an explicit libVendorDir), not
  // process.cwd(). Run it from a different working directory and it must still
  // verify the actual loaded tree (the old code read-failed every entry, or
  // under a crafted cwd could hash a different tree).
  var origCwd = process.cwd();
  var elsewhere = fs.mkdtempSync(path.join(os.tmpdir(), "config-drift-cwd-"));
  try {
    process.chdir(elsewhere);
    var fromElsewhere = b.configDrift.verifyVendorIntegrity();
    check("configDrift.verifyVendorIntegrity is cwd-independent (default vendor dir)",
      fromElsewhere.ok === true &&
      fromElsewhere.checkedCount === result.checkedCount &&
      fromElsewhere.mismatches.length === 0);
  } finally {
    process.chdir(origCwd);
    try { fs.rmSync(elsewhere, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  }

  // SECURITY.md tells an operator to run this at boot and stop the boot on a
  // bad verdict, so what the call does on a mismatch is the contract that
  // instruction rests on: it REPORTS and returns, and the operator exits. The
  // threat model and the checklist both used to say a mismatch "aborts start",
  // which it never did, so an operator following them literally would have kept
  // booting on a swapped bundle with only an audit row to show it. Pin the
  // reporting contract here so the prose cannot drift away from it again.
  var tampered = fs.mkdtempSync(path.join(os.tmpdir(), "config-drift-tamper-"));
  try {
    var pkgDir = path.join(tampered, "fake-pkg");
    fs.mkdirSync(pkgDir, { recursive: true });
    fs.writeFileSync(path.join(pkgDir, "bundle.cjs"), "module.exports = 1;\n", "utf8");
    fs.writeFileSync(path.join(tampered, "MANIFEST.json"), JSON.stringify({
      packages: {
        "fake-pkg": {
          files:  { server: "lib/vendor/fake-pkg/bundle.cjs" },
          hashes: { server: "sha256:" + "0".repeat(64) },
        },
      },
    }), "utf8");

    var verdict = null, threw = null;
    try { verdict = b.configDrift.verifyVendorIntegrity({ libVendorDir: tampered }); }
    catch (e) { threw = e; }
    check("verifyVendorIntegrity reports a mismatch rather than throwing",
      threw === null, threw ? String(threw.code || threw.message) : "");
    check("and the verdict says not ok, which is what the operator must act on",
      verdict !== null && verdict.ok === false, JSON.stringify(verdict));
    check("and it names the file that failed",
      verdict !== null && verdict.mismatches.length === 1 &&
      /bundle\.cjs$/.test(verdict.mismatches[0].path),
      JSON.stringify(verdict && verdict.mismatches));

    // A files entry carrying no hash is listed for verification and cannot be
    // verified, so it is reported rather than skipped: skipping it silently is
    // the zero-files-checked pass the throws below exist to prevent, one entry
    // at a time.
    fs.writeFileSync(path.join(tampered, "MANIFEST.json"), JSON.stringify({
      packages: { "fake-pkg": { files: { server: "lib/vendor/fake-pkg/bundle.cjs" }, hashes: {} } },
    }), "utf8");
    var unhashed = b.configDrift.verifyVendorIntegrity({ libVendorDir: tampered });
    check("a files entry with no hash is reported, not silently skipped",
      unhashed.ok === false && unhashed.mismatches.length === 1 &&
      unhashed.mismatches[0].actual === "<unverifiable-manifest-entry>",
      JSON.stringify(unhashed));

    // An absent manifest, and a manifest with no packages map, are the two cases
    // that DO throw. These are the codes an operator matches on, so they are
    // asserted rather than described.
    var missing = fs.mkdtempSync(path.join(os.tmpdir(), "config-drift-nomanifest-"));
    try {
      var missingErr = null;
      try { b.configDrift.verifyVendorIntegrity({ libVendorDir: missing }); }
      catch (e) { missingErr = e; }
      check("an absent MANIFEST.json throws rather than passing with zero files checked",
        missingErr !== null && missingErr.code === "config-drift/vendor-manifest-missing",
        missingErr ? String(missingErr.code) : "no throw");

      fs.writeFileSync(path.join(missing, "MANIFEST.json"), "{}", "utf8");
      var shapeErr = null;
      try { b.configDrift.verifyVendorIntegrity({ libVendorDir: missing }); }
      catch (e) { shapeErr = e; }
      check("a manifest with no packages map throws its own code",
        shapeErr !== null && shapeErr.code === "config-drift/vendor-manifest-shape",
        shapeErr ? String(shapeErr.code) : "no throw");

      // `typeof null === "object"` and `typeof [] === "object"`, so the shape
      // check admitted both. A null map reached Object.keys and threw a
      // TypeError carrying no code, and an array, an empty map, or a package
      // declaring no files verified nothing and answered ok: true. That is the
      // zero-files-checked pass the throw above exists to prevent, arrived at
      // by a different route.
      function _shapeOf(manifest) {
        fs.writeFileSync(path.join(missing, "MANIFEST.json"),
          JSON.stringify(manifest), "utf8");
        try {
          return { result: b.configDrift.verifyVendorIntegrity({ libVendorDir: missing }) };
        } catch (e) {
          return { code: e.code || ("<untyped " + e.name + ">") };
        }
      }

      var refusedShapes = [
        { label: "null",        manifest: { packages: null } },
        { label: "an array",    manifest: { packages: [] } },
        { label: "an empty map", manifest: { packages: {} } },
      ];
      for (var i = 0; i < refusedShapes.length; i++) {
        var got = _shapeOf(refusedShapes[i].manifest);
        check("a packages map that is " + refusedShapes[i].label +
              " throws the shape code",
          got.code === "config-drift/vendor-manifest-shape",
          JSON.stringify(got));
      }

      // A package that declares no files is reported, not skipped, and not a
      // throw: the manifest's shape is well formed and the run has something
      // to say about it.
      var noFilesCases = [
        { label: "no files map",    manifest: { packages: { lib: { version: "1.0.0" } } } },
        { label: "an empty files map", manifest: { packages: { lib: { files: {} } } } },
      ];
      for (var j = 0; j < noFilesCases.length; j++) {
        var answer = _shapeOf(noFilesCases[j].manifest);
        check("a package with " + noFilesCases[j].label + " is reported rather than passing",
          answer.result !== undefined && answer.result.ok === false &&
          answer.result.checkedCount === 0 &&
          answer.result.mismatches.length === 1 &&
          answer.result.mismatches[0].actual === "<unverifiable-manifest-entry>",
          JSON.stringify(answer));
      }
    } finally {
      try { fs.rmSync(missing, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
    }
  } finally {
    try { fs.rmSync(tampered, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  }
}

module.exports = { run: async function () { await run(); await _testVerifyVendorIntegrity(); } };

if (require.main === module) {
  module.exports.run().then(
    function () { console.log("[config-drift] OK"); },
    function (e) { console.error(e); process.exit(1); }
  );
}
