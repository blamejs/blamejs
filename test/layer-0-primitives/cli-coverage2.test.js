// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

// Supplementary coverage for lib/cli.js — targets the error / defensive /
// adversarial branches that cli-coverage.test.js (and the per-command
// cli-*.test.js files + test/00-primitives.js) leave uncovered:
//
//   - seed RUN path (apply / re-skip / --only / --force / broken-seeder catch)
//   - api-snapshot compare that DETECTS a breaking change (exit 1)
//   - audit archive/export/verify-bundle/purge arg-validation returns +
//     BLAMEJS_AUDIT_PASSPHRASE env resolution + verify-chain FAIL branch +
//     verify-chain valid --max-rows applied
//   - file-type bare / help / read-failure / json+allowlist / json-null
//   - every remaining `<cmd> help` positional (report.helpStdout)
//   - cheap arg-validation returns for security / config-drift / retention /
//     password / api-key / erase / restore / backup
//   - booted-app edges the dedicated tests skip: api-key rotate + revoke
//     no-op + empty-scopes, erase row-lookup-failure catch, retention run
//     against a missing table, mtls status(exists)/show-cert(success)/
//     issue --days/issue-p12 stream-to-stdout, security assert require/forbid-env
//
// Everything drives the public b.cli.main(argv, ctx) surface with a
// captured-output ctx. Local sqlite files + plaintext-vault temp data
// dirs keep it self-contained (no network backend).

var fs = require("node:fs");
var os = require("node:os");
var path = require("node:path");
var sqlite = require("node:sqlite");
var helpers = require("../helpers");
var b = helpers.b;
var check = helpers.check;
var cli = require("../../lib/cli");

function _captureCtx() {
  var stdout = [];
  var stderr = [];
  return {
    stdout: { write: function (s) { stdout.push(String(s)); } },
    stderr: { write: function (s) { stderr.push(String(s)); } },
    env:    {},
    cwd:    process.cwd(),
    out:    function () { return stdout.join(""); },
    err:    function () { return stderr.join(""); },
  };
}

function _tmpDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix + "-"));
}

function _rm(dir) {
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
}

// ---------------------------------------------------------------------------
// top-level dispatch edges
// ---------------------------------------------------------------------------
async function sectionTopLevel() {
  // `-v` short flag → version (covers the `args.flags.v` operand of `||`)
  var cV = _captureCtx();
  var rcV = await cli.main(["-v"], cV);
  check("-v short flag → exit 0",            rcV === 0);
  check("-v short flag → prints version",    /\d+\.\d+\.\d+/.test(cV.out()));

  // `migrate help` positional → _runMigrate's own help branch (distinct from
  // the top-level `migrate --help` synth, which never enters _runMigrate).
  var cMh = _captureCtx();
  var rcMh = await cli.main(["migrate", "help"], cMh);
  check("migrate help positional → exit 0",  rcMh === 0);
  check("migrate help positional → usage",   /Usage: blamejs migrate/.test(cMh.out()));

  // bare `audit` → AUDIT_USAGE on stderr, exit 2
  var cAudit = _captureCtx();
  var rcAudit = await cli.main(["audit"], cAudit);
  check("bare audit → exit 2",               rcAudit === 2);
  check("bare audit → usage on stderr",      /Usage: blamejs audit/.test(cAudit.err()));

  // unknown audit subcommand → exit 2
  var cAuditUnk = _captureCtx();
  var rcAuditUnk = await cli.main(["audit", "frobnicate"], cAuditUnk);
  check("audit unknown sub → exit 2",        rcAuditUnk === 2);
  check("audit unknown sub → names sub",     /unknown subcommand 'frobnicate'/.test(cAuditUnk.err()));
}

// ---------------------------------------------------------------------------
// seed run — apply / re-skip / --only / --force / broken-seeder catch
// ---------------------------------------------------------------------------
async function sectionSeedRun() {
  var dir = _tmpDir("blamejs-cli2-seed");
  try {
    var dbPath = path.join(dir, "seed.db");
    var seedRoot = path.join(dir, "seeders");
    var devDir = path.join(seedRoot, "dev");
    fs.mkdirSync(devDir, { recursive: true });
    fs.writeFileSync(path.join(devDir, "0001-alpha.js"),
      "module.exports = { description: \"a\", run: async function (db) {" +
      " db.exec(\"CREATE TABLE IF NOT EXISTS m_alpha (id INTEGER)\"); } };");
    fs.writeFileSync(path.join(devDir, "0002-beta.js"),
      "module.exports = { description: \"b\", rerunnable: true, run: async function (db) {" +
      " db.exec(\"CREATE TABLE IF NOT EXISTS m_beta (id INTEGER)\"); } };");

    // first run → both apply
    var c1 = _captureCtx();
    var r1 = await cli.main(["seed", "run", "--db", dbPath, "--env", "dev", "--dir", seedRoot], c1);
    check("seed run: first run → exit 0",         r1 === 0);
    check("seed run: applies 2 seeds",            /applied 2 seed\(s\)/.test(c1.out()));

    // status after run → applied rows loop + rerunnable listing
    var c2 = _captureCtx();
    var r2 = await cli.main(["seed", "status", "--db", dbPath, "--env", "dev", "--dir", seedRoot], c2);
    check("seed status (post-run): exit 0",       r2 === 0);
    check("seed status (post-run): env line",     /env: dev/.test(c2.out()));
    check("seed status (post-run): rerunnable",   /rerunnable:/.test(c2.out()));

    // second run → 0001 skipped, 0002 (rerunnable) re-applies
    var c3 = _captureCtx();
    var r3 = await cli.main(["seed", "run", "--db", dbPath, "--env", "dev", "--dir", seedRoot], c3);
    check("seed run: second run → exit 0",        r3 === 0);
    check("seed run: reports a skipped seed",     /skipped 1/.test(c3.out()));

    // --only an already-applied seed → nothing applied (only-branch)
    var c4 = _captureCtx();
    var r4 = await cli.main(
      ["seed", "run", "--db", dbPath, "--env", "dev", "--dir", seedRoot, "--only", "0001-alpha.js"], c4);
    check("seed run --only: exit 0",              r4 === 0);
    check("seed run --only: no re-apply",         /no seeds applied/.test(c4.out()));

    // --force → re-applies already-applied seeds (force-branch)
    var c5 = _captureCtx();
    var r5 = await cli.main(
      ["seed", "run", "--db", dbPath, "--env", "dev", "--dir", seedRoot, "--force"], c5);
    check("seed run --force: exit 0",             r5 === 0);
    check("seed run --force: applies again",      /applied \d+ seed\(s\)/.test(c5.out()));

    // broken seeder → run throws → the run catch returns exit 1
    var dir2 = _tmpDir("blamejs-cli2-seed-broken");
    try {
      var db2 = path.join(dir2, "seed.db");
      var devDir2 = path.join(dir2, "seeders", "dev");
      fs.mkdirSync(devDir2, { recursive: true });
      fs.writeFileSync(path.join(devDir2, "0001-boom.js"),
        "module.exports = { description: \"x\", run: async function () {" +
        " throw new Error(\"boom-seed\"); } };");
      var c6 = _captureCtx();
      var r6 = await cli.main(
        ["seed", "run", "--db", db2, "--env", "dev", "--dir", path.join(dir2, "seeders")], c6);
      check("seed run: broken seeder → exit 1",   r6 === 1);
      check("seed run: broken seeder → stderr",   /blamejs seed run:/.test(c6.err()));
    } finally { _rm(dir2); }
  } finally { _rm(dir); }
}

// ---------------------------------------------------------------------------
// api-snapshot compare that DETECTS a breaking change (exit 1)
// ---------------------------------------------------------------------------
async function sectionApiSnapshotBreaking() {
  var dir = _tmpDir("blamejs-cli2-apisnap");
  try {
    var modA = path.join(dir, "mod-a.js");
    var modB = path.join(dir, "mod-b.js");
    var snap = path.join(dir, "snap.json");
    fs.writeFileSync(modA,
      "module.exports = { version: \"1.0.0\", greet: function greet() {}, extra: function extra() {} };");
    fs.writeFileSync(modB,
      "module.exports = { version: \"1.0.0\", greet: function greet() {} };");

    var cCap = _captureCtx();
    var rcCap = await cli.main(
      ["api-snapshot", "capture", "--file", snap, "--module", modA], cCap);
    check("api-snapshot capture (mod-a): exit 0", rcCap === 0);

    // mod-b dropped `extra` → removed export → breaking → exit 1
    var cCmp = _captureCtx();
    var rcCmp = await cli.main(
      ["api-snapshot", "compare", "--file", snap, "--module", modB], cCmp);
    check("api-snapshot compare breaking → exit 1", rcCmp === 1);
    check("api-snapshot compare breaking → reports it",
          /BREAKING|removed|extra/i.test(cCmp.out()));
  } finally { _rm(dir); }
}

// ---------------------------------------------------------------------------
// audit — arg-validation returns + env passphrase + verify-chain FAIL / max-rows
// ---------------------------------------------------------------------------
async function sectionAudit() {
  var dir = _tmpDir("blamejs-cli2-audit");
  try {
    var outDir = path.join(dir, "bundle-out");

    // archive: missing passphrase → 2
    var a1 = _captureCtx();
    check("audit archive no-pass → exit 2",
          (await cli.main(["audit", "archive", "--out", outDir, "--before", "2020-01-01"], a1)) === 2);
    check("audit archive no-pass → message", /--passphrase or BLAMEJS_AUDIT_PASSPHRASE/.test(a1.err()));

    // archive: passphrase but no --out → 2
    var a2 = _captureCtx();
    check("audit archive no-out → exit 2",
          (await cli.main(["audit", "archive", "--passphrase", "p", "--before", "2020-01-01"], a2)) === 2);
    check("audit archive no-out → message", /--out is required/.test(a2.err()));

    // archive: passphrase + out but no --before → 2
    var a3 = _captureCtx();
    check("audit archive no-before → exit 2",
          (await cli.main(["audit", "archive", "--passphrase", "p", "--out", outDir], a3)) === 2);
    check("audit archive no-before → message", /--before is required/.test(a3.err()));

    // export: passphrase but no --out → 2
    var e1 = _captureCtx();
    check("audit export no-out → exit 2",
          (await cli.main(["audit", "export", "--passphrase", "p"], e1)) === 2);
    check("audit export no-out → message", /--out is required/.test(e1.err()));

    // export: passphrase + out but no from/to/action → 2
    var e2 = _captureCtx();
    check("audit export no-range → exit 2",
          (await cli.main(["audit", "export", "--passphrase", "p", "--out", outDir], e2)) === 2);
    check("audit export no-range → message", /at least one of --from/.test(e2.err()));

    // verify-bundle: passphrase but no --in → 2
    var vb = _captureCtx();
    check("audit verify-bundle no-in → exit 2",
          (await cli.main(["audit", "verify-bundle", "--passphrase", "p"], vb)) === 2);
    check("audit verify-bundle no-in → message", /--in is required/.test(vb.err()));

    // purge: passphrase but no --archive → 2
    var p1 = _captureCtx();
    check("audit purge no-archive → exit 2",
          (await cli.main(["audit", "purge", "--passphrase", "p"], p1)) === 2);
    check("audit purge no-archive → message", /--archive .* is required/.test(p1.err()));

    // purge: passphrase + archive but no --confirm → 2
    var p2 = _captureCtx();
    check("audit purge no-confirm → exit 2",
          (await cli.main(["audit", "purge", "--passphrase", "p", "--archive", outDir], p2)) === 2);
    check("audit purge no-confirm → message", /--confirm is REQUIRED/.test(p2.err()));

    // env passphrase resolution: BLAMEJS_AUDIT_PASSPHRASE satisfies passRequired,
    // then archive fails on the missing --out (exit 2). Exercises the env branch
    // of _resolvePassphrase.
    var envCtx = _captureCtx();
    envCtx.env = { BLAMEJS_AUDIT_PASSPHRASE: "from-env" };
    var rcEnv = await cli.main(["audit", "archive", "--before", "2020-01-01"], envCtx);
    check("audit archive env-pass → past pass-gate to --out → exit 2", rcEnv === 2);
    check("audit archive env-pass → --out message", /--out is required/.test(envCtx.err()));

    // verify-chain: valid --max-rows applied against an empty audit_log (exit 0)
    var okDb = path.join(dir, "ok.db");
    var okHandle = new sqlite.DatabaseSync(okDb);
    okHandle.prepare("CREATE TABLE audit_log (_id INTEGER PRIMARY KEY, monotonicCounter INTEGER," +
      " prevHash TEXT, rowHash TEXT, nonce BLOB)").run();
    okHandle.close();
    var mr = _captureCtx();
    var rcMr = await cli.main(["audit", "verify-chain", "--db", okDb, "--max-rows", "5"], mr);
    check("audit verify-chain --max-rows valid → exit 0", rcMr === 0);
    check("audit verify-chain --max-rows valid → verified", /rowsVerified=0/.test(mr.out()));

    // verify-chain: a tampered first row (prevHash != ZERO_HASH) → FAIL, exit 1
    var badDb = path.join(dir, "bad.db");
    var badHandle = new sqlite.DatabaseSync(badDb);
    badHandle.prepare("CREATE TABLE audit_consent (_id INTEGER PRIMARY KEY, monotonicCounter INTEGER," +
      " prevHash TEXT, rowHash TEXT, nonce BLOB)").run();
    var ins = badHandle.prepare("INSERT INTO audit_consent" +
      " (_id, monotonicCounter, prevHash, rowHash, nonce) VALUES (?, ?, ?, ?, ?)");
    // prevHash of the FIRST row must be the all-zero sentinel; "ff"*64 is a
    // valid 128-hex string that is NOT the sentinel → guaranteed chain break.
    ins.run(1, 1, "ff".repeat(64), "aa".repeat(64), Buffer.alloc(16));
    badHandle.close();
    var fc = _captureCtx();
    var rcFc = await cli.main(
      ["audit", "verify-chain", "--db", badDb, "--table", "audit_consent"], fc);
    check("audit verify-chain tampered → exit 1", rcFc === 1);
    check("audit verify-chain tampered → FAIL line", /FAIL —/.test(fc.err()));
    check("audit verify-chain tampered → prints expected/actual", /expected prevHash:/.test(fc.err()));
  } finally { _rm(dir); }
}

// ---------------------------------------------------------------------------
// file-type — bare / help / read-failure / json+allowlist / json-null
// ---------------------------------------------------------------------------
async function sectionFileType() {
  var dir = _tmpDir("blamejs-cli2-filetype");
  try {
    var pngBytes = Buffer.concat([
      Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
      Buffer.alloc(20),
    ]);
    var pngFile = path.join(dir, "img.png");
    fs.writeFileSync(pngFile, pngBytes);
    var unkFile = path.join(dir, "unk.bin");
    fs.writeFileSync(unkFile, Buffer.from("not-a-known-format-byte-stream-xyz"));

    // bare `file-type` → usage exit 2
    var bare = _captureCtx();
    check("file-type bare → exit 2", (await cli.main(["file-type"], bare)) === 2);
    check("file-type bare → usage", /Usage: blamejs file-type/.test(bare.err()));

    // `file-type help` positional → helpStdout exit 0
    var fh = _captureCtx();
    check("file-type help → exit 0", (await cli.main(["file-type", "help"], fh)) === 0);
    check("file-type help → usage", /Usage: blamejs file-type/.test(fh.out()));

    // detect a nonexistent path → read failure catch → exit 1
    var rf = _captureCtx();
    var rcRf = await cli.main(["file-type", "detect", path.join(dir, "nope.bin")], rf);
    check("file-type detect missing file → exit 1", rcRf === 1);
    check("file-type detect missing file → read failed", /read failed/.test(rf.err()));

    // json + allowlist match → the json arm of the allowlist branch
    var ja = _captureCtx();
    var rcJa = await cli.main(
      ["file-type", "detect", pngFile, "--json", "--allowlist", "image/png,application/pdf"], ja);
    check("file-type allowlist+json → exit 0", rcJa === 0);
    check("file-type allowlist+json → JSON body", /"mime":"image\/png"/.test(ja.out()));

    // json + unknown signature → prints "null" then errors (exit 1)
    var jn = _captureCtx();
    var rcJn = await cli.main(["file-type", "detect", unkFile, "--json"], jn);
    check("file-type json-null → exit 1", rcJn === 1);
    check("file-type json-null → 'null' on stdout", /null/.test(jn.out()));
  } finally { _rm(dir); }
}

// ---------------------------------------------------------------------------
// `<cmd> help` positional — report.helpStdout for every reporter-backed command
// ---------------------------------------------------------------------------
async function sectionPositionalHelp() {
  var cmds = [
    ["restore",      /Usage: blamejs restore/],
    ["backup",       /Usage: blamejs backup/],
    ["mtls",         /Usage: blamejs mtls/],
    ["vault",        /Usage: blamejs vault/],
    ["api-key",      /Usage: blamejs api-key/],
    ["security",     /Usage: blamejs security/],
    ["config-drift", /Usage: blamejs config-drift/],
    ["retention",    /Usage: blamejs retention/],
    ["password",     /Usage: blamejs password/],
  ];
  for (var i = 0; i < cmds.length; i++) {
    var ctx = _captureCtx();
    var rc = await cli.main([cmds[i][0], "help"], ctx);
    check(cmds[i][0] + " help → exit 0", rc === 0);
    check(cmds[i][0] + " help → usage",  cmds[i][1].test(ctx.out()));
  }
}

// ---------------------------------------------------------------------------
// cheap arg-validation returns (no boot)
// ---------------------------------------------------------------------------
async function sectionArgValidation() {
  // bare subcommand-less usages → exit 2
  var bares = ["security", "config-drift", "retention", "password"];
  for (var i = 0; i < bares.length; i++) {
    var cb = _captureCtx();
    check("bare " + bares[i] + " → exit 2", (await cli.main([bares[i]], cb)) === 2);
  }

  // retention: missing --data-dir → 2
  var rNoDir = _captureCtx();
  check("retention preview no data-dir → exit 2",
        (await cli.main(["retention", "preview", "--table", "t", "--age-field", "a", "--ttl-ms", "1"], rNoDir)) === 2);

  // retention: missing --ttl-ms → 2
  var rNoTtl = _captureCtx();
  check("retention preview no ttl-ms → exit 2",
        (await cli.main(["retention", "preview", "--data-dir", "/tmp/x", "--table", "t", "--age-field", "a"], rNoTtl)) === 2);

  // api-key: missing --namespace → 2 (data-dir present)
  var kNoNs = _captureCtx();
  check("api-key issue no namespace → exit 2",
        (await cli.main(["api-key", "issue", "--data-dir", "/tmp/x"], kNoNs)) === 2);
  check("api-key issue no namespace → message", /--namespace/.test(kNoNs.err()));

  // api-key: bad --vault-mode → 2
  var kBadVm = _captureCtx();
  check("api-key bad vault-mode → exit 2",
        (await cli.main(["api-key", "issue", "--data-dir", "/tmp/x", "--namespace", "n", "--vault-mode", "yolo"], kBadVm)) === 2);
  check("api-key bad vault-mode → message", /--vault-mode/.test(kBadVm.err()));

  // erase: missing --data-dir (table/row/confirm all present) → 2
  var eNoDir = _captureCtx();
  check("erase no data-dir → exit 2",
        (await cli.main(["erase", "--table", "users", "--row-id", "r-1", "--confirm", "--vault-mode", "plaintext"], eNoDir)) === 2);
  check("erase no data-dir → message", /--data-dir/.test(eNoDir.err()));
}

// ---------------------------------------------------------------------------
// backup / restore validation + error catches (mostly no boot)
// ---------------------------------------------------------------------------
async function sectionBackupRestoreValidation() {
  var dir = _tmpDir("blamejs-cli2-br");
  try {
    // --- backup ---
    // inspect: missing --bundle → 2
    var b1 = _captureCtx();
    check("backup inspect no bundle → exit 2", (await cli.main(["backup", "inspect"], b1)) === 2);
    check("backup inspect no bundle → message", /--bundle <dir> is required/.test(b1.err()));

    // inspect a nonexistent bundle → restoreBundle.inspect throws → catch → 1
    var b2 = _captureCtx();
    var rcB2 = await cli.main(["backup", "inspect", "--bundle", path.join(dir, "no-such-bundle")], b2);
    check("backup inspect bad bundle → exit 1", rcB2 === 1);

    // verify: missing passphrase → 2 (bundle present so passphrase gate is reached)
    var b3 = _captureCtx();
    check("backup verify no passphrase → exit 2",
          (await cli.main(["backup", "verify", "--bundle", path.join(dir, "b")], b3)) === 2);
    check("backup verify no passphrase → message", /--passphrase or BLAMEJS_BACKUP_PASSPHRASE/.test(b3.err()));

    // extract: passphrase present but missing --to → 2
    var b4 = _captureCtx();
    check("backup extract no --to → exit 2",
          (await cli.main(["backup", "extract", "--bundle", path.join(dir, "b"), "--passphrase", "p"], b4)) === 2);
    check("backup extract no --to → message", /--to <stagingDir> is required/.test(b4.err()));

    // --- restore ---
    // list with no selector → "--storage-root is required" → 2
    var r1 = _captureCtx();
    check("restore list no selector → exit 2", (await cli.main(["restore", "list"], r1)) === 2);
    check("restore list no selector → message", /--storage-root/.test(r1.err()));

    // inspect --storage-root without --bundle-id → 2
    var r2 = _captureCtx();
    check("restore inspect storage-root sans bundle-id → exit 2",
          (await cli.main(["restore", "inspect", "--storage-root", dir], r2)) === 2);
    check("restore inspect storage-root sans bundle-id → message", /--bundle-id is required/.test(r2.err()));

    // rollback with no --data-dir → 2
    var r3 = _captureCtx();
    check("restore rollback no data-dir → exit 2", (await cli.main(["restore", "rollback"], r3)) === 2);

    // list-rollbacks with no --data-dir → 2
    var r4 = _captureCtx();
    check("restore list-rollbacks no data-dir → exit 2", (await cli.main(["restore", "list-rollbacks"], r4)) === 2);

    // apply: valid selector + passphrase, but invalid --max-pulled-bytes → 2
    var r5 = _captureCtx();
    check("restore apply bad max-bytes → exit 2",
          (await cli.main(["restore", "apply", "--data-dir", path.join(dir, "dd"),
            "--bundle", path.join(dir, "bun"), "--passphrase", "p", "--max-pulled-bytes", "-1"], r5)) === 2);
    check("restore apply bad max-bytes → message", /--max-pulled-bytes/.test(r5.err()));

    // apply: invalid --max-pulled-files → 2
    var r6 = _captureCtx();
    check("restore apply bad max-files → exit 2",
          (await cli.main(["restore", "apply", "--data-dir", path.join(dir, "dd"),
            "--bundle", path.join(dir, "bun"), "--passphrase", "p", "--max-pulled-files", "-1"], r6)) === 2);
    check("restore apply bad max-files → message", /--max-pulled-files/.test(r6.err()));

    // rollback with an explicit --rollback that does not exist → primitive
    // throws → catch → non-zero (exercises the explicit-target branch).
    var ddEmpty = path.join(dir, "empty-data");
    fs.mkdirSync(ddEmpty, { recursive: true });
    var r7 = _captureCtx();
    var rcR7 = await cli.main(
      ["restore", "rollback", "--data-dir", ddEmpty, "--rollback", path.join(dir, "no-such-point")], r7);
    check("restore rollback bad explicit target → non-zero", rcR7 !== 0);
  } finally { _rm(dir); }
}

// ---------------------------------------------------------------------------
// booted: api-key rotate + revoke no-op + empty-scopes
// ---------------------------------------------------------------------------
async function sectionBootedApiKey() {
  var dataDir = _tmpDir("blamejs-cli2-apikey");
  try {
    var base = ["--data-dir", dataDir, "--vault-mode", "plaintext", "--namespace", "api"];

    // issue a key so rotate has something to rotate
    var ci = _captureCtx();
    var rci = await cli.main(["api-key", "issue"].concat(base).concat(
      ["--owner-id", "dave", "--scopes", "a:read"]), ci);
    check("apikey issue (for rotate): exit 0", rci === 0);
    var idMatch = ci.out().match(/^id:\s+([a-f0-9]+)/m);
    check("apikey issue: id captured", !!idMatch);
    var id = idMatch ? idMatch[1] : "deadbeef";

    // rotate → new secret, exit 0 (the rotate subcommand is otherwise untested)
    var cr = _captureCtx();
    var rcr = await cli.main(["api-key", "rotate"].concat(base).concat(["--id", id]), cr);
    check("apikey rotate: exit 0", rcr === 0);
    check("apikey rotate: prints new key", /key \(new\):/.test(cr.out()));

    // revoke a nonexistent id → registry.revoke returns false → no-op error path
    var cx = _captureCtx();
    var rcx = await cli.main(["api-key", "revoke"].concat(base).concat(["--id", "00ffffffffffffff"]), cx);
    check("apikey revoke no-op → non-zero", rcx !== 0);
    check("apikey revoke no-op → message", /no-op/.test(cx.err()));

    // issue with scopes that parse to an empty list → exit 2 (post-boot check)
    var cs = _captureCtx();
    var rcs = await cli.main(["api-key", "issue"].concat(base).concat(
      ["--owner-id", "erin", "--scopes", ","]), cs);
    check("apikey issue empty-scopes → exit 2", rcs === 2);
    check("apikey issue empty-scopes → message", /at least one non-empty scope/.test(cs.err()));
  } finally { _rm(dataDir); }
}

// ---------------------------------------------------------------------------
// booted: erase row-lookup-failure catch
// ---------------------------------------------------------------------------
async function sectionBootedErase() {
  var dataDir = _tmpDir("blamejs-cli2-erase");
  try {
    // A syntactically-valid table identifier that does not exist → the SELECT
    // prepare throws → the "row lookup failed" catch returns exit 1.
    var ctx = _captureCtx();
    var rc = await cli.main(
      ["erase", "--data-dir", dataDir, "--table", "nonexistent_tbl", "--row-id", "r-1",
       "--confirm", "--vault-mode", "plaintext"], ctx);
    check("erase missing-table lookup → exit 1", rc === 1);
    check("erase missing-table lookup → catch message", /row lookup failed/.test(ctx.err()));
  } finally { _rm(dataDir); }
}

// ---------------------------------------------------------------------------
// booted: retention run against a missing table (boot + declare + run + error path)
// ---------------------------------------------------------------------------
async function sectionBootedRetention() {
  var dataDir = _tmpDir("blamejs-cli2-retention");
  try {
    var ctx = _captureCtx();
    var rc = await cli.main(
      ["retention", "preview", "--data-dir", dataDir, "--vault-mode", "plaintext",
       "--table", "no_such_retention_tbl", "--age-field", "ts", "--ttl-ms", "1", "--action", "delete"], ctx);
    // The rule boots + declares + runs; a missing table surfaces as either a
    // per-row error summary (exit 1) or the outer catch (exit 1) — never a
    // bad-invocation (exit 2). Assert it got PAST validation into the run.
    check("retention preview missing-table → past validation (not exit 2)", rc !== 2);
    check("retention preview missing-table → exit 0 or 1", rc === 0 || rc === 1);
  } finally { _rm(dataDir); }
}

// ---------------------------------------------------------------------------
// booted: mtls status(exists) / show-cert(success) / issue --days / issue-p12 stdout
// ---------------------------------------------------------------------------
async function sectionBootedMtls() {
  var dataDir = _tmpDir("blamejs-cli2-mtls");
  try {
    var base = ["--data-dir", dataDir, "--vault-mode", "plaintext"];

    var ci = _captureCtx();
    check("mtls init: exit 0", (await cli.main(["mtls", "init"].concat(base), ci)) === 0);

    // status against an EXISTING CA → the `s.exists` true branch (generation + paths)
    var cs = _captureCtx();
    var rcs = await cli.main(["mtls", "status"].concat(base), cs);
    check("mtls status (CA exists): exit 0", rcs === 0);
    check("mtls status (CA exists): reports yes", /CA exists:\s+yes/.test(cs.out()));
    check("mtls status (CA exists): prints paths", /cert:/.test(cs.out()));

    // show-cert against an existing CA → success PEM branch
    var cc = _captureCtx();
    var rcc = await cli.main(["mtls", "show-cert"].concat(base), cc);
    check("mtls show-cert (CA exists): exit 0", rcc === 0);
    check("mtls show-cert (CA exists): prints PEM", /BEGIN CERTIFICATE/.test(cc.out()));

    // issue with --days → the days-truthy branch
    var cd = _captureCtx();
    var rcd = await cli.main(["mtls", "issue"].concat(base).concat(["--subject", "cn-a", "--days", "30"]), cd);
    check("mtls issue --days: exit 0", rcd === 0);
    check("mtls issue --days: prints cert", /BEGIN CERTIFICATE/.test(cd.out()));

    // issue-p12 WITHOUT --out → streams the p12 bytes to stdout
    var cp = _captureCtx();
    var rcp = await cli.main(["mtls", "issue-p12"].concat(base).concat(
      ["--subject", "cn-b", "--password", "p12-passphrase-abc"]), cp);
    check("mtls issue-p12 (stdout): exit 0", rcp === 0);
    check("mtls issue-p12 (stdout): prints fingerprint", /fingerprint \(sha3-512\)/.test(cp.out()));
  } finally { _rm(dataDir); }
}

// ---------------------------------------------------------------------------
// booted: security assert with --require-env / --forbid-env
// ---------------------------------------------------------------------------
async function sectionBootedSecurity() {
  var dataDir = _tmpDir("blamejs-cli2-security");
  try {
    var ctx = _captureCtx();
    var rc = await cli.main(
      ["security", "assert", "--data-dir", dataDir, "--vault-mode", "plaintext",
       "--no-audit-signing", "--no-db-at-rest", "--no-ntp-strict",
       "--require-env", "BLAMEJS_DEFINITELY_UNSET_XYZ",
       "--forbid-env", "BLAMEJS_ANOTHER_UNSET_ABC"], ctx);
    // plaintext vault vs the asserted "wrapped" posture + the unset required
    // env fail the assertion → FAIL summary, exit 1.
    check("security assert require/forbid-env → exit 1", rc === 1);
    check("security assert require/forbid-env → FAIL summary", /FAIL:/.test(ctx.out()));
  } finally { _rm(dataDir); }
}

// ---------------------------------------------------------------------------
// repeatable flags — a duplicated --arg / --watch / --ignore must accumulate
// every occurrence into an array, not collapse to the last one. Regression
// for the dev-command repeatable-flag drop: parseRaw overwrote flags[name] on
// repeat, so only the LAST --watch dir was monitored, the LAST --ignore
// applied, and only the LAST --arg reached the spawned child — every earlier
// occurrence was silently dropped even though DEV_USAGE documents all three
// as "(repeatable)".
// ---------------------------------------------------------------------------
function sectionRepeatableFlags() {
  // Public primitive: b.argParser.parseRaw (the splitter lib/cli.js runs).
  var r = b.argParser.parseRaw(
    ["dev", "--command", "node",
     "--arg", "x", "--arg", "y", "--arg", "z",
     "--watch", "./a", "--watch", "./b",
     "--ignore", "p1", "--ignore", "p2"]);
  check("parseRaw: repeated --arg accumulates in order",
    Array.isArray(r.flags.arg) && r.flags.arg.join(",") === "x,y,z");
  check("parseRaw: repeated --watch accumulates in order",
    Array.isArray(r.flags.watch) && r.flags.watch.join(",") === "./a,./b");
  check("parseRaw: repeated --ignore accumulates in order",
    Array.isArray(r.flags.ignore) && r.flags.ignore.join(",") === "p1,p2");
  // A flag seen once stays a scalar — non-repeatable flags are unaffected.
  check("parseRaw: single --command stays a scalar string", r.flags.command === "node");

  // Consumer path: cli._parseArgs is the exact splitter main() runs before
  // dispatching to _runDev, which reads args.flags.watch / .arg / .ignore and
  // funnels each through _coerceList. An array here is what _runDev needs so
  // it watches BOTH dirs and forwards BOTH args to the child.
  var a = cli._parseArgs(
    ["--command", "node", "--watch", "one", "--watch", "two",
     "--arg", "a1", "--arg", "a2"]);
  check("_parseArgs: --watch reaches _runDev as an ordered array",
    Array.isArray(a.flags.watch) && a.flags.watch.length === 2 &&
    a.flags.watch[0] === "one" && a.flags.watch[1] === "two");
  check("_parseArgs: --arg reaches _runDev as an ordered array",
    Array.isArray(a.flags.arg) && a.flags.arg.length === 2 &&
    a.flags.arg[0] === "a1" && a.flags.arg[1] === "a2");

  // The `--flag=value` form repeats accumulate too — including child flags
  // passed as `--arg=--inspect` (a value that itself starts with "--").
  var eqArg = b.argParser.parseRaw(["--arg=--inspect", "--arg=--port=3000"]);
  check("parseRaw: repeated --arg=VALUE accumulates (dash-valued children)",
    Array.isArray(eqArg.flags.arg) &&
    eqArg.flags.arg.join("|") === "--inspect|--port=3000");

  // Single occurrence of a value flag stays a plain string, not a 1-element
  // array — _coerceList wraps it, so the shape contract downstream is scalar.
  var one = b.argParser.parseRaw(["--watch", "./only"]);
  check("parseRaw: single --watch stays a string", one.flags.watch === "./only");
}

async function run() {
  sectionRepeatableFlags();
  await sectionTopLevel();
  await sectionSeedRun();
  await sectionApiSnapshotBreaking();
  await sectionAudit();
  await sectionFileType();
  await sectionPositionalHelp();
  await sectionArgValidation();
  await sectionBackupRestoreValidation();
  await sectionBootedApiKey();
  await sectionBootedErase();
  await sectionBootedRetention();
  await sectionBootedMtls();
  await sectionBootedSecurity();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
