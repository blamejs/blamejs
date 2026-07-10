// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

// Exercises lib/cli.js branches not driven by the per-command
// cli-*.test.js files or test/00-primitives.js:
//   - the `seed` subcommand (arg validation + a local-sqlite status run)
//   - `dev --grace-ms` numeric validation
//   - `api-snapshot` operator-supplied `--module` (capture + compare
//     failure paths)
//   - top-level `--help` / `-h` routing + unknown help topic fall-through
// Everything drives the public b.cli.main(argv, ctx) surface with a
// captured-output ctx; nothing here needs a live network/db backend
// (the sqlite handle is a local temp file, same shape the existing
// cli-audit-verify-chain / migrate tests use).
// It also drives the seed RUN path (apply / re-skip / --only / --force /
// broken-seeder catch), an api-snapshot compare that detects a breaking
// change, audit archive/export/verify-bundle/purge arg validation plus
// verify-chain FAIL and --max-rows branches, file-type edges, every
// `<cmd> help` positional, cheap arg-validation returns for the remaining
// commands, booted api-key / erase / retention / mtls / security edges,
// and repeatable-flag accumulation (--arg / --watch / --ignore).

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
  var dir = _tmpDir("blamejs-cli-seed");
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
    var dir2 = _tmpDir("blamejs-cli-seed-broken");
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
  var dir = _tmpDir("blamejs-cli-apisnap");
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
  var dir = _tmpDir("blamejs-cli-audit");
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
  var dir = _tmpDir("blamejs-cli-filetype");
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
  var dir = _tmpDir("blamejs-cli-br");
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
  var dataDir = _tmpDir("blamejs-cli-apikey");
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
  var dataDir = _tmpDir("blamejs-cli-erase");
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
  var dataDir = _tmpDir("blamejs-cli-retention");
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
  var dataDir = _tmpDir("blamejs-cli-mtls");
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
  var dataDir = _tmpDir("blamejs-cli-security");
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
  var dir = _tmpDir("blamejs-cli");
  try {
    // =====================================================================
    // seed — arg validation
    // =====================================================================

    // bare `seed` (no subcommand) → usage on stderr, exit 2
    var cBare = _captureCtx();
    var rcBare = await cli.main(["seed"], cBare);
    check("seed: bare → exit 2",                rcBare === 2);
    check("seed: bare → usage on stderr",       /Usage: blamejs seed/.test(cBare.err()));

    // `seed help` → usage on stdout, exit 0
    var cHelp = _captureCtx();
    var rcHelp = await cli.main(["seed", "help"], cHelp);
    check("seed help: exit 0",                  rcHelp === 0);
    check("seed help: usage on stdout",         /Usage: blamejs seed/.test(cHelp.out()));
    check("seed help: lists run + status",      /\brun\b/.test(cHelp.out()) && /\bstatus\b/.test(cHelp.out()));

    // `help seed` (top-level help dispatch → SEED_USAGE)
    var cTopHelpSeed = _captureCtx();
    var rcTopHelpSeed = await cli.main(["help", "seed"], cTopHelpSeed);
    check("help seed: exit 0",                  rcTopHelpSeed === 0);
    check("help seed: prints SEED_USAGE",       /Usage: blamejs seed/.test(cTopHelpSeed.out()));

    // unknown subcommand → exit 2 + usage
    var cUnk = _captureCtx();
    var rcUnk = await cli.main(["seed", "frobnicate"], cUnk);
    check("seed unknown sub: exit 2",           rcUnk === 2);
    check("seed unknown sub: names the sub",    /unknown subcommand 'frobnicate'/.test(cUnk.err()));

    // run without --db → exit 2
    var cNoDb = _captureCtx();
    var rcNoDb = await cli.main(["seed", "run"], cNoDb);
    check("seed run: missing --db → exit 2",    rcNoDb === 2);
    check("seed run: missing --db message",     /--db <path> is required/.test(cNoDb.err()));

    // --db present but bare (boolean flag, no value) → treated as missing
    var cDbBool = _captureCtx();
    var rcDbBool = await cli.main(["seed", "run", "--db"], cDbBool);
    check("seed run: --db with no value → exit 2", rcDbBool === 2);
    check("seed run: --db no value message",       /--db <path> is required/.test(cDbBool.err()));

    // --db present, --env missing → exit 2
    var dbPath = path.join(dir, "seed.db");
    var cNoEnv = _captureCtx();
    var rcNoEnv = await cli.main(["seed", "status", "--db", dbPath], cNoEnv);
    check("seed status: missing --env → exit 2", rcNoEnv === 2);
    check("seed status: missing --env message",  /--env <name> is required/.test(cNoEnv.err()));

    // bad db path (parent dir doesn't exist) → cannot open db, exit 1
    var cBadDb = _captureCtx();
    var rcBadDb = await cli.main(
      ["seed", "status", "--db", path.join(dir, "no-such-dir", "x.db"), "--env", "dev"],
      cBadDb);
    check("seed status: unopenable db → exit 1", rcBadDb === 1);
    check("seed status: cannot-open message",    /cannot open db/.test(cBadDb.err()));

    // =====================================================================
    // seed — status happy path against a local sqlite file + empty dir
    // =====================================================================
    var seedersDir = path.join(dir, "seeders-empty");
    var cStatus = _captureCtx();
    var rcStatus = await cli.main(
      ["seed", "status", "--db", dbPath, "--env", "dev", "--dir", seedersDir],
      cStatus);
    check("seed status: empty dir → exit 0",     rcStatus === 0);
    check("seed status: prints env line",        /env: dev/.test(cStatus.out()));
    check("seed status: 0 applied of 0 total",   /applied: 0 \/ 0/.test(cStatus.out()));
    check("seed status: 0 pending",              /pending: 0/.test(cStatus.out()));

    // =====================================================================
    // dev — --grace-ms numeric validation (returns before spawning a child)
    // =====================================================================
    var cGraceNeg = _captureCtx();
    var rcGraceNeg = await cli.main(
      ["dev", "--command", "node", "--grace-ms", "-5"], cGraceNeg);
    check("dev --grace-ms negative → exit 2",    rcGraceNeg === 2);
    check("dev --grace-ms negative message",     /--grace-ms must be a non-negative number/.test(cGraceNeg.err()));

    var cGraceNaN = _captureCtx();
    var rcGraceNaN = await cli.main(
      ["dev", "--command", "node", "--grace-ms", "not-a-number"], cGraceNaN);
    check("dev --grace-ms non-numeric → exit 2", rcGraceNaN === 2);
    check("dev --grace-ms non-numeric message",  /--grace-ms must be a non-negative number/.test(cGraceNaN.err()));

    // missing --command still exits 2 (guards the `dev` entry independent
    // of the grace-ms path above)
    var cDevNoCmd = _captureCtx();
    var rcDevNoCmd = await cli.main(["dev"], cDevNoCmd);
    check("dev: missing --command → exit 2",     rcDevNoCmd === 2);
    check("dev: missing --command message",      /--command <cmd> is required/.test(cDevNoCmd.err()));

    // =====================================================================
    // dev — --ignore pattern refusal takes the standard exit-2 + stderr
    // path, never rejects main(). An over-length pattern, a ReDoS-shape
    // pattern guardRegex refuses, and a pattern RegExp() can't compile are
    // all operator-input validation failures: they must return exit 2 like
    // every other dev validation, not reject the awaited promise (which the
    // bin shim would surface as a stack-trace + exit 1).
    // =====================================================================
    async function _devIgnore(pattern) {
      var c = _captureCtx();
      var rejected = false;
      var rc;
      try {
        rc = await cli.main(["dev", "--command", "node", "--ignore", pattern], c);
      } catch (_e) {
        rejected = true;
      }
      return { rc: rc, rejected: rejected, err: c.err() };
    }

    var igLong = await _devIgnore("a".repeat(300));
    check("dev --ignore over-length → never rejects main()", igLong.rejected === false);
    check("dev --ignore over-length → exit 2",               igLong.rc === 2);
    check("dev --ignore over-length message",                /exceeds max length/.test(igLong.err));

    var igReDoS = await _devIgnore("(a+)+$");
    check("dev --ignore ReDoS-shape → never rejects main()", igReDoS.rejected === false);
    check("dev --ignore ReDoS-shape → exit 2",               igReDoS.rc === 2);
    check("dev --ignore ReDoS-shape message",                /refused by guardRegex/.test(igReDoS.err));

    var igBadRe = await _devIgnore("(");
    check("dev --ignore uncompilable → never rejects main()", igBadRe.rejected === false);
    check("dev --ignore uncompilable → exit 2",               igBadRe.rc === 2);
    check("dev --ignore uncompilable message",                /--ignore pattern/.test(igBadRe.err));

    // =====================================================================
    // api-snapshot — operator-supplied --module
    // =====================================================================

    // capture from a non-existent module → cannot load, exit 1
    var cModBad = _captureCtx();
    var rcModBad = await cli.main(
      ["api-snapshot", "capture", "--module", path.join(dir, "no-module.js")], cModBad);
    check("api-snapshot capture bad --module → exit 1", rcModBad === 1);
    check("api-snapshot capture bad --module message",
          /cannot load module/.test(cModBad.err()));

    // capture from a valid operator module → wrote snapshot, exit 0
    var customMod = path.join(dir, "custom-mod.js");
    fs.writeFileSync(customMod,
      "module.exports = { version: \"9.9.9\", greet: function greet() {} };");
    var customSnap = path.join(dir, "custom-snap.json");
    var cModOk = _captureCtx();
    var rcModOk = await cli.main(
      ["api-snapshot", "capture", "--file", customSnap, "--module", customMod], cModOk);
    check("api-snapshot capture custom --module → exit 0", rcModOk === 0);
    check("api-snapshot capture custom --module wrote file", fs.existsSync(customSnap));
    check("api-snapshot capture custom --module reports version",
          /frameworkVersion 9\.9\.9/.test(cModOk.out()));

    // compare where the saved snapshot reads fine but capturing the CURRENT
    // surface fails (bad --module) → "cannot capture current surface", exit 1
    var cCmpBad = _captureCtx();
    var rcCmpBad = await cli.main(
      ["api-snapshot", "compare", "--file", customSnap, "--module", path.join(dir, "gone.js")],
      cCmpBad);
    check("api-snapshot compare uncapturable current → exit 1", rcCmpBad === 1);
    check("api-snapshot compare uncapturable current message",
          /cannot capture current surface/.test(cCmpBad.err()));

    // =====================================================================
    // top-level dispatch — help routing edges
    // =====================================================================

    // `<cmd> --help` synthesizes `help <cmd>` → that command's usage
    var cMigHelp = _captureCtx();
    var rcMigHelp = await cli.main(["migrate", "--help"], cMigHelp);
    check("migrate --help → exit 0",             rcMigHelp === 0);
    check("migrate --help prints migrate usage", /Usage: blamejs migrate/.test(cMigHelp.out()));

    // `-h` short flag takes the same route
    var cMigH = _captureCtx();
    var rcMigH = await cli.main(["migrate", "-h"], cMigH);
    check("migrate -h → exit 0",                 rcMigH === 0);
    check("migrate -h prints migrate usage",     /Usage: blamejs migrate/.test(cMigH.out()));

    // `help <unknown-topic>` falls through to the top-level usage
    var cBogus = _captureCtx();
    var rcBogus = await cli.main(["help", "totally-bogus-topic"], cBogus);
    check("help unknown-topic → exit 0",         rcBogus === 0);
    check("help unknown-topic prints top usage", /blamejs <command>/.test(cBogus.out()));
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  }

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
