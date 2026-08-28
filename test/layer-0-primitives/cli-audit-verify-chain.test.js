// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var fs = require("node:fs");
var nodeCrypto = require("node:crypto");
var os = require("node:os");
var path = require("node:path");
var sqlite = require("node:sqlite");
var helpers = require("../helpers");
var check = helpers.check;
var cli = require("../../lib/cli");

function _tmpDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix + "-"));
}

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

function _createAuditTable(dbPath, tableName) {
  var db = new sqlite.DatabaseSync(dbPath);
  // Minimal columns verifyChain reads from `SELECT *` on an empty table.
  // The empty-rows path returns ok=true without inspecting the columns,
  // so this is enough for the CLI surface tests.
  db.prepare("CREATE TABLE " + tableName + " (" +
    " _id INTEGER PRIMARY KEY," +
    " monotonicCounter INTEGER," +
    " prevHash TEXT," +
    " rowHash  TEXT," +
    " nonce    BLOB" +
    ")").run();
  db.close();
}

async function run() {
  // ---- empty audit_log: chain trivially verifies ----
  var dir = _tmpDir("blamejs-cli-verify-chain");
  var dbPath = path.join(dir, "blamejs.db");
  _createAuditTable(dbPath, "audit_log");

  var ctx1 = _captureCtx();
  var c1 = await cli.main(
    ["audit", "verify-chain", "--db", dbPath], ctx1);
  check("verify-chain: exits 0 on empty audit_log", c1 === 0);
  check("verify-chain: announces rowsVerified=0",
        /rowsVerified=0/.test(ctx1.out()));
  check("verify-chain: announces table=audit_log",
        /table=audit_log/.test(ctx1.out()));

  // ---- arg validation ----
  var ctx2 = _captureCtx();
  var c2 = await cli.main(["audit", "verify-chain"], ctx2);
  check("verify-chain: missing --db returns 2",
        c2 === 2 && /--db/.test(ctx2.err()));

  var ctx3 = _captureCtx();
  var c3 = await cli.main(
    ["audit", "verify-chain", "--db", dbPath, "--max-rows", "0"], ctx3);
  check("verify-chain: --max-rows=0 returns 2",
        c3 === 2 && /max-rows/.test(ctx3.err()));

  var ctx4 = _captureCtx();
  var c4 = await cli.main(
    ["audit", "verify-chain", "--db", dbPath, "--max-rows", "abc"], ctx4);
  check("verify-chain: --max-rows non-numeric returns 2",
        c4 === 2 && /max-rows/.test(ctx4.err()));

  // ---- bad db path ----
  var ctx5 = _captureCtx();
  var c5 = await cli.main(
    ["audit", "verify-chain", "--db",
     path.join(dir, "no-such-dir", "missing.db")], ctx5);
  check("verify-chain: bad db path returns 1",
        c5 === 1 && /cannot open db/.test(ctx5.err()));

  // ---- custom --table ----
  var dbPath2 = path.join(dir, "alt.db");
  _createAuditTable(dbPath2, "audit_consent");
  var ctx6 = _captureCtx();
  var c6 = await cli.main(
    ["audit", "verify-chain", "--db", dbPath2, "--table", "audit_consent"], ctx6);
  check("verify-chain: --table picks alternate audit table",
        c6 === 0 && /table=audit_consent/.test(ctx6.out()));

  // ---- --public-key pointing at an empty file ----
  // Reading it succeeds and yields "", which fingerprintOf refuses. That is a
  // wrong path on the command line — a bad invocation, which has an exit
  // code — and it reached the caller as an uncaught throw.
  var emptyPem = path.join(dir, "empty-key.pem");
  fs.writeFileSync(emptyPem, "");
  var ctx7 = _captureCtx();
  var c7 = await cli.main(
    ["audit", "verify-chain", "--db", dbPath2, "--table", "audit_consent",
     "--public-key", emptyPem], ctx7);
  check("verify-chain: an empty --public-key exits 2 rather than throwing",
        c7 === 2, "exit=" + c7 + " err=" + ctx7.err());
  check("verify-chain: and says which file was wrong",
        ctx7.err().indexOf(emptyPem) !== -1 && /not a PEM public key/.test(ctx7.err()),
        ctx7.err());

  // Non-empty content that is not a key is the likelier mistake, and the more
  // dangerous one: a fingerprint is a hash of the bytes, so any text produces
  // one, it matches no anchor, and the chain gets reported as signed under an
  // unknown key. That is a tampering alarm on a healthy volume, raised by a
  // wrong path on the command line.
  var jsonKey = path.join(dir, "audit-sign.pubkeys.json");
  fs.writeFileSync(jsonKey, JSON.stringify([{ fingerprint: "ab", publicKey: "..." }]));
  var ctx9 = _captureCtx();
  var c9 = await cli.main(
    ["audit", "verify-chain", "--db", dbPath2, "--table", "audit_consent",
     "--public-key", jsonKey], ctx9);
  check("verify-chain: a --public-key that is not a key exits 2, not a tamper report",
        c9 === 2 && /not a PEM public key/.test(ctx9.err()),
        "exit=" + c9 + " err=" + ctx9.err());

  // The same key, saved with CRLF line endings, is the same key. A fingerprint
  // is a hash of the PEM text, so hashing the file's bytes makes those two
  // spellings different keys — and the anchor, signed under one of them, gets
  // reported as signed under a key this volume does not know. Re-exporting
  // through the parsed key gives one spelling for one key.
  var genPair = nodeCrypto.generateKeyPairSync("ed25519");
  var lfPem   = genPair.publicKey.export({ type: "spki", format: "pem" }).toString();
  var crlfPem = lfPem.replace(/\n/g, "\r\n");
  var lfPath   = path.join(dir, "key-lf.pem");
  var crlfPath = path.join(dir, "key-crlf.pem");
  fs.writeFileSync(lfPath, lfPem);
  fs.writeFileSync(crlfPath, crlfPem);
  check("verify-chain: the two spellings differ on disk",
        fs.readFileSync(lfPath, "utf8") !== fs.readFileSync(crlfPath, "utf8"));

  var ctxA = _captureCtx();
  var cA = await cli.main(
    ["audit", "verify-chain", "--db", dbPath2, "--table", "audit_consent",
     "--public-key", crlfPath], ctxA);
  check("verify-chain: a CRLF-saved key is accepted like its LF twin",
        cA === 0, "exit=" + cA + " err=" + ctxA.err());

  var ctx8 = _captureCtx();
  var c8 = await cli.main(
    ["audit", "verify-chain", "--db", dbPath2, "--table", "audit_consent",
     "--public-key", path.join(dir, "no-such-key.pem")], ctx8);
  check("verify-chain: an unreadable --public-key exits 2",
        c8 === 2 && /cannot read --public-key/.test(ctx8.err()),
        "exit=" + c8 + " err=" + ctx8.err());

  // ---- --archive-dir reports what it found, and refuses what it didn't ----
  // A chain with no purge anchor says nothing about archives either way; these
  // assert the flag is accepted and does not invent a claim.
  var bundleDir = path.join(dir, "bundles");
  fs.mkdirSync(bundleDir, { recursive: true });
  var ctxB = _captureCtx();
  var cB = await cli.main(
    ["audit", "verify-chain", "--db", dbPath2, "--table", "audit_consent",
     "--archive-dir", bundleDir], ctxB);
  check("verify-chain: --archive-dir is accepted on a chain with no anchor",
        cB === 0, "exit=" + cB + " err=" + ctxB.err());
  check("verify-chain: and claims nothing about an archive when there is no anchor",
        ctxB.out().indexOf("archive") === -1, ctxB.out());

  // A flag written without its value parses as `true`. Ignoring it silently is
  // the worst reading: the operator asked for the anchor to be checked, the
  // command does not check it, and reports success — the flag exists to turn
  // an unverified result into a verified one.
  var valueless = [["--public-key"], ["--archive-dir"]];
  for (var vi = 0; vi < valueless.length; vi += 1) {
    var ctxV = _captureCtx();
    var cV = await cli.main(
      ["audit", "verify-chain", "--db", dbPath2, "--table", "audit_consent",
       valueless[vi][0]], ctxV);
    check("verify-chain: " + valueless[vi][0] + " without a value exits 2",
      cV === 2 && /requires a path/.test(ctxV.err()),
      "exit=" + cV + " err=" + ctxV.err());
  }

  // ---- cleanup ----
  fs.rmSync(dir, { recursive: true, force: true });
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
