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
// The manifest is written canonically, so a tamper fixture has to rewrite it
// the same way — otherwise the test would be measuring the formatting change
// rather than the value it altered.
var canonicalJson = require("../../lib/canonical-json");
var b = require("../../index.js");

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

// The flag's whole job is to turn "the anchor names an archive" into "and the
// archive is there", so every check above it — a directory with no bundles, a
// chain with no anchor — leaves the answering half untested. This drives the
// real path: rows recorded, archived, purged, then read back through the
// command an operator runs, against a real bundle on disk.
async function runArchiveResolution() {
  var dir = _tmpDir("blamejs-cli-archive-dir");
  var PASS = "cli-archive-dir-passphrase-not-secret";
  process.env.BLAMEJS_SKIP_NTP_CHECK           = "1";
  process.env.BLAMEJS_VAULT_PASSPHRASE         = PASS;
  process.env.BLAMEJS_AUDIT_SIGNING_PASSPHRASE = PASS;
  b.cluster._resetForTest();
  b.audit._resetForTest();
  b.vault._resetForTest();
  b.db._resetForTest();
  // Plain at-rest because the command opens a SQLite FILE: under the encrypted
  // default the durable artifact is db.enc, which it cannot read, and the test
  // would be checking a different volume than the one the purge wrote to.
  await b.vault.init({ dataDir: dir, mode: "plaintext" });
  await b.db.init({
    dataDir: dir, atRest: "plain", allowNonTmpfsTmpDir: true,
    schema: [{ name: "notes", columns: { _id: "TEXT PRIMARY KEY", body: "TEXT" } }],
  });

  b.audit.registerNamespace("cli");
  for (var si = 0; si < 4; si += 1) {
    await b.audit.record({ action: "cli.archive_dir.seed", outcome: "success" });
  }
  await b.audit.flush();
  await b.audit.checkpoint();

  var bundles = path.join(dir, "bundles");
  fs.mkdirSync(bundles, { recursive: true });
  var bundleOut = path.join(bundles, "slice-1");
  await b.auditTools.archive({ out: bundleOut, passphrase: PASS, before: Date.now() + 1000 });
  await b.auditTools.purge({ confirm: true, archive: bundleOut, passphrase: PASS });

  var pubPath = path.join(dir, "audit-sign.pub.pem");
  fs.writeFileSync(pubPath, b.auditSign.getPublicKey());
  await b.db.close();

  var dbFile = path.join(dir, "blamejs.db");
  var baseArgs = ["audit", "verify-chain", "--db", dbFile,
                  "--public-key", pubPath, "--archive-dir", bundles];

  // Every path flag resolves against the CLI context's working directory, not
  // the process's. --db already did; --archive-dir and --public-key read the
  // flag verbatim, so a caller running the CLI with its own cwd got "archive
  // missing" for an archive that was there — the one answer this command must
  // not give wrongly.
  var ctxRel = _captureCtx();
  ctxRel.cwd = dir;
  var cRel = await cli.main(["audit", "verify-chain", "--db", path.relative(dir, dbFile),
    "--public-key", path.relative(dir, pubPath),
    "--archive-dir", path.relative(dir, bundles)], ctxRel);
  check("verify-chain: relative flags resolve against the context's cwd",
        cRel === 0 && /archive .* found/.test(ctxRel.out()),
        "exit=" + cRel + " out=" + ctxRel.out() + " err=" + ctxRel.err());

  var ctxOk = _captureCtx();
  var cOk = await cli.main(baseArgs, ctxOk);
  check("verify-chain: a real bundle under --archive-dir resolves the anchor",
        cOk === 0 && /archive .* found/.test(ctxOk.out()),
        "exit=" + cOk + " out=" + ctxOk.out() + " err=" + ctxOk.err());

  // A bundle directory is named by whoever ran `audit archive`; the anchor
  // records the covering checkpoint's id. Reporting found means the manifests
  // were read, not that a directory name happened to match.
  check("verify-chain: and did so without the directory name matching the id",
        ctxOk.out().indexOf("slice-1") === -1, ctxOk.out());

  // An archive is refused without its covering checkpoint, so a bundle whose
  // checkpoint.enc is gone cannot be verified or restored. Reporting it found
  // is the false guarantee the flag exists to remove.
  var ckptPath = path.join(bundleOut, "checkpoint.enc");
  var ckptBytes = fs.readFileSync(ckptPath);
  check("verify-chain: the bundle carries a checkpoint payload to remove",
        ckptBytes.length > 0);
  fs.writeFileSync(ckptPath, Buffer.alloc(0));

  var ctxNoCkpt = _captureCtx();
  var cNoCkpt = await cli.main(baseArgs, ctxNoCkpt);
  check("verify-chain: an emptied checkpoint.enc is not a resolvable archive",
        cNoCkpt === 1 && /could not be produced/.test(ctxNoCkpt.err()),
        "exit=" + cNoCkpt + " out=" + ctxNoCkpt.out() + " err=" + ctxNoCkpt.err());

  fs.writeFileSync(ckptPath, ckptBytes);
  // The same removal on the row payload, so the check is not passing on the
  // checkpoint alone: both members the reader demands are required.
  var rowsPath = path.join(bundleOut, "rows.enc");
  var rowsBytes = fs.readFileSync(rowsPath);
  fs.writeFileSync(rowsPath, Buffer.alloc(0));
  var ctxNoRows = _captureCtx();
  var cNoRows = await cli.main(baseArgs, ctxNoRows);
  check("verify-chain: an emptied rows.enc is not a resolvable archive either",
        cNoRows === 1 && /could not be produced/.test(ctxNoRows.err()),
        "exit=" + cNoRows + " err=" + ctxNoRows.err());

  fs.writeFileSync(rowsPath, rowsBytes);
  var ctxBack = _captureCtx();
  check("verify-chain: and resolves again once both are back",
        (await cli.main(baseArgs, ctxBack)) === 0, ctxBack.err());

  // Neither payload touched, and both signed digests still match — only the
  // salt the decryption key is derived from is changed. Every byte the resolver
  // compared before still compared equal, so the archive reported as producible
  // while the key derived from that salt opened nothing: an anchor licensing
  // rows away on the strength of an archive that cannot be read. The manifest
  // is bound into the signature now, so the edit is caught.
  var saltManifestPath = path.join(bundleOut, "manifest.json");
  var saltManifestBytes = fs.readFileSync(saltManifestPath);
  var tampered = JSON.parse(saltManifestBytes.toString("utf8"));
  check("verify-chain: [setup] the manifest carries a rows salt to alter",
        tampered.salts && typeof tampered.salts.rows === "string",
        JSON.stringify(tampered.salts));
  // A different salt of the same shape — the manifest stays well-formed, and
  // every checksum it states about the payloads stays true.
  tampered.salts.rows = tampered.salts.rows.slice(0, -2) +
    (tampered.salts.rows.slice(-2) === "00" ? "11" : "00");
  fs.writeFileSync(saltManifestPath, Buffer.from(canonicalJson.stringify(tampered), "utf8"));
  var ctxSalt = _captureCtx();
  var cSalt = await cli.main(baseArgs, ctxSalt);
  check("verify-chain: an altered manifest salt is not a resolvable archive",
        cSalt === 1 && /could not be produced/.test(ctxSalt.err()),
        "exit=" + cSalt + " err=" + ctxSalt.err());

  fs.writeFileSync(saltManifestPath, saltManifestBytes);
  var ctxSaltBack = _captureCtx();
  check("verify-chain: and resolves again once the manifest is restored",
        (await cli.main(baseArgs, ctxSaltBack)) === 0, ctxSaltBack.err());

  // A fingerprint is the hash of the PEM TEXT, so one key can answer to two of
  // them. A key an operator supplied to rotateSigningKey before that call
  // canonicalized what it ingested was fingerprinted exactly as written, CRLF
  // and all, and the anchors signed under it carry that hash. Hashing only a
  // re-export here would report those healthy volumes as signed by a key this
  // deployment does not know — a tampering alarm raised by a line ending.
  var crlfKeyPath = path.join(dir, "audit-sign.pub.crlf.pem");
  fs.writeFileSync(crlfKeyPath, fs.readFileSync(pubPath, "utf8").replace(/\n/g, "\r\n"));
  check("verify-chain: the CRLF spelling really is different text",
        fs.readFileSync(crlfKeyPath, "utf8") !== fs.readFileSync(pubPath, "utf8"));
  var ctxCrlf = _captureCtx();
  var cCrlf = await cli.main(
    ["audit", "verify-chain", "--db", dbFile,
     "--public-key", crlfKeyPath, "--archive-dir", bundles], ctxCrlf);
  check("verify-chain: a key saved with CRLF still verifies the anchor",
        cCrlf === 0 && /signature-verified/.test(ctxCrlf.out()),
        "exit=" + cCrlf + " out=" + ctxCrlf.out() + " err=" + ctxCrlf.err());

  // The case above passes on the re-export alone, so it does not cover the
  // volume that matters: one whose anchor records a fingerprint taken over
  // NONCANONICAL text. Rotation now canonicalizes what it ingests, so that
  // state can no longer be created through the API — it is what an earlier
  // version left behind, and the fixture writes it directly. The signature
  // does not cover the fingerprint field, so re-labelling the anchor leaves a
  // genuinely valid signature under a differently-spelled name for its key.
  var rawFp = b.auditSign.fingerprintOf(fs.readFileSync(crlfKeyPath, "utf8"));
  var relabel = new sqlite.DatabaseSync(dbFile);
  var priorFp = relabel.prepare(
    "SELECT publicKeyFingerprint AS fp FROM _blamejs_audit_purge_anchor WHERE scope = 'audit'").get().fp;
  relabel.prepare("UPDATE _blamejs_audit_purge_anchor SET publicKeyFingerprint = ? WHERE scope = 'audit'")
    .run(rawFp);
  relabel.close();
  check("verify-chain: the legacy label differs from the canonical one",
        rawFp !== priorFp);
  var ctxLegacy = _captureCtx();
  var cLegacy = await cli.main(
    ["audit", "verify-chain", "--db", dbFile,
     "--public-key", crlfKeyPath, "--archive-dir", bundles], ctxLegacy);
  check("verify-chain: an anchor labelled with the as-written fingerprint verifies",
        cLegacy === 0 && /signature-verified/.test(ctxLegacy.out()),
        "exit=" + cLegacy + " out=" + ctxLegacy.out() + " err=" + ctxLegacy.err());
  var restoreFp = new sqlite.DatabaseSync(dbFile);
  restoreFp.prepare("UPDATE _blamejs_audit_purge_anchor SET publicKeyFingerprint = ? WHERE scope = 'audit'")
    .run(priorFp);
  restoreFp.close();

  // The checksum in a manifest travels with the bytes it describes, so an
  // attacker who replaces rows.enc replaces that checksum too and the two
  // still agree. Comparing them proves the bundle is consistent with itself,
  // which is not the question. The anchor carries the digest under its
  // signature, so what the archive must CONTAIN is a claim only the signing
  // key could make — and a consistent replacement no longer passes.
  var bundleManifestPath = path.join(bundleOut, "manifest.json");
  var bundleManifestBytes = fs.readFileSync(bundleManifestPath);
  var forgedRows = Buffer.concat([rowsBytes, Buffer.from("tampered")]);
  var forgedManifest = JSON.parse(bundleManifestBytes.toString("utf8"));
  var anchorDigestRow = new sqlite.DatabaseSync(dbFile);
  var signedDigest = anchorDigestRow.prepare(
    "SELECT archiveRowsDigest AS d FROM _blamejs_audit_purge_anchor WHERE scope = 'audit'").get().d;
  anchorDigestRow.close();
  check("verify-chain: the anchor records the archive's digest under its signature",
        typeof signedDigest === "string" && signedDigest.length > 0 &&
        signedDigest === forgedManifest.checksum.rowsSha3_512,
        String(signedDigest).slice(0, 32));

  forgedManifest.checksum.rowsSha3_512 =
    nodeCrypto.createHash("sha3-512").update(forgedRows).digest("hex");
  fs.writeFileSync(rowsPath, forgedRows);
  fs.writeFileSync(bundleManifestPath, JSON.stringify(forgedManifest));
  check("verify-chain: the forged bundle is internally consistent",
        nodeCrypto.createHash("sha3-512").update(fs.readFileSync(rowsPath)).digest("hex") ===
        JSON.parse(fs.readFileSync(bundleManifestPath, "utf8")).checksum.rowsSha3_512);
  var ctxForged = _captureCtx();
  var cForged = await cli.main(baseArgs, ctxForged);
  check("verify-chain: but it is not the archive the anchor signed for",
        cForged === 1 && /could not be produced/.test(ctxForged.err()),
        "exit=" + cForged + " out=" + ctxForged.out() + " err=" + ctxForged.err());
  fs.writeFileSync(rowsPath, rowsBytes);
  fs.writeFileSync(bundleManifestPath, bundleManifestBytes);

  // The same swap on the OTHER member. An archive is refused without its
  // covering checkpoint, so a bundle whose checkpoint payload has been
  // replaced cannot be verified or restored however well its rows still
  // match — and binding only the rows leaves that member checked against the
  // manifest, which the same hand rewrites. The result is the worst kind of
  // answer: "the archive is still there" for one that cannot be opened.
  var forgedCkpt = Buffer.concat([ckptBytes, Buffer.from("tampered")]);
  var ckptManifest = JSON.parse(bundleManifestBytes.toString("utf8"));
  var anchorCkptRow = new sqlite.DatabaseSync(dbFile);
  var signedCkptDigest = anchorCkptRow.prepare(
    "SELECT archiveCheckpointDigest AS d FROM _blamejs_audit_purge_anchor WHERE scope = 'audit'").get().d;
  anchorCkptRow.close();
  check("verify-chain: the anchor records the checkpoint's digest under its signature",
        typeof signedCkptDigest === "string" && signedCkptDigest.length > 0 &&
        signedCkptDigest === ckptManifest.checksum.checkpointSha3_512,
        String(signedCkptDigest).slice(0, 32));

  ckptManifest.checksum.checkpointSha3_512 =
    nodeCrypto.createHash("sha3-512").update(forgedCkpt).digest("hex");
  fs.writeFileSync(ckptPath, forgedCkpt);
  fs.writeFileSync(bundleManifestPath, JSON.stringify(ckptManifest));
  check("verify-chain: the checkpoint swap is internally consistent too",
        nodeCrypto.createHash("sha3-512").update(fs.readFileSync(ckptPath)).digest("hex") ===
        JSON.parse(fs.readFileSync(bundleManifestPath, "utf8")).checksum.checkpointSha3_512);
  var ctxCkpt = _captureCtx();
  var cCkpt = await cli.main(baseArgs, ctxCkpt);
  check("verify-chain: a replaced checkpoint is not the archive the anchor signed for",
        cCkpt === 1 && /could not be produced/.test(ctxCkpt.err()),
        "exit=" + cCkpt + " out=" + ctxCkpt.out() + " err=" + ctxCkpt.err());
  fs.writeFileSync(ckptPath, ckptBytes);
  fs.writeFileSync(bundleManifestPath, bundleManifestBytes);

  // Deleting the expectation is the cheapest way to defeat a comparison
  // against it. Every bundle the archiver writes records a checksum for each
  // member it includes, so a manifest without one did not come from here.
  var manifestPath = path.join(bundleOut, "manifest.json");
  var manifestBytes = fs.readFileSync(manifestPath);
  var stripped = JSON.parse(manifestBytes.toString("utf8"));
  delete stripped.checksum.rowsSha3_512;
  fs.writeFileSync(manifestPath, JSON.stringify(stripped));
  var ctxNoSum = _captureCtx();
  var cNoSum = await cli.main(baseArgs, ctxNoSum);
  check("verify-chain: a manifest with its checksum removed is not found",
        cNoSum === 1 && /could not be produced/.test(ctxNoSum.err()),
        "exit=" + cNoSum + " out=" + ctxNoSum.out() + " err=" + ctxNoSum.err());
  fs.writeFileSync(manifestPath, manifestBytes);

  // A directory reports a non-zero size on most filesystems, so a check on
  // size alone accepts one standing where the payload should be — a bundle
  // the reader cannot open, reported as producible.
  fs.rmSync(rowsPath);
  fs.mkdirSync(rowsPath);
  var ctxDir = _captureCtx();
  var cDir = await cli.main(baseArgs, ctxDir);
  check("verify-chain: a directory in place of rows.enc is not a payload",
        cDir === 1 && /could not be produced/.test(ctxDir.err()),
        "exit=" + cDir + " err=" + ctxDir.err());
  fs.rmSync(rowsPath, { recursive: true });
  fs.writeFileSync(rowsPath, rowsBytes);

  // Present and the right length is not the same as intact. A payload altered
  // in place decrypts to nothing, so the rows it accounts for cannot be
  // produced — the manifest records what the bytes should hash to, and that is
  // checkable here without the passphrase.
  var corrupted = Buffer.from(rowsBytes);
  corrupted[corrupted.length - 1] = corrupted[corrupted.length - 1] ^ 0xff;
  fs.writeFileSync(rowsPath, corrupted);
  check("verify-chain: the corrupted payload is the same size as the original",
        fs.statSync(rowsPath).size === rowsBytes.length);
  var ctxCorrupt = _captureCtx();
  var cCorrupt = await cli.main(baseArgs, ctxCorrupt);
  check("verify-chain: a payload that does not match the manifest is not found",
        cCorrupt === 1 && /could not be produced/.test(ctxCorrupt.err()),
        "exit=" + cCorrupt + " out=" + ctxCorrupt.out() + " err=" + ctxCorrupt.err());
  fs.writeFileSync(rowsPath, rowsBytes);

  // An archive is identified by the checkpoint that covers it, and one
  // checkpoint can cover several slices: archiving a subset older than the
  // last checkpoint is a supported shape, so two bundles carry one identifier.
  // Resolving on that alone reports the anchored slice as present because a
  // DIFFERENT one still is — and that one holds none of the rows the anchor
  // licensed away.
  await b.db.init({
    dataDir: dir, atRest: "plain", allowNonTmpfsTmpDir: true,
    schema: [{ name: "notes", columns: { _id: "TEXT PRIMARY KEY", body: "TEXT" } }],
  });
  for (var s2 = 0; s2 < 4; s2 += 1) {
    await b.audit.record({ action: "cli.archive_dir.seed", outcome: "success" });
  }
  await b.audit.flush();
  // `before` selects by recorded time, so the two slices need distinct
  // milliseconds to be separable at all.
  var cut = Date.now() + 1;
  await helpers.passiveObserve(25, "cli --archive-dir: separating two slices in time");
  for (var s3 = 0; s3 < 4; s3 += 1) {
    await b.audit.record({ action: "cli.archive_dir.seed", outcome: "success" });
  }
  await b.audit.flush();
  // One checkpoint over both batches — what makes the two bundles share an id.
  await b.audit.checkpoint();

  var olderOut = path.join(bundles, "slice-older");
  await b.auditTools.archive({ out: olderOut, passphrase: PASS, before: cut });
  await b.auditTools.purge({ confirm: true, archive: olderOut, passphrase: PASS });
  var newerOut = path.join(bundles, "slice-newer");
  await b.auditTools.archive({ out: newerOut, passphrase: PASS, before: Date.now() + 1000 });
  await b.auditTools.purge({ confirm: true, archive: newerOut, passphrase: PASS });
  await b.db.close();

  var olderManifest = JSON.parse(fs.readFileSync(path.join(olderOut, "manifest.json"), "utf8"));
  var newerManifest = JSON.parse(fs.readFileSync(path.join(newerOut, "manifest.json"), "utf8"));
  // The fixture's own control: without a shared identifier the removal below
  // would be unfindable anyway and the check would pass for the wrong reason.
  check("verify-chain: the two slices share one covering checkpoint id",
        String(olderManifest.checkpoint.checkpointId) ===
        String(newerManifest.checkpoint.checkpointId),
        olderManifest.checkpoint.checkpointId + " vs " + newerManifest.checkpoint.checkpointId);
  check("verify-chain: and cover different ranges under it",
        Number(olderManifest.range.lastCounter) !== Number(newerManifest.range.lastCounter),
        olderManifest.range.lastCounter + " vs " + newerManifest.range.lastCounter);

  var ctxTwo = _captureCtx();
  check("verify-chain: both bundles present resolves the anchored one",
        (await cli.main(baseArgs, ctxTwo)) === 0, ctxTwo.err());

  // Remove the slice the anchor names; its sibling stays, under the same id.
  fs.rmSync(newerOut, { recursive: true, force: true });
  var ctxSibling = _captureCtx();
  var cSibling = await cli.main(baseArgs, ctxSibling);
  check("verify-chain: a sibling under the same id is not the anchored archive",
        cSibling === 1 && /could not be produced/.test(ctxSibling.err()),
        "exit=" + cSibling + " out=" + ctxSibling.out() + " err=" + ctxSibling.err());

  b.audit._resetForTest();
  b.vault._resetForTest();
  b.db._resetForTest();
  fs.rmSync(dir, { recursive: true, force: true });
}

module.exports = { run: async function () { await run(); await runArchiveResolution(); } };

if (require.main === module) {
  module.exports.run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
