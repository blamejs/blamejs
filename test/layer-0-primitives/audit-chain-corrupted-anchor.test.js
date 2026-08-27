// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.auditChain.verifyChain — a corrupted / tampered purge anchor must fail
 * CLOSED with a clear { ok:false, reason }, not throw. The anchor's
 * lastPurgedRowHash seeds prevHash; a non-128-hex value used to flow into
 * computeRowHash, which throws "prevHash must be a 128-char hex" — turning a
 * defensive verify into an uncaught exception. A non-numeric lastPurgedCounter
 * (NaN) would skip nothing and surface as an opaque chain-break.
 *
 * Driven through a mock queryAllAsync (no DB) — the fix returns before the
 * chain-rows query, so the rows mock is irrelevant.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function _mockQuery(anchorRow, opts) {
  var refuseSignatureColumns = opts && opts.refuseSignatureColumns;
  var chainRows = (opts && opts.chainRows) || null;
  return function (sql /*, params */) {
    if (typeof sql === "string" && sql.indexOf("purge_anchor") !== -1) {
      // A volume purged before the anchor was signed has no signature columns,
      // and a verifier reading the file directly never runs the migration that
      // would add them. The database answers a SELECT naming them with an
      // error, exactly as SQLite and Postgres do.
      if (refuseSignatureColumns && /signature/i.test(sql)) {
        return Promise.reject(new Error('no such column: "signature"'));
      }
      return Promise.resolve(anchorRow ? [anchorRow] : []);
    }
    // Chain-rows query — a single plausible row (never reached on a corrupt
    // anchor, but present so the non-corrupt branch could walk).
    return Promise.resolve(chainRows || []);
  };
}

async function _verify(anchorRow) {
  return _verifyWith(anchorRow, undefined);
}

// Same, with a caller-supplied public-key resolver — the shape a verifier that
// never initialized signing (the CLI, a downstream auditor) has to use.
async function _verifyWith(anchorRow, resolvePublicKey, extraOpts, mockOpts) {
  var threw = null, result = null;
  var opts = resolvePublicKey ? { resolvePublicKey: resolvePublicKey } : {};
  if (extraOpts) {
    Object.keys(extraOpts).forEach(function (k) { opts[k] = extraOpts[k]; });
  }
  try {
    result = await b.auditChain.verifyChain(
      _mockQuery(anchorRow, mockOpts), "audit_log", opts);
  }
  catch (e) { threw = e; }
  return { threw: threw, result: result };
}

// The anchor says which rows are allowed to be missing. Unsigned, it was the
// one record an attacker could write freely, and the whole attack was three
// statements: delete the rows, delete the checkpoints covering them, insert an
// anchor naming any hash and counter. Verification adopted that hash as the
// chain origin, discarded everything at or below the counter, and reported the
// volume intact — a cheaper attack than the relink-and-forge one the chain
// already refuses.
async function testAnchorMustProveItWasWrittenWithTheSigningKey() {
  var os   = helpers.os;
  var path = helpers.path;
  var fs   = helpers.fs;
  var dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "anchor-sig-"));

  try {
    // plaintext mode — this exercises the signature contract, not key sealing,
    // which audit-sign.test.js already covers.
    await b.auditSign.init({ dataDir: dataDir, mode: "plaintext", algorithm: "ml-dsa-65" });

    var chosenHash = "a".repeat(128);
    var forged = {
      lastPurgedCounter: 10,
      lastPurgedRowHash: chosenHash,
      archiveBundleId:   "archive-under-test",
      purgedAt:          1750000000000,
    };

    // The measured attack, exactly: shape-valid, unsigned.
    var unsigned = await _verify(forged);
    check("unsigned purge anchor does not throw", unsigned.threw === null);
    check("unsigned purge anchor is refused, not adopted",
      unsigned.result && unsigned.result.ok === false,
      JSON.stringify(unsigned.result));
    check("and the refusal says the anchor carried no signature",
      unsigned.result && /no signature/i.test(unsigned.result.reason || ""),
      String(unsigned.result && unsigned.result.reason));

    // Properly signed → honored.
    var signedAnchor = {
      lastPurgedCounter: forged.lastPurgedCounter,
      lastPurgedRowHash: forged.lastPurgedRowHash,
      archiveBundleId:   forged.archiveBundleId,
      purgedAt:          forged.purgedAt,
    };
    signedAnchor.signature = b.auditSign.sign(
      b.auditChain.purgeAnchorPayload(signedAnchor));
    signedAnchor.publicKeyFingerprint = b.auditSign.getPublicKeyFingerprint();

    var honored = await _verify(signedAnchor);
    check("a signed purge anchor is honored", honored.threw === null &&
      honored.result && honored.result.ok === true, JSON.stringify(honored.result));

    // Point 3 of the report: never state a verification that was not
    // performed. The archive identifier is recorded, never resolved — nothing
    // in the framework knows where a consumer's bundles live — so a caller
    // must be able to tell "a counter was believed" from "an archive was
    // verified".
    check("the honored anchor reports that the archive was NOT resolved",
      honored.result && honored.result.purgeAnchor &&
      honored.result.purgeAnchor.honored === true &&
      honored.result.purgeAnchor.archiveResolved === false,
      JSON.stringify(honored.result && honored.result.purgeAnchor));

    // Every field the anchor licenses is covered: move the counter under a
    // good signature and it stops verifying.
    var movedCounter = Object.assign({}, signedAnchor, { lastPurgedCounter: 9999 });
    var moved = await _verify(movedCounter);
    check("editing the counter under a valid signature is refused",
      moved.result && moved.result.ok === false, JSON.stringify(moved.result));

    // Same for the hash it adopts as the chain origin.
    var movedHash = Object.assign({}, signedAnchor, { lastPurgedRowHash: "b".repeat(128) });
    var moved2 = await _verify(movedHash);
    check("editing the adopted origin hash is refused",
      moved2.result && moved2.result.ok === false, JSON.stringify(moved2.result));

    // And the archive it names, so an anchor cannot be repointed at a bundle
    // the operator never produced.
    var movedArchive = Object.assign({}, signedAnchor, { archiveBundleId: "somewhere-else" });
    var moved3 = await _verify(movedArchive);
    check("editing the named archive is refused",
      moved3.result && moved3.result.ok === false, JSON.stringify(moved3.result));

    // A signature under a key this volume has no record of is not a signature.
    var wrongFp = Object.assign({}, signedAnchor, { publicKeyFingerprint: "0".repeat(64) });
    var wrong = await _verify(wrongFp);
    check("a fingerprint naming no key on record is refused",
      wrong.result && wrong.result.ok === false, JSON.stringify(wrong.result));

    // A verifier with no signing state of its own supplies the key. Without
    // this, `blamejs audit verify-chain` — which opens a database file directly
    // and never initializes signing — resolved nothing and reported every VALID
    // anchor as unresolvable, which is a false alarm on a healthy volume.
    var pubPem = b.auditSign.getPublicKey();
    var supplied = await _verifyWith(signedAnchor, function () { return pubPem; });
    check("a caller-supplied public key resolves the anchor",
      supplied.result && supplied.result.ok === true, JSON.stringify(supplied.result));

    // And a verifier that can reach no key at all says the anchor was not
    // CHECKED, rather than that it failed — a purged volume is not a tampered
    // one, and an operator has to be able to tell those apart.
    var noKey = await _verifyWith(signedAnchor, function () {
      var e = new Error("audit-sign/not-initialized"); throw e;
    });
    check("a verifier with no key reports the anchor as unchecked",
      noKey.result && noKey.result.ok === false &&
      /could not be checked/.test(noKey.result.reason || ""),
      String(noKey.result && noKey.result.reason));
    // Flagged distinctly, because "we could not check" and "this is forged"
    // both refuse and only one is an incident. Without the flag a caller — the
    // CLI included — reports a healthy purged volume as tampering.
    check("and it is flagged unchecked rather than as a forgery",
      noKey.result && noKey.result.purgeAnchorUnchecked === true,
      JSON.stringify(noKey.result));
    check("while a genuinely bad signature is NOT flagged unchecked",
      moved.result && moved.result.purgeAnchorUnchecked !== true,
      JSON.stringify(moved.result));

    // The reported boundary is the ANCHOR's counter, not wherever the walk
    // happened to start. An incremental verify raises its own skip point to the
    // predecessor of the requested range, and reporting that would say an
    // anchor authorizing a purge through 10 authorized one through 149 — so a
    // caller would classify rows that are present, and merely outside the range
    // asked for, as purged.
    // A predecessor BELOW the requested range is what makes the incremental
    // logic raise its skip point — without one in the row set the range is
    // inert and this test would pass against the old code.
    var predecessor = {
      _id: "row-149", monotonicCounter: 149, rowHash: "c".repeat(128),
      prevHash: "d".repeat(128), recordedAt: 1750000000000,
    };
    var ranged = await _verifyWith(
      signedAnchor, function () { return pubPem; }, { from: 150 },
      { chainRows: [predecessor] });
    check("an incremental verify over a purged chain still verifies",
      ranged.threw === null && ranged.result && ranged.result.ok === true,
      JSON.stringify(ranged.result || String(ranged.threw)));
    check("the reported purge boundary is the anchor's own counter, not the range start",
      ranged.result && ranged.result.purgeAnchor &&
      ranged.result.purgeAnchor.belowCounter === forged.lastPurgedCounter,
      JSON.stringify(ranged.result && ranged.result.purgeAnchor));

    // A volume purged BEFORE anchors were signed has no signature columns, and
    // a verifier reading the file directly never runs the migration that adds
    // them. Selecting them errors. Treating that as "no anchor" would verify a
    // legitimately purged chain from ZERO_HASH and report it TAMPERED, which is
    // the loudest possible wrong answer about a volume nobody touched.
    var legacyThrew = null, legacyResult = null;
    try {
      legacyResult = await b.auditChain.verifyChain(
        _mockQuery(forged, { refuseSignatureColumns: true }), "audit_log", {});
    } catch (e) { legacyThrew = e; }
    check("a legacy anchor without signature columns does not throw",
      legacyThrew === null, String(legacyThrew && legacyThrew.message));
    check("it is refused as unsigned rather than read as an unpurged chain",
      legacyResult && legacyResult.ok === false &&
      /no signature/i.test(legacyResult.reason || ""),
      JSON.stringify(legacyResult));
    check("and it is not misreported as a chain break",
      legacyResult && !/chain|hash mismatch/i.test(String(legacyResult.reason || "").replace(/purge anchor/gi, "")),
      String(legacyResult && legacyResult.reason));
  } finally {
    try { b.auditSign._resetForTest(); } catch (_e) { /* best-effort */ }
    try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  }
}

async function run() {
  // Non-hex lastPurgedRowHash → { ok:false, reason }, NOT a throw.
  var bad1 = await _verify({ lastPurgedRowHash: "GARBAGE-not-hex", lastPurgedCounter: "5" });
  check("corrupted anchor (non-hex hash) does not throw", bad1.threw === null);
  check("corrupted anchor (non-hex hash) → ok:false", bad1.result && bad1.result.ok === false);
  check("corrupted anchor → reason names the anchor",
        bad1.result && /anchor/i.test(bad1.result.reason || ""));

  // Wrong-length hex hash → also refused.
  var bad2 = await _verify({ lastPurgedRowHash: "abcd", lastPurgedCounter: "1" });
  check("corrupted anchor (short hash) → ok:false, no throw",
        bad2.threw === null && bad2.result && bad2.result.ok === false);

  // Non-numeric lastPurgedCounter → refused (NaN would skip nothing).
  var validHash = b.auditChain.ZERO_HASH;
  var bad3 = await _verify({ lastPurgedRowHash: validHash, lastPurgedCounter: "not-a-number" });
  check("corrupted anchor (non-numeric counter) → ok:false, no throw",
        bad3.threw === null && bad3.result && bad3.result.ok === false);

  // No anchor at all (never purged) → verifies the (empty) chain fine, ok:true.
  var none = await _verify(null);
  check("no purge anchor → verifies cleanly (ok:true)", none.threw === null && none.result && none.result.ok === true);

  await testAnchorMustProveItWasWrittenWithTheSigningKey();

  console.log("[audit-chain-corrupted-anchor] OK — " + helpers.getChecks() + " checks passed");
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () {}, function (e) { console.error("FAIL: " + helpers.formatErr(e)); process.exit(1); });
}
