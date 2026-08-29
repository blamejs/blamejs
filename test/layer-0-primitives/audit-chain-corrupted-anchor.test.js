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

var nodeCrypto = require("node:crypto");
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
      // A table that has the signature columns but not the newest one. The
      // reader must narrow ONE step — to the projection without
      // firstPurgedCounter — rather than dropping to the oldest shape, which
      // omits `signature` and would read a signed anchor as unsigned.
      if (opts && opts.refuseRangeColumn && /firstPurgedCounter/i.test(sql)) {
        return Promise.reject(new Error('no such column: "firstPurgedCounter"'));
      }
      if (refuseSignatureColumns && /signature/i.test(sql)) {
        // The wording differs per engine, and the difference matters: Postgres
        // says a missing COLUMN and a missing TABLE almost identically, so a
        // classifier that reads one as the other skips the fallback entirely.
        return Promise.reject(new Error(
          (opts && opts.pgWording)
            ? 'error: column "signature" does not exist'
            : 'no such column: "signature"'));
      }
      if (!anchorRow) return Promise.resolve([]);
      // Return only the columns the query asked for, the way a database does.
      // Handing back the whole row regardless would hide a projection that
      // forgot a field the signature covers: the verifier would rebuild the
      // payload from a value the real query never fetched.
      var projected = {};
      Object.keys(anchorRow).forEach(function (col) {
        if (new RegExp('"' + col + '"|`' + col + '`|\\b' + col + '\\b').test(sql)) {
          projected[col] = anchorRow[col];
        }
      });
      return Promise.resolve([projected]);
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
  } catch (e) { threw = e; }
  return { threw: threw, result: result };
}

// The anchor says which rows are allowed to be missing, and verification
// discards everything at or below the counter it names. Shape was the whole of
// the old test — 128 hex characters and a finite number — and shape is exactly
// what an attacker supplies. Three statements erased a trail and the volume
// still verified clean: delete the rows, delete the checkpoints covering them,
// insert an anchor naming any hash and counter. That is less work than the
// relink-and-forge attack the chain already refuses and it erases more, so it
// was a way around the defence rather than a weaker version of it.
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
      fencingToken:      7,
    };
    signedAnchor.signature = b.auditSign.sign(
      b.auditChain.purgeAnchorPayload(signedAnchor));
    signedAnchor.publicKeyFingerprint = b.auditSign.getPublicKeyFingerprint();

    var honored = await _verify(signedAnchor);
    check("a signed purge anchor is honored", honored.threw === null &&
      honored.result && honored.result.ok === true, JSON.stringify(honored.result));

    // Never state a verification that was not performed. The archive
    // identifier is recorded, and by default never resolved — nothing in the
    // framework knows where a consumer keeps bundles — so a caller must be
    // able to tell "a counter was believed" from "an archive was verified".
    check("the honored anchor reports that the archive was NOT resolved",
      honored.result && honored.result.purgeAnchor &&
      honored.result.purgeAnchor.honored === true &&
      honored.result.purgeAnchor.signatureVerified === true &&
      honored.result.purgeAnchor.archiveResolved === false,
      JSON.stringify(honored.result && honored.result.purgeAnchor));
    check("and names the archive it did not resolve, so a caller can go and look",
      honored.result.purgeAnchor.archiveBundleId === forged.archiveBundleId,
      String(honored.result.purgeAnchor.archiveBundleId));

    // A signature proves this framework wrote the anchor. It says nothing
    // about whether the archive still exists or holds the rows — and a
    // boundary whose archive has gone is a gap nothing can ever show the
    // contents of. The consumer supplies that check, because only they know
    // where bundles live.
    var askedFor = [];
    var askedRange = null;
    var withArchive = await _verifyWith(signedAnchor, undefined, {
      resolveArchive: function (id, range) {
        askedFor.push(id);
        askedRange = range;
        return true;
      },
    });
    check("a caller-supplied archive check is asked about the recorded id",
      askedFor.length === 1 && askedFor[0] === forged.archiveBundleId,
      JSON.stringify(askedFor));
    // The id does not name one bundle: slices archived under a single covering
    // checkpoint all carry its id. A resolver holding only the id would accept
    // a surviving sibling as proof the anchored slice is still there, so the
    // range it has to match travels with it.
    check("and is given the range the anchor covers, not the id alone",
      askedRange !== null &&
      Number(askedRange.lastCounter) === Number(signedAnchor.lastPurgedCounter) &&
      String(askedRange.lastRowHash) === String(signedAnchor.lastPurgedRowHash) &&
      Number(askedRange.firstCounter) === Number(signedAnchor.firstPurgedCounter || 0),
      JSON.stringify(askedRange));
    check("and a resolvable archive is reported as resolved",
      withArchive.result && withArchive.result.ok === true &&
      withArchive.result.purgeAnchor.archiveResolved === true,
      JSON.stringify(withArchive.result && withArchive.result.purgeAnchor));

    // Each purge REPLACES the anchor, so after several contiguous ones the
    // boundary licenses everything below it while the row names only the
    // newest bundle. Resolving that bundle says nothing about the earlier
    // ones, and a report where `archiveResolved` stood for the whole licensed
    // range would claim a recoverability nothing checked. So the report says
    // which range the named archive actually covers.
    var laterSlice = Object.assign({}, signedAnchor, { firstPurgedCounter: 6 });
    laterSlice.signature = b.auditSign.sign(
      b.auditChain.purgeAnchorPayload(laterSlice));
    var sliceResult = await _verifyWith(laterSlice, undefined, {
      resolveArchive: function () { return true; },
    });
    check("the report says which range the named archive covers",
      sliceResult.result && sliceResult.result.purgeAnchor &&
      sliceResult.result.purgeAnchor.archiveCoversFrom === 6 &&
      sliceResult.result.purgeAnchor.archiveCoversTo === forged.lastPurgedCounter,
      JSON.stringify(sliceResult.result && sliceResult.result.purgeAnchor));
    check("which is narrower than the boundary it licenses",
      sliceResult.result.purgeAnchor.archiveCoversFrom >
      sliceResult.result.purgeAnchor.licensedFrom,
      "an archive covering only the tail must not read as covering the whole range");

    var missingArchive = await _verifyWith(signedAnchor, undefined, {
      resolveArchive: function () { return false; },
    });
    check("an anchor whose archive cannot be produced stops the verify",
      missingArchive.result && missingArchive.result.ok === false,
      JSON.stringify(missingArchive.result));
    check("and says which archive could not be produced",
      missingArchive.result &&
      missingArchive.result.reason.indexOf(forged.archiveBundleId) !== -1,
      String(missingArchive.result && missingArchive.result.reason));

    // A check that throws is not a check that passed.
    var brokenArchive = await _verifyWith(signedAnchor, undefined, {
      resolveArchive: function () { throw new Error("bundle store unreachable"); },
    });
    check("a throwing archive check refuses rather than falling through",
      brokenArchive.result && brokenArchive.result.ok === false &&
      /could not be resolved/.test(brokenArchive.result.reason || ""),
      String(brokenArchive.result && brokenArchive.result.reason));

    // A resolver that cannot be CALLED is the quiet version of the same
    // problem: both are consulted only when callable, so a typo or a config
    // that failed to load removes the check and returns a clean verify — which
    // reads as "the archive is there" and "the signature was checked" when
    // neither happened.
    var uncallable = [["resolveArchive", "yes"], ["resolveArchive", null],
                      ["resolvePublicKey", 1], ["resolvePublicKey", {}]];
    for (var ui = 0; ui < uncallable.length; ui += 1) {
      var badOpts = {};
      badOpts[uncallable[ui][0]] = uncallable[ui][1];
      var attempt = await _verifyWith(signedAnchor, undefined, badOpts);
      check("an uncallable " + uncallable[ui][0] + " (" +
        (uncallable[ui][1] === null ? "null" : typeof uncallable[ui][1]) +
        ") is refused, not ignored",
        attempt.threw instanceof TypeError &&
        attempt.threw.message.indexOf(uncallable[ui][0]) !== -1 &&
        attempt.result === null,
        String((attempt.threw && attempt.threw.message) || JSON.stringify(attempt.result)));
    }

    // Every field the anchor licenses is covered by the signature. The fencing
    // token is one of them: a purge refuses when the stored token is above its
    // own, so leaving it unsigned would let someone lower it and hand a
    // superseded leader its turn back.
    var fields = [
      ["lastPurgedCounter", 9999],
      ["lastPurgedRowHash", "b".repeat(128)],
      ["archiveBundleId",   "somewhere-else"],
      ["purgedAt",          1760000000000],
      ["fencingToken",      0],
    ];
    for (var i = 0; i < fields.length; i += 1) {
      var edited = Object.assign({}, signedAnchor);
      edited[fields[i][0]] = fields[i][1];
      var moved = await _verifyWith(edited, undefined);
      check("editing " + fields[i][0] + " under a valid signature is refused",
        moved.result && moved.result.ok === false, JSON.stringify(moved.result));
      check("and that is reported as a forgery, not as unchecked",
        moved.result && moved.result.purgeAnchorUnchecked !== true,
        JSON.stringify(moved.result));
    }

    // Half a signature is not a legacy anchor. Nothing ever wrote a row with
    // exactly one of the two fields, so the only way to reach that state is
    // that something removed the other half — and treating it as
    // pre-signing would route it onto the compatibility path, where an
    // acknowledgement pins its boundary permanently.
    var halves = [
      ["signature", { signature: null }],
      ["publicKeyFingerprint", { publicKeyFingerprint: null }],
    ];
    for (var h = 0; h < halves.length; h += 1) {
      var half = Object.assign({}, signedAnchor, halves[h][1]);
      var halfV = await _verifyWith(half, undefined, { allowUnsignedPurgeAnchor: true });
      check("an anchor missing only " + halves[h][0] + " is refused even when unsigned is acknowledged",
        halfV.result && halfV.result.ok === false, JSON.stringify(halfV.result));
      check("and it is reported as corrupt, not as a legacy unsigned anchor",
        halfV.result && /half of a signature/.test(halfV.result.reason || ""),
        String(halfV.result && halfV.result.reason));
    }

    // The counter column is a BIGINT and the signed bytes carry it as
    // String(Number(...)), so two distinct stored values above 2^53 render
    // identically — one signature would cover both, and the boundary could be
    // moved between them while verification stayed happy. Refusing that range
    // is cheaper than giving the anchor its own numeric type.
    var unsafeCounter = Object.assign({}, signedAnchor,
      { lastPurgedCounter: Number.MAX_SAFE_INTEGER + 2 });
    var unsafe = await _verifyWith(unsafeCounter, undefined,
      { allowUnsignedPurgeAnchor: true });
    check("a counter beyond the safe-integer range is refused",
      unsafe.result && unsafe.result.ok === false, JSON.stringify(unsafe.result));
    check("and is reported as corrupt rather than adopted",
      unsafe.result && /below 2\^53/.test(unsafe.result.reason || ""),
      String(unsafe.result && unsafe.result.reason));

    var mintThrew = null;
    try {
      b.auditChain.purgeAnchorPayload(Object.assign({}, signedAnchor,
        { lastPurgedCounter: Number.MAX_SAFE_INTEGER + 2 }));
    } catch (e) { mintThrew = e; }
    check("and no signature is minted over one either",
      mintThrew !== null && /2\^53/.test(mintThrew.message || ""),
      String(mintThrew && mintThrew.message));

    // MAX_SAFE_INTEGER itself is the edge that reads as safe and is not: the
    // chain resumes at the counter AFTER the boundary, and that one aliases.
    // A boundary has to leave room for its own successor.
    var atTheEdge = Object.assign({}, signedAnchor,
      { lastPurgedCounter: Number.MAX_SAFE_INTEGER });
    var edge = await _verifyWith(atTheEdge, undefined,
      { allowUnsignedPurgeAnchor: true });
    check("a boundary at MAX_SAFE_INTEGER is refused — its next counter is not safe",
      edge.result && edge.result.ok === false, JSON.stringify(edge.result));
    var edgeMint = null;
    try {
      b.auditChain.purgeAnchorPayload(Object.assign({}, signedAnchor,
        { lastPurgedCounter: Number.MAX_SAFE_INTEGER }));
    } catch (e) { edgeMint = e; }
    check("and no signature is minted at that edge either",
      edgeMint !== null, String(edgeMint && edgeMint.message));
    // One below it still works, so the bound is exactly where it should be and
    // not a blanket refusal of large counters.
    var justUnder = Object.assign({}, signedAnchor,
      { lastPurgedCounter: Number.MAX_SAFE_INTEGER - 1 });
    var underMint = null;
    try { b.auditChain.purgeAnchorPayload(justUnder); }
    catch (e) { underMint = e; }
    check("one below the edge is still accepted",
      underMint === null, String(underMint && underMint.message));

    // A signature under a key this volume has no record of is not a signature.
    var wrongFp = Object.assign({}, signedAnchor, { publicKeyFingerprint: "0".repeat(64) });
    var wrong = await _verify(wrongFp);
    check("a fingerprint naming no key on record is refused",
      wrong.result && wrong.result.ok === false, JSON.stringify(wrong.result));

    // A resolver that hands back the WRONG key is the quiet version of that.
    // `resolvePublicKey` is a documented extension point, so the anchor's
    // binding to the key it names holds only as far as this function enforces
    // it. Signing the real payload with a second keypair and resolving the
    // anchor's fingerprint to THAT key produces a signature which verifies
    // perfectly — under a key the anchor does not name. Nothing about the
    // signature can tell the difference; only the fingerprint can.
    var otherPair = nodeCrypto.generateKeyPairSync("ml-dsa-65", {
      publicKeyEncoding:  { type: "spki",  format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    var anchorPayload = b.auditChain.purgeAnchorPayload(signedAnchor);
    var otherSig = nodeCrypto.sign(null, anchorPayload,
      nodeCrypto.createPrivateKey(otherPair.privateKey));
    check("the substitute signature is genuinely valid under the substitute key",
      b.auditSign.verify(anchorPayload, otherSig, otherPair.publicKey) === true);
    var substituted = Object.assign({}, signedAnchor, { signature: otherSig });
    var swapKey = await _verifyWith(substituted, function () { return otherPair.publicKey; });
    check("a resolver returning a key the anchor does not name is refused",
      swapKey.result && swapKey.result.ok === false,
      JSON.stringify(swapKey.result));
    check("and says the resolved key hashes to something else",
      swapKey.result && /does not name/.test(swapKey.result.reason || ""),
      String(swapKey.result && swapKey.result.reason));

    // A verifier with no signing state of its own supplies the key. Without
    // this, `blamejs audit verify-chain` — which opens a database file directly
    // and never initializes signing — resolves nothing and reports every VALID
    // anchor as unresolvable, a false alarm on a healthy volume.
    var pubPem = b.auditSign.getPublicKey();
    var supplied = await _verifyWith(signedAnchor, function () { return pubPem; });
    check("a caller-supplied public key resolves the anchor",
      supplied.result && supplied.result.ok === true, JSON.stringify(supplied.result));

    var noKey = await _verifyWith(signedAnchor, function () {
      throw new Error("audit-sign/not-initialized");
    });
    check("a verifier with no key reports the anchor as UNCHECKED",
      noKey.result && noKey.result.ok === false &&
      /could not be checked/.test(noKey.result.reason || ""),
      String(noKey.result && noKey.result.reason));
    check("and flags it so a caller can tell that from a forgery",
      noKey.result && noKey.result.purgeAnchorUnchecked === true,
      JSON.stringify(noKey.result));

    // The reported boundary is the ANCHOR's counter, not wherever the walk
    // started. An incremental verify raises its own skip point to the row
    // before the requested range; reporting that would say an anchor
    // authorizing a purge through 10 authorized one through 149.
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
    check("the reported purge boundary is the anchor's own counter",
      ranged.result && ranged.result.purgeAnchor &&
      ranged.result.purgeAnchor.belowCounter === forged.lastPurgedCounter,
      JSON.stringify(ranged.result && ranged.result.purgeAnchor));

    // A volume purged BEFORE anchors were signed has no signature columns, and
    // a verifier reading the file directly never runs the migration that adds
    // them. Treating the resulting error as "no anchor" would verify a
    // legitimately purged chain from ZERO_HASH and report it TAMPERED — the
    // loudest possible wrong answer about a volume nobody touched.
    var legacy = await _verifyWith(forged, undefined, undefined,
      { refuseSignatureColumns: true });
    check("a legacy anchor without signature columns does not throw",
      legacy.threw === null, String(legacy.threw && legacy.threw.message));
    check("it is refused as unsigned rather than read as an unpurged chain",
      legacy.result && legacy.result.ok === false &&
      /no signature/i.test(legacy.result.reason || ""),
      JSON.stringify(legacy.result));

    // An anchor written before the range start was covered by the signature.
    // Its signature is over the shorter bytes, and the additive migration
    // fills the column with 0 — so rebuilding the current layout gives
    // different bytes and it would read as forged. Refusing it would strand a
    // volume nobody touched.
    var preRangeSigned = Object.assign({}, signedAnchor, { firstPurgedCounter: 0 });
    preRangeSigned.signature = b.auditSign.sign(
      b.auditChain.purgeAnchorPayload(preRangeSigned, { layout: "no-range" }));
    var preRangeResult = await _verifyWith(preRangeSigned, undefined);
    check("an anchor signed before the range start was covered still verifies",
      preRangeResult.result && preRangeResult.result.ok === true,
      JSON.stringify(preRangeResult.result));
    check("and is reported as signature-verified, not merely tolerated",
      preRangeResult.result.purgeAnchor &&
      preRangeResult.result.purgeAnchor.signatureVerified === true,
      JSON.stringify(preRangeResult.result.purgeAnchor));

    // The retry is limited to a range start of ZERO — the only value such an
    // anchor can carry, and the one place both layouts mean the same thing. An
    // anchor claiming a NON-zero start gets no second chance, so this cannot
    // become a way to drop the field from an anchor that has one.
    var droppedRange = Object.assign({}, signedAnchor, { firstPurgedCounter: 6 });
    droppedRange.signature = b.auditSign.sign(
      b.auditChain.purgeAnchorPayload(droppedRange, { layout: "no-range" }));
    var droppedResult = await _verifyWith(droppedRange, undefined);
    check("but a non-zero range start gets no legacy retry",
      droppedResult.result && droppedResult.result.ok === false,
      JSON.stringify(droppedResult.result));

    // The layouts stack. An anchor that DOES record a range but predates the
    // archive digest is the shape between the two, and it needs its own retry:
    // the oldest layout drops the range as well, so it would not match either,
    // and such a volume would read as forged with the repair behind the door
    // the refusal shuts.
    var preDigest = Object.assign({}, signedAnchor,
      { firstPurgedCounter: 6, archiveRowsDigest: "" });
    preDigest.signature = b.auditSign.sign(
      b.auditChain.purgeAnchorPayload(preDigest, { layout: "no-digest" }));
    var preDigestResult = await _verifyWith(preDigest, undefined);
    check("an anchor with a range but no archive digest still verifies",
      preDigestResult.result && preDigestResult.result.ok === true,
      JSON.stringify(preDigestResult.result));
    check("and is reported as signature-verified",
      preDigestResult.result.purgeAnchor &&
      preDigestResult.result.purgeAnchor.signatureVerified === true,
      JSON.stringify(preDigestResult.result.purgeAnchor));

    // And that retry is gated the same way: an anchor that RECORDS a digest
    // gets no layout that omits one, so stripping the digest from an anchor
    // that has one cannot be laundered into a valid signature.
    var droppedDigest = Object.assign({}, signedAnchor,
      { firstPurgedCounter: 6, archiveRowsDigest: "d".repeat(128) });
    droppedDigest.signature = b.auditSign.sign(
      b.auditChain.purgeAnchorPayload(droppedDigest, { layout: "no-digest" }));
    var droppedDigestResult = await _verifyWith(droppedDigest, undefined);
    check("but an anchor recording a digest gets no digest-less retry",
      droppedDigestResult.result && droppedDigestResult.result.ok === false,
      JSON.stringify(droppedDigestResult.result));

    // A table carrying the signature columns but not the newest one. Dropping
    // straight to the oldest projection would omit `signature` and report this
    // signed anchor as unsigned — a weaker claim about a stronger record, and
    // one a deployment that accepts unsigned anchors would then believe.
    var preRange = Object.assign({}, signedAnchor, { firstPurgedCounter: 0 });
    preRange.signature = b.auditSign.sign(b.auditChain.purgeAnchorPayload(preRange));
    var narrowed = await _verifyWith(preRange, undefined, undefined,
      { refuseRangeColumn: true });
    check("a table without the newest column still reads its signature",
      narrowed.threw === null && narrowed.result && narrowed.result.ok === true,
      JSON.stringify(narrowed.result || String(narrowed.threw)));
    check("and the anchor is honored as signature-verified, not as unsigned",
      narrowed.result.purgeAnchor &&
      narrowed.result.purgeAnchor.signatureVerified === true,
      JSON.stringify(narrowed.result.purgeAnchor));

    // Same volume, Postgres wording. A missing column and a missing table read
    // almost identically there, and reading one as the other skips the
    // fallback — the anchor goes unread and a fully purged legacy chain
    // verifies from ZERO_HASH as though nothing had ever been removed.
    var legacyPg = await _verifyWith(forged, undefined, undefined,
      { refuseSignatureColumns: true, pgWording: true });
    check("the legacy fallback is reached on Postgres wording too",
      legacyPg.threw === null && legacyPg.result && legacyPg.result.ok === false &&
      /no signature/i.test(legacyPg.result.reason || ""),
      JSON.stringify(legacyPg.result || String(legacyPg.threw)));

    // A read that FAILED is not a read that found nothing. A timeout or a
    // dropped connection says nothing about whether an anchor exists, and
    // answering it with "there is none" verifies a purged chain from ZERO_HASH
    // and calls it clean — the exact outcome the signature exists to prevent,
    // reached by a flaky network instead of an attacker.
    var transientErr = null;
    try {
      await b.auditChain.verifyChain(function (sql) {
        if (typeof sql === "string" && sql.indexOf("purge_anchor") !== -1) {
          return Promise.reject(new Error("connection terminated unexpectedly"));
        }
        return Promise.resolve([]);
      }, "audit_log", {});
    } catch (e) { transientErr = e; }
    check("a transient failure reading the anchor stops the verify",
      transientErr !== null && /connection terminated/.test(transientErr.message || ""),
      String(transientErr && transientErr.message));

    // A table that is genuinely absent still reads as "nothing was purged" —
    // that is what a deployment which has never purged looks like.
    var noTable = await _verifyWith(forged, undefined, undefined, { refuseSignatureColumns: true });
    void noTable;
    var absent = null;
    try {
      absent = await b.auditChain.verifyChain(function (sql) {
        if (typeof sql === "string" && sql.indexOf("purge_anchor") !== -1) {
          return Promise.reject(new Error("no such table: _blamejs_audit_purge_anchor"));
        }
        return Promise.resolve([]);
      }, "audit_log", {});
    } catch (e) { absent = e; }
    check("but a genuinely missing table still reads as nothing purged",
      absent && absent.ok === true, JSON.stringify(absent && (absent.message || absent)));

    // The one-time upgrade path: an operator who acknowledges the legacy
    // boundary gets it adopted, and the result says plainly that it was
    // trusted rather than verified.
    var acked = await _verifyWith(forged, undefined,
      { allowUnsignedPurgeAnchor: true });
    check("an acknowledged unsigned anchor is adopted",
      acked.result && acked.result.ok === true, JSON.stringify(acked.result));
    check("and is reported as trusted, NOT as signature-verified",
      acked.result && acked.result.purgeAnchor &&
      acked.result.purgeAnchor.honored === true &&
      acked.result.purgeAnchor.signatureVerified === false,
      JSON.stringify(acked.result && acked.result.purgeAnchor));
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
  check("and reports no purge anchor at all", none.result && none.result.purgeAnchor === undefined);

  await testAnchorMustProveItWasWrittenWithTheSigningKey();

  console.log("[audit-chain-corrupted-anchor] OK — " + helpers.getChecks() + " checks passed");
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () {}, function (e) { console.error("FAIL: " + helpers.formatErr(e)); process.exit(1); });
}
