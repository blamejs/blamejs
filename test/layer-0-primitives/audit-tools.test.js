// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.auditTools — audit-chain inspection / export / archive / verify /
 * purge. This canonical suite drives the error, adversarial, defensive
 * and option-default branches of every verb:
 *
 *   - input validation (passphrase / out-dir / date coercion / mutually-
 *     exclusive out+returnBytes),
 *   - corrupt-bundle rejection in _readBundle (missing / oversized /
 *     checksum-mismatched blobs, bad format / kind),
 *   - chain-integrity failure surfacing in verifyBundle (prevHash break,
 *     rowHash break, first/last-rowHash disagreement, checkpoint binding),
 *   - purge refusal paths (unverified archive, wrong kind, non-monotonic,
 *     anchor mismatch, dual-control gate),
 *   - the CADF export mapping across every outcome / field shape.
 *
 * The happy paths run against a real encrypted db + audit chain +
 * ML-DSA-signed checkpoint (setupTestDb) so the default readers /
 * signature verifier / writer / reader are exercised end-to-end. The
 * adversarial paths tamper written bundles on disk or inject the
 * operator-overridable readers, never a fake crypto primitive.
 */

var helpers = require("../helpers");
var b              = helpers.b;
var check          = helpers.check;
var fs             = helpers.fs;
var os             = helpers.os;
var path           = helpers.path;
var setupTestDb    = helpers.setupTestDb;
var teardownTestDb = helpers.teardownTestDb;
var backupCrypto   = require("../../lib/backup/crypto");
var nodeCrypto     = require("node:crypto");

var PASS = Buffer.from("audit-tools-canonical-test-passphrase");
var ZERO = "0".repeat(128);

var _seq = 0;
function _freshOut(root, name) { _seq += 1; return path.join(root, name + "-" + _seq); }

async function _expectCode(fn, code) {
  var threw = null;
  try { await fn(); } catch (e) { threw = e; }
  return threw && threw.code === code;
}

function _copyBundle(src, dst) {
  fs.mkdirSync(dst, { recursive: true });
  var entries = fs.readdirSync(src);
  for (var i = 0; i < entries.length; i++) {
    fs.copyFileSync(path.join(src, entries[i]), path.join(dst, entries[i]));
  }
  return dst;
}

function _flipByte(file) {
  var buf = fs.readFileSync(file);
  buf[0] = buf[0] ^ 0xff;
  fs.writeFileSync(file, buf);
}

function _editManifest(dir, mutate) {
  var p = path.join(dir, "manifest.json");
  var m = JSON.parse(fs.readFileSync(p, "utf8"));
  mutate(m);
  fs.writeFileSync(p, JSON.stringify(m));
}

// ---------------------------------------------------------------------------
// Pure / no-db branches: input validation, date coercion, CADF mapping,
// withRecordedAtIso, the reader-injection error paths that throw before any
// filesystem or db touch.
// ---------------------------------------------------------------------------
async function runInputValidation(root) {
  // _requirePassphrase — missing (not Buffer/string), and empty.
  check("archive: missing passphrase rejected",
    await _expectCode(function () { return b.auditTools.archive({}); }, "audit-tools/no-passphrase"));
  check("archive: empty-string passphrase rejected",
    await _expectCode(function () { return b.auditTools.archive({ passphrase: "" }); }, "audit-tools/no-passphrase"));
  check("archive: empty-Buffer passphrase rejected",
    await _expectCode(function () { return b.auditTools.archive({ passphrase: Buffer.alloc(0) }); }, "audit-tools/no-passphrase"));

  // _requireOutDir — not a string, and already-exists.
  check("archive: missing out (no returnBytes) rejected",
    await _expectCode(function () { return b.auditTools.archive({ passphrase: PASS, before: Date.now() }); }, "audit-tools/no-outdir"));
  var existing = _freshOut(root, "already-there");
  fs.mkdirSync(existing, { recursive: true });
  check("archive: refuses to overwrite an existing out dir",
    await _expectCode(function () {
      return b.auditTools.archive({ passphrase: PASS, before: Date.now(), out: existing });
    }, "audit-tools/outdir-exists"));

  // out + returnBytes are mutually exclusive on every verb that offers both.
  check("archive: out + returnBytes rejected",
    await _expectCode(function () {
      return b.auditTools.archive({ passphrase: PASS, returnBytes: true, out: _freshOut(root, "x"), before: Date.now() });
    }, "audit-tools/out-and-return-bytes"));
  check("exportSlice: out + returnBytes rejected",
    await _expectCode(function () {
      return b.auditTools.exportSlice({ passphrase: PASS, returnBytes: true, out: _freshOut(root, "x") });
    }, "audit-tools/out-and-return-bytes"));
  check("forensicSnapshot: out + returnBytes rejected",
    await _expectCode(function () {
      return b.auditTools.forensicSnapshot({ passphrase: PASS, returnBytes: true, out: _freshOut(root, "x"), since: Date.now(), reason: "x" });
    }, "audit-tools/out-and-return-bytes"));

  // exportSlice missing out.
  check("exportSlice: missing out rejected",
    await _expectCode(function () { return b.auditTools.exportSlice({ passphrase: PASS }); }, "audit-tools/no-outdir"));

  // archive: before is required (date coercion of undefined → null).
  check("archive: missing before rejected",
    await _expectCode(function () {
      return b.auditTools.archive({ passphrase: PASS, out: _freshOut(root, "nb") });
    }, "audit-tools/no-before"));

  // _toMs adversarial via archive (bad string / bad type).
  check("archive: unparseable before string rejected",
    await _expectCode(function () {
      return b.auditTools.archive({ passphrase: PASS, out: _freshOut(root, "bd"), before: "not-a-date" });
    }, "audit-tools/bad-date"));
  check("archive: non-date-typed before rejected",
    await _expectCode(function () {
      return b.auditTools.archive({ passphrase: PASS, out: _freshOut(root, "bt"), before: true });
    }, "audit-tools/bad-date"));

  // forensicSnapshot required-opt branches (returnBytes skips the out check).
  check("forensicSnapshot: missing since rejected",
    await _expectCode(function () {
      return b.auditTools.forensicSnapshot({ passphrase: PASS, returnBytes: true, reason: "x" });
    }, "audit-tools/no-since"));
  check("forensicSnapshot: missing/empty reason rejected",
    await _expectCode(function () {
      return b.auditTools.forensicSnapshot({ passphrase: PASS, returnBytes: true, since: Date.now() });
    }, "audit-tools/no-reason"));

  // verifyBundle / purge entry-point validation.
  check("verifyBundle: missing passphrase rejected",
    await _expectCode(function () { return b.auditTools.verifyBundle({ in: "/nope" }); }, "audit-tools/no-passphrase"));
  check("verifyBundle: missing in rejected",
    await _expectCode(function () { return b.auditTools.verifyBundle({ passphrase: PASS }); }, "audit-tools/no-indir"));
  check("purge: confirm must be exactly true",
    await _expectCode(function () { return b.auditTools.purge({ archive: "/x", passphrase: PASS }); }, "audit-tools/no-confirm"));
  check("purge: missing archive path rejected",
    await _expectCode(function () { return b.auditTools.purge({ confirm: true, passphrase: PASS }); }, "audit-tools/no-archive"));
  check("purge: missing passphrase rejected",
    await _expectCode(function () { return b.auditTools.purge({ confirm: true, archive: "/x" }); }, "audit-tools/no-passphrase"));
}

async function runReaderInjectedErrors(root) {
  async function empty() { return []; }
  // archive: no rows match.
  check("archive: no matching rows rejected",
    await _expectCode(function () {
      return b.auditTools.archive({ passphrase: PASS, out: _freshOut(root, "e"), before: Date.now(), readRows: empty });
    }, "audit-tools/empty"));
  // archive: no covering checkpoint.
  var oneRow = [{ _id: "r1", monotonicCounter: 1, recordedAt: 1, action: "a", prevHash: ZERO, rowHash: "aa", nonce: Buffer.from("nn") }];
  check("archive: no covering checkpoint rejected",
    await _expectCode(function () {
      return b.auditTools.archive({
        passphrase: PASS, out: _freshOut(root, "nc"), before: Date.now(),
        readRows: function () { return Promise.resolve(oneRow); },
        readCoveringCheckpoint: function () { return Promise.resolve(null); },
      });
    }, "audit-tools/no-covering-checkpoint"));

  // exportSlice: empty + non-contiguous.
  check("exportSlice: no matching rows rejected",
    await _expectCode(function () {
      return b.auditTools.exportSlice({ passphrase: PASS, out: _freshOut(root, "ee"), readRows: empty });
    }, "audit-tools/empty"));
  check("exportSlice: non-contiguous slice rejected",
    await _expectCode(function () {
      return b.auditTools.exportSlice({
        passphrase: PASS, out: _freshOut(root, "ncg"),
        readRows: function () { return Promise.resolve([{ monotonicCounter: 1 }, { monotonicCounter: 3 }]); },
      });
    }, "audit-tools/non-contiguous"));

  // archive witness path: covering checkpoint anchors a counter beyond the
  // purgeable slice tip, so the in-between rows ride as verification
  // witnesses. Fake rows suffice — the build only reads counters/hashes.
  function fakeRow(c) {
    return { _id: "w" + c, monotonicCounter: c, recordedAt: c * 10, action: "seed", prevHash: ZERO, rowHash: "hh" + c, nonce: Buffer.from("n" + c) };
  }
  var witnessBuilt = await b.auditTools.archive({
    passphrase: PASS, returnBytes: true, before: Date.now(),
    readRows: function (crit) {
      if (crit.beforeMs != null) return Promise.resolve([fakeRow(1), fakeRow(2), fakeRow(3)]);
      return Promise.resolve([fakeRow(4), fakeRow(5)]);   // witnesses 4..5
    },
    readCoveringCheckpoint: function () {
      return Promise.resolve({ atMonotonicCounter: 5, atRowHash: "hh5", publicKeyFingerprint: "fp", _id: "ck" });
    },
    readPredecessorRowHash: function () { return Promise.resolve(ZERO); },
  });
  check("archive witness path: purgeable rowCount excludes witnesses", witnessBuilt.rowCount === 3);
  var wPlain = (await backupCrypto.decryptWithPassphrase(
    witnessBuilt.files["rows.enc"], PASS, witnessBuilt.manifest.salts.rows)).toString("utf8");
  check("archive witness path: rows.enc carries slice + witness lines",
    wPlain.split("\n").filter(Boolean).length === 5);

  // archive: witnesses required by the checkpoint anchor are not all
  // available → the slice cannot be proven to chain to the signed anchor.
  check("archive: missing anchor witnesses rejected",
    await _expectCode(function () {
      return b.auditTools.archive({
        passphrase: PASS, returnBytes: true, before: Date.now(),
        readRows: function (crit) {
          if (crit.beforeMs != null) return Promise.resolve([fakeRow(1), fakeRow(2), fakeRow(3)]);
          return Promise.resolve([fakeRow(4)]);   // tip 4 ≠ anchor 5
        },
        readCoveringCheckpoint: function () {
          return Promise.resolve({ atMonotonicCounter: 5, atRowHash: "hh5", publicKeyFingerprint: "fp", _id: "ck" });
        },
        readPredecessorRowHash: function () { return Promise.resolve(ZERO); },
      });
    }, "audit-tools/anchor-rows-missing"));
}

async function runCadfMapping() {
  var base = Date.UTC(2026, 4, 1, 0, 0, 0);
  var rows = [
    { _id: "e1", monotonicCounter: 1, recordedAt: base, action: "auth.login", outcome: "success",
      actorUserIdHash: "h-alice", actorIp: "10.0.0.5", actorSessionId: "s-1", resourceKind: "session", resourceId: "r1",
      reason: "policy allow", metadata: { k: 1 }, prevHash: ZERO, rowHash: "aa" },
    { _id: "e2", monotonicCounter: 2, recordedAt: base + 1, action: "auth.fail", outcome: "failure",
      actorUserId: "bob", resourceId: "r2", metadata: '{"j":2}', prevHash: "aa", rowHash: "bb" },
    { _id: "e3", monotonicCounter: 3, recordedAt: base + 2, action: "policy.deny", outcome: "denied",
      metadata: "{not json", prevHash: "bb", rowHash: "cc" },
    { _id: "e4", monotonicCounter: 4, recordedAt: base + 3, action: "sys.warn", outcome: "warning",
      metadata: null, prevHash: "cc", rowHash: "dd" },
    { _id: "e5", monotonicCounter: 5, recordedAt: base + 4, action: "sys.odd", outcome: "quantum",
      prevHash: "dd", rowHash: "ee" },
    { _id: "e6", monotonicCounter: 6, recordedAt: base + 5, action: "sys.blank", prevHash: "ee", rowHash: "ff" },
  ];
  async function readRows() { return rows; }

  // Range with explicit from/to (ISO round-trip) via exportAudit default dispatch.
  var batch = await b.auditTools.exportAudit({ from: new Date(base), to: base + 100, readRows: readRows });
  check("exportAudit: defaults to cadf batch envelope",
    batch.typeURI.indexOf("event-batch") !== -1 && batch.events.length === 6);
  check("cadf: range.from is ISO", batch.range.from === new Date(base).toISOString());
  check("cadf: success outcome preserved", batch.events[0].outcome === "success");
  check("cadf: object metadata attached", batch.events[0].attachments && batch.events[0].attachments.length === 1);
  check("cadf: actorIp mapped to initiator address",
    batch.events[0].initiator.addresses && batch.events[0].initiator.addresses[0].url === "10.0.0.5");
  check("cadf: reason mapped", batch.events[0].reason && batch.events[0].reason.reasonCode === "policy allow");
  check("cadf: resourceKind → target typeURI", /session$/.test(batch.events[0].target.typeURI));
  check("cadf: failure outcome preserved", batch.events[1].outcome === "failure");
  check("cadf: string metadata parsed", batch.events[1].attachments && /"j":2/.test(batch.events[1].attachments[0].content));
  check("cadf: actorUserId fallback initiator id", batch.events[1].initiator.id === "bob");
  check("cadf: resourceId fallback target id", batch.events[1].target.id === "r2");
  check("cadf: no actorIp → no addresses", batch.events[1].initiator.addresses === undefined);
  check("cadf: denied → failure outcome", batch.events[2].outcome === "failure");
  check("cadf: unparseable metadata falls back to raw",
    batch.events[2].attachments && /not json/.test(batch.events[2].attachments[0].content));
  check("cadf: unknown initiator id when no actor fields", batch.events[2].initiator.id === "unknown");
  check("cadf: n/a target when no resource fields", batch.events[2].target.id === "n/a");
  check("cadf: warning → unknown outcome", batch.events[3].outcome === "unknown");
  check("cadf: null metadata → no attachments", batch.events[3].attachments === undefined);
  check("cadf: unrecognized outcome passes through", batch.events[4].outcome === "quantum");
  check("cadf: absent outcome → unknown", batch.events[5].outcome === "unknown");
  check("cadf: no reason → undefined", batch.events[5].reason === undefined);

  // Range with no from/to → both null; _toMs(undefined) → null branch.
  var openBatch = await b.auditTools.exportCadf({ readRows: readRows });
  check("cadf: open range yields null bounds",
    openBatch.range.from === null && openBatch.range.to === null);

  // exportCadf / exportAudit bad-format rejections.
  check("exportCadf: non-cadf format rejected",
    await _expectCode(function () { return b.auditTools.exportCadf({ format: "cef", readRows: readRows }); }, "audit-tools/bad-format"));
  check("exportAudit: unknown format rejected",
    await _expectCode(function () { return b.auditTools.exportAudit({ format: "xml", readRows: readRows }); }, "audit-tools/bad-format"));

  // _toMs Date-instance + parseable-string positive paths, and adversarial.
  var isoBatch = await b.auditTools.exportCadf({ from: "2026-01-01T00:00:00Z", readRows: readRows });
  check("cadf: parseable ISO string from-bound applied",
    isoBatch.range.from === new Date("2026-01-01T00:00:00Z").toISOString());
  check("exportCadf: unparseable from string rejected",
    await _expectCode(function () { return b.auditTools.exportCadf({ from: "nonsense", readRows: readRows }); }, "audit-tools/bad-date"));
  check("exportCadf: non-date-typed from rejected",
    await _expectCode(function () { return b.auditTools.exportCadf({ from: {}, readRows: readRows }); }, "audit-tools/bad-date"));
}

async function runForensicSuccess(root) {
  // Fake but contiguous rows starting at counter 1 → the default predecessor
  // reader short-circuits to ZERO_HASH without any db touch.
  function frow(c) {
    return { _id: "f" + c, monotonicCounter: c, recordedAt: c * 1000, action: "sys.evt", outcome: "success", prevHash: ZERO, rowHash: "rr" + c, nonce: Buffer.from("n" + c) };
  }
  async function readRows() { return [frow(1), frow(2), frow(3)]; }

  // returnBytes: assembles the slice files plus the IR wrapper in memory.
  var snap = await b.auditTools.forensicSnapshot({
    returnBytes: true, since: 0, passphrase: PASS, reason: "IR drill", incidentId: "inc-1",
    actor: { id: "alice", role: "incident-commander" }, readRows: readRows,
  });
  check("forensicSnapshot: returnBytes yields the IR wrapper file", Buffer.isBuffer(snap.files["forensic-snapshot.json"]));
  check("forensicSnapshot: returnBytes yields the slice rows.enc", Buffer.isBuffer(snap.files["rows.enc"]));
  check("forensicSnapshot: snapshotKind is forensic", snap.snapshotKind === "forensic");
  check("forensicSnapshot: incidentId + actor carried", snap.incidentId === "inc-1" && snap.actor.role === "incident-commander");
  check("forensicSnapshot: runtime fingerprint captured", snap.runtime && snap.runtime.nodeVersion === process.version);
  check("forensicSnapshot: no disk manifestPath in returnBytes mode", snap.manifestPath === undefined);

  // on-disk: writes rows.enc + manifest.json + forensic-snapshot.json.
  var fdir = _freshOut(root, "forensic");
  var snap2 = await b.auditTools.forensicSnapshot({ out: fdir, since: 0, passphrase: PASS, reason: "IR onto disk", readRows: readRows });
  check("forensicSnapshot: on-disk returns a manifestPath", typeof snap2.manifestPath === "string" && /forensic-snapshot\.json$/.test(snap2.manifestPath));
  check("forensicSnapshot: on-disk wrote the IR wrapper", fs.existsSync(snap2.manifestPath));
  check("forensicSnapshot: omitted incidentId/actor default to null", snap2.incidentId === null && snap2.actor === null);
}

function runWithRecordedAtIso() {
  check("withRecordedAtIso: null passes through", b.auditTools.withRecordedAtIso(null) === null);
  check("withRecordedAtIso: undefined passes through", b.auditTools.withRecordedAtIso(undefined) === undefined);
  var n = b.auditTools.withRecordedAtIso({ _id: "x", recordedAt: 1762560000000 });
  check("withRecordedAtIso: number recordedAt → ISO added", n.recordedAtIso === new Date(1762560000000).toISOString());
  var big = b.auditTools.withRecordedAtIso({ _id: "x", recordedAt: 1762560000000n });
  check("withRecordedAtIso: bigint recordedAt → ISO added", big.recordedAtIso === new Date(1762560000000).toISOString());
  var inf = b.auditTools.withRecordedAtIso({ _id: "x", recordedAt: Infinity });
  check("withRecordedAtIso: non-finite recordedAt → no ISO", inf.recordedAtIso === undefined);
  var str = b.auditTools.withRecordedAtIso({ _id: "x", recordedAt: "2025" });
  check("withRecordedAtIso: non-numeric recordedAt → unchanged", str.recordedAtIso === undefined);
}

// ---------------------------------------------------------------------------
// Integrated: real encrypted db + audit chain + signed checkpoint.
// ---------------------------------------------------------------------------
async function _seedAuditRows(count) {
  b.audit.registerNamespace("test");
  for (var i = 0; i < count; i++) {
    await b.audit.record({ actor: { userId: "u-" + i }, action: "test.seeded", outcome: "success", metadata: { i: i } });
  }
  await b.audit.flush();
}

async function runIntegrated(root) {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-at-db-"));
  var archiveDir = _freshOut(root, "archive");
  var tornDown = false;
  try {
    await setupTestDb(dir);
    await _seedAuditRows(6);
    await b.audit.checkpoint();

    var realRows = await b.clusterStorage.executeAll("SELECT * FROM audit_log ORDER BY monotonicCounter ASC");
    check("seeded a real audit chain", realRows.length >= 6);
    var firstCounter = Number(realRows[0].monotonicCounter);
    var lastCounter  = Number(realRows[realRows.length - 1].monotonicCounter);

    // ---- archive happy path (default readers + signer + writer) ----
    var arch = await b.auditTools.archive({ out: archiveDir, before: new Date(Date.now() + 3600000), passphrase: PASS });
    check("archive: wrote a bundle with rowCount", arch.rowCount === realRows.length);
    check("archive: manifest is archive kind", arch.manifest.kind === "archive");

    // ---- verifyBundle happy variants ----
    var ok = await b.auditTools.verifyBundle({ in: archiveDir, passphrase: PASS });
    check("verifyBundle: archive verifies ok", ok.ok === true && ok.kind === "archive");
    check("verifyBundle: rowsVerified matches", ok.rowsVerified === realRows.length);
    var okRows = await b.auditTools.verifyBundle({ in: archiveDir, passphrase: PASS, includeRows: true });
    check("verifyBundle: includeRows attaches decrypted rows", Array.isArray(okRows.rows) && okRows.rows.length === realRows.length);
    var okNoSig = await b.auditTools.verifyBundle({ in: archiveDir, passphrase: PASS, verifyCheckpointSignature: false });
    check("verifyBundle: signature check can be skipped", okNoSig.ok === true);
    var badSig = await b.auditTools.verifyBundle({ in: archiveDir, passphrase: PASS, verifySignature: function () { return false; } });
    check("verifyBundle: failing signature verifier → not ok", badSig.ok === false && /signature/.test(badSig.reason));

    // ---- exportSlice happy (default readers, predecessor at chain origin) ----
    var exportDir = _freshOut(root, "export");
    var exp = await b.auditTools.exportSlice({ out: exportDir, from: 0, to: Date.now() + 3600000, passphrase: PASS });
    check("exportSlice: wrote an export bundle", exp.manifest.kind === "export" && exp.rowCount === realRows.length);
    var okExp = await b.auditTools.verifyBundle({ in: exportDir, passphrase: PASS });
    check("verifyBundle: export bundle verifies ok", okExp.ok === true && okExp.kind === "export");

    // ---- exportSlice with a predecessor beyond the chain origin (firstCounter>1) ----
    if (realRows.length >= 3) {
      var midDir = _freshOut(root, "mid");
      var midRows = realRows.slice(2);   // starts at counter firstCounter+2
      var midExp = await b.auditTools.exportSlice({
        out: midDir, passphrase: PASS,
        readRows: function () { return Promise.resolve(midRows); },
      });
      check("exportSlice: mid-chain slice records a real predecessor hash",
        midExp.manifest.range.predecessorRowHash === String(realRows[1].rowHash));
      var okMid = await b.auditTools.verifyBundle({ in: midDir, passphrase: PASS });
      check("verifyBundle: mid-chain slice verifies against its predecessor", okMid.ok === true);
    }

    // ---- rowHash break: a row whose content was mutated after hashing ----
    var tamperedRows = realRows.map(function (r, idx) {
      return idx === 1 ? Object.assign({}, r, { action: "TAMPERED-" + r.action }) : r;
    });
    var rhDir = _freshOut(root, "rowhash-break");
    await b.auditTools.exportSlice({
      out: rhDir, passphrase: PASS,
      readRows: function () { return Promise.resolve(tamperedRows); },
      readPredecessorRowHash: function () { return Promise.resolve(String(realRows[0].prevHash)); },
    });
    var rhRes = await b.auditTools.verifyBundle({ in: rhDir, passphrase: PASS });
    check("verifyBundle: mutated row content → rowHash mismatch", rhRes.ok === false && /rowHash mismatch/.test(rhRes.reason));

    // ---- prevHash break via tampered manifest predecessor witness ----
    var pbDir = _copyBundle(archiveDir, _freshOut(root, "prevhash-break"));
    _editManifest(pbDir, function (m) { m.range.predecessorRowHash = "f".repeat(128); });
    var pbRes = await b.auditTools.verifyBundle({ in: pbDir, passphrase: PASS });
    check("verifyBundle: wrong predecessor witness → prevHash mismatch", pbRes.ok === false && /prevHash mismatch/.test(pbRes.reason));

    // ---- first/last rowHash disagreement with the manifest ----
    var frDir = _copyBundle(archiveDir, _freshOut(root, "first-mismatch"));
    _editManifest(frDir, function (m) { m.range.firstRowHash = "e".repeat(128); });
    var frRes = await b.auditTools.verifyBundle({ in: frDir, passphrase: PASS });
    check("verifyBundle: firstRowHash disagreement flagged", frRes.ok === false && /firstRowHash/.test(frRes.reason));
    var lrDir = _copyBundle(archiveDir, _freshOut(root, "last-mismatch"));
    _editManifest(lrDir, function (m) { m.range.lastRowHash = "e".repeat(128); });
    var lrRes = await b.auditTools.verifyBundle({ in: lrDir, passphrase: PASS });
    check("verifyBundle: lastRowHash disagreement flagged", lrRes.ok === false && /lastRowHash/.test(lrRes.reason));

    // ---- a range claiming to start before the rows it holds ----
    // Every check above asks about the rows that ARE present, so a manifest
    // rewritten to claim a wider range passes them all. What the claim then
    // buys is a purge authorized from the claimed start: the rows between the
    // claimed and actual start are deleted with no copy of them anywhere.
    var fcDir = _copyBundle(archiveDir, _freshOut(root, "first-counter-widened"));
    _editManifest(fcDir, function (m) {
      m.range.firstCounter = Number(m.range.firstCounter) - 50;
    });
    var fcRes = await b.auditTools.verifyBundle({ in: fcDir, passphrase: PASS });
    check("verifyBundle: a range wider than the archived rows is refused",
      fcRes.ok === false && /firstCounter/.test(fcRes.reason), JSON.stringify(fcRes.reason));

    // And the same claim from the other end: a lastCounter naming a row the
    // bundle does not carry.
    var lcDir = _copyBundle(archiveDir, _freshOut(root, "last-counter-absent"));
    _editManifest(lcDir, function (m) {
      m.range.lastCounter = Number(m.range.lastCounter) + 500;
    });
    var lcRes = await b.auditTools.verifyBundle({ in: lcDir, passphrase: PASS });
    check("verifyBundle: a lastCounter naming no archived row is refused",
      lcRes.ok === false && /lastCounter/.test(lcRes.reason), JSON.stringify(lcRes.reason));

    // ---- checkpoint atMonotonicCounter below the slice tip (build-time inject) ----
    if (realRows.length >= 2) {
      var lowDir = _freshOut(root, "ckpt-low");
      await b.auditTools.archive({
        out: lowDir, before: new Date(Date.now() + 3600000), passphrase: PASS,
        readRows: function () { return Promise.resolve(realRows); },
        readCoveringCheckpoint: function () {
          return Promise.resolve({ atMonotonicCounter: firstCounter, atRowHash: String(realRows[0].rowHash), publicKeyFingerprint: "fp", _id: "ck-low" });
        },
      });
      var lowRes = await b.auditTools.verifyBundle({ in: lowDir, passphrase: PASS });
      check("verifyBundle: checkpoint below lastCounter flagged", lowRes.ok === false && /atMonotonicCounter/.test(lowRes.reason));
    }

    // ---- checkpoint atRowHash not bound to the anchored slice row ----
    var bindDir = _freshOut(root, "ckpt-unbound");
    await b.auditTools.archive({
      out: bindDir, before: new Date(Date.now() + 3600000), passphrase: PASS,
      readRows: function () { return Promise.resolve(realRows); },
      readCoveringCheckpoint: function () {
        return Promise.resolve({ atMonotonicCounter: lastCounter, atRowHash: "f".repeat(128), publicKeyFingerprint: "fp", _id: "ck-unbound" });
      },
    });
    var bindRes = await b.auditTools.verifyBundle({ in: bindDir, passphrase: PASS, verifyCheckpointSignature: false });
    check("verifyBundle: checkpoint atRowHash not bound to slice flagged", bindRes.ok === false && /atRowHash does not match/.test(bindRes.reason));

    // ---- checkpoint anchoring a counter NOT present in the bundle ----
    // An attacker pairs a checkpoint claiming a high anchor counter with a
    // slice that omits that row. Re-encrypt checkpoint.enc on a written copy
    // with an anchor counter beyond every bundle row and refresh the manifest
    // checksum so the read passes to the binding step.
    var absentDir = _copyBundle(archiveDir, _freshOut(root, "anchor-absent"));
    var forgedCkpt = await backupCrypto.encryptWithFreshSalt(
      JSON.stringify({ atMonotonicCounter: lastCounter + 5, atRowHash: "a".repeat(128) }), PASS);
    fs.writeFileSync(path.join(absentDir, "checkpoint.enc"), forgedCkpt.encrypted);
    _editManifest(absentDir, function (m) {
      m.salts.checkpoint = forgedCkpt.salt;
      m.checksum.checkpointSha3_512 = backupCrypto.checksum(forgedCkpt.encrypted);
      m.checkpoint.atMonotonicCounter = lastCounter + 5;
    });
    var absentRes = await b.auditTools.verifyBundle({ in: absentDir, passphrase: PASS, verifyCheckpointSignature: false });
    check("verifyBundle: checkpoint anchoring an absent counter is unbound",
      absentRes.ok === false && /no such row is present/.test(absentRes.reason));

    // ---- _readBundle corrupt-blob rejections (tamper written copies) ----
    var rcDir = _copyBundle(archiveDir, _freshOut(root, "rows-checksum"));
    _flipByte(path.join(rcDir, "rows.enc"));
    check("verifyBundle: tampered rows.enc → checksum mismatch",
      await _expectCode(function () { return b.auditTools.verifyBundle({ in: rcDir, passphrase: PASS }); }, "audit-tools/rows-checksum-mismatch"));

    var nrDir = _copyBundle(archiveDir, _freshOut(root, "no-rows"));
    fs.rmSync(path.join(nrDir, "rows.enc"));
    check("verifyBundle: missing rows.enc rejected",
      await _expectCode(function () { return b.auditTools.verifyBundle({ in: nrDir, passphrase: PASS }); }, "audit-tools/no-rows-blob"));

    var nmDir = _freshOut(root, "no-manifest");
    fs.mkdirSync(nmDir, { recursive: true });
    check("verifyBundle: missing manifest rejected",
      await _expectCode(function () { return b.auditTools.verifyBundle({ in: nmDir, passphrase: PASS }); }, "audit-tools/no-manifest"));

    var tmDir = _freshOut(root, "manifest-too-large");
    fs.mkdirSync(tmDir, { recursive: true });
    fs.writeFileSync(path.join(tmDir, "manifest.json"), Buffer.alloc(5242880, 0x61));   // 5 MiB > 4 MiB cap
    check("verifyBundle: oversized manifest rejected",
      await _expectCode(function () { return b.auditTools.verifyBundle({ in: tmDir, passphrase: PASS }); }, "audit-tools/bad-format"));

    var bfDir = _copyBundle(archiveDir, _freshOut(root, "bad-format"));
    _editManifest(bfDir, function (m) { m.format = "not-a-blamejs-bundle"; });
    check("verifyBundle: wrong manifest format rejected",
      await _expectCode(function () { return b.auditTools.verifyBundle({ in: bfDir, passphrase: PASS }); }, "audit-tools/bad-format"));

    var bkDir = _copyBundle(archiveDir, _freshOut(root, "bad-kind"));
    _editManifest(bkDir, function (m) { m.kind = "bogus"; });
    check("verifyBundle: unknown manifest kind rejected",
      await _expectCode(function () { return b.auditTools.verifyBundle({ in: bkDir, passphrase: PASS }); }, "audit-tools/bad-kind"));

    var ncDir = _copyBundle(archiveDir, _freshOut(root, "no-ckpt"));
    fs.rmSync(path.join(ncDir, "checkpoint.enc"));
    check("verifyBundle: archive missing checkpoint.enc rejected",
      await _expectCode(function () { return b.auditTools.verifyBundle({ in: ncDir, passphrase: PASS }); }, "audit-tools/no-checkpoint-blob"));

    var ccDir = _copyBundle(archiveDir, _freshOut(root, "ckpt-checksum"));
    _flipByte(path.join(ccDir, "checkpoint.enc"));
    check("verifyBundle: tampered checkpoint.enc → checksum mismatch",
      await _expectCode(function () { return b.auditTools.verifyBundle({ in: ccDir, passphrase: PASS }); }, "audit-tools/checkpoint-checksum-mismatch"));

    var ctDir = _copyBundle(archiveDir, _freshOut(root, "ckpt-too-large"));
    fs.writeFileSync(path.join(ctDir, "checkpoint.enc"), Buffer.alloc(5242880, 0x62));   // 5 MiB > 4 MiB cap
    check("verifyBundle: oversized checkpoint.enc rejected",
      await _expectCode(function () { return b.auditTools.verifyBundle({ in: ctDir, passphrase: PASS }); }, "audit-tools/checkpoint-too-large"));

    check("verifyBundle: nonexistent bundle dir rejected",
      await _expectCode(function () { return b.auditTools.verifyBundle({ in: path.join(root, "does-not-exist"), passphrase: PASS }); }, "audit-tools/no-bundle"));

    // ---- _defaultReadPredecessorRowHash: ungrounded predecessor throws ----
    check("exportSlice: ungrounded predecessor rejected",
      await _expectCode(function () {
        return b.auditTools.exportSlice({
          out: _freshOut(root, "ungrounded"), passphrase: PASS,
          readRows: function () { return Promise.resolve([Object.assign({}, realRows[0], { monotonicCounter: 999999 })]); },
        });
      }, "audit-tools/no-predecessor"));

    // ---- purge refusal paths (no db mutation) ----
    check("purge: unverified archive rejected",
      await _expectCode(function () { return b.auditTools.purge({ confirm: true, archive: pbDir, passphrase: PASS }); }, "audit-tools/archive-not-ok"));
    check("purge: non-archive bundle kind rejected",
      await _expectCode(function () { return b.auditTools.purge({ confirm: true, archive: exportDir, passphrase: PASS }); }, "audit-tools/wrong-kind"));
    // Signed, so the mismatch below is the reason the purge is refused. An
    // unsigned anchor is now refused one step earlier, which would make this
    // pass without ever reaching the predecessor comparison it exists for.
    var mismatchAnchor = {
      scope:             "audit",
      lastPurgedCounter: firstCounter - 1,
      lastPurgedRowHash: "d".repeat(128),
      archiveBundleId:   "prior-archive",
      purgedAt:          1750000000000,
    };
    mismatchAnchor.signature = b.auditSign.sign(
      b.auditChain.purgeAnchorPayload(mismatchAnchor));
    mismatchAnchor.publicKeyFingerprint = b.auditSign.getPublicKeyFingerprint();
    check("purge: predecessor not matching prior anchor rejected",
      await _expectCode(function () {
        return b.auditTools.purge({
          confirm: true, archive: archiveDir, passphrase: PASS,
          readAnchor: function () { return Promise.resolve(mismatchAnchor); },
          apply: function () { return Promise.resolve({ rowsDeleted: 0, checkpointsDeleted: 0, archiveBundleId: "x" }); },
        });
      }, "audit-tools/anchor-mismatch"));

    // The SAME anchor with only its signature stripped is refused earlier, and
    // for a different reason — extending it would sign whatever boundary it
    // claims, so the check has to run before the comparison, not instead of it.
    var unsignedPrior = Object.assign({}, mismatchAnchor,
      { signature: null, publicKeyFingerprint: null });
    check("purge: an unsigned prior anchor cannot be extended",
      await _expectCode(function () {
        return b.auditTools.purge({
          confirm: true, archive: archiveDir, passphrase: PASS,
          readAnchor: function () { return Promise.resolve(unsignedPrior); },
          apply: function () { return Promise.resolve({ rowsDeleted: 0, checkpointsDeleted: 0, archiveBundleId: "x" }); },
        });
      }, "audit-tools/prior-anchor-not-verified"));

    // ---- dual-control gate refusals + a consumed-grant success (injected apply) ----
    var gate = function () { return { m: 2, n: 3 }; };
    check("purge: dual control without a grant rejected",
      await _expectCode(function () {
        return b.auditTools.purge({ confirm: true, archive: archiveDir, passphrase: PASS, checkDualControlGate: gate });
      }, "audit-tools/dual-control-required"));
    check("purge: not-ready grant rejected",
      await _expectCode(function () {
        return b.auditTools.purge({ confirm: true, archive: archiveDir, passphrase: PASS, checkDualControlGate: gate, dualControlGrant: { ready: false, action: "auditTools.purge" } });
      }, "audit-tools/dual-control-grant-not-ready"));
    check("purge: grant bound to a different action rejected",
      await _expectCode(function () {
        return b.auditTools.purge({ confirm: true, archive: archiveDir, passphrase: PASS, checkDualControlGate: gate, dualControlGrant: { ready: true, action: "db.eraseHard" } });
      }, "audit-tools/dual-control-grant-mismatch"));
    var gateOk = await b.auditTools.purge({
      confirm: true, archive: archiveDir, passphrase: PASS, checkDualControlGate: gate,
      dualControlGrant: { ready: true, action: "auditTools.purge" },
      readAnchor: function () { return Promise.resolve(null); },
      apply: function () { return Promise.resolve({ rowsDeleted: realRows.length, checkpointsDeleted: 1, archiveBundleId: "gid" }); },
    });
    check("purge: consumed dual-control grant proceeds", gateOk.purged === true && gateOk.dualControlConsumed === true);

    // ---- real purge (default anchor read + apply) mutates the chain ----
    var purged = await b.auditTools.purge({ confirm: true, archive: archiveDir, passphrase: PASS });
    check("purge: real purge deletes live rows", purged.purged === true && purged.rowsDeleted > 0);
    check("purge: reports no dual-control consumed (gate not declared)", purged.dualControlConsumed === false);

    // ---- the anchor the real purge wrote is signed, and readable as such ----
    var liveAnchor = await b.clusterStorage.executeOne(
      "SELECT * FROM _blamejs_audit_purge_anchor WHERE scope = 'audit'");
    check("purge: the anchor it wrote carries a signature",
      !!(liveAnchor && liveAnchor.signature && liveAnchor.publicKeyFingerprint));
    check("purge: that anchor verifies",
      b.auditChain.verifyPurgeAnchor(liveAnchor).status === "valid");

    // ---- an anchor tampered with mid-run stops appends ----
    // Boot refuses to start on an anchor it cannot verify; this is the same
    // question for tampering that happens once the process is running. The
    // purge just emptied the table, so the next row's link comes from the
    // anchor rather than from a tip row — exactly when an unbelievable anchor
    // matters. Starting a fresh chain instead would look cautious and be the
    // opposite: the rows would link to nothing and take counters at or below
    // the boundary the anchor claims, where a verifier skips them, so every
    // write between the tampering and the next verification would be invisible
    // to the check meant to catch it.
    var emptyAfterPurge = await b.clusterStorage.executeAll("SELECT * FROM audit_log");
    check("append: the purge left the table empty, so the anchor supplies the link",
      emptyAfterPurge.length === 0, "rows=" + emptyAfterPurge.length);

    await b.clusterStorage.execute(
      "UPDATE _blamejs_audit_purge_anchor SET lastPurgedCounter = " +
      (Number(liveAnchor.lastPurgedCounter) + 3) + " WHERE scope = 'audit'");

    var refusedWrite = null;
    try {
      await b.audit.record({ action: "test.after_tamper", outcome: "success" });
      await b.audit.flush();
    } catch (e) { refusedWrite = e; }
    check("append: a forged anchor stops the write rather than starting over",
      refusedWrite !== null && refusedWrite.code === "audit/purge-anchor-not-verified",
      String(refusedWrite && (refusedWrite.code || refusedWrite.message)));

    var stillEmpty = await b.clusterStorage.executeAll("SELECT * FROM audit_log");
    check("append: and wrote nothing while the anchor was unbelievable",
      stillEmpty.length === 0, "rows=" + stillEmpty.length);

    await b.clusterStorage.execute(
      "UPDATE _blamejs_audit_purge_anchor SET lastPurgedCounter = " +
      Number(liveAnchor.lastPurgedCounter) + " WHERE scope = 'audit'");
    var restoredAnchor = await b.clusterStorage.executeOne(
      "SELECT * FROM _blamejs_audit_purge_anchor WHERE scope = 'audit'");
    check("append: the anchor verifies again once its field is put back",
      b.auditChain.verifyPurgeAnchor(restoredAnchor).status === "valid",
      JSON.stringify(b.auditChain.verifyPurgeAnchor(restoredAnchor)));
    // Assert on the row rather than on flush(): the handler buffers, and the
    // append it failed during the tampered window is still in its retry queue,
    // so flush() surfaces that historical failure regardless of whether a new
    // write succeeds. What matters is that a write attempted AFTER the repair
    // lands.
    await b.audit.record({ action: "test.after_repair", outcome: "success" });
    try { await b.audit.flush(); } catch (_e) { /* the tampered-window failure */ }
    var repairedRows = await b.clusterStorage.executeAll(
      "SELECT * FROM audit_log ORDER BY monotonicCounter ASC");
    check("append: and resumes once the anchor verifies again",
      repairedRows.length > 0, "rows=" + repairedRows.length);
    check("append: the resumed row links to the anchor's boundary hash",
      repairedRows.length > 0 &&
      String(repairedRows[0].prevHash) === String(liveAnchor.lastPurgedRowHash),
      String(repairedRows[0] && repairedRows[0].prevHash));

    // ---- replaying the same bundle is an idempotent retry ----
    // The anchor is written before the rows are deleted, so a deletion that
    // fails leaves the boundary recorded and the rows still present — skipped
    // by verification, and repairable only by re-running this exact archive.
    // Refusing that as non-contiguous, which read literally it is, would make
    // the one repair available the one thing the guard turns away. Replaying
    // an archive whose range the anchor already names deletes rows that are
    // already gone, so there is nothing to gain by it either.
    var anchorBeforeReplay = await b.clusterStorage.executeOne(
      "SELECT * FROM _blamejs_audit_purge_anchor WHERE scope = 'audit'");
    var replay = await b.auditTools.purge({ confirm: true, archive: archiveDir, passphrase: PASS });
    check("purge: replaying the anchored range succeeds as a retry",
      replay.purged === true, JSON.stringify(replay));
    check("purge: and deletes nothing, because there is nothing left to delete",
      replay.rowsDeleted === 0, "rowsDeleted=" + replay.rowsDeleted);
    var anchorAfterReplay = await b.clusterStorage.executeOne(
      "SELECT * FROM _blamejs_audit_purge_anchor WHERE scope = 'audit'");
    check("purge: and leaves the boundary exactly where it was",
      Number(anchorAfterReplay.lastPurgedCounter) === Number(anchorBeforeReplay.lastPurgedCounter) &&
      anchorAfterReplay.lastPurgedRowHash === anchorBeforeReplay.lastPurgedRowHash);

    // The retry allowance is for THIS archive's range, not for any archive
    // that happens to end where it ended. One covering only the tail —
    // ending at the same counter and row hash, starting later — would
    // otherwise pass as a retry, delete everything through the boundary, and
    // leave the rows before its own start with no retained copy anywhere.
    // Properly SIGNED with the wider range, so the signature is not what
    // refuses it — the retry comparison is.
    var widerAnchor = {
      scope:             "audit",
      lastPurgedCounter: Number(anchorAfterReplay.lastPurgedCounter),
      lastPurgedRowHash: String(anchorAfterReplay.lastPurgedRowHash),
      archiveBundleId:   String(anchorAfterReplay.archiveBundleId),
      purgedAt:          Number(anchorAfterReplay.purgedAt),
      firstPurgedCounter: Number(anchorAfterReplay.firstPurgedCounter || 0) + 5,
      fencingToken:      Number(anchorAfterReplay.fencingToken || 0),
    };
    widerAnchor.signature = b.auditSign.sign(
      b.auditChain.purgeAnchorPayload(widerAnchor));
    widerAnchor.publicKeyFingerprint = b.auditSign.getPublicKeyFingerprint();
    check("purge: that anchor is itself valid, so the signature is not the refusal",
      b.auditChain.verifyPurgeAnchor(widerAnchor).status === "valid");

    check("purge: an archive ending at the boundary but starting later is not a retry",
      await _expectCode(function () {
        return b.auditTools.purge({
          confirm: true, archive: archiveDir, passphrase: PASS,
          readAnchor: function () { return Promise.resolve(widerAnchor); },
        });
      }, "audit-tools/non-monotonic-purge"));

    // A DIFFERENT range that does not continue from the boundary is still
    // refused — the retry allowance is for this archive, not for any archive.
    check("purge: a non-contiguous archive is still refused",
      await _expectCode(function () {
        return b.auditTools.purge({
          confirm: true, archive: archiveDir, passphrase: PASS,
          readAnchor: function () {
            return Promise.resolve(Object.assign({}, anchorAfterReplay, {
              lastPurgedCounter: Number(anchorAfterReplay.lastPurgedCounter) + 50,
            }));
          },
        });
      }, "audit-tools/prior-anchor-not-verified"));

    // An anchor written before the range start was recorded carries 0 there.
    // Chain counters begin at 1, so no real range starts at 0 and the value
    // means "unrecorded" rather than "started at zero" — holding it to the
    // archive's start would turn away the retry that finishes an interrupted
    // purge on such a volume, and the contiguity check refuses it too, since
    // the anchor already ends where this archive ends. It gets the end-only
    // match it was written under.
    var noRangeAnchor = Object.assign({}, anchorAfterReplay, { firstPurgedCounter: 0 });
    noRangeAnchor.signature = b.auditSign.sign(
      b.auditChain.purgeAnchorPayload(noRangeAnchor));
    noRangeAnchor.publicKeyFingerprint = b.auditSign.getPublicKeyFingerprint();
    check("purge: an anchor with no recorded range start is itself valid",
      b.auditChain.verifyPurgeAnchor(noRangeAnchor).status === "valid",
      JSON.stringify(b.auditChain.verifyPurgeAnchor(noRangeAnchor)));
    var legacyRetry = await b.auditTools.purge({
      confirm: true, archive: archiveDir, passphrase: PASS,
      readAnchor: function () { return Promise.resolve(noRangeAnchor); },
    });
    check("purge: replaying its archive against it is still a retry",
      legacyRetry.purged === true && legacyRetry.rowsDeleted === 0,
      JSON.stringify(legacyRetry));
    var migratedAnchor = await b.clusterStorage.executeOne(
      "SELECT * FROM _blamejs_audit_purge_anchor WHERE scope = 'audit'");
    check("purge: and the anchor it rewrites records the range start",
      Number(migratedAnchor.firstPurgedCounter) > 0 &&
      b.auditChain.verifyPurgeAnchor(migratedAnchor).status === "valid",
      "firstPurgedCounter=" + migratedAnchor.firstPurgedCounter);

    // ---- an append racing the purge lands on the right side of it ----
    // The delete and the anchor write are two writes. An append between them
    // reads an anchor that is about to be replaced and links to a hash that is
    // about to stop being the boundary, so the row contradicts the anchor the
    // moment the anchor lands — and the next verify calls that tampering.
    // Firing the append without awaiting the purge first is what puts it in
    // that window.
    await _seedAuditRows(3);
    await b.audit.checkpoint();
    var raceDir = _freshOut(root, "race-archive");
    await b.auditTools.archive({ out: raceDir, passphrase: PASS, before: Date.now() });
    // The lock the purge relies on, exercised directly: a second holder must
    // not enter until the first leaves. Racing a real append against a real
    // purge and asserting the outcome proves nothing when it passes, because
    // nothing makes the append land in the window; this asserts the property
    // the purge composes instead of hoping to observe its absence.
    var lockOrder = [];
    var releaseFirst;
    var firstHeld = new Promise(function (resolve) { releaseFirst = resolve; });
    var firstDone = b.audit.withChainLock(function () {
      lockOrder.push("first-in");
      return firstHeld.then(function () { lockOrder.push("first-out"); });
    });
    // Queued behind the holder above, so it cannot run until that resolves.
    var secondDone = b.audit.withChainLock(function () { lockOrder.push("second-in"); });
    await helpers.passiveObserve(200, "audit chain lock: second holder stays out");
    check("audit.withChainLock excludes a second holder",
      lockOrder.join(",") === "first-in", lockOrder.join(","));
    releaseFirst();
    await Promise.all([firstDone, secondDone]);
    check("audit.withChainLock admits it once the first releases",
      lockOrder.join(",") === "first-in,first-out,second-in", lockOrder.join(","));

    // Only the node that appends may purge. Appends already require
    // leadership, so a purge running anywhere else would put two writers of
    // one chain on different nodes, where this process's mutex orders neither
    // of them — two nodes could delete different ranges and each overwrite the
    // other's boundary, leaving a signed anchor that accounts for only part of
    // what was removed.
    var realRequireLeader = b.cluster.requireLeader;
    b.cluster.requireLeader = function () {
      throw new b.cluster.NotLeaderError("node 'test' is not currently leader");
    };
    var notLeader = null;
    try {
      await b.auditTools.purge({ confirm: true, archive: raceDir, passphrase: PASS });
    } catch (e) { notLeader = e; }
    b.cluster.requireLeader = realRequireLeader;
    check("purge: a node that is not the leader is refused",
      notLeader !== null && /not currently leader/.test(notLeader.message || ""),
      String(notLeader && notLeader.message));

    var stillThere = await b.clusterStorage.executeAll("SELECT * FROM audit_log");
    check("purge: and it deleted nothing on the way to that refusal",
      stillThere.length > 0, "rows=" + stillThere.length);

    // Leadership does not serialize the purge across processes: a superseded
    // leader still holds a working handle, and during a handoff two nodes can
    // both believe they hold it. The stored fencing token is the only thing
    // that can say whose turn it is, so a write carrying a lower one has to be
    // refused by the database rather than by agreement between processes.
    // Signed with the high token, not merely edited to carry one: the token is
    // part of the signed bytes now, so editing it alone is caught as a forgery
    // one step earlier and the fence would never be reached. This is what a
    // genuine successor's anchor looks like.
    var highAnchor = await b.clusterStorage.executeOne(
      "SELECT * FROM _blamejs_audit_purge_anchor WHERE scope = 'audit'");
    var highSigned = {
      scope:             "audit",
      lastPurgedCounter: Number(highAnchor.lastPurgedCounter),
      lastPurgedRowHash: String(highAnchor.lastPurgedRowHash),
      archiveBundleId:   String(highAnchor.archiveBundleId),
      purgedAt:          Number(highAnchor.purgedAt),
      // Every signed field has to be the row's own, including the range
      // start — signing a different one produces a valid signature over an
      // anchor nobody stored.
      firstPurgedCounter: Number(highAnchor.firstPurgedCounter || 0),
      archiveRowsDigest: highAnchor.archiveRowsDigest,
      archiveCheckpointDigest: highAnchor.archiveCheckpointDigest,
      fencingToken:      9999,
    };
    var highSig = b.auditSign.sign(b.auditChain.purgeAnchorPayload(highSigned));
    await b.clusterStorage.execute(
      "UPDATE _blamejs_audit_purge_anchor SET fencingToken = 9999, signature = ? " +
      "WHERE scope = 'audit'", [highSig]);
    check("purge: an anchor signed under a higher token verifies",
      b.auditChain.verifyPurgeAnchor(await b.clusterStorage.executeOne(
        "SELECT * FROM _blamejs_audit_purge_anchor WHERE scope = 'audit'")).status === "valid");

    var fencedOut = null;
    try {
      await b.auditTools.purge({ confirm: true, archive: raceDir, passphrase: PASS });
    } catch (e) { fencedOut = e; }
    check("purge: a write below the stored fencing token is refused",
      fencedOut !== null && fencedOut.code === "audit-tools/fenced-out",
      String(fencedOut && (fencedOut.code || fencedOut.message)));
    var survivedFence = await b.clusterStorage.executeAll("SELECT * FROM audit_log");
    check("purge: and it refused before deleting anything",
      survivedFence.length > 0, "rows=" + survivedFence.length);
    // Put the anchor back the way it was, signature included — leaving the
    // token high with the old signature would be a forged row, not a restored
    // one, and every later check would trip on that instead.
    var restored = Object.assign({}, highSigned, { fencingToken: 0 });
    var restoredSig = b.auditSign.sign(b.auditChain.purgeAnchorPayload(restored));
    await b.clusterStorage.execute(
      "UPDATE _blamejs_audit_purge_anchor SET fencingToken = 0, signature = ? " +
      "WHERE scope = 'audit'", [restoredSig]);

    // Two purges of the same bundle, started together. The contiguity check
    // reads the anchor and the write replaces it; if those are not one
    // decision, both read the same anchor, both believe themselves contiguous,
    // and the second overwrites the first's boundary with one that would have
    // been refused.
    //
    // Both calls settle successfully — the second names the range the first
    // just anchored, which is the retry path — so the invariant is not "one
    // fails" but that the range is deleted ONCE and the boundary is the
    // archive's, not something built by the two of them interleaving.
    //
    // This asserts the outcome; it does not force the interleaving, and it
    // passes with the locking removed because the two calls happen to
    // serialize on their own. The mutual exclusion the purge composes is
    // proven above, on the lock itself.
    var both = await Promise.allSettled([
      b.auditTools.purge({ confirm: true, archive: raceDir, passphrase: PASS }),
      b.auditTools.purge({ confirm: true, archive: raceDir, passphrase: PASS }),
    ]);
    var settled = both.filter(function (r) { return r.status === "fulfilled"; });
    check("purge: two overlapping purges of one archive both settle",
      settled.length === 2,
      JSON.stringify(both.map(function (r) {
        return r.status === "rejected" ? String(r.reason && r.reason.code) : "ok";
      })));
    var deleters = settled.filter(function (r) { return r.value.rowsDeleted > 0; });
    check("purge: and exactly one of them deleted the range",
      deleters.length === 1,
      settled.map(function (r) { return r.value.rowsDeleted; }).join(","));
    var raceAnchor = await b.clusterStorage.executeOne(
      "SELECT * FROM _blamejs_audit_purge_anchor WHERE scope = 'audit'");
    check("purge: and the boundary is the archive's, not an interleaved one",
      Number(raceAnchor.lastPurgedCounter) === Number(settled[0].value.lastPurgedCounter),
      "anchor=" + raceAnchor.lastPurgedCounter +
      " archive=" + settled[0].value.lastPurgedCounter);

    await b.audit.record({ action: "test.after_purge_race", outcome: "success" });
    await b.audit.flush();
    var raceVerify = await b.audit.verify();
    check("purge: the chain still verifies after the contended purge",
      raceVerify.ok === true, JSON.stringify(raceVerify));

    // ---- restart on the purged volume, before anything is recorded again ----
    // The purge left audit_log empty. Two startup paths have to consult the
    // anchor to get this right: the chain verify needs the signing key already
    // loaded to check its signature at all, and the counter is derived from
    // MAX(monotonicCounter), which an empty table answers with nothing.
    // Restarting at 1 puts every new row at or below the purge boundary, where
    // verifyChain skips it — the rows would be recorded, look linked, and be
    // silently excluded from every verification of this chain. Nothing reports
    // that, which makes it worse than a break.
    // From the anchor as it now stands — the race block purged again, so the
    // boundary has moved past what the first purge returned.
    var liveBoundary = await b.clusterStorage.executeOne(
      "SELECT * FROM _blamejs_audit_purge_anchor WHERE scope = 'audit'");
    var boundary     = Number(liveBoundary.lastPurgedCounter);
    var boundaryHash = String(liveBoundary.lastPurgedRowHash);
    var reopened = null;
    try { await helpers.reopenTestDb(dir); }
    catch (e) { reopened = e; }
    check("restart: a volume with a signed purge anchor re-opens",
      reopened === null, reopened && (reopened.code || reopened.message));

    var survived = await b.clusterStorage.executeOne(
      "SELECT * FROM _blamejs_audit_purge_anchor WHERE scope = 'audit'");
    check("restart: the signed anchor is still there afterwards",
      !!(survived && survived.signature),
      "the reopen must load the SAME volume, not a fresh one");

    // ---- _defaultReadPredecessorRowHash anchor branch: predecessor purged ----
    await _seedAuditRows(2);

    var afterRestart = await b.clusterStorage.executeAll(
      "SELECT * FROM audit_log ORDER BY monotonicCounter ASC");
    check("restart: the first row recorded afterwards clears the purge boundary",
      afterRestart.length > 0 && Number(afterRestart[0].monotonicCounter) > boundary,
      "boundary=" + boundary + " first=" +
        (afterRestart[0] && afterRestart[0].monotonicCounter));
    check("restart: and links to the hash the purge recorded",
      afterRestart.length > 0 && String(afterRestart[0].prevHash) === boundaryHash,
      String(afterRestart[0] && afterRestart[0].prevHash));

    var afterRestartVerify = await b.audit.verify();
    check("restart: the chain verifies over the purge",
      afterRestartVerify.ok === true, JSON.stringify(afterRestartVerify));
    check("restart: and the verify names the anchor it relied on",
      !!(afterRestartVerify.purgeAnchor &&
         afterRestartVerify.purgeAnchor.signatureVerified === true &&
         afterRestartVerify.purgeAnchor.belowCounter === boundary),
      JSON.stringify(afterRestartVerify.purgeAnchor));
    var postRows = await b.clusterStorage.executeAll("SELECT * FROM audit_log ORDER BY monotonicCounter ASC");
    if (postRows.length) {
      var pDir = _freshOut(root, "post-purge");
      var postExp = await b.auditTools.exportSlice({
        out: pDir, passphrase: PASS,
        readRows: function () { return Promise.resolve(postRows); },
      });
      // The predecessor for a slice whose first row sits right after a purged
      // range resolves through the purge anchor's lastPurgedRowHash rather than
      // a (now-deleted) predecessor row — the branch under test here.
      check("exportSlice: predecessor resolves via the purge anchor",
        postExp.manifest.range.predecessorRowHash === boundaryHash,
        postExp.manifest.range.predecessorRowHash);
      // A purge that empties audit_log does not start a new chain. Rows
      // recorded afterwards link to the hash the purge anchor recorded, so a
      // slice of them walks continuously from that predecessor. Restarting at
      // ZERO_HASH here produced a bundle that reported a prevHash mismatch —
      // a chain break at the exact point the framework itself deleted rows,
      // which then refused the next boot.
      var okPost = await b.auditTools.verifyBundle({ in: pDir, passphrase: PASS });
      check("verifyBundle: post-purge rows continue the chain from the anchor",
        okPost.ok === true, JSON.stringify(okPost && okPost.reason));
      check("and the first of them links to the anchor's boundary hash",
        String(postRows[0].prevHash) === boundaryHash,
        String(postRows[0].prevHash));
    }

    // ---- and again, now that rows sit ABOVE the boundary ----
    // The first restart happened on an empty table. This one has the resumed
    // rows in it, so the audit tip sidecar records a counter above the purge
    // boundary and the rollback guard has to accept a table whose maximum
    // matches it — the ordinary steady state after a purge, which is the state
    // an operator's every subsequent restart is in.
    var restarted = null;
    try { await helpers.reopenTestDb(dir); }
    catch (e) { restarted = e; }
    check("restart: re-opens again with rows recorded past the boundary",
      restarted === null, restarted && (restarted.code || restarted.message));


    // ---- turning signing off does not strand a volume that used it ----
    // `auditSigning: false` is a supported posture, and it skips loading a
    // key. A volume purged while signing was ON still has a SIGNED anchor, and
    // with no key loaded its fingerprint resolves to nothing — which reads as
    // "could not check", which refuses the boot. The operator would have
    // turned off a feature and lost the volume.
    var signingOffErr = null;
    try {
      await helpers.reopenTestDb(dir, undefined, { auditSigning: false });
    } catch (e) { signingOffErr = e; }
    check("boot: a signed volume re-opens with auditSigning turned off",
      signingOffErr === null, String(signingOffErr && signingOffErr.message).slice(0, 200));

    var offVerify = await b.audit.verify({ allowUncheckedPurgeAnchor: true });
    check("boot: and the verify says the signature was NOT checked",
      offVerify.ok === true && offVerify.purgeAnchor &&
      offVerify.purgeAnchor.signatureVerified === false,
      JSON.stringify(offVerify.purgeAnchor));

    // The rollback guard is asked the same question — which rows may be
    // missing — and gets its answer from the verify above rather than working
    // it out again. Deriving it twice is how the two ended up disagreeing:
    // the verify accepted this volume and the guard then refused to boot it,
    // because it had no key of its own and read the anchor as uncheckable.
    // The boot above completing IS that check; assert the boundary it used.
    check("boot: the rollback guard used the boundary the verify established",
      Number(offVerify.purgeAnchor.belowCounter) === boundary,
      "guard=" + offVerify.purgeAnchor.belowCounter + " boundary=" + boundary);

    // Booting is not enough: the append path asks the same question on every
    // row it writes. A volume that boots and then refuses every audit write is
    // worse than one that refuses to boot, because the refusal arrives as lost
    // audit rows on a running server rather than as a startup failure.
    b.audit.registerNamespace("test");
    var offWrite = null;
    try {
      await b.audit.record({ action: "test.signing_off", outcome: "success" });
      await b.audit.flush();
    } catch (e) { offWrite = e; }
    check("boot: and appends keep working with signing off",
      offWrite === null, String(offWrite && (offWrite.code || offWrite.message)));

    // The operations that run AFTER boot ask the same question, and each one
    // that works the answer out for itself will eventually disagree with the
    // boot that let the process start — the volume is then accepted at startup
    // and refused an hour later by the next archive or purge. Exporting a
    // slice grounds its proof on the anchor, so it exercises that path.
    var offSliceDir = _freshOut(root, "signing-off-slice");
    var offRows = await b.clusterStorage.executeAll(
      "SELECT * FROM audit_log ORDER BY monotonicCounter ASC");
    var offSliceErr = null;
    if (offRows.length) {
      try {
        await b.auditTools.exportSlice({
          out: offSliceDir, passphrase: PASS,
          readRows: function () { return Promise.resolve(offRows); },
        });
      } catch (e) { offSliceErr = e; }
    }
    check("boot: and an export still grounds itself on the same anchor",
      offSliceErr === null, String(offSliceErr && (offSliceErr.code || offSliceErr.message)));

    // The check above reports "not verified" only because a key that was never
    // rotated is not in the history at all. Plant one and the old fallback had
    // something to find — which is the actual hole: with signing off there is
    // no loaded key, the history is UNSEALED so a passphrase-less reader can
    // use it, and adding a self-consistent entry for a keypair you generated
    // needs no secret. An attacker who can write the audit store can write
    // that file too, so a key resolved from it licensing deleted rows is the
    // attacker vouching for themselves.
    await helpers.reopenTestDb(dir);
    var plantedPair = nodeCrypto.generateKeyPairSync("ml-dsa-65", {
      publicKeyEncoding:  { type: "spki",  format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    var plantedFp = b.auditSign.fingerprintOf(plantedPair.publicKey);
    var victimAnchor = await b.clusterStorage.executeOne(
      "SELECT * FROM _blamejs_audit_purge_anchor WHERE scope = 'audit'");
    var plantedSig = nodeCrypto.sign(null,
      b.auditChain.purgeAnchorPayload(victimAnchor),
      nodeCrypto.createPrivateKey(plantedPair.privateKey));
    await b.clusterStorage.execute(
      "UPDATE _blamejs_audit_purge_anchor SET publicKeyFingerprint = ?, signature = ? " +
      "WHERE scope = 'audit'", [plantedFp, plantedSig]);
    var histFile = path.join(dir, "audit-sign.pubkeys.json");
    var priorHist = fs.existsSync(histFile) ? fs.readFileSync(histFile, "utf8") : null;
    var plantedList = priorHist ? JSON.parse(priorHist) : [];
    plantedList.push({ fingerprint: plantedFp, publicKey: plantedPair.publicKey });
    fs.writeFileSync(histFile, JSON.stringify(plantedList));
    await b.db.close();

    await helpers.reopenTestDb(dir, undefined, { auditSigning: false });
    // What makes the planted key dangerous, shown rather than asserted: a
    // resolver that reads the history DOES accept it, because the entry is
    // self-consistent and the signature is real. Nothing about the anchor can
    // tell this from a legitimate one.
    var historyResolver = function (fp) {
      return b.auditSign.publicKeyFromHistory(dir, fp);
    };
    var wouldAccept = b.auditChain.verifyPurgeAnchor(
      await b.clusterStorage.executeOne(
        "SELECT * FROM _blamejs_audit_purge_anchor WHERE scope = 'audit'"),
      { resolvePublicKey: historyResolver });
    check("signing off: a history-reading resolver would accept the planted key",
      wouldAccept.status === "valid", JSON.stringify(wouldAccept));

    // So the deployment no longer installs one. With signing off and no key
    // named by the operator, there is no resolver at all: the anchor reports
    // as unchecked, which allowUnchecked permits, and nothing claims a proof
    // that was never made.
    var offPolicy = b.audit.getPurgeAnchorPolicy();
    check("signing off: the deployment installs no history-reading resolver",
      offPolicy.resolvePublicKey === undefined,
      String(typeof offPolicy.resolvePublicKey));
    check("signing off: and permits the unchecked verdict that follows",
      offPolicy.allowUnchecked === true);
    var planted = await b.audit.verify({ allowUncheckedPurgeAnchor: true });
    check("signing off: a key planted in the unsealed history does not license the gap",
      planted.purgeAnchor && planted.purgeAnchor.signatureVerified === false,
      JSON.stringify(planted.purgeAnchor));

    // The capability is not lost, only its false authority: an operator who
    // wants the anchor genuinely verified in this posture names the key
    // themselves. That is a trust root they chose rather than one the volume
    // supplied, and it is still bound to the fingerprint the anchor names.
    await b.db.close();
    await helpers.reopenTestDb(dir, undefined, {
      auditSigning: false, purgeAnchorPublicKey: plantedPair.publicKey,
    });
    var pinnedPolicy = b.audit.getPurgeAnchorPolicy();
    check("signing off: a pinned key becomes the deployment's anchor resolver",
      typeof pinnedPolicy.resolvePublicKey === "function");
    check("signing off: and it answers for the fingerprint the anchor names",
      pinnedPolicy.resolvePublicKey(plantedFp) ===
        b.auditSign.canonicalPublicKeyPem(plantedPair.publicKey));
    check("signing off: and for no other, so a pinned key cannot answer for one it is not",
      pinnedPolicy.resolvePublicKey("0".repeat(128)) === null);
    // A key an earlier version ingested as written was fingerprinted over that
    // exact text, so pinning it must resolve the spelling the anchor names —
    // canonicalizing alone would discard the only fingerprint that matches.
    var crlfPinned = plantedPair.publicKey.replace(/\n/g, "\r\n");
    var crlfFp = b.auditSign.fingerprintOf(crlfPinned);
    var crlfResolver = b.auditSign.pinnedKeyResolver(crlfPinned);
    check("signing off: pinning a CRLF-spelled key resolves the as-written fingerprint",
      crlfFp !== plantedFp && crlfResolver(crlfFp) === crlfPinned,
      "crlf=" + String(crlfResolver(crlfFp)).slice(0, 32));
    check("signing off: and the canonical fingerprint of the same key too",
      crlfResolver(plantedFp) === b.auditSign.canonicalPublicKeyPem(crlfPinned));
    var pinnedVerify = await b.audit.verify({ resolvePublicKey: pinnedPolicy.resolvePublicKey });
    check("signing off: a pinned key the operator supplies does verify it",
      pinnedVerify.purgeAnchor && pinnedVerify.purgeAnchor.signatureVerified === true,
      JSON.stringify(pinnedVerify.purgeAnchor));

    // Put the anchor back under the volume's own key before the rest of the
    // file runs against a signing deployment.
    await b.db.close();
    await helpers.reopenTestDb(dir, undefined, { acceptRotatedPurgeAnchorKey: true });
    var reownedAnchor = await b.clusterStorage.executeOne(
      "SELECT * FROM _blamejs_audit_purge_anchor WHERE scope = 'audit'");
    check("signing off: the volume is repairable back to its own key",
      b.auditChain.verifyPurgeAnchor(reownedAnchor).status === "valid",
      JSON.stringify(b.auditChain.verifyPurgeAnchor(reownedAnchor)));
    if (priorHist !== null) fs.writeFileSync(histFile, priorHist);

    // ---- boot refuses a boundary whose archive is gone ----
    // A signature proves the framework wrote the boundary; it says nothing
    // about whether the archive named still exists. Only the operator knows
    // where bundles live, so they supply the check — and a boundary whose
    // archive has gone is a gap nothing can ever show the contents of.
    var asked = [];
    var bootRefused = null;
    try {
      await helpers.reopenTestDb(dir, undefined, {
        resolvePurgeArchive: function (id) { asked.push(id); return false; },
      });
    } catch (e) { bootRefused = e; }
    check("boot: an archive the operator cannot produce refuses the boot",
      bootRefused !== null && /audit_log chain integrity/.test(bootRefused.message || ""),
      String(bootRefused && bootRefused.message).slice(0, 160));
    check("boot: and the check was asked about the anchor's own archive id",
      asked.length > 0, JSON.stringify(asked));

    // The same volume opens when the archive is producible, and says so.
    var bootOk = null;
    try {
      await helpers.reopenTestDb(dir, undefined, {
        resolvePurgeArchive: function () { return true; },
      });
    } catch (e) { bootOk = e; }
    check("boot: a producible archive lets the same volume open",
      bootOk === null, String(bootOk && bootOk.message).slice(0, 160));

    // ---- the upgrade path, end to end ----
    // An installation purged by a version that did not sign anchors has
    // exactly the row below. It cannot re-run the purge to produce a signed
    // one: the contiguity guard requires an archive starting one counter past
    // the recorded boundary, and the boundary is what is in question. So the
    // recovery has to work on the anchor that is already there.
    await b.clusterStorage.execute(
      "UPDATE _blamejs_audit_purge_anchor SET signature = NULL, " +
      "publicKeyFingerprint = NULL WHERE scope = 'audit'");
    var unsignedAnchor = await b.clusterStorage.executeOne(
      "SELECT * FROM _blamejs_audit_purge_anchor WHERE scope = 'audit'");
    check("upgrade: the pre-signing anchor is refused",
      b.auditChain.verifyPurgeAnchor(unsignedAnchor).status === "unsigned");

    var pinned = await b.auditTools.signExistingPurgeAnchor();
    check("upgrade: signing it reports what it pinned",
      pinned.signed === true &&
      pinned.lastPurgedCounter === Number(unsignedAnchor.lastPurgedCounter),
      JSON.stringify(pinned));

    var repaired = await b.clusterStorage.executeOne(
      "SELECT * FROM _blamejs_audit_purge_anchor WHERE scope = 'audit'");
    check("upgrade: the repaired anchor verifies",
      b.auditChain.verifyPurgeAnchor(repaired).status === "valid");
    check("upgrade: and still names the same boundary it always did",
      Number(repaired.lastPurgedCounter) === Number(unsignedAnchor.lastPurgedCounter) &&
      repaired.lastPurgedRowHash === unsignedAnchor.lastPurgedRowHash);

    // Running it again is a no-op rather than a re-sign, so an operator who
    // leaves the flag set does not keep rewriting the row.
    var again = await b.auditTools.signExistingPurgeAnchor();
    check("upgrade: a second run does nothing",
      again.signed === false && /already signed/.test(again.reason), JSON.stringify(again));

    // It pins; it does not launder. An anchor whose signature is present but
    // does not verify is a tampered anchor, and converting that into a valid
    // signature would make a detectable problem permanent.
    await b.clusterStorage.execute(
      "UPDATE _blamejs_audit_purge_anchor SET lastPurgedCounter = " +
      (Number(repaired.lastPurgedCounter) + 5) + " WHERE scope = 'audit'");
    check("upgrade: a tampered anchor is refused, not pinned",
      await _expectCode(function () { return b.auditTools.signExistingPurgeAnchor(); },
        "audit-tools/anchor-not-signable"));
    await b.clusterStorage.execute(
      "UPDATE _blamejs_audit_purge_anchor SET lastPurgedCounter = " +
      Number(repaired.lastPurgedCounter) + " WHERE scope = 'audit'");

    // ---- a rotated-out key cannot license deleted rows ----
    // The rotated-key history is UNSEALED, because a verifier holding no
    // passphrase has to resolve the key that signed a checkpoint before a
    // rotation. Making each entry hash to its own label stops one key being
    // filed under another's name, but it cannot make the file authoritative:
    // generating a keypair and adding a self-consistent entry for it needs no
    // secret at all. So an attacker who can write the audit store — the very
    // attacker the signature exists to stop — could mint a key, file it, and
    // sign any boundary they liked. A key that has been rotated out is
    // therefore no longer good enough for the one claim that erases rows.
    var liveBefore = b.auditSign.getPublicKeyFingerprint();
    var anchorNow = await b.clusterStorage.executeOne(
      "SELECT * FROM _blamejs_audit_purge_anchor WHERE scope = 'audit'");
    check("rotation: the anchor is valid under the key that signed it",
      b.auditChain.verifyPurgeAnchor(anchorNow).status === "valid" &&
      String(anchorNow.publicKeyFingerprint) === liveBefore);

    process.env.BLAMEJS_AUDIT_SIGNING_PASSPHRASE = "blamejs-test-passphrase-not-secret";
    var rotated = await b.auditSign.rotateSigningKey();
    check("rotation: the live key changed", rotated.newFingerprint !== liveBefore);
    check("rotation: and the old key is still resolvable from the history",
      b.auditSign.getPublicKeyByFingerprint(liveBefore) !== null);

    var afterRotation = b.auditChain.verifyPurgeAnchor(anchorNow);
    check("rotation: the anchor no longer licenses the gap",
      afterRotation.status === "rotated-key", JSON.stringify(afterRotation));
    check("rotation: and is not called a forgery, because it is not one",
      afterRotation.status !== "forged" &&
      /rotated out/.test(afterRotation.reason || ""),
      String(afterRotation.reason));

    // Refusing it is only half an answer: rotating a key is a normal operation
    // and every existing anchor names the old one, so the repair has to exist.
    var reSigned = await b.auditTools.signExistingPurgeAnchor();
    check("rotation: the anchor can be re-signed under the live key",
      reSigned.signed === true, JSON.stringify(reSigned));
    var reAnchored = await b.clusterStorage.executeOne(
      "SELECT * FROM _blamejs_audit_purge_anchor WHERE scope = 'audit'");
    check("rotation: and verifies again, under the new key",
      b.auditChain.verifyPurgeAnchor(reAnchored).status === "valid" &&
      String(reAnchored.publicKeyFingerprint) === rotated.newFingerprint,
      JSON.stringify(b.auditChain.verifyPurgeAnchor(reAnchored)));
    check("rotation: the boundary it names did not move",
      Number(reAnchored.lastPurgedCounter) === Number(anchorNow.lastPurgedCounter) &&
      reAnchored.lastPurgedRowHash === anchorNow.lastPurgedRowHash);

    // An anchor written before a signed field joined the payload AND since
    // rotated is the pair this repair exists for: the read path recognises the
    // older layout, so if the repair recognised fewer it would refuse to fix
    // the exact anchor the read path was written to rescue — leaving a volume
    // that can neither boot nor be repaired. Re-created here by blanking the
    // fields a pre-0.18.58 anchor did not carry and re-signing under the older
    // layout, then rotating the key out from under it.
    var legacySigner = b.auditSign.getPublicKeyFingerprint();
    var legacyPayload = b.auditChain.purgeAnchorPayload(
      { lastPurgedCounter: Number(reAnchored.lastPurgedCounter),
        lastPurgedRowHash: reAnchored.lastPurgedRowHash,
        archiveBundleId:   String(reAnchored.archiveBundleId),
        purgedAt:          Number(reAnchored.purgedAt),
        firstPurgedCounter: 0, archiveRowsDigest: "", archiveCheckpointDigest: "" },
      { layout: "no-range" });
    await b.clusterStorage.execute(
      "UPDATE _blamejs_audit_purge_anchor SET firstPurgedCounter = 0, archiveRowsDigest = '', " +
      "archiveCheckpointDigest = '', signature = ?, publicKeyFingerprint = ? WHERE scope = 'audit'",
      [b.auditSign.sign(legacyPayload), legacySigner]);
    var legacyRow = await b.clusterStorage.executeOne(
      "SELECT * FROM _blamejs_audit_purge_anchor WHERE scope = 'audit'");
    check("legacy layout: the older payload still verifies before rotation",
      b.auditChain.verifyPurgeAnchor(legacyRow).status === "valid",
      JSON.stringify(b.auditChain.verifyPurgeAnchor(legacyRow)));

    process.env.BLAMEJS_AUDIT_SIGNING_PASSPHRASE = "blamejs-test-passphrase-not-secret";
    var afterLegacyRot = await b.auditSign.rotateSigningKey();
    check("legacy layout: rotating leaves it rotated-key, not forged",
      b.auditChain.verifyPurgeAnchor(legacyRow).status === "rotated-key",
      JSON.stringify(b.auditChain.verifyPurgeAnchor(legacyRow)));
    var legacyRepair = await b.auditTools.signExistingPurgeAnchor();
    check("legacy layout: and the repair re-signs it rather than calling it unsignable",
      legacyRepair.signed === true, JSON.stringify(legacyRepair));
    var legacyReAnchored = await b.clusterStorage.executeOne(
      "SELECT * FROM _blamejs_audit_purge_anchor WHERE scope = 'audit'");
    check("legacy layout: repaired under the live key, boundary unmoved",
      b.auditChain.verifyPurgeAnchor(legacyReAnchored).status === "valid" &&
      String(legacyReAnchored.publicKeyFingerprint) === afterLegacyRot.newFingerprint &&
      Number(legacyReAnchored.lastPurgedCounter) === Number(reAnchored.lastPurgedCounter),
      JSON.stringify(b.auditChain.verifyPurgeAnchor(legacyReAnchored)));

    // Rotating and re-signing are two calls, so a process can exit between
    // them — and the repair needs a booted database, which is exactly what the
    // refused anchor prevents. Without a way in from boot itself the documented
    // recovery sits behind the door it cannot open. Rotating again and NOT
    // re-signing puts the volume in that state.
    process.env.BLAMEJS_AUDIT_SIGNING_PASSPHRASE = "blamejs-test-passphrase-not-secret";
    var secondRot = await b.auditSign.rotateSigningKey();
    check("interrupted rotation: the live key moved again",
      secondRot.newFingerprint !== rotated.newFingerprint);
    await b.db.close();

    var strandedErr = null;
    try { await helpers.reopenTestDb(dir); }
    catch (e) { strandedErr = e; }
    check("interrupted rotation: a plain reopen refuses the volume",
      strandedErr !== null, String(strandedErr && strandedErr.message).slice(0, 120));

    // The flag is the operator saying they performed the rotation. It is not
    // automatic, because the evidence that the anchor verifies under the old
    // key comes from the unsealed history, and re-signing on that alone would
    // launder a planted key into the live one.
    var recovered = null;
    try {
      await helpers.reopenTestDb(dir, undefined, { acceptRotatedPurgeAnchorKey: true });
      recovered = await b.clusterStorage.executeOne(
        "SELECT * FROM _blamejs_audit_purge_anchor WHERE scope = 'audit'");
    } catch (e) { recovered = e; }
    check("interrupted rotation: the one-boot flag repairs it",
      recovered !== null && !(recovered instanceof Error) &&
      String(recovered.publicKeyFingerprint) === secondRot.newFingerprint,
      String(recovered && (recovered.message || recovered.publicKeyFingerprint)));
    check("interrupted rotation: and the boundary is unchanged",
      recovered && Number(recovered.lastPurgedCounter) === Number(reAnchored.lastPurgedCounter));
    check("interrupted rotation: the volume opens normally afterwards",
      b.auditChain.verifyPurgeAnchor(recovered).status === "valid",
      JSON.stringify(b.auditChain.verifyPurgeAnchor(recovered)));

    // The re-sign is not a laundry either. An anchor that names a rotated key
    // but does not verify under it has been tampered with, and pinning that
    // under the live key would make a detectable problem permanent.
    await b.clusterStorage.execute(
      "UPDATE _blamejs_audit_purge_anchor SET publicKeyFingerprint = '" + liveBefore +
      "', lastPurgedCounter = " + (Number(reAnchored.lastPurgedCounter) + 7) +
      " WHERE scope = 'audit'");
    check("rotation: a tampered anchor naming the rotated key is refused",
      await _expectCode(function () { return b.auditTools.signExistingPurgeAnchor(); },
        "audit-tools/anchor-not-signable"));
    await b.clusterStorage.execute(
      "UPDATE _blamejs_audit_purge_anchor SET publicKeyFingerprint = '" +
      rotated.newFingerprint + "', lastPurgedCounter = " +
      Number(reAnchored.lastPurgedCounter) + " WHERE scope = 'audit'");

    // ---- teardown, then verify without a live signer: default verifier
    // catches the un-initialized audit-sign keypair and reports not-ok. ----
    await teardownTestDb(dir);
    tornDown = true;
    var noSigner = await b.auditTools.verifyBundle({ in: exportDir, passphrase: PASS });
    check("verifyBundle: export still verifies with no live signer", noSigner.ok === true);
  } finally {
    if (!tornDown) { try { await teardownTestDb(dir); } catch (_e) {} }
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) {}
  }
}

async function run() {
  var root = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-at-"));
  try {
    await runInputValidation(root);
    await runReaderInjectedErrors(root);
    await runCadfMapping();
    await runForensicSuccess(root);
    runWithRecordedAtIso();
    await runIntegrated(root);
  } finally {
    try { fs.rmSync(root, { recursive: true, force: true }); } catch (_e) {}
  }
  console.log("OK — audit-tools tests");
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { process.exit(0); })
       .catch(function (err) { process.exitCode = 1; throw err; });
}
