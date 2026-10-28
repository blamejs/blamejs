// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
// SMOKE_RUN_SOLO: growth checks here compare wall-clock time across input contents and sizes, which a CPU shared with the smoke pool distorts.
"use strict";
/**
 * Layer 0 — b.archive read substrate + safe-extract orchestrator +
 * guard-archive policy builders + b.guardFilename.verifyExtractionPath
 * + b.backup.bundleAdapterStorage.
 *
 * Round-trip coverage: write a ZIP via the existing write side, read
 * it back via b.archive.read.zip (random-access buffer adapter), extract
 * via b.safeArchive.extract into a quarantine directory, verify file
 * contents. Refusal coverage: zip-slip entry name, oversize entries,
 * NUL byte, PATH_MAX overflow.
 */

var helpers = require("../helpers");
var check = helpers.check;
var b = helpers.b;
var os = require("node:os");
var path = require("node:path");
var fs = require("node:fs");
var zlib = require("node:zlib");
var nodeStream = require("node:stream");
var C = require("../../lib/constants");

async function testRoundTripExtract() {
  var z = b.archive.zip();
  z.addFile("readme.txt", "Hello, archive-read!\n");
  z.addFile("data/numbers.csv", "n,sq\n1,1\n2,4\n3,9\n");
  z.addFile("docs/nested/deep.txt", Buffer.from("payload\n"));
  var bytes = z.toBuffer();

  // Inspect via buffer adapter — verifies adapter contract + EOCD walk +
  // CD-walk + LFH/CD skew check.
  var reader = b.archive.read.zip(b.archive.adapters.buffer(bytes));
  var entries = await reader.inspect();
  check("archive.read.zip.inspect: 3 entries",         entries.length === 3);
  check("archive.read.zip.inspect: name + size",        entries[0].name === "readme.txt" && entries[0].size === 21);
  check("archive.read.zip.inspect: nested name",        entries[2].name === "docs/nested/deep.txt");

  // Extract via safeArchive orchestrator.
  var dest = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-archive-test-"));
  try {
    var result = await b.safeArchive.extract({
      source:       bytes,
      destination:  dest,
      guardProfile: "balanced",
    });
    check("safeArchive.extract: 3 entries written",      result.entries.length === 3);
    check("safeArchive.extract: format=zip",             result.format === "zip");
    var readme = fs.readFileSync(path.join(dest, "readme.txt"), "utf8");
    check("safeArchive.extract: readme contents match",  readme === "Hello, archive-read!\n");
    var nested = fs.readFileSync(path.join(dest, "docs/nested/deep.txt"), "utf8");
    check("safeArchive.extract: nested file restored",   nested === "payload\n");
  } finally {
    fs.rmSync(dest, { recursive: true, force: true });
  }
}

function testSafeArchiveErrorClass() {
  // Sanity-check that the typed-error class is exported + an instance
  // can be constructed with a code + message.
  var err = new b.safeArchive.SafeArchiveError("safe-archive/test", "test instance");
  check("SafeArchiveError: code carried",     err.code === "safe-archive/test");
  check("SafeArchiveError: is Error subclass", err instanceof Error);
}

async function testSafeArchiveInspect() {
  var z = b.archive.zip();
  z.addFile("a.txt", "alpha");
  z.addFile("b.txt", "beta");
  var bytes = z.toBuffer();
  var summary = await b.safeArchive.inspect({ source: bytes });
  check("safeArchive.inspect: format=zip",                summary.format === "zip");
  check("safeArchive.inspect: 2 entries",                 summary.entries.length === 2);
  check("safeArchive.inspect: totalUncompressedBytes",    summary.totalUncompressedBytes === 9);
}

async function testZipBombPolicy() {
  var policy = b.guardArchive.zipBombPolicy({
    maxTotalDecompressedBytes: 8,
    maxExpansionRatio:         100,
  });
  check("zipBombPolicy: maxTotalDecompressedBytes carries",  policy.maxTotalDecompressedBytes === 8);
  check("zipBombPolicy: defaults applied",                   policy.maxEntries === 65535);
  // 9-byte archive payload exceeds the 8-byte total cap.
  var z = b.archive.zip();
  z.addFile("big.txt", "123456789");
  var bytes = z.toBuffer();
  var refused = null;
  try {
    var reader = b.archive.read.zip(b.archive.adapters.buffer(bytes), {
      bombPolicy: policy,
    });
    await reader.inspect();
  } catch (e) { refused = e; }
  check("bombPolicy: maxTotalDecompressedBytes trips",
    refused && /total-too-large|entry-too-large/.test(refused.code || refused.message));
}

function testEntryTypePolicy() {
  var p = b.guardArchive.entryTypePolicy({ symlinks: true });
  check("entryTypePolicy: symlinks opted in",   p.symlinks === true);
  check("entryTypePolicy: hardlinks default off", p.hardlinks === false);
  check("entryTypePolicy: devices default off",   p.devices === false);
}

function testVerifyExtractionPathHappy() {
  var dest = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-verifyx-"));
  try {
    var resolved = b.guardFilename.verifyExtractionPath("docs/readme.txt", dest);
    check("verifyExtractionPath: ok resolved", resolved.indexOf(dest) === 0);
  } finally {
    fs.rmSync(dest, { recursive: true, force: true });
  }
}

function testVerifyExtractionPathRefusals() {
  var refusals = 0;
  function r(name, root) {
    try { b.guardFilename.verifyExtractionPath(name, root); }
    catch (_e) { refusals += 1; }
  }
  r("../etc/passwd", "/tmp");                       // zip slip
  r("/etc/passwd", "/tmp");                         // absolute
  r("docs/../../etc/passwd", "/tmp");               // mid-segment ..
  // PATH_MAX overflow (4097 chars).
  var oversize = new Array(4098).join("a");
  r(oversize, "/tmp");
  check("verifyExtractionPath: 4 refusals", refusals === 4);
}

// Per-segment Windows-extraction hazards — refused even though they stay
// inside the extraction root (within-root write-target redirection /
// collision that the containment + realpath checks can't see). Platform-
// unconditional, with per-check opt-outs for Linux-only targets.
function testVerifyExtractionPathWindowsHazards() {
  function expectCode(name, code, opts) {
    var e = null;
    try { b.guardFilename.verifyExtractionPath(name, "/tmp", opts); }
    catch (err) { e = err; }
    check("verifyExtractionPath refuses " + JSON.stringify(name) + " (" + code + ")",
      e && (e.code || "").indexOf(code) !== -1);
  }
  // Windows reserved device names (bare + with extension + nested segment).
  expectCode("CON", "filename/extraction-reserved-name");
  expectCode("aux.txt", "filename/extraction-reserved-name");
  expectCode("subdir/NUL", "filename/extraction-reserved-name");
  expectCode("logs/COM1.log", "filename/extraction-reserved-name");
  // Superscript-digit COM/LPT spoof (U+00B9/B2/B3 — Windows folds to 1/2/3).
  // Built from codepoints so the test source stays pure-ASCII.
  expectCode("COM" + String.fromCharCode(0xB9), "filename/extraction-reserved-name");
  expectCode("sub/LPT" + String.fromCharCode(0xB3), "filename/extraction-reserved-name");
  // NTFS alternate data streams.
  expectCode("file.txt:evil.exe", "filename/extraction-ntfs-ads");
  expectCode("dir/data.bin:$DATA", "filename/extraction-ntfs-ads");
  // Trailing dot / leading-or-trailing whitespace (Windows strips → collision).
  expectCode("secret.txt.", "filename/extraction-leading-trailing");
  expectCode("name with trailing space ", "filename/extraction-leading-trailing");

  // Opt-outs accept the name (then pass the realpath leg into a real root).
  function expectAccept(name, opts) {
    var dest = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-vx-"));
    var ok = false, code = null;
    try { ok = b.guardFilename.verifyExtractionPath(name, dest, opts).indexOf(dest) === 0; }
    catch (e) { code = e && e.code; }
    finally { fs.rmSync(dest, { recursive: true, force: true }); }
    check("verifyExtractionPath accepts " + JSON.stringify(name) + " with opt-out" +
      (code ? " (threw " + code + ")" : ""), ok === true);
  }
  expectAccept("CON", { reservedNamePolicy: "allow" });
  expectAccept("file.txt:evil.exe", { adsPolicy: "allow" });
  expectAccept("secret.txt.", { leadingTrailingPolicy: "allow" });
}

async function testExtractRefusesOverwrite() {
  // Codex P1 on v0.12.7 PR #158 — the catch-block cleanup deleted
  // PRE-EXISTING destination files on abort because the rename-onto-
  // canonical-path path overwrote them first, then `written[].path`
  // got rm'd. Fix is to refuse overwrite up front; this regression
  // test verifies the new refusal fires + that the pre-existing file
  // is left untouched.
  var z = b.archive.zip();
  z.addFile("readme.txt", "from-archive\n");
  var bytes = z.toBuffer();
  var dest = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-overwrite-test-"));
  try {
    var collidePath = path.join(dest, "readme.txt");
    fs.writeFileSync(collidePath, "operator's pre-existing file\n");
    var refused = null;
    try {
      await b.safeArchive.extract({ source: bytes, destination: dest });
    } catch (e) { refused = e; }
    check("extract: refuses pre-existing destination file",
      refused && /destination-exists/.test(refused.code || refused.message));
    var stillThere = fs.readFileSync(collidePath, "utf8");
    check("extract: pre-existing file untouched on refusal",
      stillThere === "operator's pre-existing file\n");
  } finally {
    fs.rmSync(dest, { recursive: true, force: true });
  }
}

async function testSafeArchiveRefusesTrustedStreamSource() {
  // Codex P2 on v0.12.7 PR #158 — safeArchive.extract accepted
  // trusted-stream adapters via the input-shape validator but the
  // implementation called the random-access reader, which threw the
  // wrong-entry-point error. Fix is to refuse trusted-stream sources
  // upfront with a typed safe-archive code.
  var nodeStream = require("node:stream");
  var fakeReadable = new nodeStream.Readable({ read: function () {} });
  var adapter = b.archive.adapters.trustedStream(fakeReadable);
  var dest = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-trusted-refusal-"));
  try {
    var refused = null;
    try {
      await b.safeArchive.extract({
        source:      adapter,
        destination: dest,
      });
    } catch (e) { refused = e; }
    check("safeArchive.extract: trusted-stream upfront refused",
      refused && /trusted-stream-unsupported/.test(refused.code || refused.message));
    var inspectRefused = null;
    try { await b.safeArchive.inspect({ source: adapter }); }
    catch (e) { inspectRefused = e; }
    check("safeArchive.inspect: a trusted-stream source is refused with safe-archive/trusted-stream-unsupported",
      _hasCode(inspectRefused, "safe-archive/trusted-stream-unsupported"),
      inspectRefused ? String(inspectRefused.code) : "inspected without error");
  } finally {
    fakeReadable.destroy();
    fs.rmSync(dest, { recursive: true, force: true });
  }
}

async function testFromTrustedStreamRoundTrip() {
  var nodeStream = require("node:stream");
  var z = b.archive.zip();
  z.addFile("readme.txt", "trusted stream readme\n");
  z.addFile("data/n.csv", "a,b\n1,2\n");
  var bytes = z.toBuffer();

  // inspect over a Readable via the trusted-stream adapter (no manual
  // buffering by the caller — the reader collects + decodes).
  var reader = b.archive.read.zip.fromTrustedStream(
    b.archive.adapters.trustedStream(nodeStream.Readable.from(bytes)));
  check("fromTrustedStream: kind tag", reader.kind === "zip-trusted-sequential");
  var entries = await reader.inspect();
  check("fromTrustedStream: inspect sees both entries", entries.length === 2);
  check("fromTrustedStream: entry name round-trips",
    entries.some(function (e) { return e.name === "readme.txt"; }));

  // extractEntries over a fresh stream recovers the bytes.
  var reader2 = b.archive.read.zip.fromTrustedStream(
    b.archive.adapters.trustedStream(nodeStream.Readable.from(bytes)));
  var got = {};
  for await (var ent of reader2.extractEntries()) {
    got[ent.name] = Buffer.isBuffer(ent.bytes) ? ent.bytes.toString("utf8") : null;
  }
  check("fromTrustedStream: extractEntries recovers content",
    got["readme.txt"] === "trusted stream readme\n" && got["data/n.csv"] === "a,b\n1,2\n");

  // bombPolicy is honored through the delegated decode — a tiny
  // per-entry cap refuses the archive.
  var reader3 = b.archive.read.zip.fromTrustedStream(
    b.archive.adapters.trustedStream(nodeStream.Readable.from(bytes)),
    { bombPolicy: { maxEntryDecompressedBytes: 4 } });
  var bombErr = null;
  try { await reader3.inspect(); for await (var _e of reader3.extractEntries()) { void _e; } }
  catch (e) { bombErr = e; }
  check("fromTrustedStream: bombPolicy applies on decode", bombErr !== null);

  // bad adapter (random-access) refused.
  var badErr = null;
  try { b.archive.read.zip.fromTrustedStream(b.archive.adapters.buffer(bytes)); }
  catch (e) { badErr = e; }
  check("fromTrustedStream: non-trusted-stream adapter refused",
    badErr && /bad-adapter/.test(badErr.code || badErr.message));
}

async function testGuardArchiveInspect() {
  var z = b.archive.zip();
  z.addFile("safe.txt", "safe");
  var bytes = z.toBuffer();
  var summary = await b.guardArchive.inspect(b.archive.adapters.buffer(bytes), {
    profile: "balanced",
  });
  check("guardArchive.inspect: 1 entry",       summary.entries.length === 1);
  check("guardArchive.inspect: issues array",   Array.isArray(summary.issues));

  // A profile name the guard does not have is refused before the archive is
  // read, and the reader emits no inspect audit for it.
  var badProfiles = ["nope", "hipaa", 5];
  for (var bp = 0; bp < badProfiles.length; bp += 1) {
    var counted = _countingAdapter(bytes);
    var events = [];
    var auditSink = { safeEmit: function (ev) { events.push(ev); }, emit: function (ev) { events.push(ev); } };
    var errBp = null;
    try { await b.guardArchive.inspect(counted.adapter, { profile: badProfiles[bp], audit: auditSink }); }
    catch (err) { errBp = err; }
    check("guardArchive.inspect: profile " + JSON.stringify(badProfiles[bp]) +
      " is refused before the archive is read",
      _hasCode(errBp, "archive/bad-profile") && counted.reads.length === 0 && events.length === 0,
      (errBp ? String(errBp.code) : "inspected without error") + " reads=" + counted.reads.length +
      " audits=" + events.length);
  }

  // The validateEntries options reach validateEntries: a cap applies, and a
  // bad cap, policy or posture is refused before the archive is read.
  var two = b.archive.zip();
  two.addFile("a.txt", "a");
  two.addFile("b.txt", "b");
  var twoBytes = two.toBuffer();
  var capped = await b.guardArchive.inspect(b.archive.adapters.buffer(twoBytes), { maxEntries: 1 });
  check("guardArchive.inspect: maxEntries reaches validateEntries",
    capped.issues.some(function (i) { return i.kind === "entry-count-cap"; }),
    JSON.stringify(capped.issues.map(function (i) { return i.kind; })));
  var underCap = await b.guardArchive.inspect(b.archive.adapters.buffer(twoBytes), { maxEntries: 2 });
  check("guardArchive.inspect: two entries under maxEntries 2 draw no entry-count issue",
    !underCap.issues.some(function (i) { return i.kind === "entry-count-cap"; }));
  var badOpts = [
    { opts: { maxEntries: -1 },                     code: "archive/bad-opt" },
    { opts: { maxEntries: "x", profile: "strict" }, code: "archive/bad-opt" },
    { opts: { maxTotalBytes: 0 },                   code: "archive/bad-opt" },
    { opts: { encryptionPolicy: "bogus" },          code: "archive/bad-opt" },
    { opts: { compliancePosture: "nope" },          code: "archive/bad-posture" },
  ];
  for (var bo = 0; bo < badOpts.length; bo += 1) {
    var countedBo = _countingAdapter(twoBytes);
    var errBo = null;
    try { await b.guardArchive.inspect(countedBo.adapter, badOpts[bo].opts); }
    catch (err) { errBo = err; }
    check("guardArchive.inspect: " + JSON.stringify(badOpts[bo].opts) + " throws " + badOpts[bo].code +
      " before the archive is read",
      _hasCode(errBo, badOpts[bo].code) && countedBo.reads.length === 0,
      (errBo ? String(errBo.code) : "inspected without error") + " reads=" + countedBo.reads.length);
  }
}

async function testBundleAdapterStorageRoundTrip() {
  var rootDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-backup-adapter-root-"));
  var srcDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-backup-adapter-src-"));
  var destDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-backup-adapter-dest-"));
  try {
    // Populate a small bundle source.
    fs.writeFileSync(path.join(srcDir, "manifest.json"), JSON.stringify({ v: 1 }));
    fs.mkdirSync(path.join(srcDir, "files"));
    fs.writeFileSync(path.join(srcDir, "files", "blob.bin"), Buffer.from([1, 2, 3]));

    var storage = b.backup.bundleAdapterStorage({
      adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: rootDir }),
    });
    check("bundleAdapterStorage: name=adapter", storage.name === "adapter");

    var bundleId = "2026-05-23T07-00-00-000Z-deadbeef";
    await storage.writeBundle(bundleId, srcDir);
    check("bundleAdapterStorage: hasBundle after write", await storage.hasBundle(bundleId));
    fs.rmSync(destDir, { recursive: true });
    await storage.readBundle(bundleId, destDir);
    var restored = fs.readFileSync(path.join(destDir, "files", "blob.bin"));
    check("bundleAdapterStorage: roundtrip bytes match", restored[0] === 1 && restored.length === 3);
    var list = await storage.listBundles();
    check("bundleAdapterStorage: listBundles returns the bundle", list.length === 1 && list[0].bundleId === bundleId);
    await storage.deleteBundle(bundleId);
    check("bundleAdapterStorage: hasBundle false after delete", !(await storage.hasBundle(bundleId)));
  } finally {
    try { fs.rmSync(rootDir, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(srcDir,  { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(destDir, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  }
}

// In-memory extraction (serverless / read-only FS): reader.extractEntries()
// yields decompressed bytes without ever writing to disk, and those bytes are
// byte-identical to what disk extract() produces.
async function testExtractEntriesInMemory() {
  var z = b.archive.zip();
  z.addFile("readme.txt", "Hello, in-memory!\n");
  z.addFile("data/nums.csv", "n,sq\n2,4\n");
  z.addFile("docs/deep.bin", Buffer.from([0, 1, 2, 3, 255]));
  var bytes = z.toBuffer();

  // Spy: no fs write may happen during the in-memory path.
  var wrote = false;
  var origWrite = fs.writeFileSync;
  fs.writeFileSync = function () { wrote = true; return origWrite.apply(fs, arguments); };
  var collected = {};
  try {
    var reader = b.archive.read.zip(b.archive.adapters.buffer(bytes));
    for await (var e of reader.extractEntries()) { collected[e.name] = e.bytes; }
  } finally {
    fs.writeFileSync = origWrite;
  }
  check("zip extractEntries: no disk write", wrote === false);
  check("zip extractEntries: 3 file entries (dir skipped)", Object.keys(collected).length === 3);
  check("zip extractEntries: text bytes match", collected["readme.txt"].toString("utf8") === "Hello, in-memory!\n");
  check("zip extractEntries: binary bytes match", collected["docs/deep.bin"].equals(Buffer.from([0, 1, 2, 3, 255])));

  // Byte-equality with disk extract().
  var dest = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-archive-mem-"));
  try {
    await b.safeArchive.extract({ source: bytes, destination: dest, guardProfile: "balanced" });
    var diskBin = fs.readFileSync(path.join(dest, "docs/deep.bin"));
    check("zip extractEntries bytes == disk extract bytes", collected["docs/deep.bin"].equals(diskBin));
  } finally {
    fs.rmSync(dest, { recursive: true, force: true });
  }

  // tar in-memory.
  var t = b.archive.tar();
  t.addFile("x.txt", "world\n");
  t.addFile("sub/y.dat", Buffer.from([9, 8, 7]));
  var tbytes = t.toBuffer();
  var tcollected = {};
  var tr = b.archive.read.tar(b.archive.adapters.buffer(tbytes));
  for await (var te of tr.extractEntries()) { tcollected[te.name] = te.bytes; }
  check("tar extractEntries: 2 entries", Object.keys(tcollected).length === 2);
  check("tar extractEntries: text matches", tcollected["x.txt"].toString("utf8") === "world\n");
  check("tar extractEntries: binary matches", tcollected["sub/y.dat"].equals(Buffer.from([9, 8, 7])));
}

async function testExtractToMemoryOrchestrator() {
  // zip in-memory orchestrator — byte-equal to disk extract(), no fs write.
  var z = b.archive.zip();
  z.addFile("readme.txt", "serverless!\n");
  z.addFile("d/deep.bin", Buffer.from([5, 6, 7, 255]));
  var zbytes = z.toBuffer();

  var wrote = false;
  var origWrite = fs.writeFileSync;
  fs.writeFileSync = function () { wrote = true; return origWrite.apply(fs, arguments); };
  var collected = {};
  try {
    for await (var e of b.safeArchive.extractToMemory({ source: zbytes, guardProfile: "balanced" })) {
      collected[e.name] = e.bytes;
    }
  } finally {
    fs.writeFileSync = origWrite;
  }
  check("extractToMemory zip: no disk write",                wrote === false);
  check("extractToMemory zip: 2 file entries (dir skipped)", Object.keys(collected).length === 2);
  check("extractToMemory zip: text bytes match",             collected["readme.txt"].toString("utf8") === "serverless!\n");
  check("extractToMemory zip: binary bytes match",           collected["d/deep.bin"].equals(Buffer.from([5, 6, 7, 255])));

  // Byte-equality with the disk extract() path.
  var dest = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-sa-mem-"));
  try {
    await b.safeArchive.extract({ source: zbytes, destination: dest, guardProfile: "balanced" });
    check("extractToMemory bytes == disk extract bytes",
          collected["d/deep.bin"].equals(fs.readFileSync(path.join(dest, "d/deep.bin"))));
  } finally {
    fs.rmSync(dest, { recursive: true, force: true });
  }

  // tar source auto-detected.
  var t = b.archive.tar();
  t.addFile("a.txt", "alpha\n");
  t.addFile("p/b.dat", Buffer.from([1, 2]));
  var tbytes = t.toBuffer();
  var tcollected = {};
  for await (var te of b.safeArchive.extractToMemory({ source: tbytes })) { tcollected[te.name] = te.bytes; }
  check("extractToMemory tar: 2 entries auto-detected", Object.keys(tcollected).length === 2);
  check("extractToMemory tar: text matches",            tcollected["a.txt"].toString("utf8") === "alpha\n");

  // tar.gz — explicit format. Auto-sniff yields "gzip", which the disk
  // path also treats as unsupported, so the documented contract needs
  // the explicit hint (extractToMemory mirrors extract()'s dispatch).
  var gzBytes = b.archive.gz(tbytes).toBuffer();
  var gcollected = {};
  for await (var ge of b.safeArchive.extractToMemory({ source: gzBytes, format: "tar.gz" })) { gcollected[ge.name] = ge.bytes; }
  check("extractToMemory tar.gz: inner tar entries", Object.keys(gcollected).length === 2);
  check("extractToMemory tar.gz: binary matches",    gcollected["p/b.dat"].equals(Buffer.from([1, 2])));

  // bombPolicy refusal propagates from the composed reader.
  var bombThrew = null;
  try {
    var tinyBomb = b.guardArchive.zipBombPolicy({ maxTotalDecompressedBytes: 4 });
    for await (var be of b.safeArchive.extractToMemory({ source: zbytes, bombPolicy: tinyBomb })) { void be; }
  } catch (e) { bombThrew = e; }
  check("extractToMemory: bombPolicy refusal propagates", bombThrew !== null);

  // passphrase-wrap envelope auto-unwrapped (shared resolve path), then yielded.
  var sealed = await b.archive.wrapWithPassphrase(zbytes, { passphrase: "aLongCorrectHorseBatteryStaple9876!Phrase" });
  var wcollected = {};
  for await (var we of b.safeArchive.extractToMemory({ source: sealed, passphrase: "aLongCorrectHorseBatteryStaple9876!Phrase" })) { wcollected[we.name] = we.bytes; }
  check("extractToMemory: passphrase envelope auto-unwrapped + yielded",
        wcollected["readme.txt"] && wcollected["readme.txt"].toString("utf8") === "serverless!\n");

  // A raw b.crypto.encryptPacked blob is NOT an archive-wrap envelope (it
  // carries no BAWRP/BAWPP magic, only a 1-byte XChaCha20 format header), so
  // the orchestrator sniffs it as unknown and refuses cleanly rather than
  // pretending to auto-unwrap a phantom "EPACK" format.
  var packed = b.crypto.encryptPacked(zbytes, b.crypto.generateBytes(32));
  var packedThrew = null;
  try { for await (var pe of b.safeArchive.extractToMemory({ source: packed })) { void pe; } } catch (e) { packedThrew = e; }
  check("extractToMemory: raw encryptPacked blob refused as unsupported (no phantom EPACK unwrap)",
        packedThrew && /format-unsupported/.test(packedThrew.code || packedThrew.message));

  // trusted-stream source refused upfront — and BP5: the refusal message
  // must no longer name the stale v0.12.8 version.
  var nodeStream = require("node:stream");
  var fakeReadable = new nodeStream.Readable({ read: function () {} });
  var tsAdapter = b.archive.adapters.trustedStream(fakeReadable);
  var tsThrew = null;
  try {
    for await (var tse of b.safeArchive.extractToMemory({ source: tsAdapter })) { void tse; }
  } catch (e) { tsThrew = e; }
  fakeReadable.destroy();
  check("extractToMemory: trusted-stream refused upfront",
        tsThrew && /trusted-stream-unsupported/.test(tsThrew.code || tsThrew.message));
  check("extractToMemory: refusal message dropped the stale v0.12.8 wording",
        tsThrew && tsThrew.message.indexOf("v0.12.8") === -1);
}

// opts.signal (AbortSignal) is documented on b.archive.read.zip — verify
// it actually aborts the read at the entry boundary rather than being a
// dead doc opt.
async function testSignalAbort() {
  var z = b.archive.zip();
  z.addFile("a.txt", "one\n");
  z.addFile("b.txt", "two\n");
  var bytes = z.toBuffer();

  var ac = new AbortController();
  ac.abort();   // already aborted before any read
  var reader = b.archive.read.zip(b.archive.adapters.buffer(bytes), { signal: ac.signal });

  var inspectThrew = null;
  try { await reader.inspect(); } catch (e) { inspectThrew = e; }
  check("zip inspect honors an aborted signal",
        inspectThrew && (inspectThrew.code || "").indexOf("archive-read/aborted") !== -1);

  var extractThrew = null;
  try { for await (var _e of reader.extractEntries()) { void _e; } }
  catch (e) { extractThrew = e; }
  check("zip extractEntries honors an aborted signal",
        extractThrew && (extractThrew.code || "").indexOf("archive-read/aborted") !== -1);

  // Sanity: with no signal the same reader works.
  var ok = b.archive.read.zip(b.archive.adapters.buffer(bytes));
  var n = 0;
  for await (var e2 of ok.extractEntries()) { void e2; n += 1; }
  check("zip extractEntries with no signal still yields entries", n === 2);
}

// ---- ZIP64 read support ---------------------------------------------------
// The write side does not emit ZIP64, so we hand-build minimal ZIP64-form
// archives (infozip / Go archive/zip layout) and assert they decode to the
// same entry shape a classic reader yields, with bomb/name refusals intact.
// APPNOTE 6.3.10 §4.3.14 (EOCD64) / §4.3.15 (locator) / §4.5.3 (extra field).

var METHOD_STORE = 0;
var U32_SENTINEL = 0xffffffff;
var U16_SENTINEL = 0xffff;

// Build a single STORE-method ZIP64 archive whose CD entry carries the
// 0xFFFFFFFF uncompressed/compressed-size sentinels resolved by a §4.5.3
// extra field, fronted by a real ZIP64 EOCD record + locator and a classic
// EOCD with sentinel size/offset fields. `crc` comes from the classic
// archive the framework produced for the same bytes (CRC must agree so the
// LFH/CD skew check passes). `entryCountSentinel` exercises the EOCD64
// totalEntries path.
function buildZip64Store(name, data, crc, opts) {
  opts = opts || {};
  var nameBuf = Buffer.from(name, "utf8");
  var size = data.length;

  // ZIP64 extra field for the LFH: uncompressedSize(8) + compressedSize(8).
  var lfhExtra = Buffer.alloc(4 + 16);
  lfhExtra.writeUInt16LE(0x0001, 0);
  lfhExtra.writeUInt16LE(16, 2);
  lfhExtra.writeBigUInt64LE(BigInt(size), 4);
  lfhExtra.writeBigUInt64LE(BigInt(size), 12);

  // Local file header (30 bytes) with sentinel sizes.
  var lfh = Buffer.alloc(30);
  lfh.writeUInt32LE(0x04034b50, 0);    // sig
  lfh.writeUInt16LE(45, 4);            // version needed = 4.5 (ZIP64)
  lfh.writeUInt16LE(0, 6);             // flags
  lfh.writeUInt16LE(METHOD_STORE, 8);  // method
  lfh.writeUInt16LE(0, 10);            // mod time
  lfh.writeUInt16LE(0x21, 12);         // mod date (1980-01-01)
  lfh.writeUInt32LE(crc >>> 0, 14);    // crc32
  lfh.writeUInt32LE(U32_SENTINEL, 18); // csize sentinel
  lfh.writeUInt32LE(U32_SENTINEL, 22); // usize sentinel
  lfh.writeUInt16LE(nameBuf.length, 26);
  lfh.writeUInt16LE(lfhExtra.length, 28);

  var lfhOffset = 0;

  // ZIP64 extra field for the CD: uncompressedSize(8) + compressedSize(8)
  // (+ localHeaderOffset(8) when opted in).
  var includeOffset = opts.offsetSentinel === true;
  var cdExtraDataLen = includeOffset ? 24 : 16;
  var cdExtra = Buffer.alloc(4 + cdExtraDataLen);
  cdExtra.writeUInt16LE(0x0001, 0);
  cdExtra.writeUInt16LE(cdExtraDataLen, 2);
  cdExtra.writeBigUInt64LE(BigInt(size), 4);
  cdExtra.writeBigUInt64LE(BigInt(size), 12);
  if (includeOffset) cdExtra.writeBigUInt64LE(BigInt(lfhOffset), 20);
  // Adversarial CD-extra fixtures inject a hand-built extra block to drive
  // the ZIP64 extended-information refusal branches (truncated / missing /
  // multi-disk / value-too-large).
  if (opts.cdExtraOverride) cdExtra = opts.cdExtraOverride;

  // Central directory header (46 bytes) with sentinel sizes.
  var cd = Buffer.alloc(46);
  cd.writeUInt32LE(0x02014b50, 0);     // sig
  cd.writeUInt16LE(45, 4);             // version made by
  cd.writeUInt16LE(45, 6);             // version needed
  cd.writeUInt16LE(0, 8);              // flags
  cd.writeUInt16LE(METHOD_STORE, 10);  // method
  cd.writeUInt16LE(0, 12);             // mod time
  cd.writeUInt16LE(0x21, 14);          // mod date
  cd.writeUInt32LE(crc >>> 0, 16);     // crc32
  cd.writeUInt32LE(U32_SENTINEL, 20);  // csize sentinel
  cd.writeUInt32LE(U32_SENTINEL, 24);  // usize sentinel
  cd.writeUInt16LE(nameBuf.length, 28);
  cd.writeUInt16LE(cdExtra.length, 30);
  cd.writeUInt16LE(0, 32);             // comment len
  cd.writeUInt16LE(opts.diskSentinel === true ? U16_SENTINEL : 0, 34);  // disk start (sentinel when opted in)
  cd.writeUInt16LE(0, 36);             // internal attrs
  cd.writeUInt32LE(0, 38);             // external attrs
  cd.writeUInt32LE(includeOffset ? U32_SENTINEL : lfhOffset, 42);  // lfh offset (sentinel when opted in)

  var cdBytesBefore = Buffer.concat([lfh, nameBuf, lfhExtra, data]);
  var cdOffset = cdBytesBefore.length;
  var cdRecord = Buffer.concat([cd, nameBuf, cdExtra]);
  var cdSize = cdRecord.length;

  // ZIP64 EOCD record (56 bytes through cdOffset).
  var eocd64 = Buffer.alloc(56);
  eocd64.writeUInt32LE(0x06064b50, 0);          // sig
  eocd64.writeBigUInt64LE(BigInt(56 - 12), 4);  // size of remaining record
  eocd64.writeUInt16LE(45, 12);                 // version made by
  eocd64.writeUInt16LE(45, 14);                 // version needed
  eocd64.writeUInt32LE(0, 16);                  // disk number
  eocd64.writeUInt32LE(0, 20);                  // cd start disk
  eocd64.writeBigUInt64LE(1n, 24);              // entries this disk
  eocd64.writeBigUInt64LE(1n, 32);              // total entries
  eocd64.writeBigUInt64LE(BigInt(cdSize), 40);  // cd size
  eocd64.writeBigUInt64LE(BigInt(cdOffset), 48);// cd offset

  var eocd64Offset = cdOffset + cdSize;
  // `eocd64Gap` inserts bytes between the EOCD64 record and its locator, so
  // the record the locator names is not the one directly before it.
  var gap = opts.eocd64Gap ? Buffer.alloc(opts.eocd64Gap) : Buffer.alloc(0);

  // ZIP64 EOCD locator (20 bytes).
  var locator = Buffer.alloc(20);
  locator.writeUInt32LE(0x07064b50, 0);             // sig
  locator.writeUInt32LE(0, 4);                      // disk with eocd64
  locator.writeBigUInt64LE(BigInt(eocd64Offset), 8);// eocd64 offset
  locator.writeUInt32LE(1, 16);                     // total disks

  // Classic EOCD (22 bytes) with sentinels.
  var entryCountSentinel = opts.entryCountSentinel === true;
  var eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);   // sig
  eocd.writeUInt16LE(0, 4);            // disk number
  eocd.writeUInt16LE(0, 6);            // cd disk
  var classicCount = opts.classicCount != null ? opts.classicCount
    : (entryCountSentinel ? U16_SENTINEL : 1);
  eocd.writeUInt16LE(classicCount, 8);   // entries this disk
  eocd.writeUInt16LE(classicCount, 10);  // total entries
  eocd.writeUInt32LE(opts.classicCdSize != null ? opts.classicCdSize : U32_SENTINEL, 12);// cd size sentinel
  eocd.writeUInt32LE(opts.classicCdOffset != null ? opts.classicCdOffset : U32_SENTINEL, 16);// cd offset sentinel
  eocd.writeUInt16LE(0, 20);          // comment len

  return Buffer.concat([cdBytesBefore, cdRecord, eocd64, gap, locator, eocd]);
}

async function testZip64Read() {
  var payload = Buffer.from("ZIP64 round-trip payload — same bytes a classic reader yields.\n", "utf8");

  // Get a real CRC32 for the payload by reading it back through a classic
  // STORE archive the framework produced.
  var z = b.archive.zip();
  z.addFile("z64.txt", payload);
  var classicBytes = z.toBuffer();
  var classicReader = b.archive.read.zip(b.archive.adapters.buffer(classicBytes));
  var classicEntries = await classicReader.inspect();
  var crc = classicEntries[0].crc;

  // Size-sentinel ZIP64 form decodes to the same entry shape.
  var z64 = buildZip64Store("z64.txt", payload, crc);
  var reader = b.archive.read.zip(b.archive.adapters.buffer(z64));
  var entries = await reader.inspect();
  check("zip64: inspect sees 1 entry",          entries.length === 1);
  check("zip64: name round-trips",              entries[0].name === "z64.txt");
  check("zip64: resolved size matches payload", entries[0].size === payload.length);

  // extractEntries recovers byte-identical content (LFH/CD ZIP64 skew check
  // passes against resolved sizes).
  var got = null;
  for await (var ent of reader.extractEntries()) { got = ent; }
  check("zip64: extractEntries recovers exact bytes", got && got.bytes.equals(payload));

  // localHeaderOffset sentinel + ZIP64 extra resolution.
  var z64Off = buildZip64Store("z64.txt", payload, crc, { offsetSentinel: true });
  var readerOff = b.archive.read.zip(b.archive.adapters.buffer(z64Off));
  var gotOff = null;
  for await (var entO of readerOff.extractEntries()) { gotOff = entO; }
  check("zip64: lfhOffset sentinel resolved + bytes recovered",
    gotOff && gotOff.bytes.equals(payload));

  // EOCD64 totalEntries path — classic EOCD entry-count is the 0xFFFF
  // sentinel; the true count comes from the ZIP64 EOCD record.
  var z64Count = buildZip64Store("z64.txt", payload, crc, { entryCountSentinel: true });
  var readerCount = b.archive.read.zip(b.archive.adapters.buffer(z64Count));
  var entriesCount = await readerCount.inspect();
  check("zip64: EOCD64 totalEntries resolved from sentinel", entriesCount.length === 1);

  // Bomb cap still fires on the resolved 64-bit size.
  var bombErr = null;
  try {
    var bombReader = b.archive.read.zip(b.archive.adapters.buffer(z64), {
      bombPolicy: { maxEntryDecompressedBytes: 4 },
    });
    await bombReader.inspect();
  } catch (e) { bombErr = e; }
  check("zip64: bomb cap fires on resolved size",
    bombErr && /entry-too-large|total-too-large/.test(bombErr.code || bombErr.message));

  // Zip-Slip name refusal still fires on a ZIP64-form archive.
  var slip = buildZip64Store("../../etc/passwd", payload, crc);
  var slipDest = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-zip64-slip-"));
  var slipErr = null;
  try {
    var slipReader = b.archive.read.zip(b.archive.adapters.buffer(slip));
    await slipReader.extract({ destination: slipDest });
  } catch (e) { slipErr = e; }
  finally { fs.rmSync(slipDest, { recursive: true, force: true }); }
  check("zip64: zip-slip name still refused", slipErr !== null);

  // A classic EOCD claiming ZIP64 (sentinel) but missing the ZIP64 trailer
  // is refused, not read with a sentinel taken literally.
  var truncated = z64.slice(0, z64.length - 20 - 56 - 22);  // drop eocd64 + locator + classic eocd
  var orphanEocd = Buffer.alloc(22);
  orphanEocd.writeUInt32LE(0x06054b50, 0);
  orphanEocd.writeUInt16LE(U16_SENTINEL, 8);
  orphanEocd.writeUInt16LE(U16_SENTINEL, 10);
  orphanEocd.writeUInt32LE(U32_SENTINEL, 12);
  orphanEocd.writeUInt32LE(U32_SENTINEL, 16);
  var orphan = Buffer.concat([truncated, orphanEocd]);
  var orphanErr = null;
  try {
    var orphanReader = b.archive.read.zip(b.archive.adapters.buffer(orphan));
    await orphanReader.inspect();
  } catch (e) { orphanErr = e; }
  check("zip64: missing ZIP64 trailer refused (no literal-sentinel read)",
    orphanErr && /zip64/.test(orphanErr.code || orphanErr.message));
}

// ---------------------------------------------------------------------------
// Adversarial / defensive branch coverage — hand-built malformed archives.
// The write side always emits well-formed classic archives, so the reader's
// refusal + defensive paths (bad signatures, LFH/CD skew, ZIP64 trailer
// corruption, entry-type policy, bomb caps, deflate decode) are driven from
// hand-crafted fixtures decoded through the real b.archive.read.zip consumer
// path (buffer / objectStore adapter).
// ---------------------------------------------------------------------------

var SIG_LFH_OK  = 0x04034b50;
var SIG_CFH_OK  = 0x02014b50;
var SIG_EOCD_OK = 0x06054b50;

// External-attribute high-16-bit unix mode markers (mode << 16).
var EXT_SYMLINK  = 0xA1FF0000;   // S_IFLNK
var EXT_SOCKET   = 0xC0000000;   // S_IFSOCK
var EXT_FIFO     = 0x10000000;   // S_IFIFO
var EXT_CHARDEV  = 0x20000000;   // S_IFCHR
var EXT_BLOCKDEV = 0x60000000;   // S_IFBLK
var EXT_DIR      = 0x40000000;   // S_IFDIR

// CRC-32 of an entry's uncompressed bytes: STORE data as given, DEFLATE data
// inflated first. A fixture whose data does not inflate gets 0, and the
// fixtures that need a specific CRC pass `crc` explicitly.
function _specCrc(s) {
  if (s.crc != null) return s.crc >>> 0;
  var data = s.data || Buffer.alloc(0);
  var method = s.method != null ? s.method : 0;
  if (method === 0) return zlib.crc32(data) >>> 0;
  if (method === 8) {
    try { return zlib.crc32(zlib.inflateRawSync(data)) >>> 0; }
    catch (_e) { return 0; }
  }
  return 0;
}

// Data descriptor (APPNOTE 4.3.9) appended after an entry's data. dd:
//   { sig?: boolean (default true), crc?, csize?, usize?, wide?: boolean }
function _buildDataDescriptor(dd, crc, csize, usize) {
  var parts = [];
  if (dd.sig !== false) {
    var sig = Buffer.alloc(4);
    sig.writeUInt32LE(0x08074b50, 0);
    parts.push(sig);
  }
  var c = Buffer.alloc(4);
  c.writeUInt32LE((dd.crc != null ? dd.crc : crc) >>> 0, 0);
  parts.push(c);
  var cs = dd.csize != null ? dd.csize : csize;
  var us = dd.usize != null ? dd.usize : usize;
  var sizes;
  if (dd.wide) {
    sizes = Buffer.alloc(16);
    sizes.writeBigUInt64LE(BigInt(cs), 0);
    sizes.writeBigUInt64LE(BigInt(us), 8);
  } else {
    sizes = Buffer.alloc(8);
    sizes.writeUInt32LE(cs >>> 0, 0);
    sizes.writeUInt32LE(us >>> 0, 4);
  }
  parts.push(sizes);
  return Buffer.concat(parts);
}

// Build a classic (non-ZIP64) archive with full per-entry field control so a
// single field can be corrupted to drive one refusal branch. Each spec:
//   { name, data?, method?, usize?, csize?, crc?, flags?, lfhFlags?, externalAttrs?,
//     lfhSig?, cdSig?, lfhMethod?, lfhCrc?, lfhCsize?, lfhUsize?, lfhName?,
//     cdNameLen?, dataDescriptor?, cdLfhOffset? }
// `crc` defaults to the real CRC-32 of the entry's uncompressed bytes.
// `dataDescriptor` appends a descriptor after the data (see
// _buildDataDescriptor); `cdLfhOffset` overrides the CD's local-header offset.
// `lfhFlags` sets the local header's general-purpose flags and leaves the CD's
// flags at `flags`. `extra` and `lfhExtra` are the extra-field blocks of the
// CD entry and the local header. `nameBytes` and `lfhNameBytes` set the raw
// name-field bytes, for a name that is not valid UTF-8.
// opts: { eocdDiskNumber?, eocdCdDisk?, totalEntries?, entriesOnDisk?,
//         cdTrailing?: Buffer, eocdCdOffset?, eocdCdSize? }
function buildClassicZip(specs, opts) {
  opts = opts || {};
  var localParts = [];
  var offsets = [];
  var running = 0;
  specs.forEach(function (s) {
    var nameBuf = s.nameBytes || Buffer.from(s.name, "utf8");
    var data = s.data || Buffer.alloc(0);
    var usize = s.usize != null ? s.usize : data.length;
    var csize = s.csize != null ? s.csize : data.length;
    var crc = _specCrc(s);
    var method = s.method != null ? s.method : 0;
    var lfh = Buffer.alloc(30);
    lfh.writeUInt32LE((s.lfhSig != null ? s.lfhSig : SIG_LFH_OK) >>> 0, 0);
    lfh.writeUInt16LE(20, 4);
    lfh.writeUInt16LE(s.lfhFlags != null ? s.lfhFlags : (s.flags != null ? s.flags : 0), 6);
    lfh.writeUInt16LE(s.lfhMethod != null ? s.lfhMethod : method, 8);
    lfh.writeUInt16LE(0, 10);
    lfh.writeUInt16LE(0x21, 12);
    lfh.writeUInt32LE((s.lfhCrc != null ? s.lfhCrc : crc) >>> 0, 14);
    lfh.writeUInt32LE((s.lfhCsize != null ? s.lfhCsize : csize) >>> 0, 18);
    lfh.writeUInt32LE((s.lfhUsize != null ? s.lfhUsize : usize) >>> 0, 22);
    var lfhNameBuf = s.lfhNameBytes || (s.lfhName != null ? Buffer.from(s.lfhName, "utf8") : nameBuf);
    var lfhExtraBuf = s.lfhExtra || Buffer.alloc(0);
    lfh.writeUInt16LE(lfhNameBuf.length, 26);
    lfh.writeUInt16LE(lfhExtraBuf.length, 28);
    var pieces = [lfh, lfhNameBuf, lfhExtraBuf, data];
    if (s.dataDescriptor) pieces.push(_buildDataDescriptor(s.dataDescriptor, crc, csize, usize));
    var part = Buffer.concat(pieces);
    offsets.push(running);
    running += part.length;
    localParts.push(part);
  });
  var localBlob = Buffer.concat(localParts);
  var cdParts = [];
  specs.forEach(function (s, i) {
    var nameBuf = s.nameBytes || Buffer.from(s.name, "utf8");
    var cdExtraBuf = s.extra || Buffer.alloc(0);
    var data = s.data || Buffer.alloc(0);
    var usize = s.usize != null ? s.usize : data.length;
    var csize = s.csize != null ? s.csize : data.length;
    var crc = _specCrc(s);
    var method = s.method != null ? s.method : 0;
    var cd = Buffer.alloc(46);
    cd.writeUInt32LE((s.cdSig != null ? s.cdSig : SIG_CFH_OK) >>> 0, 0);
    cd.writeUInt16LE(20, 4);
    cd.writeUInt16LE(20, 6);
    cd.writeUInt16LE(s.flags != null ? s.flags : 0, 8);
    cd.writeUInt16LE(method, 10);
    cd.writeUInt16LE(0, 12);
    cd.writeUInt16LE(0x21, 14);
    cd.writeUInt32LE(crc, 16);
    cd.writeUInt32LE(csize >>> 0, 20);
    cd.writeUInt32LE(usize >>> 0, 24);
    cd.writeUInt16LE(s.cdNameLen != null ? s.cdNameLen : nameBuf.length, 28);
    cd.writeUInt16LE(cdExtraBuf.length, 30);
    cd.writeUInt16LE(0, 32);
    cd.writeUInt16LE(0, 34);
    cd.writeUInt16LE(0, 36);
    cd.writeUInt32LE(s.externalAttrs != null ? (s.externalAttrs >>> 0) : 0, 38);
    cd.writeUInt32LE((s.cdLfhOffset != null ? s.cdLfhOffset : offsets[i]) >>> 0, 42);
    cdParts.push(Buffer.concat([cd, nameBuf, cdExtraBuf]));
  });
  if (opts.cdTrailing) cdParts.push(opts.cdTrailing);
  var cdBlob = Buffer.concat(cdParts);
  var eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(SIG_EOCD_OK, 0);
  eocd.writeUInt16LE(opts.eocdDiskNumber != null ? opts.eocdDiskNumber : 0, 4);
  eocd.writeUInt16LE(opts.eocdCdDisk != null ? opts.eocdCdDisk : 0, 6);
  var total = opts.totalEntries != null ? opts.totalEntries : specs.length;
  eocd.writeUInt16LE(opts.entriesOnDisk != null ? opts.entriesOnDisk : total, 8);
  eocd.writeUInt16LE(total, 10);
  eocd.writeUInt32LE((opts.eocdCdSize != null ? opts.eocdCdSize : cdBlob.length) >>> 0, 12);
  eocd.writeUInt32LE((opts.eocdCdOffset != null ? opts.eocdCdOffset : localBlob.length) >>> 0, 16);
  eocd.writeUInt16LE(0, 20);
  return Buffer.concat([localBlob, cdBlob, eocd]);
}

async function _inspectErr(bytes, opts) {
  var e = null;
  try { await b.archive.read.zip(b.archive.adapters.buffer(bytes), opts).inspect(); }
  catch (err) { e = err; }
  return e;
}

async function _extractEntriesErr(bytes, opts, extractOpts) {
  var e = null;
  try {
    var r = b.archive.read.zip(b.archive.adapters.buffer(bytes), opts);
    for await (var x of r.extractEntries(extractOpts)) { void x; }
  } catch (err) { e = err; }
  return e;
}

function _hasCode(e, code) { return !!(e && (e.code || "").indexOf(code) !== -1); }

// EOCD / central-directory structural refusals driven through inspect().
async function testMalformedRefusals() {
  var e1 = await _inspectErr(Buffer.alloc(10));
  check("archive-read: sub-EOCD-size archive refused", _hasCode(e1, "archive-read/too-small"));

  var e2 = await _inspectErr(Buffer.alloc(100));
  check("archive-read: no-EOCD archive refused", _hasCode(e2, "archive-read/no-eocd"));

  var e3 = await _inspectErr(buildClassicZip([{ name: "a.txt", data: Buffer.from("x") }], { eocdDiskNumber: 1 }));
  check("archive-read: multi-disk EOCD refused", _hasCode(e3, "archive-read/multi-disk"));

  var e4 = await _inspectErr(buildClassicZip([{ name: "a.txt", data: Buffer.from("x"), cdSig: 0xdeadbeef }]));
  check("archive-read: bad central-directory signature refused", _hasCode(e4, "archive-read/bad-cd-signature"));

  var e5 = await _inspectErr(buildClassicZip([{ name: "a.txt", data: Buffer.from("x") }], { totalEntries: 2 }));
  check("archive-read: CD truncated (entry count overshoot) refused", _hasCode(e5, "archive-read/cd-truncated"));

  var e6 = await _inspectErr(buildClassicZip([{ name: "a.txt", data: Buffer.from("x"), cdNameLen: 500 }]));
  check("archive-read: CD variable-length overflow refused", _hasCode(e6, "archive-read/cd-truncated"));

  var empty = await b.archive.read.zip(b.archive.adapters.buffer(buildClassicZip([]))).inspect();
  check("archive-read: empty archive yields no entries", Array.isArray(empty) && empty.length === 0);
}

// LFH/CD skew defense — every mismatched field refuses the entry.
async function testLfhCdSkewRefusals() {
  var opts = { guardProfile: false };
  function mk(spec) { return buildClassicZip([spec]); }

  var e1 = await _extractEntriesErr(mk({ name: "a.txt", data: Buffer.from("hi"), lfhSig: 0xdeadbeef }), opts);
  check("archive-read: bad LFH signature refused", _hasCode(e1, "archive-read/bad-lfh-signature"));

  var e2 = await _extractEntriesErr(mk({ name: "a.txt", data: Buffer.from("hi"), method: 0, lfhMethod: 8 }), opts);
  check("archive-read: LFH/CD method skew refused", _hasCode(e2, "archive-read/lfh-cd-skew"));

  var e3 = await _extractEntriesErr(mk({ name: "a.txt", data: Buffer.from("hi"), crc: 1, lfhCrc: 2 }), opts);
  check("archive-read: LFH/CD crc skew refused", _hasCode(e3, "archive-read/lfh-cd-skew"));

  var e4 = await _extractEntriesErr(mk({ name: "a.txt", data: Buffer.from("hi"), lfhCsize: 99 }), opts);
  check("archive-read: LFH/CD compressed-size skew refused", _hasCode(e4, "archive-read/lfh-cd-skew"));

  var e5 = await _extractEntriesErr(mk({ name: "a.txt", data: Buffer.from("hi"), lfhUsize: 99 }), opts);
  check("archive-read: LFH/CD uncompressed-size skew refused", _hasCode(e5, "archive-read/lfh-cd-skew"));

  var e6 = await _extractEntriesErr(mk({ name: "a.txt", data: Buffer.from("hi"), lfhName: "b.txt" }), opts);
  check("archive-read: LFH/CD name skew refused", _hasCode(e6, "archive-read/lfh-cd-skew"));
}

// Zip-bomb caps that the round-trip happy path never trips.
async function testBombPolicyEdges() {
  var z = b.archive.zip();
  z.addFile("a.txt", "hello");
  var good = z.toBuffer();

  var e1 = null;
  try { await b.archive.read.zip(b.archive.adapters.buffer(good), { bombPolicy: { maxEntries: 0 } }).inspect(); }
  catch (err) { e1 = err; }
  check("archive-read: maxEntries cap trips", _hasCode(e1, "archive-read/too-many-entries"));

  // A cap that is not a number imposes nothing, because `entries.length > "abc"`
  // is false for every length. A cap read from an environment variable or a JSON
  // config arrives as a string, so this is a configuration typo away rather
  // than a contrived input.
  var z2 = b.archive.zip();
  z2.addFile("a.txt", "hello");
  z2.addFile("b.txt", "world");
  var two = z2.toBuffer();

  async function policyRefused(policy) {
    try {
      await b.archive.read.zip(b.archive.adapters.buffer(two), { bombPolicy: policy }).inspect();
      return null;
    } catch (err) { return err; }
  }

  check("archive-read: a non-numeric maxEntries is refused rather than ignored",
        (await policyRefused({ maxEntries: "abc" })) !== null,
        "a 2-entry archive was read under maxEntries \"abc\"");
  check("archive-read: a non-numeric maxEntryDecompressedBytes is refused",
        (await policyRefused({ maxEntryDecompressedBytes: "lots" })) !== null);
  check("archive-read: a non-numeric maxTotalDecompressedBytes is refused",
        (await policyRefused({ maxTotalDecompressedBytes: "plenty" })) !== null);
  check("archive-read: a non-numeric maxExpansionRatio is refused",
        (await policyRefused({ maxExpansionRatio: "high" })) !== null);
  check("archive-read: a negative maxEntries is refused",
        (await policyRefused({ maxEntries: -1 })) !== null);

  // A numeric cap still enforces, 0 still means refuse anything non-empty, and
  // a generous cap still reads the archive.
  check("archive-read: a numeric cap still trips",
        _hasCode(await policyRefused({ maxEntries: 1 }), "archive-read/too-many-entries"));
  check("archive-read: a zero cap still trips",
        _hasCode(await policyRefused({ maxEntries: 0 }), "archive-read/too-many-entries"));
  var generous = await policyRefused({ maxEntries: 10 });
  check("archive-read: a generous cap still reads the archive", generous === null,
        generous ? String(generous.code) : "");

  // The documented builder must be able to express the cap the reader honors.
  // `|| 65535` replaced an explicit 0 with the permissive default, so a policy
  // built this way could not say "refuse anything non-empty" at all.
  check("zipBombPolicy keeps an explicit maxEntries of 0",
        b.guardArchive.zipBombPolicy({ maxEntries: 0 }).maxEntries === 0,
        String(b.guardArchive.zipBombPolicy({ maxEntries: 0 }).maxEntries));
  check("zipBombPolicy still applies its default when the cap is absent",
        b.guardArchive.zipBombPolicy({}).maxEntries === 65535);
  var builderThrew = null;
  try { b.guardArchive.zipBombPolicy({ maxEntries: "abc" }); }
  catch (err) { builderThrew = err; }
  check("zipBombPolicy refuses a non-numeric cap at the call",
        builderThrew !== null, "accepted maxEntries \"abc\"");
  var ratioThrew = null;
  try { b.guardArchive.zipBombPolicy({ maxExpansionRatio: "high" }); }
  catch (err) { ratioThrew = err; }
  check("zipBombPolicy refuses a non-numeric expansion ratio", ratioThrew !== null);
  check("zipBombPolicy accepts a fractional expansion ratio",
        b.guardArchive.zipBombPolicy({ maxExpansionRatio: 1.5 }).maxExpansionRatio === 1.5);

  // Highly compressible payload → expansion ratio well above the default 100.
  var raw = Buffer.alloc(10000);
  var deflated = zlib.deflateRawSync(raw);
  var bytes = buildClassicZip([{ name: "z.bin", data: deflated, method: 8, usize: raw.length, csize: deflated.length }]);
  var e2 = await _inspectErr(bytes);
  check("archive-read: expansion-ratio cap trips", _hasCode(e2, "archive-read/expansion-ratio"));
}

// Deterministic, effectively incompressible bytes (sha256 chain off a fixed
// seed) so the entry's real deflate ratio is stable across runs.
function _incompressibleBytes(nBytes) {
  var crypto = require("node:crypto");
  var out = Buffer.alloc(nBytes);
  var block = crypto.createHash("sha256").update("blamejs-archive-ratio-fixture").digest();
  var pos = 0;
  while (pos < nBytes) {
    block = crypto.createHash("sha256").update(block).digest();
    var n = Math.min(block.length, nBytes - pos);
    block.copy(out, pos, 0, n);
    pos += n;
  }
  return out;
}

// The per-entry inflate must honor the operator's bombPolicy.maxExpansionRatio,
// not a stricter hardcoded default buried in the safeDecompress composition.
// A ~55:1 entry sits far under the reader's own default cap (100) and under an
// operator-raised cap (1000), yet the DEFLATE decode refused it because
// _decompressEntry composed b.safeDecompress WITHOUT forwarding maxRatio, so
// safeDecompress fell back to its own DEFAULT_MAX_RATIO (50) — silently
// overriding the operator's policy for every entry that compresses better than
// 50:1 (logs / JSON / zero-padded binaries). Root: archive-read/_decompressEntry.
async function testExpansionRatioHonorsPolicy() {
  var payload = Buffer.concat([_incompressibleBytes(1000), Buffer.alloc(60000, 0)]);
  var deflated = zlib.deflateRawSync(payload);
  var ratio = payload.length / deflated.length;
  // Precondition: the fixture ratio must sit in (50, 100] — above safe-decompress's
  // hardcoded 50 default, below the reader's own default policy cap of 100.
  check("archive-read: ratio fixture lands in (50, 100]", ratio > 50 && ratio <= 100);

  var bytes = buildClassicZip([{
    name: "log.txt", data: deflated, method: 8,
    usize: payload.length, csize: deflated.length,
  }]);

  // Operator RAISES the ratio cap to 1000 — comfortably above the ~55:1 entry.
  var generous = {
    maxEntries: 1000, maxExpansionRatio: 1000,
    maxEntryDecompressedBytes: 128 * 1024 * 1024,
    maxTotalDecompressedBytes: 4 * 1024 * 1024 * 1024,
  };
  var got = [];
  for await (var e of b.archive.read.zip(b.archive.adapters.buffer(bytes),
      { bombPolicy: generous, guardProfile: false }).extractEntries()) {
    got.push(e);
  }
  check("archive-read: entry within operator maxExpansionRatio extracts (policy honored)",
    got.length === 1 && got[0].bytes.equals(payload));

  // Operator LOWERS the ratio cap below the entry's real ratio — still refused,
  // proving the enforced cap tracks the operator value (not a hardcoded 50).
  var strict = Object.assign({}, generous, { maxExpansionRatio: 30 });
  var refused = null;
  try {
    var r2 = b.archive.read.zip(b.archive.adapters.buffer(bytes),
      { bombPolicy: strict, guardProfile: false });
    for await (var x of r2.extractEntries()) { void x; }
  } catch (err) { refused = err; }
  check("archive-read: entry above operator maxExpansionRatio refused",
    _hasCode(refused, "archive-read/expansion-ratio"));
}

// STORE + DEFLATE + unsupported-method decode paths + inspect() method labels.
async function testDecompressPaths() {
  var opts = { guardProfile: false };

  var payload = Buffer.from("deflate round-trip payload with some entropy 1234567890", "utf8");
  var deflated = zlib.deflateRawSync(payload);
  var dbytes = buildClassicZip([{ name: "d.txt", data: deflated, method: 8, usize: payload.length, csize: deflated.length }]);
  var dr = b.archive.read.zip(b.archive.adapters.buffer(dbytes), opts);
  var got = null;
  for await (var e of dr.extractEntries()) { got = e; }
  check("archive-read: DEFLATE entry inflates to exact bytes", got && got.bytes.equals(payload));
  var di = await dr.inspect();
  check("archive-read: inspect maps DEFLATE method label", di[0].method === "deflate");

  var e2 = await _extractEntriesErr(buildClassicZip([{ name: "s.txt", data: Buffer.from("ABCDE"), csize: 5, usize: 7 }]), opts);
  check("archive-read: STORE size mismatch refused", _hasCode(e2, "archive-read/store-size-mismatch"));

  var umBytes = buildClassicZip([{ name: "u.bin", data: Buffer.from("QQ"), method: 99 }]);
  var e3 = await _extractEntriesErr(umBytes, opts);
  check("archive-read: unsupported method refused", _hasCode(e3, "archive-read/unsupported-method"));
  var ui = await b.archive.read.zip(b.archive.adapters.buffer(umBytes), opts).inspect();
  check("archive-read: inspect maps unknown method label", ui[0].method === "method-99");

  var empBytes = buildClassicZip([{ name: "empty.txt", data: Buffer.alloc(0) }]);
  var emptyGot = null;
  for await (var ee of b.archive.read.zip(b.archive.adapters.buffer(empBytes), opts).extractEntries()) { emptyGot = ee; }
  check("archive-read: empty entry yields zero-length buffer", emptyGot && emptyGot.bytes.length === 0);

  // DEFLATE inflate-size mismatch — declared uncompressed size overstates the
  // actual inflated length (still under the per-entry cap, so it reaches the
  // post-inflate size check rather than a bomb refusal).
  var infl = Buffer.from("0123456789", "utf8");
  var inflDef = zlib.deflateRawSync(infl);
  var inflBytes = buildClassicZip([{ name: "m.txt", data: inflDef, method: 8, usize: 20, csize: inflDef.length }]);
  var e4 = await _extractEntriesErr(inflBytes, opts);
  check("archive-read: DEFLATE inflate-size mismatch refused", _hasCode(e4, "archive-read/inflate-size-mismatch"));

  // extractEntries skips directory entries (no bytes yielded for them).
  var dirMix = buildClassicZip([
    { name: "d", externalAttrs: EXT_DIR },
    { name: "d/inner.txt", data: Buffer.from("in") },
  ]);
  var dirNames = [];
  for await (var de of b.archive.read.zip(b.archive.adapters.buffer(dirMix), opts).extractEntries()) { dirNames.push(de.name); }
  check("archive-read: extractEntries skips directory entries",
    dirNames.length === 1 && dirNames[0] === "d/inner.txt");
}

// b.archive.read.zip factory adapter-shape guards.
async function testZipFactoryAdapterGuards() {
  var e1 = null;
  try { b.archive.read.zip(null); } catch (err) { e1 = err; }
  check("archive-read: null adapter refused", _hasCode(e1, "archive-read/bad-adapter"));

  var e2 = null;
  try { b.archive.read.zip({ kind: "bogus" }); } catch (err) { e2 = err; }
  check("archive-read: wrong-kind adapter refused", _hasCode(e2, "archive-read/bad-adapter"));

  var nodeStream = require("node:stream");
  var readable = new nodeStream.Readable({ read: function () {} });
  var e3 = null;
  try { b.archive.read.zip(b.archive.adapters.trustedStream(readable)); }
  catch (err) { e3 = err; }
  finally { readable.destroy(); }
  check("archive-read: trusted-stream adapter at random-access entry refused",
    _hasCode(e3, "archive-read/wrong-entry-point"));
}

// Entry-type classification surfaced on inspect() for every unix mode marker.
async function testEntryTypeClassification() {
  var bytes = buildClassicZip([
    { name: "link",     externalAttrs: EXT_SYMLINK,  data: Buffer.from("target") },
    { name: "sock",     externalAttrs: EXT_SOCKET },
    { name: "pipe",     externalAttrs: EXT_FIFO },
    { name: "cdev",     externalAttrs: EXT_CHARDEV },
    { name: "bdev",     externalAttrs: EXT_BLOCKDEV },
    { name: "dattr",    externalAttrs: EXT_DIR },
    { name: "dslash/",  data: Buffer.alloc(0) },
    { name: "file.txt", data: Buffer.from("hi") },
  ]);
  var entries = await b.archive.read.zip(b.archive.adapters.buffer(bytes)).inspect();
  var byName = {};
  entries.forEach(function (e) { byName[e.name] = e.entryType; });
  check("classify: symlink attrs",                byName["link"] === "symlink");
  check("classify: socket attrs",                 byName["sock"] === "socket");
  check("classify: fifo attrs",                   byName["pipe"] === "fifo");
  check("classify: char device attrs",            byName["cdev"] === "device");
  check("classify: block device attrs",           byName["bdev"] === "device");
  check("classify: directory via unix mode attrs", byName["dattr"] === "directory");
  check("classify: directory via trailing slash", byName["dslash/"] === "directory");
  check("classify: regular file",                 byName["file.txt"] === "file");
}

// entryTypePolicy refuses dangerous-by-default entry types on both extract
// paths (guardProfile:false isolates the type check from the guard cascade).
async function testEntryTypePolicyRefusals() {
  var opts = { guardProfile: false };
  async function refuse(attrs, label) {
    var bytes = buildClassicZip([{ name: "n", externalAttrs: attrs, data: Buffer.from("x") }]);
    var e = await _extractEntriesErr(bytes, opts);
    check("entry-type policy refuses " + label,
      _hasCode(e, "archive-read/entry-type-refused") && (e.message || "").indexOf(label) !== -1);
  }
  await refuse(EXT_SYMLINK,  "symlink");
  await refuse(EXT_CHARDEV,  "device");
  await refuse(EXT_FIFO,     "fifo");
  await refuse(EXT_SOCKET,   "socket");

  var dest = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-artype-"));
  var e = null;
  try {
    await b.archive.read.zip(
      b.archive.adapters.buffer(buildClassicZip([{ name: "lnk", externalAttrs: EXT_SYMLINK, data: Buffer.from("t") }])), opts
    ).extract({ destination: dest });
  } catch (err) { e = err; }
  finally { fs.rmSync(dest, { recursive: true, force: true }); }
  check("entry-type policy refuses symlink on disk extract", _hasCode(e, "archive-read/entry-type-refused"));
}

// Encrypted entries are refused (this reader never decrypts) on both paths.
async function testEncryptedEntryRefusal() {
  var opts = { guardProfile: false };
  var FLAG_ENCRYPTED = 0x0001;
  var bytes = buildClassicZip([{ name: "enc.txt", data: Buffer.from("cipher"), flags: FLAG_ENCRYPTED }]);

  var e1 = await _extractEntriesErr(bytes, opts);
  check("archive-read: encrypted entry refused (extractEntries)", _hasCode(e1, "archive-read/encrypted-entry"));

  var dest = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-enc-"));
  var e2 = null;
  try { await b.archive.read.zip(b.archive.adapters.buffer(bytes), opts).extract({ destination: dest }); }
  catch (err) { e2 = err; }
  finally { fs.rmSync(dest, { recursive: true, force: true }); }
  check("archive-read: encrypted entry refused (disk extract)", _hasCode(e2, "archive-read/encrypted-entry"));
}

// The raw-entry async generators on both reader variants.
async function testEntriesGenerators() {
  var z = b.archive.zip();
  z.addFile("a.txt", "A");
  z.addFile("b.txt", "B");
  var bytes = z.toBuffer();

  var names = [];
  for await (var e of b.archive.read.zip(b.archive.adapters.buffer(bytes)).entries()) { names.push(e.name); }
  check("archive-read: entries() random-access generator yields raw entries",
    names.length === 2 && names.indexOf("a.txt") !== -1);

  var nodeStream = require("node:stream");
  var tnames = [];
  var tr = b.archive.read.zip.fromTrustedStream(
    b.archive.adapters.trustedStream(nodeStream.Readable.from(bytes)));
  for await (var te of tr.entries()) { tnames.push(te.name); }
  check("archive-read: entries() trusted-stream generator yields entries", tnames.length === 2);
}

// Disk extract(): no-destination refusal, destination auto-create, directory
// materialization, and atomic rollback of a partial extract on a later error.
async function testExtractDirAndCleanup() {
  var opts = { guardProfile: false };

  var e0 = null;
  try { await b.archive.read.zip(b.archive.adapters.buffer(buildClassicZip([{ name: "a.txt", data: Buffer.from("x") }])), opts).extract({}); }
  catch (err) { e0 = err; }
  check("archive-read: extract without destination refused", _hasCode(e0, "archive-read/no-destination"));

  var eEmpty = null;
  try { await b.archive.read.zip(b.archive.adapters.buffer(buildClassicZip([{ name: "a.txt", data: Buffer.from("x") }])), opts).extract({ destination: "" }); }
  catch (err) { eEmpty = err; }
  check("archive-read: extract with empty destination string refused", _hasCode(eEmpty, "archive-read/no-destination"));

  var eBare = null;
  try { await b.archive.read.zip(b.archive.adapters.buffer(buildClassicZip([{ name: "a.txt", data: Buffer.from("x") }])), opts).extract(); }
  catch (err) { eBare = err; }
  check("archive-read: extract() with no options refused", _hasCode(eBare, "archive-read/no-destination"));

  var base = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-extdir-"));
  var dest = path.join(base, "nested-not-there");   // does not exist yet
  try {
    var dbytes = buildClassicZip([
      { name: "subdir", externalAttrs: EXT_DIR },
      { name: "subdir/f.txt", data: Buffer.from("inside\n") },
    ]);
    var res = await b.archive.read.zip(b.archive.adapters.buffer(dbytes), opts).extract({ destination: dest });
    check("archive-read: extract auto-creates destination + writes file", res.bytesExtracted === 7);
    check("archive-read: directory entry materialized", fs.existsSync(path.join(dest, "subdir")));
    check("archive-read: file under directory restored",
      fs.readFileSync(path.join(dest, "subdir", "f.txt"), "utf8") === "inside\n");
  } finally {
    fs.rmSync(base, { recursive: true, force: true });
  }

  var base2 = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-extcleanup-"));
  try {
    var mixed = buildClassicZip([
      { name: "ok.txt",  data: Buffer.from("kept-until-rollback\n") },
      { name: "bad.bin", data: Buffer.from("ZZ"), method: 99 },
    ]);
    var e2 = null;
    try { await b.archive.read.zip(b.archive.adapters.buffer(mixed), opts).extract({ destination: base2 }); }
    catch (err) { e2 = err; }
    check("archive-read: extract aborts on a later bad entry", _hasCode(e2, "archive-read/unsupported-method"));
    check("archive-read: partial file rolled back on abort", !fs.existsSync(path.join(base2, "ok.txt")));
  } finally {
    fs.rmSync(base2, { recursive: true, force: true });
  }
}

// ZIP64 trailer (EOCD64 record + locator) corruption refusals.
async function testZip64TrailerErrors() {
  var payload = Buffer.from("zip64 trailer error fixtures", "utf8");
  var z = b.archive.zip();
  z.addFile("z.txt", payload);
  var crc = (await b.archive.read.zip(b.archive.adapters.buffer(z.toBuffer())).inspect())[0].crc;

  function base() { return buildZip64Store("z.txt", payload, crc); }
  var LOC = 22 + 20;         // locator starts 42 bytes from EOF
  var E64 = 22 + 20 + 56;    // eocd64 record starts 98 bytes from EOF

  var b1 = base(); b1.writeUInt32LE(0xdeadbeef, b1.length - LOC);
  var e1 = await _inspectErr(b1);
  check("zip64: bad locator signature refused", _hasCode(e1, "archive-read/zip64-locator-missing"));

  var b2 = base(); b2.writeUInt32LE(2, b2.length - LOC + 16);
  var e2 = await _inspectErr(b2);
  check("zip64: multi-disk locator refused", _hasCode(e2, "archive-read/multi-disk"));

  var b3 = base(); b3.writeBigUInt64LE(BigInt(b3.length + 1000), b3.length - LOC + 8);
  var e3 = await _inspectErr(b3);
  check("zip64: EOCD64 offset past EOF refused", _hasCode(e3, "archive-read/zip64-eocd-out-of-range"));

  var b4 = base(); b4.writeUInt32LE(0xdeadbeef, b4.length - E64);
  var e4 = await _inspectErr(b4);
  check("zip64: bad EOCD64 record signature refused", _hasCode(e4, "archive-read/zip64-eocd-bad-signature"));

  // Classic EOCD carries a sentinel but sits at offset 0 — no room for a locator.
  var tiny = Buffer.alloc(22);
  tiny.writeUInt32LE(0x06054b50, 0);
  tiny.writeUInt16LE(1, 8); tiny.writeUInt16LE(1, 10);
  tiny.writeUInt32LE(0xffffffff, 12); tiny.writeUInt32LE(0xffffffff, 16);
  var e5 = await _inspectErr(tiny);
  check("zip64: sentinel with no room for locator refused", _hasCode(e5, "archive-read/zip64-locator-missing"));

  // EOCD64 resolves cdSize to a literal 0xFFFFFFFF, which the CD walk still
  // treats as an unresolved sentinel and refuses.
  var b6 = base();
  b6.writeBigUInt64LE(0xffffffffn, (b6.length - E64) + 40);
  var e6 = await _inspectErr(b6);
  check("zip64: EOCD64 leaves an unresolved sentinel refused", _hasCode(e6, "archive-read/zip64-eocd-unresolved"));
}

// ZIP64 extended-information extra field (§4.5.3) corruption refusals.
async function testZip64ExtraErrors() {
  var payload = Buffer.from("x", "utf8");
  var z = b.archive.zip();
  z.addFile("z.txt", payload);
  var crc = (await b.archive.read.zip(b.archive.adapters.buffer(z.toBuffer())).inspect())[0].crc;

  function zip64Extra(id, dataBuf) {
    var e = Buffer.alloc(4 + dataBuf.length);
    e.writeUInt16LE(id, 0);
    e.writeUInt16LE(dataBuf.length, 2);
    dataBuf.copy(e, 4);
    return e;
  }
  function withExtra(extra, more) {
    var o = { cdExtraOverride: extra };
    if (more) { Object.keys(more).forEach(function (k) { o[k] = more[k]; }); }
    return buildZip64Store("z.txt", payload, crc, o);
  }

  var huge = Buffer.alloc(16);
  huge.writeBigUInt64LE(1n << 53n, 0);                    // > Number.MAX_SAFE_INTEGER
  huge.writeBigUInt64LE(BigInt(payload.length), 8);
  var e1 = await _inspectErr(withExtra(zip64Extra(0x0001, huge)));
  check("zip64: extra value exceeding MAX_SAFE_INTEGER refused", _hasCode(e1, "archive-read/zip64-value-too-large"));

  var e2 = await _inspectErr(withExtra(zip64Extra(0x0001, Buffer.alloc(0))));
  check("zip64: extra truncated (uncompressed) refused", _hasCode(e2, "archive-read/zip64-extra-truncated"));

  var e3 = await _inspectErr(withExtra(zip64Extra(0x0001, Buffer.alloc(8))));
  check("zip64: extra truncated (compressed) refused", _hasCode(e3, "archive-read/zip64-extra-truncated"));

  var e4 = await _inspectErr(withExtra(zip64Extra(0x0001, Buffer.alloc(16)), { offsetSentinel: true }));
  check("zip64: extra truncated (lfh offset) refused", _hasCode(e4, "archive-read/zip64-extra-truncated"));

  var e5 = await _inspectErr(withExtra(zip64Extra(0x0001, Buffer.alloc(24)), { offsetSentinel: true, diskSentinel: true }));
  check("zip64: extra truncated (disk start) refused", _hasCode(e5, "archive-read/zip64-extra-truncated"));

  var withDisk = Buffer.alloc(28); withDisk.writeUInt32LE(1, 24);
  var e6 = await _inspectErr(withExtra(zip64Extra(0x0001, withDisk), { offsetSentinel: true, diskSentinel: true }));
  check("zip64: non-zero disk start refused", _hasCode(e6, "archive-read/multi-disk"));

  var e7 = await _inspectErr(withExtra(zip64Extra(0x9999, Buffer.alloc(0))));
  check("zip64: sentinel with no 0x0001 extra block refused", _hasCode(e7, "archive-read/zip64-extra-missing"));

  var badHeader = Buffer.alloc(4);
  badHeader.writeUInt16LE(0x0001, 0);
  badHeader.writeUInt16LE(100, 2);   // claims 100 bytes of data that aren't present
  var e8 = await _inspectErr(withExtra(badHeader));
  check("zip64: truncated extra header refused", _hasCode(e8, "archive-read/zip64-extra-missing"));

  // A fully-present extra with a valid (zero) disk start resolves cleanly —
  // the success side of the disk-start check.
  var full = Buffer.alloc(28);
  full.writeBigUInt64LE(BigInt(payload.length), 0);   // uncompressedSize
  full.writeBigUInt64LE(BigInt(payload.length), 8);   // compressedSize
  full.writeBigUInt64LE(0n, 16);                      // localHeaderOffset
  full.writeUInt32LE(0, 24);                          // diskStart = 0 (valid, single-disk)
  var okEntries = await b.archive.read.zip(
    b.archive.adapters.buffer(withExtra(zip64Extra(0x0001, full), { offsetSentinel: true, diskSentinel: true }))
  ).inspect();
  check("zip64: full extra with disk-start 0 resolves the entry",
    okEntries.length === 1 && okEntries[0].size === payload.length);
}

// objectStore adapter delivers size via resolveSize() (not a static .size),
// exercising the reader's deferred-size EOCD-locate branch.
async function testObjectStoreAdapterResolveSize() {
  var z = b.archive.zip();
  z.addFile("a.txt", "object-store payload");
  var bytes = z.toBuffer();
  var client = {
    head: async function () { return { size: bytes.length }; },
    get: async function (key, o) {
      var start = o.range[0], end = o.range[1];
      var slice = Buffer.allocUnsafe(end - start + 1);
      bytes.copy(slice, 0, start, end + 1);
      return slice;
    },
  };
  var adapter = b.archive.adapters.objectStore(client, "incoming/a.zip");
  var entries = await b.archive.read.zip(adapter).inspect();
  check("archive-read: objectStore adapter resolveSize path decodes",
    entries.length === 1 && entries[0].name === "a.txt");
}

// Split a framework-written classic STORE archive into its local region,
// central directory and EOCD.
function _zipParts(buf) {
  var e = buf.length - 22;
  var cdSize = buf.readUInt32LE(e + 12);
  var cdOffset = buf.readUInt32LE(e + 16);
  return {
    body: buf.subarray(0, cdOffset),
    cd:   buf.subarray(cdOffset, cdOffset + cdSize),
    eocd: buf.subarray(e),
  };
}

function _storeZipOf(name, body) {
  var z = b.archive.zip();
  z.addFile(name, Buffer.from(body), { method: "store" });
  return Buffer.from(z.toBuffer());
}

// The EOCD's central-directory offset and the ZIP64 locator's EOCD64 offset
// must name the structures that actually sit before the EOCD. A reader that
// takes them as written reads a different set of entries than a reader that
// locates the directory from the end of the file.
async function testCdPositionRefusals() {
  var opts = { guardProfile: false };

  // Two complete ZIP bodies in one file. The final EOCD carries the second
  // body's CD size and the first body's CD offset. A reader that locates the
  // CD as (eocdOffset - cdSize) reads good.txt; a reader that trusts cdOffset
  // reads evil.txt.
  var a = _zipParts(_storeZipOf("evil.txt", "EVIL-PAYLOAD\n"));
  var g = _zipParts(_storeZipOf("good.txt", "GOOD-CONTENT\n"));
  var amb = Buffer.from(g.eocd);
  amb.writeUInt32LE(a.body.length, 16);
  var ambiguous = Buffer.concat([a.body, a.cd, g.body, g.cd, amb]);
  var e1 = await _extractEntriesErr(ambiguous, opts);
  check("zip cd-position: two-body archive with a CD offset that does not end at the EOCD is refused",
    _hasCode(e1, "archive-read/cd-position-mismatch"), e1 ? String(e1.code) : "read without error");
  var e1i = await _inspectErr(ambiguous);
  check("zip cd-position: inspect() refuses the same archive",
    _hasCode(e1i, "archive-read/cd-position-mismatch"));

  // A CD offset pointing at the start of a valid directory that is followed
  // by unrelated bytes before the EOCD.
  var trailingGap = buildClassicZip([{ name: "a.txt", data: Buffer.from("alpha") }]);
  var tp = _zipParts(trailingGap);
  var gapped = Buffer.concat([tp.body, tp.cd, Buffer.alloc(16, 0x41), tp.eocd]);
  var e2 = await _inspectErr(gapped);
  check("zip cd-position: bytes between the CD and the EOCD are refused",
    _hasCode(e2, "archive-read/cd-position-mismatch"));

  // Prepended data (self-extractor stub) shifts every recorded offset.
  var prepended = Buffer.concat([Buffer.alloc(32, 0x4d), trailingGap]);
  var e3 = await _inspectErr(prepended);
  check("zip cd-position: prepended data is refused, not read at a guessed delta",
    _hasCode(e3, "archive-read/cd-position-mismatch"));

  // A CD whose declared size is larger than the entries the EOCD count
  // walks: the surplus can hold a second CD record another reader lists.
  var hidden = buildClassicZip([{ name: "a.txt", data: Buffer.from("alpha") }]);
  var hp = _zipParts(hidden);
  var extraCd = Buffer.from(hp.cd);
  var surplus = buildClassicZip(
    [{ name: "a.txt", data: Buffer.from("alpha") }],
    { cdTrailing: extraCd, totalEntries: 1 });
  var e4 = await _inspectErr(surplus);
  check("zip cd-position: CD bytes past the last counted entry are refused",
    _hasCode(e4, "archive-read/cd-size-mismatch"), e4 ? String(e4.code) : "read without error");

  // entries-on-this-disk disagreeing with total entries.
  var diskCount = buildClassicZip([
    { name: "a.txt", data: Buffer.from("alpha") },
    { name: "b.txt", data: Buffer.from("beta") },
  ], { entriesOnDisk: 1 });
  var e5 = await _inspectErr(diskCount);
  check("zip cd-position: EOCD entries-on-disk disagreeing with total entries is refused",
    _hasCode(e5, "archive-read/eocd-inconsistent"));

  // An entry count of zero with a non-empty central directory.
  var zeroCount = buildClassicZip([{ name: "a.txt", data: Buffer.from("alpha") }], { totalEntries: 0 });
  var e6 = await _inspectErr(zeroCount);
  check("zip cd-position: a zero entry count over a non-empty CD is refused",
    _hasCode(e6, "archive-read/cd-size-mismatch"));

  // A local-header offset at or past the central directory.
  var lfhInCd = buildClassicZip([{ name: "a.txt", data: Buffer.from("alpha"), cdLfhOffset: 40 }]);
  var e7 = await _inspectErr(lfhInCd);
  check("zip cd-position: a local-header offset inside the CD is refused",
    _hasCode(e7, "archive-read/entry-out-of-range"));

  // Two CD entries sharing one local header, and an entry whose data runs
  // over the next entry's local header (the overlapping-entry bomb shape).
  var shared = buildClassicZip([
    { name: "a.txt", data: Buffer.from("alpha") },
    { name: "b.txt", data: Buffer.from("beta"), cdLfhOffset: 0 },
  ]);
  var e8 = await _inspectErr(shared);
  check("zip cd-position: two entries sharing one local header are refused",
    _hasCode(e8, "archive-read/entry-overlap"));
  var overrun = buildClassicZip([
    { name: "a.txt", data: Buffer.from("alpha"), csize: 40, usize: 40 },
    { name: "b.txt", data: Buffer.from("beta") },
  ]);
  var e9 = await _inspectErr(overrun);
  check("zip cd-position: entry data running over the next local header is refused",
    _hasCode(e9, "archive-read/entry-overlap"));

  // A local header whose name length pushes its data past the CD is refused
  // with an archive code before the oversized name is read, and an empty
  // local-header name is a name skew.
  var longName = Buffer.from(trailingGap);
  longName.writeUInt16LE(0xffff, 26);
  var e9b = await _extractEntriesErr(longName, opts);
  check("zip cd-position: a local-header name length reaching past the CD is refused",
    _hasCode(e9b, "archive-read/entry-overlap"), e9b ? String(e9b.code) : "extracted without error");
  var noName = Buffer.from(trailingGap);
  noName.writeUInt16LE(0, 26);
  var e9c = await _extractEntriesErr(noName, opts);
  check("zip cd-position: an empty local-header name is a name skew",
    _hasCode(e9c, "archive-read/lfh-cd-skew"), e9c ? String(e9c.code) : "extracted without error");

  // ZIP64: the locator must name the EOCD64 record that ends where the
  // locator begins.
  var payload = Buffer.from("zip64 adjacency fixture", "utf8");
  var crc = zlib.crc32(payload) >>> 0;
  var z64gap = buildZip64Store("z.txt", payload, crc, { eocd64Gap: 8 });
  var e10 = await _inspectErr(z64gap);
  check("zip cd-position: ZIP64 EOCD record not adjacent to its locator is refused",
    _hasCode(e10, "archive-read/zip64-eocd-not-adjacent"), e10 ? String(e10.code) : "read without error");

  // ZIP64: a classic EOCD field that is not a sentinel must agree with the
  // EOCD64 record.
  var z64count = buildZip64Store("z.txt", payload, crc, { classicCount: 2 });
  var e11 = await _inspectErr(z64count);
  check("zip cd-position: classic entry count disagreeing with EOCD64 is refused",
    _hasCode(e11, "archive-read/eocd-inconsistent"), e11 ? String(e11.code) : "read without error");
  var z64size = buildZip64Store("z.txt", payload, crc, { classicCdSize: 7 });
  var e12 = await _inspectErr(z64size);
  check("zip cd-position: classic CD size disagreeing with EOCD64 is refused",
    _hasCode(e12, "archive-read/eocd-inconsistent"), e12 ? String(e12.code) : "read without error");

  // Controls: the shapes the checks must keep reading.
  var okClassic = await b.archive.read.zip(b.archive.adapters.buffer(trailingGap)).inspect();
  check("zip cd-position: a well-formed classic archive still reads", okClassic.length === 1);
  var okZ64 = buildZip64Store("z.txt", payload, crc);
  var gotZ64 = null;
  for await (var ez of b.archive.read.zip(b.archive.adapters.buffer(okZ64), opts).extractEntries()) { gotZ64 = ez; }
  check("zip cd-position: a well-formed ZIP64 archive still extracts", gotZ64 && gotZ64.bytes.equals(payload));
  var z64CdSize = okZ64.readUInt32LE(okZ64.length - 98 + 40);
  var z64CdOffset = okZ64.readUInt32LE(okZ64.length - 98 + 48);
  var okZ64Real = buildZip64Store("z.txt", payload, crc, { classicCount: 1, classicCdSize: z64CdSize });
  var e13 = await _inspectErr(okZ64Real);
  check("zip cd-position: classic fields equal to EOCD64 values are accepted", e13 === null,
    e13 ? String(e13.code) : "");

  // A ZIP64 trailer with no sentinel in the classic EOCD (every classic
  // field holds the real value). The CD ends at the EOCD64 record, not at
  // the classic EOCD, so the reader resolves the trailer through the locator
  // and still requires the two records to agree.
  var noSentinel = buildZip64Store("z.txt", payload, crc,
    { classicCount: 1, classicCdSize: z64CdSize, classicCdOffset: z64CdOffset });
  var gotNs = null;
  for await (var ens of b.archive.read.zip(b.archive.adapters.buffer(noSentinel), opts).extractEntries()) { gotNs = ens; }
  check("zip cd-position: ZIP64 trailer without classic sentinels still extracts",
    gotNs && gotNs.bytes.equals(payload));
  var noSentinelSkew = buildZip64Store("z.txt", payload, crc,
    { classicCount: 1, classicCdSize: z64CdSize, classicCdOffset: z64CdOffset + 1 });
  var e14 = await _inspectErr(noSentinelSkew);
  check("zip cd-position: ZIP64 trailer without sentinels whose classic offset disagrees is refused",
    _hasCode(e14, "archive-read/eocd-inconsistent"), e14 ? String(e14.code) : "read without error");
  var commented = Buffer.concat([trailingGap.subarray(0, trailingGap.length - 2), Buffer.from([5, 0]), Buffer.from("hello")]);
  var okComment = await b.archive.read.zip(b.archive.adapters.buffer(commented)).inspect();
  check("zip cd-position: an archive comment after the EOCD still reads", okComment.length === 1);
}

// Prepend `prefix` to a framework-written classic archive and move every
// recorded offset by its length, the way `zip -A` adjusts a self-extractor.
function _withAdjustedPrefix(prefix, zipBuf) {
  var p = _zipParts(zipBuf);
  var delta = prefix.length;
  var cd = Buffer.from(p.cd);
  var pos = 0;
  while (pos < cd.length) {
    cd.writeUInt32LE(cd.readUInt32LE(pos + 42) + delta, pos + 42);
    pos += 46 + cd.readUInt16LE(pos + 28) + cd.readUInt16LE(pos + 30) + cd.readUInt16LE(pos + 32);
  }
  var eocd = Buffer.from(p.eocd);
  eocd.writeUInt32LE(eocd.readUInt32LE(16) + delta, 16);
  return Buffer.concat([prefix, p.body, cd, eocd]);
}

function _rawLfh(name, data) {
  var n = Buffer.from(name, "utf8");
  var h = Buffer.alloc(30);
  h.writeUInt32LE(SIG_LFH_OK, 0);
  h.writeUInt16LE(20, 4);
  h.writeUInt16LE(0x21, 12);
  h.writeUInt32LE(zlib.crc32(data) >>> 0, 14);
  h.writeUInt32LE(data.length, 18);
  h.writeUInt32LE(data.length, 22);
  h.writeUInt16LE(n.length, 26);
  return Buffer.concat([h, n, data]);
}

function _rawCfh(name, data, lfhOffset, comment) {
  var n = Buffer.from(name, "utf8");
  var c = comment || Buffer.alloc(0);
  var h = Buffer.alloc(46);
  h.writeUInt32LE(SIG_CFH_OK, 0);
  h.writeUInt16LE(20, 4);
  h.writeUInt16LE(20, 6);
  h.writeUInt16LE(0x21, 14);
  h.writeUInt32LE(zlib.crc32(data) >>> 0, 16);
  h.writeUInt32LE(data.length, 20);
  h.writeUInt32LE(data.length, 24);
  h.writeUInt16LE(n.length, 28);
  h.writeUInt16LE(c.length, 32);
  h.writeUInt32LE(lfhOffset >>> 0, 42);
  return Buffer.concat([h, n, c]);
}

function _rawEocd(count, cdSize, cdOffset) {
  var e = Buffer.alloc(22);
  e.writeUInt32LE(SIG_EOCD_OK, 0);
  e.writeUInt16LE(count, 8);
  e.writeUInt16LE(count, 10);
  e.writeUInt32LE(cdSize >>> 0, 12);
  e.writeUInt32LE(cdOffset >>> 0, 16);
  return e;
}

function _rawZip64Trailer(count, cdSize, cdOffset, recordOffset) {
  var r = Buffer.alloc(56);
  r.writeUInt32LE(0x06064b50, 0);
  r.writeBigUInt64LE(44n, 4);
  r.writeUInt16LE(45, 12);
  r.writeUInt16LE(45, 14);
  r.writeBigUInt64LE(BigInt(count), 24);
  r.writeBigUInt64LE(BigInt(count), 32);
  r.writeBigUInt64LE(BigInt(cdSize), 40);
  r.writeBigUInt64LE(BigInt(cdOffset), 48);
  var l = Buffer.alloc(20);
  l.writeUInt32LE(0x07064b50, 0);
  l.writeBigUInt64LE(BigInt(recordOffset), 8);
  l.writeUInt32LE(1, 16);
  return Buffer.concat([r, l]);
}

async function _extractNames(bytes) {
  var out = [];
  var r = b.archive.read.zip(b.archive.adapters.buffer(bytes), { guardProfile: false });
  for await (var e of r.extractEntries()) out.push(e.name + "=" + e.bytes.toString("utf8"));
  return out.join(",");
}

// A second archive hidden where another ZIP reader finds it: a ZIP64 end
// record inside the last central-directory comment (the CVE-2025-8291
// shape), or a complete archive in the bytes before the first local header
// that the central directory references.
async function testHiddenArchiveRefusals() {
  var opts = { guardProfile: false };
  var GOOD = Buffer.from("GOOD-CONTENT\n");
  var EVIL = Buffer.from("EVIL-PAYLOAD\n");

  // The classic EOCD names good.txt and its CD ends exactly at the EOCD.
  // The last 76 bytes of good.txt's CD comment are a ZIP64 end record and
  // locator that name a CD listing evil.txt. Python 3.11 zipfile lists
  // evil.txt from this file.
  var lg = _rawLfh("good.txt", GOOD);
  var le = _rawLfh("evil.txt", EVIL);
  var local = Buffer.concat([lg, le]);
  var goodCdOff = local.length;
  var evilCd = _rawCfh("evil.txt", EVIL, lg.length);
  var evilCdOff = goodCdOff + 46 + "good.txt".length;
  var recOff = evilCdOff + evilCd.length;
  var hiddenComment = Buffer.concat([evilCd, _rawZip64Trailer(1, evilCd.length, evilCdOff, recOff)]);
  var goodCd = _rawCfh("good.txt", GOOD, 0, hiddenComment);
  var hidden = Buffer.concat([local, goodCd, _rawEocd(1, goodCd.length, goodCdOff)]);
  var eh1 = await _extractEntriesErr(hidden, opts);
  check("zip hidden archive: a ZIP64 end record in the last CD comment that disagrees with the EOCD is refused",
    _hasCode(eh1, "archive-read/eocd-inconsistent"), eh1 ? String(eh1.code) : "read without error");
  var eh1i = await _inspectErr(hidden);
  check("zip hidden archive: inspect() refuses the hidden ZIP64 end record",
    _hasCode(eh1i, "archive-read/eocd-inconsistent"), eh1i ? String(eh1i.code) : "read without error");

  // The same hiding place with a ZIP64 record whose values equal the classic
  // EOCD: the record sits inside the CD it describes.
  var agreeComment = Buffer.alloc(76);
  var agreeCd = _rawCfh("good.txt", GOOD, 0, agreeComment);
  var agreeRecOff = lg.length + agreeCd.length - 76;
  _rawZip64Trailer(1, agreeCd.length, lg.length, agreeRecOff).copy(agreeCd, agreeCd.length - 76);
  var agree = Buffer.concat([lg, agreeCd, _rawEocd(1, agreeCd.length, lg.length)]);
  var eh2 = await _inspectErr(agree);
  check("zip hidden archive: a ZIP64 end record inside the CD it describes is refused",
    _hasCode(eh2, "archive-read/cd-position-mismatch"), eh2 ? String(eh2.code) : "read without error");

  // Two complete archives in one file. The second one records absolute
  // offsets, so its CD ends at its EOCD, but a reader that walks the file
  // from the front meets the first archive's a.txt.
  var first = _storeZipOf("a.txt", "EVIL-PAYLOAD\n");
  var twoBody = _withAdjustedPrefix(first, _storeZipOf("a.txt", "GOOD-CONTENT\n"));
  var eb1 = await _extractEntriesErr(twoBody, opts);
  check("zip hidden archive: a complete archive before the first referenced local header is refused",
    _hasCode(eb1, "archive-read/embedded-archive"), eb1 ? String(eb1.code) : "read without error");
  var eb1i = await _inspectErr(twoBody);
  check("zip hidden archive: inspect() refuses the leading archive",
    _hasCode(eb1i, "archive-read/embedded-archive"), eb1i ? String(eb1i.code) : "read without error");
  var eb1t = null;
  try {
    var tr = b.archive.read.zip.fromTrustedStream(
      b.archive.adapters.trustedStream(nodeStream.Readable.from([twoBody])), opts);
    for await (var te of tr.extractEntries()) { void te; }
  } catch (err) { eb1t = err; }
  check("zip hidden archive: fromTrustedStream refuses the leading archive",
    _hasCode(eb1t, "archive-read/embedded-archive"), eb1t ? String(eb1t.code) : "read without error");
  var eb1g = null;
  try { await b.guardArchive.inspect(b.archive.adapters.buffer(twoBody), { profile: "strict" }); }
  catch (err) { eb1g = err; }
  check("zip hidden archive: b.guardArchive.inspect refuses the leading archive",
    _hasCode(eb1g, "archive-read/embedded-archive"), eb1g ? String(eb1g.code) : "read without error");

  // Each structure on its own: a lone local header with its data, a lone
  // central-directory header, and the EOCD of an empty archive.
  var loneLfh = _withAdjustedPrefix(_rawLfh("x.txt", EVIL), _storeZipOf("a.txt", "GOOD"));
  var eb2 = await _inspectErr(loneLfh);
  check("zip hidden archive: a parseable local header before the first referenced one is refused",
    _hasCode(eb2, "archive-read/embedded-archive"), eb2 ? String(eb2.code) : "read without error");
  var loneCfh = _withAdjustedPrefix(Buffer.concat([Buffer.alloc(48, 0x4d), _rawCfh("x.txt", EVIL, 0)]),
    _storeZipOf("a.txt", "GOOD"));
  var eb3 = await _inspectErr(loneCfh);
  check("zip hidden archive: a parseable central-directory header in the prefix is refused",
    _hasCode(eb3, "archive-read/embedded-archive"), eb3 ? String(eb3.code) : "read without error");
  var loneEocd = _withAdjustedPrefix(_rawEocd(0, 0, 0), _storeZipOf("a.txt", "GOOD"));
  var eb4 = await _inspectErr(loneEocd);
  check("zip hidden archive: an empty archive's EOCD in the prefix is refused",
    _hasCode(eb4, "archive-read/embedded-archive"), eb4 ? String(eb4.code) : "read without error");

  // The prefix is read in 1 MiB windows. A local header whose signature
  // starts on the last byte of the first window is still found.
  var scanWindow = 0x100000;
  var straddle = _withAdjustedPrefix(
    Buffer.concat([Buffer.alloc(scanWindow - 1), _rawLfh("x.txt", EVIL)]), _storeZipOf("a.txt", "GOOD"));
  var ebw = await _inspectErr(straddle);
  check("zip hidden archive: a local header straddling the 1 MiB scan window is refused",
    _hasCode(ebw, "archive-read/embedded-archive"), ebw ? String(ebw.code) : "read without error");

  // An archive with no entries whose CD offset sits after a complete archive.
  var emptyAfter = Buffer.concat([first, _rawEocd(0, 0, first.length)]);
  var eb5 = await _inspectErr(emptyAfter);
  check("zip hidden archive: an empty archive whose CD offset follows a complete archive is refused",
    _hasCode(eb5, "archive-read/embedded-archive"), eb5 ? String(eb5.code) : "read without error");

  // Controls. A self-extractor stub with adjusted offsets still extracts,
  // including a stub whose machine code holds the ZIP signature bytes as
  // constants that do not parse as ZIP structures.
  var plainStub = _withAdjustedPrefix(Buffer.alloc(32, 0x4d), _storeZipOf("a.txt", "GOOD-CONTENT\n"));
  var plainNames = null;
  try { plainNames = await _extractNames(plainStub); } catch (err) { plainNames = "ERR " + err.code; }
  check("zip hidden archive: a stub with adjusted offsets still extracts",
    plainNames === "a.txt=GOOD-CONTENT\n", String(plainNames));
  var codeLike = Buffer.concat([
    Buffer.from([0x7f, 0x45, 0x4c, 0x46]), Buffer.alloc(60, 0x90),
    Buffer.from([0x3d, 0x50, 0x4b, 0x03, 0x04, 0x75, 0x1c, 0xff, 0xff, 0xff, 0xff]), Buffer.alloc(40, 0xcc),
    Buffer.from([0x3d, 0x50, 0x4b, 0x01, 0x02, 0x74, 0x2a, 0xff, 0xff, 0xff, 0xff]), Buffer.alloc(60, 0xcc),
    Buffer.from([0x3d, 0x50, 0x4b, 0x05, 0x06, 0x0f, 0x85]), Buffer.alloc(40, 0xff),
  ]);
  var codeStub = _withAdjustedPrefix(codeLike, _storeZipOf("a.txt", "GOOD-CONTENT\n"));
  var codeNames = null;
  try { codeNames = await _extractNames(codeStub); } catch (err) { codeNames = "ERR " + err.code; }
  check("zip hidden archive: a stub holding ZIP signature constants that do not parse still extracts",
    codeNames === "a.txt=GOOD-CONTENT\n", String(codeNames));
}

// Lay out [LFH + data (+ descriptor) + gap bytes] per spec, then a CD and an
// EOCD with an optional comment. spec: { name, data, gap?, dir?, dd? }
function _zipWithGaps(specs, opts) {
  opts = opts || {};
  var locals = [];
  var cds = [];
  var off = opts.prefix ? opts.prefix.length : 0;
  specs.forEach(function (s) {
    var data = s.data || Buffer.alloc(0);
    var lfh = _rawLfh(s.name, data);
    var cfh = _rawCfh(s.name, data, off);
    if (s.dir) cfh.writeUInt32LE(0x41ed0010, 38);
    if (s.dd) {
      lfh.writeUInt16LE(0x0008, 6);
      lfh.writeUInt32LE(0, 14);
      lfh.writeUInt32LE(0, 18);
      lfh.writeUInt32LE(0, 22);
      cfh.writeUInt16LE(0x0008, 8);
      lfh = Buffer.concat([lfh, _buildDataDescriptor({}, zlib.crc32(data) >>> 0, data.length, data.length)]);
    }
    var part = Buffer.concat([lfh, s.gap || Buffer.alloc(0)]);
    locals.push(part);
    cds.push(cfh);
    off += part.length;
  });
  var middle = opts.beforeCd || Buffer.alloc(0);
  var cd = Buffer.concat(cds);
  var eocd = _rawEocd(specs.length, cd.length, off + middle.length);
  var comment = opts.comment || Buffer.alloc(0);
  eocd.writeUInt16LE(comment.length, 20);
  return Buffer.concat([opts.prefix || Buffer.alloc(0), Buffer.concat(locals), middle, cd, eocd, comment]);
}

async function _diskExtractErr(bytes) {
  var dest = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-gap-"));
  var e = null;
  try { await b.archive.read.zip(b.archive.adapters.buffer(bytes), { guardProfile: false }).extract({ destination: dest }); }
  catch (err) { e = err; }
  var left = fs.readdirSync(dest);
  fs.rmSync(dest, { recursive: true, force: true });
  return { err: e, left: left };
}

// ZIP structures in the places a second reader looks: a local header whose
// signature starts in the leading bytes and whose fixed header runs into the
// first referenced local header, a local header in the gap after an entry's
// data, and an end record (or a whole archive) inside the EOCD comment.
async function testEmbeddedStructureRefusals() {
  var GOOD = Buffer.from("GOOD-CONTENT\n");
  var EVIL = Buffer.from("EVIL-PAYLOAD\n");

  // A 28-byte local header right before the first referenced one. Its extra
  // length is the real header's "PK" bytes (0x4b50), and its data lies inside
  // good.bin's stored bytes.
  var fake = Buffer.alloc(28);
  fake.writeUInt32LE(SIG_LFH_OK, 0);
  fake.writeUInt16LE(20, 4);
  fake.writeUInt16LE(0x21, 12);
  fake.writeUInt32LE(zlib.crc32(EVIL) >>> 0, 14);
  fake.writeUInt32LE(EVIL.length, 18);
  fake.writeUInt32LE(EVIL.length, 22);
  fake.writeUInt16LE(1, 26);
  var bigBody = Buffer.alloc(30000, 0x20);
  GOOD.copy(bigBody, 0);
  var straddle = _withAdjustedPrefix(Buffer.concat([Buffer.from("#!/bin/sh\nexit 0\n"), fake]),
    _storeZipOf("good.bin", bigBody));
  var es1 = await _extractEntriesErr(straddle, { guardProfile: false });
  check("zip embedded: a local header whose fixed header runs into the first referenced one is refused",
    _hasCode(es1, "archive-read/embedded-archive"), es1 ? String(es1.code) : "read without error");
  var es1i = await _inspectErr(straddle);
  check("zip embedded: inspect() refuses the straddling local header",
    _hasCode(es1i, "archive-read/embedded-archive"), es1i ? String(es1i.code) : "read without error");

  // A local header with its data in the gap between two entries. A reader
  // that walks the file front to back (bsdtar reading a pipe) extracts
  // evil.txt from this file; readers that use the central directory list
  // only a.txt and b.txt.
  var gapHidden = _zipWithGaps([
    { name: "a.txt", data: GOOD, gap: _rawLfh("evil.txt", EVIL) },
    { name: "b.txt", data: GOOD },
  ]);
  var eg1 = await _extractEntriesErr(gapHidden, { guardProfile: false });
  check("zip embedded: a local header in the gap between entries is refused by extractEntries",
    _hasCode(eg1, "archive-read/embedded-archive"), eg1 ? String(eg1.code) : "read without error");
  var eg1d = await _diskExtractErr(gapHidden);
  check("zip embedded: disk extract refuses the gap local header and writes nothing",
    _hasCode(eg1d.err, "archive-read/embedded-archive") && eg1d.left.length === 0,
    (eg1d.err ? String(eg1d.err.code) : "read without error") + " left=" + eg1d.left.join(","));
  var eg1i = await _inspectErr(gapHidden);
  check("zip embedded: inspect() refuses the local header in the gap between entries",
    _hasCode(eg1i, "archive-read/embedded-archive"), eg1i ? String(eg1i.code) : "read without error");

  // The same hiding place after a directory entry, after a data descriptor,
  // and between the last entry and the central directory.
  var afterDir = _zipWithGaps([
    { name: "d/", dir: true, gap: _rawLfh("evil.txt", EVIL) },
    { name: "d/b.txt", data: GOOD },
  ]);
  var eg2 = await _extractEntriesErr(afterDir, { guardProfile: false });
  check("zip embedded: a local header after a directory entry is refused",
    _hasCode(eg2, "archive-read/embedded-archive"), eg2 ? String(eg2.code) : "read without error");
  var afterDd = _zipWithGaps([
    { name: "a.txt", data: GOOD, dd: true, gap: _rawLfh("evil.txt", EVIL) },
    { name: "b.txt", data: GOOD },
  ]);
  var eg3 = await _extractEntriesErr(afterDd, { guardProfile: false });
  check("zip embedded: a local header after a data descriptor is refused",
    _hasCode(eg3, "archive-read/embedded-archive"), eg3 ? String(eg3.code) : "read without error");
  var beforeCd = _zipWithGaps([{ name: "a.txt", data: GOOD }], { beforeCd: _rawLfh("evil.txt", EVIL) });
  var eg4 = await _extractEntriesErr(beforeCd, { guardProfile: false });
  check("zip embedded: a local header between the last entry and the CD is refused",
    _hasCode(eg4, "archive-read/embedded-archive"), eg4 ? String(eg4.code) : "read without error");

  // A second complete archive in the EOCD comment, followed by one byte so
  // its own comment does not reach the end of the file. Python 3.11 zipfile
  // lists evil.txt from this file.
  var lg = _rawLfh("good.txt", GOOD);
  var cdg = _rawCfh("good.txt", GOOD, 0);
  var commentStart = lg.length + cdg.length + 22;
  var le = _rawLfh("evil.txt", EVIL);
  var cde = _rawCfh("evil.txt", EVIL, commentStart);
  var innerComment = Buffer.concat([le, cde, _rawEocd(1, cde.length, commentStart + le.length), Buffer.from([0x0a])]);
  var inComment = _zipWithGaps([{ name: "good.txt", data: GOOD }], { comment: innerComment });
  var ec1 = await _extractEntriesErr(inComment, { guardProfile: false });
  check("zip embedded: a complete archive inside the EOCD comment is refused",
    _hasCode(ec1, "archive-read/embedded-archive"), ec1 ? String(ec1.code) : "read without error");
  var ec1i = await _inspectErr(inComment);
  check("zip embedded: inspect() refuses the archive in the EOCD comment",
    _hasCode(ec1i, "archive-read/embedded-archive"), ec1i ? String(ec1i.code) : "read without error");

  // An end-record signature with a full record after it in the comment is
  // the record a reader that takes the last signature in the file uses.
  var bareSig = Buffer.concat([Buffer.from("note "), Buffer.from([0x50, 0x4b, 0x05, 0x06]), Buffer.alloc(18, 0x41)]);
  var ec2 = await _inspectErr(_zipWithGaps([{ name: "good.txt", data: GOOD }], { comment: bareSig }));
  check("zip embedded: an end-record signature with a full record in the EOCD comment is refused",
    _hasCode(ec2, "archive-read/embedded-archive"), ec2 ? String(ec2.code) : "read without error");

  // Controls: an ordinary text comment, a comment that ends in a signature
  // too short to be a record, gap bytes that hold no ZIP structure, and an
  // APK-style signing block between the last entry and the central directory.
  var textComment = Buffer.from("Created by build 4512 on 2026-10-27. Contact: ops@example.com\n");
  var ok1 = null;
  try { ok1 = await _extractNames(_zipWithGaps([{ name: "good.txt", data: GOOD }], { comment: textComment })); }
  catch (err) { ok1 = "ERR " + err.code; }
  check("zip embedded: an ordinary text comment still extracts", ok1 === "good.txt=GOOD-CONTENT\n", String(ok1));
  var shortSig = Buffer.concat([Buffer.from("tail "), Buffer.from([0x50, 0x4b, 0x05, 0x06]), Buffer.alloc(4)]);
  var ok2 = null;
  try { ok2 = await _extractNames(_zipWithGaps([{ name: "good.txt", data: GOOD }], { comment: shortSig })); }
  catch (err) { ok2 = "ERR " + err.code; }
  check("zip embedded: a comment ending in a signature too short for a record still extracts",
    ok2 === "good.txt=GOOD-CONTENT\n", String(ok2));
  var ok3 = null;
  try {
    ok3 = await _extractNames(_zipWithGaps([
      { name: "a.txt", data: GOOD, gap: Buffer.concat([Buffer.alloc(64, 0), Buffer.from("PK\u0003\u0004"), Buffer.alloc(8, 0xff)]) },
      { name: "b.txt", data: GOOD, dd: true, gap: Buffer.alloc(16, 0) },
    ]));
  } catch (err) { ok3 = "ERR " + err.code; }
  check("zip embedded: gap bytes that hold no parseable ZIP structure still extract",
    ok3 === "a.txt=GOOD-CONTENT\n,b.txt=GOOD-CONTENT\n", String(ok3));
  var sigBlockBody = Buffer.alloc(4096);
  for (var k = 0; k < sigBlockBody.length; k += 1) sigBlockBody[k] = (k * 131 + 7) & 0xff;
  var sigBlockSize = Buffer.alloc(8);
  sigBlockSize.writeBigUInt64LE(BigInt(sigBlockBody.length + 24));
  var sigBlock = Buffer.concat([sigBlockSize, sigBlockBody, sigBlockSize, Buffer.from("APK Sig Block 42")]);
  var ok4 = null;
  try { ok4 = await _extractNames(_zipWithGaps([{ name: "classes.dex", data: GOOD }], { beforeCd: sigBlock })); }
  catch (err) { ok4 = "ERR " + err.code; }
  check("zip embedded: an APK-style signing block before the central directory still extracts",
    ok4 === "classes.dex=GOOD-CONTENT\n", String(ok4));

  // A stored entry whose content is itself a ZIP: entry data is not scanned.
  var nested = _storeZipOf("inner.txt", "INNER\n");
  var outer = _zipWithGaps([{ name: "nested.zip", data: nested }, { name: "b.txt", data: GOOD }]);
  var ok5 = null;
  try {
    var got5 = [];
    for await (var n5 of b.archive.read.zip(b.archive.adapters.buffer(outer), { guardProfile: false }).extractEntries()) {
      got5.push(n5.name + ":" + n5.bytes.equals(n5.name === "nested.zip" ? nested : GOOD));
    }
    ok5 = got5.join(",");
  } catch (err) { ok5 = "ERR " + err.code; }
  check("zip embedded: a stored entry that is itself a ZIP still extracts",
    ok5 === "nested.zip:true,b.txt:true", String(ok5));
}

// Archives written by real tools: Info-ZIP `zip -r`, Info-ZIP reading stdin
// (`zip -fd - -`, a ZIP64 data descriptor), Python zipfile to a file and to
// an unseekable stream (data descriptors), 7-Zip, and the JDK `jar` tool.
var INTEROP_ARCHIVES = {
  "infozip.zip":        "UEsDBAoAAAAAALUVXF0PpOroHwAAAB8AAAAKAAAAcmVhZG1lLnR4dGhlbGxvIGZyb20gdGhlIGludGVyb3AgZml4dHVyZQpQSwMECgAAAAAAtRVcXQAAAAAAAAAAAAAAAAUAAABkb2NzL1BLAwQKAAAAAAC1FVxdgxbcjAEAAAABAAAADAAAAGRvY3Mvb25lLnR4dHhQSwMEFAAAAAgAtRVcXUXwEzuFAAAAzgQAAA4AAABkb2NzL25vdGVzLnR4dIXTQQ6CQBBE0b2n6CPYVYJ4HDRDQjIyRLx/DAfwz/rvXqrqupW4Rltijld7759yHOuzltjat1zqWROrsBrrDeuAdcR6xzphfbBGB4u1krmSvZLBksWSyZLNktGS1cRq6myM1cRqYjWxmlhNrCZWE6uZ1cxq7lyT1cxqZjWzmlnNrOa/aj9QSwECHgMKAAAAAAC1FVxdD6Tq6B8AAAAfAAAACgAAAAAAAAABAAAApIEAAAAAcmVhZG1lLnR4dFBLAQIeAwoAAAAAALUVXF0AAAAAAAAAAAAAAAAFAAAAAAAAAAAAEADtQUcAAABkb2NzL1BLAQIeAwoAAAAAALUVXF2DFtyMAQAAAAEAAAAMAAAAAAAAAAEAAACkgWoAAABkb2NzL29uZS50eHRQSwECHgMUAAAACAC1FVxdRfATO4UAAADOBAAADgAAAAAAAAABAAAApIGVAAAAZG9jcy9ub3Rlcy50eHRQSwUGAAAAAAQABADhAAAARgEAAAAA",
  "infozip-stream.zip": "UEsDBC0ACAAIALUVXF0AAAAA//////////8BABQALQEAEAAAAAAAAAAAAAAAAAAAAAAAhdM7DgIxDEXRnlV4CdjmuxxAjiZSJhllgsTyaWi5qW939N4SpTRJva0ylpBcR/S2Scqf8e5xKLmGHKUlecirrVuPfc/PElLb+FXFalgd6wnrGesF6xXrDeudNSZYrKXMpeylDKYspkymbKaMpqxmrGaTjbGasZqxmrGasZqxmrGasZqzmrOaT67Jas5qzmrOas5qzmr+V+0LUEsHCK34qFKZAAAAAAAAAO0EAAAAAAAAUEsBAh4DLQAIAAgAtRVcXa34qFKZAAAA7QQAAAEAAAAAAAAAAQAAAIARAAAAAC1QSwUGAAAAAAEAAQAvAAAA5AAAAAAA",
  "python.zip":         "UEsDBBQAAAAIALUVXF0PpOroIQAAAB8AAAAKAAAAcmVhZG1lLnR4dMtIzcnJV0grys9VKMlIVcjMK0ktyi9QSMusKCktSuUCAFBLAwQUAAAAAAC1FVxdRfATO84EAADOBAAADgAAAGRvY3Mvbm90ZXMudHh0bGluZSAwIG9mIGEgY29tcHJlc3NpYmxlIG5vdGUKbGluZSAxIG9mIGEgY29tcHJlc3NpYmxlIG5vdGUKbGluZSAyIG9mIGEgY29tcHJlc3NpYmxlIG5vdGUKbGluZSAzIG9mIGEgY29tcHJlc3NpYmxlIG5vdGUKbGluZSA0IG9mIGEgY29tcHJlc3NpYmxlIG5vdGUKbGluZSA1IG9mIGEgY29tcHJlc3NpYmxlIG5vdGUKbGluZSA2IG9mIGEgY29tcHJlc3NpYmxlIG5vdGUKbGluZSA3IG9mIGEgY29tcHJlc3NpYmxlIG5vdGUKbGluZSA4IG9mIGEgY29tcHJlc3NpYmxlIG5vdGUKbGluZSA5IG9mIGEgY29tcHJlc3NpYmxlIG5vdGUKbGluZSAxMCBvZiBhIGNvbXByZXNzaWJsZSBub3RlCmxpbmUgMTEgb2YgYSBjb21wcmVzc2libGUgbm90ZQpsaW5lIDEyIG9mIGEgY29tcHJlc3NpYmxlIG5vdGUKbGluZSAxMyBvZiBhIGNvbXByZXNzaWJsZSBub3RlCmxpbmUgMTQgb2YgYSBjb21wcmVzc2libGUgbm90ZQpsaW5lIDE1IG9mIGEgY29tcHJlc3NpYmxlIG5vdGUKbGluZSAxNiBvZiBhIGNvbXByZXNzaWJsZSBub3RlCmxpbmUgMTcgb2YgYSBjb21wcmVzc2libGUgbm90ZQpsaW5lIDE4IG9mIGEgY29tcHJlc3NpYmxlIG5vdGUKbGluZSAxOSBvZiBhIGNvbXByZXNzaWJsZSBub3RlCmxpbmUgMjAgb2YgYSBjb21wcmVzc2libGUgbm90ZQpsaW5lIDIxIG9mIGEgY29tcHJlc3NpYmxlIG5vdGUKbGluZSAyMiBvZiBhIGNvbXByZXNzaWJsZSBub3RlCmxpbmUgMjMgb2YgYSBjb21wcmVzc2libGUgbm90ZQpsaW5lIDI0IG9mIGEgY29tcHJlc3NpYmxlIG5vdGUKbGluZSAyNSBvZiBhIGNvbXByZXNzaWJsZSBub3RlCmxpbmUgMjYgb2YgYSBjb21wcmVzc2libGUgbm90ZQpsaW5lIDI3IG9mIGEgY29tcHJlc3NpYmxlIG5vdGUKbGluZSAyOCBvZiBhIGNvbXByZXNzaWJsZSBub3RlCmxpbmUgMjkgb2YgYSBjb21wcmVzc2libGUgbm90ZQpsaW5lIDMwIG9mIGEgY29tcHJlc3NpYmxlIG5vdGUKbGluZSAzMSBvZiBhIGNvbXByZXNzaWJsZSBub3RlCmxpbmUgMzIgb2YgYSBjb21wcmVzc2libGUgbm90ZQpsaW5lIDMzIG9mIGEgY29tcHJlc3NpYmxlIG5vdGUKbGluZSAzNCBvZiBhIGNvbXByZXNzaWJsZSBub3RlCmxpbmUgMzUgb2YgYSBjb21wcmVzc2libGUgbm90ZQpsaW5lIDM2IG9mIGEgY29tcHJlc3NpYmxlIG5vdGUKbGluZSAzNyBvZiBhIGNvbXByZXNzaWJsZSBub3RlCmxpbmUgMzggb2YgYSBjb21wcmVzc2libGUgbm90ZQpsaW5lIDM5IG9mIGEgY29tcHJlc3NpYmxlIG5vdGUKUEsDBBQAAAAIALUVXF0AAAAAAgAAAAAAAAAFAAAAZG9jcy8DAFBLAQIUAxQAAAAIALUVXF0PpOroIQAAAB8AAAAKAAAAAAAAAAAAAACkgQAAAAByZWFkbWUudHh0UEsBAhQDFAAAAAAAtRVcXUXwEzvOBAAAzgQAAA4AAAAAAAAAAAAAAKSBSQAAAGRvY3Mvbm90ZXMudHh0UEsBAhQDFAAAAAgAtRVcXQAAAAACAAAAAAAAAAUAAAAAAAAAAAAQAP1BQwUAAGRvY3MvUEsFBgAAAAADAAMApwAAAGgFAAAAAA==",
  "python-stream.zip":  "UEsDBBQACAAIALUVXF0AAAAAAAAAAAAAAAAKAAAAcmVhZG1lLnR4dMtIzcnJV0grys9VKMlIVcjMK0ktyi9QSMusKCktSuUCAFBLBwgPpOroIQAAAB8AAABQSwMEFAAIAAgAAAAhAAAAAAAAAAAAAAAAAA4AAABkb2NzL25vdGVzLnR4dIXTQQ6CQBBE0b2n6CPYVYJ4HDRDQjIyRLx/DAfwz/rvXqrqupW4Rltijld7759yHOuzltjat1zqWROrsBrrDeuAdcR6xzphfbBGB4u1krmSvZLBksWSyZLNktGS1cRq6myM1cRqYjWxmlhNrCZWE6uZ1cxq7lyT1cxqZjWzmlnNrOa/aj9QSwcIRfATO4UAAADOBAAAUEsBAhQDFAAIAAgAtRVcXQ+k6ughAAAAHwAAAAoAAAAAAAAAAAAAAKSBAAAAAHJlYWRtZS50eHRQSwECFAMUAAgACAAAACEARfATO4UAAADOBAAADgAAAAAAAAAAAAAAgAFZAAAAZG9jcy9ub3Rlcy50eHRQSwUGAAAAAAIAAgB0AAAAGgEAAAAA",
  "7z.zip":             "UEsDBBQAAAAAALYVXF0AAAAAAAAAAAAAAAAFAAAAZG9jcy9QSwMEFAAAAAgAthVcXUXwEzt5AAAAzgQAAA4AAABkb2NzL25vdGVzLnR4dIXTSwqAMBAE0b2nmCMkmfw8jkoEQY0Y74/g3sr67YrufTuLGKmrTLLU47pLa9u8FznrU4ZPLapDVVSPGlAjakLNqCPX6MSyzI5ZmT1zYI7MiTkzczVnmDsbc8zK7JkDc2ROzJmZq6lhtsydayqzZw7MkTkxZ+bfai9QSwMECgAAAAAAthVcXYMW3IwBAAAAAQAAAAwAAABkb2NzL29uZS50eHR4UEsDBAoAAAAAALYVXF0PpOroHwAAAB8AAAAKAAAAcmVhZG1lLnR4dGhlbGxvIGZyb20gdGhlIGludGVyb3AgZml4dHVyZQpQSwECPwMUAAAAAAC2FVxdAAAAAAAAAAAAAAAABQAkAAAAAAAAABCA7UEAAAAAZG9jcy8KACAAAAAAAAEAGAALfMxshmbdAQAAAAAAAAAAAAAAAAAAAABQSwECPwMUAAAACAC2FVxdRfATO3kAAADOBAAADgAkAAAAAAAAACCApIEjAAAAZG9jcy9ub3Rlcy50eHQKACAAAAAAAAEAGAALfMxshmbdAQAAAAAAAAAAAAAAAAAAAABQSwECPwMKAAAAAAC2FVxdgxbcjAEAAAABAAAADAAkAAAAAAAAACCApIHIAAAAZG9jcy9vbmUudHh0CgAgAAAAAAABABgAC3zMbIZm3QEAAAAAAAAAAAAAAAAAAAAAUEsBAj8DCgAAAAAAthVcXQ+k6ugfAAAAHwAAAAoAJAAAAAAAAAAggKSB8wAAAHJlYWRtZS50eHQKACAAAAAAAAEAGAALfMxshmbdAQAAAAAAAAAAAAAAAAAAAABQSwUGAAAAAAQABABxAQAAOgEAAAAA",
  "app.jar":            "UEsDBAoAAAgAALUVXF0AAAAAAAAAAAAAAAAJAAQATUVUQS1JTkYv/soAAFBLAwQUAAgICAC1FVxdAAAAAAAAAAAAAAAAFAAAAE1FVEEtSU5GL01BTklGRVNULk1G803My0xLLS7RDUstKs7Mz7NSMNQz4OVyLkpNLElN0XWqtFIwAoroGRopaDjmFGTmpWrycvFyAQBQSwcIUTLwXTgAAAA3AAAAUEsDBBQACAgIALUVXF0AAAAAAAAAAAAAAAAKAAAAcmVhZG1lLnR4dMtIzcnJV0grys9VKMlIVcjMK0ktyi9QSMusKCktSuUCAFBLBwgPpOroIQAAAB8AAABQSwMECgAACAAAtRVcXQAAAAAAAAAAAAAAAAUAAABkb2NzL1BLAwQUAAgICAC1FVxdAAAAAAAAAAAAAAAADgAAAGRvY3Mvbm90ZXMudHh0hdNBDoJAEETRvafoI9hVgngcNENCMjJEvH8MB/DP+u9equq6lbhGW2KOV3vvn3Ic67OW2Nq3XOpZE6uwGusN64B1xHrHOmF9sEYHi7WSuZK9ksGSxZLJks2S0ZLVxGrqbIzVxGpiNbGaWE2sJlYTq5nVzGruXJPVzGpmNbOaWc2s5r9qP1BLBwhF8BM7hQAAAM4EAABQSwMEFAAICAgAtRVcXQAAAAAAAAAAAAAAAAwAAABkb2NzL29uZS50eHSrAABQSwcIgxbcjAMAAAABAAAAUEsBAgoACgAACAAAtRVcXQAAAAAAAAAAAAAAAAkABAAAAAAAAAAAAAAAAAAAAE1FVEEtSU5GL/7KAABQSwECFAAUAAgICAC1FVxdUTLwXTgAAAA3AAAAFAAAAAAAAAAAAAAAAAArAAAATUVUQS1JTkYvTUFOSUZFU1QuTUZQSwECFAAUAAgICAC1FVxdD6Tq6CEAAAAfAAAACgAAAAAAAAAAAAAAAAClAAAAcmVhZG1lLnR4dFBLAQIKAAoAAAgAALUVXF0AAAAAAAAAAAAAAAAFAAAAAAAAAAAAAAAAAP4AAABkb2NzL1BLAQIUABQACAgIALUVXF1F8BM7hQAAAM4EAAAOAAAAAAAAAAAAAAAAACEBAABkb2NzL25vdGVzLnR4dFBLAQIUABQACAgIALUVXF2DFtyMAwAAAAEAAAAMAAAAAAAAAAAAAAAAAOIBAABkb2NzL29uZS50eHRQSwUGAAAAAAYABgBeAQAAHwIAAAAA",
};

function _interopExpectedBodies() {
  var readme = "hello from the interop fixture\n";
  var notes = "";
  for (var n = 0; n < 40; n += 1) notes += "line " + n + " of a compressible note\n";
  return { "readme.txt": readme, "docs/notes.txt": notes, "docs/one.txt": "x", "-": readme + notes };
}

function _countingAdapter(bytes) {
  var inner = b.archive.adapters.buffer(bytes);
  var counter = { reads: [], adapter: null };
  counter.adapter = Object.assign({}, inner, {
    range: function (offset, length) {
      counter.reads.push({ offset: offset, length: length });
      return inner.range(offset, length);
    },
  });
  return counter;
}

// inspect() checks every local header against its central directory entry,
// and the bytes between entries, the way extract and extractEntries do. A
// reader that takes names from the local headers (a streaming unzip) would
// otherwise write a file the central directory never listed.
async function testInspectVerifiesLocalHeaders() {
  var GOOD = Buffer.from("GOOD-CONTENT\n");
  var EVIL = Buffer.from("EVIL-PAYLOAD\n");

  var nameSkew = buildClassicZip([{ name: "docs/readme.txt", data: GOOD, lfhName: "../../evil.txt" }]);
  var ei1 = await _inspectErr(nameSkew);
  check("zip inspect: a local header naming ../../evil.txt under a CD name of docs/readme.txt is refused",
    _hasCode(ei1, "archive-read/lfh-cd-skew"), ei1 ? String(ei1.code) : "inspected without error");
  var eg1 = null;
  try { await b.guardArchive.inspect(b.archive.adapters.buffer(nameSkew), { profile: "strict" }); }
  catch (err) { eg1 = err; }
  check("zip inspect: b.guardArchive.inspect refuses the same local-header name skew",
    _hasCode(eg1, "archive-read/lfh-cd-skew"), eg1 ? String(eg1.code) : "inspected without error");
  var es1 = null;
  try { await b.safeArchive.inspect({ source: nameSkew }); }
  catch (err) { es1 = err; }
  check("zip inspect: b.safeArchive.inspect refuses the same local-header name skew",
    _hasCode(es1, "archive-read/lfh-cd-skew"), es1 ? String(es1.code) : "inspected without error");
  var et1 = null;
  try {
    await b.archive.read.zip.fromTrustedStream(
      b.archive.adapters.trustedStream(nodeStream.Readable.from([nameSkew]))).inspect();
  } catch (err) { et1 = err; }
  check("zip inspect: fromTrustedStream inspect() refuses the same local-header name skew",
    _hasCode(et1, "archive-read/lfh-cd-skew"), et1 ? String(et1.code) : "inspected without error");
  var en1 = null;
  try { for await (var _n1 of b.archive.read.zip(b.archive.adapters.buffer(nameSkew)).entries()) { void _n1; } }
  catch (err) { en1 = err; }
  check("zip inspect: entries() refuses the same local-header name skew before yielding",
    _hasCode(en1, "archive-read/lfh-cd-skew"), en1 ? String(en1.code) : "enumerated without error");

  var cases = [
    { label: "a bad local-header signature", code: "archive-read/bad-lfh-signature",
      spec: { name: "a.txt", data: GOOD, lfhSig: 0xdeadbeef } },
    { label: "a method skew", code: "archive-read/lfh-cd-skew",
      spec: { name: "a.txt", data: GOOD, method: 0, lfhMethod: 8 } },
    { label: "a CRC-32 skew", code: "archive-read/lfh-cd-skew",
      spec: { name: "a.txt", data: GOOD, lfhCrc: 7 } },
    { label: "a compressed-size skew", code: "archive-read/lfh-cd-skew",
      spec: { name: "a.txt", data: GOOD, lfhCsize: 99 } },
    { label: "an uncompressed-size skew", code: "archive-read/lfh-cd-skew",
      spec: { name: "a.txt", data: GOOD, lfhUsize: 99 } },
    { label: "an encryption-flag skew", code: "archive-read/lfh-cd-skew",
      spec: { name: "a.txt", data: GOOD, lfhFlags: 0x0001 } },
    { label: "a data-descriptor-flag skew", code: "archive-read/lfh-cd-skew",
      spec: { name: "a.txt", data: GOOD, lfhFlags: 0x0008 } },
    { label: "a data descriptor that disagrees with the CD", code: "archive-read/lfh-cd-skew",
      spec: { name: "a.txt", data: GOOD, flags: 0x0008, lfhCrc: 0, lfhCsize: 0, lfhUsize: 0,
              dataDescriptor: { crc: 1 } } },
    { label: "a directory entry whose local header names another path", code: "archive-read/lfh-cd-skew",
      spec: { name: "d/", externalAttrs: EXT_DIR, lfhName: "../" } },
  ];
  for (var c = 0; c < cases.length; c += 1) {
    var bytes = buildClassicZip([cases[c].spec]);
    var ec = await _inspectErr(bytes);
    check("zip inspect: " + cases[c].label + " is refused by inspect()",
      _hasCode(ec, cases[c].code), ec ? String(ec.code) : "inspected without error");
    var egc = null;
    try { await b.guardArchive.inspect(b.archive.adapters.buffer(bytes)); }
    catch (err) { egc = err; }
    check("zip inspect: " + cases[c].label + " is refused by b.guardArchive.inspect",
      _hasCode(egc, cases[c].code), egc ? String(egc.code) : "inspected without error");
  }

  // A local header with its data in the gap between two entries, after a
  // directory entry, after a data descriptor, and before the central directory.
  var gaps = [
    _zipWithGaps([{ name: "a.txt", data: GOOD, gap: _rawLfh("evil.txt", EVIL) }, { name: "b.txt", data: GOOD }]),
    _zipWithGaps([{ name: "d/", dir: true, gap: _rawLfh("evil.txt", EVIL) }, { name: "d/b.txt", data: GOOD }]),
    _zipWithGaps([{ name: "a.txt", data: GOOD, dd: true, gap: _rawLfh("evil.txt", EVIL) }, { name: "b.txt", data: GOOD }]),
    _zipWithGaps([{ name: "a.txt", data: GOOD }], { beforeCd: _rawLfh("evil.txt", EVIL) }),
  ];
  for (var g = 0; g < gaps.length; g += 1) {
    var egi = await _inspectErr(gaps[g]);
    check("zip inspect: inspect() refuses gap archive #" + g,
      _hasCode(egi, "archive-read/embedded-archive"), egi ? String(egi.code) : "inspected without error");
    var egg = null;
    try { await b.guardArchive.inspect(b.archive.adapters.buffer(gaps[g])); }
    catch (err) { egg = err; }
    check("zip inspect: b.guardArchive.inspect refuses gap archive #" + g,
      _hasCode(egg, "archive-read/embedded-archive"), egg ? String(egg.code) : "inspected without error");
  }

  // Controls: gap bytes holding no parseable ZIP structure, an APK-style
  // signing block before the central directory, and a stored entry that is
  // itself a ZIP still inspect.
  var sigBlockBody = Buffer.alloc(4096);
  for (var k = 0; k < sigBlockBody.length; k += 1) sigBlockBody[k] = (k * 131 + 7) & 0xff;
  var sigBlockSize = Buffer.alloc(8);
  sigBlockSize.writeBigUInt64LE(BigInt(sigBlockBody.length + 24));
  var controls = [
    _zipWithGaps([
      { name: "a.txt", data: GOOD, gap: Buffer.concat([Buffer.alloc(64, 0), Buffer.from("PK\u0003\u0004"), Buffer.alloc(8, 0xff)]) },
      { name: "b.txt", data: GOOD, dd: true, gap: Buffer.alloc(16, 0) },
    ]),
    _zipWithGaps([{ name: "classes.dex", data: GOOD }],
      { beforeCd: Buffer.concat([sigBlockSize, sigBlockBody, sigBlockSize, Buffer.from("APK Sig Block 42")]) }),
    _zipWithGaps([{ name: "nested.zip", data: _storeZipOf("inner.txt", "INNER\n") }, { name: "b.txt", data: GOOD }]),
  ];
  for (var k2 = 0; k2 < controls.length; k2 += 1) {
    var okc = await _inspectErr(controls[k2]);
    check("zip inspect: control archive #" + k2 + " still inspects", okc === null, okc ? String(okc.code) : "");
  }

  // One layout pass per reader: inspect() reads each local header once, and
  // extractEntries() after it, or a second inspect(), reads none again.
  var zz = b.archive.zip();
  zz.addFile("one.txt", "one");
  zz.addFile("two.txt", "two");
  zz.addFile("three.txt", "three");
  var three = zz.toBuffer();
  var lfhOffsets = [];
  for (var p = three.indexOf(Buffer.from([0x50, 0x4b, 0x03, 0x04])); p !== -1;
       p = three.indexOf(Buffer.from([0x50, 0x4b, 0x03, 0x04]), p + 1)) {
    lfhOffsets.push(p);
  }
  function lfhReads(list) {
    return list.filter(function (r) { return lfhOffsets.indexOf(r.offset) !== -1; }).length;
  }
  var solo = _countingAdapter(three);
  await b.archive.read.zip(solo.adapter).inspect();
  var counted = _countingAdapter(three);
  var sharedReader = b.archive.read.zip(counted.adapter);
  await Promise.all([sharedReader.inspect(), sharedReader.inspect()]);
  check("zip inspect: two concurrent inspect() calls make the reads of one inspect()",
    counted.reads.length === solo.reads.length && lfhReads(counted.reads) === lfhReads(solo.reads),
    "reads=" + counted.reads.length + " solo=" + solo.reads.length);
  var afterInspect = counted.reads.length;
  await sharedReader.inspect();
  check("zip inspect: a second inspect() makes no adapter read",
    counted.reads.length === afterInspect, "reads=" + (counted.reads.length - afterInspect));
  for await (var _x of sharedReader.extractEntries()) { void _x; }
  check("zip inspect: extractEntries() after inspect() reads no local header again",
    lfhReads(counted.reads.slice(afterInspect)) === 0,
    "local-header reads=" + lfhReads(counted.reads.slice(afterInspect)));

  // A failed pass is not remembered as a pass: a second inspect() on the same
  // reader refuses the archive again.
  var skewReader = b.archive.read.zip(b.archive.adapters.buffer(nameSkew));
  var first = null;
  var second = null;
  try { await skewReader.inspect(); } catch (err) { first = err; }
  try { await skewReader.inspect(); } catch (err) { second = err; }
  check("zip inspect: a second inspect() after a refusal refuses again",
    _hasCode(first, "archive-read/lfh-cd-skew") && _hasCode(second, "archive-read/lfh-cd-skew"),
    (second ? String(second.code) : "inspected without error"));

  // opts.signal stops the inspect() layout pass at the next read. Each entry
  // is larger than the read window, so every local header is its own read.
  var innerMany = b.archive.adapters.buffer(_spreadZip(50));
  var reads = 0;
  var ac = new AbortController();
  var midway = Object.assign({}, innerMany, {
    range: function (offset, length) {
      reads += 1;
      if (reads === 6) ac.abort("stop midway");
      return innerMany.range(offset, length);
    },
  });
  var ea = null;
  try { await b.archive.read.zip(midway, { signal: ac.signal }).inspect(); }
  catch (err) { ea = err; }
  check("zip inspect: an abort during the inspect() layout pass stops it at the next read",
    _hasCode(ea, "archive-read/aborted") && reads <= 7, "reads=" + reads + " code=" + (ea ? ea.code : "none"));
  var reads2 = 0;
  var ac2 = new AbortController();
  var midway2 = Object.assign({}, innerMany, {
    range: function (offset, length) {
      reads2 += 1;
      if (reads2 === 6) ac2.abort("stop midway");
      return innerMany.range(offset, length);
    },
  });
  var ega = null;
  try { await b.guardArchive.inspect(midway2, { signal: ac2.signal }); }
  catch (err) { ega = err; }
  check("zip inspect: b.guardArchive.inspect passes opts.signal to the layout pass",
    _hasCode(ega, "archive-read/aborted") && reads2 <= 7, "reads=" + reads2 + " code=" + (ega ? ega.code : "none"));

  // Archives written by real tools still inspect, pass the guard, and extract
  // the bytes they were built from. Info-ZIP records an entry read from a
  // pipe with the FIFO file type, so that archive extracts with fifos allowed.
  var expected = _interopExpectedBodies();
  var names = Object.keys(INTEROP_ARCHIVES);
  for (var r = 0; r < names.length; r += 1) {
    var label = names[r];
    var buf = Buffer.from(INTEROP_ARCHIVES[label], "base64");
    var readOpts = label === "infozip-stream.zip" ? { entryTypePolicy: { fifos: true } } : {};
    var outcome;
    try {
      var listed = await b.archive.read.zip(b.archive.adapters.buffer(buf)).inspect();
      var guarded = await b.guardArchive.inspect(b.archive.adapters.buffer(buf), { profile: "strict" });
      var critical = guarded.issues.filter(function (i) { return i.severity === "critical"; });
      var bodiesOk = true;
      var extracted = 0;
      for await (var ent of b.archive.read.zip(b.archive.adapters.buffer(buf), readOpts).extractEntries()) {
        extracted += 1;
        if (Object.prototype.hasOwnProperty.call(expected, ent.name) &&
            ent.bytes.toString("utf8") !== expected[ent.name]) {
          bodiesOk = false;
        }
      }
      outcome = "listed=" + listed.length + " critical=" + critical.length +
        " extracted=" + extracted + " bodies=" + bodiesOk;
      check("zip inspect: the " + label + " archive inspects, passes the guard and extracts",
        listed.length > 0 && critical.length === 0 && extracted > 0 && bodiesOk, outcome);
    } catch (err) {
      check("zip inspect: the " + label + " archive inspects, passes the guard and extracts",
        false, String(err && (err.code || err.message)));
    }
  }
}

var SEVEN_ZIP_OEM_NAME_ARCHIVE = "UEsDBBQAAAAAAMe0W10AAAAAAAAAAAAAAAAFAAAAZG9jcy9QSwMECgAAAAAAx7RbXc2SgOAFAAAABQAAAA0AFwBkb2NzL2NhZoIudHh0dXATAAEFN03XZG9jcy9jYWbDqS50eHRHT09EClBLAwQKAAAAAADHtFtdHwjqRgIAAAACAAAACQAAAHBsYWluLnR4dHgKUEsBAj8AFAAAAAAAx7RbXQAAAAAAAAAAAAAAAAUAJAAAAAAAAAAQAAAAAAAAAGRvY3MvCgAgAAAAAAABABgAy1D7hZ5m3QEAAAAAAAAAAAAAAAAAAAAAUEsBAj8ACgAAAAAAx7RbXc2SgOAFAAAABQAAAA0AOwAAAAAAAAAgAAAAIwAAAGRvY3MvY2Fmgi50eHQKACAAAAAAAAEAGAC1jPuFnmbdAQAAAAAAAAAAAAAAAAAAAAB1cBMAAQU3Tddkb2NzL2NhZsOpLnR4dFBLAQI/AAoAAAAAAMe0W10fCOpGAgAAAAIAAAAJACQAAAAAAAAAIAAAAGoAAABwbGFpbi50eHQKACAAAAAAAAEAGADJofuFnmbdAQAAAAAAAAAAAAAAAAAAAABQSwUGAAAAAAMAAwAoAQAAkwAAAAAA";
var BSDTAR_OEM_NAME_ARCHIVE = "UEsDBBQAAAAAAMa0W10AAAAAAAAAAAAAAAAFACAAZG9jcy91eAsAAQQAAAAABAAAAABVVA0AB0SK4WpEiuFqRIrhalBLAwQUAAgACADGtFtdAAAAAAAAAAAAAAAADQAgAGRvY3MvY2Fmgi50eHR1eAsAAQQAAAAABAAAAABVVA0AB0SK4WpEiuFqRIrhanP393fhAgBQSwcIzZKA4AcAAAAFAAAAUEsDBBQACAAIAMa0W10AAAAAAAAAAAAAAAAJACAAcGxhaW4udHh0dXgLAAEEAAAAAAQAAAAAVVQNAAdEiuFqRIrhakSK4Wqr4AIAUEsHCB8I6kYEAAAAAgAAAFBLAQIUAxQAAAAAAMa0W10AAAAAAAAAAAAAAAAFABgAAAAAAAAAAAD/QQAAAABkb2NzL3V4CwABBAAAAAAEAAAAAFVUBQABRIrhalBLAQIUAxQACAAIAMa0W13NkoDgBwAAAAUAAAANABgAAAAAAAAAAAC2gUMAAABkb2NzL2NhZoIudHh0dXgLAAEEAAAAAAQAAAAAVVQFAAFEiuFqUEsBAhQDFAAIAAgAxrRbXR8I6kYEAAAAAgAAAAkAGAAAAAAAAAAAALaBpQAAAHBsYWluLnR4dHV4CwABBAAAAAAEAAAAAFVUBQABRIrhalBLBQYAAAAAAwADAO0AAAAAAQAAAAA=";

// Stored entries larger than the local-header read window, so the layout
// pass reads each local header separately.
function _spreadZip(n) {
  var specs = [];
  for (var i = 0; i < n; i += 1) {
    specs.push({ name: "s" + i + ".bin", data: Buffer.alloc(C.BYTES.kib(70), 0x61 + (i % 26)) });
  }
  return buildClassicZip(specs);
}

// Info-ZIP Unicode Path extra field (APPNOTE 4.6.9, id 0x7075): version,
// CRC-32 of the header's name field, then the UTF-8 path.
function _unicodePathExtra(pathName, crcOf, opts) {
  opts = opts || {};
  var fixed = Buffer.alloc(5);
  fixed[0] = opts.version != null ? opts.version : 1;
  fixed.writeUInt32LE((opts.crc != null ? opts.crc : zlib.crc32(Buffer.from(crcOf, "utf8"))) >>> 0, 1);
  var data = Buffer.concat([fixed, Buffer.isBuffer(pathName) ? pathName : Buffer.from(pathName, "utf8")]);
  if (opts.truncate != null) data = data.subarray(0, opts.truncate);
  var head = Buffer.alloc(4);
  head.writeUInt16LE(0x7075, 0);
  head.writeUInt16LE(data.length, 2);
  return Buffer.concat([head, data]);
}

// Info-ZIP Unicode Comment extra field (id 0x6375): version, CRC-32 of the
// entry comment, then the UTF-8 comment.
function _unicodeCommentExtra(text) {
  var data = Buffer.concat([Buffer.from([1, 0, 0, 0, 0]), Buffer.from(text, "utf8")]);
  var head = Buffer.alloc(4);
  head.writeUInt16LE(0x6375, 0);
  head.writeUInt16LE(data.length, 2);
  return Buffer.concat([head, data]);
}

function _extendedTimestampExtra() {
  var f = Buffer.alloc(9);
  f.writeUInt16LE(0x5455, 0);
  f.writeUInt16LE(5, 2);
  f[4] = 1;
  f.writeUInt32LE(1700000000, 5);
  return f;
}

async function _readerOutcomes(bytes) {
  var out = {};
  var e1 = await _inspectErr(bytes);
  out.inspect = e1 ? String(e1.code) : "ok";
  var e2 = null;
  try { await b.guardArchive.inspect(b.archive.adapters.buffer(bytes), { profile: "strict" }); }
  catch (err) { e2 = err; }
  out.guard = e2 ? String(e2.code) : "ok";
  var e3 = await _extractEntriesErr(bytes);
  out.extract = e3 ? String(e3.code) : "ok";
  var e4 = null;
  try { await b.safeArchive.inspect({ source: bytes }); }
  catch (err) { e4 = err; }
  out.safe = e4 ? String(e4.code) : "ok";
  return out;
}

var SEVEN_ZIP_DEFAULT_ARCHIVE = "UEsDBBQAAAAAAIq5W10AAAAAAAAAAAAAAAAFAAAAZG9jcy9QSwMECgAAAAAAirlbXayKzkYHAAAABwAAAA0AFwBkb2NzL2NhZoIudHh0dXATAAEFN03XZG9jcy9jYWbDqS50eHRoZWxsbw0KUEsDBAoAAAgAAIq5W114N1V0BAAAAAQAAAAPAAAAZG9jcy/ml6XmnKwudHh0anANClBLAQI/ABQAAAAAAIq5W10AAAAAAAAAAAAAAAAFACQAAAAAAAAAEAAAAAAAAABkb2NzLwoAIAAAAAAAAQAYAJb3CkmjZt0BAAAAAAAAAAAAAAAAAAAAAFBLAQI/AAoAAAAAAIq5W12sis5GBwAAAAcAAAANADsAAAAAAAAAIAAAACMAAABkb2NzL2NhZoIudHh0CgAgAAAAAAABABgA3cMKSaNm3QEAAAAAAAAAAAAAAAAAAAAAdXATAAEFN03XZG9jcy9jYWbDqS50eHRQSwECPwAKAAAIAACKuVtdeDdVdAQAAAAEAAAADwAkAAAAAAAAACAAAABsAAAAZG9jcy/ml6XmnKwudHh0CgAgAAAAAAABABgA1R4LSaNm3QEAAAAAAAAAAAAAAAAAAAAAUEsFBgAAAAADAAMALgEAAJ0AAAAAAA==";

async function _namesAndBodies(bytes) {
  var listed = await b.archive.read.zip(b.archive.adapters.buffer(bytes)).inspect();
  var guarded = await b.guardArchive.inspect(b.archive.adapters.buffer(bytes), { profile: "strict" });
  var bodies = [];
  for await (var ent of b.archive.read.zip(b.archive.adapters.buffer(bytes)).extractEntries()) {
    bodies.push(ent.name + "=" + ent.bytes.toString("utf8"));
  }
  var safe = await b.safeArchive.inspect({ source: bytes });
  return {
    names:    listed.map(function (e) { return e.name; }),
    critical: guarded.issues.filter(function (i) { return i.severity === "critical"; }).length,
    bodies:   bodies,
    safe:     safe.entries.map(function (e) { return e.name; }),
  };
}

// An entry's name is the one Info-ZIP unzip, 7-Zip and bsdtar extract: the
// Unicode Path extra field (0x7075) when it is version 1 and its CRC-32
// matches that header's name field, otherwise the name field. That effective
// name is listed, judged by the guard and extracted. The local and central
// name fields must agree byte for byte, the local and central effective names
// must agree, and a Unicode Path the tools read differently is refused.
async function testUnicodePathExtraField() {
  var GOOD = Buffer.from("GOOD-CONTENT\n");
  var NAME = "docs/readme.txt";
  var EVIL = "evil/payload.txt";
  var refused = [
    { label: "a local-header Unicode Path naming evil/payload.txt with none in the central directory",
      spec: { name: NAME, data: GOOD, lfhExtra: _unicodePathExtra(EVIL, NAME) } },
    { label: "a local-header Unicode Path naming ../../evil.txt with none in the central directory",
      spec: { name: NAME, data: GOOD, lfhExtra: _unicodePathExtra("../../evil.txt", NAME) } },
    { label: "a central-directory Unicode Path naming evil/payload.txt with none in the local header",
      spec: { name: NAME, data: GOOD, extra: _unicodePathExtra(EVIL, NAME) } },
    { label: "a central-directory Unicode Path after another extra field, with none in the local header",
      spec: { name: NAME, data: GOOD,
              extra: Buffer.concat([_extendedTimestampExtra(), _unicodePathExtra(EVIL, NAME)]) } },
    { label: "a valid local-header Unicode Path beside a central one whose CRC-32 does not match",
      spec: { name: NAME, data: GOOD, lfhExtra: _unicodePathExtra(EVIL, NAME),
              extra: _unicodePathExtra(EVIL, NAME, { crc: 1 }) } },
    { label: "a valid central Unicode Path beside a local one whose CRC-32 does not match",
      spec: { name: NAME, data: GOOD, extra: _unicodePathExtra(EVIL, NAME),
              lfhExtra: _unicodePathExtra(EVIL, NAME, { crc: 1 }) } },
    { label: "a Unicode Path of version 2",
      spec: { name: NAME, data: GOOD, extra: _unicodePathExtra(EVIL, NAME, { version: 2 }),
              lfhExtra: _unicodePathExtra(EVIL, NAME, { version: 2 }) } },
    { label: "a Unicode Path shorter than its version and CRC-32",
      spec: { name: NAME, data: GOOD, extra: _unicodePathExtra(NAME, NAME, { truncate: 3 }) } },
    { label: "a Unicode Path with an empty path",
      spec: { name: NAME, data: GOOD, extra: _unicodePathExtra("", NAME), lfhExtra: _unicodePathExtra("", NAME) } },
    { label: "two Unicode Path fields in one header",
      spec: { name: NAME, data: GOOD,
              extra: Buffer.concat([_unicodePathExtra(NAME, NAME), _unicodePathExtra(EVIL, NAME)]),
              lfhExtra: Buffer.concat([_unicodePathExtra(NAME, NAME), _unicodePathExtra(EVIL, NAME)]) } },
    { label: "a Unicode Path that differs from a name field flagged UTF-8 (bit 11)",
      spec: { name: NAME, data: GOOD, flags: 0x0800,
              extra: _unicodePathExtra(EVIL, NAME), lfhExtra: _unicodePathExtra(EVIL, NAME) } },
    { label: "a Unicode Path ending in a slash for a name field that does not",
      spec: { name: NAME, data: GOOD, extra: _unicodePathExtra("evil/", NAME), lfhExtra: _unicodePathExtra("evil/", NAME) } },
    { label: "a Unicode Path that is not valid UTF-8",
      spec: { name: NAME, data: GOOD,
              extra: _unicodePathExtra(Buffer.from("evil/\xff.txt", "latin1"), NAME),
              lfhExtra: _unicodePathExtra(Buffer.from("evil/\xff.txt", "latin1"), NAME) } },
  ];
  for (var i = 0; i < refused.length; i += 1) {
    var got = await _readerOutcomes(buildClassicZip([refused[i].spec]));
    var code = "archive-read/unicode-path-mismatch";
    check("zip unicode path: " + refused[i].label + " is refused by inspect(), b.guardArchive.inspect, " +
      "extractEntries() and b.safeArchive.inspect",
      got.inspect === code && got.guard === code && got.extract === code && got.safe === code,
      JSON.stringify(got));
  }

  var effective = [
    { label: "a valid Unicode Path in both headers names the entry",
      spec: { name: NAME, data: GOOD, extra: _unicodePathExtra(EVIL, NAME), lfhExtra: _unicodePathExtra(EVIL, NAME) },
      want: EVIL },
    { label: "a Unicode Path whose CRC-32 does not match the name field is not used",
      spec: { name: NAME, data: GOOD, extra: _unicodePathExtra(EVIL, NAME, { crc: 1 }),
              lfhExtra: _unicodePathExtra(EVIL, NAME, { crc: 1 }) },
      want: NAME },
    { label: "an Info-ZIP Unicode Comment field (0x6375) does not name the entry",
      spec: { name: NAME, data: GOOD, extra: _unicodeCommentExtra(EVIL), lfhExtra: _unicodeCommentExtra(EVIL) },
      want: NAME },
  ];
  for (var j = 0; j < effective.length; j += 1) {
    var res;
    try { res = await _namesAndBodies(buildClassicZip([effective[j].spec])); }
    catch (err) { res = { error: String(err && (err.code || err.message)) }; }
    var want = effective[j].want;
    check("zip unicode path: " + effective[j].label + " (inspect, guard, extractEntries and b.safeArchive.inspect use " +
      JSON.stringify(want) + ")",
      !res.error && res.names.length === 1 && res.names[0] === want && res.critical === 0 &&
      res.bodies.length === 1 && res.bodies[0] === want + "=" + GOOD.toString("utf8") &&
      res.safe[0] === want, JSON.stringify(res));
  }

  var traversal = buildClassicZip([{ name: NAME, data: GOOD,
    extra: _unicodePathExtra("../../evil.txt", NAME), lfhExtra: _unicodePathExtra("../../evil.txt", NAME) }]);
  var travListed = await b.archive.read.zip(b.archive.adapters.buffer(traversal)).inspect();
  var travGuard = await b.guardArchive.inspect(b.archive.adapters.buffer(traversal), { profile: "strict" });
  var travCritical = travGuard.issues.filter(function (x) { return x.severity === "critical"; });
  var travExtract = await _extractEntriesErr(traversal);
  check("zip unicode path: a Unicode Path naming ../../evil.txt in both headers is listed under that name, " +
    "draws a critical guard issue and is refused by extractEntries()",
    travListed[0].name === "../../evil.txt" && travCritical.length > 0 &&
    travExtract && travExtract.code === "archive-read/guard-refused",
    JSON.stringify({ name: travListed[0].name, critical: travCritical.length, extract: travExtract && travExtract.code }));

  var lossy = buildClassicZip([{
    name: "unused", data: GOOD,
    nameBytes: Buffer.from("docs/ÿ.txt", "latin1"),
    lfhNameBytes: Buffer.from("docs/þ.txt", "latin1"),
  }]);
  var lossyGot = await _readerOutcomes(lossy);
  check("zip unicode path: local and central names that decode alike but differ as bytes are refused",
    lossyGot.inspect === "archive-read/lfh-cd-skew" && lossyGot.guard === "archive-read/lfh-cd-skew" &&
    lossyGot.extract === "archive-read/lfh-cd-skew", JSON.stringify(lossyGot));

  var UNAME = "docs/café.txt";
  var agreeing = buildClassicZip([
    { name: UNAME, data: GOOD, flags: 0x0800,
      extra: Buffer.concat([_extendedTimestampExtra(), _unicodePathExtra(UNAME, UNAME)]),
      lfhExtra: Buffer.concat([_unicodePathExtra(UNAME, UNAME), _extendedTimestampExtra()]) },
    { name: "plain.txt", data: GOOD, extra: _extendedTimestampExtra(), lfhExtra: _extendedTimestampExtra() },
  ]);
  // 7-Zip 26.03 on Windows writes a non-ASCII name in the OEM code page
  // (docs/caf\x82.txt) with bit 11 clear, and its UTF-8 form (docs/café.txt)
  // in a Unicode Path field. A name the OEM code page cannot hold is written
  // as UTF-8 with bit 11 set. bsdtar writes the OEM name with no Unicode Path.
  var sevens = [
    { label: "a 7-Zip archive with an OEM-code-page name field and a Unicode Path",
      bytes: Buffer.from(SEVEN_ZIP_OEM_NAME_ARCHIVE, "base64"),
      names: ["docs/", "docs/café.txt", "plain.txt"],
      bodies: ["docs/café.txt=GOOD\n", "plain.txt=x\n"] },
    { label: "a default 7-Zip archive of docs/café.txt and docs/日本.txt",
      bytes: Buffer.from(SEVEN_ZIP_DEFAULT_ARCHIVE, "base64"),
      names: ["docs/", "docs/café.txt", "docs/日本.txt"],
      bodies: ["docs/café.txt=hello\r\n", "docs/日本.txt=jp\r\n"] },
  ];
  for (var s = 0; s < sevens.length; s += 1) {
    var sres;
    try { sres = await _namesAndBodies(sevens[s].bytes); }
    catch (err) { sres = { error: String(err && (err.code || err.message)) }; }
    check("zip unicode path: " + sevens[s].label + " inspects, passes the strict guard and extracts under its UTF-8 names",
      !sres.error && JSON.stringify(sres.names) === JSON.stringify(sevens[s].names) && sres.critical === 0 &&
      JSON.stringify(sres.bodies) === JSON.stringify(sevens[s].bodies) &&
      JSON.stringify(sres.safe) === JSON.stringify(sevens[s].names), JSON.stringify(sres));
  }
  var bsdGot = await _readerOutcomes(Buffer.from(BSDTAR_OEM_NAME_ARCHIVE, "base64"));
  check("zip unicode path: a bsdtar archive with an OEM-code-page name and no Unicode Path still reads",
    bsdGot.inspect === "ok" && bsdGot.guard === "ok" && bsdGot.extract === "ok", JSON.stringify(bsdGot));

  var agreeGot = await _readerOutcomes(agreeing);
  var listed = await b.archive.read.zip(b.archive.adapters.buffer(agreeing)).inspect();
  var bodies = [];
  for await (var ent of b.archive.read.zip(b.archive.adapters.buffer(agreeing)).extractEntries()) {
    bodies.push(ent.name + "=" + ent.bytes.toString("utf8"));
  }
  check("zip unicode path: a Unicode Path equal to the name field, with a matching CRC-32, still reads",
    agreeGot.inspect === "ok" && agreeGot.guard === "ok" && agreeGot.extract === "ok" && agreeGot.safe === "ok" &&
    listed[0].name === UNAME && bodies.length === 2 && bodies[0] === UNAME + "=" + GOOD.toString("utf8"),
    JSON.stringify(agreeGot) + " " + JSON.stringify(bodies));
}

// A Unicode Path extra field (0x7075) of `length` bytes declared with a
// larger data size than the extra block holds.
function _overrunUnicodePathExtra(declared, length) {
  var f = Buffer.alloc(4 + length);
  f.writeUInt16LE(0x7075, 0);
  f.writeUInt16LE(declared, 2);
  if (length > 0) f[4] = 1;
  return f;
}

async function _rawNameOutcome(bytes) {
  var out = {};
  try {
    var listed = await b.archive.read.zip(b.archive.adapters.buffer(bytes)).inspect();
    out.listed = listed.map(function (e) { return [e.name, e.altNames]; });
  } catch (err) { out.listed = String(err && (err.code || err.message)); }
  try {
    var guarded = await b.guardArchive.inspect(b.archive.adapters.buffer(bytes), { profile: "strict" });
    out.critical = guarded.issues.filter(function (i) { return i.severity === "critical"; })
      .map(function (i) { return i.ruleId; });
    out.kinds = guarded.issues.map(function (i) { return i.kind; });
  } catch (err) { out.guard = String(err && (err.code || err.message)); }
  var e1 = await _extractEntriesErr(bytes);
  out.extractEntries = e1 ? String(e1.code) : "ok";
  var dest = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-rawname-"));
  try {
    await b.archive.read.zip(b.archive.adapters.buffer(bytes)).extract({ destination: dest });
    out.extract = "ok";
  } catch (err) { out.extract = String(err && err.code); }
  var unguarded = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-rawname-unguarded-"));
  try {
    await b.archive.read.zip(b.archive.adapters.buffer(bytes), { guardProfile: false })
      .extract({ destination: path.join(unguarded, "out") });
    out.unguarded = "ok";
  } catch (err) { out.unguarded = String(err && err.code); }
  out.escaped = fs.existsSync(path.join(unguarded, "evil.txt")) || fs.existsSync(path.join(os.tmpdir(), "evil.txt"));
  fs.rmSync(dest, { recursive: true, force: true });
  fs.rmSync(unguarded, { recursive: true, force: true });
  return out;
}

// Java's java.util.zip and Python 3.11's zipfile ignore the Unicode Path
// extra field and use the name field. When a valid Unicode Path names the
// entry, the guard and the extract path check judge the name field too.
async function testUnicodePathRawNameJudged() {
  var GOOD = Buffer.from("GOOD-CONTENT\n");
  var BENIGN = "docs/readme.txt";
  var raws = [
    { raw: "../../evil.txt", rule: "archive.zip-slip", unguarded: "filename/extraction-traversal" },
    { raw: "/tmp/evil.txt", rule: "archive.absolute-path", unguarded: "filename/extraction-absolute" },
    { raw: "..\\..\\evil.txt", rule: "archive.zip-slip", unguarded: "filename/extraction-traversal" },
  ];
  for (var i = 0; i < raws.length; i += 1) {
    var bytes = buildClassicZip([{ name: raws[i].raw, data: GOOD,
      extra: _unicodePathExtra(BENIGN, raws[i].raw), lfhExtra: _unicodePathExtra(BENIGN, raws[i].raw) }]);
    var got = await _rawNameOutcome(bytes);
    check("zip unicode path raw name: a name field of " + JSON.stringify(raws[i].raw) + " under a Unicode Path of " +
      BENIGN + " is listed with both names, draws " + raws[i].rule + " from the strict guard, and is refused by " +
      "extractEntries(), extract() and an unguarded extract()",
      JSON.stringify(got.listed) === JSON.stringify([[BENIGN, [raws[i].raw]]]) &&
      Array.isArray(got.critical) && got.critical.indexOf(raws[i].rule) !== -1 &&
      got.extractEntries === "archive-read/guard-refused" && got.extract === "archive-read/guard-refused" &&
      got.unguarded === raws[i].unguarded && got.escaped === false,
      JSON.stringify(got));
  }

  var direct = b.guardArchive.validateEntries([
    { name: BENIGN, altNames: ["../../evil.txt"], size: 1, compressedSize: 1 },
  ], { profile: "balanced" });
  check("zip unicode path raw name: b.guardArchive.validateEntries judges an entry's altNames",
    direct.issues.some(function (x) { return x.ruleId === "archive.zip-slip" && x.severity === "critical" &&
      x.snippet.indexOf("../../evil.txt") !== -1; }), JSON.stringify(direct.issues));
  var badRaw = b.guardArchive.validateEntries([{ name: BENIGN, altNames: 7, size: 1, compressedSize: 1 }]);
  check("zip unicode path raw name: altNames that is not an array is reported",
    badRaw.issues.some(function (x) { return x.ruleId === "archive.bad-entry-name"; }), JSON.stringify(badRaw.issues));

  var dupRaw = buildClassicZip([
    { name: "x.txt", data: GOOD, extra: _unicodePathExtra("a.txt", "x.txt"), lfhExtra: _unicodePathExtra("a.txt", "x.txt") },
    { name: "x.txt", data: GOOD, extra: _unicodePathExtra("b.txt", "x.txt"), lfhExtra: _unicodePathExtra("b.txt", "x.txt") },
  ]);
  var dupGot = await _rawNameOutcome(dupRaw);
  check("zip unicode path raw name: two entries whose name fields are equal draw a duplicate-name issue " +
    "although their Unicode Paths differ",
    Array.isArray(dupGot.kinds) && dupGot.kinds.indexOf("duplicate-entry-name") !== -1 &&
    dupGot.critical.indexOf("archive.duplicate-name") !== -1 && dupGot.extract === "archive-read/guard-refused",
    JSON.stringify(dupGot));

  var dupMixed = buildClassicZip([
    { name: "x.txt", data: GOOD, extra: _unicodePathExtra("a.txt", "x.txt"), lfhExtra: _unicodePathExtra("a.txt", "x.txt") },
    { name: "x.txt", data: GOOD },
  ], {});
  var dupMixedGot = await _rawNameOutcome(dupMixed);
  check("zip unicode path raw name: an entry's name field equal to another entry's only name draws a duplicate-name issue",
    Array.isArray(dupMixedGot.kinds) && dupMixedGot.kinds.indexOf("duplicate-entry-name") !== -1,
    JSON.stringify(dupMixedGot));

  var overruns = [
    { label: "a central Unicode Path whose declared size overruns the extra block",
      spec: { name: BENIGN, data: GOOD, extra: _overrunUnicodePathExtra(40, 10) } },
    { label: "a local Unicode Path whose declared size overruns the extra block",
      spec: { name: BENIGN, data: GOOD, lfhExtra: _overrunUnicodePathExtra(40, 10) } },
    { label: "a Unicode Path whose declared size overruns the extra block in both headers",
      spec: { name: BENIGN, data: GOOD, extra: _overrunUnicodePathExtra(40, 10), lfhExtra: _overrunUnicodePathExtra(40, 10) } },
    { label: "a Unicode Path whose header is cut off by the end of the extra block",
      spec: { name: BENIGN, data: GOOD, extra: Buffer.concat([_extendedTimestampExtra(), Buffer.from([0x75, 0x70])]) } },
  ];
  for (var o = 0; o < overruns.length; o += 1) {
    var og = await _readerOutcomes(buildClassicZip([overruns[o].spec]));
    var code = "archive-read/unicode-path-mismatch";
    check("zip unicode path: " + overruns[o].label + " is refused by inspect(), b.guardArchive.inspect, " +
      "extractEntries() and b.safeArchive.inspect",
      og.inspect === code && og.guard === code && og.extract === code && og.safe === code, JSON.stringify(og));
  }
  var otherOverrun = await _readerOutcomes(buildClassicZip([{ name: BENIGN, data: GOOD,
    extra: Buffer.concat([_extendedTimestampExtra().subarray(0, 4), Buffer.from([1])]) }]));
  check("zip unicode path: an overrunning extra field that is not a Unicode Path still reads",
    otherOverrun.inspect === "ok" && otherOverrun.guard === "ok" && otherOverrun.extract === "ok",
    JSON.stringify(otherOverrun));

  var sevens = [
    { bytes: Buffer.from(SEVEN_ZIP_OEM_NAME_ARCHIVE, "base64"),
      listed: [["docs/", []], ["docs/café.txt", []], ["plain.txt", []]] },
    { bytes: Buffer.from(SEVEN_ZIP_DEFAULT_ARCHIVE, "base64"),
      listed: [["docs/", []], ["docs/café.txt", []], ["docs/日本.txt", []]] },
  ];
  for (var s = 0; s < sevens.length; s += 1) {
    var sg = await _rawNameOutcome(sevens[s].bytes);
    check("zip unicode path raw name: 7-Zip archive " + s + " lists its OEM name fields in code page 437, " +
      "draws no strict guard issue and extracts",
      JSON.stringify(sg.listed) === JSON.stringify(sevens[s].listed) && Array.isArray(sg.kinds) &&
      sg.kinds.length === 0 && sg.extractEntries === "ok" && sg.extract === "ok" && sg.unguarded === "ok",
      JSON.stringify(sg));
  }
}

async function _altNameOutcome(bytes) {
  var out = {};
  try {
    var listed = await b.archive.read.zip(b.archive.adapters.buffer(bytes)).inspect();
    out.listed = listed.map(function (e) { return [e.name, e.altNames]; });
  } catch (err) { out.listed = String(err && (err.code || err.message)); }
  try {
    var guarded = await b.guardArchive.inspect(b.archive.adapters.buffer(bytes), { profile: "strict" });
    out.issues = guarded.issues.map(function (i) { return i.severity + ":" + i.ruleId; });
  } catch (err) { out.issues = String(err && (err.code || err.message)); }
  var e1 = await _extractEntriesErr(bytes);
  out.extractEntries = e1 ? String(e1.code) : "ok";
  return out;
}

function _hasAll(list, wanted) {
  return Array.isArray(list) && wanted.every(function (w) { return list.indexOf(w) !== -1; });
}

// A name field with general-purpose bit 11 clear is read two ways by the
// readers in use. Java's java.util.zip, bsdtar, and unzip and 7-Zip for a
// Unix-made entry decode it as UTF-8, and Java ignores the Unicode Path
// extra field. Python's zipfile, and 7-Zip for an entry made on FAT or NTFS,
// decode it as code page 437. Python 3.11 ignores the Unicode Path field.
// 7-Zip 26.03 on Windows extracted the two code-page-437 names below to one
// file.
async function testZipNameFieldDecodesJudged() {
  var BENIGN = "docs/readme.txt";
  var BIDI = Buffer.from("docs/gpj‮exe.txt", "utf8");
  var ZW = Buffer.from("docs/a​b.txt", "utf8");
  var A_GRAVE = Buffer.from([0xC3, 0x80, 0x2E, 0x74, 0x78, 0x74]);
  var C_CEDIL = Buffer.from([0xC3, 0x87, 0x2E, 0x74, 0x78, 0x74]);
  var E_UPPER = Buffer.from("É.txt", "utf8");
  var E_LOWER = Buffer.from("é.txt", "utf8");
  function hidden(nameField, unicodePath, data) {
    return { name: "x", nameBytes: nameField, data: Buffer.from(data || "GOOD\n"),
      extra: _unicodePathExtra(unicodePath, nameField), lfhExtra: _unicodePathExtra(unicodePath, nameField) };
  }
  function plain(nameField, data, flags) {
    return { name: "x", nameBytes: nameField, data: Buffer.from(data || "GOOD\n"), flags: flags || 0 };
  }

  var bidiCtl = await _altNameOutcome(buildClassicZip([plain(BIDI)]));
  var bidiHid = await _altNameOutcome(buildClassicZip([hidden(BIDI, BENIGN)]));
  check("zip name field decodes: a UTF-8 bidi name field under a benign Unicode Path lists both decodes, " +
    "draws the same critical bidi issue as the name field alone, and is refused by extractEntries()",
    JSON.stringify(bidiHid.listed) === JSON.stringify([[BENIGN, ["docs/gpjΓÇ«exe.txt", "docs/gpj‮exe.txt"]]]) &&
    _hasAll(bidiCtl.issues, ["critical:archive.filename.bidi"]) &&
    _hasAll(bidiHid.issues, ["critical:archive.filename.bidi"]) &&
    bidiHid.extractEntries === "archive-read/guard-refused",
    JSON.stringify({ ctl: bidiCtl, hid: bidiHid }));

  var zwCtl = await _altNameOutcome(buildClassicZip([plain(ZW)]));
  var zwHid = await _altNameOutcome(buildClassicZip([hidden(ZW, BENIGN)]));
  var zwRules = Array.isArray(zwCtl.issues) ? zwCtl.issues.filter(function (x) { return x.indexOf("zero-width") !== -1; }) : [];
  check("zip name field decodes: a UTF-8 zero-width name field under a benign Unicode Path draws the zero-width " +
    "issue the name field alone draws",
    zwRules.length > 0 && _hasAll(zwHid.issues, zwRules), JSON.stringify({ ctl: zwCtl, hid: zwHid }));

  var caseUtf8 = await _altNameOutcome(buildClassicZip([hidden(E_UPPER, "one.txt", "ONE\n"), hidden(E_LOWER, "two.txt", "TWO\n")]));
  check("zip name field decodes: UTF-8 name fields that collide case-insensitively under distinct Unicode Paths " +
    "draw a case-collision issue",
    _hasAll(caseUtf8.issues, ["high:archive.case-collision"]), JSON.stringify(caseUtf8));

  var caseCp437 = await _altNameOutcome(buildClassicZip([hidden(A_GRAVE, "one.txt", "ONE\n"), hidden(C_CEDIL, "two.txt", "TWO\n")]));
  check("zip name field decodes: name fields whose code page 437 decodes collide case-insensitively under " +
    "distinct Unicode Paths draw a case-collision issue",
    JSON.stringify(caseCp437.listed) === JSON.stringify([
      ["one.txt", ["├Ç.txt", "À.txt"]], ["two.txt", ["├ç.txt", "Ç.txt"]]]) &&
    _hasAll(caseCp437.issues, ["high:archive.case-collision"]), JSON.stringify(caseCp437));

  var noUp = await _altNameOutcome(buildClassicZip([plain(A_GRAVE, "ONE\n"), plain(C_CEDIL, "TWO\n")]));
  check("zip name field decodes: without a Unicode Path, UTF-8 name fields with bit 11 clear whose code page 437 " +
    "decodes collide case-insensitively list that decode and draw a case-collision issue",
    JSON.stringify(noUp.listed) === JSON.stringify([["À.txt", ["├Ç.txt"]], ["Ç.txt", ["├ç.txt"]]]) &&
    _hasAll(noUp.issues, ["high:archive.case-collision"]), JSON.stringify(noUp));

  var flagged = await _altNameOutcome(buildClassicZip([plain(A_GRAVE, "ONE\n", 0x0800), plain(C_CEDIL, "TWO\n", 0x0800)]));
  check("zip name field decodes: the same name fields with bit 11 set list no other decode and draw no issue",
    JSON.stringify(flagged.listed) === JSON.stringify([["À.txt", []], ["Ç.txt", []]]) &&
    Array.isArray(flagged.issues) && flagged.issues.length === 0 && flagged.extractEntries === "ok",
    JSON.stringify(flagged));

  var dupMix = await _altNameOutcome(buildClassicZip([
    plain(Buffer.from("├Ç.txt", "utf8"), "ONE\n", 0x0800), plain(A_GRAVE, "TWO\n")]));
  check("zip name field decodes: a bit-11 name equal to another entry's code page 437 decode draws a critical " +
    "duplicate-name issue and is refused by extractEntries()",
    _hasAll(dupMix.issues, ["critical:archive.duplicate-name"]) && dupMix.extractEntries === "archive-read/guard-refused",
    JSON.stringify(dupMix));

  var direct = b.guardArchive.validateEntries([
    { name: BENIGN, altNames: ["docs/other.txt", "../../evil.txt"], size: 1, compressedSize: 1 },
  ], { profile: "balanced" });
  check("zip name field decodes: b.guardArchive.validateEntries judges every entry of altNames",
    direct.issues.some(function (x) { return x.ruleId === "archive.zip-slip" && x.severity === "critical" &&
      x.snippet.indexOf("../../evil.txt") !== -1; }), JSON.stringify(direct.issues));
  var bad = [ "x.txt", [7], [""], ["ok.txt", null] ];
  for (var i = 0; i < bad.length; i += 1) {
    var badRv = b.guardArchive.validateEntries([{ name: BENIGN, altNames: bad[i], size: 1, compressedSize: 1 }]);
    check("zip name field decodes: altNames of " + JSON.stringify(bad[i]) + " is reported as archive.bad-entry-name",
      badRv.issues.some(function (x) { return x.ruleId === "archive.bad-entry-name"; }), JSON.stringify(badRv.issues));
  }
}

// A name field flagged UTF-8 (bit 11) must hold valid UTF-8. A name field
// with bit 11 clear that is not valid UTF-8 has one decode a reader can
// write, code page 437, and that decode is the name the entry is listed,
// judged and extracted under.
async function testZipNameFieldEncoding() {
  var GOOD = Buffer.from("GOOD\n");
  var INVALID = Buffer.from([0x64, 0x6F, 0x63, 0x73, 0x2F, 0xFF, 0x2E, 0x74, 0x78, 0x74]);
  var flagged = await _readerOutcomes(buildClassicZip([{ name: "x", nameBytes: INVALID, data: GOOD, flags: 0x0800 }]));
  var code = "archive-read/bad-utf8-name";
  check("zip name encoding: a name field flagged UTF-8 (bit 11) that is not valid UTF-8 is refused by inspect(), " +
    "b.guardArchive.inspect, extractEntries() and b.safeArchive.inspect",
    flagged.inspect === code && flagged.guard === code && flagged.extract === code && flagged.safe === code,
    JSON.stringify(flagged));
  var flaggedValid = await _readerOutcomes(buildClassicZip([{ name: "x", nameBytes: Buffer.from("docs/é.txt", "utf8"),
    data: GOOD, flags: 0x0800 }]));
  check("zip name encoding: a valid UTF-8 name field flagged UTF-8 still reads",
    flaggedValid.inspect === "ok" && flaggedValid.guard === "ok" && flaggedValid.extract === "ok" &&
    flaggedValid.safe === "ok", JSON.stringify(flaggedValid));

  var unflagged = await _altNameOutcome(buildClassicZip([{ name: "x", nameBytes: INVALID, data: GOOD }]));
  check("zip name encoding: an unflagged name field that is not valid UTF-8 is listed under its code page 437 " +
    "decode with no other decode",
    JSON.stringify(unflagged.listed) === JSON.stringify([["docs/ .txt", []]]), JSON.stringify(unflagged));

  var cp437Case = await _altNameOutcome(buildClassicZip([
    { name: "x", nameBytes: Buffer.from([0x82, 0x2E, 0x74, 0x78, 0x74]), data: Buffer.from("ONE\n") },
    { name: "x", nameBytes: Buffer.from([0x90, 0x2E, 0x74, 0x78, 0x74]), data: Buffer.from("TWO\n") },
  ]));
  check("zip name encoding: two unflagged non-UTF-8 name fields are judged by their code page 437 decodes " +
    "(a case collision, not a duplicate of two U+FFFD names)",
    JSON.stringify(cp437Case.listed) === JSON.stringify([["é.txt", []], ["É.txt", []]]) &&
    _hasAll(cp437Case.issues, ["high:archive.case-collision"]) &&
    cp437Case.issues.indexOf("critical:archive.duplicate-name") === -1 && cp437Case.extractEntries === "ok",
    JSON.stringify(cp437Case));

  var bsd = await _altNameOutcome(Buffer.from(BSDTAR_OEM_NAME_ARCHIVE, "base64"));
  check("zip name encoding: the bsdtar archive with an OEM name field lists docs/café.txt and no U+FFFD name",
    JSON.stringify(bsd.listed) === JSON.stringify([["docs/", []], ["docs/café.txt", []], ["plain.txt", []]]) &&
    bsd.extractEntries === "ok", JSON.stringify(bsd));
}

function _manyEntryZip(n) {
  var specs = [];
  for (var i = 0; i < n; i += 1) {
    specs.push({ name: "f" + String(i).padStart(6, "0") + ".txt", data: Buffer.from([0x61 + (i % 26)]) });
  }
  return buildClassicZip(specs);
}

async function _inspectReadCost(bytes) {
  var counted = _countingAdapter(bytes);
  var listed = await b.archive.read.zip(counted.adapter).inspect();
  var total = 0;
  for (var i = 0; i < counted.reads.length; i += 1) total += counted.reads[i].length;
  return { entries: listed.length, reads: counted.reads.length, bytes: total };
}

// The inspect() local-header pass reads the local headers in windows taken in
// file order, so the number of adapter reads follows the archive's size and
// not its entry count.
async function testInspectReadCost() {
  var window = C.BYTES.kib(64);
  var small = _manyEntryZip(6000);
  var large = _manyEntryZip(60000);
  var s = await _inspectReadCost(small);
  var l = await _inspectReadCost(large);
  check("zip inspect cost: 60000 entries take a number of reads bounded by the archive size, not the entry count",
    l.entries === 60000 && l.reads <= 4 + Math.ceil(large.length / window),
    "reads=" + l.reads + " size=" + large.length);
  check("zip inspect cost: ten times the entries take at most twelve times the reads",
    s.entries === 6000 && l.reads <= 12 * s.reads, "small=" + s.reads + " large=" + l.reads);
  check("zip inspect cost: the bytes read stay within twice the archive size",
    l.bytes <= 2 * large.length, "bytes=" + l.bytes + " size=" + large.length);
}

function _signedDescriptor(data) {
  return _buildDataDescriptor({}, zlib.crc32(data) >>> 0, data.length, data.length);
}

async function _entryEndOutcome(bytes) {
  var res = {};
  res.entries = await _extractEntriesErr(bytes, { guardProfile: false });
  res.disk = await _diskExtractErr(bytes);
  var nodeStream = require("node:stream");
  res.stream = null;
  try {
    var tr = b.archive.read.zip.fromTrustedStream(
      b.archive.adapters.trustedStream(nodeStream.Readable.from([bytes])), { guardProfile: false });
    for await (var x of tr.extractEntries()) { void x; }
  } catch (err) { res.stream = err; }
  return res;
}

// An entry whose data, read front to back, ends before the compressed size
// the central directory records. bsdtar reading a pipe ends a stored entry
// with flag bit 3 at the first signed data descriptor whose CRC-32 matches
// the bytes before it, and ends a deflate entry where the deflate stream
// ends. It then reads the bytes that follow as the next local header and
// extracts evil.txt from both files below.
async function testEntryEndAmbiguity() {
  var GOOD = Buffer.from("GOOD-CONTENT\n");
  var EVIL = Buffer.from("EVIL-PAYLOAD\n");
  var FLAG_DD = 0x0008;
  var hidden = _rawLfh("evil.txt", EVIL);

  var storedRegion = Buffer.concat([GOOD, _signedDescriptor(GOOD), hidden]);
  var storedDd = buildClassicZip([{
    name: "a.txt", data: storedRegion, flags: FLAG_DD, lfhCrc: 0, lfhCsize: 0, lfhUsize: 0,
    dataDescriptor: {},
  }]);
  var s = await _entryEndOutcome(storedDd);
  check("zip entry end: a stored data-descriptor entry holding a matching descriptor is refused by extractEntries",
    _hasCode(s.entries, "archive-read/ambiguous-entry-end"), s.entries ? String(s.entries.code) : "read without error");
  check("zip entry end: disk extract refuses the stored entry and writes nothing",
    _hasCode(s.disk.err, "archive-read/ambiguous-entry-end") && s.disk.left.length === 0,
    (s.disk.err ? String(s.disk.err.code) : "read without error") + " left=" + s.disk.left.join(","));
  check("zip entry end: fromTrustedStream refuses the stored entry",
    _hasCode(s.stream, "archive-read/ambiguous-entry-end"), s.stream ? String(s.stream.code) : "read without error");

  var deflated = zlib.deflateRawSync(GOOD);
  var deflateRegion = Buffer.concat([deflated, _signedDescriptor(deflated), hidden]);
  var deflateDd = buildClassicZip([{
    name: "a.txt", data: deflateRegion, method: 8, usize: GOOD.length, crc: zlib.crc32(GOOD) >>> 0,
    flags: FLAG_DD, lfhCrc: 0, lfhCsize: 0, lfhUsize: 0, dataDescriptor: {},
  }]);
  var d = await _entryEndOutcome(deflateDd);
  check("zip entry end: a deflate stream that ends before the compressed size is refused by extractEntries",
    _hasCode(d.entries, "archive-read/ambiguous-entry-end"), d.entries ? String(d.entries.code) : "read without error");
  check("zip entry end: disk extract refuses the short deflate stream and writes nothing",
    _hasCode(d.disk.err, "archive-read/ambiguous-entry-end") && d.disk.left.length === 0,
    (d.disk.err ? String(d.disk.err.code) : "read without error") + " left=" + d.disk.left.join(","));
  check("zip entry end: fromTrustedStream refuses the short deflate stream",
    _hasCode(d.stream, "archive-read/ambiguous-entry-end"), d.stream ? String(d.stream.code) : "read without error");

  var deflateNoDd = buildClassicZip([{
    name: "a.txt", data: Buffer.concat([deflated, hidden]), method: 8, usize: GOOD.length,
    crc: zlib.crc32(GOOD) >>> 0,
  }]);
  var d2 = await _extractEntriesErr(deflateNoDd, { guardProfile: false });
  check("zip entry end: trailing bytes after a deflate stream are refused without a data descriptor",
    _hasCode(d2, "archive-read/ambiguous-entry-end"), d2 ? String(d2.code) : "read without error");
  var deflatePad = buildClassicZip([{
    name: "a.txt", data: Buffer.concat([deflated, Buffer.alloc(1)]), method: 8, usize: GOOD.length,
    crc: zlib.crc32(GOOD) >>> 0,
  }]);
  var d3 = await _extractEntriesErr(deflatePad, { guardProfile: false });
  check("zip entry end: one padding byte after a deflate stream is refused",
    _hasCode(d3, "archive-read/ambiguous-entry-end"), d3 ? String(d3.code) : "read without error");

  var storedOk = null;
  var sigNoMatch = Buffer.concat([GOOD, Buffer.from([0x50, 0x4b, 0x07, 0x08]), Buffer.alloc(12, 0x33), GOOD]);
  try {
    storedOk = await _extractNames(buildClassicZip([{
      name: "a.txt", data: sigNoMatch, flags: FLAG_DD, lfhCrc: 0, lfhCsize: 0, lfhUsize: 0, dataDescriptor: {},
    }]));
  } catch (err) { storedOk = "ERR " + err.code; }
  check("zip entry end: stored data holding a descriptor signature whose CRC does not match still extracts",
    storedOk === "a.txt=" + sigNoMatch.toString("utf8"), String(storedOk));
  var nestedStream = buildClassicZip([{
    name: "inner.txt", data: GOOD, flags: FLAG_DD, lfhCrc: 0, lfhCsize: 0, lfhUsize: 0, dataDescriptor: {},
  }]);
  var nestedOk = null;
  try {
    var gotNested = null;
    var outerDd = buildClassicZip([{
      name: "nested.zip", data: nestedStream, flags: FLAG_DD, lfhCrc: 0, lfhCsize: 0, lfhUsize: 0, dataDescriptor: {},
    }]);
    for await (var ne of b.archive.read.zip(b.archive.adapters.buffer(outerDd), { guardProfile: false }).extractEntries()) {
      gotNested = ne.bytes;
    }
    nestedOk = gotNested && gotNested.equals(nestedStream);
  } catch (err) { nestedOk = "ERR " + err.code; }
  check("zip entry end: a stored data-descriptor entry whose content is a streamed ZIP still extracts",
    nestedOk === true, String(nestedOk));
  var storedDdOk = null;
  try {
    storedDdOk = await _extractNames(buildClassicZip([
      { name: "a.txt", data: GOOD, flags: FLAG_DD, lfhCrc: 0, lfhCsize: 0, lfhUsize: 0, dataDescriptor: {} },
      { name: "b.txt", data: EVIL, flags: FLAG_DD, lfhCrc: 0, lfhCsize: 0, lfhUsize: 0, dataDescriptor: { wide: true } },
    ]));
  } catch (err) { storedDdOk = "ERR " + err.code; }
  check("zip entry end: well-formed stored data-descriptor entries still extract",
    storedDdOk === "a.txt=GOOD-CONTENT\n,b.txt=EVIL-PAYLOAD\n", String(storedDdOk));
  var deflateDdOk = null;
  try {
    deflateDdOk = await _extractNames(buildClassicZip([{
      name: "a.txt", data: deflated, method: 8, usize: GOOD.length, crc: zlib.crc32(GOOD) >>> 0,
      flags: FLAG_DD, lfhCrc: 0, lfhCsize: 0, lfhUsize: 0, dataDescriptor: {},
    }]));
  } catch (err) { deflateDdOk = "ERR " + err.code; }
  check("zip entry end: a deflate data-descriptor entry whose stream ends at the compressed size still extracts",
    deflateDdOk === "a.txt=GOOD-CONTENT\n", String(deflateDdOk));
}

// A reader that walks the file front to back delimits an entry by the local
// header's flags, and the central-directory path delimits it by the CD's.
// Flag bit 3 set only in the local header makes bsdtar reading a pipe end
// the stored entry below at the hidden descriptor and extract evil.txt.
// Bits 0 (encrypted), 6 (strong encryption) and 13 (masked local header)
// also change how the entry data is read, so each must agree as well.
// Bit 11 (UTF-8 name) changes how the name is decoded: Java's ZipInputStream
// reads it from the local header and ZipFile from the central directory.
async function testLfhCdFlagSkew() {
  var GOOD = Buffer.from("GOOD-CONTENT\n");
  var EVIL = Buffer.from("EVIL-PAYLOAD\n");
  var region = Buffer.concat([GOOD, _signedDescriptor(GOOD), _rawLfh("evil.txt", EVIL)]);

  var lfhOnly = buildClassicZip([{ name: "a.txt", data: region, flags: 0, lfhFlags: 0x0008 }]);
  var r1 = await _entryEndOutcome(lfhOnly);
  check("zip flag skew: flag bit 3 set only in the local header is refused by extractEntries",
    _hasCode(r1.entries, "archive-read/lfh-cd-skew"), r1.entries ? String(r1.entries.code) : "read without error");
  check("zip flag skew: disk extract refuses the local-only bit 3 and writes nothing",
    _hasCode(r1.disk.err, "archive-read/lfh-cd-skew") && r1.disk.left.length === 0,
    (r1.disk.err ? String(r1.disk.err.code) : "read without error") + " left=" + r1.disk.left.join(","));
  check("zip flag skew: fromTrustedStream refuses the local-only bit 3",
    _hasCode(r1.stream, "archive-read/lfh-cd-skew"), r1.stream ? String(r1.stream.code) : "read without error");

  var cdOnly = buildClassicZip([{ name: "a.txt", data: GOOD, flags: 0x0008, lfhFlags: 0, dataDescriptor: {} }]);
  var e2 = await _extractEntriesErr(cdOnly, { guardProfile: false });
  check("zip flag skew: flag bit 3 set only in the central directory is refused",
    _hasCode(e2, "archive-read/lfh-cd-skew"), e2 ? String(e2.code) : "read without error");

  var skews = [0x0001, 0x0040, 0x2000, 0x0800];
  for (var i = 0; i < skews.length; i += 1) {
    var e3 = await _extractEntriesErr(buildClassicZip([{ name: "a.txt", data: GOOD, flags: 0, lfhFlags: skews[i] }]),
      { guardProfile: false });
    check("zip flag skew: local-only flag 0x" + skews[i].toString(16) + " is refused",
      _hasCode(e3, "archive-read/lfh-cd-skew"), e3 ? String(e3.code) : "read without error");
  }

  var A_GRAVE = Buffer.from([0xC3, 0x80, 0x2E, 0x74, 0x78, 0x74]);
  var utf8Skews = [
    { label: "local header", flags: 0, lfhFlags: 0x0800 },
    { label: "central directory", flags: 0x0800, lfhFlags: 0 },
  ];
  for (var u = 0; u < utf8Skews.length; u += 1) {
    var skewZip = buildClassicZip([{ name: "x", nameBytes: A_GRAVE, data: GOOD,
      flags: utf8Skews[u].flags, lfhFlags: utf8Skews[u].lfhFlags }]);
    var inspectErr = await _inspectErr(skewZip);
    var guardedErr = null;
    try { await b.guardArchive.inspect(b.archive.adapters.buffer(skewZip), { profile: "strict" }); }
    catch (err) { guardedErr = err; }
    var entriesErr = await _extractEntriesErr(skewZip, { guardProfile: false });
    check("zip flag skew: UTF-8 name flag (bit 11) set only in the " + utf8Skews[u].label +
      " on a non-ASCII name is refused by inspect(), b.guardArchive.inspect and extractEntries",
      _hasCode(inspectErr, "archive-read/lfh-cd-skew") && _hasCode(guardedErr, "archive-read/lfh-cd-skew") &&
      _hasCode(entriesErr, "archive-read/lfh-cd-skew"),
      JSON.stringify([inspectErr && inspectErr.code, guardedErr && guardedErr.code, entriesErr && entriesErr.code]));
  }
  var utf8Both = null;
  try {
    utf8Both = await _extractNames(buildClassicZip([{ name: "x", nameBytes: A_GRAVE, data: GOOD,
      flags: 0x0800, lfhFlags: 0x0800 }]));
  } catch (err) { utf8Both = "ERR " + err.code; }
  check("zip flag skew: UTF-8 name flag (bit 11) set in both headers still extracts",
    utf8Both === "À.txt=GOOD-CONTENT\n", String(utf8Both));
  var control = null;
  try { control = await _extractNames(buildClassicZip([{ name: "a.txt", data: region }])); }
  catch (err) { control = "ERR " + err.code; }
  check("zip flag skew: the same stored data without flag bit 3 in either header still extracts",
    control === "a.txt=" + region.toString("utf8"), String(control).slice(0, 40));
}

function _storedDescriptorZip(data) {
  return buildClassicZip([{
    name: "a.bin", data: data, flags: 0x0008, lfhCrc: 0, lfhCsize: 0, lfhUsize: 0, dataDescriptor: {},
  }]);
}

// The stored-entry descriptor scan visits every "PK\x07\x08" in the data.
// Data made of nothing else costs the same order of work per byte as data
// that holds none.
async function testDescriptorScanCost() {
  var hidden = _rawLfh("evil.txt", Buffer.from("EVIL-PAYLOAD\n"));
  var decoy = Buffer.concat([Buffer.from("AAAAA"), Buffer.from([0x50, 0x4b, 0x07, 0x08]), Buffer.alloc(4, 0x33)]);
  var fillers = [0, 1, 2, 3, 4, 5, 7, 9, 250, 300];
  var missed = [];
  var falseHits = [];
  for (var f = 0; f < fillers.length; f += 1) {
    var filler = Buffer.alloc(fillers[f]);
    for (var fb = 0; fb < filler.length; fb += 1) filler[fb] = 0x41 + (fb % 26);
    var prefix = Buffer.concat([decoy, filler]);
    var hit = await _extractEntriesErr(_storedDescriptorZip(Buffer.concat([prefix, _signedDescriptor(prefix), hidden])),
      { guardProfile: false });
    if (!_hasCode(hit, "archive-read/ambiguous-entry-end")) missed.push(fillers[f] + ":" + (hit ? hit.code : "ok"));
    var off = _buildDataDescriptor({}, (zlib.crc32(prefix) + 1) >>> 0, prefix.length, prefix.length);
    var miss = await _extractEntriesErr(_storedDescriptorZip(Buffer.concat([prefix, off, hidden])), { guardProfile: false });
    if (miss) falseHits.push(fillers[f] + ":" + miss.code);
  }
  check("zip descriptor scan: a matching descriptor shortly after another signature is refused at every gap length",
    missed.length === 0, missed.join(","));
  check("zip descriptor scan: a descriptor whose CRC-32 is one off is not refused at any gap length",
    falseHits.length === 0, falseHits.join(","));

  var size = C.BYTES.mib(8);
  var dense = Buffer.alloc(size);
  for (var i = 0; i + 4 <= size; i += 4) dense.writeUInt32LE(0x08074b50, i);
  var inputs = {
    plain:  _storedDescriptorZip(Buffer.alloc(size)),
    dense:  _storedDescriptorZip(dense),
    dense2: _storedDescriptorZip(Buffer.concat([dense, dense])),
  };
  async function extractOnce(key) {
    var r = b.archive.read.zip(b.archive.adapters.buffer(inputs[key]), { guardProfile: false });
    var n = 0;
    for await (var e of r.extractEntries()) n += e.bytes.length;
    if (n === 0) throw new Error("descriptor scan cost: nothing extracted for " + key);
  }
  var content = await helpers.looksSuperlinearAsync(extractOnce, { small: "plain", large: "dense", threshold: 16 });
  check("zip descriptor scan: data full of descriptor signatures costs at most a small multiple of plain data",
    content.superlinear === false, "ratio=" + content.ratio);
  var growth = await helpers.looksSuperlinearAsync(extractOnce, { small: "dense", large: "dense2" });
  check("zip descriptor scan: doubling data full of descriptor signatures does not more than double the work",
    growth.superlinear === false, "ratio=" + growth.ratio);
}

// Every extracted entry is checked against the CRC-32 its central directory
// records, and a data descriptor must agree with the central directory.
async function testCrcVerification() {
  var opts = { guardProfile: false };
  var good = Buffer.from("GOOD-CONTENT-0123456789-abcdefghij", "utf8");
  var evil = Buffer.from("EVIL-CONTENT-0123456789-abcdefghij", "utf8");
  var goodCrc = zlib.crc32(good) >>> 0;

  // STORE: data replaced in place, both CRC fields left at the original.
  var storeSwap = buildClassicZip([{ name: "s.txt", data: evil, crc: goodCrc }]);
  var e1 = await _extractEntriesErr(storeSwap, opts);
  check("zip crc: STORE entry whose bytes do not match the CD CRC is refused (extractEntries)",
    _hasCode(e1, "archive-read/crc-mismatch"), e1 ? String(e1.code) : "extracted without error");

  var dest = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-crc-"));
  var e2 = null;
  try { await b.archive.read.zip(b.archive.adapters.buffer(storeSwap), opts).extract({ destination: dest }); }
  catch (err) { e2 = err; }
  check("zip crc: disk extract refuses the mismatch", _hasCode(e2, "archive-read/crc-mismatch"));
  check("zip crc: no file is left behind after the refusal", !fs.existsSync(path.join(dest, "s.txt")));
  fs.rmSync(dest, { recursive: true, force: true });

  // DEFLATE: a different same-length deflate stream with the same size.
  var goodDef = zlib.deflateRawSync(good, { level: 0 });
  var evilDef = zlib.deflateRawSync(evil, { level: 0 });
  check("zip crc: fixture deflate streams are the same length", goodDef.length === evilDef.length);
  var deflateSwap = buildClassicZip([{
    name: "d.txt", data: evilDef, method: 8, usize: evil.length, csize: evilDef.length, crc: goodCrc,
  }]);
  var e3 = await _extractEntriesErr(deflateSwap, opts);
  check("zip crc: DEFLATE entry whose inflated bytes do not match the CD CRC is refused",
    _hasCode(e3, "archive-read/crc-mismatch"), e3 ? String(e3.code) : "extracted without error");

  // Trusted-stream reader and the b.safeArchive consumer path.
  var nodeStream = require("node:stream");
  var e4 = null;
  try {
    var tr = b.archive.read.zip.fromTrustedStream(
      b.archive.adapters.trustedStream(nodeStream.Readable.from([storeSwap])), opts);
    for await (var x of tr.extractEntries()) { void x; }
  } catch (err) { e4 = err; }
  check("zip crc: trusted-stream reader refuses the mismatch", _hasCode(e4, "archive-read/crc-mismatch"));

  var dest2 = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-crc-safe-"));
  var e5 = null;
  try { await b.safeArchive.extract({ source: storeSwap, destination: dest2, guardProfile: "balanced" }); }
  catch (err) { e5 = err; }
  finally { fs.rmSync(dest2, { recursive: true, force: true }); }
  check("zip crc: b.safeArchive.extract refuses the mismatch",
    !!e5 && /crc-mismatch/.test(String(e5.code) + " " + String(e5.message)));

  // An empty entry must still record the CRC of zero bytes.
  var emptyBadCrc = buildClassicZip([{ name: "e.txt", data: Buffer.alloc(0), crc: 0x12345678 }]);
  var e6 = await _extractEntriesErr(emptyBadCrc, opts);
  check("zip crc: empty entry with a non-zero CRC is refused", _hasCode(e6, "archive-read/crc-mismatch"));

  // Data descriptor (general-purpose flag bit 3). The LFH carries zeros and
  // the descriptor after the data carries the CRC and sizes.
  var FLAG_DD = 0x0008;
  function ddEntry(dd, more) {
    var s = { name: "dd.txt", data: good, flags: FLAG_DD, lfhCrc: 0, lfhCsize: 0, lfhUsize: 0, dataDescriptor: dd };
    if (more) Object.keys(more).forEach(function (k) { s[k] = more[k]; });
    return buildClassicZip([s]);
  }
  async function ddRead(bytes) {
    var got = null;
    for await (var ent of b.archive.read.zip(b.archive.adapters.buffer(bytes), opts).extractEntries()) { got = ent; }
    return got;
  }
  var okDd = await ddRead(ddEntry({}));
  check("zip crc: entry with a signed data descriptor extracts", okDd && okDd.bytes.equals(good));
  var okDdNoSig = await ddRead(ddEntry({ sig: false }));
  check("zip crc: entry with an unsigned data descriptor extracts", okDdNoSig && okDdNoSig.bytes.equals(good));
  var okDdWide = await ddRead(ddEntry({ wide: true }));
  check("zip crc: entry with a 64-bit data descriptor extracts", okDdWide && okDdWide.bytes.equals(good));

  var e7 = await _extractEntriesErr(ddEntry({ crc: 0xdeadbeef }), opts);
  check("zip crc: data descriptor CRC disagreeing with the CD is refused",
    _hasCode(e7, "archive-read/lfh-cd-skew"), e7 ? String(e7.code) : "extracted without error");
  var e8 = await _extractEntriesErr(ddEntry({ usize: 3 }), opts);
  check("zip crc: data descriptor size disagreeing with the CD is refused",
    _hasCode(e8, "archive-read/lfh-cd-skew"), e8 ? String(e8.code) : "extracted without error");
  var noDd = buildClassicZip([{ name: "dd.txt", data: good, flags: FLAG_DD, lfhCrc: 0, lfhCsize: 0, lfhUsize: 0 }]);
  var e9 = await _extractEntriesErr(noDd, opts);
  check("zip crc: flag bit 3 with no data descriptor is refused",
    _hasCode(e9, "archive-read/lfh-cd-skew"), e9 ? String(e9.code) : "extracted without error");
  var e10 = await _extractEntriesErr(ddEntry({}, { lfhCrc: 0x0badf00d }), opts);
  check("zip crc: a non-zero LFH CRC disagreeing with the CD is refused even with a data descriptor",
    _hasCode(e10, "archive-read/lfh-cd-skew"), e10 ? String(e10.code) : "extracted without error");

  // The framework's streaming writer emits data descriptors; its output
  // reads back byte for byte.
  var zs = b.archive.zip();
  zs.addFile("streamed.txt", nodeStream.Readable.from([good]));
  zs.addFile("buffered.txt", evil);
  var sink = [];
  var collector = new nodeStream.Writable({
    write: function (chunk, enc, cb) { sink.push(Buffer.from(chunk)); cb(); },
  });
  await zs.toStream(collector);
  var streamed = Buffer.concat(sink);
  var names = {};
  for await (var se of b.archive.read.zip(b.archive.adapters.buffer(streamed)).extractEntries()) {
    names[se.name] = se.bytes;
  }
  check("zip crc: streaming-writer output with data descriptors reads back",
    names["streamed.txt"] && names["streamed.txt"].equals(good) &&
    names["buffered.txt"] && names["buffered.txt"].equals(evil));
}

// AbortSignal with a reason string surfaces the reason in the thrown message.
async function testAbortWithReason() {
  var z = b.archive.zip();
  z.addFile("a.txt", "x");
  var bytes = z.toBuffer();
  var ac = new AbortController();
  ac.abort("operator cancelled the read");
  var e = null;
  try { await b.archive.read.zip(b.archive.adapters.buffer(bytes), { signal: ac.signal }).inspect(); }
  catch (err) { e = err; }
  check("archive-read: abort reason surfaced in message",
    _hasCode(e, "archive-read/aborted") && (e.message || "").indexOf("operator cancelled") !== -1);

  // A signal-like object whose aborted flag is set but that carries no reason
  // exercises the no-reason message branch.
  var e2 = null;
  try { await b.archive.read.zip(b.archive.adapters.buffer(bytes), { signal: { aborted: true } }).inspect(); }
  catch (err) { e2 = err; }
  check("archive-read: aborted signal without a reason still refuses", _hasCode(e2, "archive-read/aborted"));
}

// The local-header preflight that extract and extractEntries run before the
// first entry honors opts.signal: an abort after inspect() makes no further
// adapter reads, and an abort during the preflight stops it at the next read.
async function testAbortStopsTheLayoutPreflight() {
  var z = b.archive.zip();
  for (var n = 0; n < 50; n += 1) z.addFile("f" + n + ".txt", "content " + n);
  var bytes = z.toBuffer();
  var inner = b.archive.adapters.buffer(bytes);

  var reads = 0;
  var counting = Object.assign({}, inner, {
    range: function (offset, length) { reads += 1; return inner.range(offset, length); },
  });
  var ac = new AbortController();
  var reader = b.archive.read.zip(counting, { signal: ac.signal });
  await reader.inspect();
  ac.abort("stop");
  var before = reads;
  var e = null;
  try { for await (var _x of reader.extractEntries()) { void _x; } }
  catch (err) { e = err; }
  check("archive-read: an abort after inspect stops extractEntries with no further adapter reads",
    _hasCode(e, "archive-read/aborted") && reads === before, "reads after abort=" + (reads - before));

  var reads2 = 0;
  var ac2 = new AbortController();
  var spread = b.archive.adapters.buffer(_spreadZip(50));
  var midway = Object.assign({}, spread, {
    range: function (offset, length) {
      reads2 += 1;
      if (reads2 === 6) ac2.abort("stop midway");
      return spread.range(offset, length);
    },
  });
  var e2 = null;
  try { for await (var _y of b.archive.read.zip(midway, { signal: ac2.signal }).extractEntries()) { void _y; } }
  catch (err) { e2 = err; }
  check("archive-read: an abort during the layout preflight stops it at the next read",
    _hasCode(e2, "archive-read/aborted") && reads2 <= 7, "reads=" + reads2);
}

async function run() {
  await testAbortStopsTheLayoutPreflight();
  await testMalformedRefusals();
  await testLfhCdSkewRefusals();
  await testBombPolicyEdges();
  await testExpansionRatioHonorsPolicy();
  await testDecompressPaths();
  await testZipFactoryAdapterGuards();
  await testEntryTypeClassification();
  await testEntryTypePolicyRefusals();
  await testEncryptedEntryRefusal();
  await testEntriesGenerators();
  await testExtractDirAndCleanup();
  await testZip64TrailerErrors();
  await testZip64ExtraErrors();
  await testObjectStoreAdapterResolveSize();
  await testAbortWithReason();
  await testCdPositionRefusals();
  await testHiddenArchiveRefusals();
  await testEmbeddedStructureRefusals();
  await testInspectVerifiesLocalHeaders();
  await testUnicodePathExtraField();
  await testUnicodePathRawNameJudged();
  await testZipNameFieldDecodesJudged();
  await testZipNameFieldEncoding();
  await testInspectReadCost();
  await testEntryEndAmbiguity();
  await testLfhCdFlagSkew();
  await testDescriptorScanCost();
  await testCrcVerification();
  await testZip64Read();
  await testRoundTripExtract();
  await testExtractEntriesInMemory();
  await testExtractToMemoryOrchestrator();
  await testSignalAbort();
  testSafeArchiveErrorClass();
  await testSafeArchiveInspect();
  await testZipBombPolicy();
  testEntryTypePolicy();
  testVerifyExtractionPathHappy();
  testVerifyExtractionPathRefusals();
  testVerifyExtractionPathWindowsHazards();
  await testExtractRefusesOverwrite();
  await testSafeArchiveRefusesTrustedStreamSource();
  await testFromTrustedStreamRoundTrip();
  await testGuardArchiveInspect();
  await testBundleAdapterStorageRoundTrip();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[archive-read] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
