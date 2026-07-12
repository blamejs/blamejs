// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.archive.read.tar — error / adversarial / defensive / option-default
 * coverage for the POSIX pax tar reader (lib/archive-tar-read.js).
 *
 * The sibling archive-tar-hardening.test.js pins the two hardening fixes
 * (random-access read cap + PAX-size NaN walker desync). This file drives
 * the remaining uncovered branches of the reader through the real
 * `b.archive.read.tar(...)` consumer path:
 *
 *   - adapter validation + adapter-kind collection (buffer / trustedStream
 *     / null-size random-access with resolveSize),
 *   - typeflag classification across every POSIX type,
 *   - the pax extended + global header merge, the malformed-pax-record and
 *     malformed-pax-size rejections, and the oversized/truncated pax body,
 *   - the walker's too-many-entries / entry-too-large / truncated-entry
 *     refusals and the single-vs-double zero-block terminator,
 *   - the guardArchive critical-issue cascade (guard-refused),
 *   - extractEntries + extract entry-type refusals, the total-decompressed
 *     cap, destination-exists refusal + cleanup, and hardlink creation.
 *
 * Fixtures build tars two ways: the real `b.archive.tar()` builder for
 * well-formed archives, and a hand-rolled ustar header builder for the
 * adversarial typeflags (symlink / hardlink / device / fifo / unknown) and
 * malformed pax bodies the write side refuses to emit.
 */

var nodeStream = require("node:stream");
var helpers = require("../helpers");
var check = helpers.check;
var b = helpers.b;
var fs = helpers.fs;
var os = helpers.os;
var path = helpers.path;

var BLOCK = 512;

// ---- hand-rolled ustar fixture builders ---------------------------------
//
// A minimal ustar header with a valid POSIX checksum. Enough for the
// reader's _parseHeader (magic at 257 + checksum at 148 are validated); the
// remaining fields are octal / NUL-terminated ASCII per POSIX.1-1988.

function _oct(n, digits) {
  var s = Math.floor(n).toString(8);
  while (s.length < digits) s = "0" + s;
  return s;
}

function _rawHeader(o) {
  var buf = Buffer.alloc(BLOCK, 0);
  var name = o.name || "";
  buf.write(name, 0, Math.min(Buffer.byteLength(name), 100), "ascii");
  buf.write(_oct(o.mode == null ? 0o644 : o.mode, 7) + "\0", 100, 8, "ascii");
  buf.write(_oct(o.uid || 0, 7) + "\0", 108, 8, "ascii");
  buf.write(_oct(o.gid || 0, 7) + "\0", 116, 8, "ascii");
  buf.write(_oct(o.size || 0, 11) + "\0", 124, 12, "ascii");
  buf.write(_oct(o.mtime || 0, 11) + "\0", 136, 12, "ascii");
  // typeflag defaults to NUL (legacy regular) when omitted.
  if (o.typeflag != null) buf.write(o.typeflag, 156, 1, "ascii");
  if (o.linkname) buf.write(o.linkname, 157, Math.min(o.linkname.length, 100), "ascii");
  if (!o.badMagic) {
    buf.write("ustar\0", 257, 6, "ascii");
    buf.write("00", 263, 2, "ascii");
  }
  if (o.uname) buf.write(o.uname, 265, Math.min(o.uname.length, 32), "ascii");
  if (o.gname) buf.write(o.gname, 297, Math.min(o.gname.length, 32), "ascii");
  // checksum: chksum field treated as 8 ASCII spaces while summing.
  for (var i = 148; i < 156; i += 1) buf[i] = 0x20;
  if (o.badChksum) {
    // A deliberately-wrong stored checksum → reader must reject.
    buf.write("000000\0 ", 148, 8, "ascii");
    return buf;
  }
  var sum = 0;
  for (var j = 0; j < BLOCK; j += 1) sum += buf[j];
  var oct = sum.toString(8);
  while (oct.length < 6) oct = "0" + oct;
  buf.write(oct + "\0 ", 148, 8, "ascii");
  return buf;
}

function _pad512(buf) {
  var rem = buf.length % BLOCK;
  return rem === 0 ? buf : Buffer.concat([buf, Buffer.alloc(BLOCK - rem, 0)]);
}

function _end() { return Buffer.alloc(BLOCK * 2, 0); }

// Iteratively-computed POSIX.1-2001 pax record: "<len> key=value\n" where
// <len> counts its own digits (mirrors lib/archive-tar.js _buildPaxRecord).
function _paxRecord(key, value) {
  var kv = key + "=" + value + "\n";
  var len = kv.length + 1;
  while (true) {
    var s = String(len) + " " + kv;
    if (s.length === len) return s;
    len = s.length;
  }
}

function _paxBody(records) {
  var s = "";
  for (var i = 0; i < records.length; i += 1) s += _paxRecord(records[i][0], records[i][1]);
  return Buffer.from(s, "utf8");
}

// A pax extended ('x') or global ('g') header followed by its padded body.
function _paxHeaderBlock(typeflag, bodyBuf, declaredSize) {
  var size = declaredSize == null ? bodyBuf.length : declaredSize;
  var hdr = _rawHeader({ name: "PaxHeader/x", size: size, typeflag: typeflag });
  return Buffer.concat([hdr, _pad512(bodyBuf)]);
}

// ---- error-code capture helpers -----------------------------------------

function _code(promise) {
  return promise.then(
    function () { return null; },
    function (e) { return (e && e.code) || (e && e.message) || "threw"; });
}

async function _iterCode(gen) {
  try {
    for await (var _e of gen) { void _e; }
    return null;
  } catch (e) {
    return (e && e.code) || (e && e.message) || "threw";
  }
}

async function _collectEntries(gen) {
  var out = [];
  for await (var e of gen) out.push(e);
  return out;
}

function _auditSink() {
  var events = [];
  return {
    events:   events,
    safeEmit: function (ev) { events.push(ev); },
  };
}

function _tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-tar-read-"));
}

// -------------------------------------------------------------------------

function testBadAdapterRejected() {
  function threwCode(fn) { try { fn(); return null; } catch (e) { return e && e.code; } }
  check("read.tar rejects a null adapter",
    threwCode(function () { b.archive.read.tar(null); }) === "archive-tar/bad-adapter");
  check("read.tar rejects a wrong-kind adapter object",
    threwCode(function () { b.archive.read.tar({ kind: "nope" }); }) === "archive-tar/bad-adapter");
}

async function testEmptyArchiveInspect() {
  // Empty buffer → the random-access collector returns a zero-length read
  // (size <= 0 short-circuit) and _walk returns no entries.
  var entries = await b.archive.read.tar(b.archive.adapters.buffer(Buffer.alloc(0))).inspect();
  check("read.tar inspect of an empty archive yields []", entries.length === 0);
}

async function testInspectClassifiesEveryTypeflag() {
  // Metadata-only entries covering every POSIX typeflag the classifier
  // handles. inspect() classifies without applying the entry-type policy,
  // so a single archive exercises every _classifyTypeflag branch.
  var tar = Buffer.concat([
    _rawHeader({ name: "regular",    size: 0, typeflag: "0" }),
    _rawHeader({ name: "legacy" }),                                   // typeflag NUL
    _rawHeader({ name: "dir",        size: 0, typeflag: "5" }),
    _rawHeader({ name: "sym",        size: 0, typeflag: "2", linkname: "t" }),
    _rawHeader({ name: "hard",       size: 0, typeflag: "1", linkname: "t" }),
    _rawHeader({ name: "chardev",    size: 0, typeflag: "3" }),
    _rawHeader({ name: "blockdev",   size: 0, typeflag: "4" }),
    _rawHeader({ name: "fifo",       size: 0, typeflag: "6" }),
    _rawHeader({ name: "contig",     size: 0, typeflag: "7" }),
    _rawHeader({ name: "weird",      size: 0, typeflag: "Z" }),
    _end(),
  ]);
  var entries = await b.archive.read.tar(b.archive.adapters.buffer(tar)).inspect();
  var byName = {};
  entries.forEach(function (e) { byName[e.name] = e.entryType; });
  check("classify regular → file", byName.regular === "file");
  check("classify legacy NUL typeflag → file", byName.legacy === "file");
  check("classify directory → directory", byName.dir === "directory");
  check("classify symlink → symlink", byName.sym === "symlink");
  check("classify hardlink → hardlink", byName.hard === "hardlink");
  check("classify char-device → device", byName.chardev === "device");
  check("classify block-device → device", byName.blockdev === "device");
  check("classify fifo → fifo", byName.fifo === "fifo");
  check("classify contiguous → file", byName.contig === "file");
  check("classify unknown typeflag → unknown", byName.weird === "unknown");
  check("inspect surfaces every entry", entries.length === 10);
  // inspect maps mtime through Date(seconds).
  check("inspect maps mtime to a Date", entries[0].mtime instanceof Date);
}

async function testInspectRealBuilderRoundTrip() {
  var t = b.archive.tar();
  t.addDirectory("docs");
  t.addFile("docs/readme.txt", "hello world\n");
  var entries = await b.archive.read.tar(b.archive.adapters.buffer(t.toBuffer())).inspect();
  var names = entries.map(function (e) { return e.name; }).sort();
  check("read.tar round-trips the builder's directory entry", names.indexOf("docs/") !== -1);
  check("read.tar round-trips the builder's file entry", names.indexOf("docs/readme.txt") !== -1);
}

async function testTrustedStreamAdapter() {
  var t = b.archive.tar();
  t.addFile("a.txt", "alpha");
  var bytes = t.toBuffer();
  var readable = nodeStream.Readable.from([bytes]);
  var entries = await b.archive.read.tar(b.archive.adapters.trustedStream(readable)).inspect();
  check("read.tar reads a trusted-sequential stream adapter", entries.length === 1);
  check("trusted-stream entry name preserved", entries[0].name === "a.txt");
}

async function testNullSizeRandomAccessResolvesSize() {
  var t = b.archive.tar();
  t.addFile("r.txt", "range-adapter-body");
  var bytes = t.toBuffer();
  // A random-access adapter whose size is unknown until resolveSize() runs —
  // exercises the `size == null → await adapter.resolveSize()` branch.
  var adapter = {
    kind:        "random-access",
    size:        null,
    resolveSize: function () { return Promise.resolve(bytes.length); },
    range:       function (off, len) { return Promise.resolve(bytes.slice(off, off + len)); },
    close:       function () {},
  };
  var entries = await b.archive.read.tar(adapter).inspect();
  check("read.tar resolves a null-size random-access adapter via resolveSize()",
    entries.length === 1 && entries[0].name === "r.txt");

  // resolveSize() reporting 0 → the collector short-circuits to an empty read.
  var emptyAdapter = {
    kind:        "random-access",
    size:        null,
    resolveSize: function () { return Promise.resolve(0); },
    range:       function () { return Promise.resolve(Buffer.alloc(0)); },
    close:       function () {},
  };
  var none = await b.archive.read.tar(emptyAdapter).inspect();
  check("read.tar treats a resolveSize()==0 source as empty", none.length === 0);
}

async function testRandomAccessSourceTooLarge() {
  var t = b.archive.tar();
  t.addFile("big.txt", "x".repeat(200));
  var bytes = t.toBuffer();
  var code = await _code(b.archive.read.tar(b.archive.adapters.buffer(bytes), {
    bombPolicy: { maxTotalDecompressedBytes: 64 },
  }).inspect());
  check("read.tar refuses a random-access source over the read cap",
    code === "archive-tar/source-too-large");
}

async function testPaxExtendedOverrides() {
  var body = _paxBody([["path", "renamed/from-pax.txt"], ["size", "5"], ["linkpath", "target/x"]]);
  var tar = Buffer.concat([
    _paxHeaderBlock("x", body),
    _rawHeader({ name: "orig.txt", size: 5, typeflag: "0" }),
    _pad512(Buffer.from("hello")),
    _end(),
  ]);
  var entries = await b.archive.read.tar(b.archive.adapters.buffer(tar)).inspect();
  check("pax extended path override applied", entries[0].name === "renamed/from-pax.txt");
  check("pax extended size override applied", entries[0].size === 5);
  check("pax extended linkpath override applied", entries[0].linkname === "target/x");
}

async function testPaxGlobalOverrides() {
  var body = _paxBody([["path", "global/name.txt"], ["size", "5"], ["linkpath", "global/link"]]);
  var tar = Buffer.concat([
    _paxHeaderBlock("g", body),
    _rawHeader({ name: "ignored.txt", size: 5, typeflag: "0" }),
    _pad512(Buffer.from("world")),
    _end(),
  ]);
  var entries = await b.archive.read.tar(b.archive.adapters.buffer(tar)).inspect();
  check("pax global path override applied", entries[0].name === "global/name.txt");
  check("pax global size override applied", entries[0].size === 5);
  check("pax global linkpath override applied", entries[0].linkname === "global/link");
}

async function testPaxMalformedRecordsRefused() {
  var cases = [
    { label: "no length-space delimiter", body: Buffer.from("noodle") },
    { label: "non-positive record length", body: Buffer.from("0 x=y\n") },
    { label: "record not newline-terminated", body: Buffer.from("6 x=yz") },
    { label: "record missing key=value", body: Buffer.from("5 ab\n") },
  ];
  for (var i = 0; i < cases.length; i += 1) {
    var tar = Buffer.concat([_paxHeaderBlock("x", cases[i].body)]);
    var code = await _code(b.archive.read.tar(b.archive.adapters.buffer(tar)).inspect());
    check("read.tar refuses malformed pax record (" + cases[i].label + ")",
      code === "archive-tar/bad-pax-record");
  }
}

async function testPaxMalformedSizeRefused() {
  // A truthy-but-non-integer pax size reaches _paxSize and is refused.
  var body = _paxBody([["size", "abc"]]);
  var tar = Buffer.concat([
    _paxHeaderBlock("x", body),
    _rawHeader({ name: "f.txt", size: 1, typeflag: "0" }),
    _pad512(Buffer.from("z")),
    _end(),
  ]);
  var code = await _code(b.archive.read.tar(b.archive.adapters.buffer(tar)).inspect());
  check("read.tar refuses a non-integer pax size override", code === "archive-tar/bad-pax-size");
}

async function testPaxBodyRespectsPerEntryCap() {
  // A pax header body larger than maxEntryDecompressedBytes is refused before
  // the UTF-8 + record-object materialization (cap sits after the pax branch's
  // continue, so it previously escaped it).
  var tar = Buffer.concat([_rawHeader({ name: "PaxHeader/x", size: 4096, typeflag: "x" })]);
  var code = await _code(b.archive.read.tar(b.archive.adapters.buffer(tar), {
    bombPolicy: { maxEntryDecompressedBytes: 1024 },
  }).inspect());
  check("read.tar caps an oversized pax header body", code === "archive-tar/entry-too-large");
}

async function testPaxBodyTruncatedRefused() {
  // Pax header declares a body larger than what the archive actually carries.
  var tar = Buffer.concat([_rawHeader({ name: "PaxHeader/x", size: 600, typeflag: "x" })]);
  var code = await _code(b.archive.read.tar(b.archive.adapters.buffer(tar)).inspect());
  check("read.tar refuses a truncated pax body", code === "archive-tar/truncated-entry");
}

async function testTooManyEntriesRefused() {
  var t = b.archive.tar();
  t.addFile("one.txt", "a");
  t.addFile("two.txt", "b");
  var code = await _code(b.archive.read.tar(b.archive.adapters.buffer(t.toBuffer()), {
    bombPolicy: { maxEntries: 1 },
  }).inspect());
  check("read.tar refuses an archive over maxEntries", code === "archive-tar/too-many-entries");
}

async function testEntryTooLargeRefused() {
  var t = b.archive.tar();
  t.addFile("payload.txt", "x".repeat(300));
  var code = await _code(b.archive.read.tar(b.archive.adapters.buffer(t.toBuffer()), {
    bombPolicy: { maxEntryDecompressedBytes: 100 },
  }).inspect());
  check("read.tar refuses an entry over maxEntryDecompressedBytes",
    code === "archive-tar/entry-too-large");
}

async function testTruncatedEntryRefused() {
  // Header declares 100 bytes but the archive ends immediately after it.
  var tar = Buffer.concat([_rawHeader({ name: "cut.txt", size: 100, typeflag: "0" })]);
  var code = await _code(b.archive.read.tar(b.archive.adapters.buffer(tar)).inspect());
  check("read.tar refuses a body-truncated entry", code === "archive-tar/truncated-entry");
}

async function testBadChecksumRefused() {
  var tar = Buffer.concat([_rawHeader({ name: "corrupt.txt", size: 0, typeflag: "0", badChksum: true }), _end()]);
  var code = await _code(b.archive.read.tar(b.archive.adapters.buffer(tar)).inspect());
  check("read.tar refuses a header with a bad checksum", code === "archive-tar/bad-chksum");
}

async function testSingleZeroBlockContinuesThenTerminates() {
  // A lone zero block between entries is skipped (continue); two consecutive
  // zero blocks terminate the walk (break).
  var tar = Buffer.concat([
    _rawHeader({ name: "a.txt", size: 2, typeflag: "0" }), _pad512(Buffer.from("aa")),
    Buffer.alloc(BLOCK, 0),                                                   // single zero block
    _rawHeader({ name: "b.txt", size: 2, typeflag: "0" }), _pad512(Buffer.from("bb")),
    _end(),
  ]);
  var entries = await b.archive.read.tar(b.archive.adapters.buffer(tar)).inspect();
  check("read.tar skips a lone zero block and reads both entries", entries.length === 2);
}

async function testExtractEntriesYieldsFileBytes() {
  var t = b.archive.tar();
  t.addDirectory("sub");
  t.addFile("hello.txt", "hello");
  var sink = _auditSink();
  var reader = b.archive.read.tar(b.archive.adapters.buffer(t.toBuffer()), { audit: sink });
  var out = await _collectEntries(reader.extractEntries());
  check("extractEntries yields only content entries", out.length === 1);
  check("extractEntries yields the file bytes", out[0].bytes.toString("utf8") === "hello");
  check("extractEntries reports size", out[0].size === 5);
  var completed = sink.events.filter(function (e) {
    return e.action === "archive.read.tar.extractEntries.completed";
  });
  check("extractEntries emits a completion audit event", completed.length === 1);
}

async function testExtractEntriesRefusesDevice() {
  // Device entries carry no isSymlink/isHardlink flag, so the guard cascade
  // passes them and the per-entry policy refuses them unconditionally.
  var tar = Buffer.concat([
    _rawHeader({ name: "dev0", size: 0, typeflag: "3" }),
    _end(),
  ]);
  var reader = b.archive.read.tar(b.archive.adapters.buffer(tar));
  var code = await _iterCode(reader.extractEntries());
  check("extractEntries refuses a device entry unconditionally",
    code === "archive-tar/entry-type-refused");
}

async function testExtractEntriesRefusesLinksByPolicy() {
  // guardProfile:false skips the guard cascade so the per-entry entryTypePolicy
  // refusal (not the guard) is what fires for symlink / hardlink.
  var symTar = Buffer.concat([
    _rawHeader({ name: "s", size: 0, typeflag: "2", linkname: "t" }), _end(),
  ]);
  var symCode = await _iterCode(
    b.archive.read.tar(b.archive.adapters.buffer(symTar), { guardProfile: false }).extractEntries());
  check("extractEntries refuses a symlink by entryTypePolicy",
    symCode === "archive-tar/entry-type-refused");

  var hardTar = Buffer.concat([
    _rawHeader({ name: "h", size: 0, typeflag: "1", linkname: "t" }), _end(),
  ]);
  var hardCode = await _iterCode(
    b.archive.read.tar(b.archive.adapters.buffer(hardTar), { guardProfile: false }).extractEntries());
  check("extractEntries refuses a hardlink by entryTypePolicy",
    hardCode === "archive-tar/entry-type-refused");
}

async function testExtractEntriesAllowsDangerousLinksButYieldsNoBytes() {
  // With the type permitted, link entries carry no content and are skipped.
  var tar = Buffer.concat([
    _rawHeader({ name: "s", size: 0, typeflag: "2", linkname: "t" }),
    _rawHeader({ name: "h", size: 0, typeflag: "1", linkname: "t" }),
    _rawHeader({ name: "real.txt", size: 3, typeflag: "0" }), _pad512(Buffer.from("abc")),
    _end(),
  ]);
  var reader = b.archive.read.tar(b.archive.adapters.buffer(tar), {
    guardProfile: false,
  });
  var out = await _collectEntries(reader.extractEntries({
    allowDangerous: { symlinks: true, hardlinks: true },
  }));
  check("extractEntries skips permitted link entries, yields only the file",
    out.length === 1 && out[0].name === "real.txt");
}

async function testExtractEntriesTotalCapRefused() {
  // Two 5-byte files under an 8-byte total cap. A trusted-sequential adapter's
  // collector cap is a fixed 1 GiB (not maxTotalDecompressedBytes), so the walk
  // proceeds and the cumulative-decompressed cap fires on the second yield.
  var t = b.archive.tar();
  t.addFile("f1.txt", "aaaaa");
  t.addFile("f2.txt", "bbbbb");
  var readable = nodeStream.Readable.from([t.toBuffer()]);
  var reader = b.archive.read.tar(b.archive.adapters.trustedStream(readable), {
    bombPolicy: { maxTotalDecompressedBytes: 8 },
  });
  var code = await _iterCode(reader.extractEntries());
  check("extractEntries refuses once cumulative decompressed exceeds the total cap",
    code === "archive-tar/total-too-large");
}

async function testGuardRefusesTraversalEntry() {
  // A traversal name reaches the guardArchive cascade (zip-slip / critical),
  // which refuses the whole archive and emits a refused audit event.
  var tar = Buffer.concat([
    _rawHeader({ name: "../escape.txt", size: 3, typeflag: "0" }), _pad512(Buffer.from("abc")),
    _end(),
  ]);
  var sink = _auditSink();
  var reader = b.archive.read.tar(b.archive.adapters.buffer(tar), { audit: sink });
  var code = await _iterCode(reader.extractEntries());
  check("read.tar refuses a traversal entry via the guard cascade",
    code === "archive-tar/guard-refused");
  var refused = sink.events.filter(function (e) {
    return e.action === "archive.read.tar.extractEntries.refused" && e.outcome === "refused";
  });
  check("guard refusal emits a refused audit event", refused.length === 1);
}

async function testExtractRequiresDestination() {
  var t = b.archive.tar();
  t.addFile("x.txt", "x");
  var reader = b.archive.read.tar(b.archive.adapters.buffer(t.toBuffer()));
  var code = await _code(reader.extract({}));
  check("extract refuses without a destination", code === "archive-tar/no-destination");
  // Called with no opts at all → the extractOpts default still refuses.
  var noArgCode = await _code(reader.extract());
  check("extract with no options refuses (destination default)",
    noArgCode === "archive-tar/no-destination");
}

async function testExtractHappyToDisk() {
  var dir = _tmpDir();
  try {
    var t = b.archive.tar();
    t.addDirectory("nested");
    t.addFile("nested/file.txt", "on disk");
    var sink = _auditSink();
    // A destination that does not yet exist → extract creates it (recursive).
    var destination = path.join(dir, "out", "here");
    var reader = b.archive.read.tar(b.archive.adapters.buffer(t.toBuffer()), { audit: sink });
    var res = await reader.extract({ destination: destination });
    check("extract reports bytes written", res.bytesExtracted === Buffer.byteLength("on disk"));
    check("extract created the missing destination + the directory entry",
      fs.existsSync(path.join(destination, "nested")));
    check("extract wrote the file to disk",
      fs.readFileSync(path.join(destination, "nested", "file.txt"), "utf8") === "on disk");
    var completed = sink.events.filter(function (e) {
      return e.action === "archive.read.tar.extract.completed";
    });
    check("extract emits a completion audit event", completed.length === 1);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

async function testExtractCreatesMissingParentDir() {
  var dir = _tmpDir();
  try {
    // A deeply-nested file with no preceding directory entry: extract must
    // create the missing parent chain before writing the body.
    var tar = Buffer.concat([
      _rawHeader({ name: "a/b/c.txt", size: 4, typeflag: "0" }), _pad512(Buffer.from("deep")),
      _end(),
    ]);
    var reader = b.archive.read.tar(b.archive.adapters.buffer(tar), { guardProfile: false });
    await reader.extract({ destination: dir });
    check("extract creates a missing parent directory chain",
      fs.readFileSync(path.join(dir, "a", "b", "c.txt"), "utf8") === "deep");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

async function testExtractRefusesEntryTypesOnDisk() {
  var dir = _tmpDir();
  try {
    // Device: passes the guard cascade (no link flag) → refused in the loop.
    var devTar = Buffer.concat([_rawHeader({ name: "dev0", size: 0, typeflag: "3" }), _end()]);
    var devCode = await _code(
      b.archive.read.tar(b.archive.adapters.buffer(devTar)).extract({ destination: dir }));
    check("extract refuses a device entry unconditionally",
      devCode === "archive-tar/entry-type-refused");

    // Symlink / hardlink: guardProfile:false isolates the per-entry policy
    // refusal (the guard would otherwise reject them first).
    var symTar = Buffer.concat([_rawHeader({ name: "s", size: 0, typeflag: "2", linkname: "t" }), _end()]);
    var symCode = await _code(
      b.archive.read.tar(b.archive.adapters.buffer(symTar), { guardProfile: false })
        .extract({ destination: dir }));
    check("extract refuses a symlink by entryTypePolicy",
      symCode === "archive-tar/entry-type-refused");

    var hardTar = Buffer.concat([_rawHeader({ name: "h", size: 0, typeflag: "1", linkname: "t" }), _end()]);
    var hardCode = await _code(
      b.archive.read.tar(b.archive.adapters.buffer(hardTar), { guardProfile: false })
        .extract({ destination: dir }));
    check("extract refuses a hardlink by entryTypePolicy",
      hardCode === "archive-tar/entry-type-refused");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

async function testExtractSymlinkCreation() {
  var dir = _tmpDir();
  try {
    // Drives the symlink-creation branch. Symlink creation needs elevated
    // privilege on some hosts (Windows without developer mode), so this
    // asserts the branch either creates the link or fails with a privilege
    // error — documenting the platform-dependent outcome without a bypass.
    var tar = Buffer.concat([
      _rawHeader({ name: "link.txt", size: 0, typeflag: "2", linkname: "target.txt" }),
      _end(),
    ]);
    var reader = b.archive.read.tar(b.archive.adapters.buffer(tar), { guardProfile: false });
    var code = await reader.extract({ destination: dir, allowDangerous: { symlinks: true } })
      .then(function () { return "created"; },
            function (e) { return (e && e.code) || "threw"; });
    var privRefused = code === "EPERM" || code === "EACCES" ||
                      code === "ENOSYS" || code === "UNKNOWN";
    check("extract either creates the symlink or is refused by OS privilege",
      code === "created" || privRefused);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

async function testExtractDestinationExistsAborts() {
  var dir = _tmpDir();
  try {
    // Two entries with the same name: the second collides with the first's
    // on-disk file, tripping the destination-exists refusal + rollback. The
    // balanced guard already rejects duplicate names as critical, so
    // guardProfile:false is used to isolate the disk-level collision branch.
    var tar = Buffer.concat([
      _rawHeader({ name: "dup.txt", size: 3, typeflag: "0" }), _pad512(Buffer.from("one")),
      _rawHeader({ name: "dup.txt", size: 3, typeflag: "0" }), _pad512(Buffer.from("two")),
      _end(),
    ]);
    var sink = _auditSink();
    var reader = b.archive.read.tar(b.archive.adapters.buffer(tar), { audit: sink, guardProfile: false });
    var code = await _code(reader.extract({ destination: dir }));
    check("extract refuses to overwrite an existing destination file",
      code === "archive-tar/destination-exists");
    check("extract rolls back the first write on abort",
      !fs.existsSync(path.join(dir, "dup.txt")));
    var aborted = sink.events.filter(function (e) {
      return e.action === "archive.read.tar.extract.aborted" && e.outcome === "failure";
    });
    check("extract emits an aborted audit event", aborted.length === 1);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

async function testExtractCreatesHardlink() {
  var dir = _tmpDir();
  try {
    // A regular file followed by a hardlink pointing at it. Hardlink creation
    // needs no elevated privilege on the host filesystem, so this drives the
    // link-creation branch portably.
    var tar = Buffer.concat([
      _rawHeader({ name: "target.txt", size: 6, typeflag: "0" }), _pad512(Buffer.from("linked")),
      _rawHeader({ name: "alias.txt", size: 0, typeflag: "1", linkname: "target.txt" }),
      _end(),
    ]);
    var reader = b.archive.read.tar(b.archive.adapters.buffer(tar), { guardProfile: false });
    var res = await reader.extract({ destination: dir, allowDangerous: { hardlinks: true } });
    check("extract creates the hardlink entry", res.entries.length === 2);
    check("extract hardlink resolves to the target's content",
      fs.readFileSync(path.join(dir, "alias.txt"), "utf8") === "linked");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

async function testExtractTotalCapAborts() {
  var dir = _tmpDir();
  try {
    // Two 5-byte files under an 8-byte total cap via a trusted stream (whose
    // collector cap is fixed, so the walk isn't blocked by the read cap). The
    // first file is written, the second trips the cap, and the rollback removes
    // the first.
    var t = b.archive.tar();
    t.addFile("a.txt", "aaaaa");
    t.addFile("b.txt", "bbbbb");
    var readable = nodeStream.Readable.from([t.toBuffer()]);
    var reader = b.archive.read.tar(b.archive.adapters.trustedStream(readable), {
      bombPolicy: { maxTotalDecompressedBytes: 8 },
    });
    var code = await _code(reader.extract({ destination: dir }));
    check("extract aborts once cumulative decompressed exceeds the total cap",
      code === "archive-tar/total-too-large");
    check("extract rolls back the first file on total-cap abort",
      !fs.existsSync(path.join(dir, "a.txt")));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

async function run() {
  testBadAdapterRejected();
  await testEmptyArchiveInspect();
  await testInspectClassifiesEveryTypeflag();
  await testInspectRealBuilderRoundTrip();
  await testTrustedStreamAdapter();
  await testNullSizeRandomAccessResolvesSize();
  await testRandomAccessSourceTooLarge();
  await testPaxExtendedOverrides();
  await testPaxGlobalOverrides();
  await testPaxMalformedRecordsRefused();
  await testPaxMalformedSizeRefused();
  await testPaxBodyRespectsPerEntryCap();
  await testPaxBodyTruncatedRefused();
  await testTooManyEntriesRefused();
  await testEntryTooLargeRefused();
  await testTruncatedEntryRefused();
  await testBadChecksumRefused();
  await testSingleZeroBlockContinuesThenTerminates();
  await testExtractEntriesYieldsFileBytes();
  await testExtractEntriesRefusesDevice();
  await testExtractEntriesRefusesLinksByPolicy();
  await testExtractEntriesAllowsDangerousLinksButYieldsNoBytes();
  await testExtractEntriesTotalCapRefused();
  await testGuardRefusesTraversalEntry();
  await testExtractRequiresDestination();
  await testExtractHappyToDisk();
  await testExtractCreatesMissingParentDir();
  await testExtractRefusesEntryTypesOnDisk();
  await testExtractSymlinkCreation();
  await testExtractDestinationExistsAborts();
  await testExtractCreatesHardlink();
  await testExtractTotalCapAborts();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
