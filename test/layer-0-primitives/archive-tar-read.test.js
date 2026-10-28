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
 *     refusals and the first-zero-block terminator,
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
  if (o.gnu) {
    // GNU / old-GNU magic: "ustar  \0" across magic + version.
    buf.write("ustar  \0", 257, 8, "ascii");
    if (o.prefix) buf.write(o.prefix, 345, Math.min(o.prefix.length, 155), "ascii");
  } else if (!o.badMagic) {
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
// <len> is the UTF-8 byte length of the whole record, its own digits
// included (mirrors lib/archive-tar.js _buildPaxRecord).
function _paxRecord(key, value) {
  var kv = key + "=" + value + "\n";
  var len = Buffer.byteLength(kv, "utf8") + 1;
  while (true) {
    var s = String(len) + " " + kv;
    var sLen = Buffer.byteLength(s, "utf8");
    if (sLen === len) return s;
    len = sLen;
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

// A GNU long-name ('L') or long-link ('K') record: a "././@LongLink" header
// whose body is the name / link target. `body` is written verbatim (latin1),
// so a caller includes or omits the NUL terminator explicitly.
function _gnuLongRecord(typeflag, body, declaredSize) {
  var bodyBuf = Buffer.from(body, "latin1");
  var size = declaredSize == null ? bodyBuf.length : declaredSize;
  var hdr = _rawHeader({ name: "././@LongLink", size: size, typeflag: typeflag, gnu: true });
  return Buffer.concat([hdr, _pad512(bodyBuf)]);
}

var GNU_FIXTURE_DIR = path.join(__dirname, "..", "fixtures", "archive-tar-gnu");

// Like _rawHeader, but overwrites chosen numeric fields with RAW bytes the
// zero-padding _oct helper can't express — e.g. POSIX-legal leading-space
// padding (star / BSD / some Java tar libraries left-pad numeric fields with
// spaces). Recomputes a valid checksum over the ACTUAL bytes so _parseHeader
// reaches the numeric-field parse. Each rawFields entry is
// { offset, width, text } and text is written verbatim (latin1) into the
// cleared field. offsets: mode 100/8, size 124/12, mtime 136/12.
function _headerRawField(o) {
  var buf = Buffer.alloc(BLOCK, 0);
  var name = o.name || "";
  buf.write(name, 0, Math.min(Buffer.byteLength(name), 100), "ascii");
  buf.write(_oct(o.mode == null ? 0o644 : o.mode, 7) + "\x00", 100, 8, "ascii");
  buf.write(_oct(o.uid || 0, 7) + "\x00", 108, 8, "ascii");
  buf.write(_oct(o.gid || 0, 7) + "\x00", 116, 8, "ascii");
  buf.write(_oct(o.size || 0, 11) + "\x00", 124, 12, "ascii");
  buf.write(_oct(o.mtime || 0, 11) + "\x00", 136, 12, "ascii");
  if (o.typeflag != null) buf.write(o.typeflag, 156, 1, "ascii");
  buf.write("ustar\x00", 257, 6, "ascii");
  buf.write("00", 263, 2, "ascii");
  var raw = o.rawFields || [];
  for (var r = 0; r < raw.length; r += 1) {
    buf.fill(0, raw[r].offset, raw[r].offset + raw[r].width);
    buf.write(raw[r].text, raw[r].offset, raw[r].width, "latin1");
  }
  for (var i = 148; i < 156; i += 1) buf[i] = 0x20;
  var sum = 0;
  for (var j = 0; j < BLOCK; j += 1) sum += buf[j];
  var oct = sum.toString(8);
  while (oct.length < 6) oct = "0" + oct;
  buf.write(oct + "\x00 ", 148, 8, "ascii");
  return buf;
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
  // A pax linkpath applies to a link entry; on a regular file it is refused
  // (testGnuLongRecordMalformedRefused), so the linkpath rides a symlink here.
  var body = _paxBody([["path", "renamed/from-pax.txt"], ["size", "5"]]);
  var linkBody = _paxBody([["linkpath", "target/x"]]);
  var tar = Buffer.concat([
    _paxHeaderBlock("x", body),
    _rawHeader({ name: "orig.txt", size: 5, typeflag: "0" }),
    _pad512(Buffer.from("hello")),
    _paxHeaderBlock("x", linkBody),
    _rawHeader({ name: "link", size: 0, typeflag: "2", linkname: "short" }),
    _end(),
  ]);
  var entries = await b.archive.read.tar(b.archive.adapters.buffer(tar)).inspect();
  check("pax extended path override applied", entries[0].name === "renamed/from-pax.txt");
  check("pax extended size override applied", entries[0].size === 5);
  check("pax extended linkpath override applied", entries[1].linkname === "target/x");
}

async function testPaxGlobalHeaderAttributes() {
  // GNU tar applies a global path, linkpath or size to every following
  // entry; bsdtar 3.8.10 refuses each one ("Unsupported pax global extended
  // header attribute"). The reader refuses them.
  var cases = [
    { label: "path", records: [["path", "global/name.txt"]],
      parts: [_ustarFile("ignored.txt", "world")] },
    { label: "linkpath", records: [["linkpath", "global/link"]],
      parts: [_rawHeader({ name: "s", size: 0, typeflag: "2", linkname: "t" })] },
    { label: "size", records: [["size", "2"]], parts: [_ustarFile("f", "abc")] },
    { label: "GNU.sparse.name", records: [["GNU.sparse.name", "A"]], parts: [_ustarFile("hdr", "x")] },
    { label: "GNU.sparse.major", records: [["GNU.sparse.major", "1"]], parts: [_ustarFile("hdr", "x")] },
    { label: "path after a comment", records: [["comment", "c"], ["path", "p"]],
      parts: [_ustarFile("hdr", "x")] },
  ];
  for (var i = 0; i < cases.length; i += 1) {
    var tar = Buffer.concat([_paxHeaderBlock("g", _paxBody(cases[i].records))]
      .concat(cases[i].parts).concat([_end()]));
    var code = await _code(b.archive.read.tar(b.archive.adapters.buffer(tar)).inspect());
    check("read.tar refuses a pax global " + cases[i].label + " (got " + code + ")",
      code === "archive-tar/global-entry-attribute");
    var iterCode = await _iterCode(b.archive.read.tar(b.archive.adapters.buffer(tar)).extractEntries());
    check("extractEntries refuses a pax global " + cases[i].label + " (got " + iterCode + ")",
      iterCode === "archive-tar/global-entry-attribute");
  }
  var commentTar = Buffer.concat([
    _paxHeaderBlock("g", _paxBody([["comment", "c"], ["mtime", "1"], ["GNU.volume.label", "VOL1"]])),
    _ustarFile("kept.txt", "world"), _end(),
  ]);
  var entries = await b.archive.read.tar(b.archive.adapters.buffer(commentTar)).inspect();
  check("a pax global header without entry attributes leaves the entry unchanged",
    entries.length === 1 && entries[0].name === "kept.txt" && entries[0].size === 5);
}

async function testPaxMalformedRecordsRefused() {
  var cases = [
    { label: "no length-space delimiter", body: Buffer.from("noodle") },
    { label: "non-positive record length", body: Buffer.from("0 x=y\n") },
    { label: "record not newline-terminated", body: Buffer.from("6 x=yz") },
    { label: "record missing key=value", body: Buffer.from("5 ab\n") },
    { label: "length with a leading plus sign", body: Buffer.from("+14 path=abcd\n") },
    { label: "length followed by a letter", body: Buffer.from("12e path=ab\n") },
    { label: "length running past the end of the body", body: Buffer.from("99 path=abcde\n") },
    { label: "length shorter than the record", body: Buffer.from("10 path=abcde\n") },
    { label: "empty key", body: Buffer.from("10 =abcde\n") },
    { label: "NUL padding after the last record", body: Buffer.from("14 path=abcde\n\0\0\0") },
    { label: "key=value delimiter only after the newline",
      body: Buffer.from("8 abcde\n5 =\nx") },
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
  var err = await b.archive.read.tar(b.archive.adapters.buffer(tar)).inspect().then(
    function () { return null; }, function (e) { return e; });
  check("read.tar refuses a body-truncated entry", err !== null && err.code === "archive-tar/truncated-entry");
  check("the truncated-entry message names the declared size and the remaining bytes",
    err !== null && /size=100 \(padded=512\) but only 0 bytes remain after header; archive truncated mid-stream$/
      .test(err.message));
}

async function testBadChecksumRefused() {
  var tar = Buffer.concat([_rawHeader({ name: "corrupt.txt", size: 0, typeflag: "0", badChksum: true }), _end()]);
  var code = await _code(b.archive.read.tar(b.archive.adapters.buffer(tar)).inspect());
  check("read.tar refuses a header with a bad checksum", code === "archive-tar/bad-chksum");
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
    return e.action === "archive.read.tar.extract_entries.completed";
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
  var guardErr = null;
  try {
    for await (var _g of reader.extractEntries()) { void _g; }
  } catch (e) { guardErr = e; }
  check("read.tar refuses a traversal entry via the guard cascade",
    guardErr !== null && guardErr.code === "archive-tar/guard-refused");
  check("the guard-refused message counts the critical issues",
    guardErr !== null && /^extract refused: \d+ critical guard issue\(s\)$/.test(guardErr.message));
  var refused = sink.events.filter(function (e) {
    return e.action === "archive.read.tar.extract_entries.refused" && e.outcome === "refused";
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
    var existsErr = await reader.extract({ destination: dir }).then(
      function () { return null; }, function (e) { return e; });
    check("extract refuses to overwrite an existing destination file",
      existsErr !== null && existsErr.code === "archive-tar/destination-exists");
    check("the destination-exists message names the path",
      existsErr !== null && /^extract: destination file already exists at ".*dup\.txt"; refusing to overwrite$/
        .test(existsErr.message));
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

// ---- leading-space octal fields (parser-differential regression) --------

async function testLeadingSpaceMetadataFieldsParsed() {
  // POSIX permits numeric header fields to be left-padded with SPACES, not
  // just zeros (star / BSD tar / several Java + Perl tar libraries emit them).
  // _readOctal treated a leading space as a field terminator, so such a field
  // silently misparsed to 0 — the reader disagreed with GNU tar / libarchive
  // on the same bytes (safe-toml / safe-ini parser-differential class). mode
  // and mtime do not steer the walker, so the misparse surfaces as a silent
  // wrong value with no throw.
  var tar = Buffer.concat([
    _headerRawField({
      name:     "meta.txt",
      typeflag: "0",
      rawFields: [
        { offset: 100, width: 8,  text: "  00755\x00" },       // mode 0o755 = 493, 2 leading spaces
        { offset: 136, width: 12, text: "  0000000144" },        // mtime octal 144 = 100s, 2 leading spaces
      ],
    }),
    _end(),
  ]);
  var entries = await b.archive.read.tar(b.archive.adapters.buffer(tar)).inspect();
  check("leading-space-padded mode field parses to its real value (not 0)",
    entries.length === 1 && entries[0].mode === 0o755);
  check("leading-space-padded mtime field parses to its real value (not epoch 0)",
    entries.length === 1 && entries[0].mtime.getTime() === 100 * 1000);
}

async function testLeadingSpaceSizeFieldNoWalkerDesync() {
  // The security-relevant consequence: a leading-space SIZE field misparsed to
  // 0 desyncs the block walker (it reads the file body as the next header),
  // which here fails the magic check and rejects the whole archive — a reader
  // that a downstream GNU-tar consumer disagrees with. Correct parse walks the
  // archive and locates the body precisely.
  var tar = Buffer.concat([
    _headerRawField({
      name:     "spaced.txt",
      typeflag: "0",
      rawFields: [{ offset: 124, width: 12, text: "   00000005\x00" }],   // size 5, 3 leading spaces
    }),
    _pad512(Buffer.from("hello")),
    _end(),
  ]);
  var reader = b.archive.read.tar(b.archive.adapters.buffer(tar), { guardProfile: false });
  var result = await _collectEntries(reader.extractEntries()).then(
    function (out) { return out; },
    function (e) { return { error: (e && e.code) || "threw" }; });
  check("leading-space size field: archive walks without desync",
    Array.isArray(result) && result.length === 1);
  check("leading-space size field: entry body located + extracted correctly",
    Array.isArray(result) && result[0] && result[0].bytes.toString("utf8") === "hello");
}

async function testReaderRefusesNonOctalNumericField() {
  // A numeric field carrying a non-octal digit (0x39 '9') is rejected — the
  // _readOctal throw branch on the read consumer path.
  var tar = Buffer.concat([
    _headerRawField({
      name:     "bad.txt",
      typeflag: "0",
      rawFields: [{ offset: 100, width: 8, text: "00099\x00\x00\x00" }],   // mode digits contain '9'
    }),
    _end(),
  ]);
  var code = await _code(b.archive.read.tar(b.archive.adapters.buffer(tar)).inspect());
  check("read.tar refuses a numeric field with a non-octal digit", code === "archive-tar/bad-octal");
}

// ---- write-side (b.archive.tar) uncovered branches ----------------------

function _threwCode(fn) { try { fn(); return null; } catch (e) { return e && e.code; } }

function testWriteSideFieldOverflows() {
  // uname wider than the 32-byte ustar field → field-overflow (write-side
  // _writeString throw). Surfaces at toBuffer(), when the header is built.
  var t = b.archive.tar();
  t.addFile("f.txt", "x", { uname: "u".repeat(40) });
  check("b.archive.tar refuses an over-wide uname field",
    _threwCode(function () { t.toBuffer(); }) === "archive-tar/field-overflow");

  // uid larger than the 7-octal-digit ustar field → octal-overflow
  // (write-side _writeOctal throw).
  var t2 = b.archive.tar();
  t2.addFile("g.txt", "x", { uid: 0o7777777 + 1 });
  check("b.archive.tar refuses a uid past the ustar octal field width",
    _threwCode(function () { t2.toBuffer(); }) === "archive-tar/octal-overflow");
}

function testAddFileNameValidation() {
  check("addFile refuses an empty name",
    _threwCode(function () { b.archive.tar().addFile("", "x"); }) === "archive-tar/bad-name");
  check("addFile refuses a name with a null byte",
    _threwCode(function () { b.archive.tar().addFile("a\x00b", "x"); }) === "archive-tar/bad-name");
  check("addFile refuses a name with CR/LF (pax path-record forgery vector)",
    _threwCode(function () { b.archive.tar().addFile("a\r\nb", "x"); }) === "archive-tar/bad-name");
  check("addFile refuses a name with a '..' segment",
    _threwCode(function () { b.archive.tar().addFile("../x", "x"); }) === "archive-tar/bad-name");
  check("addFile refuses non-Buffer/non-string content",
    _threwCode(function () { b.archive.tar().addFile("f", 123); }) === "archive-tar/bad-content");
}

async function testAddFileNameNormalization() {
  // Leading slashes stripped + backslashes normalized to forward slashes,
  // then round-tripped through the reader.
  var t = b.archive.tar();
  t.addFile("/abs/x.txt", "a");
  t.addFile("a\\b\\c.txt", "b");
  var entries = await b.archive.read.tar(b.archive.adapters.buffer(t.toBuffer())).inspect();
  var names = entries.map(function (e) { return e.name; });
  check("addFile strips a leading slash", names.indexOf("abs/x.txt") !== -1);
  check("addFile normalizes backslashes to forward slashes", names.indexOf("a/b/c.txt") !== -1);
}

async function testLongNameUstarPrefixSplitRoundTrip() {
  // A 111-char name with a '/' at offset <= 100 fits ustar via the name/prefix
  // split (no pax header). Exercises _buildUstarHeader's prefix-split branch on
  // write and _parseHeader's prefix-reassembly branch on read.
  var longName = "a".repeat(90) + "/" + "b".repeat(20);
  var t = b.archive.tar();
  t.addFile(longName, "z");
  var entries = await b.archive.read.tar(b.archive.adapters.buffer(t.toBuffer())).inspect();
  check("ustar name/prefix split round-trips a 111-char name",
    entries.length === 1 && entries[0].name === longName);
}

async function testLongNamePaxPathRoundTrip() {
  // A single >100-char path segment can't ustar-split, so the builder emits a
  // pax extended header carrying the real path + a "PaxHeader/data" sentinel
  // ustar name. Exercises _entryBytes' pax branch, _buildPaxExtendedHeader,
  // _buildPaxRecord, and _buildUstarHeader's sentinel path.
  var paxName = "c".repeat(150) + ".txt";
  var t = b.archive.tar();
  t.addFile(paxName, "w");
  var entries = await b.archive.read.tar(b.archive.adapters.buffer(t.toBuffer())).inspect();
  check("pax extended header round-trips a >100-char single-segment name",
    entries.length === 1 && entries[0].name === paxName);
}

async function testToAdapterContractAndRoundTrip() {
  check("toAdapter refuses a null adapter",
    await _code(b.archive.tar().toAdapter(null)) === "archive-tar/bad-adapter");
  check("toAdapter refuses an adapter with no write() method",
    await _code(b.archive.tar().toAdapter({})) === "archive-tar/bad-adapter");

  var chunks = [];
  var ended = false;
  var adapter = {
    write: function (buf) { chunks.push(buf); return Promise.resolve(); },
    end:   function () { ended = true; return Promise.resolve(); },
  };
  var t = b.archive.tar();
  t.addFile("aa.txt", "hi");
  await t.toAdapter(adapter);
  check("toAdapter calls end() after the trailing zero blocks", ended === true);
  var entries = await b.archive.read.tar(b.archive.adapters.buffer(Buffer.concat(chunks))).inspect();
  check("toAdapter output round-trips through the reader",
    entries.length === 1 && entries[0].name === "aa.txt");
}

async function testToStreamRoundTrip() {
  var pt = new nodeStream.PassThrough();
  var collected = [];
  pt.on("data", function (c) { collected.push(c); });
  var t = b.archive.tar();
  t.addFile("bb.txt", "yo");
  await t.toStream(pt);
  var entries = await b.archive.read.tar(b.archive.adapters.buffer(Buffer.concat(collected))).inspect();
  check("toStream output round-trips through the reader",
    entries.length === 1 && entries[0].name === "bb.txt");
}

async function testToGzipEmitsGzip() {
  var chunks = [];
  var adapter = {
    write: function (buf) { chunks.push(buf); return Promise.resolve(); },
    end:   function () { return Promise.resolve(); },
  };
  var t = b.archive.tar();
  t.addFile("cc.txt", "gz");
  await t.toGzip(adapter);
  var gz = Buffer.concat(chunks);
  check("toGzip emits a gzip stream (magic 0x1f 0x8b)",
    gz.length > 2 && gz[0] === 0x1f && gz[1] === 0x8b);
}

function testDigestIsSha3_512Hex() {
  // The tar digest hashes the whole archive bytes, which include each entry's
  // mtime; per the module contract mtime determinism is opt-in (the default is
  // the current time). So pin mtime to compare digests of "identical content"
  // deterministically — without the pin, two tars built across a one-second
  // boundary carry different mtimes and (correctly) different digests.
  var t = b.archive.tar();
  t.addFile("d.txt", "digest me", { mtime: 0 });
  var hex = t.digest();
  check("digest returns a 128-hex-char sha3-512", /^[0-9a-f]{128}$/.test(hex));
  var t2 = b.archive.tar();
  t2.addFile("d.txt", "digest me", { mtime: 0 });
  check("digest is deterministic for identical content at a pinned mtime", t2.digest() === hex);
}

// ---- GNU long-name / long-link records (typeflag L / K) -----------------

var LONG_DIR = "d".repeat(60) + "/";
var LONG_FILE = LONG_DIR + "n".repeat(70);
var LONG_TARGET = "t".repeat(130);

function _gnuFixture(name) {
  return fs.readFileSync(path.join(GNU_FIXTURE_DIR, name));
}

function _gnuFile(name, body) {
  var bodyBuf = Buffer.from(body);
  return Buffer.concat([
    _rawHeader({ name: name, size: bodyBuf.length, typeflag: "0", gnu: true }),
    _pad512(bodyBuf),
  ]);
}

function _gnuSymlink(name, linkname) {
  return _rawHeader({ name: name, size: 0, typeflag: "2", linkname: linkname, gnu: true });
}

async function testGnuLongNameAndLinkFromRealTools() {
  // Archives written by GNU tar 1.35 (--format=gnu) and bsdtar 3.8.10
  // (--format=gnutar): a 131-byte file name carried in an L record and a
  // 130-byte symlink target carried in a K record.
  var fixtures = [
    "gnu-tar-1.35-long-name-and-link.tar",
    "bsdtar-3.8.10-gnutar-long-name-and-link.tar",
  ];
  for (var i = 0; i < fixtures.length; i += 1) {
    var label = fixtures[i];
    var bytes = _gnuFixture(label);
    var entries = await b.archive.read.tar(b.archive.adapters.buffer(bytes)).inspect();
    check(label + ": inspect returns no L / K record as an entry",
      entries.length === 3 && entries.every(function (e) { return e.entryType !== "unknown"; }));
    var file = entries.filter(function (e) { return e.entryType === "file"; })[0];
    check(label + ": the file entry carries the name from the L body",
      !!file && file.name === LONG_FILE);
    var link = entries.filter(function (e) { return e.entryType === "symlink"; })[0];
    check(label + ": the symlink entry carries the target from the K body",
      !!link && link.name === "lnk" && link.linkname === LONG_TARGET);
    var out = await _collectEntries(b.archive.read.tar(b.archive.adapters.buffer(bytes))
      .extractEntries({ allowDangerous: { symlinks: true } }));
    check(label + ": extractEntries yields the file under its long name",
      out.length === 1 && out[0].name === LONG_FILE && out[0].bytes.toString("utf8") === "hi\n");
  }
}

async function testGnuLongNameTraversalReachesGuard() {
  // An L body naming a path outside the destination applies to the next
  // header, so inspect() reports the name GNU tar extracts to and the guard
  // metadata pass refuses it before extract writes anything.
  var tar = Buffer.concat([
    _gnuLongRecord("L", "../../../etc/cron.d/x\0"),
    _gnuFile("innocent", "x"),
    _end(),
  ]);
  var entries = await b.archive.read.tar(b.archive.adapters.buffer(tar)).inspect();
  check("inspect applies the L body to the next entry and drops the L record",
    entries.length === 1 && entries[0].name === "../../../etc/cron.d/x" &&
    entries[0].entryType === "file");
  var verdict = b.guardArchive.validateEntries(entries.map(function (e) {
    return { name: e.name, size: e.size, compressedSize: e.size };
  }), { profile: "balanced" });
  check("validateEntries over inspect() output reports the traversal name",
    verdict.issues.some(function (iss) { return iss.severity === "critical"; }));
  var iterCode = await _iterCode(b.archive.read.tar(b.archive.adapters.buffer(tar)).extractEntries());
  check("extractEntries refuses the L-carried traversal name via the guard pass",
    iterCode === "archive-tar/guard-refused");
  var dir = _tmpDir();
  try {
    var dest = path.join(dir, "a", "b", "c");
    var code = await _code(b.archive.read.tar(b.archive.adapters.buffer(tar)).extract({ destination: dest }));
    check("extract refuses the L-carried traversal name via the guard pass",
      code === "archive-tar/guard-refused");
    check("extract wrote nothing under the L-carried name",
      !fs.existsSync(path.join(dest, "innocent")) &&
      !fs.existsSync(path.join(dir, "etc", "cron.d", "x")));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

async function testGnuLongLinkEscapeReachesGuard() {
  var tar = Buffer.concat([
    _gnuLongRecord("K", "../../../../etc/passwd\0"),
    _gnuSymlink("s", "safe"),
    _end(),
  ]);
  var entries = await b.archive.read.tar(b.archive.adapters.buffer(tar)).inspect();
  check("inspect applies the K body to the next symlink's linkname",
    entries.length === 1 && entries[0].entryType === "symlink" &&
    entries[0].linkname === "../../../../etc/passwd");
  var code = await _iterCode(b.archive.read.tar(b.archive.adapters.buffer(tar))
    .extractEntries({ allowDangerous: { symlinks: true } }));
  check("extractEntries refuses the K-carried symlink escape via the guard pass",
    code === "archive-tar/guard-refused");
}

async function testGnuLongRecordMalformedRefused() {
  var cases = [
    { label: "stacked L records",
      code: "archive-tar/bad-long-record",
      tar: [_gnuLongRecord("L", "first\0"), _gnuLongRecord("L", "second\0"), _gnuFile("short", "x")] },
    { label: "stacked K records",
      code: "archive-tar/bad-long-record",
      tar: [_gnuLongRecord("K", "t1\0"), _gnuLongRecord("K", "t2\0"), _gnuSymlink("s", "short")] },
    { label: "L, K, L before one header",
      code: "archive-tar/bad-long-record",
      tar: [_gnuLongRecord("L", "n1\0"), _gnuLongRecord("K", "t1\0"), _gnuLongRecord("L", "n2\0"),
        _gnuSymlink("s", "short")] },
    { label: "empty L body",
      code: "archive-tar/bad-long-record",
      tar: [_gnuLongRecord("L", ""), _gnuFile("short", "x")] },
    { label: "L body that is only a NUL",
      code: "archive-tar/bad-long-record",
      tar: [_gnuLongRecord("L", "\0"), _gnuFile("short", "x")] },
    { label: "empty K body",
      code: "archive-tar/bad-long-record",
      tar: [_gnuLongRecord("K", ""), _gnuSymlink("s", "short")] },
    { label: "K record before a regular file",
      code: "archive-tar/link-target-on-non-link",
      tar: [_gnuLongRecord("K", "tgt\0"), _gnuFile("reg", "x")] },
    { label: "K record before a directory",
      code: "archive-tar/link-target-on-non-link",
      tar: [_gnuLongRecord("K", "tgt\0"),
        _rawHeader({ name: "d/", size: 0, typeflag: "5", mode: 0o755, gnu: true })] },
    { label: "pax linkpath before a regular file",
      code: "archive-tar/link-target-on-non-link",
      tar: [_paxHeaderBlock("x", _paxBody([["linkpath", "tgt"]])), _gnuFile("reg", "x")] },
    { label: "L record at the end of the archive",
      code: "archive-tar/dangling-extended-header",
      tar: [_gnuFile("a", "A"), _gnuLongRecord("L", "dangling\0")] },
    { label: "K record at the end of the archive",
      code: "archive-tar/dangling-extended-header",
      tar: [_gnuFile("a", "A"), _gnuLongRecord("K", "dangling\0")] },
    { label: "pax extended header at the end of the archive",
      code: "archive-tar/dangling-extended-header",
      tar: [_gnuFile("a", "A"), _paxHeaderBlock("x", _paxBody([["path", "dangling"]]))] },
    { label: "L record before a volume label (V) header",
      code: "archive-tar/dangling-extended-header",
      tar: [_gnuLongRecord("L", "fromL\0"), _rawHeader({ name: "vol", size: 0, typeflag: "V", gnu: true }),
        _gnuFile("short", "x")] },
    { label: "K record before a volume label (V) header",
      code: "archive-tar/dangling-extended-header",
      tar: [_gnuLongRecord("K", "fromK\0"), _rawHeader({ name: "vol", size: 0, typeflag: "V", gnu: true }),
        _gnuSymlink("s", "short")] },
    { label: "pax extended header before a volume label (V) header",
      code: "archive-tar/dangling-extended-header",
      tar: [_paxHeaderBlock("x", _paxBody([["path", "fromPax"]])),
        _rawHeader({ name: "vol", size: 0, typeflag: "V", gnu: true }), _gnuFile("short", "x")] },
    { label: "L before a pax path naming a different file",
      code: "archive-tar/long-name-pax-conflict",
      tar: [_gnuLongRecord("L", "fromL\0"), _paxHeaderBlock("x", _paxBody([["path", "fromPax"]])),
        _gnuFile("short", "x")] },
    { label: "pax path before an L naming a different file",
      code: "archive-tar/long-name-pax-conflict",
      tar: [_paxHeaderBlock("x", _paxBody([["path", "fromPax"]])), _gnuLongRecord("L", "fromL\0"),
        _gnuFile("short", "x")] },
    { label: "pax global path and an L naming a different file",
      code: "archive-tar/global-entry-attribute",
      tar: [_paxHeaderBlock("g", _paxBody([["path", "fromG"]])), _gnuLongRecord("L", "fromL\0"),
        _gnuFile("short", "x")] },
    { label: "K before a pax linkpath naming a different target",
      code: "archive-tar/long-name-pax-conflict",
      tar: [_gnuLongRecord("K", "fromK\0"), _paxHeaderBlock("x", _paxBody([["linkpath", "fromPax"]])),
        _gnuSymlink("s", "short")] },
  ];
  for (var i = 0; i < cases.length; i += 1) {
    var tar = Buffer.concat(cases[i].tar.concat([_end()]));
    var code = await _code(b.archive.read.tar(b.archive.adapters.buffer(tar)).inspect());
    check("read.tar refuses " + cases[i].label + " (" + cases[i].code + ", got " + code + ")",
      code === cases[i].code);
    var guardCode = await _iterCode(b.archive.read.tar(b.archive.adapters.buffer(tar)).extractEntries());
    check("extractEntries refuses " + cases[i].label, guardCode === cases[i].code);
  }
}

async function testGnuLongRecordBounds() {
  var overPolicy = Buffer.concat([
    _rawHeader({ name: "././@LongLink", size: 4096, typeflag: "L", gnu: true }),
  ]);
  var policyCode = await _code(b.archive.read.tar(b.archive.adapters.buffer(overPolicy), {
    bombPolicy: { maxEntryDecompressedBytes: 1024 },
  }).inspect());
  check("an L body over maxEntryDecompressedBytes is refused",
    policyCode === "archive-tar/entry-too-large");

  var overCap = Buffer.concat([
    _rawHeader({ name: "././@LongLink", size: 64 * 1024 + 1, typeflag: "K", gnu: true }),
  ]);
  var capCode = await _code(b.archive.read.tar(b.archive.adapters.buffer(overCap)).inspect());
  check("a K body over the 64 KiB long-record cap is refused under the default policy",
    capCode === "archive-tar/entry-too-large");

  var truncated = Buffer.concat([
    _rawHeader({ name: "././@LongLink", size: 600, typeflag: "L", gnu: true }),
    Buffer.alloc(BLOCK, 0x61),
  ]);
  var truncCode = await _code(b.archive.read.tar(b.archive.adapters.buffer(truncated)).inspect());
  check("a truncated L body is refused", truncCode === "archive-tar/truncated-entry");
}

async function testGnuLongRecordAcceptedShapes() {
  async function names(parts) {
    var tar = Buffer.concat(parts.concat([_end()]));
    var entries = await b.archive.read.tar(b.archive.adapters.buffer(tar)).inspect();
    return entries;
  }
  var noNul = await names([_gnuLongRecord("L", "noterm"), _gnuFile("short", "x")]);
  check("an L body without a NUL terminator names the entry with the whole body",
    noNul.length === 1 && noNul[0].name === "noterm");
  var embedded = await names([_gnuLongRecord("L", "abc\0def\0"), _gnuFile("short", "x")]);
  check("an L body is read up to its first NUL",
    embedded.length === 1 && embedded[0].name === "abc");
  var acrossPax = await names([_gnuLongRecord("L", "Lname\0"),
    _paxHeaderBlock("x", _paxBody([["mtime", "1"]])), _gnuFile("short", "x")]);
  check("an L record applies across an intervening pax header",
    acrossPax.length === 1 && acrossPax[0].name === "Lname");
  var agree = await names([_gnuLongRecord("L", "same\0"),
    _paxHeaderBlock("x", _paxBody([["path", "same"]])), _gnuFile("short", "x")]);
  check("an L record and a pax path naming the same file are accepted",
    agree.length === 1 && agree[0].name === "same");
  var hardlink = await names([_gnuFile("tgt", "T"), _gnuLongRecord("K", "tgt\0"),
    _rawHeader({ name: "h", size: 0, typeflag: "1", linkname: "x", gnu: true })]);
  check("a K record applies to a hardlink's linkname",
    hardlink.length === 2 && hardlink[1].entryType === "hardlink" && hardlink[1].linkname === "tgt");
  var leadingVolume = await names([_rawHeader({ name: "vol", size: 0, typeflag: "V", gnu: true }),
    _gnuLongRecord("L", "fromL\0"), _gnuFile("short", "x")]);
  check("an L record after a volume label applies to the entry that follows it",
    leadingVolume.length === 2 && leadingVolume[0].entryType === "unknown" &&
    leadingVolume[1].name === "fromL");
}

async function testUnknownTypeflagsRefusedOnExtract() {
  // GNU sparse (S), multi-volume continuation (M), volume label (V), old GNU
  // long name (N) and an unassigned vendor letter (Z) classify as "unknown".
  // Writing one as a regular file produces bytes no other reader produces.
  var typeflags = ["S", "M", "V", "N", "Z"];
  for (var i = 0; i < typeflags.length; i += 1) {
    var tf = typeflags[i];
    var tar = Buffer.concat([
      _rawHeader({ name: "u-" + tf, size: 1, typeflag: tf, gnu: true }), _pad512(Buffer.from("x")),
      _end(),
    ]);
    var iterCode = await _iterCode(b.archive.read.tar(b.archive.adapters.buffer(tar)).extractEntries());
    check("extractEntries refuses typeflag " + tf, iterCode === "archive-tar/entry-type-refused");
    var dir = _tmpDir();
    try {
      var code = await _code(b.archive.read.tar(b.archive.adapters.buffer(tar)).extract({ destination: dir }));
      check("extract refuses typeflag " + tf, code === "archive-tar/entry-type-refused");
      check("extract wrote nothing for typeflag " + tf, !fs.existsSync(path.join(dir, "u-" + tf)));
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }
}

async function testSolarisAclHeader() {
  // GNU tar 1.35 reads a Solaris ACL (A) header as an entry and extracts its
  // body as a regular file; bsdtar 3.8 reads the body as the ACL of the entry
  // that follows and lists no entry for it. A pending pax header or L / K
  // record therefore names the A entry in GNU tar and the next entry in bsdtar.
  var acl = _pad512(Buffer.from("01000003\0user::rw-,group::r--,other::r--\0", "latin1"));
  function aclHeader(name) {
    return Buffer.concat([_rawHeader({ name: name, size: 41, typeflag: "A" }), acl]);
  }
  var pending = [
    { label: "pax path before a Solaris ACL (A) header",
      parts: [_paxHeaderBlock("x", _paxBody([["path", "zz/evilname"]])), aclHeader("t"),
        _ustarFile("innocent", "hello\n")] },
    { label: "Solaris X path before a Solaris ACL (A) header",
      parts: [_paxHeaderBlock("X", _paxBody([["path", "zz/evilname"]])), aclHeader("t"),
        _ustarFile("innocent", "hello\n")] },
    { label: "L record before a Solaris ACL (A) header",
      parts: [_gnuLongRecord("L", "zz/evilname\0"), aclHeader("t"), _ustarFile("innocent", "hello\n")] },
    { label: "K record before a Solaris ACL (A) header",
      parts: [_gnuLongRecord("K", "tgt\0"), aclHeader("t"),
        _rawHeader({ name: "s", size: 0, typeflag: "2", linkname: "short" })] },
  ];
  for (var i = 0; i < pending.length; i += 1) {
    var tar = Buffer.concat(pending[i].parts.concat([_end()]));
    var code = await _code(b.archive.read.tar(b.archive.adapters.buffer(tar)).inspect());
    check("read.tar refuses a " + pending[i].label + " (got " + code + ")",
      code === "archive-tar/dangling-extended-header");
    var iterCode = await _iterCode(b.archive.read.tar(b.archive.adapters.buffer(tar)).extractEntries());
    check("extractEntries refuses a " + pending[i].label,
      iterCode === "archive-tar/dangling-extended-header");
  }

  var alone = Buffer.concat([aclHeader("t"), _ustarFile("innocent", "hello\n"), _end()]);
  var listed = await b.archive.read.tar(b.archive.adapters.buffer(alone)).inspect();
  check("inspect lists a standalone A header as an unknown entry and the next entry under its own name",
    listed.length === 2 && listed[0].name === "t" && listed[0].typeflag === "A" &&
    listed[0].entryType === "unknown" && listed[1].name === "innocent" && listed[1].entryType === "file");
  var aloneIter = await _iterCode(b.archive.read.tar(b.archive.adapters.buffer(alone)).extractEntries());
  check("extractEntries refuses a standalone A header", aloneIter === "archive-tar/entry-type-refused");
  var permissiveIter = await _iterCode(b.archive.read.tar(b.archive.adapters.buffer(alone), {
    entryTypePolicy: { symlinks: true, hardlinks: true },
  }).extractEntries({ allowDangerous: { symlinks: true, hardlinks: true } }));
  check("extractEntries refuses a standalone A header when links are allowed",
    permissiveIter === "archive-tar/entry-type-refused");
  var dir = _tmpDir();
  try {
    var extractCode = await _code(b.archive.read.tar(b.archive.adapters.buffer(alone)).extract({ destination: dir }));
    check("extract refuses a standalone A header", extractCode === "archive-tar/entry-type-refused");
    check("extract wrote neither the A body nor the next entry",
      !fs.existsSync(path.join(dir, "t")) && !fs.existsSync(path.join(dir, "innocent")));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }

  var after = Buffer.concat([aclHeader("t"), _paxHeaderBlock("x", _paxBody([["path", "fromPax"]])),
    _ustarFile("innocent", "hello\n"), _end()]);
  var afterListed = await b.archive.read.tar(b.archive.adapters.buffer(after)).inspect();
  check("a pax header after an A header names the entry that follows it",
    afterListed.length === 2 && afterListed[0].entryType === "unknown" && afterListed[1].name === "fromPax");
}

async function testGnuHeaderIgnoresPrefixField() {
  // GNU format headers keep atime / ctime where POSIX ustar keeps the name
  // prefix. GNU tar -G writes them; GNU tar and bsdtar both ignore the field
  // as a prefix for a "ustar  \0" header.
  var bytes = _gnuFixture("gnu-tar-1.35-incremental.tar");
  var entries = await b.archive.read.tar(b.archive.adapters.buffer(bytes)).inspect();
  check("GNU incremental archive: names are not prefixed with the atime field",
    entries.length === 2 && entries[0].name === "d/" && entries[1].name === "d/f");
  check("GNU incremental archive: the dumpdir (D) entry classifies as a directory",
    entries[0].entryType === "directory");
  var out = await _collectEntries(b.archive.read.tar(b.archive.adapters.buffer(bytes)).extractEntries());
  check("GNU incremental archive: extractEntries yields the file",
    out.length === 1 && out[0].name === "d/f" && out[0].bytes.toString("utf8") === "hi\n");
  var synthetic = Buffer.concat([
    _rawHeader({ name: "name", size: 0, typeflag: "0", gnu: true, prefix: "pre" }), _end(),
  ]);
  var synth = await b.archive.read.tar(b.archive.adapters.buffer(synthetic)).inspect();
  check("a GNU header's prefix-area bytes do not become a name prefix",
    synth.length === 1 && synth[0].name === "name");
}

// ---- pax GNU.sparse.* keys and Solaris X extended headers ------------------

function _ustarFile(name, body) {
  var bodyBuf = Buffer.from(body);
  return Buffer.concat([
    _rawHeader({ name: name, size: bodyBuf.length, typeflag: "0" }),
    _pad512(bodyBuf),
  ]);
}

async function _inspectNames(parts) {
  var tar = Buffer.concat(parts.concat([_end()]));
  return b.archive.read.tar(b.archive.adapters.buffer(tar)).inspect();
}

async function _assertTraversalRefused(label, parts) {
  var tar = Buffer.concat(parts.concat([_end()]));
  var entries = await b.archive.read.tar(b.archive.adapters.buffer(tar)).inspect();
  check(label + ": inspect names the entry ../../../etc/cron.d/x and returns no header record",
    entries.length === 1 && entries[0].name === "../../../etc/cron.d/x");
  var verdict = b.guardArchive.validateEntries(entries.map(function (e) {
    return { name: e.name, size: e.size, compressedSize: e.size };
  }), { profile: "balanced" });
  check(label + ": validateEntries over inspect() output reports the traversal name",
    verdict.issues.some(function (iss) { return iss.severity === "critical"; }));
  var iterCode = await _iterCode(b.archive.read.tar(b.archive.adapters.buffer(tar)).extractEntries());
  check(label + ": extractEntries refuses via the guard pass (got " + iterCode + ")",
    iterCode === "archive-tar/guard-refused");
  var dir = _tmpDir();
  try {
    var dest = path.join(dir, "a", "b", "c");
    var code = await _code(b.archive.read.tar(b.archive.adapters.buffer(tar)).extract({ destination: dest }));
    check(label + ": extract refuses via the guard pass (got " + code + ")",
      code === "archive-tar/guard-refused");
    check(label + ": extract wrote nothing",
      fs.readdirSync(dest).length === 0 && !fs.existsSync(path.join(dir, "etc")));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

async function testPaxSparseNameFromRealGnuTar() {
  // GNU tar 1.35 `--format=posix -S` writes a pax 1.0 sparse entry: header
  // name ./GNUSparseFile.<pid>/sparse.bin, GNU.sparse.name=sparse.bin, and a
  // body that holds the sparse map followed by the data blocks.
  var bytes = _gnuFixture("gnu-tar-1.35-posix-sparse.tar");
  var entries = await b.archive.read.tar(b.archive.adapters.buffer(bytes)).inspect();
  check("posix sparse: inspect names the entry from GNU.sparse.name",
    entries.length === 1 && entries[0].name === "sparse.bin");
  check("posix sparse: the entry classifies as unknown", entries[0].entryType === "unknown");
  var iterCode = await _iterCode(b.archive.read.tar(b.archive.adapters.buffer(bytes)).extractEntries());
  check("posix sparse: extractEntries refuses the sparse entry (got " + iterCode + ")",
    iterCode === "archive-tar/entry-type-refused");
  var dir = _tmpDir();
  try {
    var code = await _code(b.archive.read.tar(b.archive.adapters.buffer(bytes)).extract({ destination: dir }));
    check("posix sparse: extract refuses the sparse entry (got " + code + ")",
      code === "archive-tar/entry-type-refused");
    check("posix sparse: extract wrote nothing", fs.readdirSync(dir).length === 0);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }

  // GNU tar 1.35 `--format=gnu -S` writes typeflag S.
  var gnuBytes = _gnuFixture("gnu-tar-1.35-gnu-sparse.tar");
  var gnuEntries = await b.archive.read.tar(b.archive.adapters.buffer(gnuBytes)).inspect();
  check("gnu sparse: inspect lists sparse.bin as unknown",
    gnuEntries.length === 1 && gnuEntries[0].name === "sparse.bin" && gnuEntries[0].entryType === "unknown");
  var gnuCode = await _iterCode(b.archive.read.tar(b.archive.adapters.buffer(gnuBytes)).extractEntries());
  check("gnu sparse: extractEntries refuses under the default entryTypePolicy",
    gnuCode === "archive-tar/entry-type-refused");
}

async function testPaxSparseNameTraversalReachesGuard() {
  var T = "../../../etc/cron.d/x";
  await _assertTraversalRefused("x GNU.sparse.name",
    [_paxHeaderBlock("x", _paxBody([["GNU.sparse.name", T]])), _ustarFile("innocent", "x")]);
  await _assertTraversalRefused("x GNU.sparse.name after path",
    [_paxHeaderBlock("x", _paxBody([["path", "innocent"], ["GNU.sparse.name", T]])),
      _ustarFile("innocent", "x")]);
  await _assertTraversalRefused("x GNU.sparse.name before path",
    [_paxHeaderBlock("x", _paxBody([["GNU.sparse.name", T], ["path", "innocent"]])),
      _ustarFile("innocent", "x")]);
  await _assertTraversalRefused("x GNU.sparse.name after a global header",
    [_paxHeaderBlock("g", _paxBody([["comment", "innocent"]])),
      _paxHeaderBlock("x", _paxBody([["GNU.sparse.name", T]])), _ustarFile("innocent", "x")]);
  await _assertTraversalRefused("Solaris X path",
    [_paxHeaderBlock("X", _paxBody([["path", T]])), _ustarFile("innocent", "x")]);
}

async function testPaxSparseNameShapes() {
  var agreeL = await _inspectNames([_gnuLongRecord("L", "same\0"),
    _paxHeaderBlock("x", _paxBody([["GNU.sparse.name", "same"]])), _gnuFile("short", "x")]);
  check("an L record and a GNU.sparse.name naming the same file are accepted",
    agreeL.length === 1 && agreeL[0].name === "same" && agreeL[0].entryType === "unknown");
  var empty = await _inspectNames([_paxHeaderBlock("x", _paxBody([["GNU.sparse.name", ""]])),
    _ustarFile("hdr", "x")]);
  check("an empty GNU.sparse.name leaves the header name in place",
    empty.length === 1 && empty[0].name === "hdr" && empty[0].entryType === "unknown");
  var sparseKeyOnly = await _inspectNames([_paxHeaderBlock("x", _paxBody([["GNU.sparse.size", "10"]])),
    _ustarFile("hdr", "x")]);
  check("a pax GNU.sparse.size key marks the entry as unknown",
    sparseKeyOnly.length === 1 && sparseKeyOnly[0].entryType === "unknown");
  var next = await _inspectNames([_paxHeaderBlock("x", _paxBody([["GNU.sparse.name", "A"]])),
    _ustarFile("hdr", "x"), _ustarFile("plain", "y")]);
  check("GNU.sparse.name in an x header applies only to the next entry",
    next.length === 2 && next[0].name === "A" && next[1].name === "plain" && next[1].entryType === "file");

  var refusals = [
    { label: "L before a GNU.sparse.name naming a different file",
      code: "archive-tar/long-name-pax-conflict",
      tar: [_gnuLongRecord("L", "fromL\0"), _paxHeaderBlock("x", _paxBody([["GNU.sparse.name", "fromPax"]])),
        _gnuFile("short", "x")] },
    { label: "GNU.sparse.name before an L naming a different file",
      code: "archive-tar/long-name-pax-conflict",
      tar: [_paxHeaderBlock("x", _paxBody([["GNU.sparse.name", "fromPax"]])), _gnuLongRecord("L", "fromL\0"),
        _gnuFile("short", "x")] },
    { label: "GNU.sparse.name in a global header",
      code: "archive-tar/global-entry-attribute",
      tar: [_paxHeaderBlock("g", _paxBody([["GNU.sparse.name", "A"]])), _ustarFile("hdr", "x")] },
    { label: "GNU.sparse.major in a global header",
      code: "archive-tar/global-entry-attribute",
      tar: [_paxHeaderBlock("g", _paxBody([["GNU.sparse.major", "1"]])), _ustarFile("hdr", "x")] },
    { label: "Solaris X header at the end of the archive",
      code: "archive-tar/dangling-extended-header",
      tar: [_ustarFile("a", "A"), _paxHeaderBlock("X", _paxBody([["path", "dangling"]]))] },
    { label: "Solaris X header before a volume label (V) header",
      code: "archive-tar/dangling-extended-header",
      tar: [_paxHeaderBlock("X", _paxBody([["path", "fromX"]])),
        _rawHeader({ name: "vol", size: 0, typeflag: "V", gnu: true }), _gnuFile("short", "x")] },
    { label: "Solaris X linkpath before a regular file",
      code: "archive-tar/link-target-on-non-link",
      tar: [_paxHeaderBlock("X", _paxBody([["linkpath", "tgt"]])), _ustarFile("reg", "x")] },
    { label: "L before a Solaris X path naming a different file",
      code: "archive-tar/long-name-pax-conflict",
      tar: [_gnuLongRecord("L", "fromL\0"), _paxHeaderBlock("X", _paxBody([["path", "fromX"]])),
        _gnuFile("short", "x")] },
    { label: "Solaris X header with a malformed record",
      code: "archive-tar/bad-pax-record",
      tar: [_paxHeaderBlock("X", Buffer.from("garbage")), _ustarFile("hdr", "x")] },
  ];
  for (var i = 0; i < refusals.length; i += 1) {
    var tar = Buffer.concat(refusals[i].tar.concat([_end()]));
    var code = await _code(b.archive.read.tar(b.archive.adapters.buffer(tar)).inspect());
    check("read.tar refuses " + refusals[i].label + " (" + refusals[i].code + ", got " + code + ")",
      code === refusals[i].code);
    var iterCode = await _iterCode(b.archive.read.tar(b.archive.adapters.buffer(tar)).extractEntries());
    check("extractEntries refuses " + refusals[i].label + " (got " + iterCode + ")",
      iterCode === refusals[i].code);
  }
}

async function testSolarisExtendedHeaderApplied() {
  var symlink = await _inspectNames([_paxHeaderBlock("X", _paxBody([["linkpath", "T"]])),
    _rawHeader({ name: "sym", size: 0, typeflag: "2", linkname: "short" })]);
  check("a Solaris X linkpath sets the next symlink's linkname",
    symlink.length === 1 && symlink[0].entryType === "symlink" && symlink[0].linkname === "T");
  var sizeTar = Buffer.concat([
    _paxHeaderBlock("X", _paxBody([["size", "3"]])),
    _rawHeader({ name: "f", size: 0, typeflag: "0" }), _pad512(Buffer.from("abc")), _end(),
  ]);
  var out = await _collectEntries(b.archive.read.tar(b.archive.adapters.buffer(sizeTar)).extractEntries());
  check("a Solaris X size overrides the header size",
    out.length === 1 && out[0].name === "f" && out[0].bytes.toString("utf8") === "abc");
}

// ---- pax records are byte-counted; non-ASCII names from real tools -------

var NON_ASCII_NAMES = [
  "café.txt",
  "dir-é/",
  "dir-é/n日本.txt",
  "lnk-é",
  "plain.txt",
];

async function testNonAsciiNamesFromRealTools() {
  // GNU tar 1.35 --format=posix and bsdtar 3.8.10 --format=pax write a pax
  // path (and linkpath) record whose length counts UTF-8 bytes.
  var fixtures = ["gnu-tar-1.35-posix-non-ascii.tar", "bsdtar-3.8.10-pax-non-ascii.tar"];
  for (var i = 0; i < fixtures.length; i += 1) {
    var label = fixtures[i];
    var bytes = _gnuFixture(label);
    var inspectCode = await _code(b.archive.read.tar(b.archive.adapters.buffer(bytes)).inspect());
    check(label + ": inspect reads the archive (got " + inspectCode + ")", inspectCode === null);
    var listed = await b.archive.read.tar(b.archive.adapters.buffer(bytes)).inspect().catch(function () { return []; });
    var names = listed.map(function (e) { return e.name; });
    check(label + ": inspect lists the names GNU tar and bsdtar list (got " + JSON.stringify(names) + ")",
      JSON.stringify(names) === JSON.stringify(NON_ASCII_NAMES));
    var link = listed.filter(function (e) { return e.entryType === "symlink"; })[0];
    check(label + ": the symlink carries its non-ASCII pax linkpath",
      !!link && link.linkname === "café.txt");
    var out = await _collectEntries(b.archive.read.tar(b.archive.adapters.buffer(bytes))
      .extractEntries({ allowDangerous: { symlinks: true } })).catch(function () { return []; });
    var byName = {};
    out.forEach(function (e) { byName[e.name] = e.bytes.toString("utf8"); });
    check(label + ": extractEntries yields each file under its non-ASCII name",
      byName["café.txt"] === "caf\n" && byName["dir-é/n日本.txt"] === "one\n" &&
      byName["plain.txt"] === "hi\n");
    var dir = _tmpDir();
    try {
      var code = await b.archive.read.tar(b.archive.adapters.buffer(bytes))
        .extract({ destination: dir, allowDangerous: { symlinks: true } })
        .then(function () { return "created"; }, function (e) { return (e && e.code) || "threw"; });
      var privRefused = process.platform === "win32" &&
        (code === "EPERM" || code === "EACCES" || code === "UNKNOWN");
      check(label + ": extract writes the archive or the OS refuses the symlink (got " + code + ")",
        code === "created" || privRefused);
      if (code === "created") {
        check(label + ": extract wrote the files under their non-ASCII names",
          fs.readFileSync(path.join(dir, "café.txt"), "utf8") === "caf\n" &&
          fs.readFileSync(path.join(dir, "dir-é", "n日本.txt"), "utf8") === "one\n");
      }
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }
}

async function testPaxRecordsCountBytes() {
  var nonAscii = await _inspectNames([
    _paxHeaderBlock("x", _paxBody([["path", "café.txt"], ["mtime", "1"]])), _ustarFile("cafe.txt", "x"),
  ]);
  check("a non-ASCII pax path followed by another record names the entry",
    nonAscii.length === 1 && nonAscii[0].name === "café.txt");
  // A comment of k two-byte characters ahead of a k-byte path record: a reader
  // that counts characters instead of bytes swallows the path record into the
  // comment and keeps the header name.
  var T = "../../../etc/cron.d/x";
  var pathRec = _paxRecord("path", T);
  var skewBody = Buffer.from(_paxRecord("comment", "é".repeat(pathRec.length)) + pathRec, "utf8");
  await _assertTraversalRefused("non-ASCII comment before a pax path",
    [_paxHeaderBlock("x", skewBody), _ustarFile("innocent", "x")]);
  var sparseRec = _paxRecord("GNU.sparse.name", T);
  var sparseBody = Buffer.from(_paxRecord("comment", "é".repeat(sparseRec.length)) + sparseRec, "utf8");
  await _assertTraversalRefused("non-ASCII comment before a pax GNU.sparse.name",
    [_paxHeaderBlock("x", sparseBody), _ustarFile("innocent", "x")]);
  var linkRec = _paxRecord("linkpath", "/etc/passwd");
  var linkBody = Buffer.from(_paxRecord("comment", "é".repeat(linkRec.length)) + linkRec, "utf8");
  var link = await _inspectNames([_paxHeaderBlock("x", linkBody),
    _rawHeader({ name: "l", size: 0, typeflag: "2", linkname: "safe" })]);
  check("a pax linkpath after a non-ASCII comment sets the symlink target",
    link.length === 1 && link[0].linkname === "/etc/passwd");
}

async function testRedundantExtendedHeadersRefused() {
  // GNU tar keeps the last of two extended headers; bsdtar 3.8.10 refuses
  // the archive ("Redundant 'X'/'x' header").
  var cases = [
    { label: "two x headers", parts: [_paxHeaderBlock("x", _paxBody([["path", "first"]])),
      _paxHeaderBlock("x", _paxBody([["mtime", "1"]]))] },
    { label: "an x header and an X header", parts: [_paxHeaderBlock("x", _paxBody([["path", "first"]])),
      _paxHeaderBlock("X", _paxBody([["mtime", "1"]]))] },
    { label: "two x headers around a global header", parts: [
      _paxHeaderBlock("x", _paxBody([["path", "first"]])), _paxHeaderBlock("g", _paxBody([["comment", "c"]])),
      _paxHeaderBlock("x", _paxBody([["mtime", "1"]]))] },
  ];
  for (var i = 0; i < cases.length; i += 1) {
    var tar = Buffer.concat(cases[i].parts.concat([_ustarFile("innocent", "x"), _end()]));
    var code = await _code(b.archive.read.tar(b.archive.adapters.buffer(tar)).inspect());
    check("read.tar refuses " + cases[i].label + " before one entry (got " + code + ")",
      code === "archive-tar/redundant-extended-header");
    var iterCode = await _iterCode(b.archive.read.tar(b.archive.adapters.buffer(tar)).extractEntries());
    check("extractEntries refuses " + cases[i].label + " (got " + iterCode + ")",
      iterCode === "archive-tar/redundant-extended-header");
  }
}

async function testGnuVolumeLabelFromRealGnuTar() {
  // GNU tar 1.35 --format=gnu --label writes a V header with no magic; GNU
  // tar lists it as "VOL1--Volume Header--" and bsdtar skips it.
  var bytes = _gnuFixture("gnu-tar-1.35-gnu-label.tar");
  var entries = await b.archive.read.tar(b.archive.adapters.buffer(bytes)).inspect()
    .catch(function (e) { return e.code; });
  check("gnu label: inspect lists the label and the file (got " + JSON.stringify(entries) + ")",
    Array.isArray(entries) && entries.length === 2 &&
    entries[0].name === "VOL1" && entries[0].typeflag === "V" && entries[0].entryType === "unknown" &&
    entries[1].name === "plain.txt" && entries[1].entryType === "file");
  var iterCode = await _iterCode(b.archive.read.tar(b.archive.adapters.buffer(bytes)).extractEntries());
  check("gnu label: extractEntries refuses the label under the default entryTypePolicy (got " +
    iterCode + ")", iterCode === "archive-tar/entry-type-refused");
  var dir = _tmpDir();
  try {
    var code = await _code(b.archive.read.tar(b.archive.adapters.buffer(bytes)).extract({ destination: dir }));
    check("gnu label: extract refuses the label (got " + code + ")", code === "archive-tar/entry-type-refused");
    check("gnu label: extract wrote nothing", fs.readdirSync(dir).length === 0);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }

  // GNU tar --format=posix --label writes the label as a pax global
  // GNU.volume.label record instead of a V header.
  var posixBytes = _gnuFixture("gnu-tar-1.35-posix-label.tar");
  var posixOut = await _collectEntries(b.archive.read.tar(b.archive.adapters.buffer(posixBytes)).extractEntries());
  check("posix label: extractEntries yields the file",
    posixOut.length === 1 && posixOut[0].name === "plain.txt" && posixOut[0].bytes.toString("utf8") === "hi\n");

  var badSum = Buffer.concat([_rawHeader({ name: "VOL1", size: 0, typeflag: "V", badMagic: true, badChksum: true }),
    _end()]);
  check("a magic-less V header with a wrong checksum is refused",
    await _code(b.archive.read.tar(b.archive.adapters.buffer(badSum)).inspect()) === "archive-tar/bad-chksum");
  var noMagicFile = Buffer.concat([_rawHeader({ name: "f", size: 0, typeflag: "0", badMagic: true }), _end()]);
  check("a magic-less header of any other typeflag is still refused",
    await _code(b.archive.read.tar(b.archive.adapters.buffer(noMagicFile)).inspect()) === "archive-tar/bad-magic");
  var dangling = Buffer.concat([_gnuLongRecord("L", "fromL\0"),
    _rawHeader({ name: "VOL1", size: 0, typeflag: "V", badMagic: true }), _gnuFile("short", "x"), _end()]);
  check("an L record before a magic-less V header is refused",
    await _code(b.archive.read.tar(b.archive.adapters.buffer(dangling)).inspect()) ===
      "archive-tar/dangling-extended-header");
}

// ---- entry bodies that GNU tar and bsdtar do not skip -----------------------

var HIDDEN_NAME = "HIDDEN.sh";

// Copies a header, overwrites one field with raw bytes and recomputes the
// checksum, so a test can place bytes that are not valid UTF-8 in a name.
function _withFieldBytes(header, offset, width, bytes) {
  var buf = Buffer.from(header);
  buf.fill(0, offset, offset + width);
  bytes.copy(buf, offset);
  for (var i = 148; i < 156; i += 1) buf[i] = 0x20;
  var sum = 0;
  for (var j = 0; j < BLOCK; j += 1) sum += buf[j];
  var oct = sum.toString(8);
  while (oct.length < 6) oct = "0" + oct;
  buf.write(oct + "\0 ", 148, 8, "ascii");
  return buf;
}

// A header whose size covers a complete ustar entry for HIDDEN.sh. GNU tar
// 1.35 and bsdtar 3.8.10 do not skip that body for a link, device,
// directory or FIFO header, so both extract HIDDEN.sh.
function _headerHidingEntry(o) {
  var inner = _ustarFile(HIDDEN_NAME, "#!/bin/sh\necho pwned\n");
  return Buffer.concat([_rawHeader(Object.assign({ size: inner.length }, o)), inner]);
}

function _paxSizeHidingEntry(o) {
  var inner = _ustarFile(HIDDEN_NAME, "#!/bin/sh\necho pwned\n");
  return Buffer.concat([
    _paxHeaderBlock("x", _paxBody([["size", String(inner.length)]])),
    _rawHeader(Object.assign({ size: 0 }, o)),
    inner,
  ]);
}

async function _assertRefusedEverywhere(label, tar, expected) {
  var code = await _code(b.archive.read.tar(b.archive.adapters.buffer(tar)).inspect());
  check(label + ": inspect refuses with " + expected + " (got " + code + ")", code === expected);
  var iterCode = await _iterCode(b.archive.read.tar(b.archive.adapters.buffer(tar))
    .extractEntries({ allowDangerous: { symlinks: true, hardlinks: true } }));
  check(label + ": extractEntries refuses with " + expected + " (got " + iterCode + ")", iterCode === expected);
  var dir = _tmpDir();
  try {
    var extractCode = await _code(b.archive.read.tar(b.archive.adapters.buffer(tar))
      .extract({ destination: dir, allowDangerous: { symlinks: true, hardlinks: true } }));
    check(label + ": extract refuses with " + expected + " (got " + extractCode + ")", extractCode === expected);
    check(label + ": extract wrote nothing", fs.readdirSync(dir).length === 0);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

async function testNonFileEntryWithSizeRefused() {
  var after = _ustarFile("after", "x");
  var cases = [
    { label: "hardlink with a header size",
      parts: [_ustarFile("safe", "s"), _headerHidingEntry({ name: "h", typeflag: "1", linkname: "safe" })] },
    { label: "symlink with a header size",
      parts: [_headerHidingEntry({ name: "l", typeflag: "2", linkname: "safe" })] },
    { label: "char device with a header size", parts: [_headerHidingEntry({ name: "c", typeflag: "3" })] },
    { label: "block device with a header size", parts: [_headerHidingEntry({ name: "k", typeflag: "4" })] },
    { label: "directory with a header size", parts: [_headerHidingEntry({ name: "d/", typeflag: "5" })] },
    { label: "FIFO with a header size", parts: [_headerHidingEntry({ name: "f", typeflag: "6" })] },
    { label: "GNU-format directory with a header size",
      parts: [_headerHidingEntry({ name: "d/", typeflag: "5", gnu: true })] },
    { label: "GNU-format hardlink with a header size",
      parts: [_ustarFile("safe", "s"), _headerHidingEntry({ name: "h", typeflag: "1", linkname: "safe", gnu: true })] },
    { label: "typeflag 0 named with a trailing slash and a header size",
      parts: [_headerHidingEntry({ name: "d/", typeflag: "0" })] },
    { label: "typeflag NUL named with a trailing slash and a header size",
      parts: [_headerHidingEntry({ name: "d/" })] },
    { label: "typeflag 7 named with a trailing slash and a header size",
      parts: [_headerHidingEntry({ name: "d/", typeflag: "7" })] },
    { label: "directory with a pax size", parts: [_paxSizeHidingEntry({ name: "d/", typeflag: "5" })] },
    { label: "symlink with a pax size",
      parts: [_paxSizeHidingEntry({ name: "l", typeflag: "2", linkname: "safe" })] },
    { label: "hardlink with a pax size",
      parts: [_ustarFile("safe", "s"), _paxSizeHidingEntry({ name: "h", typeflag: "1", linkname: "safe" })] },
    { label: "typeflag 0 whose pax path ends in a slash, with a header size",
      parts: [_paxHeaderBlock("x", _paxBody([["path", "d/"]])), _headerHidingEntry({ name: "f", typeflag: "0" })] },
    { label: "typeflag 0 whose L name ends in a slash, with a header size",
      parts: [_gnuLongRecord("L", "d/\0"), _headerHidingEntry({ name: "f", typeflag: "0", gnu: true })] },
  ];
  for (var i = 0; i < cases.length; i += 1) {
    await _assertRefusedEverywhere(cases[i].label,
      Buffer.concat(cases[i].parts.concat([after, _end()])), "archive-tar/size-on-non-file");
  }

  var control = await _inspectNames([_rawHeader({ name: "d/", size: 0, typeflag: "5" }),
    _ustarFile(HIDDEN_NAME, "x"), after]);
  check("a directory with size 0 is followed by the next entry",
    control.map(function (e) { return e.name; }).join(",") === "d/," + HIDDEN_NAME + ",after");
  var slashDir = await _inspectNames([_rawHeader({ name: "d/", size: 0, typeflag: "0" }),
    _rawHeader({ name: "v7/", size: 0 }), _rawHeader({ name: "c/", size: 0, typeflag: "7" })]);
  check("typeflag 0, NUL and 7 entries named with a trailing slash classify as directories",
    slashDir.length === 3 && slashDir.every(function (e) { return e.entryType === "directory"; }));
}

async function testLinksAndDirectoriesFromRealTools() {
  // GNU tar 1.35 (--format=gnu and --format=posix) and bsdtar 3.8.10
  // (--format=pax) write size 0 for hardlink, symlink and directory headers.
  var fixtures = ["gnu-tar-1.35-gnu-links.tar", "gnu-tar-1.35-posix-links.tar", "bsdtar-3.8.10-pax-links.tar"];
  for (var i = 0; i < fixtures.length; i += 1) {
    var label = fixtures[i];
    var bytes = _gnuFixture(label);
    var entries = await b.archive.read.tar(b.archive.adapters.buffer(bytes)).inspect()
      .catch(function (e) { return e.code; });
    var shape = Array.isArray(entries) ? entries.map(function (e) {
      return e.name + ":" + e.entryType + (e.linkname ? "->" + e.linkname : "");
    }).join(",") : entries;
    check(label + ": inspect lists what GNU tar and bsdtar list (got " + shape + ")",
      shape === "f:file,hard:hardlink->f,sym:symlink->f,d/:directory,d/g:file");
    var out = await _collectEntries(b.archive.read.tar(b.archive.adapters.buffer(bytes), { guardProfile: false })
      .extractEntries({ allowDangerous: { symlinks: true, hardlinks: true } })).catch(function () { return []; });
    check(label + ": extractEntries yields both files",
      out.map(function (e) { return e.name + "=" + e.bytes.toString("utf8"); }).join(",") === "f=hi\n,d/g=g\n");
  }

  // GNU tar 1.35 and bsdtar 3.8.10 extract a typeflag NUL or 0 entry named
  // with a trailing slash as a directory (bsdtar --format=v7 writes
  // directories that way).
  var slashTar = Buffer.concat([_rawHeader({ name: "d/", size: 0 }), _ustarFile("d/g", "g\n"), _end()]);
  var slashEntries = await b.archive.read.tar(b.archive.adapters.buffer(slashTar)).inspect();
  check("trailing-slash NUL entry: inspect classifies d/ as a directory",
    slashEntries.length === 2 && slashEntries[0].name === "d/" && slashEntries[0].entryType === "directory" &&
    slashEntries[1].name === "d/g" && slashEntries[1].entryType === "file");
  var dir = _tmpDir();
  try {
    var code = await _code(b.archive.read.tar(b.archive.adapters.buffer(slashTar)).extract({ destination: dir }));
    check("trailing-slash NUL entry: extract succeeds (got " + code + ")", code === null);
    check("trailing-slash NUL entry: extract creates the directory and its file",
      code === null && fs.statSync(path.join(dir, "d")).isDirectory() &&
      fs.readFileSync(path.join(dir, "d", "g"), "utf8") === "g\n");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

async function testPaxSizeValueValidated() {
  // GNU tar 1.35 refuses an empty size ("Malformed extended header: invalid
  // size=") and bsdtar 3.8.10 reads it as 0, which exposes the bytes the
  // header size covers as further entries.
  var values = ["", " 1", "1 ", "+1", "-1", "0x1", "1.0", "1e3", "03", "١"];
  for (var i = 0; i < values.length; i += 1) {
    var inner = _ustarFile(HIDDEN_NAME, "#!/bin/sh\necho pwned\n");
    var tar = Buffer.concat([
      _paxHeaderBlock("x", _paxBody([["size", values[i]]])),
      _rawHeader({ name: "f", size: inner.length, typeflag: "0" }), inner,
      _ustarFile("after", "x"), _end(),
    ]);
    await _assertRefusedEverywhere("pax size " + JSON.stringify(values[i]), tar, "archive-tar/bad-pax-size");
  }
  var ok = await _inspectNames([_paxHeaderBlock("x", _paxBody([["size", "0"]])),
    _rawHeader({ name: "empty", size: 0, typeflag: "0" })]);
  check("a pax size of 0 is accepted", ok.length === 1 && ok[0].size === 0);
}

async function testLoneZeroBlockEndsArchive() {
  // GNU tar 1.35 ("A lone zero block at N") and bsdtar 3.8.10 both stop at
  // the first zero block and list nothing after it.
  var T = "../../../etc/cron.d/x";
  var tar = Buffer.concat([
    _ustarFile("a.txt", "aa"), Buffer.alloc(BLOCK, 0), _ustarFile(T, "bb"), _ustarFile("b.txt", "bb"), _end(),
  ]);
  var entries = await b.archive.read.tar(b.archive.adapters.buffer(tar)).inspect();
  check("inspect stops at a lone zero block (got " + JSON.stringify(entries.map(function (e) { return e.name; })) + ")",
    entries.length === 1 && entries[0].name === "a.txt");
  var out = await _collectEntries(b.archive.read.tar(b.archive.adapters.buffer(tar)).extractEntries());
  check("extractEntries yields only the entry before a lone zero block",
    out.length === 1 && out[0].name === "a.txt");
  var dir = _tmpDir();
  try {
    var dest = path.join(dir, "a", "b", "c");
    var code = await _code(b.archive.read.tar(b.archive.adapters.buffer(tar)).extract({ destination: dest }));
    check("extract stops at a lone zero block (got " + code + ")",
      code === null && fs.readdirSync(dest).join(",") === "a.txt" && !fs.existsSync(path.join(dir, "etc")));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  var atEnd = await b.archive.read.tar(b.archive.adapters.buffer(Buffer.concat([
    _ustarFile("a.txt", "aa"), Buffer.alloc(BLOCK, 0)]))).inspect();
  check("an archive ending in one zero block lists its entries", atEnd.length === 1 && atEnd[0].name === "a.txt");
  var dangling = Buffer.concat([_paxHeaderBlock("x", _paxBody([["path", "p"]])), Buffer.alloc(BLOCK, 0),
    _ustarFile("a.txt", "aa"), _end()]);
  check("a pax header followed by a zero block is dangling",
    await _code(b.archive.read.tar(b.archive.adapters.buffer(dangling)).inspect()) ===
      "archive-tar/dangling-extended-header");
}

function _paxRecordBytes(key, valueBytes) {
  var head = Buffer.from(" " + key + "=", "utf8");
  var rest = head.length + valueBytes.length + 1;
  var len = rest + 1;
  while (String(len).length + rest !== len) len = String(len).length + rest;
  return Buffer.concat([Buffer.from(String(len), "ascii"), head, valueBytes, Buffer.from("\n", "ascii")]);
}

async function testNamesMustBeUtf8() {
  var BAD = Buffer.from([0x6e, 0xff, 0xfe, 0x2e, 0x74]);
  var OVERLONG = Buffer.from([0x61, 0xc0, 0xaf, 0x2e, 0x2e, 0xc0, 0xaf, 0x78]);
  var symlink = _rawHeader({ name: "l", size: 0, typeflag: "2", linkname: "safe" });
  var refused = [
    { label: "an L body with an overlong slash",
      parts: [_gnuLongRecord("L", OVERLONG.toString("latin1") + "\0"), _gnuFile("i", "x")] },
    { label: "a K body that is not UTF-8",
      parts: [_gnuLongRecord("K", BAD.toString("latin1") + "\0"), _gnuSymlink("l", "safe")] },
    { label: "a pax path that is not UTF-8",
      parts: [_paxHeaderBlock("x", _paxRecordBytes("path", BAD)), _ustarFile("i", "x")] },
    { label: "a pax path after hdrcharset=BINARY",
      parts: [_paxHeaderBlock("x", Buffer.concat([_paxBody([["hdrcharset", "BINARY"]]), _paxRecordBytes("path", BAD)])),
        _ustarFile("i", "x")] },
    { label: "a pax linkpath that is not UTF-8",
      parts: [_paxHeaderBlock("x", _paxRecordBytes("linkpath", BAD)), symlink] },
    { label: "a pax GNU.sparse.name that is not UTF-8",
      parts: [_paxHeaderBlock("x", _paxRecordBytes("GNU.sparse.name", BAD)), _ustarFile("i", "x")] },
    { label: "a header name that is not UTF-8",
      parts: [_withFieldBytes(_rawHeader({ name: "i", size: 0, typeflag: "0" }), 0, 100, BAD)] },
    { label: "a ustar prefix that is not UTF-8",
      parts: [_withFieldBytes(_rawHeader({ name: "i", size: 0, typeflag: "0" }), 345, 155, BAD)] },
    { label: "a symlink header linkname that is not UTF-8",
      parts: [_withFieldBytes(symlink, 157, 100, BAD)] },
    { label: "a hardlink header linkname that is not UTF-8",
      parts: [_withFieldBytes(_rawHeader({ name: "h", size: 0, typeflag: "1", linkname: "x" }), 157, 100, BAD)] },
  ];
  for (var i = 0; i < refused.length; i += 1) {
    await _assertRefusedEverywhere(refused[i].label, Buffer.concat(refused[i].parts.concat([_end()])),
      "archive-tar/name-not-utf8");
  }
  var fixtures = ["gnu-tar-1.35-gnu-binary-name.tar", "gnu-tar-1.35-posix-binary-name.tar",
    "bsdtar-3.8.10-pax-binary-name.tar"];
  for (var f = 0; f < fixtures.length; f += 1) {
    await _assertRefusedEverywhere(fixtures[f], _gnuFixture(fixtures[f]), "archive-tar/name-not-utf8");
  }

  var nonAscii = await _inspectNames([_withFieldBytes(_rawHeader({ name: "i", size: 0, typeflag: "0" }),
    0, 100, Buffer.from("café", "utf8"))]);
  check("a UTF-8 header name is read", nonAscii.length === 1 && nonAscii[0].name === "café");
  var overriddenByPax = await _inspectNames([_paxHeaderBlock("x", _paxBody([["path", "from-pax"]])),
    _withFieldBytes(_rawHeader({ name: "i", size: 0, typeflag: "0" }), 0, 100, BAD)]);
  check("a header name replaced by a pax path is not checked",
    overriddenByPax.length === 1 && overriddenByPax[0].name === "from-pax");
  var overriddenByL = await _inspectNames([_gnuLongRecord("L", "from-l\0"),
    _withFieldBytes(_rawHeader({ name: "i", size: 0, typeflag: "0", gnu: true }), 0, 100, BAD)]);
  check("a header name replaced by an L record is not checked",
    overriddenByL.length === 1 && overriddenByL[0].name === "from-l");
  var paxHeaderName = await _inspectNames([
    _withFieldBytes(_paxHeaderBlock("x", _paxBody([["path", "p"], ["comment", "c"]])).subarray(0, BLOCK), 0, 100, BAD),
    _pad512(_paxBody([["path", "p"], ["comment", "c"]])), _ustarFile("i", "x")]);
  check("the name of a pax header itself is not checked",
    paxHeaderName.length === 1 && paxHeaderName[0].name === "p");
  var comment = await _inspectNames([_paxHeaderBlock("x", _paxRecordBytes("comment", BAD)), _ustarFile("i", "x")]);
  check("a pax comment that is not UTF-8 is accepted", comment.length === 1 && comment[0].name === "i");
  var fileLinkname = await _inspectNames([_withFieldBytes(_rawHeader({ name: "i", size: 0, typeflag: "0" }),
    157, 100, BAD)]);
  check("a linkname field on a regular file is not checked", fileLinkname.length === 1 && fileLinkname[0].name === "i");
}

function _sparseMap(buf, offset, pairs) {
  for (var i = 0; i < pairs.length; i += 1) {
    buf.write(_oct(pairs[i][0], 11) + "\0", offset + i * 24, 12, "ascii");
    buf.write(_oct(pairs[i][1], 11) + "\0", offset + i * 24 + 12, 12, "ascii");
  }
  return buf;
}

function _gnuSparseHeader(o) {
  var hdr = _rawHeader({ name: o.name || "s", size: o.size || 0, typeflag: "S", gnu: o.gnu !== false });
  var buf = Buffer.from(hdr);
  _sparseMap(buf, 386, o.map || []);
  buf[482] = o.extended ? 1 : 0;
  return _withFieldBytes(buf, 0, 0, Buffer.alloc(0));
}

function _sparseExtension(pairs, more) {
  var buf = _sparseMap(Buffer.alloc(BLOCK, 0), 0, pairs);
  buf[504] = more ? 1 : 0;
  return buf;
}

async function testGnuSparseExtensionBlocks() {
  // GNU tar 1.35 --format=gnu -S writes a typeflag S header whose four map
  // entries are full and whose isextended byte is set; an extension block
  // with more map entries follows the header ahead of the data. GNU tar and
  // bsdtar list sp.bin and after.txt.
  var bytes = _gnuFixture("gnu-tar-1.35-gnu-sparse-extended.tar");
  var entries = await b.archive.read.tar(b.archive.adapters.buffer(bytes)).inspect()
    .catch(function (e) { return e.code; });
  var shape = Array.isArray(entries) ? entries.map(function (e) { return e.name + ":" + e.entryType; }).join(",") : entries;
  check("sparse with extension blocks: inspect lists both entries (got " + shape + ")",
    shape === "sp.bin:unknown,after.txt:file");

  var four = [[0, 512], [2048, 512], [4096, 512], [6144, 512]];
  var after = _gnuFile("after", "x");
  var twoBlocks = Buffer.concat([
    _gnuSparseHeader({ map: four, extended: true, size: 3072 }),
    _sparseExtension([[8192, 512]].concat(new Array(20).fill([10240, 0]).map(function (p, k) {
      return [10240 + k * 1024, 512];
    })), true),
    _sparseExtension([[40960, 512]], false),
    Buffer.alloc(3072, 0x41), after, _end(),
  ]);
  var chained = await b.archive.read.tar(b.archive.adapters.buffer(twoBlocks)).inspect()
    .catch(function (e) { return e.code; });
  check("two chained extension blocks are consumed (got " + JSON.stringify(Array.isArray(chained) ?
    chained.map(function (e) { return e.name; }) : chained) + ")",
    Array.isArray(chained) && chained.length === 2 && chained[1].name === "after");

  var hidden = _gnuFile(HIDDEN_NAME, "#!/bin/sh\necho pwned\n");
  var refusals = [
    { label: "isextended on a ustar-magic S header",
      parts: [_gnuSparseHeader({ map: four, extended: true, gnu: false }), _sparseExtension([], false)] },
    { label: "isextended with an empty sparse map",
      parts: [_gnuSparseHeader({ extended: true }), hidden] },
    { label: "isextended with fewer than four map entries",
      parts: [_gnuSparseHeader({ map: [[0, 512]], extended: true, size: 512 }), _sparseExtension([[2048, 512]], false),
        Buffer.alloc(512, 0x41)] },
    { label: "an extension block with an empty entry and isextended set",
      parts: [_gnuSparseHeader({ map: four, extended: true }), _sparseExtension([[8192, 512]], true),
        _sparseExtension([], false)] },
  ];
  for (var i = 0; i < refusals.length; i += 1) {
    var code = await _code(b.archive.read.tar(b.archive.adapters.buffer(
      Buffer.concat(refusals[i].parts.concat([after, _end()])))).inspect());
    check("read.tar refuses " + refusals[i].label + " (got " + code + ")", code === "archive-tar/bad-sparse-header");
  }
  var truncated = Buffer.concat([_gnuSparseHeader({ map: four, extended: true })]);
  check("an extension chain cut off by the end of the archive is truncated",
    await _code(b.archive.read.tar(b.archive.adapters.buffer(truncated)).inspect()) === "archive-tar/truncated-entry");
  var regular = Buffer.from(_rawHeader({ name: "r", size: 0, typeflag: "0", gnu: true }));
  regular[482] = 1;
  var reg = await _inspectNames([_withFieldBytes(regular, 0, 0, Buffer.alloc(0)), hidden]);
  check("byte 482 of a GNU regular-file header does not consume the next block",
    reg.length === 2 && reg[1].name === HIDDEN_NAME);
}

var TRAVERSAL = "../../../etc/cron.d/x";

function _paxRecordKeyBytes(keyBytes, valueBytes, separator) {
  var rest = Buffer.concat([Buffer.from(separator || " ", "latin1"), keyBytes, Buffer.from("=", "ascii"),
    valueBytes, Buffer.from("\n", "ascii")]);
  var len = rest.length + 1;
  while (String(len).length + rest.length !== len) len = String(len).length + rest.length;
  return Buffer.concat([Buffer.from(String(len), "ascii"), rest]);
}

function _paxSizeShape(record) {
  var inner = _ustarFile(HIDDEN_NAME, "#!/bin/sh\necho pwned\n");
  return [_paxHeaderBlock("x", record), _rawHeader({ name: "f", size: inner.length, typeflag: "0" }), inner,
    _ustarFile("after", "x")];
}

function _paxPathShape(record) {
  return [_paxHeaderBlock("x", record), _ustarFile("innocent", "ok\n")];
}

function _paxLinkShape(record) {
  return [_paxHeaderBlock("x", record), _rawHeader({ name: "l", size: 0, typeflag: "2", linkname: "safe" })];
}

async function testPaxKeySpellingsRefusedWhereToolsDisagree() {
  // GNU tar 1.35 and bsdtar 3.8.10 in node:24.22.1-alpine. bsdtar compares a
  // pax key as a C string, so "size\0x" is read as "size"; GNU tar refuses
  // the record ("missing equal sign") and keeps the header values. GNU tar
  // skips blanks between the length and the key, so "<len>  path=" sets the
  // path; bsdtar reads the key " path" and ignores it.
  var latin = function (s) { return Buffer.from(s, "latin1"); };
  var shapes = [
    { key: "size", value: "0", build: _paxSizeShape },
    { key: "path", value: TRAVERSAL, build: _paxPathShape },
    { key: "linkpath", value: "/etc/passwd", build: _paxLinkShape },
    { key: "GNU.sparse.name", value: TRAVERSAL, build: _paxPathShape },
  ];
  for (var i = 0; i < shapes.length; i += 1) {
    var s = shapes[i];
    var variants = [
      { label: "a NUL inside the key", record: _paxRecordKeyBytes(latin(s.key + "\0x"), latin(s.value)) },
      { label: "a NUL at the end of the key", record: _paxRecordKeyBytes(latin(s.key + "\0"), latin(s.value)) },
      { label: "two spaces before the key", record: _paxRecordKeyBytes(latin(s.key), latin(s.value), "  ") },
      { label: "a space and a tab before the key", record: _paxRecordKeyBytes(latin(s.key), latin(s.value), " \t") },
    ];
    for (var v = 0; v < variants.length; v += 1) {
      await _assertRefusedEverywhere("pax " + s.key + " with " + variants[v].label,
        Buffer.concat(s.build(variants[v].record).concat([_end()])), "archive-tar/bad-pax-record");
    }
  }
  var other = _paxRecordKeyBytes(latin("comment\0x"), latin("c"));
  await _assertRefusedEverywhere("a NUL inside a key the reader ignores",
    Buffer.concat([_paxHeaderBlock("x", other), _ustarFile("i", "x"), _end()]), "archive-tar/bad-pax-record");
}

async function testPaxNameValuesWithNulRefused() {
  // GNU tar 1.35 and bsdtar 3.8.10 stop a pax path, linkpath or
  // GNU.sparse.name value at its first NUL. GNU tar sets an empty linkpath
  // and bsdtar keeps the header linkname.
  var latin = function (s) { return Buffer.from(s, "latin1"); };
  var refused = [
    { label: "a pax path with a NUL before a traversal",
      parts: _paxPathShape(_paxRecordKeyBytes(latin("path"), latin("innocent\0" + TRAVERSAL))) },
    { label: "a pax path with a NUL after a traversal",
      parts: _paxPathShape(_paxRecordKeyBytes(latin("path"), latin(TRAVERSAL + "\0innocent"))) },
    { label: "a pax linkpath with a NUL",
      parts: _paxLinkShape(_paxRecordKeyBytes(latin("linkpath"), latin("safe\0/etc/passwd"))) },
    { label: "a pax GNU.sparse.name with a NUL",
      parts: _paxPathShape(_paxRecordKeyBytes(latin("GNU.sparse.name"), latin("innocent\0" + TRAVERSAL))) },
    { label: "an empty pax linkpath on a symlink", parts: _paxLinkShape(_paxBody([["linkpath", ""]])) },
    { label: "an empty pax linkpath with a K record",
      parts: [_paxHeaderBlock("x", _paxBody([["linkpath", ""]])), _gnuLongRecord("K", "safe\0"), _gnuSymlink("l", "x")] },
  ];
  for (var i = 0; i < refused.length; i += 1) {
    await _assertRefusedEverywhere(refused[i].label, Buffer.concat(refused[i].parts.concat([_end()])),
      "archive-tar/bad-pax-name");
  }
}

async function testPaxKeySpellingsToolsAgreeOn() {
  // Both tools ignore a key with a trailing blank, a trailing CR or a
  // different case, keep the last of two records with the same key, and
  // keep the header name for an empty path or GNU.sparse.name.
  var latin = function (s) { return Buffer.from(s, "latin1"); };
  var ignoredKeys = ["path ", "path\t", "path\r", "PATH", "Path"];
  for (var i = 0; i < ignoredKeys.length; i += 1) {
    var e = await _inspectNames(_paxPathShape(_paxRecordKeyBytes(latin(ignoredKeys[i]), latin(TRAVERSAL))));
    check("pax key " + JSON.stringify(ignoredKeys[i]) + " is ignored as GNU tar and bsdtar ignore it",
      e.length === 1 && e[0].name === "innocent" && e[0].entryType === "file");
  }
  var sizeKeys = ["size ", "SIZE"];
  for (var s = 0; s < sizeKeys.length; s += 1) {
    var se = await _inspectNames(_paxSizeShape(_paxRecordKeyBytes(latin(sizeKeys[s]), latin("0"))));
    check("pax key " + JSON.stringify(sizeKeys[s]) + " does not change the size",
      se.map(function (x) { return x.name; }).join(",") === "f,after");
  }
  var linkUpper = await _inspectNames(_paxLinkShape(_paxRecordKeyBytes(latin("LINKPATH"), latin("/etc/passwd"))));
  check("pax key LINKPATH is ignored", linkUpper.length === 1 && linkUpper[0].linkname === "safe");
  var dupPath = await _inspectNames(_paxPathShape(_paxBody([["path", "first"], ["path", "second"]])));
  check("the last of two pax path records names the entry", dupPath.length === 1 && dupPath[0].name === "second");
  var dupLink = await _inspectNames(_paxLinkShape(_paxBody([["linkpath", "one"], ["linkpath", "two"]])));
  check("the last of two pax linkpath records is the target", dupLink.length === 1 && dupLink[0].linkname === "two");
  var emptyPath = await _inspectNames(_paxPathShape(_paxBody([["path", ""]])));
  check("an empty pax path keeps the header name", emptyPath.length === 1 && emptyPath[0].name === "innocent");
  var emptySparse = await _inspectNames(_paxPathShape(_paxBody([["GNU.sparse.name", ""]])));
  check("an empty pax GNU.sparse.name keeps the header name",
    emptySparse.length === 1 && emptySparse[0].name === "innocent");
}

async function testStarSparseKeysAreSparse() {
  // bsdtar 3.8.10 writes SCHILY.realsize bytes for the file (4096 here) and
  // fails on SUN.holesdata; GNU tar 1.35 ignores both keys and writes the
  // stored 3 bytes. In a global header bsdtar refuses both keys.
  var keys = [["SCHILY.realsize", "4096"], ["SUN.holesdata", " 0 3 4096 0"]];
  for (var i = 0; i < keys.length; i += 1) {
    var tar = Buffer.concat([_paxHeaderBlock("x", _paxBody([keys[i]])), _ustarFile("f", "abc"), _end()]);
    var e = await b.archive.read.tar(b.archive.adapters.buffer(tar)).inspect();
    check("pax " + keys[i][0] + ": inspect lists the entry as unknown",
      e.length === 1 && e[0].name === "f" && e[0].entryType === "unknown");
    check("pax " + keys[i][0] + ": extractEntries refuses the entry",
      await _iterCode(b.archive.read.tar(b.archive.adapters.buffer(tar)).extractEntries()) ===
        "archive-tar/entry-type-refused");
    var g = Buffer.concat([_paxHeaderBlock("g", _paxBody([keys[i]])), _ustarFile("f", "abc"), _end()]);
    check("pax global " + keys[i][0] + " is refused",
      await _code(b.archive.read.tar(b.archive.adapters.buffer(g)).inspect()) === "archive-tar/global-entry-attribute");
  }
}

function _magicHeader(magicAndVersion) {
  var hdr = _rawHeader({ name: "x", size: 0, typeflag: "0" });
  var withMagic = _withFieldBytes(hdr, 257, 8, Buffer.from(magicAndVersion, "latin1"));
  return _withFieldBytes(withMagic, 345, 155, Buffer.from("sub", "ascii"));
}

async function testMagicMustBeUstarOrGnu() {
  // GNU tar 1.35 reads a header as POSIX ustar (prefix joined) when the
  // magic is "ustar\0" with any version, as GNU when magic and version are
  // "ustar  \0" (prefix not joined), and otherwise as v7 (prefix not
  // joined). bsdtar 3.8.10 joins the prefix for "ustarX00", "ustar 00" and
  // "ustar \0\0", where GNU tar lists "x" and bsdtar lists "sub/x".
  var refused = ["ustarX00", "ustar 00", "ustar \0\0", "ustar\x20\x20\x20", "Ustar\0\0\0"];
  for (var i = 0; i < refused.length; i += 1) {
    var code = await _code(b.archive.read.tar(b.archive.adapters.buffer(
      Buffer.concat([_magicHeader(refused[i]), _end()]))).inspect());
    check("magic and version " + JSON.stringify(refused[i]) + " are refused (got " + code + ")",
      code === "archive-tar/bad-magic");
  }
  var accepted = [["ustar\x0000", "sub/x"], ["ustar\0XY", "sub/x"], ["ustar\0\0\0", "sub/x"],
    ["ustar\0 \0", "sub/x"], ["ustar  \0", "x"]];
  for (var a = 0; a < accepted.length; a += 1) {
    var entries = await _inspectNames([_magicHeader(accepted[a][0])]).catch(function (e) { return e.code; });
    check("magic and version " + JSON.stringify(accepted[a][0]) + " read the name " + accepted[a][1] +
      " (got " + JSON.stringify(entries) + ")",
      Array.isArray(entries) && entries.length === 1 && entries[0].name === accepted[a][1]);
  }
}

function _base256Header(o) {
  var hdr = _rawHeader({ name: o.name || "f", size: o.size || 0, typeflag: "0", gnu: true });
  return _withFieldBytes(hdr, o.offset, o.bytes.length, Buffer.from(o.bytes));
}

function _field(width, first, tail) {
  var out = new Array(width).fill(first === 0xff ? 0xff : 0);
  out[0] = first;
  for (var i = 0; i < tail.length; i += 1) out[width - tail.length + i] = tail[i];
  return out;
}

async function testBase256NumericFieldsFromRealTools() {
  // GNU tar 1.35 --format=gnu and bsdtar 3.8.10 --format=pax write mtime,
  // uid, gid and size values that do not fit the octal field in base-256:
  // a first byte of 0x80 (positive) or 0xFF (negative, two's complement).
  var dated = [
    ["gnu-tar-1.35-mtime-1960.tar", "old.txt", "1960-01-01T00:00:00.000Z", "old\n"],
    ["gnu-tar-1.35-mtime-2300.tar", "future.txt", "2300-01-01T00:00:00.000Z", "future\n"],
    ["bsdtar-3.8.10-pax-mtime-1960.tar", "old.txt", "1960-01-01T00:00:00.000Z", "old\n"],
    ["gnu-tar-1.35-uid-3000000.tar", "uid.txt", "2020-01-01T00:00:00.000Z", "uid\n"],
  ];
  for (var i = 0; i < dated.length; i += 1) {
    var label = dated[i][0];
    var bytes = _gnuFixture(label);
    var entries = await b.archive.read.tar(b.archive.adapters.buffer(bytes)).inspect()
      .catch(function (e) { return e.code; });
    check(label + ": inspect reads the entry (got " + (Array.isArray(entries) ?
      entries.map(function (e) { return e.name + "@" + e.mtime.toISOString(); }).join(",") : entries) + ")",
      Array.isArray(entries) && entries.length === 1 && entries[0].name === dated[i][1] &&
      entries[0].mtime.toISOString() === dated[i][2]);
    var out = await _collectEntries(b.archive.read.tar(b.archive.adapters.buffer(bytes)).extractEntries())
      .catch(function () { return []; });
    check(label + ": extractEntries yields the file bytes",
      out.length === 1 && out[0].bytes.toString("utf8") === dated[i][3]);
  }

  // bsdtar writes the 1960 mtime as base-256 in the first 11 bytes of the
  // header field and a pax mtime record; GNU tar and bsdtar list the pax
  // value, so the reader applies a well-formed pax mtime.
  var paxTimes = [["-315619200", -315619200000], ["1793190679.5", 1793190679500], ["1e3", 0], ["", 0],
    ["99999999999999", 0], [" 5", 0]];
  for (var t = 0; t < paxTimes.length; t += 1) {
    var timed = await _inspectNames([_paxHeaderBlock("x", _paxBody([["mtime", paxTimes[t][0]]])),
      _rawHeader({ name: "t", size: 0, typeflag: "0" })]);
    check("pax mtime " + JSON.stringify(paxTimes[t][0]) + " gives " + paxTimes[t][1] + " ms (got " +
      timed[0].mtime.getTime() + ")", timed.length === 1 && timed[0].mtime.getTime() === paxTimes[t][1]);
  }

  var big = _gnuFixture("gnu-tar-1.35-size-9gib-truncated.tar");
  check("a 9 GiB base-256 size is over the default per-entry cap",
    await _code(b.archive.read.tar(b.archive.adapters.buffer(big)).inspect()) === "archive-tar/entry-too-large");
  var bigErr = await b.archive.read.tar(b.archive.adapters.buffer(big),
    { bombPolicy: { maxEntryDecompressedBytes: 16 * 1024 * 1024 * 1024 } }).inspect().then(
    function () { return null; }, function (e) { return e; });
  check("a 9 GiB base-256 size is decoded and the cut-off body is truncated",
    bigErr !== null && bigErr.code === "archive-tar/truncated-entry" && /size=9663676416\b/.test(bigErr.message));
}

async function testBase256NumericFieldsDecodedAndBounded() {
  var sized = await _collectEntries(b.archive.read.tar(b.archive.adapters.buffer(Buffer.concat([
    _base256Header({ offset: 124, bytes: _field(12, 0x80, [0x03]) }), _pad512(Buffer.from("abc")), _end(),
  ]))).extractEntries()).catch(function (e) { return e.code; });
  check("a base-256 size of 3 locates the body (got " + JSON.stringify(sized) + ")",
    Array.isArray(sized) && sized.length === 1 && sized[0].bytes.toString("utf8") === "abc");
  var mode = await _inspectNames([_base256Header({ offset: 100, bytes: _field(8, 0x80, [0x01, 0xa4]) })]);
  check("a base-256 mode is decoded", mode.length === 1 && mode[0].mode === 0o644);
  var negTime = await _inspectNames([_base256Header({ offset: 136, bytes: _field(12, 0xff, [0xf0]) })]);
  check("a negative base-256 mtime is decoded", negTime.length === 1 && negTime[0].mtime.getTime() === -16000);

  var outOfRange = [
    ["a negative base-256 size", 124, _field(12, 0xff, [0xfe, 0x00])],
    ["a negative base-256 uid", 108, _field(8, 0xff, [0xfe])],
    ["a negative base-256 gid", 116, _field(8, 0xff, [0xfe])],
    ["a negative base-256 mode", 100, _field(8, 0xff, [0xfe])],
    ["a base-256 uid of 2^32", 108, _field(8, 0x80, [0x01, 0, 0, 0, 0])],
    ["a base-256 size of 2^53", 124, _field(12, 0x80, [0x20, 0, 0, 0, 0, 0, 0])],
    ["a base-256 mtime of 2^72", 136, _field(12, 0x80, [0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0])],
    ["a base-256 mtime past the Date range", 136, _field(12, 0x80, [0x08, 0, 0, 0, 0, 0])],
  ];
  for (var i = 0; i < outOfRange.length; i += 1) {
    await _assertRefusedEverywhere(outOfRange[i][0], Buffer.concat([
      _base256Header({ offset: outOfRange[i][1], bytes: outOfRange[i][2] }), _end()]), "archive-tar/numeric-out-of-range");
  }
  var firstBytes = [0x81, 0xc0, 0xfe];
  for (var f = 0; f < firstBytes.length; f += 1) {
    var code = await _code(b.archive.read.tar(b.archive.adapters.buffer(Buffer.concat([
      _base256Header({ offset: 136, bytes: _field(12, firstBytes[f], [0x10]) }), _end()]))).inspect());
    check("a numeric field starting with 0x" + firstBytes[f].toString(16) + " is refused (got " + code + ")",
      code === "archive-tar/bad-octal");
  }
  var chksum = Buffer.from(_rawHeader({ name: "c", size: 0, typeflag: "0" }));
  chksum[148] = 0x80;
  check("the checksum field is never read as base-256",
    await _code(b.archive.read.tar(b.archive.adapters.buffer(Buffer.concat([chksum, _end()]))).inspect()) !== null);
}

function _oldGnuSparseFields(o) {
  var hdr = Buffer.from(_rawHeader({ name: o.name || "f", size: o.size, typeflag: o.typeflag, gnu: o.gnu !== false }));
  _sparseMap(hdr, 386, o.map || []);
  if (o.extended) hdr[482] = 1;
  if (o.realsize != null) hdr.write(o.realsize, 483, 12, "latin1");
  return _withFieldBytes(hdr, 0, 0, Buffer.alloc(0));
}

async function testOldGnuSparseFieldsOnOtherTypeflags() {
  // GNU tar 1.35 reads the old-GNU sparse map, isextended byte and realsize
  // field only for typeflag S. bsdtar 3.8.10 reads them for every header with
  // the GNU magic: a realsize of 4096 on an 8-byte file gives 4096 bytes, a
  // map of [[100, 8]] puts the data at offset 100, and a map with isextended
  // set is refused as a malformed sparse map. GNU tar writes the 8 stored
  // bytes in every case.
  var body = _pad512(Buffer.from("ABCDEFGH", "ascii"));
  var after = _gnuFile("after", "x");
  var shapes = [
    { label: "a realsize field", fields: { realsize: _oct(4096, 11) + "\0" } },
    { label: "a realsize field of ASCII zeros", fields: { realsize: _oct(0, 11) + "\0" } },
    { label: "a sparse map and realsize", fields: { map: [[100, 8]], realsize: _oct(108, 11) + "\0" } },
    { label: "a split sparse map", fields: { map: [[0, 4], [100, 4]], realsize: _oct(104, 11) + "\0" } },
    { label: "a sparse map with isextended set", fields: { map: [[0, 8]], extended: true } },
  ];
  var typeflags = [["0", "0"], [null, "NUL"], ["7", "7"]];
  for (var t = 0; t < typeflags.length; t += 1) {
    for (var s = 0; s < shapes.length; s += 1) {
      var label = "typeflag " + typeflags[t][1] + " with " + shapes[s].label;
      var tar = Buffer.concat([_oldGnuSparseFields(Object.assign({ size: 8, typeflag: typeflags[t][0] }, shapes[s].fields)),
        body, after, _end()]);
      var listed = await b.archive.read.tar(b.archive.adapters.buffer(tar)).inspect()
        .catch(function (e) { return e.code; });
      var shape = Array.isArray(listed) ? listed.map(function (e) { return e.name + ":" + e.entryType; }).join(",") : listed;
      check(label + ": inspect lists the entry as unknown and keeps the next entry (got " + shape + ")",
        shape === "f:unknown,after:file");
      var iterCode = await _iterCode(b.archive.read.tar(b.archive.adapters.buffer(tar)).extractEntries());
      check(label + ": extractEntries refuses with archive-tar/entry-type-refused (got " + iterCode + ")",
        iterCode === "archive-tar/entry-type-refused");
      var dir = _tmpDir();
      try {
        var extractCode = await _code(b.archive.read.tar(b.archive.adapters.buffer(tar)).extract({ destination: dir }));
        check(label + ": extract refuses with archive-tar/entry-type-refused (got " + extractCode + ")",
          extractCode === "archive-tar/entry-type-refused");
        check(label + ": extract wrote nothing", fs.readdirSync(dir).length === 0);
      } finally {
        fs.rmSync(dir, { recursive: true, force: true });
      }
    }
  }
  var dirShape = await _inspectNames([_oldGnuSparseFields({ name: "d/", size: 0, typeflag: "5",
    realsize: _oct(4096, 11) + "\0" })]);
  check("a directory header with a realsize field is listed as unknown",
    dirShape.length === 1 && dirShape[0].entryType === "unknown");

  var controls = [
    { label: "a GNU regular file with no sparse fields", fields: {} },
    { label: "a ustar-magic file with a realsize field", fields: { gnu: false, realsize: _oct(4096, 11) + "\0" } },
  ];
  for (var c = 0; c < controls.length; c += 1) {
    var ctl = Buffer.concat([_oldGnuSparseFields(Object.assign({ size: 8, typeflag: "0" }, controls[c].fields)),
      body, after, _end()]);
    var out = await _collectEntries(b.archive.read.tar(b.archive.adapters.buffer(ctl)).extractEntries())
      .catch(function (e) { return e.code; });
    check(controls[c].label + ": extractEntries yields the 8 stored bytes (got " + JSON.stringify(out) + ")",
      Array.isArray(out) && out.length === 2 && out[0].bytes.toString("ascii") === "ABCDEFGH");
  }
}

async function testNumericFieldBytesAfterTerminatorRefused() {
  // GNU tar 1.35 stops a numeric field at its first space or NUL and reads
  // "0 0000000052" as size 0; bsdtar 3.8.10 and Python tarfile refuse the
  // archive. The reader refuses any byte other than a space or NUL after
  // the terminator.
  var inner = _ustarFile(HIDDEN_NAME, "#!/bin/sh\necho pwned\n");
  var refused = [
    { label: "a size with digits after a space", field: { offset: 124, width: 12, text: "0 0000000052" } },
    { label: "a size with digits after a NUL", field: { offset: 124, width: 12, text: "0\u000000000052\u0000" } },
    { label: "a mode with a letter after a space", field: { offset: 100, width: 8, text: "000644 x" } },
    { label: "an mtime with digits after a NUL", field: { offset: 136, width: 12, text: "0000000001\u00007" } },
    { label: "a uid with digits after a space", field: { offset: 108, width: 8, text: "00 00001" } },
  ];
  for (var i = 0; i < refused.length; i += 1) {
    await _assertRefusedEverywhere(refused[i].label, Buffer.concat([
      _headerRawField({ name: "f", size: 0, typeflag: "0", rawFields: [refused[i].field] }), inner, _end()]),
    "archive-tar/bad-octal");
  }
  var accepted = [
    { label: "a mode ending in a space and a NUL", field: { offset: 100, width: 8, text: "000644 \u0000" }, mode: 0o644 },
    { label: "a mode ending in two spaces", field: { offset: 100, width: 8, text: "00644  " }, mode: 0o644 },
    { label: "a mode ending in NULs", field: { offset: 100, width: 8, text: "644\u0000\u0000\u0000\u0000\u0000" },
      mode: 0o644 },
  ];
  for (var a = 0; a < accepted.length; a += 1) {
    var e = await _inspectNames([_headerRawField({ name: "f", size: 0, typeflag: "0", rawFields: [accepted[a].field] })])
      .catch(function (err) { return err.code; });
    check(accepted[a].label + " is read (got " + JSON.stringify(e) + ")",
      Array.isArray(e) && e.length === 1 && e[0].mode === accepted[a].mode);
  }
}

async function testV7HeadersRefused() {
  // GNU tar 1.35 --format=v7 and bsdtar 3.8.10 --format=v7 write headers
  // with an all-zero magic field. The reader refuses them.
  var v7 = _rawHeader({ name: "v7.txt", size: 0, typeflag: "0", badMagic: true });
  check("a V7 header with no magic is refused with archive-tar/bad-magic",
    await _code(b.archive.read.tar(b.archive.adapters.buffer(Buffer.concat([v7, _end()]))).inspect()) ===
      "archive-tar/bad-magic");
}

async function run() {
  await testOldGnuSparseFieldsOnOtherTypeflags();
  await testNumericFieldBytesAfterTerminatorRefused();
  await testV7HeadersRefused();
  await testPaxKeySpellingsRefusedWhereToolsDisagree();
  await testPaxNameValuesWithNulRefused();
  await testPaxKeySpellingsToolsAgreeOn();
  await testStarSparseKeysAreSparse();
  await testMagicMustBeUstarOrGnu();
  await testBase256NumericFieldsFromRealTools();
  await testBase256NumericFieldsDecodedAndBounded();
  await testGnuSparseExtensionBlocks();
  await testNonFileEntryWithSizeRefused();
  await testLinksAndDirectoriesFromRealTools();
  await testPaxSizeValueValidated();
  await testLoneZeroBlockEndsArchive();
  await testNamesMustBeUtf8();
  await testNonAsciiNamesFromRealTools();
  await testPaxRecordsCountBytes();
  await testRedundantExtendedHeadersRefused();
  await testGnuVolumeLabelFromRealGnuTar();
  await testPaxGlobalHeaderAttributes();
  await testPaxSparseNameFromRealGnuTar();
  await testPaxSparseNameTraversalReachesGuard();
  await testPaxSparseNameShapes();
  await testSolarisExtendedHeaderApplied();
  await testGnuLongNameAndLinkFromRealTools();
  await testGnuLongNameTraversalReachesGuard();
  await testGnuLongLinkEscapeReachesGuard();
  await testGnuLongRecordMalformedRefused();
  await testGnuLongRecordBounds();
  await testGnuLongRecordAcceptedShapes();
  await testUnknownTypeflagsRefusedOnExtract();
  await testSolarisAclHeader();
  await testGnuHeaderIgnoresPrefixField();
  testBadAdapterRejected();
  await testEmptyArchiveInspect();
  await testInspectClassifiesEveryTypeflag();
  await testInspectRealBuilderRoundTrip();
  await testTrustedStreamAdapter();
  await testNullSizeRandomAccessResolvesSize();
  await testRandomAccessSourceTooLarge();
  await testPaxExtendedOverrides();
  await testPaxMalformedRecordsRefused();
  await testPaxMalformedSizeRefused();
  await testPaxBodyRespectsPerEntryCap();
  await testPaxBodyTruncatedRefused();
  await testTooManyEntriesRefused();
  await testEntryTooLargeRefused();
  await testTruncatedEntryRefused();
  await testBadChecksumRefused();
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
  await testLeadingSpaceMetadataFieldsParsed();
  await testLeadingSpaceSizeFieldNoWalkerDesync();
  await testReaderRefusesNonOctalNumericField();
  testWriteSideFieldOverflows();
  testAddFileNameValidation();
  await testAddFileNameNormalization();
  await testLongNameUstarPrefixSplitRoundTrip();
  await testLongNamePaxPathRoundTrip();
  await testToAdapterContractAndRoundTrip();
  await testToStreamRoundTrip();
  await testToGzipEmitsGzip();
  testDigestIsSha3_512Hex();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
