// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
// SMOKE_RUN_SOLO: growth checks here compare wall-clock time across name shapes and sizes, which a CPU shared with the smoke pool distorts.
"use strict";
/**
 * guard-archive — archive content-safety primitive (b.guardArchive).
 *
 * Covers: surface; registry parity; zip-slip path traversal; absolute-
 * path entries; symlink + hardlink escape; symlink + hardlink reject
 * policies; compression-ratio bombs (per-entry + aggregate); total-size
 * + entry-count + per-entry-size caps; nested-archive detection;
 * duplicate-entry-name; case-insensitive collision; encryption-claim
 * mismatch; sparse entries; magic-byte detection (zip / gzip / bzip2 /
 * xz / 7z / rar / tar); checkExtractionPath helper; gate decision
 * shapes; profile + posture vocabulary.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function testGuardArchiveSurface() {
  check("guardArchive is an object",                 typeof b.guardArchive === "object");
  check("guardArchive.NAME === 'archive'",           b.guardArchive.NAME === "archive");
  check("guardArchive.MIME_TYPES has application/zip",
        b.guardArchive.MIME_TYPES.indexOf("application/zip") !== -1);
  check("guardArchive.EXTENSIONS has .zip",          b.guardArchive.EXTENSIONS.indexOf(".zip") !== -1);
  check("guardArchive.PROFILES has strict",          !!b.guardArchive.PROFILES["strict"]);
  check("guardArchive.PROFILES has balanced",        !!b.guardArchive.PROFILES["balanced"]);
  check("guardArchive.PROFILES has permissive",      !!b.guardArchive.PROFILES["permissive"]);
  check("guardArchive.COMPLIANCE_POSTURES has hipaa", !!b.guardArchive.COMPLIANCE_POSTURES["hipaa"]);
  check("guardArchive.validateEntries is a function", typeof b.guardArchive.validateEntries === "function");
  check("guardArchive.inspectMagic is a function",    typeof b.guardArchive.inspectMagic === "function");
  check("guardArchive.checkExtractionPath is a function",
        typeof b.guardArchive.checkExtractionPath === "function");
  check("guardArchive.gate is a function",           typeof b.guardArchive.gate === "function");
  check("guardArchive.GuardArchiveError is a function",
        typeof b.guardArchive.GuardArchiveError === "function");
  check("frameworkError.GuardArchiveError exposed",
        typeof b.frameworkError.GuardArchiveError === "function");
}

function testGuardArchiveRegistryParity() {
  check("guardArchive registered in guardAll",
        b.guardAll.list().some(function (g) { return g.name === "archive"; }));
  var entry = b.guardAll.list().filter(function (g) { return g.name === "archive"; })[0];
  b.guardAll.SHARED_PROFILES.forEach(function (p) {
    check("registry: archive supports shared profile " + p,
          entry.profiles.indexOf(p) !== -1);
  });
  b.guardAll.SHARED_POSTURES.forEach(function (p) {
    check("registry: archive supports shared posture " + p,
          entry.postures.indexOf(p) !== -1);
  });
}

function testGuardArchiveZipSlip() {
  var inputs = ["../etc/passwd", "../../boot.ini", "subdir/../../etc/shadow"];
  for (var i = 0; i < inputs.length; i++) {
    var rv = b.guardArchive.validateEntries(
      [{ name: inputs[i], size: 100, compressedSize: 50 }],
      { profile: "strict" });
    check("zip slip detected: " + JSON.stringify(inputs[i]),
          rv.ok === false &&
          rv.issues.some(function (issue) { return issue.kind === "zip-slip"; }));
  }
}

function testGuardArchiveAbsolutePath() {
  var inputs = ["/etc/passwd", "\\windows\\system32\\config\\sam", "C:\\evil.exe"];
  for (var i = 0; i < inputs.length; i++) {
    var rv = b.guardArchive.validateEntries(
      [{ name: inputs[i], size: 100, compressedSize: 50 }],
      { profile: "strict" });
    check("absolute path detected: " + JSON.stringify(inputs[i]),
          rv.issues.some(function (issue) { return issue.kind === "absolute-path"; }));
  }
}

function testGuardArchiveSymlinkRejectStrict() {
  var rv = b.guardArchive.validateEntries(
    [{ name: "link", size: 0, isSymlink: true, linkTarget: "target" }],
    { profile: "strict" });
  check("symlink rejected under strict",
        rv.issues.some(function (issue) { return issue.kind === "symlink-reject"; }));
}

function testGuardArchiveSymlinkEscape() {
  var rv = b.guardArchive.validateEntries(
    [{ name: "link", size: 0, isSymlink: true, linkTarget: "../etc/passwd" }],
    { profile: "balanced" });
  check("symlink escape detected (balanced)",
        rv.issues.some(function (issue) { return issue.kind === "symlink-escape"; }));

  var rv2 = b.guardArchive.validateEntries(
    [{ name: "link", size: 0, isSymlink: true, linkTarget: "/etc/shadow" }],
    { profile: "balanced" });
  check("symlink-absolute escape detected (balanced)",
        rv2.issues.some(function (issue) { return issue.kind === "symlink-escape"; }));
}

function testGuardArchiveHardlinkEscape() {
  var rv = b.guardArchive.validateEntries(
    [{ name: "link", size: 0, isHardlink: true, linkTarget: "target" }],
    { profile: "strict" });
  check("hardlink rejected under strict",
        rv.issues.some(function (issue) { return issue.kind === "hardlink-reject"; }));

  var rv2 = b.guardArchive.validateEntries(
    [{ name: "link", size: 0, isHardlink: true, linkTarget: "../etc/passwd" }],
    { profile: "permissive" });
  check("hardlink escape detected (permissive — CVE-2026-26960 class)",
        rv2.issues.some(function (issue) { return issue.kind === "hardlink-escape"; }));
}

function testGuardArchiveCompressionRatioBomb() {
  // Single-entry 1 GB / 1 KB = 1,000,000:1 ratio.
  var rv = b.guardArchive.validateEntries(
    [{ name: "bomb.txt", size: 1000000000, compressedSize: 1024 }],
    { profile: "strict" });
  check("compression-ratio bomb detected",
        rv.issues.some(function (issue) { return issue.kind === "compression-ratio-bomb"; }));
}

function testGuardArchiveAggregateRatioBomb() {
  // Many small entries that aggregate to a large ratio. Set sizes to
  // stay under per-entry caps but blow the aggregate.
  var entries = [];
  for (var i = 0; i < 50; i++) {
    entries.push({
      name: "f" + i + ".txt",
      size: 1000000,        // 1 MB each = 50 MB total
      compressedSize: 100,  // 100 bytes each = 5 KB total
    });
  }
  var rv = b.guardArchive.validateEntries(entries, { profile: "strict" });
  check("aggregate-ratio bomb detected",
        rv.issues.some(function (issue) { return issue.kind === "aggregate-ratio-bomb"; }));
}

function testGuardArchiveTotalSizeCap() {
  var entries = [];
  for (var i = 0; i < 5; i++) {
    entries.push({ name: "f" + i, size: 30000000, compressedSize: 10000000 });
  }
  // Strict cap is 100 MiB; 5 × 30 MB = 150 MB exceeds.
  var rv = b.guardArchive.validateEntries(entries, { profile: "strict" });
  check("total-size cap detected",
        rv.issues.some(function (issue) { return issue.kind === "total-size-cap"; }));
}

function testGuardArchiveEntryCountCap() {
  var entries = [];
  for (var i = 0; i < 200; i++) {
    entries.push({ name: "f" + i + ".txt", size: 1, compressedSize: 1 });
  }
  // Strict cap is 100 entries.
  var rv = b.guardArchive.validateEntries(entries, { profile: "strict" });
  check("entry-count cap detected",
        rv.issues.some(function (issue) { return issue.kind === "entry-count-cap"; }));
}

function testGuardArchiveNestedArchive() {
  var rv = b.guardArchive.validateEntries(
    [{ name: "inner.zip", size: 1000, compressedSize: 500 }],
    { profile: "strict" });
  check("nested archive detected (strict, maxNestedDepth=0)",
        rv.issues.some(function (issue) { return issue.kind === "nested-archive"; }));

  var rv2 = b.guardArchive.validateEntries(
    [{ name: "inner.tar.gz", size: 1000, compressedSize: 500 }],
    { profile: "strict" });
  check("nested .tar.gz detected",
        rv2.issues.some(function (issue) { return issue.kind === "nested-archive"; }));
}

function testGuardArchiveDuplicateNames() {
  var rv = b.guardArchive.validateEntries([
    { name: "config.json", size: 100, compressedSize: 50 },
    { name: "config.json", size: 200, compressedSize: 100 },
  ], { profile: "strict" });
  check("duplicate-entry-name detected",
        rv.issues.some(function (issue) { return issue.kind === "duplicate-entry-name"; }));
}

function testGuardArchiveCaseInsensitiveCollision() {
  var rv = b.guardArchive.validateEntries([
    { name: "README.txt", size: 100, compressedSize: 50 },
    { name: "readme.txt", size: 100, compressedSize: 50 },
  ], { profile: "strict" });
  check("case-insensitive collision detected (strict)",
        rv.issues.some(function (issue) { return issue.kind === "case-insensitive-collision"; }));
}

var NFC_NAME = "café.txt";
var NFD_NAME = "café.txt";

function _ruleIds(rv) {
  return rv.issues.map(function (issue) { return issue.severity + ":" + issue.ruleId; });
}

async function testGuardArchiveNfcEqualNames() {
  var direct = b.guardArchive.validateEntries([
    { name: NFC_NAME, size: 1, compressedSize: 1 },
    { name: NFD_NAME, size: 1, compressedSize: 1 },
  ], { profile: "strict" });
  check("NFC-equal names are a critical duplicate (validateEntries)",
        _ruleIds(direct).indexOf("critical:archive.duplicate-name") !== -1, JSON.stringify(_ruleIds(direct)));

  var balanced = b.guardArchive.validateEntries([
    { name: "docs/" + NFD_NAME, size: 1, compressedSize: 1 },
    { name: "docs/" + NFC_NAME, size: 1, compressedSize: 1 },
  ], { profile: "balanced" });
  check("NFC-equal names are a critical duplicate in either order (balanced)",
        _ruleIds(balanced).indexOf("critical:archive.duplicate-name") !== -1, JSON.stringify(_ruleIds(balanced)));

  var folded = b.guardArchive.validateEntries([
    { name: "CAFÉ.txt", size: 1, compressedSize: 1 },
    { name: NFD_NAME, size: 1, compressedSize: 1 },
  ], { profile: "strict" });
  check("names equal after NFC and case folding draw a case collision",
        _ruleIds(folded).indexOf("high:archive.case-collision") !== -1, JSON.stringify(_ruleIds(folded)));

  var distinct = b.guardArchive.validateEntries([
    { name: NFC_NAME, size: 1, compressedSize: 1 },
    { name: "cafe.txt", size: 1, compressedSize: 1 },
  ], { profile: "strict" });
  check("names that differ after NFC draw no duplicate or collision",
        !distinct.issues.some(function (issue) {
          return issue.ruleId === "archive.duplicate-name" || issue.ruleId === "archive.case-collision";
        }), JSON.stringify(_ruleIds(distinct)));

  var z = b.archive.zip();
  z.addFile(NFC_NAME, "ONE\n");
  z.addFile(NFD_NAME, "TWO\n");
  var zipBytes = z.toBuffer();
  var zipGuarded = await b.guardArchive.inspect(b.archive.adapters.buffer(zipBytes), { profile: "strict" });
  check("NFC-equal zip entry names are a critical duplicate (b.guardArchive.inspect)",
        _ruleIds(zipGuarded).indexOf("critical:archive.duplicate-name") !== -1, JSON.stringify(_ruleIds(zipGuarded)));
  var zipErr = null;
  try {
    for await (var ze of b.archive.read.zip(b.archive.adapters.buffer(zipBytes)).extractEntries()) { void ze; }
  } catch (e) { zipErr = e; }
  check("NFC-equal zip entry names are refused by extractEntries()",
        zipErr && zipErr.code === "archive-read/guard-refused", String(zipErr && (zipErr.code || zipErr.message)));

  var t = b.archive.tar();
  t.addFile(NFC_NAME, "ONE\n");
  t.addFile(NFD_NAME, "TWO\n");
  var tarErr = null;
  try {
    for await (var te of b.archive.read.tar(b.archive.adapters.buffer(t.toBuffer())).extractEntries()) { void te; }
  } catch (e) { tarErr = e; }
  check("NFC-equal tar entry names are refused by extractEntries()",
        tarErr && tarErr.code === "archive-tar/guard-refused", String(tarErr && (tarErr.code || tarErr.message)));
}

function _validated(names, profile) {
  return b.guardArchive.validateEntries(names.map(function (n) {
    return { name: n, size: 1, compressedSize: 1, isDirectory: n.charAt(n.length - 1) === "/" };
  }), { profile: profile || "strict" });
}

function testGuardArchiveBackslashEqualNames() {
  var pairs = [["d/a.txt", "d\\a.txt"], ["d\\a.txt", "d/a.txt"], ["a\\b\\c.txt", "a/b\\c.txt"]];
  for (var p = 0; p < pairs.length; p += 1) {
    var rv = _validated(pairs[p], "balanced");
    check("names equal once a backslash reads as a separator are a critical duplicate: " + JSON.stringify(pairs[p]),
          _ruleIds(rv).indexOf("critical:archive.duplicate-name") !== -1, JSON.stringify(_ruleIds(rv)));
  }
  var folded = _validated(["D\\A.txt", "d/a.txt"]);
  check("names equal after reading a backslash as a separator and case folding draw a case collision",
        _ruleIds(folded).indexOf("high:archive.case-collision") !== -1, JSON.stringify(_ruleIds(folded)));
  var distinct = _validated(["d/a.txt", "d\\b.txt"]);
  check("names that still differ after reading a backslash as a separator draw no duplicate or collision",
        !distinct.issues.some(function (issue) {
          return issue.ruleId === "archive.duplicate-name" || issue.ruleId === "archive.case-collision";
        }), JSON.stringify(_ruleIds(distinct)));
}

function _segmentEdgeIssues(name) {
  return _validated([name], "balanced").issues.filter(function (issue) {
    return issue.ruleId === "archive.filename.leading-trailing";
  });
}

function testGuardArchiveSegmentLeadingTrailing() {
  var hits = ["dir./a.txt", "dir /a.txt", "a/ b/c.txt", "a/b./c/d.txt", "dir./", "dir.\\a.txt", "a\\ b\\c.txt"];
  for (var h = 0; h < hits.length; h += 1) {
    var issues = _segmentEdgeIssues(hits[h]);
    check("a path segment with a trailing dot or a leading/trailing space draws archive.filename.leading-trailing: " +
          JSON.stringify(hits[h]), issues.length === 1, JSON.stringify(issues));
  }
  var misses = ["docs/readme.txt", "docs/", "./docs/a.txt", ".hidden/a.txt", "a/.b/c.txt", "my docs/a b.txt"];
  for (var m = 0; m < misses.length; m += 1) {
    var none = _segmentEdgeIssues(misses[m]);
    check("a path with no edge-dot or edge-space segment draws no leading-trailing issue: " +
          JSON.stringify(misses[m]), none.length === 0, JSON.stringify(none));
  }
  var whole = _segmentEdgeIssues("a/b.txt.");
  check("a trailing dot on the last segment is reported once", whole.length === 1, JSON.stringify(whole));
}

async function _extractEntriesCode(kind, names) {
  var w = kind === "zip" ? b.archive.zip() : b.archive.tar();
  for (var n = 0; n < names.length; n += 1) w.addFile(names[n], "ENTRY" + n + "\n");
  var reader = b.archive.read[kind](b.archive.adapters.buffer(w.toBuffer()));
  try {
    for await (var ent of reader.extractEntries()) { void ent; }
  } catch (e) { return e.code || e.message; }
  return "ok";
}

async function testGuardArchiveDotSegmentEqualNames() {
  var pairs = [
    ["d/a.txt", "d/./a.txt"], ["d/a.txt", "d//a.txt"], ["d/a.txt", "./d/a.txt"],
    ["./d/a.txt", "d/./a.txt"], ["d\\.\\a.txt", "d/a.txt"], ["d/a.txt", ".//d/.//a.txt"],
  ];
  for (var p = 0; p < pairs.length; p += 1) {
    var rv = _validated(pairs[p], "balanced");
    check("names equal once '.' segments and empty segments are dropped are a critical duplicate: " +
          JSON.stringify(pairs[p]),
          _ruleIds(rv).indexOf("critical:archive.duplicate-name") !== -1, JSON.stringify(_ruleIds(rv)));
  }
  var folded = _validated(["D/./A.txt", "d/a.txt"]);
  check("names equal after dropping '.' segments and case folding draw a case collision",
        _ruleIds(folded).indexOf("high:archive.case-collision") !== -1, JSON.stringify(_ruleIds(folded)));
  var controls = [["a/b.txt", "a/c.txt"], ["d/", "d/a.txt"], ["d", "d/"], ["./", "./d/", "./d/a.txt"]];
  for (var c = 0; c < controls.length; c += 1) {
    var ok = _validated(controls[c], "balanced");
    check("names that still differ after dropping '.' and empty segments draw no duplicate or collision: " +
          JSON.stringify(controls[c]),
          !ok.issues.some(function (issue) {
            return issue.ruleId === "archive.duplicate-name" || issue.ruleId === "archive.case-collision";
          }), JSON.stringify(_ruleIds(ok)));
  }
  var shapes = [["d/a.txt", "d/./a.txt"], ["d/a.txt", "d//a.txt"], ["d/a.txt", "./d/a.txt"]];
  for (var s = 0; s < shapes.length; s += 1) {
    var zipCode = await _extractEntriesCode("zip", shapes[s]);
    check("zip extractEntries() refuses names equal once '.' and empty segments are dropped: " +
          JSON.stringify(shapes[s]), zipCode === "archive-read/guard-refused", zipCode);
    var tarCode = await _extractEntriesCode("tar", shapes[s]);
    check("tar extractEntries() refuses names equal once '.' and empty segments are dropped: " +
          JSON.stringify(shapes[s]), tarCode === "archive-tar/guard-refused", tarCode);
  }
  var ctlZip = await _extractEntriesCode("zip", ["a/b.txt", "a/c.txt"]);
  check("zip extractEntries() yields two distinct names", ctlZip === "ok", ctlZip);
  var ctlTar = await _extractEntriesCode("tar", ["a/b.txt", "a/c.txt"]);
  check("tar extractEntries() yields two distinct names", ctlTar === "ok", ctlTar);
}

function _reservedIssues(name) {
  return _validated([name], "balanced").issues.filter(function (issue) {
    return issue.ruleId === "archive.filename.reserved-name";
  });
}

// A deployment that only extracts on Linux opts out of the Windows device-name
// check with reservedNamePolicy, as b.guardFilename does; the Linux kernel tree
// carries drivers/.../i2c/aux.c.
// Allowing exact duplicates must not switch off a case-collision rejection the
// caller configured: a duplicate name hides the collision only when it is
// reported itself.
function testCaseCollisionPolicyIndependentOfDuplicatePolicy() {
  var entries = [{ name: "readme.txt", size: 1 }, { name: "readme.txt", size: 1, altNames: ["README.txt"] }];
  var rv = b.guardArchive.validateEntries(entries,
    { duplicateNamePolicy: "allow", caseInsensitiveCollisionPolicy: "reject" });
  var kinds = rv.issues.map(function (i) { return i.ruleId; });
  check("duplicateNamePolicy allow does not hide a case collision rejected by caseInsensitiveCollisionPolicy",
        kinds.indexOf("archive.case-collision") !== -1 && kinds.indexOf("archive.duplicate-name") === -1,
        JSON.stringify(kinds));
  var both = b.guardArchive.validateEntries(entries,
    { duplicateNamePolicy: "reject", caseInsensitiveCollisionPolicy: "reject" }).issues
    .map(function (i) { return i.ruleId; });
  check("control: with both policies on, the duplicate is reported once and hides the case collision",
        both.filter(function (k) { return k === "archive.duplicate-name"; }).length === 1 &&
        both.indexOf("archive.case-collision") === -1, JSON.stringify(both));
}

function testGuardArchiveReservedNamePolicy() {
  var entries = [{ name: "linux/drivers/i2c/aux.c", size: 1 }, { name: "linux/drivers/i2c/bus.c", size: 1 }];
  function reservedKinds(opts) {
    return b.guardArchive.validateEntries(entries, opts).issues
      .filter(function (i) { return i.kind === "reserved-name"; })
      .map(function (i) { return i.severity; });
  }
  check("reservedNamePolicy default: aux.c in a path draws a critical reserved-name issue",
        reservedKinds({}).join(",") === "critical", reservedKinds({}).join(","));
  check("reservedNamePolicy allow: aux.c draws no reserved-name issue",
        reservedKinds({ reservedNamePolicy: "allow" }).length === 0, reservedKinds({ reservedNamePolicy: "allow" }).join(","));
  check("reservedNamePolicy audit: aux.c draws a warn-level reserved-name issue",
        reservedKinds({ reservedNamePolicy: "audit" }).join(",") === "warn", reservedKinds({ reservedNamePolicy: "audit" }).join(","));
  var threw = null;
  try { b.guardArchive.validateEntries(entries, { reservedNamePolicy: "nope" }); } catch (e) { threw = e.code; }
  check("reservedNamePolicy: an unknown value is refused with archive/bad-opt", threw === "archive/bad-opt", threw);
}

async function testGuardArchiveSegmentReservedName() {
  var hits = ["a/CON", "CON/a.txt", "a/aux.txt", "a/Lpt9.log/b.txt", "a\\nul\\b.txt", "COM1/",
              "x/y/prn.tar.gz.txt", "a/com¹.txt", "CON"];
  for (var h = 0; h < hits.length; h += 1) {
    var issues = _reservedIssues(hits[h]);
    check("a Windows reserved device name in any path segment draws one critical archive.filename.reserved-name: " +
          JSON.stringify(hits[h]),
          issues.length === 1 && issues[0].severity === "critical", JSON.stringify(issues));
  }
  var misses = ["a/CONX/b.txt", "a/console.txt", "a/xcon/b.txt", "docs/aux_data.txt", "a/com0.txt",
                "a/lpt10.txt", "com/lpt/a.txt", "a/.con/b.txt"];
  for (var m = 0; m < misses.length; m += 1) {
    var none = _reservedIssues(misses[m]);
    check("a path with no reserved device name segment draws no reserved-name issue: " + JSON.stringify(misses[m]),
          none.length === 0, JSON.stringify(none));
  }
  var shapes = ["a/CON", "CON/a.txt", "a/aux.txt"];
  for (var s = 0; s < shapes.length; s += 1) {
    var guarded = await b.guardArchive.inspect(b.archive.adapters.buffer((function () {
      var z = b.archive.zip();
      z.addFile(shapes[s], "X\n");
      return z.toBuffer();
    })()), { profile: "strict" });
    check("b.guardArchive.inspect reports a reserved device name segment: " + JSON.stringify(shapes[s]),
          _ruleIds(guarded).indexOf("critical:archive.filename.reserved-name") !== -1,
          JSON.stringify(_ruleIds(guarded)));
    var zipCode = await _extractEntriesCode("zip", [shapes[s]]);
    check("zip extractEntries() refuses a reserved device name segment, as b.safeArchive.extract does: " +
          JSON.stringify(shapes[s]), zipCode === "archive-read/guard-refused", zipCode);
  }
}

function _segmentPassEntries(unit, n) {
  return [{ name: unit.repeat(n) + "f.txt", size: 1, compressedSize: 1 }];
}

function testGuardArchiveSegmentPassCost() {
  var shapes = [["a/", "ab"], ["com0/", "comxy"], ["a\\", "ab"]];
  var n = 20000;
  for (var s = 0; s < shapes.length; s += 1) {
    var unit = shapes[s][0];
    var flat = _segmentPassEntries(shapes[s][1], n);
    var segmented = _segmentPassEntries(unit, n);
    var vsFlat = helpers.superlinearRatio(function (which) {
      b.guardArchive.validateEntries(which === "segmented" ? segmented : flat, { profile: "strict" });
    }, { small: "flat", large: "segmented", threshold: 4 });
    check("a name of " + n + " segments " + JSON.stringify(unit) +
          " costs about what a flat name of the same length costs", !vsFlat.superlinear, String(vsFlat.ratio));
    var growth = helpers.superlinearRatio(function (count) {
      b.guardArchive.validateEntries(_segmentPassEntries(unit, count), { profile: "strict" });
    }, { small: n, large: n * 2 });
    check("the per-segment pass grows linearly with segment count: " + JSON.stringify(unit),
          !growth.superlinear, String(growth.ratio));
  }
}

function testGuardArchiveEncryptionMismatch() {
  var rv = b.guardArchive.validateEntries([
    { name: "secret.txt", size: 100, compressedSize: 50, isEncrypted: true },
    { name: "public.txt", size: 100, compressedSize: 50, isEncrypted: false },
  ], { profile: "strict" });
  check("encryption-claim mismatch detected",
        rv.issues.some(function (issue) { return issue.kind === "encryption-claim-mismatch"; }));
}

function testGuardArchiveSparseEntry() {
  var rv = b.guardArchive.validateEntries(
    [{ name: "sparse.bin", size: 1000000, compressedSize: 100,
       attrs: { sparse: true } }],
    { profile: "strict" });
  check("sparse entry detected (strict)",
        rv.issues.some(function (issue) { return issue.kind === "sparse-entry"; }));
}

function testGuardArchiveInspectMagic() {
  // ZIP local file header magic.
  check("inspectMagic: zip detected",
        b.guardArchive.inspectMagic(Buffer.from([0x50, 0x4B, 0x03, 0x04])).format === "zip");
  check("inspectMagic: gzip detected",
        b.guardArchive.inspectMagic(Buffer.from([0x1F, 0x8B])).format === "gzip");
  check("inspectMagic: bzip2 detected",
        b.guardArchive.inspectMagic(Buffer.from([0x42, 0x5A, 0x68])).format === "bzip2");
  check("inspectMagic: xz detected",
        b.guardArchive.inspectMagic(Buffer.from([0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00])).format === "xz");
  check("inspectMagic: 7z detected",
        b.guardArchive.inspectMagic(Buffer.from([0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C])).format === "7z");
  check("inspectMagic: rar4 detected",
        b.guardArchive.inspectMagic(
          Buffer.from([0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00])).format === "rar4");
  check("inspectMagic: zstd detected",
        b.guardArchive.inspectMagic(
          Buffer.from([0x28, 0xB5, 0x2F, 0xFD])).format === "zstd");
  check("inspectMagic: unknown returns null",
        b.guardArchive.inspectMagic(Buffer.from([0xFF, 0xFE, 0xFD, 0xFC])) === null);

  // tar — "ustar" at offset 257 within first 512-byte header.
  var tarBuf = Buffer.alloc(512);
  tarBuf.write("ustar", 257);
  check("inspectMagic: tar via ustar offset detected",
        b.guardArchive.inspectMagic(tarBuf).format === "tar");
}

function testGuardArchiveCheckExtractionPath() {
  check("checkExtractionPath: clean entry returns ok",
        b.guardArchive.checkExtractionPath("safe/file.txt", "/extract").ok === true);
  check("checkExtractionPath: traversal returns false",
        b.guardArchive.checkExtractionPath("../escape", "/extract").ok === false);
  check("checkExtractionPath: absolute path returns false",
        b.guardArchive.checkExtractionPath("/etc/passwd", "/extract").ok === false);
  check("checkExtractionPath: empty name returns false",
        b.guardArchive.checkExtractionPath("", "/extract").ok === false);
  var nb = String.fromCharCode(0);
  check("checkExtractionPath: null byte returns false",
        b.guardArchive.checkExtractionPath("file" + nb + ".txt", "/extract").ok === false);
}

function testGuardArchiveCleanArchive() {
  // Use entry names that avoid the shell-exec-ext warn list (.js / .lnk
  // / .dll / etc. trigger warn-severity issues per guard-filename's
  // executable-extension family). The point of "clean" here is no
  // critical / high severity issues — warns are auditable but don't
  // flip ok=false.
  var rv = b.guardArchive.validateEntries([
    { name: "README.md",    size: 1000,  compressedSize: 500, isDirectory: false },
    { name: "src/main.txt", size: 2000,  compressedSize: 800, isDirectory: false },
    { name: "src/",         size: 0,     compressedSize: 0,   isDirectory: true },
  ], { profile: "strict" });
  var noCritOrHigh = !rv.issues.some(function (i) {
    return i.severity === "critical" || i.severity === "high";
  });
  check("clean archive → ok=true",   rv.ok === true && noCritOrHigh);
}

async function testGuardArchiveGate() {
  var g = b.guardArchive.gate({ profile: "strict" });
  var clean = await g.check({
    entries: [{ name: "safe.txt", size: 100, compressedSize: 50 }],
  });
  check("gate clean → action=serve",
        clean.ok === true && clean.action === "serve");

  var slip = await g.check({
    entries: [{ name: "../etc/passwd", size: 100, compressedSize: 50 }],
  });
  check("gate zip-slip → action=refuse (no safe sanitization for archives)",
        slip.action === "refuse");

  // bytes only, no entries — refuse-no-entry-list path.
  var bytesOnly = await g.check({
    bytes: Buffer.from([0x50, 0x4B, 0x03, 0x04]),
  });
  check("gate: bytes without entries → refuse with no-entry-list issue",
        bytesOnly.action === "refuse" &&
        bytesOnly.issues.some(function (i) { return i.kind === "no-entry-list"; }));
}

function testGuardArchiveCompliancePosture() {
  var hipaa = b.guardArchive.compliancePosture("hipaa");
  check("compliancePosture('hipaa') sets reject policies",
        hipaa.symlinkPolicy === "reject" &&
        hipaa.hardlinkPolicy === "reject" &&
        hipaa.traversalPolicy === "reject");

  var threw = null;
  try { b.guardArchive.compliancePosture("unknown"); }
  catch (e) { threw = e; }
  check("compliancePosture: unknown name throws",
        threw && /unknown/.test(threw.message));
}

function testGuardArchiveBadProfile() {
  var threw = null;
  try { b.guardArchive.validateEntries([], { profile: "made-up" }); }
  catch (e) { threw = e; }
  check("validateEntries: unknown profile throws",
        threw && /unknown profile/i.test(threw.message));
}

// ---- buildProfile — resolve a named profile to its merged caps ----
// The gate-contract ABI (makeProfileBuilder → buildProfile) reads the
// base profile name from `baseProfile` OR `extends` (string or array),
// plus `overrides` / `removes`.
function testGuardArchiveBuildProfile() {
  var strict = b.guardArchive.buildProfile({ baseProfile: "strict" });
  check("buildProfile(strict): maxEntries === 100",       strict.maxEntries === 100);
  check("buildProfile(strict): symlinkPolicy === reject", strict.symlinkPolicy === "reject");
  check("buildProfile(strict): maxCompressionRatio === 100",
        strict.maxCompressionRatio === 100);

  // The documented @example form `{ extends: "strict" }` — a single base
  // as a bare string — resolves the same caps as baseProfile (buildProfile
  // normalizes a string `extends` to a one-element list).
  var strictExt = b.guardArchive.buildProfile({ extends: "strict" });
  check("buildProfile({extends:'strict'}): maxEntries === 100", strictExt.maxEntries === 100);
  check("buildProfile({extends:'strict'}): symlinkPolicy === reject",
        strictExt.symlinkPolicy === "reject");
  var strictExtArr = b.guardArchive.buildProfile({ extends: ["strict"] });
  check("buildProfile({extends:['strict']}): array form resolves the same",
        strictExtArr.maxEntries === 100);

  var perm = b.guardArchive.buildProfile({ baseProfile: "permissive" });
  check("buildProfile(permissive): maxEntries === 100000", perm.maxEntries === 100000);
  check("buildProfile(permissive): symlinkPolicy === audit", perm.symlinkPolicy === "audit");
  check("buildProfile(permissive): maxNestedDepth === 4",  perm.maxNestedDepth === 4);

  // Inline overrides win over the resolved base.
  var custom = b.guardArchive.buildProfile({
    baseProfile: "strict",
    overrides:   { maxEntries: 7 },
  });
  check("buildProfile: overrides win (maxEntries)", custom.maxEntries === 7);
  check("buildProfile: base survives under override (symlinkPolicy)",
        custom.symlinkPolicy === "reject");

  // Unknown profile name throws.
  var threw = null;
  try { b.guardArchive.buildProfile({ baseProfile: "nope" }); }
  catch (e) { threw = e; }
  check("buildProfile: unknown baseProfile throws",
        threw && /unknown profile/i.test(threw.message));

  // An unrecognized key (`profile` — the shape gate() takes, not buildProfile)
  // resolves no base and yields no caps, rather than silently resolving one.
  var byProfileKey = b.guardArchive.buildProfile({ profile: "strict" });
  check("buildProfile: unrecognized `profile` key resolves no caps",
        byProfileKey.maxEntries === undefined);
}

// ---- loadRulePack — register an operator rule pack, id-validated ----
function testGuardArchiveLoadRulePack() {
  var pack = {
    id: "kb-2026-archive",
    extraReservedNames: ["system32"],
    rules: [{ id: "no-windows-system", severity: "critical",
              reason: "entry name targets Windows system directory" }],
  };
  var returned = b.guardArchive.loadRulePack(pack);
  check("loadRulePack: returns the pack unchanged", returned === pack);
  check("loadRulePack: pack.id preserved", returned.id === "kb-2026-archive");

  // Missing pack.id → archive.bad-opt.
  var noId = null;
  try { b.guardArchive.loadRulePack({ rules: [] }); }
  catch (e) { noId = e; }
  check("loadRulePack: missing id throws archive.bad-opt",
        noId && noId.code === "archive/bad-opt");

  // Empty-string id is likewise rejected.
  var emptyId = null;
  try { b.guardArchive.loadRulePack({ id: "" }); }
  catch (e) { emptyId = e; }
  check("loadRulePack: empty id throws archive.bad-opt",
        emptyId && emptyId.code === "archive/bad-opt");

  // Non-object pack throws a GuardArchiveError (proto-safe requireObject).
  var notObj = null;
  try { b.guardArchive.loadRulePack(null); }
  catch (e) { notObj = e; }
  check("loadRulePack: null pack throws GuardArchiveError",
        notObj instanceof b.guardArchive.GuardArchiveError);
}

async function run() {
  testGuardArchiveSurface();
  testGuardArchiveRegistryParity();
  testGuardArchiveZipSlip();
  testGuardArchiveAbsolutePath();
  testGuardArchiveSymlinkRejectStrict();
  testGuardArchiveSymlinkEscape();
  testGuardArchiveHardlinkEscape();
  testGuardArchiveCompressionRatioBomb();
  testGuardArchiveAggregateRatioBomb();
  testGuardArchiveTotalSizeCap();
  testGuardArchiveEntryCountCap();
  testGuardArchiveNestedArchive();
  testGuardArchiveDuplicateNames();
  testGuardArchiveCaseInsensitiveCollision();
  await testGuardArchiveNfcEqualNames();
  testGuardArchiveBackslashEqualNames();
  testGuardArchiveSegmentLeadingTrailing();
  await testGuardArchiveDotSegmentEqualNames();
  await testGuardArchiveSegmentReservedName();
  testGuardArchiveReservedNamePolicy();
  testCaseCollisionPolicyIndependentOfDuplicatePolicy();
  testGuardArchiveSegmentPassCost();
  testGuardArchiveEncryptionMismatch();
  testGuardArchiveSparseEntry();
  testGuardArchiveInspectMagic();
  testGuardArchiveCheckExtractionPath();
  testGuardArchiveCleanArchive();
  testGuardArchiveCompliancePosture();
  testGuardArchiveBadProfile();
  testGuardArchiveBuildProfile();
  testGuardArchiveLoadRulePack();
  await testGuardArchiveGate();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[guard-archive] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
