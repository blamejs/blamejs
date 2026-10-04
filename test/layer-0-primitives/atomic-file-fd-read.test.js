// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.atomicFile.fdSafeReadSync — TOCTOU-safe fd read (CWE-367 /
 * js/file-system-race). The single owner of the open-fd → fstat →
 * read-fully loop that atomic-file / network-tls / vault-seal-pem / backup
 * all route through, with the security guards exposed as opts:
 *
 *   - maxBytes        — refuse a file larger than the cap (post-fstat)
 *   - refuseSymlink   — lstat + refuse a symlink source (no follow)
 *   - inodeCheck      — refuse if the fd inode != the lstat inode (TOCTOU)
 *   - expectedHash    — SHA3-512 the content must match
 *   - encoding        — return a decoded string instead of a Buffer
 *   - allowShortRead  — slice to the bytes read instead of throwing
 *   - errorFor        — map a failure KIND to the caller's typed error
 */

var fs   = require("fs");
var path = require("path");

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function _dir() { return b.testing.tempDir("fdsaferead"); }

function _throws(fn) {
  try { fn(); return null; } catch (e) { return e; }
}

// `allowShortRead` suppresses the short-read refusal, so it loosens a check and
// has to be read strictly. `read` and `readSync` built the descriptor-read
// options without forwarding it, so the option was accepted and then dropped:
// `true` still threw, and a non-boolean reached nothing that could refuse it.
async function testReadForwardsAllowShortRead() {
  var dir = _dir();
  try {
    var p = path.join(dir.path, "forwarded.bin");
    fs.writeFileSync(p, Buffer.from("hello"), { mode: 0o600 });

    var syncBad = _throws(function () {
      return b.atomicFile.readSync(p, { allowShortRead: "nope" });
    });
    check("readSync: a non-boolean allowShortRead is refused",
      syncBad !== null && syncBad.code === "atomic-file/bad-opt",
      "code=" + (syncBad && syncBad.code));

    var asyncBad = null;
    try { await b.atomicFile.read(p, { allowShortRead: "nope" }); }
    catch (e) { asyncBad = e; }
    check("read: a non-boolean allowShortRead is refused",
      asyncBad !== null && asyncBad.code === "atomic-file/bad-opt",
      "code=" + (asyncBad && asyncBad.code));

    // The control: a real boolean is still accepted on both, and omitting the
    // option is unchanged, so the assertions above read the type rather than a
    // call that refuses the option outright.
    check("readSync: allowShortRead true is accepted",
      String(b.atomicFile.readSync(p, { allowShortRead: true, encoding: "utf8" })) === "hello");
    check("read: allowShortRead false is accepted",
      String(await b.atomicFile.read(p, { allowShortRead: false, encoding: "utf8" })) === "hello");
    check("read: omitting it reads the file as before",
      String(await b.atomicFile.read(p, { encoding: "utf8" })) === "hello");
  } finally { dir.cleanup(); }
}

function testReadsBufferAndString() {
  var dir = _dir();
  try {
    var p = path.join(dir.path, "data.bin");
    var payload = Buffer.from("fd-safe payload ✓", "utf8");
    fs.writeFileSync(p, payload, { mode: 0o600 });
    var buf = b.atomicFile.fdSafeReadSync(p);
    check("fdSafeReadSync: returns a Buffer by default", Buffer.isBuffer(buf) && buf.equals(payload));
    var str = b.atomicFile.fdSafeReadSync(p, { encoding: "utf8" });
    check("fdSafeReadSync: encoding returns a string", str === payload.toString("utf8"));
  } finally { dir.cleanup(); }
}

function testWithStat() {
  // #341: withStat returns the bound fd's fstat alongside the bytes, so the
  // mode/owner describe the exact inode read (TOCTOU-free), not a re-stat.
  var dir = _dir();
  try {
    var p = path.join(dir.path, "secret.bin");
    var payload = Buffer.from("with-stat payload", "utf8");
    fs.writeFileSync(p, payload, { mode: 0o600 });
    var r = b.atomicFile.fdSafeReadSync(p, { withStat: true });
    check("fdSafeReadSync withStat: returns { bytes, stat }",
          r && Buffer.isBuffer(r.bytes) && r.bytes.equals(payload) && r.stat && typeof r.stat === "object");
    check("fdSafeReadSync withStat: stat.size matches bytes", r.stat.size === payload.length);
    check("fdSafeReadSync withStat: stat carries mode + ino",
          typeof r.stat.mode === "number" && typeof r.stat.ino === "number");
    // The mode is the bound fd's — on POSIX a 0o600 secret has no group/other
    // bits. Windows doesn't enforce Unix permission bits, so gate the assertion.
    if (process.platform !== "win32") {
      check("fdSafeReadSync withStat: mode reflects 0o600 (no group/other)", (r.stat.mode & 0o077) === 0);
    }
    // withStat composes with encoding: bytes is the decoded string.
    var rEnc = b.atomicFile.fdSafeReadSync(p, { withStat: true, encoding: "utf8" });
    check("fdSafeReadSync withStat + encoding: bytes is a string",
          rEnc.bytes === payload.toString("utf8") && rEnc.stat.size === payload.length);
    // Without withStat, the bare value is still returned (back-compat).
    var bare = b.atomicFile.fdSafeReadSync(p);
    check("fdSafeReadSync: default still returns the bare Buffer", Buffer.isBuffer(bare));
  } finally { dir.cleanup(); }
}

function testMaxBytesCap() {
  var dir = _dir();
  try {
    var p = path.join(dir.path, "big.bin");
    fs.writeFileSync(p, Buffer.alloc(2048), { mode: 0o600 });
    var e = _throws(function () { b.atomicFile.fdSafeReadSync(p, { maxBytes: 1024 }); });
    check("fdSafeReadSync: maxBytes refuses an over-cap file",
          e !== null && /too-large|maxBytes/i.test(e.code + " " + e.message));
    // Under the cap reads fine.
    var ok = b.atomicFile.fdSafeReadSync(p, { maxBytes: 4096 });
    check("fdSafeReadSync: under the cap reads fine", ok.length === 2048);
  } finally { dir.cleanup(); }
}

function testExpectedHash() {
  var dir = _dir();
  try {
    var p = path.join(dir.path, "hashed.bin");
    fs.writeFileSync(p, Buffer.from("integrity"), { mode: 0o600 });
    var e = _throws(function () {
      b.atomicFile.fdSafeReadSync(p, { expectedHash: "0".repeat(128) });
    });
    check("fdSafeReadSync: wrong expectedHash refuses (integrity)",
          e !== null && /integrity/i.test(e.code + " " + e.message));
  } finally { dir.cleanup(); }
}

function testEnoent() {
  var dir = _dir();
  try {
    var missing = path.join(dir.path, "nope.bin");
    // Default errorFor → AtomicFileError; an errorFor returning undefined
    // rethrows the raw ENOENT (the network-tls / vault / backup posture).
    var eDefault = _throws(function () { b.atomicFile.fdSafeReadSync(missing); });
    check("fdSafeReadSync: missing file (default errorFor) throws a typed atomic-file error",
          eDefault !== null && eDefault.code === "atomic-file/enoent");
    var eRaw = _throws(function () {
      b.atomicFile.fdSafeReadSync(missing, { errorFor: function () { return undefined; } });
    });
    check("fdSafeReadSync: errorFor undefined rethrows raw ENOENT",
          eRaw !== null && eRaw.code === "ENOENT");
  } finally { dir.cleanup(); }
}

function testErrorForCustomError() {
  var dir = _dir();
  try {
    var p = path.join(dir.path, "big2.bin");
    fs.writeFileSync(p, Buffer.alloc(4096), { mode: 0o600 });
    function Tagged(msg) { this.message = msg; this.tag = "custom-too-large"; }
    var e = _throws(function () {
      b.atomicFile.fdSafeReadSync(p, {
        maxBytes: 16,
        errorFor: function (kind) { return kind === "too-large" ? new Tagged("over cap") : undefined; },
      });
    });
    check("fdSafeReadSync: errorFor maps a kind to the caller's typed error",
          e !== null && e.tag === "custom-too-large");
  } finally { dir.cleanup(); }
}

function testRefuseSymlinkAndInodeHappyPath() {
  var dir = _dir();
  try {
    var p = path.join(dir.path, "real.pem");
    fs.writeFileSync(p, Buffer.from("PEM"), { mode: 0o600 });
    // refuseSymlink + inodeCheck on a regular file reads fine (the vault posture).
    var buf = b.atomicFile.fdSafeReadSync(p, { refuseSymlink: true, inodeCheck: true });
    check("fdSafeReadSync: refuseSymlink+inodeCheck reads a regular file", buf.toString() === "PEM");

    // A symlink source is refused (no follow). Platform-conditional: Windows
    // without SeCreateSymbolicLink can't create symlinks — skip the assertion.
    var victim = path.join(dir.path, "victim.pem");
    fs.writeFileSync(victim, "SECRET", { mode: 0o600 });
    var link = path.join(dir.path, "link.pem");
    var symlinkOk = true;
    try { fs.symlinkSync(victim, link); } catch (_e) { symlinkOk = false; }
    if (symlinkOk) {
      var e = _throws(function () {
        b.atomicFile.fdSafeReadSync(link, {
          refuseSymlink: true,
          errorFor: function (kind) { return kind === "symlink" ? Object.assign(new Error("symlink"), { kind: "symlink" }) : undefined; },
        });
      });
      check("fdSafeReadSync: refuseSymlink refuses a symlink source",
            e !== null && e.kind === "symlink");
    } else {
      helpers.unavailable("fdSafeReadSync: symlink case skipped (platform lacks symlink privilege)");
    }
  } finally { dir.cleanup(); }
}

async function run() {
  testReadsBufferAndString();
  testWithStat();
  testMaxBytesCap();
  testExpectedHash();
  testEnoent();
  testErrorForCustomError();
  testRefuseSymlinkAndInodeHappyPath();
  await testReadForwardsAllowShortRead();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
