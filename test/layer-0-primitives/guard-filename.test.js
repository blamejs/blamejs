// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * guard-filename — filename content-safety primitive (b.guardFilename).
 *
 * Covers: surface; path traversal (raw + percent-encoded + double-
 * encoded + UTF-8 overlong); null-byte truncation; Windows reserved
 * device names (CON / PRN / AUX / NUL / COM1-9 / LPT1-9, with and
 * without extensions); NTFS alternate data streams; leading/trailing
 * whitespace + trailing dots; bidi / RTLO file-name spoofing; zero-
 * width chars; homoglyph mixing; reserved characters; UNC paths; length
 * caps; multi-dot / single-dot policy; extension allowlist; shell-
 * shortcut + executable extension detection; double-extension bypass;
 * sanitize round-trip; gate decision shapes; profile + posture
 * vocabulary.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var fs      = helpers.fs;
var os      = helpers.os;
var path    = helpers.path;

// Small assertion helper for the many "this hostile shape must throw with
// exactly this GuardFilenameError code" cases below. Not a mock — a thin
// try/catch wrapper around the real b.guardFilename call the test drives.
function _expectThrowCode(label, code, fn) {
  var threw = null;
  try { fn(); }
  catch (e) { threw = e; }
  check(label + " throws " + code,
        threw && threw.code === code &&
        threw instanceof b.guardFilename.GuardFilenameError);
}

function testGuardFilenameSurface() {
  check("guardFilename is an object",                typeof b.guardFilename === "object");
  check("guardFilename.NAME === 'filename'",         b.guardFilename.NAME === "filename");
  check("guardFilename.PROFILES has strict",         !!b.guardFilename.PROFILES["strict"]);
  check("guardFilename.PROFILES has balanced",       !!b.guardFilename.PROFILES["balanced"]);
  check("guardFilename.PROFILES has permissive",     !!b.guardFilename.PROFILES["permissive"]);
  check("guardFilename.COMPLIANCE_POSTURES has hipaa", !!b.guardFilename.COMPLIANCE_POSTURES["hipaa"]);
  check("guardFilename.validate is a function",      typeof b.guardFilename.validate === "function");
  check("guardFilename.sanitize is a function",      typeof b.guardFilename.sanitize === "function");
  check("guardFilename.gate is a function",          typeof b.guardFilename.gate === "function");
  check("guardFilename.GuardFilenameError is a function",
        typeof b.guardFilename.GuardFilenameError === "function");
  check("frameworkError.GuardFilenameError exposed",
        typeof b.frameworkError.GuardFilenameError === "function");
}

function testGuardFilenameStandalonePrimitive() {
  // guard-filename is intentionally a STANDALONE primitive — it does
  // NOT register into b.guardAll's content-type-routed dispatch. It
  // operates on filename strings, not content bytes; operators wire it
  // separately via b.fileUpload's filenameSafety opt.
  check("guardFilename NOT in guardAll registry",
        !b.guardAll.list().some(function (g) { return g.name === "filename"; }));
}

function testGuardFilenamePathTraversal() {
  var inputs = [
    "../etc/passwd",
    "..\\windows\\system32",
    "subdir/../../etc/shadow",
    "..",
    ".",
  ];
  for (var i = 0; i < inputs.length; i++) {
    var rv = b.guardFilename.validate(inputs[i], { profile: "strict" });
    check("path traversal rejected: " + JSON.stringify(inputs[i]),
          rv.ok === false &&
          rv.issues.some(function (issue) {
            return issue.kind === "path-traversal" ||
                   issue.kind === "path-separator-in-leaf" ||
                   issue.kind === "dot-leaf";
          }));
  }
}

function testGuardFilenamePercentEncodedTraversal() {
  var inputs = [
    "%2e%2e%2fpasswd",
    "%252e%252e%252fpasswd",
    "%c0%aepasswd",     // overlong UTF-8 of dot
  ];
  for (var i = 0; i < inputs.length; i++) {
    var rv = b.guardFilename.validate(inputs[i], { profile: "strict" });
    check("percent-encoded traversal detected: " + JSON.stringify(inputs[i]),
          rv.issues.some(function (issue) {
            return issue.kind === "path-traversal-encoded" ||
                   issue.kind === "url-encoded-separator";
          }));
  }
}

function testGuardFilenameNullByte() {
  var nb = String.fromCharCode(0);
  var rv = b.guardFilename.validate("file.txt" + nb + ".exe", { profile: "strict" });
  check("null byte truncation detected",
        rv.ok === false &&
        rv.issues.some(function (issue) { return issue.kind === "null-byte"; }));
}

function testGuardFilenameWindowsReservedNames() {
  var names = ["CON", "PRN", "AUX", "NUL",
               "COM1", "COM9", "LPT1", "LPT9",
               "con.txt", "PRN.log", "aux.dat", "Nul.bin"];
  for (var i = 0; i < names.length; i++) {
    var rv = b.guardFilename.validate(names[i], { profile: "strict" });
    check("Windows reserved name " + JSON.stringify(names[i]) + " rejected",
          rv.ok === false &&
          rv.issues.some(function (issue) { return issue.kind === "reserved-name"; }));
  }
}

function testGuardFilenameNtfsAds() {
  var rv = b.guardFilename.validate("file.txt:hidden.exe", { profile: "strict" });
  check("NTFS alternate data stream detected",
        rv.issues.some(function (issue) { return issue.kind === "ntfs-ads"; }));
}

function testGuardFilenameLeadingTrailing() {
  var inputs = [" leading.txt", "trailing.txt ", "trailing.txt.",
                "  multiple  .txt"];
  for (var i = 0; i < inputs.length; i++) {
    var rv = b.guardFilename.validate(inputs[i], { profile: "strict" });
    check("leading/trailing rejected: " + JSON.stringify(inputs[i]),
          rv.issues.some(function (issue) {
            return issue.kind === "leading-trailing-strip";
          }));
  }
}

function testGuardFilenameBidiRtlo() {
  // U+202E RLO + made-up extension swap. Memento-RTLO weaponized shape.
  var rtlo = String.fromCharCode(0x202E);
  var rv = b.guardFilename.validate("Photo01By" + rtlo + "gpj.SCR",
                                    { profile: "strict" });
  check("bidi RTLO file-name spoofing detected",
        rv.ok === false &&
        rv.issues.some(function (issue) { return issue.kind === "bidi-override"; }));
}

function testGuardFilenameReservedChars() {
  var chars = ["<", ">", ":", "\"", "|", "?", "*"];
  for (var i = 0; i < chars.length; i++) {
    var rv = b.guardFilename.validate("file" + chars[i] + "name.txt",
                                      { profile: "strict" });
    check("reserved char " + JSON.stringify(chars[i]) + " detected",
          rv.issues.some(function (issue) { return issue.kind === "reserved-char"; }));
  }
}

function testGuardFilenameUncPath() {
  var rv = b.guardFilename.validate("\\\\server\\share\\file.txt",
                                    { profile: "strict" });
  check("UNC path detected",
        rv.ok === false &&
        rv.issues.some(function (issue) { return issue.kind === "unc-path"; }));
}

function testGuardFilenamePathSeparatorsInLeaf() {
  var rv1 = b.guardFilename.validate("subdir/file.txt", { profile: "strict" });
  check("forward-slash in leaf detected (strict)",
        rv1.issues.some(function (issue) {
          return issue.kind === "path-separator-in-leaf" ||
                 issue.kind === "reserved-char";
        }));

  var rv2 = b.guardFilename.validate("subdir\\file.txt", { profile: "strict" });
  check("backslash in leaf detected (strict)",
        rv2.issues.some(function (issue) {
          return issue.kind === "path-separator-in-leaf" ||
                 issue.kind === "reserved-char";
        }));
}

function testGuardFilenameLengthCap() {
  var long = "x".repeat(100) + ".txt";
  var rv = b.guardFilename.validate(long, { profile: "strict" });
  check("length-cap (strict 64-byte) detected",
        rv.issues.some(function (issue) { return issue.kind === "too-long"; }));
}

function testGuardFilenameSingleDotPolicy() {
  var rv = b.guardFilename.validate("archive.tar.gz", { profile: "strict" });
  check("multi-dot detected under strict",
        rv.issues.some(function (issue) { return issue.kind === "multiple-dots"; }));

  var rv2 = b.guardFilename.validate("archive.tar.gz", { profile: "balanced" });
  check("multi-dot allowed under balanced",
        !rv2.issues.some(function (issue) { return issue.kind === "multiple-dots"; }));
}

function testGuardFilenameExtensionAllowlist() {
  var rv = b.guardFilename.validate("photo.gif", {
    profile:            "balanced",
    extensionAllowlist: [".png", ".jpg", ".jpeg"],
  });
  check("ext allowlist: gif rejected when only png/jpg allowed",
        rv.issues.some(function (issue) { return issue.kind === "ext-not-allowlisted"; }));

  var rv2 = b.guardFilename.validate("photo.png", {
    profile:            "balanced",
    extensionAllowlist: [".png", ".jpg", ".jpeg"],
  });
  check("ext allowlist: png accepted",
        !rv2.issues.some(function (issue) { return issue.kind === "ext-not-allowlisted"; }));
}

function testGuardFilenameShellExecExt() {
  var exts = [".exe", ".bat", ".cmd", ".vbs", ".scr", ".lnk", ".js",
              ".ps1", ".dll", ".so", ".dmg"];
  for (var i = 0; i < exts.length; i++) {
    var rv = b.guardFilename.validate("file" + exts[i], { profile: "strict" });
    check("shell-exec ext " + JSON.stringify(exts[i]) + " detected",
          rv.issues.some(function (issue) { return issue.kind === "shell-exec-ext"; }));
  }
}

function testGuardFilenameDoubleExtension() {
  var rv = b.guardFilename.validate("invoice.pdf.exe", { profile: "balanced" });
  check("double-extension with executable last-segment detected",
        rv.issues.some(function (issue) { return issue.kind === "double-extension"; }));
}

function testGuardFilenameOverlongUtf8() {
  // 0xC0 0xAE encodes `.` via non-shortest UTF-8 (RFC 3629 §3 prohibits).
  var buf = Buffer.from([0xC0, 0xAE, 0x66, 0x69, 0x6C, 0x65]);
  var rv = b.guardFilename.validate(buf, { profile: "strict" });
  check("overlong UTF-8 detected at buffer level",
        rv.ok === false &&
        rv.issues.some(function (issue) { return issue.kind === "overlong-utf8"; }));
}

function testGuardFilenameAsciiOnlyStrict() {
  var rv = b.guardFilename.validate("café.txt", { profile: "strict" });
  check("strict requireAscii: non-ASCII detected",
        rv.issues.some(function (issue) { return issue.kind === "non-ascii"; }));

  var rv2 = b.guardFilename.validate("café.txt", { profile: "balanced" });
  check("balanced allows non-ASCII",
        !rv2.issues.some(function (issue) { return issue.kind === "non-ascii"; }));
}

function testGuardFilenameClean() {
  var rv = b.guardFilename.validate("safe.txt", { profile: "strict" });
  check("clean filename → ok=true with no issues", rv.ok === true && rv.issues.length === 0);
}

function testGuardFilenameSanitize() {
  var clean = b.guardFilename.sanitize("  weird name.txt.  ", { profile: "balanced" });
  check("sanitize strips leading/trailing whitespace + trailing dot",
        clean === "weird name.txt");

  // v0.15.12 (#78) — reservedCharPolicy:"strip" (set by the permissive profile)
  // must strip EVERY reserved char, not just the first. The old non-global
  // RESERVED_CHARS_RE left the 2nd/3rd path separators in place.
  var multiSep = b.guardFilename.sanitize("a/b/c/d", { profile: "permissive" });
  check("sanitize permissive strips ALL path separators (#78)",
        multiSep.indexOf("/") === -1 && multiSep === "a_b_c_d");
  var multiBack = b.guardFilename.sanitize("x\\y\\z", { profile: "permissive" });
  check("sanitize permissive strips ALL backslashes (#78)", multiBack.indexOf("\\") === -1);
  check("sanitize permissive leaves a clean name unchanged (#78)",
        b.guardFilename.sanitize("clean.txt", { profile: "permissive" }) === "clean.txt");

  var threwTraversal = null;
  try { b.guardFilename.sanitize("../etc/passwd", { profile: "balanced" }); }
  catch (e) { threwTraversal = e; }
  check("sanitize refuses path traversal even with sanitize requested",
        threwTraversal && /traversal/.test(threwTraversal.message));

  var threwNullByte = null;
  try { b.guardFilename.sanitize("file" + String.fromCharCode(0) + ".exe",
                                 { profile: "strict" }); }
  catch (e) { threwNullByte = e; }
  check("sanitize refuses null-byte truncation",
        threwNullByte && /null/.test(threwNullByte.message));
}

async function testGuardFilenameGate() {
  var g = b.guardFilename.gate({ profile: "strict" });
  var clean = await g.check({ filename: "report.txt" });
  check("gate: clean filename → action=serve",
        clean.ok === true && clean.action === "serve");

  var hostile = await g.check({ filename: "../etc/passwd" });
  check("gate: traversal → action !== serve",
        hostile.action !== "serve");

  var nb = await g.check({ filename: "file.txt" + String.fromCharCode(0) + ".exe" });
  check("gate: null byte → action !== serve",
        nb.action !== "serve");
}

function testGuardFilenameSanitizeStripMode() {
  // Control char (CR) replaced with "_" — operator wants to put the
  // sanitized name into a Content-Disposition header where CR/LF would
  // enable response splitting. Default mode would throw; strip mode
  // returns a usable string.
  var crName = "report" + String.fromCharCode(0x0D) + ".txt";
  var stripped = b.guardFilename.sanitize(crName, { mode: "strip", profile: "balanced" });
  check("strip mode: CR replaced with underscore",
        stripped === "report_.txt");

  // Bidi RTLO replaced.
  var rtlo = "file" + String.fromCharCode(0x202E) + "txt.exe";
  var rtloStripped = b.guardFilename.sanitize(rtlo, { mode: "strip", profile: "balanced" });
  check("strip mode: RTLO bidi replaced with underscore",
        rtloStripped.indexOf(String.fromCharCode(0x202E)) === -1 &&
        rtloStripped.indexOf("_") !== -1);

  // Zero-width also stripped.
  var zw = "ab" + String.fromCharCode(0x200B) + "cd.txt";
  var zwStripped = b.guardFilename.sanitize(zw, { mode: "strip", profile: "balanced" });
  check("strip mode: zero-width replaced",
        zwStripped.indexOf(String.fromCharCode(0x200B)) === -1);

  // Path traversal STILL throws even in strip mode (security floor).
  var threwTraversal = null;
  try { b.guardFilename.sanitize("../etc/passwd", { mode: "strip", profile: "balanced" }); }
  catch (e) { threwTraversal = e; }
  check("strip mode: path traversal still throws",
        threwTraversal && /traversal/.test(threwTraversal.message));

  // Null-byte STILL throws.
  var threwNull = null;
  try { b.guardFilename.sanitize("file" + String.fromCharCode(0) + ".exe",
                                  { mode: "strip", profile: "balanced" }); }
  catch (e) { threwNull = e; }
  check("strip mode: null byte still throws",
        threwNull && /null/.test(threwNull.message));

  // UNC path STILL throws.
  var threwUnc = null;
  try { b.guardFilename.sanitize("\\\\server\\share\\file.txt",
                                  { mode: "strip", profile: "balanced" }); }
  catch (e) { threwUnc = e; }
  check("strip mode: UNC path still throws",
        threwUnc && /UNC/i.test(threwUnc.message));

  // NTFS ADS STILL throws.
  var threwAds = null;
  try { b.guardFilename.sanitize("file.txt:hidden.exe",
                                  { mode: "strip", profile: "balanced" }); }
  catch (e) { threwAds = e; }
  check("strip mode: NTFS ADS still throws",
        threwAds && /ADS|alternate data stream/i.test(threwAds.message));

  // Audit emit observed.
  var captured = [];
  var fakeAudit = {
    safeEmit: function (event) { captured.push(event); },
  };
  b.guardFilename.sanitize(crName, { mode: "strip", profile: "balanced", audit: fakeAudit });
  check("strip mode: audit emits guardfilename.sanitize.stripped",
        captured.length === 1 && captured[0].action === "guardfilename.sanitize.stripped" &&
        captured[0].outcome === "success");
}

function testGdprPostureMatchesBalancedTier() {
  // gdpr is the balanced tier for a filename guard: it allows non-ASCII
  // (data-minimization keeps the value usable) rather than inheriting the
  // strict tier's requireAscii:true. The drift was a partial gdpr posture
  // object that omitted requireAscii, so resolved opts silently backfilled
  // it from the strict-derived defaults — making gdpr a strict/balanced
  // hybrid. Drive the real consumer path: a non-ASCII leaf must NOT raise
  // a non-ascii issue under gdpr.
  var rv = b.guardFilename.validate("café.txt", { compliancePosture: "gdpr" });
  check("gdpr (balanced tier) does not flag non-ascii on a filename leaf",
        !rv.issues.some(function (issue) { return issue.kind === "non-ascii"; }));

  // The deliberate per-posture overlay survives the routing: gdpr strips
  // bidi / control on leaf names (data-minimization) where the balanced
  // profile would reject them. Both together prove balanced-tier base +
  // intended overlay.
  check("gdpr posture overlay keeps bidiPolicy=strip",
        b.guardFilename.COMPLIANCE_POSTURES.gdpr.bidiPolicy === "strip");
  check("gdpr posture overlay keeps controlPolicy=strip",
        b.guardFilename.COMPLIANCE_POSTURES.gdpr.controlPolicy === "strip");
}

function testGuardFilenameCompliancePosture() {
  var hipaa = b.guardFilename.compliancePosture("hipaa");
  check("compliancePosture('hipaa') sets reject policies",
        hipaa.bidiPolicy === "reject" &&
        hipaa.traversalPolicy === "reject" &&
        hipaa.shellExecExtPolicy === "reject");

  var threw = null;
  try { b.guardFilename.compliancePosture("unknown"); }
  catch (e) { threw = e; }
  check("compliancePosture: unknown name throws",
        threw && /unknown/.test(threw.message));
}

function testGuardFilenameBadProfile() {
  var threw = null;
  try { b.guardFilename.validate("x.txt", { profile: "made-up" }); }
  catch (e) { threw = e; }
  check("validate: unknown profile throws",
        threw && /unknown profile/i.test(threw.message));
}

function testGuardFilenameEmptyInput() {
  // Empty string / empty Buffer reach _detectIssues and surface an
  // "empty" issue rather than throwing (validate never throws).
  var rvStr = b.guardFilename.validate("", { profile: "strict" });
  check("validate empty string → empty issue",
        rvStr.ok === false &&
        rvStr.issues.some(function (i) { return i.kind === "empty"; }));

  var rvBuf = b.guardFilename.validate(Buffer.alloc(0), { profile: "strict" });
  check("validate empty Buffer → empty issue",
        rvBuf.issues.some(function (i) { return i.kind === "empty"; }));

  // Non-string / non-Buffer input is rejected by the "bytes" input
  // contract before the detector runs — a bad-input issue, not a crash.
  var rvNum = b.guardFilename.validate(12345, { profile: "strict" });
  check("validate non-string/Buffer → bad-input issue",
        rvNum.ok === false &&
        rvNum.issues.some(function (i) { return i.kind === "bad-input"; }));
}

function testGuardFilenameBenignBufferNoOverlong() {
  // A well-formed UTF-8 Buffer must NOT raise overlong-utf8 — exercises
  // the buffer scan completing without a non-shortest sequence.
  var rv = b.guardFilename.validate(Buffer.from("report-2026.txt", "utf8"),
                                    { profile: "strict" });
  check("benign Buffer → no overlong-utf8 issue",
        !rv.issues.some(function (i) { return i.kind === "overlong-utf8"; }));
  check("benign ASCII Buffer → clean",
        rv.ok === true && rv.issues.length === 0);
}

function testGuardFilenameHomoglyph() {
  // Cyrillic small a (U+0430) mixed with ASCII letters — visual-confusable
  // spoof. Under balanced (homoglyphPolicy:"audit") it surfaces a warn-
  // severity homoglyph issue.
  var cyrA = String.fromCharCode(0x0430);
  var rv = b.guardFilename.validate("p" + cyrA + "ypal.txt", { profile: "balanced" });
  check("balanced: homoglyph mixed with ASCII detected (audit=warn)",
        rv.issues.some(function (i) {
          return i.kind === "homoglyph" && i.severity === "warn";
        }));

  // Under strict (homoglyphPolicy:"reject") the same char is critical.
  var rvStrict = b.guardFilename.validate("p" + cyrA + "ypal.txt", { profile: "strict" });
  check("strict: homoglyph severity is critical",
        rvStrict.issues.some(function (i) {
          return i.kind === "homoglyph" && i.severity === "critical";
        }));

  // No ASCII letters present → homoglyph rule short-circuits (nothing to
  // confuse against), so a pure-Cyrillic leaf raises no homoglyph issue.
  var rvPure = b.guardFilename.validate(cyrA + String.fromCharCode(0x0431),
                                        { profile: "balanced" });
  check("pure non-ASCII leaf → no homoglyph issue (no ASCII to mix)",
        !rvPure.issues.some(function (i) { return i.kind === "homoglyph"; }));
}

function testGuardFilenameSuperscriptReservedName() {
  // Windows folds superscript digits U+00B9/00B2/00B3 to 1/2/3 when
  // matching COM/LPT devices — "COM<sup1>" resolves to COM1. Exercises the
  // superscript-fold branch in _isWinReserved.
  var sup1 = String.fromCharCode(0xB9);
  var rv = b.guardFilename.validate("COM" + sup1, { profile: "balanced" });
  check("superscript-digit COM device spoof → reserved-name",
        rv.issues.some(function (i) { return i.kind === "reserved-name"; }));
}

function testGuardFilenameExtAllowlistNoExtension() {
  // A name with NO extension against an allowlist → ext-not-allowlisted
  // (the empty-extension branch of the allowlist check).
  var rv = b.guardFilename.validate("readme", {
    profile:            "balanced",
    extensionAllowlist: [".txt", ".md"],
  });
  check("no-extension name against allowlist → ext-not-allowlisted",
        rv.issues.some(function (i) { return i.kind === "ext-not-allowlisted"; }));
}

function testGuardFilenameSanitizeEnforceRejections() {
  // sanitize() default (enforce) mode — every reject/throw path below is a
  // security-floor or profile-policy refusal the operator relies on.

  _expectThrowCode("sanitize empty string", "filename.empty", function () {
    b.guardFilename.sanitize("", { profile: "balanced" });
  });

  _expectThrowCode("sanitize overlong-UTF-8 Buffer", "filename.overlong-utf8", function () {
    b.guardFilename.sanitize(Buffer.from([0xC0, 0xAE, 0x66]), { profile: "balanced" });
  });

  _expectThrowCode("sanitize UNC path", "filename.unc", function () {
    b.guardFilename.sanitize("//server/share/file.txt", { profile: "balanced" });
  });

  // strict leadingTrailingPolicy:"reject" — leading whitespace refuses
  // rather than being stripped.
  _expectThrowCode("sanitize strict leading whitespace", "filename.leading-trailing", function () {
    b.guardFilename.sanitize("  report.txt", { profile: "strict" });
  });

  _expectThrowCode("sanitize reserved char (reject)", "filename.reserved-char", function () {
    b.guardFilename.sanitize("a<b.txt", { profile: "balanced" });
  });

  // balanced reservedCharPolicy:"reject" + pathSeparatorsPolicy:"reject" —
  // the "/" is not a reserved char, so the path-separator branch refuses it.
  _expectThrowCode("sanitize path separator (reject)", "filename.path-separator", function () {
    b.guardFilename.sanitize("a/b.txt", { profile: "balanced" });
  });

  _expectThrowCode("sanitize reserved device name (reject)", "filename.reserved-name", function () {
    b.guardFilename.sanitize("CON", { profile: "balanced" });
  });

  // permissive reservedNamePolicy:"audit" — disambiguates by prefixing "_"
  // rather than throwing.
  check("sanitize permissive reserved name → underscore-prefixed",
        b.guardFilename.sanitize("CON", { profile: "permissive" }) === "_CON");

  // NTFS ADS refusal in enforce mode. The ":" is normally caught by the
  // reserved-char pass first, so opt that off to drive the dedicated ADS
  // branch: reservedCharPolicy:"allow" keeps the colon, adsPolicy:"reject"
  // refuses the stream syntax.
  _expectThrowCode("sanitize NTFS ADS (dedicated branch)", "filename.ntfs-ads", function () {
    b.guardFilename.sanitize("file.txt:stream", {
      profile:            "permissive",
      reservedCharPolicy: "allow",
      adsPolicy:          "reject",
    });
  });

  _expectThrowCode("sanitize over-length leaf", "filename.length", function () {
    b.guardFilename.sanitize("x".repeat(300) + ".txt", { profile: "balanced" });
  });

  // Whitespace-only leaf strips to empty under permissive → post-strip
  // empty refusal.
  _expectThrowCode("sanitize strips to empty", "filename.empty", function () {
    b.guardFilename.sanitize("   ", { profile: "permissive" });
  });
}

function testGuardFilenameSanitizeBadInput() {
  _expectThrowCode("sanitize non-string/Buffer input", "filename.bad-input", function () {
    b.guardFilename.sanitize(12345, { profile: "balanced" });
  });
}

function testGuardFilenameSanitizeStripModeFloor() {
  // Strip-mode security floor branches not covered by the round-trip test.
  _expectThrowCode("strip-mode overlong-UTF-8 Buffer", "filename.overlong-utf8", function () {
    b.guardFilename.sanitize(Buffer.from([0xC0, 0xAE, 0x66]),
                             { mode: "strip", profile: "balanced" });
  });

  _expectThrowCode("strip-mode empty string", "filename.empty", function () {
    b.guardFilename.sanitize("", { mode: "strip", profile: "balanced" });
  });

  _expectThrowCode("strip-mode over-length leaf", "filename.length", function () {
    b.guardFilename.sanitize("x".repeat(300), { mode: "strip", profile: "balanced" });
  });
}

async function testGuardFilenameGateSanitizeAction() {
  // The gate's "sanitize" action fires only when EVERY reject-policy is off
  // and a strip-eligible high/critical issue is present. Drive it with an
  // all-policies-non-reject config and a leading-whitespace name (a "high"
  // leading-trailing issue that sanitize repairs to "report.txt").
  // The floor classes carry no policy to turn off — traversal and NUL are
  // pinned to reject, and ADS offers only reject or allow — so they are absent
  // here rather than set to a value that never applied.
  var g = b.guardFilename.gate({
    profile:               "permissive",
    bidiPolicy:            "strip",
    controlPolicy:         "strip",
    reservedCharPolicy:    "strip",
    reservedNamePolicy:    "audit",
    pathSeparatorsPolicy:  "audit",
    leadingTrailingPolicy: "strip",
  });
  var v = await g.check({ filename: " report.txt" });
  check("gate: sanitize-eligible issue → action=sanitize",
        v.ok === true && v.action === "sanitize");

  // audit-only: a warn-severity-only issue (no high/critical) resolves to
  // action=audit-only. A homoglyph under audit policy is warn-only.
  var gAudit = b.guardFilename.gate({ profile: "permissive", homoglyphPolicy: "audit" });
  var vAudit = await gAudit.check({ filename: "p" + String.fromCharCode(0x0430) + "y" });
  check("gate: warn-only issue → action=audit-only",
        vAudit.action === "audit-only");
}

function testVerifyExtractionPathStringRefusals() {
  var root = "/var/quarantine";
  _expectThrowCode("vep empty entryName", "filename.extraction-empty", function () {
    b.guardFilename.verifyExtractionPath("", root);
  });
  _expectThrowCode("vep non-string entryName", "filename.extraction-empty", function () {
    b.guardFilename.verifyExtractionPath(123, root);
  });
  _expectThrowCode("vep empty extractionRoot", "filename.extraction-bad-root", function () {
    b.guardFilename.verifyExtractionPath("ok.txt", "");
  });
  _expectThrowCode("vep non-string extractionRoot", "filename.extraction-bad-root", function () {
    b.guardFilename.verifyExtractionPath("ok.txt", 123);
  });
  _expectThrowCode("vep PATH_MAX overflow", "filename.extraction-path-max", function () {
    b.guardFilename.verifyExtractionPath("a".repeat(4097), root);
  });
  _expectThrowCode("vep null byte", "filename.extraction-null-byte", function () {
    b.guardFilename.verifyExtractionPath("file" + String.fromCharCode(0) + ".txt", root);
  });
  _expectThrowCode("vep absolute path", "filename.extraction-absolute", function () {
    b.guardFilename.verifyExtractionPath("/etc/passwd", root);
  });
  _expectThrowCode("vep drive-letter prefix", "filename.extraction-drive-prefix", function () {
    b.guardFilename.verifyExtractionPath("C:/Windows/system32", root);
  });
  _expectThrowCode("vep .. leading segment", "filename.extraction-traversal", function () {
    b.guardFilename.verifyExtractionPath("../etc/passwd", root);
  });
  _expectThrowCode("vep .. interior segment", "filename.extraction-traversal", function () {
    b.guardFilename.verifyExtractionPath("a/../b", root);
  });
  _expectThrowCode("vep backslash .. segment", "filename.extraction-traversal", function () {
    b.guardFilename.verifyExtractionPath("a\\..\\b", root);
  });
  _expectThrowCode("vep percent-encoded ..", "filename.extraction-traversal-encoded", function () {
    b.guardFilename.verifyExtractionPath("docs/%2e%2e/x", root);
  });
  _expectThrowCode("vep overlong-encoded ..", "filename.extraction-traversal-encoded", function () {
    b.guardFilename.verifyExtractionPath("docs/%c0%ae/x", root);
  });
  _expectThrowCode("vep reserved device segment", "filename.extraction-reserved-name", function () {
    b.guardFilename.verifyExtractionPath("docs/CON/x.txt", root);
  });
  _expectThrowCode("vep NTFS ADS segment", "filename.extraction-ntfs-ads", function () {
    b.guardFilename.verifyExtractionPath("docs/file.txt:stream", root);
  });
  _expectThrowCode("vep trailing-dot segment", "filename.extraction-leading-trailing", function () {
    b.guardFilename.verifyExtractionPath("docs/secret.txt.", root);
  });
  _expectThrowCode("vep leading-whitespace segment", "filename.extraction-leading-trailing", function () {
    b.guardFilename.verifyExtractionPath(" leading/x.txt", root);
  });
}

function testVerifyExtractionPathOptOuts() {
  // Non-existent root so the fs realpath block is skipped; each opt-out
  // flips a Windows-hazard segment check off and the call succeeds.
  var root = path.join(os.tmpdir(), "gfn-none-" + Date.now() + "-" + Math.random().toString(36).slice(2));
  var r1 = b.guardFilename.verifyExtractionPath("docs/CON/x.txt", root,
                                                { reservedNamePolicy: "allow" });
  check("vep reservedNamePolicy:allow permits CON segment",
        typeof r1 === "string" && r1.indexOf("x.txt") !== -1);

  var r2 = b.guardFilename.verifyExtractionPath("docs/file.txt:stream", root,
                                                { adsPolicy: "allow" });
  check("vep adsPolicy:allow permits name:stream segment",
        typeof r2 === "string" && r2.indexOf("stream") !== -1);

  var r3 = b.guardFilename.verifyExtractionPath("docs/secret.txt.", root,
                                                { leadingTrailingPolicy: "allow" });
  check("vep leadingTrailingPolicy:allow permits trailing dot",
        typeof r3 === "string");
}

function testVerifyExtractionPathSuccess() {
  // Non-existent root: string-containment passes, realpath block skipped,
  // resolved path returned.
  var noneRoot = path.join(os.tmpdir(), "gfn-none-" + Date.now() + "-" + Math.random().toString(36).slice(2));
  var resolved = b.guardFilename.verifyExtractionPath("docs/readme.txt", noneRoot);
  check("vep benign entry (no root on disk) → resolved path returned",
        typeof resolved === "string" &&
        resolved === path.resolve(noneRoot, "docs/readme.txt"));

  // Existing root on disk: exercises the realpath-agreement block — every
  // existing ancestor must realpath inside the realpath of the root.
  var realRoot = fs.mkdtempSync(path.join(os.tmpdir(), "gfn-root-"));
  try {
    var r = b.guardFilename.verifyExtractionPath("sub/dir/file.txt", realRoot);
    check("vep existing root → realpath-agreement passes, resolved returned",
          r === path.resolve(realRoot, "sub/dir/file.txt"));
  } finally {
    try { fs.rmSync(realRoot, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  }
}

function testVerifyExtractionPathRealpathEscape() {
  // A symlink/junction inside the root whose realpath escapes the root is
  // the CVE-2025-4517 PATH_MAX-TOCTOU class: string containment passes
  // (no ".." literal) but fs.realpath resolves outside. Junction on
  // Windows (no admin needed) / symlink on POSIX.
  var realRoot = fs.mkdtempSync(path.join(os.tmpdir(), "gfn-root-"));
  var outside  = fs.mkdtempSync(path.join(os.tmpdir(), "gfn-out-"));
  var linkMade = false;
  try {
    var link = path.join(realRoot, "link");
    try { fs.symlinkSync(outside, link, "junction"); linkMade = true; }
    catch (_e1) {
      try { fs.symlinkSync(outside, link, "dir"); linkMade = true; }
      catch (_e2) { linkMade = false; }
    }
    if (linkMade) {
      _expectThrowCode("vep symlink escaping root", "filename.extraction-realpath-escape", function () {
        b.guardFilename.verifyExtractionPath("link/evil.txt", realRoot);
      });
    }
  } finally {
    try { fs.rmSync(realRoot, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
    try { fs.rmSync(outside, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  }
  check("vep realpath-escape test wired (symlink/junction created)", linkMade === true);
}

function testGuardFilenameOverlongVariants() {
  // 3-byte overlong (0xE0 0x80-0x9F) and 4-byte overlong (0xF0 0x80-0x8F)
  // are non-shortest forms alongside the 2-byte 0xC0/0xC1 class.
  var three = b.guardFilename.validate(Buffer.from([0xE0, 0x80, 0xAE, 0x78]),
                                       { profile: "strict" });
  check("3-byte overlong UTF-8 detected",
        three.issues.some(function (i) { return i.kind === "overlong-utf8"; }));

  var four = b.guardFilename.validate(Buffer.from([0xF0, 0x80, 0x80, 0xAE]),
                                      { profile: "strict" });
  check("4-byte overlong UTF-8 detected",
        four.issues.some(function (i) { return i.kind === "overlong-utf8"; }));
}

function testGuardFilenameSanitizeBufferInput() {
  // A well-formed Buffer flows through the Buffer arm of both sanitize
  // modes' name-extraction and round-trips to its UTF-8 text.
  check("sanitize enforce accepts a benign Buffer",
        b.guardFilename.sanitize(Buffer.from("okname.txt", "utf8"),
                                 { profile: "balanced" }) === "okname.txt");
  check("sanitize strip accepts a benign Buffer",
        b.guardFilename.sanitize(Buffer.from("okname.txt", "utf8"),
                                 { mode: "strip", profile: "balanced" }) === "okname.txt");
}

function testGuardFilenameStripAuditEdge() {
  // Buffer input through strip-mode audit — the originalLength computation
  // takes its Buffer arm.
  var captured = [];
  var okAudit = { safeEmit: function (ev) { captured.push(ev); } };
  var crBuf = Buffer.from("report" + String.fromCharCode(0x0D) + ".txt", "utf8");
  var out = b.guardFilename.sanitize(crBuf, { mode: "strip", profile: "balanced", audit: okAudit });
  check("strip-mode audit with Buffer input emits + strips CR",
        out === "report_.txt" && captured.length === 1 &&
        captured[0].action === "guardfilename.sanitize.stripped");

  // A throwing audit sink must NOT propagate — the sink is drop-silent so
  // a crashing audit backend never breaks the producer.
  var throwingAudit = { safeEmit: function () { throw new Error("audit backend down"); } };
  var stillOut = b.guardFilename.sanitize("report" + String.fromCharCode(0x0D) + ".txt",
                                          { mode: "strip", profile: "balanced", audit: throwingAudit });
  check("strip-mode audit sink error is swallowed (drop-silent)",
        stillOut === "report_.txt");
}

async function testGuardFilenameGateCtxShapes() {
  var g = b.guardFilename.gate({ profile: "strict" });

  // ctx.name (not ctx.filename) is the fallback identity key.
  var byName = await g.check({ name: "report.txt" });
  check("gate reads ctx.name when ctx.filename absent → serve",
        byName.ok === true && byName.action === "serve");

  // No filename at all → serve (nothing to guard).
  var empty = await g.check({});
  check("gate with no filename → serve",
        empty.ok === true && empty.action === "serve");
}

function testVerifyExtractionPathDotSegment() {
  // Current-dir "." and empty segments are skipped by the per-segment
  // walk; a benign path carrying them still resolves cleanly.
  var root = path.join(os.tmpdir(), "gfn-none-" + Date.now() + "-" + Math.random().toString(36).slice(2));
  var resolved = b.guardFilename.verifyExtractionPath("a/./b.txt", root);
  check("vep skips '.' segment and resolves",
        resolved === path.resolve(root, "a/b.txt"));
}

// An over-long name is refused under THIS guard's length rule, and the error
// says so: `filename.length`. A shared character-scan helper that applied a
// byte ceiling of its own would refuse the same input a step earlier under a
// different code, and an operator matching on the documented one would stop
// recognising it.
function testOverLongNameIsRefusedUnderThisGuardsOwnRule() {
  var long = "a".repeat(300) + ".txt";
  ["strict", "balanced", "permissive"].forEach(function (p) {
    var err = null;
    try { b.guardFilename.sanitize(long, { profile: p }); }
    catch (e) { err = e; }
    check("over-long name refused under " + p, err !== null);
    check("over-long name refused as filename.length under " + p,
          err !== null && err.code === "filename.length");
  });
}

// The shape detectors are character walks. Each one is compared here against
// the pattern it replaced, over a corpus of the hostile names this guard
// exists for, so a walk that answers differently from the pattern shows up as
// a disagreement rather than as a name that quietly stops being refused.
function testShapeDetectorsAgreeWithThePatternsTheyReplaced() {
  var NAMES = [
    "", ".", "..", "...", "....", "a", "a.txt",
    "../etc/passwd", "..\\windows\\system32", "a/../b", "a/..", "../..",
    "..a", "a..", "a..b", "x/..y", "y../z", "dir/../../etc/passwd",
    "%2e%2e/etc", "%2E%2E/etc", "%252e%252e/x", "%c0%ae%c0%ae/x", "%C0%AF",
    "%2f", "%5C", "%c1%9c", "no-encoding-here",
    "\\\\server\\share\\f.txt", "//host/path", "/abs/path", "\\single",
    "C:/win", "c:\\win", "Z:/x", "1:/x", "CC:/x", "C:x",
    "report.txt:hidden", "a:b:c", "a:b/c", "a:", ":stream", "x:y",
    "name ", " name", "name.", "name..", " ", ".hidden", "n\u00a0",
    "\u3000pad", "tab\there", "report<final>.csv", "a|b", "q?", "st*r",
    "quote\"d", "back\\slash", "fwd/slash", "COM1", "com\u00b91",
  ];

  // The patterns as they were, restated here so the comparison is against the
  // old behaviour rather than against the new code.
  var PATH_TRAVERSAL_RE = /(^|[/\\])\.\.($|[/\\])/;
  var PERCENT_ENCODED_TRAVERSAL_RE = /%2e%2e|%252e%252e|%c0%ae|%c0%af/i;
  var URL_ENCODED_SLASH_RE = /%2f|%5c|%c0%af|%c1%9c/i;

  var diffs = [];
  function compare(label, name, expected, actual) {
    if (expected !== actual) diffs.push(label + " " + JSON.stringify(name));
  }

  NAMES.forEach(function (n) {
    // Traversal, percent-encoded traversal, and encoded separators are read
    // through validate, which is the surface an operator drives.
    var issues = b.guardFilename.validate(n, { profile: "strict" }).issues;
    function has(kind) {
      return issues.some(function (i) { return i.kind === kind; });
    }
    compare("traversal", n,
            PATH_TRAVERSAL_RE.test(n) || n === "..", has("path-traversal"));
    compare("encoded-traversal", n,
            PERCENT_ENCODED_TRAVERSAL_RE.test(n), has("path-traversal-encoded"));
    compare("encoded-separator", n,
            URL_ENCODED_SLASH_RE.test(n), has("url-encoded-separator"));
    compare("unc", n, /^\\\\|^\/\//.test(n), has("unc-path"));
    compare("ads", n,
            /:[^:\\/]+$/.test(n) && n.charAt(0) !== "/", has("ntfs-ads"));
    compare("leading-trailing", n, /^\s|\s$|\.$/.test(n),
            has("leading-trailing-strip"));
    compare("reserved-char", n, /[<>:"|?*]/.test(n), has("reserved-char"));
  });

  check("every shape detector agrees with the pattern it replaced (" +
        NAMES.length + " names)", diffs.length === 0,
        diffs.slice(0, 5).join(" | "));

  // The reserved-character strip replaces EVERY occurrence. A single-match
  // sanitizer returns a name that still carries the rest of them.
  var stripped = b.guardFilename.sanitize("a<b>c:d|e?f*g\"h", {
    profile: "balanced", reservedCharPolicy: "strip",
  });
  check("every reserved character is replaced, not the first",
        stripped === "a_b_c_d_e_f_g_h", stripped);

  // Whitespace the filesystem trims is not only the ASCII space: a name
  // ending in U+00A0 or U+3000 is trimmed by Windows on create, so it has to
  // be flagged the same way.
  [0x00A0, 0x3000, 0x2028, 0xFEFF, 0x205F].forEach(function (cp) {
    var name = "report.txt" + String.fromCharCode(cp);
    var flagged = b.guardFilename.validate(name, { profile: "strict" }).issues
      .some(function (i) { return i.kind === "leading-trailing-strip"; });
    check("a trailing U+" + cp.toString(16).toUpperCase() +
          " counts as trimmable whitespace", flagged);
  });

  // An astral character becomes ONE replacement in strip mode, not two.
  var astral = b.guardFilename.sanitize("a" + String.fromCodePoint(0xE0041) + "b", {
    mode: "strip", profile: "balanced",
  });
  check("an astral Tags character is replaced once, not once per surrogate",
        astral === "a_b", astral);
}

// The gate documents a floor: path-traversal, null-byte, NTFS-ADS, UNC and
// overlong UTF-8 always refuse, because none of them can be repaired into a
// safe name — a UNC prefix reaches another host, a traversal segment escapes
// the directory, a NUL truncates the name at whichever consumer reads it first,
// and an ADS suffix names a second stream on the same file.
//
// The floor has to hold against the POLICIES, not merely alongside them. When
// the gate began dispositioning each finding from its own policy, reading these
// kinds from `traversalPolicy` and `adsPolicy` meant an operator who set those
// to `audit` — a supported override, and what `permissive` is closest to —
// served the name unchanged. The classes are refused before any policy is
// consulted.
async function testGuardFilenameFloorIgnoresPolicyOverrides() {
  // The overrides that remain expressible. `traversalPolicy` and
  // `nullBytePolicy` no longer accept a non-reject value at all, and
  // `adsPolicy` accepts only reject or allow — the floor is now visible in
  // what the guard will take, not only in what it does with it. Each is
  // asserted below.
  var override = {
    profile: "permissive",
    pathSeparatorsPolicy: "audit",
    adsPolicy:            "allow",
    controlPolicy:        "audit",
  };
  var floor = [
    ["UNC path",       "\\\\server\\share\\f.txt"],
    ["traversal",      "../etc/passwd"],
    ["NTFS ADS",       "f.txt:stream"],
    ["null byte",      "f\u0000.txt"],
  ];
  for (var i = 0; i < floor.length; i += 1) {
    var d = await b.guardFilename.gate(override).check({ filename: floor[i][1] });
    check("guardFilename floor: " + floor[i][0] + " refuses under the most permissive " +
          "configuration the guard accepts",
          d.action === "refuse", floor[i][0] + " -> " + d.action);
  }

  // And the values that used to express "do not refuse this" are gone from the
  // vocabulary, so the floor is no longer something an operator can believe
  // they turned off. Each of these was accepted before and changed nothing.
  [["traversalPolicy", "audit"], ["traversalPolicy", "allow"],
   ["nullBytePolicy",  "audit"], ["nullBytePolicy",  "allow"],
   ["adsPolicy",       "audit"]].forEach(function (pair) {
    var bad = { profile: "permissive" };
    bad[pair[0]] = pair[1];
    var refused = false;
    try { b.guardFilename.resolveOpts(bad); } catch (_e) { refused = true; }
    check("guardFilename: " + pair[0] + ": " + JSON.stringify(pair[1]) +
          " is refused rather than accepted and ignored", refused);
  });

  // The repairable classes still repair, or the floor would just be a blanket
  // refusal wearing a policy map.
  var clean = await b.guardFilename.gate({ profile: "balanced" })
                     .check({ filename: "rep\u200Bort.txt" });
  check("guardFilename: a zero-width character is still repaired at balanced",
        clean.action === "sanitize" && clean.sanitized === "report.txt",
        clean.action + " " + JSON.stringify(clean.sanitized));

  // `sanitize()` is a whole-name transform under the profile, not a per-finding
  // one: a name that enters sanitization because of a `strip` class also has
  // the profile's other repairs applied, including to a class whose own policy
  // was `audit`. That is the verb's contract rather than something the gate
  // decides, and the gate must not diverge from it \u2014 an operator who calls
  // `b.guardFilename.sanitize()` directly has to get the same string back, or
  // the gate is repairing to a rule nothing else in the guard implements.
  var mixed = [
    ["permissive", "dir/file?.txt"],
    ["permissive", "ab/c?.txt"],
    ["balanced",   "rep\u200Bort.txt"],
  ];
  for (var m = 0; m < mixed.length; m += 1) {
    var verdict = await b.guardFilename.gate({ profile: mixed[m][0] })
                         .check({ filename: mixed[m][1] });
    if (verdict.action !== "sanitize") continue;
    var direct = b.guardFilename.sanitize(mixed[m][1], { profile: mixed[m][0] });
    check("guardFilename: the gate's repair equals sanitize() for " +
          JSON.stringify(mixed[m][1]) + " at " + mixed[m][0],
          verdict.sanitized === direct,
          "gate=" + JSON.stringify(verdict.sanitized) + " verb=" + JSON.stringify(direct));
  }
}

// `double-extension` fires on exactly the trigger `shell-exec-ext` does — a
// last extension in SHELL_EXEC_EXTS — so it is the same finding seen twice and
// must answer to the same policy. Leaving it unmapped sent it to the
// conservative severity default, and `critical` refuses: a profile declaring
// `shellExecExtPolicy: "audit"` then behaved as reject for precisely the
// disguised-executable names the policy is about, and for nothing else.
async function testGuardFilenameDoubleExtensionFollowsItsPolicy() {
  var cases = [
    ["balanced",   "invoice.pdf.exe"],
    ["permissive", "invoice.pdf.exe"],
    ["balanced",   "report.docx.bat"],
  ];
  for (var i = 0; i < cases.length; i += 1) {
    var profile = cases[i][0];
    var policy = b.guardFilename.PROFILES[profile].shellExecExtPolicy;
    var d = await b.guardFilename.gate({ profile: profile }).check({ filename: cases[i][1] });
    check("guardFilename: " + JSON.stringify(cases[i][1]) + " at " + profile +
          " follows shellExecExtPolicy=" + policy,
          policy !== "audit" || d.action !== "refuse",
          "policy=" + policy + " action=" + d.action);
  }

  // strict still refuses — the policy there says reject, and this must not have
  // widened into "a disguised executable is always allowed".
  var strict = await b.guardFilename.gate({ profile: "strict" })
                     .check({ filename: "invoice.pdf.exe" });
  check("guardFilename: strict still refuses a disguised executable",
        strict.action === "refuse", "action=" + strict.action);
}

// `adsPolicy` means different things at different doors, and that split is
// deliberate: an NTFS alternate-data-stream suffix is one of the shapes a
// filename guard must always refuse, while `verifyExtractionPath` serves an
// operator deliberately extracting stream-suffixed entries. The opts block has
// said so since the option gained its second value — "reject here; allow is
// honoured only by verifyExtractionPath".
//
// What it did NOT do is say that to a caller who sets `allow` and watches
// nothing happen. Three doors accept the value and ignore it, and the refusal
// they raise says only that the name carries stream syntax, so the option reads
// as broken rather than as scoped. The message now names the boundary.
//
// The colon is why this is easy to misdiagnose: it is also a Windows reserved
// character, so `reservedCharPolicy` refuses it BEFORE the ADS check is
// reached. Every case here sets that policy to "allow" so the ADS check is
// actually the one under test — without it these pass for the wrong reason.
function testAdsPolicyIsScopedToExtractionAndSaysSo() {
  var ADS = "report.txt:stream";
  var base = { reservedCharPolicy: "allow" };
  function withAds(v) { return { reservedCharPolicy: "allow", adsPolicy: v }; }

  // Control: the sample really does reach the ADS check rather than being
  // refused earlier as a reserved character.
  var earlier = null;
  try { b.guardFilename.sanitize(ADS, {}); } catch (e) { earlier = e; }
  check("guardFilename: without reservedCharPolicy the colon is refused as a " +
        "reserved character, before ADS is reached",
        earlier !== null && earlier.code === "filename.reserved-char",
        String(earlier && earlier.code));

  // The three judging doors refuse regardless of the policy.
  [undefined, "reject", "allow"].forEach(function (v) {
    var opts = v === undefined ? base : withAds(v);
    var err = null;
    try { b.guardFilename.sanitize(ADS, opts); } catch (e2) { err = e2; }
    check("guardFilename: sanitize refuses an ADS name with adsPolicy=" +
          String(v), err !== null && err.code === "filename.ntfs-ads",
          String(err && err.code));

    var res = b.guardFilename.validate(ADS, opts);
    check("guardFilename: validate refuses an ADS name with adsPolicy=" +
          String(v),
          res.ok === false && res.issues.some(function (i) {
            return i.ruleId === "filename.ntfs-ads";
          }), JSON.stringify(res.issues.map(function (i) { return i.ruleId; })));
  });

  // And the refusal explains why the option did not apply, so a caller who set
  // it is not left comparing their code against a message that never mentions
  // the setting they changed.
  var scoped = null;
  try { b.guardFilename.sanitize(ADS, withAds("allow")); } catch (e3) { scoped = e3; }
  check("guardFilename: the ADS refusal names verifyExtractionPath as where " +
        "adsPolicy \"allow\" applies",
        scoped !== null && /verifyExtractionPath/.test(String(scoped.message)),
        String(scoped && scoped.message));

  // The other side of the split: the extraction path honours it, which is the
  // whole reason the option has two values.
  var root = helpers.path.join(helpers.os.tmpdir(), "blamejs-ads-scope");
  var allowed = null, refused = null;
  try { allowed = b.guardFilename.verifyExtractionPath(ADS, root, { adsPolicy: "allow" }); }
  catch (e4) { allowed = e4; }
  try { b.guardFilename.verifyExtractionPath(ADS, root, { adsPolicy: "reject" }); }
  catch (e5) { refused = e5; }
  check("guardFilename: verifyExtractionPath honours adsPolicy \"allow\"",
        typeof allowed === "string" && allowed.indexOf(":stream") !== -1,
        String(allowed && (allowed.code || allowed)));
  check("guardFilename: verifyExtractionPath still refuses under \"reject\"",
        refused !== null && refused.code === "filename.extraction-ntfs-ads",
        String(refused && refused.code));
}

async function run() {
  testAdsPolicyIsScopedToExtractionAndSaysSo();
  await testGuardFilenameDoubleExtensionFollowsItsPolicy();
  await testGuardFilenameFloorIgnoresPolicyOverrides();
  testOverLongNameIsRefusedUnderThisGuardsOwnRule();
  testShapeDetectorsAgreeWithThePatternsTheyReplaced();
  testGuardFilenameSurface();
  testGuardFilenameStandalonePrimitive();
  testGuardFilenamePathTraversal();
  testGuardFilenamePercentEncodedTraversal();
  testGuardFilenameNullByte();
  testGuardFilenameWindowsReservedNames();
  testGuardFilenameNtfsAds();
  testGuardFilenameLeadingTrailing();
  testGuardFilenameBidiRtlo();
  testGuardFilenameReservedChars();
  testGuardFilenameUncPath();
  testGuardFilenamePathSeparatorsInLeaf();
  testGuardFilenameLengthCap();
  testGuardFilenameSingleDotPolicy();
  testGuardFilenameExtensionAllowlist();
  testGuardFilenameShellExecExt();
  testGuardFilenameDoubleExtension();
  testGuardFilenameOverlongUtf8();
  testGuardFilenameAsciiOnlyStrict();
  testGdprPostureMatchesBalancedTier();
  testGuardFilenameClean();
  testGuardFilenameSanitize();
  testGuardFilenameSanitizeStripMode();
  testGuardFilenameCompliancePosture();
  testGuardFilenameBadProfile();
  testGuardFilenameEmptyInput();
  testGuardFilenameBenignBufferNoOverlong();
  testGuardFilenameHomoglyph();
  testGuardFilenameSuperscriptReservedName();
  testGuardFilenameExtAllowlistNoExtension();
  testGuardFilenameSanitizeEnforceRejections();
  testGuardFilenameSanitizeBadInput();
  testGuardFilenameSanitizeStripModeFloor();
  testGuardFilenameOverlongVariants();
  testGuardFilenameSanitizeBufferInput();
  testGuardFilenameStripAuditEdge();
  testVerifyExtractionPathDotSegment();
  testVerifyExtractionPathStringRefusals();
  testVerifyExtractionPathOptOuts();
  testVerifyExtractionPathSuccess();
  testVerifyExtractionPathRealpathEscape();
  await testGuardFilenameGate();
  await testGuardFilenameGateSanitizeAction();
  await testGuardFilenameGateCtxShapes();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[guard-filename] OK — " + helpers.getChecks() + " checks passed"); process.exit(0); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
