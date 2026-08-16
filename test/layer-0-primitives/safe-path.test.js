// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
var helpers = require("../helpers");
var b = helpers.b;
var check = helpers.check;

function testHappyPath() {
  var p = b.safePath.resolve("/srv/uploads", "user/avatar.png");
  // Host-platform-specific absolute prefix (Windows adds a drive
  // letter, POSIX doesn't); compare the trailing relative portion.
  var normalized = p.replace(/\\/g, "/");
  check("happy-path includes base", normalized.indexOf("srv/uploads/user/avatar.png") !== -1);
  check("happy-path is absolute",   require("node:path").isAbsolute(p));
}

function testRefusalClasses() {
  var cases = [
    { name: "absolute-rel posix",   args: ["/srv", "/etc/passwd"],            code: "safe-path/absolute-rel" },
    { name: "absolute-rel drive",   args: ["/srv", "C:\\Windows\\x"],         code: "safe-path/absolute-rel" },
    { name: "absolute-rel UNC",     args: ["/srv", "\\\\server\\share"],      code: "safe-path/absolute-rel" },
    { name: "null byte",            args: ["/srv", "a\0b"],                   code: "safe-path/null-byte" },
    { name: "control char",         args: ["/srv", "a\x01b"],                 code: "safe-path/control-char" },
    { name: "bidi codepoint",       args: ["/srv", "a‮b"],               code: "safe-path/bidi" },
    { name: "encoded slash",        args: ["/srv", "a%2Fb"],                  code: "safe-path/separator-in-segment" },
    { name: "fullwidth slash",      args: ["/srv", "a／b"],               code: "safe-path/separator-in-segment" },
    { name: "win reserved CON",     args: ["/srv", "CON"],                    code: "safe-path/win-reserved" },
    { name: "win reserved con.txt", args: ["/srv", "con.txt"],                code: "safe-path/win-reserved" },
    { name: "NTFS ADS marker",      args: ["/srv", "foo:bar"],                code: "safe-path/ads-marker" },
    { name: "escapes base",         args: ["/srv", "../etc/passwd"],          code: "safe-path/escapes-base" },
  ];
  for (var i = 0; i < cases.length; i += 1) {
    var c = cases[i];
    var caught = null;
    try { b.safePath.resolve(c.args[0], c.args[1]); }
    catch (e) { caught = e; }
    check(c.name + " throws " + c.code,
      caught !== null && (caught.code === c.code || (caught.message || "").indexOf(c.code) !== -1));
  }
}

function testWindowsTrailing() {
  var caught = null;
  try { b.safePath.resolve("/srv", "foo.txt.", { platform: "windows" }); }
  catch (e) { caught = e; }
  check("win-trailing dot throws",
    caught !== null && (caught.code === "safe-path/win-trailing" || (caught.message || "").indexOf("win-trailing") !== -1));
}

function testResolveOrNullReturnsNull() {
  var p = b.safePath.resolveOrNull("/srv", "../etc/passwd");
  check("resolveOrNull returns null on refusal", p === null);
  var ok = b.safePath.resolveOrNull("/srv", "ok.txt");
  check("resolveOrNull returns path on success", typeof ok === "string" && ok.indexOf("ok.txt") !== -1);
}

function testValidateReturnsVerdict() {
  var bad = b.safePath.validate("/srv", "../etc/passwd");
  check("validate(refused) ok=false", bad.ok === false);
  check("validate(refused) carries code", typeof bad.code === "string");
  var good = b.safePath.validate("/srv", "data/x.json");
  check("validate(ok) ok=true", good.ok === true);
  check("validate(ok) carries resolved", typeof good.resolved === "string");
}

function testErrorClassExported() {
  check("SafePathError exported", typeof b.safePath.SafePathError === "function");
}

// #371 — opts.platform gates the per-segment naming rules AND the lexical
// containment resolution. The lexical resolve + boundary use the TARGET
// platform's path module (nodePath.win32 / nodePath.posix) so the resolved
// output's separator matches the boundary slice. Validating against the
// OPPOSITE platform's rules (the recommended cross-platform pattern) used to
// refuse every in-base path with safe-path/escapes-base because the boundary
// slice compared the runtime-separated nodePath.resolve output against the
// opts.platform separator. With target-platform resolution the in-base path is
// accepted AND a genuine traversal is still refused under any override.
function testCrossPlatformContainment() {
  var nodePath = require("node:path");
  var other = process.platform === "win32" ? "linux" : "windows";
  var pathMod = other === "windows" ? nodePath.win32 : nodePath.posix;
  // Drive-prefixed base on Windows, posix base elsewhere.
  var base = process.platform === "win32" ? "C:/srv/uploads" : "/srv/uploads";

  var inBase = b.safePath.resolveOrNull(base, "file.txt", { platform: other });
  check("opposite-platform override resolves an in-base file (not null)",
    typeof inBase === "string" && inBase.indexOf("file.txt") !== -1);
  var nested = b.safePath.resolveOrNull(base, "a/b/file.txt", { platform: other });
  check("opposite-platform override resolves a nested in-base path",
    typeof nested === "string" && nested.indexOf("file.txt") !== -1);
  var v = b.safePath.validate(base, "data/x.json", { platform: other });
  check("opposite-platform override validate() ok=true", v.ok === true && typeof v.resolved === "string");
  // Containment is still ENFORCED under the override — a real traversal refused.
  check("opposite-platform override still refuses a forward-slash traversal",
    b.safePath.resolveOrNull(base, "../../etc/passwd", { platform: other }) === null);
  // The containment boundary uses the TARGET platform's separator, so the
  // resolved path begins with the target-resolved base.
  check("resolved path begins with the target-resolved base",
    typeof inBase === "string" && inBase.indexOf(pathMod.resolve(base)) === 0);
}

// #371 P1 — cross-platform backslash traversal. A POSIX host validating with
// opts.platform: "windows" must collapse Windows separators (\) and `..` the
// SAME way the per-segment walk does. The lexical resolve previously used the
// runtime path module: on POSIX, node:path treats \ as an ordinary filename
// character, so `ok\..\..\outside` slipped past containment and resolved to
// `<base>/ok\..\..\outside` — a path that escapes the base once a Windows
// consumer interprets the backslashes. Validating FOR windows now resolves with
// nodePath.win32 on every host, so the traversal is refused. (On a Windows host
// win32 IS the runtime, so this also guards the same case there.)
function testCrossPlatformBackslashTraversalRefused() {
  var BS = String.fromCharCode(92); // backslash without source-escaping ambiguity
  var base = "/srv/uploads";
  var trav = "ok" + BS + ".." + BS + ".." + BS + "outside"; // ok\..\..\outside
  check("windows-target backslash traversal refused (resolveOrNull → null)",
    b.safePath.resolveOrNull(base, trav, { platform: "windows" }) === null);
  var v = b.safePath.validate(base, trav, { platform: "windows" });
  check("windows-target backslash traversal refused (validate ok=false)",
    v.ok === false && v.code === "safe-path/escapes-base");
  var threw = false, code = null;
  try { b.safePath.resolve(base, trav, { platform: "windows" }); }
  catch (e) { threw = true; code = e && e.code; }
  check("windows-target backslash traversal refused (resolve throws escapes-base)",
    threw === true && code === "safe-path/escapes-base");
  // A nested-but-in-base Windows path with backslashes still resolves.
  var ok = b.safePath.resolveOrNull(base, "a" + BS + "b" + BS + "c.txt", { platform: "windows" });
  check("windows-target in-base backslash path resolves",
    typeof ok === "string" && ok.indexOf("c.txt") !== -1);
}

// confineToBase is the lexical-containment core resolve() layers its
// user-input strictness on top of. It contains traversal (escape → null)
// while NOT pre-judging segment content — so a consumer that wants only
// containment and runs its own, separately-calibrated filename validation
// (b.staticServe, with a per-file b.guardFilename basename gate) composes it
// instead of resolve. That layering divergence is why the primitive exists.
function testConfineToBaseContainsWithoutUserInputStrictness() {
  var inRoot = b.safePath.confineToBase("/srv/www", "docs/a.html", { platform: "linux" });
  check("confineToBase resolves an in-base path",
    typeof inRoot === "string" && inRoot.indexOf("docs/a.html") !== -1);
  check("confineToBase refuses a `..` escape (→ null)",
    b.safePath.confineToBase("/srv/www", "../etc/passwd", { platform: "linux" }) === null);
  // The two entry points diverge on a colon-bearing segment: confineToBase
  // (pure containment) admits it; resolve() refuses it as a user-input ADS
  // marker. The consumer decides how to validate segment content separately.
  var colon = "2026-07-24T12:00:00.log";
  check("confineToBase admits a colon-bearing segment (no user-input strictness)",
    typeof b.safePath.confineToBase("/srv/www", colon, { platform: "linux" }) === "string");
  check("resolve() still refuses the same colon name (user-input strictness)",
    b.safePath.resolveOrNull("/srv/www", colon, { platform: "linux" }) === null);
  // Windows-target backslash traversal is contained by the target-platform
  // resolve, same as resolve()'s core.
  var BS = String.fromCharCode(92);
  check("confineToBase refuses a windows-target backslash traversal",
    b.safePath.confineToBase("/srv/www", "ok" + BS + ".." + BS + ".." + BS + "x", { platform: "windows" }) === null);
  check("confineToBase bad-input → null (empty base / non-string rel)",
    b.safePath.confineToBase("", "x") === null && b.safePath.confineToBase("/srv", 5) === null);
}

// The refusal shapes are character walks now. Each is compared against the
// pattern it replaced, over a corpus of the relative paths this primitive
// exists to refuse — so a walk that answers differently shows up here rather
// than as a path that quietly stops being refused.
function testRefusalShapesAgreeWithThePatternsTheyReplaced() {
  var CP = require("../../lib/codepoint-class");

  // The patterns as they were.
  var WIN_RESERVED_RE = /^(con|prn|aux|nul|com[0-9\u00B9\u00B2\u00B3]|lpt[0-9\u00B9\u00B2\u00B3]|conin\$|conout\$)(?:\..*)?$/i;
  var ENCODED_SEPARATOR_RE = new RegExp(
    "(%2[fF]|%5[cC]|%C0%AF|%C1%9C|[" +
    CP.charClass([0xFF0F, 0xFF3C, 0x2215, 0x29F8, 0x2044]) + "])");
  var C0_RE = new RegExp("[" + CP.charClass([[0x0001, 0x001F], 0x007F]) + "]");

  var RELS = [
    "a/b.txt", "user/avatar.png", "deep/nested/path/file", "", ".",
    "con", "CON", "con.txt", "console", "console.txt", "conin$", "CONOUT$.log",
    "com1", "com0", "com9", "com10", "lpt3", "lpt", "com", "aux.tar.gz",
    "nul", "nulx", "x/con/y", "x/console/y", "com" + String.fromCharCode(0xB9),
    "a%2Fb", "a%2fb", "A%5CB", "x%C0%AFy", "x%c1%9cy", "a%2Gb", "plain%20space",
    "a" + String.fromCharCode(0xFF0F) + "b", "a" + String.fromCharCode(0x2215) + "b",
    "a" + String.fromCharCode(0x29F8) + "b", "a" + String.fromCharCode(0x2044) + "b",
    "a" + String.fromCharCode(0xFF3C) + "b",
    "a" + String.fromCharCode(0x01) + "b", "a" + String.fromCharCode(0x1F) + "b",
    "a" + String.fromCharCode(0x7F) + "b", "a\tb", "a b",
    "C:/x", "c:\\x", "Z:/y", "1:/x", "CC:/x", "C:x", "//host/x", "\\\\srv\\s",
    "/abs", "rel/../x",
  ];

  var diffs = [];
  RELS.forEach(function (rel) {
    var caught = null;
    try { b.safePath.resolve("/srv", rel); } catch (e) { caught = e; }
    var code = caught === null ? null : caught.code;

    // Control characters, encoded separators and drive/UNC prefixes are
    // refused before anything else can, so the code identifies the shape.
    if (C0_RE.test(rel) && rel.indexOf("\0") === -1) {
      if (code !== "safe-path/control-char") diffs.push("control " + JSON.stringify(rel) + " -> " + code);
      return;
    }
    if (ENCODED_SEPARATOR_RE.test(rel)) {
      if (code !== "safe-path/separator-in-segment") {
        diffs.push("separator " + JSON.stringify(rel) + " -> " + code);
      }
      return;
    }
    var wasAbsolute = /^[A-Za-z]:[\\/]/.test(rel) || /^\\\\/.test(rel) ||
                      /^\/\//.test(rel) || rel.charAt(0) === "/";
    if (wasAbsolute) {
      if (code !== "safe-path/absolute-rel") diffs.push("absolute " + JSON.stringify(rel) + " -> " + code);
      return;
    }
    // Reserved names are decided per segment.
    var reserved = rel.split("/").some(function (seg) {
      if (seg.length === 0 || seg === "." || seg === "..") return false;
      var lc = seg.toLowerCase();
      var stem = lc.indexOf(".") === -1 ? lc : lc.slice(0, lc.indexOf("."));
      return WIN_RESERVED_RE.test(seg) || WIN_RESERVED_RE.test(stem);
    });
    if (reserved && code !== "safe-path/win-reserved") {
      diffs.push("reserved " + JSON.stringify(rel) + " -> " + code);
    }
    if (!reserved && code === "safe-path/win-reserved") {
      diffs.push("not-reserved-but-refused " + JSON.stringify(rel));
    }
  });
  check("every refusal shape agrees with the pattern it replaced (" +
        RELS.length + " paths)", diffs.length === 0, diffs.slice(0, 5).join(" | "));

  // The bidi set is now the shared table, which carries one codepoint the
  // local copy did not: the Arabic letter mark.
  var alm = null;
  try { b.safePath.resolve("/srv", "a" + String.fromCharCode(0x061C) + "b"); }
  catch (e) { alm = e; }
  check("the Arabic letter mark (U+061C) is refused as a bidi codepoint",
        alm !== null && alm.code === "safe-path/bidi");
  [0x200E, 0x200F, 0x202A, 0x202E, 0x2066, 0x2069].forEach(function (cp) {
    var err = null;
    try { b.safePath.resolve("/srv", "a" + String.fromCharCode(cp) + "b"); }
    catch (e) { err = e; }
    check("U+" + cp.toString(16).toUpperCase() + " is still refused as bidi",
          err !== null && err.code === "safe-path/bidi");
  });
}

function run() {
  testHappyPath();
  testRefusalClasses();
  testRefusalShapesAgreeWithThePatternsTheyReplaced();
  testWindowsTrailing();
  testResolveOrNullReturnsNull();
  testValidateReturnsVerdict();
  testErrorClassExported();
  testCrossPlatformContainment();
  testCrossPlatformBackslashTraversalRefused();
  testConfineToBaseContainsWithoutUserInputStrictness();
}

if (require.main === module) run();
module.exports = { run: run };
