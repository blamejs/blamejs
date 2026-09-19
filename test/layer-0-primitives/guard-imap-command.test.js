// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var helpers = require("../helpers");
var check = helpers.check;
var b = helpers.b;

function testSurface() {
  check("namespace present",         typeof b.guardImapCommand === "object");
  check("validate is fn",            typeof b.guardImapCommand.validate === "function");
  check("detectLiteralSmuggling fn", typeof b.guardImapCommand.detectLiteralSmuggling === "function");
  check("compliancePosture fn",      typeof b.guardImapCommand.compliancePosture === "function");
  check("PROFILES has strict/balanced/permissive",
        ["strict","balanced","permissive"].every(function (p) { return b.guardImapCommand.PROFILES[p]; }));
  check("GuardImapCommandError class is fn",
        typeof b.guardImapCommand.GuardImapCommandError === "function");
  // Verify the error class matches what validate throws on refusal
  var threw = null;
  try { b.guardImapCommand.validate(""); } catch (e) { threw = e; }
  check("validate refusal throws GuardImapCommandError",
        threw instanceof b.guardImapCommand.GuardImapCommandError);
}

function testHappyPath() {
  var p = b.guardImapCommand.validate("A001 LOGIN alice secret");
  check("LOGIN: tag", p.tag === "A001");
  check("LOGIN: verb", p.verb === "LOGIN");
  check("LOGIN: args", p.args === "alice secret");
  check("LOGIN: no literal", p.literalSize === null);

  var s = b.guardImapCommand.validate("A002 SELECT INBOX");
  check("SELECT: parsed", s.tag === "A002" && s.verb === "SELECT" && s.args === "INBOX");

  var n = b.guardImapCommand.validate("A003 NOOP");
  check("NOOP: zero-arg parsed", n.verb === "NOOP" && n.args === "");

  var pending = b.guardImapCommand.validate("A004 APPEND INBOX {1024}");
  check("APPEND with literal: size captured", pending.literalSize === 1024);
  check("APPEND with literal: not non-sync",  pending.literalNonSync === false);

  var pendingPlus = b.guardImapCommand.validate("A005 APPEND INBOX {1024+}",
    { profile: "balanced", authenticated: true });
  check("APPEND LITERAL+: non-sync captured under balanced + authenticated",
    pendingPlus.literalSize === 1024 && pendingPlus.literalNonSync === true);
}

function testBadInputRefused() {
  function expectThrow(label, fn, codeMatch) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf(codeMatch) !== -1);
  }
  expectThrow("refuses non-string", function () {
    b.guardImapCommand.validate(null);
  }, "guard-imap-command/bad-input");
  expectThrow("refuses empty line", function () {
    b.guardImapCommand.validate("");
  }, "guard-imap-command/empty-line");
  expectThrow("refuses missing verb", function () {
    b.guardImapCommand.validate("A001NOSPACE");
  }, "guard-imap-command/missing-verb");
  expectThrow("refuses bad tag", function () {
    b.guardImapCommand.validate("* LOGIN a b");   // server-untagged reserved
  }, "guard-imap-command/bad-tag");
  expectThrow("refuses bad tag continuation", function () {
    b.guardImapCommand.validate("+ LOGIN a b");   // continuation marker reserved
  }, "guard-imap-command/bad-tag");
  expectThrow("refuses oversize tag", function () {
    var tag = ""; for (var i = 0; i < 65; i++) tag += "A";
    b.guardImapCommand.validate(tag + " LOGIN a b");
  }, "guard-imap-command/bad-tag");
  expectThrow("refuses unknown verb", function () {
    b.guardImapCommand.validate("A001 FROBNICATE");
  }, "guard-imap-command/unknown-verb");
  expectThrow("refuses args on zero-arg verb", function () {
    b.guardImapCommand.validate("A001 NOOP extra");
  }, "guard-imap-command/unexpected-args");
  expectThrow("refuses bad profile name", function () {
    b.guardImapCommand.validate("A001 LOGIN a b", { profile: "wide-open" });
  }, "guard-imap-command/bad-profile");
}

function testSmugglingDefense() {
  // Bare LF refused under strict
  var threw1 = null;
  try { b.guardImapCommand.validate("A001 LOGIN a\nb"); } catch (e) { threw1 = e; }
  check("refuses bare-LF in command (strict)",
    threw1 && threw1.code === "guard-imap-command/bad-byte");

  // Bare CR refused
  var threw2 = null;
  try { b.guardImapCommand.validate("A001 LOGIN a\rb"); } catch (e) { threw2 = e; }
  check("refuses bare-CR in command",
    threw2 && threw2.code === "guard-imap-command/bad-byte");

  // NUL refused
  var threw3 = null;
  try { b.guardImapCommand.validate("A001 LOGIN a\x00b"); } catch (e) { threw3 = e; }
  check("refuses NUL in command",
    threw3 && threw3.code === "guard-imap-command/bad-byte");

  // C0 control refused
  var threw4 = null;
  try { b.guardImapCommand.validate("A001 LOGIN a\u0008b"); } catch (e) { threw4 = e; }
  check("refuses C0 control (BS)",
    threw4 && threw4.code === "guard-imap-command/bad-byte");

  // Tab (0x09) allowed — RFC 9051 §9 atom-specials excludes HT
  var p = b.guardImapCommand.validate("A001 LOGIN a\tb");
  check("allows TAB inside args", p.verb === "LOGIN");

  // Permissive allows bare-LF
  var pl = b.guardImapCommand.validate("A001 LOGIN a\nb", { profile: "permissive" });
  check("permissive accepts bare-LF", pl.verb === "LOGIN");
}

function testLiteralInjection() {
  check("detectLiteralSmuggling: mid-line {n} → true",
    b.guardImapCommand.detectLiteralSmuggling("A001 APPEND INBOX {10} smuggled") === true);
  check("detectLiteralSmuggling: end-of-line {n} → false",
    b.guardImapCommand.detectLiteralSmuggling("A001 APPEND INBOX {10}") === false);
  check("detectLiteralSmuggling: end-of-line {n+} (LITERAL+) → false",
    b.guardImapCommand.detectLiteralSmuggling("A001 APPEND INBOX {10+}") === false);
  check("detectLiteralSmuggling: no literal → false",
    b.guardImapCommand.detectLiteralSmuggling("A001 LOGIN alice secret") === false);
  check("detectLiteralSmuggling: non-string input → false",
    b.guardImapCommand.detectLiteralSmuggling(null) === false);

  // validate() must refuse smuggling shape
  var threwSmug = null;
  try { b.guardImapCommand.validate("A001 APPEND INBOX {10} hostile"); } catch (e) { threwSmug = e; }
  check("validate refuses mid-line literal opener",
    threwSmug && threwSmug.code === "guard-imap-command/literal-smuggling");
}

function testLiteralCaps() {
  // Strict caps literal at 64 MiB; refuse a 128 MiB request
  var threw = null;
  try { b.guardImapCommand.validate("A001 APPEND INBOX {134217729}"); }
  catch (e) { threw = e; }
  check("refuses oversize literal under strict",
    threw && threw.code === "guard-imap-command/literal-too-large");

  // LITERAL+ refused under strict (default-off)
  var threw2 = null;
  try { b.guardImapCommand.validate("A001 APPEND INBOX {10+}"); }
  catch (e) { threw2 = e; }
  check("LITERAL+ refused under strict",
    threw2 && threw2.code === "guard-imap-command/literal-plus-refused");

  // LITERAL+ refused pre-auth even under balanced (RFC 7888 §1)
  var threw3 = null;
  try { b.guardImapCommand.validate("A001 APPEND INBOX {10+}",
        { profile: "balanced", authenticated: false }); }
  catch (e) { threw3 = e; }
  check("LITERAL+ refused pre-auth under balanced",
    threw3 && threw3.code === "guard-imap-command/literal-plus-pre-auth");
}

function testCompliancePosture() {
  check("compliancePosture hipaa → strict",
    b.guardImapCommand.compliancePosture("hipaa") === "strict");
  check("compliancePosture pci-dss → strict",
    b.guardImapCommand.compliancePosture("pci-dss") === "strict");
  check("compliancePosture gdpr → strict",
    b.guardImapCommand.compliancePosture("gdpr") === "strict");
  check("compliancePosture soc2 → strict",
    b.guardImapCommand.compliancePosture("soc2") === "strict");
  check("compliancePosture unknown → null",
    b.guardImapCommand.compliancePosture("nope") === null);

  // posture opt routes through to strict caps
  var threw = null;
  try {
    b.guardImapCommand.validate("A001 APPEND INBOX {10+}",
      { posture: "hipaa", authenticated: true });
  } catch (e) { threw = e; }
  check("posture: hipaa forces strict (LITERAL+ refused)",
    threw && threw.code === "guard-imap-command/literal-plus-refused");
}

function testByteCapMultibyte() {
  // Regression: maxLineBytes is a BYTE cap. A multibyte line whose char
  // count is under the cap but whose byte count exceeds it must be refused.
  var line = String.fromCharCode(0x4e2d).repeat(2731); // 2731 chars / 8193 UTF-8 bytes; strict cap 8192
  var threw = null;
  try { b.guardImapCommand.validate(line, { profile: "strict" }); } catch (e) { threw = e; }
  check("imap byte-cap: oversize multibyte line refused as line-too-long",
    threw && threw.code === "guard-imap-command/line-too-long");
  check("imap byte-cap: error reports byte count (8193), not char count",
    threw && threw.message.indexOf("8193 bytes") !== -1);
}

function testProfilePrototypeKeyRefused() {
  // A profile / posture name that collides with a JS prototype-key
  // (constructor / __proto__ / toString / ...) must resolve to
  // bad-profile, never silently disable the caps. Pre-fix the resolver
  // read PROFILES[profileName] by bracket access, so PROFILES["constructor"]
  // was the inherited Object function — truthy — and `if (!caps)` never
  // fired; every size / literal cap then compared against `undefined`
  // (always false) and failed open.
  var protoKeys = ["constructor", "__proto__", "toString", "valueOf", "hasOwnProperty"];
  for (var i = 0; i < protoKeys.length; i += 1) {
    var threw = null;
    try { b.guardImapCommand.validate("A001 NOOP", { profile: protoKeys[i] }); }
    catch (e) { threw = e; }
    check("profile '" + protoKeys[i] + "' refused as bad-profile",
      threw && threw.code === "guard-imap-command/bad-profile");
  }
  // Concrete fail-open proof: an oversize literal the strict cap
  // (67108864) refuses must NOT be accepted under a prototype-key profile.
  var threwLit = null;
  try { b.guardImapCommand.validate("A002 APPEND INBOX {999999999999}", { profile: "constructor" }); }
  catch (e) { threwLit = e; }
  check("prototype-key profile does not fail open on the literal cap",
    threwLit && threwLit.code === "guard-imap-command/bad-profile");
}

// A listener that REFUSES a line needs the size the line announced, to decide
// what to do with the octets the client is sending: with `{n+}` (RFC 7888) the
// payload is already in flight and has to be consumed before the next line is
// parsed, or it is parsed as commands. `validate` cannot answer that, because
// on a refusal it throws. The reader reports the size as announced, with no
// cap applied, so the caller can refuse a size it will not read.
function testAnnouncedLiteral() {
  var ROWS = [
    { line: "a1 APPEND INBOX {24+}", size: 24, nonSync: true },
    { line: "a1 APPEND INBOX {24}",  size: 24, nonSync: false },
    { line: "a1 APPEND INBOX {0+}",  size: 0,  nonSync: true },
    // Announced sizes far above any cap are reported, not clamped or refused.
    { line: "a1 APPEND INBOX {999999999999+}", size: 999999999999, nonSync: true },
    { line: "a1 NOOP",                 want: null },
    { line: "a1 APPEND INBOX {24",     want: null },
    { line: "a1 APPEND INBOX {}",      want: null },
    { line: "a1 APPEND INBOX {2x}",    want: null },
    // An opener that is not at the end of the line is not the command's
    // literal: RFC 9051 section 2.2.2 puts it last, and the smuggling
    // detector is what refuses this shape.
    { line: "a1 APPEND {5+} INBOX",    want: null },
    { line: "",                        want: null },
  ];
  var wrong = [];
  for (var i = 0; i < ROWS.length; i += 1) {
    var got = b.guardImapCommand.announcedLiteral(ROWS[i].line);
    if (ROWS[i].want === null) {
      if (got !== null) wrong.push(JSON.stringify(ROWS[i].line) + " -> " + JSON.stringify(got));
      continue;
    }
    if (!got || got.size !== ROWS[i].size || got.nonSync !== ROWS[i].nonSync) {
      wrong.push(JSON.stringify(ROWS[i].line) + " -> " + JSON.stringify(got));
    }
  }
  check("announcedLiteral reads the size and the synchronizing form" +
    (wrong.length ? " (" + wrong.join("; ") + ")" : ""), wrong.length === 0);
  check("a non-string line reads as no literal",
    b.guardImapCommand.announcedLiteral(null) === null &&
    b.guardImapCommand.announcedLiteral(undefined) === null &&
    b.guardImapCommand.announcedLiteral(42) === null);
}

function run() {
  testByteCapMultibyte();
  testSurface();
  testHappyPath();
  testBadInputRefused();
  testSmugglingDefense();
  testLiteralInjection();
  testAnnouncedLiteral();
  testLiteralCaps();
  testProfilePrototypeKeyRefused();
  testCompliancePosture();
}

module.exports = { run: run };

if (require.main === module) {
  try { run(); console.log("[guard-imap-command] OK"); }
  catch (e) { process.stderr.write("FAIL: " + (e && e.stack || e) + "\n"); process.exit(1); }
}
