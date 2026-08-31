// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * guard-email — Email content-safety primitive (b.guardEmail).
 *
 * Covers: surface; registry parity; SMTP smuggling (bare CR / bare LF
 * + smuggled SMTP verbs per CVE-2023-51764 / 51765 / 51766 class);
 * CRLF header injection; multi-@ rejection; IDN homograph (mixed-
 * script) detection; punycode flag; display-name spoofing; IP literal
 * detection; address-comment rejection; RFC 5321 length caps (local-
 * part 64 / domain 255 / address 320); RFC 5322 line cap (998); BOM
 * detection; bidi/null/control char detection; sanitize discipline;
 * gate composition; profile + posture vocabulary.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function testGuardEmailSurface() {
  check("guardEmail is an object",                       typeof b.guardEmail === "object");
  check("guardEmail.NAME === 'email'",                   b.guardEmail.NAME === "email");
  check("guardEmail.KIND === 'content'",                 b.guardEmail.KIND === "content");
  check("guardEmail.MIME_TYPES has message/rfc822",      b.guardEmail.MIME_TYPES.indexOf("message/rfc822") !== -1);
  check("guardEmail.EXTENSIONS has .eml",                b.guardEmail.EXTENSIONS.indexOf(".eml") !== -1);
  check("guardEmail.PROFILES has strict",                !!b.guardEmail.PROFILES["strict"]);
  check("guardEmail.PROFILES has balanced",              !!b.guardEmail.PROFILES["balanced"]);
  check("guardEmail.PROFILES has permissive",            !!b.guardEmail.PROFILES["permissive"]);
  check("guardEmail.COMPLIANCE_POSTURES has hipaa",      !!b.guardEmail.COMPLIANCE_POSTURES["hipaa"]);
  check("guardEmail.validate is a function",             typeof b.guardEmail.validate === "function");
  check("guardEmail.validateAddress is a function",      typeof b.guardEmail.validateAddress === "function");
  check("guardEmail.validateMessage is a function",      typeof b.guardEmail.validateMessage === "function");
  check("guardEmail.sanitize is a function",             typeof b.guardEmail.sanitize === "function");
  check("guardEmail.gate is a function",                 typeof b.guardEmail.gate === "function");
  check("frameworkError.GuardEmailError exposed",        typeof b.frameworkError.GuardEmailError === "function");
}

function testGuardEmailRegistryParity() {
  check("guardEmail registered in guardAll",
        b.guardAll.list().some(function (g) { return g.name === "email"; }));
}

function testGuardEmailCleanAddress() {
  var rv = b.guardEmail.validateAddress("alice@example.com", { profile: "strict" });
  check("clean address → ok=true",
        rv.ok === true && rv.issues.length === 0);
}

function testGuardEmailMultiAt() {
  var rv = b.guardEmail.validateAddress("a@b@c.com", { profile: "strict" });
  check("multi-@ detected (RFC 5322 violation)",
        rv.issues.some(function (i) { return i.kind === "multi-at"; }));
}

function testGuardEmailLengthCaps() {
  var local = new Array(67).join("a");                                            // 66 chars
  var rv = b.guardEmail.validateAddress(local + "@example.com", { profile: "strict" });
  check("local-part > 64 detected",
        rv.issues.some(function (i) { return i.kind === "local-part-cap"; }));

  var longDomain = "x@" + new Array(60).join("aaaaa") + ".com";                   // > 255 bytes
  var rvD = b.guardEmail.validateAddress(longDomain, { profile: "strict" });
  check("domain > 255 OR address > 320 detected",
        rvD.issues.some(function (i) {
          return i.kind === "domain-cap" || i.kind === "address-cap";
        }));
}

function testGuardEmailMultibyteByteCaps() {
  // A cap named in *Bytes must measure UTF-8 bytes, not UTF-16 .length code
  // units. A 2-byte codepoint (U+00E9, "e acute") counts as 1 code unit, so a
  // length-based comparison under-enforces: input over the byte cap slips
  // through. Build inputs whose byteLength EXCEEDS the cap while .length does
  // NOT, and assert each cap fires. Codepoint built programmatically so the
  // source stays pure ASCII.
  var acute = String.fromCodePoint(0x00e9);                                       // U+00E9 = 2 UTF-8 bytes
  var mb40  = new Array(41).join(acute);                                          // .length 40, 80 bytes
  var mb50  = new Array(51).join(acute);                                          // .length 50, 100 bytes

  // Message total-byte cap (maxBytes).
  var rvMsg = b.guardEmail.validateMessage(mb50, { profile: "strict", maxBytes: 60 });
  check("message maxBytes cap measures bytes (multibyte over byte cap → too-large)",
        rvMsg.issues.some(function (i) { return i.kind === "too-large"; }));

  // Total-address byte cap (maxAddressBytes).
  var rvAddr = b.guardEmail.validateAddress(mb40 + "@example.com",
    { profile: "strict", maxAddressBytes: 60, maxLocalPartBytes: 100000, maxDomainBytes: 100000 });
  check("address maxAddressBytes cap measures bytes (multibyte over byte cap → address-cap)",
        rvAddr.issues.some(function (i) { return i.kind === "address-cap"; }));

  // Local-part byte cap (maxLocalPartBytes).
  var rvLp = b.guardEmail.validateAddress(mb40 + "@example.com",
    { profile: "strict", maxLocalPartBytes: 60, maxAddressBytes: 100000, maxDomainBytes: 100000 });
  check("local-part maxLocalPartBytes cap measures bytes (multibyte over byte cap → local-part-cap)",
        rvLp.issues.some(function (i) { return i.kind === "local-part-cap"; }));

  // Domain byte cap (maxDomainBytes).
  var rvDom = b.guardEmail.validateAddress("a@" + mb40 + ".com",
    { profile: "strict", maxDomainBytes: 60, maxAddressBytes: 100000, maxLocalPartBytes: 100000 });
  check("domain maxDomainBytes cap measures bytes (multibyte over byte cap → domain-cap)",
        rvDom.issues.some(function (i) { return i.kind === "domain-cap"; }));

  // Header-line byte cap (maxHeaderLineBytes).
  var msg = "From: alice@example.com\r\nSubject: " + mb40 + "\r\n\r\nbody\r\n";
  var rvHdr = b.guardEmail.validateMessage(msg, { profile: "strict", maxHeaderLineBytes: 60 });
  check("header-line maxHeaderLineBytes cap measures bytes (multibyte over byte cap → header-line-cap)",
        rvHdr.issues.some(function (i) { return i.kind === "header-line-cap"; }));

  // ASCII regression: clean inputs are unchanged; a real over-cap ASCII
  // local-part still fires (byte count == code-unit count for ASCII).
  var cleanAddr = b.guardEmail.validateAddress("alice@example.com", { profile: "strict" });
  check("ASCII clean address unchanged (byte-cap fix is ASCII-transparent)",
        cleanAddr.ok === true && cleanAddr.issues.length === 0);
  var asciiLp = b.guardEmail.validateAddress(new Array(67).join("a") + "@example.com",
    { profile: "strict" });
  check("ASCII local-part > 64 still caps after byte-measure fix",
        asciiLp.issues.some(function (i) { return i.kind === "local-part-cap"; }));
}

function testGuardEmailIpLiteral() {
  var rv = b.guardEmail.validateAddress("user@[1.2.3.4]", { profile: "strict" });
  check("IP literal address detected (DMARC alignment bypass)",
        rv.issues.some(function (i) { return i.kind === "ip-literal"; }));
}

function testGuardEmailAddressComment() {
  var rv = b.guardEmail.validateAddress("alice(comment)@example.com", { profile: "strict" });
  check("RFC 5322 comment in address detected",
        rv.issues.some(function (i) {
          return i.kind === "address-comment" || i.kind === "address-syntax";
        }));
}

function testGuardEmailPunycode() {
  var rv = b.guardEmail.validateAddress("user@xn--ample-c0a.com", { profile: "strict" });
  check("Punycode/IDN domain detected (homograph spoofing risk)",
        rv.issues.some(function (i) { return i.kind === "punycode-domain"; }));
}

function testGuardEmailMixedScript() {
  // Cyrillic 'а' (U+0430) inside an otherwise-Latin domain.
  var domain = "user@exa" + String.fromCharCode(0x0430) + "mple.com";
  var rv = b.guardEmail.validateAddress(domain, { profile: "strict" });
  check("mixed-script Cyrillic-in-Latin domain detected (IDN homograph)",
        rv.issues.some(function (i) { return i.kind === "mixed-script-domain"; }));
}

function testGuardEmailUnicodeLocalPartRejected() {
  // Unicode local-part (RFC 6531 SMTPUTF8 / EAI) is NOT accepted — the
  // local-part is ASCII atext only (RFC 5321 §4.1.2 / RFC 5322 §3.2.3).
  // Build the accented codepoint programmatically so the source stays
  // pure ASCII (no attack characters as literals). U+00E9 = "e acute".
  var local = "u" + String.fromCodePoint(0x00e9) + "ser";
  var rv = b.guardEmail.validateAddress(local + "@example.com", { profile: "strict" });
  check("unicode local-part not accepted (no RFC 6531 EAI mailbox)",
        rv.ok === false);
  check("unicode local-part surfaces as address-syntax (ASCII-only contract)",
        rv.issues.some(function (i) { return i.kind === "address-syntax"; }));
}

function testGuardEmailSyntaxReject() {
  var rv = b.guardEmail.validateAddress("not an email", { profile: "strict" });
  check("malformed address → multi-at or address-syntax issue",
        rv.issues.some(function (i) {
          return i.kind === "multi-at" || i.kind === "address-syntax";
        }));
}

function testGuardEmailBareLfSmuggling() {
  // Bare LF in body — SMTP smuggling vector (CVE-2023-51765 / 51766).
  var msg = "From: a@example.com\r\nTo: b@example.com\r\nSubject: x\r\n\r\nbody\nMAIL FROM: <evil@x>\r\n";
  var rv = b.guardEmail.validateMessage(msg, { profile: "strict" });
  check("bare LF detected (SMTP smuggling vector class)",
        rv.issues.some(function (i) { return i.kind === "bare-lf"; }));
  check("smuggled SMTP verb after bare LF detected",
        rv.issues.some(function (i) { return i.kind === "smtp-smuggling"; }));
}

function testGuardEmailCrlfHeaderInjection() {
  // Build a header value that contains an embedded CRLF — header injection.
  // The unfolder collapses adjacent line; we simulate by injecting raw `\r\n`
  // into the value space without folding whitespace following it.
  var msg = "From: alice@example.com\r\nTo: bob@example.com\r\n" +
            "Subject: hi\r\nReply-To: a@x.com\rEvil-Header: x\r\n" +
            "\r\nbody\r\n";
  var rv = b.guardEmail.validateMessage(msg, { profile: "strict" });
  check("bare CR or CRLF-injected header detected",
        rv.issues.some(function (i) {
          return i.kind === "bare-cr" || i.kind === "crlf-header-injection";
        }));
}

function testGuardEmailAutoRouterHeaderInjection() {
  // The auto-router footgun: a value an operator intends as a single address
  // but that carries CRLF + an injected header. `validate` sees the newline,
  // treats it as a message, and (before the fix) the bare `a@b.com` line was
  // silently dropped while the injected `Bcc` passed — ok:true. The shared
  // mimeParse.classifyHeaderBlock now surfaces the colon-less header-section
  // line as malformed → ok:false.
  var rv = b.guardEmail.validate("a@b.com\r\nBcc: evil@x.com", { profile: "strict" });
  check("auto-router CRLF+injected-header → ok:false",
        rv.ok === false &&
        rv.issues.some(function (i) { return i.kind === "malformed-header-line"; }));

  // A bare address with a trailing CRLF is the same footgun shape.
  var rv2 = b.guardEmail.validate("alice@example.com\r\n", { profile: "strict" });
  check("auto-router address+trailing-CRLF → ok:false", rv2.ok === false);

  // A well-formed RFC 5322 message must still pass — header fields, folding, and
  // bare BODY lines after the blank boundary are all legitimate.
  var ok = b.guardEmail.validate(
    "From: a@example.com\r\nTo: b@example.com\r\nSubject: long\r\n folded\r\n" +
    "Date: Mon, 5 May 2026 10:00:00 +0000\r\n\r\nbare body line\r\nanother\r\n",
    { profile: "strict" });
  check("well-formed message (folding + body lines) still passes", ok.ok === true);
}

function testGuardEmailDisplayNameSpoof() {
  var msg = 'From: "support@apple.com" <attacker@evil.com>\r\n' +
            "To: bob@example.com\r\nSubject: x\r\n\r\nbody\r\n";
  var rv = b.guardEmail.validateMessage(msg, { profile: "strict" });
  check("display-name spoofing (impersonating apple.com) detected",
        rv.issues.some(function (i) { return i.kind === "display-name-spoof"; }));
}

function testGuardEmailBom() {
  var msg = String.fromCharCode(0xfeff) +
            "From: alice@example.com\r\nTo: bob@example.com\r\n" +
            "Subject: x\r\n\r\nbody\r\n";
  var rv = b.guardEmail.validateMessage(msg, { profile: "strict" });
  check("BOM at start of message detected",
        rv.issues.some(function (i) { return i.kind === "bom"; }));
}

function testGuardEmailHeaderLineCap() {
  var bigSubject = "Subject: " + new Array(1010).join("x");                       // > 998 bytes
  var msg = "From: alice@example.com\r\nTo: bob@example.com\r\n" +
            bigSubject + "\r\n\r\nbody\r\n";
  var rv = b.guardEmail.validateMessage(msg, { profile: "strict" });
  check("header-line cap (RFC 5322 998) detected",
        rv.issues.some(function (i) { return i.kind === "header-line-cap"; }));
}

function testGuardEmailBidiInAddress() {
  var bidi = String.fromCharCode(0x202e);
  var rv = b.guardEmail.validateAddress("a" + bidi + "b@example.com", { profile: "strict" });
  check("bidi override in address detected",
        rv.issues.some(function (i) { return i.kind === "bidi-override"; }));
}

function testGuardEmailCleanMessage() {
  var msg = "From: alice@example.com\r\nTo: bob@example.com\r\n" +
            "Subject: hi\r\nDate: Mon, 5 May 2026 10:00:00 +0000\r\n\r\n" +
            "Hello.\r\n";
  var rv = b.guardEmail.validateMessage(msg, { profile: "strict" });
  check("clean RFC 5322 message → ok=true",
        rv.ok === true && rv.issues.length === 0);
}

function testGuardEmailSanitizeRefusesCritical() {
  var msg = "From: alice@example.com\r\nTo: bob@example.com\r\n" +
            "Subject: x\r\n\r\nbody\nMAIL FROM: <evil@x>\r\n";
  var threw = null;
  try { b.guardEmail.sanitize(msg, { profile: "balanced" }); }
  catch (e) { threw = e; }
  check("sanitize refuses SMTP smuggling pattern",
        threw && /smuggling|bare-lf|refused/.test(threw.code || threw.message || ""));
}

async function testGuardEmailGate() {
  var g = b.guardEmail.gate({ profile: "strict" });
  var clean = await g.check({
    contentType: "message/rfc822",
    bytes:       Buffer.from("From: a@x.com\r\nTo: b@y.com\r\nSubject: ok\r\n" +
                             "Date: Mon, 5 May 2026 00:00:00 +0000\r\n\r\nbody\r\n", "utf8"),
  });
  check("gate clean → action=serve",
        clean.ok === true && clean.action === "serve");

  var hostile = await g.check({
    contentType: "message/rfc822",
    bytes:       Buffer.from("From: a@x.com\r\nTo: b@y.com\r\nSubject: x\r\n\r\n" +
                             "body\nMAIL FROM: <evil@x>\r\n", "utf8"),
  });
  check("gate SMTP smuggling → action !== serve",
        hostile.action !== "serve");
}

function testGuardEmailCompliancePosture() {
  var hipaa = b.guardEmail.compliancePosture("hipaa");
  check("compliancePosture('hipaa') sets reject policies",
        hipaa.smtpSmugglingPolicy === "reject" &&
        hipaa.crlfHeaderInjectionPolicy === "reject");
  var threw = null;
  try { b.guardEmail.compliancePosture("unknown"); }
  catch (e) { threw = e; }
  check("compliancePosture: unknown name throws",
        threw && /unknown/.test(threw.message));
}

// The address, IP-literal, punycode, smuggling and display-name shapes are
// character walks. Each is compared against the pattern it replaced, over a
// corpus of the addresses and messages this guard exists to classify.
function testAddressShapesAgreeWithThePatternsTheyReplaced() {
  var api = b.guardEmail._shapesForTest;

  var _LOCAL = "[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+";
  var _LABEL = "[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?";
  var _DOMAIN = "(?:" + _LABEL + "(?:\\." + _LABEL + ")+)";
  var ADDRESS_RE = new RegExp("^(" + _LOCAL + ")@(" + _DOMAIN + ")$");
  var IP_LITERAL_RE = /^[^@]+@\[[^\]]+\]$/;
  var PUNYCODE_LABEL_RE = /(?:^|\.)xn--/i;
  var SMUGGLED_VERB_RE = /(?:\r(?!\n)|(?<!\r)\n)\.?\s*(?:MAIL FROM|RCPT TO|DATA|EHLO|HELO|RSET|QUIT)\b/i;
  var DISPLAY_PHRASE_ANGLE_RE = /^\s*(.*?)\s*<\s*([^>]+)\s*>\s*$/;

  var ADDRESSES = [
    "", "a", "@", "a@", "@b", "a@b", "a@b.c", "user@example.com",
    "user.name+tag@example.co.uk", "a@b@c.com", "user@@example.com",
    "user@[1.2.3.4]", "user@[::1]", "user@[]", "user@[a]b", "u@[1.2]3.4]",
    "user@example", "user@.com", "user@com.", "user@-a.com", "user@a-.com",
    "user@a--b.com", "user@" + "a".repeat(63) + ".com",
    "user@" + "a".repeat(64) + ".com",
    "user@xn--80ak6aa92e.com", "user@sub.xn--p1ai", "user@XN--P1AI.com",
    "user@notxn--a.com", "us er@example.com", "us(er@example.com",
    "user@example.com ", "caf" + String.fromCharCode(0xE9) + "@example.com",
    "user@caf" + String.fromCharCode(0xE9) + ".com", "!#$%&'*+/=?^_@a.bb",
  ];
  var strictDiffs = [], ipDiffs = [], punyDiffs = [];
  ADDRESSES.forEach(function (a) {
    if (ADDRESS_RE.test(a) !== api.isStrictAddress(a)) strictDiffs.push(JSON.stringify(a));
    if (IP_LITERAL_RE.test(a) !== api.isIpLiteralAddress(a)) ipDiffs.push(JSON.stringify(a));
    var at = a.lastIndexOf("@");
    var domain = at === -1 ? "" : a.slice(at + 1);
    if (PUNYCODE_LABEL_RE.test(domain) !== api.hasPunycodeLabel(domain)) {
      punyDiffs.push(JSON.stringify(domain));
    }
  });
  check("the strict-address walk agrees with the pattern it replaced",
        strictDiffs.length === 0, strictDiffs.slice(0, 4).join(" | "));
  check("the IP-literal walk agrees with the pattern it replaced",
        ipDiffs.length === 0, ipDiffs.slice(0, 4).join(" | "));
  check("the punycode-label walk agrees with the pattern it replaced",
        punyDiffs.length === 0, punyDiffs.slice(0, 4).join(" | "));

  var MESSAGES = [
    "", "Subject: x\r\n\r\nbody", "Subject: x\r\n\r\nbody\r\nDATA\r\n",
    "a\rMAIL FROM:<x>", "a\nRCPT TO:<x>", "a\r\nDATA", "a\n.DATA",
    "a\n . data", "a\nDATABASE", "a\ndatalink", "a\rquit", "a\rQUIT",
    "a\n\tEHLO x", "a\r\n\r\n.\r\nMAIL FROM:<y>", "no bare endings here\r\n",
    "trailing\r", "\nDATA", "\rHELO x", "body\n.\nRSET",
  ];
  var smugDiffs = [];
  MESSAGES.forEach(function (m) {
    if (SMUGGLED_VERB_RE.test(m) !== api.hasSmuggledVerb(m)) {
      smugDiffs.push(JSON.stringify(m));
    }
  });
  check("the SMTP-smuggling walk agrees with the pattern it replaced",
        smugDiffs.length === 0, smugDiffs.slice(0, 4).join(" | "));

  var LINES = [
    "", "a@b.com", "<a@b.com>", "Name <a@b.com>", "  Name   <a@b.com>  ",
    "\"Name\" <a@b.com>", "\"a>b\" <x@y.com>", "a>b <x@y.com>",
    "Name <>", "Name < >", "Name <  a@b.com  >", "Name <a@b.com",
    "Name a@b.com>", "Name <a@b><c@d>", "Name <a<b@c.com>",
    "Support <support@apple.com> <evil@bad.com>",
    "line\nbreak <a@b.com>", "line\rbreak <a@b.com>",
    "\n  Name <a@b.com>", "Name <a@b.com>\n",
  ];
  var parseDiffs = [];
  LINES.forEach(function (line) {
    var m = line.match(DISPLAY_PHRASE_ANGLE_RE);
    var expected = m
      ? { display: m[1].replace(/^"|"$/g, ""), envelope: m[2] }
      : { display: "", envelope: line.trim() };
    var actual = api.parseAddressLine(line);
    if (expected.display !== actual.display || expected.envelope !== actual.envelope) {
      parseDiffs.push(JSON.stringify(line) + " want " + JSON.stringify(expected) +
                      " got " + JSON.stringify(actual));
    }
  });
  check("the display-name split agrees with the pattern it replaced",
        parseDiffs.length === 0, parseDiffs.slice(0, 3).join(" | "));

  var SECTIONS = ["", "a", "a\nb", "a\r\nb", "a\r\nb\nc", "\n", "\r\n",
                  "a\n\nb", "a\rb", "a\r\n", "a\n"];
  var splitDiffs = [];
  SECTIONS.forEach(function (s) {
    var ref = s.split(/\r?\n/);
    var got = api.splitLines(s);
    if (JSON.stringify(ref) !== JSON.stringify(got)) {
      splitDiffs.push(JSON.stringify(s) + " want " + JSON.stringify(ref) +
                      " got " + JSON.stringify(got));
    }
  });
  check("the header-line split agrees with the pattern it replaced",
        splitDiffs.length === 0, splitDiffs.slice(0, 3).join(" | "));
}

// The smuggled-verb scan looks for an SMTP verb after a bare line ending. It
// skipped whitespace by walking forward from every bare ending it found, and a
// carriage return is itself whitespace, so a value that is nothing but bare
// carriage returns made it re-walk the same run once per position: time
// proportional to the SQUARE of the value. A guard is handed hostile input by
// definition, so this is the one place that shape is guaranteed to arrive.
function testSmuggledVerbScanIsLinear() {
  function _ms(n) {
    var subject = "\r".repeat(n);
    try { b.guardEmail.sanitize(subject); } catch (_e) { /* refusal is fine */ }
    var best = Infinity;
    for (var k = 0; k < 3; k += 1) {
      var t0 = process.hrtime.bigint();
      try { b.guardEmail.sanitize(subject); } catch (_e2) { /* timing the work */ }
      best = Math.min(best, Number(process.hrtime.bigint() - t0) / 1e6);
    }
    return best;
  }
  var small = _ms(2000);
  var large = _ms(8000);
  // Four times the input is about four times the work when the scan is linear
  // and about sixteen when it is quadratic. Growth rather than a wall-clock
  // budget, so a loaded machine moves both readings together.
  var ratio = small > 0.05 ? (large / small) : 1;
  check("a value of bare carriage returns is scanned in linear time",
        ratio < 8, "4x input took " + ratio.toFixed(1) + "x the time (" +
        small.toFixed(1) + "ms -> " + large.toFixed(1) + "ms)");

  // The detection itself is unchanged: a bare ending followed by a verb is
  // still smuggling, and one followed by ordinary text is still not.
  var smuggled = b.guardEmail.validateMessage("Subject: hi\r.\r\n RCPT TO: <x@y.example>");
  check("a bare ending before an SMTP verb is still detected",
        smuggled && smuggled.ok === false);
  var clean = b.guardEmail.validateMessage("Subject: hi\r\nTo: a@b.example\r\n\r\nbody text\r\n");
  check("an ordinary message is still accepted", clean && clean.ok === true,
        JSON.stringify(clean && clean.issues));
}

async function run() {
  testSmuggledVerbScanIsLinear();
  testAddressShapesAgreeWithThePatternsTheyReplaced();
  testGuardEmailSurface();
  testGuardEmailRegistryParity();
  testGuardEmailCleanAddress();
  testGuardEmailMultiAt();
  testGuardEmailLengthCaps();
  testGuardEmailMultibyteByteCaps();
  testGuardEmailIpLiteral();
  testGuardEmailAddressComment();
  testGuardEmailPunycode();
  testGuardEmailMixedScript();
  testGuardEmailUnicodeLocalPartRejected();
  testGuardEmailSyntaxReject();
  testGuardEmailBareLfSmuggling();
  testGuardEmailCrlfHeaderInjection();
  testGuardEmailAutoRouterHeaderInjection();
  testGuardEmailDisplayNameSpoof();
  testGuardEmailBom();
  testGuardEmailHeaderLineCap();
  testGuardEmailBidiInAddress();
  testGuardEmailCleanMessage();
  testGuardEmailSanitizeRefusesCritical();
  testGuardEmailCompliancePosture();
  await testGuardEmailGate();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[guard-email] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
