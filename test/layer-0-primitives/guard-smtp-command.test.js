// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.guardSmtpCommand — SMTP command-line validator. Tests bare-CR /
 * bare-LF refusal (smuggling defense per CVE-2023-51764/51765/51766/
 * 2026-32178), per-verb shape checks, and caps.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function _throws(label, fn, code) {
  var threw = null;
  try { fn(); }
  catch (e) { threw = e; }
  check(label, threw && threw.code === code);
}

function testSurface() {
  check("validate is fn",          typeof b.guardSmtpCommand.validate === "function");
  check("gate is fn",              typeof b.guardSmtpCommand.gate === "function");
  check("compliancePosture is fn", typeof b.guardSmtpCommand.compliancePosture === "function");
  check("PROFILES frozen",         Object.isFrozen(b.guardSmtpCommand.PROFILES));
  check("KNOWN_VERBS frozen",      Object.isFrozen(b.guardSmtpCommand.KNOWN_VERBS));
  check("GuardSmtpCommandError",   typeof b.guardSmtpCommand.GuardSmtpCommandError === "function");
  check("NAME=smtpCommand",        b.guardSmtpCommand.NAME === "smtpCommand");
  check("KIND=identifier",         b.guardSmtpCommand.KIND === "identifier");
}

function testParsesGreeting() {
  var p = b.guardSmtpCommand.validate("EHLO mail.example.com");
  check("EHLO verb",       p.verb === "EHLO");
  check("EHLO arg",        p.args[0] === "mail.example.com");
  check("EHLO no params",  Object.keys(p.params).length === 0);

  var helo = b.guardSmtpCommand.validate("HELO mail.example.com");
  check("HELO verb",       helo.verb === "HELO");

  var addrLit = b.guardSmtpCommand.validate("EHLO [192.0.2.1]");
  check("EHLO addr-literal", addrLit.args[0] === "[192.0.2.1]");

  var v6 = b.guardSmtpCommand.validate("EHLO [IPv6:2001:db8::1]");
  check("EHLO IPv6 addr-literal", v6.args[0] === "[IPv6:2001:db8::1]");
}

function testParsesMailFrom() {
  var p = b.guardSmtpCommand.validate("MAIL FROM:<alice@example.com>");
  check("MAIL verb",         p.verb === "MAIL");
  check("MAIL path",         p.args[0] === "<alice@example.com>");

  var withExt = b.guardSmtpCommand.validate("MAIL FROM:<a@b.com> SIZE=12345 BODY=8BITMIME");
  check("MAIL ext params",   withExt.params.SIZE === "12345");
  check("MAIL ext flag",     withExt.params.BODY === "8BITMIME");

  // Bounce sender — empty path is valid for MAIL FROM
  var bounce = b.guardSmtpCommand.validate("MAIL FROM:<>");
  check("MAIL empty path (bounce)", bounce.args[0] === "<>");
}

function testParsesRcptTo() {
  var p = b.guardSmtpCommand.validate("RCPT TO:<bob@example.com>");
  check("RCPT verb",         p.verb === "RCPT");
  check("RCPT path",         p.args[0] === "<bob@example.com>");

  // Empty forward-path refused
  _throws("RCPT TO:<> refused", function () {
    b.guardSmtpCommand.validate("RCPT TO:<>");
  }, "guard-smtp-command/empty-path");
}

function testRefusesBareCr() {
  _throws("bare CR refused",
    function () { b.guardSmtpCommand.validate("EHLO mail\rmalicious"); },
    "guard-smtp-command/bare-cr");
}

function testRefusesBareLf() {
  _throws("bare LF refused",
    function () { b.guardSmtpCommand.validate("EHLO mail\nmalicious"); },
    "guard-smtp-command/bare-lf");
}

function testPermissiveAcceptsBareLf() {
  // PR #58 Codex P2: permissive profile documents allowBareLf=true
  // but the control-char loop was rejecting 0x0a regardless. Verify
  // the documented legacy-Sendmail compat path actually accepts LF.
  // The line still needs valid SMTP shape after the LF.
  var line = "MAIL FROM:<a@b.com>";
  var parsed = b.guardSmtpCommand.validate(line, { profile: "permissive" });
  check("permissive accepts MAIL FROM (sanity)", parsed.verb === "MAIL");
  // With bare LF embedded — should now NOT throw under permissive.
  var withLf = b.guardSmtpCommand.validate("MAIL FROM:<a@b.com>\nlegacy", { profile: "permissive" });
  check("permissive accepts bare LF in line (Codex P2 fix)", withLf.verb === "MAIL");
  // Strict still rejects.
  var threw = null;
  try { b.guardSmtpCommand.validate("MAIL FROM:<a@b.com>\nlegacy"); }
  catch (e) { threw = e; }
  check("strict still rejects bare LF", threw && threw.code === "guard-smtp-command/bare-lf");
}

function testRefusesNul() {
  _throws("NUL refused",
    function () { b.guardSmtpCommand.validate("EHLO mail" + String.fromCharCode(0) + "x"); },
    "guard-smtp-command/nul");
}

function testRefusesC0Control() {
  _throws("C0 0x01 refused",
    function () { b.guardSmtpCommand.validate("EHLO mail" + String.fromCharCode(1)); },
    "guard-smtp-command/control-char");
}

function testRefusesDel() {
  _throws("DEL refused",
    function () { b.guardSmtpCommand.validate("EHLO mail" + String.fromCharCode(0x7f)); },
    "guard-smtp-command/control-char");
}

function testRefusesNonAsciiUnderStrict() {
  _throws("non-ASCII refused under strict",
    function () { b.guardSmtpCommand.validate("EHLO mαil.example.com"); },
    "guard-smtp-command/non-ascii");

  // Balanced accepts SMTPUTF8 (RFC 6531) for mailbox local-part in
  // MAIL FROM — EHLO hostnames still want the A-label form, so the
  // realistic SMTPUTF8 surface is the mailbox path.
  var p = b.guardSmtpCommand.validate("MAIL FROM:<αlice@example.com>", { profile: "balanced" });
  check("SMTPUTF8 mailbox accepted under balanced", p.verb === "MAIL");
}

function testRefusesOversizeLine() {
  // Pad past strict cap of 512.
  var pad = "x".repeat(600);
  _throws("oversize line refused",
    function () { b.guardSmtpCommand.validate("MAIL FROM:<" + pad + "@example.com>"); },
    "guard-smtp-command/oversize-line");
}

function testRefusesUnknownVerb() {
  _throws("unknown verb refused",
    function () { b.guardSmtpCommand.validate("BOGUS arg"); },
    "guard-smtp-command/unknown-verb");
}

function testRefusesZeroArgVerbWithArgs() {
  _throws("DATA with args refused",
    function () { b.guardSmtpCommand.validate("DATA extra"); },
    "guard-smtp-command/unexpected-args");
  _throws("STARTTLS with args refused (CVE-2021-38371 / -33515 class)",
    function () { b.guardSmtpCommand.validate("STARTTLS extra"); },
    "guard-smtp-command/unexpected-args");
}

function testZeroArgVerbsAccepted() {
  check("DATA accepted",     b.guardSmtpCommand.validate("DATA").verb === "DATA");
  check("RSET accepted",     b.guardSmtpCommand.validate("RSET").verb === "RSET");
  check("QUIT accepted",     b.guardSmtpCommand.validate("QUIT").verb === "QUIT");
  check("STARTTLS accepted", b.guardSmtpCommand.validate("STARTTLS").verb === "STARTTLS");
}

function testBdat() {
  var p = b.guardSmtpCommand.validate("BDAT 1024");
  check("BDAT chunk size",    p.args[0] === "1024");
  check("BDAT not LAST",      !p.params.LAST);
  var last = b.guardSmtpCommand.validate("BDAT 512 LAST");
  check("BDAT LAST",          last.params.LAST === true);
  _throws("BDAT bad chunk-size",
    function () { b.guardSmtpCommand.validate("BDAT not-a-number"); },
    "guard-smtp-command/bad-shape");
}

function testAuth() {
  var p = b.guardSmtpCommand.validate("AUTH PLAIN");
  check("AUTH mech",          p.args[0] === "PLAIN");

  var withIr = b.guardSmtpCommand.validate("AUTH PLAIN AGFsaWNlAHB3ZA==");
  check("AUTH initial-response", withIr.params.initialResponse === "AGFsaWNlAHB3ZA==");
}

function testVrfyExpn() {
  var v = b.guardSmtpCommand.validate("VRFY alice@example.com");
  check("VRFY mailbox", v.args[0] === "alice@example.com");
  var e = b.guardSmtpCommand.validate("EXPN admins");
  check("EXPN list",    e.args[0] === "admins");
}

function testRefusesEhloWithoutArg() {
  _throws("EHLO without arg refused",
    function () { b.guardSmtpCommand.validate("EHLO"); },
    "guard-smtp-command/bad-shape");
}

function testRefusesMailWithoutFrom() {
  _throws("MAIL without FROM: refused",
    function () { b.guardSmtpCommand.validate("MAIL TO:<x@y.com>"); },
    "guard-smtp-command/bad-shape");
}

function testGateServe() {
  var gate = b.guardSmtpCommand.gate({ profile: "strict" });
  return gate.check({ identifier: "EHLO mail.example.com" }).then(function (r) {
    check("gate serves valid command", r.ok === true && r.action === "serve");
  });
}

function testGateRefuseSmuggling() {
  var gate = b.guardSmtpCommand.gate({ profile: "strict" });
  return gate.check({ identifier: "MAIL FROM:<a@b.com>\r\n.\r\nMAIL FROM:<evil@x.com>" }).then(function (r) {
    check("gate refuses CRLF smuggling", r.ok === false && r.action === "refuse");
    check("gate issue.kind=bare-cr",      r.issues[0].kind === "bare-cr");
  });
}

// A `.` alone on its line is an SMTP end-of-data marker; it smuggles a second
// message past a lenient relay when its surrounding line endings are not both
// canonical CRLF. Every such non-canonical variant (`<LF>.<LF>`, `<CRLF>.<LF>`,
// `<LF>.<CRLF>`, `<CR>.<CR>`, `<CR>.<LF>`, `<LF>.<CR>`, `<CRLF>.<CR>`) is
// refused; the canonical `<CRLF>.<CRLF>` terminator and a lone bare LF / CR
// that is not such a dot-line (a binary BDAT body carries those) are not.
function testDetectBodySmugglingVariants() {
  var det = b.guardSmtpCommand.detectBodySmuggling;
  function S(s) { return det(Buffer.from(s, "latin1"), true); }
  check("smuggling LF.LF",     S("abc\n.\n") === true);
  check("smuggling CRLF.LF",   S("abc\r\n.\n") === true);
  check("smuggling LF.CRLF",   S("abc\n.\r\n") === true);
  check("smuggling CR.CR",     S("abc\r.\r") === true);
  check("smuggling CR.LF",     S("abc\r.\n") === true);
  check("smuggling LF.CR",     S("abc\n.\rX") === true);
  check("smuggling CRLF.CR",   S("abc\r\n.\rX") === true);
  check("dot-line at body start with bare LF", S(".\n") === true);
  check("lone bare LF (no dot-line) not flagged", S("abc\ndef") === false);
  check("lone bare CR (no dot-line) not flagged", S("abc\rdef") === false);
  check("canonical CRLF.CRLF terminator is not smuggling", S("abc\r\n.\r\n") === false);
  check("empty-body .CRLF at start is canonical", S(".\r\n") === false);
  check("clean CRLF body is not smuggling", S("line one\r\nline two\r\n") === false);
  check("plain text is not smuggling", S("hello world") === false);
  // Continuation buffer (isBodyStart false): a dot-line at offset 1 is still
  // scanned, and a leading `.` preceded by a CR in the prior chunk is a bare CR.
  check("continuation dot-line at offset 1", det(Buffer.from("\n.\n", "latin1"), false) === true);
  check("continuation leading dot after prior CR", det(Buffer.from(".\n", "latin1"), false, true) === true);
  // A trailing `.` then bare CR after a canonical `\r\n.` is the ambiguous
  // split of a canonical `\r\n.\r\n`: a streaming caller (moreComing omitted
  // or true) must defer it so valid mail chunked at the CR is not rejected;
  // only an explicit final buffer (moreComing false) reads it as a bare CR.
  check("trailing CRLF.CR deferred for legacy 3-arg caller",
    det(Buffer.from("abc\r\n.\r", "latin1"), true) === false);
  check("trailing CRLF.CR deferred when moreComing true",
    det(Buffer.from("abc\r\n.\r", "latin1"), true, false, true) === false);
  check("trailing CRLF.CR flagged when final buffer",
    det(Buffer.from("abc\r\n.\r", "latin1"), true, false, false) === true);
  // A bare CR or LF before the dot is unambiguous smuggling; a trailing bare
  // CR after it is flagged at once, with no dependence on moreComing.
  check("trailing CR.CR flagged for legacy 3-arg caller",
    det(Buffer.from("abc\r.\r", "latin1"), true) === true);
}

// The streaming scanner must reach the same verdict as a whole-body scan for
// every split point: a smuggling terminator or a canonical one straddling a
// chunk boundary is neither missed nor falsely flagged.
function testBodySmugglingCrossChunk() {
  function scanSplit(bytes, at) {
    var buf = Buffer.from(bytes, "latin1");
    var scanner = b.safeSmtp.createBodyScanner();
    var s1 = scanner.push(buf.subarray(0, at));
    var s2 = scanner.push(buf.subarray(at));
    return s1.smuggling || s2.smuggling;
  }
  var cases = {
    "abc\r\n.\r\ndef": false,
    "abc\n.\ndef":     true,
    "abc\r.\ndef":     true,
    "abc\n.\rXdef":    true,
    "abc\r\n.\rXdef":  true,
    "abc\r\n.\ndef":   true,
  };
  Object.keys(cases).forEach(function (s) {
    var whole = b.guardSmtpCommand.detectBodySmuggling(Buffer.from(s, "latin1"), true);
    check("whole-body matches expected: " + JSON.stringify(s), whole === cases[s]);
    for (var at = 0; at <= s.length; at += 1) {
      check("split at " + at + " agrees: " + JSON.stringify(s), scanSplit(s, at) === cases[s]);
    }
  });
}

function testCompliancePosture() {
  check("hipaa → strict",     b.guardSmtpCommand.compliancePosture("hipaa") === "strict");
  check("pci-dss → strict",   b.guardSmtpCommand.compliancePosture("pci-dss") === "strict");
  check("gdpr → strict",      b.guardSmtpCommand.compliancePosture("gdpr") === "strict");
  check("soc2 → strict",      b.guardSmtpCommand.compliancePosture("soc2") === "strict");
  check("unknown → null",     b.guardSmtpCommand.compliancePosture("hipa-typo") === null);
}

function testPostureBindsStrict() {
  // Under hipaa posture, non-ASCII refused even though caller asked balanced
  // (posture overrides profile).
  _throws("hipaa posture pins strict (no SMTPUTF8)",
    function () { b.guardSmtpCommand.validate("EHLO mαil.example.com", { posture: "hipaa" }); },
    "guard-smtp-command/non-ascii");
}

function testRegisteredInGuardAll() {
  var all = b.guardAll.allGuards();
  var found = all.some(function (g) { return g && g.NAME === "smtpCommand"; });
  check("registered in guardAll", found);
}

async function run() {
  testSurface();
  testParsesGreeting();
  testParsesMailFrom();
  testParsesRcptTo();
  testRefusesBareCr();
  testRefusesBareLf();
  testPermissiveAcceptsBareLf();
  testRefusesNul();
  testRefusesC0Control();
  testRefusesDel();
  testRefusesNonAsciiUnderStrict();
  testRefusesOversizeLine();
  testRefusesUnknownVerb();
  testRefusesZeroArgVerbWithArgs();
  testZeroArgVerbsAccepted();
  testBdat();
  testAuth();
  testVrfyExpn();
  testRefusesEhloWithoutArg();
  testRefusesMailWithoutFrom();
  await testGateServe();
  await testGateRefuseSmuggling();
  testDetectBodySmugglingVariants();
  testBodySmugglingCrossChunk();
  testCompliancePosture();
  testPostureBindsStrict();
  testRegisteredInGuardAll();
}

module.exports = { run: run };

if (require.main === module) run().catch(function (e) {
  process.stderr.write("FAIL: " + (e && e.stack || e) + "\n");
  process.exit(1);
});
