// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function testSurface() {
  check("b.safeSieve.parse exists",    typeof b.safeSieve.parse === "function");
  check("b.safeSieve.validate exists", typeof b.safeSieve.validate === "function");
  check("PROFILES strict/balanced/permissive present",
    b.safeSieve.PROFILES.strict && b.safeSieve.PROFILES.balanced && b.safeSieve.PROFILES.permissive);
}

function testHappyPath() {
  var ast = b.safeSieve.parse(
    'require ["fileinto"];\r\n' +
    'if header :contains "Subject" "[bug]" {\r\n' +
    '  fileinto "bugs";\r\n' +
    '}\r\n');
  check("script ast kind",     ast.kind === "script");
  check("requiredCaps captured", ast.requiredCaps.length === 1 && ast.requiredCaps[0] === "fileinto");
  check("two top-level commands (require + if)", ast.commands.length === 2);
}

function testLfNormalization() {
  // LF-only input gets normalized to CRLF.
  var ast = b.safeSieve.parse('require ["fileinto"];\nkeep;\n');
  check("LF normalized to CRLF, parse succeeds", ast.commands.length === 2);
}

function testUnknownCapability() {
  var rv = b.safeSieve.validate('require ["nonsense-cap"];\nkeep;\n');
  check("unknown capability refused",
    !rv.ok && rv.issues[0].ruleId === "safe-sieve/unknown-capability");
}

function testUnimplementedCapability() {
  var rv = b.safeSieve.validate('require ["vacation"];\nkeep;\n');
  check("RFC-defined-but-unimplemented capability refused",
    !rv.ok && rv.issues[0].ruleId === "safe-sieve/unimplemented-capability");
}

function testScriptTooLarge() {
  var rv = b.safeSieve.validate("keep;\n".repeat(20000));
  check("oversized script refused",
    !rv.ok && rv.issues[0].ruleId === "safe-sieve/script-too-large");
}

function testBareCrRefused() {
  var rv = b.safeSieve.validate("keep;\r\rdiscard;\r\n");
  check("bare CR refused",
    !rv.ok && /bare CR/.test(rv.issues[0].snippet));
}

function testControlByteRefused() {
  var rv = b.safeSieve.validate("keep;\r\n\x01\r\n");
  check("control byte refused outside string",
    !rv.ok && /control byte/.test(rv.issues[0].snippet));
}

function testStringTooLarge() {
  var huge = '"' + "x".repeat(5000) + '"';
  var rv = b.safeSieve.validate('if header :is "X" ' + huge + ' { keep; }\r\n');
  check("oversized string literal refused",
    !rv.ok && /maxStringBytes/.test(rv.issues[0].snippet));
}

function testNestingCap() {
  // Build a script that nests blocks past maxDepth=32 strict cap.
  var s = "";
  for (var i = 0; i < 35; i++) s += 'if true {';
  s += "keep;";
  for (var j = 0; j < 35; j++) s += '}';
  s += "\r\n";
  var rv = b.safeSieve.validate(s);
  check("over-nested block refused",
    !rv.ok && /maxDepth/.test(rv.issues[0].snippet));
}

function testMultilineString() {
  var ast = b.safeSieve.parse(
    'require ["fileinto"];\r\n' +
    'fileinto text:\r\nMy\r\nFolder\r\n.\r\n;\r\n');
  check("multi-line string parsed",
    ast.commands[1].args.positional[0].v === "My\r\nFolder");
}

// RFC 5228 §2.4.2 dot-stuffing removal applies to EVERY body line, including the
// first. A leading `..` on the first body line must decode to `.`, not stay `..`
// (the SMTP/POP3 dot-stuffing class) — else the decoded script diverges from what
// a conformant Sieve engine executes (match keys, fileinto folders, addresses).
function testMultilineFirstLineDotStuffed() {
  var first = b.safeSieve.parse(
    'require ["fileinto"];\r\n' +
    'fileinto text:\r\n..Junk\r\n.\r\n;\r\n');
  check("first body line is de-stuffed (..Junk -> .Junk)",
    first.commands[1].args.positional[0].v === ".Junk",
    JSON.stringify(first.commands[1].args.positional[0].v));
  var triple = b.safeSieve.parse(
    'require ["fileinto"];\r\n' +
    'fileinto text:\r\n...Deep\r\nplain\r\n..mid\r\n.\r\n;\r\n');
  check("first-line ...Deep -> ..Deep and interior ..mid -> .mid",
    triple.commands[1].args.positional[0].v === "..Deep\r\nplain\r\n.mid",
    JSON.stringify(triple.commands[1].args.positional[0].v));
  var single = b.safeSieve.parse(
    'require ["fileinto"];\r\n' +
    'fileinto text:\r\n.Junk\r\n.\r\n;\r\n');
  check("a single leading dot is preserved (.Junk stays .Junk)",
    single.commands[1].args.positional[0].v === ".Junk",
    JSON.stringify(single.commands[1].args.positional[0].v));
}

function testCompliancePosture() {
  check("posture hipaa → strict",   b.safeSieve.compliancePosture("hipaa") === "strict");
  check("posture pci-dss → strict", b.safeSieve.compliancePosture("pci-dss") === "strict");
}

function testErrorClassExported() {
  check("b.safeSieve.SafeSieveError is a constructor",
    typeof b.safeSieve.SafeSieveError === "function");
  var threw = null;
  try { b.safeSieve.parse(123); } catch (e) { threw = e; }
  check("parse on non-string throws SafeSieveError",
    threw instanceof b.safeSieve.SafeSieveError);
}

function run() {
  testSurface();
  testHappyPath();
  testLfNormalization();
  testUnknownCapability();
  testUnimplementedCapability();
  testScriptTooLarge();
  testBareCrRefused();
  testControlByteRefused();
  testStringTooLarge();
  testNestingCap();
  testMultilineString();
  testMultilineFirstLineDotStuffed();
  testCompliancePosture();
  testErrorClassExported();
}

module.exports = { run: run };

if (require.main === module) {
  try { run(); console.log("[safe-sieve] OK"); }
  catch (e) { process.stderr.write("FAIL: " + (e && e.stack || e) + "\n"); process.exit(1); }
}
