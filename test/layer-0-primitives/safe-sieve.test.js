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

function testAnEncodedRunCannotCarryAByteTheScriptCouldNotWrite() {
  // The decoder runs AFTER tokenization, so a run can put a byte into a string
  // value that the tokenizer would have refused had the script written it out.
  // The tokenizer refuses exactly one byte inside a string literal, NUL, so
  // that is the byte a run may not produce either. The other control
  // characters ARE writable literally: the tokenizer counts a raw LF and the
  // `text:` form builds a value full of CRLF by construction, so refusing them
  // here rejected scripts RFC 5228 requires an implementation to accept while
  // leaving the same bytes reachable by writing them literally. Where those
  // bytes are genuinely dangerous, in a `redirect` address that becomes an
  // SMTP command, they are refused at the redirect.
  var REFUSED = [
    ['${hex:00}',    "a NUL"],
    ['${unicode:0}', "a NUL by its code point"],
  ];
  REFUSED.forEach(function (row) {
    var src = 'require ["encoded-character"];\r\nkeep;\r\n' +
              'if header :contains "Subject" "x' + row[0] + 'y" { stop; }\r\n';
    var threw = null;
    try { b.safeSieve.parse(src); } catch (e) { threw = e; }
    check("an encoded run decoding to " + row[1] + " is refused",
          threw !== null && typeof threw.code === "string" &&
            threw.code.indexOf("safe-sieve/") === 0,
          threw ? String(threw.code) : "accepted");
  });

  // A byte the script may write literally is a byte a run may produce.
  var ALLOWED = [
    ['${hex:0d 0a}', "CR LF"],
    ['${hex:0a}',    "a bare LF"],
    ['${unicode:7f}', "DEL"],
    ['${unicode:85}', "U+0085"],
  ];
  ALLOWED.forEach(function (row) {
    var src = 'require ["encoded-character"];\r\nkeep;\r\n' +
              'if header :contains "Subject" "x' + row[0] + 'y" { stop; }\r\n';
    var threw = null;
    try { b.safeSieve.parse(src); } catch (e) { threw = e; }
    check("an encoded run decoding to " + row[1] + " parses, as the literal does",
          threw === null, threw ? String(threw.code) : "ok");
  });

  // An ordinary character written the same way still decodes.
  var ok = b.safeSieve.parse(
    'require ["encoded-character"];\r\n' +
    'if header :contains "Subject" "${hex:41}" { stop; }\r\n');
  check("an encoded run decoding to a printable character still parses",
        ok.commands.length === 2, JSON.stringify(ok.commands.length));
}

function testAnExtensionNeedsTheRequireThatDeclaresIt() {
  // RFC 5228 section 2.10.5: an extension may not be used unless `require`
  // declared it, and this module's own @intro says `envelope` is available
  // "when envelope capability declared". Both ran without one, so a script
  // this parser accepted was refused by any conformant peer it was migrated
  // to, and the declaration the parser publishes did not describe it.
  var noCap = b.safeSieve.validate('fileinto "x";\r\n');
  check("fileinto without its require is refused",
        !noCap.ok && /undeclared-extension|require/.test(JSON.stringify(noCap)),
        JSON.stringify(noCap).slice(0, 160));

  var noEnv = b.safeSieve.validate('if envelope :is "from" "a@b.c" { keep; }\r\n');
  check("envelope without its require is refused",
        !noEnv.ok && /undeclared-extension|require/.test(JSON.stringify(noEnv)),
        JSON.stringify(noEnv).slice(0, 160));

  // Declared, they parse.
  var declared = b.safeSieve.parse(
    'require ["fileinto", "envelope"];\r\n' +
    'if envelope :is "from" "a@b.c" { fileinto "x"; }\r\n');
  check("both parse once the script declares them",
        declared.commands.length === 2, JSON.stringify(declared.commands.length));

  // A command that is not an extension needs no declaration.
  var core = b.safeSieve.parse('if header :is "Subject" "x" { keep; }\r\n');
  check("a core command still needs no require",
        core.commands.length === 1, JSON.stringify(core.commands.length));
}

function testAnUnterminatedStringIsRefusedRatherThanDropped() {
  // The scanner walks a quoted string with _advance, which only moves while
  // i < n, so the `if (i > n)` refusal after the loop could never fire. A
  // string with no closing quote ran off the end, pushed no token, and the
  // tokenizer went straight to eof: everything from the opening quote onwards
  // vanished and the parser saw a well-formed prefix. validate() then reported
  // ok:true for a script a conformant RFC 5228 implementation rejects, and the
  // framework ran the prefix.
  var trailing = b.safeSieve.validate('keep;\r\n"');
  check("a script ending inside a string literal is refused",
        !trailing.ok, JSON.stringify(trailing));

  var midScript = b.safeSieve.validate(
    'require ["fileinto"];\r\nfileinto "Inbox";\r\nfileinto "Evil;\r\ndiscard;\r\n');
  check("an unterminated string mid-script is refused",
        !midScript.ok, JSON.stringify(midScript).slice(0, 160));

  // A terminated string is untouched, so the refusal is about the missing
  // quote rather than about quoting.
  var fine = b.safeSieve.parse('require ["fileinto"];\r\nfileinto "Inbox";\r\n');
  check("a terminated string still parses", fine.commands.length === 2,
        JSON.stringify(fine.commands.length));
}

function testTheTestGrammarNestsTooAndIsCapped() {
  // maxDepth was checked in _parseBlock alone, and a test nests through `not`
  // / `anyof` / `allof` without ever reaching a block. A script that nested
  // only its tests validated clean at 12019 bytes, well inside the strict
  // maxScriptBytes of 65536 — so ManageSieve PUTSCRIPT stored it — and then
  // threw a bare RangeError out of b.mail.sieve.run on every delivery, with
  // e.code undefined and not a MailSieveError for a caller to branch on.
  var notNest = "if " + "not ".repeat(3000) + "true { keep; }\r\n";
  check("the nested-test script is inside maxScriptBytes",
        Buffer.byteLength(notNest) < b.safeSieve.PROFILES.strict.maxScriptBytes,
        Buffer.byteLength(notNest) + " bytes");
  var rvNot = b.safeSieve.validate(notNest);
  check("a `not` nested past maxDepth is refused at validate",
        !rvNot.ok && /maxDepth/.test(rvNot.issues[0].snippet),
        JSON.stringify(rvNot).slice(0, 160));

  var anyNest = "true";
  for (var i = 0; i < 3000; i++) anyNest = "anyof(" + anyNest + ")";
  var rvAny = b.safeSieve.validate("if " + anyNest + " { keep; }\r\n");
  check("an `anyof` nested past maxDepth is refused at validate",
        !rvAny.ok && /maxDepth/.test(rvAny.issues[0].snippet),
        JSON.stringify(rvAny).slice(0, 160));

  // The bound is the profile's, so a script inside it still parses and the
  // refusal is about the depth rather than about the construct.
  var shallow = b.safeSieve.parse("if " + "not ".repeat(8) + "true { keep; }\r\n");
  check("a test nested inside maxDepth still parses",
        shallow.commands.length === 1, JSON.stringify(shallow.commands.length));
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
  testTheTestGrammarNestsTooAndIsCapped();
  testAnUnterminatedStringIsRefusedRatherThanDropped();
  testAnExtensionNeedsTheRequireThatDeclaresIt();
  testAnEncodedRunCannotCarryAByteTheScriptCouldNotWrite();
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
