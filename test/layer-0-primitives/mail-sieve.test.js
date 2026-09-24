// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// SMOKE_RUN_SOLO: growth checks here compare wall-clock time across input sizes, which a CPU shared with the smoke pool distorts.

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function testSurface() {
  check("b.mail.sieve.run exists",       typeof b.mail.sieve.run === "function");
  check("b.mail.sieve.runScript exists", typeof b.mail.sieve.runScript === "function");
  check("b.mail.sieve.create exists",    typeof b.mail.sieve.create === "function");
}

function testImplicitKeep() {
  var rv = b.mail.sieve.runScript('# empty script\r\n', {});
  check("implicit keep when no action fires",
    rv.actions.length === 1 && rv.actions[0].kind === "keep" && rv.actions[0].implicit);
}

function testFileinto() {
  var script = 'require ["fileinto"];\r\n' +
    'if header :contains "Subject" "[bug]" { fileinto "bugs"; }\r\n';
  var rv = b.mail.sieve.runScript(script, {
    headers: [{ name: "Subject", value: "Re: [bug] crash" }],
  });
  check("fileinto fires + cancels implicit keep",
    rv.actions.length === 1 && rv.actions[0].kind === "fileinto" && rv.actions[0].folder === "bugs");
}

function testAddressDomain() {
  var script = 'if address :is :domain "From" "trusted.com" { keep; }\r\n';
  var rv1 = b.mail.sieve.runScript(script, {
    headers: [{ name: "From", value: "alice@trusted.com" }],
  });
  check("address :domain match",
    rv1.actions.length === 1 && rv1.actions[0].kind === "keep");
  var rv2 = b.mail.sieve.runScript(script, {
    headers: [{ name: "From", value: "alice@untrusted.com" }],
  });
  check("address :domain non-match → implicit keep",
    rv2.actions[0].implicit === true);
}

function testEnvelope() {
  // RFC 5228 section 2.10.5: both `envelope` and `fileinto` are extensions and
  // a script that uses one declares it.
  var script = 'require ["envelope", "fileinto"];\r\n' +
    'if envelope :is "from" "boss@example.com" { fileinto "Boss"; }\r\n';
  var rv = b.mail.sieve.runScript(script, {
    envelope: { from: "boss@example.com", to: "me@example.com" },
    headers:  [],
  });
  check("envelope test reads env.envelope",
    rv.actions[0].kind === "fileinto" && rv.actions[0].folder === "Boss");
}

function testSize() {
  var script = 'if size :over 1K { discard; }\r\n';
  var big = b.mail.sieve.runScript(script, { sizeBytes: 2048 });
  check("size :over fires on 2KB",
    big.actions[0].kind === "discard");
  var small = b.mail.sieve.runScript(script, { sizeBytes: 512 });
  check("size :over below threshold → implicit keep",
    small.actions[0].implicit === true);
}

function testWildcardMatches() {
  var script = 'if header :matches "Subject" "[bug]*" { fileinto "bugs"; }\r\n';
  var rv = b.mail.sieve.runScript('require ["fileinto"];\r\n' + script, {
    headers: [{ name: "Subject", value: "[bug] tracker #42" }],
  });
  check("`:matches` wildcard fires",
    rv.actions[0].kind === "fileinto");
}

function testAnyofAllof() {
  var script =
    'if anyof(header :is "X-Spam" "yes", header :contains "Subject" "viagra") {\r\n' +
    '  discard;\r\n' +
    '}\r\n';
  var rv = b.mail.sieve.runScript(script, {
    headers: [{ name: "Subject", value: "buy viagra now" }],
  });
  check("anyof matches second branch", rv.actions[0].kind === "discard");
}

function testRedirect() {
  var script = 'if header :is "From" "alerts@example.com" { redirect "ops@example.com"; }\r\n';
  var rv = b.mail.sieve.runScript(script, {
    headers: [{ name: "From", value: "alerts@example.com" }],
  });
  check("redirect captures address",
    rv.actions[0].kind === "redirect" && rv.actions[0].address === "ops@example.com");
}

function testStop() {
  var script =
    'if header :is "From" "ignore@x.com" { stop; }\r\n' +
    'keep;\r\n';
  var rv = b.mail.sieve.runScript(script, {
    headers: [{ name: "From", value: "ignore@x.com" }],
  });
  check("stop halts further commands → implicit keep applies (no explicit keep ran)",
    rv.stopped === true);
}

function testGasExhaustion() {
  // Wide allof to consume gas without nesting.
  var subs = []; for (var i = 0; i < 20; i++) subs.push("true");
  var script = "if allof(" + subs.join(", ") + ") { keep; }\r\n";
  var threw = null;
  try { b.mail.sieve.runScript(script, {}, { maxGas: 3 }); } catch (e) { threw = e; }
  check("gas exhaustion throws",
    threw && threw.code === "mail-sieve/gas-exhausted");
}

function testBadAst() {
  var threw = null;
  try { b.mail.sieve.run({ notAnAst: true }, {}); } catch (e) { threw = e; }
  check("non-script ast refused",
    threw && threw.code === "mail-sieve/bad-ast");
}

function testCreateHandle() {
  var sieve = b.mail.sieve.create({ maxGas: 100 });
  var rv = sieve.runScript('require ["fileinto"];\r\nfileinto "Test";\r\n', { headers: [] });
  check("handle runScript returns action",
    rv.actions[0].kind === "fileinto" && rv.actions[0].folder === "Test");
  var v = sieve.validateScript('require ["nonsense"];\nkeep;\n');
  check("handle validateScript surfaces unknown cap",
    !v.ok && v.issues[0].ruleId === "safe-sieve/unknown-capability");
}

// ---- tests / adversarial input ------------------------------------------

function testUnknownTestRefused() {
  // A test identifier the grammar accepts but the interpreter never wired —
  // must refuse, not silently pass/fail-open. The parser resolves the name
  // against the interpreter's published set, so the refusal now arrives
  // there, before a script naming it can be stored.
  var threw = null;
  try { b.mail.sieve.runScript('if bogustest "x" { keep; }', {}); }
  catch (e) { threw = e; }
  check("unknown test refused with typed error",
    threw && threw.code === "safe-sieve/unimplemented-test", threw && threw.code);

  // The interpreter keeps its own refusal for an AST that did not come from
  // the parser, which is the only way an unwired name still reaches it.
  var handBuilt = null;
  try {
    b.mail.sieve.run({
      kind:         "script",
      requiredCaps: [],
      commands:     [{
        kind:     "if",
        test:     { kind: "test", name: "bogustest", args: { tags: [], positional: [] } },
        thenBody: [], elif: [], elseBody: [],
      }],
    }, {});
  } catch (e) { handBuilt = e; }
  check("and a hand-built AST is still refused at run time",
    handBuilt && handBuilt.code === "mail-sieve/unknown-test", handBuilt && handBuilt.code);
}

function testUnknownActionRefused() {
  var threw = null;
  try { b.mail.sieve.runScript('frobnicate;', {}); } catch (e) { threw = e; }
  check("unknown action refused with typed error",
    threw && threw.code === "safe-sieve/unimplemented-action", threw && threw.code);

  var handBuilt = null;
  try {
    b.mail.sieve.run({
      kind:         "script",
      requiredCaps: [],
      commands:     [{ kind: "action", name: "frobnicate", args: { tags: [], positional: [] } }],
    }, {});
  } catch (e) { handBuilt = e; }
  check("and a hand-built AST is still refused at run time",
    handBuilt && handBuilt.code === "mail-sieve/unknown-action", handBuilt && handBuilt.code);
}

function testBadCommandKind() {
  // Hand-built AST fed to the public run() entry — an unmodeled command
  // kind must throw a typed refusal, never fall through.
  var threw = null;
  try {
    b.mail.sieve.run({ kind: "script", commands: [{ kind: "weird" }] }, {});
  } catch (e) { threw = e; }
  check("unmodeled command kind refused",
    threw && threw.code === "mail-sieve/bad-command");
}

function testFileintoMissingFolder() {
  var threw = null;
  try { b.mail.sieve.runScript('require ["fileinto"];\r\nfileinto;\r\n', {}); }
  catch (e) { threw = e; }
  check("fileinto without folder refused",
    threw && threw.code === "mail-sieve/bad-fileinto");
  // Empty string-list argument is equally malformed (v.v[0] → null).
  var threw2 = null;
  try { b.mail.sieve.runScript('require ["fileinto"];\r\nfileinto [];\r\n', {}); }
  catch (e) { threw2 = e; }
  check("fileinto with empty list refused",
    threw2 && threw2.code === "mail-sieve/bad-fileinto");
}

function testRedirectMissingAddress() {
  var threw = null;
  try { b.mail.sieve.runScript('redirect;', {}); } catch (e) { threw = e; }
  check("redirect without address refused",
    threw && threw.code === "mail-sieve/bad-redirect");
}

function testNotTest() {
  var rv = b.mail.sieve.runScript('if not exists "X-Missing" { discard; }',
    { headers: [] });
  check("`not` inverts the sub-test",
    rv.actions[0].kind === "discard");
}

function testExists() {
  var present = b.mail.sieve.runScript('if exists "Subject" { discard; }',
    { headers: [{ name: "Subject", value: "hi" }] });
  check("exists fires when header present", present.actions[0].kind === "discard");
  var absent = b.mail.sieve.runScript('if exists "Subject" { discard; }',
    { headers: [] });
  check("exists false → implicit keep when header absent",
    absent.actions[0].implicit === true);
  // Header present but value null still counts as existing.
  var nullVal = b.mail.sieve.runScript('if exists "X-Flag" { discard; }',
    { headers: [{ name: "X-Flag", value: null }] });
  check("exists treats null-valued header as present",
    nullVal.actions[0].kind === "discard");
}

function testSizeUnderAndFallbacks() {
  var under = b.mail.sieve.runScript('if size :under 1K { discard; }',
    { sizeBytes: 512 });
  check("size :under fires below threshold", under.actions[0].kind === "discard");
  // Falls back to bodyBytes.length when sizeBytes absent.
  var body = b.mail.sieve.runScript('if size :over 3 { discard; }',
    { bodyBytes: Buffer.from("hello") });
  check("size falls back to bodyBytes.length", body.actions[0].kind === "discard");
  // No size info at all → 0 bytes, :under fires.
  var zero = b.mail.sieve.runScript('if size :under 10 { discard; }', {});
  check("size defaults to 0 bytes with no env info",
    zero.actions[0].kind === "discard");
}

function testAddressPartsAndExtraction() {
  // :localpart on a display-name address.
  var lp = b.mail.sieve.runScript(
    'if address :is :localpart "From" "alice" { keep; }',
    { headers: [{ name: "From", value: "Alice Smith <alice@example.com>" }] });
  check("address :localpart extracts local part before @",
    lp.actions[0].kind === "keep" && !lp.actions[0].implicit);
  // :all on a bracketed address returns the full addr-spec.
  var all = b.mail.sieve.runScript(
    'if address :is :all "From" "a@x.com" { keep; }',
    { headers: [{ name: "From", value: "A <a@x.com>" }] });
  check("address :all extracts full addr-spec from brackets",
    all.actions[0].kind === "keep" && !all.actions[0].implicit);
  // Address without an @: localpart is the whole token; domain is "".
  var noAtLocal = b.mail.sieve.runScript(
    'if address :is :localpart "From" "weird" { keep; }',
    { headers: [{ name: "From", value: "weird" }] });
  check("address :localpart of at-less token is the whole token",
    !noAtLocal.actions[0].implicit);
  var noAtDomain = b.mail.sieve.runScript(
    'if address :is :domain "From" "" { keep; }',
    { headers: [{ name: "From", value: "nodomain" }] });
  check("address :domain of at-less token is empty string",
    !noAtDomain.actions[0].implicit);
}

function testEnvelopeArrayAndBogusField() {
  // Array-valued envelope recipient list — each entry compared.
  var arr = b.mail.sieve.runScript(
    'require ["envelope"];\r\nif envelope :is "to" "b@x.com" { keep; }',
    { envelope: { to: ["a@x.com", "b@x.com"] } });
  check("envelope matches any entry of an array value",
    arr.actions[0].kind === "keep" && !arr.actions[0].implicit);
  // Envelope field other than from/to is skipped per RFC 5228 §5.4.
  var bogus = b.mail.sieve.runScript(
    'require ["envelope"];\r\nif envelope :is "subject" "x" { discard; }',
    { envelope: { from: "a@x.com" } });
  check("envelope ignores fields other than from/to",
    bogus.actions[0].implicit === true);
  // No envelope object at all → no match.
  var none = b.mail.sieve.runScript(
    'require ["envelope"];\r\nif envelope :is "from" "a@x.com" { discard; }', {});
  check("envelope with no env.envelope → implicit keep",
    none.actions[0].implicit === true);
}

function testHeaderListsAndMultiValue() {
  // List of header names + list of keys.
  var lists = b.mail.sieve.runScript(
    'if header :contains ["To","Cc"] ["vip"] { discard; }',
    { headers: [{ name: "Cc", value: "vip@x.com" }] });
  check("header test spans a list of names and keys",
    lists.actions[0].kind === "discard");
  // Two headers of the same name — both values considered.
  var multi = b.mail.sieve.runScript('if header :is "Received" "b" { discard; }',
    { headers: [{ name: "Received", value: "a" }, { name: "Received", value: "b" }] });
  check("header test considers every value of a repeated header",
    multi.actions[0].kind === "discard");
}

function testComparatorDefaultCaseInsensitive() {
  // Default comparator is i;ascii-casemap → case-insensitive :is.
  var ci = b.mail.sieve.runScript('if header :is "Subject" "hello" { discard; }',
    { headers: [{ name: "Subject", value: "HELLO" }] });
  check("default comparator is case-insensitive (i;ascii-casemap)",
    ci.actions[0].kind === "discard");

  // An explicit `:comparator "i;octet"` binds the comparator name to the tag
  // (RFC 5228 §2.7.3), not into the positional stream -- so the header name and
  // keys stay aligned and the test still matches (previously the comparator
  // value was mis-read as the header name, silently disabling the test = a
  // filter bypass). i;octet is case-SENSITIVE (unlike the default
  // i;ascii-casemap): an exact-case key matches, a wrong-case key does not.
  var octet = b.mail.sieve.runScript(
    'if header :comparator "i;octet" :is "Subject" "HELLO" { discard; }',
    { headers: [{ name: "Subject", value: "HELLO" }] });
  check("explicit :comparator :is exact-case matches (no filter bypass)",
    octet.actions[0].kind === "discard");
  var octetMiss = b.mail.sieve.runScript(
    'if header :comparator "i;octet" :is "Subject" "hello" { discard; }',
    { headers: [{ name: "Subject", value: "HELLO" }] });
  check("explicit :comparator i;octet is case-sensitive (wrong case falls through to keep)",
    octetMiss.actions[0].implicit === true);
  // A `:comparator` with no following comparator-name string fails closed at parse.
  var badComp = false;
  try { b.mail.sieve.runScript('if header :comparator :is "Subject" "x" { discard; }', { headers: [] }); }
  catch (e) { badComp = /parse-error/.test(e.code || e.message); }
  check("explicit :comparator without a value is refused at parse", badComp);
  // An unsupported comparator name is refused at parse (like the
  // require ["comparator-<name>"] capability guard), not silently treated as
  // octet exact-matching -- otherwise it would bypass the capability guard.
  var badCompName = false;
  try {
    b.mail.sieve.runScript('if header :comparator "i;unicode-casemap" :is "Subject" "HELLO" { discard; }',
      { headers: [{ name: "Subject", value: "HELLO" }] });
  } catch (e) { badCompName = /unknown-capability|unimplemented-capability/.test(e.code || e.message); }
  check("explicit :comparator with an unsupported name is refused (no capability-guard bypass)", badCompName);
}

function testWildcardEscaping() {
  // `?` matches exactly one byte.
  var q = b.mail.sieve.runScript('if header :matches "Subject" "a?c" { discard; }',
    { headers: [{ name: "Subject", value: "abc" }] });
  check("`:matches` ? matches a single byte", q.actions[0].kind === "discard");
  // Regex metacharacters other than * / ? are escaped — `.` is literal.
  var dot = b.mail.sieve.runScript('if header :matches "Subject" "a.c" { discard; }',
    { headers: [{ name: "Subject", value: "axc" }] });
  check("`:matches` escapes regex metachars (`.` is literal, not wildcard)",
    dot.actions[0].implicit === true);
}

function testElsifElse() {
  var script =
    'if header :is "X" "1" { discard; }\r\n' +
    'elsif header :is "X" "2" { redirect "a@b.com"; }\r\n' +
    'else { keep; }\r\n';
  var elif = b.mail.sieve.runScript(script, { headers: [{ name: "X", value: "2" }] });
  check("elsif branch taken",
    elif.actions[0].kind === "redirect" && elif.actions[0].address === "a@b.com");
  var els = b.mail.sieve.runScript(script, { headers: [{ name: "X", value: "9" }] });
  check("else branch taken when no if/elsif matches",
    els.actions[0].kind === "keep" && !els.actions[0].implicit);
}

function testExplicitKeepAndStopSkips() {
  var k = b.mail.sieve.runScript('keep;\r\n', {});
  check("explicit keep is not marked implicit",
    k.actions.length === 1 && k.actions[0].kind === "keep" && !k.actions[0].implicit);
  // stop halts before a following action ever runs.
  var s = b.mail.sieve.runScript(
    'require ["fileinto"];\r\nstop;\r\nfileinto "X";\r\n', {});
  check("stop skips subsequent commands",
    s.stopped === true &&
    !s.actions.some(function (a) { return a.kind === "fileinto"; }));
}

function testFileintoListArg() {
  var rv = b.mail.sieve.runScript('require ["fileinto"];\r\nfileinto ["A","B"];\r\n', {});
  check("fileinto takes first element of a string-list arg",
    rv.actions[0].kind === "fileinto" && rv.actions[0].folder === "A");
}

function testGasExhaustionInCommands() {
  var threw = null;
  try { b.mail.sieve.runScript('keep;\r\nkeep;\r\nkeep;\r\n', {}, { maxGas: 2 }); }
  catch (e) { threw = e; }
  check("gas exhausts across a command sequence",
    threw && threw.code === "mail-sieve/gas-exhausted");
}

function testMaxGasOptValidation() {
  var cases = [
    ["zero", 0],
    ["negative", -1],
    ["Infinity", Infinity],
    ["NaN", NaN],
    ["string", "5"],
    ["fractional", 1.5],
    ["over-cap", b.mail.sieve.MAX_GAS_UNITS + 1],
  ];
  var allRefused = true;
  for (var i = 0; i < cases.length; i++) {
    var threw = null;
    try { b.mail.sieve.runScript('keep;', {}, { maxGas: cases[i][1] }); }
    catch (e) { threw = e; }
    if (!threw || threw.code !== "mail-sieve/bad-opt") allRefused = false;
  }
  check("run() refuses every out-of-range/ill-typed maxGas", allRefused);
}

function testParseErrorsPropagate() {
  // runScript surfaces the parser's typed refusals unchanged.
  var badSyntax = null;
  try { b.mail.sieve.runScript('if header :is', {}); } catch (e) { badSyntax = e; }
  check("runScript propagates parse-error", badSyntax && badSyntax.code === "safe-sieve/parse-error");
  var unimpl = null;
  try { b.mail.sieve.runScript('require ["vacation"];\r\nkeep;\r\n', {}); }
  catch (e) { unimpl = e; }
  check("runScript propagates unimplemented-capability refusal",
    unimpl && unimpl.code === "safe-sieve/unimplemented-capability");
}

function testAnEmptyNameIsRefusedInBothSpellings() {
  // `fileinto ["x"]` and `fileinto "x"` name the same folder, and the reader
  // dropped an empty list entry to null while letting an empty STRING through:
  // `fileinto ""` filed the message into a folder with no name and cancelled
  // the implicit keep, while `fileinto [""]` was refused. One value, two
  // spellings, two answers.
  [['fileinto ""', "mail-sieve/bad-fileinto"],
   ['fileinto [""]', "mail-sieve/bad-fileinto"],
   ['redirect ""', "mail-sieve/bad-redirect"],
   ['redirect [""]', "mail-sieve/bad-redirect"]].forEach(function (row) {
    var threw = null;
    try {
      b.mail.sieve.runScript('require ["fileinto"];\r\n' + row[0] + ";\r\n", {});
    } catch (e) { threw = e; }
    check("an empty name is refused: " + row[0],
          threw !== null && threw.code === row[1],
          threw ? String(threw.code) : "accepted");
  });

  // A named folder still files.
  var ok = b.mail.sieve.runScript(
    'require ["fileinto"];\r\nfileinto "Archive";\r\n', {});
  check("a named folder still files",
        ok.actions.some(function (a) { return a.kind === "fileinto" && a.folder === "Archive"; }),
        JSON.stringify(ok.actions));
}

function testARedirectAddressCannotEndTheSmtpCommandThatCarriesIt() {
  // A redirect address is written into an SMTP `RCPT TO:` line, so a CR or LF
  // in it ends that command and the rest is read as another one. The check
  // belongs here, where every redirect passes whatever spelling produced the
  // address: screening the encoded-character decoder instead refused
  // conformant scripts for bytes their literal text was allowed to carry, and
  // the same address written with a literal CRLF went through untouched.
  function actionsFor(script) {
    var ast = b.safeSieve.parse(script, { profile: "permissive" });
    return b.mail.sieve.run(ast, {});
  }
  function refusalFor(script) {
    try { actionsFor(script); } catch (e) { return e; }
    return null;
  }

  var literal = refusalFor(
    'require ["encoded-character"];\nredirect "a@b.c\r\nRCPT TO:<x@y.z>";');
  check("a redirect address carrying a literal CRLF is refused",
        literal !== null && literal.code === "mail-sieve/bad-redirect",
        literal ? String(literal.code) : "accepted");

  var encoded = refusalFor(
    'require ["encoded-character"];\nredirect "a@b.c${hex:0d 0a}RCPT TO:<x@y.z>";');
  check("and so is the same address written as an encoded run",
        encoded !== null && encoded.code === "mail-sieve/bad-redirect",
        encoded ? String(encoded.code) : "accepted");

  // The check answers whether the address can break the command, and nothing
  // else, so addresses an email-deliverability policy would argue about still
  // redirect.
  ['a@b.c', "x@localhost", '\\"odd name\\"@example.com'].forEach(function (addr) {
    var ran = null;
    try { ran = actionsFor('redirect "' + addr + '";'); } catch (e) { ran = e; }
    check("an ordinary address still redirects (" + addr + ")",
          ran !== null && ran.actions &&
          ran.actions.some(function (a) { return a.kind === "redirect"; }),
          JSON.stringify(ran && (ran.actions || ran.code)));
  });
}

function testAnEncodedRunIsHeldToWhatALiteralMayCarry() {
  // The encoded-character extension may not smuggle in a character the string
  // grammar forbids, and the grammar forbids exactly one: NUL. Screening the
  // decoded text for every control character instead refused scripts RFC 5228
  // requires an implementation to accept, and blamed a run for a byte the
  // literal text beside it carried.
  function parses(script) {
    try { b.safeSieve.parse(script, { profile: "permissive" }); return null; }
    catch (e) { return e; }
  }

  var c1 = parses('require ["encoded-character"];\n' +
    'if header :contains "X" "N${unicode:85}O" { stop; }');
  check("a run decoding to U+0085 parses, as RFC 5228 section 2.4.2.4 requires",
        c1 === null, c1 ? String(c1.code) + " " + String(c1.message).slice(0, 60) : "ok");

  var beside = parses('require ["encoded-character"];\n' +
    'if header :contains "X" "line1\r\nline2 ${hex:41}" { stop; }');
  check("a literal CRLF beside a run is not blamed on the run",
        beside === null, beside ? String(beside.code) : "ok");

  var nulHex = parses('require ["encoded-character"];\n' +
    'if header :contains "X" "a${hex:00}b" { stop; }');
  check("a run decoding to NUL is refused",
        nulHex !== null && nulHex.code === "safe-sieve/bad-encoded-character",
        nulHex ? String(nulHex.code) : "accepted");

  var nulUni = parses('require ["encoded-character"];\n' +
    'if header :contains "X" "a${unicode:0}b" { stop; }');
  check("and so is the same NUL written as a unicode run",
        nulUni !== null && nulUni.code === "safe-sieve/bad-encoded-character",
        nulUni ? String(nulUni.code) : "accepted");
}

function testWhateverTheParserCertifiesTheInterpreterRuns() {
  // The upload half and the delivery half read the same script, so a script
  // the parser calls valid has to run. The interpreter's cap and the
  // permissive profile's are both 128, and the interpreter counted the
  // top-level command list as a nesting level while the parser does not, so
  // the deepest script the parser accepted was refused at delivery: the
  // mailbox owner uploads a script the server certifies and then loses mail
  // to `mail-sieve/nesting-too-deep`. The cap is probed AT the boundary,
  // since a test that only tries 8 and 20000 cannot see a one-level gap.
  function nest(levels) {
    var open = "";
    var close = "";
    for (var i = 0; i < levels; i += 1) { open += "if true { "; close += " }"; }
    return open + "stop;" + close;
  }

  var deepest = 0;
  for (var n = 1; n <= 130; n += 1) {
    var parsed = null;
    try { parsed = b.safeSieve.parse(nest(n), { profile: "permissive" }); }
    catch (_e) { break; }
    if (parsed === null) break;
    deepest = n;
    var ran = true;
    var code = null;
    try { b.mail.sieve.run(parsed, {}); }
    catch (e) { ran = false; code = e.code || e.message; }
    if (!ran) {
      check("the interpreter runs every depth the parser certifies (level " + n + ")",
            false, String(code));
      return;
    }
  }
  check("the permissive parser's deepest accepted script also runs",
        deepest === 128, "deepest=" + deepest);

  // And one level past it is refused by the parser, so the cap still bites.
  var tooDeep = null;
  try { b.safeSieve.parse(nest(deepest + 1), { profile: "permissive" }); }
  catch (e) { tooDeep = e; }
  check("one level deeper is refused at parse",
        tooDeep !== null, tooDeep ? String(tooDeep.code) : "accepted");
}

function testRunBoundsTheAstItIsHandedRatherThanTheOneItParsed() {
  // run() takes an ast and the only shape check is kind === "script", so the
  // parser's nesting cap is not the interpreter's: the caller chooses the AST.
  // _evalTest recurses through `not` / `anyof` / `allof` exactly as the parser
  // does, and a hand-built tree ran until the stack gave out, which reaches
  // the caller as a bare RangeError carrying no code.
  function nest(levels) {
    var t = { kind: "test", name: "true" };
    for (var i = 0; i < levels; i += 1) t = { kind: "test", name: "not", subs: [t] };
    return {
      kind: "script",
      requiredCaps: [],
      commands: [{
        kind: "if", test: t, elif: [], elseBody: null,
        thenBody: [{ kind: "action", name: "keep", args: { tags: [], positional: [] } }],
      }],
    };
  }

  var threw = null;
  var out = null;
  try { out = b.mail.sieve.run(nest(20000), {}); } catch (e) { threw = e; }
  check("a hand-built AST nested past the cap is refused, not run off the stack",
        threw !== null && !(threw instanceof RangeError) &&
          typeof threw.code === "string" && threw.code.indexOf("mail-sieve/") === 0,
        threw ? (threw.constructor.name + " code=" + threw.code)
              : "ran: " + JSON.stringify(out && out.actions));

  // The test grammar is one of two ways an AST recurses. Commands nest too,
  // through thenBody / elif / elseBody, and bounding only the tests left the
  // other half reaching the caller as the bare RangeError this test's own
  // reasoning calls out.
  function nestBlocks(levels) {
    var inner = { kind: "action", name: "keep", args: { tags: [], positional: [] } };
    for (var i = 0; i < levels; i += 1) {
      inner = {
        kind: "if", test: { kind: "test", name: "true" }, elif: [], elseBody: null,
        thenBody: [inner],
      };
    }
    return { kind: "script", requiredCaps: [], commands: [inner] };
  }
  var blockThrew = null;
  try { b.mail.sieve.run(nestBlocks(20000), {}); } catch (e) { blockThrew = e; }
  check("a hand-built AST whose BLOCKS nest past the cap is refused too",
        blockThrew !== null && !(blockThrew instanceof RangeError) &&
          typeof blockThrew.code === "string" &&
          blockThrew.code.indexOf("mail-sieve/") === 0,
        blockThrew ? (blockThrew.constructor.name + " code=" + blockThrew.code) : "ran");

  var okBlocks = b.mail.sieve.run(nestBlocks(8), {});
  check("blocks nested inside the cap still evaluate",
        okBlocks && Array.isArray(okBlocks.actions),
        JSON.stringify(okBlocks && okBlocks.actions));

  // A tree inside the cap still evaluates, so the refusal is about the depth.
  var okOut = b.mail.sieve.run(nest(8), {});
  check("a hand-built AST inside the cap still evaluates",
        okOut && Array.isArray(okOut.actions),
        JSON.stringify(okOut && okOut.actions));
}

function testCreateOptValidation() {
  var badOpts = null;
  try { b.mail.sieve.create(42); } catch (e) { badOpts = e; }
  check("create refuses non-object opts", badOpts && badOpts.code === "mail-sieve/bad-opt");
  var badGas = null;
  try { b.mail.sieve.create({ maxGas: -1 }); } catch (e) { badGas = e; }
  check("create refuses bad maxGas", badGas && badGas.code === "mail-sieve/bad-opt");
  var overCap = null;
  try { b.mail.sieve.create({ maxGas: b.mail.sieve.MAX_GAS_UNITS + 1 }); }
  catch (e) { overCap = e; }
  check("create refuses maxGas over cap", overCap && overCap.code === "mail-sieve/bad-opt");
}

function testCreateAuditEmissions() {
  var events = [];
  var sieve = b.mail.sieve.create({
    audit: { safeEmit: function (e) { events.push(e.action + "/" + e.outcome); } },
  });
  sieve.runScript('keep;\r\n', {});
  sieve.validateScript('require ["fileinto"];\r\nkeep;\r\n');
  sieve.validateScript('require ["nonsense"];\r\nkeep;\r\n');
  sieve.run(b.safeSieve.parse('keep;\r\n'), {});
  check("create handle emits run + validate(success/failure) + run audit events",
    events.length === 4 &&
    events[0] === "mail.sieve.run/success" &&
    events[1] === "mail.sieve.validate/success" &&
    events[2] === "mail.sieve.validate/failure" &&
    events[3] === "mail.sieve.run/success");
}

function testCreateAuditThrowDropSilent() {
  var sieve = b.mail.sieve.create({
    audit: { safeEmit: function () { throw new Error("audit sink exploded"); } },
  });
  var rv = sieve.runScript('keep;\r\n', {});
  check("create handle survives a throwing audit sink (drop-silent)",
    rv.actions[0].kind === "keep");
}

// A Sieve script is written by the mailbox owner, not the operator: RFC 5228 is
// a user-level filtering language, so `:matches` carries a pattern the server
// did not author and runs it against every message that arrives.
//
// `*` means "any sequence", and translating it to a regex `.*` hands a
// backtracking engine one `.*` per star. Every additional star multiplies the
// number of ways the run can be divided, so the cost is polynomial in the
// subject length with degree equal to the star count — on a subject that never
// supplies the final literal, so the engine has to try all of them.
//
// The gas budget does not bound this: gas counts operations, and one match is
// one operation however long the engine spends inside it.
//
// Measured as GROWTH, because the claim is about the shape of the curve and a
// wall-clock budget is a claim about the machine. The one-star control is
// linear and shows the harness can tell the two apart.
function testWildcardMatchDoesNotBacktrack() {
  function matchOnce(pattern, subjectLen) {
    var script = 'require ["fileinto"];\n' +
                 'if header :matches "Subject" "' + pattern + '" { fileinto "X"; }';
    var env = { headers: [{ name: "Subject", value: "a".repeat(subjectLen) }] };
    b.mail.sieve.runScript(script, env);
  }
  // Shared with the other suites that assert growth, so the reps and the noise
  // floor cannot drift apart between hand-rolled copies.
  function runMatch(pattern, subjectLen) {
    return helpers.bestMs(function () { matchOnce(pattern, subjectLen); }, 3);
  }

  // Control: one star cannot be superlinear, so this reads as a sanity check on
  // the measurement rather than as an assertion about the code.
  //
  // It goes through the SAME re-measuring helper as the real check below. A
  // single ratio with a fixed noise floor was what it used before, and that is
  // the shape the helper exists to replace: on a 64-way-parallel container run
  // the 4000-character sample landed at 2.96ms — just past a 2ms floor — while
  // the 2000-character one was preempted, and the control read x18.4 on a
  // matcher that cannot backtrack at all. Raising the floor would only move the
  // number at which the same jitter wins; re-measuring is what tells jitter and
  // a curve apart, because contention does not reproduce and a curve does.
  var controlLarge = runMatch("*b", 4000);
  var controlSuperlinear = helpers.looksSuperlinear(function (n) {
    matchOnce("*b", n);
  }, { small: 2000, large: 4000, floorMs: 2 });

  // Three stars against a subject with no trailing `b`. A backtracking
  // translation is cubic here, so doubling the subject costs about eight times
  // as much; a matcher that does not backtrack stays near two.
  var small = runMatch("*a*a*b", 400);
  var large = runMatch("*a*a*b", 800);
  var ratio = large / Math.max(small, 0.05);
  // A superlinear-looking ratio is re-measured before it fails anything: a
  // contended runner preempted between two samples reads superlinear on a
  // matcher that cannot backtrack, while a real cubic reproduces every time.
  var reallySuperlinear = helpers.looksSuperlinear(function (n) {
    matchOnce("*a*a*b", n);
  }, { small: 400, large: 800, floorMs: 2 });

  check("sieve :matches — the one-star control scales linearly (" +
        controlLarge.toFixed(2) + "ms at 4000)",
        !controlSuperlinear,
        "control re-measured superlinear at " + controlLarge.toFixed(2) + "ms");
  check("sieve :matches — doubling the subject does not more than double the " +
        "work at three stars (x" + ratio.toFixed(1) + ", " + large.toFixed(1) + "ms)",
        !reallySuperlinear, "x" + ratio.toFixed(1) + " at " + large.toFixed(1) + "ms");

  // `?` matches exactly one character, and folding must not change how many
  // there are. `"İ".toLowerCase()` is two UTF-16 units, so a fold applied
  // to the whole subject would leave a one-character Subject looking like two
  // and `?` failing to match it. `i;ascii-casemap` folds only US-ASCII A-Z
  // (RFC 4790 §9.2), which is length-preserving by construction.
  var dotted = "İ";
  var oneChar = b.mail.sieve.runScript(
    'require ["fileinto"];\nif header :matches :comparator "i;ascii-casemap" "Subject" "?" { fileinto "X"; }',
    { headers: [{ name: "Subject", value: dotted }] });
  check("sieve :matches — `?` still matches a single character whose lowercase " +
        "form is longer than it is",
        oneChar.actions[0].kind === "fileinto", oneChar.actions[0].kind);

  // And the shape an author can type without trying: ten stars on a short
  // subject. Under a backtracking translation this does not return.
  var ten = runMatch("*a*a*a*a*a*a*a*a*a*b", 64);
  check("sieve :matches — ten stars on a 64-character subject stays bounded (" +
        ten.toFixed(1) + "ms)", ten < 250, ten.toFixed(1) + "ms");

  // The property that actually changed: cost no longer tracks the WILDCARD
  // COUNT. The translation was polynomial with degree equal to that count, so
  // each extra `*` multiplied the work by the subject length again. Adding
  // twenty more wildcards to the same pattern should now cost about the same.
  // Measured through the same re-measuring helper as the checks above, with
  // the WILDCARD COUNT as the dimension that varies instead of the subject
  // length. A single ratio between two samples is what reads superlinear on a
  // contended runner; a real degree-per-wildcard curve reproduces.
  var twenty = runMatch("*a".repeat(20) + "*b", 512);
  var byCountSuperlinear = helpers.looksSuperlinear(function (stars) {
    matchOnce("*a".repeat(stars) + "*b", 512);
  }, { small: 3, large: 20, threshold: 8, floorMs: 2 });
  // BOTH terms, because they catch different things at different scales. The
  // absolute bound is what actually fires against the regression this guards:
  // with the fix a 20-star match runs in hundredths of a millisecond, and a
  // return to degree-per-wildcard would run to seconds, so 25ms is a ~2000x
  // margin. The re-measured ratio adds nothing at that speed — it declines to
  // judge below its noise floor — but it is what catches a subtler curve if
  // this ever gets slow enough to take a ratio of.
  check("sieve :matches — cost does not track the number of wildcards (" +
        twenty.toFixed(1) + "ms at 20)",
        twenty < 25 && !byCountSuperlinear,
        twenty.toFixed(1) + "ms" +
        (byCountSuperlinear ? " and re-measured superlinear in wildcard count" : ""));
}

function run() {
  testWildcardMatchDoesNotBacktrack();
  testSurface();
  testImplicitKeep();
  testFileinto();
  testAddressDomain();
  testEnvelope();
  testSize();
  testWildcardMatches();
  testAnyofAllof();
  testRedirect();
  testStop();
  testGasExhaustion();
  testBadAst();
  testCreateHandle();
  testUnknownTestRefused();
  testUnknownActionRefused();
  testBadCommandKind();
  testFileintoMissingFolder();
  testRedirectMissingAddress();
  testNotTest();
  testExists();
  testSizeUnderAndFallbacks();
  testAddressPartsAndExtraction();
  testEnvelopeArrayAndBogusField();
  testHeaderListsAndMultiValue();
  testComparatorDefaultCaseInsensitive();
  testWildcardEscaping();
  testElsifElse();
  testExplicitKeepAndStopSkips();
  testFileintoListArg();
  testGasExhaustionInCommands();
  testMaxGasOptValidation();
  testParseErrorsPropagate();
  testARedirectAddressCannotEndTheSmtpCommandThatCarriesIt();
  testAnEncodedRunIsHeldToWhatALiteralMayCarry();
  testWhateverTheParserCertifiesTheInterpreterRuns();
  testRunBoundsTheAstItIsHandedRatherThanTheOneItParsed();
  testAnEmptyNameIsRefusedInBothSpellings();
  testCreateOptValidation();
  testCreateAuditEmissions();
  testCreateAuditThrowDropSilent();
}

module.exports = { run: run };

if (require.main === module) {
  try { run(); console.log("[mail-sieve] OK"); }
  catch (e) { process.stderr.write("FAIL: " + (e && e.stack || e) + "\n"); process.exit(1); }
}
