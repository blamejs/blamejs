// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Two questions a Sieve script author asks the library, both previously
 * answered wrong in the direction that loses mail silently.
 *
 * The first is `require ["encoded-character"]`. The capability table said
 * `true`, which put the extension in the ManageSieve capability banner and
 * made `require` succeed, but nothing decoded `${hex:...}` or
 * `${unicode:...}` anywhere. RFC 5228 section 2.4.2.4 defines the extension
 * as exactly that decoding, so a script that declared it, passed `require`
 * and used it filed mail under the literal text `${hex:4a 75 6e 6b}`. The
 * table now matches the tokenizer, which decodes both forms.
 *
 * The second is what `validate` accepts. The grammar reads any identifier
 * followed by arguments as a command, so a script naming an action the
 * interpreter does not implement validated clean. The name was resolved at
 * delivery, where the throw costs the whole script rather than the one line,
 * so `vacation`, `reject` and ordinary typos like `fileinfo` were stored with
 * `ok: true` and every later message was filtered by nothing. `validate`
 * resolves names against the interpreter's own sets, so the author is
 * refused while still looking at the upload.
 *
 * The names come from `b.mail.sieve`, not from a copy kept here: a second
 * list is the thing that rots at the next extension.
 *
 * The grammar the decoder implements, from RFC 5228 section 2.4.2.4, is
 * `*blank hexval *(1*blank hexval) *blank`, where blank is space or tab and
 * hexval is 1*2 HEXDIG for `${hex:...}` and 1*6 HEXDIG for `${unicode:...}`.
 * Anything else inside `${...}` is ordinary text and stays as written, which
 * is what keeps a script using a literal dollar-brace from being refused.
 *
 * A `${hex:...}` run is octets and a Sieve string is text, so the octets are
 * decoded as UTF-8: `${hex:c3 a9}` has to mean the same character as
 * `${unicode:e9}` and as a literal one, or a filter compares against the
 * wrong value and files into the wrong mailbox. The substitutions are
 * assembled with the octets of the text around them and the whole string is
 * decoded once, because a character's octets can be written as two
 * substitutions: decoding each on its own turns `${hex:c3}${hex:a9}` into
 * two replacement characters.
 */

var fs      = require("fs");
var path    = require("path");
var helpers = require("../helpers");
var check   = helpers.check;
var b       = helpers.b;

function _filedInto(script, message, parseOpts) {
  var result = b.mail.sieve.run(b.safeSieve.parse(script, parseOpts), message);
  var actions = (result && result.actions) || [];
  for (var i = 0; i < actions.length; i += 1) {
    if (actions[i].kind === "fileinto") return actions[i].folder;
  }
  return null;
}

var MESSAGE = {
  headers: { subject: "A", from: "a@example.com", to: "b@example.net" },
  body:    "hi",
};

function testHexEscapesDecodeToTheirOctets() {
  var script = 'require ["fileinto","encoded-character"];\r\n' +
               'fileinto "${hex:4a 75 6e 6b}";\r\n';
  check("a hex-encoded folder name decodes to its characters",
        _filedInto(script, MESSAGE) === "Junk", JSON.stringify(_filedInto(script, MESSAGE)));
}

function testUnicodeEscapesDecodeToTheirScalars() {
  var script = 'require ["fileinto","encoded-character"];\r\n' +
               'fileinto "${unicode:2603}";\r\n';
  check("a unicode-encoded folder name decodes to its scalar",
        _filedInto(script, MESSAGE) === "☃", JSON.stringify(_filedInto(script, MESSAGE)));
}

function testTheDecodingIsNotAppliedWithoutTheRequire() {
  // The extension is the gate: an undeclared script keeps the literal text,
  // which is what every reader that does not implement it sees.
  var script = 'require ["fileinto"];\r\nfileinto "${hex:4a 75 6e 6b}";\r\n';
  check("an undeclared script keeps the text as written",
        _filedInto(script, MESSAGE) === "${hex:4a 75 6e 6b}",
        JSON.stringify(_filedInto(script, MESSAGE)));
}

function testTextThatOnlyLooksEncodedIsLeftAlone() {
  // RFC 5228 2.4.2.4 decodes only what matches the grammar; anything else is
  // ordinary text, and turning it into an error would refuse valid scripts.
  var script = 'require ["fileinto","encoded-character"];\r\n' +
               'fileinto "${hex:zz} ${nothex:41} ${unicode}";\r\n';
  check("a non-matching sequence is left exactly as written",
        _filedInto(script, MESSAGE) === "${hex:zz} ${nothex:41} ${unicode}",
        JSON.stringify(_filedInto(script, MESSAGE)));
}

function testHexOctetsDecodeAsUtf8() {
  // The run is octets and a Sieve string is text, so the three spellings of
  // one character have to agree: a script filing on ${hex:c3 a9} and one
  // filing on a literal e-acute must reach the same folder, or a filter
  // silently misfiles.
  var viaHex = 'require ["fileinto","encoded-character"];\r\n' +
               'fileinto "caf${hex:c3 a9}";\r\n';
  var viaUnicode = 'require ["fileinto","encoded-character"];\r\n' +
                   'fileinto "caf${unicode:e9}";\r\n';
  var literal = 'require ["fileinto"];\r\nfileinto "café";\r\n';
  var hexFolder = _filedInto(viaHex, MESSAGE);
  check("a UTF-8 octet run decodes to the character it encodes",
        hexFolder === "café", JSON.stringify(hexFolder));
  check("and agrees with the unicode spelling",
        hexFolder === _filedInto(viaUnicode, MESSAGE),
        JSON.stringify([hexFolder, _filedInto(viaUnicode, MESSAGE)]));
  check("and with the literal one",
        hexFolder === _filedInto(literal, MESSAGE),
        JSON.stringify([hexFolder, _filedInto(literal, MESSAGE)]));

  // The octets of one character can be written as two substitutions, so
  // they are assembled with the text around them and decoded once. Decoding
  // each substitution on its own turns this into two replacement characters.
  var split = 'require ["fileinto","encoded-character"];\r\n' +
              'fileinto "caf${hex:c3}${hex:a9}";\r\n';
  check("a character split across two substitutions is still that character",
        _filedInto(split, MESSAGE) === "café",
        JSON.stringify(_filedInto(split, MESSAGE)));

  // And the halves may be split across a substitution boundary and literal
  // text either side.
  var trailing = 'require ["fileinto","encoded-character"];\r\n' +
                 'fileinto "${hex:c3}${hex:a9}tag";\r\n';
  check("with literal text after it",
        _filedInto(trailing, MESSAGE) === "étag",
        JSON.stringify(_filedInto(trailing, MESSAGE)));
}

function testALongRunInsideTheProfilesStringLimitStillDecodes() {
  // The run is bounded by the string literal that carries it, which the
  // profile already caps. A second fixed cap silently left a valid script's
  // text literal instead of decoding it, so the filter compared against the
  // encoding rather than the characters.
  var octets = [];
  for (var i = 0; i < 1400; i += 1) octets.push("41");
  var script = 'require ["fileinto","encoded-character"];\r\n' +
               'fileinto "${hex:' + octets.join(" ") + '}";\r\n';
  var folder = null;
  try {
    folder = _filedInto(script, MESSAGE, { profile: "balanced" });
  } catch (e) { folder = "threw: " + e.code; }
  check("a long run inside the profile's string limit decodes",
        folder === "A".repeat(1400), typeof folder === "string"
          ? folder.slice(0, 40) + " (len " + folder.length + ")" : String(folder));
}

function testAComparatorNameIsDecodedToo() {
  // Every other string in the script is decoded, so a comparator written
  // the same way has to be: refusing it as unknown reports a comparator the
  // author did not write.
  var script = 'require ["fileinto","encoded-character"];\r\n' +
               'if header :comparator "${hex:69};ascii-casemap" :is "Subject" "A" ' +
               '{ fileinto "Keep"; }\r\n';
  var result = b.safeSieve.validate(script);
  check("a comparator spelled with an encoded character is accepted",
        result.ok === true, JSON.stringify(result.issues || []));

  var ast = b.safeSieve.parse(script);
  var tags = ast.commands[1].test.args.tags;
  var comparator = tags.filter(function (t) { return t.name === "comparator"; })[0];
  check("and it is stored decoded, so the interpreter compares with it",
        comparator && comparator.val === "i;ascii-casemap",
        JSON.stringify(comparator));
}

function testTheHexGrammarBoundsEachValueAtTwoDigits() {
  // hex-pair is 1*2HEXDIG, so a three-digit run is not the grammar and stays
  // literal rather than decoding to something the author did not write.
  var script = 'require ["fileinto","encoded-character"];\r\nfileinto "${hex:414}";\r\n';
  check("a three-digit hex run is not decoded",
        _filedInto(script, MESSAGE) === "${hex:414}", JSON.stringify(_filedInto(script, MESSAGE)));

  var single = 'require ["fileinto","encoded-character"];\r\nfileinto "${hex:4A}";\r\n';
  check("a two-digit run decodes, upper case included",
        _filedInto(single, MESSAGE) === "J", JSON.stringify(_filedInto(single, MESSAGE)));

  // Two octets written without a blank between them are one four-digit run,
  // which is not a hex-pair either. The SEPARATOR is what carries this, and
  // it is required rather than optional: RFC 5228 section 2.4.2.4 writes
  // `hex-pair-seq = *blank hex-pair *(1*blank hex-pair) *blank` with
  // `hex-pair = 1*2HEXDIG`, so a second pair may follow only after `1*blank`.
  // `4142` is therefore one four-digit run, which no hex-pair matches, and
  // the whole encoded sequence stays literal.
  //
  // The example table alone does NOT settle this, which is worth writing down
  // because it was once read as though it did: `"${hex:400}" -> "${hex:400}"`
  // is equally consistent with a rule of exactly-two-digit pairs written
  // adjacently, under which `400` is an odd-length run and also stays
  // literal. The `1*blank` in the production is the part that decides, and
  // under that rule `${hex:4}` is a valid one-digit pair while `${hex:4142}`
  // is not two pairs. The RFC never writes adjacent pairs in an example; its
  // own two-octet case is `"$${hex:24 24}" -> "$$$"`, with the blank.
  var joined = 'require ["fileinto","encoded-character"];\r\nfileinto "${hex:4142}";\r\n';
  check("two octets run together are not split into a pair each",
        _filedInto(joined, MESSAGE) === "${hex:4142}",
        JSON.stringify(_filedInto(joined, MESSAGE)));
  var separated = 'require ["fileinto","encoded-character"];\r\nfileinto "${hex:41 42}";\r\n';
  check("while the same two octets with a blank between them decode",
        _filedInto(separated, MESSAGE) === "AB",
        JSON.stringify(_filedInto(separated, MESSAGE)));

  // One digit is a hex-pair, so it is the octet it names, and the value it
  // decodes to is what proves the digit was read as an octet rather than left
  // as text. RFC 5228 section 2.4.2.4 writes the production as
  // `hex-pair = 1*2HEXDIG`, not `2HEXDIG`: the name says pair, the grammar
  // allows one digit, and the grammar is what the decoder implements.
  var lone = 'require ["fileinto","encoded-character"];\r\nfileinto "a${hex:4}b";\r\n';
  check("a single digit is read as the low octet it names",
        _filedInto(lone, MESSAGE) === "a\u0004b",
        JSON.stringify(_filedInto(lone, MESSAGE)));
}

function testAUnicodeRunHasNoDigitCap() {
  // The two grammars differ: RFC 5228 2.4.2.4 writes hex-pair as 1*2HEXDIG
  // but unicode-hex as 1*HEXDIG, so leading zeros are as valid as any other
  // digit. Reading both through one two-digit-shaped cap left a longer run
  // as literal text, which files mail under the encoding rather than the
  // character it names.
  var padded = 'require ["fileinto","encoded-character"];\r\n' +
               'fileinto "${unicode:0000041}";\r\n';
  check("a run longer than six digits still decodes",
        _filedInto(padded, MESSAGE) === "A", JSON.stringify(_filedInto(padded, MESSAGE)));
  var wide = 'require ["fileinto","encoded-character"];\r\n' +
             'fileinto "${unicode:00002603}";\r\n';
  check("and so does a padded astral-range scalar",
        _filedInto(wide, MESSAGE) === "☃", JSON.stringify(_filedInto(wide, MESSAGE)));

  // The value is still refused when it names no scalar, however it is spelled.
  var tooHigh = b.safeSieve.validate(
    'require ["fileinto","encoded-character"];\r\nfileinto "${unicode:0000110000}";\r\n');
  check("a padded value above 10FFFF is still refused",
        tooHigh.ok === false, JSON.stringify(tooHigh.issues || tooHigh));

  // And the hex grammar keeps its own cap.
  var hex = 'require ["fileinto","encoded-character"];\r\nfileinto "${hex:0041}";\r\n';
  check("a four-digit hex run is still not the hex grammar",
        _filedInto(hex, MESSAGE) === "${hex:0041}", JSON.stringify(_filedInto(hex, MESSAGE)));
}

function testBlanksInsideTheRunAreTabsOrSpaces() {
  var tabbed = 'require ["fileinto","encoded-character"];\r\n' +
               'fileinto "${hex: 4a\t75  6e 6b }";\r\n';
  check("leading, trailing and repeated blanks are all part of the grammar",
        _filedInto(tabbed, MESSAGE) === "Junk", JSON.stringify(_filedInto(tabbed, MESSAGE)));

  var newlined = 'require ["fileinto","encoded-character"];\r\n' +
                 'fileinto "${hex:4a\\n75}";\r\n';
  check("but a newline is not a blank, so the run stays literal",
        String(_filedInto(newlined, MESSAGE)).indexOf("${hex:") === 0,
        JSON.stringify(_filedInto(newlined, MESSAGE)));
}

function testAStringOfFailedCandidatesIsScannedOnce() {
  // Every `${` starts a candidate. A candidate that is not `hex:` or
  // `unicode:` is literal text, and deciding that scanned forward to the next
  // `}` and copied the remainder each time, so a string of them costs the
  // square of how many there are. Measured through validate: 2000/4000/8000/
  // 16000/32000 openers cost 3/13/42/152/606 ms, about four times per
  // doubling. A script is capped at a mebibyte and many such strings fit
  // inside one, so an authenticated PUTSCRIPT holds the event loop before any
  // execution gas applies.
  function timeValidate(count) {
    var script = 'require ["fileinto","encoded-character"];\r\n' +
      'fileinto "' + "${".repeat(count) + ':}";\r\n';
    var started = process.hrtime.bigint();
    try { b.safeSieve.validate(script, { profile: "permissive" }); }
    catch (_e) { /* the shape of the refusal is not what this measures */ }
    return Number((process.hrtime.bigint() - started) / 1000000n);
  }

  var small = timeValidate(8000);
  var large = timeValidate(16000);
  var ratio = small < 20 ? 0 : large / small;
  check("doubling the number of failed candidates does not quadruple the work" +
        " (small=" + small + "ms large=" + large + "ms)",
        ratio < 3, "ratio=" + ratio);

  // Deciding the candidates are literal must still leave them literal, which
  // is what stops this being a test of speed alone.
  var literal = 'require ["fileinto","encoded-character"];\r\n' +
    'fileinto "a${b}c";\r\n';
  check("a candidate that names no encoding stays the text it was",
        _filedInto(literal, MESSAGE) === "a${b}c",
        JSON.stringify(_filedInto(literal, MESSAGE)));
  var mixed = 'require ["fileinto","encoded-character"];\r\n' +
    'fileinto "${nope}${hex:41}${also}";\r\n';
  check("and a real run beside them still decodes",
        _filedInto(mixed, MESSAGE) === "${nope}A${also}",
        JSON.stringify(_filedInto(mixed, MESSAGE)));
}

function testDecodedTextIsNotItselfRescanned() {
  // A single left-to-right pass: bytes that decode into something that looks
  // like another sequence are output, not decoded again.
  var script = 'require ["fileinto","encoded-character"];\r\n' +
               'fileinto "${hex:24 7b 68 65 78 3a 34 31 7d}";\r\n';
  check("decoded output is not decoded a second time",
        _filedInto(script, MESSAGE) === "${hex:41}", JSON.stringify(_filedInto(script, MESSAGE)));
}

function testAnUnpairedSurrogateIsRefused() {
  // Not a Unicode scalar value, so it cannot be encoded at all.
  var refused = b.safeSieve.validate(
    'require ["fileinto","encoded-character"];\r\nfileinto "${unicode:D800}";\r\n');
  check("a surrogate code point is refused rather than substituted",
        refused.ok === false, JSON.stringify(refused.issues || refused));
}

function testAValueAboveTheUnicodeRangeIsRefused() {
  var refused = b.safeSieve.validate(
    'require ["fileinto","encoded-character"];\r\nfileinto "${unicode:110000}";\r\n');
  check("a scalar above 10FFFF is refused", refused.ok === false,
        JSON.stringify(refused.issues || refused));
}

function testOctetsThatAreNotUtf8AreRefused() {
  // A Sieve string is UTF-8 text (RFC 5228 2.4.2), so a hex run that is not a
  // UTF-8 sequence encodes no string at all. Decoding it with replacement
  // characters made ${hex:ff} and ${hex:fe} the same value, so an i;octet
  // comparison matched a byte sequence the script never wrote and an action
  // targeted a folder it never named.
  var lone = b.safeSieve.validate(
    'require ["fileinto","encoded-character"];\r\nfileinto "${hex:ff}";\r\n');
  check("a lone 0xFF octet is refused rather than substituted",
        lone.ok === false, JSON.stringify(lone.issues || lone));
  var truncated = b.safeSieve.validate(
    'require ["fileinto","encoded-character"];\r\nfileinto "${hex:c3}";\r\n');
  check("so is the first half of a two-octet character on its own",
        truncated.ok === false, JSON.stringify(truncated.issues || truncated));
  var pair = b.safeSieve.validate(
    'require ["fileinto","encoded-character"];\r\nfileinto "${hex:c3 a9}";\r\n');
  check("while the complete character is still accepted",
        pair.ok === true, JSON.stringify(pair.issues || pair));
}

function testAnUnimplementedActionIsRefusedAtValidate() {
  // The shape a typo takes: no require names it, so require cannot catch it.
  var result = b.safeSieve.validate('if header :is "Subject" "x" { fileinfo "Junk"; }');
  check("a misspelled action does not validate clean", result.ok === false,
        JSON.stringify(result.issues || result));
  check("and the finding names the command that is not implemented",
        JSON.stringify(result.issues || []).indexOf("fileinfo") !== -1,
        JSON.stringify(result.issues || []));
}

function testAnUnimplementedTestIsRefusedAtValidate() {
  var result = b.safeSieve.validate('if spamtest :is "3" { stop; }');
  check("an unimplemented test does not validate clean", result.ok === false,
        JSON.stringify(result.issues || result));
}

function testEveryImplementedNameStillValidates() {
  // The refusal must not shrink what the interpreter actually runs, so the
  // check is driven from the interpreter's own sets rather than a list here.
  var names = b.mail.sieve.implementedNames();
  check("the interpreter publishes both name sets",
        Array.isArray(names.actions) && names.actions.length > 0 &&
        Array.isArray(names.tests) && names.tests.length > 0,
        JSON.stringify(names));
  var refusedAction = null;
  for (var i = 0; i < names.actions.length; i += 1) {
    var one = b.safeSieve.validate('require ["fileinto"];\r\n' + names.actions[i] + ' "x";');
    if (one.ok === false &&
        JSON.stringify(one.issues || []).indexOf("not implemented") !== -1) {
      refusedAction = names.actions[i];
      break;
    }
  }
  check("no implemented action is refused as unimplemented",
        refusedAction === null, String(refusedAction));

  var refusedTest = null;
  for (var j = 0; j < names.tests.length; j += 1) {
    var t = b.safeSieve.validate('if ' + names.tests[j] + ' "a" "b" { stop; }');
    if (t.ok === false &&
        JSON.stringify(t.issues || []).indexOf("not implemented") !== -1) {
      refusedTest = names.tests[j];
      break;
    }
  }
  check("no implemented test is refused as unimplemented",
        refusedTest === null, String(refusedTest));
}

function testTheCapabilityBannerMatchesWhatIsImplemented() {
  // The banner is what a ManageSieve client reads before it uploads, so a
  // capability advertised there has to be one require can honour.
  var caps = b.safeSieve.KNOWN_CAPABILITIES || {};
  check("encoded-character is advertised only because it is implemented",
        caps["encoded-character"] === true, JSON.stringify(caps["encoded-character"]));
  var declared = b.safeSieve.validate(
    'require ["encoded-character"];\r\nstop;\r\n');
  check("and requiring it succeeds", declared.ok === true,
        JSON.stringify(declared.issues || []));
}

function testThePublishedSetsMatchTheDispatchTheyDescribe() {
  // The sets are what validate refuses against, so a name added to the
  // interpreter and not to the set would be refused at upload while the
  // interpreter runs it. Compare the two rather than trusting they agree.
  var src = fs.readFileSync(path.join(__dirname, "..", "..", "lib", "mail-sieve.js"), "utf8");
  function _namesIn(fnName, varName) {
    var at = src.indexOf("function " + fnName + "(");
    check("the dispatch function " + fnName + " is still there", at !== -1);
    var end = src.indexOf("\n}", at);
    var body = src.slice(at, end);
    var found = {};
    var re = new RegExp(varName + '\\s*===\\s*"([a-z0-9-]+)"', "g");
    var m = re.exec(body);
    while (m !== null) { found[m[1]] = true; m = re.exec(body); }
    return Object.keys(found).sort();
  }
  var names = b.mail.sieve.implementedNames();
  // _evalTest bounds the recursion and hands the dispatch to _evalTestInner,
  // so the names live in the inner one.
  var dispatchTests   = _namesIn("_evalTestInner", "name");
  var dispatchActions = _namesIn("_runCommand", "n");
  check("every test the dispatch answers is published",
        dispatchTests.filter(function (n) { return names.tests.indexOf(n) === -1; }).length === 0,
        JSON.stringify(dispatchTests.filter(function (n) { return names.tests.indexOf(n) === -1; })));
  check("and every published test is one the dispatch answers",
        names.tests.filter(function (n) { return dispatchTests.indexOf(n) === -1; }).length === 0,
        JSON.stringify(names.tests.filter(function (n) { return dispatchTests.indexOf(n) === -1; })));
  check("every action the dispatch answers is published",
        dispatchActions.filter(function (n) { return names.actions.indexOf(n) === -1; }).length === 0,
        JSON.stringify(dispatchActions.filter(function (n) { return names.actions.indexOf(n) === -1; })));
  check("and every published action is one the dispatch answers",
        names.actions.filter(function (n) { return dispatchActions.indexOf(n) === -1; }).length === 0,
        JSON.stringify(names.actions.filter(function (n) { return dispatchActions.indexOf(n) === -1; })));
}

function run() {
  testThePublishedSetsMatchTheDispatchTheyDescribe();
  testHexEscapesDecodeToTheirOctets();
  testUnicodeEscapesDecodeToTheirScalars();
  testTheDecodingIsNotAppliedWithoutTheRequire();
  testTextThatOnlyLooksEncodedIsLeftAlone();
  testHexOctetsDecodeAsUtf8();
  testALongRunInsideTheProfilesStringLimitStillDecodes();
  testAComparatorNameIsDecodedToo();
  testTheHexGrammarBoundsEachValueAtTwoDigits();
  testAUnicodeRunHasNoDigitCap();
  testBlanksInsideTheRunAreTabsOrSpaces();
  testAStringOfFailedCandidatesIsScannedOnce();
  testDecodedTextIsNotItselfRescanned();
  testAnUnpairedSurrogateIsRefused();
  testOctetsThatAreNotUtf8AreRefused();
  testAValueAboveTheUnicodeRangeIsRefused();
  testAnUnimplementedActionIsRefusedAtValidate();
  testAnUnimplementedTestIsRefusedAtValidate();
  testEveryImplementedNameStillValidates();
  testTheCapabilityBannerMatchesWhatIsImplemented();
}

module.exports = { run: run };

if (require.main === module) {
  try {
    run();
    console.log("[safe-sieve-declared-surface] OK — " + helpers.getChecks() + " checks passed");
  } catch (e) {
    console.error("FAIL:", (e && e.stack) || e);
    process.exit(1);
  }
}
