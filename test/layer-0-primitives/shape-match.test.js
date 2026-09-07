// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Tests for test/helpers/_shape-match.js — a test-time substrate,
 * unit-tested directly rather than only through the codebase-patterns
 * detectors that compose it.
 *
 * This DOES run in smoke: the runner takes every `*.test.js` under the
 * layer directory, and the only opt-out is a `STANDALONE_ONLY` marker in
 * the first 2 KiB, which this file does not carry. The header used to say
 * the opposite, which is the kind of claim that invites a failure here to
 * be read as not blocking.
 */

var vm = require("vm");
var sm = require("../helpers/_shape-match");
var helpers = require("../helpers");

var failed = 0;
var passed = 0;
function check(label, condition) {
  if (condition) { passed += 1; }
  else { failed += 1; console.error("FAIL: " + label); }
}

// ---- findCalls ----

function testFindCallsSimpleIdent() {
  var src = "foo(); bar(1, 2); foo();";
  var calls = sm.findCalls(src, /^foo$/);
  check("findCalls: matches 2 foo()", calls.length === 2);
  check("findCalls: chain is 'foo'", calls[0].chain === "foo");
}

function testFindCallsMemberChain() {
  var src = "audit.emit({}); audit.safeEmit({}); foo.audit.emit({});";
  var calls = sm.findCalls(src, /^audit\.emit$/);
  check("findCalls: catches audit.emit only (not safeEmit)", calls.length === 1);
  check("findCalls: chain is 'audit.emit'", calls[0].chain === "audit.emit");
}

function testFindCallsBracketAccess() {
  var src = 'obj["emit"]({}); obj.emit({});';
  var calls = sm.findCalls(src, /^obj\.emit$/);
  check("findCalls: handles bracket + dot uniformly", calls.length === 2);
}

function testFindCallsIgnoresStrings() {
  var src = 'var x = "audit.emit(payload)"; audit.emit({});';
  var calls = sm.findCalls(src, /^audit\.emit$/);
  check("findCalls: ignores call inside string literal", calls.length === 1);
}

function testFindCallsIgnoresComments() {
  var src = "// audit.emit({}); should be ignored\naudit.emit({});";
  var calls = sm.findCalls(src, /^audit\.emit$/);
  check("findCalls: ignores call inside line comment", calls.length === 1);
}

function testFindCallsIgnoresBlockComments() {
  var src = "/* audit.emit({}); ignore */ audit.emit({});";
  var calls = sm.findCalls(src, /^audit\.emit$/);
  check("findCalls: ignores call inside block comment", calls.length === 1);
}

// ---- findEnclosingTry ----

function testFindEnclosingTryHits() {
  var src = 'function f() { try { audit.emit({}); } catch (e) {} }';
  var calls = sm.findCalls(src, /^audit\.emit$/);
  var encl = sm.findEnclosingTry(src, calls[0].head.start);
  check("findEnclosingTry: finds enclosing try block", encl !== null);
  check("findEnclosingTry: bodyStart < call.start", encl.bodyStart < calls[0].head.start);
  check("findEnclosingTry: bodyEnd > call.end", encl.bodyEnd > calls[0].closeParen);
}

function testFindEnclosingTryMisses() {
  var src = 'function f() { audit.emit({}); }';
  var calls = sm.findCalls(src, /^audit\.emit$/);
  var encl = sm.findEnclosingTry(src, calls[0].head.start);
  check("findEnclosingTry: returns null when no try wraps the call", encl === null);
}

function testFindEnclosingTrySiblingTryDoesNotMatch() {
  var src = 'function f() { try {} catch (e) {} audit.emit({}); }';
  var calls = sm.findCalls(src, /^audit\.emit$/);
  var encl = sm.findEnclosingTry(src, calls[0].head.start);
  check("findEnclosingTry: sibling try block does NOT enclose", encl === null);
}

// ---- aliasesOf ----

function testAliasesOfFindsVarRebind() {
  var src = "var emit = audit.emit; var safe = audit.safeEmit; var unrelated = foo.bar;";
  var aliases = sm.aliasesOf(src, /^audit\.emit$/);
  check("aliasesOf: var emit = audit.emit; → 'emit' is alias",
        aliases["emit"] === "audit.emit");
  check("aliasesOf: doesn't include safe (different chain)",
        aliases["safe"] === undefined);
  check("aliasesOf: doesn't include unrelated",
        aliases["unrelated"] === undefined);
}

function testAliasesOfFindsConstRebind() {
  var src = "const emit = audit.emit;";
  var aliases = sm.aliasesOf(src, /^audit\.emit$/);
  check("aliasesOf: handles const",
        aliases["emit"] === "audit.emit");
}

// ---- Tokenizer edge cases ----

function testTokenizerHandlesTemplateLiteral() {
  var src = "var x = `hello ${name}` + audit.emit({});";
  var calls = sm.findCalls(src, /^audit\.emit$/);
  check("tokenizer: template literal doesn't swallow surrounding calls",
        calls.length === 1);
}

function testTokenizerHandlesRegexAfterReturn() {
  var src = "function f() { return /audit\\.emit/.test(x); } audit.emit({});";
  var calls = sm.findCalls(src, /^audit\.emit$/);
  check("tokenizer: regex literal after return doesn't trip findCalls",
        calls.length === 1);
}

// ---- template substitutions ----

// Reading where a substitution ends costs the substitution, not the rest of
// the file. It used to lex the whole remainder for each one, and each nested
// template in that remainder lexed ITS remainder again: 1,280 one-substitution
// templates took 11.4 seconds, growing about eightfold per doubling.
function testTemplateRunStaysLinear() {
  var UNIT = "var x = `a${1}`;\n";
  check("tokenizer: a run of templates reads the same tokens either way",
        sm.tokenize(UNIT.repeat(64)).filter(function (t) {
          return t.type === sm.TOK_TEMPLATE;
        }).length === 64);
  check("tokenizer: a run of templates does not grow superlinearly",
        !helpers.looksSuperlinear(function (n) {
          sm.tokenize(UNIT.repeat(n));
        }, { small: 320, large: 640,
             label: "shape-match: tokenize over a run of templates" }));
}

// ---- regexSpans ----

// The one answer to "which slashes open a pattern", for both readers in the
// file and for the one that extracts literals.
function testRegexSpansReadsPatterns() {
  var read = sm.regexSpans("var re = /a+/g; var n = 4 / 2;");
  check("regexSpans: a pattern is one span and a division is none",
        read !== null && Object.keys(read.spans).length === 1 &&
        read.unread.length === 0);
  var start = Number(Object.keys(read.spans)[0]);
  check("regexSpans: the span covers the literal and its flags",
        "var re = /a+/g; var n = 4 / 2;".slice(start, read.spans[start]) === "/a+/g");

  // A template is one token, so a pattern inside a substitution reaches no
  // caller reading pattern tokens.
  var inSub = sm.regexSpans("var t = `${ /a+/.test(s) }`;");
  check("regexSpans: a pattern inside a substitution is found",
        inSub !== null && Object.keys(inSub.spans).length === 1);

  // Readable and holding no pattern is NOT the same answer as unreadable: a
  // caller told there are none reads every slash as division.
  var none = sm.regexSpans("var n = 4 / 2;");
  check("regexSpans: a source with no pattern reads clean and names no region",
        none !== null && Object.keys(none.spans).length === 0 &&
        none.unread.length === 0);
}

// The stripper takes its slash decisions from that same table, so a pattern
// holding a comment opener is not read as division. Left to its own reading it
// swallowed the rest of the file.
function testStripperKeepsPatternsHoldingCommentOpeners() {
  var cases = [
    "var re = /[/*]/.test(s); var after = 1;",
    "var await = 4; var g = async x => 1; await / 2; var re = /[/*]/; var after = 1;",
    "var await = 4; var t = `${await / 2}`; var re = /[/*]/; var after = 1;",
    // The loop carries the label the jump names, since a `break` to a label
    // nothing declares is an early error and pins nothing.
    "async: while (x) { break async\n/[/*]/.test(t); var after = 1; }",
    // A bare arrow cannot be a division operand, so what follows its body is a
    // statement, which may begin with a pattern.
    "var q = () => {}\n/[a/*]/.test(s); var after = 1;",
    "var q2 = (() => {}) / 2; var re = /[/*]/; var after = 1;",
    // The HTML-like comment forms a script accepts.
    "<!-- comment\n/[/*]/.test(s); var after = 1;",
  ];
  // Each fixture is put to the parser first: one written on source no parser
  // accepts pins nothing, and two of these did before they were corrected.
  var unparseable = 0;
  cases.forEach(function (src) {
    try { new vm.Script("(function () {\n" + src + "\n})"); }
    catch (_e) { unparseable += 1; }
  });
  check("stripComments: every fixture here is valid source", unparseable === 0);
  var kept = 0;
  cases.forEach(function (src) {
    if (sm.stripComments(src).indexOf("var after = 1") !== -1) kept += 1;
  });
  check("stripComments: a slash read as an opener cannot delete the file",
        kept === cases.length);
}

// Reading the patterns in a source costs one pass over it. Reading them back
// out of each substitution after the fact cost a pass per nesting level, and
// 800 nested substitutions took 99ms where the whole file takes under one.
function testNestedSubstitutionsStayLinear() {
  function nested(depth) {
    var s = "x";
    for (var i = 0; i < depth; i += 1) s = "`${" + s + "}`";
    return "var d = " + s + ";";
  }
  check("regexSpans: a deeply nested substitution is still read",
        sm.regexSpans("var d = `${`${ /a+/.test(s) }`}`;") !== null &&
        Object.keys(sm.regexSpans("var d = `${`${ /a+/.test(s) }`}`;").spans)
          .length === 1);
  check("stripComments: nesting substitutions does not grow the work",
        !helpers.looksSuperlinear(function (depth) {
          sm.stripComments(nested(depth));
        }, { small: 400, large: 800,
             label: "shape-match: stripComments over nested substitutions" }));

  // Past the depth the recursive read can carry, it runs out of stack and the
  // brace COUNT finds where the substitution ends without reading inside it.
  // The table is then short by whatever that substitution held, which is worse
  // than no table: the caller reads every slash in there as division, and a
  // pattern holding a `/*` opens a comment that runs to the end of the file.
  var deep = "var t=" + "`${".repeat(1600) + "/[/*]/.test(x)" +
             "}`".repeat(1600) + "; var after=1;";
  var deepParses = true;
  try { new vm.Script("(function () {\n" + deep + "\n})"); }
  catch (_e) { deepParses = false; }
  // Whether the read reaches that depth depends on the stack the process was
  // given, so the claim is not that it fails: it is that the answer is never a
  // table that quietly omits what it did not read. Either the region was read
  // and the pattern is in the table, or the source is reported unread.
  //
  // A process whose stack cannot parse the fixture at all holds the reader to
  // nothing, so that is said rather than passed over: `--stack-size=200`
  // reaches it, the default and larger do not.
  if (!deepParses) {
    check("regexSpans: deep nesting is not exercised, this stack cannot parse it",
          true);
    return;
  }
  var deepRead = sm.regexSpans(deep);
  var deepComplete = deepRead !== null &&
    Object.keys(deepRead.spans).some(function (k) {
      return deep.slice(Number(k), deepRead.spans[k]) === "/[/*]/";
    });
  check("regexSpans: an answer is complete or it names the region it did not read",
        deepRead === null || deepComplete || deepRead.unread.length > 0);

  // A region that went unread costs that region and nothing else. The patterns
  // beside it are still found, and a reader that discarded them fell back over
  // code it had already read.
  var beside = "var re = /(a+)+$/;\n" + nested(1600);
  var besideRead = sm.regexSpans(beside);
  check("regexSpans: a pattern beside an unread region is still found",
        besideRead === null || Object.keys(besideRead.spans).some(function (k) {
          return beside.slice(Number(k), besideRead.spans[k]) === "/(a+)+$/";
        }));
  var stripped = sm.stripComments(deep);
  var strippedParses = true;
  try { new vm.Script("(function () {\n" + stripped + "\n})"); }
  catch (_e2) { strippedParses = false; }
  check("stripComments: an unread region falls back rather than deleting the file",
        strippedParses && stripped.indexOf("var after=1") !== -1);
}

function run() {
  testNestedSubstitutionsStayLinear();
  testRegexSpansReadsPatterns();
  testStripperKeepsPatternsHoldingCommentOpeners();
  testFindCallsSimpleIdent();
  testFindCallsMemberChain();
  testFindCallsBracketAccess();
  testFindCallsIgnoresStrings();
  testFindCallsIgnoresComments();
  testFindCallsIgnoresBlockComments();
  testFindEnclosingTryHits();
  testFindEnclosingTryMisses();
  testFindEnclosingTrySiblingTryDoesNotMatch();
  testAliasesOfFindsVarRebind();
  testAliasesOfFindsConstRebind();
  testTokenizerHandlesTemplateLiteral();
  testTokenizerHandlesRegexAfterReturn();
  testTemplateRunStaysLinear();

  if (failed > 0) {
    console.error("\n" + failed + " check(s) FAILED, " + passed + " passed");
    process.exit(1);
  }
  console.log("OK — " + passed + " checks passed");
}

if (require.main === module) run();
module.exports = { run: run };
