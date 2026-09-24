// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * One reader for the quoted-string grammar `b.safeBuffer.quoteString`
 * writes.
 *
 * Two modules had derived the same scanner: `b.guardImapCommand`'s
 * `_firstArgument` and the IMAP listener's own operand reader. Both walk a
 * value that is either a DQUOTE-wrapped run with backslash escapes or a bare
 * run up to the next space, and both are reading strings this framework's
 * own `quoteString` produced. Two copies of one grammar drift, and the one
 * that drifts is whichever is not the one being looked at: a guard that
 * unquotes differently from the listener it guards will pass a command whose
 * argument the listener then reads as something else.
 *
 * The reader lives beside the writer, so the pair can only disagree by
 * someone changing both.
 */

var helpers = require("../helpers");
var check   = helpers.check;
var b       = helpers.b;

function testADelimiterInsideQuotesIsNotTheDelimiter() {
  // The same grammar read from the other side: a reader looking for where an
  // address ends must not stop at a bracket the sender wrote as data. The
  // JMAP From reader and b.guardSmtpCommand both cut
  // `<"a>b"@example.com>` at the first `>` and refused a valid sender.
  var find = b.safeBuffer.unquotedIndexOf;
  check("a delimiter inside a quoted run is skipped",
        find('"a>b"@example.com>', ">") === 17,
        String(find('"a>b"@example.com>', ">")));
  check("a delimiter outside quotes is found",
        find("ops@example.com>", ">") === 15, String(find("ops@example.com>", ">")));
  check("a quoted pair does not close the quoted run",
        find('"a\\">b"@x>', ">") === 9, String(find('"a\\">b"@x>', ">")));
  check("an unterminated quoted run swallows the rest",
        find('"a>b@example.com', ">") === -1, String(find('"a>b@example.com', ">")));
  check("a delimiter that is absent answers -1",
        find("ops@example.com", ">") === -1, String(find("ops@example.com", ">")));
  check("the search starts where the caller says",
        find("a>b>c", ">", 2) === 3, String(find("a>b>c", ">", 2)));
  check("the quoting characters are not delimiters",
        find('"a"', "\"") === -1 && find("a\\b", "\\") === -1,
        JSON.stringify([find('"a"', "\""), find("a\\b", "\\")]));
}

function testItUndoesWhatQuoteStringDid() {
  // The property that matters: for any value the writer accepts, reading
  // back what it wrote returns the value.
  var values = [
    "plain",
    "with space",
    'say "hi"',
    "back\\slash",
    'both "and" \\ together',
    "",
    "trailing ",
    "\\",
    '"',
  ];
  var bad = null;
  for (var i = 0; i < values.length; i += 1) {
    var round = b.safeBuffer.readQuotedString(b.safeBuffer.quoteString(values[i]));
    if (round === null || round.value !== values[i]) {
      bad = { input: values[i], got: round };
      break;
    }
  }
  check("every value quoteString writes reads back unchanged",
        bad === null, JSON.stringify(bad));
}

function testABareRunEndsAtTheFirstSpace() {
  var one = b.safeBuffer.readQuotedString("INBOX rest here");
  check("a bare word stops at the space",
        one !== null && one.value === "INBOX", JSON.stringify(one));
  check("and reports where it stopped",
        one !== null && one.next === "INBOX".length, JSON.stringify(one));

  var only = b.safeBuffer.readQuotedString("INBOX");
  check("a bare word with nothing after it is the whole input",
        only !== null && only.value === "INBOX", JSON.stringify(only));
}

function testAQuotedRunKeepsItsSpaces() {
  var q = b.safeBuffer.readQuotedString('"two words" after');
  check("a quoted run carries spaces through",
        q !== null && q.value === "two words", JSON.stringify(q));
  check("and stops after the closing quote",
        q !== null && q.next === '"two words"'.length, JSON.stringify(q));
}

function testAnUnterminatedQuoteIsRefused() {
  // The reason this is not "return what we have": an unterminated quote means
  // the sender's framing and the reader's disagree, and guessing where the
  // string ends is how one side reads an argument the other did not send.
  check("an unterminated quoted run is refused",
        b.safeBuffer.readQuotedString('"never closed') === null);
  check("a lone backslash at the end is refused too",
        b.safeBuffer.readQuotedString('"escaped\\') === null);
}

function testAnEmptyInputHasNoOperand() {
  check("nothing to read is null", b.safeBuffer.readQuotedString("") === null);
  check("and so is a run of spaces", b.safeBuffer.readQuotedString("   ") === null);
}

function testLeadingSpacesAreSkipped() {
  var v = b.safeBuffer.readQuotedString("   INBOX", 0);
  check("leading spaces are not part of the operand",
        v !== null && v.value === "INBOX", JSON.stringify(v));
}

function testItReadsFromAGivenOffset() {
  var line = 'LIST "" "%"';
  var first = b.safeBuffer.readQuotedString(line, "LIST".length);
  check("reading from an offset finds the next operand",
        first !== null && first.value === "", JSON.stringify(first));
  var second = b.safeBuffer.readQuotedString(line, first.next);
  check("and the offset it reports continues the scan",
        second !== null && second.value === "%", JSON.stringify(second));
}

function testTheGuardAndTheListenerReadTheSameArgument() {
  // The drift this extraction exists to prevent, driven through the two
  // consumers rather than asserted about them.
  var name = 'a "quoted" name';
  var args = b.safeBuffer.quoteString(name);
  var readBack = b.safeBuffer.readQuotedString(args, 0);
  check("the listener's operand reader recovers the name",
        readBack !== null && readBack.value === name, JSON.stringify(readBack));
  var guarded = b.guardImapCommand.validate("a1 SELECT " + args, { profile: "permissive" });
  check("and the guard accepts the line, reading the same operand",
        guarded && guarded.verb === "SELECT" &&
        b.safeBuffer.readQuotedString(guarded.args, 0).value === name,
        JSON.stringify(guarded));
}

function run() {
  testADelimiterInsideQuotesIsNotTheDelimiter();
  testItUndoesWhatQuoteStringDid();
  testABareRunEndsAtTheFirstSpace();
  testAQuotedRunKeepsItsSpaces();
  testAnUnterminatedQuoteIsRefused();
  testAnEmptyInputHasNoOperand();
  testLeadingSpacesAreSkipped();
  testItReadsFromAGivenOffset();
  testTheGuardAndTheListenerReadTheSameArgument();
}

module.exports = { run: run };

if (require.main === module) {
  try {
    run();
    console.log("[safe-buffer-read-quoted] OK — " + helpers.getChecks() + " checks passed");
  } catch (e) {
    console.error("FAIL:", (e && e.stack) || e);
    process.exit(1);
  }
}
