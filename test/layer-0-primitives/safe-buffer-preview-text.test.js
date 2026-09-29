// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A refusal that quotes the input it refused renders it, rather than
 * repeating a stranger's bytes.
 *
 * Three parsers had each derived the same helper: cap the text at 64
 * characters and interpolate it. A length cap named for a log preview reads
 * like a safety measure and is only a size limit, so an escape opening an
 * erase-in-line sequence reached whatever printed the message and erased the
 * line it was printed beside, and a right-to-left override reversed the
 * remainder of the sentence an operator was reading. The input to all three
 * is a document a stranger sent.
 *
 * One primitive renders it: printable US-ASCII passes through, everything
 * else becomes a code-point escape, and the cap stays. The three parsers
 * compose it, so a fourth parser gets the behaviour by using the primitive
 * rather than by remembering the hazard.
 */

var helpers = require("../helpers");
var check   = helpers.check;
var b       = helpers.b;

// Built from code points so this source file carries none of them: a fixture
// holding the raw bytes is the hazard it is testing for.
var ESC = String.fromCharCode(0x1b);
var CSI = String.fromCharCode(0x9b);
var ESC_ERASE = ESC + "[2K";
var RLO = String.fromCharCode(0x202e);

function testPrintableAsciiPassesThrough() {
  check("ordinary text is unchanged",
        b.safeBuffer.previewText("BEGIN:VCALENDAR") === "BEGIN:VCALENDAR",
        JSON.stringify(b.safeBuffer.previewText("BEGIN:VCALENDAR")));
  check("punctuation and spaces are unchanged",
        b.safeBuffer.previewText('a "b" c; d=e') === 'a "b" c; d=e',
        JSON.stringify(b.safeBuffer.previewText('a "b" c; d=e')));
}

function testEverythingElseIsEscaped() {
  var out = b.safeBuffer.previewText("X" + ESC_ERASE + RLO + CSI + "Y");
  check("no escape, override or C1 byte survives",
        out.indexOf(ESC) === -1 && out.indexOf(RLO) === -1 &&
        out.indexOf(CSI) === -1, JSON.stringify(out));
  check("each is rendered by code point instead",
        out.indexOf("\\u{1b}") !== -1 && out.indexOf("\\u{202e}") !== -1 &&
        out.indexOf("\\u{9b}") !== -1, JSON.stringify(out));
  check("and the surrounding text is still readable",
        out.indexOf("X") === 0 && out.charAt(out.length - 1) === "Y",
        JSON.stringify(out));
}

function testTheLengthCapIsKept() {
  var long = b.safeBuffer.previewText("a".repeat(200));
  check("a long input is still capped", long.length < 200, String(long.length));
  check("and says it was truncated",
        long.slice(-3) === "...", JSON.stringify(long.slice(-8)));
}

function testANonStringIsCoerced() {
  check("a non-string is coerced rather than thrown at",
        b.safeBuffer.previewText(42) === "42", b.safeBuffer.previewText(42));
  check("null and undefined render as text",
        typeof b.safeBuffer.previewText(null) === "string" &&
        typeof b.safeBuffer.previewText(undefined) === "string");
}

function _refusalMessage(fn) {
  try { fn(); return null; }
  catch (e) { return (e && e.message) || String(e); }
}

// Scanned by code point rather than matched: a regex holding these bytes is
// itself a source file carrying control characters.
function _carriesRawBytes(message) {
  if (message === null) return false;
  for (var i = 0; i < message.length; i += 1) {
    var c = message.charCodeAt(i);
    if (c < 0x20 && c !== 0x09 && c !== 0x0a && c !== 0x0d) return true;
    if (c === 0x7f) return true;
    if (c >= 0x80 && c <= 0x9f) return true;
    if (c >= 0x202a && c <= 0x202e) return true;
  }
  return false;
}

function testEveryParserThatQuotesItsInputRendersIt() {
  // Driven through each parser's own refusal rather than asserted about the
  // helper, because the hazard is what the consumer's message carries.
  var hostile = "X" + ESC_ERASE + RLO + CSI;
  var offenders = [];

  var mime = _refusalMessage(function () {
    b.safeMime.parse(Buffer.from(hostile + " no colon here\r\n\r\nbody\r\n", "utf8"));
  });
  if (_carriesRawBytes(mime)) offenders.push({ parser: "safeMime", message: mime });

  var ical = _refusalMessage(function () {
    b.safeIcal.parse("BEGIN:VCALENDAR\r\n" + hostile + "\r\nEND:VCALENDAR\r\n");
  });
  if (_carriesRawBytes(ical)) offenders.push({ parser: "safeIcal", message: ical });

  var vcard = _refusalMessage(function () {
    b.safeVcard.parse("BEGIN:VCARD\r\n" + hostile + "\r\nEND:VCARD\r\n");
  });
  if (_carriesRawBytes(vcard)) offenders.push({ parser: "safeVcard", message: vcard });

  check("no parser's refusal carries a raw control or bidi byte",
        offenders.length === 0, JSON.stringify(offenders));
}

function run() {
  testPrintableAsciiPassesThrough();
  testEverythingElseIsEscaped();
  testTheLengthCapIsKept();
  testANonStringIsCoerced();
  testEveryParserThatQuotesItsInputRendersIt();
}

module.exports = { run: run };

if (require.main === module) {
  try {
    run();
    console.log("[safe-buffer-preview-text] OK — " + helpers.getChecks() + " checks passed");
  } catch (e) {
    console.error("FAIL:", (e && e.stack) || e);
    process.exit(1);
  }
}
