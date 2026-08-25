// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.safeSmtp — SMTP wire-protocol parsing helpers.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function testSurface() {
  check("findDotTerminator is fn", typeof b.safeSmtp.findDotTerminator === "function");
  check("dotUnstuff is fn",        typeof b.safeSmtp.dotUnstuff === "function");
  check("SafeSmtpError is fn",     typeof b.safeSmtp.SafeSmtpError === "function");
}

function testFindDotTerminatorCanonical() {
  var body = Buffer.from("Hello world.\r\n.\r\n", "utf8");
  var idx = b.safeSmtp.findDotTerminator(body);
  check("canonical \\r\\n.\\r\\n found at correct index",
    idx === Buffer.byteLength("Hello world.", "utf8"));
}

function testFindDotTerminatorMissing() {
  check("incomplete body returns -1",
    b.safeSmtp.findDotTerminator(Buffer.from("body without terminator")) === -1);
}

function testFindDotTerminatorStrictCrlf() {
  // Bare-LF alternate terminator MUST NOT match (smuggling defense
  // lives in b.guardSmtpCommand.detectBodySmuggling; the safe-*
  // scanner is strict-CRLF-only by construction).
  check("bare-LF \\n.\\n does not match",
    b.safeSmtp.findDotTerminator(Buffer.from("body\n.\n")) === -1);
  check("CR-only \\r.\\r does not match",
    b.safeSmtp.findDotTerminator(Buffer.from("body\r.\r")) === -1);
}

function testDotUnstuffReverses() {
  var wire = Buffer.from("hello\r\n..secret line\r\nworld\r\n", "utf8");
  var clear = b.safeSmtp.dotUnstuff(wire);
  check("'..' at line start reduced to '.'",
    clear.toString("utf8") === "hello\r\n.secret line\r\nworld\r\n");
}

// RFC 5321 §4.5.2 has the sender stuff a leading dot on ANY line of the body,
// including the first — there is no exemption for it. The unstuffer only looked
// for a dot after a CRLF, so a body whose first line began with a stuffed dot
// arrived with the extra dot still on it: `..signature` delivered as
// `..signature` instead of `.signature`.
//
// dotStuff is the pair, and it stuffs offset 0 correctly, so this was a
// round-trip that did not round-trip.
function testDotUnstuffHandlesTheFirstLine() {
  var wire = Buffer.from("..leading dot\r\nrest\r\n", "latin1");
  check("dotUnstuff: a stuffed dot on the FIRST line is unstuffed",
    b.safeSmtp.dotUnstuff(wire).toString("latin1") === ".leading dot\r\nrest\r\n",
    JSON.stringify(b.safeSmtp.dotUnstuff(wire).toString("latin1")));

  // The pair round-trips: whatever dotStuff produces, dotUnstuff must undo.
  var bodies = [
    ".leading dot\r\nrest\r\n",
    "..already doubled\r\n",
    ".\r\n",
    "ordinary\r\n.mid-body dot\r\n",
    "no dots at all\r\n",
  ];
  var broken = [];
  bodies.forEach(function (text) {
    var original = Buffer.from(text, "latin1");
    var round = b.safeSmtp.dotUnstuff(b.safeSmtp.dotStuff(original));
    if (!round.equals(original)) {
      broken.push(JSON.stringify(text) + " -> " + JSON.stringify(round.toString("latin1")));
    }
  });
  check("dotUnstuff undoes dotStuff for every body, first line included",
        broken.length === 0, broken.join(" | "));
}

function testDotUnstuffPassthrough() {
  var plain = Buffer.from("hello\r\nworld\r\n", "utf8");
  check("plain body passes through unchanged",
    b.safeSmtp.dotUnstuff(plain).toString("utf8") === "hello\r\nworld\r\n");
}

function testDotUnstuffLengthInvariant() {
  // Property: output length is always <= input length.
  var inputs = [
    Buffer.alloc(0),
    Buffer.from("hello"),
    Buffer.from("\r\n..\r\n"),
    Buffer.from("\r\n.."),
    Buffer.from("..."),
    Buffer.from("\r\n....\r\n"),
  ];
  for (var i = 0; i < inputs.length; i += 1) {
    var out = b.safeSmtp.dotUnstuff(inputs[i]);
    check("dotUnstuff output length <= input #" + i, out.length <= inputs[i].length);
  }
}

function testRefusesBadInput() {
  function expectThrow(label, fn) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf("safe-smtp/") === 0);
  }
  expectThrow("findDotTerminator refuses non-Buffer",
    function () { b.safeSmtp.findDotTerminator("not-a-buffer"); });
  expectThrow("dotUnstuff refuses non-Buffer",
    function () { b.safeSmtp.dotUnstuff("not-a-buffer"); });
}

// The incremental scanner has to agree with the whole-buffer scans it replaces
// on EVERY input and at EVERY chunk boundary. Boundaries are the whole risk: a
// pattern straddling one is exactly what the overlap exists for, and an
// off-by-one there is a screen that silently stops seeing the shape it guards.
//
// This is a differential rather than a fixture list, because the two
// implementations share no code — a disagreement is a real defect in one of
// them rather than a typo they both inherited. It found one during development:
// with one-byte chunks the dot-at-body-start shape was missed, because the
// "is this the body's beginning" test asked about bytes CONSUMED rather than
// where the current window starts.
function testBodyScannerAgreesWithTheWholeBufferScans() {
  var bodies = [
    Buffer.from("plain body with no terminator", "latin1"),
    Buffer.from("header\r\n\r\nbody\r\n.\r\n", "latin1"),
    Buffer.from("body\n.\r\nMAIL FROM:<x>\r\n", "latin1"),         // bare-LF before the dot
    Buffer.from("body\r\n.\nMAIL FROM:<x>\r\n", "latin1"),         // bare-LF after the dot
    Buffer.from("body\n.\nMAIL FROM:<x>\r\n", "latin1"),           // bare-LF both sides
    Buffer.from(".\nstarts with a dot line", "latin1"),            // dot at body offset 0
    Buffer.from("\r\n.\r\n", "latin1"),                            // terminator at offset 0
    Buffer.from("a", "latin1"),
    Buffer.alloc(0),
  ];
  var sizes = [1, 2, 3, 4, 5, 7, 13, 64];
  var diffs = [];

  bodies.forEach(function (body, bi) {
    var wholeSmuggling = b.guardSmtpCommand.detectBodySmuggling(body);
    var wholeTerm      = b.safeSmtp.findDotTerminator(body);
    sizes.forEach(function (size) {
      var scan = b.safeSmtp.createBodyScanner();
      var seen = { smuggling: false, terminatorAt: -1 };
      for (var off = 0; off < body.length; off += size) {
        seen = scan.push(body.subarray(off, Math.min(off + size, body.length)));
      }
      if (body.length === 0) seen = scan.push(Buffer.alloc(0));
      if (seen.smuggling !== wholeSmuggling || seen.terminatorAt !== wholeTerm ||
          scan.bytesSeen() !== body.length) {
        diffs.push("body#" + bi + " size=" + size +
                   " smuggling=" + seen.smuggling + "/" + wholeSmuggling +
                   " term=" + seen.terminatorAt + "/" + wholeTerm +
                   " seen=" + scan.bytesSeen() + "/" + body.length);
      }
    });
  });
  check("body scanner: incremental verdicts match the whole-buffer scans at " +
        "every chunk size", diffs.length === 0, diffs.slice(0, 4).join(" | "));

  // And the reason it exists: cost grows with the body, not with the body
  // squared. Both listeners re-derived the whole accumulated buffer per chunk,
  // which made accepting a message quadratic in its size while the byte cap
  // held — a cap bounds BYTES, not processor time.
  function feed(bytes) {
    var chunk = Buffer.alloc(1400, 0x61);
    var scan = b.safeSmtp.createBodyScanner();
    for (var sent = 0; sent < bytes; sent += chunk.length) scan.push(chunk);
  }
  check("body scanner: cost does not grow quadratically with the body",
        !helpers.looksSuperlinear(feed, { small: 1024 * 1024, large: 4 * 1024 * 1024,
                                          threshold: 8, floorMs: 5 }));
}

function run() {
  testBodyScannerAgreesWithTheWholeBufferScans();
  testSurface();
  testFindDotTerminatorCanonical();
  testFindDotTerminatorMissing();
  testFindDotTerminatorStrictCrlf();
  testDotUnstuffReverses();
  testDotUnstuffHandlesTheFirstLine();
  testDotUnstuffPassthrough();
  testDotUnstuffLengthInvariant();
  testRefusesBadInput();
}

module.exports = { run: run };

if (require.main === module) {
  try { run(); console.log("[safe-smtp] OK"); }
  catch (e) { process.stderr.write("FAIL: " + (e && e.stack || e) + "\n"); process.exit(1); }
}
