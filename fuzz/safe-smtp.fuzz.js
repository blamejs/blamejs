// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: b.mail.server.mx wire-protocol layer.
 *
 * Targets the three byte-scan helpers that defend SMTP smuggling
 * (CVE-2023-51764 / CVE-2024-32178) and the RFC 5321 §4.5.2 dot-
 * stuffing reversal. Operator-supplied byte input drives the SMTP
 * server's DATA-body ingestion; the engine mutates these bytes to
 * find shapes the detectors miss OR shapes the detectors flag
 * spuriously.
 *
 * libFuzzer / jazzer.js harness; ClusterFuzzLite consumes this shape.
 *
 * Expected behavior:
 *   - _detectSmugglingShape returns boolean; never throws.
 *   - _findDotTerminator returns -1 or a valid byte index in [0, buf.length].
 *   - _dotUnstuff returns a Buffer of length <= input length; never throws.
 */

var guardSmtpCommand = require("../lib/guard-smtp-command");
var safeSmtp         = require("../lib/safe-smtp");
var expected = require("./_expected");

module.exports.fuzz = function (data) {
  // Skip empty + huge inputs — libFuzzer mutates length too.
  if (data.length === 0 || data.length > 1 * 1024 * 1024) return;

  try {
    // 1. guardSmtpCommand.detectBodySmuggling — must return boolean.
    var smuggling = guardSmtpCommand.detectBodySmuggling(data);
    if (typeof smuggling !== "boolean") {
      throw new Error("detectBodySmuggling returned non-boolean: " + typeof smuggling);
    }

    // 2. safeSmtp.findDotTerminator — must return -1 OR an index in range.
    var endIdx = safeSmtp.findDotTerminator(data);
    if (typeof endIdx !== "number") {
      throw new Error("findDotTerminator returned non-number: " + typeof endIdx);
    }
    if (endIdx !== -1 && (endIdx < 0 || endIdx > data.length)) {
      throw new Error("findDotTerminator returned out-of-range index: " + endIdx);
    }
    // The index is where the MAIL DATA ends, which RFC 5321 §4.1.1.4 puts
    // after the terminator's leading CRLF -- that CRLF ends the last line of
    // the message. So the 5-byte terminator starts two octets BEFORE the
    // returned index.
    //
    // Empty mail data is the exception and returns 0: the client answered the
    // 354 with `.\r\n` alone, and the CRLF that opens the terminator ended the
    // DATA command line, so it is not in this buffer.
    if (endIdx === 0) {
      if (data[0] !== 0x2e || data[1] !== 0x0d || data[2] !== 0x0a) {
        throw new Error("findDotTerminator returned 0 without a leading dot-line");
      }
    } else if (endIdx !== -1) {
      var t = endIdx - 2;
      if (data[t]     !== 0x0d || data[t + 1] !== 0x0a ||
          data[t + 2] !== 0x2e ||
          data[t + 3] !== 0x0d || data[t + 4] !== 0x0a) {
        throw new Error("findDotTerminator returned index without CRLF.CRLF: " + endIdx);
      }
    }

    // 3. safeSmtp.dotUnstuff — must return a Buffer; length never exceeds input.
    var unstuffed = safeSmtp.dotUnstuff(data);
    if (!Buffer.isBuffer(unstuffed)) {
      throw new Error("dotUnstuff returned non-Buffer: " + typeof unstuffed);
    }
    if (unstuffed.length > data.length) {
      throw new Error("dotUnstuff returned longer buffer: " + unstuffed.length + " > " + data.length);
    }
  } catch (e) {
    if (expected.isExpected(e)) return;
    throw e;
  }
};
