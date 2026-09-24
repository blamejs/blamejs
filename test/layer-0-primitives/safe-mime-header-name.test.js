// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A header name is held to the grammar its value already was, and no refusal
 * carries a stranger's bytes out raw.
 *
 * `safeMime.parse` ran `firstControlCharOffset` over the header value and
 * over nothing else. The name arrived from a split, a trim and a lowercase,
 * so whatever a peer put before the colon became a key in the header map and
 * came back out through `names()` and `raw`. RFC 5322 section 3.6.8 spells
 * the name as `field-name = 1*ftext` with `ftext = %d33-57 / %d59-126`,
 * printable US-ASCII without the colon, written as explicit numeric ranges,
 * so RFC 6532 (which widens `VCHAR` and `text` for internationalized field
 * bodies) does not widen it.
 *
 * The same bytes then left through two refusals. The control-char refusal
 * renders the value's offending byte carefully, as a hex code and a byte
 * offset, and interpolated the unvalidated name raw in the same sentence.
 * The missing-colon refusal passed the line through a helper that capped
 * length and screened nothing.
 *
 * That matters because these bytes are a stranger's to choose. An escape
 * opening an erase-in-line sequence makes a consumer writing the refusal to
 * a terminal lose the line it printed beside; a right-to-left override
 * reverses the rest of the sentence an operator is reading. A consumer
 * cannot screen the message afterwards, because by then the parser has
 * already decided what the sentence says.
 */

var helpers = require("../helpers");
var check   = helpers.check;
var b       = helpers.b;

// Built from code points so this source file carries none of them.
var CSI = String.fromCharCode(0x9b);
var ESC_ERASE = String.fromCharCode(0x1b) + "[2K";
var RLO = String.fromCharCode(0x202e);
var DEL = String.fromCharCode(0x7f);
var SOH = String.fromCharCode(0x01);

function _message(headerLines) {
  return Buffer.from(headerLines.join("\r\n") + "\r\n\r\nbody\r\n", "utf8");
}

function _parseError(bytes) {
  try { b.safeMime.parse(bytes); return null; }
  catch (e) { return e; }
}

// Scanned by code point rather than matched: a regex holding these bytes is
// itself a source file carrying control characters.
function _firstRawByteOffset(text) {
  for (var i = 0; i < text.length; i += 1) {
    var c = text.charCodeAt(i);
    if (c < 0x20 && c !== 0x09 && c !== 0x0a && c !== 0x0d) return i;
    if (c === 0x7f) return i;
    if (c >= 0x80 && c <= 0x9f) return i;
    if (c >= 0x202a && c <= 0x202e) return i;
  }
  return -1;
}

function testAFieldNameOutsideFtextIsRefused() {
  var cases = [
    { label: "a C1 control", name: "X-Probe" + CSI },
    { label: "an ANSI escape", name: "X-Esc" + ESC_ERASE },
    { label: "a bidi override", name: "X-Rlo" + RLO },
    { label: "a space inside the name", name: "X Probe" },
    { label: "a DEL byte", name: "X-Del" + DEL },
    { label: "a non-ASCII letter", name: "X-Pröbe" },
  ];
  var accepted = [];
  for (var i = 0; i < cases.length; i += 1) {
    var err = _parseError(_message([cases[i].name + ": value", "Subject: ok"]));
    if (err === null || err.code !== "safe-mime/bad-header-name") {
      accepted.push({ label: cases[i].label, code: err && err.code });
    }
  }
  check("every field name outside ftext is refused by its own code",
        accepted.length === 0, JSON.stringify(accepted));
}

function testAnOrdinaryNameIsStillAccepted() {
  // ftext is %d33-57 / %d59-126, so the punctuation real headers use has to
  // keep working: a refusal that ate List-Unsubscribe would be worse than
  // the hole.
  var ok = _parseError(_message([
    "Subject: hi",
    "X-Spam_Score: 4.2",
    "Content-Type: text/plain",
    "List-Unsubscribe: <mailto:x@example.com>",
    "DKIM-Signature: v=1; a=rsa-sha256",
    "X-Weird!#$%&'*+-.^_`|~: still ftext",
  ]));
  check("a message of ordinary header names still parses", ok === null,
        ok && (ok.code + ": " + ok.message));
}

function testTheRefusalDoesNotCarryTheNameRaw() {
  var err = _parseError(_message(["X-Probe" + CSI + ": value", "Subject: ok"]));
  check("the bad name is refused", err !== null && err.code === "safe-mime/bad-header-name",
        err && err.code);
  var message = (err && err.message) || "";
  check("and its control byte does not reach the message",
        message.indexOf(CSI) === -1, JSON.stringify(message));
  check("the offending byte is reported positionally instead",
        /0x9b/i.test(message) && /offset/.test(message), JSON.stringify(message));
}

function testTheControlCharRefusalDoesNotCarryTheNameRaw() {
  // The sentence that reported the value's byte carefully and the name's
  // raw. A name that is valid but a value that is not still names the
  // header, so the header has to be identifiable without echoing it.
  var err = _parseError(_message(["X-Ok: bad" + SOH + "value", "Subject: ok"]));
  check("a control char in the value is still refused",
        err !== null && err.code === "safe-mime/control-char-in-header",
        err && err.code);
  var message = (err && err.message) || "";
  check("the value's byte is reported as hex with an offset",
        /0x1\b/.test(message) && /offset/.test(message), JSON.stringify(message));
  check("and no raw control byte is anywhere in the sentence",
        _firstRawByteOffset(message) === -1, JSON.stringify(message));
}

function testTheMissingColonRefusalEscapesWhatItPreviews() {
  var err = _parseError(_message([
    "X-Probe" + CSI + ESC_ERASE + RLO + "gpj.exe no colon here",
    "Subject: ok",
  ]));
  check("a header line without a colon is refused", err !== null, err && err.code);
  var message = (err && err.message) || "";
  check("no raw control or bidi byte reaches the message",
        _firstRawByteOffset(message) === -1, JSON.stringify(message));
}

function testNoParsedNameCanCarryAControlByte() {
  // The store, not just the messages: whatever survives parsing is what a
  // consumer lists, and it has to be inside the grammar.
  var parsed = null;
  try {
    parsed = b.safeMime.parse(_message(["Subject: fine", "X-Also-Fine: yes"]));
  } catch (_e) { parsed = null; }
  check("a clean message parses", parsed !== null);
  var names = parsed ? parsed.headers.names() : [];
  var bad = names.filter(function (n) {
    for (var i = 0; i < n.length; i += 1) {
      var c = n.charCodeAt(i);
      if (c < 33 || c > 126 || c === 58) return true;
    }
    return false;
  });
  check("every stored name is inside ftext", bad.length === 0, JSON.stringify(bad));
}

// RFC 2046 section 5.1.5: a multipart/digest "is syntactically identical to
// multipart/mixed, but the semantics are different. In particular, in a
// digest, the default Content-Type value for a body part is changed from
// text/plain to message/rfc822." RFC 8621 section 4.1.4 says the same for the
// `type` property it defines. Defaulting every part with no Content-Type to
// text/plain read a digest's enclosed messages as plain-text bodies, so the
// first one became the message's body and the rest became files.
function testADigestPartDefaultsToTheEnclosedMessageType() {
  var digest = b.safeMime.parse(Buffer.from([
    "From: a@example.com", "Subject: s", "MIME-Version: 1.0",
    'Content-Type: multipart/digest; boundary="d"', "",
    "--d", "", "From: inner@example.com\r\nSubject: inner\r\n\r\ninner body",
    "--d", "", "From: second@example.com\r\nSubject: second\r\n\r\nsecond body",
    "--d--", "",
  ].join("\r\n"), "utf8"));
  var types = [];
  b.safeMime.walk(digest, function (part) {
    if (part.leaf) types.push(part.leaf.contentType);
  });
  check("a digest part carrying no Content-Type is an enclosed message",
        types.length === 2 && types[0] === "message/rfc822" &&
        types[1] === "message/rfc822", JSON.stringify(types));

  // The same part inside a multipart/mixed keeps the ordinary default.
  var mixed = b.safeMime.parse(Buffer.from([
    "From: a@example.com", "Subject: s", "MIME-Version: 1.0",
    'Content-Type: multipart/mixed; boundary="m"', "",
    "--m", "X-Note: no content type here", "", "just text",
    "--m--", "",
  ].join("\r\n"), "utf8"));
  var mixedTypes = [];
  b.safeMime.walk(mixed, function (part) {
    if (part.leaf) mixedTypes.push(part.leaf.contentType);
  });
  check("and the default elsewhere is still text/plain",
        mixedTypes.length === 1 && mixedTypes[0] === "text/plain",
        JSON.stringify(mixedTypes));
}

// RFC 5322 section 2.1.1 caps a line at 998 characters and section 2.1 makes
// those characters US-ASCII octets; RFC 6532 section 3.4 widens the field body
// to UTF-8 and keeps the limit in octets. `maxHeaderLineBytes` is named in
// bytes and was compared against `line.length`, which counts UTF-16 code
// units, so a line of multibyte characters passed a cap it exceeds: 700 two-
// byte characters measure 700 against a 998 cap and occupy 1400 octets.
function testTheHeaderLineCapIsMeasuredInBytes() {
  var eAcute = String.fromCharCode(0xe9);
  function _message(count) {
    return Buffer.from([
      "From: a@example.com",
      "X-Note: " + new Array(count + 1).join(eAcute),
      "Subject: s", "", "body", "",
    ].join("\r\n"), "utf8");
  }
  var over = _parseError(_message(700));
  check("a header line over the cap in bytes is refused",
        over !== null && over.code === "safe-mime/oversize-header-line",
        over && (over.code + ": " + over.message));

  // The same field short enough to fit in the cap still parses, so the
  // refusal is the length and not the character set.
  var under = _parseError(_message(400));
  check("and a multibyte line that fits is still accepted", under === null,
        under && (under.code + ": " + under.message));
}

// The ftext check reads the name a key/value split HANDED it, and that split
// trims. So `Content-Type : text/html` arrived as `content-type`, which is
// valid ftext, and the space RFC 5322 section 3.6.8 forbids never reached the
// check: `field-name = 1*ftext` with `ftext = %d33-57 / %d59-126` admits no
// space. A receiver that reads the raw name sees a field called
// `Content-Type ` and no `Content-Type`, so it does not apply the MIME
// semantics this parser applies, which is the disagreement the check exists to
// stop. An empty name passed for the same reason: the loop over zero
// characters finds no offending byte.
function testTheFieldNameIsCheckedAsTheBytesCarriedIt() {
  var CASES = [
    { label: "a space before the colon", line: "Content-Type : text/html" },
    { label: "a tab before the colon", line: "Content-Type\t: text/html" },
    { label: "an empty name", line: ": value" },
    { label: "only whitespace before the colon", line: "  : value" },
    { label: "a space inside and before", line: "X Probe : value" },
  ];
  var accepted = [];
  for (var i = 0; i < CASES.length; i += 1) {
    var err = _parseError(_message([CASES[i].line, "Subject: ok"]));
    if (err === null || err.code !== "safe-mime/bad-header-name") {
      accepted.push(CASES[i].label + " -> " + (err === null ? "accepted" : err.code));
    }
  }
  check("a field name is held to ftext as the bytes carried it" +
        (accepted.length ? " (" + accepted.join("; ") + ")" : ""),
        accepted.length === 0);

  // A conformant header still parses, so the check is the raw name and not a
  // refusal of ordinary mail.
  var ok = _parseError(_message([
    "Subject: hi", "Content-Type: text/plain", "X-Spam_Score: 4.2",
  ]));
  check("an ordinary header block still parses", ok === null,
        ok && (ok.code + ": " + ok.message));
}

function run() {
  testADigestPartDefaultsToTheEnclosedMessageType();
  testTheFieldNameIsCheckedAsTheBytesCarriedIt();
  testTheHeaderLineCapIsMeasuredInBytes();
  testAFieldNameOutsideFtextIsRefused();
  testAnOrdinaryNameIsStillAccepted();
  testTheRefusalDoesNotCarryTheNameRaw();
  testTheControlCharRefusalDoesNotCarryTheNameRaw();
  testTheMissingColonRefusalEscapesWhatItPreviews();
  testNoParsedNameCanCarryAControlByte();
}

module.exports = { run: run };

if (require.main === module) {
  try {
    run();
    console.log("[safe-mime-header-name] OK — " + helpers.getChecks() + " checks passed");
  } catch (e) {
    console.error("FAIL:", (e && e.stack) || e);
    process.exit(1);
  }
}
