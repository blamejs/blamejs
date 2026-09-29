// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The `Content-Disposition` a download is served with is the RFC 8187
 * grammar, and the reader accepts what other senders emit.
 *
 * `b.staticServe` built the `filename*` ext-value with `encodeURIComponent`,
 * whose escaping set is not RFC 8187 §3.2.1 `attr-char`. Four characters go
 * out raw that the grammar does not admit: `'`, `(`, `)` and `*`. The
 * apostrophe is the delimiter the ext-value is parsed on, so a file named
 * `reçu café's.pdf` was served as
 * `filename*=UTF-8''re%C3%A7u%20caf%C3%A9's.pdf`, carrying a third `'`, and
 * this framework's own `b.safeMime` reader split on it and returned
 * `reçu café`. The encoder and the decoder disagreed about the same header.
 *
 * Both sides move. The emitter escapes everything outside `attr-char`, which
 * is what the grammar requires of a sender. The reader keeps everything after
 * the second `'` rather than truncating at the third, because senders that
 * make exactly this mistake are common and the name after it is recoverable.
 *
 * The builder is exported, because a consumer serving a stranger-named file
 * had to write the header itself and the obvious way to write it is the way
 * this file wrote it, which is how the defect was found in the wild.
 */

var helpers = require("../helpers");
var check   = helpers.check;
var b       = helpers.b;

// RFC 8187 §3.2.1: attr-char = ALPHA / DIGIT / "!" / "#" / "$" / "&" / "+" /
// "-" / "." / "^" / "_" / "`" / "|" / "~"
var ATTR_CHAR = /^[A-Za-z0-9!#$&+\-.^_`|~]$/;

function _extValueOf(header) {
  var at = header.indexOf("filename*=");
  if (at === -1) return null;
  var rest = header.slice(at + "filename*=".length);
  var semi = rest.indexOf(";");
  return semi === -1 ? rest : rest.slice(0, semi);
}

function testEveryEmittedCharacterIsInTheGrammar() {
  var NAMES = [
    "reçu café's.pdf",
    "budget (final).xlsx",
    "star*name.txt",
    "plain.txt",
    "a'b(c)d*e.txt",
    "日本語.txt",
  ];
  var wrong = [];
  NAMES.forEach(function (name) {
    var header = b.staticServe.attachmentDisposition(name);
    var ext = _extValueOf(header);
    if (ext === null) { wrong.push(name + ": no filename*"); return; }
    if (ext.indexOf("UTF-8''") !== 0) { wrong.push(name + ": bad prefix " + ext); return; }
    var valueChars = ext.slice("UTF-8''".length);
    for (var i = 0; i < valueChars.length; i += 1) {
      var ch = valueChars.charAt(i);
      if (ch === "%") {
        if (!/^%[0-9A-Fa-f]{2}/.test(valueChars.slice(i))) {
          wrong.push(name + ": bad percent escape at " + i);
          break;
        }
        i += 2;
        continue;
      }
      if (!ATTR_CHAR.test(ch)) {
        wrong.push(name + ": raw " + JSON.stringify(ch) + " is not attr-char");
        break;
      }
    }
  });
  check("every character of the ext-value is attr-char or a percent escape" +
        (wrong.length ? " (" + wrong.join("; ") + ")" : ""), wrong.length === 0);

  // The four encodeURIComponent leaves raw that the grammar refuses.
  var header = b.staticServe.attachmentDisposition("a'b(c)d*e.txt");
  var ext = _extValueOf(header);
  check("the apostrophe is escaped, so the ext-value has exactly two delimiters",
        ext.split("'").length === 3, ext);
  check("the parenthesis and asterisk are escaped too",
        ext.indexOf("(") === -1 && ext.indexOf(")") === -1 &&
        ext.slice("UTF-8''".length).indexOf("*") === -1, ext);
}

function testTheHeaderRoundTripsThroughTheFrameworksOwnReader() {
  var NAMES = ["reçu café's.pdf", "budget (final).xlsx", "日本語.txt"];
  var wrong = [];
  NAMES.forEach(function (name) {
    var header = b.staticServe.attachmentDisposition(name);
    var message = "Content-Type: application/octet-stream\r\n" +
                  "Content-Disposition: " + header + "\r\n\r\nbody\r\n";
    var parsed = b.safeMime.parse(Buffer.from(message, "utf8"));
    var atts = b.safeMime.extractAttachments(parsed);
    var got = atts.length > 0 ? atts[0].filename : null;
    if (got !== name) wrong.push(JSON.stringify(name) + " read back as " + JSON.stringify(got));
  });
  check("the name the emitter sends is the name the reader returns" +
        (wrong.length ? " (" + wrong.join("; ") + ")" : ""), wrong.length === 0);
}

function testTheReaderRecoversAnUnescapedApostropheFromOtherSenders() {
  // The shape a sender using encodeURIComponent emits. Truncating at the
  // third delimiter loses the rest of a name that is still recoverable.
  var message = "Content-Type: application/octet-stream\r\n" +
                "Content-Disposition: attachment; filename*=UTF-8''re%C3%A7u%20caf%C3%A9's.pdf\r\n" +
                "\r\nbody\r\n";
  var atts = b.safeMime.extractAttachments(b.safeMime.parse(Buffer.from(message, "utf8")));
  check("a third delimiter does not truncate the name",
        atts.length > 0 && atts[0].filename === "reçu café's.pdf",
        atts.length > 0 ? JSON.stringify(atts[0].filename) : "(no attachment)");
}

function testTheAsciiFallbackAndRefusalsAreUnchanged() {
  var header = b.staticServe.attachmentDisposition("reçu café.pdf");
  check("RFC 6266 section 4.3 pairing: a plain filename travels with filename*",
        /filename="[^"]*"/.test(header) && header.indexOf("filename*=") !== -1, header);
  check("the plain filename carries no non-ASCII and no quote",
        /filename="[\x20-\x21\x23-\x5b\x5d-\x7e]*"/.test(header), header);
  var injected = b.staticServe.attachmentDisposition("a\r\nb: c.txt");
  check("a name carrying CR or LF cannot split the header",
        injected.indexOf("\r") === -1 && injected.indexOf("\n") === -1, injected);
}

async function run() {
  testEveryEmittedCharacterIsInTheGrammar();
  testTheHeaderRoundTripsThroughTheFrameworksOwnReader();
  testTheReaderRecoversAnUnescapedApostropheFromOtherSenders();
  testTheAsciiFallbackAndRefusalsAreUnchanged();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[static-attachment-disposition] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
