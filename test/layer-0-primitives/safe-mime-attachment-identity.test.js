// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Each attachment `b.safeMime.extractAttachments` returns says which part it
 * came from, and the filename reader it uses is available to a caller walking
 * the tree itself.
 *
 * The entries carried `filename`, `contentType`, `body` and `headers` and
 * nothing identifying the part, so a consumer serving one part at a URL had
 * no stable key for it. `walk` already computes the position and hands it to
 * the visitor as a second argument; `extractAttachments` dropped it. The way
 * around it was a second `walk` zipped to this list by index, which is
 * correct only while both traversals visit leaves in the same order, a thing
 * no document promises: an ordering change would pair one part's name with
 * another part's bytes and nothing in the consumer would look wrong.
 *
 * The same consumer then had no way to read a part's filename the way this
 * module reads it, because `_filenameFromHeaders` was internal, so it wrote
 * another `Content-Disposition` and RFC 2231 reader.
 */

var helpers = require("../helpers");
var check   = helpers.check;
var b       = helpers.b;

// Two attachments under a mixed root, with a nested multipart in between so
// the positions are not simply 0 and 1.
var MESSAGE = [
  "From: a@example.com",
  "To: b@example.net",
  "Subject: two files",
  "MIME-Version: 1.0",
  'Content-Type: multipart/mixed; boundary="outer"',
  "",
  "--outer",
  'Content-Type: multipart/alternative; boundary="inner"',
  "",
  "--inner",
  "Content-Type: text/plain",
  "",
  "hello",
  "--inner",
  "Content-Type: text/html",
  "",
  "<p>hello</p>",
  "--inner--",
  "--outer",
  "Content-Type: application/pdf",
  'Content-Disposition: attachment; filename="first.pdf"',
  "",
  "PDFBYTES",
  "--outer",
  "Content-Type: text/csv",
  'Content-Disposition: attachment; filename="second.csv"',
  "",
  "a,b",
  "--outer--",
  "",
].join("\r\n");

function _attachments() {
  return b.safeMime.extractAttachments(b.safeMime.parse(Buffer.from(MESSAGE, "utf8")));
}

function testEachAttachmentCarriesItsPosition() {
  var atts = _attachments();
  check("both attachments are found", atts.length === 2,
        JSON.stringify(atts.map(function (a) { return a.filename; })));
  var missing = atts.filter(function (a) { return !Array.isArray(a.path); });
  check("every attachment carries the part path walk already computed" +
        (missing.length ? " (" + missing.length + " without one)" : ""),
        missing.length === 0);
  check("the paths are distinct, so they are usable as a key",
        atts.length === 2 && JSON.stringify(atts[0].path) !== JSON.stringify(atts[1].path),
        JSON.stringify(atts.map(function (a) { return a.path; })));
  check("the path is the position walk reports for that part",
        JSON.stringify(atts[0].path) === JSON.stringify([1]) &&
        JSON.stringify(atts[1].path) === JSON.stringify([2]),
        JSON.stringify(atts.map(function (a) { return a.path; })));
}

function testThePathAddressesTheSamePartTheBodyCameFrom() {
  // The point of the key: resolving it must reach the bytes the entry
  // carries, without a second traversal correlated by index.
  var tree = b.safeMime.parse(Buffer.from(MESSAGE, "utf8"));
  var atts = b.safeMime.extractAttachments(tree);
  var wrong = [];
  atts.forEach(function (att) {
    var node = tree;
    for (var i = 0; i < att.path.length; i += 1) {
      node = node && node.parts ? node.parts[att.path[i]] : null;
    }
    var body = node && node.leaf ? node.leaf.body : null;
    if (body === null || body.toString("utf8").trim() !== att.body.toString("utf8").trim()) {
      wrong.push(att.filename + " at " + JSON.stringify(att.path));
    }
  });
  check("following an entry's path reaches the part its bytes came from" +
        (wrong.length ? " (" + wrong.join("; ") + ")" : ""), wrong.length === 0);
}

function testTheFilenameReaderIsAvailableToACallerWalkingItself() {
  var tree = b.safeMime.parse(Buffer.from(MESSAGE, "utf8"));
  var seen = [];
  b.safeMime.walk(tree, function (part) {
    if (!part.leaf) return;
    var name = b.safeMime.filenameFromHeaders(part.headers);
    if (name !== null) seen.push(name);
  });
  check("a caller walking the tree reads filenames the way this module does",
        JSON.stringify(seen) === JSON.stringify(["first.pdf", "second.csv"]),
        JSON.stringify(seen));
  check("a part with no filename reads as null",
        b.safeMime.filenameFromHeaders(
          b.safeMime.parse(Buffer.from("Content-Type: text/plain\r\n\r\nx\r\n", "utf8")).headers) === null);
}

async function run() {
  testEachAttachmentCarriesItsPosition();
  testThePathAddressesTheSamePartTheBodyCameFrom();
  testTheFilenameReaderIsAvailableToACallerWalkingItself();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[safe-mime-attachment-identity] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
