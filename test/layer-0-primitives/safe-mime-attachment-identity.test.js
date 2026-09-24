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

function testAPartAnnouncedOnlyByContentTypeIsStillAnAttachment() {
  // Content-Disposition is optional, and a PDF announced only as
  // `Content-Type: application/pdf; name=invoice.pdf` is an attachment to
  // every reader. Requiring the disposition made this reader disagree with
  // b.mail.server.jmap.emailBodyProperties, which follows RFC 8621 4.1.4 and
  // counts any leaf that is not displayed body text, so a message could be
  // stored as carrying no file while JMAP offered one to download.
  var message = Buffer.from([
    "From: a@example.com", "To: b@example.net", "Subject: s", "MIME-Version: 1.0",
    'Content-Type: multipart/mixed; boundary="x"', "",
    "--x", "Content-Type: text/plain", "", "hi",
    "--x", "Content-Type: application/pdf; name=invoice.pdf", "", "PDFBYTES",
    "--x--", "",
  ].join("\r\n"), "utf8");
  var tree = b.safeMime.parse(message);

  var extracted = b.safeMime.extractAttachments(tree);
  check("the part is counted as an attachment", extracted.length === 1,
        JSON.stringify(extracted.map(function (a) { return a.filename; })));
  check("and it carries the name from its Content-Type",
        extracted[0].filename === "invoice.pdf", JSON.stringify(extracted[0].filename));

  var jmap = b.mail.server.jmap.emailBodyProperties(tree, { blobIdPrefix: "obj1" });
  check("the JMAP view counts the same parts",
        jmap.attachments.length === extracted.length,
        JSON.stringify([jmap.attachments.length, extracted.length]));

  var plain = b.safeMime.parse(
    Buffer.from("From: a@example.com\r\nSubject: s\r\n\r\njust text\r\n", "utf8"));
  check("and an ordinary text message still carries none",
        b.safeMime.extractAttachments(plain).length === 0);
}

function testAnInlineFileIsCountedTheWayTheJmapViewCountsIt() {
  // `Content-Disposition: inline; filename="a.pdf"` is how a sender asks a
  // reader to display a file in place. RFC 8621 4.1.4 counts a named inline
  // part among the attachments, and b.mail.server.jmap.emailBodyProperties
  // does. This reader skipped every inline part, so b.mail.store.append
  // recorded hasAttachment false for a message whose file Email/get offers
  // for download, and a mailbox listing hid it.
  var message = Buffer.from([
    "From: a@example.com", "To: b@example.net", "Subject: s", "MIME-Version: 1.0",
    'Content-Type: multipart/mixed; boundary="x"', "",
    "--x", "Content-Type: text/plain", "", "hi",
    "--x", "Content-Type: application/pdf",
    'Content-Disposition: inline; filename="a.pdf"', "", "PDFBYTES",
    "--x--", "",
  ].join("\r\n"), "utf8");
  var tree = b.safeMime.parse(message);

  var extracted = b.safeMime.extractAttachments(tree);
  check("a named inline file is counted", extracted.length === 1,
        JSON.stringify(extracted.map(function (a) { return a.filename; })));
  check("and it carries the name from its disposition",
        extracted.length === 1 && extracted[0].filename === "a.pdf",
        JSON.stringify(extracted.map(function (a) { return a.filename; })));

  var jmap = b.mail.server.jmap.emailBodyProperties(tree, { blobIdPrefix: "obj1" });
  check("the JMAP view counts the same parts",
        jmap.attachments.length === extracted.length,
        JSON.stringify([jmap.attachments.length, extracted.length]));

  // An inline part with no name is displayed body text, not a file, and
  // neither reader counts it.
  var unnamed = b.safeMime.parse(Buffer.from([
    "From: a@example.com", "Subject: s", "MIME-Version: 1.0",
    'Content-Type: multipart/mixed; boundary="y"', "",
    "--y", "Content-Type: text/plain", "Content-Disposition: inline", "", "hi",
    "--y--", "",
  ].join("\r\n"), "utf8"));
  var unnamedJmap = b.mail.server.jmap.emailBodyProperties(unnamed, { blobIdPrefix: "obj2" });
  check("an unnamed inline text part is body on both readers",
        b.safeMime.extractAttachments(unnamed).length === 0 &&
        unnamedJmap.attachments.length === 0,
        JSON.stringify([b.safeMime.extractAttachments(unnamed).length,
                        unnamedJmap.attachments.length]));
}

function testAFilenameThatLooksLikeAParameterIsNotReadAsOne() {
  // Only text outside a quoted value is parameter syntax. A plain filename
  // may itself contain "filename*=", and reading that as the extended
  // parameter returns a name the sender never wrote, so the round trip
  // through the writer and this reader has to come back unchanged.
  var awkward = "notes filename*=draft.txt";
  var header = b.staticServe.attachmentDisposition(awkward);
  var headers = { get: function (n) {
    return String(n).toLowerCase() === "content-disposition" ? header : null;
  } };
  check("a filename containing a parameter spelling reads back unchanged",
        b.safeMime.filenameFromHeaders(headers) === awkward,
        JSON.stringify([awkward, b.safeMime.filenameFromHeaders(headers)]));
}

function testWhitespaceAroundTheParameterEqualsIsAllowed() {
  // RFC 2045 section 5.1 writes a parameter as `attribute "=" value`, and the
  // structured-field grammar it inherits from RFC 822 permits linear
  // whitespace around the separator. A reader that insists on an immediate
  // `=` does not find the parameter at all, so a named part reads as body
  // text and drops out of the attachment list and out of what JMAP reports:
  // the sender chooses the spacing.
  function _named(cd) {
    return { get: function (n) {
      return String(n).toLowerCase() === "content-disposition" ? cd : null;
    } };
  }
  [["a space before the equals",       "attachment; filename =\"notes.txt\""],
   ["a space either side",             "attachment; filename = \"notes.txt\""],
   ["a tab before the equals",         "attachment; filename\t=\"notes.txt\""],
   ["no space at all",                 "attachment; filename=\"notes.txt\""],
   ["an unquoted value with spacing",  "attachment; filename = notes.txt"]].forEach(function (row) {
    check("filename is read with " + row[0],
          b.safeMime.filenameFromHeaders(_named(row[1])) === "notes.txt",
          JSON.stringify([row[1], b.safeMime.filenameFromHeaders(_named(row[1]))]));
  });

  // The extended form carries its `*` inside the attribute, so the whitespace
  // it admits is the same whitespace, on the other side of the star.
  check("the RFC 2231 extended form is read with spacing too",
        b.safeMime.filenameFromHeaders(
          _named("attachment; filename* = UTF-8''notes.txt")) === "notes.txt",
        JSON.stringify(b.safeMime.filenameFromHeaders(
          _named("attachment; filename* = UTF-8''notes.txt"))));

  // And the part it names is a file, not the body: this is the reading that
  // decides whether the attachment list mentions it at all.
  var message = Buffer.from(
    "MIME-Version: 1.0\r\n" +
    "Content-Type: multipart/mixed; boundary=b1\r\n" +
    "\r\n" +
    "--b1\r\n" +
    "Content-Type: text/plain\r\n" +
    "\r\n" +
    "the body\r\n" +
    "--b1\r\n" +
    "Content-Type: text/plain\r\n" +
    "Content-Disposition: attachment; filename = \"notes.txt\"\r\n" +
    "\r\n" +
    "attached text\r\n" +
    "--b1--\r\n", "utf8");
  var names = b.safeMime.extractAttachments(b.safeMime.parse(message))
    .map(function (a) { return a.filename; });
  check("a part named with spacing is offered as an attachment",
        names.indexOf("notes.txt") !== -1, JSON.stringify(names));
}

function testASupersededAlternativesFilesAreStillOffered() {
  // The parts of a multipart/alternative are one body written several ways,
  // and only one of them is displayed. Its FILES are a separate question:
  // RFC 8621 section 4.1.4, the classification this module implements, puts a
  // payload leaf of a superseded branch in `attachments`, and its own worked
  // example does exactly that with an image inside a multipart/related inside
  // an alternative. What the two readers have to agree on is the answer, not
  // which of them drops more: a leaf `bodyStructure` hands a blobId for is
  // named by some list, whatever branch it sat in.
  var raw = [
    "From: a@example.com", "To: b@example.net", "Subject: s", "MIME-Version: 1.0",
    'Content-Type: multipart/alternative; boundary="alt"', "",
    "--alt", 'Content-Type: multipart/related; boundary="rel"', "",
    "--rel", "Content-Type: text/html; charset=utf-8", "",
    '<p>with image <img src="cid:logo@example.com"></p>',
    "--rel", "Content-Type: image/png", "Content-ID: <logo@example.com>",
    'Content-Disposition: inline; filename="logo.png"', "", "PNGBYTES",
    "--rel--",
    "--alt", "Content-Type: text/html; charset=utf-8", "", "<p>plain html</p>",
    "--alt--", "",
  ].join("\r\n");
  var tree = b.safeMime.parse(Buffer.from(raw, "utf8"));
  var extracted = b.safeMime.extractAttachments(tree);
  var jmap = b.mail.server.jmap.emailBodyProperties(tree, { blobIdPrefix: "obj1" });
  check("the superseded representation's file is still offered",
        extracted.length === 1 && extracted[0].filename === "logo.png",
        JSON.stringify(extracted.map(function (a) { return a.filename; })));
  check("and the two readers agree",
        extracted.length === jmap.attachments.length,
        JSON.stringify([extracted.length, jmap.attachments.length]));

  // With the same two representations the other way round, the one carrying
  // the file is the preferred one and both readers count it.
  var chosen = b.safeMime.parse(Buffer.from([
    "From: a@example.com", "Subject: s", "MIME-Version: 1.0",
    'Content-Type: multipart/alternative; boundary="alt"', "",
    "--alt", "Content-Type: text/html; charset=utf-8", "", "<p>plain html</p>",
    "--alt", 'Content-Type: multipart/related; boundary="rel"', "",
    "--rel", "Content-Type: text/html; charset=utf-8", "", "<p>with image</p>",
    "--rel", "Content-Type: image/png",
    'Content-Disposition: inline; filename="logo.png"', "", "PNGBYTES",
    "--rel--",
    "--alt--", "",
  ].join("\r\n"), "utf8"));
  var chosenFiles = b.safeMime.extractAttachments(chosen);
  var chosenJmap = b.mail.server.jmap.emailBodyProperties(chosen, { blobIdPrefix: "obj2" });
  check("the chosen representation's file is counted",
        chosenFiles.length === 1 && chosenFiles[0].filename === "logo.png",
        JSON.stringify(chosenFiles.map(function (a) { return a.filename; })));
  check("and the two readers agree there too",
        chosenFiles.length === chosenJmap.attachments.length,
        JSON.stringify([chosenFiles.length, chosenJmap.attachments.length]));

  // A file beside the alternative, rather than inside one, belongs to the
  // message however the alternatives are chosen.
  var beside = b.safeMime.parse(Buffer.from([
    "From: a@example.com", "Subject: s", "MIME-Version: 1.0",
    'Content-Type: multipart/mixed; boundary="mix"', "",
    "--mix", 'Content-Type: multipart/alternative; boundary="alt"', "",
    "--alt", "Content-Type: text/plain", "", "hi",
    "--alt", "Content-Type: text/html", "", "<p>hi</p>",
    "--alt--",
    "--mix", "Content-Type: application/pdf",
    'Content-Disposition: attachment; filename="report.pdf"', "", "PDFBYTES",
    "--mix--", "",
  ].join("\r\n"), "utf8"));
  var besideFiles = b.safeMime.extractAttachments(beside);
  var besideJmap = b.mail.server.jmap.emailBodyProperties(beside, { blobIdPrefix: "obj3" });
  check("a file beside the alternatives is still counted",
        besideFiles.length === 1 && besideFiles[0].filename === "report.pdf",
        JSON.stringify(besideFiles.map(function (a) { return a.filename; })));
  check("and both readers agree about it",
        besideFiles.length === besideJmap.attachments.length,
        JSON.stringify([besideFiles.length, besideJmap.attachments.length]));
}

function testThePreferredAlternativeIsTheLastOne() {
  // RFC 2046 5.1.4: the parts of a multipart/alternative are ordered from
  // simplest to richest, and a reader displays the LAST one it can. Choosing
  // the first displayed the representation the sender meant to supersede,
  // and it disagreed with b.safeMime.extractText, which has always read the
  // alternative backwards. One message then had two answers to "what is the
  // body": b.mail.store.append stores extractText's and reported this
  // selection's files, so a stored body and its attachment facts could
  // describe different representations.
  var raw = [
    "From: a@example.com", "To: b@example.net", "Subject: s", "MIME-Version: 1.0",
    'Content-Type: multipart/alternative; boundary="alt"', "",
    "--alt", "Content-Type: text/html; charset=utf-8", "", "<p>simple</p>",
    "--alt", "Content-Type: text/html; charset=utf-8", "", "<p>rich</p>",
    "--alt--", "",
  ].join("\r\n");
  var tree = b.safeMime.parse(Buffer.from(raw, "utf8"));
  var selection = b.safeMime.selectBodyParts(tree);
  check("the richest HTML representation is the displayed one",
        selection.html.length === 1 &&
        selection.html[0].part.leaf.body.toString("utf8").indexOf("rich") !== -1,
        JSON.stringify(selection.html.map(function (e) { return e.path; })));

  var extracted = b.safeMime.extractText(tree, { prefer: "html" });
  check("and extractText names the same part",
        extracted !== null &&
        extracted.body === selection.html[0].part.leaf.body.toString("utf8"),
        JSON.stringify([extracted && extracted.body,
                        selection.html[0].part.leaf.body.toString("utf8")]));

  // The same for plain text, and the two spellings of one body still both
  // survive when they are of different types.
  var mixed = b.safeMime.parse(Buffer.from([
    "From: a@example.com", "Subject: s", "MIME-Version: 1.0",
    'Content-Type: multipart/alternative; boundary="alt"', "",
    "--alt", "Content-Type: text/plain", "", "simple text",
    "--alt", "Content-Type: text/plain", "", "rich text",
    "--alt", "Content-Type: text/html", "", "<p>html</p>",
    "--alt--", "",
  ].join("\r\n"), "utf8"));
  var mixedSelection = b.safeMime.selectBodyParts(mixed);
  check("the last plain-text representation is the displayed text",
        mixedSelection.text.length === 1 &&
        mixedSelection.text[0].part.leaf.body.toString("utf8").indexOf("rich") !== -1,
        JSON.stringify(mixedSelection.text.map(function (e) { return e.path; })));
  check("and the HTML representation is displayed beside it",
        mixedSelection.html.length === 1,
        JSON.stringify(mixedSelection.html.map(function (e) { return e.path; })));
  var plain = b.safeMime.extractText(mixed, { prefer: "plain" });
  check("extractText agrees about the text too",
        plain !== null && plain.body === mixedSelection.text[0].part.leaf.body.toString("utf8"),
        JSON.stringify([plain && plain.body]));

  // A representation wrapped in a multipart is one choice, and being last
  // makes it the preferred one: its inline file comes with it.
  var wrapped = b.safeMime.parse(Buffer.from([
    "From: a@example.com", "Subject: s", "MIME-Version: 1.0",
    'Content-Type: multipart/alternative; boundary="alt"', "",
    "--alt", "Content-Type: text/plain", "", "fallback",
    "--alt", 'Content-Type: multipart/related; boundary="rel"', "",
    "--rel", "Content-Type: text/html; charset=utf-8", "", "<p>with image</p>",
    "--rel", "Content-Type: image/png",
    'Content-Disposition: inline; filename="logo.png"', "", "PNGBYTES",
    "--rel--",
    "--alt--", "",
  ].join("\r\n"), "utf8"));
  var wrappedSelection = b.safeMime.selectBodyParts(wrapped);
  check("the wrapped representation is chosen when it is last",
        wrappedSelection.html.length === 1 &&
        wrappedSelection.files.length === 1 &&
        wrappedSelection.files[0].filename === "logo.png",
        JSON.stringify([wrappedSelection.html.length,
                        wrappedSelection.files.map(function (e) { return e.filename; })]));
  check("and the plain fallback is still the displayed text",
        wrappedSelection.text.length === 1 &&
        wrappedSelection.text[0].part.leaf.body.toString("utf8").indexOf("fallback") !== -1,
        JSON.stringify(wrappedSelection.text.map(function (e) { return e.path; })));
}

function testAFileWithNoDispositionSurvivesLosingTheContestToo() {
  // The earlier fix kept a losing branch's files only where the sender had
  // written `Content-Disposition: attachment`. Disposition is optional, and
  // the rule this module states is that a leaf is a file when it is not
  // displayed body text, which is why a bare `application/pdf` counts as an
  // attachment everywhere else in this file. The carve-out is the wrong way
  // round: what belongs to a losing REPRESENTATION is its inline parts, and a
  // payload leaf carrying no disposition is not one of them. RFC 8621 4.1.4
  // lands in the same place, since isInline wants a text or inline media
  // type and an application/* leaf falls through to attachments.
  // The payload type is the sender's to choose, so the guarantee is checked
  // across the types a sender actually reaches for, not one of them. Keying
  // the carve-out on the media type instead of the disposition moved the
  // sender's lever rather than removing it: every image, audio and video leaf
  // then vanished from every list while bodyStructure kept offering its
  // blobId, and only application/* shapes were ever exercised here.
  var PAYLOADS = [
    { type: "application/x-msdownload", name: "setup.exe", body: "MZBYTES" },
    { type: "application/pdf",          name: "report.pdf", body: "PDFBYTES" },
    { type: "image/svg+xml",            name: "logo.svg",  body: "<svg/>" },
    { type: "image/png",                name: "photo.png", body: "PNGBYTES" },
    { type: "video/mp4",                name: "clip.mp4",  body: "MP4BYTES" },
    { type: "audio/mpeg",               name: "note.mp3",  body: "MP3BYTES" },
    { type: "text/calendar",            name: "invite.ics", body: "BEGIN:VCALENDAR" },
  ];

  PAYLOADS.forEach(function (payload, n) {
    var raw = [
      "From: a@example.com", "To: b@example.net", "Subject: s", "MIME-Version: 1.0",
      'Content-Type: multipart/alternative; boundary="alt"', "",
      "--alt", 'Content-Type: multipart/related; boundary="rel"', "",
      "--rel", "Content-Type: text/html; charset=utf-8", "", "<p>superseded</p>",
      "--rel", "Content-Type: " + payload.type + "; name=" + payload.name, "", payload.body,
      "--rel--",
      "--alt", "Content-Type: text/html; charset=utf-8", "", "<p>preferred</p>",
      "--alt--", "",
    ].join("\r\n");
    var tree = b.safeMime.parse(Buffer.from(raw, "utf8"));

    var files = b.safeMime.extractAttachments(tree);
    check("a " + payload.type + " leaf with no disposition survives its branch losing",
          files.length === 1 && files[0].filename === payload.name,
          JSON.stringify(files.map(function (f) { return f.filename; })));

    var props = b.mail.server.jmap.emailBodyProperties(tree, { blobIdPrefix: "obj2-" + n });
    check("and the JMAP view counts the " + payload.type +
          " rather than only advertising its blobId",
          props.hasAttachment === true && props.attachments.length === 1,
          JSON.stringify({ has: props.hasAttachment, n: props.attachments.length }));

    // The two halves of one response have to agree about payload. A superseded
    // text representation is legitimately in bodyStructure and in no list,
    // which is what an alternative IS, but any other leaf that no list names
    // is a downloadable blob no reader accounts for. Only text/plain and
    // text/html are body representations, so a text/calendar leaf no list
    // names is an orphan like any other.
    var offered = [];
    (function walkNode(node) {
      if (!node) return;
      if (!node.subParts || node.subParts.length === 0) { offered.push(node); return; }
      node.subParts.forEach(walkNode);
    })(props.bodyStructure);
    var accountedFor = Object.create(null);
    props.attachments.concat(props.textBody || [], props.htmlBody || [])
      .forEach(function (p) { accountedFor[p.partId] = true; });
    var orphans = offered.filter(function (node) {
      var type = String(node.type || "").toLowerCase();
      return node.blobId && !accountedFor[node.partId] &&
             type !== "text/plain" && type !== "text/html";
    });
    check("no " + payload.type + " leaf is downloadable without appearing in any list",
          orphans.length === 0,
          JSON.stringify(orphans.map(function (node) { return node.type + "@" + node.partId; })));
  });

  // The sender picks the disposition AND the part order, so keying the
  // carve-out on the word `inline` let them mark a payload inline, put it in
  // the branch that loses, and have it vanish from every list while
  // bodyStructure went on offering its blobId. What belongs to a
  // representation is what a reader RENDERS in place, which RFC 8621 4.1.4
  // reads off the media type, not off the disposition alone.
  var inlinePayload = b.safeMime.parse(Buffer.from([
    "From: a@example.com", "To: b@example.net", "Subject: s", "MIME-Version: 1.0",
    'Content-Type: multipart/alternative; boundary="alt"', "",
    "--alt", 'Content-Type: multipart/related; boundary="rel"', "",
    "--rel", "Content-Type: text/html; charset=utf-8", "", "<p>superseded</p>",
    "--rel", "Content-Type: application/pdf",
    'Content-Disposition: inline; filename="invoice.pdf"', "", "PDFBYTES",
    "--rel--",
    "--alt", "Content-Type: text/html; charset=utf-8", "", "<p>preferred</p>",
    "--alt--", "",
  ].join("\r\n"), "utf8"));
  check("a payload marked inline in the losing branch is still offered",
        b.safeMime.extractAttachments(inlinePayload).length === 1,
        JSON.stringify(b.safeMime.extractAttachments(inlinePayload)
          .map(function (f) { return f.filename; })));

  // Even a part the superseded body really does render in place, named by
  // `cid:` and carrying the matching Content-ID, is offered: a reader that
  // never shows that representation never renders it, and the bytes are
  // reachable either way.
  var withInline = b.safeMime.parse(Buffer.from([
    "From: a@example.com", "To: b@example.net", "Subject: s", "MIME-Version: 1.0",
    'Content-Type: multipart/alternative; boundary="alt"', "",
    "--alt", 'Content-Type: multipart/related; boundary="rel"', "",
    "--rel", "Content-Type: text/html; charset=utf-8", "",
    '<p>superseded <img src="cid:bullet@example.com"></p>',
    "--rel", "Content-Type: image/png", "Content-ID: <bullet@example.com>",
    'Content-Disposition: inline; filename="bullet.png"', "", "PNGBYTES",
    "--rel--",
    "--alt", "Content-Type: text/html; charset=utf-8", "", "<p>preferred</p>",
    "--alt--", "",
  ].join("\r\n"), "utf8"));
  check("a cid-referenced inline part of the losing representation is offered",
        b.safeMime.extractAttachments(withInline).length === 1,
        JSON.stringify(b.safeMime.extractAttachments(withInline)
          .map(function (f) { return f.filename; })));

  // Every input this rule could read is one the sender writes: the
  // disposition, the media type, the Content-ID and the order of the
  // branches. Each time the rule took one more of them as proof that a part
  // belongs to a representation, the sender supplied that one too and the
  // payload went back to being downloadable while no list named it. RFC 8621
  // section 4.1.4, the classification this module says it implements, never
  // drops a leaf: its parseStructure puts a payload part of a superseded
  // branch in `attachments`. So nothing is dropped, and the invariant is the
  // one this test already states for every other shape.
  var INLINE_SHAPES = [
    { label: "no disposition", extra: [] },
    { label: "inline", extra: ['Content-Disposition: inline; filename="payload.png"'] },
    { label: "inline with a Content-ID", extra: [
      "Content-ID: <nobody-names-me@example.com>",
      'Content-Disposition: inline; filename="payload.png"',
    ] },
    { label: "inline with an empty Content-ID", extra: [
      "Content-ID: <>",
      'Content-Disposition: inline; filename="payload.png"',
    ] },
  ];
  INLINE_SHAPES.forEach(function (shape, n) {
    var tree = b.safeMime.parse(Buffer.from([
      "From: a@example.com", "To: b@example.net", "Subject: s", "MIME-Version: 1.0",
      'Content-Type: multipart/alternative; boundary="alt"', "",
      "--alt", 'Content-Type: multipart/related; boundary="rel"', "",
      "--rel", "Content-Type: text/html; charset=utf-8", "",
      "<p>superseded, references nothing</p>",
      "--rel", "Content-Type: image/png",
    ].concat(shape.extra).concat([
      "", "MZTHISISNOTAPNG",
      "--rel--",
      "--alt", "Content-Type: text/html; charset=utf-8", "", "<p>preferred</p>",
      "--alt--", "",
    ]).join("\r\n"), "utf8"));
    var props = b.mail.server.jmap.emailBodyProperties(tree, { blobIdPrefix: "inl" + n });
    var leaves = [];
    (function walk(node) {
      if (!node) return;
      if (!node.subParts || node.subParts.length === 0) { leaves.push(node); return; }
      node.subParts.forEach(walk);
    })(props.bodyStructure);
    var accounted = Object.create(null);
    props.attachments.concat(props.textBody || [], props.htmlBody || [])
      .forEach(function (x) { accounted[x.partId] = true; });
    var orphans = leaves.filter(function (node) {
      var type = String(node.type || "").toLowerCase();
      return node.blobId && !accounted[node.partId] &&
             type !== "text/plain" && type !== "text/html";
    });
    check("a losing branch's payload is named by some list (" + shape.label + ")",
          orphans.length === 0,
          JSON.stringify(orphans.map(function (node) { return node.type + "@" + node.partId; })));
  });
  var unreferenced = b.safeMime.parse(Buffer.from([
    "From: a@example.com", "To: b@example.net", "Subject: s", "MIME-Version: 1.0",
    'Content-Type: multipart/alternative; boundary="alt"', "",
    "--alt", 'Content-Type: multipart/related; boundary="rel"', "",
    "--rel", "Content-Type: text/html; charset=utf-8", "", "<p>superseded</p>",
    "--rel", "Content-Type: image/png",
    'Content-Disposition: inline; filename="payload.png"', "", "NOTREALLYAPNG",
    "--rel--",
    "--alt", "Content-Type: text/html; charset=utf-8", "", "<p>preferred</p>",
    "--alt--", "",
  ].join("\r\n"), "utf8"));
  var unreferencedFiles = b.safeMime.extractAttachments(unreferenced);
  check("an inline part nothing references survives the branch losing",
        unreferencedFiles.length === 1 &&
          unreferencedFiles[0].filename === "payload.png",
        JSON.stringify(unreferencedFiles.map(function (f) { return f.filename; })));

  var unreferencedProps = b.mail.server.jmap.emailBodyProperties(
    unreferenced, { blobIdPrefix: "obj3" });
  check("and the JMAP view counts it rather than only advertising its blobId",
        unreferencedProps.hasAttachment === true &&
          unreferencedProps.attachments.length === 1,
        JSON.stringify({ has: unreferencedProps.hasAttachment,
                         n: unreferencedProps.attachments.length }));
}

function testExtractTextAndTheSelectionAgreeAboutWhatTheBodyIs() {
  // extractText and selectBodyParts are two readers of one message, and a
  // caller sees both: b.mailStore.appendMessage seals body_text from the
  // first and derives has_attachment from the second. extractText walked
  // every leaf of the wanted type, so a message carrying an ATTACHED .txt
  // and an inline HTML body stored the attachment's contents as the body
  // while reporting that same part as a file.
  var raw = [
    "From: a@example.com", "To: b@example.net", "Subject: s", "MIME-Version: 1.0",
    'Content-Type: multipart/mixed; boundary="m"', "",
    "--m", "Content-Type: text/plain",
    'Content-Disposition: attachment; filename="notes.txt"', "", "ATTACHED PLAIN",
    "--m", "Content-Type: text/html", "", "<p>REAL BODY</p>",
    "--m--", "",
  ].join("\r\n");
  var tree = b.safeMime.parse(Buffer.from(raw, "utf8"));
  var selection = b.safeMime.selectBodyParts(tree);

  check("the selection calls the attached part a file and not the body",
        selection.text.length === 0 && selection.html.length === 1 &&
        selection.files.length === 1,
        JSON.stringify({ text: selection.text.length, html: selection.html.length,
                         files: selection.files.length }));

  var plain = b.safeMime.extractText(tree, { prefer: "plain" });
  check("extractText does not answer with the attachment as the body",
        plain === null || String(plain.body).indexOf("ATTACHED PLAIN") === -1,
        JSON.stringify(plain && plain.body));
  check("and answers with the body the selection displays",
        plain !== null && plain.contentType === "text/html",
        JSON.stringify(plain && plain.contentType));

  // A message whose only text IS the attachment still answers with it: there
  // is nothing else to call the body, and refusing would lose the bytes for
  // the single-part deployments that spell one file that way.
  var onlyAttached = b.safeMime.parse(Buffer.from([
    "From: a@example.com", "To: b@example.net", "Subject: s", "MIME-Version: 1.0",
    'Content-Type: multipart/mixed; boundary="m"', "",
    "--m", "Content-Type: text/plain",
    'Content-Disposition: attachment; filename="notes.txt"', "", "ATTACHED ONLY",
    "--m--", "",
  ].join("\r\n"), "utf8"));
  var only = b.safeMime.extractText(onlyAttached, { prefer: "plain" });
  check("a message whose only text is attached still reads back",
        only !== null && String(only.body).indexOf("ATTACHED ONLY") !== -1,
        JSON.stringify(only && only.body));
}

function testAnAttachedFileSurvivesLosingTheRepresentationContest() {
  // Which alternative a reader displays is a contest between spellings of
  // the body. A part the sender marked `Content-Disposition: attachment` is
  // not a spelling of the body, so it belongs to the message whichever
  // branch it sits in. Dropping the losing branch whole took its attachments
  // with it: the bytes reached no content guard, the stored attachment facts
  // said none, and the JMAP view said none while its own bodyStructure went
  // on advertising the part's blobId. The sender chooses the part order, so
  // the sender chooses which branch loses.
  var raw = [
    "From: a@example.com", "To: b@example.net", "Subject: s", "MIME-Version: 1.0",
    'Content-Type: multipart/alternative; boundary="alt"', "",
    "--alt", 'Content-Type: multipart/related; boundary="rel"', "",
    "--rel", "Content-Type: text/html; charset=utf-8", "", "<p>superseded</p>",
    "--rel", "Content-Type: application/octet-stream",
    'Content-Disposition: attachment; filename="evil.exe"', "", "MZBYTES",
    "--rel--",
    "--alt", "Content-Type: text/html; charset=utf-8", "", "<p>preferred</p>",
    "--alt--", "",
  ].join("\r\n");
  var tree = b.safeMime.parse(Buffer.from(raw, "utf8"));
  var files = b.safeMime.extractAttachments(tree);
  check("the attached file survives its branch losing",
        files.length === 1 && files[0].filename === "evil.exe",
        JSON.stringify(files.map(function (f) { return f.filename; })));

  var props = b.mail.server.jmap.emailBodyProperties(tree, { blobIdPrefix: "obj1" });
  check("and the JMAP view counts it too",
        props.attachments.length === 1 && props.hasAttachment === true,
        JSON.stringify(props.attachments.map(function (p) { return p.name; })));
  check("while only the preferred representation is displayed",
        props.htmlBody.length === 1 &&
        props.htmlBody[0].partId === props.bodyStructure.subParts[1].partId,
        JSON.stringify(props.htmlBody.map(function (p) { return p.partId; })));

  // Not specific to HTML, or to multipart/related.
  var plain = b.safeMime.parse(Buffer.from([
    "From: a@example.com", "Subject: s", "MIME-Version: 1.0",
    'Content-Type: multipart/alternative; boundary="alt"', "",
    "--alt", 'Content-Type: multipart/mixed; boundary="mix"', "",
    "--mix", "Content-Type: text/plain", "", "superseded",
    "--mix", "Content-Type: application/pdf",
    'Content-Disposition: attachment; filename="invoice.pdf"', "", "PDFBYTES",
    "--mix--",
    "--alt", "Content-Type: text/plain", "", "preferred",
    "--alt--", "",
  ].join("\r\n"), "utf8"));
  check("a plain-text branch keeps its attachment the same way",
        b.safeMime.extractAttachments(plain).length === 1,
        JSON.stringify(b.safeMime.extractAttachments(plain)
          .map(function (f) { return f.filename; })));

  // A cid: image of a superseded body is offered too. Which representation a
  // reader displays decides what the BODY is; it does not decide which leaves
  // exist, and a leaf reachable through `bodyStructure` that no list names is
  // a blob nobody accounts for whatever the sender called it.
  var inlineOnly = b.safeMime.parse(Buffer.from([
    "From: a@example.com", "Subject: s", "MIME-Version: 1.0",
    'Content-Type: multipart/alternative; boundary="alt"', "",
    "--alt", 'Content-Type: multipart/related; boundary="rel"', "",
    "--rel", "Content-Type: text/html", "",
    '<p>superseded <img src="cid:logo@example.com"></p>',
    "--rel", "Content-Type: image/png", "Content-ID: <logo@example.com>",
    'Content-Disposition: inline; filename="logo.png"', "", "PNGBYTES",
    "--rel--",
    "--alt", "Content-Type: text/html", "", "<p>preferred</p>",
    "--alt--", "",
  ].join("\r\n"), "utf8"));
  check("and an inline part of the losing representation is counted too",
        b.safeMime.extractAttachments(inlineOnly).length === 1,
        JSON.stringify(b.safeMime.extractAttachments(inlineOnly)
          .map(function (f) { return f.filename; })));
}

function testEveryAttachedLeafTheStructureShowsIsOffered() {
  // The durable form of the rule above, which does not depend on the shape
  // that happened to break: whatever the tree, a leaf the structure hands a
  // client with `disposition: "attachment"` is a leaf the attachment list
  // names. The two readers walked the tree differently, so one advertised a
  // blobId the other said did not exist.
  var shapes = [
    ['Content-Type: multipart/alternative; boundary="a"', "",
     "--a", 'Content-Type: multipart/related; boundary="r"', "",
     "--r", "Content-Type: text/html", "", "<p>one</p>",
     "--r", "Content-Type: application/pdf",
     'Content-Disposition: attachment; filename="a.pdf"', "", "P",
     "--r--",
     "--a", "Content-Type: text/html", "", "<p>two</p>", "--a--"],
    ['Content-Type: multipart/mixed; boundary="m"', "",
     "--m", "Content-Type: text/plain", "", "hi",
     "--m", "Content-Type: application/pdf",
     'Content-Disposition: attachment; filename="b.pdf"', "", "P", "--m--"],
    ['Content-Type: multipart/alternative; boundary="a"', "",
     "--a", "Content-Type: text/plain", "", "one",
     "--a", "Content-Type: text/plain", "", "two", "--a--"],
  ];
  var mismatches = [];
  shapes.forEach(function (body, i) {
    var tree = b.safeMime.parse(Buffer.from(
      ["From: a@example.com", "Subject: s", "MIME-Version: 1.0"]
        .concat(body).concat([""]).join("\r\n"), "utf8"));
    var props = b.mail.server.jmap.emailBodyProperties(tree, { blobIdPrefix: "obj" + i });
    var offered = {};
    props.attachments.forEach(function (p) { offered[p.partId] = true; });
    (function walk(node) {
      if (node.subParts && node.subParts.length > 0) {
        node.subParts.forEach(walk);
        return;
      }
      if (node.disposition === "attachment" && !offered[node.partId]) {
        mismatches.push("shape " + i + " part " + node.partId);
      }
    })(props.bodyStructure);
  });
  check("every attached leaf the structure shows is one the attachment list names" +
        (mismatches.length ? " (" + mismatches.join("; ") + ")" : ""),
        mismatches.length === 0);
}

function testPreferOutranksTheOppositeTypeEvenOutsideTheDisplayLists() {
  // `prefer` names the type the caller wants, and a part of that type sitting
  // outside the displayed representation is still a part of that type.
  // Falling straight from "no displayed HTML" to "the displayed plain text"
  // answered with the type the caller did not ask for while a part of the
  // type they did ask for sat in the same message.
  var raw = ["From: a@example.com", "Subject: s", "MIME-Version: 1.0",
    'Content-Type: multipart/mixed; boundary="m"', "",
    "--m", "Content-Type: text/plain", "", "plain body",
    "--m", 'Content-Type: multipart/related; boundary="r"', "",
    "--r", "Content-Type: text/html", "", "<p>html body</p>",
    "--r--",
    "--m--", ""].join("\r\n");
  var tree = b.safeMime.parse(Buffer.from(raw, "utf8"));
  var html = b.safeMime.extractText(tree, { prefer: "html" });
  check("the preferred type wins over the opposite one",
        html && html.contentType === "text/html",
        JSON.stringify(html && html.contentType));

  // A part of the wanted type that the selection classified as a FILE is not
  // a body of that type. This reader guarded only on `attachment` while the
  // selection also calls `inline` with a name a file, so the two disagreed
  // and the attachment's bytes were sealed into the store's body column while
  // the attachment list named the same leaf.
  var attachedHtml = b.safeMime.parse(Buffer.from(
    ["From: a@example.com", "Subject: s", "MIME-Version: 1.0",
     'Content-Type: multipart/mixed; boundary="m"', "",
     "--m", "Content-Type: text/plain", "", "REAL BODY",
     "--m", "Content-Type: text/html",
     'Content-Disposition: inline; filename="page.html"', "", "<p>ATTACHED</p>",
     "--m--", ""].join("\r\n"), "utf8"));
  var asHtml = b.safeMime.extractText(attachedHtml, { prefer: "html" });
  check("an attached part of the wanted type is not read as that body",
        !asHtml || asHtml.contentType !== "text/html",
        JSON.stringify(asHtml && asHtml.contentType));
  check("and it is offered as a file instead",
        b.safeMime.extractAttachments(attachedHtml).length === 1,
        JSON.stringify(b.safeMime.extractAttachments(attachedHtml)
          .map(function (f) { return f.filename; })));
  var plain = b.safeMime.extractText(tree, { prefer: "plain" });
  check("and the other preference still answers with its own type",
        plain && plain.contentType === "text/plain",
        JSON.stringify(plain && plain.contentType));

  // With no part of the preferred type anywhere, the opposite type is still
  // better than nothing, which is what this reader has always answered.
  var plainOnly = b.safeMime.parse(Buffer.from(
    ["From: a@example.com", "Subject: s", "", "just text", ""].join("\r\n"), "utf8"));
  check("a message with no HTML still answers with what it has",
        b.safeMime.extractText(plainOnly, { prefer: "html" }).contentType === "text/plain",
        JSON.stringify(b.safeMime.extractText(plainOnly, { prefer: "html" })));
}

function testPreferAnyAsksTheConstructThatKnows() {
  // "give me whichever you have" means two different things depending on
  // what the parts are. Inside a multipart/alternative they are spellings of
  // one body, so the richest (the last, RFC 2046 5.1.4) is wanted. Inside a
  // multipart/mixed they are consecutive sections, so the first is the body
  // and the last is whatever came after it. Applying the alternative's rule
  // to a flat list of everything answered the wrong section for the mixed.
  var alt = b.safeMime.parse(Buffer.from([
    "From: a@example.com", "Subject: s", "MIME-Version: 1.0",
    'Content-Type: multipart/alternative; boundary="A"', "",
    "--A", "Content-Type: text/plain", "", "plain body",
    "--A", "Content-Type: text/html", "", "<p>rich body</p>",
    "--A--", "",
  ].join("\r\n"), "utf8"));
  check("an alternative answers with its richest representation",
        b.safeMime.extractText(alt, { prefer: "any" }).contentType === "text/html",
        JSON.stringify(b.safeMime.extractText(alt, { prefer: "any" }).contentType));

  var mixed = b.safeMime.parse(Buffer.from([
    "From: a@example.com", "Subject: s", "MIME-Version: 1.0",
    'Content-Type: multipart/mixed; boundary="M"', "",
    "--M", "Content-Type: text/plain", "", "the body",
    "--M", "Content-Type: text/html", "", "<p>a later section</p>",
    "--M--", "",
  ].join("\r\n"), "utf8"));
  var anyMixed = b.safeMime.extractText(mixed, { prefer: "any" });
  check("a mixed answers with its first section, not its last",
        anyMixed.contentType === "text/plain" && anyMixed.body.indexOf("the body") !== -1,
        JSON.stringify([anyMixed.contentType, anyMixed.body]));

  // A mixed whose first section is itself an alternative takes that
  // alternative's answer, because that is where the choice belongs.
  var nested = b.safeMime.parse(Buffer.from([
    "From: a@example.com", "Subject: s", "MIME-Version: 1.0",
    'Content-Type: multipart/mixed; boundary="M"', "",
    "--M", 'Content-Type: multipart/alternative; boundary="A"', "",
    "--A", "Content-Type: text/plain", "", "plain body",
    "--A", "Content-Type: text/html", "", "<p>rich body</p>",
    "--A--",
    "--M", "Content-Type: application/pdf",
    'Content-Disposition: attachment; filename="r.pdf"', "", "PDF",
    "--M--", "",
  ].join("\r\n"), "utf8"));
  check("a nested alternative still answers with its richest",
        b.safeMime.extractText(nested, { prefer: "any" }).contentType === "text/html",
        JSON.stringify(b.safeMime.extractText(nested, { prefer: "any" }).contentType));
}

function testARelatedRootIsTheOneTheSenderDeclared() {
  // RFC 2387 section 3.2 gives a `multipart/related` a `start` parameter
  // naming the Content-ID of its root body part, and makes the FIRST part the
  // root only when `start` is absent. RFC 8621 section 4.1.4's suggested
  // algorithm writes that as `i === 0`, which is the same rule for the common
  // message and the wrong one for a message that declares its root: the body
  // was classified a file because an inline image preceded it, `textBody` and
  // `htmlBody` came back empty, and `b.safeMime.extractText` still answered
  // with that part, so the two readers described one message differently.
  var declared = b.safeMime.parse(Buffer.from([
    "From: a@example.com", "Subject: s", "MIME-Version: 1.0",
    'Content-Type: multipart/related; boundary="R"; start="<root@example.com>"', "",
    "--R", "Content-Type: image/png", "Content-ID: <logo@example.com>", "",
    "PNGBYTES",
    "--R", "Content-Type: text/html", "Content-ID: <root@example.com>", "",
    "<p>the body</p>",
    "--R--", "",
  ].join("\r\n"), "utf8"));

  var selection = b.safeMime.selectBodyParts(declared);
  check("the declared root is the body a reader displays",
        selection.html.length === 1 &&
        selection.html[0].part.leaf.contentType === "text/html",
        JSON.stringify(selection.html.map(function (h) {
          return h.part.leaf.contentType;
        })));
  check("and the part that precedes it is a file",
        selection.files.length === 1 &&
        selection.files[0].part.leaf.contentType === "image/png",
        JSON.stringify(selection.files.map(function (f) {
          return f.part.leaf.contentType;
        })));

  // The reader that answers with the body and the one that sorts the leaves
  // are describing the same message.
  var text = b.safeMime.extractText(declared, { prefer: "html" });
  check("extractText answers with that same part",
        text !== null && text.contentType === "text/html",
        JSON.stringify(text && text.contentType));

  // With no `start`, the first part is the root, which is RFC 8621's rule and
  // the shape its own worked example uses.
  var undeclared = b.safeMime.parse(Buffer.from([
    "From: a@example.com", "Subject: s", "MIME-Version: 1.0",
    'Content-Type: multipart/related; boundary="R"', "",
    "--R", "Content-Type: text/html", "Content-ID: <root@example.com>", "",
    "<p>the body</p>",
    "--R", "Content-Type: image/png", "Content-ID: <logo@example.com>", "",
    "PNGBYTES",
    "--R--", "",
  ].join("\r\n"), "utf8"));
  var plainSelection = b.safeMime.selectBodyParts(undeclared);
  check("with no declared root the first part is still the body",
        plainSelection.html.length === 1 &&
        plainSelection.html[0].part.leaf.contentType === "text/html",
        JSON.stringify(plainSelection.html.map(function (h) {
          return h.part.leaf.contentType;
        })));

  // A `start` naming a Content-ID no part carries is not a root, so the rule
  // falls back rather than leaving the message with no body at all.
  var dangling = b.safeMime.parse(Buffer.from([
    "From: a@example.com", "Subject: s", "MIME-Version: 1.0",
    'Content-Type: multipart/related; boundary="R"; start="<absent@example.com>"', "",
    "--R", "Content-Type: text/html", "Content-ID: <root@example.com>", "",
    "<p>the body</p>",
    "--R", "Content-Type: image/png", "Content-ID: <logo@example.com>", "",
    "PNGBYTES",
    "--R--", "",
  ].join("\r\n"), "utf8"));
  var danglingSelection = b.safeMime.selectBodyParts(dangling);
  check("a start naming no part falls back to the first",
        danglingSelection.html.length === 1 &&
        danglingSelection.html[0].part.leaf.contentType === "text/html",
        JSON.stringify(danglingSelection.html.map(function (h) {
          return h.part.leaf.contentType;
        })));

  // The structure of a header comes from the bytes on the wire, because
  // decoding an RFC 2047 encoded word can produce a quote or a semicolon that
  // is data rather than syntax. Reading the root's `start` off the DECODED
  // header re-parsed a header whose decoded form is unbalanced, so a message
  // that parses cleanly threw `safe-mime/malformed-content-type` out of
  // `extractText`, `extractAttachments` and `b.mailStore.appendMessage`.
  var decodesToAQuote = b.safeMime.parse(Buffer.from([
    "From: a@example.com", "Subject: s", "MIME-Version: 1.0",
    'Content-Type: multipart/related; boundary="R"; name="=?utf-8?B?YSJi?="', "",
    "--R", "Content-Type: text/html", "Content-ID: <root@example.com>", "",
    "<p>the body</p>",
    "--R", "Content-Type: image/png", "Content-ID: <logo@example.com>", "",
    "PNGBYTES",
    "--R--", "",
  ].join("\r\n"), "utf8"));
  var threw = null;
  var quoteSelection = null;
  try { quoteSelection = b.safeMime.selectBodyParts(decodesToAQuote); }
  catch (e) { threw = e; }
  check("a related whose parameter decodes to a quote still sorts its leaves",
        threw === null, threw && (threw.code + ": " + threw.message));
  check("and its first part is still the body",
        quoteSelection !== null && quoteSelection.html.length === 1,
        JSON.stringify(quoteSelection && quoteSelection.html.length));
  var quoteText = null;
  try { quoteText = b.safeMime.extractText(decodesToAQuote, { prefer: "html" }); }
  catch (e) { quoteText = "THREW " + e.code; }
  check("extractText answers for it rather than throwing",
        quoteText !== null && quoteText.contentType === "text/html",
        JSON.stringify(quoteText && (quoteText.contentType || quoteText)));

  // RFC 8621 section 4.1.4's rule for a `multipart/related` is that only the
  // root part is displayed, and a non-root child is a resource whether it is a
  // leaf or a multipart of its own. The walk passed a multipart child straight
  // through and started its children at position 0, so a resource that is
  // itself a `multipart/alternative` had its representations promoted to the
  // displayed body: the sender chooses that shape, so the sender chose which
  // text a reader shows.
  var nestedResource = b.safeMime.parse(Buffer.from([
    "From: a@example.com", "Subject: s", "MIME-Version: 1.0",
    'Content-Type: multipart/related; boundary="R"; start="<root@example.com>"', "",
    "--R", 'Content-Type: multipart/alternative; boundary="A"',
    "Content-ID: <resource@example.com>", "",
    "--A", "Content-Type: text/plain", "", "the resource text",
    "--A", "Content-Type: text/html", "", "<p>the resource</p>",
    "--A--",
    "--R", "Content-Type: text/html", "Content-ID: <root@example.com>", "",
    "<p>the body</p>",
    "--R--", "",
  ].join("\r\n"), "utf8"));
  var nestedSelection = b.safeMime.selectBodyParts(nestedResource);
  check("only the declared root of a related supplies the body",
        nestedSelection.html.length === 1 &&
        nestedSelection.html[0].part.leaf.body.toString("utf8").indexOf("the body") !== -1,
        JSON.stringify(nestedSelection.html.map(function (h) {
          return h.part.leaf.body.toString("utf8");
        })));
  check("and the whole non-root branch is offered as files",
        nestedSelection.text.length === 0 && nestedSelection.files.length === 2,
        JSON.stringify([nestedSelection.text.length, nestedSelection.files.length]));
  var nestedAny = b.safeMime.extractText(nestedResource, { prefer: "any" });
  check("extractText answers with the root, not with the resource",
        nestedAny !== null &&
        nestedAny.body.toString("utf8").indexOf("the body") !== -1,
        JSON.stringify(nestedAny && nestedAny.body.toString("utf8")));

  // The same shape with the multipart child as the ROOT still supplies the
  // body, so the rule is the position and not the nesting.
  var nestedRoot = b.safeMime.parse(Buffer.from([
    "From: a@example.com", "Subject: s", "MIME-Version: 1.0",
    'Content-Type: multipart/related; boundary="R"; start="<root@example.com>"', "",
    "--R", "Content-Type: image/png", "Content-ID: <logo@example.com>", "",
    "PNGBYTES",
    "--R", 'Content-Type: multipart/alternative; boundary="A"',
    "Content-ID: <root@example.com>", "",
    "--A", "Content-Type: text/plain", "", "the body",
    "--A", "Content-Type: text/html", "", "<p>the body</p>",
    "--A--",
    "--R--", "",
  ].join("\r\n"), "utf8"));
  var rootSelection = b.safeMime.selectBodyParts(nestedRoot);
  check("a multipart root still supplies both representations",
        rootSelection.text.length === 1 && rootSelection.html.length === 1,
        JSON.stringify([rootSelection.text.length, rootSelection.html.length,
                        rootSelection.files.length]));

  // Agents write the Content-ID with angle brackets and the `start` value with
  // or without them, and RFC 2387 section 3.2 says the value IS the
  // Content-ID, so the two are compared without their delimiters.
  var bareStart = b.safeMime.parse(Buffer.from([
    "From: a@example.com", "Subject: s", "MIME-Version: 1.0",
    'Content-Type: multipart/related; boundary="R"; start="root@example.com"', "",
    "--R", "Content-Type: image/png", "Content-ID: <logo@example.com>", "",
    "PNGBYTES",
    "--R", "Content-Type: text/html", "Content-ID: <root@example.com>", "",
    "<p>the body</p>",
    "--R--", "",
  ].join("\r\n"), "utf8"));
  var bareSelection = b.safeMime.selectBodyParts(bareStart);
  check("a start written without angle brackets names the same part",
        bareSelection.html.length === 1 &&
        bareSelection.html[0].part.leaf.contentType === "text/html",
        JSON.stringify(bareSelection.html.map(function (h) {
          return h.part.leaf.contentType;
        })));
}

function testANamedFirstAlternativeBesideARealBodyIsAFileToo() {
  // The same question asked of a `multipart/alternative`: a named
  // `text/plain` first, the real body after it as `text/html`. This branch
  // answered it the other way, exempting the first part from the name test
  // outright, so the named file was offered as the message text while no list
  // named it, and the identical shape under `multipart/mixed` was already
  // read the other way. One question with two answers is the defect; the
  // exemption is a fallback for a part with no siblings, in both.
  var alt = b.safeMime.parse(Buffer.from([
    "From: a@example.com", "Subject: s", "MIME-Version: 1.0",
    'Content-Type: multipart/alternative; boundary="a"', "",
    "--a", "Content-Type: text/plain",
    'Content-Disposition: inline; filename="notes.txt"', "", "attached notes",
    "--a", "Content-Type: text/html", "", "<p>the real body</p>",
    "--a--", "",
  ].join("\r\n"), "utf8"));

  var altSelection = b.safeMime.selectBodyParts(alt);
  check("the named first alternative is a file",
        altSelection.files.length === 1 && altSelection.files[0].filename === "notes.txt",
        JSON.stringify(altSelection.files.map(function (f) { return f.filename; })));
  check("and it is not offered as the message text",
        altSelection.text.length === 0, String(altSelection.text.length));
  check("while the part carrying no name is the body",
        altSelection.html.length === 1 &&
        altSelection.html[0].part.leaf.body.toString("utf8").indexOf("the real body") !== -1,
        JSON.stringify(altSelection.html.map(function (h) {
          return h.part.leaf.body.toString("utf8");
        })));
  check("extractAttachments offers it",
        b.safeMime.extractAttachments(alt).map(function (f) { return f.filename; })
          .join(",") === "notes.txt",
        JSON.stringify(b.safeMime.extractAttachments(alt)
          .map(function (f) { return f.filename; })));

  // The body a named part is weighed against is not always a sibling LEAF.
  // A `multipart/mixed` that opens with a named inline note and carries the
  // real body after it as a `multipart/alternative` has one leaf sibling and
  // one subtree, and reading only the leaves leaves the note looking like the
  // only thing on offer, so it went back to being the message text and left
  // the attachment list.
  var nested = b.safeMime.parse(Buffer.from([
    "From: a@example.com", "Subject: s", "MIME-Version: 1.0",
    'Content-Type: multipart/mixed; boundary="m"', "",
    "--m", "Content-Type: text/plain",
    'Content-Disposition: inline; filename="notes.txt"', "", "attached notes",
    "--m", 'Content-Type: multipart/alternative; boundary="a"', "",
    "--a", "Content-Type: text/plain", "", "the real body",
    "--a", "Content-Type: text/html", "", "<p>the real body</p>",
    "--a--", "",
    "--m--", "",
  ].join("\r\n"), "utf8"));
  var nestedSelection = b.safeMime.selectBodyParts(nested);
  check("a body inside a sibling multipart still makes the named part a file",
        nestedSelection.files.length === 1 &&
        nestedSelection.files[0].filename === "notes.txt",
        JSON.stringify(nestedSelection.files.map(function (f) { return f.filename; })));
  check("and the body comes from the alternative",
        nestedSelection.text.length === 1 &&
        nestedSelection.text[0].part.leaf.body.toString("utf8")
          .indexOf("the real body") !== -1,
        JSON.stringify(nestedSelection.text.map(function (t) {
          return t.part.leaf.body.toString("utf8");
        })));

  // The fallback: an alternative holding one named text part has nothing
  // else to show, so that part is still the body.
  var only = b.safeMime.parse(Buffer.from([
    "From: a@example.com", "Subject: s", "MIME-Version: 1.0",
    'Content-Type: multipart/alternative; boundary="a"', "",
    "--a", "Content-Type: text/plain",
    'Content-Disposition: inline; filename="message.txt"', "", "the only thing here",
    "--a--", "",
  ].join("\r\n"), "utf8"));
  var onlySelection = b.safeMime.selectBodyParts(only);
  check("a lone named alternative is still the body",
        onlySelection.text.length === 1 && onlySelection.files.length === 0,
        JSON.stringify([onlySelection.text.length, onlySelection.files.length]));
}

function testANamedFirstPartBesideARealBodyIsAFile() {
  // RFC 8621 section 4.1.4's algorithm exempts the first part from the name
  // test outright (`i === 0 ||`), and taking that literally makes a named file
  // the body whenever the sender puts it first: a `multipart/mixed` opening
  // with `text/plain; inline; filename="notes.txt"` and carrying the real body
  // after it offered the file as the message text, left it out of
  // `attachments`, and stored both facts wrong.
  //
  // The exemption is there for the message that has nothing else to show: a
  // lone `text/plain` a gateway wrote as `inline; filename="message.txt"` is
  // the body, and calling it a file leaves the message with none. So the
  // exemption is a FALLBACK for a part with no siblings, not a precedence over
  // the name.
  var mixed = b.safeMime.parse(Buffer.from([
    "From: a@example.com", "Subject: s", "MIME-Version: 1.0",
    'Content-Type: multipart/mixed; boundary="m"', "",
    "--m", "Content-Type: text/plain",
    'Content-Disposition: inline; filename="notes.txt"', "", "attached notes",
    "--m", "Content-Type: text/plain", "", "the real body",
    "--m--", "",
  ].join("\r\n"), "utf8"));

  var selection = b.safeMime.selectBodyParts(mixed);
  check("the named first part is a file",
        selection.files.length === 1 &&
        selection.files[0].filename === "notes.txt",
        JSON.stringify(selection.files.map(function (f) { return f.filename; })));
  check("and the body is the part that carries no name",
        selection.text.length === 1 &&
        selection.text[0].part.leaf.body.toString("utf8").indexOf("the real body") !== -1,
        JSON.stringify(selection.text.map(function (t) {
          return t.part.leaf.body.toString("utf8");
        })));

  var text = b.safeMime.extractText(mixed, { prefer: "plain" });
  check("extractText answers with the body, not the named file",
        text !== null && text.body.toString("utf8").indexOf("the real body") !== -1,
        JSON.stringify(text && text.body.toString("utf8")));

  var files = b.safeMime.extractAttachments(mixed);
  check("extractAttachments offers the named file",
        files.length === 1 && files[0].filename === "notes.txt",
        JSON.stringify(files.map(function (f) { return f.filename; })));

  // The fallback still holds: a lone named text part is the body, because
  // there is nothing else the message could show.
  var lone = b.safeMime.parse(Buffer.from([
    "From: a@example.com", "Subject: s", "MIME-Version: 1.0",
    "Content-Type: text/plain",
    'Content-Disposition: inline; filename="message.txt"', "",
    "the only thing here", "",
  ].join("\r\n"), "utf8"));
  var loneSelection = b.safeMime.selectBodyParts(lone);
  check("a lone named text part is still the body",
        loneSelection.text.length === 1 && loneSelection.files.length === 0,
        JSON.stringify([loneSelection.text.length, loneSelection.files.length]));
}

function testAnAttachedMultipartTakesItsWholeSubtreeWithIt() {
  // A `Content-Disposition: attachment` on a CONTAINER says the whole thing is
  // attached, and RFC 2183 section 2.2 puts the disposition on the body part
  // it heads without exempting a multipart. The walk read the disposition when
  // it reached a leaf and not when it descended, so an attached
  // `multipart/alternative` had its representations read as the message's own
  // body: `textBody` and `htmlBody` carried the attachment's text, and
  // `attachments` and `hasAttachment` said the message carried no file at all.
  // The container's disposition is the sender's to write.
  var tree = b.safeMime.parse(Buffer.from([
    "From: a@example.com", "Subject: s", "MIME-Version: 1.0",
    'Content-Type: multipart/mixed; boundary="m"', "",
    "--m", "Content-Type: text/plain", "", "the real body",
    "--m", 'Content-Type: multipart/alternative; boundary="a"',
    'Content-Disposition: attachment; filename="forwarded.eml"', "",
    "--a", "Content-Type: text/plain", "", "attached plain",
    "--a", "Content-Type: text/html", "", "<p>attached html</p>",
    "--a--",
    "--m--", "",
  ].join("\r\n"), "utf8"));

  var selection = b.safeMime.selectBodyParts(tree);
  check("the attached container's parts are files",
        selection.files.length === 2,
        JSON.stringify(selection.files.map(function (f) {
          return f.part.leaf.contentType;
        })));
  check("and the message's own body is the only displayed text",
        selection.text.length === 1 &&
        selection.text[0].part.leaf.body.toString("utf8").indexOf("the real body") !== -1,
        JSON.stringify(selection.text.map(function (t) {
          return t.part.leaf.body.toString("utf8");
        })));
  check("with no displayed HTML, because the only HTML is attached",
        selection.html.length === 0,
        JSON.stringify(selection.html.length));

  var view = b.mail.server.jmap.emailBodyProperties(tree, { blobIdPrefix: "bl" });
  check("the JMAP view reports the attachment",
        view.hasAttachment === true && view.attachments.length === 2,
        JSON.stringify([view.hasAttachment, view.attachments.length]));
  check("and does not offer its text as the body",
        view.textBody.every(function (p) { return p.partId === "1"; }) &&
        view.htmlBody.every(function (p) { return p.partId === "1"; }),
        JSON.stringify([view.textBody.map(function (p) { return p.partId; }),
                        view.htmlBody.map(function (p) { return p.partId; })]));

  // A container with no such disposition is unchanged, so the rule is the
  // disposition and not the nesting.
  var plain = b.safeMime.parse(Buffer.from([
    "From: a@example.com", "Subject: s", "MIME-Version: 1.0",
    'Content-Type: multipart/mixed; boundary="m"', "",
    "--m", "Content-Type: text/plain", "", "the real body",
    "--m", 'Content-Type: multipart/alternative; boundary="a"', "",
    "--a", "Content-Type: text/plain", "", "alt plain",
    "--a", "Content-Type: text/html", "", "<p>alt html</p>",
    "--a--",
    "--m--", "",
  ].join("\r\n"), "utf8"));
  var plainSelection = b.safeMime.selectBodyParts(plain);
  check("an undispositioned container still contributes its body",
        plainSelection.html.length === 1 && plainSelection.files.length === 0,
        JSON.stringify([plainSelection.text.length, plainSelection.html.length,
                        plainSelection.files.length]));
}

function testTheRichestRepresentationIsATextTypeQuestion() {
  // `prefer: "any"` asks which representation of the body is richest, and RFC
  // 2046 section 5.1.4 answers "the last". That is a question about text
  // types: `text/enriched` (RFC 1896) and `text/markdown` (RFC 7763) are
  // representations of a body. The JMAP body classification RFC 8621 section
  // 4.1.4 defines answers a narrower question, which parts a JMAP client puts
  // in `textBody` and `htmlBody`, and it names only `text/plain` and
  // `text/html`. Ranking the representations by the narrower answer skipped
  // every richer text type, so an alternative ending in `text/enriched` was
  // answered with the plain representation the sender wrote first.
  function _alt(rows) {
    var lines = [
      "From: a@example.com", "Subject: s", "MIME-Version: 1.0",
      'Content-Type: multipart/alternative; boundary="A"', "",
    ];
    for (var i = 0; i < rows.length; i += 1) {
      lines.push("--A");
      lines.push.apply(lines, rows[i]);
    }
    lines.push("--A--", "");
    return b.safeMime.parse(Buffer.from(lines.join("\r\n"), "utf8"));
  }

  var ROWS = [
    { label: "plain then enriched",
      rows: [["Content-Type: text/plain", "", "plain body"],
             ["Content-Type: text/enriched", "", "enriched body"]],
      want: "text/enriched" },
    { label: "plain, html, then enriched",
      rows: [["Content-Type: text/plain", "", "plain body"],
             ["Content-Type: text/html", "", "<p>rich</p>"],
             ["Content-Type: text/enriched", "", "enriched body"]],
      want: "text/enriched" },
    // The rule is "the last", not "the unusual one": a plain representation
    // written after a richer one is still the one the sender ordered last.
    { label: "enriched then plain",
      rows: [["Content-Type: text/enriched", "", "enriched body"],
             ["Content-Type: text/plain", "", "plain body"]],
      want: "text/plain" },
    { label: "markdown then plain",
      rows: [["Content-Type: text/markdown", "", "# md"],
             ["Content-Type: text/plain", "", "plain body"]],
      want: "text/plain" },
    // A representation wrapped in another multipart counts as that one
    // choice, which is the rule the selection already applies to plain and
    // HTML.
    { label: "plain then a related wrapping enriched",
      rows: [["Content-Type: text/plain", "", "plain body"],
             ['Content-Type: multipart/related; boundary="R"', "",
              "--R", "Content-Type: text/enriched", "", "enriched body",
              "--R--"]],
      want: "text/enriched" },
    // A part the sender marked as an attachment is not a spelling of the
    // body, whichever branch it sits in, so it is not the richest
    // representation either.
    { label: "plain then an attachment-dispositioned enriched",
      rows: [["Content-Type: text/plain", "", "plain body"],
             ["Content-Type: text/enriched",
              'Content-Disposition: attachment; filename="r.enriched"', "",
              "enriched body"]],
      want: "text/plain" },
  ];

  var wrong = [];
  for (var i = 0; i < ROWS.length; i += 1) {
    var got = b.safeMime.extractText(_alt(ROWS[i].rows), { prefer: "any" });
    var ct = got === null ? "null" : got.contentType;
    if (ct !== ROWS[i].want) wrong.push(ROWS[i].label + " -> " + ct);
  }
  check("the richest representation is the last text-typed one" +
        (wrong.length ? " (" + wrong.join("; ") + ")" : ""), wrong.length === 0);

  // Which representation `prefer: "any"` answers with does not move a leaf
  // between the body lists and the files: a `text/enriched` is still a file
  // to the JMAP classification, so `attachments` and the stored attachment
  // count say the same thing they did.
  var enriched = _alt([["Content-Type: text/plain", "", "plain body"],
                       ["Content-Type: text/enriched", "", "enriched body"]]);
  var selection = b.safeMime.selectBodyParts(enriched);
  check("and the selection still calls a richer text type a file",
        selection.files.length === 1 &&
        selection.files[0].part.leaf.contentType === "text/enriched",
        JSON.stringify(selection.files.map(function (f) {
          return f.part.leaf.contentType;
        })));
  check("while the plain representation is still the displayed text",
        selection.text.length === 1 &&
        selection.text[0].part.leaf.contentType === "text/plain",
        JSON.stringify(selection.text.map(function (t) {
          return t.part.leaf.contentType;
        })));

  // An alternative carrying no HTML at all answers `prefer: "html"` with the
  // text representation a reader displays, which is the last one RFC 2046
  // section 5.1.4 orders. Answering with the first text-typed part instead
  // reads the ordering backwards and hands back the simplest representation
  // for the request that asked for the richest.
  var FALLBACK = [
    { label: "enriched then plain",
      rows: [["Content-Type: text/enriched", "", "enriched body"],
             ["Content-Type: text/plain", "", "plain body"]],
      want: "text/plain" },
    { label: "markdown then plain",
      rows: [["Content-Type: text/markdown", "", "# md"],
             ["Content-Type: text/plain", "", "plain body"]],
      want: "text/plain" },
    { label: "plain then a second plain",
      rows: [["Content-Type: text/plain", "", "first"],
             ["Content-Type: text/plain", "", "second"]],
      want: "text/plain" },
  ];
  var fallbackWrong = [];
  for (var f = 0; f < FALLBACK.length; f += 1) {
    var answer = b.safeMime.extractText(_alt(FALLBACK[f].rows), { prefer: "html" });
    var answerType = answer === null ? "null" : answer.contentType;
    if (answerType !== FALLBACK[f].want) {
      fallbackWrong.push(FALLBACK[f].label + " -> " + answerType);
    }
  }
  check("an alternative with no HTML answers with the text a reader displays" +
        (fallbackWrong.length ? " (" + fallbackWrong.join("; ") + ")" : ""),
        fallbackWrong.length === 0);

  var secondPlain = b.safeMime.extractText(_alt(FALLBACK[2].rows), { prefer: "html" });
  check("and that is the last representation, not the first",
        secondPlain !== null && secondPlain.body.indexOf("second") !== -1,
        JSON.stringify(secondPlain && secondPlain.body));
}

function testInlineInclusionReturnsEveryLeaf() {
  // includeInline is the caller asking for every part rather than the files
  // a reader would offer, so it cannot be the display selection with the
  // body added back: that already dropped the parts of a representation
  // nobody displays, and a caller walking every part would never see them.
  var raw = [
    "From: a@example.com", "Subject: s", "MIME-Version: 1.0",
    'Content-Type: multipart/alternative; boundary="alt"', "",
    "--alt", 'Content-Type: multipart/related; boundary="rel"', "",
    "--rel", "Content-Type: text/html", "",
    '<p>superseded <img src="cid:logo@example.com"></p>',
    "--rel", "Content-Type: image/png", "Content-ID: <logo@example.com>",
    'Content-Disposition: inline; filename="logo.png"', "", "PNGBYTES",
    "--rel--",
    "--alt", "Content-Type: text/html", "", "<p>preferred</p>",
    "--alt--", "",
  ].join("\r\n");
  var tree = b.safeMime.parse(Buffer.from(raw, "utf8"));
  var every = b.safeMime.extractAttachments(tree, { includeInline: true });
  check("every leaf is returned, superseded representation included",
        every.length === 3,
        JSON.stringify(every.map(function (a) { return a.path.join("."); })));
  check("and they are in document order",
        JSON.stringify(every.map(function (a) { return a.path.join("."); })) ===
        JSON.stringify(["0.0", "0.1", "1"]),
        JSON.stringify(every.map(function (a) { return a.path.join("."); })));
  // The default answer names the files, which here is the one payload leaf;
  // the two text representations are the body written twice and are not
  // files under either option.
  var byDefault = b.safeMime.extractAttachments(tree);
  check("while the default offers the files and not the body representations",
        byDefault.length === 1 && byDefault[0].filename === "logo.png",
        JSON.stringify(byDefault.map(function (a) { return a.filename; })));
}

function testInlineInclusionKeepsDocumentOrder() {
  // includeInline merges the display lists back into the file list, which is
  // a sort rather than a walk. Sorting the paths as joined strings orders a
  // twelve-part message 0, 1, 10, 11, 2, so a caller reading the parts in
  // order read them out of order.
  var lines = ["From: a@example.com", "Subject: s", "MIME-Version: 1.0",
               'Content-Type: multipart/mixed; boundary="m"', ""];
  for (var i = 0; i < 12; i += 1) {
    lines.push("--m", "Content-Type: text/plain", "", "part " + i);
  }
  lines.push("--m--", "");
  var tree = b.safeMime.parse(Buffer.from(lines.join("\r\n"), "utf8"));
  var all = b.safeMime.extractAttachments(tree, { includeInline: true });
  check("every part is returned", all.length === 12, String(all.length));
  var bodies = all.map(function (a) { return a.body.toString("utf8").trim(); });
  var expected = [];
  for (var j = 0; j < 12; j += 1) expected.push("part " + j);
  check("and they are in document order, not string order",
        JSON.stringify(bodies) === JSON.stringify(expected), JSON.stringify(bodies));
}

function testTheSelectionIsReadableOnItsOwn() {
  // The policy both readers share, answered directly: a consumer rendering a
  // message needs the same three lists, and a fourth copy of the rule is the
  // thing this primitive exists to prevent.
  var tree = b.safeMime.parse(Buffer.from([
    "From: a@example.com", "Subject: s", "MIME-Version: 1.0",
    'Content-Type: multipart/mixed; boundary="mix"', "",
    "--mix", 'Content-Type: multipart/alternative; boundary="alt"', "",
    "--alt", "Content-Type: text/plain", "", "hi",
    "--alt", "Content-Type: text/html", "", "<p>hi</p>",
    "--alt--",
    "--mix", "Content-Type: application/pdf",
    'Content-Disposition: attachment; filename="report.pdf"', "", "PDFBYTES",
    "--mix--", "",
  ].join("\r\n"), "utf8"));
  var selection = b.safeMime.selectBodyParts(tree);
  check("the plain-text representation is the displayed text",
        selection.text.length === 1 && selection.text[0].part.leaf.contentType === "text/plain",
        JSON.stringify(selection.text.map(function (e) { return e.path; })));
  check("the HTML representation is the displayed HTML",
        selection.html.length === 1 && selection.html[0].part.leaf.contentType === "text/html",
        JSON.stringify(selection.html.map(function (e) { return e.path; })));
  check("and the file is the one beside them",
        selection.files.length === 1 && selection.files[0].filename === "report.pdf",
        JSON.stringify(selection.files.map(function (e) { return e.filename; })));
  check("each entry says where in the tree it came from",
        JSON.stringify(selection.files[0].path) === JSON.stringify([1]),
        JSON.stringify(selection.files[0].path));
  check("a tree with nothing in it answers three empty lists",
        b.safeMime.selectBodyParts(null).files.length === 0 &&
        b.safeMime.selectBodyParts(null).text.length === 0 &&
        b.safeMime.selectBodyParts(null).html.length === 0);
}

function testOnlyTheFilenameParameterIsReadAsTheFilename() {
  // The reader searched the header for the text "filename", which is the
  // tail of every parameter ending in those letters. A sender writing
  // `x-filename*=` put a name of their choosing ahead of the real one, and
  // an extended form is preferred over a plain one, so theirs won outright.
  function _headers(cd) {
    return { get: function (n) {
      return String(n).toLowerCase() === "content-disposition" ? cd : null;
    } };
  }
  var spoofed = _headers(
    'attachment; x-filename*=UTF-8\'\'evil.exe; filename="real.pdf"');
  check("a parameter ending in those letters is not the filename",
        b.safeMime.filenameFromHeaders(spoofed) === "real.pdf",
        JSON.stringify(b.safeMime.filenameFromHeaders(spoofed)));

  // The real extended form is still preferred over the plain one (RFC 6266).
  var extended = _headers(
    'attachment; filename="plain.pdf"; filename*=UTF-8\'\'r%C3%A9el.pdf');
  check("the extended parameter still wins when it is the real one",
        b.safeMime.filenameFromHeaders(extended) === "réel.pdf",
        JSON.stringify(b.safeMime.filenameFromHeaders(extended)));

  // And a parameter that merely starts with the letters is not it either.
  var prefixed = _headers('attachment; filenamex=other.exe; filename="real.pdf"');
  check("nor is one that merely starts with them",
        b.safeMime.filenameFromHeaders(prefixed) === "real.pdf",
        JSON.stringify(b.safeMime.filenameFromHeaders(prefixed)));

  // The value ended at the first `;` in the whole header, found with a bare
  // search that did not know it was inside a quoted string. A semicolon is an
  // ordinary filename character, so the name was cut at it AND kept the
  // opening quote: `filename="a;b.txt"` read back as `"a`, which has no
  // extension for b.guardAll.byExtension to dispatch on.
  var semi = _headers('attachment; filename="a;b.txt"');
  check("a semicolon inside the quotes is part of the name",
        b.safeMime.filenameFromHeaders(semi) === "a;b.txt",
        JSON.stringify(b.safeMime.filenameFromHeaders(semi)));

  // RFC 2045 5.1 quoted-pair: the escape is spelling, not content.
  var escaped = _headers('attachment; filename="a\\"b.txt"');
  check("an escaped quote inside the name is unescaped",
        b.safeMime.filenameFromHeaders(escaped) === 'a"b.txt',
        JSON.stringify(b.safeMime.filenameFromHeaders(escaped)));

  // A parameter after the quoted one is still a parameter.
  var after = _headers('attachment; filename="a;b.txt"; size=42');
  check("a parameter after the quoted name still ends the name",
        b.safeMime.filenameFromHeaders(after) === "a;b.txt",
        JSON.stringify(b.safeMime.filenameFromHeaders(after)));
}

function testOnlyTheNameParameterIsReadAsTheName() {
  // The Content-Type fallback searched the raw header for the text "name=",
  // which is the tail of every parameter ending in those letters and appears
  // inside quoted values too. `x-username=bob` was therefore read as a file
  // named "bob", and a `name=` written inside another parameter's quoted
  // value named the file, which is a name the sender chose for a parameter
  // that is not a filename at all. The header is parsed, so the parameter is
  // looked up rather than searched for.
  function _headers(ct) {
    return { get: function (n) {
      return String(n).toLowerCase() === "content-type" ? ct : null;
    } };
  }
  check("the name parameter is still read",
        b.safeMime.filenameFromHeaders(_headers("application/pdf; name=report.pdf")) ===
        "report.pdf",
        JSON.stringify(b.safeMime.filenameFromHeaders(_headers("application/pdf; name=report.pdf"))));
  check("a parameter merely ending in those letters is not the name",
        b.safeMime.filenameFromHeaders(
          _headers("application/octet-stream; x-username=bob")) === null,
        JSON.stringify(b.safeMime.filenameFromHeaders(
          _headers("application/octet-stream; x-username=bob"))));
  check("nor is one inside another parameter's quoted value",
        b.safeMime.filenameFromHeaders(
          _headers('application/pdf; x="a; name=evil.exe"')) === null,
        JSON.stringify(b.safeMime.filenameFromHeaders(
          _headers('application/pdf; x="a; name=evil.exe"'))));
  check("a quoted name keeps the spaces inside it",
        b.safeMime.filenameFromHeaders(
          _headers('application/pdf; name="q1 report.pdf"')) === "q1 report.pdf",
        JSON.stringify(b.safeMime.filenameFromHeaders(
          _headers('application/pdf; name="q1 report.pdf"'))));
  // Content-Disposition still wins over the Content-Type fallback.
  var both = { get: function (n) {
    var k = String(n).toLowerCase();
    if (k === "content-disposition") return 'attachment; filename="chosen.pdf"';
    if (k === "content-type") return "application/pdf; name=other.pdf";
    return null;
  } };
  check("the disposition filename is preferred over the type's name",
        b.safeMime.filenameFromHeaders(both) === "chosen.pdf",
        JSON.stringify(b.safeMime.filenameFromHeaders(both)));
}

async function run() {
  testEachAttachmentCarriesItsPosition();
  testThePathAddressesTheSamePartTheBodyCameFrom();
  testTheFilenameReaderIsAvailableToACallerWalkingItself();
  testAPartAnnouncedOnlyByContentTypeIsStillAnAttachment();
  testAnInlineFileIsCountedTheWayTheJmapViewCountsIt();
  testAFilenameThatLooksLikeAParameterIsNotReadAsOne();
  testWhitespaceAroundTheParameterEqualsIsAllowed();
  testASupersededAlternativesFilesAreStillOffered();
  testThePreferredAlternativeIsTheLastOne();
  testAnAttachedFileSurvivesLosingTheRepresentationContest();
  testAFileWithNoDispositionSurvivesLosingTheContestToo();
  testExtractTextAndTheSelectionAgreeAboutWhatTheBodyIs();
  testEveryAttachedLeafTheStructureShowsIsOffered();
  testPreferOutranksTheOppositeTypeEvenOutsideTheDisplayLists();
  testPreferAnyAsksTheConstructThatKnows();
  testARelatedRootIsTheOneTheSenderDeclared();
  testANamedFirstPartBesideARealBodyIsAFile();
  testANamedFirstAlternativeBesideARealBodyIsAFileToo();
  testAnAttachedMultipartTakesItsWholeSubtreeWithIt();
  testTheRichestRepresentationIsATextTypeQuestion();
  testInlineInclusionReturnsEveryLeaf();
  testInlineInclusionKeepsDocumentOrder();
  testTheSelectionIsReadableOnItsOwn();
  testOnlyTheFilenameParameterIsReadAsTheFilename();
  testOnlyTheNameParameterIsReadAsTheName();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[safe-mime-attachment-identity] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
