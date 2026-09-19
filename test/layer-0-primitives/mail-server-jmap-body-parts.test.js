// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A JMAP `Email/get` can answer the body-part properties RFC 8621 §4.1.4
 * defines, built from a parsed message.
 *
 * `b.mail.server.jmap` carried no `bodyStructure`, `attachments` or
 * `hasAttachment` anywhere, so a client could not see that a message held a
 * file, list its parts, or fetch one. The gap is invisible: `Email/get`
 * returns a well-formed response, the client reads the properties it knows,
 * and a message with three files attached looks the same as one with none.
 *
 * `Email/get` is an operator-supplied handler here, so the framework's part
 * is the builder the handler composes: it turns the tree `b.safeMime.parse`
 * produces into `bodyStructure`, `textBody`, `htmlBody`, `attachments` and
 * `hasAttachment`, giving each `EmailBodyPart` the `partId` and `blobId` a
 * client needs to fetch one part through the download endpoint.
 *
 * `blobId` has to satisfy the JMAP Id grammar of RFC 8620 §1.2, because the
 * download handler in this same module refuses anything else.
 */

var helpers = require("../helpers");
var check   = helpers.check;
var b       = helpers.b;

var JMAP_ID_RE = /^[A-Za-z0-9_-]{1,255}$/;

var MESSAGE = [
  "From: a@example.com",
  "To: b@example.net",
  "Subject: with files",
  "MIME-Version: 1.0",
  'Content-Type: multipart/mixed; boundary="outer"',
  "",
  "--outer",
  'Content-Type: multipart/alternative; boundary="inner"',
  "",
  "--inner",
  "Content-Type: text/plain; charset=utf-8",
  "",
  "hello",
  "--inner",
  "Content-Type: text/html; charset=utf-8",
  "",
  "<p>hello</p>",
  "--inner--",
  "--outer",
  "Content-Type: application/pdf",
  'Content-Disposition: attachment; filename="report.pdf"',
  "",
  "PDFBYTES",
  "--outer--",
  "",
].join("\r\n");

var PLAIN = [
  "From: a@example.com",
  "To: b@example.net",
  "Subject: no files",
  "Content-Type: text/plain; charset=utf-8",
  "",
  "just text",
  "",
].join("\r\n");

function _build(raw, opts) {
  var tree = b.safeMime.parse(Buffer.from(raw, "utf8"));
  return b.mail.server.jmap.emailBodyProperties(tree, opts || { blobIdPrefix: "obj_1" });
}

function _eachPart(node, visit) {
  visit(node);
  (node.subParts || []).forEach(function (sub) { _eachPart(sub, visit); });
}

function testTheShapeIsTheOneTheRfcDefines() {
  var props = _build(MESSAGE);
  check("the five body properties are answered",
        props.bodyStructure !== undefined && Array.isArray(props.textBody) &&
        Array.isArray(props.htmlBody) && Array.isArray(props.attachments) &&
        typeof props.hasAttachment === "boolean",
        Object.keys(props).join(", "));
  check("hasAttachment is true for a message carrying one",
        props.hasAttachment === true);
  check("the attachment is listed with its name and type",
        props.attachments.length === 1 &&
        props.attachments[0].name === "report.pdf" &&
        props.attachments[0].type === "application/pdf",
        JSON.stringify(props.attachments.map(function (p) { return [p.name, p.type]; })));
  check("textBody and htmlBody name the alternative's two leaves",
        props.textBody.length === 1 && props.textBody[0].type === "text/plain" &&
        props.htmlBody.length === 1 && props.htmlBody[0].type === "text/html",
        JSON.stringify([props.textBody.map(function (p) { return p.type; }),
                        props.htmlBody.map(function (p) { return p.type; })]));
  check("bodyStructure is the whole tree, so the multiparts are present",
        props.bodyStructure.type === "multipart/mixed" &&
        Array.isArray(props.bodyStructure.subParts) &&
        props.bodyStructure.subParts.length === 2,
        props.bodyStructure.type);
}

function testEveryPartCanBeFetched() {
  var props = _build(MESSAGE);
  var parts = [];
  _eachPart(props.bodyStructure, function (p) { parts.push(p); });
  var badBlob = parts.filter(function (p) {
    return p.blobId !== null && !JMAP_ID_RE.test(p.blobId);
  });
  check("every blobId satisfies the JMAP Id grammar the download handler enforces" +
        (badBlob.length ? " (" + badBlob.map(function (p) { return p.blobId; }).join(", ") + ")" : ""),
        badBlob.length === 0);
  var leaves = parts.filter(function (p) { return !p.subParts || p.subParts.length === 0; });
  check("every leaf carries a blobId, so a client can fetch it",
        leaves.length > 0 && leaves.every(function (p) { return typeof p.blobId === "string"; }),
        JSON.stringify(leaves.map(function (p) { return p.blobId; })));
  var ids = parts.map(function (p) { return p.partId; }).filter(function (v) { return v !== null; });
  check("partIds are distinct within the message",
        ids.length === new Set(ids).size, JSON.stringify(ids));
  check("a multipart carries no blobId of its own, per section 4.1.4",
        props.bodyStructure.blobId === null, JSON.stringify(props.bodyStructure.blobId));
  check("the prefix scopes the blobIds to the message",
        leaves.every(function (p) { return p.blobId.indexOf("obj_1") === 0; }),
        JSON.stringify(leaves.map(function (p) { return p.blobId; })));
}

function testAMessageWithNoFilesSaysSo() {
  var props = _build(PLAIN);
  check("hasAttachment is false and attachments is empty",
        props.hasAttachment === false && props.attachments.length === 0);
  check("a single-part message still reports its text body",
        props.textBody.length === 1 && props.textBody[0].type === "text/plain",
        JSON.stringify(props.textBody));
  check("the root of a single-part message is fetchable",
        typeof props.bodyStructure.blobId === "string" &&
        JMAP_ID_RE.test(props.bodyStructure.blobId),
        String(props.bodyStructure.blobId));
}

function testTheBuilderRefusesInputItCannotIdentify() {
  var threw = null;
  try { b.mail.server.jmap.emailBodyProperties(b.safeMime.parse(Buffer.from(PLAIN, "utf8")), {}); }
  catch (e) { threw = e; }
  check("a missing blobIdPrefix is refused, because a blobId without one is not unique",
        threw !== null, threw && threw.code);
  var threwId = null;
  try {
    b.mail.server.jmap.emailBodyProperties(b.safeMime.parse(Buffer.from(PLAIN, "utf8")),
      { blobIdPrefix: "not a jmap id!" });
  } catch (e) { threwId = e; }
  check("a prefix that is not a JMAP Id is refused, rather than emitting an unfetchable blobId",
        threwId !== null, threwId && threwId.code);
}

async function run() {
  testTheShapeIsTheOneTheRfcDefines();
  testEveryPartCanBeFetched();
  testAMessageWithNoFilesSaysSo();
  testTheBuilderRefusesInputItCannotIdentify();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[mail-server-jmap-body-parts] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
