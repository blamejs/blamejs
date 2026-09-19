// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * `b.safeMime.parse` can walk a message's structure without decoding its
 * bodies, and `b.mailStore` records what it learned at append.
 *
 * Every option `parse` took was a cap, so a consumer that wanted only the
 * SHAPE of a message, whether it carries a file and how many, had to decode
 * all of its content to find out. Measured by a consumer against a real store
 * at a page size of 50: listing alone 153 ms, reading the octets 1385 ms, and
 * reading plus parsing 7526 ms for 2 MB messages, of which about 6100 ms is
 * the decoding. The parse already happens at append, which is where the
 * answer is free, and it was thrown away.
 *
 * Both halves are needed and neither is sufficient. Reading the octets alone
 * costs about 5.5 ms per message whatever its size, so a structure-only mode
 * does not make per-render derivation viable; it makes the append-time parse
 * cheap enough that the answer can be recorded once and read from the row.
 */

var helpers  = require("../helpers");
var check    = helpers.check;
var b        = helpers.b;
var nodeFs   = require("node:fs");
var nodeOs   = require("node:os");
var nodePath = require("node:path");

function _message(attachmentCount) {
  var lines = [
    "From: a@example.com",
    "To: b@example.net",
    "Subject: shape",
    "MIME-Version: 1.0",
    'Content-Type: multipart/mixed; boundary="outer"',
    "",
    "--outer",
    "Content-Type: text/plain; charset=utf-8",
    "",
    "hello",
  ];
  for (var i = 0; i < attachmentCount; i += 1) {
    lines.push("--outer");
    lines.push("Content-Type: application/pdf");
    lines.push('Content-Disposition: attachment; filename="f' + i + '.pdf"');
    lines.push("Content-Transfer-Encoding: base64");
    lines.push("");
    lines.push(Buffer.from("PDF-" + i).toString("base64"));
  }
  lines.push("--outer--");
  lines.push("");
  return Buffer.from(lines.join("\r\n"), "utf8");
}

function testStructureOnlyWalksWithoutDecoding() {
  var raw = _message(2);
  var full = b.safeMime.parse(raw);
  var shape = b.safeMime.parse(raw, { structureOnly: true });

  function leaves(tree) {
    var out = [];
    b.safeMime.walk(tree, function (p) { if (p.leaf) out.push(p); });
    return out;
  }
  var fullLeaves  = leaves(full);
  var shapeLeaves = leaves(shape);

  check("the same parts are found either way",
        fullLeaves.length === shapeLeaves.length && shapeLeaves.length === 3,
        fullLeaves.length + " vs " + shapeLeaves.length);
  check("each part keeps its content type and headers",
        shapeLeaves.every(function (p, i) {
          return p.leaf.contentType === fullLeaves[i].leaf.contentType &&
                 p.headers.get("content-type") !== null;
        }),
        JSON.stringify(shapeLeaves.map(function (p) { return p.leaf.contentType; })));
  check("no body is decoded",
        shapeLeaves.every(function (p) { return p.leaf.body === null; }),
        JSON.stringify(shapeLeaves.map(function (p) { return p.leaf.body === null; })));
  check("the encoded size is still reported, so a caller can bound what it fetches",
        shapeLeaves.every(function (p) { return typeof p.leaf.encodedSize === "number" && p.leaf.encodedSize > 0; }),
        JSON.stringify(shapeLeaves.map(function (p) { return p.leaf.encodedSize; })));
  check("attachments are still identifiable from the shape alone",
        b.safeMime.extractAttachments(shape).length === 2,
        String(b.safeMime.extractAttachments(shape).length));
}

function testStructureOnlyStillRefusesHostileShapes() {
  // The caps are the reason this parser exists; a cheaper mode must not be a
  // way around them.
  // Genuinely nested: each level's single part IS the next multipart. A
  // message that repeats one boundary is 40 siblings, not 40 levels, and
  // would prove nothing about the depth cap.
  function nest(level, depth) {
    var boundary = "b" + level;
    var inner = level === depth
      ? "Content-Type: text/plain\r\n\r\nleaf\r\n"
      : "Content-Type: multipart/mixed; boundary=b" + (level + 1) + "\r\n\r\n" +
        nest(level + 1, depth);
    return "--" + boundary + "\r\n" + inner + "\r\n--" + boundary + "--\r\n";
  }
  var deep = "Content-Type: multipart/mixed; boundary=b0\r\n\r\n" + nest(0, 12);
  var deepBuf = Buffer.from(deep, "utf8");

  // The premise: this fixture really does exceed the cap, in the mode that
  // was already enforcing it.
  var threwFull = null;
  try { b.safeMime.parse(deepBuf, { maxNestingDepth: 4 }); } catch (e) { threwFull = e; }
  check("the fixture is deep enough to trip the cap in the ordinary mode",
        threwFull !== null && /nesting/.test((threwFull && threwFull.code) || ""),
        threwFull && threwFull.code);

  var threw = null;
  try { b.safeMime.parse(deepBuf, { structureOnly: true, maxNestingDepth: 4 }); }
  catch (e) { threw = e; }
  check("the nesting cap still applies in structure-only mode",
        threw !== null && /nesting/.test((threw && threw.code) || ""),
        threw && threw.code);

  var threwEnc = null;
  try {
    b.safeMime.parse(Buffer.from(
      "Content-Type: text/plain\r\nContent-Transfer-Encoding: x-nope\r\n\r\nhi\r\n", "utf8"),
      { structureOnly: true });
  } catch (e) { threwEnc = e; }
  check("an unknown transfer encoding is still refused",
        threwEnc !== null && /transfer-encoding/.test((threwEnc && threwEnc.code) || ""),
        threwEnc && threwEnc.code);
}

async function testTheStoreRecordsTheShapeAtAppend() {
  var dataDir = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), "mailstore-shape-"));
  if (typeof b.vault._resetForTest === "function") b.vault._resetForTest();
  b.cryptoField.clearForTest();
  await b.vault.init({ dataDir: dataDir, mode: "plaintext" });
  var db = new (require("node:sqlite").DatabaseSync)(nodePath.join(dataDir, "store.db"));
  try {
    var store = b.mailStore.create({ backend: db });
    var withFiles = store.appendMessage("INBOX", _message(2));
    var without   = store.appendMessage("INBOX", _message(0));

    var a = store.fetchByObjectId("INBOX", withFiles.objectid);
    var c = store.fetchByObjectId("INBOX", without.objectid);
    check("a message carrying files records that it does",
          a.hasAttachment === true && a.attachmentCount === 2,
          JSON.stringify([a.hasAttachment, a.attachmentCount]));
    check("a message carrying none records that too",
          c.hasAttachment === false && c.attachmentCount === 0,
          JSON.stringify([c.hasAttachment, c.attachmentCount]));

    var rows = store.queryByModseq("INBOX", { sinceModseq: 0 });
    var listed = rows.filter(function (r) { return r.objectid === withFiles.objectid; })[0];
    check("the listing projection carries it, so a mailbox page needs no second read",
          listed !== undefined && listed.hasAttachment === true &&
          listed.attachmentCount === 2,
          JSON.stringify(listed));
  } finally {
    try { db.close(); } catch (_e) { /* best-effort */ }
    if (typeof b.vault._resetForTest === "function") b.vault._resetForTest();
    b.cryptoField.clearForTest();
    try { nodeFs.rmSync(dataDir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  }
}

async function run() {
  testStructureOnlyWalksWithoutDecoding();
  testStructureOnlyStillRefusesHostileShapes();
  await testTheStoreRecordsTheShapeAtAppend();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[safe-mime-structure-only] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
