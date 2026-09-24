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

var helpers  = require("../helpers");
var check    = helpers.check;
var b        = helpers.b;
var nodeFs   = require("node:fs");
var nodeOs   = require("node:os");
var nodePath = require("node:path");

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

function testOneAlternativeRepresentationIsChosen() {
  // The parts of a multipart/alternative are one body written several ways,
  // not consecutive sections of one body. Collecting every descendant put
  // both text/plain representations in textBody, and a client rendering the
  // list in order showed the message twice, with whichever wording the
  // sender meant to supersede. RFC 8621 4.1.4 has the display lists carry
  // one representation.
  var raw = [
    "From: a@example.com", "To: b@example.net", "Subject: two spellings",
    "MIME-Version: 1.0",
    'Content-Type: multipart/alternative; boundary="alt"', "",
    "--alt", "Content-Type: text/plain; charset=utf-8", "", "plain one",
    "--alt", "Content-Type: text/plain; charset=utf-8", "", "plain two",
    "--alt", "Content-Type: text/html; charset=utf-8", "", "<p>one</p>",
    "--alt", "Content-Type: text/html; charset=utf-8", "", "<p>two</p>",
    "--alt--", "",
  ].join("\r\n");
  var props = _build(raw);
  check("textBody carries one of the plain representations",
        props.textBody.length === 1,
        JSON.stringify(props.textBody.map(function (p) { return p.partId; })));
  check("and htmlBody one of the HTML ones",
        props.htmlBody.length === 1,
        JSON.stringify(props.htmlBody.map(function (p) { return p.partId; })));
  // RFC 2046 5.1.4 orders the alternatives from simplest to richest, so the
  // last representation of each type is the one a reader displays.
  check("the last of each is the one chosen",
        props.textBody[0] && props.htmlBody[0] &&
        props.textBody[0].partId === props.bodyStructure.subParts[1].partId &&
        props.htmlBody[0].partId === props.bodyStructure.subParts[3].partId,
        JSON.stringify([props.textBody[0] && props.textBody[0].partId,
                        props.htmlBody[0] && props.htmlBody[0].partId]));
  check("and a representation that was not chosen is not served as a file",
        props.attachments.length === 0 && props.hasAttachment === false,
        JSON.stringify(props.attachments.map(function (p) { return p.partId; })));
  // Every representation is still reachable through the structure, which is
  // where a client goes to render a different one.
  check("while all four are still in bodyStructure",
        props.bodyStructure.subParts.length === 4,
        String(props.bodyStructure.subParts.length));
}

function testARepresentationWrappedInAMultipartIsStillOneChoice() {
  // The usual shape of an HTML mail with inline images: a plain text/html
  // representation, and a multipart/related carrying the same body with its
  // images as the richer one after it. Choosing by the immediate child's own
  // media type saw the multipart as neither, so it took the plain HTML and
  // then the related's HTML as well, and the client showed both.
  var raw = [
    "From: a@example.com", "To: b@example.net", "Subject: html then related",
    "MIME-Version: 1.0",
    'Content-Type: multipart/alternative; boundary="alt"', "",
    "--alt", "Content-Type: text/html; charset=utf-8", "", "<p>plain html</p>",
    "--alt", 'Content-Type: multipart/related; boundary="rel"', "",
    "--rel", "Content-Type: text/html; charset=utf-8", "", "<p>with image</p>",
    "--rel", "Content-Type: image/png",
    'Content-Disposition: inline; filename="logo.png"', "", "PNGBYTES",
    "--rel--",
    "--alt--", "",
  ].join("\r\n");
  var props = _build(raw);
  check("only one HTML representation is displayed",
        props.htmlBody.length === 1,
        JSON.stringify(props.htmlBody.map(function (p) { return p.partId; })));
  check("and it is the one inside the related part, which RFC 2046 5.1.4 prefers",
        props.htmlBody[0] &&
        props.htmlBody[0].partId === props.bodyStructure.subParts[1].subParts[0].partId,
        JSON.stringify(props.htmlBody[0] && props.htmlBody[0].partId));
  check("the inline image of the chosen representation is still offered",
        props.attachments.length === 1 && props.hasAttachment === true,
        JSON.stringify(props.attachments.map(function (p) { return p.name; })));
}

function testConsecutiveSectionsOfOneRepresentationAreAllKept() {
  // The counterpart: a multipart/mixed is sections of one body, so nothing
  // is dropped there, including a mixed part standing as one alternative.
  var raw = [
    "From: a@example.com", "To: b@example.net", "Subject: sections",
    "MIME-Version: 1.0",
    'Content-Type: multipart/alternative; boundary="alt"', "",
    "--alt", 'Content-Type: multipart/mixed; boundary="mix"', "",
    "--mix", "Content-Type: text/plain; charset=utf-8", "", "first section",
    "--mix", "Content-Type: text/plain; charset=utf-8", "", "second section",
    "--mix--",
    "--alt", "Content-Type: text/html; charset=utf-8", "", "<p>one</p>",
    "--alt--", "",
  ].join("\r\n");
  var props = _build(raw);
  check("both sections of the mixed representation are kept",
        props.textBody.length === 2,
        JSON.stringify(props.textBody.map(function (p) { return p.partId; })));
  check("and the HTML representation is there too",
        props.htmlBody.length === 1,
        JSON.stringify(props.htmlBody.map(function (p) { return p.partId; })));
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

function testEveryGeneratedBlobIdFitsTheDownloadHandlersLimit() {
  // The prefix is bounded at the JMAP Id length, but a part's path is
  // appended to it, so a prefix at the limit produced a 257-character id for
  // the first child: advertised by the builder and refused by the download
  // handler in the same module.
  var longPrefix = "p".repeat(255);
  var threw = null;
  try { _build(MESSAGE, { blobIdPrefix: longPrefix }); } catch (e) { threw = e; }
  check("a prefix that cannot carry a part suffix is refused up front",
        threw !== null, threw && threw.code);

  // At a prefix that does leave room, every generated id still fits.
  var props = _build(MESSAGE, { blobIdPrefix: "p".repeat(200) });
  var tooLong = [];
  (function walk(node) {
    if (typeof node.blobId === "string" && !JMAP_ID_RE.test(node.blobId)) {
      tooLong.push(node.blobId.length);
    }
    (node.subParts || []).forEach(walk);
  })(props.bodyStructure);
  check("every generated blobId satisfies the grammar, suffix included" +
        (tooLong.length ? " (lengths " + tooLong.join(", ") + ")" : ""),
        tooLong.length === 0);
}

function testACopyMethodsOwnAccountArgumentsAreAccepted() {
  // RFC 8620 section 5.4 gives /copy `fromAccountId` for the source and
  // `accountId` for the destination, so a conforming copy does name an
  // accountId and the mandatory-account check does not stand in its way.
  // Pinned because a reviewer read the destination as `toAccountId`, which
  // RFC 8620 does not define, and a silent change here would break copies.
  // The section's argument list is `fromAccountId` ("The id of the account to
  // copy records from"), `ifFromInState`, `accountId` ("The id of the account
  // to copy records to"), `ifInState`, `create`, `onSuccessDestroyOriginal`
  // and `destroyFromIfInState`. There is no `toAccountId` in it.
  var seen = [];
  var jmap = b.mail.server.jmap.create({
    mailStore:   { appendMessage: function () {} },
    accountsFor: async function () {
      return { primaryAccounts: { mail: "A1" }, accounts: { A1: {}, A2: {} } };
    },
    methods: {
      "Email/copy": async function (actor, args) { seen.push(args); return { accountId: args.accountId }; },
    },
  });
  return jmap.dispatch({ id: "actor1" }, {
    using:       ["urn:ietf:params:jmap:core"],
    methodCalls: [["Email/copy", { fromAccountId: "A1", accountId: "A2", create: {} }, "c0"]],
  }).then(function (rv) {
    check("a conforming Email/copy reaches its handler",
          rv.methodResponses[0][0] === "Email/copy" && seen.length === 1,
          JSON.stringify(rv.methodResponses[0]));
    return jmap.dispatch({ id: "actor1" }, {
      using:       ["urn:ietf:params:jmap:core"],
      methodCalls: [["Email/copy", { fromAccountId: "A1", toAccountId: "A2", create: {} }, "c1"]],
    });
  }).then(function (rv) {
    // `toAccountId` is not an argument RFC 8620 defines, so a copy spelled
    // that way names no destination and is refused rather than copying into
    // an account the request never identified.
    check("a copy naming toAccountId instead is refused",
          rv.methodResponses[0][0] === "error" &&
          rv.methodResponses[0][1].type === "invalidArguments",
          JSON.stringify(rv.methodResponses[0]));
    check("and its handler did not run", seen.length === 1, String(seen.length));
  });
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

// Three readers answer one question, "which leaves are files", and an operator
// is shown all three: `b.safeMime.extractAttachments` in a handler,
// `emailBodyProperties` in `Email/get`, and the `attachmentCount` the store
// recorded at append. Each time they were left to answer separately they
// drifted, and the drift is invisible from any one of them: a mailbox listing
// says a message carries nothing while the download endpoint serves the bytes.
// They are compared against each other over generated messages rather than
// each being spot-checked on a shape someone thought of.
async function testTheThreeReadersAgreeAcrossGeneratedMessages() {
  var TYPES = ["application/pdf", "image/png", "image/svg+xml", "video/mp4",
               "audio/mpeg", "text/calendar", "application/octet-stream"];
  var DISPOSITIONS = [null, "inline", "attachment"];
  var SHAPES = ["alt-related", "alt-mixed", "mixed", "related", "alt-nested"];

  var seed = 424242;
  function rnd() { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed / 0x7fffffff; }
  function choose(list) { return list[Math.floor(rnd() * list.length) % list.length]; }

  function build(n) {
    var type = choose(TYPES);
    var disposition = choose(DISPOSITIONS);
    var shape = choose(SHAPES);
    var named = rnd() < 0.5;
    var cid = rnd() < 0.5;
    var payload = ["Content-Type: " + type + (named ? '; name="f' + n + '"' : "")];
    if (cid) payload.push("Content-ID: <c" + n + "@example.com>");
    if (disposition) {
      payload.push("Content-Disposition: " + disposition +
        (named ? '; filename="f' + n + '"' : ""));
    }
    payload.push("", "PAYLOADBYTES" + n);

    var body;
    if (shape === "mixed") {
      body = ['Content-Type: multipart/mixed; boundary="m"', "",
        "--m", "Content-Type: text/plain", "", "plain body",
        "--m"].concat(payload).concat(["--m--", ""]);
    } else if (shape === "related") {
      body = ['Content-Type: multipart/related; boundary="r"', "",
        "--r", "Content-Type: text/html", "", "<p>body</p>",
        "--r"].concat(payload).concat(["--r--", ""]);
    } else if (shape === "alt-nested") {
      body = ['Content-Type: multipart/alternative; boundary="alt"', "",
        "--alt", "Content-Type: text/plain", "", "plain",
        "--alt", 'Content-Type: multipart/alternative; boundary="in"', "",
        "--in", "Content-Type: text/html", "", "<p>inner</p>",
        "--in"].concat(payload).concat(["--in--", "--alt--", ""]);
    } else {
      var wrapper = shape === "alt-related" ? "related" : "mixed";
      body = ['Content-Type: multipart/alternative; boundary="alt"', "",
        "--alt", 'Content-Type: multipart/' + wrapper + '; boundary="w"', "",
        "--w", "Content-Type: text/html", "", "<p>superseded</p>",
        "--w"].concat(payload).concat(["--w--",
        "--alt", "Content-Type: text/html", "", "<p>preferred</p>",
        "--alt--", ""]);
    }
    return {
      raw: ["From: a@example.com", "To: b@example.net", "Subject: s" + n,
            "MIME-Version: 1.0"].concat(body).join("\r\n"),
      shape: shape, type: type, disposition: disposition, named: named, cid: cid,
    };
  }

  var dataDir = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), "three-readers-"));
  var db = null;
  try {
    if (typeof b.vault._resetForTest === "function") b.vault._resetForTest();
    b.cryptoField.clearForTest();
    await b.vault.init({ dataDir: dataDir, mode: "plaintext" });
    db = new (require("node:sqlite").DatabaseSync)(nodePath.join(dataDir, "store.db"));
    var store = b.mailStore.create({
      backend: { prepare: function (t) { return db.prepare(t); } },
    });

    var disagreements = [];
    var orphans = [];
    var TOTAL = 300;
    for (var i = 0; i < TOTAL; i += 1) {
      var m = build(i);
      var buf = Buffer.from(m.raw, "utf8");
      var tree;
      try { tree = b.safeMime.parse(buf); } catch (_e) { continue; }

      var fromMime = b.safeMime.extractAttachments(tree).length;
      var props = b.mail.server.jmap.emailBodyProperties(tree, { blobIdPrefix: "t" + i });
      var fromJmap = props.attachments.length;
      var meta = store.appendMessage("INBOX", buf);
      var fromStore = store.fetchByObjectId("INBOX", meta.objectid).attachmentCount;

      if (!(fromMime === fromJmap && fromJmap === fromStore)) {
        disagreements.push(m.shape + " " + m.type + " disposition=" + m.disposition +
          " named=" + m.named + " cid=" + m.cid +
          "  mime=" + fromMime + " jmap=" + fromJmap + " store=" + fromStore);
      }

      var leaves = [];
      (function walk(node) {
        if (!node) return;
        if (!node.subParts || node.subParts.length === 0) { leaves.push(node); return; }
        node.subParts.forEach(walk);
      })(props.bodyStructure);
      var accounted = Object.create(null);
      props.attachments.concat(props.textBody || [], props.htmlBody || [])
        .forEach(function (x) { accounted[x.partId] = true; });
      leaves.forEach(function (node) {
        var leafType = String(node.type || "").toLowerCase();
        if (node.blobId && !accounted[node.partId] &&
            leafType !== "text/plain" && leafType !== "text/html") {
          orphans.push(m.shape + " " + leafType + " disposition=" + m.disposition +
            " cid=" + m.cid);
        }
      });
    }

    check("the three readers agree on how many files every generated message carries",
          disagreements.length === 0, disagreements.slice(0, 3).join(" | "));
    check("and no leaf the structure hands a blobId for is missing from every list",
          orphans.length === 0, orphans.slice(0, 3).join(" | "));
  } finally {
    try { if (db) db.close(); } catch (_e) { /* best-effort */ }
    try { nodeFs.rmSync(dataDir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  }
}

// RFC 8621 section 4.1.4 defines htmlBody as "A list of 'text/plain',
// 'text/html', 'image/*', 'audio/*', and/or 'video/*' parts to display
// (sequentially) as the message body, with a preference for 'text/html' when
// alternative versions are available", and textBody the mirror of it. Naming
// text/plain as a member of htmlBody is only meaningful when a plain part
// lands there because no HTML alternative exists. Sorting each leaf into one
// list by its own media type answered `htmlBody: []` for a plain-text message,
// which is the commonest shape there is, and a client that asks for htmlBody
// with fetchHTMLBodyValues, the request RFC 8621 section 4.2.1 prints as its
// own example, then renders nothing at all.
function testAMultipartNeverCarriesAPartIdOrABlobId() {
  // RFC 8621 section 4.1.4 is an "if and only if": `partId` and `blobId` are
  // null exactly when the part is `multipart/*`. The builder decided leaf-ness
  // by child count instead, and a multipart whose own boundary never appears in
  // its body parses to no children at all, so it was handed a `partId` and a
  // fetchable `blobId` while reporting `type: "multipart/mixed"`. The sender
  // writes that shape with one mistyped or unterminated inner boundary, and a
  // truncated message produces it too.
  //
  // The same node then reached none of textBody, htmlBody or attachments,
  // because the selection walks children and stops at a node that has neither
  // children nor a leaf: a part `bodyStructure` advertised for download that no
  // list named.
  var tree = b.safeMime.parse(Buffer.from([
    "From: a@example.com", "Subject: s", "MIME-Version: 1.0",
    'Content-Type: multipart/mixed; boundary="OUT"', "",
    "--OUT", "Content-Type: text/plain", "", "the body",
    "--OUT", 'Content-Type: multipart/mixed; boundary="INNER"', "",
    "nothing here delimits INNER",
    "--OUT--", "",
  ].join("\r\n"), "utf8"));

  var view = b.mail.server.jmap.emailBodyProperties(tree, { blobIdPrefix: "bl" });
  var offenders = [];
  (function walk(node) {
    if (/^multipart\//.test(node.type) &&
        (node.partId !== null || node.blobId !== null)) {
      offenders.push(node.type + " partId=" + node.partId + " blobId=" + node.blobId);
    }
    (node.subParts || []).forEach(walk);
  })(view.bodyStructure);
  check("no multipart part carries a partId or a blobId" +
        (offenders.length ? " (" + offenders.join("; ") + ")" : ""),
        offenders.length === 0);

  // And nothing bodyStructure hands a blobId for is left out of every list,
  // which is the invariant the generated cross-check already asserts.
  var listed = Object.create(null);
  ["textBody", "htmlBody", "attachments"].forEach(function (k) {
    view[k].forEach(function (p) { if (p.blobId) listed[p.blobId] = true; });
  });
  var orphans = [];
  (function walk(node) {
    if (node.blobId && listed[node.blobId] !== true) {
      orphans.push(node.type + ":" + node.blobId);
    }
    (node.subParts || []).forEach(walk);
  })(view.bodyStructure);
  check("every downloadable part is named by one of the lists" +
        (orphans.length ? " (" + orphans.join("; ") + ")" : ""),
        orphans.length === 0);
}

function testABodyPartReportsSubPartsAndLanguageAsDefined() {
  // RFC 8621 section 4.1.4 types `subParts` as `EmailBodyPart[]|null` and
  // gives it a meaning only for a multipart: "If the type is multipart/*, this
  // contains the body parts of each child", and the section adds that "None of
  // these parts include subParts, including message/* types". Every leaf
  // carried an empty array instead, which reads as a multipart with no
  // children rather than as a part that cannot have any.
  //
  // `language` is `String[]|null`, "The list of language tags, as defined in
  // RFC 3282, in the Content-Language header field of the part, if present",
  // and was reported null whatever the part carried, so a client choosing a
  // rendering by declared language had nothing to choose from.
  var tree = b.safeMime.parse(Buffer.from([
    "From: a@example.com", "Subject: s", "MIME-Version: 1.0",
    'Content-Type: multipart/mixed; boundary="m"', "",
    "--m", "Content-Type: text/plain", "Content-Language: en", "", "hello",
    "--m", "Content-Type: text/html", "Content-Language: en-GB, fr", "",
    "<p>hello</p>",
    "--m", "Content-Type: application/pdf",
    'Content-Disposition: attachment; filename="r.pdf"', "", "PDF",
    "--m--", "",
  ].join("\r\n"), "utf8"));
  var view = b.mail.server.jmap.emailBodyProperties(tree, { blobIdPrefix: "bl" });

  var wrongSubParts = [];
  (function walk(node) {
    var isMultipart = /^multipart\//.test(node.type);
    if (isMultipart && !Array.isArray(node.subParts)) {
      wrongSubParts.push(node.type + " subParts=" + JSON.stringify(node.subParts));
    }
    if (!isMultipart && node.subParts !== null) {
      wrongSubParts.push(node.type + " subParts=" + JSON.stringify(node.subParts));
    }
    (node.subParts || []).forEach(walk);
  })(view.bodyStructure);
  check("subParts is an array for a multipart and null for everything else" +
        (wrongSubParts.length ? " (" + wrongSubParts.join("; ") + ")" : ""),
        wrongSubParts.length === 0);

  var byType = Object.create(null);
  (function walk(node) {
    byType[node.type] = node;
    (node.subParts || []).forEach(walk);
  })(view.bodyStructure);
  check("a single language tag is a one-element list",
        JSON.stringify(byType["text/plain"].language) === JSON.stringify(["en"]),
        JSON.stringify(byType["text/plain"].language));
  check("and several are split on the comma and trimmed",
        JSON.stringify(byType["text/html"].language) === JSON.stringify(["en-GB", "fr"]),
        JSON.stringify(byType["text/html"].language));
  check("a part with no Content-Language reports null",
        byType["application/pdf"].language === null,
        JSON.stringify(byType["application/pdf"].language));
}

function testAStructureOnlyTreeIsRefusedRatherThanSizedAtZero() {
  // `parse(bytes, { structureOnly: true })` keeps the shape and drops the
  // bodies, so every leaf's body is null. RFC 8621 section 4.1.4 defines
  // `size` as "The size, in octets, of the raw data after content transfer
  // decoding", and a tree with no bodies cannot answer it: every attachment
  // came back advertised at `size: 0` while `bodyStructure` offered its
  // blobId, so a client sized a download it could then fetch.
  //
  // `b.safeMime.extractText` already refuses such a tree with
  // `safe-mime/structure-only` rather than answering emptily. Two readers,
  // one question: this one refuses too.
  var raw = [
    "From: a@example.com", "Subject: s", "MIME-Version: 1.0",
    'Content-Type: multipart/mixed; boundary="m"', "",
    "--m", "Content-Type: text/plain", "", "hello",
    "--m", "Content-Type: application/pdf",
    'Content-Disposition: attachment; filename="r.pdf"', "", "%PDF-1",
    "--m--", "",
  ].join("\r\n");

  var whole = b.safeMime.parse(Buffer.from(raw, "utf8"));
  var sized = b.mail.server.jmap.emailBodyProperties(whole, { blobIdPrefix: "bl" });
  check("a fully parsed tree sizes its attachment",
        sized.attachments.length === 1 && sized.attachments[0].size === 6,
        JSON.stringify(sized.attachments.map(function (a) { return a.size; })));

  var shape = b.safeMime.parse(Buffer.from(raw, "utf8"), { structureOnly: true });
  var refused = null;
  try { b.mail.server.jmap.emailBodyProperties(shape, { blobIdPrefix: "bl" }); }
  catch (e) { refused = e; }
  check("a structure-only tree is refused rather than sized at zero",
        refused !== null && refused.code === "safe-mime/structure-only",
        JSON.stringify(refused && (refused.code || refused.message)));
}

function testABodyWithNoAlternativeFillsBothLists() {
  function lists(raw) {
    var p = b.mail.server.jmap.emailBodyProperties(
      b.safeMime.parse(Buffer.from(raw, "utf8")), { blobIdPrefix: "bl" });
    return {
      text: p.textBody.map(function (x) { return x.type; }),
      html: p.htmlBody.map(function (x) { return x.type; }),
    };
  }

  var plainOnly = lists(["From: a@example.com", "Subject: s", "MIME-Version: 1.0",
    "Content-Type: text/plain; charset=utf-8", "", "Hello"].join("\r\n"));
  check("a plain-text message offers its body to an HTML client too",
        plainOnly.html.length === 1 && plainOnly.html[0] === "text/plain",
        JSON.stringify(plainOnly));

  var htmlOnly = lists(["From: a@example.com", "Subject: s", "MIME-Version: 1.0",
    "Content-Type: text/html; charset=utf-8", "", "<p>Hello</p>"].join("\r\n"));
  check("and an HTML-only message offers its body to a plain client",
        htmlOnly.text.length === 1 && htmlOnly.text[0] === "text/html",
        JSON.stringify(htmlOnly));

  // An alternative carrying one representation is the same question one level
  // down: the RFC copies whichever list it filled into the other.
  var altPlainOnly = lists(["From: a@example.com", "Subject: s", "MIME-Version: 1.0",
    'Content-Type: multipart/alternative; boundary="a"', "",
    "--a", "Content-Type: text/plain", "", "t", "--a--", ""].join("\r\n"));
  check("an alternative with only a plain representation fills both lists",
        altPlainOnly.html.length === 1 && altPlainOnly.html[0] === "text/plain",
        JSON.stringify(altPlainOnly));

  // When both representations are there the preference is real and the lists
  // differ, which is the case the copy must NOT touch.
  var both = lists(["From: a@example.com", "Subject: s", "MIME-Version: 1.0",
    'Content-Type: multipart/alternative; boundary="a"', "",
    "--a", "Content-Type: text/plain", "", "t",
    "--a", "Content-Type: text/html", "", "<p>h</p>", "--a--", ""].join("\r\n"));
  check("an alternative with both keeps each list to its own representation",
        both.text.length === 1 && both.text[0] === "text/plain" &&
        both.html.length === 1 && both.html[0] === "text/html",
        JSON.stringify(both));

  // The question is per branch, not per message. RFC 8621 section 4.1.4 puts a
  // displayed part that is NOT one of several representations into both lists,
  // and reserves the one-list-each rule for the alternatives themselves. A
  // whole-message test asked only whether either list was empty, so a mixed
  // carrying a plain introduction and then an alternative left both lists
  // non-empty and the introduction never reached htmlBody: an HTML client
  // rendered the message without the paragraph that opens it.
  function paths(raw) {
    var p = b.mail.server.jmap.emailBodyProperties(
      b.safeMime.parse(Buffer.from(raw, "utf8")), { blobIdPrefix: "bl" });
    return {
      text: p.textBody.map(function (x) { return x.partId; }),
      html: p.htmlBody.map(function (x) { return x.partId; }),
    };
  }

  var introThenAlternative = paths([
    "From: a@example.com", "Subject: s", "MIME-Version: 1.0",
    'Content-Type: multipart/mixed; boundary="m"', "",
    "--m", "Content-Type: text/plain", "", "the introduction",
    "--m", 'Content-Type: multipart/alternative; boundary="a"', "",
    "--a", "Content-Type: text/plain", "", "the body",
    "--a", "Content-Type: text/html", "", "<p>the body</p>",
    "--a--",
    "--m--", "",
  ].join("\r\n"));
  check("a section outside an alternative reaches both lists",
        JSON.stringify(introThenAlternative.text) === JSON.stringify(["1", "2.1"]) &&
        JSON.stringify(introThenAlternative.html) === JSON.stringify(["1", "2.2"]),
        JSON.stringify(introThenAlternative));

  // The same message the other way round: the alternative first, then a
  // closing plain section.
  var alternativeThenOutro = paths([
    "From: a@example.com", "Subject: s", "MIME-Version: 1.0",
    'Content-Type: multipart/mixed; boundary="m"', "",
    "--m", 'Content-Type: multipart/alternative; boundary="a"', "",
    "--a", "Content-Type: text/plain", "", "the body",
    "--a", "Content-Type: text/html", "", "<p>the body</p>",
    "--a--",
    "--m", "Content-Type: text/plain", "", "the footer",
    "--m--", "",
  ].join("\r\n"));
  check("and a section after one does too, in document order",
        JSON.stringify(alternativeThenOutro.text) === JSON.stringify(["1.1", "2"]) &&
        JSON.stringify(alternativeThenOutro.html) === JSON.stringify(["1.2", "2"]),
        JSON.stringify(alternativeThenOutro));

  // An HTML section outside an alternative is the mirror of the first case.
  var htmlIntro = paths([
    "From: a@example.com", "Subject: s", "MIME-Version: 1.0",
    'Content-Type: multipart/mixed; boundary="m"', "",
    "--m", "Content-Type: text/html", "", "<p>the introduction</p>",
    "--m", 'Content-Type: multipart/alternative; boundary="a"', "",
    "--a", "Content-Type: text/plain", "", "the body",
    "--a", "Content-Type: text/html", "", "<p>the body</p>",
    "--a--",
    "--m--", "",
  ].join("\r\n"));
  check("an HTML section outside an alternative reaches both lists too",
        JSON.stringify(htmlIntro.text) === JSON.stringify(["1", "2.1"]) &&
        JSON.stringify(htmlIntro.html) === JSON.stringify(["1", "2.2"]),
        JSON.stringify(htmlIntro));
}

async function run() {
  testAMultipartNeverCarriesAPartIdOrABlobId();
  testABodyPartReportsSubPartsAndLanguageAsDefined();
  testAStructureOnlyTreeIsRefusedRatherThanSizedAtZero();
  testABodyWithNoAlternativeFillsBothLists();
  await testTheThreeReadersAgreeAcrossGeneratedMessages();
  testTheShapeIsTheOneTheRfcDefines();
  testOneAlternativeRepresentationIsChosen();
  testARepresentationWrappedInAMultipartIsStillOneChoice();
  testConsecutiveSectionsOfOneRepresentationAreAllKept();
  testEveryPartCanBeFetched();
  testAMessageWithNoFilesSaysSo();
  testEveryGeneratedBlobIdFitsTheDownloadHandlersLimit();
  await testACopyMethodsOwnAccountArgumentsAreAccepted();
  testTheBuilderRefusesInputItCannotIdentify();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[mail-server-jmap-body-parts] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
