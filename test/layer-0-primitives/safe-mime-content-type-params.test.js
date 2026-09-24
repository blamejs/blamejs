// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A parsed leaf says what its `Content-Type` header actually carried.
 *
 * `parse` read the header's parameters, used them, and then dropped them: the
 * only survivor was `charset`, with `us-ascii` written in whenever the sender
 * had written nothing (RFC 2045 section 5.2). A caller could therefore not
 * tell a message that says `charset=us-ascii` from one that says nothing,
 * which is the distinction RFC 8621 section 4.1.4 asks for when it defines
 * the `charset` property of an `EmailBodyPart` as the value of the parameter:
 * a JMAP client reads an absent property differently from a present one.
 *
 * Everything else the header carried was gone with it. `format=flowed` and
 * `delsp` (RFC 3676) decide how a text part is rendered, and a caller
 * rendering a body had no way to read either.
 *
 * The parameters are now on the leaf as `contentTypeParams`, beside the
 * defaulted `charset`, so the defaulting is no longer the only thing a caller
 * can see and the header is still read exactly once. The alternative, letting
 * each consumer parse the header again, is the shape that drifts: this
 * framework's own JMAP body-part builder had started down it.
 */

var helpers = require("../helpers");
var check   = helpers.check;
var b       = helpers.b;

function _parse(headerLines, body) {
  return b.safeMime.parse(Buffer.from(
    ["From: a@example.com", "To: b@example.net", "Subject: s"]
      .concat(headerLines).concat(["", body || "hi", ""]).join("\r\n"), "utf8"));
}

function testAWrittenCharsetIsDistinguishableFromADefaultedOne() {
  var written = _parse(["Content-Type: text/plain; charset=us-ascii"]);
  var absent  = _parse(["Content-Type: text/plain"]);

  check("both leaves still carry the effective charset",
        written.leaf.charset === "us-ascii" && absent.leaf.charset === "us-ascii",
        JSON.stringify([written.leaf.charset, absent.leaf.charset]));
  check("the written one is reported as written",
        written.leaf.contentTypeParams.charset === "us-ascii",
        JSON.stringify(written.leaf.contentTypeParams));
  check("and the absent one is absent rather than defaulted",
        absent.leaf.contentTypeParams.charset === undefined,
        JSON.stringify(absent.leaf.contentTypeParams));
}

function testEveryParameterTheHeaderCarriedIsReadable() {
  // RFC 3676: a reader that cannot see these renders flowed text wrongly.
  var flowed = _parse(['Content-Type: text/plain; charset=utf-8; format=flowed; delsp=yes']);
  check("format is readable", flowed.leaf.contentTypeParams.format === "flowed",
        JSON.stringify(flowed.leaf.contentTypeParams));
  check("and so is delsp", flowed.leaf.contentTypeParams.delsp === "yes",
        JSON.stringify(flowed.leaf.contentTypeParams));

  // A quoted value is unquoted the same way the rest of the parser unquotes.
  var quoted = _parse(['Content-Type: application/pdf; name="q1 report.pdf"']);
  check("a quoted parameter value is unquoted once",
        quoted.leaf.contentTypeParams.name === "q1 report.pdf",
        JSON.stringify(quoted.leaf.contentTypeParams));
}

function testAQuotedPairInsideAParameterDoesNotEndIt() {
  // RFC 2045 §5.1 takes its quoted-string from RFC 822, where a backslash
  // escapes the character after it, so `note="a\"b"` is one parameter whose
  // value contains a quote. Splitting on quotes alone read that inner quote
  // as the end of the value, so everything after it became part of the same
  // parameter: `charset` was swallowed and the leaf silently fell back to
  // us-ascii, which is a charset the sender never wrote and decodes the body
  // differently. The sender writes this header.
  var part = _parse(['Content-Type: text/plain; note="a\\"b"; charset=utf-8']);
  check("the escaped quote stays inside its own parameter",
        part.leaf.contentTypeParams.note === 'a"b',
        JSON.stringify(part.leaf.contentTypeParams));
  check("and the parameter after it is still read",
        part.leaf.contentTypeParams.charset === "utf-8",
        JSON.stringify(part.leaf.contentTypeParams));
  check("so the leaf carries the charset the sender wrote",
        part.leaf.charset === "utf-8", JSON.stringify(part.leaf.charset));

  // A trailing backslash inside the quotes escapes the closing quote, so the
  // value is unterminated: the reader must not run past the header.
  // `note="a\\"` is an escaped BACKSLASH followed by the closing quote, so
  // the value is terminated and `charset` is a parameter of its own.
  var escapedBackslash = _parse(['Content-Type: text/plain; note="a\\\\"; charset=utf-8']);
  check("an escaped backslash still closes the value",
        escapedBackslash.leaf.contentTypeParams.charset === "utf-8",
        JSON.stringify(escapedBackslash.leaf.contentTypeParams));

  // `note="a\"` is an escaped QUOTE, so the value runs on and there is no
  // closing quote at all: everything after it is inside the value rather than
  // a parameter of its own. Neither reading a charset out of the run nor
  // taking the RFC 2045 default is safe, because the default is the weaker of
  // the two and the sender is the one who chose it by leaving the quote open.
  var dangling = null;
  try { _parse(['Content-Type: text/plain; note="a\\"; charset=utf-8']); }
  catch (e) { dangling = e; }
  check("an escaped quote leaves the value unterminated, and the header is refused",
        dangling !== null && dangling.code === "safe-mime/malformed-content-type",
        dangling ? String(dangling.code) : "parsed");
}

function testAHeaderThatOpensAQuoteAndNeverClosesItIsRefused() {
  // The escape-aware splitter drops a trailing piece it cannot terminate, so
  // a value that is nothing but an unterminated quoted string splits to no
  // pieces at all and the type read from the first one was undefined. A
  // parser in this family answers with its own error for hostile input; a
  // raw TypeError carries no code for a caller to branch on and says the
  // crash was a programming mistake rather than a refusal.
  var raw = ["From: a@example.com", "Subject: s", "MIME-Version: 1.0",
             'Content-Type: "unterminated', "", "hi", ""].join("\r\n");
  var threw = null;
  var tree = null;
  try { tree = b.safeMime.parse(Buffer.from(raw, "utf8")); }
  catch (e) { threw = e; }
  check("an unterminated quoted value does not crash the parser",
        !(threw instanceof TypeError),
        threw ? threw.constructor.name + ": " + threw.message : "parsed");
  check("and the part still reads as a part",
        threw !== null
          ? typeof threw.code === "string" && threw.code.indexOf("safe-mime/") === 0
          : typeof tree.leaf.contentType === "string",
        threw ? String(threw.code) : JSON.stringify(tree.leaf.contentType));

  // The same shape inside a parameter splits to one piece rather than none,
  // so the type read fine and everything after the open quote read as
  // unwritten. That is the shape a sender uses to walk a part past the
  // charset allowlist, so it takes the same refusal as the value-only form.
  var partialThrew = null;
  try {
    b.safeMime.parse(Buffer.from(
      ["From: a@example.com", "Subject: s", "MIME-Version: 1.0",
       'Content-Type: text/plain; name="unterminated', "", "hi", ""].join("\r\n"), "utf8"));
  } catch (e) { partialThrew = e; }
  check("a type followed by an unterminated parameter is refused too",
        partialThrew !== null &&
          partialThrew.code === "safe-mime/malformed-content-type",
        partialThrew ? String(partialThrew.code) : "parsed");
}

function testTheQuoteCountIsTakenFromTheWireNotFromTheDecode() {
  // The parser decodes RFC 2047 encoded words into the header value before it
  // parses the value's structure, so a quote the DECODE produced counted
  // towards the quote balance. `=22` is how an MUA writes a quote inside an
  // encoded word, and `name="=?utf-8?Q?13=22_monitor=2Epdf?="` is a correctly
  // written header: two quotes on the wire, three after decoding. Refusing on
  // the decoded count rejected the whole message.
  //
  // Reading the raw value alone would not be enough either: the parameter
  // SPLIT runs on the decoded value too, so an encoded word could still push
  // `charset` out of the piece list and silently default it. Structure is
  // read from the wire and each parameter value is decoded after.
  var part = _parse(['Content-Type: application/pdf; name="=?utf-8?Q?13=22_monitor=2Epdf?="']);
  check("a quote produced by decoding does not unbalance the header",
        part.leaf.contentType === "application/pdf",
        JSON.stringify(part.leaf.contentType));
  check("and the decoded name reaches the parameter map",
        part.leaf.contentTypeParams.name === '13" monitor.pdf',
        JSON.stringify(part.leaf.contentTypeParams.name));

  // The same encoded word cannot push a later parameter out of the split.
  var withCharset = _parse([
    'Content-Type: text/plain; name="=?utf-8?Q?a=22b?="; charset=utf-8']);
  check("a parameter after an encoded word still parses",
        withCharset.leaf.charset === "utf-8",
        JSON.stringify(withCharset.leaf.charset));

  // And an encoded word cannot smuggle a charset past the allowlist by
  // unbalancing the quotes the split reads.
  var smuggled = null;
  try { _parse(['Content-Type: text/plain; name="=?utf-8?Q?=22?="; charset=nonsense-1']); }
  catch (e) { smuggled = e; }
  check("a charset outside the allowlist is still refused after an encoded word",
        smuggled !== null && smuggled.code === "safe-mime/unknown-charset",
        smuggled ? String(smuggled.code) : "parsed");
}

function testAQuoteCannotWalkAPartPastTheCharsetAllowlist() {
  // A charset the allowlist does not hold is refused. The splitter that reads
  // the parameters stops at an unterminated quote and drops everything after
  // it, so the same header one character apart produces no charset parameter
  // at all, and a leaf with no charset takes the us-ascii default. The refusal
  // and the silent default are the two answers to one hostile header, and the
  // sender picks which one it gets.
  var refused = null;
  try { _parse(["Content-Type: text/plain; charset=nonsense-1"]); }
  catch (e) { refused = e; }
  check("a charset outside the allowlist is refused",
        refused !== null && refused.code === "safe-mime/unknown-charset",
        refused ? String(refused.code) : "parsed");

  ['Content-Type: text/plain; charset="utf-8',
   'Content-Type: text/plain; charset=utf"-8',
   'Content-Type: text/plain; note="x; charset=utf-8'].forEach(function (header) {
    var threw = null;
    var tree  = null;
    try { tree = _parse([header]); } catch (e) { threw = e; }
    check("a parameter section that ends inside a quote is refused: " + header,
          threw !== null && typeof threw.code === "string" &&
            threw.code.indexOf("safe-mime/") === 0,
          threw ? String(threw.code)
                : "parsed as charset=" + JSON.stringify(tree.leaf.charset));
  });

  // A quote the sender did close still reads, so the refusal is about the
  // unterminated run and not about quoting.
  var quoted = _parse(['Content-Type: text/plain; note="x; y"; charset=utf-8']);
  check("a closed quote containing the separator still parses",
        quoted.leaf.charset === "utf-8" && quoted.leaf.contentTypeParams.note === "x; y",
        JSON.stringify(quoted.leaf.contentTypeParams));
}

function testTheParametersAreNotWritableThroughTheTree() {
  // A caller holding the tree must not be able to change what a later
  // consumer of the same tree reads out of it.
  var part = _parse(["Content-Type: text/plain; charset=utf-8"]);
  try { part.leaf.contentTypeParams.charset = "iso-8859-1"; } catch (_e) { /* frozen */ }
  check("a parameter cannot be rewritten in place",
        part.leaf.contentTypeParams.charset === "utf-8",
        JSON.stringify(part.leaf.contentTypeParams));
  try { part.leaf.contentTypeParams.extra = "x"; } catch (_e) { /* frozen */ }
  check("and none can be added",
        part.leaf.contentTypeParams.extra === undefined,
        JSON.stringify(part.leaf.contentTypeParams));
}

function testAStructureOnlyParseAnswersTheSameParameters() {
  // structureOnly skips the body, not the header, so the two modes must
  // agree about what the header said.
  var full  = _parse(["Content-Type: text/plain; charset=utf-8; format=flowed"]);
  var shape = b.safeMime.parse(Buffer.from(
    ["From: a@example.com", "Subject: s",
     "Content-Type: text/plain; charset=utf-8; format=flowed", "", "hi", ""].join("\r\n"),
    "utf8"), { structureOnly: true });
  check("structure-only reads the same parameters",
        JSON.stringify(shape.leaf.contentTypeParams) ===
        JSON.stringify(full.leaf.contentTypeParams),
        JSON.stringify([shape.leaf.contentTypeParams, full.leaf.contentTypeParams]));
}

function testTheJmapViewReadsTheSameParseRatherThanItsOwn() {
  // The consumer this was blocking. Reading the header a second time is how
  // two answers to one question start to disagree; the builder now reports
  // what the parser recorded.
  var raw = [
    "From: a@example.com", "To: b@example.net", "Subject: s", "MIME-Version: 1.0",
    'Content-Type: multipart/mixed; boundary="x"', "",
    "--x", "Content-Type: text/plain; charset=utf-8", "", "hi",
    "--x", "Content-Type: text/html", "", "<p>hi</p>",
    "--x--", "",
  ].join("\r\n");
  var tree = b.safeMime.parse(Buffer.from(raw, "utf8"));
  var props = b.mail.server.jmap.emailBodyProperties(tree, { blobIdPrefix: "obj1" });
  var leaves = props.bodyStructure.subParts;
  check("a part whose charset was written reports it",
        leaves[0].charset === "utf-8", JSON.stringify(leaves[0].charset));
  check("and a part that wrote none reports none",
        leaves[1].charset === null, JSON.stringify(leaves[1].charset));
  check("the reported value is the one the parser recorded",
        leaves[0].charset === tree.parts[0].leaf.contentTypeParams.charset,
        JSON.stringify([leaves[0].charset, tree.parts[0].leaf.contentTypeParams]));
}

function testAStructuralParameterIsReadAsTheWireWroteIt() {
  // RFC 2047 section 5 gives no encoded-word form for a parameter value; RFC
  // 2231 is the mechanism there. Decoding every parameter therefore invents a
  // value the header never carried, and for `boundary` that value is the
  // delimiter the body is split on: a sender writing an encoded word as the
  // boundary had the decoded form compared against a body that uses the
  // literal one, so every part was lost and the message parsed as a
  // multipart carrying nothing. `name` and `filename` are decoded because
  // mail agents really do write encoded words there, and a wrong display
  // name is a display defect rather than a lost message.
  function build(boundaryParam) {
    return [
      "From: a@example.com", "To: b@example.net", "Subject: s", "MIME-Version: 1.0",
      "Content-Type: multipart/mixed; boundary=" + boundaryParam, "",
      "--=?us-ascii?Q?bnd?=", "Content-Type: text/plain", "", "visible body text",
      "--=?us-ascii?Q?bnd?=",
      "Content-Type: application/x-msdownload; name=setup.exe", "", "MZ",
      "--=?us-ascii?Q?bnd?=--", "",
    ].join("\r\n");
  }

  var bare = b.safeMime.parse(Buffer.from(build('"=?us-ascii?Q?bnd?="'), "utf8"));
  check("a boundary written as an encoded word still splits the message",
        bare.parts.length === 2, "parts=" + bare.parts.length);
  check("and its parts are the ones the body carried",
        b.safeMime.extractAttachments(bare).length === 1,
        JSON.stringify(b.safeMime.extractAttachments(bare)
          .map(function (f) { return f.filename; })));

  // The same boundary with a quoted-pair: RFC 2045 removes the backslash, so
  // the value is the same delimiter and the same message.
  var escaped = b.safeMime.parse(Buffer.from(build('"=?us-ascii?Q?bnd?\\="'), "utf8"));
  check("a quoted-pair in the boundary reaches the same message",
        escaped.parts.length === 2, "parts=" + escaped.parts.length);

  // An encoded word is not a registered charset name, so reading the
  // parameter as written puts it outside the allowlist and the part is
  // refused. Decoding it first turned the same bytes into `utf-8` and
  // admitted them, which let a sender spell any charset in a form the
  // allowlist never saw.
  var smuggled = null;
  try {
    b.safeMime.parse(Buffer.from([
      "From: a@example.com", "To: b@example.net", "Subject: s", "MIME-Version: 1.0",
      'Content-Type: text/plain; charset="=?us-ascii?q?utf-8?="', "", "body",
    ].join("\r\n"), "utf8"));
  } catch (e) { smuggled = e; }
  check("a charset spelled as an encoded word does not reach the allowlist decoded",
        smuggled !== null && smuggled.code === "safe-mime/unknown-charset",
        smuggled ? smuggled.code + " " + String(smuggled.message).slice(0, 70) : "accepted");

  // The display name keeps the decode the header really needs.
  var named = b.safeMime.parse(Buffer.from([
    "From: a@example.com", "To: b@example.net", "Subject: s", "MIME-Version: 1.0",
    'Content-Type: multipart/mixed; boundary="bnd"', "",
    "--bnd", "Content-Type: text/plain", "", "body",
    "--bnd", 'Content-Type: application/pdf; name="=?utf-8?Q?13=22_monitor=2Epdf?="',
    "", "PDF",
    "--bnd--", "",
  ].join("\r\n"), "utf8"));
  var namedFiles = b.safeMime.extractAttachments(named);
  check("an encoded word in name is still decoded for display",
        namedFiles.length === 1 && namedFiles[0].filename === '13" monitor.pdf',
        JSON.stringify(namedFiles.map(function (f) { return f.filename; })));
}

function run() {
  testAWrittenCharsetIsDistinguishableFromADefaultedOne();
  testEveryParameterTheHeaderCarriedIsReadable();
  testAQuotedPairInsideAParameterDoesNotEndIt();
  testAHeaderThatOpensAQuoteAndNeverClosesItIsRefused();
  testAQuoteCannotWalkAPartPastTheCharsetAllowlist();
  testTheQuoteCountIsTakenFromTheWireNotFromTheDecode();
  testTheParametersAreNotWritableThroughTheTree();
  testAStructureOnlyParseAnswersTheSameParameters();
  testTheJmapViewReadsTheSameParseRatherThanItsOwn();
  testAStructuralParameterIsReadAsTheWireWroteIt();
}

module.exports = { run: run };

if (require.main === module) {
  try {
    run();
    console.log("[safe-mime-content-type-params] OK — " + helpers.getChecks() + " checks passed");
  } catch (e) {
    console.error("FAIL:", (e && e.stack) || e);
    process.exit(1);
  }
}
