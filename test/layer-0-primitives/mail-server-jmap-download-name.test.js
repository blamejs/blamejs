// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The JMAP download handler names the file it serves the way the rest of
 * this framework does.
 *
 * `downloadHandler` built `Content-Disposition` itself: it tested the URL's
 * last segment against `/^[A-Za-z0-9._-]{1,200}$/` and, when that matched,
 * interpolated the segment straight into a quoted string. Two consequences
 * follow from one line.
 *
 * A name the test refuses is not served under a fallback, it is served with
 * no `Content-Disposition` at all, so a browser handed `rapport-financier.pdf`
 * spelled with an accent gets no filename and no `attachment`, and renders
 * the bytes inline instead of downloading them. Every non-ASCII name in every
 * language reaching this endpoint takes that path.
 *
 * The header also never carried the RFC 8187 `filename*` form, which is the
 * only one that can express a non-ASCII name at all.
 *
 * `b.staticServe.attachmentDisposition` already answers this question for
 * the static file server, RFC 6266 section 4.3 pairing and RFC 8187
 * `attr-char` escaping included. The handler composes it rather than
 * carrying a second answer.
 */

var helpers = require("../helpers");
var check   = helpers.check;
var b       = helpers.b;

function _mockReqRes(url) {
  var headers = {};
  var chunks  = [];
  var status  = 200;
  var req = {
    method: "GET", url: url, headers: {},
    user:   { id: "u1" },
    socket: { remoteAddress: "127.0.0.1" },
  };
  var res = {
    setHeader: function (k, v) { headers[k.toLowerCase()] = String(v); },
    getHeader: function (k) { return headers[k.toLowerCase()]; },
    end:       function (c) { if (c) chunks.push(Buffer.from(c)); },
    _headers:  function () { return headers; },
    _buf:      function () { return Buffer.concat(chunks).toString("utf8"); },
    _status:   function () { return status; },
  };
  Object.defineProperty(res, "statusCode", {
    get: function () { return status; },
    set: function (v) { status = v; },
  });
  return { req: req, res: res };
}

function _jmap() {
  return b.mail.server.jmap.create({
    mailStore: {
      appendMessage: function () {},
      downloadBlob:  function () {
        return Promise.resolve({ bytes: Buffer.from("PDFBYTES"), type: "application/pdf" });
      },
    },
    accountsFor: async function () { return { accounts: { A1: { name: "x" } } }; },
    methods:     {},
  });
}

async function _download(name) {
  var mr = _mockReqRes("/jmap/download/A1/blob_42/" + name);
  _jmap().downloadHandler(mr.req, mr.res);
  await new Promise(function (r) { setImmediate(function () { setImmediate(r); }); });
  await new Promise(function (r) { setImmediate(r); });
  return mr.res;
}

async function testANonAsciiNameIsStillServedAsAnAttachment() {
  // The failure that reaches an operator: no header at all, so the browser
  // renders the bytes instead of saving them.
  var res = await _download(encodeURIComponent("rapport-financiér.pdf"));
  var disposition = res._headers()["content-disposition"] || "";
  check("the response still succeeds", res._status() === 200, String(res._status()));
  check("a non-ASCII name is still served as an attachment",
        disposition.indexOf("attachment") === 0, JSON.stringify(disposition));
  check("and the real name is carried in the RFC 8187 ext-value",
        /filename\*=UTF-8''rapport-financi%C3%A9r\.pdf/.test(disposition),
        JSON.stringify(disposition));
  check("with an ASCII fallback for readers that predate it",
        /filename="rapport-financi_r\.pdf"/.test(disposition), JSON.stringify(disposition));
}

async function testAnApostropheIsEscapedAgainstAttrChar() {
  // The ext-value is parsed on apostrophes, so one left raw truncates the
  // name at it. This is the same defect the static server carried.
  var res = await _download(encodeURIComponent("q1'25 (final).pdf"));
  var disposition = res._headers()["content-disposition"] || "";
  check("an apostrophe is percent-escaped, not left to split the ext-value",
        disposition.indexOf("%27") !== -1 &&
        /filename\*=UTF-8''[^']*$/.test(disposition), JSON.stringify(disposition));
  check("and so are the parens encodeURIComponent leaves raw",
        disposition.indexOf("%28") !== -1 && disposition.indexOf("%29") !== -1,
        JSON.stringify(disposition));
}

async function testAPlainAsciiNameIsUnchanged() {
  var res = await _download("note.txt");
  var disposition = res._headers()["content-disposition"] || "";
  check("a plain name still reads as it always did",
        /^attachment; filename="note\.txt"/.test(disposition), JSON.stringify(disposition));
}

async function testAHeaderInjectingNameCannotSplitTheResponse() {
  // The segment is attacker-chosen, so the name must never carry CR or LF
  // into a header value whatever the caller sends.
  var res = await _download(encodeURIComponent("a\r\nX-Injected: 1\r\n.txt"));
  var disposition = res._headers()["content-disposition"] || "";
  // `|| ""` above makes an ABSENT header satisfy a "carries no CR or LF"
  // test, and emitting no header at all was the behaviour this release
  // fixed, so the header has to be there before its contents mean anything.
  check("the response still carries a disposition header",
        typeof res._headers()["content-disposition"] === "string" &&
        res._headers()["content-disposition"].indexOf("attachment") === 0,
        JSON.stringify(res._headers()["content-disposition"]));
  check("a name carrying CRLF does not reach the header",
        disposition.indexOf("\r") === -1 && disposition.indexOf("\n") === -1,
        JSON.stringify(disposition));
  check("and no injected header appears on the response",
        res._headers()["x-injected"] === undefined);
}

async function testAPathSegmentCannotEscapeTheName() {
  var res = await _download(encodeURIComponent("../../etc/passwd"));
  var disposition = res._headers()["content-disposition"] || "";
  check("a traversal name is reduced to its basename",
        disposition.indexOf("etc") === -1 && /filename="passwd"/.test(disposition),
        JSON.stringify(disposition));
}

async function testARouterSuppliedNameIsNotDecodedTwice() {
  // b.router decodes the pathname before it matches route parameters, so
  // req.params.name is already the name. Decoding it again turned a file
  // literally called "report%20final.txt" into "report final.txt", and the
  // browser saved it under a name the sender never used.
  var mr = _mockReqRes("/jmap/download/A1/blob_42/report%2520final.txt");
  mr.req.params = { accountId: "A1", blobId: "blob_42", name: "report%20final.txt" };
  _jmap().downloadHandler(mr.req, mr.res);
  await new Promise(function (r) { setImmediate(function () { setImmediate(r); }); });
  await new Promise(function (r) { setImmediate(r); });
  var disposition = mr.res._headers()["content-disposition"] || "";
  check("the name the router decoded is used as it stands",
        disposition.indexOf("report%20final.txt") !== -1 ||
        /filename\*=UTF-8''report%2520final\.txt/.test(disposition),
        JSON.stringify(disposition));
  check("and it is not decoded a second time",
        disposition.indexOf("report final.txt") === -1, JSON.stringify(disposition));

  // The raw-path route still decodes, because nothing has decoded it yet.
  var raw = await _download(encodeURIComponent("report final.txt"));
  check("a raw path segment is still decoded once",
        /filename="report final\.txt"/.test(raw._headers()["content-disposition"] || ""),
        JSON.stringify(raw._headers()["content-disposition"]));
}

async function run() {
  await testANonAsciiNameIsStillServedAsAnAttachment();
  await testARouterSuppliedNameIsNotDecodedTwice();
  await testAnApostropheIsEscapedAgainstAttrChar();
  await testAPlainAsciiNameIsUnchanged();
  await testAHeaderInjectingNameCannotSplitTheResponse();
  await testAPathSegmentCannotEscapeTheName();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[mail-server-jmap-download-name] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
