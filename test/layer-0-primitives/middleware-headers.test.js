// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.middleware.headers — inbound HTTP header threat detection.
 *
 * Drives the RFC 9110 §5.1 token grammar check, RFC 9112 §6.1
 * request-smuggling shapes (CL+TE, multi-CL, multi-TE), oversize
 * count / value caps, deprecated X-Forwarded-* warning, and the
 * enforce-vs-audit-only disposition.
 *
 * Run standalone: `node test/layer-0-primitives/middleware-headers.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function _req(headers) {
  return { method: "GET", url: "/x", headers: headers || {} };
}
function _res() {
  return b.testing.mockRes();
}

function testCleanHeadersPass() {
  var mw = b.middleware.headers({});
  var req = _req({ host: "app.example.com", accept: "*/*" });
  var res = _res();
  var nextCalled = false;
  mw(req, res, function () { nextCalled = true; });
  check("headers: clean request passes through", nextCalled === true);
  check("headers: clean request writes no refusal", res.statusCode === null);
}

function testCrlfInValueRefused() {
  var mw = b.middleware.headers({ mode: "enforce" });
  var req = _req({ host: "x", "x-note": "line1\r\nline2" });
  var res = _res();
  var nextCalled = false;
  mw(req, res, function () { nextCalled = true; });
  check("headers: CR/LF in a header value refused with 400",
    res.statusCode === 400 && nextCalled === false);
  var body = JSON.parse(res._captured().body);
  check("headers: refusal names header-value-control-byte",
    body.error === "header-threat-detected" &&
    body.issues.some(function (i) { return i.kind === "header-value-control-byte"; }));
}

function testClTeSmugglingRefused() {
  var mw = b.middleware.headers({ mode: "enforce" });
  var req = _req({ host: "x", "content-length": "5", "transfer-encoding": "chunked" });
  var res = _res();
  var nextCalled = false;
  mw(req, res, function () { nextCalled = true; });
  check("headers: CL+TE request-smuggling shape refused with 400",
    res.statusCode === 400 && nextCalled === false);
  var body = JSON.parse(res._captured().body);
  check("headers: refusal names smuggling-cl-te",
    body.issues.some(function (i) { return i.kind === "smuggling-cl-te"; }));
}

function testMultiValueSmugglingRefused() {
  var mw = b.middleware.headers({ mode: "enforce" });
  // Node surfaces repeated headers as an array — the proxy-desync class.
  var reqCl = _req({ host: "x", "content-length": ["5", "6"] });
  var resCl = _res();
  mw(reqCl, resCl, function () {});
  check("headers: multiple Content-Length values refused", resCl.statusCode === 400);

  var reqTe = _req({ host: "x", "transfer-encoding": ["chunked", "gzip"] });
  var resTe = _res();
  mw(reqTe, resTe, function () {});
  check("headers: multiple Transfer-Encoding values refused", resTe.statusCode === 400);
}

function testHeaderCountCapRefused() {
  var mw = b.middleware.headers({ mode: "enforce", maxHeaderCount: 3 });
  var req = _req({ host: "x", a: "1", b: "2", c: "3", d: "4" });
  var res = _res();
  var nextCalled = false;
  mw(req, res, function () { nextCalled = true; });
  check("headers: header count over the cap refused",
    res.statusCode === 400 && nextCalled === false);
}

// A cap is enforced with `>`, and `5 > "abc"` is false for every count, so a
// cap that is not a number capped nothing and the middleware admitted any
// number of headers. A limit read from an environment variable or a JSON config
// arrives as a string, so this needs a configuration typo, not an attacker. The
// file already validates `trustProxy` for the same reason, because reading its
// truthiness let the string "false" keep trusting forwarding headers.
function testNonNumericCapsAreRefusedAtConfigTime() {
  function built(opts) {
    try { b.middleware.headers(opts); return null; }
    catch (e) { return e; }
  }
  check("headers: a non-numeric maxHeaderCount is refused when the middleware is built",
        built({ maxHeaderCount: "abc" }) !== null,
        "accepted maxHeaderCount \"abc\"");
  check("headers: a non-numeric maxValueBytes is refused",
        built({ maxValueBytes: "lots" }) !== null);
  check("headers: a negative maxHeaderCount is refused",
        built({ maxHeaderCount: -1 }) !== null);
  check("headers: a fractional maxHeaderCount is refused",
        built({ maxHeaderCount: 2.5 }) !== null);
  check("headers: a valid cap is still accepted",
        built({ maxHeaderCount: 3, maxValueBytes: 16 }) === null);

  // An explicit 0 means refuse anything non-empty, and `|| 100` replaced it
  // with the permissive default, so the strictest setting could not be asked
  // for at all.
  var strict = b.middleware.headers({ mode: "enforce", maxHeaderCount: 0 });
  var req = _req({ host: "x" });
  var res = _res();
  var nextCalled = false;
  strict(req, res, function () { nextCalled = true; });
  check("headers: maxHeaderCount 0 refuses a request carrying a header",
        res.statusCode === 400 && nextCalled === false,
        "status " + res.statusCode + ", next called " + nextCalled);
}

function testValueByteCapRefused() {
  var mw = b.middleware.headers({ mode: "enforce", maxValueBytes: 16 });
  var req = _req({ host: "x", "x-big": "A".repeat(64) });
  var res = _res();
  mw(req, res, function () {});
  check("headers: header value over the byte cap refused", res.statusCode === 400);
}

function testInvalidHeaderNameShapeRefused() {
  var mw = b.middleware.headers({ mode: "enforce" });
  var req = _req({ host: "x", "bad header name": "v" });
  var res = _res();
  mw(req, res, function () {});
  check("headers: non-RFC9110-token header name refused", res.statusCode === 400);
}

function testDeprecatedTrustHeaderWarnsButPasses() {
  var audit = b.testing.captureAudit();
  var mw = b.middleware.headers({ audit: audit });
  var req = _req({ host: "x", "x-forwarded-for": "1.2.3.4" });
  var res = _res();
  var nextCalled = false;
  mw(req, res, function () { nextCalled = true; });
  check("headers: deprecated X-Forwarded-* is WARN-only — request passes",
    nextCalled === true && res.statusCode === null);
  check("headers: the deprecated-trust-header warning is audited",
    audit.captured.some(function (e) {
      return e.action === "middleware.headers.threat-detected" &&
             e.metadata && e.metadata.kind === "deprecated-trust-header";
    }));
}

function testTrustProxySuppressesWarning() {
  var mw = b.middleware.headers({ trustProxy: true });
  var req = _req({ host: "x", "x-forwarded-for": "1.2.3.4" });
  var res = _res();
  var nextCalled = false;
  mw(req, res, function () { nextCalled = true; });
  check("headers: trustProxy opt-in suppresses the X-Forwarded-* warning",
    nextCalled === true && res.statusCode === null);
}

function testAuditOnlyPassesHighSeverity() {
  var audit = b.testing.captureAudit();
  var mw = b.middleware.headers({ mode: "audit-only", audit: audit });
  var req = _req({ host: "x", "x-note": "a\r\nb" });
  var res = _res();
  var nextCalled = false;
  mw(req, res, function () { nextCalled = true; });
  check("headers: audit-only passes a HIGH-severity request through",
    nextCalled === true && res.statusCode === null);
  check("headers: audit-only still emits the threat audit",
    audit.captured.some(function (e) { return e.action === "middleware.headers.threat-detected"; }));
}

function run() {
  testCleanHeadersPass();
  testCrlfInValueRefused();
  testClTeSmugglingRefused();
  testMultiValueSmugglingRefused();
  testHeaderCountCapRefused();
  testValueByteCapRefused();
  testNonNumericCapsAreRefusedAtConfigTime();
  testInvalidHeaderNameShapeRefused();
  testDeprecatedTrustHeaderWarnsButPasses();
  testTrustProxySuppressesWarning();
  testAuditOnlyPassesHighSeverity();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.message); process.exit(1); }
  );
}
