// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.middleware.csrfProtect — cookie-header parsing prototype-pollution
 * defense (CWE-915 / CWE-1321) + double-submit success path.
 *
 * The Cookie request header is attacker-controlled. The internal cookie
 * parser builds its map from [name, value] pairs through
 * Object.fromEntries onto a null-prototype object — never a computed-
 * write (`out[name] = value`) sink. These tests drive the middleware
 * end-to-end (no internal mocks) to verify:
 *   - a Cookie header carrying `__proto__` / `constructor` / `prototype`
 *     names does NOT pollute Object.prototype;
 *   - a legitimate CSRF cookie alongside those hostile names still
 *     resolves and the double-submit check passes (header token matches);
 *   - first-occurrence-wins is preserved for duplicate cookie names.
 *
 * Run standalone: `node test/layer-0-primitives/csrf-protect.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b        = helpers.b;
var check    = helpers.check;
var _mockReq = helpers._mockReq;
var _mockRes = helpers._mockRes;

// Drive one request through the csrf middleware; resolve to an outcome
// object describing whether next() was called or the request was denied.
function _runCsrf(mwOpts, req) {
  var res = _mockRes();
  return new Promise(function (resolve) {
    var calledNext = false;
    var mw = b.middleware.csrfProtect(mwOpts);
    // denyResponse writes to res + ends it; next() is the success signal.
    // mockRes captures the status via writeHead → res._captured().status.
    var origEnd = res.end;
    res.end = function () {
      var r = origEnd.apply(res, arguments);
      var cap = res._captured();
      resolve({ outcome: "denied", status: cap.status, body: cap.body, req: req, res: res, calledNext: calledNext });
      return r;
    };
    mw(req, res, function () {
      calledNext = true;
      resolve({ outcome: "next", req: req, res: res, calledNext: true });
    });
  });
}

// skipStateless exists because a request with no ambient credential cannot be
// forged on a victim's behalf: CSRF spends a cookie the browser attaches by
// itself. What it used to test for was an `Authorization` header, and presence
// is not authenticity — an attacker composing a cross-site request writes their
// own headers, so `Authorization: Bearer nonsense` met the condition by being
// typed. Worse, the header says nothing about which credential actually
// authenticated the request: b.middleware.attachUser with tokenFrom: "both"
// reads the COOKIE first, so a request carrying both was authenticated by
// exactly the ambient credential this gate protects, and skipped the gate
// because of a header nobody read.
async function testSkipStatelessTurnsOnTheAmbientCredential() {
  var token = b.forms.generateCsrfToken();

  // The bug: a session cookie present, no CSRF token, and a junk bearer header.
  var forged = _mockReq({
    method: "POST",
    url: "/submit",
    headers: {
      host:          "example.com",
      cookie:        "csrf=" + token + "; session=abc",
      authorization: "Bearer not-a-real-token",
    },
  });
  var r = await _runCsrf({ cookie: true, skipStateless: true }, forged);
  check("csrf: an unvalidated Authorization header does not waive the token check",
    r.outcome === "denied" && r.status === 403,
    r.outcome + " " + (r.status || ""));

  // What skipStateless is actually for, and it still works: no cookie at all,
  // so there is no ambient credential to abuse.
  var cookieless = _mockReq({
    method: "POST",
    url: "/submit",
    headers: { host: "example.com", authorization: "Bearer whatever" },
  });
  var r2 = await _runCsrf({ cookie: true, skipStateless: true }, cookieless);
  check("csrf: a cookieless request is still not CSRF-able, so it passes",
    r2.outcome === "next", r2.outcome + " " + (r2.status || ""));

  // And with no cookie AND no Authorization header — the header was never the
  // thing that mattered.
  var bare = _mockReq({
    method: "POST", url: "/submit", headers: { host: "example.com" },
  });
  var r3 = await _runCsrf({ cookie: true, skipStateless: true }, bare);
  check("csrf: a bare cookieless POST passes on the same reasoning",
    r3.outcome === "next", r3.outcome + " " + (r3.status || ""));

  // Control: without skipStateless the cookieless request IS validated, so the
  // checks above are reading the option rather than a blanket pass.
  var strict = _mockReq({
    method: "POST", url: "/submit", headers: { host: "example.com" },
  });
  var r4 = await _runCsrf({ cookie: true }, strict);
  check("csrf: the same request is refused when skipStateless is off",
    r4.outcome === "denied" && r4.status === 403,
    r4.outcome + " " + (r4.status || ""));
}

// A consumer that asked for checkOrigin asked for something the token compare
// does not provide, and there is no reading of "stateless" under which a
// cross-origin state change becomes acceptable. The skip used to run first, so
// the option meant to be the second line of defence was waived by the branch
// that waived the first.
async function testSkipStatelessCannotWaiveTheOriginCheck() {
  var crossOrigin = _mockReq({
    method: "POST",
    url: "/submit",
    headers: {
      host:          "example.com",
      origin:        "https://attacker.example",
      authorization: "Bearer not-a-real-token",
    },
  });
  var r = await _runCsrf(
    { cookie: true, skipStateless: true, checkOrigin: true }, crossOrigin);
  check("csrf: a cross-origin stateless request is still refused on origin",
    r.outcome === "denied" && r.status === 403,
    r.outcome + " " + (r.status || ""));

  // Control: same request, same-origin, still passes — the refusal above is
  // the origin check firing and not skipStateless having stopped working.
  var sameOrigin = _mockReq({
    method: "POST",
    url: "/submit",
    headers: {
      host:          "example.com",
      origin:        "http://example.com",
      authorization: "Bearer not-a-real-token",
    },
  });
  var r2 = await _runCsrf(
    { cookie: true, skipStateless: true, checkOrigin: true }, sameOrigin);
  check("csrf: the same-origin stateless request still passes",
    r2.outcome === "next", r2.outcome + " " + (r2.status || ""));
}

async function testSuccessPathDoubleSubmit() {
  // Valid 64-hex cookie + matching X-CSRF-Token header on a POST → next().
  var token = b.forms.generateCsrfToken();
  var req = _mockReq({
    method: "POST",
    url: "/submit",
    headers: {
      host:         "example.com",
      cookie:       "csrf=" + token,
      "x-csrf-token": token,
    },
  });
  var r = await _runCsrf({ cookie: true }, req);
  check("csrf: valid double-submit passes (next called)", r.outcome === "next");
}

async function testMismatchDenied() {
  var token = b.forms.generateCsrfToken();
  var req = _mockReq({
    method: "POST",
    url: "/submit",
    headers: {
      host:           "example.com",
      cookie:         "csrf=" + token,
      "x-csrf-token": b.forms.generateCsrfToken(),    // different token
    },
  });
  var r = await _runCsrf({ cookie: true }, req);
  check("csrf: token mismatch denied (403)", r.outcome === "denied" && r.status === 403);
}

async function testPoisonedCookieNamesDoNotPollute() {
  // A Cookie header carrying __proto__ / constructor / prototype names
  // alongside the real csrf cookie must not pollute Object.prototype, and
  // the legitimate cookie must still resolve so the double-submit passes.
  var token = b.forms.generateCsrfToken();
  var req = _mockReq({
    method: "POST",
    url: "/submit",
    headers: {
      host:   "example.com",
      cookie: "__proto__=polluted; constructor=evil; prototype=evil2; csrf=" + token + "; other=ok",
      "x-csrf-token": token,
    },
  });
  var r = await _runCsrf({ cookie: true }, req);
  check("csrf: hostile cookie names did not pollute Object.prototype",
        ({}).polluted === undefined &&
        Object.prototype.polluted === undefined &&
        ({}).evil === undefined &&
        ({}).evil2 === undefined);
  check("csrf: legitimate cookie still resolved (double-submit passed)",
        r.outcome === "next");
}

async function testFirstOccurrenceWinsForDuplicateCookie() {
  // RFC 6265 §5.2 — duplicate cookie names resolve to the FIRST occurrence
  // (most-specific path). A later forged `csrf=` must not override the
  // first; the double-submit must validate against the first value.
  var first  = b.forms.generateCsrfToken();
  var second = b.forms.generateCsrfToken();
  var req = _mockReq({
    method: "POST",
    url: "/submit",
    headers: {
      host:           "example.com",
      cookie:         "csrf=" + first + "; csrf=" + second,
      "x-csrf-token": first,                       // matches FIRST occurrence
    },
  });
  var r = await _runCsrf({ cookie: true }, req);
  check("csrf: duplicate cookie resolves to first occurrence (next on first-token submit)",
        r.outcome === "next");

  // Submitting the SECOND value must be rejected — proves first-wins, not
  // last-wins.
  var req2 = _mockReq({
    method: "POST",
    url: "/submit",
    headers: {
      host:           "example.com",
      cookie:         "csrf=" + first + "; csrf=" + second,
      "x-csrf-token": second,
    },
  });
  var r2 = await _runCsrf({ cookie: true }, req2);
  check("csrf: submitting the second (shadowed) cookie value is denied",
        r2.outcome === "denied" && r2.status === 403);
}

function testMethodsEmptyThrows() {
  // An empty methods array would silently disable the primary CSRF method-gate
  // for all state-changing requests — refuse it at config time.
  var threw = null;
  try { b.middleware.csrfProtect({ cookie: true, methods: [] }); } catch (e) { threw = e; }
  check("csrfProtect({ methods: [] }) refused at config time (no silent CSRF disable)",
        threw && /non-empty array/.test(threw.message || ""));
}

// Two distinct csrf instances on the same response (createApp wires csrf
// globally AND an operator re-mounts it at the route level) must issue a
// SINGLE Set-Cookie for the same cookie name — cookie issuance is a
// response-level resource, deduped by name. Enforcement stays per instance
// (the next test).
async function testRedundantMountIssuesSingleCookie() {
  var req = _mockReq({ method: "GET", url: "/", headers: { host: "example.com" } });
  var res = _mockRes();
  var mw1 = b.middleware.csrfProtect({ cookie: true });
  var mw2 = b.middleware.csrfProtect({ cookie: true });
  await new Promise(function (r) { mw1(req, res, r); });
  await new Promise(function (r) { mw2(req, res, r); });
  var sc = res.getHeader("set-cookie");
  var arr = Array.isArray(sc) ? sc : (sc ? [sc] : []);
  var csrfCookies = arr.filter(function (c) { return /^csrf=/.test(c); });
  check("csrf: redundant same-name mount issues a single Set-Cookie",
        csrfCookies.length === 1);
  check("csrf: both instances expose the same req.csrfToken",
        typeof req.csrfToken === "string" && req.csrfToken.length === 64);
}

// The cookie-issuance dedup must NOT disable per-instance enforcement: two
// distinct instances each validate the double-submit token on a POST. A bad
// token reaches a deny regardless of which instance runs first — a shared
// "already handled" flag (the bug the per-instance gate fixed) would let the
// first instance mark the request handled and skip the second's check.
async function testDistinctInstancesBothEnforce() {
  var good = b.forms.generateCsrfToken();
  var req = _mockReq({
    method: "POST", url: "/submit",
    headers: { host: "example.com", cookie: "csrf=" + good, "x-csrf-token": "deadbeef" },
  });
  var res = _mockRes();
  var denied = false;
  var origEnd = res.end;
  res.end = function () { denied = true; return origEnd.apply(res, arguments); };
  var mw = b.middleware.csrfProtect({ cookie: true });
  var nextCalled = false;
  await new Promise(function (r) { mw(req, res, function () { nextCalled = true; r(); }); if (denied) r(); });
  // The instance denies the mismatched token (cookie != header), proving
  // enforcement runs per instance and the cookie-dedup did not mark the
  // request "already handled".
  check("csrf: distinct instance enforces double-submit (bad token denied)",
        denied === true && nextCalled === false);
}

// The Origin/Referer cross-check must canonicalize host case the same way on
// both sides. The candidate Origin is canonicalized via new URL(...).origin
// (lowercases host, strips default port), but the same-origin baseline was
// built by raw `proto + Host` concatenation and the allowedOrigins were
// compared verbatim — so a legitimate same-origin POST whose Host header is
// mixed-case (or carries an explicit default port) was wrongly refused.
async function testOriginCheckCanonicalizesHost() {
  var tok = b.forms.generateCsrfToken();
  var req = _mockReq({
    method: "POST", url: "/submit",
    headers: {
      host:           "App.Example.com",            // mixed-case Host
      origin:         "http://app.example.com",      // lowercased same origin
      cookie:         "csrf=" + tok,
      "x-csrf-token": tok,
    },
  });
  var r = await _runCsrf({ cookie: true, checkOrigin: true }, req);
  check("csrf: same-origin POST with a mixed-case Host is allowed (not cross-origin-refused)",
        r.outcome === "next");

  // A mixed-case allowedOrigins entry must admit the lowercased candidate too.
  var tok2 = b.forms.generateCsrfToken();
  var req2 = _mockReq({
    method: "POST", url: "/submit",
    headers: {
      host:           "app.example.com",
      origin:         "http://cdn.example.com",
      cookie:         "csrf=" + tok2,
      "x-csrf-token": tok2,
    },
  });
  var r2 = await _runCsrf({ cookie: true, checkOrigin: true, allowedOrigins: ["http://CDN.Example.com"] }, req2);
  check("csrf: a mixed-case allowedOrigins entry admits the lowercased Origin",
        r2.outcome === "next");
}

// Every Set-Cookie the middleware queued, flattened.
function _issuedCookies(res) {
  var sc = res.getHeader("set-cookie");
  return Array.isArray(sc) ? sc : (sc ? [sc] : []);
}

async function _issueCookie(mwOpts, req) {
  var res = _mockRes();
  var mw = b.middleware.csrfProtect(mwOpts);
  await new Promise(function (r) { mw(req, res, r); });
  return { res: res, cookies: _issuedCookies(res) };
}

// The cookie attributes csrf-protect writes come from operator config and go
// straight into a response header. Path was interpolated into the Set-Cookie
// string with no CRLF scrub, so a config value carrying a bare CR or LF split
// the header and appended one of the operator's choosing. b.cookies.serialize
// scrubs every attribute for exactly this reason; the middleware has to route
// through it rather than formatting its own.
async function testCookieAttributesCannotSplitTheHeader() {
  var req = _mockReq({ method: "GET", url: "/", headers: { host: "example.com" } });
  var issued = await _issueCookie(
    { cookie: { path: "/app\r\nX-Injected: yes" } }, req);
  check("csrf: exactly one cookie issued", issued.cookies.length === 1);
  var header = issued.cookies[0];
  check("csrf: a CR in cookie.path cannot reach the response header",
        header.indexOf("\r") === -1);
  check("csrf: an LF in cookie.path cannot reach the response header",
        header.indexOf("\n") === -1);
  check("csrf: the injected header name did not become a header",
        issued.res.getHeader("x-injected") === undefined);
}

// A __Host- name is a promise to the browser: Secure, Path=/, no Domain. With
// `secure` left to auto-detect, that promise is broken per-request — over
// plain HTTP the cookie went out as `__Host-csrf` with no Secure, and every
// browser silently drops it, so the double-submit token never persists and
// each request looks like a first visit. The boot check could not see it
// because the decision is made per request; the name and the auto-detect are
// what conflict, so that is what has to be refused at boot.
function testHostPrefixWithAutoDetectedSecureRefusedAtBoot() {
  var threw = null;
  try { b.middleware.csrfProtect({ cookie: { name: "__Host-csrf" } }); }
  catch (e) { threw = e; }
  check("csrf: __Host-* with auto-detected secure is refused at boot",
        threw !== null && /__Host-/.test(String(threw.message)));

  var threwSecure = null;
  try { b.middleware.csrfProtect({ cookie: { name: "__Secure-csrf" } }); }
  catch (e) { threwSecure = e; }
  check("csrf: __Secure-* with auto-detected secure is refused at boot",
        threwSecure !== null && /__Secure-/.test(String(threwSecure.message)));

  // Declaring the transport explicitly is the way through — the operator is
  // asserting HTTPS, which is what the prefix already claims.
  var ok = null;
  try { b.middleware.csrfProtect({ cookie: { name: "__Host-csrf", secure: true } }); }
  catch (e) { ok = e; }
  check("csrf: __Host-* with an explicit secure: true is accepted", ok === null);

  // A name with no prefix keeps auto-detect — nothing about the common case
  // changes.
  var plain = null;
  try { b.middleware.csrfProtect({ cookie: { name: "csrf" } }); }
  catch (e) { plain = e; }
  check("csrf: a prefix-free cookie name still auto-detects", plain === null);
}

// The issued cookie must survive alongside cookies the route already queued,
// and must itself be a validly serialized one.
async function testIssuedCookieShape() {
  var req = _mockReq({ method: "GET", url: "/", headers: { host: "example.com" } });
  var res = _mockRes();
  res.setHeader("Set-Cookie", "locale=en; Path=/");
  var mw = b.middleware.csrfProtect({ cookie: true });
  await new Promise(function (r) { mw(req, res, r); });
  var all = _issuedCookies(res);
  check("csrf: a cookie already on the response is preserved",
        all.indexOf("locale=en; Path=/") !== -1);
  check("csrf: the csrf cookie is queued alongside it",
        all.filter(function (c) { return c.indexOf("csrf=") === 0; }).length === 1);

  // The token is 64 hex chars — percent-encoding must be a no-op on it, so
  // the value the browser sends back still matches the double-submit compare.
  var csrf = all.filter(function (c) { return c.indexOf("csrf=") === 0; })[0];
  var value = csrf.slice("csrf=".length).split(";")[0];
  check("csrf: the issued token round-trips unencoded",
        value === req.csrfToken && /^[a-f0-9]{64}$/.test(value));
}

// The denial's reason is the whole value of an enhanced audit line, and this
// exit returned an object where every other one returns a string. The caller
// builds the line by concatenation, so the one configuration an operator turns
// on deliberately -- `requireOrigin` -- recorded `origin/referer:
// [object Object]`, indistinguishable in the trail from any other object that
// might arrive there later. The refusal itself was never affected.
async function testRequireOriginDenialNamesItsReason() {
  var events = [];
  var realSafeEmit = b.audit.safeEmit;
  b.audit.safeEmit = function (ev) { events.push(ev); };
  var r;
  try {
    var noOriginAtAll = _mockReq({
      method:  "POST",
      url:     "/submit",
      headers: { host: "example.com" },
    });
    r = await _runCsrf(
      { cookie: true, checkOrigin: true, requireOrigin: true }, noOriginAtAll);
  } finally { b.audit.safeEmit = realSafeEmit; }

  check("csrf: a request with no Origin or Referer is refused under requireOrigin",
        r.outcome === "denied" && r.status === 403, r.outcome + " " + (r.status || ""));

  var reasons = events.map(function (e) {
    return (e && e.metadata && e.metadata.reason) || (e && e.reason) || "";
  }).join(" | ");
  check("csrf: and the denial names the reason rather than an object",
        /missing-origin-and-referer/.test(reasons) && !/\[object Object\]/.test(reasons),
        JSON.stringify(reasons.slice(0, 200)));
}

// The same-origin baseline is built from the authority the request named, and
// node maps neither `Host` nor `:authority` into the other. Over HTTP/2 — what
// this framework's own TLS listeners negotiate with every browser — reading
// `Host` alone left the baseline empty, so every browser Origin mismatched and
// the gate refused every form submission.
//
// Both sides: the h2 request must pass, and a cross-origin one over h2 must
// still be refused, so the fix is not "the check stopped running".
async function testTheOriginBaselineIsBuiltFromTheHttp2Authority() {
  var sameOrigin = _mockReq({
    method: "POST", url: "/submit",
    headers: {
      ":authority":   "example.com",
      origin:         "http://example.com",
      authorization:  "Bearer not-a-real-token",
    },
  });
  var r = await _runCsrf(
    { cookie: true, skipStateless: true, checkOrigin: true }, sameOrigin);
  check("csrf: a same-origin HTTP/2 request is not refused for a missing Host",
    r.outcome === "next", r.outcome + " " + (r.status || ""));

  var crossOrigin = _mockReq({
    method: "POST", url: "/submit",
    headers: {
      ":authority":   "example.com",
      origin:         "https://attacker.example",
      authorization:  "Bearer not-a-real-token",
    },
  });
  var r2 = await _runCsrf(
    { cookie: true, skipStateless: true, checkOrigin: true }, crossOrigin);
  check("csrf: and a cross-origin HTTP/2 request is still refused",
    r2.outcome === "denied" && r2.status === 403, r2.outcome + " " + (r2.status || ""));

  // The pseudo-header comes from the connection; a `Host` sent alongside it is
  // caller text. Believing the latter let a non-browser client write BOTH
  // halves of the comparison and have the check agree with it.
  var forged = _mockReq({
    method: "POST", url: "/submit",
    headers: {
      ":authority":   "example.com",
      host:           "attacker.example",
      origin:         "http://attacker.example",
      authorization:  "Bearer not-a-real-token",
    },
  });
  var r3 = await _runCsrf(
    { cookie: true, skipStateless: true, checkOrigin: true }, forged);
  check("csrf: a forged Host cannot supply both halves of the origin comparison",
    r3.outcome === "denied" && r3.status === 403, r3.outcome + " " + (r3.status || ""));
}

async function run() {
  await testTheOriginBaselineIsBuiltFromTheHttp2Authority();
  await testRequireOriginDenialNamesItsReason();
  await testSuccessPathDoubleSubmit();
  await testCookieAttributesCannotSplitTheHeader();
  testHostPrefixWithAutoDetectedSecureRefusedAtBoot();
  await testIssuedCookieShape();
  await testMismatchDenied();
  await testPoisonedCookieNamesDoNotPollute();
  await testSkipStatelessTurnsOnTheAmbientCredential();
  await testSkipStatelessCannotWaiveTheOriginCheck();
  await testFirstOccurrenceWinsForDuplicateCookie();
  await testRedundantMountIssuesSingleCookie();
  await testDistinctInstancesBothEnforce();
  testMethodsEmptyThrows();
  await testOriginCheckCanonicalizesHost();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    // Re-throw rather than logging e.message: the failure message can
    // echo request-derived cookie names/values fed into the middleware,
    // and writing that to the log unescaped would be log injection
    // (CWE-117). The non-zero exit + thrown stack still surface the
    // failure to the runner.
    function (e) { process.exitCode = 1; throw e; }
  );
}
