// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * request-helpers — resolveRoute + captureResponseStatus.
 *
 * Run standalone: `node test/layer-0-primitives/request-helpers.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b         = helpers.b;
var check     = helpers.check;
var _bodyRes  = helpers._bodyRes;
var _mockRes  = helpers._mockRes;

function testSurface() {
  check("b.requestHelpers exposed",                  typeof b.requestHelpers === "object");
  check("resolveRoute is a function",                typeof b.requestHelpers.resolveRoute === "function");
  check("captureResponseStatus is a function",       typeof b.requestHelpers.captureResponseStatus === "function");
  check("ipKey is a function",                       typeof b.requestHelpers.ipKey === "function");
}

function testResolveRoutePrefersRoutePattern() {
  var r = b.requestHelpers.resolveRoute({
    routePattern: "/users/:id",
    url:          "/users/42?q=x",
  });
  check("resolveRoute: prefers routePattern over URL", r === "/users/:id");
}

function testResolveRouteFallsBackToUrl() {
  var r = b.requestHelpers.resolveRoute({ url: "/raw-path?x=1" });
  check("resolveRoute: URL fallback strips query",   r === "/raw-path");
}

function testResolveRouteEmptyOrMissingUrl() {
  check("resolveRoute: missing url → /",   b.requestHelpers.resolveRoute({}) === "/");
  check("resolveRoute: empty url → /",     b.requestHelpers.resolveRoute({ url: "" }) === "/");
  check("resolveRoute: null req safe",     b.requestHelpers.resolveRoute(null) === "/");
}

function testResolveRouteIgnoresEmptyRoutePattern() {
  var r = b.requestHelpers.resolveRoute({
    routePattern: "",      // empty string = router didn't resolve
    url:          "/foo",
  });
  check("resolveRoute: empty routePattern falls through to URL", r === "/foo");
}

async function testCaptureStatusFromWriteHead() {
  var res = _bodyRes();
  var captured = null;
  b.requestHelpers.captureResponseStatus(res, function (status) { captured = status; });
  await new Promise(function (resolve) {
    res.on("finish", resolve);
    res.writeHead(404);
    res.end();
  });
  check("captureResponseStatus: writeHead status captured", captured === 404);
}

async function testCaptureStatusFromStatusCode() {
  var res = _bodyRes();
  var captured = null;
  b.requestHelpers.captureResponseStatus(res, function (status) { captured = status; });
  await new Promise(function (resolve) {
    res.on("finish", resolve);
    res.statusCode = 503;
    res.end();
  });
  check("captureResponseStatus: res.statusCode captured (no writeHead)",
        captured === 503);
}

async function testCaptureStatusDefaults200() {
  var res = _bodyRes();
  var captured = null;
  b.requestHelpers.captureResponseStatus(res, function (status) { captured = status; });
  await new Promise(function (resolve) {
    res.on("finish", resolve);
    res.statusCode = undefined;
    res.end();
  });
  check("captureResponseStatus: default 200 when nothing set",
        captured === 200);
}

async function testCaptureStatusOnEndThrowDoesntBreakResponse() {
  var res = _bodyRes();
  b.requestHelpers.captureResponseStatus(res, function () {
    throw new Error("instrumentation bug");
  });
  var threw = null;
  try {
    await new Promise(function (resolve) {
      res.on("finish", resolve);
      res.statusCode = 200;
      res.end();
    });
  } catch (e) { threw = e; }
  check("captureResponseStatus: onEnd throw does not break response", threw === null);
}

function testCaptureStatusValidatesArgs() {
  var threwNoOnEnd = null;
  try { b.requestHelpers.captureResponseStatus(_bodyRes()); }
  catch (e) { threwNoOnEnd = e; }
  check("captureResponseStatus: rejects missing onEnd", threwNoOnEnd !== null);
}

function testParseListHeader() {
  var rh = b.requestHelpers;
  check("parseListHeader: basic",
        JSON.stringify(rh.parseListHeader("a,b,c")) === '["a","b","c"]');
  check("parseListHeader: trims whitespace",
        JSON.stringify(rh.parseListHeader("a, b , c")) === '["a","b","c"]');
  check("parseListHeader: filters empty",
        JSON.stringify(rh.parseListHeader("a,, ,b")) === '["a","b"]');
  check("parseListHeader: lowercase opt",
        JSON.stringify(rh.parseListHeader("Foo, BAR", { lowercase: true })) === '["foo","bar"]');
  check("parseListHeader: lowercase off (default)",
        JSON.stringify(rh.parseListHeader("Foo, BAR")) === '["Foo","BAR"]');
  check("parseListHeader: null input → []",
        rh.parseListHeader(null).length === 0);
  check("parseListHeader: undefined input → []",
        rh.parseListHeader(undefined).length === 0);
  check("parseListHeader: empty string → []",
        rh.parseListHeader("").length === 0);
  check("parseListHeader: number coerced",
        JSON.stringify(rh.parseListHeader(42)) === '["42"]');
  check("parseListHeader: only commas → []",
        rh.parseListHeader(",,,").length === 0);
  check("parseListHeader: trailing comma tolerated",
        JSON.stringify(rh.parseListHeader("a,b,")) === '["a","b"]');
  check("parseListHeader: tabs/spaces trimmed",
        JSON.stringify(rh.parseListHeader("\ta\t,\tb\n")) === '["a","b"]');
}

function testParseQualityListQuoteAware() {
  var rh = b.requestHelpers;
  // The q-value must come from the parameter literally named `q`, parsed
  // quote-aware — never a `q=`-shaped substring inside a quoted parameter value,
  // and a quoted value's ',' / ';' must not split the list.
  var quoted = rh.parseQualityList('text/html;title="x;q=0.1";q=0.9');
  check("parseQualityList: q= inside a quoted value is not the q-value",
        quoted.length === 1 && quoted[0].value === "text/html" && quoted[0].q === 0.9);
  var commaInQuote = rh.parseQualityList('a/b;p="x,y";q=0.3');
  check("parseQualityList: comma inside a quoted value does not split the list",
        commaInQuote.length === 1 && commaInQuote[0].value === "a/b" && commaInQuote[0].q === 0.3);
  var leveled = rh.parseQualityList("text/html;level=1;q=0.5");
  check("parseQualityList: a media-type param before q is ignored",
        leveled.length === 1 && leveled[0].q === 0.5);
  var ranked = rh.parseQualityList("br;q=1.0, gzip;q=0.5, *;q=0");
  check("parseQualityList: ranks by descending q",
        ranked[0].value === "br" && ranked[1].value === "gzip" && ranked[2].q === 0);
  check("parseQualityList: missing q defaults to 1",
        rh.parseQualityList("en")[0].q === 1);
}

function testSafeHeadersDistinct() {
  check("safeHeadersDistinct is fn", typeof b.requestHelpers.safeHeadersDistinct === "function");

  var out = b.requestHelpers.safeHeadersDistinct({
    rawHeaders: ["Content-Type", "application/json", "X-Foo", "a", "X-Foo", "b"],
  });
  check("safeHeadersDistinct: lowercases names", !!out["content-type"] && !!out["x-foo"]);
  check("safeHeadersDistinct: collects multi values",
        Array.isArray(out["x-foo"]) && out["x-foo"].length === 2 &&
        out["x-foo"][0] === "a" && out["x-foo"][1] === "b");

  var hostile = b.requestHelpers.safeHeadersDistinct({
    rawHeaders: ["__proto__", "polluted", "constructor", "evil", "X-Real", "ok"],
  });
  check("safeHeadersDistinct: __proto__ refused",   hostile["__proto__"] === undefined);
  check("safeHeadersDistinct: constructor refused", hostile.constructor === undefined);
  check("safeHeadersDistinct: real header passes",  hostile["x-real"] && hostile["x-real"][0] === "ok");

  var np = b.requestHelpers.safeHeadersDistinct({ rawHeaders: ["X-A", "1"] });
  check("safeHeadersDistinct: null prototype", Object.getPrototypeOf(np) === null);

  var empty = b.requestHelpers.safeHeadersDistinct({});
  check("safeHeadersDistinct: missing rawHeaders", Object.keys(empty).length === 0);
}

function testExtractBearerSurface() {
  check("extractBearer is a function", typeof b.requestHelpers.extractBearer === "function");
}

function testExtractBearerHappyPath() {
  var token = b.requestHelpers.extractBearer({
    headers: { authorization: "Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig" },
  });
  check("extractBearer: returns the token from Authorization: Bearer ...",
        token === "eyJhbGciOiJIUzI1NiJ9.payload.sig");
}

function testExtractBearerCaseInsensitiveScheme() {
  // RFC 6750 §2.1 — scheme is case-insensitive.
  var lower = b.requestHelpers.extractBearer({
    headers: { authorization: "bearer abc" },
  });
  var upper = b.requestHelpers.extractBearer({
    headers: { authorization: "BEARER abc" },
  });
  var mixed = b.requestHelpers.extractBearer({
    headers: { authorization: "BeArEr abc" },
  });
  check("extractBearer: lowercase scheme accepted", lower === "abc");
  check("extractBearer: uppercase scheme accepted", upper === "abc");
  check("extractBearer: mixed-case scheme accepted", mixed === "abc");
}

function testExtractBearerCapitalAuthorizationKey() {
  // Some shim layers populate `Authorization` with capital A; Node's
  // http parser lowercases by default but the helper tolerates the
  // capital form too.
  var token = b.requestHelpers.extractBearer({
    headers: { Authorization: "Bearer abc" },
  });
  check("extractBearer: tolerates capital Authorization key", token === "abc");
}

function testExtractBearerMissingHeader() {
  check("extractBearer: missing Authorization → null",
        b.requestHelpers.extractBearer({ headers: {} }) === null);
  check("extractBearer: empty Authorization → null",
        b.requestHelpers.extractBearer({ headers: { authorization: "" } }) === null);
  check("extractBearer: null req → null",
        b.requestHelpers.extractBearer(null) === null);
  check("extractBearer: missing headers → null",
        b.requestHelpers.extractBearer({}) === null);
}

function testExtractBearerNonBearerScheme() {
  check("extractBearer: Basic scheme → null",
        b.requestHelpers.extractBearer({
          headers: { authorization: "Basic dXNlcjpwYXNz" },
        }) === null);
  check("extractBearer: Digest scheme → null",
        b.requestHelpers.extractBearer({
          headers: { authorization: "Digest abc" },
        }) === null);
}

function testExtractBearerMalformed() {
  check("extractBearer: 'Bearer' (no token) → null",
        b.requestHelpers.extractBearer({
          headers: { authorization: "Bearer" },
        }) === null);
  check("extractBearer: 'Bearer ' (empty token) → null",
        b.requestHelpers.extractBearer({
          headers: { authorization: "Bearer " },
        }) === null);
  check("extractBearer: 'Bearer  abc' (double space surface) returns null when token is empty",
        b.requestHelpers.extractBearer({
          headers: { authorization: "Bearer       " },
        }) === null);
}

function testExtractBearerControlBytes() {
  // CRLF injection / response-splitting class.
  check("extractBearer: CR in header → null",
        b.requestHelpers.extractBearer({
          headers: { authorization: "Bearer abc\rinjected" },
        }) === null);
  check("extractBearer: LF in header → null",
        b.requestHelpers.extractBearer({
          headers: { authorization: "Bearer abc\ninjected" },
        }) === null);
  check("extractBearer: NUL in header → null",
        b.requestHelpers.extractBearer({
          headers: { authorization: "Bearer abc\x00trail" },
        }) === null);
  check("extractBearer: tab in header → null",
        b.requestHelpers.extractBearer({
          headers: { authorization: "Bearer abc\tdef" },
        }) === null);
}

function testExtractBearerEmbeddedSpace() {
  // Embedded space slips a second value past callers reading suffixes
  // as JWT / opaque-id.
  check("extractBearer: embedded space in token → null",
        b.requestHelpers.extractBearer({
          headers: { authorization: "Bearer abc def" },
        }) === null);
}

function testExtractBearerMultipleAuthHeaders() {
  // CWE-345 trust mismatch — refuse multi-Authorization.
  var twoRaw = b.requestHelpers.extractBearer({
    rawHeaders: ["Authorization", "Bearer first", "Authorization", "Bearer second"],
    headers:    { authorization: "Bearer first" },
  });
  check("extractBearer: multiple Authorization rawHeaders → null", twoRaw === null);

  // Pre-folded duplicate (Node's default: Authorization values get
  // joined with ", "). Comma in value triggers the same refusal.
  var folded = b.requestHelpers.extractBearer({
    headers: { authorization: "Bearer first, Bearer second" },
  });
  check("extractBearer: comma-folded duplicate Authorization → null", folded === null);
}

function testExtractBearerNonString() {
  check("extractBearer: non-string Authorization → null",
        b.requestHelpers.extractBearer({
          headers: { authorization: 42 },
        }) === null);
  check("extractBearer: array Authorization → null",
        b.requestHelpers.extractBearer({
          headers: { authorization: ["Bearer abc"] },
        }) === null);
}

function testExtractBearerLeadingTrailingSpaces() {
  // Tolerate leading/trailing whitespace in the token portion (RFC 7230
  // OWS) while still rejecting embedded spaces.
  var t = b.requestHelpers.extractBearer({
    headers: { authorization: "Bearer  abc  " },
  });
  check("extractBearer: trims leading + trailing whitespace from token", t === "abc");
}

function testClientIpDefaultIgnoresXff() {
  // Default: socket address only — X-Forwarded-For is attacker-forgeable.
  var req = { socket: { remoteAddress: "10.0.0.1" },
    headers: { "x-forwarded-for": "203.0.113.7, 10.0.0.5" } };
  check("clientIp default → socket addr", b.requestHelpers.clientIp(req) === "10.0.0.1");
}

function testClientIpPeerGatedTrustedPeer() {
  // Predicate form: peer 10.0.0.1 is a trusted proxy → first untrusted hop
  // walking right-to-left is the real client.
  var trust = function (a) { return a.indexOf("10.") === 0; };
  var req = { socket: { remoteAddress: "10.0.0.1" },
    headers: { "x-forwarded-for": "203.0.113.7, 10.0.0.5" } };
  check("clientIp peer-gated (trusted peer) → first untrusted hop",
    b.requestHelpers.clientIp(req, { trustProxy: trust }) === "203.0.113.7");
}

function testClientIpPeerGatedUntrustedPeerIgnoresXff() {
  // The bypass: a direct attacker (socket peer NOT a trusted proxy) forging
  // an XFF must NOT be believed — fall through to the socket address.
  var trust = function (a) { return a.indexOf("10.") === 0; };
  var forged = { socket: { remoteAddress: "198.51.100.66" },
    headers: { "x-forwarded-for": "203.0.113.7" } };
  check("clientIp peer-gated (untrusted peer) → ignores forged XFF",
    b.requestHelpers.clientIp(forged, { trustProxy: trust }) === "198.51.100.66");
}

function testClientIpPeerGatedAllHopsTrusted() {
  // Whole chain trusted (no untrusted hop) → earliest claimed client.
  var trust = function (a) { return a.indexOf("10.") === 0; };
  var req = { socket: { remoteAddress: "10.0.0.1" },
    headers: { "x-forwarded-for": "10.0.0.9, 10.0.0.5" } };
  check("clientIp peer-gated (all trusted) → leftmost",
    b.requestHelpers.clientIp(req, { trustProxy: trust }) === "10.0.0.9");
}

function testTrustProxyRequiresBooleanTrue() {
  // Function-form trustProxy must return an EXACT boolean true — an async
  // (Promise) or truthy-non-boolean predicate must NOT trust the peer, else a
  // forged X-Forwarded-* header would be honored for an access-control decision.
  var asyncTrust = async function () { return true; };
  var truthyTrust = function () { return 1; };
  var ipReq = { socket: { remoteAddress: "10.0.0.9" }, headers: { "x-forwarded-for": "203.0.113.7" } };
  check("clientIp: an async trustProxy is NOT trusted (falls to socket addr)",
    b.requestHelpers.clientIp(ipReq, { trustProxy: asyncTrust }) === "10.0.0.9");
  check("clientIp: a truthy-non-boolean trustProxy is NOT trusted",
    b.requestHelpers.clientIp(ipReq, { trustProxy: truthyTrust }) === "10.0.0.9");
  var protoReq = { socket: { encrypted: false, remoteAddress: "10.0.0.9" }, headers: { "x-forwarded-proto": "https" } };
  check("requestProtocol: an async trustProxy is NOT trusted (ignores forged X-Forwarded-Proto)",
    b.requestHelpers.requestProtocol(protoReq, { trustProxy: asyncTrust }) === "http");
  var hostReq = { socket: { remoteAddress: "10.0.0.9" }, headers: { host: "real.example", "x-forwarded-host": "evil.example" } };
  check("requestHost: an async trustProxy is NOT trusted (ignores forged X-Forwarded-Host)",
    b.requestHelpers.requestHost(hostReq, { trustProxy: asyncTrust }) === "real.example");
}

function testClientIpLegacyFormsStillWork() {
  // Legacy spoofable forms preserved for edge-terminated deployments.
  var req = { socket: { remoteAddress: "10.0.0.1" },
    headers: { "x-forwarded-for": "203.0.113.7, 10.0.0.5" } };
  check("clientIp legacy true → leftmost", b.requestHelpers.clientIp(req, { trustProxy: true }) === "203.0.113.7");
  check("clientIp legacy N=1 → Nth-from-right", b.requestHelpers.clientIp(req, { trustProxy: 1 }) === "10.0.0.5");
}

function testTrustedClientIpPeerGatedFlag() {
  check("trustedClientIp default → not peerGated",
    b.requestHelpers.trustedClientIp().peerGated === false);
  check("trustedClientIp trustedProxies → peerGated",
    b.requestHelpers.trustedClientIp({ trustedProxies: ["10.0.0.0/8"] }).peerGated === true);
  check("trustedClientIp clientIpResolver → peerGated",
    b.requestHelpers.trustedClientIp({ clientIpResolver: function () { return "1.2.3.4"; } }).peerGated === true);
}

function testTrustedClientIpResolves() {
  var pg = b.requestHelpers.trustedClientIp({ trustedProxies: ["10.0.0.0/8"] });
  var forged = { socket: { remoteAddress: "198.51.100.66" },
    headers: { "x-forwarded-for": "203.0.113.7" } };
  check("trustedClientIp peer-gated ignores forged XFF (untrusted peer)",
    pg.resolve(forged) === "198.51.100.66");
  var viaProxy = { socket: { remoteAddress: "10.0.0.9" },
    headers: { "x-forwarded-for": "203.0.113.7" } };
  check("trustedClientIp peer-gated honors XFF behind trusted proxy",
    pg.resolve(viaProxy) === "203.0.113.7");
  var owned = b.requestHelpers.trustedClientIp({ clientIpResolver: function (rq) { return rq.headers["true-client-ip"]; } });
  check("trustedClientIp clientIpResolver wins",
    owned.resolve({ headers: { "true-client-ip": "9.9.9.9" } }) === "9.9.9.9");
}

// The peer gate is the same; only WHICH forwarded header carries the address
// changes. Cloudflare publishes CF-Connecting-IP and the common nginx recipe
// publishes X-Real-IP, so a deployment behind either had no way to use this
// resolver: reading the header directly loses the gate, and clientIpResolver
// hands back the whole trust decision (CIDR matching, mapped-IPv6 folding)
// while still reporting peerGated.
function testTrustedClientIpForwardedHeaderFamily() {
  var viaCf = {
    socket:  { remoteAddress: "10.0.0.9" },
    headers: { "cf-connecting-ip": "203.0.113.9" },
  };
  var cf = b.requestHelpers.trustedClientIp({
    trustedProxies:   ["10.0.0.0/8"],
    forwardedHeaders: ["cf-connecting-ip"],
  });
  check("trustedClientIp honors a named forwarded header behind a trusted peer",
        cf.resolve(viaCf) === "203.0.113.9");

  // The gate is unchanged: the same header from a peer that is not a declared
  // proxy is ignored, exactly as X-Forwarded-For is.
  var forged = {
    socket:  { remoteAddress: "198.51.100.66" },
    headers: { "cf-connecting-ip": "203.0.113.9" },
  };
  check("trustedClientIp ignores a named forwarded header from an untrusted peer",
        cf.resolve(forged) === "198.51.100.66");

  // With no trustedProxies at all the family is ignored outright — naming a
  // header must not become a second, ungated trust path.
  var ungated = b.requestHelpers.trustedClientIp({ forwardedHeaders: ["cf-connecting-ip"] });
  check("trustedClientIp with no trustedProxies ignores the named family",
        ungated.resolve(viaCf) === "10.0.0.9");
  check("trustedClientIp with only forwardedHeaders is not peerGated",
        ungated.peerGated === false);

  // Order is the operator's: the first header PRESENT on the request wins,
  // whether or not later ones are also present.
  var both = {
    socket:  { remoteAddress: "10.0.0.9" },
    headers: { "x-real-ip": "203.0.113.20", "x-forwarded-for": "203.0.113.30" },
  };
  var ordered = b.requestHelpers.trustedClientIp({
    trustedProxies:   ["10.0.0.0/8"],
    forwardedHeaders: ["x-real-ip", "x-forwarded-for"],
  });
  check("trustedClientIp takes the first PRESENT header in the declared order",
        ordered.resolve(both) === "203.0.113.20");
  var reversed = b.requestHelpers.trustedClientIp({
    trustedProxies:   ["10.0.0.0/8"],
    forwardedHeaders: ["x-forwarded-for", "x-real-ip"],
  });
  check("trustedClientIp order is the operator's, not a fixed precedence",
        reversed.resolve(both) === "203.0.113.30");

  // PRESENT decides, not non-empty. A first-listed header that arrives empty
  // says this request carries no forwarded address; falling through to a
  // lower-priority header would answer with one the client may have set.
  var emptyFirst = {
    socket:  { remoteAddress: "10.0.0.9" },
    headers: { "x-real-ip": "", "x-forwarded-for": "203.0.113.30" },
  };
  check("trustedClientIp stops at an empty higher-priority header",
        ordered.resolve(emptyFirst) === "10.0.0.9");
  // Absent is different from empty — that one is skipped.
  check("trustedClientIp skips an ABSENT higher-priority header",
        ordered.resolve({ socket: { remoteAddress: "10.0.0.9" },
                          headers: { "x-forwarded-for": "203.0.113.30" } }) === "203.0.113.30");

  // A header earlier in the list but absent from the request is skipped.
  var onlyXff = {
    socket:  { remoteAddress: "10.0.0.9" },
    headers: { "x-forwarded-for": "203.0.113.30" },
  };
  check("trustedClientIp falls through an absent header to the next named one",
        ordered.resolve(onlyXff) === "203.0.113.30");

  // Node lowercases incoming header names; an operator writing the vendor's
  // documented casing must not silently match nothing.
  var cased = b.requestHelpers.trustedClientIp({
    trustedProxies:   ["10.0.0.0/8"],
    forwardedHeaders: ["CF-Connecting-IP"],
  });
  check("trustedClientIp matches a header named in the vendor's casing",
        cased.resolve(viaCf) === "203.0.113.9");

  // A multi-value chain in a named header walks right-to-left exactly as
  // X-Forwarded-For does — a single address is simply a one-hop chain.
  var chained = {
    socket:  { remoteAddress: "10.0.0.9" },
    headers: { "x-real-ip": "203.0.113.40, 10.0.0.5" },
  };
  check("trustedClientIp walks a chained named header right-to-left",
        b.requestHelpers.trustedClientIp({
          trustedProxies:   ["10.0.0.0/8"],
          forwardedHeaders: ["x-real-ip"],
        }).resolve(chained) === "203.0.113.40");

  // Default is unchanged for every existing caller.
  var dflt = b.requestHelpers.trustedClientIp({ trustedProxies: ["10.0.0.0/8"] });
  check("trustedClientIp default family is still X-Forwarded-For only",
        dflt.resolve(onlyXff) === "203.0.113.30" && dflt.resolve(viaCf) === "10.0.0.9");

  // The low-level reader carries the same opt so a caller that already drives
  // clientIp directly is not forced up to the resolver to get the family.
  var trust = function (a) { return a.indexOf("10.") === 0; };
  check("clientIp accepts forwardedHeaders alongside a trustProxy predicate",
        b.requestHelpers.clientIp(viaCf, { trustProxy: trust, forwardedHeaders: ["cf-connecting-ip"] })
          === "203.0.113.9");
  check("clientIp without forwardedHeaders still reads X-Forwarded-For only",
        b.requestHelpers.clientIp(viaCf, { trustProxy: trust }) === "10.0.0.9");
}

// clientIp is a request-shape reader on the hot path, documented never to
// throw. Strict validation belongs at construction, where a typo is a config
// mistake caught at boot — not on a live request, where the same typo would
// escape as an exception from whatever gate happened to call it.
function testClientIpToleratesMalformedForwardedHeaders() {
  var trust = function (a) { return a.indexOf("10.") === 0; };
  var viaProxy = {
    socket:  { remoteAddress: "10.0.0.9" },
    headers: { "x-forwarded-for": "203.0.113.7", "cf-connecting-ip": "203.0.113.8" },
  };
  [["a bare string", "cf-connecting-ip"], ["a number", 7], ["an empty array", []],
   ["a non-string member", ["x-forwarded-for", 7]], ["a member with a space", ["x forwarded for"]],
   ["an object", {}]].forEach(function (pair) {
    var out, threw = false;
    try { out = b.requestHelpers.clientIp(viaProxy, { trustProxy: trust, forwardedHeaders: pair[1] }); }
    catch (_e) { threw = true; }
    check("clientIp does not throw on forwardedHeaders as " + pair[0], threw === false);
    // Falling back to the socket address, not to X-Forwarded-For: reading a
    // header the operator did not ask for is the wrong way to fail.
    check("clientIp falls back to the socket address on " + pair[0], out === "10.0.0.9");
  });
  // A well-formed family still works, so the tolerance is not blanket.
  check("clientIp still honours a well-formed family",
        b.requestHelpers.clientIp(viaProxy, { trustProxy: trust, forwardedHeaders: ["cf-connecting-ip"] })
          === "203.0.113.8");
  // The construction-time path stays strict.
  var threwAtBuild = false;
  try { b.requestHelpers.trustedClientIp({ trustedProxies: ["10.0.0.0/8"], forwardedHeaders: "nope" }); }
  catch (_e) { threwAtBuild = true; }
  check("trustedClientIp still refuses the same value at construction", threwAtBuild);
}

function testTrustedClientIpForwardedHeadersValidated() {
  var bad = [
    ["a string",            "cf-connecting-ip"],
    ["a number",            7],
    ["an empty array",      []],
    ["a non-string member", ["x-forwarded-for", 7]],
    ["an empty member",     ["x-forwarded-for", ""]],
    ["a member with a space", ["x forwarded for"]],
    ["a member with a colon", ["x-real-ip:"]],
  ];
  bad.forEach(function (pair) {
    var err = null;
    try {
      b.requestHelpers.trustedClientIp({ trustedProxies: ["10.0.0.0/8"], forwardedHeaders: pair[1] });
    } catch (e) { err = e; }
    check("trustedClientIp refuses forwardedHeaders as " + pair[0], err !== null);
  });
}

function testTrustedProxyMappedPeerNormalized() {
  // A dual-stack listener reports an IPv4 proxy peer as an IPv4-mapped IPv6
  // address (::ffff:10.0.0.9). It must still match an IPv4 trustedProxies CIDR
  // so X-Forwarded-* is honored — otherwise the proxy is treated as untrusted
  // and the gate keys on the proxy address / misclassifies the scheme.
  var pg = b.requestHelpers.trustedClientIp({ trustedProxies: ["10.0.0.0/8"] });
  var viaMapped = { socket: { remoteAddress: "::ffff:10.0.0.9" },
    headers: { "x-forwarded-for": "203.0.113.7" } };
  check("trustedClientIp recognizes an IPv4-mapped trusted-proxy peer",
    pg.resolve(viaMapped) === "203.0.113.7");

  var tp = b.requestHelpers.trustedProtocol({ trustedProxies: ["10.0.0.0/8"] });
  var mappedHttps = { socket: { encrypted: false, remoteAddress: "::ffff:10.0.0.9" },
    headers: { "x-forwarded-proto": "https" } };
  check("trustedProtocol recognizes an IPv4-mapped trusted-proxy peer",
    tp.resolve(mappedHttps) === "https");

  // A direct (untrusted) IPv4-mapped peer still can't forge: not in the CIDR.
  var forgedMapped = { socket: { remoteAddress: "::ffff:198.51.100.66" },
    headers: { "x-forwarded-for": "203.0.113.7" } };
  check("trustedClientIp still ignores forged XFF from an untrusted mapped peer",
    pg.resolve(forgedMapped) === "::ffff:198.51.100.66");
}

function testTrustedProtocol() {
  var tp = b.requestHelpers.trustedProtocol({ trustedProxies: ["10.0.0.0/8"] });
  check("trustedProtocol trustedProxies → peerGated", tp.peerGated === true);
  check("trustedProtocol default → not peerGated", b.requestHelpers.trustedProtocol().peerGated === false);
  var forged = { socket: { encrypted: false, remoteAddress: "198.51.100.66" }, headers: { "x-forwarded-proto": "https" } };
  check("trustedProtocol: forged XFP from untrusted peer → http", tp.resolve(forged) === "http");
  var viaProxy = { socket: { encrypted: false, remoteAddress: "10.0.0.9" }, headers: { "x-forwarded-proto": "https" } };
  check("trustedProtocol: XFP via trusted proxy → https", tp.resolve(viaProxy) === "https");
  var realTls = { socket: { encrypted: true, remoteAddress: "203.0.113.1" }, headers: {} };
  check("trustedProtocol: real TLS socket → https", tp.resolve(realTls) === "https");
  var owned = b.requestHelpers.trustedProtocol({ protocolResolver: function () { return "https"; } });
  check("trustedProtocol: protocolResolver wins", owned.resolve({}) === "https");
  var threwBadCidr = false;
  try { b.requestHelpers.trustedProtocol({ trustedProxies: ["nope"] }); } catch (_e) { threwBadCidr = true; }
  check("trustedProtocol: malformed CIDR refused", threwBadCidr === true);
}

function testTrustedClientIpValidates() {
  var threwResolver = false;
  try { b.requestHelpers.trustedClientIp({ clientIpResolver: 123 }); } catch (_e) { threwResolver = true; }
  check("trustedClientIp rejects non-function resolver", threwResolver === true);
  var threwCidr = false;
  try { b.requestHelpers.trustedClientIp({ trustedProxies: ["not-a-cidr"] }); } catch (_e) { threwCidr = true; }
  check("trustedClientIp rejects malformed CIDR", threwCidr === true);
}

function testIpPrefixMasking() {
  var ip = b.requestHelpers.ipPrefix;
  check("ipPrefix is a function", typeof ip === "function");
  // IPv4 → /24 (network address, low octet zeroed).
  check("ipPrefix v4 masks to /24", ip("203.0.113.47") === "203.0.113.0/24");
  check("ipPrefix v4 same /24 → same bucket", ip("203.0.113.47") === ip("203.0.113.250"));
  check("ipPrefix v4 cross-/24 → different bucket", ip("203.0.113.1") !== ip("198.51.100.1"));
  // IPv6 → /64 (low 64 bits zeroed), deterministic uncompressed emit.
  check("ipPrefix v6 masks to /64", ip("2001:db8:1234:5678::1") === "2001:db8:1234:5678:0:0:0:0/64");
  check("ipPrefix v6 same /64 → same bucket",
    ip("2001:db8:1234:5678::1") === ip("2001:db8:1234:5678:abcd:ef01:2345:6789"));
  check("ipPrefix v6 cross-/64 → different bucket",
    ip("2001:db8:1234:5678::1") !== ip("2001:db8:1234:9999::1"));
  // IPv4-mapped IPv6 folds to the v4 /24 bucket.
  check("ipPrefix folds ::ffff: mapped v4 to the v4 bucket",
    ip("::ffff:203.0.113.5") === ip("203.0.113.99"));
  // Garbage / non-string → "" (never throws).
  check("ipPrefix returns '' for a non-string", ip(null) === "" && ip(12345) === "");
  check("ipPrefix returns '' for an empty string", ip("") === "");
  check("ipPrefix returns '' for an unparseable address", ip("not-an-ip") === "");
  check("ipPrefix rejects an out-of-range v4 octet", ip("999.0.0.1") === "");
}

// #352 — ipKey: IPv4 verbatim (exact host), IPv6 collapsed to /64 so one
// end-site can't rotate the low 64 bits to mint unlimited rate-limit keys.
function testIpKeyForRateLimit() {
  var k = b.requestHelpers.ipKey;
  check("ipKey is a function", typeof k === "function");
  // IPv4 kept exact (no /24 masking, no /32 suffix) — one IPv4 is one host.
  check("ipKey v4 exact verbatim", k("203.0.113.47") === "203.0.113.47");
  check("ipKey v4 distinct hosts → distinct keys", k("203.0.113.47") !== k("203.0.113.48"));
  // IPv6 → /64; rotating the low 64 bits yields the SAME key (the defense).
  var k64 = k("2001:db8:1:2:dead:beef:0:1");
  check("ipKey v6 → /64 suffix, low bits zeroed",
        /\/64$/.test(k64) && k64.indexOf("dead") === -1);
  check("ipKey v6 low-64 rotation → same key (rotation defeated)",
        k("2001:db8:1:2:dead:beef:0:1") === k("2001:db8:1:2:ffff:ffff:ffff:ffff"));
  check("ipKey v6 different /64 → different key",
        k("2001:db8:1:2::1") !== k("2001:db8:1:3::1"));
  // Configurable width.
  check("ipKey v6 ipv6Bits=48 widens the bucket", /\/48$/.test(k("2001:db8:1:2::1", { ipv6Bits: 48 })));
  // IPv4-mapped IPv6 folds to its exact dotted host.
  check("ipKey folds ::ffff: mapped v4 to the exact v4 host",
        k("::ffff:203.0.113.47") === "203.0.113.47");
  // Defensive defaults — never throws, "" on bad input (caller falls back).
  check("ipKey '' for non-string", k(null) === "" && k(12345) === "");
  check("ipKey '' for empty", k("") === "");
  check("ipKey '' for unparseable", k("not-an-ip") === "");
  check("ipKey '' for out-of-range v4 octet", k("999.0.0.1") === "");
  // Distinct from ipPrefix: ipKey keeps v4 exact where ipPrefix masks to /24.
  check("ipKey v4 != ipPrefix v4 (exact vs /24)",
        k("203.0.113.47") !== b.requestHelpers.ipPrefix("203.0.113.47"));
}

function testTrustedIdentityHeaders() {
  var TP = ["10.0.0.0/8"];
  var HDRS = { login: "Tailscale-User-Login", name: "Tailscale-User-Name" };
  var ident = b.requestHelpers.trustedIdentityHeaders({ trustedProxies: TP, headers: HDRS });
  check("trustedIdentityHeaders: peerGated when trustedProxies given", ident.peerGated === true);
  check("trustedIdentityHeaders: headerNames lowercased",
    ident.headerNames.indexOf("tailscale-user-login") !== -1);

  // Trusted peer (10.x) → identity surfaced from the family headers.
  var trustedReq = { socket: { remoteAddress: "10.0.0.5" },
    headers: { "tailscale-user-login": "alice@example.com", "tailscale-user-name": "Alice" } };
  var r = ident.resolve(trustedReq);
  check("trustedIdentityHeaders: trusted peer → trusted + identity",
    r.trusted === true && r.identity.login === "alice@example.com" && r.identity.name === "Alice");

  // Untrusted peer presenting a FORGED identity header → not trusted, empty identity.
  var forged = { socket: { remoteAddress: "198.51.100.66" },
    headers: { "tailscale-user-login": "attacker@evil.example" } };
  var rf = ident.resolve(forged);
  check("trustedIdentityHeaders: untrusted peer → not trusted, empty identity",
    rf.trusted === false && Object.keys(rf.identity).length === 0);

  // middleware: trusted sets req[as]; untrusted STRIPS the forged header + nulls it.
  ident.middleware(trustedReq, {}, function () {});
  check("trustedIdentityHeaders middleware: trusted sets req.proxyIdentity",
    trustedReq.proxyIdentity && trustedReq.proxyIdentity.login === "alice@example.com");
  ident.middleware(forged, {}, function () {});
  check("trustedIdentityHeaders middleware: untrusted STRIPS the forged header (impersonation blocked)",
    forged.headers["tailscale-user-login"] === undefined && forged.proxyIdentity === null);

  // No gate → fail-closed: never trusted, always strips.
  var nogate = b.requestHelpers.trustedIdentityHeaders({ headers: HDRS });
  check("trustedIdentityHeaders: no gate → not peerGated (fail-closed)", nogate.peerGated === false);
  var wouldBe = { socket: { remoteAddress: "10.0.0.5" }, headers: { "tailscale-user-login": "x" } };
  nogate.middleware(wouldBe, {}, function () {});
  check("trustedIdentityHeaders: no gate strips even a would-be-trusted peer",
    wouldBe.headers["tailscale-user-login"] === undefined);

  // peerTrust must return an EXACT synchronous `true` — an async (Promise) or
  // truthy-non-boolean result is NOT trusted (a Promise is truthy and would
  // otherwise let an untrusted peer be impersonated).
  var aReq = { socket: { remoteAddress: "1.2.3.4" }, headers: { "tailscale-user-login": "x" } };
  var asyncPt = b.requestHelpers.trustedIdentityHeaders({ headers: HDRS, peerTrust: async function () { return true; } });
  check("trustedIdentityHeaders: an async peerTrust (returns a Promise) is NOT trusted",
    asyncPt.resolve(aReq).trusted === false);
  var truthyPt = b.requestHelpers.trustedIdentityHeaders({ headers: HDRS, peerTrust: function () { return 1; } });
  check("trustedIdentityHeaders: a truthy-non-boolean peerTrust is NOT trusted",
    truthyPt.resolve(aReq).trusted === false);

  // Custom peerTrust predicate + custom 'as' property.
  var pt = b.requestHelpers.trustedIdentityHeaders({ headers: HDRS, peerTrust: function () { return true; }, as: "who" });
  var ptReq = { socket: { remoteAddress: "1.2.3.4" }, headers: { "tailscale-user-login": "svc" } };
  pt.middleware(ptReq, {}, function () {});
  check("trustedIdentityHeaders: custom peerTrust + custom 'as' surfaces identity",
    ptReq.who && ptReq.who.login === "svc");

  // _socketAddr falls back to the legacy req.connection when socket has no
  // string remoteAddress (older Node request shapes / proxied streams).
  var connReq = { socket: {}, connection: { remoteAddress: "10.0.0.9" },
    headers: { "tailscale-user-login": "legacy@example.com" } };
  var rc = ident.resolve(connReq);
  check("trustedIdentityHeaders: req.connection remoteAddress fallback is honoured",
    rc.trusted === true && rc.identity.login === "legacy@example.com");
  // A peer with no resolvable address (neither socket nor connection) is untrusted.
  var noAddr = ident.resolve({ socket: {}, headers: { "tailscale-user-login": "x" } });
  check("trustedIdentityHeaders: a peer with no resolvable address is not trusted", noAddr.trusted === false);

  // Config-time validation.
  function threw(fn) { try { fn(); return null; } catch (e) { return e; } }
  check("trustedIdentityHeaders: no opts refused (defaults applied, then headers required)",
    threw(function () { b.requestHelpers.trustedIdentityHeaders(); }) !== null);
  check("trustedIdentityHeaders: missing headers refused",
    threw(function () { b.requestHelpers.trustedIdentityHeaders({ trustedProxies: TP }); }) !== null);
  check("trustedIdentityHeaders: empty headers refused",
    threw(function () { b.requestHelpers.trustedIdentityHeaders({ headers: {} }); }) !== null);
  check("trustedIdentityHeaders: non-string header name refused",
    threw(function () { b.requestHelpers.trustedIdentityHeaders({ headers: { login: 123 } }); }) !== null);
  check("trustedIdentityHeaders: bad peerTrust refused",
    threw(function () { b.requestHelpers.trustedIdentityHeaders({ headers: HDRS, peerTrust: "nope" }); }) !== null);
}

async function run() {
  testSurface();
  testSafeHeadersDistinct();
  testIpPrefixMasking();
  testIpKeyForRateLimit();
  testClientIpDefaultIgnoresXff();
  testClientIpPeerGatedTrustedPeer();
  testClientIpPeerGatedUntrustedPeerIgnoresXff();
  testClientIpPeerGatedAllHopsTrusted();
  testTrustProxyRequiresBooleanTrue();
  testClientIpLegacyFormsStillWork();
  testTrustedClientIpPeerGatedFlag();
  testTrustedClientIpResolves();
  testTrustedClientIpForwardedHeaderFamily();
  testTrustedClientIpForwardedHeadersValidated();
  testClientIpToleratesMalformedForwardedHeaders();
  testTrustedIdentityHeaders();
  testTrustedProxyMappedPeerNormalized();
  testTrustedProtocol();
  testRequestProtocolNoProxy();
  testRequestProtocolPeerGatedTrustedProxy();
  testRequestProtocolPeerGatedUntrustedProxyIgnoresForgedHeader();
  testRequestProtocolLegacyTrustProxyTrue();
  testAppendVary();
  testTrustedClientIpValidates();
  testResolveRoutePrefersRoutePattern();
  testResolveRouteFallsBackToUrl();
  testResolveRouteEmptyOrMissingUrl();
  testResolveRouteIgnoresEmptyRoutePattern();
  await testCaptureStatusFromWriteHead();
  await testCaptureStatusFromStatusCode();
  await testCaptureStatusDefaults200();
  await testCaptureStatusOnEndThrowDoesntBreakResponse();
  testCaptureStatusValidatesArgs();
  testParseListHeader();
  testParseQualityListQuoteAware();
  testExtractBearerSurface();
  testExtractBearerHappyPath();
  testExtractBearerCaseInsensitiveScheme();
  testExtractBearerCapitalAuthorizationKey();
  testExtractBearerMissingHeader();
  testExtractBearerNonBearerScheme();
  testExtractBearerMalformed();
  testExtractBearerControlBytes();
  testExtractBearerEmbeddedSpace();
  testExtractBearerMultipleAuthHeaders();
  testExtractBearerNonString();
  testExtractBearerLeadingTrailingSpaces();
  testMakeSkipMatcher();
  testMakeResourceAuditEmitter();
  testStatusPredicatesClassifyWholeNumbersOnly();
}

// `failAfterHeaders` asks `C.HTTP.bodiless` whether a response carries a body,
// so the predicates are part of the request path rather than a lookup table
// beside it.
function testStatusPredicatesClassifyWholeNumbersOnly() {
  var HTTP = b.constants.HTTP;

  check("a 1xx is informational and carries no body",
        HTTP.informational(HTTP.STATUS.CONTINUE) === true &&
        HTTP.bodiless(HTTP.STATUS.CONTINUE) === true);
  check("204, 205 and 304 carry no body either",
        HTTP.bodiless(HTTP.STATUS.NO_CONTENT) === true &&
        HTTP.bodiless(HTTP.STATUS.RESET_CONTENT) === true &&
        HTTP.bodiless(HTTP.STATUS.NOT_MODIFIED) === true);
  check("and an ordinary 200 does",
        HTTP.bodiless(HTTP.STATUS.OK) === false && HTTP.success(HTTP.STATUS.OK) === true);
  check("each class answers for its own range",
        HTTP.redirect(HTTP.STATUS.FOUND) === true &&
        HTTP.clientError(HTTP.STATUS.NOT_FOUND) === true &&
        HTTP.serverError(HTTP.STATUS.BAD_GATEWAY) === true &&
        HTTP.success(HTTP.STATUS.NOT_FOUND) === false);

  // A status is a three-digit integer. A fraction that lands inside a range is
  // not one, and answering that it is would let a status arrived at by
  // arithmetic pass here and be refused later by the socket, with the handler
  // already run and the headers already sent.
  var refused = [];
  [200.5, 150.5, 304.1, -0.5, NaN, Infinity, "200", null, undefined, {}]
    .forEach(function (bad) {
      var threw = false;
      try { HTTP.success(bad); } catch (_e) { threw = true; }
      if (!threw) refused.push(JSON.stringify(bad) + " was accepted");
    });
  check("a status that is not a whole number is refused rather than classified" +
        (refused.length ? " — " + refused.join(" | ") : ""), refused.length === 0);

  // A whole number outside the bands is ANSWERED, not refused: `b.webhook`
  // reports on a delivery whose transport failed with the status defaulted to
  // zero, and throwing there would turn a failed delivery into a crash.
  var answered = true;
  try {
    answered = HTTP.success(0) === false && HTTP.serverError(0) === false &&
               HTTP.bodiless(0) === false && HTTP.success(999) === false;
  } catch (_e) { answered = false; }
  check("a whole number outside every band is answered false, not thrown at",
        answered === true);
}

function testMakeResourceAuditEmitter() {
  var events = [];
  var sink = { safeEmit: function (e) { events.push(e); } };

  // idFor derives the resource id; no req → no actor.
  var emit = b.requestHelpers.makeResourceAuditEmitter(sink, "auth.lockout",
    function (key) { return "ns:" + key; });
  check("makeResourceAuditEmitter: returns an emitter", typeof emit === "function");
  emit("locked", "k1", "denied", { attempts: 3 }, null);
  check("makeResourceAuditEmitter: event action/outcome",
    events[0] && events[0].action === "locked" && events[0].outcome === "denied");
  check("makeResourceAuditEmitter: resource kind + idFor-derived id",
    events[0].resource && events[0].resource.kind === "auth.lockout" && events[0].resource.id === "ns:k1");
  check("makeResourceAuditEmitter: metadata passed through", events[0].metadata.attempts === 3);
  check("makeResourceAuditEmitter: no req → no actor", events[0].actor === undefined);

  // default idFor = key verbatim; req → actor stamped.
  var emit2 = b.requestHelpers.makeResourceAuditEmitter(sink, "session.device");
  emit2("rotated", "tok-hash", "success", {}, { socket: { remoteAddress: "1.2.3.4" }, headers: {} });
  check("makeResourceAuditEmitter: default idFor is the key verbatim", events[1].resource.id === "tok-hash");
  check("makeResourceAuditEmitter: req → actor stamped", events[1].actor !== undefined);

  // falsy sink → disabled (operator opted out).
  var n = events.length;
  b.requestHelpers.makeResourceAuditEmitter(null, "x")("a", "k", "o", {}, null);
  check("makeResourceAuditEmitter: falsy sink disables emit", events.length === n);

  // a throwing sink is swallowed (never breaks the request).
  var threw = false;
  try {
    b.requestHelpers.makeResourceAuditEmitter({ safeEmit: function () { throw new Error("boom"); } }, "x")
      ("a", "k", "o", {}, null);
  } catch (_e) { threw = true; }
  check("makeResourceAuditEmitter: throwing sink is drop-silent", threw === false);
}

function testMakeSkipMatcher() {
  var shouldSkip = b.requestHelpers.makeSkipMatcher(
    { skipPaths: ["/healthz", /^\/webhooks\//] }, "test.makeSkipMatcher");
  check("makeSkipMatcher: returns a predicate", typeof shouldSkip === "function");
  check("makeSkipMatcher: string-prefix match",     shouldSkip({ pathname: "/healthz" }) === true);
  check("makeSkipMatcher: regexp match",            shouldSkip({ pathname: "/webhooks/stripe" }) === true);
  check("makeSkipMatcher: non-matching path",       shouldSkip({ pathname: "/account" }) === false);
  check("makeSkipMatcher: falls back to req.url",   shouldSkip({ url: "/healthz" }) === true);
  check("makeSkipMatcher: falls back to req.originalUrl", shouldSkip({ originalUrl: "/healthz" }) === true);
  check("makeSkipMatcher: missing path → '/' (no skip)", shouldSkip({}) === false);

  // SEGMENT-BOUNDARY (not raw startsWith) — the guard-bypass fix. "/healthz"
  // must NOT skip the sibling "/healthzzz", but MUST skip the descendant.
  check("makeSkipMatcher: segment boundary — sibling NOT skipped", shouldSkip({ pathname: "/healthzzz" }) === false);
  check("makeSkipMatcher: segment boundary — descendant skipped",  shouldSkip({ pathname: "/healthz/ready" }) === true);
  // Query string is stripped before matching (match on path, never the query).
  check("makeSkipMatcher: query string stripped", shouldSkip({ url: "/healthz?ready=1" }) === true);
  check("makeSkipMatcher: query can't fake a match", shouldSkip({ url: "/account?x=/healthz" }) === false);

  // A string entry ending in "/" is itself a segment prefix.
  var slashEntry = b.requestHelpers.makeSkipMatcher({ skipPaths: ["/api/"] }, "test.slash");
  check("makeSkipMatcher: trailing-slash entry matches descendant", slashEntry({ pathname: "/api/v1" }) === true);
  check("makeSkipMatcher: trailing-slash entry rejects sibling",    slashEntry({ pathname: "/apixyz" }) === false);

  // exact:true — whole-path equality only, no descendant.
  var exactM = b.requestHelpers.makeSkipMatcher({ skipPaths: ["/foo"], exact: true }, "test.exact");
  check("makeSkipMatcher: exact matches whole path", exactM({ pathname: "/foo" }) === true);
  check("makeSkipMatcher: exact rejects descendant",  exactM({ pathname: "/foo/bar" }) === false);

  // skip(req) predicate composes; a throwing predicate fails CLOSED (keeps guard ON).
  var withFn = b.requestHelpers.makeSkipMatcher(
    { skip: function (req) { return req.method === "OPTIONS"; } }, "test.skipFn");
  check("makeSkipMatcher: skip predicate true",     withFn({ method: "OPTIONS" }) === true);
  check("makeSkipMatcher: skip predicate false",    withFn({ method: "POST" }) === false);
  var throwing = b.requestHelpers.makeSkipMatcher(
    { skip: function () { throw new Error("boom"); } }, "test.skipThrow");
  check("makeSkipMatcher: throwing predicate fails closed (no skip)", throwing({}) === false);

  // Build-time validation: a bad skipPaths entry dies at boot, not on first request.
  check("makeSkipMatcher: non-array skipPaths throws",
        (function () { try { b.requestHelpers.makeSkipMatcher({ skipPaths: "x" }); return false; }
                       catch (e) { return e instanceof TypeError; } })());
  check("makeSkipMatcher: bad skipPaths entry throws",
        (function () { try { b.requestHelpers.makeSkipMatcher({ skipPaths: [123] }); return false; }
                       catch (e) { return e instanceof TypeError; } })());
  check("makeSkipMatcher: non-function skip throws",
        (function () { try { b.requestHelpers.makeSkipMatcher({ skip: "x" }); return false; }
                       catch (e) { return e instanceof TypeError; } })());
  // A ReDoS-shaped skip RegExp (wrapped nested quantifier) is screened at
  // build time, never reaching the per-request .test() on attacker paths.
  check("makeSkipMatcher: ReDoS-shaped skipPaths RegExp refused",
        (function () { try { b.requestHelpers.makeSkipMatcher({ skipPaths: [/((a)+)+$/] }); return false; }
                       catch (e) { return e instanceof Error; } })());
}

function testAppendVary() {
  // Append preserves prior tokens (compression + auth helpers each add one).
  var res = _mockRes();
  res.setHeader("Vary", "Accept-Encoding");
  b.requestHelpers.appendVary(res, "Authorization");
  check("appendVary: appends without dropping the prior token",
        res.getHeader("Vary") === "Accept-Encoding, Authorization");

  // Idempotent — re-adding an existing token (case-insensitive) is a no-op.
  b.requestHelpers.appendVary(res, "accept-encoding");
  check("appendVary: re-adding an existing token (case-insensitive) is a no-op",
        res.getHeader("Vary") === "Accept-Encoding, Authorization");

  // First token when Vary is unset.
  var fresh = _mockRes();
  b.requestHelpers.appendVary(fresh, "Origin");
  check("appendVary: sets Vary when none existed", fresh.getHeader("Vary") === "Origin");

  // Empty-string Vary is treated as unset.
  var emptyVary = _mockRes();
  emptyVary.setHeader("Vary", "");
  b.requestHelpers.appendVary(emptyVary, "Cookie");
  check("appendVary: empty existing Vary treated as unset", emptyVary.getHeader("Vary") === "Cookie");

  // Silent no-op when res doesn't expose getHeader/setHeader (never throws).
  var threw = null;
  try {
    b.requestHelpers.appendVary(null, "X");
    b.requestHelpers.appendVary({}, "X");
    b.requestHelpers.appendVary({ getHeader: function () { return null; } }, "X");
  } catch (e) { threw = e; }
  check("appendVary: no-ops (no throw) on a res without header methods", threw === null);
}

function testRequestProtocolNoProxy() {
  check("requestProtocol: encrypted socket → https",
        b.requestHelpers.requestProtocol({ socket: { encrypted: true } }) === "https");
  check("requestProtocol: plain socket → http",
        b.requestHelpers.requestProtocol({ socket: { encrypted: false } }) === "http");
  check("requestProtocol: connection.encrypted fallback → https",
        b.requestHelpers.requestProtocol({ connection: { encrypted: true } }) === "https");
  check("requestProtocol: undefined req → http", b.requestHelpers.requestProtocol(undefined) === "http");
  check("requestProtocol: null req → http", b.requestHelpers.requestProtocol(null) === "http");
}

function testRequestProtocolPeerGatedTrustedProxy() {
  // Predicate (peer-gated): X-Forwarded-Proto honored only when the immediate
  // TCP peer is a trusted proxy — the leftmost hop is returned.
  var trust = function (addr) { return addr.indexOf("10.") === 0; };
  var viaProxy = {
    socket:  { encrypted: false, remoteAddress: "10.0.0.9" },
    headers: { "x-forwarded-proto": "https, http" },
  };
  check("requestProtocol: XFP via trusted proxy peer → https",
        b.requestHelpers.requestProtocol(viaProxy, { trustProxy: trust }) === "https");
}

function testRequestProtocolPeerGatedUntrustedProxyIgnoresForgedHeader() {
  // The bypass: a direct caller whose socket peer is NOT a trusted proxy
  // cannot forge the scheme — the forged X-Forwarded-Proto is ignored and the
  // real (cleartext) socket wins.
  var trust = function (addr) { return addr.indexOf("10.") === 0; };
  var forged = {
    socket:  { encrypted: false, remoteAddress: "198.51.100.66" },
    headers: { "x-forwarded-proto": "https" },
  };
  check("requestProtocol: forged XFP from an untrusted peer → http (ignored)",
        b.requestHelpers.requestProtocol(forged, { trustProxy: trust }) === "http");
  // Even a peer-gated request with no forwarded header falls back to the socket.
  var realTls = { socket: { encrypted: true, remoteAddress: "198.51.100.66" }, headers: {} };
  check("requestProtocol: peer-gated real-TLS socket without XFP → https",
        b.requestHelpers.requestProtocol(realTls, { trustProxy: trust }) === "https");
}

function testRequestProtocolLegacyTrustProxyTrue() {
  // Legacy trustProxy:true reads the leftmost hop WITHOUT checking the peer —
  // spoofable, documented as safe only behind a header-rewriting edge.
  var behindEdge = {
    socket:  { encrypted: false, remoteAddress: "203.0.113.1" },
    headers: { "x-forwarded-proto": "https, http" },
  };
  check("requestProtocol: legacy trustProxy:true → leftmost forwarded hop",
        b.requestHelpers.requestProtocol(behindEdge, { trustProxy: true }) === "https");
  // Default (no trustProxy) ignores X-Forwarded-Proto entirely.
  check("requestProtocol: default ignores X-Forwarded-Proto",
        b.requestHelpers.requestProtocol(behindEdge) === "http");
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("request-helpers tests passed"); process.exit(0); },
    function (e) { console.error(e); process.exit(1); }
  );
}
