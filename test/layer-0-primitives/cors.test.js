// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * cors middleware — same-origin pass-through + allow-list refusal.
 *
 * Run standalone: `node test/layer-0-primitives/cors.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b      = helpers.b;
var check  = helpers.check;

function _req(opts) {
  opts = opts || {};
  return {
    method:  opts.method  || "POST",
    url:     opts.url     || "/login",
    headers: Object.assign({
      host:   "localhost:8080",
      origin: "http://localhost:8080",
    }, opts.headers || {}),
    socket:  opts.socket  || { remoteAddress: "127.0.0.1", encrypted: false },
  };
}

function _res() {
  var sent = { headers: {}, statusCode: null, body: "" };
  return {
    setHeader: function (k, v) { sent.headers[k.toLowerCase()] = v; },
    writeHead: function (sc, h) {
      sent.statusCode = sc;
      if (h) {
        var keys = Object.keys(h);
        for (var i = 0; i < keys.length; i++) sent.headers[keys[i].toLowerCase()] = h[keys[i]];
      }
    },
    end:      function (b) { sent.body = b || ""; },
    _sent:    sent,
  };
}

function _drive(mw, req) {
  return new Promise(function (resolve) {
    var res = _res();
    var nextCalled = false;
    mw(req, res, function () { nextCalled = true; resolve({ res: res, nextCalled: nextCalled }); });
    // If next was synchronous, the resolve above happened. Otherwise
    // the middleware terminated the response — fall through after a
    // tiny passive window and resolve with whatever state we observed.
    helpers.passiveObserve(5, "cors: middleware short-circuit window")
      .then(function () { resolve({ res: res, nextCalled: nextCalled }); });
  });
}

async function testCorsSameOriginPostPassesWithoutAllowList() {
  // Empty allow-list: a same-origin POST (browser sets Origin header
  // per Fetch spec) must NOT get refused. This was the wiki login bug.
  var mw = b.middleware.cors({ origins: [], refuseUnknown: true });
  var req = _req({
    method:  "POST",
    headers: { host: "localhost:8080", origin: "http://localhost:8080" },
  });
  var out = await _drive(mw, req);
  check("same-origin POST passes through (no 403)",     out.nextCalled === true);
  check("same-origin POST: no CORS headers added",      out.res._sent.headers["access-control-allow-origin"] === undefined);
}

async function testCorsCrossOriginPostStillRefused() {
  // Same allow-list, different origin → refused as before.
  var mw = b.middleware.cors({ origins: [], refuseUnknown: true });
  var req = _req({
    method:  "POST",
    headers: { host: "localhost:8080", origin: "https://attacker.example.com" },
  });
  var out = await _drive(mw, req);
  check("cross-origin POST refused (403)",              out.res._sent.statusCode === 403);
  check("cross-origin POST refusal body intact",        /CORS: origin not allowed/.test(out.res._sent.body));
  check("cross-origin POST: next NOT called",           out.nextCalled === false);
}

async function testCorsExplicitSiteOriginAcceptsThatOrigin() {
  // Operator-supplied siteOrigin is the authoritative same-origin
  // signal — used behind TLS terminators where the framework can't
  // infer scheme from the socket.
  var mw = b.middleware.cors({
    origins:    [],
    siteOrigin: "https://wiki.example.com",
  });
  var req = _req({
    method:  "POST",
    headers: { host: "internal-wiki:8080", origin: "https://wiki.example.com" },
  });
  var out = await _drive(mw, req);
  check("explicit siteOrigin: matching Origin passes",  out.nextCalled === true);
}

async function testCorsExplicitSiteOriginRejectsInferredOrigin() {
  // Once siteOrigin is supplied, the framework's inferred-origin
  // check is replaced — the request's own Host/scheme is no longer
  // trusted as same-origin.
  var mw = b.middleware.cors({
    origins:    [],
    siteOrigin: "https://wiki.example.com",
  });
  var req = _req({
    method:  "POST",
    headers: { host: "localhost:8080", origin: "http://localhost:8080" },
  });
  var out = await _drive(mw, req);
  check("explicit siteOrigin: non-matching origin refused (403)",
        out.res._sent.statusCode === 403);
}

async function testCorsXForwardedProtoRespected() {
  // Behind a TLS terminator: socket is HTTP but Origin claims https. With
  // trustedProxies covering the proxy peer, X-Forwarded-Proto: https flips the
  // inferred scheme so same-origin detection matches — peer-gated, so only a
  // request arriving via the trusted proxy gets the header honored.
  var mw = b.middleware.cors({ origins: [], refuseUnknown: true, trustedProxies: ["127.0.0.0/8"] });
  var req = _req({
    method:  "POST",
    headers: {
      host:   "wiki.example.com",
      origin: "https://wiki.example.com",
      "x-forwarded-proto": "https",
    },
    socket:  { remoteAddress: "127.0.0.1", encrypted: false },
  });
  var out = await _drive(mw, req);
  check("X-Forwarded-Proto: https via trusted proxy → same-origin pass-through",
        out.nextCalled === true);

  // A bare trustProxy is refused at construction (spoofable).
  var threwBare = false;
  try { b.middleware.cors({ origins: [], refuseUnknown: true, trustProxy: true }); }
  catch (_e) { threwBare = true; }
  check("cors: bare trustProxy refused (spoofable)", threwBare === true);

  // Forged X-Forwarded-Proto from an UNTRUSTED peer is ignored → inferred
  // origin stays http://… so the https Origin is cross-origin → blocked.
  var forged = _req({
    method:  "POST",
    headers: {
      host:   "wiki.example.com",
      origin: "https://wiki.example.com",
      "x-forwarded-proto": "https",
    },
    socket:  { remoteAddress: "198.51.100.66", encrypted: false },
  });
  var outForged = await _drive(mw, forged);
  check("forged X-Forwarded-Proto from untrusted peer ignored → blocked",
        outForged.nextCalled === false);
}

async function testCorsXForwardedProtoIgnoredWithoutTrustProxy() {
  // Same request without trustProxy: the framework refuses to consult
  // forwarded headers, so the inferred origin is http://… and the
  // same-origin check fails — refuseUnknown rejects the request. This
  // is the secure default: an attacker can't forge the header.
  var mw = b.middleware.cors({ origins: [], refuseUnknown: true });
  var req = _req({
    method:  "POST",
    headers: {
      host:   "wiki.example.com",
      origin: "https://wiki.example.com",
      "x-forwarded-proto": "https",
    },
    socket:  { remoteAddress: "127.0.0.1", encrypted: false },
  });
  var out = await _drive(mw, req);
  check("X-Forwarded-Proto without trustProxy → cross-origin treated as cross-origin",
        out.nextCalled === false);
}

async function testCorsNoOriginHeaderPassesThrough() {
  // GET requests typically have no Origin header (and same-origin
  // GETs definitely don't). Pass through untouched.
  var mw = b.middleware.cors({ origins: [], refuseUnknown: true });
  var req = _req({
    method:  "GET",
    url:     "/",
    headers: { host: "localhost:8080" },   // no origin
  });
  var out = await _drive(mw, req);
  check("no Origin header: next called (no 403)",       out.nextCalled === true);
}

async function testCorsNullOriginStrictByDefault() {
  // Default: strictNullOrigin: true — refuse Origin: null even with
  // Sec-Fetch-Site: same-origin, because non-browser callers can forge
  // that header freely. Operators with a no-referrer page producing
  // legitimate Origin: null on same-origin POSTs flip strictNullOrigin: false.
  var mw = b.middleware.cors({ origins: [], refuseUnknown: true });
  var req = _req({
    method:  "POST",
    headers: {
      host:   "localhost:8080",
      origin: "null",
      "sec-fetch-site": "same-origin",   // browsers send this; non-browsers can forge it
    },
  });
  var out = await _drive(mw, req);
  check("Origin:null refused even with sec-fetch-site:same-origin (default strict)",
        out.res._sent.statusCode === 403);
}

async function testCorsNullOriginRelaxedOptIn() {
  // Operators with a no-referrer page that produces Origin: null on
  // same-origin POSTs flip strictNullOrigin: false to allow the
  // Sec-Fetch-Site shortcut.
  var mw = b.middleware.cors({
    origins: [], refuseUnknown: true, strictNullOrigin: false,
  });
  var req = _req({
    method:  "POST",
    headers: {
      host:   "localhost:8080",
      origin: "null",
      "sec-fetch-site": "same-origin",
    },
  });
  var out = await _drive(mw, req);
  check("strictNullOrigin:false honors sec-fetch-site:same-origin",
        out.nextCalled === true);
}

async function testCorsNullOriginRelaxedRequiresSameOrigin() {
  // Even with strictNullOrigin: false, only same-origin / none signals
  // pass — a cross-site fetch-metadata still gets refused.
  var mw = b.middleware.cors({
    origins: [], refuseUnknown: true, strictNullOrigin: false,
  });
  var req = _req({
    method:  "POST",
    headers: {
      host:   "localhost:8080",
      origin: "null",
      "sec-fetch-site": "cross-site",
    },
  });
  var out = await _drive(mw, req);
  check("strictNullOrigin:false + cross-site fetch-site still refused",
        out.res._sent.statusCode === 403);
}

async function testCorsNullOriginWithoutFetchSiteRefused() {
  // Origin:null with no fetch-metadata at all (older browser, curl, etc.)
  // — without the same-origin signal we can't trust it. Refuse.
  var mw = b.middleware.cors({ origins: [], refuseUnknown: true });
  var req = _req({
    method:  "POST",
    headers: { host: "localhost:8080", origin: "null" },
  });
  var out = await _drive(mw, req);
  check("Origin:null without Sec-Fetch-Site refused",
        out.res._sent.statusCode === 403);
}

function testCorsConfigValidationThrows() {
  // Bad config surfaces at create() not at request time.
  var threwOnBadOrigin = null;
  try { b.middleware.cors({ origins: [42] }); }
  catch (e) { threwOnBadOrigin = e; }
  check("bad origins[] entry throws CorsError",
        threwOnBadOrigin && threwOnBadOrigin.code === "cors/bad-origin");

  var threwOnBadSiteOriginType = null;
  try { b.middleware.cors({ siteOrigin: 42 }); }
  catch (e) { threwOnBadSiteOriginType = e; }
  check("non-string siteOrigin throws CorsError",
        threwOnBadSiteOriginType && threwOnBadSiteOriginType.code === "cors/bad-site-origin");

  var threwOnUnparseableSiteOrigin = null;
  try { b.middleware.cors({ siteOrigin: "not-a-url" }); }
  catch (e) { threwOnUnparseableSiteOrigin = e; }
  check("unparseable siteOrigin URL throws CorsError",
        threwOnUnparseableSiteOrigin && threwOnUnparseableSiteOrigin.code === "cors/bad-site-origin");

  // A catastrophic-backtracking (ReDoS) RegExp in origins[] is screened
  // at create() — the wrapped nested quantifier /((a)+)+$/ would pin a
  // CPU when .test()'d against a hostile Origin header, so it's refused
  // before the middleware is built.
  var threwOnUnsafePattern = null;
  try { b.middleware.cors({ origins: [/((a)+)+$/] }); }
  catch (e) { threwOnUnsafePattern = e; }
  check("ReDoS-shaped origins[] RegExp throws cors/unsafe-pattern",
        threwOnUnsafePattern && threwOnUnsafePattern.code === "cors/unsafe-pattern");

  // undefined / not-passed → no throw, default behaviour.
  var ok = b.middleware.cors({});
  check("no opts: returns a function (default behaviour)", typeof ok === "function");

  // Reflecting a pattern-matched origin WITH credentials leaks authenticated
  // responses to any host the RegExp admits, and no finite check can prove an
  // arbitrary RegExp is host-specific (a /.*\.com$/ trusts every registrable
  // .com). So a RegExp origin paired with credentials:true is refused outright;
  // credentialed CORS uses exact string origins (Fetch §3.2.3; OWASP).
  var regexCreds = null;
  try { b.middleware.cors({ origins: [/^https:\/\/([a-z0-9-]+\.)?example\.com$/], credentials: true }); }
  catch (e) { regexCreds = e; }
  check("cors: a RegExp origin with credentials:true throws cors/regex-origin-with-credentials",
        regexCreds && regexCreds.code === "cors/regex-origin-with-credentials",
        regexCreds && (regexCreds.code + " :: " + regexCreds.message));

  // The refusal reads credentials the SAME way the runtime does (!!opts), so a
  // truthy non-boolean value cannot skip the guard while still enabling
  // Access-Control-Allow-Credentials at runtime.
  var regexCredsTruthy = null;
  try { b.middleware.cors({ origins: [/^https:\/\/.*\.com$/], credentials: 1 }); }
  catch (e) { regexCredsTruthy = e; }
  check("cors: a RegExp origin with a truthy non-boolean credentials also throws",
        regexCredsTruthy && regexCredsTruthy.code === "cors/regex-origin-with-credentials",
        regexCredsTruthy && regexCredsTruthy.code);

  // For credentials:false, a RegExp origin is applied with .test(origin). An
  // unanchored or over-broad pattern still reflects a look-alike attacker origin
  // (without credentials), so create() must require whole-origin anchoring and
  // reject catch-alls (PortSwigger "CORS via regex"; Fetch §3.2.3).
  var unanchored = null;
  try { b.middleware.cors({ origins: [/example\.com/] }); }
  catch (e) { unanchored = e; }
  check("cors: an unanchored RegExp origin throws cors/unanchored-pattern at create()",
        unanchored && unanchored.code === "cors/unanchored-pattern",
        unanchored && (unanchored.code + " :: " + unanchored.message));

  var endOnly = null;
  try { b.middleware.cors({ origins: [/example\.com$/] }); }
  catch (e) { endOnly = e; }
  check("cors: a RegExp origin anchored at one end only throws cors/unanchored-pattern",
        endOnly && endOnly.code === "cors/unanchored-pattern",
        endOnly && endOnly.code);

  var catchAll = null;
  try { b.middleware.cors({ origins: [/^https:\/\/.*$/] }); }
  catch (e) { catchAll = e; }
  check("cors: an anchored HTTPS catch-all RegExp origin throws cors/overbroad-pattern",
        catchAll && catchAll.code === "cors/overbroad-pattern",
        catchAll && (catchAll.code + " :: " + catchAll.message));

  // The canary probes every scheme CORS canonicalizes, not just https.
  var catchAllHttp = null;
  try { b.middleware.cors({ origins: [/^http:\/\/.*$/] }); }
  catch (e) { catchAllHttp = e; }
  check("cors: an anchored HTTP catch-all RegExp origin throws cors/overbroad-pattern",
        catchAllHttp && catchAllHttp.code === "cors/overbroad-pattern",
        catchAllHttp && (catchAllHttp.code + " :: " + catchAllHttp.message));

  // The probes cross the origin grammar (scheme x host-form x port), so a
  // catch-all that requires a port, or an IPv6/IPv4 host, is caught too.
  var catchAllPort = null;
  try { b.middleware.cors({ origins: [/^https:\/\/.*:\d+$/] }); }
  catch (e) { catchAllPort = e; }
  check("cors: a port-requiring catch-all RegExp origin throws cors/overbroad-pattern",
        catchAllPort && catchAllPort.code === "cors/overbroad-pattern",
        catchAllPort && catchAllPort.code);

  var catchAllV6 = null;
  try { b.middleware.cors({ origins: [/^https:\/\/\[.*\]$/] }); }
  catch (e) { catchAllV6 = e; }
  check("cors: an IPv6-host catch-all RegExp origin throws cors/overbroad-pattern",
        catchAllV6 && catchAllV6.code === "cors/overbroad-pattern",
        catchAllV6 && catchAllV6.code);

  // Control — a host-specific pattern that also allows an optional port is NOT
  // over-broad and still builds (the probes use a different host).
  var okWithPort = false;
  try { b.middleware.cors({ origins: [/^https:\/\/app\.example\.com(:\d+)?$/] }); okWithPort = true; }
  catch (_e) { okWithPort = false; }
  check("cors: a host-specific pattern allowing an optional port still builds", okWithPort);

  // Allowlist canonicalization — case + default-port differences match.
  var threwOnUnparseableOrigin = null;
  try { b.middleware.cors({ origins: ["not-a-url"] }); }
  catch (e) { threwOnUnparseableOrigin = e; }
  check("unparseable origin URL throws cors/bad-origin",
        threwOnUnparseableOrigin && threwOnUnparseableOrigin.code === "cors/bad-origin");
}

async function testCorsAllowlistCanonicalization() {
  // String entries are canonicalized at create() — case + default-port
  // differences between the configured value and the inbound Origin
  // header now match consistently.
  var mw = b.middleware.cors({
    origins:       ["https://APP.example.com:443"],   // upper-case + default port
    refuseUnknown: true,
  });

  // Browser sends the canonical lower-case host without the default port.
  var req = _req({
    method:  "POST",
    headers: { host: "wiki.example.com", origin: "https://app.example.com" },
  });
  var out = await _drive(mw, req);
  check("allowlist: case + default-port differences match",
        out.nextCalled === true || out.res._sent.statusCode !== 403);

  // Different host: still refused.
  var req2 = _req({
    method:  "POST",
    headers: { host: "wiki.example.com", origin: "https://other.example.com" },
  });
  var out2 = await _drive(mw, req2);
  check("allowlist: different host still refused",
        out2.res._sent.statusCode === 403);
}

async function testCorsPnaPreflightDefaultRefused() {
  var mw = b.middleware.cors({ origins: ["https://app.example.com"] });
  var req = _req({
    method:  "OPTIONS",
    headers: {
      host:                                "app.example.com",
      origin:                              "https://app.example.com",
      "access-control-request-method":     "GET",
      "access-control-request-private-network": "true",
    },
  });
  var out = await _drive(mw, req);
  check("PNA: preflight refused by default",
        out.res._sent.statusCode === 403 || !out.res._sent.headers["access-control-allow-private-network"]);
}

async function testCorsPnaPreflightAllowedWhenOptedIn() {
  var mw = b.middleware.cors({
    origins: ["https://app.example.com"],
    allowPrivateNetwork: true,
  });
  var req = _req({
    method:  "OPTIONS",
    headers: {
      host:                                "app.example.com",
      origin:                              "https://app.example.com",
      "access-control-request-method":     "GET",
      "access-control-request-private-network": "true",
    },
  });
  var out = await _drive(mw, req);
  check("PNA: preflight allowed when allowPrivateNetwork: true",
        out.res._sent.headers["access-control-allow-private-network"] === "true");
}

// A RegExp origin with the global (g) or sticky (y) flag makes `.test()` stateful
// across calls (it advances lastIndex), so credentialed CORS matching would flip
// unpredictably between requests. Such a pattern must be refused at construction.
function testCorsRejectsStatefulRegexOrigin() {
  var threwG = false;
  try { b.middleware.cors({ origins: [/\.example\.com$/g] }); }
  catch (e) { threwG = !!(e && e.code === "cors/stateful-pattern"); }
  check("cors: a global-flagged RegExp origin is refused (stateful .test())", threwG);

  var threwY = false;
  try { b.middleware.cors({ origins: [new RegExp("\\.example\\.com$", "y")] }); }
  catch (e) { threwY = !!(e && e.code === "cors/stateful-pattern"); }
  check("cors: a sticky-flagged RegExp origin is refused", threwY);

  var okPlain = false;
  try { b.middleware.cors({ origins: [/^https:\/\/.+\.example\.com$/] }); okPlain = true; }
  catch (_e) { okPlain = false; }
  check("cors: a plain (unflagged) anchored RegExp origin is still accepted", okPlain);
}

// A properly anchored, host-scoped RegExp origin still builds and behaves: it
// matches a real subdomain and rejects an attacker origin that merely contains
// the host as a substring (the look-alike the unanchored form would reflect).
async function testCorsAnchoredRegexOriginMatchesHostScoped() {
  var mw = b.middleware.cors({
    origins:     [/^https:\/\/([a-z0-9-]+\.)?example\.com$/],
    credentials: false,
  });
  var good = await _drive(mw, _req({
    method: "GET", headers: { origin: "https://app.example.com" },
  }));
  check("cors: anchored host-scoped RegExp matches a real subdomain (reflects it)",
        good.res._sent.headers["access-control-allow-origin"] === "https://app.example.com",
        JSON.stringify(good.res._sent.headers["access-control-allow-origin"]));
  var evil = await _drive(mw, _req({
    method: "GET", headers: { origin: "https://example.com.attacker.test" },
  }));
  check("cors: anchored host-scoped RegExp rejects a look-alike attacker origin",
        evil.res._sent.headers["access-control-allow-origin"] === undefined &&
        (evil.res._sent.statusCode === 403 || evil.nextCalled === false),
        "acao=" + evil.res._sent.headers["access-control-allow-origin"] +
        " status=" + evil.res._sent.statusCode + " next=" + evil.nextCalled);

  // Alternation must not let a branch be only half-anchored. /^A|B$/ has a
  // start-anchored first branch and an end-anchored second branch; a char-only
  // "starts with ^, ends with $" check passes it, yet .test() on the raw
  // pattern would substring-match https://trusted.example.attacker.test on the
  // first branch. Matching must consume the WHOLE origin, so the attacker
  // origin is not reflected, while both intended origins still match.
  var alt = b.middleware.cors({
    origins:     [/^https:\/\/trusted\.example|https:\/\/other\.example$/],
    credentials: false,
  });
  var altEvil = await _drive(alt, _req({
    method: "GET", headers: { origin: "https://trusted.example.attacker.test" },
  }));
  check("cors: an alternation branch cannot substring-match an attacker origin",
        altEvil.res._sent.headers["access-control-allow-origin"] === undefined &&
        (altEvil.res._sent.statusCode === 403 || altEvil.nextCalled === false),
        "acao=" + altEvil.res._sent.headers["access-control-allow-origin"]);
  var altGood = await _drive(alt, _req({
    method: "GET", headers: { origin: "https://trusted.example" },
  }));
  check("cors: an anchored alternation still matches its intended origins",
        altGood.res._sent.headers["access-control-allow-origin"] === "https://trusted.example");
}

async function run() {
  await testCorsSameOriginPostPassesWithoutAllowList();
  testCorsRejectsStatefulRegexOrigin();
  await testCorsCrossOriginPostStillRefused();
  await testCorsExplicitSiteOriginAcceptsThatOrigin();
  await testCorsExplicitSiteOriginRejectsInferredOrigin();
  await testCorsXForwardedProtoRespected();
  await testCorsXForwardedProtoIgnoredWithoutTrustProxy();
  await testCorsNoOriginHeaderPassesThrough();
  await testCorsNullOriginStrictByDefault();
  await testCorsNullOriginRelaxedOptIn();
  await testCorsNullOriginRelaxedRequiresSameOrigin();
  await testCorsNullOriginWithoutFetchSiteRefused();
  testCorsConfigValidationThrows();
  await testCorsAnchoredRegexOriginMatchesHostScoped();
  await testCorsAllowlistCanonicalization();
  await testCorsPnaPreflightDefaultRefused();
  await testCorsPnaPreflightAllowedWhenOptedIn();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.message); process.exit(1); }
  );
}
