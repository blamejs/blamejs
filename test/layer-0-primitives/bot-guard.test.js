// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — b.middleware.botGuard.
 * Focus: an ABSENT header must never refuse a legitimate client, whichever
 * header it is. Browsers omit Fetch Metadata (Sec-Fetch-*) on plain-HTTP
 * non-localhost origins (Umbrel, LAN / *.local reverse proxies) and in
 * Safari < 16.4 even over HTTPS; every major search-engine crawler omits
 * Accept-Language. Both are therefore advisory-only — they tag in
 * mode:"tag" and never block. Drive-by bots are blocked by the User-Agent
 * deny-list, which is what actually identifies automation.
 */

var b = require("../../index");
var helpers = require("../helpers");
var check = helpers.check;

var BROWSER_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36";

function _run(opts, reqInit) {
  var mw = b.middleware.botGuard(opts || {});
  var req = b.testing.mockReq(reqInit);
  var res = b.testing.mockRes();
  var nexted = false;
  mw(req, res, function () { nexted = true; });
  var cap = res._captured();
  return { nexted: nexted, blocked: cap.status === 403, status: cap.status, body: cap.body, suspectedBot: req.suspectedBot };
}

// Search-engine crawlers do not send Accept-Language. Google documents that
// Googlebot "sends HTTP requests without setting Accept-Language in the request
// header"; bingbot behaves the same. Blocking on that header's absence made
// every content page of a blamejs site answer 403 to a crawler while a browser
// sailed through — measured on a live deployment, where the sitemap listed 337
// URLs and only the nginx-cached homepage was reachable.
var GOOGLEBOT_UA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";
var BINGBOT_UA   = "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)";

function testCrawlersAreNotBlocked() {
  var goog = _run({ mode: "block" }, {
    method: "GET", url: "/acme",
    headers: { "user-agent": GOOGLEBOT_UA, host: "app.example.com" },
    socket: { encrypted: true },
  });
  check("bot-guard: Googlebot without Accept-Language is not blocked",
        goog.nexted && !goog.blocked);

  var bing = _run({ mode: "block" }, {
    method: "GET", url: "/acme",
    headers: { "user-agent": BINGBOT_UA, host: "app.example.com" },
    socket: { encrypted: true },
  });
  check("bot-guard: bingbot without Accept-Language is not blocked",
        bing.nexted && !bing.blocked);

  // The header's absence is not a block signal for anyone — a client family
  // that omits it is not evidence of automation, which is the same conclusion
  // the Sec-Fetch-Mode check reached.
  var browser = _run({ mode: "block" }, {
    method: "GET", url: "/",
    headers: { "user-agent": BROWSER_UA, host: "app.example.com" },
    socket: { encrypted: true },
  });
  check("bot-guard: a browser omitting Accept-Language is not blocked",
        browser.nexted && !browser.blocked);

  // It survives as an advisory signal, so an operator can still shape traffic
  // on it (rate-limit, log) without refusing the request.
  var tagged = _run({ mode: "tag" }, {
    method: "GET", url: "/",
    headers: { "user-agent": GOOGLEBOT_UA, host: "app.example.com" },
    socket: { encrypted: true },
  });
  check("bot-guard: tag mode still reports missing-accept-language",
        tagged.nexted && tagged.suspectedBot === "missing-accept-language");

  // The User-Agent deny-list is untouched — this must not become a way for
  // automation libraries to walk through.
  var curl = _run({ mode: "block" }, {
    method: "GET", url: "/",
    headers: { "user-agent": "curl/8.4.0", host: "app.example.com" },
    socket: { encrypted: true },
  });
  check("bot-guard: curl is still blocked with no Accept-Language", curl.blocked);

  var curlWithLang = _run({ mode: "block" }, {
    method: "GET", url: "/",
    headers: { "user-agent": "curl/8.4.0", "accept-language": "en", host: "app.example.com" },
    socket: { encrypted: true },
  });
  check("bot-guard: curl is still blocked even with Accept-Language",
        curlWithLang.blocked);
}

// The invariant behind the fix, asserted directly: NO SINGLE absent header may
// block. Start from a complete browser request and remove one header at a time.
//
// This is stated behaviourally on purpose. It was first written as a
// codebase-patterns text check, which took six review rounds and was wrong a
// different way each time — anchored on the first expression in the condition,
// then bounded at the first `)`, then bounded to one line, then defeated by a
// statement before the return, by an OR'd guard, and by a `)` inside a string
// literal. Each round was a step further into hand-parsing JavaScript in a test
// file, which is what CLAUDE.md rule 2 says not to do: a detector catches one
// lexical shape and rots, a test catches the behaviour however it is
// reintroduced. Every one of those six shapes fails this loop, because the loop
// runs the middleware instead of reading it.
function testNoSingleAbsentHeaderBlocks() {
  var full = {
    "user-agent":      BROWSER_UA,
    "accept-language": "en-US,en;q=0.9",
    "accept":          "text/html,application/xhtml+xml",
    "accept-encoding": "gzip, deflate, br",
    "sec-fetch-mode":  "navigate",
    "sec-fetch-site":  "none",
    "sec-fetch-dest":  "document",
    host:              "app.example.com",
  };

  var baseline = _run({ mode: "block" }, {
    method: "GET", url: "/", headers: full, socket: { encrypted: true },
  });
  check("bot-guard: the complete browser request passes", baseline.nexted && !baseline.blocked);

  Object.keys(full).forEach(function (omitted) {
    var headers = {};
    Object.keys(full).forEach(function (k) { if (k !== omitted) headers[k] = full[k]; });
    var r = _run({ mode: "block" }, {
      method: "GET", url: "/", headers: headers, socket: { encrypted: true },
    });
    check("bot-guard: omitting " + omitted + " alone does not block", r.nexted && !r.blocked);
  });
}

function testSurface() {
  check("b.middleware.botGuard is a function", typeof b.middleware.botGuard === "function");
  check("returns a (req,res,next) middleware", b.middleware.botGuard({}).length === 3);
}

function testSecFetchNeverBlocks() {
  // The reported defect: a real browser on a plain-HTTP non-localhost
  // origin (Umbrel app / LAN proxy) sends Accept-Language but no Sec-Fetch-*.
  var umbrel = _run({ mode: "block" }, { method: "GET", url: "/", headers: { "accept-language": "en-US", "user-agent": BROWSER_UA, host: "umbrel-dev.local:3080" } });
  check("plain-HTTP browser (Umbrel) is NOT blocked", umbrel.nexted && !umbrel.blocked);

  // Safari < 16.4 omits Sec-Fetch-* even over HTTPS — must not 403 either.
  var safari = _run({ mode: "block" }, { method: "GET", url: "/", headers: { "accept-language": "en-US", "user-agent": "Mozilla/5.0 (Macintosh) Version/15.6 Safari/605", host: "app.example.com" }, socket: { encrypted: true } });
  check("Safari-over-HTTPS (no Sec-Fetch) is NOT blocked", safari.nexted && !safari.blocked);

  // localhost over plain HTTP, no Sec-Fetch — also fine.
  var local = _run({ mode: "block" }, { method: "GET", url: "/", headers: { "accept-language": "en", "user-agent": BROWSER_UA, host: "localhost:3000" } });
  check("localhost browser is NOT blocked", local.nexted && !local.blocked);

  // A secure-context browser that DID send Sec-Fetch-Mode passes (sanity).
  var modern = _run({ mode: "block" }, { method: "GET", url: "/", headers: { "accept-language": "en", "user-agent": BROWSER_UA, "sec-fetch-mode": "navigate", host: "app.example.com" }, socket: { encrypted: true } });
  check("modern HTTPS browser passes", modern.nexted && !modern.blocked);
}

function testBotsStillBlocked() {
  // The User-Agent deny-list is what identifies automation, and it is the only
  // thing that blocks. Header ABSENCE never does — see
  // testCrawlersAreNotBlocked for why, and for the crawler cases it protects.
  //
  // Known automation UA remains a hard block.
  var curl = _run({ mode: "block" }, { method: "GET", url: "/", headers: { "accept-language": "en", "user-agent": "curl/8.4.0", host: "app.example.com" } });
  check("curl UA is blocked", curl.blocked && curl.status === 403);

  var py = _run({ mode: "block" }, { method: "GET", url: "/", headers: { "accept-language": "en", "user-agent": "python-requests/2.31.0", host: "x" } });
  check("python-requests UA is blocked", py.blocked);
}

function testTagModeAdvisory() {
  // mode:"tag" — secure context, no Sec-Fetch-Mode → advisory tag, never blocks.
  var tagged = _run({ mode: "tag" }, { method: "GET", url: "/", headers: { "accept-language": "en", "user-agent": BROWSER_UA, host: "app.example.com" }, socket: { encrypted: true } });
  check("tag mode: secure-context Sec-Fetch miss tags but continues", tagged.nexted && !tagged.blocked && tagged.suspectedBot === "missing-sec-fetch-mode");

  // mode:"tag" — plain-HTTP non-localhost → NOT tagged for Sec-Fetch (insecure context).
  var untagged = _run({ mode: "tag" }, { method: "GET", url: "/", headers: { "accept-language": "en", "user-agent": BROWSER_UA, host: "umbrel.local" } });
  check("tag mode: plain-HTTP origin is NOT tagged for Sec-Fetch", untagged.nexted && !untagged.suspectedBot);
}

function testOverridesAndSkips() {
  // allowedAgents override beats the deny-list.
  var allowed = _run({ mode: "block", allowedAgents: [/^curl\//i] }, { method: "GET", url: "/", headers: { "accept-language": "en", "user-agent": "curl/8.4.0", host: "x" } });
  check("allowedAgents override lets curl through", allowed.nexted && !allowed.blocked);

  // API routes skip the browser-fingerprint checks (onlyForHtml default).
  var api = _run({ mode: "block" }, { method: "GET", url: "/api/data", pathname: "/api/data", headers: { "user-agent": BROWSER_UA, host: "x" } });
  check("API route skips fingerprint checks", api.nexted && !api.blocked);

  // skipPaths bypass.
  var skipped = _run({ mode: "block", skipPaths: ["/healthz"] }, { method: "GET", url: "/healthz", pathname: "/healthz", headers: { "user-agent": "curl/8" } });
  check("skipPaths bypasses bot-guard", skipped.nexted && !skipped.blocked);

  // RegExp patterns are required (string patterns refused at create()).
  var threw = null;
  try { b.middleware.botGuard({ blockedAgents: ["badbot"] }); } catch (e) { threw = e.code; }
  check("string blockedAgents pattern is refused", threw === "bot-guard/bad-pattern");

  // An operator bot pattern is .test()'d against the attacker-controlled
  // User-Agent on every request, so a catastrophic-backtracking RegExp would be
  // a per-request DoS. The pattern is screened through b.guardRegex at create().
  var threwRedos = null;
  try { b.middleware.botGuard({ blockedAgents: [/((a)+)+$/] }); } catch (e) { threwRedos = e.code; }
  check("ReDoS-shaped blockedAgents pattern is refused", threwRedos === "bot-guard/unsafe-pattern");
  var threwRedosAllow = null;
  try { b.middleware.botGuard({ allowedAgents: [/(a+)+$/] }); } catch (e) { threwRedosAllow = e.code; }
  check("ReDoS-shaped allowedAgents pattern is refused", threwRedosAllow === "bot-guard/unsafe-pattern");
}

function testPeerGatedAuditIp() {
  // Audit-attribution IP can be peer-gated so a forged X-Forwarded-For from a
  // direct caller can't pollute it. Construction wiring + validation.
  var okTrusted = true;
  try { b.middleware.botGuard({ trustedProxies: ["10.0.0.0/8"] }); } catch (_e) { okTrusted = false; }
  check("botGuard: trustedProxies accepted", okTrusted === true);

  var okResolver = true;
  try { b.middleware.botGuard({ clientIpResolver: function () { return "1.2.3.4"; } }); } catch (_e) { okResolver = false; }
  check("botGuard: clientIpResolver accepted", okResolver === true);

  var threwCidr = null;
  try { b.middleware.botGuard({ trustedProxies: ["nope"] }); } catch (e) { threwCidr = e.code; }
  check("botGuard: malformed trustedProxies CIDR refused", threwCidr === "bot-guard/bad-opt");
}

async function run() {
  testSurface();
  testCrawlersAreNotBlocked();
  testNoSingleAbsentHeaderBlocks();
  testSecFetchNeverBlocks();
  testBotsStillBlocked();
  testTagModeAdvisory();
  testOverridesAndSkips();
  testPeerGatedAuditIp();
}
module.exports = { run: run };
if (require.main === module) { run().then(function () { console.log("[bot-guard] OK — " + helpers.getChecks() + " checks passed"); }, function (e) { console.error("FAIL: " + helpers.formatErr(e)); process.exit(1); }); }
