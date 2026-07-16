// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.httpClient.cache — RFC 9111 §3.5 Authorization rule.
 *
 * A shared cache MUST NOT reuse a stored response to a request that
 * carried an `Authorization` header to satisfy a subsequent request
 * unless the response explicitly permits it via `public`, `s-maxage`,
 * or `must-revalidate`. Without that gate a per-user authenticated
 * response lands in a fleet-shared cache and a different principal's
 * request is served it — a cross-user data leak.
 *
 * Coverage:
 *   - shared cache + Authorization + only max-age → NOT reused across users
 *   - shared cache + Authorization + `public` → reuse permitted (origin opt-in)
 *   - shared cache + Authorization + `s-maxage` → reuse permitted
 *   - private cache (sharedCache:false) + Authorization → cached (single tenant)
 *
 * No live network — local http.Server on a random loopback port via
 * b.testing.listenOnRandomPort.
 */

var http = require("http");

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function _httpDate(ms) { return new Date(ms).toUTCString(); }

async function _withServer(handler, fn) {
  var server = http.createServer(handler);
  var port = await b.testing.listenOnRandomPort(server, "127.0.0.1");
  try {
    return await fn("http://127.0.0.1:" + port);
  } finally {
    await new Promise(function (resolve) { server.close(function () { resolve(); }); });
  }
}

function _newCache(extra) {
  var store = b.httpClient.cache.memoryStore({ maxBytes: 1024 * 1024, maxEntries: 64 });
  return b.httpClient.cache.create(Object.assign({ store: store }, extra || {}));
}

// A handler that echoes the caller's Authorization into the body so the
// served bytes reveal which principal the response was generated for.
function _echoAuthHandler(cacheControl, hitsRef) {
  return function (req, res) {
    hitsRef.n += 1;
    res.writeHead(200, {
      "Content-Type":  "text/plain",
      "Cache-Control": cacheControl,
      "Date":          _httpDate(Date.now()),
    });
    res.end("secret-for:" + (req.headers["authorization"] || "anon"));
  };
}

// A handler whose FIRST 200 carries the `must-revalidate` §3.5 opt-in (with
// max-age=0 so the entry is immediately stale), then answers the conditional
// revalidation with a 304 that DROPS must-revalidate and substitutes a plain
// max-age=60. A shared cache that refreshes the entry from that 304 without
// re-applying the Authorization gate would retain a now-freely-shareable
// authed response.
function _optInThenDropOn304Handler(hitsRef) {
  return function (req, res) {
    hitsRef.n += 1;
    if (req.headers["if-none-match"]) {
      res.writeHead(304, {
        "Cache-Control": "max-age=60",
        "ETag":          '"v1"',
        "Date":          _httpDate(Date.now()),
      });
      res.end();
      return;
    }
    res.writeHead(200, {
      "Content-Type":  "text/plain",
      "Cache-Control": "must-revalidate, max-age=0",
      "ETag":          '"v1"',
      "Date":          _httpDate(Date.now()),
    });
    res.end("secret-for:" + (req.headers["authorization"] || "anon"));
  };
}

// A 304 can replace Cache-Control: an authed entry first stored under the
// must-revalidate opt-in can be revalidated into a plain max-age=60 response.
// The refresh must re-apply RFC 9111 §3.5 and EVICT the entry (it lost its
// opt-in) rather than retain it as a freely-shareable authed response served
// to a different principal.
async function testAuthOptInDroppedOn304EvictsNotShares() {
  var hits = { n: 0 };
  await _withServer(_optInThenDropOn304Handler(hits), async function (baseUrl) {
    var cache = _newCache({ sharedCache: true });
    var r1 = await b.httpClient.request({
      url: baseUrl + "/acct", cache: cache,
      headers: { Authorization: "Bearer USER-AAA" },
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    check("304-optin: AAA first request MISS", r1.headers["x-blamejs-cache"] === "MISS");
    check("304-optin: AAA body", r1.body.toString("utf8") === "secret-for:Bearer USER-AAA");
    // AAA again — entry is stale (max-age=0), revalidates, gets the 304 that
    // drops must-revalidate for max-age=60.
    var r2 = await b.httpClient.request({
      url: baseUrl + "/acct", cache: cache,
      headers: { Authorization: "Bearer USER-AAA" },
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    check("304-optin: AAA revalidated serve is still AAA's body",
          r2.body.toString("utf8") === "secret-for:Bearer USER-AAA");
    // BBB (a different principal) must NOT receive AAA's body — the entry must
    // have been evicted on the opt-in-dropping 304.
    var r3 = await b.httpClient.request({
      url: baseUrl + "/acct", cache: cache,
      headers: { Authorization: "Bearer USER-BBB" },
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    check("304-optin: BBB does NOT receive AAA's body after the 304 dropped the opt-in",
          r3.body.toString("utf8") !== "secret-for:Bearer USER-AAA");
    check("304-optin: BBB receives its own response",
          r3.body.toString("utf8") === "secret-for:Bearer USER-BBB");
  });
}

// ---- The leak: shared cache must not cross Authorization principals ----

async function testAuthNotSharedAcrossUsersSharedCache() {
  var hits = { n: 0 };
  await _withServer(_echoAuthHandler("max-age=60", hits), async function (baseUrl) {
    var cache = _newCache({ sharedCache: true });

    var r1 = await b.httpClient.request({
      url: baseUrl + "/account", cache: cache,
      headers: { Authorization: "Bearer USER-AAA" },
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    check("shared+auth: first request MISS",
          r1.headers["x-blamejs-cache"] === "MISS");
    check("shared+auth: first request body is AAA's",
          r1.body.toString("utf8") === "secret-for:Bearer USER-AAA");

    var r2 = await b.httpClient.request({
      url: baseUrl + "/account", cache: cache,
      headers: { Authorization: "Bearer USER-BBB" },
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    // The core assertion: USER-BBB must NEVER receive USER-AAA's body.
    check("shared+auth: USER-BBB does NOT receive USER-AAA's cached response",
          r2.body.toString("utf8") !== "secret-for:Bearer USER-AAA");
    check("shared+auth: USER-BBB receives its own response",
          r2.body.toString("utf8") === "secret-for:Bearer USER-BBB");
    check("shared+auth: second request was not served from cache",
          r2.headers["x-blamejs-cache"] === "MISS");
    check("shared+auth: both requests reached upstream", hits.n === 2);
  });
}

// ---- `public` is the origin's opt-in to share an authed response ----

async function testPublicPermitsSharedAuthReuse() {
  var hits = { n: 0 };
  await _withServer(_echoAuthHandler("public, max-age=60", hits), async function (baseUrl) {
    var cache = _newCache({ sharedCache: true });

    var r1 = await b.httpClient.request({
      url: baseUrl + "/pub", cache: cache,
      headers: { Authorization: "Bearer USER-AAA" },
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    check("public+auth: first request MISS", r1.headers["x-blamejs-cache"] === "MISS");

    var r2 = await b.httpClient.request({
      url: baseUrl + "/pub", cache: cache,
      headers: { Authorization: "Bearer USER-BBB" },
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    // `public` is an explicit origin declaration that the response is
    // shareable, so a HIT here is correct RFC 9111 §3.5 behaviour.
    check("public+auth: second request served from cache (origin opt-in)",
          r2.headers["x-blamejs-cache"] === "HIT");
    check("public+auth: only one upstream call", hits.n === 1);
  });
}

async function testSmaxagePermitsSharedAuthReuse() {
  var hits = { n: 0 };
  await _withServer(_echoAuthHandler("s-maxage=60", hits), async function (baseUrl) {
    var cache = _newCache({ sharedCache: true });

    await b.httpClient.request({
      url: baseUrl + "/s", cache: cache,
      headers: { Authorization: "Bearer USER-AAA" },
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    var r2 = await b.httpClient.request({
      url: baseUrl + "/s", cache: cache,
      headers: { Authorization: "Bearer USER-BBB" },
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    check("s-maxage+auth: second request served from cache",
          r2.headers["x-blamejs-cache"] === "HIT");
    check("s-maxage+auth: only one upstream call", hits.n === 1);
  });
}

// ---- A private cache (single tenant) may cache an authed response ----

async function testPrivateCacheCachesAuthedResponse() {
  var hits = { n: 0 };
  await _withServer(_echoAuthHandler("max-age=60", hits), async function (baseUrl) {
    var cache = _newCache({ sharedCache: false });

    await b.httpClient.request({
      url: baseUrl + "/me", cache: cache,
      headers: { Authorization: "Bearer USER-AAA" },
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    var r2 = await b.httpClient.request({
      url: baseUrl + "/me", cache: cache,
      headers: { Authorization: "Bearer USER-AAA" },
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    check("private+auth: same-principal repeat served from cache",
          r2.headers["x-blamejs-cache"] === "HIT");
    check("private+auth: only one upstream call", hits.n === 1);
  });
}

// ---- Run ----------------------------------------------------------------

async function run() {
  try {
    await testAuthNotSharedAcrossUsersSharedCache();
    await testAuthOptInDroppedOn304EvictsNotShares();
    await testPublicPermitsSharedAuthReuse();
    await testSmaxagePermitsSharedAuthReuse();
    await testPrivateCacheCachesAuthedResponse();
  } finally {
    await _drainTcpHandles();
  }
}

async function _drainTcpHandles() {
  b.httpClient._resetForTest();
  if (typeof process.getActiveResourcesInfo !== "function") return;
  await helpers.waitUntil(function () {
    return process.getActiveResourcesInfo().filter(function (t) {
      return t === "TCPSocketWrap" || t === "TCPServerWrap";
    }).length === 0;
  }, { timeoutMs: 5000, label: "http-client-cache-authorization: TCP handle drain" });
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
