// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.middleware.noCache — RFC 9111 §5.2.2.5 Cache-Control: no-store middleware.
 */

var fs      = require("fs");
var http    = require("http");
var os      = require("os");
var path    = require("path");
var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function _mockReq(url) {
  return { method: "GET", url: url || "/", headers: {} };
}

function _mockRes() {
  var headers = {};
  return {
    setHeader: function (k, v) { headers[k.toLowerCase()] = v; },
    getHeader: function (k) { return headers[k.toLowerCase()]; },
    _headers: function () { return headers; },
  };
}

function testSurface() {
  check("middleware.noCache is fn", typeof b.middleware.noCache === "function");
}

function testDefaultHeaders() {
  var mw = b.middleware.noCache();
  var req = _mockReq();
  var res = _mockRes();
  var nextCalled = false;
  mw(req, res, function () { nextCalled = true; });
  check("noCache: next() called",            nextCalled);
  check("noCache: Cache-Control no-store",   res._headers()["cache-control"] === "no-store");
  check("noCache: Pragma no-cache",          res._headers()["pragma"] === "no-cache");
  check("noCache: Vary Cookie+Auth",         res._headers()["vary"] === "Cookie, Authorization");
}

function testWhenPredicate() {
  var mw = b.middleware.noCache({
    when: function (req) { return req.url.indexOf("/api/private/") === 0; },
  });
  var req1 = _mockReq("/api/public/foo");
  var res1 = _mockRes();
  mw(req1, res1, function () {});
  check("noCache when=false: no headers set", !res1._headers()["cache-control"]);

  var req2 = _mockReq("/api/private/bar");
  var res2 = _mockRes();
  mw(req2, res2, function () {});
  check("noCache when=true: headers set", res2._headers()["cache-control"] === "no-store");
}

function testCustomCacheControlAndVary() {
  var mw = b.middleware.noCache({
    cacheControl: "no-store, private",
    vary:         "Cookie",
  });
  var res = _mockRes();
  mw(_mockReq(), res, function () {});
  check("noCache: custom cacheControl", res._headers()["cache-control"] === "no-store, private");
  check("noCache: custom vary",         res._headers()["vary"] === "Cookie");
}

function testSkipExisting() {
  var mw = b.middleware.noCache({ skipExisting: true });
  var res = _mockRes();
  res.setHeader("Cache-Control", "public, max-age=600");
  var nextCalled = false;
  mw(_mockReq(), res, function () { nextCalled = true; });
  check("noCache skipExisting: pre-set header preserved",
        res._headers()["cache-control"] === "public, max-age=600");
  check("noCache skipExisting: next still called", nextCalled);
}

function testBadOpts() {
  var threw = null;
  try { b.middleware.noCache({ when: "not a fn" }); }
  catch (e) { threw = e; }
  check("noCache: bad when refused",
        threw && /no-cache\/bad-when/.test(threw.code || ""));
}

// Each writer below has its own Cache-Control default that is weaker than
// no-store. With b.middleware.noCache run first, the header the client receives
// still carries no-store, and a writer whose default carries no-transform keeps
// that directive too.
async function testNoStoreSurvivesFrameworkWriters() {
  var stubEngine = { render: function () { return "<p>page</p>"; } };
  var staticDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-nocache-static-"));
  fs.writeFileSync(path.join(staticDir, "hello.txt"), "hello world");
  var staticServe = b.staticServe.create({ root: staticDir });
  var jmap = b.mail.server.jmap.create({
    mailStore: {
      appendMessage: function () {},
      subscribePush: function () { return Promise.resolve(function () {}); },
    },
    accountsFor: async function () { return {}; },
    methods: {},
  });
  function middlewareRow(mw) {
    return function (req, res) {
      return mw(req, res, function () { res.statusCode = 404; res.end("fell through"); });
    };
  }
  var ROWS = [
    { name: "b.render.json", path: "/r", run: function (req, res) { b.render.json(res, { ok: true }); } },
    { name: "b.render.text", path: "/r", run: function (req, res) { b.render.text(res, "ok"); } },
    { name: "b.render.htmlString", path: "/r", run: function (req, res) { b.render.htmlString(res, "<p>x</p>"); } },
    { name: "b.render.redirect", path: "/r", run: function (req, res) { b.render.redirect(res, "/next"); } },
    { name: "b.render.stream", path: "/r", run: function (req, res) { return b.render.stream(res, ["a", "b"]); } },
    { name: "b.render.create().html", path: "/r",
      run: function (req, res) { b.render.create({ engine: stubEngine }).html(res, "page", {}); } },
    { name: "b.middleware.sse", path: "/events", noTransform: true,
      run: function (req, res) { return b.middleware.sse(async function () {}, { heartbeatMs: false })(req, res); } },
    { name: "b.middleware.openapiServe", path: "/openapi.json",
      run: middlewareRow(b.middleware.openapiServe({
        document: b.openapi.create({ info: { title: "T", version: "1.0.0" } }) })) },
    { name: "b.middleware.asyncapiServe", path: "/asyncapi.json",
      run: middlewareRow(b.middleware.asyncapiServe({
        document: b.asyncapi.create({ info: { title: "T", version: "1.0.0" } }) })) },
    { name: "b.middleware.securityTxt", path: "/.well-known/security.txt",
      run: middlewareRow(b.middleware.securityTxt({
        contact: ["mailto:security@example.com"], expires: "2099-01-01T00:00:00Z" })) },
    { name: "b.middleware.assetlinks", path: "/.well-known/assetlinks.json",
      run: middlewareRow(b.middleware.assetlinks({ statements: [{
        relation: ["delegate_permission/common.handle_all_urls"],
        target: { namespace: "android_app", package_name: "com.example.app",
                  sha256_cert_fingerprints: ["AB:CD:EF:01:23:45:67:89"] },
      }] })) },
    { name: "b.middleware.webAppManifest", path: "/manifest.webmanifest",
      run: middlewareRow(b.middleware.webAppManifest({ name: "Example App", start_url: "/", display: "standalone",
        icons: [{ src: "/icons/192.png", sizes: "192x192", type: "image/png" }] })) },
    { name: "b.middleware.protectedResourceMetadata", path: "/.well-known/oauth-protected-resource",
      run: middlewareRow(b.middleware.protectedResourceMetadata({
        resource: "https://api.example.com", authorizationServers: ["https://idp.example.com"] })) },
    { name: "b.a2a.middleware.agentCard", path: "/.well-known/agent.json",
      run: middlewareRow(b.a2a.middleware.agentCard({ card: { card: { agent: "test" }, signature: "sig" } })) },
    { name: "b.mail.server.jmap eventSourceHandler", path: "/jmap/eventsource?types=Email&closeafter=no&ping=60",
      run: function (req, res) { req.user = { id: "u1" }; jmap.eventSourceHandler(req, res); } },
    { name: "b.sse.create", path: "/stream", noTransform: true,
      run: function (req, res) { b.sse.create(req, res, { heartbeatMs: 0, audit: false }).close(); } },
    { name: "b.openapi.create().middleware", path: "/openapi.json",
      run: middlewareRow(b.openapi.create({ info: { title: "T", version: "1.0.0" } }).middleware()) },
    { name: "b.router.serveStatic", path: "/hello.txt",
      run: function (req, res) {
        req.pathname = "/hello.txt";
        return b.router.serveStatic(staticDir)(req, res, function () { res.statusCode = 404; res.end("fell through"); });
      } },
    { name: "b.staticServe.create", path: "/hello.txt", run: middlewareRow(staticServe) },
  ];
  var noCache = b.middleware.noCache();
  var server = http.createServer(function (req, res) {
    var row = ROWS[Number(req.headers["x-row"])];
    noCache(req, res, function () {});
    Promise.resolve().then(function () { return row.run(req, res); }).catch(function (e) {
      row.threw = e;
      if (!res.headersSent) res.statusCode = 500;
      if (!res.writableEnded) res.end();
    });
  });
  var port = await helpers.listenOnRandomPort(server);
  var failed = [];
  try {
    for (var i = 0; i < ROWS.length; i += 1) {
      var got = await new Promise(function (resolve) {
        var request = http.get({ host: "127.0.0.1", port: port, path: ROWS[i].path, headers: { "x-row": String(i) } },
          function (response) {
            resolve({ status: response.statusCode, cacheControl: response.headers["cache-control"] || "" });
            response.destroy();
          });
        request.setTimeout(5000, function () { request.destroy(new Error("no response within 5 s")); });
        request.on("error", function (e) { resolve({ status: 599, cacheControl: "request failed: " + e.message }); });
      });
      if (ROWS[i].threw) got.status = 598;
      var parsed = b.cdnCacheControl.parse(got.cacheControl) || {};
      var ok = got.status < 400 && parsed.noStore === true && (!ROWS[i].noTransform || parsed.noTransform === true);
      if (!ok) failed.push(ROWS[i].name + " sent " + got.status + " \"" + got.cacheControl + "\"");
    }
    var staticRow = ROWS.length - 1;
    var first = await new Promise(function (resolve, reject) {
      http.get({ host: "127.0.0.1", port: port, path: "/hello.txt", headers: { "x-row": String(staticRow) } },
        function (response) { response.resume(); resolve(response.headers.etag); }).on("error", reject);
    });
    var revalidated = await new Promise(function (resolve, reject) {
      http.get({ host: "127.0.0.1", port: port, path: "/hello.txt",
                 headers: { "x-row": String(staticRow), "if-none-match": first } },
        function (response) {
          response.resume();
          resolve({ status: response.statusCode, cacheControl: response.headers["cache-control"] || "" });
        }).on("error", reject);
    });
    var revalidatedParsed = b.cdnCacheControl.parse(revalidated.cacheControl) || {};
    if (revalidated.status !== 304 || revalidatedParsed.noStore !== true) {
      failed.push("b.staticServe.create 304 sent " + revalidated.status + " \"" + revalidated.cacheControl + "\"");
    }
  } finally {
    await new Promise(function (resolve) { server.close(resolve); server.closeAllConnections(); });
    fs.rmSync(staticDir, { recursive: true, force: true });
  }
  check("noCache: every framework writer keeps no-store" +
        (failed.length ? " (replaced by: " + failed.join("; ") + ")" : ""), failed.length === 0);

  var explicit = await new Promise(function (resolve) {
    var s = http.createServer(function (req, res) {
      noCache(req, res, function () {});
      b.render.json(res, { ok: true }, { headers: { "Cache-Control": "public, max-age=60" } });
    });
    helpers.listenOnRandomPort(s).then(function (p) {
      http.get({ host: "127.0.0.1", port: p, path: "/" }, function (response) {
        var value = response.headers["cache-control"];
        response.resume();
        s.close(function () { resolve(value); });
      });
    });
  });
  check("noCache: an explicit opts.headers Cache-Control on a render call still wins",
        explicit === "public, max-age=60", explicit);
}

async function run() {
  testSurface();
  testDefaultHeaders();
  testWhenPredicate();
  testCustomCacheControlAndVary();
  testSkipExisting();
  testBadOpts();
  await testNoStoreSurvivesFrameworkWriters();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
