// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Vary set earlier on a response is merged, not replaced.
 *
 * A middleware that varies the response (b.middleware.cors adds Origin,
 * b.middleware.compression adds Accept-Encoding) sets Vary with setHeader.
 * node:http lets a header object passed to writeHead replace a header set
 * that way, so a writer whose header object carried its own Vary sent only
 * that value and a shared cache stored one response for every Origin.
 * b.requestHelpers.mergeVary joins the two lists, and every framework writer
 * that passes a header object to writeHead goes through it.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var http    = require("http");

function testMergeVaryUnit() {
  function res(existing) {
    var store = existing === undefined ? {} : { vary: existing };
    return {
      getHeader: function (n) { return store[n.toLowerCase()]; },
      setHeader: function (n, v) { store[n.toLowerCase()] = v; },
    };
  }
  var mv = b.requestHelpers.mergeVary;
  var wrong = [];
  function expect(label, got, want) {
    if (JSON.stringify(got) !== JSON.stringify(want)) wrong.push(label + " -> " + JSON.stringify(got));
  }
  expect("earlier Cookie + Vary Origin", mv(res("Cookie"), { Vary: "Origin", "X-A": "1" }), { "X-A": "1", Vary: "Cookie, Origin" });
  expect("lower-case key, repeated token in another case", mv(res("Cookie"), { vary: "cookie, Origin" }), { Vary: "Cookie, Origin" });
  expect("no earlier Vary", mv(res(), { Vary: "Origin" }), { Vary: "Origin" });
  expect("no Vary in the object", mv(res("Cookie"), { "X-A": "1" }), { "X-A": "1" });
  expect("earlier value is an array", mv(res(["Cookie", "Accept"]), { Vary: "Origin" }), { Vary: "Cookie, Accept, Origin" });
  expect("a star on either side", mv(res("Cookie"), { Vary: "*" }), { Vary: "*" });
  expect("two keys that differ only in case", mv(res(), { Vary: "Origin", VARY: "Accept" }), { Vary: "Origin, Accept" });
  var input = { Vary: "Origin" };
  mv(res("Cookie"), input);
  expect("the caller's object is not changed", input, { Vary: "Origin" });
  check("requestHelpers.mergeVary joins an earlier Vary with the header object's Vary" +
        (wrong.length ? " (" + wrong.join("; ") + ")" : ""), wrong.length === 0);
}

async function testWritersKeepAnEarlierVary() {
  var withVary = { headers: { Vary: "Accept-Language" } };
  var docsOrigin = { allowOrigin: "https://docs.example.com" };
  function middlewareRow(mw) {
    return function (req, res) {
      return mw(req, res, function () { res.statusCode = 404; res.end("fell through"); });
    };
  }
  var ROWS = [
    { name: "b.render.json", path: "/r", want: "Cookie, Accept-Language",
      run: function (req, res) { b.render.json(res, { ok: true }, withVary); } },
    { name: "b.render.text", path: "/r", want: "Cookie, Accept-Language",
      run: function (req, res) { b.render.text(res, "ok", withVary); } },
    { name: "b.render.htmlString", path: "/r", want: "Cookie, Accept-Language",
      run: function (req, res) { b.render.htmlString(res, "<p>x</p>", withVary); } },
    { name: "b.render.redirect", path: "/r", want: "Cookie, Accept-Language",
      run: function (req, res) { b.render.redirect(res, "/next", withVary); } },
    { name: "b.render.stream", path: "/r", want: "Cookie, Accept-Language",
      run: function (req, res) { return b.render.stream(res, ["a", "b"], withVary); } },
    { name: "b.middleware.openapiServe", path: "/openapi.json", want: "Cookie, Origin",
      run: middlewareRow(b.middleware.openapiServe({ accessControl: docsOrigin,
        document: b.openapi.create({ info: { title: "T", version: "1.0.0" } }) })) },
    { name: "b.middleware.asyncapiServe", path: "/asyncapi.json", want: "Cookie, Origin",
      run: middlewareRow(b.middleware.asyncapiServe({ accessControl: docsOrigin,
        document: b.asyncapi.create({ info: { title: "T", version: "1.0.0" } }) })) },
  ];
  var server = http.createServer(function (req, res) {
    res.setHeader("Vary", "Cookie");
    var row = ROWS[Number(req.headers["x-row"])];
    Promise.resolve().then(function () { return row.run(req, res); })
      .catch(function () { if (!res.writableEnded) res.end(); });
  });
  var port = await helpers.listenOnRandomPort(server);
  var failed = [];
  try {
    for (var i = 0; i < ROWS.length; i += 1) {
      var got = await new Promise(function (resolve) {
        var request = http.get({ host: "127.0.0.1", port: port, path: ROWS[i].path, headers: { "x-row": String(i) } },
          function (response) {
            resolve({ status: response.statusCode, vary: response.headers.vary });
            response.destroy();
          });
        request.setTimeout(5000, function () { request.destroy(new Error("no response within 5 s")); });
        request.on("error", function (e) { resolve({ status: 599, vary: "request failed: " + e.message }); });
      });
      if (got.vary !== ROWS[i].want) failed.push(ROWS[i].name + " sent Vary " + JSON.stringify(got.vary) + " (status " + got.status + ")");
    }
  } finally {
    await new Promise(function (resolve) { server.close(resolve); });
  }
  check("framework writers keep a Vary set earlier on the response" +
        (failed.length ? " (" + failed.join("; ") + ")" : ""), failed.length === 0);
}

// Middleware that add their own Vary tokens join the list an earlier
// middleware set: b.middleware.noCache adds Cookie and Authorization, and
// b.middleware.compression adds Accept-Encoding to the header object a
// handler passes to writeHead without dropping the Vary already on res.
async function testVaryAddingMiddlewareKeepAnEarlierVary() {
  var noCache = b.middleware.noCache();
  var compression = b.middleware.compression({ threshold: 0 });
  var ROWS = [
    { name: "b.middleware.noCache", want: "Origin, Cookie, Authorization",
      run: function (req, res) { noCache(req, res, function () { res.end("ok"); }); } },
    { name: "b.middleware.compression over writeHead(status, { Vary })", want: "Origin, Accept-Language, Accept-Encoding",
      run: function (req, res) {
        compression(req, res, function () {
          res.writeHead(200, { "Content-Type": "text/plain", Vary: "Accept-Language" });
          res.end("hello hello hello hello hello");
        });
      } },
  ];
  var server = http.createServer(function (req, res) {
    res.setHeader("Vary", "Origin");
    ROWS[Number(req.headers["x-row"])].run(req, res);
  });
  var port = await helpers.listenOnRandomPort(server);
  var failed = [];
  try {
    for (var i = 0; i < ROWS.length; i += 1) {
      var got = await new Promise(function (resolve) {
        var request = http.get({ host: "127.0.0.1", port: port, path: "/",
          headers: { "x-row": String(i), "accept-encoding": "gzip" } }, function (response) {
          resolve(response.headers.vary);
          response.destroy();
        });
        request.setTimeout(5000, function () { request.destroy(new Error("no response within 5 s")); });
        request.on("error", function (e) { resolve("request failed: " + e.message); });
      });
      if (got !== ROWS[i].want) failed.push(ROWS[i].name + " sent Vary " + JSON.stringify(got));
    }
  } finally {
    await new Promise(function (resolve) { server.close(resolve); });
  }
  check("Vary-adding middleware keep a Vary set earlier on the response" +
        (failed.length ? " (" + failed.join("; ") + ")" : ""), failed.length === 0);
}

async function run() {
  testMergeVaryUnit();
  await testWritersKeepAnEarlierVary();
  await testVaryAddingMiddlewareKeepAnEarlierVary();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
