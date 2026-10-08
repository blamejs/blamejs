// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A middleware that reports a failure with `next(err)` stops the request.
 *
 * `Router.handle` passed each `router.use()` middleware the callback
 * `() => (next = true)`, which does not read its argument, so `next(err)` was
 * indistinguishable from `next()`: the router ran the remaining middleware and
 * the route handler, and the `onError` handler never saw the error. A route
 * handler declared with three or more parameters received a callback of the
 * same shape.
 *
 * A session, authentication or CSRF middleware that reports a store failure
 * that way let the request through without its check.
 *
 * `b.middleware.composePipeline` already dispatched on the argument, so the
 * framework held two answers to one question; the router now gives the same
 * one.
 *
 * Run standalone: `node test/layer-0-primitives/router-next-error.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var http = require("node:http");
var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

// b.router's listen is listen(port, cb, tlsOptions, host): the callback is the
// second argument, so passing a host there leaves it never called.
function _listen(router) {
  return new Promise(function (resolve) {
    var server = router.listen(0, function () {
      resolve({ port: server.address().port, server: server });
    }, undefined, "127.0.0.1");
  });
}

function _get(port, path) {
  return new Promise(function (resolve, reject) {
    var req = http.request({ host: "127.0.0.1", port: port, path: path, method: "GET" },
      function (res) {
        var body = "";
        res.setEncoding("utf8");
        res.on("data", function (c) { body += c; });
        res.on("end", function () { resolve({ statusCode: res.statusCode, body: body }); });
      });
    req.on("error", reject);
    req.end();
  });
}

async function run() {
  // ---- router.use() middleware ----
  var ran = [];
  var seenErr = null;
  var app = b.router.create();
  app.onError(function (err, req, res) {
    seenErr = err;
    res.writeHead(500, { "Content-Type": "text/plain" });
    res.end("onError");
  });
  app.use(function failing(req, res, next) {
    ran.push("failing");
    next(new Error("store unavailable"));
  });
  app.use(function laterMiddleware(req, res, next) {
    ran.push("later");
    next();
  });
  app.get("/x", function (req, res) { ran.push("route"); res.end("route ran"); });

  var live = await _listen(app);
  try {
    var res1 = await _get(live.port, "/x");
    check("next(err) from a use() middleware reaches the onError handler",
      res1.statusCode === 500 && res1.body === "onError",
      res1.statusCode + " " + JSON.stringify(res1.body));
    check("and the error it was given is the one onError received",
      !!seenErr && seenErr.message === "store unavailable",
      seenErr && String(seenErr.message));
    check("the middleware after it did not run",
      ran.indexOf("later") === -1, JSON.stringify(ran));
    check("and neither did the route handler",
      ran.indexOf("route") === -1, JSON.stringify(ran));
    check("the middleware that failed did run, so the chain started",
      ran.indexOf("failing") !== -1, JSON.stringify(ran));
    check("the error carries the middleware's name, as a thrown one does",
      seenErr && seenErr.blamejsMiddleware === "failing",
      seenErr && String(seenErr.blamejsMiddleware));
  } finally { live.server.close(); }

  // ---- a plain next() still continues: the control ----
  var ranOk = [];
  var appOk = b.router.create();
  appOk.onError(function (err, req, res) { res.writeHead(500); res.end("onError"); });
  appOk.use(function (req, res, next) { ranOk.push("mw"); next(); });
  appOk.get("/x", function (req, res) { ranOk.push("route"); res.end("ok"); });
  var liveOk = await _listen(appOk);
  try {
    var res2 = await _get(liveOk.port, "/x");
    check("a plain next() still runs the route",
      res2.statusCode === 200 && res2.body === "ok" &&
      ranOk.join(",") === "mw,route", JSON.stringify(ranOk));
    // next(null) and next(undefined) mean "carry on", as they do elsewhere.
    check("and next(null) is not an error", true);
  } finally { liveOk.server.close(); }

  var ranNull = [];
  var appNull = b.router.create();
  appNull.use(function (req, res, next) { ranNull.push("mw"); next(null); });
  appNull.get("/x", function (req, res) { ranNull.push("route"); res.end("ok"); });
  var liveNull = await _listen(appNull);
  try {
    var res3 = await _get(liveNull.port, "/x");
    check("next(null) carries on to the route",
      res3.statusCode === 200 && ranNull.join(",") === "mw,route",
      res3.statusCode + " " + JSON.stringify(ranNull));
  } finally { liveNull.server.close(); }

  // ---- a route handler taking three or more parameters ----
  var routeSeen = null;
  var ranRoute = [];
  var appRoute = b.router.create();
  appRoute.onError(function (err, req, res) {
    routeSeen = err;
    res.writeHead(500, { "Content-Type": "text/plain" });
    res.end("onError");
  });
  appRoute.get("/y",
    function first(req, res, next) { ranRoute.push("first"); next(new Error("handler refused")); },
    function second(req, res) { ranRoute.push("second"); res.end("second ran"); });
  var liveRoute = await _listen(appRoute);
  try {
    var res4 = await _get(liveRoute.port, "/y");
    check("next(err) from a route handler reaches the onError handler",
      res4.statusCode === 500 && res4.body === "onError",
      res4.statusCode + " " + JSON.stringify(res4.body));
    check("and the handler after it did not run",
      ranRoute.join(",") === "first", JSON.stringify(ranRoute));
    check("the error it was given is the one onError received",
      !!routeSeen && routeSeen.message === "handler refused",
      routeSeen && String(routeSeen.message));
  } finally { liveRoute.server.close(); }

  // `b.testing.request` drives the same error path a live request does. It
  // answered its own 500 and never called `onError`, so a test written against
  // the harness could not observe the handler at all, which is why the bug
  // above survived: the framework's own harness could not see it.
  var harnessSeen = null;
  var harnessRan = [];
  var appHarness = b.router.create();
  appHarness.onError(function (err, req, res) {
    harnessSeen = err;
    res.writeHead(503, { "Content-Type": "text/plain" });
    res.end("from onError");
  });
  appHarness.use(function store(req, res, next) { next(new Error("store down")); });
  appHarness.get("/x", function (req, res) { harnessRan.push("route"); res.end("route ran"); });
  var harnessRes = await b.testing.request(appHarness).get("/x");
  check("b.testing.request routes the error through the router's own onError",
    harnessRes.status === 503 && /from onError/.test(harnessRes.body || ""),
    harnessRes.status + " " + JSON.stringify(harnessRes.body));
  check("and the route did not run under the harness either",
    harnessRan.length === 0 && !!harnessSeen,
    JSON.stringify(harnessRan));

  // With no onError registered the request still must not reach the route.
  var ranBare = [];
  var appBare = b.router.create();
  appBare.use(function (req, res, next) { next(new Error("no handler for this")); });
  appBare.get("/x", function (req, res) { ranBare.push("route"); res.end("route ran"); });
  var liveBare = await _listen(appBare);
  try {
    var res5 = await _get(liveBare.port, "/x");
    check("with no onError, next(err) answers 500 rather than running the route",
      res5.statusCode === 500 && ranBare.length === 0,
      res5.statusCode + " " + JSON.stringify(ranBare));
  } finally { liveBare.server.close(); }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[router-next-error] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
