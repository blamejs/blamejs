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

  await _staleNextCases();
}

// A middleware's `next` belongs to that middleware's turn. One that keeps its
// callback and calls it again after the chain has moved on must not decide
// the verdict for a later middleware. Each case has the earlier middleware
// store its `next`; the later one calls the stored callback during its own
// turn, which is exactly when a delayed or duplicated call lands.
function _deny(res) {
  res.statusCode = 403;
  setImmediate(function () { res.end("denied"); });
}

async function _staleNextCases() {
  // (a) use() chain: a gate that never calls next and ends its 403 on a later
  // tick. The stale next() from the middleware before it must not let the
  // request through.
  var staleA = null;
  var ranA = [];
  var appA = b.router.create();
  appA.use(function keeper(req, res, next) { staleA = next; next(); });
  appA.use(async function gate(req, res, _next) {
    staleA();
    await Promise.resolve();
    _deny(res);
  });
  appA.get("/x", function (req, res) { ranA.push("route"); res.end("ok"); });
  var liveA = await _listen(appA);
  try {
    var rA = await _get(liveA.port, "/x");
    check("use(): a stale next() from an earlier middleware does not pass a gate that never called next",
      rA.statusCode === 403 && rA.body === "denied" && ranA.length === 0,
      rA.statusCode + " " + JSON.stringify(rA.body) + " " + JSON.stringify(ranA));
  } finally { liveA.server.close(); }

  // (b) use() chain: a stale next(err) from an earlier middleware must not
  // abort a later middleware that called next(), nor be blamed on it.
  var staleB = null;
  var errB = null;
  var ranB = [];
  var appB = b.router.create();
  appB.onError(function (err, req, res) { errB = err; res.writeHead(500); res.end("onError"); });
  appB.use(function keeper(req, res, next) { staleB = next; next(); });
  appB.use(function second(req, res, next) {
    staleB(new Error("late error from keeper"));
    next();
  });
  appB.get("/x", function (req, res) { ranB.push("route"); res.end("ok"); });
  var liveB = await _listen(appB);
  try {
    var rB = await _get(liveB.port, "/x");
    check("use(): a stale next(err) from an earlier middleware does not abort a later one that called next()",
      rB.statusCode === 200 && rB.body === "ok" && errB === null && ranB.join(",") === "route",
      rB.statusCode + " " + JSON.stringify(rB.body) + " " + (errB && errB.blamejsMiddleware));
  } finally { liveB.server.close(); }

  // (c) route-handler chain: the same stale next() against an async gate
  // handler declared with three parameters.
  var staleC = null;
  var ranC = [];
  var appC = b.router.create();
  appC.get("/y",
    function first(req, res, next) { staleC = next; next(); },
    async function gate(req, res, _next) {
      staleC();
      await Promise.resolve();
      _deny(res);
    },
    function final(req, res, _next) { ranC.push("final"); res.end("ok"); });
  var liveC = await _listen(appC);
  try {
    var rC = await _get(liveC.port, "/y");
    check("route handlers: a stale next() from an earlier handler does not pass a gate that never called next",
      rC.statusCode === 403 && rC.body === "denied" && ranC.length === 0,
      rC.statusCode + " " + JSON.stringify(rC.body) + " " + JSON.stringify(ranC));
  } finally { liveC.server.close(); }

  // (d) route-handler chain: a stale next(err) does not abort the handler
  // that legitimately advanced.
  var staleD = null;
  var errD = null;
  var ranD = [];
  var appD = b.router.create();
  appD.onError(function (err, req, res) { errD = err; res.writeHead(500); res.end("onError"); });
  appD.get("/y",
    function first(req, res, next) { staleD = next; next(); },
    function second(req, res, next) { staleD(new Error("late error from first")); next(); },
    function final(req, res, _next) { ranD.push("final"); res.end("ok"); });
  var liveD = await _listen(appD);
  try {
    var rD = await _get(liveD.port, "/y");
    check("route handlers: a stale next(err) from an earlier handler does not abort a later one",
      rD.statusCode === 200 && errD === null && ranD.join(",") === "final",
      rD.statusCode + " " + JSON.stringify(rD.body) + " " + (errD && errD.message));
  } finally { liveD.server.close(); }

  // (e) Within its own turn, a next(err) wins over a next() in either
  // order: the request stops and onError answers.
  var ranE = [];
  var errE = null;
  var appE = b.router.create();
  appE.onError(function (err, req, res) { errE = err; res.writeHead(500); res.end("onError"); });
  appE.use(function twice(req, res, next) { next(); next(new Error("second call")); });
  appE.get("/x", function (req, res) { ranE.push("route"); res.end("ok"); });
  var liveE = await _listen(appE);
  try {
    var rE = await _get(liveE.port, "/x");
    check("use(): next() then next(err) in the same turn stops the request with the error",
      rE.statusCode === 500 && errE && errE.message === "second call" && ranE.length === 0,
      rE.statusCode + " " + JSON.stringify(rE.body));
  } finally { liveE.server.close(); }

  var ranE2 = [];
  var errE2 = null;
  var appE2 = b.router.create();
  appE2.onError(function (err, req, res) { errE2 = err; res.writeHead(500); res.end("onError"); });
  appE2.use(function twice(req, res, next) { next(new Error("first call")); next(); });
  appE2.get("/x", function (req, res) { ranE2.push("route"); res.end("ok"); });
  var liveE2 = await _listen(appE2);
  try {
    var rE2 = await _get(liveE2.port, "/x");
    check("use(): next(err) then next() in the same turn stops the request with the first error",
      rE2.statusCode === 500 && errE2 && errE2.message === "first call" && ranE2.length === 0,
      rE2.statusCode + " " + JSON.stringify(rE2.body));
  } finally { liveE2.server.close(); }

  var ranE3 = [];
  var errE3 = null;
  var appE3 = b.router.create();
  appE3.onError(function (err, req, res) { errE3 = err; res.writeHead(500); res.end("onError"); });
  appE3.get("/x",
    function twice(req, res, next) { next(); next(new Error("handler second call")); },
    function final(req, res, _next) { ranE3.push("final"); res.end("ok"); });
  var liveE3 = await _listen(appE3);
  try {
    var rE3 = await _get(liveE3.port, "/x");
    check("route handlers: next() then next(err) in the same turn stops the request with the error",
      rE3.statusCode === 500 && errE3 && errE3.message === "handler second call" && ranE3.length === 0,
      rE3.statusCode + " " + JSON.stringify(rE3.body));
  } finally { liveE3.server.close(); }

  // Control: a middleware that awaits and then calls next() still continues.
  var ranF = [];
  var appF = b.router.create();
  appF.use(async function slow(req, res, next) { await Promise.resolve(); next(); });
  appF.get("/x", function (req, res) { ranF.push("route"); res.end("ok"); });
  var liveF = await _listen(appF);
  try {
    var rF = await _get(liveF.port, "/x");
    check("control: an async middleware that calls next() before it resolves still continues",
      rF.statusCode === 200 && ranF.join(",") === "route",
      rF.statusCode + " " + JSON.stringify(ranF));
  } finally { liveF.server.close(); }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[router-next-error] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
