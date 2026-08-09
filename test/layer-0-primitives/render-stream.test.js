// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.render.stream + b.safeAsync.writeChunk — writing an async iterable to a
 * response.
 *
 * Every consumer serving a generated download writes this loop, and the
 * obvious version is wrong in three ways that a local client never exposes:
 * it discards back-pressure, it hangs when the peer has gone, and a producer
 * that throws after the first byte turns a truncated body into an apparent
 * success. Each of those is asserted against the shipped primitive here.
 *
 * Run standalone: `node test/layer-0-primitives/render-stream.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function _res(opts) { return b.testing.streamingRes(opts); }

async function* _rows(n, onPull) {
  for (var i = 0; i < n; i += 1) {
    if (onPull) onPull(i);
    yield "row-" + i + "\n";
  }
}

async function testWritesEveryChunkAndEnds() {
  var res = _res();
  var ended = false;
  res.on("finish", function () { ended = true; });
  await b.render.stream(res, _rows(3), {
    headers: { "Content-Type": "text/csv; charset=utf-8" },
  });
  check("every chunk reaches the response",
        res._captured().toString("utf8") === "row-0\nrow-1\nrow-2\n");
  check("the response is ended once the producer is done", ended === true);
  check("the status is sent with the first chunk", res._statusCode === 200);
  check("the caller's content type is used",
        res._headers["content-type"] === "text/csv; charset=utf-8");
  check("a dynamic cache-control is set by default",
        typeof res._headers["cache-control"] === "string");
}

// A local client drains instantly, so a consumer that discards `write()`'s
// return value looks correct and buffers without limit against a slow one.
// The double reports "full" past its high-water mark, which is the only way to
// exercise the path at all.
async function testAwaitsBackpressure() {
  var res = _res({ highWaterMark: 8 });
  var refused = 0;
  var realWrite = res.write;
  res.write = function (chunk) {
    var accepted = realWrite.call(res, chunk);
    if (accepted === false) refused += 1;
    return accepted;
  };
  await b.render.stream(res, _rows(20));
  check("the double actually reported back-pressure (else the next check is vacuous)",
        refused > 0);
  check("every row still arrives, in order",
        res._captured().toString("utf8") === Array.from({ length: 20 },
          function (_, i) { return "row-" + i + "\n"; }).join(""));
}

// A closed socket never emits `drain`, so a loop that always waits for one
// hangs the request forever — and without a disconnect check it keeps pulling
// rows from the database to write them nowhere.
async function testStopsWhenThePeerGoes() {
  var res = _res();
  var pulled = 0;
  res.destroyed = false;
  var settled = false;
  b.render.stream(res, _rows(50, function (i) {
    pulled = i + 1;
    if (i === 2) res.destroyed = true;              // the client hangs up
  })).then(function () { settled = true; }, function () { settled = true; });
  await helpers.waitUntil(function () { return settled; }, {
    timeoutMs: 4000,
    label: "render.stream: a closed peer settles the loop instead of hanging",
  });
  check("the loop stops instead of hanging on a drain that never comes", settled === true);
  check("it stops pulling from the producer once the peer is gone", pulled < 50);
}

// The one worth fixing centrally. After the first byte the status line cannot
// be replaced, so an error page appends its message to the partial body and
// the client sees a 200 whose last row reads "Internal Server Error".
async function testMidStreamThrowDestroysRatherThanLying() {
  var res = _res();
  var destroyed = false;
  res.destroy = function () { destroyed = true; };
  var boom = new Error("cursor died halfway");
  async function* failing() {
    yield "order_id,total\n";
    yield "ord_1,10.00\n";
    throw boom;
  }
  var caught = null;
  try { await b.render.stream(res, failing()); } catch (e) { caught = e; }

  check("the failure reaches the caller so it is still logged", caught === boom);
  check("the connection is destroyed, so the transfer reads as incomplete", destroyed === true);
  check("no prose is appended to the rows the client already has",
        res._captured().toString("utf8").indexOf("Internal Server Error") === -1);
  check("the rows written before the failure are unchanged",
        res._captured().toString("utf8") === "order_id,total\nord_1,10.00\n");
}

// The status line is written before the first chunk is pulled, so there is no
// "before commit" window: a producer that fails on its very first row has
// already put headers and `Transfer-Encoding: chunked` on the wire. Treating
// that as uncommitted left the response neither ended nor destroyed and the
// client waited forever.
async function testThrowOnTheFirstRowStillEndsTheTransfer() {
  var res = _res();
  var destroyed = false;
  res.destroy = function () { destroyed = true; res.destroyed = true; };
  async function* failsImmediately() {
    throw new Error("query rejected");
    yield "unreachable";                             // eslint-disable-line no-unreachable
  }
  var caught = null;
  try { await b.render.stream(res, failsImmediately()); } catch (e) { caught = e; }
  check("the failure is re-thrown", caught !== null);
  check("the response does not stay open once its headers are out", destroyed === true);
}

async function testOnErrorRethrowLeavesTheSocketToTheCaller() {
  var res = _res();
  var destroyed = false;
  res.destroy = function () { destroyed = true; };
  async function* failing() { yield "a"; throw new Error("mid"); }
  var caught = null;
  try { await b.render.stream(res, failing(), { onError: "rethrow" }); }
  catch (e) { caught = e; }
  check("onError rethrow still surfaces the failure", caught !== null);
  check("and leaves the connection for the caller to decide about", destroyed === false);
}

async function testRejectsInputItCannotStream() {
  var res = _res();
  var threw = false;
  try { await b.render.stream(res, 42); } catch (_e) { threw = true; }
  check("a non-iterable is refused at the call, not mid-stream", threw);

  var badOpt = false;
  try { await b.render.stream(res, _rows(1), { onError: "ignore" }); }
  catch (_e) { badOpt = true; }
  check("an unknown onError is a config typo and throws", badOpt);

  var unknown = false;
  try { await b.render.stream(res, _rows(1), { statuz: 200 }); }
  catch (_e) { unknown = true; }
  check("a misspelled option is refused rather than silently dropped", unknown);
}

// The drain-aware write is one primitive, composed by the archive writer and
// the response streamer alike. A closed stream must reject rather than wait.
async function testWriteChunkSettlesOnAClosedStream() {
  var EventEmitter = require("node:events").EventEmitter;
  var sink = new EventEmitter();
  sink.write = function () { return false; };
  var settled = null;
  var run = b.safeAsync.writeChunk(sink, "x").then(
    function () { settled = "resolved"; }, function () { settled = "rejected"; });
  sink.emit("close");
  await run;
  check("a stream that closes before draining rejects instead of hanging",
        settled === "rejected");

  var ok = new EventEmitter();
  ok.write = function () { return true; };
  var accepted = false;
  await b.safeAsync.writeChunk(ok, "x").then(function () { accepted = true; });
  check("an accepted write resolves without waiting for a drain", accepted === true);
}

// Every failure below was measured against a real http.Server before it was
// fixed: a process kill, three hangs, and two truncations that read as
// success. They are asserted here through the shipped consumer path.
async function testAgainstARealServer() {
  var http = require("node:http");
  var nodeUrl = require("node:url");
  void nodeUrl;

  async function serve(handler) {
    var srv = http.createServer(handler);
    srv.unref();
    await new Promise(function (r) { srv.listen(0, "127.0.0.1", r); });
    return srv;
  }
  function get(port, opts) {
    return new Promise(function (resolve) {
      var req = http.get({ host: "127.0.0.1", port: port, path: "/" }, function (r) {
        var body = "";
        r.setEncoding("utf8");
        r.on("data", function (d) { body += d; });
        r.on("end", function () { resolve({ status: r.statusCode, body: body, complete: r.complete }); });
        r.on("aborted", function () { resolve({ status: r.statusCode, body: body, complete: false }); });
      });
      req.on("error", function (e) { resolve({ error: e.code || e.message, body: "" }); });
      if (opts && opts.timeoutMs) {
        req.setTimeout(opts.timeoutMs, function () { req.destroy(); resolve({ error: "TIMEOUT" }); });
      }
    });
  }

  // A producer that fails on its FIRST row still has headers on the wire, so
  // the response must not be left open. It used to hang the client forever.
  var srvEarly = await serve(async function (req, res) {
    async function* fails() { throw new Error("query rejected"); }
    try { await b.render.stream(res, fails()); } catch (_e) { /* logged by the caller */ }
  });
  var early = await get(srvEarly.address().port, { timeoutMs: 3000 });
  srvEarly.close();
  check("a failure on the first row does not leave the client waiting",
        early.error !== "TIMEOUT");
  check("and it is not reported as a complete transfer",
        early.complete !== true || early.body === "");

  // The whole point: a truncated export must not arrive as a complete one.
  var srvMid = await serve(async function (req, res) {
    async function* fails() {
      yield "order_id,total\n";
      yield "ord_1,10.00\n";
      throw new Error("cursor died halfway");
    }
    try {
      await b.render.stream(res, fails(), { headers: { "Content-Type": "text/csv" } });
    } catch (_e) { /* logged by the caller */ }
  });
  var mid = await get(srvMid.address().port, { timeoutMs: 3000 });
  srvMid.close();
  check("a mid-stream failure reaches the client as an incomplete transfer",
        mid.complete !== true);
  check("and carries no prose appended to the rows already sent",
        String(mid.body).indexOf("Internal Server Error") === -1);

  // An abort is a truncation too. Ending normally would hand the client four
  // rows of a fifty-row export as a well-formed, successful 200.
  var srvAbort = await serve(async function (req, res) {
    var ac = new AbortController();
    // Aborted from inside the producer at a known row, so the point of
    // truncation is fixed rather than whatever a timer happens to land on.
    async function* slow() {
      for (var i = 0; i < 50; i += 1) {
        if (i === 4) ac.abort();
        yield "row-" + i + "\n";
      }
    }
    try { await b.render.stream(res, slow(), { signal: ac.signal }); } catch (_e) { /* fine */ }
  });
  var aborted = await get(srvAbort.address().port, { timeoutMs: 4000 });
  srvAbort.close();
  check("an abort does not present a partial export as complete",
        aborted.complete !== true);

  // The abort has to reach a producer that is blocked, not only the gap
  // between chunks, or the request is pinned until an unrelated timeout.
  var settled = false;
  var srvStuck = await serve(async function (req, res) {
    var ac = new AbortController();
    async function* stuck() {
      yield "row-0\n";
      ac.abort();                                    // then block on a query that never returns
      await new Promise(function () { /* never settles */ });
    }
    try { await b.render.stream(res, stuck(), { signal: ac.signal }); } catch (_e) { /* fine */ }
    settled = true;
  });
  var stuck = await get(srvStuck.address().port, { timeoutMs: 4000 });
  await helpers.waitUntil(function () { return settled; }, {
    timeoutMs: 4000, label: "render.stream: an abort settles a blocked producer",
  });
  srvStuck.close();
  check("an abort settles a producer that is blocked", settled === true);
  check("and the client is not left waiting either", stuck.error !== "TIMEOUT");

  // The framework's own router must survive a route that fails after the first
  // byte. This used to throw ERR_HTTP_HEADERS_SENT out of a promise rejection
  // handler and take the process with it.
  var router = b.router.create();
  router.get("/partial", async function (req, res) {
    res.writeHead(200, { "Content-Type": "text/csv" });
    res.write("id,total\n1,10\n");
    throw new Error("producer failed mid-export");
  });
  var routed = router.listen(0, function () {});
  routed.unref();
  await helpers.waitUntil(function () { return !!routed.address(); }, {
    timeoutMs: 4000, label: "render.stream: the router bound a port",
  });
  var viaRouter = await new Promise(function (resolve) {
    var req = http.get({ host: "127.0.0.1", port: routed.address().port, path: "/partial" },
      function (r) {
        var body = "";
        r.on("data", function (d) { body += d; });
        r.on("end", function () { resolve({ complete: r.complete, body: body }); });
        r.on("aborted", function () { resolve({ complete: false, body: body }); });
      });
    req.on("error", function (e) { resolve({ error: e.code }); });
    req.setTimeout(3000, function () { req.destroy(); resolve({ error: "TIMEOUT" }); });
  });
  routed.close();
  check("the router survives a route that fails after the first byte",
        viaRouter.error !== "TIMEOUT");
  check("and the client is told the transfer is incomplete",
        viaRouter.complete !== true);
}

// The archive writer and the response streamer share one drain-aware write, so
// a destination that has already gone away must fail both rather than pin one.
async function testAlreadyClosedStreamRejects() {
  var Writable = require("node:stream").Writable;
  var sink = new Writable({ write: function (c, e, cb) { cb(); } });
  sink.destroy();
  await helpers.waitUntil(function () { return sink.destroyed === true; }, {
    timeoutMs: 2000, label: "writeChunk: the sink reports destroyed",
  });
  var outcome = null;
  await b.safeAsync.writeChunk(sink, "x").then(
    function () { outcome = "resolved"; }, function (e) { outcome = e.code; });
  check("a stream closed BEFORE the call rejects instead of waiting forever",
        outcome === "async/writable-closed");

  var bad = null;
  await b.safeAsync.writeChunk(undefined, "x").then(
    function () { bad = "resolved"; }, function (e) { bad = e.code; });
  check("the error carries its code in .code, not its prose",
        bad === "async/bad-writable");
}

// How to signal failure once the status line is out is one question with three
// answers, and getting any of them wrong is how a truncated body reaches a
// client as a complete one.
function testFailAfterHeadersPicksTheRightSignal() {
  var helpersApi = b.requestHelpers;

  var fresh = { headersSent: false };
  check("a response whose headers are still ours is left to the caller",
        helpersApi.failAfterHeaders(fresh) === false);

  var h1 = { headersSent: true, statusCode: 200, destroyed: false, destroy: function () { h1.destroyed = true; } };
  check("HTTP/1.1 destroys the socket, so the chunked body ends unterminated",
        helpersApi.failAfterHeaders(h1) === true && h1.destroyed === true);

  // A bare destroy on HTTP/2 closes with NO_ERROR, which a client reads as a
  // clean end — the truncated body would arrive as a complete 200.
  var closedWith = null;
  var h2 = {
    headersSent: true, statusCode: 200,
    stream: { close: function (code) { closedWith = code; } },
    destroy: function () { closedWith = "destroy"; },
  };
  helpersApi.failAfterHeaders(h2);
  check("HTTP/2 closes the stream with a non-zero error code", closedWith === 0x02);

  // Nothing can be truncated in a response that carries no body, so destroying
  // would throw away a valid one.
  [204, 304].forEach(function (status) {
    var ended = false, killed = false;
    var bodiless = {
      headersSent: true, statusCode: status,
      end: function () { ended = true; }, destroy: function () { killed = true; },
    };
    check("a " + status + " is completed rather than destroyed",
          helpersApi.failAfterHeaders(bodiless) === true && ended === true && killed === false);
  });
  var headEnded = false;
  var head = {
    headersSent: true, statusCode: 200, _hasBody: false,
    end: function () { headEnded = true; }, destroy: function () { headEnded = "destroyed"; },
  };
  helpersApi.failAfterHeaders(head);
  check("a HEAD response is completed rather than destroyed", headEnded === true);
}

async function run() {
  testFailAfterHeadersPicksTheRightSignal();
  await testWritesEveryChunkAndEnds();
  await testAgainstARealServer();
  await testAlreadyClosedStreamRejects();
  await testAwaitsBackpressure();
  await testStopsWhenThePeerGoes();
  await testMidStreamThrowDestroysRatherThanLying();
  await testThrowOnTheFirstRowStillEndsTheTransfer();
  await testOnErrorRethrowLeavesTheSocketToTheCaller();
  await testRejectsInputItCannotStream();
  await testWriteChunkSettlesOnAClosedStream();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("render-stream OK — " + helpers.getChecks() + " checks"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
