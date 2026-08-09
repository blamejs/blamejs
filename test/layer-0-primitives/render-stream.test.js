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
  // The query rejects before the first row, which is how a cursor that cannot
  // open reaches this primitive.
  async function* failsImmediately() {
    await Promise.reject(new Error("query rejected"));
    yield "never";
  }
  var caught = null;
  try { await b.render.stream(res, failsImmediately()); } catch (e) { caught = e; }
  check("the failure is re-thrown", caught !== null);
  check("the response does not stay open once its headers are out", destroyed === true);
}

// A signal that was already aborted when the call began takes the same path as
// one that fires mid-stream: the status line has gone out, so an empty export
// ended normally is still a truncated one presented as success.
async function testAPreAbortedSignalIsATruncationToo() {
  var res = _res();
  var destroyed = false;
  res.destroy = function () { destroyed = true; res.destroyed = true; };
  var ac = new AbortController();
  ac.abort();
  await b.render.stream(res, _rows(5), { signal: ac.signal });
  check("a signal aborted before the call does not end as a success", destroyed === true);
  check("and nothing was produced", res._captured().length === 0);
}

// A rejected iterator step does not run `for await`'s cleanup, so a producer
// abandoned mid-pull stays suspended and whatever it holds — a cursor, a file
// handle, a `finally` that closes a connection — is never released.
async function testTheProducerIsReleasedWhenTheLoopStopsEarly() {
  var res = _res();
  res.destroy = function () { res.destroyed = true; };
  var returned = false;
  var ac = new AbortController();
  var source = {};
  source[Symbol.asyncIterator] = function () {
    return {
      next: function () {
        ac.abort();
        return new Promise(function () { /* a query that never answers */ });
      },
      return: function () { returned = true; return Promise.resolve({ done: true }); },
    };
  };
  await b.render.stream(res, source, { signal: ac.signal });
  check("the producer is given its cleanup when an abort wins the pull", returned === true);

  // The same when the PEER goes rather than the caller aborting.
  var res2 = _res();
  var returned2 = false;
  var source2 = {};
  source2[Symbol.asyncIterator] = function () {
    return {
      next: function () {
        res2.destroyed = true;
        res2.emit("close");
        return new Promise(function () { /* never answers */ });
      },
      return: function () { returned2 = true; return Promise.resolve({ done: true }); },
    };
  };
  var settled = false;
  b.render.stream(res2, source2).then(function () { settled = true; }, function () { settled = true; });
  await helpers.waitUntil(function () { return settled; }, {
    timeoutMs: 4000, label: "render.stream: a disconnect settles a blocked pull",
  });
  check("a disconnect during a blocked pull settles the stream", settled === true);
  check("and releases the producer", returned2 === true);
}

// `return()` on an async generator queues behind the pull it means to cancel,
// so a generator parked in an unresolved `await` never reaches its `finally`
// and whatever it holds stays open. Cancellation has to reach that pending work
// instead, which is what the signal handed to a producer function is for.
async function testCancellationReachesAGeneratorBlockedInItsOwnAwait() {
  var res = _res();
  res.destroy = function () { res.destroyed = true; };
  var ended = false;
  res.on("finish", function () { ended = true; });
  var ac = new AbortController();
  var cursorClosed = false;
  var pullStarted = false;

  // A real async generator — not a hand-written iterator with an obliging
  // `return()`, which is exactly what hides this.
  async function* rows(signal) {
    try {
      yield "header\n";
      pullStarted = true;
      await new Promise(function (resolve, reject) {
        // The query the client walked away from. Only the signal ends it.
        signal.addEventListener("abort", function () { reject(new Error("cancelled")); },
                                { once: true });
      });
      yield "never\n";
    } finally {
      cursorClosed = true;
    }
  }

  var done = false;
  b.render.stream(res, function (signal) { return rows(signal); }, { signal: ac.signal })
    .then(function () { done = true; }, function () { done = true; });
  await helpers.waitUntil(function () { return pullStarted; }, {
    timeoutMs: 4000, label: "render.stream: the generator reached its blocking await",
  });
  ac.abort();
  await helpers.waitUntil(function () { return done && cursorClosed; }, {
    timeoutMs: 4000, label: "render.stream: the blocked generator ran its finally",
  });
  check("a generator blocked in its own await still releases what it holds", cursorClosed === true);
  check("and the truncated response is not passed off as complete",
        ended === false && res.destroyed === true);

  // A producer that ignores the signal is still not allowed to hold the
  // response open — the stream settles and the transfer is broken either way.
  var res2 = _res();
  res2.destroy = function () { res2.destroyed = true; };
  var ac2 = new AbortController();
  async function* stubborn() { yield "a"; await new Promise(function () {}); }
  var settled2 = false;
  b.render.stream(res2, stubborn(), { signal: ac2.signal })
    .then(function () { settled2 = true; }, function () { settled2 = true; });
  await helpers.waitUntil(function () { return res2._captured().length >= 1; }, {
    timeoutMs: 4000, label: "render.stream: the stubborn producer wrote its first chunk",
  });
  ac2.abort();
  await helpers.waitUntil(function () { return settled2; }, {
    timeoutMs: 4000, label: "render.stream: an unco-operative producer does not pin the response",
  });
  check("an unco-operative producer does not keep the response alive", settled2 === true);
}

// A source that throws while being opened must not leave a committed response
// behind: the status line is not written until there is something to stream.
async function testAFailureToOpenTheSourceIsNotACommittedResponse() {
  var res = _res();
  var ended = false;
  res.on("finish", function () { ended = true; });
  var boom = {};
  boom[Symbol.asyncIterator] = function () { throw new Error("cannot open cursor"); };
  var caught = null;
  try { await b.render.stream(res, boom); } catch (e) { caught = e; }
  check("an iterator method that throws reaches the caller", caught !== null &&
        caught.message === "cannot open cursor");
  check("with nothing committed, so an error page is still possible",
        res.headersSent === false && ended === false);

  var res2 = _res();
  var caught2 = null;
  try {
    await b.render.stream(res2, function () { throw new Error("no connection"); });
  } catch (e) { caught2 = e; }
  check("so does a producer factory that throws", caught2 !== null &&
        caught2.message === "no connection");
  check("and it commits nothing either", res2.headersSent === false);

  var res3 = _res();
  var caught3 = null;
  try { await b.render.stream(res3, function () { return 42; }); } catch (e) { caught3 = e; }
  check("a factory that does not return an iterable is refused", caught3 !== null);
}

// A producer that breaks the iterator protocol has to fail, not be tolerated:
// reading `done` off a non-object yields undefined every time, so a forgiving
// loop pulls from it forever with the response held open.
async function testAMalformedIteratorFailsRatherThanSpinning() {
  var res = _res();
  var destroyed = false;
  res.destroy = function () { destroyed = true; res.destroyed = true; };
  var pulls = 0;
  var broken = {};
  broken[Symbol.asyncIterator] = function () {
    return { next: function () { pulls += 1; return Promise.resolve(undefined); } };
  };
  var caught = null;
  var settled = false;
  b.render.stream(res, broken).then(function () { settled = true; },
                                    function (e) { caught = e; settled = true; });
  await helpers.waitUntil(function () { return settled; }, {
    timeoutMs: 4000, label: "render.stream: a malformed producer settles rather than spinning",
  });
  check("a step that is not an iterator result is a failure", caught instanceof TypeError);
  check("and it is not retried in a loop", pulls === 1);
  check("and the committed response is broken rather than completed", destroyed === true);

  // The same for a sync iterable, whose `next` is not wrapped in a promise.
  var res2 = _res();
  res2.destroy = function () { res2.destroyed = true; };
  var syncBroken = {};
  syncBroken[Symbol.iterator] = function () { return { next: function () { return null; } }; };
  var caught2 = null;
  try { await b.render.stream(res2, syncBroken); } catch (e) { caught2 = e; }
  check("a sync producer breaking the protocol fails too", caught2 instanceof TypeError);
}

// `for await` resolves a promise yielded by a SYNC iterable before handing it
// on; a hand-rolled loop that skips that writes "[object Promise]" into the
// export.
async function testASyncIterableMayYieldPromises() {
  var res = _res();
  await b.render.stream(res, [Promise.resolve("a,"), "b,", Promise.resolve("c")]);
  check("promised chunks from a sync iterable are resolved before writing",
        res._captured().toString("utf8") === "a,b,c");

  // A rejected one is a mid-stream failure like any other.
  var res2 = _res();
  var destroyed = false;
  var ended2 = false;
  res2.on("finish", function () { ended2 = true; });
  res2.destroy = function () { destroyed = true; res2.destroyed = true; };
  var caught = null;
  try {
    await b.render.stream(res2, ["a", Promise.reject(new Error("row 2 failed"))]);
  } catch (e) { caught = e; }
  check("a rejected chunk surfaces to the caller", caught !== null &&
        caught.message === "row 2 failed");
  check("and breaks the transfer rather than completing it", destroyed === true &&
        ended2 === false);
}

// A producer that cancels itself and then lets its own pull reject leaves a
// promise nobody is waiting for. Unobserved, that is an unhandled rejection,
// which by default takes the whole process down — one cancelled export killing
// every other in-flight request.
async function testAnAbandonedPullIsNotAnUnhandledRejection() {
  var res = _res();
  res.destroy = function () { res.destroyed = true; };
  var ac = new AbortController();
  var unhandled = [];
  function onUnhandled(e) { unhandled.push(e); }
  process.on("unhandledRejection", onUnhandled);
  try {
    var source = {};
    source[Symbol.asyncIterator] = function () {
      return {
        next: function () {
          // The producer decides to cancel, THEN hands back a pull that fails.
          ac.abort();
          return new Promise(function (_resolve, reject) {
            setImmediate(function () { reject(new Error("query cancelled")); });
          });
        },
        "return": function () { return Promise.resolve({ done: true }); },
      };
    };
    await b.render.stream(res, source, { signal: ac.signal });
    // Give the abandoned pull time to reject and the rejection time to surface.
    await helpers.passiveObserve(200, "render.stream: the abandoned pull settles unobserved");
    check("an abandoned pull does not become an unhandled rejection", unhandled.length === 0);
    check("and the truncated response is still broken, not ended", res.destroyed === true);
  } finally {
    process.removeListener("unhandledRejection", onUnhandled);
  }
}

// The producer is opened before anything is committed, which leaves a window:
// a status out of range or a header value Node refuses throws AFTER the cursor
// is open. Without cleanup that handle is held for the life of the process.
async function testAHeaderMistakeStillReleasesTheProducer() {
  var res = _res();
  res.writeHead = function () { throw new RangeError("Invalid status code: 99"); };
  var released = false;
  var source = {};
  source[Symbol.asyncIterator] = function () {
    return {
      next: function () { return Promise.resolve({ done: true }); },
      "return": function () { released = true; return Promise.resolve({ done: true }); },
    };
  };
  var caught = null;
  try { await b.render.stream(res, source, { status: 99 }); } catch (e) { caught = e; }
  check("the configuration mistake reaches the caller", caught instanceof RangeError);
  check("and the producer it had already opened is released", released === true);

  // The same for the producer-function form, whose signal must be dropped too.
  var res2 = _res();
  res2.writeHead = function () { throw new RangeError("Invalid header value"); };
  var sawAbort = false;
  var caught2 = null;
  try {
    await b.render.stream(res2, function (signal) {
      signal.addEventListener("abort", function () { sawAbort = true; }, { once: true });
      return _rows(3);
    });
  } catch (e) { caught2 = e; }
  check("a factory producer sees the same failure", caught2 instanceof RangeError);
  check("and is told to stop", sawAbort === true);
}

// A sink that takes the chunk and fails afterwards. `write()` returning true
// only means there is room for more, so resolving on it dropped the listeners
// before the failure arrived — and an unhandled 'error' ends the process.
async function testAWriteThatFailsAfterAcceptingIsStillAFailure() {
  var Writable = require("node:stream").Writable;
  var sink = new Writable({
    write: function (_chunk, _enc, cb) {
      setImmediate(function () { cb(new Error("disk full")); });
    },
  });
  var unhandled = [];
  function onUnhandled(e) { unhandled.push(e); }
  process.on("unhandledRejection", onUnhandled);
  var caught = null;
  try {
    await b.safeAsync.writeChunk(sink, "row\n");
  } catch (e) { caught = e; } finally {
    process.removeListener("unhandledRejection", onUnhandled);
  }
  check("a sink that fails after taking the chunk rejects the write",
        caught !== null && caught.message === "disk full");
  check("and nothing is left unhandled behind it", unhandled.length === 0);

  // A sink that succeeds still resolves, so the common path is unchanged.
  var written = [];
  var good = new Writable({
    write: function (chunk, _enc, cb) { written.push(chunk.toString()); setImmediate(cb); },
  });
  await b.safeAsync.writeChunk(good, "row\n");
  check("a sink that takes the chunk cleanly resolves", written.join("") === "row\n");

  // Whether a sink reports completion is asked of the object, not of how its
  // `write` happens to be declared: a wrapper written with rest parameters
  // supports the callback exactly as one written out in full does.
  var innerFail = new Writable({
    write: function (_c, _e, cb) { setImmediate(function () { cb(new Error("disk full")); }); },
  });
  var wrapper = Object.create(innerFail);
  wrapper.write = function () { return innerFail.write.apply(innerFail, arguments); };
  var caughtWrapped = null;
  try { await b.safeAsync.writeChunk(wrapper, "row\n"); } catch (e) { caughtWrapped = e; }
  check("a wrapper declared with rest parameters still reports its failure",
        caughtWrapped !== null && caughtWrapped.message === "disk full");
  // And a response double, which reports nothing, is still answered on the spot.
  var double = _res();
  await b.safeAsync.writeChunk(double, "row\n");
  check("while a plain response double resolves as before",
        double._captured().toString("utf8") === "row\n");

  // A sink can answer before `write()` has even returned. Settling on that
  // answer alone would resolve a write that still owes a drain — and leave the
  // listeners attached after it with nothing left to remove them.
  var syncInner = new Writable({ write: function (_c, _e, cb) { cb(); } });
  var syncSink = Object.create(syncInner);
  var drainRequested = false;
  syncSink.write = function (chunk, cb) {
    if (typeof cb === "function") cb(null);                 // answers first
    return false;                                           // and asks for a drain
  };
  syncSink.once = function (event, fn) {
    if (event === "drain") { drainRequested = true; setImmediate(fn); }
    return syncSink;
  };
  syncSink.removeListener = function () { return syncSink; };
  await b.safeAsync.writeChunk(syncSink, "row\n");
  check("a sink that answers before it returns is still made to drain", drainRequested === true);

  // The absorber covers only the error the callback said was coming. A failure
  // that ARRIVES as an error event has no second one behind it, and arming for
  // one would swallow whatever unrelated failure happened to follow.
  var emitter = new Writable({ write: function (_c, _e, cb) { cb(); } });
  emitter.write = function () { return false; };            // no completion callback
  var caught2 = null;
  var later = [];
  var pending = b.safeAsync.writeChunk(emitter, "row\n").catch(function (e) { caught2 = e; });
  emitter.emit("error", new Error("first"));
  await pending;
  emitter.on("error", function (e) { later.push(e.message); });
  emitter.emit("error", new Error("second, unrelated"));
  check("an error event settles the write", caught2 !== null && caught2.message === "first");
  check("and a later unrelated error is not swallowed", later.join("") === "second, unrelated");
}

// `create({ engine })` returns the same helpers bound to that engine. A new one
// missing from it is a primitive the documented surface cannot reach.
function testTheEngineBoundRendererCarriesEveryHelper() {
  var renderer = b.render.create({ engine: { render: function () { return "<p>x</p>"; } } });
  var expected = ["html", "htmlString", "json", "stream", "text", "redirect"];
  var missing = expected.filter(function (name) { return typeof renderer[name] !== "function"; });
  check("every module helper is on the engine-bound renderer too", missing.length === 0);
  check("including stream", renderer.stream === b.render.stream);
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
  await testAPreAbortedSignalIsATruncationToo();
  await testTheProducerIsReleasedWhenTheLoopStopsEarly();
  await testCancellationReachesAGeneratorBlockedInItsOwnAwait();
  await testAFailureToOpenTheSourceIsNotACommittedResponse();
  await testAMalformedIteratorFailsRatherThanSpinning();
  await testAnAbandonedPullIsNotAnUnhandledRejection();
  await testAHeaderMistakeStillReleasesTheProducer();
  await testAWriteThatFailsAfterAcceptingIsStillAFailure();
  testTheEngineBoundRendererCarriesEveryHelper();
  await testASyncIterableMayYieldPromises();
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
