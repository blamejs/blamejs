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

// Opening an async generator runs none of its body — that waits for the first
// pull — so "the source opened" said nothing about whether the producer can
// produce. The first value is fetched while the status line is still unsent, so
// a producer that fails before yielding anything is a failure to OPEN rather
// than a truncated export: nothing was committed, and the caller can still
// render an error page. Committing first turned an outage into a download that
// died partway, which is the one failure an error page has something to say
// about.
async function testAThrowBeforeTheFirstRowNeverCommitsTheResponse() {
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
  check("the failure is re-thrown", caught !== null && caught.message === "query rejected");
  check("with the status line still unsent", res.headersSent !== true);
  check("so there is nothing to destroy", destroyed === false);
  check("and no headers were written", Object.keys(res._headers || {}).length === 0);

  // A producer that yields once and THEN fails is the other case, and stays a
  // truncation: those rows are on the wire and cannot be taken back.
  var res2 = _res();
  var destroyed2 = false;
  res2.destroy = function () { destroyed2 = true; res2.destroyed = true; };
  async function* failsAfterOne() {
    yield "row\n";
    throw new Error("cursor died");
  }
  var caught2 = null;
  try { await b.render.stream(res2, failsAfterOne()); } catch (e) { caught2 = e; }
  check("a failure after the first row is still re-thrown", caught2 !== null);
  check("and that one IS a committed, destroyed response",
        res2.headersSent === true && destroyed2 === true);
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
  // The FIRST step is read before the status line goes out, so a producer that
  // answers wrongly from the start is a bad argument and not a committed
  // response — there is nothing on the wire to break.
  check("and nothing was committed to break", destroyed === false && res.headersSent !== true);

  // The same for a sync iterable, whose `next` is not wrapped in a promise.
  var res2 = _res();
  res2.destroy = function () { res2.destroyed = true; };
  var syncBroken = {};
  syncBroken[Symbol.iterator] = function () { return { next: function () { return null; } }; };
  var caught2 = null;
  try { await b.render.stream(res2, syncBroken); } catch (e) { caught2 = e; }
  check("a sync producer breaking the protocol fails too", caught2 instanceof TypeError);

  // Breaking it LATER is the committed case, and stays one.
  var res3 = _res();
  var destroyed3 = false;
  res3.destroy = function () { destroyed3 = true; res3.destroyed = true; };
  var late = {};
  late[Symbol.asyncIterator] = function () {
    var sent = false;
    return {
      next: function () {
        if (sent) return Promise.resolve(undefined);
        sent = true;
        return Promise.resolve({ value: "row\n", done: false });
      },
    };
  };
  var caught3 = null;
  try { await b.render.stream(res3, late); } catch (e) { caught3 = e; }
  check("a producer that breaks the protocol after a row still fails",
        caught3 instanceof TypeError);
  check("and that response IS committed and broken",
        res3.headersSent === true && destroyed3 === true);
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

// The double exists to test streaming a lot of output, so writing a lot of it
// must not cost more than doing it. Asking for the accumulated payload on every
// write concatenated every chunk written so far — quadratic, in the helper
// written for exactly this.
async function testTheStreamingDoubleCostsWhatItWrites() {
  var res = _res({ highWaterMark: 1024 });
  var started = Date.now();
  for (var i = 0; i < 20000; i += 1) res.write("0123456789");
  var took = Date.now() - started;
  check("twenty thousand small chunks cost their number, not its square",
        took < b.constants.TIME.seconds(2));
  check("and every byte of them is still there", res._captured().length === 200000);

  // Back-pressure still reports the same way it did.
  var marked = _res({ highWaterMark: 8 });
  var under = marked.write("aaaa");
  var over = marked.write("bbbbb");
  check("under the mark it takes the chunk, past it it says full",
        under === true && over === false);
  await helpers.waitUntil(function () { return marked._pending === 0; }, {
    timeoutMs: 4000, label: "streamingRes: the double drained",
  });
  check("and it drains, leaving what was written", marked._captured().toString("utf8") === "aaaabbbbb");
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

  // A producer that fails BEFORE producing anything is not a truncated export —
  // nothing was ever produced. Opening an async generator runs none of its body,
  // so the first value is fetched while the status line is still unsent, and the
  // failure reaches the route with a response it can still answer on. What the
  // operator sees is the difference: an export attempted while the database is
  // down gives a page saying so rather than a download that dies partway.
  var earlyCommitted = null;
  var srvEarly = await serve(async function (req, res) {
    async function* fails() { throw new Error("query rejected before any row"); }
    try {
      await b.render.stream(res, fails(), { headers: { "Content-Type": "text/csv" } });
    } catch (_e) {
      earlyCommitted = res.headersSent;
      b.render.json(res, { error: "export unavailable" }, { status: 503 });
    }
  });
  var early = await get(srvEarly.address().port, { timeoutMs: 3000 });
  srvEarly.close();
  check("a failure before the first row leaves the response uncommitted",
        earlyCommitted === false);
  check("so the route can still answer it, completely",
        early.status === 503 && early.complete === true);
  check("and the client is told what happened rather than getting a dead download",
        String(early.body).indexOf("export unavailable") !== -1);

  // "Before the status line goes out" is this primitive's own status line. A
  // route may have sent one already — the documented shape where it writes its
  // own head and streams into it, which is how SSE is written — and then there
  // is no pre-commit window to fail into. Those headers are on the wire, so the
  // only honest ending is an incomplete transfer; leaving the response neither
  // ended nor destroyed reads to the client as a body that never arrives, and
  // holds the socket for the life of the process.
  var preCommitted = [
    { label: "the producer fails on its first pull",
      make: function () { return (async function* () { throw new Error("subscribe failed"); })(); } },
    { label: "the source fails to open at all",
      make: function () { return function () { throw new Error("factory blew up"); }; } },
    { label: "the first step is not an iterator result",
      make: function () {
        var broken = {};
        broken[Symbol.asyncIterator] = function () {
          return { next: function () { return Promise.resolve(undefined); } };
        };
        return broken;
      } },
  ];
  var hanging = [];
  for (var pc = 0; pc < preCommitted.length; pc += 1) {
    var shape = preCommitted[pc];
    var srvOwn = await serve(async function (req, res) {
      res.writeHead(200, { "Content-Type": "text/event-stream" });
      res.flushHeaders();
      try { await b.render.stream(res, shape.make()); } catch (_e) { /* logged by the caller */ }
    });
    var own = await get(srvOwn.address().port, { timeoutMs: 3000 });
    srvOwn.close();
    if (own.error === "TIMEOUT") hanging.push(shape.label);
  }
  check("a response the ROUTE committed is ended even when nothing was produced" +
        (hanging.length ? " — hung on: " + hanging.join(", ") : ""),
        hanging.length === 0);

  // And that response does not wait for a first value before its headers reach
  // the client. There is no pre-commit window to protect once the route has
  // sent its own head, so holding the stream back would only delay a connection
  // the client is waiting to see established — minutes, for an event stream
  // whose first event is minutes away.
  var release = null;
  var slowFirst = new Promise(function (r) { release = r; });
  var srvSlow = await serve(async function (req, res) {
    res.writeHead(200, { "Content-Type": "text/event-stream" });
    res.flushHeaders();
    async function* waits() { await slowFirst; yield "data: 1\n\n"; }
    try { await b.render.stream(res, waits()); } catch (_e) { /* logged */ }
  });
  var slowPort = srvSlow.address().port;
  var sawHeaders = await new Promise(function (resolve) {
    var req = http.get({ host: "127.0.0.1", port: slowPort, path: "/" }, function (r) {
      resolve(r.statusCode === 200 && r.headers["content-type"] === "text/event-stream");
      r.resume();
    });
    req.setTimeout(3000, function () { req.destroy(); resolve(false); });
  });
  check("and its headers reach the client before the producer has anything to say",
        sawHeaders === true);
  release();
  srvSlow.close();

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
  // would throw away a valid one. RFC 9110 gives the whole set — every 1xx,
  // 204, 205 and 304 — and a 205 belongs there for the same reason a 204 does:
  // it is defined to carry nothing.
  [100, 101, 204, 205, 304].forEach(function (status) {
    var ended = false, killed = false;
    var bodiless = {
      headersSent: true, statusCode: status,
      end: function () { ended = true; }, destroy: function () { killed = true; },
    };
    check("a " + status + " is completed rather than destroyed",
          helpersApi.failAfterHeaders(bodiless) === true && ended === true && killed === false);
  });
  // And a status that DOES carry one is still broken, or the truncation signal
  // this exists for would be lost.
  [200, 302, 500].forEach(function (status) {
    var wasKilled = false;
    var carries = {
      headersSent: true, statusCode: status,
      end: function () {}, destroy: function () { wasKilled = true; },
    };
    helpersApi.failAfterHeaders(carries);
    check("a " + status + " is still destroyed, since it can be truncated", wasKilled === true);
  });
  var headEnded = false;
  var head = {
    headersSent: true, statusCode: 200, _hasBody: false,
    end: function () { headEnded = true; }, destroy: function () { headEnded = "destroyed"; },
  };
  helpersApi.failAfterHeaders(head);
  check("a HEAD response is completed rather than destroyed", headEnded === true);
}

// A status the caller GAVE is sent as given. `0` and `NaN` are falsy, and
// defaulting them away would answer a misconfigured handler with a successful
// response instead of letting the socket refuse the value.
async function testAStatusThatWasGivenIsNotDefaultedAway() {
  var sent = [];
  function recorder() {
    return {
      headersSent: false, writableEnded: false,
      writeHead: function (status) { sent.push(status); throw new Error("invalid status"); },
      setHeader: function () {}, end: function () {}, destroy: function () {},
    };
  }

  var jsonThrew = false;
  try { b.render.json(recorder(), { ok: true }, { status: 0 }); }
  catch (_e) { jsonThrew = true; }
  check("render.json passes a zero status through rather than sending 200",
        sent[0] === 0 && jsonThrew === true);

  sent.length = 0;
  var nanThrew = false;
  try { b.render.json(recorder(), { ok: true }, { status: NaN }); }
  catch (_e2) { nanThrew = true; }
  check("and a NaN status likewise",
        Number.isNaN(sent[0]) && nanThrew === true);

  // Absent still takes the default, which is the whole point of the option.
  sent.length = 0;
  try { b.render.json(recorder(), { ok: true }); } catch (_e3) { /* the recorder throws */ }
  check("while an absent status still takes the default",
        sent[0] === b.constants.HTTP.STATUS.OK);

  // The streaming path reports it the same way, as a failure to open rather
  // than a committed response.
  var streamRes = recorder();
  var streamFailed = false;
  try {
    await b.render.stream(streamRes, (async function* () { yield "x"; })(), { status: 0 });
  } catch (_e4) { streamFailed = true; }
  check("render.stream refuses a zero status rather than streaming a 200",
        streamFailed === true);

  // And a redirect says so by name, since it knows what range it needs.
  var redirectMessage = "";
  try { b.render.redirect(recorder(), "/x", { status: 0 }); }
  catch (e5) { redirectMessage = e5.message; }
  check("and render.redirect names the range it needed",
        redirectMessage.indexOf("3xx") !== -1);
}

// Copying the caller's headers runs whatever `opts.headers` chooses to run.
// Doing that after the producer was opened left a throw there with no path back
// to the cleanup, and the producer's cursor or file handle stayed held.
async function testAHeaderThatThrowsWhileBeingReadReleasesNothingBecauseNothingWasTaken() {
  var opened = false;
  var released = false;
  var source = {};
  source[Symbol.asyncIterator] = function () {
    opened = true;
    return {
      next: function () { return Promise.resolve({ value: "x", done: false }); },
      return: function () { released = true; return Promise.resolve({ done: true }); },
    };
  };

  var hostile = {};
  Object.defineProperty(hostile, "X-Trouble", {
    enumerable: true,
    get: function () { throw new Error("header getter refused"); },
  });

  var res = {
    headersSent: false, writableEnded: false,
    writeHead: function () {}, setHeader: function () {},
    write: function () { return true; }, end: function () {}, destroy: function () {},
  };

  var message = "";
  try { await b.render.stream(res, source, { headers: hostile }); }
  catch (e) { message = e.message; }
  check("the header mistake reaches the caller", message === "header getter refused");
  check("and the producer was never opened, so there is nothing to leak",
        opened === false && released === false);

  // A producer that WAS opened is still released when the status line is the
  // thing Node refuses, which is the neighbouring path.
  var openedTwo = false;
  var releasedTwo = false;
  var second = {};
  second[Symbol.asyncIterator] = function () {
    openedTwo = true;
    return {
      next: function () { return Promise.resolve({ value: "x", done: false }); },
      return: function () { releasedTwo = true; return Promise.resolve({ done: true }); },
    };
  };
  var refusing = {
    headersSent: false, writableEnded: false,
    writeHead: function () { throw new Error("status out of range"); },
    setHeader: function () {}, write: function () { return true; },
    end: function () {}, destroy: function () {},
  };
  var secondMessage = "";
  try { await b.render.stream(refusing, second, { status: 0 }); }
  catch (e2) { secondMessage = e2.message; }
  check("a status Node refuses still releases the producer it had opened",
        secondMessage === "status out of range" && openedTwo === true &&
        releasedTwo === true);
}

// What the iterable's method HANDS BACK has to be an iterator, and asking at the
// first pull was too late: the status line had gone out, so a malformed producer
// arrived as a committed response that was then destroyed rather than as a bad
// argument the caller could still render an error page for.
async function testAnIteratorMethodThatReturnsNonsenseIsCaughtBeforeTheStatusLine() {
  var returns = { "null": null, "a number": 42, "no next": { done: true },
                  "a next that is not callable": { next: 7 } };
  var wrong = [];
  var labels = Object.keys(returns);
  for (var i = 0; i < labels.length; i += 1) {
    var label = labels[i];
    var iterable = {};
    iterable[Symbol.asyncIterator] = (function (value) {
      return function () { return value; };
    })(returns[label]);
    var committed = false;
    var res = {
      headersSent: false, writableEnded: false,
      writeHead: function () { committed = true; },
      setHeader: function () {}, write: function () { return true; },
      end: function () {}, destroy: function () {},
    };
    var failed = false;
    try { await b.render.stream(res, iterable, {}); } catch (_e) { failed = true; }
    if (!failed || committed) {
      wrong.push(label + ": failed=" + failed + " headersWritten=" + committed);
    }
  }
  check("a malformed iterator is refused with the status line still unsent" +
        (wrong.length ? " — " + wrong.join(" | ") : ""), wrong.length === 0);
}

// Setting a header is the ordinary way for a route to say what its response is,
// and `writeHead(status, headers)` lets its own object win on a name they share.
// So a DEFAULT silently replaced the route's own answer — and only for the names
// the defaults happen to carry, which is what made it hard to see: a
// `Content-Disposition` survived while the `Content-Type` beside it did not.
async function testADefaultDoesNotOverrideAHeaderTheRouteAlreadySet() {
  var wrong = [];

  function fresh() {
    var res = _res();
    res.setHeader("content-type", "text/csv; charset=utf-8");
    res.setHeader("content-disposition", 'attachment; filename="m.csv"');
    return res;
  }
  function typeOn(res) {
    return res.getHeader("content-type");
  }

  var streamed = fresh();
  await b.render.stream(streamed, (async function* () { yield "a,b\n"; })());
  if (typeOn(streamed) !== "text/csv; charset=utf-8") {
    wrong.push("stream: " + typeOn(streamed));
  }
  if (streamed.getHeader("content-disposition") !== 'attachment; filename="m.csv"') {
    wrong.push("stream lost the disposition it never set");
  }
  check("the octet-stream default steps aside for a type the route already set" +
        (wrong.length ? " — " + wrong.join(" | ") : ""), wrong.length === 0);

  // The helpers that ENCODE the body do not inherit it. Their Content-Type
  // describes the bytes they just produced, so a `text/html` left on the
  // response by an earlier route is how a JSON error body carrying a reflected
  // value comes to be parsed as markup by the browser, same-origin.
  var inherited = [];
  var jsoned = fresh();
  b.render.json(jsoned, { ok: true });
  if (typeOn(jsoned) !== "application/json; charset=utf-8") inherited.push("json: " + typeOn(jsoned));

  var texted = fresh();
  b.render.text(texted, "hello");
  if (typeOn(texted) !== "text/plain; charset=utf-8") inherited.push("text: " + typeOn(texted));

  var htmled = fresh();
  b.render.htmlString(htmled, "<p>hi</p>");
  if (typeOn(htmled) !== "text/html; charset=utf-8") inherited.push("htmlString: " + typeOn(htmled));

  var htmlPage = _res();
  htmlPage.setHeader("content-type", "text/html; charset=utf-8");
  b.render.json(htmlPage, { error: "<img src=x onerror=alert(1)>" }, { status: 400 });
  if (String(htmlPage.getHeader("content-type")).indexOf("text/html") === 0) {
    inherited.push("a JSON error body inherited text/html from the page route");
  }
  check("a helper that encodes the body sends its own content type" +
        (inherited.length ? " — " + inherited.join(" | ") : ""), inherited.length === 0);

  // Cache-Control is a security default rather than a formatting one, so it
  // does not step aside for anything an earlier setHeader put there.
  var relaxed = _res();
  relaxed.setHeader("cache-control", "public, max-age=31536000");
  await b.render.stream(relaxed, (async function* () { yield "x"; })());
  check("and the revalidation default is not relaxed by an earlier setHeader",
        relaxed.getHeader("cache-control") === "private, no-cache, must-revalidate");

  // An explicit `opts.headers` entry still wins over both, which is the
  // documented precedence and the reason this is a change to the DEFAULTS only.
  var explicit = fresh();
  await b.render.stream(explicit, (async function* () { yield "x"; })(),
                        { headers: { "Content-Type": "application/json" } });
  check("and an explicit opts.headers entry still wins over both",
        explicit.getHeader("content-type") === "application/json");

  // A length describes the bytes THIS call is writing, so a stale one a route
  // guessed earlier would mis-frame the response.
  var stale = _res();
  stale.setHeader("content-length", "9999");
  b.render.json(stale, { ok: true });
  check("a content length the route guessed earlier does not survive",
        Number(stale.getHeader("content-length")) ===
          Buffer.byteLength(JSON.stringify({ ok: true }), "utf8"));

  // A header set to nothing states nothing, so the default still applies.
  var blank = _res();
  blank.setHeader("content-type", "");
  await b.render.stream(blank, (async function* () { yield "x"; })());
  check("an empty content type is not an answer, so the default still applies",
        blank.getHeader("content-type") === "application/octet-stream");

  // Nothing set beforehand: the defaults apply exactly as they always did.
  var plain = _res();
  b.render.json(plain, { ok: true });
  check("with nothing set beforehand the defaults still apply",
        plain.getHeader("content-type") === "application/json; charset=utf-8" &&
        plain.getHeader("cache-control") === "private, no-cache, must-revalidate");

  // A response double with no getHeader at all must not break the merge.
  var bare = {
    headersSent: false, writableEnded: false, _h: null,
    writeHead: function (s, h) { this._h = h; },
    end: function () {}, destroy: function () {},
  };
  b.render.json(bare, { ok: true });
  check("a response that cannot be asked about its headers still gets the defaults",
        bare._h && bare._h["Content-Type"] === "application/json; charset=utf-8");
}

async function run() {
  testFailAfterHeadersPicksTheRightSignal();
  await testADefaultDoesNotOverrideAHeaderTheRouteAlreadySet();
  await testAnIteratorMethodThatReturnsNonsenseIsCaughtBeforeTheStatusLine();
  await testAStatusThatWasGivenIsNotDefaultedAway();
  await testAHeaderThatThrowsWhileBeingReadReleasesNothingBecauseNothingWasTaken();
  await testWritesEveryChunkAndEnds();
  await testAgainstARealServer();
  await testAlreadyClosedStreamRejects();
  await testAwaitsBackpressure();
  await testStopsWhenThePeerGoes();
  await testMidStreamThrowDestroysRatherThanLying();
  await testAThrowBeforeTheFirstRowNeverCommitsTheResponse();
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
  await testTheStreamingDoubleCostsWhatItWrites();
  await testWriteChunkSettlesOnAClosedStream();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("render-stream OK — " + helpers.getChecks() + " checks"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
