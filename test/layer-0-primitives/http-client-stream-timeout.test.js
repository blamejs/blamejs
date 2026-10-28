// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A stream-mode response body must end with an error, never a clean `end`,
 * when the transfer stops before the response is complete.
 *
 * `request({ responseMode: "stream" })` resolves on the response headers and
 * hands back the body as a readable. When `timeoutMs` or `idleTimeoutMs`
 * fired after that point, the HTTP/2 path canceled the stream and the
 * readable side ended without an error, so a caller reading the body read a
 * truncated body as a complete one. The HTTP/1.1 path destroyed the socket
 * and the body errored with ECONNRESET "aborted", so neither transport
 * reported the timeout as ETIMEDOUT. An HTTP/2 stream the peer resets with
 * CANCEL, or ends short of the Content-Length it declared, also ended
 * cleanly.
 *
 * Each case is driven over HTTP/1.1 and over h2c (`preferH2`).
 */

var http  = require("node:http");
var http2 = require("node:http2");
var fs    = require("node:fs");
var os    = require("node:os");
var path  = require("node:path");

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

var DECLARED = 10000000;

function _trickle(declare) {
  return function (req, res) {
    var h = {};
    if (declare) h["content-length"] = String(DECLARED);
    res.writeHead(200, h);
    var t = setInterval(function () {
      if (!res.destroyed && !res.writableEnded) res.write(Buffer.alloc(1000, 0x61));
    }, 40);
    res.on("close", function () { clearInterval(t); });
  };
}

function _stall(req, res) {
  res.writeHead(200, { "content-length": "100000" });
  res.write(Buffer.alloc(10, 0x62));
}

function _complete(req, res) {
  res.writeHead(200, { "content-length": "4096" });
  res.end(Buffer.alloc(4096, 0x63));
}

function _notModified(req, res) {
  res.writeHead(304, { "content-length": "100", etag: "\"v1\"" });
  res.end();
}

function _h2ResetCancel(req, res) {
  res.writeHead(200);
  res.write(Buffer.alloc(100, 0x64));
  setTimeout(function () { res.stream.close(http2.constants.NGHTTP2_CANCEL); }, 60);
}

function _h2Short(req, res) {
  res.writeHead(200, { "content-length": "100" });
  res.write(Buffer.alloc(10, 0x65));
  setTimeout(function () { res.stream.close(http2.constants.NGHTTP2_NO_ERROR); }, 60);
}

function _h2EndStreamShort(req, res) {
  res.stream.respond({ ":status": 200, "content-length": "100" });
  res.stream.end(Buffer.alloc(10, 0x66));
}

function _h1Short(req, res) {
  res.writeHead(200, { "content-length": "100" });
  res.write(Buffer.alloc(10, 0x67));
  setTimeout(function () { res.socket.destroy(); }, 60);
}

function _small(req, res) {
  res.writeHead(200, { "content-length": "50" });
  res.end(Buffer.alloc(50, 0x68));
}

async function _withServer(kind, handler, fn) {
  var server = kind === "h2" ? http2.createServer(handler) : http.createServer(handler);
  var sessions = [];
  if (kind === "h2") server.on("session", function (s) { sessions.push(s); });
  var port = await helpers.listenOnRandomPort(server, "127.0.0.1");
  try {
    return await fn("http://127.0.0.1:" + port + "/");
  } finally {
    sessions.forEach(function (s) { try { s.destroy(); } catch (_e) { /* already closed */ } });
    if (typeof server.closeAllConnections === "function") server.closeAllConnections();
    await new Promise(function (resolve) { server.close(function () { resolve(); }); });
    b.httpClient._resetForTest();
  }
}

async function _readBody(kind, url, extra) {
  var started = Date.now();
  var res = await b.httpClient.request(Object.assign({
    url: url, responseMode: "stream", allowInternal: true,
    allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, preferH2: kind === "h2",
  }, extra || {}));
  var out = { statusCode: res.statusCode, bytes: 0, ended: false, error: null, ms: 0 };
  res.body.on("data", function (c) { out.bytes += c.length; });
  res.body.on("error", function (e) { out.error = e; out.ms = Date.now() - started; });
  res.body.on("end", function () { out.ended = true; out.ms = Date.now() - started; });
  await helpers.waitUntil(function () { return out.ended || out.error !== null; },
    { timeoutMs: 10000, label: "http-client stream: body settles (" + kind + ")" });
  return out;
}

function _describe(o) {
  return JSON.stringify({ bytes: o.bytes, ended: o.ended, ms: o.ms,
    code: o.error && o.error.code, permanent: o.error && o.error.permanent,
    transient: o.error && o.error.transient });
}

async function testWallClockTimeoutAfterHeaders() {
  var kinds = ["h1", "h2"];
  for (var i = 0; i < kinds.length; i += 1) {
    var kind = kinds[i];
    await _withServer(kind, _trickle(true), async function (url) {
      var o = await _readBody(kind, url, { timeoutMs: 600 });
      check(kind + ": timeoutMs after the headers ends the body with an error, not a clean end",
        o.error !== null && o.ended === false, _describe(o));
      check(kind + ": and the error is ETIMEDOUT", o.error !== null && o.error.code === "ETIMEDOUT", _describe(o));
      check(kind + ": and it is retryable", o.error !== null && b.retry.isRetryable(o.error) === true &&
        o.error.permanent === false && o.error.transient === true, _describe(o));
      check(kind + ": and it arrives at the timeout, well before the body is complete",
        o.bytes < DECLARED, _describe(o));
    });
  }
}

async function testIdleTimeoutAfterHeaders() {
  var kinds = ["h1", "h2"];
  for (var i = 0; i < kinds.length; i += 1) {
    var kind = kinds[i];
    await _withServer(kind, _stall, async function (url) {
      var o = await _readBody(kind, url, { idleTimeoutMs: 400 });
      check(kind + ": idleTimeoutMs after the headers ends the body with ETIMEDOUT",
        o.error !== null && o.error.code === "ETIMEDOUT" && o.ended === false, _describe(o));
      check(kind + ": and the idle timeout is retryable",
        o.error !== null && b.retry.isRetryable(o.error) === true, _describe(o));
    });
  }
}

async function testAbortAfterHeadersErrors() {
  var kinds = ["h1", "h2"];
  for (var i = 0; i < kinds.length; i += 1) {
    var kind = kinds[i];
    await _withServer(kind, _trickle(true), async function (url) {
      var ac = new AbortController();
      setTimeout(function () { ac.abort(); }, 300);
      var o = await _readBody(kind, url, { signal: ac.signal });
      check(kind + ": an abort after the headers ends the body with an ABORT error",
        o.error !== null && o.error.code === "ABORT" && o.ended === false, _describe(o));
    });
  }
}

async function testH2PeerResetEndsWithAnError() {
  await _withServer("h2", _h2ResetCancel, async function (url) {
    var o = await _readBody("h2", url, {});
    check("h2: a stream the peer resets with CANCEL before the body ends fails the body",
      o.error !== null && o.ended === false, _describe(o));
    check("h2: and the failure is http-client/truncated-body, retryable",
      o.error !== null && o.error.code === "http-client/truncated-body" &&
      b.retry.isRetryable(o.error) === true, _describe(o));
  });
}

async function testShortBodyEndsWithAnError() {
  await _withServer("h2", _h2Short, async function (url) {
    var o = await _readBody("h2", url, {});
    check("h2: a body that ends short of Content-Length fails the body",
      o.error !== null && o.ended === false, _describe(o));
    check("h2: and the failure is http-client/truncated-body, retryable",
      o.error !== null && o.error.code === "http-client/truncated-body" &&
      b.retry.isRetryable(o.error) === true, _describe(o));
  });
}

async function testEndStreamShortOfContentLength() {
  var shapes = [["h2", "END_STREAM short of Content-Length", _h2EndStreamShort],
                ["h1", "a connection closed short of Content-Length", _h1Short]];
  for (var i = 0; i < shapes.length; i += 1) {
    var kind = shapes[i][0];
    var label = shapes[i][1];
    await _withServer(kind, shapes[i][2], async function (url) {
      var o = await _readBody(kind, url, {});
      check(kind + " stream: " + label + " fails the body with http-client/truncated-body",
        o.error !== null && o.ended === false && o.error.code === "http-client/truncated-body", _describe(o));
      check(kind + " stream: " + label + " is retryable",
        o.error !== null && b.retry.isRetryable(o.error) === true &&
        o.error.permanent === false && o.error.transient === true, _describe(o));
    });
  }
}

async function testBufferedH2BodyCutShortRejects() {
  var handlers = [["h2", "a short body", _h2Short], ["h2", "a peer reset", _h2ResetCancel],
                  ["h2", "END_STREAM short of Content-Length", _h2EndStreamShort],
                  ["h1", "a connection closed short of Content-Length", _h1Short]];
  for (var i = 0; i < handlers.length; i += 1) {
    var kind = handlers[i][0];
    var label = handlers[i][1];
    await _withServer(kind, handlers[i][2], async function (url) {
      var caught = null;
      var res = null;
      try {
        res = await b.httpClient.request({ url: url, allowInternal: true,
          allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, preferH2: kind === "h2" });
      } catch (e) { caught = e; }
      check(kind + " buffered: " + label + " rejects with http-client/truncated-body",
        caught !== null && caught.code === "http-client/truncated-body",
        caught ? String(caught.code) : "resolved with " + (res && res.body && res.body.length) + " bytes");
      check(kind + " buffered: " + label + " is retryable", caught !== null && b.retry.isRetryable(caught) === true,
        caught ? JSON.stringify({ permanent: caught.permanent, transient: caught.transient }) : "resolved");
    });
  }
}

async function _readLate(kind, url, extra, trigger) {
  var res = await b.httpClient.request(Object.assign({
    url: url, responseMode: "stream", allowInternal: true,
    allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, preferH2: kind === "h2",
  }, extra));
  if (trigger) trigger();
  await helpers.passiveObserve(700, "http-client stream: consumer starts reading after the deadline (" + kind + ")");
  var out = { statusCode: res.statusCode, bytes: 0, ended: false, error: res.body.errored || null, ms: 0 };
  if (out.error !== null) return out;
  res.body.on("data", function (c) { out.bytes += c.length; });
  res.body.on("error", function (e) { out.error = e; });
  res.body.on("end", function () { out.ended = true; });
  await helpers.waitUntil(function () { return out.ended || out.error !== null; },
    { timeoutMs: 10000, label: "http-client stream: late-read body settles (" + kind + ")" });
  return out;
}

async function testBodyThatArrivedIsDeliveredToALateReader() {
  var kinds = ["h1", "h2"];
  for (var i = 0; i < kinds.length; i += 1) {
    var kind = kinds[i];
    await _withServer(kind, _small, async function (url) {
      var o = await _readLate(kind, url, { timeoutMs: 300 }, null);
      check(kind + ": a body that fully arrived is delivered whole when read after timeoutMs",
        o.ended === true && o.error === null && o.bytes === 50, _describe(o));
    });
    await _withServer(kind, _small, async function (url) {
      var o = await _readLate(kind, url, { idleTimeoutMs: 300 }, null);
      check(kind + ": a body that fully arrived is delivered whole when read after idleTimeoutMs",
        o.ended === true && o.error === null && o.bytes === 50, _describe(o));
    });
    await _withServer(kind, _small, async function (url) {
      var ac = new AbortController();
      var o = await _readLate(kind, url, { signal: ac.signal }, function () {
        setTimeout(function () { ac.abort(); }, 200);
      });
      check(kind + ": a body that fully arrived is delivered whole when signal aborts before the read",
        o.ended === true && o.error === null && o.bytes === 50, _describe(o));
    });
    await _withServer(kind, _stall, async function (url) {
      var o = await _readLate(kind, url, { timeoutMs: 300 }, null);
      check(kind + " control: a body still arriving at timeoutMs errors with ETIMEDOUT for a late reader",
        o.error !== null && o.error.code === "ETIMEDOUT" && o.ended === false, _describe(o));
    });
  }
}

async function testCompleteBodiesStillEnd() {
  var kinds = ["h1", "h2"];
  for (var i = 0; i < kinds.length; i += 1) {
    var kind = kinds[i];
    await _withServer(kind, _complete, async function (url) {
      var o = await _readBody(kind, url, { timeoutMs: 5000 });
      check(kind + " control: a complete body ends cleanly", o.ended === true && o.error === null &&
        o.bytes === 4096, _describe(o));
    });
    await _withServer(kind, _notModified, async function (url) {
      var o = await _readBody(kind, url, {});
      check(kind + " control: a 304 carrying the cached Content-Length is not read as a short body",
        o.ended === true && o.error === null && o.bytes === 0 && o.statusCode === 304, _describe(o));
    });
    await _withServer(kind, _complete, async function (url) {
      var o = await _readBody(kind, url, { method: "HEAD" });
      check(kind + " control: a HEAD response carrying Content-Length is not read as a short body",
        o.ended === true && o.error === null && o.bytes === 0, _describe(o));
    });
  }
}

async function testDownloadStreamReportsTheTimeout() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "dl-timeout-"));
  try {
    await _withServer("h1", _trickle(true), async function (url) {
      var caught = null;
      try {
        await b.httpClient.downloadStream({
          url: url, dest: path.join(dir, "out.bin"), timeoutMs: 600,
          allowInternal: true, allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
        });
      } catch (e) { caught = e; }
      check("downloadStream: timeoutMs after the headers rejects with ETIMEDOUT",
        caught !== null && caught.code === "ETIMEDOUT", caught ? String(caught.code) : "resolved");
      check("downloadStream: and it is retryable", caught !== null && b.retry.isRetryable(caught) === true,
        caught ? JSON.stringify({ permanent: caught.permanent, transient: caught.transient }) : "resolved");
      check("downloadStream: and no partial file is left at dest", fs.existsSync(path.join(dir, "out.bin")) === false);
    });
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  }
}

async function run() {
  await helpers.withDrain("http-client-stream-timeout", async function () {
    await testWallClockTimeoutAfterHeaders();
    await testIdleTimeoutAfterHeaders();
    await testAbortAfterHeadersErrors();
    await testH2PeerResetEndsWithAnError();
    await testShortBodyEndsWithAnError();
    await testEndStreamShortOfContentLength();
    await testBufferedH2BodyCutShortRejects();
    await testBodyThatArrivedIsDeliveredToALateReader();
    await testCompleteBodiesStillEnd();
    await testDownloadStreamReportsTheTimeout();
  });
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
