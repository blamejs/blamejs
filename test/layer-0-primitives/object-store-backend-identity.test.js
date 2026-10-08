// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What `b.objectStore.buildBackend` requires, and what names the backend it
 * returns.
 *
 * `protocol` was documented as defaulting to `local`. It does not default: the
 * dispatcher refuses a missing protocol, and the `fallbackProtocol` the store
 * registers is only named in the text of a deferred-protocol refusal. Had the
 * documented default been real, a config with a typo'd key would have built a
 * local store under whatever directory the rest of the config implied.
 *
 * A config omitted entirely raised a bare `Error` carrying no code, while
 * every other refusal from this module, including the one `bucketOps.create`
 * raises for the same mistake, carried an `ObjectStoreError` and a code. An
 * operator catching by code could not catch the first one.
 *
 * Run standalone: `node test/layer-0-primitives/object-store-backend-identity.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var fs = require("node:fs");
var path = require("node:path");
var os = require("node:os");
var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function _refusal(fn) {
  try { fn(); return null; } catch (e) { return e; }
}

async function run() {
  var rootDir = fs.mkdtempSync(path.join(os.tmpdir(), "os-identity-"));
  try {
    var noConfig = _refusal(function () { return b.objectStore.buildBackend(); });
    check("a missing config is refused with a code, not a bare Error",
          !!noConfig && noConfig.code === "objectstore/bad-opt",
          "got " + (noConfig && (noConfig.code || noConfig.constructor.name)));
    check("and bucketOps.create refuses the same mistake the same way",
          (_refusal(function () { return b.objectStore.bucketOps.create(); }) || {}).code ===
            "objectstore/bad-opt");

    var noProto = _refusal(function () {
      return b.objectStore.buildBackend({ rootDir: rootDir });
    });
    check("an omitted protocol is refused rather than defaulted to local",
          !!noProto && noProto.code === "protocol-dispatcher/missing-protocol",
          "got " + (noProto && (noProto.code || noProto.message)));

    var badProto = _refusal(function () {
      return b.objectStore.buildBackend({ protocol: "s3", rootDir: rootDir });
    });
    check("an unknown protocol is refused and the message lists the known ones",
          !!badProto && badProto.code === "protocol-dispatcher/unknown-protocol" &&
            /local/.test(badProto.message) && /sigv4/.test(badProto.message),
          badProto && badProto.message);

    // The control for the three refusals above: the same config with the
    // protocol named builds, so each refusal is about the protocol and not
    // about the directory or the module failing to load at all.
    var store = b.objectStore.buildBackend({ protocol: "local", rootDir: rootDir });
    check("naming the protocol builds the backend", typeof store.put === "function");
    check("the backend's name defaults to the protocol", store.name === "local");
    check("the backend reports the protocol it was built for", store.protocol === "local");
    check("the breaker is named protocol:root, so two roots trip independently",
          store.breaker.name === "local:" + path.resolve(rootDir),
          store.breaker.name);

    var second = b.objectStore.buildBackend({ protocol: "local", rootDir: rootDir, name: "archive" });
    check("an explicit name takes over the backend's name", second.name === "archive");
    check("and the breaker's", second.breaker.name === "archive");

    check("classifications default to any, and residency to unrestricted",
          store.servesClassification("phi") === true &&
            store.residencyTag === "unrestricted");
  } finally {
    try { fs.rmSync(rootDir, { recursive: true, force: true }); } catch (_e) { /* best effort */ }
  }

  await _testAStreamPutIsNotRetried();
  await _testGetStreamYieldsBeforeTheTransferEnds();
  await _testAConditionalGetStreamIsNotShort();
}

// RFC 7230 section 3.3.2 lets a 304 carry the Content-Length of the selected
// representation, and a 304 carries no body. The length check compared that
// declaration against the zero bytes delivered and failed the stream with
// objectstore/truncated-body, so a conditional read that succeeded reported the
// object as cut short.
async function _testAConditionalGetStreamIsNotShort() {
  var http = require("node:http");
  var sawIfNoneMatch = null;
  var server = http.createServer(function (req, res) {
    sawIfNoneMatch = req.headers["if-none-match"] || null;
    res.writeHead(304, { "content-length": "100", etag: "\"v1\"" });
    res.end();
  });
  await new Promise(function (resolve) { server.listen(0, "127.0.0.1", resolve); });
  var port = server.address().port;
  try {
    var store = b.objectStore.buildBackend({
      name: "cond", protocol: "sigv4",
      endpoint: "http://127.0.0.1:" + port, region: "us-east-1",
      bucket: "bkt", accessKeyId: "AK", secretAccessKey: "SK", pathStyle: true,
      allowInternal: true, allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
    });
    var err = null;
    var bytes = 0;
    var stream = store.getStream("cached", { ifNoneMatch: "\"v1\"" });
    await new Promise(function (resolve) {
      stream.on("data", function (c) { bytes += c.length; });
      stream.on("error", function (e) { err = e; resolve(); });
      stream.on("end", resolve);
    });
    check("the conditional header reached the store",
      sawIfNoneMatch === "\"v1\"", String(sawIfNoneMatch));
    check("a 304 carrying the cached length is not read as a short body",
      err === null, err ? String(err.code) : "");
    check("and the conditional read delivers no bytes", bytes === 0, "bytes=" + bytes);
  } finally {
    await new Promise(function (resolve) { server.close(resolve); });
  }
}

// getStream on the remote backends was promiseToStream(get(key)), which awaits
// the buffered get and then yields the whole body as one chunk. The first byte
// reached the caller only after the last byte arrived from the store, an object
// up to the 1 GiB get cap was held in memory in full, and every concurrent read
// held its own copy. The local backend streams, and its get() refuses an object
// over 64 MiB with a message telling the caller to use getStream().
async function _testGetStreamYieldsBeforeTheTransferEnds() {
  var http = require("node:http");
  var PIECES = 8;
  var sentAll = false;
  var missing = false;
  var redirecting = false;
  var truncating = false;
  var server = http.createServer(function (req, res) {
    if (missing) { res.writeHead(404); res.end("no such key"); return; }
    if (truncating) {
      // Declares more than it sends, which is what a transfer cut short
      // after the headers looks like.
      res.writeHead(200, { "content-length": "100" });
      res.write(Buffer.alloc(7, 0x71));
      res.end();
      return;
    }
    if (redirecting) {
      res.writeHead(302, { location: "https://elsewhere.example/x" });
      res.end("<html>moved</html>");
      return;
    }
    res.writeHead(200, { "content-type": "application/octet-stream" });
    var i = 0;
    (function sendOne() {
      if (i >= PIECES) { sentAll = true; res.end(); return; }
      i += 1;
      res.write(Buffer.alloc(1024, 0x7a));
      setTimeout(sendOne, 25);
    })();
  });
  await new Promise(function (resolve) { server.listen(0, "127.0.0.1", resolve); });
  var port = server.address().port;
  try {
    var store = b.objectStore.buildBackend({
      protocol: "http-put",
      baseUrl:  "http://127.0.0.1:" + port + "/",
      allowInternal: true,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
    });
    var stream = store.getStream("k");
    var firstChunkBeforeEnd = null;
    var total = 0;
    await new Promise(function (resolve, reject) {
      stream.on("data", function (c) {
        if (firstChunkBeforeEnd === null) firstChunkBeforeEnd = (sentAll === false);
        total += c.length;
      });
      stream.on("end", resolve);
      stream.on("error", reject);
    });
    check("getStream delivers the whole object", total === PIECES * 1024,
      "bytes=" + total);
    check("and the first chunk arrives before the transfer finishes",
      firstChunkBeforeEnd === true, String(firstChunkBeforeEnd));

    // Streaming bypassed get(), and with it the error mapping, so a missing
    // key surfaced the transport error instead of the backend-independent
    // code every backend shares.
    missing = true;
    var missErr = null;
    var missStream = store.getStream("gone");
    await new Promise(function (resolve) {
      missStream.on("error", function (e) { missErr = e; resolve(); });
      missStream.on("end", resolve);
      missStream.resume();
    });
    check("a missing key still reports objectstore/not-found",
      missErr !== null && missErr.code === "objectstore/not-found",
      missErr ? String(missErr.code) : "no error");
    missing = false;

    // Stream mode resolves any status, including a 3xx, where the buffered
    // path rejected it. Without a status check the redirect's own body was
    // handed back as the object's contents.
    redirecting = true;
    var redirErr = null;
    var redirBody = [];
    var redirStream = store.getStream("moved");
    await new Promise(function (resolve) {
      redirStream.on("data", function (c) { redirBody.push(c); });
      redirStream.on("error", function (e) { redirErr = e; resolve(); });
      redirStream.on("end", resolve);
    });
    check("a redirect is refused rather than streamed as the object",
      redirErr !== null, "body=" + Buffer.concat(redirBody).toString().slice(0, 40));
    check("and no redirect body reaches the caller",
      Buffer.concat(redirBody).length === 0,
      Buffer.concat(redirBody).toString().slice(0, 40));
    redirecting = false;

    // A transfer cut short after the headers ends its readable side without
    // an error over HTTP/2, so the bytes received read as the whole object.
    truncating = true;
    var truncErr = null;
    var truncBytes = 0;
    var truncStream = store.getStream("short");
    await new Promise(function (resolve) {
      truncStream.on("data", function (c) { truncBytes += c.length; });
      truncStream.on("error", function (e) { truncErr = e; resolve(); });
      truncStream.on("end", resolve);
    });
    check("a body shorter than Content-Length fails the stream",
      truncErr !== null, "bytes=" + truncBytes + " no error");
    // Over HTTP/1.1 Node raises the reset itself before the length check; the
    // check is what catches the HTTP/2 shape, where the readable side ends
    // cleanly. Either way the short body must not read as a complete object.
    check("and it is reported rather than completing",
      truncErr !== null &&
      (truncErr.code === "objectstore/truncated-body" || truncErr.code === "ECONNRESET"),
      truncErr ? String(truncErr.code) : "no error");
    truncating = false;
  } finally {
    await new Promise(function (resolve) { server.close(resolve); });
  }
}

// put is wrapped in b.retry.withRetry, and a retry called put again with the
// same readable. When the source had already ended at the point of failure,
// which is the case for a failure on the last part, on the only part, or on
// the completion call, the next attempt read nothing: the backend uploaded a
// zero-byte part, completed the upload, and put resolved { size: 0 }. The key
// held an empty object and the caller was told it succeeded.
async function _testAStreamPutIsNotRetried() {
  var http = require("node:http");
  var Readable = require("node:stream").Readable;
  var bodiesSeen = [];
  // 503 on the first attempt, accept the second. A retry of a consumed stream
  // sends nothing, so the second attempt is what writes the empty object.
  var server = http.createServer(function (req, res) {
    var n = 0;
    req.on("data", function (c) { n += c.length; });
    req.on("end", function () {
      bodiesSeen.push(n);
      if (bodiesSeen.length === 1) { res.writeHead(503); res.end("try later"); }
      else { res.writeHead(200); res.end("ok"); }
    });
  });
  await new Promise(function (resolve) { server.listen(0, "127.0.0.1", resolve); });
  var port = server.address().port;
  try {
    var store = b.objectStore.buildBackend({
      protocol: "http-put",
      baseUrl:  "http://127.0.0.1:" + port + "/",
      allowInternal: true,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
      retry: { maxAttempts: 3, baseDelayMs: 1 },
    });
    var failed = null;
    try {
      await store.put("k", Readable.from([Buffer.from("hello world")]));
    } catch (e) { failed = e; }

    check("a stream put that fails reaches the caller rather than succeeding empty",
      failed !== null, "resolved instead of rejecting");
    check("and the consumed stream is not replayed as an empty body",
      bodiesSeen.length === 1, JSON.stringify(bodiesSeen));

    // The control: a Buffer body can be replayed, so it is still retried and
    // the second attempt succeeds.
    bodiesSeen.length = 0;
    var ok = await store.put("k2", Buffer.from("hello world"));
    check("a buffer body is still retried to success", ok !== undefined,
      JSON.stringify(ok));
    check("and the retry sent the bytes again",
      bodiesSeen.length === 2 && bodiesSeen[1] === 11, JSON.stringify(bodiesSeen));
  } finally {
    await new Promise(function (resolve) { server.close(resolve); });
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[object-store-backend-identity] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
