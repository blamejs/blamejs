// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.httpClient — error / defensive / adversarial branch coverage.
 *
 * Targets the gap left by http-client-stream / -cache / -throttle-transform:
 * the validation rejections, the SSRF/allowedHosts egress gate, the cross-
 * origin redirect machinery, the h1 + h2 error paths (idle timeout, abort,
 * body-stream error, oversized response, non-2xx), configurePool validation,
 * and the pinned-DNS lookup contract.
 *
 * No live network:
 *   - loopback http.Server on a random port (b.testing.listenOnRandomPort)
 *   - loopback cleartext-h2 (h2c) http2.Server for the HTTP/2 code path,
 *     reached via preferH2:true (no TLS, no ALPN — prior-knowledge h2c)
 *   - fault injection (pre-aborted signal, erroring body Readable, a port
 *     with no listener for ECONNREFUSED) for the defensive branches
 */

var http       = require("http");
var http2      = require("http2");
var nodeStream = require("stream");

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

var ALLOW = b.safeUrl.ALLOW_HTTP_ALL;

// ---- shared fixtures ------------------------------------------------

function _mkAuditCapture() {
  var events = [];
  return { events: events, safeEmit: function (e) { events.push(e); } };
}

async function _withServer(handler, fn) {
  var server = http.createServer(handler);
  var port = await b.testing.listenOnRandomPort(server, "127.0.0.1");
  try {
    return await fn("http://127.0.0.1:" + port, port);
  } finally {
    await new Promise(function (resolve) { server.close(function () { resolve(); }); });
  }
}

async function _withTwoServers(handlerA, handlerB, fn) {
  var serverA = http.createServer(handlerA);
  var serverB = http.createServer(handlerB);
  var portA = await b.testing.listenOnRandomPort(serverA, "127.0.0.1");
  var portB = await b.testing.listenOnRandomPort(serverB, "127.0.0.1");
  try {
    return await fn("http://127.0.0.1:" + portA, "http://127.0.0.1:" + portB);
  } finally {
    await new Promise(function (resolve) { serverA.close(function () { resolve(); }); });
    await new Promise(function (resolve) { serverB.close(function () { resolve(); }); });
  }
}

async function _withH2cServer(onStream, fn) {
  var server = http2.createServer();
  server.on("stream", onStream);
  var port = await b.testing.listenOnRandomPort(server, "127.0.0.1");
  try {
    return await fn("http://127.0.0.1:" + port);
  } finally {
    await new Promise(function (resolve) { server.close(function () { resolve(); }); });
  }
}

// Assert a promise rejects with a matching code (string) or message regex.
async function _expectReject(label, promise, codeOrRe) {
  var err = null;
  try { await promise; } catch (e) { err = e; }
  var ok;
  if (typeof codeOrRe === "string") ok = err != null && err.code === codeOrRe;
  else ok = err != null && codeOrRe.test((err.code || "") + " " + (err.message || ""));
  check(label, ok);
  return err;
}

// ---- surface --------------------------------------------------------

function testSurface() {
  check("httpClient.request is a function", typeof b.httpClient.request === "function");
  check("httpClient.configurePool is a function", typeof b.httpClient.configurePool === "function");
  check("httpClient.DEFAULT_CONTROL_PLANE_CAP is a number", typeof b.httpClient.DEFAULT_CONTROL_PLANE_CAP === "number");
  check("httpClient.DEFAULT_GET_CAP is a number", typeof b.httpClient.DEFAULT_GET_CAP === "number");
}

// ---- configurePool validation + cache teardown ---------------------

async function testConfigurePool() {
  check("configurePool: non-object throws",
    (function () { try { b.httpClient.configurePool(42); return false; } catch (_e) { return true; } })());
  check("configurePool: unknown key throws",
    (function () { try { b.httpClient.configurePool({ nope: 1 }); return false; } catch (e) { return /unknown option/.test(e.message); } })());
  check("configurePool: non-positive maxSockets throws (bad-opts)",
    (function () { try { b.httpClient.configurePool({ maxSockets: 0 }); return false; } catch (e) { return e.code === "httpclient/bad-opts" || /maxSockets/i.test(e.message); } })());
  check("configurePool: non-integer keepAliveMsecs throws",
    (function () { try { b.httpClient.configurePool({ keepAliveMsecs: 1.5 }); return false; } catch (_e) { return true; } })());
  check("configurePool: non-boolean keepAlive throws",
    (function () { try { b.httpClient.configurePool({ keepAlive: "yes" }); return false; } catch (e) { return /keepAlive must be a boolean/.test(e.message); } })());
  check("configurePool: bad scheduling throws",
    (function () { try { b.httpClient.configurePool({ scheduling: "random" }); return false; } catch (e) { return /scheduling/.test(e.message); } })());

  // Valid reconfigure tears down the per-origin cache (both h1 + h2 entries).
  await _withServer(function (req, res) { res.writeHead(200); res.end("ok"); }, async function (base) {
    await b.httpClient.request({ url: base + "/", allowedProtocols: ALLOW, allowInternal: true });
    check("configurePool: an h1 transport is cached before reconfigure",
      b.httpClient._getCachedTransportCount() >= 1);
    b.httpClient.configurePool({ maxSockets: 8, maxFreeSockets: 4 });
    check("configurePool: valid reconfigure clears the transport cache",
      b.httpClient._getCachedTransportCount() === 0);
  });
  // Restore the shipped defaults so later tests / other files see the norm.
  b.httpClient.configurePool({
    maxSockets: b.httpClient.DEFAULT_AGENT_OPTS.maxSockets,
    maxFreeSockets: b.httpClient.DEFAULT_AGENT_OPTS.maxFreeSockets,
    keepAliveMsecs: b.httpClient.DEFAULT_AGENT_OPTS.keepAliveMsecs,
    keepAlive: b.httpClient.DEFAULT_AGENT_OPTS.keepAlive,
    scheduling: b.httpClient.DEFAULT_AGENT_OPTS.scheduling,
  });
}

// ---- request() argument validation (all reject, no network) --------

async function testArgValidation() {
  await _expectReject("request: no opts rejects", b.httpClient.request(), "BAD_ARG");
  await _expectReject("request: no url rejects", b.httpClient.request({ method: "GET" }), "BAD_ARG");
  await _expectReject("request: before not an array rejects",
    b.httpClient.request({ url: "https://x.example/", before: "nope" }), "BAD_ARG");
  await _expectReject("request: before with non-function rejects",
    b.httpClient.request({ url: "https://x.example/", before: [function () {}, 5] }), "BAD_ARG");
  await _expectReject("request: after not an array rejects",
    b.httpClient.request({ url: "https://x.example/", after: {} }), "BAD_ARG");
  await _expectReject("request: onUploadProgress non-function rejects",
    b.httpClient.request({ url: "https://x.example/", onUploadProgress: 1 }), "BAD_ARG");
  await _expectReject("request: onDownloadProgress non-function rejects",
    b.httpClient.request({ url: "https://x.example/", onDownloadProgress: 1 }), "BAD_ARG");
  await _expectReject("request: onChunk non-function rejects",
    b.httpClient.request({ url: "https://x.example/", onChunk: 1 }), "BAD_ARG");
  await _expectReject("request: bad jar shape rejects",
    b.httpClient.request({ url: "https://x.example/", jar: { cookieHeaderFor: 1 } }), "BAD_ARG");
  await _expectReject("request: bad cache shape rejects",
    b.httpClient.request({ url: "https://x.example/", cache: { _lookup: 1 } }), "BAD_ARG");
  await _expectReject("request: negative maxRedirects rejects",
    b.httpClient.request({ url: "https://x.example/", maxRedirects: -1 }), "BAD_ARG");
  await _expectReject("request: non-integer maxRedirects rejects",
    b.httpClient.request({ url: "https://x.example/", maxRedirects: 2.5 }), "BAD_ARG");
  await _expectReject("request: multipart + body together rejects",
    b.httpClient.request({ url: "https://x.example/", body: "x", multipart: { fields: {} } }), "BAD_ARG");
  await _expectReject("request: malformed multipart file entry rejects",
    b.httpClient.request({ url: "https://x.example/", multipart: { files: [{ field: "f" }] } }), "BAD_ARG");
  await _expectReject("request: before hook that throws surfaces BEFORE_THREW",
    b.httpClient.request({ url: "https://x.example/", before: [function () { throw new Error("bad pre"); }] }), "BEFORE_THREW");
  // maxBytesPerSec + transform validation (branch also probed elsewhere).
  await _expectReject("request: maxBytesPerSec non-number rejects",
    b.httpClient.request({ url: "https://x.example/", maxBytesPerSec: "fast" }), /maxBytesPerSec/);
  await _expectReject("request: uploadTransform non-Transform rejects",
    b.httpClient.request({ url: "https://x.example/", uploadTransform: 7 }), /Transform/);
  // Default scheme gate: a plain http URL without ALLOW_HTTP_ALL is refused.
  await _expectReject("request: cleartext http refused without ALLOW_HTTP_ALL opt-in",
    b.httpClient.request({ url: "http://127.0.0.1:1/", allowInternal: true }), /./);
}

// ---- before / after interceptors -----------------------------------

async function testBeforeAfterInterceptors() {
  await _withServer(function (req, res) {
    res.writeHead(200, { "x-echo-inject": req.headers["x-inject"] || "" });
    res.end("ok");
  }, async function (base) {
    var afterRan = 0;
    var res = await b.httpClient.request({
      url: base + "/", method: "GET",
      allowedProtocols: ALLOW, allowInternal: true,
      before: [function (o) { return Object.assign({}, o, { headers: { "x-inject": "on" } }); }],
      after: [
        function () { afterRan += 1; },
        function () { throw new Error("after hooks are best-effort"); },  // must be swallowed
      ],
    });
    check("before: mutated opts reached the wire (server echoed injected header)",
      res.headers["x-echo-inject"] === "on");
    check("after: first hook ran", afterRan === 1);
    check("after: a throwing hook did not break the response", res.statusCode === 200);
  });
}

// ---- allowedHosts egress gate --------------------------------------

async function testAllowedHosts() {
  await _withServer(function (req, res) { res.writeHead(200); res.end("ok"); }, async function (base, port) {
    // Exact host allow.
    var r1 = await b.httpClient.request({
      url: base + "/", allowedHosts: ["127.0.0.1"], allowedProtocols: ALLOW, allowInternal: true });
    check("allowedHosts: exact host allowed", r1.statusCode === 200);

    // Suffix + glob forms both match 127.0.0.1? No — use a hostname suffix case
    // with the object/method-restricted form on the real loopback host.
    var r2 = await b.httpClient.request({
      url: base + "/", method: "GET",
      allowedHosts: [{ host: "127.0.0.1", methods: ["GET", "HEAD"] }],
      allowedProtocols: ALLOW, allowInternal: true });
    check("allowedHosts: method-restricted entry allows GET", r2.statusCode === 200);

    // Method-restricted entry denies a non-listed method.
    var audit = _mkAuditCapture();
    var denied = await _expectReject("allowedHosts: method-restricted entry denies POST",
      b.httpClient.request({
        url: base + "/", method: "POST", body: "x",
        allowedHosts: [{ host: "127.0.0.1", methods: ["GET"] }],
        audit: audit, allowedProtocols: ALLOW, allowInternal: true }), "HOST_DISALLOWED");
    check("allowedHosts: deny emitted a host_denied audit event",
      audit.events.some(function (e) {
        return e.action === "system.httpclient.host_denied" && e.outcome === "denied";
      }));
    void denied; void port;

    // Host not on the list at all → denied.
    await _expectReject("allowedHosts: unlisted host denied",
      b.httpClient.request({
        url: base + "/", allowedHosts: ["api.partner.example"],
        allowedProtocols: ALLOW, allowInternal: true }), "HOST_DISALLOWED");

    // Suffix form (".0.0.1") — "127.0.0.1".endsWith(".0.0.1") matches.
    var r3 = await b.httpClient.request({
      url: base + "/", allowedHosts: [".0.0.1"], allowedProtocols: ALLOW, allowInternal: true });
    check("allowedHosts: suffix (.0.0.1) matches 127.0.0.1", r3.statusCode === 200);

    // Glob form ("*.0.0.1") normalizes to the suffix and matches.
    var r4 = await b.httpClient.request({
      url: base + "/", allowedHosts: ["*.0.0.1"], allowedProtocols: ALLOW, allowInternal: true });
    check("allowedHosts: glob (*.0.0.1) normalizes + matches", r4.statusCode === 200);

    // Leading-dot exact form (".127.0.0.1") matches via host === allow.slice(1).
    var r5 = await b.httpClient.request({
      url: base + "/", allowedHosts: [".127.0.0.1"], allowedProtocols: ALLOW, allowInternal: true });
    check("allowedHosts: dotted-exact (.127.0.0.1) matches via slice", r5.statusCode === 200);

    // Caller-supplied agent bypasses the transport cache (h1 override path).
    var customAgent = new http.Agent({ keepAlive: false });
    try {
      var r6 = await b.httpClient.request({
        url: base + "/", agent: customAgent, allowedProtocols: ALLOW, allowInternal: true });
      check("agent override: request succeeds through the caller's agent", r6.statusCode === 200);
    } finally {
      customAgent.destroy();
    }

    // String body path (Content-Length + ulTotal via Buffer.byteLength).
    var r7 = await b.httpClient.request({
      url: base + "/", method: "POST", body: "hello-string",
      allowedProtocols: ALLOW, allowInternal: true });
    check("string body: request with string body succeeds", r7.statusCode === 200);
  });
}

// ---- buffered response error branches (h1) -------------------------

async function testBufferedErrorBranches() {
  // non-2xx → HTTP_ERROR (default buffer mode)
  await _withServer(function (req, res) {
    res.writeHead(404, { "Content-Type": "text/plain" }); res.end("nope");
  }, async function (base) {
    var err = await _expectReject("buffer 404: rejects HTTP_ERROR",
      b.httpClient.request({ url: base + "/x", allowedProtocols: ALLOW, allowInternal: true }), "HTTP_ERROR");
    check("buffer 404: message names the status", err && /404/.test(err.message));
  });

  // always-resolve → non-2xx returned, not thrown
  await _withServer(function (req, res) {
    res.writeHead(503, { "Content-Type": "text/plain" }); res.end("down");
  }, async function (base) {
    var r = await b.httpClient.request({
      url: base + "/x", responseMode: "always-resolve",
      allowedProtocols: ALLOW, allowInternal: true });
    check("always-resolve: 503 returned structurally", r.statusCode === 503 && r.body.toString() === "down");
  });

  // maxResponseBytes cap → RESPONSE_TOO_LARGE
  await _withServer(function (req, res) {
    res.writeHead(200, { "Content-Length": "2000" }); res.end(Buffer.alloc(2000, 0x61));
  }, async function (base) {
    await _expectReject("buffer over-cap: rejects RESPONSE_TOO_LARGE",
      b.httpClient.request({ url: base + "/big", maxResponseBytes: 100,
        allowedProtocols: ALLOW, allowInternal: true }), "RESPONSE_TOO_LARGE");
  });
}

// ---- progress + observer + onChunk hooks (h1) ----------------------

async function testProgressAndObserver() {
  var payload = Buffer.alloc(4096, 0x62);
  await _withServer(function (req, res) {
    var chunks = [];
    req.on("data", function (c) { chunks.push(c); });
    req.on("end", function () {
      res.writeHead(200, { "Content-Length": String(payload.length) });
      res.end(payload);
    });
  }, async function (base) {
    var stages = [];
    var dl = [];
    var ul = [];
    var chunkBytes = 0;
    var res = await b.httpClient.request({
      url: base + "/", method: "POST", body: Buffer.alloc(2048, 0x63),
      allowedProtocols: ALLOW, allowInternal: true,
      observer: function (stage) { stages.push(stage); },
      onDownloadProgress: function (p) { dl.push(p); },
      onUploadProgress: function (p) { ul.push(p); },
      onChunk: function (c) { chunkBytes += c.length; },
    });
    check("observer: saw request:start and response:end",
      stages.indexOf("request:start") !== -1 && stages.indexOf("response:end") !== -1);
    check("onDownloadProgress: fired with loaded/total", dl.length > 0 && dl[dl.length - 1].loaded === payload.length && dl[dl.length - 1].total === payload.length);
    check("onUploadProgress: fired and summed to body length", ul.length > 0 && ul[ul.length - 1].loaded === 2048);
    check("onChunk: saw the full response body", chunkBytes === payload.length);
    check("response body intact", res.body.equals(payload));
  });
}

// ---- idle timeout + abort + connection error (h1) ------------------

async function testTimeoutAbortConnError() {
  // Idle timeout: server accepts but never responds.
  await _withServer(function () { /* hold the request open, never respond */ }, async function (base) {
    await _expectReject("idle timeout: rejects ETIMEDOUT",
      b.httpClient.request({ url: base + "/hang", idleTimeoutMs: 300,
        allowedProtocols: ALLOW, allowInternal: true }), "ETIMEDOUT");
  });

  // Pre-aborted signal → rejects before any socket work.
  var pre = new AbortController();
  pre.abort();
  await _expectReject("pre-aborted signal: rejects ABORT",
    b.httpClient.request({ url: "http://127.0.0.1:9/x", signal: pre.signal,
      allowedProtocols: ALLOW, allowInternal: true }), "ABORT");

  // Abort mid-flight: server holds the request, we abort right after issuing.
  await _withServer(function () { /* hold open */ }, async function (base) {
    var ctrl = new AbortController();
    var p = b.httpClient.request({ url: base + "/hang", signal: ctrl.signal,
      allowedProtocols: ALLOW, allowInternal: true });
    ctrl.abort();
    await _expectReject("in-flight abort: rejects ABORT", p, "ABORT");
  });

  // Connection refused: bind a server, capture its port, close it, then hit it.
  var deadPort = await (async function () {
    var s = http.createServer();
    var port = await b.testing.listenOnRandomPort(s, "127.0.0.1");
    await new Promise(function (r) { s.close(function () { r(); }); });
    return port;
  })();
  b.httpClient._resetForTest();  // drop any cached transport for that origin
  await _expectReject("connection refused: rejects with a connect error",
    b.httpClient.request({ url: "http://127.0.0.1:" + deadPort + "/x",
      allowedProtocols: ALLOW, allowInternal: true }), /ECONNREFUSED|REQ_ERROR/);
}

// ---- request-body stream error (h1) --------------------------------

async function testRequestBodyStreamError() {
  await _withServer(function (req) {
    // Consume + hold: the body error should settle the promise, not the response.
    req.on("data", function () {});
    req.on("error", function () {});
  }, async function (base) {
    var bad = new nodeStream.Readable({
      read: function () { this.destroy(new Error("body source blew up")); },
    });
    await _expectReject("upload body stream error: rejects REQ_BODY_ERROR",
      b.httpClient.request({ url: base + "/u", method: "POST", body: bad,
        allowedProtocols: ALLOW, allowInternal: true }), "REQ_BODY_ERROR");
  });
}

// ---- cookie jar attach + record (h1) -------------------------------

async function testCookieJar() {
  var jar = b.httpClient.cookieJar.create();
  var sawCookie = null;
  await _withServer(function (req, res) {
    sawCookie = req.headers.cookie || null;
    res.writeHead(200, { "set-cookie": "sid=abc123; Path=/" });
    res.end("ok");
  }, async function (base) {
    // First request: no cookie yet, server sets one.
    await b.httpClient.request({ url: base + "/", jar: jar, allowedProtocols: ALLOW, allowInternal: true });
    check("jar: first request sent no cookie", sawCookie === null);
    var hdr = jar.cookieHeaderFor(base + "/");
    check("jar: recorded Set-Cookie from the response", typeof hdr === "string" && /sid=abc123/.test(hdr));
    // Second request: jar-derived Cookie header is attached.
    await b.httpClient.request({ url: base + "/", jar: jar, allowedProtocols: ALLOW, allowInternal: true });
    check("jar: second request carried the stored cookie", /sid=abc123/.test(sawCookie || ""));
  });
}

// ---- redirect following (h1) ---------------------------------------

async function testRedirects() {
  // Simple same-origin chain to a 200.
  await _withServer(function (req, res) {
    if (req.url === "/a") { res.writeHead(302, { Location: "/b" }); res.end(); return; }
    res.writeHead(200); res.end("final");
  }, async function (base) {
    var r = await b.httpClient.request({ url: base + "/a", maxRedirects: 3,
      allowedProtocols: ALLOW, allowInternal: true });
    check("redirect: followed 302 to final 200", r.statusCode === 200 && r.body.toString() === "final");
  });

  // 303 coerces to GET and drops the body.
  await _withServer(function (req, res) {
    if (req.url === "/post") { res.writeHead(303, { Location: "/see" }); res.end(); return; }
    var chunks = [];
    req.on("data", function (c) { chunks.push(c); });
    req.on("end", function () {
      res.writeHead(200, { "x-method": req.method, "x-body-len": String(Buffer.concat(chunks).length) });
      res.end("done");
    });
  }, async function (base) {
    var r = await b.httpClient.request({ url: base + "/post", method: "POST", body: "payload",
      maxRedirects: 2, allowedProtocols: ALLOW, allowInternal: true });
    check("redirect 303: coerced to GET", r.headers["x-method"] === "GET");
    check("redirect 303: body dropped", r.headers["x-body-len"] === "0");
  });

  // 307 preserves method + body.
  await _withServer(function (req, res) {
    if (req.url === "/keep") { res.writeHead(307, { Location: "/echo" }); res.end(); return; }
    var chunks = [];
    req.on("data", function (c) { chunks.push(c); });
    req.on("end", function () {
      res.writeHead(200, { "x-method": req.method });
      res.end(Buffer.concat(chunks));
    });
  }, async function (base) {
    var r = await b.httpClient.request({ url: base + "/keep", method: "PUT", body: "keepme",
      maxRedirects: 2, allowedProtocols: ALLOW, allowInternal: true });
    check("redirect 307: method preserved", r.headers["x-method"] === "PUT");
    check("redirect 307: body preserved", r.body.toString() === "keepme");
  });

  // 3xx with no Location returned as-is.
  await _withServer(function (req, res) { res.writeHead(302); res.end(); }, async function (base) {
    var r = await b.httpClient.request({ url: base + "/noloc", maxRedirects: 3,
      allowedProtocols: ALLOW, allowInternal: true });
    check("redirect: 3xx without Location returned to caller", r.statusCode === 302);
  });

  // Invalid Location → BAD_REDIRECT.
  await _withServer(function (req, res) {
    res.writeHead(302, { Location: "http://[not a url" }); res.end();
  }, async function (base) {
    await _expectReject("redirect: invalid Location rejects BAD_REDIRECT",
      b.httpClient.request({ url: base + "/bad", maxRedirects: 3,
        allowedProtocols: ALLOW, allowInternal: true }), "BAD_REDIRECT");
  });

  // Redirect budget exhausted → last 3xx returned.
  await _withServer(function (req, res) {
    var n = parseInt(req.url.slice(1), 10) || 0;
    res.writeHead(302, { Location: "/" + (n + 1) }); res.end();
  }, async function (base) {
    var r = await b.httpClient.request({ url: base + "/0", maxRedirects: 2,
      allowedProtocols: ALLOW, allowInternal: true });
    check("redirect: budget exhausted returns the last 3xx", r.statusCode === 302);
  });

  // onRedirect sync throw → REDIRECT_ABORTED.
  await _withServer(function (req, res) {
    if (req.url === "/a") { res.writeHead(302, { Location: "/b" }); res.end(); return; }
    res.writeHead(200); res.end("final");
  }, async function (base) {
    await _expectReject("onRedirect: sync throw aborts with REDIRECT_ABORTED",
      b.httpClient.request({ url: base + "/a", maxRedirects: 3,
        onRedirect: function () { throw new Error("no thanks"); },
        allowedProtocols: ALLOW, allowInternal: true }), "REDIRECT_ABORTED");
  });

  // onRedirect async (returns a promise) proceeds.
  await _withServer(function (req, res) {
    if (req.url === "/a") { res.writeHead(302, { Location: "/b" }); res.end(); return; }
    res.writeHead(200); res.end("final");
  }, async function (base) {
    var seen = [];
    var r = await b.httpClient.request({ url: base + "/a", maxRedirects: 3,
      onRedirect: function (ev) { seen.push(ev.statusCode); return Promise.resolve(); },
      allowedProtocols: ALLOW, allowInternal: true });
    check("onRedirect: async hook awaited then follow proceeds",
      r.statusCode === 200 && seen[0] === 302);
  });
}

// ---- cross-origin auth-header strip on redirect --------------------

async function testCrossOriginStrip() {
  var sawAuthOnB = "unset";
  var sawKeepOnB = "unset";
  var bBase = null;
  await _withTwoServers(
    // A: redirect cross-origin to B's absolute URL (bBase set before any request).
    function (req, res) { res.writeHead(302, { Location: bBase + "/landing" }); res.end(); },
    // B: record whether the sensitive + non-sensitive headers survived the hop.
    function (req, res) {
      sawAuthOnB = req.headers.authorization || null;
      sawKeepOnB = req.headers["x-keep"] || null;
      res.writeHead(200); res.end("b");
    },
    async function (baseA, baseB) {
      bBase = baseB;
      var r = await b.httpClient.request({
        url: baseA + "/start", maxRedirects: 2,
        headers: { Authorization: "Bearer secret-token", "X-Keep": "1" },
        allowedProtocols: ALLOW, allowInternal: true });
      check("cross-origin redirect: reached origin B", r.statusCode === 200 && r.body.toString() === "b");
      check("cross-origin redirect: Authorization stripped on hop to B", sawAuthOnB === null);
      check("cross-origin redirect: non-sensitive header preserved", sawKeepOnB === "1");
    });
}

// ---- HTTP/2 (h2c) code path ----------------------------------------

async function testH2cPaths() {
  await _withH2cServer(function (stream, headers) {
    var path = headers[":path"];
    if (path === "/big") { stream.respond({ ":status": 200 }); stream.end(Buffer.alloc(3000, 0x64)); return; }
    if (path === "/err") { stream.respond({ ":status": 500 }); stream.end("boom"); return; }
    if (path === "/echo") {
      var chunks = [];
      stream.on("data", function (c) { chunks.push(c); });
      stream.on("end", function () {
        stream.respond({ ":status": 200, "content-type": "text/plain" });
        stream.end(Buffer.concat(chunks));
      });
      return;
    }
    stream.respond({ ":status": 200, "content-type": "text/plain" });
    stream.end("h2c-ok");
  }, async function (base) {
    var r = await b.httpClient.request({ url: base + "/x", preferH2: true,
      allowedProtocols: ALLOW, allowInternal: true });
    check("h2c: GET succeeds over prior-knowledge h2c",
      r.statusCode === 200 && r.body.toString() === "h2c-ok");
    check("h2c: transport cached as h2", b.httpClient._getCachedTransportKind(base + "/x") === "h2");

    // non-2xx → HTTP_ERROR
    await _expectReject("h2c: non-2xx rejects HTTP_ERROR",
      b.httpClient.request({ url: base + "/err", preferH2: true,
        allowedProtocols: ALLOW, allowInternal: true }), "HTTP_ERROR");

    // always-resolve returns the non-2xx structurally
    var ar = await b.httpClient.request({ url: base + "/err", preferH2: true,
      responseMode: "always-resolve", allowedProtocols: ALLOW, allowInternal: true });
    check("h2c: always-resolve returns 500 body", ar.statusCode === 500 && ar.body.toString() === "boom");

    // oversized response → RESPONSE_TOO_LARGE
    await _expectReject("h2c: over-cap rejects RESPONSE_TOO_LARGE",
      b.httpClient.request({ url: base + "/big", preferH2: true, maxResponseBytes: 100,
        allowedProtocols: ALLOW, allowInternal: true }), "RESPONSE_TOO_LARGE");

    // POST body echoes back
    var echo = await b.httpClient.request({ url: base + "/echo", method: "POST", body: "h2-body",
      preferH2: true, allowedProtocols: ALLOW, allowInternal: true });
    check("h2c: POST body delivered + echoed", echo.body.toString() === "h2-body");

    // stream mode over h2c
    var s = await b.httpClient.request({ url: base + "/x", preferH2: true, responseMode: "stream",
      allowedProtocols: ALLOW, allowInternal: true });
    var drained = await new Promise(function (resolve, reject) {
      var cs = [];
      s.body.on("data", function (c) { cs.push(c); });
      s.body.on("end", function () { resolve(Buffer.concat(cs)); });
      s.body.on("error", reject);
    });
    check("h2c: stream-mode body drains to the full payload", drained.toString() === "h2c-ok");
  });
  b.httpClient._resetForTest();
}

// ---- multipart valid round-trip (buffer body path) -----------------

async function testMultipartValidRoundTrip() {
  var received = null;
  var contentType = null;
  var contentLength = null;
  await _withServer(function (req, res) {
    contentType = req.headers["content-type"];
    contentLength = req.headers["content-length"];
    var chunks = [];
    req.on("data", function (c) { chunks.push(c); });
    req.on("end", function () { received = Buffer.concat(chunks).toString("utf8"); res.writeHead(200); res.end("ok"); });
  }, async function (base) {
    var r = await b.httpClient.request({
      url: base + "/u",
      multipart: {
        fields: { title: "hello", tags: ["a", "b"] },     // array form → two parts
        files: [{ field: "doc", content: "FILEDATA", filename: "d.txt", contentType: "text/plain" }],
      },
      allowedProtocols: ALLOW, allowInternal: true });
    check("multipart: POST default method + 200", r.statusCode === 200);
    check("multipart: server saw multipart Content-Type", /^multipart\/form-data;\s*boundary=/i.test(contentType || ""));
    check("multipart: Content-Length set for all-buffer body", contentLength != null && Number(contentLength) > 0);
    check("multipart: array field emitted both values",
      /name="tags"/.test(received) && received.indexOf("a") !== -1 && received.indexOf("b") !== -1);
    check("multipart: file part carries content + filename",
      received.indexOf('name="doc"') !== -1 && received.indexOf("FILEDATA") !== -1 && received.indexOf('filename="d.txt"') !== -1);
  });
}

// ---- downloadStream maxBytes cap (defensive) -----------------------

async function testDownloadMaxBytes() {
  await _withServer(function (req, res) {
    res.writeHead(200, { "Content-Type": "application/octet-stream" });
    res.end(Buffer.alloc(4096, 0x65));
  }, async function (base) {
    var dir = b.testing.tempDir("httpclient-cov-dl");
    try {
      var dest = helpers.path.join(dir.path, "capped.bin");
      await _expectReject("downloadStream: over maxBytes rejects response-too-large",
        b.httpClient.downloadStream({
          url: base + "/big", dest: dest, maxBytes: 512,
          allowedProtocols: ALLOW, allowInternal: true }), "httpclient/response-too-large");
      check("downloadStream: over-cap left no dest file", !helpers.fs.existsSync(dest));
    } finally {
      dir.cleanup();
    }
  });
}

// Destroy the httpClient transport pool and wait for every TCP handle to
// close, so the async teardown completes inside run() rather than in the
// forked worker's post-run grace window. Poll, don't sleep.
async function _drainTcpHandles() {
  b.httpClient._resetForTest();
  if (typeof process.getActiveResourcesInfo !== "function") return;
  await helpers.waitUntil(function () {
    return process.getActiveResourcesInfo().filter(function (t) {
      return t === "TCPSocketWrap" || t === "TCPServerWrap";
    }).length === 0;
  }, { timeoutMs: 5000, label: "http-client-coverage: TCP handle drain after _resetForTest" });
}

async function run() {
  try {
    testSurface();
    await testConfigurePool();
    await testArgValidation();
    await testBeforeAfterInterceptors();
    await testAllowedHosts();
    await testBufferedErrorBranches();
    await testProgressAndObserver();
    await testTimeoutAbortConnError();
    await testRequestBodyStreamError();
    await testCookieJar();
    await testRedirects();
    await testCrossOriginStrip();
    await testH2cPaths();
    await testMultipartValidRoundTrip();
    await testDownloadMaxBytes();
  } finally {
    await _drainTcpHandles();
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK http-client-coverage — " + helpers.getChecks() + " checks"); })
       .catch(function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); });
}
