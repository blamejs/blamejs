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

// ---- pinned-DNS lookup contract (unit) -----------------------------

function testPinnedLookupContract() {
  var lk = b.httpClient._pinnedLookupForTest([
    { address: "10.9.8.7", family: 4 }, { address: "10.9.8.6", family: 4 }]);
  var allRes = null, singleAddr = null, singleFam = null, fnAddr = null;
  lk("h", { all: true }, function (err, addrs) { allRes = addrs; });
  lk("h", {}, function (err, addr, fam) { singleAddr = addr; singleFam = fam; });
  lk("h", function (err, addr) { fnAddr = addr; });   // options-as-callback shape
  check("pinnedLookup: all:true returns the full family list",
    Array.isArray(allRes) && allRes.length === 2 && allRes[0].address === "10.9.8.7");
  check("pinnedLookup: single returns the first address + family",
    singleAddr === "10.9.8.7" && singleFam === 4);
  check("pinnedLookup: options-as-callback shape resolves the first address", fnAddr === "10.9.8.7");
  check("pinnedLookup: empty / null ips yields undefined (no pinning)",
    b.httpClient._pinnedLookupForTest([]) === undefined &&
    b.httpClient._pinnedLookupForTest(null) === undefined);
}

// ---- multipart body build: injection rejects + streaming entry -----

async function testMultipartBuildBranches() {
  function mpReject(label, multipart) {
    return _expectReject(label,
      b.httpClient.request({ url: "https://x.example/", multipart: multipart }), "BAD_ARG");
  }
  await mpReject("multipart: CRLF in field name refused (header injection)",
    { fields: { "a\r\nInjected: 1": "v" } });
  await mpReject("multipart: empty field name refused",
    { fields: { "": "v" } });
  await mpReject("multipart: CRLF in filename refused (header injection)",
    { files: [{ field: "f", content: "x", filename: "a\r\nX-Injected: 1" }] });
  await mpReject("multipart: CRLF in contentType refused (header injection)",
    { files: [{ field: "f", content: "x", contentType: "text/plain\r\nX-Injected: 1" }] });
  await mpReject("multipart: non-object file entry refused",
    { files: [42] });
  await mpReject("multipart: file entry missing field refused",
    { files: [{ content: "x" }] });
  await mpReject("multipart: file entry with two sources refused",
    { files: [{ field: "f", content: "x", filePath: "/nope" }] });
  await mpReject("multipart: non-buffer/string content refused",
    { files: [{ field: "f", content: 42 }] });

  // Valid: a content file WITHOUT filename defaults to "blob".
  var body = null;
  await _withServer(function (req, res) {
    var chunks = []; req.on("data", function (c) { chunks.push(c); });
    req.on("end", function () { body = Buffer.concat(chunks).toString("utf8"); res.writeHead(200); res.end("ok"); });
  }, async function (base) {
    var r = await b.httpClient.request({ url: base + "/mp",
      multipart: { files: [{ field: "f", content: "PAYLOAD" }] },
      allowedProtocols: ALLOW, allowInternal: true });
    check("multipart: content file without a filename defaults to blob",
      r.statusCode === 200 && /filename="blob"/.test(body || ""));
  });

  // Valid: an operator-supplied Readable stream entry (unknown size) →
  // Content-Length omitted, chunked transfer, iterator streams the bytes.
  var got = null, hadCL = "unset", te = "unset";
  await _withServer(function (req, res) {
    hadCL = req.headers["content-length"] || null;
    te = req.headers["transfer-encoding"] || null;
    var chunks = []; req.on("data", function (c) { chunks.push(c); });
    req.on("end", function () { got = Buffer.concat(chunks).toString("utf8"); res.writeHead(200); res.end("ok"); });
  }, async function (base) {
    var src = nodeStream.Readable.from([Buffer.from("STREAM-ENTRY-DATA")]);
    var r = await b.httpClient.request({ url: base + "/mp",
      multipart: { fields: { a: "1" }, files: [{ field: "f", stream: src, filename: "s.bin" }] },
      allowedProtocols: ALLOW, allowInternal: true });
    check("multipart: stream entry (unknown size) omits Content-Length + chunks",
      r.statusCode === 200 && hadCL === null && te === "chunked");
    check("multipart: stream entry body reached the server",
      got != null && got.indexOf("STREAM-ENTRY-DATA") !== -1);
  });

  // Valid: a filePath entry WITHOUT an explicit filename → path.basename.
  var fpBody = null;
  await _withServer(function (req, res) {
    var chunks = []; req.on("data", function (c) { chunks.push(c); });
    req.on("end", function () { fpBody = Buffer.concat(chunks).toString("utf8"); res.writeHead(200); res.end("ok"); });
  }, async function (base) {
    var dir = b.testing.tempDir("httpclient-cov-fpn");
    try {
      var fp = helpers.path.join(dir.path, "the-name.dat");
      helpers.fs.writeFileSync(fp, "FILEPATH-DATA");
      var r = await b.httpClient.request({ url: base + "/mp",
        multipart: { files: [{ field: "f", filePath: fp }] },
        allowedProtocols: ALLOW, allowInternal: true });
      check("multipart: filePath entry without filename defaults to path.basename",
        r.statusCode === 200 && /filename="the-name\.dat"/.test(fpBody || ""));
    } finally {
      dir.cleanup();
    }
  });
}

// ---- jar merges with a caller-supplied Cookie header ---------------

async function testJarCookieMerge() {
  var jar = b.httpClient.cookieJar.create();
  var saw = null;
  await _withServer(function (req, res) {
    saw = req.headers.cookie || null;
    res.writeHead(200, { "set-cookie": "sid=z9; Path=/" });
    res.end("ok");
  }, async function (base) {
    // Seed the jar from a first response.
    await b.httpClient.request({ url: base + "/", jar: jar, allowedProtocols: ALLOW, allowInternal: true });
    // Second request supplies its OWN Cookie header — the jar supplements it.
    await b.httpClient.request({ url: base + "/", jar: jar,
      headers: { Cookie: "caller=1" }, allowedProtocols: ALLOW, allowInternal: true });
    check("jar: caller Cookie header merged with the jar cookie (both present)",
      /caller=1/.test(saw || "") && /sid=z9/.test(saw || ""));
  });
}

// ---- stream-mode non-2xx error body (h1) ---------------------------

async function testStreamModeHttpError() {
  // Small error body: rejects HTTP_ERROR with a bounded err.body prefix.
  await _withServer(function (req, res) {
    res.writeHead(404, { "Content-Type": "application/problem+json" });
    res.end('{"detail":"missing"}');
  }, async function (base) {
    var err = await _expectReject("stream 404: rejects HTTP_ERROR",
      b.httpClient.request({ url: base + "/x", responseMode: "stream",
        allowedProtocols: ALLOW, allowInternal: true }), "HTTP_ERROR");
    check("stream 404: err.body carries the error payload prefix",
      err && Buffer.isBuffer(err.body) && /missing/.test(err.body.toString("utf8")));
  });

  // Large error body: the collector fills its 16 KiB cap, destroys the
  // stream, and still rejects (doesn't hang on a slow / large error body).
  await _withServer(function (req, res) {
    res.writeHead(413, { "Content-Type": "text/plain" });
    res.end(Buffer.alloc(40000, 0x7a));
  }, async function (base) {
    var err = await _expectReject("stream 413: oversized error body still rejects HTTP_ERROR",
      b.httpClient.request({ url: base + "/big", responseMode: "stream",
        allowedProtocols: ALLOW, allowInternal: true }), "HTTP_ERROR");
    check("stream 413: err.body prefix capped at 16 KiB",
      err && Buffer.isBuffer(err.body) && err.body.length <= 16384 && err.body.length > 0);
  });
}

// ---- bandwidth throttle + transform interpose (h1) -----------------

async function testThrottleAndTransformH1() {
  var payload = Buffer.alloc(64, 0x71);
  await _withServer(function (req, res) {
    var chunks = []; req.on("data", function (c) { chunks.push(c); });
    req.on("end", function () { res.writeHead(200); res.end(payload); });
  }, async function (base) {
    var dlSeen = 0, ulSeen = 0, chunkSeen = 0;
    // Upload body larger than the per-second budget forces the token-bucket
    // to stall at least once (exercises the refill / setTimeout wait branch).
    var upBody = Buffer.alloc(1500, 0x72);
    var res = await b.httpClient.request({
      url: base + "/t", method: "POST", body: upBody,
      maxBytesPerSec: 1024,
      downloadTransform: function () { return new nodeStream.PassThrough(); },  // factory form
      uploadTransform: new nodeStream.PassThrough(),                            // instance form
      onUploadProgress: function (p) { ulSeen = p.loaded; },
      onDownloadProgress: function (p) { dlSeen = p.loaded; },
      onChunk: function (c) { chunkSeen += c.length; },
      allowedProtocols: ALLOW, allowInternal: true });
    check("throttle h1: response intact through the throttle + transform chain",
      res.body.equals(payload));
    check("throttle h1: upload progress summed to the body length", ulSeen === 1500);
    check("throttle h1: download progress + onChunk observed the full payload",
      dlSeen === payload.length && chunkSeen === payload.length);
  });
}

// ---- upload progress on a piped Readable body (no throttle) --------

async function testUploadProgressPipedBody() {
  await _withServer(function (req, res) {
    req.on("data", function () {}); req.on("end", function () { res.writeHead(200); res.end("ok"); });
  }, async function (base) {
    var total = 0;
    var src = nodeStream.Readable.from([Buffer.from("AAAA"), Buffer.from("BBBB")]);
    var res = await b.httpClient.request({ url: base + "/u", method: "POST", body: src,
      onUploadProgress: function (p) { total = p.loaded; },
      allowedProtocols: ALLOW, allowInternal: true });
    check("upload progress (piped Readable): summed bytes across data events",
      res.statusCode === 200 && total === 8);
  });
}

// ---- download-transform error surfaces on the buffered read (h1) ---

async function testDownloadTransformErrorH1() {
  await _withServer(function (req, res) { res.writeHead(200); res.end(Buffer.alloc(64, 1)); },
    async function (base) {
      await _expectReject("h1 buffer-mode download-transform error rejects RES_ERROR",
        b.httpClient.request({ url: base + "/x",
          downloadTransform: function () {
            return new nodeStream.Transform({ transform: function (c, e, cb) { cb(new Error("xform boom")); } });
          },
          allowedProtocols: ALLOW, allowInternal: true }), "RES_ERROR");
    });
}

// ---- downloadStream lifecycle: success / verify / mismatch / non-2xx

async function testDownloadStreamLifecycle() {
  // Config-time validation rejects (async — the opts shape is checked first).
  await _expectReject("downloadStream: non-object opts rejects bad-opts",
    b.httpClient.downloadStream(1), "httpclient/bad-opts");
  await _expectReject("downloadStream: unknown hash alg rejects",
    b.httpClient.downloadStream({ url: "https://x/", dest: "/x", hash: "md5" }), /hash must be one of/);
  await _expectReject("downloadStream: non-hex expected digest rejects",
    b.httpClient.downloadStream({ url: "https://x/", dest: "/x", expected: "nothex!!" }), /hex digest/);

  var payload = Buffer.from("DOWNLOAD-STREAM-PAYLOAD-abc123");
  await _withServer(function (req, res) {
    if (req.url === "/redir") { res.writeHead(302, { Location: "/elsewhere" }); res.end(); return; }
    res.writeHead(200, { "Content-Type": "application/octet-stream" });
    res.end(payload);
  }, async function (base) {
    var dir = b.testing.tempDir("httpclient-cov-dllife");
    try {
      // Success (no expected): file lands, hash + bytesWritten returned.
      var dest1 = helpers.path.join(dir.path, "a.bin");
      var d1 = await b.httpClient.downloadStream({ url: base + "/f", dest: dest1,
        allowedProtocols: ALLOW, allowInternal: true });
      check("downloadStream: success returns statusCode / bytesWritten / hash",
        d1.statusCode === 200 && d1.bytesWritten === payload.length &&
        typeof d1.hash === "string" && d1.hash.length > 0);
      check("downloadStream: success created the dest file", helpers.fs.existsSync(dest1));

      // Verified: expected === the first download's hash → renamed into place.
      var dest2 = helpers.path.join(dir.path, "b.bin");
      var d2 = await b.httpClient.downloadStream({ url: base + "/f", dest: dest2, expected: d1.hash,
        allowedProtocols: ALLOW, allowInternal: true });
      check("downloadStream: matching expected hash completes the download",
        d2.statusCode === 200 && helpers.fs.existsSync(dest2));

      // Mismatch: wrong expected → hash-mismatch, tmp removed, no dest.
      var dest3 = helpers.path.join(dir.path, "c.bin");
      var audit = _mkAuditCapture();
      await _expectReject("downloadStream: wrong expected hash rejects hash-mismatch",
        b.httpClient.downloadStream({ url: base + "/f", dest: dest3, expected: "deadbeefcafe",
          audit: audit, allowedProtocols: ALLOW, allowInternal: true }), "httpclient/hash-mismatch");
      check("downloadStream: mismatch left no dest file", !helpers.fs.existsSync(dest3));
      check("downloadStream: mismatch emitted a refused audit event",
        audit.events.some(function (e) { return e.action === "system.httpclient.download_stream.refused"; }));

      // 3xx slips through stream mode (no redirect follow) → http-error.
      var dest4 = helpers.path.join(dir.path, "d.bin");
      var err = await _expectReject("downloadStream: 3xx upstream rejects http-error",
        b.httpClient.downloadStream({ url: base + "/redir", dest: dest4,
          allowedProtocols: ALLOW, allowInternal: true }), "httpclient/http-error");
      check("downloadStream: http-error carries the upstream status", err && err.statusCode === 302);

      // Rename failure: point dest at an existing directory so the atomic
      // tmp→dest rename fails; the tmp is cleaned + a refused audit emits.
      var destDir = helpers.path.join(dir.path, "adir");
      helpers.fs.mkdirSync(destDir);
      var raudit = _mkAuditCapture();
      await _expectReject("downloadStream: rename onto a directory rejects rename-failed",
        b.httpClient.downloadStream({ url: base + "/f", dest: destDir, audit: raudit,
          allowedProtocols: ALLOW, allowInternal: true }), "httpclient/rename-failed");
      check("downloadStream: rename failure emitted a refused audit event",
        raudit.events.some(function (e) {
          return e.action === "system.httpclient.download_stream.refused" && e.metadata.reason === "rename-failed";
        }));
    } finally {
      dir.cleanup();
    }
  });

  // request-failed (connection refused) → refused audit + rethrow.
  var failDir = b.testing.tempDir("httpclient-cov-dlfail");
  try {
    var audit2 = _mkAuditCapture();
    b.httpClient._resetForTest();
    var e = null;
    try {
      await b.httpClient.downloadStream({ url: "http://127.0.0.1:1/x",
        dest: helpers.path.join(failDir.path, "x.bin"),
        audit: audit2, allowedProtocols: ALLOW, allowInternal: true });
    } catch (err) { e = err; }
    check("downloadStream: connection failure rethrows + audits refused (request-failed)",
      e != null && audit2.events.some(function (x) {
        return x.action === "system.httpclient.download_stream.refused" && x.metadata.reason === "request-failed";
      }));
  } finally {
    failDir.cleanup();
  }
}

// ---- uploadMultipartStream lifecycle -------------------------------

async function testUploadMultipartStreamLifecycle() {
  // Config-time validation rejects (async — the opts shape is checked first).
  await _expectReject("uploadMultipartStream: non-object opts rejects bad-opts",
    b.httpClient.uploadMultipartStream(1), "httpclient/bad-opts");
  await _expectReject("uploadMultipartStream: missing file object rejects",
    b.httpClient.uploadMultipartStream({ url: "https://x/" }), /file must be an object/);
  await _expectReject("uploadMultipartStream: non-object fields rejects",
    b.httpClient.uploadMultipartStream({ url: "https://x/", file: { path: "/p", fieldName: "f" }, fields: [1] }), /fields must be an object/);

  var dir = b.testing.tempDir("httpclient-cov-upload");
  try {
    var src = helpers.path.join(dir.path, "artifact.txt");
    helpers.fs.writeFileSync(src, "UPLOAD-STREAM-BODY");

    var sawCT = null, sawBodyLen = 0;
    await _withServer(function (req, res) {
      sawCT = req.headers["content-type"] || null;
      var chunks = []; req.on("data", function (c) { chunks.push(c); });
      req.on("end", function () { sawBodyLen = Buffer.concat(chunks).length; res.writeHead(200); res.end("stored"); });
    }, async function (base) {
      var audit = _mkAuditCapture();
      var r = await b.httpClient.uploadMultipartStream({
        url: base + "/up",
        file: { path: src, fieldName: "artifact", contentType: "text/plain" },
        fields: { tag: "v1" }, audit: audit,
        allowedProtocols: ALLOW, allowInternal: true });
      check("uploadMultipartStream: success returns statusCode + response",
        r.statusCode === 200 && r.response && r.response.body.toString() === "stored");
      check("uploadMultipartStream: server saw a multipart Content-Type + a body",
        /^multipart\/form-data;\s*boundary=/i.test(sawCT || "") && sawBodyLen > 0);
      check("uploadMultipartStream: completed audit emitted",
        audit.events.some(function (e) { return e.action === "system.httpclient.upload_stream.completed"; }));
    });

    // Missing file path → missing-file.
    await _expectReject("uploadMultipartStream: missing file rejects missing-file",
      b.httpClient.uploadMultipartStream({ url: "https://x.example/up",
        file: { path: helpers.path.join(dir.path, "nope.txt"), fieldName: "f" },
        allowedProtocols: ALLOW, allowInternal: true }), "httpclient/missing-file");

    // A directory path (not a regular file) → missing-file.
    await _expectReject("uploadMultipartStream: directory path rejects missing-file",
      b.httpClient.uploadMultipartStream({ url: "https://x.example/up",
        file: { path: dir.path, fieldName: "f" },
        allowedProtocols: ALLOW, allowInternal: true }), "httpclient/missing-file");

    // Request failure (connection refused) → refused audit + rethrow.
    var audit2 = _mkAuditCapture();
    b.httpClient._resetForTest();
    var e = null;
    try {
      await b.httpClient.uploadMultipartStream({ url: "http://127.0.0.1:1/up",
        file: { path: src, fieldName: "f" }, audit: audit2,
        allowedProtocols: ALLOW, allowInternal: true });
    } catch (err) { e = err; }
    check("uploadMultipartStream: connection failure rethrows + audits refused (request-failed)",
      e != null && audit2.events.some(function (x) {
        return x.action === "system.httpclient.upload_stream.refused" && x.metadata.reason === "request-failed";
      }));
  } finally {
    dir.cleanup();
    b.httpClient._resetForTest();
  }
}

// ---- RFC 9111 outbound cache paths ---------------------------------

function _newHttpCache(extra) {
  var store = b.httpClient.cache.memoryStore({ maxBytes: 1048576, maxEntries: 64 });
  return b.httpClient.cache.create(Object.assign({ store: store }, extra || {}));
}

async function testCachePaths() {
  // Fresh HIT: max-age=60 → second request served from cache (no upstream hit).
  var hitCount = 0;
  await _withServer(function (req, res) {
    hitCount += 1;
    res.writeHead(200, { "Cache-Control": "max-age=60", "Content-Type": "text/plain" });
    res.end("fresh-body");
  }, async function (base) {
    var cache = _newHttpCache();
    var m = await b.httpClient.request({ url: base + "/hit", cache: cache, allowedProtocols: ALLOW, allowInternal: true });
    var h = await b.httpClient.request({ url: base + "/hit", cache: cache, allowedProtocols: ALLOW, allowInternal: true });
    check("cache: first request is a MISS, second a HIT",
      m.headers["x-blamejs-cache"] === "MISS" && h.headers["x-blamejs-cache"] === "HIT");
    check("cache: HIT served without a second upstream fetch", hitCount === 1);
    check("cache: HIT carries the stored body + an Age header",
      h.body.toString() === "fresh-body" && typeof h.headers.age === "string");
  });

  // Inline revalidation → 304 Not Modified → REVALIDATED.
  await _withServer(function (req, res) {
    if (req.headers["if-none-match"] === '"v1"') { res.writeHead(304, { ETag: '"v1"' }); res.end(); return; }
    res.writeHead(200, { "Cache-Control": "max-age=0", "ETag": '"v1"' });
    res.end("revalidate-body");
  }, async function (base) {
    var cache = _newHttpCache();
    await b.httpClient.request({ url: base + "/rev", cache: cache, allowedProtocols: ALLOW, allowInternal: true });
    var r = await b.httpClient.request({ url: base + "/rev", cache: cache, allowedProtocols: ALLOW, allowInternal: true });
    check("cache: stale-then-304 marks REVALIDATED + keeps the stored body",
      r.headers["x-blamejs-cache"] === "REVALIDATED" && r.body.toString() === "revalidate-body");
  });

  // Inline revalidation → 200 fresh response → MISS (store replaced).
  var n = 0;
  await _withServer(function (req, res) {
    n += 1;
    res.writeHead(200, { "Cache-Control": "max-age=0", "ETag": '"e' + n + '"' });
    res.end("v" + n);
  }, async function (base) {
    var cache = _newHttpCache();
    await b.httpClient.request({ url: base + "/fr", cache: cache, allowedProtocols: ALLOW, allowInternal: true });
    var r = await b.httpClient.request({ url: base + "/fr", cache: cache, allowedProtocols: ALLOW, allowInternal: true });
    check("cache: revalidation returning 200 is a fresh MISS with the new body",
      r.headers["x-blamejs-cache"] === "MISS" && r.body.toString() === "v2");
  });

  // stale-while-revalidate: serve STALE immediately + background refresh.
  var swrHits = 0;
  await _withServer(function (req, res) {
    swrHits += 1;
    res.writeHead(200, { "Cache-Control": "max-age=0, stale-while-revalidate=60", "ETag": '"s' + swrHits + '"' });
    res.end("swr" + swrHits);
  }, async function (base) {
    var cache = _newHttpCache({ revalidateInBackground: true });
    await b.httpClient.request({ url: base + "/swr", cache: cache, allowedProtocols: ALLOW, allowInternal: true });   // MISS + store
    var s = await b.httpClient.request({ url: base + "/swr", cache: cache, allowedProtocols: ALLOW, allowInternal: true });  // STALE served
    check("cache: stale-while-revalidate serves STALE immediately",
      s.headers["x-blamejs-cache"] === "STALE" && s.body.toString() === "swr1");
    // Background revalidation fires async — wait for the upstream to see it
    // so the fire-and-forget request completes inside the server's lifetime.
    await helpers.waitUntil(function () { return swrHits >= 2; },
      { timeoutMs: 5000, label: "cache swr: background revalidation reached upstream" });
    check("cache: swr background revalidation refreshed from upstream", swrHits >= 2);
  });

  // stale-if-error: revalidation fails → serve STALE within the SIE window.
  await _withServer(function (req, res) {
    if (req.headers["if-none-match"]) { req.destroy(); return; }   // fail the revalidation
    res.writeHead(200, { "Cache-Control": "max-age=0, stale-if-error=60", "ETag": '"sie"' });
    res.end("sie-body");
  }, async function (base) {
    var cache = _newHttpCache();
    await b.httpClient.request({ url: base + "/sie", cache: cache, allowedProtocols: ALLOW, allowInternal: true });   // MISS + store
    var r = await b.httpClient.request({ url: base + "/sie", cache: cache, allowedProtocols: ALLOW, allowInternal: true });  // reval errors → STALE
    check("cache: stale-if-error serves STALE when revalidation fails",
      r.headers["x-blamejs-cache"] === "STALE" && r.body.toString() === "sie-body");
  });

  // Revalidation error with NO stale-if-error window → the error propagates.
  await _withServer(function (req, res) {
    if (req.headers["if-none-match"]) { req.destroy(); return; }   // fail the revalidation
    res.writeHead(200, { "Cache-Control": "max-age=0", "ETag": '"z"' });
    res.end("zbody");
  }, async function (base) {
    var cache = _newHttpCache();
    await b.httpClient.request({ url: base + "/z", cache: cache, allowedProtocols: ALLOW, allowInternal: true });   // MISS + store
    var e = null;
    try { await b.httpClient.request({ url: base + "/z", cache: cache, allowedProtocols: ALLOW, allowInternal: true }); }
    catch (err) { e = err; }
    check("cache: revalidation error without a stale window propagates the error",
      e != null && /ECONNRESET|ECONNREFUSED|socket|REQ_ERROR|RES_ERROR/i.test((e.code || "") + " " + (e.message || "")));
  });

  // Cache MISS whose network fetch follows a redirect (the cache path threads
  // through the redirect-aware request, not the single-shot one).
  await _withServer(function (req, res) {
    if (req.url === "/start") { res.writeHead(302, { Location: "/final" }); res.end(); return; }
    res.writeHead(200, { "Cache-Control": "max-age=60" }); res.end("finalbody");
  }, async function (base) {
    var cache = _newHttpCache();
    var r = await b.httpClient.request({ url: base + "/start", cache: cache, maxRedirects: 3,
      allowedProtocols: ALLOW, allowInternal: true });
    check("cache: MISS follows a redirect through the cache path",
      r.statusCode === 200 && r.body.toString() === "finalbody" && r.headers["x-blamejs-cache"] === "MISS");
  });

  // stale-while-revalidate where the BACKGROUND revalidation itself errors —
  // the stale response is already returned; the failure is swallowed.
  var sawConditional = false;
  await _withServer(function (req, res) {
    if (req.headers["if-none-match"]) { sawConditional = true; req.destroy(); return; }
    res.writeHead(200, { "Cache-Control": "max-age=0, stale-while-revalidate=60", "ETag": '"sw"' });
    res.end("swbody");
  }, async function (base) {
    var cache = _newHttpCache({ revalidateInBackground: true });
    await b.httpClient.request({ url: base + "/s", cache: cache, allowedProtocols: ALLOW, allowInternal: true });   // MISS + store
    var s = await b.httpClient.request({ url: base + "/s", cache: cache, allowedProtocols: ALLOW, allowInternal: true });  // STALE served
    check("cache: swr still serves STALE when the background refresh fails",
      s.headers["x-blamejs-cache"] === "STALE");
    await helpers.waitUntil(function () { return sawConditional; },
      { timeoutMs: 5000, label: "cache swr-error: background revalidation attempted" });
    check("cache: swr background revalidation was attempted (and its error swallowed)", sawConditional);
  });

  // Non-GET method bypasses the cache entirely (network every time).
  var posts = 0;
  await _withServer(function (req, res) { posts += 1; req.resume(); res.writeHead(200); res.end("p"); },
    async function (base) {
      var cache = _newHttpCache();
      await b.httpClient.request({ url: base + "/p", method: "POST", body: "x", cache: cache, allowedProtocols: ALLOW, allowInternal: true });
      await b.httpClient.request({ url: base + "/p", method: "POST", body: "x", cache: cache, allowedProtocols: ALLOW, allowInternal: true });
      check("cache: POST bypasses the cache (both reach upstream)", posts === 2);
    });
  b.httpClient._resetForTest();
}

// ---- HTTP/2 (h2c) extended paths -----------------------------------

async function testH2cExtended() {
  await _withH2cServer(function (stream, headers) {
    stream.on("error", function () {});   // guard server-side stream errors on client reset
    var p = headers[":path"];
    if (p === "/hdr") {
      stream.respond({ ":status": 200,
        "x-saw-custom":     headers["x-custom"] || "",
        "x-saw-connection": headers["connection"] || "absent",   // connection-specific header must be stripped
        "x-saw-ae":         headers["accept-encoding"] || "" });
      stream.end("ok");
      return;
    }
    if (p === "/echo") {
      var chunks = []; stream.on("data", function (c) { chunks.push(c); });
      stream.on("end", function () { stream.respond({ ":status": 200 }); stream.end(Buffer.concat(chunks)); });
      return;
    }
    if (p === "/cookie") { stream.respond({ ":status": 200, "set-cookie": "h2sid=q1; Path=/" }); stream.end("ck"); return; }
    if (p === "/err500") { stream.respond({ ":status": 500 }); stream.end("boom"); return; }
    if (p === "/reset")  { stream.close(http2.constants.NGHTTP2_INTERNAL_ERROR); return; }
    stream.respond({ ":status": 200 }); stream.end("ok");
  }, async function (base) {
    // Custom + connection-specific headers: connection stripped, custom passes,
    // an explicit accept-encoding is preserved (default is identity otherwise).
    var r = await b.httpClient.request({ url: base + "/hdr", preferH2: true,
      headers: { "X-Custom": "cv", "Connection": "keep-alive", "Accept-Encoding": "gzip" },
      allowedProtocols: ALLOW, allowInternal: true });
    check("h2c headers: custom forwarded, connection-specific stripped",
      r.headers["x-saw-custom"] === "cv" && r.headers["x-saw-connection"] === "absent");
    check("h2c headers: explicit accept-encoding preserved", r.headers["x-saw-ae"] === "gzip");

    // Buffer request body → content-length set, body echoed intact.
    var echo = await b.httpClient.request({ url: base + "/echo", preferH2: true, method: "POST",
      body: Buffer.from("h2-buffer-body"), allowedProtocols: ALLOW, allowInternal: true });
    check("h2c buffer body: echoed intact", echo.body.toString() === "h2-buffer-body");

    // Cookie jar records Set-Cookie over h2.
    var jar = b.httpClient.cookieJar.create();
    await b.httpClient.request({ url: base + "/cookie", preferH2: true, jar: jar, allowedProtocols: ALLOW, allowInternal: true });
    check("h2c jar: Set-Cookie recorded from the h2 response",
      /h2sid=q1/.test(jar.cookieHeaderFor(base + "/cookie") || ""));

    // Observer fires request:start + response:end over h2.
    var stages = [];
    await b.httpClient.request({ url: base + "/ok", preferH2: true,
      observer: function (s) { stages.push(s); }, allowedProtocols: ALLOW, allowInternal: true });
    check("h2c observer: request:start + response:end fired",
      stages.indexOf("request:start") !== -1 && stages.indexOf("response:end") !== -1);

    // Stream-mode non-2xx over h2 → HTTP_ERROR with bounded err.body.
    var se = await _expectReject("h2c stream 500: rejects HTTP_ERROR",
      b.httpClient.request({ url: base + "/err500", preferH2: true, responseMode: "stream",
        allowedProtocols: ALLOW, allowInternal: true }), "HTTP_ERROR");
    check("h2c stream 500: err.body carries the error payload",
      se && Buffer.isBuffer(se.body) && /boom/.test(se.body.toString()));

    // Upload throttle stages over h2 (paces the request body).
    var up = await b.httpClient.request({ url: base + "/echo", preferH2: true, method: "POST",
      body: Buffer.alloc(1500, 0x33), maxBytesPerSec: 1024, allowedProtocols: ALLOW, allowInternal: true });
    check("h2c upload throttle: paced body delivered intact", up.body.length === 1500);

    // Download transform that errors → surfaced on the pipeline tail as H2_STREAM_ERROR.
    await _expectReject("h2c download-transform error rejects H2_STREAM_ERROR",
      b.httpClient.request({ url: base + "/ok", preferH2: true,
        downloadTransform: function () {
          return new nodeStream.Transform({ transform: function (c, e, cb) { cb(new Error("xform boom")); } });
        },
        allowedProtocols: ALLOW, allowInternal: true }), "H2_STREAM_ERROR");

    // Piped Readable request body that errors → REQ_BODY_ERROR over h2.
    var badBody = new nodeStream.Readable({ read: function () { this.destroy(new Error("body blew up")); } });
    await _expectReject("h2c upload body stream error rejects REQ_BODY_ERROR",
      b.httpClient.request({ url: base + "/echo", preferH2: true, method: "POST", body: badBody,
        allowedProtocols: ALLOW, allowInternal: true }), "REQ_BODY_ERROR");

    // Server resets the stream → client surfaces the stream error.
    await _expectReject("h2c server stream reset surfaces a stream error",
      b.httpClient.request({ url: base + "/reset", preferH2: true,
        allowedProtocols: ALLOW, allowInternal: true }), /ERR_HTTP2|H2_STREAM_ERROR/);
  });
  b.httpClient._resetForTest();
}

// ---- HTTP/2 (h2c) connect error / idle timeout / in-flight abort ---

async function testH2cTimeoutAbortConnErr() {
  // Connect error — no listener on the captured port.
  var deadPort = await (async function () {
    var s = http.createServer();
    var port = await b.testing.listenOnRandomPort(s, "127.0.0.1");
    await new Promise(function (r) { s.close(function () { r(); }); });
    return port;
  })();
  b.httpClient._resetForTest();
  await _expectReject("h2c: connect to a dead port rejects with a connect error",
    b.httpClient.request({ url: "http://127.0.0.1:" + deadPort + "/x", preferH2: true,
      allowedProtocols: ALLOW, allowInternal: true }), /ECONNREFUSED|REQ_ERROR|H2_/);

  // Idle timeout — server accepts the stream but never responds.
  await _withH2cServer(function (stream) { stream.on("error", function () {}); /* never respond */ },
    async function (base) {
      await _expectReject("h2c: idle timeout rejects ETIMEDOUT",
        b.httpClient.request({ url: base + "/hang", preferH2: true, idleTimeoutMs: 300,
          allowedProtocols: ALLOW, allowInternal: true }), "ETIMEDOUT");
    });
  b.httpClient._resetForTest();

  // In-flight abort — abort after the stream is on the wire.
  var onWire = false;
  await _withH2cServer(function (stream) { stream.on("error", function () {}); onWire = true; /* never respond */ },
    async function (base) {
      var ctrl = new AbortController();
      var p = b.httpClient.request({ url: base + "/hang", preferH2: true, signal: ctrl.signal,
        allowedProtocols: ALLOW, allowInternal: true });
      await helpers.waitUntil(function () { return onWire; },
        { timeoutMs: 5000, label: "h2c abort: stream reached the server" });
      ctrl.abort();
      await _expectReject("h2c: in-flight abort rejects ABORT", p, "ABORT");
    });
  b.httpClient._resetForTest();
}

// ---- h1 in-flight abort with the abort listener already attached ---

async function testH1AbortOnWire() {
  var onWire = false;
  await _withServer(function (req, res) { onWire = true; void res; /* hold the request open */ },
    async function (base) {
      var ctrl = new AbortController();
      var p = b.httpClient.request({ url: base + "/hang", signal: ctrl.signal,
        allowedProtocols: ALLOW, allowInternal: true });
      await helpers.waitUntil(function () { return onWire; },
        { timeoutMs: 5000, label: "h1 abort: request reached the server" });
      ctrl.abort();
      await _expectReject("h1: in-flight abort (listener attached) rejects ABORT", p, "ABORT");
    });
}

// ---- default-port origin keys (unit) -------------------------------

function testDefaultPortKeys() {
  // A portless URL exercises the IANA default-port fallback inside the
  // origin-key builder (443 for https, 80 for http). No transport is
  // cached for these hosts, so the lookup is a pure parse + map miss.
  check("origin key: portless https resolves without a cached transport",
    b.httpClient._getCachedTransportKind("https://origin.invalid/") === null);
  check("origin key: portless http resolves without a cached transport",
    b.httpClient._getCachedTransportKind("http://origin.invalid/") === null);
}

// ---- throttled/transformed upload body error (h1 + h2) -------------

async function testThrottledUploadBodyError() {
  // h1: an erroring body routed through the throttle stages → REQ_BODY_ERROR.
  await _withServer(function (req) { req.on("data", function () {}); req.on("error", function () {}); },
    async function (base) {
      var bad = new nodeStream.Readable({ read: function () { this.destroy(new Error("throttled body blew up")); } });
      await _expectReject("throttle h1: erroring upload body rejects REQ_BODY_ERROR",
        b.httpClient.request({ url: base + "/u", method: "POST", body: bad, maxBytesPerSec: 1024,
          allowedProtocols: ALLOW, allowInternal: true }), "REQ_BODY_ERROR");
    });

  // h2: same, over the h2 stream upload stages.
  await _withH2cServer(function (stream) { stream.on("error", function () {}); stream.on("data", function () {}); },
    async function (base) {
      var bad = new nodeStream.Readable({ read: function () { this.destroy(new Error("throttled body blew up")); } });
      await _expectReject("throttle h2: erroring upload body rejects REQ_BODY_ERROR",
        b.httpClient.request({ url: base + "/u", method: "POST", body: bad, preferH2: true, maxBytesPerSec: 1024,
          allowedProtocols: ALLOW, allowInternal: true }), "REQ_BODY_ERROR");
    });
  b.httpClient._resetForTest();
}

// ---- h2 pre-aborted signal + h2 transport teardown -----------------

async function testH2PreAbortAndTeardown() {
  // Scope 1: warm h2, pre-aborted signal, then _resetForTest tears down the
  // live h2 session (its per-origin key isn't re-warmed inside this scope, so
  // no old-session `close` can race a fresh entry).
  await _withH2cServer(function (stream) { stream.on("error", function () {}); stream.respond({ ":status": 200 }); stream.end("ok"); },
    async function (base) {
      await b.httpClient.request({ url: base + "/x", preferH2: true, allowedProtocols: ALLOW, allowInternal: true });
      check("h2 teardown: transport cached as h2 after the first request",
        b.httpClient._getCachedTransportKind(base + "/x") === "h2");

      // Pre-aborted signal on a warm h2 origin → rejects before any stream.
      var ac = new AbortController();
      ac.abort();
      await _expectReject("h2 pre-aborted signal: rejects ABORT",
        b.httpClient.request({ url: base + "/x", preferH2: true, signal: ac.signal,
          allowedProtocols: ALLOW, allowInternal: true }), "ABORT");

      b.httpClient._resetForTest();   // covers _resetForTest's live-h2-session teardown branch
      check("h2 teardown: _resetForTest cleared the live h2 session",
        b.httpClient._getCachedTransportCount() === 0);
    });

  // Scope 2 (fresh origin): warm h2, then configurePool tears down the live
  // h2 session + clears the cache.
  await _withH2cServer(function (stream) { stream.on("error", function () {}); stream.respond({ ":status": 200 }); stream.end("ok"); },
    async function (base) {
      await b.httpClient.request({ url: base + "/y", preferH2: true, allowedProtocols: ALLOW, allowInternal: true });
      check("h2 teardown: transport cached before configurePool",
        b.httpClient._getCachedTransportKind(base + "/y") === "h2");
      b.httpClient.configurePool({ maxSockets: 8 });
      check("h2 teardown: configurePool cleared the h2 transport",
        b.httpClient._getCachedTransportCount() === 0);
      b.httpClient.configurePool({
        maxSockets:     b.httpClient.DEFAULT_AGENT_OPTS.maxSockets,
        maxFreeSockets: b.httpClient.DEFAULT_AGENT_OPTS.maxFreeSockets,
        keepAliveMsecs: b.httpClient.DEFAULT_AGENT_OPTS.keepAliveMsecs,
        keepAlive:      b.httpClient.DEFAULT_AGENT_OPTS.keepAlive,
        scheduling:     b.httpClient.DEFAULT_AGENT_OPTS.scheduling,
      });
    });
  b.httpClient._resetForTest();
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
  }, { timeoutMs: 5000, label: "http-client: TCP handle drain after _resetForTest" });
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
    testPinnedLookupContract();
    await testMultipartBuildBranches();
    await testJarCookieMerge();
    await testStreamModeHttpError();
    await testThrottleAndTransformH1();
    await testUploadProgressPipedBody();
    await testDownloadTransformErrorH1();
    await testDownloadStreamLifecycle();
    await testUploadMultipartStreamLifecycle();
    await testCachePaths();
    await testH2cExtended();
    await testH2cTimeoutAbortConnErr();
    await testH1AbortOnWire();
    testDefaultPortKeys();
    await testThrottledUploadBodyError();
    await testH2PreAbortAndTeardown();
  } finally {
    await _drainTcpHandles();
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK http-client — " + helpers.getChecks() + " checks"); })
       .catch(function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); });
}
