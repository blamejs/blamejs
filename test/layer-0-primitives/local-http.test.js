// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// b.localHttp — SSRF-safe HTTP over a local transport (unix socket / Windows
// named pipe / loopback TCP+token).

var helpers = require("../helpers");
var check = helpers.check;
var b = helpers.b;
var http = require("node:http");
var os = require("node:os");
var nodePath = require("node:path");
var fs = require("node:fs");

// A local socket path that works on the host OS: a Windows named pipe, else a
// Unix domain socket under the temp dir.
var _n = 0;
function _localPath() {
  _n += 1;
  if (process.platform === "win32") return "\\\\.\\pipe\\blamejs-lh-" + process.pid + "-" + _n;
  var p = nodePath.join(os.tmpdir(), "blamejs-lh-" + process.pid + "-" + _n + ".sock");
  try { fs.unlinkSync(p); } catch (_e) { /* not present */ }
  return p;
}

// Start an http server on a local socket path; returns { path, server, seen() }.
function _startSocketServer(handler) {
  return new Promise(function (resolve) {
    var path = _localPath();
    var last = null;
    var server = http.createServer(function (req, res) {
      last = { method: req.method, url: req.url, headers: req.headers };
      var chunks = [];
      req.on("data", function (c) { chunks.push(c); });
      req.on("end", function () { last.body = Buffer.concat(chunks).toString("utf8"); handler(req, res, last); });
    });
    server.listen(path, function () { resolve({ path: path, server: server, seen: function () { return last; } }); });
  });
}

async function testSocketRoundtrip() {
  var srv = await _startSocketServer(function (req, res, seen) {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ ok: true, saw: seen.headers.host }));
  });
  try {
    var d = b.localHttp.create({ socketPath: srv.path, hostHeader: "local-tailscaled.sock" });
    var r = await d.get("/localapi/v0/status");
    check("localHttp socket: 200 + typed body", r.statusCode === 200 && Buffer.isBuffer(r.body));
    check("localHttp socket: json() parses", r.json().ok === true);
    check("localHttp socket: text() decodes", /"ok":true/.test(r.text()));
    check("localHttp socket: caller Host reaches the daemon", srv.seen().headers.host === "local-tailscaled.sock");
    check("localHttp socket: setHost:false didn't add a second host", srv.seen().headers.host === "local-tailscaled.sock");
  } finally { srv.server.close(); }
}

async function testOriginRefererStripped() {
  var srv = await _startSocketServer(function (req, res) { res.writeHead(204); res.end(); });
  try {
    var d = b.localHttp.create({ socketPath: srv.path, hostHeader: "d",
      defaultHeaders: { origin: "https://evil.example", "x-keep": "1" } });
    await d.request({ method: "GET", path: "/x", headers: { referer: "https://evil.example" } });
    var h = srv.seen().headers;
    check("localHttp: Origin is never forwarded to a local daemon", h.origin === undefined);
    check("localHttp: Referer is never forwarded",                  h.referer === undefined);
    check("localHttp: other default/request headers pass through",  h["x-keep"] === "1");
  } finally { srv.server.close(); }
}

async function testPostJsonAndBearer() {
  var srv = await _startSocketServer(function (req, res, seen) {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ echo: seen.body, ct: seen.headers["content-type"], auth: seen.headers.authorization }));
  });
  try {
    var d = b.localHttp.create({ socketPath: srv.path, hostHeader: "d", bearerToken: "sekret" });
    var r = await d.postJson("/submit", { hello: "world" });
    var out = r.json();
    check("localHttp postJson: body serialized",         out.echo === '{"hello":"world"}');
    check("localHttp postJson: content-type application/json", out.ct === "application/json");
    check("localHttp: bearerToken sent as Authorization",  out.auth === "Bearer sekret");
  } finally { srv.server.close(); }
}

async function testLoopbackTcp() {
  var server = http.createServer(function (req, res) {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ host: req.headers.host }));
  });
  await new Promise(function (r) { server.listen(0, "127.0.0.1", r); });
  try {
    var d = b.localHttp.create({ host: "127.0.0.1", port: server.address().port, hostHeader: "tcp-daemon" });
    var r = await d.get("/status");
    check("localHttp loopback-tcp: 200 + Host honoured", r.statusCode === 200 && r.json().host === "tcp-daemon");
  } finally { server.close(); }
}

async function testResponseCap() {
  var srv = await _startSocketServer(function (req, res) {
    res.writeHead(200);
    res.end(Buffer.alloc(4096, 0x61));   // 4 KiB
  });
  try {
    var d = b.localHttp.create({ socketPath: srv.path, hostHeader: "d", maxResponseBytes: 1024 });
    var e = null;
    try { await d.get("/big"); } catch (err) { e = err; }
    check("localHttp: an over-cap response is refused", e && e.code === "local-http/response-too-large");
  } finally { srv.server.close(); }
}

async function testTimeout() {
  var srv = await _startSocketServer(function () { /* never responds */ });
  try {
    var d = b.localHttp.create({ socketPath: srv.path, hostHeader: "d", timeoutMs: 200 });
    var e = null;
    try { await d.get("/hang"); } catch (err) { e = err; }
    check("localHttp: a stalled daemon times out", e && e.code === "local-http/timeout");
  } finally { srv.server.close(); }
}

async function testOneShotRequest() {
  var srv = await _startSocketServer(function (req, res) { res.writeHead(200); res.end("pong"); });
  try {
    var r = await b.localHttp.request({ socketPath: srv.path, hostHeader: "d", path: "/ping" });
    check("localHttp.request one-shot: 200 + body", r.statusCode === 200 && r.text() === "pong");
  } finally { srv.server.close(); }
}

async function testBodyVariantsAndCustomHeaders() {
  var srv = await _startSocketServer(function (req, res, seen) {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ body: seen.body, xc: seen.headers["x-custom"] }));
  });
  try {
    var d = b.localHttp.create({ socketPath: srv.path, hostHeader: "d" });
    // A Buffer request body is sent verbatim.
    var rb = await d.request({ method: "POST", path: "/x", body: Buffer.from("raw-bytes") });
    check("localHttp: a Buffer request body is sent", rb.json().body === "raw-bytes");
    // A non-Buffer/string body is refused.
    var eb = null;
    try { await d.request({ method: "POST", path: "/x", body: 12345 }); } catch (e) { eb = e; }
    check("localHttp: a non-Buffer/string body is refused", eb && eb.code === "local-http/bad-body");
    // postJson merges caller headers with the JSON content-type.
    var rp = await d.postJson("/x", { a: 1 }, { headers: { "x-custom": "yes" } });
    check("localHttp postJson: caller headers merge with content-type", rp.json().xc === "yes");
  } finally { srv.server.close(); }
}

async function testTransportError() {
  var missing = process.platform === "win32"
    ? "\\\\.\\pipe\\blamejs-lh-missing-" + process.pid
    : nodePath.join(os.tmpdir(), "blamejs-lh-missing-" + process.pid + ".sock");
  var d = b.localHttp.create({ socketPath: missing, hostHeader: "d", timeoutMs: 2000 });
  var e = null;
  try { await d.get("/x"); } catch (err) { e = err; }
  check("localHttp: a transport error (no such socket) is surfaced",
    e && (e.code === "local-http/request-error" || e.code === "local-http/timeout"));
}

function testValidation() {
  function threw(fn) { try { fn(); return null; } catch (e) { return e; } }
  check("localHttp.create: neither transport refused",
    threw(function () { b.localHttp.create({}); }).code === "local-http/bad-transport");
  check("localHttp.create: both transports refused",
    threw(function () { b.localHttp.create({ socketPath: "/x", host: "127.0.0.1", port: 1 }); }).code === "local-http/bad-transport");
  check("localHttp.create: a non-loopback host is refused (SSRF-safe)",
    threw(function () { b.localHttp.create({ host: "10.0.0.5", port: 80 }); }).code === "local-http/non-loopback-host");
  check("localHttp.create: a public host is refused",
    threw(function () { b.localHttp.create({ host: "example.com", port: 80 }); }).code === "local-http/non-loopback-host");
  check("localHttp.create: a non-string host is refused",
    threw(function () { b.localHttp.create({ host: 123, port: 80 }); }).code === "local-http/non-loopback-host");
  check("localHttp.create: a trailing-dot loopback is accepted (localhost.)",
    (function () { try { b.localHttp.create({ host: "localhost.", port: 80 }); return true; } catch (_e) { return false; } })());
  check("localHttp.create: 127.x loopback accepted",
    (function () { try { b.localHttp.create({ host: "127.0.0.5", port: 80 }); return true; } catch (_e) { return false; } })());
  check("localHttp.create: an empty socketPath is refused",
    threw(function () { b.localHttp.create({ socketPath: "" }); }).code === "local-http/bad-socket-path");
  check("localHttp.create: an empty hostHeader is refused",
    threw(function () { b.localHttp.create({ socketPath: "/x", hostHeader: "" }); }).code === "local-http/bad-host-header");
  check("localHttp.create: a bad port is refused",
    threw(function () { b.localHttp.create({ host: "127.0.0.1", port: 70000 }); }).code === "local-http/bad-port");
  check("localHttp.create: a non-object defaultHeaders is refused",
    threw(function () { b.localHttp.create({ socketPath: "/x", defaultHeaders: "nope" }); }).code === "local-http/bad-default-headers");
  check("localHttp.create: a null defaultHeaders is refused",
    threw(function () { b.localHttp.create({ socketPath: "/x", defaultHeaders: null }); }).code === "local-http/bad-default-headers");
  check("localHttp.create: a bad timeoutMs is refused",
    threw(function () { b.localHttp.create({ socketPath: "/x", timeoutMs: -1 }); }) !== null);
  check("localHttp.create: a bad maxResponseBytes is refused",
    threw(function () { b.localHttp.create({ socketPath: "/x", maxResponseBytes: 0 }); }) !== null);
  check("localHttp.create: non-object opts refused",
    threw(function () { b.localHttp.create(null); }) !== null);
  check("localHttp errors are LocalHttpError",
    threw(function () { throw new b.localHttp.LocalHttpError("local-http/x", "y"); }) instanceof b.localHttp.LocalHttpError);
}

async function run() {
  await testSocketRoundtrip();
  await testOriginRefererStripped();
  await testPostJsonAndBearer();
  await testLoopbackTcp();
  await testResponseCap();
  await testTimeout();
  await testOneShotRequest();
  await testBodyVariantsAndCustomHeaders();
  await testTransportError();
  testValidation();
  // bad request path (async refusal); also covers request() called with no opts.
  var client = b.localHttp.create({ socketPath: "/x.sock", hostHeader: "d" });
  var pe = null;
  try { await client.request({ path: "no-slash" }); } catch (e) { pe = e; }
  check("localHttp.request: a path without a leading / is refused", pe && pe.code === "local-http/bad-path");
  var ne = null;
  try { await client.request(); } catch (e) { ne = e; }
  check("localHttp.request: no opts → bad-path (defaults applied)", ne && ne.code === "local-http/bad-path");
}

if (require.main === module) {
  run().catch(function (e) { console.error(e); process.exit(1); });
}
module.exports = { run: run };
