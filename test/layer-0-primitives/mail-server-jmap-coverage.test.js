// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.mail.server.jmap — error / defensive / adversarial branch coverage driven
 * over REAL localhost connections. JMAP is HTTP-mounted (RFC 8620), so the
 * Express-style handlers (apiHandler / sessionHandler / discoveryHandler /
 * eventSourceHandler / uploadHandler / downloadHandler) are mounted on a real
 * node:http server and driven with genuine HTTP requests + a real WebSocket
 * client (b.wsClient) for the RFC 8887 webSocketHandler. The sibling
 * mail-server-jmap.test.js covers opts validation + the mock-req/res happy
 * paths; this file drives the wrong-state / malformed / backend-failure /
 * resource-limit / cross-tenant refusals over the wire.
 *
 * Run standalone: `node test/layer-0-primitives/mail-server-jmap-coverage.test.js`
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

var nodeHttp = require("node:http");

// ---- global handle tracking (WS clients + upgrade sockets + servers) ----
var _httpServers = [];
var _wsClients   = [];
var _wsSockets   = [];

function _actorFrom(req, cfg) {
  if (cfg.noActor) return null;
  var h = req.headers["x-actor"];
  if (h === "none")   return null;
  if (h === "idonly") return { id: "uid-9" };
  if (h === "empty")  return {};
  return cfg.actor || { id: "u1", username: "alice" };
}

// Mount every JMAP handler on a real node:http server. Body-consuming
// apiHandler reads the request body first (simulating b.middleware.bodyParser);
// the streaming upload/download/eventsource handlers own their own req stream.
function _startHttp(jmap, cfg) {
  cfg = cfg || {};
  var server = nodeHttp.createServer(function (req, res) {
    req.user = _actorFrom(req, cfg);
    if (cfg.params) req.params = cfg.params;
    var path = String(req.url || "").split("?")[0];
    if (cfg.forceDownload) { jmap.downloadHandler(req, res); return; }
    if (cfg.forceUpload)   { jmap.uploadHandler(req, res); return; }
    if (path === "/jmap/session")      { jmap.sessionHandler(req, res); return; }
    if (path === "/.well-known/jmap")  { jmap.discoveryHandler(req, res); return; }
    if (path === "/jmap/eventsource")  { jmap.eventSourceHandler(req, res); return; }
    if (path.indexOf("/jmap/upload/") === 0)   { jmap.uploadHandler(req, res); return; }
    if (path.indexOf("/jmap/download/") === 0) { jmap.downloadHandler(req, res); return; }
    if (path === "/jmap/api") {
      var chunks = [];
      req.on("data", function (c) { chunks.push(c); });
      req.on("end", function () {
        var raw = Buffer.concat(chunks).toString("utf8");
        // Leave req.body UNDEFINED on an empty body so the "body missing"
        // branch is reachable; otherwise hand apiHandler the parsed object.
        if (raw.length > 0) { try { req.body = JSON.parse(raw); } catch (_e) { req.body = raw; } }
        jmap.apiHandler(req, res);
      });
      return;
    }
    res.statusCode = 404; res.end();
  });
  server.on("upgrade", function (req, socket, head) {
    _wsSockets.push(socket);
    req.user = _actorFrom(req, cfg);
    jmap.webSocketHandler(req, socket, head);
  });
  _httpServers.push(server);
  return new Promise(function (resolve) {
    server.listen(0, "127.0.0.1", function () { resolve({ server: server, port: server.address().port }); });
  });
}

function _stop(server) {
  return new Promise(function (resolve) { try { server.close(function () { resolve(); }); } catch (_e) { resolve(); } });
}

// One HTTP request → { status, headers, body(string) }. agent:false so each
// request uses a fresh socket that closes (no keep-alive handle leak).
function _req(port, opts) {
  opts = opts || {};
  return new Promise(function (resolve, reject) {
    var r = nodeHttp.request({
      host: "127.0.0.1", port: port, method: opts.method || "GET",
      path: opts.path, headers: opts.headers || {}, agent: false,
    }, function (res) {
      var chunks = [];
      res.on("data", function (c) { chunks.push(c); });
      res.on("end", function () {
        resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString("utf8") });
      });
    });
    r.on("error", reject);
    if (opts.body != null) r.write(opts.body);
    r.end();
  });
}

// Tolerant request — resolves { refused:true } if the socket resets (the
// oversize-upload responder writes 413 then destroys the request stream, a
// respond-then-reset race). Either a 413 read OR a reset proves refusal.
function _reqSafe(port, opts) {
  return _req(port, opts).then(
    function (r) { return r; },
    function (_e) { return { refused: true, status: 0, headers: {}, body: "" }; }
  );
}

// Open an SSE / streaming response; resolve on the response head so we can
// read status + a live-growing buffer, then abort.
function _openSse(port, path, headers) {
  return new Promise(function (resolve, reject) {
    var r = nodeHttp.request({
      host: "127.0.0.1", port: port, method: "GET", path: path, headers: headers || {}, agent: false,
    }, function (res) {
      var buf = ""; var closed = false;
      res.on("data",  function (c) { buf += c.toString("utf8"); });
      res.on("end",   function () { closed = true; });
      res.on("close", function () { closed = true; });
      res.on("error", function () { closed = true; });
      resolve({
        status: res.statusCode, headers: res.headers,
        read: function () { return buf; },
        isClosed: function () { return closed; },
        abort: function () { try { r.destroy(); } catch (_e) { /* best-effort */ } },
      });
    });
    r.on("error", reject);
    r.end();
  });
}

function _wsConnect(port, opts) {
  var client = b.wsClient.connect("ws://127.0.0.1:" + port + "/jmap/ws",
    Object.assign({ subprotocols: ["jmap"], reconnect: false, audit: false, allowInternal: true }, opts || {}));
  _wsClients.push(client);
  return client;
}

var DEFAULT_ACCOUNTS = async function () {
  return { primaryAccounts: { core: "A1" }, accounts: { A1: { name: "tenant-a" } } };
};

// ==========================================================================
// 1. sessionHandler (RFC 8620 §2) — the sibling suite has NO session tests
// ==========================================================================
async function testSessionHandler() {
  // 1a. default caps inject the websocket transport (no operator ws cap)
  var jmap = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {} },
    accountsFor: DEFAULT_ACCOUNTS,
    methods: {},
  });
  var s = await _startHttp(jmap, {});
  try {
    var r = await _req(s.port, { path: "/jmap/session" });
    check("session → 200", r.status === 200);
    check("session content-type json", /application\/json/.test(r.headers["content-type"] || ""));
    var sess = JSON.parse(r.body);
    check("session advertises default websocket cap",
      sess.capabilities["urn:ietf:params:jmap:websocket"] &&
      sess.capabilities["urn:ietf:params:jmap:websocket"].url === "/jmap/ws");
    check("session core cap present", !!sess.capabilities["urn:ietf:params:jmap:core"]);
    check("session accounts echoed", sess.accounts.A1 && sess.accounts.A1.name === "tenant-a");
    check("session primaryAccounts echoed", sess.primaryAccounts.core === "A1");
    check("session apiUrl default", sess.apiUrl === "/jmap/api");
    check("session username from actor.username", sess.username === "alice");
    check("session state present", typeof sess.state === "string" && sess.state.length > 0);

    // 1b. username falls back to actor.id, then "unknown"
    var rId = await _req(s.port, { path: "/jmap/session", headers: { "x-actor": "idonly" } });
    check("session username falls back to actor.id", JSON.parse(rId.body).username === "uid-9");
    var rEmpty = await _req(s.port, { path: "/jmap/session", headers: { "x-actor": "empty" } });
    check("session username falls back to 'unknown'", JSON.parse(rEmpty.body).username === "unknown");

    // 1c. unauthenticated → 401 forbidden
    var rNo = await _req(s.port, { path: "/jmap/session", headers: { "x-actor": "none" } });
    check("session unauth → 401", rNo.status === 401);
    check("session unauth → forbidden type", /jmap:error:forbidden/.test(rNo.body));
  } finally { await _stop(s.server); }

  // 1d. operator-supplied websocket cap → NOT overwritten + urlEndpointResolution set
  var jmapWs = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {} },
    accountsFor: DEFAULT_ACCOUNTS,
    methods: {},
    serverCapabilities: { "urn:ietf:params:jmap:websocket": { url: "/operator/ws", supportsPush: false } },
  });
  var sWs = await _startHttp(jmapWs, {});
  try {
    var rw = await _req(sWs.port, { path: "/jmap/session" });
    var sessw = JSON.parse(rw.body);
    check("session keeps operator websocket cap",
      sessw.capabilities["urn:ietf:params:jmap:websocket"].url === "/operator/ws");
    check("session urlEndpointResolution present when operator ws cap set",
      sessw.urlEndpointResolution && sessw.urlEndpointResolution.useEndpoint === "/jmap/ws");
  } finally { await _stop(sWs.server); }

  // 1e. accountsFor returns null → defaults; and accountsFor rejects → 500
  var jmapNull = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {} },
    accountsFor: async function () { return null; },
    methods: {},
  });
  var sNull = await _startHttp(jmapNull, {});
  try {
    var rn = await _req(sNull.port, { path: "/jmap/session" });
    check("session accountInfo null → 200 with empty accounts",
      rn.status === 200 && JSON.stringify(JSON.parse(rn.body).accounts) === "{}");
  } finally { await _stop(sNull.server); }

  var jmapThrow = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {} },
    accountsFor: async function () { throw new Error("accountsFor boom"); },
    methods: {},
  });
  var sThrow = await _startHttp(jmapThrow, {});
  try {
    var rt = await _req(sThrow.port, { path: "/jmap/session" });
    check("session accountsFor throw → 500", rt.status === 500);
    check("session accountsFor throw → serverFail", /jmap:error:serverFail/.test(rt.body));
  } finally { await _stop(sThrow.server); }
}

// ==========================================================================
// 2. discoveryHandler (RFC 8620 §2.2) — 302 redirect
// ==========================================================================
async function testDiscoveryHandler() {
  var jmap = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {} }, accountsFor: DEFAULT_ACCOUNTS, methods: {},
  });
  var s = await _startHttp(jmap, {});
  try {
    var r = await _req(s.port, { path: "/.well-known/jmap" });
    check("discovery → 302", r.status === 302);
    check("discovery → Location /jmap/session", r.headers["location"] === "/jmap/session");
  } finally { await _stop(s.server); }

  var jmapCustom = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {} }, accountsFor: DEFAULT_ACCOUNTS, methods: {},
    sessionUrl: "/custom/session",
  });
  var sc = await _startHttp(jmapCustom, {});
  try {
    var rc = await _req(sc.port, { path: "/.well-known/jmap" });
    check("discovery custom sessionUrl honored", rc.headers["location"] === "/custom/session");
  } finally { await _stop(sc.server); }
}

// ==========================================================================
// 3. apiHandler (RFC 8620 §3.3) over HTTP — refusal / error status mapping
// ==========================================================================
async function testApiHandler() {
  var jmap = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {} },
    accountsFor: DEFAULT_ACCOUNTS,
    methods: {
      "Core/echo": async function (actor, args) { return { hi: args.hi }; },
      "Op/err":    async function () { return { type: "urn:ietf:params:jmap:error:invalidArguments", description: "operator says no" }; },
    },
  });
  var s = await _startHttp(jmap, {});
  try {
    // 3a. body missing (bodyParser not run) → 400
    var rNoBody = await _req(s.port, { method: "POST", path: "/jmap/api" });
    check("api missing body → 400", rNoBody.status === 400);
    check("api missing body → invalidArguments", /request body missing/.test(rNoBody.body));

    // 3b. happy 200
    var rOk = await _req(s.port, {
      method: "POST", path: "/jmap/api", headers: { "content-type": "application/json" },
      body: JSON.stringify({ using: [], methodCalls: [["Core/echo", { hi: 7 }, "c0"]] }),
    });
    check("api happy → 200", rOk.status === 200);
    var okBody = JSON.parse(rOk.body);
    check("api happy → result echoed", okBody.methodResponses[0][1].hi === 7);
    check("api happy → sessionState", typeof okBody.sessionState === "string");

    // 3c. guard refusal (no `using`) → 400 invalidArguments
    var rBad = await _req(s.port, {
      method: "POST", path: "/jmap/api", headers: { "content-type": "application/json" },
      body: JSON.stringify({ methodCalls: [["Core/echo", {}, "c0"]] }),
    });
    check("api guard-refusal → 400", rBad.status === 400);
    check("api guard-refusal → invalidArguments", /jmap:error:invalidArguments/.test(rBad.body));

    // 3d. no actor → forbidden mapped to 401
    var rForbidden = await _req(s.port, {
      method: "POST", path: "/jmap/api", headers: { "content-type": "application/json", "x-actor": "none" },
      body: JSON.stringify({ using: [], methodCalls: [["Core/echo", {}, "c0"]] }),
    });
    check("api no-actor → 401", rForbidden.status === 401);
    check("api no-actor → forbidden", /jmap:error:forbidden/.test(rForbidden.body));

    // 3e. operator-emitted error shape → preserved (200, error inside)
    var rOpErr = await _req(s.port, {
      method: "POST", path: "/jmap/api", headers: { "content-type": "application/json" },
      body: JSON.stringify({ using: [], methodCalls: [["Op/err", {}, "c0"]] }),
    });
    check("api operator-error-shape → 200", rOpErr.status === 200);
    var opErrBody = JSON.parse(rOpErr.body);
    check("api operator-error-shape preserved",
      opErrBody.methodResponses[0][0] === "error" &&
      opErrBody.methodResponses[0][1].type === "urn:ietf:params:jmap:error:invalidArguments");
  } finally { await _stop(s.server); }

  // 3f. accountsFor throws inside dispatch → serverFail refusal (mapped 400)
  var jmapAcctThrow = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {} },
    accountsFor: async function () { throw new Error("acct boom"); },
    methods: { "Core/echo": async function () { return {}; } },
  });
  var sat = await _startHttp(jmapAcctThrow, {});
  try {
    var rat = await _req(sat.port, {
      method: "POST", path: "/jmap/api", headers: { "content-type": "application/json" },
      body: JSON.stringify({ using: [], methodCalls: [["Core/echo", {}, "c0"]] }),
    });
    check("api accountsFor-throw → 400 (serverFail refusal)", rat.status === 400);
    check("api accountsFor-throw → serverFail", /jmap:error:serverFail/.test(rat.body));
    check("api accountsFor-throw → account authorization unavailable",
      /account authorization unavailable/.test(rat.body));
  } finally { await _stop(sat.server); }
}

// ==========================================================================
// 4. Back-reference resolution + JSON-Pointer edge cases (RFC 8620 §3.7 /
//    RFC 6901) — driven through apiHandler over HTTP
// ==========================================================================
async function testBackRefsAndPointer() {
  var jmap = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {} },
    accountsFor: DEFAULT_ACCOUNTS,
    methods: {
      "First/get":  async function () {
        return { list: [{ id: "x1" }, { id: "x2" }], name: "n", s: "str", "a/b": "slash", "c~d": "tilde" };
      },
      "Second/use": async function (actor, args) { return { received: args }; },
    },
  });
  var s = await _startHttp(jmap, {});
  try {
    // 4a. pointer edges that SUCCEED (whole result / array-* / escapes / nested)
    var rv = await _req(s.port, {
      method: "POST", path: "/jmap/api", headers: { "content-type": "application/json" },
      body: JSON.stringify({ using: [], methodCalls: [
        ["First/get", {}, "c0"],
        ["Second/use", {
          "#whole": { resultOf: "c0", name: "First/get", path: "" },
          "#arr":   { resultOf: "c0", name: "First/get", path: "/list/*" },
          "#first": { resultOf: "c0", name: "First/get", path: "/list/0/id" },
          "#sl":    { resultOf: "c0", name: "First/get", path: "/a~1b" },
          "#ti":    { resultOf: "c0", name: "First/get", path: "/c~0d" },
        }, "c1"],
      ] }),
    });
    var got = JSON.parse(rv.body).methodResponses[1][1].received;
    check("backref path='' resolves whole result", got.whole && got.whole.name === "n");
    check("backref path='/list/*' resolves array", Array.isArray(got.arr) && got.arr.length === 2);
    check("backref path='/list/0/id' resolves scalar", got.first === "x1");
    check("backref ~1 escape → '/'", got.sl === "slash");
    check("backref ~0 escape → '~'", got.ti === "tilde");

    // 4b. pointer into a NON-object (string) → undefined → invalidResultReference
    var rNon = await _req(s.port, {
      method: "POST", path: "/jmap/api", headers: { "content-type": "application/json" },
      body: JSON.stringify({ using: [], methodCalls: [
        ["First/get", {}, "c0"],
        ["Second/use", { "#x": { resultOf: "c0", name: "First/get", path: "/s/foo" } }, "c1"],
      ] }),
    });
    check("backref into non-object → invalidResultReference",
      JSON.parse(rNon.body).methodResponses[1][1].type === "urn:ietf:params:jmap:error:invalidResultReference");

    // 4c. malformed back-ref value (missing `path`) → invalidResultReference
    var rMissing = await _req(s.port, {
      method: "POST", path: "/jmap/api", headers: { "content-type": "application/json" },
      body: JSON.stringify({ using: [], methodCalls: [
        ["First/get", {}, "c0"],
        ["Second/use", { "#bad": { resultOf: "c0", name: "First/get" } }, "c1"],
      ] }),
    });
    check("backref missing path → invalidResultReference",
      JSON.parse(rMissing.body).methodResponses[1][1].type === "urn:ietf:params:jmap:error:invalidResultReference");

    // 4d. back-ref value is an ARRAY (not the { resultOf, name, path } object)
    var rArr = await _req(s.port, {
      method: "POST", path: "/jmap/api", headers: { "content-type": "application/json" },
      body: JSON.stringify({ using: [], methodCalls: [
        ["First/get", {}, "c0"],
        ["Second/use", { "#bad": [1, 2, 3] }, "c1"],
      ] }),
    });
    check("backref value-is-array → invalidResultReference",
      JSON.parse(rArr.body).methodResponses[1][1].type === "urn:ietf:params:jmap:error:invalidResultReference");

    // 4e. back-ref name mismatch (prior clientId produced a different method)
    var rName = await _req(s.port, {
      method: "POST", path: "/jmap/api", headers: { "content-type": "application/json" },
      body: JSON.stringify({ using: [], methodCalls: [
        ["First/get", {}, "c0"],
        ["Second/use", { "#bad": { resultOf: "c0", name: "Other/get", path: "/list/0/id" } }, "c1"],
      ] }),
    });
    check("backref name-mismatch → invalidResultReference",
      JSON.parse(rName.body).methodResponses[1][1].type === "urn:ietf:params:jmap:error:invalidResultReference");

    // 4e2. back-ref array index is non-numeric → undefined → invalidResultReference
    var rNaN = await _req(s.port, {
      method: "POST", path: "/jmap/api", headers: { "content-type": "application/json" },
      body: JSON.stringify({ using: [], methodCalls: [
        ["First/get", {}, "c0"],
        ["Second/use", { "#bad": { resultOf: "c0", name: "First/get", path: "/list/notanum/id" } }, "c1"],
      ] }),
    });
    check("backref non-numeric array index → invalidResultReference",
      JSON.parse(rNaN.body).methodResponses[1][1].type === "urn:ietf:params:jmap:error:invalidResultReference");

    // 4f. unknown method → unknownMethod
    var rUnknown = await _req(s.port, {
      method: "POST", path: "/jmap/api", headers: { "content-type": "application/json" },
      body: JSON.stringify({ using: [], methodCalls: [["Nope/nope", {}, "c0"]] }),
    });
    check("unknown method → unknownMethod",
      JSON.parse(rUnknown.body).methodResponses[0][1].type === "urn:ietf:params:jmap:error:unknownMethod");
  } finally { await _stop(s.server); }
}

// ==========================================================================
// 5. uploadHandler (RFC 8620 §6.1) over HTTP
// ==========================================================================
async function testUploadHandler() {
  // 5a. happy 201 + meta defaults (uploadBlob returns no type/size → defaults)
  var jmap = b.mail.server.jmap.create({
    mailStore: {
      appendMessage: function () {},
      uploadBlob: function (actor, accountId, type, bytes) { return Promise.resolve({ blobId: "blob_1" }); },
    },
    accountsFor: DEFAULT_ACCOUNTS, methods: {},
  });
  var s = await _startHttp(jmap, {});
  try {
    var rOk = await _req(s.port, {
      method: "POST", path: "/jmap/upload/A1", headers: { "content-type": "text/plain" }, body: "hello",
    });
    check("upload happy → 201", rOk.status === 201);
    var meta = JSON.parse(rOk.body);
    check("upload meta type defaults to content-type", meta.type === "text/plain");
    check("upload meta size defaults to byte length", meta.size === 5);
    check("upload echoes accountId", meta.accountId === "A1");

    // 5b. default content-type when no header
    var rNoCt = await _req(s.port, { method: "POST", path: "/jmap/upload/A1", body: "x" });
    check("upload no content-type → octet-stream default", JSON.parse(rNoCt.body).type === "application/octet-stream");

    // 5c. malformed accountId (path-traversal shape) → 400
    var rBadId = await _req(s.port, { method: "POST", path: "/jmap/upload/..%2Fevil", body: "x" });
    check("upload bad accountId → 400", rBadId.status === 400);
    check("upload bad accountId → invalidArguments", /jmap:error:invalidArguments/.test(rBadId.body));

    // 5d. over-long URL (> 8 KiB) → segments empty → 400
    var longSeg = "a"; for (var i = 0; i < 14; i += 1) longSeg += longSeg;   // ~16 KiB
    var rLong = await _req(s.port, { method: "POST", path: "/jmap/upload/" + longSeg.slice(0, 8300), body: "x" });
    check("upload over-long URL → 400", rLong.status === 400);
    check("upload over-long URL → cap message", /exceeds the/.test(rLong.body));

    // 5e. foreign accountId → 404 accountNotFound
    var rForeign = await _req(s.port, { method: "POST", path: "/jmap/upload/B9", body: "x" });
    check("upload foreign accountId → 404", rForeign.status === 404);
    check("upload foreign accountId → accountNotFound", /jmap:error:accountNotFound/.test(rForeign.body));

    // 5f. unauthenticated → 401
    var rUnauth = await _req(s.port, { method: "POST", path: "/jmap/upload/A1", headers: { "x-actor": "none" }, body: "x" });
    check("upload unauth → 401", rUnauth.status === 401);
  } finally { await _stop(s.server); }

  // 5g. no uploadBlob backend → 503
  var jmapNoBackend = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {} }, accountsFor: DEFAULT_ACCOUNTS, methods: {},
  });
  var sNb = await _startHttp(jmapNoBackend, {});
  try {
    var rNb = await _req(sNb.port, { method: "POST", path: "/jmap/upload/A1", body: "x" });
    check("upload no-backend → 503", rNb.status === 503);
    check("upload no-backend → serverUnavailable", /jmap:error:serverUnavailable/.test(rNb.body));
  } finally { await _stop(sNb.server); }

  // 5h. oversize body → refused (413 branch runs server-side; client sees 413 or reset)
  var jmapCap = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {}, uploadBlob: function () { return Promise.resolve({ blobId: "x" }); } },
    accountsFor: DEFAULT_ACCOUNTS, methods: {}, maxBlobBytes: b.constants.BYTES.bytes(16),
  });
  var sCap = await _startHttp(jmapCap, {});
  try {
    var rOver = await _reqSafe(sCap.port, { method: "POST", path: "/jmap/upload/A1", body: Buffer.alloc(64, 0x41) });
    check("upload oversize → not accepted (refused)", rOver.status !== 201);
    check("upload oversize → 413 or connection reset",
      rOver.status === 413 || rOver.refused === true);
  } finally { await _stop(sCap.server); }

  // 5i. uploadBlob returns bad meta (no blobId) → 500 serverFail
  var jmapBadMeta = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {}, uploadBlob: function () { return Promise.resolve({}); } },
    accountsFor: DEFAULT_ACCOUNTS, methods: {},
  });
  var sBad = await _startHttp(jmapBadMeta, {});
  try {
    var rBadMeta = await _req(sBad.port, { method: "POST", path: "/jmap/upload/A1", body: "x" });
    check("upload bad-meta → 500", rBadMeta.status === 500);
    check("upload bad-meta → serverFail", /jmap:error:serverFail/.test(rBadMeta.body));
  } finally { await _stop(sBad.server); }

  // 5j. uploadBlob throws → 500 serverFail
  var jmapThrow = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {}, uploadBlob: function () { return Promise.reject(new Error("upload boom")); } },
    accountsFor: DEFAULT_ACCOUNTS, methods: {},
  });
  var sTh = await _startHttp(jmapThrow, {});
  try {
    var rTh = await _req(sTh.port, { method: "POST", path: "/jmap/upload/A1", body: "x" });
    check("upload backend-throw → 500", rTh.status === 500);
    check("upload backend-throw → serverFail", /jmap:error:serverFail/.test(rTh.body));
  } finally { await _stop(sTh.server); }

  // 5k. router-supplied req.params.accountId path is honored
  var uploadedAcct = null;
  var jmapParams = b.mail.server.jmap.create({
    mailStore: {
      appendMessage: function () {},
      uploadBlob: function (actor, accountId) { uploadedAcct = accountId; return Promise.resolve({ blobId: "x" }); },
    },
    accountsFor: DEFAULT_ACCOUNTS, methods: {},
  });
  var sParam = await _startHttp(jmapParams, { forceUpload: true, params: { accountId: "A1" } });
  try {
    var rp = await _req(sParam.port, { method: "POST", path: "/anything/here", body: "x" });
    check("upload router-supplied params.accountId honored → 201", rp.status === 201 && uploadedAcct === "A1");
  } finally { await _stop(sParam.server); }
}

// ==========================================================================
// 6. downloadHandler (RFC 8620 §6.2) over HTTP
// ==========================================================================
async function testDownloadHandler() {
  // 6a. happy 5-seg path (+ Content-Disposition) and raw-Buffer / accept branch
  var jmap = b.mail.server.jmap.create({
    mailStore: {
      appendMessage: function () {},
      downloadBlob: function (actor, accountId, blobId) {
        if (blobId === "rawbuf") return Promise.resolve(Buffer.from("rawbytes"));
        if (blobId === "notbuf") return Promise.resolve({ bytes: "not-a-buffer" });
        if (blobId === "missing") return Promise.resolve(null);
        if (blobId === "boom") return Promise.reject(new Error("download boom"));
        return Promise.resolve({ bytes: Buffer.from("hello blob"), type: "text/plain" });
      },
    },
    accountsFor: DEFAULT_ACCOUNTS, methods: {},
  });
  var s = await _startHttp(jmap, {});
  try {
    var rOk = await _req(s.port, { path: "/jmap/download/A1/blob_1/note.txt" });
    check("download happy → 200", rOk.status === 200);
    check("download content-type from backend", (rOk.headers["content-type"] || "") === "text/plain");
    check("download body bytes", rOk.body === "hello blob");
    check("download Content-Disposition attachment",
      /attachment; filename="note\.txt"/.test(rOk.headers["content-disposition"] || ""));

    // 6b. invalid filename segment → no Content-Disposition
    var rNoDisp = await _req(s.port, { path: "/jmap/download/A1/blob_1/no,te" });
    check("download invalid filename → no disposition", !rNoDisp.headers["content-disposition"]);

    // 6c. raw Buffer result + ?accept type
    var rRaw = await _req(s.port, { path: "/jmap/download/A1/rawbuf/f.bin?accept=application/x-test" });
    check("download raw Buffer + accept → 200", rRaw.status === 200);
    check("download raw Buffer uses accept type", (rRaw.headers["content-type"] || "") === "application/x-test");
    check("download raw Buffer body", rRaw.body === "rawbytes");

    // 6d. malformed %-encoded accept is drop-silent (still 200 octet-stream)
    var rBadAccept = await _req(s.port, { path: "/jmap/download/A1/rawbuf/f.bin?accept=%zz" });
    check("download malformed accept drop-silent → 200", rBadAccept.status === 200);
    check("download malformed accept → octet-stream default",
      (rBadAccept.headers["content-type"] || "") === "application/octet-stream");

    // 6e. non-Buffer backend body → 500
    var rNotBuf = await _req(s.port, { path: "/jmap/download/A1/notbuf/f.bin" });
    check("download non-Buffer body → 500", rNotBuf.status === 500);
    check("download non-Buffer → serverFail", /non-Buffer body/.test(rNotBuf.body));

    // 6f. null backend result → 404 blob-not-found
    var rMissing = await _req(s.port, { path: "/jmap/download/A1/missing/f.bin" });
    check("download null result → 404", rMissing.status === 404);
    check("download null result → Blob not found", /Blob not found/.test(rMissing.body));

    // 6g. backend throws → 500
    var rBoom = await _req(s.port, { path: "/jmap/download/A1/boom/f.bin" });
    check("download backend-throw → 500", rBoom.status === 500);
    check("download backend-throw → serverFail", /jmap:error:serverFail/.test(rBoom.body));

    // 6h. malformed accountId segment → 400
    var rBadAcct = await _req(s.port, { path: "/jmap/download/..%2Fx/blob_1/f.bin" });
    check("download malformed accountId → 400", rBadAcct.status === 400);
    check("download malformed accountId → invalidArguments", /malformed accountId/.test(rBadAcct.body));

    // 6i. malformed blobId segment → 400
    var rBadBlob = await _req(s.port, { path: "/jmap/download/A1/..%2Fx/f.bin" });
    check("download malformed blobId → 400", rBadBlob.status === 400);
    check("download malformed blobId → invalidArguments", /malformed blobId/.test(rBadBlob.body));

    // 6j. missing name segment (only 4 real segments → not 3, not 5+) → 400
    var rShort = await _req(s.port, { path: "/jmap/download/A1/blob_1" });
    check("download missing name segment → 400", rShort.status === 400);

    // 6k. over-long URL → 400
    var lp = "a"; for (var i = 0; i < 14; i += 1) lp += lp;
    var rLong = await _req(s.port, { path: "/jmap/download/A1/blob_1/" + lp.slice(0, 8300) });
    check("download over-long URL → 400", rLong.status === 400);
    check("download over-long URL → cap message", /exceeds the/.test(rLong.body));

    // 6l. foreign accountId → 404 accountNotFound
    var rForeign = await _req(s.port, { path: "/jmap/download/B9/blob_1/f.bin" });
    check("download foreign accountId → 404", rForeign.status === 404);
    check("download foreign accountId → accountNotFound", /jmap:error:accountNotFound/.test(rForeign.body));

    // 6m. unauthenticated → 401
    var rUnauth = await _req(s.port, { path: "/jmap/download/A1/blob_1/f.bin", headers: { "x-actor": "none" } });
    check("download unauth → 401", rUnauth.status === 401);
  } finally { await _stop(s.server); }

  // 6n. no downloadBlob backend → 503
  var jmapNb = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {} }, accountsFor: DEFAULT_ACCOUNTS, methods: {},
  });
  var sNb = await _startHttp(jmapNb, {});
  try {
    var rNb = await _req(sNb.port, { path: "/jmap/download/A1/blob_1/f.bin" });
    check("download no-backend → 503", rNb.status === 503);
  } finally { await _stop(sNb.server); }

  // 6o. router-stripped 3-segment path ({accountId}/{blobId}/{name})
  var strippedCall = null;
  var jmapStrip = b.mail.server.jmap.create({
    mailStore: {
      appendMessage: function () {},
      downloadBlob: function (actor, accountId, blobId) {
        strippedCall = { accountId: accountId, blobId: blobId };
        return Promise.resolve({ bytes: Buffer.from("s"), type: "text/plain" });
      },
    },
    accountsFor: DEFAULT_ACCOUNTS, methods: {},
  });
  var sStrip = await _startHttp(jmapStrip, { forceDownload: true });
  try {
    var rStrip = await _req(sStrip.port, { path: "/A1/blob_9/note.txt" });
    check("download router-stripped 3-seg → 200", rStrip.status === 200);
    check("download router-stripped mapped segments",
      strippedCall && strippedCall.accountId === "A1" && strippedCall.blobId === "blob_9");
  } finally { await _stop(sStrip.server); }
}

// ==========================================================================
// 7. eventSourceHandler (RFC 8620 §7.3, SSE) over HTTP
// ==========================================================================
async function testEventSource() {
  // 7a. no subscribePush backend → 503
  var jmapNb = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {} }, accountsFor: DEFAULT_ACCOUNTS, methods: {},
  });
  var sNb = await _startHttp(jmapNb, {});
  try {
    var rNb = await _req(sNb.port, { path: "/jmap/eventsource" });
    check("eventsource no-backend → 503", rNb.status === 503);
    check("eventsource no-backend → serverUnavailable", /jmap:error:serverUnavailable/.test(rNb.body));

    // 7b. unauth → 401
    var rUn = await _req(sNb.port, { path: "/jmap/eventsource", headers: { "x-actor": "none" } });
    check("eventsource unauth → 401", rUn.status === 401);
  } finally { await _stop(sNb.server); }

  // 7c. invalid closeafter → 400 (subscribePush present so we pass the 503 gate)
  var jmapBadCa = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {}, subscribePush: function () { return Promise.resolve(); } },
    accountsFor: DEFAULT_ACCOUNTS, methods: {},
  });
  var sCa = await _startHttp(jmapBadCa, {});
  try {
    var rCa = await _req(sCa.port, { path: "/jmap/eventsource?closeafter=banana" });
    check("eventsource bad closeafter → 400", rCa.status === 400);
    check("eventsource bad closeafter → invalidArguments", /jmap:error:invalidArguments/.test(rCa.body));
  } finally { await _stop(sCa.server); }

  // 7d. full SSE stream: headers + connected + StateChange emit + unsubscribe
  var captured = {};
  var jmap = b.mail.server.jmap.create({
    mailStore: {
      appendMessage: function () {},
      subscribePush: function (actor, types, emitFn) {
        captured.types = types; captured.emit = emitFn;
        return Promise.resolve(function () { captured.unsub = true; });
      },
    },
    accountsFor: DEFAULT_ACCOUNTS, methods: {},
  });
  var s = await _startHttp(jmap, {});
  try {
    // ping=1000 exercises the >900 clamp; %zz key exercises decode drop-silent;
    // `flag` (no '=') exercises the eq===-1 branch.
    var sse = await _openSse(s.port, "/jmap/eventsource?types=Email,Mailbox&ping=1000&%zz=bad&flag");
    check("eventsource → 200", sse.status === 200);
    check("eventsource content-type event-stream", /text\/event-stream/.test(sse.headers["content-type"] || ""));
    check("eventsource cache-control no-cache", sse.headers["cache-control"] === "no-cache");
    check("eventsource X-Accel-Buffering no", sse.headers["x-accel-buffering"] === "no");
    await helpers.waitUntil(function () { return typeof captured.emit === "function"; },
      { timeoutMs: 5000, label: "eventsource: subscribePush emitFn captured" });
    check("eventsource connected comment present", /: connected/.test(sse.read()));
    check("eventsource types forwarded", captured.types && captured.types[0] === "Email");
    // push a StateChange over the real stream
    captured.emit({ kind: "StateChange", changed: { A1: { Email: "s1" } } });
    await helpers.waitUntil(function () { return /event: state/.test(sse.read()); },
      { timeoutMs: 5000, label: "eventsource: state event delivered" });
    check("eventsource StateChange delivered",
      /event: state/.test(sse.read()) && /"@type":"StateChange"/.test(sse.read()));
    // non-StateChange event is ignored (no crash)
    captured.emit({ kind: "Other" });
    captured.emit(null);
    // abort → req 'close' → cleanup → unsubscribe invoked
    sse.abort();
    await helpers.waitUntil(function () { return captured.unsub === true; },
      { timeoutMs: 5000, label: "eventsource: unsubscribe after client close" });
    check("eventsource unsubscribe called on client close", captured.unsub === true);
  } finally { await _stop(s.server); }

  // 7e. closeafter=state → stream closes after first StateChange
  var cap2 = {};
  var jmap2 = b.mail.server.jmap.create({
    mailStore: {
      appendMessage: function () {},
      subscribePush: function (actor, types, emitFn) { cap2.emit = emitFn; return Promise.resolve(); },
    },
    accountsFor: DEFAULT_ACCOUNTS, methods: {},
  });
  var s2 = await _startHttp(jmap2, {});
  try {
    var sse2 = await _openSse(s2.port, "/jmap/eventsource?closeafter=state&ping=0");
    await helpers.waitUntil(function () { return typeof cap2.emit === "function"; },
      { timeoutMs: 5000, label: "eventsource closeafter: emitFn captured" });
    cap2.emit({ kind: "StateChange", changed: { A1: { Email: "s2" } } });
    await helpers.waitUntil(function () { return sse2.isClosed(); },
      { timeoutMs: 5000, label: "eventsource closeafter=state: stream closed" });
    check("eventsource closeafter=state → closed after event",
      sse2.isClosed() && /event: state/.test(sse2.read()));
  } finally { await _stop(s2.server); }

  // 7f. subscribePush rejects → handler cleans up (stream closes)
  var jmap3 = b.mail.server.jmap.create({
    mailStore: {
      appendMessage: function () {},
      subscribePush: function () { return Promise.reject(new Error("subscribe boom")); },
    },
    accountsFor: DEFAULT_ACCOUNTS, methods: {},
  });
  var s3 = await _startHttp(jmap3, {});
  try {
    var sse3 = await _openSse(s3.port, "/jmap/eventsource");
    check("eventsource subscribe-reject: 200 headers already sent", sse3.status === 200);
    await helpers.waitUntil(function () { return sse3.isClosed(); },
      { timeoutMs: 5000, label: "eventsource subscribe-reject: stream cleaned up" });
    check("eventsource subscribe-reject → stream closed", sse3.isClosed());
  } finally { await _stop(s3.server); }
}

// ==========================================================================
// 8. webSocketHandler (RFC 8887) over a REAL b.wsClient connection
// ==========================================================================
function _wsWait(client, until, label) {
  return helpers.waitUntil(until, { timeoutMs: 5000, label: label });
}

async function testWebSocket() {
  var captured = {};
  var jmap = b.mail.server.jmap.create({
    mailStore: {
      appendMessage: function () {},
      subscribePush: function (actor, dataTypes, emitFn) {
        captured.emit = emitFn; return Promise.resolve(function () { captured.unsub = true; });
      },
    },
    accountsFor: DEFAULT_ACCOUNTS,
    methods: { "Core/echo": async function (actor, args) { return { hi: args.hi }; } },
  });
  var s = await _startHttp(jmap, {});
  try {
    var client = _wsConnect(s.port);
    var msgs = [];
    var errSeen = null;
    client.on("message", function (d) { msgs.push(typeof d === "string" ? d : d.toString("utf8")); });
    client.on("error", function (e) { errSeen = e; });
    await _wsWait(client, function () { return client.readyState === "open"; }, "ws: open");
    check("ws negotiated jmap subprotocol", client.subprotocol === "jmap");

    // 8a. valid Request → Response
    client.send(JSON.stringify({ "@type": "Request", id: "r1", using: [], methodCalls: [["Core/echo", { hi: 9 }, "c0"]] }));
    await _wsWait(client, function () { return msgs.length >= 1; }, "ws: response received");
    var resp = JSON.parse(msgs[0]);
    check("ws Request → Response @type", resp["@type"] === "Response");
    check("ws Response echoes requestId", resp.requestId === "r1");
    check("ws Response carries methodResponses", resp.methodResponses[0][1].hi === 9);

    // 8b. binary frame → RequestError notJSON
    msgs.length = 0;
    client.send(Buffer.from([0x00, 0x01, 0x02]));
    await _wsWait(client, function () { return msgs.length >= 1; }, "ws: binary refused");
    check("ws binary frame → RequestError notJSON",
      JSON.parse(msgs[0])["@type"] === "RequestError" && /notJSON/.test(msgs[0]));

    // 8c. non-JSON text frame → RequestError notJSON
    msgs.length = 0;
    client.send("this is not json {");
    await _wsWait(client, function () { return msgs.length >= 1; }, "ws: bad json refused");
    check("ws non-JSON text → RequestError notJSON",
      JSON.parse(msgs[0])["@type"] === "RequestError" && /not valid JSON/.test(msgs[0]));

    // 8d. Request that fails envelope validation → RequestError (not empty Response)
    msgs.length = 0;
    client.send(JSON.stringify({ "@type": "Request", id: "r2", using: [], methodCalls: [] }));
    await _wsWait(client, function () { return msgs.length >= 1; }, "ws: invalid request refused");
    check("ws invalid Request → RequestError",
      JSON.parse(msgs[0])["@type"] === "RequestError");
    check("ws invalid Request → requestId echoed", JSON.parse(msgs[0]).requestId === "r2");

    // 8e. unknown @type → RequestError unknownDataType
    msgs.length = 0;
    client.send(JSON.stringify({ "@type": "Bogus", id: "r3" }));
    await _wsWait(client, function () { return msgs.length >= 1; }, "ws: unknown type refused");
    check("ws unknown @type → unknownDataType",
      /unknownDataType/.test(msgs[0]) && JSON.parse(msgs[0]).requestId === "r3");

    // 8f. WebSocketPushEnable → StateChange push; duplicate enable is a no-op
    client.send(JSON.stringify({ "@type": "WebSocketPushEnable", dataTypes: ["Email"] }));
    await _wsWait(client, function () { return typeof captured.emit === "function"; }, "ws: push enabled");
    client.send(JSON.stringify({ "@type": "WebSocketPushEnable" }));   // duplicate no-op
    msgs.length = 0;
    captured.emit({ kind: "StateChange", changed: { A1: { Email: "sc" } } });
    captured.emit(null);           // guard: !event
    captured.emit({ kind: "Nope" }); // non-StateChange ignored
    await _wsWait(client, function () { return msgs.length >= 1; }, "ws: statechange pushed");
    check("ws StateChange pushed", JSON.parse(msgs[0])["@type"] === "StateChange");

    // 8g. WebSocketPushDisable → unsubscribe invoked
    client.send(JSON.stringify({ "@type": "WebSocketPushDisable" }));
    await _wsWait(client, function () { return captured.unsub === true; }, "ws: push disabled/unsub");
    check("ws PushDisable → unsubscribe called", captured.unsub === true);

    check("ws no client error over the exchange", errSeen === null);
    client.close(1000, "bye");
    await _wsWait(client, function () { return client.readyState === "closed"; }, "ws: closed");
  } finally { await _stop(s.server); }

  // 8h. WebSocketPushEnable with no subscribePush backend → serverUnavailable
  var jmapNoPush = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {} }, accountsFor: DEFAULT_ACCOUNTS, methods: {},
  });
  var sNp = await _startHttp(jmapNoPush, {});
  try {
    var c2 = _wsConnect(sNp.port);
    var m2 = [];
    c2.on("message", function (d) { m2.push(typeof d === "string" ? d : d.toString("utf8")); });
    c2.on("error", function () {});
    await _wsWait(c2, function () { return c2.readyState === "open"; }, "ws(no-push): open");
    c2.send(JSON.stringify({ "@type": "WebSocketPushEnable" }));
    await _wsWait(c2, function () { return m2.length >= 1; }, "ws(no-push): serverUnavailable");
    check("ws PushEnable no-backend → serverUnavailable", /serverUnavailable/.test(m2[0]));
    c2.close(1000, "bye");
  } finally { await _stop(sNp.server); }

  // 8i. WebSocketPushEnable whose subscribePush REJECTS → serverFail + rollback
  var jmapReject = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {}, subscribePush: function () { return Promise.reject(new Error("sub reject")); } },
    accountsFor: DEFAULT_ACCOUNTS, methods: {},
  });
  var sRj = await _startHttp(jmapReject, {});
  try {
    var c3 = _wsConnect(sRj.port);
    var m3 = [];
    c3.on("message", function (d) { m3.push(typeof d === "string" ? d : d.toString("utf8")); });
    c3.on("error", function () {});
    await _wsWait(c3, function () { return c3.readyState === "open"; }, "ws(reject): open");
    c3.send(JSON.stringify({ "@type": "WebSocketPushEnable" }));
    await _wsWait(c3, function () { return m3.length >= 1; }, "ws(reject): serverFail");
    check("ws PushEnable subscribe-reject → serverFail",
      JSON.parse(m3[0])["@type"] === "RequestError" && /serverFail/.test(m3[0]));
    c3.close(1000, "bye");
  } finally { await _stop(sRj.server); }

  // 8j. unauthenticated upgrade → 401 handshake refusal (client sees error)
  var jmapUn = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {} }, accountsFor: DEFAULT_ACCOUNTS, methods: {},
  });
  var sUn = await _startHttp(jmapUn, { noActor: true });
  try {
    var c4 = _wsConnect(sUn.port);
    var err4 = null; var closed4 = false;
    c4.on("error", function (e) { err4 = e; });
    c4.on("close", function () { closed4 = true; });
    await _wsWait(c4, function () { return err4 !== null || closed4; }, "ws(unauth): handshake refused");
    check("ws unauth handshake → client error/close", err4 !== null || closed4);
  } finally { await _stop(sUn.server); }
}

// ---- teardown: force every WS client + socket down, wait for TCP drain ----
async function _drainTcpHandles() {
  _wsClients.forEach(function (c) {
    try { c.cancelReconnect(); } catch (_e) { /* best-effort */ }
    try { c.close(); } catch (_e) { /* best-effort */ }
    try { c._teardown(b.wsClient.CLOSE_NORMAL, "", false); } catch (_e) { /* best-effort */ }
  });
  _wsSockets.forEach(function (sock) {
    try { if (sock && !sock.destroyed) sock.destroy(); } catch (_e) { /* best-effort */ }
  });
  await Promise.all(_httpServers.map(function (srv) {
    return new Promise(function (res) {
      try { if (typeof srv.closeAllConnections === "function") srv.closeAllConnections(); } catch (_e) { /* best-effort */ }
      try { srv.close(function () { res(); }); } catch (_e) { res(); }
    });
  }));
  _wsClients = []; _wsSockets = []; _httpServers = [];
  if (typeof process.getActiveResourcesInfo !== "function") return;
  await helpers.waitUntil(function () {
    return process.getActiveResourcesInfo().filter(function (t) {
      return t === "TCPSocketWrap" || t === "TCPServerWrap";
    }).length === 0;
  }, { timeoutMs: 5000, label: "mail-server-jmap-coverage: TCP handle drain after run" });
}

async function run() {
  var wtt = helpers.withTestTimeout;
  try {
    await wtt("session handler",   testSessionHandler);
    await wtt("discovery handler", testDiscoveryHandler);
    await wtt("api handler",       testApiHandler);
    await wtt("backrefs+pointer",  testBackRefsAndPointer);
    await wtt("upload handler",    testUploadHandler);
    await wtt("download handler",  testDownloadHandler);
    await wtt("event source",      testEventSource);
    await wtt("web socket",        testWebSocket);
  } finally {
    await _drainTcpHandles();
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("mail-server-jmap-coverage OK — " + helpers.getChecks() + " checks"); },
    function (e) { console.error(e && e.stack || e); process.exit(1); }
  );
}
