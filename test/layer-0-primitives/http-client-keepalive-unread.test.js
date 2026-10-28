// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A keep-alive socket whose peer wrote an unsolicited response must not carry
 * another request. Node 24.22.1 and later check the socket handle for unread
 * bytes (`hasPendingRead`) before reusing it; an older runtime only notices
 * those bytes when the event loop polls, so a request issued before that poll
 * reads the stale response as its own (CVE-2026-105481).
 *
 * A socket is reused in two ways: from the idle pool, and handed straight to a
 * request that was queued behind the agent's `maxSockets` limit when the
 * previous response ends. The sequential cases below cover the idle pool; the
 * queued cases cover the handoff. Every keep-alive agent the framework builds
 * or uses is covered: the b.httpClient default pool and an operator `agent`,
 * b.pqcAgent.create / createHttp used directly with node:http(s), the
 * b.network.proxy agent used directly, b.localHttp, b.testing.request and the
 * b.network.dns DNS-over-HTTPS agent.
 *
 * `hasPendingRead` on a TLS socket asks the TCP handle underneath it, so it
 * does not count a TLS record the client has already read from the kernel but
 * not yet decrypted. The "tls-" cases have the server write its response and
 * an unsolicited one as two TLS records in the same tick, and assert that a
 * TLS connection carries one request only, on every runtime.
 *
 * Each case runs in a child process. In the "unchecked" mode the child
 * removes `hasPendingRead` from the socket handle prototypes, which reproduces
 * an older runtime on every Node version. The server writes the unsolicited
 * response and the client issues its next request in the same synchronous
 * block, so no poll runs between them.
 */

var nodeHttp  = require("node:http");
var nodeHttps = require("node:https");
var nodeNet   = require("node:net");
var nodeTls   = require("node:tls");
var nodeCp    = require("node:child_process");
var nodeFs    = require("node:fs");
var nodeOs    = require("node:os");
var nodePath  = require("node:path");

var helpers   = require("../helpers");
var check     = helpers.check;
var ck        = require("../helpers/compromised-keys");

var PENDING_READ = { tcp: null, tls: null };
var FIRST_BODY_LEN = 65444;

function _capturePendingReadCheck(handles) {
  PENDING_READ.tcp = handles[0] && typeof handles[0].hasPendingRead === "function" ? handles[0].hasPendingRead : null;
  PENDING_READ.tls = handles[1] && typeof handles[1].hasPendingRead === "function" ? handles[1].hasPendingRead : null;
}

var REMOVED_CHECKS = [];

function _removePendingReadCheck(handles) {
  handles.forEach(function (h) {
    var proto = h ? Object.getPrototypeOf(h) : null;
    while (proto && !Object.prototype.hasOwnProperty.call(proto, "hasPendingRead")) {
      proto = Object.getPrototypeOf(proto);
    }
    if (proto) {
      REMOVED_CHECKS.push({ proto: proto, fn: proto.hasPendingRead });
      delete proto.hasPendingRead;
    }
  });
}

function _measureWithChecksRestored(fn) {
  REMOVED_CHECKS.forEach(function (r) { r.proto.hasPendingRead = r.fn; });
  try { return fn(); }
  finally { REMOVED_CHECKS.forEach(function (r) { delete r.proto.hasPendingRead; }); }
}

function _spin(ms) {
  var end = Date.now() + ms;
  while (Date.now() < end) { /* the event loop stays blocked, so no poll runs */ }
}

var CLIENT_SOCKETS = [];
var AGENTS = new Set();

function _recordClientSockets() {
  var connect = nodeNet.Socket.prototype.connect;
  nodeNet.Socket.prototype.connect = function () {
    CLIENT_SOCKETS.push(this);
    return connect.apply(this, arguments);
  };
  var addRequest = nodeHttp.Agent.prototype.addRequest;
  nodeHttp.Agent.prototype.addRequest = function () {
    AGENTS.add(this);
    return addRequest.apply(this, arguments);
  };
}

function _queuedRequestCount() {
  var n = 0;
  AGENTS.forEach(function (agent) {
    Object.keys(agent.requests || {}).forEach(function (name) { n += agent.requests[name].length; });
  });
  return n;
}

function _blockUntilReadable(serverSock, check) {
  var port = serverSock.remotePort;
  var client = CLIENT_SOCKETS.filter(function (s) {
    return s !== serverSock && !s.destroyed && s.localPort === port && s._handle;
  })[0];
  if (!client) { _spin(200); return "no-pooled-socket"; }
  if (typeof check !== "function") { _spin(200); return "unmeasured"; }
  return _measureWithChecksRestored(function () {
    var end = Date.now() + 5000;
    while (Date.now() < end) {
      if (check.call(client._handle) === true) return true;
    }
    return false;
  });
}

function _clientsReleased(label) {
  return helpers.waitUntil(function () {
    return CLIENT_SOCKETS.length > 0 && CLIENT_SOCKETS.every(function (s) {
      return s.destroyed || !s._httpMessage;
    });
  }, { timeoutMs: 5000, label: "keepalive-unread: " + label });
}

function _rawResponse(body, type) {
  var buf = Buffer.isBuffer(body) ? body : Buffer.from(body, "latin1");
  return Buffer.concat([Buffer.from("HTTP/1.1 200 OK\r\nContent-Type: " + (type || "text/plain") +
    "\r\nContent-Length: " + buf.length + "\r\nConnection: keep-alive\r\n\r\n", "latin1"), buf]);
}

function _abbrev(text) {
  return text.length > 20 ? text.charAt(0) + "x" + text.length : text;
}

function _rawServer(onRequest, tlsOpts) {
  var state = { connections: 0, sockets: [], seen: [] };
  function onSocket(sock) {
    state.connections += 1;
    state.sockets.push(sock);
    var conn = state.connections;
    var buf = "";
    sock.on("data", function (d) {
      buf += d.toString("latin1");
      var idx;
      while ((idx = buf.indexOf("\r\n\r\n")) !== -1) {
        var head = buf.slice(0, idx);
        buf = buf.slice(idx + 4);
        var path = head.split(" ")[1];
        state.seen.push(conn + ":" + path);
        onRequest(sock, path);
      }
    });
    sock.on("error", function () { /* the client destroyed the socket */ });
  }
  var server = tlsOpts
    ? nodeTls.createServer(tlsOpts).on("secureConnection", onSocket)
    : nodeNet.createServer(onSocket);
  if (tlsOpts) server.on("tlsClientError", function () { /* the client refused the chain */ });
  return new Promise(function (resolve) {
    server.listen(0, "127.0.0.1", function () { state.server = server; resolve(state); });
  });
}

function _plainServer(tlsOpts) {
  return _rawServer(function (sock, path) {
    sock.write(_rawResponse(path === "/a" ? "A" : "B"));
  }, tlsOpts);
}

function _connectProxy() {
  var state = { tunnels: 0, clientSides: [] };
  var proxy = nodeHttp.createServer();
  proxy.on("connect", function (req, client, head) {
    state.tunnels += 1;
    state.clientSides.push(client);
    var parts = req.url.split(":");
    var up = nodeNet.connect(Number(parts[parts.length - 1]), "127.0.0.1", function () {
      client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (head && head.length) up.write(head);
      up.pipe(client);
      client.pipe(up);
    });
    up.on("error", function () { client.destroy(); });
    client.on("error", function () { up.destroy(); });
  });
  return new Promise(function (resolve) {
    proxy.listen(0, "127.0.0.1", function () { state.server = proxy; resolve(state); });
  });
}

function _qname(name) {
  var parts = name.split(".").map(function (l) { return Buffer.concat([Buffer.from([l.length]), Buffer.from(l, "ascii")]); });
  return Buffer.concat(parts.concat([Buffer.from([0])]));
}

function _dnsAnswerFor(name, ip) {
  var hdr = Buffer.from([0, 0, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
  var q = Buffer.concat([_qname(name), Buffer.from([0, 1, 0, 1])]);
  var octets = ip.split(".").map(Number);
  var a = Buffer.from([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4].concat(octets));
  return Buffer.concat([hdr, q, a]);
}

function _questionName(query) {
  var labels = [];
  var off = 12;
  while (query[off] !== 0) {
    labels.push(query.subarray(off + 1, off + 1 + query[off]).toString("ascii"));
    off += query[off] + 1;
  }
  return labels.join(".");
}

var DOH_ANSWERS = { "a.example": "192.0.2.1", "b.example": "192.0.2.2", "c.example": "192.0.2.3" };

function _dohServer(chain) {
  var state = { connections: 0, sockets: [] };
  var server = nodeHttps.createServer({ key: chain.key, cert: chain.cert }, function (req, res) {
    var u = new URL(req.url, "https://localhost");
    function reply(q) {
      var name = _questionName(q);
      res.setHeader("Content-Type", "application/dns-message");
      res.end(_dnsAnswerFor(name, DOH_ANSWERS[name] || "192.0.2.99"));
    }
    var dns = u.searchParams.get("dns");
    if (dns) { reply(Buffer.from(dns, "base64url")); return; }
    var body = [];
    req.on("data", function (c) { body.push(c); });
    req.on("end", function () { reply(Buffer.concat(body)); });
  });
  server.on("secureConnection", function (sock) { state.connections += 1; state.sockets.push(sock); });
  server.on("tlsClientError", function () { /* the client refused the chain */ });
  return new Promise(function (resolve) {
    server.listen(0, "127.0.0.1", function () { state.server = server; resolve(state); });
  });
}

function _socketHandles() {
  return new Promise(function (resolve) {
    var srv = nodeNet.createServer(function (s) { s.destroy(); });
    srv.listen(0, "127.0.0.1", function () {
      var c = nodeNet.connect(srv.address().port, "127.0.0.1", function () {
        var tlsSock = new nodeTls.TLSSocket(new nodeNet.Socket(), {});
        var handles = [c._handle, tlsSock._handle];
        c.destroy();
        tlsSock.destroy();
        srv.close(function () { resolve(handles); });
      });
      c.on("error", function () { /* the server closed it */ });
    });
  });
}

function _nodeGet(lib, reqOpts) {
  return new Promise(function (resolve) {
    var req = lib.request(reqOpts, function (res) {
      var chunks = [];
      res.on("data", function (c) { chunks.push(c); });
      res.on("end", function () { resolve(_abbrev(Buffer.concat(chunks).toString("latin1"))); });
      res.on("error", function (e) { resolve("ERR:" + (e.code || e.message)); });
    });
    req.on("error", function (e) { resolve("ERR:" + (e.code || e.message)); });
    req.end();
  });
}

function _settle(p) {
  return p.then(function (text) { return _abbrev(text); }, function (e) { return "ERR:" + (e.code || e.message); });
}

async function _requester(scenario, b, srv, opts) {
  var port = srv.server.address().port;
  var base = "http://127.0.0.1:" + port;
  var queued = opts.queued === true;
  var out = { get: null, injectInto: null };
  function viaHttpClient(agent) {
    return function (path) {
      return _settle(b.httpClient.request({
        url: base + path, allowInternal: true, allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, agent: agent,
      }).then(function (r) { return r.body.toString("latin1"); }));
    };
  }
  if (scenario === "http" || scenario === "queued-pool") {
    out.get = viaHttpClient(undefined);
  } else if (scenario === "http-agent" || scenario === "queued-agent") {
    out.get = viaHttpClient(new nodeHttp.Agent({ keepAlive: true, maxSockets: queued ? 1 : 4, maxFreeSockets: 4 }));
  } else if (scenario === "pqc-http" || scenario === "queued-pqc-http") {
    var httpAgent = b.pqcAgent.createHttp({ maxSockets: queued ? 1 : 4 });
    out.get = function (path) {
      return _nodeGet(nodeHttp, { host: "127.0.0.1", port: port, path: path, agent: httpAgent });
    };
  } else if (scenario === "pqc-https") {
    var httpsAgent = b.pqcAgent.create({ ca: opts.rootPem });
    out.get = function (path) {
      return _nodeGet(nodeHttps, { host: "127.0.0.1", servername: "localhost", port: port, path: path,
        agent: httpsAgent });
    };
  } else if (scenario === "proxy-http") {
    var proxy = await _connectProxy();
    b.network.proxy.set({ http: "http://127.0.0.1:" + proxy.server.address().port });
    var proxyAgent = b.network.proxy.agentFor(base + "/");
    out.get = function (path) {
      return _nodeGet(nodeHttp, { host: "127.0.0.1", port: port, path: path, agent: proxyAgent });
    };
    out.injectInto = function () { return proxy.clientSides[proxy.clientSides.length - 1]; };
  } else if (scenario === "local-http") {
    var local = b.localHttp.create({ host: "127.0.0.1", port: port });
    out.get = function (path) {
      return _settle(local.request({ method: "GET", path: path }).then(function (r) { return r.body.toString("latin1"); }));
    };
  } else if (scenario === "testing-request") {
    out.get = function (path) {
      return _settle(b.testing.request(srv.server).get(path).then(function (r) { return r.text; }));
    };
  } else {
    throw new Error("unknown scenario " + scenario);
  }
  return out;
}

async function _childSequential(scenario, mode, chain) {
  var b = require("../../index.js");
  var useTls = scenario === "pqc-https";
  var handles = await _socketHandles();
  _capturePendingReadCheck(handles);
  var pendingRead = useTls ? PENDING_READ.tls : PENDING_READ.tcp;
  if (mode === "unchecked") _removePendingReadCheck(handles);
  var srv = await _plainServer(useTls ? { key: chain.key, cert: chain.cert } : null);
  var client = await _requester(scenario, b, srv, { rootPem: chain.rootPem });
  var out = { runtimeChecks: pendingRead !== null };
  out.first = await client.get("/a");
  await _clientsReleased("first response released its socket");
  out.reuse = await client.get("/a");
  out.connectionsAfterReuse = srv.connections;
  await _clientsReleased("second response released its socket");
  var live = client.injectInto ? client.injectInto() : srv.sockets[srv.sockets.length - 1];
  if (!live) return out;
  live.write(_rawResponse("INJECTED"));
  out.readableBeforeRequest = _blockUntilReadable(live, pendingRead);
  out.second = await client.get("/b");
  out.connections = srv.connections;
  return out;
}

async function _childQueued(scenario, mode) {
  var b = require("../../index.js");
  var handles = await _socketHandles();
  _capturePendingReadCheck(handles);
  var checked = PENDING_READ.tcp !== null;
  if (mode === "unchecked") _removePendingReadCheck(handles);
  var pool = scenario === "queued-pool";
  var expectQueued = pool ? 1 : 2;
  var flags = { victimSettled: false };
  var srv = await _rawServer(function (sock, path) {
    if (path === "/a") {
      helpers.waitUntil(function () { return _queuedRequestCount() >= expectQueued; },
        { timeoutMs: 5000, label: "keepalive-unread: a request queued behind the first" })
        .then(function () {
          sock.write(Buffer.concat([_rawResponse("A".repeat(FIRST_BODY_LEN)), _rawResponse("INJECTED")]));
          _spin(150);
        }, function () { sock.destroy(); });
    } else if (path.indexOf("/busy") === 0) {
      helpers.waitUntil(function () { return flags.victimSettled; },
        { timeoutMs: 5000, label: "keepalive-unread: the queued request settled" })
        .then(function () { sock.write(_rawResponse("BUSY")); }, function () { sock.destroy(); });
    } else {
      sock.write(_rawResponse(path.slice(1).toUpperCase()));
    }
  }, null);
  var client = await _requester(scenario, b, srv, { queued: true });
  var out = { runtimeChecks: checked };
  if (pool) {
    var first = [client.get("/a")];
    for (var i = 0; i < 15; i += 1) first.push(client.get("/busy" + i));
    await helpers.waitUntil(function () { return srv.seen.length >= 16; },
      { timeoutMs: 5000, label: "keepalive-unread: the default pool has every socket busy" });
    var victim = client.get("/victim").then(function (v) { flags.victimSettled = true; return v; });
    var all = await Promise.all(first.concat([victim]));
    out.a = all[0];
    out.victim = all[16];
  } else {
    var three = await Promise.all([client.get("/a"), client.get("/b"), client.get("/c")]);
    out.a = three[0];
    out.b = three[1];
    out.c = three[2];
  }
  out.connections = srv.connections;
  out.serverSaw = srv.seen.slice(0, 4);
  return out;
}

async function _tlsRequester(scenario, b, port, rootPem, proxyState) {
  var origin = "https://localhost:" + port;
  function viaHttpClient(agent) {
    return function (path) {
      return _settle(b.httpClient.request({ url: origin + path, allowInternal: true, agent: agent })
        .then(function (r) { return r.body.toString("latin1"); }));
    };
  }
  if (scenario === "tls-pool" || scenario === "tls-pool-queued") return viaHttpClient(undefined);
  if (scenario === "tls-agent-queued") return viaHttpClient(b.pqcAgent.create({ ca: rootPem, maxSockets: 1 }));
  var agent;
  if (scenario === "tls-pqc-https") {
    agent = b.pqcAgent.create({ ca: rootPem });
  } else if (scenario === "tls-proxy") {
    b.network.proxy.set({ https: "http://127.0.0.1:" + proxyState.server.address().port });
    agent = b.network.proxy.agentFor("https://127.0.0.1:" + port + "/");
  } else {
    throw new Error("unknown scenario " + scenario);
  }
  return function (path) {
    return _nodeGet(nodeHttps, { host: "127.0.0.1", servername: "localhost", port: port, path: path,
      agent: agent, ca: rootPem });
  };
}

async function _childTls(scenario, mode, chain) {
  var b = require("../../index.js");
  var handles = await _socketHandles();
  _capturePendingReadCheck(handles);
  if (mode === "unchecked") _removePendingReadCheck(handles);
  var queued = /-queued$/.test(scenario);
  var pool = scenario === "tls-pool-queued";
  var flags = { victimSettled: false };
  function answerFirst(sock, path) {
    sock.write(_rawResponse(path.slice(1).toUpperCase()));
    sock.write(_rawResponse("INJECTED"));
  }
  var seenCount = 0;
  var srv = await _rawServer(function (sock, path) {
    seenCount += 1;
    var firstSeen = seenCount === 1;
    if (path === "/a" && !queued) {
      answerFirst(sock, path);
    } else if (queued && firstSeen) {
      helpers.waitUntil(function () { return _queuedRequestCount() >= (pool ? 1 : 2); },
        { timeoutMs: 5000, label: "keepalive-unread: a TLS request queued behind the first" })
        .then(function () { answerFirst(sock, path); }, function () { sock.destroy(); });
    } else if (path.indexOf("/busy") === 0) {
      helpers.waitUntil(function () { return flags.victimSettled; },
        { timeoutMs: 5000, label: "keepalive-unread: the queued TLS request settled" })
        .then(function () { sock.write(_rawResponse("BUSY")); }, function () { sock.destroy(); });
    } else {
      sock.write(_rawResponse(path.slice(1).toUpperCase()));
    }
  }, { key: chain.key, cert: chain.cert, ALPNProtocols: ["http/1.1"] });
  var proxyState = scenario === "tls-proxy" ? await _connectProxy() : null;
  var get = await _tlsRequester(scenario, b, srv.server.address().port, chain.rootPem, proxyState);
  var out = { runtimeChecks: PENDING_READ.tls !== null };
  if (pool) {
    var first = [get("/a")];
    for (var i = 0; i < 15; i += 1) first.push(get("/busy" + i));
    await helpers.waitUntil(function () { return srv.seen.length >= 16; },
      { timeoutMs: 5000, label: "keepalive-unread: the default pool has every TLS socket busy" });
    var victim = get("/victim").then(function (v) { flags.victimSettled = true; return v; });
    var all = await Promise.all(first.concat([victim]));
    out.a = all[0];
    out.victim = all[16];
    out.requests = 17;
  } else if (queued) {
    var three = await Promise.all([get("/a"), get("/b"), get("/c")]);
    out.a = three[0];
    out.b = three[1];
    out.c = three[2];
    out.requests = 3;
  } else {
    out.a = await get("/a");
    out.b = await get("/b");
    out.c = await get("/c");
    out.requests = 3;
  }
  out.connections = srv.connections;
  out.tunnels = proxyState ? proxyState.tunnels : null;
  out.serverSaw = srv.seen.slice(0, 4);
  return out;
}

if (require.main === module && process.argv[2] === "child") {
  _recordClientSockets();
  var scenario = process.argv[3];
  var mode = process.argv[4];
  var chain = { key: process.env.KA_KEY, cert: process.env.KA_CERT, rootPem: process.env.KA_ROOT };
  var p;
  if (scenario === "doh") p = _childDoh(mode, chain.key, chain.cert, chain.rootPem);
  else if (scenario.indexOf("tls-") === 0) p = _childTls(scenario, mode, chain);
  else if (scenario.indexOf("queued-") === 0) p = _childQueued(scenario, mode);
  else p = _childSequential(scenario, mode, chain);
  p.then(function (out) { process.stdout.write("RESULT " + JSON.stringify(out) + "\n"); process.exit(0); })
   .catch(function (e) { process.stderr.write(String((e && e.stack) || e)); process.exit(1); });
  return;
}

async function _childDoh(mode, chainKey, chainCert, rootPem) {
  var b = require("../../index.js");
  var handles = await _socketHandles();
  _capturePendingReadCheck(handles);
  var checked = PENDING_READ.tls !== null;
  if (mode === "unchecked") _removePendingReadCheck(handles);
  var srv = await _dohServer({ key: chainKey, cert: chainCert });
  b.network.dns.useDnsOverHttps({ url: "https://localhost:" + srv.server.address().port + "/dns-query", ca: rootPem });
  async function look(name) {
    try { return (await b.network.dns.resolve4(name, { transport: "doh" })).join(","); }
    catch (e) { return "ERR:" + (e.code || e.message); }
  }
  var out = { runtimeChecks: checked };
  out.first = await look("a.example");
  await _clientsReleased("first DoH answer released its socket");
  out.reuse = await look("c.example");
  out.connectionsAfterReuse = srv.connections;
  await _clientsReleased("second DoH answer released its socket");
  var live = srv.sockets[srv.sockets.length - 1];
  if (!live) return out;
  live.write(_rawResponse(_dnsAnswerFor("b.example", "203.0.113.66"), "application/dns-message"));
  out.readableBeforeRequest = _blockUntilReadable(live, PENDING_READ.tls);
  out.second = await look("b.example");
  out.connections = srv.connections;
  return out;
}

function _runChild(scenario, mode) {
  return new Promise(function (resolve) {
    var env = Object.assign({}, process.env);
    delete env.NODE_OPTIONS;
    var caFile = null;
    if (scenario === "doh" || scenario === "pqc-https" || scenario.indexOf("tls-") === 0) {
      var chain = ck.tlsChain("control");
      env.KA_KEY = String(chain.key);
      env.KA_CERT = String(chain.cert);
      env.KA_ROOT = ck.certPem(ck.TLS_ROOT_DER);
    }
    if (scenario.indexOf("tls-pool") === 0) {
      caFile = nodePath.join(nodeOs.tmpdir(), "blamejs-keepalive-root-" + process.pid + "-" + scenario + ".pem");
      nodeFs.writeFileSync(caFile, env.KA_ROOT);
      env.NODE_EXTRA_CA_CERTS = caFile;
    }
    var child = nodeCp.spawn(process.execPath, [__filename, "child", scenario, mode], {
      env: env, stdio: ["ignore", "pipe", "pipe"],
    });
    child.on("close", function () {
      if (caFile) { try { nodeFs.unlinkSync(caFile); } catch (_e) { /* already removed */ } }
    });
    var so = "";
    var se = "";
    child.stdout.on("data", function (d) { so += d; });
    child.stderr.on("data", function (d) { se += d; });
    child.on("close", function (code) {
      var line = so.split("\n").filter(function (l) { return l.indexOf("RESULT ") === 0; })[0];
      var parsed = null;
      if (line) { try { parsed = JSON.parse(line.slice("RESULT ".length)); } catch (_e) { parsed = null; } }
      resolve({ code: code, result: parsed, stderr: se.slice(0, 2000) });
    });
  });
}

async function _scenario(name, expect) {
  var asIs = await _runChild(name, "asis");
  var r = asIs.result;
  check(name + ": the child reports a result", r !== null, asIs.stderr);
  if (r === null) return;
  check(name + ": the first request is answered", r.first === expect.first, JSON.stringify(r));
  if (r.runtimeChecks && expect.pooled && !expect.tls) {
    check(name + " premise: the unsolicited response is readable on the client socket before the next request",
          r.readableBeforeRequest === true, JSON.stringify(r));
  }
  check(name + ": an unsolicited response written to an idle socket is not read as the next request's response",
        r.second === expect.second, JSON.stringify(r));
  if (r.runtimeChecks && expect.pooled && !expect.tls) {
    check(name + ": on a runtime that checks pooled sockets, a clean idle socket is still reused",
          r.reuse === expect.reuse && r.connectionsAfterReuse === 1, JSON.stringify(r));
  }
  if (expect.tls) {
    check(name + ": a TLS connection is not reused, even after a clean response",
          r.reuse === expect.reuse && r.connectionsAfterReuse === 2, JSON.stringify(r));
  }
  if (!expect.pooled) {
    check(name + ": each request opens its own connection", r.connections === 3, JSON.stringify(r));
  }

  var unchecked = await _runChild(name, "unchecked");
  var u = unchecked.result;
  check(name + " (runtime without hasPendingRead): the child reports a result", u !== null, unchecked.stderr);
  if (u === null) return;
  if (u.runtimeChecks) {
    check(name + " (runtime without hasPendingRead) premise: a pooled socket, when there is one, has the unsolicited response readable before the next request",
          u.readableBeforeRequest === true || u.readableBeforeRequest === "no-pooled-socket", JSON.stringify(u));
  }
  check(name + " (runtime without hasPendingRead): the unsolicited response is not read as the next request's response",
        u.second === expect.second, JSON.stringify(u));
  check(name + " (runtime without hasPendingRead): the next request runs on a new connection",
        u.connections >= 2, JSON.stringify(u));
}

async function _queuedScenario(name, expect, maxConnections) {
  var modes = ["asis", "unchecked"];
  for (var i = 0; i < modes.length; i += 1) {
    var run = await _runChild(name, modes[i]);
    var r = run.result;
    var label = name + " (" + modes[i] + ")";
    check(label + ": the child reports a result", r !== null, run.stderr);
    if (r === null) continue;
    check(label + ": the first request reads its own 64 KiB response", r.a === "Ax" + FIRST_BODY_LEN, JSON.stringify(r));
    Object.keys(expect).forEach(function (k) {
      check(label + ": the request queued for a socket is not answered with the unsolicited response (" + k + ")",
            r[k] === expect[k], JSON.stringify(r));
    });
    check(label + ": a socket opened for a waiting request is handed to it, not closed and reopened",
          r.connections <= maxConnections, JSON.stringify(r));
  }
}

async function _tlsScenario(name, expect) {
  var modes = ["asis", "unchecked"];
  for (var i = 0; i < modes.length; i += 1) {
    var run = await _runChild(name, modes[i]);
    var r = run.result;
    var label = name + " (" + modes[i] + ")";
    check(label + ": the child reports a result", r !== null, run.stderr);
    if (r === null) continue;
    check(label + ": the first request is answered", r.a === "A", JSON.stringify(r));
    Object.keys(expect).forEach(function (k) {
      check(label + ": a response the server wrote after the first one is not read as the answer to a later request (" +
            k + ")", r[k] === expect[k], JSON.stringify(r));
    });
    check(label + ": every request runs on its own TLS connection", r.connections >= r.requests, JSON.stringify(r));
    check(label + ": no connection is closed and reopened for the same request", r.connections <= r.requests + 1,
          JSON.stringify(r));
  }
}

async function testTlsPqcAgentUsedDirectly() {
  await _tlsScenario("tls-pqc-https", { b: "B", c: "C" });
}

async function testTlsDefaultPool() {
  await _tlsScenario("tls-pool", { b: "B", c: "C" });
}

async function testTlsQueuedRequestOnDefaultPool() {
  await _tlsScenario("tls-pool-queued", { victim: "VICTIM" });
}

async function testTlsQueuedRequestOnOperatorAgent() {
  await _tlsScenario("tls-agent-queued", { b: "B", c: "C" });
}

async function testTlsProxyAgentUsedDirectly() {
  await _tlsScenario("tls-proxy", { b: "B", c: "C" });
}

async function testHttpClientDefaultTransport() {
  await _scenario("http", { first: "A", reuse: "A", second: "B", pooled: true });
}

async function testHttpClientOperatorAgent() {
  await _scenario("http-agent", { first: "A", reuse: "A", second: "B", pooled: true });
}

async function testPqcAgentCreateHttpUsedDirectly() {
  await _scenario("pqc-http", { first: "A", reuse: "A", second: "B", pooled: true });
}

async function testPqcAgentCreateUsedDirectly() {
  await _scenario("pqc-https", { first: "A", reuse: "A", second: "B", pooled: true, tls: true });
}

async function testProxyAgentUsedDirectly() {
  await _scenario("proxy-http", { first: "A", reuse: "A", second: "B", pooled: true });
}

async function testLocalHttp() {
  await _scenario("local-http", { first: "A", reuse: "A", second: "B", pooled: false });
}

async function testTestingRequest() {
  await _scenario("testing-request", { first: "A", reuse: "A", second: "B", pooled: false });
}

async function testDnsOverHttpsAgent() {
  await _scenario("doh", { first: "192.0.2.1", reuse: "192.0.2.3", second: "192.0.2.2", pooled: true, tls: true });
}

async function testQueuedRequestOnDefaultPool() {
  await _queuedScenario("queued-pool", { victim: "VICTIM" }, 17);
}

async function testQueuedRequestOnOperatorAgent() {
  await _queuedScenario("queued-agent", { b: "B", c: "C" }, 3);
}

async function testQueuedRequestOnPqcAgentUsedDirectly() {
  await _queuedScenario("queued-pqc-http", { b: "B", c: "C" }, 3);
}

async function testAgentThatCannotBeGuardedIsRefused() {
  var b = helpers.b;
  var srv = await _plainServer(null);
  var base = "http://127.0.0.1:" + srv.server.address().port;
  function get(agent) {
    return b.httpClient.request({ url: base + "/a", allowInternal: true,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, agent: agent });
  }
  try {
    var inner = new nodeHttp.Agent({ keepAlive: true });
    var notAnEmitter = { addRequest: function (req, o) { return inner.addRequest(req, o); } };
    var err = null;
    try { await get(notAnEmitter); } catch (e) { err = e; }
    check("an agent that is not an EventEmitter and may reuse sockets rejects with http-client/agent-unguarded",
          err !== null && err.code === "http-client/agent-unguarded", err && (err.code + " " + err.message));
    check("an agent that cannot be guarded opens no connection", srv.connections === 0);
    inner.destroy();

    var oneShotInner = new nodeHttp.Agent({ keepAlive: false });
    var oneShot = { keepAlive: false, maxSockets: Infinity,
      addRequest: function (req, o) { return oneShotInner.addRequest(req, o); } };
    var r = await get(oneShot);
    check("control: an agent that is not an EventEmitter and never reuses a socket still sends the request",
          r.body.toString("latin1") === "A");

    var sealed = new nodeHttp.Agent({ keepAlive: true });
    var before = sealed.listenerCount("free");
    Object.preventExtensions(sealed);
    var fr = await get(sealed);
    await get(sealed);
    check("a non-extensible keep-alive agent is guarded and sends the request", fr.body.toString("latin1") === "A");
    check("an agent is guarded once, however many requests use it", sealed.listenerCount("free") === before + 1,
          before + " -> " + sealed.listenerCount("free"));
    sealed.destroy();
  } finally {
    srv.sockets.forEach(function (s) { s.destroy(); });
    await new Promise(function (resolve) { srv.server.close(function () { resolve(); }); });
  }
}

var TESTS = [testHttpClientDefaultTransport, testHttpClientOperatorAgent, testPqcAgentCreateHttpUsedDirectly,
             testPqcAgentCreateUsedDirectly, testProxyAgentUsedDirectly, testLocalHttp, testTestingRequest,
             testDnsOverHttpsAgent, testQueuedRequestOnDefaultPool, testQueuedRequestOnOperatorAgent,
             testQueuedRequestOnPqcAgentUsedDirectly, testAgentThatCannotBeGuardedIsRefused,
             testTlsPqcAgentUsedDirectly, testTlsDefaultPool, testTlsQueuedRequestOnDefaultPool,
             testTlsQueuedRequestOnOperatorAgent, testTlsProxyAgentUsedDirectly];

async function run() {
  for (var i = 0; i < TESTS.length; i += 1) await TESTS[i]();
}

module.exports = { run: run, TESTS: TESTS };

if (require.main === module) {
  var only = process.argv[2];
  var selected = only ? TESTS.filter(function (t) { return t.name === only; }) : TESTS;
  (async function () { for (var j = 0; j < selected.length; j += 1) await selected[j](); })()
    .then(function () { console.log("OK", helpers.getChecks(), "checks"); })
    .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
