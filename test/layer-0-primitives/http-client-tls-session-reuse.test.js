// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * TLS session resumption and the keep-alive opt-in for https HTTP/1.1.
 *
 * The client opens one TLS connection per https HTTP/1.1 request, and each
 * new connection resumes the session of an earlier one when the server
 * allows it. When the pinned lookup returns an IPv6 and an IPv4 address,
 * Node dials through happy eyeballs (`autoSelectFamily`). When the first
 * family's attempt fails and the next one connects, the TLS socket emits no
 * `session` event, and `https.Agent` caches a session only from that event,
 * so no later connection resumed. The dual-stack case resolves `localhost`
 * to `::1` then `127.0.0.1` and listens on `127.0.0.1` only, so the `::1`
 * attempt is refused (or fails where the host has no IPv6 loopback) and the
 * connection lands on the second family.
 *
 * `b.httpClient.configurePool({ trustedKeepAliveOrigins })` keeps pooling
 * https HTTP/1.1 connections to the origins it names. Every other origin
 * still gets one connection per request.
 *
 * On an agent the caller passes in, a request that carries its own
 * `checkServerIdentity` gets a session-cache key that Node never reads
 * again. The client stores no session under such a key, so it does not
 * evict sessions that other code cached on the same agent.
 *
 * Each case runs in a child process with the fixture root in
 * NODE_EXTRA_CA_CERTS, so the client's default trust store verifies the
 * loopback server and verification stays on.
 */

var nodeHttps = require("node:https");
var nodeHttp2 = require("node:http2");
var nodeCp    = require("node:child_process");
var nodeFs    = require("node:fs");
var nodeOs    = require("node:os");
var nodePath  = require("node:path");

// The parent and every spawned child load these modules directly. The
// package root takes about 5 s to load in a container against the bind
// mount, and these modules take a fraction of that.
var checkMod = require("../helpers/check");
var wait     = require("../helpers/wait");
var ck       = require("../helpers/compromised-keys");
var b = {
  httpClient: require("../../lib/http-client"),
  pqcAgent:   require("../../lib/pqc-agent"),
};
var helpers = { check: checkMod.check, getChecks: checkMod.getChecks, waitUntil: wait.waitUntil, b: b };
var check   = helpers.check;

var REQUESTS = 6;

function _tlsServer(chain, host) {
  var state = { connections: 0, resumed: 0, server: null, held: [] };
  var server = nodeHttps.createServer({ key: chain.key, cert: chain.cert }, function (req, res) {
    if (req.url === "/held") {
      res.write("first-");
      state.held.push(res);
      return;
    }
    res.end("ok:" + req.url);
  });
  server.on("secureConnection", function (s) {
    state.connections += 1;
    if (s.isSessionReused()) state.resumed += 1;
  });
  server.on("tlsClientError", function () { /* a probe the client abandoned */ });
  return new Promise(function (resolve) {
    server.listen(0, host, function () { state.server = server; resolve(state); });
  });
}

function _pinLocalhost(addresses) {
  var dnsP = require("node:dns").promises;
  var original = dnsP.lookup;
  dnsP.lookup = function (host, opts) {
    if (String(host).toLowerCase() !== "localhost") return original.apply(dnsP, arguments);
    if (opts && opts.all) return Promise.resolve(addresses.slice());
    return Promise.resolve(addresses[0]);
  };
}

async function _sequential(b, base, n) {
  var bodies = [];
  for (var i = 0; i < n; i += 1) {
    var r = await b.httpClient.request({ url: base + "/r" + i, allowInternal: true, timeoutMs: 10000 });
    bodies.push(r.body.toString("latin1"));
  }
  return bodies;
}

function _plainGet(agent, port) {
  return new Promise(function (resolve, reject) {
    nodeHttps.get({ host: "127.0.0.1", port: port, agent: agent, servername: "localhost",
      headers: { connection: "close" } }, function (res) {
      res.resume();
      res.on("end", resolve);
    }).on("error", reject);
  });
}

async function _operatorAgentChild(b, chain) {
  var other = await _tlsServer(chain, "127.0.0.1");
  var srv = await _tlsServer(chain, "127.0.0.1");
  var agent = new nodeHttps.Agent({ keepAlive: true, maxCachedSessions: 2 });
  var out = { scenario: "operator-agent" };
  try {
    await _plainGet(agent, other.server.address().port);
    await _plainGet(agent, other.server.address().port);
    out.otherResumedBefore = other.resumed;
    out.cacheBefore = agent._sessionCache.list.length;
    var bodies = [];
    for (var i = 0; i < 3; i += 1) {
      var r = await b.httpClient.request({ url: "https://localhost:" + srv.server.address().port + "/r" + i,
        allowInternal: true, timeoutMs: 10000, agent: agent });
      bodies.push(r.body.toString("latin1"));
    }
    out.bodies = bodies;
    out.cacheAfter = agent._sessionCache.list.length;
    await _plainGet(agent, other.server.address().port);
    out.otherResumedAfter = other.resumed;
  } finally {
    agent.destroy();
    other.server.close();
    srv.server.close();
  }
  return out;
}

function _h2Server(chain, host) {
  var state = { connections: 0, server: null, held: [] };
  var server = nodeHttp2.createSecureServer({ key: chain.key, cert: chain.cert }, function (req, res) {
    if (req.url === "/dropped") {
      res.write("first-", function () { req.stream.session.destroy(); });
      return;
    }
    if (req.url === "/silent") {
      state.held.push(res);
      return;
    }
    if (req.url === "/held") {
      res.write("first-");
      state.held.push(res);
      return;
    }
    res.end("ok:" + req.url);
  });
  server.on("secureConnection", function () { state.connections += 1; });
  server.on("tlsClientError", function () { /* a probe the client abandoned */ });
  return new Promise(function (resolve) {
    server.listen(0, host, function () { state.server = server; resolve(state); });
  });
}

async function _callerAgentChild(b, scenario, srv, base) {
  var agent = b.pqcAgent.create({ keepAlive: true, maxSockets: 6 });
  var out = { scenario: scenario };
  try {
    if (scenario === "caller-agent-trusted" || scenario === "caller-agent-untrust") {
      b.httpClient.configurePool({ trustedKeepAliveOrigins: [base] });
    }
    var bodies = [];
    for (var i = 0; i < REQUESTS; i += 1) {
      var r = await b.httpClient.request({ url: base + "/r" + i, allowInternal: true, timeoutMs: 10000, agent: agent });
      bodies.push(r.body.toString("latin1"));
    }
    out.bodies = bodies;
    out.connections = srv.connections;
    if (scenario === "caller-agent-untrust") {
      b.httpClient.configurePool({ trustedKeepAliveOrigins: [] });
      for (var j = 0; j < 2; j += 1) {
        await b.httpClient.request({ url: base + "/after" + j, allowInternal: true, timeoutMs: 10000, agent: agent });
      }
      out.connectionsAfterUntrust = srv.connections;
    }
    if (scenario === "caller-agent-trusted") {
      var before = srv.connections;
      await _keepAliveGet(agent, srv.server.address().port, "/plain0");
      await _keepAliveGet(agent, srv.server.address().port, "/plain1");
      out.plainConnections = srv.connections - before;
      await b.httpClient.request({ url: base + "/refill", allowInternal: true, timeoutMs: 10000, agent: agent });
      out.freeBeforeSameHost = _freeSocketCount(agent);
      var beforeSameHost = srv.connections;
      await _keepAliveGet(agent, srv.server.address().port, "/same0", "localhost");
      await _keepAliveGet(agent, srv.server.address().port, "/same1", "localhost");
      out.sameHostConnections = srv.connections - beforeSameHost;
      var beforeTrusted = srv.connections;
      await b.httpClient.request({ url: base + "/again", allowInternal: true, timeoutMs: 10000, agent: agent });
      out.trustedAfterSameHost = srv.connections - beforeTrusted;
    }
  } finally {
    agent.destroy();
    srv.server.close();
  }
  return out;
}

function _freeSocketCount(agent) {
  var free = agent.freeSockets || {};
  return Object.keys(free).reduce(function (n, name) { return n + (free[name] || []).length; }, 0);
}

function _loopbackV4Lookup(_host, opts, cb) {
  if (opts && opts.all) cb(null, [{ address: "127.0.0.1", family: 4 }]);
  else cb(null, "127.0.0.1", 4);
}

// host "localhost" with a v4-only lookup gives the request the same agent
// pool name as b.httpClient's requests to https://localhost:<port>.
function _keepAliveGet(agent, port, path, host) {
  var reqOpts = { host: host || "127.0.0.1", port: port, path: path, agent: agent, servername: "localhost" };
  if (host === "localhost") reqOpts.lookup = _loopbackV4Lookup;
  return new Promise(function (resolve, reject) {
    nodeHttps.get(reqOpts, function (res) {
      res.resume();
      res.on("end", resolve);
    }).on("error", reject);
  });
}

async function _inflightChild(b, scenario, chain) {
  var srv = scenario === "inflight-h2-pool-opts" ? await _h2Server(chain, "127.0.0.1") : await _tlsServer(chain, "127.0.0.1");
  var base = "https://localhost:" + srv.server.address().port;
  var out = { scenario: scenario };
  try {
    var r = await b.httpClient.request({ url: base + "/held", responseMode: "stream", allowInternal: true,
      timeoutMs: 10000 });
    var chunks = [];
    var ended = new Promise(function (resolve, reject) {
      r.body.on("data", function (c) { chunks.push(c); });
      r.body.on("end", resolve);
      r.body.on("error", reject);
    });
    ended.catch(function () { /* read below */ });
    await helpers.waitUntil(function () { return chunks.length > 0 && srv.held.length === 1; },
      { timeoutMs: 10000, label: scenario + ": first chunk of the held response arrives" });
    if (scenario === "inflight-trust-change") {
      b.httpClient.configurePool({ trustedKeepAliveOrigins: [base] });
    } else {
      b.httpClient.configurePool({ maxSockets: 32 });
    }
    srv.held[0].end("last");
    try { await ended; out.body = Buffer.concat(chunks).toString("latin1"); }
    catch (e) { out.error = (e && (e.code || e.message)) || String(e); }
    var after = await b.httpClient.request({ url: base + "/after", allowInternal: true, timeoutMs: 10000 });
    out.after = after.body.toString("latin1");
  } finally {
    srv.server.close();
  }
  return out;
}

async function _droppedChild(b, scenario, chain) {
  var srv = await _h2Server(chain, "127.0.0.1");
  var base = "https://localhost:" + srv.server.address().port;
  var out = { scenario: scenario };
  var local = scenario.indexOf("h2-dropped-local-") === 0;
  var silent = scenario.indexOf("h2-dropped-local-silent-") === 0;
  var path = silent ? "/silent" : (local ? "/held" : "/dropped");
  var chunkArrived = false;
  function _onChunk() { chunkArrived = true; }
  function _tearDownWhenHeld() {
    if (!local) return Promise.resolve();
    return helpers.waitUntil(function () { return srv.held.length === 1 && (silent || chunkArrived); },
      { timeoutMs: 10000, label: scenario + ": the server holds the response at the point under test" })
      .then(function () { b.httpClient._resetForTest(); });
  }
  try {
    if (silent && scenario === "h2-dropped-local-silent-stream") {
      var pendingS = b.httpClient.request({ url: base + path, responseMode: "stream", allowInternal: true,
        timeoutMs: 10000 });
      pendingS.catch(function () { /* read below */ });
      await _tearDownWhenHeld();
      try { await pendingS; out.body = "resolved"; }
      catch (eS) { out.error = eS.code || eS.message; }
    } else if (scenario === "h2-dropped-stream" || scenario === "h2-dropped-local-stream") {
      var r = await b.httpClient.request({ url: base + path, responseMode: "stream", allowInternal: true,
        timeoutMs: 10000, onChunk: _onChunk });
      var torn = _tearDownWhenHeld();
      var chunks = [];
      await new Promise(function (resolve) {
        r.body.on("data", function (c) { chunks.push(c); });
        r.body.on("end", function () { out.body = Buffer.concat(chunks).toString("latin1"); resolve(); });
        r.body.on("error", function (e) { out.error = e.code || e.message; resolve(); });
      });
      await torn;
    } else {
      var pending = b.httpClient.request({ url: base + path, allowInternal: true, timeoutMs: 10000,
        onChunk: _onChunk });
      pending.catch(function () { /* read below */ });
      await _tearDownWhenHeld();
      try {
        var rb = await pending;
        out.body = rb.body.toString("latin1");
      } catch (e) { out.error = e.code || e.message; }
    }
  } finally {
    srv.server.close();
  }
  return out;
}

async function _untrustChild(b, srv, base) {
  var out = { scenario: "untrust-closes-pooled" };
  try {
    b.httpClient.configurePool({ trustedKeepAliveOrigins: [base] });
    await _sequential(b, base, 3);
    out.connectionsTrusted = srv.connections;
    b.httpClient.configurePool({ trustedKeepAliveOrigins: [] });
    await _sequential(b, base, 3);
    out.connectionsAfterUntrust = srv.connections;
  } finally {
    srv.server.close();
  }
  return out;
}

async function _child(scenario) {
  var chain = ck.tlsChain("control");
  var dual = [{ address: "::1", family: 6 }, { address: "127.0.0.1", family: 4 }];
  _pinLocalhost(scenario === "dual-stack" || scenario === "trusted" || scenario === "untrusted-beside-trusted"
    ? dual : [dual[1]]);
  if (scenario === "operator-agent") return _operatorAgentChild(b, chain);
  if (scenario.indexOf("inflight-") === 0) return _inflightChild(b, scenario, chain);
  if (scenario.indexOf("h2-dropped-") === 0) return _droppedChild(b, scenario, chain);
  if (scenario.indexOf("caller-agent-") === 0 || scenario === "untrust-closes-pooled") {
    var cSrv = await _tlsServer(chain, "127.0.0.1");
    var cBase = "https://localhost:" + cSrv.server.address().port;
    if (scenario === "untrust-closes-pooled") return _untrustChild(b, cSrv, cBase);
    return _callerAgentChild(b, scenario, cSrv, cBase);
  }
  var srv = await _tlsServer(chain, "127.0.0.1");
  var base = "https://localhost:" + srv.server.address().port;
  var out = { scenario: scenario };
  try {
    if (scenario === "untrusted-beside-trusted") {
      var other = await _tlsServer(chain, "127.0.0.1");
      b.httpClient.configurePool({ trustedKeepAliveOrigins: ["https://localhost:" + other.server.address().port] });
      await _sequential(b, "https://localhost:" + other.server.address().port, 2);
      other.server.close();
    } else if (scenario === "trusted") {
      b.httpClient.configurePool({ trustedKeepAliveOrigins: [base.toUpperCase().replace("HTTPS", "https")] });
    }
    var t0 = Date.now();
    out.bodies = await _sequential(b, base, REQUESTS);
    out.msPerRequest = Math.round((Date.now() - t0) / REQUESTS);
    out.connections = srv.connections;
    out.resumed = srv.resumed;
  } finally {
    srv.server.close();
  }
  return out;
}

function _runChild(scenario) {
  return new Promise(function (resolve) {
    var env = Object.assign({}, process.env);
    delete env.NODE_OPTIONS;
    var caFile = nodePath.join(nodeOs.tmpdir(), "blamejs-session-reuse-root-" + process.pid + "-" + scenario + ".pem");
    nodeFs.writeFileSync(caFile, ck.certPem(ck.TLS_ROOT_DER));
    env.NODE_EXTRA_CA_CERTS = caFile;
    var child = nodeCp.spawn(process.execPath, [__filename, "child", scenario], {
      env: env, stdio: ["ignore", "pipe", "pipe"],
    });
    var so = "";
    var se = "";
    child.stdout.on("data", function (d) { so += d; });
    child.stderr.on("data", function (d) { se += d; });
    child.on("close", function (code) {
      try { nodeFs.unlinkSync(caFile); } catch (_e) { /* already removed */ }
      var line = so.split("\n").filter(function (l) { return l.indexOf("RESULT ") === 0; })[0];
      var parsed = null;
      if (line) { try { parsed = JSON.parse(line.slice("RESULT ".length)); } catch (_e) { parsed = null; } }
      resolve({ code: code, result: parsed, stderr: se.slice(0, 2000) });
    });
  });
}

function _answered(r) {
  for (var i = 0; i < REQUESTS; i += 1) {
    if (!r.bodies || r.bodies[i] !== "ok:/r" + i) return false;
  }
  return true;
}

async function testDualStackFallbackResumesSessions() {
  var run = await _runChild("dual-stack");
  var r = run.result;
  check("dual-stack: the child reports a result", r !== null, run.stderr);
  if (r === null) return;
  check("dual-stack: every request is answered", _answered(r), JSON.stringify(r));
  check("dual-stack: each request opens its own TLS connection", r.connections >= REQUESTS, JSON.stringify(r));
  check("dual-stack: a connection that lands on the second address family still caches its session, " +
        "so every later connection resumes it", r.resumed >= REQUESTS - 1, JSON.stringify(r));
}

async function testSingleFamilyResumesSessions() {
  var run = await _runChild("v4-only");
  var r = run.result;
  check("v4-only control: the child reports a result", r !== null, run.stderr);
  if (r === null) return;
  check("v4-only control: every request is answered", _answered(r), JSON.stringify(r));
  check("v4-only control: every later connection resumes the session", r.resumed >= REQUESTS - 1, JSON.stringify(r));
}

async function testTrustedOriginPoolsConnections() {
  var run = await _runChild("trusted");
  var r = run.result;
  check("trusted: the child reports a result", r !== null, run.stderr);
  if (r === null) return;
  check("trusted: every request is answered", _answered(r), JSON.stringify(r));
  check("trusted: requests to an origin in trustedKeepAliveOrigins share a pooled connection",
        r.connections <= 2, JSON.stringify(r));
}

async function testUntrustedOriginKeepsOneConnectionPerRequest() {
  var run = await _runChild("untrusted-beside-trusted");
  var r = run.result;
  check("untrusted: the child reports a result", r !== null, run.stderr);
  if (r === null) return;
  check("untrusted: every request is answered", _answered(r), JSON.stringify(r));
  check("untrusted: an origin not in trustedKeepAliveOrigins still opens one connection per request",
        r.connections >= REQUESTS, JSON.stringify(r));
}

async function testOperatorAgentSessionCacheKeepsOtherSessions() {
  var run = await _runChild("operator-agent");
  var r = run.result;
  check("operator-agent: the child reports a result", r !== null, run.stderr);
  if (r === null) return;
  check("operator-agent: every client request is answered",
        Array.isArray(r.bodies) && r.bodies.join(",") === "ok:/r0,ok:/r1,ok:/r2", JSON.stringify(r));
  check("operator-agent control: other code on the agent resumes its own session", r.otherResumedBefore === 1,
        JSON.stringify(r));
  check("operator-agent: client requests that carry their own identity check add no session-cache entry " +
        "Node never reads", r.cacheAfter === r.cacheBefore, JSON.stringify(r));
  check("operator-agent: a session other code cached on the agent is not evicted by client requests",
        r.otherResumedAfter === 2, JSON.stringify(r));
}

async function testCallerAgentPoolsTrustedOrigin() {
  var run = await _runChild("caller-agent-trusted");
  var r = run.result;
  check("caller-agent trusted: the child reports a result", r !== null, run.stderr);
  if (r === null) return;
  check("caller-agent trusted: every request is answered", _answered(r), JSON.stringify(r));
  check("caller-agent trusted: requests through a b.pqcAgent.create agent to an origin in " +
        "trustedKeepAliveOrigins share a pooled connection", r.connections <= 2, JSON.stringify(r));
  check("caller-agent trusted: a request on the same agent made outside b.httpClient still opens " +
        "one connection per request", r.plainConnections === 2, JSON.stringify(r));
  check("caller-agent trusted control: a b.httpClient connection to the trusted origin is idle in the agent's pool",
        r.freeBeforeSameHost >= 1, JSON.stringify(r));
  check("caller-agent trusted: a request outside b.httpClient to the same host name does not take the " +
        "pooled trusted connection", r.sameHostConnections === 2, JSON.stringify(r));
  check("caller-agent trusted: b.httpClient still reuses its pooled connection afterwards",
        r.trustedAfterSameHost === 0, JSON.stringify(r));
}

async function testCallerAgentUntrustedOriginKeepsOneConnectionPerRequest() {
  var run = await _runChild("caller-agent-unlisted");
  var r = run.result;
  check("caller-agent unlisted: the child reports a result", r !== null, run.stderr);
  if (r === null) return;
  check("caller-agent unlisted: every request is answered", _answered(r), JSON.stringify(r));
  check("caller-agent unlisted: an origin not in trustedKeepAliveOrigins opens one connection per request " +
        "through a caller's agent", r.connections >= REQUESTS, JSON.stringify(r));
}

async function testCallerAgentStopsPoolingWhenOriginRemoved() {
  var run = await _runChild("caller-agent-untrust");
  var r = run.result;
  check("caller-agent untrust: the child reports a result", r !== null, run.stderr);
  if (r === null) return;
  check("caller-agent untrust: every request is answered", _answered(r), JSON.stringify(r));
  check("caller-agent untrust: the trusted requests share a pooled connection", r.connections <= 2,
        JSON.stringify(r));
  check("caller-agent untrust: after the origin leaves the list, each request opens its own connection " +
        "and the pooled one is not reused", r.connectionsAfterUntrust - r.connections === 2, JSON.stringify(r));
}

async function testUntrustClosesPooledConnection() {
  var run = await _runChild("untrust-closes-pooled");
  var r = run.result;
  check("untrust: the child reports a result", r !== null, run.stderr);
  if (r === null) return;
  check("untrust: the trusted requests share a pooled connection", r.connectionsTrusted <= 2, JSON.stringify(r));
  check("untrust: after the origin leaves the list, each request opens its own connection",
        r.connectionsAfterUntrust - r.connectionsTrusted === 3, JSON.stringify(r));
}

async function _checkInflight(scenario, label) {
  var run = await _runChild(scenario);
  var r = run.result;
  check(label + ": the child reports a result", r !== null, run.stderr);
  if (r === null) return;
  check(label + ": a streamed response in flight when configurePool runs arrives whole",
        r.body === "first-last" && r.error === undefined, JSON.stringify(r));
  check(label + ": a request after configurePool is answered", r.after === "ok:/after", JSON.stringify(r));
}

async function testInflightSurvivesTrustChange() {
  await _checkInflight("inflight-trust-change", "inflight trust change");
}

async function testInflightSurvivesPoolOptionChange() {
  await _checkInflight("inflight-pool-opts", "inflight pool option change");
}

async function testInflightH2SurvivesPoolOptionChange() {
  await _checkInflight("inflight-h2-pool-opts", "inflight h2 pool option change");
}

async function _checkDropped(scenario, label) {
  var run = await _runChild(scenario);
  var r = run.result;
  check(label + ": the child reports a result", r !== null, run.stderr);
  if (r === null) return;
  check(label + ": an HTTP/2 response whose session closes before the stream ends fails with " +
        "http-client/truncated-body instead of ending short", r.error === "http-client/truncated-body",
        JSON.stringify(r));
}

async function testH2SessionDroppedMidStreamIsTruncation() {
  await _checkDropped("h2-dropped-stream", "h2 dropped (stream mode)");
}

async function testH2SessionDroppedMidBufferIsTruncation() {
  await _checkDropped("h2-dropped-buffer", "h2 dropped (buffer mode)");
}

async function testH2SessionTornDownLocallyMidStreamIsTruncation() {
  await _checkDropped("h2-dropped-local-stream", "h2 torn down locally (stream mode)");
}

async function testH2SessionTornDownLocallyMidBufferIsTruncation() {
  await _checkDropped("h2-dropped-local-buffer", "h2 torn down locally (buffer mode)");
}

async function _checkClosedBeforeResponse(scenario, label) {
  var run = await _runChild(scenario);
  var r = run.result;
  check(label + ": the child reports a result", r !== null, run.stderr);
  if (r === null) return;
  check(label + ": a request whose HTTP/2 stream closes before the response arrives rejects with " +
        "http-client/h2-stream-error instead of waiting for timeoutMs", r.error === "http-client/h2-stream-error",
        JSON.stringify(r));
}

async function testH2SessionTornDownBeforeResponseRejectsBuffer() {
  await _checkClosedBeforeResponse("h2-dropped-local-silent-buffer", "h2 torn down before response (buffer mode)");
}

async function testH2SessionTornDownBeforeResponseRejectsStream() {
  await _checkClosedBeforeResponse("h2-dropped-local-silent-stream", "h2 torn down before response (stream mode)");
}

function _refuses(label, value, codeExpected) {
  var err = null;
  try { b.httpClient.configurePool({ trustedKeepAliveOrigins: value }); } catch (e) { err = e; }
  check("configurePool refuses " + label, err !== null && err.code === codeExpected,
        err ? (err.code + " " + err.message) : "accepted");
}

function testTrustedOriginsValidatedAtConfigTime() {
  _refuses("a trustedKeepAliveOrigins that is not an array", "https://a.example", "http-client/bad-opts");
  _refuses("a non-string origin", [42], "http-client/bad-opts");
  _refuses("an origin that is not a URL", ["not a url"], "http-client/bad-opts");
  _refuses("an origin with a path", ["https://a.example/bucket"], "http-client/bad-opts");
  _refuses("an origin with a query", ["https://a.example?x=1"], "http-client/bad-opts");
  _refuses("an origin with credentials", ["https://user:pw@a.example"], "http-client/bad-opts");
  _refuses("a cleartext origin", ["http://a.example"], "http-client/bad-opts");
  _refuses("an origin of another protocol", ["ftp://a.example"], "http-client/bad-opts");
  var err = null;
  try {
    b.httpClient.configurePool({ trustedKeepAliveOrigins: ["https://a.example", "https://b.example:8443/"] });
    b.httpClient.configurePool({ trustedKeepAliveOrigins: [] });
  } catch (e) { err = e; }
  check("configurePool accepts https origins and [] to clear them", err === null, err && err.message);
}

if (require.main === module && process.argv[2] === "child") {
  _child(process.argv[3]).then(function (out) {
    process.stdout.write("RESULT " + JSON.stringify(out) + "\n");
    process.exit(0);
  }, function (e) {
    process.stderr.write(String(e && e.stack || e) + "\n");
    process.exit(1);
  });
}

var TESTS = [testTrustedOriginsValidatedAtConfigTime, testSingleFamilyResumesSessions,
             testDualStackFallbackResumesSessions, testTrustedOriginPoolsConnections,
             testUntrustedOriginKeepsOneConnectionPerRequest, testOperatorAgentSessionCacheKeepsOtherSessions,
             testCallerAgentPoolsTrustedOrigin, testCallerAgentUntrustedOriginKeepsOneConnectionPerRequest,
             testCallerAgentStopsPoolingWhenOriginRemoved, testUntrustClosesPooledConnection,
             testInflightSurvivesTrustChange, testInflightSurvivesPoolOptionChange,
             testInflightH2SurvivesPoolOptionChange, testH2SessionDroppedMidStreamIsTruncation,
             testH2SessionDroppedMidBufferIsTruncation, testH2SessionTornDownLocallyMidStreamIsTruncation,
             testH2SessionTornDownLocallyMidBufferIsTruncation, testH2SessionTornDownBeforeResponseRejectsBuffer,
             testH2SessionTornDownBeforeResponseRejectsStream];

async function run() {
  for (var i = 0; i < TESTS.length; i += 1) await TESTS[i]();
}

module.exports = { run: run, TESTS: TESTS };

if (require.main === module && process.argv[2] !== "child") {
  var only = process.argv[2];
  var selected = only ? TESTS.filter(function (t) { return t.name === only; }) : TESTS;
  (async function () { for (var j = 0; j < selected.length; j += 1) await selected[j](); })()
    .then(function () { console.log("OK", helpers.getChecks(), "checks"); })
    .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
