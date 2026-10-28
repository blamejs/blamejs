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
var nodeCp    = require("node:child_process");
var nodeFs    = require("node:fs");
var nodeOs    = require("node:os");
var nodePath  = require("node:path");

var helpers = require("../helpers");
var check   = helpers.check;
var ck      = require("../helpers/compromised-keys");

var REQUESTS = 6;

function _tlsServer(chain, host) {
  var state = { connections: 0, resumed: 0, server: null };
  var server = nodeHttps.createServer({ key: chain.key, cert: chain.cert }, function (req, res) {
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

async function _child(scenario) {
  var chain = ck.tlsChain("control");
  var dual = [{ address: "::1", family: 6 }, { address: "127.0.0.1", family: 4 }];
  _pinLocalhost(scenario === "v4-only" || scenario === "operator-agent" ? [dual[1]] : dual);
  var b = require("../../index.js");
  if (scenario === "operator-agent") return _operatorAgentChild(b, chain);
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

function _refuses(label, value, codeExpected) {
  var b = helpers.b;
  var err = null;
  try { b.httpClient.configurePool({ trustedKeepAliveOrigins: value }); } catch (e) { err = e; }
  check("configurePool refuses " + label, err !== null && err.code === codeExpected,
        err ? (err.code + " " + err.message) : "accepted");
}

function testTrustedOriginsValidatedAtConfigTime() {
  var b = helpers.b;
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
             testUntrustedOriginKeepsOneConnectionPerRequest, testOperatorAgentSessionCacheKeepsOtherSessions];

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
