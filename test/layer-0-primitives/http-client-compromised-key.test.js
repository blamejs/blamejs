// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.httpClient.request refuses a server whose verified chain carries a
 * compromised key, over HTTP/2, HTTP/1.1, an operator agent and the
 * b.network.proxy tunnel. The fixture root is trusted with
 * b.network.tls.addCa or the operator agent's ca; the server's intermediate
 * has private key 1 in the compromised chain and an ordinary key in the
 * control chain.
 */

var http    = require("node:http");
var https   = require("node:https");
var http2   = require("node:http2");
var net     = require("node:net");
var nodeTls = require("node:tls");
var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var ck      = require("../helpers/compromised-keys");
var paths   = require("../helpers/chain-path");
var httpClientLib = require("../../lib/http-client");

// A server sending one fixture chain: "control" or "compromised" from
// ck.tlsChain, or "path-evasion" (the issuing CA with private key 1 hidden
// behind an expired alternate issuer and a decoy root) and "path-control"
// from the chain-path fixtures. Every chain sits under the TLS fixture root.
function _server(which, h2) {
  var chain = which === "path-evasion" ? paths.evasionChain("compromised-evasion")
            : which === "path-control" ? paths.evasionChain("control")
            : ck.tlsChain(which);
  var opts = { key: chain.key, cert: chain.cert };
  var counts = { connections: 0 };
  function handler(req, res) { res.end("hello"); }
  var server = h2
    ? http2.createSecureServer(Object.assign({ allowHTTP1: true }, opts), handler)
    : https.createServer(Object.assign({ keepAliveTimeout: 30000 }, opts), handler);
  server.on("secureConnection", function () { counts.connections += 1; });
  server.on("tlsClientError", function () { /* the client refused the chain */ });
  return new Promise(function (resolve) {
    server.listen(0, "127.0.0.1", function () {
      resolve({ server: server, port: server.address().port, rootCa: ck.certPem(ck.TLS_ROOT_DER), counts: counts });
    });
  });
}

function _close(server) {
  if (typeof server.closeAllConnections === "function") server.closeAllConnections();
  return new Promise(function (resolve) { server.close(function () { resolve(); }); });
}

async function _request(port) {
  try {
    var res = await b.httpClient.request({ url: "https://localhost:" + port + "/", allowInternal: true });
    return { status: res.statusCode || res.status, code: null };
  } catch (e) {
    return { status: null, code: (e && e.code) || String(e), message: e && e.message };
  }
}

async function _case(h2) {
  var label = h2 ? "h2" : "h1";
  var nt = b.network.tls;
  nt._resetForTest();
  var control = await _server("control", h2);
  var bad = await _server("compromised", h2);
  var pathControl = await _server("path-control", h2);
  var evasion = await _server("path-evasion", h2);
  nt.addCa(control.rootCa, { label: "fixture-root", audit: false });
  try {
    var ok = await _request(control.port);
    check("httpClient " + label + " control: the control chain under an added root answers 200",
          ok.status === 200, JSON.stringify(ok));
    var refused = await _request(bad.port);
    check("httpClient " + label + ": a server chain whose intermediate's private key is 1 is refused with tls/compromised-key",
          refused.status === null && refused.code === "tls/compromised-key", JSON.stringify(refused));
    var pathOk = await _request(pathControl.port);
    check("httpClient " + label + " control: a three-certificate chain under ordinary keys answers 200",
          pathOk.status === 200, JSON.stringify(pathOk));
    var hidden = await _request(evasion.port);
    check("httpClient " + label + ": a chain hiding the compromised issuing CA behind a decoy root is refused",
          hidden.status === null && hidden.code === "tls/server-chain-unverifiable", JSON.stringify(hidden));
  } finally {
    nt._resetForTest();
    httpClientLib._resetForTest();
    await _close(control.server);
    await _close(bad.server);
    await _close(pathControl.server);
    await _close(evasion.server);
  }
}

async function testHttp2() { await _case(true); }
async function testHttp1() { await _case(false); }

async function _requestWithAgent(port, agent) {
  try {
    var res = await b.httpClient.request({ url: "https://localhost:" + port + "/", allowInternal: true, agent: agent });
    return { status: res.statusCode || res.status, code: null };
  } catch (e) {
    return { status: null, code: (e && e.code) || String(e), message: e && e.message };
  }
}

async function testOperatorAgent() {
  b.network.tls._resetForTest();
  var control = await _server("control", false);
  var bad = await _server("compromised", false);
  var evasion = await _server("path-evasion", false);
  var agent = new https.Agent({ ca: [control.rootCa], keepAlive: false });
  try {
    var ok = await _requestWithAgent(control.port, agent);
    check("httpClient opts.agent control: an operator agent trusting the root reaches the control chain",
          ok.status === 200, JSON.stringify(ok));
    var refused = await _requestWithAgent(bad.port, agent);
    check("httpClient opts.agent: an operator agent's dial refuses a chain whose intermediate's private key is 1",
          refused.status === null && refused.code === "tls/compromised-key", JSON.stringify(refused));
    var hidden = await _requestWithAgent(evasion.port, agent);
    check("httpClient opts.agent: a chain hiding the compromised issuing CA behind a decoy root is refused",
          hidden.status === null && hidden.code === "tls/server-chain-unverifiable", JSON.stringify(hidden));
  } finally {
    agent.destroy();
    httpClientLib._resetForTest();
    await _close(control.server);
    await _close(bad.server);
    await _close(evasion.server);
  }
}

// An operator agent that sets its own checkServerIdentity keeps it, and the
// chain check runs around it.
async function testOperatorAgentWithItsOwnIdentityCheck() {
  b.network.tls._resetForTest();
  var control = await _server("control", false);
  var bad = await _server("compromised", false);
  var seen = [];
  var agent = new https.Agent({ ca: [control.rootCa], keepAlive: false, checkServerIdentity: function (host, cert) {
    seen.push(host);
    return nodeTls.checkServerIdentity(host, cert);
  } });
  try {
    var ok = await _requestWithAgent(control.port, agent);
    check("httpClient opts.agent control: an agent with its own checkServerIdentity reaches the control chain",
          ok.status === 200 && seen.length === 1, JSON.stringify({ ok: ok, seen: seen }));
    var refused = await _requestWithAgent(bad.port, agent);
    check("httpClient opts.agent: an agent with its own checkServerIdentity refuses a chain whose intermediate's private key is 1",
          refused.status === null && refused.code === "tls/compromised-key", JSON.stringify(refused));
  } finally {
    agent.destroy();
    httpClientLib._resetForTest();
    await _close(control.server);
    await _close(bad.server);
  }
}

// Five sequential requests through one keep-alive agent built from
// applyToContext each open their own TLS connection to the server, and that
// agent's check still refuses the chain hiding the compromised issuing CA.
async function testOperatorAgentOpensAConnectionPerRequest() {
  b.network.tls._resetForTest();
  var control = await _server("control", false);
  var evasion = await _server("path-evasion", false);
  var agent = new https.Agent(b.network.tls.applyToContext({ role: "client",
    base: { ca: [control.rootCa], keepAlive: true } }));
  try {
    var statuses = [];
    for (var i = 0; i < 5; i += 1) statuses.push((await _requestWithAgent(control.port, agent)).status);
    check("httpClient opts.agent from applyToContext: five keep-alive requests answer 200, each over its own TLS connection",
          statuses.every(function (s) { return s === 200; }) && control.counts.connections === 5,
          JSON.stringify({ statuses: statuses, connections: control.counts.connections }));
    var hidden = await _requestWithAgent(evasion.port, agent);
    check("httpClient opts.agent from applyToContext: a chain hiding the compromised issuing CA is refused",
          hidden.status === null && hidden.code === "tls/server-chain-unverifiable", JSON.stringify(hidden));
  } finally {
    agent.destroy();
    httpClientLib._resetForTest();
    await _close(control.server);
    await _close(evasion.server);
  }
}

// b.httpClient through b.network.proxy: the request goes through the proxy's
// CONNECT tunnel, and the chain the target sends behind it is checked.
async function testThroughProxy() {
  var nt = b.network.tls;
  nt._resetForTest();
  var tunnels = 0;
  var sockets = [];
  var proxy = http.createServer();
  proxy.on("connect", function (req, client, head) {
    tunnels += 1;
    var parts = req.url.split(":");
    var up = net.connect(Number(parts[parts.length - 1]), "127.0.0.1", function () {
      client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (head && head.length) up.write(head);
      up.pipe(client);
      client.pipe(up);
    });
    sockets.push(up, client);
    up.on("error", function () { client.destroy(); });
    client.on("error", function () { up.destroy(); });
  });
  await new Promise(function (resolve) { proxy.listen(0, "127.0.0.1", resolve); });
  var control = await _server("control", false);
  var bad = await _server("compromised", false);
  var evasion = await _server("path-evasion", false);
  nt.addCa(control.rootCa, { label: "fixture-root", audit: false });
  b.network.proxy.set({ https: "http://127.0.0.1:" + proxy.address().port });
  try {
    var ok = await _request(control.port);
    check("httpClient through the proxy control: the control chain behind the tunnel answers 200",
          ok.status === 200 && tunnels === 1, JSON.stringify(ok) + " tunnels=" + tunnels);
    var refused = await _request(bad.port);
    check("httpClient through the proxy: a target chain whose intermediate's private key is 1 is refused with tls/compromised-key",
          refused.status === null && refused.code === "tls/compromised-key" && tunnels === 2,
          JSON.stringify(refused) + " tunnels=" + tunnels);
    var hidden = await _request(evasion.port);
    check("httpClient through the proxy: a target chain hiding the compromised issuing CA behind a decoy root is refused",
          hidden.status === null && hidden.code === "tls/server-chain-unverifiable", JSON.stringify(hidden));
    var before = { tunnels: tunnels, connections: control.counts.connections };
    var statuses = [];
    for (var i = 0; i < 4; i += 1) statuses.push((await _request(control.port)).status);
    check("httpClient through the proxy: each later request to the control server opens its own tunnel and TLS connection",
          statuses.every(function (s) { return s === 200; }) &&
            control.counts.connections === before.connections + 4 && tunnels === before.tunnels + 4,
          JSON.stringify({ statuses: statuses, before: before, tunnels: tunnels, connections: control.counts.connections }));
  } finally {
    b.network.proxy._resetForTest();
    nt._resetForTest();
    httpClientLib._resetForTest();
    sockets.forEach(function (s) { s.destroy(); });
    await _close(proxy);
    await _close(control.server);
    await _close(bad.server);
    await _close(evasion.server);
  }
}

function _agentGet(port, agent) {
  return new Promise(function (resolve) {
    var req = https.request({ host: "127.0.0.1", port: port, servername: "localhost", path: "/", agent: agent },
      function (res) { res.resume(); res.on("end", function () { resolve({ status: res.statusCode, code: null }); }); });
    req.on("error", function (e) { resolve({ status: null, code: (e && e.code) || String(e) }); });
    req.end();
  });
}

// b.pqcAgent.reloadCerts with a new ca: the agent's chain check reads its
// anchors from that ca, so a server under the new root is reached and a
// server under the old root is not.
async function testPqcAgentReloadedCa() {
  b.network.tls._resetForTest();
  var underNew = paths.crossChain("intermediate");
  var newServer = https.createServer({ key: underNew.key, cert: underNew.cert }, function (q, s) { s.end("ok"); });
  var oldServer = await _server("control", false);
  await new Promise(function (resolve) { newServer.listen(0, "127.0.0.1", resolve); });
  var agent = b.pqcAgent.create({ ca: [ck.certPem(ck.TLS_ROOT_DER)], keepAlive: false });
  try {
    var before = await _agentGet(oldServer.port, agent);
    check("pqcAgent control: the agent reaches a server under the ca it was built with",
          before.status === 200, JSON.stringify(before));
    var direct = paths.crossChain("direct");
    agent.reloadCerts({ cert: direct.cert, key: direct.key, ca: [underNew.anchor] });
    var after = await _agentGet(newServer.address().port, agent);
    check("pqcAgent.reloadCerts: after a new ca, the agent reaches a server under the new root",
          after.status === 200, JSON.stringify(after));
    var old = await _agentGet(oldServer.port, agent);
    check("pqcAgent.reloadCerts: after a new ca, a server under the old root is not reached",
          old.status === null, JSON.stringify(old));
  } finally {
    agent.destroy();
    await _close(newServer);
    await _close(oldServer.server);
  }
}

var TESTS = [testHttp2, testHttp1, testOperatorAgent, testOperatorAgentWithItsOwnIdentityCheck, testOperatorAgentOpensAConnectionPerRequest, testThroughProxy,
  testPqcAgentReloadedCa];

async function run() {
  for (var i = 0; i < TESTS.length; i += 1) await TESTS[i]();
}

module.exports = { run: run, TESTS: TESTS };

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); process.exit(0); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
