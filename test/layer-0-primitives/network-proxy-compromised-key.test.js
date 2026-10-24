// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.network.proxy.agentFor refuses a compromised key on the tunneled TLS dial:
 * a request `ca` whose key anyone can hold is refused with
 * proxy/compromised-key before the tunnel opens, and a target behind the proxy
 * whose verified chain carries a compromised key is refused with
 * tls/compromised-key. Each refusal has a control that differs only in the key.
 */

var http    = require("node:http");
var https   = require("node:https");
var net     = require("node:net");
var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var ck      = require("../helpers/compromised-keys");

var COMPROMISED_CA_PEM = ck.certPem(ck.P384_COMPROMISED_CA_DER);

function _listen(server) {
  return new Promise(function (resolve) { server.listen(0, "127.0.0.1", function () { resolve(server.address().port); }); });
}

function _close(server) {
  if (typeof server.closeAllConnections === "function") server.closeAllConnections();
  return new Promise(function (resolve) { server.close(function () { resolve(); }); });
}

async function _fixture() {
  var tunnels = { count: 0 };
  var proxy = http.createServer();
  var sockets = [];
  proxy.on("connect", function (req, client, head) {
    tunnels.count += 1;
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
  var servers = {};
  ["control", "compromised"].forEach(function (which) {
    var chain = ck.tlsChain(which);
    servers[which] = { server: https.createServer({ key: chain.key, cert: chain.cert },
      function (req, res) { res.end("hello"); }), rootCa: chain.rootCa };
    servers[which].server.on("tlsClientError", function () { /* the client refused the chain */ });
  });
  var proxyPort = await _listen(proxy);
  servers.control.port = await _listen(servers.control.server);
  servers.compromised.port = await _listen(servers.compromised.server);
  b.network.proxy.set({ https: "http://127.0.0.1:" + proxyPort });
  return {
    tunnels: tunnels, servers: servers,
    close: async function () {
      b.network.proxy._resetForTest();
      sockets.forEach(function (s) { s.destroy(); });
      await _close(proxy);
      await _close(servers.control.server);
      await _close(servers.compromised.server);
    },
  };
}

function _get(port, ca) {
  var url = "https://localhost:" + port + "/";
  var agent = b.network.proxy.agentFor(url);
  return new Promise(function (resolve) {
    var req = https.request({ host: "localhost", port: port, path: "/", agent: agent, ca: ca }, function (res) {
      res.resume();
      res.on("end", function () { resolve({ status: res.statusCode, code: null }); });
    });
    req.on("error", function (e) { resolve({ status: null, code: (e && e.code) || e.message }); });
    req.end();
  });
}

async function testRequestCa() {
  var fx = await _fixture();
  try {
    var ok = await _get(fx.servers.control.port, fx.servers.control.rootCa);
    check("proxy agentFor control: an ordinary request ca reaches the target through the tunnel",
          ok.status === 200 && fx.tunnels.count === 1, JSON.stringify(ok));
    var refused = await _get(fx.servers.control.port, COMPROMISED_CA_PEM);
    check("proxy agentFor: a request ca whose private key is 1 is refused with proxy/compromised-key before a tunnel opens",
          refused.status === null && refused.code === "proxy/compromised-key" && fx.tunnels.count === 1,
          JSON.stringify(refused) + " tunnels=" + fx.tunnels.count);
  } finally {
    await fx.close();
  }
}

async function testTunneledChain() {
  var fx = await _fixture();
  try {
    var ok = await _get(fx.servers.control.port, fx.servers.control.rootCa);
    check("proxy agentFor control: the control chain behind the proxy is accepted", ok.status === 200, JSON.stringify(ok));
    var refused = await _get(fx.servers.compromised.port, fx.servers.compromised.rootCa);
    check("proxy agentFor: a target chain whose intermediate's private key is 1 is refused with tls/compromised-key",
          refused.status === null && refused.code === "tls/compromised-key", JSON.stringify(refused));
  } finally {
    await fx.close();
  }
}

async function testHttpsProxyHop() {
  var nt = b.network.tls;
  nt._resetForTest();
  var results = {};
  var whichList = ["control", "compromised"];
  for (var i = 0; i < whichList.length; i += 1) {
    var which = whichList[i];
    var chain = ck.tlsChain(which);
    var proxy = https.createServer({ key: chain.key, cert: chain.cert });
    proxy.on("tlsClientError", function () { /* the client refused the chain */ });
    proxy.on("connect", function (req, client) { client.end("HTTP/1.1 403 Forbidden\r\n\r\n"); });
    var port = await _listen(proxy);
    nt.addCa(chain.rootCa, { label: "fixture-root", audit: false });
    b.network.proxy.set({ https: "https://127.0.0.1:" + port });
    results[which] = await _get(443, undefined);
    b.network.proxy._resetForTest();
    nt._resetForTest();
    await _close(proxy);
  }
  check("proxy https hop control: the control proxy chain is accepted and its CONNECT reply read",
        results.control.code === "proxy/connect-failed", JSON.stringify(results.control));
  check("proxy https hop: a proxy chain whose intermediate's private key is 1 is refused with tls/compromised-key",
        results.compromised.code === "tls/compromised-key", JSON.stringify(results.compromised));
}

var TESTS = [testRequestCa, testTunneledChain, testHttpsProxyHop];

async function run() {
  for (var i = 0; i < TESTS.length; i += 1) await TESTS[i]();
}

module.exports = { run: run, TESTS: TESTS };

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
