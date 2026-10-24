// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.pqcAgent refuses a compromised key: create({ ca }) and
 * agent.reloadCerts({ ca }) throw pqcagent/compromised-key for a CA whose
 * private key anyone can hold, and a request through an agent refuses a server
 * whose verified chain carries a compromised key. Each refusal has a control
 * that differs only in the key.
 */

var https   = require("node:https");
var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var ck      = require("../helpers/compromised-keys");

var COMPROMISED_CA_PEM = ck.certPem(ck.P384_COMPROMISED_CA_DER);
var CONTROL_CA_PEM     = ck.certPem(ck.P384_CONTROL_CA_DER);

function _codeOf(fn) {
  try { fn(); return null; } catch (e) { return (e && e.code) || String(e); }
}

function _server(which) {
  var chain = ck.tlsChain(which);
  var server = https.createServer({ key: chain.key, cert: chain.cert }, function (req, res) { res.end("hello"); });
  server.on("tlsClientError", function () { /* the client refused the chain */ });
  return new Promise(function (resolve) {
    server.listen(0, "127.0.0.1", function () { resolve({ server: server, port: server.address().port, rootCa: chain.rootCa }); });
  });
}

function _close(server) {
  server.closeAllConnections();
  return new Promise(function (resolve) { server.close(function () { resolve(); }); });
}

function _get(agent, port) {
  return new Promise(function (resolve) {
    var req = https.request({ host: "127.0.0.1", servername: "localhost", port: port, path: "/", agent: agent },
      function (res) { res.resume(); res.on("end", function () { resolve({ status: res.statusCode, code: null }); }); });
    req.on("error", function (e) { resolve({ status: null, code: (e && e.code) || e.message }); });
    req.end();
  });
}

function testCreateCa() {
  b.network.tls._resetForTest();
  var agent = b.pqcAgent.create({ ca: CONTROL_CA_PEM });
  check("pqcAgent.create control: an ordinary ca builds an agent", agent && agent.options.ca === CONTROL_CA_PEM);
  agent.destroy();
  check("pqcAgent.create: a ca whose private key is 1 throws pqcagent/compromised-key",
        _codeOf(function () { b.pqcAgent.create({ ca: COMPROMISED_CA_PEM }); }) === "pqcagent/compromised-key");
  check("pqcAgent.create: the listed eDellRoot as ca throws pqcagent/compromised-key",
        _codeOf(function () { b.pqcAgent.create({ ca: [CONTROL_CA_PEM, ck.EDELLROOT_CERT_PEM] }); }) ===
          "pqcagent/compromised-key");
}

function testReloadCertsCa() {
  b.network.tls._resetForTest();
  var chain = ck.tlsChain("control");
  var agent = b.pqcAgent.create();
  var ok = agent.reloadCerts({ cert: chain.cert, key: chain.key, ca: CONTROL_CA_PEM });
  check("agent.reloadCerts control: an ordinary ca is swapped in",
        ok && ok.reloaded === true && agent.options.ca === CONTROL_CA_PEM);
  check("agent.reloadCerts: a ca whose private key is 1 throws pqcagent/compromised-key and keeps the old ca",
        _codeOf(function () { agent.reloadCerts({ cert: chain.cert, key: chain.key, ca: COMPROMISED_CA_PEM }); }) ===
          "pqcagent/compromised-key" && agent.options.ca === CONTROL_CA_PEM);
  agent.destroy();
}

async function testAgentChain() {
  b.network.tls._resetForTest();
  var control = await _server("control");
  var bad = await _server("compromised");
  var agent = b.pqcAgent.create({ ca: control.rootCa, keepAlive: false });
  try {
    var ok = await _get(agent, control.port);
    check("pqcAgent control: a request through the agent reaches the control chain", ok.status === 200, JSON.stringify(ok));
    var refused = await _get(agent, bad.port);
    check("pqcAgent: a request through the agent refuses a chain whose intermediate's private key is 1",
          refused.status === null && refused.code === "tls/compromised-key", JSON.stringify(refused));
  } finally {
    agent.destroy();
    await _close(control.server);
    await _close(bad.server);
  }
}

var TESTS = [testCreateCa, testReloadCertsCa, testAgentChain];

async function run() {
  for (var i = 0; i < TESTS.length; i += 1) await TESTS[i]();
}

module.exports = { run: run, TESTS: TESTS };

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
