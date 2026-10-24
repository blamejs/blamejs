// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.wsClient.connect refuses a compromised key on a wss:// dial: a
 * `tlsOpts.ca` whose key anyone can hold throws ws-client/compromised-key, one
 * returned by `tlsOptsFor` is reported on `error` with the same code, and a
 * server whose verified chain carries a compromised key is reported as
 * tls/compromised-key before the upgrade request is written. Each refusal has
 * a control that differs only in the key.
 */

var nodeTls = require("node:tls");
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
  var seen = { upgrades: 0 };
  var sockets = [];
  var server = nodeTls.createServer({ key: chain.key, cert: chain.cert }, function (s) {
    sockets.push(s);
    s.on("error", function () { /* the client tears the socket down */ });
    s.once("data", function (d) { if (/^GET /.test(d.toString("latin1"))) seen.upgrades += 1; });
  });
  server.on("tlsClientError", function () { /* the client refused the chain */ });
  return new Promise(function (resolve) {
    server.listen(0, "127.0.0.1", function () {
      resolve({ port: server.address().port, rootCa: chain.rootCa, seen: seen,
        close: function () {
          sockets.forEach(function (s) { s.destroy(); });
          return new Promise(function (r) { server.close(function () { r(); }); });
        } });
    });
  });
}

async function _dial(port, opts) {
  var c = b.wsClient.connect("wss://localhost:" + port + "/", Object.assign({
    reconnect: false, audit: false, allowInternal: true, handshakeTimeoutMs: 1500,
  }, opts));
  var err = null;
  c.on("error", function (e) { if (!err) err = e; });
  await helpers.waitUntil(function () { return err !== null; },
    { timeoutMs: 8000, label: "ws-client compromised key: dial settles" });
  try { c._teardown(b.wsClient.CLOSE_NORMAL, "", false); } catch (_e) { /* best-effort */ }
  return err;
}

async function testTlsOptsCa() {
  var c = b.wsClient.connect("wss://127.0.0.1:1/", { reconnect: false, audit: false, allowInternal: true,
    tlsOpts: { ca: CONTROL_CA_PEM } });
  var err = null;
  c.on("error", function (e) { if (!err) err = e; });
  check("wsClient.connect control: an ordinary tlsOpts.ca is accepted", c && typeof c.send === "function");
  await helpers.waitUntil(function () { return err !== null; },
    { timeoutMs: 8000, label: "ws-client compromised key: control dial to a closed port settles" });
  var bad = null;
  var code = _codeOf(function () {
    bad = b.wsClient.connect("wss://127.0.0.1:1/", { reconnect: false, audit: false, allowInternal: true,
      tlsOpts: { ca: COMPROMISED_CA_PEM } });
  });
  if (bad) bad.on("error", function () { /* the client was built; its dial to port 1 fails */ });
  check("wsClient.connect: a tlsOpts.ca whose private key is 1 throws ws-client/compromised-key",
        code === "ws-client/compromised-key", code);
}

async function testTlsOptsForCa() {
  var control = await _server("control");
  try {
    var okErr = await _dial(control.port, { tlsOptsFor: function () { return { ca: control.rootCa }; } });
    check("wsClient tlsOptsFor control: an ordinary ca reaches the upgrade request",
          control.seen.upgrades === 1 && okErr.code === "ws-client/handshake-timeout", okErr.code + " " + okErr.message);
    var badErr = await _dial(control.port, { tlsOptsFor: function () { return { ca: COMPROMISED_CA_PEM }; } });
    check("wsClient tlsOptsFor: a ca whose private key is 1 is reported as ws-client/compromised-key before the dial",
          badErr.code === "ws-client/compromised-key" && control.seen.upgrades === 1, badErr.code + " " + badErr.message);
  } finally {
    await control.close();
  }
}

async function testServerChain() {
  var control = await _server("control");
  var bad = await _server("compromised");
  try {
    var okErr = await _dial(control.port, { tlsOpts: { ca: control.rootCa } });
    check("wsClient control: the control chain reaches the upgrade request",
          control.seen.upgrades === 1 && okErr.code === "ws-client/handshake-timeout", okErr.code + " " + okErr.message);
    var badErr = await _dial(bad.port, { tlsOpts: { ca: bad.rootCa } });
    check("wsClient: a server chain whose intermediate's private key is 1 is refused with tls/compromised-key",
          badErr.code === "tls/compromised-key" && bad.seen.upgrades === 0, badErr.code + " " + badErr.message);
  } finally {
    await control.close();
    await bad.close();
  }
}

var TESTS = [testTlsOptsCa, testTlsOptsForCa, testServerChain];

async function run() {
  for (var i = 0; i < TESTS.length; i += 1) await TESTS[i]();
}

module.exports = { run: run, TESTS: TESTS };

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
