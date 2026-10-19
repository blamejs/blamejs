// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A listener given a bracketed IPv6 literal ("[::1]", the form a URL
 * authority carries) binds the address, as the bare form does. Linux
 * getaddrinfo refuses the bracketed text with ENOTFOUND; Windows resolves it,
 * so this file reproduces only on Linux (the container smoke leg).
 *
 * Covers b.router listen(), b.testing.listenOnRandomPort and the shared mail
 * listener behind b.mail.server.mx (and the other mail servers).
 */

var nodeNet  = require("node:net");
var nodeHttp = require("node:http");
var nodeTls  = require("node:tls");

var helpers = require("../helpers");
var check   = helpers.check;
var b       = helpers.b;

function _canListenOnLoopbackV6() {
  return new Promise(function (resolve) {
    var s = nodeNet.createServer();
    s.once("error", function (e) { resolve(e); });
    s.listen(0, "::1", function () { s.close(function () { resolve(null); }); });
  });
}

function _connect(port) {
  return new Promise(function (resolve) {
    var sock = nodeNet.connect({ host: "::1", port: port });
    sock.once("connect", function () { sock.destroy(); resolve(true); });
    sock.once("error", function () { resolve(false); });
  });
}

function _close(server) {
  return new Promise(function (resolve) { server.close(function () { resolve(); }); });
}

async function testRouterListensOnBracketedIpv6() {
  var router = b.router.create();
  router.get("/", function (req, res) { res.end("ok"); });
  var server = null;
  var err = null;
  try {
    server = await new Promise(function (resolve, reject) {
      var s = router.listen(0, function () { resolve(s); }, undefined, "[::1]");
      s.once("error", reject);
    });
  } catch (e) { err = e; }
  check("b.router listen() binds a bracketed IPv6 host ([::1])",
    server !== null && server.address() && server.address().address === "::1",
    err ? err.code + " " + err.message : JSON.stringify(server && server.address()));
  if (server) {
    check("b.router listener on [::1] accepts a connection", await _connect(server.address().port));
    await _close(server);
  }
}

async function testListenOnRandomPortBracketedIpv6() {
  var server = nodeHttp.createServer(function (req, res) { res.end("ok"); });
  var port = null;
  var err = null;
  try { port = await b.testing.listenOnRandomPort(server, "[::1]"); }
  catch (e) { err = e; }
  check("b.testing.listenOnRandomPort binds a bracketed IPv6 host ([::1])",
    typeof port === "number" && server.address().address === "::1",
    err ? err.code + " " + err.message : JSON.stringify(server.address()));
  if (port !== null) await _close(server);
}

async function _makeTlsContext() {
  var ca = await b.mtlsEngine.generateCa({ name: "listen-v6-test-ca" });
  var leaf = await b.mtlsEngine.signClientCert({
    cn:           "mx.test",
    caCertPem:    ca.caCertPem,
    caKeyPem:     ca.caKeyPem,
    usage:        "server",
    sans:         ["DNS:mx.test", "IP:::1"],
    validityDays: 1,
  });
  return nodeTls.createSecureContext({ key: leaf.key, cert: leaf.cert });
}

async function testMailListenerBracketedIpv6() {
  var ctx = await _makeTlsContext();
  var srv = b.mail.server.mx.create({ tlsContext: ctx, profile: "permissive", localDomains: [] });
  var info = null;
  var err = null;
  try { info = await srv.listen({ port: 0, address: "[::1]" }); }
  catch (e) { err = e; }
  check("b.mail.server.mx listen() binds a bracketed IPv6 address ([::1])",
    info !== null && typeof info.port === "number",
    err ? err.code + " " + err.message : JSON.stringify(info));
  if (info !== null) {
    check("mx listener on [::1] accepts a connection", await _connect(info.port));
    await srv.close();
  }
}

async function run() {
  var v6 = await _canListenOnLoopbackV6();
  if (v6 !== null) {
    helpers.unavailable("listen on [::1]", "cannot listen on ::1: " + v6.code);
    return;
  }
  await testRouterListensOnBracketedIpv6();
  await testListenOnRandomPortBracketedIpv6();
  await testMailListenerBracketedIpv6();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("[listen-bracketed-ipv6] OK - " + helpers.getChecks() + " checks passed"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
