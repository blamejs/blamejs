// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A refused ManageSieve command that announced a literal still consumes the
 * literal's octets, so the payload is never parsed as protocol.
 *
 * The same shape the IMAP listener carried: `PUTSCRIPT` answers
 * `NO "AUTHENTICATE first"` for an unauthenticated client and returns without
 * arming `state.pendingLiteral`, so the script the client announced arrives as
 * ordinary lines and is executed as commands. RFC 5804 §4 makes a `{N+}`
 * literal non-synchronizing, so the client sends the octets without waiting
 * and the refusal does not stop them. Measured before the fix: an
 * unauthenticated `PUTSCRIPT "x" {11+}` followed by `NOOP "zzz9"` answered
 * `OK (TAG "zzz9") "NOOP completed"`.
 *
 * The octets are consumed only for `{N+}`. A synchronizing `{N}` waits for the
 * `OK` that a refusal never sends, so nothing is in flight and consuming would
 * eat the client's next command.
 */

var helpers = require("../helpers");
var check   = helpers.check;
var b       = helpers.b;
var nodeNet = require("node:net");
var nodeTls = require("node:tls");

async function _tlsContext() {
  var ca = await b.mtlsEngine.generateCa({ name: "managesieve-refused-literal-ca" });
  var leaf = await b.mtlsEngine.signClientCert({
    cn:           "sieve.test",
    caCertPem:    ca.caCertPem,
    caKeyPem:     ca.caKeyPem,
    usage:        "server",
    sans:         ["DNS:sieve.test", "IP:127.0.0.1"],
    validityDays: 1,
  });
  return nodeTls.createSecureContext({ key: leaf.key, cert: leaf.cert });
}

async function _open() {
  var srv = b.mail.server.managesieve.create({
    tlsContext: await _tlsContext(),
    mailStore:  { sieveScripts: {
      put:       function () { return Promise.resolve({ ok: true }); },
      list:      function () { return Promise.resolve([]); },
      haveSpace: function () { return Promise.resolve({ ok: true }); },
    } },
    auth: { mechanisms: ["PLAIN"], verify: function () {
      return Promise.resolve({ ok: true, actor: { id: "u1" } });
    } },
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var socket = nodeNet.connect(info.port, "127.0.0.1");
  await new Promise(function (r) { socket.once("connect", r); });
  var seen = "";
  socket.on("data", function (c) { seen += c.toString("utf8"); });
  await helpers.waitUntil(function () { return /OK "blamejs ManageSieve ready"/.test(seen); },
    { timeoutMs: 5000, label: "managesieve refused-literal: banner" });
  return {
    socket: socket,
    text:  function () { return seen; },
    send:  function (bytes) { socket.write(bytes); },
    close: async function () {
      try { socket.destroy(); } catch (_e) { /* best-effort */ }
      try { await srv.close(); } catch (_e) { /* best-effort */ }
    },
  };
}

// A complete command whose tag echoes back only if it was executed.
var SMUGGLED = 'NOOP "zzz9"';

async function testARefusedPutscriptConsumesItsLiteral() {
  var c = await _open();
  try {
    c.send('PUTSCRIPT "x" {' + SMUGGLED.length + '+}\r\n' + SMUGGLED + "\r\n");
    await helpers.waitUntil(function () { return /NO /.test(c.text()); },
      { timeoutMs: 5000, label: "managesieve refused-literal: refusal" });
    await helpers.passiveObserve(400, "managesieve refused-literal: no smuggled execution");
    var transcript = c.text();
    check("the unauthenticated PUTSCRIPT is refused",
          /NO "AUTHENTICATE first"/.test(transcript), transcript.slice(-200));
    check("the announced script is not executed as a command",
          transcript.indexOf("zzz9") === -1, transcript.slice(-300));
  } finally { await c.close(); }
}

async function testTheConnectionResynchronizesAfterTheDiscard() {
  var c = await _open();
  try {
    c.send('PUTSCRIPT "x" {' + SMUGGLED.length + '+}\r\n' + SMUGGLED + "\r\n");
    await helpers.waitUntil(function () { return /NO /.test(c.text()); },
      { timeoutMs: 5000, label: "managesieve refused-literal: refusal before resync" });
    c.send('NOOP "after"\r\n');
    await helpers.waitUntil(function () { return /"after"/.test(c.text()); },
      { timeoutMs: 5000, label: "managesieve refused-literal: next command answered" });
    var transcript = c.text();
    check("a real command after the discard is answered",
          /OK \(TAG "after"\)/.test(transcript), transcript.slice(-200));
    check("and the smuggled one still never ran",
          transcript.indexOf("zzz9") === -1, transcript.slice(-300));
  } finally { await c.close(); }
}

async function run() {
  await testARefusedPutscriptConsumesItsLiteral();
  await testTheConnectionResynchronizesAfterTheDiscard();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[mail-server-managesieve-refused-literal] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
