// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A refused IMAP command line that opened a literal still consumes the
 * literal's octets, so the payload is never parsed as protocol.
 *
 * `b.mail.server.imap` read a line, handed it to `b.guardImapCommand`, and on
 * a refusal wrote `BAD` and returned without arming `state.pendingLiteral`.
 * The connection stayed in command mode while the client sent the literal it
 * had announced, so those octets arrived as ordinary lines and were executed
 * as commands. RFC 7888 makes this reachable without any cooperation from the
 * server: a non-synchronizing literal `{N+}` needs no continuation, so the
 * client sends the payload immediately and the refusal does not stop it.
 * Bytes the sender presented as message data became protocol, which is a
 * parser desynchronization: RFC 9051 §2.2 has the octets after a literal
 * opener belong to that command, not to the command stream.
 *
 * Three refusal paths returned that way: the guard's own refusal, the
 * oversize-literal refusal and the pre-authentication refusal. The octets are
 * consumed only for `{N+}`, which is the form whose payload is already in
 * flight; for `{N}` the client is waiting for a continuation the refusal never
 * sends, so consuming N octets there would eat the client's next command.
 */

var helpers = require("../helpers");
var check   = helpers.check;
var b       = helpers.b;
var nodeNet = require("node:net");
var nodeTls = require("node:tls");

// The listener takes no implicit plaintext mode, so a context is built even
// though these connections stay on the plaintext port and never STARTTLS.
async function _tlsContext() {
  var ca = await b.mtlsEngine.generateCa({ name: "imap-refused-literal-test-ca" });
  var leaf = await b.mtlsEngine.signClientCert({
    cn:           "imap.test",
    caCertPem:    ca.caCertPem,
    caKeyPem:     ca.caKeyPem,
    usage:        "server",
    sans:         ["DNS:imap.test", "DNS:localhost", "IP:127.0.0.1"],
    validityDays: 1,
  });
  return nodeTls.createSecureContext({ key: leaf.key, cert: leaf.cert });
}

function _mailStore() {
  return {
    appendMessage: function () { return Promise.resolve(); },
    selectFolder:  function () {
      return Promise.resolve({ uidvalidity: 1, modseq: 1, exists: 0,
                               recent: 0, unseen: 0, flags: [] });
    },
  };
}

async function _open(createOpts) {
  var srv = b.mail.server.imap.create(Object.assign({
    tlsContext: await _tlsContext(),
    mailStore: _mailStore(),
    profile:   "permissive",
    auth:      {
      mechanisms: ["PLAIN"],
      verify: function () {
        return Promise.resolve({ ok: true, actor: { id: "u1", mailboxes: ["INBOX"] } });
      },
    },
  }, createOpts || {}));
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var socket = nodeNet.connect(info.port, "127.0.0.1");
  await new Promise(function (r) { socket.once("connect", r); });
  var seen = "";
  socket.on("data", function (c) { seen += c.toString("utf8"); });
  await helpers.waitUntil(function () { return /\* OK/.test(seen); },
    { timeoutMs: 5000, label: "imap refused-literal: greeting" });
  return {
    srv: srv, socket: socket,
    text: function () { return seen; },
    send: function (bytes) { socket.write(bytes); },
    close: async function () {
      try { socket.destroy(); } catch (_e) { /* best-effort */ }
      try { await srv.close(); } catch (_e) { /* best-effort */ }
    },
  };
}

// The payload a refused opener announces: a complete, correctly tagged
// command, so if the connection reads it as protocol the transcript carries
// `z9 ` and there is no other way for that tag to appear. The literal's
// octets are the command text alone; the CRLF after them terminates the
// command line that opened the literal, which is how a client frames `{N+}`.
var SMUGGLED = "z9 NOOP";
var SMUGGLED_BYTES = SMUGGLED.length;

async function testAGuardRefusalConsumesTheLiteral() {
  // `LOGIN {5+}` opens a LITERAL+ the guard refuses (RFC 7888 forbids it
  // pre-authentication), so the five octets that follow are the literal's,
  // not a command.
  var c = await _open();
  try {
    c.send("a1 LOGIN {" + SMUGGLED_BYTES + "+}\r\n" + SMUGGLED + "\r\na2 CAPABILITY\r\n");
    await helpers.waitUntil(function () { return /^a2 /m.test(c.text()); },
      { timeoutMs: 5000, label: "imap refused-literal: a2 answered" });
    var transcript = c.text();
    check("the opener is refused", /BAD .*LITERAL\+ refused/.test(transcript),
          transcript.slice(0, 200));
    check("the smuggled command is not executed",
          transcript.indexOf("z9 ") === -1, transcript.slice(0, 400));
    check("the literal's octets do not reach the parser at all",
          (transcript.match(/\* BAD/g) || []).length === 1, transcript.slice(0, 400));
    check("the connection resynchronizes, so the next real command answers",
          /^a2 OK/m.test(transcript), transcript.slice(0, 400));
  } finally { await c.close(); }
}

async function testAnOversizeLiteralConsumesNothingAndDoesNotExecute() {
  // The oversize path knows the size but refuses the command. Consuming a
  // literal larger than the cap would mean reading what the cap exists to
  // refuse, so the connection closes instead: a byte stream that cannot be
  // located again is not recoverable.
  var c = await _open({ maxLiteralBytes: 16 });
  try {
    c.send("b1 APPEND INBOX {64+}\r\n" + "x".repeat(64) + "\r\nz9 NOOP\r\n");
    await helpers.waitUntil(function () {
      return /b1 (NO|BAD)/.test(c.text()) || c.socket.destroyed;
    }, { timeoutMs: 5000, label: "imap refused-literal: oversize answered" });
    await helpers.passiveObserve(300, "imap refused-literal: nothing further executes");
    var transcript = c.text();
    check("the oversize literal is refused",
          /b1 (NO|BAD)/.test(transcript) || /BYE/.test(transcript),
          transcript.slice(0, 200));
    check("nothing after it is executed as a command",
          transcript.indexOf("z9 ") === -1, transcript.slice(0, 400));
  } finally { await c.close(); }
}

async function testARefusedSynchronizingLiteralDoesNotEatTheNextCommand() {
  // The counterpart, and the reason the discard is armed only for `{N+}`.
  // RFC 9051 §2.2.2 has a client announcing `{N}` wait for the `+` a refusal
  // never sends, so no payload is in flight; a conformant client sends its
  // next command instead. Discarding N octets there would consume that
  // command, turning the fix into the same desynchronization in the other
  // direction.
  var c = await _open();
  try {
    c.send("c1 APPEND INBOX {" + SMUGGLED_BYTES + "}\r\n");
    await helpers.waitUntil(function () {
      return /(c1 (NO|BAD))|(\* BAD)/.test(c.text());
    }, { timeoutMs: 5000, label: "imap refused-literal: sync literal answered" });
    c.send("c2 CAPABILITY\r\n");
    await helpers.waitUntil(function () { return /^c2 /m.test(c.text()); },
      { timeoutMs: 5000, label: "imap refused-literal: next command answered" });
    var transcript = c.text();
    check("the synchronizing literal is refused",
          /(c1 (NO|BAD))|(\* BAD)/.test(transcript), transcript.slice(0, 200));
    check("no continuation is offered for a refused literal",
          transcript.indexOf("\r\n+ ") === -1, transcript.slice(0, 400));
    check("the conformant client's next command is answered, not eaten",
          /^c2 OK/m.test(transcript), transcript.slice(0, 400));
  } finally { await c.close(); }
}

async function run() {
  await testAGuardRefusalConsumesTheLiteral();
  await testAnOversizeLiteralConsumesNothingAndDoesNotExecute();
  await testARefusedSynchronizingLiteralDoesNotEatTheNextCommand();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[mail-server-imap-refused-literal] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
