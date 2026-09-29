// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A closing IMAP connection delivers what it wrote before the socket goes.
 *
 * A listener that calls `end()` and `destroy()` in the same turn loses
 * everything still queued. On plain TCP a small write usually reaches the
 * kernel buffer synchronously and survives, but a `TLSSocket` holds its own
 * write buffer above the TCP socket, so destroying the wrapper drops
 * ciphertext that has not been handed down yet. Everything this listener
 * says at the moment it closes is exactly what would be lost: the untagged
 * `BYE`, the tagged `LOGOUT` completion RFC 9051 section 6.1.3 requires, and
 * an `[ALERT]`, which RFC 9051 section 7.1 says a client MUST show its user.
 *
 * The listener closes through `mailServerNet.destroySocketAfterFlush`,
 * which passes a callback to `end()` and only destroys once the flush
 * reports done, under a grace timer so a peer that stops reading cannot hold
 * the socket open. This drives a real TLS connection through `LOGOUT` and
 * reads what actually arrives, because the difference between the two
 * teardowns is invisible on plain TCP and only shows over TLS.
 */

var helpers = require("../helpers");
var check   = helpers.check;
var b       = helpers.b;
var nodeTls = require("node:tls");

async function _tlsServerContext() {
  var ca = await b.mtlsEngine.generateCa({ name: "imap-close-flush-ca" });
  var leaf = await b.mtlsEngine.signClientCert({
    cn:           "imap.test",
    caCertPem:    ca.caCertPem,
    caKeyPem:     ca.caKeyPem,
    usage:        "server",
    sans:         ["DNS:imap.test", "DNS:localhost", "IP:127.0.0.1"],
    validityDays: 1,
  });
  return {
    context: nodeTls.createSecureContext({ key: leaf.key, cert: leaf.cert }),
    caPem:   ca.caCertPem,
  };
}

async function _openImplicitTls() {
  var tls = await _tlsServerContext();
  var srv = b.mail.server.imap.create({
    tlsContext:  tls.context,
    implicitTls: true,
    profile:     "permissive",
    mailStore:   {
      appendMessage: function () { return Promise.resolve(); },
      selectFolder:  function () {
        return Promise.resolve({ uidvalidity: 1, modseq: 1, exists: 0,
                                 recent: 0, unseen: 0, flags: [] });
      },
    },
    auth: {
      mechanisms: ["PLAIN"],
      verify: function () {
        return Promise.resolve({ ok: true, actor: { id: "u1", mailboxes: ["INBOX"] } });
      },
    },
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var socket = nodeTls.connect({
    port: info.port, host: "127.0.0.1", servername: "imap.test", ca: [tls.caPem],
  });
  await new Promise(function (resolve, reject) {
    socket.once("secureConnect", resolve);
    socket.once("error", reject);
  });
  var seen = "";
  var ended = false;
  socket.on("data", function (c) { seen += c.toString("utf8"); });
  socket.on("close", function () { ended = true; });
  await helpers.waitUntil(function () { return /\* OK/.test(seen); },
    { timeoutMs: 5000, label: "imap close-flush: greeting over TLS" });
  return {
    srv: srv, socket: socket,
    text:  function () { return seen; },
    ended: function () { return ended; },
    send:  function (line) { socket.write(line + "\r\n"); },
    close: async function () {
      try { socket.destroy(); } catch (_e) { /* best-effort */ }
      try { await srv.close(); } catch (_e) { /* best-effort */ }
    },
  };
}

async function testLogoutDeliversItsByeAndCompletionOverTls() {
  var c = await _openImplicitTls();
  try {
    c.send("a1 LOGOUT");
    await helpers.waitUntil(function () { return c.ended() || /^a1 /m.test(c.text()); },
      { timeoutMs: 5000, label: "imap close-flush: logout answered or socket closed" });
    var transcript = c.text();
    check("the untagged BYE arrives before the socket goes",
          /^\* BYE/m.test(transcript), JSON.stringify(transcript));
    check("and so does the tagged LOGOUT completion RFC 9051 6.1.3 requires",
          /^a1 OK/m.test(transcript), JSON.stringify(transcript));
  } finally { await c.close(); }
}

async function testTheConnectionIsActuallyClosedAfterwards() {
  // Flushing must not mean lingering: the socket still has to go, or a peer
  // that never reads holds a connection slot open.
  var c = await _openImplicitTls();
  try {
    c.send("a1 LOGOUT");
    await helpers.waitUntil(function () { return c.ended(); },
      { timeoutMs: 8000, label: "imap close-flush: socket closed after logout" });
    check("the socket is closed once the diagnostics are out", c.ended() === true);
  } finally { await c.close(); }
}

async function testTheGraceIsBoundedWhenThePeerStopsReading() {
  // destroySocketAfterFlush arms a timer so a peer that
  // never drains cannot keep the socket alive; the tear-down happens either
  // way.
  var torn = false;
  var fake = {
    once: function (event, fn) { if (event === "close") this._onClose = fn; },
    end:  function () { /* never calls back: the flush never completes */ },
    destroy: function () { torn = true; },
  };
  var mailServerNet = require("../../lib/mail-server-net.js");
  mailServerNet.destroySocketAfterFlush(fake, { graceMs: 25 });
  check("a flush that never completes has not torn the socket down yet",
        torn === false);
  await helpers.waitUntil(function () { return torn; },
    { timeoutMs: 3000, label: "imap close-flush: grace timer fires" });
  check("and the grace timer destroys it anyway", torn === true);
}

async function run() {
  await testLogoutDeliversItsByeAndCompletionOverTls();
  await testTheConnectionIsActuallyClosedAfterwards();
  await testTheGraceIsBoundedWhenThePeerStopsReading();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[mail-server-imap-close-flush] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
