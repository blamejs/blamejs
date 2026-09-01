// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.mail.server.submission — outbound SMTP submission listener.
 *
 * Tests cover opts validation, AUTH-required posture under strict
 * profile, AUTH-needs-TLS gate (RFC 4954 §4), identity-binding,
 * and the multi-step verify hook contract. Error / defensive /
 * adversarial branches are also driven over a real localhost listener:
 * wrong-state and malformed-command refusals, AUTH failure modes and
 * per-IP rate-limits, tenant scoping, STARTTLS / implicit-TLS postures,
 * DKIM-required modes, recipient policy, size and line limits, DATA
 * smuggling refusals, idle-timeout, and close() drain.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

var nodeNet = require("node:net");
var nodeTls = require("node:tls");

async function _makeTestTlsContext() {
  var ca = await b.mtlsEngine.generateCa({ name: "submission-bdat-test-ca" });
  var leaf = await b.mtlsEngine.signClientCert({
    cn:           "submission.test",
    caCertPem:    ca.caCertPem,
    caKeyPem:     ca.caKeyPem,
    usage:        "server",
    sans:         ["DNS:submission.test", "DNS:localhost", "IP:127.0.0.1"],
    validityDays: 1,
  });
  return nodeTls.createSecureContext({ key: leaf.key, cert: leaf.cert });
}

async function _readGreeting(socket) {
  return new Promise(function (resolve, reject) {
    var buf = "";
    function onData(chunk) {
      buf += chunk.toString("utf8");
      if (buf.indexOf("\r\n") !== -1) {
        socket.removeListener("data", onData);
        resolve(buf);
      }
    }
    socket.on("data", onData);
    socket.once("error", reject);
  });
}

async function _sendCommand(socket, line) {
  return new Promise(function (resolve, reject) {
    var buf = "";
    function onData(chunk) {
      buf += chunk.toString("utf8");
      if (buf.indexOf("\r\n") !== -1) {
        var lines = buf.split("\r\n").filter(Boolean);
        var last = lines[lines.length - 1];
        if (/^\d{3} /.test(last)) {
          socket.removeListener("data", onData);
          resolve(buf);
        }
      }
    }
    socket.on("data", onData);
    socket.once("error", reject);
    socket.write(line + "\r\n");
  });
}

// Send the BDAT command line + the payload bytes in one go (the byte
// stream after the CRLF is consumed verbatim per RFC 3030).
async function _sendBdat(socket, payload, isLast) {
  return new Promise(function (resolve, reject) {
    var buf = "";
    function onData(chunk) {
      buf += chunk.toString("utf8");
      var lines = buf.split("\r\n").filter(Boolean);
      var last = lines[lines.length - 1];
      if (/^\d{3} /.test(last)) {
        socket.removeListener("data", onData);
        resolve(buf);
      }
    }
    socket.on("data", onData);
    socket.once("error", reject);
    var payloadBuf = Buffer.isBuffer(payload) ? payload : Buffer.from(payload, "utf8");
    socket.write("BDAT " + payloadBuf.length + (isLast ? " LAST" : "") + "\r\n");
    socket.write(payloadBuf);
  });
}

function testSurface() {
  check("submission.create is fn",
    typeof b.mail.server.submission.create === "function");
  check("MailServerSubmissionError is fn",
    typeof b.mail.server.submission.MailServerSubmissionError === "function");
}

function testCreateRequiresTlsContext() {
  var threw = null;
  try { b.mail.server.submission.create({}); } catch (e) { threw = e; }
  check("submission.create refuses missing tlsContext",
    threw && threw.code === "mail-server-submission/no-tls-context");
}

function testStrictProfileRequiresAuthConfig() {
  var threw = null;
  try {
    b.mail.server.submission.create({
      tlsContext: {},
      // no auth config — strict default refuses
    });
  } catch (e) { threw = e; }
  check("strict profile refuses missing auth config",
    threw && threw.code === "mail-server-submission/no-auth");
}

function testPermissiveAllowsNoAuth() {
  var threw = null;
  try {
    b.mail.server.submission.create({
      tlsContext: {},
      profile:    "permissive",
    });
  } catch (e) { threw = e; }
  check("permissive accepts no auth (operator-acknowledged legacy)",
    threw === null);
}

function testBadAuthShapeRefused() {
  var threw = null;
  try {
    b.mail.server.submission.create({
      tlsContext: {},
      auth:       { mechanisms: [], verify: function () {} },
    });
  } catch (e) { threw = e; }
  check("empty mechanisms refused",
    threw && threw.code === "mail-server-submission/bad-auth");

  threw = null;
  try {
    b.mail.server.submission.create({
      tlsContext: {},
      auth:       { mechanisms: ["PLAIN"], verify: "not-a-fn" },
    });
  } catch (e) { threw = e; }
  check("non-function verify refused",
    threw && threw.code === "mail-server-submission/bad-auth");
}

function testBadBoundsRefused() {
  function expectBad(label, opts) {
    var threw = null;
    try { b.mail.server.submission.create(opts); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf("mail-server-submission/") === 0);
  }
  expectBad("negative maxLineBytes refused",
    { tlsContext: {}, profile: "permissive", maxLineBytes: -1 });
  expectBad("non-finite idleTimeoutMs refused",
    { tlsContext: {}, profile: "permissive", idleTimeoutMs: Infinity });
}

async function _makePermissiveServer() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { return null; }
  var handoffs = [];
  var agent = {
    handoff: function (env) {
      handoffs.push(env);
      return Promise.resolve({ messageId: "<test@bdat>" });
    },
  };
  var srv = b.mail.server.submission.create({
    tlsContext: ctx,
    profile:    "permissive",
    agent:      agent,
  });
  return { srv: srv, handoffs: handoffs };
}

async function testEhloAdvertisesChunking() {
  var bundle = await _makePermissiveServer();
  if (!bundle) { check("BDAT CHUNKING advertised (skipped — no TLS ctx)", true); return; }
  var srv = bundle.srv;
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  try {
    var socket = nodeNet.connect(info.port, "127.0.0.1");
    await new Promise(function (r) { socket.once("connect", r); });
    await _readGreeting(socket);
    var ehlo = await _sendCommand(socket, "EHLO client.example.com");
    check("EHLO advertises CHUNKING",          /250.CHUNKING/.test(ehlo));
    socket.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                  // allow:raw-time-literal — test-only short drain
}

async function testBdatSingleLastChunk() {
  var bundle = await _makePermissiveServer();
  if (!bundle) { check("BDAT single LAST chunk (skipped)", true); return; }
  var srv = bundle.srv;
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  try {
    var socket = nodeNet.connect(info.port, "127.0.0.1");
    await new Promise(function (r) { socket.once("connect", r); });
    await _readGreeting(socket);
    await _sendCommand(socket, "EHLO client.example.com");
    await _sendCommand(socket, "MAIL FROM:<sender@example.com>");
    await _sendCommand(socket, "RCPT TO:<recipient@example.com>");
    var body = "From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: BDAT test\r\n\r\nHello BDAT.";
    var reply = await _sendBdat(socket, body, true);
    check("BDAT LAST replies 250",             /^250 /m.test(reply));
    check("BDAT handed off to agent",          bundle.handoffs.length === 1);
    check("BDAT body bytes match exactly",
          bundle.handoffs[0] && bundle.handoffs[0].body.toString("utf8") === body);
    socket.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                  // allow:raw-time-literal — test-only short drain
}

// The DATA branch refuses a body carrying the CVE-2023-51764 smuggling shape
// (a dot-line whose boundary is anything other than canonical CRLF). The BDAT
// branch ran no such screen, so the SAME body that DATA answers 554 to was
// accepted 250 when it arrived in chunks, and handed to the agent for storage
// and relay.
//
// Why the screen belongs on a length-framed path at all: BDAT counts its
// octets, so a dot-line cannot terminate THAT transfer early. It matters
// because the body is RELAYED onward and the next hop is usually DATA — the
// screen is about what the body CONTAINS, not how it arrived. Framing changes
// downstream; content does not.
async function testBdatRefusesSmuggledBody() {
  var bundle = await _makePermissiveServer();
  if (!bundle) { check("BDAT smuggling screen (skipped)", true); return; }
  var srv = bundle.srv;
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  try {
    // A bare-LF dot-line: `\n.\r\n`. A lenient receiver downstream ends the
    // message there and reads what follows as fresh SMTP commands.
    var smuggled = Buffer.concat([
      Buffer.from("From: sender@example.com\r\nTo: recipient@example.com\r\n" +
                  "Subject: BDAT smuggle\r\n\r\nbody", "latin1"),
      Buffer.from([0x0A, 0x2E, 0x0D, 0x0A]),                                                            // "\n.\r\n"
      Buffer.from("MAIL FROM:<attacker@evil.example>\r\n", "latin1"),
    ]);

    var socket = nodeNet.connect(info.port, "127.0.0.1");
    await new Promise(function (r) { socket.once("connect", r); });
    await _readGreeting(socket);
    await _sendCommand(socket, "EHLO client.example.com");
    await _sendCommand(socket, "MAIL FROM:<sender@example.com>");
    await _sendCommand(socket, "RCPT TO:<recipient@example.com>");
    var reply = await _sendBdat(socket, smuggled, true);
    check("BDAT: a smuggled dot-line body is refused 554",
          /^554 /m.test(reply), JSON.stringify(reply));
    check("BDAT: the refusal names the smuggling class",
          /5\.7\.0/.test(reply), JSON.stringify(reply));
    check("BDAT: the smuggled body never reached the agent",
          bundle.handoffs.length === 0, String(bundle.handoffs.length));
    socket.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                  // allow:raw-time-literal — test-only short drain

  // The OTHER BDAT exit: send the smuggled body as a non-final chunk and
  // terminate with `BDAT 0 LAST`. That path takes the same accumulated
  // collector and reaches the agent too, so screening only the sized-LAST
  // chunk would leave this open — which is the shape of the original bug one
  // level down.
  var zeroBundle = await _makePermissiveServer();
  if (zeroBundle) {
    var zInfo = await zeroBundle.srv.listen({ port: 0, address: "127.0.0.1" });
    try {
      var zBody = Buffer.concat([
        Buffer.from("From: sender@example.com\r\nTo: recipient@example.com\r\n\r\nbody", "latin1"),
        Buffer.from([0x0A, 0x2E, 0x0D, 0x0A]),                                                          // "\n.\r\n"
      ]);
      var z = nodeNet.connect(zInfo.port, "127.0.0.1");
      await new Promise(function (r) { z.once("connect", r); });
      await _readGreeting(z);
      await _sendCommand(z, "EHLO client.example.com");
      await _sendCommand(z, "MAIL FROM:<sender@example.com>");
      await _sendCommand(z, "RCPT TO:<recipient@example.com>");
      await _sendBdat(z, zBody, false);                       // non-final chunk carries the payload
      var zReply = await _sendBdat(z, Buffer.alloc(0), true); // zero-length LAST terminates it
      check("BDAT: a smuggled body terminated by a zero-length LAST is refused",
            /^554 /m.test(zReply), JSON.stringify(zReply));
      check("BDAT: and it never reached the agent either",
            zeroBundle.handoffs.length === 0, String(zeroBundle.handoffs.length));
      z.destroy();
    } finally { await zeroBundle.srv.close({ timeoutMs: 1000 }); }                                      // allow:raw-time-literal — test-only short drain
  }

  // Control: an ordinary body still goes through on the same path, so the
  // screen refuses a smuggling shape rather than refusing BDAT.
  var ok = await _makePermissiveServer();
  if (!ok) return;
  var okInfo = await ok.srv.listen({ port: 0, address: "127.0.0.1" });
  try {
    var s2 = nodeNet.connect(okInfo.port, "127.0.0.1");
    await new Promise(function (r) { s2.once("connect", r); });
    await _readGreeting(s2);
    await _sendCommand(s2, "EHLO client.example.com");
    await _sendCommand(s2, "MAIL FROM:<sender@example.com>");
    await _sendCommand(s2, "RCPT TO:<recipient@example.com>");
    var clean = "From: sender@example.com\r\nTo: recipient@example.com\r\n\r\nordinary body\r\n";
    var okReply = await _sendBdat(s2, clean, true);
    check("BDAT control: an ordinary body is still accepted",
          /^250 /m.test(okReply), JSON.stringify(okReply));
    check("BDAT control: and still reaches the agent", ok.handoffs.length === 1);
    s2.destroy();
  } finally { await ok.srv.close({ timeoutMs: 1000 }); }                                                // allow:raw-time-literal — test-only short drain
}

async function testBdatMultipleChunksThenLast() {
  var bundle = await _makePermissiveServer();
  if (!bundle) { check("BDAT multiple chunks (skipped)", true); return; }
  var srv = bundle.srv;
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  try {
    var socket = nodeNet.connect(info.port, "127.0.0.1");
    await new Promise(function (r) { socket.once("connect", r); });
    await _readGreeting(socket);
    await _sendCommand(socket, "EHLO client.example.com");
    await _sendCommand(socket, "MAIL FROM:<a@example.com>");
    await _sendCommand(socket, "RCPT TO:<b@example.com>");
    var part1 = "From: a@x\r\nTo: b@x\r\nSubject: Multi-chunk\r\n\r\n";
    var part2 = "First chunk of body.\r\n";
    var part3 = "Second chunk concludes.";
    var r1 = await _sendBdat(socket, part1, false);
    check("first BDAT chunk replies 250",       /^250 /m.test(r1));
    var r2 = await _sendBdat(socket, part2, false);
    check("second BDAT chunk replies 250",      /^250 /m.test(r2));
    var r3 = await _sendBdat(socket, part3, true);
    check("BDAT LAST replies 250",              /^250 /m.test(r3));
    check("agent received concatenated body",
          bundle.handoffs[0].body.toString("utf8") === part1 + part2 + part3);
    socket.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                  // allow:raw-time-literal — test-only short drain
}

async function testBdatZeroByteLast() {
  var bundle = await _makePermissiveServer();
  if (!bundle) { check("BDAT zero-byte LAST (skipped)", true); return; }
  var srv = bundle.srv;
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  try {
    var socket = nodeNet.connect(info.port, "127.0.0.1");
    await new Promise(function (r) { socket.once("connect", r); });
    await _readGreeting(socket);
    await _sendCommand(socket, "EHLO client.example.com");
    await _sendCommand(socket, "MAIL FROM:<a@example.com>");
    await _sendCommand(socket, "RCPT TO:<b@example.com>");
    var body = "From: a@x\r\nTo: b@x\r\nSubject: Body in chunk 1 only\r\n\r\nAll bytes here.";
    await _sendBdat(socket, body, false);
    var r = await _sendCommand(socket, "BDAT 0 LAST");
    check("zero-byte BDAT LAST replies 250",    /^250 /m.test(r));
    check("agent received chunk-1 body intact", bundle.handoffs[0].body.toString("utf8") === body);
    socket.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                  // allow:raw-time-literal — test-only short drain
}

async function testBdatOutsideTransaction() {
  var bundle = await _makePermissiveServer();
  if (!bundle) { check("BDAT outside transaction (skipped)", true); return; }
  var srv = bundle.srv;
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  try {
    var socket = nodeNet.connect(info.port, "127.0.0.1");
    await new Promise(function (r) { socket.once("connect", r); });
    await _readGreeting(socket);
    await _sendCommand(socket, "EHLO client.example.com");
    var r = await _sendCommand(socket, "BDAT 5 LAST");
    check("BDAT before MAIL FROM → 503",       /^503 /m.test(r));
    socket.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                  // allow:raw-time-literal — test-only short drain
}

async function testBdatBadArgs() {
  var bundle = await _makePermissiveServer();
  if (!bundle) { check("BDAT bad args (skipped)", true); return; }
  var srv = bundle.srv;
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  try {
    var socket = nodeNet.connect(info.port, "127.0.0.1");
    await new Promise(function (r) { socket.once("connect", r); });
    await _readGreeting(socket);
    await _sendCommand(socket, "EHLO client.example.com");
    await _sendCommand(socket, "MAIL FROM:<a@example.com>");
    await _sendCommand(socket, "RCPT TO:<b@example.com>");
    // guardSmtpCommand pre-validates BDAT shape → 500 5.5.2 (syntax)
    // before our handler returns 501 5.5.4. Either is a refusal.
    var r1 = await _sendCommand(socket, "BDAT");
    check("BDAT missing size refused",         /^5\d\d /m.test(r1));
    var r2 = await _sendCommand(socket, "BDAT abc");
    check("BDAT non-integer size refused",     /^5\d\d /m.test(r2));
    var r3 = await _sendCommand(socket, "BDAT 10 NOTLAST");
    check("BDAT invalid 3rd arg refused",      /^5\d\d /m.test(r3));
    var r4 = await _sendCommand(socket, "BDAT -5 LAST");
    check("BDAT negative size refused",        /^5\d\d /m.test(r4));
    socket.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                  // allow:raw-time-literal — test-only short drain
}

async function testBdatBinaryBytesPreserved() {
  // Codex P1 — BDAT payloads can be 8-bit / binary (BINARYMIME, MIME
  // attachments). The line-buffer drain MUST NOT round-trip bytes
  // through UTF-8 — invalid sequences get replaced with U+FFFD and
  // the body corrupts. Send a payload containing every non-CR/LF
  // byte value 0x00..0xFF and assert byte-for-byte equality.
  var bundle = await _makePermissiveServer();
  if (!bundle) { check("BDAT binary bytes preserved (skipped)", true); return; }
  var srv = bundle.srv;
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  try {
    var socket = nodeNet.connect(info.port, "127.0.0.1");
    await new Promise(function (r) { socket.once("connect", r); });
    await _readGreeting(socket);
    await _sendCommand(socket, "EHLO client.example.com");
    await _sendCommand(socket, "MAIL FROM:<a@example.com>");
    await _sendCommand(socket, "RCPT TO:<b@example.com>");
    // RFC 822-shaped header + binary body (every byte except CR/LF
    // in the body slot). Header MUST end with CRLF CRLF; the binary
    // section starts after.
    var header = Buffer.from(
      "From: a@example.com\r\nTo: b@example.com\r\nSubject: bin\r\n" +
      "Content-Type: application/octet-stream\r\n\r\n", "utf8");
    var binBytes = [];
    for (var i = 0; i < 256; i += 1) {
      // Skip 0x0A/0x0D — bare CR/LF inside a BDAT header section
      // would still be invalid SMTP, but for the body any byte is
      // legal under BINARYMIME.
      binBytes.push(i);
    }
    var body = Buffer.concat([header, Buffer.from(binBytes)]);
    var reply = await _sendBdat(socket, body, true);
    check("BDAT LAST with binary body → 250",   /^250 /m.test(reply));
    check("agent received body length",        bundle.handoffs[0] && bundle.handoffs[0].body.length === body.length);
    // Byte-for-byte equality
    var same = bundle.handoffs[0].body.equals(body);
    check("agent received body byte-equal",    same === true);
    socket.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                  // allow:raw-time-literal — test-only short drain
}

// The AUTH guards read state the verify writes, and the verify is
// asynchronous. The line loop holds the client's pipelined remainder for the
// sender-policy hook; it has to hold it here too, or two credential exchanges
// written in one segment are both dispatched while the session is still
// unauthenticated.
async function testPipelinedAuthCannotRaceTheSubmissionGuard() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("submission pipelined AUTH (skipped)", true); return; }
  var verifies = 0;
  var srv = b.mail.server.submission.create({
    tlsContext: ctx,
    profile:    "permissive",
    auth: { mechanisms: ["PLAIN"], verify: function () {
      verifies += 1;
      return Promise.resolve({ ok: true, actor: { id: "u1", username: "alice" } });
    } },
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  try {
    var socket = nodeNet.connect(info.port, "127.0.0.1");
    await new Promise(function (r) { socket.once("connect", r); });
    await _readGreeting(socket);
    await _sendCommand(socket, "EHLO client.example.com");

    var seen = "";
    socket.on("data", function (c) { seen += c.toString("utf8"); });
    var plain = Buffer.from(NUL + "alice" + NUL + "pw", "utf8").toString("base64");
    // One write, no waiting between them.
    socket.write("AUTH PLAIN " + plain + "\r\nAUTH PLAIN " + plain + "\r\n");
    await helpers.waitUntil(function () {
      return seen.split("\r\n").filter(function (l) { return l.length > 0; }).length >= 2;
    }, { timeoutMs: 5000, label: "submission pipelined AUTH: two replies" });
    await helpers.passiveObserve(300, "submission pipelined AUTH: settle");

    var replies = seen.split("\r\n").filter(function (l) { return l.length > 0; });
    var accepted = replies.filter(function (l) { return l.indexOf("235") === 0; });
    check("a pipelined second AUTH does not authenticate again",
          accepted.length <= 1, JSON.stringify(replies));
    check("and the second exchange is not verified concurrently with the first",
          verifies <= 1, String(verifies));
    socket.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                  // allow:raw-time-literal — test-only short drain
}

// Refusing the pipelined backlog destroys the socket, and the command that was
// already waiting on a verdict resumes the drain when it answers. Unless the
// close marks the SESSION, that resume reads the buffer the refusal was about
// and runs it: a transaction pipelined behind an AUTH reaches the agent on a
// connection the server refused and closed.
async function testRefusedBacklogDoesNotFinalizeAfterTheVerdict() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("submission refused backlog (skipped)", true); return; }
  var release   = null;
  var gate      = new Promise(function (r) { release = r; });
  var handoffs  = [];
  var srv = b.mail.server.submission.create({
    tlsContext: ctx,
    profile:    "permissive",
    // The aggregate bound is maxLineBytes * (maxRcptsPerMsg + 4). Both are set
    // small so a short flood clears it, and the per-line bound (maxLineBytes
    // * 4) stays well above the longest line the test sends.
    maxLineBytes:       100,                                                                           // allow:raw-byte-literal — 400-byte per-line bound, far above any line here
    maxRcptsPerMessage: 2,
    agent: { handoff: function (env) { handoffs.push(env); return Promise.resolve({ messageId: "<x@t>" }); } },
    // The mailbox matters: without an assigned send-as identity the queued
    // MAIL FROM is refused on its own merits and the test would pass whether
    // or not the reader had stopped.
    auth: { mechanisms: ["PLAIN"], verify: function () {
      return gate.then(function () {
        return { ok: true, actor: { id: "alice@example.com", mailboxes: ["alice@example.com"] } };
      });
    } },
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  try {
    var socket = nodeNet.connect(info.port, "127.0.0.1");
    await new Promise(function (r) { socket.once("connect", r); });
    await _readGreeting(socket);
    await _sendCommand(socket, "EHLO client.example.com");

    var seen = "";
    socket.on("data", function (c) { seen += c.toString("utf8"); });

    // Hold the reader on a credential check that will not finish.
    var plain = Buffer.from(NUL + "alice" + NUL + "pw", "utf8").toString("base64");
    socket.write("AUTH PLAIN " + plain + "\r\n");
    await helpers.passiveObserve(120, "submission refused backlog: verify in flight");

    // Then overrun the allowance, with a whole transaction at the end of it.
    // Sized to clear the 600-byte bound and still fit in ONE segment: the
    // refusal destroys the socket, which stops the reader, so bytes in a later
    // segment never arrive and the transaction has to be in the buffer the
    // refusal is about.
    var flood = "";
    for (var i = 0; i < 110; i += 1) flood += "NOOP\r\n";
    socket.write(flood +
      "MAIL FROM:<alice@example.com>\r\n" +
      "RCPT TO:<b@example.com>\r\n" +
      "BDAT 5 LAST\r\nhello");
    await helpers.waitUntil(function () { return /Too many pipelined bytes/.test(seen); },
      { timeoutMs: 5000, label: "submission refused backlog: refusal written" });

    // Release the verdict the reader was waiting on. Its continuation must not
    // pick the queue back up.
    release();
    await helpers.passiveObserve(500, "submission refused backlog: nothing resumes");
    check("a transaction queued behind a refused backlog does not reach the agent",
          handoffs.length === 0, JSON.stringify(handoffs.length));
    socket.destroy();
  } finally { if (release) release(); await srv.close({ timeoutMs: 1000 }); }                           // allow:raw-time-literal — test-only short drain
}

// A session also ends without the listener deciding it. A peer that pipelines
// a transaction behind a command still waiting on a verdict and then hangs up
// leaves nothing to mark the session, so the verdict's continuation resumes
// the drain and the message reaches the agent on a connection that is gone.
async function testAPeerHangUpStopsTheDrain() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("submission peer hang-up (skipped)", true); return; }
  var release  = null;
  var gate     = new Promise(function (r) { release = r; });
  var handoffs = [];
  var srv = b.mail.server.submission.create({
    tlsContext: ctx,
    profile:    "permissive",
    agent: { handoff: function (env) { handoffs.push(env); return Promise.resolve({ messageId: "<x@t>" }); } },
    auth: { mechanisms: ["PLAIN"], verify: function () {
      return gate.then(function () {
        return { ok: true, actor: { id: "alice@example.com", mailboxes: ["alice@example.com"] } };
      });
    } },
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  try {
    var socket = nodeNet.connect(info.port, "127.0.0.1");
    await new Promise(function (r) { socket.once("connect", r); });
    await _readGreeting(socket);
    await _sendCommand(socket, "EHLO client.example.com");

    // The credential check parks the reader; the whole transaction is queued
    // behind it in the same segment.
    var plain = Buffer.from(NUL + "alice" + NUL + "pw", "utf8").toString("base64");
    socket.write("AUTH PLAIN " + plain + "\r\n" +
      "MAIL FROM:<alice@example.com>\r\n" +
      "RCPT TO:<b@example.com>\r\n" +
      "BDAT 5 LAST\r\nhello");
    await helpers.passiveObserve(200, "submission peer hang-up: verify in flight");

    socket.destroy();
    await helpers.passiveObserve(300, "submission peer hang-up: the close is delivered");
    release();
    await helpers.passiveObserve(500, "submission peer hang-up: nothing resumes");
    check("a transaction queued behind a verdict does not reach the agent after a hang-up",
          handoffs.length === 0, JSON.stringify(handoffs.length));
  } finally { if (release) release(); await srv.close({ timeoutMs: 1000 }); }                           // allow:raw-time-literal — test-only short drain
}

async function testBdatOversizeRefused() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("BDAT oversize (skipped)", true); return; }
  // Tight 1 KiB cap so the test runs fast.
  var srv = b.mail.server.submission.create({
    tlsContext:      ctx,
    profile:         "permissive",
    maxMessageBytes: 1024,                                                                             // allow:raw-byte-literal — tight test cap to exercise size refusal
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  try {
    var socket = nodeNet.connect(info.port, "127.0.0.1");
    await new Promise(function (r) { socket.once("connect", r); });
    await _readGreeting(socket);
    await _sendCommand(socket, "EHLO client.example.com");
    await _sendCommand(socket, "MAIL FROM:<a@example.com>");
    await _sendCommand(socket, "RCPT TO:<b@example.com>");
    var r = await _sendCommand(socket, "BDAT 99999 LAST");
    check("BDAT exceeds cap → 552",            /^552 /m.test(r));
    socket.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                  // allow:raw-time-literal — test-only short drain
}

var NUL = String.fromCharCode(0);
var LF  = String.fromCharCode(10);
var CR  = String.fromCharCode(13);

// ---- socket plumbing ----

function _readReply(socket) {
  return new Promise(function (resolve, reject) {
    var buf = "";
    function onData(chunk) {
      buf += chunk.toString("utf8");
      // A complete SMTP reply always ends with CRLF; only then is its
      // final line the terminal "NNN <text>" (a multiline reply's earlier
      // lines are "NNN-<text>"). Requiring the trailing CRLF prevents
      // resolving on a chunk boundary that happens to split mid-reply.
      if (!/\r\n$/.test(buf)) return;
      var lines = buf.split("\r\n").filter(Boolean);
      var last = lines[lines.length - 1];
      if (last && /^\d{3} /.test(last)) {
        socket.removeListener("data", onData);
        socket.removeListener("error", onErr);
        resolve(buf);
      }
    }
    function onErr(e) {
      socket.removeListener("data", onData);
      reject(e);
    }
    socket.on("data", onData);
    socket.once("error", onErr);
  });
}

function _send(socket, line) {
  var p = _readReply(socket);
  socket.write(line + "\r\n");
  return p;
}

// Write raw bytes and read the next reply (for DATA-body payloads).
function _writeRaw(socket, bytes) {
  var p = _readReply(socket);
  socket.write(bytes);
  return p;
}

// DATA command → 354 → dot-terminated body → final reply.
async function _dataDot(socket, body) {
  await _send(socket, "DATA");
  return _writeRaw(socket, body + "\r\n.\r\n");
}

async function _makeTestTlsContextWithCa() {
  var ca = await b.mtlsEngine.generateCa({ name: "submission-wire-test-ca" });
  var leaf = await b.mtlsEngine.signClientCert({
    cn:           "submission.test",
    caCertPem:    ca.caCertPem,
    caKeyPem:     ca.caKeyPem,
    usage:        "server",
    sans:         ["DNS:submission.test", "DNS:localhost", "IP:127.0.0.1"],
    validityDays: 1,
  });
  return {
    ctx:   nodeTls.createSecureContext({ key: leaf.key, cert: leaf.cert }),
    caPem: ca.caCertPem,
  };
}

// Build + listen a submission server sharing the test TLS context.
async function _mk(tls, extra) {
  var handoffs = [];
  var opts = { tlsContext: tls.ctx };
  if (extra) { Object.keys(extra).forEach(function (k) { opts[k] = extra[k]; }); }
  var srv = b.mail.server.submission.create(opts);
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  return { srv: srv, port: info.port, caPem: tls.caPem, handoffs: handoffs };
}

function _agentCapturing(handoffs, mode) {
  return {
    handoff: function (env) {
      handoffs.push(env);
      if (mode === "reject") return Promise.reject(new Error("upstream down"));
      return Promise.resolve({ messageId: "<accepted@test>" });
    },
  };
}

function _connect(port) {
  var socket = nodeNet.connect(port, "127.0.0.1");
  socket.on("error", function () { /* swallow ECONNRESET on close */ });
  return new Promise(function (resolve, reject) {
    socket.once("connect", function () { resolve(socket); });
    socket.once("error", reject);
  });
}

async function _tlsUpgrade(rawSocket, caPem) {
  var tls = nodeTls.connect({ socket: rawSocket, ca: caPem, servername: "localhost" });
  tls.on("error", function () {});
  await new Promise(function (r, j) { tls.once("secureConnect", r); tls.once("error", j); });
  return tls;
}

// SASL PLAIN blob (authzid NUL authcid NUL passwd), base64.
function _saslPlain(user, pass) {
  return Buffer.from(["", user, pass].join(NUL), "utf8").toString("base64");
}

// ---- create() defensive branches ----

function testCreateValidation(tls) {
  function expect(label, opts, code) {
    var threw = null;
    try { b.mail.server.submission.create(opts); } catch (e) { threw = e; }
    check(label, threw && threw.code === code);
  }
  // Non-object opts.
  var threwObj = null;
  try { b.mail.server.submission.create(null); } catch (e) { threwObj = e; }
  check("null opts refused", threwObj && (threwObj.code || "").indexOf("mail-server-submission/") === 0);

  // Missing tlsContext.
  var threwTls = null;
  try { b.mail.server.submission.create({ profile: "permissive" }); } catch (e) { threwTls = e; }
  check("missing tlsContext refused", threwTls && threwTls.code === "mail-server-submission/no-tls-context");
  // Strict profile requires auth.
  expect("strict profile without auth refused",
    { tlsContext: tls.ctx }, "mail-server-submission/no-auth");
  // Bad auth.verify + bad mechanisms.
  expect("non-function auth.verify refused",
    { tlsContext: tls.ctx, auth: { verify: "nope" } }, "mail-server-submission/bad-auth");
  expect("empty auth.mechanisms refused",
    { tlsContext: tls.ctx, auth: { verify: function () {}, mechanisms: [] } }, "mail-server-submission/bad-auth");
  // Bad numeric bound.
  var threwBound = null;
  try { b.mail.server.submission.create({ tlsContext: tls.ctx, profile: "permissive", maxLineBytes: -1 }); } catch (e) { threwBound = e; }
  check("negative maxLineBytes refused", threwBound && (threwBound.code || "").indexOf("mail-server-submission/") === 0);

  expect("bad tenantScope (no check fn) refused",
    { tlsContext: tls.ctx, profile: "permissive", tenantScope: {}, agentTenantId: "t1" },
    "mail-server-submission/bad-tenant-scope");
  expect("tenantScope without agentTenantId refused",
    { tlsContext: tls.ctx, profile: "permissive", tenantScope: { check: function () {} } },
    "mail-server-submission/no-agent-tenant-id");
  expect("bad dkimRequireMode refused",
    { tlsContext: tls.ctx, profile: "permissive", dkimRequireMode: "sometimes" },
    "mail-server-submission/bad-dkim-require-mode");

  // guardDomain:false + guardDomain object both accepted at create.
  var okA = null, okB = null;
  try { b.mail.server.submission.create({ tlsContext: tls.ctx, profile: "permissive", guardDomain: false }); } catch (e) { okA = e; }
  try { b.mail.server.submission.create({ tlsContext: tls.ctx, profile: "permissive", guardDomain: { profile: "strict" } }); } catch (e) { okB = e; }
  check("guardDomain:false accepted", okA === null);
  check("guardDomain object accepted", okB === null);
}

async function testCloseBeforeListen(tls) {
  var srv = b.mail.server.submission.create({ tlsContext: tls.ctx, profile: "permissive" });
  var threw = null;
  try { await srv.close(); } catch (e) { threw = e; }
  check("close() before listen() is a no-op", threw === null);
  check("connectionCount is 0 before listen", srv.connectionCount() === 0);
  check("_portForTest is null before listen", srv._portForTest() === null);
}

async function testDoubleListen(tls) {
  var srv = b.mail.server.submission.create({ tlsContext: tls.ctx, profile: "permissive" });
  await srv.listen({ port: 0, address: "127.0.0.1" });
  try {
    check("_portForTest returns a bound port", typeof srv._portForTest() === "number" && srv._portForTest() > 0);
    var threw = null;
    try { await srv.listen({ port: 0, address: "127.0.0.1" }); } catch (e) { threw = e; }
    check("double listen() refused (already-listening)",
      threw && (threw.code || "").indexOf("mail-server-submission/") === 0);
  } finally { await srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }
}

// ---- permissive dispatch + wrong-state + malformed refusals ----

async function testPermissiveDispatch(tls) {
  var s = await _mk(tls, { profile: "permissive" });
  var sock = await _connect(s.port);
  try {
    check("greeting is 220", /^220 /.test(await _readReply(sock)));

    // Wrong-state before EHLO.
    check("MAIL before EHLO → 503",  /^503 /.test(await _send(sock, "MAIL FROM:<a@example.com>")));
    check("RCPT before MAIL → 503",  /^503 /.test(await _send(sock, "RCPT TO:<b@example.com>")));
    check("DATA before RCPT → 503",  /^503 /.test(await _send(sock, "DATA")));
    check("BDAT before MAIL → 503",  /^5\d\d /.test(await _send(sock, "BDAT 3 LAST")));

    // HELO single-line reply branch.
    check("HELO replies single 250", /^250 /.test(await _send(sock, "HELO client.example.com")));
    // EHLO multiline with STARTTLS advertised (plaintext port).
    var ehlo = await _send(sock, "EHLO client.example.com");
    check("EHLO advertises PIPELINING", /250[ -]PIPELINING/.test(ehlo));
    check("EHLO advertises STARTTLS (plaintext port)", /250[ -]STARTTLS/.test(ehlo));
    check("EHLO advertises CHUNKING", /250[ -]CHUNKING/.test(ehlo));

    // Simple verbs.
    check("NOOP → 250", /^250 /.test(await _send(sock, "NOOP")));
    check("VRFY → 502", /^502 /.test(await _send(sock, "VRFY alice")));
    check("EXPN → 502", /^502 /.test(await _send(sock, "EXPN list")));
    // Unknown verb passes guardSmtpCommand under permissive → switch default 500.
    check("unknown verb → 500", /^500 /.test(await _send(sock, "FLOOP arg")));
    // HELP is a guardSmtpCommand-known verb with no submission handler →
    // reaches the switch default (500 Unknown command).
    check("HELP → 500 (no handler)", /^500 /.test(await _send(sock, "HELP")));

    // Control-char / NUL / bare-LF / bare-CR refusals (guardSmtpCommand → 500).
    check("bare-LF in command → 500", /^500 /.test(await _writeRaw(sock, "NOOP" + LF + "X\r\n")));
    check("bare-CR in command → 500", /^500 /.test(await _writeRaw(sock, "NOOP" + CR + "X\r\n")));
    check("NUL in command → 500",     /^500 /.test(await _writeRaw(sock, "NOOP" + NUL + "X\r\n")));

    // RSET resets, QUIT closes.
    check("RSET → 250", /^250 /.test(await _send(sock, "RSET")));
    check("QUIT → 221", /^221 /.test(await _send(sock, "QUIT")));
  } finally { sock.destroy(); await s.srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }
}

// ---- domain hardening refusals (HELO / MAIL FROM / RCPT TO) ----

async function testDomainRefusals(tls) {
  var s = await _mk(tls, { profile: "permissive", guardDomain: { profile: "strict" } });
  var sock = await _connect(s.port);
  try {
    await _readReply(sock);
    // Bare-IPv4 domain refused (CVE-2021-22931 class) at HELO.
    check("EHLO bare-IP domain → 501", /^501 /.test(await _send(sock, "EHLO 10.0.0.1")));
    // Valid EHLO to advance.
    check("EHLO valid domain → 250", /^250[ -]/.test(await _send(sock, "EHLO client.example.com")));
    // MAIL FROM with bare-IP domain refused.
    check("MAIL FROM bare-IP domain → 501", /^501 /.test(await _send(sock, "MAIL FROM:<a@10.0.0.1>")));
    // Valid MAIL FROM.
    check("MAIL FROM valid → 250", /^250 /.test(await _send(sock, "MAIL FROM:<a@example.com>")));
    // RCPT TO with bare-IP domain refused.
    check("RCPT TO bare-IP domain → 501", /^501 /.test(await _send(sock, "RCPT TO:<b@127.0.0.1>")));
    check("RCPT TO valid → 250", /^250 /.test(await _send(sock, "RCPT TO:<b@example.com>")));
  } finally { sock.destroy(); await s.srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }
}

// ---- DATA path (audit-only + agent handoff success + agent reject) ----

async function testDataPaths(tls) {
  // Audit-only (no agent), permissive.
  var s1 = await _mk(tls, { profile: "permissive" });
  var sock = await _connect(s1.port);
  try {
    await _readReply(sock);
    await _send(sock, "EHLO client.example.com");
    await _send(sock, "MAIL FROM:<a@example.com>");
    await _send(sock, "RCPT TO:<b@example.com>");
    var body = "From: a@example.com\r\nTo: b@example.com\r\nSubject: hi\r\n\r\nHello.";
    check("DATA audit-only → 250", /^250 /.test(await _dataDot(sock, body)));
  } finally { sock.destroy(); await s1.srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }

  // Agent handoff resolves → outbound_routed 250.
  var h2 = [];
  var s2 = await _mk(tls, { profile: "permissive", agent: _agentCapturing(h2, "accept") });
  var sock2 = await _connect(s2.port);
  try {
    await _readReply(sock2);
    await _send(sock2, "EHLO client.example.com");
    await _send(sock2, "MAIL FROM:<a@example.com>");
    await _send(sock2, "RCPT TO:<b@example.com>");
    var reply = await _dataDot(sock2, "From: a@example.com\r\n\r\nbody");
    check("agent handoff accepted → 250 with id", /^250 .*accepted/.test(reply));
    check("agent received one handoff", h2.length === 1);
    check("handoff direction outbound", h2[0] && h2[0].direction === "outbound");
  } finally { sock2.destroy(); await s2.srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }

  // Agent handoff resolves without a messageId → 250 without id suffix.
  var hEmpty = [];
  var sEmpty = await _mk(tls, {
    profile: "permissive",
    agent: { handoff: function (env) { hEmpty.push(env); return Promise.resolve({}); } },
  });
  var sockE = await _connect(sEmpty.port);
  try {
    await _readReply(sockE);
    await _send(sockE, "EHLO client.example.com");
    await _send(sockE, "MAIL FROM:<a@example.com>");
    await _send(sockE, "RCPT TO:<b@example.com>");
    check("agent ack without messageId → 250", /^250 /.test(await _dataDot(sockE, "From: a@example.com\r\n\r\nx")));
  } finally { sockE.destroy(); await sEmpty.srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }

  // Agent handoff rejects → 451.
  var h3 = [];
  var s3 = await _mk(tls, { profile: "permissive", agent: _agentCapturing(h3, "reject") });
  var sock3 = await _connect(s3.port);
  try {
    await _readReply(sock3);
    await _send(sock3, "EHLO client.example.com");
    await _send(sock3, "MAIL FROM:<a@example.com>");
    await _send(sock3, "RCPT TO:<b@example.com>");
    check("agent handoff rejected → 451", /^451 /.test(await _dataDot(sock3, "From: a@example.com\r\n\r\nx")));
  } finally { sock3.destroy(); await s3.srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }

  await testAgentRefusalChoosesItsReply(tls);
}

// A refusal on policy grounds is permanent, and RFC 5321 §4.2.1 makes 4yz mean
// "retry" — so answering every rejection 451 tells a conforming MTA to retry a
// message that will be refused identically until its queue lifetime expires.
// The agent is the only party that knows which it is, so the rejection carries
// the answer and the listener writes it.
async function testAgentRefusalChoosesItsReply(tls) {
  function _rejectingWith(fields) {
    return { handoff: function () {
      var e = new Error("refused by policy");
      Object.keys(fields).forEach(function (k) { e[k] = fields[k]; });
      return Promise.reject(e);
    } };
  }
  async function _replyFor(fields) {
    var s = await _mk(tls, { profile: "permissive", agent: _rejectingWith(fields) });
    var sock = await _connect(s.port);
    try {
      await _readReply(sock);
      await _send(sock, "EHLO client.example.com");
      await _send(sock, "MAIL FROM:<a@example.com>");
      await _send(sock, "RCPT TO:<b@example.com>");
      return await _dataDot(sock, "From: a@example.com\r\n\r\nx");
    } finally { sock.destroy(); await s.srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }
  }

  var permanent = await _replyFor({
    smtpCode: "550", enhancedStatus: "5.7.1",
    replyText: "sender not authorised for that From address",
  });
  check("agent refusal: a permanent verdict answers 5yz",
    /^550 5\.7\.1 sender not authorised for that From address/.test(permanent), permanent);

  var transient = await _replyFor({ smtpCode: "452", enhancedStatus: "4.2.2" });
  check("agent refusal: a transient verdict keeps its own code",
    /^452 4\.2\.2 /.test(transient), transient);

  // A code outside 4yz/5yz is not a refusal a client can act on, and a 2yz
  // would tell the peer the message was accepted by the very call that
  // refused it.
  var bogus = await _replyFor({ smtpCode: "250", enhancedStatus: "2.0.0" });
  check("agent refusal: a non-failure code falls back to 451 4.3.0",
    /^451 4\.3\.0 /.test(bogus), bogus);

  // An enhanced status whose class contradicts the code is not usable either:
  // a peer parsing one gets the opposite verdict from the peer parsing the
  // other.
  var mismatched = await _replyFor({ smtpCode: "550", enhancedStatus: "4.7.1" });
  check("agent refusal: a contradictory enhanced status is replaced, code kept",
    /^550 5\.\d+\.\d+ /.test(mismatched), mismatched);

  // Operator prose reaches the wire, so a CR or LF in it would end the reply
  // line early and everything after would be read as a second server response.
  var injected = await _replyFor({
    smtpCode: "550", enhancedStatus: "5.7.1",
    replyText: "refused\r\n250 accepted",
  });
  check("agent refusal: injected line terminators do not reach the wire",
    /^550 5\.7\.1 /.test(injected) && injected.indexOf("250 accepted") === -1, injected);

  var bare = await _replyFor({});
  check("agent refusal: a plain rejection still answers 451 4.3.0",
    /^451 4\.3\.0 Local delivery error/.test(bare), bare);
}

// ---- BDAT extra branches (0-not-last ack, cumulative cap, DATA-before-RCPT) ----

async function testBdatBranches(tls) {
  var h = [];
  var s = await _mk(tls, { profile: "permissive", agent: _agentCapturing(h, "accept") });
  var sock = await _connect(s.port);
  try {
    await _readReply(sock);
    await _send(sock, "EHLO client.example.com");
    await _send(sock, "MAIL FROM:<a@example.com>");
    // BDAT with zero recipients → 503.
    check("BDAT with no rcpts → 503", /^503 /.test(await _send(sock, "BDAT 3 LAST")));
    await _send(sock, "RCPT TO:<b@example.com>");
    // Zero-byte non-last chunk → 250 "0 octets received".
    check("BDAT 0 (not last) → 250 0 octets", /^250 .*0 octets/.test(await _send(sock, "BDAT 0")));
    // A real chunk then LAST.
    var part = "From: a@example.com\r\n\r\npayload";
    var pbuf = Buffer.from(part, "utf8");
    var r = _readReply(sock);
    sock.write("BDAT " + pbuf.length + " LAST\r\n");
    sock.write(pbuf);
    check("BDAT LAST finalizes → 250", /^250 /.test(await r));
    await helpers.waitUntil(function () { return h.length >= 1; },
      { timeoutMs: 5000, label: "submission BDAT: agent handoff received after BDAT LAST" });
    check("agent got BDAT body", h.length === 1 && h[0].body.toString("utf8") === part);
  } finally { sock.destroy(); await s.srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }
}

// With the delimiter named, mail addressed to ok+tag@example.com is delivered
// to ok@example.com by this same server — so refusing it as a SENDER makes one
// identity give two answers, and the detail part is chosen by whoever writes
// the address, so it can never be enumerated into the set in advance. An MUA
// configured with a subaddress identity puts it in both From and MAIL FROM, so
// the account cannot send at all.
async function testSubaddressFoldingWhenConfigured(tls) {
  var s = await _mk(tls, {
    profile:             "permissive",
    identityBinding:     "strict",
    subaddressDelimiter: "+",
    auth: {
      mechanisms: ["PLAIN"],
      verify: function (mech, creds) {
        var parts = Buffer.from(creds.clientResponse || "", "base64").toString("utf8").split(NUL);
        return Promise.resolve({ ok: true,
          actor: { id: parts[1] + "@example.com", mailboxes: ["ok@example.com"] } });
      },
    },
  });
  var sock = await _connect(s.port);
  try {
    await _readReply(sock);
    await _send(sock, "EHLO client.example.com");
    await _send(sock, "AUTH PLAIN " + _saslPlain("ok", "pw"));
    check("subaddress: a tag on a mailbox in the set → 250",
      /^250 /.test(await _send(sock, "MAIL FROM:<ok+newsletter@example.com>")));
    check("subaddress: RSET → 250", /^250 /.test(await _send(sock, "RSET")));
    // The fold must not reach past the local part: a DIFFERENT mailbox whose
    // name merely starts with an entry in the set is not that entry.
    check("subaddress: a different mailbox is still refused",
      /^553 /.test(await _send(sock, "MAIL FROM:<oktober@example.com>")));
    check("subaddress: RSET again → 250", /^250 /.test(await _send(sock, "RSET")));
    // Nor past the domain: same local part, someone else's domain.
    check("subaddress: another domain is still refused",
      /^553 /.test(await _send(sock, "MAIL FROM:<ok+tag@evil.example>")));
    check("subaddress: RSET once more → 250", /^250 /.test(await _send(sock, "RSET")));
    // A different delimiter is a literal character, not a separator.
    check("subaddress: a qmail-style tag is not folded under a '+' delimiter",
      /^553 /.test(await _send(sock, "MAIL FROM:<ok-newsletter@example.com>")));
    check("subaddress: RSET before the case check → 250", /^250 /.test(await _send(sock, "RSET")));
    // The listener folds local-part case where it parses the address, which is
    // its own deployment-shaped choice and not the subaddress fold's. Both
    // halves still work together: a mixed-case subaddress of a mailbox in the
    // set is accepted.
    check("subaddress: a mixed-case subaddress of the same mailbox is accepted",
      /^250 /.test(await _send(sock, "MAIL FROM:<OK+Newsletter@Example.COM>")));
  } finally { sock.destroy(); await s.srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }
}

// The mailbox set is fixed at construction, so it cannot answer a question the
// consumer resolves per request: an alias that lands in this account's mailbox
// is an address it may legitimately speak for, and nothing in a frozen array
// can say so. `senderPolicy` is asked only after the set has declined.
async function testSenderPolicy(tls) {
  var asked = [];
  function _mkWithPolicy(policy) {
    return _mk(tls, {
      profile:         "permissive",
      identityBinding: "strict",
      senderPolicy:    policy,
      auth: {
        mechanisms: ["PLAIN"],
        verify: function (mech, creds) {
          var parts = Buffer.from(creds.clientResponse || "", "base64").toString("utf8").split(NUL);
          return Promise.resolve({ ok: true,
            actor: { id: parts[1] + "@example.com", mailboxes: ["ok@example.com"] } });
        },
      },
    });
  }
  async function _mailFrom(srv, addr) {
    var sock = await _connect(srv.port);
    try {
      await _readReply(sock);
      await _send(sock, "EHLO client.example.com");
      await _send(sock, "AUTH PLAIN " + _saslPlain("ok", "pw"));
      return await _send(sock, "MAIL FROM:<" + addr + ">");
    } finally { sock.destroy(); }
  }

  var sAllow = await _mkWithPolicy(function (ctx) {
    asked.push(ctx);
    return Promise.resolve({ ok: ctx.mailFrom === "alias@example.com" });
  });
  try {
    check("senderPolicy: an alias it accepts is allowed",
      /^250 /.test(await _mailFrom(sAllow, "alias@example.com")));
    check("senderPolicy: and it was asked with the address and the actor",
      asked.length === 1 && asked[0].mailFrom === "alias@example.com" &&
      asked[0].actor && asked[0].actor.id === "ok@example.com" &&
      asked[0].mailboxes.indexOf("ok@example.com") !== -1,
      JSON.stringify(asked[0] && { mailFrom: asked[0].mailFrom, mailboxes: asked[0].mailboxes }));
    check("senderPolicy: one it declines is still refused",
      /^553 /.test(await _mailFrom(sAllow, "someone@example.com")));
    // An address the set already covers must not reach it: a consumer that
    // supplies a policy should not be consulted on every ordinary send.
    var askedBefore = asked.length;
    check("senderPolicy: an address in the set is accepted without asking",
      /^250 /.test(await _mailFrom(sAllow, "ok@example.com")));
    check("senderPolicy: and the policy was not consulted for it",
      asked.length === askedBefore, String(asked.length - askedBefore));
  } finally { await sAllow.srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }

  // Fail-closed: this is the control that stops an authenticated account
  // sending as someone else, and a policy that could not decide has not
  // decided in the consumer's favour.
  var sThrow = await _mkWithPolicy(function () { throw new Error("policy backend down"); });
  try {
    check("senderPolicy: a throwing policy refuses rather than admits",
      /^553 /.test(await _mailFrom(sThrow, "alias@example.com")));
  } finally { await sThrow.srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }

  var sReject = await _mkWithPolicy(async function () { throw new Error("policy timed out"); });
  try {
    check("senderPolicy: a rejecting async policy refuses too",
      /^553 /.test(await _mailFrom(sReject, "alias@example.com")));
  } finally { await sReject.srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }

  // A verdict that is not the documented shape is not an acceptance.
  var sJunk = await _mkWithPolicy(function () { return Promise.resolve("yes"); });
  try {
    check("senderPolicy: a verdict that is not { ok: true } refuses",
      /^553 /.test(await _mailFrom(sJunk, "alias@example.com")));
  } finally { await sJunk.srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }

  // RFC 2920 PIPELINING: the client is entitled to send MAIL and RCPT in one
  // segment. While the policy is outstanding the listener must not answer past
  // the command waiting on it — a RCPT dispatched first gets "MAIL FROM first"
  // for a MAIL that is about to succeed, and the two replies arrive in the
  // wrong order.
  var release = null;
  var sPipelined = await _mkWithPolicy(function () {
    return new Promise(function (resolve) { release = function () { resolve({ ok: true }); }; });
  });
  var sockP = await _connect(sPipelined.port);
  try {
    await _readReply(sockP);
    await _send(sockP, "EHLO client.example.com");
    await _send(sockP, "AUTH PLAIN " + _saslPlain("ok", "pw"));
    // Collected line-by-line rather than through _readReply, which accumulates
    // until a terminal line and would swallow two replies arriving in one
    // chunk — which is exactly what correct ordering produces here.
    var pipelined = [];
    sockP.on("data", function (d) {
      String(d).split(/\r\n/).forEach(function (l) { if (l) pipelined.push(l); });
    });
    // Both commands in ONE write, so the second is already buffered when the
    // first yields.
    sockP.write("MAIL FROM:<alias@example.com>\r\nRCPT TO:<dest@example.com>\r\n");
    await helpers.waitUntil(function () { return release !== null; },
      { timeoutMs: 5000, label: "submission pipelining: senderPolicy was consulted" });
    await helpers.passiveObserve(200, "submission pipelining: nothing answered while the policy runs");
    check("pipelining: nothing is answered until the verdict lands",
      pipelined.length === 0, JSON.stringify(pipelined));
    release();
    await helpers.waitUntil(function () { return pipelined.length >= 2; },
      { timeoutMs: 5000, label: "submission pipelining: both replies" });
    check("pipelining: the MAIL verdict is answered first",
      /^250 2\.1\.0 /.test(pipelined[0]), JSON.stringify(pipelined));
    check("pipelining: and the RCPT behind it sees the sender that was accepted",
      /^250 2\.1\.5 /.test(pipelined[1]), JSON.stringify(pipelined));
  } finally { sockP.destroy(); await sPipelined.srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }

  // The same out-of-order answer by a different route: the client sends the
  // next command in a LATER segment, while the verdict is still outstanding.
  var release2 = null;
  var sLater = await _mkWithPolicy(function () {
    return new Promise(function (resolve) { release2 = function () { resolve({ ok: true }); }; });
  });
  var sockL = await _connect(sLater.port);
  try {
    await _readReply(sockL);
    await _send(sockL, "EHLO client.example.com");
    await _send(sockL, "AUTH PLAIN " + _saslPlain("ok", "pw"));
    var later = [];
    sockL.on("data", function (d) {
      String(d).split(/\r\n/).forEach(function (l) { if (l) later.push(l); });
    });
    sockL.write("MAIL FROM:<alias@example.com>\r\n");
    await helpers.waitUntil(function () { return release2 !== null; },
      { timeoutMs: 5000, label: "submission later-segment: senderPolicy was consulted" });
    sockL.write("RCPT TO:<dest@example.com>\r\n");   // a separate segment
    await helpers.passiveObserve(250, "submission later-segment: nothing answered while pending");
    check("later segment: nothing is answered until the verdict lands",
      later.length === 0, JSON.stringify(later));
    release2();
    await helpers.waitUntil(function () { return later.length >= 2; },
      { timeoutMs: 5000, label: "submission later-segment: both replies" });
    check("later segment: the MAIL verdict is still answered first",
      /^250 2\.1\.0 /.test(later[0]) && /^250 2\.1\.5 /.test(later[1]), JSON.stringify(later));
  } finally { sockL.destroy(); await sLater.srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }
  // Holding the pipeline must not turn the client's whole batch into one
  // over-long "line". A MAIL plus a page of near-limit RCPTs is an ordinary
  // PIPELINING client, and disconnecting it with 5.5.6 would be the hold
  // breaking what it was added to protect.
  var release3 = null;
  var sBatch = await _mkWithPolicy(function () {
    return new Promise(function (resolve) { release3 = function () { resolve({ ok: true }); }; });
  });
  var sockB = await _connect(sBatch.port);
  try {
    await _readReply(sockB);
    await _send(sockB, "EHLO client.example.com");
    await _send(sockB, "AUTH PLAIN " + _saslPlain("ok", "pw"));
    var batch = [];
    sockB.on("data", function (d) {
      String(d).split(/\r\n/).forEach(function (l) { if (l) batch.push(l); });
    });
    // Long-but-legal recipients: 20 of them, each well under the per-line cap,
    // together far past it.
    var rcpts = "";
    for (var ri = 0; ri < 20; ri += 1) {
      rcpts += "RCPT TO:<" + ("r" + ri) + new Array(180).join("x") + "@example.com>\r\n";
    }
    sockB.write("MAIL FROM:<alias@example.com>\r\n" + rcpts);
    await helpers.waitUntil(function () { return release3 !== null; },
      { timeoutMs: 5000, label: "submission batch: senderPolicy was consulted" });
    release3();
    await helpers.waitUntil(function () { return batch.length >= 21; },
      { timeoutMs: 5000, label: "submission batch: every reply" });
    check("pipelined batch: the sender is accepted first",
      /^250 2\.1\.0 /.test(batch[0]), JSON.stringify(batch.slice(0, 2)));
    check("pipelined batch: no reply is a line-too-long disconnect",
      batch.every(function (l) { return !/5\.5\.6/.test(l); }),
      JSON.stringify(batch.filter(function (l) { return /5\.5\.6/.test(l); })));
  } finally { sockB.destroy(); await sBatch.srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }

  // Config-time: a non-callable senderPolicy is the operator asking for a
  // check the listener would then never run.
  var badOpts = null;
  try {
    b.mail.server.submission.create({ tlsContext: tls.ctx, profile: "permissive",
      senderPolicy: "yes-please" });
  } catch (e) { badOpts = e; }
  check("senderPolicy: a non-callable one is refused at construction",
    badOpts !== null && /senderPolicy/.test(badOpts.message || ""),
    String(badOpts && badOpts.message));
}

// ---- cleartext AUTH accepted + identity binding (strict) ----

async function testCleartextAuthAndIdentity(tls) {
  var s = await _mk(tls, {
    profile:         "permissive",
    identityBinding: "strict",
    auth: {
      mechanisms: ["PLAIN", "LOGIN"],
      verify: function (mech, creds) {
        var parts = Buffer.from(creds.clientResponse || "", "base64").toString("utf8").split(NUL);
        var user = parts[1];
        if (user === "empty") return Promise.resolve({ ok: true, actor: { id: "empty@example.com" } });
        // "solo" carries a single-mailbox STRING (not the array form).
        if (user === "solo") return Promise.resolve({ ok: true, actor: { id: "solo@example.com", mailbox: "solo@example.com" } });
        return Promise.resolve({ ok: true, actor: { id: user + "@example.com", mailboxes: ["ok@example.com"] } });
      },
    },
  });

  // Actor with a mailbox set.
  var sock = await _connect(s.port);
  try {
    await _readReply(sock);
    await _send(sock, "EHLO client.example.com");
    check("cleartext AUTH PLAIN accepted → 235",
      /^235 /.test(await _send(sock, "AUTH PLAIN " + _saslPlain("ok", "pw"))));
    check("AUTH again after success → 503",
      /^503 /.test(await _send(sock, "AUTH PLAIN " + _saslPlain("ok", "pw"))));
    // Identity binding: not in set → 553.
    check("MAIL FROM not in actor set → 553",
      /^553 /.test(await _send(sock, "MAIL FROM:<evil@example.com>")));
    check("RSET → 250", /^250 /.test(await _send(sock, "RSET")));
    // In set → 250.
    check("MAIL FROM in actor set → 250",
      /^250 /.test(await _send(sock, "MAIL FROM:<ok@example.com>")));
    check("RSET after the accepted sender → 250", /^250 /.test(await _send(sock, "RSET")));
    // Subaddressing is a DELIVERY convention this framework does not
    // implement, so it cannot assume `ok+tag@` reaches `ok@` here. Unasked
    // for, the fold does not happen — on a deployment that allocates
    // plus-addresses as distinct mailboxes, folding would hand this account
    // send-as authority over another's.
    check("MAIL FROM as a subaddress is refused when no delimiter is configured",
      /^553 /.test(await _send(sock, "MAIL FROM:<ok+newsletter@example.com>")));
  } finally { sock.destroy(); }

  await testSubaddressFoldingWhenConfigured(tls);

  // Actor with NO mailboxes → every MAIL FROM refused.
  var sock2 = await _connect(s.port);
  try {
    await _readReply(sock2);
    await _send(sock2, "EHLO client.example.com");
    await _send(sock2, "AUTH PLAIN " + _saslPlain("empty", "pw"));
    check("MAIL FROM with no-mailbox actor → 553",
      /^553 /.test(await _send(sock2, "MAIL FROM:<whatever@example.com>")));
  } finally { sock2.destroy(); }

  // Actor whose mailbox set is the single-string form.
  var sock3 = await _connect(s.port);
  try {
    await _readReply(sock3);
    await _send(sock3, "EHLO client.example.com");
    await _send(sock3, "AUTH PLAIN " + _saslPlain("solo", "pw"));
    check("MAIL FROM matching string-mailbox actor → 250",
      /^250 /.test(await _send(sock3, "MAIL FROM:<solo@example.com>")));
  } finally { sock3.destroy(); await s.srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }
}

// ---- AUTH failures: mech-not-advertised, verify-fail, verify-throw, multi-step ----

async function testAuthFailuresAndMultiStep(tls) {
  var s = await _mk(tls, {
    profile: "permissive",
    auth: {
      mechanisms: ["PLAIN", "LOGIN"],
      verify: function (mech, creds) {
        if (mech === "LOGIN") {
          if (creds.step === 0) return Promise.resolve({ pending: true, challenge: Buffer.from("Username:", "utf8").toString("base64") });
          return Promise.resolve({ ok: true, actor: { id: "u@example.com" } });
        }
        if (mech === "PLAIN") {
          var parts = Buffer.from(creds.clientResponse || "", "base64").toString("utf8").split(NUL);
          if (parts[2] === "boom") return Promise.reject(new Error("backend exploded"));
          if (parts[2] === "good") return Promise.resolve({ ok: true, actor: { id: parts[1] } });
          return Promise.resolve({ ok: false, reason: "bad-password" });
        }
        return Promise.resolve({ ok: false });
      },
    },
  });
  var sock = await _connect(s.port);
  try {
    await _readReply(sock);
    await _send(sock, "EHLO client.example.com");
    // Mechanism not advertised → 535.
    check("AUTH unadvertised mech → 535", /^535 /.test(await _send(sock, "AUTH CRAM-MD5 abcd")));
    // verify returns { ok:false } → 535.
    check("AUTH verify-fail → 535", /^535 /.test(await _send(sock, "AUTH PLAIN " + _saslPlain("u", "nope"))));
    // verify throws → 535.
    check("AUTH verify-throw → 535", /^535 /.test(await _send(sock, "AUTH PLAIN " + _saslPlain("u", "boom"))));
    // Multi-step LOGIN: 334 challenge then 235.
    check("AUTH LOGIN issues 334 challenge", /^334 /.test(await _send(sock, "AUTH LOGIN")));
    check("AUTH LOGIN completes → 235",
      /^235 /.test(await _send(sock, Buffer.from("user", "utf8").toString("base64"))));
  } finally { sock.destroy(); await s.srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }
}

// ---- AUTH-failure per-IP rate-limit (421 + close) ----

async function testAuthRateLimit(tls) {
  var s = await _mk(tls, {
    profile:   "permissive",
    rateLimit: { authFailuresPerIpPer15Min: 1 },
    auth: {
      mechanisms: ["PLAIN"],
      verify: function () { return Promise.resolve({ ok: false, reason: "always-fail" }); },
    },
  });
  var sock = await _connect(s.port);
  try {
    await _readReply(sock);
    await _send(sock, "EHLO client.example.com");
    check("first AUTH fails → 535", /^535 /.test(await _send(sock, "AUTH PLAIN " + _saslPlain("u", "x"))));
    // Second attempt trips the per-IP budget → 421 + close.
    check("AUTH over budget → 421", /^421 /.test(await _send(sock, "AUTH PLAIN " + _saslPlain("u", "y"))));
  } finally { sock.destroy(); await s.srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }
}

// ---- cross-tenant refusal ----

async function testCrossTenant(tls) {
  var tenantScope = {
    check: function (actor, tid) {
      if (!actor || actor.tenantId !== tid) {
        var e = new Error("cross-tenant"); e.code = "tenant/mismatch"; throw e;
      }
    },
  };
  var s = await _mk(tls, {
    profile:       "permissive",
    tenantScope:   tenantScope,
    agentTenantId: "t1",
    auth: {
      mechanisms: ["PLAIN"],
      verify: function (mech, creds) {
        var parts = Buffer.from(creds.clientResponse || "", "base64").toString("utf8").split(NUL);
        return Promise.resolve({ ok: true, actor: { id: parts[1], tenantId: parts[1] === "right" ? "t1" : "t2" } });
      },
    },
  });
  var sock = await _connect(s.port);
  try {
    await _readReply(sock);
    await _send(sock, "EHLO client.example.com");
    check("wrong tenant → 535 cross-tenant",
      /^535 /.test(await _send(sock, "AUTH PLAIN " + _saslPlain("wrong", "x"))));
  } finally { sock.destroy(); }

  var sock2 = await _connect(s.port);
  try {
    await _readReply(sock2);
    await _send(sock2, "EHLO client.example.com");
    check("right tenant → 235",
      /^235 /.test(await _send(sock2, "AUTH PLAIN " + _saslPlain("right", "x"))));
  } finally { sock2.destroy(); await s.srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }
}

// ---- strict profile: pre-TLS refusals, STARTTLS upgrade, DKIM-required ----

async function testStrictProfileStartTls(tls) {
  var s = await _mk(tls, {
    profile: "strict",
    auth: {
      mechanisms: ["PLAIN", "LOGIN"],
      verify: function (mech, creds) {
        var parts = Buffer.from(creds.clientResponse || "", "base64").toString("utf8").split(NUL);
        return Promise.resolve({ ok: true, actor: { id: (parts[1] || "u") + "@example.com", mailboxes: ["ok@example.com"] } });
      },
    },
  });
  var raw = await _connect(s.port);
  try {
    await _readReply(raw);
    var ehlo = await _send(raw, "EHLO client.example.com");
    check("strict EHLO advertises STARTTLS", /250[ -]STARTTLS/.test(ehlo));
    check("strict EHLO hides AUTH pre-TLS",   !/AUTH /.test(ehlo));
    check("AUTH before STARTTLS → 538", /^538 /.test(await _send(raw, "AUTH PLAIN " + _saslPlain("ok", "x"))));
    check("MAIL before STARTTLS → 530", /^530 /.test(await _send(raw, "MAIL FROM:<ok@example.com>")));
    check("STARTTLS → 220", /^220 /.test(await _send(raw, "STARTTLS")));

    var tsock = await _tlsUpgrade(raw, s.caPem);
    var ehlo2 = await _send(tsock, "EHLO client.example.com");
    check("post-TLS EHLO advertises AUTH", /AUTH /.test(ehlo2));
    check("post-TLS EHLO hides STARTTLS",  !/250[ -]STARTTLS/.test(ehlo2));
    check("STARTTLS after upgrade → 503",  /^503 /.test(await _send(tsock, "STARTTLS")));
    // Over TLS but not yet authenticated → strict profile still requires AUTH.
    check("MAIL over TLS pre-AUTH (strict) → 530", /^530 /.test(await _send(tsock, "MAIL FROM:<ok@example.com>")));
    check("AUTH over TLS succeeds → 235",  /^235 /.test(await _send(tsock, "AUTH PLAIN " + _saslPlain("ok", "x"))));
    // Identity binding (strict default): not-in-set 553, then in-set OK.
    check("MAIL not-in-set over TLS → 553", /^553 /.test(await _send(tsock, "MAIL FROM:<evil@example.com>")));
    await _send(tsock, "RSET");
    check("MAIL in-set over TLS → 250",     /^250 /.test(await _send(tsock, "MAIL FROM:<ok@example.com>")));
    check("RCPT over TLS → 250",            /^250 /.test(await _send(tsock, "RCPT TO:<b@example.com>")));
    // strict requireDkim default true + no DKIM-Signature → 550.
    check("DATA without DKIM (strict) → 550", /^550 /.test(await _dataDot(tsock, "From: ok@example.com\r\n\r\nno dkim here")));
    tsock.destroy();
  } finally { raw.destroy(); await s.srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }
}

// ---- implicit-TLS ----

async function testImplicitTls(tls) {
  var s = await _mk(tls, { profile: "permissive", implicitTls: true });
  var raw = await _connect(s.port);
  var tsock = null;
  try {
    tsock = await _tlsUpgrade(raw, s.caPem);
    check("implicit-TLS greeting is 220", /^220 /.test(await _readReply(tsock)));
    var ehlo = await _send(tsock, "EHLO client.example.com");
    check("implicit-TLS EHLO hides STARTTLS", !/250[ -]STARTTLS/.test(ehlo));
    // On implicit-TLS, state.tls is already true, so STARTTLS is refused as
    // "already active" (503) — the RFC 8314 502 branch is unreachable here.
    // Either way STARTTLS is correctly refused.
    check("STARTTLS on implicit-TLS refused (5xx)", /^5\d\d /.test(await _send(tsock, "STARTTLS")));
    check("MAIL FROM over implicit-TLS → 250", /^250 /.test(await _send(tsock, "MAIL FROM:<a@example.com>")));
    check("RCPT over implicit-TLS → 250", /^250 /.test(await _send(tsock, "RCPT TO:<b@example.com>")));
    check("DATA over implicit-TLS → 250", /^250 /.test(await _dataDot(tsock, "From: a@example.com\r\n\r\nx")));
  } finally { if (tsock) tsock.destroy(); raw.destroy(); await s.srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }
}

// ---- DKIM-required modes (any / self / mismatch / no header block) ----

async function _dkimTxn(port, body) {
  var sock = await _connect(port);
  await _readReply(sock);
  await _send(sock, "EHLO client.example.com");
  await _send(sock, "MAIL FROM:<a@example.com>");
  await _send(sock, "RCPT TO:<b@example.com>");
  var reply = await _dataDot(sock, body);
  sock.destroy();
  return reply;
}

async function testDkimModes(tls) {
  // any: present → ok, absent → 550.
  var sAny = await _mk(tls, { profile: "permissive", requireDkim: true, dkimRequireMode: "any" });
  try {
    check("dkim any: signature present → 250",
      /^250 /.test(await _dkimTxn(sAny.port, "DKIM-Signature: v=1; d=example.com; b=zzz\r\nFrom: a@example.com\r\n\r\nbody")));
    check("dkim any: no signature → 550",
      /^550 /.test(await _dkimTxn(sAny.port, "From: a@example.com\r\n\r\nbody")));
    // header block with no blank line (headerEnd === -1) still finds the sig.
    check("dkim any: no header/body split still finds sig → 250",
      /^250 /.test(await _dkimTxn(sAny.port, "DKIM-Signature: v=1; d=example.com; b=zzz")));
    // Folded DKIM-Signature (continuation line begins with SP) is unfolded.
    check("dkim any: folded signature accepted → 250",
      /^250 /.test(await _dkimTxn(sAny.port, "DKIM-Signature: v=1;\r\n d=example.com;\r\n b=zzz\r\nFrom: a@example.com\r\n\r\nbody")));
  } finally { await sAny.srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }

  // self: d= must match envelope-sender domain (no auth → falls back to MAIL FROM domain).
  var sSelf = await _mk(tls, { profile: "permissive", requireDkim: true, dkimRequireMode: "self" });
  try {
    check("dkim self: matching d= → 250",
      /^250 /.test(await _dkimTxn(sSelf.port, "DKIM-Signature: v=1; d=example.com; b=zzz\r\nFrom: a@example.com\r\n\r\nbody")));
    check("dkim self: mismatched d= → 550",
      /^550 /.test(await _dkimTxn(sSelf.port, "DKIM-Signature: v=1; d=other.org; b=zzz\r\nFrom: a@example.com\r\n\r\nbody")));
  } finally { await sSelf.srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }

  // off: requireDkim forced false → DATA without sig accepted.
  var sOff = await _mk(tls, { profile: "permissive", requireDkim: true, dkimRequireMode: "off" });
  try {
    check("dkim off: no signature accepted → 250",
      /^250 /.test(await _dkimTxn(sOff.port, "From: a@example.com\r\n\r\nbody")));
  } finally { await sOff.srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }
}

// ---- recipientPolicy accept / refuse / throw + rcpt cap ----

async function testRecipientPolicy(tls) {
  var s = await _mk(tls, {
    profile:            "permissive",
    maxRcptsPerMessage: 2,
    recipientPolicy: function (ctx) {
      if (ctx.rcptTo.indexOf("throw@") === 0) return Promise.reject(new Error("policy engine down"));
      if (ctx.rcptTo.indexOf("deny@") === 0) return Promise.resolve({ ok: false, reason: "on deny list" });
      return Promise.resolve({ ok: true });
    },
  });
  var sock = await _connect(s.port);
  try {
    await _readReply(sock);
    await _send(sock, "EHLO client.example.com");
    await _send(sock, "MAIL FROM:<a@example.com>");
    check("recipientPolicy accept → 250", /^250 /.test(await _send(sock, "RCPT TO:<ok@example.com>")));
    check("recipientPolicy refuse → 550", /^550 /.test(await _send(sock, "RCPT TO:<deny@example.com>")));
    check("recipientPolicy throw → 451",  /^451 /.test(await _send(sock, "RCPT TO:<throw@example.com>")));
    // Second accepted recipient reaches the cap (2); a third → 452.
    check("second accepted rcpt → 250", /^250 /.test(await _send(sock, "RCPT TO:<ok2@example.com>")));
    check("rcpt over cap → 452",        /^452 /.test(await _send(sock, "RCPT TO:<ok3@example.com>")));
  } finally { sock.destroy(); await s.srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }
}

// ---- concurrent-connection rate-limit ----

async function testConnRateLimit(tls) {
  var s = await _mk(tls, { profile: "permissive", rateLimit: { maxConcurrentConnectionsPerIp: 1 } });
  var first = await _connect(s.port);
  try {
    check("first connection greeted 220", /^220 /.test(await _readReply(first)));
    var second = await _connect(s.port);
    check("second connection from same IP → 421", /^421 /.test(await _readReply(second)));
    second.destroy();
  } finally { first.destroy(); await s.srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }
}

// ---- line-too-long, body-too-large, DATA smuggling, SIZE-exceeds ----

async function testLimitsAndSmuggling(tls) {
  // Line too long: cap is maxLineBytes*4.
  var sLine = await _mk(tls, { profile: "permissive", maxLineBytes: b.constants.BYTES.bytes(16) });
  var lsock = await _connect(sLine.port);
  try {
    await _readReply(lsock);
    var longLine = "NOOP " + new Array(200).join("A"); // ~204 bytes > 16*4
    check("overlong command line → 500", /^500 /.test(await _send(lsock, longLine)));
  } finally { lsock.destroy(); await sLine.srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }

  // Body too large + SIZE-declared refusal + smuggling, tight maxMessageBytes.
  var sBody = await _mk(tls, { profile: "permissive", maxMessageBytes: b.constants.BYTES.kib(1) });
  var bsock = await _connect(sBody.port);
  try {
    await _readReply(bsock);
    await _send(bsock, "EHLO client.example.com");
    // SIZE param exceeds fixed maximum → 552.
    check("MAIL FROM SIZE over max → 552",
      /^552 /.test(await _send(bsock, "MAIL FROM:<a@example.com> SIZE=999999")));
    await _send(bsock, "MAIL FROM:<a@example.com>");
    await _send(bsock, "RCPT TO:<b@example.com>");
    // Over-cap DATA body → 552.
    var big = new Array(2100).join("A"); // ~2099 bytes > 1 KiB
    check("DATA body over max → 552", /^552 /.test(await _dataDot(bsock, big)));
  } finally { bsock.destroy(); await sBody.srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }

  // DATA-body bare-LF-dot smuggling → 554.
  var sSm = await _mk(tls, { profile: "permissive" });
  var ssock = await _connect(sSm.port);
  try {
    await _readReply(ssock);
    await _send(ssock, "EHLO client.example.com");
    await _send(ssock, "MAIL FROM:<a@example.com>");
    await _send(ssock, "RCPT TO:<b@example.com>");
    await _send(ssock, "DATA");
    // bare-LF dot line — CVE-2023-51764 smuggling shape.
    check("DATA bare-LF-dot smuggling → 554",
      /^554 /.test(await _writeRaw(ssock, "evil body" + LF + "." + LF + "injected")));
  } finally { ssock.destroy(); await sSm.srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }
}

// The slow-loris floor, on the sibling listener. mx has the same test; a floor
// enforced on one listener and not the other is exactly the shape that left
// `minBytesPerSecond` unenforced on BOTH of them for as long as it existed.
//
// A limiter whose floor is unreachable in a fast test is substituted so the
// branch is reached without spending the ten-second grace window; the number
// itself is pinned in mail-server-rate-limit.test.js.
// The same floor on the OTHER body path. This listener advertises CHUNKING, so
// a body can arrive by BDAT instead of DATA, and a defence applied to one path
// is a defence a client opts out of by using the other — which is exactly what
// happened to the bare-LF smuggling screen earlier in this release. Applying a
// body-phase check to DATA alone is the mistake this file has now made twice.
async function testBodyRateFloorAppliesToBdatToo(tls) {
  var asked = [];
  var real = b.mail.server.rateLimit.create({});
  var starving = {};
  Object.keys(real).forEach(function (k) {
    starving[k] = typeof real[k] === "function"
      ? function () { return real[k].apply(real, arguments); }
      : real[k];
  });
  starving.bodyRateStarved = function (bytes, elapsedMs) {
    asked.push({ bytes: bytes, elapsedMs: elapsedMs });
    return true;
  };

  var s = await _mk(tls, { profile: "permissive", rateLimit: starving });
  var sock = await _connect(s.port);
  try {
    await _readReply(sock);
    await _send(sock, "EHLO client.example.com");
    await _send(sock, "MAIL FROM:<a@example.com>");
    await _send(sock, "RCPT TO:<b@example.com>");

    var body = "Subject: chunked\r\n\r\nx";
    var reply = await _send(sock,
      "BDAT " + Buffer.byteLength(body, "utf8") + " LAST\r\n" + body);
    check("submission: a BDAT body below the rate floor is refused 421",
      /^421 /.test(reply), JSON.stringify(reply));
    check("submission: the BDAT refusal is transient, not permanent",
      /4\.7\.0/.test(reply), JSON.stringify(reply));
    check("submission: the listener asked the limiter on the BDAT path too",
      asked.length >= 1, String(asked.length));
    // The count is measured from where the window opened, so the first reading
    // after opening is legitimately zero — nothing has arrived since. What must
    // never happen is a count larger than the bytes actually sent, which is
    // what crediting a byte twice looks like; the monotonicity test below bounds
    // it against the real wire total.
    check("submission: the BDAT reading is measured from the window, never negative",
      asked.every(function (a) { return a.bytes >= 0; }),
      JSON.stringify(asked.map(function (a) { return a.bytes; })));
  } finally {
    sock.destroy();
    await s.srv.close({ timeoutMs: b.constants.TIME.seconds(2) });
  }

  // A sequence of ZERO-LENGTH chunks carries no bytes, so a window keyed on the
  // byte count restarts on every command and the zero-length path returns before
  // reaching any measurement. One `BDAT 0` before each idle timeout then holds
  // the connection forever without ever meeting the floor — the same slow-loris,
  // wearing a different command.
  var zeroAsked = [];
  var zeroReal = b.mail.server.rateLimit.create({});
  var zeroStarving = {};
  Object.keys(zeroReal).forEach(function (k) {
    zeroStarving[k] = typeof zeroReal[k] === "function"
      ? function () { return zeroReal[k].apply(zeroReal, arguments); }
      : zeroReal[k];
  });
  zeroStarving.bodyRateStarved = function (bytes, elapsedMs) {
    zeroAsked.push({ bytes: bytes, elapsedMs: elapsedMs });
    return true;
  };

  var z = await _mk(tls, { profile: "permissive", rateLimit: zeroStarving });
  var zsock = await _connect(z.port);
  try {
    await _readReply(zsock);
    await _send(zsock, "EHLO client.example.com");
    await _send(zsock, "MAIL FROM:<a@example.com>");
    await _send(zsock, "RCPT TO:<b@example.com>");
    // The first BDAT opens the window; the second is judged against it.
    await _send(zsock, "BDAT 0");
    var second = await _send(zsock, "BDAT 0");
    check("submission: a repeated zero-length BDAT is judged, not waved through",
      /^421 /.test(second), JSON.stringify(second));
    check("submission: the zero-length path reaches the limiter",
      zeroAsked.length >= 1, String(zeroAsked.length));
  } finally {
    zsock.destroy();
    await z.srv.close({ timeoutMs: b.constants.TIME.seconds(2) });
  }

  // The count handed to the limiter must be CUMULATIVE for the transfer. The
  // window subtracts the previous window's baseline from it, so a count that
  // goes flat or backwards across a roll reads as no progress and refuses a
  // client that is in fact sending steadily — an over-refusal, which is the
  // direction that costs a working sender rather than an attacker.
  //
  // Counting only BDAT payload bytes did exactly that: command bytes never
  // landed in the total, so a sequence carrying `BDAT 0` and interleaved NOOP
  // reported the same number every time.
  var counts = [];
  var monoReal = b.mail.server.rateLimit.create({});
  var monoLimiter = {};
  Object.keys(monoReal).forEach(function (k) {
    monoLimiter[k] = typeof monoReal[k] === "function"
      ? function () { return monoReal[k].apply(monoReal, arguments); }
      : monoReal[k];
  });
  monoLimiter.bodyRateStarved = function (bytes) { counts.push(bytes); return false; };

  var m = await _mk(tls, { profile: "permissive", rateLimit: monoLimiter });
  var msock = await _connect(m.port);
  try {
    await _readReply(msock);
    await _send(msock, "EHLO client.example.com");
    await _send(msock, "MAIL FROM:<a@example.com>");
    await _send(msock, "RCPT TO:<b@example.com>");
    // Count the bytes the client actually puts on the wire from the moment the
    // BDAT sequence opens, so the readings can be bounded against reality.
    var sentSinceOpen = 0;
    function sendCounted(line) {
      sentSinceOpen += Buffer.byteLength(line + "\r\n", "utf8");
      return _send(msock, line);
    }
    await _send(msock, "BDAT 0");          // opens the window; its own bytes are the baseline
    await sendCounted("NOOP");
    await sendCounted("NOOP");
    var payload = "Subject: c\r\n\r\nbody";
    await sendCounted("BDAT " + Buffer.byteLength(payload, "utf8") + "\r\n" + payload);

    check("submission: the limiter is given a count for every inbound chunk",
      counts.length >= 3, String(counts.length));
    var monotonic = counts.every(function (n, i) { return i === 0 || n >= counts[i - 1]; });
    check("submission: that count never goes backwards across the transfer",
      monotonic, JSON.stringify(counts));
    check("submission: and it grows as bytes arrive, rather than repeating",
      counts[counts.length - 1] > counts[0], JSON.stringify(counts));
    // The bound that catches double-crediting: re-feeding a chunk's tail
    // through the parser must not let a byte be counted twice, which would show
    // up here as a reading larger than everything the client actually sent.
    check("submission: no byte is credited twice",
      counts[counts.length - 1] <= sentSinceOpen,
      "counted " + counts[counts.length - 1] + " against " + sentSinceOpen + " sent");
  } finally {
    msock.destroy();
    await m.srv.close({ timeoutMs: b.constants.TIME.seconds(2) });
  }

  // The same accounting, over STARTTLS — which is how submission is actually
  // deployed, and the one configuration the checks above cannot speak for.
  //
  // Upgrading removes the plaintext `data` listener and delivers decrypted
  // chunks to a separate callback. Counting on the listener alone therefore
  // stops counting the moment the connection becomes the one operators use:
  // the reading handed to the limiter freezes, and once the grace period
  // elapses a client sending well above the floor is judged to have sent
  // nothing and gets 421. That is an over-refusal on the ordinary path, which
  // costs a working sender rather than an attacker.
  var tlsCounts = [];
  var tlsReal = b.mail.server.rateLimit.create({});
  var tlsLimiter = {};
  Object.keys(tlsReal).forEach(function (k) {
    tlsLimiter[k] = typeof tlsReal[k] === "function"
      ? function () { return tlsReal[k].apply(tlsReal, arguments); }
      : tlsReal[k];
  });
  tlsLimiter.bodyRateStarved = function (bytes) { tlsCounts.push(bytes); return false; };

  var t = await _mk(tls, { profile: "permissive", rateLimit: tlsLimiter });
  var traw = await _connect(t.port);
  var tsk = null;
  try {
    await _readReply(traw);
    await _send(traw, "EHLO client.example.com");
    await _send(traw, "STARTTLS");
    tsk = await _tlsUpgrade(traw, t.caPem);
    await _send(tsk, "EHLO client.example.com");
    await _send(tsk, "MAIL FROM:<a@example.com>");
    await _send(tsk, "RCPT TO:<b@example.com>");

    var tlsSent = 0;
    function sendTlsCounted(line) {
      tlsSent += Buffer.byteLength(line + "\r\n", "utf8");
      return _send(tsk, line);
    }
    await _send(tsk, "BDAT 0");            // opens the window
    await sendTlsCounted("NOOP");
    var tlsPayload = "Subject: c\r\n\r\nbody";
    await sendTlsCounted("BDAT " + Buffer.byteLength(tlsPayload, "utf8") + "\r\n" + tlsPayload);

    check("submission: the limiter is asked over TLS too",
      tlsCounts.length >= 2, String(tlsCounts.length));
    check("submission: and the reading grows as encrypted bytes arrive",
      tlsCounts[tlsCounts.length - 1] > tlsCounts[0], JSON.stringify(tlsCounts));
    // Same double-credit bound as the plaintext path: routing both transports
    // through one counter must not make a byte count twice.
    check("submission: no encrypted byte is credited twice",
      tlsCounts[tlsCounts.length - 1] <= tlsSent,
      "counted " + tlsCounts[tlsCounts.length - 1] + " against " + tlsSent + " sent");
  } finally {
    if (tsk) tsk.destroy();
    traw.destroy();
    await t.srv.close({ timeoutMs: b.constants.TIME.seconds(2) });
  }
}

async function testBodyRateFloorIsAskedDuringData(tls) {
  var asked = [];
  var real = b.mail.server.rateLimit.create({});
  var starving = {};
  Object.keys(real).forEach(function (k) {
    starving[k] = typeof real[k] === "function"
      ? function () { return real[k].apply(real, arguments); }
      : real[k];
  });
  starving.bodyRateStarved = function (bytes, elapsedMs) {
    asked.push({ bytes: bytes, elapsedMs: elapsedMs });
    return true;
  };

  var s = await _mk(tls, { profile: "permissive", rateLimit: starving });
  var sock = await _connect(s.port);
  try {
    await _readReply(sock);
    await _send(sock, "EHLO client.example.com");
    await _send(sock, "MAIL FROM:<a@example.com>");
    await _send(sock, "RCPT TO:<b@example.com>");
    // A COMPLETE body: the rate check runs before the scanner looks for the
    // terminator, so a starved verdict still refuses — and without the
    // terminator a listener that never asks would hang this read instead of
    // failing it, which is a test that cannot go red.
    var reply = await _dataDot(sock, "Subject: trickle\r\n\r\nx");
    check("submission: a body below the rate floor is refused 421",
      /^421 /.test(reply), JSON.stringify(reply));
    check("submission: the refusal is transient, not permanent",
      /4\.7\.0/.test(reply), JSON.stringify(reply));
    check("submission: the listener asked the limiter about the body rate",
      asked.length >= 1, String(asked.length));
    check("submission: the bytes reported include the chunk under judgement",
      asked.length >= 1 && asked[0].bytes > 0,
      asked.length ? String(asked[0].bytes) : "never asked");
  } finally {
    sock.destroy();
    await s.srv.close({ timeoutMs: b.constants.TIME.seconds(2) });
  }
}

// ---- AUTH not configured (permissive, no auth) ----

async function testAuthNotConfigured(tls) {
  var s = await _mk(tls, { profile: "permissive" });
  var sock = await _connect(s.port);
  try {
    await _readReply(sock);
    await _send(sock, "EHLO client.example.com");
    check("AUTH with no authenticator → 502", /^502 /.test(await _send(sock, "AUTH PLAIN " + _saslPlain("u", "p"))));
  } finally { sock.destroy(); await s.srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }
}

// ---- idle timeout ----

async function testIdleTimeout(tls) {
  var s = await _mk(tls, { profile: "permissive", idleTimeoutMs: b.constants.TIME.seconds(1) });
  var sock = await _connect(s.port);
  try {
    await _readReply(sock); // greeting
    // No further traffic → server should fire the idle-timeout 421.
    var reply = await _readReply(sock);
    check("idle timeout → 421", /^421 /.test(reply));
  } finally { sock.destroy(); await s.srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }
}

// ---- close() drain writes 421 to live sockets ----

async function testCloseDrain(tls) {
  var s = await _mk(tls, { profile: "permissive" });
  var sock = await _connect(s.port);
  await _readReply(sock);
  check("connectionCount is 1 with a live socket", s.srv.connectionCount() >= 1);
  var got421 = false;
  sock.on("data", function (c) { if (/421 /.test(c.toString("utf8"))) got421 = true; });
  var closing = s.srv.close({ timeoutMs: b.constants.TIME.seconds(5) });
  // Let the drain write its 421, then release the socket so close resolves fast.
  await helpers.waitUntil(function () { return got421; }, {
    timeoutMs: b.constants.TIME.seconds(3),
    label:     "close-drain: 421 shutdown notice delivered",
  });
  sock.destroy();
  await closing;
  check("close() drained live socket with 421", got421 === true);
  check("connectionCount is 0 after close", s.srv.connectionCount() === 0);
}

// ---- BDAT: non-final chunk ack, tail re-feed, empty-LAST, cumulative cap ----

async function testBdatMore(tls) {
  var h = [];
  var s = await _mk(tls, { profile: "permissive", agent: _agentCapturing(h, "accept") });

  // Non-final non-zero chunk → "N octets received", then finalize.
  var sock = await _connect(s.port);
  try {
    await _readReply(sock);
    await _send(sock, "EHLO client.example.com");
    await _send(sock, "MAIL FROM:<a@example.com>");
    await _send(sock, "RCPT TO:<b@example.com>");
    var r1 = _readReply(sock);
    sock.write("BDAT 5\r\n");
    sock.write("abcde");
    check("BDAT non-final chunk → 250 N octets", /^250 .*octets/.test(await r1));
    // Tail re-feed: BDAT chunk + trailing command in one segment.
    var r2 = _readReply(sock);
    sock.write("BDAT 3\r\nxyzNOOP\r\n");
    check("BDAT chunk with pipelined tail → 250", /^250 /.test(await r2));
    // Zero-byte LAST after real chunks → finalizes the accumulated body.
    check("BDAT 0 LAST after chunks → 250", /^250 /.test(await _send(sock, "BDAT 0 LAST")));
    await helpers.waitUntil(function () { return h.length >= 1; },
      { timeoutMs: 5000, label: "submission BDAT: agent handoff received after BDAT 0 LAST" });
    check("agent received accumulated BDAT body", h.length === 1 && h[0].body.toString("utf8") === "abcdexyz");
  } finally { sock.destroy(); }

  // BDAT 0 LAST as the only chunk → empty body finalized.
  var sock2 = await _connect(s.port);
  try {
    await _readReply(sock2);
    await _send(sock2, "EHLO client.example.com");
    await _send(sock2, "MAIL FROM:<a@example.com>");
    await _send(sock2, "RCPT TO:<b@example.com>");
    check("BDAT 0 LAST empty message → 250", /^250 /.test(await _send(sock2, "BDAT 0 LAST")));
  } finally { sock2.destroy(); await s.srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }

  // Cumulative-size cap up-front refusal.
  var sCap = await _mk(tls, { profile: "permissive", maxMessageBytes: b.constants.BYTES.kib(1) });
  var sock3 = await _connect(sCap.port);
  try {
    await _readReply(sock3);
    await _send(sock3, "EHLO client.example.com");
    await _send(sock3, "MAIL FROM:<a@example.com>");
    await _send(sock3, "RCPT TO:<b@example.com>");
    check("BDAT cumulative over cap → 552", /^552 /.test(await _send(sock3, "BDAT 99999 LAST")));
  } finally { sock3.destroy(); await sCap.srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }
}

// ---- PIPELINING: RCPT verdict still in-flight when DATA / BDAT arrives ----

async function testPipeliningRace(tls) {
  var s = await _mk(tls, {
    profile: "permissive",
    // Async accept: the verdict resolves on a microtask AFTER the pipelined
    // DATA / BDAT line is dispatched in the same ingest pass.
    recipientPolicy: function () { return Promise.resolve({ ok: true }); },
  });

  var sock = await _connect(s.port);
  try {
    await _readReply(sock);
    await _send(sock, "EHLO client.example.com");
    await _send(sock, "MAIL FROM:<a@example.com>");
    await _send(sock, "RCPT TO:<committed@example.com>"); // one committed recipient
    // Pipeline a second RCPT (verdict pending) + DATA in one segment.
    var r = _readReply(sock);
    sock.write("RCPT TO:<pending@example.com>\r\nDATA\r\n");
    check("DATA while RCPT verdict pending → 451", /^451 /.test(await r));
  } finally { sock.destroy(); }

  var sock2 = await _connect(s.port);
  try {
    await _readReply(sock2);
    await _send(sock2, "EHLO client.example.com");
    await _send(sock2, "MAIL FROM:<a@example.com>");
    await _send(sock2, "RCPT TO:<committed@example.com>");
    var r2 = _readReply(sock2);
    sock2.write("RCPT TO:<pending@example.com>\r\nBDAT 5 LAST\r\n");
    check("BDAT while RCPT verdict pending → 451", /^451 /.test(await r2));
  } finally { sock2.destroy(); await s.srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }
}

// A DKIM-Signature header is unfolded before its tags are read, so the value
// handed to the tag scan is bounded by `maxMessageBytes` (50 MiB by default),
// not by `maxLineBytes`. The client writes the header, and nothing obliges it
// to put a `;` anywhere, so one tag can be as long as the message allows.
//
// That matters because the tag was trimmed with `/^\s+|\s+$/g`, which is the
// classic quadratic trim: the `\s+$` alternative is retried from every start
// position when the run does not reach the end. Measured on the operation
// alone: 109ms at 20k characters, 698ms at 50k, 2850ms at 100k, against
// 0.00ms for a native trim of the same strings.
//
// Driven over the real listener rather than against the private function,
// because the bound that makes it reachable is upstream of it: a test that
// called the trim directly would prove the arithmetic and miss the unfolding.
async function testFoldedDkimTagDoesNotBacktrack(tls) {
  var s = await _mk(tls, {
    profile:         "permissive",
    identityBinding: "permissive",
    requireDkim:     true,
    dkimRequireMode: "self",
    auth: {
      mechanisms: ["PLAIN"],
      verify: function (mech, creds) {
        var parts = Buffer.from(creds.clientResponse || "", "base64").toString("utf8").split(NUL);
        return Promise.resolve({ ok: true, actor: { id: parts[1] + "@example.com" } });
      },
    },
  });
  var sock = await _connect(s.port);
  try {
    await _readReply(sock);
    await _send(sock, "EHLO client.example.com");
    await _send(sock, "AUTH PLAIN " + _saslPlain("u", "x"));
    await _send(sock, "MAIL FROM:<u@example.com>");
    await _send(sock, "RCPT TO:<b@example.com>");

    // One tag, no semicolons, and a long run of whitespace that does not reach
    // the end — which is the shape `\s+$` has to retry from every position.
    //
    // Getting that run past the unfolder takes care. It strips the LEADING
    // whitespace of each continuation line, so a line of 120 spaces collapses
    // to nothing and contributes only the single space the join adds. What it
    // cannot collapse is the join itself: every EMPTY continuation line adds
    // exactly one space to the run, so the attacker's lever is the line COUNT,
    // not the line length. 40,000 empty continuation lines is a 120 KB message,
    // trivially inside the 50 MiB cap, and yields a 40,000-character run.
    //
    // A first version of this test used 600 fat lines and passed against the
    // unfixed code, which is what a green test with no control looks like.
    //
    // Measured as GROWTH between two sizes rather than against a millisecond
    // budget. A budget answers "is this machine fast right now" as much as it
    // answers the question asked: at SMOKE_PARALLEL=64 this box put a linear
    // scan at 420ms against a 400ms ceiling, which is a red gate saying nothing
    // about backtracking.
    //
    // The size STEP has to be chosen for what it separates. Doubling the input
    // costs a linear scan 2x and a quadratic one 4x — and a doubling measured
    // 3.21x here under parallel load, squarely between the two hypotheses,
    // because contention does not scale with input size. Quadrupling separates
    // them properly: 4x against 16x, so even a load factor like that one lands
    // far below the bound. That is the whole reason to assert a curve instead
    // of a number — the two runs inflate together, and the ratio survives what
    // a ceiling cannot.
    // Sized so both runs are well clear of timer noise. 40,000 lines — the
    // size a millisecond budget was once put around — scans in about 3ms on an
    // idle box, which is the other half of why that budget was measuring load
    // rather than complexity: there was nothing else in the number.
    async function _run(lines) {
      var hostile = "DKIM-Signature: v=1 x" + "\r\n ".repeat(lines) + "y\r\n" +
                    "From: u@example.com\r\n\r\nx";
      await _send(sock, "MAIL FROM:<u@example.com>");
      await _send(sock, "RCPT TO:<b@example.com>");
      // The verdict is not the point — no d= tag means it is refused either
      // way. What is measured is how the time moves with the input.
      await _dataDot(sock, hostile);
    }

    // The shared measurement, not a ratio taken here: it takes the best of
    // several samples per size, declines to judge below a floor where the shape
    // is already ruled out, and RE-MEASURES before it fails anything. A single
    // reading of this probe returned 9.41 against a bound of 9 at
    // SMOKE_PARALLEL=64 and failed a release gate on a scan that is linear.
    var verdict = await helpers.looksSuperlinearAsync(_run, {
      small: 100000, large: 400000,
      // Four times the input, so the hypotheses are 4x for a linear scan and
      // 16x for a backtracking one. The bound sits between them with room on
      // both sides for a load factor, which a 2x step does not leave: a
      // doubling measured 3.21x here under parallel load, squarely between
      // what linear and quadratic predict at that step.
      threshold: 9,
    });
    check("submission: a folded DKIM-Signature tag is scanned without " +
          "backtracking (x" + (verdict.ratio === null ? "under floor" : verdict.ratio.toFixed(2)) +
          " for 4x the input)",
          verdict.superlinear === false, JSON.stringify(verdict));
  } finally { sock.destroy(); await s.srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }
}

// ---- DKIM self mode with an authenticated actor (id-domain fallback) +
//      d-less signature + folded signature ----

async function testDkimSelfActor(tls) {
  var s = await _mk(tls, {
    profile:         "permissive",
    identityBinding: "permissive",         // allow MAIL FROM without a mailbox set
    requireDkim:     true,
    dkimRequireMode: "self",
    auth: {
      mechanisms: ["PLAIN"],
      verify: function (mech, creds) {
        var parts = Buffer.from(creds.clientResponse || "", "base64").toString("utf8").split(NUL);
        // actor with an id carrying the domain but NO explicit .domain field
        // → _actorDomain falls back to the id's @-domain.
        return Promise.resolve({ ok: true, actor: { id: parts[1] + "@example.com" } });
      },
    },
  });
  var sock = await _connect(s.port);
  try {
    await _readReply(sock);
    await _send(sock, "EHLO client.example.com");
    await _send(sock, "AUTH PLAIN " + _saslPlain("u", "x"));
    await _send(sock, "MAIL FROM:<u@example.com>");
    await _send(sock, "RCPT TO:<b@example.com>");
    // d= matches the actor-id domain → accepted.
    check("dkim self (actor id-domain) matching d= → 250",
      /^250 /.test(await _dataDot(sock, "DKIM-Signature: v=1; d=example.com; b=z\r\nFrom: u@example.com\r\n\r\nx")));
    await _send(sock, "MAIL FROM:<u@example.com>");
    await _send(sock, "RCPT TO:<b@example.com>");
    // Signature present but no d= tag → no match → 550.
    check("dkim self signature without d= → 550",
      /^550 /.test(await _dataDot(sock, "DKIM-Signature: v=1; b=z\r\nFrom: u@example.com\r\n\r\nx")));
  } finally { sock.destroy(); await s.srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }
}

async function run() {
  testSurface();
  testCreateRequiresTlsContext();
  testStrictProfileRequiresAuthConfig();
  testPermissiveAllowsNoAuth();
  testBadAuthShapeRefused();
  testBadBoundsRefused();
  await testEhloAdvertisesChunking();
  await testBdatSingleLastChunk();
  await testBdatRefusesSmuggledBody();
  await testBdatMultipleChunksThenLast();
  await testBdatZeroByteLast();
  await testBdatOutsideTransaction();
  await testBdatBadArgs();
  await testBdatBinaryBytesPreserved();
  await testPipelinedAuthCannotRaceTheSubmissionGuard();
  await testRefusedBacklogDoesNotFinalizeAfterTheVerdict();
  await testAPeerHangUpStopsTheDrain();
  await testBdatOversizeRefused();

  var tls;
  try { tls = await _makeTestTlsContextWithCa(); }
  catch (_e) { check("mail-server-submission error branches skipped (no TLS ctx)", true); return; }

  testCreateValidation(tls);
  await testCloseBeforeListen(tls);
  await testDoubleListen(tls);
  await testPermissiveDispatch(tls);
  await testDomainRefusals(tls);
  await testDataPaths(tls);
  await testBdatBranches(tls);
  await testBdatMore(tls);
  await testPipeliningRace(tls);
  await testDkimSelfActor(tls);
  await testFoldedDkimTagDoesNotBacktrack(tls);
  await testCleartextAuthAndIdentity(tls);
  await testSenderPolicy(tls);
  await testAuthFailuresAndMultiStep(tls);
  await testAuthRateLimit(tls);
  await testCrossTenant(tls);
  await testStrictProfileStartTls(tls);
  await testImplicitTls(tls);
  await testDkimModes(tls);
  await testRecipientPolicy(tls);
  await testConnRateLimit(tls);
  await testLimitsAndSmuggling(tls);
  await testBodyRateFloorIsAskedDuringData(tls);
  await testBodyRateFloorAppliesToBdatToo(tls);
  await testAuthNotConfigured(tls);
  await testIdleTimeout(tls);
  await testCloseDrain(tls);
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[mail-server-submission] OK"); },
    function (e) { process.stderr.write("FAIL: " + (e && e.stack || e) + "\n"); process.exit(1); }
  );
}
