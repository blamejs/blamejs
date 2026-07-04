// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.mail — error / defensive / adversarial branch coverage for lib/mail.js.
 *
 * Drives the public API (b.mail.create / transports.* / feedbackId /
 * toAscii / toUnicode / _buildRfc822ForTest) with in-memory fakes and
 * loopback fake servers. The SMTP state machine is exercised over a
 * loopback TLS server whose leaf cert is minted by b.mtlsEngine and
 * trusted via opts.ca (verification stays ON — no rejectUnauthorized
 * bypass). No external endpoints.
 */

var net = require("node:net");
var tls = require("node:tls");
var http = require("node:http");
var helpers = require("../helpers");
var b = helpers.b;
var check = helpers.check;

var C = b.constants;

// ---------------------------------------------------------------------------
// Loopback SMTP mock — a scriptable RFC 5321 state machine over an
// already-secure socket (implicit TLS) or a cleartext socket that
// upgrades on STARTTLS. Captures every wire line + BDAT chunks.
// ---------------------------------------------------------------------------

function _wireHandler(sock, script, state) {
  sock.setEncoding("utf8");
  var pending = Buffer.alloc(0);
  var inData = false;
  var dataBuf = "";
  var bdatRemaining = 0;
  var bdatLast = false;
  var bdatBody = Buffer.alloc(0);
  function reply(code, text) { sock.write(code + " " + text + "\r\n"); }
  sock.on("data", function (chunk) {
    pending = Buffer.concat([pending, Buffer.from(chunk, "utf8")]);
    while (true) {
      if (bdatRemaining > 0) {
        if (pending.length === 0) return;
        var take = Math.min(bdatRemaining, pending.length);
        bdatBody = Buffer.concat([bdatBody, pending.slice(0, take)]);
        pending = pending.slice(take);
        bdatRemaining -= take;
        if (bdatRemaining === 0) {
          state.bdatChunks.push({ size: bdatBody.length, last: bdatLast });
          bdatBody = Buffer.alloc(0);
          reply(script.bdatCode || 250, "chunk ok");
        }
        continue;
      }
      if (inData) {
        dataBuf += pending.toString("utf8");
        pending = Buffer.alloc(0);
        if (dataBuf.indexOf("\r\n.\r\n") >= 0) {
          inData = false; dataBuf = "";
          reply(script.bodyCode || 250, "message accepted");
        }
        return;
      }
      var nl = pending.indexOf("\r\n");
      if (nl < 0) return;
      var line = pending.slice(0, nl).toString("utf8");
      pending = pending.slice(nl + 2);
      if (!line) continue;
      state.lines.push(line);
      var u = line.toUpperCase();
      if (u.indexOf("EHLO") === 0) {
        if (script.noEhloResponse) return;
        var ext = script.ext || [];
        var resp = "250-mock greets you\r\n";
        for (var i = 0; i < ext.length; i += 1) {
          resp += ((i === ext.length - 1) ? "250 " : "250-") + ext[i] + "\r\n";
        }
        if (ext.length === 0) resp = (script.ehloCode || 250) + " mock\r\n";
        else if (script.ehloCode && script.ehloCode !== 250) {
          resp = script.ehloCode + " ehlo rejected\r\n";
        }
        sock.write(resp);
      } else if (u.indexOf("AUTH LOGIN") === 0) {
        reply(script.authUserCode || 334, "VXNlcm5hbWU6");
      } else if (u.indexOf("MAIL FROM") === 0) {
        state.mailFromLine = line;
        reply(script.mailFromCode || 250, "sender ok");
      } else if (u.indexOf("RCPT TO") === 0) {
        state.rcptLines.push(line);
        reply(script.rcptCode || 250, "rcpt ok");
      } else if (u === "DATA") {
        if (script.dataCode && script.dataCode !== 354) {
          reply(script.dataCode, "data rejected");
        } else { inData = true; reply(354, "send body"); }
      } else if (u.indexOf("BDAT ") === 0) {
        var parts = line.split(/\s+/);
        var n = parseInt(parts[1], 10);
        bdatRemaining = isFinite(n) && n >= 0 ? n : 0;
        bdatLast = (parts.length >= 3 && parts[2].toUpperCase() === "LAST");
        if (bdatRemaining === 0) {
          state.bdatChunks.push({ size: 0, last: bdatLast });
          reply(script.bdatCode || 250, "empty chunk ok");
        }
      } else if (u === "QUIT") {
        reply(221, "bye"); sock.end();
      } else if (state.authStage !== undefined) {
        // AUTH LOGIN username/password base64 lines.
        state.authLines.push(line);
        if (state.authStage === 0) {
          state.authStage = 1;
          reply(script.authPassCode || 334, "UGFzc3dvcmQ6");
        } else {
          reply(script.authFinalCode || 235, "auth ok");
        }
      } else {
        reply(250, "ok");
      }
      // Track AUTH LOGIN follow-up lines: after "AUTH LOGIN" the next two
      // non-command lines are user + pass base64.
      if (u.indexOf("AUTH LOGIN") === 0) state.authStage = 0;
    }
  });
  sock.on("error", function () { /* client teardown is expected */ });
}

function _newState() {
  return {
    lines: [], mailFromLine: null, rcptLines: [], bdatChunks: [],
    authLines: [], authStage: undefined,
  };
}

// Implicit-TLS SMTP server.
function startTlsSmtp(certPair, script) {
  var state = _newState();
  var server = tls.createServer({ key: certPair.key, cert: certPair.cert }, function (sock) {
    if (typeof script.greetingFlood === "number") {
      sock.write(Buffer.alloc(script.greetingFlood, 0x61).toString("utf8"));  // allow:raw-byte-literal — 'a' filler for oversize-framing test
      sock.on("error", function () {});
      return;
    }
    sock.write((script.greeting || "220 mock ESMTP") + "\r\n");
    if (script.greetingReject) { sock.on("error", function () {}); return; }
    _wireHandler(sock, script, state);
  });
  state.server = server;
  return state;
}

// Cleartext SMTP server that upgrades to TLS on STARTTLS.
function startStarttlsSmtp(certPair, script) {
  var state = _newState();
  var server = net.createServer(function (raw) {
    raw.setEncoding("utf8");
    raw.write("220 mock ESMTP\r\n");
    var buf = "";
    raw.on("data", function onData(d) {
      buf += d;
      var idx;
      while ((idx = buf.indexOf("\r\n")) >= 0) {
        var line = buf.slice(0, idx);
        buf = buf.slice(idx + 2);
        if (!line) continue;
        state.lines.push(line);
        var u = line.toUpperCase();
        if (u.indexOf("EHLO") === 0) {
          raw.write("250-mock\r\n250 STARTTLS\r\n");
        } else if (u.indexOf("STARTTLS") === 0) {
          if (script.starttls === "reject") { raw.write("502 no starttls\r\n"); continue; }
          raw.write("220 go ahead\r\n");
          raw.removeListener("data", onData);
          var upgraded = new tls.TLSSocket(raw, {
            isServer: true, key: certPair.key, cert: certPair.cert,
          });
          _wireHandler(upgraded, script, state);
          return;
        }
      }
    });
    raw.on("error", function () {});
  });
  state.server = server;
  return state;
}

function listen(state) {
  return new Promise(function (resolve, reject) {
    state.server.listen(0, "127.0.0.1", function () {
      state.port = state.server.address().port;
      resolve(state.port);
    });
    state.server.on("error", reject);
  });
}

function closeServer(state) {
  return new Promise(function (resolve) {
    try { state.server.close(function () { resolve(); }); }
    catch (_e) { resolve(); }
  });
}

// A TLS smtp transport pointed at a loopback mock; verification stays on
// via opts.ca + opts.servername:"localhost" (cert carries a localhost SAN).
function tlsTransport(certPair, port, extra) {
  var opts = {
    host: "127.0.0.1", port: port, implicitTls: true,
    ca: certPair.caCertPem, servername: "localhost", preferFamily: 4,
    timeoutMs: C.TIME.seconds(4),
  };
  if (extra) { for (var k in extra) if (Object.prototype.hasOwnProperty.call(extra, k)) opts[k] = extra[k]; }
  return b.mail.transports.smtp(opts);
}

function starttlsTransport(certPair, port, extra) {
  var opts = {
    host: "127.0.0.1", port: port,
    ca: certPair.caCertPem, servername: "localhost", preferFamily: 4,
    timeoutMs: C.TIME.seconds(4),
  };
  if (extra) { for (var k in extra) if (Object.prototype.hasOwnProperty.call(extra, k)) opts[k] = extra[k]; }
  return b.mail.transports.smtp(opts);
}

async function _sendErr(transport, message) {
  var err = null;
  try { await transport.send(message); }
  catch (e) { err = e; }
  return err;
}

// ---------------------------------------------------------------------------
// Pure helpers: toAscii / toUnicode
// ---------------------------------------------------------------------------

function testToAsciiBranches() {
  check("toAscii(non-string) → null", b.mail.toAscii(123) === null);
  check("toAscii('') → null", b.mail.toAscii("") === null);
  check("toAscii with '/' → null", b.mail.toAscii("a.com/evil") === null);
  check("toAscii with '?' → null", b.mail.toAscii("a.com?x") === null);
  check("toAscii with '#' → null", b.mail.toAscii("a.com#x") === null);
  check("toAscii with '\\\\' → null", b.mail.toAscii("a.com\\x") === null);
  check("toAscii with ':' → null", b.mail.toAscii("a.com:25") === null);
  check("toAscii with '@' → null", b.mail.toAscii("u@a.com") === null);
  check("toAscii with '[' → null", b.mail.toAscii("[1.2.3.4]") === null);
  check("toAscii IDN → xn--", b.mail.toAscii("münchen.de") === "xn--mnchen-3ya.de");
}

function testToUnicodeBranches() {
  check("toUnicode(non-string) → null", b.mail.toUnicode(123) === null);
  check("toUnicode('') → null", b.mail.toUnicode("") === null);
  check("toUnicode xn-- → unicode", b.mail.toUnicode("xn--mnchen-3ya.de") === "münchen.de");
}

// ---------------------------------------------------------------------------
// _buildRfc822ForTest — multipart, calendar, attachments, dot-stuffing
// ---------------------------------------------------------------------------

function testBuildRfc822MultipartAlternative() {
  var wire = b.mail._buildRfc822ForTest({
    from: "a@x.com", to: "b@y.com", subject: "s",
    text: "plain text", html: "<p>html</p>",
  });
  check("alt: multipart/alternative content-type",
    /Content-Type: multipart\/alternative; boundary="/.test(wire));
  check("alt: carries text part", wire.indexOf("text/plain; charset=utf-8") !== -1);
  check("alt: carries html part", wire.indexOf("text/html; charset=utf-8") !== -1);
  check("alt: closes boundary", /--blamejs-alt-[^\r\n]+--/.test(wire));
}

function testBuildRfc822CalendarCcReplyToHeaders() {
  var wire = b.mail._buildRfc822ForTest({
    from: "a@x.com", to: ["b@y.com", "c@y.com"], cc: ["d@y.com"],
    replyTo: "reply@x.com", subject: "invite",
    headers: { "X-Custom": "vv" },
    calendar: { method: "REQUEST", icalText: "BEGIN:VCALENDAR\r\nEND:VCALENDAR" },
  });
  check("cal: To joins array", /^To: b@y\.com, c@y\.com/m.test(wire));
  check("cal: Cc header present", /^Cc: d@y\.com/m.test(wire));
  check("cal: Reply-To header present", /^Reply-To: reply@x\.com/m.test(wire));
  check("cal: custom header present", /^X-Custom: vv/m.test(wire));
  check("cal: text/calendar with method param",
    wire.indexOf('text/calendar; method="REQUEST"') !== -1);
}

function testBuildRfc822AttachmentsAndDotStuffing() {
  var wire = b.mail._buildRfc822ForTest({
    from: "a@x.com", to: "b@y.com", subject: "s",
    text: ".leading dot line\nsecond",
    attachments: [
      { filename: "a.txt", content: "hello", contentType: "text/plain" },
      { filename: "logo.png", content: Buffer.from([0x89, 0x50]), cid: "img1" },  // allow:raw-byte-literal — 2-byte fixture
    ],
  });
  check("att: multipart/mixed wrapper", /Content-Type: multipart\/mixed; boundary="/.test(wire));
  check("att: base64 transfer encoding", wire.indexOf("Content-Transfer-Encoding: base64") !== -1);
  check("att: filename param", wire.indexOf('filename="a.txt"') !== -1);
  check("att: inline cid → Content-ID", wire.indexOf("Content-ID: <img1>") !== -1);
  check("att: inline disposition for cid part", wire.indexOf("Content-Disposition: inline") !== -1);
  check("att: built message body is NOT pre-dot-stuffed (DATA transparency moved to DATA send; BDAT gets raw)",
    wire.indexOf("\r\n.leading dot line") !== -1 && wire.indexOf("\r\n..leading dot line") === -1);
}

// ---------------------------------------------------------------------------
// console + memory transports
// ---------------------------------------------------------------------------

function _fakeStream() {
  var out = { data: "" };
  out.write = function (s) { out.data += s; };
  return out;
}

async function testConsoleTransport() {
  var s1 = _fakeStream();
  var t1 = b.mail.transports.console({ stream: s1 });
  var r1 = await t1.send({
    to: ["a@x.com", "b@x.com"], from: "f@x.com", subject: "hi",
    cc: ["c@x.com"], bcc: ["secret@x.com"], text: "body-text",
  });
  check("console: returns transport marker", r1.transport === "console" && typeof r1.deliveredAt === "number");
  check("console: prints To joined", s1.data.indexOf("To: a@x.com, b@x.com") !== -1);
  check("console: prints Cc", s1.data.indexOf("Cc: c@x.com") !== -1);
  check("console: prints Bcc addresses (redact off)", s1.data.indexOf("Bcc: secret@x.com") !== -1);
  check("console: prints body", s1.data.indexOf("body-text") !== -1);

  var s2 = _fakeStream();
  var t2 = b.mail.transports.console({ stream: s2, redactBcc: true });
  await t2.send({ to: "a@x.com", from: "f@x.com", bcc: ["x@x.com", "y@x.com"], html: "<b>hi</b>" });
  check("console: redactBcc hides addresses", s2.data.indexOf("x@x.com") === -1);
  check("console: redactBcc shows count", s2.data.indexOf("2 recipients") !== -1);
  check("console: html-only body renders size hint", s2.data.indexOf("(html body,") !== -1);

  // Single (non-array) recipient + single bcc branch.
  var s3 = _fakeStream();
  var t3 = b.mail.transports.console({ stream: s3, redactBcc: true });
  await t3.send({ to: "solo@x.com", from: "f@x.com", bcc: "one@x.com" });
  check("console: single bcc redacts to '1 recipient'", s3.data.indexOf("1 recipient —") !== -1);
}

async function testMemoryTransport() {
  var mem = b.mail.transports.memory();
  var r0 = await mem.send({ to: "a@x.com", from: "f@x.com" });
  var r1 = await mem.send({ to: "b@x.com", from: "f@x.com" });
  check("memory: captures sends", mem.sent.length === 2);
  check("memory: index reflects order", r0.index === 0 && r1.index === 1);
  check("memory: transport marker", r0.transport === "memory");
  mem.reset();
  check("memory: reset clears sent", mem.sent.length === 0);
}

// ---------------------------------------------------------------------------
// httpTransport — config gates, serializer faults, error wrap, interpret
// ---------------------------------------------------------------------------

function testHttpTransportConfigGates() {
  function threw(fn) { try { fn(); return null; } catch (e) { return e; } }
  check("http: requires endpoint",
    threw(function () { b.mail.transports.http({ serialize: function () {} }); }).code === "mail/http-misconfigured");
  check("http: requires serialize fn",
    threw(function () { b.mail.transports.http({ endpoint: "https://x.test" }); }).code === "mail/http-misconfigured");
}

async function testHttpTransportBadSerializer() {
  var t1 = b.mail.transports.http({
    endpoint: "https://x.test", name: "vend",
    serialize: function () { return null; },
  });
  var e1 = await _sendErr(t1, { to: "a@x.com", from: "f@x.com" });
  check("http: serialize non-object → bad-serializer", e1 && e1.code === "mail/vend-bad-serializer");

  var t2 = b.mail.transports.http({
    endpoint: "https://x.test", name: "vend",
    serialize: function () { return { body: 42 }; },
  });
  var e2 = await _sendErr(t2, { to: "a@x.com", from: "f@x.com" });
  check("http: serialize body non-string/Buffer → bad-serializer", e2 && e2.code === "mail/vend-bad-serializer");
}

async function testHttpTransportRequestFailureWrap() {
  // Point at a closed loopback port → ECONNREFUSED inside http-client →
  // rewrapped into mail/<name>-failed with the original as cause.
  var t = b.mail.transports.http({
    endpoint: "http://127.0.0.1:1/send", name: "vend",
    allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    serialize: function () { return { body: "{}" }; },
  });
  var e = await _sendErr(t, { to: "a@x.com", from: "f@x.com" });
  check("http: request failure → mail/vend-failed", e && e.code === "mail/vend-failed");
  check("http: original error preserved as cause", e && e.cause != null);
}

async function testHttpTransportSuccessAndInterpret() {
  // Loopback HTTP server returns a controllable status + body; interpret
  // branches drive off it.
  var server = http.createServer(function (req, res) {
    var chunks = [];
    req.on("data", function (c) { chunks.push(c); });
    req.on("end", function () {
      var mode = req.headers["x-mode"];
      if (mode === "500") { res.writeHead(500); res.end("err"); return; }
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ id: "msg-123", extraKey: "ev" }));
    });
  });
  await new Promise(function (r) { server.listen(0, "127.0.0.1", r); });
  var port = server.address().port;
  var base = {
    endpoint: "http://127.0.0.1:" + port + "/send", name: "vend",
    allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
  };
  try {
    // (a) No interpret → returns info + statusCode.
    var tNo = b.mail.transports.http(Object.assign({}, base, {
      serialize: function () { return { body: "{}" }; },
    }));
    var rNo = await tNo.send({ to: "a@x.com", from: "f@x.com" });
    check("http: no-interpret returns info", rNo.transport === "vend" && rNo.statusCode === 200);

    // (b) interpret ok with id + extra merged.
    var tOk = b.mail.transports.http(Object.assign({}, base, {
      serialize: function () { return { headers: { "Content-Length": "2" }, body: "{}" }; },
      interpret: function (res) {
        var d = JSON.parse(res.body.toString("utf8"));
        return { ok: true, id: d.id, extra: { extraKey: d.extraKey } };
      },
    }));
    var rOk = await tOk.send({ to: "a@x.com", from: "f@x.com" });
    check("http: interpret id merged", rOk.id === "msg-123");
    check("http: interpret extra merged", rOk.extraKey === "ev");

    // (c) interpret verdict false → rejected with statusCode.
    var tRej = b.mail.transports.http(Object.assign({}, base, {
      serialize: function () { return { body: "{}" }; },
      interpret: function () { return { ok: false, reason: "nope", statusCode: 422 }; },
    }));
    var eRej = await _sendErr(tRej, { to: "a@x.com", from: "f@x.com" });
    check("http: verdict false → rejected", eRej && eRej.code === "mail/vend-rejected");
    check("http: rejected carries statusCode", eRej && eRej.statusCode === 422);

    // (d) interpret throws plain → interpret-failed.
    var tThrow = b.mail.transports.http(Object.assign({}, base, {
      serialize: function () { return { body: "{}" }; },
      interpret: function () { throw new Error("boom"); },
    }));
    var eThrow = await _sendErr(tThrow, { to: "a@x.com", from: "f@x.com" });
    check("http: interpret throw → interpret-failed", eThrow && eThrow.code === "mail/vend-interpret-failed");

    // (e) interpret throws a MailError → passthrough.
    var tMail = b.mail.transports.http(Object.assign({}, base, {
      serialize: function () { return { body: "{}" }; },
      interpret: function () { throw new b.mail.MailError("mail/custom-code", "x", true); },
    }));
    var eMail = await _sendErr(tMail, { to: "a@x.com", from: "f@x.com" });
    check("http: interpret MailError passthrough", eMail && eMail.code === "mail/custom-code");

    // (f) non-2xx status → http-client throws → mail/vend-failed with statusCode.
    var tErr = b.mail.transports.http(Object.assign({}, base, {
      serialize: function () { return { headers: { "X-Mode": "500" }, body: "{}" }; },
    }));
    var eErr = await _sendErr(tErr, { to: "a@x.com", from: "f@x.com" });
    check("http: non-2xx → mail/vend-failed", eErr && eErr.code === "mail/vend-failed");
  } finally {
    await new Promise(function (r) { server.close(function () { r(); }); });
  }
}

// ---------------------------------------------------------------------------
// resendTransport — config gate + serialize + interpret over loopback
// ---------------------------------------------------------------------------

function testResendConfigGate() {
  var threw = null;
  try { b.mail.transports.resend({}); } catch (e) { threw = e; }
  check("resend: requires apiKey", threw && threw.code === "mail/resend-misconfigured");
}

async function testResendOverLoopback() {
  var lastBody = { v: null };
  var server = http.createServer(function (req, res) {
    var chunks = [];
    req.on("data", function (c) { chunks.push(c); });
    req.on("end", function () {
      lastBody.v = Buffer.concat(chunks).toString("utf8");
      var mode = req.headers["x-scenario"];
      res.writeHead(200, { "Content-Type": "application/json" });
      if (mode === "noid") { res.end(JSON.stringify({ message: "quota exceeded" })); return; }
      if (mode === "badjson") { res.end("<html>not json</html>"); return; }
      res.end(JSON.stringify({ id: "re_abc" }));
    });
  });
  await new Promise(function (r) { server.listen(0, "127.0.0.1", r); });
  var port = server.address().port;
  var endpoint = "http://127.0.0.1:" + port + "/emails";
  try {
    var tOk = b.mail.transports.resend({
      apiKey: "re_key", endpoint: endpoint,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    var rOk = await tOk.send({
      from: "f@x.com", to: "a@x.com", cc: ["c@x.com"], bcc: "d@x.com",
      replyTo: "r@x.com", subject: "s", html: "<p>h</p>", text: "t",
      headers: { "X-H": "1" },
      attachments: [{ filename: "a.txt", content: "hello", contentType: "text/plain", cid: "c1" }],
    });
    check("resend: ok → id", rOk.id === "re_abc");
    var payload = JSON.parse(lastBody.v);
    check("resend: serialize to as array", Array.isArray(payload.to));
    check("resend: serialize cc/bcc arrays", Array.isArray(payload.cc) && Array.isArray(payload.bcc));
    check("resend: serialize reply_to", payload.reply_to === "r@x.com");
    check("resend: serialize attachment base64 + content_id",
      payload.attachments[0].content === Buffer.from("hello").toString("base64") &&
      payload.attachments[0].content_id === "c1");
  } finally {
    await new Promise(function (r) { server.close(function () { r(); }); });
  }
}

async function testResendBadResponseAndNoId() {
  // Dedicated server that keys behavior off the request path so the real
  // resendTransport interpret branches (bad-json + no-id) are exercised.
  var server = http.createServer(function (req, res) {
    res.writeHead(200, { "Content-Type": "application/json" });
    if (req.url.indexOf("badjson") !== -1) { res.end("<html>nope</html>"); return; }
    if (req.url.indexOf("noid") !== -1) { res.end(JSON.stringify({ message: "denied" })); return; }
    res.end(JSON.stringify({ id: "re_ok" }));
  });
  await new Promise(function (r) { server.listen(0, "127.0.0.1", r); });
  var port = server.address().port;
  try {
    var tBad = b.mail.transports.resend({
      apiKey: "k", endpoint: "http://127.0.0.1:" + port + "/badjson",
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    var eBad = await _sendErr(tBad, { to: "a@x.com", from: "f@x.com", subject: "s", text: "t" });
    check("resend: non-JSON body → bad-response", eBad && eBad.code === "mail/resend-bad-response");

    var tNo = b.mail.transports.resend({
      apiKey: "k", endpoint: "http://127.0.0.1:" + port + "/noid",
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    var eNo = await _sendErr(tNo, { to: "a@x.com", from: "f@x.com", subject: "s", text: "t" });
    check("resend: missing id → rejected (reason = message)",
      eNo && eNo.code === "mail/resend-rejected" && /denied/.test(eNo.message));
  } finally {
    await new Promise(function (r) { server.close(function () { r(); }); });
  }
}

// ---------------------------------------------------------------------------
// create() — opts validation, transport shapes, error wrap, footer/unsub
// ---------------------------------------------------------------------------

function testCreateOptsAndTransportShapes() {
  function threw(fn) { try { fn(); return null; } catch (e) { return e; } }
  check("create: unknown opt rejected",
    threw(function () { b.mail.create({ bogusKey: 1 }); }) !== null);
  check("create: bad transport (object w/o send) rejected",
    threw(function () { b.mail.create({ transport: { name: "x" } }); }).code === "mail/bad-transport");
  // transport as a bare function is wrapped into { send, name:"anonymous" }.
  var m = b.mail.create({ transport: function () { return Promise.resolve({ ok: 1 }); }, audit: false });
  check("create: function transport wrapped", m.transport.name === "anonymous");
  // Default transport (console) when omitted.
  var m2 = b.mail.create({ audit: false });
  check("create: default transport is console", m2.transport.name === "console");
}

async function testCreateTransportErrorWrap() {
  // Non-MailError thrown by transport → wrapped as mail/transport-failed.
  var mPlain = b.mail.create({
    transport: function () { throw new Error("kaboom"); },
    guardDomain: false, audit: false,
  });
  var ePlain = await _sendErr(mPlain, { to: "a@x.com", from: "f@x.com", text: "hi" });
  check("create: plain transport error → mail/transport-failed", ePlain && ePlain.code === "mail/transport-failed");
  check("create: transport error preserves cause", ePlain && ePlain.cause && ePlain.cause.message === "kaboom");

  // A MailError thrown by transport is re-thrown unchanged.
  var mMail = b.mail.create({
    transport: function () { throw new b.mail.MailError("mail/custom", "nope", true); },
    guardDomain: false, audit: false,
  });
  var eMail = await _sendErr(mMail, { to: "a@x.com", from: "f@x.com", text: "hi" });
  check("create: MailError from transport passes through", eMail && eMail.code === "mail/custom");
}

async function testCreateUnsubscribeExpansion() {
  var captured = [];
  var m = b.mail.create({
    transport: function (msg) { captured.push(msg); return Promise.resolve({ ok: 1 }); },
    guardDomain: false, audit: false,
  });
  await m.send({
    to: "a@x.com", from: "f@x.com", text: "hi",
    unsubscribe: { url: "https://x.test/unsub", oneClick: true },
  });
  var sent = captured[0];
  var keys = Object.keys(sent.headers || {}).map(function (k) { return k.toLowerCase(); });
  check("create: unsubscribe expands into List-Unsubscribe header",
    keys.indexOf("list-unsubscribe") !== -1);
  check("create: unsubscribe object removed after expansion", sent.unsubscribe === undefined);
}

function testCreateFooterHtmlValidation() {
  function threw(fn) { try { fn(); return null; } catch (e) { return e; } }
  var addr = { street: "1 St", city: "X", region: "Y", postalCode: "62701", country: "US" };
  // Valid override carrying country + postalCode → create succeeds.
  var ok = threw(function () {
    b.mail.create({
      transport: b.mail.transports.memory(), commercial: true, audit: false,
      postalAddress: addr, footerHtml: "<div>Acme, 62701, US</div>",
    });
  });
  check("create: footerHtml with country+postalCode accepted", ok === null);
  // Missing country → refused.
  var eC = threw(function () {
    b.mail.create({
      transport: b.mail.transports.memory(), commercial: true, audit: false,
      postalAddress: addr, footerHtml: "<div>Acme 62701</div>",
    });
  });
  check("create: footerHtml missing country → bad-footer-html", eC && eC.code === "mail/bad-footer-html");
  // Missing postalCode (country present) → refused.
  var eP = threw(function () {
    b.mail.create({
      transport: b.mail.transports.memory(), commercial: true, audit: false,
      postalAddress: addr, footerHtml: "<div>Acme US</div>",
    });
  });
  check("create: footerHtml missing postalCode → bad-footer-html", eP && eP.code === "mail/bad-footer-html");
}

async function testCommercialHtmlOnlyAndStringAddress() {
  // commercial:true with a STRING postalAddress + html-only message: text
  // is null → the append-when-null branch fills text with the address.
  var captured = [];
  var m = b.mail.create({
    transport: function (msg) { captured.push(msg); return Promise.resolve({ ok: 1 }); },
    guardDomain: false, audit: false, commercial: true,
    postalAddress: "Acme Inc, 500 Rue, 75001 Paris, France",
    defaults: { from: "shop@x.com" },
  });
  await m.send({
    to: "a@x.com", subject: "promo", html: "<p>buy</p>",
    headers: { "List-Unsubscribe": "<https://x.test/u>" },
  });
  var sent = captured[0];
  check("commercial: html footer appended with string address", sent.html.indexOf("Acme Inc") !== -1);
  check("commercial: text synthesized from string address when text null",
    typeof sent.text === "string" && sent.text.indexOf("Acme Inc") !== -1);
}

// ---------------------------------------------------------------------------
// _validateMessage — adversarial / malformed message branches
// ---------------------------------------------------------------------------

function _validator() {
  return b.mail.create({
    transport: function () { return Promise.resolve({ ok: 1 }); },
    guardDomain: false, audit: false,
  });
}

async function testValidateMessageBranches() {
  var m = _validator();
  async function expect(label, message, code) {
    var e = await _sendErr(m, message);
    check(label, e && e.code === code);
  }
  await expect("missing to", { from: "f@x.com", text: "hi" }, "mail/missing-to");
  await expect("empty-string recipient", { to: [""], from: "f@x.com", text: "hi" }, "mail/invalid-recipient");
  await expect("recipient control char", { to: ["a\r\nb@x.com"], from: "f@x.com", text: "hi" }, "mail/invalid-recipient");
  await expect("recipient bad address", { to: ["notanemail"], from: "f@x.com", text: "hi" }, "mail/invalid-recipient");
  await expect("missing from", { to: "a@x.com", text: "hi" }, "mail/missing-from");
  await expect("from control char", { to: "a@x.com", from: "a\r\nb@x.com", text: "hi" }, "mail/invalid-from");
  await expect("from bad address", { to: "a@x.com", from: "notanemail", text: "hi" }, "mail/invalid-from");
  await expect("subject CRLF", { to: "a@x.com", from: "f@x.com", subject: "a\r\nb", text: "hi" }, "mail/invalid-subject");
  await expect("missing body", { to: "a@x.com", from: "f@x.com" }, "mail/missing-body");
}

async function testValidateCalendarBranches() {
  var m = _validator();
  async function expect(label, cal, code) {
    var e = await _sendErr(m, { to: "a@x.com", from: "f@x.com", calendar: cal });
    check(label, e && e.code === code);
  }
  await expect("calendar not object", 5, "mail/invalid-calendar");
  await expect("calendar bad method", { method: "BOGUS", icalText: "BEGIN:VCALENDAR" }, "mail/invalid-calendar");
  await expect("calendar no icalText", { method: "REQUEST" }, "mail/invalid-calendar");
  await expect("calendar not vcalendar", { method: "REQUEST", icalText: "nope" }, "mail/invalid-calendar");
  // Valid calendar-only message dispatches.
  var captured = [];
  var m2 = b.mail.create({
    transport: function (msg) { captured.push(msg); return Promise.resolve({ ok: 1 }); },
    guardDomain: false, audit: false,
  });
  await m2.send({ to: "a@x.com", from: "f@x.com", calendar: { method: "PUBLISH", icalText: "BEGIN:VCALENDAR\r\nEND:VCALENDAR" } });
  check("calendar: valid calendar-only dispatches", captured.length === 1);
}

async function testValidateAttachmentBranches() {
  var m = _validator();
  var base = { to: "a@x.com", from: "f@x.com", text: "hi" };
  async function expect(label, attachments, code) {
    var msg = Object.assign({}, base, { attachments: attachments });
    var e = await _sendErr(m, msg);
    check(label, e && e.code === code);
  }
  await expect("attachments not array", "nope", "mail/invalid-attachments");
  await expect("attachment not object", [5], "mail/invalid-attachment");
  await expect("attachment no filename", [{ content: "x" }], "mail/invalid-attachment");
  await expect("attachment filename control char", [{ filename: "a\r\nb.txt", content: "x" }], "mail/invalid-attachment");
  await expect("attachment filename traversal (guardFilename)", [{ filename: "../../etc/passwd", content: "x" }], "mail/invalid-attachment");
  await expect("attachment content missing", [{ filename: "a.txt" }], "mail/invalid-attachment");
  await expect("attachment content wrong type", [{ filename: "a.txt", content: 5 }], "mail/invalid-attachment");
  await expect("attachment contentType unclean", [{ filename: "a.txt", content: "x", contentType: "text/plain\r\nX: y" }], "mail/invalid-attachment");
  await expect("attachment bad disposition", [{ filename: "a.txt", content: "x", contentDisposition: "sideways" }], "mail/invalid-attachment");
  await expect("attachment bad cid (angle bracket)", [{ filename: "a.txt", content: "x", cid: "a<b>" }], "mail/invalid-attachment");
  // Magic-byte mismatch: real PNG magic bytes but claimed text/plain.
  await expect("attachment magic-byte mismatch",
    [{ filename: "a.txt", content: Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D]), contentType: "text/plain" }],  // allow:raw-byte-literal — PNG magic bytes vs text/plain claim
    "mail/invalid-attachment");
  // skipFilenameSafety + skipMagicByteCheck bypasses → send succeeds.
  var captured = [];
  var m2 = b.mail.create({
    transport: function (msg) { captured.push(msg); return Promise.resolve({ ok: 1 }); },
    guardDomain: false, audit: false,
  });
  await m2.send(Object.assign({}, base, {
    attachments: [{
      filename: "weird name.txt".replace(" ", ""), content: "x",
      skipFilenameSafety: true, skipMagicByteCheck: true, contentType: "text/plain",
      contentDisposition: "attachment",
    }],
  }));
  check("attachment: valid attachment dispatches", captured.length === 1);
}

async function testEaiRecipientAccepted() {
  // EAI path: Unicode local + IDN domain must validate through _isValidEmail.
  var captured = [];
  var m = b.mail.create({
    transport: function (msg) { captured.push(msg); return Promise.resolve({ ok: 1 }); },
    guardDomain: false, audit: false,
  });
  await m.send({ to: "bü@münchen.de", from: "f@x.com", subject: "grüße", text: "hi" });
  check("eai: unicode recipient + IDN domain accepted", captured.length === 1);
  // "Name <addr>" display form accepted.
  captured.length = 0;
  await m.send({ to: "Alice <alice@x.com>", from: "Bob <bob@x.com>", text: "hi" });
  check("display-name form accepted", captured.length === 1);
}

// ---------------------------------------------------------------------------
// smtpTransport — config-time gates (no socket needed)
// ---------------------------------------------------------------------------

function testSmtpConfigGates() {
  function threw(fn) { try { fn(); return null; } catch (e) { return e; } }
  check("smtp: requires host",
    threw(function () { b.mail.transports.smtp({}); }).code === "mail/smtp-misconfigured");
  check("smtp: bad dkimSigner shape",
    threw(function () { b.mail.transports.smtp({ host: "h", dkimSigner: { nope: 1 } }); }).code === "mail/smtp-misconfigured");
  check("smtp: CRLF in ehloName refused",
    threw(function () { b.mail.transports.smtp({ host: "h", ehloName: "x\r\nMAIL FROM:<e>" }); }).code === "mail/smtp-misconfigured");
  check("smtp: CRLF in user refused",
    threw(function () { b.mail.transports.smtp({ host: "h", user: "u\r\nx" }); }).code === "mail/smtp-misconfigured");
  check("smtp: CRLF in pass refused",
    threw(function () { b.mail.transports.smtp({ host: "h", pass: "p\r\nx" }); }).code === "mail/smtp-misconfigured");
  check("smtp: CRLF in host refused",
    threw(function () { b.mail.transports.smtp({ host: "h\r\nx" }); }).code === "mail/smtp-misconfigured");
  check("smtp: CRLF in servername refused",
    threw(function () { b.mail.transports.smtp({ host: "h", servername: "s\r\nx" }); }).code === "mail/smtp-misconfigured");
  check("smtp: bad port refused",
    threw(function () { b.mail.transports.smtp({ host: "h", port: 70000 }); }).code === "mail/smtp-misconfigured");
  check("smtp: bad chunkSize refused",
    threw(function () { b.mail.transports.smtp({ host: "h", chunkSize: -1 }); }).code === "mail/smtp-misconfigured");
  check("smtp: bad maxTransactionMs refused",
    threw(function () { b.mail.transports.smtp({ host: "h", maxTransactionMs: -5 }); }).code === "mail/smtp-misconfigured");
}

async function testSmtpDkimSignFailureRejectsPreConnect() {
  // A dkimSigner whose .sign() throws rejects the send synchronously,
  // before any socket is opened — so any unroutable host is fine.
  var t = b.mail.transports.smtp({
    host: "127.0.0.1", port: 1, implicitTls: true,
    dkimSigner: { sign: function () { throw new Error("no key"); } },
  });
  var e = await _sendErr(t, { from: "s@a.test", to: "r@b.test", subject: "s", text: "t" });
  check("smtp: dkim sign failure → mail/dkim-sign-failed", e && e.code === "mail/dkim-sign-failed");
}

// ---------------------------------------------------------------------------
// smtpTransport — full state machine over loopback TLS
// ---------------------------------------------------------------------------

async function testSmtpHappyPathData(certPair) {
  var st = startTlsSmtp(certPair, { ext: ["8BITMIME"] });
  await listen(st);
  try {
    var t = tlsTransport(certPair, st.port);
    var r = await t.send({ from: "s@a.test", to: ["r1@b.test", "r2@b.test"], cc: "c@b.test", subject: "hi", text: "hello" });
    check("smtp-data: delivered with code 250", r.transport === "smtp" && r.code === 250);
    check("smtp-data: sent RCPT for to+cc (3)", st.rcptLines.length === 3);
    check("smtp-data: used DATA not BDAT", st.bdatChunks.length === 0);
  } finally { await closeServer(st); }
}

async function testSmtpAuthLogin(certPair) {
  var st = startTlsSmtp(certPair, { ext: ["8BITMIME"] });
  await listen(st);
  try {
    var t = tlsTransport(certPair, st.port, { user: "user", pass: "pass" });
    var r = await t.send({ from: "s@a.test", to: "r@b.test", subject: "hi", text: "hello" });
    check("smtp-auth: delivered after AUTH LOGIN", r.code === 250);
    check("smtp-auth: sent AUTH LOGIN", st.lines.some(function (l) { return /^AUTH LOGIN/i.test(l); }));
    check("smtp-auth: sent b64 user", st.authLines.indexOf(Buffer.from("user").toString("base64")) !== -1);
    check("smtp-auth: sent b64 pass", st.authLines.indexOf(Buffer.from("pass").toString("base64")) !== -1);
  } finally { await closeServer(st); }
}

async function testSmtpBdatChunking(certPair) {
  var st = startTlsSmtp(certPair, { ext: ["CHUNKING", "8BITMIME"] });
  await listen(st);
  try {
    // Small chunkSize forces multiple BDAT chunks.
    var t = tlsTransport(certPair, st.port, { chunkSize: C.BYTES.bytes(32) });
    var r = await t.send({ from: "s@a.test", to: "r@b.test", subject: "hi", text: new Array(20).join("chunkybody-") });
    check("smtp-bdat: delivered", r.code === 250);
    check("smtp-bdat: used BDAT (multiple chunks)", st.bdatChunks.length >= 2);
    check("smtp-bdat: final chunk marked LAST", st.bdatChunks[st.bdatChunks.length - 1].last === true);
  } finally { await closeServer(st); }
}

async function testSmtpBinaryMimeBdat(certPair) {
  var st = startTlsSmtp(certPair, { ext: ["CHUNKING", "BINARYMIME", "8BITMIME"] });
  await listen(st);
  try {
    var t = tlsTransport(certPair, st.port);
    var r = await t.send({
      from: "s@a.test", to: "r@b.test", subject: "bin", text: "see attached",
      attachments: [{ filename: "a.bin", content: Buffer.from([0x00, 0x01, 0x02, 0x00]), binary: true, skipMagicByteCheck: true, contentType: "application/octet-stream" }],  // allow:raw-byte-literal — NUL-bearing binary fixture
    });
    check("smtp-binarymime: delivered via BDAT", r.code === 250 && st.bdatChunks.length >= 1);
    check("smtp-binarymime: MAIL FROM carried BODY=BINARYMIME", /BODY=BINARYMIME/.test(st.mailFromLine || ""));
  } finally { await closeServer(st); }
}

async function testSmtpSmtpUtf8And8BitMime(certPair) {
  var st1 = startTlsSmtp(certPair, { ext: ["SMTPUTF8", "8BITMIME", "SIZE 1000000"] });
  await listen(st1);
  try {
    var t1 = tlsTransport(certPair, st1.port);
    var r1 = await t1.send({ from: "s@a.test", to: "r@b.test", subject: "grüße", text: "hallo" });
    check("smtp-utf8: delivered", r1.code === 250);
    check("smtp-utf8: MAIL FROM carried SMTPUTF8", /SMTPUTF8/.test(st1.mailFromLine || ""));
    check("smtp-utf8: MAIL FROM carried SIZE=", /SIZE=\d+/.test(st1.mailFromLine || ""));
  } finally { await closeServer(st1); }

  var st2 = startTlsSmtp(certPair, { ext: ["8BITMIME"] });
  await listen(st2);
  try {
    var t2 = tlsTransport(certPair, st2.port);
    var r2 = await t2.send({ from: "s@a.test", to: "r@b.test", subject: "s", text: "café ☕ body" });
    check("smtp-8bit: delivered", r2.code === 250);
    check("smtp-8bit: MAIL FROM carried BODY=8BITMIME", /BODY=8BITMIME/.test(st2.mailFromLine || ""));
  } finally { await closeServer(st2); }
}

async function testSmtpSizeRefusal(certPair) {
  var st = startTlsSmtp(certPair, { ext: ["SIZE 10"] });
  await listen(st);
  try {
    var t = tlsTransport(certPair, st.port);
    var e = await _sendErr(t, { from: "s@a.test", to: "r@b.test", subject: "s", text: "this body far exceeds ten bytes" });
    check("smtp-size: peer SIZE cap exceeded → mail/peer-size-exceeded", e && e.code === "mail/peer-size-exceeded");
  } finally { await closeServer(st); }
}

async function testSmtpEaiUnsupportedRefusal(certPair) {
  // Message requires SMTPUTF8 (unicode subject) but peer does not advertise it.
  var st = startTlsSmtp(certPair, { ext: ["8BITMIME"] });
  await listen(st);
  try {
    var t = tlsTransport(certPair, st.port);
    var e = await _sendErr(t, { from: "s@a.test", to: "r@b.test", subject: "grüße", text: "hi" });
    check("smtp-eai: unicode but no SMTPUTF8 → mail/smtp-failed(eai)",
      e && e.code === "mail/smtp-failed" && /eai-required-not-supported/.test(e.message));
  } finally { await closeServer(st); }
}

async function testSmtpBinaryMimeUnsupportedRefusal(certPair) {
  var st = startTlsSmtp(certPair, { ext: ["8BITMIME"] });
  await listen(st);
  try {
    var t = tlsTransport(certPair, st.port);
    var e = await _sendErr(t, {
      from: "s@a.test", to: "r@b.test", subject: "s", text: "x",
      attachments: [{ filename: "a.bin", content: Buffer.from([0x00, 0x00]), binary: true, skipMagicByteCheck: true, contentType: "application/octet-stream" }],  // allow:raw-byte-literal — NUL binary fixture
    });
    check("smtp-binarymime-unsupported → mail/binarymime-not-advertised",
      e && e.code === "mail/binarymime-not-advertised");
  } finally { await closeServer(st); }
}

async function testSmtpRejectionCodes(certPair) {
  // greeting rejected
  var stG = startTlsSmtp(certPair, { greeting: "554 go away" });
  await listen(stG);
  try {
    var eG = await _sendErr(tlsTransport(certPair, stG.port), { from: "s@a.test", to: "r@b.test", text: "x" });
    check("smtp-reject: greeting 554 → smtp-failed", eG && /greeting-rejected/.test(eG.message));
  } finally { await closeServer(stG); }

  // EHLO rejected
  var stE = startTlsSmtp(certPair, { ext: [], ehloCode: 500 });
  await listen(stE);
  try {
    var eE = await _sendErr(tlsTransport(certPair, stE.port), { from: "s@a.test", to: "r@b.test", text: "x" });
    check("smtp-reject: EHLO 500 → smtp-failed", eE && /ehlo-rejected/.test(eE.message));
  } finally { await closeServer(stE); }

  // MAIL FROM rejected
  var stM = startTlsSmtp(certPair, { ext: ["8BITMIME"], mailFromCode: 550 });
  await listen(stM);
  try {
    var eM = await _sendErr(tlsTransport(certPair, stM.port), { from: "s@a.test", to: "r@b.test", text: "x" });
    check("smtp-reject: MAIL FROM 550 → smtp-failed", eM && /mail-from-rejected/.test(eM.message));
  } finally { await closeServer(stM); }

  // RCPT rejected
  var stR = startTlsSmtp(certPair, { ext: ["8BITMIME"], rcptCode: 550 });
  await listen(stR);
  try {
    var eR = await _sendErr(tlsTransport(certPair, stR.port), { from: "s@a.test", to: "r@b.test", text: "x" });
    check("smtp-reject: RCPT 550 → smtp-failed", eR && /rcpt-rejected/.test(eR.message));
  } finally { await closeServer(stR); }

  // DATA rejected
  var stD = startTlsSmtp(certPair, { ext: ["8BITMIME"], dataCode: 503 });
  await listen(stD);
  try {
    var eD = await _sendErr(tlsTransport(certPair, stD.port), { from: "s@a.test", to: "r@b.test", text: "x" });
    check("smtp-reject: DATA 503 → smtp-failed", eD && /data-rejected/.test(eD.message));
  } finally { await closeServer(stD); }

  // BODY rejected (post-DATA final code non-250 → smtp-rejected)
  var stB = startTlsSmtp(certPair, { ext: ["8BITMIME"], bodyCode: 552 });
  await listen(stB);
  try {
    var eB = await _sendErr(tlsTransport(certPair, stB.port), { from: "s@a.test", to: "r@b.test", text: "x" });
    check("smtp-reject: BODY 552 → mail/smtp-rejected", eB && eB.code === "mail/smtp-rejected");
  } finally { await closeServer(stB); }

  // BDAT chunk rejected
  var stBd = startTlsSmtp(certPair, { ext: ["CHUNKING", "8BITMIME"], bdatCode: 552 });
  await listen(stBd);
  try {
    var eBd = await _sendErr(tlsTransport(certPair, stBd.port), { from: "s@a.test", to: "r@b.test", text: "x" });
    check("smtp-reject: BDAT chunk 552 → mail/bdat-chunk-rejected", eBd && eBd.code === "mail/bdat-chunk-rejected");
  } finally { await closeServer(stBd); }

  // AUTH final rejected
  var stA = startTlsSmtp(certPair, { ext: ["8BITMIME"], authFinalCode: 535 });
  await listen(stA);
  try {
    var eA = await _sendErr(tlsTransport(certPair, stA.port, { user: "u", pass: "p" }), { from: "s@a.test", to: "r@b.test", text: "x" });
    check("smtp-reject: AUTH final 535 → smtp-failed", eA && /auth-failed/.test(eA.message));
  } finally { await closeServer(stA); }
}

async function testSmtpResponseTooLarge(certPair) {
  var st = startTlsSmtp(certPair, { greetingFlood: C.BYTES.kib(300) });
  await listen(st);
  try {
    var e = await _sendErr(tlsTransport(certPair, st.port), { from: "s@a.test", to: "r@b.test", text: "x" });
    check("smtp: oversize framing → response-too-large", e && /response-too-large/.test(e.message));
  } finally { await closeServer(st); }
}

async function testSmtpTransactionTimeout(certPair) {
  // Server greets then never answers EHLO; a small maxTransactionMs
  // trips the absolute transaction deadline (socket idle timeout kept high).
  var st = startTlsSmtp(certPair, { noEhloResponse: true });
  await listen(st);
  try {
    var t = tlsTransport(certPair, st.port, { maxTransactionMs: C.TIME.seconds(0.3), timeoutMs: C.TIME.seconds(10) });
    var e = await _sendErr(t, { from: "s@a.test", to: "r@b.test", text: "x" });
    check("smtp: transaction deadline → transaction-timeout", e && /transaction-timeout/.test(e.message));
  } finally { await closeServer(st); }
}

async function testSmtpSocketTimeout(certPair) {
  // Small socket idle timeout, large transaction deadline → 'timeout' fires.
  var st = startTlsSmtp(certPair, { noEhloResponse: true });
  await listen(st);
  try {
    var t = tlsTransport(certPair, st.port, { timeoutMs: C.TIME.seconds(0.3), maxTransactionMs: C.TIME.seconds(30) });
    var e = await _sendErr(t, { from: "s@a.test", to: "r@b.test", text: "x" });
    check("smtp: idle timeout → smtp-failed(timeout)", e && e.code === "mail/smtp-failed" && /timeout/.test(e.message));
  } finally { await closeServer(st); }
}

async function testSmtpStarttlsHappyPath(certPair) {
  var st = startStarttlsSmtp(certPair, { ext: ["8BITMIME"] });
  await listen(st);
  try {
    var t = starttlsTransport(certPair, st.port);
    var r = await t.send({ from: "s@a.test", to: "r@b.test", subject: "hi", text: "hello" });
    check("smtp-starttls: delivered after upgrade", r.code === 250);
    check("smtp-starttls: issued STARTTLS then re-EHLO",
      st.lines.filter(function (l) { return /^EHLO/i.test(l); }).length >= 2);
  } finally { await closeServer(st); }
}

async function testSmtpStarttlsRejected(certPair) {
  var st = startStarttlsSmtp(certPair, { starttls: "reject" });
  await listen(st);
  try {
    var t = starttlsTransport(certPair, st.port);
    var e = await _sendErr(t, { from: "s@a.test", to: "r@b.test", text: "x" });
    check("smtp-starttls: rejected upgrade → starttls-rejected", e && /starttls-rejected/.test(e.message));
  } finally { await closeServer(st); }
}

// ---------------------------------------------------------------------------
// reverseDns — error branches via a fake resolver injected through
// network-dns? Not injectable; use documented shape checks on bad input.
// ---------------------------------------------------------------------------

async function testReverseDnsErrorShape() {
  var r = await b.mail.reverseDns("definitely not an ip");
  check("reverseDns: bad input → ok:false + error", r.ok === false && typeof r.error === "string" && r.fcrdns === false);
}

// ---------------------------------------------------------------------------

async function run() {
  // Pure / no-socket branches first.
  testToAsciiBranches();
  testToUnicodeBranches();
  testBuildRfc822MultipartAlternative();
  testBuildRfc822CalendarCcReplyToHeaders();
  testBuildRfc822AttachmentsAndDotStuffing();
  await testConsoleTransport();
  await testMemoryTransport();
  testHttpTransportConfigGates();
  await testHttpTransportBadSerializer();
  await testHttpTransportRequestFailureWrap();
  await testHttpTransportSuccessAndInterpret();
  testResendConfigGate();
  await testResendOverLoopback();
  await testResendBadResponseAndNoId();
  testCreateOptsAndTransportShapes();
  await testCreateTransportErrorWrap();
  await testCreateUnsubscribeExpansion();
  testCreateFooterHtmlValidation();
  await testCommercialHtmlOnlyAndStringAddress();
  await testValidateMessageBranches();
  await testValidateCalendarBranches();
  await testValidateAttachmentBranches();
  await testEaiRecipientAccepted();
  testSmtpConfigGates();
  await testSmtpDkimSignFailureRejectsPreConnect();
  await testReverseDnsErrorShape();

  // SMTP state machine over loopback TLS — mint one cert pair, reuse.
  var ca = await b.mtlsEngine.generateCa({ generation: 1 });
  var leaf = await b.mtlsEngine.signClientCert({
    cn: "localhost", caCertPem: ca.caCertPem, caKeyPem: ca.caKeyPem,
    usage: "server", sans: ["IP:127.0.0.1", "localhost"],
  });
  var certPair = { key: leaf.key, cert: leaf.cert, caCertPem: ca.caCertPem };

  await testSmtpHappyPathData(certPair);
  await testSmtpAuthLogin(certPair);
  await testSmtpBdatChunking(certPair);
  await testSmtpBinaryMimeBdat(certPair);
  await testSmtpSmtpUtf8And8BitMime(certPair);
  await testSmtpSizeRefusal(certPair);
  await testSmtpEaiUnsupportedRefusal(certPair);
  await testSmtpBinaryMimeUnsupportedRefusal(certPair);
  await testSmtpRejectionCodes(certPair);
  await testSmtpResponseTooLarge(certPair);
  await testSmtpTransactionTimeout(certPair);
  await testSmtpSocketTimeout(certPair);
  await testSmtpStarttlsHappyPath(certPair);
  await testSmtpStarttlsRejected(certPair);
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[mail-coverage] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
