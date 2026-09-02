// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.mail.server.mx — inbound SMTP / MX listener.
 *
 * Tests cover the wire-protocol state machine, SMTP-smuggling defense
 * (CVE-2023-51764 / -51765 / -51766 — bare-LF dot-terminator), open-
 * relay refusal by default, STARTTLS-stripping defense, and the
 * helper byte-scan primitives (_detectSmugglingShape /
 * _findDotTerminator / _dotUnstuff).
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

var nodeNet  = require("node:net");
var nodeTls  = require("node:tls");
// The exact audit module auditEmit resolves via require("./audit") — patch
// its safeEmit to capture the drop-silent events the listener emits (there
// is no test helper for global-audit capture; restore in finally).
var auditMod = require("../../lib/audit");

function testSurface() {
  check("mx.create is fn",            typeof b.mail.server.mx.create === "function");
  check("MailServerMxError is fn",    typeof b.mail.server.mx.MailServerMxError === "function");
  // Wire-protocol parsing helpers now live in b.safeSmtp; smuggling
  // detection in b.guardSmtpCommand. The MX listener consumes both.
  check("safeSmtp.findDotTerminator is fn",
        typeof b.safeSmtp.findDotTerminator === "function");
  check("safeSmtp.dotUnstuff is fn",
        typeof b.safeSmtp.dotUnstuff === "function");
  check("guardSmtpCommand.detectBodySmuggling is fn",
        typeof b.guardSmtpCommand.detectBodySmuggling === "function");
}

function testCreateRequiresTlsContext() {
  var threw = null;
  try { b.mail.server.mx.create({}); } catch (e) { threw = e; }
  check("create refuses missing tlsContext",
    threw && threw.code === "mail-server-mx/no-tls-context");
}

function testCreateRejectsBadBounds() {
  function expectBad(label, opts) {
    var threw = null;
    try { b.mail.server.mx.create(opts); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf("mail-server-mx/") === 0);
  }
  expectBad("negative maxLineBytes refused",
    { tlsContext: {}, maxLineBytes: -1 });
  expectBad("non-array localDomains refused",
    { tlsContext: {}, localDomains: "example.com" });
  // An EMPTY localDomains is ACCEPTED and means "hosts no domains, refuses
  // every recipient". This assertion used to require the opposite, which left
  // the only constructible spelling the one that skipped the relay check
  // entirely — see testEmptyLocalDomainsRefusesEveryRecipient for what that
  // did on the wire.
  var emptyThrew = null;
  try { b.mail.server.mx.create({ tlsContext: {}, localDomains: [] }); }
  catch (e) { emptyThrew = e; }
  check("empty localDomains array is accepted (means: host nothing)",
        emptyThrew === null || (emptyThrew.code || "").indexOf("mail-server-mx/bad-opts") !== 0,
        emptyThrew && emptyThrew.message);
  expectBad("non-array relayAllowedFor refused",
    { tlsContext: {}, relayAllowedFor: "x" });
}

function testDetectSmugglingShape() {
  // Canonical CRLF-only body — no smuggling shape.
  var clean = Buffer.from("hello\r\nworld\r\n.\r\n", "utf8");
  check("clean CRLF body not flagged as smuggling",
    b.guardSmtpCommand.detectBodySmuggling(clean) === false);

  // Bare-LF dot-line smuggling shape (CVE-2023-51764).
  var smuggled = Buffer.from("hello\nworld\n.\n", "utf8");
  check("bare-LF dot-line flagged as smuggling",
    b.guardSmtpCommand.detectBodySmuggling(smuggled) === true);

  // Mid-body bare-LF without dot — not the smuggling shape.
  var mixed = Buffer.from("hello\nthere\r\n.\r\n", "utf8");
  check("bare-LF without dot terminator not flagged",
    b.guardSmtpCommand.detectBodySmuggling(mixed) === false);
}

function testFindDotTerminator() {
  var withTerm = Buffer.from("body line\r\n.\r\n", "utf8");
  var idx = b.safeSmtp.findDotTerminator(withTerm);
  // The terminator's leading CRLF ends the last line of the mail data
  // (RFC 5321 §4.1.1.4), so it is inside the message, not framing around it.
  check("mail data runs to the end of its last line",
    idx === Buffer.byteLength("body line\r\n", "utf8"), String(idx));
  check("the sliced body is what the peer transmitted",
    withTerm.subarray(0, idx).toString("utf8") === "body line\r\n");

  var noTerm = Buffer.from("body line\r\n", "utf8");
  check("no terminator returns -1",
    b.safeSmtp.findDotTerminator(noTerm) === -1);

  // CRLF dot CRLF only — RFC 5321 §2.3.8 canonical form. Bare LF
  // alone shouldn't match (smuggling defense — the terminator
  // scanner is strict-CRLF; the smuggling detector lives in
  // b.guardSmtpCommand.detectBodySmuggling).
  var bareLf = Buffer.from("body\n.\n", "utf8");
  check("bare-LF terminator does not match canonical CRLF",
    b.safeSmtp.findDotTerminator(bareLf) === -1);
}

function testDotUnstuff() {
  // ".." line at body start → "." (stuffing reversed).
  var stuffed = Buffer.from("hello\r\n..secret line\r\nworld\r\n", "utf8");
  var unstuffed = b.safeSmtp.dotUnstuff(stuffed);
  check("dot-stuffing reversed: '..' → '.'",
    unstuffed.toString("utf8") === "hello\r\n.secret line\r\nworld\r\n");

  // Plain body without dot-prefix lines passes through.
  var plain = Buffer.from("hello\r\nworld\r\n", "utf8");
  check("plain body passes through unstuff",
    b.safeSmtp.dotUnstuff(plain).toString("utf8") === "hello\r\nworld\r\n");
}

// ---- End-to-end SMTP conversation test ---------------------------------

async function _makeTestTlsContext() {
  // Mint a CA + server leaf cert via the framework's mtls-engine.
  // node:tls accepts the resulting PEM pair as a server identity for
  // TLS 1.3; we use this rather than baking a fixed test fixture into
  // the repo so the cert can't drift past expiry.
  var ca = await b.mtlsEngine.generateCa({ name: "mail-server-mx-test-ca" });
  var leaf = await b.mtlsEngine.signClientCert({
    cn:           "mx.test",
    caCertPem:    ca.caCertPem,
    caKeyPem:     ca.caKeyPem,
    usage:        "server",
    sans:         ["DNS:mx.test", "DNS:localhost", "IP:127.0.0.1"],
    validityDays: 1,
  });
  return nodeTls.createSecureContext({
    key:  leaf.key,
    cert: leaf.cert,
  });
}

async function _sendCommand(socket, line) {
  return new Promise(function (resolve, reject) {
    var buf = "";
    function onData(chunk) {
      buf += chunk.toString("utf8");
      if (buf.indexOf("\r\n") !== -1) {
        // Read until the LAST "code SP" line — multi-line 250- responses
        // have continuation lines starting with "code-".
        var lines = buf.split("\r\n").filter(Boolean);
        var last = lines[lines.length - 1];
        if (/^\d{3} /.test(last)) {
          socket.removeListener("data", onData);
          socket.removeListener("error", onError);
          resolve(buf);
        }
      }
    }
    // Detach on settle — a long transaction issues a dozen commands on
    // one socket, and never-fired once("error") handlers accumulate
    // past the MaxListeners warning threshold.
    function onError(e) { socket.removeListener("data", onData); reject(e); }
    socket.on("data", onData);
    socket.once("error", onError);
    socket.write(line + "\r\n");
  });
}

async function _readGreeting(socket) {
  return new Promise(function (resolve, reject) {
    var buf = "";
    function onData(chunk) {
      buf += chunk.toString("utf8");
      if (buf.indexOf("\r\n") !== -1) {
        socket.removeListener("data", onData);
        socket.removeListener("error", onError);
        resolve(buf);
      }
    }
    function onError(e) { socket.removeListener("data", onData); reject(e); }
    socket.on("data", onData);
    socket.once("error", onError);
  });
}

// Passive accumulator for unsolicited server replies (idle-timeout 421,
// shutdown 421) — the caller polls the buffer via helpers.waitUntil rather
// than issuing a command. Swallows post-close socket errors (ECONNRESET
// when the server destroys the connection) so they don't reject the run.
function _collect(socket) {
  var buf = "";
  socket.on("data", function (chunk) { buf += chunk.toString("utf8"); });
  socket.on("error", function () { /* connection torn down by server; ignore */ });
  return { text: function () { return buf; } };
}

// Capture the drop-silent audit events the listener emits while `fn`'s
// window is open. Patches the exact module object auditEmit resolves and
// restores it unconditionally, so no global-audit state leaks to the
// smoke harness.
function _withAuditCapture(fn) {
  var events = [];
  var orig = auditMod.safeEmit;
  auditMod.safeEmit = function (evt) {
    events.push(evt);
    return orig.call(auditMod, evt);
  };
  return Promise.resolve()
    .then(function () { return fn(events); })
    .finally(function () { auditMod.safeEmit = orig; });
}

// Connect + read the 220 greeting, returning the live socket.
async function _connectTo(info) {
  var socket = nodeNet.connect(info.port, "127.0.0.1");
  await new Promise(function (r) { socket.once("connect", r); });
  await _readGreeting(socket);
  return socket;
}

// An unknown mailbox on a local domain had no reachable refusal. The listener
// decided recipients from localDomains alone, so every local part was accepted
// at RCPT, and the application first learned the recipient at agent.handoff —
// after 354 and after the whole message. From there the only answers were 250
// (tell the peer it arrived, then owe a DSN) or 451 (tell a peer holding a
// permanent condition to keep retrying). The correct answer, 550 5.1.1 at
// RCPT, was not expressible.
//
// The submission listener already had `recipientPolicy`. MX, where an unknown
// mailbox actually arrives, did not.
// An empty allowlist means "permit nothing". It must never mean "no
// restriction" — an allowlist that disappears when empty is a firewall rule set
// that opens when the last rule is deleted.
//
// `mail.server.mx` had no spelling for "this server hosts no domains yet", and
// the two available spellings failed in opposite directions: `localDomains: []`
// was refused at construction, while omitting it constructed a listener whose
// relay check was nested inside a non-empty test and therefore never ran. The
// only spelling that started a server was the one that turned the check off,
// and every RCPT TO was accepted.
//
// Delivery still failed later, so nothing was relayed. What a relay prober sees
// is 250 at MAIL FROM and 250 at RCPT TO for a sender and recipient the server
// has no relationship with, which is what a blocklist operator acts on; and the
// eventual refusal is a transient 451 that arrives only after the peer has
// transmitted the whole message, so it retries indefinitely.
async function testEmptyLocalDomainsRefusesEveryRecipient() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("mx empty localDomains (skipped — cert fixture unavailable)", true); return; }

  // The explicit spelling must construct: a server hosting nothing has to be
  // able to bind and refuse politely, not be unable to start.
  var srv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: [],
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var socket = await _connectTo(info);
  try {
    await _sendCommand(socket, "EHLO scanner.example.net");
    await _sendCommand(socket, "MAIL FROM:<attacker@evil.example.net>");
    var rcpt = await _sendCommand(socket, "RCPT TO:<victim@unrelated.example.org>");
    check("mx: with localDomains [] every recipient is refused at RCPT",
          /^550 /.test(rcpt), JSON.stringify(rcpt));
    check("mx: and the refusal says relaying denied, not a transient error",
          /5\.7\.1/.test(rcpt), JSON.stringify(rcpt));
  } finally {
    try { socket.destroy(); } catch (_e) { /* already gone */ }
    await srv.close({ timeoutMs: 1000 });                                                              // allow:raw-time-literal — test-only short drain
  }

  // Omitting the option entirely must behave the same way. This is the shape
  // that shipped: absent normalised to an empty set, and the check was skipped.
  var srv2 = b.mail.server.mx.create({ tlsContext: ctx, profile: "permissive" });
  var info2 = await srv2.listen({ port: 0, address: "127.0.0.1" });
  var socket2 = await _connectTo(info2);
  try {
    await _sendCommand(socket2, "EHLO scanner.example.net");
    await _sendCommand(socket2, "MAIL FROM:<attacker@evil.example.net>");
    var rcpt2 = await _sendCommand(socket2, "RCPT TO:<victim@unrelated.example.org>");
    check("mx: an absent localDomains refuses every recipient too",
          /^550 /.test(rcpt2), JSON.stringify(rcpt2));
  } finally {
    try { socket2.destroy(); } catch (_e) { /* already gone */ }
    await srv2.close({ timeoutMs: 1000 });                                                             // allow:raw-time-literal — test-only short drain
  }

  // Control: a configured domain is still accepted, so the above is refusing a
  // recipient the server does not host rather than refusing everything.
  var srv3 = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
  });
  var info3 = await srv3.listen({ port: 0, address: "127.0.0.1" });
  var socket3 = await _connectTo(info3);
  try {
    await _sendCommand(socket3, "EHLO sender.example.com");
    await _sendCommand(socket3, "MAIL FROM:<peer@sender.example.com>");
    var ok = await _sendCommand(socket3, "RCPT TO:<alice@example.com>");
    check("mx control: a hosted domain is still accepted",
          /^250 /.test(ok), JSON.stringify(ok));
    var off = await _sendCommand(socket3, "RCPT TO:<victim@unrelated.example.org>");
    check("mx control: an unhosted domain is still refused",
          /^550 /.test(off), JSON.stringify(off));
  } finally {
    try { socket3.destroy(); } catch (_e) { /* already gone */ }
    await srv3.close({ timeoutMs: 1000 });                                                             // allow:raw-time-literal — test-only short drain
  }
}

// Hosting a domain is administrative state, not configuration. Captured at
// create(), a withdrawn domain kept drawing 250 at RCPT until the process
// restarted — every management surface agreed it was gone, and nothing told the
// operator mail was still arriving for it. The neighbouring recipientPolicy was
// already answered per RCPT, so one question had two halves of different age.
async function testLocalDomainsCanBeAnsweredPerRecipient() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("mx live localDomains (skipped — cert fixture unavailable)", true); return; }

  // ONE array, mutated in place — the way an operator actually keeps this
  // state. A resolver that cached on the array's identity would normalize this
  // once and then answer from the frozen copy forever, which is the very bug
  // the callback exists to fix.
  var hosted = ["example.com"];
  var srv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive",
    localDomains: function () { return hosted; },
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var socket = await _connectTo(info);
  try {
    await _sendCommand(socket, "EHLO sender.example.com");
    await _sendCommand(socket, "MAIL FROM:<peer@sender.example.com>");
    check("mx: a hosted domain from the callback is accepted",
      /^250 /.test(await _sendCommand(socket, "RCPT TO:<alice@example.com>")));
    check("mx: one it does not name is refused",
      /^550 /.test(await _sendCommand(socket, "RCPT TO:<bob@added.example.org>")));

    // Add one, in place. A sender told 550 a moment ago is now accepted, with
    // no restart and nothing swapped on the listener.
    hosted.push("added.example.org");
    check("mx: a domain added while the server runs is accepted",
      /^250 /.test(await _sendCommand(socket, "RCPT TO:<bob@added.example.org>")));

    // Withdraw one, in place. This is the direction that bit: it used to keep
    // answering 250 for a domain the operator had stopped hosting.
    hosted.splice(hosted.indexOf("example.com"), 1);
    check("mx: a withdrawn domain stops being accepted",
      /^550 /.test(await _sendCommand(socket, "RCPT TO:<alice@example.com>")));
    check("mx: and the one still hosted keeps working",
      /^250 /.test(await _sendCommand(socket, "RCPT TO:<bob@added.example.org>")));

    // An entry the domain guard refuses is dropped, not thrown on — the
    // connection that happened to arrive must not become an outage. An IP
    // literal is one of the shapes the boot check already refuses.
    hosted.push("192.0.2.1");
    check("mx: a bad entry in a live set does not kill the connection",
      /^250 /.test(await _sendCommand(socket, "RCPT TO:<bob@added.example.org>")));
    var badEntryReply = await _sendCommand(socket, "RCPT TO:<eve@192.0.2.1>");
    check("mx: and mail for that entry is refused",
      /^5\d\d /.test(badEntryReply), JSON.stringify(badEntryReply));

    // A set that cannot be read refuses rather than accepting, and the
    // listener stays up to say so.
    hosted = "example.com";                       // a string, not an array
    check("mx: a set of the wrong shape refuses every recipient",
      /^550 /.test(await _sendCommand(socket, "RCPT TO:<bob@added.example.org>")));

    // A self-referencing array does not end the connection. The cycle coerces
    // to a string the domain guard rejects, so that entry drops and the valid
    // one beside it keeps serving — the same answer any other bad entry gets.
    var circular = ["added.example.org"];
    circular.push(circular);
    hosted = circular;
    check("mx: a self-referencing set drops the bad entry and keeps serving",
      /^250 /.test(await _sendCommand(socket, "RCPT TO:<bob@added.example.org>")));

    // Two DIFFERENT hosted sets must not share a cache key. Objects with
    // different toString() results are indistinguishable to JSON.stringify —
    // both serialize as {} — so keying the cache on the raw array answered the
    // second set from the first one's cached result, and a withdrawn domain
    // stayed accepted. The key is built from the coerced strings for that
    // reason.
    hosted = [{ toString: function () { return "first.example.org"; } }];
    check("mx: a domain named by a coercible object is hosted",
      /^250 /.test(await _sendCommand(socket, "RCPT TO:<a@first.example.org>")));
    hosted = [{ toString: function () { return "second.example.org"; } }];
    check("mx: swapping it for another object-named domain is seen",
      /^250 /.test(await _sendCommand(socket, "RCPT TO:<a@second.example.org>")));
    check("mx: and the one it replaced is no longer accepted",
      /^550 /.test(await _sendCommand(socket, "RCPT TO:<a@first.example.org>")));

    // An entry whose string coercion throws is dropped like any other bad one,
    // and the entries around it keep serving. Guarding the serialization alone
    // would not have caught this — the array stringifies fine and the throw
    // happens per entry.
    var hostile = Object.create(null);
    Object.defineProperty(hostile, "toString", {
      value: function () { throw new Error("no string for you"); },
    });
    hosted = ["added.example.org", hostile];
    check("mx: an entry that cannot be coerced is dropped, not fatal",
      /^250 /.test(await _sendCommand(socket, "RCPT TO:<bob@added.example.org>")));

    // And the listener is still answering afterwards, which is the part that
    // distinguishes "refused" from "the socket died".
    hosted = ["added.example.org"];
    check("mx: and the connection recovers once the set is readable again",
      /^250 /.test(await _sendCommand(socket, "RCPT TO:<bob@added.example.org>")));
  } finally {
    try { socket.destroy(); } catch (_e) { /* already gone */ }
    await srv.close({ timeoutMs: 1000 });                                                              // allow:raw-time-literal — test-only short drain
  }
}

async function testRecipientPolicyRefusesUnknownMailbox() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("mx recipientPolicy (skipped — cert fixture unavailable)", true); return; }

  var seen = [];
  var srv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
    recipientPolicy: function (rcptCtx) {
      seen.push(rcptCtx);
      return rcptCtx.rcptTo === "alice@example.com"
        ? { ok: true }
        : { ok: false, reason: "No such user here" };
    },
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var socket = await _connectTo(info);
  try {
    await _sendCommand(socket, "EHLO sender.example.com");
    await _sendCommand(socket, "MAIL FROM:<peer@sender.example.com>");

    var unknown = await _sendCommand(socket, "RCPT TO:<nobody@example.com>");
    check("mx: an unknown mailbox is refused 550 at RCPT, before DATA",
          /^550 /.test(unknown), JSON.stringify(unknown));
    check("mx: the refusal carries the RFC 3463 mailbox-unavailable code",
          /5\.1\.1/.test(unknown), JSON.stringify(unknown));
    check("mx: the policy's reason reaches the peer",
          unknown.indexOf("No such user here") !== -1, JSON.stringify(unknown));

    // The control: a recipient the policy accepts must still be accepted, or
    // "refused" above would just mean the hook rejects everything.
    var known = await _sendCommand(socket, "RCPT TO:<alice@example.com>");
    check("mx control: an accepted recipient still gets 250",
          /^250 /.test(known), JSON.stringify(known));

    check("mx: the hook saw both recipients with the envelope context",
          seen.length === 2 && seen[0].rcptTo === "nobody@example.com" &&
          seen[0].mailFrom === "peer@sender.example.com" &&
          typeof seen[0].remoteAddress === "string",
          JSON.stringify(seen));

    // DATA must proceed on the surviving recipient — a refused RCPT does not
    // poison the transaction.
    check("mx: DATA proceeds for the accepted recipient",
          /^354 /.test(await _sendCommand(socket, "DATA")));
  } finally { socket.destroy(); await srv.close(); }
}

// The reason is written into a line-oriented SMTP reply, and a directory-derived
// reason routinely quotes the address that was looked up — which the peer chose.
// A CR or LF in it ends the 550 line early and the remainder is read by the peer
// as a second, forged server reply.
async function testRecipientPolicyReasonCannotForgeAReplyLine() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("mx recipientPolicy reason injection (skipped — cert fixture)", true); return; }

  var srv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
    recipientPolicy: function (rcptCtx) {
      // The shape a directory wrapper produces: the looked-up address, echoed.
      return { ok: false, reason: "No such user: " + rcptCtx.rcptTo };
    },
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var socket = await _connectTo(info);
  try {
    await _sendCommand(socket, "EHLO sender.example.com");
    await _sendCommand(socket, "MAIL FROM:<peer@sender.example.com>");
    // The local part carries the injection. RCPT TO is where the peer speaks.
    var reply = await _sendCommand(socket,
      "RCPT TO:<evil\r\n250 Accepted@example.com>");
    check("mx: a reason carrying CRLF does not emit a second reply line",
          reply.indexOf("250 Accepted") === -1, JSON.stringify(reply));
    check("mx: the recipient is still refused", /^5\d\d /.test(reply), JSON.stringify(reply));
  } finally { socket.destroy(); await srv.close(); }

  // And directly: a policy that simply returns a terminator-bearing reason must
  // not be able to write it, whatever the recipient looked like.
  var srv2 = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
    recipientPolicy: function () {
      return { ok: false, reason: "gone\r\n250 Accepted" };
    },
  });
  var info2 = await srv2.listen({ port: 0, address: "127.0.0.1" });
  var socket2 = await _connectTo(info2);
  try {
    await _sendCommand(socket2, "EHLO sender.example.com");
    await _sendCommand(socket2, "MAIL FROM:<peer@sender.example.com>");
    var reply2 = await _sendCommand(socket2, "RCPT TO:<nobody@example.com>");
    check("mx: an unsafe reason is replaced, not written",
          reply2.indexOf("250 Accepted") === -1, JSON.stringify(reply2));
    check("mx: the refusal still carries the 5.1.1 code",
          /5\.1\.1/.test(reply2), JSON.stringify(reply2));

  } finally { socket2.destroy(); await srv2.close(); }

  // Control: a clean reason still reaches the peer, so the guard is replacing
  // only what it must rather than discarding every reason.
  var srv3 = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
    recipientPolicy: function () { return { ok: false, reason: "No such user here" }; },
  });
  var info3 = await srv3.listen({ port: 0, address: "127.0.0.1" });
  var socket3 = await _connectTo(info3);
  try {
    await _sendCommand(socket3, "EHLO sender.example.com");
    await _sendCommand(socket3, "MAIL FROM:<peer@sender.example.com>");
    var reply3 = await _sendCommand(socket3, "RCPT TO:<nobody@example.com>");
    check("mx control: a clean reason still reaches the peer",
          reply3.indexOf("No such user here") !== -1, JSON.stringify(reply3));
  } finally { socket3.destroy(); await srv3.close(); }

  // The shared helper itself, since two listeners now depend on it.
  var mailServerNet = require("../../lib/mail-server-net.js");
  check("replyTextOrFallback: clean text passes through",
        mailServerNet.replyTextOrFallback("No such user", "fb") === "No such user");
  check("replyTextOrFallback: CR falls back",
        mailServerNet.replyTextOrFallback("a\r\n250 ok", "fb") === "fb");
  check("replyTextOrFallback: LF falls back",
        mailServerNet.replyTextOrFallback("a\nb", "fb") === "fb");
  check("replyTextOrFallback: NUL falls back",
        mailServerNet.replyTextOrFallback("a" + String.fromCharCode(0), "fb") === "fb");
  check("replyTextOrFallback: empty and non-string fall back",
        mailServerNet.replyTextOrFallback("", "fb") === "fb" &&
        mailServerNet.replyTextOrFallback(undefined, "fb") === "fb" &&
        mailServerNet.replyTextOrFallback(42, "fb") === "fb");
}

// A 550 at RCPT is a mailbox-existence oracle: the difference between 250 and
// 550 tells a scanner which local parts exist. The relay-denied refusal already
// charges the per-IP recipient-failure budget for exactly this reason, and a
// policy refusal has to charge it too — otherwise adding the hook hands
// scanners a free enumeration channel the listener previously did not have.
async function testRecipientPolicyRefusalCostsTheScannerBudget() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("mx recipientPolicy budget (skipped — cert fixture)", true); return; }

  var noted = 0;
  var real = b.mail.server.rateLimit.create({});
  var counting = {};
  Object.keys(real).forEach(function (k) {
    counting[k] = typeof real[k] === "function"
      ? function () { return real[k].apply(real, arguments); }
      : real[k];
  });
  counting.noteRcptFailure = function (ip) { noted += 1; return real.noteRcptFailure(ip); };

  var srv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
    rateLimit: counting,
    recipientPolicy: function () { return { ok: false, reason: "No such user" }; },
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var socket = await _connectTo(info);
  try {
    await _sendCommand(socket, "EHLO sender.example.com");
    await _sendCommand(socket, "MAIL FROM:<peer@sender.example.com>");
    await _sendCommand(socket, "RCPT TO:<nobody@example.com>");
    check("mx: a policy refusal charges the per-IP recipient-failure budget",
          noted === 1, String(noted));
  } finally { socket.destroy(); await srv.close(); }
}

// A hook that throws is the operator's policy engine being unavailable, not a
// verdict about this mailbox. Answering 550 there would permanently reject mail
// for a legitimate recipient because a lookup failed.
async function testRecipientPolicyThrowIsTransient() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("mx recipientPolicy throw (skipped — cert fixture)", true); return; }

  var srv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
    recipientPolicy: function () { throw new Error("directory unreachable"); },
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var socket = await _connectTo(info);
  try {
    await _sendCommand(socket, "EHLO sender.example.com");
    await _sendCommand(socket, "MAIL FROM:<peer@sender.example.com>");
    var reply = await _sendCommand(socket, "RCPT TO:<alice@example.com>");
    check("mx: a throwing recipient policy defers 451, never refuses 550",
          /^451 /.test(reply), JSON.stringify(reply));
  } finally { socket.destroy(); await srv.close(); }
}

// `minBytesPerSecond` was validated at construction, defaulted, and exposed as
// a getter that no listener ever called. The policy test in
// mail-server-rate-limit.test.js pins the number; this pins that the listener
// ASKS. A limiter whose floor is unreachable in a fast test is substituted, so
// the test does not have to spend the ten-second grace window to reach the
// branch.
async function testBodyRateFloorIsAskedDuringData() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("mx body-rate floor (skipped — cert fixture)", true); return; }

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

  var srv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
    rateLimit: starving,
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var socket = await _connectTo(info);
  try {
    await _sendCommand(socket, "EHLO sender.example.com");
    await _sendCommand(socket, "MAIL FROM:<peer@sender.example.com>");
    await _sendCommand(socket, "RCPT TO:<alice@example.com>");
    check("mx: DATA opens", /^354 /.test(await _sendCommand(socket, "DATA")));

    // A COMPLETE body, terminator included. The rate check runs before the
    // scanner looks for the terminator, so a starved verdict still refuses —
    // and without the terminator a listener that never asks would leave this
    // read hanging instead of failing, which is a test that cannot go red.
    var reply = await _sendCommand(socket, "Subject: trickle\r\n\r\nx\r\n.");
    check("mx: a body below the rate floor is refused 421, not accepted",
          /^421 /.test(reply), JSON.stringify(reply));
    check("mx: the refusal names a transient condition, not a permanent one",
          /4\.7\.0/.test(reply), JSON.stringify(reply));
    check("mx: the listener asked the limiter about the body rate",
          asked.length >= 1, String(asked.length));
    // Elapsed is measured from 354, not from connect: a peer that idles before
    // DATA has not yet sent a body, and charging it that time would cut off a
    // sender that paused between RCPT and DATA.
    check("mx: elapsed is measured from the DATA prompt",
          asked.length >= 1 && asked[0].elapsedMs >= 0 && asked[0].elapsedMs < 30000,
          asked.length ? String(asked[0].elapsedMs) : "never asked");
    // The bytes reported must include the chunk being judged. Reporting only
    // what was already banked understates the rate by exactly the newest
    // chunk, which on a one-chunk body is the entire message.
    check("mx: the bytes reported include the chunk under judgement",
          asked.length >= 1 && asked[0].bytes > 0,
          asked.length ? String(asked[0].bytes) : "never asked");
  } finally { socket.destroy(); await srv.close(); }
}

async function testEhloFlow() {
  // Boot the server with a permissive profile so plaintext EHLO works
  // (operator-acknowledged downgrade for staging). Skip if the test
  // cert fixture isn't available.
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) {
    check("EHLO flow (skipped — test cert fixture unavailable)", true);
    return;
  }
  var srv = b.mail.server.mx.create({
    tlsContext:   ctx,
    profile:      "permissive",
    localDomains: ["example.com"],
  });
  var listenInfo = await srv.listen({ port: 0, address: "127.0.0.1" });
  try {
    var socket = nodeNet.connect(listenInfo.port, "127.0.0.1");
    await new Promise(function (r) { socket.once("connect", r); });
    var greeting = await _readGreeting(socket);
    check("server sends 220 greeting", /^220 /.test(greeting));

    var ehloReply = await _sendCommand(socket, "EHLO sender.example.com");
    check("EHLO returns 250 with capabilities",
      /^250-/m.test(ehloReply) && /^250 ENHANCEDSTATUSCODES/m.test(ehloReply));
    check("EHLO advertises STARTTLS",      /250.STARTTLS/.test(ehloReply));
    check("EHLO advertises SIZE",          /250.SIZE \d+/.test(ehloReply));

    var mailReply = await _sendCommand(socket, "MAIL FROM:<sender@external.com>");
    check("MAIL FROM accepted under permissive",  /^250 /.test(mailReply));

    var rcptReply = await _sendCommand(socket, "RCPT TO:<alice@example.com>");
    check("RCPT TO local domain accepted",  /^250 /.test(rcptReply));

    var dataReply = await _sendCommand(socket, "DATA");
    check("DATA returns 354 prompt",        /^354 /.test(dataReply));

    var endReply = await _sendCommand(socket, "Subject: test\r\nFrom: sender@external.com\r\n\r\nHello world.\r\n.");
    check("DATA body accepted with 250",    /^250 /.test(endReply));

    var quitReply = await _sendCommand(socket, "QUIT");
    check("QUIT returns 221 bye",           /^221 /.test(quitReply));
    socket.destroy();
  } finally {
    await srv.close({ timeoutMs: 1000 });                                                            // allow:raw-time-literal — test-only short drain
  }
}

async function testRelayRefused() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) {
    check("Relay refusal (skipped)", true);
    return;
  }
  var srv = b.mail.server.mx.create({
    tlsContext:   ctx,
    profile:      "permissive",
    localDomains: ["example.com"],
  });
  var listenInfo = await srv.listen({ port: 0, address: "127.0.0.1" });
  try {
    var socket = nodeNet.connect(listenInfo.port, "127.0.0.1");
    await new Promise(function (r) { socket.once("connect", r); });
    await _readGreeting(socket);
    await _sendCommand(socket, "EHLO sender.example.com");
    await _sendCommand(socket, "MAIL FROM:<sender@external.com>");
    var rcptReply = await _sendCommand(socket, "RCPT TO:<bob@notlocal.example>");
    check("non-local RCPT refused with 550 5.7.1",
      /^550 5\.7\.1/.test(rcptReply));
    socket.destroy();
  } finally {
    await srv.close({ timeoutMs: 1000 });                                                            // allow:raw-time-literal — test-only short drain
  }
}

async function testStrictProfileRequiresStartTls() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) {
    check("strict-profile STARTTLS gate (skipped)", true);
    return;
  }
  var srv = b.mail.server.mx.create({
    tlsContext:   ctx,
    profile:      "strict",  // requires STARTTLS before MAIL FROM
    localDomains: ["example.com"],
  });
  var listenInfo = await srv.listen({ port: 0, address: "127.0.0.1" });
  try {
    var socket = nodeNet.connect(listenInfo.port, "127.0.0.1");
    await new Promise(function (r) { socket.once("connect", r); });
    await _readGreeting(socket);
    await _sendCommand(socket, "EHLO sender.example.com");
    var mailReply = await _sendCommand(socket, "MAIL FROM:<sender@external.com>");
    check("strict-profile refuses plaintext MAIL FROM with 530",
      /^530 5\.7\.0/.test(mailReply));
    socket.destroy();
  } finally {
    await srv.close({ timeoutMs: 1000 });                                                            // allow:raw-time-literal — test-only short drain
  }
}

// Connection-level gates (helo / rbl / greylist) wired into the live
// state machine. Each gate is an operator-supplied object; we drive the
// real wire protocol with mock gates and assert the SMTP verdict.
async function testConnectionGates() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) {
    check("connection gates (skipped — test cert fixture unavailable)", true);
    return;
  }

  async function _connect(srv) {
    var info = await srv.listen({ port: 0, address: "127.0.0.1" });
    var socket = nodeNet.connect(info.port, "127.0.0.1");
    await new Promise(function (r) { socket.once("connect", r); });
    await _readGreeting(socket);
    return socket;
  }

  // ---- greylist defer → 450 tempfail at RCPT ----
  var greySrv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
    greylist: { check: async function () { return { action: "defer", reason: "first-seen" }; } },
  });
  var grerr = null, greySock;
  try {
    greySock = await _connect(greySrv);
    await _sendCommand(greySock, "EHLO sender.example.com");
    await _sendCommand(greySock, "MAIL FROM:<s@external.com>");
    var greyRcpt = await _sendCommand(greySock, "RCPT TO:<alice@example.com>");
    check("greylist defer → 450 tempfail", /^450 4\.7\.1/.test(greyRcpt));
    greySock.destroy();
  } catch (e) { grerr = e; } finally { await greySrv.close({ timeoutMs: 1000 }); }   // allow:raw-time-literal — test-only short drain
  check("greylist gate ran without error", grerr === null);

  // ---- RBL listed → 554 at RCPT ----
  var rblSrv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
    rbl: { query: async function () {
      return { listed: [{ zone: "zen.spamhaus.org" }], allowed: [], neutral: [], errors: [] };
    } },
  });
  try {
    var rblSock = await _connect(rblSrv);
    await _sendCommand(rblSock, "EHLO sender.example.com");
    await _sendCommand(rblSock, "MAIL FROM:<s@external.com>");
    var rblRcpt = await _sendCommand(rblSock, "RCPT TO:<alice@example.com>");
    check("RBL-listed IP → 554 at RCPT", /^554 5\.7\.1/.test(rblRcpt));
    rblSock.destroy();
  } finally { await rblSrv.close({ timeoutMs: 1000 }); }                              // allow:raw-time-literal — test-only short drain

  // ---- helo hard-reject → 550 at EHLO ----
  var heloSrv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
    helo: { evaluate: async function () { return { action: "reject-shape" }; } },
  });
  try {
    var heloSock = await _connect(heloSrv);
    // A syntactically-valid domain (passes guardDomain) so the refusal
    // comes from the helo GATE (reject-shape), not domain hardening.
    var heloReply = await _sendCommand(heloSock, "EHLO sender.example.com");
    check("helo hard-reject → 550 at EHLO", /^550 5\.7\.1/.test(heloReply));
    heloSock.destroy();
  } finally { await heloSrv.close({ timeoutMs: 1000 }); }                             // allow:raw-time-literal — test-only short drain

  // ---- gates that accept → normal flow (gate ran + passed) ----
  var passSrv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
    helo:     { evaluate: async function () { return { action: "accept" }; } },
    rbl:      { query:    async function () { return { listed: [], allowed: [], neutral: [], errors: [] }; } },
    greylist: { check:    async function () { return { action: "accept", reason: "known" }; } },
  });
  try {
    var passSock = await _connect(passSrv);
    await _sendCommand(passSock, "EHLO sender.example.com");
    await _sendCommand(passSock, "MAIL FROM:<s@external.com>");
    var passRcpt = await _sendCommand(passSock, "RCPT TO:<alice@example.com>");
    check("accepting gates → RCPT 250", /^250 /.test(passRcpt));
    passSock.destroy();
  } finally { await passSrv.close({ timeoutMs: 1000 }); }                             // allow:raw-time-literal — test-only short drain

  // ---- async-serial pump: pipelined commands (RFC 2920) keep ordering
  // even though the greylist gate awaits between RCPTs. Send EHLO + MAIL
  // + RCPT in a single write; the deferred RCPT must still answer 450
  // and replies must arrive in order. ----
  var slowCount = 0;
  var pipeSrv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
    greylist: { check: async function () {
      slowCount += 1;
      await helpers.waitUntil(function () { return true; }, { timeoutMs: 100, label: "gate async yield" });
      return { action: "defer", reason: "first-seen" };
    } },
  });
  try {
    var pipeInfo = await pipeSrv.listen({ port: 0, address: "127.0.0.1" });
    var pipeSock = nodeNet.connect(pipeInfo.port, "127.0.0.1");
    await new Promise(function (r) { pipeSock.once("connect", r); });
    await _readGreeting(pipeSock);
    // Pipeline EHLO + MAIL + RCPT in one TCP write.
    var combined = await new Promise(function (resolve, reject) {
      var buf = "";
      function onData(chunk) {
        buf += chunk.toString("utf8");
        if (/^450 /m.test(buf)) { pipeSock.removeListener("data", onData); resolve(buf); }
      }
      pipeSock.on("data", onData);
      pipeSock.once("error", reject);
      pipeSock.write("EHLO sender.example.com\r\nMAIL FROM:<s@external.com>\r\nRCPT TO:<alice@example.com>\r\n");
    });
    var idx250ehlo = combined.indexOf("250");
    var idx450 = combined.indexOf("450");
    check("pipelined commands answered in order (250… before 450)",
      idx250ehlo !== -1 && idx450 !== -1 && idx250ehlo < idx450);
    check("greylist gate ran exactly once for the pipelined RCPT", slowCount === 1);
    pipeSock.destroy();
  } finally { await pipeSrv.close({ timeoutMs: 1000 }); }                             // allow:raw-time-literal — test-only short drain
}

// Gates must run + serialize on the POST-STARTTLS path too — the default
// strict/balanced profiles require STARTTLS before MAIL, so that's where
// the gates actually fire. Mint a CA so the client can trust the upgraded
// connection (no rejectUnauthorized bypass), do a real STARTTLS handshake,
// and assert the greylist gate produces 450 over TLS.
async function testGateOverStartTls() {
  var ca, leaf;
  try {
    ca = await b.mtlsEngine.generateCa({ name: "mx-starttls-test-ca" });
    leaf = await b.mtlsEngine.signClientCert({
      cn: "localhost", caCertPem: ca.caCertPem, caKeyPem: ca.caKeyPem,
      usage: "server", sans: ["DNS:localhost", "IP:127.0.0.1"], validityDays: 1,
    });
  } catch (_e) {
    check("gate over STARTTLS (skipped — cert fixture unavailable)", true);
    return;
  }
  var ctx = nodeTls.createSecureContext({ key: leaf.key, cert: leaf.cert });
  var srv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "strict", localDomains: ["example.com"],
    greylist: { check: async function () { return { action: "defer", reason: "first-seen" }; } },
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var plain, tlsSock;
  try {
    plain = nodeNet.connect(info.port, "127.0.0.1");
    await new Promise(function (r) { plain.once("connect", r); });
    await _readGreeting(plain);
    await _sendCommand(plain, "EHLO sender.example.com");
    var stReply = await _sendCommand(plain, "STARTTLS");
    check("STARTTLS → 220 ready", /^220 /.test(stReply));
    tlsSock = nodeTls.connect({ socket: plain, ca: [ca.caCertPem], servername: "localhost" });
    await new Promise(function (r, j) {
      tlsSock.once("secureConnect", r); tlsSock.once("error", j);
    });
    await _sendCommand(tlsSock, "EHLO sender.example.com");   // re-issue per RFC 3207 §4.2
    await _sendCommand(tlsSock, "MAIL FROM:<s@external.com>");
    var rcpt = await _sendCommand(tlsSock, "RCPT TO:<alice@example.com>");
    check("greylist gate runs on the post-STARTTLS serialized pump → 450",
      /^450 4\.7\.1/.test(rcpt));
    tlsSock.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                 // allow:raw-time-literal — test-only short drain
}

// DATA-phase SPF/DKIM/DMARC gate (opts.guardEnvelope → b.mail.inbound
// .verify). Drives full SMTP transactions against a mocked DNS: the
// policy-reject path answers 550 5.7.1 before the agent handoff, the
// aligned path delivers with the verdict on the handoff ctx + the
// RFC 8601 Authentication-Results header prepended, quarantine
// delivers annotated, monitor mode never refuses, and DNS temperror
// defers (451) or accepts per onTemperror.
async function testGuardEnvelopeGate() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("guardEnvelope gate (skipped — test cert fixture unavailable)", true); return; }
  var records = {
    "external.com/TXT":         [["v=spf1 ip4:127.0.0.1 -all"]],
    "_dmarc.external.com/TXT":  [["v=DMARC1; p=reject"]],
    "spoof.example/TXT":        [["v=spf1 -all"]],
    "_dmarc.spoof.example/TXT": [["v=DMARC1; p=reject"]],
    "spoofq.example/TXT":        [["v=spf1 -all"]],
    "_dmarc.spoofq.example/TXT": [["v=DMARC1; p=quarantine"]],
  };
  var dnsLookup = async function (host, type) {
    if (records[host + "/" + type]) return records[host + "/" + type];
    var err = new Error("ENOTFOUND"); err.code = "ENOTFOUND"; throw err;
  };
  async function _transact(socket, mailFrom, body) {
    await _sendCommand(socket, "MAIL FROM:<" + mailFrom + ">");
    await _sendCommand(socket, "RCPT TO:<alice@example.com>");
    await _sendCommand(socket, "DATA");
    return _sendCommand(socket, body + "\r\n.");
  }

  // Boot-time validation of the gate config.
  var eBad = null;
  try {
    b.mail.server.mx.create({ tlsContext: ctx, guardEnvelope: "yes" });
  } catch (e) { eBad = e; }
  check("guardEnvelope: non-boolean/object config refused at boot", eBad !== null);
  var eMode = null;
  try {
    b.mail.server.mx.create({ tlsContext: ctx, guardEnvelope: { mode: "loud" } });
  } catch (e) { eMode = e; }
  check("guardEnvelope: unknown mode refused at boot", eMode !== null);
  // DKIM verifier ranges are mirrored at boot — a config the verifier
  // would refuse per-message must fail startup, not break live SMTP.
  var eSigs = null;
  try {
    b.mail.server.mx.create({ tlsContext: ctx, guardEnvelope: { maxSignatures: 100 } });
  } catch (e) { eSigs = e; }
  check("guardEnvelope: maxSignatures above the DKIM verifier ceiling refused at boot",
        eSigs !== null && /bad-bound/.test(eSigs.code || ""));
  var eSkew = null;
  try {
    b.mail.server.mx.create({ tlsContext: ctx,
      guardEnvelope: { clockSkewMs: b.mail.dkim.DKIM_CLOCK_SKEW_MS_MAX + 1 } });
  } catch (e) { eSkew = e; }
  check("guardEnvelope: clockSkewMs above the DKIM verifier ceiling refused at boot",
        eSkew !== null && /bad-bound/.test(eSkew.code || ""));

  // ---- enforce mode ----
  var handoffs = [];
  var srv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
    guardEnvelope: { mode: "enforce", dnsLookup: dnsLookup },
    agent: { handoff: async function (h) { handoffs.push(h); return { messageId: "m" + handoffs.length }; } },
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  try {
    var sock = nodeNet.connect(info.port, "127.0.0.1");
    await new Promise(function (r) { sock.once("connect", r); });
    await _readGreeting(sock);
    await _sendCommand(sock, "EHLO sender.example.com");

    // Policy reject: SPF fail against p=reject → refused at the wire
    // with the RFC 7372 multiple-authentication-checks-failed code.
    var rej = await _transact(sock, "ceo@spoof.example",
      "From: ceo@spoof.example\r\nSubject: urgent\r\n\r\npay this invoice\r\n");
    check("guardEnvelope enforce: DMARC p=reject + SPF fail → 550 5.7.26 (RFC 7372)", /^550 5\.7\.26/.test(rej));
    check("guardEnvelope enforce: refused message never reaches the agent", handoffs.length === 0);

    // Multi-From spoofing shape → refused.
    var multi = await _transact(sock, "s@external.com",
      "From: s@external.com\r\nFrom: ceo@spoof.example\r\nSubject: x\r\n\r\nbody\r\n");
    check("guardEnvelope enforce: duplicated From → 550 5.7.1 (RFC 9989 §5.3.1)",
      /^550 5\.7\.1/.test(multi) && handoffs.length === 0);

    // Aligned pass: delivered with verdict + A-R header. The message
    // arrives with a FORGED Authentication-Results header claiming
    // this receiver's authserv-id — RFC 8601 §5 requires it stripped
    // before the computed one is prepended.
    var ok = await _transact(sock, "s@external.com",
      "Authentication-Results: example.com;\r\n  dkim=pass header.d=forged.example\r\n" +
      "From: s@external.com\r\nSubject: hi\r\n\r\nhello\r\n");
    check("guardEnvelope enforce: aligned SPF pass → 250 accepted", /^250 /.test(ok));
    check("guardEnvelope: handoff carries the auth verdict",
      handoffs.length === 1 && handoffs[0].auth &&
      handoffs[0].auth.action === "accept" &&
      handoffs[0].auth.spf.result === "pass" &&
      handoffs[0].auth.dmarc.result === "pass" &&
      handoffs[0].auth.quarantine === false);
    // The ARC chain was evaluated, written into the Authentication-Results
    // header and into the audit event, and then dropped before the handoff.
    // A consumer wanting to act on it had to re-parse a header the pipeline
    // had just produced — and the header cannot carry what the structured
    // verdict does: `Authentication-Results` flattens every failure to
    // `arc=fail`, losing the distinction between a chain that is
    // structurally incomplete and one whose seal did not verify.
    check("guardEnvelope: handoff carries the ARC verdict beside the other three",
      handoffs.length === 1 && handoffs[0].auth &&
      handoffs[0].auth.arc && typeof handoffs[0].auth.arc.chainStatus === "string",
      handoffs.length === 1 ? JSON.stringify(handoffs[0].auth.arc) : "no handoff");
    check("guardEnvelope: an unsealed message reports chainStatus none",
      handoffs.length === 1 && handoffs[0].auth &&
      handoffs[0].auth.arc && handoffs[0].auth.arc.chainStatus === "none",
      handoffs.length === 1 ? JSON.stringify(handoffs[0].auth.arc) : "no handoff");
    var delivered = handoffs.length === 1 ? handoffs[0].body.toString("utf8") : "";
    check("guardEnvelope: A-R header prepended with the localDomains authserv-id",
      delivered.indexOf("Authentication-Results: example.com") === 0 &&
      /spf=pass/.test(delivered) && /dmarc=pass/.test(delivered));
    check("guardEnvelope: forged same-authserv-id A-R header stripped (RFC 8601 §5)",
      delivered.indexOf("forged.example") === -1 &&
      delivered.split("Authentication-Results: example.com").length === 2);
    check("guardEnvelope: original message preserved after the A-R header",
      delivered.indexOf("Subject: hi") !== -1 && delivered.indexOf("hello") !== -1);

    // Quarantine policy: delivered, annotated for the downstream agent.
    var q = await _transact(sock, "news@spoofq.example",
      "From: news@spoofq.example\r\nSubject: promo\r\n\r\ndeal\r\n");
    check("guardEnvelope enforce: p=quarantine → 250 delivered annotated",
      /^250 /.test(q) && handoffs.length === 2 &&
      handoffs[1].auth.quarantine === true &&
      handoffs[1].auth.action === "quarantine");
    sock.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                  // allow:raw-time-literal — test-only short drain

  // ---- monitor mode: same spoof, never refused ----
  var monHandoffs = [];
  var monSrv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
    guardEnvelope: { mode: "monitor", dnsLookup: dnsLookup },
    agent: { handoff: async function (h) { monHandoffs.push(h); return {}; } },
  });
  var monInfo = await monSrv.listen({ port: 0, address: "127.0.0.1" });
  try {
    var monSock = nodeNet.connect(monInfo.port, "127.0.0.1");
    await new Promise(function (r) { monSock.once("connect", r); });
    await _readGreeting(monSock);
    await _sendCommand(monSock, "EHLO sender.example.com");
    var monRej = await _transact(monSock, "ceo@spoof.example",
      "From: ceo@spoof.example\r\nSubject: urgent\r\n\r\npay\r\n");
    check("guardEnvelope monitor: policy-reject message still delivered",
      /^250 /.test(monRej) && monHandoffs.length === 1 &&
      monHandoffs[0].auth.action === "reject" &&
      monHandoffs[0].auth.mode === "monitor");
    monSock.destroy();
  } finally { await monSrv.close({ timeoutMs: 1000 }); }                               // allow:raw-time-literal — test-only short drain

  // ---- DNS temperror: defer (default) vs accept ----
  var servfail = async function () { throw new Error("SERVFAIL"); };
  var deferSrv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
    guardEnvelope: { mode: "enforce", dnsLookup: servfail },
  });
  var deferInfo = await deferSrv.listen({ port: 0, address: "127.0.0.1" });
  try {
    var dSock = nodeNet.connect(deferInfo.port, "127.0.0.1");
    await new Promise(function (r) { dSock.once("connect", r); });
    await _readGreeting(dSock);
    await _sendCommand(dSock, "EHLO sender.example.com");
    var deferred = await _transact(dSock, "s@external.com",
      "From: s@external.com\r\nSubject: hi\r\n\r\nhello\r\n");
    check("guardEnvelope: DNS temperror defers with 451 4.7.0 (sender retries)",
      /^451 4\.7\.0/.test(deferred));
    dSock.destroy();
  } finally { await deferSrv.close({ timeoutMs: 1000 }); }                             // allow:raw-time-literal — test-only short drain

  // ---- pipeline wall-clock timeout: a hanging resolver cannot pin
  // the connection slot — the race defers on the temperror path ----
  var hangForever = function () { return new Promise(function () {}); };
  var timeoutSrv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
    guardEnvelope: { mode: "enforce", dnsLookup: hangForever, timeoutMs: 250 },        // allow:raw-time-literal — test-only short budget
  });
  var timeoutInfo = await timeoutSrv.listen({ port: 0, address: "127.0.0.1" });
  try {
    var tSock = nodeNet.connect(timeoutInfo.port, "127.0.0.1");
    await new Promise(function (r) { tSock.once("connect", r); });
    await _readGreeting(tSock);
    await _sendCommand(tSock, "EHLO sender.example.com");
    var timedOut = await _transact(tSock, "s@external.com",
      "From: s@external.com\r\nSubject: hi\r\n\r\nhello\r\n");
    check("guardEnvelope: hanging resolver hits timeoutMs → 451 4.7.0",
      /^451 4\.7\.0/.test(timedOut));
    tSock.destroy();
  } finally { await timeoutSrv.close({ timeoutMs: 1000 }); }                           // allow:raw-time-literal — test-only short drain

  var acceptSrv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
    guardEnvelope: { mode: "enforce", onTemperror: "accept", dnsLookup: servfail },
  });
  var acceptInfo = await acceptSrv.listen({ port: 0, address: "127.0.0.1" });
  try {
    var aSock = nodeNet.connect(acceptInfo.port, "127.0.0.1");
    await new Promise(function (r) { aSock.once("connect", r); });
    await _readGreeting(aSock);
    await _sendCommand(aSock, "EHLO sender.example.com");
    var accepted = await _transact(aSock, "s@external.com",
      "From: s@external.com\r\nSubject: hi\r\n\r\nhello\r\n");
    check("guardEnvelope: onTemperror accept admits when DNS is down",
      /^250 /.test(accepted));
    aSock.destroy();
  } finally { await acceptSrv.close({ timeoutMs: 1000 }); }                            // allow:raw-time-literal — test-only short drain
}

// ---- Boot-time validation of the guardEnvelope config object -----------
// The gate's tunables are validated at create() so an operator typo fails
// startup rather than turning every live DATA into an envelope_error.
function testGuardEnvelopeBootValidation() {
  function expectThrow(label, opts) {
    var threw = null;
    try { b.mail.server.mx.create(opts); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf("mail-server-mx/") === 0);
  }
  expectThrow("guardEnvelope.onTemperror invalid → throw",
    { tlsContext: {}, guardEnvelope: { onTemperror: "maybe" } });
  expectThrow("guardEnvelope.authservId non-string → throw",
    { tlsContext: {}, guardEnvelope: { authservId: 123 } });
  expectThrow("guardEnvelope.authservId empty string → throw",
    { tlsContext: {}, guardEnvelope: { authservId: "" } });
  expectThrow("guardEnvelope.dnsLookup non-function → throw",
    { tlsContext: {}, guardEnvelope: { dnsLookup: "not-a-fn" } });

  // A fully-specified gate config (explicit authservId + onTemperror
  // accept + dnsLookup fn) constructs cleanly — exercises the accept
  // branches the reject cases above skip.
  var okServer = null;
  try {
    okServer = b.mail.server.mx.create({
      tlsContext: {}, profile: "permissive",
      guardEnvelope: {
        mode:        "monitor",
        onTemperror: "accept",
        authservId:  "custom.mx.example",
        dnsLookup:   async function () { return []; },
      },
    });
  } catch (_e) { okServer = null; }
  check("guardEnvelope full valid config constructs", okServer !== null &&
    typeof okServer.listen === "function");

  // `guardEnvelope: true` shorthand — mode defaults to the profile-derived
  // posture (permissive → monitor, otherwise enforce).
  var trueMonitor = null, trueEnforce = null;
  try {
    trueMonitor = b.mail.server.mx.create({
      tlsContext: {}, profile: "permissive", guardEnvelope: true });
  } catch (_e) { trueMonitor = null; }
  try {
    trueEnforce = b.mail.server.mx.create({ tlsContext: {}, guardEnvelope: true });
  } catch (_e) { trueEnforce = null; }
  check("guardEnvelope:true under permissive constructs (monitor default)",
    trueMonitor !== null);
  check("guardEnvelope:true under default profile constructs (enforce default)",
    trueEnforce !== null);
}

// ---- guardDomain opt: false (disable) and object (profile override) ----
function testGuardDomainBootOptions() {
  var offServer = null;
  try {
    offServer = b.mail.server.mx.create({ tlsContext: {}, guardDomain: false });
  } catch (_e) { offServer = null; }
  check("guardDomain:false constructs (hardening disabled)", offServer !== null);

  var objServer = null;
  try {
    objServer = b.mail.server.mx.create({
      tlsContext: {}, guardDomain: { profile: "balanced" },
    });
  } catch (_e) { objServer = null; }
  check("guardDomain object with profile override constructs", objServer !== null);

  // guardDomain object WITHOUT its own profile falls back to the server
  // profile.
  var objDefault = null;
  try {
    objDefault = b.mail.server.mx.create({ tlsContext: {}, guardDomain: {} });
  } catch (_e) { objDefault = null; }
  check("guardDomain object without profile falls back to server profile",
    objDefault !== null);

  // An operator localDomains entry that guardDomain itself rejects (a
  // special-use domain) must fail startup, not silently weaken the gate.
  var badLocal = null;
  try {
    b.mail.server.mx.create({ tlsContext: {}, localDomains: ["foo.local"] });
  } catch (e) { badLocal = e; }
  check("localDomains rejected by guardDomain → bad-local-domain at boot",
    badLocal !== null && /bad-local-domain/.test(badLocal.code || ""));
}

// ---- Command dispatch: NOOP / RSET / VRFY / EXPN / unknown / HELO / EHLO-no-arg
async function testCommandDispatch() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("command dispatch (skipped — cert fixture unavailable)", true); return; }
  var srv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var sock;
  try {
    sock = await _connectTo(info);
    check("NOOP → 250", /^250 /.test(await _sendCommand(sock, "NOOP")));
    check("RSET → 250", /^250 /.test(await _sendCommand(sock, "RSET")));
    check("VRFY → 502 not implemented",
      /^502 5\.5\.1/.test(await _sendCommand(sock, "VRFY alice")));
    check("EXPN → 502 not implemented",
      /^502 5\.5\.1/.test(await _sendCommand(sock, "EXPN staff")));
    check("unknown verb → 500",
      /^500 5\.5\.2/.test(await _sendCommand(sock, "HELP")));
    check("HELO (not EHLO) → single-line 250",
      /^250 /.test(await _sendCommand(sock, "HELO relay.example.com")));
    sock.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                 // allow:raw-time-literal — test-only short drain
}

// ---- Sequence + syntax errors: out-of-order commands and malformed args -
async function testSequenceAndSyntaxErrors() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("sequence/syntax errors (skipped)", true); return; }
  var srv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var s1, s2;
  try {
    // MAIL FROM before any EHLO → 503 bad sequence.
    s1 = await _connectTo(info);
    check("MAIL FROM before EHLO → 503",
      /^503 5\.5\.1/.test(await _sendCommand(s1, "MAIL FROM:<a@external.com>")));
    s1.destroy();

    // Fresh connection: EHLO, then RCPT before MAIL, DATA before RCPT,
    // and malformed MAIL / RCPT the shape-guard passes but the listener's
    // stricter address regex rejects (501).
    s2 = await _connectTo(info);
    await _sendCommand(s2, "EHLO sender.example.com");
    check("RCPT before MAIL → 503",
      /^503 5\.5\.1/.test(await _sendCommand(s2, "RCPT TO:<a@example.com>")));
    check("DATA before RCPT → 503",
      /^503 5\.5\.1/.test(await _sendCommand(s2, "DATA")));
    check("malformed MAIL FROM (trailing junk) → 501",
      /^501 5\.5\.4/.test(await _sendCommand(s2, "MAIL FROM:<a@external.com>extra")));
    // Land a good MAIL so the next RCPT reaches the address parse.
    await _sendCommand(s2, "MAIL FROM:<a@external.com>");
    check("malformed RCPT TO (trailing junk) → 501",
      /^501 5\.5\.4/.test(await _sendCommand(s2, "RCPT TO:<a@example.com>extra")));
    s2.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                 // allow:raw-time-literal — test-only short drain
}

// ---- Domain hardening refuses HELO / MAIL FROM / RCPT TO bad domains ----
// bare-IPv4-as-domain (CVE-2021-22931 class) + special-use domain (RFC 6761).
async function testDomainRefusals() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("domain refusals (skipped)", true); return; }
  var srv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var s1, s2;
  try {
    // HELO with a bare IPv4 (not an address literal) → guardDomain refuses.
    s1 = await _connectTo(info);
    check("HELO bare-IPv4 domain → 501",
      /^501 5\.5\.4/.test(await _sendCommand(s1, "HELO 1.2.3.4")));
    s1.destroy();

    s2 = await _connectTo(info);
    await _sendCommand(s2, "EHLO sender.example.com");
    check("MAIL FROM bare-IPv4 domain → 501",
      /^501 5\.5\.4/.test(await _sendCommand(s2, "MAIL FROM:<x@1.2.3.4>")));
    await _sendCommand(s2, "MAIL FROM:<s@external.com>");
    check("RCPT TO special-use domain → 501",
      /^501 5\.5\.4/.test(await _sendCommand(s2, "RCPT TO:<x@foo.local>")));
    s2.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                 // allow:raw-time-literal — test-only short drain
}

// ---- Resource caps: SIZE=, per-message size, recipient count, line length
async function testResourceLimits() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("resource limits (skipped)", true); return; }

  // Small per-message cap: declared SIZE= over the cap refused at MAIL
  // FROM (552), and a DATA body over the cap refused mid-stream (552).
  var capSrv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
    maxMessageBytes: 64,
  });
  var capInfo = await capSrv.listen({ port: 0, address: "127.0.0.1" });
  var capSock;
  try {
    capSock = await _connectTo(capInfo);
    await _sendCommand(capSock, "EHLO sender.example.com");
    check("MAIL FROM SIZE= over maxMessageBytes → 552",
      /^552 5\.3\.4/.test(await _sendCommand(capSock, "MAIL FROM:<s@external.com> SIZE=100000")));
    await _sendCommand(capSock, "MAIL FROM:<s@external.com>");
    await _sendCommand(capSock, "RCPT TO:<alice@example.com>");
    await _sendCommand(capSock, "DATA");
    var big = "";
    for (var i = 0; i < 200; i += 1) big += "A";
    check("DATA body over maxMessageBytes → 552 mid-stream",
      /^552 5\.3\.4/.test(await _sendCommand(capSock, big)));
    capSock.destroy();
  } finally { await capSrv.close({ timeoutMs: 1000 }); }                              // allow:raw-time-literal — test-only short drain

  // Per-message recipient cap (default maxMessageBytes so SIZE overrun
  // has room). maxRcptsPerMessage:1 → the second RCPT is refused 452.
  var rcptSrv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
    maxRcptsPerMessage: 1,
  });
  var rcptInfo = await rcptSrv.listen({ port: 0, address: "127.0.0.1" });
  var rcptSock;
  try {
    rcptSock = await _connectTo(rcptInfo);
    await _sendCommand(rcptSock, "EHLO sender.example.com");
    await _sendCommand(rcptSock, "MAIL FROM:<s@external.com>");
    await _sendCommand(rcptSock, "RCPT TO:<alice@example.com>");
    check("second RCPT past maxRcptsPerMessage → 452",
      /^452 4\.5\.3/.test(await _sendCommand(rcptSock, "RCPT TO:<bob@example.com>")));
    rcptSock.destroy();
  } finally { await rcptSrv.close({ timeoutMs: 1000 }); }                             // allow:raw-time-literal — test-only short drain

  // Declared SIZE= reconciled against the actual DATA byte count (RFC 1870
  // §6.3): a body larger than the declared SIZE is refused after DATA.
  var overrunSrv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
  });
  var overrunInfo = await overrunSrv.listen({ port: 0, address: "127.0.0.1" });
  var overrunSock;
  try {
    overrunSock = await _connectTo(overrunInfo);
    await _sendCommand(overrunSock, "EHLO sender.example.com");
    await _sendCommand(overrunSock, "MAIL FROM:<s@external.com> SIZE=10");
    await _sendCommand(overrunSock, "RCPT TO:<alice@example.com>");
    await _sendCommand(overrunSock, "DATA");
    check("DATA body over declared SIZE= → 552 (RFC 1870 §6.3)",
      /^552 5\.3\.4/.test(await _sendCommand(overrunSock,
        "From: s@external.com\r\nSubject: overrun\r\n\r\nthis body is far larger than ten bytes\r\n.")));
    overrunSock.destroy();
  } finally { await overrunSrv.close({ timeoutMs: 1000 }); }                          // allow:raw-time-literal — test-only short drain

  // Per-command line cap: a command line past the hard byte ceiling is
  // refused 500 and the connection is dropped.
  var lineSrv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
    maxLineBytes: 64,
  });
  var lineInfo = await lineSrv.listen({ port: 0, address: "127.0.0.1" });
  var lineSock;
  try {
    lineSock = await _connectTo(lineInfo);
    var overlong = "";
    for (var j = 0; j < 400; j += 1) overlong += "A";
    check("over-long command line → 500 5.5.6 + close",
      /^500 5\.5\.6/.test(await _sendCommand(lineSock, overlong)));
    lineSock.destroy();
  } finally { await lineSrv.close({ timeoutMs: 1000 }); }                             // allow:raw-time-literal — test-only short drain
}

// ---- Per-IP RCPT-failure cap: repeated failed recipients trip a 421 + close
// (the mailbox-enumeration backstop — RFC 5321 §3.5). A low cap makes the
// backoff deterministic.
async function testRcptFailureRateLimit() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("RCPT-failure rate limit (skipped)", true); return; }
  var srv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
    rateLimit: { rcptFailuresPerIpPerMinute: 2 },
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var sock;
  try {
    sock = await _connectTo(info);
    await _sendCommand(sock, "EHLO sender.example.com");
    await _sendCommand(sock, "MAIL FROM:<s@external.com>");
    // Two relay-denied recipients spend the failure budget.
    check("first relay-denied RCPT → 550",
      /^550 5\.7\.1/.test(await _sendCommand(sock, "RCPT TO:<a@notlocal.example>")));
    check("second relay-denied RCPT → 550",
      /^550 5\.7\.1/.test(await _sendCommand(sock, "RCPT TO:<b@notlocal.example>")));
    // The next RCPT trips the per-IP failure cap → 421 + connection close.
    check("RCPT past the per-IP failure cap → 421 + close",
      /^421 4\.7\.0/.test(await _sendCommand(sock, "RCPT TO:<c@notlocal.example>")));
    sock.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                 // allow:raw-time-literal — test-only short drain
}

// ---- SMTP-smuggling wire paths: bare-LF / bare-CR / NUL command lines and
// a bare-LF dot-terminator in the DATA body. Captures the smtp_smuggling
// _detected audit to prove the NUL-injection path is audited (regression:
// the code guard emits is `guard-smtp-command/nul`, not `nul-byte`).
async function testWireSmuggling() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("wire smuggling (skipped)", true); return; }

  // strict profile refuses bare LF (permissive tolerates it), so the
  // smuggling-detected audit fires for bare LF / bare CR / NUL here.
  var strictSrv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "strict", localDomains: ["example.com"],
  });
  var strictInfo = await strictSrv.listen({ port: 0, address: "127.0.0.1" });
  var cmdSock;
  await _withAuditCapture(async function (events) {
    try {
      cmdSock = await _connectTo(strictInfo);
      check("bare-LF in command line → 500",
        /^500 5\.5\.2/.test(await _sendCommand(cmdSock, "EHLO x\ny")));
      check("bare-CR in command line → 500",
        /^500 5\.5\.2/.test(await _sendCommand(cmdSock, "EHLO x\rY")));
      check("NUL byte in command line → 500",
        /^500 5\.5\.2/.test(await _sendCommand(cmdSock, ("EHL" + String.fromCharCode(0) + "O example.com"))));
      cmdSock.destroy();
    } finally { if (cmdSock) cmdSock.destroy(); }

    function smug(code) {
      return events.filter(function (e) {
        return e && e.action === "mail.server.mx.smtp_smuggling_detected" &&
          e.metadata && e.metadata.code === code;
      }).length;
    }
    check("bare-LF command emits smtp_smuggling_detected audit",
      smug("guard-smtp-command/bare-lf") >= 1);
    check("bare-CR command emits smtp_smuggling_detected audit",
      smug("guard-smtp-command/bare-cr") >= 1);
    check("NUL-byte command emits smtp_smuggling_detected audit (code /nul)",
      smug("guard-smtp-command/nul") >= 1);
  });
  await strictSrv.close({ timeoutMs: 1000 });                                          // allow:raw-time-literal — test-only short drain

  // DATA-body bare-LF dot terminator (the CVE-2023-51764 smuggling shape)
  // is refused 554 mid-body under any profile.
  var bodySrv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
  });
  var bodyInfo = await bodySrv.listen({ port: 0, address: "127.0.0.1" });
  var bodySock;
  try {
    bodySock = await _connectTo(bodyInfo);
    await _sendCommand(bodySock, "EHLO sender.example.com");
    await _sendCommand(bodySock, "MAIL FROM:<s@external.com>");
    await _sendCommand(bodySock, "RCPT TO:<alice@example.com>");
    await _sendCommand(bodySock, "DATA");
    check("bare-LF dot-terminator in DATA body → 554 (SMTP smuggling)",
      /^554 5\.7\.0/.test(await _sendCommand(bodySock, "smuggled\n.\n")));
    bodySock.destroy();
  } finally { await bodySrv.close({ timeoutMs: 1000 }); }                             // allow:raw-time-literal — test-only short drain
}

// ---- Operator-explicit relay allowlist admits non-local recipients ------
async function testRelayAllowed() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("relay allowlist (skipped)", true); return; }
  var srv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
    relayAllowedFor: [{ cidr: "0.0.0.0/0", scope: "all" }],
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var sock;
  try {
    sock = await _connectTo(info);
    await _sendCommand(sock, "EHLO sender.example.com");
    await _sendCommand(sock, "MAIL FROM:<s@external.com>");
    check("non-local RCPT admitted when relayAllowedFor is set → 250",
      /^250 /.test(await _sendCommand(sock, "RCPT TO:<bob@notlocal.example>")));
    sock.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                 // allow:raw-time-literal — test-only short drain
}

// ---- relayAllowedFor enforces the entry CIDR against the peer address ---
// A peer OUTSIDE every allowlisted range must be relay-refused; only a peer
// INSIDE a range is admitted. Regression guard for the open-relay class where
// a non-empty relayAllowedFor admitted every peer regardless of source
// address (the entry `cidr` was ignored).
async function testRelayCidrEnforced() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("relay CIDR enforcement (skipped)", true); return; }

  // (a) Peer 127.0.0.1 is OUTSIDE 10.0.0.0/8 → relay refused with 550.
  var denySrv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
    relayAllowedFor: [{ cidr: "10.0.0.0/8", scope: "internal" }],
  });
  var denyInfo = await denySrv.listen({ port: 0, address: "127.0.0.1" });
  var denySock;
  try {
    denySock = await _connectTo(denyInfo);
    await _sendCommand(denySock, "EHLO sender.example.com");
    await _sendCommand(denySock, "MAIL FROM:<attacker@evil.com>");
    check("out-of-CIDR peer relay-refused → 550 (no open relay)",
      /^550 5\.7\.1/.test(await _sendCommand(denySock, "RCPT TO:<victim@notlocal.example>")));
    denySock.destroy();
  } finally { await denySrv.close({ timeoutMs: 1000 }); }                              // allow:raw-time-literal — test-only short drain

  // (b) Peer 127.0.0.1 is INSIDE 127.0.0.0/8 → relay admitted with 250.
  var allowSrv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
    relayAllowedFor: [{ cidr: "127.0.0.0/8", scope: "loopback" }],
  });
  var allowInfo = await allowSrv.listen({ port: 0, address: "127.0.0.1" });
  var allowSock;
  try {
    allowSock = await _connectTo(allowInfo);
    await _sendCommand(allowSock, "EHLO sender.example.com");
    await _sendCommand(allowSock, "MAIL FROM:<s@external.com>");
    check("in-CIDR peer relay admitted → 250",
      /^250 /.test(await _sendCommand(allowSock, "RCPT TO:<bob@notlocal.example>")));
    allowSock.destroy();
  } finally { await allowSrv.close({ timeoutMs: 1000 }); }                             // allow:raw-time-literal — test-only short drain

  // (b2) IPv4-mapped fold the relay gate relies on. An IPv4 client on the
  // common dual-stack `::` listener is reported by Node as ::ffff:a.b.c.d;
  // cidrContains refuses a cross-family compare, so the gate folds the mapped
  // peer via ssrfGuard.canonicalizeHost before matching (otherwise every IPv4
  // client on a `::` listener would be denied against a documented IPv4 CIDR).
  // Asserted at the composed-primitive level — deterministic and hang-free,
  // where an end-to-end `::` bind + IPv4 dialog is runtime/dual-stack dependent.
  check("relay fold: a mapped peer canonicalizes to its IPv4 dotted form",
    b.ssrfGuard.canonicalizeHost("::ffff:127.0.0.1") === "127.0.0.1");
  check("relay fold: the raw mixed-family compare does NOT match (fold is required)",
    b.ssrfGuard.cidrContains("127.0.0.0/8", "::ffff:127.0.0.1") === false);
  check("relay fold: the folded IPv4 peer matches the IPv4 relay CIDR",
    b.ssrfGuard.cidrContains("127.0.0.0/8", b.ssrfGuard.canonicalizeHost("::ffff:127.0.0.1")) === true);
  check("relay fold: an out-of-CIDR mapped peer stays refused after folding (no fail-open)",
    b.ssrfGuard.cidrContains("127.0.0.0/8", b.ssrfGuard.canonicalizeHost("::ffff:10.9.9.9")) === false);

  // (c) Config-time: a malformed / mask-less relay CIDR is refused at boot.
  function bootRejects(label, entry) {
    var threw = null;
    try {
      b.mail.server.mx.create({
        tlsContext: {}, relayAllowedFor: [entry],
      });
    } catch (e) { threw = e; }
    check(label, threw && threw.code === "mail-server-mx/bad-relay-cidr");
  }
  bootRejects("malformed relay CIDR refused at boot", { cidr: "not-a-cidr", scope: "x" });
  bootRejects("mask-less relay CIDR refused at boot", { cidr: "203.0.113.5", scope: "x" });
  bootRejects("out-of-range prefix refused at boot", { cidr: "10.0.0.0/40", scope: "x" });
  bootRejects("non-object relay entry refused at boot", "10.0.0.0/8");

  // (c2) A dotted IPv4-mapped IPv6 relay CIDR (::ffff:10.0.0.0/104) is a valid
  // spelling that cidrContains accepts; the config validation folds it to the
  // plain IPv4 CIDR (10.0.0.0/8) so it is accepted at boot (rather than refused
  // as bad-relay-cidr) and then matches BOTH a genuine IPv4 peer and a mapped
  // peer via the gate's peer fold — not just the mapped form.
  function bootAccepts(label, entry) {
    var ok = true;
    try { b.mail.server.mx.create({ tlsContext: {}, relayAllowedFor: [entry] }); }
    catch (_e) { ok = false; }
    check(label, ok);
  }
  bootAccepts("dotted IPv4-mapped relay CIDR accepted at boot (folded to IPv4)",
    { cidr: "::ffff:10.0.0.0/104", scope: "internal" });
  bootAccepts("hex-group IPv4-mapped relay CIDR accepted at boot",
    { cidr: "::ffff:0a00:0/104", scope: "internal" });
  check("the ::ffff:10.0.0.0/104 fold (10.0.0.0/8) matches a genuine IPv4 peer",
    b.ssrfGuard.cidrContains("10.0.0.0/8", "10.2.3.4") === true);
  check("the ::ffff:10.0.0.0/104 fold (10.0.0.0/8) matches an IPv4-mapped peer",
    b.ssrfGuard.cidrContains("10.0.0.0/8", b.ssrfGuard.canonicalizeHost("::ffff:10.2.3.4")) === true);
}

// ---- Agent handoff failure surfaces a 451 transient error ---------------
async function testAgentHandoffFailure() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("agent handoff failure (skipped)", true); return; }
  var srv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
    agent: { handoff: async function () { throw new Error("mail store unavailable"); } },
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var sock;
  try {
    sock = await _connectTo(info);
    await _sendCommand(sock, "EHLO sender.example.com");
    await _sendCommand(sock, "MAIL FROM:<s@external.com>");
    await _sendCommand(sock, "RCPT TO:<alice@example.com>");
    await _sendCommand(sock, "DATA");
    check("agent handoff rejection → 451 local delivery error",
      /^451 4\.3\.0/.test(await _sendCommand(sock,
        "From: s@external.com\r\nSubject: hi\r\n\r\nhello\r\n.")));
    sock.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                 // allow:raw-time-literal — test-only short drain

  await testAgentRefusalChoosesItsReply(ctx);
}

// The receiving side has the same problem as submission: a refusal the agent
// made on policy grounds is permanent, and answering 451 tells a conforming
// sender to retry it until its queue lifetime expires.
async function testAgentRefusalChoosesItsReply(ctx) {
  async function _replyFor(fields) {
    var srv = b.mail.server.mx.create({
      tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
      agent: { handoff: async function () {
        var e = new Error("refused by policy");
        Object.keys(fields).forEach(function (k) { e[k] = fields[k]; });
        throw e;
      } },
    });
    var info = await srv.listen({ port: 0, address: "127.0.0.1" });
    var sock;
    try {
      sock = await _connectTo(info);
      await _sendCommand(sock, "EHLO sender.example.com");
      await _sendCommand(sock, "MAIL FROM:<s@external.com>");
      await _sendCommand(sock, "RCPT TO:<alice@example.com>");
      await _sendCommand(sock, "DATA");
      var reply = await _sendCommand(sock,
        "From: s@external.com\r\nSubject: hi\r\n\r\nhello\r\n.");
      sock.destroy();
      return reply;
    } finally { await srv.close({ timeoutMs: 1000 }); }                               // allow:raw-time-literal — test-only short drain
  }

  var permanent = await _replyFor({
    smtpCode: "550", enhancedStatus: "5.7.1", replyText: "message refused by policy",
  });
  check("mx agent refusal: a permanent verdict answers 5yz",
    /^550 5\.7\.1 message refused by policy/.test(permanent), permanent);

  var bogus = await _replyFor({ smtpCode: "250" });
  check("mx agent refusal: a non-failure code falls back to 451 4.3.0",
    /^451 4\.3\.0 /.test(bogus), bogus);

  var injected = await _replyFor({ smtpCode: "550", replyText: "no\r\n250 accepted" });
  check("mx agent refusal: injected line terminators do not reach the wire",
    /^550 5\.0\.0 /.test(injected) && injected.indexOf("250 accepted") === -1, injected);
}

// ---- A gate that throws is caught by the pump → 421 + connection close --
async function testGateThrows() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("gate throws (skipped)", true); return; }
  var srv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
    helo: { evaluate: async function () { throw new Error("gate backend down"); } },
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var sock;
  try {
    sock = await _connectTo(info);
    check("throwing helo gate → 421 server error",
      /^421 4\.3\.0/.test(await _sendCommand(sock, "EHLO sender.example.com")));
    sock.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                 // allow:raw-time-literal — test-only short drain
}

// ---- Idle-timeout fires a 421 and closes the plaintext connection -------
async function testIdleTimeout() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("idle timeout (skipped)", true); return; }
  var srv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
    idleTimeoutMs: 300,                                                                // allow:raw-time-literal — test-only short idle window
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var sock;
  try {
    sock = await _connectTo(info);
    var col = _collect(sock);
    // Send nothing — the idle timer fires the transient 421.
    await helpers.waitUntil(function () { return /^421 4\.4\.2/m.test(col.text()); },
      { timeoutMs: 5000, label: "mx idle timeout: 421 4.4.2 delivered" });
    check("idle connection → 421 4.4.2 + close", /^421 4\.4\.2/m.test(col.text()));
    sock.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                 // allow:raw-time-literal — test-only short drain
}

// A chunk that arrives while an earlier one is still in a gate is chained
// behind it, and the flag that stops the queue was written from the socket's
// own `close` event. That event is a macrotask; the chained chunk resumes on a
// microtask, so between a handler deciding to tear the connection down and the
// event firing there is a turn in which the peer's queued commands still run.
// The flag has to be set where the teardown is decided.
async function testAQueuedChunkDoesNotRunAfterTheGateTearsDown() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("mx queued chunk after teardown (skipped)", true); return; }
  var rejectQuery = null;
  var queries     = 0;
  var srv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
    // Awaited without a try/catch, so a rejection reaches the pump's own
    // handler-fault arm — which answers 421 and tears the connection down.
    rbl: { query: function () {
      queries += 1;
      return new Promise(function (_r, j) { rejectQuery = function () { j(new Error("rbl down")); }; });
    } },
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var sock;
  try {
    sock = await _connectTo(info);                       // greeting already read
    _collect(sock);
    sock.write("EHLO peer.example.net\r\nMAIL FROM:<a@example.net>\r\nRCPT TO:<x@example.com>\r\n");
    await helpers.waitUntil(function () { return rejectQuery !== null; },
      { timeoutMs: 5000, label: "mx queued chunk: first RCPT is in the gate" });

    // A separate segment, chained behind the chunk still in the gate.
    sock.write("RCPT TO:<y@example.com>\r\n");
    await helpers.passiveObserve(120, "mx queued chunk: second segment is queued");

    rejectQuery();
    await helpers.passiveObserve(400, "mx queued chunk: nothing resumes");
    check("a chunk queued behind a torn-down gate is not processed",
          queries === 1, String(queries));
    sock.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                 // allow:raw-time-literal — test-only short drain
}

// A second MAIL inside an open transaction is RFC 5321 section 4.1.4's "sender
// already specified". It was answered with "EHLO/HELO first", which the client
// already did successfully, so a reader who trusts the reply goes looking for a
// session that lost its EHLO.
async function testASecondMailNamesTheRightFault() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("mx second MAIL reply (skipped)", true); return; }
  var srv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var sock;
  try {
    sock = await _connectTo(info);
    await _sendCommand(sock, "EHLO peer.example.net");
    await _sendCommand(sock, "MAIL FROM:<a@example.net>");

    var second = await _sendCommand(sock, "MAIL FROM:<a@example.net>");
    check("mx: a second MAIL is refused", /^503 /m.test(second), JSON.stringify(second));
    check("mx: and it says the sender is already specified, not to issue EHLO",
          /Sender already specified/.test(second) && !/EHLO\/HELO first/.test(second),
          JSON.stringify(second));

    await _sendCommand(sock, "RSET");
    var third = await _sendCommand(sock, "MAIL FROM:<a@example.net>");
    check("mx: and after RSET a MAIL is accepted again",
          /^250 /m.test(third), JSON.stringify(third));

    // The null reverse path — RFC 5321 section 4.5.5, the bounce sender — is
    // the case an MX sees most, and it stores as the EMPTY STRING. A
    // truthiness test for an open transaction misses exactly this one.
    await _sendCommand(sock, "RSET");
    var bounce = await _sendCommand(sock, "MAIL FROM:<>");
    check("mx: the null reverse path is accepted", /^250 /m.test(bounce), JSON.stringify(bounce));
    var afterBounce = await _sendCommand(sock, "MAIL FROM:<a@example.net>");
    check("mx: and a second MAIL after it is refused as sender-already-specified",
          /Sender already specified/.test(afterBounce) && !/EHLO\/HELO first/.test(afterBounce),
          JSON.stringify(afterBounce));
    sock.destroy();

    // The other half still answers its own fault.
    var s2 = await _connectTo(info);
    var noHelo = await _sendCommand(s2, "MAIL FROM:<a@example.net>");
    check("mx: a MAIL before EHLO is still told to issue one",
          /EHLO\/HELO first/.test(noHelo), JSON.stringify(noHelo));
    s2.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                 // allow:raw-time-literal — test-only short drain
}

// A permanent refusal has to reach the peer. `end()` queues the FIN behind
// whatever is still in the write buffer, and a `destroy()` on the next line
// tore the socket down without waiting for it — so whether the reply arrived
// depended on how much the PEER had sent, not on anything the server decided.
//
// RFC 5321 section 4.2.1 makes that load-bearing: a peer that receives a 5xx
// stops and reports to its sender, and one that receives nothing has no verdict
// and falls back to its retry schedule for the whole of its queue lifetime.
async function testAPermanentRefusalSurvivesALargeOvershoot() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("refusal delivery (skipped)", true); return; }
  var srv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
    maxMessageBytes: 65536,                                                            // allow:raw-byte-literal — small ceiling so the overshoot is cheap to send
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var sock;
  try {
    sock = await _connectTo(info);
    var col = _collect(sock);
    await _sendCommand(sock, "EHLO peer.example.net");
    await _sendCommand(sock, "MAIL FROM:<a@example.net>");
    await _sendCommand(sock, "RCPT TO:<x@example.com>");
    await _sendCommand(sock, "DATA");

    // Far past the ceiling, in one push, so the refusal is written while the
    // peer still has a great deal in flight — the shape that used to reset the
    // connection with nothing delivered.
    sock.write("x".repeat(512 * 1024));                                                // allow:raw-byte-literal — overshoot well past the 64 KiB ceiling

    await helpers.waitUntil(function () { return /^55[0-9] /m.test(col.text()); },
      { timeoutMs: 8000, label: "refusal delivery: permanent reply reaches the peer" });
    check("a permanent refusal reaches a peer that overshot by a large margin",
          /^55[0-9] /m.test(col.text()), JSON.stringify(col.text().slice(-160)));
    sock.destroy();
  } finally { await srv.close({ timeoutMs: 2000 }); }                                 // allow:raw-time-literal — test-only short drain
}

// ---- close() drains, then force-destroys a lingering connection ---------
async function testCloseDestroysLingering() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("close-drain destroy (skipped)", true); return; }
  var srv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var sock = await _connectTo(info);
  _collect(sock);   // swallow the shutdown 421 + reset without rejecting
  await _sendCommand(sock, "EHLO sender.example.com");
  check("one live connection tracked before close", srv.connectionCount() === 1);
  // Hold the client socket open; close() writes the shutdown 421, waits
  // out the short drain, then force-destroys the lingering connection.
  await srv.close({ timeoutMs: 200 });                                                 // allow:raw-time-literal — test-only short drain window
  check("close() force-destroys lingering connection → count 0",
    srv.connectionCount() === 0);
  sock.destroy();
}

// ---- TLS error/lifecycle paths: STARTTLS-when-already-active (503),
// a non-TLS ClientHello after the STARTTLS 220 (handshake failure), and
// the post-STARTTLS idle timeout. Mints one CA and reuses it. ------------
async function testTlsErrorPaths() {
  var ca, leaf;
  try {
    ca = await b.mtlsEngine.generateCa({ name: "mx-tls-errpaths-ca" });
    leaf = await b.mtlsEngine.signClientCert({
      cn: "localhost", caCertPem: ca.caCertPem, caKeyPem: ca.caKeyPem,
      usage: "server", sans: ["DNS:localhost", "IP:127.0.0.1"], validityDays: 1,
    });
  } catch (_e) { check("TLS error paths (skipped — cert fixture unavailable)", true); return; }
  var ctx = nodeTls.createSecureContext({ key: leaf.key, cert: leaf.cert });

  // ---- STARTTLS issued a second time over the negotiated TLS → 503 ----
  var dupSrv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
  });
  var dupInfo = await dupSrv.listen({ port: 0, address: "127.0.0.1" });
  var dupPlain, dupTls;
  try {
    dupPlain = await _connectTo(dupInfo);
    await _sendCommand(dupPlain, "EHLO sender.example.com");
    check("STARTTLS → 220 ready", /^220 /.test(await _sendCommand(dupPlain, "STARTTLS")));
    dupTls = nodeTls.connect({ socket: dupPlain, ca: [ca.caCertPem], servername: "localhost" });
    await new Promise(function (r, j) { dupTls.once("secureConnect", r); dupTls.once("error", j); });
    await _sendCommand(dupTls, "EHLO sender.example.com");
    check("STARTTLS when TLS already active → 503",
      /^503 5\.5\.1/.test(await _sendCommand(dupTls, "STARTTLS")));
    dupTls.destroy();
  } finally { await dupSrv.close({ timeoutMs: 1000 }); }                               // allow:raw-time-literal — test-only short drain

  // ---- Non-TLS bytes after the STARTTLS 220 → handshake failure/close --
  var hsSrv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
  });
  var hsInfo = await hsSrv.listen({ port: 0, address: "127.0.0.1" });
  var hsSock;
  try {
    hsSock = await _connectTo(hsInfo);
    await _sendCommand(hsSock, "EHLO sender.example.com");
    await _sendCommand(hsSock, "STARTTLS");
    var closed = false;
    hsSock.on("close", function () { closed = true; });
    hsSock.on("error", function () { /* reset on failed handshake */ });
    // Garbage where the TLS ClientHello should be — the server's TLS
    // wrap errors and tears the connection down.
    hsSock.write("this is definitely not a tls client hello\r\n");
    await helpers.waitUntil(function () { return closed; },
      { timeoutMs: 5000, label: "mx STARTTLS: non-TLS bytes close the connection" });
    check("non-TLS bytes after STARTTLS 220 → connection closed", closed === true);
    hsSock.destroy();
  } finally { await hsSrv.close({ timeoutMs: 1000 }); }                                // allow:raw-time-literal — test-only short drain

  // ---- Post-STARTTLS idle timeout fires 421 over the TLS socket -------
  var idleSrv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
    idleTimeoutMs: 600,                                                                // allow:raw-time-literal — room for handshake, then idle
  });
  var idleInfo = await idleSrv.listen({ port: 0, address: "127.0.0.1" });
  var idlePlain, idleTls;
  try {
    idlePlain = await _connectTo(idleInfo);
    await _sendCommand(idlePlain, "EHLO sender.example.com");
    await _sendCommand(idlePlain, "STARTTLS");
    idleTls = nodeTls.connect({ socket: idlePlain, ca: [ca.caCertPem], servername: "localhost" });
    await new Promise(function (r, j) { idleTls.once("secureConnect", r); idleTls.once("error", j); });
    await _sendCommand(idleTls, "EHLO sender.example.com");
    var tlsCol = _collect(idleTls);
    await helpers.waitUntil(function () { return /^421 4\.4\.2/m.test(tlsCol.text()); },
      { timeoutMs: 5000, label: "mx TLS idle timeout: 421 4.4.2 over TLS" });
    check("post-STARTTLS idle → 421 4.4.2 over TLS", /^421 4\.4\.2/m.test(tlsCol.text()));
    idleTls.destroy();
  } finally { await idleSrv.close({ timeoutMs: 1000 }); }                              // allow:raw-time-literal — test-only short drain
}

// ---- Address-literal HELO / null reverse-path skip domain hardening -----
// RFC 5321 §4.1.3 address literals (`[1.2.3.4]`) and the §4.5.5 empty
// reverse path (`<>`) are legitimate non-domain forms; the guardDomain
// hardening is skipped for them rather than refusing.
async function testAddressLiteralAndNullSender() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("address-literal / null sender (skipped)", true); return; }
  var srv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var sock;
  try {
    sock = await _connectTo(info);
    check("EHLO address literal [127.0.0.1] accepted (hardening skipped)",
      /^250[ -]/.test(await _sendCommand(sock, "EHLO [127.0.0.1]")));
    check("MAIL FROM:<> null reverse path accepted (bounce path)",
      /^250 /.test(await _sendCommand(sock, "MAIL FROM:<>")));
    check("RCPT after null sender still accepted → 250",
      /^250 /.test(await _sendCommand(sock, "RCPT TO:<alice@example.com>")));
    // RCPT TO address literal skips domain hardening (RFC 5321 §4.1.3);
    // the non-local literal is then relay-refused.
    check("RCPT TO address literal skips hardening, then relay-refused → 550",
      /^550 5\.7\.1/.test(await _sendCommand(sock, "RCPT TO:<x@[127.0.0.1]>")));
    sock.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                 // allow:raw-time-literal — test-only short drain

  // guardDomain disabled → the HELO/EHLO hardening branch is skipped
  // entirely (operator closed-network opt-out).
  var offSrv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
    guardDomain: false,
  });
  var offInfo = await offSrv.listen({ port: 0, address: "127.0.0.1" });
  var offSock;
  try {
    offSock = await _connectTo(offInfo);
    check("EHLO with guardDomain disabled accepted (no hardening) → 250",
      /^250[ -]/.test(await _sendCommand(offSock, "EHLO sender.example.com")));
    offSock.destroy();
  } finally { await offSrv.close({ timeoutMs: 1000 }); }                               // allow:raw-time-literal — test-only short drain
}

// ---- Per-IP concurrent-connection cap refuses the excess connection ----
async function testConnectionRateLimit() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("connection rate limit (skipped)", true); return; }
  var srv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
    rateLimit: { maxConcurrentConnectionsPerIp: 1 },
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var first, second;
  try {
    first = await _connectTo(info);   // admitted; held open to occupy the single slot
    second = nodeNet.connect(info.port, "127.0.0.1");
    await new Promise(function (r) { second.once("connect", r); });
    var reply = await _readGreeting(second);   // first line is the refusal, not a 220
    check("excess concurrent connection refused with 421 4.7.0",
      /^421 4\.7\.0/.test(reply));
    first.destroy();
    second.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                 // allow:raw-time-literal — test-only short drain
}

// ---- close() is idempotent: no-arg close drains, second close is a no-op
async function testCloseIdempotent() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("close idempotency (skipped)", true); return; }
  var srv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
  });
  await srv.listen({ port: 0, address: "127.0.0.1" });
  var firstErr = null;
  try { await srv.close(); } catch (e) { firstErr = e; }   // no opts → default drain timeout
  check("close() with no options resolves", firstErr === null);
  var secondErr = null;
  try { await srv.close(); } catch (e) { secondErr = e; }  // already closed → early return
  check("second close() is a no-op", secondErr === null);
}

async function run() {
  testSurface();
  testCreateRequiresTlsContext();
  testCreateRejectsBadBounds();
  testGuardEnvelopeBootValidation();
  testGuardDomainBootOptions();
  testDetectSmugglingShape();
  testFindDotTerminator();
  testDotUnstuff();
  await testEhloFlow();
  await testEmptyLocalDomainsRefusesEveryRecipient();
  await testLocalDomainsCanBeAnsweredPerRecipient();
  await testRecipientPolicyRefusesUnknownMailbox();
  await testRecipientPolicyReasonCannotForgeAReplyLine();
  await testRecipientPolicyRefusalCostsTheScannerBudget();
  await testRecipientPolicyThrowIsTransient();
  await testBodyRateFloorIsAskedDuringData();
  await testRelayRefused();
  await testStrictProfileRequiresStartTls();
  await testConnectionGates();
  await testGateOverStartTls();
  await testGuardEnvelopeGate();
  await testCommandDispatch();
  await testSequenceAndSyntaxErrors();
  await testDomainRefusals();
  await testAddressLiteralAndNullSender();
  await testResourceLimits();
  await testRcptFailureRateLimit();
  await testConnectionRateLimit();
  await testWireSmuggling();
  await testRelayAllowed();
  await testRelayCidrEnforced();
  await testAgentHandoffFailure();
  await testGateThrows();
  await testIdleTimeout();
  await testAQueuedChunkDoesNotRunAfterTheGateTearsDown();
  await testASecondMailNamesTheRightFault();
  await testAPermanentRefusalSurvivesALargeOvershoot();
  await testCloseDestroysLingering();
  await testCloseIdempotent();
  await testTlsErrorPaths();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[mail-server-mx] OK"); },
    function (e) { console.error(e); process.exit(1); }
  );
}
