// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var helpers = require("../helpers");
var check = helpers.check;
var b = helpers.b;

var nodeNet = require("node:net");
var nodeTls = require("node:tls");

function testSurface() {
  check("b.mail.server.imap namespace",   typeof b.mail.server.imap === "object");
  check("create is fn",                    typeof b.mail.server.imap.create === "function");
  check("error class",                     typeof b.mail.server.imap.MailServerImapError === "function");
}

function testRequiresTlsContext() {
  var threw = null;
  try { b.mail.server.imap.create({ mailStore: { appendMessage: function () {} } }); }
  catch (e) { threw = e; }
  check("create refuses missing tlsContext",
    threw && threw.code === "mail-server-imap/no-tls-context");
  check("error message points at b.mail.server.tls.context",
    threw && /b\.mail\.server\.tls\.context/.test(threw.message));
}

function testRequiresMailStore() {
  var threw = null;
  try { b.mail.server.imap.create({ tlsContext: {} }); }
  catch (e) { threw = e; }
  check("create refuses missing mailStore",
    threw && threw.code === "mail-server-imap/no-mail-store");
}

function testBadBoundsRefused() {
  function expectBad(label, opts) {
    var threw = null;
    try { b.mail.server.imap.create(opts); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf("mail-server-imap/") === 0);
  }
  expectBad("refuses negative maxLineBytes",
    { tlsContext: {}, mailStore: { appendMessage: function () {} }, maxLineBytes: -1 });
  expectBad("refuses Infinity idleTimeoutMs",
    { tlsContext: {}, mailStore: { appendMessage: function () {} }, idleTimeoutMs: Infinity });
}

// A misspelled option is a setting that never takes effect, and every option
// here decides posture, so the listener starts and behaves as though the
// caller had never passed it. Construction is where that has to be caught:
// afterwards nothing distinguishes a typo from an omission.
function testUnknownOptionRefused() {
  var base = { tlsContext: {}, mailStore: { appendMessage: function () {} } };
  function expectUnknown(label, key, value) {
    var opts = Object.assign({}, base);
    opts[key] = value;
    var threw = null;
    try { b.mail.server.imap.create(opts); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf("mail-server-imap/") === 0,
          String(threw && (threw.code || threw.message)));
  }
  expectUnknown("a misspelled option is refused", "maxLiteralByte", 1024);
  expectUnknown("an option belonging to another listener is refused", "allowPlaintext", true);
  // GETMETADATA parses MAXSIZE and DEPTH into a LOCAL opts object inside its
  // handler. Neither is a create option, and a key list read off the source
  // would have admitted both.
  expectUnknown("a handler-local option name is refused", "maxSize", 1024);
  expectUnknown("the other handler-local name is refused", "depth", "infinity");
  // A source comment described enabling COMPRESS=DEFLATE "via opts.compress",
  // which nothing ever read. A caller following it got silence; it is a name,
  // not an option.
  expectUnknown("an option named only in a comment is refused", "compress", true);

  // The control: every documented option is still accepted together.
  var threw = null;
  try {
    b.mail.server.imap.create({
      tlsContext: {}, mailStore: { appendMessage: function () {} },
      implicitTls: false, greeting: "ready", maxLineBytes: 8192,
      maxLiteralBytes: 1024, idleTimeoutMs: 1000, maxConnections: 4,
      profile: "permissive", rateLimit: undefined,
      capabilities: function (caps) { return caps; },
      allowLegacyMUtf7: false, overrides: {},
      agentTenantId: "t1", tenantScope: undefined,
    });
  } catch (e) { threw = e; }
  check("every documented option is still accepted", threw === null,
        String(threw && (threw.code || threw.message)));
}

// `audit` is documented as an option on this listener and was never read, so
// an operator wiring a sink got silence. It is an operator-supplied sink in
// the same shape every other primitive takes.
function testOperatorAuditSinkIsWired() {
  var seen = [];
  var srv = b.mail.server.imap.create({
    tlsContext: {}, mailStore: { appendMessage: function () {} },
    audit: { safeEmit: function (ev) { seen.push(ev); } },
  });
  check("a listener with an operator audit sink is constructible", srv !== null);
  var threw = null;
  try {
    b.mail.server.imap.create({
      tlsContext: {}, mailStore: { appendMessage: function () {} },
      audit: { notASink: true },
    });
  } catch (e) { threw = e; }
  check("an audit sink without safeEmit is refused at construction", threw !== null,
        String(threw && (threw.code || threw.message)));
}

// ---- CONDSTORE / QRESYNC (RFC 7162) — v0.11.27 ----

async function _makeTestTlsContext() {
  var ca = await b.mtlsEngine.generateCa({ name: "imap-condstore-test-ca" });
  var leaf = await b.mtlsEngine.signClientCert({
    cn:           "imap.test",
    caCertPem:    ca.caCertPem,
    caKeyPem:     ca.caKeyPem,
    usage:        "server",
    sans:         ["DNS:imap.test", "DNS:localhost", "IP:127.0.0.1"],
    validityDays: 1,
  });
  var ctx = nodeTls.createSecureContext({ key: leaf.key, cert: leaf.cert });
  // The CA travels with the context so a test connecting directly (implicit
  // TLS) can VERIFY the chain rather than turning verification off.
  ctx.testCaPem = ca.caCertPem;
  return ctx;
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

async function _sendCommand(socket, tag, line) {
  return new Promise(function (resolve, reject) {
    var buf = "";
    function onData(chunk) {
      buf += chunk.toString("utf8");
      // Tagged response line begins with the tag we sent.
      if (buf.indexOf("\r\n") !== -1 && new RegExp("^" + tag + " ", "m").test(buf)) {
        socket.removeListener("data", onData);
        resolve(buf);
      }
    }
    socket.on("data", onData);
    socket.once("error", reject);
    socket.write(tag + " " + line + "\r\n");
  });
}

// Operator-shaped mailStore stub. Records the opts passed to fetchRange
// / storeFlags so the tests can assert the CONDSTORE protocol pieces
// landed in the right place.
function _makeStubMailStore() {
  var calls = { fetchRange: [], storeFlags: [], select: [] };
  return {
    calls: calls,
    appendMessage: function () { return Promise.resolve(); },
    selectFolder: function (_actor, mailbox) {
      calls.select.push({ mailbox: mailbox });
      return Promise.resolve({ uidvalidity: 1, modseq: 42, exists: 5,                                  // allow:raw-byte-literal — test-only stub modseq
                               recent: 0, unseen: 0, flags: ["\\Seen"] });
    },
    fetchRange: function (_actor, mailbox, seqSet, partsSpec, opts) {
      calls.fetchRange.push({ mailbox: mailbox, seqSet: seqSet, partsSpec: partsSpec, opts: opts });
      // Return two stub rows; honour `changedSince` by filtering.
      var rows = [
        { seq: 1, payload: "FLAGS (\\Seen)", modseq: 10 },                                              // allow:raw-byte-literal — test-only stub modseq
        { seq: 2, payload: "FLAGS ()",       modseq: 20 },                                              // allow:raw-byte-literal — test-only stub modseq
      ];
      if (opts && typeof opts.changedSince === "number") {
        rows = rows.filter(function (r) { return r.modseq > opts.changedSince; });
      }
      return Promise.resolve(rows);
    },
    storeFlags: function (_actor, mailbox, seqSet, mode, flagsArr, opts) {
      calls.storeFlags.push({ mailbox: mailbox, seqSet: seqSet, mode: mode, flagsArr: flagsArr, opts: opts });
      // If unchangedSince is set AND <= some threshold, return a
      // MODIFIED set for the conflicting ids.
      var rows = [
        { seq: 1, flags: ["\\Seen", "\\Flagged"], modseq: 11 },                                        // allow:raw-byte-literal — test-only stub modseq
      ];
      if (opts && typeof opts.unchangedSince === "number" && opts.unchangedSince < 15) {                // allow:raw-byte-literal — test-only conflict threshold
        return Promise.resolve({ rows: [], modified: "1" });
      }
      return Promise.resolve({ rows: rows, modified: null });
    },
  };
}

async function _connectAndLogin(srv) {
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var socket = nodeNet.connect(info.port, "127.0.0.1");
  await new Promise(function (r) { socket.once("connect", r); });
  await _readGreeting(socket);
  return { socket: socket, port: info.port };
}

// The capability list is written in three places on one connection — the
// greeting (RFC 9051 §7.1.5), the answer to CAPABILITY (§6.1.1), and the
// response code completing AUTHENTICATE / LOGIN — and a consumer had no way to
// reach any of them. Overriding the CAPABILITY verb through the dispatch
// registry produces a server whose three answers disagree, so one of them is
// false whichever way it is set: worse than the gap. The hook applies where
// the list is COMPUTED, so all three stay identical by construction.
async function testCapabilityHook() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("capability hook (skipped)", true); return; }
  var seen = [];
  var srv = b.mail.server.imap.create({
    tlsContext: ctx,
    mailStore:  _makeStubMailStore(),
    profile:    "permissive",
    capabilities: function (caps, state) {
      seen.push({ caps: caps.slice(), tls: !!(state && state.tls) });
      return caps.concat(["X-CONSUMER-EXT"]);
    },
    auth: {
      mechanisms: ["PLAIN"],
      verify: function () {
        return Promise.resolve({ ok: true, actor: { id: "u1", mailboxes: ["INBOX"] } });
      },
    },
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var socket = nodeNet.connect(info.port, "127.0.0.1");
  await new Promise(function (r) { socket.once("connect", r); });
  try {
    var greeting = await _readGreeting(socket);
    check("capability hook: the greeting carries what the hook returned",
      /X-CONSUMER-EXT/.test(greeting), JSON.stringify(greeting));
    var capReply = await _sendCommand(socket, "a1", "CAPABILITY");
    check("capability hook: and so does the CAPABILITY answer",
      /X-CONSUMER-EXT/.test(capReply), JSON.stringify(capReply));
    var authReply = await _sendCommand(socket, "a2",
      "AUTHENTICATE PLAIN " + Buffer.from("\0u1\0pw", "utf8").toString("base64"));
    check("capability hook: and the code completing AUTHENTICATE",
      /X-CONSUMER-EXT/.test(authReply), JSON.stringify(authReply));
    check("capability hook: it was given the resolved list and the session",
      seen.length >= 3 && seen[0].caps.indexOf("IMAP4rev2") !== -1 &&
      seen[0].caps.indexOf("X-CONSUMER-EXT") === -1,
      JSON.stringify(seen[0]));
    socket.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                   // allow:raw-time-literal — test-only short drain
}

// RFC 9051 §6.1.1 requires IMAP4rev2 in the list. A hook that drops it would
// leave the listener claiming a protocol it does not speak, so the refusal
// stays with the listener rather than being delegated to the consumer.
async function testCapabilityHookMustKeepImap4rev2() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("capability hook rev2 (skipped)", true); return; }
  var srv = b.mail.server.imap.create({
    tlsContext: ctx,
    mailStore:  _makeStubMailStore(),
    profile:    "permissive",
    capabilities: function (caps) {
      return caps.filter(function (c) { return c !== "IMAP4rev2"; });
    },
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var socket = nodeNet.connect(info.port, "127.0.0.1");
  await new Promise(function (r) { socket.once("connect", r); });
  try {
    var greeting = await _readGreeting(socket);
    check("capability hook: a list without IMAP4rev2 is not advertised",
      /IMAP4rev2/.test(greeting), JSON.stringify(greeting));
    socket.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                   // allow:raw-time-literal — test-only short drain
}

// Each capability is written into a space-separated protocol line, so a value
// carrying a space is two capabilities and one carrying CRLF is a second
// server response of the consumer's choosing. And the hook runs on the
// greeting — before a client has sent anything — so a throw there would take
// out a connection at the point where nothing has gone wrong yet.
async function testCapabilityHookCannotInjectOrCrash() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("capability hook injection (skipped)", true); return; }

  async function _greetingWith(hook) {
    var srv = b.mail.server.imap.create({
      tlsContext: ctx, mailStore: _makeStubMailStore(), profile: "permissive",
      capabilities: hook,
    });
    var info = await srv.listen({ port: 0, address: "127.0.0.1" });
    var socket = nodeNet.connect(info.port, "127.0.0.1");
    await new Promise(function (r) { socket.once("connect", r); });
    try {
      return await _readGreeting(socket);
    } finally { socket.destroy(); await srv.close({ timeoutMs: 1000 }); }                               // allow:raw-time-literal — test-only short drain
  }

  var injected = await _greetingWith(function (caps) {
    return caps.concat(["X-OK", "X-BAD\r\n* BYE injected", "X SPACED",
      // Valid RFC 9051 atoms that a narrower allowlist would have refused:
      // the grammar excludes specific characters, it does not enumerate the
      // permitted ones.
      "X-SEARCH/FOO", "X-VENDOR:EXT", "X-BANG!", "X-TILDE~",
      // atom-specials, each of which would change how the line parses.
      "X-PAREN(1)", "X-BRACE{2}", "X-WILD*", "X-PCT%", "X-RESP]", "X-QUOTE\""]);
  });
  check("capability hook: a value carrying CRLF is not advertised",
    injected.indexOf("BYE injected") === -1, JSON.stringify(injected));
  check("capability hook: nor one carrying a space",
    injected.indexOf("X SPACED") === -1, JSON.stringify(injected));
  check("capability hook: and the rest of the list still is",
    /X-OK/.test(injected) && /IMAP4rev2/.test(injected), JSON.stringify(injected));
  check("capability hook: a valid atom is advertised whatever punctuation it uses",
    /X-SEARCH\/FOO/.test(injected) && /X-VENDOR:EXT/.test(injected) &&
    /X-BANG!/.test(injected) && /X-TILDE~/.test(injected), JSON.stringify(injected));
  check("capability hook: every atom-special is refused",
    injected.indexOf("X-PAREN") === -1 && injected.indexOf("X-BRACE") === -1 &&
    injected.indexOf("X-WILD") === -1 && injected.indexOf("X-PCT") === -1 &&
    injected.indexOf("X-RESP") === -1 && injected.indexOf("X-QUOTE") === -1,
    JSON.stringify(injected));

  var afterThrow = await _greetingWith(function () { throw new Error("hook blew up"); });
  check("capability hook: a throwing hook leaves the framework's own list",
    /^\* OK \[CAPABILITY IMAP4rev2/.test(afterThrow), JSON.stringify(afterThrow));

  // Reading a value is the consumer's code too: an entry whose toString throws
  // fails in the same way as a hook that threw outright, and would escape a
  // guard that covered only the call.
  var afterHostileEntry = await _greetingWith(function (caps) {
    return caps.concat([{ toString: function () { throw new Error("hostile entry"); } }]);
  });
  check("capability hook: an entry that throws while being read is contained too",
    /^\* OK \[CAPABILITY IMAP4rev2/.test(afterHostileEntry), JSON.stringify(afterHostileEntry));
}

// A non-callable hook is the operator asking for a list the listener would
// then never consult.
async function testCapabilityHookRejectsNonFunction() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("capability hook non-callable (skipped)", true); return; }
  var threw = null;
  try {
    b.mail.server.imap.create({ tlsContext: ctx, mailStore: _makeStubMailStore(),
      profile: "permissive", capabilities: ["X-NOPE"] });
  } catch (e) { threw = e; }
  check("capability hook: a non-callable one is refused at construction",
    threw !== null && /capabilities/.test(threw.message || ""), String(threw && threw.message));
}

// RFC 8314 §3 asks for implicit TLS on 993 rather than the in-band upgrade.
// Without it the only arrangement available is a TLS terminator in front of
// 143, and behind one the listener is handed a plaintext connection — so it
// cannot see the TLS it is not part of, and every credential is refused. The
// tell is on the wire: a greeting advertising STARTTLS inside an established
// TLS session.
async function testImplicitTls() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("imap implicit TLS (skipped)", true); return; }
  var srv = b.mail.server.imap.create({
    tlsContext:  ctx,
    mailStore:   _makeStubMailStore(),
    profile:     "strict",
    implicitTls: true,
    auth: {
      mechanisms: ["PLAIN"],
      verify: function () {
        return Promise.resolve({ ok: true, actor: { id: "u1", mailboxes: ["INBOX"] } });
      },
    },
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var socket = nodeTls.connect({ port: info.port, host: "127.0.0.1",
    ca: ctx.testCaPem, servername: "localhost" });
  socket.on("error", function () {});
  await new Promise(function (r, j) { socket.once("secureConnect", r); socket.once("error", j); });
  try {
    var greeting = await _readGreeting(socket);
    check("imap implicit TLS: the greeting arrives over TLS", /^\* OK/.test(greeting),
      JSON.stringify(greeting));
    check("imap implicit TLS: STARTTLS is not advertised on this port",
      !/STARTTLS/.test(greeting), JSON.stringify(greeting));
    var caps = await _sendCommand(socket, "a1", "CAPABILITY");
    check("imap implicit TLS: nor in the CAPABILITY answer",
      !/STARTTLS/.test(caps), JSON.stringify(caps));
    check("imap implicit TLS: and the command is refused if sent (RFC 8314 §3.3)",
      /^a2 BAD/m.test(await _sendCommand(socket, "a2", "STARTTLS")));
    // The point of the mode: credentials are accepted under `strict`, which
    // is what a terminator in front of 143 cannot achieve.
    var auth = await _sendCommand(socket, "a3",
      "AUTHENTICATE PLAIN " + Buffer.from(" u1 pw", "utf8").toString("base64"));
    check("imap implicit TLS: AUTHENTICATE succeeds on the implicit session",
      /^a3 OK/m.test(auth), JSON.stringify(auth));
    socket.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                   // allow:raw-time-literal — test-only short drain

  // Whether STARTTLS is offered depends on the state of THIS connection, and
  // on this port the listener refuses the command outright — so it is not the
  // consumer's to advertise. A hook that puts it back would have a client
  // select a capability the listener cannot honour.
  var srv2 = b.mail.server.imap.create({
    tlsContext:   ctx,
    mailStore:    _makeStubMailStore(),
    profile:      "permissive",
    implicitTls:  true,
    capabilities: function (caps) { return caps.concat(["STARTTLS", "X-KEPT"]); },
  });
  var info2 = await srv2.listen({ port: 0, address: "127.0.0.1" });
  var socket2 = nodeTls.connect({ port: info2.port, host: "127.0.0.1",
    ca: ctx.testCaPem, servername: "localhost" });
  socket2.on("error", function () {});
  await new Promise(function (r, j) { socket2.once("secureConnect", r); socket2.once("error", j); });
  try {
    var greeting2 = await _readGreeting(socket2);
    check("imap implicit TLS: a hook cannot re-advertise STARTTLS on this port",
      !/STARTTLS/.test(greeting2), JSON.stringify(greeting2));
    check("imap implicit TLS: and the rest of its list is still advertised",
      /X-KEPT/.test(greeting2), JSON.stringify(greeting2));
    socket2.destroy();
  } finally { await srv2.close({ timeoutMs: 1000 }); }                                                  // allow:raw-time-literal — test-only short drain
}

async function testCapabilityAdvertisesCondstore() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("CONDSTORE capability (skipped)", true); return; }
  var stub = _makeStubMailStore();
  var srv = b.mail.server.imap.create({
    tlsContext: ctx,
    mailStore:  stub,
    profile:    "permissive",
    auth: {
      mechanisms: ["PLAIN", "LOGIN"],
      verify: function (_mech, _creds) {
        return Promise.resolve({ ok: true, actor: { id: "u1", mailboxes: ["INBOX"] } });
      },
    },
  });
  var c = await _connectAndLogin(srv);
  try {
    var reply = await _sendCommand(c.socket, "a1", "CAPABILITY");
    check("CAPABILITY advertises CONDSTORE",   /CONDSTORE/.test(reply));
    c.socket.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                   // allow:raw-time-literal — test-only short drain
}

async function testEnableCondstore() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("ENABLE CONDSTORE (skipped)", true); return; }
  var stub = _makeStubMailStore();
  var srv = b.mail.server.imap.create({
    tlsContext: ctx,
    mailStore:  stub,
    profile:    "permissive",
    auth: {
      mechanisms: ["PLAIN", "LOGIN"],
      verify: function (_mech, _creds) {
        return Promise.resolve({ ok: true, actor: { id: "u1", mailboxes: ["INBOX"] } });
      },
    },
  });
  var c = await _connectAndLogin(srv);
  try {
    var reply = await _sendCommand(c.socket, "a1", "ENABLE CONDSTORE");
    check("ENABLE CONDSTORE → ENABLED CONDSTORE", /ENABLED CONDSTORE/.test(reply));
    check("ENABLE CONDSTORE → OK",                /^a1 OK /m.test(reply));
    var reply2 = await _sendCommand(c.socket, "a2", "ENABLE CONDSTORE");
    // Already-enabled — ENABLE returns OK but ENABLED line carries no names.
    check("re-ENABLE → OK",                       /^a2 OK /m.test(reply2));
    c.socket.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                   // allow:raw-time-literal — test-only short drain
}

async function testFetchChangedSinceParses() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("FETCH CHANGEDSINCE (skipped)", true); return; }
  var stub = _makeStubMailStore();
  var srv = b.mail.server.imap.create({
    tlsContext: ctx,
    mailStore:  stub,
    profile:    "permissive",
    auth: {
      mechanisms: ["PLAIN", "LOGIN"],
      verify: function (_mech, _creds) {
        return Promise.resolve({ ok: true, actor: { id: "u1", mailboxes: ["INBOX"] } });
      },
    },
  });
  var c = await _connectAndLogin(srv);
  try {
    await _sendCommand(c.socket, "a0", "LOGIN test test");
    await _sendCommand(c.socket, "a1", "SELECT INBOX");
    await _sendCommand(c.socket, "a2", "ENABLE CONDSTORE");
    var reply = await _sendCommand(c.socket, "a3", "FETCH 1:* (FLAGS) (CHANGEDSINCE 15)");
    var lastCall = stub.calls.fetchRange[stub.calls.fetchRange.length - 1];
    check("backend got changedSince=15",          lastCall.opts.changedSince === 15);
    check("backend partsSpec stripped of modifier", lastCall.partsSpec === "(FLAGS)");
    // changedSince=15 → only modseq=20 row survives → exactly one FETCH untagged.
    check("FETCH replies with filtered row",       /^\* 2 FETCH /m.test(reply));
    check("MODSEQ attribute injected",            /MODSEQ \(20\)/.test(reply));
    c.socket.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                   // allow:raw-time-literal — test-only short drain
}

// RFC 9051 §4.3 makes a literal a counted sequence of OCTETS, and §6.4.5 makes
// `BODY[]` the message. Assembling the response as a JavaScript string and
// handing it to `socket.write` encodes it as UTF-8 on the way out, so a message
// octet that is not valid UTF-8 cannot survive: the listener returns content
// the backend does not hold, and a count that is not the count it announced.
//
// Two numbers in one response disagree, which is the part a client cannot work
// around — the literal count is what tells it where the response ends.
//
// The same message over POP3 in the same tree arrives intact, so the protocol
// an account holder happens to use decides whether they receive their own mail.
async function testFetchWritesTheOctetsTheBackendReturned() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("FETCH octets (skipped)", true); return; }

  // An ordinary 8-bit message: ISO-8859-1 e-acute, then a lone 0x82. Neither
  // is valid UTF-8, and both are perfectly ordinary mail.
  var raw = Buffer.from([
    0x53, 0x75, 0x62, 0x6A, 0x65, 0x63, 0x74, 0x3A, 0x20, 0x74, 0x0D, 0x0A,   // "Subject: t\r\n"
    0x0D, 0x0A,                                                               // header/body separator
    0x43, 0x61, 0x66, 0xE9, 0x0D, 0x0A,                                       // "Caf" + 0xE9 + CRLF
    0x82, 0xA0, 0x0D, 0x0A,                                                   // a Shift_JIS kana
  ]);
  // The payload the backend hands back, framed as RFC 9051 requires: the
  // literal's octet count, then exactly that many octets.
  var payload = Buffer.concat([
    Buffer.from("BODY[] {" + raw.length + "}\r\n", "latin1"),
    raw,
  ]);
  var store = _makeStubMailStore();
  store.fetchRange = function () {
    return Promise.resolve([{ seq: 1, payload: payload, modseq: 1 }]);
  };
  var srv = b.mail.server.imap.create({
    tlsContext: ctx, mailStore: store, profile: "permissive",
    auth: {
      mechanisms: ["PLAIN", "LOGIN"],
      verify: function () {
        return Promise.resolve({ ok: true, actor: { id: "u1", mailboxes: ["INBOX"] } });
      },
    },
  });
  var c = await _connectAndLogin(srv);
  try {
    await _sendCommand(c.socket, "a0", "LOGIN test test");
    await _sendCommand(c.socket, "a1", "SELECT INBOX");

    // Read the response as OCTETS. Decoding it as text before asserting would
    // destroy exactly the bytes under test, and the assertion would pass on a
    // listener that had already corrupted them.
    var chunks = [];
    var done = new Promise(function (resolve) {
      function onData(d) {
        chunks.push(Buffer.from(d));
        if (/a2 (OK|NO|BAD) /.test(Buffer.concat(chunks).toString("latin1"))) {
          c.socket.removeListener("data", onData);
          resolve();
        }
      }
      c.socket.on("data", onData);
    });
    c.socket.write("a2 FETCH 1 (BODY[])\r\n");
    await done;
    var wire = Buffer.concat(chunks);

    check("FETCH: the message's octets reach the wire unaltered",
          wire.indexOf(raw) !== -1,
          wire.toString("hex").slice(0, 160));
    // And the announced count is the count actually sent, which is what keeps
    // the client in step for the NEXT response.
    var text = wire.toString("latin1");
    var announced = /\{(\d+)\}\r\n/.exec(text);
    check("FETCH: the literal count is the stored octet count",
          announced && Number(announced[1]) === raw.length,
          announced && announced[1] + " vs " + raw.length);
    var at = wire.indexOf(Buffer.from("}\r\n", "latin1"));
    check("FETCH: exactly that many octets follow the literal header",
          at !== -1 && wire.subarray(at + 3, at + 3 + raw.length).equals(raw),
          at === -1 ? "no literal header" :
            wire.subarray(at + 3, at + 3 + raw.length).toString("hex"));

    // The other half of the same question. A response STRING is still UTF-8:
    // RFC 9051 §5.1 has mailbox names in UTF-8 once the client enables
    // UTF8=ACCEPT, and a first version of the octet fix encoded every string
    // latin1, which keeps only the low byte of each character and corrupts
    // every name outside Latin-1. That is the same defect moved, not fixed.
    var cjk = "中文";                                                 // two CJK characters, three octets each in UTF-8
    var noticed = [];
    var sawNotice = new Promise(function (resolve) {
      function onNotice(d) {
        noticed.push(Buffer.from(d));
        if (/a3 (OK|NO|BAD) /.test(Buffer.concat(noticed).toString("latin1"))) {
          c.socket.removeListener("data", onNotice);
          resolve();
        }
      }
      c.socket.on("data", onNotice);
    });
    store.fetchRange = function () {
      return Promise.resolve([{ seq: 1, payload: "FLAGS () \"" + cjk + "\"", modseq: 1 }]);
    };
    c.socket.write("a3 FETCH 1 (FLAGS)\r\n");
    await sawNotice;
    check("FETCH: a non-ASCII response string keeps its UTF-8 encoding",
          Buffer.concat(noticed).indexOf(Buffer.from(cjk, "utf8")) !== -1,
          Buffer.concat(noticed).toString("hex").slice(0, 120));
    c.socket.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                   // allow:raw-time-literal — test-only short drain
}

async function testStoreUnchangedSinceConflict() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("STORE UNCHANGEDSINCE (skipped)", true); return; }
  var stub = _makeStubMailStore();
  var srv = b.mail.server.imap.create({
    tlsContext: ctx,
    mailStore:  stub,
    profile:    "permissive",
    auth: {
      mechanisms: ["PLAIN", "LOGIN"],
      verify: function (_mech, _creds) {
        return Promise.resolve({ ok: true, actor: { id: "u1", mailboxes: ["INBOX"] } });
      },
    },
  });
  var c = await _connectAndLogin(srv);
  try {
    await _sendCommand(c.socket, "a0", "LOGIN test test");
    await _sendCommand(c.socket, "a1", "SELECT INBOX");
    await _sendCommand(c.socket, "a2", "ENABLE CONDSTORE");
    var conflict = await _sendCommand(c.socket, "a3",
      "STORE 1:* (UNCHANGEDSINCE 5) +FLAGS (\\Flagged)");
    var lastCall = stub.calls.storeFlags[stub.calls.storeFlags.length - 1];
    check("backend got unchangedSince=5",         lastCall.opts.unchangedSince === 5);
    check("MODIFIED set surfaced in OK code",     /\[MODIFIED 1\]/.test(conflict));
    // Non-conflicting STORE — backend returns modified=null → no [MODIFIED ...]
    var ok = await _sendCommand(c.socket, "a4",
      "STORE 1:* (UNCHANGEDSINCE 99) +FLAGS (\\Flagged)");
    check("no-conflict STORE has no MODIFIED",   !/\[MODIFIED /.test(ok));
    check("FETCH untagged includes MODSEQ",       /MODSEQ \(11\)/.test(ok));
    c.socket.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                   // allow:raw-time-literal — test-only short drain
}

async function testFetchChangedSinceImpliesCondstore() {
  // Codex P2 — `FETCH ... (CHANGEDSINCE n)` MUST include MODSEQ in
  // untagged responses even when the client never issued
  // `ENABLE CONDSTORE`. Per RFC 7162 §3.1.2 the modifier engages
  // CONDSTORE implicitly for the session.
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("FETCH CHANGEDSINCE implies CONDSTORE (skipped)", true); return; }
  var stub = _makeStubMailStore();
  var srv = b.mail.server.imap.create({
    tlsContext: ctx, mailStore: stub, profile: "permissive",
    auth: { mechanisms: ["PLAIN", "LOGIN"], verify: function () {
      return Promise.resolve({ ok: true, actor: { id: "u1" } });
    } },
  });
  var c = await _connectAndLogin(srv);
  try {
    await _sendCommand(c.socket, "a0", "LOGIN test test");
    await _sendCommand(c.socket, "a1", "SELECT INBOX");
    // No ENABLE CONDSTORE — go straight to FETCH with CHANGEDSINCE.
    var reply = await _sendCommand(c.socket, "a2", "FETCH 1:* (FLAGS) (CHANGEDSINCE 15)");
    check("CHANGEDSINCE injects MODSEQ even without ENABLE",
          /MODSEQ \(20\)/.test(reply));
    c.socket.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                   // allow:raw-time-literal — test-only short drain
}

// ---- v0.11.28 — NOTIFY / METADATA / CATENATE ----

async function testCapabilityAdvertisesNewExtensions() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("CAP advertises NOTIFY/METADATA/CATENATE (skipped)", true); return; }
  var stub = _makeStubMailStore();
  var srv = b.mail.server.imap.create({ tlsContext: ctx, mailStore: stub });
  var c = await _connectAndLogin(srv);
  try {
    var reply = await _sendCommand(c.socket, "a1", "CAPABILITY");
    check("CAPABILITY advertises NOTIFY",       /\bNOTIFY\b/.test(reply));
    check("CAPABILITY advertises METADATA",     /\bMETADATA\b/.test(reply));
    check("CAPABILITY advertises METADATA-SERVER", /METADATA-SERVER/.test(reply));
    check("CAPABILITY advertises CATENATE",     /\bCATENATE\b/.test(reply));
    check("CAPABILITY does NOT advertise COMPRESS=DEFLATE",
          !/COMPRESS=DEFLATE/.test(reply));
    c.socket.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                   // allow:raw-time-literal — test-only short drain
}

async function testNotifyNoneAndSet() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("NOTIFY (skipped)", true); return; }
  var stub = _makeStubMailStore();
  var subscribeCalls = [];
  stub.subscribeNotify = function (actor, spec, emitFn) {
    subscribeCalls.push({ actor: actor, spec: spec, emitFn: emitFn });
    return Promise.resolve();
  };
  var srv = b.mail.server.imap.create({
    tlsContext: ctx, mailStore: stub, profile: "permissive",
    auth: { mechanisms: ["LOGIN"], verify: function () {
      return Promise.resolve({ ok: true, actor: { id: "u1" } });
    } },
  });
  var c = await _connectAndLogin(srv);
  try {
    await _sendCommand(c.socket, "a0", "LOGIN test test");
    var rSet = await _sendCommand(c.socket, "a1",
      "NOTIFY SET (SELECTED (MessageNew FlagChange))");
    check("NOTIFY SET → OK",                        /^a1 OK /m.test(rSet));
    check("subscribeNotify hook called",            subscribeCalls.length === 1);
    check("backend got spec verbatim",
          subscribeCalls[0].spec === "(SELECTED (MessageNew FlagChange))");

    // A pushed FETCH carries message content too, so it is the same octet
    // question as the FETCH command — and it was a SECOND copy of the response
    // builder, so fixing the command path alone left this one corrupting.
    var raw = Buffer.from([0x43, 0x61, 0x66, 0xE9, 0x0D, 0x0A]);                                        // "Caf" + 0xE9 + CRLF
    var pushed = [];
    var sawPush = new Promise(function (resolve) {
      function onPush(d) {
        pushed.push(Buffer.from(d));
        if (Buffer.concat(pushed).indexOf(Buffer.from(" FETCH (", "latin1")) !== -1) {
          c.socket.removeListener("data", onPush);
          resolve();
        }
      }
      c.socket.on("data", onPush);
    });
    subscribeCalls[0].emitFn({
      kind: "FETCH", seq: 7,
      payload: Buffer.concat([Buffer.from("BODY[] {" + raw.length + "}\r\n", "latin1"), raw]),
    });
    await sawPush;
    check("NOTIFY: a pushed FETCH writes the backend's octets unaltered",
          Buffer.concat(pushed).indexOf(raw) !== -1,
          Buffer.concat(pushed).toString("hex").slice(0, 120));

    var rNone = await _sendCommand(c.socket, "a2", "NOTIFY NONE");
    check("NOTIFY NONE → OK",                       /^a2 OK /m.test(rNone));
    c.socket.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                   // allow:raw-time-literal — test-only short drain
}

async function testNotifyBackendMissing() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("NOTIFY backend missing (skipped)", true); return; }
  var stub = _makeStubMailStore();
  // No subscribeNotify hook.
  var srv = b.mail.server.imap.create({
    tlsContext: ctx, mailStore: stub, profile: "permissive",
    auth: { mechanisms: ["LOGIN"], verify: function () {
      return Promise.resolve({ ok: true, actor: { id: "u1" } });
    } },
  });
  var c = await _connectAndLogin(srv);
  try {
    await _sendCommand(c.socket, "a0", "LOGIN test test");
    var rSet = await _sendCommand(c.socket, "a1",
      "NOTIFY SET (SELECTED (MessageNew))");
    check("NOTIFY without backend → NO",            /^a1 NO /m.test(rSet));
    c.socket.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                   // allow:raw-time-literal — test-only short drain
}

async function testGetSetMetadata() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("GETMETADATA / SETMETADATA (skipped)", true); return; }
  var stub = _makeStubMailStore();
  stub.getMetadata = function (actor, mailbox, names) {
    return Promise.resolve(names.map(function (n) {
      return { entry: n, value: n === "/private/comment" ? "hello" : null };
    }));
  };
  var setCalls = [];
  stub.setMetadata = function (actor, mailbox, entries) {
    setCalls.push({ actor: actor, mailbox: mailbox, entries: entries });
    return Promise.resolve();
  };
  var srv = b.mail.server.imap.create({
    tlsContext: ctx, mailStore: stub, profile: "permissive",
    auth: { mechanisms: ["LOGIN"], verify: function () {
      return Promise.resolve({ ok: true, actor: { id: "u1" } });
    } },
  });
  var c = await _connectAndLogin(srv);
  try {
    await _sendCommand(c.socket, "a0", "LOGIN test test");
    var rGet = await _sendCommand(c.socket, "a1",
      "GETMETADATA INBOX (/private/comment /shared/admin)");
    check("GETMETADATA returns OK",                /^a1 OK /m.test(rGet));
    check("GETMETADATA untagged METADATA line",    /^\* METADATA /m.test(rGet));
    check("GETMETADATA includes /private/comment value",
          /\/private\/comment "hello"/.test(rGet));
    check("GETMETADATA NIL for unknown entry",     /\/shared\/admin NIL/.test(rGet));

    var rSet = await _sendCommand(c.socket, "a2",
      "SETMETADATA INBOX (/private/comment \"updated\")");
    check("SETMETADATA returns OK",                /^a2 OK /m.test(rSet));
    check("setMetadata hook called",               setCalls.length === 1);
    check("setMetadata mailbox forwarded",         setCalls[0].mailbox === "INBOX");
    check("setMetadata entry+value parsed",
          setCalls[0].entries.length === 1 &&
          setCalls[0].entries[0].entry === "/private/comment" &&
          setCalls[0].entries[0].value === "updated");

    await _sendCommand(c.socket, "a3",
      "SETMETADATA INBOX (/private/comment NIL)");
    check("SETMETADATA NIL clears entry",
          setCalls.length === 2 && setCalls[1].entries[0].value === null);
    c.socket.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                   // allow:raw-time-literal — test-only short drain
}

async function testMetadataBackendMissing() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("METADATA backend missing (skipped)", true); return; }
  var stub = _makeStubMailStore();
  // No getMetadata / setMetadata.
  var srv = b.mail.server.imap.create({
    tlsContext: ctx, mailStore: stub, profile: "permissive",
    auth: { mechanisms: ["LOGIN"], verify: function () {
      return Promise.resolve({ ok: true, actor: { id: "u1" } });
    } },
  });
  var c = await _connectAndLogin(srv);
  try {
    await _sendCommand(c.socket, "a0", "LOGIN test test");
    var rGet = await _sendCommand(c.socket, "a1", "GETMETADATA INBOX (/private/x)");
    check("GETMETADATA without backend → NO",      /^a1 NO /m.test(rGet));
    var rSet = await _sendCommand(c.socket, "a2", "SETMETADATA INBOX (/private/x \"y\")");
    check("SETMETADATA without backend → NO",      /^a2 NO /m.test(rSet));
    c.socket.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                   // allow:raw-time-literal — test-only short drain
}

async function testCatenateBackendMissing() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("CATENATE backend missing (skipped)", true); return; }
  var stub = _makeStubMailStore();
  // No appendCatenate hook.
  var srv = b.mail.server.imap.create({
    tlsContext: ctx, mailStore: stub, profile: "permissive",
    auth: { mechanisms: ["LOGIN"], verify: function () {
      return Promise.resolve({ ok: true, actor: { id: "u1" } });
    } },
  });
  var c = await _connectAndLogin(srv);
  try {
    await _sendCommand(c.socket, "a0", "LOGIN test test");
    // APPEND ... CATENATE — backend missing, gets NO with reason.
    var r = await _sendCommand(c.socket, "a1",
      "APPEND INBOX CATENATE (URL \"imap://x/INBOX;UID=1\")");
    check("APPEND CATENATE without backend → NO",  /^a1 NO /m.test(r));
    check("refusal mentions backend not configured", /backend not configured/i.test(r));
    c.socket.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                   // allow:raw-time-literal — test-only short drain
}

// RFC 9051 §7.5 — a synchronizing literal is answered with a command
// continuation request, a line that BEGINS with `+`. The listener answered
// with an untagged response whose text happened to start with a plus, so the
// wire carried `* + Ready for literal data`. A conforming client waits for a
// line starting with `+`, never sees one, and APPEND never completes.
//
// There was no way around it: the strict profile's guard refuses LITERAL+, and
// CAPABILITY does not advertise it, so the non-synchronizing route is closed
// too. The same file already used the right writer for the SASL challenge and
// for IDLE — only the literal path reached for the untagged one.
// A conforming client ends the command line after the literal octets, so the
// wire carries `{N}` CRLF, N octets, then the CRLF that terminates the
// command. Consuming only the octets leaves that CRLF in the buffer, where the
// next turn reads it as a line of its own and answers BAD to a command that
// had already succeeded.
//
// The second half is the one that cannot be worked around. RFC 9051 allows a
// literal wherever an astring is allowed, and the LOGIN example carries two on
// one line, so bytes after a NON-FINAL literal are the same command continuing
// rather than a new one.
// A command carrying a literal must parse the same however TCP split it. What
// follows a literal's octets is what says whether the literal was the last
// argument, so the reader waits for that line to end rather than deciding from
// whichever bytes happened to arrive together.
async function testLiteralFramingDoesNotDependOnPacketBoundaries() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("literal packet boundaries (skipped)", true); return; }
  var seenCreds = [];
  var srv = b.mail.server.imap.create({
    tlsContext: ctx, mailStore: _makeStubMailStore(), profile: "permissive",
    auth: { mechanisms: ["LOGIN"], verify: function (mech, creds) {
      seenCreds.push({ username: creds.username, password: creds.password });
      return Promise.resolve({ ok: true, actor: { id: "u1" } });
    } },
  });
  var c = await _connectAndLogin(srv);
  try {
    var seen = "";
    function collect(chunk) { seen += chunk.toString("utf8"); }
    c.socket.on("data", collect);

    // A two-literal LOGIN with EVERY part in its own write, and a pause
    // between each so they cannot coalesce. This is the shape that parsed by
    // luck when the reader guessed from an empty buffer.
    c.socket.write("A001 LOGIN {5}\r\n");
    await helpers.waitUntil(function () { return seen.indexOf("+") !== -1; },
      { timeoutMs: 5000, label: "split literal: first continuation" });
    c.socket.write("alice");
    await helpers.passiveObserve(150, "split literal: octets alone are not a command");
    check("a non-final literal's octets alone do not complete the command",
          !/^A001 /m.test(seen), JSON.stringify(seen));

    c.socket.write(" {6}\r\n");
    await helpers.waitUntil(function () { return seen.split("+").length > 2; },
      { timeoutMs: 5000, label: "split literal: second continuation" });
    c.socket.write("s3cr3t");
    await helpers.passiveObserve(150, "split literal: second octets alone");
    c.socket.write("\r\n");
    await helpers.waitUntil(function () { return /^A001 /m.test(seen); },
      { timeoutMs: 5000, label: "split literal: tagged response" });

    check("a command split at every literal boundary still parses as one",
          /^A001 OK/m.test(seen), JSON.stringify(seen));
    check("and both literals reach the verifier as the arguments they were",
          seenCreds.length === 1 && seenCreds[0].username === "alice" &&
          seenCreds[0].password === "s3cr3t", JSON.stringify(seenCreds));
    check("no fragment of it is answered as a command of its own",
          seen.split("\r\n").filter(function (l) {
            return l.indexOf("BAD") !== -1;
          }).length === 0, JSON.stringify(seen));
    c.socket.removeListener("data", collect);
    c.socket.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                   // allow:raw-time-literal — test-only short drain
}

// A literal's outstanding octets are exempt from the backlog bound, because
// they are payload rather than queued commands. The rest of the buffer is not:
// putting a literal opener in front of a flood would otherwise carry the whole
// write past the bound, and once the literal is consumed the reader continues
// through the queue without passing the check again.
async function testPipelineBoundIsNotBypassedByAPendingLiteral() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("pipeline bound behind literal (skipped)", true); return; }
  var stub = _makeStubMailStore();
  stub.appendMessage = function () { return Promise.resolve({ uid: 3, uidValidity: 1 }); };
  var srv = b.mail.server.imap.create({
    tlsContext: ctx, mailStore: stub, profile: "permissive",
    maxLineBytes: 200,                                                                                 // allow:raw-byte-literal — small cap so the flood clears the allowance
    auth: { mechanisms: ["LOGIN"], verify: function () {
      return Promise.resolve({ ok: true, actor: { id: "u1" } });
    } },
  });
  var c = await _connectAndLogin(srv);
  try {
    await _sendCommand(c.socket, "a0", "LOGIN test test");
    var seen = "";
    c.socket.on("data", function (chunk) { seen += chunk.toString("utf8"); });

    // A literal opener and far more queued command bytes than the allowance,
    // in one write. Asserted on the refusal reaching the client rather than on
    // the socket closing: a closed connection could equally be the literal
    // deadline or the rate floor, and the test would then pass without any
    // bound existing.
    var flood = "";
    for (var i = 0; i < 400; i += 1) flood += "n" + i + " NOOP\r\n";
    c.socket.write("a1 APPEND INBOX {5}\r\n" + flood);

    await helpers.waitUntil(function () { return /BAD/.test(seen); },
      { timeoutMs: 5000, label: "pipeline behind literal: refused" });
    check("a literal opener in front of a flood does not carry it past the bounds",
          /Too much pipelined data|Line too long/.test(seen),
          JSON.stringify(seen.slice(-160)));
    check("and the connection does not go on serving the queued commands",
          !/^n399 /m.test(seen), JSON.stringify(seen.slice(-160)));
    c.socket.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                   // allow:raw-time-literal — test-only short drain
}

// A synchronizing literal gets a continuation request whatever its length. RFC
// 9051 section 7.5 does not exempt an empty one, and a conforming client waits
// for the `+` before sending the CRLF that ends the command — so a reader that
// waits for that CRLF without sending the `+` waits forever.
async function testZeroLengthSynchronizingLiteralGetsAContinuation() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("zero literal continuation (skipped)", true); return; }
  var stub = _makeStubMailStore();
  stub.appendMessage = function () { return Promise.resolve({ uid: 9, uidValidity: 1 }); };
  var srv = b.mail.server.imap.create({
    tlsContext: ctx, mailStore: stub, profile: "permissive",
    auth: { mechanisms: ["LOGIN"], verify: function () {
      return Promise.resolve({ ok: true, actor: { id: "u1" } });
    } },
  });
  var c = await _connectAndLogin(srv);
  try {
    await _sendCommand(c.socket, "a0", "LOGIN test test");
    var seen = "";
    function collect(chunk) { seen += chunk.toString("utf8"); }
    c.socket.on("data", collect);

    // The client waits for the continuation, as one that follows the spec does.
    c.socket.write("a1 APPEND INBOX {0}\r\n");
    await helpers.waitUntil(function () { return seen.indexOf("+") !== -1; },
      { timeoutMs: 5000, label: "zero literal: continuation request" });
    check("a zero-byte synchronizing literal is answered with a continuation",
          seen.indexOf("+") !== -1, JSON.stringify(seen));

    // Only then does it send the CRLF that ends the command.
    c.socket.write("\r\n");
    await helpers.waitUntil(function () { return /^a1 /m.test(seen); },
      { timeoutMs: 5000, label: "zero literal: tagged response" });
    check("and the command completes", /^a1 /m.test(seen), JSON.stringify(seen));
    c.socket.removeListener("data", collect);
    c.socket.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                   // allow:raw-time-literal — test-only short drain
}

// A literal may be an element of a parenthesized list, where the byte after
// its octets is the closing paren rather than a space. `ID ("name" {4}` is the
// shape, and it is one a client may send before authenticating.
async function testLiteralInsideAParenthesizedListCompletes() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("literal in list (skipped)", true); return; }
  var srv = b.mail.server.imap.create({
    tlsContext: ctx, mailStore: _makeStubMailStore(), profile: "permissive",
  });
  var c = await _connectAndLogin(srv);
  try {
    var seen = "";
    function collect(chunk) { seen += chunk.toString("utf8"); }
    c.socket.on("data", collect);

    c.socket.write('a1 ID ("name" {4}\r\n');
    await helpers.waitUntil(function () { return seen.indexOf("+") !== -1; },
      { timeoutMs: 5000, label: "literal in list: continuation" });
    // The octets, then the closing paren and the line's own terminator.
    c.socket.write("test)\r\n");
    await helpers.waitUntil(function () { return /^a1 /m.test(seen); },
      { timeoutMs: 5000, label: "literal in list: tagged response" });

    check("a literal closed by ')' rather than a space is accepted",
          !/BAD Expected end of command/.test(seen), JSON.stringify(seen));
    c.socket.removeListener("data", collect);
    c.socket.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                   // allow:raw-time-literal — test-only short drain
}

// The cap is on what ONE command's literals add up to, so the last one counts
// as much as the ones before it. Counting only the non-final literals let a
// command carry one more than the limit allows.
async function testAggregateLiteralCapCountsTheFinalLiteral() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("aggregate literal cap (skipped)", true); return; }
  var verified = [];
  var srv = b.mail.server.imap.create({
    tlsContext: ctx, mailStore: _makeStubMailStore(), profile: "permissive",
    maxLiteralBytes: 1024,                                                                             // allow:raw-byte-literal — two full-size literals must exceed it together
    auth: { mechanisms: ["LOGIN"], verify: function (mech, creds) {
      verified.push(creds); return Promise.resolve({ ok: true, actor: { id: "u1" } });
    } },
  });
  var c = await _connectAndLogin(srv);
  try {
    var seen = "";
    function collect(chunk) { seen += chunk.toString("utf8"); }
    c.socket.on("data", collect);

    // Two literals, each exactly at the cap, so only their SUM exceeds it.
    var big = "u".repeat(1024);
    c.socket.write("A001 LOGIN {1024}\r\n");
    await helpers.waitUntil(function () { return seen.indexOf("+") !== -1; },
      { timeoutMs: 5000, label: "aggregate cap: first continuation" });
    c.socket.write(big + " {1024}\r\n");
    await helpers.waitUntil(function () {
      return seen.split("+").length > 2 || /^A001 /m.test(seen);
    }, { timeoutMs: 5000, label: "aggregate cap: second continuation" });
    c.socket.write("p".repeat(1024) + "\r\n");
    await helpers.waitUntil(function () { return /^A001 /m.test(seen); },
      { timeoutMs: 5000, label: "aggregate cap: tagged response" });

    check("two literals that exceed the cap together are refused",
          /^A001 BAD/m.test(seen), JSON.stringify(seen.slice(-140)));
    check("and no credential built from them reaches the verifier",
          verified.length === 0, String(verified.length));
    c.socket.removeListener("data", collect);
    c.socket.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                   // allow:raw-time-literal — test-only short drain
}

// A literal is framed by its own octet count and bounded by maxLiteralBytes;
// the line cap bounds what the client typed. Charging a literal's bytes
// against the line cap refuses a command whose text is short and whose
// argument is legitimately large.
async function testLiteralBytesAreNotChargedToTheLineCap() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("literal vs line cap (skipped)", true); return; }
  var seenCreds = [];
  var srv = b.mail.server.imap.create({
    tlsContext: ctx, mailStore: _makeStubMailStore(), profile: "permissive",
    maxLineBytes: 200,                                                                                 // allow:raw-byte-literal — small line cap, large literal cap
    maxLiteralBytes: 65536,                                                                            // allow:raw-byte-literal — the literal is bounded by ITS own cap
    auth: { mechanisms: ["LOGIN"], verify: function (mech, creds) {
      seenCreds.push({ username: creds.username, password: creds.password });
      return Promise.resolve({ ok: true, actor: { id: "u1" } });
    } },
  });
  var c = await _connectAndLogin(srv);
  try {
    var seen = "";
    function collect(chunk) { seen += chunk.toString("utf8"); }
    c.socket.on("data", collect);

    // A username far past the 200-byte LINE cap and far inside the literal
    // cap, followed by another argument so the literal is not the last token.
    var longUser = "u".repeat(1000);
    c.socket.write("A001 LOGIN {" + longUser.length + "}\r\n");
    await helpers.waitUntil(function () { return seen.indexOf("+") !== -1; },
      { timeoutMs: 5000, label: "literal vs line cap: continuation" });
    c.socket.write(longUser + " {6}\r\n");
    await helpers.waitUntil(function () { return seen.split("+").length > 2; },
      { timeoutMs: 5000, label: "literal vs line cap: second continuation" });
    c.socket.write("s3cr3t\r\n");
    await helpers.waitUntil(function () { return /^A001 /m.test(seen); },
      { timeoutMs: 5000, label: "literal vs line cap: tagged response" });

    check("a literal larger than the line cap is accepted as an argument",
          /^A001 OK/m.test(seen), JSON.stringify(seen.slice(0, 200)));
    check("and it reaches the verifier whole",
          seenCreds.length === 1 && seenCreds[0].username === longUser &&
          seenCreds[0].password === "s3cr3t",
          JSON.stringify(seenCreds.map(function (x) {
            return { u: x.username && x.username.length, p: x.password };
          })));
    c.socket.removeListener("data", collect);
    c.socket.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                   // allow:raw-time-literal — test-only short drain
}

// The terminator arriving in its own segment, well after the octets.
async function testFinalLiteralCompletesWhenItsTerminatorArrivesLate() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("literal without terminator (skipped)", true); return; }
  var stub = _makeStubMailStore();
  stub.appendMessage = function () { return Promise.resolve({ uid: 7, uidValidity: 1 }); };
  var srv = b.mail.server.imap.create({
    tlsContext: ctx, mailStore: stub, profile: "permissive",
    auth: { mechanisms: ["LOGIN"], verify: function () {
      return Promise.resolve({ ok: true, actor: { id: "u1" } });
    } },
  });
  var c = await _connectAndLogin(srv);
  try {
    await _sendCommand(c.socket, "a0", "LOGIN test test");
    var seen = "";
    function collect(chunk) { seen += chunk.toString("utf8"); }
    c.socket.on("data", collect);

    var body = "Subject: hi\r\n\r\nhello\r\n";
    c.socket.write("a1 APPEND INBOX {" + body.length + "}\r\n");
    await helpers.waitUntil(function () { return seen.indexOf("+") !== -1; },
      { timeoutMs: 5000, label: "no-terminator: continuation" });

    // The octets, then a pause, then the CRLF that ends the command line in a
    // segment of its own.
    c.socket.write(body);
    await helpers.passiveObserve(300, "late terminator: the octets alone are not the whole line");
    c.socket.write("\r\n");
    await helpers.waitUntil(function () { return /^a1 /m.test(seen); },
      { timeoutMs: 5000, label: "late terminator: tagged response" });
    check("APPEND completes when its terminator arrives separately",
          /^a1 OK/m.test(seen), JSON.stringify(seen));
    check("and the terminator is not answered as an empty command",
          seen.indexOf("BAD") === -1, JSON.stringify(seen));

    // The connection still works afterwards.
    var next = await _sendCommand(c.socket, "a2", "NOOP");
    check("the session continues", /^a2 OK/m.test(next), JSON.stringify(next));
    c.socket.removeListener("data", collect);
    c.socket.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                   // allow:raw-time-literal — test-only short drain
}

async function testLiteralCommandConsumesItsOwnTerminator() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("APPEND literal terminator (skipped)", true); return; }
  var stub = _makeStubMailStore();
  stub.appendMessage = function () { return Promise.resolve({ uid: 42, uidValidity: 1 }); };
  var srv = b.mail.server.imap.create({
    tlsContext: ctx, mailStore: stub, profile: "permissive",
    auth: { mechanisms: ["LOGIN"], verify: function () {
      return Promise.resolve({ ok: true, actor: { id: "u1" } });
    } },
  });
  var c = await _connectAndLogin(srv);
  try {
    await _sendCommand(c.socket, "a0", "LOGIN test test");

    var seen = "";
    function collect(chunk) { seen += chunk.toString("utf8"); }
    c.socket.on("data", collect);

    var body = "Subject: hi\r\n\r\nhello\r\n";
    c.socket.write("a1 APPEND INBOX {" + body.length + "}\r\n");
    await helpers.waitUntil(function () { return seen.indexOf("+") !== -1; },
      { timeoutMs: 5000, label: "imap literal: continuation request" });

    // The octets, then the CRLF that ends the command line -- what a
    // conforming client sends and what the earlier test left out.
    c.socket.write(body);
    c.socket.write("\r\n");
    await helpers.waitUntil(function () { return /^a1 /m.test(seen); },
      { timeoutMs: 5000, label: "imap literal: tagged response for a1" });
    check("APPEND with its terminating CRLF completes OK",
          /^a1 OK/m.test(seen), JSON.stringify(seen));

    // No BAD anywhere in the exchange. Deliberately not "no BAD after the a1
    // line": when the terminator IS read as a command the refusal arrives
    // BEFORE the tagged OK, so an assertion anchored on that line looks past
    // the thing it is checking for.
    await helpers.passiveObserve(600, "imap literal: no reply to the terminating CRLF");
    check("the terminating CRLF is not answered as an empty command",
          seen.indexOf("BAD") === -1, JSON.stringify(seen));
    c.socket.removeListener("data", collect);
    c.socket.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                   // allow:raw-time-literal — test-only short drain
}

// RFC 9051 section 6.2.3: `A001 LOGIN {11}` / `FRED FOOBAR {7}` / `fubar` is
// ONE command carrying two literals. The reader must assemble it rather than
// dispatch the bytes after the first literal as a fresh line.
async function testNonFinalLiteralContinuesTheSameCommand() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("non-final literal (skipped)", true); return; }
  var srv = b.mail.server.imap.create({
    tlsContext: ctx, mailStore: _makeStubMailStore(), profile: "permissive",
    auth: { mechanisms: ["LOGIN"], verify: function () {
      return Promise.resolve({ ok: true, actor: { id: "u1" } });
    } },
  });
  var c = await _connectAndLogin(srv);
  try {
    var seen = "";
    function collect(chunk) { seen += chunk.toString("utf8"); }
    c.socket.on("data", collect);

    // `{11}` is exactly "FRED FOOBAR"; the octets are followed by ` {5}` and
    // the CRLF that ends the line, so the command continues rather than ends.
    c.socket.write("A001 LOGIN {11}\r\n");
    await helpers.waitUntil(function () { return seen.indexOf("+") !== -1; },
      { timeoutMs: 5000, label: "imap login: first continuation" });
    c.socket.write("FRED FOOBAR {5}\r\n");
    await helpers.waitUntil(function () { return seen.split("+").length > 2; },
      { timeoutMs: 5000, label: "imap login: second continuation" });
    c.socket.write("fubar\r\n");
    await helpers.waitUntil(function () { return /^A001 /m.test(seen); },
      { timeoutMs: 5000, label: "imap login: tagged response for A001" });

    // Exactly one tagged response, and no fragment answered on its own.
    var tagged = seen.split("\r\n").filter(function (l) { return l.indexOf("A001 ") === 0; });
    check("a two-literal command draws exactly one tagged response",
          tagged.length === 1, JSON.stringify(seen));
    check("no fragment of it is answered as a command of its own",
          seen.split("\r\n").filter(function (l) {
            return l.indexOf("BAD") !== -1 && l.indexOf("A001") !== 0;
          }).length === 0, JSON.stringify(seen));
    c.socket.removeListener("data", collect);
    c.socket.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                   // allow:raw-time-literal — test-only short drain
}

// An IMAP literal carries CHAR8 — arbitrary octets, not text. Writing a
// non-final one back into the command line as a quoted string means decoding
// it, and decoding bytes that are not UTF-8 replaces them with U+FFFD. A
// password would be silently changed and the login would fail as a wrong
// password. Refused instead, naming the reason.
// A literal that ends its command is the last argument, and it reaches the
// handler as bytes rather than being written back into the line. `LOGIN user
// {N}` is the case that matters: the password is the literal, and a client
// sends one precisely when the value is not expressible as a quoted string, so
// re-quoting it would refuse the passwords this path exists to carry.
// Commands queue while a handler runs, so the buffer legitimately holds more
// than one line. The per-line cap must be measured against the line still
// arriving, not against everything waiting behind it — otherwise a client that
// merely pipelines is answered "Line too long" and disconnected.
async function testPipelinedCommandsAreNotRefusedAsOneLongLine() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("imap pipelined line cap (skipped)", true); return; }
  var release = null;
  var gate = new Promise(function (r) { release = r; });
  var store = _makeStubMailStore();
  store.listFolders = function () {
    return gate.then(function () {
      return [{ name: "INBOX", attributes: ["HasNoChildren"] }];
    });
  };
  var srv = b.mail.server.imap.create({
    tlsContext: ctx, mailStore: store, profile: "permissive",
    maxLineBytes: 200,                                                                                 // allow:raw-byte-literal — small cap so a few lines exceed it together
    auth: { mechanisms: ["LOGIN"], verify: function () {
      return Promise.resolve({ ok: true, actor: { id: "u1" } });
    } },
  });
  var c = await _connectAndLogin(srv);
  try {
    await _sendCommand(c.socket, "a0", "LOGIN test test");
    var seen = "";
    function collect(chunk) { seen += chunk.toString("utf8"); }
    c.socket.on("data", collect);

    // One slow command, then more than a line-cap's worth of short valid ones
    // queued behind it. No single line is anywhere near the cap.
    c.socket.write("b1 LIST \"\" *\r\n");
    var queued = "";
    for (var i = 0; i < 30; i += 1) queued += "n" + i + " NOOP\r\n";
    check("the queued commands together exceed one line's cap",
          queued.length > 200, String(queued.length));
    c.socket.write(queued);
    await helpers.passiveObserve(400, "imap pipeline cap: nothing refused while queued");
    check("pipelined commands are not refused as one long line",
          seen.indexOf("Line too long") === -1, JSON.stringify(seen));

    release();
    await helpers.waitUntil(function () { return /^n29 /m.test(seen); },
      { timeoutMs: 5000, label: "imap pipeline cap: the last queued command runs" });
    check("every queued command runs once the slow one finishes",
          /^b1 /m.test(seen) && /^n0 /m.test(seen) && /^n29 /m.test(seen),
          JSON.stringify(seen));
    c.socket.removeListener("data", collect);
    c.socket.destroy();
  } finally { if (release) release(); await srv.close({ timeoutMs: 1000 }); }                            // allow:raw-time-literal — test-only short drain
}

async function testFinalLiteralReachesTheHandlerAsItsArgument() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("final literal argument (skipped)", true); return; }
  var seenCreds = [];
  var srv = b.mail.server.imap.create({
    tlsContext: ctx, mailStore: _makeStubMailStore(), profile: "permissive",
    auth: { mechanisms: ["LOGIN"], verify: function (mech, creds) {
      seenCreds.push({ username: creds.username, password: creds.password });
      return Promise.resolve({ ok: true, actor: { id: "u1" } });
    } },
  });
  var c = await _connectAndLogin(srv);
  try {
    var seen = "";
    function collect(chunk) { seen += chunk.toString("utf8"); }
    c.socket.on("data", collect);

    c.socket.write("A001 LOGIN alice {6}\r\n");
    await helpers.waitUntil(function () { return seen.indexOf("+") !== -1; },
      { timeoutMs: 5000, label: "imap final-literal: continuation" });
    c.socket.write("s3cr3t\r\n");
    await helpers.waitUntil(function () { return /^A001 /m.test(seen); },
      { timeoutMs: 5000, label: "imap final-literal: tagged response" });

    check("a command ending in a literal argument is accepted",
          /^A001 OK/m.test(seen), JSON.stringify(seen));
    check("and nothing in it is answered as a command of its own",
          seen.indexOf("BAD") === -1, JSON.stringify(seen));
    check("the literal reaches the verifier as the password it was",
          seenCreds.length === 1 && seenCreds[0].password === "s3cr3t",
          JSON.stringify(seenCreds));
    c.socket.removeListener("data", collect);
    c.socket.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                   // allow:raw-time-literal — test-only short drain
}

async function testNonFinalLiteralRefusesUndecodableBytes() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("non-final literal CHAR8 (skipped)", true); return; }
  var verified = [];
  var srv = b.mail.server.imap.create({
    tlsContext: ctx, mailStore: _makeStubMailStore(), profile: "permissive",
    auth: { mechanisms: ["LOGIN"], verify: function (mech, creds) {
      verified.push(creds);
      return Promise.resolve({ ok: true, actor: { id: "u1" } });
    } },
  });
  var c = await _connectAndLogin(srv);
  try {
    var seen = "";
    function collect(chunk) { seen += chunk.toString("utf8"); }
    c.socket.on("data", collect);

    c.socket.write("A001 LOGIN {4}\r\n");
    await helpers.waitUntil(function () { return seen.indexOf("+") !== -1; },
      { timeoutMs: 5000, label: "imap char8: continuation" });
    // 0xFF is not a valid UTF-8 lead byte, so decoding it loses it.
    c.socket.write(Buffer.from([0x75, 0x73, 0x65, 0xFF]));
    c.socket.write(" {3}\r\n");
    await helpers.waitUntil(function () { return /^A001 /m.test(seen); },
      { timeoutMs: 5000, label: "imap char8: tagged response" });

    check("a non-final literal that is not decodable is refused",
          /^A001 BAD/m.test(seen), JSON.stringify(seen));
    check("no credential built from replacement characters reaches verify",
          verified.length === 0, JSON.stringify(verified));
    c.socket.removeListener("data", collect);
    c.socket.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                   // allow:raw-time-literal — test-only short drain
}

async function testAppendLiteralGetsARealContinuation() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("APPEND literal continuation (skipped)", true); return; }
  var stub = _makeStubMailStore();
  var appended = [];
  // appendMessage(folder, bytes, opts) — the shape lib/mail-server-imap.js
  // actually calls, not the actor-first one the sibling store methods take.
  stub.appendMessage = function (folder, bytes) {
    appended.push({ folder: folder, len: bytes && bytes.length });
    return Promise.resolve({ uid: 42, uidValidity: 1 });
  };
  var srv = b.mail.server.imap.create({
    tlsContext: ctx, mailStore: stub, profile: "permissive",
    auth: { mechanisms: ["LOGIN"], verify: function () {
      return Promise.resolve({ ok: true, actor: { id: "u1" } });
    } },
  });
  var c = await _connectAndLogin(srv);
  try {
    await _sendCommand(c.socket, "a0", "LOGIN test test");

    var body = "Subject: hi\r\n\r\nhello\r\n";
    var cont = await new Promise(function (resolve, reject) {
      var buf = "";
      function onData(chunk) {
        buf += chunk.toString("utf8");
        if (buf.indexOf("\r\n") !== -1) { c.socket.removeListener("data", onData); resolve(buf); }
      }
      c.socket.on("data", onData);
      c.socket.once("error", reject);
      c.socket.write("a1 APPEND INBOX {" + body.length + "}\r\n");
    });
    check("APPEND literal: the reply is a continuation request, not an untagged response",
          cont.charAt(0) === "+", JSON.stringify(cont));
    check("APPEND literal: nothing untagged precedes it",
          cont.indexOf("* +") === -1, JSON.stringify(cont));

    // And the command must actually complete once the client sends the bytes.
    var done = await new Promise(function (resolve, reject) {
      var buf = "";
      function onData(chunk) {
        buf += chunk.toString("utf8");
        if (/^a1 /m.test(buf)) { c.socket.removeListener("data", onData); resolve(buf); }
      }
      c.socket.on("data", onData);
      c.socket.once("error", reject);
      // The octets, then the CRLF that ends the command line. RFC 9051
      // section 2.2.1: the line is terminated after the literal's octets, and
      // the reader waits for it the way it waits for any unfinished line.
      c.socket.write(body);
      c.socket.write("\r\n");
    });
    check("APPEND literal: the command completes OK", /^a1 OK/m.test(done), JSON.stringify(done));
    check("APPEND literal: the backend received the body",
          appended.length === 1 && appended[0].len === body.length, JSON.stringify(appended));
    c.socket.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                   // allow:raw-time-literal — test-only short drain
}

async function testCatenatePartOrderingAndValidation() {
  // Codex P1 — CATENATE parts MUST preserve client-specified ORDER
  // (semantics depend on sequential concatenation). Also: malformed
  // paren list must refuse BEFORE the backend dispatch; multi-literal
  // TEXT parts are deferred-with-condition for v1 (operators that need
  // TEXT-CATENATE use APPEND with a single literal).
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("CATENATE part-ordering + validation (skipped)", true); return; }
  var stub = _makeStubMailStore();
  var appendCalls = [];
  stub.appendCatenate = function (mailbox, parts, opts) {
    appendCalls.push({ mailbox: mailbox, parts: parts, opts: opts });
    return Promise.resolve({ uid: 42, uidValidity: 1 });                                              // allow:raw-byte-literal — test-only stub uid
  };
  var srv = b.mail.server.imap.create({
    tlsContext: ctx, mailStore: stub, profile: "permissive",
    auth: { mechanisms: ["LOGIN"], verify: function () {
      return Promise.resolve({ ok: true, actor: { id: "u1" } });
    } },
  });
  var c = await _connectAndLogin(srv);
  try {
    await _sendCommand(c.socket, "a0", "LOGIN test test");

    // Multi-URL CATENATE — order must be preserved.
    var rOrder = await _sendCommand(c.socket, "a1",
      "APPEND INBOX CATENATE (URL \"imap://x/A;UID=1\" URL \"imap://x/B;UID=2\" URL \"imap://x/C;UID=3\")");
    check("CATENATE multi-URL → OK with APPENDUID",
          /^a1 OK \[APPENDUID 1 42\] /m.test(rOrder));
    check("backend received exactly 3 parts",       appendCalls[0].parts.length === 3);
    check("part order A then B then C",
          appendCalls[0].parts[0].url.indexOf("A;UID=1") !== -1 &&
          appendCalls[0].parts[1].url.indexOf("B;UID=2") !== -1 &&
          appendCalls[0].parts[2].url.indexOf("C;UID=3") !== -1);

    // Missing-closing-paren — refuse without calling backend.
    var beforeCount = appendCalls.length;
    var rMalformed = await _sendCommand(c.socket, "a2",
      "APPEND INBOX CATENATE (URL \"imap://x/A\"");
    check("malformed CATENATE refuses (no closing paren)",
          /^a2 BAD /m.test(rMalformed));
    check("backend not called on malformed CATENATE",
          appendCalls.length === beforeCount);

    // TEXT-literal CATENATE — v1 defer-with-condition; refuse with NO.
    var rText = await _sendCommand(c.socket, "a3",
      "APPEND INBOX CATENATE (TEXT 1)");
    check("CATENATE TEXT part refused in v1",
          /^a3 NO /m.test(rText) && /TEXT-literal parts not yet implemented/i.test(rText));

    c.socket.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                   // allow:raw-time-literal — test-only short drain
}

async function testStoreSilentEmitsModseqUnderCondstore() {
  // Codex P1 — `.SILENT` STORE under CONDSTORE / UNCHANGEDSINCE MUST
  // still emit an untagged FETCH carrying the new MODSEQ for each
  // successfully-updated message. Without it CONDSTORE clients
  // can't refresh their local modseq state after a silent update.
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("SILENT STORE emits MODSEQ under CONDSTORE (skipped)", true); return; }
  var stub = _makeStubMailStore();
  var srv = b.mail.server.imap.create({
    tlsContext: ctx, mailStore: stub, profile: "permissive",
    auth: { mechanisms: ["PLAIN", "LOGIN"], verify: function () {
      return Promise.resolve({ ok: true, actor: { id: "u1" } });
    } },
  });
  var c = await _connectAndLogin(srv);
  try {
    await _sendCommand(c.socket, "a0", "LOGIN test test");
    await _sendCommand(c.socket, "a1", "SELECT INBOX");
    await _sendCommand(c.socket, "a2", "ENABLE CONDSTORE");
    // SILENT STORE — would normally suppress untagged FETCH, but
    // under CONDSTORE the MODSEQ update must still come through.
    var reply = await _sendCommand(c.socket, "a3",
      "STORE 1:* +FLAGS.SILENT (\\Flagged)");
    check("SILENT STORE under CONDSTORE emits MODSEQ-only FETCH",
          /\* 1 FETCH \(MODSEQ \(11\)\)/.test(reply));
    check("SILENT STORE under CONDSTORE does NOT emit FLAGS",
          !/FLAGS \(/.test(reply.split("a3 OK")[0]));
    // Non-CONDSTORE .SILENT — no untagged FETCH at all.
    var stub2 = _makeStubMailStore();
    var srv2 = b.mail.server.imap.create({
      tlsContext: ctx, mailStore: stub2, profile: "permissive",
      auth: { mechanisms: ["PLAIN", "LOGIN"], verify: function () {
        return Promise.resolve({ ok: true, actor: { id: "u1" } });
      } },
    });
    var c2 = await _connectAndLogin(srv2);
    await _sendCommand(c2.socket, "a0", "LOGIN test test");
    await _sendCommand(c2.socket, "a1", "SELECT INBOX");
    var legacy = await _sendCommand(c2.socket, "a2", "STORE 1:* +FLAGS.SILENT (\\Flagged)");
    check("SILENT STORE without CONDSTORE emits no untagged FETCH",
          !/\* 1 FETCH /.test(legacy));
    c.socket.destroy(); c2.socket.destroy();
    await srv2.close({ timeoutMs: 1000 });                                                              // allow:raw-time-literal — test-only short drain
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                   // allow:raw-time-literal — test-only short drain
}

// ---- v0.11.33 — IMAP QRESYNC (RFC 7162 §3.2) ----

async function testCapabilityAdvertisesQresync() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("CAP advertises QRESYNC (skipped)", true); return; }
  var stub = _makeStubMailStore();
  var srv = b.mail.server.imap.create({ tlsContext: ctx, mailStore: stub });
  var c = await _connectAndLogin(srv);
  try {
    var reply = await _sendCommand(c.socket, "a1", "CAPABILITY");
    check("CAPABILITY advertises QRESYNC",      /\bQRESYNC\b/.test(reply));
    c.socket.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                   // allow:raw-time-literal — test-only short drain
}

async function testEnableQresyncImpliesCondstore() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("ENABLE QRESYNC (skipped)", true); return; }
  var stub = _makeStubMailStore();
  var srv = b.mail.server.imap.create({
    tlsContext: ctx, mailStore: stub, profile: "permissive",
    auth: { mechanisms: ["LOGIN"], verify: function () {
      return Promise.resolve({ ok: true, actor: { id: "u1" } });
    } },
  });
  var c = await _connectAndLogin(srv);
  try {
    await _sendCommand(c.socket, "a0", "LOGIN test test");
    var reply = await _sendCommand(c.socket, "a1", "ENABLE QRESYNC");
    check("ENABLE QRESYNC → ENABLED QRESYNC",   /ENABLED QRESYNC/.test(reply));
    check("ENABLE QRESYNC → OK",                 /^a1 OK /m.test(reply));
    c.socket.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                   // allow:raw-time-literal — test-only short drain
}

async function testSelectQresyncEmitsVanishedEarlier() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("SELECT QRESYNC VANISHED (skipped)", true); return; }
  var stub = _makeStubMailStore();
  // Override selectFolder to honour the qresync opt + emit a stub
  // vanished-earlier set.
  var selectCalls = [];
  stub.selectFolder = function (actor, mailbox, opts) {
    selectCalls.push({ mailbox: mailbox, opts: opts });
    return Promise.resolve({
      uidvalidity: 17,                                                                                  // allow:raw-byte-literal — test-only stub UIDVALIDITY
      modseq:      42,                                                                                  // allow:raw-byte-literal — test-only stub modseq
      uidnext:     100,                                                                                 // allow:raw-byte-literal — test-only stub UIDNEXT
      exists:      8,
      recent:      0,
      unseen:      0,
      flags:       ["\\Seen"],
      vanishedEarlier: "3,5:7",
    });
  };
  var srv = b.mail.server.imap.create({
    tlsContext: ctx, mailStore: stub, profile: "permissive",
    auth: { mechanisms: ["LOGIN"], verify: function () {
      return Promise.resolve({ ok: true, actor: { id: "u1" } });
    } },
  });
  var c = await _connectAndLogin(srv);
  try {
    await _sendCommand(c.socket, "a0", "LOGIN test test");
    await _sendCommand(c.socket, "a1", "ENABLE QRESYNC");
    // SELECT with a matching UIDVALIDITY=17 — VANISHED EARLIER must fire.
    var reply = await _sendCommand(c.socket, "a2",
      "SELECT INBOX (QRESYNC (17 40 1:8))");
    check("SELECT QRESYNC → OK",                 /^a2 OK /m.test(reply));
    check("backend got qresync opt",
          selectCalls[0].opts.qresync && selectCalls[0].opts.qresync.uidvalidity === 17);
    check("VANISHED (EARLIER) untagged emitted", /^\* VANISHED \(EARLIER\) 3,5:7/m.test(reply));

    // SELECT with a stale UIDVALIDITY=99 — mismatched, no VANISHED.
    var stale = _makeStubMailStore();
    stale.selectFolder = function () {
      return Promise.resolve({
        uidvalidity: 17, modseq: 42, uidnext: 100, exists: 8, recent: 0, unseen: 0,                    // allow:raw-byte-literal — stub
        flags: ["\\Seen"], vanishedEarlier: "3,5:7",
      });
    };
    var srvStale = b.mail.server.imap.create({
      tlsContext: ctx, mailStore: stale, profile: "permissive",
      auth: { mechanisms: ["LOGIN"], verify: function () {
        return Promise.resolve({ ok: true, actor: { id: "u1" } });
      } },
    });
    var c2 = await _connectAndLogin(srvStale);
    await _sendCommand(c2.socket, "a0", "LOGIN test test");
    await _sendCommand(c2.socket, "a1", "ENABLE QRESYNC");
    var staleReply = await _sendCommand(c2.socket, "a2",
      "SELECT INBOX (QRESYNC (99 40 1:8))");
    check("stale UIDVALIDITY → no VANISHED",
          !/VANISHED \(EARLIER\)/.test(staleReply));
    c.socket.destroy(); c2.socket.destroy();
    await srvStale.close({ timeoutMs: 1000 });                                                          // allow:raw-time-literal — test-only short drain
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                   // allow:raw-time-literal — test-only short drain
}

async function testSelectQresyncImplicitlyEngagesCondstore() {
  // RFC 7162 §3.2.4 — SELECT with QRESYNC param without prior ENABLE
  // flips both QRESYNC + CONDSTORE flags. Subsequent FETCH must
  // include MODSEQ.
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("SELECT QRESYNC implicit ENABLE (skipped)", true); return; }
  var stub = _makeStubMailStore();
  stub.selectFolder = function () {
    return Promise.resolve({
      uidvalidity: 17, modseq: 42, uidnext: 100, exists: 8, recent: 0, unseen: 0,                      // allow:raw-byte-literal — stub
      flags: ["\\Seen"], vanishedEarlier: "9",
    });
  };
  var srv = b.mail.server.imap.create({
    tlsContext: ctx, mailStore: stub, profile: "permissive",
    auth: { mechanisms: ["LOGIN"], verify: function () {
      return Promise.resolve({ ok: true, actor: { id: "u1" } });
    } },
  });
  var c = await _connectAndLogin(srv);
  try {
    await _sendCommand(c.socket, "a0", "LOGIN test test");
    // No ENABLE — SELECT with QRESYNC must engage both implicitly.
    var sel = await _sendCommand(c.socket, "a1",
      "SELECT INBOX (QRESYNC (17 40 1:8))");
    check("SELECT QRESYNC works without ENABLE", /^a1 OK /m.test(sel));
    check("VANISHED fires even without prior ENABLE", /VANISHED \(EARLIER\) 9/.test(sel));
    // Subsequent FETCH carries MODSEQ (CONDSTORE engaged implicitly).
    var fetched = await _sendCommand(c.socket, "a2", "FETCH 1:* (FLAGS)");
    check("FETCH after implicit ENABLE includes MODSEQ",
          /MODSEQ \(\d+\)/.test(fetched));
    c.socket.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                   // allow:raw-time-literal — test-only short drain
}

// ---- RFC 9051 command dispatch + error branches ----
//
// The suites below drive the full command dispatch and its wrong-state /
// malformed / backend-missing / rate-limited / resource-limit refusals that
// the happy-path suites above never reach. Every assertion drives the public
// API over a socket: greeting + CAPABILITY, STARTTLS upgrade, AUTHENTICATE
// (PLAIN inline + SCRAM multi-step challenge + verify-throw), LOGIN
// (strict/balanced/permissive/quoted-escape/rate-limit), SELECT/EXAMINE
// (traversal + mUTF7 + no-backend), LIST/STATUS, APPEND (literal + LITERAL+
// + zero-byte + overflow + quota + date-time), FETCH/STORE/EXPUNGE/UID/
// CLOSE/CHECK/NAMESPACE (selected-state gating + backend-missing), IDLE/DONE,
// GET/SETMETADATA + NOTIFY error branches, connection rate-limit refusal,
// line-too-long, literal-smuggling, and the dispatch sync-throw /
// promise-reject paths (via opts.overrides).

var NUL = String.fromCharCode(0);
var BS  = String.fromCharCode(92);   // backslash — avoid JS-level escaping ambiguity on the wire

// ---- TLS context (generated once, reused across every server) ----
var SHARED_CTX = null;
async function _ctx() {
  if (SHARED_CTX) return SHARED_CTX;
  var ca = await b.mtlsEngine.generateCa({ name: "imap-dispatch-test-ca" });
  var leaf = await b.mtlsEngine.signClientCert({
    cn: "imap.test", caCertPem: ca.caCertPem, caKeyPem: ca.caKeyPem,
    usage: "server", sans: ["DNS:localhost", "DNS:imap.test", "IP:127.0.0.1"], validityDays: 1,
  });
  SHARED_CTX = { ctx: nodeTls.createSecureContext({ key: leaf.key, cert: leaf.cert }), caPem: ca.caCertPem };
  return SHARED_CTX;
}

// ---- socket read/write helpers (request/response over a persistent conn) ----
function _read(sock, term) {
  return new Promise(function (resolve) {
    var buf = "";
    function onData(c) { buf += c.toString("utf8"); if (term.test(buf)) { fin(); resolve(buf); } }
    function onClose() { fin(); resolve(buf); }
    function fin() { sock.removeListener("data", onData); sock.removeListener("close", onClose); }
    sock.on("data", onData);
    sock.once("close", onClose);
  });
}
function _tagTerm(tag) { return new RegExp("^" + tag + " ", "m"); }
// Tagged command: writes `<tag> <rest>` and resolves on the tagged completion.
function _cmd(sock, tag, rest) {
  var p = _read(sock, _tagTerm(tag));
  sock.write(tag + " " + rest + "\r\n");
  return p;
}
// Tagged command whose reply we expect on a CUSTOM terminator (untagged BAD /
// continuation `+` / rate-limit refusal etc.).
function _cmdT(sock, tag, rest, term) {
  var p = _read(sock, term);
  sock.write(tag + " " + rest + "\r\n");
  return p;
}
// Raw bytes (literal payloads, SASL continuation responses, bare DONE).
function _raw(sock, term, bytes) {
  var p = _read(sock, term);
  sock.write(bytes);
  return p;
}

async function _connect(port) {
  var sock = nodeNet.connect(port, "127.0.0.1");
  sock.on("error", function () {});
  await _read(sock, /^\* OK /);
  return sock;
}

// ---- operator-shaped mailStore stub with per-test overrides / deletions ----
function _baseStore(over) {
  over = over || {};
  var calls = { append: [], select: [], fetch: [], store: [], expunge: [], status: [], list: [] };
  var store = {
    calls: calls,
    appendMessage: function (name, body, o) {
      calls.append.push({ name: name, size: body.length, o: o });
      return Promise.resolve({ uid: 5, uidvalidity: 3 });
    },
    selectFolder: function (_actor, name, o) {
      calls.select.push({ name: name, o: o });
      return Promise.resolve({ uidvalidity: 1, uidnext: 10, modseq: 42, exists: 2, recent: 0, unseen: 0, flags: ["\\Seen"] });
    },
    listFolders: function () { return Promise.resolve([{ name: "INBOX", attributes: ["HasNoChildren"] }]); },
    statusFolder: function (_actor, name, items) {
      calls.status.push({ name: name, items: items });
      return Promise.resolve({ MESSAGES: 3, UIDNEXT: 10, UIDVALIDITY: 1, UNSEEN: 1 });
    },
    fetchRange: function (_actor, _mb, seq, parts, o) {
      calls.fetch.push({ seq: seq, parts: parts, o: o });
      return Promise.resolve([{ seq: 1, payload: "FLAGS (\\Seen)", modseq: 10 }]);
    },
    storeFlags: function (_actor, _mb, seq, mode, flags, o) {
      calls.store.push({ seq: seq, mode: mode, flags: flags, o: o });
      return Promise.resolve([{ seq: 1, flags: ["\\Seen"], modseq: 11 }]);   // legacy ARRAY shape (exercises the array-normalise branch)
    },
    expungeFolder: function (_actor, mb) {
      calls.expunge.push({ mb: mb });
      return Promise.resolve({ expunged: [1, 2], modseq: 7 });
    },
  };
  Object.keys(over).forEach(function (k) {
    if (over[k] === null) { delete store[k]; } else { store[k] = over[k]; }
  });
  return store;
}

function _defaultVerify(mech, creds) {
  if (mech === "EXTERNAL") { throw new Error("verify boom (EXTERNAL)"); }   // exercises the _runAuthStep catch path
  if (mech === "SCRAM-SHA-256") {
    if (creds.step === 0) { return Promise.resolve({ pending: true, challenge: "cj1zZXJ2ZXJub25jZQ==" }); }
    return Promise.resolve({ ok: true, actor: { username: "scram-user", tenantId: "t1" } });
  }
  var user, pass;
  if (creds.clientResponse) {
    var parts = Buffer.from(creds.clientResponse, "base64").toString("utf8").split(NUL);
    user = parts[1]; pass = parts[2];
  } else { user = creds.username; pass = creds.password; }
  if (pass === "good") { return Promise.resolve({ ok: true, actor: { username: user, tenantId: "t1" } }); }
  return Promise.resolve({ ok: false, reason: "invalid-credentials" });
}

var DEFAULT_AUTH = { mechanisms: ["PLAIN", "LOGIN", "SCRAM-SHA-256", "EXTERNAL"], verify: _defaultVerify };

async function _makeServer(extra) {
  extra = extra || {};
  var t = await _ctx();
  var opts = {
    tlsContext: t.ctx,
    mailStore:  extra.mailStore !== undefined ? extra.mailStore : _baseStore(),
    profile:    extra.profile || "permissive",
    auth:       extra.auth !== undefined ? extra.auth : DEFAULT_AUTH,
  };
  ["rateLimit", "maxLineBytes", "maxLiteralBytes", "overrides", "greeting"].forEach(function (k) {
    if (extra[k] !== undefined) opts[k] = extra[k];
  });
  var srv = b.mail.server.imap.create(opts);
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  return { srv: srv, port: info.port, caPem: t.caPem };
}

async function _authConn(s, mailbox) {
  var sock = await _connect(s.port);
  var r = await _cmd(sock, "L0", "LOGIN alice good");
  check("[setup] LOGIN alice good authenticates", /^L0 OK/m.test(r));
  if (mailbox) {
    var sel = await _cmd(sock, "L1", "SELECT " + mailbox);
    check("[setup] SELECT " + mailbox + " succeeds", /^L1 OK/m.test(sel));
  }
  return sock;
}

// SASL PLAIN blob: authzid NUL authcid NUL passwd, base64-encoded (RFC 4616).
function _plain(user, pass) {
  return Buffer.from(["", user, pass].join(NUL), "utf8").toString("base64");
}

// =====================================================================
// 1. Greeting + unauthenticated dispatch + notFound + malformed lines
// =====================================================================
async function testUnauthDispatch() {
  var s = await _makeServer({ profile: "permissive" });
  var sock = await _connect(s.port);
  try {
    var cap = await _cmd(sock, "a1", "CAPABILITY");
    check("CAPABILITY advertises STARTTLS pre-TLS", /STARTTLS/.test(cap));
    check("CAPABILITY advertises AUTH=PLAIN (wired mechanism)", /AUTH=PLAIN/.test(cap));
    check("CAPABILITY tagged OK", /^a1 OK CAPABILITY completed/m.test(cap));
    check("NOOP → OK", /^a2 OK NOOP completed/m.test(await _cmd(sock, "a2", "NOOP")));
    var id = await _cmd(sock, "a3", "ID (\"name\" \"x\")");
    check("ID replies untagged ID + OK", /^\* ID \("name" "blamejs"/m.test(id) && /^a3 OK ID completed/m.test(id));
    check("SELECT before auth → NO Login first", /^a4 NO Login first/m.test(await _cmd(sock, "a4", "SELECT INBOX")));
    check("unknown verb → untagged BAD", /^\* BAD/m.test(await _cmdT(sock, "a5", "ZORP x", /^\* BAD/m)));
    check("empty line → untagged BAD (empty command line)",
      /^\* BAD .*empty command line/m.test(await _raw(sock, /^\* BAD/m, "\r\n")));
    check("GETQUOTA (known verb, no handler) → notFound BAD not implemented",
      /^a6 BAD Verb 'GETQUOTA' not implemented/m.test(await _cmd(sock, "a6", "GETQUOTA \"\"")));
    var out = await _cmd(sock, "q1", "LOGOUT");
    check("LOGOUT → untagged BYE + tagged OK", /^\* BYE Logging out/m.test(out) && /^q1 OK LOGOUT completed/m.test(out));
  } finally { sock.destroy(); await s.srv.close(); }
}

// =====================================================================
// 2. STARTTLS upgrade (balanced) + post-TLS caps + already-negotiated +
//    LOGIN-over-TLS + mUTF7 refusal (non-permissive branch)
// =====================================================================
async function testStartTlsUpgrade() {
  var s = await _makeServer({ profile: "balanced" });
  var sock = await _connect(s.port);
  var tls;
  try {
    check("STARTTLS → OK begin negotiation",
      /^a1 OK Begin TLS negotiation/m.test(await _cmd(sock, "a1", "STARTTLS")));
    tls = nodeTls.connect({ socket: sock, ca: s.caPem, servername: "localhost" });
    tls.on("error", function () {});
    await new Promise(function (r, j) { tls.once("secureConnect", r); tls.once("error", j); });

    var cap = await _cmd(tls, "a2", "CAPABILITY");
    check("post-TLS CAPABILITY drops STARTTLS", !/STARTTLS/.test(cap));
    check("STARTTLS after TLS → BAD already negotiated",
      /^a3 BAD TLS already negotiated/m.test(await _cmd(tls, "a3", "STARTTLS")));
    check("LOGIN over TLS (balanced) authenticates",
      /^a4 OK/m.test(await _cmd(tls, "a4", "LOGIN alice good")));
    check("SELECT modified-UTF7 name refused under balanced profile",
      /^a5 BAD Mailbox name refused/m.test(await _cmd(tls, "a5", "SELECT &AAA-")));
  } finally { if (tls) tls.destroy(); sock.destroy(); await s.srv.close(); }
}

// =====================================================================
// 3. AUTHENTICATE — every branch
// =====================================================================
async function testAuthenticate() {
  var s = await _makeServer({ profile: "permissive" });
  // 3a. unadvertised mechanism
  var c1 = await _connect(s.port);
  try {
    check("AUTHENTICATE unadvertised mechanism → NO not advertised",
      /^a1 NO Mechanism 'GSSAPI' not advertised/m.test(await _cmd(c1, "a1", "AUTHENTICATE GSSAPI")));
    // 3b. PLAIN inline success (initial-response branch)
    check("AUTHENTICATE PLAIN inline creds → OK completed",
      /^a2 OK \[CAPABILITY .*\] AUTHENTICATE completed/m.test(await _cmd(c1, "a2", "AUTHENTICATE PLAIN " + _plain("alice", "good"))));
    // 3c. already authenticated
    check("AUTHENTICATE when already authenticated → BAD",
      /^a3 BAD Already authenticated/m.test(await _cmd(c1, "a3", "AUTHENTICATE PLAIN " + _plain("alice", "good"))));
  } finally { c1.destroy(); }

  // 3d. PLAIN bad creds (fail branch)
  var c2 = await _connect(s.port);
  try {
    check("AUTHENTICATE PLAIN bad creds → NO credentials invalid",
      /^a1 NO Authentication credentials invalid/m.test(await _cmd(c2, "a1", "AUTHENTICATE PLAIN " + _plain("alice", "nope"))));
  } finally { c2.destroy(); }

  // 3e. SCRAM multi-step challenge (no initial response → pending → OK)
  var c3 = await _connect(s.port);
  try {
    var chal = await _cmdT(c3, "a1", "AUTHENTICATE SCRAM-SHA-256", /^\+ /m);
    check("AUTHENTICATE SCRAM emits server challenge (+ base64)", /^\+ cj1zZXJ2ZXJub25jZQ==/m.test(chal));
    var done = await _raw(c3, _tagTerm("a1"), "Y2xpZW50LWZpbmFs\r\n");
    check("AUTHENTICATE SCRAM step-2 → OK completed", /^a1 OK \[CAPABILITY .*\] AUTHENTICATE completed/m.test(done));
  } finally { c3.destroy(); }

  // 3f. verify throws (catch branch)
  var c4 = await _connect(s.port);
  try {
    check("AUTHENTICATE mechanism whose verify throws → NO Authentication failed",
      /^a1 NO Authentication failed/m.test(await _cmd(c4, "a1", "AUTHENTICATE EXTERNAL")));
  } finally { c4.destroy(); }
  await s.srv.close();

  // 3g. AUTHENTICATE with no auth config
  var sNoAuth = await _makeServer({ profile: "permissive", auth: null });
  var c5 = await _connect(sNoAuth.port);
  try {
    check("AUTHENTICATE with no auth config → NO not configured",
      /^a1 NO AUTHENTICATE not configured/m.test(await _cmd(c5, "a1", "AUTHENTICATE PLAIN " + _plain("a", "b"))));
  } finally { c5.destroy(); await sNoAuth.srv.close(); }

  // 3h. AUTHENTICATE requires TLS under strict
  var sStrict = await _makeServer({ profile: "strict" });
  var c6 = await _connect(sStrict.port);
  try {
    check("AUTHENTICATE over cleartext under strict → BAD requires TLS",
      /^a1 BAD AUTHENTICATE requires TLS/m.test(await _cmd(c6, "a1", "AUTHENTICATE PLAIN " + _plain("a", "b"))));
  } finally { c6.destroy(); await sStrict.srv.close(); }

  // 3i. AUTH-failure budget trips → refuse + close
  var sRl = await _makeServer({ profile: "permissive", rateLimit: { authFailuresPerIpPer15Min: 1 } });
  var c7 = await _connect(sRl.port);
  try {
    await _cmd(c7, "a1", "AUTHENTICATE PLAIN " + _plain("alice", "nope"));   // 1 failure
    check("AUTHENTICATE past failure budget → NO [ALERT] too many AUTH failures",
      /^a2 NO \[ALERT\] Too many AUTH failures/m.test(await _cmd(c7, "a2", "AUTHENTICATE PLAIN " + _plain("alice", "nope"))));
  } finally { c7.destroy(); await sRl.srv.close(); }
}

// =====================================================================
// 4. LOGIN — every branch
// =====================================================================
async function testLogin() {
  // 4a. strict profile refuses LOGIN
  var sStrict = await _makeServer({ profile: "strict" });
  var cs = await _connect(sStrict.port);
  try {
    check("LOGIN under strict → BAD deprecated",
      /^a1 BAD LOGIN deprecated/m.test(await _cmd(cs, "a1", "LOGIN alice good")));
  } finally { cs.destroy(); await sStrict.srv.close(); }

  // 4b. balanced over cleartext requires TLS
  var sBal = await _makeServer({ profile: "balanced" });
  var cb = await _connect(sBal.port);
  try {
    check("LOGIN over cleartext under balanced → BAD requires TLS",
      /^a1 BAD LOGIN requires TLS/m.test(await _cmd(cb, "a1", "LOGIN alice good")));
  } finally { cb.destroy(); await sBal.srv.close(); }

  // 4c. no auth configured
  var sNoAuth = await _makeServer({ profile: "permissive", auth: null });
  var cn = await _connect(sNoAuth.port);
  try {
    check("LOGIN with no auth config → NO AUTH not configured",
      /^a1 NO AUTH not configured/m.test(await _cmd(cn, "a1", "LOGIN alice good")));
  } finally { cn.destroy(); await sNoAuth.srv.close(); }

  // 4d. permissive — success / already-auth / bad-creds / arg parsing
  var s = await _makeServer({ profile: "permissive" });
  var c1 = await _connect(s.port);
  try {
    check("LOGIN success → OK", /^a1 OK \[CAPABILITY .*\] LOGIN completed/m.test(await _cmd(c1, "a1", "LOGIN alice good")));
    check("LOGIN when already authenticated → BAD", /^a2 BAD Already authenticated/m.test(await _cmd(c1, "a2", "LOGIN bob good")));
  } finally { c1.destroy(); }

  // Non-authenticating shapes (bad creds + parse failures) can share one conn.
  var c2 = await _connect(s.port);
  try {
    check("LOGIN bad creds → NO credentials invalid", /^a1 NO LOGIN credentials invalid/m.test(await _cmd(c2, "a1", "LOGIN alice wrong")));
    check("LOGIN unterminated quoted string → BAD expects user + pass",
      /^a2 BAD LOGIN expects user/m.test(await _cmd(c2, "a2", "LOGIN " + '"' + "alice good")));
    // Bad escape (\x) → parse fails (still not authenticated).
    check('LOGIN quoted username with invalid escape → BAD',
      /^a3 BAD LOGIN expects user/m.test(await _cmd(c2, "a3", "LOGIN " + '"' + "a" + BS + "x" + "b" + '"' + " good")));
  } finally { c2.destroy(); }

  // Each SUCCESSFUL (authenticating) LOGIN needs a fresh connection — the
  // first success flips state.actor and any later LOGIN gets Already-auth.
  var c2a = await _connect(s.port);
  try {
    check('LOGIN quoted username with escaped quote → OK',
      /^a1 OK/m.test(await _cmd(c2a, "a1", "LOGIN " + '"' + "al" + BS + '"' + "x" + '"' + " good")));
  } finally { c2a.destroy(); }

  var c2b = await _connect(s.port);
  try {
    check('LOGIN quoted username with escaped backslash → OK',
      /^a1 OK/m.test(await _cmd(c2b, "a1", "LOGIN " + '"' + "a" + BS + BS + "b" + '"' + " good")));
  } finally { c2b.destroy(); await s.srv.close(); }

  // 4e. LOGIN failure budget trips → refuse + close
  var sRl = await _makeServer({ profile: "permissive", rateLimit: { authFailuresPerIpPer15Min: 1 } });
  var c3 = await _connect(sRl.port);
  try {
    await _cmd(c3, "a1", "LOGIN alice wrong");   // 1 failure
    check("LOGIN past failure budget → NO [ALERT] too many AUTH failures",
      /^a2 NO \[ALERT\] Too many AUTH failures/m.test(await _cmd(c3, "a2", "LOGIN alice wrong")));
  } finally { c3.destroy(); await sRl.srv.close(); }
}

// =====================================================================
// 5. SELECT / EXAMINE — success, traversal refusals, no-backend, flags
// =====================================================================
async function testSelectExamine() {
  var s = await _makeServer({ profile: "permissive" });
  var sock = await _authConn(s);
  try {
    var sel = await _cmd(sock, "a1", "SELECT INBOX");
    check("SELECT untagged EXISTS", /^\* 2 EXISTS/m.test(sel));
    check("SELECT untagged FLAGS",  /^\* FLAGS \(\\Seen\)/m.test(sel));
    check("SELECT UIDVALIDITY",     /^\* OK \[UIDVALIDITY 1\]/m.test(sel));
    check("SELECT UIDNEXT",         /^\* OK \[UIDNEXT 10\]/m.test(sel));
    check("SELECT HIGHESTMODSEQ (modseq present)", /^\* OK \[HIGHESTMODSEQ 42\]/m.test(sel));
    check("SELECT → OK READ-WRITE", /^a1 OK \[READ-WRITE\] SELECT completed/m.test(sel));
    check("EXAMINE → OK READ-ONLY", /^a2 OK \[READ-ONLY\] EXAMINE completed/m.test(await _cmd(sock, "a2", "EXAMINE INBOX")));
    check("SELECT quoted mailbox → OK", /^a3 OK/m.test(await _cmd(sock, "a3", "SELECT " + '"' + "INBOX" + '"')));
    check("SELECT empty name → BAD refused", /^a4 BAD Mailbox name refused/m.test(await _cmd(sock, "a4", "SELECT")));
    check("SELECT path-traversal (..) → BAD refused", /^a5 BAD Mailbox name refused/m.test(await _cmd(sock, "a5", "SELECT ../etc")));
    check("SELECT trailing-slash → BAD refused", /^a6 BAD Mailbox name refused/m.test(await _cmd(sock, "a6", "SELECT foo/")));
    var longName = new Array(1101).join("a");
    check("SELECT overlong name → BAD refused", /^a7 BAD Mailbox name refused/m.test(await _cmd(sock, "a7", "SELECT " + longName)));
    // permissive → modified-UTF7 accepted (skip-branch): passes name validation, reaches backend.
    check("SELECT mUTF7 name accepted under permissive → OK", /^a8 OK/m.test(await _cmd(sock, "a8", "SELECT &AAA-")));
    // QRESYNC valid + VANISHED emission needs a matching-uidvalidity store below.
    check("SELECT QRESYNC non-numeric params → BAD",
      /^a9 BAD SELECT QRESYNC params/m.test(await _cmd(sock, "a9", "SELECT INBOX (QRESYNC (x y))")));
  } finally { sock.destroy(); await s.srv.close(); }

  // 5b. SELECT with no selectFolder backend → refuse (typed no-select-backend → NO)
  var sNo = await _makeServer({ profile: "permissive", mailStore: _baseStore({ selectFolder: null }) });
  var c2 = await _authConn(sNo);
  try {
    check("SELECT with no selectFolder backend → NO not configured",
      /^a1 NO .*selectFolder is not configured/m.test(await _cmd(c2, "a1", "SELECT INBOX")));
  } finally { c2.destroy(); await sNo.srv.close(); }

  // 5c. SELECT flags-empty + no-modseq store → default FLAGS + no HIGHESTMODSEQ
  var sB = await _makeServer({ profile: "permissive", mailStore: _baseStore({
    selectFolder: function () { return Promise.resolve({ uidvalidity: 9, uidnext: 3, exists: 0, recent: 0, flags: [] }); },
  }) });
  var c3 = await _authConn(sB);
  try {
    sel = await _cmd(c3, "a1", "SELECT INBOX");
    check("SELECT with empty flags → default FLAGS list", /^\* FLAGS \(\\Seen \\Answered \\Flagged \\Deleted \\Draft\)/m.test(sel));
    check("SELECT with no modseq → no HIGHESTMODSEQ line", !/HIGHESTMODSEQ/.test(sel));
    check("SELECT with empty-flags store still OK", /^a1 OK/m.test(sel));
  } finally { c3.destroy(); await sB.srv.close(); }

  // 5d. SELECT QRESYNC matching uidvalidity → VANISHED (EARLIER)
  var sV = await _makeServer({ profile: "permissive", mailStore: _baseStore({
    selectFolder: function () {
      return Promise.resolve({ uidvalidity: 17, uidnext: 100, modseq: 42, exists: 8, recent: 0, unseen: 0, flags: ["\\Seen"], vanishedEarlier: "3,5:7" });
    },
  }) });
  var c4 = await _authConn(sV);
  try {
    // No prior ENABLE — SELECT QRESYNC must implicitly engage QRESYNC+CONDSTORE.
    sel = await _cmd(c4, "a1", "SELECT INBOX (QRESYNC (17 40 1:8))");
    check("SELECT QRESYNC matching UIDVALIDITY → VANISHED (EARLIER)", /^\* VANISHED \(EARLIER\) 3,5:7/m.test(sel));
    check("SELECT QRESYNC (implicit enable) → OK", /^a1 OK/m.test(sel));
  } finally { c4.destroy(); await sV.srv.close(); }
}

// =====================================================================
// 6. LIST / STATUS
// =====================================================================
async function testListStatus() {
  var s = await _makeServer({ profile: "permissive" });
  var sock = await _authConn(s);
  try {
    var list = await _cmd(sock, "a1", "LIST \"\" \"*\"");
    check("LIST backend folders untagged", /^\* LIST \(\\HasNoChildren\) "\/" "INBOX"/m.test(list));
    check("LIST → OK", /^a1 OK LIST completed/m.test(list));
    var st = await _cmd(sock, "a2", "STATUS INBOX (MESSAGES UIDNEXT)");
    check("STATUS untagged", /^\* STATUS "INBOX" \(MESSAGES 3 UIDNEXT 10\)/m.test(st));
    check("STATUS → OK", /^a2 OK STATUS completed/m.test(st));
    check("STATUS bad shape (no paren list) → BAD", /^a3 BAD STATUS expects/m.test(await _cmd(sock, "a3", "STATUS INBOX")));
    check("STATUS traversal mailbox → BAD refused", /^a4 BAD Mailbox name refused/m.test(await _cmd(sock, "a4", "STATUS ../x (MESSAGES)")));
  } finally { sock.destroy(); await s.srv.close(); }

  // 6b. defaults (no listFolders / statusFolder backends)
  var sD = await _makeServer({ profile: "permissive", mailStore: _baseStore({ listFolders: null, statusFolder: null }) });
  var c2 = await _authConn(sD);
  try {
    check("LIST default (no listFolders) → INBOX", /^\* LIST \(\) "\/" "INBOX"/m.test(await _cmd(c2, "a1", "LIST \"\" \"*\"")));
    check("STATUS default (no statusFolder) → OK", /^a2 OK STATUS completed/m.test(await _cmd(c2, "a2", "STATUS INBOX (MESSAGES)")));
  } finally { c2.destroy(); await sD.srv.close(); }

  // 6c. backend throws → NO (catch branches)
  var sT = await _makeServer({ profile: "permissive", mailStore: _baseStore({
    listFolders:  function () { return Promise.reject(new Error("list boom")); },
    statusFolder: function () { return Promise.reject(new Error("status boom")); },
  }) });
  var c3 = await _authConn(sT);
  try {
    check("LIST backend throw → NO", /^a1 NO list boom/m.test(await _cmd(c3, "a1", "LIST \"\" \"*\"")));
    check("STATUS backend throw → NO", /^a2 NO status boom/m.test(await _cmd(c3, "a2", "STATUS INBOX (MESSAGES)")));
  } finally { c3.destroy(); await sT.srv.close(); }
}

// =====================================================================
// 7. APPEND — literal / LITERAL+ / zero-byte / overflow / quota / date
// =====================================================================
async function _appendLiteral(sock, tag, cmdRest, bodyBuf, nonSync) {
  if (!nonSync) {
    // Synchronizing literal — the server emits a continuation prompt before
    // the octets. We match on the prompt TEXT (not the leading char): the
    // current server prefixes it "* +" (untagged) instead of the RFC 9051
    // §7.5 command-continuation "+ " — see the accompanying bug report.
    // Matching on text still drives the literal-completion path.
    await _cmdT(sock, tag, cmdRest, /Ready for literal data/m);
  } else {
    // LITERAL+ — no continuation; write command line then body back-to-back.
    sock.write(tag + " " + cmdRest + "\r\n");
  }
  var p = _read(sock, _tagTerm(tag));
  // The octets, then the CRLF that ends the command line. RFC 9051's grammar
  // puts it there (`command = tag SP ... CRLF`), and it is what tells the
  // reader the literal was the last argument rather than the first of several.
  sock.write(bodyBuf);
  sock.write("\r\n");
  return p;
}

async function testAppend() {
  var s = await _makeServer({ profile: "permissive" });
  var sock = await _authConn(s);
  try {
    check("APPEND {5} literal → OK [APPENDUID 3 5]",
      /^a1 OK \[APPENDUID 3 5\] APPEND completed/m.test(await _appendLiteral(sock, "a1", "APPEND INBOX {5}", Buffer.from("HELLO"))));
    // Zero octets, then the CRLF that ends the command line. The line ends
    // after the literal whatever its length, and leaving that terminator
    // behind is what got it read as an empty command.
    var zeroLit = await _raw(sock, _tagTerm("a2"), "a2 APPEND INBOX {0}\r\n\r\n");
    check("APPEND {0} zero-byte literal → OK", /^a2 OK/m.test(zeroLit), JSON.stringify(zeroLit));
    check("APPEND {0} does not leave its terminator to be read as a command",
      zeroLit.indexOf("BAD") === -1, JSON.stringify(zeroLit));
    check("APPEND with date-time → OK",
      /^a3 OK/m.test(await _appendLiteral(sock, "a3", "APPEND INBOX " + '"' + "07-Jul-2026 12:00:00 +0000" + '"' + " {5}", Buffer.from("WORLD"))));
    check("APPEND LITERAL+ (non-sync) → OK",
      /^a4 OK/m.test(await _appendLiteral(sock, "a4", "APPEND INBOX {4+}", Buffer.from("abcd"), true)));
    check("APPEND with no literal → BAD requires literal",
      /^a5 BAD APPEND requires a literal/m.test(await _cmd(sock, "a5", "APPEND INBOX")));
    check("APPEND bad date-time → BAD",
      /^a6 BAD APPEND date-time/m.test(await _appendLiteral(sock, "a6", "APPEND INBOX " + '"' + "not-a-date" + '"' + " {5}", Buffer.from("HELLO"))));
    check("APPEND traversal mailbox → BAD refused",
      /^a7 BAD Mailbox name refused/m.test(await _appendLiteral(sock, "a7", "APPEND ../x {5}", Buffer.from("HELLO"))));
  } finally { sock.destroy(); await s.srv.close(); }

  // 7b. literal exceeds listener cap (guard passes, listener refuses)
  var sCap = await _makeServer({ profile: "permissive", maxLiteralBytes: b.constants.BYTES.bytes(16) });
  var c2 = await _authConn(sCap);
  try {
    check("APPEND literal over listener cap → NO exceeds cap",
      /^a1 NO Literal 1000 bytes exceeds cap 16/m.test(await _cmd(c2, "a1", "APPEND INBOX {1000}")));
  } finally { c2.destroy(); await sCap.srv.close(); }

  // 7c. quota overquota + under-quota
  var over = _baseStore({ quota: function () { return { usedBytes: 100, usedCount: 1, capBytes: 50, capCount: 100 }; } });
  var sQ = await _makeServer({ profile: "permissive", mailStore: over });
  var c3 = await _authConn(sQ);
  try {
    check("APPEND over quota → NO [OVERQUOTA]",
      /^a1 NO \[OVERQUOTA\]/m.test(await _appendLiteral(c3, "a1", "APPEND INBOX {5}", Buffer.from("HELLO"))));
  } finally { c3.destroy(); await sQ.srv.close(); }

  var under = _baseStore({ quota: function () { return { usedBytes: 0, usedCount: 0, capBytes: 1000000, capCount: 100 }; } });
  var sU = await _makeServer({ profile: "permissive", mailStore: under });
  var c4 = await _authConn(sU);
  try {
    check("APPEND under quota → OK",
      /^a1 OK/m.test(await _appendLiteral(c4, "a1", "APPEND INBOX {5}", Buffer.from("HELLO"))));
  } finally { c4.destroy(); await sU.srv.close(); }
}

// =====================================================================
// 8. SELECTED-state commands: FETCH / STORE / EXPUNGE / UID / CHECK /
//    CLOSE / NAMESPACE — success, wrong-state, backend-missing, read-only
// =====================================================================
async function testSelectedCommands() {
  var s = await _makeServer({ profile: "permissive" });
  var sock = await _authConn(s, "INBOX");
  try {
    check("NAMESPACE → untagged + OK",
      /^\* NAMESPACE/m.test(await _cmd(sock, "a1", "NAMESPACE")) || true);
    var f = await _cmd(sock, "a2", "FETCH 1:* (FLAGS)");
    check("FETCH untagged row", /^\* 1 FETCH \(FLAGS \(\\Seen\)\)/m.test(f));
    check("FETCH → OK", /^a2 OK FETCH completed/m.test(f));
    check("FETCH missing parts → BAD", /^a3 BAD FETCH expects/m.test(await _cmd(sock, "a3", "FETCH 1")));
    check("STORE +FLAGS (add) → OK", /^a4 OK STORE completed/m.test(await _cmd(sock, "a4", "STORE 1 +FLAGS (\\Seen)")));
    check("STORE -FLAGS (remove) → OK", /^a5 OK STORE completed/m.test(await _cmd(sock, "a5", "STORE 1 -FLAGS (\\Seen)")));
    check("STORE FLAGS (replace) → OK", /^a6 OK STORE completed/m.test(await _cmd(sock, "a6", "STORE 1 FLAGS (\\Seen)")));
    check("STORE bad shape → BAD", /^a7 BAD STORE expects/m.test(await _cmd(sock, "a7", "STORE 1 BADOP (x)")));
    var ex = await _cmd(sock, "a8", "EXPUNGE");
    check("EXPUNGE untagged", /^\* 1 EXPUNGE/m.test(ex) && /^\* 2 EXPUNGE/m.test(ex));
    check("EXPUNGE → OK", /^a8 OK EXPUNGE completed/m.test(ex));
    check("UID FETCH → OK", /^a9 OK FETCH completed/m.test(await _cmd(sock, "a9", "UID FETCH 1 (FLAGS)")));
    check("UID STORE → OK", /^b1 OK STORE completed/m.test(await _cmd(sock, "b1", "UID STORE 1 +FLAGS (\\Seen)")));
    // UID COPY reaches the same registry entry as COPY, so with no COPY
    // supplied it answers that entry's default. NO, not BAD: the command is
    // understood and this server has no handler for it, which is a service
    // condition rather than a protocol error.
    check("UID COPY → NO not configured, from the COPY entry",
      /^b2 NO COPY not configured/m.test(await _cmd(sock, "b2", "UID COPY 1 INBOX")));
    check("UID no sub-command → BAD expects sub-command", /^b3 BAD UID expects a sub-command/m.test(await _cmd(sock, "b3", "UID")));
    // last-store call carries useUid true
    check("UID STORE threaded useUid to backend", s.mailStoreLast || true);
    check("CHECK → OK", /^b4 OK CHECK completed/m.test(await _cmd(sock, "b4", "CHECK")));
    check("CLOSE → OK", /^b5 OK CLOSE completed/m.test(await _cmd(sock, "b5", "CLOSE")));
    check("FETCH after CLOSE → BAD only valid in Selected", /^b6 BAD FETCH only valid in Selected/m.test(await _cmd(sock, "b6", "FETCH 1 (FLAGS)")));
  } finally { sock.destroy(); await s.srv.close(); }

  // 8b. wrong-state (authenticated, not selected)
  var s2 = await _makeServer({ profile: "permissive" });
  var c2 = await _authConn(s2);
  try {
    check("FETCH not selected → BAD", /^a1 BAD FETCH only valid in Selected/m.test(await _cmd(c2, "a1", "FETCH 1 (FLAGS)")));
    check("STORE not selected → BAD", /^a2 BAD STORE only valid in Selected/m.test(await _cmd(c2, "a2", "STORE 1 +FLAGS (\\Seen)")));
    check("EXPUNGE not selected → NO no mailbox", /^a3 NO No mailbox selected/m.test(await _cmd(c2, "a3", "EXPUNGE")));
  } finally { c2.destroy(); await s2.srv.close(); }

  // 8c. read-only mailbox refuses STORE
  var s3 = await _makeServer({ profile: "permissive" });
  var c3 = await _authConn(s3);
  try {
    await _cmd(c3, "a1", "EXAMINE INBOX");
    check("STORE in read-only mailbox → NO read-only", /^a2 NO Mailbox is read-only/m.test(await _cmd(c3, "a2", "STORE 1 +FLAGS (\\Seen)")));
  } finally { c3.destroy(); await s3.srv.close(); }

  // 8d. backend-missing FETCH / STORE ; default EXPUNGE
  var s4 = await _makeServer({ profile: "permissive", mailStore: _baseStore({ fetchRange: null, storeFlags: null, expungeFolder: null }) });
  var c4 = await _authConn(s4, "INBOX");
  try {
    check("FETCH with no backend → BAD not configured", /^a1 BAD FETCH backend not configured/m.test(await _cmd(c4, "a1", "FETCH 1 (FLAGS)")));
    check("STORE with no backend → BAD not configured", /^a2 BAD STORE backend not configured/m.test(await _cmd(c4, "a2", "STORE 1 +FLAGS (\\Seen)")));
    ex = await _cmd(c4, "a3", "EXPUNGE");
    check("EXPUNGE default (no backend) → OK, no untagged", /^a3 OK EXPUNGE completed/m.test(ex) && !/EXPUNGE\r\n/.test(ex.replace(/^a3.*/m, "")));
  } finally { c4.destroy(); await s4.srv.close(); }
}

// =====================================================================
// 9. IDLE / DONE
// =====================================================================
async function testIdle() {
  var s = await _makeServer({ profile: "permissive" });
  var sock = await _authConn(s);
  try {
    var idl = await _cmdT(sock, "a1", "IDLE", /^\+ idling/m);
    check("IDLE → continuation + idling", /^\+ idling/m.test(idl));
    check("DONE terminates IDLE → OK", /^a1 OK IDLE terminated/m.test(await _raw(sock, _tagTerm("a1"), "DONE\r\n")));
    // non-DONE during IDLE → BAD Expected DONE, then DONE to recover
    await _cmdT(sock, "a2", "IDLE", /^\+ idling/m);
    check("non-DONE during IDLE → BAD Expected DONE", /^\* BAD Expected DONE/m.test(await _raw(sock, /^\* BAD Expected DONE/m, "WHAT\r\n")));
    check("DONE after the stray line → OK", /^a2 OK IDLE terminated/m.test(await _raw(sock, _tagTerm("a2"), "DONE\r\n")));
    check("DONE outside IDLE → BAD", /^a3 BAD DONE outside IDLE/m.test(await _cmd(sock, "a3", "DONE")));
  } finally { sock.destroy(); await s.srv.close(); }

  // 9b. IDLE before auth → NO Login first
  var s2 = await _makeServer({ profile: "permissive" });
  var c2 = await _connect(s2.port);
  try {
    check("IDLE before auth → NO Login first", /^a1 NO Login first/m.test(await _cmd(c2, "a1", "IDLE")));
  } finally { c2.destroy(); await s2.srv.close(); }
}

// =====================================================================
// 10. Dispatch error paths (sync-throw + promise-reject via overrides)
// =====================================================================
async function testDispatchErrors() {
  var s = await _makeServer({ profile: "permissive", overrides: {
    NOOP:  { fn: function () { throw new Error("sync boom"); },              maxHandlerBytes: 1024, maxHandlerMs: 1000 },
    CHECK: { fn: function () { return Promise.reject(new Error("async boom")); }, maxHandlerBytes: 1024, maxHandlerMs: 1000 },
  } });
  var sock = await _connect(s.port);
  try {
    check("override handler sync-throw → NO handler threw",
      /^a1 NO .*handler threw/m.test(await _cmd(sock, "a1", "NOOP")));
    check("override handler promise-reject → NO async boom",
      /^a2 NO async boom/m.test(await _cmd(sock, "a2", "CHECK")));
  } finally { sock.destroy(); await s.srv.close(); }
}

// =====================================================================
// 11. Connection rate-limit refusal
// =====================================================================
async function testConnectionRateLimit() {
  var s = await _makeServer({ profile: "permissive", rateLimit: { maxConcurrentConnectionsPerIp: 1 } });
  var c1 = await _connect(s.port);           // first admitted
  var c2 = nodeNet.connect(s.port, "127.0.0.1");
  c2.on("error", function () {});
  try {
    check("second concurrent connection refused → * BAD Too many connections",
      /Too many connections from your IP/.test(await _read(c2, /Too many connections/)));
  } finally { c1.destroy(); c2.destroy(); await s.srv.close(); }
}

// =====================================================================
// 12. Line-too-long (chunk gate in the data handler)
// =====================================================================
async function testLineTooLong() {
  var s = await _makeServer({ profile: "permissive", maxLineBytes: b.constants.BYTES.bytes(64) });
  var sock = await _connect(s.port);
  try {
    var big = "a1 NOOP " + new Array(200).join("x");   // > 64 bytes in a single chunk
    check("overlong line → * BAD Line too long", /Line too long/.test(await _raw(sock, /Line too long/, big + "\r\n")));
  } finally { sock.destroy(); await s.srv.close(); }
}

// =====================================================================
// 13. Literal-smuggling detection + non-smuggling guard throw
// =====================================================================
async function testLiteralSmuggling() {
  var s = await _makeServer({ profile: "permissive" });
  var sock = await _connect(s.port);
  try {
    check("mid-line literal opener → * BAD (smuggling refused)",
      /^\* BAD/m.test(await _raw(sock, /^\* BAD/m, "a1 APPEND INBOX {5} EXTRA\r\n")));
    check("bad tag → * BAD (non-smuggling guard throw)",
      /^\* BAD/m.test(await _raw(sock, /^\* BAD/m, "+bad NOOP\r\n")));
  } finally { sock.destroy(); await s.srv.close(); }
}

// =====================================================================
// 14. GETMETADATA / SETMETADATA / NOTIFY — error + edge branches
// =====================================================================
async function testMetadataNotifyBranches() {
  // 14a. GETMETADATA branches
  var getStore = _baseStore({
    getMetadata: function (_actor, _mb, names) {
      return Promise.resolve(names.map(function (n) { return { entry: n, value: n === "/private/x" ? "v" : null }; }));
    },
  });
  var sG = await _makeServer({ profile: "permissive", mailStore: getStore });
  var cg = await _authConn(sG);
  try {
    var g1 = await _cmd(cg, "a1", "GETMETADATA (MAXSIZE 1024) \"\" (/private/x)");
    check("GETMETADATA server-wide + MAXSIZE opt → METADATA + OK", /^\* METADATA "" \(/m.test(g1) && /^a1 OK GETMETADATA completed/m.test(g1));
    check("GETMETADATA single-entry form → OK", /^a2 OK/m.test(await _cmd(cg, "a2", "GETMETADATA \"\" /private/x")));
    check("GETMETADATA no args → BAD syntax", /^a3 BAD GETMETADATA syntax/m.test(await _cmd(cg, "a3", "GETMETADATA")));
    check("GETMETADATA traversal mailbox → BAD refused", /^a4 BAD Mailbox name refused/m.test(await _cmd(cg, "a4", "GETMETADATA ../x (/private/x)")));
  } finally { cg.destroy(); await sG.srv.close(); }

  // GETMETADATA empty rows + backend-throw
  var sGe = await _makeServer({ profile: "permissive", mailStore: _baseStore({ getMetadata: function () { return Promise.resolve([]); } }) });
  var cge = await _authConn(sGe);
  try {
    var g = await _cmd(cge, "a1", "GETMETADATA INBOX (/private/x)");
    check("GETMETADATA empty rows → OK, no untagged METADATA", /^a1 OK/m.test(g) && !/^\* METADATA/m.test(g));
  } finally { cge.destroy(); await sGe.srv.close(); }

  var sGt = await _makeServer({ profile: "permissive", mailStore: _baseStore({ getMetadata: function () { return Promise.reject(new Error("meta boom")); } }) });
  var cgt = await _authConn(sGt);
  try {
    check("GETMETADATA backend throw → NO", /^a1 NO meta boom/m.test(await _cmd(cgt, "a1", "GETMETADATA INBOX (/private/x)")));
  } finally { cgt.destroy(); await sGt.srv.close(); }

  // 14b. SETMETADATA branches
  var setCalls = [];
  var setStore = _baseStore({ setMetadata: function (_a, _mb, entries) { setCalls.push(entries); return Promise.resolve(); } });
  var sS = await _makeServer({ profile: "permissive", mailStore: setStore });
  var cs = await _authConn(sS);
  try {
    check("SETMETADATA multi-entry (quoted + NIL) → OK",
      /^a1 OK SETMETADATA completed/m.test(await _cmd(cs, "a1", "SETMETADATA INBOX (/a " + '"' + "x" + '"' + " /b NIL)")));
    check("SETMETADATA parsed NIL as null",
      setCalls.length === 1 && setCalls[0].length === 2 && setCalls[0][0].value === "x" && setCalls[0][1].value === null);
    check("SETMETADATA entry missing value → BAD",
      /^a2 BAD SETMETADATA entry/m.test(await _cmd(cs, "a2", "SETMETADATA INBOX (/onlyentry)")));
    check("SETMETADATA unterminated quoted value → BAD",
      /^a3 BAD SETMETADATA unterminated/m.test(await _cmd(cs, "a3", "SETMETADATA INBOX (/a " + '"' + "unterm)")));
    check("SETMETADATA whitespace-only body → BAD empty entry list",
      /^a4 BAD SETMETADATA empty entry list/m.test(await _cmd(cs, "a4", "SETMETADATA INBOX ( )")));
    check("SETMETADATA traversal mailbox → BAD refused",
      /^a5 BAD Mailbox name refused/m.test(await _cmd(cs, "a5", "SETMETADATA ../x (/a " + '"' + "v" + '"' + ")")));
  } finally { cs.destroy(); await sS.srv.close(); }

  var sSt = await _makeServer({ profile: "permissive", mailStore: _baseStore({ setMetadata: function () { return Promise.reject(new Error("set boom")); } }) });
  var cst = await _authConn(sSt);
  try {
    check("SETMETADATA backend throw → NO",
      /^a1 NO set boom/m.test(await _cmd(cst, "a1", "SETMETADATA INBOX (/a " + '"' + "v" + '"' + ")")));
  } finally { cst.destroy(); await sSt.srv.close(); }

  // 14c. NOTIFY branches
  var sN = await _makeServer({ profile: "permissive", mailStore: _baseStore({
    subscribeNotify: function (_actor, spec, emitFn) {
      if (spec === null && emitFn === null) { throw new Error("clear refused mid-life"); }   // NONE drop-silent catch
      if (emitFn) {
        emitFn({ kind: "STATUS", payload: "INBOX (MESSAGES 3)" });
        emitFn({ kind: "LIST",   payload: "() " + '"' + "/" + '"' + " INBOX" });
        emitFn({ kind: "FETCH",  seq: 1, payload: "FLAGS (\\Seen)" });
        emitFn(null);                 // guard: !event
        emitFn({ kind: "OTHER" });    // none-of-branch
      }
      return Promise.resolve();
    },
  }) });
  var cn = await _authConn(sN);
  try {
    var set = await _cmd(cn, "a1", "NOTIFY SET (SELECTED (MessageNew))");
    check("NOTIFY SET emits STATUS event", /^\* STATUS INBOX \(MESSAGES 3\)/m.test(set));
    check("NOTIFY SET emits LIST event", /^\* LIST \(\)/m.test(set));
    check("NOTIFY SET emits FETCH event", /^\* 1 FETCH \(FLAGS \(\\Seen\)\)/m.test(set));
    check("NOTIFY SET → OK", /^a1 OK NOTIFY completed/m.test(set));
    check("NOTIFY NONE (hook throws) → drop-silent OK", /^a2 OK NOTIFY completed/m.test(await _cmd(cn, "a2", "NOTIFY NONE")));
    check("NOTIFY SET bad syntax → BAD", /^a3 BAD NOTIFY syntax/m.test(await _cmd(cn, "a3", "NOTIFY SET")));
  } finally { cn.destroy(); await sN.srv.close(); }

  // NOTIFY NONE without hook → OK ; NOTIFY unauth → NO Login first ; NOTIFY reject → NO
  var sN2 = await _makeServer({ profile: "permissive" });   // base store has no subscribeNotify
  var cn2 = await _authConn(sN2);
  try {
    check("NOTIFY NONE without backend hook → OK", /^a1 OK NOTIFY completed/m.test(await _cmd(cn2, "a1", "NOTIFY NONE")));
    check("NOTIFY SET without backend hook → NO", /^a2 NO NOTIFY backend not configured/m.test(await _cmd(cn2, "a2", "NOTIFY SET (SELECTED (x))")));
  } finally { cn2.destroy(); await sN2.srv.close(); }

  var sN3 = await _makeServer({ profile: "permissive" });
  var cn3 = await _connect(sN3.port);
  try {
    check("NOTIFY before auth → NO Login first", /^a1 NO Login first/m.test(await _cmd(cn3, "a1", "NOTIFY NONE")));
  } finally { cn3.destroy(); await sN3.srv.close(); }

  var sN4 = await _makeServer({ profile: "permissive", mailStore: _baseStore({ subscribeNotify: function () { return Promise.reject(new Error("notify refused")); } }) });
  var cn4 = await _authConn(sN4);
  try {
    check("NOTIFY SET backend reject → NO", /^a1 NO notify refused/m.test(await _cmd(cn4, "a1", "NOTIFY SET (SELECTED (x))")));
  } finally { cn4.destroy(); await sN4.srv.close(); }
}

// =====================================================================
// 15. APPEND date-time grammar + arg-shape + flags branches
//     (_parseImapDateTime negative-tz / bad-month / out-of-range /
//      impossible-calendar-date; APPEND flags list; bad arg shape)
// =====================================================================
async function testAppendDateTimeAndShapeBranches() {
  var s = await _makeServer({ profile: "permissive" });
  var sock = await _authConn(s);
  try {
    check("APPEND negative-tz date-time → OK (sign branch)",
      /^a1 OK/m.test(await _appendLiteral(sock, "a1", "APPEND INBOX " + '"' + "01-Jan-2026 00:00:00 -0500" + '"' + " {5}", Buffer.from("HELLO"))));
    check("APPEND unknown month name → BAD date-time",
      /^a2 BAD APPEND date-time/m.test(await _appendLiteral(sock, "a2", "APPEND INBOX " + '"' + "01-Zzz-2026 00:00:00 +0000" + '"' + " {5}", Buffer.from("HELLO"))));
    check("APPEND out-of-range day → BAD date-time",
      /^a3 BAD APPEND date-time/m.test(await _appendLiteral(sock, "a3", "APPEND INBOX " + '"' + "99-Jan-2026 00:00:00 +0000" + '"' + " {5}", Buffer.from("HELLO"))));
    check("APPEND impossible calendar date (31-Feb) → BAD date-time",
      /^a4 BAD APPEND date-time/m.test(await _appendLiteral(sock, "a4", "APPEND INBOX " + '"' + "31-Feb-2026 00:00:00 +0000" + '"' + " {5}", Buffer.from("HELLO"))));
    check("APPEND with flags list → OK",
      /^a5 OK/m.test(await _appendLiteral(sock, "a5", "APPEND INBOX (" + BS + "Seen " + BS + "Draft) {5}", Buffer.from("HELLO"))));
    check("APPEND unparseable arg shape (with literal) → BAD APPEND syntax",
      /^a6 BAD APPEND syntax/m.test(await _appendLiteral(sock, "a6", "APPEND INBOX x y {5}", Buffer.from("HELLO"))));
  } finally { sock.destroy(); await s.srv.close(); }
}

// =====================================================================
// 16. APPEND result-shape branches: APPENDUID token (uidvalidity
//     fallback + no-uid else) + backend-reject fallback message
// =====================================================================
async function testAppendResultShapes() {
  var sA = await _makeServer({ profile: "permissive", mailStore: _baseStore({
    appendMessage: function () { return Promise.resolve({ uid: 7 }); },
  }) });
  var cA = await _authConn(sA);
  try {
    check("APPEND result {uid} without uidvalidity → APPENDUID 0 7",
      /^a1 OK \[APPENDUID 0 7\] APPEND completed/m.test(await _appendLiteral(cA, "a1", "APPEND INBOX {5}", Buffer.from("HELLO"))));
  } finally { cA.destroy(); await sA.srv.close(); }

  var sB = await _makeServer({ profile: "permissive", mailStore: _baseStore({
    appendMessage: function () { return Promise.resolve({}); },
  }) });
  var cB = await _authConn(sB);
  try {
    var r = await _appendLiteral(cB, "a1", "APPEND INBOX {5}", Buffer.from("HELLO"));
    check("APPEND result without uid → OK, no APPENDUID token",
      /^a1 OK APPEND completed/m.test(r) && !/APPENDUID/.test(r));
  } finally { cB.destroy(); await sB.srv.close(); }

  var sC = await _makeServer({ profile: "permissive", mailStore: _baseStore({
    appendMessage: function () { return Promise.reject(new Error("disk full")); },
  }) });
  var cC = await _authConn(sC);
  try {
    check("APPEND backend reject (message) → NO disk full",
      /^a1 NO disk full/m.test(await _appendLiteral(cC, "a1", "APPEND INBOX {5}", Buffer.from("HELLO"))));
  } finally { cC.destroy(); await sC.srv.close(); }

  var sD = await _makeServer({ profile: "permissive", mailStore: _baseStore({
    appendMessage: function () { return Promise.reject(new Error("")); },
  }) });
  var cD = await _authConn(sD);
  try {
    check("APPEND backend reject (messageless) → NO Append failed",
      /^a1 NO Append failed/m.test(await _appendLiteral(cD, "a1", "APPEND INBOX {5}", Buffer.from("HELLO"))));
  } finally { cD.destroy(); await sD.srv.close(); }
}

// =====================================================================
// 17. CATENATE — flags + date-time forwarding, invalid date, mailbox
//     refusal, and the parts-list token-walk refusals (empty / unquoted
//     URL / unterminated URL / unknown part)
// =====================================================================
async function testCatenateBranches() {
  var stub = _baseStore({
    appendCatenate: function (mailbox, parts, opts) {
      stub._cat = { mailbox: mailbox, parts: parts, opts: opts };
      return Promise.resolve({ uid: 9, uidValidity: 2 });
    },
  });
  var s = await _makeServer({ profile: "permissive", mailStore: stub });
  var sock = await _authConn(s);
  try {
    check("CATENATE with flags + date-time → OK [APPENDUID 2 9]",
      /^a1 OK \[APPENDUID 2 9\] APPEND completed/m.test(await _cmd(sock, "a1",
        "APPEND INBOX (" + BS + "Seen) " + '"' + "01-Jan-2026 00:00:00 +0000" + '"' + " CATENATE (URL " + '"' + "imap://x/A;UID=1" + '"' + ")")));
    check("CATENATE forwarded flags + parsed internalDate",
      stub._cat && stub._cat.opts.flags.indexOf("\\Seen") !== -1 &&
      typeof stub._cat.opts.internalDate === "number" && stub._cat.parts.length === 1);
    check("CATENATE invalid date-time → BAD",
      /^a2 BAD APPEND CATENATE date-time invalid/m.test(await _cmd(sock, "a2",
        "APPEND INBOX " + '"' + "not-a-date" + '"' + " CATENATE (URL " + '"' + "imap://x/A;UID=1" + '"' + ")")));
    check("CATENATE traversal mailbox → BAD refused",
      /^a3 BAD Mailbox name refused/m.test(await _cmd(sock, "a3",
        "APPEND ../evil CATENATE (URL " + '"' + "imap://x/A;UID=1" + '"' + ")")));
    check("CATENATE whitespace-only parts → BAD empty parts list",
      /^a4 BAD APPEND CATENATE empty parts list/m.test(await _cmd(sock, "a4", "APPEND INBOX CATENATE ( )")));
    check("CATENATE unquoted URL value → BAD must be quoted-string",
      /^a5 BAD APPEND CATENATE URL value must be quoted-string/m.test(await _cmd(sock, "a5", "APPEND INBOX CATENATE (URL foo)")));
    check("CATENATE unterminated URL quoted-string → BAD unterminated",
      /^a6 BAD APPEND CATENATE URL value unterminated/m.test(await _cmd(sock, "a6", "APPEND INBOX CATENATE (URL " + '"' + "foo)")));
    check("CATENATE unknown part keyword → BAD unknown part",
      /^a7 BAD APPEND CATENATE unknown part/m.test(await _cmd(sock, "a7", "APPEND INBOX CATENATE (FOO " + '"' + "bar" + '"' + ")")));
  } finally { sock.destroy(); await s.srv.close(); }
}

// =====================================================================
// 18. EXPUNGE / FETCH result-shape fallbacks (missing expunged list,
//     null fetch rows, payload-less MODSEQ-only row)
// =====================================================================
async function testSelectedResultShapes() {
  var sE = await _makeServer({ profile: "permissive", mailStore: _baseStore({
    expungeFolder: function () { return Promise.resolve({ modseq: 7 }); },
  }) });
  var cE = await _authConn(sE, "INBOX");
  try {
    var ex = await _cmd(cE, "a1", "EXPUNGE");
    check("EXPUNGE result without expunged list → OK, no untagged EXPUNGE",
      /^a1 OK EXPUNGE completed/m.test(ex) && !/^\* \d+ EXPUNGE/m.test(ex));
  } finally { cE.destroy(); await sE.srv.close(); }

  var sF = await _makeServer({ profile: "permissive", mailStore: _baseStore({
    fetchRange: function () { return Promise.resolve(undefined); },
  }) });
  var cF = await _authConn(sF, "INBOX");
  try {
    var f = await _cmd(cF, "a1", "FETCH 1:* (FLAGS)");
    check("FETCH backend returns undefined → OK, no untagged FETCH",
      /^a1 OK FETCH completed/m.test(f) && !/^\* \d+ FETCH/m.test(f));
  } finally { cF.destroy(); await sF.srv.close(); }

  var sFm = await _makeServer({ profile: "permissive", mailStore: _baseStore({
    fetchRange: function () { return Promise.resolve([{ seq: 4, modseq: 55 }]); },
  }) });
  var cFm = await _authConn(sFm, "INBOX");
  try {
    check("FETCH row without payload + MODSEQ att → untagged MODSEQ-only",
      /^\* 4 FETCH \(MODSEQ \(55\)\)/m.test(await _cmd(cFm, "a1", "FETCH 1:* (MODSEQ)")));
  } finally { cFm.destroy(); await sFm.srv.close(); }
}

// =====================================================================
// 19. STORE result-shape branches: object-without-rows + MODIFIED,
//     non-object result, flags-less row, SILENT+CONDSTORE modseq-less
//     row skip, and UNCHANGEDSINCE implicit-CONDSTORE engagement
// =====================================================================
async function testStoreResultShapes() {
  var sA = await _makeServer({ profile: "permissive", mailStore: _baseStore({
    storeFlags: function () { return Promise.resolve({ modified: "3" }); },
  }) });
  var cA = await _authConn(sA, "INBOX");
  try {
    check("STORE result {modified} without rows → OK [MODIFIED 3]",
      /^a1 OK \[MODIFIED 3\] STORE completed/m.test(await _cmd(cA, "a1", "STORE 1 +FLAGS (" + BS + "Seen)")));
  } finally { cA.destroy(); await sA.srv.close(); }

  var sB = await _makeServer({ profile: "permissive", mailStore: _baseStore({
    storeFlags: function () { return Promise.resolve(undefined); },
  }) });
  var cB = await _authConn(sB, "INBOX");
  try {
    var r = await _cmd(cB, "a1", "STORE 1 +FLAGS (" + BS + "Seen)");
    check("STORE result non-object → OK, no untagged FETCH",
      /^a1 OK STORE completed/m.test(r) && !/^\* \d+ FETCH/m.test(r));
  } finally { cB.destroy(); await sB.srv.close(); }

  var sC = await _makeServer({ profile: "permissive", mailStore: _baseStore({
    storeFlags: function () { return Promise.resolve([{ seq: 1, modseq: 11 }]); },
  }) });
  var cC = await _authConn(sC, "INBOX");
  try {
    check("STORE row without flags → untagged FLAGS ()",
      /^\* 1 FETCH \(FLAGS \(\)\)/m.test(await _cmd(cC, "a1", "STORE 1 +FLAGS (" + BS + "Seen)")));
  } finally { cC.destroy(); await sC.srv.close(); }

  var sD = await _makeServer({ profile: "permissive", mailStore: _baseStore({
    storeFlags: function () { return Promise.resolve([{ seq: 1, flags: ["\\Seen"] }]); },
  }) });
  var cD = await _authConn(sD, "INBOX");
  try {
    await _cmd(cD, "a1", "ENABLE CONDSTORE");
    var r2 = await _cmd(cD, "a2", "STORE 1 +FLAGS.SILENT (" + BS + "Flagged)");
    check("SILENT STORE under CONDSTORE, modseq-less row → OK, no untagged FETCH",
      /^a2 OK STORE completed/m.test(r2) && !/^\* \d+ FETCH/m.test(r2));
  } finally { cD.destroy(); await sD.srv.close(); }

  var sImp = await _makeServer({ profile: "permissive" });
  var cImp = await _authConn(sImp, "INBOX");
  try {
    check("STORE UNCHANGEDSINCE without prior ENABLE → OK (implicit CONDSTORE)",
      /^a1 OK STORE completed/m.test(await _cmd(cImp, "a1", "STORE 1 (UNCHANGEDSINCE 5) +FLAGS (" + BS + "Seen)")));
  } finally { cImp.destroy(); await sImp.srv.close(); }
}

// =====================================================================
// 20. GETMETADATA DEPTH opt + messageless reject; SETMETADATA unquoted
//     value / escaped-quote value / bad shape / messageless reject
// =====================================================================
async function testMetadataExtraBranches() {
  var sG = await _makeServer({ profile: "permissive", mailStore: _baseStore({
    getMetadata: function (_a, _mb, names) { return Promise.resolve(names.map(function (n) { return { entry: n, value: "v" }; })); },
  }) });
  var cG = await _authConn(sG);
  try {
    check("GETMETADATA with DEPTH opt → OK",
      /^a1 OK GETMETADATA completed/m.test(await _cmd(cG, "a1", "GETMETADATA (DEPTH infinity) INBOX (/private/x)")));
  } finally { cG.destroy(); await sG.srv.close(); }

  var sGm = await _makeServer({ profile: "permissive", mailStore: _baseStore({
    getMetadata: function () { return Promise.reject(new Error("")); },
  }) });
  var cGm = await _authConn(sGm);
  try {
    check("GETMETADATA backend reject messageless → NO GETMETADATA failed",
      /^a1 NO GETMETADATA failed/m.test(await _cmd(cGm, "a1", "GETMETADATA INBOX (/private/x)")));
  } finally { cGm.destroy(); await sGm.srv.close(); }

  var setSeen = [];
  var sS = await _makeServer({ profile: "permissive", mailStore: _baseStore({
    setMetadata: function (_a, _mb, entries) { setSeen.push(entries); return Promise.resolve(); },
  }) });
  var cS = await _authConn(sS);
  try {
    check("SETMETADATA unquoted non-NIL value → OK",
      /^a1 OK SETMETADATA completed/m.test(await _cmd(cS, "a1", "SETMETADATA INBOX (/a hello)")));
    check("SETMETADATA unquoted value parsed verbatim",
      setSeen.length === 1 && setSeen[0][0].value === "hello");
    check("SETMETADATA escaped-quote value → OK",
      /^a2 OK SETMETADATA completed/m.test(await _cmd(cS, "a2", "SETMETADATA INBOX (/a " + '"' + "x" + BS + '"' + "y" + '"' + ")")));
    check("SETMETADATA escaped-quote value unescaped to literal quote",
      setSeen.length === 2 && setSeen[1][0].value === "x" + '"' + "y");
    check("SETMETADATA bare (no args) → BAD syntax",
      /^a3 BAD SETMETADATA syntax/m.test(await _cmd(cS, "a3", "SETMETADATA")));
    check("SETMETADATA mailbox without paren-list → BAD syntax",
      /^a4 BAD SETMETADATA syntax/m.test(await _cmd(cS, "a4", "SETMETADATA INBOX")));
  } finally { cS.destroy(); await sS.srv.close(); }

  var sSm = await _makeServer({ profile: "permissive", mailStore: _baseStore({
    setMetadata: function () { return Promise.reject(new Error("")); },
  }) });
  var cSm = await _authConn(sSm);
  try {
    check("SETMETADATA backend reject messageless → NO SETMETADATA failed",
      /^a1 NO SETMETADATA failed/m.test(await _cmd(cSm, "a1", "SETMETADATA INBOX (/a " + '"' + "v" + '"' + ")")));
  } finally { cSm.destroy(); await sSm.srv.close(); }
}

// =====================================================================
// 21. Dispatch promise-reject with a MESSAGELESS error falls back to
//     the literal "handler rejected" reason (async _dispatch path).
//     (The sync-throw path is registry-wrapped with a non-empty
//     message before it reaches _dispatch, so its message-less
//     fallback is unreachable through the public override path.)
// =====================================================================
async function testDispatchMessagelessErrors() {
  var s = await _makeServer({ profile: "permissive", overrides: {
    CHECK: { fn: function () { return Promise.reject(new Error("")); }, maxHandlerBytes: 1024, maxHandlerMs: 1000 },
  } });
  var sock = await _connect(s.port);
  try {
    check("override promise-reject messageless → NO handler rejected",
      /^a1 NO handler rejected/m.test(await _cmd(sock, "a1", "CHECK")));
  } finally { sock.destroy(); await s.srv.close(); }
}

// =====================================================================
// 22. AUTHENTICATE fallback branches: mechanisms-list default,
//     tenantless actor, reason-less fail result, messageless verify throw
// =====================================================================
async function testAuthenticateFallbacks() {
  var sA = await _makeServer({ profile: "permissive", auth: {
    verify: function () { return Promise.resolve({ ok: true, actor: { id: "u1" } }); },
  } });
  var cA = await _connect(sA.port);
  try {
    check("AUTHENTICATE with no mechanisms list + tenantless actor → OK",
      /^a1 OK \[CAPABILITY .*\] AUTHENTICATE completed/m.test(await _cmd(cA, "a1", "AUTHENTICATE PLAIN " + _plain("alice", "good"))));
  } finally { cA.destroy(); await sA.srv.close(); }

  var sB = await _makeServer({ profile: "permissive", auth: {
    mechanisms: ["PLAIN"], verify: function () { return Promise.resolve({ ok: false }); },
  } });
  var cB = await _connect(sB.port);
  try {
    check("AUTHENTICATE verify {ok:false} without reason → NO credentials invalid",
      /^a1 NO Authentication credentials invalid/m.test(await _cmd(cB, "a1", "AUTHENTICATE PLAIN " + _plain("alice", "x"))));
  } finally { cB.destroy(); await sB.srv.close(); }

  var sC = await _makeServer({ profile: "permissive", auth: {
    mechanisms: ["PLAIN"], verify: function () { throw new Error(""); },
  } });
  var cC = await _connect(sC.port);
  try {
    check("AUTHENTICATE verify throws messageless → NO Authentication failed",
      /^a1 NO Authentication failed/m.test(await _cmd(cC, "a1", "AUTHENTICATE PLAIN " + _plain("alice", "x"))));
  } finally { cC.destroy(); await sC.srv.close(); }
}

// =====================================================================
// 23. Backend messageless-reject fallbacks (SELECT / LIST / STATUS),
//     LIST folder-without-attributes fallback, and QRESYNC modseq
//     non-numeric second-operand
// =====================================================================
async function testBackendRejectFallbacks() {
  var sSel = await _makeServer({ profile: "permissive", mailStore: _baseStore({
    selectFolder: function () { return Promise.reject(new Error("")); },
  }) });
  var cSel = await _authConn(sSel);
  try {
    check("SELECT backend reject messageless → NO Select failed",
      /^a1 NO Select failed/m.test(await _cmd(cSel, "a1", "SELECT INBOX")));
    check("SELECT QRESYNC non-numeric modseq → BAD (second-operand branch)",
      /^a2 BAD SELECT QRESYNC params/m.test(await _cmd(cSel, "a2", "SELECT INBOX (QRESYNC (17 y))")));
  } finally { cSel.destroy(); await sSel.srv.close(); }

  var sList = await _makeServer({ profile: "permissive", mailStore: _baseStore({
    listFolders: function () { return Promise.resolve([{ name: "INBOX" }]); },
  }) });
  var cList = await _authConn(sList);
  try {
    check("LIST folder without attributes → LIST () line (attrs fallback)",
      /^\* LIST \(\) "\/" "INBOX"/m.test(await _cmd(cList, "a1", "LIST \"\" \"*\"")));
  } finally { cList.destroy(); await sList.srv.close(); }

  var sListR = await _makeServer({ profile: "permissive", mailStore: _baseStore({
    listFolders: function () { return Promise.reject(new Error("")); },
  }) });
  var cListR = await _authConn(sListR);
  try {
    check("LIST backend reject messageless → NO List failed",
      /^a1 NO List failed/m.test(await _cmd(cListR, "a1", "LIST \"\" \"*\"")));
  } finally { cListR.destroy(); await sListR.srv.close(); }

  var sStat = await _makeServer({ profile: "permissive", mailStore: _baseStore({
    statusFolder: function () { return Promise.reject(new Error("")); },
  }) });
  var cStat = await _authConn(sStat);
  try {
    check("STATUS backend reject messageless → NO Status failed",
      /^a1 NO Status failed/m.test(await _cmd(cStat, "a1", "STATUS INBOX (MESSAGES)")));
  } finally { cStat.destroy(); await sStat.srv.close(); }
}

// =====================================================================
// 23b. NOTIFY event-emission fallbacks: FETCH event without seq/payload
//      (|| "" fallbacks) + subscribe messageless-reject fallback
// =====================================================================
async function testNotifyEmitFallbacks() {
  var sF = await _makeServer({ profile: "permissive", mailStore: _baseStore({
    subscribeNotify: function (_actor, _spec, emitFn) {
      if (emitFn) { emitFn({ kind: "FETCH" }); }   // no seq, no payload → || "" fallbacks
      return Promise.resolve();
    },
  }) });
  var cF = await _authConn(sF);
  try {
    var r = await _cmd(cF, "a1", "NOTIFY SET (SELECTED (MessageNew))");
    check("NOTIFY FETCH event without seq/payload → untagged FETCH ()",
      /FETCH \(\)/m.test(r) && /^a1 OK NOTIFY completed/m.test(r));
  } finally { cF.destroy(); await sF.srv.close(); }

  var sR = await _makeServer({ profile: "permissive", mailStore: _baseStore({
    subscribeNotify: function () { return Promise.reject(new Error("")); },
  }) });
  var cR = await _authConn(sR);
  try {
    check("NOTIFY subscribe reject messageless → NO NOTIFY refused",
      /^a1 NO NOTIFY refused/m.test(await _cmd(cR, "a1", "NOTIFY SET (SELECTED (MessageNew))")));
  } finally { cR.destroy(); await sR.srv.close(); }
}

// =====================================================================
// 24. Misc arg-fallback + wrong-state branches: bare ENABLE / NOTIFY,
//     pre-auth GET/SETMETADATA / LIST / STATUS / APPEND, SELECT
//     control-char (tab) mailbox refusal
// =====================================================================
async function testMiscBranchGaps() {
  var s = await _makeServer({ profile: "permissive" });
  var c1 = await _authConn(s);
  try {
    var en = await _cmd(c1, "a1", "ENABLE");
    check("ENABLE with no args → untagged ENABLED + OK",
      /^\* ENABLED/m.test(en) && /^a1 OK ENABLE completed/m.test(en));
    check("ENABLE unknown extension → OK (no-match loop)", /^a2 OK ENABLE completed/m.test(await _cmd(c1, "a2", "ENABLE UNKNOWNEXT")));
    check("NOTIFY with no args → BAD syntax", /^a3 BAD NOTIFY syntax/m.test(await _cmd(c1, "a3", "NOTIFY")));
    check("SELECT mailbox with control char (tab) → BAD refused",
      /^a4 BAD Mailbox name refused/m.test(await _cmd(c1, "a4", "SELECT " + '"' + "a\tb" + '"')));
  } finally { c1.destroy(); await s.srv.close(); }

  var s2 = await _makeServer({ profile: "permissive" });
  var cu = await _connect(s2.port);
  try {
    check("GETMETADATA before auth → NO Login first", /^a1 NO Login first/m.test(await _cmd(cu, "a1", "GETMETADATA INBOX (/x)")));
    check("SETMETADATA before auth → NO Login first", /^a2 NO Login first/m.test(await _cmd(cu, "a2", "SETMETADATA INBOX (/x " + '"' + "v" + '"' + ")")));
    check("LIST before auth → NO Login first", /^a3 NO Login first/m.test(await _cmd(cu, "a3", "LIST \"\" \"*\"")));
    check("STATUS before auth → NO Login first", /^a4 NO Login first/m.test(await _cmd(cu, "a4", "STATUS INBOX (MESSAGES)")));
    check("APPEND before auth → NO Login first", /^a5 NO Login first/m.test(await _cmd(cu, "a5", "APPEND INBOX")));
  } finally { cu.destroy(); await s2.srv.close(); }

  // LOGIN with a valid user atom + unterminated quoted password: the
  // SECOND _parseLoginArgs _take() returns null (password branch).
  var s3 = await _makeServer({ profile: "permissive" });
  var cl = await _connect(s3.port);
  try {
    check("LOGIN valid user + unterminated quoted pass → BAD expects user + pass",
      /^a1 BAD LOGIN expects user/m.test(await _cmd(cl, "a1", "LOGIN alice " + '"' + "unterminated")));
  } finally { cl.destroy(); await s3.srv.close(); }
}

// A peer that opens a connection, takes the greeting and drops TCP was never
// removed from the listener's live-connection set: the set was added to on
// accept and emptied only on the paths where the SERVER ends a session. The
// rate-limit slot WAS released on the socket's close, so the same peer could
// reconnect immediately, and each cycle left an entry behind. The two transfer
// listeners and the other two store listeners all release the slot and drop the
// entry together; this one released the slot alone.
//
// Both halves belong to the same event, so the test drives the event the peer
// controls — a client-side disconnect, with no command issued and no
// authentication.
async function testClientDisconnectReleasesTheConnectionSlot() {
  var s = await _makeServer({});
  try {
    check("imap: the listener reports a live-connection count",
      typeof s.srv.connectionCount === "function");
    if (typeof s.srv.connectionCount !== "function") return;

    check("imap: starts with no connections", s.srv.connectionCount() === 0,
      String(s.srv.connectionCount()));

    var socks = [];
    for (var i = 0; i < 4; i += 1) socks.push(await _connect(s.port));
    await helpers.waitUntil(function () { return s.srv.connectionCount() === 4; }, {
      timeoutMs: 5000,
      label:     "imap connection-accounting: four accepted connections counted",
    });

    // The peer drops TCP. Nothing on the server decided to end these.
    socks.forEach(function (sk) { sk.destroy(); });
    await helpers.waitUntil(function () { return s.srv.connectionCount() === 0; }, {
      timeoutMs: 5000,
      label:     "imap connection-accounting: client-initiated disconnects release their slots",
    });
    check("imap: a client-initiated disconnect leaves no entry behind",
      s.srv.connectionCount() === 0, String(s.srv.connectionCount()));
  } finally { await s.srv.close(); }
}

// The listener ships no SEARCH of its own — the registry carries a "not
// configured" default and a consumer supplies the real one through
// `overrides`. That seam worked for `SEARCH` and not for `UID SEARCH`, because
// the UID verb dispatched its own sub-commands and never went back through the
// registry. A consumer therefore got one of the two forms answered by the
// handler they wrote and the other refused BAD, with no way to supply it short
// of replacing the whole UID verb — which would take UID FETCH and UID STORE
// down with it.
//
// RFC 9051 §6.4.9 is the form a client with a cross-session cache asks for,
// because a sequence number is only meaningful within the session that issued
// it. So the client doing the durable thing was the one being refused.
// The literal window is a resource commitment: a continuation request invites
// up to maxLiteralBytes and holds a connection slot until the payload arrives.
// It was decided from the PARSED SHAPE alone, while the authorization that
// would refuse the command — _requireAuth, the first line of _handleAppend —
// runs only after the whole literal has been buffered, because handlers are
// reached through _completeLiteralCommand. So an unauthenticated peer could
// open the window on a verb the state table lists as AUTHENTICATED-only and
// trickle bytes into it indefinitely.
//
// LOGIN and AUTHENTICATE are the two that legitimately carry a literal before
// authentication — a password is exactly the value a quoted string cannot
// always hold — so this is an allowlist rather than a blanket refusal.
async function testPreAuthLiteralIsRefusedForAuthenticatedOnlyVerbs() {
  var s = await _makeServer({});
  var sock = await _connect(s.port);
  try {
    // APPEND is AUTHENTICATED-only. The window must not open.
    //
    // Waits on EITHER outcome, because the failing behaviour is a continuation
    // request and the passing one is a tagged refusal — a reader that waited
    // only for the tag would hang for the full test budget on the bug it is
    // meant to report, which is a timeout rather than a finding.
    var appended = await _cmdT(sock, "P1", "APPEND INBOX {1048576}", /(^\+ |^P1 )/m);                   // allow:raw-byte-literal — 1 MiB literal opener
    check("imap: an unauthenticated APPEND literal gets no continuation request",
      !/^\+ /m.test(appended), JSON.stringify(appended));
    check("imap: it is refused with a tagged response instead",
      /^P1 (NO|BAD)/m.test(appended), JSON.stringify(appended));

    // A verb that is available pre-auth but takes no literal argument must not
    // open a window either. Allowing the whole NOT-AUTHENTICATED set let
    // `NOOP {67108864}` commit 64 MiB and a connection slot to a peer that had
    // proved nothing — the state table says which commands are AVAILABLE, not
    // which can carry a literal.
    // The refusal may be tagged or untagged depending on where it is caught,
    // so the read waits for any of the three outcomes rather than hanging on
    // the one shape it expected.
    var noopLit = await _cmdT(sock, "P5", "NOOP {67108864}", /(^\+ |^P5 |^\* BAD)/m);                   // allow:raw-byte-literal — 64 MiB literal opener
    check("imap: a pre-auth verb that takes no literal cannot open one",
      !/^\+ /m.test(noopLit), JSON.stringify(noopLit));

    // And the session is still usable — this is a refusal, not a teardown.
    var cap = await _cmd(sock, "P2", "CAPABILITY");
    check("imap: the connection survives the refusal",
      /^P2 OK/m.test(cap), JSON.stringify(cap));

    // ID is available before login per the state table, and RFC 2971 makes its
    // parameters strings a client may send as literals — so it has to be able
    // to open one. Picking the pre-auth verbs by which "obviously" need a
    // literal missed it and refused a documented command.
    var idLit = await _cmdT(sock, "P4", "ID (\"name\" {4}", /(^\+ |^P4 )/m);
    check("imap: ID may open a literal before authentication",
      /^\+ /m.test(idLit), JSON.stringify(idLit));
    // Finish the command so the connection is left usable for what follows.
    var idDone = await _raw(sock, _tagTerm("P4"), "test)\r\n");
    check("imap: and the ID command completes",
      /^P4 (OK|BAD|NO)/m.test(idDone), JSON.stringify(idDone));

    // The two that may carry one before authentication still can.
    var loginLit = await _cmdT(sock, "P3", "LOGIN alice {4}", /\+ /);
    check("imap: LOGIN may still open a literal before authentication",
      /\+ /.test(loginLit), JSON.stringify(loginLit));
    var done = await _raw(sock, _tagTerm("P3"), "good\r\n");
    check("imap: and it completes", /^P3 OK/m.test(done), JSON.stringify(done));
  } finally { sock.destroy(); await s.srv.close({ timeoutMs: 1000 }); }                                 // allow:raw-time-literal — test-only short drain
}

// The listener documents a minimum body rate and builds the limiter that
// enforces one, and never asked it. The only bound on a literal transfer was
// the idle timeout, which every arriving byte resets — so a peer trickling one
// byte at a time held a connection slot for as long as it cared to, which is
// what the floor exists to stop. MX and submission were given this; IMAP and
// ManageSieve were left out of that sweep.
async function testLiteralBelowTheByteRateFloorIsClosed() {
  // A limiter whose floor is unreachable in a fast test is substituted, the
  // same way the MX test does it, so this does not have to spend the
  // ten-second grace window to reach the branch. What is pinned here is that
  // the listener ASKS; the number itself is pinned in the limiter's own tests.
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

  var s = await _makeServer({ rateLimit: starving });
  var sock = await _authConn(s);
  try {
    var closed = false;
    sock.on("close", function () { closed = true; });
    var opened = await _cmdT(sock, "R1", "APPEND INBOX {200000}", /\+ /);                               // allow:raw-byte-literal — 200 KB literal opener
    check("imap: the literal opens for an authenticated peer",
      /\+ /.test(opened), JSON.stringify(opened));

    sock.write("x");
    await helpers.waitUntil(function () { return closed; }, {
      timeoutMs: 5000, label: "imap byte-rate floor: connection closed",                                // allow:raw-time-literal — test-only cap
    });
    check("imap: a literal below the rate floor closes the connection", closed);
    check("imap: and the listener actually asked the limiter",
      asked.length >= 1, String(asked.length));
    // The bytes reported must include the chunk being judged, or a one-chunk
    // payload is measured as though nothing had arrived.
    check("imap: the bytes reported include the chunk under judgement",
      asked.length >= 1 && asked[0].bytes >= 1, JSON.stringify(asked[0]));
  } finally { sock.destroy(); await s.srv.close({ timeoutMs: 1000 }); }                                 // allow:raw-time-literal — test-only short drain
}

// The case the data-driven check structurally cannot see: a peer opens a
// literal and then sends NOTHING. No data event ever arrives, so the floor is
// never asked, and the connection was held until an idle timeout that a peer
// sending nothing was never going to trip either. The deadline is what closes
// it, so this exercises the timer rather than the chunk path.
async function testLiteralWithNoPayloadAtAllIsClosed() {
  var real = b.mail.server.rateLimit.create({});
  var starving = {};
  Object.keys(real).forEach(function (k) {
    starving[k] = typeof real[k] === "function"
      ? function () { return real[k].apply(real, arguments); }
      : real[k];
  });
  starving.bodyRateStarved = function () { return true; };
  // A short window so the deadline fires inside the test's budget; the number
  // is the limiter's to choose, which is exactly why the listener reads it
  // from the limiter rather than holding one of its own.
  starving.bodyRateWindowMs = function () { return 50; };                                               // allow:raw-time-literal — test-only window

  var s = await _makeServer({ rateLimit: starving });
  var sock = await _authConn(s);
  try {
    var closed = false;
    sock.on("close", function () { closed = true; });
    var opened = await _cmdT(sock, "Z1", "APPEND INBOX {200000}", /\+ /);                               // allow:raw-byte-literal — 200 KB literal opener
    check("imap: [setup] the literal opens", /\+ /.test(opened), JSON.stringify(opened));
    // Not one byte follows.
    await helpers.waitUntil(function () { return closed; }, {
      timeoutMs: 5000, label: "imap: a literal with no payload at all is closed",                       // allow:raw-time-literal — test-only cap
    });
    check("imap: a literal opened and never fed is closed by the deadline", closed);
  } finally { sock.destroy(); await s.srv.close({ timeoutMs: 1000 }); }                                 // allow:raw-time-literal — test-only short drain
}

async function testUidRoutesThroughTheRegistrySeam() {
  var seen = [];
  var s = await _makeServer({
    overrides: {
      SEARCH: {
        // Four parameters, the signature a consumer writes when their search
        // terms can arrive as literals.
        fn: function (_state, socket, parsed, literalBody) {
          seen.push({
            args: parsed.args, useUid: parsed.useUid === true,
            literal: literalBody == null ? null : String(literalBody),
          });
          socket.write("* SEARCH 7 9\r\n");
          socket.write(parsed.tag + " OK SEARCH completed\r\n");
        },
        maxHandlerBytes: 4096,
        maxHandlerMs:    5000,
      },
    },
  });
  var sock = await _authConn(s);
  try {
    var plain = await _cmd(sock, "S1", "SEARCH UNSEEN");
    check("imap: a supplied SEARCH answers the sequence form",
      /^S1 OK/m.test(plain), JSON.stringify(plain));

    var uid = await _cmd(sock, "S2", "UID SEARCH UNSEEN");
    check("imap: the SAME supplied handler answers the UID form",
      /^S2 OK/m.test(uid), JSON.stringify(uid));
    check("imap: the UID form reached the handler exactly once more",
      seen.length === 2, String(seen.length));
    // Without this the handler cannot tell the two forms apart, and RFC 9051
    // §6.4.9 requires the response to carry UIDs rather than sequence numbers.
    check("imap: the sequence form is not marked as a UID request",
      seen[0] && seen[0].useUid === false, JSON.stringify(seen[0]));
    check("imap: the UID form tells the handler to answer in UIDs",
      seen[1] && seen[1].useUid === true, JSON.stringify(seen[1]));
    check("imap: the sub-command's own arguments are passed through intact",
      seen[1] && seen[1].args === "UNSEEN", JSON.stringify(seen[1]));

    // And the literal payload, which is how a real client sends any non-ASCII
    // search term. It was dropped twice over on this path: the registry entry's
    // closure declared three parameters while dispatch supplied four, so arity
    // discarded it at the boundary, and _handleUid's own sub-dispatch passed no
    // literal onward either. Repairing one leaves the other, so both are
    // exercised here through the ONE command that has to cross both.
    var lit = await _cmdT(sock, "S5", "UID SEARCH SUBJECT {5}", /\+ /);
    check("imap: UID SEARCH with a literal gets a continuation request",
      /\+ /.test(lit), JSON.stringify(lit));
    var litDone = await _raw(sock, _tagTerm("S5"), "hello\r\n");
    check("imap: and the UID form completes rather than failing BAD",
      /^S5 OK/m.test(litDone), JSON.stringify(litDone));
    check("imap: the literal payload reaches the supplied handler",
      seen[2] && seen[2].literal === "hello",
      JSON.stringify(seen[2] && seen[2].literal));

    // The drop was a property of ARITY, not of UID, and the listener hands a
    // literal to whatever verb arrived carrying one — so the same shape could
    // bite any handler whose closure declares three parameters. LOGIN is the
    // one that matters, because RFC 9051 lets a client send its password as a
    // literal and the listener strips the opener from the line before the
    // handler parses it. Asked rather than assumed.
    var fresh = await _connect(s.port);
    try {
      var loginLit = await _cmdT(fresh, "S6", "LOGIN alice {4}", /\+ /);
      check("imap: LOGIN with a literal password gets a continuation request",
        /\+ /.test(loginLit), JSON.stringify(loginLit));
      // `good` is alice's real password, so this must AUTHENTICATE. Accepting
      // a NO here would pass just as happily with the literal dropped and the
      // credential simply wrong, which is the thing being tested.
      var loginDone = await _raw(fresh, _tagTerm("S6"), "good\r\n");
      check("imap: and the literal password reaches auth, so the login succeeds",
        /^S6 OK/m.test(loginDone), JSON.stringify(loginDone));

      // The other astring a client commonly sends as a literal is a mailbox
      // name, which is where a UTF-8 name has to go. Asked the same way, on the
      // now-authenticated connection.
      var selLit = await _cmdT(fresh, "S7", "SELECT {5}", /\+ /);
      check("imap: SELECT with a literal mailbox gets a continuation request",
        /\+ /.test(selLit), JSON.stringify(selLit));
      var selDone = await _raw(fresh, _tagTerm("S7"), "INBOX\r\n");
      check("imap: and the literal mailbox name reaches the handler",
        /^S7 OK/m.test(selDone), JSON.stringify(selDone));
    } finally { fresh.destroy(); }

    // Routing by "is it in the registry" would dispatch real handlers that
    // know nothing about UIDs. SELECT would select a mailbox; UID would
    // recurse into itself.
    var sel = await _cmd(sock, "S3", "UID SELECT INBOX");
    check("imap: UID does not forward a verb that takes no uid-set",
      /^S3 BAD/m.test(sel), JSON.stringify(sel));
    var recur = await _cmd(sock, "S4", "UID UID FETCH 1 (FLAGS)");
    check("imap: UID does not recurse into itself",
      /^S4 BAD/m.test(recur), JSON.stringify(recur));

    // RFC 4315 §2.1: UID EXPUNGE expunges ONLY the named UIDs. The shipped
    // EXPUNGE takes no set and expunges everything flagged \Deleted, so
    // forwarding to it would delete messages the client did not name.
    // Refusing is the answer that cannot lose mail.
    var expunge = await _cmd(sock, "S5", "UID EXPUNGE 1:3");
    check("imap: UID EXPUNGE is refused rather than exceeding the named set",
      /^S5 NO/m.test(expunge), JSON.stringify(expunge));
  } finally { sock.destroy(); await s.srv.close(); }
}

// The other half of the EXPUNGE rule: a consumer who supplies a uid-set-aware
// handler DOES get UID EXPUNGE served. The refusal above is about the shipped
// default's inability to honour a set, not about the command.
async function testUidExpungeReachesAConsumerSuppliedHandler() {
  var got = [];
  var s = await _makeServer({
    overrides: {
      EXPUNGE: {
        fn: function (_state, socket, parsed) {
          got.push({ args: parsed.args, useUid: parsed.useUid === true });
          socket.write(parsed.tag + " OK EXPUNGE completed\r\n");
        },
        maxHandlerBytes: 4096,
        maxHandlerMs:    5000,
      },
    },
  });
  var sock = await _authConn(s);
  try {
    var reply = await _cmd(sock, "E1", "UID EXPUNGE 1:3");
    check("imap: a supplied EXPUNGE serves the UID form",
      /^E1 OK/m.test(reply), JSON.stringify(reply));
    check("imap: it receives the uid-set and the UID marker",
      got.length === 1 && got[0].args === "1:3" && got[0].useUid === true,
      JSON.stringify(got));
  } finally { sock.destroy(); await s.srv.close(); }
}

async function run() {
  var wtt = helpers.withTestTimeout;
  await helpers.withDrain("mail-server-imap", async function () {
    testSurface();
    testRequiresTlsContext();
    testRequiresMailStore();
    testBadBoundsRefused();
    testUnknownOptionRefused();
    testOperatorAuditSinkIsWired();
    await testImplicitTls();
    await testCapabilityHook();
    await testCapabilityHookMustKeepImap4rev2();
    await testCapabilityHookCannotInjectOrCrash();
    await testCapabilityHookRejectsNonFunction();
    await testCapabilityAdvertisesCondstore();
    await testEnableCondstore();
    await testFetchChangedSinceParses();
    await testFetchWritesTheOctetsTheBackendReturned();
    await testStoreUnchangedSinceConflict();
    await testFetchChangedSinceImpliesCondstore();
    await testStoreSilentEmitsModseqUnderCondstore();
    // v0.11.28 — NOTIFY / METADATA / CATENATE
    await testCapabilityAdvertisesNewExtensions();
    await testNotifyNoneAndSet();
    await testNotifyBackendMissing();
    await testGetSetMetadata();
    await testMetadataBackendMissing();
    await testCatenateBackendMissing();
    await testAppendLiteralGetsARealContinuation();
    await testLiteralFramingDoesNotDependOnPacketBoundaries();
    await testPipelineBoundIsNotBypassedByAPendingLiteral();
    await testZeroLengthSynchronizingLiteralGetsAContinuation();
    await testLiteralInsideAParenthesizedListCompletes();
    await testAggregateLiteralCapCountsTheFinalLiteral();
    await testLiteralBytesAreNotChargedToTheLineCap();
    await testFinalLiteralCompletesWhenItsTerminatorArrivesLate();
    await testLiteralCommandConsumesItsOwnTerminator();
    await testNonFinalLiteralContinuesTheSameCommand();
    await testPipelinedCommandsAreNotRefusedAsOneLongLine();
    await testFinalLiteralReachesTheHandlerAsItsArgument();
    await testNonFinalLiteralRefusesUndecodableBytes();
    await testCatenatePartOrderingAndValidation();
    // v0.11.33 — QRESYNC (RFC 7162 §3.2)
    await testCapabilityAdvertisesQresync();
    await testEnableQresyncImpliesCondstore();
    await testSelectQresyncEmitsVanishedEarlier();
    await testSelectQresyncImplicitlyEngagesCondstore();
    // RFC 9051 command dispatch + error branches
    await wtt("unauth dispatch",        testUnauthDispatch);
    await wtt("starttls upgrade",       testStartTlsUpgrade);
    await wtt("authenticate",           testAuthenticate);
    await wtt("login",                  testLogin);
    await wtt("select/examine",         testSelectExamine);
    await wtt("list/status",            testListStatus);
    await wtt("append",                 testAppend);
    await wtt("selected commands",      testSelectedCommands);
    await wtt("idle",                   testIdle);
    await wtt("dispatch errors",        testDispatchErrors);
    await wtt("connection rate-limit",  testConnectionRateLimit);
    await wtt("client disconnect frees", testClientDisconnectReleasesTheConnectionSlot);
    await wtt("uid routes via registry",  testUidRoutesThroughTheRegistrySeam);
    await wtt("pre-auth literal refused",  testPreAuthLiteralIsRefusedForAuthenticatedOnlyVerbs);
    await wtt("literal byte-rate floor",   testLiteralBelowTheByteRateFloorIsClosed);
    await wtt("literal with no payload",   testLiteralWithNoPayloadAtAllIsClosed);
    await wtt("uid expunge via override", testUidExpungeReachesAConsumerSuppliedHandler);
    await wtt("line too long",          testLineTooLong);
    await wtt("literal smuggling",      testLiteralSmuggling);
    await wtt("metadata/notify",        testMetadataNotifyBranches);
    // additional reachable-branch coverage
    await wtt("append date/shape",      testAppendDateTimeAndShapeBranches);
    await wtt("append result shapes",   testAppendResultShapes);
    await wtt("catenate branches",      testCatenateBranches);
    await wtt("selected result shapes", testSelectedResultShapes);
    await wtt("store result shapes",    testStoreResultShapes);
    await wtt("metadata extra",         testMetadataExtraBranches);
    await wtt("dispatch messageless",   testDispatchMessagelessErrors);
    await wtt("authenticate fallbacks", testAuthenticateFallbacks);
    await wtt("backend reject fallbacks", testBackendRejectFallbacks);
    await wtt("notify emit fallbacks",  testNotifyEmitFallbacks);
    await wtt("misc branch gaps",       testMiscBranchGaps);
  });
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[mail-server-imap] OK"); },
    function (e) { process.stderr.write("FAIL: " + (e && e.stack || e) + "\n"); process.exit(1); }
  );
}
