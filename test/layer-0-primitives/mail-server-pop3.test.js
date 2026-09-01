// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.mail.server.pop3 — create() opts validation plus command-handler and
 * error-branch behavior driven over a real localhost listener (plaintext
 * AUTHORIZATION path + STLS->TLS upgrade + authenticated TRANSACTION path):
 * the RFC 1939 / RFC 2595 command dispatch (CAPA/STLS/USER/PASS/STAT/LIST/
 * RETR/TOP/UIDL/DELE/RSET/NOOP/QUIT) and its wrong-state / malformed /
 * not-found refusals. Every socket assertion drives the public API.
 *
 * Run standalone: `node test/layer-0-primitives/mail-server-pop3.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var check = helpers.check;
var b = helpers.b;

var nodeNet = require("node:net");
var nodeTls = require("node:tls");

var NUL = String.fromCharCode(0);

function testSurface() {
  check("namespace",    typeof b.mail.server.pop3 === "object");
  check("create fn",    typeof b.mail.server.pop3.create === "function");
  check("error class",  typeof b.mail.server.pop3.MailServerPop3Error === "function");
}

function _stubMailStore() {
  return {
    openPop3Drop:    async function () { return { dropId: "drop-1", count: 0, totalBytes: 0 }; },
    commitPop3Drop:  async function () { return { deleted: 0 }; },
    listMessages:    async function () { return []; },
    getMessage:      async function () { return null; },
    markDelete:      async function () { return; },
  };
}

function testRequiresTlsContext() {
  var threw = null;
  try { b.mail.server.pop3.create({ mailStore: _stubMailStore() }); }
  catch (e) { threw = e; }
  check("create refuses missing tlsContext",
    threw && threw.code === "mail-server-pop3/no-tls-context");
  check("error message points at b.mail.server.tls.context",
    threw && /b\.mail\.server\.tls\.context/.test(threw.message));
}

function testRequiresMailStore() {
  var threw = null;
  try { b.mail.server.pop3.create({ tlsContext: {} }); }
  catch (e) { threw = e; }
  check("create refuses missing mailStore",
    threw && threw.code === "mail-server-pop3/no-mail-store");
}

function testRequiresMailStoreOpenPop3Drop() {
  var threw = null;
  try { b.mail.server.pop3.create({ tlsContext: {}, mailStore: {} }); }
  catch (e) { threw = e; }
  check("create refuses mailStore without openPop3Drop",
    threw && threw.code === "mail-server-pop3/no-mail-store");
}

function testBadBoundsRefused() {
  function expectBad(label, opts) {
    var threw = null;
    try { b.mail.server.pop3.create(opts); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf("mail-server-pop3/") === 0);
  }
  expectBad("refuses negative maxLineBytes",
    { tlsContext: {}, mailStore: _stubMailStore(), maxLineBytes: -1 });
  expectBad("refuses Infinity idleTimeoutMs",
    { tlsContext: {}, mailStore: _stubMailStore(), idleTimeoutMs: Infinity });
}

function _readReply(socket, multiline) {
  return new Promise(function (resolve, reject) {
    var buf = "";
    function onData(chunk) {
      buf += chunk.toString("utf8");
      var done = multiline ? (/\r\n\.\r\n$/.test(buf) || /^-ERR/.test(buf)) : /\r\n$/.test(buf);
      if (done) { socket.removeListener("data", onData); socket.removeListener("error", onErr); resolve(buf); }
    }
    function onErr(e) { socket.removeListener("data", onData); reject(e); }
    socket.on("data", onData);
    socket.once("error", onErr);
  });
}
function _send(socket, line, multiline) {
  var p = _readReply(socket, multiline);
  socket.write(line + "\r\n");
  return p;
}

async function _makeTestTlsContext() {
  var ca = await b.mtlsEngine.generateCa({ name: "pop3-test-ca" });
  var leaf = await b.mtlsEngine.signClientCert({
    cn: "pop3.test", caCertPem: ca.caCertPem, caKeyPem: ca.caKeyPem,
    usage: "server", sans: ["DNS:localhost", "IP:127.0.0.1"], validityDays: 1,
  });
  return { ctx: nodeTls.createSecureContext({ key: leaf.key, cert: leaf.cert }), caPem: ca.caCertPem };
}

function _stubStore() {
  var msgs = [
    { msgNum: 1, size: 14, uid: "uid-1", bytes: Buffer.from("Subject: a\r\n\r\nhi") },
    { msgNum: 2, size: 5,  uid: "uid-2", bytes: Buffer.from("world") },
  ];
  return {
    openPop3Drop:   async function () { return { dropId: "drop-1", count: msgs.length, totalBytes: 19 }; },
    commitPop3Drop: async function () { return { deleted: 0 }; },
    listMessages:   async function () { return msgs.map(function (m) { return { msgNum: m.msgNum, size: m.size, uid: m.uid, uidl: m.uid }; }); },
    getMessage:     async function (actor, dropId, n) { var f = msgs.find(function (m) { return m.msgNum === n; }); return f ? { size: f.size, rawBytes: f.bytes } : null; },
    markDelete:     async function () { return; },
  };
}

async function _makeServer(extra) {
  var tls = await _makeTestTlsContext();
  var opts = {
    tlsContext: tls.ctx,
    mailStore:  _stubStore(),
    auth: { verify: async function (mech, creds) {
      // PASS gives parsed username/password; AUTH gives a raw base64 SASL blob
      // in clientResponse (authzid NUL authcid NUL passwd) for us to decode.
      var username = creds.username, password = creds.password;
      if (creds.clientResponse) {
        var parts = Buffer.from(creds.clientResponse, "base64").toString("utf8").split(NUL);
        username = parts[1]; password = parts[2];
      }
      return password === "good"
        ? { ok: true, actor: { username: username, tenantId: "t1" } }
        : { ok: false };
    } },
  };
  if (extra) { Object.keys(extra).forEach(function (k) { opts[k] = extra[k]; }); }
  var srv = b.mail.server.pop3.create(opts);
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  return { srv: srv, port: info.port, caPem: tls.caPem };
}

// ---- plaintext AUTHORIZATION path: dispatch + wrong-state + malformed ----
async function testPlaintextDispatch() {
  var s = await _makeServer();
  var sock = nodeNet.connect(s.port, "127.0.0.1");
  sock.on("error", function () {});
  try {
    check("greeting is +OK", /^\+OK/.test(await _readReply(sock)));
    check("CAPA lists STLS", /STLS/.test(await _send(sock, "CAPA", true)));
    check("RETR before auth refused", /^-ERR/.test(await _send(sock, "RETR 1")));
    check("STAT before auth refused", /^-ERR/.test(await _send(sock, "STAT")));
    check("USER over cleartext refused (RFC 2595)", /^-ERR/.test(await _send(sock, "USER alice")));
    check("unknown verb refused", /^-ERR/.test(await _send(sock, "FLOOP")));
    check("NOOP ok", /^\+OK/.test(await _send(sock, "NOOP")));
    check("empty line refused", /^-ERR/.test(await _send(sock, "")));
    check("QUIT in authorization ok", /^\+OK/.test(await _send(sock, "QUIT")));
  } finally { sock.destroy(); await s.srv.close(); }
}

// ---- STLS->TLS upgrade + authenticated TRANSACTION path ----
async function testAuthenticatedTransaction() {
  var s = await _makeServer();
  var sock = nodeNet.connect(s.port, "127.0.0.1");
  sock.on("error", function () {});
  await _readReply(sock); // greeting
  check("STLS begins negotiation", /^\+OK/.test(await _send(sock, "STLS")));
  var tls = nodeTls.connect({ socket: sock, ca: s.caPem, servername: "localhost" });
  tls.on("error", function () {});
  await new Promise(function (r, j) { tls.once("secureConnect", r); tls.once("error", j); });
  try {
    check("USER accepted over TLS", /^\+OK/.test(await _send(tls, "USER alice")));
    check("PASS with bad creds refused", /^-ERR/.test(await _send(tls, "PASS wrong")));
    check("USER re-issued after failure", /^\+OK/.test(await _send(tls, "USER alice")));
    check("PASS with good creds authenticates", /^\+OK/.test(await _send(tls, "PASS good")));
    check("USER after auth refused (already authenticated)", /^-ERR/.test(await _send(tls, "USER bob")));
    check("STAT returns count+size", /^\+OK 2 /.test(await _send(tls, "STAT")));
    check("LIST all is multiline", /\r\n\.\r\n$/.test(await _send(tls, "LIST", true)));
    check("LIST single ok", /^\+OK 1 /.test(await _send(tls, "LIST 1")));
    check("LIST out-of-range refused", /^-ERR/.test(await _send(tls, "LIST 99")));
    check("RETR existing returns body", /octets/.test(await _send(tls, "RETR 1", true)));
    check("RETR missing refused", /^-ERR/.test(await _send(tls, "RETR 99")));
    check("RETR non-numeric refused", /^-ERR/.test(await _send(tls, "RETR abc")));
    check("TOP existing ok", /^\+OK/.test(await _send(tls, "TOP 1 0", true)));
    check("TOP missing refused", /^-ERR/.test(await _send(tls, "TOP 99 0")));
    check("UIDL all is multiline", /\r\n\.\r\n$/.test(await _send(tls, "UIDL", true)));
    check("UIDL single ok", /^\+OK 1 /.test(await _send(tls, "UIDL 1")));
    check("DELE marks message", /^\+OK/.test(await _send(tls, "DELE 1")));
    check("NOOP in transaction ok", /^\+OK/.test(await _send(tls, "NOOP")));
    check("RSET clears delete marks", /^\+OK/.test(await _send(tls, "RSET")));
    check("STLS after TLS refused", /^-ERR/.test(await _send(tls, "STLS")));
    check("QUIT commits + closes", /^\+OK/.test(await _send(tls, "QUIT")));
  } finally { tls.destroy(); sock.destroy(); await s.srv.close(); }
}

// ---- AUTH PLAIN mechanism over TLS ----
// The AUTHORIZATION-state guards read `state.stage` and `state.actor`, and the
// stage moves only after an async verify resolves. The drain loop dispatched
// every complete line in the buffer without awaiting any of them, so a client
// that wrote both credential pairs in ONE segment had all four lines
// dispatched while the stage was still "authorization" and the actor still
// null. Both guards passed, and two verifies raced to own the session.
async function testPipelinedCredentialsCannotRaceTheAuthGuard() {
  var s = await _makeServer();
  var sock = nodeNet.connect(s.port, "127.0.0.1");
  sock.on("error", function () {});
  await _readReply(sock);                                    // greeting
  await _send(sock, "STLS");
  var tls = nodeTls.connect({ socket: sock, ca: s.caPem, servername: "localhost" });
  tls.on("error", function () {});
  await new Promise(function (r, j) { tls.once("secureConnect", r); tls.once("error", j); });
  try {
    var seen = "";
    tls.on("data", function (c) { seen += c.toString("utf8"); });

    // One write. Nothing here awaits a reply, which is the point.
    tls.write("USER alice\r\nPASS good\r\nUSER bob\r\nPASS good\r\n");
    await helpers.waitUntil(function () {
      return seen.split("\r\n").filter(function (l) { return l.length > 0; }).length >= 4;
    }, { timeoutMs: 5000, label: "pop3 pipeline: four replies" });
    await helpers.passiveObserve(300, "pop3 pipeline: settle");

    var replies = seen.split("\r\n").filter(function (l) { return l.length > 0; });
    var oks = replies.filter(function (l) { return l.indexOf("+OK") === 0; });
    // One session authenticates once. Three or four +OK means the
    // re-authentication guard was passed.
    check("a pipelined second credential pair does not authenticate again",
          oks.length <= 2, JSON.stringify(replies));
    tls.destroy();
  } finally { await s.srv.close({ timeoutMs: 1000 }); }                                                 // allow:raw-time-literal — test-only short drain
}

// The same race on the OTHER authentication verb. Serializing the reader only
// helps for handlers that hand their work back to it, and the stage moves
// inside a chain that runs after the credential check resolves.
async function testPipelinedAuthVerbsCannotRaceEither() {
  var s = await _makeServer();
  var sock = nodeNet.connect(s.port, "127.0.0.1");
  sock.on("error", function () {});
  await _readReply(sock);                                    // greeting
  await _send(sock, "STLS");
  var tls = nodeTls.connect({ socket: sock, ca: s.caPem, servername: "localhost" });
  tls.on("error", function () {});
  await new Promise(function (r, j) { tls.once("secureConnect", r); tls.once("error", j); });
  try {
    var seen = "";
    tls.on("data", function (c) { seen += c.toString("utf8"); });

    // SASL PLAIN is authzid NUL authcid NUL passwd. NUL is the module
    // constant, never a byte typed into this file.
    var plain = Buffer.from(NUL + "alice" + NUL + "good", "utf8").toString("base64");
    tls.write("AUTH PLAIN " + plain + "\r\nAUTH PLAIN " + plain + "\r\n");
    await helpers.waitUntil(function () {
      return seen.split("\r\n").filter(function (l) { return l.length > 0; }).length >= 2;
    }, { timeoutMs: 5000, label: "pop3 pipelined AUTH: two replies" });
    await helpers.passiveObserve(300, "pop3 pipelined AUTH: settle");

    var replies = seen.split("\r\n").filter(function (l) { return l.length > 0; });
    var oks = replies.filter(function (l) { return l.indexOf("+OK") === 0; });
    check("a pipelined second AUTH does not authenticate again",
          oks.length <= 1, JSON.stringify(replies));
    tls.destroy();
  } finally { await s.srv.close({ timeoutMs: 1000 }); }                                                 // allow:raw-time-literal — test-only short drain
}

// Commands wait while a handler runs, so the buffer holds a queue. A client
// that sends faster than the handlers complete would grow it for as long as it
// liked, which a per-line cap cannot bound because it says nothing about how
// many lines are held.
async function testPipelinedBacklogIsBounded() {
  // The pump has to be BUSY for a backlog to exist at all: with fast handlers
  // the buffer drains as quickly as it fills and never grows. So the verify is
  // held open while the client keeps sending.
  var release = null;
  var gate = new Promise(function (r) { release = r; });
  var s = await _makeServer({
    auth: { verify: function () { return gate.then(function () { return { ok: false }; }); } },
  });
  var sock = nodeNet.connect(s.port, "127.0.0.1");
  sock.on("error", function () {});
  await _readReply(sock);                                    // greeting
  await _send(sock, "STLS");
  var tls = nodeTls.connect({ socket: sock, ca: s.caPem, servername: "localhost" });
  tls.on("error", function () {});
  await new Promise(function (r, j) { tls.once("secureConnect", r); tls.once("error", j); });
  try {
    var seen = "";
    var closed = false;
    tls.on("data", function (c) { seen += c.toString("utf8"); });
    tls.on("close", function () { closed = true; });

    // The cap holds on the FIRST data event too, before any handler is
    // running: a single write carrying more than the allowance takes the
    // pump-not-yet-started path, and a bound checked only once a pump is
    // already running would let that whole buffer through.
    var upfront = "";
    for (var u = 0; u < 3000; u += 1) upfront += "NOOP\r\n";
    tls.write(upfront);
    await helpers.waitUntil(function () { return closed || /Too much pipelined data/.test(seen); },
      { timeoutMs: 5000, label: "pop3 backlog: first-chunk flood refused" });
    check("a first data event past the allowance is refused, not drained",
          /Too much pipelined data/.test(seen) || closed, JSON.stringify(seen.slice(-160)));
    tls.destroy();
    await s.srv.close({ timeoutMs: 1000 });                                                             // allow:raw-time-literal — test-only short drain

    // And again with a handler held open, which is the other way a backlog
    // forms.
    s = await _makeServer({
      auth: { verify: function () { return gate.then(function () { return { ok: false }; }); } },
    });
    sock = nodeNet.connect(s.port, "127.0.0.1");
    sock.on("error", function () {});
    await _readReply(sock);
    await _send(sock, "STLS");
    tls = nodeTls.connect({ socket: sock, ca: s.caPem, servername: "localhost" });
    tls.on("error", function () {});
    await new Promise(function (r, j) { tls.once("secureConnect", r); tls.once("error", j); });
    seen = "";
    closed = false;
    tls.on("data", function (c) { seen += c.toString("utf8"); });
    tls.on("close", function () { closed = true; });

    // Start a credential check that will not finish, so the reader is holding.
    tls.write("USER alice\r\nPASS good\r\n");
    await helpers.waitUntil(function () { return /Send password/.test(seen); },
      { timeoutMs: 5000, label: "pop3 backlog: verify in flight" });

    // Then keep sending. Well past eight lines' worth of the 1024-byte
    // default, in valid short commands, with nothing draining them.
    var flood = "";
    for (var i = 0; i < 3000; i += 1) flood += "NOOP\r\n";
    tls.write(flood);

    await helpers.waitUntil(function () { return closed || /Too much pipelined data/.test(seen); },
      { timeoutMs: 5000, label: "pop3 backlog: refused or closed" });
    check("a backlog past the pipeline allowance is refused, not buffered",
          /Too much pipelined data/.test(seen) || closed, JSON.stringify(seen.slice(-160)));
    tls.destroy();
  } finally { if (release) release(); await s.srv.close({ timeoutMs: 1000 }); }                          // allow:raw-time-literal — test-only short drain
}

// Refusing a backlog closes the connection, and the reader has to stop with
// it. The pump was waiting on a handler; when that handler settles its
// continuation resumes, and unless closing marks the session the queued
// commands are executed on a connection the server already refused.
async function testRefusedBacklogStopsTheReader() {
  var release = null;
  var gate = new Promise(function (r) { release = r; });
  // STAT reaches the store through listMessages, and only once the session is
  // in TRANSACTION — so the verify SUCCEEDS here. Otherwise the state guard
  // refuses the queued command for its own reasons and the test would pass
  // whether or not the reader had stopped.
  var seenVerbs = [];
  var store = _stubStore();
  var origList = store.listMessages;
  store.listMessages = function () {
    seenVerbs.push("listMessages");
    return origList.apply(this, arguments);
  };
  var s = await _makeServer({
    mailStore: store,
    auth: { verify: function () {
      return gate.then(function () {
        return { ok: true, actor: { username: "alice", tenantId: "t1" } };
      });
    } },
  });
  var sock = nodeNet.connect(s.port, "127.0.0.1");
  sock.on("error", function () {});
  await _readReply(sock);                                    // greeting
  await _send(sock, "STLS");
  var tls = nodeTls.connect({ socket: sock, ca: s.caPem, servername: "localhost" });
  tls.on("error", function () {});
  await new Promise(function (r, j) { tls.once("secureConnect", r); tls.once("error", j); });
  try {
    var seen = "";
    tls.on("data", function (c) { seen += c.toString("utf8"); });

    // Hold the reader on a credential check that will not finish.
    tls.write("USER alice\r\nPASS good\r\n");
    await helpers.waitUntil(function () { return /Send password/.test(seen); },
      { timeoutMs: 5000, label: "refused backlog: verify in flight" });

    // Then overrun the allowance, with a real command at the end of the queue.
    var flood = "";
    for (var i = 0; i < 3000; i += 1) flood += "NOOP\r\n";
    tls.write(flood + "STAT\r\n");
    await helpers.waitUntil(function () { return /Too much pipelined data/.test(seen); },
      { timeoutMs: 5000, label: "refused backlog: refusal written" });

    // Release the handler the reader was waiting on. Its continuation must not
    // pick the queue back up.
    release();
    await helpers.passiveObserve(500, "refused backlog: nothing resumes");
    check("a command queued behind a refused backlog is not executed",
          seenVerbs.length === 0, JSON.stringify(seenVerbs));
    tls.destroy();
  } finally { if (release) release(); await s.srv.close({ timeoutMs: 1000 }); }                          // allow:raw-time-literal — test-only short drain
}

// The same stop, on the other close path. A post-STLS idle timeout is wired
// separately from the plaintext one and hands the upgraded socket to the
// close, so a close that does not take the session leaves the reader believing
// the connection is still live and it runs the peer's queued commands after
// the teardown wrote -ERR and destroyed the socket.
async function testPostStlsTimeoutStopsTheReader() {
  var releaseList = null;
  var listCalled  = false;
  var marked      = [];
  var store = _stubStore();
  store.listMessages = function () {
    listCalled = true;
    return new Promise(function (r) { releaseList = function () { r([]); }; });
  };
  store.markDelete = async function (actor, dropId, n) { marked.push(n); };
  var s = await _makeServer({
    mailStore:     store,
    idleTimeoutMs: b.constants.TIME.seconds(0.3),
  });
  var sock = nodeNet.connect(s.port, "127.0.0.1");
  sock.on("error", function () {});
  await _readReply(sock);                                    // greeting
  await _send(sock, "STLS");
  var tls = nodeTls.connect({ socket: sock, ca: s.caPem, servername: "localhost" });
  tls.on("error", function () {});
  await new Promise(function (r, j) { tls.once("secureConnect", r); tls.once("error", j); });
  try {
    await _send(tls, "USER alice");
    await _send(tls, "PASS good");                           // TRANSACTION

    var seen = "";
    tls.on("data", function (c) { seen += c.toString("utf8"); });
    // One segment: the reader takes STAT and waits on a store call that does
    // not resolve, so DELE is still queued when the connection goes idle.
    tls.write("STAT\r\nDELE 1\r\n");
    await helpers.waitUntil(function () { return listCalled; },
      { timeoutMs: 5000, label: "post-STLS timeout: STAT reached the store" });
    await helpers.waitUntil(function () { return /Idle timeout/.test(seen); },
      { timeoutMs: 5000, label: "post-STLS timeout: idle -ERR written" });

    releaseList();
    await helpers.passiveObserve(500, "post-STLS timeout: nothing resumes");
    check("a command queued behind a running handler does not run after a post-TLS timeout",
          marked.length === 0, JSON.stringify(marked));
    tls.destroy();
  } finally { if (releaseList) releaseList(); await s.srv.close({ timeoutMs: 1000 }); }                  // allow:raw-time-literal — test-only short drain
}

async function testAuthPlainMechanism() {
  var s = await _makeServer();
  var sock = nodeNet.connect(s.port, "127.0.0.1");
  sock.on("error", function () {});
  await _readReply(sock);
  await _send(sock, "STLS");
  var tls = nodeTls.connect({ socket: sock, ca: s.caPem, servername: "localhost" });
  tls.on("error", function () {});
  await new Promise(function (r, j) { tls.once("secureConnect", r); tls.once("error", j); });
  try {
    // SASL PLAIN (RFC 4616): authzid NUL authcid NUL passwd, base64-encoded.
    var sasl = ["", "alice", "good"].join(NUL);
    var authArg = Buffer.from(sasl, "utf8").toString("base64");
    check("AUTH PLAIN with inline creds authenticates", /^\+OK/.test(await _send(tls, "AUTH PLAIN " + authArg)));
    check("STAT after AUTH ok", /^\+OK/.test(await _send(tls, "STAT")));
  } finally { tls.destroy(); sock.destroy(); await s.srv.close(); }
}

// The real rate limiter, with noteAuthFailure counted. Wrapping the shipped
// handle rather than hand-rolling one keeps every other method's behaviour
// exactly as the listener will meet it in production.
function _countingRateLimit(onFailure) {
  var real = b.mail.server.rateLimit.create({});
  var wrapper = {};
  Object.keys(real).forEach(function (k) {
    wrapper[k] = typeof real[k] === "function"
      ? function () { return real[k].apply(real, arguments); }
      : real[k];
  });
  wrapper.noteAuthFailure = function (ip) { onFailure(); return real.noteAuthFailure(ip); };
  return wrapper;
}

// ---- multi-step SASL: a challenge is a round trip, not a failure ----
//
// The verifier contract lets an operator mechanism ask for another round trip
// by returning { pending: true, challenge }. IMAP and submission honour it;
// POP3 called verify once, passed no `step`, and dropped a pending verdict
// into the failure branch — which also SPENT the client's authentication
// failure budget, the thing that exists to slow down credential guessing.
async function testAuthMultiStepChallenge() {
  var calls = [];
  var failures = 0;
  var s = await _makeServer({
    auth: {
      mechanisms: ["CRAM-STYLE"],
      verify: async function (mech, creds) {
        calls.push({ mech: mech, step: creds.step, clientResponse: creds.clientResponse });
        if (calls.length === 1) {
          return { pending: true, challenge: Buffer.from("nonce-42").toString("base64") };
        }
        return creds.clientResponse === "cmVzcG9uc2U="                                 // base64("response")
          ? { ok: true, actor: { username: "alice", tenantId: "t1" } }
          : { ok: false };
      },
    },
    rateLimit: _countingRateLimit(function () { failures += 1; }),
  });
  var sock = nodeNet.connect(s.port, "127.0.0.1");
  sock.on("error", function () {});
  await _readReply(sock);
  await _send(sock, "STLS");
  var tls = nodeTls.connect({ socket: sock, ca: s.caPem, servername: "localhost" });
  tls.on("error", function () {});
  await new Promise(function (r, j) { tls.once("secureConnect", r); tls.once("error", j); });
  try {
    var challenge = await _send(tls, "AUTH CRAM-STYLE");
    check("pop3: a pending verdict writes a continuation, not -ERR",
          /^\+ /.test(challenge), JSON.stringify(challenge));
    check("pop3: the continuation carries the verifier's challenge",
          challenge.indexOf(Buffer.from("nonce-42").toString("base64")) !== -1,
          JSON.stringify(challenge));

    var done = await _send(tls, "cmVzcG9uc2U=");
    check("pop3: the client's reply completes the exchange",
          /^\+OK/.test(done), JSON.stringify(done));
    check("pop3: verify saw two steps, numbered",
          calls.length === 2 && calls[0].step === 0 && calls[1].step === 1,
          JSON.stringify(calls));
    check("pop3: the client's base64 reply reached the verifier, not the verb table",
          calls[1].clientResponse === "cmVzcG9uc2U=", JSON.stringify(calls[1]));
    check("pop3: a challenge round trip costs no auth-failure budget",
          failures === 0, String(failures));
    check("pop3: authenticated after the exchange", /^\+OK/.test(await _send(tls, "STAT")));
  } finally { tls.destroy(); sock.destroy(); await s.srv.close(); }
}

// The control for the check above: a genuinely failed multi-step exchange must
// still spend the budget, or "no failure counted" would just mean the counter
// is dead.
async function testAuthMultiStepFailureStillCounts() {
  var failures = 0;
  var s = await _makeServer({
    auth: {
      mechanisms: ["CRAM-STYLE"],
      verify: async function (mech, creds) {
        if (creds.step === 0) return { pending: true, challenge: "" };
        return { ok: false };
      },
    },
    rateLimit: _countingRateLimit(function () { failures += 1; }),
  });
  var sock = nodeNet.connect(s.port, "127.0.0.1");
  sock.on("error", function () {});
  await _readReply(sock);
  await _send(sock, "STLS");
  var tls = nodeTls.connect({ socket: sock, ca: s.caPem, servername: "localhost" });
  tls.on("error", function () {});
  await new Promise(function (r, j) { tls.once("secureConnect", r); tls.once("error", j); });
  try {
    await _send(tls, "AUTH CRAM-STYLE");
    var bad = await _send(tls, "d3Jvbmc=");                                             // base64("wrong")
    check("pop3: a wrong response to the challenge is -ERR", /^-ERR/.test(bad), JSON.stringify(bad));
    check("pop3: and it DOES spend the auth-failure budget", failures === 1, String(failures));
  } finally { tls.destroy(); sock.destroy(); await s.srv.close(); }
}

// The shared check itself, exercised directly. It now guards the SASL
// continuation on three listeners (imap / pop3 / submission), so its own
// boundary is worth pinning rather than inferring from one caller.
function testSaslChallengeGuard() {
  var mailServerNet = require("../../lib/mail-server-net.js");
  var g = mailServerNet.saslChallengeOrNull;
  check("sasl guard: an ordinary base64 challenge passes through",
        g("bm9uY2UtNDI=") === "bm9uY2UtNDI=");
  check("sasl guard: an empty challenge is valid (RFC 4422 §3)", g("") === "");
  check("sasl guard: CR is refused",   g("abc\rdef") === null);
  check("sasl guard: LF is refused",   g("abc\ndef") === null);
  check("sasl guard: CRLF is refused", g("abc\r\n+OK") === null);
  check("sasl guard: NUL is refused",  g("abc" + NUL + "def") === null);
  check("sasl guard: a terminator at the very end is still refused",
        g("abc\r\n") === null);
  check("sasl guard: a non-string is refused", g(undefined) === null && g(42) === null);
}

// A SASL challenge is written straight to the wire, and it is not always the
// operator's own text: SCRAM and CRAM compose theirs from the client's nonce,
// so client bytes reach that line. A CR or LF in it ends the reply early and
// the rest is read as a second server response.
async function testAuthChallengeCannotInjectALine() {
  var s = await _makeServer({
    auth: {
      mechanisms: ["EVIL"],
      verify: async function () {
        return { pending: true, challenge: "abc\r\n+OK Logged in" };
      },
    },
  });
  var sock = nodeNet.connect(s.port, "127.0.0.1");
  sock.on("error", function () {});
  await _readReply(sock);
  await _send(sock, "STLS");
  var tls = nodeTls.connect({ socket: sock, ca: s.caPem, servername: "localhost" });
  tls.on("error", function () {});
  await new Promise(function (r, j) { tls.once("secureConnect", r); tls.once("error", j); });
  try {
    var reply = await _send(tls, "AUTH EVIL");
    check("pop3: a challenge carrying CRLF is refused, not written",
          /^-ERR/.test(reply), JSON.stringify(reply));
    check("pop3: the smuggled +OK never reaches the client",
          reply.indexOf("+OK") === -1, JSON.stringify(reply));
    // And the connection is not left mid-exchange: the next line must be
    // parsed as a verb again, not swallowed as a SASL response.
    check("pop3: the failed exchange releases the connection",
          /^-ERR/.test(await _send(tls, "STAT")));
  } finally { tls.destroy(); sock.destroy(); await s.srv.close(); }
}

// ---- error / enumeration / malformed-argument branches ----
async function testEdgeCases() {
  var s = await _makeServer({ maxLineBytes: b.constants.BYTES.bytes(64) });
  var sock = nodeNet.connect(s.port, "127.0.0.1");
  sock.on("error", function () {});
  try {
    await _readReply(sock); // greeting
    check("AUTH with no mechanism enumerates (RFC 5034)", /^\+OK/.test(await _send(sock, "AUTH", true)));
    check("AUTH PLAIN over cleartext refused (RFC 2595)", /^-ERR/.test(await _send(sock, "AUTH PLAIN")));
    check("PASS without prior USER refused", /^-ERR/.test(await _send(sock, "PASS secret")));
    check("APOP handled (refused under strict / no shared secret)", /^-ERR/.test(await _send(sock, "APOP alice deadbeef")));
    check("DELE in authorization refused", /^-ERR/.test(await _send(sock, "DELE 1")));
    // Overlong line: exceeds the 64-byte cap -> -ERR + close.
    var longArg = "USER " + new Array(200).join("a");
    var reply = await _send(sock, longArg);
    check("overlong line refused", /^-ERR/.test(reply));
  } finally { sock.destroy(); await s.srv.close(); }
}

// ---- raw byte-stream connection collector -------------------------------
// A single accumulator over the socket lets pipelined / async-window /
// server-initiated-close scenarios be asserted with helpers.waitUntil
// (poll, never a bare setTimeout) without interleaving multiple `data`
// readers on the same socket.
function _conn(port) {
  var sock = nodeNet.connect(port, "127.0.0.1");
  var acc = "";
  var closed = false;
  sock.on("data", function (chunk) { acc += chunk.toString("utf8"); });
  sock.on("error", function () {});
  sock.on("close", function () { closed = true; });
  return {
    sock:     sock,
    text:     function () { return acc; },
    isClosed: function () { return closed; },
    send:     function (line) { try { sock.write(line + "\r\n"); } catch (_e) { /* socket down */ } },
    writeRaw: function (buf)  { try { sock.write(buf); } catch (_e) { /* socket down */ } },
    waitFor:  function (re, label) {
      return helpers.waitUntil(function () { return re.test(acc); },
        { timeoutMs: 5000, label: "pop3 reply: " + (label || String(re)) });
    },
    waitClosed: function (label) {
      return helpers.waitUntil(function () { return closed; },
        { timeoutMs: 5000, label: "pop3 close: " + (label || "connection") });
    },
    destroy: function () { try { sock.destroy(); } catch (_e) { /* idempotent */ } },
  };
}

// Drive one command sequence on a fresh connection and assert the reply.
async function _driveOnce(port, lines, expectRe, label) {
  var c = _conn(port);
  try {
    await c.waitFor(/ready\r\n/, label + " greeting");
    lines.forEach(function (ln) { c.send(ln); });
    await c.waitFor(expectRe, label);
    check(label, expectRe.test(c.text()));
  } finally { c.destroy(); }
}

// One authenticator that covers every mechanism the listener drives:
// PASS (username/password), AUTH PLAIN (base64 authzid NUL authcid NUL
// passwd via clientResponse), and APOP (username + digest). A `boom`
// credential makes verify throw (exercises the .catch branch); `good`
// authenticates; anything else fails closed.
function _fullVerify() {
  return async function (mech, creds) {
    if (mech === "APOP") {
      if (creds.digest === "boom") throw new Error("apop-verify-boom");
      return creds.digest === "good"
        ? { ok: true, actor: { username: creds.username, tenantId: "t1" } }
        : { ok: false };
    }
    var username = creds.username, password = creds.password;
    if (creds.clientResponse) {
      var parts = Buffer.from(creds.clientResponse, "base64").toString("utf8").split(NUL);
      username = parts[1]; password = parts[2];
    }
    if (password === "boom") throw new Error("pass-verify-boom");
    return password === "good"
      ? { ok: true, actor: { username: username, tenantId: "t1" } }
      : { ok: false };
  };
}

// Permissive listener with the full authenticator — the profile that
// exercises the USER/PASS/APOP/AUTH transaction path over plaintext
// (permissive opts out of the cleartext-auth refusal) so the deep
// error/verify branches are reachable without a TLS handshake per case.
async function _makeFullServer(extra) {
  var merged = { profile: "permissive", auth: { verify: _fullVerify(), mechanisms: ["PLAIN"] } };
  if (extra) { Object.keys(extra).forEach(function (k) { merged[k] = extra[k]; }); }
  return _makeServer(merged);
}

function _saslBlob(user, pass) {
  return Buffer.from(["", user, pass].join(NUL), "utf8").toString("base64");
}

// ---- create()-time tenant-scope validation ----
function testTenantScopeCreateValidation() {
  var e1 = null;
  try { b.mail.server.pop3.create({ tlsContext: {}, mailStore: _stubMailStore(), tenantScope: {} }); }
  catch (e) { e1 = e; }
  check("tenantScope without .check refused at create",
    e1 && e1.code === "mail-server-pop3/bad-tenant-scope");
  var e2 = null;
  try { b.mail.server.pop3.create({ tlsContext: {}, mailStore: _stubMailStore(), tenantScope: { check: function () {} } }); }
  catch (e) { e2 = e; }
  check("tenantScope without agentTenantId refused at create",
    e2 && e2.code === "mail-server-pop3/no-agent-tenant-id");
}

// ---- cross-tenant AUTH refusal (and same-tenant accept) ----
async function testTenantScopeEnforcement() {
  var s1 = await _makeFullServer({
    tenantScope:   { check: function () { var e = new Error("wrong tenant"); e.code = "agent-tenant/cross-tenant"; throw e; } },
    agentTenantId: "agent-1",
  });
  try {
    await _driveOnce(s1.port, ["USER alice", "PASS good"], /cross-tenant/, "cross-tenant auth refused");
  } finally { await s1.srv.close(); }

  var s2 = await _makeFullServer({
    tenantScope:   { check: function () { /* same tenant — accept */ } },
    agentTenantId: "agent-1",
  });
  try {
    await _driveOnce(s2.port, ["USER alice", "PASS good"], /Logged in/, "same-tenant auth accepted");
  } finally { await s2.srv.close(); }
}

// ---- CAPA advertises wired SASL mechanisms (uppercased) ----
async function testCapaAdvertisesSasl() {
  var s = await _makeServer({ auth: { verify: _fullVerify(), mechanisms: ["plain", "login"] } });
  var c = _conn(s.port);
  try {
    await c.waitFor(/ready\r\n/, "greeting");
    c.send("CAPA");
    await c.waitFor(/\r\n\.\r\n/, "capa terminator");
    check("CAPA advertises wired SASL mechanisms uppercased", /SASL PLAIN LOGIN\r\n/.test(c.text()));
  } finally { c.destroy(); await s.srv.close(); }
}

// ---- idle timeout closes an authorization-state connection ----
async function testIdleTimeoutClosesConnection() {
  await helpers.withTestTimeout("pop3 idle timeout", async function () {
    var s = await _makeServer({ idleTimeoutMs: 300 });
    var c = _conn(s.port);
    try {
      await c.waitFor(/ready\r\n/, "greeting");
      await c.waitFor(/-ERR Idle timeout/, "idle timeout -ERR");
      check("idle connection receives -ERR Idle timeout", /-ERR Idle timeout/.test(c.text()));
      await c.waitClosed("idle timeout close");
      check("idle connection is closed by the listener", c.isClosed());
    } finally { c.destroy(); await s.srv.close(); }
  }, { timeoutMs: 8000 });
}

// ---- server survives a peer RST (socket error handler) ----
async function testSocketErrorSurvived() {
  var s = await _makeServer();
  var c1 = _conn(s.port);
  try {
    await c1.waitFor(/ready\r\n/, "greeting");
    // Abort with an RST so the server-side socket emits 'error'
    // (ECONNRESET) rather than a clean FIN — exercises the socket
    // error handler; the listener must stay up.
    if (typeof c1.sock.resetAndDestroy === "function") c1.sock.resetAndDestroy();
    else c1.sock.destroy(new Error("reset"));
    var c2 = _conn(s.port);
    try {
      await c2.waitFor(/ready\r\n/, "post-reset greeting");
      check("listener survives a peer RST and still serves new connections",
        /ready/.test(c2.text()));
    } finally { c2.destroy(); }
  } finally { c1.destroy(); await s.srv.close(); }
}

// ---- overlong line with no CRLF is refused + closed ----
async function testLineTooLongNoCrlf() {
  var s = await _makeServer({ maxLineBytes: b.constants.BYTES.bytes(64) });
  var c = _conn(s.port);
  try {
    await c.waitFor(/ready\r\n/, "greeting");
    // 99 bytes, no CRLF — buffer exceeds the 64-byte cap before a line
    // terminator arrives → -ERR + close (distinct from the guard's
    // line-too-long, which needs a terminated line).
    c.writeRaw(Buffer.from(new Array(100).join("A"), "utf8"));
    await c.waitFor(/-ERR Line too long/, "unterminated overlong line");
    check("unterminated overlong line refused", /-ERR Line too long \(cap 64\)/.test(c.text()));
    await c.waitClosed("overlong line close");
  } finally { c.destroy(); await s.srv.close(); }
}

// ---- STLS / AUTH / APOP refused once in TRANSACTION state ----
async function testPostAuthWrongState() {
  var s = await _makeFullServer();
  var c = _conn(s.port);
  try {
    await c.waitFor(/ready\r\n/, "greeting");
    c.send("USER alice"); c.send("PASS good");
    await c.waitFor(/Logged in/, "authenticated");
    c.send("STLS");
    await c.waitFor(/STLS only valid in AUTHORIZATION/, "STLS wrong-state");
    c.send("AUTH PLAIN " + _saslBlob("alice", "good"));
    await c.waitFor(/AUTH only valid in AUTHORIZATION/, "AUTH wrong-state");
    c.send("APOP alice deadbeef");
    await c.waitFor(/APOP only valid in AUTHORIZATION/, "APOP wrong-state");
    check("STLS refused in TRANSACTION (RFC 2595 §4)", /STLS only valid in AUTHORIZATION/.test(c.text()));
    check("AUTH refused in TRANSACTION", /AUTH only valid in AUTHORIZATION/.test(c.text()));
    check("APOP refused in TRANSACTION", /APOP only valid in AUTHORIZATION/.test(c.text()));
  } finally { c.destroy(); await s.srv.close(); }
}

// ---- STLS handshake failure (onError) closes the connection ----
async function testStlsHandshakeFailureClosed() {
  await helpers.withTestTimeout("pop3 stls handshake failure", async function () {
    var s = await _makeServer();
    var c = _conn(s.port);
    try {
      await c.waitFor(/ready\r\n/, "greeting");
      c.send("STLS");
      await c.waitFor(/Begin TLS negotiation/, "stls ack");
      // Feed non-TLS bytes where a ClientHello is expected → the server
      // TLS socket errors → onError → tls_handshake_failed + close.
      c.writeRaw(Buffer.from("this-is-not-a-tls-clienthello-record\r\n\r\n", "utf8"));
      await c.waitClosed("stls handshake failure close");
      check("failed STLS handshake closes the connection", c.isClosed());
    } finally { c.destroy(); await s.srv.close(); }
  }, { timeoutMs: 8000 });
}

// ---- post-handshake idle timeout (STLS onTimeout) ----
async function testTlsIdleTimeoutClosed() {
  await helpers.withTestTimeout("pop3 tls idle timeout", async function () {
    var s = await _makeServer({ idleTimeoutMs: 400 });
    var sock = nodeNet.connect(s.port, "127.0.0.1");
    sock.on("error", function () {});
    var tls = null;
    try {
      await _readReply(sock);                 // greeting
      await _send(sock, "STLS");              // +OK Begin TLS negotiation
      tls = nodeTls.connect({ socket: sock, ca: s.caPem, servername: "localhost" });
      tls.on("error", function () {});
      await new Promise(function (r, j) { tls.once("secureConnect", r); tls.once("error", j); });
      // Go idle so the post-handshake timer fires. The idle-timeout reply MUST
      // arrive DECRYPTED over the TLS channel — the pre-upgrade plain-socket idle
      // timer must NOT survive the STLS upgrade and inject a plaintext "-ERR Idle
      // timeout" into the cipher stream (which the peer sees as a TLS decode error
      // / reset, never a clean decrypted reply). Asserting "closed OR reply" would
      // pass on the plaintext-injection bug, so require the decrypted reply + no
      // TLS error.
      var got = "";
      var tlsErr = null;
      tls.on("data", function (ch) { got += ch.toString("utf8"); });
      tls.on("error", function (e) { tlsErr = e; });
      await helpers.waitUntil(function () { return /-ERR Idle timeout/.test(got) || tlsErr !== null; },
        { timeoutMs: 6000, label: "post-handshake idle timeout reply over TLS" });
      check("post-handshake idle timeout is delivered ENCRYPTED over TLS (no plaintext injection into the cipher stream)",
        /-ERR Idle timeout/.test(got) && tlsErr === null);
    } finally {
      if (tls) tls.destroy();
      sock.destroy();
      await s.srv.close();
    }
  }, { timeoutMs: 9000 });
}

// ---- STLS handshake window is bounded by the idle timeout ----
// A peer that sends STLS then WITHHOLDS the TLS ClientHello must be timed out and
// closed within the idle bound — the upgraded socket arms its idle timer before
// the handshake completes. Disarming the plain timer without arming the TLS one
// (arming only on "secure") would leave this half-open connection + its rate-limit
// slot open indefinitely.
async function testStlsHandshakeIsBounded() {
  await helpers.withTestTimeout("pop3 stls handshake bound", async function () {
    var s = await _makeServer({ idleTimeoutMs: 300 });
    var sock = nodeNet.connect(s.port, "127.0.0.1");
    sock.on("error", function () {});
    try {
      await _readReply(sock);        // greeting
      await _send(sock, "STLS");     // +OK begin TLS — but never start the handshake
      var closed = false;
      sock.on("close", function () { closed = true; });
      await helpers.waitUntil(function () { return closed; },
        { timeoutMs: 4000, label: "pop3 STLS-then-withhold-ClientHello closed within idle bound" });
      check("STLS without a following ClientHello is closed within the idle timeout (handshake bounded)", closed);
    } finally { sock.destroy(); await s.srv.close(); }
  }, { timeoutMs: 9000 });
}

// ---- USER arriving in the auth window (actor set, drop pending) ----
async function testUserDuringAuthWindowRefused() {
  await helpers.withTestTimeout("pop3 user-during-auth-window", async function () {
    var releaseOpen = null;
    var openGate = new Promise(function (res) { releaseOpen = res; });
    var openCalled = false;
    var store = _stubStore();
    store.openPop3Drop = async function () {
      openCalled = true; await openGate;
      return { dropId: "drop-1", count: 0, totalBytes: 0 };
    };
    var s = await _makeFullServer({ mailStore: store });
    var c = _conn(s.port);
    try {
      await c.waitFor(/ready\r\n/, "greeting");
      c.send("USER alice");
      await c.waitFor(/Send password/, "user ack");
      c.send("PASS good");
      // state.actor is set synchronously before openPop3Drop is awaited;
      // wait until the drop-open is in flight (stage still authorization).
      await helpers.waitUntil(function () { return openCalled; },
        { timeoutMs: 5000, label: "openPop3Drop invoked" });
      c.send("USER bob");
      // It is not answered inside the window any more, because the reader
      // does not take a command while the previous one is still running --
      // which is what let a pipelined pair authenticate twice. The guarantee
      // it was written for is stronger now: the command is READ after the
      // session finishes authenticating, and refused then.
      await helpers.passiveObserve(400, "pop3 auth-window: USER bob is not answered yet");
      check("USER sent during the pending-drop window is not answered inside it",
        !/Already authenticated/.test(c.text()), c.text());
      releaseOpen();
      await c.waitFor(/Logged in/, "auth completes after gate release");
      // Read after the session finished authenticating, so the state guard is
      // the one that answers it rather than the already-authenticated guard.
      // Either way it is refused and never grants a second login.
      await c.waitFor(/only valid in AUTHORIZATION|Already authenticated/,
        "USER refused once the window closes");
      check("USER sent during the pending-drop window is refused, not granted",
        /-ERR/.test(c.text()) && c.text().split("+OK").length - 1 <= 3, c.text());
    } finally {
      if (releaseOpen) releaseOpen();
      c.destroy(); await s.srv.close();
    }
  }, { timeoutMs: 9000 });
}

// ---- USER / APOP refused over cleartext under balanced ----
async function testClearttextRefusedBalanced() {
  var s = await _makeServer({ profile: "balanced" });
  try {
    // balanced lets USER/APOP past the wire-protocol guard pre-TLS, but
    // the listener's defense-in-depth refuses the cleartext credential.
    await _driveOnce(s.port, ["USER alice"], /USER refused over cleartext/, "USER over cleartext refused (balanced)");
    await _driveOnce(s.port, ["APOP alice deadbeef"], /APOP refused over cleartext/, "APOP over cleartext refused (balanced)");
  } finally { await s.srv.close(); }
}

// ---- listener with no authenticator wired ----
async function testNoAuthConfigured() {
  var s = await _makeServer({ profile: "permissive", auth: null });
  try {
    await _driveOnce(s.port, ["USER alice", "PASS secret"], /AUTH not configured on this listener/, "PASS with no authConfig");
    await _driveOnce(s.port, ["APOP alice deadbeef"], /AUTH not configured/, "APOP with no authConfig");
    await _driveOnce(s.port, ["AUTH PLAIN " + _saslBlob("alice", "good")], /AUTH not configured/, "AUTH with no authConfig");
  } finally { await s.srv.close(); }
}

// ---- PASS branches: no prior USER, verify-throw, auth-failure budget ----
async function testPassBranches() {
  var s1 = await _makeFullServer();
  try {
    await _driveOnce(s1.port, ["PASS secret"], /PASS only valid after USER/, "PASS before USER refused");
  } finally { await s1.srv.close(); }

  var s2 = await _makeFullServer();
  try {
    await _driveOnce(s2.port, ["USER alice", "PASS boom"], /Authentication failed/, "PASS verify-throw refused");
  } finally { await s2.srv.close(); }

  var s3 = await _makeFullServer({ rateLimit: { authFailuresPerIpPer15Min: 1 } });
  var c = _conn(s3.port);
  try {
    await c.waitFor(/ready\r\n/, "greeting");
    c.send("USER alice"); c.send("PASS wrong");
    await c.waitFor(/Authentication failed/, "first PASS failure");
    c.send("USER alice"); c.send("PASS wrong");
    await c.waitFor(/Too many AUTH failures/, "PASS budget exhausted");
    check("PASS past the auth-failure budget is refused + closed", /Too many AUTH failures/.test(c.text()));
    await c.waitClosed("PASS rate-limit close");
  } finally { c.destroy(); await s3.srv.close(); }
}

// ---- APOP verify branches under permissive ----
async function testApopMechanism() {
  var s = await _makeFullServer();
  try {
    await _driveOnce(s.port, ["APOP alice good"], /Logged in/, "APOP success authenticates");
    await _driveOnce(s.port, ["APOP alice nope"], /Authentication failed/, "APOP bad digest refused");
    await _driveOnce(s.port, ["APOP alice boom"], /Authentication failed/, "APOP verify-throw refused");
  } finally { await s.srv.close(); }

  var s2 = await _makeFullServer({ rateLimit: { authFailuresPerIpPer15Min: 1 } });
  var c = _conn(s2.port);
  try {
    await c.waitFor(/ready\r\n/, "greeting");
    c.send("APOP alice nope");
    await c.waitFor(/Authentication failed/, "first APOP failure");
    c.send("APOP alice nope");
    await c.waitFor(/Too many AUTH failures/, "APOP budget exhausted");
    check("APOP past the auth-failure budget is refused + closed", /Too many AUTH failures/.test(c.text()));
    await c.waitClosed("APOP rate-limit close");
  } finally { c.destroy(); await s2.srv.close(); }
}

// ---- AUTH verify branches under permissive ----
async function testAuthMechanismBranches() {
  var s1 = await _makeFullServer();
  try {
    await _driveOnce(s1.port, ["AUTH PLAIN " + _saslBlob("alice", "wrong")], /Authentication failed/, "AUTH PLAIN bad creds refused");
  } finally { await s1.srv.close(); }

  var s2 = await _makeFullServer();
  try {
    await _driveOnce(s2.port, ["AUTH PLAIN " + _saslBlob("alice", "boom")], /Authentication failed/, "AUTH PLAIN verify-throw refused");
  } finally { await s2.srv.close(); }

  var s3 = await _makeFullServer({ rateLimit: { authFailuresPerIpPer15Min: 1 } });
  var c = _conn(s3.port);
  try {
    await c.waitFor(/ready\r\n/, "greeting");
    c.send("AUTH PLAIN " + _saslBlob("alice", "wrong"));
    await c.waitFor(/Authentication failed/, "first AUTH failure");
    c.send("AUTH PLAIN " + _saslBlob("alice", "wrong"));
    await c.waitFor(/Too many AUTH failures/, "AUTH budget exhausted");
    check("AUTH past the auth-failure budget is refused + closed", /Too many AUTH failures/.test(c.text()));
    await c.waitClosed("AUTH rate-limit close");
  } finally { c.destroy(); await s3.srv.close(); }
}

// ---- backend openPop3Drop rejection surfaces -ERR ----
async function testOpenDropRejects() {
  var store = _stubStore();
  store.openPop3Drop = async function () { throw new Error("drop-locked"); };
  var s = await _makeFullServer({ mailStore: store });
  var c = _conn(s.port);
  try {
    await c.waitFor(/ready\r\n/, "greeting");
    c.send("USER alice"); c.send("PASS good");
    await c.waitFor(/Cannot open drop/, "open-drop rejection");
    check("openPop3Drop rejection surfaces -ERR Cannot open drop",
      /Cannot open drop: drop-locked/.test(c.text()));
  } finally { c.destroy(); await s.srv.close(); }
}

// ---- UPDATE-state commit rejection surfaces -ERR + close ----
async function testQuitCommitFails() {
  var store = _stubStore();
  store.commitPop3Drop = async function () { throw new Error("commit-broke"); };
  var s = await _makeFullServer({ mailStore: store });
  var c = _conn(s.port);
  try {
    await c.waitFor(/ready\r\n/, "greeting");
    c.send("USER alice"); c.send("PASS good");
    await c.waitFor(/Logged in/, "authenticated");
    c.send("QUIT");
    await c.waitFor(/Commit failed/, "commit rejection");
    check("QUIT commit rejection surfaces -ERR Commit failed",
      /Commit failed: commit-broke/.test(c.text()));
    await c.waitClosed("commit-fail close");
  } finally { c.destroy(); await s.srv.close(); }
}

// ---- RSET routes through mailStore.resetPop3Drop when present ----
async function testRsetInvokesResetPop3Drop() {
  var resetCalled = false;
  var store = _stubStore();
  store.resetPop3Drop = async function () { resetCalled = true; };
  var s = await _makeFullServer({ mailStore: store });
  var c = _conn(s.port);
  try {
    await c.waitFor(/ready\r\n/, "greeting");
    c.send("USER alice"); c.send("PASS good");
    await c.waitFor(/Logged in/, "authenticated");
    c.send("RSET");
    await c.waitFor(/delete marks cleared/, "rset ok");
    await helpers.waitUntil(function () { return resetCalled; },
      { timeoutMs: 5000, label: "resetPop3Drop invoked" });
    check("RSET routes through mailStore.resetPop3Drop when present", resetCalled);
  } finally { c.destroy(); await s.srv.close(); }
}

// A mailStore whose method return-shapes exercise the listener's
// defensive fallbacks: listMessages yields a size-less message (STAT's
// `size || 0`) and a uid-less-but-uidl-only message (UIDL's
// `uid || uidl || ""`); getMessage yields a text-only body (the
// `msg.rawBytes ? … : Buffer.from(msg.text || "")` arm) for msg 1 and a
// body already CRLF-terminated (the "don't append a trailing CRLF" arm)
// for msg 2.
function _shapeStore() {
  return {
    openPop3Drop:   async function () { return { dropId: "drop-1", count: 2, totalBytes: 7 }; },
    commitPop3Drop: async function () { return { deleted: 0 }; },
    listMessages:   async function () {
      return [
        { msgNum: 1 },                        // no size, no uid, no uidl
        { msgNum: 2, size: 7, uidl: "U2" },   // uidl-only (no uid)
      ];
    },
    getMessage: async function (actor, dropId, n) {
      if (n === 1) return { size: 5, text: "hi\nthere" };                    // text body, rawBytes absent
      if (n === 2) return { size: 6, rawBytes: Buffer.from("a\r\nb\r\n") };  // already CRLF-terminated
      return null;
    },
    markDelete: async function () { return; },
  };
}

// ---- _enterTransaction refuses when openPop3Drop vanishes post-create ----
// create() validates mailStore.openPop3Drop is a function; a store whose
// method is removed AFTER the listener is built reaches the transaction-
// entry defensive guard.
async function testEnterTransactionMissingOpenDrop() {
  var store = _stubStore();
  var s = await _makeFullServer({ mailStore: store });
  store.openPop3Drop = null;   // removed after create() validated it
  var c = _conn(s.port);
  try {
    await c.waitFor(/ready\r\n/, "greeting");
    c.send("USER alice"); c.send("PASS good");
    await c.waitFor(/Backend missing openPop3Drop/, "missing openPop3Drop");
    check("_enterTransaction refuses when mailStore.openPop3Drop is absent",
      /-ERR Backend missing openPop3Drop/.test(c.text()));
  } finally { c.destroy(); await s.srv.close(); }
}

// ---- per-IP concurrent-connection cap refuses the second connection ----
async function testConnectionRateLimitRefused() {
  var s = await _makeServer({ rateLimit: { maxConcurrentConnectionsPerIp: 1 } });
  var c1 = _conn(s.port);
  try {
    await c1.waitFor(/ready\r\n/, "first connection greeting");
    var c2 = _conn(s.port);
    try {
      await c2.waitFor(/Too many connections/, "second connection refused");
      check("second concurrent connection from the same IP is refused (no greeting)",
        /-ERR Too many connections from your IP/.test(c2.text()) && !/ready/.test(c2.text()));
      await c2.waitClosed("rate-limited connection close");
    } finally { c2.destroy(); }
  } finally { c1.destroy(); await s.srv.close(); }
}

// ---- AUTH MECH with no initial response (RFC 5034 continuation shape) ----
// `AUTH PLAIN` alone (no inline base64) drives the `initialResp = … : null`
// arm; verify sees clientResponse === null and fails closed.
async function testAuthBareMechNoInitialResp() {
  var s = await _makeFullServer();
  try {
    await _driveOnce(s.port, ["AUTH PLAIN"], /Authentication failed/,
      "AUTH PLAIN with no initial response fails closed");
  } finally { await s.srv.close(); }
}

// ---- read/transaction verbs refused pre-auth (the _requireTrans arms) ----
async function testReadCommandsBeforeAuthRefused() {
  var s = await _makeFullServer();
  try {
    await _driveOnce(s.port, ["LIST"],    /Not authorized/, "LIST before auth refused");
    await _driveOnce(s.port, ["UIDL"],    /Not authorized/, "UIDL before auth refused");
    await _driveOnce(s.port, ["TOP 1 0"], /Not authorized/, "TOP before auth refused");
    await _driveOnce(s.port, ["RSET"],    /Not authorized/, "RSET before auth refused");
  } finally { await s.srv.close(); }
}

// ---- listener fallbacks for sparse mailStore return-shapes ----
async function testStoreFallbackShapes() {
  var s = await _makeFullServer({ mailStore: _shapeStore() });
  var sock = nodeNet.connect(s.port, "127.0.0.1");
  sock.on("error", function () {});
  try {
    await _readReply(sock);                                   // greeting
    check("USER over permissive plaintext ok", /^\+OK/.test(await _send(sock, "USER alice")));
    check("PASS good logs in", /Logged in/.test(await _send(sock, "PASS good")));
    check("STAT sums sizes past a size-less message (size || 0)",
      /^\+OK 2 7/.test(await _send(sock, "STAT")));
    check("LIST all terminates", /\r\n\.\r\n$/.test(await _send(sock, "LIST", true)));
    check("UIDL all terminates (uid/uidl/'' fallbacks)", /\r\n\.\r\n$/.test(await _send(sock, "UIDL", true)));
    check("UIDL single, message with neither uid nor uidl", /^\+OK 1 /.test(await _send(sock, "UIDL 1")));
    check("UIDL single, uidl-only fallback", /^\+OK 2 U2/.test(await _send(sock, "UIDL 2")));
    check("UIDL single missing refused", /^-ERR/.test(await _send(sock, "UIDL 99")));
    check("RETR text-body message (rawBytes absent)", /octets/.test(await _send(sock, "RETR 1", true)));
    check("RETR body already CRLF-terminated", /\r\n\.\r\n$/.test(await _send(sock, "RETR 2", true)));
    check("TOP text-body message (rawBytes absent)", /^\+OK/.test(await _send(sock, "TOP 1 0", true)));
    check("TOP body already CRLF-terminated", /\r\n\.\r\n$/.test(await _send(sock, "TOP 2 0", true)));
  } finally { sock.destroy(); await s.srv.close(); }
}

// ---- null listMessages + empty message body drive the `|| []` / `|| ""`
// fallbacks in STAT / LIST / UIDL and the RETR / TOP body builder. ----
async function testNullListAndEmptyBodyFallbacks() {
  var store = _stubStore();
  store.listMessages = async function () { return null; };        // msgs || [] arms
  store.getMessage   = async function () { return { size: 0 }; };  // no rawBytes, no text -> text || ""
  var s = await _makeFullServer({ mailStore: store });
  var sock = nodeNet.connect(s.port, "127.0.0.1");
  sock.on("error", function () {});
  try {
    await _readReply(sock);                                   // greeting
    await _send(sock, "USER alice");
    check("PASS good logs in (null-list store)", /Logged in/.test(await _send(sock, "PASS good")));
    check("STAT with null listMessages -> +OK 0 0", /^\+OK 0 0/.test(await _send(sock, "STAT")));
    check("LIST all with null listMessages terminates", /\r\n\.\r\n$/.test(await _send(sock, "LIST", true)));
    check("UIDL all with null listMessages terminates", /\r\n\.\r\n$/.test(await _send(sock, "UIDL", true)));
    check("RETR message with empty body (text || '')", /octets/.test(await _send(sock, "RETR 1", true)));
    check("TOP message with empty body (text || '')", /\r\n\.\r\n$/.test(await _send(sock, "TOP 1 0", true)));
  } finally { sock.destroy(); await s.srv.close(); }
}

// ---- message-less backend rejections fall back to "backend error" ----
async function testBackendMessagelessRejections() {
  var openStore = _stubStore();
  openStore.openPop3Drop = async function () { throw new Error(""); };   // Error with empty (falsy) message
  var s1 = await _makeFullServer({ mailStore: openStore });
  try {
    await _driveOnce(s1.port, ["USER alice", "PASS good"], /Cannot open drop: backend error/,
      "message-less openPop3Drop rejection uses fallback text");
  } finally { await s1.srv.close(); }

  var commitStore = _stubStore();
  commitStore.commitPop3Drop = async function () { throw new Error(""); };
  var s2 = await _makeFullServer({ mailStore: commitStore });
  var c = _conn(s2.port);
  try {
    await c.waitFor(/ready\r\n/, "greeting");
    c.send("USER alice"); c.send("PASS good");
    await c.waitFor(/Logged in/, "authenticated");
    c.send("QUIT");
    await c.waitFor(/Commit failed: backend error/, "commit message-less rejection");
    check("message-less commitPop3Drop rejection uses fallback text",
      /Commit failed: backend error/.test(c.text()));
    await c.waitClosed("commit-fail close");
  } finally { c.destroy(); await s2.srv.close(); }
}

// ---- cross-tenant refusal with a tenant-less actor + code-less error ----
// Drives the `(actor && actor.tenantId) || null` and `(err && err.code) ||
// null` fallbacks in the refusal audit, across PASS / APOP / AUTH.
async function testTenantRefuseNullFallbacks() {
  var verifyNoTenant = async function (mech, creds) {
    if (mech === "APOP") return { ok: true, actor: { username: creds.username } };
    var u = creds.username, p = creds.password;
    if (creds.clientResponse) {
      var parts = Buffer.from(creds.clientResponse, "base64").toString("utf8").split(NUL);
      u = parts[1]; p = parts[2];
    }
    return p === "good" ? { ok: true, actor: { username: u } } : { ok: false };
  };
  function mk() {
    return _makeServer({
      profile:       "permissive",
      auth:          { verify: verifyNoTenant, mechanisms: ["PLAIN"] },
      tenantScope:   { check: function () { throw new Error("nope"); } },   // no .code
      agentTenantId: "agent-1",
    });
  }
  var s1 = await mk();
  try { await _driveOnce(s1.port, ["USER alice", "PASS good"], /cross-tenant/, "PASS cross-tenant refused (null fallbacks)"); }
  finally { await s1.srv.close(); }
  var s2 = await mk();
  try { await _driveOnce(s2.port, ["APOP alice good"], /cross-tenant/, "APOP cross-tenant refused"); }
  finally { await s2.srv.close(); }
  var s3 = await mk();
  try { await _driveOnce(s3.port, ["AUTH PLAIN " + _saslBlob("alice", "good")], /cross-tenant/, "AUTH cross-tenant refused"); }
  finally { await s3.srv.close(); }
}

// ---- a tenant-less actor authenticates (auth_success `tenantId || null`) ----
async function testAuthSuccessTenantless() {
  var verifyTenantless = async function (mech, creds) {
    return creds.password === "good" ? { ok: true, actor: { username: creds.username } } : { ok: false };
  };
  var s = await _makeServer({ profile: "permissive", auth: { verify: verifyTenantless } });
  try {
    await _driveOnce(s.port, ["USER alice", "PASS good"], /Logged in/, "tenant-less actor logs in (tenantId || null)");
  } finally { await s.srv.close(); }
}

async function run() {
  testSurface();
  testRequiresTlsContext();
  testRequiresMailStore();
  testRequiresMailStoreOpenPop3Drop();
  testBadBoundsRefused();
  testTenantScopeCreateValidation();
  await testPlaintextDispatch();
  await testAuthenticatedTransaction();
  await testPipelinedCredentialsCannotRaceTheAuthGuard();
  await testPipelinedAuthVerbsCannotRaceEither();
  await testPipelinedBacklogIsBounded();
  await testRefusedBacklogStopsTheReader();
  await testPostStlsTimeoutStopsTheReader();
  await testAuthPlainMechanism();
  await testAuthMultiStepChallenge();
  await testAuthMultiStepFailureStillCounts();
  testSaslChallengeGuard();
  await testAuthChallengeCannotInjectALine();
  await testEdgeCases();
  await testTenantScopeEnforcement();
  await testCapaAdvertisesSasl();
  await testIdleTimeoutClosesConnection();
  await testSocketErrorSurvived();
  await testLineTooLongNoCrlf();
  await testPostAuthWrongState();
  await testStlsHandshakeFailureClosed();
  await testTlsIdleTimeoutClosed();
  await testStlsHandshakeIsBounded();
  await testUserDuringAuthWindowRefused();
  await testClearttextRefusedBalanced();
  await testNoAuthConfigured();
  await testPassBranches();
  await testApopMechanism();
  await testAuthMechanismBranches();
  await testOpenDropRejects();
  await testQuitCommitFails();
  await testRsetInvokesResetPop3Drop();
  await testEnterTransactionMissingOpenDrop();
  await testConnectionRateLimitRefused();
  await testAuthBareMechNoInitialResp();
  await testReadCommandsBeforeAuthRefused();
  await testStoreFallbackShapes();
  await testNullListAndEmptyBodyFallbacks();
  await testBackendMessagelessRejections();
  await testTenantRefuseNullFallbacks();
  await testAuthSuccessTenantless();
  await testSessionLifecycleHooks();
  await testLifecycleHooksThatThrow();
  await testLifecycleHooksThatReject();
  await testSessionEndWaitsForStoreWork();
  await testImplicitTls();
}

// RFC 8314 §3 asks for implicit TLS on 995 rather than the in-band upgrade.
// Without it the only arrangement available is a TLS terminator in front of
// 110, and behind one the listener is handed a plaintext connection — so it
// cannot see the TLS it is not part of, and every credential is refused. The
// tell is visible on the wire: a greeting advertising STLS inside an
// established TLS session.
async function testImplicitTls() {
  var s = await _makeServer({ implicitTls: true });
  // No STLS step: TLS from the first byte.
  var tls = nodeTls.connect({ port: s.port, host: "127.0.0.1", ca: s.caPem,
    servername: "localhost" });
  tls.on("error", function () {});
  await new Promise(function (r, j) { tls.once("secureConnect", r); tls.once("error", j); });
  try {
    check("implicit TLS: the greeting arrives over TLS", /^\+OK/.test(await _readReply(tls)));
    var capa = await _send(tls, "CAPA", true);
    check("implicit TLS: STLS is not advertised on this port",
      !/STLS/.test(capa), JSON.stringify(capa));
    check("implicit TLS: and the verb is refused if sent anyway (RFC 8314 §3.3)",
      /^-ERR/.test(await _send(tls, "STLS")));
    // The point of the whole thing: credentials are accepted, because the
    // listener knows the session is encrypted.
    check("implicit TLS: USER accepted", /^\+OK/.test(await _send(tls, "USER alice")));
    check("implicit TLS: PASS accepted over the implicit session",
      /^\+OK/.test(await _send(tls, "PASS good")));
  } finally { tls.destroy(); await s.srv.close(); }

  await testImplicitTlsRefusalIsAClose();
}

// A rate-limit refusal is decided before the socket is wrapped, so writing the
// protocol's refusal line there would put plaintext in front of a peer that is
// mid-handshake: it reads as a handshake failure, the refusal itself is
// unreadable, and the port's "TLS from the first byte" claim is broken by the
// listener. Handshaking first so the line COULD be written would spend a full
// key exchange on every rejected peer — the resource the limit protects.
async function testImplicitTlsRefusalIsAClose() {
  var s = await _makeServer({
    implicitTls: true,
    rateLimit: {
      admitConnection:   function () { return { ok: false, reason: "too-many" }; },
      releaseConnection: function () {},
      checkAuthAdmit:    function () { return { ok: true }; },
      noteAuthFailure:   function () {},
      checkRcptAdmit:    function () { return { ok: true }; },
      noteRcptFailure:   function () {},
      minBytesPerSecond: function () { return 0; },
      bodyRateStarved:   function () { return false; },
      bodyRateWindowMs:  function () { return 1000; },                                                // allow:raw-time-literal — test-only stub window
    },
  });
  var raw = nodeNet.connect(s.port, "127.0.0.1");
  var bytes = Buffer.alloc(0);
  raw.on("error", function () {});
  raw.on("data", function (d) { bytes = Buffer.concat([bytes, d]); });
  await new Promise(function (r) { raw.once("connect", r); });
  await new Promise(function (r) { raw.once("close", r); });
  check("implicit TLS: a refused connection is closed, not answered in plaintext",
    bytes.length === 0, JSON.stringify(bytes.toString("utf8").slice(0, 80)));
  raw.destroy();
  await s.srv.close();
}

// A consumer releases the exclusive maildrop on onSessionEnd, so the end must
// not be reported around store work that is still running. A link dropping
// mid-open would otherwise report the end BEFORE the open acquired the lease —
// stranding a lease whose end has already been announced — and one dropping
// mid-commit would let the next session in while UPDATE is still writing.
async function testSessionEndWaitsForStoreWork() {
  var order = [];
  var releaseOpen = null;
  var store = _stubStore();
  var baseOpen = store.openPop3Drop;
  store.openPop3Drop = function (actor, opts) {
    order.push("open-started");
    return new Promise(function (resolve) {
      releaseOpen = function () {
        order.push("open-finished");
        resolve(baseOpen.call(store, actor, opts));
      };
    });
  };
  var s = await _makeServer({
    mailStore:    store,
    onSessionEnd: function () { order.push("session-end"); },
  });
  var sock = nodeNet.connect(s.port, "127.0.0.1");
  sock.on("error", function () {});
  await _readReply(sock); // greeting
  check("store-work: STLS begins negotiation", /^\+OK/.test(await _send(sock, "STLS")));
  var tls = nodeTls.connect({ socket: sock, ca: s.caPem, servername: "localhost" });
  tls.on("error", function () {});
  await new Promise(function (r, j) { tls.once("secureConnect", r); tls.once("error", j); });
  check("store-work: USER accepted", /^\+OK/.test(await _send(tls, "USER alice")));
  // PASS opens the drop; the stub holds it open until released below.
  tls.write("PASS good\r\n");
  await helpers.waitUntil(function () { return order.indexOf("open-started") !== -1; },
    { timeoutMs: 5000, label: "pop3 store-work: open started" });

  // Drop the link with the open still in flight.
  tls.destroy();
  sock.destroy();
  await helpers.passiveObserve(200, "pop3 store-work: no session end while the open is pending");
  check("store-work: the end is not reported while the open is in flight",
    order.indexOf("session-end") === -1, JSON.stringify(order));

  releaseOpen();
  await helpers.waitUntil(function () { return order.indexOf("session-end") !== -1; },
    { timeoutMs: 5000, label: "pop3 store-work: session end after the open settled" });
  check("store-work: and is reported once the lease it acquired exists",
    order.indexOf("open-finished") < order.indexOf("session-end"), JSON.stringify(order));
  await s.srv.close();

  await testCleartextRefusalChecksTheBudgetBeforeCounting();
  await testSessionEndWaitsForASlowCommit();
  await testSessionEndWaitsForEveryStoreCall();
  await testNoMaildropAfterTheSessionEnded();
}

// The peer can go while its credentials are still being verified. Nothing is
// in flight against the store at that moment, so the end is reported at once —
// and the verify then resolves and opens a maildrop. That lease is taken after
// the only end notification the consumer will ever get, so nothing releases
// it: the account is locked out of its own mailbox by a login that never
// finished.
async function testNoMaildropAfterTheSessionEnded() {
  var ended = [];
  var opened = 0;
  var releaseVerify = null;
  var store = _stubStore();
  var baseOpen = store.openPop3Drop;
  store.openPop3Drop = function (actor, opts) { opened += 1; return baseOpen.call(store, actor, opts); };
  var s = await _makeServer({
    mailStore: store,
    auth: { verify: function () {
      return new Promise(function (resolve) {
        releaseVerify = function () {
          resolve({ ok: true, actor: { username: "alice", tenantId: "t1" } });
        };
      });
    } },
    onSessionEnd: function () { ended.push(1); },
  });
  var sock = nodeNet.connect(s.port, "127.0.0.1");
  sock.on("error", function () {});
  await _readReply(sock);
  await _send(sock, "STLS");
  var tls = nodeTls.connect({ socket: sock, ca: s.caPem, servername: "localhost" });
  tls.on("error", function () {});
  await new Promise(function (r, j) { tls.once("secureConnect", r); tls.once("error", j); });
  await _send(tls, "USER alice");
  tls.write("PASS good\r\n");
  await helpers.waitUntil(function () { return releaseVerify !== null; },
    { timeoutMs: 5000, label: "pop3 late-auth: the verifier was called" });

  // The link goes while the verifier is still deciding.
  tls.destroy();
  sock.destroy();
  await helpers.waitUntil(function () { return ended.length > 0; },
    { timeoutMs: 5000, label: "pop3 late-auth: the session ended" });
  check("late auth: the session end is reported when the link drops",
    ended.length === 1, JSON.stringify(ended));

  releaseVerify();
  await helpers.passiveObserve(300, "pop3 late-auth: no maildrop opened after the end");
  check("late auth: a verdict that lands after the end opens no maildrop",
    opened === 0, String(opened));
  check("late auth: and no second end is reported for it",
    ended.length === 1, JSON.stringify(ended));
  await s.srv.close();
}

// A DELE mutates the maildrop exactly as an open or a commit does, and so does
// an RSET clearing the marks. Tracking only the two operations that came to
// mind would let a link dropping mid-DELE report the session ended, and the
// consumer would release the exclusive lease and admit the next session while
// the previous one is still writing.
async function testSessionEndWaitsForEveryStoreCall() {
  var order = [];
  var releaseDelete = null;
  var store = _stubStore();
  store.markDelete = function () {
    order.push("delete-started");
    return new Promise(function (resolve) {
      releaseDelete = function () { order.push("delete-finished"); resolve(); };
    });
  };
  var s = await _makeServer({
    mailStore:    store,
    onSessionEnd: function () { order.push("session-end"); },
  });
  var sock = nodeNet.connect(s.port, "127.0.0.1");
  sock.on("error", function () {});
  await _readReply(sock);
  await _send(sock, "STLS");
  var tls = nodeTls.connect({ socket: sock, ca: s.caPem, servername: "localhost" });
  tls.on("error", function () {});
  await new Promise(function (r, j) { tls.once("secureConnect", r); tls.once("error", j); });
  await _send(tls, "USER alice");
  check("every store call: PASS accepted", /^\+OK/.test(await _send(tls, "PASS good")));
  tls.write("DELE 1\r\n");
  await helpers.waitUntil(function () { return order.indexOf("delete-started") !== -1; },
    { timeoutMs: 5000, label: "pop3 store-calls: the delete started" });

  tls.destroy();
  sock.destroy();
  await helpers.passiveObserve(250, "pop3 store-calls: no session end while the delete runs");
  check("every store call: the session does not end while a DELE is in flight",
    order.indexOf("session-end") === -1, JSON.stringify(order));

  releaseDelete();
  await helpers.waitUntil(function () { return order.indexOf("session-end") !== -1; },
    { timeoutMs: 5000, label: "pop3 store-calls: session end after the delete settled" });
  check("every store call: and is reported once the drop is no longer being written",
    order.indexOf("delete-finished") < order.indexOf("session-end"), JSON.stringify(order));
  await s.srv.close();
}

// A commit that outruns commitTimeoutMs is answered on the wire — the client
// cannot be left hanging — but the write is still in progress: a timeout gives
// up on the ANSWER, it does not stop the backend. Releasing the maildrop then
// would hand the next session a mailbox that is still being mutated, which is
// the same corruption the deferral exists to prevent, reached by the one path
// that reports failure.
// A cleartext credential verb is refused under the balanced profile, and the
// refusal is COUNTED against the per-IP auth-failure budget on purpose — a
// scanner enumerating over plaintext should spend budget doing it. What it must
// not do is count before asking whether the address is still admitted.
//
// The budget is a rolling window over stored timestamps, not a counter that
// decays: `checkAuthAdmit` prunes entries older than the window and refuses once
// enough remain. So an address already at the cap that keeps ADDING timestamps
// holds the window populated and pushes the end of its own wait forward. Every
// sibling listener closes the connection before anything is counted, so the
// address serves the time it earned; these four branches counted first and
// returned, and the refusals are free — no credential verified, no work done,
// nothing closing the socket. A client looping USER over plaintext could hold
// its own address, and anyone sharing it, out of the listener indefinitely
// without ever presenting a password.
async function testCleartextRefusalChecksTheBudgetBeforeCounting() {
  var verbs = [
    { label: "USER", lines: ["USER alice"] },
    { label: "PASS", lines: ["USER alice", "PASS wrong"] },
    { label: "APOP", lines: ["APOP alice nope"] },
  ];
  for (var i = 0; i < verbs.length; i += 1) {
    var v = verbs[i];
    // Cap of 1, so the SECOND arrival is already over budget. Balanced profile
    // over a plaintext connection is the configuration that reaches these
    // branches at all.
    var s = await _makeFullServer({
      profile: "balanced",
      rateLimit: { authFailuresPerIpPer15Min: 1 },
    });
    var c = _conn(s.port);
    try {
      await c.waitFor(/ready\r\n/, v.label + ": greeting");
      v.lines.forEach(function (ln) { c.send(ln); });
      await c.waitFor(/refused over cleartext/, v.label + ": first cleartext refusal");

      // Second attempt from the same address, now over the cap. It has to be
      // closed rather than served another free refusal — and being served one
      // is what extended the window.
      v.lines.forEach(function (ln) { c.send(ln); });
      await c.waitFor(/Too many AUTH failures/, v.label + ": budget refusal");
      check("pop3 " + v.label + " over cleartext is closed once the address is " +
            "at the per-IP cap, not served another counted refusal",
        /Too many AUTH failures/.test(c.text()));
      await c.waitClosed(v.label + ": rate-limit close");
    } finally { c.destroy(); await s.srv.close(); }
  }
}

async function testSessionEndWaitsForASlowCommit() {
  var order = [];
  var releaseCommit = null;
  var store = _stubStore();
  store.commitPop3Drop = function () {
    order.push("commit-started");
    return new Promise(function (resolve) {
      releaseCommit = function () { order.push("commit-finished"); resolve({ deleted: 0 }); };
    });
  };
  var s = await _makeServer({
    mailStore:        store,
    commitTimeoutMs:  200,
    onSessionEnd:     function () { order.push("session-end"); },
  });
  var sock = nodeNet.connect(s.port, "127.0.0.1");
  sock.on("error", function () {});
  await _readReply(sock);
  check("slow commit: STLS begins negotiation", /^\+OK/.test(await _send(sock, "STLS")));
  var tls = nodeTls.connect({ socket: sock, ca: s.caPem, servername: "localhost" });
  tls.on("error", function () {});
  await new Promise(function (r, j) { tls.once("secureConnect", r); tls.once("error", j); });
  await _send(tls, "USER alice");
  check("slow commit: PASS accepted", /^\+OK/.test(await _send(tls, "PASS good")));
  tls.write("QUIT\r\n");
  await helpers.waitUntil(function () { return order.indexOf("commit-started") !== -1; },
    { timeoutMs: 5000, label: "pop3 slow commit: the commit started" });

  // Past the timeout: the client has been answered and the socket closed, but
  // the write has not finished.
  await helpers.passiveObserve(600, "pop3 slow commit: no session end while the commit runs");
  check("slow commit: the session does not end while the write is still running",
    order.indexOf("session-end") === -1, JSON.stringify(order));

  releaseCommit();
  await helpers.waitUntil(function () { return order.indexOf("session-end") !== -1; },
    { timeoutMs: 5000, label: "pop3 slow commit: session end after the commit settled" });
  check("slow commit: and is reported once the mailbox is no longer being written",
    order.indexOf("commit-finished") < order.indexOf("session-end"), JSON.stringify(order));
  await s.srv.close();
}

// RFC 1939 §3 gives a maildrop to one session at a time, so a store leases it
// exclusively — and had no signal telling it when to let go. A client that
// loses its link never sends QUIT, so the socket just goes away, and the lease
// stays held until a timer the consumer guessed at expires. For that window the
// account holder's own retries are refused, correctly, for a lease genuinely
// still held.
async function testSessionLifecycleHooks() {
  var ended = [];
  var activity = [];
  var s = await _makeServer({
    onSessionEnd: function (actor, sessionId) {
      ended.push({ user: actor && actor.username, sessionId: sessionId });
    },
    onSessionActivity: function (actor, sessionId, verb) {
      activity.push(verb);
    },
  });
  var sock = nodeNet.connect(s.port, "127.0.0.1");
  sock.on("error", function () {});
  await _readReply(sock); // greeting
  check("lifecycle: STLS begins negotiation", /^\+OK/.test(await _send(sock, "STLS")));
  var tls = nodeTls.connect({ socket: sock, ca: s.caPem, servername: "localhost" });
  tls.on("error", function () {});
  await new Promise(function (r, j) { tls.once("secureConnect", r); tls.once("error", j); });
  check("lifecycle: USER accepted", /^\+OK/.test(await _send(tls, "USER alice")));
  check("lifecycle: PASS accepted", /^\+OK/.test(await _send(tls, "PASS good")));
  // NOOP is what the protocol offers as a keepalive, and the listener answers
  // it without touching the store — so a consumer ageing an idle lease never
  // saw it and reaped the lease under a live connection.
  check("lifecycle: NOOP answered", /^\+OK/.test(await _send(tls, "NOOP")));
  check("lifecycle: the keepalive reaches the consumer",
    activity.indexOf("NOOP") !== -1, JSON.stringify(activity));
  check("lifecycle: and so does every other verb",
    activity.indexOf("USER") !== -1 && activity.indexOf("PASS") !== -1,
    JSON.stringify(activity));

  // The case that locks a mailbox: the link drops mid-session. No QUIT, no
  // commit — just a socket that goes away.
  check("lifecycle: no session end reported while the session is open",
    ended.length === 0, JSON.stringify(ended));
  tls.destroy();
  sock.destroy();
  await helpers.waitUntil(function () { return ended.length > 0; },
    { timeoutMs: 5000, label: "pop3 lifecycle: onSessionEnd after a dropped link" });
  check("lifecycle: a dropped link ends the session",
    ended.length === 1, JSON.stringify(ended));
  check("lifecycle: and reports the actor the drop was opened with",
    ended[0].user === "alice" && typeof ended[0].sessionId === "string",
    JSON.stringify(ended[0]));

  // Once only: a socket that errors AND closes emits both, and a consumer
  // releasing by decrementing a holder count would corrupt its own accounting.
  await helpers.passiveObserve(120, "pop3 lifecycle: no second session end");
  check("lifecycle: the end is reported exactly once",
    ended.length === 1, JSON.stringify(ended));
  await s.srv.close();
}

// A consumer hook is a report, not a veto: by the time either one runs, the
// thing it describes has already happened. So a hook that throws must not take
// anything down with it — not the command it fired on, not the connection, and
// least of all the process, since onSessionEnd runs inside the socket's own
// close handler where an escaping throw has no caller left to catch it.
async function testLifecycleHooksThatThrow() {
  var ended = [];
  var s = await _makeServer({
    onSessionActivity: function () { throw new Error("consumer activity hook blew up"); },
    onSessionEnd:      function (actor, sessionId) { ended.push(sessionId); },
  });
  var sock = nodeNet.connect(s.port, "127.0.0.1");
  sock.on("error", function () {});
  await _readReply(sock); // greeting
  check("throwing hook: the command it fired on is still answered",
    /STLS/.test(await _send(sock, "CAPA", true)));
  check("throwing hook: and so is the next one",
    /^\+OK/.test(await _send(sock, "STLS")));
  sock.destroy();
  await helpers.waitUntil(function () { return ended.length > 0; },
    { timeoutMs: 5000, label: "pop3 lifecycle: session end after a throwing activity hook" });
  check("throwing hook: the session still ends exactly once",
    ended.length === 1, JSON.stringify(ended));
  await s.srv.close();

  // The end hook is the dangerous one: it runs from the close handler, so an
  // escaping throw is an uncaught exception on an EventEmitter, not a rejected
  // promise someone can observe.
  var s2 = await _makeServer({
    onSessionEnd: function () { throw new Error("consumer end hook blew up"); },
  });
  var sock2 = nodeNet.connect(s2.port, "127.0.0.1");
  sock2.on("error", function () {});
  await _readReply(sock2);
  sock2.destroy();
  await helpers.passiveObserve(150, "pop3 lifecycle: throwing end hook does not kill the listener");
  var sock3 = nodeNet.connect(s2.port, "127.0.0.1");
  sock3.on("error", function () {});
  check("throwing end hook: the listener still serves the next connection",
    /^\+OK/.test(await _readReply(sock3)));
  sock3.destroy();
  await s2.srv.close();
}

// A consumer hook is more likely to be async than not — releasing a lease is a
// store call — and a rejected promise is the same failure as a throw, arriving
// later. Unobserved it is an unhandled rejection, which under Node's default
// takes the process down: exactly the outcome the synchronous catch prevents
// for the synchronous shape.
async function testLifecycleHooksThatReject() {
  var unhandled   = [];
  var onUnhandled = function (e) { unhandled.push(e); };
  process.on("unhandledRejection", onUnhandled);
  try {
    var ended = [];
    var s = await _makeServer({
      onSessionActivity: async function () { throw new Error("async activity hook rejected"); },
      onSessionEnd:      async function () {
        ended.push(1);
        throw new Error("async end hook rejected");
      },
    });
    var sock = nodeNet.connect(s.port, "127.0.0.1");
    sock.on("error", function () {});
    await _readReply(sock); // greeting
    check("rejecting hook: the command it fired on is still answered",
      /STLS/.test(await _send(sock, "CAPA", true)));
    sock.destroy();
    await helpers.waitUntil(function () { return ended.length > 0; },
      { timeoutMs: 5000, label: "pop3 lifecycle: async end hook ran" });
    // The rejection surfaces a turn after the hook runs, so give it one.
    await helpers.passiveObserve(200, "pop3 lifecycle: no unhandled rejection from a hook");
    check("rejecting hook: no unhandled rejection reaches the process",
      unhandled.length === 0, JSON.stringify(unhandled.map(String)));
    await s.srv.close();
  } finally {
    process.removeListener("unhandledRejection", onUnhandled);
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("[mail-server-pop3] OK"); },
    function (e) { process.stderr.write("FAIL: " + (e && e.stack || e) + "\n"); process.exit(1); });
}
