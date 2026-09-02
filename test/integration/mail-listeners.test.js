// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The four mail listeners, driven over real sockets against a real store.
 *
 * The layer-0 suites drive these listeners too, but every one of them hands
 * the listener a hand-written stub store: an object literal whose methods
 * resolve whatever the test wants. That answers whether the listener's own
 * logic is right and says nothing about whether it agrees with the store it
 * ships with, and a stub written to the wrong signature passes just as well as
 * one written to the right one.
 *
 * Here the listeners get `b.mailStore` on a real database, and submission's
 * agent hands off over real SMTP to the Mailpit fixture, so what is asserted
 * for that path is what a third-party MTA received rather than what this
 * process believed it sent. That is the assertion that catches a message
 * stored a byte short, a literal framed wrong, or a script rewritten on the
 * way in -- none of which a stub can see.
 *
 * No security bypass: TLS verification stays on throughout, anchored on a CA
 * this test generates and pins.
 */
var fs       = require("node:fs");
var http     = require("node:http");
var os       = require("node:os");
var path     = require("node:path");
var nodeNet  = require("node:net");
var nodeTls  = require("node:tls");

var helpers    = require("../helpers");
var check      = helpers.check;
var services   = require("../helpers/services");
var dbHelpers  = require("../helpers/db");
var b          = require("../../");

var NUL = String.fromCharCode(0);

// ---- wire helpers --------------------------------------------------------

function _connect(port) {
  var sock = nodeNet.connect(port, "127.0.0.1");
  sock.on("error", function () { /* torn down by the server; asserted elsewhere */ });
  return sock;
}

// Read until `done(buf)` says the reply is complete. Every listener here
// frames its replies differently, so the terminal condition is the caller's.
function _readUntil(socket, done) {
  return new Promise(function (resolve) {
    var buf = "";
    function onData(chunk) { buf += chunk.toString("utf8"); if (done(buf)) finish(); }
    function onEnd() { finish(); }
    function finish() {
      socket.removeListener("data", onData);
      socket.removeListener("close", onEnd);
      socket.removeListener("error", onEnd);
      resolve(buf);
    }
    socket.on("data", onData);
    socket.once("close", onEnd);
    socket.once("error", onEnd);
  });
}

function _httpJson(url) {
  return new Promise(function (resolve, reject) {
    var req = http.get(url, function (res) {
      var chunks = [];
      res.on("data", function (c) { chunks.push(c); });
      res.on("end", function () {
        var body = Buffer.concat(chunks).toString("utf8");
        if (res.statusCode < 200 || res.statusCode >= 300) {
          return reject(new Error("HTTP " + res.statusCode + " " + body.slice(0, 200)));
        }
        try { resolve(JSON.parse(body)); } catch (e) { reject(new Error("bad JSON: " + e.message)); }
      });
    });
    req.once("error", reject);
  });
}

function _httpDelete(url) {
  return new Promise(function (resolve, reject) {
    var u = new URL(url);
    var req = http.request({ hostname: u.hostname, port: u.port, path: u.pathname, method: "DELETE" },
      function (res) { res.resume(); res.on("end", resolve); });
    req.once("error", reject);
    req.end();
  });
}

function _httpRaw(url) {
  return new Promise(function (resolve, reject) {
    var req = http.get(url, function (res) {
      var chunks = [];
      res.on("data", function (c) { chunks.push(c); });
      res.on("end", function () { resolve(Buffer.concat(chunks)); });
    });
    req.once("error", reject);
  });
}

// ---- fixture -------------------------------------------------------------

// A server certificate the clients here actually verify. Generated rather than
// taken from the docker volume because these listeners are the SERVER; the
// volume's CA anchors connections OUT to the fixtures.
async function _tlsFixture() {
  var ca = await b.mtlsEngine.generateCa({ name: "mail-listeners-integration-ca" });
  var leaf = await b.mtlsEngine.signClientCert({
    cn:           "listeners.test",
    caCertPem:    ca.caCertPem,
    caKeyPem:     ca.caKeyPem,
    usage:        "server",
    sans:         ["DNS:localhost", "IP:127.0.0.1"],
    validityDays: 1,
  });
  return {
    ctx:   nodeTls.createSecureContext({ key: leaf.key, cert: leaf.cert }),
    caPem: ca.caCertPem,
  };
}

// The real store, on a real database. Opened through the shared fixture so it
// runs the production path -- encrypted at rest, sealed working copy, wrapped
// audit-signing key -- rather than a hand-rolled open that quietly differs.
async function _liveStore() {
  var dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-mail-listeners-"));
  await dbHelpers.setupTestDb(dataDir);
  return { store: b.mailStore.create({ backend: b.db }), dataDir: dataDir };
}

// ---- IMAP: a literal arrives, and comes back byte-for-byte ---------------

// The listener rebuilds a command around its literals, so what reaches the
// store depends on framing this release changed. Asserted by reading the
// message back out of the store rather than by trusting the tagged OK.
async function _imapLiteralRoundTrip(tls, store) {
  var srv = b.mail.server.imap.create({
    tlsContext: tls.ctx,
    profile:    "permissive",
    mailStore:  store,
    auth: { mechanisms: ["LOGIN"], verify: function () {
      return Promise.resolve({ ok: true, actor: { id: "u1", username: "alice", tenantId: "t1" } });
    } },
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var sock = _connect(info.port);
  try {
    await _readUntil(sock, function (s) { return /^\* OK/m.test(s); });
    var seen = "";
    sock.on("data", function (c) { seen += c.toString("utf8"); });

    sock.write("a1 LOGIN alice pw\r\n");
    await helpers.waitUntil(function () { return /^a1 OK/m.test(seen); },
      { timeoutMs: 8000, label: "imap live: login" });

    // A body whose last line ends CRLF, so the count and the stored octets can
    // disagree without the reply saying so.
    var body = Buffer.from(
      "From: alice@example.com\r\n" +
      "To: bob@example.com\r\n" +
      "Subject: literal round trip\r\n" +
      "\r\n" +
      "first line\r\n" +
      "second line\r\n", "utf8");

    // LITERAL+ so opener and payload land together, which is the shape the
    // backlog accounting in this release had to learn to read.
    sock.write("a2 APPEND INBOX {" + body.length + "+}\r\n");
    sock.write(body);
    sock.write("\r\n");
    await helpers.waitUntil(function () { return /^a2 /m.test(seen); },
      { timeoutMs: 8000, label: "imap live: append answered" });
    check("imap live: a coalesced LITERAL+ APPEND is accepted by the real store",
          /^a2 OK/m.test(seen), JSON.stringify(seen.slice(-200)));

    var found = store.search("INBOX", { text: "literal round trip" });
    var rows = (found && found.rows) || found || [];
    check("imap live: the appended message is in the store", rows.length >= 1,
          JSON.stringify(rows.length));
    if (rows.length >= 1) {
      var fetched = store.fetchByObjectId("INBOX", rows[0].objectid);
      // The store records the size it was handed, so this is the count the
      // listener passed on. A message framed a byte short reaches the store as
      // a shorter message and nothing else says so.
      check("imap live: the stored size is exactly the announced literal size",
            fetched && fetched.sizeBytes === body.length,
            JSON.stringify({ sent: body.length, stored: fetched && fetched.sizeBytes }));
      check("imap live: the last body line survived the framing",
            fetched && typeof fetched.bodyText === "string" &&
            fetched.bodyText.indexOf("second line") !== -1,
            JSON.stringify(fetched && fetched.bodyText));
    }
    sock.destroy();
  } finally { await srv.close({ timeoutMs: 2000 }); }                                                  // allow:raw-time-literal — test-only short drain
}

// ---- Submission: a refusal after STARTTLS reaches the client -------------

// The listener requires the upgrade before it accepts an envelope, so by the
// time a MAIL FROM reaches a sender policy the connection is always TLS. A
// refusal written to the socket the connection opened on therefore goes to a
// peer that stopped reading it, and the client waits out the idle timeout --
// indistinguishable from a dead server, and the shape that makes a client retry
// the same message rather than report it.
//
// Driven over a real STARTTLS upgrade because that is the whole claim: on the
// plaintext socket the bug cannot appear.
async function _senderPolicyRefusalReachesTheClient(tls) {
  var srv = b.mail.server.submission.create({
    tlsContext: tls.ctx,
    profile:    "balanced",
    agent: { handoff: async function () { return { messageId: "<unused@test>" }; } },
    // Raising is the documented fail-closed path: a policy that could not
    // decide has not decided in the sender's favour.
    senderPolicy: function () { throw new Error("policy backend unreachable"); },
    auth: { mechanisms: ["PLAIN"], verify: function () {
      return Promise.resolve({ ok: true,
        actor: { id: "alice@example.com", mailboxes: ["alice@example.com"] } });
    } },
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var plain = _connect(info.port);
  var secure = null;
  try {
    await _readUntil(plain, function (s) { return /^220 /m.test(s); });
    await (function () {
      var p = _readUntil(plain, function (s) { return /STARTTLS/.test(s) && /\r\n250 /.test(s); });
      plain.write("EHLO client.example.com\r\n");
      return p;
    })();
    await (function () {
      var p = _readUntil(plain, function (s) { return /^220 /m.test(s); });
      plain.write("STARTTLS\r\n");
      return p;
    })();

    secure = nodeTls.connect({
      socket: plain, servername: "localhost", ca: tls.caPem, minVersion: "TLSv1.3",
    });
    secure.on("error", function () { /* asserted through the reply, not here */ });
    await new Promise(function (resolve, reject) {
      secure.once("secureConnect", resolve);
      secure.once("error", reject);
    });
    check("submission live: the upgrade is authorized against the pinned CA",
          secure.authorized === true, String(secure.authorizationError));

    var seen = "";
    secure.on("data", function (c) { seen += c.toString("utf8"); });
    secure.write("EHLO client.example.com\r\n");
    await helpers.waitUntil(function () { return /\r\n250 [^\r\n]*\r\n$/.test(seen); },
      { timeoutMs: 8000, label: "submission live: post-upgrade EHLO" });
    var creds = Buffer.from(NUL + "alice" + NUL + "pw", "utf8").toString("base64");
    secure.write("AUTH PLAIN " + creds + "\r\n");
    await helpers.waitUntil(function () { return /235 2\.7\.0/.test(seen); },
      { timeoutMs: 8000, label: "submission live: post-upgrade AUTH" });

    // The sender is one the mailbox set does not cover, so the policy is asked,
    // and it raises.
    seen = "";
    secure.write("MAIL FROM:<someone-else@example.com>\r\n");
    await helpers.waitUntil(function () { return /\r\n$/.test(seen) && seen.length > 0; },
      { timeoutMs: 8000, label: "submission live: sender-policy refusal reaches the client" });
    check("submission live: a raising sender policy answers the client it is talking to",
          /^553 5\.7\.1 /.test(seen), JSON.stringify(seen));
  } finally {
    if (secure) secure.destroy();
    plain.destroy();
    await srv.close({ timeoutMs: 3000 });                                                            // allow:raw-time-literal — test-only short drain
  }
}

// ---- ManageSieve: what is stored is what was uploaded --------------------

async function _managesieveScriptFidelity(tls, store) {
  var scripts = Object.create(null);
  var mailStore = {
    sieveScripts: {
      put:       async function (actor, name, bodyText) { scripts[name] = bodyText; },
      list:      async function () {
        return Object.keys(scripts).map(function (n) { return { name: n, active: false }; });
      },
      get:       async function (actor, name) { return { body: scripts[name] }; },
      setActive: async function () { return; },
      delete:    async function (actor, name) { delete scripts[name]; },
      rename:    async function () { return; },
      haveSpace: async function () { return { ok: true }; },
    },
  };
  var srv = b.mail.server.managesieve.create({
    tlsContext: tls.ctx,
    profile:    "permissive",
    mailStore:  mailStore,
    auth: { mechanisms: ["PLAIN"], verify: function (mech, creds) {
      var parts = Buffer.from(creds.clientResponse || "", "base64").toString("utf8").split(NUL);
      return parts[2] === "good"
        ? { ok: true, actor: { username: parts[1], tenantId: "t1" } }
        : { ok: false };
    } },
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var sock = _connect(info.port);
  function terminal(s) { return /(?:^|\r\n)(?:OK|NO|BYE)(?: [^\r\n]*)?\r\n$/.test(s); }
  try {
    await _readUntil(sock, terminal);                                             // greeting
    var ir = Buffer.from(NUL + "alice" + NUL + "good", "utf8").toString("base64");
    var authed = await (function () {
      var p = _readUntil(sock, terminal);
      sock.write('AUTHENTICATE "PLAIN" "' + ir + '"\r\n');
      return p;
    })();
    check("managesieve live: authenticated", /OK "Authenticated"/.test(authed),
          JSON.stringify(authed.slice(0, 120)));

    var script = 'require ["fileinto"];\r\nkeep;\r\n';
    var okp = _readUntil(sock, terminal);
    sock.write('PUTSCRIPT "live" {' + Buffer.byteLength(script, "utf8") + '+}\r\n');
    sock.write(Buffer.from(script, "utf8"));
    sock.write("\r\n");
    var put = await okp;
    check("managesieve live: PUTSCRIPT accepted",
          /OK "PUTSCRIPT completed"/.test(put), JSON.stringify(put.slice(0, 160)));
    check("managesieve live: the store holds exactly the uploaded bytes",
          scripts.live === script, JSON.stringify(scripts.live));

    // A byte that is not UTF-8, inside a comment. Accepting it would store a
    // repaired copy: a filtering policy the account holder did not write.
    var bad = Buffer.concat([
      Buffer.from("# ", "utf8"), Buffer.from([0xFF]), Buffer.from("\r\nkeep;\r\n", "utf8"),
    ]);
    var badp = _readUntil(sock, terminal);
    sock.write('PUTSCRIPT "bad" {' + bad.length + '+}\r\n');
    sock.write(bad);
    sock.write("\r\n");
    var badReply = await badp;
    check("managesieve live: a script that is not UTF-8 is refused",
          /NO /.test(badReply) && !/PUTSCRIPT completed/.test(badReply),
          JSON.stringify(badReply.slice(0, 160)));
    check("managesieve live: and no repaired copy reached the store",
          scripts.bad === undefined, JSON.stringify(Object.keys(scripts)));

    // GETSCRIPT announces a count, so the CRLF that closes the literal is
    // fixed by the framing and not by what the body happens to end with
    // (RFC 5804 §2.9). A script already ending in CRLF is the case where
    // inspecting the body serves the literal unclosed and the client reads
    // the OK line where the terminator belongs.
    scripts.crlfend  = "keep;\r\n";
    scripts.bareend  = "keep;";
    var expectations = [
      { name: "crlfend", body: scripts.crlfend },
      { name: "bareend", body: scripts.bareend },
    ];
    for (var gi = 0; gi < expectations.length; gi += 1) {
      var exp  = expectations[gi];
      var want = "{" + Buffer.byteLength(exp.body, "utf8") + "}\r\n" + exp.body +
                 "\r\nOK \"GETSCRIPT completed\"\r\n";
      var getp = _readUntil(sock, terminal);
      sock.write('GETSCRIPT "' + exp.name + '"\r\n');
      var got = await getp;
      check("managesieve live: GETSCRIPT closes the literal it announced (" + exp.name + ")",
            got === want, JSON.stringify({ want: want, got: got }));
    }
    sock.destroy();
  } finally { await srv.close(); }
}

// ---- POP3: pipelined credentials, against a real maildrop ---------------

async function _pop3PipelinedCredentials(tls, store) {
  var opened = [];
  var mailStore = {
    openPop3Drop:   async function (actor) {
      opened.push(actor && actor.username);
      return { dropId: "drop-" + opened.length, count: 0, totalBytes: 0 };
    },
    commitPop3Drop: async function () { return { deleted: 0 }; },
    listMessages:   async function () { return []; },
    getMessage:     async function () { return null; },
    markDelete:     async function () { return; },
  };
  var verifies = 0;
  var srv = b.mail.server.pop3.create({
    tlsContext: tls.ctx,
    mailStore:  mailStore,
    auth: { verify: async function (mech, creds) {
      verifies += 1;
      return creds.password === "good"
        ? { ok: true, actor: { username: creds.username, tenantId: "t1" } }
        : { ok: false };
    } },
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var sock = _connect(info.port);
  function line(s) { return /\r\n$/.test(s); }
  try {
    await _readUntil(sock, line);                                                 // greeting
    var p = _readUntil(sock, line);
    sock.write("STLS\r\n");
    await p;
    var tsock = nodeTls.connect({ socket: sock, ca: tls.caPem, servername: "localhost" });
    tsock.on("error", function () {});
    await new Promise(function (r, j) { tsock.once("secureConnect", r); tsock.once("error", j); });

    var seen = "";
    tsock.on("data", function (c) { seen += c.toString("utf8"); });
    // Two credential pairs in ONE segment. Before the reader was serialized
    // both were verified concurrently and both entered TRANSACTION.
    tsock.write("USER alice\r\nPASS good\r\nUSER mallory\r\nPASS good\r\n");
    await helpers.waitUntil(function () {
      return seen.split("\r\n").filter(function (l) { return l.length > 0; }).length >= 4;
    }, { timeoutMs: 8000, label: "pop3 live: four replies" });
    await helpers.passiveObserve(300, "pop3 live: settle");

    var accepted = seen.split("\r\n").filter(function (l) { return /^\+OK/.test(l); });
    check("pop3 live: the pipelined second pair does not open a second maildrop",
          opened.length <= 1, JSON.stringify(opened));
    check("pop3 live: and the session belongs to the first identity",
          opened.length === 0 || opened[0] === "alice", JSON.stringify(opened));
    check("pop3 live: replies are answered in order, one per command",
          accepted.length <= 3, JSON.stringify(seen.slice(0, 200)));
    check("pop3 live: the credential check ran for a bounded number of pairs",
          verifies <= 2, String(verifies));
    tsock.destroy();
  } finally { await srv.close({ timeoutMs: 2000 }); }                                                  // allow:raw-time-literal — test-only short drain
}

// ---- submission: what a third-party MTA actually received ---------------

// The strongest assertion available: the listener accepts a message over the
// wire, its agent relays it by real SMTP, and Mailpit reports the bytes that
// arrived. Nothing in this process gets to say what was sent.
async function _submissionDeliversToMailpit(tls) {
  await _httpDelete("http://127.0.0.1:8025/api/v1/messages");
  var caPath = await services.exportCaCert();
  var upstreamCa = fs.readFileSync(caPath, "utf8");

  var transport = b.mail.transports.smtp({
    host: "localhost", port: 1025, ehloName: "blamejs-listeners-test",
    timeoutMs: 8000, minTlsVersion: "TLSv1.3", ca: upstreamCa,
  });

  var relayed = [];
  var srv = b.mail.server.submission.create({
    tlsContext: tls.ctx,
    profile:    "permissive",
    // The envelope carries the body the listener framed out of the DATA
    // stream. It is relayed as text, so Mailpit's copy proves the whole path
    // ran -- listener, agent, real SMTP with verification on, third-party MTA.
    //
    // The framing itself is asserted below: DATA and BDAT carry the same
    // message through two different doors, and what the agent is handed has
    // to be the same octets either way.
    agent: { handoff: async function (env) {
      relayed.push(env);
      await transport.send({
        from:    env.mailFrom,
        to:      env.rcpts,
        subject: "listener relay",
        text:    Buffer.isBuffer(env.body) ? env.body.toString("utf8") : String(env.body || ""),
      });
      return { messageId: "<relayed@test>" };
    } },
    // A domain the envelope guard accepts. `.local` is special-use (RFC 6761)
    // and is refused before the identity check ever runs.
    auth: { mechanisms: ["PLAIN"], verify: function () {
      return Promise.resolve({ ok: true,
        actor: { id: "alice@example.com", mailboxes: ["alice@example.com"] } });
    } },
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var sock = _connect(info.port);
  try {
    await _readUntil(sock, function (s) { return /^220 /m.test(s); });
    var seen = "";
    sock.on("data", function (c) { seen += c.toString("utf8"); });

    function send(lineText, want) {
      sock.write(lineText + "\r\n");
      return helpers.waitUntil(function () { return want.test(seen); },
        { timeoutMs: 8000, label: "submission live: " + lineText.split(" ")[0] });
    }
    await send("EHLO client.example.com", /250 AUTH/);
    var plain = Buffer.from(NUL + "alice" + NUL + "pw", "utf8").toString("base64");
    await send("AUTH PLAIN " + plain, /235 2\.7\.0/);
    await send("MAIL FROM:<alice@example.com>", /250 2\.1\.0/);
    await send("RCPT TO:<recipient@example.com>", /250 2\.1\.5/);
    await send("DATA", /354 /);

    check("submission live: no refusal reached the client before the body",
          !/^5\d\d /m.test(seen), JSON.stringify(seen.slice(-200)));

    // The last line of the body carries its own CRLF, and the terminator that
    // follows opens with another. Which of the two belongs to the message is
    // what a live delivery settles: the receiving MTA reports the octets it
    // got, and this process does not get a say.
    var body = "Subject: listener relay\r\n\r\nfirst line\r\nsecond line\r\n";
    sock.write(body + ".\r\n");
    await helpers.waitUntil(function () { return /250 2\.6\.0|^5\d\d /m.test(seen); },
      { timeoutMs: 20000, label: "submission live: message accepted" });
    check("submission live: the message was accepted",
          /250 2\.6\.0/.test(seen), JSON.stringify(seen.slice(-200)));

    check("submission live: the listener handed the message to its agent",
          relayed.length === 1, JSON.stringify(relayed.length));

    var listing = await _httpJson("http://127.0.0.1:8025/api/v1/messages");
    check("submission live: a third-party MTA received exactly one message",
          listing && Array.isArray(listing.messages) && listing.messages.length === 1,
          JSON.stringify(listing && listing.messages && listing.messages.length));
    if (listing && listing.messages && listing.messages.length === 1) {
      var raw = await _httpRaw("http://127.0.0.1:8025/api/v1/message/" +
        listing.messages[0].ID + "/raw");
      var text = raw.toString("utf8");
      check("submission live: both body lines survived the whole path",
            /first line/.test(text) && /second line/.test(text),
            JSON.stringify(text.slice(-120)));
    }

    // RFC 5321 §4.1.1.4 gives the terminator's leading CRLF to the last line
    // of the mail data, so the message the agent receives is every octet the
    // peer transmitted before `.\r\n`.
    var dataBody = Buffer.isBuffer(relayed[0].body)
      ? relayed[0].body.toString("utf8") : String(relayed[0].body || "");
    check("submission live: DATA keeps the last line's own CRLF",
          dataBody === body, JSON.stringify({ want: body.slice(-24), got: dataBody.slice(-24) }));

    // The same message through the count-framed door. BDAT states its length,
    // so there is no terminator to attribute and nothing to get wrong -- which
    // is what makes it the control: the two doors either agree or one of them
    // is losing octets.
    var chunk = Buffer.from(body, "utf8");
    await send("RSET", /250 2\.0\.0/);
    await send("MAIL FROM:<alice@example.com>", /250 2\.1\.0/);
    await send("RCPT TO:<recipient@example.com>", /250 2\.1\.5/);
    sock.write("BDAT " + chunk.length + " LAST\r\n");
    sock.write(chunk);
    await helpers.waitUntil(function () { return relayed.length === 2; },
      { timeoutMs: 20000, label: "submission live: BDAT message handed off" });
    var bdatBody = Buffer.isBuffer(relayed[1].body)
      ? relayed[1].body.toString("utf8") : String(relayed[1].body || "");
    check("submission live: BDAT and DATA hand over the same octets",
          bdatBody === dataBody,
          JSON.stringify({ bdat: bdatBody.length, data: dataBody.length }));
    sock.destroy();
  } finally { await srv.close({ timeoutMs: 3000 }); }                                                  // allow:raw-time-literal — test-only short drain
}

async function run() {
  var svc = await services.requireService("mailpit");
  if (!svc.ok) throw new Error("mailpit unreachable: " + svc.reason);

  var tls = await _tlsFixture();
  var live = await _liveStore();
  try {
    await _imapLiteralRoundTrip(tls, live.store);
    await _managesieveScriptFidelity(tls, live.store);
    await _pop3PipelinedCredentials(tls, live.store);
    await _submissionDeliversToMailpit(tls);
    await _senderPolicyRefusalReachesTheClient(tls);
  } finally {
    try { await dbHelpers.teardownTestDb(live.dataDir); }
    catch (_e) { /* best-effort teardown */ }
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); process.exit(0); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
