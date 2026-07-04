// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.mail.server.pop3 — command-handler + error-branch coverage driven over a
 * real localhost listener (plaintext AUTHORIZATION path + STLS->TLS upgrade +
 * authenticated TRANSACTION path). The sibling mail-server-pop3.test.js covers
 * create() opts validation; this file drives the RFC 1939 / RFC 2595 command
 * dispatch (CAPA/STLS/USER/PASS/STAT/LIST/RETR/TOP/UIDL/DELE/RSET/NOOP/QUIT)
 * and its wrong-state / malformed / not-found refusals that the happy-path
 * suites never reach. Every assertion drives the public API over a socket.
 *
 * Run standalone: `node test/layer-0-primitives/mail-server-pop3-coverage.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

var nodeNet = require("node:net");
var nodeTls = require("node:tls");

var NUL = String.fromCharCode(0);

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
  var ca = await b.mtlsEngine.generateCa({ name: "pop3-cov-ca" });
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

async function run() {
  await testPlaintextDispatch();
  await testAuthenticatedTransaction();
  await testAuthPlainMechanism();
  await testEdgeCases();
}

if (require.main === module) {
  run().then(function () { console.log("mail-server-pop3-coverage OK — " + helpers.getChecks() + " checks"); },
    function (e) { console.error(e && e.stack || e); process.exit(1); });
}

module.exports = { run: run };
