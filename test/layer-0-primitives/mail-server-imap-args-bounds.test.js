// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The argument readers of SELECT / EXAMINE, STORE and APPEND cost time in
 * proportion to the line an authenticated client sends, and SELECT reads its
 * parameter list by the RFC 7162 grammar.
 *
 * SMOKE_RUN_SOLO: this file measures growth, and a runner sharing its cores
 * with sixty-three siblings reads contention as a curve.
 *
 * Each reader matched a whitespace run with two quantifiers that both accept
 * a space, followed by something that can fail: `\(\s*([^)]+)\)` in the
 * QRESYNC list with no closing parenthesis, and `\s+(.+)$` after
 * UNCHANGEDSINCE and CATENATE with a U+2028 later in the line, which `.`
 * does not match. The engine retried every split of the run. With
 * maxLineBytes raised to 64 KiB a single command held the event loop for
 * 1.1s to 1.5s, and every other connection waited with it.
 *
 * SELECT also passed any parameter list the regex did not recognize, the
 * RFC 7162 seq-match-data form among them, to the store as part of the
 * mailbox name. A parameter list is now parsed or answered BAD, and so is
 * any other text after the mailbox name.
 */

var helpers = require("../helpers");
var check   = helpers.check;
var b       = helpers.b;
var nodeNet = require("node:net");
var nodeTls = require("node:tls");

var LINE_BYTES = 65536;
// U+2028 LINE SEPARATOR: guard-imap-command passes it, and `.` does not match it.
var LS = String.fromCharCode(0x2028);

async function _tlsContext() {
  var ca = await b.mtlsEngine.generateCa({ name: "imap-args-bounds-ca" });
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

function _recordingStore() {
  var calls = { select: [], store: [], catenate: [] };
  return {
    calls: calls,
    appendMessage: function () { return Promise.resolve(); },
    selectFolder:  function (actor, name, opts) {
      calls.select.push({ name: name, opts: opts });
      return Promise.resolve({ uidvalidity: 1, uidnext: 2, modseq: 1, exists: 1,
                               recent: 0, unseen: 0, flags: [] });
    },
    listFolders:   function () { return [{ name: "INBOX", attributes: [], subscribed: true }]; },
    storeFlags:    function (actor, mailbox, seqSet, mode, flags, opts) {
      calls.store.push({ seqSet: seqSet, mode: mode, flags: flags, opts: opts });
      return Promise.resolve([]);
    },
    appendCatenate: function (mailbox, parts, opts) {
      calls.catenate.push({ mailbox: mailbox, parts: parts, opts: opts });
      return Promise.resolve({ uid: 1, uidValidity: 1 });
    },
  };
}

async function _open() {
  var store = _recordingStore();
  var srv = b.mail.server.imap.create({
    tlsContext:   await _tlsContext(),
    mailStore:    store,
    profile:      "permissive",
    maxLineBytes: LINE_BYTES,
    auth:         {
      mechanisms: ["PLAIN"],
      verify: function () {
        return Promise.resolve({ ok: true, actor: { id: "u1", mailboxes: ["INBOX"] } });
      },
    },
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var socket = nodeNet.connect(info.port, "127.0.0.1");
  await new Promise(function (r) { socket.once("connect", r); });
  var seen = "";
  socket.on("data", function (c) { seen += c.toString("utf8"); });
  await helpers.waitUntil(function () { return /\* OK/.test(seen); },
    { timeoutMs: 5000, label: "imap args-bounds: greeting" });
  var counter = 0;
  var conn = {
    store: store,
    cmd: async function (line) {
      counter += 1;
      var tag = "t" + counter;
      var before = seen.length;
      socket.write(tag + " " + line + "\r\n");
      await helpers.waitUntil(function () {
        return new RegExp("^" + tag + " ", "m").test(seen.slice(before));
      }, { timeoutMs: 20000, label: "imap args-bounds: " + tag + " answered" });
      var reply = seen.slice(before);
      var m = new RegExp("^" + tag + " (\\S+)", "m").exec(reply);
      return { text: reply, status: m ? m[1] : null };
    },
    literal: async function (head, body) {
      counter += 1;
      var tag = "t" + counter;
      var before = seen.length;
      socket.write(tag + " " + head + " {" + Buffer.byteLength(body, "utf8") + "}\r\n");
      await helpers.waitUntil(function () { return /^\+ /m.test(seen.slice(before)); },
        { timeoutMs: 5000, label: "imap args-bounds: " + tag + " continuation" });
      socket.write(body + "\r\n");
      await helpers.waitUntil(function () {
        return new RegExp("^" + tag + " ", "m").test(seen.slice(before));
      }, { timeoutMs: 5000, label: "imap args-bounds: " + tag + " answered" });
      var m = new RegExp("^" + tag + " (\\S+)", "m").exec(seen.slice(before));
      return { text: seen.slice(before), status: m ? m[1] : null };
    },
    close: async function () {
      try { socket.destroy(); } catch (_e) { /* best-effort */ }
      try { await srv.close(); } catch (_e) { /* best-effort */ }
    },
  };
  await conn.cmd('LOGIN "u1" "pw"');
  return conn;
}

async function testSelectQresyncCostIsLinear() {
  var c = await _open();
  try {
    var first = await helpers.looksSuperlinearAsync(async function (n) {
      await c.cmd("SELECT INBOX (QRESYNC (" + " ".repeat(n) + "x");
    }, { small: 16000, large: 64000, threshold: 6, label: "IMAP SELECT QRESYNC whitespace run" });
    check("SELECT: an unterminated QRESYNC list costs time linear in its length (ratio " +
          first.ratio + ")", first.superlinear === false);

    var second = await helpers.looksSuperlinearAsync(async function (n) {
      await c.cmd("SELECT INBOX (QRESYNC (1 2 (" + " ".repeat(n) + "x");
    }, { small: 16000, large: 64000, threshold: 6, label: "IMAP SELECT seq-match-data whitespace run" });
    check("SELECT: an unterminated seq-match-data list costs time linear in its length (ratio " +
          second.ratio + ")", second.superlinear === false);

    var refused = await c.cmd("SELECT INBOX (QRESYNC (" + " ".repeat(64000) + "x");
    check("SELECT: the unterminated list is answered BAD", refused.status === "BAD", refused.text);
  } finally { await c.close(); }
}

async function testSelectParametersAreParsedOrRefused() {
  var c = await _open();
  try {
    var calls = c.store.calls.select;

    var plain = await c.cmd("SELECT INBOX (QRESYNC (1 2))");
    var last = calls[calls.length - 1];
    check("SELECT QRESYNC (1 2) is OK", plain.status === "OK", plain.text);
    check("SELECT QRESYNC (1 2) reaches the store with the mailbox and the parameters",
          last && last.name === "INBOX" && last.opts.qresync &&
          last.opts.qresync.uidvalidity === 1 && last.opts.qresync.modseq === 2 &&
          last.opts.qresync.knownUids === null && last.opts.qresync.knownSeq === null,
          JSON.stringify(last));

    var uids = await c.cmd("SELECT INBOX (QRESYNC (17 40 1:8))");
    last = calls[calls.length - 1];
    check("SELECT QRESYNC with known-uids passes them on",
          uids.status === "OK" && last.opts.qresync.knownUids === "1:8", JSON.stringify(last));

    var list = await c.cmd("SELECT INBOX (QRESYNC (17 40 1,3:5,7))");
    last = calls[calls.length - 1];
    check("SELECT QRESYNC with a known-uids list of numbers and ranges passes it on",
          list.status === "OK" && last.opts.qresync.knownUids === "1,3:5,7", JSON.stringify(last));

    // RFC 7162 section 3.2.5: seq-match-data is a parenthesized pair inside
    // the QRESYNC list.
    var nested = await c.cmd("SELECT INBOX (QRESYNC (67890007 90060115194045000 1:29997 (5000,7500 15000,22500)))");
    last = calls[calls.length - 1];
    check("SELECT with seq-match-data is OK", nested.status === "OK", nested.text);
    check("SELECT with seq-match-data selects INBOX and passes the pair on",
          last.name === "INBOX" && last.opts.qresync.uidvalidity === 67890007 &&
          last.opts.qresync.knownUids === "1:29997" &&
          last.opts.qresync.knownSeq === "5000,7500 15000,22500", last.name);
    check("a modseq above Number.MAX_SAFE_INTEGER reaches the store exactly, as a BigInt",
          last.opts.qresync.modseq === BigInt("90060115194045000"), String(last.opts.qresync.modseq));

    var widest = await c.cmd("SELECT INBOX (QRESYNC (4294967295 9223372036854775807))");
    last = calls[calls.length - 1];
    check("SELECT QRESYNC at the top of both ranges is OK",
          widest.status === "OK" && last.opts.qresync.uidvalidity === 4294967295 &&
          last.opts.qresync.modseq === BigInt("9223372036854775807"), widest.text);

    var safe = await c.cmd("SELECT INBOX (QRESYNC (1 9007199254740991))");
    last = calls[calls.length - 1];
    check("a modseq at Number.MAX_SAFE_INTEGER reaches the store as a number",
          safe.status === "OK" && last.opts.qresync.modseq === 9007199254740991, safe.text);

    var noUids = await c.cmd("SELECT INBOX (QRESYNC (1 2 (1:5 1:5)))");
    last = calls[calls.length - 1];
    check("SELECT with seq-match-data and no known-uids is OK",
          noUids.status === "OK" && last.name === "INBOX" &&
          last.opts.qresync.knownUids === null && last.opts.qresync.knownSeq === "1:5 1:5",
          JSON.stringify(last));

    var quoted = await c.cmd('EXAMINE "INBOX" (QRESYNC (1 2))');
    last = calls[calls.length - 1];
    check("EXAMINE with a quoted mailbox and QRESYNC is OK",
          quoted.status === "OK" && last.name === "INBOX" && last.opts.readOnly === true,
          JSON.stringify(last));

    var condstore = await c.cmd("SELECT INBOX (CONDSTORE)");
    last = calls[calls.length - 1];
    check("SELECT (CONDSTORE) selects INBOX", condstore.status === "OK" && last.name === "INBOX",
          JSON.stringify(last));

    var bare = await c.cmd("SELECT INBOX   ");
    last = calls[calls.length - 1];
    check("SELECT with trailing spaces selects INBOX", bare.status === "OK" && last.name === "INBOX",
          JSON.stringify(last));

    var before = calls.length;
    var bad = [
      "SELECT INBOX (QRESYNC ( ))",
      "SELECT INBOX (QRESYNC ())",
      "SELECT INBOX (QRESYNC (1 2) (1:5 1:5))",
      "SELECT INBOX (QRESYNC (1 2 1:5 (1,3 1,3) junk))",
      "SELECT INBOX (QRESYNC (1 2 1:5 (1,3)))",
      "SELECT INBOX (QRESYNC (1 2 1:5 ((1 1))))",
      "SELECT INBOX (QRESYNC (1 2 1:5 junk))",
      "SELECT INBOX (QRESYNC (x 2))",
      "SELECT INBOX (QRESYNC (1 2)",
      "SELECT INBOX (QRESYNC (1 2)) trailing",
      "SELECT INBOX (BOGUS)",
      "SELECT INBOX ()",
      "SELECT INBOX (QRESYNC (1 2) QRESYNC (1 2))",
      "SELECT INBOX (QRESYNC (1 2 (1:5 1:5" + LS + ")))",
      // RFC 9051: select = "SELECT" SP mailbox [select-params]. Text after
      // the mailbox name that is not a parameter list is not a name.
      "SELECT INBOX junk (QRESYNC (1 2))",
      "SELECT INBOX junk",
      'SELECT "INBOX" junk',
      'SELECT "INBOX"junk',
      'SELECT "INBOX"(CONDSTORE)',
      "SELECT INBOX(CONDSTORE)",
      // uidvalidity is an nz-number below 2^32; mod-sequence-value is
      // 1 to 2^63-1 (RFC 7162 section 7).
      "SELECT INBOX (QRESYNC (" + "9".repeat(400) + " 2))",
      "SELECT INBOX (QRESYNC (1 " + "9".repeat(400) + "))",
      "SELECT INBOX (QRESYNC (0 2))",
      "SELECT INBOX (QRESYNC (01 2))",
      "SELECT INBOX (QRESYNC (4294967296 2))",
      "SELECT INBOX (QRESYNC (1 0))",
      "SELECT INBOX (QRESYNC (1 9223372036854775808))",
      // known-uids, known-sequence-set and known-uid-set do not allow "*".
      "SELECT INBOX (QRESYNC (1 2 *))",
      "SELECT INBOX (QRESYNC (1 2 1:*))",
      "SELECT INBOX (QRESYNC (1 2 ,,,))",
      "SELECT INBOX (QRESYNC (1 2 0:5))",
      "SELECT INBOX (QRESYNC (1 2 1:2:3))",
      "SELECT INBOX (QRESYNC (1 2 4294967296))",
      "SELECT INBOX (QRESYNC (1 2 (1:* 1:5)))",
      "SELECT INBOX (QRESYNC (1 2 (1:5 1,,5)))",
    ];
    for (var i = 0; i < bad.length; i += 1) {
      var r = await c.cmd(bad[i]);
      check("refused with BAD: " + JSON.stringify(bad[i].slice(0, 80)), r.status === "BAD", r.text);
    }
    check("no refused SELECT line reached the store",
          calls.length === before, JSON.stringify(calls.slice(before), function (k, v) {
            return typeof v === "bigint" ? String(v) + "n" : v;
          }));

    var spaced = await c.cmd('SELECT "Box (QRESYNC (1 2))"');
    last = calls[calls.length - 1];
    check("a quoted mailbox name holding a parenthesis is still a mailbox name",
          spaced.status === "OK" && last.name === "Box (QRESYNC (1 2))" && last.opts.qresync === null,
          JSON.stringify(last));

    // A literal is the whole mailbox name, so a space inside it is part of
    // the name and not trailing text.
    var lit = await c.literal("SELECT", "Sent Items");
    last = calls[calls.length - 1];
    check("SELECT with a literal mailbox name holding a space selects that name",
          lit.status === "OK" && last.name === "Sent Items" && last.opts.qresync === null,
          lit.text + " " + JSON.stringify(last));
    var litQuote = await c.literal("EXAMINE", "\"Quoted\"");
    last = calls[calls.length - 1];
    check("EXAMINE with a literal keeps the name exactly as sent",
          litQuote.status === "OK" && last.name === "\"Quoted\"", litQuote.text + " " + JSON.stringify(last));
  } finally { await c.close(); }
}

async function testStoreUnchangedsinceCostIsLinear() {
  var c = await _open();
  try {
    await c.cmd("SELECT INBOX");
    var growth = await helpers.looksSuperlinearAsync(async function (n) {
      await c.cmd("STORE 1 (UNCHANGEDSINCE 1)" + " ".repeat(n) + "x" + LS + "y");
    }, { small: 16000, large: 64000, threshold: 6, label: "IMAP STORE UNCHANGEDSINCE whitespace run" });
    check("STORE: the UNCHANGEDSINCE reader costs time linear in the line (ratio " +
          growth.ratio + ")", growth.superlinear === false);

    var calls = c.store.calls.store;
    var ok = await c.cmd("STORE 1 (UNCHANGEDSINCE 5) +FLAGS (\\Seen)");
    var last = calls[calls.length - 1];
    check("STORE (UNCHANGEDSINCE 5) still reaches storeFlags with unchangedSince 5",
          ok.status === "OK" && last && last.opts.unchangedSince === 5 &&
          last.seqSet === "1" && last.mode === "add" && last.flags[0] === "\\Seen",
          ok.text + " " + JSON.stringify(last));
    var before = calls.length;
    var junk = await c.cmd("STORE 1 (UNCHANGEDSINCE 1)    x" + LS + "y");
    check("STORE with a line separator in the tail is still answered BAD",
          junk.status === "BAD" && calls.length === before, junk.text);
  } finally { await c.close(); }
}

async function testAppendCatenateCostIsLinear() {
  var c = await _open();
  try {
    var growth = await helpers.looksSuperlinearAsync(async function (n) {
      await c.cmd("APPEND INBOX CATENATE" + " ".repeat(n) + "x" + LS + "y");
    }, { small: 16000, large: 64000, threshold: 6, label: "IMAP APPEND CATENATE whitespace run" });
    check("APPEND: the CATENATE reader costs time linear in the line (ratio " +
          growth.ratio + ")", growth.superlinear === false);

    var calls = c.store.calls.catenate;
    var ok = await c.cmd('APPEND INBOX CATENATE (URL "/INBOX;UIDVALIDITY=1/;UID=1")');
    var last = calls[calls.length - 1];
    check("APPEND CATENATE with a URL part still reaches appendCatenate",
          /^t\d+ OK \[APPENDUID 1 1\]/m.test(ok.text) && last && last.mailbox === "INBOX" &&
          last.parts.length === 1 && last.parts[0].kind === "URL" &&
          last.parts[0].url === "/INBOX;UIDVALIDITY=1/;UID=1",
          ok.text + " " + JSON.stringify(last));
    var flagged = await c.cmd('APPEND INBOX (\\Seen) CATENATE (URL "/INBOX;UIDVALIDITY=1/;UID=2")');
    last = calls[calls.length - 1];
    check("APPEND CATENATE with flags passes the flags on",
          flagged.status === "OK" && last.opts.flags[0] === "\\Seen", JSON.stringify(last));
  } finally { await c.close(); }
}

async function run() {
  await testSelectParametersAreParsedOrRefused();
  await testSelectQresyncCostIsLinear();
  await testStoreUnchangedsinceCostIsLinear();
  await testAppendCatenateCostIsLinear();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[mail-server-imap-args-bounds] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
