// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A thread stays inside the account that owns the folders it spans.
 *
 * `appendMessage` looked each In-Reply-To and References message id up in
 * `message_id_hash` across the whole messages table, with no folder
 * condition and no ordering, and took the first row's `thread_root_id`.
 * `threadFor` then returned every row with that root, in every folder. The
 * store has no account column and one `b.mail.server.jmap` listener takes
 * one store for every account `accountsFor` returns, so two things followed.
 * An account holder who appended a message naming a Message-ID got their own
 * objectid back as the root only when no message anywhere in the store
 * carried it, which answers "does any other account hold this Message-ID"
 * for any id they choose. And a message delivered to two accounts, with a
 * reply reaching only the second, put that reply in a thread with the first
 * account's copy and left the second account's own copy in a thread alone.
 *
 * RFC 8621 section 3 reads a Thread inside one account, and RFC 8620
 * section 1.6.2 makes `accountId` mandatory on the methods that read it.
 * A folder now carries an owner, every message takes the owning account's
 * scope, and both lookups match only rows in that scope.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var nodeFs  = require("node:fs");
var nodeOs  = require("node:os");
var nodePath = require("node:path");

function _msg(headers, body) {
  return headers.join("\r\n") + "\r\n\r\n" + (body || "");
}

async function _store() {
  var dataDir = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), "mailstore-thread-scope-"));
  if (typeof b.vault._resetForTest === "function") b.vault._resetForTest();
  b.cryptoField.clearForTest();
  await b.vault.init({ dataDir: dataDir, mode: "plaintext" });
  var nodeSqlite = require("node:sqlite");
  var db = new nodeSqlite.DatabaseSync(nodePath.join(dataDir, "store.db"));
  var store = b.mailStore.create({ backend: db });
  return { dataDir: dataDir, db: db, store: store };
}

function _teardown(fx) {
  try { if (fx.db && fx.db.close) fx.db.close(); } catch (_e) { /* best-effort */ }
  if (typeof b.vault._resetForTest === "function") b.vault._resetForTest();
  b.cryptoField.clearForTest();
  try { nodeFs.rmSync(fx.dataDir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
}

var HELD = "<q3-numbers-7741@partner.example>";
var NOBODY = "<nobody-holds-this@partner.example>";

async function testOneAccountCannotProbeAnothersMessageIds() {
  var fx = await _store();
  try {
    fx.store.createFolder("acctA.INBOX", { owner: "A" });
    fx.store.createFolder("acctB.INBOX", { owner: "B" });

    fx.store.appendMessage("acctB.INBOX", _msg([
      "From: partner@partner.example", "To: b@example.test",
      "Subject: Q3 numbers", "Message-Id: " + HELD,
    ], "figures"));

    var held = fx.store.appendMessage("acctA.INBOX", _msg([
      "From: a@example.test", "To: a@example.test",
      "Subject: probe", "Message-Id: <probe-1@example.test>",
      "In-Reply-To: " + HELD,
    ], "probe"));
    var unheld = fx.store.appendMessage("acctA.INBOX", _msg([
      "From: a@example.test", "To: a@example.test",
      "Subject: probe", "Message-Id: <probe-2@example.test>",
      "In-Reply-To: " + NOBODY,
    ], "probe"));

    // The oracle is the difference between the two answers, so the test is
    // that they are the same shape: each probe roots itself.
    check("a reply to a Message-ID another account holds roots itself",
          held.threadRootId === held.objectid,
          held.threadRootId + " vs " + held.objectid);
    check("a reply to a Message-ID nobody holds roots itself too",
          unheld.threadRootId === unheld.objectid);
    check("the two probes are indistinguishable, so neither answers whether " +
          "another account holds the Message-ID",
          (held.threadRootId === held.objectid) ===
          (unheld.threadRootId === unheld.objectid));
    check("the thread of the probe holds only the probe",
          JSON.stringify(fx.store.threadFor(held.objectid)) ===
          JSON.stringify([held.objectid]),
          JSON.stringify(fx.store.threadFor(held.objectid)));
  } finally { _teardown(fx); }
}

async function testADoubleDeliveredMessageKeepsEachAccountsThreadWhole() {
  var fx = await _store();
  try {
    fx.store.createFolder("acctC.INBOX", { owner: "C" });
    fx.store.createFolder("acctD.INBOX", { owner: "D" });
    var original = _msg([
      "From: partner@partner.example", "To: c@example.test, d@example.test",
      "Subject: shared", "Message-Id: <shared-1@partner.example>",
    ], "hello");
    var cCopy = fx.store.appendMessage("acctC.INBOX", original);
    var dCopy = fx.store.appendMessage("acctD.INBOX", original);
    var dReply = fx.store.appendMessage("acctD.INBOX", _msg([
      "From: partner@partner.example", "To: d@example.test",
      "Subject: Re: shared", "Message-Id: <shared-2@partner.example>",
      "In-Reply-To: <shared-1@partner.example>",
    ], "more"));

    check("the reply joins the thread of the copy in its own account",
          dReply.threadRootId === dCopy.threadRootId,
          dReply.threadRootId + " vs " + dCopy.threadRootId);
    check("it is not rooted on the other account's copy",
          dReply.threadRootId !== cCopy.threadRootId);
    var dThread = fx.store.threadFor(dReply.objectid);
    check("that account's thread holds both of its own messages and nothing else",
          JSON.stringify(dThread.slice().sort()) ===
          JSON.stringify([dCopy.objectid, dReply.objectid].sort()),
          JSON.stringify(dThread));
    check("the other account's thread holds only its own copy",
          JSON.stringify(fx.store.threadFor(cCopy.objectid)) ===
          JSON.stringify([cCopy.objectid]),
          JSON.stringify(fx.store.threadFor(cCopy.objectid)));
  } finally { _teardown(fx); }
}

async function testThreadingStillSpansOneAccountsFolders() {
  // The scope is the account, not the folder: a reply filed in Sent still
  // threads with the message in INBOX.
  var fx = await _store();
  try {
    fx.store.createFolder("one.INBOX", { owner: "one" });
    fx.store.createFolder("one.Sent", { owner: "one" });
    var incoming = fx.store.appendMessage("one.INBOX", _msg([
      "From: peer@example.test", "To: one@example.test",
      "Subject: hi", "Message-Id: <in-1@example.test>",
    ], "hi"));
    var reply = fx.store.appendMessage("one.Sent", _msg([
      "From: one@example.test", "To: peer@example.test",
      "Subject: Re: hi", "Message-Id: <out-1@example.test>",
      "In-Reply-To: <in-1@example.test>",
    ], "hello back"));
    check("a reply in another folder of the same account joins the thread",
          reply.threadRootId === incoming.threadRootId);
    check("the thread lists both",
          fx.store.threadFor(reply.objectid).length === 2,
          JSON.stringify(fx.store.threadFor(reply.objectid)));
  } finally { _teardown(fx); }
}

async function testAStoreWithNoOwnersThreadsAsOneAccount() {
  // A store whose folders declare no owner is one account's store, which is
  // what every single-account deployment has.
  var fx = await _store();
  try {
    // INBOX and Archive are the default folders the store seeds, and neither
    // declares an owner.
    var first = fx.store.appendMessage("INBOX", _msg([
      "From: peer@example.test", "To: me@example.test",
      "Subject: hi", "Message-Id: <plain-1@example.test>",
    ], "hi"));
    var second = fx.store.appendMessage("Archive", _msg([
      "From: peer@example.test", "To: me@example.test",
      "Subject: Re: hi", "Message-Id: <plain-2@example.test>",
      "In-Reply-To: <plain-1@example.test>",
    ], "again"));
    check("folders with no owner share one scope",
          second.threadRootId === first.threadRootId);
  } finally { _teardown(fx); }
}

async function testAnAppendMayNameItsOwnScope() {
  var fx = await _store();
  try {
    fx.store.createFolder("shared.INBOX");
    var e = fx.store.appendMessage("shared.INBOX", _msg([
      "From: peer@example.test", "To: e@example.test",
      "Subject: hi", "Message-Id: <scoped-1@example.test>",
    ], "hi"), { threadScope: "E" });
    var f = fx.store.appendMessage("shared.INBOX", _msg([
      "From: peer@example.test", "To: f@example.test",
      "Subject: Re: hi", "Message-Id: <scoped-2@example.test>",
      "In-Reply-To: <scoped-1@example.test>",
    ], "hi"), { threadScope: "F" });
    var sameScope = fx.store.appendMessage("shared.INBOX", _msg([
      "From: peer@example.test", "To: e@example.test",
      "Subject: Re: hi", "Message-Id: <scoped-3@example.test>",
      "In-Reply-To: <scoped-1@example.test>",
    ], "hi"), { threadScope: "E" });
    check("appendOpts.threadScope separates two scopes in one folder",
          f.threadRootId !== e.threadRootId && f.threadRootId === f.objectid,
          f.threadRootId + " vs " + e.threadRootId);
    check("and joins two messages that share a scope",
          sameScope.threadRootId === e.threadRootId);
    check("threadFor stays inside the scope",
          JSON.stringify(fx.store.threadFor(e.objectid).slice().sort()) ===
          JSON.stringify([e.objectid, sameScope.objectid].sort()),
          JSON.stringify(fx.store.threadFor(e.objectid)));
  } finally { _teardown(fx); }
}

async function testTheRootChoiceDoesNotDependOnRowOrder() {
  // Two messages in one scope carry the same Message-ID, which a sender can
  // arrange. The root a later reply takes is the older of them either way.
  var fx = await _store();
  try {
    fx.store.createFolder("g.INBOX", { owner: "G" });
    var dupe = ["From: peer@example.test", "To: g@example.test",
                "Subject: dupe", "Message-Id: <dupe-1@example.test>"];
    var older = fx.store.appendMessage("g.INBOX", _msg(dupe, "one"));
    fx.store.appendMessage("g.INBOX", _msg(dupe, "two"));
    var reply = fx.store.appendMessage("g.INBOX", _msg([
      "From: peer@example.test", "To: g@example.test",
      "Subject: Re: dupe", "Message-Id: <dupe-2@example.test>",
      "In-Reply-To: <dupe-1@example.test>",
    ], "reply"));
    check("the reply roots on the oldest row carrying the Message-ID",
          reply.threadRootId === older.threadRootId,
          reply.threadRootId + " vs " + older.threadRootId);
  } finally { _teardown(fx); }
}

function testEveryThreadLookupCarriesTheScope() {
  // The leak was a lookup with no scope condition, so the guarantee is about
  // every such lookup rather than the two that were found: a select keyed on
  // `message_id_hash` or `thread_root_id` crosses accounts unless it also
  // matches `thread_scope`.
  var fs   = require("node:fs");
  var path = require("node:path");
  var src  = fs.readFileSync(path.join(__dirname, "..", "..", "lib", "mail-store.js"), "utf8");
  var unscoped = [];
  src.split(/\bdb\.prepare\(/).slice(1).forEach(function (chunk) {
    var stmt = chunk.split(".toSql()")[0];
    if (!/\.where(?:Op|In)?\("(?:message_id_hash|thread_root_id)"/.test(stmt)) return;
    if (/\.where\("thread_scope"/.test(stmt)) return;
    unscoped.push(stmt.replace(/\s+/g, " ").slice(0, 90));
  });
  check("every message-id or thread-root lookup also matches thread_scope" +
        (unscoped.length ? " (" + unscoped.join(" | ") + ")" : ""),
        unscoped.length === 0);
}

async function run() {
  testEveryThreadLookupCarriesTheScope();
  await testOneAccountCannotProbeAnothersMessageIds();
  await testADoubleDeliveredMessageKeepsEachAccountsThreadWhole();
  await testThreadingStillSpansOneAccountsFolders();
  await testAStoreWithNoOwnersThreadsAsOneAccount();
  await testAnAppendMayNameItsOwnScope();
  await testTheRootChoiceDoesNotDependOnRowOrder();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[mail-store-thread-scope] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
