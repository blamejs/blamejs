// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A folder can be removed, renamed and subscribed to, not only created.
 *
 * `b.mailStore` had `createFolder` and `listFolders` and no way to remove
 * one, so a consumer implementing IMAP `DELETE` had no call to make: the
 * mailbox disappeared from its own bookkeeping while the row stayed, and
 * every deleted mailbox left one behind. `RENAME` and the subscription list
 * that RFC 9051 `LIST (SUBSCRIBED)` reads had the same hole.
 *
 * Deleting a folder deletes the messages in it. That is what the verb means,
 * and leaving them behind would orphan rows pointing at a folder id nothing
 * resolves, which is the same defect one level down.
 *
 * INBOX is refused, because RFC 9051 section 6.3.5 forbids deleting it and a
 * store that allowed it would let a client destroy the delivery target.
 * Renaming it is refused too: RFC 9051 section 6.3.6 gives INBOX special
 * rename semantics, moving its messages to the new mailbox and leaving INBOX
 * in place, and an ordinary rename would move the delivery target itself, so
 * the operation is refused rather than half-implemented.
 *
 * Deleting a folder that holds a message under legal hold is refused, since
 * `hardExpunge` already refuses such a message and deleting the folder
 * around it would bypass the hold one level up. The full-text index is a
 * virtual table with no cascading key, so its rows are removed explicitly or
 * they index messages that no longer exist.
 *
 * Everything the refusals are decided from is read inside the same
 * transaction that deletes. Reading first and deleting afterwards leaves a
 * window in which another connection sets a hold, or appends a held message,
 * between the check and the folder-wide delete that would then remove it.
 *
 * RFC 9051 section 2.3.1.1 requires a mailbox's UIDVALIDITY not to go
 * backwards, and a deleted mailbox takes its row with it, so the highest
 * value ever issued is kept in the store's meta table. Without it a mailbox
 * deleted and recreated inside the same second gets its old value back and a
 * client applies a stale UID cache to different messages. The mark is seeded
 * from the folders already in the database, because a store written before
 * it existed, and the default folders seeded at `create()`, both carry values
 * nothing recorded: deleting one of those would discard the only trace of
 * the value it used. Reading the mark and writing its successor are one
 * step, because two connections that each read before either writes would
 * hand out the same value, and the point of the mark is that a value is
 * never handed out twice. SQLite has no nested transactions, so an inner
 * call joins the one already open rather than committing the outer work
 * early. Seeding is serialized with allocation where the backend supports
 * it, and still correct where it does not, because the write only ever
 * raises the mark: a concurrent allocation is at worst re-applied, never
 * undone. It is written only when it would raise the mark, and only while
 * initializing, so opening an existing store to read it writes nothing and a
 * read-only backend still opens.
 *
 * A transaction already open, whether this module started it or the caller
 * did, is the one used: SQLite has no nested transactions, and a second
 * BEGIN would either fail or commit the caller's work early.
 *
 * Subscriptions are held by mailbox name in their own table rather than on
 * the folder row, because RFC 9051 sections 6.3.5 and 6.3.6 say DELETE and
 * RENAME do not change what a client is subscribed to. A subscription
 * therefore outlives the mailbox it names, so unsubscribing works on a name
 * whose folder is gone: refusing would leave a client unable to remove an
 * entry it can see in LIST (SUBSCRIBED).
 */

var nodeFs   = require("node:fs");
var nodeOs   = require("node:os");
var nodePath = require("node:path");
var helpers  = require("../helpers");
var dbHelpers = require("../helpers/db");
var check    = helpers.check;
var b        = helpers.b;

function _names(store) {
  return store.listFolders().map(function (f) { return f.name; }).sort();
}

// The full-text index is a virtual table with no cascading key, so a row
// left behind is invisible to every store API. Counted directly.
function _ftsRowCount(store) {
  var row = store._dbForTest
    .prepare("SELECT COUNT(*) AS n FROM blamejs_mail_messages_fts").get();
  return row && typeof row.n === "number" ? row.n : -1;
}

async function _withStore(fn) {
  var dataDir = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), "mailstore-folder-life-"));
  if (typeof b.vault._resetForTest === "function") b.vault._resetForTest();
  b.cryptoField.clearForTest();
  await b.vault.init({ dataDir: dataDir, mode: "plaintext" });
  var nodeSqlite = require("node:sqlite");
  var db = new nodeSqlite.DatabaseSync(nodePath.join(dataDir, "store.db"));
  try {
    var store = b.mailStore.create({ backend: db });
    store._dbForTest = db;
    return await fn(store);
  }
  finally {
    try { db.close(); } catch (_e) { /* best-effort */ }
    try { nodeFs.rmSync(dataDir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  }
}

function testAttachmentFactsMatchWhatTheMessageCarries() {
  // hasAttachment and attachmentCount are recorded at append from
  // b.safeMime.extractAttachments, and a mailbox listing reads them rather
  // than re-parsing. A part announced only by its Content-Type was not
  // counted, so a message with a file was stored as having none while the
  // JMAP view of the same message offered it for download.
  return _withStore(function (store) {
    var meta = store.appendMessage("INBOX", Buffer.from([
      "From: a@example.com", "To: b@example.net", "Subject: with a file",
      "MIME-Version: 1.0", 'Content-Type: multipart/mixed; boundary="x"', "",
      "--x", "Content-Type: text/plain", "", "hi",
      "--x", "Content-Type: application/pdf; name=invoice.pdf", "", "PDFBYTES",
      "--x--", "",
    ].join("\r\n"), "utf8"));

    var fetched = store.fetchByObjectId("INBOX", meta.objectid);
    check("the stored message reports that it carries a file",
          fetched.hasAttachment === true, JSON.stringify(fetched.hasAttachment));
    check("and counts it", fetched.attachmentCount === 1,
          JSON.stringify(fetched.attachmentCount));

    var plain = store.appendMessage("INBOX", Buffer.from(
      "From: a@example.com\r\nSubject: no file\r\n\r\njust text\r\n", "utf8"));
    var plainFetched = store.fetchByObjectId("INBOX", plain.objectid);
    check("a message with no file still reports none",
          plainFetched.hasAttachment === false && plainFetched.attachmentCount === 0,
          JSON.stringify([plainFetched.hasAttachment, plainFetched.attachmentCount]));
  });
}

function testAFolderCanBeDeleted() {
  return _withStore(function (store) {
    // Archive is one of the folders a fresh store seeds.
    check("the folder is there to begin with",
          _names(store).indexOf("Archive") !== -1, JSON.stringify(_names(store)));
    store.deleteFolder("Archive");
    check("and it is gone after deleteFolder, not left as a row",
          _names(store).indexOf("Archive") === -1, JSON.stringify(_names(store)));
  });
}

// Rows for one folder, read the way _ftsRowCount above reads the index. The
// store exposes no listMessages, so asking it for one answered undefined and
// an assertion written against that answer could not fail either way.
function _msgRowCount(store, folderId) {
  var row = store._dbForTest
    .prepare("SELECT COUNT(*) AS n FROM " + store._tablePrefix +
             "_messages WHERE folder_id = ?")
    .get(folderId);
  return row && typeof row.n === "number" ? row.n : -1;
}

function testANamedBodyPartStillReachesTheStoredColumns() {
  // A mail gateway that names the body (`Content-Disposition: inline;
  // filename="message.txt"`) is a real shape, and RFC 8621 section 4.1.4
  // reads a name as evidence of an attachment only for a part that is not
  // the FIRST of its multipart. So the first representation is the body
  // however it is named, and the store seals it rather than an empty column.
  // The named second representation is an attachment by that same rule; it is
  // classified differently, not lost, so the message is asked for both.
  return _withStore(function (store) {
    var raw = Buffer.from([
      "From: a@example.com", "To: b@example.net", "Subject: named body",
      "MIME-Version: 1.0",
      'Content-Type: multipart/alternative; boundary="a"', "",
      "--a", "Content-Type: text/plain",
      'Content-Disposition: inline; filename="message.txt"', "", "plain body",
      "--a", "Content-Type: text/html",
      'Content-Disposition: inline; filename="message.html"', "", "<p>html body</p>",
      "--a--", "",
    ].join("\r\n"), "utf8");
    var meta = store.appendMessage("INBOX", raw);
    var row = store.fetchByObjectId("INBOX", meta.objectid);
    check("the named first representation is the body, not an empty column",
          row && row.bodyText.indexOf("plain body") !== -1,
          JSON.stringify(row && row.bodyText));
    check("and the named second representation is offered as a file",
          row && row.attachmentCount === 1,
          JSON.stringify(row && row.attachmentCount));
    var files = b.safeMime.extractAttachments(b.safeMime.parse(raw));
    check("which is the one the sender named",
          files.length === 1 && files[0].filename === "message.html",
          JSON.stringify(files.map(function (f) { return f.filename; })));

    // A lone text/plain the gateway named is the whole message: it is the
    // body and there is no file, which the name rule applied to every leaf
    // got backwards on the commonest shape there is.
    var lone = Buffer.from([
      "From: a@example.com", "To: b@example.net", "Subject: lone named body",
      "MIME-Version: 1.0", "Content-Type: text/plain",
      'Content-Disposition: inline; filename="message.txt"', "", "just the body",
    ].join("\r\n"), "utf8");
    var loneMeta = store.appendMessage("INBOX", lone);
    var loneRow = store.fetchByObjectId("INBOX", loneMeta.objectid);
    check("a lone named text/plain is the body",
          loneRow && loneRow.bodyText.indexOf("just the body") !== -1,
          JSON.stringify(loneRow && loneRow.bodyText));
    check("and the message carries no file",
          loneRow && loneRow.attachmentCount === 0 && loneRow.hasAttachment === false,
          JSON.stringify(loneRow && { n: loneRow.attachmentCount, has: loneRow.hasAttachment }));
  });
}

function testDeletingAFolderTakesItsMessagesWithIt() {
  return _withStore(function (store) {
    var folder = store.createFolder("Doomed");
    store.appendMessage("Doomed",
      Buffer.from("From: a@example.com\r\nSubject: x\r\n\r\nbody"));
    // The id is captured before the delete: afterwards the name resolves to
    // nothing, so a count taken by name would report zero however the rows
    // actually fared.
    var folderId = folder.id;
    check("the folder holds a message", _msgRowCount(store, folderId) === 1,
          String(_msgRowCount(store, folderId)));
    store.deleteFolder("Doomed");
    check("the folder is gone", _names(store).indexOf("Doomed") === -1,
          JSON.stringify(_names(store)));
    check("and no message row is left pointing at it",
          _msgRowCount(store, folderId) === 0, String(_msgRowCount(store, folderId)));
  });
}

function testAFolderCannotBeParkedOnInboxsNameInAnotherCase() {
  // createFolder inserts the name as written and the UNIQUE index is binary,
  // so "inbox" is a folder distinct from "INBOX". deleteFolder and
  // renameFolder decide by upper-casing, so they refuse every case variant:
  // the folder that was just created can never be removed or renamed, and
  // renaming an ordinary folder TO "Inbox" reaches the same dead end from the
  // other side, taking its messages with it.
  return _withStore(function (store) {
    var created = null;
    try { store.createFolder("inbox"); } catch (e) { created = e; }
    check("a folder differing from INBOX only in case is refused at creation",
          created !== null && created.code === "mail-store/reserved-folder-name",
          created ? String(created.code) : "created");

    store.createFolder("Notes");
    var renamed = null;
    try { store.renameFolder("Notes", "Inbox"); } catch (e) { renamed = e; }
    check("and a folder cannot be renamed onto that name either",
          renamed !== null && renamed.code === "mail-store/reserved-folder-name",
          renamed ? String(renamed.code) : "renamed");

    // Notes is still there and still removable, so the refusal did not strand it.
    check("the folder the rename refused is untouched",
          store.listFolders().some(function (f) { return f.name === "Notes"; }));
    store.deleteFolder("Notes");
    check("and can still be deleted",
          !store.listFolders().some(function (f) { return f.name === "Notes"; }));
  });
}

function testInboxCannotBeDeleted() {
  return _withStore(function (store) {
    // A fresh store already has INBOX; it is the delivery target.
    check("INBOX is there to begin with",
          _names(store).indexOf("INBOX") !== -1, JSON.stringify(_names(store)));
    var threw = null;
    try { store.deleteFolder("INBOX"); } catch (e) { threw = e; }
    check("deleting INBOX is refused by name",
          threw !== null && threw.code === "mail-store/inbox-undeletable",
          threw && (threw.code + ": " + threw.message));
    check("and INBOX is still there",
          _names(store).indexOf("INBOX") !== -1, JSON.stringify(_names(store)));
  });
}

function testDeletingAFolderThatIsNotThereIsRefused() {
  return _withStore(function (store) {
    var threw = null;
    try { store.deleteFolder("NoSuchFolder"); } catch (e) { threw = e; }
    check("deleting an absent folder is refused rather than silently passing",
          threw !== null && threw.code === "mail-store/no-folder",
          threw && (threw.code + ": " + threw.message));
  });
}

function testAFolderHoldingHeldMessagesIsNotDeleted() {
  // hardExpunge refuses a message under legal hold, so deleting the folder
  // around it has to refuse too, or the hold is bypassed one level up.
  return _withStore(function (store) {
    store.createFolder("Litigation");
    var meta = store.appendMessage("Litigation",
      Buffer.from("From: a@example.com\r\nSubject: keep\r\n\r\nbody"));
    store.setLegalHold([meta.objectid], { hold: true });

    var threw = null;
    try { store.deleteFolder("Litigation"); } catch (e) { threw = e; }
    check("deleting a folder holding a held message is refused",
          threw !== null && threw.code === "mail-store/folder-holds-legal-hold",
          threw && (threw.code + ": " + threw.message));
    check("and the folder is still there",
          _names(store).indexOf("Litigation") !== -1, JSON.stringify(_names(store)));

    store.setLegalHold([meta.objectid], { hold: false });
    store.deleteFolder("Litigation");
    check("once the hold is released the folder deletes",
          _names(store).indexOf("Litigation") === -1, JSON.stringify(_names(store)));
  });
}

function testDeletingAFolderTakesItsSearchIndexWithIt() {
  // The FTS table is independent of the message rows and has no cascading
  // key, so rows left behind index content for messages that no longer
  // exist.
  return _withStore(function (store) {
    store.createFolder("Indexed");
    store.appendMessage("Indexed",
      Buffer.from("From: a@example.com\r\nSubject: findmeplease\r\n\r\nbody"));
    var before = _ftsRowCount(store);
    check("the message has an index row to begin with", before === 1, String(before));

    store.deleteFolder("Indexed");
    check("and the row goes with the folder rather than being orphaned",
          _ftsRowCount(store) === 0, String(_ftsRowCount(store)));
  });
}

function testAParentFolderIsNotDeletedOutFromUnderItsChildren() {
  // parent_id is a supported createFolder option, and deleting the row it
  // points at leaves every child naming a folder that is not there, which
  // listFolders then reports as a hierarchy nothing can resolve.
  return _withStore(function (store) {
    var parent = store.createFolder("Parent");
    store.createFolder("Child", { parentId: parent.id });

    var threw = null;
    try { store.deleteFolder("Parent"); } catch (e) { threw = e; }
    check("deleting a folder that has children is refused",
          threw !== null && threw.code === "mail-store/folder-has-children",
          threw && (threw.code + ": " + threw.message));
    check("and the parent is still there",
          _names(store).indexOf("Parent") !== -1, JSON.stringify(_names(store)));

    store.deleteFolder("Child");
    store.deleteFolder("Parent");
    var left = _names(store);
    check("once the child is gone the parent deletes",
          left.indexOf("Parent") === -1 && left.indexOf("Child") === -1,
          JSON.stringify(left));
    var dangling = store.listFolders().filter(function (f) {
      if (f.parent_id === null || f.parent_id === undefined) return false;
      return !store.listFolders().some(function (o) { return o.id === f.parent_id; });
    });
    check("and no folder is left naming a parent that is not there",
          dangling.length === 0, JSON.stringify(dangling));
  });
}

function testInboxIsNotRenamed() {
  return _withStore(function (store) {
    var threw = null;
    try { store.renameFolder("INBOX", "OldInbox"); } catch (e) { threw = e; }
    check("renaming INBOX is refused rather than moving the delivery target",
          threw !== null && threw.code === "mail-store/inbox-unrenamable",
          threw && (threw.code + ": " + threw.message));
    check("INBOX is still there", _names(store).indexOf("INBOX") !== -1,
          JSON.stringify(_names(store)));
    var meta = store.appendMessage("INBOX",
      Buffer.from("From: a@example.com\r\nSubject: still delivers\r\n\r\nbody"));
    check("and delivery to it still works", meta && typeof meta.objectid === "string");
  });
}

function testAWrapperBackendReportsItsInnerTransaction() {
  // b.db is the documented backend and begins its transaction on the handle
  // underneath rather than on itself, so a store operation inside
  // b.db.transaction() cannot see the open transaction by reading the wrapper.
  // A wrapper is free not to report it at all, and the documented contract is
  // `prepare` and `transaction` with no way to ask, so the store must compose
  // either way. Driving only the reporting wrapper left the assertion passing
  // for a reason it did not name: with the report removed it passed too.
  //
  // The third shape is the one that bites. A wrapper whose BEGIN sits inside
  // its own try/catch answers a refused nested BEGIN by running its ROLLBACK,
  // which closes the transaction the CALLER opened, so the caller's COMMIT
  // then fails and the write is left autocommitted outside it. A store that
  // never issues that second BEGIN never triggers it.
  var SHAPES = [
    { label: "a wrapper that reports its inner transaction", reports: true },
    { label: "a wrapper that reports nothing", reports: false },
  ];

  return SHAPES.reduce(function (chain, shape) {
    return chain.then(function () {
      return _withStore(function (inner) {
        var db = inner._dbForTest;
        var issued = [];
        var wrapper = {
          prepare: function (text) {
            issued.push(String(text).trim().split(/\s+/)[0].toUpperCase());
            return db.prepare(text);
          },
          transaction: function (fn) {
            db.exec("BEGIN");
            try { var out = fn(); db.exec("COMMIT"); return out; }
            catch (e) { try { db.exec("ROLLBACK"); } catch (_r) { /* report the first */ } throw e; }
          },
        };
        if (shape.reports) {
          Object.defineProperty(wrapper, "isTransaction", {
            get: function () { return db.isTransaction; },
            configurable: true,
          });
        }
        var store = b.mailStore.create({ backend: wrapper, init: false });

        var threw = null;
        var out = null;
        issued.length = 0;
        try {
          out = wrapper.transaction(function () { return store.createFolder("Inside"); });
        } catch (e) { threw = e; }

        check("a store call inside " + shape.label + " does not start a second one",
              threw === null, threw && ((threw.code || "") + ": " + threw.message));
        check("and the folder " + shape.label + " created is there",
              out !== null && _names(store).indexOf("Inside") !== -1,
              JSON.stringify(_names(store)));
        // The assertion that can fail. Running the body bare inside the
        // caller's transaction leaves a failure half-applied, and reading the
        // wrapper for an answer cannot be the mechanism because the contract
        // has no such member: the store takes a savepoint either way.
        check("the store joined the caller's transaction under a savepoint (" +
              shape.label + ")",
              issued.indexOf("SAVEPOINT") !== -1, issued.join(",").slice(0, 80));
        check("and opened no transaction of its own (" + shape.label + ")",
              issued.indexOf("BEGIN") === -1, issued.join(",").slice(0, 80));
      });
    });
  }, Promise.resolve());
}

async function testBDbReportsWhetherATransactionIsOpen() {
  // The property the detection above reads. b.db begins on the handle
  // underneath, so without this it always answered "no transaction" and the
  // store started a second one inside the caller's. Asserting only that it
  // reads false outside a transaction would hold for a getter hard-coded to
  // false, which is the exact bug: the direction that matters is the one
  // inside b.db.transaction().
  check("b.db exposes isTransaction", "isTransaction" in b.db);
  check("and it is false before anything opens one", b.db.isTransaction === false);

  var dataDir = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), "mailstore-bdb-tx-"));
  try {
    await dbHelpers.setupTestDb(dataDir);
    var insideReading = null;
    b.db.transaction(function () { insideReading = b.db.isTransaction; });
    check("and true inside a transaction it opened itself",
          insideReading === true, String(insideReading));
    check("and false again once that transaction closed",
          b.db.isTransaction === false, String(b.db.isTransaction));
  } finally {
    try { await dbHelpers.teardownTestDb(dataDir); } catch (_e) { /* best-effort */ }
    try { nodeFs.rmSync(dataDir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  }
}

function testOpeningWithoutInitWritesNothing() {
  // A store opened with init:false is being read, and a read-only backend
  // refuses any write at all: seeding the high-water mark there turned a
  // supported read-only open into "attempt to write a readonly database".
  var dataDir = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), "mailstore-ro-"));
  var db = null;
  return (async function () {
    if (typeof b.vault._resetForTest === "function") b.vault._resetForTest();
    b.cryptoField.clearForTest();
    await b.vault.init({ dataDir: dataDir, mode: "plaintext" });
    db = new (require("node:sqlite").DatabaseSync)(nodePath.join(dataDir, "store.db"));
    b.mailStore.create({ backend: db });

    var writes = [];
    var readOnly = {
      prepare: function (text) {
        var stmt = db.prepare(text);
        return {
          get: function () { return stmt.get.apply(stmt, arguments); },
          all: function () { return stmt.all.apply(stmt, arguments); },
          run: function () {
            writes.push(text);
            throw new Error("attempt to write a readonly database");
          },
        };
      },
    };
    var reader = b.mailStore.create({ backend: readOnly, init: false });
    check("opening an existing store without init writes nothing",
          writes.length === 0, JSON.stringify(writes.slice(0, 3)));
    check("and it can still read", reader.listFolders().length > 0,
          String(reader.listFolders().length));
  })().finally(function () {
    try { if (db) db.close(); } catch (_e) { /* best-effort */ }
    try { nodeFs.rmSync(dataDir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  });
}

function testStoreOperationsComposeInsideACallersTransaction() {
  // A caller may wrap several store calls in its own transaction. SQLite has
  // no nested transactions, so issuing another BEGIN inside one either fails
  // or commits the caller's work early: the open transaction is joined.
  return _withStore(function (store) {
    var db = store._dbForTest;
    db.exec("BEGIN");
    var threw = null;
    try {
      store.createFolder("Work");
      store.appendMessage("Work",
        Buffer.from("From: a@example.com\r\nSubject: inside\r\n\r\nbody"));
    } catch (e) { threw = e; }
    check("store calls inside a caller's transaction do not throw",
          threw === null, threw && ((threw.code || "") + ": " + threw.message));
    check("and the caller's transaction is still open, not committed early",
          db.isTransaction === true, String(db.isTransaction));

    db.exec("ROLLBACK");
    check("so the caller's rollback still undoes them",
          _names(store).indexOf("Work") === -1, JSON.stringify(_names(store)));
  });
}

function testAPrepareOnlyBackendComposesInsideACallersTransaction() {
  // Two shapes this file already declares supported, crossed: the documented
  // MINIMUM backend (prepare alone), and composing store calls inside a
  // transaction the caller opened. Neither test drove the other, so nothing
  // saw that the store could not tell it was nested. The contract carries no
  // way to ask — `transaction(fn)` is the only other member and a caller's
  // own BEGIN is invisible through `prepare` — so the store opened a second
  // one, the backend refused it, and the append was lost while the caller's
  // COMMIT still reported success.
  var dataDir = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), "mailstore-nested-"));
  var db = null;
  return (async function () {
    if (typeof b.vault._resetForTest === "function") b.vault._resetForTest();
    b.cryptoField.clearForTest();
    await b.vault.init({ dataDir: dataDir, mode: "plaintext" });
    db = new (require("node:sqlite").DatabaseSync)(nodePath.join(dataDir, "store.db"));
    // Exactly the documented surface: prepare(sql) -> { run, get, all }. No
    // transaction(), no exec(), and nothing that reports the handle's state.
    var prepareOnly = { prepare: function (text) { return db.prepare(text); } };
    var store = b.mailStore.create({ backend: prepareOnly });

    // The caller opens its transaction through that same contract.
    prepareOnly.prepare("BEGIN").run();
    var threw = null;
    try {
      store.appendMessage("INBOX",
        Buffer.from("From: a@example.com\r\nSubject: nested\r\n\r\nbody"));
    } catch (e) { threw = e; }
    prepareOnly.prepare("COMMIT").run();

    check("an append inside the caller's transaction does not throw",
          threw === null, threw ? String(threw.message).slice(0, 90) : "ok");

    var rows = prepareOnly.prepare(
      "SELECT COUNT(*) AS n FROM blamejs_mail_messages").get();
    check("and the message the caller committed is there",
          rows && rows.n === 1, JSON.stringify(rows));
  })().finally(function () {
    try { if (db) db.close(); } catch (_e) { /* best-effort */ }
    try { nodeFs.rmSync(dataDir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  });
}

function testARefusalInsideACallersTransactionKeepsTheCallersWork() {
  // The documented minimum backend is `prepare(sql)` alone, which reports
  // nothing about the handle's state, so a caller's own BEGIN is invisible and
  // the store treats the savepoint it opens as its own. Unwinding a failure by
  // aborting the whole transaction is therefore the store deciding the fate of
  // work it cannot see: an ordinary refusal, deleting a folder that is not
  // there, threw away the caller's unrelated insert and closed the transaction
  // under it. Rolling back to the savepoint already undoes everything the
  // store did, so the transaction-level abort is only for the case where that
  // does not work.
  var dataDir = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), "mailstore-refusal-"));
  var db = null;
  return (async function () {
    if (typeof b.vault._resetForTest === "function") b.vault._resetForTest();
    b.cryptoField.clearForTest();
    await b.vault.init({ dataDir: dataDir, mode: "plaintext" });
    db = new (require("node:sqlite").DatabaseSync)(nodePath.join(dataDir, "store.db"));
    var prepareOnly = { prepare: function (text) { return db.prepare(text); } };
    var store = b.mailStore.create({ backend: prepareOnly });
    prepareOnly.prepare("CREATE TABLE callers_own (k TEXT)").run();

    prepareOnly.prepare("BEGIN").run();
    prepareOnly.prepare("INSERT INTO callers_own (k) VALUES (?)").run("row");
    var refused = null;
    try { store.deleteFolder("NoSuchFolder"); }
    catch (e) { refused = e; }

    // The control: a call that did not fail says nothing about the unwind.
    check("deleting a folder that is not there is refused",
          refused !== null, "deleteFolder returned without throwing");

    var stillOpen = null;
    try {
      prepareOnly.prepare("SELECT COUNT(*) AS n FROM callers_own").get();
      prepareOnly.prepare("COMMIT").run();
      stillOpen = true;
    } catch (_e) { stillOpen = false; }
    check("the caller's transaction is still the caller's to commit",
          stillOpen === true, String(stillOpen));

    var kept = prepareOnly.prepare(
      "SELECT COUNT(*) AS n FROM callers_own WHERE k = ?").get("row");
    check("and the row the caller wrote before the refusal survived",
          kept && kept.n === 1, JSON.stringify(kept));

    // The store's own work is still undone, which is what the savepoint is for.
    var folders = prepareOnly.prepare(
      "SELECT COUNT(*) AS n FROM blamejs_mail_folders WHERE name = ?").get("NoSuchFolder");
    check("the refused deletion left no folder behind",
          folders && folders.n === 0, JSON.stringify(folders));
  })().finally(function () {
    try { if (db && db.isTransaction) db.exec("ROLLBACK"); } catch (_e) { /* best-effort */ }
    try { if (db) db.close(); } catch (_e) { /* best-effort */ }
    try { nodeFs.rmSync(dataDir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  });
}

function testACallersTransactionSurvivesABackendThatAcceptsANestedBegin() {
  // The test above drives SQLite, which refuses a second BEGIN, and a store
  // that recognised the nested case by the text of that refusal passed it
  // while depending on one driver's wording. A backend that accepts a second
  // BEGIN is the other half of the contract: nothing raises, so the store's
  // own COMMIT ends the transaction the CALLER opened, the caller is told the
  // write succeeded, and the caller's rollback has nothing left to undo. This
  // backend answers the way PostgreSQL was measured to answer, including
  // COMMIT and ROLLBACK with nothing open being warnings rather than errors.
  var dataDir = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), "mailstore-nested2-"));
  var db = null;
  return (async function () {
    if (typeof b.vault._resetForTest === "function") b.vault._resetForTest();
    b.cryptoField.clearForTest();
    await b.vault.init({ dataDir: dataDir, mode: "plaintext" });
    db = new (require("node:sqlite").DatabaseSync)(nodePath.join(dataDir, "store.db"));

    var depth = 0;
    var issued = [];
    var accepting = {
      prepare: function (text) {
        var head = String(text).trim().split(/\s+/)[0].toUpperCase();
        var stmt = db.prepare(text);
        return {
          run: function () {
            issued.push(head);
            var out;
            if (head === "BEGIN" && depth > 0) out = { changes: 0 };
            else if ((head === "COMMIT" || head === "ROLLBACK") && !db.isTransaction) out = { changes: 0 };
            else out = stmt.run.apply(stmt, arguments);
            if (head === "BEGIN") depth += 1;
            if (head === "COMMIT" || head === "ROLLBACK") depth = 0;
            return out;
          },
          get: function () { return stmt.get.apply(stmt, arguments); },
          all: function () { return stmt.all.apply(stmt, arguments); },
        };
      },
    };

    var store = b.mailStore.create({ backend: accepting });

    accepting.prepare("BEGIN").run();
    issued.length = 0;
    var threw = null;
    try {
      store.appendMessage("INBOX",
        Buffer.from("From: a@example.com\r\nSubject: nested\r\n\r\nbody"));
    } catch (e) { threw = e; }
    var openWhenTheCallerRolledBack = depth === 1;
    accepting.prepare("ROLLBACK").run();

    check("an append inside the caller's transaction does not throw",
          threw === null, threw ? String(threw.message).slice(0, 90) : "ok");
    check("the store opens no transaction of its own inside the caller's",
          issued.indexOf("BEGIN") === -1, issued.join(",").slice(0, 90));
    check("so the caller's transaction is still open when it rolls back",
          openWhenTheCallerRolledBack, "depth=" + depth);

    var rows = accepting.prepare(
      "SELECT COUNT(*) AS n FROM blamejs_mail_messages").get();
    check("and the caller's rollback discards the store's write",
          rows && rows.n === 0, JSON.stringify(rows));
  })().finally(function () {
    try { if (db) db.close(); } catch (_e) { /* best-effort */ }
    try { nodeFs.rmSync(dataDir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  });
}

function testAPrepareOnlyBackendStillWorks() {
  // The documented contract asks a backend for prepare(sql) returning
  // run/get/all and nothing else, so a wrapper offering exactly that has to
  // keep working: running transactions through exec alone refused it.
  var dataDir = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), "mailstore-prepare-"));
  var db = null;
  return (async function () {
    if (typeof b.vault._resetForTest === "function") b.vault._resetForTest();
    b.cryptoField.clearForTest();
    await b.vault.init({ dataDir: dataDir, mode: "plaintext" });
    db = new (require("node:sqlite").DatabaseSync)(nodePath.join(dataDir, "store.db"));
    var prepareOnly = { prepare: function (text) { return db.prepare(text); } };

    var store = b.mailStore.create({ backend: prepareOnly });
    var meta = store.appendMessage("INBOX",
      Buffer.from("From: a@example.com\r\nSubject: hello\r\n\r\nbody"));
    check("appending through a prepare-only backend works",
          meta && typeof meta.objectid === "string", JSON.stringify(meta));

    store.createFolder("Temp");
    store.appendMessage("Temp",
      Buffer.from("From: b@example.com\r\nSubject: bye\r\n\r\nbody"));
    store.deleteFolder("Temp");
    check("and so does a folder deletion, which runs in a transaction",
          store.listFolders().every(function (f) { return f.name !== "Temp"; }),
          JSON.stringify(store.listFolders().map(function (f) { return f.name; })));
  })().finally(function () {
    try { if (db) db.close(); } catch (_e) { /* best-effort */ }
    try { nodeFs.rmSync(dataDir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  });
}

function testAFailedDeletionIsAtomicInsideACallersTransactionToo() {
  // The test above proves the deletion is atomic when the STORE owns the
  // transaction. Composing store calls inside a transaction the CALLER opened
  // is a supported shape, and on that path the helper ran the body directly
  // with no savepoint: a failure partway left the flag, index, message and
  // quota deletes sitting in the caller's transaction, so a caller batching
  // several mailbox deletions committed a folder that still exists with its
  // messages already gone.
  return _withStore(function (store) {
    store.createFolder("Fragile2");
    store.appendMessage("Fragile2",
      Buffer.from("From: a@example.com\r\nSubject: one\r\n\r\nbody"));
    store.appendMessage("Fragile2",
      Buffer.from("From: b@example.com\r\nSubject: two\r\n\r\nbody"));
    check("the folder holds indexed messages", _ftsRowCount(store) === 2,
          String(_ftsRowCount(store)));

    var db = store._dbForTest;
    var realPrepare = db.prepare.bind(db);
    var threw = null;
    db.exec("BEGIN");
    try {
      db.prepare = function (text) {
        if (text.indexOf("DELETE") !== -1 && text.indexOf("folders") !== -1) {
          return { run: function () { throw new Error("backend failed mid-delete"); } };
        }
        return realPrepare(text);
      };
      try { store.deleteFolder("Fragile2"); } catch (e) { threw = e; }
      db.prepare = realPrepare;

      check("the deletion reports the failure", threw !== null, String(threw));
      check("the folder is still there inside the caller's transaction",
            _names(store).indexOf("Fragile2") !== -1, JSON.stringify(_names(store)));
      check("and its messages are still there with it",
            _ftsRowCount(store) === 2, String(_ftsRowCount(store)));
    } finally {
      db.prepare = realPrepare;
      try { db.exec("COMMIT"); } catch (_e) { try { db.exec("ROLLBACK"); } catch (_e2) { /* best-effort */ } }
    }

    // What the caller committed is what it could see: the folder survived the
    // failed deletion whole.
    check("the committed state still holds the folder",
          _names(store).indexOf("Fragile2") !== -1, JSON.stringify(_names(store)));
    check("and still holds its messages", _ftsRowCount(store) === 2,
          String(_ftsRowCount(store)));
  });
}

function testAFailedDeletionLeavesTheFolderWhole() {
  // node:sqlite's DatabaseSync has no transaction() wrapper, so the helper
  // ran the callback with no transaction at all and a failure part way
  // through left the writes before it committed: the folder survived with
  // its messages already gone.
  return _withStore(function (store) {
    store.createFolder("Fragile");
    store.appendMessage("Fragile",
      Buffer.from("From: a@example.com\r\nSubject: one\r\n\r\nbody"));
    store.appendMessage("Fragile",
      Buffer.from("From: b@example.com\r\nSubject: two\r\n\r\nbody"));
    var before = _ftsRowCount(store);
    check("the folder holds indexed messages", before === 2, String(before));

    // Fail the last statement of the deletion, after the messages have gone.
    var realPrepare = store._dbForTest.prepare.bind(store._dbForTest);
    var threw = null;
    store._dbForTest.prepare = function (text) {
      var stmt = realPrepare(text);
      if (text.indexOf("DELETE") !== -1 && text.indexOf("folders") !== -1) {
        return { run: function () { throw new Error("backend failed mid-delete"); } };
      }
      return stmt;
    };
    try { store.deleteFolder("Fragile"); } catch (e) { threw = e; }
    store._dbForTest.prepare = realPrepare;

    check("the deletion reports the failure", threw !== null, String(threw));
    check("the folder is still there", _names(store).indexOf("Fragile") !== -1,
          JSON.stringify(_names(store)));
    check("and its messages came back with it, rather than being gone already",
          _ftsRowCount(store) === 2, String(_ftsRowCount(store)));
  });
}

function testARenameRunsAsOneTransaction() {
  // The rename read the source row, checked the destination was free and
  // wrote the UPDATE as separate statements. Two connections renaming the
  // same folder both read the original row and both reported success. The
  // whole sequence has to hold one transaction for the checks to still be
  // true at the write.
  //
  // The write is found by its own shape, `SET name`, rather than by a column
  // it happens to touch: it used to set a fresh uidvalidity, and keying on
  // that left the hook matching nothing once the rename stopped doing so.
  return _withStore(function (store) {
    store.createFolder("Before");
    var db = store._dbForTest;
    var realPrepare = db.prepare.bind(db);
    var openAtUpdate = null;
    db.prepare = function (text) {
      var stmt = realPrepare(text);
      if (/UPDATE[\s\S]*SET[\s\S]*name/.test(text)) {                                                // allow:regex-no-length-cap — matched against this test's own SQL
        return { run: function () {
          openAtUpdate = db.isTransaction;
          return stmt.run.apply(stmt, arguments);
        } };
      }
      return stmt;
    };
    try { store.renameFolder("Before", "After"); }
    finally { db.prepare = realPrepare; }

    check("the rename is applied", _names(store).indexOf("After") !== -1,
          JSON.stringify(_names(store)));
    check("and the checks and the write ran in one transaction",
          openAtUpdate === true, String(openAtUpdate));
  });
}

async function testARenameKeepsTheMailboxsUidvalidity() {
  // UIDVALIDITY identifies the set of UIDs, not the name: RFC 9051 section
  // 2.3.1.1 lets a client reuse what it has cached for a mailbox only while
  // that number holds. A rename moves no messages and renumbers nothing, so
  // changing it tells every client its cache is worthless, makes it download
  // the mailbox again, and discards the QRESYNC state it would have resumed
  // from.
  await _withStore(async function (store) {
    store.createFolder("Before");
    var before = store.listFolders().filter(function (f) { return f.name === "Before"; })[0];
    check("the folder starts with a uidvalidity", typeof before.uidvalidity === "number",
          JSON.stringify(before));

    store.renameFolder("Before", "After");
    var after = store.listFolders().filter(function (f) { return f.name === "After"; })[0];
    check("the rename is applied", after !== undefined, JSON.stringify(_names(store)));
    check("and the mailbox keeps the uidvalidity its UIDs were issued under",
          after.uidvalidity === before.uidvalidity,
          JSON.stringify({ before: before.uidvalidity, after: after.uidvalidity }));

    // A fresh mailbox created at the freed name is a different mailbox and
    // gets its own number, so the two are not confusable.
    store.createFolder("Before");
    var reused = store.listFolders().filter(function (f) { return f.name === "Before"; })[0];
    check("a new mailbox at the freed name gets its own uidvalidity",
          reused.uidvalidity !== before.uidvalidity,
          JSON.stringify({ original: before.uidvalidity, reused: reused.uidvalidity }));
  });
}

function testASecondDatabaseGetsItsOwnTransaction() {
  // "Am I already inside a transaction" was answered by one module-wide flag,
  // so a store operation running inside another store's transaction skipped
  // its own BEGIN even when the two sit on different databases. The second
  // database's writes then autocommitted and survived a failure that rolled
  // the first one back. The question is per handle.
  var dataDir = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), "mailstore-two-db-"));
  var dbA = null;
  var dbB = null;
  return (async function () {
    if (typeof b.vault._resetForTest === "function") b.vault._resetForTest();
    b.cryptoField.clearForTest();
    await b.vault.init({ dataDir: dataDir, mode: "plaintext" });
    var nodeSqlite = require("node:sqlite");
    dbA = new nodeSqlite.DatabaseSync(nodePath.join(dataDir, "a.db"));
    dbB = new nodeSqlite.DatabaseSync(nodePath.join(dataDir, "b.db"));
    // Each store prepares its statements when it is created, so the probes go
    // on before that rather than after.
    var openAtInsert = null;
    var recording = false;
    var prepareB = dbB.prepare.bind(dbB);
    dbB.prepare = function (text) {
      var stmt = prepareB(text);
      if (text.indexOf("INSERT") !== -1 && text.indexOf("uidvalidity") !== -1) {
        return { run: function () {
          if (recording && openAtInsert === null) openAtInsert = dbB.isTransaction;
          return stmt.run.apply(stmt, arguments);
        } };
      }
      return stmt;
    };
    var storeB = b.mailStore.create({ backend: dbB });

    var armed = false;
    var nested = false;
    var prepareA = dbA.prepare.bind(dbA);
    dbA.prepare = function (text) {
      var stmt = prepareA(text);
      if (text.indexOf("INSERT") !== -1 && text.indexOf("uidvalidity") !== -1) {
        return { run: function () {
          var out = stmt.run.apply(stmt, arguments);
          if (armed && !nested) {
            nested = true;
            recording = true;
            try { storeB.createFolder("Second"); }
            finally { recording = false; }
          }
          return out;
        } };
      }
      return stmt;
    };
    var storeA = b.mailStore.create({ backend: dbA });
    armed = true;
    storeA.createFolder("First");
    armed = false;

    check("the folder on the first database is there",
          _names(storeA).indexOf("First") !== -1, JSON.stringify(_names(storeA)));
    check("the nested call ran", nested === true, String(nested));
    check("and the one on the second database is too",
          _names(storeB).indexOf("Second") !== -1, JSON.stringify(_names(storeB)));
    check("the second database opened its own transaction",
          openAtInsert === true, String(openAtInsert));
    dbA.prepare = prepareA;
    dbB.prepare = prepareB;
  })().finally(function () {
    try { if (dbA) dbA.close(); } catch (_e) { /* best-effort */ }
    try { if (dbB) dbB.close(); } catch (_e) { /* best-effort */ }
    try { nodeFs.rmSync(dataDir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  });
}

function testInboxAnswersToAnySpellingOfItsName() {
  // RFC 9051 section 5.1 calls INBOX "the case-insensitive mailbox name", and
  // every one of these takes a NAME rather than a pattern, so a client that
  // spells it `inbox` is naming the same mailbox. Three of them read the name
  // verbatim: appending and subscribing answered `mail-store/no-folder` for a
  // mailbox that is always there, and unsubscribing reported success while
  // deleting no row, so a client could not remove a subscription it could see.
  return _withStore(function (store) {
    var MSG = Buffer.from("From: a@example.com\r\nSubject: s\r\n\r\nbody\r\n", "utf8");

    var appended = null;
    try { appended = store.appendMessage("inbox", MSG); }
    catch (e) { appended = e.code || e.message; }
    check("a message appended to `inbox` reaches INBOX",
          appended !== null && typeof appended === "object" && appended.objectid,
          JSON.stringify(appended));

    var subscribed = null;
    try { subscribed = store.subscribeFolder("inbox"); }
    catch (e) { subscribed = e.code || e.message; }
    check("subscribing to `inbox` names INBOX",
          subscribed !== null && subscribed.name === "INBOX",
          JSON.stringify(subscribed));
    check("and the subscription is recorded against INBOX",
          store.listFolders().filter(function (f) { return f.subscribed; })
            .map(function (f) { return f.name; }).indexOf("INBOX") !== -1,
          JSON.stringify(store.listFolders().map(function (f) {
            return f.name + "=" + f.subscribed;
          })));

    var unsubscribed = null;
    try { unsubscribed = store.unsubscribeFolder("InBoX"); }
    catch (e) { unsubscribed = e.code || e.message; }
    check("unsubscribing by another spelling answers for INBOX",
          unsubscribed !== null && unsubscribed.name === "INBOX",
          JSON.stringify(unsubscribed));
    check("and the subscription is actually gone",
          store.listFolders().filter(function (f) { return f.subscribed; })
            .map(function (f) { return f.name; }).indexOf("INBOX") === -1,
          JSON.stringify(store.listFolders().map(function (f) {
            return f.name + "=" + f.subscribed;
          })));

    // Only INBOX is the reserved name: every other mailbox keeps its case, so
    // a spelling that differs is a mailbox that is not there.
    var other = null;
    try { other = store.subscribeFolder("archive"); }
    catch (e) { other = e.code; }
    check("another mailbox is still matched by its own case",
          other === "mail-store/no-folder", JSON.stringify(other));

    // The case INBOX is insensitive to is ASCII case. A folder name is
    // `[A-Za-z0-9_.-]+`, so the namespace holds no character outside ASCII and
    // a Unicode uppercase mapping can only ever over-match: U+0131 LATIN SMALL
    // LETTER DOTLESS I uppercases to `I`, so `toUpperCase()` reads `ınbox`
    // as INBOX and every verb resolved a name `createFolder` refuses as
    // invalid. The framework holds the same position elsewhere, where `I` and
    // `ı` are pinned apart.
    var dotlessI = String.fromCharCode(0x131) + "nbox";
    var NOT_INBOX = [dotlessI, "ıNBOX", "inbox ", " inbox", "inboxx", "inbo"];
    var overMatched = [];
    for (var n = 0; n < NOT_INBOX.length; n += 1) {
      var resolved = null;
      try { resolved = store.subscribeFolder(NOT_INBOX[n]); }
      catch (e) { resolved = e.code; }
      if (resolved !== "mail-store/no-folder") {
        overMatched.push(JSON.stringify(NOT_INBOX[n]) + " -> " +
                         JSON.stringify(resolved));
      }
    }
    check("a name that is not an ASCII case variant of INBOX is not INBOX" +
          (overMatched.length ? " (" + overMatched.join("; ") + ")" : ""),
          overMatched.length === 0);

    // Resolving the folder row for a read and writing its modification
    // sequence by the caller's spelling are two answers to one question. The
    // lookup folded and the UPDATE did not, so the row matched nothing: the
    // message landed, `modseq_max` stayed where it was, and the next mutation
    // handed out a sequence already given to another message. A client
    // synchronizing from the sequence it last saw never learns about the
    // second one. RFC 9051 section 7.4.3 has a client resume from the highest
    // modification sequence it has seen.
    var assigned = [];
    var SPELLINGS = ["INBOX", "inbox", "INBOX", "InBoX", "iNbOx"];
    for (var s = 0; s < SPELLINGS.length; s += 1) {
      assigned.push(store.appendMessage(SPELLINGS[s],
        Buffer.from("From: a@example.com\r\nSubject: m" + s + "\r\n\r\nbody\r\n",
                    "utf8")).modseq);
    }
    var seen = Object.create(null);
    var reused = [];
    for (var m = 0; m < assigned.length; m += 1) {
      if (seen[assigned[m]] === true) reused.push(assigned[m]);
      seen[assigned[m]] = true;
    }
    check("no modification sequence is handed out twice, whatever the spelling" +
          (reused.length ? " (reused " + JSON.stringify(reused) + ")" : ""),
          reused.length === 0, JSON.stringify(assigned));

    var ascending = true;
    for (var a = 1; a < assigned.length; a += 1) {
      if (assigned[a] <= assigned[a - 1]) ascending = false;
    }
    check("and each one is higher than the last", ascending,
          JSON.stringify(assigned));
  });
}

function testAFolderAlreadyNamedLikeInboxKeepsItsOwnRows() {
  // Refusing to CREATE a folder whose name differs from INBOX only in case is
  // new here, so a store written by an earlier version can already hold one,
  // and resolving every spelling to INBOX would take its messages out of
  // reach: the store's own rename and delete both refuse INBOX, so there
  // would be no way back to them either. A name that is already a row is that
  // row; the reserved name answers only when nothing else does.
  var dataDir = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), "mailstore-legacy-case-"));
  var db = null;
  return (async function () {
    if (typeof b.vault._resetForTest === "function") b.vault._resetForTest();
    b.cryptoField.clearForTest();
    await b.vault.init({ dataDir: dataDir, mode: "plaintext" });
    db = new (require("node:sqlite").DatabaseSync)(nodePath.join(dataDir, "store.db"));
    var store = b.mailStore.create({ backend: db });

    // The row an earlier version would have written. Inserted directly
    // because this version's createFolder is what refuses it.
    db.prepare("INSERT INTO blamejs_mail_folders " +
               "(name, role, parent_id, modseq_max, uidvalidity, owner) " +
               "VALUES (?, ?, ?, ?, ?, ?)").run("inbox", null, null, 0, 1, null);

    var appended = store.appendMessage("inbox", Buffer.from(
      "From: a@example.com\r\nSubject: legacy\r\n\r\nbody\r\n", "utf8"));
    check("a message appended to the existing folder is accepted",
          appended && appended.objectid, JSON.stringify(appended));

    var inLegacy = db.prepare(
      "SELECT COUNT(*) AS n FROM blamejs_mail_messages WHERE folder_id = " +
      "(SELECT id FROM blamejs_mail_folders WHERE name = 'inbox')").get();
    check("and it lands in that folder rather than in INBOX",
          inLegacy.n === 1, JSON.stringify(inLegacy));

    var inInbox = db.prepare(
      "SELECT COUNT(*) AS n FROM blamejs_mail_messages WHERE folder_id = " +
      "(SELECT id FROM blamejs_mail_folders WHERE name = 'INBOX')").get();
    check("INBOX is untouched", inInbox.n === 0, JSON.stringify(inInbox));

    // The message is reachable through the store, which is what makes the
    // folder usable rather than merely present.
    var fetched = store.fetchByObjectId("inbox", appended.objectid);
    check("the message is readable back under the name it was written to",
          fetched !== null && fetched.objectid === appended.objectid,
          JSON.stringify(fetched && fetched.objectid));

    // Subscriptions follow the same rule.
    var subscribed = store.subscribeFolder("inbox");
    check("subscribing names the existing folder",
          subscribed.name === "inbox", JSON.stringify(subscribed));

    // And the reserved name still answers for a spelling no row carries.
    var otherCase = store.appendMessage("InBoX", Buffer.from(
      "From: a@example.com\r\nSubject: reserved\r\n\r\nbody\r\n", "utf8"));
    check("a spelling no row carries still reaches INBOX",
          otherCase && otherCase.objectid, JSON.stringify(otherCase));
    var reserved = db.prepare(
      "SELECT COUNT(*) AS n FROM blamejs_mail_messages WHERE folder_id = " +
      "(SELECT id FROM blamejs_mail_folders WHERE name = 'INBOX')").get();
    check("and lands in INBOX", reserved.n === 1, JSON.stringify(reserved));
  })().finally(function () {
    try { if (db) db.close(); } catch (_e) { /* best-effort */ }
    try { nodeFs.rmSync(dataDir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  });
}

function testAFailedCommitOnThePrepareOnlyBackendLeavesNothingStranded() {
  // The documented minimum backend is `prepare(sql)`, which reports nothing
  // about the handle, so the store cannot read `isTransaction` to decide
  // whether it opened the transaction. Reserving the transaction-level abort
  // for backends that do report it left this one with a transaction it could
  // never close: the connection keeps the write lock, every other connection
  // is refused, and the store's own later calls open a savepoint nested in the
  // stranded transaction, so they report success and commit nothing.
  //
  // The signal is in the failure itself rather than in the handle: only the
  // OUTERMOST savepoint's release commits, so a release that fails the way a
  // commit fails is proof the store owns the transaction.
  var dataDir = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), "mailstore-strand-"));
  var writer = null;
  var reader = null;
  var other = null;
  return (async function () {
    if (typeof b.vault._resetForTest === "function") b.vault._resetForTest();
    b.cryptoField.clearForTest();
    await b.vault.init({ dataDir: dataDir, mode: "plaintext" });
    var nodeSqlite = require("node:sqlite");
    var file = nodePath.join(dataDir, "store.db");
    writer = new nodeSqlite.DatabaseSync(file);
    writer.exec("PRAGMA journal_mode = delete");
    // Exactly the documented minimum: prepare(sql) and nothing that reports
    // the handle's state.
    var prepareOnly = { prepare: function (text) { return writer.prepare(text); } };
    var store = b.mailStore.create({ backend: prepareOnly });

    reader = new nodeSqlite.DatabaseSync(file);
    reader.exec("PRAGMA journal_mode = delete");
    reader.exec("BEGIN");
    reader.prepare("SELECT COUNT(*) AS n FROM blamejs_mail_folders").get();

    var refused = null;
    try { store.createFolder("Stranded"); }
    catch (e) { refused = e; }
    check("the commit is refused while another connection reads",
          refused !== null, "createFolder returned without throwing");

    // The reader lets go; whether the writer is still holding a transaction is
    // then the question, and it is observable from another connection. The
    // rollback is best-effort because a writer holding the lock can refuse
    // even this, which is itself the wedge being measured.
    var readerReleased = null;
    try { reader.exec("ROLLBACK"); readerReleased = true; }
    catch (e) { readerReleased = (e && e.message) || "threw"; }
    check("the reader can end its own transaction",
          readerReleased === true, String(readerReleased));
    other = new nodeSqlite.DatabaseSync(file);
    var otherCanWrite = null;
    try {
      other.exec("PRAGMA journal_mode = delete");
      other.exec("CREATE TABLE probe_other (k TEXT)");
      otherCanWrite = true;
    } catch (e) { otherCanWrite = (e && e.message) || "threw"; }
    check("another connection can write once the reader is gone",
          otherCanWrite === true, String(otherCanWrite));

    // And the store's own later work reaches the file rather than a
    // transaction nobody will commit.
    store.createFolder("Later");
    var onDisk = null;
    try {
      onDisk = other.prepare(
        "SELECT COUNT(*) AS n FROM blamejs_mail_folders WHERE name = ?").get("Later");
    } catch (e) { onDisk = (e && e.message) || "threw"; }
    check("a folder created afterwards is visible to another connection",
          onDisk && onDisk.n === 1, JSON.stringify(onDisk));
  })().finally(function () {
    try { if (reader) reader.close(); } catch (_e) { /* best-effort */ }
    try { if (other) other.close(); } catch (_e) { /* best-effort */ }
    try { if (writer && writer.isTransaction) writer.exec("ROLLBACK"); } catch (_e) { /* best-effort */ }
    try { if (writer) writer.close(); } catch (_e) { /* best-effort */ }
    try { nodeFs.rmSync(dataDir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  });
}

function testAFailedCommitLeavesNoTransactionOpen() {
  // Releasing the outermost savepoint IS the commit, and a commit can fail:
  // SQLite answers SQLITE_BUSY while another connection holds a read
  // transaction in rollback-journal mode. The release ran after the catch
  // rather than inside the try, so nothing unwound it: createFolder threw, the
  // transaction stayed open with the new row pending on the writer connection,
  // the database stayed locked against every other connection, and the next
  // write reported success inside a transaction nobody would commit.
  var dataDir = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), "mailstore-busy-commit-"));
  var writer = null;
  var reader = null;
  return (async function () {
    if (typeof b.vault._resetForTest === "function") b.vault._resetForTest();
    b.cryptoField.clearForTest();
    await b.vault.init({ dataDir: dataDir, mode: "plaintext" });
    var nodeSqlite = require("node:sqlite");
    var file = nodePath.join(dataDir, "store.db");
    writer = new nodeSqlite.DatabaseSync(file);
    // WAL lets a reader and a writer proceed together, so the commit this row
    // is about would never be refused under it.
    writer.exec("PRAGMA journal_mode = delete");
    var store = b.mailStore.create({ backend: writer });

    reader = new nodeSqlite.DatabaseSync(file);
    reader.exec("PRAGMA journal_mode = delete");
    reader.exec("BEGIN");
    reader.prepare("SELECT COUNT(*) AS n FROM blamejs_mail_folders").get();

    var refused = null;
    try { store.createFolder("BusyTest"); }
    catch (e) { refused = e; }

    // The control: if the commit was not refused, every assertion below is
    // about a failure that did not happen and passes for the wrong reason.
    check("the commit is refused while another connection holds a read transaction",
          refused !== null, "createFolder returned without throwing");

    check("no transaction is left open on the writer",
          writer.isTransaction === false, String(writer.isTransaction));

    var pending = writer.prepare(
      "SELECT COUNT(*) AS n FROM blamejs_mail_folders WHERE name = ?").get("BusyTest");
    check("and the folder the failed write created is not left pending",
          pending.n === 0, JSON.stringify(pending));

    // A caller's own transaction is a different case: the store's savepoint is
    // nested inside it, releasing that savepoint commits nothing, and unwinding
    // it must not abort the work the caller did. The reader's transaction ends
    // first, because it is what makes every write on this file refuse.
    reader.exec("ROLLBACK");
    writer.exec("CREATE TABLE callers_own (k TEXT)");
    writer.exec("BEGIN");
    writer.prepare("INSERT INTO callers_own (k) VALUES (?)").run("row");
    var nestedFailure = null;
    try { store.createFolder("INBOX"); }
    catch (e) { nestedFailure = e; }
    check("a store operation that fails inside a caller's transaction still throws",
          nestedFailure !== null, "createFolder returned without throwing");
    check("the caller's transaction is still open",
          writer.isTransaction === true, String(writer.isTransaction));
    var callerRow = writer.prepare(
      "SELECT COUNT(*) AS n FROM callers_own WHERE k = ?").get("row");
    check("and the caller's own row survived",
          callerRow.n === 1, JSON.stringify(callerRow));
    writer.exec("ROLLBACK");
  })().finally(function () {
    try { if (reader) reader.exec("ROLLBACK"); } catch (_e) { /* best-effort */ }
    try { if (writer && writer.isTransaction) writer.exec("ROLLBACK"); } catch (_e) { /* best-effort */ }
    try { if (reader) reader.close(); } catch (_e) { /* best-effort */ }
    try { if (writer) writer.close(); } catch (_e) { /* best-effort */ }
    try { nodeFs.rmSync(dataDir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  });
}

function testALifecycleChangeSurvivesReopeningTheStore() {
  // create() seeded the default folders every time, so a deleted default
  // came back the next time anything opened the database, and a renamed one
  // left a second row carrying the same role.
  var dataDir = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), "mailstore-reopen-"));
  var db = null;
  return (async function () {
    if (typeof b.vault._resetForTest === "function") b.vault._resetForTest();
    b.cryptoField.clearForTest();
    await b.vault.init({ dataDir: dataDir, mode: "plaintext" });
    db = new (require("node:sqlite").DatabaseSync)(nodePath.join(dataDir, "store.db"));

    var first = b.mailStore.create({ backend: db });
    first.deleteFolder("Archive");
    first.renameFolder("Drafts", "Entwuerfe");
    check("the delete and rename land in the first handle",
          _names(first).indexOf("Archive") === -1 &&
          _names(first).indexOf("Entwuerfe") !== -1, JSON.stringify(_names(first)));

    var second = b.mailStore.create({ backend: db });
    var names = _names(second);
    check("the deleted folder does not come back when the store is reopened",
          names.indexOf("Archive") === -1, JSON.stringify(names));
    check("and the renamed one is not recreated under its old name",
          names.indexOf("Drafts") === -1 && names.indexOf("Entwuerfe") !== -1,
          JSON.stringify(names));
    var drafts = second.listFolders().filter(function (f) { return f.role === "drafts"; });
    check("so no two folders carry the same role", drafts.length === 1,
          JSON.stringify(drafts));
  })().finally(function () {
    try { if (db) db.close(); } catch (_e) { /* best-effort */ }
    try { nodeFs.rmSync(dataDir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  });
}

function testUidvalidityNeverGoesBackwards() {
  // RFC 9051 2.3.1.1: a client caches UIDs against UIDVALIDITY, and a
  // mailbox deleted and recreated inside the same second used to get the
  // same value back, so the cache was applied to different messages.
  return _withStore(function (store) {
    var first = store.createFolder("Recycled");
    store.deleteFolder("Recycled");
    var second = store.createFolder("Recycled");
    check("a recreated mailbox does not reuse its UIDVALIDITY",
          second.uidvalidity > first.uidvalidity,
          JSON.stringify([first.uidvalidity, second.uidvalidity]));

    store.deleteFolder("Recycled");
    var third = store.createFolder("Recycled");
    check("and it keeps increasing across further cycles",
          third.uidvalidity > second.uidvalidity,
          JSON.stringify([second.uidvalidity, third.uidvalidity]));

    var sibling = store.createFolder("Neighbour");
    check("a different mailbox also gets its own value",
          sibling.uidvalidity > third.uidvalidity,
          JSON.stringify([third.uidvalidity, sibling.uidvalidity]));

    // A default folder is seeded by create() without recording its value, so
    // the mark is seeded from the folders already present. Without that,
    // deleting one of them discards the only trace of the value it used.
    var seededBefore = store.listFolders()
      .filter(function (f) { return f.name === "Archive"; })[0];
    store.deleteFolder("Archive");
    var seededAfter = store.createFolder("Archive");
    check("a seeded default folder does not reuse its UIDVALIDITY either",
          seededAfter.uidvalidity > seededBefore.uidvalidity,
          JSON.stringify([seededBefore.uidvalidity, seededAfter.uidvalidity]));

    // Renaming onto a name that used to exist replaces what that name holds,
    // so it is a new generation of that mailbox: two folders created in the
    // same second carry the same value, and moving one onto the other's name
    // without a fresh one lets a client keep its UID cache for it.
    var doomed = store.listFolders().filter(function (f) { return f.name === "Trash"; })[0];
    store.deleteFolder("Trash");
    var moved = store.renameFolder("Neighbour", "Trash");
    check("a rename onto a previously used name takes a fresh UIDVALIDITY",
          moved.uidvalidity > doomed.uidvalidity,
          JSON.stringify([doomed.uidvalidity, moved.uidvalidity]));
  });
}

function testAFolderCanBeRenamed() {
  return _withStore(function (store) {
    store.createFolder("Old");
    store.renameFolder("Old", "New");
    var names = _names(store);
    check("the new name is listed and the old one is not",
          names.indexOf("New") !== -1 && names.indexOf("Old") === -1,
          JSON.stringify(names));

    store.createFolder("Taken");
    var threw = null;
    try { store.renameFolder("New", "Taken"); } catch (e) { threw = e; }
    check("renaming onto an existing name is refused",
          threw !== null, threw && (threw.code + ": " + threw.message));
  });
}

function testSubscriptionIsRecordedAndListed() {
  return _withStore(function (store) {
    store.createFolder("Watched");
    store.createFolder("Ignored");
    var fresh = store.listFolders().filter(function (f) { return f.subscribed === true; });
    check("a new folder is not subscribed", fresh.length === 0, JSON.stringify(fresh));

    store.subscribeFolder("Watched");
    var subscribed = store.listFolders()
      .filter(function (f) { return f.subscribed === true; })
      .map(function (f) { return f.name; });
    check("subscribeFolder is visible in listFolders",
          JSON.stringify(subscribed) === JSON.stringify(["Watched"]),
          JSON.stringify(subscribed));

    store.unsubscribeFolder("Watched");
    var after = store.listFolders().filter(function (f) { return f.subscribed === true; });
    check("and unsubscribeFolder clears it", after.length === 0, JSON.stringify(after));
  });
}

function testDeleteAndRenameLeaveSubscriptionsAlone() {
  // RFC 9051 6.3.5 and 6.3.6: neither DELETE nor RENAME changes what a
  // client is subscribed to. Holding the flag on the folder row made a
  // delete erase the subscription and a rename carry it to the new name,
  // silently editing the client's subscribed-mailbox list.
  return _withStore(function (store) {
    store.createFolder("Watched");
    store.subscribeFolder("Watched");
    check("the mailbox is subscribed",
          store.listSubscriptions().indexOf("Watched") !== -1,
          JSON.stringify(store.listSubscriptions()));

    store.deleteFolder("Watched");
    check("deleting the mailbox does not unsubscribe it",
          store.listSubscriptions().indexOf("Watched") !== -1,
          JSON.stringify(store.listSubscriptions()));

    store.createFolder("Watched");
    check("and recreating the name finds it still subscribed",
          store.listFolders().filter(function (f) {
            return f.name === "Watched";
          })[0].subscribed === true,
          JSON.stringify(store.listSubscriptions()));

    store.createFolder("Moving");
    store.subscribeFolder("Moving");
    store.renameFolder("Moving", "Moved");
    var after = store.listSubscriptions();
    check("a rename leaves the subscription on the name it was made against",
          after.indexOf("Moving") !== -1 && after.indexOf("Moved") === -1,
          JSON.stringify(after));

    // A subscription outlives its mailbox, so the client has to be able to
    // remove one whose folder is gone; refusing would leave an entry it can
    // see and cannot clear.
    store.unsubscribeFolder("Moving");
    check("unsubscribing a name whose mailbox is gone works",
          store.listSubscriptions().indexOf("Moving") === -1,
          JSON.stringify(store.listSubscriptions()));
  });
}

function testSubscribingAnAbsentFolderIsRefused() {
  return _withStore(function (store) {
    var threw = null;
    try { store.subscribeFolder("Nowhere"); } catch (e) { threw = e; }
    check("subscribing to a folder that is not there is refused",
          threw !== null && threw.code === "mail-store/no-folder",
          threw && (threw.code + ": " + threw.message));
  });
}

async function run() {
  await testAttachmentFactsMatchWhatTheMessageCarries();
  await testAFolderCanBeDeleted();
  await testANamedBodyPartStillReachesTheStoredColumns();
  await testDeletingAFolderTakesItsMessagesWithIt();
  await testInboxCannotBeDeleted();
  await testAFolderCannotBeParkedOnInboxsNameInAnotherCase();
  await testDeletingAFolderThatIsNotThereIsRefused();
  await testAFolderHoldingHeldMessagesIsNotDeleted();
  await testDeletingAFolderTakesItsSearchIndexWithIt();
  await testAParentFolderIsNotDeletedOutFromUnderItsChildren();
  await testInboxIsNotRenamed();
  await testARenameKeepsTheMailboxsUidvalidity();
  await testStoreOperationsComposeInsideACallersTransaction();
  await testAWrapperBackendReportsItsInnerTransaction();
  await testBDbReportsWhetherATransactionIsOpen();
  await testOpeningWithoutInitWritesNothing();
  await testAPrepareOnlyBackendStillWorks();
  await testAPrepareOnlyBackendComposesInsideACallersTransaction();
  await testARefusalInsideACallersTransactionKeepsTheCallersWork();
  await testACallersTransactionSurvivesABackendThatAcceptsANestedBegin();
  await testAFailedDeletionLeavesTheFolderWhole();
  await testAFailedDeletionIsAtomicInsideACallersTransactionToo();
  await testARenameRunsAsOneTransaction();
  await testASecondDatabaseGetsItsOwnTransaction();
  await testInboxAnswersToAnySpellingOfItsName();
  await testAFailedCommitLeavesNoTransactionOpen();
  await testAFolderAlreadyNamedLikeInboxKeepsItsOwnRows();
  await testAFailedCommitOnThePrepareOnlyBackendLeavesNothingStranded();
  await testALifecycleChangeSurvivesReopeningTheStore();
  await testUidvalidityNeverGoesBackwards();
  await testAFolderCanBeRenamed();
  await testSubscriptionIsRecordedAndListed();
  await testDeleteAndRenameLeaveSubscriptionsAlone();
  await testSubscribingAnAbsentFolderIsRefused();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[mail-store-folder-lifecycle] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
