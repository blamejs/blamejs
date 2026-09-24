// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * `LIST` answers what the client asked for, and the mailbox-management verbs
 * reach the store that can carry them.
 *
 * `_handleList` did `void args` and returned every folder for every request,
 * so `LIST "" "INBOX"`, `LIST "" "%"`, `LIST "Archive/" "%"` and
 * `LIST (SUBSCRIBED) "" "*"` all produced the identical full list. Three
 * things follow, in rising order of how badly they fail.
 *
 * A client filtering by pattern got more than it asked for, which is wrong
 * only for a client that trusts the server. `LIST (SUBSCRIBED)` was not
 * answerable at all, and RFC 9051 removes `LSUB` in favour of it, so an
 * IMAP4rev2 client had no way to read a subscription list: an account could
 * subscribe and unsubscribe and never see the result. And
 * `RETURN (STATUS (...))` is the round-trip reduction RFC 9051 section 6.3.9
 * exists to offer; without it a client listing mailboxes issues one `STATUS`
 * per mailbox, which on a large account is hundreds of round trips instead
 * of one.
 *
 * None of it was reachable by composition either, because the handler is
 * registered in the listener's own dispatch table, so a consumer wanting a
 * conforming `LIST` had to reimplement the verb.
 *
 * `CREATE`, `DELETE`, `RENAME`, `SUBSCRIBE` and `UNSUBSCRIBE` answered
 * "not configured" whatever the store could do, which is the same gap seen
 * from the other side: a store that can create a folder could not be asked
 * to, so a client implementing `DELETE` left an empty folder row per deleted
 * mailbox.
 *
 * The matcher follows RFC 9051 section 6.3.9: `%` matches within one
 * hierarchy level, `*` matches across the delimiter, and every other
 * character is literal. The operands are read by a scanner: an astring is a
 * quoted string with backslash escapes or a bare run up to the next space,
 * and a selection or return list is a parenthesised run of bare words.
 *
 * A name that is deleted or renamed no longer identifies the mailbox a
 * session selected under it, and a name recreated afterwards is a different
 * mailbox, so every session holding it returns to the authenticated state
 * and has to SELECT again, the renaming session included: the store gives a
 * renamed mailbox a fresh UIDVALIDITY, so following the rename would leave
 * that client using a cache generation that no longer applies. INBOX is the
 * exception, because RFC 9051 section 6.3.6 leaves it in place while moving
 * its messages elsewhere. A rename carries the whole subtree to the new
 * name, so a session holding a descendant is as stale as one holding the
 * name itself; a delete removes only the mailbox, because RFC 9051 section
 * 6.3.5 does not delete inferiors, so a surviving child stays selected.
 *
 * Accounts are compared field by field rather than by joining their
 * identity into one string: a value carrying the separator would otherwise
 * spell another account's identity and reach into its sessions. `tenantId`
 * scopes an account rather than naming one, so two actors sharing only a
 * tenant are different accounts, and an operator whose actors carry the name
 * somewhere this listener cannot read states it with `opts.accountKey`.
 *
 * A session whose mailbox went away is told so with the RFC 9051 section 7.1
 * `[CLOSED]` response code, rather than discovering it from an unexplained
 * BAD on its next command, or never, if it is idling.
 *
 * A SELECT already in flight when the namespace changes is refused rather
 * than installed: what came back describes the mailbox as it was before, so
 * accepting it would hand the client a selection whose UIDVALIDITY no longer
 * identifies what the name means. The generation is per account, because one
 * account's namespace changing says nothing about another's, and it moves
 * only when which mailboxes exist changes: a CREATE counts, because
 * recreating a deleted name is exactly the case where a name starts meaning
 * something else, and a subscription change does not. The generation is held
 * against the actor and found with the same comparison that decides whose
 * selections a change affects, so the two cannot disagree: a key synthesized
 * by joining the identity fields collides whenever a value can carry the
 * separator between them. Entries are dropped once no session holds the
 * account, so a long-lived listener does not accumulate one per account that
 * ever connected. A SELECT refused this way leaves no mailbox selected, per
 * RFC 9051 section 6.3.2: saying CLOSED while the previous selection stayed
 * in place would let the next command act on a mailbox the client was just
 * told it had lost. A FETCH, STORE or EXPUNGE already reading that mailbox
 * is refused for the same reason: emitting its rows afterwards would
 * describe a mailbox the client has been told it lost, by sequence numbers
 * that no longer mean anything.
 *
 * RFC 9051 section 6.3.9 also has the SUBSCRIBED selection report a
 * subscribed name whose mailbox no longer exists, marked `\NonExistent`:
 * without it a client cannot see the entry it would need to unsubscribe.
 */

var helpers = require("../helpers");
var check   = helpers.check;
var b       = helpers.b;
var nodeNet = require("node:net");
var nodeTls = require("node:tls");

async function _tlsContext() {
  var ca = await b.mtlsEngine.generateCa({ name: "imap-list-test-ca" });
  var leaf = await b.mtlsEngine.signClientCert({
    cn:           "imap.test",
    caCertPem:    ca.caCertPem,
    caKeyPem:     ca.caKeyPem,
    usage:        "server",
    sans:         ["DNS:imap.test", "DNS:localhost", "IP:127.0.0.1"],
    validityDays: 1,
  });
  // The CA is kept so a client can verify this server rather than being told
  // to skip verification.
  LAST_TEST_CA_PEM = ca.caCertPem;
  return nodeTls.createSecureContext({ key: leaf.key, cert: leaf.cert });
}

var LAST_TEST_CA_PEM = null;

// A store that carries a folder namespace with subscriptions, which is what
// the verbs need to be answerable at all.
function _mailStore() {
  var folders = [
    { name: "INBOX",           attributes: [], subscribed: true,  messages: 3 },
    { name: "Archive",         attributes: [], subscribed: false, messages: 0 },
    { name: "Archive/2025",    attributes: [], subscribed: true,  messages: 7 },
    { name: "Archive/2026",    attributes: [], subscribed: false, messages: 1 },
    { name: "Drafts",          attributes: [], subscribed: true,  messages: 0 },
  ];
  function _find(name) {
    for (var i = 0; i < folders.length; i += 1) {
      if (folders[i].name === name) return folders[i];
    }
    return null;
  }
  return {
    folders:       folders,
    appendMessage: function () { return Promise.resolve(); },
    selectFolder:  function () {
      return Promise.resolve({ uidvalidity: 1, modseq: 1, exists: 0,
                               recent: 0, unseen: 0, flags: [] });
    },
    listFolders:   function () {
      return folders.map(function (f) {
        return { name: f.name, attributes: f.attributes.slice(), subscribed: f.subscribed };
      });
    },
    statusFolder:  function (actor, name) {
      var f = _find(name);
      if (!f) throw new Error("no such folder: " + name);
      return { MESSAGES: f.messages, UIDNEXT: f.messages + 1, UIDVALIDITY: 1, UNSEEN: 0 };
    },
    // These take the operands alone, which is the signature b.mailStore
    // ships: a mock that took an actor first would accept calls the real
    // store refuses, and hide exactly that mismatch.
    createFolder:  function (name) {
      if (_find(name)) throw new Error("folder exists: " + name);
      folders.push({ name: name, attributes: [], subscribed: false, messages: 0 });
      return Promise.resolve();
    },
    deleteFolder:  function (name) {
      var f = _find(name);
      if (!f) throw new Error("no such folder: " + name);
      folders.splice(folders.indexOf(f), 1);
      return Promise.resolve();
    },
    renameFolder:  function (from, to) {
      var f = _find(from);
      if (!f) throw new Error("no such folder: " + from);
      f.name = to;
      return Promise.resolve();
    },
    subscribeFolder: function (name) {
      var f = _find(name);
      if (!f) throw new Error("no such folder: " + name);
      f.subscribed = true;
      return Promise.resolve();
    },
    unsubscribeFolder: function (name) {
      var f = _find(name);
      if (!f) throw new Error("no such folder: " + name);
      f.subscribed = false;
      return Promise.resolve();
    },
  };
}

// The mutating verbs take an operator-supplied administrator, called as
// method(actor, ...names), because they change a namespace the client names
// by string: which account may do that is the operator's question. Without
// one the verbs answer NO, which is what they did before they existed.
function _adminFor(store) {
  return {
    createFolder:      function (actor, name) { return store.createFolder(name); },
    deleteFolder:      function (actor, name) { return store.deleteFolder(name); },
    renameFolder:      function (actor, from, to) { return store.renameFolder(from, to); },
    subscribeFolder:   function (actor, name) { return store.subscribeFolder(name); },
    unsubscribeFolder: function (actor, name) { return store.unsubscribeFolder(name); },
  };
}

// Opens one more client against a listener that is already running, so two
// accounts can be on it at once.
async function _connect(port, username) {
  var socket = nodeNet.connect(port, "127.0.0.1");
  await new Promise(function (r) { socket.once("connect", r); });
  var seen = "";
  socket.on("data", function (c) { seen += c.toString("utf8"); });
  await helpers.waitUntil(function () { return /\* OK/.test(seen); },
    { timeoutMs: 5000, label: "imap list: greeting for " + username });
  var conn = {
    socket: socket,
    text: function () { return seen; },
    cmd: async function (tag, line) {
      var before = seen.length;
      socket.write(tag + " " + line + "\r\n");
      await helpers.waitUntil(function () {
        return new RegExp("^" + tag + " ", "m").test(seen.slice(before));
      }, { timeoutMs: 5000, label: "imap list: " + tag + " for " + username });
      return seen.slice(before);
    },
    close: async function () {
      try { socket.destroy(); } catch (_e) { /* best-effort */ }
    },
  };
  await conn.cmd("login", 'LOGIN "' + username + '" "pw"');
  return conn;
}

// Connects in plaintext, issues STARTTLS, and keeps talking over the TLS
// socket the upgrade produces.
async function _connectStartTls(port) {
  var raw = nodeNet.connect(port, "127.0.0.1");
  await new Promise(function (r) { raw.once("connect", r); });
  var greeting = "";
  function onGreeting(c) { greeting += c.toString("utf8"); }
  raw.on("data", onGreeting);
  await helpers.waitUntil(function () { return /\* OK/.test(greeting); },
    { timeoutMs: 5000, label: "imap list: plaintext greeting" });
  raw.write("s1 STARTTLS\r\n");
  await helpers.waitUntil(function () { return /^s1 OK/m.test(greeting); },
    { timeoutMs: 5000, label: "imap list: STARTTLS accepted" });
  raw.removeListener("data", onGreeting);

  var socket = nodeTls.connect({
    socket: raw, servername: "imap.test", ca: [LAST_TEST_CA_PEM],
  });
  await new Promise(function (resolve, reject) {
    socket.once("secureConnect", resolve);
    socket.once("error", reject);
  });
  var seen = "";
  socket.on("data", function (c) { seen += c.toString("utf8"); });
  return {
    socket: socket,
    text: function () { return seen; },
    cmd: async function (tag, line) {
      var before = seen.length;
      socket.write(tag + " " + line + "\r\n");
      await helpers.waitUntil(function () {
        return new RegExp("^" + tag + " ", "m").test(seen.slice(before));
      }, { timeoutMs: 5000, label: "imap list: " + tag + " over TLS" });
      return seen.slice(before);
    },
    close: async function () {
      try { socket.destroy(); } catch (_e) { /* best-effort */ }
      try { raw.destroy(); } catch (_e) { /* best-effort */ }
    },
  };
}

async function _open(store, admin, profileName) {
  var srv = b.mail.server.imap.create({
    tlsContext:   await _tlsContext(),
    mailStore:    store,
    mailboxAdmin: admin === undefined ? _adminFor(store) : admin,
    profile:      profileName || "permissive",
    auth:       {
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
    { timeoutMs: 5000, label: "imap list: greeting" });

  var conn = {
    srv: srv, socket: socket,
    text: function () { return seen; },
    // Send one command and return only the lines it produced.
    cmd: async function (tag, line) {
      var before = seen.length;
      socket.write(tag + " " + line + "\r\n");
      await helpers.waitUntil(function () {
        return new RegExp("^" + tag + " ", "m").test(seen.slice(before));
      }, { timeoutMs: 5000, label: "imap list: " + tag + " answered" });
      return seen.slice(before);
    },
    close: async function () {
      try { socket.destroy(); } catch (_e) { /* best-effort */ }
      try { await srv.close(); } catch (_e) { /* best-effort */ }
    },
  };
  await conn.cmd("a0", 'LOGIN "u1" "pw"');
  return conn;
}

function _listed(reply) {
  var out = [];
  var lines = reply.split("\r\n");
  for (var i = 0; i < lines.length; i += 1) {
    var m = /^\* LIST \(([^)]*)\) "[^"]*" (.+)$/.exec(lines[i]);
    if (m) out.push({ attrs: m[1], name: m[2].replace(/^"|"$/g, "") });
  }
  return out;
}

async function testAnExactNameReturnsOnlyThatMailbox() {
  var c = await _open(_mailStore());
  try {
    var names = _listed(await c.cmd("a1", 'LIST "" "INBOX"')).map(function (e) { return e.name; });
    check("an exact pattern returns only the mailbox asked for",
          names.length === 1 && names[0] === "INBOX", JSON.stringify(names));
  } finally { await c.close(); }
}

async function testPercentMatchesOneHierarchyLevel() {
  var c = await _open(_mailStore());
  try {
    var names = _listed(await c.cmd("a1", 'LIST "" "%"')).map(function (e) { return e.name; }).sort();
    check("% matches one level and does not cross the delimiter",
          JSON.stringify(names) === JSON.stringify(["Archive", "Drafts", "INBOX"]),
          JSON.stringify(names));

    var under = _listed(await c.cmd("a2", 'LIST "" "Archive/%"'))
      .map(function (e) { return e.name; }).sort();
    check("and one level below a prefix is the children of that prefix",
          JSON.stringify(under) === JSON.stringify(["Archive/2025", "Archive/2026"]),
          JSON.stringify(under));
  } finally { await c.close(); }
}

async function testStarMatchesAcrossTheDelimiter() {
  var c = await _open(_mailStore());
  try {
    var names = _listed(await c.cmd("a1", 'LIST "" "Archive*"'))
      .map(function (e) { return e.name; }).sort();
    check("* crosses the hierarchy delimiter",
          JSON.stringify(names) === JSON.stringify(["Archive", "Archive/2025", "Archive/2026"]),
          JSON.stringify(names));
  } finally { await c.close(); }
}

async function testTheReferenceIsPrependedToThePattern() {
  var c = await _open(_mailStore());
  try {
    var names = _listed(await c.cmd("a1", 'LIST "Archive/" "%"'))
      .map(function (e) { return e.name; }).sort();
    check("a reference names the point the pattern starts from",
          JSON.stringify(names) === JSON.stringify(["Archive/2025", "Archive/2026"]),
          JSON.stringify(names));
  } finally { await c.close(); }
}

async function testInboxCaseFoldingFollowsTheRuleListDefines() {
  // Two rules that look like one. RFC 9051 section 5.1 calls INBOX "the
  // case-insensitive mailbox name", which is about NAMING a mailbox, and LIST
  // has its own sentence for pattern matching (RFC 3501 section 6.3.8, carried
  // into RFC 9051): "The special name INBOX is included in the output from
  // LIST, if INBOX is supported by this server for this user and if the
  // uppercase string \"INBOX\" matches the interpreted reference and mailbox
  // name arguments". The pattern is matched AS WRITTEN against the uppercase
  // string; it is not itself folded.
  //
  // So a pattern carrying no wildcard is a name, and a name is
  // case-insensitive: `inbox` finds INBOX. A pattern carrying a wildcard is a
  // pattern, and `inb*` does not match "INBOX", while `INB*` does. Folding the
  // whole pattern instead would make `%x` match INBOX, because INBOX ends in
  // X, which is a pattern the client never meant to write.
  var c = await _open(_mailStore());
  try {
    var ROWS = [
      { pattern: "INBOX",  want: ["INBOX"] },
      { pattern: "inbox",  want: ["INBOX"] },
      { pattern: "InBoX",  want: ["INBOX"] },
      { pattern: "INB*",   want: ["INBOX"] },
      { pattern: "IN*OX",  want: ["INBOX"] },
      { pattern: "inb*",   want: [] },
      { pattern: "%x",     want: [] },
    ];
    var wrong = [];
    for (var i = 0; i < ROWS.length; i += 1) {
      var names = _listed(await c.cmd("c" + i, 'LIST "" "' + ROWS[i].pattern + '"'))
        .map(function (e) { return e.name; }).sort();
      if (JSON.stringify(names) !== JSON.stringify(ROWS[i].want)) {
        wrong.push(ROWS[i].pattern + " -> " + JSON.stringify(names));
      }
    }
    check("INBOX answers a name in any case and a pattern as written" +
          (wrong.length ? " (" + wrong.join("; ") + ")" : ""), wrong.length === 0);

    // Only INBOX is the reserved name; every other mailbox keeps its case.
    var folded = _listed(await c.cmd("c9", 'LIST "" "archive"'))
      .map(function (e) { return e.name; });
    check("and another mailbox is not matched in the wrong case",
          folded.length === 0, JSON.stringify(folded));
  } finally { await c.close(); }
}

async function testEveryMailboxOperandIsHeldToTheByteCap() {
  // `maxMailboxBytes` is a cap in BYTES, and two things read it as though it
  // were a cap in characters written on the first operand alone: the command
  // guard measures the first argument only, and the listener's own name check
  // compared a JavaScript string length. A RENAME names two mailboxes, so its
  // destination went unmeasured, and the backend received a name the guard
  // refuses on the next command that mentions it.
  //
  // 700 CJK characters are 700 UTF-16 units, under the 1024 the name check
  // compared, and 2100 bytes, over the balanced profile's 2048-byte cap. The
  // two measures have to disagree for the row to mean anything, which is why
  // the name is not ASCII.
  var wide = new Array(701).join(String.fromCharCode(0x754c));
  var narrow = new Array(101).join(String.fromCharCode(0x754c));

  // One connection per command: a refusal may close the connection, and a
  // later command sharing it would be measuring the close rather than the cap.
  // The balanced profile refuses LOGIN before TLS, which is the right default
  // and means this cannot use the plaintext opener.
  async function attempt(command) {
    var reached = [];
    var srv = b.mail.server.imap.create({
      tlsContext:   await _tlsContext(),
      mailStore:    _mailStore(),
      profile:      "balanced",
      mailboxAdmin: {
        createFolder: function (actor, name) { reached.push(["create", name.length]); return Promise.resolve(); },
        renameFolder: function (actor, from, to) { reached.push(["rename", to.length]); return Promise.resolve(); },
        deleteFolder: function (actor, name) { reached.push(["delete", name.length]); return Promise.resolve(); },
      },
      auth: {
        mechanisms: ["PLAIN"],
        verify: function () {
          return Promise.resolve({ ok: true, actor: { id: "u1", mailboxes: ["INBOX"] } });
        },
      },
    });
    var info = await srv.listen({ port: 0, address: "127.0.0.1" });
    var c = await _connectStartTls(info.port);
    var reply = "";
    var transcript = "";
    try {
      await c.cmd("z0", 'LOGIN "u1" "pw"');
      reply = await c.cmd("z1", command);
    } catch (e) { reply = "NO ANSWER: " + ((e && e.message) || e); }
    finally {
      try { transcript = c.text().slice(0, 400); } catch (_e) { transcript = ""; }
      await c.close();
      try { await srv.close(); } catch (_e) { /* best-effort */ }
    }
    return { reply: reply, reached: reached, transcript: transcript };
  }

  var renamed = await attempt('RENAME "Archive" "' + wide + '"');
  check("a rename destination over the byte cap does not succeed",
        !/^z1 OK/m.test(renamed.reply), renamed.reply.slice(0, 160));
  // The control that makes the refusal mean something: the backend never saw
  // the name. Without it, an unauthenticated connection or a dropped one
  // would pass the row above.
  check("and the rename never reached the backend",
        renamed.reached.length === 0, JSON.stringify(renamed.reached));

  var created = await attempt('CREATE "' + wide + '"');
  check("a create naming it does not succeed either",
        !/^z1 OK/m.test(created.reply), created.reply.slice(0, 160));
  check("and it never reached the backend",
        created.reached.length === 0, JSON.stringify(created.reached));

  // A non-ASCII name within the cap still works, so the check is the byte
  // length and not the character set, and the backend is reachable at all,
  // which is what makes the two rows above meaningful.
  var ok = await attempt('CREATE "' + narrow + '"');
  check("a non-ASCII name within the cap is accepted",
        /^z1 OK/m.test(ok.reply), ok.transcript);
  check("and reaches the backend with its own name",
        ok.reached.length === 1 && ok.reached[0][0] === "create" &&
        ok.reached[0][1] === 100, JSON.stringify(ok.reached));
}

async function testAWildcardInTheReferenceIsALiteralCharacter() {
  // The reference names the point the pattern starts from; it is a mailbox
  // name, not a pattern. Concatenating it into the pattern made `%` and `*`
  // inside it wildcards, so `LIST "100%/" "*"` matched every sibling whose
  // name begins `100` and returned mailboxes the client never named.
  var store = _mailStore();
  store.folders.push({ name: "100%", attributes: [], subscribed: false, messages: 0 });
  store.folders.push({ name: "100%/Own", attributes: [], subscribed: false, messages: 0 });
  store.folders.push({ name: "100-other", attributes: [], subscribed: false, messages: 0 });
  store.folders.push({ name: "100-other/Secret", attributes: [], subscribed: false, messages: 0 });
  var c = await _open(store);
  try {
    var names = _listed(await c.cmd("r1", 'LIST "100%/" "*"'))
      .map(function (e) { return e.name; }).sort();
    check("a reference is a literal prefix, not a pattern",
          JSON.stringify(names) === JSON.stringify(["100%/Own"]), JSON.stringify(names));

    // The ordinary reference still works, so the fix is the literal reading
    // and not a refusal.
    var under = _listed(await c.cmd("r2", 'LIST "Archive/" "%"'))
      .map(function (e) { return e.name; }).sort();
    check("and an ordinary reference still names where the pattern starts",
          JSON.stringify(under) === JSON.stringify(["Archive/2025", "Archive/2026"]),
          JSON.stringify(under));

    // A pattern that starts at the hierarchy root ignores the reference, which
    // is the rule that already held.
    var rooted = _listed(await c.cmd("r3", 'LIST "Archive/" "/%"'))
      .map(function (e) { return e.name; });
    check("a pattern rooted at the delimiter still ignores the reference",
          rooted.length === 0, JSON.stringify(rooted));
  } finally { await c.close(); }
}

async function testSubscribedSelectionReturnsOnlySubscribedMailboxes() {
  var c = await _open(_mailStore());
  try {
    var reply = await c.cmd("a1", 'LIST (SUBSCRIBED) "" "*"');
    var entries = _listed(reply);
    var names = entries.map(function (e) { return e.name; }).sort();
    check("the SUBSCRIBED selection option filters the list",
          JSON.stringify(names) === JSON.stringify(["Archive/2025", "Drafts", "INBOX"]),
          JSON.stringify(names));
    check("and each is marked \\Subscribed",
          entries.every(function (e) { return e.attrs.indexOf("\\Subscribed") !== -1; }),
          JSON.stringify(entries));
  } finally { await c.close(); }
}

async function testReturnChildrenMarksWhichMailboxesHaveChildren() {
  var c = await _open(_mailStore());
  try {
    var entries = _listed(await c.cmd("a1", 'LIST "" "%" RETURN (CHILDREN)'));
    var byName = {};
    entries.forEach(function (e) { byName[e.name] = e.attrs; });
    check("a mailbox with children is marked \\HasChildren",
          (byName["Archive"] || "").indexOf("\\HasChildren") !== -1,
          JSON.stringify(byName));
    check("and one without is marked \\HasNoChildren",
          (byName["Drafts"] || "").indexOf("\\HasNoChildren") !== -1,
          JSON.stringify(byName));
  } finally { await c.close(); }
}

async function testReturnStatusAnswersInTheSameRoundTrip() {
  var c = await _open(_mailStore());
  try {
    var reply = await c.cmd("a1", 'LIST "" "%" RETURN (STATUS (MESSAGES))');
    check("a STATUS response rides with the listing",
          /^\* STATUS "?INBOX"? \(MESSAGES 3\)/m.test(reply), reply);
    check("and the command still completes OK", /^a1 OK/m.test(reply), reply);
  } finally { await c.close(); }
}

async function testSubscribeAndUnsubscribeChangeWhatIsListed() {
  var store = _mailStore();
  var c = await _open(store);
  try {
    var sub = await c.cmd("a1", 'SUBSCRIBE "Archive"');
    check("SUBSCRIBE is answered by the store, not refused as unconfigured",
          /^a1 OK/m.test(sub), sub);
    var after = _listed(await c.cmd("a2", 'LIST (SUBSCRIBED) "" "*"'))
      .map(function (e) { return e.name; });
    check("the newly subscribed mailbox is listed",
          after.indexOf("Archive") !== -1, JSON.stringify(after));

    var unsub = await c.cmd("a3", 'UNSUBSCRIBE "Archive"');
    check("UNSUBSCRIBE is answered too", /^a3 OK/m.test(unsub), unsub);
    var later = _listed(await c.cmd("a4", 'LIST (SUBSCRIBED) "" "*"'))
      .map(function (e) { return e.name; });
    check("and it drops out of the subscribed list",
          later.indexOf("Archive") === -1, JSON.stringify(later));
  } finally { await c.close(); }
}

async function testCreateDeleteAndRenameReachTheStore() {
  var store = _mailStore();
  var c = await _open(store);
  try {
    var created = await c.cmd("a1", 'CREATE "Projects"');
    check("CREATE reaches a store that can carry it", /^a1 OK/m.test(created), created);
    check("and the folder is there", store.folders.some(function (f) {
      return f.name === "Projects";
    }), JSON.stringify(store.folders.map(function (f) { return f.name; })));

    var renamed = await c.cmd("a2", 'RENAME "Projects" "Work"');
    check("RENAME reaches the store", /^a2 OK/m.test(renamed), renamed);

    var deleted = await c.cmd("a3", 'DELETE "Work"');
    check("DELETE reaches the store", /^a3 OK/m.test(deleted), deleted);
    check("and the folder is gone, not left as an empty row",
          !store.folders.some(function (f) { return f.name === "Work"; }),
          JSON.stringify(store.folders.map(function (f) { return f.name; })));
  } finally { await c.close(); }
}

async function testAPatternOfManyWildcardsIsRefusedNotWalked() {
  // Backtracking is the product of the wildcard positions, so a pattern
  // built only of them is the cheap way to make the server do the work.
  var c = await _open(_mailStore());
  try {
    var started = Date.now();
    var reply = await c.cmd("a1", 'LIST "" "' + "%".repeat(200) + 'x"');
    check("the command still answers promptly",
          Date.now() - started < 3000, String(Date.now() - started));
    check("and matches nothing rather than walking the pattern",
          _listed(reply).length === 0, reply);
    check("the command completes OK", /^a1 OK/m.test(reply), reply);

    var ordinary = _listed(await c.cmd("a2", 'LIST "" "Archive/%"'));
    check("a pattern within the bound still matches",
          ordinary.length === 2, JSON.stringify(ordinary));
  } finally { await c.close(); }
}

async function testASubscriptionOutlivingItsMailboxIsStillListed() {
  // RFC 9051 6.3.9: LIST (SUBSCRIBED) reports a subscribed name whose
  // mailbox no longer exists, marked \NonExistent. Iterating only existing
  // folders hid the entry, leaving a client no way to see what it would
  // need to unsubscribe.
  var nodeFs = require("node:fs");
  var nodeOs = require("node:os");
  var nodePath = require("node:path");
  var dataDir = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), "imap-list-sub-"));
  var db = null;
  var c = null;
  try {
    if (typeof b.vault._resetForTest === "function") b.vault._resetForTest();
    b.cryptoField.clearForTest();
    await b.vault.init({ dataDir: dataDir, mode: "plaintext" });
    db = new (require("node:sqlite").DatabaseSync)(nodePath.join(dataDir, "store.db"));
    var store = b.mailStore.create({ backend: db });

    c = await _open(store, _adminFor(store));
    await c.cmd("a1", 'CREATE "Temporary"');
    await c.cmd("a2", 'SUBSCRIBE "Temporary"');
    await c.cmd("a3", 'DELETE "Temporary"');

    var reply = await c.cmd("a4", 'LIST (SUBSCRIBED) "" "*"');
    var names = _listed(reply).map(function (e) { return e.name; });
    check("the subscription is still listed after its mailbox is gone",
          names.indexOf("Temporary") !== -1, JSON.stringify(names));
    check("and it is marked as no longer existing",
          /\\NonExistent/.test(reply), reply);

    var removed = await c.cmd("a5", 'UNSUBSCRIBE "Temporary"');
    check("the client can unsubscribe it", /^a5 OK/m.test(removed), removed);
    var after = _listed(await c.cmd("a6", 'LIST (SUBSCRIBED) "" "*"'))
      .map(function (e) { return e.name; });
    check("and it is gone from the list",
          after.indexOf("Temporary") === -1, JSON.stringify(after));
  } finally {
    if (c) await c.close();
    try { if (db) db.close(); } catch (_e) { /* best-effort */ }
    try { nodeFs.rmSync(dataDir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  }
}

async function testAnAsyncSubscriptionLookupIsWaitedFor() {
  // Every other store method may answer with a Promise, and this one was
  // read as though it could not: the array was undefined, so a stale
  // subscription silently vanished from the listing.
  var store = _mailStore();
  store.listSubscriptions = function () { return Promise.resolve(["Vanished"]); };
  var c = await _open(store);
  try {
    var reply = await c.cmd("a1", 'LIST (SUBSCRIBED) "" "*"');
    var names = _listed(reply).map(function (e) { return e.name; });
    check("a subscription an async store reports is listed",
          names.indexOf("Vanished") !== -1, JSON.stringify(names));
    check("and marked as no longer existing", /\\NonExistent/.test(reply), reply);
    check("the command still completes OK", /^a1 OK/m.test(reply), reply);
  } finally { await c.close(); }
}

async function testTheVerbsWorkAgainstTheShippedStore() {
  // The mock above answers the signature b.mailStore ships, but only the
  // shipped store proves the listener calls it the way it is written: a
  // mock is a statement about the runtime, and this is the runtime.
  var nodeFs = require("node:fs");
  var nodeOs = require("node:os");
  var nodePath = require("node:path");
  var dataDir = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), "imap-list-real-"));
  var db = null;
  var c = null;
  try {
    if (typeof b.vault._resetForTest === "function") b.vault._resetForTest();
    b.cryptoField.clearForTest();
    await b.vault.init({ dataDir: dataDir, mode: "plaintext" });
    db = new (require("node:sqlite").DatabaseSync)(nodePath.join(dataDir, "store.db"));
    var store = b.mailStore.create({ backend: db });

    c = await _open(store, _adminFor(store));
    var created = await c.cmd("a1", 'CREATE "Projects"');
    check("CREATE reaches the shipped store", /^a1 OK/m.test(created), created);
    check("and the folder is really there",
          store.listFolders().some(function (f) { return f.name === "Projects"; }),
          JSON.stringify(store.listFolders().map(function (f) { return f.name; })));

    var subscribed = await c.cmd("a2", 'SUBSCRIBE "Projects"');
    check("SUBSCRIBE reaches it too", /^a2 OK/m.test(subscribed), subscribed);
    var listed = _listed(await c.cmd("a3", 'LIST (SUBSCRIBED) "" "*"'))
      .map(function (e) { return e.name; });
    check("and the subscription is what LIST (SUBSCRIBED) reads",
          listed.indexOf("Projects") !== -1, JSON.stringify(listed));

    var renamed = await c.cmd("a4", 'RENAME "Projects" "Work"');
    check("RENAME reaches it", /^a4 OK/m.test(renamed), renamed);
    var deleted = await c.cmd("a5", 'DELETE "Work"');
    check("DELETE reaches it", /^a5 OK/m.test(deleted), deleted);
    check("and the folder is gone from the store",
          !store.listFolders().some(function (f) { return f.name === "Work"; }),
          JSON.stringify(store.listFolders().map(function (f) { return f.name; })));

    var inbox = await c.cmd("a6", 'DELETE "INBOX"');
    check("deleting INBOX is refused through the listener too",
          /^a6 NO/m.test(inbox), inbox);
  } finally {
    if (c) await c.close();
    try { if (db) db.close(); } catch (_e) { /* best-effort */ }
    try { nodeFs.rmSync(dataDir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  }
}

async function testRenamingTheSelectedMailboxClosesIt() {
  // The session holds the selected mailbox by name, so a rename left every
  // later FETCH, STORE and EXPUNGE resolving a name that no longer exists.
  // Following the rename is not the answer either: the store gives the
  // renamed mailbox a fresh UIDVALIDITY, so the client's cache generation
  // has changed and it has to SELECT again to learn the new one.
  var store = _mailStore();
  var asked = [];
  store.selectFolder = function (actor, name) {
    asked.push(name);
    return Promise.resolve({ uidvalidity: 1, modseq: 1, exists: 0,
                             recent: 0, unseen: 0, flags: [] });
  };
  var c = await _open(store);
  try {
    await c.cmd("a1", 'SELECT "Archive"');
    var renamed = await c.cmd("a2", 'RENAME "Archive" "Renamed"');
    check("the rename succeeds", /^a2 OK/m.test(renamed), renamed);
    check("and the session is told its mailbox closed",
          /^\* OK \[CLOSED\]/m.test(renamed), renamed);

    asked.length = 0;
    await c.cmd("a3", 'SELECT "Renamed"');
    check("so it selects the mailbox again under its new name, learning the new UIDVALIDITY",
          asked.indexOf("Renamed") !== -1, JSON.stringify(asked));

    var status = await c.cmd("a4", 'STATUS "Renamed" (MESSAGES)');
    check("the renamed mailbox answers STATUS", /^a4 OK/m.test(status), status);
  } finally { await c.close(); }
}

async function testARecreatedNameDoesNotInheritTheOldSelection() {
  // SELECT Archive, DELETE Archive, CREATE Archive: the session was still
  // selected on the name, so EXPUNGE, STORE and FETCH reached the new
  // mailbox with no SELECT of it. A deleted name stops identifying anything,
  // so the session goes back to the authenticated state.
  var store = _mailStore();
  var expunged = [];
  store.expungeFolder = function (actor, name) { expunged.push(name); return Promise.resolve([]); };
  var c = await _open(store);
  try {
    await c.cmd("a1", 'SELECT "Archive"');
    await c.cmd("a2", 'DELETE "Archive"');
    await c.cmd("a3", 'CREATE "Archive"');

    var reply = await c.cmd("a4", "EXPUNGE");
    check("EXPUNGE after the name was deleted and recreated is refused",
          /^a4 (NO|BAD)/m.test(reply), reply);
    check("and it never reached the new mailbox",
          expunged.length === 0, JSON.stringify(expunged));

    var reselect = await c.cmd("a5", 'SELECT "Archive"');
    check("the client can select the new mailbox explicitly",
          /^a5 OK/m.test(reselect), reselect);
  } finally { await c.close(); }
}

async function testAnotherAccountsSelectionIsLeftAlone() {
  // Invalidating by name alone reaches into every session holding that
  // name, so one account deleting its own Archive knocked every other
  // account off theirs and they got selected-state errors they could not
  // explain.
  var store = _mailStore();
  var srv = b.mail.server.imap.create({
    tlsContext:   await _tlsContext(),
    mailStore:    store,
    mailboxAdmin: _adminFor(store),
    profile:      "permissive",
    auth: {
      mechanisms: ["PLAIN"],
      // The account is whatever the client logged in as, so two connections
      // can be two accounts.
      // The listener calls verify(mechanism, creds): taking creds first
      // gives every connection the same fallback identity, which is exactly
      // the mistake that makes an account-scoping test pass for nothing.
      verify: function (mechanism, creds) {
        var who = (creds && creds.username) || "u1";
        return Promise.resolve({ ok: true, actor: { id: who, mailboxes: ["INBOX"] } });
      },
    },
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var one = null;
  var two = null;
  try {
    one = await _connect(info.port, "alice");
    two = await _connect(info.port, "bob");
    await one.cmd("a1", 'SELECT "Archive"');
    await two.cmd("b1", 'SELECT "Archive"');

    await one.cmd("a2", 'DELETE "Archive"');
    var otherStill = await two.cmd("b2", "NOOP");
    check("the other account's connection is still usable",
          /^b2 OK/m.test(otherStill), otherStill);
    // NOOP and CLOSE both answer OK whether or not the selection was
    // released, so neither can tell the two apart. The untagged [CLOSED]
    // this release emits is the signal, and EXPUNGE is the command that
    // reads the selection: it answers "NO No mailbox selected" once it has
    // gone.
    check("the other account was never told its mailbox closed",
          two.text().indexOf("[CLOSED]") === -1,
          JSON.stringify(two.text().slice(-200)));
    var otherActs = await two.cmd("b3", "EXPUNGE");
    check("and it can still act on the mailbox it holds",
          /^b3 OK/m.test(otherActs), otherActs);
    var otherClose = await two.cmd("b4", "CLOSE");
    check("and closes from the selected state",
          /^b4 OK/m.test(otherClose), otherClose);
  } finally {
    if (one) await one.close();
    if (two) await two.close();
    try { await srv.close(); } catch (_e) { /* best-effort */ }
  }
}

async function testTheOtherConnectionIsToldItsMailboxClosed() {
  // Clearing the selection server-side only leaves the client believing it
  // still has one: its next FETCH gets an unexplained BAD, and an idling
  // client is told nothing at all.
  var store = _mailStore();
  var srv = b.mail.server.imap.create({
    tlsContext:   await _tlsContext(),
    mailStore:    store,
    mailboxAdmin: _adminFor(store),
    profile:      "permissive",
    auth: {
      mechanisms: ["PLAIN"],
      verify: function (mechanism, creds) {
        return Promise.resolve({
          ok: true, actor: { id: (creds && creds.username) || "u1", mailboxes: ["INBOX"] },
        });
      },
    },
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var one = null;
  var two = null;
  try {
    one = await _connect(info.port, "alice");
    two = await _connect(info.port, "alice");
    await two.cmd("b1", 'SELECT "Archive"');
    var before = two.text().length;

    await one.cmd("a1", 'DELETE "Archive"');
    await helpers.waitUntil(function () { return /\[CLOSED\]/.test(two.text().slice(before)); },
      { timeoutMs: 5000, label: "imap list: other connection told its mailbox closed" });
    var told = two.text().slice(before);
    check("the other connection is told its mailbox closed",
          /^\* OK \[CLOSED\]/m.test(told), JSON.stringify(told));
    check("and the notice says why", /deleted/.test(told), JSON.stringify(told));

    // The deleting client is in the same position: its own selection is gone
    // and only a tagged OK would leave it believing otherwise.
    await one.cmd("a2", 'CREATE "Own"');
    await one.cmd("a3", 'SELECT "Own"');
    var ownBefore = one.text().length;
    var deleted = await one.cmd("a4", 'DELETE "Own"');
    check("a client deleting its own selected mailbox is told too",
          /^\* OK \[CLOSED\]/m.test(one.text().slice(ownBefore)),
          JSON.stringify(deleted));
  } finally {
    if (one) await one.close();
    if (two) await two.close();
    try { await srv.close(); } catch (_e) { /* best-effort */ }
  }
}

async function testTheNoticeReachesAConnectionThatUpgradedToTls() {
  // STARTTLS replaces the socket, so a notice written to the one saved at
  // connect time would go to a socket nothing is reading.
  var store = _mailStore();
  var srv = b.mail.server.imap.create({
    tlsContext:   await _tlsContext(),
    mailStore:    store,
    mailboxAdmin: _adminFor(store),
    profile:      "permissive",
    auth: {
      mechanisms: ["PLAIN"],
      verify: function () {
        return Promise.resolve({ ok: true, actor: { id: "u1", mailboxes: ["INBOX"] } });
      },
    },
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var plain = null;
  var upgraded = null;
  try {
    upgraded = await _connectStartTls(info.port);
    await upgraded.cmd("t1", 'LOGIN "u1" "pw"');
    await upgraded.cmd("t2", 'SELECT "Archive"');
    var before = upgraded.text().length;

    plain = await _connect(info.port, "u1");
    await plain.cmd("p1", 'DELETE "Archive"');

    await helpers.waitUntil(
      function () { return /\[CLOSED\]/.test(upgraded.text().slice(before)); },
      { timeoutMs: 5000, label: "imap list: notice reaches the upgraded socket" });
    check("the notice reaches the connection over its TLS socket",
          /^\* OK \[CLOSED\]/m.test(upgraded.text().slice(before)),
          JSON.stringify(upgraded.text().slice(before)));
  } finally {
    if (plain) await plain.close();
    if (upgraded) await upgraded.close();
    try { await srv.close(); } catch (_e) { /* best-effort */ }
  }
}

async function testTenantAloneDoesNotMakeTwoActorsOneAccount() {
  // tenantId scopes an account rather than naming one, so two actors that
  // share only a tenant are different accounts. Treating them as one let a
  // delete by either clear the other's selection.
  var store = _mailStore();
  var srv = b.mail.server.imap.create({
    tlsContext:   await _tlsContext(),
    mailStore:    store,
    mailboxAdmin: _adminFor(store),
    profile:      "permissive",
    auth: {
      mechanisms: ["PLAIN"],
      // Named by a field the listener DOES read, so the tenant rule is what
      // the test exercises. Naming them by a field it does not read would
      // leave both actors unnamed, and two unnamed actors are already
      // different accounts: the assertion would hold for two identical
      // actors too, which is not the rule being pinned.
      verify: function (mechanism, creds) {
        return Promise.resolve({
          ok: true,
          actor: { tenantId: "t1", id: (creds && creds.username) || "x",
                   mailboxes: ["INBOX"] },
        });
      },
    },
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var alice = null;
  var bob = null;
  try {
    alice = await _connect(info.port, "alice");
    bob = await _connect(info.port, "bob");
    await bob.cmd("b1", 'SELECT "Archive"');
    var before = bob.text().length;

    await alice.cmd("a1", 'DELETE "Archive"');
    await helpers.passiveObserve(300, "imap list: bob's selection is not disturbed");
    check("an actor sharing only a tenant does not clear the other's selection",
          !/\[CLOSED\]/.test(bob.text().slice(before)),
          JSON.stringify(bob.text().slice(before)));
    var still = await bob.cmd("b2", "NOOP");
    check("and that connection is still usable", /^b2 OK/m.test(still), still);

    // The other direction, so the rule is pinned rather than the absence of
    // one: two connections that ARE the same account inside that tenant do
    // release each other's selection.
    var sameOne = await _connect(info.port, "carol");
    var sameTwo = await _connect(info.port, "carol");
    try {
      await sameTwo.cmd("c1", 'SELECT "Archive/2026"');
      var mark = sameTwo.text().length;
      await sameOne.cmd("c2", 'DELETE "Archive/2026"');
      await helpers.waitUntil(function () {
        return /\[CLOSED\]/.test(sameTwo.text().slice(mark));
      }, { timeoutMs: 5000, label: "imap list: the same account's selection is released" });
      check("while one account's own second connection is told its mailbox closed",
            /\[CLOSED\]/.test(sameTwo.text().slice(mark)),
            JSON.stringify(sameTwo.text().slice(mark)));
    } finally {
      await sameOne.close();
      await sameTwo.close();
    }
  } finally {
    if (alice) await alice.close();
    if (bob) await bob.close();
    try { await srv.close(); } catch (_e) { /* best-effort */ }
  }
}

async function testAnOperatorCanNameTheAccountExplicitly() {
  // opts.accountKey is the contract for an actor shape this listener cannot
  // read: with it, two connections for one account are matched again.
  var store = _mailStore();
  var srv = b.mail.server.imap.create({
    tlsContext:   await _tlsContext(),
    mailStore:    store,
    mailboxAdmin: _adminFor(store),
    profile:      "permissive",
    accountKey:   function (actor) { return actor.tenantId + "/" + actor.accountId; },
    auth: {
      mechanisms: ["PLAIN"],
      verify: function (mechanism, creds) {
        return Promise.resolve({
          ok: true,
          actor: { tenantId: "t1", accountId: (creds && creds.username) || "x",
                   mailboxes: ["INBOX"] },
        });
      },
    },
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var first = null;
  var second = null;
  try {
    first = await _connect(info.port, "alice");
    second = await _connect(info.port, "alice");
    await second.cmd("s1", 'SELECT "Archive"');
    var before = second.text().length;

    await first.cmd("f1", 'DELETE "Archive"');
    await helpers.waitUntil(function () { return /\[CLOSED\]/.test(second.text().slice(before)); },
      { timeoutMs: 5000, label: "imap list: accountKey matched the sessions" });
    check("the operator's accountKey matches two sessions of one account",
          /^\* OK \[CLOSED\]/m.test(second.text().slice(before)),
          JSON.stringify(second.text().slice(before)));
  } finally {
    if (first) await first.close();
    if (second) await second.close();
    try { await srv.close(); } catch (_e) { /* best-effort */ }
  }
}

async function testASubscriptionChangeDoesNotDisturbAnotherAccountsSelect() {
  // The generation that refuses a stale SELECT is per account, and a
  // subscription change does not alter which mailboxes exist. A single
  // counter bumped by every verb let ordinary subscription traffic refuse
  // other users' SELECTs on mailboxes nothing had touched.
  var store = _mailStore();
  var release = null;
  store.selectFolder = function () {
    return new Promise(function (resolve) {
      release = function () {
        resolve({ uidvalidity: 1, modseq: 1, exists: 0, recent: 0, unseen: 0, flags: [] });
      };
    });
  };
  var srv = b.mail.server.imap.create({
    tlsContext:   await _tlsContext(),
    mailStore:    store,
    mailboxAdmin: _adminFor(store),
    profile:      "permissive",
    auth: {
      mechanisms: ["PLAIN"],
      verify: function (mechanism, creds) {
        return Promise.resolve({
          ok: true, actor: { id: (creds && creds.username) || "x", mailboxes: ["INBOX"] },
        });
      },
    },
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var alice = null;
  var bob = null;
  try {
    alice = await _connect(info.port, "alice");
    bob = await _connect(info.port, "bob");

    // Bob's SELECT is in flight, held open by the store above.
    var pending = bob.cmd("b1", 'SELECT "Archive"');
    await helpers.waitUntil(function () { return release !== null; },
      { timeoutMs: 5000, label: "imap list: bob's select reached the store" });

    await alice.cmd("a1", 'SUBSCRIBE "Drafts"');
    await alice.cmd("a2", 'CREATE "AlicesOwn"');
    release();
    var reply = await pending;
    check("another account's namespace activity does not refuse this SELECT",
          /^b1 OK/m.test(reply), reply);
  } finally {
    if (alice) await alice.close();
    if (bob) await bob.close();
    try { await srv.close(); } catch (_e) { /* best-effort */ }
  }
}

async function testAThrowingAccountKeyDoesNotKillTheListener() {
  // The hook is the operator's code and runs against whatever their verify()
  // returned, so it throws on a shape they did not anticipate. It is called
  // from the socket close path, where a throw is an uncaught exception
  // rather than a failed command: the whole listener goes down, taking every
  // other account's session with it. A service account that authenticates
  // and disconnects is enough to reach it.
  var store = _mailStore();
  var srv = b.mail.server.imap.create({
    tlsContext:   await _tlsContext(),
    mailStore:    store,
    mailboxAdmin: _adminFor(store),
    profile:      "permissive",
    accountKey:   function (actor) { return actor.tenant.name; },
    auth: {
      mechanisms: ["PLAIN"],
      verify: function (mechanism, creds) {
        var who = (creds && creds.username) || "x";
        // The service account carries no `tenant`, so the hook throws on it.
        var actor = who === "service"
          ? { id: "service", mailboxes: ["INBOX"] }
          : { id: who, tenant: { name: "t1" }, mailboxes: ["INBOX"] };
        return Promise.resolve({ ok: true, actor: actor });
      },
    },
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var held = null;
  try {
    held = await _connect(info.port, "ada");
    await held.cmd("a1", 'CREATE "Fresh"');

    var service = await _connect(info.port, "service");
    await service.close();
    await helpers.passiveObserve(300, "imap list: the listener survives the hook throwing");

    var still = await held.cmd("a2", "NOOP");
    check("the listener is still answering after the hook threw",
          /^a2 OK/m.test(still), still);
    var listed = await held.cmd("a3", 'LIST "" "*"');
    check("and still serving the accounts that remain",
          /^a3 OK/m.test(listed), listed);
  } finally {
    if (held) await held.close();
    try { await srv.close(); } catch (_e) { /* best-effort */ }
  }
}

async function testAMistypedOptionIsRefusedRatherThanIgnored() {
  // Both options decide a rule rather than a value: without mailboxAdmin the
  // five mailbox verbs are refused, and without accountKey the listener
  // compares actors field by field instead of asking the operator. Reading
  // each only when it has the right type meant a misspelling or a typo'd
  // shape changed the listener's behaviour with nothing said.
  var ctx = await _tlsContext();
  var store = _mailStore();
  var cases = [
    { opt: "mailboxAdmin", value: function () {}, code: "mail-server-imap/bad-mailbox-admin" },
    { opt: "accountKey",   value: { key: "x" },   code: "mail-server-imap/bad-account-key" },
  ];
  var wrong = [];
  cases.forEach(function (row) {
    var made = { tlsContext: ctx, mailStore: store, profile: "permissive" };
    made[row.opt] = row.value;
    var threw = null;
    try { b.mail.server.imap.create(made); } catch (e) { threw = e; }
    if (!threw || threw.code !== row.code) {
      wrong.push(row.opt + " -> " + (threw ? threw.code : "accepted"));
    }
  });
  check("a mistyped option is refused by name" +
        (wrong.length ? " (" + wrong.join("; ") + ")" : ""), wrong.length === 0);

  // The absent case is still the documented one: no mailboxAdmin is a
  // deployment that does not offer the verbs.
  var noneThrew = null;
  try {
    b.mail.server.imap.create({ tlsContext: ctx, mailStore: store, profile: "permissive" });
  } catch (e) { noneThrew = e; }
  check("while leaving them out is still allowed",
        noneThrew === null, noneThrew && noneThrew.code);
}

async function testSubscribingDoesNotRefuseTheAccountsOwnSelect() {
  // The rule has two halves and only one was observable. CREATE, DELETE and
  // RENAME change which mailboxes exist, so an in-flight SELECT for the same
  // account is answered NO rather than with a view taken before the change.
  // SUBSCRIBE and UNSUBSCRIBE change no such thing, so the same SELECT has
  // to survive them. Tested on ONE account: across accounts both halves
  // behave alike, which is why the existing case cannot tell them apart.
  var store = _mailStore();
  var release = null;
  store.selectFolder = function () {
    return new Promise(function (resolve) {
      release = function () {
        resolve({ uidvalidity: 1, modseq: 1, exists: 0, recent: 0, unseen: 0, flags: [] });
      };
    });
  };
  var srv = b.mail.server.imap.create({
    tlsContext:   await _tlsContext(),
    mailStore:    store,
    mailboxAdmin: _adminFor(store),
    profile:      "permissive",
    auth: {
      mechanisms: ["PLAIN"],
      // Both connections are the SAME account, which is what makes the two
      // halves of the rule distinguishable.
      verify: function () {
        return Promise.resolve({ ok: true, actor: { id: "ada", mailboxes: ["INBOX"] } });
      },
    },
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var one = null;
  var two = null;
  try {
    one = await _connect(info.port, "ada");
    two = await _connect(info.port, "ada");

    var pending = one.cmd("a1", 'SELECT "Archive"');
    await helpers.waitUntil(function () { return release !== null; },
      { timeoutMs: 5000, label: "imap list: the held SELECT reached the store" });
    await two.cmd("b1", 'SUBSCRIBE "Drafts"');
    release();
    check("subscribing does not refuse the account's own in-flight SELECT",
          /^a1 OK/m.test(await pending), "subscribe half");

    release = null;
    var pendingTwo = one.cmd("a2", 'SELECT "Archive"');
    await helpers.waitUntil(function () { return release !== null; },
      { timeoutMs: 5000, label: "imap list: the second held SELECT reached the store" });
    await two.cmd("b2", 'CREATE "Fresh"');
    release();
    check("while creating a mailbox does refuse it",
          /^a2 NO/m.test(await pendingTwo), "create half");
  } finally {
    if (one) await one.close();
    if (two) await two.close();
    try { await srv.close(); } catch (_e) { /* best-effort */ }
  }
}

async function testTwoIdentitiesThatLookAlikeStayApart() {
  // `{username: "user@tenant"}` and `{username: "user", tenantId: "tenant"}`
  // are different accounts, and a generation key built by joining the fields
  // makes them one. Tracking the generation against the actor, found with
  // the same comparison that decides whose selections a change affects,
  // leaves no second answer to disagree with.
  var store = _mailStore();
  var release = null;
  store.selectFolder = function () {
    return new Promise(function (resolve) {
      release = function () {
        resolve({ uidvalidity: 1, modseq: 1, exists: 0, recent: 0, unseen: 0, flags: [] });
      };
    });
  };
  var srv = b.mail.server.imap.create({
    tlsContext:   await _tlsContext(),
    mailStore:    store,
    mailboxAdmin: _adminFor(store),
    profile:      "permissive",
    auth: {
      mechanisms: ["PLAIN"],
      verify: function (mechanism, creds) {
        var name = (creds && creds.username) || "";
        return Promise.resolve(name === "joined"
          ? { ok: true, actor: { username: "user@tenant", mailboxes: ["INBOX"] } }
          : { ok: true, actor: { username: "user", tenantId: "tenant", mailboxes: ["INBOX"] } });
      },
    },
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var joined = null;
  var split = null;
  try {
    joined = await _connect(info.port, "joined");
    split = await _connect(info.port, "split");

    var pending = split.cmd("s1", 'SELECT "Archive"');
    await helpers.waitUntil(function () { return release !== null; },
      { timeoutMs: 5000, label: "imap list: the split identity's select is in flight" });

    await joined.cmd("j1", 'CREATE "JoinedOwn"');
    release();
    var reply = await pending;
    check("the look-alike account's CREATE does not refuse this SELECT",
          /^s1 OK/m.test(reply), reply);
  } finally {
    if (joined) await joined.close();
    if (split) await split.close();
    try { await srv.close(); } catch (_e) { /* best-effort */ }
  }
}

async function testAnInFlightFetchDoesNotAnswerForAClosedMailbox() {
  // The mailbox a FETCH reads can go away while the read is in flight, and
  // emitting its rows afterwards describes a mailbox the client has already
  // been told it lost, by sequence numbers that no longer mean anything.
  var store = _mailStore();
  var release = null;
  store.selectFolder = function () {
    return Promise.resolve({ uidvalidity: 1, modseq: 1, exists: 1,
                             recent: 0, unseen: 0, flags: [] });
  };
  store.fetchRange = function () {
    return new Promise(function (resolve) {
      release = function () { resolve([{ seq: 1, uid: 1, parts: "FLAGS (\\Seen)" }]); };
    });
  };
  var srv = b.mail.server.imap.create({
    tlsContext:   await _tlsContext(),
    mailStore:    store,
    mailboxAdmin: _adminFor(store),
    profile:      "permissive",
    auth: {
      mechanisms: ["PLAIN"],
      verify: function (mechanism, creds) {
        return Promise.resolve({
          ok: true, actor: { id: (creds && creds.username) || "x", mailboxes: ["INBOX"] },
        });
      },
    },
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var reader = null;
  var deleter = null;
  try {
    reader = await _connect(info.port, "alice");
    deleter = await _connect(info.port, "alice");
    await reader.cmd("r1", 'SELECT "Archive"');

    var pending = reader.cmd("r2", "FETCH 1 FLAGS");
    await helpers.waitUntil(function () { return release !== null; },
      { timeoutMs: 5000, label: "imap list: the fetch reached the store" });

    await deleter.cmd("d1", 'DELETE "Archive"');
    release();
    var reply = await pending;
    check("the fetch is refused rather than answering for the closed mailbox",
          /^r2 NO/m.test(reply), reply);
    check("and no FETCH row is emitted after the close",
          !/^\* 1 FETCH/m.test(reply), reply);
  } finally {
    if (reader) await reader.close();
    if (deleter) await deleter.close();
    try { await srv.close(); } catch (_e) { /* best-effort */ }
  }
}

async function testDeletingAParentLeavesAChildsSelectionAlone() {
  // RFC 9051 6.3.5: DELETE removes the mailbox, not its inferiors. A RENAME
  // carries the subtree, so a descendant's selection is stale then; a delete
  // of the parent leaves a surviving child exactly where it was.
  var store = _mailStore();
  var c = await _open(store);
  try {
    await c.cmd("a1", 'SELECT "Archive/2025"');
    var before = c.text().length;
    await c.cmd("a2", 'DELETE "Archive"');
    check("the child's session is not told its mailbox closed",
          !/\[CLOSED\]/.test(c.text().slice(before)),
          JSON.stringify(c.text().slice(before)));

    var status = await c.cmd("a3", 'STATUS "Archive/2025" (MESSAGES)');
    check("and the child is still there to act on", /^a3 OK/m.test(status), status);
  } finally { await c.close(); }
}

async function testRenamingInboxDoesNotMoveTheSelection() {
  // RFC 9051 6.3.6 renaming INBOX moves its messages and leaves INBOX in
  // place, so a session selected on INBOX is still selected on INBOX.
  // Following the rename would silently point FETCH, STORE and EXPUNGE at
  // the destination with no SELECT of it.
  var store = _mailStore();
  var selected = [];
  store.selectFolder = function (actor, name) {
    selected.push(name);
    return Promise.resolve({ uidvalidity: 1, modseq: 1, exists: 0,
                             recent: 0, unseen: 0, flags: [] });
  };
  var moved = [];
  var admin = _adminFor(store);
  admin.renameFolder = function (actor, from, to) { moved.push([from, to]); return Promise.resolve(); };
  var c = await _open(store, admin);
  try {
    await c.cmd("a1", 'SELECT "INBOX"');
    var renamed = await c.cmd("a2", 'RENAME "INBOX" "Archived"');
    check("the administrator is asked to perform the INBOX rename",
          /^a2 OK/m.test(renamed) && moved.length === 1, renamed);

    check("the session is not told its mailbox closed",
          !/\[CLOSED\]/.test(renamed), JSON.stringify(renamed));

    // STATUS reads its mailbox out of its own arguments and never looks at
    // the session's selection, so it answers OK whether the selection was
    // released or not: both outcomes mapped into it. EXPUNGE is the command
    // that reads the selection. This store has no expungeFolder, so a
    // selected session is answered OK and a released one is answered
    // "NO No mailbox selected".
    selected.length = 0;
    var acted = await c.cmd("a3", "EXPUNGE");
    check("and INBOX is still the mailbox the session can act on",
          /^a3 OK/m.test(acted), acted);
    check("without the session having reselected anything",
          selected.length === 0, JSON.stringify(selected));
  } finally { await c.close(); }
}

async function testAStoreWithoutTheseVerbsStillRefusesCleanly() {
  // A consumer whose store cannot manage folders must get a refusal, not a
  // crash, and the refusal has to say the server cannot do it.
  var bare = {
    appendMessage: function () { return Promise.resolve(); },
    selectFolder:  function () {
      return Promise.resolve({ uidvalidity: 1, modseq: 1, exists: 0,
                               recent: 0, unseen: 0, flags: [] });
    },
  };
  var c = await _open(bare, null);
  try {
    var reply = await c.cmd("a1", 'CREATE "Whatever"');
    check("with no mailboxAdmin the mutating verbs refuse by name",
          /^a1 NO/m.test(reply), reply);
    check("and say they are not configured rather than failing obscurely",
          /not configured/.test(reply), reply);
    var listed = await c.cmd("a2", 'LIST "" "*"');
    check("and LIST still answers the default namespace",
          /^\* LIST .*INBOX/m.test(listed) && /^a2 OK/m.test(listed), listed);
  } finally { await c.close(); }
}

async function run() {
  await testAnExactNameReturnsOnlyThatMailbox();
  await testPercentMatchesOneHierarchyLevel();
  await testStarMatchesAcrossTheDelimiter();
  await testTheReferenceIsPrependedToThePattern();
  await testInboxCaseFoldingFollowsTheRuleListDefines();
  await testAWildcardInTheReferenceIsALiteralCharacter();
  await testEveryMailboxOperandIsHeldToTheByteCap();
  await testSubscribedSelectionReturnsOnlySubscribedMailboxes();
  await testReturnChildrenMarksWhichMailboxesHaveChildren();
  await testReturnStatusAnswersInTheSameRoundTrip();
  await testSubscribeAndUnsubscribeChangeWhatIsListed();
  await testCreateDeleteAndRenameReachTheStore();
  await testAPatternOfManyWildcardsIsRefusedNotWalked();
  await testASubscriptionOutlivingItsMailboxIsStillListed();
  await testAnAsyncSubscriptionLookupIsWaitedFor();
  await testTheVerbsWorkAgainstTheShippedStore();
  await testRenamingTheSelectedMailboxClosesIt();
  await testARecreatedNameDoesNotInheritTheOldSelection();
  await testAnotherAccountsSelectionIsLeftAlone();
  await testTheOtherConnectionIsToldItsMailboxClosed();
  await testTheNoticeReachesAConnectionThatUpgradedToTls();
  await testTenantAloneDoesNotMakeTwoActorsOneAccount();
  await testAnOperatorCanNameTheAccountExplicitly();
  await testASubscriptionChangeDoesNotDisturbAnotherAccountsSelect();
  await testAThrowingAccountKeyDoesNotKillTheListener();
  await testAMistypedOptionIsRefusedRatherThanIgnored();
  await testSubscribingDoesNotRefuseTheAccountsOwnSelect();
  await testTwoIdentitiesThatLookAlikeStayApart();
  await testAnInFlightFetchDoesNotAnswerForAClosedMailbox();
  await testDeletingAParentLeavesAChildsSelectionAlone();
  await testRenamingInboxDoesNotMoveTheSelection();
  await testAStoreWithoutTheseVerbsStillRefusesCleanly();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[mail-server-imap-list] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
