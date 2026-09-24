// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A LIST an authenticated client sends cannot stall the process it is
 * talking to.
 *
 * SMOKE_RUN_SOLO: this file measures growth, and a runner sharing its cores
 * with sixty-three siblings reads contention as a curve.
 *
 * Two ways in, both reachable with a short command the command guard
 * accepts, and both blocking the event loop rather than the request, so an
 * asynchronous handler timeout cannot interrupt them and every other
 * connection, every other account's mail and the health probe stop with it.
 *
 * The first is the matcher. Backtracking over wildcards costs the product of
 * their positions, so `****************x` against an ordinary mailbox name
 * runs past any timeout while carrying only sixteen wildcards: a cap on how
 * many there are does not bound what they cost. The matcher decides the
 * whole pattern against the whole name in one pass over their product
 * instead.
 *
 * The second is the RETURN option scanner. On `RETURN (())` the inner
 * parenthesis produced a zero-length word, which matched no option and left
 * the read position where it was, so the loop ran forever. Every iteration
 * now either consumes a character or refuses the command.
 *
 * The matcher decides each (pattern position, name position) pair once,
 * walking the pattern from its end and filling each row of answers from the
 * row after it, so the whole match costs their product. The RETURN scanner
 * refuses a zero-length word, which is what a character it does not consume
 * produces, so every iteration either advances or refuses.
 *
 * A command may present its last operand as a literal, which arrives beside
 * the command line rather than in it. It is quoted back into the argument
 * text so one operand scanner reads either spelling, rather than each
 * handler learning about literals separately. Its bytes are checked before
 * they become text: decoding turns an invalid byte into U+FFFD rather than
 * failing, and a name that quietly became a different name can address a
 * different mailbox.
 *
 * The rest is the mailbox grammar the matcher has to keep: parentheses
 * inside a quoted pattern are mailbox-name characters rather than list
 * delimiters, and RFC 9051 section 5.1 reserves INBOX case-insensitively, so
 * a client naming it in any spelling finds it. Only a pattern that names
 * INBOX outright is folded; folding one carrying wildcards would widen what
 * those wildcards match, which is the over-matching the grammar exists to
 * stop, and no other mailbox name is folded at all.
 */

var helpers = require("../helpers");
var check   = helpers.check;
var b       = helpers.b;
var nodeNet = require("node:net");
var nodeTls = require("node:tls");

async function _tlsContext() {
  var ca = await b.mtlsEngine.generateCa({ name: "imap-list-bounds-ca" });
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

function _mailStore(extraNames) {
  var folders = [
    { name: "INBOX",        attributes: [], subscribed: true },
    { name: "Archive",      attributes: [], subscribed: false },
    { name: "Archive/2026", attributes: [], subscribed: false },
    { name: "foo)bar",      attributes: [], subscribed: false },
    // A child whose parent level is not a mailbox in its own right.
    { name: "Orphan/Child", attributes: [], subscribed: false },
  ];
  (extraNames || []).forEach(function (n) {
    folders.push({ name: n, attributes: [], subscribed: false });
  });
  return {
    appendMessage: function () { return Promise.resolve(); },
    selectFolder:  function () {
      return Promise.resolve({ uidvalidity: 1, modseq: 1, exists: 0,
                               recent: 0, unseen: 0, flags: [] });
    },
    listFolders: function () { return folders.map(function (f) { return f; }); },
  };
}

async function _open(openOpts) {
  var srv = b.mail.server.imap.create({
    tlsContext: await _tlsContext(),
    mailStore:  _mailStore(openOpts && openOpts.folders),
    profile:    "permissive",
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
    { timeoutMs: 5000, label: "imap list-bounds: greeting" });
  var conn = {
    srv: srv, socket: socket,
    text: function () { return seen; },
    cmd: async function (tag, line) {
      var before = seen.length;
      socket.write(tag + " " + line + "\r\n");
      await helpers.waitUntil(function () {
        return new RegExp("^" + tag + " ", "m").test(seen.slice(before));
      }, { timeoutMs: 8000, label: "imap list-bounds: " + tag + " answered" });
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
    if (m) out.push(m[2].replace(/^"|"$/g, ""));
  }
  return out;
}

async function testAWildcardStormAnswersPromptly() {
  // Sixteen wildcards is inside any count-based cap, and backtracking over
  // them is what costs: the bound has to be on the work, not the count.
  var c = await _open();
  try {
    var started = Date.now();
    var reply = await c.cmd("a1", 'LIST "" "' + "*".repeat(16) + 'x"');
    var elapsed = Date.now() - started;
    check("a pattern of sixteen wildcards answers in well under a second",
          elapsed < 1000, elapsed + "ms");
    check("and matches nothing, since no mailbox ends in x",
          _listed(reply).length === 0, reply);

    // The event loop has to have been free the whole time, which is the
    // property that matters: the next command answers too.
    var after = await c.cmd("a2", 'LIST "" "INBOX"');
    check("the connection still serves the next command",
          _listed(after).length === 1, after);
  } finally { await c.close(); }
}

async function testTheMatcherCostDoesNotGrowWithThePatternLength() {
  // Sixteen wildcards is inside any count-based cap and finishes instantly,
  // so it rules out nothing. The cost of the matcher is the pattern length
  // times the name length, taken once per folder, and the pattern is the
  // one operand the client supplies: LIST carries no per-argument byte cap
  // of its own, so a four-kilobyte pattern fits inside the line cap and is
  // paid against every mailbox, synchronously, before the reply.
  // Enough mailboxes that the per-folder cost is measurable above the
  // helper's floor: with too few, the large sample finishes under it and no
  // ratio is taken, so the assertion holds whatever the matcher costs.
  var names = [];
  for (var f = 0; f < 2000; f += 1) names.push("Folder" + f + "-" + "n".repeat(40));
  var c = await _open({ folders: names });
  try {
    // The literal characters cannot match a shorter name, and a run of
    // wildcards says no more than one of them does, so neither shape has
    // work to do that grows with how much of it the client sends.
    var grew = await helpers.looksSuperlinearAsync(async function (len) {
      await c.cmd("g" + len, 'LIST "" "' + "q".repeat(len) + '"');
    }, { small: 500, large: 4000, threshold: 3, label: "IMAP LIST literal pattern" });
    check("a longer literal pattern does not cost proportionally more",
          grew.superlinear === false, "ratio=" + grew.ratio);

    var grewWild = await helpers.looksSuperlinearAsync(async function (len) {
      await c.cmd("w" + len, 'LIST "" "' + "a*".repeat(len / 2) + 'zz"');
    }, { small: 500, large: 4000, threshold: 3, label: "IMAP LIST wildcard pattern" });
    check("nor does a longer alternating wildcard pattern",
          grewWild.superlinear === false, "ratio=" + grewWild.ratio);

    // LIST has two operands and the client supplies both. The reference is
    // prepended to the pattern before matching, so a bound on one of them
    // leaves the other paying the same cost.
    var grewRef = await helpers.looksSuperlinearAsync(async function (len) {
      await c.cmd("r" + len, 'LIST "' + "%".repeat(len) + '" "*"');
    }, { small: 500, large: 4000, threshold: 3, label: "IMAP LIST reference operand" });
    check("a longer reference does not cost proportionally more either",
          grewRef.superlinear === false, "ratio=" + grewRef.ratio);

    // The bound must not cost correctness: the ordinary patterns still work.
    var listed = _listed(await c.cmd("a9", 'LIST "" "Folder1-*"'));
    check("an ordinary wildcard still matches its mailbox",
          listed.length === 1 && listed[0].indexOf("Folder1-") === 0,
          JSON.stringify(listed.slice(0, 3)));
    check("and the connection still serves the next command",
          _listed(await c.cmd("a10", 'LIST "" "INBOX"')).length === 1);
  } finally { await c.close(); }
}

async function testChildrenReportingDoesNotGrowWithTheMailboxCount() {
  // `RETURN (CHILDREN)` asks, for each mailbox it reports, whether any other
  // mailbox sits under it. Answering that by scanning the whole folder list
  // once per reported mailbox is quadratic in the number of mailboxes, and it
  // runs synchronously before the reply, so the event loop is held for the
  // whole of it and no handler timeout can interrupt it. The answer is a
  // property of the set, so the set is walked once.
  //
  // The size doubles rather than the pattern length: this cost grows with how
  // many mailboxes the account has, which is the operator's data rather than
  // the client's argument.
  // Writing one untagged response per mailbox is honest linear work and would
  // dilute the ratio, so the same LIST is timed with and without the option
  // and the difference is what CHILDREN costs.
  async function childrenOverhead(count) {
    var names = [];
    for (var f = 0; f < count; f += 1) names.push("Box" + f);
    var c = await _open({ folders: names });
    try {
      var t0 = process.hrtime.bigint();
      await c.cmd("k0", 'LIST "" "*"');
      var plain = Number((process.hrtime.bigint() - t0) / 1000000n);
      var t1 = process.hrtime.bigint();
      await c.cmd("k1", 'LIST "" "*" RETURN (CHILDREN)');
      var withChildren = Number((process.hrtime.bigint() - t1) / 1000000n);
      return Math.max(0, withChildren - plain);
    } finally { await c.close(); }
  }

  // Measured on the scan this replaces: 8000 mailboxes cost 66 ms of child
  // checks and 16000 cost 314 ms, a 4.8x rise for a 2x set. A set built once
  // answers both in about a millisecond.
  var small = await childrenOverhead(8000);
  var large = await childrenOverhead(16000);
  var ratio = small < 20 ? 0 : large / small;
  check("doubling the mailbox count does not quadruple what CHILDREN costs" +
        " (small=" + small + "ms large=" + large + "ms)",
        ratio < 3, "ratio=" + ratio);

  // The other scan on the same path. RFC 9051 6.3.9 has LIST report the
  // hierarchy levels between the matched mailboxes, marked \Noselect, and
  // finding which of those levels is not itself a mailbox was a search of the
  // whole list per level. A flat corpus never reaches it, because a flat name
  // has no parent level to enumerate, so the row above passes with it intact.
  // It also runs when the pattern matches nothing.
  async function levelsOverhead(count) {
    var names = [];
    for (var f = 0; f < count; f += 1) names.push("folder" + f + "/child");
    var c = await _open({ folders: names });
    try {
      var t0 = process.hrtime.bigint();
      await c.cmd("j1", 'LIST "" "nothing-matches-this"');
      return Number((process.hrtime.bigint() - t0) / 1000000n);
    } finally { await c.close(); }
  }
  var smallLevels = await levelsOverhead(8000);
  var largeLevels = await levelsOverhead(16000);
  var levelRatio = smallLevels < 20 ? 0 : largeLevels / smallLevels;
  check("enumerating the hierarchy levels does not grow with the square of it" +
        " (small=" + smallLevels + "ms large=" + largeLevels + "ms)",
        levelRatio < 3, "ratio=" + levelRatio);

  // The answer is still correct, which is what stops this being a test of
  // speed alone.
  var c2 = await _open({ folders: ["Parent", "Parent/Child", "Lonely"] });
  try {
    var reply = await c2.cmd("k2", 'LIST "" "*" RETURN (CHILDREN)');
    check("a mailbox with a child is reported as having one",
          /\\HasChildren[^\r\n]*"Parent"/.test(reply), reply.slice(0, 300));
    check("and one without is reported as having none",
          /\\HasNoChildren[^\r\n]*"Lonely"/.test(reply), reply.slice(0, 300));
  } finally { await c2.close(); }
}

async function testTheAggregateMatchingWorkIsBounded() {
  // The per-pattern bounds hold and the aggregate still does not: the matcher
  // costs pattern length times name length, paid once per mailbox, so the
  // product is what a client can drive. Collapsing wildcard RUNS does not
  // touch an ALTERNATING pattern, and the literal-count short-circuit only
  // fires when the pattern's literals outnumber the name's characters, which
  // is why a corpus of short names never pays for it: measured directly,
  // `"*a" x 500 + "z"` costs 2 ms against 2000 forty-character names and
  // 2088 ms against 2000 names of a kilobyte, held synchronously with no
  // handler timeout able to interrupt it.
  var names = [];
  for (var f = 0; f < 2000; f += 1) names.push("Box" + f + "-" + "x".repeat(1024));
  var c = await _open({ folders: names });
  try {
    var started = Date.now();
    var reply = await c.cmd("b1", 'LIST "" "' + ("*a".repeat(500) + "z") + '"');
    var elapsed = Date.now() - started;
    check("a pattern whose product with the mailbox set is unbounded is refused",
          !/^b1 OK/m.test(reply), reply.slice(0, 200));
    check("and nothing is listed for it", _listed(reply).length === 0,
          String(_listed(reply).length));
    // The refusal is the point, and it has to arrive rather than be reached
    // after the work it was meant to avoid.
    check("the refusal arrives without doing the work (" + elapsed + "ms)",
          elapsed < 1000, String(elapsed));

    // A budget spent up front counts the population it was written against.
    // LIST matches three: the folders, the hierarchy levels it synthesizes
    // between them (RFC 9051 6.3.9), and the subscriptions whose folders are
    // gone. Fifty deep names synthesize 24,550 ancestors, so an estimate over
    // the folders alone admitted a request that then matched billions of cells
    // against names the folder list never contained. The budget is charged
    // where the matching happens, so every population pays.
    var deep = [];
    for (var d = 0; d < 50; d += 1) deep.push("folder" + d + "/" + "a/".repeat(490) + "a");
    var deepConn = await _open({ folders: deep });
    try {
      var deepStarted = Date.now();
      var deepReply = await deepConn.cmd("b4",
        'LIST "" "' + ("*a".repeat(250) + "z") + '"');
      var deepElapsed = Date.now() - deepStarted;
      check("the synthesized hierarchy levels are charged too",
            !/^b4 OK/m.test(deepReply), deepReply.slice(0, 200));
      check("and that refusal arrives too (" + deepElapsed + "ms)",
            deepElapsed < 2000, String(deepElapsed));
    } finally { await deepConn.close(); }

    // An ordinary pattern over the same mailbox set is still served, so the
    // bound is on the product and not on having many mailboxes.
    var ordinary = await c.cmd("b2", 'LIST "" "Box7-*"');
    check("an ordinary pattern over the same set still matches",
          _listed(ordinary).length === 1, String(_listed(ordinary).length));
    var everything = await c.cmd("b3", 'LIST "" "*"');
    check("and so does a plain wildcard",
          _listed(everything).length >= 2000, String(_listed(everything).length));
  } finally { await c.close(); }
}

async function testAnEmptyReturnListDoesNotHangTheServer() {
  var c = await _open();
  try {
    var started = Date.now();
    var reply = await c.cmd("a1", 'LIST "" "*" RETURN (())');
    check("the command is answered rather than looping forever",
          Date.now() - started < 3000, String(Date.now() - started));
    check("and it is refused as malformed", /^a1 BAD/m.test(reply), reply);

    var after = await c.cmd("a2", 'LIST "" "INBOX"');
    check("the connection still works afterwards",
          _listed(after).length === 1, after);
  } finally { await c.close(); }
}

async function testAParenInsideAQuotedPatternIsAMailboxCharacter() {
  var c = await _open();
  try {
    var reply = await c.cmd("a1", 'LIST "" ("foo)bar")');
    check("a quoted pattern carrying a parenthesis is not a syntax error",
          /^a1 OK/m.test(reply), reply);
    check("and the mailbox it names is listed",
          _listed(reply).indexOf("foo)bar") !== -1, reply);
  } finally { await c.close(); }
}

async function testInboxIsMatchedCaseInsensitively() {
  var c = await _open();
  try {
    var lower = await c.cmd("a1", 'LIST "" "inbox"');
    check("IMAP's reserved INBOX is found under any spelling",
          _listed(lower).indexOf("INBOX") !== -1, lower);
    var mixed = await c.cmd("a2", 'LIST "" "InBoX"');
    check("including a mixed-case one",
          _listed(mixed).indexOf("INBOX") !== -1, mixed);

    var other = await c.cmd("a3", 'LIST "" "archive"');
    check("but an ordinary mailbox name is still case-sensitive",
          _listed(other).length === 0, other);
  } finally { await c.close(); }
}

async function testAnEmptyPatternAnswersTheDelimiterQuery() {
  // RFC 9051 6.3.9 makes LIST "" "" the way a client learns the hierarchy
  // delimiter and the root. Filtering it like an ordinary pattern matches
  // nothing and leaves the client with no way to ask.
  var c = await _open();
  try {
    var reply = await c.cmd("a1", 'LIST "" ""');
    check("the delimiter query is answered with a LIST response",
          /^\* LIST /m.test(reply), reply);
    check("naming the hierarchy delimiter",
          /^\* LIST \([^)]*\) "\/" ""/m.test(reply), reply);
    check("and the root as an unselectable mailbox",
          /\\Noselect/.test(reply), reply);
    check("the command completes OK", /^a1 OK/m.test(reply), reply);
  } finally { await c.close(); }
}

async function testRecursivematchIsRefusedRatherThanIgnored() {
  // Accepting the option and not implementing it hides subscribed
  // descendants from a client walking the subscription hierarchy, which is
  // the one thing the option exists to reveal.
  var c = await _open();
  try {
    var reply = await c.cmd("a1", 'LIST (SUBSCRIBED RECURSIVEMATCH) "" "%"');
    check("an unimplemented selection option is refused by name",
          /^a1 BAD/m.test(reply), reply);
    var plain = await c.cmd("a2", 'LIST (SUBSCRIBED) "" "%"');
    check("while the option it is paired with still works",
          /^a2 OK/m.test(plain), plain);
  } finally { await c.close(); }
}

async function testAHierarchyLevelWithNoMailboxOfItsOwnIsStillListed() {
  // A store can hold Deep/Nested without holding Deep. Listing one level at
  // a time is how a client browses, so omitting the level makes everything
  // under it undiscoverable; RFC 9051 6.3.9 returns it as \Noselect.
  var c = await _open();
  try {
    var reply = await c.cmd("a1", 'LIST "" "%"');
    check("the level that has no mailbox of its own is listed",
          _listed(reply).indexOf("Orphan") !== -1, reply);
    check("and marked unselectable, because there is nothing to select",
          /^\* LIST \([^)]*\\Noselect[^)]*\) "\/" "Orphan"/m.test(reply), reply);

    var deeper = _listed(await c.cmd("a2", 'LIST "" "Orphan/%"'));
    check("and its children are reachable through it",
          deeper.indexOf("Orphan/Child") !== -1, JSON.stringify(deeper));
  } finally { await c.close(); }
}

async function testAnOperandSentAsALiteralIsStillRead() {
  // A client may present the last operand as a literal, which arrives beside
  // the command line rather than in it. Parsing only the line dropped the
  // pattern, so a valid command answered BAD.
  var c = await _open();
  try {
    var before = c.text().length;
    c.socket.write('a1 LIST "" {1+}\r\n*\r\n');
    await helpers.waitUntil(function () { return /^a1 /m.test(c.text().slice(before)); },
      { timeoutMs: 5000, label: "imap list-bounds: literal pattern answered" });
    var reply = c.text().slice(before);
    check("a pattern sent as a literal is read, not dropped",
          /^a1 OK/m.test(reply), reply);
    check("and it matches as the pattern it is",
          _listed(reply).indexOf("INBOX") !== -1, reply);
  } finally { await c.close(); }
}

async function testALiteralThatIsNotValidUtf8IsRefused() {
  // Decoding turns an invalid byte into U+FFFD rather than failing, so a
  // name that quietly became a different name could address a different
  // mailbox. The bytes are checked before they become text.
  var c = await _open();
  try {
    var before = c.text().length;
    c.socket.write(Buffer.concat([
      Buffer.from("a1 LIST \"\" {1+}\r\n", "utf8"),
      Buffer.from([0xff]),
      Buffer.from("\r\n", "utf8"),
    ]));
    await helpers.waitUntil(function () { return /^a1 /m.test(c.text().slice(before)); },
      { timeoutMs: 5000, label: "imap list-bounds: invalid literal answered" });
    var reply = c.text().slice(before);
    check("a literal that is not valid UTF-8 is refused",
          /^a1 BAD/m.test(reply), reply);
    check("and nothing is listed for it", _listed(reply).length === 0, reply);

    var after = await c.cmd("a2", 'LIST "" "INBOX"');
    check("the connection still serves the next command",
          _listed(after).length === 1, after);
  } finally { await c.close(); }
}

async function testOrdinaryPatternsStillMatch() {
  var c = await _open();
  try {
    var star = _listed(await c.cmd("a1", 'LIST "" "Archive*"')).sort();
    check("* still crosses the delimiter",
          JSON.stringify(star) === JSON.stringify(["Archive", "Archive/2026"]),
          JSON.stringify(star));
    var pct = _listed(await c.cmd("a2", 'LIST "" "Archive/%"'));
    check("% still matches one level",
          JSON.stringify(pct) === JSON.stringify(["Archive/2026"]), JSON.stringify(pct));
    var exact = _listed(await c.cmd("a3", 'LIST "" "Archive"'));
    check("and an exact name is still exact",
          JSON.stringify(exact) === JSON.stringify(["Archive"]), JSON.stringify(exact));
  } finally { await c.close(); }
}

async function run() {
  await testAWildcardStormAnswersPromptly();
  await testTheMatcherCostDoesNotGrowWithThePatternLength();
  await testChildrenReportingDoesNotGrowWithTheMailboxCount();
  await testTheAggregateMatchingWorkIsBounded();
  await testAnEmptyReturnListDoesNotHangTheServer();
  await testAParenInsideAQuotedPatternIsAMailboxCharacter();
  await testInboxIsMatchedCaseInsensitively();
  await testAnEmptyPatternAnswersTheDelimiterQuery();
  await testRecursivematchIsRefusedRatherThanIgnored();
  await testAHierarchyLevelWithNoMailboxOfItsOwnIsStillListed();
  await testAnOperandSentAsALiteralIsStillRead();
  await testALiteralThatIsNotValidUtf8IsRefused();
  await testOrdinaryPatternsStillMatch();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[mail-server-imap-list-bounds] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
