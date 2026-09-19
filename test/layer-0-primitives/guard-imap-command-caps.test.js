// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Every cap `b.guardImapCommand`'s profiles declare is a cap `validate`
 * applies, and the listener reads the profile's answer rather than its own.
 *
 * The three profiles each declared six caps and `validate` read two,
 * `maxLineBytes` and `maxLiteralBytes`. `maxMailboxBytes`,
 * `maxSequenceSetItems` and `maxSearchDepth` appeared nowhere else in the
 * framework, so a consumer selecting the strict profile for its sequence-set
 * bound got the line bound and nothing else: the effective limit moved with
 * the length of the line rather than with the element count the cap names,
 * and nothing bounded `SEARCH` nesting at all. A seventh value,
 * `allowLegacyMUtf7`, was read by the listener from `profile === "permissive"`
 * rather than from the table, so under the balanced profile the table said
 * legacy modified UTF-7 mailbox names were allowed and the listener refused
 * them.
 *
 * The caps name real resources RFC 9051 leaves to the server: §5.1 a mailbox
 * name, §6.4.8 a sequence set, §6.4.4 the nesting of a SEARCH key.
 */

var helpers = require("../helpers");
var check   = helpers.check;
var b       = helpers.b;

function _refusal(line, opts) {
  try { b.guardImapCommand.validate(line, opts || {}); return null; }
  catch (e) { return e.code || "threw"; }
}

function testEveryDeclaredCapIsRead() {
  // The mechanical form of the guarantee: a cap in the table that no code
  // reads is a number the operator sets and nothing obeys.
  var fs   = require("node:fs");
  var path = require("node:path");
  var root = path.join(__dirname, "..", "..", "lib");
  var sources = fs.readdirSync(root)
    .filter(function (f) { return /\.js$/.test(f); })
    .map(function (f) { return fs.readFileSync(path.join(root, f), "utf8"); })
    .join("\n");
  var declared = Object.create(null);
  Object.keys(b.guardImapCommand.PROFILES).forEach(function (p) {
    Object.keys(b.guardImapCommand.PROFILES[p]).forEach(function (k) { declared[k] = 1; });
  });
  var unread = Object.keys(declared).filter(function (k) {
    return sources.indexOf("." + k) === -1;
  });
  check("every declared IMAP profile cap is read somewhere in lib/" +
        (unread.length ? " (" + unread.join(", ") + " read nowhere)" : ""),
        unread.length === 0);
}

function testTheMailboxNameCapIsApplied() {
  var strict = b.guardImapCommand.PROFILES.strict.maxMailboxBytes;
  var atCap  = "A001 SELECT " + "m".repeat(strict);
  var over   = "A001 SELECT " + "m".repeat(strict + 1);
  check("a mailbox name at the cap is accepted",
        _refusal(atCap, { profile: "strict" }) === null,
        String(_refusal(atCap, { profile: "strict" })));
  check("a mailbox name over the cap is refused by name",
        _refusal(over, { profile: "strict" }) === "guard-imap-command/mailbox-too-long",
        String(_refusal(over, { profile: "strict" })));
  // The cap is the profile's, not a constant: permissive allows more.
  check("the profile chooses the cap",
        _refusal(over, { profile: "permissive" }) === null,
        String(_refusal(over, { profile: "permissive" })));
  // Counted in BYTES, so a multibyte name cannot buy extra length.
  var multibyte = "A001 SELECT " + "é".repeat(strict);
  check("the cap counts bytes, not code units",
        _refusal(multibyte, { profile: "strict" }) === "guard-imap-command/mailbox-too-long",
        String(_refusal(multibyte, { profile: "strict" })));
}

function testTheSequenceSetCapIsApplied() {
  // A sequence set's cost is the number of elements it expands to, which a
  // range states without spelling out: `1:100000` is one short token.
  var strict = b.guardImapCommand.PROFILES.strict.maxSequenceSetItems;
  var under  = "A001 FETCH 1:" + strict + " (FLAGS)";
  var over   = "A001 FETCH 1:" + (strict + 1) + " (FLAGS)";
  check("a sequence set at the cap is accepted",
        _refusal(under, { profile: "strict" }) === null,
        String(_refusal(under, { profile: "strict" })));
  check("a range expanding past the cap is refused by name",
        _refusal(over, { profile: "strict" }) === "guard-imap-command/sequence-set-too-large",
        String(_refusal(over, { profile: "strict" })));
  check("an enumerated set is counted the same way",
        _refusal("A001 STORE 1,2,3 +FLAGS (\\Seen)", { profile: "strict" }) === null);
  check("the profile chooses the cap",
        _refusal(over, { profile: "permissive" }) === null,
        String(_refusal(over, { profile: "permissive" })));
  // `*` is the largest message number, not an unbounded expansion, so a
  // range to it cannot be counted and is not refused on count alone.
  check("a range to * is not refused for its count",
        _refusal("A001 FETCH 1:* (FLAGS)", { profile: "strict" }) === null,
        String(_refusal("A001 FETCH 1:* (FLAGS)", { profile: "strict" })));
}

function testTheSearchDepthCapIsApplied() {
  var strict = b.guardImapCommand.PROFILES.strict.maxSearchDepth;
  function nested(depth) {
    var inner = "FROM alice";
    for (var i = 0; i < depth; i += 1) inner = "(" + inner + ")";
    return "A001 SEARCH " + inner;
  }
  check("a SEARCH key at the depth cap is accepted",
        _refusal(nested(strict), { profile: "strict" }) === null,
        String(_refusal(nested(strict), { profile: "strict" })));
  check("a SEARCH key past the depth cap is refused by name",
        _refusal(nested(strict + 1), { profile: "strict" }) === "guard-imap-command/search-too-deep",
        String(_refusal(nested(strict + 1), { profile: "strict" })));
  check("the profile chooses the cap",
        _refusal(nested(strict + 1), { profile: "permissive" }) === null,
        String(_refusal(nested(strict + 1), { profile: "permissive" })));
}

function testLimitsForResolvesTheSameCaps() {
  // The listener reads its caps from here rather than reaching into the
  // table, so the resolver's answer and the table's entry are one value.
  var strict = b.guardImapCommand.limitsFor({ profile: "strict" });
  check("limitsFor returns the profile the name selects",
        strict === b.guardImapCommand.PROFILES.strict);
  check("a posture selects its profile",
        b.guardImapCommand.limitsFor({ posture: "hipaa" }).maxSequenceSetItems ===
        b.guardImapCommand.PROFILES.strict.maxSequenceSetItems);
  check("the caps it hands back cannot be edited", Object.isFrozen(strict));
  var threw = null;
  try { b.guardImapCommand.limitsFor({ profile: "nope" }); } catch (e) { threw = e; }
  check("an unknown profile is refused",
        threw !== null && threw.code === "guard-imap-command/bad-profile",
        threw && threw.code);
}

function testTheListenerReadsTheProfilesMUtf7Answer() {
  // Two statements about one option: the table says balanced allows legacy
  // modified UTF-7, the listener derived `profile === "permissive"` and
  // refused it. A test that compares them is the only thing that keeps them
  // from drifting again.
  var wrong = [];
  ["strict", "balanced", "permissive"].forEach(function (name) {
    var declared = b.guardImapCommand.PROFILES[name].allowLegacyMUtf7;
    var applied  = b.mail.server.imap.legacyMUtf7Allowed(name);
    if (declared !== applied) {
      wrong.push(name + ": table " + declared + ", listener " + applied);
    }
  });
  check("the listener's legacy modified UTF-7 answer is the profile's" +
        (wrong.length ? " (" + wrong.join("; ") + ")" : ""), wrong.length === 0);
}

async function run() {
  testEveryDeclaredCapIsRead();
  testTheMailboxNameCapIsApplied();
  testTheSequenceSetCapIsApplied();
  testTheSearchDepthCapIsApplied();
  testLimitsForResolvesTheSameCaps();
  testTheListenerReadsTheProfilesMUtf7Answer();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[guard-imap-command-caps] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
