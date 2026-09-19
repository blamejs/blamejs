// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A peer's forged `Authentication-Results` is removed in every spelling the
 * readers downstream accept, not just the canonical one.
 *
 * The strip matched the field name as a literal line prefix and read the
 * authserv-id off that same line, while every reader downstream is an
 * RFC 5322 parser, including this framework's own `b.safeMime.parse`. Three
 * spellings the parser accepts as the same header went straight through:
 *
 *   1. folded before the authserv-id, which RFC 5322 §2.2.3 allows anywhere
 *      in a header's whitespace, so the id token read as empty;
 *   2. a quoted authserv-id, which RFC 8601 §2.2 permits, so the token
 *      carried its quote characters and matched nothing;
 *   3. whitespace before the colon, which RFC 5322 §4.5.8 keeps as
 *      obs-optional, so the prefix comparison failed outright.
 *
 * Measured on a real session: a peer failing SPF and DMARC delivered a folded
 * forged header claiming `dmarc=pass`, and the stored message carried two
 * verdicts under the receiving server's own name, the true one and the
 * forged one.
 *
 * The defect is not three missing cases. The screen used a different grammar
 * from the readers, so the test is written against the grammar: whatever
 * spelling is fed in, what `b.safeMime.parse` reads back afterwards must
 * carry no verdict under this server's authserv-id except the one the server
 * itself wrote.
 */

var helpers = require("../helpers");
var check   = helpers.check;
var b       = helpers.b;

var AUTHSERV = "mx.example.com";

var SPELLINGS = [
  { label: "canonical",
    header: "Authentication-Results: mx.example.com; dmarc=pass" },
  { label: "folded before the authserv-id (RFC 5322 2.2.3)",
    header: "Authentication-Results:\r\n\tmx.example.com; dmarc=pass" },
  { label: "quoted authserv-id (RFC 8601 2.2)",
    header: 'Authentication-Results: "mx.example.com"; dmarc=pass' },
  { label: "space before the colon (RFC 5322 4.5.8 obs-optional)",
    header: "Authentication-Results : mx.example.com; dmarc=pass" },
  { label: "tab before the colon",
    header: "Authentication-Results\t: mx.example.com; dmarc=pass" },
  { label: "upper-case field name",
    header: "AUTHENTICATION-RESULTS: mx.example.com; dmarc=pass" },
  { label: "folded with the id on a later line and a comment between",
    header: "Authentication-Results:\r\n (a comment)\r\n mx.example.com; dmarc=pass" },
];

function _messageWith(header) {
  return Buffer.from([
    "Received: from peer.example ([192.0.2.1])",
    header,
    "From: attacker@evil.example",
    "To: victim@example.com",
    "Subject: forged verdict",
    "",
    "body",
    "",
  ].join("\r\n"), "utf8");
}

function _authResultsAfterStrip(header) {
  var stripped = b.mail.server.mx.stripForgedAuthResults(_messageWith(header), AUTHSERV);
  var tree = b.safeMime.parse(stripped);
  return tree.headers.getAll("authentication-results") || [];
}

function testNoSpellingSurvivesUnderThisServersName() {
  var survived = [];
  SPELLINGS.forEach(function (row) {
    var left = _authResultsAfterStrip(row.header);
    // What matters is what a reader sees: a verdict attributed to this
    // server's authserv-id must not be among the headers that remain.
    var forged = left.filter(function (value) {
      return String(value).toLowerCase().indexOf(AUTHSERV) !== -1;
    });
    if (forged.length > 0) survived.push(row.label + " -> " + JSON.stringify(forged));
  });
  check("no spelling of a forged Authentication-Results survives the strip" +
        (survived.length ? " (" + survived.join("; ") + ")" : ""),
        survived.length === 0);
}

function testAnotherServersVerdictIsLeftAlone() {
  // The strip removes what claims to be THIS server, and nothing else: an
  // upstream relay's verdict is evidence the operator may want.
  var left = _authResultsAfterStrip("Authentication-Results: upstream.example.net; dmarc=pass");
  check("a verdict under another authserv-id is kept",
        left.length === 1 && String(left[0]).indexOf("upstream.example.net") !== -1,
        JSON.stringify(left));
  var foldedOther = _authResultsAfterStrip(
    "Authentication-Results:\r\n\tupstream.example.net; dmarc=pass");
  check("and kept when it is folded, so the unfolding does not over-remove",
        foldedOther.length === 1 &&
        String(foldedOther[0]).indexOf("upstream.example.net") !== -1,
        JSON.stringify(foldedOther));
}

function testTheRestOfTheMessageIsUntouched() {
  var stripped = b.mail.server.mx.stripForgedAuthResults(
    _messageWith("Authentication-Results:\r\n\tmx.example.com; dmarc=pass"), AUTHSERV);
  var tree = b.safeMime.parse(stripped);
  check("the other headers survive the rewrite",
        tree.headers.get("from") === "attacker@evil.example" &&
        tree.headers.get("subject") === "forged verdict" &&
        (tree.headers.get("received") || "").indexOf("peer.example") !== -1,
        JSON.stringify([tree.headers.get("from"), tree.headers.get("subject")]));
  check("the body survives", stripped.toString("utf8").indexOf("\r\n\r\nbody") !== -1);
}

async function run() {
  testNoSpellingSurvivesUnderThisServersName();
  testAnotherServersVerdictIsLeftAlone();
  testTheRestOfTheMessageIsUntouched();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[mail-server-mx-strip-forged-auth] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
