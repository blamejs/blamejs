// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A message sent with the null reverse path gets no DSN, in either spelling
 * of it.
 *
 * The guard tested `envelope.from !== ""`, an exact comparison against one of
 * the two ways the null reverse path is written. On the wire it is `<>`, and
 * that is the spelling it arrives in, so a caller passing it through got a
 * DSN generated for a message RFC 5321 §4.5.5 says must not receive one. The
 * reason is the whole point of the null sender: a DSN's `To:` is the original
 * `from`, so bouncing a bounce addresses it to nobody, and to a less careful
 * peer, to itself.
 *
 * The question is asked as a predicate rather than compared inline, because
 * the same question is asked in more than one place and a comparison added
 * later repeats the omission.
 */

var helpers = require("../helpers");
var check   = helpers.check;
var b       = helpers.b;

// A domain with no MX at all fails PERMANENTLY (deliver/no-mx), which is the
// outcome that reaches the DSN decision. A reachable-but-refusing peer fails
// transiently and never gets there, which would make every row below pass for
// the wrong reason.
function _recordingResolver() {
  return {
    queryMx:   function () { return Promise.resolve({ rrs: [] }); },
    queryTxt:  function () { return Promise.resolve({ rrs: [] }); },
    queryTlsa: function () { return Promise.resolve({ rrs: [] }); },
  };
}

async function _deliverWithFrom(from) {
  var dsns = [];
  var deliver = b.mail.send.deliver.create({
    hostname: "sender.example.com",
    resolver: _recordingResolver(),
    policy:   { mtaSts: "off", dane: "off" },
    audit:    false,
    dsn: {
      from: "postmaster@sender.example.com",
      onPermanentFailure: function (envelope, res, dsnMessage) {
        dsns.push({ recipient: res.recipient, dsnMessage: dsnMessage });
        return Promise.resolve();
      },
    },
  });
  try {
    await deliver({
      from:   from,
      to:     ["nobody@invalid.test"],
      rfc822: "From: a@example.com\r\nTo: nobody@invalid.test\r\n\r\nhi\r\n",
    });
  } catch (_e) { /* delivery cannot succeed here; the DSN decision is the subject */ }
  return dsns;
}

async function testNeitherSpellingOfTheNullSenderGetsADsn() {
  var empty = await _deliverWithFrom("");
  check("the empty-string spelling gets no DSN", empty.length === 0,
        JSON.stringify(empty.map(function (d) { return d.recipient; })));

  var wire = await _deliverWithFrom("<>");
  check("the wire spelling <> gets no DSN either", wire.length === 0,
        JSON.stringify(wire.map(function (d) { return d.recipient; })));

  var spaced = await _deliverWithFrom(" <> ");
  check("and neither does it with surrounding whitespace", spaced.length === 0,
        JSON.stringify(spaced.map(function (d) { return d.recipient; })));
}

async function testAnOrdinarySenderStillGetsOne() {
  // The control: the guard must not have been widened into refusing every
  // DSN, which would pass the rows above for the wrong reason.
  var dsns = await _deliverWithFrom("sender@example.com");
  check("an ordinary reverse path still produces a DSN", dsns.length === 1,
        JSON.stringify(dsns.map(function (d) { return d.recipient; })));
  check("and the DSN it produces is a real message",
        dsns.length === 1 && typeof dsns[0].dsnMessage === "string" &&
        dsns[0].dsnMessage.indexOf("report-type=delivery-status") !== -1,
        dsns.length === 1 ? String(dsns[0].dsnMessage).slice(0, 80) : "(none)");
}

async function run() {
  await testNeitherSpellingOfTheNullSenderGetsADsn();
  await testAnOrdinarySenderStillGetsOne();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[mail-send-deliver-null-sender] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
