// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Every DNS question `b.mail.send.deliver` asks on the consumer's behalf goes
 * through the resolver the consumer pinned.
 *
 * `deliver.create` took `opts.resolver` and used it for the MX lookup and the
 * DANE TLSA lookup. The MTA-STS lookup was the exception: `_applyMtaStsPolicy`
 * called `mtaSts.fetch(domain)` with the domain alone, so `_mta-sts.<domain>`
 * was answered by whatever the host resolves with. That record is the whole
 * decision. RFC 8461 §3.1 gives a receiver one TXT record to declare a policy,
 * and a sender that sees no record enforces nothing, so a suppressed answer
 * and an honest absence are the same answer: the one lookup that decides
 * whether a message goes out under an enforced TLS policy was the one lookup
 * the consumer's resolver did not reach.
 */

var helpers = require("../helpers");
var check   = helpers.check;
var b       = helpers.b;

// A resolver handle of the shape b.network.dns.resolver.create returns, which
// records every question it is asked.
function _recordingResolver(asked) {
  return {
    queryMx: function (name) {
      asked.push("MX " + name);
      return Promise.resolve({ rrs: [{ type: 15, decoded: { exchange: "mx.example.net", priority: 10 } }] });
    },
    queryTxt: function (name) {
      asked.push("TXT " + name);
      return Promise.resolve({ rrs: [] });
    },
    queryTlsa: function (name) {
      asked.push("TLSA " + name);
      return Promise.resolve({ rrs: [] });
    },
  };
}

async function testTheMtaStsLookupUsesThePinnedResolver() {
  var asked = [];
  var resolver = _recordingResolver(asked);
  var deliver = b.mail.send.deliver.create({
    hostname: "sender.example.com",
    resolver: resolver,
    policy:   { mtaSts: "testing" },
    audit:    false,
  });
  try {
    // `create` returns the deliver function itself. The send cannot complete
    // here, because no SMTP peer answers the MX this resolver names; the
    // lookups it makes on the way are what this test reads.
    await deliver({
      from:   "a@example.com",
      to:     ["b@example.net"],
      rfc822: "From: a@example.com\r\nTo: b@example.net\r\n\r\nhi\r\n",
    });
  } catch (_e) { /* delivery failure is expected and not what is asserted */ }

  var stsQuestions = asked.filter(function (q) { return q.indexOf("TXT _mta-sts.") === 0; });
  check("the _mta-sts TXT question is asked through the pinned resolver" +
        " (asked: " + JSON.stringify(asked) + ")",
        stsQuestions.length > 0);
}

async function run() {
  await testTheMtaStsLookupUsesThePinnedResolver();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[mail-send-deliver-resolver] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
