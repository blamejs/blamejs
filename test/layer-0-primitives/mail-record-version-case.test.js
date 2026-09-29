// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A published record's version tag is matched with the case rule its own ABNF
 * gives it, which is not the same rule for every record type.
 *
 * SPF selection compared the version with a case-sensitive read, so
 * `V=spf1 -all` was not seen as an SPF record at all and a domain publishing
 * a strict policy evaluated as if it published nothing. RFC 7208 §12 writes
 * the version as the quoted ABNF literal `"v=spf1"`, and RFC 5234 §2.3 makes
 * quoted literals case-insensitive, so both halves of it fold.
 *
 * The other record types do not fold the same way, and a uniform rule would
 * be wrong in the other direction. Their ABNF spells the version value in hex
 * (`%x44 %x4d %x41 %x52 %x43 %x31` for DMARC), which is case-SENSITIVE, while
 * most of them still write the tag NAME as the quoted literal `"v"`, which
 * folds. TLS-RPT writes even the name in hex. So this is a table with one row
 * per record type, each row citing the ABNF it comes from, rather than one
 * rule applied everywhere:
 *
 *   SPF      RFC 7208 §12    "v=spf1"                     name folds, value folds
 *   DMARC    RFC 7489 §6.4   "v" ... %x44 %x4d ...        name folds, value exact
 *   MTA-STS  RFC 8461 §3.1   "v" ... %x53 %x54 %x53 ...   name folds, value exact
 *   TLS-RPT  RFC 8460 §3     %x76 "=" %x54 %x4c %x53 ...  name exact, value exact
 */

var helpers = require("../helpers");
var check   = helpers.check;
var b       = helpers.b;

function testSpfFoldsBothHalvesOfItsQuotedLiteral() {
  var ACCEPTED = ["v=spf1 -all", "V=spf1 -all", "v=SPF1 -all", "V=SPF1 -all", "v=spf1"];
  var REFUSED  = ["v=spf10 +all", "vv=spf1 -all", "x=spf1 -all", "v=spf2 -all"];
  var wrong = [];
  ACCEPTED.forEach(function (rec) {
    var ok = true;
    try { b.mail.spf.parseRecord(rec); } catch (_e) { ok = false; }
    if (!ok) wrong.push(JSON.stringify(rec) + " refused");
  });
  REFUSED.forEach(function (rec) {
    var refused = false;
    try { b.mail.spf.parseRecord(rec); } catch (_e) { refused = true; }
    if (!refused) wrong.push(JSON.stringify(rec) + " accepted");
  });
  check("SPF reads its version as the case-insensitive literal RFC 7208 writes" +
        (wrong.length ? " (" + wrong.join("; ") + ")" : ""), wrong.length === 0);
}

function testTheMatcherAppliesEachRecordTypesOwnRule() {
  var sf = b.structuredFields;
  // One row per record type: [record, name, value, opts, expected, why]
  var ROWS = [
    ["v=spf1 -all",      "v", "spf1",     { end: "space", nameIgnoresCase: true, valueIgnoresCase: true }, true,  "SPF, exact"],
    ["V=spf1 -all",      "v", "spf1",     { end: "space", nameIgnoresCase: true, valueIgnoresCase: true }, true,  "SPF, folded name"],
    ["v=SPF1 -all",      "v", "spf1",     { end: "space", nameIgnoresCase: true, valueIgnoresCase: true }, true,  "SPF, folded value"],
    ["v=spf10 +all",     "v", "spf1",     { end: "space", nameIgnoresCase: true, valueIgnoresCase: true }, false, "SPF, unterminated"],

    ["v=DMARC1; p=none", "v", "DMARC1",   { wspAroundEquals: true, nameIgnoresCase: true }, true,  "DMARC, exact"],
    ["V=DMARC1; p=none", "v", "DMARC1",   { wspAroundEquals: true, nameIgnoresCase: true }, true,  "DMARC, folded name"],
    ["v=dmarc1; p=none", "v", "DMARC1",   { wspAroundEquals: true, nameIgnoresCase: true }, false, "DMARC value is hex in the ABNF"],

    ["v=STSv1; id=a",    "v", "STSv1",    { requireNextField: true, nameIgnoresCase: true }, true,  "MTA-STS, exact"],
    ["V=STSv1; id=a",    "v", "STSv1",    { requireNextField: true, nameIgnoresCase: true }, true,  "MTA-STS name is \"v\" in the ABNF"],
    ["v=stsv1; id=a",    "v", "STSv1",    { requireNextField: true, nameIgnoresCase: true }, false, "MTA-STS value is hex"],

    ["v=TLSRPTv1; rua=mailto:a@b.c", "v", "TLSRPTv1", { requireNextField: true }, true,  "TLS-RPT, exact"],
    ["V=TLSRPTv1; rua=mailto:a@b.c", "v", "TLSRPTv1", { requireNextField: true }, false, "TLS-RPT name is %x76 in the ABNF"],
  ];
  var wrong = [];
  ROWS.forEach(function (row) {
    var got = sf.recordVersionMatches(row[0], row[1], row[2], row[3]);
    if (got !== row[4]) wrong.push(row[5] + ": " + JSON.stringify(row[0]) + " -> " + got);
  });
  check("each record type's version is matched by its own ABNF's case rule" +
        (wrong.length ? " (" + wrong.join("; ") + ")" : ""), wrong.length === 0);
}

async function testAStrictSpfPolicyInAnotherCaseStillApplies() {
  // The consequence the case rule exists for: a published `-all` must refuse
  // an unlisted sender whatever case the version tag was typed in.
  function lookup(record) {
    return function (qname, type) {
      if (type !== "TXT") return Promise.resolve([]);
      void qname;
      return Promise.resolve([[record]]);
    };
  }
  var wrong = [];
  var RECORDS = ["v=spf1 -all", "V=spf1 -all", "v=SPF1 -all"];
  for (var i = 0; i < RECORDS.length; i += 1) {
    var rv = await b.mail.spf.verify({
      ip: "192.0.2.1", helo: "mail.example.com",
      mailFrom: "sender@example.com", dnsLookup: lookup(RECORDS[i]),
    });
    if (!rv || rv.result !== "fail") {
      wrong.push(JSON.stringify(RECORDS[i]) + " -> " + (rv && rv.result));
    }
  }
  check("a published -all refuses the sender whatever case its version carries" +
        (wrong.length ? " (" + wrong.join("; ") + ")" : ""), wrong.length === 0);
}

async function run() {
  testSpfFoldsBothHalvesOfItsQuotedLiteral();
  testTheMatcherAppliesEachRecordTypesOwnRule();
  await testAStrictSpfPolicyInAnotherCaseStillApplies();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[mail-record-version-case] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
