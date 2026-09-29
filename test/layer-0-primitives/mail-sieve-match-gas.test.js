// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A Sieve test is charged for the work it does, not once for existing.
 *
 * `_evalTest` charged one gas unit per test and then ran `_anyOfMatches`,
 * which compares every value against every key, and each comparison walks a
 * pattern against a value. The charge was therefore one unit for work whose
 * cost is the product of two list lengths, the pattern length and the value
 * length.
 *
 * None of the surrounding ceilings measures that product. The script-size cap
 * bounds the text, the gas budget bounds the number of operations, the
 * language has no loops, and nesting is capped, while the cost lives in the
 * operands. The worst case does not even need a large script: one test with a
 * long pattern against a header a peer controls spends the same time, and a
 * Sieve script runs on the delivery path, so in a single-process server that
 * time is every other account's mail and the health probe too.
 *
 * Gas is now charged inside the comparison loop, in proportion to the
 * characters actually compared, so a filter that is expensive because it is
 * genuinely large still runs and one that is expensive because of a product
 * exhausts the budget it was always meant to be charged against.
 */

var helpers = require("../helpers");
var check   = helpers.check;
var b       = helpers.b;

function _run(script, message, opts) {
  return b.mail.sieve.run(b.safeSieve.parse(script), message, opts);
}

function _message(subject) {
  return {
    headers: [
      { name: "Subject", value: subject },
      { name: "From",    value: "a@example.com" },
      { name: "To",      value: "b@example.net" },
    ],
    body: "hi",
  };
}

var SMALL = _message("a short subject");

function testAnOrdinaryFilterStillCostsAlmostNothing() {
  // The charge must stay meaningful for real scripts, or the fix is just a
  // lower ceiling wearing the budget's name.
  var script = 'require ["fileinto"];\r\n' +
               'if header :contains "Subject" "short" { fileinto "Keep"; }\r\n';
  var result = _run(script, SMALL);
  // Assert the filter actually fired: every run ends with an implicit keep,
  // so an action count alone cannot tell a match from a miss.
  var filed = result.actions.filter(function (a) { return a.kind === "fileinto"; });
  check("an ordinary header test still matches and files",
        filed.length === 1 && filed[0].folder === "Keep",
        JSON.stringify(result.actions));
  check("and costs a small part of the budget",
        result.gas < 100, String(result.gas));
}

function testTheChargeGrowsWithTheCharactersCompared() {
  // Same one test, same one key: only the value the peer sent grows. A charge
  // that does not move with it is not measuring the work.
  var script = 'require ["fileinto"];\r\n' +
               'if header :matches "Subject" "' + "a*".repeat(200) + '" { fileinto "Keep"; }\r\n';
  var small = _run(script, _message("a".repeat(200)));
  var large = _run(script, _message("a".repeat(20000)), { maxGas: 1000000 });
  check("a hundredfold larger value costs materially more gas",
        large.gas > small.gas * 10,
        "small=" + small.gas + " large=" + large.gas);
}

function testALongPatternAgainstALargeHeaderExhaustsTheBudget() {
  // The row that needs no large script at all: one test, a long pattern, and
  // a header value the peer chose.
  var script = 'require ["fileinto"];\r\n' +
               'if header :matches "Subject" "' + "a*".repeat(2000) + '" { fileinto "Junk"; }\r\n';
  var threw = null;
  try { _run(script, _message("a".repeat(1000000))); }
  catch (e) { threw = e; }
  check("the run is refused rather than held for the product of the operands",
        threw !== null && threw.code === "mail-sieve/gas-exhausted",
        threw && (threw.code + ": " + threw.message));
}

function testManyKeysAgainstManyValuesAreChargedForEachComparison() {
  // The other half of the product: the comparison count itself.
  var keys = [];
  for (var i = 0; i < 200; i += 1) keys.push('"' + "k".repeat(200) + i + '"');
  var script = 'require ["fileinto"];\r\n' +
               'if header :contains ["Subject","From","To"] [' + keys.join(",") + '] ' +
               '{ fileinto "Junk"; }\r\n';
  var oneKey = _run('require ["fileinto"];\r\n' +
                    'if header :contains "Subject" "zzz" { fileinto "Junk"; }\r\n', SMALL);
  var manyKeys = _run(script, SMALL, { maxGas: 1000000 });
  check("six hundred comparisons cost more than one",
        manyKeys.gas > oneKey.gas * 10,
        "one=" + oneKey.gas + " many=" + manyKeys.gas);
}

function testAnEqualityTestIsChargedForTheCharactersItReads() {
  // `:is` compares two strings for equality and `:contains` searches one
  // inside the other with indexOf. Both walk their operands once, so neither
  // spends the product of the two lengths, and charging it refused a valid
  // filter comparing a long header against an equally long key.
  //
  // Measured, because the product charge was defended as a DoS bound: the
  // naive-search worst case, one million `a` searched for `a` x3499 + `b`,
  // takes 2.72 ms. The product is 3.5 billion character reads, which would be
  // seconds. V8 does not run the naive search. `:matches` is the form that can
  // go superlinear, and it keeps the product charge.
  var subject = "s".repeat(3500);
  var script = 'require ["fileinto"];\r\n' +
               'if header :is "Subject" "' + subject + '" { fileinto "Keep"; }\r\n';
  var result = _run(script, _message(subject));
  var filed = result.actions.filter(function (a) { return a.kind === "fileinto"; });
  check("a long equality test matches under the default budget",
        filed.length === 1 && filed[0].folder === "Keep", JSON.stringify(result.actions));
  check("and is charged for the characters it reads, not their product",
        result.gas < 100, String(result.gas));

  // The same operands under :contains run too, and are charged in proportion
  // to the characters read. A sender who can put a large header on a message
  // must not be able to exhaust the budget of a filter that only searches it,
  // because the filter then runs nothing and the message goes unfiltered.
  var searching = 'require ["fileinto"];\r\n' +
                  'if header :contains "Subject" "' + subject + '" { fileinto "Keep"; }\r\n';
  var big = null;
  var threw = null;
  try { big = _run(searching, _message("s".repeat(200000))); } catch (e) { threw = e; }
  check("a substring search over a large header still runs",
        threw === null, threw && threw.code);
  check("and is charged for the characters it reads",
        big !== null && big.gas > 0 && big.gas < 1000, String(big && big.gas));

  // `:matches` is the superlinear one and keeps the product charge, so the
  // budget still stops a pattern whose cost is the product.
  var wild = 'require ["fileinto"];\r\n' +
             'if header :matches "Subject" "' + "a*".repeat(2000) + '" { fileinto "Keep"; }\r\n';
  var wildThrew = null;
  try { _run(wild, _message("s".repeat(200000))); } catch (e) { wildThrew = e; }
  check("a wildcard pattern over the same header is still refused",
        wildThrew !== null && wildThrew.code === "mail-sieve/gas-exhausted",
        wildThrew && wildThrew.code);
}

function testTheBudgetIsStillReportedAndHonoured() {
  // The budget stays the operator's knob: a script refused at the default
  // must run when the operator raises it.
  var script = 'require ["fileinto"];\r\n' +
               'if header :matches "Subject" "' + "a*".repeat(400) + '" { fileinto "Junk"; }\r\n';
  var message = _message("a".repeat(60000));
  var refused = null;
  try { _run(script, message); } catch (e) { refused = e; }
  check("refused under the default budget",
        refused !== null && refused.code === "mail-sieve/gas-exhausted",
        refused && refused.code);
  var raised = _run(script, message, { maxGas: 1000000 });
  check("and allowed when the operator raises the budget",
        typeof raised.gas === "number" && raised.gas > 0, String(raised && raised.gas));
}

function run() {
  testAnOrdinaryFilterStillCostsAlmostNothing();
  testTheChargeGrowsWithTheCharactersCompared();
  testALongPatternAgainstALargeHeaderExhaustsTheBudget();
  testManyKeysAgainstManyValuesAreChargedForEachComparison();
  testAnEqualityTestIsChargedForTheCharactersItReads();
  testTheBudgetIsStillReportedAndHonoured();
}

module.exports = { run: run };

if (require.main === module) {
  try {
    run();
    console.log("[mail-sieve-match-gas] OK — " + helpers.getChecks() + " checks passed");
  } catch (e) {
    console.error("FAIL:", (e && e.stack) || e);
    process.exit(1);
  }
}
