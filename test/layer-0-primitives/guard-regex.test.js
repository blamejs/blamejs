// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.guardRegex — ReDoS screening for operator-supplied patterns. Covers the
 * nested-quantifier detector's true positives AND the linear shapes it must NOT
 * false-refuse (#432 / #429): a quantified non-capturing group (`(?:…)?`,
 * `(?:…)*`) and an OPTIONAL quantified group (`(X+)?`, `(?:X+)?`) repeat the
 * group at most once, so they are linear, not catastrophic. The catastrophic
 * class requires the OUTER quantifier to be unbounded (`*`/`+`/`{n,}`).
 *
 * Run standalone: `node test/layer-0-primitives/guard-regex.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function assertSafeAccepts(src) {
  try { b.guardRegex.assertSafe(new RegExp(src), "x"); return true; } catch (_e) { return false; }
}
function sanitizeAccepts(src) {
  try { b.guardRegex.sanitize(src); return true; } catch (_e) { return false; }
}

// ---- #432 / #429: linear shapes must be ACCEPTED (were false-refused) ----
function testLinearShapesAccepted() {
  var linear = [
    "^(?:/page/\\d+)?$",            // optional non-capturing group
    "^foo(?:bar)*$",               // quantified non-capturing group
    "^foo(?:bar)?$",
    "^(a+)?$",                     // optional quantified group — repeats 0..1
    "(?:[-+][0-9A-Za-z.-]+)?",     // optional group with inner quantifier (#429)
    "(?:[-+][0-9A-Za-z.-]{1,64})?",
    "v\\d+\\.\\d+\\.\\d+(?:[-+][0-9A-Za-z.-]+)?-linux-x64",
  ];
  linear.forEach(function (src) {
    check("assertSafe accepts linear " + JSON.stringify(src), assertSafeAccepts(src));
    check("sanitize accepts linear " + JSON.stringify(src), sanitizeAccepts(src));
  });
}

// ---- genuine nested-UNBOUNDED shapes must still be REFUSED ----
function testCatastrophicShapesRefused() {
  var bad = ["^(a+)+$", "(a+)*", "((a)+)+", "(([a-z]+)*)*", "(a+){2,}"];
  bad.forEach(function (src) {
    check("assertSafe refuses catastrophic " + JSON.stringify(src), assertSafeAccepts(src) === false);
  });
}

// ---- provably-unambiguous shapes must be ACCEPTED ----
// Two conservative refusals blocked patterns an operator would reasonably
// write, and neither can be rewritten without losing what it expresses.
//
// An alternation whose branches cannot start with the same character is a
// one-character decision at every position, so the quantifier has nothing to
// backtrack into — `(?:b|c)+` is the character class `[bc]+` spelled long.
//
// A group body ending in a literal that none of its other atoms can match has
// its repetition boundaries fixed by the occurrences of that literal, so the
// outer quantifier cannot re-split the input — the coupling that makes a
// nested quantifier catastrophic is broken.
function testProvablyUnambiguousShapesAccepted() {
  var linear = [
    // disjoint alternation under a quantifier
    "/a(?:b|c)+",
    "(?:b|c)+",
    "(?:b|c)*",
    "(a|b)+",                      // capturing group, same reasoning
    "(?:ab|cd)+",                  // multi-character branches, disjoint first chars
    "(?:[a-z]|[0-9])+",            // disjoint classes
    "(?:\\d|[a-z])+",              // shorthand vs class
    "(?:GET|POST)+",
    // delimiter-separated nested quantifier
    "/shop/(?:[a-z]+-)*[a-z]+",
    "(?:[a-z]+-)*",
    "(?:[a-z]+/)*",
    "(?:[^/]+/)*",                 // the delimiter is exactly what the class excludes
    "(?:\\w+\\.)+",
    "(?:\\d+,)*",
    "(?:[a-z]+_)*",
    "^/blog/(?:[a-z0-9-]+/)*[a-z0-9-]+$",
  ];
  linear.forEach(function (src) {
    check("assertSafe accepts provably-unambiguous " + JSON.stringify(src), assertSafeAccepts(src));
    check("sanitize accepts provably-unambiguous " + JSON.stringify(src), sanitizeAccepts(src));
  });
}

// The loosening is bounded by what can be PROVEN disjoint. Everything a cheap
// analysis cannot characterise keeps being refused, and every shape that is
// genuinely ambiguous stays refused whatever it is dressed up as.
function testAmbiguousShapesStillRefused() {
  var bad = [
    // alternation the branches of which can start at the same character
    "(a|a)*b",                     // identical branches — the canonical case
    "(?:a|ab)+",                   // prefix overlap
    "(?:[a-z]|[a-c])+",            // overlapping classes
    "(?:\\d|\\w)+",                // one shorthand contains the other
    "(?:POST|PUT)+",               // same first character
    "(?:a|)+",                     // a nullable branch
    "(?:a|.)+",                    // `.` cannot be characterised
    "(?:[^a]|b)+",                 // negated class overlapping a literal
    "(?:a|\\1)+",                  // a backreference
    "(\\d|\\d{2})*",
    "(?:b+|c)+",                   // an unbounded quantifier inside the branch
    // a group body whose trailing literal is NOT excluded by its own atoms
    "(?:[a-z]+a)*",                // the trailing literal is inside the class
    "(?:\\w+_)*",                  // `_` is a member of \w
    "(?:.+/)*",                    // `.` matches the delimiter
    "(?:[^/]+x)*",                 // `x` is matchable by the negated class
    "(?:[a-z]+-+)*",               // the delimiter is itself quantified
    // A forced delimiter pins where each repetition ENDS, but the number of
    // paths through the whole match is the PRODUCT of the paths through each
    // repetition. Two variable-length atoms in the body give at least two
    // parses per repetition, so m repetitions give 2^m — the delimiter buys
    // nothing. Every one of these is exponential.
    "(?:a*a*-)*",
    "(?:a*a?-)*",
    "(?:\\w+\\d*;)*",              // a shape an operator would plausibly write
    "(?:[a-z]+[a-z0-9]*_)*",
    "(?:\\w+\\w*-)*",
    "(?:[^-]*[^-]*-)*",
    "(?:[^/]+[^/]*/)*",
    "(?:\\s*\\s*,)*",
    "(?:a{1,}a{1,}-)*",
    "(?:a*?a*?-)*",                // lazy inner quantifiers backtrack the same
    // The branch CHOICE being decided by one character does not decide the
    // branch LENGTH. An optional tail whose character can start another branch
    // gives two parses per unit, which is the same exponential.
    "(?:ab?|b)+",
    "(?:ab{0,1}|b)+",
    "(?:ab{1,2}|b)+",
    "(?:(?:[a-z]+)+-)*",           // the body carries its own nested quantifier
    "(?:[a-z]+)*-",                // the delimiter is OUTSIDE the group
    // the classic catastrophic set, unchanged
    "(a+)+$", "((a)+)+", "(?:a+)+", "(([a-z]+)*)*", "(a+){2,}",
  ];
  bad.forEach(function (src) {
    check("assertSafe still refuses ambiguous " + JSON.stringify(src), assertSafeAccepts(src) === false);
  });

  // The alternation shape check has always been paren-blind: a branch holding
  // a group means its `[^()]*` cannot span the alternation, so the check never
  // fires and the analysis above is never consulted. Pinned so a later change
  // to either half is a deliberate one — the pattern is linear (`x` and `y`
  // cannot both start a branch), so accepting it is right.
  check("a grouped branch does not reach the alternation check at all",
        assertSafeAccepts("(?:(x)|y)+"));
}

// The screener must not become the denial of service it exists to prevent.
// Proving branches disjoint means expanding character classes and comparing
// every pair, so a pattern well inside the profile's byte cap can be shaped to
// cost quadratic work in both dimensions at once. Analysis work is budgeted;
// exhausting the budget declines to prove, which leaves the refusal in place.
function testAnalysisWorkIsBounded() {
  var chr = String.fromCharCode;
  // Pairwise-disjoint 256-character branches: nothing can exit a comparison
  // early, so the cost is quadratic in branch count and in class width at
  // once. Sized by UTF-8 byte length to sit just INSIDE the strict profile's
  // 1 KiB cap, which is what makes it reachable at all.
  function hostileWithinBytes(byteBudget) {
    var parts = [];
    for (var i = 0; i < 4000; i += 1) {
      var branch = "[" + chr(0x100 + i * 256) + "-" + chr(0x100 + i * 256 + 255) + "]";
      var next = "(?:" + parts.concat([branch]).join("|") + ")+";
      if (Buffer.byteLength(next, "utf8") > byteBudget) break;
      parts.push(branch);
    }
    return "(?:" + parts.join("|") + ")+";
  }

  var hostile = hostileWithinBytes(1024);
  check("the hostile analysis input is inside the strict byte cap",
        Buffer.byteLength(hostile, "utf8") <= 1024);
  var started = Date.now();
  var rv = b.guardRegex.validate(hostile, { profile: "strict" });
  check("a pattern shaped to be expensive to analyse is screened in bounded time",
        Date.now() - started < 250);
  check("declining to prove leaves the refusal in place (fail closed)", rv.ok === false);

  // The delimiter analysis expands classes on the same terms.
  var nested = [];
  for (var g = 0; g < 400; g += 1) nested.push("(?:[" + chr(0x100) + "-" + chr(0x1ff) + "]+-)*");
  var startedNested = Date.now();
  b.guardRegex.validate(nested.join(""), { profile: "permissive", maxPatternBytes: 65536, maxBytes: 65536 });
  check("the delimiter analysis is bounded too", Date.now() - startedNested < 250);

  // Budgeting must not cost the ordinary case its proof.
  check("an everyday disjoint alternation is still proven", assertSafeAccepts("(?:[a-z]|[0-9])+"));
  check("an everyday delimited group is still proven", assertSafeAccepts("(?:[a-z]+/)*"));
}

// A RegExp's flags decide what its source means. Screening `.source` alone
// reads `(a|A)+` as two disjoint branches, when under `i` the engine sees one
// branch twice and backtracks exactly as it does on `(a|a)+`.
function testRegExpFlagsReachTheAnalysis() {
  check("case-insensitive overlapping branches refused via the RegExp's own flags",
        assertSafeAccepts2(/^(a|A)+$/i) === false);
  check("the same source WITHOUT the flag is still accepted",
        assertSafeAccepts2(/^(a|A)+$/));
  check("case-insensitive DISJOINT branches are still accepted",
        assertSafeAccepts2(/^(?:b|c)+$/i));
  check("case-insensitive class overlap refused",
        assertSafeAccepts2(/^(?:[a-z]|[A-Z])+$/i) === false);
  // A delimiter whose OTHER CASE is inside a preceding atom is not a
  // delimiter: under `i` the quantifier can consume it, so the boundary it
  // was supposed to pin is not pinned. `[A-Z]` folds to cover `z`.
  check("case-insensitive delimiter reachable by the preceding class refused",
        assertSafeAccepts2(/^(?:[A-Z]+z)*$/i) === false);
  check("the same source WITHOUT the flag is accepted (Z-range excludes z)",
        assertSafeAccepts2(/^(?:[A-Z]+z)*$/));
  check("case-insensitive delimiter genuinely outside the class accepted",
        assertSafeAccepts2(/^(?:[a-z]+-)*$/i));
  // A caller screening a raw STRING declares the flags it will compile with.
  var strictOpts = function (f) {
    return { profile: "strict", boundedRepeatPolicy: "allow", regexFlags: f };
  };
  var accWith = function (src, f) {
    try { b.guardRegex.assertSafe(src, "x", null, null, strictOpts(f)); return true; }
    catch (_e) { return false; }
  };
  check("a declared i flag refuses the overlap on a raw string", accWith("^(a|A)+$", "i") === false);
  check("the v flag declines the suppression outright", accWith("^(?:b|c)+$", "v") === false);
}
function assertSafeAccepts2(re) {
  try { b.guardRegex.assertSafe(re, "x"); return true; } catch (_e) { return false; }
}

// ---- other ReDoS classes the guard covers stay covered ----
function testOtherClasses() {
  // `(a|b|c)+` is the character class `[abc]+` written out long: no two
  // branches can start on the same character, so a single character decides
  // the branch and there is nothing to backtrack into. It used to be refused
  // on shape alone. The hazard the rule names is OVERLAP, and overlap is what
  // is still refused.
  check("disjoint alternation-with-quantifier accepted", assertSafeAccepts("^(a|b|c)+$"));
  check("overlapping alternation-with-quantifier still refused",
        assertSafeAccepts("^(\\d|\\d{2})*$") === false);
  check("plain linear pattern accepted", assertSafeAccepts("^[a-z0-9_-]{1,64}$"));
  check("anchored alternation without group-quantifier accepted", assertSafeAccepts("^(?:cat|dog|bird)$"));
}

// ---- b.guardRegex.gate — the request-boundary screener ----
// The gate reads ctx.identifier (or ctx.pattern) and maps validate's
// severity to serve / audit-only / refuse before any new RegExp() compile.
async function testGate() {
  var gate = b.guardRegex.gate({ profile: "strict" });

  var clean = await gate.check({ identifier: "^[a-z]+$" });
  check("gate: linear pattern → action=serve, ok=true",
    clean.ok === true && clean.action === "serve");

  var nested = await gate.check({ identifier: "(a+)+b" });
  check("gate: nested-quantifier ReDoS → action=refuse, ok=false",
    nested.ok === false && nested.action === "refuse");
  check("gate: nested-quantifier → nested-quantifier issue",
    nested.issues.some(function (i) { return i.kind === "nested-quantifier"; }));

  // ctx.pattern is the documented fallback field for the pattern.
  var alt = await gate.check({ pattern: "(a|a)*b" });
  check("gate: overlapping alternation-with-quantifier via ctx.pattern → refuse",
    alt.action === "refuse");
  var disjointAlt = await gate.check({ pattern: "(a|b|c)+" });
  check("gate: disjoint alternation-with-quantifier via ctx.pattern → serve",
    disjointAlt.action === "serve");

  // Absent pattern is a no-op serve (nothing to screen).
  var none = await gate.check({});
  check("gate: no pattern supplied → action=serve",
    none.ok === true && none.action === "serve");
}

async function run() {
  testLinearShapesAccepted();
  testProvablyUnambiguousShapesAccepted();
  testAmbiguousShapesStillRefused();
  testAnalysisWorkIsBounded();
  testRegExpFlagsReachTheAnalysis();
  testCatastrophicShapesRefused();
  testOtherClasses();
  await testGate();
}

if (require.main === module) {
  run()
    .then(function () { console.log("guard-regex OK — " + helpers.getChecks() + " checks"); })
    .catch(function (e) { console.error("FAIL:", e.stack || e); process.exit(1); });
}

module.exports = { run: run };
