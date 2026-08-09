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
    // A varying body is not by itself ambiguous. Every repetition here must
    // begin at an `a`, and the optional tail cannot be re-attributed to the
    // next one, so the split is decided — measured flat to 200,000 characters.
    // Refusing these would re-open the complaint this release set out to fix.
    "(?:ab?)+c",
    "(?:ab?c?)+d",
    "(?:a[0-9]{0,2})+z",
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
    // Each group below is individually unambiguous; the ways to partition one
    // run of input AMONG them are not, and neither analysis models
    // concatenation. Six disjoint alternations in a row took ~0.7s on 80
    // characters before the suppression required a single quantified group.
    "^(?:a|b)+(?:a|b)+(?:a|b)+(?:a|b)+(?:a|b)+(?:a|b)+!$",
    "^(?:[a-z]+-)*(?:[a-z]+-)*!$",   // the second group matches `-` too, so the split floats
    // Conservative: `[bc]` and `[de]` are disjoint so this one is in fact
    // linear, but the only multi-term boundary proven here is the delimited
    // one, and neither group carries a delimiter. Refusing is the safe answer.
    "(?:b|c)+(?:d|e)+",
    "(?:(?:[a-z]+)+-)*",           // the body carries its own nested quantifier
    "(?:[a-z]+)*-",                // the delimiter is OUTSIDE the group
    // A repeated group is catastrophic when its body can match a VARYING
    // number of characters that the next repetition could have taken instead
    // — the quantifier doing the varying need not be unbounded. `{1,2}` and
    // `?` vary just as `+` does, and the detector counted only the unbounded
    // ones, so a dotted-quad or version validator an operator would plausibly
    // write was accepted and pins a core on ~30 characters.
    "^(?:\\d{1,3}\\.?)+$",
    "(?:a{1,2})+b",
    "^(?:a?a?)+b",
    "^(?:[a-z]{1,2})+$",
    "^(?:[A-Za-z0-9]{1,2})+$",
    "^(?:\\w{0,3})+$",
    "^(?:[a-z]{1,3}\\.?)+$",
    "(?:a?)+",
    "(?:ab?b?)+c",                 // two optional atoms over the same character
    // A group with no quantifier of its own still varies when its body does.
    // Twenty adjacent `(?:aa?)` groups can redistribute their optional `a`s
    // among themselves and into the repetition that follows.
    "^" + new Array(21).join("(?:aa?)") + "(?:a|b)+!$",
    "^(?:aa?)(?:aa?)(?:a|b)+!$",
    // A complement's members are what it EXCLUDES, so a term mixing `[^b]`
    // with a positive set must not come out as a set that excludes both — read
    // that way the boundary proof concludes a later term cannot consume an
    // earlier delimiter when it plainly can.
    "^(?:x+a)*(?:[^b]a?){30}!$",
    "^(?:x+a)*(?:[^b]a?)+!$",
    // the classic catastrophic set, unchanged
    "(a+)+$", "((a)+)+", "(?:a+)+", "(([a-z]+)*)*", "(a+){2,}",
  ];
  bad.forEach(function (src) {
    check("assertSafe still refuses ambiguous " + JSON.stringify(src), assertSafeAccepts(src) === false);
  });

  // A branch holding a group reaches the analysis and is judged on what it
  // matches: a group that neither repeats nor alternates is its own contents,
  // so `(x)` is `x`. This pattern is linear — `x` and `y` cannot both start a
  // branch — and is accepted because that was proven, not because the check
  // could not see it.
  check("a grouped branch is analysed, and a disjoint one is accepted",
        assertSafeAccepts("(?:(x)|y)+"));
  check("a grouped branch that OVERLAPS its sibling is refused",
        assertSafeAccepts("(?:(x)|x)+") === false);
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
  // The boundary proof asks what a LATER term can match, which is the union of
  // its atoms. Folding case after combining that union loses which characters
  // a positive atom supplied: `[^ab]` unioned with `A` is everything-but-a-and-b,
  // and folding THAT excludes `a` outright — so `A`, which matches `a` under
  // `i`, reads as unable to consume the `a` delimiter of the group before it.
  // The split between the two groups floats, and the pattern is super-linear.
  check("a later term reaching the delimiter only by case folding is refused",
        assertSafeAccepts2(/^(?:x+a)*(?:[^ab]A)*!$/i) === false);
  check("the same shape with more of the pattern in front is refused too",
        assertSafeAccepts2(/^(?:x+a)*(?:[^abA]+A)*(?:[^abA]A)*!$/i) === false);
  check("the same source WITHOUT the flag is still refused (a is a plain overlap)",
        assertSafeAccepts2(/^(?:x+a)*(?:[^ab]a)*!$/) === false);
  check("a later term that genuinely cannot reach the delimiter is still proven",
        assertSafeAccepts2(/^(?:x+a)*(?:[^abA]B)*!$/i));

  // The same overlapping alternation, spelled three ways. A shape check that
  // reads the pattern differently from the analysis that judges it lets the
  // spellings it cannot see straight through: `{1,}` IS `+`, and one paren
  // around a branch changes nothing about how the engine backtracks. Both were
  // exponential and accepted at every profile.
  check("an overlapping alternation is refused as `+`", assertSafeAccepts2(/^(a|a)+$/) === false);
  check("the same repetition spelled `{1,}` is refused too",
        assertSafeAccepts2(/^(a|a){1,}$/) === false);
  check("and spelled `{0,}`", assertSafeAccepts2(/^(a|a){0,}$/) === false);
  check("a branch wrapped in a group does not hide the overlap",
        assertSafeAccepts2(/^((a)|a)+$/) === false);
  check("nor does wrapping the other branch",
        assertSafeAccepts2(/^(?:a|(a))+$/) === false);
  check("a bounded repetition of the same alternation is refused too — a " +
        "ceiling changes the cost, not the shape",
        assertSafeAccepts2(/^(a|a){1,2}$/) === false);
  check("a repetition that can be taken at most once is not this rule's shape",
        assertSafeAccepts2(/^(a|a){0,1}$/) && assertSafeAccepts2(/^(a|a)?$/));
  check("a disjoint alternation spelled `{1,}` is still proven",
        assertSafeAccepts2(/^(?:b|c){1,}$/));
  // A wrapper that neither repeats nor chooses changes nothing about how the
  // engine backtracks: `((a|a))+` repeats the same alternation `(a|a)+` does.
  // Reading only the outermost body sees no alternation where the engine sees
  // one, and the inner group carries no quantifier of its own to catch it.
  check("an alternation inherited through a plain wrapper is refused",
        assertSafeAccepts2(/^((a|a))+!$/) === false);
  check("through two plain wrappers as well",
        assertSafeAccepts2(/^(?:(?:(a|a)))+!$/) === false);
  check("and through a wrapper repeated with `{1,}`",
        assertSafeAccepts2(/^((a|a)){1,}!$/) === false);
  check("a disjoint alternation behind the same wrapper is still proven",
        assertSafeAccepts2(/^((a|b))+!$/));
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

// Every spelling of "this repeats and its parts compete" has to reach the
// analysis. Each of these runs 1.5-17 seconds against a 28-character failing
// input, and each was accepted because one reader of the pattern disagreed
// with another about what counts as a repetition.
function testRepetitionSpellingsAllReachTheAnalysis() {
  // A ceiling is not a defence. `{2,30}` still admits every composition of the
  // input among its repetitions, and an exact `{10}` is polynomial of degree
  // nine. Only a quantifier that permits at most ONE repetition is harmless.
  check("a bounded outer repeat of a variable body is refused",
        assertSafeAccepts2(/(a+){2,30}!/) === false);
  check("including at the profile's own bound",
        assertSafeAccepts2(/(a+){1,100}!/) === false);
  check("an exact outer count above one is refused",
        assertSafeAccepts2(/(a+){10}!/) === false);
  check("two bounded repeats nested are refused",
        assertSafeAccepts2(/(?:a{1,10}){1,10}!/) === false);
  check("a bounded repeat of an overlapping alternation is refused",
        assertSafeAccepts2(/(a|a){2,60}!/) === false);
  check("an outer repeat that can be taken at most once is still fine",
        assertSafeAccepts2(/(a+)?!/) && assertSafeAccepts2(/(a+){0,1}!/) &&
        assertSafeAccepts2(/(a+){1}!/));

  // Leading zeros keep the value at 2 while pushing the digit count past what
  // the quantifier readers would match, so the group reported as carrying no
  // quantifier at all.
  check("a quantifier written with leading zeros is still read",
        assertSafeAccepts2(/(a|a){0000000002,}!/) === false);
  check("and with more digits still",
        assertSafeAccepts2(/(a|a){00000000002,}!/) === false);
  check("bounded, with leading zeros, too",
        assertSafeAccepts2(/(a|a){0000000002,0000000099}!/) === false);

  // A group prefix the parser does not recognise must leave the pattern
  // unproven, not out of scope. Wrapping the canonical exponential in an
  // ES2025 modifier group silenced the detector that exists to catch it.
  check("a modifier group does not hide an overlapping alternation",
        assertSafeAccepts2(new RegExp("(?i:a|a)+b")) === false);
  check("nor a negated modifier group",
        assertSafeAccepts2(new RegExp("(?-i:a|a)+b")) === false);
  check("nor a named group whose name is longer than the parser expected",
        assertSafeAccepts2(new RegExp("(?<" + "n".repeat(66) + ">a|a)+b")) === false);
  check("a modifier group around a disjoint alternation is still accepted",
        assertSafeAccepts2(new RegExp("^(?i:a|b)+$")));

  // The `?` after an escaped metacharacter is a real quantifier. Deciding by
  // the preceding SOURCE character reads the metacharacter as the lazy marker
  // it would be if it had been a quantifier, and drops the repetition.
  check("an optional after a bare `}` counts as length variation",
        assertSafeAccepts2(/(?:a}?}?)+!/) === false);
  check("an optional after an escaped `*` counts too",
        assertSafeAccepts2(/(?:a\*?\*?)+!/) === false);
  check("and after an escaped `(`",
        assertSafeAccepts2(/(?:a\(?\(?)+!/) === false);
  check("the control shape over an ordinary character was always refused",
        assertSafeAccepts2(/(?:ab?b?)+!/) === false);
  check("a lazy quantifier is still not counted twice",
        assertSafeAccepts2(/^(?:[a-z]+?-)*[a-z]+$/));

  // Adjacent unbounded quantifiers over the same characters are polynomial in
  // how many of them there are. Nothing outside a group was examined at all.
  check("adjacent overlapping quantifiers are refused",
        assertSafeAccepts2(/a*a*a*a*a*a*a*a*a*a*b/) === false);
  check("including through character classes",
        assertSafeAccepts2(/\w*\w*\w*\w*\w*\w*\w*\w*!/) === false);
  check("two adjacent overlapping quantifiers are enough",
        assertSafeAccepts2(/^\w*\w*!$/) === false);
  check("adjacent quantifiers over DISJOINT characters are accepted",
        assertSafeAccepts2(/^a*b*c*d*!$/));
  check("a single quantifier per position is untouched",
        assertSafeAccepts2(/^\w+@\w+\.\w+$/) && assertSafeAccepts2(/^[a-z]*-[0-9]*$/));
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
  testRepetitionSpellingsAllReachTheAnalysis();
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
