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
    // Anchored: the body is unambiguous, and a MANDATORY repetition of it is
    // separately a scan when it is not pinned to one position (see the
    // unanchored-scan checks).
    "^(?:\\w+\\.)+$",
    "(?:\\d+,)*",
    "(?:[a-z]+_)*",
    "^/blog/(?:[a-z0-9-]+/)*[a-z0-9-]+$",
    // A varying body is not by itself ambiguous. Every repetition here must
    // begin at an `a`, and the optional tail cannot be re-attributed to the
    // next one, so the split is decided — measured flat to 200,000 characters.
    // Refusing these would re-open the complaint this release set out to fix.
    // They are anchored because unanchored they are quadratic for a reason
    // that has nothing to do with the body: the whole pattern is retried at
    // every position (see testUnanchoredScanCost).
    "^(?:ab?)+c$",
    "^(?:ab?c?)+d$",
    "^(?:a[0-9]{0,2})+z$",
    // Two repeated groups in a row, where nothing the second can begin with is
    // something the first could have taken instead. The split between them
    // cannot float, so each group is judged on its own and both are decided.
    "^(?:b|c)+(?:d|e)+$",
    "^[a-z0-9]+(?:-[a-z0-9]+)*$",   // the separator leads each repetition
    "^\\w+(?:\\.\\w+)*$",
    "^[^,]+(?:,[^,]+)*$",
    // A separator that repeats is still a separator: nothing else in the body
    // can match a dash, so the whole run of them belongs to it and the split
    // is pinned. Measured flat to 64,000 characters.
    "(?:[a-z]+-+)*",
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
  // A ceiling only helps when it and the body's own variation are both small
  // enough that the whole repetition explores a fixed number of ways to match:
  // twice around an overlapping alternation is four of them, a constant. Sixty
  // times around is 2^60, which is the shape the rule exists for.
  check("a repetition small enough to enumerate is accepted",
        assertSafeAccepts2(/^(a|a){1,2}$/));
  check("a repetition that can be taken at most once is not this rule's shape",
        assertSafeAccepts2(/^(a|a){0,1}$/) && assertSafeAccepts2(/^(a|a)?$/));
  check("a ceiling too high to enumerate is refused",
        assertSafeAccepts2(/^(a|a){2,60}!$/) === false);
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
  // Anchored, because unanchored these are quadratic for a reason that has
  // nothing to do with the repetition: the pattern is retried at every
  // position and each attempt walks the input (see testUnanchoredScanCost).
  check("an outer repeat that can be taken at most once is still fine",
        assertSafeAccepts2(/^(a+)?!$/) && assertSafeAccepts2(/^(a+){0,1}!$/) &&
        assertSafeAccepts2(/^(a+){1}!$/));
  // Both bounds finite and their product small: the engine enumerates a fixed
  // number of ways to match whatever the input length, so a dotted quad with a
  // prefix length or a port after it stays an ordinary pattern.
  check("a bounded repeat of a bounded body is accepted",
        assertSafeAccepts2(/^(?:\d{1,3}\.){3}\d{1,3}$/) &&
        assertSafeAccepts2(/^(?:\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/) &&
        assertSafeAccepts2(/^(?:\d{1,3}\.){3}\d{1,3}:\d+$/) &&
        assertSafeAccepts2(/^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/));

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
  // The modifier changes the flags for what it encloses, so the analysis
  // inside has to fold the way the engine will. Read under the pattern's own
  // flags, `a` and `A` look like two branches; under the group's, they are one.
  check("a modifier group's own flags reach the branch analysis",
        assertSafeAccepts2(new RegExp("^(?i:a|A)+!$")) === false);
  check("a modifier that turns case-insensitivity OFF is honoured too",
        assertSafeAccepts2(new RegExp("^(?-i:a|A)+$", "i")));
  check("and reach the body-variation proof, not only the branch proof",
        assertSafeAccepts2(new RegExp("^(?i:aA?)+!$")) === false &&
        assertSafeAccepts2(new RegExp("^(?i:[A-Z]+z)*$")) === false);
  check("the same bodies without the modifier are still proven",
        assertSafeAccepts2(new RegExp("^(?:aA?)+!$")) &&
        assertSafeAccepts2(new RegExp("^(?i:ab?)+c$")));

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

}

// Every spelling of an ambiguous repetition that was once accepted, kept in
// one place. Each was measured super-linear against a failing input — between
// a tenth of a second and seventeen seconds at twenty-eight characters — and
// each got through because two readers of the pattern disagreed about what
// they were looking at. They are listed by the disagreement they came from.
function testEverySpellingOfAmbiguityIsRefused() {
  var bad = [
    // the canonical shapes
    "(a+)+$", "(a|a)+$", "(a+)*", "((a)+)+", "(([a-z]+)*)*",
    // a wrapper that neither repeats nor chooses
    "((a|a))+!", "((a)|a)+$", "(?:(a)|a)+$", "(?:(?:(a|a)))+!",
    // a ceiling is not a defence
    "(a+){2,30}!", "(a+){1,100}!", "(a+){10}!", "(?:a{1,10}){1,10}!",
    "(a|a){2,60}!", "(a|a){1,}!",
    // a bound too long for a reader that counted digits
    "(a|a){0000000002,}!", "(a+){2,99999999999999999999}$",
    // an optional after an escaped metacharacter is a real quantifier
    "(?:a}?}?)+!", "(?:a\\*?\\*?)+!", "(?:a\\(?\\(?)+!", "(?:ab?b?)+!",
    // two positions repeating over characters they share
    "^a*a*!$", "^a*a*a*!$", "^\\w*\\w*!$", "^(a*)(a*)!", "^(?:\\w*)(?:\\w*)!$",
    "^a*b?a*!", "^a\\.\\w*\\w*!$", "^[^a]*[^b]*!$",
    // the delimiter pins where a repetition ends, not what happens inside it
    "(?:a*a*-)*", "(?:\\w+\\d*;)*", "(?:[^-]*[^-]*-)*",
    // branch choice decided, branch length not
    "(?:ab?|b)+", "(?:ab{1,2}|b)+",
  ];
  bad.forEach(function (src) {
    check("refuses " + JSON.stringify(src), assertSafeAccepts(src) === false);
  });

  // The same, where the flags are what makes it ambiguous.
  var flagged = [
    ["^(?:x+a)*(?:[^ab]A)*!$", "i"],       // a later term reaches the delimiter only by folding
    ["^(a|A)+$", "i"],
    ["^(?i:a|a)+b$", ""],                  // a modifier group hid the alternation
    ["^(?i:a|A)+!$", ""],                  // its own flags make the branches one
    ["^(?i:aA?)+!$", ""],                  // and reach the body-variation proof
    ["^(?i:[A-Z]+z)*$", ""],
  ];
  flagged.forEach(function (pair) {
    check("refuses /" + pair[0] + "/" + pair[1],
          assertSafeAccepts2(new RegExp(pair[0], pair[1])) === false);
  });
  var longName = "(?<" + new Array(301).join("n") + ">a|a)+b";
  check("a name longer than the parser expected does not hide the alternation",
        assertSafeAccepts2(new RegExp(longName)) === false);

  // Patterns an operator actually writes, which must keep working. Several of
  // these were refused before the analysis read a parse tree rather than the
  // pattern source.
  var ordinary = [
    "^[a-z0-9]+(?:-[a-z0-9]+)*$",                  // slug — the separator LEADS each repetition
    "^\\w+(?:\\.\\w+)*$",                          // dotted key
    "^[^,]+(?:,[^,]+)*$",                          // one csv row
    "^(?:\\d{1,3}\\.){3}\\d{1,3}$",                // dotted quad
    "^(?:\\d{1,3}\\.){3}\\d{1,3}\\/\\d{1,2}$",     // with a prefix length
    "^(?:\\d{1,3}\\.){3}\\d{1,3}:\\d+$",           // with a port
    "^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$",      // mac address
    "^(?:GET|POST|PUT|DELETE)$",
    "^\\w+\\s*=\\s*.*$",                           // a config line
    "^\\s*[-*+]\\s+.*$",                           // a list item
    "^a*b*c*d*!$",                                 // adjacent, over characters they do not share
    "^v\\d+\\.\\d+\\.\\d+(?:[-+][0-9A-Za-z.-]+)?-linux-x64$",
    "^(?:b|c)+(?:d|e)+$",                          // neither group can start on the other's characters
  ];
  ordinary.forEach(function (src) {
    check("accepts " + JSON.stringify(src), assertSafeAccepts(src));
  });

  // A lookaround consumes nothing, so it takes no characters from what follows
  // — but the engine backtracks inside an assertion exactly as it does outside
  // one, and a body skipped to its closing parenthesis is a body never judged.
  var lookarounds = [
    ["^(?=((a|a)+!))", false],
    ["^(?=(a+)+b)", false],
    ["^(?<=x)(a|a)+$", false],
    ["^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d).{8,}$", true],   // the everyday password policy
    ["^(?!.*\\.\\.)[\\w.]+$", true],
    ["^(?=[a-z])[a-z0-9]{2,30}$", true],
  ];
  lookarounds.forEach(function (pair) {
    check((pair[1] ? "accepts " : "refuses ") + JSON.stringify(pair[0]),
          assertSafeAccepts(pair[0]) === pair[1]);
  });

  // A negated shorthand inside a negated class is a complement of a complement.
  // Copying its exclusions in as members and then negating the class states the
  // opposite of what it means, which made two branches that both match a digit
  // look disjoint.
  check("a double-negated class does not read as its own opposite",
        assertSafeAccepts("(?:[^\\D]|5)+!$") === false);
  check("the class alone is still accepted",
        assertSafeAccepts("^[^\\D]+$"));

  // Under `u` a surrogate pair is ONE character to the engine, so a quantifier
  // after it repeats the whole code point. Read a code unit at a time, an
  // astral literal looks like a fixed lead followed by a repeated trail — and
  // the canonical nested quantifier written with an emoji stopped looking like
  // one.
  var astral = String.fromCodePoint(0x1f600);
  check("an astral literal is one atom under the u flag",
        assertSafeAccepts2(new RegExp("^(?:" + astral + "+)+!$", "u")) === false);
  check("and its branches overlap the same way",
        assertSafeAccepts2(new RegExp("^(?:" + astral + "|" + astral + ")+!$", "u")) === false);
  check("one repetition of it is still fine",
        assertSafeAccepts2(new RegExp("^" + astral + "+!$", "u")));

  // Two positions repeating over characters they share, with nothing after them
  // but an anchor. The engine still comes back to try another split whenever
  // the match can fail, and it can fail on any character neither position
  // accepts — which is the difference between these and the linear
  // `^\s*.*$`, where between them they accept everything.
  var anchored = [
    ["^a*a*$", false], ["^a*a*a*$", false], ["^[a-z]*[a-z0-9]*$", false],
    ["^(?:a*)(?:a*)$", false],
    ["^\\s*.*$", true], ["^\\w+\\s*=\\s*.*$", true],
    ["^a*b*c*d*!$", true],
  ];
  anchored.forEach(function (pair) {
    check((pair[1] ? "accepts " : "refuses ") + JSON.stringify(pair[0]),
          assertSafeAccepts(pair[0]) === pair[1]);
  });

  // Positions that are each cheap on their own are not cheap together: their
  // ways of matching multiply, so four of them divide a run four-deep.
  check("bounded positions compose rather than each being excused",
        assertSafeAccepts("^a{0,4095}a{0,4095}x$") === false &&
        assertSafeAccepts("^a{0,4095}a{0,4095}a{0,4095}x$") === false);
  check("but a genuinely small pair is still fine",
        assertSafeAccepts("^\\d{1,3}\\d{1,2}x$"));

  // `]` ends a character class wherever it appears. Treating the first one as
  // a member walked past the real terminator and swallowed the rest of the
  // pattern, so every repetition after it disappeared from the tree.
  check("an empty class does not swallow the pattern behind it",
        assertSafeAccepts("^[]*a*a*x$") === false);
  check("nor does the any-class",
        assertSafeAccepts("^[^]*[^]*x$") === false);
  check("both are still read as the classes they are",
        assertSafeAccepts("^[]$") && assertSafeAccepts("^[^]$"));

  // Every flag an inline modifier names changes what its body means, not just
  // the one about case: with `s` a dot covers a newline, so the two branches
  // below are the same character and the pattern is exponential.
  check("dotAll inside a modifier group reaches the analysis",
        assertSafeAccepts("^(?s:.|\\n)+!$") === false);
  check("without it the two branches really are disjoint",
        assertSafeAccepts("^(?:.|\\n)+!$"));

  // An astral letter's case partner is astral too. A length check that only
  // accepted a single UTF-16 unit dropped it, and two Deseret letters the
  // engine treats as one read as disjoint.
  var deseretUpper = String.fromCodePoint(0x10400);
  var deseretLower = String.fromCodePoint(0x10428);
  check("an astral case pair folds together",
        assertSafeAccepts2(new RegExp("^(?:" + deseretUpper + "|" + deseretLower + ")+!$", "iu")) === false);
  check("an astral letter beside something else is still proven",
        assertSafeAccepts2(new RegExp("^(?:" + deseretUpper + "|b)+!$", "iu")));

  // An assertion consumes nothing but can still refuse, and a refusal is what
  // sends the engine back for another split. Only a start-or-end anchor after a
  // pair that covers every character is safe, and only because the greedy first
  // attempt already reached the end.
  check("a never-matching lookahead after the pair is a failure point",
        assertSafeAccepts("^\\s*.*(?!)$") === false);
  check("so is a word boundary",
        assertSafeAccepts("^\\s*.*\\b$") === false);
  // A group hides what comes after it: the pair inside sees only the rest of
  // its own sequence, so the `!` beyond the closing parenthesis went unnoticed.
  check("a failure point outside the group still reaches the pair inside it",
        assertSafeAccepts("^(?:\\s*.*)!$") === false);
  check("and the same group with nothing fallible after it is still linear",
        assertSafeAccepts("^(?:\\s*.*)$"));

  check("a trailing START anchor is a failure point, unlike an end anchor",
        assertSafeAccepts("^\\s*.*^$") === false);
  check("the same pair with only an end anchor is still linear",
        assertSafeAccepts("^\\s*.*$"));

  // The engine decides which characters are one under `i`. A lower/upper pass
  // does not compute the fold class: the Kelvin sign folds to `k`, but `k`
  // upper-cases to `K` and never back, so a pass starting at `K` never reaches
  // it and two branches that both match it read as disjoint. The engine is
  // asked about the characters the pattern actually contains.
  var kelvin = String.fromCharCode(0x212a);
  var longS  = String.fromCharCode(0x017f);
  var angstrom = String.fromCharCode(0x212b);
  check("a fold the engine makes but lower/upper does not is still found",
        assertSafeAccepts2(new RegExp("^(?:K|(?-i:" + kelvin + "))+!$", "iu")) === false);
  check("and for the long s",
        assertSafeAccepts2(new RegExp("^(?:s|(?-i:" + longS + "))+!$", "iu")) === false);
  check("and for the angstrom sign",
        assertSafeAccepts2(new RegExp("^(?:" + angstrom + "|(?-i:" +
              String.fromCharCode(0x00c5) + "))+!$", "iu")) === false);
  check("folding switched on inside the pattern gets the same treatment",
        assertSafeAccepts2(new RegExp("^(?i:K|(?-i:" + kelvin + "))+!$", "u")) === false);
  check("branches that genuinely do not fold together are still proven",
        assertSafeAccepts2(new RegExp("^(?:b|c)+$", "iu")));

  // The screener must not become the denial of service it exists to prevent.
  // A kilobyte of pairwise-disjoint 256-character ranges cost over two seconds
  // to analyse when sets were arrays and folding was repeated at each reader.
  var wide = "[";
  var cp = 0x0100;
  for (var i = 0; i < 78; i += 1) {
    wide += String.fromCharCode(cp) + "-" + String.fromCharCode(cp + 255);
    cp += 256;
  }
  wide += "]*b*";
  var started = Date.now();
  try { b.guardRegex.assertSafe(new RegExp(wide, "i"), "x"); } catch (_e) { /* verdict is not the point */ }
  var elapsed = Date.now() - started;
  check("analysing a kilobyte of disjoint ranges stays well under a second " +
        "(took " + elapsed + "ms)", elapsed < 500);
}

// A separator is whatever a repetition must contain and nothing else in it can
// match. Requiring that to be exactly one atom occurring exactly once left two
// everyday shapes unproven: a separator that repeats (`\s+`), and one written
// as more than one character (`::`). And a body may carry more than one part
// that varies, as long as those parts cannot take each other's characters —
// counting them, rather than asking whether they overlap, refused a comma-space
// list alongside the genuinely ambiguous shapes.
function testSeparatorsAndVaryingPartsAreJudgedOnWhatTheyMatch() {
  var linear = [
    "^[a-z]+(?:\\s+[a-z]+)*$",        // a separator that repeats
    "^\\w+(?:\\s+\\w+)*$",
    "^[a-z]+(?:::[a-z]+)*$",          // a separator of two characters
    "^[A-Za-z]+(?: > [A-Za-z]+)*$",
    "^[a-z]+(?:,\\s*[a-z]+)*$",       // two varying parts, disjoint, separated
    "^(?:&[a-z]+=[0-9]+)*$",
    "^([0-9.]+)(?:,\\s*([0-9.]+))*$",
    "^[a-z-]+(?:=\\d+)?(?:, [a-z-]+(?:=\\d+)?)*$",
  ];
  linear.forEach(function (src) {
    check("accepts " + JSON.stringify(src), assertSafeAccepts(src));
  });

  // Two published patterns operators copy verbatim. Both were refused at every
  // profile, so there was no configuration in which they worked.
  var semver = "^(0|[1-9]\\d*)\\.(0|[1-9]\\d*)\\.(0|[1-9]\\d*)" +
    "(?:-((?:0|[1-9]\\d*|\\d*[a-zA-Z-][0-9a-zA-Z-]*)" +
    "(?:\\.(?:0|[1-9]\\d*|\\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?" +
    "(?:\\+([0-9a-zA-Z-]+(?:\\.[0-9a-zA-Z-]+)*))?$";
  var email = "^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9]" +
    "(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?" +
    "(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$";
  check("accepts the published semver validation pattern", assertSafeAccepts(semver));
  check("accepts the WHATWG email-input pattern", assertSafeAccepts(email));

  // A separator only separates when there is something on the other side of
  // it. If the rest of the body can match nothing, the body IS the separator
  // and a run of its characters divides among repetitions every possible way —
  // `(?:b*a+)+` is `(a+)+` with a nullable decoration.
  var nullableRemainder = [
    "^(?:b*a+)+$", "^(?:\\s*[a-z]+)+$", "^(?:\\d*[a-z]+)+$",
    "^(?:a+b*)+$", "^(?:[bc]*a+)+$", "^(?:[^a]*a+)*$",
  ];
  nullableRemainder.forEach(function (src) {
    check("a separator with a nullable remainder is refused " + JSON.stringify(src),
          assertSafeAccepts(src) === false);
  });
  check("the same shapes with a mandatory remainder are still proven",
        assertSafeAccepts("^(?:b+a+)+$") && assertSafeAccepts("^(?:b*a)+$"));

  // Two varying parts can trade through a fixed-width term between them: in
  // `a*[ab]b*` the segment "aab" parses two ways, so comparing only the
  // varying parts to each other misses it — `[ab]` bridges {a} and {b}.
  check("varying parts that trade through a fixed term between them are refused",
        assertSafeAccepts("^(?:a*[ab]b*-)+$") === false);
  check("and through a wider bridging class",
        assertSafeAccepts("^(?:[a-z]*[a-z0-9][0-9]*-)+$") === false);
  check("a fixed term that bridges nothing still lets the parts be proven",
        assertSafeAccepts("^(?:[a-z]*=[0-9]*-)+$"));

  // The separator has to be something a repetition MUST contain, and the
  // varying parts still have to be unable to trade characters.
  var ambiguous = [
    "^(?:&[a-z]+[a-z0-9]+)*$",        // two varying parts that overlap
    "(?:a*a*-)*",
    "(?:[a-z]+a)*",                   // the separator is inside the class
    "(?:a}?}?)+",                     // the candidate separator is optional
    "(?:\\w+\\d*;)*",
  ];
  ambiguous.forEach(function (src) {
    check("still refuses " + JSON.stringify(src), assertSafeAccepts(src) === false);
  });

  // The hand-off between two varying parts runs the whole way along the fixed
  // atoms between them, not one atom at a time. In `a*[ab][bc]c*` no single
  // atom touches both ends, and `abc` still parses twice — every atom takes its
  // neighbour's character and the segment shifts by one. Against
  // `"abc-".repeat(n) + "!"` that is 202 ms at n=24, 3.2 s at n=28 and 52 s at
  // n=32.
  check("varying parts that trade along a CHAIN of atoms are ambiguous",
        assertSafeAccepts("^(?:a*[ab][bc]c*-)+$") === false &&
        assertSafeAccepts("^(?:a*[ab]b*-)+$") === false);
  // A chain broken anywhere carries nothing: `=` is neither a letter nor a
  // digit, so the two runs beside it cannot reach each other.
  check("but one broken anywhere along it is not",
        assertSafeAccepts("^(?:&[a-z]+=[0-9]+)*$") &&
        assertSafeAccepts("^[a-z]+(?:,\\s*[a-z]+)*$"));
  // The chain is read one character at a time, so parentheses cannot change the
  // answer: `(?:ax)(?:xb)` is `a` `x` `x` `b`, and the step from `a` to `x`
  // breaks it exactly as the written-out form does.
  check("the chain is read character by character, however it is grouped",
        assertSafeAccepts("^(?:a*(?:ax)(?:xb)b*-)+$") &&
        assertSafeAccepts("^(?:a*axxbb*-)+$") &&
        assertSafeAccepts("^(?:a*(?:[ab])(?:[bc])c*-)+$") === false);
  // Reading the chain must not become the cost it is screening for. A count is
  // never written out: repeating one set carries exactly as one copy does.
  var started = Date.now();
  assertSafeAccepts("^(?:a*[ab]{1000000000}b*-)+$");
  assertSafeAccepts("^(?:a*[ab]{999999999999999999999}b*-)+$");
  assertSafeAccepts("^(?:a*(?:ab){100000000}b*-)+$");
  check("a huge repetition count costs the screen nothing to read",
        Date.now() - started < b.constants.TIME.seconds(2));
}

// A pattern that is not anchored at the start is retried at EVERY position in
// the subject. When it can consume an unbounded amount before reaching
// something that must match, each of those attempts costs the length of what
// remains — so the whole scan is quadratic in the input, with no ambiguity
// anywhere inside the pattern for the other rules to find.
function testUnanchoredScanCost() {
  var quadratic = [
    "(\\w+)\\s+(\\d+)",               // an ordinary two-field scan
    "([^;]+);\\s*q=([0-9.]+)",        // an Accept-header q-value
    "(\\S+)=(\\S+);",
    "a+b",
  ];
  quadratic.forEach(function (src) {
    check("refuses the unanchored scan " + JSON.stringify(src),
          assertSafeAccepts(src) === false);
  });

  var bounded = [
    "^(\\w+)\\s+(\\d+)$",             // anchored — one attempt
    "\\.[a-f0-9]{8,}\\.",             // a mandatory fixed head fails an attempt at once
    "foo",
    "a+",                             // nothing after it must match, so nothing fails late
  ];
  bounded.forEach(function (src) {
    check("accepts " + JSON.stringify(src), assertSafeAccepts(src));
  });
  check("the sticky flag pins the attempt to one position",
        assertSafeAccepts2(new RegExp("(\\w+)\\s+(\\d+)", "y")));

  // A group around the whole pattern changes nothing about how many positions
  // the engine tries it at, so reading only the outermost term list let one
  // pair of parentheses hide the cost.
  var wrapped = ["(a+b)", "([^>]*>)", "(?:(a+b))", "(?:x|a+b)"];
  wrapped.forEach(function (src) {
    check("a wrapping group does not hide the scan cost " + JSON.stringify(src),
          assertSafeAccepts(src) === false);
  });
  check("wrapping an anchored pattern is still fine",
        assertSafeAccepts("^(a+b)$") && assertSafeAccepts("(?:^a+b$)"));

  // A choice is several scans and only one of them has to run away. It need
  // not be the first thing in the pattern — every starting position enters the
  // same branch whatever fixed atoms precede it.
  check("a choice that runs away in one branch is a scan wherever it sits",
        assertSafeAccepts("(?:x|a+b)") === false &&
        assertSafeAccepts("a(?:x|a+b)") === false &&
        assertSafeAccepts("(?:x|(?:y|a+b))") === false);

  // A lookaround consumes nothing, which is not the same as costing nothing:
  // its body is a pattern in its own right, re-run wherever the attempt
  // reaches it.
  check("an assertion whose BODY is a scan is a scan",
        assertSafeAccepts("(?=a+b)") === false &&
        assertSafeAccepts("(?!a+b)") === false &&
        assertSafeAccepts("[ax]*(?=a+b)") === false);
  check("but the body is read whole, anchors included",
        assertSafeAccepts("(?=^a+b)") && assertSafeAccepts("^(?=a+b)"));
  // Reached from only a bounded number of positions, its body runs a bounded
  // number of times: no subject both matches the `x` everywhere and feeds the
  // `a+`.
  check("and an assertion the subject cannot reach everywhere is not",
        assertSafeAccepts("x(?=a+b)"));
  // A lookBEHIND is matched backwards, so which end runs away is the other one.
  // `(?<=a+b)` tests the neighbouring `b` first and fails there at nearly every
  // position; `(?<=ba+)` walks back through everything before it at every one.
  check("a lookbehind is read the way it is matched",
        assertSafeAccepts("(?<=a+b)") && assertSafeAccepts("(?<=ab)") &&
        assertSafeAccepts("(?<=\\bfoo)bar"));
  check("so a lookbehind that walks its way back is a scan",
        assertSafeAccepts("(?<=ba+)") === false);

  // What `^` pins depends on the flags in force WHERE IT STANDS. A modifier
  // group turns multiline on for part of a pattern, and then the anchor is a
  // line start rather than the one position the whole rule turns on.
  check("a scoped m is read where it applies",
        assertSafeAccepts("(?=(?m:^[\\s\\S]+z))") === false &&
        assertSafeAccepts("(?m:^a+b)"));

  // An anchor in front of a scan can hold it to a bounded number of runs. `$`
  // outside multiline succeeds once, so what follows it runs once. The others
  // succeed often, and it depends on the scan: their firings are separated by a
  // newline or by a character of the other class, so a scan that cannot match
  // across that separator gets no further than the next one and the two trade
  // off exactly. A scan that CAN cross reaches the end from every firing.
  check("an end anchor holds the assertion after it to one run",
        assertSafeAccepts("$(?=a+b)"));
  check("a boundary holds a scan that cannot cross it",
        assertSafeAccepts("\\b(?=a+b)") && assertSafeAccepts("\\ba+b") &&
        assertSafeAccepts("\\b\\w+\\s+\\d+"));
  check("but not one that can",
        assertSafeAccepts("\\b.*z") === false);
  // `\B` is the opposite assertion: it succeeds everywhere EXCEPT the
  // transitions, so it fires all the way through a run instead of separating
  // one from the next, and bounds nothing.
  // An assertion is judged on what it STARTS by consuming, exactly as the same
  // shape written directly is: `\b(?=\w+\s+\d+)` costs what `\b\w+\s+\d+` costs.
  check("an assertion is bounded on the same terms as the shape written out",
        assertSafeAccepts("\\b(?=\\w+\\s+\\d+)") && assertSafeAccepts("\\b\\w+\\s+\\d+") &&
        assertSafeAccepts("\\b(?=.*z)") === false);
  check("and the opposite assertion bounds nothing",
        assertSafeAccepts("\\b\\w+z") && assertSafeAccepts("\\B\\w+z") === false &&
        assertSafeAccepts("\\B(?=a+b)") === false);
  check("a line anchor holds a scan that stops at the newline",
        assertSafeAccepts2(new RegExp("^a+b", "m")) &&
        assertSafeAccepts2(new RegExp("^.*z", "m")));
  check("but not one that reads straight through it",
        assertSafeAccepts2(new RegExp("^[\\s\\S]*z", "m")) === false);
  // Every line terminator counts, not just the newline: `^` under `m` fires
  // after a carriage return and after U+2028 / U+2029 as well. `.` excludes all
  // four, which is why it stops where a hand-written `[^\n]` does not.
  check("a scan that stops at only SOME line terminators is not held",
        assertSafeAccepts2(new RegExp("^[^\\n]*z", "m")) === false &&
        assertSafeAccepts2(new RegExp("^[^\\r\\n]*z", "m")) === false);

  // An assertion that always SUCCEEDS still costs what its run costs, and
  // something failing after it makes the engine pay that again from the next
  // position. `(?=a+)` on its own matches at the first position and stops.
  check("what follows an assertion is where its attempt can fail",
        assertSafeAccepts("(?=a+)[^a]") === false &&
        assertSafeAccepts("(?<=a+)[^a]") === false &&
        assertSafeAccepts("(?=a*)[^a]") === false);
  check("with nothing after it to fail on, it is not a scan",
        assertSafeAccepts("(?=a+)") && assertSafeAccepts("^(?=a+)[^a]"));
  // For a NEGATED assertion the body succeeding IS the failure, so nothing
  // after it matters: `(?!a+)` refuses at every position, each time having
  // walked the rest of the subject to find the `a+` it forbids.
  check("a negated assertion needs nothing after it to be a scan",
        assertSafeAccepts("(?!a+)") === false && assertSafeAccepts("(?!a+)a") === false);

  // The failure can be INSIDE the term that runs away. `(?:a+b)+` has nothing
  // after it to fail on and fails on its own `b` at every position all the same.
  check("a failure inside a repeated group is still a failure",
        assertSafeAccepts("(?:a+b)+") === false && assertSafeAccepts("(?:a+b){2}") === false);
  // Only while the repetition is MANDATORY: one that can be left out matches
  // empty and the attempt succeeds there and then.
  check("but one that can be left out matches empty and succeeds at once",
        assertSafeAccepts("(?:a+b)*") && assertSafeAccepts("(?:[a-z]+-)*"));
  check("and anchoring it pins the attempt as ever",
        assertSafeAccepts("^(?:a+b)+$") && assertSafeAccepts("^(?:\\w+\\.)+$"));
  // An anchor only pins what comes AFTER it. An assertion in front of one is
  // evaluated before the anchor can refuse, so the anchor does not cover it.
  check("an anchor does not pin an assertion that precedes it",
        assertSafeAccepts("(?=a+b)^") === false && assertSafeAccepts("^(?=a+b)"));
  check("and a harmless assertion in front of one is still fine",
        assertSafeAccepts("(?=x)^a+b"));
  // A positive lookahead in front of another tests the same position, so it
  // decides where the second is reached at all: where an `x` stands, the `a+`
  // stops at once.
  check("an assertion the one before it rules out is not reached everywhere",
        assertSafeAccepts("(?=x)(?=a+b)") && assertSafeAccepts("(?=[^a])(?=a+b)"));
  check("but one it lets through is",
        assertSafeAccepts("(?=a)(?=a+b)") === false);
  // A negative one narrows too, when what it forbids is a character rather
  // than a sequence. `(?!ab)` leaves every `a` not followed by a `b`.
  check("what a negative assertion forbids narrows the next one",
        assertSafeAccepts("(?!a)(?=a+b)") && assertSafeAccepts("(?!a|b)(?=[ab]+c)") &&
        assertSafeAccepts("(?!ab)(?=a+b)") === false);
  // Parentheses alone change nothing about what is forbidden.
  check("however it is written",
        assertSafeAccepts("(?!(?:a))(?=a+b)") && assertSafeAccepts("(?!((a)))(?=a+b)") &&
        assertSafeAccepts("(?!(?:a|b))(?=[ab]+c)") &&
        assertSafeAccepts("(?!(?:ab))(?=a+b)") === false &&
        assertSafeAccepts("(?!a{2})(?=a+b)") === false);
  // The body consumes nothing, so a following assertion is tested where the
  // body STARTED. `(?=a+)` succeeds and `(?!a)` then refuses at the same `a`,
  // at every position, each having paid for the run.
  check("an assertion after one is where it stands, not past the body",
        assertSafeAccepts("(?=a+)(?!a)") === false);
  // The lookaheads operators actually write are anchored and stay accepted.
  check("real anchored assertions are unaffected",
        assertSafeAccepts("^(?=.*[a-z])(?=.*\\d)[A-Za-z\\d]{8,}$") &&
        assertSafeAccepts("^(?!.*\\.\\.)[\\w./-]+$"));

  // The run that walks away need not be the FIRST thing in the pattern. A
  // fixed atom in front costs an attempt nothing, so `aa+b` scans every suffix
  // from every position exactly as `a+b` does.
  check("a fixed atom in front does not bound the scan",
        assertSafeAccepts("aa+b") === false && assertSafeAccepts("a.*b") === false);
  // Unless that atom is something the run cannot eat: no single input can both
  // match a leading dot everywhere and feed a run of hex digits.
  check("but a mandatory prefix the run cannot consume does",
        assertSafeAccepts("\\.[a-f0-9]{8,}\\."));

  // An assertion after the run consumes nothing and can still refuse, which is
  // what sends the engine back to the next starting position.
  check("a trailing anchor is a late failure point",
        assertSafeAccepts("a+$") === false);
  check("so is a trailing lookahead",
        assertSafeAccepts("a+(?=b)") === false);
  // But only when the run cannot satisfy it. A lookahead asking for what the
  // run just ate is answered by handing one character back, and a NEGATIVE one
  // asking about a character the run never matches is answered by standing
  // still — both settle on the first attempt.
  check("a lookahead the run itself satisfies is not a failure point",
        assertSafeAccepts("a+(?=a)") && assertSafeAccepts("\\w+(?=\\w)"));
  check("and one it satisfies with room to spare",
        assertSafeAccepts("a+(?=[ab])") && assertSafeAccepts("a+(?=ab?)") &&
        assertSafeAccepts("a+(?=a|b)"));
  // What it can START with does not decide it. `(?=a[^a])` opens on ground a
  // run of `a` covers and then asks for a character that run never supplies,
  // so it fails at every depth the engine backtracks to.
  check("a lookahead the run can begin but not finish is still a failure point",
        assertSafeAccepts("a+(?=a[^a])") === false &&
        assertSafeAccepts("a+(?=aab)") === false &&
        assertSafeAccepts("a+(?=b|c)") === false);
  check("nor is a negative lookahead the run can never trip",
        assertSafeAccepts("a+(?!b)") && assertSafeAccepts("[a-z]+(?![0-9])"));
  check("nor one that forbids only what a greedy run has already eaten",
        assertSafeAccepts("a+(?!a)") && assertSafeAccepts("[a-z]+(?![a-c])"));
  // The partial overlap is the one that walks back through the run refusing at
  // every step: `a+(?![ab])` on a run of `a` ending in `b`.
  check("a negative lookahead reaching both inside and outside the run does fail late",
        assertSafeAccepts("a+(?![ab])") === false &&
        assertSafeAccepts("[ab]+(?![bc])") === false);

  // A suffix the run could always hand back is not a failure point: wherever
  // the run matched enough, the match succeeds on its first attempt.
  check("a suffix the run itself satisfies is not quadratic",
        assertSafeAccepts("a+a") && assertSafeAccepts("\\w+\\w"));
  check("but a suffix INSIDE the run's characters still is",
        assertSafeAccepts(".*b") === false);
  // The whole suffix has to hold, not its first character, and a group with a
  // count hides the rest of it: `(?:ab){2}` asks for the same `b` as `ab` does.
  check("a suffix whose LATER parts the run cannot satisfy is a failure point",
        assertSafeAccepts("a+(?:ab){2}") === false &&
        assertSafeAccepts("a+ab") === false &&
        assertSafeAccepts("a+a?b") === false);
  check("while one the run satisfies all the way through is not",
        assertSafeAccepts("a+aa") && assertSafeAccepts("\\w+\\w\\w"));
  // "Can the run satisfy it" is not "can SOME string over the run's characters
  // satisfy it" — the subject is the attacker's to choose. A run over `[ab]`
  // eats both, but against a subject of nothing but `a` the `b` is never there.
  check("a suffix satisfiable by only SOME of the run's strings is a failure point",
        assertSafeAccepts("[ab]+(?=ab)") === false &&
        assertSafeAccepts("[ab]+ab") === false);
  // Branches cover the run together, not one at a time: `(?:a|b)` is `[ab]`
  // written out long, and the engine takes the branch the character calls for.
  check("branches that cover the run between them are not a failure point",
        assertSafeAccepts("[ab]+(?:a|b)") && assertSafeAccepts("[ab]+(?=a|b)"));
  check("but only while each of them holds on its own characters",
        assertSafeAccepts("[ab]+(?:ab|b)") === false);

  // It is its own rule, so an operator who bounds the subject length instead
  // can turn it off without giving up the backtracking classes.
  var relaxed = b.guardRegex.validate("(\\w+)\\s+(\\d+)",
    { profile: "strict", boundedRepeatPolicy: "allow", unanchoredScanPolicy: "allow" });
  check("the finding has a policy of its own", relaxed.ok === true);
  var reported = b.guardRegex.validate("(\\w+)\\s+(\\d+)",
    { profile: "strict", boundedRepeatPolicy: "allow" });
  check("and its own rule id",
        (reported.issues || []).some(function (i) { return i.ruleId === "regex.unanchored-scan"; }));
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
  testEverySpellingOfAmbiguityIsRefused();
  testSeparatorsAndVaryingPartsAreJudgedOnWhatTheyMatch();
  testUnanchoredScanCost();
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
