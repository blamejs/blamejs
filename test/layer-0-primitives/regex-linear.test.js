// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.regexLinear — running an operator's pattern in time proportional to the
 * subject.
 *
 * The claim is exactness AND a bound, so both are tested against the platform
 * engine rather than against expectations written by hand. A fixed corpus and a
 * seeded generator compare every result, character for character, with what
 * `RegExp` returns; the shapes that hang the platform engine are timed.
 *
 * Run standalone: `node test/layer-0-primitives/regex-linear.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

// The result, written out, so a difference in any part of it shows.
function shape(m) {
  if (m === null || m === undefined) return "null";
  var parts = [String(m.index)];
  for (var i = 0; i < m.length; i += 1) {
    parts.push(m[i] === undefined ? "<undef>" : JSON.stringify(m[i]));
  }
  return parts.join("|");
}

function agrees(src, flags, subject) {
  var mine, theirs;
  try { mine = shape(b.regexLinear.compile(src, flags).exec(subject)); }
  catch (e) { mine = "THREW " + (e.code || e.message); }
  try { theirs = shape(new RegExp(src, flags).exec(subject)); }
  catch (e2) { theirs = "THREW " + e2.message; }
  return { same: mine === theirs, mine: mine, theirs: theirs };
}

var CORPUS_PATTERNS = [
  "abc", "a|b", "a*", "a+", "a?", "a{2}", "a{2,}", "a{2,4}", "a*?", "a+?",
  "a{2,4}?", "^abc$", "\\bfoo\\b", "\\Bfoo", ".", "[abc]", "[^abc]", "[a-z]",
  "[a-z0-9_]", "[\\d]", "[\\w-]", "[\\s]", "\\d+", "\\w+", "\\s+", "\\D+",
  "\\W+", "(a)(b)", "(a|b)+", "(?:ab)+", "(a)?b", "a(b(c))d", "colou?r",
  "(?<first>\\w+)\\s+(?<second>\\w+)", "[-a-z]", "[a\\-z]", "\\$\\d+\\.\\d{2}",
  "(\\d{1,3}\\.){3}\\d{1,3}", "^[a-z0-9]+(-[a-z0-9]+)*$",
  "^[a-z]+(,\\s*[a-z]+)*$", "a.c", "a\\.c", "\\n", "\\t", "\\x41", "\\u0041",
  "[\\x00-\\x1f]", "", "()", "(|a)", "ab|cd|ef", "(ab|a)(b?)c", "[^\\n]*",
  "^$", "\\w{0}", "(a)(b)?(c)", "^(\\w+)@([\\w.]+)$", "(a+)+$", "(a|a)*$",
  "^\\s*$", "\\b\\w+\\s+\\d+", "[ab]+(?:a|b)", "(?:a+b)+", "a(?:x|a+b)",
  // A shorthand at either end of what looks like a range is not a range: these
  // are the shorthand, a hyphen, and the character beside it, and the tail of
  // `[\d-a-z]` must not be picked back up as an `a`-to-`z` range.
  "[\\d-a-z]", "[\\d-z]", "[a-\\d]", "[a-\\dz]", "[\\w-\\d]", "[\\d-]", "[-\\d]",
  "[\\W-a]", "[\\d-a-z-0-9]",
  // A complemented shorthand has to be complemented on its case closure, or the
  // fold test finds a character on both sides of the complement.
  "[\\W]", "[^\\W]", "[\\W\\d]", "[\\Wx]", "[\\D]", "[\\S]", "[^\\w]", "\\W",
  // Braces that are text, not a quantifier.
  "{a}", "a{", "a{1", "}", "a}b", "[{]", "[}]", "\\{1\\}",
  // Escapes the legacy grammar reads differently from the strict one. A `\c`
  // names a control from a digit or an underscore inside a class and from a
  // letter anywhere; naming nothing, it is a literal backslash. `\x`, `\p`,
  // `\P` and a `\k` with no group to name are identity escapes.
  "[\\c1]", "[\\c_]", "[\\c9]", "[\\cA]", "[\\ca]", "[\\c]", "[\\c-]", "[\\c%]",
  "\\c1", "\\c_", "\\cA", "\\c", "\\c%", "a\\cb",
  "\\xZZ", "\\x4", "[\\xZ]", "\\x41", "\\p{L}", "\\P", "[\\p]", "\\k", "\\kx",
  "[\\k]", "\\q", "[\\q]",
];

var CORPUS_SUBJECTS = [
  "", "a", "b", "abc", "aaa", "aaab", "abcabc", "ABC", "Abc", " abc ", "foo",
  "foobar", "a b", "a\nb", "\n", "hello world", "ada@example.com", "127.0.0.1",
  "$12.34", "xy", "a-z", "-", "_", "a1b2c3", "   ", "one, two, three",
  "my-slug-here", "aaaaaaaaaaaa", "aaaaaaaaaaaa!", "tab\there", "A", "z",
  "a,b", "0", "9", "ab 12", "m", "k", "s", "{1}", "{a}", "}",
  "\\", "\\c", "\\c1", "\\c_",
  // The controls those legacy `\c` forms name, spelled as escapes rather than
  // written into the file as the bytes themselves.
  "", "", "", "",
  "xZZ", "x4", "p{L}", "P", "kx", "q", "acb",
  // A final sigma reaches its class through neither of its own cases, and an
  // astral character is one code point under `u` and two units without it.
  "ς", "σ", "Σ", "😀",
  // A Kelvin sign and a long s fold onto ASCII letters under `u`, and onto
  // nothing without it — the pair that separates a case closure from a cast.
  "K", "ſ", "aKb",
];

var CORPUS_FLAGS = ["", "i", "m", "s", "u", "iu"];

// One shape does not belong in the corpus while the platform reads it the way
// it currently does: a character class immediately before a `$`, under `u`,
// against an astral subject. The platform misses that match and its own
// `^`-anchored form finds it, so a corpus entry of that shape would report a
// difference that is not this matcher's — see the test that pins it.

// Every pattern, every subject, every flag set — compared with the platform.
function testAgreesWithThePlatformOverACorpus() {
  var compared = 0;
  var differing = [];
  CORPUS_PATTERNS.forEach(function (src) {
    CORPUS_FLAGS.forEach(function (flags) {
      var supported = true;
      try { b.regexLinear.compile(src, flags); }
      catch (e) { if (String(e.code || "").indexOf("regex/") === 0) supported = false; }
      if (!supported) return;
      CORPUS_SUBJECTS.forEach(function (subject) {
        compared += 1;
        var verdict = agrees(src, flags, subject);
        if (!verdict.same && differing.length < 5) {
          differing.push("/" + src + "/" + flags + " on " + JSON.stringify(subject) +
                         " — linear " + verdict.mine + ", native " + verdict.theirs);
        }
      });
    });
  });
  check("the corpus is large enough to mean something", compared > 5000);
  check("every result matches the platform engine's, character for character" +
        (differing.length ? " — " + differing.join(" | ") : ""), differing.length === 0);
}

// Patterns built from a grammar rather than chosen, so the comparison covers
// combinations nobody thought to write down. The seeds are fixed, so a failure
// here is reproducible rather than a flake; there are several of them because
// one walk of the grammar reaches one corner of it.
function testAgreesWithThePlatformOverGeneratedPatterns() {
  var totals = { compared: 0, refused: 0, alsoRefused: 0 };
  var differing = [];
  [12345, 424242, 8675309].forEach(function (seed) {
    generateAndCompare(seed, 1200, totals, differing);
  });
  check("the generator produced a real body of comparisons", totals.compared > 6000);
  check("and refused only what it says it refuses", totals.refused > 0);
  // A pattern the platform will not compile must not compile here either.
  // Accepting one is how `{1}` came to mean a literal brace, a digit and a
  // second brace — a private language nobody can run anywhere else.
  check("the generator reached patterns the platform itself refuses",
        totals.alsoRefused > 100);
  check("every generated pattern agrees with the platform engine" +
        (differing.length ? " — " + differing.join(" | ") : ""), differing.length === 0);
}

function generateAndCompare(seedInit, rounds, totals, differing) {
  var seed = seedInit;
  function rnd() {
    seed ^= seed << 13; seed >>>= 0;
    seed ^= seed >> 17;
    seed ^= seed << 5;  seed >>>= 0;
    return seed / 4294967296;
  }
  function pick(a) { return a[Math.floor(rnd() * a.length)]; }
  function chance(p) { return rnd() < p; }

  var ATOMS = ["a", "b", "c", "x", "0", "1", "-", "_", ".", "\\d", "\\w", "\\s",
               "\\D", "\\W", "[abc]", "[^abc]", "[a-c]", "[a-z0-9]", "[^\\d]",
               "\\.", "\\-", "\\n", "\\x41", "\\u0062",
               // A shorthand beside a hyphen, a complemented shorthand, and a
               // brace that is text rather than a quantifier — the three shapes
               // where reading the pattern the obvious way parts company with
               // the platform.
               "[\\d-a-z]", "[a-\\d]", "[\\w-\\d]", "[\\d-]", "[\\W]", "[^\\W]",
               "[\\Wx]", "[\\S\\d]", "{", "}", "{a}", "[{]", "K", "ſ",
               // Legacy escapes: the control forms, the identity fallbacks, and
               // the named group that turns `\k` back into a backreference —
               // and, inside a class, into a syntax error.
               "\\c1", "\\c_", "\\cA", "\\c", "\\c%", "[\\c1]", "[\\c_]",
               "[\\cA]", "[\\c]", "[\\c-]", "\\xZZ", "\\x4", "[\\xZ]",
               "\\p{L}", "\\P", "[\\p]", "\\k", "\\kx", "[\\k]", "\\q",
               "(?<n>a)", "\\0", "\\07"];
  var QUANTS = ["", "", "", "*", "+", "?", "*?", "+?", "??", "{2}", "{1,3}",
                "{0,2}", "{2,}"];
  var ALPHABET = "abcx01-_. \nAB{}KſkσςΣ";

  function genAtom(depth) {
    if (depth > 0 && chance(0.25)) {
      var inner = genAlt(depth - 1);
      return chance(0.4) ? "(" + inner + ")" : "(?:" + inner + ")";
    }
    return pick(ATOMS);
  }
  function genSeq(depth) {
    var n = 1 + Math.floor(rnd() * 3);
    var out = "";
    for (var i = 0; i < n; i += 1) out += genAtom(depth) + pick(QUANTS);
    if (chance(0.12)) out = "^" + out;
    if (chance(0.12)) out += "$";
    if (chance(0.08)) out = "\\b" + out;
    return out;
  }
  function genAlt(depth) {
    var n = 1 + Math.floor(rnd() * 2);
    var parts = [];
    for (var i = 0; i < n; i += 1) parts.push(genSeq(depth));
    return parts.join("|");
  }
  function genSubject() {
    var n = Math.floor(rnd() * 14);
    var out = "";
    for (var i = 0; i < n; i += 1) out += ALPHABET.charAt(Math.floor(rnd() * ALPHABET.length));
    return out;
  }

  for (var r = 0; r < rounds; r += 1) {
    var src = genAlt(2);
    var flags = pick(["", "", "", "i", "m", "s", "im", "iu", "u", "iu", "ims"]);
    var platformCompiles = true;
    try { new RegExp(src, flags); } catch (_invalid) { platformCompiles = false; }

    var refusal = null;
    try { b.regexLinear.compile(src, flags); } catch (e) { refusal = e; }

    if (!platformCompiles) {
      // The platform will not run this pattern. Accepting it here would hand
      // the operator a language only this engine speaks.
      if (refusal === null && differing.length < 5) {
        differing.push("accepted a pattern the platform refuses: /" + src + "/" + flags);
      } else if (refusal !== null) totals.alsoRefused += 1;
      continue;
    }
    if (refusal !== null) {
      if (String(refusal.code || "").indexOf("regex/") === 0) { totals.refused += 1; continue; }
      differing.push("compile /" + src + "/" + flags + " — " + refusal.message);
      continue;
    }
    for (var s = 0; s < 5; s += 1) {
      var subject = genSubject();
      totals.compared += 1;
      var verdict = agrees(src, flags, subject);
      if (!verdict.same && differing.length < 5) {
        differing.push("/" + src + "/" + flags + " on " + JSON.stringify(subject) +
                       " — linear " + verdict.mine + ", native " + verdict.theirs);
      }
    }
  }
}

// The point of the whole thing: the shapes that make the platform engine hang.
function testTheShapesThatHangThePlatformRunInLinearTime() {
  var catastrophic = ["(a+)+$", "(a|a)*$", "([a-zA-Z]+)*$", "(a+)+(b+)+$"];
  var slowest = 0;
  catastrophic.forEach(function (src) {
    var m = b.regexLinear.compile(src);
    var subject = "a".repeat(2000) + "!";
    var started = Date.now();
    m.test(subject);
    var took = Date.now() - started;
    if (took > slowest) slowest = took;
  });
  check("the classic catastrophic shapes finish at once on 2,000 characters",
        slowest < b.constants.TIME.seconds(1));

  // Growing the subject grows the work in proportion, rather than exploding.
  var scanner = b.regexLinear.compile("\\w+@[\\w.]+");
  var shortRun = Date.now();
  scanner.test("a".repeat(16384));
  shortRun = Date.now() - shortRun;
  var longRun = Date.now();
  scanner.test("a".repeat(65536));
  longRun = Date.now() - longRun;
  check("and four times the subject is nothing like four times squared the work",
        longRun < b.constants.TIME.seconds(2) && shortRun < b.constants.TIME.seconds(1));

  // Reading the pattern has to stay linear too. Whether a pattern names a group
  // is a property of the whole source, so asking it once per escape rather than
  // once per pattern made COMPILING quadratic — and a promise about linear
  // MATCHING says nothing about a compiler that can be made to crawl.
  //
  // 32,768 escapes is the most the 64 KiB source cap admits, which is what puts
  // the two costs a hundred times apart: reading this once takes about ten
  // milliseconds, and re-reading it per escape takes about a second.
  var many = "\\k".repeat(32768);
  var compileStarted = Date.now();
  b.regexLinear.compile(many);
  var compileTook = Date.now() - compileStarted;
  check("the longest pattern the cap admits compiles in one pass over it, not " +
        "one pass per escape (" + compileTook + "ms)",
        compileTook < b.constants.TIME.seconds(1) / 2);

  // The `y` flag allows exactly ONE start. Once its attempt has died there is
  // nothing left to seed, and reading the rest of the subject buys an answer
  // already in hand — two million characters were being walked to say no.
  var pinned = b.regexLinear.compile("z", "y");
  var haystack = "a".repeat(2000000);
  var stickyStarted = Date.now();
  var stickyFound = pinned.test(haystack);
  var stickyTook = Date.now() - stickyStarted;
  check("a sticky pattern that fails at its one position stops there (" +
        stickyTook + "ms over two million characters)",
        stickyFound === false && stickyTook < b.constants.TIME.seconds(1) / 4);
  // The same pattern without `y` has every position to try and must read them,
  // so the saving belongs to stickiness rather than to giving up early.
  check("while the same pattern unanchored still searches the whole subject",
        b.regexLinear.compile("z", "").test(haystack + "z") === true);
}

// The rule both the matcher and the screen fold by, checked directly: two
// characters are the same under `i` exactly when it answers alike for them.
function testCanonicalizeForCaseIsTheRuleNotACaseConversion() {
  var canon = b.codepointClass.canonicalizeForCase;
  function same(a, z, unicode) {
    return canon(a.codePointAt(0), unicode) === canon(z.codePointAt(0), unicode);
  }
  check("ordinary letters fold", same("k", "K", false) && same("é", "É", false));
  // A non-ASCII character does not fold onto an ASCII one, which is the rule
  // converting both ways and comparing gets wrong.
  check("a Kelvin sign is not a k", same("k", "K", false) === false);
  check("nor under u, where it folds the other way", same("k", "K", true) === true);
  // Under u the rule is case FOLDING, so a long s reaches an ordinary s.
  check("a long s is an s only under u",
        same("s", "ſ", false) === false && same("s", "ſ", true) === true);
  check("a character whose upper case is two characters is left alone",
        canon("ß".codePointAt(0), false) === "ß".codePointAt(0));
  // Upper- then lower-casing a dotless i lands on an ordinary i, and Unicode
  // still does not call them the same character.
  check("a dotless i is not an i, however casing suggests otherwise",
        same("i", "ı", true) === false && same("I", "ı", true) === false);
  check("and it agrees with the platform on each of them",
        new RegExp("k", "i").test("K") === same("k", "K", false) &&
        new RegExp("s", "iu").test("ſ") === same("s", "ſ", true) &&
        new RegExp("i", "iu").test("ı") === same("i", "ı", true));

  // The partners of a character, for the case where what it is compared against
  // is a class of ranges rather than a list that can be walked.
  var partners = b.codepointClass.caseFoldPartners;
  function links(from, to, unicode) {
    return partners(from.codePointAt(0), unicode).indexOf(to.codePointAt(0)) !== -1;
  }
  check("a final sigma and an ordinary one are partners, which casing never reaches",
        links("σ", "ς", true) && links("ς", "σ", true));
  check("so are a micro sign and a Greek mu", links("µ", "μ", false));
  check("while a Kelvin sign keeps its distance from k without u",
        links("K", "k", false) === false && links("K", "k", true) === true);
}

// Folding, through the matcher rather than the rule, against the platform.
function testCaseFoldingFollowsTheLanguageRatherThanCaseConversion() {
  var cases = [
    ["ABC", "i", "abc"], ["[a-z]", "i", "Q"], ["[^abc]", "i", "B"],
    ["k", "i", "K"], ["k", "iu", "K"], ["s", "i", "ſ"],
    ["s", "iu", "ſ"], ["ß", "i", "ẞ"], ["ß", "iu", "ẞ"],
    ["é", "i", "É"], ["[à-ÿ]", "i", "É"],
    // A character that folds onto a word character is one for boundaries too.
    ["\\b.", "iu", "K"], ["\\b.", "i", "K"], ["\\b.", "iu", "ſ"],
    // Classes casing alone never reaches, which come from the table
    // scripts/gen-case-fold-classes.js derives from this platform: a final
    // sigma and an ordinary one, a micro sign and a Greek mu, the title-case
    // digraphs, a ring sign — and a dotless i, which is NOT an `i`.
    ["ς", "iu", "σ"], ["σ", "iu", "ς"], ["[ς]", "iu", "σ"],
    ["µ", "i", "μ"], ["μ", "i", "µ"],
    ["Ǆ", "i", "ǅ"], ["ǆ", "i", "Ǆ"],
    ["Å", "iu", "Å"],
    ["I", "iu", "ı"], ["i", "iu", "ı"], ["ı", "iu", "i"],
  ];
  var differing = [];
  cases.forEach(function (c) {
    var mine, theirs;
    try { mine = String(b.regexLinear.compile(c[0], c[1]).test(c[2])); }
    catch (_e) { mine = "refused"; }
    try { theirs = String(new RegExp(c[0], c[1]).test(c[2])); }
    catch (_e2) { theirs = "throws"; }
    if (mine !== theirs) {
      differing.push(JSON.stringify(c[0]) + "/" + c[1] + " on " + JSON.stringify(c[2]) +
                     " — linear " + mine + ", native " + theirs);
    }
  });
  check("case folding matches the platform across every awkward class" +
        (differing.length ? " — " + differing.join(" | ") : ""), differing.length === 0);

  // Between the halves of an astral character is a position the engine still
  // looks at, where a zero-width pattern still matches — and nothing that
  // consumes can, because no character begins there.
  var astralSubjects = ["a💩b", "💩", "x💩", "💩x"];
  var splitPatterns = ["\\B", "x|\\B", "\\Bb", "\\b", "(?:)", "\\B\\w", "\\w\\B", "^\\B", "\\B$", "."];
  var splitDiffs = [];
  splitPatterns.forEach(function (src) {
    astralSubjects.forEach(function (subject) {
      var verdict = agrees(src, "u", subject);
      if (!verdict.same && splitDiffs.length < 4) {
        splitDiffs.push("/" + src + "/u on " + JSON.stringify(subject) +
                        " — linear " + verdict.mine + ", native " + verdict.theirs);
      }
    });
  });
  check("a position inside a surrogate pair is looked at exactly as the platform looks at it" +
        (splitDiffs.length ? " — " + splitDiffs.join(" | ") : ""), splitDiffs.length === 0);

  // An astral letter is one character, not two units, so its case forms meet.
  var astralUpper = String.fromCodePoint(0x10400);
  var astralLower = String.fromCodePoint(0x10428);
  check("astral letters fold as characters rather than as surrogate halves",
        b.regexLinear.compile(astralUpper, "iu").test(astralLower) ===
        new RegExp(astralUpper, "iu").test(astralLower));
}

// A pattern the platform refuses must be refused here too, or a configuration
// mistake passes unnoticed on its way to production.
function testRefusesWhatThePlatformItselfRefuses() {
  var alsoInvalid = [
    ["a++", ""], ["a", "ii"], ["a", "uv"], ["a", "gg"], ["\\a", "u"],
    // Nothing repeats an assertion — not even once. `^{1}` is a syntax error
    // although repeating once would have meant nothing, and `\b{0}` would
    // silently drop the boundary the operator asked for.
    ["^{1}a", ""], ["\\b{0}a", ""], ["^*", ""], ["$+", ""], ["\\B{2}x", ""],
  ];
  var accepted = alsoInvalid.filter(function (c) {
    var nativeThrew = false;
    try { new RegExp(c[0], c[1]); } catch (_e) { nativeThrew = true; }
    if (!nativeThrew) return false;
    try { b.regexLinear.compile(c[0], c[1]); return true; } catch (_e2) { return false; }
  });
  check("what RegExp refuses, this refuses" +
        (accepted.length ? " — accepted " + JSON.stringify(accepted) : ""), accepted.length === 0);
  var dCode = null;
  try { b.regexLinear.compile(/a/d); } catch (e) { dCode = e.code; }
  check("a flag promising a result this does not produce is refused, not ignored",
        dCode === "regex/unsupported-flag");
  var vCode = null;
  try { b.regexLinear.compile("[a&&b]", "v"); } catch (e) { vCode = e.code; }
  check("and the v flag is refused rather than read as ordinary class members",
        vCode === "regex/unsupported-flag");

  // Every flag the platform takes lands in one of three states, and which one
  // is what the docstring promises. Compiling without throwing is NOT evidence
  // of honouring: an implementation that read `i` and did nothing with it would
  // pass that. Each honoured flag is asked for a result it alone produces.
  var probes = {
    // flag: [pattern, subject, matches with the flag, matches without it]
    i: ["a",        "A",    true,  false],
    m: ["^b",       "a\nb", true,  false],
    s: ["a.b",      "a\nb", true,  false],
    u: ["\\u{61}",  "a",    true,  false],
  };
  var wrongFlags = [];
  Object.keys(probes).forEach(function (flag) {
    var probe = probes[flag];
    var withFlag, without;
    try { withFlag = b.regexLinear.compile(probe[0], flag).test(probe[1]); }
    catch (e) { withFlag = "threw " + e.code; }
    try { without = b.regexLinear.compile(probe[0], "").test(probe[1]); }
    catch (e2) { without = "threw " + e2.code; }
    if (withFlag !== probe[2] || without !== probe[3]) {
      wrongFlags.push(flag + ": with=" + withFlag + " without=" + without +
                      " (wanted " + probe[2] + "/" + probe[3] + ")");
    }
    // And the platform reads the same pattern the same way.
    if (new RegExp(probe[0], flag).test(probe[1]) !== probe[2]) {
      wrongFlags.push(flag + ": the platform no longer behaves this way");
    }
  });
  // Sticky anchors the attempt where it starts rather than scanning forward.
  var sticky = b.regexLinear.compile("a", "y").exec("ba");
  var scanning = b.regexLinear.compile("a", "").exec("ba");
  if (sticky !== null || scanning === null || scanning.index !== 1) {
    wrongFlags.push("y: sticky " + JSON.stringify(sticky) + ", scanning " +
                    JSON.stringify(scanning && scanning.index));
  }
  check("every honoured flag changes a result that names it" +
        (wrongFlags.length ? " — " + wrongFlags.join(" | ") : ""), wrongFlags.length === 0);

  // `g` is ACCEPTED and deliberately does nothing, because the matcher returns
  // one match and the caller decides what comes next. That is a third state,
  // and saying so keeps it from being mistaken for a flag that was honoured.
  var withG = b.regexLinear.compile("a", "g").exec("aa");
  var withoutG = b.regexLinear.compile("a", "").exec("aa");
  check("g is accepted and changes nothing, which is what it promises",
        withG !== null && withoutG !== null && withG.index === withoutG.index &&
        withG[0] === withoutG[0]);

  // And the two that are refused by name are refused for every pattern, not
  // only the one that shows why.
  var notRefused = [];
  ["d", "v"].forEach(function (flag) {
    ["a", "[abc]", "(x)y"].forEach(function (src) {
      var code = null;
      try { b.regexLinear.compile(src, flag); } catch (e) { code = e.code; }
      if (code !== "regex/unsupported-flag") notRefused.push("/" + src + "/" + flag + " → " + code);
    });
  });
  check("d and v are refused by name whatever the pattern" +
        (notRefused.length ? " — " + notRefused.join(" | ") : ""), notRefused.length === 0);
  // `\u{61}` is Unicode-mode syntax; without `u` the platform reads it as a
  // repeated `u`, and so does this.
  check("escape syntax is read under the mode that applies to it",
        b.regexLinear.compile("\\u{61}", "").test("a") === new RegExp("\\u{61}", "").test("a"));
}

// What it cannot simulate, it refuses by name rather than handing to the engine
// that can be made to hang.
function testRefusesWhatItCannotRunInLinearTime() {
  // A property escape is only a property escape under `u`; `/\p{L}+/` without
  // it is a `p`, a brace, an `L` and a repeated brace, and runs fine.
  var refusals = [
    ["(a)\\1", "", "regex/unsupported-backreference"],
    ["(?<n>a)\\k<n>", "", "regex/unsupported-backreference"],
    ["a(?=b)", "", "regex/unsupported-lookaround"],
    ["a(?!b)", "", "regex/unsupported-lookaround"],
    ["(?<=a)b", "", "regex/unsupported-lookaround"],
    ["(?<!a)b", "", "regex/unsupported-lookaround"],
    ["(a*)*", "", "regex/nullable-repetition"],
    ["(a*)?", "", "regex/nullable-repetition"],
    ["(?:a*b*?)*", "", "regex/nullable-repetition"],
    ["\\p{L}+", "u", "regex/unsupported-property"],
    ["\\P{L}+", "u", "regex/unsupported-property"],
    ["a{5000}", "", "regex/repeat-too-large"],
  ];
  var wrong = [];
  refusals.forEach(function (entry) {
    var code = null;
    try { b.regexLinear.compile(entry[0], entry[1]); } catch (e) { code = e.code; }
    if (code !== entry[2]) wrong.push(entry[0] + " -> " + code + " (wanted " + entry[2] + ")");
  });
  check("each unsupported construct is refused under its own code" +
        (wrong.length ? " — " + wrong.join(" | ") : ""), wrong.length === 0);

  // The refusal says what to do about it, not just that it happened.
  var message = "";
  try { b.regexLinear.compile("a(?=b)"); } catch (e) { message = e.message; }
  check("and the refusal tells the operator what to do instead",
        message.indexOf("b.guardRegex.assertSafe") !== -1);

  // Compiling must not become the cost it screens for. Counts multiply where
  // they nest, so a short pattern can ask for a program of millions of steps —
  // and a pattern of nothing but zero-width steps must not overflow a stack.
  var started = Date.now();
  var nestedCode = null;
  try { b.regexLinear.compile("(a{4096}){4096}"); } catch (e) { nestedCode = e.code; }
  check("nested repetition counts are bounded by the whole program, not each one",
        nestedCode === "regex/repeat-too-large" &&
        Date.now() - started < b.constants.TIME.seconds(2));
  check("and a pattern that nests modestly still compiles",
        b.regexLinear.compile("(a{100}){100}").test("a") === false);
  check("a long chain of zero-width steps runs rather than overflowing",
        b.regexLinear.compile("(){2000}").test("") === new RegExp("(){2000}").test(""));

  // Recording a capture must not copy every slot, or a pattern of N groups does
  // N-squared work and the promised bound holds only for patterns that were
  // small anyway. Eight hundred groups is not a real pattern; it is the shape
  // that shows the difference.
  function groupsCost(n) {
    var many = b.regexLinear.compile("()".repeat(n) + "a");
    var began = Date.now();
    many.exec("a");
    return Date.now() - began;
  }
  groupsCost(200);                                        // warm, so the first call pays no extra
  var eightHundred = groupsCost(800);
  check("many capture groups cost their number, not its square",
        eightHundred < b.constants.TIME.seconds(1));
  check("and the captures they record are still right",
        JSON.stringify(b.regexLinear.compile("(a)(b)?(c)").exec("ac").slice(0)) ===
        JSON.stringify(new RegExp("(a)(b)?(c)").exec("ac").slice(0)));

  // The catastrophic shapes it DOES accept are the ones operators hit.
  check("the shapes people actually get bitten by are accepted, not refused",
        b.regexLinear.compile("(a+)+$").test("aaa!") === false &&
        b.regexLinear.compile("([a-zA-Z]+)*$").test("abc") === true);
}

function testTheSurfaceReportsWhatItCompiled() {
  var m = b.regexLinear.compile("(?<user>\\w+)@(\\w+)", "i");
  check("it reports the pattern it was given",
        m.source === "(?<user>\\w+)@(\\w+)" && m.flags === "i");
  check("and how many groups it found", m.groupCount === 2);
  check("and their names", m.groupNames.join(",") === "user");
  var found = m.exec("ADA@example");
  check("a named group is readable by name", found.groups.user === "ADA");
  check("and by number", found[2] === "example");
  check("with the index it was found at", found.index === 0);

  check("a RegExp can be handed over whole",
        b.regexLinear.compile(/^a+$/i).test("AAA") === true);
  check("exec can start part-way along",
        b.regexLinear.compile("a").exec("bba", 2).index === 2);
  check("the sticky flag pins it to where it was told to start",
        b.regexLinear.compile("a", "y").exec("ba") === null);

  // Under `u` an offset that splits a surrogate pair does not name a place a
  // character starts, and the platform's own answer there is not one rule — a
  // zero-width assertion matches at the split index while a consuming pattern
  // reports the index before it. Refusing beats differing quietly.
  var splitOffset = null;
  try { b.regexLinear.compile(".", "u").exec("😀", 1); }
  catch (e) { splitOffset = e; }
  check("an offset splitting a surrogate pair is refused under u",
        splitOffset instanceof RangeError);
  check("while the same offset is ordinary without u",
        b.regexLinear.compile("\ude00", "").exec("😀", 1) !== null);
}

function testRefusesInputItCannotCompile() {
  var bad = ["a**", "(", "[a", "a{2,1}", "\\", "*a", "(?a)", "(?<1>a)", "(?<->a)"];
  var accepted = bad.filter(function (src) {
    try { b.regexLinear.compile(src); return true; } catch (_e) { return false; }
  });
  check("malformed patterns are refused rather than half-read" +
        (accepted.length ? " — accepted " + accepted.join(" ") : ""), accepted.length === 0);

  var typeErrors = 0;
  try { b.regexLinear.compile(42); } catch (e) { if (e instanceof TypeError) typeErrors += 1; }
  try { b.regexLinear.compile("a", "q"); } catch (e) { if (e instanceof TypeError) typeErrors += 1; }
  try { b.regexLinear.compile("a").exec(42); } catch (e) { if (e instanceof TypeError) typeErrors += 1; }
  check("and a caller's mistake is a TypeError at the call", typeErrors === 3);
}

// The screen and the runner answer different questions, and the module says so.
function testItComposesWithTheScreenRatherThanReplacingIt() {
  var pattern = "(a+)+$";
  var screened = true;
  try { b.guardRegex.assertSafe(new RegExp(pattern), "x"); } catch (_e) { screened = false; }
  check("the screen turns away what it cannot vouch for", screened === false);
  check("and the runner runs the same pattern anyway, in linear time",
        b.regexLinear.compile(pattern).test("a".repeat(500) + "!") === false);
}

// Compiling a pattern must not change what a pattern compiled elsewhere means.
// A class is assembled by concatenating its members' range lists, and a
// shorthand contributes the shared table itself; a neighbour absorbed into one
// of those ranges in place widened the shorthand for the whole process, so one
// operator-supplied pattern silently loosened every validator beside it.
function testCompilingOneClassCannotWidenAnother() {
  var pairs = [
    { widener: "[\\d:]",  probe: "\\d",   subject: ":" },
    { widener: "[\\d:]",  probe: "[\\d]", subject: ":" },
    { widener: "[\\w{]",  probe: "\\w",   subject: "{" },
    { widener: "[\\s!]",  probe: "\\s",   subject: "!" },
    { widener: "[\\s\\u0008]", probe: "\\s", subject: "" },
  ];
  pairs.forEach(function (p) {
    var before = b.regexLinear.compile(p.probe).test(p.subject);
    b.regexLinear.compile(p.widener);
    var after = b.regexLinear.compile(p.probe).test(p.subject);
    check("/" + p.probe + "/ still refuses " + JSON.stringify(p.subject) +
          " after /" + p.widener + "/ was compiled",
          before === false && after === false);
    check("and the platform agrees about /" + p.probe + "/",
          new RegExp(p.probe).test(p.subject) === false);
  });
  // The complement is built from the same table, so it drifts the other way.
  b.regexLinear.compile("[\\d:]");
  check("a complemented shorthand did not narrow either",
        b.regexLinear.compile("\\D").test(":") === true);
  // A word boundary reads that table too, so the widening reached assertions.
  b.regexLinear.compile("[\\w{]");
  check("and a boundary still sees a brace as a non-word character",
        b.regexLinear.compile("b\\b").test("b{") === true);
}

// Which characters may be escaped is not one rule but four, because it differs
// inside a class from outside one and under `u` from without it. Rather than
// name the characters that matter, this asks the platform about every printable
// one in all four positions — `\-` is legal in a class under `u` and a syntax
// error outside it, and nothing but an exhaustive question finds that.
function testEveryEscapedCharacterIsReadTheWayThePlatformReadsIt() {
  // A digit escape is refused on purpose: `\1` is a backreference where a group
  // exists and a legacy octal escape where none does, and the message says to
  // write `\xNN` for the character. It is the one deliberate departure.
  var deliberate = "123456789";
  var disagreeing = [];
  ["", "u"].forEach(function (flags) {
    for (var cp = 0x20; cp < 0x7F; cp += 1) {
      var ch = String.fromCharCode(cp);
      [["\\" + ch, "outside a class"], ["[\\" + ch + "]", "inside a class"]]
        .forEach(function (form) {
          if (deliberate.indexOf(ch) !== -1 && form[1] === "outside a class") return;
          var platform = true;
          try { new RegExp(form[0], flags); } catch (_e) { platform = false; }
          var linear = true;
          try { b.regexLinear.compile(form[0], flags); } catch (_e2) { linear = false; }
          if (platform !== linear) {
            disagreeing.push("\\" + ch + " " + form[1] + " /" + flags + "/ — " +
                             "platform " + (platform ? "accepts" : "refuses") +
                             ", linear " + (linear ? "accepts" : "refuses"));
          }
        });
    }
  });
  check("every printable character escaped in every position is read alike" +
        (disagreeing.length ? " — " + disagreeing.join(" | ") : ""),
        disagreeing.length === 0);

  // And the deliberate departure is still deliberate, rather than quietly gone.
  var code = null;
  try { b.regexLinear.compile("\\1"); } catch (e) { code = e.code; }
  check("a digit escape is still refused by name",
        code === "regex/unsupported-backreference");
}

// The one shape where the two answers differ, and why the difference is the
// platform's. Under `u`, an unanchored pattern ending in a character class then
// `$` misses a subject ending in an astral character — but the same pattern
// with a `^` in front of it finds the match, and a `^` can only take positions
// away. This does not assert what the platform answers, so a fix there will not
// break it; it asserts that the answer given here is the one the platform's own
// anchored form agrees with.
function testTheAstralEndAnchorFollowsTheLanguageNotThePlatformShortcut() {
  var emoji = "\u{1F600}";
  // Every shape whose class can match at most one code point before the `$`.
  var shapes = ["[^a]$", "[\\s\\S]$", "(?:[^a])$", "[^a]{1}$", "[^a]?$",
                "[^a]{0,1}$"];
  var disagreeing = [];
  shapes.forEach(function (src) {
    var mine = b.regexLinear.compile(src, "u").exec(emoji);
    // What the platform says when the same pattern is pinned to position zero,
    // where its end-anchor shortcut does not apply.
    var anchored = new RegExp("^" + src, "u").exec(emoji);
    if (mine === null || anchored === null || mine[0] !== anchored[0] ||
        mine.index !== anchored.index) {
      disagreeing.push("/" + src + "/u — linear " + JSON.stringify(mine && mine[0]) +
                       ", platform anchored " + JSON.stringify(anchored && anchored[0]));
    }
  });
  check("a class before an end anchor matches an astral character, as the " +
        "platform's own anchored form confirms" +
        (disagreeing.length ? " — " + disagreeing.join(" | ") : ""),
        disagreeing.length === 0);

  // The shapes the platform reads correctly stay identical, so the departure is
  // this one shortcut rather than a difference in how astral input is read.
  // And the neighbours: a class that may run on, a shorthand, the dot, and the
  // character written out. The shortcut does not reach any of them.
  var unaffected = ["\\W$", ".$", "[^a]+$", "[^a]*$", "\\u{1F600}$"];
  var differing = [];
  unaffected.forEach(function (src) {
    var verdict = agrees(src, "u", emoji);
    if (!verdict.same) {
      differing.push("/" + src + "/u — linear " + verdict.mine + ", native " + verdict.theirs);
    }
  });
  check("and every neighbouring shape still matches the platform exactly" +
        (differing.length ? " — " + differing.join(" | ") : ""), differing.length === 0);
}

// The fold table is DERIVED from the running platform, so the thing worth
// asserting is that the derivation still agrees with it — over every code point
// that has any case behaviour at all, rather than over the handful of pairs
// somebody thought to write down. Three separate classes were missing when this
// was a list: a Greek eta with a iota subscript beside its capital form (both
// upper-case to two characters, so neither leads to the other), a long-s-t
// ligature beside an st ligature (which share only the "ST" they upper-case to),
// and a dotless i, which folds onto an ordinary `i` by every route the casing
// functions offer and is still not the same character.
function testTheFoldTableStillAgreesWithThePlatformItWasDerivedFrom() {
  var canonical = b.codepointClass.canonicalizeForCase;
  var partners = b.codepointClass.caseFoldPartners;
  var WINDOW = 32;
  var MAX = 0x10FFFF;

  function isSurrogate(cp) { return cp >= 0xD800 && cp <= 0xDFFF; }
  // Whole-string equality rather than a class: without `u`, a class holding an
  // astral character is a class of its two surrogate halves, and would report a
  // fold between every pair of Deseret letters.
  function spell(cp, unicode) {
    if (unicode) return "\\u{" + cp.toString(16) + "}";
    return String.fromCodePoint(cp).split("").map(function (unit) {
      return "\\u" + unit.charCodeAt(0).toString(16).padStart(4, "0");
    }).join("");
  }
  function platformSaysSame(a, bb, flags, unicode) {
    try {
      return new RegExp("^" + spell(a, unicode) + "$", flags).test(String.fromCodePoint(bb)) &&
             new RegExp("^" + spell(bb, unicode) + "$", flags).test(String.fromCodePoint(a));
    } catch (_e) { return null; }
  }

  var caseBearing = [];
  for (var cp = 0; cp <= MAX; cp += 1) {
    if (isSurrogate(cp)) continue;
    var ch = String.fromCodePoint(cp);
    if (ch.toLowerCase() !== ch || ch.toUpperCase() !== ch) caseBearing.push(cp);
  }
  check("the sweep covers every code point with any case behaviour",
        caseBearing.length > 2500);

  var compared = 0;
  var disagreeing = [];
  [true, false].forEach(function (unicode) {
    var flags = unicode ? "iu" : "i";
    caseBearing.forEach(function (a) {
      var candidates = Object.create(null);
      partners(a, unicode).forEach(function (p) { candidates[p] = true; });
      var s = String.fromCodePoint(a);
      [s.toLowerCase(), s.toUpperCase(), s.toUpperCase().toLowerCase()].forEach(function (image) {
        if (image.length === 1 || (image.length === 2 && image.codePointAt(0) > 0xFFFF)) {
          candidates[image.codePointAt(0)] = true;
        }
      });
      for (var d = -WINDOW; d <= WINDOW; d += 1) {
        var near = a + d;
        if (near >= 0 && near <= MAX && !isSurrogate(near)) candidates[near] = true;
      }
      Object.keys(candidates).forEach(function (key) {
        var other = Number(key);
        if (other === a) return;
        var theirs = platformSaysSame(a, other, flags, unicode);
        if (theirs === null) return;
        compared += 1;
        var mine = canonical(a, unicode) === canonical(other, unicode);
        if (mine !== theirs && disagreeing.length < 8) {
          disagreeing.push("U+" + a.toString(16).toUpperCase() + " and U+" +
                           other.toString(16).toUpperCase() + " under /" + flags +
                           "/ — the table says " + mine + ", the platform says " + theirs);
        }
      });
    });
  });
  check("the sweep compared a real body of pairs", compared > 300000);
  check("every pair is folded the way the platform folds it" +
        (disagreeing.length ? " — " + disagreeing.join(" | ") : ""),
        disagreeing.length === 0);

  // And every partner it names is a partner, so the table cannot pass by
  // claiming nothing.
  var unreal = [];
  [true, false].forEach(function (unicode) {
    var flags = unicode ? "iu" : "i";
    caseBearing.forEach(function (a) {
      partners(a, unicode).forEach(function (p) {
        if (platformSaysSame(a, p, flags, unicode) === false && unreal.length < 8) {
          unreal.push("U+" + a.toString(16).toUpperCase() + " claims U+" +
                      p.toString(16).toUpperCase() + " under /" + flags + "/");
        }
      });
    });
  });
  check("and every partner the table names is one the platform agrees with" +
        (unreal.length ? " — " + unreal.join(" | ") : ""), unreal.length === 0);
}

function run() {
  testAgreesWithThePlatformOverACorpus();
  testTheFoldTableStillAgreesWithThePlatformItWasDerivedFrom();
  testEveryEscapedCharacterIsReadTheWayThePlatformReadsIt();
  testTheAstralEndAnchorFollowsTheLanguageNotThePlatformShortcut();
  testCompilingOneClassCannotWidenAnother();
  testAgreesWithThePlatformOverGeneratedPatterns();
  testTheShapesThatHangThePlatformRunInLinearTime();
  testCanonicalizeForCaseIsTheRuleNotACaseConversion();
  testCaseFoldingFollowsTheLanguageRatherThanCaseConversion();
  testRefusesWhatThePlatformItselfRefuses();
  testRefusesWhatItCannotRunInLinearTime();
  testTheSurfaceReportsWhatItCompiled();
  testRefusesInputItCannotCompile();
  testItComposesWithTheScreenRatherThanReplacingIt();
}

if (require.main === module) {
  try {
    run();
    console.log("regex-linear OK — " + helpers.getChecks() + " checks");
  } catch (e) {
    console.error("FAIL:", e.stack || e);
    process.exit(1);
  }
}

module.exports = { run: run };
