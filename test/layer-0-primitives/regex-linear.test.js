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
];

var CORPUS_SUBJECTS = [
  "", "a", "b", "abc", "aaa", "aaab", "abcabc", "ABC", "Abc", " abc ", "foo",
  "foobar", "a b", "a\nb", "\n", "hello world", "ada@example.com", "127.0.0.1",
  "$12.34", "xy", "a-z", "-", "_", "a1b2c3", "   ", "one, two, three",
  "my-slug-here", "aaaaaaaaaaaa", "aaaaaaaaaaaa!", "tab\there", "A", "z",
  "a,b", "0", "9", "ab 12", "m", "k", "s", "{1}", "{a}", "}",
  // A final sigma reaches its class through neither of its own cases, and an
  // astral character is one code point under `u` and two units without it.
  "ς", "σ", "Σ", "😀",
  // A Kelvin sign and a long s fold onto ASCII letters under `u`, and onto
  // nothing without it — the pair that separates a case closure from a cast.
  "K", "ſ", "aKb",
];

var CORPUS_FLAGS = ["", "i", "m", "s", "u", "iu"];

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
               "[\\Wx]", "[\\S\\d]", "{", "}", "{a}", "[{]", "K", "ſ"];
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
  // `\u{61}` is Unicode-mode syntax; without `u` the platform reads it as a
  // repeated `u`, and so does this.
  check("escape syntax is read under the mode that applies to it",
        b.regexLinear.compile("\\u{61}", "").test("a") === new RegExp("\\u{61}", "").test("a"));
}

// What it cannot simulate, it refuses by name rather than handing to the engine
// that can be made to hang.
function testRefusesWhatItCannotRunInLinearTime() {
  var refusals = [
    ["(a)\\1", "regex/unsupported-backreference"],
    ["(?<n>a)\\k<n>", "regex/unsupported-backreference"],
    ["a(?=b)", "regex/unsupported-lookaround"],
    ["a(?!b)", "regex/unsupported-lookaround"],
    ["(?<=a)b", "regex/unsupported-lookaround"],
    ["(?<!a)b", "regex/unsupported-lookaround"],
    ["(a*)*", "regex/nullable-repetition"],
    ["(a*)?", "regex/nullable-repetition"],
    ["(?:a*b*?)*", "regex/nullable-repetition"],
    ["\\p{L}+", "regex/unsupported-property"],
    ["a{5000}", "regex/repeat-too-large"],
  ];
  var wrong = [];
  refusals.forEach(function (entry) {
    var code = null;
    try { b.regexLinear.compile(entry[0]); } catch (e) { code = e.code; }
    if (code !== entry[1]) wrong.push(entry[0] + " -> " + code + " (wanted " + entry[1] + ")");
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

function run() {
  testAgreesWithThePlatformOverACorpus();
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
