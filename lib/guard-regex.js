// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.guardRegex
 * @nav    Guards
 * @title  Guard Regex
 *
 * @intro
 *   Regex-pattern content-safety guard — refuses user-supplied
 *   pattern strings that exhibit catastrophic-backtracking (ReDoS)
 *   shapes BEFORE the framework compiles them with `new RegExp(...)`.
 *   Operator-untrusted patterns flow into search filters, allow-lists,
 *   route matchers, and form validators; this primitive screens them
 *   so a hostile input can't pin a CPU at 100% inside the regex
 *   engine. KIND=`identifier`; the gate consumes `ctx.identifier`
 *   (or `ctx.pattern`) and refuses on hostile shapes. Composes with
 *   framework parsers (`b.safeJson` / `b.safeBuffer` / route helpers)
 *   so any operator-fed pattern hits the guard first.
 *
 *   Threat catalog: nested quantifiers (`(a+)+`, `(a*)+`, `(.+)+` —
 *   the canonical ReDoS class, e.g. CVE-2024-21538 cross-spawn and
 *   CVE-2022-25929 chartjs-adapter-luxon); alternation-with-
 *   quantifier (`(a|a)*`, `(\d|\d{2})*`) where two branches can match
 *   at the same position and the overlap amplifies search paths — an
 *   alternation whose branches cannot start on the same character is
 *   the character class it is written out long-hand as, and passes;
 *   quantifier-inside-lookaround
 *   (`(?=.*+)`, `(?!a*)`) — catastrophic in some engines; bounded
 *   repetition with a large upper bound (gated by
 *   `maxBoundedRepeat`); per-pattern byte cap to defend against
 *   parser-stage DoS; BIDI override / zero-width / C0 control /
 *   null-byte universal refuse.
 *
 *   Profiles: `strict` / `balanced` / `permissive`. Compliance
 *   postures: `hipaa` / `pci-dss` / `gdpr` / `soc2`. Operators
 *   select via `{ profile: "strict" }` or
 *   `{ compliancePosture: "hipaa" }`; postures overlay on top of the
 *   profile baseline. Nested-quantifier rejection holds at every
 *   profile — the catastrophic class is never an operator opt-in.
 *
 *   Pattern strings can't be repaired safely — `sanitize` either
 *   passes through clean input or throws `GuardRegexError`; the
 *   gate returns `serve` / `audit-only` / `refuse` (no `sanitize`
 *   action). Detector regexes themselves are length-bounded by
 *   `maxPatternBytes` so the screener can't be DoS'd by its own
 *   inputs, and the unambiguity analysis spends a fixed work budget
 *   — a pattern too expensive to reason about exhausts it and stays
 *   refused, so cost cannot buy leniency.
 *
 * @card
 *   Regex-pattern content-safety guard — refuses user-supplied pattern strings that exhibit catastrophic-backtracking (ReDoS) shapes BEFORE the framework compiles them with `new RegExp(...)`.
 */

var lazyRequire = require("./lazy-require");
var gateContract = require("./gate-contract");
var C = require("./constants");
var { GuardRegexError } = require("./framework-error");

var observability = lazyRequire(function () { return require("./observability"); });
void observability;

var _err = GuardRegexError.factory;

// Nested-quantifier detector: `(group)+`-style followed by another
// quantifier or repetition that operates on the grouped match.
// (The flat single-group nested-quantifier case is handled by the paren-aware
// structural scanner _hasNestedQuantifier, which — unlike a flat regex — requires
// the OUTER quantifier to be UNBOUNDED (`*`/`+`/`{n,}`, not `?`/`{0,1}`/`{n,m}`)
// and does not miscount a `(?:` group prefix as an inner quantifier, so it does
// not false-positive on linear shapes like `(?:X+)?` / `(X+)?` / `(?:bar)*`.)

// Alternation-with-quantifier — `(a|b|...)+`, `(a|b)*`. A shape check only:
// it says nothing about whether the branches can actually overlap, so a hit
// is passed to _alternationBranchesProvablyDisjoint before it becomes a
// finding. Deliberately paren-blind (`[^()]*` cannot span a nested group), so
// a branch containing a group never reaches the analysis either.
var ALTERNATION_QUANT_RE = /\([^()]*\|[^()]*\)\s*[*+]/;

// Bounded repetition — captures the upper bound when present.
var BOUNDED_REPEAT_RE = /\{(\d+)(?:,(\d*))?\}/g;

// Lookaround with internal quantifier — `(?=.*+)`, `(?!a*)`.
var LOOKAROUND_QUANT_RE = /\(\?[=!<][^()]*[*+]/;

// Nested extglob detector — picomatch `*(...)` / `+(...)` / `?(...)` /
// `@(...)` / `!(...)` containing another extglob inside (CVE-2026-33671
// nested-extglob catastrophic-backtracking class). Two extglob heads in
// the same pattern with no closing paren between them indicates nesting.
// The consecutive-star detector (CVE-2026-26996) walks the input by
// char so doesn't need a regex literal.
var EXTGLOB_HEAD_RE = /[*+?@!]\(/g;                                                  // allow:regex-no-length-cap — input bounded by maxPatternBytes

// ---- Profile presets ----

var PROFILES = Object.freeze({
  "strict": {
    ...gateContract.CHAR_THREATS_REJECT_ALL,
    nestedQuantPolicy:         "reject",
    alternationQuantPolicy:    "reject",
    boundedRepeatPolicy:       "reject",
    lookaroundQuantPolicy:     "reject",
    consecutiveStarPolicy:    "reject",
    nestedExtglobPolicy:      "reject",
    inputKind:                "regex",                                            // CVE-2026-26996 + CVE-2026-33671 detectors apply only when inputKind=="glob"
    maxBoundedRepeat:          100,                                              // bounded repeat ceiling
    maxConsecutiveStars:        2,                                                // `**` recursive glob permitted; >=3 refused
    maxPatternBytes:           C.BYTES.kib(1),
    maxBytes:                  C.BYTES.kib(1),
    maxRuntimeMs:              C.TIME.seconds(2),
  },
  "balanced": {
    ...gateContract.CHAR_THREATS_REJECT_ALL,
    nestedQuantPolicy:         "reject",
    alternationQuantPolicy:    "audit",
    boundedRepeatPolicy:       "audit",
    lookaroundQuantPolicy:     "audit",
    consecutiveStarPolicy:    "reject",                                          // CVE-2026-26996 refused at every profile
    nestedExtglobPolicy:      "reject",                                          // CVE-2026-33671 refused at every profile
    maxBoundedRepeat:          1000,                                             // bounded repeat ceiling
    maxConsecutiveStars:        2,                                                // `**` recursive glob permitted; >=3 refused
    maxPatternBytes:           C.BYTES.kib(2),
    maxBytes:                  C.BYTES.kib(2),
    maxRuntimeMs:              C.TIME.seconds(2),
  },
  "permissive": {
    ...gateContract.CHAR_THREATS_REJECT_ALL,
    nestedQuantPolicy:         "reject",                                          // canonical ReDoS class refused at every profile
    alternationQuantPolicy:    "allow",
    boundedRepeatPolicy:       "audit",
    lookaroundQuantPolicy:     "audit",
    consecutiveStarPolicy:    "reject",                                          // CVE-2026-26996 refused at every profile
    nestedExtglobPolicy:      "reject",                                          // CVE-2026-33671 refused at every profile
    maxBoundedRepeat:          10000,                                            // bounded repeat ceiling
    maxConsecutiveStars:        2,                                                // `**` recursive glob permitted; >=3 refused
    maxPatternBytes:           C.BYTES.kib(8),
    maxBytes:                  C.BYTES.kib(8),
    maxRuntimeMs:              C.TIME.seconds(2),
  },
});

var DEFAULTS = gateContract.strictDefaults(PROFILES);

var COMPLIANCE_POSTURES = gateContract.compliancePostures(PROFILES, { base: 256 });

// Structural nested-unbounded-quantifier detector. NESTED_QUANT_RE is paren-
// blind (its `[^()]*` can't span a nested group), so it misses WRAPPED forms
// like `((a)+)+` / `(([a-z]+)*)*` / `((a+))+` — adding one extra group around
// the inner quantifier bypasses the regex while the pattern stays catastrophic.
// This linear scan tracks group nesting and flags an unbounded-quantified group
// (`)+`, `)*`, `){n,}`) whose body itself contains an unbounded quantifier — the
// two-nested-unbounded-quantifier ReDoS class — at any group depth. Bounded
// repeats (`{n}`, `{n,m}`, `?`) are not unbounded, so they don't trip it (the
// large-bound case is handled separately by maxBoundedRepeat).
function _hasNestedQuantifier(src, flags) {
  var stack = [];        // open groups: each { quant, open } — body has an unbounded quantifier
  var inClass = false;   // inside a [...] character class
  var i = 0;
  var n = src.length;
  var UNBOUNDED_AFTER_GROUP = /^(?:[*+]\??|\{\d*,\})/;   // )+ )* )+? )*? ){n,}
  // One budget for the whole walk, not per group: a pattern carrying many
  // groups must not multiply the analysis cost by their number.
  var budget = _budget();
  // Same reason as the alternation analysis: a forced delimiter pins the
  // boundaries WITHIN one group, not the split between two of them.
  var soleGroup = _countUnboundedQuantifiedGroups(src) === 1;
  while (i < n) {
    var c = src.charAt(i);
    if (c === "\\") { i += 2; continue; }                          // escaped atom — skip both chars
    if (inClass) { if (c === "]") inClass = false; i += 1; continue; }
    if (c === "[") { inClass = true; i += 1; continue; }
    if (c === "(") { stack.push({ quant: false, open: i }); i += 1; continue; }
    if (c === ")") {
      var grp = stack.pop() || { quant: false, open: -1 };
      var qm = UNBOUNDED_AFTER_GROUP.exec(src.slice(i + 1));       // allow:regex-no-length-cap — bounded slice of a maxPatternBytes-capped input
      var closeUnbounded = qm !== null;
      // A repeated group whose body ends in a literal none of its other atoms
      // can match is not the catastrophic shape: the occurrences of that
      // literal pin where each repetition ends, so the outer quantifier has
      // no alternative split to explore. That is the whole difference between
      // `(?:[a-z]+-)*` and `(?:[a-z]+)*`.
      if (grp.quant && closeUnbounded && grp.open >= 0 &&
          soleGroup && !_declinesOnFlags(flags) &&
          _delimitedBodyForcesSplit(src.slice(grp.open + 1, i), budget, flags)) {
        if (stack.length) stack[stack.length - 1].quant = true;
        i += 1 + qm[0].length;
        continue;
      }
      if (grp.quant && closeUnbounded) return true;               // nested unbounded quantifier → catastrophic
      // The closing group contributes an unbounded quantifier to its PARENT's
      // body if its own body had one, or if it is itself unbounded-quantified.
      if (stack.length && (grp.quant || closeUnbounded)) stack[stack.length - 1].quant = true;
      i += 1 + (qm ? qm[0].length : 0);
      continue;
    }
    if (c === "*" || c === "+") {                                  // unbounded quantifier on the preceding atom
      if (stack.length) stack[stack.length - 1].quant = true;
      i += 1; continue;
    }
    if (c === "{") {
      var open = /^\{\d*,\}/.exec(src.slice(i));                  // allow:regex-no-length-cap — bounded slice // {n,} unbounded
      if (open) { if (stack.length) stack[stack.length - 1].quant = true; i += open[0].length; continue; }
      var bounded = /^\{\d+(?:,\d+)?\}/.exec(src.slice(i));       // allow:regex-no-length-cap — bounded slice // {n} / {n,m} bounded
      if (bounded) { i += bounded[0].length; continue; }
      i += 1; continue;                                            // literal `{`
    }
    i += 1;
  }
  return false;
}


// ---- unambiguity analysis -------------------------------------------------
//
// Both quantifier detectors above are shape checks: they fire on a pattern
// that LOOKS like the catastrophic class without asking whether it can
// actually backtrack. Backtracking needs AMBIGUITY — two ways to match the
// same input — and for two common shapes that ambiguity is provably absent:
//
//   `(?:b|c)+`         no two branches can start on the same character, so a
//                      single character decides the branch at every position.
//                      It is the character class `[bc]+` written out long.
//   `(?:[a-z]+-)*`     each repetition must end at a `-`, and `-` is not a
//                      letter, so the occurrences of `-` pin every repetition
//                      boundary. There is exactly one way to split the input.
//
// The analysis below proves those two cases and nothing else. It runs only to
// SUPPRESS a finding the shape check already raised, so anything it cannot
// characterise — a nested group, `.`, a backreference, a wide range — leaves
// the refusal exactly as it was.

var DIGIT_CHARS = "0123456789".split("");
var WORD_CHARS  = ("abcdefghijklmnopqrstuvwxyz" +
                   "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "0123456789_").split("");
// ECMAScript \s, spelled with escapes so this file stays pure ASCII.
var SPACE_CHARS = [
  " ", "\t", "\n", "\r", "\f", "\v",
  "\u00a0", "\u1680", "\u2000", "\u2001", "\u2002", "\u2003",
  "\u2004", "\u2005", "\u2006", "\u2007", "\u2008", "\u2009",
  "\u200a", "\u2028", "\u2029", "\u202f", "\u205f", "\u3000",
  "\ufeff",
];
// A range wider than this is refused rather than materialised — the analysis
// is an optimisation on a refusal, so declining to answer is always safe.
var MAX_CLASS_RANGE = 256;

// Total character-set work one screening may spend. Expanding a class and
// comparing a pair of branches are both linear in class width, and a pattern
// can carry many wide branches, so the cost is quadratic in two dimensions at
// once: without a bound, a ~1 KiB pattern of pairwise-disjoint 256-character
// branches cost half a second inside the screener — the screener becoming the
// denial of service it exists to prevent, and the one thing the per-pattern
// byte cap alone does not stop. Running out of budget simply declines to
// prove, so a pattern cannot buy leniency by being expensive to reason about.
// Everyday patterns spend a few hundred units of this.
var ANALYSIS_BUDGET = 20000;

function _budget() { return { left: ANALYSIS_BUDGET }; }
function _spend(budget, n) { budget.left -= n; return budget.left >= 0; }

// Flags change what the source means, so the analysis has to see them.
// `i` folds case; `v` adds set notation (`[[a-z]--[aeiou]]`) that this parser
// would read as an ordinary class and get wrong, so it declines outright.
function _ignoresCase(flags) {
  return typeof flags === "string" && flags.indexOf("i") !== -1;
}
function _declinesOnFlags(flags) {
  return typeof flags === "string" && flags.indexOf("v") !== -1;
}

function _set(chars, negated) { return { chars: chars, negated: !!negated }; }

// Fold a set to cover both cases. Under the `i` flag two branches that look
// disjoint on the page are not — `(a|A)+` is `(a|a)+`, and the engine
// backtracks accordingly — so the analysis must compare what the engine
// compares. Widening a positive set makes an intersection MORE likely and
// widening a negated set's exclusions makes it narrower: both push toward
// declining to prove, which is the safe direction.
function _foldCase(set) {
  var out = set.chars.slice();
  for (var i = 0; i < set.chars.length; i += 1) {
    var c = set.chars[i];
    var lo = c.toLowerCase();
    var up = c.toUpperCase();
    if (lo.length === 1 && out.indexOf(lo) === -1) out.push(lo);
    if (up.length === 1 && out.indexOf(up) === -1) out.push(up);
  }
  return _set(out, set.negated);
}

function _setContains(set, ch) {
  return set.negated ? set.chars.indexOf(ch) === -1 : set.chars.indexOf(ch) !== -1;
}

function _setsIntersect(a, b, budget) {
  if (a.negated && b.negated) return true;          // two complements always share members
  // Charged and compared through a Set, so a pair costs the SUM of the two
  // widths rather than their product.
  if (!_spend(budget, a.chars.length + b.chars.length)) return true;
  if (!a.negated && !b.negated) {
    var seen = new Set(b.chars);
    return a.chars.some(function (c) { return seen.has(c); });
  }
  var positive = a.negated ? b : a;
  var excluded = new Set((a.negated ? a : b).chars);
  return positive.chars.some(function (c) { return !excluded.has(c); });
}

// A backslash escape as a character set, or null when it is not a plain set
// of characters (a boundary, a backreference, an encoding escape).
function _escapeSet(e) {
  if (e === "") return null;
  if (e === "d") return _set(DIGIT_CHARS, false);
  if (e === "D") return _set(DIGIT_CHARS, true);
  if (e === "w") return _set(WORD_CHARS, false);
  if (e === "W") return _set(WORD_CHARS, true);
  if (e === "s") return _set(SPACE_CHARS, false);
  if (e === "S") return _set(SPACE_CHARS, true);
  if (e === "n") return _set(["\n"], false);
  if (e === "r") return _set(["\r"], false);
  if (e === "t") return _set(["\t"], false);
  if (e === "f") return _set(["\f"], false);
  if (e === "v") return _set(["\v"], false);
  if ("0123456789bBcpPuxk".indexOf(e) !== -1) return null;
  return _set([e], false);                          // an escaped literal
}

function _pushChar(chars, ch) { if (chars.indexOf(ch) === -1) chars.push(ch); }

function _findClassEnd(src, start) {
  var i = start + 1;
  if (src.charAt(i) === "^") i += 1;
  if (src.charAt(i) === "]") i += 1;                // a leading ] is a literal
  while (i < src.length) {
    var c = src.charAt(i);
    if (c === "\\") { i += 2; continue; }
    if (c === "]") return i;
    i += 1;
  }
  return -1;
}

// Expand a character-class body to an exact membership set, or null when a
// member cannot be enumerated.
function _classSet(body, budget) {
  var negated = false;
  var i = 0;
  if (body.charAt(0) === "^") { negated = true; i = 1; }
  var chars = [];
  while (i < body.length) {
    var lo;
    if (body.charAt(i) === "\\") {
      var esc = _escapeSet(body.charAt(i + 1));
      if (esc === null || esc.negated) return null; // a negated shorthand inside a class
      if (!_spend(budget, esc.chars.length)) return null;
      i += 2;
      if (esc.chars.length !== 1) {
        for (var k = 0; k < esc.chars.length; k += 1) _pushChar(chars, esc.chars[k]);
        continue;
      }
      lo = esc.chars[0];
    } else {
      lo = body.charAt(i);
      i += 1;
    }
    if (body.charAt(i) === "-" && i + 1 < body.length) {
      var hi;
      if (body.charAt(i + 1) === "\\") {
        var hiEsc = _escapeSet(body.charAt(i + 2));
        if (hiEsc === null || hiEsc.negated || hiEsc.chars.length !== 1) return null;
        hi = hiEsc.chars[0]; i += 3;
      } else { hi = body.charAt(i + 1); i += 2; }
      var from = lo.charCodeAt(0);
      var to   = hi.charCodeAt(0);
      if (to < from || to - from > MAX_CLASS_RANGE) return null;
      if (!_spend(budget, to - from + 1)) return null;
      for (var cp = from; cp <= to; cp += 1) _pushChar(chars, String.fromCharCode(cp));
    } else {
      _pushChar(chars, lo);
    }
  }
  return chars.length === 0 ? null : _set(chars, negated);
}

// Parse a group-free fragment into a flat atom list of { set, quant }, or null
// when it contains anything this analysis will not reason about: a group, an
// alternation, `.`, an anchor, a stray quantifier.
function _parseAtoms(src, budget) {
  var atoms = [];
  var i = 0;
  while (i < src.length) {
    var c = src.charAt(i);
    var set;
    if (c === "\\") {
      set = _escapeSet(src.charAt(i + 1));
      if (set === null) return null;
      i += 2;
    } else if (c === "[") {
      var close = _findClassEnd(src, i);
      if (close === -1) return null;
      set = _classSet(src.slice(i + 1, close), budget);
      if (set === null) return null;
      i = close + 1;
    } else if ("()|.^$*+?{".indexOf(c) !== -1) {
      return null;
    } else {
      set = _set([c], false);
      i += 1;
    }
    var quant = "";
    var q = src.charAt(i);
    if (q === "*" || q === "+" || q === "?") {
      quant = q;
      i += 1;
    } else if (q === "{") {
      var m = /^\{\d{1,9}(?:,\d{0,9})?\}/.exec(src.slice(i));
      if (!m) return null;
      quant = m[0];
      i += m[0].length;
    }
    if (quant !== "" && src.charAt(i) === "?") i += 1;   // lazy form
    if (!_spend(budget, 1)) return null;
    atoms.push({ set: set, quant: quant });
  }
  return atoms;
}

// A quantifier whose atom can match a VARYING number of characters. This is
// the property that matters, not merely whether it is unbounded: `?`, `{0,1}`
// and `{2,5}` are all bounded and all make the length ambiguous, and length
// ambiguity multiplies exactly the way choice ambiguity does.
function _isVariableQuant(q) {
  if (q === "") return false;
  if (q === "*" || q === "+" || q === "?") return true;
  var m = /^\{(\d{1,9})(?:,(\d{0,9}))?\}$/.exec(q);
  if (!m) return true;                              // unrecognised — assume variable
  if (m[2] === undefined) return false;             // {n} is exactly n
  return m[2] === "" || m[2] !== m[1];              // {n,} and {n,m<>n} vary
}

function _countVariableQuants(atoms) {
  var n = 0;
  for (var i = 0; i < atoms.length; i += 1) if (_isVariableQuant(atoms[i].quant)) n += 1;
  return n;
}

// The characters a fragment can begin with, or null when it might match
// nothing at all (an empty branch, or a leading atom that is optional) — a
// nullable branch can start anywhere, so it is never provably disjoint.
function _firstSet(atoms) {
  if (atoms.length === 0) return null;
  var head = atoms[0];
  if (head.quant === "*" || head.quant === "?" || /^\{0(?:,|\})/.test(head.quant)) return null;
  return head.set;
}

// Drop a group's `?:` / `?<name>` prefix. Returns null for a lookaround,
// which the lookaround detector owns.
function _stripGroupPrefix(body) {
  if (body.charAt(0) !== "?") return body;
  if (body.slice(0, 2) === "?:") return body.slice(2);
  var named = /^\?<[A-Za-z_$][A-Za-z0-9_$]{0,64}>/.exec(body);
  if (named) return body.slice(named[0].length);
  return null;
}

// Split on the alternation bars at depth 0, aware of groups, classes and
// escapes. Returns null when the fragment is unbalanced.
function _splitTopLevelAlternation(body) {
  var parts = [];
  var depth = 0;
  var inClass = false;
  var start = 0;
  var i = 0;
  while (i < body.length) {
    var c = body.charAt(i);
    if (c === "\\") { i += 2; continue; }
    if (inClass) { if (c === "]") inClass = false; i += 1; continue; }
    if (c === "[") { inClass = true; i += 1; continue; }
    if (c === "(") { depth += 1; i += 1; continue; }
    if (c === ")") { depth -= 1; if (depth < 0) return null; i += 1; continue; }
    if (c === "|" && depth === 0) { parts.push(body.slice(start, i)); start = i + 1; }
    i += 1;
  }
  if (depth !== 0) return null;
  parts.push(body.slice(start));
  return parts;
}

// Visit every group in the pattern, reporting the quantifier that follows its
// closing paren. Same escape / class / nesting handling as the scanner above.
function _walkGroups(src, visit) {
  var stack = [];
  var inClass = false;
  var i = 0;
  var AFTER_GROUP = /^(?:[*+?]\??|\{\d{0,9}(?:,\d{0,9})?\}\??)/;
  while (i < src.length) {
    var c = src.charAt(i);
    if (c === "\\") { i += 2; continue; }
    if (inClass) { if (c === "]") inClass = false; i += 1; continue; }
    if (c === "[") { inClass = true; i += 1; continue; }
    if (c === "(") { stack.push(i); i += 1; continue; }
    if (c === ")") {
      var open = stack.pop();
      var qm = AFTER_GROUP.exec(src.slice(i + 1));   // allow:regex-no-length-cap — bounded slice of a maxPatternBytes-capped input
      var quant = qm ? qm[0] : "";
      if (open !== undefined) visit(src.slice(open + 1, i), quant);
      i += 1 + quant.length;
      continue;
    }
    i += 1;
  }
}

// How many groups in the pattern carry an unbounded quantifier.
//
// Both suppressions below prove ONE group unambiguous in isolation, which says
// nothing about the boundary BETWEEN two of them: six individually-disjoint
// `(?:a|b)+` groups in a row are each unambiguous, while the ways to partition
// one run of input among the six are not, and the engine explores them all.
// Neither analysis models concatenation, so neither is applied unless there is
// exactly one such group and no boundary to get wrong.
function _countUnboundedQuantifiedGroups(src) {
  var n = 0;
  _walkGroups(src, function (_body, quant) {
    if (quant === "*" || quant === "+" || quant === "*?" || quant === "+?" ||
        /^\{\d{0,9},\}\??$/.test(quant)) {
      n += 1;
    }
  });
  return n;
}

// A repeated group body of the form `<atoms><literal>` where the trailing
// literal occurs exactly once and none of the preceding atoms can match it.
// Every repetition then contains exactly one of that literal, at its end, so
// the split into repetitions is unique and the outer quantifier cannot
// re-partition the input.
function _delimitedBodyForcesSplit(body, budget, flags) {
  var stripped = _stripGroupPrefix(body);
  if (stripped === null) return false;
  var atoms = _parseAtoms(stripped, budget);
  if (atoms === null || atoms.length < 2) return false;
  // Pinning the boundaries is only half of it. The number of paths through the
  // whole match is the PRODUCT of the paths through each repetition, so a body
  // that can itself be parsed two ways still gives 2^m over m repetitions and
  // the delimiter buys nothing — `(?:a*a*-)*` is exponential despite every
  // boundary being forced. With at most ONE variable-length atom the body has
  // exactly one parse: the fixed atoms consume fixed extents and the single
  // variable one takes whatever remains before the delimiter.
  if (_countVariableQuants(atoms) > 1) return false;
  var last = atoms[atoms.length - 1];
  if (last.quant !== "") return false;              // must occur exactly once
  if (last.set.negated || last.set.chars.length !== 1) return false;
  var delimiter = last.set.chars[0];
  var fold = _ignoresCase(flags);
  for (var i = 0; i < atoms.length - 1; i += 1) {
    var preceding = fold ? _foldCase(atoms[i].set) : atoms[i].set;
    if (!_spend(budget, preceding.chars.length)) return false;
    if (_setContains(preceding, delimiter)) return false;
    if (fold && (_setContains(preceding, delimiter.toLowerCase()) ||
                 _setContains(preceding, delimiter.toUpperCase()))) return false;
  }
  return true;
}

// True when EVERY `*`/`+`-quantified alternation in the pattern has branches
// that cannot start on the same character — and each branch is a fixed
// sequence of characterisable atoms, so its length is decided too. One
// character then selects the branch at every position and there is exactly
// one parse, which is what makes the shape equivalent to a character class.
//
// Requires at least one such group, so a pattern the shape check fired on for
// a reason this analysis never examined is never suppressed.
function _alternationBranchesProvablyDisjoint(src, flags) {
  if (_declinesOnFlags(flags)) return false;
  // More than one quantified group means concatenation boundaries this
  // analysis does not model — decline rather than prove each in isolation.
  if (_countUnboundedQuantifiedGroups(src) !== 1) return false;
  var fold = _ignoresCase(flags);
  var budget = _budget();
  var proven = true;
  var examined = false;
  _walkGroups(src, function (body, quant) {
    if (!proven) return;
    if (quant !== "*" && quant !== "+" && quant !== "*?" && quant !== "+?") return;
    var stripped = _stripGroupPrefix(body);
    if (stripped === null) return;                  // lookaround — a different detector
    var branches = _splitTopLevelAlternation(stripped);
    if (branches === null || branches.length < 2) return;
    examined = true;
    var firsts = [];
    for (var i = 0; i < branches.length; i += 1) {
      var atoms = _parseAtoms(branches[i], budget);
      // Disjoint first characters decide WHICH branch matches, not HOW MUCH it
      // consumes. A branch that can match two different lengths gives two
      // parses per unit whenever the shorter one leaves a character that can
      // start a branch — `(?:ab?|b)+` is exponential even though `a` and `b`
      // are disjoint. So every atom must be fixed-length; then one character
      // picks the branch and the branch fixes its own extent.
      if (atoms === null || _countVariableQuants(atoms) > 0) { proven = false; return; }
      var first = _firstSet(atoms);
      if (first === null) { proven = false; return; }
      firsts.push(fold ? _foldCase(first) : first);
    }
    for (var a = 0; a < firsts.length; a += 1) {
      for (var b = a + 1; b < firsts.length; b += 1) {
        if (_setsIntersect(firsts[a], firsts[b], budget)) { proven = false; return; }
      }
    }
  });
  return examined && proven;
}

function _detectIssues(input, opts) {
  var pre = gateContract.detectStringInput(input, opts, { name: "regex", noun: "regex pattern", cap: { bytes: opts.maxPatternBytes, kind: "pattern-cap", snippet: "regex pattern exceeds maxPatternBytes " + opts.maxPatternBytes } });
  if (pre.done) return pre.issues;
  var issues = pre.issues;

  if (opts.nestedQuantPolicy !== "allow" && _hasNestedQuantifier(input, opts.regexFlags)) {
    issues.push({
      kind: "nested-quantifier", severity: "critical",
      ruleId: "regex.nested-quantifier",
      snippet: "pattern contains nested-quantifier shape (e.g. " +
               "`(a+)+` / `((a)+)+`) — canonical ReDoS catastrophic-" +
               "backtracking class (CVE-2024-21538 cross-spawn / CVE-2022-25929)",
    });
  }

  if (opts.alternationQuantPolicy !== "allow" &&
      ALTERNATION_QUANT_RE.test(input) &&                                        // allow:regex-no-length-cap — input bounded by maxPatternBytes
      !_alternationBranchesProvablyDisjoint(input, opts.regexFlags)) {
    issues.push({
      kind: "alternation-quantifier",
      severity: opts.alternationQuantPolicy === "reject" ? "high" : "warn",
      ruleId: "regex.alternation-quantifier",
      snippet: "pattern contains alternation-with-quantifier shape whose " +
               "branches can match at the same position (e.g. `(a|a)*`, " +
               "`(\\d|\\d{2})*`) — the overlap amplifies search paths. " +
               "Branches that cannot start on the same character are " +
               "accepted; give each one a distinct leading character",
    });
  }

  if (opts.lookaroundQuantPolicy !== "allow" &&
      LOOKAROUND_QUANT_RE.test(input)) {                                         // allow:regex-no-length-cap — input bounded by maxPatternBytes
    issues.push({
      kind: "lookaround-quantifier",
      severity: opts.lookaroundQuantPolicy === "reject" ? "high" : "warn",
      ruleId: "regex.lookaround-quantifier",
      snippet: "pattern contains quantifier inside lookaround " +
               "(`(?=.*+)`) — catastrophic in some engines",
    });
  }

  if (opts.boundedRepeatPolicy !== "allow") {
    BOUNDED_REPEAT_RE.lastIndex = 0;
    var match;
    while ((match = BOUNDED_REPEAT_RE.exec(input)) !== null) {                   // allow:regex-no-length-cap — input bounded by maxPatternBytes
      var lower = parseInt(match[1], 10);                                        // base-10 radix
      var upper = match[2] === undefined ? lower :
                  match[2] === "" ? Infinity : parseInt(match[2], 10);           // base-10 radix
      var ceiling = (upper === Infinity || upper > lower) ? upper : lower;
      if (ceiling > opts.maxBoundedRepeat) {
        issues.push({
          kind: "bounded-repeat-cap",
          severity: opts.boundedRepeatPolicy === "reject" ? "high" : "warn",
          ruleId: "regex.bounded-repeat-cap",
          snippet: "bounded-repeat `" + match[0] + "` upper bound " +
                   (ceiling === Infinity ? "unbounded" : ceiling) +
                   " exceeds maxBoundedRepeat " + opts.maxBoundedRepeat,
        });
        break;
      }
    }
  }

  _detectConsecutiveStar(input, opts, issues);
  _detectNestedExtglob(input, opts, issues);

  return issues;
}

// Consecutive-star wildcard cap (CVE-2026-26996). Operator-supplied
// glob fragments compile to minimatch / picomatch / RegExp; a long run
// of `*` against a non-matching literal walks O(4^N). Three-or-more
// consecutive `*` is the canonical bad shape; `**` (recursive glob)
// stays permitted, gated by the profile's `maxConsecutiveStars`.
function _detectConsecutiveStar(input, opts, issues) {
  if (opts.consecutiveStarPolicy === "allow") return;
  // CVE-2026-26996 is a minimatch glob-shape backtracking class —
  // `***+literal` walks O(4^N) when minimatch translates the run to a
  // backtracking-heavy regex. Native ECMAScript regex syntax cannot
  // produce three consecutive `*` quantifiers (it's a SyntaxError),
  // so applying this detector to `inputKind: "regex"` strings only
  // produces false positives on legitimate regex shapes like
  // `a*(b)*` where `*(` is quantifier+group, not extglob.
  if (opts.inputKind !== "glob") return;
  var starRun = 0;
  var starRunMax = 0;
  for (var si = 0; si < input.length; si += 1) {
    if (input.charAt(si) === "*") {
      starRun += 1;
      if (starRun > starRunMax) starRunMax = starRun;
    } else {
      starRun = 0;
    }
  }
  var starCeiling = opts.maxConsecutiveStars === undefined ?
                    2 : opts.maxConsecutiveStars;                                // `**` glob ceiling
  if (starRunMax > starCeiling) {
    issues.push({
      kind: "consecutive-star",
      severity: opts.consecutiveStarPolicy === "reject" ? "critical" : "high",
      ruleId: "regex.consecutive-star",
      snippet: "pattern has " + starRunMax + " consecutive `*` " +
               "wildcards (cap " + starCeiling + ") — O(4^N) " +
               "backtracking on non-matching literal (CVE-2026-26996)",
    });
  }
}

// Nested-extglob detector (CVE-2026-33671). picomatch `*(...)` /
// `+(...)` / `?(...)` / `@(...)` / `!(...)` containing another
// extglob inside compiles to catastrophic-backtracking regex.
function _detectNestedExtglob(input, opts, issues) {
  if (opts.nestedExtglobPolicy === "allow") return;
  // CVE-2026-33671 is picomatch-specific: the extglob heads `*(`/
  // `+(`/`?(`/`@(`/`!(` collide with valid ECMAScript regex shapes
  // (quantifier + capturing group). Restricting this detector to
  // `inputKind: "glob"` avoids false-positive refusal of regex
  // patterns like `a*(b+(c))` where the heads are quantifier
  // groupings, not extglob.
  if (opts.inputKind !== "glob") return;
  // Collect extglob head positions via match() — read-only scan.
  var heads = [];
  var allHeads = input.match(EXTGLOB_HEAD_RE);                                   // allow:regex-no-length-cap — input bounded by maxPatternBytes
  if (allHeads === null || allHeads.length < 2) return;
  // Locate each head index manually (match returns substrings, not idx).
  var scanFrom = 0;
  for (var hh = 0; hh < allHeads.length; hh += 1) {
    var ch0 = allHeads[hh].charAt(0);
    var idx = scanFrom;
    while (idx < input.length - 1) {
      var c0 = input.charAt(idx);
      var c1 = input.charAt(idx + 1);
      if (c1 === "(" && c0 === ch0) break;
      idx += 1;
    }
    heads.push(idx);
    scanFrom = idx + 1;
    if (heads.length > 1024) break;                                              // head-count safety cap
  }
  var nested = false;
  for (var hi = 0; hi < heads.length && !nested; hi += 1) {
    var headStart = heads[hi];
    // Walk forward tracking paren depth. Inner head before close = nested.
    var pdepth = 1;
    for (var pj = headStart + 2; pj < input.length && pdepth > 0; pj += 1) {
      var ch = input.charAt(pj);
      if (ch === "(") {
        pdepth += 1;
        if (pj > 0) {
          var preVerb = input.charAt(pj - 1);
          if (preVerb === "*" || preVerb === "+" || preVerb === "?" ||
              preVerb === "@" || preVerb === "!") {
            nested = true;
            break;
          }
        }
      } else if (ch === ")") {
        pdepth -= 1;
      }
    }
  }
  if (nested) {
    issues.push({
      kind: "nested-extglob",
      severity: opts.nestedExtglobPolicy === "reject" ? "critical" : "high",
      ruleId: "regex.nested-extglob",
      snippet: "pattern contains nested extglob quantifier " +
               "(`*(...*(...))`) — catastrophic backtracking class " +
               "(CVE-2026-33671 picomatch)",
    });
  }
}

/**
 * @primitive  b.guardRegex.validate
 * @signature  b.guardRegex.validate(input, opts)
 * @since      0.7.13
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardRegex.gate, b.guardRegex.sanitize
 *
 * Inspect a user-supplied regex pattern string and return an
 * aggregated issue list. Pure inspection — never throws on hostile
 * patterns; caller decides what to do with the issues. The `ok`
 * flag is `true` only when zero `critical` / `high` issues fire.
 * Throws `GuardRegexError("regex.bad-opt")` when a numeric opt is
 * non-finite / negative (config-time mistake by the operator).
 *
 * @opts
 *   profile:                "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   bidiPolicy:             "reject"|"audit"|"allow",
 *   controlPolicy:          "reject"|"audit"|"allow",
 *   nullBytePolicy:         "reject"|"audit"|"allow",
 *   zeroWidthPolicy:        "reject"|"strip"|"audit"|"allow",
 *   nestedQuantPolicy:      "reject"|"audit"|"allow",
 *   alternationQuantPolicy: "reject"|"audit"|"allow",
 *   boundedRepeatPolicy:    "reject"|"audit"|"allow",
 *   lookaroundQuantPolicy:  "reject"|"audit"|"allow",
 *   consecutiveStarPolicy:  "reject"|"audit"|"allow",
 *   nestedExtglobPolicy:    "reject"|"audit"|"allow",
 *   inputKind:              "regex"|"glob",
 *   maxBoundedRepeat:       number,
 *   maxConsecutiveStars:    number,
 *   maxPatternBytes:        number,
 *   maxBytes:               number,
 *   maxRuntimeMs:           number,
 *
 * @example
 *   var clean = b.guardRegex.validate("^[a-z]+$", { profile: "strict" });
 *   clean.ok;                                          // → true
 *
 *   var hostile = b.guardRegex.validate("(a+)+b", { profile: "strict" });
 *   hostile.ok;                                        // → false
 *   hostile.issues.some(function (i) { return i.kind === "nested-quantifier"; });  // → true
 */
// validate is assembled by gateContract.defineGuard from `detect`
// (_detectIssues), with the positive-finite-int caps declared via `intOpts`.
// The @primitive block above documents the resulting ABI.

/**
 * @primitive  b.guardRegex.sanitize
 * @signature  b.guardRegex.sanitize(input, opts)
 * @since      0.7.13
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardRegex.validate, b.guardRegex.gate
 *
 * Pass-through-or-throw. Regex patterns cannot be safely repaired
 * (stripping a `+` from a quantifier silently changes match
 * semantics); this primitive returns the input unchanged when no
 * `critical` or `high` issue fires, otherwise throws
 * `GuardRegexError` with the offending rule id (e.g.
 * `regex.nested-quantifier`, `regex.lookaround-quantifier`,
 * `regex.bounded-repeat-cap`). Operators that need a "best-effort
 * cleanup" semantic should reject the input at the boundary
 * instead.
 *
 * @opts
 *   profile:                "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   nestedQuantPolicy:      "reject"|"audit"|"allow",
 *   alternationQuantPolicy: "reject"|"audit"|"allow",
 *   boundedRepeatPolicy:    "reject"|"audit"|"allow",
 *   lookaroundQuantPolicy:  "reject"|"audit"|"allow",
 *   consecutiveStarPolicy:  "reject"|"audit"|"allow",
 *   nestedExtglobPolicy:    "reject"|"audit"|"allow",
 *   inputKind:              "regex"|"glob",
 *   maxBoundedRepeat:       number,
 *   maxConsecutiveStars:    number,
 *   maxPatternBytes:        number,
 *
 * @example
 *   var safe = b.guardRegex.sanitize("^[a-z]+$", { profile: "strict" });
 *   safe;                                              // → "^[a-z]+$"
 *
 *   try {
 *     b.guardRegex.sanitize("(a+)+b", { profile: "strict" });
 *   } catch (e) {
 *     e.code;                                          // → "regex.nested-quantifier"
 *   }
 */
// _sanitizeTransform — the normalize tail applied by defineGuard's generated
// sanitize AFTER resolve -> detect -> throwOnRefusalSeverity. Regex patterns
// cannot be safely repaired, so the transform is a pass-through: a non-string
// or any critical/high finding refuses upstream, clean input returns verbatim.
function _sanitizeTransform(input) {
  return input;
}

/**
 * @primitive  b.guardRegex.gate
 * @signature  b.guardRegex.gate(opts)
 * @since      0.7.13
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardRegex.validate, b.guardRegex.sanitize
 *
 * Build a `b.gateContract` gate that screens `ctx.identifier` (or
 * `ctx.pattern`) before any compilation step. Action chain:
 * `serve` (no issues) → `audit-only` (warn-only) → `refuse` (any
 * `critical` or `high`). No `sanitize` action — pattern strings
 * cannot be repaired. Compose into framework parsers / form
 * validators / route matchers so operator-fed patterns hit the
 * guard before reaching `new RegExp()`.
 *
 * @opts
 *   profile:                "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   name:                   string,    // override gate name in audit emissions
 *   nestedQuantPolicy:      "reject"|"audit"|"allow",
 *   alternationQuantPolicy: "reject"|"audit"|"allow",
 *   boundedRepeatPolicy:    "reject"|"audit"|"allow",
 *   lookaroundQuantPolicy:  "reject"|"audit"|"allow",
 *   consecutiveStarPolicy:  "reject"|"audit"|"allow",
 *   nestedExtglobPolicy:    "reject"|"audit"|"allow",
 *   inputKind:              "regex"|"glob",
 *   maxBoundedRepeat:       number,
 *   maxConsecutiveStars:    number,
 *   maxPatternBytes:        number,
 *
 * @example
 *   var gate = b.guardRegex.gate({ profile: "strict" });
 *
 *   gate.check({ identifier: "(a+)+b" }).then(function (rv) {
 *     rv.ok;                                           // → false
 *     rv.action;                                       // → "refuse"
 *   });
 *
 *   gate.check({ identifier: "^[a-z]+$" }).then(function (rv) {
 *     rv.action;                                       // → "serve"
 *   });
 */
function gate(opts) {
  opts = _guard.resolveOpts(opts);
  return gateContract.buildGuardGate(
    opts.name || "guardRegex:" + (opts.profile || "default"),
    opts,
    async function (ctx) {
      var pattern = ctx && (ctx.identifier || ctx.pattern);
      if (pattern === undefined || pattern === null) {
        return { ok: true, action: "serve" };
      }
      var rv = module.exports.validate(pattern, opts);
      return gateContract.severityDisposition(rv.issues);
    });
}

// buildProfile / compliancePosture / loadRulePack are assembled by
// gateContract.defineGuard below (makeProfileBuilder(PROFILES) /
// lookupCompliancePosture(_, COMPLIANCE_POSTURES) / makeRulePackLoader).
// Their wiki sections render from the single-sourced @abiTemplate blocks
// in gate-contract.js, instantiated per guard by the page generator.

// ---- adaptive integration-test fixtures (consumed by layer-5 host harness) ----
var INTEGRATION_FIXTURES = gateContract.identifierFixtures("^[a-z]+$", "(a+)+b");

/**
 * @primitive  b.guardRegex.assertSafe
 * @signature  b.guardRegex.assertSafe(input, label?, ErrorClass?, code?, opts?)
 * @since      0.15.39
 * @status     stable
 * @related    b.guardRegex.sanitize, b.guardRegex.validate
 *
 * Screen an already-compiled <code>RegExp</code> (or a raw pattern string) for
 * catastrophic-backtracking (ReDoS) shapes, throwing if the pattern is unsafe.
 * This is the config-time guard for request-lifecycle code that matches an
 * operator-supplied regex against attacker-controlled input (User-Agent,
 * Origin, request path, form field, HELO) — an accidentally-catastrophic
 * operator pattern would otherwise be a per-request DoS once a hostile input
 * triggers the backtracking.
 *
 * Pass a <code>RegExp</code> instance (its <code>.source</code> is screened) or
 * a pattern string. On a hostile shape it throws <code>ErrorClass(code, ...)</code>
 * when an error class is supplied, otherwise the underlying
 * <code>GuardRegexError</code>. Returns the input unchanged on success.
 *
 * By default it rejects the catastrophic-backtracking classes — nested,
 * alternation-with, and lookaround quantifiers — but ALLOWS large/open bounded
 * repeats (<code>{8,}</code>, <code>{n,m}</code>): a single counted repeat is
 * linear, not exponential, and legitimate patterns (e.g. a hex hash of 8+
 * digits) use them. Pass an explicit <code>opts</code> to override.
 *
 * @opts
 *   profile:             string,   // guardRegex profile (default: "strict")
 *   boundedRepeatPolicy: string,   // default: "allow" (large bounded repeats are linear)
 *
 * @example
 *   b.guardRegex.assertSafe(/^[a-z]+$/);            // ok — returns the RegExp
 *   b.guardRegex.assertSafe(/\.[a-f0-9]{8,}\./);    // ok — a single bounded repeat is linear
 *   try { b.guardRegex.assertSafe(/((a)+)+$/); }    // throws — nested quantifier
 *   catch (e) { e.code; }                           // → "regex/unsafe-pattern"
 */
function assertSafe(input, label, ErrorClass, code, opts) {
  var source = (input instanceof RegExp) ? input.source : input;
  // The flags decide what the source means. Screening `.source` alone reads
  // `(a|A)+` as two disjoint branches when under `i` the engine sees one
  // branch twice — the exact overlap the alternation rule exists to catch. A
  // RegExp carries its flags, so they travel with it; a caller screening a
  // raw string that they will later compile case-insensitively passes
  // `regexFlags` themselves.
  if (input instanceof RegExp && (!opts || opts.regexFlags === undefined)) {
    opts = Object.assign({ profile: "strict", boundedRepeatPolicy: "allow" },
                         opts || {}, { regexFlags: input.flags });
  }
  try {
    // Screen the catastrophic-backtracking classes (nested / alternation /
    // lookaround quantifiers — held at every profile) but allow large bounded
    // repeats: a counted repeat matches in linear time, and rejecting `{n,}`
    // would refuse legitimate operator patterns (and the framework's own
    // defaults, e.g. b.staticServe.DEFAULT_HASHED_PATTERN's `{8,}`).
    _guard.sanitize(source, opts || { profile: "strict", boundedRepeatPolicy: "allow" });
  } catch (e) {
    if (ErrorClass) {
      throw new ErrorClass(code || "regex/unsafe-pattern",
        (label || "regex") + ": pattern rejected as unsafe (ReDoS shape) - " + (e && e.message));
    }
    throw e;
  }
  return input;
}

// Assembled from the gate-contract guard factory: error class, registry
// exports (NAME / KIND / INTEGRATION_FIXTURES), buildProfile /
// compliancePosture / loadRulePack wiring, plus the per-guard inspection
// surface (validate / sanitize / gate). The bespoke `gate` carries
// guardRegex's ctx.identifier || ctx.pattern dispatch unchanged.
var _guard = module.exports = gateContract.defineGuard({
  name:        "regex",
  kind:        "identifier",
  errorClass:  GuardRegexError,
  profiles:    PROFILES,
  defaults:    DEFAULTS,
  postures:    COMPLIANCE_POSTURES,
  integrationFixtures: INTEGRATION_FIXTURES,
  detect:            _detectIssues,
  sanitizeTransform: _sanitizeTransform,
  intOpts:           ["maxBytes", "maxPatternBytes", "maxBoundedRepeat", "maxConsecutiveStars"],
  gate:        gate,
});

_guard.assertSafe = assertSafe;
