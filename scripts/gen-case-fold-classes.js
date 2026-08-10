#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Regenerate lib/case-fold-classes.js.
 *
 * Two characters are the same under a regular expression's `i` flag when they
 * canonicalize alike. Most such pairs are reachable from one another by upper-
 * or lower-casing, and are found without a table. A few dozen are not: a micro
 * sign and a Greek mu, a final sigma and an ordinary one, the title-case forms
 * of the digraphs. Those are the ones written here.
 *
 * The data is DERIVED, not copied — every code point is canonicalized with the
 * running Node's own case mappings and grouped, so the table says exactly what
 * this platform does rather than what some other Unicode revision said. Rerun
 * it when the Node floor moves; `node scripts/gen-case-fold-classes.js --check`
 * fails if the committed file no longer matches what this produces, which is
 * how CI notices.
 *
 *   node scripts/gen-case-fold-classes.js
 *   node scripts/gen-case-fold-classes.js --check
 */

var fs = require("node:fs");
var path = require("node:path");

var MAX_CODE_POINT = 0x10FFFF;
var OUT = path.join(__dirname, "..", "lib", "case-fold-classes.js");

function oneCodePoint(s) {
  if (s.length === 1) return true;
  return s.length === 2 && s.codePointAt(0) > 0xFFFF;
}

// The rule WITHOUT the corrections this script produces. Reading the corrected
// one would make the output depend on the last output, and rerunning would keep
// moving; from the raw rule it is the same table every time.
function rawCanonical(cp, unicode) {
  var ch = String.fromCodePoint(cp);
  var upper = ch.toUpperCase();
  if (unicode) {
    if (oneCodePoint(upper)) {
      var folded = upper.toLowerCase();
      if (oneCodePoint(folded)) return folded.codePointAt(0);
    }
    var lowered = ch.toLowerCase();
    return oneCodePoint(lowered) ? lowered.codePointAt(0) : cp;
  }
  if (!oneCodePoint(upper)) return cp;
  var canon = upper.codePointAt(0);
  if (cp >= 128 && canon < 128) return cp;
  return canon;
}

// The partners reachable WITHOUT a table, which is what the table must supply
// the remainder of.
function reachableByCasing(cp) {
  var ch = String.fromCodePoint(cp);
  var out = [];
  [ch.toLowerCase(), ch.toUpperCase(), ch.toUpperCase().toLowerCase()].forEach(function (s) {
    if (oneCodePoint(s)) out.push(s.codePointAt(0));
  });
  return out;
}

// Casing gets the candidate classes close but not right: it folds a dotless i
// onto an ordinary one, and Unicode does not. So each candidate class is put to
// the engine — pair by pair, and only within a class, which is a few thousand
// questions rather than the impossible number — and split where the engine
// disagrees. Asking here is free; the shipped code never does it.
function truePartition(members, unicode) {
  var flags = unicode ? "iu" : "i";
  var groups = [];
  members.forEach(function (member) {
    var joined = false;
    for (var g = 0; g < groups.length && !joined; g += 1) {
      var head = groups[g][0];
      var same;
      try {
        same = new RegExp(String.fromCodePoint(head), flags).test(String.fromCodePoint(member)) &&
               new RegExp(String.fromCodePoint(member), flags).test(String.fromCodePoint(head));
      } catch (_e) { same = false; }                       // a syntax character — its own group
      if (same) { groups[g].push(member); joined = true; }
    }
    if (!joined) groups.push([member]);
  });
  return groups;
}

// Everything that might put two characters in the same class. The approximation
// is deliberately GENEROUS, because the engine below can split a class that is
// too big and nothing can rejoin one that was never assembled: grouping on the
// canonical alone meant that where the approximation separated a pair — as it
// did for a Greek eta with a iota subscript and its capital form, both of whose
// upper cases expand — the pair was never even offered for testing.
function groupingKeys(cp, unicode) {
  var ch = String.fromCodePoint(cp);
  var keys = ["c:" + rawCanonical(cp, unicode)];
  [ch.toLowerCase(), ch.toUpperCase(), ch.toUpperCase().toLowerCase()].forEach(function (s) {
    if (oneCodePoint(s)) keys.push("k:" + s.codePointAt(0));
  });
  // The WHOLE mapping, expansion and all, because two characters can share one
  // while sharing nothing else: a long-s-t ligature and an st ligature both
  // upper-case to "ST" and neither leads to the other by any single-character
  // route, and the engine calls them the same character under `iu`.
  keys.push("U:" + ch.toUpperCase());
  keys.push("L:" + ch.toLowerCase());
  return keys;
}

// What the class should canonicalize to. It has to be a MEMBER of the class:
// a raw answer pointing outside it is exactly the case the correction exists to
// repair — a dotless i raw-canonicalizes to an ordinary `i`, which the engine
// puts in a different class, so the dotless i must answer for itself. Among the
// members, the value most of them already give keeps the table small; ties go to
// the lower code point so the output is the same from one run to the next.
function classCanonical(group, unicode) {
  var counts = new Map();
  group.forEach(function (member) {
    var raw = rawCanonical(member, unicode);
    if (group.indexOf(raw) === -1) return;                 // points outside the class
    counts.set(raw, (counts.get(raw) || 0) + 1);
  });
  var best = null;
  var bestCount = -1;
  Array.from(counts.keys()).sort(function (a, b) { return a - b; }).forEach(function (value) {
    if (counts.get(value) > bestCount) { best = value; bestCount = counts.get(value); }
  });
  return best === null ? group[0] : best;
}

function classesFor(unicode) {
  // Union-find over every grouping key, so a class is assembled from any
  // relation that suggests it and pulled apart afterwards by the engine.
  var parent = new Map();
  function find(x) {
    while (parent.get(x) !== x) { parent.set(x, parent.get(parent.get(x))); x = parent.get(x); }
    return x;
  }
  function union(a, b) {
    var ra = find(a);
    var rb = find(b);
    if (ra !== rb) parent.set(ra > rb ? ra : rb, ra > rb ? rb : ra);
  }

  var cp;
  var byKey = new Map();
  for (cp = 0; cp <= MAX_CODE_POINT; cp += 1) {
    if (cp >= 0xD800 && cp <= 0xDFFF) continue;            // lone surrogates are not characters
    parent.set(cp, cp);
  }
  for (cp = 0; cp <= MAX_CODE_POINT; cp += 1) {
    if (cp >= 0xD800 && cp <= 0xDFFF) continue;
    groupingKeys(cp, unicode).forEach(function (key) {
      var first = byKey.get(key);
      if (first === undefined) byKey.set(key, cp);
      else if (parent.has(first)) union(first, cp);
    });
  }

  var components = new Map();
  for (cp = 0; cp <= MAX_CODE_POINT; cp += 1) {
    if (cp >= 0xD800 && cp <= 0xDFFF) continue;
    var root = find(cp);
    var members = components.get(root);
    if (members === undefined) { members = []; components.set(root, members); }
    members.push(cp);
  }

  var extras = new Map();
  var splits = new Map();
  components.forEach(function (members) {
    if (members.length < 2) return;
    truePartition(members, unicode).forEach(function (group) {
      var target = classCanonical(group, unicode);
      // Only where the raw rule actually lands the character elsewhere: a
      // correction that repeats the raw answer says nothing and pads the table.
      group.forEach(function (member) {
        if (rawCanonical(member, unicode) !== target) splits.set(member, target);
      });
      if (group.length < 2) return;
      group.forEach(function (member) {
        var reach = reachableByCasing(member);
        var missing = group.filter(function (other) {
          return other !== member && reach.indexOf(other) === -1;
        });
        if (missing.length !== 0) extras.set(member, missing);
      });
    });
  });
  return { extras: extras, splits: splits };
}

function render(extras) {
  var keys = Array.from(extras.keys()).sort(function (a, b) { return a - b; });
  var lines = keys.map(function (cp) {
    var partners = extras.get(cp).sort(function (a, b) { return a - b; });
    return "  " + cp + ": [" + partners.join(", ") + "],";
  });
  return lines.join("\n");
}

function renderSplits(splits) {
  var keys = Array.from(splits.keys()).sort(function (a, b) { return a - b; });
  return keys.map(function (cp) { return "  " + cp + ": " + splits.get(cp) + ","; }).join("\n");
}

function build() {
  var plain = classesFor(false);
  var unicode = classesFor(true);
  return [
    "// SPDX-License-Identifier: Apache-2.0",
    "// Copyright (c) blamejs contributors",
    '"use strict";',
    "// GENERATED by scripts/gen-case-fold-classes.js — do not edit by hand.",
    "//",
    "// Characters that a regular expression treats as the same under `i` but that",
    "// upper- and lower-casing does not lead from one to the other: a micro sign",
    "// and a Greek mu, a final sigma and an ordinary one, the title-case digraphs,",
    "// and — under `u` only — a Kelvin sign and a `k`, a long s and an `s`.",
    "//",
    "// Every other equal pair is found by casing and is not listed. Keyed by code",
    "// point, giving the partners that casing alone would miss.",
    "",
    "var PLAIN = {",
    render(plain.extras),
    "};",
    "",
    "var UNICODE = {",
    render(unicode.extras),
    "};",
    "",
    "// Where folding through upper case lands a character in the wrong company.",
    "// A dotless i upper-cases to `I`, which lower-cases to `i` — and Unicode",
    "// still does not call them the same character. These say which company the",
    "// character actually keeps.",
    "var PLAIN_CANONICAL = {",
    renderSplits(plain.splits),
    "};",
    "",
    "var UNICODE_CANONICAL = {",
    renderSplits(unicode.splits),
    "};",
    "",
    "module.exports = {",
    "  PLAIN: PLAIN, UNICODE: UNICODE,",
    "  PLAIN_CANONICAL: PLAIN_CANONICAL, UNICODE_CANONICAL: UNICODE_CANONICAL,",
    "};",
    "",
  ].join("\n");
}

var produced = build();
if (process.argv.indexOf("--check") !== -1) {
  var onDisk = "";
  try { onDisk = fs.readFileSync(OUT, "utf8"); } catch (_e) { onDisk = ""; }
  if (onDisk.replace(/\r\n/g, "\n") !== produced) {
    process.stderr.write("[gen-case-fold-classes] lib/case-fold-classes.js is out of date for this " +
                         "Node's case mappings — rerun `node scripts/gen-case-fold-classes.js`\n");
    process.exit(1);
  }
  process.stdout.write("[gen-case-fold-classes] OK - matches this platform's case mappings\n");
} else {
  fs.writeFileSync(OUT, produced);
  process.stdout.write("[gen-case-fold-classes] wrote " + OUT + "\n");
}
