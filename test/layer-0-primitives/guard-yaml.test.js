// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * guard-yaml — YAML content-safety primitive (b.guardYaml).
 *
 * Covers: surface; registry parity; dangerous-tag detection
 * (!!python/ / !!java. / !!ruby/ / !!perl/ / !!js/ / !!cs/ / !!system.
 * / !!eval / !!exec / !!new / !!apply); custom-tag and core-tag
 * policy; anchor/alias detection; alias-explosion detection; multi-
 * document streams; Norway-problem implicit booleans (no/yes/y/n/on/
 * off); leading-zero octals; merge-key chain; duplicate keys at same
 * indent level; bidi/null/control char detection; sanitize discipline
 * (no safe sanitization — refuse on critical/high); profile + posture
 * vocabulary.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function testGuardYamlSurface() {
  check("guardYaml is an object",                    typeof b.guardYaml === "object");
  check("guardYaml.NAME === 'yaml'",                 b.guardYaml.NAME === "yaml");
  check("guardYaml.KIND === 'content'",              b.guardYaml.KIND === "content");
  check("guardYaml.MIME_TYPES has application/yaml", b.guardYaml.MIME_TYPES.indexOf("application/yaml") !== -1);
  check("guardYaml.EXTENSIONS has .yaml",            b.guardYaml.EXTENSIONS.indexOf(".yaml") !== -1);
  check("guardYaml.PROFILES has strict",             !!b.guardYaml.PROFILES["strict"]);
  check("guardYaml.PROFILES has balanced",           !!b.guardYaml.PROFILES["balanced"]);
  check("guardYaml.PROFILES has permissive",         !!b.guardYaml.PROFILES["permissive"]);
  check("guardYaml.COMPLIANCE_POSTURES has hipaa",   !!b.guardYaml.COMPLIANCE_POSTURES["hipaa"]);
  check("guardYaml.validate is a function",          typeof b.guardYaml.validate === "function");
  check("guardYaml.parse is a function",             typeof b.guardYaml.parse === "function");
  check("guardYaml.gate is a function",              typeof b.guardYaml.gate === "function");
  check("guardYaml.GuardYamlError is a function",    typeof b.guardYaml.GuardYamlError === "function");
  check("frameworkError.GuardYamlError exposed",     typeof b.frameworkError.GuardYamlError === "function");
}

function testGuardYamlRegistryParity() {
  check("guardYaml registered in guardAll",
        b.guardAll.list().some(function (g) { return g.name === "yaml"; }));
}

function testGuardYamlDangerousTags() {
  var prefixes = ["!!python/object", "!!java.util.HashMap",
                  "!!ruby/object:Class", "!!perl/", "!!js/Function",
                  "!!system.IO.File", "!!eval foo", "!!apply [1]"];
  for (var i = 0; i < prefixes.length; i++) {
    var rv = b.guardYaml.validate(prefixes[i] + "\n", { profile: "strict" });
    check("dangerous-tag detected: " + JSON.stringify(prefixes[i]),
          rv.ok === false &&
          rv.issues.some(function (issue) { return issue.kind === "dangerous-tag"; }));
  }
}

function testGuardYamlCustomTag() {
  var rv = b.guardYaml.validate("!Foo bar\n", { profile: "strict" });
  check("custom tag refused under strict",
        rv.issues.some(function (issue) { return issue.kind === "custom-tag"; }));
}

function testGuardYamlAlias() {
  var rv = b.guardYaml.validate("a: &a v\nb: *a\n", { profile: "strict" });
  check("anchors+aliases refused under strict",
        rv.issues.some(function (issue) { return issue.kind === "alias-disabled"; }));
}

function testGuardYamlAliasExplosion() {
  // Build alias-amplification > 8x anchors.
  var src = "a: &a 1\n";
  for (var i = 0; i < 20; i++) src += "b" + i + ": *a\n";
  var rv = b.guardYaml.validate(src, { profile: "balanced" });
  check("alias explosion detected (8x amplification floor)",
        rv.issues.some(function (issue) { return issue.kind === "alias-explosion"; }));
}

function testGuardYamlMultiDoc() {
  var rv = b.guardYaml.validate("---\nfoo: 1\n---\nbar: 2\n", { profile: "strict" });
  check("multi-document refused under strict",
        rv.issues.some(function (issue) { return issue.kind === "multi-document"; }));
}

function testGuardYamlNorwayProblem() {
  var inputs = ["country: NO\n", "x: yes\n", "y: y\n", "active: on\n",
                "mode: off\n", "n: no\n"];
  for (var i = 0; i < inputs.length; i++) {
    var rv = b.guardYaml.validate(inputs[i], { profile: "strict" });
    check("Norway problem detected: " + JSON.stringify(inputs[i]),
          rv.issues.some(function (issue) { return issue.kind === "norway-implicit-bool"; }));
  }

  // Quoted form NOT flagged.
  var rvQuoted = b.guardYaml.validate('country: "NO"\n', { profile: "strict" });
  check("quoted form NOT flagged",
        !rvQuoted.issues.some(function (issue) { return issue.kind === "norway-implicit-bool"; }));
}

function testGuardYamlLeadingZeroOctal() {
  var rv = b.guardYaml.validate("mode: 0777\n", { profile: "strict" });
  check("leading-zero octal detected",
        rv.issues.some(function (issue) { return issue.kind === "leading-zero-octal"; }));

  // Repeated on the SAME input. A scan whose matcher carries state between
  // calls answers the same question differently each time — a validator that
  // detects a finding on the first document and misses it on the second is
  // worse than one that never detected it, because nothing about the input
  // says which answer you got. A single call can never show this, which is
  // why the check above passed while every other invocation missed.
  var seen = 0;
  for (var i = 0; i < 6; i += 1) {
    var again = b.guardYaml.validate("mode: 0777\n", { profile: "strict" });
    if (again.issues.some(function (issue) { return issue.kind === "leading-zero-octal"; })) seen += 1;
  }
  check("leading-zero octal detected on every repeat call, not alternating",
        seen === 6);

  // Distinct documents in sequence, the shape an operator's gate actually sees.
  var docs = ["mode: 0777\n", "perm: 0644\n", "umask: 0022\n", "bits: 0755\n"];
  var missed = docs.filter(function (doc) {
    return !b.guardYaml.validate(doc, { profile: "strict" }).issues
      .some(function (issue) { return issue.kind === "leading-zero-octal"; });
  });
  check("leading-zero octal detected across a run of distinct documents",
        missed.length === 0);
}

function testGuardYamlMergeKey() {
  var rv = b.guardYaml.validate("base: &b\n  x: 1\nuser:\n  <<: *b\n  y: 2\n",
                                { profile: "strict" });
  check("merge-key with anchor reference detected",
        rv.issues.some(function (issue) { return issue.kind === "merge-key"; }));

  // A merge key is a mapping key, so it is structure — and `<<: *base` written
  // inside a block scalar is a line of somebody's shell script. Found by
  // sweeping #642's root rather than reported: the duplicate-key screen was one
  // structural rule reading raw source, and this was the other.
  function mergeKinds(src) {
    return b.guardYaml.validate(src, { profile: "strict" }).issues
      .filter(function (issue) { return issue.kind === "merge-key"; }).length;
  }
  check("a merge key inside a block scalar is not a merge key",
        mergeKinds("script: |\n  <<: *base\n  echo hi\n") === 0,
        String(mergeKinds("script: |\n  <<: *base\n  echo hi\n")));
  check("a merge key inside a quoted value is not a merge key",
        mergeKinds("note: \"<<: *base\"\n") === 0,
        String(mergeKinds("note: \"<<: *base\"\n")));
  // Every OTHER region that is literal text, because listing two of them was
  // the first attempt at this fix and it left six more open. The screen asks
  // the lexer whether a node can begin at the `<<` instead, and a node begins
  // in none of these.
  var literalRegions = [
    ["a comment after a value",             "a: 1 # <<: *base\n"],
    ["a comment on its own line",           "# <<: *base\na: 1\n"],
    ["a comment after a document marker",   "--- # <<: *base\na: 1\n"],
    ["a plain scalar's continuation line",  "note: this is prose\n  <<: *base\n"],
    ["a quoted scalar's continuation line", "s: \"one\n  <<: *base\"\n"],
    ["a single-quoted value",               "s: '<<: *base'\n"],
    ["a folded block scalar's body",        "s: >\n  <<: *base\n"],
  ];
  literalRegions.forEach(function (pair) {
    check("a merge key in " + pair[0] + " is not a merge key",
          mergeKinds(pair[1]) === 0, String(mergeKinds(pair[1])));
  });
  // Controls: the real ones are still found, so this is reading structure
  // rather than having stopped looking. The second is the smuggling shape —
  // not a well-formed mapping entry, and refused anyway, which is why the
  // question is "could a node begin here" and not "is this valid structure".
  check("control: a real merge key is still detected",
        mergeKinds("base: &b\n  x: 1\nuser:\n  <<: *b\n") === 1,
        String(mergeKinds("base: &b\n  x: 1\nuser:\n  <<: *b\n")));
  check("control: the no-space shape is still refused",
        mergeKinds("use:\n  <<:*d\n") === 1, String(mergeKinds("use:\n  <<:*d\n")));
  check("control: a merge key in a flow mapping is still detected",
        mergeKinds("x: { <<: *b }\n") === 1, String(mergeKinds("x: { <<: *b }\n")));
  // An apostrophe inside a quoted body must not desynchronise the reading of a
  // LATER merge key. A first version counted quote characters to decide what
  // was inside a string, which is the lexer's job re-derived badly.
  check("control: an apostrophe in a quoted value does not hide a later merge key",
        mergeKinds("k: \"it's\"\nx:\n  <<: *b\n") === 1,
        String(mergeKinds("k: \"it's\"\nx:\n  <<: *b\n")));
}

function testGuardYamlDuplicateKeys() {
  var rv = b.guardYaml.validate("a: 1\na: 2\n", { profile: "strict" });
  check("duplicate-key detected at same indent",
        rv.issues.some(function (issue) { return issue.kind === "duplicate-key"; }));

  var rvNotDup = b.guardYaml.validate("x:\n  a: 1\ny:\n  a: 2\n", { profile: "strict" });
  check("same key at different scopes NOT flagged",
        !rvNotDup.issues.some(function (issue) { return issue.kind === "duplicate-key"; }));

  // A block scalar's body is text, not structure. Two lines inside one that
  // merely LOOK like `key: value` are not two mapping entries, and there is no
  // mapping at any indent inside a block scalar for them to collide in. This is
  // the same root as #631/#632 — a screen deciding structure by reading the raw
  // source — and it survived that fix because only the sigil scans were moved
  // onto the lexer's mask (#642).
  function dupsIn(src) {
    return b.guardYaml.validate(src, { profile: "strict" }).issues
      .filter(function (issue) { return issue.kind === "duplicate-key"; })
      .map(function (issue) { return issue.snippet; });
  }
  var script =
    "with:\n" +
    "  script: |\n" +
    "    a({\n" +
    "      owner: ctx.owner,\n" +
    "    });\n" +
    "    b({\n" +
    "      owner: ctx.owner,\n" +
    "    });\n";
  check("#642: key-shaped lines inside a block scalar are not duplicate keys",
        dupsIn(script).length === 0, JSON.stringify(dupsIn(script)));

  var folded =
    "run: >\n" +
    "  owner: one\n" +
    "  owner: two\n";
  check("#642: a folded block scalar behaves the same",
        dupsIn(folded).length === 0, JSON.stringify(dupsIn(folded)));

  // The controls. A real duplicate OUTSIDE the scalar must still be reported,
  // and so must one in the mapping that owns the scalar — otherwise the fix
  // would be "stop looking" rather than "look at the structure".
  var realDup =
    "with:\n" +
    "  script: |\n" +
    "    owner: inside\n" +
    "  env: a\n" +
    "  env: b\n";
  check("#642 control: a duplicate beside the block scalar is still reported",
        dupsIn(realDup).length === 1 && /"env"/.test(dupsIn(realDup)[0]),
        JSON.stringify(dupsIn(realDup)));

  var afterScalar =
    "script: |\n" +
    "  owner: inside\n" +
    "top: 1\n" +
    "top: 2\n";
  check("#642 control: a duplicate after the scalar ends is still reported",
        dupsIn(afterScalar).length === 1 && /"top"/.test(dupsIn(afterScalar)[0]),
        JSON.stringify(dupsIn(afterScalar)));

  // And a quoted scalar carrying a colon is not a mapping entry either.
  check("#642: a colon inside a quoted value is not a second key",
        dupsIn("a: \"x: 1\"\nb: \"x: 2\"\n").length === 0,
        JSON.stringify(dupsIn("a: \"x: 1\"\nb: \"x: 2\"\n")));

  // Each item of a sequence is its OWN mapping, so the same key appearing once
  // per item is not a duplicate — it is the ordinary shape of every list of
  // records there is. The scope was keyed on indent alone and a sequence-item
  // line never reset it, so the second item's keys landed in the first item's
  // scope and the second occurrence of every key after the first read as a
  // duplicate.
  function dupKeys(src) {
    return b.guardYaml.validate(src, { profile: "strict" }).issues
      .filter(function (issue) { return issue.kind === "duplicate-key"; })
      .map(function (issue) { return issue.snippet; });
  }
  check("a sequence of two-key mappings is not a duplicate",
        dupKeys("steps:\n  - p: 1\n    q: 2\n  - p: 3\n    q: 4\n").length === 0,
        JSON.stringify(dupKeys("steps:\n  - p: 1\n    q: 2\n  - p: 3\n    q: 4\n")));
  check("nor is a sequence of three-key mappings",
        dupKeys("s:\n  - a: 1\n    b: 2\n    c: 3\n  - a: 4\n    b: 5\n    c: 6\n")
          .length === 0,
        JSON.stringify(dupKeys(
          "s:\n  - a: 1\n    b: 2\n    c: 3\n  - a: 4\n    b: 5\n    c: 6\n")));
  // The control the fix must not break: a key repeated WITHIN one item is a
  // real duplicate, and the reset must not swallow it. Without this the check
  // above is satisfied by never reporting anything at all.
  check("CONTROL — a key repeated inside ONE sequence item is still a duplicate",
        dupKeys("steps:\n  - p: 1\n    p: 2\n").length === 1,
        JSON.stringify(dupKeys("steps:\n  - p: 1\n    p: 2\n")));
  check("CONTROL — a duplicate in a plain mapping is still a duplicate",
        dupKeys("steps:\n  uses: a\n  uses: b\n").length === 1,
        JSON.stringify(dupKeys("steps:\n  uses: a\n  uses: b\n")));
  // The key written INLINE with the dash belongs to the item's mapping, so a
  // repeat of it is a duplicate too — that key was being skipped entirely.
  check("the key inline with the dash is tracked, so repeating it is caught",
        dupKeys("steps:\n  - p: 1\n    q: 2\n    p: 3\n").length === 1,
        JSON.stringify(dupKeys("steps:\n  - p: 1\n    q: 2\n    p: 3\n")));
  // An item may write NO key beside its dash, and that line then carries no
  // `key: value` at all. A reset that waited for one never ran for this layout,
  // so the same document was accepted written one way and refused written the
  // other. The boundary is the dash; where the first key sits is layout.
  check("a sequence whose items put no key beside the dash is not a duplicate",
        dupKeys("steps:\n  -\n    p: 1\n  -\n    p: 2\n").length === 0,
        JSON.stringify(dupKeys("steps:\n  -\n    p: 1\n  -\n    p: 2\n")));
  check("CONTROL — and a repeat WITHIN one such item is still caught",
        dupKeys("steps:\n  -\n    p: 1\n    p: 2\n").length === 1,
        JSON.stringify(dupKeys("steps:\n  -\n    p: 1\n    p: 2\n")));
  // A dash that is not a sequence indicator must not reset anything: `-quux`
  // and `-1` are scalars, and treating them as item boundaries would drop a
  // scope and hide a real duplicate.
  check("CONTROL — a leading dash that is part of a scalar is not an item " +
        "boundary",
        dupKeys("a: -1\np: 1\np: 2\n").length === 1,
        JSON.stringify(dupKeys("a: -1\np: 1\np: 2\n")));
  // An item's mapping is ONE mapping however its keys are laid out, so the
  // scope must not depend on how many spaces follow the dash. Keying on the raw
  // column filed `-   a: 1` (column 4) and the `a: 2` under it (column 2)
  // separately and reported no duplicate — and this is the smuggling shape the
  // detector exists for, since one parser reads two keys here and another reads
  // one.
  check("a key repeated across an item's lines is a duplicate whatever the " +
        "spacing after the dash",
        dupKeys("-   a: 1\n  a: 2\n").length === 1,
        JSON.stringify(dupKeys("-   a: 1\n  a: 2\n")));
  check("CONTROL — and a key reused in a mapping NESTED inside that item is " +
        "still not one",
        dupKeys("- a: 1\n  b:\n    a: 2\n").length === 0,
        JSON.stringify(dupKeys("- a: 1\n  b:\n    a: 2\n")));
  check("CONTROL — nor when the nesting hangs off the key beside the dash",
        dupKeys("- a:\n    x: 1\n    a: 2\n").length === 0,
        JSON.stringify(dupKeys("- a:\n    x: 1\n    a: 2\n")));
  check("CONTROL — nor with extra spacing and a nested reuse together",
        dupKeys("-   a: 1\n  b:\n    a: 2\n").length === 0,
        JSON.stringify(dupKeys("-   a: 1\n  b:\n    a: 2\n")));

  // Sequences NEST, so the item being tracked is a stack rather than a slot.
  // Holding only the innermost let a nested sequence take its parent's scope
  // and never give it back, so a key repeated in the OUTER item after the
  // nested one closed was filed elsewhere and went unreported.
  check("a key repeated in the outer item AFTER a nested sequence is still a " +
        "duplicate",
        dupKeys("- a: 1\n  inner:\n    - x: 1\n  a: 2\n").length === 1,
        JSON.stringify(dupKeys("- a: 1\n  inner:\n    - x: 1\n  a: 2\n")));
  check("and the same when the outer item writes no key beside its dash",
        dupKeys("-\n  a: 1\n  children:\n    - x: 1\n  a: 2\n").length === 1,
        JSON.stringify(dupKeys("-\n  a: 1\n  children:\n    - x: 1\n  a: 2\n")));
  check("CONTROL — a nested sequence with no outer repeat is still clean",
        dupKeys("- a: 1\n  inner:\n    - x: 1\n  b: 2\n").length === 0,
        JSON.stringify(dupKeys("- a: 1\n  inner:\n    - x: 1\n  b: 2\n")));
  check("CONTROL — two items of a NESTED sequence may each use the same key",
        dupKeys("- a: 1\n  inner:\n    - x: 1\n    - x: 2\n").length === 0,
        JSON.stringify(dupKeys("- a: 1\n  inner:\n    - x: 1\n    - x: 2\n")));
  check("CONTROL — a duplicate INSIDE one nested item is still caught",
        dupKeys("- a: 1\n  inner:\n    - x: 1\n      x: 2\n").length === 1,
        JSON.stringify(dupKeys("- a: 1\n  inner:\n    - x: 1\n      x: 2\n")));
}

// YAML's JSON compatibility lets a QUOTED key take its colon with no space
// after it, so the character in front of a sigil written that way is `:`. Every
// screen decided position by looking at that character, and so reported nothing
// for this form — including for a deserialization tag, which is the single most
// dangerous thing the tag screen exists to surface.
function testGuardYamlCompactFlowSigils() {
  function kinds(src) {
    return b.guardYaml.validate(src, { profile: "strict" }).issues
      .map(function (issue) { return issue.kind; });
  }
  check("a deserialization tag written in the compact flow form is reported",
        kinds('{"a":!!python/object x}').indexOf("dangerous-tag") !== -1,
        JSON.stringify(kinds('{"a":!!python/object x}')));
  check("a custom tag in the compact flow form is reported",
        kinds('{"a":!mytag x}').indexOf("custom-tag") !== -1,
        JSON.stringify(kinds('{"a":!mytag x}')));
  check("an anchor in the compact flow form is reported",
        kinds('{"a":&anch x}').indexOf("alias-disabled") !== -1,
        JSON.stringify(kinds('{"a":&anch x}')));
  check("an alias in the compact flow form is reported",
        kinds('{"a":*anch}').indexOf("alias-disabled") !== -1,
        JSON.stringify(kinds('{"a":*anch}')));
  // YAML permits separation between a JSON-style key and its adjacent value, so
  // the same shape with a space before the colon is equally valid — and one
  // space was enough to reopen the bypass while the unspaced form was closed.
  check("and with separation before the colon, which YAML also allows",
        kinds('{"a" :!!python/object x}').indexOf("dangerous-tag") !== -1,
        JSON.stringify(kinds('{"a" :!!python/object x}')));
  check("however much separation there is",
        kinds('{"a"  :&anch x}').indexOf("alias-disabled") !== -1,
        JSON.stringify(kinds('{"a"  :&anch x}')));
  // There are TWO kinds of JSON-like key, and both take an adjacent value: a
  // quoted scalar and a flow COLLECTION. Closing one production left the other
  // open, which is the same bypass reached by the other route.
  [
    ["a mapping key",           '{{a: b}:!!python/object x}'],
    ["a mapping key, spaced",   '{{a: b} :!!python/object x}'],
    ["a sequence key",          '{[a]:!!python/object x}'],
  ].forEach(function (pair) {
    check("a dangerous tag after " + pair[0] + " is reported",
          kinds(pair[1]).indexOf("dangerous-tag") !== -1,
          JSON.stringify(kinds(pair[1])));
  });
  check("and an anchor after a collection key is reported",
        kinds('{{a: b}:&anch x}').indexOf("alias-disabled") !== -1,
        JSON.stringify(kinds('{{a: b}:&anch x}')));
  check("CONTROL — an ordinary nested flow mapping is still reported as nothing",
        kinds("{a: {b: 1}, c: 2}").length === 0,
        JSON.stringify(kinds("{a: {b: 1}, c: 2}")));
  // CONTROLS. Dropping the preceding-character test is only safe because the
  // mask decides position, so the shapes it must still stay quiet about are
  // asserted in the same breath.
  [
    ["a bang in prose",            "x: hello !world\n"],
    ["a bang in a comment",        "x: 1 # note !bang\n"],
    ["an ampersand in prose",      "text: this &notanchor\n"],
    ["a bang in a quoted scalar",  'x: "hello !world"\n'],
    ["a bang in a block body",     "x: |\n  echo !boom\n"],
  ].forEach(function (pair) {
    check("CONTROL — " + pair[0] + " is still reported as nothing",
          kinds(pair[1]).length === 0, JSON.stringify(kinds(pair[1])));
  });
}

function testGuardYamlBidiNull() {
  var bidi = String.fromCharCode(0x202E);
  var rv = b.guardYaml.validate("name: a" + bidi + "b\n", { profile: "strict" });
  check("bidi override detected in YAML scalar",
        rv.issues.some(function (issue) { return issue.kind === "bidi-override"; }));

  var nb = String.fromCharCode(0);
  var rvNull = b.guardYaml.validate("name: a" + nb + "b\n", { profile: "strict" });
  check("null byte detected",
        rvNull.issues.some(function (issue) { return issue.kind === "null-byte"; }));
}

function testGuardYamlByteCap() {
  // "é" (U+00E9) is 1 UTF-16 code unit but 2 UTF-8 bytes. Five of them are
  // 5 code units / 10 bytes; with maxBytes:6 the cap must measure BYTES — a
  // .length compare would see 5 <= 6 and let a 10-byte input past a 6-byte cap.
  var multibyte = "é".repeat(5);
  var rvOver = b.guardYaml.validate(multibyte, { profile: "permissive", maxBytes: 6 });
  var capIssue = rvOver.issues.filter(function (issue) { return issue.kind === "too-large"; })[0];
  check("multibyte over byte cap → too-large fires (byte measure, not char)",
        !!capIssue);
  check("too-large snippet reports the byte length, not the char length",
        !!capIssue && capIssue.snippet === "input 10 bytes exceeds maxBytes 6");
  check("too-large carries ruleId yaml.too-large",
        !!capIssue && capIssue.ruleId === "yaml.too-large");

  // Same five code units fit under a byte cap that covers their 10 bytes.
  var rvUnder = b.guardYaml.validate(multibyte, { profile: "permissive", maxBytes: 16 });
  check("multibyte under byte cap → too-large does NOT fire",
        !rvUnder.issues.some(function (issue) { return issue.kind === "too-large"; }));

  // ASCII (1 byte == 1 code unit) is unaffected by the byte measure.
  var rvAscii = b.guardYaml.validate("aaaaaaaa", { profile: "permissive", maxBytes: 4 });
  check("ASCII over cap still fires with byte-count snippet",
        rvAscii.issues.some(function (issue) {
          return issue.kind === "too-large" &&
                 issue.snippet === "input 8 bytes exceeds maxBytes 4";
        }));

  // Non-string input is refused with the yaml.bad-input ruleId.
  var rvBad = b.guardYaml.validate(12345, { profile: "permissive" });
  check("non-string input → bad-input with ruleId yaml.bad-input",
        rvBad.issues.some(function (issue) {
          return issue.kind === "bad-input" && issue.ruleId === "yaml.bad-input";
        }));
}

function testGuardYamlClean() {
  var rv = b.guardYaml.validate("name: alice\nage: 30\ntags:\n  - one\n  - two\n",
                                { profile: "strict" });
  check("clean YAML → ok=true with no issues",
        rv.ok === true && rv.issues.length === 0);
}

function testGuardYamlParseStrictThrows() {
  var threw = null;
  try { b.guardYaml.parse("!!python/object/new:cls\nargs: [a]\n", { profile: "strict" }); }
  catch (e) { threw = e; }
  check("parse strict: throws on dangerous tag",
        threw && /dangerous-tag/.test(threw.code || threw.message || ""));
}

async function testGuardYamlGate() {
  var g = b.guardYaml.gate({ profile: "strict" });
  var clean = await g.check({
    contentType: "application/yaml",
    bytes:       Buffer.from("name: alice\n", "utf8"),
  });
  check("gate clean → action=serve",
        clean.ok === true && clean.action === "serve");

  var hostile = await g.check({
    contentType: "application/yaml",
    bytes:       Buffer.from("!!python/object/new:cls\nargs: [a]\n", "utf8"),
  });
  check("gate dangerous tag → action !== serve",
        hostile.action !== "serve");
}

// Each character class carries a policy per profile, and the gate's action has
// to be the one that policy names — `strip` repairs, `audit` records, `reject`
// refuses. Resolving the action from a finding's SEVERITY instead ignores the
// policy entirely and refuses every class, so an operator who configured
// `strip` gets their document rejected rather than cleaned.
//
// The carrier is a YAML scalar so the document still parses with the character
// removed; the guard therefore reports exactly the character finding, and the
// action under test is unambiguous.
async function testGuardYamlGateFollowsCharacterPolicy() {
  var CARRIER = { bidiPolicy: "\u202e", controlPolicy: "\u0001",
                  zeroWidthPolicy: "\u200b", nullBytePolicy: "\u0000" };
  var WANT = { reject: "refuse", strip: "sanitize", audit: "audit-only" };
  var probed = 0;
  var wrong = [];

  for (var profile of Object.keys(b.guardYaml.PROFILES)) {
    var policies = b.guardYaml.PROFILES[profile];
    for (var key of Object.keys(CARRIER)) {
      var declared = policies[key];
      if (!declared || !WANT[declared]) continue;
      var decision = await b.guardYaml.gate({ profile: profile }).check({
        contentType: "application/yaml",
        bytes: Buffer.from("key: va" + CARRIER[key] + "lue\n", "utf8"),
      });
      probed += 1;
      if (decision.action !== WANT[declared]) {
        wrong.push(profile + "." + key + "=" + declared +
                   " → " + decision.action + " (want " + WANT[declared] + ")");
      }
    }
  }

  check("guard-yaml: every character policy was reachable to probe",
        probed >= 8, "probed=" + probed);
  check("guard-yaml: the gate action follows the declared policy",
        wrong.length === 0, wrong.join("; "));
}

function testGuardYamlCompliancePosture() {
  var hipaa = b.guardYaml.compliancePosture("hipaa");
  check("compliancePosture('hipaa') sets reject policies",
        hipaa.tagPolicy === "reject" &&
        hipaa.aliasPolicy === "reject");
  var threw = null;
  try { b.guardYaml.compliancePosture("unknown"); }
  catch (e) { threw = e; }
  check("compliancePosture: unknown name throws",
        threw && /unknown/.test(threw.message));
}

function testGuardYamlBadProfile() {
  var threw = null;
  try { b.guardYaml.validate("a: 1\n", { profile: "made-up" }); }
  catch (e) { threw = e; }
  check("validate: unknown profile throws",
        threw && /unknown profile/i.test(threw.message));
}

// The anchor, alias, Norway-token, leading-zero and merge-key screens are
// character walks. Each is compared against the pattern it replaced, over a
// corpus of the documents this guard exists to classify.
function testYamlScreensAgreeWithThePatternsTheyReplaced() {
  var ANCHOR_DECL_RE = /(^|\s|:|-)(&[A-Za-z_][A-Za-z0-9_-]*)/g;
  var ALIAS_REF_RE   = /(^|\s|:|-|\[|\{|,)(\*[A-Za-z_][A-Za-z0-9_-]*)/g;
  var NORWAY_BOOL_QUIRK_RE = /:\s*(no|yes|y|n|on|off)\b/gi;
  var LEADING_ZERO_OCTAL_RE = /:\s*0\d+\b/;
  var MERGE_KEY_RE = /<<\s*:\s*\*/;

  var DOCS = [
    "", "a: 1", "a: &anchor 1\nb: *anchor",
    "a: &x 1\nb: &y 2\nc: *x\nd: *y",
    "list: [*a, *b]", "map: {k: *a}", "x: -&a", "x:&a", "a&b: 1",
    "text: this &notanchor", "t: a*b", "s: '*star'",
    "country: no", "country: NO", "country: nope", "flag: yes", "flag: y",
    "flag: on", "flag: off", "v: n", "v: none", "v: nyet",
    "mode: 0777", "mode: 0", "mode: 00", "mode: 0x1f", "mode: 012abc",
    "v: 0777\nw: 1", "url: http://x", "time: 12:30:00",
    "defaults: &d\n  a: 1\nuse:\n  <<: *d",
    "use:\n  << : *d", "use:\n  <<:*d", "use:\n  <<  :  *d", "no merge here",
    "---\na: 1\n---\nb: 2", "--- \nx: 1", "a: 1\n---\nb: 2", "---",
    "--- ", "\n--- x", "a: 1\n--- ",
    // An empty first document is the cheapest multi-document stream to write,
    // and its first separator sits at index 1 rather than at index 0.
    "\n--- \na: 1", "\n---\na: 1\n---\nb: 2", "\r\n--- \na: 1",
  ];

  var diffs = [];
  DOCS.forEach(function (doc) {
    var kinds = b.guardYaml.validate(doc, { profile: "strict" }).issues
      .map(function (i) { return i.kind; });
    function has(k) { return kinds.indexOf(k) !== -1; }
    function compare(label, expected, actual) {
      if (expected !== actual) {
        diffs.push(label + " " + JSON.stringify(doc) + " kinds=" + JSON.stringify(kinds));
      }
    }
    var anchors = (doc.match(ANCHOR_DECL_RE) || []).length;
    var aliases = (doc.match(ALIAS_REF_RE) || []).length;
    // The anchor/alias screen is deliberately NO LONGER the pattern's equal, and
    // these are the documents where they part company. In each one the pattern
    // matched a sigil sitting inside a plain scalar, where it declares nothing:
    // an anchor and an alias are separate tokens, so `&` and `*` in the middle
    // of a value are ordinary characters. The pattern could not tell, because it
    // looked only at the character before.
    //
    // This is not a relaxed guard. The screen exists to stop alias
    // AMPLIFICATION, which needs a real anchor to bind a name and a real alias
    // to expand it; a sigil inside a scalar binds nothing, so no expansion can
    // reach it. And `use:\n  <<:*d` is still refused — the merge-key screen
    // catches it, as the comparison below asserts.
    //
    // Each entry is named rather than counted, so adding one is a decision
    // somebody has to write down.
    var PLAIN_SCALAR_SIGILS = {
      "x: -&a":                1,   // the value is the plain scalar `-&a`
      "x:&a":                  1,   // a colon needs a space to separate a key
      "text: this &notanchor": 1,   // prose, and the reason operators hit this
      "use:\n  <<:*d":         1,   // scalar `<<:*d`; merge-key still refuses it
    };
    if (!Object.prototype.hasOwnProperty.call(PLAIN_SCALAR_SIGILS, doc)) {
      compare("alias", anchors > 0 || aliases > 0, has("alias-disabled"));
    } else {
      compare("alias(plain-scalar sigil)", false, has("alias-disabled"));
    }
    NORWAY_BOOL_QUIRK_RE.lastIndex = 0;
    compare("norway", NORWAY_BOOL_QUIRK_RE.test(doc), has("norway-implicit-bool"));
    compare("octal", LEADING_ZERO_OCTAL_RE.test(doc), has("leading-zero-octal"));
    compare("merge-key", MERGE_KEY_RE.test(doc), has("merge-key"));
    // Under strict, multiDocPolicy is reject, so the finding appears whenever
    // the scan counted at least one separator.
    compare("multi-document", (doc.match(/(^|\n)---\s/g) || []).length > 0,
            has("multi-document"));
  });
  check("every YAML screen agrees with the pattern it replaced (" +
        DOCS.length + " documents)", diffs.length === 0,
        diffs.slice(0, 4).join(" | "));

  // The exception list above says four documents should NOT be flagged. On its
  // own that is satisfied by a screen which flags nothing at all, so the real
  // constructs are asserted here in the same breath. A declaration and a
  // reference, in each of the positions they are actually written.
  function flags(doc) {
    return b.guardYaml.validate(doc, { profile: "strict" }).issues
      .some(function (i) { return i.kind === "alias-disabled"; });
  }
  [
    ["an anchor declaration",        "a: &x 1\n"],
    ["an alias reference",           "b: *x\n"],
    ["an alias inside a flow seq",   "list: [*a, *b]\n"],
    ["an alias inside a flow map",   "map: {k: *a}\n"],
    ["an anchor on a sequence item", "s:\n  - &x 1\n"],
    ["a merge key's alias",          "use:\n  <<: *d\n"],
  ].forEach(function (pair) {
    check("the anchor/alias screen still catches " + pair[0],
          flags(pair[1]), JSON.stringify(pair[1]));
  });
  // And the document the exception list excuses is still REFUSED, by the screen
  // that owns it — the sigil is not an alias, but the merge key is a merge key.
  check("a merge key written without spaces is still refused, by the merge-key " +
        "screen rather than the alias one",
        b.guardYaml.validate("use:\n  <<:*d", { profile: "strict" }).issues
          .some(function (i) { return i.kind === "merge-key"; }),
        "");
}

// Every policy is a config-time entry point, so a value outside its vocabulary
// belongs at boot rather than at the first hostile document. Read leniently, a
// typo takes whichever branch is not the strict one: `aliasPolicy: "rejct"` is
// not "allow", so the check runs, and it is not "reject" either, so a
// billion-laughs alias chain drops to a warning.
//
// `audit-only` is not in the vocabulary here, unlike most of the family:
// tagPolicy tests for "audit" exactly, and the synonym would fall past both
// branches.
function testPolicyVocabularyIsEnforced() {
  var LEGAL = {
    tagPolicy:          ["reject", "audit", "allow"],
    aliasPolicy:        ["reject", "audit", "allow"],
    multiDocPolicy:     ["reject", "audit", "allow"],
    norwayPolicy:       ["reject", "audit", "allow"],
    leadingZeroPolicy:  ["reject", "audit", "allow"],
    duplicateKeyPolicy: ["reject", "audit", "allow"],
    mergeKeyPolicy:     ["reject", "audit", "allow"],
  };
  helpers.assertPolicyVocabulary(b.guardYaml, LEGAL, { label: "yaml", sample: "a: 1\n" });

  // `parse` binds its own resolver rather than the generated one, so it is its
  // own door and has to refuse the same values.
  var parseRefused = false;
  try { b.guardYaml.parse("a: 1\n", { aliasPolicy: "definitely-not-a-policy-value" }); }
  catch (_e) { parseRefused = true; }
  check("yaml: parse refuses a policy value outside the vocabulary too", parseRefused);
}

async function run() {
  testPolicyVocabularyIsEnforced();
  testYamlScreensAgreeWithThePatternsTheyReplaced();
  testGuardYamlSurface();
  testGuardYamlRegistryParity();
  testGuardYamlDangerousTags();
  testGuardYamlCustomTag();
  testGuardYamlAlias();
  testGuardYamlAliasExplosion();
  testGuardYamlMultiDoc();
  testGuardYamlNorwayProblem();
  testGuardYamlLeadingZeroOctal();
  testGuardYamlMergeKey();
  testGuardYamlDuplicateKeys();
  testGuardYamlCompactFlowSigils();
  testGuardYamlBidiNull();
  testGuardYamlByteCap();
  testGuardYamlClean();
  testGuardYamlParseStrictThrows();
  testGuardYamlCompliancePosture();
  testGuardYamlBadProfile();
  await testGuardYamlGate();
  await testGuardYamlGateFollowsCharacterPolicy();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[guard-yaml] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
