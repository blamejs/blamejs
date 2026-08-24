// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * yaml-lex — the shared answer to "which region of a YAML document is this
 * character in".
 *
 * Two modules used to answer it separately and disagree. `guard-yaml` decided
 * a `!` opened a tag when it followed whitespace, so it reported one inside a
 * quoted scalar, a block-scalar body and a comment; `parsers/safe-yaml` masked
 * quoted scalars but copied comment text through verbatim and had no
 * block-scalar handling, despite its own note promising both. Between them,
 * ordinary documents carrying an exclamation mark in prose were refused.
 *
 * The mask is checked on three properties, because a failure of any one of
 * them is silent:
 *
 *   1. It is the SAME LENGTH as its source, so a location reported against the
 *      mask is a location in the source. A mask that is a character short does
 *      not report nothing, it reports the wrong place confidently.
 *   2. A sigil survives it exactly where the sigil is real.
 *   3. Structure the callers still need — directives, document markers — is
 *      never masked away.
 */

var helpers = require("../helpers");
var check   = helpers.check;

var yamlLex = require("../../lib/yaml-lex");

// Which indices still carry `ch` after masking. This is the question both
// callers ask, so it is the question the tests ask.
function survivorsOf(src, ch) {
  var masked = yamlLex.maskNonStructural(src);
  var at = [];
  for (var i = 0; i < masked.length; i += 1) {
    if (masked.charAt(i) === ch) at.push(i);
  }
  return at;
}

function masksAway(src, ch) { return survivorsOf(src, ch).length === 0; }

function testMaskIsIndexAlignedWithItsSource() {
  // Every document below, whatever else it exercises, must come back the same
  // length. Callers index into the mask and report against the source.
  var DOCS = [
    "", "a: 1", "x: hello !world\n", 'x: "q"\n', "x: |\n  body\n",
    "x: 1 # c\n", "%YAML 1.2\n---\nx: 1\n", "x: 1\r\ny: 2\r\n",
    "a:\n  - b: 1\n    c: 2\n", "x: {a: 1, b: [2, 3]}\n",
    "x: \"unterminated\n", "\ttabbed: 1\n", "x: 'a''b'\n",
    "x: \"a\\\"b\"\n", "- - nested\n", "? key\n: value\n",
  ];
  var bad = [];
  DOCS.forEach(function (doc) {
    var m = yamlLex.maskNonStructural(doc);
    if (m.length !== doc.length) {
      bad.push(JSON.stringify(doc) + " -> " + m.length + " vs " + doc.length);
    }
  });
  check("the mask is always the same length as its source (" + DOCS.length +
        " documents)", bad.length === 0, bad.join(" | "));

  // A CRLF document is the one that used to lose a character per line, because
  // the line splitter strips the carriage return and rejoining puts back only
  // the newline. Every index after the first line then points one place early.
  var crlf = "x: 1\r\ny: !t 2\r\n";
  var m = yamlLex.maskNonStructural(crlf);
  check("a CRLF document keeps its carriage returns",
        m.length === crlf.length && m.indexOf("\r\n") !== -1, JSON.stringify(m));
  check("and a tag on its SECOND line is still found at the source's index",
        crlf.charAt(survivorsOf(crlf, "!")[0]) === "!",
        JSON.stringify(survivorsOf(crlf, "!")));
}

function testASigilSurvivesOnlyWhereItIsReal() {
  // Kept: the sigil is a node property, which is the only place it means what
  // it looks like.
  [
    ["a tag at a node start",          "x: !mytag 1\n"],
    ["a tag after an anchor",          "x: &a !t v\n"],
    ["a tag inside a flow mapping",    "x: { a: !t 1 }\n"],
    ["a tag on a sequence item",       "s:\n  - !t v\n"],
    ["a tag at the document root",     "!t\n"],
  ].forEach(function (pair) {
    check("kept: " + pair[0], survivorsOf(pair[1], "!").length === 1,
          JSON.stringify(yamlLex.maskNonStructural(pair[1])));
  });

  // Masked: every position a `!` can sit where it introduces nothing. Each of
  // these was a refusal an operator actually hit.
  [
    ["inside a double-quoted scalar", 'x: "hello !world"\n'],
    ["inside a single-quoted scalar", "x: 'hello !world'\n"],
    ["inside a block-scalar body",    "x: |\n  echo !boom\n"],
    ["inside a block scalar whose header carries indicators", "x: |2-\n   echo !boom\n"],
    ["in the middle of a plain scalar", "x: hello !world\n"],
    ["inside a comment",              "x: 1 # note !bang\n"],
    ["inside a key",                  "a!b: 1\n"],
    ["on the continuation of a multi-line quoted scalar", "x: \"hello\n  !world\"\n"],
    ["inside an unterminated quoted scalar", "x: \"never closes !no\n"],
  ].forEach(function (pair) {
    check("masked: a bang " + pair[0], masksAway(pair[1], "!"),
          JSON.stringify(yamlLex.maskNonStructural(pair[1])));
  });

  // A block scalar inside an inline sequence entry ends at the ENTRY's indent,
  // not the dash's. Measuring it from the dash swallows the entry's sibling
  // keys into the body — and that failure is the dangerous direction: it does
  // not refuse a good document, it hides a real tag inside a bad one and hands
  // both screens something they then call clean.
  var siblingAfterBlock = "- key: |\n    body\n  evil: !tag x\n";
  check("a block scalar in an inline sequence entry does not swallow its " +
        "sibling key, so a tag after it is still seen",
        survivorsOf(siblingAfterBlock, "!").length === 1,
        JSON.stringify(yamlLex.maskNonStructural(siblingAfterBlock)));
  check("CONTROL — the block's own body is still masked",
        yamlLex.maskNonStructural("- key: |\n    body !no\n  evil: 1\n")
          .indexOf("!") === -1,
        JSON.stringify(yamlLex.maskNonStructural(
          "- key: |\n    body !no\n  evil: 1\n")));
  check("CONTROL — an ordinary block scalar body is still masked",
        masksAway("x: |\n  body !no\ny: 1\n", "!"), "");

  // The mirror case, and it goes the other way. When the block scalar IS the
  // item's node (`- |` with no key between), its body starts in the same column
  // the `|` sits in, so measuring from that column masks nothing at all and the
  // scalar's own text reads as a tag. The block belongs to the ITEM there, so
  // the dash bounds it.
  [
    ["a bare block scalar after a dash",        "- |\n  !hello\n"],
    ["the same, indented",                      "  - |\n    !hello\n"],
    ["a folded one",                            "- >\n  !folded\n"],
  ].forEach(function (pair) {
    check("masked: " + pair[0] + " keeps its body content",
          masksAway(pair[1], "!"),
          JSON.stringify(yamlLex.maskNonStructural(pair[1])));
  });
  check("CONTROL — the NEXT sequence item after a bare block is structure again",
        survivorsOf("- |\n  body\n- !tag v\n", "!").length === 1,
        JSON.stringify(yamlLex.maskNonStructural("- |\n  body\n- !tag v\n")));

  // What follows a continued quoted scalar's CLOSING quote is structure again.
  // Blanking the rest of that line was the tidy-looking simplification, and it
  // failed in the dangerous direction: the comma and the tag after the scalar
  // belong to the collection, so masking them hid a real tag.
  var flowAcrossLines = "x: [\"first\n second\", !tag value]\n";
  check("a tag after a continued quoted scalar closes on the same line survives",
        survivorsOf(flowAcrossLines, "!").length === 1,
        JSON.stringify(yamlLex.maskNonStructural(flowAcrossLines)));
  check("CONTROL — the continued scalar's own body is still masked",
        yamlLex.maskNonStructural("x: [\"first\n !no\", ok]\n").indexOf("!") === -1,
        JSON.stringify(yamlLex.maskNonStructural("x: [\"first\n !no\", ok]\n")));

  // A plain scalar spans lines too — that is how a long description gets
  // written without quotes — and its continuation is content. This is the
  // fourth form a scalar takes, and the last one; with quoted, block, plain
  // single-line and plain multi-line all handled, the taxonomy is closed.
  check("masked: a bang on the continuation of a multi-line plain scalar",
        masksAway("x: hello\n  !world\ny: 1\n", "!"),
        JSON.stringify(yamlLex.maskNonStructural("x: hello\n  !world\ny: 1\n")));
  // A plain scalar continues inside a FLOW collection too, and there the
  // continuation line may still close the collection. So the line is scanned
  // rather than blanked: the scalar is masked and the `]` that ends the
  // sequence survives, as does a tag after the comma that ends the scalar.
  check("masked: a bang continuing a plain scalar inside a flow sequence",
        masksAway("x: [hello\n  !world]\ny: 1\n", "!"),
        JSON.stringify(yamlLex.maskNonStructural("x: [hello\n  !world]\ny: 1\n")));
  check("and the bracket closing that sequence still survives",
        yamlLex.maskNonStructural("x: [hello\n  !world]\ny: 1\n").indexOf("]") !== -1,
        "");
  check("CONTROL — a tag after the comma that ends the continuation survives",
        survivorsOf("x: [hello\n  !no, !yes v]\n", "!").length === 1,
        JSON.stringify(yamlLex.maskNonStructural("x: [hello\n  !no, !yes v]\n")));
  check("a continuation running over several lines stays content throughout",
        survivorsOf("x: a\n  b\n  !c\nz: !real 1\n", "!").length === 1,
        JSON.stringify(yamlLex.maskNonStructural("x: a\n  b\n  !c\nz: !real 1\n")));

  // The controls that keep this from swallowing structure. Over-masking is the
  // dangerous direction, so each shape that is NOT a continuation is asserted.
  [
    ["a sibling key after a value line",      "x: hello\ny: !tag 1\n"],
    ["a nested mapping under a bare key",     "x:\n  y: !tag 1\n"],
    ["a sequence under a bare key",           "x:\n  - !tag v\n"],
    ["a tag after a continuation has ended",  "x: hello\n  !world\nz: !real 1\n"],
  ].forEach(function (pair) {
    check("CONTROL — " + pair[0] + " is still structure",
          survivorsOf(pair[1], "!").length === 1,
          JSON.stringify(yamlLex.maskNonStructural(pair[1])));
  });

  // The same rule governs anchors and aliases, and it has to, or the fix lands
  // on one sigil and leaves its two siblings reporting prose as structure.
  check("masked: an ampersand in prose is not an anchor",
        masksAway("text: this &notanchor\n", "&"),
        JSON.stringify(yamlLex.maskNonStructural("text: this &notanchor\n")));
  check("kept: a real anchor is still an anchor",
        survivorsOf("a: &x 1\n", "&").length === 1, "");
  check("masked: a star inside a scalar is not an alias",
        masksAway("t: a*b\n", "*"), "");
  check("kept: a real alias is still an alias",
        survivorsOf("b: *x\n", "*").length === 1, "");
  check("masked: a star inside a quoted scalar is not an alias",
        masksAway("s: '*star'\n", "*"), "");
}

function testStructureTheCallersStillNeedIsNeverMasked() {
  // A directive is only a directive at column zero, and a caller that has
  // stopped being able to see one has stopped refusing it.
  var directive = "%YAML 1.2\n---\nx: 1\n";
  var dm = yamlLex.maskNonStructural(directive);
  check("a directive line survives the mask",
        dm.indexOf("%YAML") === 0, JSON.stringify(dm));
  check("and so does the document marker after it",
        dm.indexOf("---") !== -1, JSON.stringify(dm));

  var multi = "---\na: 1\n---\nb: 2\n";
  var mm = yamlLex.maskNonStructural(multi);
  var seps = mm.split("---").length - 1;
  check("both separators of a multi-document stream survive", seps === 2,
        JSON.stringify(mm));

  // A marker or directive line may carry a comment, and passing the line
  // through whole to keep its structure kept the comment's text with it — so
  // the one branch that skipped the scan put the false positive back.
  [
    ["a document marker",  "--- # note !bang\nx: 1\n"],
    ["a directive",        "%YAML 1.2 # note !bang\n---\nx: 1\n"],
    ["an end-of-document", "x: 1\n... # note !bang\n"],
  ].forEach(function (pair) {
    check("a comment after " + pair[0] + " is masked like any other",
          masksAway(pair[1], "!"),
          JSON.stringify(yamlLex.maskNonStructural(pair[1])));
  });
  check("and the marker it follows still survives",
        yamlLex.maskNonStructural("--- # note !bang\nx: 1\n").indexOf("---") === 0,
        JSON.stringify(yamlLex.maskNonStructural("--- # note !bang\nx: 1\n")));
  check("and the directive it follows still survives",
        yamlLex.maskNonStructural("%YAML 1.2 # c\n---\nx: 1\n").indexOf("%YAML 1.2") === 0,
        "");

  // A directive-looking line INSIDE a quoted scalar is content, not structure,
  // and this is the case that needs the carried quote state to get right.
  var quotedPercent = "x: \"line\n%YAML 1.2\n\"\ny: 1\n";
  var qm = yamlLex.maskNonStructural(quotedPercent);
  check("a %YAML inside a multi-line quoted scalar is NOT left as a directive",
        qm.indexOf("%YAML") === -1, JSON.stringify(qm));
}

function run() {
  testMaskIsIndexAlignedWithItsSource();
  testASigilSurvivesOnlyWhereItIsReal();
  testStructureTheCallersStillNeedIsNeverMasked();
}

module.exports = { run: run };

if (require.main === module) {
  try {
    run();
    console.log("[yaml-lex] OK — " + helpers.getChecks() + " checks passed");
  } catch (e) {
    console.error("FAIL:", (e && e.stack) || e);
    process.exit(1);
  }
}
