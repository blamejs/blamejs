// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
//
// Remove the comments in lib/ that a reader cannot check against the code,
// keeping the ones something READS.
//
//   node scripts/strip-lib-comments.js --dry-run [--file <rel>] [--diff <rel>]
//   node scripts/strip-lib-comments.js --apply
//
// Comment boundaries come from the shared lexer (`commentRanges`), never a
// regex: `//` appears inside strings, regex literals and template
// interpolations throughout this tree.
//
// `isKept` is exported because the GATE that refuses a narrative comment has to
// answer the question the same way this script does. Two classifiers drift, and
// the one that drifts is whichever is not the one the tree was last swept with.
"use strict";

var fs   = require("node:fs");
var path = require("node:path");

var REPO = path.resolve(__dirname, "..");
var sm   = require(path.join(REPO, "test", "helpers", "_shape-match.js"));

// ---- what is KEPT ---------------------------------------------------------
//
// Each of these is read by something. Nothing else in a comment is.

// The licence header every file carries.
var HEADER_RE = /SPDX-License-Identifier|Copyright \(c\)/;

// A tag at the start of a line inside a block: `@module`, `@primitive`,
// `@param`, `@example`. The wiki extracts `/\/\*\*([\s\S]*?)\*\//g` and a
// primitive's page IS its block, so a tagged block is content, not narrative.
// Anchored at line start so an email address or an `@` inside prose does not
// count.
var JSDOC_TAG_RE = /^[ \t]*\*?[ \t]*@[a-zA-Z]/m;

// Suppression markers the gates and tooling read. The rule is the PREFIX:
// there are 33 allow classes and a list would go stale on the next one.
var MARKER_RE = /\ballow:[a-z0-9-]|codebase-patterns:allow-file|eslint-disable|c8 ignore|istanbul ignore|@ts-|prettier-ignore/;

// A comment that is the WHOLE body of a block. `catch (_e) { /* best-effort */ }`
// is the shape: the comment is the only thing between the braces, and taking it
// out leaves `catch (_e) { }` -- which the `silent-catch-stream-teardown` gate
// scans for and refuses, because an empty catch with no explanation is a
// swallow. That comment is read, by a gate, and by anyone asking why the block
// is empty; it is not narrative about something that no longer exists.
// A block's body can be SEVERAL comments, not one, and each of them is then
// the reason the block is empty. Walking out from one has to step over its
// neighbours as well as the whitespace between them: checking only whitespace
// kept a single-comment body and dropped both halves of a two-comment one,
// which left four `if` blocks in lib/ genuinely empty and eslint's `no-empty`
// naming every one.
function _isSoleBlockBody(src, range, ranges, index) {
  var b = range.start - 1;
  var i = index - 1;
  for (;;) {
    while (b >= 0 && /\s/.test(src.charAt(b))) b -= 1;
    if (i >= 0 && ranges[i].end === b + 1) { b = ranges[i].start - 1; i -= 1; continue; }
    break;
  }
  if (src.charAt(b) !== "{") return false;
  var a = range.end;
  var j = index + 1;
  for (;;) {
    while (a < src.length && /\s/.test(src.charAt(a))) a += 1;
    if (j < ranges.length && ranges[j].start === a) { a = ranges[j].end; j += 1; continue; }
    break;
  }
  return src.charAt(a) === "}";
}

// The comment that justifies a `lazyRequire`. The project's own convention is
// "top-of-file require(), except where a documented circular-load reason forces
// lazy-load" -- so the note IS the documentation that rule asks for, and a
// reader can check it by opening the module named in it and finding the require
// that closes the cycle. Removing it leaves a lazyRequire with no stated reason
// and merges two require sub-blocks whose `=` columns the alignment gate reads
// separately.
function _justifiesALazyRequire(src, range, ranges, index) {
  var a = range.end;
  var j = index + 1;
  for (;;) {
    while (a < src.length && /\s/.test(src.charAt(a))) a += 1;
    if (j < ranges.length && ranges[j].start === a) { a = ranges[j].end; j += 1; continue; }
    break;
  }
  // A comment can introduce the whole lazy-require GROUP rather than the one
  // line under it -- in lib/crypto.js it sits above `var lazyRequire =
  // require("./lazy-require")` and explains the three `lazyRequire(...)` lines
  // that follow. Looking only at the next line dropped it, which merged two
  // require sub-blocks and left their `=` columns disagreeing.
  var tail = src.slice(a, a + 400);
  var lines = tail.split("\n").slice(0, 4);
  for (var k = 0; k < lines.length; k += 1) {
    if (/lazyRequire\s*\(/.test(lines[k])) return true;
    if (lines[k].trim() !== "" && !/^\s*var\s+[\w${}\s,]+=\s*(?:require|lazyRequire)\s*\(/.test(lines[k])) return false;
  }
  return false;
}

// "drop-silent -- by design" and its neighbours. The three-tier validation rule
// asks a hot-path observability sink to SAY it drops silently, so the note is
// the mark that rule requires and not a story about how the code got here.
var DISCIPLINE_RE = /drop-silent|drop silent/i;

function isKept(text, src, range, ranges, index) {
  if (HEADER_RE.test(text)) return "header";
  if (MARKER_RE.test(text)) return "marker";
  if (DISCIPLINE_RE.test(text)) return "marker";
  if (text.indexOf("/**") === 0 && JSDOC_TAG_RE.test(text)) return "jsdoc-tagged";
  if (src && _isSoleBlockBody(src, range, ranges, index)) return "empty-block";
  if (src && _justifiesALazyRequire(src, range, ranges, index)) return "lazy-require";
  return null;
}

// ---- excision -------------------------------------------------------------

function stripFile(src) {
  var ranges = sm.commentRanges(src);
  var drop = [];
  var kept = { header: 0, marker: 0, "jsdoc-tagged": 0, "empty-block": 0, "lazy-require": 0 };
  for (var i = 0; i < ranges.length; i += 1) {
    var text = src.slice(ranges[i].start, ranges[i].end);
    var why  = isKept(text, src, ranges[i], ranges, i);
    if (why) { kept[why] += 1; continue; }
    drop.push(ranges[i]);
  }
  if (drop.length === 0) return { out: src, removed: 0, kept: kept };

  // Excise, then drop a line only if it HAD content and now has none -- a
  // comment on its own line leaves an empty line behind, and a file gaining
  // hundreds of blank lines is a different kind of noise. A line that was
  // already blank stays blank: the paragraph breaks in real code are not this
  // script's to remove.
  var out = "", prev = 0;
  var blanked = [];            // line numbers whose only content was a comment
  for (var d = 0; d < drop.length; d += 1) {
    out += src.slice(prev, drop[d].start);
    prev = drop[d].end;
  }
  out += src.slice(prev);

  var srcLines = src.split("\n");
  var outLines = out.split("\n");
  // The excision preserves newlines OUTSIDE comments; a block comment's own
  // newlines are removed with it, so line numbers shift and the two arrays
  // cannot be compared by index. Walk the output and drop a line that is
  // whitespace-only where the corresponding source region held a comment.
  var result = [];
  for (var li = 0; li < outLines.length; li += 1) {
    if (outLines[li].trim() === "") {
      // Was this line blank because a comment was taken off it? A line that is
      // blank in the OUTPUT and whose source counterpart was blank too is a
      // real paragraph break; one that held only a comment is not.
      blanked.push(li);
    }
    result.push(outLines[li]);
  }
  void srcLines; void result;

  // Simpler and exact: re-walk the source line-wise, deciding per line.
  return { out: _rebuild(src, drop), removed: drop.length, kept: kept };
}

// Rebuild by walking the source once, tracking which characters are inside a
// dropped range. A line whose every non-dropped character is whitespace, and
// which had at least one dropped character, disappears entirely.
function _rebuild(src, drop) {
  var dropped = new Uint8Array(src.length);
  for (var d = 0; d < drop.length; d += 1) {
    for (var p = drop[d].start; p < drop[d].end && p < src.length; p += 1) dropped[p] = 1;
  }
  var out = [];
  var lineStart = 0;
  // A blank line on each side of a removed block leaves the two adjacent, and
  // the pair reads as a paragraph break nobody wrote. Collapsed -- but only
  // where the strip CREATED the adjacency: 28 files in lib/ carry a run of two
  // or three blank lines of their own, and rewriting those would be a change
  // made for a reason unrelated to comments, in files whose diff nobody would
  // then be reading for it.
  var droppedSinceEmit = false;
  for (var i = 0; i <= src.length; i += 1) {
    if (i !== src.length && src.charAt(i) !== "\n") continue;
    var keptText = "";
    var hadDrop  = false;
    var inDrop   = false;
    for (var c = lineStart; c < i; c += 1) {
      if (dropped[c]) { hadDrop = true; inDrop = true; continue; }
      // A block comment can SEPARATE two tokens -- `foo/* note */bar`, or
      // `a +/* note */+b` -- and deleting it outright fuses them into `foobar`
      // and `a ++b`, which are different programs. One space where the two
      // sides would otherwise touch restores the boundary; where either side
      // is already whitespace nothing is inserted, so a `f(/* x */a)` stays
      // `f(a)`.
      if (inDrop) {
        inDrop = false;
        if (sm.wouldFuse(keptText.charAt(keptText.length - 1), src.charAt(c))) keptText += " ";
      }
      keptText += src.charAt(c);
    }
    lineStart = i + 1;
    // A line that lost a comment and has nothing else left goes away. A line
    // that never had one is emitted exactly as it was, blank or not.
    if (hadDrop && keptText.trim() === "") { droppedSinceEmit = true; continue; }
    var text = hadDrop ? keptText.replace(/[ \t]+$/, "") : keptText;
    if (text.trim() === "" && droppedSinceEmit &&
        out.length > 0 && out[out.length - 1].trim() === "") {
      continue;
    }
    out.push(text);
    droppedSinceEmit = false;
  }
  return out.join("\n");
}

// Every comment in `src` this script would remove, as
// `{ start, end, line, text }`. The gate walks this; the stripper excises it.
function narrativeComments(src) {
  var ranges = sm.commentRanges(src);
  var out = [];
  for (var i = 0; i < ranges.length; i += 1) {
    var text = src.slice(ranges[i].start, ranges[i].end);
    if (isKept(text, src, ranges[i], ranges, i)) continue;
    out.push({
      start: ranges[i].start,
      end:   ranges[i].end,
      line:  src.slice(0, ranges[i].start).split("\n").length,
      text:  text,
    });
  }
  return out;
}

module.exports = {
  isKept:             isKept,
  narrativeComments:  narrativeComments,
  stripFile:          stripFile,
};

// ---- driver ---------------------------------------------------------------

function libFiles(dir, acc) {
  acc = acc || [];
  fs.readdirSync(dir, { withFileTypes: true }).forEach(function (e) {
    var full = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (e.name === "vendor" || e.name === "node_modules") return;
      libFiles(full, acc);
      return;
    }
    if (/\.js$/.test(e.name)) acc.push(full);
  });
  return acc;
}

module.exports.libFiles = libFiles;
module.exports.REPO = REPO;

// Required by the gate for `isKept`; run directly to sweep or to report.
if (require.main !== module) return;

var args   = process.argv.slice(2);
var apply  = args.indexOf("--apply") !== -1;
var dryRun = args.indexOf("--dry-run") !== -1;
var only   = args.indexOf("--file") !== -1 ? args[args.indexOf("--file") + 1] : null;
var diffOf = args.indexOf("--diff") !== -1 ? args[args.indexOf("--diff") + 1] : null;

// One of the two is required. A bare invocation that silently reported instead
// of writing, or wrote instead of reporting, is the kind of ambiguity a tool
// that rewrites 561 files should not have.
if (apply === dryRun) {
  console.error("usage: node scripts/strip-lib-comments.js --dry-run|--apply " +
                "[--file <rel>] [--diff <rel>]");
  process.exit(2);
}

var files = libFiles(path.join(REPO, "lib"));
if (only) files = files.filter(function (f) { return path.relative(REPO, f).replace(/\\/g, "/") === only; });

var totals = { files: 0, touched: 0, removed: 0, header: 0, marker: 0, "jsdoc-tagged": 0,
               "empty-block": 0, "lazy-require": 0, linesBefore: 0, linesAfter: 0 };
var perFile = [];

files.forEach(function (f) {
  var rel = path.relative(REPO, f).replace(/\\/g, "/");
  var src = fs.readFileSync(f, "utf8");
  var r   = stripFile(src);
  totals.files += 1;
  totals.removed += r.removed;
  totals.header += r.kept.header;
  totals.marker += r.kept.marker;
  totals["jsdoc-tagged"] += r.kept["jsdoc-tagged"];
  totals["empty-block"]  += r.kept["empty-block"];
  totals["lazy-require"] += r.kept["lazy-require"];
  totals.linesBefore += src.split("\n").length;
  totals.linesAfter  += r.out.split("\n").length;
  if (r.removed > 0) {
    totals.touched += 1;
    perFile.push({ rel: rel, removed: r.removed });
  }
  if (diffOf && rel === diffOf) {
    fs.writeFileSync(path.join(REPO, ".test-output", "strip-before.js"), src);
    fs.writeFileSync(path.join(REPO, ".test-output", "strip-after.js"), r.out);
    console.log("wrote .test-output/strip-before.js and strip-after.js for " + rel);
  }
  if (apply && r.removed > 0) fs.writeFileSync(f, r.out);
});

perFile.sort(function (a, b) { return b.removed - a.removed; });
console.log((apply ? "APPLIED" : "DRY RUN") + " over " + totals.files + " files in lib/");
console.log("  comments removed : " + totals.removed);
console.log("  kept (header)    : " + totals.header);
console.log("  kept (marker)    : " + totals.marker);
console.log("  kept (jsdoc tag) : " + totals["jsdoc-tagged"]);
console.log("  kept (empty blk) : " + totals["empty-block"]);
console.log("  kept (lazyreq)   : " + totals["lazy-require"]);
console.log("  files touched    : " + totals.touched);
console.log("  lines            : " + totals.linesBefore + " -> " + totals.linesAfter +
            "  (" + (totals.linesBefore - totals.linesAfter) + " fewer)");
console.log("  top files:");
perFile.slice(0, 12).forEach(function (p) {
  console.log("    " + String(p.removed).padStart(5) + "  " + p.rel);
});
