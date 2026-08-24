// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// Where in a YAML document a character actually SITS.
//
// Two modules were answering that question separately and getting different
// wrong answers. `guard-yaml` decided a `!` opened a tag if it followed
// whitespace, so it reported one inside a quoted scalar, inside a block-scalar
// body, and inside a comment. `parsers/safe-yaml` masked quoted scalars but
// passed comment text through verbatim and had no block-scalar handling at all,
// despite its own note promising both. Between them every ordinary document
// carrying an exclamation mark in prose was refused, by one module or the other.
//
// The question is not "what precedes this character" — it is "what region is
// this character in", and no amount of looking at the previous byte answers it.
// Region is a property of everything before, so it takes a scan. This module is
// that scan, written once, so the two callers cannot drift apart again.
//
// `maskNonStructural` returns a string the SAME LENGTH as its input, with every
// non-structural region replaced by spaces and newlines preserved. Callers keep
// their existing sigil searches and run them against the mask instead of the
// source: an index into one is an index into the other, so reported locations
// and line numbers stay true.
//
// What survives the mask, because it is what the callers are looking for:
// structural punctuation, node properties (`!tag`, `&anchor`, `*alias`),
// directive lines, and document markers. What is masked is scalar content in
// every form it takes: quoted, plain, and block.
//
// The mask is deliberately readier to KEEP than to hide. Masking something
// structural is the dangerous direction: it does not refuse a good document, it
// hides a real tag inside a bad one and hands the callers something they then
// call clean. Every case below that looked like a tidy simplification and was
// not — blanking the rest of a line, measuring a block body from the wrong
// column — failed in exactly that direction.

// No line-splitting helper is used here on purpose: `codepointClass.splitLines`
// strips the carriage return of a CRLF pair, and this function's whole contract
// is that its output is the same length as its input. See the split below.

// Deliberately not a regex, in either sense. The guard and safe families forbid
// them, and a scanner is what this file exists to be.
function _isSpace(code) { return code === 0x20 || code === 0x09; }

function _isPlainSpace(ch) { return ch === " " || ch === "\t"; }

// A node property is a tag, an anchor, or an alias. They chain, so `!tag &a`
// and `&a !tag` are both a single node's properties and the scalar begins after
// the last of them.
function _isPropertySigil(ch) { return ch === "!" || ch === "&" || ch === "*"; }

// A block-scalar header is `|` or `>`, optionally followed by the chomping and
// indentation indicators in EITHER order (`|2-` and `|-2` are equally valid),
// and then nothing but whitespace or a comment. Misreading one scans a shell
// script as if it were YAML.
function _blockHeaderEnd(line, at) {
  var ch = line.charAt(at);
  if (ch !== "|" && ch !== ">") return -1;
  var i = at + 1;
  var sawDigit = false, sawChomp = false;
  while (i < line.length) {
    var c = line.charAt(i);
    if (c >= "1" && c <= "9" && !sawDigit) { sawDigit = true; i += 1; continue; }
    if ((c === "-" || c === "+") && !sawChomp) { sawChomp = true; i += 1; continue; }
    break;
  }
  // Only a header if the rest of the line is blank or a comment; `x: |foo` is
  // an ordinary plain scalar that happens to start with a bar.
  var j = i;
  while (j < line.length && _isPlainSpace(line.charAt(j))) j += 1;
  if (j < line.length && line.charAt(j) !== "#") return -1;
  return i;
}

// The document markers and directive lines a caller still needs to see. A
// directive is only a directive at column zero, and `---` / `...` only at the
// start of a line.
function _isVerbatimLine(line, indent) {
  if (line.charAt(0) === "%") return true;
  var rest = line.slice(indent);
  if (rest.indexOf("---") === 0 &&
      (rest.length === 3 || _isPlainSpace(rest.charAt(3)))) return true;
  if (rest.indexOf("...") === 0 &&
      (rest.length === 3 || _isPlainSpace(rest.charAt(3)))) return true;
  return false;
}

function maskNonStructural(text) {
  var src = String(text == null ? "" : text);
  // Split on the newline ALONE, keeping any `\r` with the line it terminates.
  // `codepointClass.splitLines` strips it, and rejoining those with "\n" drops
  // one character per CRLF line — which would shift every index after the first
  // such line and silently break the alignment this whole function exists to
  // provide. A mask that is not the same length as its source is worse than no
  // mask, because the locations it reports are confidently wrong.
  var lines = src.split("\n");
  var out = [];
  // -1 when no block scalar is open; otherwise the indent of the node that
  // opened it. The body is every following line indented FURTHER than that,
  // plus any blank line among them.
  var blockIndent = -1;
  // A quoted scalar may span lines, so the quote that opened one carries across
  // until it closes. Scanning each line independently would read the
  // CONTINUATION as structure, which puts back the exact false positive this
  // module exists to remove: `x: "hello` / `  !world"` would name a tag on the
  // second line.
  var openQuote = null;
  // A flow collection may also span lines, so its depth carries across too. It
  // decides where a plain scalar ends, and resetting it per line would end one
  // at the wrong place inside a multi-line `[ ... ]`.
  var flowDepth = 0;
  // A PLAIN scalar spans lines as well — that is how a long description gets
  // written without quotes — and its continuation lines are indented further
  // than the node that opened it. Reading one as a fresh line puts the false
  // positive back a fourth way: in
  //
  //     x: hello
  //       !world
  //
  // the value is `hello !world` and the bang introduces nothing.
  //
  // -1 when no plain scalar is open. Otherwise the indent of the node that
  // opened it, which a continuation must beat. This is set ONLY when a line
  // actually read plain-scalar content, so `x:` with its value underneath does
  // not arm it and a nested mapping is still read as structure.
  var plainOpen = -1;

  for (var li = 0; li < lines.length; li += 1) {
    var raw = lines[li];
    // The carriage return of a CRLF pair is a line TERMINATOR, not content, so
    // it is held aside and put back verbatim. Letting it into the scan would
    // have it read as the first character of a plain scalar and masked to a
    // space, which changes the bytes of a document the mask is meant to mirror.
    var cr = raw.length && raw.charAt(raw.length - 1) === "\r";
    var line = cr ? raw.slice(0, raw.length - 1) : raw;
    var indent = 0;
    while (indent < line.length && _isSpace(line.charCodeAt(indent))) indent += 1;
    var blank = indent === line.length;

    // A quoted scalar carried over from an earlier line owns this one until it
    // closes, and nothing before that point is structure — not a `---` that
    // looks like a document marker, and not a `%` in column zero that looks
    // like a directive. So this is answered before either of those.
    //
    // What follows the closing quote on that line IS structure again, and the
    // scan resumes there rather than blanking it. Blanking hid a real tag: in
    // `x: ["first` / ` second", !tag value]` the comma and the tag after the
    // scalar belong to the collection, and masking them takes a tagged document
    // and hands both screens something they call clean.
    var resumeAt = -1;
    var resumePrefix = "";
    if (openQuote !== null) {
      var cont = _maskQuotedBody(line, 0, openQuote);
      if (!cont.closed) {
        out.push(cont.masked + (cr ? "\r" : ""));
        continue;                                   // the whole line is body
      }
      openQuote = null;
      resumeAt = cont.end;
      resumePrefix = cont.masked;
    }

    if (resumeAt === -1) {
      if (blockIndent >= 0) {
        if (blank || indent > blockIndent) {
          out.push(_blanked(line) + (cr ? "\r" : ""));
          continue;
        }
        blockIndent = -1;                           // the body ended here
      }
      if (blank) { out.push(raw); continue; }
      // A directive or a document marker is structure the callers still need to
      // see, but only the marker itself is. A comment may follow one on the same
      // line, and its text is no more YAML there than anywhere else — passing
      // the whole line through left `--- # note !bang` naming a tag, which is
      // the very class this module removes, surviving in the one branch that
      // skipped the scan.
      if (_isVerbatimLine(line, indent)) {
        out.push(_maskTrailingComment(line) + (cr ? "\r" : ""));
        flowDepth = 0;                  // a document marker closes any flow
        continue;
      }
    }

    // Resuming after a closed continuation starts where the quote ended, with
    // that scalar already behind us; otherwise the line's own content begins.
    var masked = resumeAt === -1 ? line.slice(0, indent) : resumePrefix;
    var i = resumeAt === -1 ? indent : resumeAt;
    // A node may begin here: at the start of the line's content, and again
    // after every structural token that introduces one.
    //
    // Two things mean it does NOT begin here. A resumed line has just finished
    // reading a quoted scalar. And a line continuing a PLAIN scalar opened
    // earlier is more of that scalar, so its first character is content:
    //
    //     x: hello
    //       !world
    //
    // The continuation is scanned rather than blanked, because inside a flow
    // collection it may still end at a `,` or a `]` that belongs to the
    // collection — `x: [hello` / `  !world]` closes a sequence on its second
    // line. Closing the node position is enough to make the leading sigil fall
    // into the plain-scalar branch, and it costs no special case.
    var continuesPlain = resumeAt === -1 && plainOpen >= 0 && !blank &&
                         indent > plainOpen;
    var atNodeStart = resumeAt === -1 && !continuesPlain;
    // Where the NODE on this line begins, which is the line's indent until a
    // sequence dash moves it along. A block scalar's body is measured from
    // here, not from the leading whitespace.
    var nodeIndent = indent;
    // The column of the innermost sequence dash read on this line, or -1. A
    // block scalar standing where that dash's own node goes belongs to the
    // ITEM, so this is what bounds its body.
    var dashIndent = -1;
    // Was the token just read a JSON-LIKE key? YAML's JSON compatibility lets
    // one take its value colon with no space after it, and there are two kinds:
    // a quoted scalar, and a flow collection. Both end this flag set.
    var prevWasJsonKey = false;
    // Did the line finish inside a plain scalar? Set by the plain-scalar branch
    // when it runs to the end of the line, and false the moment anything else
    // is read after it.
    var sawPlainToEol = false;

    while (i < line.length) {
      var ch = line.charAt(i);
      // Cleared here and re-set only by the quoted-scalar branch, so no branch
      // can leave it true by forgetting to. The colon rule reads the captured
      // copy rather than the live flag.
      var jsonKeyBefore = prevWasJsonKey;
      prevWasJsonKey = false;

      // A comment opens on `#` at the start of the content or after whitespace,
      // and runs to the end of the line. Its text is not YAML, whatever it
      // says: `x: 1 # note !bang` names no tag.
      if (ch === "#" && (i === indent || _isPlainSpace(line.charAt(i - 1)))) {
        masked += _blanked(line.slice(i));
        break;
      }

      // Whitespace carries the quoted-key flag rather than clearing it. YAML
      // allows separation between a JSON-style key and its adjacent value, so
      // `{"a" :!!python/object x}` is as valid as `{"a":!!python/object x}` —
      // and clearing here left the second form closed and the first one open,
      // which is a deserialization tag hidden behind one space.
      if (_isPlainSpace(ch)) {
        masked += ch; i += 1; prevWasJsonKey = jsonKeyBefore; continue;
      }

      // Structural punctuation stays visible, and each of these opens a node
      // position after it.
      if (ch === "{" || ch === "[") {
        masked += ch; i += 1; flowDepth += 1; atNodeStart = true; continue;
      }
      if (ch === "}" || ch === "]") {
        masked += ch; i += 1; if (flowDepth > 0) flowDepth -= 1;
        atNodeStart = false;
        // A closing delimiter ends a JSON-LIKE key just as a closing quote
        // does, and YAML lets that kind of key take its colon with no space
        // after it. `{{a: b}:!!python/object x}` is valid, and reading the `:`
        // as ordinary text left the tag masked — the same bypass as the quoted
        // key, through the other production for the same rule.
        prevWasJsonKey = true;
        continue;
      }
      if (ch === ",") { masked += ch; i += 1; atNodeStart = true; continue; }
      if (ch === "-" && (i + 1 >= line.length || _isPlainSpace(line.charAt(i + 1)))) {
        masked += ch; i += 1; atNodeStart = true;
        // A sequence entry written inline starts a node PAST the dash, and any
        // block scalar it opens is measured from there rather than from the
        // line's leading whitespace. Getting this wrong is not a false refusal
        // but a false ACCEPT: in
        //
        //     - key: |
        //         body
        //       evil: !tag x
        //
        // `evil` is a sibling of `key`, and measuring the body against the
        // dash's indent of zero swallows it — masking a real tag and handing
        // both screens a document they then call clean.
        var afterDash = i;
        while (afterDash < line.length && _isPlainSpace(line.charAt(afterDash))) afterDash += 1;
        if (afterDash < line.length) nodeIndent = afterDash;
        // ...unless the item's node IS a block scalar, with no mapping in
        // between: `- |` then `  !hello`. There the body starts at the same
        // column the `|` sits in, so measuring from that column masks nothing
        // and the scalar's first line reads as a tag. The owner of the block is
        // the sequence ITEM, so the dash's column is what bounds it.
        dashIndent = i - 1;
        continue;
      }
      if (ch === "?" && (i + 1 >= line.length || _isPlainSpace(line.charAt(i + 1)))) {
        masked += ch; i += 1; atNodeStart = true; continue;
      }
      // A colon separates a key from its value when whitespace follows, when a
      // flow delimiter does — and, inside a flow collection, when the key was
      // QUOTED. That last form is YAML's JSON compatibility: `{"a":value}` is
      // valid and needs no space, so requiring one left the colon unread, the
      // node position closed, and the value masked as though it were more of
      // the key's scalar. `{"a":!!python/object x}` therefore reached both
      // screens with its tag hidden — a deserialization tag, which is the
      // single most dangerous thing this scan exists to surface.
      if (ch === ":" &&
          (i + 1 >= line.length || _isPlainSpace(line.charAt(i + 1)) ||
           (flowDepth > 0 && ",}]".indexOf(line.charAt(i + 1)) !== -1) ||
           (flowDepth > 0 && jsonKeyBefore))) {
        masked += ch; i += 1; atNodeStart = true; continue;
      }

      // A node's properties survive: they are exactly what the callers scan for,
      // and they are the ONLY place a `!`, `&` or `*` means what it looks like.
      if (atNodeStart && _isPropertySigil(ch)) {
        var pEnd = i + 1;
        if (ch === "!" && line.charAt(pEnd) === "!") pEnd += 1;
        while (pEnd < line.length && !_isPlainSpace(line.charAt(pEnd)) &&
               (flowDepth === 0 || ",}]".indexOf(line.charAt(pEnd)) === -1)) pEnd += 1;
        masked += line.slice(i, pEnd);
        i = pEnd;
        continue;                                   // properties chain
      }

      // A quoted scalar: the quotes stay, the body goes. The body is content by
      // construction, so nothing in it is ever structure.
      if (ch === '"' || ch === "'") {
        var qr = _maskQuotedBody(line, i + 1, ch);
        masked += ch + qr.masked;
        i = qr.end;
        // Not closed on this line means the scalar CONTINUES, which YAML allows
        // and which the line-at-a-time reading would otherwise lose. The quote
        // is remembered so the next line is read as its body rather than as
        // structure.
        if (!qr.closed) { openQuote = ch; break; }
        atNodeStart = false;
        // Remembered for the colon rule above: a quoted scalar is one of the
        // two JSON-like key forms that may take its colon with no space between.
        prevWasJsonKey = true;
        continue;
      }

      // A block-scalar header ends the line's structure; the body is masked by
      // the outer loop.
      var bEnd = _blockHeaderEnd(line, i);
      if (bEnd !== -1) {
        masked += line.slice(i, bEnd);
        // The block belongs to whichever node opened it. A header standing where
        // the dash's own node would be (`- |`) is the ITEM's scalar, so the
        // dash bounds its body; a header after a key (`- key: |`) belongs to
        // that key, and the mapping's column bounds it — which is what stops
        // the body swallowing the key's siblings.
        blockIndent = (dashIndent >= 0 && i === nodeIndent) ? dashIndent : nodeIndent;
        i = bEnd;
        atNodeStart = false;
        continue;
      }

      // Anything else begins a PLAIN scalar, and everything to the end of it is
      // content. This is the case the previous implementations had no notion of:
      // in `x: hello !world` the `!world` sits inside a scalar that started at
      // `hello`, so it names no tag, and only knowing a scalar had already begun
      // can tell you that.
      var s = i;
      while (s < line.length) {
        var c3 = line.charAt(s);
        if (c3 === "#" && _isPlainSpace(line.charAt(s - 1))) break;
        if (c3 === ":" &&
            (s + 1 >= line.length || _isPlainSpace(line.charAt(s + 1)) ||
             (flowDepth > 0 && ",}]".indexOf(line.charAt(s + 1)) !== -1))) break;
        if (flowDepth > 0 && ",}][{".indexOf(c3) !== -1) break;
        s += 1;
      }
      masked += _blanked(line.slice(i, s));
      i = s;
      atNodeStart = false;
      // A plain scalar reaching the end of the line may continue on the next
      // one. Only the LAST thing read on a line can, so this is recorded here
      // and cleared by anything that follows it.
      sawPlainToEol = s >= line.length;
    }
    // Armed only when the line ended inside a plain scalar, and measured
    // against the node that opened it rather than the line's own indent. `x:`
    // with nothing after it never arms this, so the mapping written underneath
    // it is still read as structure rather than swallowed as text.
    // Armed inside a flow collection too: a plain scalar spans lines there just
    // as it does outside one, and requiring depth zero left `x: [hello` /
    // `  !world]` reading its second line at a fresh node start.
    plainOpen = (sawPlainToEol && openQuote === null && blockIndent < 0)
      ? (continuesPlain ? plainOpen : nodeIndent)
      : -1;
    out.push(masked + (cr ? "\r" : ""));
  }
  return out.join("\n");
}

// A line kept for its structure, with any comment on it masked. Used for the
// directive and document-marker lines, which are passed through whole because
// what makes them structural is their shape rather than a scan of their parts.
// The comment is still content and still has to go.
function _maskTrailingComment(line) {
  for (var i = 0; i < line.length; i += 1) {
    if (line.charAt(i) !== "#") continue;
    if (i !== 0 && !_isPlainSpace(line.charAt(i - 1))) continue;
    return line.slice(0, i) + _blanked(line.slice(i));
  }
  return line;
}

// The body of a quoted scalar from `at`, masked, stopping at the closing quote.
// Returns where the scan ended (past the quote when it closed) and whether it
// did close, which is what tells the caller the scalar runs onto the next line.
//
// Both the escape forms are honoured because both hide a quote that would
// otherwise look like the end: `\"` inside a double-quoted scalar and `''`
// inside a single-quoted one. Reading either as a terminator ends the mask
// early and hands the rest of the scalar back to the structural scan as though
// it were YAML.
function _maskQuotedBody(line, at, quote) {
  var body = "";
  var k = at;
  while (k < line.length) {
    var c = line.charAt(k);
    if (quote === '"' && c === "\\" && k + 1 < line.length) { body += "  "; k += 2; continue; }
    if (c === quote) {
      if (quote === "'" && line.charAt(k + 1) === "'") { body += "  "; k += 2; continue; }
      return { masked: body + quote, end: k + 1, closed: true };
    }
    body += c === "\t" ? "\t" : " ";
    k += 1;
  }
  return { masked: body, end: k, closed: false };
}

// Same length, spaces throughout. Newlines cannot appear here — the caller
// splits on them first — but a tab is preserved so column arithmetic that
// counts it as one character still agrees with the source.
function _blanked(s) {
  var o = "";
  for (var i = 0; i < s.length; i += 1) o += s.charAt(i) === "\t" ? "\t" : " ";
  return o;
}

module.exports = {
  maskNonStructural: maskNonStructural,
};
