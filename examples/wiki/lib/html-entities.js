// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

// Single-pass decode of the built-in HTML entities the wiki page generator
// emits. A CHAINED decode (`.replace(/&amp;/g,"&").replace(/&lt;/g,"<")...`)
// double-decodes: `&amp;lt;` -> `&lt;` (step 1) -> `<` (step 2), un-escaping a
// level that was never escaped at the source (CodeQL js/double-escaping,
// CWE-116). One regex pass consumes each entity exactly once, so a replacement
// output is never re-scanned. Mirrors the framework's production decoders
// (lib/parsers/safe-xml.js etc.), which are all single-pass and not flagged.
// The named entities the page generator and the source comment blocks emit.
// `&nbsp;` becomes an ordinary space: every caller either collapses runs of
// whitespace or compares a title, and neither wants a character that looks
// like a space and does not compare as one.
var _ENT = {
  "&amp;":    "&",
  "&lt;":     "<",
  "&gt;":     ">",
  "&quot;":   "\"",
  "&apos;":   "'",
  "&nbsp;":   " ",
  "&ensp;":   " ",
  "&emsp;":   " ",
  "&thinsp;": " ",
  "&colon;":  ":",
  "&Tab;":    "\t",
  "&NewLine;": "\n",
  "&mdash;":  "—",
  "&ndash;":  "–",
  "&minus;":  "−",
  "&hellip;": "…",
  "&middot;": "·",
  "&bull;":   "•",
  "&dagger;": "†",
  "&Dagger;": "‡",
  "&lsquo;":  "‘",
  "&rsquo;":  "’",
  "&ldquo;":  "“",
  "&rdquo;":  "”",
  "&laquo;":  "«",
  "&raquo;":  "»",
  "&rarr;":   "→",
  "&larr;":   "←",
  "&uarr;":   "↑",
  "&darr;":   "↓",
  "&harr;":   "↔",
  "&copy;":   "©",
  "&reg;":    "®",
  "&trade;":  "™",
  "&sect;":   "§",
  "&para;":   "¶",
  "&deg;":    "°",
  "&plusmn;": "±",
  "&times;":  "×",
  "&divide;": "÷",
  "&frac12;": "½",
  "&frac14;": "¼",
  "&sup2;":   "²",
  "&sup3;":   "³",
  "&micro;":  "µ",
  "&euro;":   "€",
  "&pound;":  "£",
  "&yen;":    "¥",
  "&cent;":   "¢",
  "&szlig;":  "ß",
  "&agrave;": "à", "&aacute;": "á", "&acirc;": "â",
  "&atilde;": "ã", "&auml;":   "ä", "&aring;": "å",
  "&aelig;":  "æ", "&ccedil;": "ç", "&egrave;": "è",
  "&eacute;": "é", "&ecirc;":  "ê", "&euml;":   "ë",
  "&igrave;": "ì", "&iacute;": "í", "&icirc;":  "î",
  "&iuml;":   "ï", "&ntilde;": "ñ", "&ograve;": "ò",
  "&oacute;": "ó", "&ocirc;":  "ô", "&otilde;": "õ",
  "&ouml;":   "ö", "&oslash;": "ø", "&ugrave;": "ù",
  "&uacute;": "ú", "&ucirc;":  "û", "&uuml;":   "ü",
  "&yacute;": "ý", "&yuml;":   "ÿ",
};
var _ENT_RE = /&([a-zA-Z][a-zA-Z0-9]{1,31});|&#(\d{1,7});|&#[xX]([0-9a-fA-F]{1,6});/g;

// A code point a numeric reference may resolve to. A surrogate half and
// anything past the Unicode maximum are left as the text they were written
// as, which is what a page showing the reference meant anyway.
function _fromCodePoint(cp) {
  if (!isFinite(cp) || cp < 0 || cp > 0x10ffff) return null;
  if (cp >= 0xd800 && cp <= 0xdfff) return null;
  return String.fromCodePoint(cp);
}

// `dropUnknown` replaces a named reference this table does not carry with a
// space instead of leaving its spelling in the text. The search index wants
// that: an undecoded `&copy;` makes `copy` a word a reader can match and never
// see, and the search view escapes what it renders, so the spelling is what
// the excerpt would show. A caller comparing a title wants the text left as
// it was written, so the default is to leave it.
function unescapeBuiltinEntities(s, opts) {
  var dropUnknown = !!(opts && opts.dropUnknown);
  return String(s).replace(_ENT_RE, function (m, name, dec, hex) {
    if (name !== undefined) {
      var known = _ENT["&" + name + ";"];
      if (known !== undefined) return known;
      return dropUnknown ? " " : m;
    }
    if (dec !== undefined) return _fromCodePoint(parseInt(dec, 10)) || m;
    // allow:raw-byte-literal — the radix of a hex character reference
    return _fromCodePoint(parseInt(hex, 16)) || m;
  });
}

// Markup removal for the search index. <script> and <style> go with their
// contents; an HTML comment goes whole, so a `>` inside one leaves no tail
// behind; every remaining tag becomes a space, which takes attribute values
// with it and keeps two adjacent elements from fusing into one token. The
// control characters go after the entities are decoded, so a numeric
// reference cannot carry one in, among them the two the search route uses to
// delimit a highlight.
var _SCRIPT_OR_STYLE_RE = /<(script|style)\b[^>]*>[\s\S]*?<\/\1\s*>/gi;
var _COMMENT_RE = /<!--[\s\S]*?-->/g;
// What may follow a `<` for it to open a tag. Past the end of the string
// charAt returns "", which answers false here.
function _startsTag(c) {
  return (c >= "a" && c <= "z") || (c >= "A" && c <= "Z") ||
         c === "/" || c === "!" || c === "?";
}

// Tags out, one character at a time rather than by a `<[^>]*>` match, for two
// reasons an author's HTML runs into. A `>` inside a quoted attribute value
// ends that match early and leaves the rest of the attribute behind as text,
// which is how attribute text got into the index in the first place. And a
// `<` that starts no tag, as in the prose `2 < 3 and 5 > 4`, makes the match
// swallow everything up to the next `>`.
function _stripTags(html) {
  var out = "";
  var i = 0;
  while (i < html.length) {
    var lt = html.indexOf("<", i);
    if (lt === -1) { out += html.slice(i); break; }
    if (!_startsTag(html.charAt(lt + 1))) {
      out += html.slice(i, lt + 1);
      i = lt + 1;
      continue;
    }
    out += html.slice(i, lt) + " ";
    var j = lt + 1;
    var quote = null;
    while (j < html.length) {
      var c = html.charAt(j);
      if (quote !== null) {
        if (c === quote) quote = null;
      } else if (c === "\"" || c === "'") {
        quote = c;
      } else if (c === ">") {
        j += 1;
        break;
      }
      j += 1;
    }
    i = j;
  }
  return out;
}
// eslint-disable-next-line no-control-regex -- the C0/C1 set is what this removes
var _CONTROL_RE = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/g;
var _WS_RE = /\s+/g;

// Entities are decoded last, after every tag is gone, so a code sample's
// `&lt;h1&gt;` reaches the index as the `<h1>` a reader sees rather than as
// a tag an earlier pass strips. The result is text and carries `<`, `>` and
// `"` of its own: a caller that renders it escapes it.
function htmlToSearchText(html) {
  var stripped = _stripTags(
    String(html)
      .replace(_SCRIPT_OR_STYLE_RE, " ")
      .replace(_COMMENT_RE, " ")
  );
  return unescapeBuiltinEntities(stripped, { dropUnknown: true })
    .replace(_CONTROL_RE, " ")
    .replace(_WS_RE, " ")
    .trim();
}

module.exports = {
  unescapeBuiltinEntities: unescapeBuiltinEntities,
  htmlToSearchText:        htmlToSearchText,
};
