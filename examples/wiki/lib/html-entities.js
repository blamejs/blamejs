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
  "&colon;":  ":",
  "&Tab;":    "\t",
  "&mdash;":  "—",
  "&ndash;":  "–",
  "&hellip;": "…",
  "&middot;": "·",
  "&rarr;":   "→",
  "&larr;":   "←",
  "&szlig;":  "ß",
};
var _ENT_RE =
  /&(?:amp|lt|gt|quot|apos|nbsp|colon|Tab|mdash|ndash|hellip|middot|rarr|larr|szlig);|&#(\d{1,7});|&#[xX]([0-9a-fA-F]{1,6});/g;

// A code point a numeric reference may resolve to. A surrogate half and
// anything past the Unicode maximum are left as the text they were written
// as, which is what a page showing the reference meant anyway.
function _fromCodePoint(cp) {
  if (!isFinite(cp) || cp < 0 || cp > 0x10ffff) return null;
  if (cp >= 0xd800 && cp <= 0xdfff) return null;
  return String.fromCodePoint(cp);
}

function unescapeBuiltinEntities(s) {
  return String(s).replace(_ENT_RE, function (m, dec, hex) {
    if (dec !== undefined) return _fromCodePoint(parseInt(dec, 10)) || m;
    // allow:raw-byte-literal — the radix of a hex character reference
    if (hex !== undefined) return _fromCodePoint(parseInt(hex, 16)) || m;
    return _ENT[m];
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
var _TAG_RE = /<[^>]*>/g;
// eslint-disable-next-line no-control-regex -- the C0/C1 set is what this removes
var _CONTROL_RE = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/g;
var _WS_RE = /\s+/g;

// Entities are decoded last, after every tag is gone, so a code sample's
// `&lt;h1&gt;` reaches the index as the `<h1>` a reader sees rather than as
// a tag an earlier pass strips. The result is text and carries `<`, `>` and
// `"` of its own: a caller that renders it escapes it.
function htmlToSearchText(html) {
  var stripped = String(html)
    .replace(_SCRIPT_OR_STYLE_RE, " ")
    .replace(_COMMENT_RE, " ")
    .replace(_TAG_RE, " ");
  return unescapeBuiltinEntities(stripped)
    .replace(_CONTROL_RE, " ")
    .replace(_WS_RE, " ")
    .trim();
}

module.exports = {
  unescapeBuiltinEntities: unescapeBuiltinEntities,
  htmlToSearchText:        htmlToSearchText,
};
