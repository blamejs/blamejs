// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * guard-markdown — Markdown content-safety primitive (b.guardMarkdown).
 *
 * Covers: surface; registry parity; raw HTML detection; whitespace-tag
 * bypass (CVE-2026-30838); javascript:/data:/vbscript: link schemes;
 * autolink scheme detection; reference-link smuggling; image scheme
 * bypass; HTML-entity scheme decode bypass; HTML comments; front-matter;
 * code-fence language injection; catastrophic emphasis runs; list +
 * blockquote depth caps; bidi/null/control char detection; sanitize
 * discipline; gate composition; profile + posture vocabulary.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function testGuardMarkdownSurface() {
  check("guardMarkdown is an object",                   typeof b.guardMarkdown === "object");
  check("guardMarkdown.NAME === 'markdown'",            b.guardMarkdown.NAME === "markdown");
  check("guardMarkdown.KIND === 'content'",             b.guardMarkdown.KIND === "content");
  check("guardMarkdown.MIME_TYPES has text/markdown",   b.guardMarkdown.MIME_TYPES.indexOf("text/markdown") !== -1);
  check("guardMarkdown.EXTENSIONS has .md",             b.guardMarkdown.EXTENSIONS.indexOf(".md") !== -1);
  check("guardMarkdown.PROFILES has strict",            !!b.guardMarkdown.PROFILES["strict"]);
  check("guardMarkdown.PROFILES has balanced",          !!b.guardMarkdown.PROFILES["balanced"]);
  check("guardMarkdown.PROFILES has permissive",        !!b.guardMarkdown.PROFILES["permissive"]);
  check("guardMarkdown.COMPLIANCE_POSTURES has hipaa",  !!b.guardMarkdown.COMPLIANCE_POSTURES["hipaa"]);
  check("guardMarkdown.validate is a function",         typeof b.guardMarkdown.validate === "function");
  check("guardMarkdown.sanitize is a function",         typeof b.guardMarkdown.sanitize === "function");
  check("guardMarkdown.gate is a function",             typeof b.guardMarkdown.gate === "function");
  check("frameworkError.GuardMarkdownError exposed",    typeof b.frameworkError.GuardMarkdownError === "function");
}

function testGuardMarkdownRegistryParity() {
  check("guardMarkdown registered in guardAll",
        b.guardAll.list().some(function (g) { return g.name === "markdown"; }));
}

function testGuardMarkdownDangerousScheme() {
  var rv = b.guardMarkdown.validate(
    "# x\n\n[click](javascript:alert(1))\n",
    { profile: "strict" });
  check("javascript: link scheme detected (CVE-2025-9540 class)",
        rv.ok === false &&
        rv.issues.some(function (i) { return i.kind === "link-scheme"; }));

  var rvData = b.guardMarkdown.validate(
    "[x](data:text/html,<script>alert(1)</script>)\n",
    { profile: "strict" });
  check("data:text/html link scheme detected",
        rvData.issues.some(function (i) { return i.kind === "link-scheme"; }));

  var rvVbs = b.guardMarkdown.validate(
    "[x](vbscript:msgbox)\n", { profile: "strict" });
  check("vbscript: link scheme detected",
        rvVbs.issues.some(function (i) { return i.kind === "link-scheme"; }));

  // A malformed OUTER link can carry a well-formed INNER one, and a renderer
  // recovers and emits the inner destination. A scan that resumed past the
  // whole failed candidate skipped the inner `[` and let the scheme through.
  [
    "[bad]([ok]( javascript:x))",
    "[bad]([ok](javascript:x) trailing)",
    "[a]([b]([c](javascript:x)))",
    "text [outer]( [inner](vbscript:msgbox) ) more",
  ].forEach(function (doc) {
    var nested = b.guardMarkdown.validate(doc, { profile: "strict" });
    check("a dangerous scheme inside a malformed outer link is still seen: " +
          JSON.stringify(doc),
          nested.issues.some(function (i) { return i.kind === "link-scheme"; }),
          JSON.stringify(nested.issues.map(function (i) { return i.kind; })));
  });

  // Resuming after a failure must not turn the scan quadratic — the shape it
  // costs is a document of prefixes that each fail the same way.
  var NESTED_FLOOD_MS = 4000;
  [["[a](", 200000], ["[a](\"", 200000], ["[bad]([ok](", 100000]].forEach(function (c) {
    var doc = c[0].repeat(c[1]);
    var started = Date.now();
    b.guardMarkdown._shapesForTest.inlineLinks(doc);
    var elapsed = Date.now() - started;
    check("a " + doc.length + "-character run of " + JSON.stringify(c[0]) +
          " still scans in linear time (" + elapsed + "ms)",
          elapsed < NESTED_FLOOD_MS);
  });
}

function testGuardMarkdownEntityBypass() {
  // `&#x6A;avascript:` decodes to `javascript:` in the URL — the gate
  // must decode HTML entities before scheme-matching.
  var rv = b.guardMarkdown.validate(
    "[x](&#x6A;avascript:alert(1))\n", { profile: "strict" });
  check("HTML-entity-encoded javascript: scheme detected",
        rv.issues.some(function (i) { return i.kind === "link-scheme"; }));

  var rvDec = b.guardMarkdown.validate(
    "[x](&#106;avascript:alert(1))\n", { profile: "strict" });
  check("decimal-entity javascript: scheme detected",
        rvDec.issues.some(function (i) { return i.kind === "link-scheme"; }));

  // Named entities + entity-encoded leading space: a browser resolves &Tab; /
  // &NewLine; and trims a leading C0-control-or-space run before parsing the URL,
  // so `java&Tab;script:` and `&#32;javascript:` navigate as javascript:. Decoding
  // numeric-only, or not trimming the entity space, let these bypass -> fail-open.
  var mdWs = [
    ["named &Tab;",         "[x](java&Tab;script:alert(1))"],
    ["named &NewLine;",     "[x](java&NewLine;script:alert(1))"],
    ["entity space &#32;",  "[x](&#32;javascript:alert(1))"],
    ["entity space &#x20;", "[x](&#x20;javascript:alert(1))"],
  ];
  for (var w = 0; w < mdWs.length; w++) {
    var rvW = b.guardMarkdown.validate(mdWs[w][1], { profile: "strict" });
    check("markdown whitespace/entity-hidden scheme (" + mdWs[w][0] + ") detected",
          rvW.issues.some(function (i) { return i.kind === "link-scheme"; }));
  }
}

function testGuardMarkdownAutolinkScheme() {
  var rv = b.guardMarkdown.validate(
    "<javascript:alert(1)>\n", { profile: "strict" });
  check("autolink javascript: scheme detected (NuGetGallery / MDC class)",
        rv.issues.some(function (i) { return i.kind === "autolink-scheme"; }));
}

function testGuardMarkdownReferenceLinkSmuggling() {
  var rv = b.guardMarkdown.validate(
    "[click][ref]\n\n[ref]: javascript:alert(1)\n",
    { profile: "strict" });
  check("reference-link definition with javascript: detected",
        rv.issues.some(function (i) { return i.kind === "reference-link-scheme"; }));
}

function testGuardMarkdownImageScheme() {
  var rv = b.guardMarkdown.validate(
    "![alt](javascript:alert(1))\n", { profile: "strict" });
  check("image with javascript: scheme detected",
        rv.issues.some(function (i) { return i.kind === "image-scheme"; }));
}

function testGuardMarkdownDangerousTag() {
  var rv = b.guardMarkdown.validate(
    "<script>alert(1)</script>\n", { profile: "strict" });
  check("raw <script> tag detected",
        rv.issues.some(function (i) { return i.kind === "dangerous-tag"; }));
}

function testGuardMarkdownWhitespaceTagBypass() {
  // CVE-2026-30838 — naive `<script>` matchers miss `<script\n>`.
  var rv = b.guardMarkdown.validate(
    "<script\n>alert(1)</script>\n", { profile: "strict" });
  check("whitespace-tolerant <script\\n> bypass detected (CVE-2026-30838)",
        rv.issues.some(function (i) { return i.kind === "dangerous-tag"; }));

  var rvTab = b.guardMarkdown.validate(
    "<\tiframe src=x>\n", { profile: "strict" });
  check("leading-whitespace <\\tiframe> bypass detected",
        rvTab.issues.some(function (i) { return i.kind === "dangerous-tag"; }));
}

function testGuardMarkdownHtmlComment() {
  var rv = b.guardMarkdown.validate(
    "Some text <!-- payload --> more.\n", { profile: "strict" });
  check("HTML comment block detected",
        rv.issues.some(function (i) { return i.kind === "html-comment"; }));
}

function testGuardMarkdownFrontMatter() {
  var rv = b.guardMarkdown.validate(
    "---\ntitle: x\n---\n\n# Body\n", { profile: "strict" });
  check("YAML front-matter detected",
        rv.issues.some(function (i) { return i.kind === "front-matter"; }));

  var rvToml = b.guardMarkdown.validate(
    "+++\ntitle = \"x\"\n+++\n\n# Body\n", { profile: "strict" });
  check("TOML front-matter detected",
        rvToml.issues.some(function (i) { return i.kind === "front-matter"; }));
}

function testGuardMarkdownCodeFenceLang() {
  var rv = b.guardMarkdown.validate(
    "```\"><script>alert(1)</script>\nx\n```\n", { profile: "strict" });
  check("code-fence language tag with attribute-breaking chars detected",
        rv.issues.some(function (i) { return i.kind === "code-fence-lang"; }));
}

function testGuardMarkdownEmphasisRun() {
  var rv = b.guardMarkdown.validate(
    "x" + new Array(50).join("*") + "y\n", { profile: "strict" });
  check("catastrophic emphasis run detected (CVE-2025-6493 class)",
        rv.issues.some(function (i) { return i.kind === "emphasis-run"; }));
}

function testGuardMarkdownDoctype() {
  var rv = b.guardMarkdown.validate(
    "<!DOCTYPE html>\n# x\n", { profile: "strict" });
  check("inline DOCTYPE detected",
        rv.issues.some(function (i) { return i.kind === "doctype"; }));
}

function testGuardMarkdownBidiNull() {
  var bidi = String.fromCharCode(0x202E);
  var rv = b.guardMarkdown.validate(
    "# t\n\nhello" + bidi + "world\n", { profile: "strict" });
  check("bidi override detected",
        rv.issues.some(function (i) { return i.kind === "bidi-override"; }));

  var nb = String.fromCharCode(0);
  var rvNull = b.guardMarkdown.validate(
    "# t\n\nhello" + nb + "world\n", { profile: "strict" });
  check("null byte detected",
        rvNull.issues.some(function (i) { return i.kind === "null-byte"; }));
}

function testGuardMarkdownClean() {
  var rv = b.guardMarkdown.validate(
    "# Title\n\nA [link](https://example.com) and *emphasis*.\n",
    { profile: "strict" });
  check("clean markdown → ok=true with no issues",
        rv.ok === true && rv.issues.length === 0);
}

function testGuardMarkdownLinkCap() {
  var src = "# x\n";
  for (var i = 0; i < 300; i++) src += "[a](https://x.com)\n";
  var rv = b.guardMarkdown.validate(src, { profile: "strict" });
  check("link cap detected (strict maxLinks 256)",
        rv.issues.some(function (i) { return i.kind === "link-cap"; }));
}

function testGuardMarkdownListDepthCap() {
  var src = "# x\n";
  for (var i = 0; i < 20; i++) {
    src += new Array(i * 2 + 1).join(" ") + "- item\n";
  }
  var rv = b.guardMarkdown.validate(src, { profile: "strict" });
  check("list depth cap detected (strict maxListDepth 16)",
        rv.issues.some(function (i) { return i.kind === "list-depth-cap"; }));
}

function testGuardMarkdownBlockquoteDepthCap() {
  var src = "# x\n" + new Array(20).join(">") + " deeply quoted\n";
  var rv = b.guardMarkdown.validate(src, { profile: "strict" });
  check("blockquote depth cap detected (strict maxBlockquoteDepth 16)",
        rv.issues.some(function (i) { return i.kind === "blockquote-depth-cap"; }));
}

function testGuardMarkdownByteCap() {
  // maxBytes is a BYTE limit. A multibyte string can stay under the cap by
  // UTF-16 code-unit count (.length) while its UTF-8 encoding blows past it,
  // so the cap must measure Buffer.byteLength, never .length. "é" (U+00E9)
  // is 1 code unit but 2 UTF-8 bytes: 8 of them = .length 8 (under a 10-byte
  // cap by char count) yet 16 bytes (over it).
  var multibyte = "é".repeat(8);
  check("multibyte input is 8 UTF-16 units but 16 UTF-8 bytes",
        multibyte.length === 8 && Buffer.byteLength(multibyte, "utf8") === 16);

  var rvOver = b.guardMarkdown.validate(multibyte, { maxBytes: 10 });
  var cap = rvOver.issues.filter(function (i) { return i.kind === "too-large"; });
  check("multibyte over the BYTE cap fires too-large (not char-count-gated)",
        cap.length === 1);
  check("too-large snippet reports the BYTE length, not the char count",
        cap.length === 1 && /16 bytes exceeds maxBytes 10/.test(cap[0].snippet));
  check("too-large carries ruleId markdown.too-large",
        cap.length === 1 && cap[0].ruleId === "markdown.too-large");

  // ASCII is unaffected: byte length equals char length, so the cap behaves
  // identically before and after the fix.
  var rvAsciiUnder = b.guardMarkdown.validate("aaaaaaaa", { maxBytes: 10 });
  check("ASCII under the byte cap → no too-large",
        !rvAsciiUnder.issues.some(function (i) { return i.kind === "too-large"; }));
  var rvAsciiOver = b.guardMarkdown.validate("aaaaaaaaaaaaaaaa", { maxBytes: 10 });
  check("ASCII over the byte cap → too-large still fires",
        rvAsciiOver.issues.some(function (i) { return i.kind === "too-large"; }));
}

function testGuardMarkdownSanitizeRefusesCritical() {
  var threw = null;
  try { b.guardMarkdown.sanitize(
    "[x](javascript:alert(1))\n", { profile: "balanced" }); }
  catch (e) { threw = e; }
  check("sanitize refuses javascript: link (no safe sanitization)",
        threw && /scheme|refused/.test(threw.code || threw.message || ""));
}

function testGuardMarkdownSanitizeRefusesBadInput() {
  // A non-string/Buffer sanitize input is unprocessable — it must throw a typed
  // markdown.bad-input, NEVER silently return the garbage. (sanitizeSeverities
  // is ["critical"], so the high-severity bad-input issue is not a content
  // refusal; the generated sanitize refuses a `bad-input` KIND unconditionally.)
  [123, null, {}, [1, 2, 3], true].forEach(function (bad) {
    var threw = null;
    try { b.guardMarkdown.sanitize(bad, { profile: "strict" }); }
    catch (e) { threw = e; }
    check("sanitize(" + JSON.stringify(bad) + ") throws markdown.bad-input (no silent pass)",
          threw && threw.code === "markdown/bad-input");
  });
}

async function testGuardMarkdownGate() {
  var g = b.guardMarkdown.gate({ profile: "strict" });
  var clean = await g.check({
    contentType: "text/markdown",
    bytes:       Buffer.from("# t\n\nhello [w](https://w.com)\n", "utf8"),
  });
  check("gate clean → action=serve",
        clean.ok === true && clean.action === "serve");

  var hostile = await g.check({
    contentType: "text/markdown",
    bytes:       Buffer.from("# x\n\n[click](javascript:alert(1))\n", "utf8"),
  });
  check("gate javascript: link → action !== serve",
        hostile.action !== "serve");
}

function testGuardMarkdownCompliancePosture() {
  var hipaa = b.guardMarkdown.compliancePosture("hipaa");
  check("compliancePosture('hipaa') sets reject policies",
        hipaa.dangerousTagPolicy === "reject" &&
        hipaa.dangerousSchemePolicy === "reject");
  var threw = null;
  try { b.guardMarkdown.compliancePosture("unknown"); }
  catch (e) { threw = e; }
  check("compliancePosture: unknown name throws",
        threw && /unknown/.test(threw.message));
}

// The link, autolink, reference-definition and code-fence extractors and the
// raw-HTML / dangerous-tag / comment / DOCTYPE / front-matter / emphasis
// screens are character walks. Each is compared against the pattern it
// replaced, over the shapes a markdown payload is written in. The extractors
// matter most: a URL a walk fails to find is a URL whose scheme is never
// screened.
function testMarkdownExtractorsAgreeWithThePatternsTheyReplaced() {
  var api = b.guardMarkdown._shapesForTest;

  var INLINE_LINK_RE = /(!?)\[([^\]\n]*)\]\(\s*([^)\s]+)\s*(?:"[^"]*")?\s*\)/g;
  var AUTOLINK_RE    = /<((?:[a-zA-Z][a-zA-Z0-9+.-]{0,32}):[^\s>]+)>/g;
  // The destination may follow one line ending, never a blank line. The two
  // Unicode line separators are built from their code points so the source
  // holds no invisible characters.
  var ONE_LINE_ENDING = "(?:\\r\\n|\\r|\\n|" + String.fromCharCode(0x2028) + "|" +
                        String.fromCharCode(0x2029) + ")?";
  var REF_DEF_RE     = new RegExp("^ {0,3}\\[([^\\]\\n]+)\\]:[ \\t]*" + ONE_LINE_ENDING +
                                  "[ \\t]*([^\\s]+)", "gm");
  // The container prefixes a definition may follow at the top level of a
  // document: block quote markers and list markers, each after up to three
  // spaces, then up to three spaces of leaf indentation.
  var REF_DEF_CONTAINER_RE = new RegExp(
    "^(?: {0,3}(?:>[ ]?|[-+*][ \\t]|\\d{1,9}[.)][ \\t]))* {0,3}\\[([^\\]\\n]+)\\]:[ \\t]*" +
    ONE_LINE_ENDING + "[ \\t]*([^\\s]+)", "gm");
  var CODE_FENCE_LANG_RE = /^(?:```|~~~)([^\n]*)\n/gm;
  var RAW_HTML_TAG_RE = /<\s*\/?\s*[A-Za-z][\w-]*[\s\S]*?>/;
  var DANGEROUS_TAG_RE = /<\s*\/?\s*(script|iframe|object|embed|applet|form|input|button|textarea|select|option|meta|link|base|frame|frameset|noscript|noembed|svg|math|video|audio|source|track|style|template|portal|marquee)\b/i;
  var HTML_COMMENT_RE = /<!--[\s\S]*?-->/;
  var DOCTYPE_INLINE_RE = /<!DOCTYPE\b/i;
  var FRONT_MATTER_YAML_RE = /^---\s*\n[\s\S]+?\n---\s*\n?/;
  var FRONT_MATTER_TOML_RE = /^\+\+\+\s*\n[\s\S]+?\n\+\+\+\s*\n?/;
  var EMPH_RUN_RE = /[*_]{20,}/;

  var DOCS = [
    "", "plain text", "[a](b)", "![a](b)", "[a](  b  )", "[a](b \"t\")",
    "[](b)", "[a]()", "[a](b c)", "[a\nb](c)", "[a](b)[c](d)",
    "text [x](javascript:alert(1)) more", "![i](data:text/html,x)",
    // A title with no whitespace before it ends the URL — running the URL
    // through the quote loses the link and with it the scheme screen.
    "[a](javascript:x\"title with space\")", "[a](https://x\"t\")",
    "[a](https://x\"unclosed)", "[a](https://x\"t\" trailing)",
    "[a](\"just a title\")", "[a](x\"y\"z\")",
    "<https://x>", "<javascript:alert(1)>", "<not a link>", "<a>", "<>",
    "<" + "a".repeat(40) + ":x>", "<mailto:a@b>", "<x:>",
    "[ref]: https://x", "   [ref]: https://x", "    [ref]: https://x",
    "[ref]:https://x", "[]: x", "[a]: ", "line\n\n[ref]: javascript:x",
    // The destination may sit on the next line — the whitespace after the
    // colon includes the line break, so a line-by-line walk loses the URL and
    // never screens its scheme.
    "[x]:\njavascript:alert(1)", "[x]:\n  https://ok", "[x]:\n\nhttps://ok",
    "[a]: one\n[b]: two", "[a]:\n", "[a]:",
    // A lone CR starts a line for a `^` under the `m` flag, and so do the two
    // Unicode line separators — a scan that only knows LF misses these. Two
    // of them make the blank line a definition needs after a paragraph.
    "x\r\r[ref]: javascript:y", "x\r```<script>\ny",
    "x" + String.fromCharCode(0x2028, 0x2028) + "[ref]: javascript:y",
    "x\r\n\r\n[ref]: javascript:y", "x\r\n```<script>\ny",
    "```js\ncode\n```", "~~~py\ncode\n~~~", "```<script>\nx\n```",
    "```\nx\n```", "```js", "text\n```sh\nx\n```",
    "<script>x</script>", "< script >x", "<scriptx>", "<div>", "<DIV>",
    "< / script >", "<a-b>", "<a_b>", "no tags here",
    // A hyphen is not a word character, so it ENDS the name: `<script-x>` is
    // a `script` finding. Treating it as part of the name loses these.
    "<script-x>", "<script->", "<form-a>", "<script.>", "<script_x>",
    "<script1>", "< script -x>", "<!DOCTYPE-foo>", "<!DOCTYPE.", "<!DOCTYPE_x",
    // Front matter whose closing fence has trailing text, which the pattern
    // accepted because its tail was optional.
    "---\na: 1\n---evil\n", "---\na: 1\n--- \n", "---\na: 1\n---",
    "---x\na: 1\n---\n", "---\na\n---trailing",
    // Two fences with nothing between them are not front matter.
    "---\n\n---", "---\n\n---\n", "---\n---", "---\n \n---", "---\n\n\n---",
    "+++\n\n+++", "+++\na=1\n+++\n",
    "<!-- c -->", "<!--", "-->", "<!--\nmulti\n-->",
    "<!DOCTYPE html>", "<!doctype html>", "<!DOCTYPEX", "<!DOC",
    "---\na: 1\n---\n", "---\n---\n", "---no newline", "+++\na=1\n+++\n",
    "text\n---\na: 1\n---\n", "--- \na: 1\n---\n",
    "*".repeat(19), "*".repeat(20), "_".repeat(25), "*_*_*_*_*_*_*_*_*_*_",
    "a" + "*".repeat(20) + "b", "*".repeat(10) + "x" + "*".repeat(10),
  ];

  var diffs = [];
  DOCS.forEach(function (doc) {
    function compare(label, expected, actual) {
      if (expected !== actual) {
        diffs.push(label + " " + JSON.stringify(doc.slice(0, 40)) +
                   " want " + expected + " got " + actual);
      }
    }
    // Extractors: compare the URLs found, in order. A label may contain a line
    // ending, which the pattern never matched, so a link whose label holds one
    // is the walk's alone; those are asserted as refusals further down.
    var reLinks = Array.from(doc.matchAll(INLINE_LINK_RE)).map(function (m) {
      return m[1] + "|" + m[3];
    });
    var gotLinks = api.inlineLinks(doc).filter(function (l) {
      return doc.slice(l.index, l.urlStart).indexOf("\n") === -1;
    }).map(function (l) { return l.bang + "|" + l.url; });
    compare("inline-links", JSON.stringify(reLinks), JSON.stringify(gotLinks));

    var reAuto = Array.from(doc.matchAll(AUTOLINK_RE)).map(function (m) { return m[1]; });
    var gotAuto = api.autolinks(doc).map(function (a) { return a.url; });
    compare("autolinks", JSON.stringify(reAuto), JSON.stringify(gotAuto));

    // The pattern allowed a definition three columns of indent, which is the
    // rule at the top level of a document. A definition also follows the
    // container markers on its line, each with its own three-column budget,
    // and the walk reads those where the pattern stopped at the first marker.
    // Every URL the pattern found is found by the walk, and over these
    // single-container documents the container pattern says exactly what the
    // walk finds.
    var reRefs = Array.from(doc.matchAll(REF_DEF_RE)).map(function (m) { return m[2]; });
    var gotRefs = api.refDefs(doc).map(function (r) { return r.url; });
    var missing = reRefs.filter(function (u) { return gotRefs.indexOf(u) === -1; });
    compare("ref-defs-subset", JSON.stringify([]), JSON.stringify(missing));
    var reRefsContainer = Array.from(doc.matchAll(REF_DEF_CONTAINER_RE))
      .map(function (m) { return m[2]; });
    compare("ref-defs", JSON.stringify(reRefsContainer), JSON.stringify(gotRefs));

    // The pattern needed a newline after the fence line, so a fence on the
    // last line was invisible to it; the walk sees that one too. Compare the
    // fences the pattern could see against the walk's first N.
    var reFences = Array.from(doc.matchAll(CODE_FENCE_LANG_RE)).map(function (m) { return m[1]; });
    var gotFences = api.codeFenceLangs(doc);
    compare("code-fence-langs", JSON.stringify(reFences),
            JSON.stringify(gotFences.slice(0, reFences.length)));

    compare("raw-html-tag", RAW_HTML_TAG_RE.test(doc), api.hasRawHtmlTag(doc));
    compare("dangerous-tag", DANGEROUS_TAG_RE.test(doc), api.hasDangerousTag(doc));
    // The comment screen is a WIDENING: it closes a comment where a browser
    // does, which includes forms the legacy `-->` pattern never saw. So the
    // pattern's finding must still be a finding, but not the reverse.
    if (HTML_COMMENT_RE.test(doc) && !api.hasHtmlComment(doc)) {
      diffs.push("html-comment missed " + JSON.stringify(doc.slice(0, 40)));
    }
    compare("doctype", DOCTYPE_INLINE_RE.test(doc), api.hasDoctype(doc));
    // The closing fence must END its line, which the pattern never checked —
    // `\n---\s*\n?` can match with nothing after the delimiter at all, so
    // `---not-a-fence` closed the block. Asserted separately below.
    if (!/\n(?:---|\+\+\+)\S/.test(doc)) {
      compare("front-matter",
              FRONT_MATTER_YAML_RE.test(doc) || FRONT_MATTER_TOML_RE.test(doc),
              api.hasFrontMatter(doc, "---") || api.hasFrontMatter(doc, "+++"));
    }
    compare("emphasis-run", EMPH_RUN_RE.test(doc), api.hasLongEmphasisRun(doc));
  });

  check("every markdown extractor and screen agrees with the pattern it " +
        "replaced (" + DOCS.length + " documents)", diffs.length === 0,
        diffs.slice(0, 5).join(" | "));

  // A tightening, in the other direction. `\n---\s*\n?` requires nothing at
  // all after the closing delimiter — both quantifiers can match empty — so a
  // line of ordinary text that merely STARTS with the delimiter closed the
  // block. Every front-matter parser requires the fence to end its line, and
  // reporting front matter in a document that has none is a refusal under a
  // strict profile.
  var FRONT_MATTER_YAML_RE_LOOSE = /^---\s*\n[\s\S]+?\n---\s*\n?/;
  var notAFence = "---\nordinary paragraph\n---not-a-fence\n";
  check("the pattern closed the block on a line that only starts with the fence",
        FRONT_MATTER_YAML_RE_LOOSE.test(notAFence) === true);
  check("the walk requires the closing fence to end its line",
        api.hasFrontMatter(notAFence, "---") === false);
  check("...and a fence followed only by whitespace still closes",
        api.hasFrontMatter("---\nx\n--- \n", "---") === true &&
        api.hasFrontMatter("---\nx\n---\t", "---") === true &&
        api.hasFrontMatter("---\nx\n---", "---") === true);

  // The one deliberate widening: a code fence on the last line, with no
  // newline after it, was invisible to the pattern. A renderer still reads
  // that language tag, so the screen has to see it.
  check("a code fence on the final line is seen",
        JSON.stringify(api.codeFenceLangs("```<script>")) === JSON.stringify(["<script>"]));
  var lastLineFence = b.guardMarkdown.validate("```<script>", { profile: "strict" }).issues;
  check("a code-fence language on the final line is flagged",
        lastLineFence.some(function (i) { return i.kind === "code-fence-lang"; }),
        JSON.stringify(lastLineFence.map(function (i) { return i.kind; })));

  // The other widening: a comment ends where a BROWSER ends it. The legacy
  // `-->` pattern read these as unterminated and reported nothing, so markup
  // a browser runs after the early close went unmentioned.
  [["comment-end-bang", "<!-- x --!>"],
   ["abrupt close", "<!-->"],
   ["abrupt close with dash", "<!--->"]].forEach(function (row) {
    check("an HTML comment closed by " + row[0] + " is seen",
          api.hasHtmlComment(row[1]), JSON.stringify(row[1]));
  });
  check("an unterminated comment is still not a comment",
        api.hasHtmlComment("<!-- never closed") === false);

  // Every scanner has to stay LINEAR. A walk that rescans forward from each
  // candidate is quadratic on a document built entirely of that candidate's
  // prefix, which is a CPU denial of service the single pattern it replaced
  // did not have — `"<a".repeat(2e6)` took over a minute mid-conversion.
  // These budgets are deliberately loose; the failure they catch is orders of
  // magnitude, not percent.
  var PERF_BUDGET_MS = 4000;
  var PERF_CASES = [
    ["hasRawHtmlTag",      "<a".repeat(500000)],
    ["hasDangerousTag",    "<a".repeat(500000)],
    ["hasDoctype",         "<!DOCTYP".repeat(125000)],
    ["inlineLinks",        "[".repeat(500000)],
    ["inlineLinks",        "[a](".repeat(250000)],
    ["autolinks",          "<a:".repeat(330000)],
    ["refDefs",            "[a]:".repeat(250000)],
    ["codeFenceLangs",     "```\n".repeat(250000)],
    ["hasLongEmphasisRun", "*".repeat(19).concat("a").repeat(25000)],
    ["hasHtmlComment",     "<!--".repeat(250000)],
    // The title backtracking has its own worst case: a URL run full of
    // quotes, where each one is a candidate split point.
    ["inlineLinks",        "[a](" + "\"".repeat(200000)],
    ["inlineLinks",        "[a](" + "x\"".repeat(150000) + ")"],
    ["inlineLinks",        "[a](\"t\")".repeat(100000)],
  ];
  var slow = [];
  PERF_CASES.forEach(function (row) {
    var t0 = Date.now();
    api[row[0]](row[1]);
    var ms = Date.now() - t0;
    if (ms > PERF_BUDGET_MS) slow.push(row[0] + " " + ms + "ms");
  });
  check("every markdown scanner stays linear on a prefix-only document",
        slow.length === 0, slow.join(" | "));
  var t0 = Date.now();
  api.hasFrontMatter("---\n" + "x\n".repeat(250000), "---");
  check("the front-matter scan stays linear",
        Date.now() - t0 <= PERF_BUDGET_MS);
}

// A dangerous autolink must not be hidden by wrapping it in a harmless one.
//
// The autolink body scan ran to the closing ">" without stopping at "<", so an
// outer candidate swallowed everything nested inside it. `<a:<javascript:...>>`
// recorded one URL beginning `a:` — a scheme nothing objects to — and the scan
// resumed PAST the inner candidate, which was therefore never examined. The
// scheme filter did not fail; it was never asked.
//
// This renderer escapes autolinks rather than emitting them, so the output here
// is safe either way. The report is what matters: validate() is what an
// operator consults before handing author Markdown to a renderer that DOES
// support autolinks, and a finding that goes missing there is a decision made
// on wrong information. An autolink body cannot contain "<" in CommonMark
// either, so stopping at one is what the grammar already says.
function testNestedAutolinkIsNotHiddenByAnOuterCandidate() {
  var CASES = [
    "<a:<javascript:alert(1)>>",
    "<a:<b:<javascript:alert(1)>>>",
    "<harmless:<vbscript:msgbox(1)>>",
    "text <x:<javascript:alert(1)>> more",
  ];
  CASES.forEach(function (src) {
    var rv = b.guardMarkdown.validate(src);
    var found = (rv.issues || []).some(function (i) { return i.kind === "autolink-scheme"; });
    check("guardMarkdown: nested dangerous autolink is still reported — " +
          JSON.stringify(src), found);
  });

  // The control: the same scheme unwrapped is reported, so the checks above
  // are not passing on a detector that flags everything.
  var plain = b.guardMarkdown.validate("<javascript:alert(1)>");
  check("guardMarkdown: the unwrapped case is still reported",
        (plain.issues || []).some(function (i) { return i.kind === "autolink-scheme"; }));

  // And a genuinely harmless autolink must NOT be reported, or the sweep passes
  // for a detector that has simply started flagging every angle bracket.
  var safe = b.guardMarkdown.validate("<https://example.com/a>");
  check("guardMarkdown: an https autolink is not reported as a bad scheme",
        !(safe.issues || []).some(function (i) { return i.kind === "autolink-scheme"; }));
}

function testLinkLabelWithBracketsStillReachesTheDestination() {
  // Both scanners took the first `]` as the end of a label. A label may hold
  // balanced brackets, and a backslash escapes the next character, so a linked
  // image, an inner bracketed run, or an escaped bracket closed the label early
  // and the outer destination was never extracted: the scheme policy never saw
  // it, validate() reported nothing, and sanitize() returned the input intact.
  var hostile = [
    "[![alt](img.png)](javascript:alert(1))",
    "[a [b] c](javascript:alert(1))",
    "[a\\]b](javascript:alert(1))",
    "[a\\[b](javascript:alert(1))",
    "[a [b] c]: javascript:alert(1)",
    "[a\\]b]: javascript:alert(1)",
  ];
  ["strict", "balanced", "permissive"].forEach(function (profile) {
    hostile.forEach(function (md) {
      var r = b.guardMarkdown.validate(md, { profile: profile });
      check("guardMarkdown refuses " + JSON.stringify(md) + " at " + profile,
            r.ok === false);
    });
  });
  // The same shapes with a safe destination are ordinary links.
  [
    "[![x](i.png)](https://ok.example/)",
    "[a [b] c](https://ok.example/)",
    "[a\\]b](https://ok.example/)",
    "[a [b] c]: https://ok.example/",
  ].forEach(function (md) {
    check("guardMarkdown keeps " + JSON.stringify(md),
          b.guardMarkdown.validate(md, { profile: "strict" }).ok === true);
  });
  // A policy of "allow" graded the reference-definition and autolink rules and
  // also switched them off: at permissive `[ref]: javascript:...` and
  // `<javascript:...>` passed with no issue while the inline rule stayed
  // critical. The knob still sets severity; a dangerous scheme is always
  // reported.
  check("referenceLinkPolicy 'allow' still refuses a dangerous scheme",
        b.guardMarkdown.validate("[r]: javascript:alert(1)",
          { profile: "permissive", referenceLinkPolicy: "allow" }).ok === false);
  check("autolinkSchemePolicy 'allow' still refuses a dangerous scheme",
        b.guardMarkdown.validate("<javascript:alert(1)>",
          { profile: "permissive", autolinkSchemePolicy: "allow" }).ok === false);
  // The inline-link and image rules carried the same escape.
  check("dangerousSchemePolicy 'allow' still refuses a dangerous inline link",
        b.guardMarkdown.validate("[x](javascript:alert(1))",
          { profile: "permissive", dangerousSchemePolicy: "allow" }).ok === false);
  check("imageSchemePolicy 'allow' still refuses a dangerous image source",
        b.guardMarkdown.validate("![x](javascript:alert(1))",
          { profile: "permissive", imageSchemePolicy: "allow" }).ok === false);
  // An unmatched `[` earlier on the line must not hide a link after it. A
  // depth-tracking scan that skipped to the newline on no match did exactly
  // that, and the first-`]` scan it replaced had caught this shape by accident.
  check("guardMarkdown refuses a hostile link after a stray `[` on the line",
        b.guardMarkdown.validate("[ [x](javascript:alert(1))",
          { profile: "strict" }).ok === false);
  check("guardMarkdown refuses a hostile link after an escaped `\\[`",
        b.guardMarkdown.validate("\\[ [x](javascript:alert(1))",
          { profile: "strict" }).ok === false);
  // Brackets are matched in one pass and looked up, not rescanned from every
  // `[`. A run of unmatched openers is the adversarial shape: rescanning from
  // each one is quadratic, and a guard on request data must not be.
  var growth = require("../helpers/growth");
  function scanNested(size) {
    var md = new Array(size + 1).join("[") + "x](javascript:alert(1))";
    // permissive carries the largest link and image caps, so extraction is not
    // truncated and a quadratic term cannot hide behind the cap.
    b.guardMarkdown.validate(md, { profile: "permissive" });
  }
  check("guardMarkdown link scan stays linear in the number of `[`",
        growth.looksSuperlinear(scanNested,
          { small: 4000, large: 16000, threshold: 8 }) === false);
  // Matched nested brackets whose destinations sit at DECREASING offsets: each
  // link's URL starts earlier than the last, so a forward-only cache on the URL
  // scanner misses every time and rescans overlapping suffixes. A 32 KB input
  // of this shape took two seconds. The run end is memoized by position, so an
  // index is scanned once however the destinations are ordered.
  function scanNestedDestinations(size) {
    var md = new Array(size + 1).join("[") + "x]" +
             new Array(size).join("](a") + ")";
    // permissive carries the largest link and image caps, so extraction is not
    // truncated and a quadratic term cannot hide behind the cap.
    b.guardMarkdown.validate(md, { profile: "permissive" });
  }
  check("guardMarkdown stays linear when nested destinations start at decreasing offsets",
        growth.looksSuperlinear(scanNestedDestinations,
          { small: 2000, large: 8000, threshold: 8 }) === false);
  // The same overlap with entity-encoded control padding as the shared suffix.
  // A plain prefix decides the scheme in constant time, but padding forces the
  // normalizing path, and normalizing each overlapping suffix in full is
  // quadratic: 2.7 seconds at n=8000. The scheme is now read by position
  // through a memoized skip of what normalization strips, so the shared
  // padding is walked once for all of the links that start inside it. The
  // memo is one span per destination, and the destinations arrive at
  // DECREASING offsets: each span went in at the front of a sorted array,
  // which is quadratic in the number of links (0.8 s of shifting at 64,000).
  // The span index grows room at its front, so a span below every other is
  // one write. The index is measured on its own below, past the size where
  // the shifting showed, and that is the reading that separates the two
  // indexes (57x against 4x). This end-to-end reading measures 4x for 4x the
  // input on a quiet box and sits at the helper's floor, so under a 64-way
  // smoke its large sample inflates past a bound of 8 on linear work; the
  // bound is 12, which a quadratic term still crosses.
  function scanPaddedDestinations(size) {
    var md = new Array(size + 1).join("[") + "x]" +
             new Array(size).join("](&#1;a") + ")";
    b.guardMarkdown.validate(md, { profile: "permissive" });
  }
  check("guardMarkdown stays linear when overlapping destinations share entity padding",
        growth.looksSuperlinear(scanPaddedDestinations,
          { small: 2000, large: 8000, threshold: 12 }) === false);
  function fillSpanIndexFromTheFront(size) {
    var index = b.guardMarkdown._spanIndexForTest();
    for (var at = size * 4; at > 0; at -= 4) index.add(at, at + 2, at + 3);
  }
  check("the span index takes a span below every other in constant time",
        growth.looksSuperlinear(fillSpanIndexFromTheFront,
          { small: 8000, large: 64000, threshold: 12 }) === false);
  var spans = b.guardMarkdown._spanIndexForTest();
  spans.add(40, 44, 45);
  spans.add(10, 12, 13);
  spans.add(20, 22, 23);
  spans.add(13, 19, 23);
  check("the span index answers a position inside a span with the span's value after front inserts",
        spans.find(41) === 45 && spans.find(11) === 13 && spans.find(15) === 23 &&
        spans.find(22) === 23 && spans.find(9) === undefined && spans.find(30) === undefined);
  // Nested links that all end at one endpoint, followed by a long run of
  // whitespace before the closing paren. Whether a link closes there is a
  // function of the endpoint alone, but it was recomputed per link, and each
  // recomputation skipped the whole run: 2000 links over 1 MiB took seconds.
  // The answer is memoized per endpoint, so the run is skipped once.
  var SPACE_TAIL = new Array(256 * 1024 + 1).join(" ");
  function scanSharedEndpoint(size) {
    var md = new Array(size + 1).join("[") + "x]" +
             new Array(size).join("](a") + SPACE_TAIL + ")";
    b.guardMarkdown.validate(md, { profile: "balanced" });
  }
  check("guardMarkdown stays linear when nested links share an endpoint before a long tail",
        growth.looksSuperlinear(scanSharedEndpoint,
          { small: 500, large: 2000, threshold: 8 }) === false);
  // Every parenthesized title opener resolves to the one closing paren, and
  // the whitespace run after that closer was rescanned once per opener. The
  // document is accepted, so the cost is paid for a request that passes.
  function scanSharedTitleCloser(size) {
    var md = "[x](" + new Array(size + 1).join("(") + " t)" +
             new Array(size + 1).join(" ") + "x";
    b.guardMarkdown.validate(md, { profile: "balanced" });
  }
  check("guardMarkdown stays linear when title openers share a closer before a space run",
        growth.looksSuperlinear(scanSharedTitleCloser,
          { small: 8000, large: 32000, threshold: 8 }) === false);
  check("the shared-closer document is accepted",
        b.guardMarkdown.validate("[x](" + "(".repeat(200) + " t)" + " ".repeat(200) + "x",
          { profile: "balanced" }).issues.length === 0);
  // The delimiter lookup that made the walk above linear must not be a table
  // the size of the document. Three of those on a 64 MiB permissive body are
  // 768 MiB. This is a memory assertion; a timing one passes either way. A
  // typed array's backing store is counted in `arrayBuffers`, not `heapUsed`:
  // measured against the build that allocated the tables, this 4 MiB document
  // moved arrayBuffers by 48 MiB and heapUsed by 4.5 MiB, and the fixed build
  // moves arrayBuffers by 0 and heapUsed by the same 4.5 MiB. An assertion on
  // heapUsed passed against both.
  var filler = "lorem ipsum dolor sit amet ".repeat(4 * 1024 * 1024 / 27);
  var wide = filler + "\n[a](u \"t\") [b](u 't') [c](u (t))\n";
  var before = process.memoryUsage().arrayBuffers;
  b.guardMarkdown.validate(wide, { profile: "permissive" });
  var grewMiB = (process.memoryUsage().arrayBuffers - before) / (1024 * 1024);
  check("title-delimiter lookups do not allocate per character of the document",
        grewMiB < 8, "a 4 MiB document grew arrayBuffers by " + grewMiB.toFixed(1) + " MiB");
  // Reading the scheme by position has to reach the same verdict the whole-
  // string normalization did, on every padding and encoding it strips.
  [
    "[x](&#1;&#1;&#1;javascript:alert(1))",
    "[x](" + String.fromCharCode(1, 1) + "javascript:alert(1))",
    "[x](j&Tab;avascript:alert(1))",
    "[x](j&NewLine;avascript:alert(1))",
    "[x](&#x6A;avascript:alert(1))",
    "[x](&#106;&#97;vascript:alert(1))",
    "[x](" + String.fromCharCode(0x200B) + "javascript:alert(1))",
    "[x]( javascript:alert(1))",
    "[x](JAVASCRIPT:alert(1))",
  ].forEach(function (md) {
    check("guardMarkdown refuses a padded or encoded scheme " + JSON.stringify(md),
          b.guardMarkdown.validate(md, { profile: "permissive" }).ok === false);
  });
  [
    "[x](https://ok.example/)",
    "[x](&#x68;ttps://ok.example/)",
    "[x](&#1;https://ok.example/)",
    "[x](/relative/path)",
    "[x](mailto:a@ok.example)",
  ].forEach(function (md) {
    check("guardMarkdown keeps a safe destination " + JSON.stringify(md),
          b.guardMarkdown.validate(md, { profile: "permissive" }).ok === true);
  });
  // sanitize() is the output path, so a refusal there has to hold too.
  var threw = false;
  try { b.guardMarkdown.sanitize("[![alt](img.png)](javascript:alert(1))", { profile: "strict" }); }
  catch (e) { threw = !!(e && e.isGuardMarkdownError); }
  check("guardMarkdown.sanitize refuses the linked-image bypass", threw);
}

async function testEncodedAndZeroWidthSchemesAreRefused() {
  // The whole-string decoder runs numeric references in one pass and named
  // references in a second pass over the result, so a numeric reference that
  // yields an ampersand completes a named reference with the text after it.
  // Reading by position has to reproduce that order, or `&#38;colon;` reads as
  // an ampersand plus text where the renderer reads a colon.
  ["strict", "balanced", "permissive"].forEach(function (profile) {
    ["[x](javascript&#38;colon;alert(1))", "[x](j&#38;Tab;avascript:alert(1))"]
      .forEach(function (md) {
        check("guardMarkdown refuses " + JSON.stringify(md) + " at " + profile,
              b.guardMarkdown.validate(md, { profile: profile }).ok === false);
      });
  });
  // The first pass does not rescan what it produced, so an ampersand from a
  // numeric reference followed by another numeric reference stays literal and
  // the destination is not a scheme. The positional reader agrees.
  check("guardMarkdown keeps [x](javascript&#38;#58;alert(1)), which decodes to no scheme",
        b.guardMarkdown.validate("[x](javascript&#38;#58;alert(1))",
          { profile: "permissive" }).ok === true);
  // The positional reader stands in for whole-string normalization, so its
  // verdict is checked against that normalization rather than against a
  // hardcoded answer: the expected value is computed from the reference path
  // in this test, for the shapes where the two are easiest to get to differ.
  var cc = b.codepointClass;
  var SCHEMES = ["javascript", "vbscript", "livescript", "mocha", "view-source",
                 "data", "jar", "blob", "feed", "tel", "facetime", "facetime-audio"];
  function referenceSaysDangerous(url) {
    var s = cc.stripUrlSchemeWhitespace(cc.decodeMarkupEntities(url.trim())).toLowerCase();
    return SCHEMES.some(function (name) {
      if (s.slice(0, name.length) !== name) return false;
      var j = name.length;
      while (j < s.length && cc.inRanges(s.charCodeAt(j), cc.WHITESPACE_RANGES)) j += 1;
      return s.charAt(j) === ":";
    });
  }
  [
    "java&nbsp;script:alert(1)",
    "javascript&co&#108;on;alert(1)",
    "javascript&#38;co&#108;on;alert(1)",
    "javascript&amp;colon;alert(1)",
    "javascript&#38;colon;alert(1)",
    "javascript&#38;&#99;&#111;&#108;&#111;&#110;&#59;alert(1)",
    "&#0000106;avascript:alert(1)",
    "javascript&#38;#58;alert(1)",
    "j&#38;Tab;avascript:alert(1)",
    // Whitespace between the name and its colon is skipped without bound by
    // the reference, so a run of it must not consume the bounded prefix; a
    // run inside the name is kept and is not a scheme.
    "javascript" + new Array(41).join("&#32;") + ":alert(1)",
    "javascript" + new Array(41).join("&nbsp;") + ":alert(1)",
    "java" + new Array(41).join("&#32;") + "script:alert(1)",
    "javascript&#9;&#9;&#9;:alert(1)",
  ].forEach(function (url) {
    var expectOk = !referenceSaysDangerous(url);
    check("positional scheme reading agrees with whole-string normalization on " +
          JSON.stringify(url) + " (ok=" + expectOk + ")",
          b.guardMarkdown.validate("[x](" + url + ")", { profile: "permissive" }).ok === expectOk);
  });
  // The bracket index is bounded before it is built. A document of brackets
  // and nothing else once built an index proportional to its length, and past
  // V8's map limit threw instead of answering. Over the cap the index is not
  // built and the document is refused, so a hostile link among the brackets
  // cannot ride through an unextracted scan as a clean verdict.
  var flood = new Array(70001).join("[]");
  var capped = b.guardMarkdown.validate(flood, { profile: "permissive" });
  check("guardMarkdown refuses a document past the bracket opener cap",
        capped.ok === false &&
        capped.issues.some(function (i) { return i.kind === "delimiter-cap"; }));
  check("guardMarkdown refuses a hostile link hidden past the bracket opener cap",
        b.guardMarkdown.validate(flood + "[x](javascript:alert(1))",
          { profile: "permissive" }).ok === false);
  var under = new Array(60001).join("[]");
  check("guardMarkdown accepts a bracket-only document under the cap",
        b.guardMarkdown.validate(under, { profile: "permissive" }).ok === true);
  // Brackets inside a code span are literal to CommonMark and take no part in
  // label matching. A matcher that paired them let a backtick-quoted `[` in an
  // image label take the closing bracket, so the image was extracted as a
  // plain link and never counted against maxImages; a quoted `]` likewise
  // closed an outer label early and hid its destination.
  var tick = String.fromCharCode(0x60);
  var spanImage = "![a " + tick + "[" + tick + " b](https://example.com/a.png)";
  var twoImages = b.guardMarkdown.validate(spanImage + "\n" + spanImage + "\n",
    { profile: "strict", maxImages: 1 });
  check("an image whose label holds a code-span bracket still counts toward maxImages",
        twoImages.ok === false &&
        twoImages.issues.some(function (i) { return i.kind === "image-cap"; }));
  [
    "[x " + tick + "]" + tick + " ](javascript:alert(1))",
    "[![a](i.png) " + tick + "]" + tick + "](javascript:alert(1))",
  ].forEach(function (md) {
    check("guardMarkdown refuses a hostile link whose label quotes a bracket in a code span " +
          JSON.stringify(md),
          b.guardMarkdown.validate(md, { profile: "permissive" }).ok === false);
  });
  check("guardMarkdown keeps a benign link whose label is a bracket in a code span",
        b.guardMarkdown.validate("[" + tick + "[" + tick + "](https://ok.example/)",
          { profile: "strict" }).ok === true);
  // A backtick run with no closing run of the same length is literal text, not
  // the start of a code span. A matcher that treated every run as an opener
  // ignored every bracket after a stray backtick, so a hostile link that
  // followed one was never extracted: validate() passed it and sanitize()
  // returned it unchanged.
  var stray = "[a " + tick + " b](javascript:alert(1))";
  check("guardMarkdown refuses a hostile link after an unmatched backtick",
        b.guardMarkdown.validate(stray, { profile: "strict" }).ok === false);
  var strayThrew = false;
  try { b.guardMarkdown.sanitize(stray, { profile: "strict" }); }
  catch (e) { strayThrew = e.code === "markdown.link-scheme"; }
  check("guardMarkdown sanitize refuses a hostile link after an unmatched backtick",
        strayThrew);
  [
    "[a " + tick + tick + " b " + tick + " c](javascript:alert(1))",
    "[x " + tick + " a " + tick + tick + " b " + tick + " c " + tick + tick + "](javascript:alert(1))",
  ].forEach(function (md) {
    check("guardMarkdown refuses a hostile link whose label holds unmatched backtick runs " +
          JSON.stringify(md),
          b.guardMarkdown.validate(md, { profile: "strict" }).ok === false);
  });
  // Pairing backtick runs is one pass over the line, so a document that is
  // nothing but code spans costs the same per byte as one with none.
  var growth = require("../helpers/growth");
  function scanBacktickPairs(n) {
    var parts = new Array(n + 1).join(tick + " " + tick + " ");
    b.guardMarkdown.validate(parts, { profile: "permissive" });
  }
  check("guardMarkdown stays linear on a document of back-to-back code spans",
        growth.looksSuperlinear(scanBacktickPairs,
          { small: 4000, large: 16000, threshold: 8 }) === false);
  // A code span binds tighter than a link in CommonMark, but a link-first
  // renderer reads a backtick inside a destination as part of the URL, so a
  // span fabricated from that backtick hid the hostile link after it. Links
  // and reference definitions are extracted both with and without code spans
  // and every match found either way is inspected. An escaped backtick cannot
  // open a span but does close one, as in cmark, whose closer scan is raw.
  var bs = String.fromCharCode(0x5C);
  [
    "[a](https://foo/" + tick + ") [x](javascript:a) " + tick,
    "[x " + bs + tick + " ](javascript:alert(1)) " + tick,
    "[x " + tick + "a" + bs + tick + " ](javascript:alert(1)) " + tick,
  ].forEach(function (md) {
    check("guardMarkdown refuses a hostile link a fabricated code span would hide " +
          JSON.stringify(md),
          b.guardMarkdown.validate(md, { profile: "strict" }).ok === false);
  });
  var hiddenRef = "[a](https://foo/" + tick + ")\n\n[r]: javascript:alert(1)\n\n[x][r] " + tick;
  var hiddenRefResult = b.guardMarkdown.validate(hiddenRef, { profile: "strict" });
  check("guardMarkdown refuses a reference definition a fabricated code span would hide",
        hiddenRefResult.ok === false &&
        hiddenRefResult.issues.some(function (i) { return i.kind === "reference-link-scheme"; }));
  check("guardMarkdown keeps a benign link whose label is an escaped backtick",
        b.guardMarkdown.validate("[" + bs + tick + "](https://ok.example/)",
          { profile: "strict" }).ok === true);
  check("guardMarkdown keeps a benign link followed by a code span",
        b.guardMarkdown.validate("[a](https://ok.example/) " + tick + "code" + tick,
          { profile: "strict" }).ok === true);
  // Unmatched runs of many distinct lengths stay pending while later spans
  // pair, and clearing a pending opener by deleting its map entry cost a
  // rehash proportional to the pending count on every span: 4 MB of this
  // shape took five seconds. Pending openers are cleared in place instead.
  function scanPendingLengths(n) {
    var parts = ["["];
    var lengths = Math.max(2, Math.round(n / 250));
    for (var len = 2; len <= lengths; len += 1) parts.push(new Array(len + 1).join(tick) + " ");
    parts.push(new Array(n + 1).join(tick + "x" + tick + " "));
    b.guardMarkdown.validate(parts.join(""), { profile: "permissive" });
  }
  check("guardMarkdown stays linear on code spans after many unmatched run lengths",
        growth.looksSuperlinear(scanPendingLengths,
          { small: 25000, large: 100000, threshold: 8 }) === false);
  // Code spans are exactly CommonMark's. An earlier opener that finds a closer
  // wins over any pair inside it, so a greedy pairing that emitted the inner
  // pair first left the enclosing span unapplied and a quoted bracket live.
  // An escaped backtick removes one backtick from an opener candidate, while a
  // closer is matched on the raw run. Labels and spans cross a line ending but
  // not a blank line, which ends the paragraph.
  var spanImage2 = "![a " + tick + " " + tick + tick + "x" + tick + tick + " [ " + tick + "](https://a)";
  var twoImages2 = b.guardMarkdown.validate(spanImage2 + "\n" + spanImage2 + "\n",
    { profile: "strict", maxImages: 1 });
  check("an image whose label holds an enclosing code span still counts toward maxImages",
        twoImages2.ok === false &&
        twoImages2.issues.some(function (i) { return i.kind === "image-cap"; }));
  [
    "[x " + tick + tick + " ] " + tick + " b " + tick + " c " + tick + tick + " ](javascript:alert(1))",
    "[x " + bs + tick + tick + " ] " + tick + " ](javascript:alert(1))",
    "[x " + tick + tick + " ] " + bs + tick + tick + " ](javascript:alert(1))",
    "[x\ny](javascript:alert(1))",
    "![x\ny](javascript:alert(1))",
    "[x " + tick + "\n]" + tick + " ](javascript:alert(1))",
    "[x " + tick + "\n\n[y](javascript:alert(1)) " + tick,
  ].forEach(function (md) {
    check("guardMarkdown refuses a hostile link whose bracket a code span or line ending hid " +
          JSON.stringify(md),
          b.guardMarkdown.validate(md, { profile: "strict" }).ok === false);
  });
  var twoLineRef = b.guardMarkdown.validate("[r\nq]: javascript:alert(1)\n\n[x][r q]",
    { profile: "strict" });
  check("guardMarkdown refuses a reference definition whose label spans two lines",
        twoLineRef.ok === false &&
        twoLineRef.issues.some(function (i) { return i.kind === "reference-link-scheme"; }));
  [
    "[x\n\ny](javascript:alert(1))",
    "[x " + tick + "\n\n](javascript:alert(1)) " + tick,
  ].forEach(function (md) {
    check("guardMarkdown reads no link across a blank line " + JSON.stringify(md),
          b.guardMarkdown.validate(md, { profile: "strict" }).ok === true);
  });
  check("guardMarkdown keeps a benign two-line label",
        b.guardMarkdown.validate("[x\ny](https://ok.example/)", { profile: "strict" }).ok === true);
  check("guardMarkdown keeps a benign label holding an enclosing code span with an inner pair",
        b.guardMarkdown.validate("[" + tick + tick + " a " + tick + " b " + tick + " " + tick + tick +
          "](https://ok.example/)", { profile: "strict" }).ok === true);
  // A document over the opener cap was never inspected, so the gate refuses
  // it under every profile rather than serving or sanitizing it.
  var floodGate = b.guardMarkdown.gate({ profile: "permissive" });
  var floodVerdict = await floodGate.check({
    contentType: "text/markdown",
    bytes:       Buffer.from(flood + "[x](javascript:alert(1))", "utf8"),
  });
  check("guardMarkdown gate refuses a document over the bracket opener cap",
        floodVerdict.ok === false && floodVerdict.action === "refuse");
  // Autolinks and raw HTML tags bind tighter than links, as code spans do, so
  // a bracket inside one is literal. A matcher that paired it let an autolink
  // holding `[` in an image label take the image's closing bracket, so the
  // image escaped the cap, and a `]` inside a tag attribute or a comment
  // closed a label early and hid its destination. The first construct in text
  // order wins: a backtick inside an autolink is literal, and an autolink
  // inside a code span is literal.
  var autoImage = "![<https://example.com/[>](https://example.com/image.png)";
  var twoAutoImages = b.guardMarkdown.validate(autoImage + "\n" + autoImage + "\n",
    { profile: "permissive", maxImages: 1 });
  check("an image whose label holds an autolink bracket still counts toward maxImages",
        twoAutoImages.ok === false &&
        twoAutoImages.issues.some(function (i) { return i.kind === "image-cap"; }));
  [
    "[x <https://a/]> ](javascript:alert(1))",
    "[x <span title=\"]\"> ](javascript:alert(1))",
    "[x <a title=\"< ]\"> ](javascript:alert(1))",
    "[x <!-- ] --> ](javascript:alert(1))",
    "[x <https://a/" + tick + "]> ](javascript:alert(1)) " + tick,
    "[x " + tick + "<https://a/]>" + tick + " ](javascript:alert(1))",
  ].forEach(function (md) {
    var r = b.guardMarkdown.validate(md, { profile: "permissive" });
    check("guardMarkdown refuses a hostile link whose bracket an autolink or tag hid " +
          JSON.stringify(md),
          r.ok === false && r.issues.some(function (i) { return i.kind === "link-scheme"; }));
  });
  [
    "[<https://a/[>](https://ok.example/)",
    "[x <b>bold</b>](https://ok.example/)",
    "[x </b ]> ](https://ok.example/)",
    "[x < span ]> ](https://ok.example/)",
  ].forEach(function (md) {
    check("guardMarkdown keeps a benign link around an autolink or tag " + JSON.stringify(md),
          b.guardMarkdown.validate(md, { profile: "permissive" }).ok === true);
  });
  // A tag that never closes is scanned once, however many tag starts follow
  // inside its quoted values, so a flood of them stays linear.
  function scanNestedTagStarts(n) {
    b.guardMarkdown.validate("[" + new Array(n + 1).join("<a b=\"<c d=\" e=\""),
      { profile: "permissive" });
  }
  check("guardMarkdown stays linear on a flood of unclosed nested tag starts",
        growth.looksSuperlinear(scanNestedTagStarts,
          { small: 10000, large: 40000, threshold: 8 }) === false);
  // The two readings are unioned by appending the second to the first, so the
  // combined list was not in document order. The scheme reader walks it by
  // position through a forward-only index of what survives normalization, and
  // a backwards step made that index rescan from the start: a document that
  // alternates a plain link with one whose opener sits inside a code span,
  // each destination carrying zero-width padding so the positional path is
  // taken, went 118 ms to 7112 ms over an 8x size step while the same links
  // without the code spans stayed linear. The union is sorted back into
  // document order.
  function paddedUrl() {
    var pad = String.fromCharCode(0x200B);
    var o = "";
    for (var q = 0; q < 20; q += 1) o += "a" + pad;
    return "https:" + pad + "//" + o;
  }
  function scanInterleavedUnion(n) {
    var s = "";
    for (var q = 0; q < n; q += 1) {
      s += "[a](" + paddedUrl() + ")\n";
      s += tick + "[" + tick + "b](" + paddedUrl() + ")\n";
    }
    b.guardMarkdown.validate(s, { profile: "permissive" });
  }
  check("guardMarkdown stays linear when both link readings interleave",
        growth.looksSuperlinear(scanInterleavedUnion,
          { small: 500, large: 2000, threshold: 8 }) === false);
  // CommonMark gives a link title three delimiter pairs. The scanner knew only
  // the double quote, so with a `'…'` or `(…)` title no closing paren was
  // found, the opener was dropped, and the destination was never handed to the
  // scheme check at all: `[x](javascript:1 'y')` validated clean and sanitize
  // returned it unchanged at every profile, while its double-quoted twin was
  // critical. A `<…>` destination may also hold spaces, which the run scanner
  // stops on, so it is read to its own closing bracket.
  [
    ["[x](javascript:1 'y')", "link-scheme"],
    ["[x](javascript:1 (y))", "link-scheme"],
    ["![x](javascript:1 'y')", "image-scheme"],
    ["[x](data:text/html;base64,PHNjcmlwdD4= 'y')", "link-scheme"],
    ["[x](<javascript:alert(1) >)", "link-scheme"],
    ["[x](<javascript: alert(1)>)", "link-scheme"],
  ].forEach(function (row) {
    ["strict", "balanced", "permissive"].forEach(function (profile) {
      var r = b.guardMarkdown.validate(row[0], { profile: profile });
      check("guardMarkdown inspects the destination of " + JSON.stringify(row[0]) +
            " at " + profile,
            r.ok === false &&
            r.issues.some(function (i) { return i.kind === row[1]; }));
    });
  });
  [
    "[x](https://ok.example/ 'Title')",
    "[x](https://ok.example/ (Title))",
    "[x](https://ok.example/a_(b)_c)",
  ].forEach(function (md) {
    check("guardMarkdown keeps a benign titled link " + JSON.stringify(md),
          b.guardMarkdown.validate(md, { profile: "strict" }).ok === true);
  });
  // A backslash escapes the delimiter inside a title, so `"a\"b"` is one title
  // and the link closes after it. Taking the escaped copy as the close dropped
  // the link, and its destination, from the scheme check.
  var BSL = String.fromCharCode(92);
  var escapedTitles = [];
  [
    '[x](javascript:alert%281%29 "a' + BSL + '"b")',
    "[x](javascript:alert%281%29 'a" + BSL + "'b')",
    "[x](javascript:alert%281%29 (a" + BSL + ")b))",
    '[x](javascript:alert%281%29 "a' + BSL + BSL + BSL + '"b")',
  ].forEach(function (md) {
    var ks = b.guardMarkdown.validate(md, { profile: "strict" })
      .issues.map(function (i) { return i.kind; });
    if (ks.indexOf("link-scheme") === -1) escapedTitles.push(md);
  });
  check("an escaped delimiter inside a title does not close it",
        escapedTitles.length === 0, escapedTitles.join(" | "));
  check("a doubled backslash before the delimiter is a literal backslash",
        b.guardMarkdown.validate('[x](https://ok "a' + BSL + BSL + '")', { profile: "strict" }).ok);
  check("a benign title with escaped quotes is accepted",
        b.guardMarkdown.validate('[x](https://ok "say ' + BSL + '"hi' + BSL + '"")',
                                 { profile: "strict" }).ok);
  // Accepting `(` as a title delimiter put a `)` search inside the loop that
  // steps backwards through a destination, so an unterminated destination made
  // of parentheses rescanned the same suffix from every position: 400 KB took
  // 1.58 s. Each delimiter keeps one scanned interval, so a query inside it
  // is answered without a scan and a query below it extends it.
  function scanParenDestination(n) {
    b.guardMarkdown.validate("[x](https:" + new Array(n + 1).join("("),
      { profile: "permissive" });
  }
  check("guardMarkdown stays linear on an unterminated parenthesized destination",
        growth.looksSuperlinear(scanParenDestination,
          { small: 50000, large: 200000, threshold: 8 }) === false);
  // The per-position memos behind that walk must not hold a heap entry per
  // character either: keyed as Maps they cost 141 bytes per input character,
  // which is 9 GB at the permissive size cap. Measured without a collection
  // the walk now costs about 8 bytes per character of collectible garbage,
  // so a bound of 32 separates the two by a wide margin either way.
  var wideParen = "[x](https:" + new Array(2000001).join("(");
  var heapBefore = process.memoryUsage().heapUsed;
  b.guardMarkdown.validate(wideParen, { profile: "permissive" });
  var perChar = (process.memoryUsage().heapUsed - heapBefore) / wideParen.length;
  check("the link walk does not hold a heap entry per input character",
        perChar < 32, perChar.toFixed(1) + " bytes per character");
  // The info string reaches a class attribute in renderers that interpolate it,
  // and the rule only fired on a fence at column 0. CommonMark allows up to
  // three columns of indent and a fence inside a block quote; four columns
  // opens an indented code block, where the backticks are literal text. A tab
  // advances to the next stop of four, so a tab-led line is that code block
  // and is covered by testBlockIndentationIsMeasuredInColumns.
  var infoFence = "```js\" onerror=\"alert(1)\nbody\n```\n";
  [" ", "   ", "> ", ">> ", ">   "].forEach(function (lead) {
    var r = b.guardMarkdown.validate(lead + infoFence, { profile: "strict" });
    check("guardMarkdown inspects the info string of a fence led by " +
          JSON.stringify(lead),
          r.ok === false &&
          r.issues.some(function (i) { return i.kind === "code-fence-lang"; }));
  });
  check("guardMarkdown reads no fence in a four-space indented code block",
        b.guardMarkdown.validate("    " + infoFence, { profile: "strict" }).ok === true);
  // A named reference has to reach the same verdict as the character it names.
  // `&hyphen;` decoded to U+002D HYPHEN-MINUS instead of U+2010 HYPHEN, so it
  // manufactured `view-source:` out of a character that cannot form a scheme
  // and refused `[a](view&hyphen;source:x)` while accepting the spelling a
  // browser actually produces.
  [["hyphen", 0x2010], ["nbsp", 0x00A0]].forEach(function (row) {
    var entity = "[a](view&" + row[0] + ";source:x)";
    var literal = "[a](view" + String.fromCharCode(row[1]) + "source:x)";
    ["strict", "permissive"].forEach(function (profile) {
      check("guardMarkdown reads &" + row[0] + "; as the character it names at " + profile,
            b.guardMarkdown.validate(entity, { profile: profile }).ok ===
            b.guardMarkdown.validate(literal, { profile: profile }).ok);
    });
  });
  check("guardMarkdown still refuses a colon written as a named reference",
        b.guardMarkdown.validate("[a](javascript&colon;alert(1))",
          { profile: "permissive" }).ok === false);
  // Two readings can assign different destinations to one opener. Both are
  // inspected, but the construct is one construct, so the caps are not spent
  // twice on it and a document with one image is not refused at maxImages 1.
  var dualImage = "![a " + tick + "](https://inner.example)" + tick + " ](https://outer.example)";
  check("one image read two ways counts once against maxImages",
        b.guardMarkdown.validate(dualImage, { profile: "strict", maxImages: 1 }).ok === true);
  check("one link read two ways counts once against maxLinks",
        b.guardMarkdown.validate("[a " + tick + "](https://inner.example)" + tick +
          " ](https://outer.example)", { profile: "strict", maxLinks: 1 }).ok === true);
  check("one reference definition read two ways counts once against maxRefDefs",
        b.guardMarkdown.validate("[a " + tick + "]: https://inner.example\n" + tick +
          " ]: https://outer.example\n\n[x][a]",
          { profile: "strict", maxRefDefs: 1 }).ok === true);
  [
    "[a " + tick + "](javascript:alert(1))" + tick + " ](https://outer.example)",
    "[a " + tick + "](https://inner.example)" + tick + " ](javascript:alert(1))",
  ].forEach(function (md) {
    check("guardMarkdown inspects both destinations one opener is read with " +
          JSON.stringify(md),
          b.guardMarkdown.validate(md, { profile: "strict" }).ok === false);
  });
  var dualRefHostile = b.guardMarkdown.validate("[a " + tick + "]: javascript:alert(1)\n" +
    tick + " ]: https://outer.example\n\n[x][a]", { profile: "strict" });
  check("guardMarkdown inspects both destinations one reference label is read with",
        dualRefHostile.ok === false &&
        dualRefHostile.issues.some(function (i) { return i.kind === "reference-link-scheme"; }));
  var twoImages3 = b.guardMarkdown.validate(spanImage + "\n" + spanImage + "\n",
    { profile: "strict", maxImages: 2 });
  check("two distinct images still count separately",
        twoImages3.ok === true);
  // A zero-width character inside the scheme of a reference definition is
  // stripped by normalization and by a browser, so the plain-prefix shortcut
  // must not treat it as plain text. validate() folded it away and hid the
  // gap; the gate's disposition exposed it as sanitize rather than refuse.
  var zw = String.fromCharCode(0x200B);
  var refDef = "[r]: java" + zw + "script:alert(1)\n\n[x][r]\n";
  check("guardMarkdown refuses a zero-width character inside a reference scheme",
        b.guardMarkdown.validate(refDef, { profile: "balanced" }).ok === false);
  var gate = b.guardMarkdown.gate({ profile: "balanced" });
  var verdict = await gate.check({
    contentType: "text/markdown",
    bytes:       Buffer.from(refDef, "utf8"),
  });
  check("the balanced gate refuses that reference rather than sanitizing it",
        verdict.action === "refuse");
}

async function run() {
  await testEncodedAndZeroWidthSchemesAreRefused();
  testLinkLabelWithBracketsStillReachesTheDestination();
  testMarkdownExtractorsAgreeWithThePatternsTheyReplaced();
  testGuardMarkdownSurface();
  testGuardMarkdownRegistryParity();
  testGuardMarkdownDangerousScheme();
  testGuardMarkdownEntityBypass();
  testGuardMarkdownAutolinkScheme();
  testNestedAutolinkIsNotHiddenByAnOuterCandidate();
  testGuardMarkdownReferenceLinkSmuggling();
  testGuardMarkdownImageScheme();
  testGuardMarkdownDangerousTag();
  testGuardMarkdownWhitespaceTagBypass();
  testGuardMarkdownHtmlComment();
  testGuardMarkdownFrontMatter();
  testGuardMarkdownCodeFenceLang();
  testGuardMarkdownEmphasisRun();
  testGuardMarkdownDoctype();
  testGuardMarkdownBidiNull();
  testGuardMarkdownClean();
  testGuardMarkdownLinkCap();
  testGuardMarkdownListDepthCap();
  testGuardMarkdownBlockquoteDepthCap();
  testGuardMarkdownByteCap();
  testGuardMarkdownSanitizeRefusesCritical();
  testGuardMarkdownSanitizeRefusesBadInput();
  testGuardMarkdownCompliancePosture();
  testBlockIndentationIsMeasuredInColumns();
  testContainerMarkersPrecedeADefinitionOrFence();
  testADefinitionScanThatFailsLeavesItsLinesToTheBlockReader();
  await testGuardMarkdownGate();
}

function testBlockIndentationIsMeasuredInColumns() {
  var TAB = String.fromCharCode(9);
  function kinds(src, profile) {
    return b.guardMarkdown.validate(src, { profile: profile || "balanced" })
      .issues.map(function (i) { return i.kind; });
  }
  function isFence(src) { return kinds(src).indexOf("code-fence-lang") !== -1; }

  // A tab advances to the next column stop of four, so a line opening with one
  // is indented code and the three characters after it are not a fence.
  check("a tab before a fence marker is indented code",
        !isFence(TAB + '~~~foo"bar'), JSON.stringify(kinds(TAB + '~~~foo"bar')));
  check("four spaces before a fence marker is indented code",
        !isFence('    ~~~foo"bar'));
  check("three spaces before a fence marker still opens a fence",
        isFence('   ~~~foo"bar'));
  check("an unindented tilde fence still opens a fence", isFence('~~~foo"bar'));
  check("an unindented backtick fence still opens a fence", isFence('```foo"bar'));
  check("a fence inside a block quote still opens a fence", isFence('> ```foo"bar'));
  // One space after `>` belongs to the marker, not to the indentation, so
  // `>` followed by four spaces is one marker space and three of indent, which
  // is still a fence. Counting all four made it indented code and let the
  // info string past the check.
  check("a block-quote marker's optional space is not fence indentation",
        isFence('>    ```foo"bar'));
  check("nor for nested markers", isFence('>>    ```foo"bar'));
  // A tab after the marker expands to the next stop of four; one of its
  // columns is the marker's space and the rest are indentation.
  check("a tab after the marker leaves two columns of indent, so a fence follows",
        isFence(">" + TAB + '```foo"bar'));
  check("a tab after the marker plus three spaces is five columns: indented code",
        !isFence(">" + TAB + '   ```foo"bar'));
  check("a tab after the marker plus one space is three columns: a fence",
        isFence(">" + TAB + ' ```foo"bar'));
  check("a fifth space after the marker is indented code", !isFence('>     ```foo"bar'));
  // The columns a tab leaves over indent the NEXT marker, which consumes
  // them; they do not carry through to the fence.
  check("nested markers each with a tab still open a fence",
        isFence(">" + TAB + ">" + TAB + '~~~foo"bar'));
  check("nested markers with a tab then three spaces are indented code",
        !isFence(">" + TAB + ">" + TAB + '   ~~~foo"bar'));

  // A reference definition's indent budget is relative to the block that
  // contains it. At the top level four columns is indented code; inside a
  // list item the item's content column is where counting starts.
  function refKinds(src) {
    return b.guardMarkdown.validate(src, { profile: "strict" })
      .issues.map(function (i) { return i.kind; });
  }
  var def = "[x]: javascript:alert(1)";
  [
    { name: "unindented", src: def },
    { name: "three spaces", src: "   " + def },
    { name: "inside a list item", src: "- item\n\n" + TAB + def + "\n\n[x]" },
    { name: "inside a block quote", src: "> " + def },
    { name: "after blank lines", src: "\n\n\n" + def },
  ].forEach(function (c) {
    check("a reference definition " + c.name + " is read",
          refKinds(c.src).indexOf("reference-link-scheme") !== -1,
          JSON.stringify(refKinds(c.src)));
  });
  [
    { name: "four spaces", src: "    " + def },
    { name: "a tab", src: TAB + def },
  ].forEach(function (c) {
    check("a reference definition after " + c.name + " at the top level is code",
          refKinds(c.src).indexOf("reference-link-scheme") === -1,
          JSON.stringify(refKinds(c.src)));
  });

  var refused = false;
  try {
    b.guardMarkdown.sanitize("- item\n\n" + TAB + def + "\n\n[x]", { profile: "strict" });
  } catch (e) { refused = e.code === "markdown.reference-link-scheme"; }
  check("sanitize refuses a dangerous definition rather than preserving it", refused);
}

function testContainerMarkersPrecedeADefinitionOrFence() {
  // A definition or a fence sits after the container markers on its line: a
  // block quote marker, a list item marker, or both, each after at most three
  // columns of indentation relative to the previous marker's content. The
  // reader skipped `>` and whitespace only, so a definition on a list marker
  // line was never read while every renderer resolves it.
  var TAB = String.fromCharCode(9);
  function kinds(src) {
    return b.guardMarkdown.validate(src, { profile: "strict" })
      .issues.map(function (i) { return i.kind; });
  }
  function reads(src) { return kinds(src).indexOf("reference-link-scheme") !== -1; }
  function fences(src) { return kinds(src).indexOf("code-fence-lang") !== -1; }
  var def = "[x]: javascript:alert(1)";
  var use = "\n\n[x]";

  var missed = [];
  [
    ["a bullet", "- " + def],
    ["a star bullet", "* " + def],
    ["a plus bullet", "+ " + def],
    ["an ordered marker", "1. " + def],
    ["a parenthesized ordered marker", "9) " + def],
    ["a nine-digit ordered marker", "123456789. " + def],
    ["a bullet inside a block quote", "> - " + def],
    ["a block quote inside a bullet", "- > " + def],
    ["an indented bullet", "   - " + def],
    ["a bullet followed by a tab", "-" + TAB + def],
    ["nested bullets", "- - " + def],
    ["a marker with two spaces", "1.  " + def],
    ["a marker with four spaces", "-    " + def],
    ["a bullet after a nested quote", ">> - " + def],
  ].forEach(function (c) { if (!reads(c[1] + use)) missed.push(c[0]); });
  check("a definition on a list marker line is read after the marker",
        missed.length === 0, missed.join(", "));

  // A list item that is open holds a later line at any indentation the item
  // can contain, so the top-level four-column rule does not apply to it.
  var unheld = [];
  [
    ["four spaces after a blank line", "- item\n\n    " + def],
    ["two spaces after a blank line", "- item\n\n  " + def],
    ["after an indented paragraph", "- item\n\n  para\n\n    " + def],
    ["after a lazy paragraph continuation", "- item\nparagraph\n\n    " + def],
    ["inside a quoted list", "> - item\n>\n>     " + def],
    ["under an ordered item", "1. item\n\n     " + def],
    ["under a nested item", "- a\n  - b\n\n      " + def],
    ["after a fenced block in the item", "- item\n\n  ```\n  x\n\n  ```\n    " + def],
    ["under a quoted item after a quoted blank", "> - item\n>\n>   " + def],
    // Six spaces under an item's paragraph is that paragraph's text, so the
    // unindented line after it is lazy continuation and the item stays open.
    ["after a deeply indented paragraph continuation", "- item\n      text\npara\n\n    " + def],
  ].forEach(function (c) { if (!reads(c[1] + use)) unheld.push(c[0]); });
  check("a definition an open list item holds is read at the item's indentation",
        unheld.length === 0, unheld.join(", "));

  // Four columns past the innermost container is indented code, and a list
  // closed by a blank line and a line indented less than its content is closed.
  var overread = [];
  [
    ["four spaces at the top level", "    " + def],
    ["a tab at the top level", TAB + def],
    ["five spaces after a quote marker", ">     " + def],
    ["a quote marker after four spaces", "    > " + def],
    ["five spaces after a bullet", "-     " + def],
    ["four spaces after a nested quote", ">>     " + def],
    ["after a list closed by a one-space paragraph", "- item\n\n para\n\n    " + def],
    ["after a list closed by a paragraph", "- item\n\nparagraph\n\n    " + def],
    ["after a list closed by a heading", "- item\n\n# h\n\n    " + def],
    ["after a heading directly under an item", "- item\n# h\n\n    " + def],
    ["after a quote directly under an item", "- item\n>\n\n    " + def],
    ["after an empty item and a blank line", "-\n\n    " + def],
    // A code block cannot be lazily continued, so the unindented line after
    // an item holding only code closes the item.
    ["after a code-only item and an unindented line", "-     code\npara\n\n    " + def],
    ["in a quote with no list", "> a\n>     " + def],
  ].forEach(function (c) { if (reads(c[1] + use)) overread.push(c[0]); });
  check("a definition four columns inside its container is code",
        overread.length === 0, overread.join(", "));

  // The same prefixes precede a fence.
  var missedFence = [];
  [
    ["a bullet", '- ```foo"'],
    ["an ordered marker", '1. ```foo"'],
    ["a bullet inside a quote", '> - ```foo"'],
    ["four spaces in an open item", '- item\n\n    ```foo"'],
    ["four spaces on the line after a marker", '- item\n    ```foo"'],
  ].forEach(function (c) { if (!fences(c[1])) missedFence.push(c[0]); });
  check("a fence after a container marker is read", missedFence.length === 0, missedFence.join(", "));
  var overFence = [];
  [
    ["four spaces at the top level", '    ```foo"'],
    ["a quote marker after four spaces", '    > ```foo"'],
    ["five spaces after a quote marker", '>     ```foo"'],
    ["five spaces after a bullet", '-     ```foo"'],
    ["six spaces in an open item", '- item\n\n      ```foo"'],
  ].forEach(function (c) { if (fences(c[1])) overFence.push(c[0]); });
  check("a fence four columns inside its container is code", overFence.length === 0, overFence.join(", "));

  // A definition cannot interrupt a paragraph: on the line after paragraph
  // text, with no container opened or closed between them, it is that
  // paragraph's continuation text.
  var continued = [];
  [
    ["a paragraph", "para\n" + def],
    ["a two-line paragraph", "para\nmore\n" + def],
    ["an item's paragraph", "- item\n" + def],
    ["an item's paragraph, indented", "- item\n  " + def],
    ["a quoted paragraph, lazily", "> quoted\n" + def],
    ["a quoted paragraph", "> quoted\n> " + def],
    ["a quoted item's paragraph", "> - item\n> " + def],
    ["a lazy continuation line", "- item\nlazy\n" + def],
  ].forEach(function (c) { if (reads(c[1] + use)) continued.push(c[0]); });
  check("a definition directly under paragraph text is the paragraph's text",
        continued.length === 0, continued.join(", "));
  var ended = [];
  [
    ["a blank line", "para\n\n" + def],
    ["a heading", "# h\n" + def],
    ["a thematic break", "***\n" + def],
    ["a closing fence", "```\ncode\n```\n" + def],
    ["another definition", "[y]: https://ok\n" + def],
    ["a quote the definition leaves", "- > quoted\n> " + def],
    ["a new quote", "para\n> " + def],
    ["a new item", "para\n- " + def],
    ["an item the definition closes", "- item\n\n" + def],
    ["indented code", "    code\n" + def],
    ["a table row", "| a |\n" + def],
    ["an HTML line", "<div>\n\n" + def],
  ].forEach(function (c) { if (!reads(c[1] + use)) ended.push(c[0]); });
  check("a definition after a line that ends a paragraph is read",
        ended.length === 0, ended.join(", "));

  // A list marker interrupts a paragraph only as a bullet or a `1.` with
  // content, and a `-` or `=` run under paragraph text is a setext underline.
  // A line the paragraph's container does not hold is judged by the outer
  // container instead, where it does start a list.
  var interrupted = [];
  [
    ["a 9) marker under a paragraph", "text\n9) " + def],
    ["an empty bullet under a paragraph", "text\n-\n" + def],
    ["a 10) marker under a lazy continuation", "> quoted\ntext\n10) item\n" + def],
    ["a dash underline under a paragraph", "text\n- \n  " + def + "\n\n[x]"],
  ].forEach(function (c) {
    var expectRead = c[0].indexOf("underline") !== -1 || c[0].indexOf("empty bullet") !== -1;
    if (reads(c[1] + use) !== expectRead) interrupted.push(c[0]);
  });
  check("a marker that cannot interrupt a paragraph is paragraph text",
        interrupted.length === 0, interrupted.join(", "));
  check("a 9) marker outside the item that holds the paragraph starts a list",
        reads("- item\n9) " + def + use));
  check("a 10) marker outside the quote that holds the paragraph starts a list",
        reads("> quoted\ntext\n10) item\n> " + def + use));

  // Fenced code and HTML blocks hold no definitions. A fence closes on a
  // closing fence of its container, or when that container closes; a raw
  // HTML block ends on any of the four closing tags; a block-level tag runs
  // to the next blank line.
  var inside = [];
  [
    ["a backtick fence", "```\n" + def + "\n```"],
    ["a tilde fence", "~~~\n" + def + "\n~~~"],
    ["a fence whose closer is shorter", "````\n" + def + "\n```\n"],
    ["a fence inside an item", "- ```\n  " + def + "\n  ```"],
    ["a fence inside a quote", "> ```\n> " + def + "\n> ```"],
    ["a div block", "<div>\n" + def],
    ["a comment block", "<!--\n" + def + "\n-->"],
    ["a pre block", "<pre>\n" + def + "\n</pre>"],
    ["a processing instruction", "<?php\n" + def + "\n?>"],
    ["a cdata section", "<![CDATA[\n" + def + "\n]]>"],
    ["a closing block tag", "</div>\n" + def],
  ].forEach(function (c) { if (reads(c[1] + use)) inside.push(c[0]); });
  check("a definition inside a fenced or HTML block is content",
        inside.length === 0, inside.join(", "));
  var after = [];
  [
    ["a closed fence", "```\ncode\n```\n" + def],
    ["a fence its item closed", "- ```\n  code\n" + def],
    ["a fence its quote closed", "> ```\n> code\n\n" + def],
    ["a raw block closed by another raw tag", "<pre>\ncode\n</script>\n" + def],
    ["a div block ended by a blank line", "<div>\n\n" + def],
    ["a comment closed on its own line", "<!-- c -->\n" + def],
    ["a fence-shaped line inside a tilde fence", "~~~\n```\n~~~\n" + def],
    ["a lone inline tag line", "<b>\n\n" + def],
  ].forEach(function (c) { if (!reads(c[1] + use)) after.push(c[0]); });
  check("a definition after a fenced or HTML block is read", after.length === 0, after.join(", "));
  // A definition's title may sit on the line after its destination, and may
  // span lines; the definition after it is still a definition.
  var titled = [];
  [
    ["a title on the next line", '[safe]: https://ok\n  "title"\n' + def],
    ["a single-quoted title on the next line", "[safe]: https://ok\n  'title'\n" + def],
    ["a parenthesized title on the next line", "[safe]: https://ok\n  (title)\n" + def],
    ["a title spanning two lines", '[safe]: https://ok\n"two\nlines"\n' + def],
    ["a title with an escaped quote", '[safe]: https://ok\n"a\\"b"\n' + def],
    ["a title on the destination's line", '[safe]: https://ok "title"\n' + def],
    ["a title inside a quote", '> [safe]: https://ok\n> "title"\n> ' + def],
    ["a two-line title inside a quote", '> [safe]: https://ok\n> "two\n> lines"\n> ' + def],
    ["a title inside an item", '- [safe]: https://ok\n  "title"\n  ' + def],
    ["a definition after a quoted blank inside a would-be title",
     '> [safe]: https://ok\n> "open\n>\n> ' + def + '\n> close"'],
  ].forEach(function (c) { if (!reads(c[1] + use)) titled.push(c[0]); });
  check("a definition after a titled definition is read", titled.length === 0, titled.join(", "));
  check("a would-be title followed by text is a paragraph the definition cannot interrupt",
        !reads('[safe]: https://ok\n"title" more\n' + def + use));
  check("a would-be title over a blank line is not a title",
        reads('[safe]: https://ok\n"open\n\n' + def + use));
  var broken = [];
  [
    ["a heading", '[safe]: https://ok "open\n# h\n' + def + '\nclose"'],
    ["a thematic break", '[safe]: https://ok\n"open\n***\n' + def + '\nclose"'],
    ["a new quote", '[safe]: https://ok\n"open\n> ' + def + '\nclose"'],
    ["a bullet", '[safe]: https://ok\n"open\n- ' + def + '\nclose"'],
    ["an HTML block", '[safe]: https://ok\n"open\n<div>\n\n' + def + '\nclose"'],
  ].forEach(function (c) { if (!reads(c[1] + use)) broken.push(c[0]); });
  check("a would-be title that a block start cuts is not a title", broken.length === 0, broken.join(", "));
  check("an unterminated title leaves text an underline can head",
        reads('[safe]: https://ok "open\n===\n' + def + '\nclose"' + use));
  check("a malformed lone tag is paragraph text, not an HTML block",
        reads("<b invalid=>\n> " + def + use));
  check("a well-formed lone tag with attributes is an HTML block",
        !reads('<b class="x" data-y=z>\n' + def + use));
  check("a lone tag opening a new quote starts an HTML block there",
        reads("text\n> <b>\n" + def + use));
  // A `>` that opens a new quote, a thematic break that outranks a bullet,
  // and a lone tag line that opens an HTML block all end a paragraph.
  check("a new quote's indented code does not continue the paragraph before it",
        reads("para\n>     code\n" + def + use));
  check("a bullet followed by dashes is a thematic break, not an item",
        reads("- ---\n    para\n " + def + use));
  check("a lone tag line inside a quote is an HTML block that no line continues lazily",
        reads("> <b>\n> para\n" + def + use));
  check("a lone tag line at the top level is an HTML block",
        !reads("<b>\n" + def + use));
  check("a tag followed by text is paragraph text",
        !reads("<b>x</b> text\n" + def + use));
  check("a lone tag line cannot interrupt a paragraph",
        !reads("text\n<b>\n" + def + use));
  // Renderers differ on what follows a definition-only paragraph: cmark
  // extracts the definition when the paragraph closes, so a marker that
  // cannot interrupt a paragraph is text there, while markdown-it consumes
  // the definition as its own block and starts a list. The guard reads what
  // either resolves. An underline needs paragraph text in both.
  check("an empty bullet after a definition starts a list for one renderer, so the definition after it is read",
        reads("[safe]: https://ok\n- \n" + def + use));
  check("a 9) marker after a definition starts a list for one renderer",
        reads("[safe]: https://ok\n9) " + def + use));
  check("an equals run after a definition-only paragraph is text",
        !reads("[safe]: https://ok\n===\n" + def + use));
  check("a dash run after a definition-only paragraph is a thematic break",
        reads("[safe]: https://ok\n---\n" + def + use));
  check("an equals run after text and a definition is an underline",
        reads("text\n[safe]: https://ok\n===\n" + def + use));
  // A declaration block opens on `<!` and an UPPERCASE letter; `<!a` is text.
  check("a lowercase letter after <! does not open a declaration block",
        reads("<!a\n\n" + def + use));
  check("an uppercase letter after <! does",
        !reads("<!DOCTYPE html\n" + def + "\n>" + use));
  // An autolink line or an inline tag with text is paragraph text, not an
  // HTML block, so the fence after it is a fence.
  check("a fence after an autolink line has its info string checked",
        fences('<https://example.com>\n```foo"\nx\n```'));
  check("and a definition inside that fence is content",
        !reads('<https://example.com>\n```\n' + def + '\n```' + use));
  check("a fence after an inline tag with text is a fence",
        fences('<b>x</b> text\n```foo"\nx\n```'));
  check("a four-backtick fence's info string starts after the run",
        !fences('````js\ncode\n````'));
  check("a fence-shaped line inside a tilde fence is not a fence",
        !fences('~~~\n```foo"\n~~~'));

  // The container reader is linear in the document: many lines of nested
  // markers, and a marker chain as deep as the line is long.
  var growth = require("../helpers/growth");
  function scanNestedLines(size) {
    var lines = [];
    for (var i = 0; i < size; i += 1) lines.push("> - > - > " + (i % 3 === 0 ? "" : "  ") + "[a]: https://ok");
    b.guardMarkdown.validate(lines.join("\n"), { profile: "permissive" });
  }
  check("the container reader stays linear in the number of lines",
        growth.looksSuperlinear(scanNestedLines, { small: 2000, large: 8000, threshold: 8 }) === false);
  function scanDeepChains(size) {
    var chain = new Array(size + 1).join("> ");
    var lines = [];
    for (var i = 0; i < 64; i += 1) lines.push(chain + (i % 2 === 0 ? "[a]: https://ok" : ""));
    b.guardMarkdown.validate(lines.join("\n"), { profile: "permissive" });
  }
  check("the container reader stays linear in marker depth",
        growth.looksSuperlinear(scanDeepChains, { small: 500, large: 2000, threshold: 8 }) === false);
  // A chain of bullets is tested for a thematic break at every marker; the
  // suffix is scanned once for all of them.
  function scanBulletChain(size) {
    b.guardMarkdown.validate(new Array(size + 1).join("- ") + "text", { profile: "strict" });
  }
  check("the container reader stays linear in bullets on one line",
        growth.looksSuperlinear(scanBulletChain, { small: 2000, large: 8000, threshold: 8 }) === false);

  // An angle-bracketed destination may hold spaces and runs to its closing
  // bracket, so what follows it is read as the title or the line's end.
  check("a definition after an angle-bracketed destination with a space is read",
        reads("[safe]: <./a b>\n" + def + use));
  check("an angle-bracketed executable destination is a definition finding",
        kinds("[x]: <javascript:alert(1) >\n\n[x]").indexOf("reference-link-scheme") !== -1);
  // markdown-it consumes a definition as its own block: a code-indented line
  // after it is code, a shallower line after one in a quote leaves the quote,
  // and its title scan runs through an equals line and an outdented line.
  var mditShapes = [];
  [
    ["a code-indented line after a titled definition", '[a]: /url "title"\n    [a]: /url "\n' + def],
    ["a shallower line after a quoted definition", "> [a]: /url\n(title\n> " + def],
    ["a title spanning an equals line and an outdented line", '- [a]: /url "\n    ===\ntitle"\n' + def],
  ].forEach(function (c) { if (!reads(c[1] + use)) mditShapes.push(c[0]); });
  check("a definition one renderer's reference block exposes is read",
        mditShapes.length === 0, mditShapes.join(", "));
  // A parenthesized title may not hold an unescaped `(`, a destination may not
  // hold unbalanced parentheses, and the fence pass sees definitions too.
  check("a would-be title holding an unescaped parenthesis is not a title",
        reads("[a]: /url\n    (title\n" + def + use));
  check("a destination with unbalanced parentheses is not a destination",
        reads("[a]:\n(title\n===\n" + def + use));
  check("a fence after an item a definition-only paragraph allows is read",
        fences('[a]: /url\n-\n  ~~~\n~~~foo"\n'));
  // With HTML enabled, markdown-it lets a lone tag open an HTML block after a
  // reference block; and its title scan absorbs code-indented and outdented
  // lines through a quote until the closing delimiter.
  check("a lone tag after a quoted definition ends the quote for a renderer with HTML on",
        reads('> [a]: /url "title"\n> <b>\n' + def + use));
  check("an open title absorbs a code-indented line and a quoted line until it closes",
        reads('> [a]: /url "\n    -\n> =\n"\n' + def + use));

  // Line endings: a CRLF document holds the same structure as an LF one.
  check("a CRLF list item still holds its definition",
        reads("- item\r\nparagraph\r\n\r\n    " + def + "\r\n\r\n[x]"));
  check("and a CRLF top-level code block is still code",
        !reads("para\r\n\r\n    " + def + "\r\n\r\n[x]"));
  check("and a CR-separated paragraph still continues",
        !reads("para\r" + def + "\r\r[x]"));

  // sanitize refuses the marker-line definition the way it refuses any other.
  var refused = false;
  try { b.guardMarkdown.sanitize("- " + def + use, { profile: "strict" }); }
  catch (e) { refused = e.code === "markdown.reference-link-scheme"; }
  check("sanitize refuses a definition on a marker line", refused);
}

function testADefinitionScanThatFailsLeavesItsLinesToTheBlockReader() {
  // A definition may span lines: a label to its closing bracket, a destination
  // on the next line, a title opened on the destination line or the one after
  // it and closed lines later. The reader took those lines as the definition's
  // while the scan was open; when the scan failed, the lines it had absorbed
  // were never read again as blocks, so a setext underline, a fence, or a
  // fresh definition among them was lost. Every renderer re-reads them.
  function kinds(src) {
    return b.guardMarkdown.validate(src, { profile: "strict" })
      .issues.map(function (i) { return i.kind; });
  }
  function reads(src) { return kinds(src).indexOf("reference-link-scheme") !== -1; }
  function fences(src) { return kinds(src).indexOf("code-fence-lang") !== -1; }
  var def = "[x]: javascript:alert(1)";
  var use = "\n\n[x]";

  // A title that opens on the line after the destination and never closes:
  // the definition stands at its destination, and the lines after it are
  // blocks again. For a renderer with a reference block the quote has ended,
  // so `(foo` and `===` make a heading and the definition after it resolves.
  check("a failed next-line title leaves an underline to head the text it absorbed",
        reads("> [a]: /url\n(foo\n===\n" + def + use));
  check("and the same without the quote",
        reads("[a]: /url\n(foo\n===\n" + def + use));
  // A title that opens on the destination line and never closes fails the
  // whole definition: the line is paragraph text, an underline heads it, and
  // the definition after the heading resolves.
  check("a failed same-line title leaves the definition line as text an underline heads",
        reads('[safe]: https://ok "open\n===\n' + def + use));
  check("a closed title with trailing text on a later line fails the same way",
        reads('[safe]: https://ok "open\nclose" x\n===\n' + def + use));
  // A label that spans lines is read line by line: a fence between its lines
  // interrupts the paragraph, so the fence's info string is inspected.
  check("a fence inside a would-be multiline label is a fence",
        fences('[foo\n~~~bad"\nbar]: /url'));
  check("and a backtick fence too",
        fences('[foo\n```bad"\nbar]: /url'));
  check("a fence after a label line whose destination sits on the next line is a fence",
        fences('[foo]:\n~~~bad"\n/url'));
  // A definition start among the absorbed lines is a definition on replay.
  check("a definition among lines a failed title absorbed is read",
        reads('[a]: /url\n"open\n\n' + def + use));
  check("a definition a failed multiline label absorbed is read",
        reads("[foo\n***\n" + def + "\nbar]: /url" + use));
  check("a definition after a label whose destination line is a list marker is read",
        reads("[foo]:\n- " + def + use));
  // Lines a scan absorbs and then keeps: no replay changes a title that closes.
  check("a title that closes lines later still hides the definition inside it",
        !reads('[a]: /url "\n' + def + '\n"' + use));
  check("a multiline label that closes with a destination is one definition",
        reads("[fo\no]: javascript:alert(1)\n\n[fo o]"));
  // A scan open at the end of the document fails the same way as one a block
  // interrupts.
  check("a title left open at the end of input leaves the definition standing",
        kinds("[x]\n\n[x]: javascript:alert(1)\n\"open").indexOf("reference-link-scheme") !== -1);
  check("a label left open at the end of input is text",
        !reads("[x]\n\n[x\njavascript:alert(1)"));

  // A definition or a title line that continues a quote's paragraph lazily
  // belongs to the quote, so a code-indented definition on the quote's next
  // line is the paragraph's next definition.
  check("a definition after a lazy destination line keeps the quote's depth",
        reads("> [a]:\n<b>\n>     " + def + use));
  check("a chained definition on a lazy line keeps the quote's depth",
        reads('    ===\n> [a]: /url\n[a]: /url "title"\n>     ' + def + use));
  // An angle bracket that never closes is not a destination, so the line is
  // paragraph text that a dash underline heads.
  check("an unterminated angle destination leaves paragraph text an underline heads",
        reads("[s]: <a\n-\n    - deep\n   " + def + use));
  // A bracket pair holding a nested pair is not a label: the line is text an
  // underline heads, though the destination after it is still inspected.
  check("a nested-bracket line is text an underline heads",
        reads("[a [b]]: /u\n===\n" + def + use));
  check("and its own destination is still inspected",
        reads("[a [b]]: javascript:alert(1)\n\n[a [b]]"));

  // markdown-it reads a GFM table: a header row with a pipe, a delimiter row
  // of dashes, then rows until a blank line or a line that opens a block, and
  // any list marker opens a block there.
  check("a 9) marker after a table's rows is a list and holds a definition",
        reads("| a |\n| - |\n9) " + def + use));
  check("a table interrupts a paragraph",
        reads("text\n| a |\n| - |\n9) " + def + use));
  check("a table ends a title scan, and a marker after its rows is a list",
        reads('[a]: /url "\n| a |\n| - |\n"\nrow\n9) ' + def + use));
  check("a code-indented line after a table is code, not the table's paragraph",
        reads('| - |\n| - |\n[y]: /u\n"open\n    ~~~\n ' + def + ' "open\nclose"' + use));
  check("a header whose cell count differs from the delimiter's is text",
        !reads("| a | b |\n|-|\n9) " + def + use));
  // A quote's lazy line is tested for a block start by the quotes inside it
  // with its indentation erased: a code-indented marker two quotes deep closes
  // them and is code outside, so the next line starts fresh.
  check("a code-indented marker under two quotes closes them",
        reads("> > x\n    -\n" + def + use));
  check("but under one quote it continues the paragraph",
        !reads("> x\n    -\n" + def + use));
  check("a code-indented fence under two quotes ends a title scan and closes them",
        reads('>> [a]: /v "\n    ~~~\n' + def + '\n"' + use));
  // A renderer with tables off reads the header and delimiter rows as a
  // setext heading, and a tab-indented `>` then continues the quote.
  check("a would-be table is a heading for a renderer without tables",
        reads("> -|\n> --\n\t> " + def + use));
  // A Unicode line separator is not a CommonMark line ending: a renderer
  // reads `text<LS>~~~` as one paragraph line, so no fence opens and the
  // definition after the blank line resolves. The document is also read with
  // the separator as a line ending, so a definition only that reading sees is
  // still inspected.
  var LS = String.fromCharCode(0x2028);
  var PS = String.fromCharCode(0x2029);
  check("a fence marker after a Unicode line separator does not open a fence",
        reads("text" + LS + "~~~\n\n" + def + use));
  check("nor after a paragraph separator",
        reads("text" + PS + "```\n\n" + def + use));
  check("a definition after two Unicode line separators is still read",
        reads("x" + LS + LS + def + use));
  check("a fence's info string after a Unicode line separator is still read",
        fences("x" + LS + '```foo"\ncode\n```'));
  // A line not indented enough for its item: a break, a heading or a fence
  // there closes the item's paragraph for markdown-it and is code where it
  // lands; a list marker there continues the paragraph.
  check("an under-indented break after an indented item closes its paragraph",
        reads("  9) x\n    ***\n" + def + use));
  check("an under-indented marker after an indented item is the paragraph's text",
        !reads("  9) x\n    - deep\n" + def + use));
  check("and a later item of that list holds a fence",
        fences('  9) x\n    - deep\n| - | - |\n  9) ```foo"\ncode\n```'));
  // A code-indented line after a lazy line continues the quote's paragraph
  // at any depth; a marker on a shallower line then opens a list.
  check("a code-indented lazy line keeps the paragraph, and a marker after it is a list",
        reads('>> c\n<!-- c -->\n \t x\n"\n9) ' + def + use));
  // A fenced block's backticks are not code-span delimiters: with a bracket
  // between two runs the definition is read both ways, and the fence a marker
  // after it opens is inspected.
  check("a definition between backtick runs still lets a marker open a fence",
        fences('  ```\n````\n[y]: /u\n9) ```foo"\ncode\n```'));

  // A line that is not a lazy continuation closes every container deeper than
  // its own depth, list items included, so a later quote at that depth starts
  // with no item open: four spaces there are indented code, which no line
  // continues lazily.
  check("a quote reopened after a marker line holds no stale item",
        reads("> > - x\n9) x\n> >     x\n  " + def + "\n[x]"));

  // The rollback replays absorbed lines, so the reader must stay linear when
  // scans absorb many lines, when scan spans nest through the three title
  // delimiters, and when a deep container stack precedes many failed scans.
  // A run of lazy lines under a deep item chain looks its landing item up by
  // binary search, so it stays linear too.
  var growth = require("../helpers/growth");
  function scanLazyLinesUnderItems(size) {
    b.guardMarkdown.validate(new Array(size + 1).join("- ") + "x\n" + new Array(size + 1).join("x\n"),
                             { profile: "permissive" });
  }
  check("lazy lines under a deep item chain stay linear",
        growth.looksSuperlinear(scanLazyLinesUnderItems, { small: 2000, large: 8000, threshold: 8 }) === false);
  function scanAbsorbedLines(size) {
    var lines = ['[a]: /url "'];
    for (var i = 0; i < size; i += 1) lines.push("x");
    lines.push("", def, "", "[x]");
    b.guardMarkdown.validate(lines.join("\n"), { profile: "permissive" });
  }
  check("a scan that absorbs many lines before failing stays linear",
        growth.looksSuperlinear(scanAbsorbedLines, { small: 2000, large: 8000, threshold: 8 }) === false);
  function scanNestedSpans(size) {
    var openers = ['"', "'", "("];
    var lines = [];
    for (var i = 0; i < size; i += 1) lines.push("[a" + i + "]: /url " + openers[i % 3]);
    b.guardMarkdown.validate(lines.join("\n") + use, { profile: "permissive" });
  }
  check("scans whose spans nest through the title delimiters stay linear",
        growth.looksSuperlinear(scanNestedSpans, { small: 2000, large: 8000, threshold: 8 }) === false);
  function scanFailedNextLineTitles(size) {
    var lines = [];
    for (var i = 0; i < size; i += 1) lines.push("[a" + i + "]: /url", "(", "x", "");
    b.guardMarkdown.validate(lines.join("\n") + use, { profile: "permissive" });
  }
  check("many failed next-line titles stay linear",
        growth.looksSuperlinear(scanFailedNextLineTitles, { small: 2000, large: 8000, threshold: 8 }) === false);
  function scanDeepThenFailedScans(size) {
    var lines = [new Array(401).join("> ") + "x"];
    for (var i = 0; i < size; i += 1) lines.push("- [a" + i + "]: /url", "(", "");
    b.guardMarkdown.validate(lines.join("\n") + use, { profile: "permissive" });
  }
  check("failed scans after a deep container stack stay linear",
        growth.looksSuperlinear(scanDeepThenFailedScans, { small: 1000, large: 4000, threshold: 8 }) === false);
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[guard-markdown] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
