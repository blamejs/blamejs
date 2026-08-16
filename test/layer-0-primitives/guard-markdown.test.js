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
          threw && threw.code === "markdown.bad-input");
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
  var REF_DEF_RE     = /^\s{0,3}\[([^\]\n]+)\]:\s*([^\s]+)/gm;
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
    "[ref]:https://x", "[]: x", "[a]: ", "line\n[ref]: javascript:x",
    // The destination may sit on the next line — the whitespace after the
    // colon includes the line break, so a line-by-line walk loses the URL and
    // never screens its scheme.
    "[x]:\njavascript:alert(1)", "[x]:\n  https://ok", "[x]:\n\nhttps://ok",
    "[a]: one\n[b]: two", "[a]:\n", "[a]:",
    // A lone CR starts a line for a `^` under the `m` flag, and so do the two
    // Unicode line separators — a scan that only knows LF misses these.
    "x\r[ref]: javascript:y", "x\r```<script>\ny",
    "x" + String.fromCharCode(0x2028) + "[ref]: javascript:y",
    "x\r\n[ref]: javascript:y", "x\r\n```<script>\ny",
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
    // Extractors: compare the URLs found, in order.
    var reLinks = Array.from(doc.matchAll(INLINE_LINK_RE)).map(function (m) {
      return m[1] + "|" + m[3];
    });
    var gotLinks = api.inlineLinks(doc).map(function (l) { return l.bang + "|" + l.url; });
    compare("inline-links", JSON.stringify(reLinks), JSON.stringify(gotLinks));

    var reAuto = Array.from(doc.matchAll(AUTOLINK_RE)).map(function (m) { return m[1]; });
    var gotAuto = api.autolinks(doc).map(function (a) { return a.url; });
    compare("autolinks", JSON.stringify(reAuto), JSON.stringify(gotAuto));

    var reRefs = Array.from(doc.matchAll(REF_DEF_RE)).map(function (m) { return m[2]; });
    var gotRefs = api.refDefs(doc).map(function (r) { return r.url; });
    compare("ref-defs", JSON.stringify(reRefs), JSON.stringify(gotRefs));

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

async function run() {
  testMarkdownExtractorsAgreeWithThePatternsTheyReplaced();
  testGuardMarkdownSurface();
  testGuardMarkdownRegistryParity();
  testGuardMarkdownDangerousScheme();
  testGuardMarkdownEntityBypass();
  testGuardMarkdownAutolinkScheme();
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
  await testGuardMarkdownGate();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[guard-markdown] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
