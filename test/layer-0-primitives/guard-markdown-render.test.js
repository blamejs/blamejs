// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.guardMarkdown.render - Markdown to HTML, escape-by-default.
 *
 * The module could validate and sanitise Markdown but not render it, so every
 * consumer that accepts Markdown from an author and shows it to a visitor
 * wrote the HTML emitter itself by string concatenation. The three things
 * those copies get wrong are the three the framework already has opinions
 * about, and each is a stored-XSS hole in a CMS or a help centre:
 *
 *   - author text emitted unescaped,
 *   - `javascript:` / `data:` surviving in `[text](url)`,
 *   - raw HTML passed through in the hope of sanitising it afterwards.
 *
 * So the assertions below are mostly adversarial. The rendering-correctness
 * ones exist to stop the safe answer from being "escape everything and emit
 * no markup at all", which would pass every safety test and be useless.
 *
 * Hostile fixtures are BUILT from char codes rather than typed - a raw
 * zero-width or BIDI character in a source file is invisible in review.
 *
 * Run standalone: `node test/layer-0-primitives/guard-markdown-render.test.js`
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

var CH = String.fromCharCode;

function render(src, opts) { return b.guardMarkdown.render(src, opts); }

// Does the output contain a live element of this name (a real tag, not the
// escaped text of one)?
function hasTag(html, name) {
  return html.indexOf("<" + name + ">") !== -1 ||
         html.indexOf("<" + name + " ") !== -1;
}

// ---------------------------------------------------------------------------
// Safety - the reason this belongs upstream.
// ---------------------------------------------------------------------------

function testAuthorTextIsAlwaysEscaped() {
  var out = render("A <script>alert(1)</script> B");
  check("render: a script tag in prose is never emitted as markup",
    !hasTag(out, "script") && out.indexOf("alert(1)") !== -1);
  check("render: the escaped form is present instead",
    out.indexOf("&lt;script&gt;") !== -1);

  // Ampersands must not be double-escaped into visible noise, and must not be
  // left raw where they could start an entity the browser resolves.
  var amp = render("Tom & Jerry");
  check("render: a bare ampersand is escaped exactly once",
    amp.indexOf("&amp;") !== -1 && amp.indexOf("&amp;amp;") === -1);

  // Escaping has to survive INSIDE every construct, not only in paragraphs.
  var inHeading = render("# <img onerror=x>");
  check("render: a heading escapes its text", !hasTag(inHeading, "img"));
  var inList = render("- <img onerror=x>");
  check("render: a list item escapes its text", !hasTag(inList, "img"));
  var inQuote = render("> <img onerror=x>");
  check("render: a blockquote escapes its text", !hasTag(inQuote, "img"));
  var inCode = render("```\n<img onerror=x>\n```");
  check("render: a code fence escapes its contents", !hasTag(inCode, "img"));
  var inEmph = render("*<img onerror=x>*");
  check("render: emphasis escapes its text", !hasTag(inEmph, "img"));
  var inLinkText = render("[<img onerror=x>](https://example.com)");
  check("render: link TEXT is escaped", !hasTag(inLinkText, "img"));
}

function testDangerousUrlSchemesAreRefused() {
  var hostile = [
    "javascript:alert(1)",
    "JaVaScRiPt:alert(1)",
    "data:text/html;base64,PHNjcmlwdD4=",
    "vbscript:msgbox(1)",
    "  javascript:alert(1)",                       // leading whitespace
    "java" + CH(0x09) + "script:alert(1)",         // embedded tab
    "java" + CH(0x0A) + "script:alert(1)",         // embedded newline
    "&#106;avascript:alert(1)",                    // numeric entity
    "java&Tab;script:alert(1)",                    // named entity
    "javascript&colon;alert(1)",                   // entity-hidden colon
  ];
  var leaked = hostile.filter(function (u) {
    var out = render("[click](" + u + ")");
    // Whatever the renderer does with it, the result must not be an href a
    // browser would execute.
    var i = out.indexOf("href=");
    if (i === -1) return false;
    var quote = out.charAt(i + 5);
    var end = out.indexOf(quote, i + 6);
    var href = out.slice(i + 6, end).toLowerCase();
    return href.indexOf("javascript") !== -1 || href.indexOf("vbscript") !== -1 ||
           href.indexOf("data:") !== -1;
  });
  check("render: no dangerous scheme survives into an href" +
    (leaked.length ? " (leaked " + JSON.stringify(leaked) + ")" : ""),
    leaked.length === 0);

  // Refusing must not mean dropping the author's words silently.
  var refused = render("[click me](javascript:alert(1))");
  check("render: a refused link still shows its text",
    refused.indexOf("click me") !== -1);
}

// RFC 3986 §3.1: scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ). A check
// that reads only the leading LETTER run stops at the `+` in `web+evil:` and
// concludes the target has no scheme at all, so it is treated as relative and
// emitted as a live href. Browsers hand registered `xxx+yyy:` schemes to
// protocol handlers, so this is an active target, not a broken one.
function testSchemeGrammarIsTheWholeScheme() {
  var shapes = [
    "web+evil:payload",
    "a1+b-c.d:payload",
    "ms-word:ofe|u|http://x",
    "x1:payload",
    "foo.bar:payload",
    "foo-bar:payload",
  ];
  var live = shapes.filter(function (u) {
    return render("[open](" + u + ")").indexOf("href=") !== -1;
  });
  check("render: a scheme using digits or +/-/. is not mistaken for a relative path" +
    (live.length ? " (live: " + JSON.stringify(live) + ")" : ""),
    live.length === 0);

  // The characters that make a scheme must not make a RELATIVE path look like
  // one - a path segment may legitimately contain a dot or a plus.
  var relatives = ["./a+b.c", "a+b.c/d", "/x/y.z", "#a.b", "?q=a+b"];
  var dropped = relatives.filter(function (u) {
    return render("[t](" + u + ")").indexOf("href=") === -1;
  });
  check("render: a relative path containing +, - or . still renders" +
    (dropped.length ? " (dropped " + JSON.stringify(dropped) + ")" : ""),
    dropped.length === 0);
}

function testSafeUrlSchemesSurvive() {
  var safe = [
    "https://example.com/a?b=1",
    "http://example.com",
    "mailto:someone@example.com",
    "/relative/path",
    "./sibling",
    "#fragment",
  ];
  var dropped = safe.filter(function (u) {
    return render("[t](" + u + ")").indexOf("href=") === -1;
  });
  check("render: ordinary link targets are preserved" +
    (dropped.length ? " (dropped " + JSON.stringify(dropped) + ")" : ""),
    dropped.length === 0);

  // A quote or angle bracket inside a URL must not be able to close the
  // attribute and start a new one.
  var breakout = render('[t](https://example.com/" onmouseover="alert(1))');
  check("render: a quote inside a URL cannot break out of the href attribute",
    breakout.indexOf("onmouseover=") === -1);
  var angle = render("[t](https://example.com/<script>)");
  check("render: an angle bracket inside a URL cannot open a tag",
    !hasTag(angle, "script"));
}

function testRawHtmlIsEscapedNotSanitized() {
  var out = render("<div onclick=\"steal()\">hi</div>");
  check("render: a raw HTML block is emitted as escaped text, not markup",
    !hasTag(out, "div") && out.indexOf("&lt;div") !== -1);
  check("render: the attribute inside it cannot execute",
    out.indexOf("onclick=\"steal()\"") === -1);

  // The classic sanitiser bypass: a tag that only becomes one after the
  // sanitiser's own rewrite. Escaping outright is immune, which is the point.
  var nested = render("<scr<script>ipt>alert(1)</scr</script>ipt>");
  check("render: a split-tag bypass produces no live script",
    !hasTag(nested, "script"));
}

function testImagesDoNotBecomeMarkup() {
  // Images are outside the documented subset. They must degrade to escaped
  // text rather than silently emitting an element with an author-controlled
  // src and an onerror surface.
  var out = render("![alt](javascript:alert(1))");
  check("render: an image does not emit an img element",
    !hasTag(out, "img"));
  check("render: an image's alt text is still shown",
    out.indexOf("alt") !== -1);
}

function testInvisibleCharactersDoNotReachOutput() {
  var bidi = render("A" + CH(0x202E) + "B");
  check("render: a BIDI override does not pass through into the HTML",
    bidi.indexOf(CH(0x202E)) === -1);
  var zw = render("A" + CH(0x200B) + "B");
  check("render: a zero-width space does not pass through into the HTML",
    zw.indexOf(CH(0x200B)) === -1);
  var nul = render("A" + CH(0x0000) + "B");
  check("render: a NUL does not pass through into the HTML",
    nul.indexOf(CH(0x0000)) === -1);
}

// ---------------------------------------------------------------------------
// Rendering - so "escape everything, emit nothing" cannot pass.
// ---------------------------------------------------------------------------

function testBlockConstructsRender() {
  check("render: a paragraph becomes <p>", hasTag(render("hello"), "p"));
  check("render: an ATX heading becomes <h1>", hasTag(render("# Title"), "h1"));
  check("render: a level-three heading becomes <h3>", hasTag(render("### T"), "h3"));
  var ul = render("- one\n- two");
  check("render: a bullet list becomes <ul> with two <li>",
    hasTag(ul, "ul") && ul.split("<li>").length === 3);
  var ol = render("1. one\n2. two");
  check("render: a numbered list becomes <ol>", hasTag(ol, "ol"));
  check("render: a blockquote becomes <blockquote>",
    hasTag(render("> quoted"), "blockquote"));
  var fence = render("```js\nvar x = 1;\n```");
  check("render: a fenced block becomes <pre><code>",
    hasTag(fence, "pre") && fence.indexOf("<code") !== -1);
  check("render: the fence's contents are preserved",
    fence.indexOf("var x = 1;") !== -1);
  check("render: a thematic break becomes <hr>",
    render("---").indexOf("<hr") !== -1);
}

function testInlineConstructsRender() {
  check("render: *text* becomes <em>", hasTag(render("*hi*"), "em"));
  check("render: _text_ becomes <em>", hasTag(render("_hi_"), "em"));
  check("render: **text** becomes <strong>", hasTag(render("**hi**"), "strong"));
  check("render: `code` becomes <code>", render("`x`").indexOf("<code>") !== -1);
  var link = render("[text](https://example.com)");
  check("render: a link becomes an anchor carrying its text",
    link.indexOf("href=") !== -1 && link.indexOf(">text<") !== -1);
  // A code span's contents are literal - an asterisk inside it is not emphasis.
  var literal = render("`*not emphasis*`");
  check("render: a code span's contents are literal, not re-parsed",
    !hasTag(literal, "em"));
}

// Escape-and-preserve is the documented behaviour for anything outside the
// subset. Silently DROPPING a line is worse than rendering it as plain text:
// the author sees their content vanish with no error anywhere.
function testNothingIsSilentlyDiscarded() {
  var cases = [
    { label: "hash with no space", src: "#not-a-heading", needle: "not-a-heading" },
    { label: "seven hashes", src: "####### title", needle: "title" },
    { label: "close-bracket line", src: "]orphan", needle: "orphan" },
    { label: "bare marker", src: "-nospace", needle: "nospace" },
    { label: "ordered no space", src: "1.nospace", needle: "nospace" },
    { label: "quote no space", src: ">quoted", needle: "quoted" },
  ];
  var lost = cases.filter(function (c) {
    return render(c.src).indexOf(c.needle) === -1;
  }).map(function (c) { return c.label; });
  check("render: a line the block parser does not recognise is preserved as text" +
    (lost.length ? " (lost: " + lost.join(", ") + ")" : ""),
    lost.length === 0);

  // `#` alone IS a heading - an empty one - so it is recognised rather than
  // discarded. It still has to produce the element, not nothing at all.
  check("render: a lone hash is an empty heading, not an empty document",
    hasTag(render("#"), "h1"));
}

// The docstring lists indented code in the subset. A four-space indent that
// renders as a paragraph loses both the indentation and the code semantics,
// and - because the paragraph path runs its content through the inline parser
// - re-parses what the author marked as literal.
function testIndentedCodeRendersAsCode() {
  var out = render("    <tag>\n");
  check("render: a four-space indent becomes <pre><code>",
    out.indexOf("<pre><code") !== -1);
  check("render: its contents are escaped, not markup",
    out.indexOf("&lt;tag&gt;") !== -1 && !hasTag(out, "tag"));

  // Inside indented code, inline syntax is literal.
  var literal = render("    *not emphasis*\n");
  check("render: indented code does not re-parse inline syntax",
    !hasTag(literal, "em"));

  // A list continuation is indented too - four spaces under a bullet must not
  // silently become a code block.
  var listCont = render("- item\n  continued\n");
  check("render: a two-space list continuation is not treated as code",
    listCont.indexOf("<pre") === -1);
}

function testDegenerateInputIsHandled() {
  var cases = ["", "   ", "\n\n\n", "#", "```", "```\nunclosed",
               "[", "[](", "[t](", "*", "***", "- ", ">", "1."];
  var threw = cases.filter(function (s) {
    try { render(s); return false; } catch (_e) { return true; }
  });
  check("render: degenerate and truncated input never throws" +
    (threw.length ? " (threw on " + JSON.stringify(threw) + ")" : ""),
    threw.length === 0);

  var nonString = null;
  try { render(42); } catch (e) { nonString = e; }
  check("render: non-string input throws a framework error, not a TypeError",
    nonString !== null && typeof nonString.code === "string");
}

function testProfilesReachTheRenderer() {
  // The module's strictness dial has to apply to rendering too, otherwise a
  // consumer that picked strict for validate gets balanced behaviour here.
  var strict = render("<b>x</b>", { profile: "strict" });
  check("render: strict escapes raw HTML", !hasTag(strict, "b"));
  var permissive = render("<b>x</b>", { profile: "permissive" });
  check("render: even permissive does not emit author HTML as markup",
    !hasTag(permissive, "b"));
  var badProfile = null;
  try { render("x", { profile: "nonexistent" }); } catch (e) { badProfile = e; }
  check("render: an unknown profile is refused rather than silently defaulted",
    badProfile !== null);
}

// A renderer that runs on visitor-supplied Markdown is a denial-of-service
// surface as much as an injection one. Both of these were found by attacking
// the first working version of this renderer, not by review.
function testHostileInputIsBoundedNotFatal() {
  // Deeply nested blockquotes recurse once per level. Unbounded, 20k of them
  // exhausts the call stack and takes the process down - a crash, not a
  // refusal, so no error handler upstream can contain it.
  var deep = null;
  try { render(">".repeat(20000) + " x"); }
  catch (e) { deep = e; }
  check("render: deep blockquote nesting is refused, never a stack overflow",
    deep === null ||
    (typeof deep.code === "string" && String(deep.message).indexOf("call stack") === -1));

  // Delimiter scanning must not be quadratic: an input of one repeated
  // character is the cheapest possible attack to send.
  var shapes = [
    { label: "brackets", src: "[".repeat(50000) + "x" },
    { label: "emphasis", src: "*".repeat(20000) + "x" + "*".repeat(20000) },
    { label: "backticks", src: "`".repeat(20000) },
    { label: "parens", src: "[x](".repeat(20000) },
  ];
  var slow = shapes.filter(function (s) {
    var t0 = process.hrtime.bigint();
    try { render(s.src); } catch (_e) { /* a refusal is a fine answer; a hang is not */ }
    return Number(process.hrtime.bigint() - t0) / 1e6 > 250;
  }).map(function (s) { return s.label; });
  check("render: repeated-delimiter input stays linear" +
    (slow.length ? " (slow: " + slow.join(",") + ")" : ""),
    slow.length === 0);
}

// The profile resolves maxBytes and maxLines. If render parses a source that
// exceeds them, those documented options are decorative on this path and an
// attacker gets an unbounded parse — the caps exist precisely because the input
// is untrusted.
function testInputCapsAreEnforced() {
  var overBytes = "a".repeat(2 * 1024 * 1024);          // 2 MiB > strict's 1 MiB
  var bytesErr = null;
  try { render(overBytes, { profile: "strict" }); } catch (e) { bytesErr = e; }
  check("render: a source past maxBytes is refused",
    bytesErr !== null && typeof bytesErr.code === "string");

  var overLines = "x\n".repeat(5000);                    // 5000 > strict's 4096
  var linesErr = null;
  try { render(overLines, { profile: "strict" }); } catch (e) { linesErr = e; }
  check("render: a source past maxLines is refused",
    linesErr !== null && typeof linesErr.code === "string");

  // The cap is named maxBYTES, so it must measure bytes. A run of two-byte
  // characters whose BYTE length is over the cap while its CHARACTER length is
  // under it passes a length check and fails a byte check — the difference
  // between a cap that holds and one that is 50% wrong on non-ASCII input.
  var twoByte = CH(0x00E9);                              // U+00E9, 2 bytes in UTF-8
  var overBytesUnderChars = twoByte.repeat(700 * 1024);  // 700 Ki chars, 1.4 MiB
  check("render: the byte cap is measured in bytes, not characters " +
    "(chars=" + overBytesUnderChars.length + ", bytes=" +
    Buffer.byteLength(overBytesUnderChars, "utf8") + ")",
    overBytesUnderChars.length < 1024 * 1024 &&
    Buffer.byteLength(overBytesUnderChars, "utf8") > 1024 * 1024);
  var byteCapErr = null;
  try { render(overBytesUnderChars, { profile: "strict" }); } catch (e) { byteCapErr = e; }
  check("render: a source under the char count but over the byte cap is refused",
    byteCapErr !== null && typeof byteCapErr.code === "string");

  // CONTROL: the same inputs must RENDER under a profile whose caps admit them,
  // or the checks above would pass for a renderer that simply refuses
  // everything large.
  var permissiveErr = null;
  try { render(overLines, { profile: "permissive" }); } catch (e) { permissiveErr = e; }
  check("render CONTROL: a source within permissive's caps still renders" +
    (permissiveErr ? " (threw " + (permissiveErr.code || permissiveErr.message) + ")" : ""),
    permissiveErr === null);
}

// A malformed limit must be refused, not silently disable the limit. `byteLen
// > "8mb"` is false for every input, so a configuration typo turns the
// advertised hostile-input cap off without a word. validate() and sanitize()
// already screen these through the guard factory's intOpts; render must not
// be the one door that skips it.
function testMalformedLimitsAreRefusedNotIgnored() {
  var bad = [
    { label: "maxBytes string",      opts: { maxBytes: "8mb" } },
    { label: "maxBytes negative",    opts: { maxBytes: -1 } },
    { label: "maxBytes zero",        opts: { maxBytes: 0 } },
    { label: "maxBytes fractional",  opts: { maxBytes: 1.5 } },
    { label: "maxBytes Infinity",    opts: { maxBytes: Infinity } },
    { label: "maxLines string",      opts: { maxLines: "many" } },
    { label: "maxLines negative",    opts: { maxLines: -5 } },
    { label: "maxBlockquoteDepth fractional", opts: { maxBlockquoteDepth: 1.5 } },
    { label: "maxBlockquoteDepth string",     opts: { maxBlockquoteDepth: "16" } },
  ];
  var accepted = bad.filter(function (c) {
    try { render("hello", c.opts); return true; } catch (_e) { return false; }
  }).map(function (c) { return c.label; });
  check("render: a malformed limit is refused rather than silently disabling the cap" +
    (accepted.length ? " (accepted " + accepted.join(", ") + ")" : ""),
    accepted.length === 0);

  // CONTROL: well-formed overrides still work, so the check above cannot pass
  // for a renderer that refuses every explicit limit.
  var okErr = null;
  try { render("hello", { maxBytes: 4096, maxLines: 10, maxBlockquoteDepth: 4 }); }
  catch (e) { okErr = e; }
  check("render CONTROL: well-formed limit overrides are accepted" +
    (okErr ? " (threw " + (okErr.code || okErr.message) + ")" : ""),
    okErr === null);
}

// maxBlockquoteDepth is caller-configurable, and blockquotes render by
// recursion. A policy limit above the call-stack's real ceiling turns a
// refusal into a native RangeError — the framework crashing rather than
// declining. The implementation needs its own ceiling, independent of policy.
function testBlockquoteRecursionHasAnImplementationCeiling() {
  var deep = "> ".repeat(10000) + "x";
  var err = null;
  var out = null;
  try { out = render(deep, { maxBlockquoteDepth: 10001 }); }
  catch (e) { err = e; }
  check("render: 10,000 nested blockquotes do not raise a native RangeError " +
    (err ? "(got " + (err.code || err.name + ": " + err.message) + ")" : "(rendered)"),
    err === null || (typeof err.code === "string" && err.name !== "RangeError"));
  check("render: a policy limit above the implementation ceiling still refuses cleanly",
    out !== null || (err !== null && typeof err.code === "string"));
}

// Nesting depth must not multiply the work done per character.
//
// The renderer derived a bracket-match map at entry, and the link-label and
// emphasis paths both recurse on a substring — so every level re-derived a map
// spanning nearly the whole remaining span, and every parent's map stayed live
// while it did. Depth is capped at 24, so a document inside the balanced
// profile's own 8 MiB cap produced twenty-four full-length maps: 6.68 MiB of
// input grew the heap by 1,334 MiB, and permissive allows eight times the
// input. Satisfying every advertised cap and still exhausting memory is the
// failure this asserts against.
//
// The assertion is on the COUNT of maps built rather than on elapsed time or
// heap size, because the count is exact: it does not move with machine speed,
// GC timing, or how loaded the runner is. Depth-independence is the property —
// two documents of identical size and different nesting must build the same
// number of maps.
function testNestingDepthDoesNotMultiplyBracketMaps() {
  function nestedLinks(levels, filler) {
    // Each level must itself be a link for the label path to recurse:
    // [[[x](u)](u)](u). A label that is merely bracketed does not.
    return "[".repeat(levels) + "x".repeat(filler) + "](u)".repeat(levels);
  }
  function mapsFor(src) {
    var before = b.guardMarkdown._bracketMapsBuiltForTest();
    render(src, { profile: "balanced" });
    return b.guardMarkdown._bracketMapsBuiltForTest() - before;
  }

  var shallow = mapsFor(nestedLinks(2, 4000));
  var deep = mapsFor(nestedLinks(24, 4000));
  check("render: nesting depth does not multiply bracket-map allocations " +
        "(2 levels built " + shallow + ", 24 levels built " + deep + ")",
        deep === shallow);

  // A control, so the check above cannot pass by building zero maps in both:
  // a document with inline syntax must build at least one.
  check("render: an inline run builds a bracket map at all (" + shallow + ")",
        shallow >= 1);

  // Emphasis recurses through the same path and must not reintroduce it.
  var emShallow = mapsFor("*" + "y".repeat(4000) + "*");
  var emDeep = mapsFor("*".repeat(12) + "y".repeat(4000) + "*".repeat(12));
  check("render: emphasis nesting does not multiply bracket-map allocations " +
        "(1 level built " + emShallow + ", 12 levels built " + emDeep + ")",
        emDeep === emShallow);
}

// The output has to be usable as a fragment: no stray unclosed element, and
// balanced tags for every construct above.
function testOutputIsBalanced() {
  var src = "# T\n\npara *em* and `code`\n\n- a\n- b\n\n> q\n\n```\nx\n```\n";
  var html = render(src);
  var names = ["p", "h1", "ul", "li", "blockquote", "pre", "code", "em"];
  var unbalanced = names.filter(function (n) {
    var open = html.split("<" + n + ">").length - 1 +
               (html.split("<" + n + " ").length - 1);
    var close = html.split("</" + n + ">").length - 1;
    return open !== close;
  });
  check("render: every emitted element is closed" +
    (unbalanced.length ? " (unbalanced " + unbalanced.join(",") + ")" : ""),
    unbalanced.length === 0);
}

async function run() {
  testAuthorTextIsAlwaysEscaped();
  testDangerousUrlSchemesAreRefused();
  testSchemeGrammarIsTheWholeScheme();
  testSafeUrlSchemesSurvive();
  testRawHtmlIsEscapedNotSanitized();
  testImagesDoNotBecomeMarkup();
  testInvisibleCharactersDoNotReachOutput();
  testBlockConstructsRender();
  testInlineConstructsRender();
  testNothingIsSilentlyDiscarded();
  testIndentedCodeRendersAsCode();
  testDegenerateInputIsHandled();
  testProfilesReachTheRenderer();
  testHostileInputIsBoundedNotFatal();
  testInputCapsAreEnforced();
  testMalformedLimitsAreRefusedNotIgnored();
  testBlockquoteRecursionHasAnImplementationCeiling();
  testNestingDepthDoesNotMultiplyBracketMaps();
  testOutputIsBalanced();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[guard-markdown-render] OK - " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL: " + helpers.formatErr(e)); process.exit(1); }
  );
}
