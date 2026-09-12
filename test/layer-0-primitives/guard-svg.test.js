// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * guard-svg — SVG content-safety primitive (b.guardSvg).
 *
 * Covers: surface; registry parity; dangerous-tag detection (script /
 * foreignObject / handler / iframe / animate-family); on* event-handler
 * strip; href + xlink:href dangerous URL schemes (javascript / vbscript
 * / file / mhtml + entity-encoded form); animation-element
 * attributeName allowlist (animate attributeName="href"
 * to="javascript:" hijack); cross-origin <use> external-ref refusal;
 * DOCTYPE rejection (billion laughs / XXE); <!ENTITY> declaration
 * detection; CDATA + processing-instruction policy; SVGZ magic-byte
 * detection; CSS injection in style attribute; bidi / control / null
 * detection; element-count + use-depth + attr-count caps; sanitize
 * round-trip; gate decision shapes (clean / refuse / sanitize); profile
 * + posture vocabulary.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var markupTokenizer = require("../../lib/markup-tokenizer");

function testGuardSvgSurface() {
  check("guardSvg is an object",                     typeof b.guardSvg === "object");
  check("guardSvg.NAME === 'svg'",                   b.guardSvg.NAME === "svg");
  check("guardSvg.MIME_TYPES has image/svg+xml",     b.guardSvg.MIME_TYPES.indexOf("image/svg+xml") !== -1);
  check("guardSvg.EXTENSIONS includes .svg",         b.guardSvg.EXTENSIONS.indexOf(".svg") !== -1);
  check("guardSvg.PROFILES has strict",              !!b.guardSvg.PROFILES["strict"]);
  check("guardSvg.PROFILES has balanced",            !!b.guardSvg.PROFILES["balanced"]);
  check("guardSvg.PROFILES has permissive",          !!b.guardSvg.PROFILES["permissive"]);
  check("guardSvg.COMPLIANCE_POSTURES has hipaa",    !!b.guardSvg.COMPLIANCE_POSTURES["hipaa"]);
  check("guardSvg.validate is a function",           typeof b.guardSvg.validate === "function");
  check("guardSvg.sanitize is a function",           typeof b.guardSvg.sanitize === "function");
  check("guardSvg.gate is a function",               typeof b.guardSvg.gate === "function");
  check("guardSvg.GuardSvgError is a function",      typeof b.guardSvg.GuardSvgError === "function");
  check("frameworkError.GuardSvgError exposed",      typeof b.frameworkError.GuardSvgError === "function");
}

function testGuardSvgRegistryParity() {
  check("guardSvg registered in guardAll",
        b.guardAll.list().some(function (g) { return g.name === "svg"; }));
  var entry = b.guardAll.list().filter(function (g) { return g.name === "svg"; })[0];
  b.guardAll.SHARED_PROFILES.forEach(function (p) {
    check("registry: svg supports shared profile " + p,
          entry.profiles.indexOf(p) !== -1);
  });
  b.guardAll.SHARED_POSTURES.forEach(function (p) {
    check("registry: svg supports shared posture " + p,
          entry.postures.indexOf(p) !== -1);
  });
}

function testGuardSvgDangerousTags() {
  var tags = ["script", "foreignObject", "handler", "listener",
              "iframe", "embed", "object", "audio", "video"];
  for (var i = 0; i < tags.length; i++) {
    var rv = b.guardSvg.validate("<svg><" + tags[i] + ">x</" + tags[i] + "></svg>",
                                 { profile: "strict" });
    check("dangerous tag <" + tags[i] + "> detected",
          rv.ok === false &&
          rv.issues.some(function (issue) { return issue.kind === "dangerous-tag"; }));
  }
}

function testGuardSvgEventHandlers() {
  var handlers = ["onclick", "onerror", "onload", "onbegin", "onend",
                  "onrepeat", "onfocusin", "onfocusout"];
  for (var i = 0; i < handlers.length; i++) {
    var rv = b.guardSvg.validate('<svg><circle ' + handlers[i] + '="x"/></svg>',
                                 { profile: "balanced" });
    check("event handler " + handlers[i] + " detected",
          rv.issues.some(function (issue) { return issue.kind === "event-handler"; }));
  }
}

function testGuardSvgUrlSchemes() {
  var dangerous = ["javascript:", "vbscript:", "livescript:", "data:text/html,",
                   "file:///", "mhtml:", "view-source:", "jar:"];
  for (var i = 0; i < dangerous.length; i++) {
    var rv = b.guardSvg.validate(
      '<svg><a xlink:href="' + dangerous[i] + 'x">y</a></svg>',
      { profile: "balanced" });
    check("dangerous scheme " + JSON.stringify(dangerous[i]) + " detected",
          rv.issues.some(function (issue) { return issue.kind === "dangerous-url-scheme"; }));
  }

  var rvEnc = b.guardSvg.validate(
    '<svg><a xlink:href="&#x6A;avascript:alert(1)">x</a></svg>',
    { profile: "balanced" });
  check("entity-encoded javascript: scheme detected",
        rvEnc.issues.some(function (issue) { return issue.kind === "dangerous-url-scheme"; }));

  // Fragment-only references allowed.
  var rvFrag = b.guardSvg.validate(
    '<svg><use xlink:href="#icon"/></svg>',
    { profile: "balanced" });
  check("fragment-only #ref allowed (not flagged as scheme)",
        !rvFrag.issues.some(function (issue) { return issue.kind === "dangerous-url-scheme"; }));
}

function testGuardSvgAnimationHrefHijack() {
  var rv = b.guardSvg.validate(
    '<svg><animate attributeName="href" to="javascript:alert(1)"/></svg>',
    { profile: "permissive" });
  check("animation attributeName=href hijack detected",
        rv.issues.some(function (issue) { return issue.kind === "animation-target"; }));

  var rv2 = b.guardSvg.validate(
    '<svg><animate attributeName="xlink:href" to="evil"/></svg>',
    { profile: "permissive" });
  check("animation attributeName=xlink:href hijack detected",
        rv2.issues.some(function (issue) { return issue.kind === "animation-target"; }));

  // attributeName="cx" — safe target, not flagged.
  var rvSafe = b.guardSvg.validate(
    '<svg><animate attributeName="cx" to="100"/></svg>',
    { profile: "permissive" });
  check("animation attributeName=cx (safe target) NOT flagged",
        !rvSafe.issues.some(function (issue) { return issue.kind === "animation-target"; }));
}

function testGuardSvgUseExternalRef() {
  var rv = b.guardSvg.validate(
    '<svg><use xlink:href="https://evil.example/icons.svg#x"/></svg>',
    { profile: "strict" });
  check("strict: cross-origin <use> external-ref detected",
        rv.issues.some(function (issue) { return issue.kind === "external-ref" ||
                                                 issue.kind === "non-allowlisted-url-scheme" ||
                                                 issue.kind === "dangerous-url-scheme"; }));
}

function testGuardSvgDoctype() {
  var rv = b.guardSvg.validate(
    '<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "x.dtd"><svg/>',
    { profile: "strict" });
  check("DOCTYPE detected",
        rv.issues.some(function (issue) { return issue.kind === "doctype"; }));

  var rvEntity = b.guardSvg.validate(
    '<!DOCTYPE svg [<!ENTITY xx "yy">]><svg/>',
    { profile: "strict" });
  check("<!ENTITY> declaration detected",
        rvEntity.issues.some(function (issue) { return issue.kind === "entity-declaration"; }));
}

function testGuardSvgCdataAndPi() {
  var rvCdata = b.guardSvg.validate(
    '<svg><![CDATA[x]]><circle/></svg>',
    { profile: "strict" });
  check("CDATA detected under strict",
        rvCdata.issues.some(function (issue) { return issue.kind === "cdata"; }));

  var rvPi = b.guardSvg.validate(
    '<?xml-stylesheet type="text/css" href="x.css"?><svg/>',
    { profile: "strict" });
  check("processing-instruction detected under strict",
        rvPi.issues.some(function (issue) { return issue.kind === "processing-instruction"; }));
}

function testGuardSvgSvgz() {
  var rv = b.guardSvg.validate(
    Buffer.from([0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00]),
    { profile: "strict" });
  check("SVGZ magic-byte detected",
        rv.issues.some(function (issue) { return issue.kind === "svgz-compressed"; }));
}

function testGuardSvgCssInjection() {
  var rv = b.guardSvg.validate(
    '<svg><circle style="background:url(javascript:alert(1))"/></svg>',
    { profile: "balanced" });
  check("CSS injection in style attribute detected",
        rv.issues.some(function (issue) { return issue.kind === "css-injection"; }));
}

function testGuardSvgBidiNullControl() {
  var bidi = "‮";
  var rvBidi = b.guardSvg.validate("<svg><title>x" + bidi + "y</title></svg>",
                                   { profile: "strict" });
  check("bidi override detected",
        rvBidi.issues.some(function (issue) { return issue.kind === "bidi-override"; }));

  var nb = String.fromCharCode(0);
  var rvNull = b.guardSvg.validate("<svg><title>x" + nb + "y</title></svg>",
                                   { profile: "strict" });
  check("null byte detected",
        rvNull.issues.some(function (issue) { return issue.kind === "null-byte"; }));
}

function testGuardSvgCaps() {
  var threwSize = null;
  try { b.guardSvg.sanitize("<svg>" + "<g/>".repeat(100), { profile: "strict", maxBytes: 50 }); }
  catch (e) { threwSize = e; }
  check("maxBytes cap throws on sanitize",
        threwSize && /exceeds maxBytes/.test(threwSize.message));

  // <use> nesting depth.
  var deep = "";
  for (var i = 0; i < 20; i++) deep += "<use>";
  var rv = b.guardSvg.validate("<svg>" + deep + "</svg>",
                               { profile: "balanced", maxUseDepth: 5 });
  check("maxUseDepth cap detected",
        rv.issues.some(function (issue) { return issue.kind === "use-depth-cap"; }));
}

function testGuardSvgByteCapsMeasureBytes() {
  // Caps named in *Bytes must measure UTF-8 bytes, not UTF-16 code units.
  // "é" is one code unit (.length 1) but two UTF-8 bytes. A 50-char run is
  // 50 code units / 100 bytes — under a 60 char-count but over a 60-byte cap.
  var multibyte = "é".repeat(50);
  check("multibyte fixture: 50 code units, 100 UTF-8 bytes",
        multibyte.length === 50 && Buffer.byteLength(multibyte, "utf8") === 100);

  // Top-level maxBytes (validate path → tokenizer cap).
  var rvSize = b.guardSvg.validate(multibyte, { profile: "strict", maxBytes: 60 });
  check("validate: multibyte over byte cap reports too-large",
        rvSize.issues.some(function (issue) {
          return /exceeds maxBytes/.test(issue.snippet || "");
        }));
  check("validate: too-large snippet reports the BYTE count, not char count",
        rvSize.issues.some(function (issue) {
          return /input 100 bytes exceeds maxBytes 60/.test(issue.snippet || "");
        }));

  // Top-level maxBytes (sanitize path → throws).
  var threwMb = null;
  try { b.guardSvg.sanitize(multibyte, { profile: "strict", maxBytes: 60 }); }
  catch (e) { threwMb = e; }
  check("sanitize: multibyte over byte cap throws too-large with byte count",
        threwMb && /input 100 bytes exceeds maxBytes 60/.test(threwMb.message));

  // ASCII under the same cap stays unchanged (no false positive).
  var rvAscii = b.guardSvg.validate("a".repeat(50), { profile: "strict", maxBytes: 60 });
  check("validate: 50-byte ASCII under 60-byte cap is NOT flagged too-large",
        !rvAscii.issues.some(function (issue) {
          return /exceeds maxBytes/.test(issue.snippet || "");
        }));

  // Per-attribute maxAttrValueBytes measures bytes too.
  var attrMb = "<svg><circle foo=\"" + "é".repeat(50) + "\"/></svg>";
  var rvAttr = b.guardSvg.validate(attrMb,
    { profile: "balanced", maxAttrValueBytes: 60, maxBytes: 1000000 });
  check("validate: multibyte attr value over byte cap reports attr-value-too-large",
        rvAttr.issues.some(function (issue) { return issue.ruleId === "svg.attr-size"; }));

  var attrAscii = "<svg><circle foo=\"" + "a".repeat(50) + "\"/></svg>";
  var rvAttrAscii = b.guardSvg.validate(attrAscii,
    { profile: "balanced", maxAttrValueBytes: 60, maxBytes: 1000000 });
  check("validate: 50-byte ASCII attr value under 60-byte cap NOT flagged",
        !rvAttrAscii.issues.some(function (issue) { return issue.ruleId === "svg.attr-size"; }));
}

function testGuardSvgSanitize() {
  var clean = b.guardSvg.sanitize("<svg><script>alert(1)</script><circle/></svg>",
                                  { profile: "strict" });
  check("sanitize: script + body dropped",
        /<svg><circle\/?>(<\/svg>)?/.test(clean) && clean.indexOf("script") === -1);

  var clean2 = b.guardSvg.sanitize(
    '<svg><a xlink:href="javascript:alert(1)">x</a></svg>',
    { profile: "balanced" });
  check("sanitize: javascript: href stripped",
        clean2.indexOf("javascript") === -1);

  var clean3 = b.guardSvg.sanitize(
    '<svg><circle onclick="x"/></svg>', { profile: "strict" });
  check("sanitize: onclick stripped",
        clean3.indexOf("onclick") === -1);
}

async function testGuardSvgGate() {
  var g = b.guardSvg.gate({ profile: "strict" });
  var rv = await g.check({
    contentType: "image/svg+xml",
    bytes: Buffer.from("<svg><circle r=\"10\"/></svg>"),
  });
  check("gate clean → action=serve", rv.ok === true && rv.action === "serve");

  var rvHostile = await g.check({
    contentType: "image/svg+xml",
    bytes: Buffer.from('<svg><script>alert(1)</script></svg>'),
  });
  check("gate hostile under strict → not serve",
        rvHostile.action !== "serve");

  var rvSvgz = await g.check({
    contentType: "image/svg+xml",
    bytes: Buffer.from([0x1F, 0x8B, 0x08, 0x00]),
  });
  check("gate svgz → refuse (never sanitize-eligible)",
        rvSvgz.action === "refuse");
}

function testGuardSvgCompliancePosture() {
  var hipaa = b.guardSvg.compliancePosture("hipaa");
  check("compliancePosture('hipaa') sets reject policies",
        hipaa.bidiPolicy === "reject" &&
        hipaa.cssPolicy === "reject" &&
        hipaa.doctypePolicy === "reject");
  var threw = null;
  try { b.guardSvg.compliancePosture("unknown"); }
  catch (e) { threw = e; }
  check("compliancePosture: unknown name throws",
        threw && /unknown/.test(threw.message));
}

function testGdprPostureMatchesBalancedTier() {
  // gdpr is the balanced-tier posture for content guards (data-minimization
  // strips rather than rejects, but structural threats stay rejected). svg's
  // balanced profile allows cross-origin external refs (allowExternalRefs:
  // true) while strict refuses them. A partial gdpr posture object that omits
  // allowExternalRefs silently backfills the strict value, turning gdpr into
  // an incoherent strict/balanced hybrid that rejects an external <use> the
  // balanced tier accepts. Assert the gdpr verdict matches the balanced
  // verdict for that exact input.
  var external = '<svg><use xlink:href="https://cdn.example/icons.svg#x"/></svg>';
  var gdpr     = b.guardSvg.validate(external, { compliancePosture: "gdpr" });
  var balanced = b.guardSvg.validate(external, { profile: "balanced" });

  check("gdpr posture allows the same external <use> the balanced tier allows",
        gdpr.ok === balanced.ok);
  check("gdpr posture raises no external-ref the balanced tier does not",
        !gdpr.issues.some(function (issue) { return issue.kind === "external-ref"; }));

  // Structural identity: the gdpr posture is the balanced profile plus the
  // data-minimization forensic budget (base 256 / 2 = 128), nothing
  // strict-derived backfilled.
  var expected = Object.assign({}, b.guardSvg.PROFILES.balanced,
                               { forensicSnippetBytes: 128 });
  check("COMPLIANCE_POSTURES.gdpr deep-equals balanced + forensicSnippetBytes:128",
        JSON.stringify(b.guardSvg.COMPLIANCE_POSTURES.gdpr) === JSON.stringify(expected));
}

function testGuardSvgBadProfile() {
  var threw = null;
  try { b.guardSvg.validate("<svg/>", { profile: "made-up" }); }
  catch (e) { threw = e; }
  check("validate: unknown profile throws",
        threw && /unknown profile/i.test(threw.message));
}

function testGuardSvgSchemeWhitespaceBypass() {
  // Browsers remove ASCII tab (U+0009) / LF (U+000A) / CR (U+000D) from a URL
  // before resolving its scheme (WHATWG URL parser "remove ASCII tab or
  // newline"), so `java<TAB>script:` / `java<LF>script:` navigate as
  // `javascript:`. The guard's scheme decoder even maps the NAMED entities
  // `&Tab;`/`&NewLine;` to those characters (its own comment names
  // `java&Tab;script:` as the threat), but decoding is defeated unless the
  // resulting whitespace is stripped before the scheme match. A miss here is
  // a fail-open: validate returns ok and the gate serves the hostile bytes.
  //
  // The same URL parser also trims a leading/trailing C0-control-OR-SPACE run
  // (U+0000..U+0020) before parsing, so an ENTITY-encoded leading space
  // (`&#32;javascript:` / `&#x20;javascript:`) decodes to " javascript:" and
  // navigates as `javascript:`. A literal leading space is caught by the raw
  // .trim(), but the entity-encoded space survives the decode (space is not a
  // C0 control, not tab/lf/cr), so it must be trimmed after decoding.
  var vectors = [
    ["literal tab",   '<svg><a xlink:href="java\tscript:alert(1)">x</a></svg>'],
    ["literal lf",    '<svg><a xlink:href="java\nscript:alert(1)">x</a></svg>'],
    ["literal cr",    '<svg><a xlink:href="java\rscript:alert(1)">x</a></svg>'],
    ["&Tab; named",   '<svg><a xlink:href="java&Tab;script:alert(1)">x</a></svg>'],
    ["&NewLine; named", '<svg><a xlink:href="java&NewLine;script:alert(1)">x</a></svg>'],
    ["&#9; numeric",  '<svg><a xlink:href="java&#9;script:alert(1)">x</a></svg>'],
    ["&#32; entity leading space",  '<svg><a xlink:href="&#32;javascript:alert(1)">x</a></svg>'],
    ["&#x20; entity leading space", '<svg><a xlink:href="&#x20;javascript:alert(1)">x</a></svg>'],
  ];
  for (var i = 0; i < vectors.length; i++) {
    var rv = b.guardSvg.validate(vectors[i][1], { profile: "balanced" });
    check("scheme bypass (" + vectors[i][0] + ") flagged dangerous-url-scheme",
          rv.ok === false &&
          rv.issues.some(function (issue) { return issue.kind === "dangerous-url-scheme"; }));
  }

  // A control char the strip set DOES cover (U+0001) must still be caught.
  var rvCtrl = b.guardSvg.validate(
    '<svg><a xlink:href="&#1;javascript:alert(1)">x</a></svg>', { profile: "balanced" });
  check("control-char-prefixed javascript: still flagged (no regression)",
        rvCtrl.issues.some(function (issue) { return issue.kind === "dangerous-url-scheme"; }));

  // A legitimate https URL is NOT flagged (no false positive from stripping).
  var rvOk = b.guardSvg.validate(
    '<svg><a xlink:href="https://example.com/a">x</a></svg>', { profile: "balanced" });
  check("plain https href not flagged as dangerous scheme",
        !rvOk.issues.some(function (issue) { return issue.kind === "dangerous-url-scheme"; }));

  // sanitize must strip the tab-obfuscated scheme, not re-emit it.
  var san = b.guardSvg.sanitize('<svg><a xlink:href="java\tscript:alert(1)">x</a></svg>',
                                { profile: "balanced" });
  check("sanitize: tab-obfuscated javascript scheme stripped",
        san.indexOf("script:") === -1);
}

function testGuardSvgCssEntityBypass() {
  // A style attribute is HTML/XML character-reference-decoded before the CSS
  // parser sees it, so `ex&#x70;ression(` reaches CSS as `expression(` and
  // `behavior&colon;` as `behavior:`. The css-danger check must decode the
  // same references the URL-scheme check already decodes, or an entity-encoded
  // style payload is served verbatim and executes (stored XSS).
  var vectors = [
    ["numeric &#x70; -> p (expression()",
     '<svg><rect style="width:ex&#x70;ression(alert(1))"/></svg>'],
    ["numeric &#x6A; -> j (url(javascript:))",
     '<svg><rect style="background:url(&#x6A;avascript:alert(1))"/></svg>'],
    ["decimal &#106; -> j (url(javascript:))",
     '<svg><rect style="background:url(&#106;avascript:alert(1))"/></svg>'],
    ["named &colon; -> : (behavior:)",
     '<svg><rect style="behavior&colon;url(evil.htc)"/></svg>'],
    // Whitespace-hidden scheme inside url(): a browser strips tab/lf/cr from a URL
    // before resolving its scheme, so url(java<TAB>script:) navigates as
    // javascript:. The decoded CSS value must also fold that URL whitespace.
    ["named &Tab; -> tab (url(java<TAB>script:))",
     '<svg><rect style="background:url(java&Tab;script:alert(1))"/></svg>'],
    ["numeric &#9; -> tab (url(java<TAB>script:))",
     '<svg><rect style="background:url(java&#9;script:alert(1))"/></svg>'],
  ];
  for (var i = 0; i < vectors.length; i++) {
    var rv = b.guardSvg.validate(vectors[i][1], { profile: "balanced" });
    check("CSS entity bypass (" + vectors[i][0] + ") flagged css-injection",
          rv.issues.some(function (issue) { return issue.kind === "css-injection"; }));
  }

  // Plain (unencoded) dangerous CSS still flagged (regression guard).
  var plain = b.guardSvg.validate('<svg><rect style="width:expression(alert(1))"/></svg>',
                                  { profile: "balanced" });
  check("CSS: plain expression( still flagged",
        plain.issues.some(function (issue) { return issue.kind === "css-injection"; }));

  // No false positive: a benign style value is untouched.
  var benign = b.guardSvg.validate('<svg><rect style="fill:red;stroke-width:2"/></svg>',
                                   { profile: "balanced" });
  check("CSS: benign style not flagged as css-injection",
        !benign.issues.some(function (issue) { return issue.kind === "css-injection"; }));
}

function testGuardSvgSanitizeAnimationPreserved() {
  // permissive permits animation; a safe-target <animate> must SURVIVE
  // sanitize. Every animation tag is in DANGEROUS_TAGS, so the sanitizer must
  // affirmatively re-permit the safe case — otherwise the open tag is dropped
  // while its (still allowlisted) close tag is emitted, leaving an orphan.
  var safe = '<svg><animate attributeName="cx" to="100"/></svg>';
  var out = b.guardSvg.sanitize(safe, { profile: "permissive" });
  check("sanitize permissive: safe <animate> open tag preserved",
        /<animate\b/i.test(out));

  var motion = '<svg><animateMotion dur="1s"><mpath xlink:href="#p"/></animateMotion></svg>';
  var outM = b.guardSvg.sanitize(motion, { profile: "permissive" });
  var opens  = (outM.match(/<animatemotion\b/gi) || []).length;
  var closes = (outM.match(/<\/animatemotion\b/gi) || []).length;
  check("sanitize permissive: animateMotion open/close balanced (no orphan close)",
        opens === 1 && closes === 1);

  // Unsafe attributeName animation is still neutralized under permissive.
  var unsafe = '<svg><animate attributeName="href" to="javascript:alert(1)"/></svg>';
  var outU = b.guardSvg.sanitize(unsafe, { profile: "permissive" });
  check("sanitize permissive: unsafe-target <animate> payload dropped",
        outU.indexOf("javascript") === -1);
}

async function testGuardSvgGateFailOpen() {
  var g = b.guardSvg.gate({ profile: "balanced" });

  var rvScheme = await g.check({
    contentType: "image/svg+xml",
    bytes: Buffer.from('<svg><a xlink:href="java\tscript:alert(1)">x</a></svg>', "utf8"),
  });
  check("gate: tab-obfuscated javascript scheme not served as-is",
        rvScheme.action !== "serve");

  var rvCss = await g.check({
    contentType: "image/svg+xml",
    bytes: Buffer.from('<svg><rect style="width:ex&#x70;ression(alert(1))"/></svg>', "utf8"),
  });
  check("gate: entity-encoded CSS expression not served as-is",
        rvCss.action !== "serve");
}

function testGuardSvgBadInput() {
  // Non-string / non-Buffer input → a single bad-input issue; validate never
  // throws on hostile input (callers inspect the issue list themselves).
  [123, null, undefined, {}, ["<svg/>"], true].forEach(function (bad, idx) {
    var rv = b.guardSvg.validate(bad, { profile: "strict" });
    check("validate(bad-input #" + idx + ") → ok=false + single bad-input issue",
          rv.ok === false &&
          rv.issues.length === 1 &&
          rv.issues[0].kind === "bad-input" &&
          rv.issues[0].severity === "high");
  });
  // sanitize refuses non-string/non-Buffer at the entry point (throws, since a
  // sanitizer has nothing to serialize back).
  var threw = null;
  try { b.guardSvg.sanitize(123, { profile: "strict" }); }
  catch (e) { threw = e; }
  check("sanitize(number) throws svg.bad-input",
        threw && /string or Buffer/.test(threw.message));
}

function testGuardSvgShortInput() {
  // A sub-2-byte input can't be SVGZ (the gzip signature is 2 bytes) — the
  // length<2 guard must return false, not read past the buffer.
  var rv = b.guardSvg.validate("x", { profile: "strict" });
  check("1-char input NOT mis-detected as SVGZ",
        !rv.issues.some(function (i) { return i.kind === "svgz-compressed"; }));
  var rvBuf = b.guardSvg.validate(Buffer.from([0x1F]), { profile: "strict" });
  check("1-byte 0x1F Buffer NOT mis-detected as SVGZ (needs both magic bytes)",
        !rvBuf.issues.some(function (i) { return i.kind === "svgz-compressed"; }));
}

function testGuardSvgImageDataUrl() {
  // allowImageData (balanced / permissive): a data:image/<raster>; URL on
  // <image> is the ONE permitted use of the otherwise-denylisted data: scheme.
  var okData = '<svg><image href="data:image/png;base64,iVBORw0KGgo="/></svg>';
  var rv = b.guardSvg.validate(okData, { profile: "balanced" });
  check("balanced: data:image/png on <image> allowed (no dangerous-url-scheme)",
        rv.ok === true &&
        !rv.issues.some(function (i) { return i.kind === "dangerous-url-scheme"; }));
  var san = b.guardSvg.sanitize(okData, { profile: "balanced" });
  check("balanced sanitize: data:image/png survives on <image>",
        san.indexOf("data:image/png") !== -1);

  // The exact same data URL on a NON-image element stays denied — the
  // exception is <image>-scoped, not a blanket data:-image allow.
  var rvA = b.guardSvg.validate(
    '<svg><a xlink:href="data:image/png;base64,iVBORw0KGgo=">x</a></svg>',
    { profile: "balanced" });
  check("balanced: data:image/png on <a> still flagged dangerous-url-scheme",
        rvA.issues.some(function (i) { return i.kind === "dangerous-url-scheme"; }));

  // A non-raster data: MIME on <image> (text/html) is NOT the image exception.
  var rvHtml = b.guardSvg.validate(
    '<svg><image href="data:text/html;base64,PHNjcmlwdD4="/></svg>',
    { profile: "balanced" });
  check("balanced: data:text/html on <image> flagged dangerous-url-scheme",
        rvHtml.issues.some(function (i) { return i.kind === "dangerous-url-scheme"; }));

  // strict has allowImageData:false — even a raster data URL on <image> is
  // refused there.
  var rvStrict = b.guardSvg.validate(okData, { profile: "strict" });
  check("strict: data:image/png on <image> refused (allowImageData false)",
        rvStrict.issues.some(function (i) { return i.kind === "dangerous-url-scheme"; }));
}

function testGuardSvgNonAllowlistedScheme() {
  // A scheme that is neither dangerous NOR in the profile's urlSchemes
  // allowlist (ftp under strict) → non-allowlisted-url-scheme (sanitize-class),
  // distinct from the dangerous-scheme denylist hit.
  var svg = '<svg><path href="ftp://host/x" d="M0 0"/></svg>';
  var rv = b.guardSvg.validate(svg, { profile: "strict" });
  check("strict: ftp scheme flagged non-allowlisted-url-scheme (not dangerous)",
        rv.issues.some(function (i) { return i.kind === "non-allowlisted-url-scheme"; }) &&
        !rv.issues.some(function (i) { return i.kind === "dangerous-url-scheme"; }));
  var san = b.guardSvg.sanitize(svg, { profile: "strict" });
  check("strict sanitize: ftp href dropped, benign d preserved",
        san.indexOf("ftp") === -1 && san.indexOf('d="M0 0"') !== -1);

  // ftp IS in the balanced profile's urlSchemes → not flagged there.
  var rvBal = b.guardSvg.validate('<svg><a xlink:href="ftp://host/x">y</a></svg>',
                                  { profile: "balanced" });
  check("balanced: ftp scheme allowed (in profile urlSchemes)",
        !rvBal.issues.some(function (i) { return i.kind === "non-allowlisted-url-scheme" ||
                                                 i.kind === "dangerous-url-scheme"; }));
}

function testGuardSvgStructuralCaps() {
  // element-count-cap: total token count over maxElementCount → high issue.
  var manyTokens = "<g></g>".repeat(20);
  var rvEl = b.guardSvg.validate(manyTokens, { profile: "strict", maxElementCount: 5 });
  check("element-count-cap fires when token count exceeds maxElementCount",
        rvEl.issues.some(function (i) { return i.kind === "element-count-cap"; }));

  // attr-count-cap: attribute count on one tag over maxAttrsPerTag → high issue.
  var manyAttrs = "<circle";
  for (var i = 0; i < 10; i += 1) manyAttrs += ' a' + i + '="1"';
  manyAttrs += "/>";
  var rvAttr = b.guardSvg.validate("<svg>" + manyAttrs + "</svg>",
                                   { profile: "balanced", maxAttrsPerTag: 3 });
  check("attr-count-cap fires when attribute count exceeds maxAttrsPerTag",
        rvAttr.issues.some(function (i) { return i.kind === "attr-count-cap"; }));
}

function testGuardSvgStandaloneEntityDeclaration() {
  // A bare <!ENTITY ...> OUTSIDE a DOCTYPE (tokenized as a declaration, not a
  // doctype) is still an entity-expansion / XXE vector and must be flagged.
  var rv = b.guardSvg.validate('<!ENTITY xxe "payload"><svg><circle r="1"/></svg>',
                               { profile: "strict" });
  check("standalone <!ENTITY> declaration flagged entity-declaration",
        rv.ok === false &&
        rv.issues.some(function (i) { return i.kind === "entity-declaration"; }));

  // A benign non-ENTITY declaration (<!ATTLIST>) is dropped, no entity flag.
  var rvAttlist = b.guardSvg.validate('<!ATTLIST x y CDATA><svg><circle r="1"/></svg>',
                                      { profile: "strict" });
  check("non-ENTITY <!ATTLIST> declaration raises no entity-declaration",
        !rvAttlist.issues.some(function (i) { return i.kind === "entity-declaration"; }));
}

function testGuardSvgCdataPiAuditSeverity() {
  // Under balanced, cdataPolicy is "audit" → warn severity (not critical), and
  // ok stays true (warn does not flip ok).
  var rvCdata = b.guardSvg.validate('<svg><![CDATA[x]]><circle r="1"/></svg>',
                                    { profile: "balanced" });
  check("balanced CDATA → warn severity (audit policy), ok stays true",
        rvCdata.ok === true &&
        rvCdata.issues.some(function (i) {
          return i.kind === "cdata" && i.severity === "warn";
        }));

  // Under permissive, processingInstrPolicy is "audit" → warn severity.
  var rvPi = b.guardSvg.validate('<?xml-stylesheet href="x"?><svg/>',
                                 { profile: "permissive" });
  check("permissive processing-instruction → warn severity (audit policy)",
        rvPi.issues.some(function (i) {
          return i.kind === "processing-instruction" && i.severity === "warn";
        }));
}

function testGuardSvgTruncatedTokens() {
  // Truncated / unterminated markup must not silently smuggle content: the
  // tokenizer treats each open-without-close as a token running to EOF.
  var rvCdata = b.guardSvg.validate('<svg><![CDATA[unterminated payload',
                                    { profile: "strict" });
  check("unterminated CDATA still flagged (scans to EOF)",
        rvCdata.issues.some(function (i) { return i.kind === "cdata"; }));

  var rvPi = b.guardSvg.validate('<svg><?xml-stylesheet type="text/css"',
                                 { profile: "strict" });
  check("unterminated processing-instruction still flagged",
        rvPi.issues.some(function (i) { return i.kind === "processing-instruction"; }));

  // Unterminated DOCTYPE with an internal-subset '[' and no closing ']' / '>'
  // — still detected as a doctype plus its embedded <!ENTITY>.
  var rvDoc = b.guardSvg.validate('<!DOCTYPE svg [<!ENTITY x "y"',
                                  { profile: "strict" });
  check("unterminated DOCTYPE-with-subset still flags doctype + entity",
        rvDoc.issues.some(function (i) { return i.kind === "doctype"; }) &&
        rvDoc.issues.some(function (i) { return i.kind === "entity-declaration"; }));

  // Unterminated (no closing '>') start tag for a DANGEROUS element is still
  // caught — the tokenizer scans to EOF and names the tag.
  var rvTag = b.guardSvg.validate('<svg><script', { profile: "strict" });
  check("unterminated <script (no >) still flagged dangerous-tag",
        rvTag.issues.some(function (i) { return i.kind === "dangerous-tag"; }));

  // Unterminated benign start tag validates clean (no spurious issue) — covers
  // the raw-without-trailing-'>' reconstruction path.
  var rvBenign = b.guardSvg.validate('<svg><circle r="1"', { profile: "strict" });
  check("unterminated benign <circle validates clean", rvBenign.ok === true);

  // Unterminated quoted attribute value (no closing quote, EOF) — parser must
  // clamp to EOF without crashing.
  var rvQuote = b.guardSvg.validate('<svg><circle r="unterminated', { profile: "strict" });
  check("unterminated quoted attr value handled without error",
        rvQuote && Array.isArray(rvQuote.issues));

  // Unterminated end tag (no '>') is dropped without error.
  var rvEnd = b.guardSvg.validate('<svg><circle r="1"/></circle', { profile: "strict" });
  check("unterminated end tag handled without error", rvEnd.ok === true);

  // Unterminated comment (no terminator, runs to EOF) — the hidden text stays
  // inert (not smuggled as a live element).
  var rvComment = b.guardSvg.validate('<svg><circle r="1"/><!-- <script>alert(1)',
                                      { profile: "strict" });
  check("unterminated comment swallows trailing markup (no dangerous-tag)",
        !rvComment.issues.some(function (i) { return i.kind === "dangerous-tag"; }));

  // Unterminated DOCTYPE WITHOUT an internal subset '[' and no closing '>' —
  // still flagged as a doctype.
  var rvDocPlain = b.guardSvg.validate('<!DOCTYPE svg PUBLIC "id"', { profile: "strict" });
  check("unterminated bracket-less DOCTYPE still flagged doctype",
        rvDocPlain.issues.some(function (i) { return i.kind === "doctype"; }));

  // Unterminated generic declaration (no '>') — dropped without error, no
  // spurious entity flag.
  var rvDecl = b.guardSvg.validate('<svg><circle r="1"/></svg><!ATTLIST foo',
                                   { profile: "strict" });
  check("unterminated <!ATTLIST declaration handled without error",
        rvDecl && Array.isArray(rvDecl.issues) &&
        !rvDecl.issues.some(function (i) { return i.kind === "entity-declaration"; }));
}

function testGuardSvgComment() {
  // A comment's contents are NOT parsed as markup — a <script> hidden inside a
  // comment is inert and must be dropped, not tokenized as a live element.
  var withComment = '<svg><!-- <script>alert(1)</script> --><circle r="1"/></svg>';
  var rv = b.guardSvg.validate(withComment, { profile: "strict" });
  check("comment-wrapped <script> not flagged (comment content inert)",
        rv.ok === true &&
        !rv.issues.some(function (i) { return i.kind === "dangerous-tag"; }));
  var san = b.guardSvg.sanitize(withComment, { profile: "strict" });
  check("sanitize strips the comment entirely (no smuggled script)",
        san.indexOf("<!--") === -1 && san.indexOf("script") === -1);
}

function testGuardSvgSanitizeStructural() {
  // Structural noise (DOCTYPE / declaration / CDATA / PI / comment) is dropped
  // by sanitize, leaving only the allowlisted element.
  var noisy = '<!DOCTYPE svg><!ENTITY z "z"><svg><![CDATA[x]]>' +
              '<?xml-stylesheet href="x"?><!--c--><circle r="1"/></svg>';
  var san = b.guardSvg.sanitize(noisy, { profile: "strict" });
  check("sanitize drops doctype/declaration/cdata/pi/comment structural tokens",
        san.indexOf("DOCTYPE") === -1 && san.indexOf("ENTITY") === -1 &&
        san.indexOf("CDATA") === -1 && san.indexOf("xml-stylesheet") === -1 &&
        san.indexOf("<!--") === -1 && /<circle r="1"\/?>/.test(san));

  // Nested same-name dangerous element: the body-drop scan must balance the
  // inner <script> against the outer so ALL nested content is removed.
  var nested = '<svg><script>a<script>b</script>c</script><circle r="1"/></svg>';
  var sanNest = b.guardSvg.sanitize(nested, { profile: "strict" });
  check("sanitize body-drop balances nested <script> (no leaked payload)",
        sanNest.indexOf("script") === -1 &&
        sanNest.indexOf(">a") === -1 && sanNest.indexOf("b<") === -1 &&
        sanNest.indexOf("c<") === -1);

  // Over-cap attribute value is dropped while its element is kept.
  var bigAttr = '<svg><circle foo="' + "a".repeat(100) + '" r="1"/></svg>';
  var sanBig = b.guardSvg.sanitize(bigAttr, { profile: "balanced", maxAttrValueBytes: 20 });
  check("sanitize drops an over-cap attribute value but keeps the element",
        sanBig.indexOf("foo") === -1 && /<circle[^>]*r="1"/.test(sanBig));

  // External-ref on <use> under allowExternalRefs:false → href stripped, the
  // <use> element itself kept.
  var extUse = '<svg><use xlink:href="icons.svg#x"/></svg>';
  var sanUse = b.guardSvg.sanitize(extUse, { profile: "balanced", allowExternalRefs: false });
  check("sanitize strips external <use> href when allowExternalRefs:false",
        sanUse.indexOf("icons.svg") === -1 && /<use\/?>/.test(sanUse));

  // Single-quoted + unquoted attribute values are parsed and re-emitted
  // double-quoted (re-serialization normalizes quoting).
  var mixed = "<svg><rect fill='red' width=10 height=10/></svg>";
  var sanMixed = b.guardSvg.sanitize(mixed, { profile: "balanced" });
  check("sanitize normalizes single-quoted + unquoted attrs to double-quoted",
        sanMixed.indexOf('fill="red"') !== -1 &&
        sanMixed.indexOf('width="10"') !== -1 &&
        sanMixed.indexOf('height="10"') !== -1);
}

function testGuardSvgSvgzSanitizeThrows() {
  // sanitize refuses gzipped SVGZ bytes — a text sanitizer must never run on
  // compressed input (operator ungzips + re-sanitizes the inner SVG).
  var threw = null;
  try {
    b.guardSvg.sanitize(Buffer.from([0x1F, 0x8B, 0x08, 0x00, 0x00]), { profile: "strict" });
  } catch (e) { threw = e; }
  check("sanitize(SVGZ magic bytes) throws svg.svgz",
        threw && /SVGZ|ungzip/i.test(threw.message));
}

function testGuardSvgAttrEdgeCases() {
  // Empty URL-bearing attribute value → treated as a fragment (no scheme),
  // never flagged. Exercises the empty-string extraction / fragment paths.
  var rvEmpty = b.guardSvg.validate('<svg><a xlink:href="">x</a></svg>',
                                    { profile: "balanced" });
  check("empty xlink:href value not flagged as a dangerous scheme",
        !rvEmpty.issues.some(function (i) { return i.kind === "dangerous-url-scheme"; }));

  // Spaced attribute (name = value) — whitespace around the '=' is skipped.
  var rvSpaced = b.guardSvg.validate('<svg><circle r = "1" /></svg>', { profile: "strict" });
  check("spaced attribute (name = value) parsed cleanly", rvSpaced.ok === true);

  // Malformed attribute source (leading '=' with no name) must not crash — the
  // scanner breaks out cleanly.
  var rvMal = b.guardSvg.validate('<svg><circle  = r="1" /></svg>', { profile: "strict" });
  check("malformed attribute source (leading =) parsed without error",
        rvMal && Array.isArray(rvMal.issues));

  // Trailing intra-tag whitespace before '>' exercises the whitespace-run break.
  var rvWs = b.guardSvg.validate('<svg><circle r="1"   ></circle></svg>', { profile: "strict" });
  check("trailing intra-tag whitespace parsed cleanly", rvWs.ok === true);
}

async function testGuardSvgGateDispositions() {
  // Each disposition class the gate maps, exercised through the real
  // gate().check() consumer path (verdict.action is the observable contract).
  var bidi  = String.fromCharCode(0x202E);
  var gStrict = b.guardSvg.gate({ profile: "strict" });
  var gBal    = b.guardSvg.gate({ profile: "balanced" });
  var gPerm   = b.guardSvg.gate({ profile: "permissive" });

  // char-threat (bidi) under permissive (bidiPolicy "audit") → audit-only.
  var rvBidi = await gPerm.check({
    bytes: Buffer.from("<svg><title>x" + bidi + "y</title></svg>", "utf8"),
  });
  check("gate: permissive bidi (audit policy) → audit-only",
        rvBidi.action === "audit-only");

  // doctype (reject policy in every profile) → refuse.
  var rvDoc = await gStrict.check({ bytes: Buffer.from('<!DOCTYPE svg><svg/>', "utf8") });
  check("gate: doctype → refuse", rvDoc.action === "refuse");

  // cdata under balanced (audit policy) → audit-only.
  var rvCdata = await gBal.check({ bytes: Buffer.from('<svg><![CDATA[x]]></svg>', "utf8") });
  check("gate: balanced cdata (audit policy) → audit-only",
        rvCdata.action === "audit-only");

  // processing-instruction under permissive (audit policy) → audit-only.
  var rvPi = await gPerm.check({ bytes: Buffer.from('<?xml-stylesheet href="x"?><svg/>', "utf8") });
  check("gate: permissive processing-instruction (audit policy) → audit-only",
        rvPi.action === "audit-only");

  // non-allowlisted (benign) tag → sanitize.
  var rvNal = await gBal.check({ bytes: Buffer.from('<svg><foobar/></svg>', "utf8") });
  check("gate: non-allowlisted benign tag → sanitize", rvNal.action === "sanitize");

  // tokenize-failed (input over maxBytes) → refuse.
  var rvTok = await b.guardSvg.gate({ profile: "strict", maxBytes: 10 }).check({
    bytes: Buffer.from('<svg><circle r="10"/></svg>', "utf8"),
  });
  check("gate: tokenize-failed (over maxBytes) → refuse", rvTok.action === "refuse");

  // element-count-cap → refuse.
  var rvEl = await b.guardSvg.gate({ profile: "strict", maxElementCount: 3 }).check({
    bytes: Buffer.from("<g></g>".repeat(10), "utf8"),
  });
  check("gate: element-count-cap → refuse", rvEl.action === "refuse");

  // attr-count-cap → refuse.
  var manyAttrs = "<circle";
  for (var i = 0; i < 10; i += 1) manyAttrs += ' a' + i + '="1"';
  manyAttrs += "/>";
  var rvAttrCap = await b.guardSvg.gate({ profile: "balanced", maxAttrsPerTag: 3 }).check({
    bytes: Buffer.from("<svg>" + manyAttrs + "</svg>", "utf8"),
  });
  check("gate: attr-count-cap → refuse", rvAttrCap.action === "refuse");

  // use-depth-cap → refuse.
  var deep = "";
  for (var j = 0; j < 10; j += 1) deep += "<use>";
  var rvUse = await b.guardSvg.gate({ profile: "balanced", maxUseDepth: 3 }).check({
    bytes: Buffer.from("<svg>" + deep + "</svg>", "utf8"),
  });
  check("gate: use-depth-cap → refuse", rvUse.action === "refuse");

  // attr-value-too-large → refuse.
  var rvBig = await b.guardSvg.gate({ profile: "balanced", maxAttrValueBytes: 10 }).check({
    bytes: Buffer.from('<svg><circle foo="' + "a".repeat(50) + '"/></svg>', "utf8"),
  });
  check("gate: attr-value-too-large → refuse", rvBig.action === "refuse");

  // bad-input (ctx.bytes is neither Buffer nor string) → refuse.
  var rvBad = await gStrict.check({ bytes: 12345 });
  check("gate: non-Buffer bytes (bad-input) → refuse", rvBad.action === "refuse");
}

// Every policy is a config-time entry point, so a value outside its vocabulary
// belongs at boot rather than at the first hostile request. Read leniently, a
// typo lands on whichever branch is not the strict one: `cdataPolicy: "rejct"`
// is not "allow", so the check still runs, and it is not "reject" either, so
// the finding drops from critical to warn — the operator asked to refuse a
// CDATA section and silently got an audit line.
//
// `svgzPolicy` takes one value because a gzipped payload is refused
// unconditionally: the byte signature is caught before any parse and sanitize
// throws on it outright. An operator who writes `svgzPolicy: "allow"` today
// gets a silent no-op; the single-value vocabulary tells them instead.
//
// The character policies are absent on purpose — they are derived for the
// whole family, and an entry here would shadow that derivation.
function testSvgPolicyVocabularyIsEnforced() {
  var LEGAL = {
    cssPolicy:             ["allow", "audit", "audit-only", "strip", "reject"],
    doctypePolicy:         ["allow", "audit", "audit-only", "strip", "reject"],
    cdataPolicy:           ["allow", "audit", "audit-only", "strip", "reject"],
    processingInstrPolicy: ["allow", "audit", "audit-only", "strip", "reject"],
    svgzPolicy:            ["reject"],
  };
  helpers.assertPolicyVocabulary(b.guardSvg, LEGAL, { label: "svg", sample: "<svg/>" });

  // The one value svgzPolicy does NOT take, precisely because accepting it
  // would read as "SVGZ now passes" while the refusal stayed unconditional.
  var svgzAllowRefused = false;
  try { b.guardSvg.resolveOpts({ svgzPolicy: "allow" }); }
  catch (_e3) { svgzAllowRefused = true; }
  check("svgzPolicy refuses `allow` rather than accepting it as a no-op",
        svgzAllowRefused);
}

// An EMPTY tag allowlist permits NOTHING — the guard-html sibling of this
// carries the same reasoning. Omitting `allowedTags` is how "use the profile's
// set" is spelled (balanced supplies 54), so an empty one is a caller asking
// that no tag survive, and reading it as "every tag is fine" is the inverse.
function testEmptySvgTagAllowlistPermitsNothing() {
  var empty = b.guardSvg.validate("<svg><g/></svg>", { profile: "balanced", allowedTags: [] });
  check("guard-svg: an EMPTY allowedTags refuses every tag",
        empty.issues.some(function (i) { return i.kind === "non-allowlisted-tag"; }),
        JSON.stringify(empty.issues.map(function (i) { return i.kind; })));

  // Control: absent still uses the profile's set, so an ordinary element the
  // profile permits is not flagged.
  var absent = b.guardSvg.validate("<svg><g/></svg>", { profile: "balanced" });
  check("guard-svg control: an absent allowedTags uses the profile's set",
        !absent.issues.some(function (i) { return i.kind === "non-allowlisted-tag"; }),
        JSON.stringify(absent.issues.map(function (i) { return i.kind; })));
}

async function run() {
  testUseReferenceExpansionIsBounded();
  testExpansionAgreesWithBruteForceExpansion();
  testEverySpellingOfAReferenceReachesOneVerdict();
  testPaintServerReferencesAreExpansionRoots();
  testFunctionalReferenceEdgesAreScoped();
  testCssEscapedReferencesResolve();
  testCssValueGrammarIsRespected();
  testStyleEdgesFollowRenderingDeclarations();
  testOnlyReachableCyclesAreReported();
  await testNonAllowlistedAttributeIsRepairable();
  testPrefixedHrefIsReadEverywhereHrefIs();
  testAnimatedPaintValuesAreReferences();
  testExpansionCountsTheElementsEachReferenceClones();
  testSvgTagScanSharesTheTokenizerStates();
  testReferenceScanStaysLinear();
  testWideTagIsRefusedRatherThanThrown();
  testEmptySvgTagAllowlistPermitsNothing();
  testGuardSvgSurface();
  testGuardSvgRegistryParity();
  testGuardSvgDangerousTags();
  testGuardSvgEventHandlers();
  testGuardSvgUrlSchemes();
  testGuardSvgAnimationHrefHijack();
  testGuardSvgUseExternalRef();
  testGuardSvgDoctype();
  testGuardSvgCdataAndPi();
  testGuardSvgSvgz();
  testGuardSvgCssInjection();
  testGuardSvgBidiNullControl();
  testGuardSvgCaps();
  testGuardSvgByteCapsMeasureBytes();
  testGuardSvgSanitize();
  testGuardSvgCompliancePosture();
  testGdprPostureMatchesBalancedTier();
  testGuardSvgBadProfile();
  testGuardSvgSchemeWhitespaceBypass();
  testGuardSvgCssEntityBypass();
  testGuardSvgSanitizeAnimationPreserved();
  testGuardSvgBadInput();
  testGuardSvgShortInput();
  testGuardSvgImageDataUrl();
  testGuardSvgNonAllowlistedScheme();
  testGuardSvgStructuralCaps();
  testGuardSvgStandaloneEntityDeclaration();
  testGuardSvgCdataPiAuditSeverity();
  testGuardSvgTruncatedTokens();
  testGuardSvgComment();
  testGuardSvgSanitizeStructural();
  testGuardSvgSvgzSanitizeThrows();
  testGuardSvgAttrEdgeCases();
  await testGuardSvgGate();
  await testGuardSvgGateFailOpen();
  await testGuardSvgGateDispositions();
  testSvgPolicyVocabularyIsEnforced();
}

if (require.main === module) {
  run().then(function () { console.log("OK — " + helpers.getChecks() + " checks"); })
       .catch(function (e) { console.error(helpers.formatErr(e)); process.exit(1); });
}

// A <use> renders the subtree it names, and that subtree may hold further
// <use> elements, so the quantity to bound is how far a reference chain
// reaches and how many instances it expands to. Counting source nesting
// measures neither: sibling <use/> elements nest not at all and still expand,
// so a sprite sheet was refused while twenty-five groups each referencing the
// previous one twice, about thirty-three million instances in 1.4 KB, passed.
function testUseReferenceExpansionIsBounded() {
  function bomb(n) {
    var s = '<svg xmlns="http://www.w3.org/2000/svg"><g id="g0"><circle r="1"/></g>';
    for (var i = 1; i <= n; i += 1) {
      s += '<g id="g' + i + '"><use href="#g' + (i - 1) + '"/>' +
           '<use href="#g' + (i - 1) + '"/></g>';
    }
    return s + '<use href="#g' + n + '"/></svg>';
  }
  function capped(svg, profile) {
    return b.guardSvg.validate(svg, { profile: profile })
      .issues.some(function (i) { return i.kind === "use-depth-cap"; });
  }
  ["strict", "balanced", "permissive"].forEach(function (profile) {
    [10, 25, 40].forEach(function (n) {
      check("a " + n + "-group reference bomb is refused at " + profile,
            capped(bomb(n), profile));
    });
    check("a reference cycle is refused at " + profile,
          capped('<svg xmlns="http://www.w3.org/2000/svg">' +
            '<g id="a"><use href="#b"/></g><g id="b"><use href="#a"/></g>' +
            '<use href="#a"/></svg>', profile));
    // A sheet of independent icons renders about one instance per element.
    check("a 64-icon sprite sheet is not refused at " + profile,
          !capped('<svg xmlns="http://www.w3.org/2000/svg"><defs><g id="i">' +
            '<circle r="1"/></g></defs>' +
            new Array(65).join('<use href="#i"/>') + "</svg>", profile));
  });
  check("a two-level icon composition is not refused",
        !capped('<svg xmlns="http://www.w3.org/2000/svg">' +
          '<g id="leaf"><circle r="1"/></g><g id="mid"><use href="#leaf"/></g>' +
          '<use href="#mid"/><use href="#mid"/></svg>', "strict"));
  // A rendered <use> is rendered whatever ids its ancestors carry. Keying the
  // graph only on the nearest enclosing id meant an `id` on the outer <svg>
  // moved every top-level reference off the root and left the total at zero.
  [10, 25].forEach(function (n) {
    var withId = bomb(n).replace('<svg xmlns="http://www.w3.org/2000/svg">',
      '<svg xmlns="http://www.w3.org/2000/svg" id="root">');
    ["strict", "balanced", "permissive"].forEach(function (profile) {
      check("an id on the outer svg does not hide a " + n + "-group bomb at " + profile,
            capped(withId, profile));
    });
  });

  // Chain depth is memoized per node, so reaching a node by a short path first
  // must not hide the longer path through it.
  function ascendingChain(n) {
    var s = '<svg xmlns="http://www.w3.org/2000/svg"><g id="g0"><circle r="1"/></g>';
    for (var i = 1; i <= n; i += 1) {
      s += '<g id="g' + i + '"><use href="#g' + (i - 1) + '"/></g>';
    }
    for (var j = 1; j <= n; j += 1) s += '<use href="#g' + j + '"/>';
    return s + "</svg>";
  }
  check("a deep chain used in ascending order is still refused",
        capped(ascendingChain(50), "balanced"));

  // A chain long enough to exhaust the call stack is the shape this exists to
  // refuse, so the walk carries its own stack.
  var deepThrew = null;
  var deepResult = null;
  try { deepResult = b.guardSvg.validate(ascendingChain(15000), { profile: "balanced" }); }
  catch (e) { deepThrew = e; }
  check("a 15000-group chain is measured rather than overflowing the stack",
        deepThrew === null && deepResult !== null &&
        deepResult.issues.some(function (i) { return i.kind === "use-depth-cap"; }),
        deepThrew ? String(deepThrew.message).slice(0, 80) : "");

  // Referencing an element renders its whole subtree, so a <use> belongs to
  // every id-bearing ancestor it sits under. Recording only against the
  // nearest one let an id-bearing wrapper around each group's children
  // disconnect the graph.
  function wrappedBomb(n) {
    var s = '<svg xmlns="http://www.w3.org/2000/svg"><g id="g0"><circle r="1"/></g>';
    for (var i = 1; i <= n; i += 1) {
      s += '<g id="g' + i + '"><g id="inner' + i + '">' +
           '<use href="#g' + (i - 1) + '"/><use href="#g' + (i - 1) + '"/></g></g>';
    }
    return s + '<use href="#g' + n + '"/></svg>';
  }
  ["strict", "balanced", "permissive"].forEach(function (profile) {
    check("an id-bearing wrapper does not disconnect the graph at " + profile,
          capped(wrappedBomb(25), profile));
  });

  // The instance count saturates, so a budget allowed to reach the same
  // ceiling could never be exceeded: padding the document with cheap
  // references bought enough budget to hide a real expansion.
  function paddedBomb(levels, pad) {
    var s = '<svg xmlns="http://www.w3.org/2000/svg"><g id="g0"><circle r="1"/></g>';
    for (var i = 1; i <= levels; i += 1) {
      s += '<g id="g' + i + '">';
      for (var k = 0; k < 4; k += 1) s += '<use href="#g' + (i - 1) + '"/>';
      s += "</g>";
    }
    s += '<use href="#g' + levels + '"/>';
    for (var j = 0; j < pad; j += 1) s += '<use href="#g0"/>';
    return s + "</svg>";
  }
  check("a four-way ten-level graph is refused", capped(paddedBomb(10, 0), "balanced"));
  check("padding the <use> count does not buy budget to hide it",
        capped(paddedBomb(10, 12500), "balanced"));

  // Only id-bearing ancestors are tracked, so groups without ids cost nothing
  // per reference. Scanning the whole ancestor stack was quadratic: 80000
  // nested groups took 1.43 s.
  function nestedNoIds(n) {
    return '<svg xmlns="http://www.w3.org/2000/svg"><g id="a"><circle r="1"/></g>' +
      new Array(n + 1).join("<g>") + new Array(n + 1).join('<use href="#a"/>') +
      new Array(n + 1).join("</g>") + "</svg>";
  }
  var deepStart = Date.now();
  b.guardSvg.validate(nestedNoIds(40000), { profile: "permissive" });
  check("40000 nested id-less groups are measured in linear time",
        Date.now() - deepStart < 3000);

  // A renderer resolves `href="&#35;g1"` as `#g1`, so both sides of an edge
  // are compared after decoding.
  check("a character-referenced href is the same edge",
        capped(bomb(25).split('href="#').join('href="&#35;'), "balanced"));

  // A <use> may carry an id and be referenced in turn, so it is a node as
  // well as an edge. Excluding <use> from id tracking disconnected chains
  // whose targets were themselves <use> elements.
  function useIdChain(n) {
    var s = '<svg xmlns="http://www.w3.org/2000/svg"><defs><g id="u0"><circle r="1"/></g>';
    for (var i = 1; i <= n; i += 1) {
      s += '<use id="u' + i + '" href="#u' + (i - 1) + '"/>';
    }
    return s + '</defs><use href="#u' + n + '"/></svg>';
  }
  check("a chain built from <use> ids is still a chain",
        capped(useIdChain(50), "balanced"));

  // One edge per reference and one per id-bearing element, so the graph is
  // linear in the document. Copying each reference into every id-bearing
  // ancestor made 4000 nested ids around 4000 references cost 269 MiB.
  function nestedIdsInDefs(n) {
    var s = '<svg xmlns="http://www.w3.org/2000/svg"><g id="leaf"><circle r="1"/></g><defs>';
    for (var i = 0; i < n; i += 1) s += '<g id="n' + i + '">';
    for (var j = 0; j < n; j += 1) s += '<use href="#leaf"/>';
    for (var k = 0; k < n; k += 1) s += "</g>";
    return s + "</defs></svg>";
  }
  var graphStart = Date.now();
  b.guardSvg.validate(nestedIdsInDefs(4000), { profile: "balanced" });
  check("nested ids around many references build a bounded graph",
        Date.now() - graphStart < 3000);

  // A <use> carrying an id is its own node, and its owner reaches the target
  // through it. Recording the owner edge as well counted one rendering twice,
  // so a ten-level chain scored 1024 instances and was refused, while the
  // identical document without the use ids passed.
  function idChainGroups(n) {
    var s = '<svg xmlns="http://www.w3.org/2000/svg"><defs><g id="t"><circle r="1"/></g>';
    for (var i = 1; i <= n; i += 1) {
      s += '<g id="p' + i + '"><use id="c' + i + '" href="#t"/></g>';
    }
    return s + '</defs><use href="#p' + n + '"/></svg>';
  }
  check("a chain of id-bearing uses is one path, not two",
        !capped(idChainGroups(10), "balanced"));
  check("and reaches the same verdict as the spelling without use ids",
        capped(idChainGroups(10), "balanced") ===
        capped(idChainGroups(10).split(' id="c').join(' data-c="'), "balanced"));

  // Adjacency is built once per node with the reference cost on each edge, so
  // many id-bearing siblings under one group stay linear. Concatenating the
  // lists per iteration and scanning for containment took 17 s at 64000.
  function manyIdUses(n) {
    var s = '<svg xmlns="http://www.w3.org/2000/svg"><g id="t"><circle r="1"/></g><g id="w">';
    for (var i = 0; i < n; i += 1) s += '<use id="u' + i + '" href="#t"/>';
    return s + "</g></svg>";
  }
  var siblingStart = Date.now();
  b.guardSvg.validate(manyIdUses(32000), { profile: "balanced" });
  check("32000 id-bearing <use> siblings are measured in linear time",
        Date.now() - siblingStart < 4000);

  // A renderer gives `href` precedence over `xlink:href` whatever order they
  // appear in. Returning whichever fragment came first let a decoy
  // `xlink:href` make a 16-level doubling chain look shallow.
  function bombWithDecoy(n) {
    var s = '<svg xmlns="http://www.w3.org/2000/svg"><defs><g id="g0"><circle r="1"/></g>';
    for (var i = 1; i <= n; i += 1) {
      s += '<g id="g' + i + '">';
      for (var k = 0; k < 2; k += 1) {
        s += '<use xlink:href="#g0" href="#g' + (i - 1) + '"/>';
      }
      s += "</g>";
    }
    return s + '</defs><use href="#g' + n + '"/></svg>';
  }
  check("a decoy xlink:href does not hide the effective href",
        capped(bombWithDecoy(16), "balanced"));

  // A fragment reference is a URL, so `#g%31` names the element `g1`. Treating
  // the escape as literal made a 20-level doubling chain reference targets
  // that did not exist, and the graph looked empty.
  function percentBomb(n) {
    var s = '<svg xmlns="http://www.w3.org/2000/svg"><defs><g id="g0"><circle r="1"/></g>';
    for (var i = 1; i <= n; i += 1) {
      var t = "g%3" + String(i - 1).split("").join("%3");
      s += '<g id="g' + i + '"><use href="#' + t + '"/><use href="#' + t + '"/></g>';
    }
    return s + '</defs><use href="#g' + n + '"/></svg>';
  }
  check("a percent-encoded fragment resolves to the element it names",
        capped(percentBomb(20), "balanced"));
  // A malformed escape stays literal rather than throwing, as in a URL parser.
  ["#g%", "#g%ZZ", "#g%4", "#%41", "#a%20b"].forEach(function (frag) {
    var doc = '<svg xmlns="http://www.w3.org/2000/svg"><defs><g id="g0">' +
      '<circle r="1"/></g></defs><use href="' + frag + '"/></svg>';
    var threw = null;
    try { b.guardSvg.validate(doc, { profile: "balanced" }); }
    catch (e) { threw = e; }
    check("a malformed percent escape " + JSON.stringify(frag) + " does not throw",
          threw === null, threw ? String(threw.message).slice(0, 60) : "");
  });

  // What is bounded is the copies <use> adds, not the elements already written
  // out. Counting every id-bearing child as an instance refused an ordinary
  // icon of 300 id-bearing paths used once, which amplifies nothing.
  var paths = "";
  for (var p = 0; p < 300; p += 1) paths += '<path id="p' + p + '" d="M0 0"/>';
  var icon = '<svg xmlns="http://www.w3.org/2000/svg"><defs><g id="icon">' +
    paths + '</g></defs><use href="#icon"/></svg>';
  check("ordinary geometry carrying ids is not amplification",
        !capped(icon, "balanced"));
  check("and reaches the same verdict as the same icon without ids",
        capped(icon, "balanced") ===
        capped(icon.split(' id="p').join(' data-p="'), "balanced"));

  // A URL strips leading and trailing ASCII whitespace and nothing else, so a
  // character such as U+2000 belongs to the fragment. Trimming the id with
  // String.trim removed it from one side only, and the graph lost the edge.
  var U2000 = String.fromCharCode(0x2000);
  function unicodeIdBomb(n) {
    var s = '<svg xmlns="http://www.w3.org/2000/svg"><defs><g id="' + U2000 +
            'g0"><circle r="1"/></g>';
    for (var i = 1; i <= n; i += 1) {
      s += '<g id="' + U2000 + "g" + i + '">' +
           '<use href="#%E2%80%80g' + (i - 1) + '"/>' +
           '<use href="#%E2%80%80g' + (i - 1) + '"/></g>';
    }
    return s + '</defs><use href="#%E2%80%80g' + n + '"/></svg>';
  }
  check("an id is matched without trimming its contents",
        capped(unicodeIdBomb(24), "balanced"));
  check("a fragment padded with ASCII space still resolves",
        !capped('<svg xmlns="http://www.w3.org/2000/svg"><defs>' +
          '<g id="g0"><circle r="1"/></g><g id="g1">' +
          '<use href="  #g0  "/><use href="#g0"/></g></defs>' +
          '<use href="#g1"/></svg>', "balanced"));

  // Rendering an element does not render the definitions inside it, so a
  // containment edge stops at a <defs> boundary. Crossing it turned a
  // definition that names its own ancestor into a false cycle.
  check("a definition naming its ancestor is not a rendered cycle",
        !capped('<svg xmlns="http://www.w3.org/2000/svg"><g id="icon">' +
          '<defs><g id="unused"><use href="#icon"/></g></defs>' +
          '<path d="M0 0"/></g><use href="#icon"/></svg>', "balanced"));

  // URL parsing removes every tab and newline wherever it appears, not only at
  // the ends, so `#g&#10;19` names `g19`. Trimming only the ends left the
  // graph looking for a target that does not exist.
  [["&#10;", "newline"], ["&#9;", "tab"], ["&#13;", "carriage return"]]
    .forEach(function (row) {
      var s = '<svg xmlns="http://www.w3.org/2000/svg"><defs><g id="g0">' +
              '<circle r="1"/></g>';
      for (var i = 1; i <= 20; i += 1) {
        var t = "g" + row[0] + (i - 1);
        s += '<g id="g' + i + '"><use href="#' + t + '"/><use href="#' + t + '"/></g>';
      }
      s += '</defs><use href="#g20"/></svg>';
      check("a fragment split by a " + row[1] + " names the element it renders",
            capped(s, "balanced"));
    });

  // A <defs> boundary ends rendering ownership for a reference as well as for
  // containment. Applying it to only one of the two rejected an id-less <use>
  // inside a definition while the id-bearing spelling passed.
  var idlessInDefs = '<svg xmlns="http://www.w3.org/2000/svg"><g id="icon">' +
    '<defs><use href="#icon"/></defs><path d="M0 0"/></g><use href="#icon"/></svg>';
  var wrappedInDefs = '<svg xmlns="http://www.w3.org/2000/svg"><g id="icon">' +
    '<defs><g id="w"><use href="#icon"/></g></defs><path d="M0 0"/></g>' +
    '<use href="#icon"/></svg>';
  check("an id-less use inside defs is not a rendered cycle",
        !capped(idlessInDefs, "balanced"));
  check("and reaches the same verdict as the id-bearing spelling",
        capped(idlessInDefs, "balanced") === capped(wrappedInDefs, "balanced"));

  // SVG is XML, so character references resolve in one pass: `&#38;colon;` is
  // the five characters `&colon;`. Decoding with the HTML two-pass decoder
  // went on to produce a colon, so an id and the reference naming it stopped
  // matching and a 24-level chain lost every edge.
  function xmlRefBomb(n) {
    var s = '<svg xmlns="http://www.w3.org/2000/svg"><defs>' +
            '<g id="&#38;colon;g0"><circle r="1"/></g>';
    for (var i = 1; i <= n; i += 1) {
      var t = "%26colon;g" + (i - 1);
      s += '<g id="&#38;colon;g' + i + '">' +
           '<use href="#' + t + '"/><use href="#' + t + '"/></g>';
    }
    return s + '</defs><use href="#%26colon;g' + n + '"/></svg>';
  }
  check("character references resolve with XML semantics",
        capped(xmlRefBomb(24), "balanced"));

  // A container that defines rather than draws does not render where it
  // stands, so it is not contained by its parent and an ancestor outside it
  // cannot reach in. Treating only <defs> that way made an uninstantiated
  // symbol look like a cycle.
  ["symbol", "clipPath", "mask", "marker", "pattern", "filter"].forEach(function (tag) {
    check("an uninstantiated <" + tag + "> is not a rendered cycle",
          !capped('<svg xmlns="http://www.w3.org/2000/svg"><g id="icon">' +
            "<" + tag + ' id="unused"><use href="#icon"/></' + tag + ">" +
            '<path d="M0 0"/></g><use href="#icon"/></svg>', "balanced"));
  });
  // But instantiating one still reaches its contents, so a bomb built from
  // symbols is refused exactly as one built from groups is.
  function symbolBomb(n) {
    var s = '<svg xmlns="http://www.w3.org/2000/svg"><defs><g id="g0"><circle r="1"/></g>';
    for (var i = 1; i <= n; i += 1) {
      s += '<symbol id="g' + i + '"><use href="#g' + (i - 1) + '"/>' +
           '<use href="#g' + (i - 1) + '"/></symbol>';
    }
    return s + '</defs><use href="#g' + n + '"/></svg>';
  }
  check("a bomb built from instantiated symbols is refused",
        capped(symbolBomb(24), "balanced"));
  check("instantiating a symbol renders its contents without capping",
        !capped('<svg xmlns="http://www.w3.org/2000/svg"><defs>' +
          '<g id="leaf"><circle r="1"/></g><symbol id="s"><use href="#leaf"/></symbol>' +
          '</defs><use href="#s"/></svg>', "balanced"));

  // The walk memoizes, so a document built to blow it up stays cheap.
  var t0 = Date.now();
  b.guardSvg.validate(bomb(200), { profile: "permissive" });
  check("a 200-group reference bomb is measured quickly", Date.now() - t0 < 2000);
}

// The expansion analysis walks a graph to decide what a document renders. This
// decides the same question by actually expanding the tree and counting what
// comes out, over generated documents, and asserts the two agree. The walk was
// wrong in five successive review rounds while every hand-written case passed,
// because each case was written from the same understanding as the code.
function testExpansionAgreesWithBruteForceExpansion() {
  var MAX = 100000, FLOOR = 256, AMP = 8;
  var DEPTH = { balanced: 16, permissive: 32 };

  function rng(seed) {
    var s = seed >>> 0;
    return function () { s = (s * 1664525 + 1013904223) >>> 0; return s / 4294967296; };
  }
  function makeDoc(rand, nodes, maxRefs, allowForward, wrap) {
    var defs = [];
    for (var i = 1; i < nodes; i += 1) {
      var refs = [];
      var n = Math.floor(rand() * (maxRefs + 1));
      for (var k = 0; k < n; k += 1) {
        refs.push(allowForward ? Math.floor(rand() * nodes) : Math.floor(rand() * i));
      }
      defs.push({ id: i, refs: refs });
    }
    var rendered = [];
    var r = 1 + Math.floor(rand() * 2);
    for (var q = 0; q < r; q += 1) rendered.push(1 + Math.floor(rand() * (nodes - 1)));
    return { defs: defs, rendered: rendered, wrap: wrap };
  }
  function toSvg(doc, opts) {
    var o = opts || {};
    function name(t) {
      // A fragment reference is a URL, so `#n%31` names the element `n1`.
      return o.percent ? "n%3" + String(t).split("").join("%3") : "n" + t;
    }
    function href(t) {
      return o.xlink
        ? 'xlink:href="#zz" href="#' + name(t) + '"'
        : 'href="#' + name(t) + '"';
    }
    var s = '<svg xmlns="http://www.w3.org/2000/svg"><defs><g id="n0"><circle r="1"/></g>';
    doc.defs.forEach(function (d) {
      s += '<g id="n' + d.id + '">';
      if (doc.wrap) s += '<g id="w' + d.id + '">';
      for (var p = 0; p < (o.geometry || 0); p += 1) {
        s += '<path id="p' + d.id + "_" + p + '" d="M0 0"/>';
      }
      d.refs.forEach(function (t) { s += "<use " + href(t) + "/>"; });
      if (doc.wrap) s += "</g>";
      s += "</g>";
    });
    s += "</defs>";
    doc.rendered.forEach(function (t) { s += "<use " + href(t) + "/>"; });
    return s + "</svg>";
  }
  function edgesOf(doc) {
    var byId = new Map();
    doc.defs.forEach(function (d) { byId.set(d.id, d.refs); });
    return byId;
  }
  // Expand for real, with a step budget.
  function expand(doc) {
    var byId = edgesOf(doc);
    var instances = 0, deepest = 0, steps = 0;
    var stack = [];
    doc.rendered.forEach(function (t) { stack.push({ id: t, depth: 1 }); });
    while (stack.length > 0 && steps < MAX * 4 && instances < MAX) {
      steps += 1;
      var cur = stack.pop();
      if (cur.depth > deepest) deepest = cur.depth;
      // Each reference followed renders one copy of its target, whatever
      // geometry that target holds.
      instances += 1;
      if (cur.depth > 64) { instances = MAX; break; }
      var kids = byId.get(cur.id) || [];
      for (var i = 0; i < kids.length; i += 1) {
        stack.push({ id: kids[i], depth: cur.depth + 1 });
      }
    }
    if (steps >= MAX * 4) instances = MAX;
    return { instances: Math.min(instances, MAX), depth: deepest };
  }
  // A reference cycle is refused wherever it sits, so its presence is the
  // finding rather than its effect on a particular rendering.
  function hasCycle(doc) {
    var byId = edgesOf(doc);
    var found = false;
    var done = new Set();
    function visit(id, path) {
      if (path.indexOf(id) !== -1) { found = true; return; }
      if (done.has(id)) return;
      var kids = byId.get(id) || [];
      for (var i = 0; i < kids.length && !found; i += 1) visit(kids[i], path.concat([id]));
      done.add(id);
    }
    // Only what renders can loop. A cycle among definitions nothing
    // references is never walked, so it is not a finding.
    doc.rendered.forEach(function (id) { if (!found) visit(id, []); });
    return found;
  }
  // The amplification allowance is drawn from the references that take part
  // in rendering: the roots, plus every reference inside a definition reached
  // from a root. A definition nothing reaches contributes none, so padding a
  // document with dormant references cannot lift the cap.
  function useCountOf(doc) {
    var byId = edgesOf(doc);
    var seen = new Set();
    var stack = doc.rendered.slice();
    var n = doc.rendered.length;
    while (stack.length > 0) {
      var id = stack.pop();
      if (seen.has(id)) continue;
      seen.add(id);
      var kids = byId.get(id) || [];
      n += kids.length;
      for (var i = 0; i < kids.length; i += 1) stack.push(kids[i]);
    }
    return n;
  }
  function predict(doc, profile) {
    if (hasCycle(doc)) return true;
    var e = expand(doc);
    if (e.depth > DEPTH[profile]) return true;
    var budget = Math.min(MAX - 1, Math.max(FLOOR, useCountOf(doc) * AMP));
    return e.instances >= MAX || e.instances > budget;
  }

  var shapes = [
    { nodes: 6, maxRefs: 2, fwd: false, wrap: false },
    { nodes: 10, maxRefs: 3, fwd: false, wrap: false },
    { nodes: 10, maxRefs: 2, fwd: false, wrap: true },
    { nodes: 8, maxRefs: 2, fwd: true, wrap: false },
    { nodes: 14, maxRefs: 2, fwd: false, wrap: true },
    { nodes: 8, maxRefs: 2, fwd: false, wrap: false, geometry: 40 },
    { nodes: 6, maxRefs: 2, fwd: false, wrap: true, geometry: 12 },
    { nodes: 8, maxRefs: 2, fwd: false, wrap: false, xlink: true },
    { nodes: 8, maxRefs: 2, fwd: false, wrap: false, percent: true },
    { nodes: 10, maxRefs: 2, fwd: false, wrap: true, percent: true },
  ];
  var mismatches = [];
  var cappedSeen = 0;
  var total = 0;
  shapes.forEach(function (shape, si) {
    var rand = rng(1000 + si * 7919);
    for (var t = 0; t < 60; t += 1) {
      var doc = makeDoc(rand, shape.nodes, shape.maxRefs, shape.fwd, shape.wrap);
      var svg = toSvg(doc, {
        geometry: shape.geometry, xlink: shape.xlink, percent: shape.percent,
      });
      ["balanced", "permissive"].forEach(function (profile) {
        var want = predict(doc, profile);
        var got = b.guardSvg.validate(svg, { profile: profile })
          .issues.some(function (i) { return i.kind === "use-depth-cap"; });
        total += 1;
        if (want) cappedSeen += 1;
        if (want !== got && mismatches.length < 3) {
          mismatches.push(profile + " want=" + want + " got=" + got + " " + svg.slice(0, 150));
        } else if (want !== got) {
          mismatches.push("(more)");
        }
      });
    }
  });
  check("the expansion analysis agrees with brute-force expansion over " +
        total + " generated documents",
        mismatches.length === 0, mismatches.slice(0, 2).join(" || "));
  // The corpus has to contain both verdicts, or agreement proves nothing.
  check("the generated corpus exercises both verdicts",
        cappedSeen > 0 && cappedSeen < total,
        cappedSeen + " of " + total + " capped");
}

function testEverySpellingOfAReferenceReachesOneVerdict() {
  var SPELLINGS = [
    { name: "plain", id: function (s) { return s; }, frag: function (s) { return s; } },
    { name: "numeric character reference in the id",
      id: function (s) { return "&#x67;" + s.slice(1); },
      frag: function (s) { return s; } },
    { name: "percent-encoded fragment",
      id: function (s) { return s; },
      frag: function (s) { return "%67" + s.slice(1); } },
    { name: "tab inside the fragment",
      id: function (s) { return s; },
      frag: function (s) { return s.charAt(0) + "&#9;" + s.slice(1); } },
    { name: "newline inside the fragment",
      id: function (s) { return s; },
      frag: function (s) { return s.charAt(0) + "&#10;" + s.slice(1); } },
    { name: "ASCII space around the fragment",
      id: function (s) { return s; },
      frag: function (s) { return s; }, pad: true },
    { name: "U+2000 in the id and percent-escaped in the fragment",
      id: function (s) { return String.fromCharCode(0x2000) + s; },
      frag: function (s) { return "%E2%80%80" + s; } },
    { name: "XML character reference in the id, percent-escaped in the fragment",
      id: function (s) { return "&#38;colon;" + s; },
      frag: function (s) { return "%26colon;" + s; } },
  ];
  var HREF_ATTRS = [
    { name: "href", write: function (v) { return 'href="' + v + '"'; } },
    { name: "xlink:href", write: function (v) { return 'xlink:href="' + v + '"'; } },
    { name: "href following an xlink:href",
      write: function (v) { return 'xlink:href="#absent" href="' + v + '"'; } },
  ];

  function build(levels, spelling, attr, breakRefs) {
    function idOf(n) { return spelling.id("g" + n); }
    function refOf(n) {
      var f = "#" + spelling.frag("g" + n) + (breakRefs ? "-absent" : "");
      return spelling.pad ? "  " + f + "  " : f;
    }
    var s = '<svg xmlns="http://www.w3.org/2000/svg"><defs><g id="' + idOf(0) +
            '"><circle r="1"/></g>';
    for (var i = 1; i <= levels; i += 1) {
      s += '<g id="' + idOf(i) + '">' +
           "<use " + attr.write(refOf(i - 1)) + "/>" +
           "<use " + attr.write(refOf(i - 1)) + "/></g>";
    }
    return s + "</defs><use " + attr.write(refOf(levels)) + "/></svg>";
  }
  function capped(svg) {
    return b.guardSvg.validate(svg, { profile: "balanced" })
      .issues.some(function (i) { return i.kind === "use-depth-cap"; });
  }

  var missedBombs = [];
  var refusedBenign = [];
  var liveControls = [];
  SPELLINGS.forEach(function (sp) {
    HREF_ATTRS.forEach(function (attr) {
      var where = sp.name + " via " + attr.name;
      if (!capped(build(20, sp, attr, false))) missedBombs.push(where);
      if (capped(build(2, sp, attr, false))) refusedBenign.push(where);
      // Control: the same document with every fragment pointed at an id that
      // does not exist has no edges to walk, so a capped verdict here would
      // mean the assertion above passes without resolving anything.
      if (capped(build(20, sp, attr, true))) liveControls.push(where);
    });
  });

  check("a doubling bomb is refused however its references are spelled",
        missedBombs.length === 0, missedBombs.slice(0, 3).join(", "));
  check("a shallow document is served however its references are spelled",
        refusedBenign.length === 0, refusedBenign.slice(0, 3).join(", "));
  check("the same shapes with unresolvable fragments are served",
        liveControls.length === 0, liveControls.slice(0, 3).join(", "));
}

function testPaintServerReferencesAreExpansionRoots() {
  function capped(svg) {
    return b.guardSvg.validate(svg, { profile: "balanced" })
      .issues.some(function (i) { return i.kind === "use-depth-cap"; });
  }
  function chain(levels) {
    var s = '<g id="g0"><circle r="1"/></g>';
    for (var i = 1; i <= levels; i += 1) {
      s += '<g id="g' + i + '"><use href="#g' + (i - 1) + '"/>' +
           '<use href="#g' + (i - 1) + '"/></g>';
    }
    return s;
  }
  var CASES = [
    { tag: "pattern", attr: 'fill="url(#ref)"' },
    { tag: "pattern", attr: 'stroke="url(#ref)"' },
    { tag: "mask", attr: 'mask="url(#ref)"' },
    { tag: "clipPath", attr: 'clip-path="url(#ref)"' },
    { tag: "filter", attr: 'filter="url(#ref)"' },
    { tag: "marker", attr: 'marker-start="url(#ref)"' },
    { tag: "linearGradient", attr: 'fill="url(#ref)"' },
    { tag: "pattern", attr: 'style="fill:url(#ref)"' },
    { tag: "pattern", attr: "fill=\"url('#ref')\"" },
    { tag: "pattern", attr: 'fill="URL(#ref)"' },
    { tag: "pattern", attr: 'fill="url(#%72ef)"' },
    { tag: "pattern", attr: 'fill="url(#&#114;ef)"' },
  ];
  var escaped = [];
  CASES.forEach(function (c) {
    var doc = '<svg xmlns="http://www.w3.org/2000/svg"><defs>' + chain(20) +
      "<" + c.tag + ' id="ref"><use href="#g20"/></' + c.tag + ">" +
      "</defs><rect " + c.attr + "/></svg>";
    if (!capped(doc)) escaped.push("<" + c.tag + "> " + c.attr);
  });
  check("a bomb reached through a functional reference is refused",
        escaped.length === 0, escaped.slice(0, 3).join(", "));

  // Control: the same bomb in the same container, with nothing painting it.
  // A capped verdict here would mean the checks above pass without the
  // reference being read at all.
  check("the same container is served when nothing references it",
        !capped('<svg xmlns="http://www.w3.org/2000/svg"><defs>' + chain(20) +
          '<pattern id="ref"><use href="#g20"/></pattern>' +
          '</defs><rect fill="#333"/></svg>'));

  check("a sprite sheet with gradients, patterns and clips is served",
        !capped('<svg xmlns="http://www.w3.org/2000/svg"><defs>' +
          '<pattern id="hatch"><path d="M0 0L4 4"/></pattern>' +
          '<linearGradient id="grad"><stop offset="0"/><stop offset="1"/></linearGradient>' +
          '<clipPath id="clip"><rect width="10" height="10"/></clipPath>' +
          '<g id="icon"><circle r="2"/></g></defs>' +
          '<rect fill="url(#hatch)" clip-path="url(#clip)"/>' +
          '<rect fill="url(#grad)"/><use href="#icon"/><use href="#icon"/></svg>'));
  check("a gradient inheriting from another gradient is served",
        !capped('<svg xmlns="http://www.w3.org/2000/svg"><defs>' +
          '<linearGradient id="base"><stop offset="0"/></linearGradient>' +
          '<linearGradient id="derived" href="#base"/></defs>' +
          '<rect fill="url(#derived)"/></svg>'));
  check("two patterns painting each other are refused",
        capped('<svg xmlns="http://www.w3.org/2000/svg">' +
          '<pattern id="p"><rect fill="url(#q)"/></pattern>' +
          '<pattern id="q"><rect fill="url(#p)"/></pattern>' +
          '<rect fill="url(#p)"/></svg>'));
}

function testFunctionalReferenceEdgesAreScoped() {
  function capped(svg) {
    return b.guardSvg.validate(svg, { profile: "balanced" })
      .issues.some(function (i) { return i.kind === "use-depth-cap"; });
  }
  function chain(levels) {
    var s = '<g id="g0"><circle r="1"/></g>';
    for (var i = 1; i <= levels; i += 1) {
      s += '<g id="g' + i + '"><use href="#g' + (i - 1) + '"/>' +
           '<use href="#g' + (i - 1) + '"/></g>';
    }
    return s;
  }
  function painted(attr) {
    return '<svg xmlns="http://www.w3.org/2000/svg"><defs>' + chain(20) +
      '<pattern id="ref"><use href="#g20"/></pattern></defs><rect ' + attr + "/></svg>";
  }

  // A reference costs one instance, so the budget counts it the same way the
  // expansion does. Ordinary documents share one paint server across many
  // elements and must stay inside it.
  check("257 rectangles sharing one gradient are served",
        !capped('<svg xmlns="http://www.w3.org/2000/svg"><defs>' +
          '<linearGradient id="g"><stop offset="0"/></linearGradient></defs>' +
          '<rect fill="url(#g)"/>'.repeat(257) + "</svg>"));
  check("400 rectangles sharing one clip path are served",
        !capped('<svg xmlns="http://www.w3.org/2000/svg"><defs>' +
          '<clipPath id="c"><rect width="4" height="4"/></clipPath></defs>' +
          '<rect clip-path="url(#c)"/>'.repeat(400) + "</svg>"));

  // Only a property that takes a functional reference is an edge. A label or a
  // data attribute holding the same text renders nothing.
  var described = [];
  [
    '<g id="x" aria-label="url(#x)"><rect/></g>',
    '<g id="x" data-note="url(#x)"><rect/></g>',
    '<g id="x"><rect title="url(#x)"/></g>',
  ].forEach(function (body) {
    var doc = '<svg xmlns="http://www.w3.org/2000/svg">' + body + "</svg>";
    if (capped(doc)) described.push(body);
  });
  check("a descriptive attribute holding url(#id) is not an edge",
        described.length === 0, described.join(" | "));

  // A functional reference may quote its argument and pad it with spaces.
  var missed = [];
  [
    "fill=\"url( '#ref' )\"",
    'fill="url( &quot;#ref&quot; )"',
    'fill="url(  #ref  )"',
    "style=\"fill: url( '#ref' )\"",
  ].forEach(function (attr) {
    if (!capped(painted(attr))) missed.push(attr);
  });
  check("a quoted or padded url argument still resolves",
        missed.length === 0, missed.join(" | "));

  // A template element takes its content from the element it names, so the
  // reference is an edge even though the element is not a <use>.
  check("a pattern inheriting a bomb is refused",
        capped('<svg xmlns="http://www.w3.org/2000/svg"><defs>' + chain(20) +
          '<pattern id="src"><use href="#g20"/></pattern>' +
          '<pattern id="dst" href="#src"/></defs><rect fill="url(#dst)"/></svg>'));
  check("two gradients inheriting each other are refused",
        capped('<svg xmlns="http://www.w3.org/2000/svg"><defs>' +
          '<linearGradient id="a" href="#b"/><linearGradient id="b" href="#a"/>' +
          '</defs><rect fill="url(#a)"/></svg>'));
  check("a gradient inheriting from another gradient is served",
        !capped('<svg xmlns="http://www.w3.org/2000/svg"><defs>' +
          '<linearGradient id="base"><stop offset="0"/></linearGradient>' +
          '<linearGradient id="derived" href="#base"/></defs>' +
          '<rect fill="url(#derived)"/></svg>'));
}

function testCssEscapedReferencesResolve() {
  var BS = String.fromCharCode(92);
  function capped(svg) {
    return b.guardSvg.validate(svg, { profile: "balanced" })
      .issues.some(function (i) { return i.kind === "use-depth-cap"; });
  }
  function chain(levels) {
    var s = '<g id="g0"><circle r="1"/></g>';
    for (var i = 1; i <= levels; i += 1) {
      s += '<g id="g' + i + '"><use href="#g' + (i - 1) + '"/>' +
           '<use href="#g' + (i - 1) + '"/></g>';
    }
    return s;
  }
  function painted(attr) {
    return '<svg xmlns="http://www.w3.org/2000/svg"><defs>' + chain(25) +
      '<pattern id="ref"><use href="#g25"/></pattern></defs><rect ' + attr + "/></svg>";
  }

  // A CSS escape is a spelling, not a different value: a renderer resolves
  // all of these to url(#ref). The escape may sit in the function name, the
  // argument, or the identifier, and one whitespace character after the hex
  // digits delimits the escape rather than being part of the value.
  var missed = [];
  [
    'fill="url(' + BS + '23 ref)"',
    'style="fill:u' + BS + '72l(#ref)"',
    'fill="u' + BS + '72l(#ref)"',
    'style="fill:url(' + BS + '23 ref)"',
    'fill="url(' + BS + '000023 ref)"',
    'fill="url(#' + BS + '72 ef)"',
    'fill="url(#ref)"',
  ].forEach(function (attr) {
    if (!capped(painted(attr))) missed.push(attr);
  });
  check("a CSS-escaped functional reference is still an edge",
        missed.length === 0, missed.join(" | "));

  check("the same document with nothing painted is served",
        !capped('<svg xmlns="http://www.w3.org/2000/svg"><defs>' + chain(25) +
          '<pattern id="ref"><use href="#g25"/></pattern></defs><rect fill="#333"/></svg>'));

  check("a <style> element is refused, so the attribute is the only CSS read",
        b.guardSvg.validate('<svg xmlns="http://www.w3.org/2000/svg"><style>' +
          "*{fill:red}</style><rect/></svg>", { profile: "balanced" }).ok === false);

  var mt = markupTokenizer;
  check("cssUnescape resolves a hex escape and its delimiter",
        mt.cssUnescape(BS + "23 ref") === "#ref", mt.cssUnescape(BS + "23 ref"));
  check("cssUnescape keeps a second space",
        mt.cssUnescape(BS + "23  ref") === "# ref");
  check("cssUnescape passes a literal escape through",
        mt.cssUnescape(BS + BS + "x") === BS + "x");
  check("cssUnescape leaves text with no backslash alone",
        mt.cssUnescape("url(#ref)") === "url(#ref)");
  check("cssUnescape maps a null escape to the replacement character",
        mt.cssUnescape(BS + "0 a") === String.fromCharCode(0xFFFD) + "a");
}

function testCssValueGrammarIsRespected() {
  function capped(svg) {
    return b.guardSvg.validate(svg, { profile: "balanced" })
      .issues.some(function (i) { return i.kind === "use-depth-cap"; });
  }
  function chain(levels) {
    var s = '<g id="g0"><circle r="1"/></g>';
    for (var i = 1; i <= levels; i += 1) {
      s += '<g id="g' + i + '"><use href="#g' + (i - 1) + '"/>' +
           '<use href="#g' + (i - 1) + '"/></g>';
    }
    return s;
  }
  function painted(attr, id) {
    return '<svg xmlns="http://www.w3.org/2000/svg"><defs>' + chain(20) +
      '<pattern id="' + id + '"><use href="#g20"/></pattern></defs>' +
      "<rect " + attr + "/></svg>";
  }

  // The argument of url() may be quoted, and a quoted argument runs to its
  // own closing quote, so a parenthesis inside it does not end the function.
  var missed = [];
  [
    { attr: "fill=\"url('#r)ef')\"", id: "r)ef" },
    { attr: 'fill="url(&quot;#r)ef&quot;)"', id: "r)ef" },
    { attr: "style=\"fill:url('#r)ef')\"", id: "r)ef" },
    { attr: "fill=\"url('#ref')\"", id: "ref" },
    { attr: 'fill="url(#ref)"', id: "ref" },
  ].forEach(function (c) {
    if (!capped(painted(c.attr, c.id))) missed.push(c.attr);
  });
  check("a quoted url argument may contain a parenthesis",
        missed.length === 0, missed.join(" | "));

  // A commented-out declaration paints nothing, so it is not an edge.
  var invented = [];
  [
    '<g id="x" style="/* fill:url(#x) */ fill:red"><rect/></g>',
    '<g id="x" style="/*url(#x)*/"><rect/></g>',
    '<g id="x" style="fill:red /* url(#x) */"><rect/></g>',
    '<g id="x" style="/* fill:url(#x)"><rect/></g>',
  ].forEach(function (body) {
    if (capped('<svg xmlns="http://www.w3.org/2000/svg">' + body + "</svg>")) {
      invented.push(body);
    }
  });
  check("a CSS comment does not create a reference",
        invented.length === 0, invented.join(" | "));

  // Control: with the comment closed, the declaration beside it still counts.
  check("a live declaration beside a comment is still a reference",
        capped(painted('style="/* nothing */ fill:url(#ref)"', "ref")));
}

function testStyleEdgesFollowRenderingDeclarations() {
  function capped(svg) {
    return b.guardSvg.validate(svg, { profile: "balanced" })
      .issues.some(function (i) { return i.kind === "use-depth-cap"; });
  }
  function chain(levels) {
    var s = '<g id="g0"><circle r="1"/></g>';
    for (var i = 1; i <= levels; i += 1) {
      s += '<g id="g' + i + '"><use href="#g' + (i - 1) + '"/>' +
           '<use href="#g' + (i - 1) + '"/></g>';
    }
    return s;
  }
  function painted(attr, id) {
    return '<svg xmlns="http://www.w3.org/2000/svg"><defs>' + chain(20) +
      '<pattern id="' + (id || "ref") + '"><use href="#g20"/></pattern></defs>' +
      "<rect " + attr + "/></svg>";
  }

  // Deciding whether a particular `url(#id)` is the one that paints takes a
  // CSS cascade: declaration order and importance, custom-property scope and
  // inheritance, guaranteed-invalid values, the shadow tree a <use> builds.
  // A second, weaker implementation of that is the thing an attacker writes
  // against, and each rule it lacks is a reference the renderer follows and
  // the guard does not. So the guard does not model the cascade. Every
  // `url(#id)` written in a property that takes one, or in a custom property,
  // is a reference. The cost is over-refusal of a document that names a
  // fragment it never paints; the assertions below pin both sides of that.
  var missed = [];
  [
    'style="--p:url(#ref);fill:var(--p)"',
    'style="--p:url(#ref)" fill="var(--p)"',
    'style="--a:url(#ref);--b:var(--a);fill:var(--b)"',
    'style="--p:url(#ref);fill:var(--missing,var(--p))"',
    'style="fill:var(--missing,url(#ref))"',
    'style="fill:url(#ref)"',
    'style="--note:none;fill:url(#ref)"',
    'style="--P:url(#ref);fill:var(--P)"',
    'style="fill:url(#ref);fill:red"',
    'style="fill:red;fill:url(#ref)"',
    'style="mask:url(#ref);mask:bogus"',
    'style="fill:url(#ref)!impor\\74 ant;fill:none"',
    'fill="url(#ref)" style="fill:red"',
  ].forEach(function (attr) { if (!capped(painted(attr))) missed.push(attr); });
  check("every url(#id) a renderer could follow is a reference",
        missed.length === 0, missed.join(" | "));
  check("a reference on an ancestor is read for its descendants too",
        capped('<svg xmlns="http://www.w3.org/2000/svg"><defs>' + chain(20) +
          '<pattern id="ref"><use href="#g20"/></pattern></defs>' +
          '<g style="--p:url(#ref)"><rect fill="var(--p)"/></g></svg>'));
  check("a reference on a use instance is read",
        capped('<svg xmlns="http://www.w3.org/2000/svg"><defs>' + chain(20) +
          '<pattern id="ref"><use href="#g20"/></pattern>' +
          '<g id="icon"><rect style="mask:var(--paint)"/></g></defs>' +
          '<use href="#icon" style="--paint:url(#ref)"/></svg>'));
  check("a semicolon inside a quoted argument does not split the declaration",
        capped(painted("style=\"fill:url('#r;ef')\"", "r;ef")));

  // The one filter kept is the property name, which is a lookup rather than a
  // cascade: a declaration whose property never takes a functional reference
  // paints nothing through it.
  check("a property that takes no functional reference is not a reference",
        !capped('<svg xmlns="http://www.w3.org/2000/svg">' +
          '<g id="x" style="background-image:url(#x)"><rect/></g></svg>'));

  // A comment stands where whitespace may, including around a quoted argument.
  var dropped = [];
  [
    "fill=\"url('#ref' /* c */)\"",
    'fill="url(/* c */ &quot;#ref&quot;)"',
    "fill=\"url(/* c */ '#ref' /* c */)\"",
    'fill="url( /* c */ #ref )"',
  ].forEach(function (attr) { if (!capped(painted(attr))) dropped.push(attr); });
  check("a comment may stand wherever whitespace may", dropped.length === 0,
        dropped.join(" | "));

  check("a definition inside defs reaches nothing on its own",
        !capped('<svg xmlns="http://www.w3.org/2000/svg"><defs>' + chain(20) +
          '<pattern id="ref"><use href="#g20"/></pattern>' +
          '<g style="--p:url(#ref)"><rect/></g></defs><rect fill="#333"/></svg>'));

  // An element that defines rather than draws does not render its own
  // attributes either, so naming itself is not a loop until something paints it.
  var selfNamed = [];
  ["pattern", "mask", "clipPath", "marker", "filter", "symbol", "linearGradient"]
    .forEach(function (tag) {
      if (capped('<svg xmlns="http://www.w3.org/2000/svg">' +
        "<" + tag + ' id="p" fill="url(#p)"><rect/></' + tag + "><rect/></svg>")) {
        selfNamed.push(tag);
      }
    });
  check("an unused non-rendering element naming itself is served",
        selfNamed.length === 0, selfNamed.join(", "));
  check("a drawing element naming itself is still a cycle",
        capped('<svg xmlns="http://www.w3.org/2000/svg">' +
          '<g id="p" fill="url(#p)"><rect/></g></svg>'));

  check("a definition inside a referenced definition is followed",
        capped('<svg xmlns="http://www.w3.org/2000/svg"><defs>' + chain(20) +
          '<pattern id="ref"><use href="#g20"/></pattern>' +
          '<g id="holder" style="--p:url(#ref)"><rect fill="var(--p)"/></g>' +
          '</defs><use href="#holder"/></svg>'));

  // An element that defines rather than draws does not bind its own reference
  // to the ancestor that encloses it.
  check("an unused gradient naming its ancestor is served",
        !capped('<svg xmlns="http://www.w3.org/2000/svg">' +
          '<g id="icon"><linearGradient href="#icon"/>' +
          '<rect width="10" height="10"/></g><use href="#icon"/></svg>'));
  check("giving that gradient an id does not change the verdict",
        !capped('<svg xmlns="http://www.w3.org/2000/svg">' +
          '<g id="icon"><linearGradient id="grad" href="#icon"/>' +
          '<rect width="10" height="10"/></g><use href="#icon"/></svg>'));

  check("an ordinary property name still folds case",
        capped(painted('style="FILL:url(#ref)"')));

  // The documented cost of not modelling the cascade: a fragment named in a
  // declaration the renderer discards is still read. These are refused, and
  // recording that here is what keeps the trade visible rather than a
  // surprise. Each names a pattern that references itself, so reading it at
  // all is a cycle.
  function loopFor(body) {
    return '<svg xmlns="http://www.w3.org/2000/svg"><defs>' +
      '<pattern id="p"><use href="#p"/></pattern></defs>' + body + "</svg>";
  }
  var overRefused = [];
  [
    '<rect style="--unused:url(#p);fill:red"/>',
    '<rect style="fill:red;fill:url(#p)"/>',
    '<rect style="fill:red !important;fill:url(#p)"/>',
    '<rect style="--paint:red;fill:var(--paint,url(#p))"/>',
    '<g id="x" style="--a:url(#p);--b:var(--a);fill:red"><rect/></g>',
  ].forEach(function (body) {
    if (!capped(loopFor(body))) overRefused.push(body);
  });
  check("a fragment named in a discarded declaration is still read",
        overRefused.length === 0, overRefused.join(" | "));
}

async function testNonAllowlistedAttributeIsRepairable() {
  // The sanitizer removes the attribute, so the gate offers that repair rather
  // than refusing the document, which is how a non-allowlisted tag behaves.
  var opts = { profile: "balanced", allowedAttrs: ["xmlns"] };
  var doc = '<svg xmlns="http://www.w3.org/2000/svg"><rect role="img"/></svg>';
  check("validate reports the attribute",
        b.guardSvg.validate(doc, opts).issues.some(function (i) {
          return i.kind === "non-allowlisted-attr";
        }));
  var cleaned = b.guardSvg.sanitize(doc, opts);
  check("sanitize removes the attribute and keeps the element",
        cleaned.indexOf("role") === -1 && cleaned.indexOf("<rect") !== -1, cleaned);
  var verdict = await b.guardSvg.gate(opts).check({
    contentType: "image/svg+xml", bytes: Buffer.from(doc, "utf8"),
  });
  check("the gate asks for sanitize", verdict.action === "sanitize",
        "action=" + verdict.action);
  // Control: a finding the sanitizer cannot repair is still a refusal.
  var evil = '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>';
  var refused = await b.guardSvg.gate({ profile: "balanced" }).check({
    contentType: "image/svg+xml", bytes: Buffer.from(evil, "utf8"),
  });
  check("a script element is still refused", refused.action === "refuse",
        "action=" + refused.action);
}

function testOnlyReachableCyclesAreReported() {
  function capped(svg) {
    return b.guardSvg.validate(svg, { profile: "balanced" })
      .issues.some(function (i) { return i.kind === "use-depth-cap"; });
  }
  // A definition nothing references is never walked by a renderer, so a loop
  // inside it costs nothing and is not a finding.
  check("a self-referencing unused definition is served",
        !capped('<svg xmlns="http://www.w3.org/2000/svg"><defs>' +
          '<g id="unused"><use href="#unused"/></g></defs><rect/></svg>'));
  check("a two-node unused cycle is served",
        !capped('<svg xmlns="http://www.w3.org/2000/svg"><defs>' +
          '<g id="a"><use href="#b"/></g><g id="b"><use href="#a"/></g>' +
          "</defs><rect/></svg>"));
  // Control: the same loops, reached.
  check("a cycle that renders is refused",
        capped('<svg xmlns="http://www.w3.org/2000/svg">' +
          '<g id="a"><use href="#b"/></g><g id="b"><use href="#a"/></g>' +
          '<use href="#a"/></svg>'));
  check("a cycle reached through paint is refused",
        capped('<svg xmlns="http://www.w3.org/2000/svg">' +
          '<pattern id="p"><rect fill="url(#q)"/></pattern>' +
          '<pattern id="q"><rect fill="url(#p)"/></pattern>' +
          '<rect fill="url(#p)"/></svg>'));
}

function testReferenceScanStaysLinear() {
  // A cell or attribute of unmatched openers must not make each opener rescan
  // the suffix behind it.
  var growth = require("../helpers/growth");
  function svgOf(n) {
    return '<svg xmlns="http://www.w3.org/2000/svg"><rect fill="' +
      "url(".repeat(n) + '"/></svg>';
  }
  check("guardSvg stays linear over repeated unterminated url(",
        !growth.looksSuperlinear(function (n) {
          b.guardSvg.validate(svgOf(n), { profile: "balanced" });
        }, { small: 16000, large: 64000, threshold: 8 }));

  // An escaped closing parenthesis is a `)` to lastIndexOf and not to the
  // argument scanner, so the "no closer after here" shortcut let every opener
  // scan to the end. A scan that runs off the end now ends the walk.
  var BS = String.fromCharCode(92);
  function escapedTail(n) {
    return '<svg xmlns="http://www.w3.org/2000/svg"><rect style="fill:' +
      "url(".repeat(n) + BS + ')"/></svg>';
  }
  check("guardSvg stays linear over repeated url( before an escaped closer",
        !growth.looksSuperlinear(function (n) {
          b.guardSvg.validate(escapedTail(n), { profile: "balanced" });
        }, { small: 4000, large: 16000, threshold: 8 }));

  function nestedVar(n) {
    return '<svg xmlns="http://www.w3.org/2000/svg"><g style="fill:' +
      "var(".repeat(n) + "--x" + ")".repeat(n) + '"><rect/></g></svg>';
  }
  check("guardSvg stays linear over nested var(",
        !growth.looksSuperlinear(function (n) {
          b.guardSvg.validate(nestedVar(n), { profile: "balanced" });
        }, { small: 2000, large: 8000, threshold: 8 }));

  // Definitions written in reverse dependency order resolve in one chain.
  function reverseChain(n) {
    var s = '<svg xmlns="http://www.w3.org/2000/svg"><g style="';
    for (var i = n; i >= 1; i -= 1) s += "--x" + i + ":var(--x" + (i - 1) + ");";
    return s + 'fill:var(--x' + n + ')"><rect/></g></svg>';
  }
  check("guardSvg stays linear over a reverse-ordered definition chain",
        !growth.looksSuperlinear(function (n) {
          b.guardSvg.validate(reverseChain(n), { profile: "balanced" });
        }, { small: 4000, large: 16000, threshold: 8 }));

  // A lookup that walked every open ancestor per name was quadratic in the
  // product of nesting depth and name count.
  function manyNames(n) {
    var s = '<svg xmlns="http://www.w3.org/2000/svg"><g style="';
    for (var i = 0; i < n; i += 1) s += "--x" + i + ":red;";
    s += '"><rect style="fill:';
    for (var j = 0; j < n; j += 1) s += "var(--x" + j + ") ";
    return s + '"/></g></svg>';
  }
  check("guardSvg stays linear over many distinct custom-property names",
        !growth.looksSuperlinear(function (n) {
          b.guardSvg.validate(manyNames(n), { profile: "balanced" });
        }, { small: 2000, large: 8000, threshold: 8 }));

  // Every consumer of one deep chain must not re-walk it.
  function manyConsumers(n) {
    var open = "";
    var close = "";
    for (var i = 1; i <= n; i += 1) {
      open += '<g style="--x' + i + ':var(--x' + (i - 1) + ')">';
      close += "</g>";
    }
    var rects = "";
    for (var j = 0; j < n; j += 1) rects += '<rect style="fill:var(--x' + n + ')"/>';
    return '<svg xmlns="http://www.w3.org/2000/svg">' + open + rects + close + "</svg>";
  }
  check("guardSvg stays linear over many consumers of one chain",
        !growth.looksSuperlinear(function (n) {
          b.guardSvg.validate(manyConsumers(n), { profile: "balanced" });
        }, { small: 1000, large: 4000, threshold: 8 }));

  // Each level names the one below it twice. Storing the resolved targets as a
  // list rather than a set doubles the stored array per level, so this is a
  // memory assertion: a timing one passes either way once the work is cached.
  function doubling(levels) {
    var s = '<svg xmlns="http://www.w3.org/2000/svg"><defs>' +
      '<g id="a"><circle r="1"/></g></defs><rect style="--x0:url(#a);';
    for (var i = 1; i <= levels; i += 1) {
      s += "--x" + i + ":var(--x" + (i - 1) + ") var(--x" + (i - 1) + ");";
    }
    return s + "fill:var(--x" + levels + ')"/></svg>';
  }
  var doc = doubling(26);
  var before = process.memoryUsage().heapUsed;
  b.guardSvg.validate(doc, { profile: "balanced" });
  var grewMiB = (process.memoryUsage().heapUsed - before) / (1024 * 1024);
  check("a doubling definition chain does not amplify memory",
        grewMiB < 64, doc.length + " bytes grew the heap by " + grewMiB.toFixed(1) + " MiB");

  // Each link adds one new target to the one below it. Caching a resolved
  // target list per definition stores every earlier target again at every
  // link, which is quadratic in the declaration count.
  function additive(n) {
    var s = '<svg xmlns="http://www.w3.org/2000/svg"><defs>';
    for (var i = 0; i < n; i += 1) s += '<g id="x' + i + '"><circle r="1"/></g>';
    s += '</defs><rect style="--v0:url(#x0);';
    for (var j = 1; j < n; j += 1) {
      s += "--v" + j + ":var(--v" + (j - 1) + ") url(#x" + j + ");";
    }
    return s + "fill:var(--v" + (n - 1) + ')"/></svg>';
  }
  var wide = additive(2000);
  var wideBefore = process.memoryUsage().heapUsed;
  b.guardSvg.validate(wide, { profile: "balanced" });
  var wideMiB = (process.memoryUsage().heapUsed - wideBefore) / (1024 * 1024);
  check("an additive definition chain does not amplify memory",
        wideMiB < 128,
        wide.length + " bytes grew the heap by " + wideMiB.toFixed(1) + " MiB");
  check("a doubling chain onto a bomb is still refused",
        b.guardSvg.validate(
          '<svg xmlns="http://www.w3.org/2000/svg"><defs>' + (function () {
            var s = '<g id="g0"><circle r="1"/></g>';
            for (var i = 1; i <= 20; i += 1) {
              s += '<g id="g' + i + '"><use href="#g' + (i - 1) + '"/>' +
                   '<use href="#g' + (i - 1) + '"/></g>';
            }
            return s;
          })() + '<pattern id="ref"><use href="#g20"/></pattern></defs>' +
          '<rect style="--x0:url(#ref);--x1:var(--x0) var(--x0);' +
          '--x2:var(--x1) var(--x1);fill:var(--x2)"/></svg>',
          { profile: "balanced" }
        ).issues.some(function (i) { return i.kind === "use-depth-cap"; }));
}

function testPrefixedHrefIsReadEverywhereHrefIs() {
  // In an XML document the prefix is a binding, not a name: with
  // xmlns:l bound to the XLink namespace, l:href is xlink:href. The guard does
  // not model the bindings; any prefix on href is read, which is the stricter
  // side, and every check that reads href reads it: the expansion graph, the
  // dangerous-scheme check in validate and in sanitize, and the external
  // reference rule at strict.
  var NS = ' xmlns="http://www.w3.org/2000/svg"' +
    ' xmlns:l="http://www.w3.org/1999/xlink"' +
    ' xmlns:xlink="http://www.w3.org/1999/xlink"';
  function kinds(svg, p) {
    return b.guardSvg.validate(svg, { profile: p }).issues.map(function (i) { return i.kind; });
  }
  function chain(levels, attr) {
    var s = '<g id="g0"><circle r="1"/></g>';
    for (var i = 1; i <= levels; i += 1) {
      s += '<g id="g' + i + '"><use ' + attr + '="#g' + (i - 1) + '"/>' +
           "<use " + attr + '="#g' + (i - 1) + '"/></g>';
    }
    return s;
  }
  check("a bound prefix on href is an expansion edge",
        kinds("<svg" + NS + "><defs>" + chain(20, "l:href") +
              '</defs><use l:href="#g20"/></svg>', "balanced")
          .indexOf("use-depth-cap") !== -1);
  // Which of several href spellings a renderer honors depends on the
  // namespace bindings, which the guard does not model, so every spelling on
  // the element is followed: a prefix bound to nothing cannot shadow the
  // real one, whichever order they appear in.
  var shadowed = [];
  [
    '<use foo:href="#g0" xlink:href="#g20"/>',
    '<use xlink:href="#g20" foo:href="#g0"/>',
    '<use l:href="#g20" href="#g0"/>',
    '<use href="#g0" l:href="#g20"/>',
  ].forEach(function (use) {
    if (kinds("<svg" + NS + ' xmlns:foo="urn:ignored"><defs>' + chain(20, "href") +
              "</defs>" + use + "</svg>", "balanced").indexOf("use-depth-cap") === -1) {
      shadowed.push(use);
    }
  });
  check("no href spelling shadows another", shadowed.length === 0, shadowed.join(" | "));
  // Both spellings naming the same fragment is the backward-compatible form
  // every exporter writes, and a renderer instantiates the target once. Two
  // edges per level had turned a nine-link chain into a thousand instances.
  function bothSpellings(levels) {
    var s = '<g id="g0"><circle r="1"/></g>';
    for (var i = 1; i <= levels; i += 1) {
      s += '<g id="g' + i + '"><use href="#g' + (i - 1) + '" xlink:href="#g' + (i - 1) + '"/></g>';
    }
    return "<svg" + NS + "><defs>" + s + '</defs><use href="#g' + levels + '" xlink:href="#g' + levels + '"/></svg>';
  }
  check("href and xlink:href naming one target are one reference",
        kinds(bothSpellings(9), "balanced").indexOf("use-depth-cap") === -1);
  check("and a chain past maxUseDepth with both spellings is still refused",
        kinds(bothSpellings(20), "balanced").indexOf("use-depth-cap") !== -1);

  var missed = [];
  ["a", "image"].forEach(function (tag) {
    ["l:href", "foo:href"].forEach(function (attr) {
      ["balanced", "permissive"].forEach(function (p) {
        var doc = "<svg" + NS + "><" + tag + " " + attr + '="javascript:alert(1)"/></svg>';
        if (kinds(doc, p).indexOf("dangerous-url-scheme") === -1) {
          missed.push(tag + " " + attr + " " + p);
        }
      });
    });
  });
  check("a prefixed href takes the dangerous-scheme check at every profile",
        missed.length === 0, missed.join(", "));

  var doc = "<svg" + NS + '><a l:href="javascript:alert(1)"><text>x</text></a></svg>';
  var out = b.guardSvg.sanitize(doc, { profile: "permissive" });
  check("sanitize removes a javascript: value from a prefixed href",
        out.indexOf("javascript") === -1, out);

  var both = ["xlink:href", "l:href"].map(function (attr) {
    return kinds("<svg" + NS + "><use " + attr +
                 '="https://evil.example/x.svg#a"/></svg>', "strict")
      .indexOf("external-ref") !== -1;
  });
  check("the external reference rule at strict reads both spellings",
        both[0] === true && both[1] === true);
}

function testAnimatedPaintValuesAreReferences() {
  // An allowed animation can set a paint property to a functional reference,
  // so its value attributes take the same reading a static declaration does.
  function capped(svg) {
    return b.guardSvg.validate(svg, { profile: "permissive" })
      .issues.some(function (i) { return i.kind === "use-depth-cap"; });
  }
  function chain(levels) {
    var s = '<g id="g0"><circle r="1"/></g>';
    for (var i = 1; i <= levels; i += 1) {
      s += '<g id="g' + i + '"><use href="#g' + (i - 1) + '"/>' +
           '<use href="#g' + (i - 1) + '"/></g>';
    }
    return s;
  }
  function withBomb(body) {
    return '<svg xmlns="http://www.w3.org/2000/svg"><defs>' + chain(20) +
      '<pattern id="ref"><use href="#g20"/></pattern></defs>' + body + "</svg>";
  }
  var missed = [];
  [
    '<rect><set attributeName="fill" to="url(#ref)"/></rect>',
    '<rect><animate attributeName="fill" from="red" to="url(#ref)"/></rect>',
    '<rect><animate attributeName="fill" values="red;url(#ref);blue"/></rect>',
    '<rect><animate attributeName="fill" by="url(#ref)"/></rect>',
    '<rect><animate attributeName="mask" to="url(#ref)"/></rect>',
  ].forEach(function (body) { if (!capped(withBomb(body))) missed.push(body); });
  check("an animated value naming a reference is an edge",
        missed.length === 0, missed.join(" | "));
  check("an animation inside defs reaches nothing on its own",
        !capped('<svg xmlns="http://www.w3.org/2000/svg"><defs>' + chain(20) +
          '<pattern id="ref"><use href="#g20"/></pattern>' +
          '<rect><set attributeName="fill" to="url(#ref)"/></rect></defs>' +
          '<rect fill="#333"/></svg>'));
  check("an animation naming no reference is served",
        !capped('<svg xmlns="http://www.w3.org/2000/svg"><rect>' +
          '<animate attributeName="opacity" from="0" to="1" dur="1s"/></rect></svg>'));
}

function testExpansionCountsTheElementsEachReferenceClones() {
  // A reference renders every element of its target, so the cost of a
  // document is the elements it draws, not the references it follows. Five
  // thousand references to a five-thousand-element group is five thousand
  // references and twenty-five million rectangles.
  function capped(svg, p) {
    return b.guardSvg.validate(svg, { profile: p || "balanced" })
      .issues.some(function (i) { return i.kind === "use-depth-cap"; });
  }
  function tile(rects, uses, withIds) {
    var leaves = "";
    for (var i = 0; i < rects; i += 1) {
      leaves += withIds ? '<path id="p' + i + '" d="M0 0"/>' : '<rect width="1" height="1"/>';
    }
    return '<svg xmlns="http://www.w3.org/2000/svg"><defs><g id="tile">' + leaves +
      "</g></defs>" + '<use href="#tile"/>'.repeat(uses) + "</svg>";
  }
  check("5000 references to a 5000-element group are refused", capped(tile(5000, 5000)));
  check("and at the permissive profile", capped(tile(5000, 5000), "permissive"));
  // An element with an id is its own node in the graph, and a node that did
  // not count itself weighed nothing, so the same document rendered for free.
  check("the same document with an id on every leaf is refused",
        capped(tile(5000, 5000, true)));
  check("a 300 by 400 tiling is refused", capped(tile(300, 400)));

  // Control: the documents a sprite sheet or an illustration actually contains.
  var refused = [];
  [
    [50, 17], [200, 3], [10, 257], [100, 100],
  ].forEach(function (c) { if (capped(tile(c[0], c[1]))) refused.push(c.join("x")); });
  check("ordinary reuse stays served", refused.length === 0, refused.join(", "));
  check("a heavy group nothing references is served",
        !capped('<svg xmlns="http://www.w3.org/2000/svg"><defs><g id="big">' +
          '<rect/>'.repeat(5000) + '</g></defs><rect fill="#333"/></svg>'));
  // An element with an id is a node that counts itself, so its parent must
  // not count it again: 6000 identified rectangles used ten times is 60,000
  // rendered elements, under the cap, and used twenty times is over it.
  check("an identified element is counted once, so ordinary reuse is served",
        !capped(tile(6000, 10, true)));
  check("and the same group used twice as often is refused",
        capped(tile(6000, 20, true)));
  check("a plain document of 5000 elements is served",
        !capped('<svg xmlns="http://www.w3.org/2000/svg">' +
          '<rect width="1" height="1"/>'.repeat(5000) + "</svg>"));

  // The amplification allowance is drawn from references that render, so a
  // definition nothing reaches cannot pad it. Counting every reference in the
  // source let 2,730 dormant patterns raise the budget over a 21,845-instance
  // graph.
  function fourWay(levels) {
    var s = '<g id="g0"><circle r="1"/></g>';
    for (var i = 1; i <= levels; i += 1) {
      s += '<g id="g' + i + '">' + ('<use href="#g' + (i - 1) + '"/>').repeat(4) + "</g>";
    }
    return s;
  }
  var padding = "";
  for (var p = 0; p < 2730; p += 1) padding += '<pattern href="#missing' + p + '"/>';
  check("a seven-level four-way graph is refused",
        capped('<svg xmlns="http://www.w3.org/2000/svg"><defs>' + fourWay(7) +
          '</defs><use href="#g7"/></svg>'));
  check("dormant references do not lift the amplification cap",
        capped('<svg xmlns="http://www.w3.org/2000/svg"><defs>' + fourWay(7) + padding +
          '</defs><use href="#g7"/></svg>'));
  check("nor at the permissive profile",
        capped('<svg xmlns="http://www.w3.org/2000/svg"><defs>' + fourWay(7) + padding +
          '</defs><use href="#g7"/></svg>', "permissive"));
}

function testSvgTagScanSharesTheTokenizerStates() {
  // The SVG guard reads tags through the same scanner the HTML guard does,
  // so the unquoted-value and recovery rules hold here too.
  function kinds(doc) {
    return b.guardSvg.validate(doc, { profile: "strict" }).issues.map(function (i) { return i.kind; });
  }
  check("a quote inside an unquoted value does not swallow the following script",
        kinds('<svg xmlns="http://www.w3.org/2000/svg"><rect x=a=\'b><script>alert(1)</script></svg>')
          .some(function (k) { return k === "dangerous-tag" || k === "non-allowlisted-tag"; }));
  var unread = [];
  [65, 200, 5000].forEach(function (n) {
    var doc = '<svg xmlns="http://www.w3.org/2000/svg"><rect ' + "/".repeat(n) + " onload=alert(1)/></svg>";
    if (kinds(doc).indexOf("event-handler") === -1) unread.push(String(n));
  });
  check("a handler after any number of separators is read", unread.length === 0,
        "unread after " + unread.join(", ") + " separators");
}

function testWideTagIsRefusedRatherThanThrown() {
  // A call carries every spread element as its own argument, so an array
  // appended with .apply decides the argument count. V8 refuses past roughly
  // 125000 of them.
  var wideAttrs = "a ".repeat(130000);
  var attrs = markupTokenizer.parseAttrsRecovering(wideAttrs);
  check("the recovering parser reads 130000 attributes", attrs.length === 130000,
        "got " + attrs.length);

  var wideTag = "<div " + wideAttrs + ">x</div>";
  var wideSvg = '<svg xmlns="http://www.w3.org/2000/svg"><rect ' + wideAttrs + "/></svg>";
  var threw = [];
  ["strict", "balanced", "permissive"].forEach(function (profile) {
    [
      { name: "guardHtml.validate", run: function () { b.guardHtml.validate(wideTag, { profile: profile }); } },
      { name: "guardHtml.sanitize", run: function () { b.guardHtml.sanitize(wideTag, { profile: profile }); } },
      { name: "guardSvg.validate", run: function () { b.guardSvg.validate(wideSvg, { profile: profile }); } },
      { name: "guardSvg.sanitize", run: function () { b.guardSvg.sanitize(wideSvg, { profile: profile }); } },
    ].forEach(function (c) {
      try { c.run(); } catch (e) { threw.push(c.name + " " + profile + ": " + e.message); }
    });
  });
  check("a tag of 130000 attributes reaches the guards' policies rather than throwing",
        threw.length === 0, threw.slice(0, 2).join(" || "));
}

module.exports = { run: run };
