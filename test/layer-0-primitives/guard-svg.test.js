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

async function run() {
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
  await testGuardSvgGate();
  await testGuardSvgGateFailOpen();
}

if (require.main === module) {
  run().then(function () { console.log("OK — " + helpers.getChecks() + " checks"); })
       .catch(function (e) { console.error(helpers.formatErr(e)); process.exit(1); });
}

module.exports = { run: run };
