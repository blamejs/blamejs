// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * guard-yaml — YAML content-safety primitive (b.guardYaml).
 *
 * Covers: surface; registry parity; dangerous-tag detection
 * (!!python/ / !!java. / !!ruby/ / !!perl/ / !!js/ / !!cs/ / !!system.
 * / !!eval / !!exec / !!new / !!apply); custom-tag and core-tag
 * policy; anchor/alias detection; alias-explosion detection; multi-
 * document streams; Norway-problem implicit booleans (no/yes/y/n/on/
 * off); leading-zero octals; merge-key chain; duplicate keys at same
 * indent level; bidi/null/control char detection; sanitize discipline
 * (no safe sanitization — refuse on critical/high); profile + posture
 * vocabulary.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function testGuardYamlSurface() {
  check("guardYaml is an object",                    typeof b.guardYaml === "object");
  check("guardYaml.NAME === 'yaml'",                 b.guardYaml.NAME === "yaml");
  check("guardYaml.KIND === 'content'",              b.guardYaml.KIND === "content");
  check("guardYaml.MIME_TYPES has application/yaml", b.guardYaml.MIME_TYPES.indexOf("application/yaml") !== -1);
  check("guardYaml.EXTENSIONS has .yaml",            b.guardYaml.EXTENSIONS.indexOf(".yaml") !== -1);
  check("guardYaml.PROFILES has strict",             !!b.guardYaml.PROFILES["strict"]);
  check("guardYaml.PROFILES has balanced",           !!b.guardYaml.PROFILES["balanced"]);
  check("guardYaml.PROFILES has permissive",         !!b.guardYaml.PROFILES["permissive"]);
  check("guardYaml.COMPLIANCE_POSTURES has hipaa",   !!b.guardYaml.COMPLIANCE_POSTURES["hipaa"]);
  check("guardYaml.validate is a function",          typeof b.guardYaml.validate === "function");
  check("guardYaml.parse is a function",             typeof b.guardYaml.parse === "function");
  check("guardYaml.gate is a function",              typeof b.guardYaml.gate === "function");
  check("guardYaml.GuardYamlError is a function",    typeof b.guardYaml.GuardYamlError === "function");
  check("frameworkError.GuardYamlError exposed",     typeof b.frameworkError.GuardYamlError === "function");
}

function testGuardYamlRegistryParity() {
  check("guardYaml registered in guardAll",
        b.guardAll.list().some(function (g) { return g.name === "yaml"; }));
}

function testGuardYamlDangerousTags() {
  var prefixes = ["!!python/object", "!!java.util.HashMap",
                  "!!ruby/object:Class", "!!perl/", "!!js/Function",
                  "!!system.IO.File", "!!eval foo", "!!apply [1]"];
  for (var i = 0; i < prefixes.length; i++) {
    var rv = b.guardYaml.validate(prefixes[i] + "\n", { profile: "strict" });
    check("dangerous-tag detected: " + JSON.stringify(prefixes[i]),
          rv.ok === false &&
          rv.issues.some(function (issue) { return issue.kind === "dangerous-tag"; }));
  }
}

function testGuardYamlCustomTag() {
  var rv = b.guardYaml.validate("!Foo bar\n", { profile: "strict" });
  check("custom tag refused under strict",
        rv.issues.some(function (issue) { return issue.kind === "custom-tag"; }));
}

function testGuardYamlAlias() {
  var rv = b.guardYaml.validate("a: &a v\nb: *a\n", { profile: "strict" });
  check("anchors+aliases refused under strict",
        rv.issues.some(function (issue) { return issue.kind === "alias-disabled"; }));
}

function testGuardYamlAliasExplosion() {
  // Build alias-amplification > 8x anchors.
  var src = "a: &a 1\n";
  for (var i = 0; i < 20; i++) src += "b" + i + ": *a\n";
  var rv = b.guardYaml.validate(src, { profile: "balanced" });
  check("alias explosion detected (8x amplification floor)",
        rv.issues.some(function (issue) { return issue.kind === "alias-explosion"; }));
}

function testGuardYamlMultiDoc() {
  var rv = b.guardYaml.validate("---\nfoo: 1\n---\nbar: 2\n", { profile: "strict" });
  check("multi-document refused under strict",
        rv.issues.some(function (issue) { return issue.kind === "multi-document"; }));
}

function testGuardYamlNorwayProblem() {
  var inputs = ["country: NO\n", "x: yes\n", "y: y\n", "active: on\n",
                "mode: off\n", "n: no\n"];
  for (var i = 0; i < inputs.length; i++) {
    var rv = b.guardYaml.validate(inputs[i], { profile: "strict" });
    check("Norway problem detected: " + JSON.stringify(inputs[i]),
          rv.issues.some(function (issue) { return issue.kind === "norway-implicit-bool"; }));
  }

  // Quoted form NOT flagged.
  var rvQuoted = b.guardYaml.validate('country: "NO"\n', { profile: "strict" });
  check("quoted form NOT flagged",
        !rvQuoted.issues.some(function (issue) { return issue.kind === "norway-implicit-bool"; }));
}

function testGuardYamlLeadingZeroOctal() {
  var rv = b.guardYaml.validate("mode: 0777\n", { profile: "strict" });
  check("leading-zero octal detected",
        rv.issues.some(function (issue) { return issue.kind === "leading-zero-octal"; }));

  // Repeated on the SAME input. A scan whose matcher carries state between
  // calls answers the same question differently each time — a validator that
  // detects a finding on the first document and misses it on the second is
  // worse than one that never detected it, because nothing about the input
  // says which answer you got. A single call can never show this, which is
  // why the check above passed while every other invocation missed.
  var seen = 0;
  for (var i = 0; i < 6; i += 1) {
    var again = b.guardYaml.validate("mode: 0777\n", { profile: "strict" });
    if (again.issues.some(function (issue) { return issue.kind === "leading-zero-octal"; })) seen += 1;
  }
  check("leading-zero octal detected on every repeat call, not alternating",
        seen === 6);

  // Distinct documents in sequence, the shape an operator's gate actually sees.
  var docs = ["mode: 0777\n", "perm: 0644\n", "umask: 0022\n", "bits: 0755\n"];
  var missed = docs.filter(function (doc) {
    return !b.guardYaml.validate(doc, { profile: "strict" }).issues
      .some(function (issue) { return issue.kind === "leading-zero-octal"; });
  });
  check("leading-zero octal detected across a run of distinct documents",
        missed.length === 0);
}

function testGuardYamlMergeKey() {
  var rv = b.guardYaml.validate("base: &b\n  x: 1\nuser:\n  <<: *b\n  y: 2\n",
                                { profile: "strict" });
  check("merge-key with anchor reference detected",
        rv.issues.some(function (issue) { return issue.kind === "merge-key"; }));
}

function testGuardYamlDuplicateKeys() {
  var rv = b.guardYaml.validate("a: 1\na: 2\n", { profile: "strict" });
  check("duplicate-key detected at same indent",
        rv.issues.some(function (issue) { return issue.kind === "duplicate-key"; }));

  var rvNotDup = b.guardYaml.validate("x:\n  a: 1\ny:\n  a: 2\n", { profile: "strict" });
  check("same key at different scopes NOT flagged",
        !rvNotDup.issues.some(function (issue) { return issue.kind === "duplicate-key"; }));
}

function testGuardYamlBidiNull() {
  var bidi = String.fromCharCode(0x202E);
  var rv = b.guardYaml.validate("name: a" + bidi + "b\n", { profile: "strict" });
  check("bidi override detected in YAML scalar",
        rv.issues.some(function (issue) { return issue.kind === "bidi-override"; }));

  var nb = String.fromCharCode(0);
  var rvNull = b.guardYaml.validate("name: a" + nb + "b\n", { profile: "strict" });
  check("null byte detected",
        rvNull.issues.some(function (issue) { return issue.kind === "null-byte"; }));
}

function testGuardYamlByteCap() {
  // "é" (U+00E9) is 1 UTF-16 code unit but 2 UTF-8 bytes. Five of them are
  // 5 code units / 10 bytes; with maxBytes:6 the cap must measure BYTES — a
  // .length compare would see 5 <= 6 and let a 10-byte input past a 6-byte cap.
  var multibyte = "é".repeat(5);
  var rvOver = b.guardYaml.validate(multibyte, { profile: "permissive", maxBytes: 6 });
  var capIssue = rvOver.issues.filter(function (issue) { return issue.kind === "too-large"; })[0];
  check("multibyte over byte cap → too-large fires (byte measure, not char)",
        !!capIssue);
  check("too-large snippet reports the byte length, not the char length",
        !!capIssue && capIssue.snippet === "input 10 bytes exceeds maxBytes 6");
  check("too-large carries ruleId yaml.too-large",
        !!capIssue && capIssue.ruleId === "yaml.too-large");

  // Same five code units fit under a byte cap that covers their 10 bytes.
  var rvUnder = b.guardYaml.validate(multibyte, { profile: "permissive", maxBytes: 16 });
  check("multibyte under byte cap → too-large does NOT fire",
        !rvUnder.issues.some(function (issue) { return issue.kind === "too-large"; }));

  // ASCII (1 byte == 1 code unit) is unaffected by the byte measure.
  var rvAscii = b.guardYaml.validate("aaaaaaaa", { profile: "permissive", maxBytes: 4 });
  check("ASCII over cap still fires with byte-count snippet",
        rvAscii.issues.some(function (issue) {
          return issue.kind === "too-large" &&
                 issue.snippet === "input 8 bytes exceeds maxBytes 4";
        }));

  // Non-string input is refused with the yaml.bad-input ruleId.
  var rvBad = b.guardYaml.validate(12345, { profile: "permissive" });
  check("non-string input → bad-input with ruleId yaml.bad-input",
        rvBad.issues.some(function (issue) {
          return issue.kind === "bad-input" && issue.ruleId === "yaml.bad-input";
        }));
}

function testGuardYamlClean() {
  var rv = b.guardYaml.validate("name: alice\nage: 30\ntags:\n  - one\n  - two\n",
                                { profile: "strict" });
  check("clean YAML → ok=true with no issues",
        rv.ok === true && rv.issues.length === 0);
}

function testGuardYamlParseStrictThrows() {
  var threw = null;
  try { b.guardYaml.parse("!!python/object/new:cls\nargs: [a]\n", { profile: "strict" }); }
  catch (e) { threw = e; }
  check("parse strict: throws on dangerous tag",
        threw && /dangerous-tag/.test(threw.code || threw.message || ""));
}

async function testGuardYamlGate() {
  var g = b.guardYaml.gate({ profile: "strict" });
  var clean = await g.check({
    contentType: "application/yaml",
    bytes:       Buffer.from("name: alice\n", "utf8"),
  });
  check("gate clean → action=serve",
        clean.ok === true && clean.action === "serve");

  var hostile = await g.check({
    contentType: "application/yaml",
    bytes:       Buffer.from("!!python/object/new:cls\nargs: [a]\n", "utf8"),
  });
  check("gate dangerous tag → action !== serve",
        hostile.action !== "serve");
}

// Each character class carries a policy per profile, and the gate's action has
// to be the one that policy names — `strip` repairs, `audit` records, `reject`
// refuses. Resolving the action from a finding's SEVERITY instead ignores the
// policy entirely and refuses every class, so an operator who configured
// `strip` gets their document rejected rather than cleaned.
//
// The carrier is a YAML scalar so the document still parses with the character
// removed; the guard therefore reports exactly the character finding, and the
// action under test is unambiguous.
async function testGuardYamlGateFollowsCharacterPolicy() {
  var CARRIER = { bidiPolicy: "\u202e", controlPolicy: "\u0001",
                  zeroWidthPolicy: "\u200b", nullBytePolicy: "\u0000" };
  var WANT = { reject: "refuse", strip: "sanitize", audit: "audit-only" };
  var probed = 0;
  var wrong = [];

  for (var profile of Object.keys(b.guardYaml.PROFILES)) {
    var policies = b.guardYaml.PROFILES[profile];
    for (var key of Object.keys(CARRIER)) {
      var declared = policies[key];
      if (!declared || !WANT[declared]) continue;
      var decision = await b.guardYaml.gate({ profile: profile }).check({
        contentType: "application/yaml",
        bytes: Buffer.from("key: va" + CARRIER[key] + "lue\n", "utf8"),
      });
      probed += 1;
      if (decision.action !== WANT[declared]) {
        wrong.push(profile + "." + key + "=" + declared +
                   " → " + decision.action + " (want " + WANT[declared] + ")");
      }
    }
  }

  check("guard-yaml: every character policy was reachable to probe",
        probed >= 8, "probed=" + probed);
  check("guard-yaml: the gate action follows the declared policy",
        wrong.length === 0, wrong.join("; "));
}

function testGuardYamlCompliancePosture() {
  var hipaa = b.guardYaml.compliancePosture("hipaa");
  check("compliancePosture('hipaa') sets reject policies",
        hipaa.tagPolicy === "reject" &&
        hipaa.aliasPolicy === "reject");
  var threw = null;
  try { b.guardYaml.compliancePosture("unknown"); }
  catch (e) { threw = e; }
  check("compliancePosture: unknown name throws",
        threw && /unknown/.test(threw.message));
}

function testGuardYamlBadProfile() {
  var threw = null;
  try { b.guardYaml.validate("a: 1\n", { profile: "made-up" }); }
  catch (e) { threw = e; }
  check("validate: unknown profile throws",
        threw && /unknown profile/i.test(threw.message));
}

// The anchor, alias, Norway-token, leading-zero and merge-key screens are
// character walks. Each is compared against the pattern it replaced, over a
// corpus of the documents this guard exists to classify.
function testYamlScreensAgreeWithThePatternsTheyReplaced() {
  var ANCHOR_DECL_RE = /(^|\s|:|-)(&[A-Za-z_][A-Za-z0-9_-]*)/g;
  var ALIAS_REF_RE   = /(^|\s|:|-|\[|\{|,)(\*[A-Za-z_][A-Za-z0-9_-]*)/g;
  var NORWAY_BOOL_QUIRK_RE = /:\s*(no|yes|y|n|on|off)\b/gi;
  var LEADING_ZERO_OCTAL_RE = /:\s*0\d+\b/;
  var MERGE_KEY_RE = /<<\s*:\s*\*/;

  var DOCS = [
    "", "a: 1", "a: &anchor 1\nb: *anchor",
    "a: &x 1\nb: &y 2\nc: *x\nd: *y",
    "list: [*a, *b]", "map: {k: *a}", "x: -&a", "x:&a", "a&b: 1",
    "text: this &notanchor", "t: a*b", "s: '*star'",
    "country: no", "country: NO", "country: nope", "flag: yes", "flag: y",
    "flag: on", "flag: off", "v: n", "v: none", "v: nyet",
    "mode: 0777", "mode: 0", "mode: 00", "mode: 0x1f", "mode: 012abc",
    "v: 0777\nw: 1", "url: http://x", "time: 12:30:00",
    "defaults: &d\n  a: 1\nuse:\n  <<: *d",
    "use:\n  << : *d", "use:\n  <<:*d", "use:\n  <<  :  *d", "no merge here",
    "---\na: 1\n---\nb: 2", "--- \nx: 1", "a: 1\n---\nb: 2", "---",
    "--- ", "\n--- x", "a: 1\n--- ",
    // An empty first document is the cheapest multi-document stream to write,
    // and its first separator sits at index 1 rather than at index 0.
    "\n--- \na: 1", "\n---\na: 1\n---\nb: 2", "\r\n--- \na: 1",
  ];

  var diffs = [];
  DOCS.forEach(function (doc) {
    var kinds = b.guardYaml.validate(doc, { profile: "strict" }).issues
      .map(function (i) { return i.kind; });
    function has(k) { return kinds.indexOf(k) !== -1; }
    function compare(label, expected, actual) {
      if (expected !== actual) {
        diffs.push(label + " " + JSON.stringify(doc) + " kinds=" + JSON.stringify(kinds));
      }
    }
    var anchors = (doc.match(ANCHOR_DECL_RE) || []).length;
    var aliases = (doc.match(ALIAS_REF_RE) || []).length;
    compare("alias", anchors > 0 || aliases > 0, has("alias-disabled"));
    NORWAY_BOOL_QUIRK_RE.lastIndex = 0;
    compare("norway", NORWAY_BOOL_QUIRK_RE.test(doc), has("norway-implicit-bool"));
    compare("octal", LEADING_ZERO_OCTAL_RE.test(doc), has("leading-zero-octal"));
    compare("merge-key", MERGE_KEY_RE.test(doc), has("merge-key"));
    // Under strict, multiDocPolicy is reject, so the finding appears whenever
    // the scan counted at least one separator.
    compare("multi-document", (doc.match(/(^|\n)---\s/g) || []).length > 0,
            has("multi-document"));
  });
  check("every YAML screen agrees with the pattern it replaced (" +
        DOCS.length + " documents)", diffs.length === 0,
        diffs.slice(0, 4).join(" | "));
}

// Every policy is a config-time entry point, so a value outside its vocabulary
// belongs at boot rather than at the first hostile document. Read leniently, a
// typo takes whichever branch is not the strict one: `aliasPolicy: "rejct"` is
// not "allow", so the check runs, and it is not "reject" either, so a
// billion-laughs alias chain drops to a warning.
//
// `audit-only` is not in the vocabulary here, unlike most of the family:
// tagPolicy tests for "audit" exactly, and the synonym would fall past both
// branches.
function testPolicyVocabularyIsEnforced() {
  var LEGAL = {
    tagPolicy:          ["reject", "audit", "allow"],
    aliasPolicy:        ["reject", "audit", "allow"],
    multiDocPolicy:     ["reject", "audit", "allow"],
    norwayPolicy:       ["reject", "audit", "allow"],
    leadingZeroPolicy:  ["reject", "audit", "allow"],
    duplicateKeyPolicy: ["reject", "audit", "allow"],
    mergeKeyPolicy:     ["reject", "audit", "allow"],
  };
  helpers.assertPolicyVocabulary(b.guardYaml, LEGAL, { label: "yaml", sample: "a: 1\n" });

  // `parse` binds its own resolver rather than the generated one, so it is its
  // own door and has to refuse the same values.
  var parseRefused = false;
  try { b.guardYaml.parse("a: 1\n", { aliasPolicy: "definitely-not-a-policy-value" }); }
  catch (_e) { parseRefused = true; }
  check("yaml: parse refuses a policy value outside the vocabulary too", parseRefused);
}

async function run() {
  testPolicyVocabularyIsEnforced();
  testYamlScreensAgreeWithThePatternsTheyReplaced();
  testGuardYamlSurface();
  testGuardYamlRegistryParity();
  testGuardYamlDangerousTags();
  testGuardYamlCustomTag();
  testGuardYamlAlias();
  testGuardYamlAliasExplosion();
  testGuardYamlMultiDoc();
  testGuardYamlNorwayProblem();
  testGuardYamlLeadingZeroOctal();
  testGuardYamlMergeKey();
  testGuardYamlDuplicateKeys();
  testGuardYamlBidiNull();
  testGuardYamlByteCap();
  testGuardYamlClean();
  testGuardYamlParseStrictThrows();
  testGuardYamlCompliancePosture();
  testGuardYamlBadProfile();
  await testGuardYamlGate();
  await testGuardYamlGateFollowsCharacterPolicy();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[guard-yaml] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
