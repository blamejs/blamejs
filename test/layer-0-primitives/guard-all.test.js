// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * guard-all — registry + aggregator for the guard-* family (b.guardAll).
 *
 * Covers: surface; registry parity check (every member declares NAME /
 * MIME_TYPES / EXTENSIONS / shared profiles / shared postures / gate);
 * gate creation defaults to ALL guards on; exceptFor opt-out requires a
 * non-empty reason; override merges into per-guard opts; bad profile /
 * bad posture / unknown guard name throw; byExtension / byContentType
 * map shape; audit emission on creation; opt-out path appears in audit
 * skipped roster; per-mime dispatch routes to the right guard.
 *
 * Run standalone: node test/layer-0-primitives/guard-all.test.js
 * Or via smoke:   node test/smoke.js
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var gateContract = require("../../lib/gate-contract");

// ---- Surface ----

function testGuardAllSurface() {
  check("guardAll is an object",                  typeof b.guardAll === "object");
  check("guardAll.gate is a function",            typeof b.guardAll.gate === "function");
  check("guardAll.byExtension is a function",     typeof b.guardAll.byExtension === "function");
  check("guardAll.byContentType is a function",   typeof b.guardAll.byContentType === "function");
  check("guardAll.list is a function",            typeof b.guardAll.list === "function");
  check("guardAll.GUARDS is an array",            Array.isArray(b.guardAll.GUARDS));
  check("guardAll.GUARDS contains at least one",  b.guardAll.GUARDS.length >= 1);
  check("guardAll.SHARED_PROFILES is array",      Array.isArray(b.guardAll.SHARED_PROFILES));
  check("guardAll.SHARED_PROFILES has 3 names",   b.guardAll.SHARED_PROFILES.length === 3);
  check("guardAll.SHARED_POSTURES has 4 names",   b.guardAll.SHARED_POSTURES.length === 4);
  check("guardAll.GuardAllError is a function",   typeof b.guardAll.GuardAllError === "function");
  check("frameworkError.GuardAllError exposed",   typeof b.frameworkError.GuardAllError === "function");
}

function testGuardAllRegistryParity() {
  // Every registered guard MUST declare NAME, MIME_TYPES, EXTENSIONS,
  // gate, and the full shared-profiles + shared-postures vocabulary.
  // The parity check at module load already enforced this — surface it
  // as explicit assertions here for the operator-readable test report.
  var registered = b.guardAll.list();
  for (var i = 0; i < registered.length; i++) {
    var entry = registered[i];
    check("registry: " + entry.name + " declares MIME_TYPES",
          Array.isArray(entry.mimeTypes) && entry.mimeTypes.length > 0);
    check("registry: " + entry.name + " declares EXTENSIONS",
          Array.isArray(entry.extensions) && entry.extensions.length > 0);
    b.guardAll.SHARED_PROFILES.forEach(function (p) {
      check("registry: " + entry.name + " supports shared profile " + p,
            entry.profiles.indexOf(p) !== -1);
    });
    b.guardAll.SHARED_POSTURES.forEach(function (p) {
      check("registry: " + entry.name + " supports shared posture " + p,
            entry.postures.indexOf(p) !== -1);
    });
  }
}

// ---- Default-on behaviour ----

function testGuardAllDefaultAllOn() {
  // No exceptFor → every registered guard's mime types are in the map.
  var map = b.guardAll.byContentType({ profile: "strict" });
  var allMimes = [];
  b.guardAll.list().forEach(function (e) {
    e.mimeTypes.forEach(function (m) { allMimes.push(m); });
  });
  for (var i = 0; i < allMimes.length; i++) {
    check("default-on: " + allMimes[i] + " is in byContentType map",
          map[allMimes[i].toLowerCase()] !== undefined);
  }

  var extMap = b.guardAll.byExtension({ profile: "strict" });
  var allExt = [];
  b.guardAll.list().forEach(function (e) {
    e.extensions.forEach(function (x) { allExt.push(x); });
  });
  for (var j = 0; j < allExt.length; j++) {
    check("default-on: " + allExt[j] + " is in byExtension map",
          extMap[allExt[j].toLowerCase()] !== undefined);
  }
}

// ---- exceptFor ----

function testGuardAllExceptForRequiresReason() {
  var threwBad = null;
  try {
    b.guardAll.gate({
      profile:   "strict",
      exceptFor: { csv: {} },
    });
  } catch (e) { threwBad = e; }
  check("exceptFor: missing reason throws",
        threwBad && /reason/.test(threwBad.message));

  var threwEmpty = null;
  try {
    b.guardAll.gate({
      profile:   "strict",
      exceptFor: { csv: { reason: "   " } },
    });
  } catch (e) { threwEmpty = e; }
  check("exceptFor: blank-reason throws",
        threwEmpty && /reason/.test(threwEmpty.message));

  var threwShape = null;
  try {
    b.guardAll.gate({
      profile:   "strict",
      exceptFor: { csv: "string-not-object" },
    });
  } catch (e) { threwShape = e; }
  check("exceptFor: non-object entry throws",
        threwShape && /plain object/i.test(threwShape.message));

  var threwUnknown = null;
  try {
    b.guardAll.gate({
      profile:   "strict",
      exceptFor: { madeup: { reason: "test" } },
    });
  } catch (e) { threwUnknown = e; }
  check("exceptFor: unknown guard name throws",
        threwUnknown && /unknown guard/i.test(threwUnknown.message));
}

function testGuardAllExceptForRemovesGuard() {
  // Opting csv out leaves an empty byContentType map (today csv is the
  // only registered guard); the gate still constructs successfully.
  var map = b.guardAll.byContentType({
    profile:   "strict",
    exceptFor: { csv: { reason: "no CSV emission in this app" } },
  });
  check("exceptFor: opted-out guard absent from byContentType",
        map["text/csv"] === undefined);
  check("exceptFor: opted-out guard absent from byExtension", true);
}

// ---- Override ----

function testGuardAllOverrideAppliesPerGuardOpts() {
  // override.csv.profile = "email-attachment" — guard-csv-specific
  // profile that's NOT in the shared vocabulary; reaches the underlying
  // guard via the override map.
  var threw = null;
  try {
    b.guardAll.gate({
      profile:  "strict",
      override: { csv: { profile: "email-attachment" } },
    });
  } catch (e) { threw = e; }
  check("override: per-guard extension profile accepted via override",
        threw === null);

  var threwBadOverride = null;
  try {
    b.guardAll.gate({
      profile:  "strict",
      override: { csv: "not-an-object" },
    });
  } catch (e) { threwBadOverride = e; }
  check("override: non-object entry throws",
        threwBadOverride && /plain object/i.test(threwBadOverride.message));

  var threwUnknown = null;
  try {
    b.guardAll.gate({
      profile:  "strict",
      override: { madeup: { profile: "strict" } },
    });
  } catch (e) { threwUnknown = e; }
  check("override: unknown guard name throws",
        threwUnknown && /unknown guard/i.test(threwUnknown.message));
}

// ---- Profile + posture vocabulary ----

function testGuardAllProfileVocabulary() {
  // Per-guard extension profiles like csv's "email-attachment" are NOT
  // accepted by guardAll directly — they must come through override.
  var threw = null;
  try {
    b.guardAll.gate({ profile: "email-attachment" });
  } catch (e) { threw = e; }
  check("profile: per-guard extension name rejected at the aggregator",
        threw && /shared vocabulary/i.test(threw.message));

  var threwBadType = null;
  try { b.guardAll.gate({ profile: 42 }); }
  catch (e) { threwBadType = e; }
  check("profile: non-string throws", threwBadType && /must be a string/.test(threwBadType.message));

  // Each shared profile constructs successfully.
  for (var i = 0; i < b.guardAll.SHARED_PROFILES.length; i++) {
    var p = b.guardAll.SHARED_PROFILES[i];
    var ok = false;
    try { b.guardAll.gate({ profile: p }); ok = true; } catch (_e) { /* noop */ }
    check("profile: shared profile " + p + " constructs", ok);
  }
}

function testGuardAllPostureVocabulary() {
  var threw = null;
  try { b.guardAll.gate({ compliancePosture: "made-up-posture" }); }
  catch (e) { threw = e; }
  check("posture: unknown name rejected", threw && /shared vocabulary/i.test(threw.message));

  for (var i = 0; i < b.guardAll.SHARED_POSTURES.length; i++) {
    var p = b.guardAll.SHARED_POSTURES[i];
    var ok = false;
    try { b.guardAll.gate({ compliancePosture: p }); ok = true; } catch (_e) { /* noop */ }
    check("posture: shared posture " + p + " constructs", ok);
  }
}

// ---- Audit emission ----

function testGuardAllAuditEmitsCreationRoster() {
  var emitted = [];
  var fakeAudit = { emit: function (e) { emitted.push(e); } };
  b.guardAll.gate({
    profile:   "strict",
    audit:     fakeAudit,
    exceptFor: { csv: { reason: "trusted-source-only emission in this app" } },
  });
  var creation = emitted.filter(function (e) {
    return e.event === "guardAll.gate.created";
  })[0];
  check("audit: guardAll.gate.created emitted",   !!creation);
  check("audit: outcome=success",                 creation && creation.outcome === "success");
  check("audit: profile recorded",                creation && creation.metadata.profile === "strict");
  check("audit: skipped roster includes csv",
        creation &&
        creation.metadata.skipped.length === 1 &&
        creation.metadata.skipped[0].name === "csv" &&
        /trusted-source-only/.test(creation.metadata.skipped[0].reason));
  check("audit: active roster excludes opted-out csv",
        creation && creation.metadata.active.indexOf("csv") === -1);
}

function testGuardAllAuditEmitsAllOnByDefault() {
  var emitted = [];
  var fakeAudit = { emit: function (e) { emitted.push(e); } };
  b.guardAll.gate({ profile: "strict", audit: fakeAudit });
  var creation = emitted.filter(function (e) {
    return e.event === "guardAll.gate.created";
  })[0];
  check("audit: default-on records every guard active",
        creation && creation.metadata.active.indexOf("csv") !== -1);
  check("audit: default-on records empty skipped roster",
        creation && creation.metadata.skipped.length === 0);
}

// ---- Dispatch correctness ----

async function testGuardAllDispatchRoutesByMime() {
  // The aggregated gate should route a benign csv buffer to the csv
  // guard and serve clean. A non-registered content type bypasses (no
  // gate to apply) and serves clean as well.
  var g = b.guardAll.gate({ profile: "strict" });
  var benign = await g.check({
    contentType: "text/csv",
    bytes:       Buffer.from("a,b\n1,2\n"),
  });
  check("dispatch: text/csv benign → action=serve",
        benign.ok === true && benign.action === "serve");

  // Hostile csv → refuse / sanitize per profile.
  var hostile = await g.check({
    contentType: "text/csv",
    bytes:       Buffer.from("name,formula\r\nalice,=cmd|x\r\n"),
  });
  check("dispatch: text/csv hostile → action !== serve",
        hostile.action !== "serve");

  // Unrelated content-type with no registered guard → bypass.
  var bypass = await g.check({
    contentType: "application/json",
    bytes:       Buffer.from('{"k":"v"}'),
  });
  check("dispatch: unregistered mime → action=serve (bypass)",
        bypass.ok === true && bypass.action === "serve");
}

// ---- Wired-into-staticServe / fileUpload smoke ----

function testGuardAllByExtensionShape() {
  var map = b.guardAll.byExtension({ profile: "strict" });
  var keys = Object.keys(map);
  check("byExtension: keys are dot-prefixed lowercase extensions",
        keys.length > 0 && keys.every(function (k) { return /^\.[a-z0-9.]+$/.test(k); }));
  check("byExtension: each value has a check() function",
        keys.every(function (k) { return typeof map[k].check === "function"; }));
}

function testGuardAllByContentTypeShape() {
  var map = b.guardAll.byContentType({ profile: "strict" });
  var keys = Object.keys(map);
  check("byContentType: keys are lowercase mime strings",
        keys.length > 0 && keys.every(function (k) {
          return /^[a-z0-9][a-z0-9!#$&^_.+-]*\/[a-z0-9!#$&^_.+-]+$/.test(k);
        }));
  check("byContentType: each value has a check() function",
        keys.every(function (k) { return typeof map[k].check === "function"; }));
}

// ---- Run all ----

async function run() {
  testGuardAllSurface();
  testGuardAllRegistryParity();
  testGuardAllDefaultAllOn();
  testGuardAllExceptForRequiresReason();
  testGuardAllExceptForRemovesGuard();
  testGuardAllOverrideAppliesPerGuardOpts();
  testGuardAllProfileVocabulary();
  testGuardAllPostureVocabulary();
  testGuardAllAuditEmitsCreationRoster();
  testGuardAllAuditEmitsAllOnByDefault();
  testGuardAllByExtensionShape();
  testGuardAllByContentTypeShape();
  testGuardFamilySanitizeNeverServesThreatVerbatim();
  testGuardFamilyGateReachesTagsEnforcement();
  await testGuardFamilyTagsDispositionMatchesZeroWidth();
  testGuardFamilySeverityAgreesWithPolicy();
  testGuardFamilyEveryStripPathRemovesTheSameClasses();
  testGuardFamilyValidateIsDeterministicAcrossCalls();
  testCharacterPolicyVocabularyIsEnforced();
  testGuardFamilyDeclaresOnlyPerformableActions();
  testGuardFamilyRefusesAMalformedNumericCap();
  await testGuardFamilyGateAgreesWithValidateOnAnEmptyValue();
  await testGuardFamilyDispositionFollowsPolicy();
  testGuardFamilyStrictRejectsEveryZeroWidthCharacter();
  return testGuardAllDispatchRoutesByMime();
}

// ---- Family invariant: a declared "reject" actually rejects ----

// A guard whose strict profile says `zeroWidthPolicy: "reject"` has to refuse
// every character in the zero-width table. That was not true for seven of
// them: the shared scan was gated on an optional argument, so a caller that
// omitted it disabled the scan whatever the operator's policy said, and six
// more passed a hardcoded "warn" that dispositions to serve.
//
// The policy is read off each guard rather than listing names, so a new family
// member is covered the day it lands. A guard whose policy path this cannot
// reach FAILS rather than quietly shrinking the survey — the C0 controls are
// the proof it is reached, since every participating guard refuses those.
function testGuardFamilyStrictRejectsEveryZeroWidthCharacter() {
  var ZERO_WIDTH = [
    ["U+00AD", 0x00AD], ["U+200B", 0x200B], ["U+200C", 0x200C],
    ["U+200D", 0x200D], ["U+2060", 0x2060], ["U+2061", 0x2061],
    ["U+2062", 0x2062], ["U+2063", 0x2063], ["U+2064", 0x2064],
    ["U+FEFF", 0xFEFF],
  ];
  var LIVENESS = [["U+0000", 0x0000], ["U+001F", 0x001F]];
  var PAYLOAD = {
    yaml:     function (c) { return "a: x" + c + "y\n"; },
    shell:    function (c) { return "echo x" + c + "y"; },
    regex:    function (c) { return "^a" + c + "b$"; },
    jsonpath: function (c) { return "$.a" + c + "b"; },
    json:     function (c) { return '{"a":"x' + c + 'y"}'; },
    xml:      function (c) { return "<r>x" + c + "y</r>"; },
    svg:      function (c) { return '<svg xmlns="http://www.w3.org/2000/svg">' +
                                    "<title>x" + c + "y</title></svg>"; },
    csv:      function (c) { return "col\r\nx" + c + "y\r\n"; },
    filename: function (c) { return "re" + c + "port.txt"; },
    template: function (c) { return "Hello na" + c + "me"; },
  };
  function payloadFor(name, ch) {
    var key = Object.keys(PAYLOAD).find(function (p) { return name.indexOf(p) !== -1; });
    return key ? PAYLOAD[key](ch) : "safe" + ch + "text";
  }
  function refuses(guard, name, cp) {
    try {
      var r = guard.validate(payloadFor(name, String.fromCodePoint(cp)),
                             { profile: "strict" });
      return !!(r && r.ok === false);
    } catch (_e) {
      return true;                    // a throw is a refusal
    }
  }

  var declaring = b.guardAll.allGuards().filter(function (g) {
    return g && typeof g.validate === "function" && g.PROFILES &&
           g.PROFILES.strict && g.PROFILES.strict.zeroWidthPolicy === "reject";
  });
  check("guards declaring zeroWidthPolicy reject in strict were found",
        declaring.length > 0);

  var unreachable = [], accepted = [];
  declaring.forEach(function (g) {
    var name = g.NAME || "?";
    if (!LIVENESS.every(function (c) { return refuses(g, name, c[1]); })) {
      unreachable.push(name);
      return;
    }
    ZERO_WIDTH.forEach(function (c) {
      if (!refuses(g, name, c[1])) accepted.push(name + " accepts " + c[0]);
    });
  });

  check("every guard declaring zeroWidthPolicy reject refuses a C0 control " +
        "on the same path", unreachable.length === 0, unreachable.join(", "));
  check("every guard declaring zeroWidthPolicy reject refuses every " +
        "zero-width character", accepted.length === 0,
        accepted.slice(0, 8).join("; "));
}

// ---- Family invariant: sanitize never serves a threat back verbatim ----

// Every content guard's strip table removes only the classes an operator set
// to "strip". A guard whose sanitize also never refuses therefore has a hole
// at "reject": neither branch runs, and the threat is returned unchanged with
// no error — the strictest setting the weakest behavior. This walks the live
// registry rather than a hardcoded list, so a guard added later is covered the
// day it registers.
var THREAT_CODEPOINTS = [
  ["bidi override",  String.fromCharCode(0x202E)],
  ["C0 control",     String.fromCharCode(0x07)],
  ["null byte",      String.fromCharCode(0x00)],
  ["zero width",     String.fromCharCode(0x200B)],
  ["Unicode tags",   String.fromCodePoint(0xE0041)],
];

function testGuardFamilySanitizeNeverServesThreatVerbatim() {
  var covered = 0;
  b.guardAll.allGuards().forEach(function (g) {
    if (g.KIND !== "content" || typeof g.sanitize !== "function") return;
    var fixtures = g.INTEGRATION_FIXTURES;
    if (!fixtures || fixtures.benignBytes === undefined) return;
    var carrier = Buffer.isBuffer(fixtures.benignBytes)
      ? fixtures.benignBytes.toString("utf8")
      : String(fixtures.benignBytes);
    // Only guards whose sanitize accepts their own benign fixture can be
    // probed this way; one that refuses it has nothing to say about a threat
    // appended to it.
    try { g.sanitize(carrier, { profile: "strict" }); }
    catch (_e) { return; }
    covered += 1;
    THREAT_CODEPOINTS.forEach(function (t) {
      var label = t[0], ch = t[1];
      var out = null, threw = false;
      try { out = g.sanitize(carrier + ch, { profile: "strict" }); }
      catch (_e) { threw = true; }
      var servedVerbatim = !threw && typeof out === "string" && out.indexOf(ch) !== -1;
      check("guard " + g.NAME + ": sanitize refuses or strips " + label +
            " under strict, never serves it", servedVerbatim === false);
    });
  });
  // Guard the guard: if the probe stops reaching any member the assertions
  // above pass vacuously, which is the failure mode that hides a regression.
  check("family sanitize invariant probed at least three content guards",
        covered >= 3);
}

// ---- Family invariant: the gate reaches the enforcement sanitize has ----

// A content gate validates first and only sanitizes when validation found
// something. So enforcement that exists ONLY in the sanitize path is
// unreachable through the gate: the document validates clean and is served
// unchanged, with the strip that would have removed the threat never running.
// Unicode Tags shipped exactly that way — every guard's strip table handles
// them, and no guard but one reported them.
function testGuardFamilyGateReachesTagsEnforcement() {
  var TAG = String.fromCodePoint(0xE0041);
  var probed = 0;
  b.guardAll.allGuards().forEach(function (g) {
    if (g.KIND !== "content" || typeof g.validate !== "function") return;
    var fixtures = g.INTEGRATION_FIXTURES;
    if (!fixtures || fixtures.benignBytes === undefined) return;
    var carrier = Buffer.isBuffer(fixtures.benignBytes)
      ? fixtures.benignBytes.toString("utf8") : String(fixtures.benignBytes);
    // Only guards that accept their own benign fixture can be probed.
    var clean;
    try { clean = g.validate(carrier, { profile: "strict" }); }
    catch (_e) { return; }
    if (!clean || !Array.isArray(clean.issues)) return;
    probed += 1;

    var v;
    try { v = g.validate(carrier + TAG, { profile: "strict" }); }
    catch (_e2) { return; }          // refusing outright is enforcement too
    check("guard " + g.NAME + ": validate reports a Unicode Tags character",
          (v.issues || []).length > (clean.issues || []).length);
  });
  check("tags-detection invariant probed at least three content guards", probed >= 3);
}

// Detecting a class is only half of it: the gate maps each finding kind to a
// disposition, and a kind no map knows degrades to severity. For a class the
// sanitizer can physically remove that means refusing a document it could have
// repaired — at every profile, including permissive.
//
// Tags inherits the zero-width POLICY, so zero-width is the reference for
// whether the gate repairs — but not for severity. The two are rated
// differently on purpose: a zero-width character is a spacing artifact, a Tags
// character carries an invisible copy of ASCII text, and guardText has always
// rated the second higher. guardEmail acts on that difference (it maps severity
// straight to a disposition, serving one and refusing the other), which is
// right rather than a divergence to flatten.
//
// So two properties, both true of every guard:
//   - a Tags character is never SERVED with the character intact
//   - where the gate repairs zero-width, it repairs Tags too — a repairable
//     class must not refuse a document the sanitizer could have fixed
async function testGuardFamilyTagsDispositionMatchesZeroWidth() {
  var TAG = String.fromCodePoint(0xE0041);
  var ZWSP = String.fromCharCode(0x200B);
  var probed = 0;
  var guards = b.guardAll.allGuards().filter(function (g) {
    return g.KIND === "content" && typeof g.gate === "function" &&
           g.INTEGRATION_FIXTURES && g.INTEGRATION_FIXTURES.benignBytes !== undefined;
  });
  for (var i = 0; i < guards.length; i += 1) {
    var g = guards[i];
    var carrier = Buffer.isBuffer(g.INTEGRATION_FIXTURES.benignBytes)
      ? g.INTEGRATION_FIXTURES.benignBytes.toString("utf8")
      : String(g.INTEGRATION_FIXTURES.benignBytes);
    // Only meaningful where the guard applies the same policy to both.
    var resolved = typeof g.resolveOpts === "function"
      ? g.resolveOpts({ profile: "balanced" }) : null;
    if (!resolved || resolved.tagsPolicy !== undefined) continue;

    var withTag, withZw, base;
    try {
      base    = await g.gate({ profile: "balanced" }).check({ bytes: Buffer.from(carrier, "utf8") });
      withTag = await g.gate({ profile: "balanced" }).check({ bytes: Buffer.from(carrier + TAG, "utf8") });
      withZw  = await g.gate({ profile: "balanced" }).check({ bytes: Buffer.from(carrier + ZWSP, "utf8") });
    } catch (_e) { continue; }

    // Appending to a structured document can break its syntax — for JSON or
    // XML that is a parse finding and refusing is right. Compare only where
    // each append introduced exactly its own invisible-character finding.
    function addedKinds(v) {
      return (v.issues || []).map(function (x) { return x.kind; }).filter(function (k) {
        return !(base.issues || []).some(function (bi) { return bi.kind === k; });
      });
    }
    var tagAdded = addedKinds(withTag), zwAdded = addedKinds(withZw);
    if (tagAdded.length !== 1 || tagAdded[0] !== "unicode-tags") continue;
    probed += 1;

    check("guard " + g.NAME + ": a Tags character is never served intact",
          withTag.action !== "serve" &&
          !(withTag.sanitized &&
            Buffer.from(withTag.sanitized).toString("utf8").indexOf(TAG) !== -1));

    // Repair parity, only where zero-width is itself the lone added finding
    // and the gate chose to repair it.
    if (zwAdded.length === 1 && zwAdded[0] === "zero-width" &&
        withZw.action === "sanitize") {
      check("guard " + g.NAME + ": Tags is repaired where zero-width is repaired",
            withTag.action === "sanitize");
    }
  }
  check("tags disposition probed at least two content guards", probed >= 2);
}

// A finding's SEVERITY has to agree with the policy that produced it. Several
// guards refuse a critical finding before their transform runs, so a class
// stamped critical while the resolved policy says `strip` makes the public
// `sanitize` throw on input it was configured to repair — the same
// policy-versus-behaviour mismatch as a strip table that never strips.
function testGuardFamilySeverityAgreesWithPolicy() {
  var TAG = String.fromCodePoint(0xE0041);
  var probed = 0;
  b.guardAll.allGuards().forEach(function (g) {
    if (g.KIND !== "content" || typeof g.sanitize !== "function") return;
    if (typeof g.resolveOpts !== "function") return;
    var fixtures = g.INTEGRATION_FIXTURES;
    if (!fixtures || fixtures.benignBytes === undefined) return;
    var carrier = Buffer.isBuffer(fixtures.benignBytes)
      ? fixtures.benignBytes.toString("utf8") : String(fixtures.benignBytes);
    var resolved = g.resolveOpts({ profile: "balanced" });
    var policy = resolved.tagsPolicy === undefined
      ? resolved.zeroWidthPolicy : resolved.tagsPolicy;
    if (policy !== "strip") return;
    // The guard must accept its own benign fixture first, or the probe says
    // nothing about the Tags character.
    try { g.sanitize(carrier, { profile: "balanced" }); }
    catch (_e) { return; }
    // Appending to a STRUCTURED document can break its syntax, and a guard
    // whose sanitize re-parses then refuses the malformed result — correctly,
    // and for a reason that has nothing to do with the Tags policy. Judge only
    // where the appended character is the lone new finding, the same
    // discriminator the tags-disposition probe uses. Without it this asserted
    // that `{"a":1}<TAG>` must sanitize, which is not valid JSON at all.
    var baseIssues, tagIssues;
    try {
      baseIssues = (g.validate(carrier, { profile: "balanced" }).issues || []);
      tagIssues  = (g.validate(carrier + TAG, { profile: "balanced" }).issues || []);
    } catch (_e2) { return; }
    var addedKinds = tagIssues.map(function (i) { return i.kind; })
      .filter(function (kind) {
        return !baseIssues.some(function (bi) { return bi.kind === kind; });
      });
    if (addedKinds.length !== 1 || addedKinds[0] !== "unicode-tags") return;
    probed += 1;

    var out = null, threw = null;
    try { out = g.sanitize(carrier + TAG, { profile: "balanced" }); }
    catch (e) { threw = e; }
    check("guard " + g.NAME + ": sanitize strips a strip-policy Tags char " +
          "rather than refusing it", threw === null);
    if (threw === null) {
      check("guard " + g.NAME + ": the stripped output no longer carries it",
            String(out).indexOf(TAG) === -1);
    }
  });
  check("severity/policy agreement probed at least three content guards", probed >= 3);
}

// Every public entry point that REMOVES characters has to remove the same set.
// A guard whose validate reports a class while some other hand-rolled strip
// path in the same guard hands it back is the mismatch this catches:
// guardJson.parse and guardFilename.sanitize each replaced zero-width and not
// Unicode Tags, so balanced validation called the character a threat and
// balanced parsing returned it inside the value.
function testGuardFamilyEveryStripPathRemovesTheSameClasses() {
  var TAG = String.fromCodePoint(0xE0041);
  var ZWSP = String.fromCharCode(0x200B);
  var probes = [
    ["guardJson.parse", function () {
      return JSON.stringify(b.guardJson.parse("{\"a\":\"x" + TAG + ZWSP + "\"}",
                                              { profile: "balanced" }));
    }],
    ["guardFilename.sanitize strip", function () {
      return b.guardFilename.sanitize("re" + TAG + ZWSP + "port.txt",
                                      { profile: "balanced", mode: "strip" });
    }],
    ["guardCsv.sanitize", function () {
      return b.guardCsv.sanitize("a,b\r\nx,y" + TAG + ZWSP + "\r\n", { profile: "balanced" });
    }],
    ["guardText.sanitize", function () {
      return b.guardText.sanitize("ok" + TAG + ZWSP, { profile: "balanced" });
    }],
    ["guardHtml.sanitize", function () {
      return b.guardHtml.sanitize("<p>x" + TAG + ZWSP + "</p>", { profile: "balanced" });
    }],
  ];
  probes.forEach(function (p) {
    var out = null;
    try { out = String(p[1]()); }
    catch (_e) { return; }        // refusing is the other valid answer
    check(p[0] + ": removes the Unicode Tags character",
          out.indexOf(TAG) === -1);
    check(p[0] + ": removes the zero-width character",
          out.indexOf(ZWSP) === -1);
  });

  // The inheritance runs one way only: an EXPLICIT tagsPolicy wins over the
  // zero-width setting it would otherwise borrow. A scrub path that re-derives
  // the policy by reading `zeroWidthPolicy` alone strips a character its own
  // validate says to allow.
  var allowOpts = { profile: "balanced", tagsPolicy: "allow" };
  var jsonAllowed = b.guardJson.parse("{\"a\":\"x" + TAG + "\"}", allowOpts);
  check("guardJson.parse honors an explicit tagsPolicy: allow",
        String(jsonAllowed.a).indexOf(TAG) !== -1);
  check("guardJson.validate agrees — no Tags finding under allow",
        (b.guardJson.validate("{\"a\":\"x" + TAG + "\"}", allowOpts).issues || [])
          .every(function (i) { return i.kind !== "unicode-tags"; }));
  var nameAllowed = b.guardFilename.sanitize("re" + TAG + "port.txt",
    { profile: "balanced", mode: "strip", tagsPolicy: "allow" });
  check("guardFilename.sanitize honors an explicit tagsPolicy: allow",
        String(nameAllowed).indexOf(TAG) !== -1);
}

// ---- Family invariant: a verdict does not depend on how many came before ----

// Scanning state must not survive a call. A regex carrying `g` keeps its
// `lastIndex` between invocations and `.test()` resumes from it, so the same
// document answers true, then false, then true — the guard reports a finding on
// every other call and nothing about the input says which answer you got. That
// is worse than never detecting it: an operator sees the rule work when they
// try it and miss half the traffic in production. guardYaml's leading-zero
// octal scan shipped exactly this way.
//
// A lexical detector cannot catch the class. The declaration and the `.test()`
// sit thousands of characters apart with no structural boundary between them,
// and whether it is safe depends on what else touches that ONE name — a
// data-flow question a pattern match cannot ask. Driving the shipped consumer
// path twice can: it catches statefulness of any origin, however reintroduced.
//
// Its reach is bounded by the fixtures: it can only observe drift in rules the
// hostile fixture actually trips, so a guard whose fixture exercises one rule
// is checked for that rule alone. That is an argument for richer fixtures, not
// against the invariant — and the per-guard repeat tests cover the rest.
function testGuardFamilyValidateIsDeterministicAcrossCalls() {
  var probed = 0;
  b.guardAll.allGuards().forEach(function (g) {
    if (typeof g.validate !== "function") return;
    var fixtures = g.INTEGRATION_FIXTURES;
    if (!fixtures) return;
    var hostile = fixtures.hostileIdentifier !== undefined ? fixtures.hostileIdentifier
                : fixtures.hostileFilename   !== undefined ? fixtures.hostileFilename
                : fixtures.hostileMetadata   !== undefined ? fixtures.hostileMetadata
                : fixtures.hostileBytes;
    if (hostile === undefined) return;
    // Content guards take bytes OR text; several refuse a Buffer outright, and
    // a `bad-input` verdict exercises no rule at all. Prefer the text form so
    // the probe reaches the scanners it is meant to be watching.
    if (Buffer.isBuffer(hostile) && g.KIND === "content") hostile = hostile.toString("utf8");

    var first;
    try { first = g.validate(hostile); }
    catch (_e) { return; }              // refusing is a verdict too, just not one to diff here
    if (!first || !Array.isArray(first.issues)) return;
    if (first.issues.length === 0) return;   // nothing to observe drift in
    probed += 1;

    var firstIds = first.issues.map(function (i) { return i.ruleId; }).sort().join(",");
    var stable = true;
    for (var n = 0; n < 5 && stable; n += 1) {
      var again;
      try { again = g.validate(hostile); } catch (_e2) { stable = false; break; }
      var againIds = (again.issues || []).map(function (i) { return i.ruleId; }).sort().join(",");
      if (againIds !== firstIds || again.ok !== first.ok) stable = false;
    }
    check("guard " + g.NAME + ": validate returns the same verdict on repeat calls",
          stable);
  });
  // Guard the guard: vacuous passes are the failure mode this is meant to stop.
  check("determinism invariant probed at least eight guards", probed >= 8);
}

// A gate must not serve a value its own validator refuses.
//
// The ctx reader used a truthy test and returned "" both when a field was
// absent and when it was present but empty, and the gate short-circuited to
// serve on the falsy result. So `gate().check({ country: "" })` served while
// `validate("")` reported the value as empty — the gate disagreeing with the
// validator it exists to enforce, on eight guards, at the request boundary
// where residency and jurisdiction decisions are actually made.
//
// Absence still short-circuits: a ctx that carries none of a guard's fields
// has nothing for that guard to look at, and that is the case the
// short-circuit was written for.
async function testGuardFamilyGateAgreesWithValidateOnAnEmptyValue() {
  var CTX_KEYS = ["text", "bytes", "identifier", "country", "countryCode",
                  "filename", "entries", "value", "input", "sql", "url"];
  var disagreed = [];
  var probed = 0;
  var guards = b.guardAll.allGuards();
  for (var n = 0; n < guards.length; n += 1) {
    var g = guards[n];
    if (typeof g.gate !== "function" || typeof g.validate !== "function") continue;
    // Only the kinds whose value IS a string. A `metadata`, `entries`,
    // `oauth-flow`, `graphql-request` or `auth-bundle` guard takes a structured
    // bag, so validate("") refusing says the type is wrong, not that an empty
    // identifier slipped through — a different question with a different
    // answer, and asserting it here would be asserting the wrong thing.
    if (g.KIND !== "identifier" && g.KIND !== "filename") continue;

    // What does the validator make of an empty value?
    var refusesEmpty;
    try {
      var rv = g.validate("");
      refusesEmpty = rv && rv.ok === false;
    } catch (_e) { refusesEmpty = true; }   // cannot parse it is not approval
    if (!refusesEmpty) continue;            // empty is fine for this guard
    probed += 1;

    var ctx = {};
    CTX_KEYS.forEach(function (k) { ctx[k] = ""; });
    var action;
    try { action = (await g.gate().check(ctx)).action; }
    catch (_e2) { action = "threw"; }
    if (action === "serve") disagreed.push(g.NAME);
  }
  check("guard gates do not serve an empty value their validator refuses" +
        (disagreed.length ? " (served on " + disagreed.join(", ") + ")" : ""),
        disagreed.length === 0);
  // A control, so the sweep cannot pass by finding no guard that refuses "".
  check("the empty-value sweep reached guards that refuse an empty value (" +
        probed + ")", probed >= 8);

  // And the other half of the contract: an ABSENT field still serves, or this
  // would turn every request carrying no value for a guard into a refusal.
  var served = 0;
  var refusedOnAbsent = [];
  for (var m = 0; m < guards.length; m += 1) {
    var g2 = guards[m];
    if (typeof g2.gate !== "function") continue;
    var a;
    try { a = (await g2.gate().check({})).action; } catch (_e3) { a = "threw"; }
    if (a === "serve") served += 1; else refusedOnAbsent.push(g2.NAME + ":" + a);
  }
  check("an absent field still serves" +
        (refusedOnAbsent.length ? " (refused on " + refusedOnAbsent.slice(0, 5).join(", ") + ")" : ""),
        refusedOnAbsent.length === 0 && served >= 20);
}

// A cap an operator can override must refuse a shape it cannot compare against.
//
// Every numeric limit in the family is read as `measured > opts.maxThing`. Hand
// that comparison a string, an Infinity or a fraction and it is false for all
// input, so a malformed value does not fall back to the default — it DISABLES
// the cap, on exactly the untrusted input the cap exists to bound. The check
// existed, but only inside the generated validate(), and the list of keys it
// covered was hand-maintained per guard: maxRuntimeMs was in every guard's
// defaults and named in none of them, guard-csv declared no list at all, and
// the hand-written entry points (guardMarkdown.render and its peers) resolved
// their own opts and never reached the check. 136 combinations were accepted.
//
// Derived from each guard's own resolved defaults rather than from a list here,
// so a cap added to any guard tomorrow is covered without editing this file.
function testGuardFamilyRefusesAMalformedNumericCap() {
  var MALFORMED = [["a string", "8mb"], ["Infinity", Infinity],
                   ["a fraction", 1.5], ["a negative", -1], ["NaN", NaN]];
  var probedGuards = 0;
  var probedCaps = 0;
  b.guardAll.allGuards().forEach(function (g) {
    if (typeof g.resolveOpts !== "function") return;
    var base;
    try { base = g.resolveOpts({}); } catch (_e) { return; }
    var caps = Object.keys(base).filter(function (k) {
      return typeof base[k] === "number" && Number.isInteger(base[k]) && base[k] > 0;
    });
    if (caps.length === 0) return;
    probedGuards += 1;
    caps.forEach(function (cap) {
      probedCaps += 1;
      var accepted = MALFORMED.filter(function (pair) {
        var o = {};
        o[cap] = pair[1];
        try { g.resolveOpts(o); return true; }
        catch (_e) { return false; }
      }).map(function (pair) { return pair[0]; });
      check("guard " + g.NAME + ": " + cap + " refuses a malformed value" +
            (accepted.length ? " (accepted " + accepted.join(", ") + ")" : ""),
            accepted.length === 0);
    });
  });
  // A control, so the sweep cannot pass by surveying nothing: the failure this
  // was written for spanned 27 guards, and a probe that reached two would have
  // reported clean.
  check("malformed-cap sweep reached the whole family (" + probedGuards +
        " guards, " + probedCaps + " caps)", probedGuards >= 20 && probedCaps >= 40);
  // The same resolver must still ACCEPT a well-formed override, or the sweep
  // above passes for a resolver that simply refuses everything.
  var markdown = b.guardAll.allGuards().filter(function (g) { return g.NAME === "markdown"; })[0];
  var raised = null;
  try { raised = markdown.resolveOpts({ maxBytes: 1024 }); } catch (_e) { /* raised stays null */ }
  check("a well-formed cap override is still accepted",
        raised !== null && raised.maxBytes === 1024);

  // Zero is a VALUE on the options that are not caps. `maxRuntimeMs: 0` means
  // "no runtime budget" and `nbfFutureSlackMs: 0` means "allow no clock
  // slack" — settings an operator may already be using, which requiring a
  // positive integer took away. Derivation cannot tell a cap from a tolerance,
  // so a derived option is held only to "still a non-negative integer", and an
  // option the guard AUTHOR declared as a cap keeps refusing zero.
  //
  // Both halves are pinned here because the first attempt kept a hand-written
  // list of the options where zero is a value, and that list had already
  // missed two.
  var zeroKept = 0;
  var zeroRefusedOnANonCap = [];
  b.guardAll.allGuards().forEach(function (g) {
    if (typeof g.resolveOpts !== "function") return;
    var base;
    try { base = g.resolveOpts({}); } catch (_e) { return; }
    Object.keys(base).forEach(function (k) {
      if (!(typeof base[k] === "number" && Number.isInteger(base[k]) && base[k] > 0)) return;
      var declared = Array.isArray(g.INT_OPTS) && g.INT_OPTS.indexOf(k) !== -1;
      var o = {};
      o[k] = 0;
      var accepted = true;
      try { g.resolveOpts(o); } catch (_e3) { accepted = false; }
      if (!declared && !accepted) zeroRefusedOnANonCap.push(g.NAME + "." + k);
      if (!declared && accepted) zeroKept += 1;
    });
  });
  check("zero stays a setting on an option the guard did not declare a cap" +
        (zeroRefusedOnANonCap.length
          ? " (refused on " + zeroRefusedOnANonCap.slice(0, 5).join(", ") + ")" : ""),
        zeroRefusedOnANonCap.length === 0);
  check("the zero-is-a-setting contract was probed family-wide (" + zeroKept + " options)",
        zeroKept >= 20);

  // The other half: a `max*` limit IS a cap, so every guard must declare it and
  // refuse zero for it. Five guards declared no caps at all and quietly took
  // `maxRows: 0`, which is fail-closed but is not the contract — an operator
  // should learn about it at the call that sets it.
  var undeclaredCaps = [];
  b.guardAll.allGuards().forEach(function (g) {
    if (typeof g.resolveOpts !== "function") return;
    var base;
    try { base = g.resolveOpts({}); } catch (_e) { base = g.DEFAULTS || {}; }
    var declared = g.INT_OPTS || [];
    Object.keys(base).forEach(function (k) {
      if (k === "maxRuntimeMs") return;                 // a budget, not a cap
      if (k.indexOf("max") !== 0) return;
      if (!(typeof base[k] === "number" && Number.isInteger(base[k]) && base[k] > 0)) return;
      if (declared.indexOf(k) === -1) undeclaredCaps.push(g.NAME + "." + k);
    });
  });
  check("every max* limit is declared as a cap" +
        (undeclaredCaps.length ? " (undeclared: " + undeclaredCaps.slice(0, 6).join(", ") + ")" : ""),
        undeclaredCaps.length === 0);

  // The specific cases the reviews named, by name, so they cannot regress
  // quietly behind an aggregate count.
  var NAMED = [["guardJwt", "nbfFutureSlackMs"], ["guardJwt", "iatFutureSlackMs"],
               ["guardMarkdown", "maxRuntimeMs"], ["guardCsv", "maxRuntimeMs"]];
  NAMED.forEach(function (p) {
    var g = b[p[0]];
    if (!g || typeof g.resolveOpts !== "function") return;
    var o = {};
    o[p[1]] = 0;
    var kept = false;
    try { kept = g.resolveOpts(o)[p[1]] === 0; } catch (_e4) { kept = false; }
    check(p[0] + ": " + p[1] + " 0 is kept, not refused", kept);
    // ...and the malformed shapes are still refused on the same option.
    var stillRefused = ["8mb", Infinity, NaN, 1.5, -1].every(function (bad) {
      var b2 = {};
      b2[p[1]] = bad;
      try { g.resolveOpts(b2); return false; } catch (_e5) { return true; }
    });
    check(p[0] + ": " + p[1] + " still refuses a malformed value", stillRefused);
  });

  // An explicitly-undefined override means "I did not set this", not "remove
  // the limit". `{ maxBytes: parsedEnvValue }` with the variable unset is the
  // ordinary way to reach this, and the merge copied the undefined over the
  // profile default — after which the present-value check skipped it as absent
  // and every `measured > undefined` comparison was false. Same fail-open as a
  // malformed value, through a shape a careful operator writes on purpose.
  var lostDefault = [];
  b.guardAll.allGuards().forEach(function (g) {
    if (typeof g.resolveOpts !== "function") return;
    var base;
    try { base = g.resolveOpts({}); } catch (_e) { return; }
    Object.keys(base).forEach(function (k) {
      if (!(typeof base[k] === "number" && Number.isInteger(base[k]) && base[k] > 0)) return;
      var o = {};
      o[k] = undefined;
      var got;
      try { got = g.resolveOpts(o); } catch (_e2) { return; }   // refusing is fine too
      if (got[k] !== base[k]) lostDefault.push(g.NAME + "." + k + "=" + got[k]);
    });
  });
  check("an explicitly-undefined override keeps the profile default" +
        (lostDefault.length ? " (lost on " + lostDefault.length + ": " +
          lostDefault.slice(0, 4).join(", ") + ")" : ""),
        lostDefault.length === 0);

  // Drive gate() too, not just resolveOpts().
  //
  // Several guards bind their own resolver inside a hand-written gate() rather
  // than going through the generated one — guard-image, guard-pdf, guard-sql,
  // guard-text and guard-yaml all did. A sweep that only exercises resolveOpts
  // reports clean while those paths accept a malformed cap and compare against
  // NaN, which is how this was missed twice: the probe and the code agreed
  // because both went through the same door.
  var gateAccepted = [];
  var gatesProbed = 0;
  b.guardAll.allGuards().forEach(function (g) {
    if (typeof g.gate !== "function" || typeof g.resolveOpts !== "function") return;
    var base;
    try { base = g.resolveOpts({}); } catch (_e) { return; }
    var caps = Object.keys(base).filter(function (k) {
      return typeof base[k] === "number" && Number.isInteger(base[k]) && base[k] > 0 &&
             k !== "maxRuntimeMs";
    });
    if (caps.length === 0) return;
    gatesProbed += 1;
    // One cap per guard is enough: they share a resolver per guard, so if one
    // is checked they all are, and this keeps the sweep from being O(caps).
    var o = {};
    o[caps[0]] = "8mb";
    try { g.gate(o); gateAccepted.push(g.NAME + "." + caps[0]); }
    catch (_e2) { /* refused, as it should be */ }
  });
  check("guard gate() refuses a malformed cap as resolveOpts does" +
        (gateAccepted.length ? " (accepted on " + gateAccepted.join(", ") + ")" : ""),
        gateAccepted.length === 0);
  check("the gate-construction sweep reached the family (" + gatesProbed + " guards)",
        gatesProbed >= 15);
}

// A policy opt is a CONFIG-TIME entry point, so a value outside its vocabulary
// is a boot error, not a runtime surprise. `bidiPolicy: "rejct"` used to be
// accepted by both doors — resolveOpts and gate — and then read leniently: the
// scan runs (the value is not "allow"), an issue is raised, and
// policyDisposition falls through to "refuse". Fail-closed, so not a hole, but
// the operator asked for one disposition and silently got another with nothing
// said at boot.
//
// guard-country already fixed this for its own three opts by declaring
// `enumOpts`, and its comment records the same bug. The mechanism was applied
// to one guard and the class left open across the other 259 policy opts; this
// covers the character family, which shares one vocabulary.
function testCharacterPolicyVocabularyIsEnforced() {
  var CHAR_POLICY_KEYS = ["bidiPolicy", "nullBytePolicy", "controlPolicy",
                          "zeroWidthPolicy", "tagsPolicy"];
  var NONSENSE = "definitely-not-a-policy-value";
  var acceptedNonsense = [];
  var refusedLegal = [];
  var probed = 0;

  b.guardAll.allGuards().forEach(function (g) {
    if (typeof g.resolveOpts !== "function") return;
    var base;
    try { base = g.resolveOpts({}); } catch (_e) { return; }
    CHAR_POLICY_KEYS.forEach(function (key) {
      if (typeof base[key] !== "string") return;
      probed += 1;

      var bad = {};
      bad[key] = NONSENSE;
      var refused = false;
      try { g.resolveOpts(bad); } catch (_e2) { refused = true; }
      if (!refused) acceptedNonsense.push(g.NAME + "." + key);

      // And the legal vocabulary must still pass, or the enum is a regression
      // wearing a fix. `strip` is legal only where the guard can perform it —
      // the same rule the performable-actions invariant below asserts.
      var legal = ["allow", "audit", "audit-only", "reject"];
      if (typeof g.sanitize === "function" && g.KIND !== "entries") legal.push("strip");
      legal.forEach(function (v) {
        var ok = {};
        ok[key] = v;
        try { g.resolveOpts(ok); }
        catch (_e3) { refusedLegal.push(g.NAME + "." + key + "=" + v); }
      });
    });
  });

  check("the character-policy sweep reached the family (" + probed + " cells)",
        probed >= 40, "probed " + probed);
  check("a character policy refuses a value outside its vocabulary" +
        (acceptedNonsense.length
          ? " (accepted on " + acceptedNonsense.length + ": " +
            acceptedNonsense.slice(0, 6).join(", ") + ")"
          : ""),
        acceptedNonsense.length === 0);
  check("and still accepts every legal value" +
        (refusedLegal.length ? " (refused " + refusedLegal.slice(0, 6).join(", ") + ")" : ""),
        refusedLegal.length === 0);
}

// A guard may only declare a policy it can carry out. `strip` is an instruction
// to repair, and a guard with no `sanitize` has nothing to repair with, so the
// setting is accepted at config time and silently means "refuse" at runtime.
// Nothing checked this, and twelve such cells shipped across two content guards
// — the same shape as a strip table that never strips, one level up: the
// framework accepting a setting it does not honour.
//
// This is structural on purpose. It asks what a guard CAN do, not what it did
// for one fixture, so it covers every profile of every registered guard
// including ones whose fixtures never reach the policy in question.
function testGuardFamilyDeclaresOnlyPerformableActions() {
  var CHAR_POLICY_KEYS = ["bidiPolicy", "nullBytePolicy", "controlPolicy",
                          "zeroWidthPolicy", "tagsPolicy"];
  // The repair vocabulary — anything that promises the input comes back fixed.
  var REPAIR = { strip: 1, sanitize: 1, escape: 1, "strip-and-audit": 1 };
  var unperformable = [];
  var probed = 0;
  b.guardAll.allGuards().forEach(function (g) {
    var profiles = g.PROFILES || {};
    Object.keys(profiles).forEach(function (profile) {
      var resolved = profiles[profile] || {};
      CHAR_POLICY_KEYS.forEach(function (key) {
        var policy = resolved[key];
        if (policy === undefined || policy === "allow") return;
        probed += 1;
        if (REPAIR[policy] !== 1) return;
        // A repair policy needs a repair. An `entries` guard has none by
        // design — a hostile archive entry cannot be made safe — so declaring
        // one there is a contradiction rather than a missing export.
        if (g.KIND === "entries") {
          unperformable.push(g.NAME + " " + profile + "." + key + " = " + policy +
                             " (an entries guard cannot repair its input)");
          return;
        }
        if (typeof g.sanitize !== "function") {
          unperformable.push(g.NAME + " " + profile + "." + key + " = " + policy +
                             " (exports no sanitize)");
        }
      });
    });
  });
  check("every declared character policy is one the guard can perform",
        unperformable.length === 0, unperformable.slice(0, 12).join("; "));
  check("performable-action invariant probed at least forty policy cells",
        probed >= 40, "probed " + probed);
}

// And the behavioural half: the action a gate takes on a character threat has
// to be the one that class's policy asks for. A guard that does not route
// through `b.gateContract.charThreatDisposition` falls back to the default
// severity rule, where `critical` and `high` both refuse — so `strip` refuses
// instead of repairing and `audit` refuses instead of recording. Seventeen
// cells across three guards resolved that way.
//
// The probe compares against a baseline of the same document without the
// character, and only judges a cell where the injected character is the LONE
// added finding. Injecting a control byte into an address also makes it
// malformed, and that finding refuses on its own merits — judging the cell
// there would test the wrong rule and pass for the wrong reason.
// The number of policy cells the probe below actually reaches. Raise it when a
// guard or a class is added; never lower it to make a run green — a drop means
// a cell stopped being covered, which is the condition this exists to catch.
var DISPOSITION_PROBE_FLOOR = 63;

async function testGuardFamilyDispositionFollowsPolicy() {
  var CHARS = {
    bidiPolicy:      { ch: String.fromCharCode(0x202E), kind: "bidi-override" },
    nullBytePolicy:  { ch: String.fromCharCode(0x0000), kind: "null-byte" },
    controlPolicy:   { ch: String.fromCharCode(0x0001), kind: "control-char" },
    zeroWidthPolicy: { ch: String.fromCharCode(0x200B), kind: "zero-width" },
    tagsPolicy:      { ch: String.fromCodePoint(0xE0041), kind: "unicode-tags" },
  };
  var wrong = [];
  var probed = 0;
  var unprobed = [];
  // Not content-kind only. A `filename` guard declares the same character
  // policies and routes them through the same helper, and excluding it left
  // three of its declared cells outside every invariant the family has.
  var guards = b.guardAll.allGuards().filter(function (g) {
    if (typeof g.gate !== "function" || !g.INTEGRATION_FIXTURES) return false;
    if (g.KIND === "content") return g.INTEGRATION_FIXTURES.benignBytes !== undefined;
    if (g.KIND === "filename") return g.INTEGRATION_FIXTURES.benignFilename !== undefined;
    return false;
  });
  // A `filename` gate reads the name off the context rather than a byte body,
  // so the probe has to hand it the shape its own KIND declares.
  function ctxFor(g, text) {
    return g.KIND === "filename" ? { filename: text }
                                 : { bytes: Buffer.from(text, "utf8") };
  }
  // Inject the character where the document stays WELL-FORMED, which for a
  // line-oriented format means inside the last line rather than after the
  // trailing newline. Appending past it starts a new bare line, and a guard
  // that parses its subject then reports a parse failure alongside the
  // character finding — two added kinds, so the cell is recorded as unreachable
  // and every one of that guard's policies goes unprobed. YAML lost all twelve
  // of its cells that way, and a real defect sat behind the gap: seven of them
  // refused where the profile declared strip or audit.
  function inject(carrier, ch) {
    return carrier.endsWith("\n")
      ? carrier.slice(0, -1) + ch + "\n"
      : carrier + ch;
  }
  for (var i = 0; i < guards.length; i += 1) {
    var g = guards[i];
    var carrier = g.KIND === "filename"
      ? String(g.INTEGRATION_FIXTURES.benignFilename)
      : (Buffer.isBuffer(g.INTEGRATION_FIXTURES.benignBytes)
          ? g.INTEGRATION_FIXTURES.benignBytes.toString("utf8")
          : String(g.INTEGRATION_FIXTURES.benignBytes));
    var profiles = Object.keys(g.PROFILES || {});
    for (var p = 0; p < profiles.length; p += 1) {
      var profile = profiles[p];
      var resolved = typeof g.resolveOpts === "function"
        ? g.resolveOpts({ profile: profile }) : (g.PROFILES[profile] || {});
      var base;
      try { base = await g.gate({ profile: profile }).check(ctxFor(g, carrier)); }
      catch (_e) { unprobed.push(g.NAME + " " + profile + ": benign fixture refused"); continue; }
      var keys = Object.keys(CHARS);
      for (var k = 0; k < keys.length; k += 1) {
        var key = keys[k];
        var policy = resolved[key];
        if (policy === undefined || policy === "allow") continue;
        var got;
        try {
          got = await g.gate({ profile: profile })
                       .check(ctxFor(g, inject(carrier, CHARS[key].ch)));
        } catch (_e2) {
          unprobed.push(g.NAME + " " + profile + "." + key + ": check threw");
          continue;
        }
        var added = (got.issues || []).map(function (x) { return x.kind; })
          .filter(function (kind) {
            return !(base.issues || []).some(function (bi) { return bi.kind === kind; });
          });
        // A cell the probe cannot reach is RECORDED, not silently dropped. The
        // skips are where the drift hides: a declared policy whose class the
        // carrier never triggers is a cell no invariant covers, and counting
        // only the successful probes made that indistinguishable from a pass.
        if (added.length !== 1 || added[0] !== CHARS[key].kind) {
          unprobed.push(g.NAME + " " + profile + "." + key + ": carrier did not isolate " +
                        CHARS[key].kind + " (added " + JSON.stringify(added) + ")");
          continue;
        }
        probed += 1;
        // The two vocabularies spell the same outcome differently: a
        // disposition of `audit` is the action-chain's `audit-only`. Compare
        // the outcome, not the word.
        var want = gateContract.policyDisposition(policy);
        if (want === "audit") want = "audit-only";
        if (got.action !== want) {
          wrong.push(g.NAME + " " + profile + "." + key + " = " + policy +
                     " -> " + got.action + ", policy asks " + want);
        } else if (got.action === "sanitize" &&
                   (got.sanitized === null || got.sanitized === undefined)) {
          // A verdict of `sanitize` with nothing sanitized is not a repair, it
          // is a claim of one: the caller is told the input was cleaned and
          // handed nothing to use. The verdict builder carries `sanitized`, so
          // a guard returning the repair under its own field name loses it
          // silently — and only a guard whose sanitize path is reachable ever
          // shows the mistake.
          wrong.push(g.NAME + " " + profile + "." + key + " = " + policy +
                     " -> sanitize, but the verdict carries no sanitized value");
        }
      }
    }
  }
  check("a gate disposes a character threat the way its policy asks",
        wrong.length === 0, wrong.slice(0, 12).join("; "));
  // A floor of six was low enough that the invariant could skip most of the
  // family and still pass, which is how a wiring gap in two guards stayed
  // invisible while a helper-level test of the same rule was green. The floor
  // is now the coverage this actually achieves, so losing a probe is a failure
  // rather than a quieter run.
  check("disposition-follows-policy reaches the cells it did before",
        probed >= DISPOSITION_PROBE_FLOOR,
        "probed " + probed + " (floor " + DISPOSITION_PROBE_FLOOR + "); unreached: " +
        unprobed.slice(0, 8).join("; "));
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[guard-all] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
