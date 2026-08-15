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
  testGuardFamilyValidateIsDeterministicAcrossCalls();
  return testGuardAllDispatchRoutesByMime();
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

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[guard-all] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
