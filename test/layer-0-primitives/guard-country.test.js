// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.guardCountry - ISO 3166-1 alpha-2 identifier guard.
 *
 * The hand-rolled version this replaces accepts any two uppercase letters and
 * then asks `Intl.DisplayNames` whether it names a region. That has two
 * failure modes, and both are tested here:
 *
 *   - it accepts codes that are NOT countries. `ZZ` is the CLDR unknown
 *     region, `UK` is not a code at all (`GB` is), `EU` / `EZ` / `UN` are
 *     exceptionally reserved, `AA` / `XA` / `XB` / `QO` are user-assigned.
 *     Each reaching a tax-nexus lookup or a data-residency decision is a wrong
 *     answer wearing the shape of a right one.
 *   - it fails OPEN on a stripped-ICU runtime. `small-icu` and `no-icu` Node
 *     builds have no `Intl.DisplayNames`, so the `catch` returns true and
 *     every two-letter string becomes a country. The guard therefore answers
 *     from a bundled table and never consults `Intl` at all - the assertion
 *     below removes `Intl` outright and the answers must not move.
 *
 * Every hostile fixture is BUILT from char codes rather than typed. A raw
 * zero-width space or BIDI override in a source file is invisible in a diff,
 * unmatchable by a later edit, and indistinguishable from the ASCII it hides
 * behind.
 *
 * Run standalone: `node test/layer-0-primitives/guard-country.test.js`
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

var CH = String.fromCharCode;

// Every code #574 names, plus the deprecated ones a legacy dataset carries.
var MUST_REFUSE = [
  "ZZ",  // CLDR unknown region
  "UK",  // not a code - GB is
  "EU",  // exceptionally reserved
  "EZ",  // exceptionally reserved (Eurozone)
  "UN",  // exceptionally reserved
  "AA",  // user-assigned
  "XA", "XB", "XK",  // user-assigned (XA-XZ)
  "QM", "QO",        // user-assigned (QM-QZ)
  "AC", "CP", "CQ", "DG", "EA", "IC", "TA",   // exceptionally reserved
  "AN", "BU", "CS", "DD", "FX", "NT", "SU", "TP", "YD", "YU", "ZR",  // formerly used
];

// A spread across the assigned set, including the ones that are easy to get
// wrong: GB (not UK), BQ/CW/SX (2010 Netherlands Antilles split), SS (2011),
// TL (renamed from TP), ME/RS (2006 split), MF/BL (2007).
var MUST_ACCEPT = [
  "US", "GB", "DE", "FR", "JP", "AU", "CA", "BR", "IN", "ZA", "NZ", "IE",
  "BQ", "CW", "SX", "SS", "TL", "ME", "RS", "MF", "BL", "AX", "GG", "JE", "IM",
];

function testAcceptsAssignedCodes() {
  var rejected = MUST_ACCEPT.filter(function (c) {
    return b.guardCountry.validate(c, { profile: "strict" }).ok !== true;
  });
  check("guardCountry: every officially assigned code is accepted at strict" +
    (rejected.length ? " (rejected " + rejected.join(",") + ")" : ""),
    rejected.length === 0);
}

function testRefusesEveryNonCountry() {
  var accepted = MUST_REFUSE.filter(function (c) {
    return b.guardCountry.validate(c, { profile: "strict" }).ok === true;
  });
  check("guardCountry: no reserved / user-assigned / formerly-used code is accepted at strict" +
    (accepted.length ? " (accepted " + accepted.join(",") + ")" : ""),
    accepted.length === 0);

  // UK is the one an operator is most likely to type by hand, so it earns its
  // own assertion rather than only counting in the batch above.
  check("guardCountry: UK is refused (the code for the United Kingdom is GB)",
    b.guardCountry.validate("UK", { profile: "strict" }).ok === false);
  check("guardCountry: GB is accepted",
    b.guardCountry.validate("GB", { profile: "strict" }).ok === true);
}

function testShapeRefusals() {
  var shapes = [
    "", "U", "USA", "U1", "12", "u-s", "US ", " US", "U S", "U\tS",
    "US" + CH(0x200B),              // trailing zero-width space
    CH(0xFF35) + CH(0xFF33),        // fullwidth U+FF35 U+FF33 - renders as "US"
    "US" + CH(0x0301),              // S + combining acute
    "US" + CH(0x0000),              // trailing NUL
    CH(0x0413) + CH(0x0412),        // Cyrillic homoglyphs for G and V
    CH(0x202E) + "US",              // BIDI override prefix
  ];
  var accepted = shapes.filter(function (s) {
    return b.guardCountry.validate(s, { profile: "strict" }).ok === true;
  });
  check("guardCountry: nothing but two ASCII letters is accepted" +
    (accepted.length ? " (accepted " + JSON.stringify(accepted) + ")" : ""),
    accepted.length === 0);

  // Non-string input reports rather than throwing - the family contract.
  var notAString = b.guardCountry.validate(42, { profile: "strict" });
  check("guardCountry: non-string input reports an issue instead of throwing",
    notAString.ok === false && notAString.issues.length > 0);
}

function testCaseIsNormalisedNotIgnored() {
  check("guardCountry: sanitize upper-cases a lowercase code",
    b.guardCountry.sanitize("gb", { profile: "strict" }) === "GB");
  check("guardCountry: sanitize accepts a mixed-case code",
    b.guardCountry.sanitize("gB", { profile: "strict" }) === "GB");
  var threw = null;
  try { b.guardCountry.sanitize("uk", { profile: "strict" }); } catch (e) { threw = e; }
  check("guardCountry: sanitize throws on a code that is not assigned",
    threw !== null && typeof threw.code === "string");
}

function testIsValidSugar() {
  check("guardCountry: isValid returns a boolean, not a result object",
    b.guardCountry.isValid("GB") === true && b.guardCountry.isValid("UK") === false);
  check("guardCountry: isValid accepts lower case",
    b.guardCountry.isValid("gb") === true);
  check("guardCountry: isValid on non-string is false, never a throw",
    b.guardCountry.isValid(null) === false && b.guardCountry.isValid(42) === false);

  // isValid answers ONE question — is this an officially assigned code — and
  // that answer cannot depend on a profile. The profiles differ only in how
  // they DISPOSE of a non-assigned code: strict refuses, balanced and
  // permissive downgrade some findings to `warn`, which leaves validate().ok
  // true. A predicate that forwarded its opts would therefore call `EU`, `ZZ`,
  // `SU` and `AN` valid under permissive and feed reserved and sentinel values
  // straight into residency and jurisdiction routing.
  //
  // Checking only the DEFAULT profile is what hid this: that is the one
  // configuration where the bug cannot appear.
  var leaked = [];
  ["strict", "balanced", "permissive"].forEach(function (profile) {
    MUST_REFUSE.forEach(function (code) {
      if (b.guardCountry.isValid(code, { profile: profile }) === true) {
        leaked.push(code + "@" + profile);
      }
    });
  });
  check("guardCountry: no profile can make isValid accept a non-assigned code" +
    (leaked.length ? " (accepted " + JSON.stringify(leaked.slice(0, 8)) +
      (leaked.length > 8 ? " +" + (leaked.length - 8) + " more" : "") + ")" : ""),
    leaked.length === 0);

  // CONTROL: an assigned code stays valid under every profile, so the check
  // above cannot pass for a predicate that simply answers false.
  var lost = [];
  ["strict", "balanced", "permissive"].forEach(function (profile) {
    MUST_ACCEPT.forEach(function (code) {
      if (b.guardCountry.isValid(code, { profile: profile }) !== true) {
        lost.push(code + "@" + profile);
      }
    });
  });
  check("guardCountry CONTROL: an assigned code is valid under every profile" +
    (lost.length ? " (rejected " + JSON.stringify(lost.slice(0, 8)) + ")" : ""),
    lost.length === 0);
}

// The reason this is a bundled table rather than an Intl echo test: on a
// small-icu / no-icu build Intl.DisplayNames is absent, and the hand-rolled
// version's catch turns every two-letter string into a country.
function testDoesNotConsultIntl() {
  var realIntl = global.Intl;
  var answers;
  try {
    delete global.Intl;
    answers = {
      gb: b.guardCountry.isValid("GB"),
      uk: b.guardCountry.isValid("UK"),
      zz: b.guardCountry.isValid("ZZ"),
      bq: b.guardCountry.isValid("BQ"),
    };
  } finally {
    global.Intl = realIntl;
  }
  check("guardCountry: a stripped-ICU runtime still accepts assigned codes",
    answers.gb === true && answers.bq === true);
  check("guardCountry: a stripped-ICU runtime still REFUSES non-countries " +
    "(the hand-rolled Intl version fails open here)",
    answers.uk === false && answers.zz === false);
}

// The categories the guard names must be ones it can point at a record for.
// "unassigned" is not claimed: ISO reserves codes the framework has no source
// for (the indeterminately-reserved set), so calling an unknown code
// unassigned would be an affirmative false statement.
function testIssueKindsAreSourced() {
  function kinds(code) {
    return b.guardCountry.validate(code, { profile: "strict" }).issues
      .map(function (i) { return i.kind; });
  }
  check("guardCountry: a user-assigned code is named as user-assigned",
    kinds("AA").indexOf("country-user-assigned") !== -1);
  check("guardCountry: an exceptionally reserved code is named as such",
    kinds("EU").indexOf("country-exceptionally-reserved") !== -1);
  check("guardCountry: a formerly-used code is named as such",
    kinds("SU").indexOf("country-formerly-used") !== -1);
  check("guardCountry: a code with no known assignment is not called 'unassigned'",
    kinds("OO").indexOf("country-not-assigned") !== -1 &&
    kinds("OO").indexOf("country-unassigned") === -1);

  // A formerly-used code whose registry record names a replacement says so,
  // and one whose record does not must not invent one.
  function formerly(code) {
    return b.guardCountry.validate(code, { profile: "strict" }).issues
      .filter(function (i) { return i.kind === "country-formerly-used"; })[0];
  }
  var fx = formerly("FX");
  check("guardCountry: FX reports the replacement its record carries (FR)",
    fx !== undefined && fx.snippet.indexOf("FR") !== -1);
  var nt = formerly("NT");
  check("guardCountry: NT has no recorded replacement and none is invented",
    nt !== undefined && nt.snippet.indexOf("replaced by") === -1);
}

function testProfilesDiffer() {
  // strict refuses a formerly-used code outright; permissive lets it through
  // with a signal, for an operator migrating a legacy dataset.
  check("guardCountry: strict refuses a formerly-used code",
    b.guardCountry.validate("SU", { profile: "strict" }).ok === false);
  var permissive = b.guardCountry.validate("SU", { profile: "permissive" });
  check("guardCountry: permissive accepts a formerly-used code but still reports it",
    permissive.ok === true && permissive.issues.length > 0);
  // Nothing makes a malformed code acceptable.
  check("guardCountry: permissive still refuses a malformed code",
    b.guardCountry.validate("U1", { profile: "permissive" }).ok === false);
}

function testFamilyRegistration() {
  check("guardCountry: exports the registry contract",
    b.guardCountry.NAME === "country" && b.guardCountry.KIND === "identifier");
  var names = b.guardAll.allGuards().map(function (g) { return g.NAME; });
  check("guardCountry: is registered in the guard-all aggregator",
    names.indexOf("country") !== -1);
  var shared = ["strict", "balanced", "permissive"];
  check("guardCountry: ships every shared profile",
    shared.every(function (p) { return b.guardCountry.PROFILES[p] !== undefined; }));
  var postures = ["hipaa", "pci-dss", "gdpr", "soc2"];
  check("guardCountry: ships every compliance posture",
    postures.every(function (p) { return b.guardCountry.COMPLIANCE_POSTURES[p] !== undefined; }));
  check("guardCountry: exports integration fixtures for the adaptive harness",
    b.guardCountry.INTEGRATION_FIXTURES !== undefined);
}

async function testGateRefusesThroughTheContract() {
  // check() is async - the gate contract awaits audit / observability sinks.
  var gate = b.guardCountry.gate({ profile: "strict" });
  var served = await gate.check({ identifier: "GB" });
  check("guardCountry: gate serves an assigned code", served.action === "serve");
  var refused = await gate.check({ identifier: "ZZ" });
  check("guardCountry: gate refuses a non-country", refused.action === "refuse");
  // The gate reads countryCode too, so a caller does not have to rename its
  // field to identifier just to run the check.
  var byCountryCode = await gate.check({ countryCode: "UK" });
  check("guardCountry: gate reads ctx.countryCode as well as ctx.identifier",
    byCountryCode.action === "refuse");
}

// The table is a fact set with a known size - a truncated paste would
// otherwise pass every spot check above.
function testTableIsComplete() {
  var codes = b.guardCountry.ASSIGNED_CODES;
  check("guardCountry: the table holds all 249 officially assigned alpha-2 codes " +
    "(got " + codes.length + ")", codes.length === 249);
  var sorted = codes.slice().sort();
  check("guardCountry: the table is sorted and free of duplicates",
    codes.every(function (c, i) { return c === sorted[i]; }) &&
    new Set(codes).size === codes.length);
  check("guardCountry: every table entry is two uppercase ASCII letters",
    codes.every(function (c) {
      if (typeof c !== "string" || c.length !== 2) return false;
      for (var i = 0; i < 2; i++) {
        var cc = c.charCodeAt(i);
        if (cc < 0x41 || cc > 0x5A) return false;
      }
      return true;
    }));
}

// `allow` has to differ from `audit`, or one of the two settings is a lie.
//
// The severity helper mapped every policy that was not "reject" to "warn", so
// an explicitly allowed code still produced a finding, and a finding still
// dispositions to audit-only. An operator who set `reservedPolicy: "allow"`
// because they route on `EU` deliberately got the same audit trail as one who
// asked to be told about it. The rest of the family reads the policy and skips
// emitting when it says allow.
//
// Swept across all three policies and a code from each of their sets, because
// the report named one and the helper served all three.
function testAllowSuppressesTheFindingRatherThanDowngradingIt() {
  var CASES = [
    { policy: "reservedPolicy",     code: "EU", kind: "country-exceptionally-reserved" },
    { policy: "userAssignedPolicy", code: "ZZ", kind: "country-user-assigned" },
    { policy: "formerlyUsedPolicy", code: "AN", kind: "country-formerly-used" },
  ];
  CASES.forEach(function (c) {
    var allowOpts = {};
    allowOpts[c.policy] = "allow";
    var allowed = b.guardCountry.validate(c.code, allowOpts);
    var hit = (allowed.issues || []).filter(function (i) { return i.kind === c.kind; });
    check("guardCountry: " + c.policy + " allow emits no " + c.kind + " finding " +
          "(got " + hit.length + ")", hit.length === 0);
    check("guardCountry: " + c.policy + " allow reports ok for " + c.code,
          allowed.ok === true);

    // The control: the same code under `audit` must STILL be reported, or the
    // check above passes for a guard that simply stopped detecting.
    var auditOpts = {};
    auditOpts[c.policy] = "audit";
    var audited = b.guardCountry.validate(c.code, auditOpts);
    var auditHit = (audited.issues || []).filter(function (i) { return i.kind === c.kind; });
    check("guardCountry: " + c.policy + " audit still reports " + c.kind,
          auditHit.length === 1 && auditHit[0].severity === "warn");

    // And `reject` must still refuse, so allow/audit/reject stay three settings.
    var rejectOpts = {};
    rejectOpts[c.policy] = "reject";
    var rejected = b.guardCountry.validate(c.code, rejectOpts);
    var rejectHit = (rejected.issues || []).filter(function (i) { return i.kind === c.kind; });
    check("guardCountry: " + c.policy + " reject still refuses " + c.kind,
          rejectHit.length === 1 && rejectHit[0].severity === "high");
  });
}

// A misspelled policy must be refused, not read as the mildest one.
//
// The severity helper mapped anything that was not "reject" to "warn", so a
// typo did not fall back to the profile's setting — it silently downgraded a
// refusal to an audit entry. `{ reservedPolicy: "rejcet" }` returned ok for
// `EU` and served it. A policy that decides whether a code is refused is
// config-time input: the operator should learn about the typo at boot, not
// from a residency decision that quietly went the other way.
function testAMisspelledPolicyIsRefusedNotTreatedAsWarn() {
  var BAD = ["rejcet", "REJECT", "deny", "", "warn", null, 1, true, {}];
  var POLICIES = ["reservedPolicy", "userAssignedPolicy", "formerlyUsedPolicy"];
  POLICIES.forEach(function (p) {
    var accepted = BAD.filter(function (v) {
      var o = {};
      o[p] = v;
      try { b.guardCountry.validate("EU", o); return true; }
      catch (_e) { return false; }
    });
    check("guardCountry: " + p + " refuses a value outside reject|audit|allow" +
          (accepted.length ? " (accepted " + JSON.stringify(accepted) + ")" : ""),
          accepted.length === 0);

    // The control: the three documented values must still be accepted, or the
    // check above passes for a guard that refuses every policy.
    var good = ["reject", "audit", "allow"].filter(function (v) {
      var o = {};
      o[p] = v;
      try { b.guardCountry.validate("EU", o); return true; }
      catch (_e) { return false; }
    });
    check("guardCountry: " + p + " still accepts reject, audit and allow (" +
          good.length + "/3)", good.length === 3);

    // The refusal has to happen where options are RESOLVED, so a typo is a
    // boot error rather than a request that fails later. Checking only
    // validate() would leave gate construction accepting the misconfiguration.
    var typo = {};
    typo[p] = "rejcet";
    var atResolve = null;
    try { b.guardCountry.resolveOpts(typo); } catch (e) { atResolve = e; }
    check("guardCountry: " + p + " typo is refused by resolveOpts",
          atResolve !== null && String(atResolve.code || "").indexOf("bad-opt") !== -1);

    var atGate = null;
    try { b.guardCountry.gate(typo); } catch (e) { atGate = e; }
    check("guardCountry: " + p + " typo is refused at gate construction",
          atGate !== null);
  });
}

async function run() {
  testAcceptsAssignedCodes();
  testRefusesEveryNonCountry();
  testShapeRefusals();
  testCaseIsNormalisedNotIgnored();
  testIsValidSugar();
  testDoesNotConsultIntl();
  testIssueKindsAreSourced();
  testProfilesDiffer();
  testAllowSuppressesTheFindingRatherThanDowngradingIt();
  testAMisspelledPolicyIsRefusedNotTreatedAsWarn();
  testFamilyRegistration();
  await testGateRefusesThroughTheContract();
  testTableIsComplete();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[guard-country] OK - " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL: " + helpers.formatErr(e)); process.exit(1); }
  );
}
