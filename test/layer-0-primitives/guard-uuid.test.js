// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * guard-uuid — RFC 9562 UUID identifier-safety primitive (b.guardUuid).
 *
 * Covers the normalize-or-throw sanitize contract: sanitize strips the
 * `urn:uuid:` prefix and Microsoft GUID braces and lower-cases to the
 * canonical hyphenated form, and throws GuardUuidError on a critical /
 * high finding (nil / max sentinel under reject).
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

var CANON = "550e8400-e29b-41d4-a716-446655440000";
function _code(fn) { try { fn(); return null; } catch (e) { return e && e.code; } }

// Each of this guard's three policies is a CONFIG-TIME entry point, so a value
// outside its vocabulary is a boot error rather than a runtime surprise. Read
// leniently, a misspelling takes whichever branch is not the strict one:
// `versionPolicy: "reject-unassinged"` is not "allow", so the check runs, and
// it is not the reject spelling either, so the finding drops to a warning —
// the operator asked to refuse an unassigned version and silently got an audit.
//
// The vocabularies come from the guard itself: written inline beside each
// profile entry, and confirmed against what the code compares. `audit-only` is
// accepted alongside `audit` because it behaves identically here and the
// framework treats the two as synonyms everywhere else — refusing it here
// while accepting it elsewhere would be a fresh inconsistency.
function testPolicyVocabularyIsEnforced() {
  var LEGAL = {
    formatPolicy:  ["hyphenated", "hyphenless", "braced", "urn", "hyphenated-only", "any"],
    versionPolicy: ["reject-unassigned", "audit", "audit-only", "allow"],
    variantPolicy: ["reject-non-rfc", "audit", "audit-only", "allow"],
    nilPolicy:     ["reject", "audit", "audit-only", "allow"],
    maxPolicy:     ["reject", "audit", "audit-only", "allow"],
    urnPolicy:     ["reject", "audit", "audit-only", "allow"],
    bracedPolicy:  ["reject", "audit", "audit-only", "allow"],
  };
  helpers.assertPolicyVocabulary(b.guardUuid, LEGAL, { label: "uuid", sample: CANON });
}

function testGuardUuidSurface() {
  check("guardUuid is an object",           typeof b.guardUuid === "object");
  check("guardUuid.NAME === 'uuid'",        b.guardUuid.NAME === "uuid");
  check("guardUuid.sanitize is a function", typeof b.guardUuid.sanitize === "function");
  check("guardUuid registered in guardAll",
    b.guardAll.allGuards().some(function (g) { return (g.name || g.NAME) === "uuid"; }));
  check("frameworkError.GuardUuidError exposed",
    typeof b.frameworkError.GuardUuidError === "function");
}

function testSanitizeCanonicalPassthrough() {
  var out = b.guardUuid.sanitize(CANON, { profile: "strict" });
  check("already-canonical UUID passes through", out === CANON);
}

function testSanitizeNormalizesUrnPrefix() {
  // urn:uuid: prefix stripped + upper-case lowered → canonical form.
  var out = b.guardUuid.sanitize("urn:uuid:550E8400-E29B-41D4-A716-446655440000",
    { profile: "balanced" });
  check("urn:uuid: prefix normalized to canonical", out === CANON);
}

function testSanitizeNormalizesBraces() {
  // Microsoft GUID braces stripped → canonical form.
  var out = b.guardUuid.sanitize("{550E8400-E29B-41D4-A716-446655440000}",
    { profile: "balanced" });
  check("GUID braces normalized to canonical", out === CANON);
}

function testSanitizeRefusesMaxSentinelStrict() {
  check("max UUID sentinel refused under strict",
    _code(function () {
      b.guardUuid.sanitize("ffffffff-ffff-ffff-ffff-ffffffffffff", { profile: "strict" });
    }) === "uuid.max-uuid");
}

function testSanitizeRefusesNilSentinelStrict() {
  check("nil UUID sentinel refused under strict",
    _code(function () {
      b.guardUuid.sanitize("00000000-0000-0000-0000-000000000000", { profile: "strict" });
    }) === "uuid.nil-uuid");
}

function testSanitizeThrowsGuardUuidError() {
  var caught = null;
  try { b.guardUuid.sanitize("not-a-uuid", { profile: "strict" }); }
  catch (e) { caught = e; }
  check("malformed UUID sanitize throws a GuardUuidError instance",
    caught instanceof b.frameworkError.GuardUuidError);
}

// The form classifier is a character walk. It is compared against the four
// patterns it replaced, over every accepted spelling and the near misses —
// one digit short, one long, a wrong separator, an unbalanced wrapper.
function testFormClassifierAgreesWithThePatternsItReplaced() {
  var UUID_HYPHENATED_RE = /^([0-9a-f]{8})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{12})$/i;
  var UUID_HYPHENLESS_RE = /^[0-9a-f]{32}$/i;
  var UUID_BRACED_RE = /^\{([0-9a-f]{8})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{12})\}$/i;
  var UUID_URN_RE = /^urn:uuid:([0-9a-f]{8})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{12})$/i;

  function oldClassify(s) {
    if (UUID_URN_RE.test(s)) return "urn";
    if (UUID_BRACED_RE.test(s)) return "braced";
    if (UUID_HYPHENATED_RE.test(s)) return "hyphenated";
    if (UUID_HYPHENLESS_RE.test(s)) return "hyphenless";
    return null;
  }

  var U = "550e8400-e29b-41d4-a716-446655440000";
  var BARE = "550e8400e29b41d4a716446655440000";
  var INPUTS = ["", "x", U, U.toUpperCase(), "{" + U + "}", "urn:uuid:" + U,
    "URN:UUID:" + U, "Urn:Uuid:" + U, BARE, BARE.toUpperCase(),
    U + "x", "x" + U, " " + U, U + " ", "{" + U, U + "}", "{{" + U + "}}",
    "urn:uuid:" + U + "x", "urn:uuid" + U, "urn:uuid:{" + U + "}",
    "550e8400-e29b-41d4-a716-44665544000",
    "550e8400-e29b-41d4-a716-4466554400000",
    "550e8400-e29b-41d4-a716_446655440000",
    "550e8400_e29b_41d4_a716_446655440000",
    "g50e8400-e29b-41d4-a716-446655440000",
    "00000000-0000-0000-0000-000000000000",
    "ffffffff-ffff-ffff-ffff-ffffffffffff",
    "-".repeat(36), "0".repeat(31), "0".repeat(33)];

  var diffs = [];
  INPUTS.forEach(function (s) {
    var expected = oldClassify(s);
    var actual = b.guardUuid._classifyFormForTest(s);
    if (expected !== actual) {
      diffs.push(JSON.stringify(s) + " want " + expected + " got " + actual);
    }
  });
  check("the UUID form classifier agrees with the patterns it replaced (" +
        INPUTS.length + " inputs)", diffs.length === 0,
        diffs.slice(0, 4).join(" | "));
}

function run() {
  testFormClassifierAgreesWithThePatternsItReplaced();
  testGuardUuidSurface();
  testPolicyVocabularyIsEnforced();
  testSanitizeCanonicalPassthrough();
  testSanitizeNormalizesUrnPrefix();
  testSanitizeNormalizesBraces();
  testSanitizeRefusesMaxSentinelStrict();
  testSanitizeRefusesNilSentinelStrict();
  testSanitizeThrowsGuardUuidError();
}

module.exports = { run: run };

if (require.main === module) {
  try { run(); console.log("[guard-uuid] OK — " + helpers.getChecks() + " checks passed"); }
  catch (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
}
