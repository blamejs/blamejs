// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — b.auth.totp (RFC 6238 / RFC 4226).
 * Oracle: the RFC 6238 Appendix B reference codes, verified through the
 * verify-only SHA-1 path an operator migrating from a legacy authenticator
 * actually drives.
 * The drift window is the focus: which step verify() reports, that every step
 * in the window is reachable, that a step outside it is refused, and that a
 * replayed step is refused on the strength of lastUsedStep rather than on the
 * code being wrong. verify() takes an injectable `now`, so none of this needs
 * a wall clock.
 */

var b = require("../../index");
var helpers = require("../helpers");
var check = helpers.check;
function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }

var SECRET = b.auth.totp.generateSecret();
var STEP_MS = b.auth.totp.DEFAULT_STEP_SECONDS * 1000;
// A fixed instant, so every step number below is arithmetic rather than a race
// against the runner's clock.
var NOW = 1767225600000;                                   // 2026-01-01T00:00:00Z
var NOW_STEP = Math.floor(NOW / 1000 / b.auth.totp.DEFAULT_STEP_SECONDS);

async function testVerifyReportsTheMatchedStep() {
  var codeNow = b.auth.totp.generate(SECRET, { now: NOW });
  var got = b.auth.totp.verify(SECRET, codeNow, { now: NOW });
  check("verify returns the matched step, not just true", got === NOW_STEP, "got " + got + " want " + NOW_STEP);
  check("a wrong code returns false", b.auth.totp.verify(SECRET, "00000000", { now: NOW }) === false);
  // false and step 0 are both falsy in a boolean context; the contract is that
  // a caller can tell them apart, which is what makes lastUsedStep usable.
  check("the miss verdict is exactly false", b.auth.totp.verify(SECRET, "00000000", { now: NOW }) !== 0);
}

async function testEveryStepInTheDriftWindowVerifies() {
  // Default drift is +/-1 step. A code minted one step either side of now must
  // verify AND report ITS OWN step — reporting the current step instead would
  // make lastUsedStep replay-tracking useless.
  var drift = b.auth.totp.DEFAULT_DRIFT_STEPS;
  for (var d = -drift; d <= drift; d++) {
    var mintedAt = NOW + (d * STEP_MS);
    var c = b.auth.totp.generate(SECRET, { now: mintedAt });
    var got = b.auth.totp.verify(SECRET, c, { now: NOW });
    check("step offset " + d + " verifies and reports its own step",
      got === NOW_STEP + d, "got " + got + " want " + (NOW_STEP + d));
  }
}

async function testOutsideTheDriftWindowIsRefused() {
  var drift = b.auth.totp.DEFAULT_DRIFT_STEPS;
  var tooOld = b.auth.totp.generate(SECRET, { now: NOW - ((drift + 1) * STEP_MS) });
  var tooNew = b.auth.totp.generate(SECRET, { now: NOW + ((drift + 1) * STEP_MS) });
  check("a code one step past the window is refused", b.auth.totp.verify(SECRET, tooOld, { now: NOW }) === false);
  check("a code one step ahead of the window is refused", b.auth.totp.verify(SECRET, tooNew, { now: NOW }) === false);
  // Widening the window accepts it — proving the refusal above was the window
  // and not an unrelated failure.
  check("widening driftSteps accepts the same code",
    b.auth.totp.verify(SECRET, tooOld, { now: NOW, driftSteps: drift + 1 }) === NOW_STEP - (drift + 1));
}

async function testReplayIsRefusedByStepNotByCode() {
  var c = b.auth.totp.generate(SECRET, { now: NOW });
  var first = b.auth.totp.verify(SECRET, c, { now: NOW });
  check("first use of the code is accepted", first === NOW_STEP);
  check("the same code is refused once its step is recorded",
    b.auth.totp.verify(SECRET, c, { now: NOW, lastUsedStep: first }) === false);
  check("a step at-or-below lastUsedStep is refused even one step later",
    b.auth.totp.verify(SECRET, c, { now: NOW, lastUsedStep: NOW_STEP + 1 }) === false);
  // The next step's code is still accepted — the replay guard bounds the
  // window, it does not lock the secret out.
  var next = b.auth.totp.generate(SECRET, { now: NOW + STEP_MS });
  check("the following step still verifies after a replay refusal",
    b.auth.totp.verify(SECRET, next, { now: NOW + STEP_MS, lastUsedStep: NOW_STEP }) === NOW_STEP + 1);
}

async function testSeparatorsAreStripped() {
  var c = b.auth.totp.generate(SECRET, { now: NOW });
  var half = Math.floor(c.length / 2);
  var spaced = c.slice(0, half) + " " + c.slice(half);
  var dashed = c.slice(0, half) + "-" + c.slice(half);
  var dotted = c.slice(0, half) + "." + c.slice(half);
  check("a space-separated code verifies", b.auth.totp.verify(SECRET, spaced, { now: NOW }) === NOW_STEP);
  check("a dash-separated code verifies", b.auth.totp.verify(SECRET, dashed, { now: NOW }) === NOW_STEP);
  check("a dot-separated code verifies", b.auth.totp.verify(SECRET, dotted, { now: NOW }) === NOW_STEP);
  check("a numeric code verifies as well as its string form",
    b.auth.totp.verify(SECRET, Number(c), { now: NOW }) === NOW_STEP);
}

async function testRfc6238ReferenceVectors() {
  // RFC 6238 Appendix B. The published vectors are SHA-1 / 8 digits, which is
  // the legacy algorithm this framework accepts only on the verify path, so
  // these run through verifyOnly rather than generate().
  var RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";        // base32 of "12345678901234567890"
  var VECTORS = [
    [59,          "94287082"],
    [1111111109,  "07081804"],
    [1111111111,  "14050471"],
    [1234567890,  "89005924"],
    [2000000000,  "69279037"],
  ];
  VECTORS.forEach(function (v) {
    var atMs = v[0] * 1000;
    var want = Math.floor(v[0] / 30);
    var got = b.auth.totp.verify(RFC_SECRET, v[1], {
      now: atMs, algorithm: "sha1", verifyOnly: true, digits: 8, stepSeconds: 30, driftSteps: 0,
    });
    check("RFC 6238 vector at t=" + v[0] + " verifies at its own step",
      got === want, "got " + got + " want " + want);
  });
  check("a legacy SHA-1 verify without verifyOnly is refused",
    code(function () {
      b.auth.totp.verify(RFC_SECRET, "94287082", { now: 59000, algorithm: "sha1", digits: 8, stepSeconds: 30 });
    }) !== "NO-THROW");
}

async function testMalformedInputReadsAsNoMatch() {
  // verify() is documented tolerant: a malformed token is "didn't match", not
  // an exception the login path has to catch.
  check("empty secret is false", b.auth.totp.verify("", "12345678", { now: NOW }) === false);
  check("null secret is false", b.auth.totp.verify(null, "12345678", { now: NOW }) === false);
  check("null code is false", b.auth.totp.verify(SECRET, null, { now: NOW }) === false);
  check("undefined code is false", b.auth.totp.verify(SECRET, undefined, { now: NOW }) === false);
  check("a non-numeric code is false", b.auth.totp.verify(SECRET, "not-a-code", { now: NOW }) === false);
  // A misconfigured VERIFIER still throws — that must surface rather than read
  // as a silent "didn't match" on every login.
  check("a bad driftSteps throws rather than reading as no-match",
    code(function () { b.auth.totp.verify(SECRET, "12345678", { now: NOW, driftSteps: -1 }); }) !== "NO-THROW");
  check("a bad stepSeconds throws rather than reading as no-match",
    code(function () { b.auth.totp.verify(SECRET, "12345678", { now: NOW, stepSeconds: 0 }); }) !== "NO-THROW");
}

async function run() {
  await testVerifyReportsTheMatchedStep();
  await testEveryStepInTheDriftWindowVerifies();
  await testOutsideTheDriftWindowIsRefused();
  await testReplayIsRefusedByStepNotByCode();
  await testSeparatorsAreStripped();
  await testRfc6238ReferenceVectors();
  await testMalformedInputReadsAsNoMatch();
}
module.exports = { run: run };
if (require.main === module) { run().then(function () { console.log("[totp] OK — " + helpers.getChecks() + " checks passed"); }, function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }); }
