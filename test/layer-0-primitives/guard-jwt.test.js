// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

// Minimal ES256 token — valid JSON header/payload, required claims
// present, far-future exp. The "sig" segment is a placeholder; the
// guard is the shape/header/claims contract, not a signature verifier.
var BENIGN_JWT =
  "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9." +
  "eyJpc3MiOiJleGFtcGxlIiwiZXhwIjo5OTk5OTk5OTk5LCJpYXQiOjE3MDAwMDAwMDB9." +
  "sig";

// alg=none — RFC 7518 §3.6 explicit-no-signature; the canonical
// CVE-2015-9235 / CVE-2018-0114 algorithm-confusion refuse class.
var ALG_NONE_JWT =
  "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0." +
  "eyJzdWIiOiJhdHRhY2tlciJ9.";

function expectThrows(label, fn, codeMatch) {
  var threw = null;
  try { fn(); } catch (e) { threw = e; }
  check(label, !!threw && (threw.code || "") === codeMatch);
  return threw;
}

function testKidSafe() {
  // Benign: a plain keystore identifier survives unchanged.
  var ok = b.guardJwt.kidSafe("tenant-1-2026-05");
  check("guardJwt.kidSafe benign passthrough",   ok === "tenant-1-2026-05");

  // Hostile: dot-dot path traversal — the operator keyResolver could
  // otherwise read outside the keystore directory.
  var trav = expectThrows("guardJwt.kidSafe rejects ../ traversal",
    function () { b.guardJwt.kidSafe("../../etc/passwd"); },
    "jwt.kid-traversal");
  check("guardJwt.kidSafe traversal GuardJwtError",
    trav instanceof b.guardJwt.GuardJwtError);

  // Hostile: forward slash / backslash separators and percent-encoded
  // variants are each refused as traversal indicators.
  expectThrows("guardJwt.kidSafe rejects embedded ../",
    function () { b.guardJwt.kidSafe("keys/../secret"); },
    "jwt.kid-traversal");
  expectThrows("guardJwt.kidSafe rejects backslash separator",
    function () { b.guardJwt.kidSafe("keys\\secret"); },
    "jwt.kid-traversal");
  expectThrows("guardJwt.kidSafe rejects percent-encoded dot-dot",
    function () { b.guardJwt.kidSafe("%2e%2e/keys"); },
    "jwt.kid-traversal");
  expectThrows("guardJwt.kidSafe rejects percent-encoded slash",
    function () { b.guardJwt.kidSafe("id%2fx"); },
    "jwt.kid-traversal");

  // Empty / non-string kid is a config-time refusal.
  expectThrows("guardJwt.kidSafe rejects empty string",
    function () { b.guardJwt.kidSafe(""); },
    "jwt.kid-empty");

  // Control byte in the kid — non-printable smuggling refuse.
  expectThrows("guardJwt.kidSafe rejects control byte",
    function () { b.guardJwt.kidSafe("bad\x00ctl"); },
    "jwt.kid-control");
}

function testSanitize() {
  // Benign: a well-formed ES256 token with required claims passes
  // through unchanged (compact serialization can't be repaired).
  var safe = b.guardJwt.sanitize(BENIGN_JWT, { profile: "strict" });
  check("guardJwt.sanitize benign passthrough",  safe === BENIGN_JWT);

  // Hostile: alg=none — critical, refused at every profile. sanitize
  // throws rather than returning a "cleaned" token.
  var noneErr = expectThrows("guardJwt.sanitize rejects alg=none",
    function () { b.guardJwt.sanitize(ALG_NONE_JWT, { profile: "strict" }); },
    "jwt.alg-none");
  check("guardJwt.sanitize alg-none GuardJwtError",
    noneErr instanceof b.guardJwt.GuardJwtError);

  // alg=none is universal — even permissive, which loosens the alg
  // allowlist entirely, still refuses the explicit-no-signature class.
  expectThrows("guardJwt.sanitize rejects alg=none at permissive too",
    function () { b.guardJwt.sanitize(ALG_NONE_JWT, { profile: "permissive" }); },
    "jwt.alg-none");

  // Hostile: not JWT compact-serialization shape — refused as jwt-shape.
  expectThrows("guardJwt.sanitize rejects non-JWT shape",
    function () { b.guardJwt.sanitize("not-a-jwt", { profile: "strict" }); },
    "jwt.jwt-shape");
}

function testValidateAlgNone() {
  // validate is the non-throwing sibling — confirm the alg=none refuse
  // surfaces in the issue list with ok=false, matching sanitize's throw.
  var rv = b.guardJwt.validate(ALG_NONE_JWT, { profile: "strict" });
  check("guardJwt.validate alg=none ok=false", rv.ok === false);
  check("guardJwt.validate alg-none kind present",
    rv.issues.some(function (i) { return i.kind === "alg-none"; }));
}

async function run() {
  testKidSafe();
  testSanitize();
  testValidateAlgNone();
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
