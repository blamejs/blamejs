// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

// A well-formed structural JWT (ES256 header, future exp/iat/iss) — passes
// guardJwt's structural validation. Not a real signature; validate is a
// pure inspection of shape, not a cryptographic verify.
var BENIGN_JWT =
  "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9." +
  "eyJpc3MiOiJleGFtcGxlIiwiZXhwIjo5OTk5OTk5OTk5LCJpYXQiOjE3MDAwMDAwMDB9.sig";

// alg=none JWT — RFC 7518 §3.6 explicit-no-signature, the canonical
// bearer-token forgery class guardAuth advertises routing through guardJwt.
var ALG_NONE_JWT = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.";

function expectThrows(label, fn, codeMatch) {
  var threw = null;
  try { fn(); } catch (e) { threw = e; }
  check(label, !!threw && (threw.code || "") === codeMatch);
  return threw;
}

function testValidate() {
  // Benign bundle (bearer token + cookie header) is clean under balanced.
  var okRv = b.guardAuth.validate(
    { jwtToken: BENIGN_JWT, cookieHeader: "sid=abc123; theme=dark" },
    { profile: "balanced" });
  check("guardAuth.validate benign ok",             okRv.ok === true);
  check("guardAuth.validate benign no issues",      okRv.issues.length === 0);

  // Hostile: alg=none token routed to guardJwt, tagged source="jwt".
  var jwtRv = b.guardAuth.validate({ jwtToken: ALG_NONE_JWT }, { profile: "strict" });
  check("guardAuth.validate alg=none refused",      jwtRv.ok === false);
  check("guardAuth.validate alg=none source=jwt",
    jwtRv.issues.some(function (i) { return i.source === "jwt"; }));
  check("guardAuth.validate alg=none alg-none rule",
    jwtRv.issues.some(function (i) { return i.ruleId === "jwt.alg-none"; }));

  // Strict requireAtLeastOne — an empty bundle is refused so an operator
  // can't wire a gate onto a credential-less request.
  var emptyRv = b.guardAuth.validate({}, { profile: "strict" });
  check("guardAuth.validate empty strict refused",  emptyRv.ok === false);
  check("guardAuth.validate empty no-auth-input",
    emptyRv.issues.some(function (i) { return i.ruleId === "auth.no-auth-input"; }));

  // CL+TE request-header smuggling (RFC 9112 §6.1), source="headers".
  var smugRv = b.guardAuth.validate(
    { requestHeaders: { "content-length": "10", "transfer-encoding": "chunked" } },
    { profile: "strict" });
  check("guardAuth.validate smuggling refused",     smugRv.ok === false);
  check("guardAuth.validate smuggling source=headers",
    smugRv.issues.some(function (i) {
      return i.source === "headers" && i.ruleId === "auth.header-smuggling-cl-te";
    }));
}

function testSanitize() {
  // Clean bundle passes through unchanged (identity transform), and the
  // returned bundle re-validates clean.
  var input = { jwtToken: BENIGN_JWT, cookieHeader: "sid=abc123; theme=dark" };
  var clean = b.guardAuth.sanitize(input, { profile: "balanced" });
  check("guardAuth.sanitize benign returns bundle", clean === input);
  check("guardAuth.sanitize benign revalidates ok",
    b.guardAuth.validate(clean, { profile: "balanced" }).ok === true);

  // Hostile: a CL+TE smuggling bundle is REFUSED (thrown), never returned —
  // the auth bundle can't be repaired in transit, so neutralization is
  // refusal, not a silently-mutated pass-through.
  var attack = { requestHeaders: { "content-length": "10", "transfer-encoding": "chunked" } };
  var err = expectThrows("guardAuth.sanitize smuggling throws",
    function () { b.guardAuth.sanitize(attack, { profile: "strict" }); },
    "auth.header-smuggling-cl-te");
  check("guardAuth.sanitize smuggling GuardAuthError",
    err instanceof b.guardAuth.GuardAuthError);

  // Hostile: alg=none bearer token refuses at sanitize too.
  expectThrows("guardAuth.sanitize alg=none throws",
    function () { b.guardAuth.sanitize({ jwtToken: ALG_NONE_JWT }, { profile: "strict" }); },
    "jwt.alg-none");
}

async function testGate() {
  var authGate = b.guardAuth.gate({ profile: "strict" });

  // Hostile alg=none bundle → refuse.
  var refuse = await authGate.check({ authBundle: { jwtToken: ALG_NONE_JWT } });
  check("guardAuth.gate alg=none action=refuse",    refuse.action === "refuse");
  check("guardAuth.gate alg=none ok=false",         refuse.ok === false);
  check("guardAuth.gate alg=none issue source=jwt",
    refuse.issues.some(function (i) { return i.source === "jwt"; }));

  // Benign bearer token → serve.
  var serve = await authGate.check({ authBundle: { jwtToken: BENIGN_JWT } });
  check("guardAuth.gate benign action=serve",       serve.action === "serve");
  check("guardAuth.gate benign ok=true",            serve.ok === true);

  // No bundle on ctx → serve (nothing to gate; other middleware owns the
  // absent-credential decision).
  var none = await authGate.check({});
  check("guardAuth.gate no-bundle action=serve",    none.action === "serve");
}

// guardAuth is a WRAPPER, so an option the operator sets for the guard it wraps
// has to reach that guard. It forwarded two keys out of guardOauth's fifteen,
// so every policy and every companion object was dropped on the floor — silently
// while the dropped checks were themselves silent, and fatally once the replay
// check began failing closed: a code-bearing flow refused, and supplying the
// store that would satisfy it changed nothing, because the store never arrived.
function testOauthOptForwarding() {
  var FLOW = {
    response_type: "code",
    redirect_uri:  "https://app.example.com/callback",
    state:         "csrf-rand-1",
    scope:         "openid profile",
    code_challenge: "abc123def456ghi789jkl012mno345pqr678",
    code_challenge_method: "S256",
    code:          "auth-code-xyz",
  };
  var BASE = { profile: "strict", allowedRedirectUris: ["https://app.example.com/callback"] };
  function validate(extra) {
    return b.guardAuth.validate({ oauthFlow: FLOW }, Object.assign({}, BASE, extra || {}));
  }

  // A working store must satisfy the replay check THROUGH the wrapper.
  var withStore = validate({ seenCodeStore: { hasSeen: function () { return false; } } });
  check("guardAuth: a seenCodeStore reaches guardOauth", withStore.ok === true);

  // ...and a store reporting a replay must still refuse through it.
  var replayed = validate({ seenCodeStore: { hasSeen: function () { return true; } } });
  check("guardAuth: a replayed code is refused through the wrapper",
        replayed.ok === false &&
        replayed.issues.some(function (i) { return i.ruleId === "oauth.code-reused"; }));

  // The documented opt-out must be reachable too, or the only escape from the
  // fail-closed default is to stop using the wrapper.
  var optOut = validate({ codeReusePolicy: "allow" });
  check("guardAuth: codeReusePolicy reaches guardOauth", optOut.ok === true);

  // Unconfigured still fails closed — the forwarding fix must not reopen the
  // hole it exists to make fixable.
  check("guardAuth: no store still fails closed", validate().ok === false);

  // A policy opt other than the replay pair proves this is forwarding, not two
  // special cases: relaxing PKCE must reach the child guard.
  var noPkce = Object.assign({}, FLOW);
  delete noPkce.code_challenge; delete noPkce.code_challenge_method;
  var strictPkce = b.guardAuth.validate({ oauthFlow: noPkce },
    Object.assign({}, BASE, { codeReusePolicy: "allow" }));
  var relaxedPkce = b.guardAuth.validate({ oauthFlow: noPkce },
    Object.assign({}, BASE, { codeReusePolicy: "allow", pkcePolicy: "allow" }));
  check("guardAuth: a missing PKCE challenge is refused by default", strictPkce.ok === false);
  check("guardAuth: pkcePolicy reaches guardOauth", relaxedPkce.ok === true);

  // `maxBytes` is the one name the two guards both use and mean differently:
  // here it caps the whole auth BUNDLE, in guardOauth it caps the flow. So the
  // child's cap gets its own wrapper name rather than being unreachable —
  // `maxParamBytes` was already tunable through the wrapper, which made the
  // absence of a flow-size control arbitrary.
  var bigFlow = Object.assign({}, FLOW, { scope: "x".repeat(9 * 1024) });
  function withCaps(extra) {
    return b.guardAuth.validate({ oauthFlow: bigFlow },
      Object.assign({ profile: "strict", codeReusePolicy: "allow",
                      allowedRedirectUris: ["https://app.example.com/callback"] }, extra || {}));
  }
  var cappedByChild = withCaps({ maxBytes: 65536 });
  check("guardAuth: its own maxBytes does NOT raise the child's flow cap",
        cappedByChild.issues.some(function (i) { return i.ruleId === "oauth.flow-cap"; }));

  var raised = withCaps({ oauthMaxBytes: 32 * 1024 });
  check("guardAuth: oauthMaxBytes raises the child's flow cap",
        !raised.issues.some(function (i) { return i.ruleId === "oauth.flow-cap"; }));

  var tightened = withCaps({ oauthMaxBytes: 512 });
  check("guardAuth: oauthMaxBytes can tighten the child's flow cap too",
        tightened.issues.some(function (i) { return i.ruleId === "oauth.flow-cap"; }));

  // ...and it must not be mistaken for the bundle cap, which still applies.
  var bundleCapped = b.guardAuth.validate({ oauthFlow: bigFlow },
    { profile: "strict", codeReusePolicy: "allow",
      allowedRedirectUris: ["https://app.example.com/callback"],
      oauthMaxBytes: 32 * 1024, maxBytes: 1024 });
  check("guardAuth: the bundle cap still governs the wrapper", bundleCapped.ok === false);
}

async function run() {
  testValidate();
  testSanitize();
  testOauthOptForwarding();
  await testGate();
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
