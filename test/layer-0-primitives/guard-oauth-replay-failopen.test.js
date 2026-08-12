// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.guardOauth code-reuse (replay) defense must FAIL CLOSED when the operator's
 * seenCodeStore errors. A store-lookup failure means "could not prove the
 * authorization code is unused" — which is a denial, not "the code is fresh".
 * Pre-fix the seenCodeStore.hasSeen() call was wrapped in a drop-silent catch,
 * so a backend outage silently skipped the replay check and the code was
 * accepted (codeReusePolicy is "reject" at every profile, so the defense is
 * meant to be unconditional).
 */

var helpers = require("../helpers");
var b = helpers.b;
var check = helpers.check;

var BENIGN_FLOW = {
  response_type: "code",
  redirect_uri:  "https://app.example.com/callback",
  state:         "csrf-rand-1",
  scope:         "openid profile",
  code_challenge: "abc123def456ghi789jkl012mno345pqr678",
  code_challenge_method: "S256",
  code:          "auth-code-xyz",
};
var OPTS = {
  profile: "strict",
  allowedRedirectUris: ["https://app.example.com/callback"],
};

async function run() {
  // Control 1 — store says "not seen": the flow validates.
  var freshStore = { hasSeen: function () { return false; } };
  var rvFresh = b.guardOauth.validate(BENIGN_FLOW, Object.assign({}, OPTS, { seenCodeStore: freshStore }));
  check("guard-oauth: an unused code with a working store validates", rvFresh.ok === true);

  // Control 2 — store says "seen": the replay is refused.
  var seenStore = { hasSeen: function () { return true; } };
  var rvSeen = b.guardOauth.validate(BENIGN_FLOW, Object.assign({}, OPTS, { seenCodeStore: seenStore }));
  check("guard-oauth: a replayed code (store hit) is refused",
        rvSeen.ok === false && rvSeen.issues.some(function (i) { return i.ruleId === "oauth.code-reused"; }));

  // THE FIX — store THROWS (backend outage): must fail closed, not accept.
  var throwingStore = { hasSeen: function () { throw new Error("replay store backend unavailable"); } };
  var rvErr = b.guardOauth.validate(BENIGN_FLOW, Object.assign({}, OPTS, { seenCodeStore: throwingStore }));
  check("guard-oauth: a replay-store error FAILS CLOSED (code not accepted)", rvErr.ok === false);
  check("guard-oauth: a replay-store error surfaces a could-not-verify refusal",
        rvErr.issues.some(function (i) { return i.ruleId === "oauth.code-reuse-unverifiable"; }));

  // The door NEXT to the one already closed. The earlier fix made a store that
  // ERRORS fail closed; a store that is simply ABSENT still skipped the check
  // entirely, which is the same "could not prove the code is unused" state with
  // a quieter cause. "Unconditional" has to mean unconditional: an operator who
  // does not want the check says so with codeReusePolicy "allow".
  var rvNoStore = b.guardOauth.validate(BENIGN_FLOW, OPTS);
  check("guard-oauth: a MISSING replay store fails closed too", rvNoStore.ok === false);
  check("guard-oauth: a missing replay store says why",
        rvNoStore.issues.some(function (i) { return i.ruleId === "oauth.code-reuse-unverifiable"; }));

  // ...and the explicit opt-out still works, so this is a default, not a wall.
  var rvOptOut = b.guardOauth.validate(BENIGN_FLOW, Object.assign({}, OPTS, { codeReusePolicy: "allow" }));
  check("guard-oauth: codeReusePolicy 'allow' still skips the check", rvOptOut.ok === true);

  // A flow with no code at all has nothing to replay.
  var noCode = Object.assign({}, BENIGN_FLOW); delete noCode.code;
  check("guard-oauth: a flow without a code is unaffected",
        b.guardOauth.validate(noCode, OPTS).ok === true);

  // The same shape one policy over: redirectUriPolicy "require-exact-allowlist"
  // (strict AND balanced, and every compliance posture pins strict) skipped the
  // exact-match check when the operator supplied no allowlist — so the
  // attacker-controlled redirect_uri class the policy exists for passed. The
  // @intro excused it by pointing at a startup audit that does not exist
  // anywhere in lib/.
  // This one is REPORTED, not refused: with no allowlist the guard cannot say
  // the redirect_uri is wrong, only that it was never given anything to compare
  // against. Refusing would make the primitive unusable before it is
  // configured. What was broken is that the warning went nowhere — the @intro
  // deferred it to a startup audit that does not exist in lib/.
  var noAllowlist = { profile: "strict", codeReusePolicy: "allow" };
  var rvNoList = b.guardOauth.validate(BENIGN_FLOW, noAllowlist);
  check("guard-oauth: a missing allowlist is REPORTED",
        rvNoList.issues.some(function (i) { return i.ruleId === "oauth.redirect-uri-allowlist-missing"; }));
  check("guard-oauth: ...without refusing an otherwise-clean flow", rvNoList.ok === true);
  check("guard-oauth: ...at a severity that stays out of the refusal set",
        rvNoList.issues.every(function (i) {
          return i.ruleId !== "oauth.redirect-uri-allowlist-missing" ||
                 (i.severity !== "high" && i.severity !== "critical");
        }));

  // An empty array is a configured allowlist that permits nothing, so it takes
  // the same warning path rather than reading as "anything goes".
  var rvEmptyList = b.guardOauth.validate(BENIGN_FLOW,
    { profile: "strict", codeReusePolicy: "allow", allowedRedirectUris: [] });
  check("guard-oauth: an EMPTY allowlist is reported, not treated as open",
        rvEmptyList.issues.some(function (i) { return i.ruleId === "oauth.redirect-uri-allowlist-missing"; }));

  // A CONFIGURED allowlist still refuses a redirect_uri outside it — the check
  // this whole policy exists for must keep working.
  var rvMismatch = b.guardOauth.validate(
    Object.assign({}, BENIGN_FLOW, { redirect_uri: "https://attacker.example/steal" }),
    { profile: "strict", codeReusePolicy: "allow", allowedRedirectUris: ["https://app.example.com/callback"] });
  check("guard-oauth: a configured allowlist still refuses a foreign redirect_uri",
        rvMismatch.ok === false &&
        rvMismatch.issues.some(function (i) { return i.ruleId === "oauth.redirect-uri-not-allowed"; }));

  // The permissive profile audits rather than requires, so it is unaffected.
  var rvAudit = b.guardOauth.validate(BENIGN_FLOW, { profile: "permissive", codeReusePolicy: "allow" });
  check("guard-oauth: redirectUriPolicy 'audit' does not demand an allowlist",
        !rvAudit.issues.some(function (i) { return i.ruleId === "oauth.redirect-uri-allowlist-missing"; }));
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); });
}
