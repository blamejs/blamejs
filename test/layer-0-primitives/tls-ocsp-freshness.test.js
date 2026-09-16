// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.network.tls.ocsp.evaluate — OCSP response FRESHNESS enforcement
 * (RFC 6960 §4.2.2.1). Regression coverage for the dead staleness gate:
 * evaluateOcspResponse called Date.parse() on thisUpdate/nextUpdate, but
 * those fields are already unix-ms NUMBERS (parseOcspResponse → _parseTime
 * returns Date.UTC(...)). Date.parse(<number>) coerces to a bare-integer
 * string → NaN, so the !isFinite guard rejected EVERY signature-valid
 * response (fresh or stale) with a misleading "missing thisUpdate", leaving
 * the real future-thisUpdate / past-nextUpdate window checks as unreachable
 * dead code (the past-nextUpdate branch latently fail-open).
 *
 * No existing test built a full SIGNED `successful` BasicOCSPResponse — every
 * prior OCSP test short-circuited before the freshness gate — which is why
 * the dead check shipped. This builds a real ECDSA-SHA256-signed response and
 * drives the consumer path, asserting:
 *   - a STALE response (past nextUpdate) is REJECTED for the stale reason
 *     (RED before the fix: rejected, but with "missing thisUpdate");
 *   - a FRESH response is ACCEPTED (RED before the fix: rejected as "missing
 *     thisUpdate" — the bug cannot tell fresh from stale);
 *   - a FUTURE-thisUpdate response is rejected for the future reason.
 *
 * Run standalone: node test/layer-0-primitives/tls-ocsp-freshness.test.js
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

// A fixed reference time so the test is wall-clock independent (passed to
// evaluate as opts.now). All thisUpdate/nextUpdate are offsets from this.
var FIXED_NOW = 1750000000000;   // 2025-06-15T...Z, a stable ms value

// A STALE response (nextUpdate well in the past) MUST be rejected — and for
// the STALE reason, not the misleading "missing thisUpdate" the dead gate
// produced. RED before the fix: ok:false but errors=["...missing thisUpdate..."].
function testRejectsStaleResponse() {
  var fx = helpers.buildOcspResponse({
    producedAtMs: FIXED_NOW,
    thisUpdateMs: FIXED_NOW - 3 * 86400000,   // 3 days ago
    nextUpdateMs: FIXED_NOW - 2 * 86400000,   // 2 days ago → STALE
  });
  var rv = b.network.tls.ocsp.evaluate(fx.der, {
    issuerPem: fx.issuerPem, serialHex: fx.serialHex, now: FIXED_NOW,
  });
  check("stale: rejected (ok=false)", rv.ok === false);
  check("stale: signature still verified (proves we reached the freshness gate)",
        rv.signatureValid === true);
  var errs = (rv.errors || []).join(" ; ");
  check("stale: rejected for the STALE reason, not 'missing thisUpdate'",
        /nextUpdate|stale/i.test(errs) && !/missing thisUpdate/i.test(errs));
}

// A FRESH response (thisUpdate just past, nextUpdate in the future) MUST be
// accepted. RED before the fix: rejected as "missing thisUpdate" (the bug
// cannot distinguish fresh from stale — both wrongly ok:false).
function testAcceptsFreshResponse() {
  var fx = helpers.buildOcspResponse({
    producedAtMs: FIXED_NOW,
    thisUpdateMs: FIXED_NOW - 3600000,        // 1 hour ago
    nextUpdateMs: FIXED_NOW + 86400000,       // +1 day → FRESH
  });
  var rv = b.network.tls.ocsp.evaluate(fx.der, {
    issuerPem: fx.issuerPem, serialHex: fx.serialHex, now: FIXED_NOW,
  });
  check("fresh: accepted (ok=true)", rv.ok === true);
  check("fresh: certStatus good", rv.certStatus === "good");
  check("fresh: signature verified", rv.signatureValid === true);
  check("fresh: no errors", Array.isArray(rv.errors) && rv.errors.length === 0);
}

// A FUTURE-dated thisUpdate (clock skew / replay) MUST be rejected for the
// future reason — proves the future-window check is live, not dead.
function testRejectsFutureThisUpdate() {
  var fx = helpers.buildOcspResponse({
    producedAtMs: FIXED_NOW,
    thisUpdateMs: FIXED_NOW + 2 * 86400000,   // 2 days in the future
    nextUpdateMs: FIXED_NOW + 3 * 86400000,
  });
  var rv = b.network.tls.ocsp.evaluate(fx.der, {
    issuerPem: fx.issuerPem, serialHex: fx.serialHex, now: FIXED_NOW,
  });
  check("future: rejected (ok=false)", rv.ok === false);
  check("future: rejected for the FUTURE reason",
        /future/i.test((rv.errors || []).join(" ; ")));
}

// A fresh response with NO nextUpdate (optional field absent) MUST be
// accepted — guards the typeof-guard's null→NaN handling of the optional
// nextUpdate branch.
function testAcceptsFreshNoNextUpdate() {
  var fx = helpers.buildOcspResponse({
    producedAtMs: FIXED_NOW,
    thisUpdateMs: FIXED_NOW - 3600000,        // 1 hour ago, no nextUpdate
  });
  var rv = b.network.tls.ocsp.evaluate(fx.der, {
    issuerPem: fx.issuerPem, serialHex: fx.serialHex, now: FIXED_NOW,
  });
  check("no-nextUpdate fresh: accepted (ok=true)", rv.ok === true);
  check("no-nextUpdate fresh: certStatus good", rv.certStatus === "good");
}

// A non-finite clockSkewMs must NOT disable the freshness window. The stale
// check is `now > nextUpdate + skew`; skew === Infinity makes it `now >
// Infinity` (always false), so a STALE (past-nextUpdate) response — exactly
// the pre-revocation "good" reply an attacker replays after the cert is
// revoked — would be accepted. A present-but-non-finite skew falls back to
// the safe default instead of being honored. RED before the fix: rv.ok===true.
function testInfinityClockSkewDoesNotDisableFreshness() {
  var fx = helpers.buildOcspResponse({
    producedAtMs: FIXED_NOW,
    thisUpdateMs: FIXED_NOW - 3 * 86400000,   // 3 days ago
    nextUpdateMs: FIXED_NOW - 2 * 86400000,   // 2 days ago → STALE
  });
  var rv = b.network.tls.ocsp.evaluate(fx.der, {
    issuerPem: fx.issuerPem, serialHex: fx.serialHex, now: FIXED_NOW,
    clockSkewMs: Infinity,
  });
  check("Infinity skew: stale response still rejected (freshness not disabled)", rv.ok === false);
  check("Infinity skew: rejected for the STALE reason",
        /nextUpdate|stale/i.test((rv.errors || []).join(" ; ")));
  // A negative skew is likewise treated as invalid → safe default, so the
  // stale response stays rejected.
  var rvNeg = b.network.tls.ocsp.evaluate(fx.der, {
    issuerPem: fx.issuerPem, serialHex: fx.serialHex, now: FIXED_NOW,
    clockSkewMs: -1,
  });
  check("negative skew: stale response still rejected", rvNeg.ok === false);
}

// A response that OMITS nextUpdate has no stated expiry. RFC 6960 §4.2.2.1
// then puts no upper bound on how old thisUpdate may be, so a signature-valid
// "good" from before the certificate was revoked stays convincing forever —
// the same replay the nextUpdate window closes for responses that carry one.
// evaluate bounds the age from thisUpdate (default 24h) when nextUpdate is
// absent. RED before the fix: an 8-day-old no-nextUpdate response is ok:true.
function testRejectsStaleNoNextUpdate() {
  var fx = helpers.buildOcspResponse({
    producedAtMs: FIXED_NOW,
    thisUpdateMs: FIXED_NOW - 8 * 86400000,   // 8 days ago, no nextUpdate
  });
  var rv = b.network.tls.ocsp.evaluate(fx.der, {
    issuerPem: fx.issuerPem, serialHex: fx.serialHex, now: FIXED_NOW,
  });
  check("no-nextUpdate stale: rejected (ok=false)", rv.ok === false);
  check("no-nextUpdate stale: signature still verified (reached the age gate)",
        rv.signatureValid === true);
  check("no-nextUpdate stale: rejected for the age/nextUpdate reason, not 'missing thisUpdate'",
        /nextUpdate|older than the maximum|age/i.test((rv.errors || []).join(" ; ")) &&
        !/missing thisUpdate/i.test((rv.errors || []).join(" ; ")));
}

// A caller may widen the accepted age for a no-nextUpdate responder it trusts
// via opts.maxAgeMs. A 3-day-old response under a 7-day bound is accepted.
function testMaxAgeOverrideAcceptsWithinWindow() {
  var fx = helpers.buildOcspResponse({
    producedAtMs: FIXED_NOW,
    thisUpdateMs: FIXED_NOW - 3 * 86400000,   // 3 days ago, no nextUpdate
  });
  var rv = b.network.tls.ocsp.evaluate(fx.der, {
    issuerPem: fx.issuerPem, serialHex: fx.serialHex, now: FIXED_NOW,
    maxAgeMs: 7 * 86400000,
  });
  check("maxAge override (7d): 3-day-old no-nextUpdate accepted", rv.ok === true);
}

// A caller may also tighten it. A 2-hour-old no-nextUpdate response under a
// 1-hour bound is refused. RED before the fix: no age bound exists, so a
// no-nextUpdate response is accepted regardless of maxAgeMs.
function testMaxAgeOverrideRefusesBeyondWindow() {
  var fx = helpers.buildOcspResponse({
    producedAtMs: FIXED_NOW,
    thisUpdateMs: FIXED_NOW - 2 * 3600000,    // 2 hours ago, no nextUpdate
  });
  var rv = b.network.tls.ocsp.evaluate(fx.der, {
    issuerPem: fx.issuerPem, serialHex: fx.serialHex, now: FIXED_NOW,
    maxAgeMs: 3600000,                        // 1 hour
  });
  check("maxAge override (1h): 2-hour-old no-nextUpdate refused", rv.ok === false);
  check("maxAge override (1h): refused for the age reason",
        /older than the maximum|age|nextUpdate/i.test((rv.errors || []).join(" ; ")));
}

// The age bound applies ONLY when nextUpdate is absent: a response that STATES
// a future nextUpdate is honored for its stated validity even when thisUpdate
// is well past the default max age. Guards against the fix over-refusing a
// long-validity response that carries an explicit, unexpired nextUpdate.
function testPresentNextUpdateNotBoundedByMaxAge() {
  var fx = helpers.buildOcspResponse({
    producedAtMs: FIXED_NOW,
    thisUpdateMs: FIXED_NOW - 8 * 86400000,   // 8 days ago
    nextUpdateMs: FIXED_NOW + 86400000,       // but valid for another day
  });
  var rv = b.network.tls.ocsp.evaluate(fx.der, {
    issuerPem: fx.issuerPem, serialHex: fx.serialHex, now: FIXED_NOW,
  });
  check("present-nextUpdate: old thisUpdate accepted while nextUpdate is unexpired",
        rv.ok === true);
}

async function run() {
  testRejectsStaleResponse();
  testAcceptsFreshResponse();
  testRejectsFutureThisUpdate();
  testAcceptsFreshNoNextUpdate();
  testInfinityClockSkewDoesNotDisableFreshness();
  testRejectsStaleNoNextUpdate();
  testMaxAgeOverrideAcceptsWithinWindow();
  testMaxAgeOverrideRefusesBeyondWindow();
  testPresentNextUpdateNotBoundedByMaxAge();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
