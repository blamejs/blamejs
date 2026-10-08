// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.fda21cfr11 — 21 CFR Part 11 §11.10(e) audit-content + §11.50(b)
 * electronic-signature shape primitives.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function _fakeAudit() {
  var emitted = [];
  return {
    safeEmit: function (event) { emitted.push(event); },
    query:    function () { return Promise.resolve([]); },
    _emitted: emitted,
  };
}

function testSurface() {
  check("fda21cfr11.posture is a function", typeof b.fda21cfr11.posture === "function");
  check("fda21cfr11.electronicSignature.create exposed",
        typeof b.fda21cfr11.electronicSignature.create === "function");
  check("fda21cfr11.assertGxpAudit exposed",
        typeof b.fda21cfr11.assertGxpAudit === "function");
  check("fda21cfr11.checkGxpAudit is fn",
        typeof b.fda21cfr11.checkGxpAudit === "function");
  check("fda21cfr11.Fda21Cfr11Error is fn",
        typeof b.fda21cfr11.Fda21Cfr11Error === "function");
  check("frameworkError.Fda21Cfr11Error exposed",
        typeof b.frameworkError.Fda21Cfr11Error === "function");
  check("DEFAULT_SIGNATURE_MEANINGS includes 'approval'",
        b.fda21cfr11.DEFAULT_SIGNATURE_MEANINGS.indexOf("approval") !== -1);
}

function testSignatureCreate() {
  var fda = b.fda21cfr11.posture({ audit: _fakeAudit(), interceptAudit: false });
  var rec = fda.electronicSignature.create({
    printedName:      "Jane Doe, M.D.",
    signatureMeaning: "approval",
    predicateRule:    "21 CFR 312.62 — investigator records",
    boundRecord:      Buffer.from("trial-data"),
  });
  check("signature has printedName",       rec.printedName === "Jane Doe, M.D.");
  check("signature has dateTimeUtc ISO",   /^\d{4}-\d{2}-\d{2}T/.test(rec.dateTimeUtc));
  check("signature has signatureMeaning",  rec.signatureMeaning === "approval");
  check("signature has predicateRule",     rec.predicateRule.indexOf("21 CFR 312.62") === 0);
  check("signature has recordHash hex",    typeof rec.recordHash === "string" && rec.recordHash.length > 0);
  check("signature has signatureRecord",   typeof rec.signatureRecord === "string");
}

function testSignatureBadMeaning() {
  var fda = b.fda21cfr11.posture({ audit: _fakeAudit(), interceptAudit: false });
  var threw = null;
  try {
    fda.electronicSignature.create({
      printedName: "X", signatureMeaning: "bogus",
      predicateRule: "21 CFR x",
    });
  } catch (e) { threw = e; }
  check("bad signatureMeaning throws Fda21Cfr11Error",
        threw && /bad-signature-meaning/.test(threw.code || ""));
}

function testSignatureMissingPredicate() {
  var fda = b.fda21cfr11.posture({ audit: _fakeAudit(), interceptAudit: false });
  var threw = null;
  try {
    fda.electronicSignature.create({
      printedName: "X", signatureMeaning: "approval",
    });
  } catch (e) { threw = e; }
  check("missing predicateRule throws",
        threw && /missing-predicate-rule/.test(threw.code || ""));
}

function testAssertGxpAuditOk() {
  var fda = b.fda21cfr11.posture({ audit: _fakeAudit(), interceptAudit: false });
  var ok = fda.assertGxpAudit({
    recordedAt: Date.now(),
    actorUserId: "user-1",
    action: "subject.update",
    reason: "operator request",
    metadata: { before: { x: 1 }, after: { x: 2 } },
  });
  check("assertGxpAudit returns true on valid row", ok === true);
}

function testAssertGxpAuditMissingBefore() {
  var fda = b.fda21cfr11.posture({ audit: _fakeAudit(), interceptAudit: false });
  var threw = null;
  try {
    fda.assertGxpAudit({
      recordedAt: Date.now(),
      actorUserId: "user-1",
      action: "subject.updated",
      reason: "operator request",
      metadata: { after: { x: 2 } },
    });
  } catch (e) { threw = e; }
  check("assertGxpAudit throws on missing before",
        threw && /gxp-shape-violation/.test(threw.code || ""));
}

function testAssertGxpAuditMetadataAsString() {
  var fda = b.fda21cfr11.posture({ audit: _fakeAudit(), interceptAudit: false });
  // Audit chain rows have metadata as a JSON string. Accept that form.
  var ok = fda.assertGxpAudit({
    recordedAt: Date.now(),
    actorUserId: "u",
    action: "subject.update",
    reason: "r",
    metadata: JSON.stringify({ before: 1, after: 2 }),
  });
  check("assertGxpAudit accepts JSON-string metadata", ok === true);
}

function testCheckGxpAuditMissingActor() {
  var fda = b.fda21cfr11.posture({ audit: _fakeAudit(), interceptAudit: false });
  var rv = fda.checkGxpAudit({
    recordedAt: Date.now(),
    action: "subject.update",
  });
  check("checkGxpAudit returns ok=false missing-actor",
        rv.ok === false && /actor/.test(rv.reason));
}

function testNonModificationBypassesShape() {
  var fda = b.fda21cfr11.posture({ audit: _fakeAudit(), interceptAudit: false });
  // Read-shaped events don't need before/after.
  var ok = fda.assertGxpAudit({
    recordedAt: Date.now(),
    actorUserId: "u",
    action: "subject.read",
  });
  check("read-shape audit bypasses before/after requirement", ok === true);
}

function testOffListModificationVerbsRequireShape() {
  // §11.10(e) must fail closed: a modifying verb NOT on the legacy denylist
  // (anonymize / revoke / overwrite / merge / withdraw_consent / restrict)
  // must still require before/after — previously it bypassed the check.
  var mods = ["subject.anonymize", "consent.revoke", "subject.overwrite",
              "db.merge", "subject.withdraw_consent", "subject.restrict"];
  for (var i = 0; i < mods.length; i += 1) {
    var r = b.fda21cfr11.checkGxpAudit({
      action: mods[i], recordedAt: Date.now(), actorUserId: "u",
    });
    check("checkGxpAudit requires §11.10(e) shape for " + mods[i], r.ok === false);
  }
  // A genuinely complete modification row (before/after/reason) passes.
  var full = b.fda21cfr11.checkGxpAudit({
    action: "subject.anonymize", recordedAt: Date.now(), actorUserId: "u",
    reason: "GDPR Art.17", metadata: { before: { name: "Alice" }, after: { name: null } },
  });
  check("checkGxpAudit accepts a complete anonymize row", full.ok === true);
}

function testSignatureStrippedRefusedWhenVerifierWired() {
  // #B0 — with verifyWith wired, a record whose signature is null/empty must
  // NOT verify on recordHash alone (recordHash is self-consistency, not
  // authentication). Accepting it is alg:none-style signature stripping.
  var nc  = require("node:crypto");
  var key = nc.randomBytes(32);
  var sign   = function (buf) { return nc.createHmac("sha256", key).update(buf).digest(); };
  var verify = function (buf, sig) { try { return nc.timingSafeEqual(sign(buf), sig); } catch (_e) { return false; } };
  var fda = b.fda21cfr11.posture({ audit: _fakeAudit(), interceptAudit: false, signWith: sign, verifyWith: verify });
  var rec = fda.electronicSignature.create({
    printedName: "Jane Doe, M.D.", signatureMeaning: "approval",
    predicateRule: "21 CFR 312.62", boundRecord: Buffer.from("trial-data"),
  });
  check("FDA properly-signed record verifies",
    fda.electronicSignature.verify(rec, Buffer.from("trial-data")).ok === true);
  var stripped = Object.assign({}, rec, { signature: null });
  var v = fda.electronicSignature.verify(stripped, Buffer.from("trial-data"));
  check("FDA signature-stripped record refused when verifier wired",
    v.ok === false && v.reason === "signature-required");
}

// Interception wraps `b.audit.safeEmit`, which is a hot-path sink: a throw
// there would fail the request that was only writing an audit row. So a
// malformed GxP row is dropped and a denied event recorded, and the emitting
// code hears nothing. The block used to say interception called
// `assertGxpAudit`, which would have let the caller correct the row.
function testInterceptionDropsSilentlyRatherThanRaising() {
  // `install()` wraps the framework audit sink, which is the seam the posture
  // interposes on; `opts.audit` only receives the posture's own events. The
  // collector stands in for the sink so the wrap has something to call
  // through to, and `uninstall()` puts the original back.
  var seen = [];
  var originalSafeEmit = b.audit.safeEmit;
  b.audit.safeEmit = function (event) { seen.push(event); };
  var fake = _fakeAudit();
  var installed = b.fda21cfr11.posture({ audit: fake, interceptAudit: true }).install();
  try {
    var bad = {
      action:      "subject.consent.granted",   // a modification verb
      actorUserId: "dr.chen",
      recordedAt:  Date.now(),
      // no reason, and no metadata.before / metadata.after
    };
    var raised = null;
    try { b.audit.safeEmit(bad); } catch (e) { raised = e; }
    check("interception does not raise on a malformed GxP row", raised === null,
      raised && String(raised.code));
    var actions = seen.map(function (e) { return e && e.action; });
    check("the malformed row is not written",
      actions.indexOf("subject.consent.granted") === -1, JSON.stringify(actions));
    var refused = seen.filter(function (e) {
      return e && e.action === "fda21cfr11.audit.refused";
    })[0];
    check("a denied fda21cfr11.audit.refused is written in its place",
      !!refused && refused.outcome === "denied" &&
      refused.metadata.attempted === "subject.consent.granted" &&
      typeof refused.metadata.reason === "string",
      JSON.stringify(refused));

    // The control: a well-formed row in the same namespace still goes through,
    // so the drop above is about the shape and not interception blocking the
    // namespace outright.
    b.audit.safeEmit({
      action:      "subject.consent.revoked",
      actorUserId: "dr.chen",
      recordedAt:  Date.now(),
      reason:      "withdrawal received",
      metadata:    { before: { consent: true }, after: { consent: false } },
    });
    check("a well-formed row in the same namespace is written",
      seen.some(function (e) {
        return e && e.action === "subject.consent.revoked";
      }));

    // assertGxpAudit is the call that does report the failure.
    var asserted = null;
    try { b.fda21cfr11.assertGxpAudit(bad); } catch (e) { asserted = e; }
    check("assertGxpAudit raises on the same row",
      !!asserted && asserted.code === "fda21cfr11/gxp-shape-violation",
      asserted && String(asserted.code));
  } finally {
    installed.uninstall();
    b.audit.safeEmit = originalSafeEmit;
  }
}

async function run() {
  testSurface();
  testInterceptionDropsSilentlyRatherThanRaising();
  testSignatureCreate();
  testSignatureBadMeaning();
  testSignatureMissingPredicate();
  testSignatureStrippedRefusedWhenVerifierWired();
  testAssertGxpAuditOk();
  testAssertGxpAuditMissingBefore();
  testAssertGxpAuditMetadataAsString();
  testCheckGxpAuditMissingActor();
  testNonModificationBypassesShape();
  testOffListModificationVerbsRequireShape();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
