// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.mail.send.deliver — error / defensive / adversarial branch coverage.
 *
 * Companion to mail-send-deliver.test.js. That file covers the happy
 * paths + primary validation; this one drives the gap: the outcome-
 * classifier fallthroughs, every create() validation code, resolver
 * shape variance + timeout + node:dns fallback, the full MTA-STS policy
 * matrix (fetch-fail / none / testing / mismatch), the DANE lookup
 * matrix, DSN default fields, the DSN-callback failure path, the
 * _extractHeaderBlock separator variants, and the retry-budget clamp.
 *
 * The SMTP wire layer + MX resolver are driven with in-memory fakes.
 * The MTA-STS / DANE policy surface (b.network.smtp.policy) is not
 * opts-injectable, so those branches use fault injection: the shared
 * module's `mtaSts` / `dane` export objects are swapped for in-memory
 * stubs for the duration of one scenario and restored in a finally.
 * The node:dns fallback path swaps dns.promises.resolveMx the same way.
 * No real socket, resolver, or external endpoint is opened.
 */

var helpers        = require("../helpers");
var smtpPolicyMod  = require("../../lib/network-smtp-policy");
var dnsPromises    = require("node:dns").promises;

var b     = helpers.b;
var check = helpers.check;

// ---- local test utilities ----

function threw(fn) {
  try { fn(); return null; } catch (e) { return e; }
}
function okResolver(mxFor) {
  return { queryMx: async function (domain) { return mxFor(domain); } };
}
function okTransport() {
  return function () {
    return { send: async function () { return { ok: true, code: 250 }; } };
  };
}

// Swap b.network.smtp.policy's mtaSts / dane export objects for stubs.
// The top-level exports object is mutable (only the inner objects are
// frozen), so property reassignment is visible to the deliver module's
// cached lazyRequire handle. Restored in finally.
async function withSmtpPolicyStub(overrides, body) {
  var origMta  = smtpPolicyMod.mtaSts;
  var origDane = smtpPolicyMod.dane;
  try {
    if (overrides.mtaSts) smtpPolicyMod.mtaSts = overrides.mtaSts;
    if (overrides.dane)   smtpPolicyMod.dane   = overrides.dane;
    return await body();
  } finally {
    smtpPolicyMod.mtaSts = origMta;
    smtpPolicyMod.dane   = origDane;
  }
}

async function withNodeDnsResolveMx(fake, body) {
  var orig = dnsPromises.resolveMx;
  try {
    dnsPromises.resolveMx = fake;
    return await body();
  } finally {
    dnsPromises.resolveMx = orig;
  }
}

// ---- Outcome classifier — fallthrough / OR-alternative branches ----

function testClassifierFallthroughs() {
  var deliver = b.mail.send.deliver({ hostname: "m.example", audit: false });

  // No error, no response → the terminal `return "transient"`.
  check("classify(null,null) → transient",
    deliver.classifyOutcome(null, null) === "transient");
  // 3xx is neither 2/4/5xx → falls through to transient.
  check("classify 3xx → transient (fallthrough)",
    deliver.classifyOutcome(null, { code: 354 }) === "transient");
  // Response present but no code → String("") matches nothing → transient.
  check("classify response w/o code → transient",
    deliver.classifyOutcome(null, {}) === "transient");
  // Policy signal in the MESSAGE only (empty code) → the OR alternative
  // of the policy-class regex must still classify permanent.
  check("classify policy-signal via message only → permanent",
    deliver.classifyOutcome({ code: "", message: "REQUIRETLS was not offered" }, null) === "permanent");
  // Generic error code that is neither a network code nor a policy
  // signal → transient (the err-branch fallthrough).
  check("classify generic err code → transient",
    deliver.classifyOutcome({ code: "EPIPE", message: "broken pipe" }, null) === "transient");
  check("classify ENETUNREACH → transient",
    deliver.classifyOutcome({ code: "ENETUNREACH" }, null) === "transient");
  // Response wins over err when both present.
  check("classify 550 response beats err → permanent",
    deliver.classifyOutcome({ code: "ECONNREFUSED" }, { code: 550 }) === "permanent");
}

// ---- create(): remaining shape-validation codes ----

function testCreateValidationCodes() {
  var eUnknown = threw(function () {
    b.mail.send.deliver({ hostname: "m.example", bogusKey: 1 });
  });
  check("unknown top-level opt → throws (unknown option)",
    eUnknown && /unknown option/.test(eUnknown.message || ""));

  var ePolicy = threw(function () { b.mail.send.deliver({ hostname: "m.example", policy: 5 }); });
  check("policy non-object → deliver/bad-policy", ePolicy && ePolicy.code === "deliver/bad-policy");

  var eRetry = threw(function () { b.mail.send.deliver({ hostname: "m.example", retry: 5 }); });
  check("retry non-object → deliver/bad-retry", eRetry && eRetry.code === "deliver/bad-retry");

  var eDsn = threw(function () { b.mail.send.deliver({ hostname: "m.example", dsn: 5 }); });
  check("dsn non-object → deliver/bad-dsn", eDsn && eDsn.code === "deliver/bad-dsn");

  var eTo = threw(function () { b.mail.send.deliver({ hostname: "m.example", timeouts: 5 }); });
  check("timeouts non-object → deliver/bad-timeouts", eTo && eTo.code === "deliver/bad-timeouts");

  var eRes = threw(function () { b.mail.send.deliver({ hostname: "m.example", resolver: 5 }); });
  check("resolver non-object → deliver/bad-resolver", eRes && eRes.code === "deliver/bad-resolver");

  var eTf = threw(function () { b.mail.send.deliver({ hostname: "m.example", transportFactory: 5 }); });
  check("transportFactory non-function → deliver/bad-transport-factory",
    eTf && eTf.code === "deliver/bad-transport-factory");

  var eAudit = threw(function () { b.mail.send.deliver({ hostname: "m.example", audit: "yes" }); });
  check("audit non-boolean → deliver/bad-audit", eAudit && eAudit.code === "deliver/bad-audit");

  var eDsnFrom = threw(function () {
    b.mail.send.deliver({ hostname: "m.example", dsn: { from: 123, onPermanentFailure: function () {} } });
  });
  check("dsn.from non-string → deliver/bad-dsn-from", eDsnFrom && eDsnFrom.code === "deliver/bad-dsn-from");

  var ePerHost = threw(function () {
    b.mail.send.deliver({ hostname: "m.example", timeouts: { perHostMs: "30000" } });
  });
  check("timeouts.perHostMs string → deliver/bad-timeout-perHostMs",
    ePerHost && ePerHost.code === "deliver/bad-timeout-perHostMs");

  var ePolicyKey = threw(function () {
    b.mail.send.deliver({ hostname: "m.example", policy: { mtaSts: "off", nope: 1 } });
  });
  check("unknown policy sub-key → throws (unknown option)",
    ePolicyKey && /unknown option/.test(ePolicyKey.message || ""));

  // Custom backoffMs array is accepted (the truthy branch of the
  // backoffMs default-or-supplied selection).
  var okBackoff = threw(function () {
    b.mail.send.deliver({
      hostname: "m.example",
      retry:    { backoffMs: [b.constants.TIME.seconds(30), b.constants.TIME.minutes(2)] },
      audit:    false,
    });
  });
  check("custom retry.backoffMs accepted", okBackoff === null);
}

// ---- DSN composer — default-field branches ----

function testDsnDefaultFields() {
  var deliver = b.mail.send.deliver({ hostname: "m.example", audit: false });

  // reportingMta / statusCode / reason / originalHeaders all omitted →
  // every `|| default` branch fires.
  var dsn = deliver.buildDsn({
    dsnFrom:      "mailer-daemon@m.example",
    originalFrom: "alice@sender.com",
    recipient:    "bob@dest.com",
  });
  check("DSN default reason is 'permanent failure'",
    /^Diagnostic-Code: smtp; permanent failure/m.test(dsn));
  check("DSN default Status is 5.0.0", /^Status: 5\.0\.0/m.test(dsn));
  check("DSN reportingMta falls back to dsnFrom in the prose line",
    dsn.indexOf("mail delivery system at mailer-daemon@m.example") !== -1);
  check("DSN Reporting-MTA falls back to dsnFrom's domain",
    /^Reporting-MTA: dns; m\.example/m.test(dsn));

  // dsnFrom with no '@' → from.split("@")[1] is undefined → the final
  // `|| ""` fallback produces an empty Reporting-MTA authority.
  var dsn2 = deliver.buildDsn({
    dsnFrom:      "mailerdaemon",
    originalFrom: "alice@sender.com",
    recipient:    "bob@dest.com",
  });
  check("DSN Reporting-MTA empty-authority fallback (dsnFrom has no @)",
    dsn2.indexOf("Reporting-MTA: dns; \r\n") !== -1);
}

// ---- Resolver wrapper shape { rrs: [...] } ----

async function testResolverWrapperShape() {
  var deliver = b.mail.send.deliver({
    hostname:         "mta1.example.com",
    resolver:         { queryMx: async function (domain) {
      return { rrs: [{ exchange: "mx1." + domain, priority: 10 }], ttl: 300, provenance: "doh" };
    } },
    policy:           { mtaSts: "off", dane: "off" },
    transportFactory: okTransport(),
    audit:            false,
  });
  var result = await deliver({ from: "ops@example.com", to: ["a@recipient.com"], rfc822: Buffer.from("hi") });
  check("resolver { rrs } wrapper shape is accepted → delivered",
    result.delivered.length === 1 && result.delivered[0].mxHost === "mx1.recipient.com");
}

// ---- Resolver bad shapes → no-mx / null-mx → permanent ----

async function testResolverBadShapes() {
  function deliverForResolver(resolver) {
    return b.mail.send.deliver({
      hostname: "mta1.example.com", resolver: resolver,
      policy: { mtaSts: "off", dane: "off" }, audit: false,
    });
  }
  var msg = Buffer.from("hi");

  var r1 = await deliverForResolver({ queryMx: async function () { return {}; } })(
    { from: "ops@example.com", to: ["a@x.com"], rfc822: msg });
  check("resolver returns non-array/non-rrs → no-mx permanent",
    r1.failed.length === 1 && r1.failed[0].reasonCode === "5.1.2");

  var r2 = await deliverForResolver({ queryMx: async function () { return []; } })(
    { from: "ops@example.com", to: ["a@x.com"], rfc822: msg });
  check("resolver returns empty array → no-mx permanent",
    r2.failed.length === 1 && r2.failed[0].reasonCode === "5.1.2");

  // RFC 7505 null MX signalled with an empty-string exchange (the "."
  // form is covered by the sibling test).
  var r3 = await deliverForResolver({ queryMx: async function () { return [{ exchange: "", priority: 0 }]; } })(
    { from: "ops@example.com", to: ["a@x.com"], rfc822: msg });
  check("resolver returns empty-exchange null-MX → permanent 5.1.2",
    r3.failed.length === 1 && r3.failed[0].reasonCode === "5.1.2");
  check("null-MX failed.mxHost is null (no host was tried)",
    r3.failed[0].mxHost === null);
}

// ---- MX lookup timeout → transient → deferred ----

async function testMxLookupTimeout() {
  await helpers.withTestTimeout("mx-lookup timeout branch", async function () {
    var deliver = b.mail.send.deliver({
      hostname: "mta1.example.com",
      // Never-resolving lookup + a 1ms budget forces the internal
      // setTimeout reject path in _resolveMx. `1` is an intentionally
      // tiny timeout to exercise the timeout branch, not a duration.
      resolver: { queryMx: function () { return new Promise(function () {}); } },
      policy:   { mtaSts: "off", dane: "off" },
      timeouts: { mxLookupMs: 1 },
      audit:    false,
    });
    var result = await deliver({ from: "ops@example.com", to: ["a@slow.example"], rfc822: Buffer.from("hi") });
    check("mx-timeout → deferred (transient)", result.deferred.length === 1);
    check("mx-timeout → reasonCode 4.4.4", result.deferred[0].reasonCode === "4.4.4");
  });
}

// ---- No resolver → node:dns fallback path ----

async function testNodeDnsFallback() {
  await withNodeDnsResolveMx(async function (domain) {
    return [{ exchange: "mx.node." + domain, priority: 5 }];
  }, async function () {
    // resolver omitted → ctx.resolver null → _resolveMx uses nodeDns.resolveMx.
    var deliver = b.mail.send.deliver({
      hostname:         "mta1.example.com",
      policy:           { mtaSts: "off", dane: "off" },
      transportFactory: okTransport(),
      audit:            false,
    });
    var result = await deliver({ from: "ops@example.com", to: ["a@recipient.com"], rfc822: Buffer.from("hi") });
    check("no-resolver node:dns fallback → delivered",
      result.delivered.length === 1 && result.delivered[0].mxHost === "mx.node.recipient.com");
  });
}

// ---- Recipient with no usable domain ----

async function testRecipientNoDomain() {
  var deliver = b.mail.send.deliver({
    hostname: "mta1.example.com",
    resolver: okResolver(function (d) { return [{ exchange: "mx1." + d, priority: 10 }]; }),
    policy:   { mtaSts: "off", dane: "off" },
    transportFactory: okTransport(),
    audit:    false,
  });
  var r1 = await deliver({ from: "ops@example.com", to: ["nodomain"], rfc822: Buffer.from("hi") });
  check("recipient without '@' → permanent no-domain 5.1.3",
    r1.failed.length === 1 && r1.failed[0].reasonCode === "5.1.3");
  var r2 = await deliver({ from: "ops@example.com", to: ["trailingat@"], rfc822: Buffer.from("hi") });
  check("recipient with empty domain (trailing @) → permanent 5.1.3",
    r2.failed.length === 1 && r2.failed[0].reasonCode === "5.1.3");
}

// ---- All MX hosts transient → final transient → deferred ----

async function testAllHostsTransient() {
  var deliver = b.mail.send.deliver({
    hostname: "mta1.example.com",
    resolver: okResolver(function (d) {
      return [{ exchange: "mx1." + d, priority: 10 }, { exchange: "mx2." + d, priority: 20 }];
    }),
    policy:   { mtaSts: "off", dane: "off" },
    transportFactory: function () {
      return { send: async function () {
        var err = new Error("temporary failure");
        err.smtpResponse = { code: 451 };
        throw err;
      } };
    },
    audit:    false,
  });
  var result = await deliver({ from: "ops@example.com", to: ["a@example.com"], rfc822: Buffer.from("hi") });
  check("all-MX-transient → deferred (no delivery, no permanent fail)",
    result.deferred.length === 1 && result.delivered.length === 0 && result.failed.length === 0);
  check("all-MX-transient carries the last SMTP response code (4xx)",
    result.deferred[0].reasonCode === 451);
}

// ---- Permanent 5xx send failure records the MX host on the result ----

async function testPermanentFailKeepsMxHost() {
  var deliver = b.mail.send.deliver({
    hostname: "mta1.example.com",
    resolver: okResolver(function (d) { return [{ exchange: "mx1." + d, priority: 10 }]; }),
    policy:   { mtaSts: "off", dane: "off" },
    transportFactory: function () {
      return { send: async function () {
        var err = new Error("550 5.1.1 no such user");
        err.smtpResponse = { code: 550 };
        throw err;
      } };
    },
    audit:    false,
  });
  var result = await deliver({ from: "ops@example.com", to: ["a@example.com"], rfc822: Buffer.from("hi") });
  check("permanent 5xx → failed with mxHost recorded",
    result.failed.length === 1 && result.failed[0].mxHost === "mx1.example.com");
  check("permanent 5xx reasonCode is the SMTP code",
    result.failed[0].reasonCode === 550);
}

// ---- MTA-STS policy matrix (fault-injected b.network.smtp.policy) ----

async function runMtaStsScenario(sc) {
  var mtaStub = {
    fetch: async function () {
      if (sc.fetchThrows) throw new Error(sc.fetchThrows);
      return sc.fetchResult;
    },
    matchMx:     function () { return !!sc.matchMx; },
    parsePolicy: smtpPolicyMod.mtaSts.parsePolicy,
  };
  var out = { result: null, err: null };
  await withSmtpPolicyStub({ mtaSts: mtaStub }, async function () {
    var deliver = b.mail.send.deliver({
      hostname:         "mta1.example.com",
      resolver:         okResolver(function (d) { return [{ exchange: "mx1." + d, priority: 10 }]; }),
      policy:           { mtaSts: sc.policyMtaSts, dane: "off" },
      transportFactory: okTransport(),
      audit:            false,
    });
    try {
      out.result = await deliver({ from: "ops@example.com", to: ["a@recipient.com"], rfc822: Buffer.from("hi") });
    } catch (e) { out.err = e; }
  });
  return out;
}

async function testMtaStsMatrix() {
  // fetch throws under enforce → permanent mta-sts-fetch-failed (5.7.10).
  var s1 = await runMtaStsScenario({ policyMtaSts: "enforce", fetchThrows: "network down" });
  check("MTA-STS fetch fail under enforce → permanent 5.7.10",
    s1.result && s1.result.failed.length === 1 && s1.result.failed[0].reasonCode === "5.7.10");

  // fetch throws under testing → skip + continue with original MX → delivered.
  var s2 = await runMtaStsScenario({ policyMtaSts: "testing", fetchThrows: "network down" });
  check("MTA-STS fetch fail under testing → skipped, delivered",
    s2.result && s2.result.delivered.length === 1);

  // null policy → 'none' audit + continue → delivered.
  var s3 = await runMtaStsScenario({ policyMtaSts: "enforce", fetchResult: null });
  check("MTA-STS fetch returns null → delivered (no policy published)",
    s3.result && s3.result.delivered.length === 1);

  // mode 'none' → delivered.
  var s4 = await runMtaStsScenario({ policyMtaSts: "enforce", fetchResult: { mode: "none" } });
  check("MTA-STS mode none → delivered",
    s4.result && s4.result.delivered.length === 1);

  // enforce policy, MX matches → filtered non-empty → delivered.
  var s5 = await runMtaStsScenario({
    policyMtaSts: "enforce", fetchResult: { mode: "enforce", mx: ["*.recipient.com"] }, matchMx: true });
  check("MTA-STS enforce + MX match → delivered",
    s5.result && s5.result.delivered.length === 1);

  // enforce policy, MX does not match → mismatch → permanent 5.7.10.
  var s6 = await runMtaStsScenario({
    policyMtaSts: "enforce", fetchResult: { mode: "enforce", mx: ["mail.other.com"] }, matchMx: false });
  check("MTA-STS enforce + no MX match → permanent 5.7.10",
    s6.result && s6.result.failed.length === 1 && s6.result.failed[0].reasonCode === "5.7.10");

  // testing policy + testing local + no match → 'no-match' audit + continue → delivered.
  var s7 = await runMtaStsScenario({
    policyMtaSts: "testing", fetchResult: { mode: "testing", mx: ["mail.other.com"] }, matchMx: false });
  check("MTA-STS testing + no match (local testing) → delivered (report-only)",
    s7.result && s7.result.delivered.length === 1);

  // testing policy + enforce local + match → 'testing' audit + filtered → delivered.
  var s8 = await runMtaStsScenario({
    policyMtaSts: "enforce", fetchResult: { mode: "testing", mx: ["*.recipient.com"] }, matchMx: true });
  check("MTA-STS testing published + local enforce + match → delivered",
    s8.result && s8.result.delivered.length === 1);
}

// ---- RFC 8461 §5.2: published testing-mode policy is report-only ----
// A domain-published "testing" policy MUST NOT cause a hard failure —
// failures are report-only and delivery proceeds. The default local
// posture (mtaSts:"enforce") cannot promote a domain's testing policy
// to a bounce. RED before the fix (the no-match testing policy threw
// mta-sts-mx-mismatch → permanent bounce under local enforce).
async function testMtaStsTestingNotEnforcedUnderLocalEnforce() {
  var s = await runMtaStsScenario({
    policyMtaSts: "enforce", fetchResult: { mode: "testing", mx: ["mail.other.com"] }, matchMx: false });
  check("testing-mode + local enforce + no MX match → NOT bounced (report-only)",
    s.result && s.result.failed.length === 0 && s.result.deferred.length === 0);
  check("testing-mode + local enforce + no MX match → delivered against full MX set",
    s.result && s.result.delivered.length === 1);
  check("testing-mode report-only does not reject deliver()",
    s.err === null);
}

// ---- DANE lookup matrix (fault-injected b.network.smtp.policy.dane) ----

async function runDaneScenario(sc) {
  var daneStub = {
    tlsa: async function () {
      if (sc.tlsaThrows) throw new Error(sc.tlsaThrows);
      return sc.tlsaResult;
    },
    recordShape: smtpPolicyMod.dane.recordShape,
    verifyChain: smtpPolicyMod.dane.verifyChain,
  };
  var out = { result: null, err: null };
  await withSmtpPolicyStub({ dane: daneStub }, async function () {
    var deliver = b.mail.send.deliver({
      hostname:         "mta1.example.com",
      resolver:         okResolver(function (d) { return [{ exchange: "mx1." + d, priority: 10 }]; }),
      policy:           { mtaSts: "off", dane: sc.policyDane },
      transportFactory: okTransport(),
      audit:            false,
    });
    try {
      out.result = await deliver({ from: "ops@example.com", to: ["a@recipient.com"], rfc822: Buffer.from("hi") });
    } catch (e) { out.err = e; }
  });
  return out;
}

async function testDaneMatrix() {
  var d1 = await runDaneScenario({ policyDane: "opportunistic",
    tlsaResult: [{ usage: 3, selector: 1, mtype: 1, dataHex: "ab" }] });
  check("DANE opportunistic + TLSA records present → delivered",
    d1.result && d1.result.delivered.length === 1);

  var d2 = await runDaneScenario({ policyDane: "opportunistic", tlsaResult: [] });
  check("DANE opportunistic + empty TLSA → delivered",
    d2.result && d2.result.delivered.length === 1);

  var d3 = await runDaneScenario({ policyDane: "opportunistic", tlsaResult: null });
  check("DANE opportunistic + no TLSA → delivered",
    d3.result && d3.result.delivered.length === 1);

  var d4 = await runDaneScenario({ policyDane: "opportunistic", tlsaThrows: "SERVFAIL" });
  check("DANE opportunistic + TLSA lookup throws → skipped, delivered",
    d4.result && d4.result.delivered.length === 1);
}

// ---- DANE enforce TLSA failure is per-recipient, not batch-fatal ----
// A DANE-enforce TLSA lookup failure must fail (defer) the single
// affected recipient and STILL return the batch result object the
// contract promises — it must NOT throw out of deliver() and discard
// the sibling recipients' outcomes. RED before the fix (the throw
// propagated out of deliver() and rejected the whole call).
async function testDaneEnforceFailsOneRecipientNotBatch() {
  var d = await runDaneScenario({ policyDane: "enforce", tlsaThrows: "SERVFAIL" });
  check("DANE enforce TLSA failure does not reject deliver()",
    d.err === null && d.result !== null);
  check("DANE enforce TLSA failure defers the affected recipient",
    d.result && d.result.deferred.length === 1 && d.result.delivered.length === 0);
}

// A DANE-enforce TLSA failure for ONE recipient's MX must not abort the
// sibling recipient in the same deliver() batch. The DANE stub throws
// only for the "bad" domain's MX host; the "good" domain must still be
// delivered in the same call.
async function testDaneEnforceBatchSurvivesSiblingFailure() {
  var daneStub = {
    tlsa: async function (mxHost) {
      // Fault-inject a TLSA lookup failure for the bad domain's MX only.
      if (String(mxHost).indexOf("bad.example") !== -1) throw new Error("SERVFAIL");
      return null;
    },
    recordShape: smtpPolicyMod.dane.recordShape,
    verifyChain: smtpPolicyMod.dane.verifyChain,
  };
  var out = { result: null, err: null };
  await withSmtpPolicyStub({ dane: daneStub }, async function () {
    var deliver = b.mail.send.deliver({
      hostname:         "mta1.example.com",
      resolver:         okResolver(function (d) { return [{ exchange: "mx1." + d, priority: 10 }]; }),
      policy:           { mtaSts: "off", dane: "enforce" },
      transportFactory: okTransport(),
      audit:            false,
    });
    try {
      out.result = await deliver({
        from:   "ops@example.com",
        to:     ["victim@bad.example", "friend@good.example"],
        rfc822: Buffer.from("hi"),
      });
    } catch (e) { out.err = e; }
  });
  check("mixed DANE batch does not reject deliver()",
    out.err === null && out.result !== null);
  check("mixed DANE batch delivers the healthy sibling recipient",
    out.result && out.result.delivered.length === 1 &&
    out.result.delivered[0].recipient === "friend@good.example");
  check("mixed DANE batch defers the DANE-failed recipient",
    out.result && out.result.deferred.length === 1 &&
    out.result.deferred[0].recipient === "victim@bad.example");
}

// ---- DSN callback failure path ----

async function testDsnCallbackFailure() {
  var deliver = b.mail.send.deliver({
    hostname: "mta1.example.com",
    resolver: okResolver(function (d) { return [{ exchange: "mx1." + d, priority: 10 }]; }),
    policy:   { mtaSts: "off", dane: "off" },
    transportFactory: function () {
      return { send: async function () {
        var err = new Error("550 5.1.1 no such user");
        err.smtpResponse = { code: 550 };
        throw err;
      } };
    },
    dsn: {
      from: "mailer-daemon@example.com",
      onPermanentFailure: async function () { throw new Error("DSN transport exploded"); },
    },
    audit: false,
  });
  var result = await deliver({ from: "ops@example.com", to: ["a@example.com"], rfc822: Buffer.from("hi") });
  check("DSN callback throwing → recipient still recorded as failed",
    result.failed.length === 1);
  check("DSN callback throwing → dsnSent flag stays false",
    result.failed[0].dsnSent === false);
}

// ---- _extractHeaderBlock separator variants (via the DSN path) ----

async function testExtractHeaderBlockVariants() {
  var seen = [];
  function makeDeliver() {
    return b.mail.send.deliver({
      hostname: "mta1.example.com",
      resolver: okResolver(function (d) { return [{ exchange: "mx1." + d, priority: 10 }]; }),
      policy:   { mtaSts: "off", dane: "off" },
      transportFactory: function () {
        return { send: async function () {
          var err = new Error("550 5.1.1 no such user");
          err.smtpResponse = { code: 550 };
          throw err;
        } };
      },
      dsn: {
        from: "mailer-daemon@example.com",
        onPermanentFailure: async function (env, res, dsnMessage) { seen.push(dsnMessage); },
      },
      audit: false,
    });
  }

  // LF-only header separator → the `\n\n` fallback branch.
  await makeDeliver()({ from: "ops@example.com", to: ["a@example.com"],
    rfc822: Buffer.from("Subject: lf-only\nX-Tag: one\n\nbody") });
  check("DSN embeds LF-only-separated original headers",
    seen.length === 1 && seen[0].indexOf("Subject: lf-only") !== -1);

  // No blank-line separator at all → whole string returned.
  await makeDeliver()({ from: "ops@example.com", to: ["a@example.com"],
    rfc822: Buffer.from("Subject: no-separator-single-line") });
  check("DSN embeds header block when message has no blank-line separator",
    seen.length === 2 && seen[1].indexOf("Subject: no-separator-single-line") !== -1);
}

// ---- Retry budget: custom backoff + attempt-index clamp + envelope.attempt ----

async function testRetryBudgetClamp() {
  var backoff = [b.constants.TIME.seconds(30), b.constants.TIME.minutes(2)];
  var deliver = b.mail.send.deliver({
    hostname: "mta1.example.com",
    resolver: okResolver(function (d) { return [{ exchange: "mx1." + d, priority: 10 }]; }),
    policy:   { mtaSts: "off", dane: "off" },
    retry:    { maxAttempts: 10, backoffMs: backoff },
    transportFactory: function () {
      return { send: async function () {
        var err = new Error("temporary");
        err.smtpResponse = { code: 451 };
        throw err;
      } };
    },
    audit:    false,
  });
  // envelope.attempt: 3 → attempts becomes 4; still < maxAttempts(10) so
  // it defers; idx = min(attempts-1=3, backoffMs.length-1=1) = 1 → clamps
  // to the last backoff entry.
  var result = await deliver({
    from: "ops@example.com", to: ["a@example.com"], rfc822: Buffer.from("hi"), attempt: 3,
  });
  check("retry: prior attempt count carried through → deferred attempt is 4",
    result.deferred.length === 1 && result.deferred[0].attempt === 4);
  check("retry: attempt index clamps to the last backoff entry",
    result.deferred[0].retryAfterMs === backoff[backoff.length - 1]);
}

// ---- Default-audit (audit enabled) path executes cleanly ----

async function testDefaultAuditEnabled() {
  // audit omitted → auditEnabled true branch; the real (best-effort)
  // audit sink runs. Delivery must still succeed.
  var deliver = b.mail.send.deliver({
    hostname: "mta1.example.com",
    resolver: okResolver(function (d) { return [{ exchange: "mx1." + d, priority: 10 }]; }),
    policy:   { mtaSts: "off", dane: "off" },
    transportFactory: okTransport(),
  });
  var result = await deliver({ from: "ops@example.com", to: ["a@recipient.com"], rfc822: Buffer.from("hi") });
  check("audit-enabled default path delivers", result.delivered.length === 1);
}

// ---- Run ----

async function run() {
  testClassifierFallthroughs();
  testCreateValidationCodes();
  testDsnDefaultFields();
  await testResolverWrapperShape();
  await testResolverBadShapes();
  await testMxLookupTimeout();
  await testNodeDnsFallback();
  await testRecipientNoDomain();
  await testAllHostsTransient();
  await testPermanentFailKeepsMxHost();
  await testMtaStsMatrix();
  await testMtaStsTestingNotEnforcedUnderLocalEnforce();
  await testDaneMatrix();
  await testDaneEnforceFailsOneRecipientNotBatch();
  await testDaneEnforceBatchSurvivesSiblingFailure();
  await testDsnCallbackFailure();
  await testExtractHeaderBlockVariants();
  await testRetryBudgetClamp();
  await testDefaultAuditEnabled();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[mail-send-deliver-coverage] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
