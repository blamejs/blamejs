// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
/**
 * b.mail.spf / b.mail.dmarc / b.mail.arc / b.mail.inbound —
 * second supplementary branch-coverage companion.
 *
 * Targets the ERROR / DEFENSIVE / ADVERSARIAL arms the first coverage
 * companion (mail-auth-coverage.test.js) leaves untouched: macro
 * escapes + letters + custom delimiters, IPv6 macro forms, additional
 * bad-macro-syntax shapes, CIDR mask edges (/0 + partial-group), the
 * multiple-record + transient-DNS + lookup-ceiling classifications, the
 * a/mx/exists/include DNS-failure arms, DMARC transient + pct-sampling
 * dispositions, the aggregate-report pre-parsed / bad-input / cap arms,
 * the ARC per-hop key-material failure arms, and the inbound.verify
 * no-identity / helo-only branches.
 *
 * Everything is driven through the public API with in-memory dnsLookup
 * fakes (a throwing fake stands in for a transient resolver fault) and a
 * locally-generated RSA key for the ARC crypto path — no live network.
 */

var helpers    = require("../helpers");
var b          = helpers.b;
var check      = helpers.check;
var nodeCrypto = require("node:crypto");

// A TXT-only dnsLookup fake: map[host] returns the operator TXT shape;
// everything else is ENOTFOUND.
function _txtOnly(map) {
  return async function (host, type) {
    if (type === "TXT" && Object.prototype.hasOwnProperty.call(map, host)) return map[host];
    var e = new Error("ENOTFOUND"); e.code = "ENOTFOUND"; throw e;
  };
}

// A dnsLookup fake that throws a transient (non-absence) resolver fault
// for every query — drives the temperror classification arms.
function _transientDns() {
  return async function () {
    var e = new Error("resolver server failure"); e.code = "ESERVFAIL"; throw e;
  };
}

function _enotfound() {
  var e = new Error("ENOTFOUND"); e.code = "ENOTFOUND"; throw e;
}

function _threw(fn) {
  try { fn(); return null; } catch (e) { return e; }
}

// Run one SPF exists: policy and capture the expanded A-query names.
async function _spfExistsExpand(record, mailFrom, ip) {
  var queried = [];
  var dns = async function (host, type) {
    if (type === "TXT" && host === "s.example") return [[record]];
    if (type === "A") { queried.push(host); return ["127.0.0.2"]; }
    return _enotfound();
  };
  var rv = await b.mail.spf.verify({
    ip: ip || "192.0.2.9", mailFrom: mailFrom, dnsLookup: dns,
  });
  return { result: rv.result, queried: queried, explanation: rv.explanation };
}

// ---- SPF: macro escapes, letters, and custom delimiters (RFC 7208 §7) ----

async function testSpfMacroEscapesAndLetters() {
  var mf = "alice@s.example";
  // `%-` legacy escape expands to the literal "%20" (RFC 7208 §7.1).
  var hyphen = await _spfExistsExpand("v=spf1 exists:a%-b.probe -all", mf);
  check("spf macro %- → literal %20",
        hyphen.result === "pass" && hyphen.queried.indexOf("a%20b.probe") !== -1);
  // `%{s}` — the whole sender identity (local@domain).
  var sender = await _spfExistsExpand("v=spf1 exists:%{s}.probe -all", mf);
  check("spf macro %{s} → full sender identity",
        sender.result === "pass" && sender.queried.indexOf("alice@s.example.probe") !== -1);
  // `%{p}` — validated-domain sentinel; the framework returns "unknown"
  // rather than performing the discouraged §5.5 reverse-lookup.
  var pMac = await _spfExistsExpand("v=spf1 exists:%{p}.probe -all", mf);
  check("spf macro %{p} → RFC 7208 §5.5 'unknown' sentinel",
        pMac.result === "pass" && pMac.queried.indexOf("unknown.probe") !== -1);
  // `%{c}` — an exp-text-only letter; empty in mechanism context (§7.3).
  var cMac = await _spfExistsExpand("v=spf1 exists:x%{c}y.probe -all", mf);
  check("spf macro %{c} (exp-only letter) → empty in mechanism context",
        cMac.result === "pass" && cMac.queried.indexOf("xy.probe") !== -1);
  // Custom delimiter set: `%{l+}` splits the local-part on `+` and
  // re-joins with `.` (RFC 7208 §7.1 transformer delimiter set).
  var delim = await _spfExistsExpand("v=spf1 exists:%{l+}.probe -all", "a+b@s.example");
  check("spf macro %{l+} → custom '+' split delimiter re-joined with '.'",
        delim.result === "pass" && delim.queried.indexOf("a.b.probe") !== -1);
}

// ---- SPF: IPv6 macro letters (RFC 7208 §7.3) ----

async function testSpfMacroIpv6Letters() {
  var mf = "u@s.example";
  var v = await _spfExistsExpand("v=spf1 exists:%{v}.probe -all", mf, "2001:db8::1");
  check("spf macro %{v} on IPv6 connection → 'ip6'",
        v.result === "pass" && v.queried.indexOf("ip6.probe") !== -1);
  var iMac = await _spfExistsExpand("v=spf1 exists:%{i}.probe -all", mf, "2001:db8::1");
  check("spf macro %{i} on IPv6 → nibble-dotted 32-part form",
        iMac.result === "pass" &&
        iMac.queried.indexOf("2.0.0.1.0.d.b.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.probe") !== -1);
}

// ---- SPF: additional malformed-macro syntax arms (RFC 7208 §7.1) ----

async function testSpfMacroBadSyntaxMore() {
  async function bad(record) {
    var dns = _txtOnly({ "s.example": [[record]] });
    var rv = await b.mail.spf.verify({ ip: "192.0.2.5", mailFrom: "a@s.example", dnsLookup: dns });
    return rv;
  }
  var bare = await bad("v=spf1 exists:foo% -all");
  check("spf macro: trailing bare '%' → permerror",
        bare.result === "permerror" && /bare '%'/.test(bare.explanation || ""));
  var digit0 = await bad("v=spf1 exists:%{s0} -all");
  check("spf macro: transformer digit count 0 → permerror",
        digit0.result === "permerror" && /digit count must be >= 1/.test(digit0.explanation || ""));
  var badDelim = await bad("v=spf1 exists:%{d!} -all");
  check("spf macro: delimiter outside the §7.1 set → permerror",
        badDelim.result === "permerror" && /not in the RFC 7208 §7\.1 set/.test(badDelim.explanation || ""));
}

// ---- SPF: CIDR mask edges — /0 (match-all) + partial-group prefix ----

async function testSpfCidrMaskEdges() {
  // ip4:0.0.0.0/0 — a /0 authorizes every IPv4 (mask 0 → unconditional).
  var dns4 = _txtOnly({ "s.example": [["v=spf1 ip4:0.0.0.0/0 -all"]] });
  var r4 = await b.mail.spf.verify({ ip: "203.0.113.9", mailFrom: "a@s.example", dnsLookup: dns4 });
  check("spf ip4:0.0.0.0/0 → pass (mask 0 matches any IPv4)", r4.result === "pass");

  // ip6 partial-group prefix (/36): compares full groups + a masked
  // remainder-bit nibble, exercising the non-16-aligned mask arm.
  var dns36 = _txtOnly({ "s.example": [["v=spf1 ip6:2001:db8:8000::/36 -all"]] });
  var in36 = await b.mail.spf.verify({ ip: "2001:db8:8fff::1", mailFrom: "a@s.example", dnsLookup: dns36 });
  check("spf ip6:.../36 — IP inside the partial-group prefix → pass", in36.result === "pass");
  var out36 = await b.mail.spf.verify({ ip: "2001:db8:0fff::1", mailFrom: "a@s.example", dnsLookup: dns36 });
  check("spf ip6:.../36 — IP outside the partial-group prefix → fail (-all)", out36.result === "fail");

  // ip6 /0 — mask 0 authorizes any IPv6.
  var dns6z = _txtOnly({ "s.example": [["v=spf1 ip6:2001:db8::/0 -all"]] });
  var r6z = await b.mail.spf.verify({ ip: "fe80::1", mailFrom: "a@s.example", dnsLookup: dns6z });
  check("spf ip6:.../0 → pass (mask 0 matches any IPv6)", r6z.result === "pass");
}

// ---- SPF: multiple published records → permerror (RFC 7208 §4.5) ----

async function testSpfMultipleRecordsPermerror() {
  var dns = _txtOnly({ "s.example": [["v=spf1 -all"], ["v=spf1 +all"]] });
  var rv = await b.mail.spf.verify({ ip: "192.0.2.5", mailFrom: "a@s.example", dnsLookup: dns });
  check("spf.verify: two published v=spf1 records → permerror (RFC 7208 §4.5)",
        rv.result === "permerror" && /at most one/.test(rv.explanation || ""));
}

// ---- SPF: transient TXT lookup fault → temperror ----

async function testSpfLookupFailureTemperror() {
  var rv = await b.mail.spf.verify({ ip: "192.0.2.5", mailFrom: "a@s.example", dnsLookup: _transientDns() });
  check("spf.verify: transient TXT resolver fault → temperror (a verdict, not a throw)",
        rv.result === "temperror" && /lookup for s\.example failed/.test(rv.explanation || ""));
}

// ---- SPF: DNS-lookup ceiling exceeded (RFC 7208 §4.6.4) ----

async function testSpfLookupLimitExceeded() {
  // Eleven DNS-touching `a` mechanisms — the 11th crosses the 10-lookup
  // ceiling. Each A resolves to a non-matching address so the loop keeps
  // consuming lookups instead of short-circuiting on a match.
  var dns = async function (host, type) {
    if (type === "TXT" && host === "s.example") return [["v=spf1 a a a a a a a a a a a -all"]];
    if (type === "A") return ["198.51.100.1"];
    return _enotfound();
  };
  var rv = await b.mail.spf.verify({ ip: "192.0.2.5", mailFrom: "a@s.example", dnsLookup: dns });
  check("spf.verify: 11 DNS mechanisms → permerror (RFC 7208 §4.6.4 lookup ceiling)",
        rv.result === "permerror" && /DNS lookup limit exceeded/.test(rv.explanation || ""));
}

// ---- SPF: a / mx DNS-failure + macro arms ----

async function testSpfAMxErrorBranches() {
  // a: with a bad-macro domain-spec → permerror (the §7 expansion throws).
  var badMacro = _txtOnly({ "s.example": [["v=spf1 a:%{z} -all"]] });
  var rBad = await b.mail.spf.verify({ ip: "192.0.2.5", mailFrom: "a@s.example", dnsLookup: badMacro });
  check("spf a:%{z} — invalid macro-letter in domain-spec → permerror",
        rBad.result === "permerror" && /not a valid macro-letter/.test(rBad.explanation || ""));

  // a: whose domain-spec macro-expands to the empty string → permerror.
  var emptyMacro = _txtOnly({ "s.example": [["v=spf1 a:%{c} -all"]] });
  var rEmpty = await b.mail.spf.verify({ ip: "192.0.2.5", mailFrom: "a@s.example", dnsLookup: emptyMacro });
  check("spf a:%{c} — domain-spec expands to empty → permerror",
        rEmpty.result === "permerror" && /expanded to empty/.test(rEmpty.explanation || ""));

  // a — transient A lookup fault → temperror.
  var aTemp = async function (host, type) {
    if (type === "TXT" && host === "s.example") return [["v=spf1 a -all"]];
    if (type === "A") { var e = new Error("srv"); e.code = "ESERVFAIL"; throw e; }
    return _enotfound();
  };
  var rATemp = await b.mail.spf.verify({ ip: "192.0.2.5", mailFrom: "a@s.example", dnsLookup: aTemp });
  check("spf a — transient A lookup fault → temperror",
        rATemp.result === "temperror" && /a:s\.example lookup failed/.test(rATemp.explanation || ""));

  // mx — transient MX lookup fault → temperror.
  var mxTemp = async function (host, type) {
    if (type === "TXT" && host === "s.example") return [["v=spf1 mx -all"]];
    if (type === "MX") { var e = new Error("srv"); e.code = "ESERVFAIL"; throw e; }
    return _enotfound();
  };
  var rMxTemp = await b.mail.spf.verify({ ip: "192.0.2.5", mailFrom: "a@s.example", dnsLookup: mxTemp });
  check("spf mx — transient MX lookup fault → temperror",
        rMxTemp.result === "temperror" && /mx:s\.example MX lookup failed/.test(rMxTemp.explanation || ""));

  // mx — MX host A resolution transient fault → temperror.
  var mxHostTemp = async function (host, type) {
    if (type === "TXT" && host === "s.example") return [["v=spf1 mx -all"]];
    if (type === "MX") return [{ exchange: "mx1.s.example", preference: 10 }];
    if (type === "A") { var e = new Error("srv"); e.code = "ESERVFAIL"; throw e; }
    return _enotfound();
  };
  var rMxHostTemp = await b.mail.spf.verify({ ip: "192.0.2.5", mailFrom: "a@s.example", dnsLookup: mxHostTemp });
  check("spf mx — MX-host A resolution fault → temperror",
        rMxHostTemp.result === "temperror" && /mx host mx1\.s\.example A\/AAAA lookup failed/.test(rMxHostTemp.explanation || ""));

  // mx — MX host with no A record (void) is a miss, not an error → -all fail.
  var mxHostVoid = async function (host, type) {
    if (type === "TXT" && host === "s.example") return [["v=spf1 mx -all"]];
    if (type === "MX") return [{ exchange: "mx1.s.example", preference: 10 }];
    return _enotfound();
  };
  var rMxVoid = await b.mail.spf.verify({ ip: "192.0.2.5", mailFrom: "a@s.example", dnsLookup: mxHostVoid });
  check("spf mx — MX host with no A record → miss, falls to -all fail",
        rMxVoid.result === "fail");
}

// ---- SPF: exists transient lookup fault → temperror ----

async function testSpfExistsTemperror() {
  var dns = async function (host, type) {
    if (type === "TXT" && host === "s.example") return [["v=spf1 exists:p.%{d} -all"]];
    if (type === "A") { var e = new Error("srv"); e.code = "ESERVFAIL"; throw e; }
    return _enotfound();
  };
  var rv = await b.mail.spf.verify({ ip: "192.0.2.5", mailFrom: "a@s.example", dnsLookup: dns });
  check("spf exists — transient A lookup fault → temperror",
        rv.result === "temperror" && /exists:p\.s\.example lookup failed/.test(rv.explanation || ""));
}

// ---- SPF: include macro + transient arms ----

async function testSpfIncludeErrorBranches() {
  // include target is itself a bad macro-string → permerror.
  var badMacro = _txtOnly({ "s.example": [["v=spf1 include:%{z} -all"]] });
  var rBad = await b.mail.spf.verify({ ip: "192.0.2.5", mailFrom: "a@s.example", dnsLookup: badMacro });
  check("spf include:%{z} — invalid macro-letter → permerror",
        rBad.result === "permerror" && /not a valid macro-letter/.test(rBad.explanation || ""));

  // include target's TXT resolution transiently faults → temperror propagates.
  var incTemp = async function (host, type) {
    if (type === "TXT" && host === "s.example") return [["v=spf1 include:inner.example -all"]];
    if (type === "TXT" && host === "inner.example") { var e = new Error("srv"); e.code = "ESERVFAIL"; throw e; }
    return _enotfound();
  };
  var rTemp = await b.mail.spf.verify({ ip: "192.0.2.5", mailFrom: "a@s.example", dnsLookup: incTemp });
  check("spf include — inner transient TXT fault → temperror propagates to outer verdict",
        rTemp.result === "temperror" && /lookup for inner\.example failed/.test(rTemp.explanation || ""));
}

// ---- DMARC: transient _dmarc lookup fault → temperror ----

async function testDmarcTemperror() {
  var rv = await b.mail.dmarc.evaluate({
    from: "u@x.example", spf: { result: "fail", domain: "x" }, dkim: [], dnsLookup: _transientDns(),
  });
  check("dmarc.evaluate: transient _dmarc lookup fault → temperror (not a silent pass)",
        rv.result === "temperror" && rv.policy === null &&
        rv.alignment.spf === false && rv.alignment.dkim === false);
}

// ---- DMARC: pct< 100 sampled disposition (RFC 7489 §6.6.4) ----

async function testDmarcPctSampledDispositions() {
  // The sample roll is a deterministic SHAKE256 of pctSampleKey → [0,100).
  // Recompute it here and publish pct = roll so `roll >= pct` holds → the
  // failing message lands in the SAMPLED (next-less-strict) fraction.
  var key = "sampled-disposition-key";
  var digest = nodeCrypto.createHash("shake256", { outputLength: 4 }).update(key).digest();
  var u32 = (digest[0] << 24 >>> 0) + (digest[1] << 16) + (digest[2] << 8) + digest[3];
  var roll = u32 % 100;

  var rejectDns = _txtOnly({ "_dmarc.example.com": [["v=DMARC1; p=reject; pct=" + roll]] });
  var reject = await b.mail.dmarc.evaluate({
    from: "a@example.com", spf: { result: "fail", domain: "x" }, dkim: [],
    dnsLookup: rejectDns, pctSampleKey: key,
  });
  check("dmarc.evaluate: p=reject, sampled fraction → recommendedAction quarantine (§6.6.4 step-down)",
        reject.result === "fail" && reject.recommendedAction === "quarantine");

  var quarDns = _txtOnly({ "_dmarc.example.com": [["v=DMARC1; p=quarantine; pct=" + roll]] });
  var quar = await b.mail.dmarc.evaluate({
    from: "a@example.com", spf: { result: "fail", domain: "x" }, dkim: [],
    dnsLookup: quarDns, pctSampleKey: key,
  });
  check("dmarc.evaluate: p=quarantine, sampled fraction → recommendedAction none (§6.6.4 step-down)",
        quar.result === "fail" && quar.recommendedAction === "none");
}

// ---- DMARC aggregate report: pre-parsed / bad-input / cap arms ----

async function testDmarcAggregatePreParsedAndErrors() {
  // Non-Buffer / non-string / non-feedback input → typed throw.
  var eIn = _threw(function () { b.mail.dmarc.parseAggregateReport(12345); });
  check("dmarc.parseAggregateReport: numeric input → dmarc-rua-bad-input",
        eIn && /dmarc-rua-bad-input/.test(eIn.code || ""));

  // Pre-parsed object shortcut: skips parse, shapes directly + aggregates
  // the per-record totals.
  var shaped = b.mail.dmarc.parseAggregateReport({
    feedback: {
      report_metadata: { org_name: "acme", report_id: "r-1", date_range: { begin: "1000", end: "2000" } },
      policy_published: { domain: "d.example", p: "none", pct: "100" },
      record: [
        { row: { source_ip: "1.2.3.4", count: "5",
                 policy_evaluated: { disposition: "none", dkim: "pass", spf: "fail" } },
          identifiers: { header_from: "d.example" },
          auth_results: { dkim: { domain: "d.example", selector: "s", result: "pass" },
                          spf: { domain: "d.example", result: "pass" } } },
        { row: { source_ip: "5.6.7.8", count: "3",
                 policy_evaluated: { disposition: "reject", dkim: "fail", spf: "fail",
                                     reason: { type: "trusted_forwarder", comment: "fwd" } } },
          identifiers: { header_from: "d.example", envelope_from: "d.example" },
          auth_results: { dkim: [], spf: [] } },
      ],
    },
  });
  check("dmarc.parseAggregateReport: pre-parsed object shortcut shapes metadata + records",
        shaped.reportMetadata.orgName === "acme" && shaped.records.length === 2 &&
        shaped.reportMetadata.dateRange.begin === 1000);
  check("dmarc.parseAggregateReport: totals aggregate aligned vs not-aligned by count",
        shaped.totals.messages === 8 && shaped.totals.aligned === 5 && shaped.totals.notAligned === 3);
  check("dmarc.parseAggregateReport: per-record policy_evaluated reasons shaped",
        shaped.records[1].dispositions.reasons.length === 1 &&
        shaped.records[1].dispositions.reasons[0].type === "trusted_forwarder");

  // Over the per-report record cap → typed throw.
  var big = { feedback: { report_metadata: {}, policy_published: {}, record: [] } };
  for (var i = 0; i < 10001; i += 1) big.feedback.record.push({});
  var eCap = _threw(function () { b.mail.dmarc.parseAggregateReport(big); });
  check("dmarc.parseAggregateReport: over the 10000-record cap → dmarc-rua-too-many-records",
        eCap && /dmarc-rua-too-many-records/.test(eCap.code || ""));

  // Parsed XML whose root is not <feedback> → typed throw.
  var eNoFb = _threw(function () { b.mail.dmarc.parseAggregateReport("<other></other>"); });
  check("dmarc.parseAggregateReport: non-<feedback> XML root → dmarc-rua-no-feedback",
        eNoFb && /dmarc-rua-no-feedback/.test(eNoFb.code || ""));
}

// ---- ARC: per-hop key-material failure arms (RFC 8617 §5.1) ----

function _arcKeyDns(qname, records) {
  return async function (q) {
    if (q === qname) return records;
    return _enotfound();
  };
}

async function testArcKeyErrorBranches() {
  var from = "From: alice@example.com\r\nTo: bob@example.com\r\n\r\nbody\r\n";

  // AMS missing its d= tag → the AMS reports "missing required tag(s)";
  // the AS (all tags present) fails its key lookup → permerror.
  var missingTags =
    "ARC-Seal: i=1; a=rsa-sha256; cv=none; d=example.com; s=arc; b=AAAA\r\n" +
    "ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; s=arc; bh=AAAA; h=from; b=AAAA\r\n" +
    "ARC-Authentication-Results: i=1; example.com; spf=pass\r\n" + from;
  var rMiss = await b.mail.arc.verify(missingTags, { dnsLookup: async function () { return _enotfound(); } });
  var missAmsErrs = ((rMiss.hops[0] || {}).amsErrors || []).join(" ; ");
  check("arc.verify: AMS missing d/s/b/a → missing-required-tag(s) + chain fail",
        rMiss.chainStatus === "fail" && /missing required tag/.test(missAmsErrs));

  // AMS unsupported signature algorithm → permerror.
  var unsupAlg =
    "ARC-Seal: i=1; a=rsa-sha256; cv=none; d=example.com; s=arc; b=AAAA\r\n" +
    "ARC-Message-Signature: i=1; a=magic-alg; c=relaxed/relaxed; d=example.com; s=arc; bh=AAAA; h=from; b=AAAA\r\n" +
    "ARC-Authentication-Results: i=1; example.com; spf=pass\r\n" + from;
  var rAlg = await b.mail.arc.verify(unsupAlg, { dnsLookup: async function () { return _enotfound(); } });
  var algErrs = ((rAlg.hops[0] || {}).amsErrors || []).join(" ; ");
  check("arc.verify: AMS unsupported alg → permerror + chain fail",
        rAlg.chainStatus === "fail" && /unsupported alg 'magic-alg'/.test(algErrs));

  // A structurally-complete hop with valid tags.
  var fullHop =
    "ARC-Seal: i=1; a=rsa-sha256; cv=none; d=example.com; s=arc; b=AAAA\r\n" +
    "ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=arc; bh=AAAA; h=from; b=AAAA\r\n" +
    "ARC-Authentication-Results: i=1; example.com; spf=pass\r\n" + from;

  // Published key record lacks p= → permerror.
  var rNoP = await b.mail.arc.verify(fullHop,
    { dnsLookup: _arcKeyDns("arc._domainkey.example.com", [["v=DKIM1; k=rsa"]]) });
  var noPErrs = ((rNoP.hops[0] || {}).asErrors || []).join(" ; ");
  check("arc.verify: key record missing p= → permerror",
        rNoP.chainStatus === "fail" && /key record missing p=/.test(noPErrs));

  // Published p= is well-formed base64 but not a valid SPKI key → the AS
  // key parse fails → permerror.
  var rBadKey = await b.mail.arc.verify(fullHop,
    { dnsLookup: _arcKeyDns("arc._domainkey.example.com", [["v=DKIM1; k=rsa; p=AAAABBBB"]]) });
  var badKeyErrs = ((rBadKey.hops[0] || {}).asErrors || []).join(" ; ");
  check("arc.verify: unparseable key material → key-parse-failed permerror",
        rBadKey.chainStatus === "fail" && /key parse failed/.test(badKeyErrs));

  // Key lookup returns nothing (ENOTFOUND) on a valid-tag hop → permerror.
  var rNoKey = await b.mail.arc.verify(fullHop, { dnsLookup: async function () { return _enotfound(); } });
  check("arc.verify: key lookup ENOTFOUND → permerror (definitive absence, not temperror)",
        rNoKey.chainStatus === "fail" &&
        (rNoKey.hops[0] || {}).asResult === "permerror" &&
        (rNoKey.hops[0] || {}).amsResult === "permerror");
}

// ---- inbound.verify: no-identity + helo-only arms ----

async function testInboundNoIdentitySpfNone() {
  // Neither MAIL FROM nor HELO → SPF short-circuits to `none` without any
  // envelope-identity lookup. Keep the whole call offline with an
  // absence-only resolver so DMARC also resolves no record.
  var msg = "From: alice@example.com\r\nTo: bob@x\r\nSubject: hi\r\n\r\nbody\r\n";
  var v = await b.mail.inbound.verify({
    ip: "203.0.113.5", message: msg, dnsLookup: async function () { return _enotfound(); },
  });
  check("inbound.verify: no MAIL FROM / HELO → spf none (no identity lookup)",
        v.spf.result === "none" && /no MAIL FROM or HELO identity/.test(v.spf.explanation || ""));
  check("inbound.verify: no-identity + no DMARC record → dmarc none",
        v.dmarc.result === "none");
}

async function testInboundHeloOnlyAuthResults() {
  // HELO-only envelope: the emitted Authentication-Results carries the
  // spf clause with an smtp.helo property (not smtp.mailfrom).
  var msg = "From: alice@example.com\r\nTo: bob@x\r\nSubject: hi\r\n\r\nbody\r\n";
  var dns = _txtOnly({
    "mail.example.com":  [["v=spf1 ip4:203.0.113.0/24 -all"]],
    "_dmarc.example.com": [["v=DMARC1; p=none"]],
  });
  var v = await b.mail.inbound.verify({
    ip: "203.0.113.5", helo: "mail.example.com", message: msg,
    authservId: "mx.receiver.example", dnsLookup: dns,
  });
  check("inbound.verify: HELO-only identity → spf pass on the HELO domain",
        v.spf.result === "pass");
  check("inbound.verify: A-R spf clause carries smtp.helo (not smtp.mailfrom)",
        typeof v.authResults === "string" &&
        /spf=pass smtp\.helo=mail\.example\.com/.test(v.authResults) &&
        v.authResults.indexOf("smtp.mailfrom=") === -1);
}

async function run() {
  await testSpfMacroEscapesAndLetters();
  await testSpfMacroIpv6Letters();
  await testSpfMacroBadSyntaxMore();
  await testSpfCidrMaskEdges();
  await testSpfMultipleRecordsPermerror();
  await testSpfLookupFailureTemperror();
  await testSpfLookupLimitExceeded();
  await testSpfAMxErrorBranches();
  await testSpfExistsTemperror();
  await testSpfIncludeErrorBranches();
  await testDmarcTemperror();
  await testDmarcPctSampledDispositions();
  await testDmarcAggregatePreParsedAndErrors();
  await testArcKeyErrorBranches();
  await testInboundNoIdentitySpfNone();
  await testInboundHeloOnlyAuthResults();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
