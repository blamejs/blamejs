// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.publicSuffix — Mozilla PSL substrate.
 *
 * Covers the lookup algorithm against the vendored
 * lib/vendor/public-suffix-list.dat: exact match, wildcard rules,
 * exception rules, IDN normalization, organizational-domain
 * derivation across registry depths, and input-shape rejects.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function testExactMatch() {
  check("publicSuffix('example.com') = 'com'",
        b.publicSuffix.publicSuffix("example.com") === "com");
  check("publicSuffix('foo.example.com') = 'com'",
        b.publicSuffix.publicSuffix("foo.example.com") === "com");
  check("publicSuffix('example.co.uk') = 'co.uk'",
        b.publicSuffix.publicSuffix("example.co.uk") === "co.uk");
  check("publicSuffix('a.b.example.co.uk') = 'co.uk'",
        b.publicSuffix.publicSuffix("a.b.example.co.uk") === "co.uk");
  // Multi-label rules from the PSL private section.
  check("publicSuffix('example.s3.amazonaws.com') = 's3.amazonaws.com'",
        b.publicSuffix.publicSuffix("example.s3.amazonaws.com") === "s3.amazonaws.com");
}

function testInputItselfIsPublicSuffix() {
  // Input that IS a public suffix returns itself for publicSuffix().
  check("publicSuffix('co.uk') = 'co.uk'",
        b.publicSuffix.publicSuffix("co.uk") === "co.uk");
  check("publicSuffix('com') = 'com'",
        b.publicSuffix.publicSuffix("com") === "com");
}

function testWildcardRule() {
  // The PSL has `*.ck` — every `<label>.ck` is a public suffix.
  // For `foo.bar.ck`, suffix is `bar.ck` (wildcard ate one extra label).
  check("publicSuffix('foo.bar.ck') = 'bar.ck' (wildcard)",
        b.publicSuffix.publicSuffix("foo.bar.ck") === "bar.ck");
}

function testWildcardOutranksShorterExactRule() {
  // `ck` above is one of only eight wildcards in the list whose parent
  // chain holds no shorter exact rule, so it passes under any precedence
  // order. The other 275 sit under a listed TLD, and there the ordering
  // decides the answer: the PSL algorithm keeps the matching rule with the
  // MOST LABELS, so `*.kawasaki.jp` (three) beats `jp` (one).
  check("publicSuffix('x.kawasaki.jp') = 'x.kawasaki.jp' (wildcard beats 'jp')",
        b.publicSuffix.publicSuffix("x.kawasaki.jp") === "x.kawasaki.jp");
  check("publicSuffix('a.x.kawasaki.jp') = 'x.kawasaki.jp'",
        b.publicSuffix.publicSuffix("a.x.kawasaki.jp") === "x.kawasaki.jp");
  check("publicSuffix('x.sch.uk') = 'x.sch.uk' (wildcard beats 'uk')",
        b.publicSuffix.publicSuffix("x.sch.uk") === "x.sch.uk");
  check("publicSuffix('x.nom.br') = 'x.nom.br' (wildcard beats 'br')",
        b.publicSuffix.publicSuffix("x.nom.br") === "x.nom.br");

  // The reason it matters. Two tenants under one wildcard registry are
  // separate organizations; resolving both to the registry's own domain
  // makes DMARC relaxed alignment and cookie scope treat them as one.
  check("organizationalDomain('mail.a.compute.amazonaws.com.cn') stays in tenant a",
        b.publicSuffix.organizationalDomain("mail.a.compute.amazonaws.com.cn") ===
        "mail.a.compute.amazonaws.com.cn");
  // One label deeper than the suffix is where tenants actually live: at the
  // wildcard label itself both names ARE public suffixes and both correctly
  // have no registrable parent.
  check("two tenants under one wildcard registry do not share an org domain",
        b.publicSuffix.organizationalDomain("mail.a.kawasaki.jp") !==
        b.publicSuffix.organizationalDomain("mail.bexample.kawasaki.jp"));
  check("each tenant's org domain is its own name",
        b.publicSuffix.organizationalDomain("mail.a.kawasaki.jp") ===
        "mail.a.kawasaki.jp");

  // A wildcard label is a public suffix in its own right, so nothing is
  // registrable at that depth.
  check("organizationalDomain('x.kawasaki.jp') = null (the label IS the suffix)",
        b.publicSuffix.organizationalDomain("x.kawasaki.jp") === null);
  check("isPublicSuffix('x.kawasaki.jp') = true",
        b.publicSuffix.isPublicSuffix("x.kawasaki.jp") === true);

  // An exact rule LONGER than a matching wildcard still wins, so the fix
  // must compare label counts rather than swap one blanket order for the
  // other. `*.aivencloud.com` and `aivencloud.com` are both listed.
  check("publicSuffix('x.aivencloud.com') = 'x.aivencloud.com' (longer rule wins)",
        b.publicSuffix.publicSuffix("x.aivencloud.com") === "x.aivencloud.com");
  check("publicSuffix('s3.amazonaws.com') = 's3.amazonaws.com' (exact, no wildcard)",
        b.publicSuffix.publicSuffix("s3.amazonaws.com") === "s3.amazonaws.com");

  // An exception rule outranks both regardless of length: `!city.kawasaki.jp`
  // is registrable even though `*.kawasaki.jp` matches it with more labels.
  check("publicSuffix('city.kawasaki.jp') = 'kawasaki.jp' (exception outranks)",
        b.publicSuffix.publicSuffix("city.kawasaki.jp") === "kawasaki.jp");
  check("organizationalDomain('a.city.kawasaki.jp') = 'city.kawasaki.jp'",
        b.publicSuffix.organizationalDomain("a.city.kawasaki.jp") === "city.kawasaki.jp");

  // Plain domains are untouched by the ordering change.
  check("publicSuffix('example.com') is still 'com'",
        b.publicSuffix.publicSuffix("example.com") === "com");
  check("publicSuffix('a.b.co.uk') is still 'co.uk'",
        b.publicSuffix.publicSuffix("a.b.co.uk") === "co.uk");
  check("publicSuffix('x.github.io') is still 'github.io'",
        b.publicSuffix.publicSuffix("x.github.io") === "github.io");
}

// The conformance suite published alongside the list itself
// (publicsuffix/list `tests/test_psl.txt`, CC0-1.0, taken at commit
// fe5aa073ba579b9d5ae92958b63a7d1de8c13e3a). Each row is one upstream
// `checkPublicSuffix(input, expected)` call, and `expected` is the
// REGISTRABLE domain — what this module calls the organizational domain.
//
// Hand-written cases pin the shapes someone thought to write down; these pin
// the algorithm. The wildcard-precedence defect was invisible to the
// hand-written set for releases because the one wildcard it exercised, `*.ck`,
// is among the eight in the list that no shorter exact rule can outrank.
var PSL_CONFORMANCE = [
  // Mixed case.
  ["COM", null], ["example.COM", "example.com"], ["WwW.example.COM", "example.com"],
  // Unlisted TLD.
  ["example", null], ["example.example", "example.example"],
  ["b.example.example", "example.example"], ["a.b.example.example", "example.example"],
  // TLD with only one rule.
  ["biz", null], ["domain.biz", "domain.biz"], ["b.domain.biz", "domain.biz"],
  ["a.b.domain.biz", "domain.biz"],
  // TLD with some two-level rules.
  ["com", null], ["example.com", "example.com"], ["b.example.com", "example.com"],
  ["a.b.example.com", "example.com"], ["uk.com", null],
  ["example.uk.com", "example.uk.com"], ["b.example.uk.com", "example.uk.com"],
  ["a.b.example.uk.com", "example.uk.com"], ["test.ac", "test.ac"],
  // TLD whose only rule is a wildcard.
  ["mm", null], ["c.mm", null], ["b.c.mm", "b.c.mm"], ["a.b.c.mm", "b.c.mm"],
  // A registry with wildcards under a listed TLD — the case the type-ordered
  // precedence resolved to the TLD, merging every tenant into one domain.
  ["jp", null], ["test.jp", "test.jp"], ["www.test.jp", "test.jp"],
  ["ac.jp", null], ["test.ac.jp", "test.ac.jp"], ["www.test.ac.jp", "test.ac.jp"],
  ["kyoto.jp", null], ["test.kyoto.jp", "test.kyoto.jp"], ["ide.kyoto.jp", null],
  ["b.ide.kyoto.jp", "b.ide.kyoto.jp"], ["a.b.ide.kyoto.jp", "b.ide.kyoto.jp"],
  ["c.kobe.jp", null], ["b.c.kobe.jp", "b.c.kobe.jp"], ["a.b.c.kobe.jp", "b.c.kobe.jp"],
  ["city.kobe.jp", "city.kobe.jp"], ["www.city.kobe.jp", "city.kobe.jp"],
  // Wildcard plus exception.
  ["ck", null], ["test.ck", null], ["b.test.ck", "b.test.ck"],
  ["a.b.test.ck", "b.test.ck"], ["www.ck", "www.ck"], ["www.www.ck", "www.ck"],
  // US K12.
  ["us", null], ["test.us", "test.us"], ["www.test.us", "test.us"],
  ["ak.us", null], ["test.ak.us", "test.ak.us"], ["www.test.ak.us", "test.ak.us"],
  ["k12.ak.us", null], ["test.k12.ak.us", "test.k12.ak.us"],
  ["www.test.k12.ak.us", "test.k12.ak.us"],
  // IDN labels, punycoded. The unicode spellings of these same names are
  // checked below, where the answer comes back in A-label form.
  ["xn--85x722f.com.cn", "xn--85x722f.com.cn"],
  ["xn--85x722f.xn--55qx5d.cn", "xn--85x722f.xn--55qx5d.cn"],
  ["www.xn--85x722f.xn--55qx5d.cn", "xn--85x722f.xn--55qx5d.cn"],
  ["shishi.xn--55qx5d.cn", "shishi.xn--55qx5d.cn"], ["xn--55qx5d.cn", null],
  ["xn--85x722f.xn--fiqs8s", "xn--85x722f.xn--fiqs8s"],
  ["www.xn--85x722f.xn--fiqs8s", "xn--85x722f.xn--fiqs8s"],
  ["shishi.xn--fiqs8s", "shishi.xn--fiqs8s"], ["xn--fiqs8s", null],
];

function testPslConformanceVectors() {
  var failed = [];
  PSL_CONFORMANCE.forEach(function (row) {
    var got = b.publicSuffix.organizationalDomain(row[0]);
    if (got !== row[1]) failed.push(row[0] + ": want " + row[1] + ", got " + got);
  });
  check("official PSL conformance vectors (" + PSL_CONFORMANCE.length +
        ") all pass" + (failed.length ? " — " + failed.join("; ") : ""),
        failed.length === 0);
}

function testPslConformanceDepartures() {
  // Two places this module answers differently from the upstream harness, both
  // deliberate. Pinned here so a change to either is a decision rather than a
  // drift, and so the conformance set above stays an exact comparison.

  // 1. Output is in A-label form. Lookup normalizes to punycode and the result
  //    is reported as looked up, so a U-label input comes back punycoded. The
  //    upstream harness compares against the input's own spelling.
  var shishi = "食狮";        // the two-character label in the vectors
  var gongsi = "公司";        // "company", the .cn second level
  var zhongguo = "中国";      // the IDN TLD
  check("a U-label input resolves to the same name in A-label form",
        b.publicSuffix.organizationalDomain(shishi + ".com.cn") ===
        "xn--85x722f.com.cn");
  check("a U-label second level resolves likewise",
        b.publicSuffix.organizationalDomain("www." + shishi + "." + gongsi + ".cn") ===
        "xn--85x722f.xn--55qx5d.cn");
  check("a U-label TLD resolves likewise",
        b.publicSuffix.organizationalDomain(shishi + "." + zhongguo) ===
        "xn--85x722f.xn--fiqs8s");
  check("the U-label and A-label spellings agree",
        b.publicSuffix.organizationalDomain("shishi." + zhongguo) ===
        b.publicSuffix.organizationalDomain("shishi.xn--fiqs8s"));

  // 2. A malformed input throws rather than returning null. The upstream
  //    harness folds "not a domain" into the same null as "no registrable
  //    parent"; this is a config-time primitive, so the two stay distinct.
  [null, ".com", ".example", ".example.com", ".example.example"].forEach(function (bad) {
    var code = null;
    try { b.publicSuffix.organizationalDomain(bad); } catch (e) { code = e.code; }
    check("organizationalDomain(" + JSON.stringify(bad) + ") throws invalid-domain",
          code === "public-suffix/invalid-domain");
  });
}

function testExceptionRule() {
  // `!www.ck` overrides the `*.ck` wildcard — `www.ck` itself is
  // registrable. The public suffix is `ck`.
  check("publicSuffix('www.ck') = 'ck' (exception)",
        b.publicSuffix.publicSuffix("www.ck") === "ck");
  check("publicSuffix('foo.www.ck') = 'ck' (exception parent)",
        b.publicSuffix.publicSuffix("foo.www.ck") === "ck");
}

function testIdn() {
  // Non-ASCII input punycodes via UTS #46 before lookup. `münchen.de`
  // — `de` is the public suffix (registrable below it).
  check("publicSuffix('münchen.de') = 'de'",
        b.publicSuffix.publicSuffix("münchen.de") === "de");
  // Punycode form of the same input — same answer.
  check("publicSuffix('xn--mnchen-3ya.de') = 'de'",
        b.publicSuffix.publicSuffix("xn--mnchen-3ya.de") === "de");
}

function testTrailingDot() {
  // A single trailing dot (FQDN form) is stripped before lookup.
  check("publicSuffix('example.com.') = 'com'",
        b.publicSuffix.publicSuffix("example.com.") === "com");
}

function testOrganizationalDomain() {
  check("orgDomain('foo.bar.example.co.uk') = 'example.co.uk'",
        b.publicSuffix.organizationalDomain("foo.bar.example.co.uk") === "example.co.uk");
  check("orgDomain('example.co.uk') = 'example.co.uk'",
        b.publicSuffix.organizationalDomain("example.co.uk") === "example.co.uk");
  check("orgDomain('example.com') = 'example.com'",
        b.publicSuffix.organizationalDomain("example.com") === "example.com");
  check("orgDomain('foo.bar.example.com') = 'example.com'",
        b.publicSuffix.organizationalDomain("foo.bar.example.com") === "example.com");
  // Input IS a public suffix → no organizational domain exists.
  check("orgDomain('co.uk') = null",
        b.publicSuffix.organizationalDomain("co.uk") === null);
  check("orgDomain('com') = null",
        b.publicSuffix.organizationalDomain("com") === null);
  // Wildcard depth: `bar.ck` is the suffix, `example.bar.ck` is the orgdomain.
  check("orgDomain('foo.example.bar.ck') = 'example.bar.ck'",
        b.publicSuffix.organizationalDomain("foo.example.bar.ck") === "example.bar.ck");
}

function testIsPublicSuffix() {
  check("isPublicSuffix('com') = true",
        b.publicSuffix.isPublicSuffix("com") === true);
  check("isPublicSuffix('co.uk') = true",
        b.publicSuffix.isPublicSuffix("co.uk") === true);
  check("isPublicSuffix('example.com') = false",
        b.publicSuffix.isPublicSuffix("example.com") === false);
  check("isPublicSuffix('example.co.uk') = false",
        b.publicSuffix.isPublicSuffix("example.co.uk") === false);
  // Multi-label private-section rule.
  check("isPublicSuffix('s3.amazonaws.com') = true",
        b.publicSuffix.isPublicSuffix("s3.amazonaws.com") === true);
}

function testInvalidInput() {
  var threw, err;

  threw = false;
  try { b.publicSuffix.publicSuffix(null); }
  catch (e) { threw = true; err = e; }
  check("null input throws invalid-domain",
        threw && err.code === "public-suffix/invalid-domain");

  threw = false;
  try { b.publicSuffix.publicSuffix(""); }
  catch (e) { threw = true; err = e; }
  check("empty string throws invalid-domain",
        threw && err.code === "public-suffix/invalid-domain");

  threw = false;
  try { b.publicSuffix.publicSuffix(123); }
  catch (e) { threw = true; err = e; }
  check("non-string throws invalid-domain",
        threw && err.code === "public-suffix/invalid-domain");

  threw = false;
  try { b.publicSuffix.publicSuffix("foo..bar"); }
  catch (e) { threw = true; err = e; }
  check("empty label throws invalid-domain",
        threw && err.code === "public-suffix/invalid-domain");

  threw = false;
  try { b.publicSuffix.publicSuffix("foo\x00.com"); }
  catch (e) { threw = true; err = e; }
  check("null byte throws invalid-domain",
        threw && err.code === "public-suffix/invalid-domain");

  threw = false;
  try { b.publicSuffix.publicSuffix("foo bar.com"); }
  catch (e) { threw = true; err = e; }
  check("whitespace byte throws invalid-domain",
        threw && err.code === "public-suffix/invalid-domain");

  // 254-char input exceeds RFC 1035 cap.
  var tooLong = new Array(252).join("a") + ".co";
  threw = false;
  try { b.publicSuffix.publicSuffix(tooLong); }
  catch (e) { threw = true; err = e; }
  check("253-octet overflow throws invalid-domain",
        threw && err.code === "public-suffix/invalid-domain");
}

function testLookupSource() {
  var src = b.publicSuffix.lookupSource();
  check("lookupSource returns object",
        src && typeof src === "object");
  check("lookupSource.entries > 1000",
        typeof src.entries === "number" && src.entries > 1000);
  check("lookupSource.sha256 is 64-hex",
        typeof src.sha256 === "string" && /^[0-9a-f]{64}$/.test(src.sha256));
  check("lookupSource.vendoredAt is a string",
        typeof src.vendoredAt === "string" && src.vendoredAt.length > 0);
  // Frozen so callers can't mutate the framework-internal cache.
  // Either a throw (strict-mode + frozen) or a no-op (non-strict
  // ignore) is acceptable; the invariant is "the cached value didn't
  // change". We swallow the throw and re-fetch.
  try { src.entries = 0; }
  catch (_e) { /* frozen-mutation rejection is the success path */ }
  check("lookupSource is frozen (mutation no-op)",
        b.publicSuffix.lookupSource().entries === src.entries &&
        b.publicSuffix.lookupSource().entries > 1000);
}

function testCaseInsensitive() {
  check("publicSuffix('EXAMPLE.CO.UK') = 'co.uk'",
        b.publicSuffix.publicSuffix("EXAMPLE.CO.UK") === "co.uk");
  check("orgDomain('EXAMPLE.CO.UK') = 'example.co.uk'",
        b.publicSuffix.organizationalDomain("EXAMPLE.CO.UK") === "example.co.uk");
}

function testCanonicalDomain() {
  // Encoding-stable host form for identity comparison: case, trailing dot, and
  // IDN A-label collapse; invalid/hostile input fails closed to "".
  check("canonicalDomain lowercases + strips trailing dot",
        b.publicSuffix.canonicalDomain("Example.COM.") === "example.com");
  check("canonicalDomain is idempotent on an already-canonical host",
        b.publicSuffix.canonicalDomain("example.com") === "example.com");
  // The root marker of an absolute name need not be an ASCII dot. UTS #46 maps
  // U+3002 (and U+FF0E, U+FF61) to ".", so those spellings only BECOME a
  // trailing dot during IDN normalization — after the one place that strips it.
  // Returning `xn--mnchen-3ya.example.` from a function documented to strip the
  // trailing dot leaves every caller to compensate, and two of them did:
  // `b.mail.dmarc.evaluate` compared an authenticated domain against an Author
  // Domain in a different canonical form, so a message aligned with itself
  // failed alignment.
  check("canonicalDomain strips a UTS #46 root marker, not just an ASCII dot",
        b.publicSuffix.canonicalDomain("münchen.example。") === "xn--mnchen-3ya.example",
        JSON.stringify(b.publicSuffix.canonicalDomain("münchen.example。")));
  check("canonicalDomain agrees across every spelling of one absolute name",
        b.publicSuffix.canonicalDomain("münchen.example。") ===
        b.publicSuffix.canonicalDomain("münchen.example.") &&
        b.publicSuffix.canonicalDomain("münchen.example.") ===
        b.publicSuffix.canonicalDomain("münchen.example"));
  // At most ONE root marker comes off, whichever spelling it used. Two of them
  // is an empty final label, and removing both would hand the caller a
  // different, real domain than the one they asked about — the same
  // repair-instead-of-refuse mistake the empty-label rule exists to stop.
  // Every MIXED spelling too. A doubled ASCII pair and a doubled U+3002 pair
  // are both caught by the pre-existing `..` check once converted, so testing
  // only those two proves nothing about the at-most-one-marker guard — the
  // guard is what catches an ASCII dot followed by a mapped marker, where the
  // first comes off before conversion and the second only appears after it.
  var doubledMarkers = [
    "example.com..", "example.com。。", "example.com．．", "example.com｡｡",
    "example.com.。", "example.com。.", "example.com.．", "example.com．.",
    "example.com。．", "example.com．。", "example.com.｡", "example.com｡.",
    "münchen.example..", "münchen.example。。", "münchen.example.。", "münchen.example。.",
  ];
  var admitted = doubledMarkers.filter(function (d) {
    return b.publicSuffix.canonicalDomain(d) !== "";
  });
  check("canonicalDomain refuses every spelling of a doubled root marker",
        admitted.length === 0,
        "admitted: " + admitted.map(function (d) {
          return JSON.stringify(d) + " -> " + JSON.stringify(b.publicSuffix.canonicalDomain(d));
        }).join(", "));

  // The absolute spelling of a maximum-length name is the same name. Measuring
  // the root marker as a character refused it in every absolute spelling while
  // accepting the relative one.
  var maxLabel = "a".repeat(63);
  var max253 = maxLabel + "." + maxLabel + "." + maxLabel + "." + "a".repeat(61);
  check("the max-length fixture is exactly 253 characters", max253.length === 253,
        "length=" + max253.length);
  var maxSpellings = [".", "。", "．", "｡"].filter(function (m) {
    return b.publicSuffix.canonicalDomain(max253 + m) !== max253;
  });
  check("canonicalDomain accepts a maximum-length name in every absolute spelling",
        maxSpellings.length === 0,
        "refused with: " + maxSpellings.map(function (m) {
          return JSON.stringify(m) + " -> " + JSON.stringify(b.publicSuffix.canonicalDomain(max253 + m));
        }).join(", "));
  check("canonicalDomain U-label and A-label converge",
        b.publicSuffix.canonicalDomain("bücher.de") === "xn--bcher-kva.de" &&
        b.publicSuffix.canonicalDomain("xn--bcher-kva.de") === "xn--bcher-kva.de");
  check("canonicalDomain fails closed to '' on an empty label",
        b.publicSuffix.canonicalDomain("a..b") === "");
  // domainToASCII silently TRUNCATES at a URL delimiter ("a.com/evil" -> "a.com"),
  // which would reduce a hostile host to a trusted prefix — must fail closed.
  check("canonicalDomain fails closed to '' on a URL delimiter (no prefix truncation)",
        b.publicSuffix.canonicalDomain("example.com/evil") === "" &&
        b.publicSuffix.canonicalDomain("example.com?x") === "" &&
        b.publicSuffix.canonicalDomain("example.com#frag") === "" &&
        b.publicSuffix.canonicalDomain("example.com\\evil") === "");
  check("canonicalDomain fails closed to '' on a control byte",
        b.publicSuffix.canonicalDomain("a\x00.com") === "");
  check("canonicalDomain fails closed to '' on a non-string",
        b.publicSuffix.canonicalDomain(123) === "" &&
        b.publicSuffix.canonicalDomain(null) === "");
}

// ONE definition of "is this a domain name", across the three primitives that
// answer it. b.publicSuffix owns the rule; b.network.dns and b.mail.dmarc route
// through it. They drifted apart exactly once — each removed a root marker of
// its own before delegating, so between them two came off and a name with an
// empty final label became a real, separately-owned one that the resolver then
// queried and cached, and that DMARC discovered a policy under.
//
// The invariant that catches that is not "each layer is correct" but "no layer
// accepts what the owner refuses" — and it has to actually DRIVE each layer.
// Checking only DNS would still pass while the mail layer regressed, which is
// precisely the cross-layer drift this exists to stop.
async function testDomainDefinitionAgreesAcrossPrimitives() {
  // EVERY rejection class canonicalDomain has, not just the one the last bug
  // came from. A fixture drawn from a single family passes while the layers
  // disagree about all the others — which is what happened: the root-marker
  // rows agreed while `example.com/evil`, `a\u0000.com` and `a b.com` were
  // refused here and encoded into DNS query labels over there.
  var HOSTILE = [
    // empty label / root marker
    "example.com..", "example.com。。", "example.com.。", "example.com。.",
    "example.com．．", "example.com｡｡", "münchen.example..", "münchen.example。。",
    "evil..example.com", ".example.com", "a..b",
    // URL-structural delimiters — domainToASCII TRUNCATES at these, so a name
    // carrying one can masquerade as a trusted prefix of itself
    "example.com/evil", "example.com?x", "example.com#f", "example.com\\x",
    "example.com:80", "user@example.com", "[example.com]",
    // characters domainToASCII itself refuses, which no hand-written list of
    // "bad characters" reliably reproduces — the reason the rule is asked of
    // canonicalDomain rather than mirrored
    // (a quote and braces are NOT here: domainToASCII permits them, so the
    // owner accepts them and there is nothing for the other layers to disagree
    // with. Putting them in would assert about the owner's rule rather than
    // about agreement, which is what this test is for.)
    "a%b.com", "a^b.com", "a|b.com", "a<b.com", "a>b.com",
    // control bytes and whitespace
    "a\u0000.com", "a b.com", "a\tb.com", "a\nb.com", "example.com",
    // over the RFC 1035 name ceiling. A 64-octet LABEL is deliberately absent:
    // canonicalDomain caps the whole name at 253 but says nothing about label
    // length, so it accepts one — the wire encoder is what refuses that, and
    // this invariant only claims that nothing accepts what the owner refuses.
    "a".repeat(250) + "." + "b".repeat(250) + ".com",
  ];
  var refused = HOSTILE.filter(function (h) { return b.publicSuffix.canonicalDomain(h) === ""; });
  check("the hostile fixture set is one b.publicSuffix actually refuses",
        refused.length === HOSTILE.length,
        "owner accepted: " + HOSTILE.filter(function (h) {
          return b.publicSuffix.canonicalDomain(h) !== "";
        }).join(", "));

  var dnsAdmitted = refused.filter(function (h) {
    try { b.network.dns._validateHostShape(h, "probe"); return true; }
    catch (_e) { return false; }
  });
  check("no b.network.dns entry point accepts a name b.publicSuffix refuses",
        dnsAdmitted.length === 0,
        "admitted: " + dnsAdmitted.map(function (h) { return JSON.stringify(h); }).join(", "));

  var mailAdmitted = [];
  for (var i = 0; i < refused.length; i += 1) {
    var accepted = true;
    try {
      await b.mail.dmarc.evaluate({
        from: "alice@" + refused[i],
        spf: { result: "pass", domain: "elsewhere.test" },
        dkim: [],
        dnsLookup: async function () { return null; },
      });
    } catch (e) {
      if (/dmarc-bad-from/.test(e.code || "")) accepted = false;
    }
    if (accepted) mailAdmitted.push(refused[i]);
  }
  check("b.mail.dmarc.evaluate accepts no Author Domain b.publicSuffix refuses",
        mailAdmitted.length === 0,
        "admitted: " + mailAdmitted.map(function (h) { return JSON.stringify(h); }).join(", "));
}

async function run() {
  testExactMatch();
  testInputItselfIsPublicSuffix();
  testWildcardRule();
  testWildcardOutranksShorterExactRule();
  testPslConformanceVectors();
  testPslConformanceDepartures();
  testExceptionRule();
  testIdn();
  testTrailingDot();
  testOrganizationalDomain();
  testIsPublicSuffix();
  testInvalidInput();
  testLookupSource();
  testCaseInsensitive();
  testCanonicalDomain();
  await testDomainDefinitionAgreesAcrossPrimitives();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
