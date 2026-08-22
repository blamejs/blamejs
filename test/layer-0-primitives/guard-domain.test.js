// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function expectThrows(label, fn, codeMatch) {
  var threw = null;
  try { fn(); } catch (e) { threw = e; }
  check(label, !!threw && (threw.code || "") === codeMatch);
  return threw;
}

// Assert a validate result carries an issue of `kind` (and, when given, the
// exact `severity`). Drives the real `b.guardDomain.validate` consumer path.
function hasIssue(issues, kind, severity) {
  return issues.some(function (i) {
    return i.kind === kind && (severity === undefined || i.severity === severity);
  });
}

// Non-ASCII adversarial inputs are built via String.fromCharCode so the source
// file stays pure ASCII (no invisible codepoints to mis-copy or corrupt).
var CYRILLIC_HOMOGRAPH = String.fromCharCode(0x430) + "pple.com";      // Cyrillic + Latin pple
var NULL_BYTE_DOMAIN   = "exa" + String.fromCharCode(0) + "mple.com";   // C0 NUL
var BIDI_DOMAIN        = "exa" + String.fromCharCode(0x202E) + "mple.com"; // RLO override
var ZERO_WIDTH_DOMAIN  = "exa" + String.fromCharCode(0x200B) + "mple.com"; // zero-width space

function testSanitize() {
  // Benign: mixed-case FQDN with trailing dot. Safe transforms are ASCII
  // lowercasing + trailing-dot strip, so the allowlist comparison key is
  // canonical - neutralizing case / FQDN-marker mismatch.
  var canonical = b.guardDomain.sanitize("Example.Com.", { profile: "balanced" });
  check("guardDomain.sanitize lowercases + strips dot", canonical === "example.com");
  check("guardDomain.sanitize output neutralized",      canonical !== "Example.Com.");
  check("guardDomain.sanitize output revalidates ok",
    b.guardDomain.validate(canonical, { profile: "balanced" }).ok === true);

  // A clean host is returned unchanged.
  var same = b.guardDomain.sanitize("cdn.example.org", { profile: "strict" });
  check("guardDomain.sanitize clean unchanged",         same === "cdn.example.org");

  // Hostile: dotted-decimal IPv4 as a domain (CVE-2021-22931 DNS-rebinding
  // class) is REFUSED (thrown), never normalized into an allowlist key.
  var ipErr = expectThrows("guardDomain.sanitize IPv4 throws",
    function () { b.guardDomain.sanitize("192.168.1.1", { profile: "strict" }); },
    "domain.ipv4-as-domain");
  check("guardDomain.sanitize IPv4 GuardDomainError",
    ipErr instanceof b.guardDomain.GuardDomainError);

  // Hostile: mixed-script homograph label (Cyrillic + Latin) - a raw Unicode
  // IDN label is refused under strict; the spoof never round-trips to a
  // canonical form the framework would silently trust.
  var homoErr = expectThrows("guardDomain.sanitize homograph throws",
    function () { b.guardDomain.sanitize(CYRILLIC_HOMOGRAPH, { profile: "strict" }); },
    "domain.raw-unicode-label");
  check("guardDomain.sanitize homograph GuardDomainError",
    homoErr instanceof b.guardDomain.GuardDomainError);

  // Hostile: RFC 6761 special-use suffix (`.localhost`) - refused (thrown),
  // never normalized into a webhook/allowlist target routing to loopback.
  expectThrows("guardDomain.sanitize special-use throws",
    function () { b.guardDomain.sanitize("foo.localhost", { profile: "strict" }); },
    "domain.special-use");
}

// IPv4-as-domain across every parser-permissive numeric form (CVE-2021-22931
// DNS-rebinding class): octal segments, 0x-hex segments, long-decimal and
// long-hex without dots. Also pins the NON-IPv4 boundary cases that drive the
// false branches inside `_looksLikeIpv4Permissive`.
function testIpv4PermissiveForms() {
  var forms = [
    ["octal segments",   "0177.0.0.1"],
    ["0x-hex segments",  "0xC0.0xA8.0x01.0x01"],
    ["long-decimal",     "3232235777"],
    ["long-hex",         "0xC0A80101"],
  ];
  forms.forEach(function (f) {
    var rv = b.guardDomain.validate(f[1], { profile: "strict" });
    check("guardDomain.validate " + f[0] + " -> ipv4-as-domain refuse",
      rv.ok === false && hasIssue(rv.issues, "ipv4-as-domain", "high"));
  });

  // ipLiteralPolicy:"audit" downgrades the same detection to a warn (ok stays
  // true) - exercises the reject/warn severity fork on the IPv4 path.
  var au = b.guardDomain.validate("10.0.0.1",
    { profile: "strict", ipLiteralPolicy: "audit" });
  check("guardDomain.validate IPv4 audit -> warn, ok true",
    au.ok === true && hasIssue(au.issues, "ipv4-as-domain", "warn"));

  // ipLiteralPolicy:"allow" (permissive) lets the IPv4-shaped input through
  // with no ipv4 issue - the operator explicitly opted into raw IPs.
  var al = b.guardDomain.validate("3232235777", { profile: "permissive" });
  check("guardDomain.validate long-decimal permissive -> no ipv4 issue",
    hasIssue(al.issues, "ipv4-as-domain") === false);

  // Boundary: a short all-digit label (< 8 digits, no dots) is NOT long-decimal
  // IPv4 - it is a single-label domain instead (drives the `s.length >= 8`
  // false branch).
  var sn = b.guardDomain.validate("12345", { profile: "strict" });
  check("guardDomain.validate short numeric -> single-label, not ipv4",
    hasIssue(sn.issues, "ipv4-as-domain") === false &&
    hasIssue(sn.issues, "single-label", "high"));

  // Boundary: an alphanumeric single label (digit present, not a whole numeric
  // token, no dot) is not IPv4 - drives the dot-less early return inside
  // `_looksLikeIpv4Permissive`.
  var an = b.guardDomain.validate("host12345", { profile: "strict" });
  check("guardDomain.validate alphanumeric no-dot label -> not ipv4",
    hasIssue(an.issues, "ipv4-as-domain") === false &&
    hasIssue(an.issues, "single-label", "high"));

  // Boundary: three numeric segments (wrong arity) and four segments with a
  // non-numeric part both fail the permissive-IPv4 dotted loop and validate as
  // ordinary LDH domains.
  var p3 = b.guardDomain.validate("1.2.3", { profile: "strict" });
  check("guardDomain.validate 3 numeric segments -> not ipv4, ok",
    p3.ok === true && hasIssue(p3.issues, "ipv4-as-domain") === false);
  var p4 = b.guardDomain.validate("1.2.3.x", { profile: "strict" });
  check("guardDomain.validate 4 segments w/ non-numeric -> not ipv4, ok",
    p4.ok === true && hasIssue(p4.issues, "ipv4-as-domain") === false);
}

// IPv6 bracket literal bypasses DNS-name validation - refuse under strict,
// warn under audit, allow (early-return with no issue) under permissive.
function testIpv6BracketLiteral() {
  var rj = b.guardDomain.validate("[2001:db8::1]", { profile: "strict" });
  check("guardDomain.validate IPv6 literal strict -> refuse",
    rj.ok === false && hasIssue(rj.issues, "ipv6-literal", "high"));

  var au = b.guardDomain.validate("[::1]",
    { profile: "strict", ipLiteralPolicy: "audit" });
  check("guardDomain.validate IPv6 literal audit -> warn, ok",
    au.ok === true && hasIssue(au.issues, "ipv6-literal", "warn"));

  var al = b.guardDomain.validate("[::1]", { profile: "permissive" });
  check("guardDomain.validate IPv6 literal permissive -> no issue",
    al.ok === true && hasIssue(al.issues, "ipv6-literal") === false);
}

// RFC 6761 / IETF reserved special-use suffixes route to loopback / mDNS / Tor
// / LAN. Suffix-match (`.localhost`) and exact-match (`home.arpa`) both fire.
function testSpecialUseSuffix() {
  var suffix = b.guardDomain.validate("foo.localhost", { profile: "strict" });
  check("guardDomain.validate .localhost suffix strict -> refuse",
    suffix.ok === false && hasIssue(suffix.issues, "special-use", "high"));

  // Exact whole-name match (no leading label) - drives the `lower === su` arm.
  var exact = b.guardDomain.validate("home.arpa", { profile: "strict" });
  check("guardDomain.validate home.arpa exact -> special-use refuse",
    exact.ok === false && hasIssue(exact.issues, "special-use", "high"));

  var au = b.guardDomain.validate("foo.internal",
    { profile: "strict", specialUsePolicy: "audit" });
  check("guardDomain.validate special-use audit -> warn, ok",
    au.ok === true && hasIssue(au.issues, "special-use", "warn"));

  // specialUsePolicy:"allow" suppresses the suffix issue entirely.
  var al = b.guardDomain.validate("foo.localhost",
    { profile: "strict", specialUsePolicy: "allow" });
  check("guardDomain.validate special-use allow -> no issue",
    hasIssue(al.issues, "special-use") === false);
}

// Single-label / TLD-only, empty input, and empty-label refuse under strict;
// the whole-domain octet cap (RFC 1035 sec 2.3.4) short-circuits detection.
function testSingleLabelEmptyAndCap() {
  var single = b.guardDomain.validate("example", { profile: "strict" });
  check("guardDomain.validate single-label strict -> refuse",
    single.ok === false && hasIssue(single.issues, "single-label", "high"));

  var au = b.guardDomain.validate("intranet",
    { profile: "strict", singleLabelPolicy: "audit" });
  check("guardDomain.validate single-label audit -> warn, ok",
    au.ok === true && hasIssue(au.issues, "single-label", "warn"));

  // Bare `.` -> after trailing-dot strip the name is empty.
  var dot = b.guardDomain.validate(".", { profile: "strict" });
  check("guardDomain.validate bare dot -> empty refuse",
    dot.ok === false && hasIssue(dot.issues, "empty", "high"));

  // Consecutive dots produce a zero-length interior label.
  var emptyLabel = b.guardDomain.validate("foo..bar", { profile: "strict" });
  check("guardDomain.validate consecutive dots -> empty-label refuse",
    emptyLabel.ok === false && hasIssue(emptyLabel.issues, "empty-label", "high"));

  // Whole-FQDN octet cap: > 253 octets short-circuits at detectStringInput
  // (pre.done) with a domain-cap issue and no label parsing.
  var over = b.guardDomain.validate(("a".repeat(300)) + ".com", { profile: "strict" });
  check("guardDomain.validate >253 octets -> domain-cap refuse",
    over.ok === false && hasIssue(over.issues, "domain-cap", "high"));
  check("guardDomain.validate domain-cap is the only issue (short-circuit)",
    over.issues.length === 1);
}

// Per-label octet cap and wildcard label. Wildcard is refuse at every profile
// (never a user-input identifier); `wildcardPolicy:"allow"` is the escape hatch.
function testLabelCapAndWildcard() {
  var longLabel = ("a".repeat(64)) + ".example.com";   // 64 > 63 octet cap
  var lc = b.guardDomain.validate(longLabel, { profile: "strict" });
  check("guardDomain.validate 64-octet label -> label-cap refuse",
    lc.ok === false && hasIssue(lc.issues, "label-cap", "high"));

  var wild = b.guardDomain.validate("*.example.com", { profile: "strict" });
  check("guardDomain.validate wildcard label strict -> refuse",
    wild.ok === false && hasIssue(wild.issues, "wildcard", "high"));

  // Even permissive refuses wildcard; only an explicit allow opt suppresses it.
  var wildPerm = b.guardDomain.validate("*.example.com", { profile: "permissive" });
  check("guardDomain.validate wildcard permissive -> still refuse",
    wildPerm.ok === false && hasIssue(wildPerm.issues, "wildcard", "high"));

  var wildAllow = b.guardDomain.validate("*.example.com",
    { profile: "strict", wildcardPolicy: "allow" });
  check("guardDomain.validate wildcard allow -> no wildcard issue",
    hasIssue(wildAllow.issues, "wildcard") === false);
}

// RFC 8552 service-prefix labels (`_dmarc`) are never valid hostnames - refuse
// under strict/balanced, warn under audit, allow under permissive. A malformed
// underscore label (bare `_`) is a hard refusal regardless of policy.
function testUnderscoreLabels() {
  var svc = b.guardDomain.validate("_dmarc.example.com", { profile: "strict" });
  check("guardDomain.validate service label strict -> refuse",
    svc.ok === false && hasIssue(svc.issues, "underscore-label", "high"));

  var au = b.guardDomain.validate("_dmarc.example.com",
    { profile: "strict", underscorePolicy: "audit" });
  check("guardDomain.validate service label audit -> warn, ok",
    au.ok === true && hasIssue(au.issues, "underscore-label", "warn"));

  var perm = b.guardDomain.validate("_dmarc.example.com", { profile: "permissive" });
  check("guardDomain.validate service label permissive -> no issue",
    hasIssue(perm.issues, "underscore-label") === false);

  // `_` alone doesn't match the service-label grammar -> hard refusal.
  var bad = b.guardDomain.validate("_.example.com", { profile: "permissive" });
  check("guardDomain.validate malformed underscore -> refuse (any profile)",
    bad.ok === false && hasIssue(bad.issues, "underscore-malformed", "high"));
}

// IDN A-labels (`xn--`). Bare `xn--` (no payload) is malformed -> refuse. A real
// A-label is a homograph-spoofing class: refuse strict, warn balanced, allow
// permissive. A Punycode label that also violates LDH stacks both issues.
function testPunycodeLabels() {
  var bare = b.guardDomain.validate("xn--.example.com", { profile: "strict" });
  check("guardDomain.validate bare xn-- -> punycode-bare refuse",
    bare.ok === false && hasIssue(bare.issues, "punycode-bare", "high"));

  var strict = b.guardDomain.validate("xn--nxasmq6b.example.com", { profile: "strict" });
  check("guardDomain.validate A-label strict -> refuse",
    strict.ok === false && hasIssue(strict.issues, "punycode-label", "high"));

  var bal = b.guardDomain.validate("xn--nxasmq6b.example.com", { profile: "balanced" });
  check("guardDomain.validate A-label balanced -> warn, ok",
    bal.ok === true && hasIssue(bal.issues, "punycode-label", "warn"));

  var perm = b.guardDomain.validate("xn--nxasmq6b.example.com", { profile: "permissive" });
  check("guardDomain.validate A-label permissive -> no issue",
    hasIssue(perm.issues, "punycode-label") === false);

  // A Punycode-prefixed label carrying an underscore violates LDH too - the
  // A-label homograph issue AND the LDH violation both fire.
  var ldh = b.guardDomain.validate("xn--foo_bar.example.com", { profile: "strict" });
  check("guardDomain.validate A-label with LDH violation -> both issues",
    ldh.ok === false &&
    hasIssue(ldh.issues, "punycode-label", "high") &&
    hasIssue(ldh.issues, "ldh-violation", "high"));
}

// ASCII LDH grammar (RFC 952 / 1123) and the position 3-4 double-hyphen
// heuristic (a non-`xn--` `--` at the IDN-prefix position).
function testLdhAndDoubleHyphen() {
  var bad = b.guardDomain.validate("foo_bar.example.com", { profile: "strict" });
  check("guardDomain.validate underscore in ASCII label -> ldh-violation refuse",
    bad.ok === false && hasIssue(bad.issues, "ldh-violation", "high"));

  var au = b.guardDomain.validate("foo_bar.example.com",
    { profile: "strict", ldhPolicy: "audit" });
  check("guardDomain.validate LDH audit -> warn, ok",
    au.ok === true && hasIssue(au.issues, "ldh-violation", "warn"));

  // `ab--cd` is LDH-legal but carries `--` at positions 3-4 without `xn--`.
  var dh = b.guardDomain.validate("ab--cd.example.com", { profile: "strict" });
  check("guardDomain.validate positions 3-4 double-hyphen -> warn, ok",
    dh.ok === true && hasIssue(dh.issues, "double-hyphen", "warn"));
}

// Raw Unicode (non-ASCII) label handling at the audit severities - complements
// testSanitize's strict/reject path. A Cyrillic-Latin homograph mixes scripts.
function testRawUnicodeAndMixedScript() {
  var rv = b.guardDomain.validate(CYRILLIC_HOMOGRAPH,
    { profile: "strict", punycodePolicy: "audit", mixedScriptPolicy: "audit" });
  check("guardDomain.validate raw-unicode audit -> warn",
    hasIssue(rv.issues, "raw-unicode-label", "warn"));
  // mixedScriptPolicy:"audit" downgrades the homograph mix from critical to
  // high (still refuses - ok is false).
  check("guardDomain.validate mixed-script audit -> high, refuse",
    rv.ok === false && hasIssue(rv.issues, "mixed-script", "high"));
}

// DGA entropy heuristic: a long, high-entropy label is a C2 / domain-generation
// shape. Refuse strict, warn balanced. Low-entropy long labels and the
// operator-tunable minimum-label-length floor drive the negative branches.
function testDgaEntropy() {
  var hi = b.guardDomain.validate("x7q2m9k4p1z8w3.example.com", { profile: "strict" });
  check("guardDomain.validate high-entropy label strict -> dga refuse",
    hi.ok === false && hasIssue(hi.issues, "dga-entropy", "high"));

  var bal = b.guardDomain.validate("x7q2m9k4p1z8w3.example.com", { profile: "balanced" });
  check("guardDomain.validate high-entropy label balanced -> warn, ok",
    bal.ok === true && hasIssue(bal.issues, "dga-entropy", "warn"));

  // A long but low-entropy (repeated-char) label is below the threshold.
  var lo = b.guardDomain.validate("aaaaaaaaaaaaaa.example.com", { profile: "strict" });
  check("guardDomain.validate low-entropy long label -> no dga issue",
    lo.ok === true && hasIssue(lo.issues, "dga-entropy") === false);

  // dgaPolicy:"allow" (permissive) suppresses the heuristic even on a hostile
  // high-entropy label.
  var perm = b.guardDomain.validate("x7q2m9k4p1z8w3.example.com", { profile: "permissive" });
  check("guardDomain.validate high-entropy permissive -> no dga issue",
    hasIssue(perm.issues, "dga-entropy") === false);

  // dgaMinLabelLen:1 drives the entropy calc over every label including a
  // single-character one (whose entropy is defined as 0 -> below threshold).
  var tiny = b.guardDomain.validate("a.example.com",
    { profile: "strict", dgaMinLabelLen: 1, dgaPolicy: "reject" });
  check("guardDomain.validate 1-char label entropy=0 -> no dga issue",
    tiny.ok === true && hasIssue(tiny.issues, "dga-entropy") === false);
}

// Trailing-dot FQDN marker: normalized silently by default, but surfaced as an
// audit warn when the operator opts into trailingDotPolicy:"audit".
function testTrailingDotAudit() {
  var rv = b.guardDomain.validate("example.com.",
    { profile: "strict", trailingDotPolicy: "audit" });
  check("guardDomain.validate trailing-dot audit -> warn, ok",
    rv.ok === true && hasIssue(rv.issues, "trailing-dot", "warn"));

  // Default policy normalizes silently - no trailing-dot issue.
  var norm = b.guardDomain.validate("example.com.", { profile: "strict" });
  check("guardDomain.validate trailing-dot default -> normalized, no issue",
    norm.ok === true && hasIssue(norm.issues, "trailing-dot") === false);
}

// Codepoint threats (CVE-2021-42574 Trojan Source class). Null byte and BIDI
// override are universal-refuse (rejected even under permissive); a bare
// zero-width space is caught only by the raw-Unicode gate under strict. Non-
// string input is bad-input.
function testCharThreatsAndBadInput() {
  // Null byte refuses at every profile.
  var nul = b.guardDomain.validate(NULL_BYTE_DOMAIN, { profile: "permissive" });
  check("guardDomain.validate null byte -> refuse (universal)",
    nul.ok === false && hasIssue(nul.issues, "null-byte"));

  // BIDI override refuses at every profile.
  var bidi = b.guardDomain.validate(BIDI_DOMAIN, { profile: "permissive" });
  check("guardDomain.validate BIDI override -> refuse (universal)",
    bidi.ok === false && hasIssue(bidi.issues, "bidi-override"));

  // A bare zero-width space is a raw non-ASCII codepoint: refused under strict
  // as a raw-Unicode label.
  var zwStrict = b.guardDomain.validate(ZERO_WIDTH_DOMAIN, { profile: "strict" });
  check("guardDomain.validate zero-width strict -> refuse (raw-unicode)",
    zwStrict.ok === false && hasIssue(zwStrict.issues, "raw-unicode-label"));
  // Zero-width refuses at EVERY profile, like the bidi override above it: all
  // three declare `zeroWidthPolicy: "reject"`, because an invisible character
  // in a domain label is a spoofing vector whatever else the profile permits.
  // Permissive allows raw Unicode LABELS — it does not allow characters that
  // render as nothing.
  //
  // This previously asserted the opposite and said it documented current
  // behavior. It documented a fail-open: the shared scan was gated on an
  // optional argument its caller did not pass, so the declared policy was
  // never applied and permissive served the character.
  var zwPerm = b.guardDomain.validate(ZERO_WIDTH_DOMAIN, { profile: "permissive" });
  check("guardDomain.validate zero-width permissive -> refuse (universal)",
    zwPerm.ok === false && hasIssue(zwPerm.issues, "zero-width"));

  var non = b.guardDomain.validate(12345, { profile: "strict" });
  check("guardDomain.validate non-string -> bad-input refuse",
    non.ok === false && hasIssue(non.issues, "bad-input", "high"));
}

// The gate consumer path: `gate({...}).check(ctx)` reading ctx.identifier OR
// ctx.domain, returning the serve/refuse decision that flows through the same
// detector as validate.
async function testGateConsumerPath() {
  var g = b.guardDomain.gate({ profile: "strict" });

  var ipv4 = await g.check({ identifier: "192.168.1.1" });
  check("guardDomain.gate ctx.identifier IPv4 -> refuse",
    ipv4.ok === false && ipv4.action === "refuse" &&
    hasIssue(ipv4.issues, "ipv4-as-domain"));

  var clean = await g.check({ identifier: "cdn.example.org" });
  check("guardDomain.gate ctx.identifier clean -> serve",
    clean.ok === true && clean.action === "serve");

  // The gate reads ctx.domain as a fallback field.
  var special = await g.check({ domain: "foo.localhost" });
  check("guardDomain.gate ctx.domain special-use -> refuse",
    special.ok === false && special.action === "refuse" &&
    hasIssue(special.issues, "special-use"));
}

// The label shapes are character walks. Each is compared against the pattern
// it replaced, over a corpus of the names this guard exists to classify.
function testLabelShapesAgreeWithThePatternsTheyReplaced() {
  var LDH_LABEL_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/;
  var SERVICE_LABEL_RE = /^_[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/;
  var PUNYCODE_LABEL_RE = /^xn--/i;
  var BARE_XN_RE = /^xn--$/i;
  var IPV6_BRACKET_RE = /^\[[0-9a-fA-F:.]+\]$/;
  var IPV4_NUMERIC_SEGMENT_RE = /^(?:0[xX][0-9a-fA-F]+|[0-9]+)$/;
  function oldLooksLikeIpv4(s) {
    if (!/[0-9]/.test(s)) return false;
    if (IPV4_NUMERIC_SEGMENT_RE.test(s)) {
      return s.length > 0 && !/^[0-9]+$/.test(s) ? true : s.length >= 8;
    }
    if (s.indexOf(".") === -1) return false;
    var parts = s.split(".");
    if (parts.length !== 4) return false;
    for (var i = 0; i < parts.length; i += 1) {
      if (!IPV4_NUMERIC_SEGMENT_RE.test(parts[i])) return false;
    }
    return true;
  }

  var LABELS = [
    "", "a", "ab", "a-b", "-a", "a-", "-", "--", "a--b", "1", "1a", "a1",
    "example", "EXAMPLE", "xn--", "XN--", "xn--a", "xn--80ak6aa92e", "xnn--a",
    "x-n--a", "_dmarc", "_", "_-", "_a", "_a-b", "_a-", "a_b", "*", "**", "*a",
    "a.b", "caf" + String.fromCharCode(0xE9), "a b", "a.b.c", "a_",
  ];
  var ldhDiffs = [], svcDiffs = [], punyDiffs = [], bareDiffs = [];
  LABELS.forEach(function (l) {
    var api = b.guardDomain._shapesForTest;
    if (LDH_LABEL_RE.test(l) !== api.isLdhLabel(l)) ldhDiffs.push(JSON.stringify(l));
    if (SERVICE_LABEL_RE.test(l) !== api.isServiceLabel(l)) svcDiffs.push(JSON.stringify(l));
    if (PUNYCODE_LABEL_RE.test(l) !== api.hasPunycodePrefix(l)) punyDiffs.push(JSON.stringify(l));
    if (BARE_XN_RE.test(l) !== api.isBarePunycodePrefix(l)) bareDiffs.push(JSON.stringify(l));
  });
  check("the LDH-label walk agrees with the pattern it replaced",
        ldhDiffs.length === 0, ldhDiffs.slice(0, 4).join(" | "));
  check("the service-label walk agrees with the pattern it replaced",
        svcDiffs.length === 0, svcDiffs.slice(0, 4).join(" | "));
  check("the punycode-prefix walk agrees with the pattern it replaced",
        punyDiffs.length === 0, punyDiffs.slice(0, 4).join(" | "));
  check("the bare-xn-- walk agrees with the pattern it replaced",
        bareDiffs.length === 0, bareDiffs.slice(0, 4).join(" | "));

  var HOSTS = [
    "", "[::1]", "[fe80::1%25eth0]", "[]", "[g::1]", "[1.2.3.4]", "::1",
    "192.168.1.1", "0177.0.0.1", "0xC0.0xA8.0x01.0x01", "3232235777",
    "0xC0A80101", "1234567", "12345678", "1.2.3", "1.2.3.4.5", "a.b.c.d",
    "0x", "0xZZ", "00.00.00.00", "example.com", "9.9.9.9",
  ];
  var v6Diffs = [], v4Diffs = [];
  HOSTS.forEach(function (h) {
    var api = b.guardDomain._shapesForTest;
    if (IPV6_BRACKET_RE.test(h) !== api.isIpv6BracketLiteral(h)) v6Diffs.push(JSON.stringify(h));
    if (oldLooksLikeIpv4(h) !== api.looksLikeIpv4Permissive(h)) v4Diffs.push(JSON.stringify(h));
  });
  check("the IPv6-bracket walk agrees with the pattern it replaced",
        v6Diffs.length === 0, v6Diffs.slice(0, 4).join(" | "));
  check("the permissive-IPv4 walk agrees with the code it replaced",
        v4Diffs.length === 0, v4Diffs.slice(0, 4).join(" | "));

  // A trailing run of dots no longer hides a special-use name: a resolver
  // that tolerates `localhost..` resolves it as `localhost`.
  var doubled = b.guardDomain.validate("localhost..", { profile: "strict" }).issues
    .some(function (i) { return i.kind === "special-use"; });
  check("a special-use name with a doubled trailing dot is still flagged", doubled);
}

// Each policy is a CONFIG-TIME entry point, so a value outside its vocabulary
// is a boot error rather than a runtime surprise. Read leniently, a typo takes
// whichever branch is not the strict one: `punycodePolicy: "rejct"` is not
// "allow", so the check runs, and it is not "reject" either, so the finding
// drops to a warning — the operator asked to refuse punycode and silently got
// an audit.
//
// The vocabularies are the guard's OWN documented ones. Note that
// trailingDotPolicy takes `normalize` rather than `allow`, and does NOT take
// `audit-only`: its code compares `=== "audit"` exactly, so the synonym would
// not be honoured there. Reading each opt is what surfaces that; a shared list
// would have advertised it.
function testPolicyVocabularyIsEnforced() {
  var THREE_WAY = ["reject", "audit", "audit-only", "allow"];
  var LEGAL = {
    ldhPolicy:         THREE_WAY, punycodePolicy:    THREE_WAY,
    mixedScriptPolicy: THREE_WAY, specialUsePolicy:  THREE_WAY,
    ipLiteralPolicy:   THREE_WAY, wildcardPolicy:    THREE_WAY,
    singleLabelPolicy: THREE_WAY, underscorePolicy:  THREE_WAY,
    dgaPolicy:         THREE_WAY,
    trailingDotPolicy: ["normalize", "audit", "reject"],
  };
  helpers.assertPolicyVocabulary(b.guardDomain, LEGAL, { label: "domain", sample: "example.com" });
}

async function run() {
  testLabelShapesAgreeWithThePatternsTheyReplaced();
  testSanitize();
  testIpv4PermissiveForms();
  testIpv6BracketLiteral();
  testSpecialUseSuffix();
  testSingleLabelEmptyAndCap();
  testLabelCapAndWildcard();
  testUnderscoreLabels();
  testPunycodeLabels();
  testLdhAndDoubleHyphen();
  testRawUnicodeAndMixedScript();
  testDgaEntropy();
  testTrailingDotAudit();
  testCharThreatsAndBadInput();
  testPolicyVocabularyIsEnforced();
  await testGateConsumerPath();
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
