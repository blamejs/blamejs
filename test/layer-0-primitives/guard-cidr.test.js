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

function _kinds(rv) {
  return rv.issues.map(function (i) { return i.kind; });
}

function testValidate() {
  // Benign: a public /24 with zero host bits is clean under strict.
  var okRv = b.guardCidr.validate("8.8.8.0/24", { profile: "strict" });
  check("guardCidr.validate benign ok",             okRv.ok === true);
  check("guardCidr.validate benign no issues",      okRv.issues.length === 0);

  // Hostile: RFC 1918 private range — refused as reserved-range under strict.
  var reserved = b.guardCidr.validate("10.0.0.0/8", { profile: "strict" });
  check("guardCidr.validate reserved refused",      reserved.ok === false);
  check("guardCidr.validate reserved-range kind",
    _kinds(reserved).indexOf("reserved-range") !== -1);

  // Mask out of range for IPv4 (>32) — mask-cap high.
  var maskCap = b.guardCidr.validate("8.8.8.0/40", { profile: "strict" });
  check("guardCidr.validate mask-cap refused",      maskCap.ok === false);
  check("guardCidr.validate mask-cap kind",
    _kinds(maskCap).indexOf("mask-cap") !== -1);

  // Not a valid IPv4 dotted-decimal or IPv6 hex-group form — address-shape.
  var badShape = b.guardCidr.validate("not.an.ip/24", { profile: "strict" });
  check("guardCidr.validate address-shape refused", badShape.ok === false);
  check("guardCidr.validate address-shape kind",
    _kinds(badShape).indexOf("address-shape") !== -1);

  // RFC 4291 §2.2 — a "::" adjacent to a full 8 explicit groups compresses zero
  // groups and is malformed IPv6 (net.isIP rejects it). The parser must not
  // admit the non-canonical spelling into CIDR matching as a valid address.
  ["1:2:3:4:5:6:7:8::/64", "::1:2:3:4:5:6:7:8/64", "1:2:3:4:5:6:7::8/64"]
    .forEach(function (c) {
      var zc = b.guardCidr.validate(c, { profile: "strict" });
      check("guardCidr.validate rejects zero-group '::' " + c, zc.ok === false);
      check("guardCidr.validate zero-group '::' is address-shape " + c,
        _kinds(zc).indexOf("address-shape") !== -1);
    });

  // Host bits set under the mask — network-misaligned (common typo class).
  var misaligned = b.guardCidr.validate("10.0.0.1/24", { profile: "strict" });
  check("guardCidr.validate misaligned refused",    misaligned.ok === false);
  check("guardCidr.validate network-misaligned kind",
    _kinds(misaligned).indexOf("network-misaligned") !== -1);

  // IPv4-mapped IPv6 — dual-stack allowlist confusion (CVE-2021-22931 class).
  var mapped = b.guardCidr.validate("::ffff:0:0/96", { profile: "strict" });
  check("guardCidr.validate ipv4-mapped refused",   mapped.ok === false);
  check("guardCidr.validate ipv4-mapped-ipv6 kind",
    _kinds(mapped).indexOf("ipv4-mapped-ipv6") !== -1);

  // Bare IP with no /mask — refused under strict (reject-bare-ip).
  var bare = b.guardCidr.validate("8.8.8.8", { profile: "strict" });
  check("guardCidr.validate bare-ip refused",       bare.ok === false);
  check("guardCidr.validate bare-ip kind",
    _kinds(bare).indexOf("bare-ip") !== -1);
}

function testSanitize() {
  // Benign IPv6 with uppercase hex groups — permissive allows the
  // documentation range; sanitize lowercases the hex so a case-varying
  // allowlist key can't slip a duplicate past a case-sensitive matcher.
  var lowered = b.guardCidr.sanitize("2001:DB8::/32", { profile: "permissive" });
  check("guardCidr.sanitize lowercases IPv6",       lowered === "2001:db8::/32");
  check("guardCidr.sanitize output neutralized",    lowered !== "2001:DB8::/32");
  check("guardCidr.sanitize output revalidates ok",
    b.guardCidr.validate(lowered, { profile: "permissive" }).ok === true);

  // IPv4 has no canonical casing — returned unchanged when clean.
  var v4 = b.guardCidr.sanitize("8.8.8.0/24", { profile: "strict" });
  check("guardCidr.sanitize IPv4 unchanged",        v4 === "8.8.8.0/24");

  // Hostile: reserved private range REFUSED (thrown), never returned — an
  // allowlist gate must not silently normalize a reserved range into place.
  var err = expectThrows("guardCidr.sanitize reserved throws",
    function () { b.guardCidr.sanitize("10.0.0.0/8", { profile: "strict" }); },
    "cidr.reserved-range");
  check("guardCidr.sanitize reserved GuardCidrError",
    err instanceof b.guardCidr.GuardCidrError);
}

function testIpv6ReservedNibbleMisaligned() {
  // IPv6 reserved-range membership is a bit-prefix relation, not a hex-nibble
  // one. ULA fc00::/7 (7 bits) and link-local fe80::/10 (10 bits) do not fall
  // on a 4-bit nibble boundary, so a hex-string startsWith("fc") / ("fe8")
  // match silently misses every reserved address whose partial nibble differs
  // — most importantly fd00::/8, the HALF of fc00::/7 that real deployments
  // actually assign (RFC 4193 L=1). Under strict, reservedRangesPolicy is
  // "reject", so a missed reserved range fails OPEN: a private/link-local
  // range validates as clean and can be added to an allowlist as if public.
  var strict = { profile: "strict" };

  // fc00::/7 ULA — BOTH halves must be caught. fd00::/8 is the assigned one.
  ["fc00::/8", "fd00::/8", "fdab:cd12::/32"].forEach(function (c) {
    var rv = b.guardCidr.validate(c, strict);
    check("guardCidr ULA " + c + " refused", rv.ok === false);
    check("guardCidr ULA " + c + " reserved-range kind",
      _kinds(rv).indexOf("reserved-range") !== -1);
  });

  // fe80::/10 link-local — the whole /10 must be caught, not just fe8x.
  ["fe80::/16", "fe90::/16", "fea0::/16", "feb0::/16"].forEach(function (c) {
    var rv = b.guardCidr.validate(c, strict);
    check("guardCidr link-local " + c + " refused", rv.ok === false);
    check("guardCidr link-local " + c + " reserved-range kind",
      _kinds(rv).indexOf("reserved-range") !== -1);
  });

  // Regression — the fix must not OVER-match. fec0::/10 (deprecated site-local)
  // is NOT in the reserved table and shares only the fe8x visual prefix's
  // sibling nibble; it must stay clean, as must genuine public space.
  ["fec0::/16", "2606:4700::/32", "2001:4860::/32"].forEach(function (c) {
    var rv = b.guardCidr.validate(c, strict);
    check("guardCidr public/site-local " + c + " clean", rv.ok === true);
  });

  // Regression — nibble-aligned reserved prefixes stay caught.
  ["ff02::1/128", "2001:db8::/32", "::1/128"].forEach(function (c) {
    var rv = b.guardCidr.validate(c, strict);
    check("guardCidr aligned-reserved " + c + " refused", rv.ok === false);
    check("guardCidr aligned-reserved " + c + " reserved-range kind",
      _kinds(rv).indexOf("reserved-range") !== -1);
  });
}

// Each policy is a CONFIG-TIME entry point, so a value outside its vocabulary
// is a boot error rather than a runtime surprise. Read leniently, a typo takes
// whichever branch is not the strict one: `reservedRangesPolicy: "rejct"` is
// not "allow", so the check runs, and it is not "reject" either, so the finding
// drops to a warning — the operator asked to refuse a reserved range and
// silently got an audit instead.
//
// The vocabularies are the ones the code compares against, confirmed against
// what the shipped profiles select. requireMaskPolicy carries its own spelling
// set because the answer is about the mask, not a threat disposition.
function testPolicyVocabularyIsEnforced() {
  var LEGAL = {
    networkAlignmentPolicy: ["allow", "audit", "audit-only", "reject"],
    reservedRangesPolicy:   ["allow", "audit", "audit-only", "reject"],
    ipv4MappedIpv6Policy:   ["allow", "audit", "audit-only", "reject"],
    requireMaskPolicy:      ["allow-bare-ip", "audit-bare-ip", "reject-bare-ip"],
  };
  helpers.assertPolicyVocabulary(b.guardCidr, LEGAL, { label: "cidr", sample: "8.8.8.0/24" });
}

// RFC 4291 section 2.2 form 3: the low 32 bits of an IPv6 address may be
// written as dotted-decimal IPv4 (`::ffff:192.0.2.1`, `64:ff9b::192.0.2.1`).
// Each dotted form must produce exactly the findings its all-hex spelling
// produces, under every profile, and a dotted tail that is not a strict
// IPv4 address in the last 32 bits stays an address-shape refusal.
function testIpv6DottedIpv4Tail() {
  var PAIRS = [
    ["::ffff:192.0.2.1/128",        "::ffff:c000:201/128"],
    ["::FFFF:8.8.8.8/128",          "::ffff:808:808/128"],
    ["::ffff:0.0.0.0/96",           "::ffff:0:0/96"],
    ["::ffff:255.255.255.255/128",  "::ffff:ffff:ffff/128"],
    ["64:ff9b::192.0.2.1/128",      "64:ff9b::c000:201/128"],
    ["64:ff9b::0.0.0.0/96",         "64:ff9b::/96"],
    ["64:ff9b::192.0.2.1/96",       "64:ff9b::c000:201/96"],
    ["1:2:3:4:5:6:192.0.2.1/128",   "1:2:3:4:5:6:c000:201/128"],
    ["1:2:3:4:5::192.0.2.1/128",    "1:2:3:4:5::c000:201/128"],
    ["::192.0.2.1/128",             "::c000:201/128"],
    ["::ffff:8.8.8.8",              "::ffff:808:808"],
  ];
  ["strict", "balanced", "permissive"].forEach(function (profile) {
    PAIRS.forEach(function (p) {
      var dotted = b.guardCidr.validate(p[0], { profile: profile });
      var hex    = b.guardCidr.validate(p[1], { profile: profile });
      check("guardCidr.validate " + p[0] + " (" + profile + ") is not address-shape",
        _kinds(dotted).indexOf("address-shape") === -1, JSON.stringify(dotted.issues));
      check("guardCidr.validate " + p[0] + " (" + profile + ") matches " + p[1],
        JSON.stringify(_kinds(dotted)) === JSON.stringify(_kinds(hex)) && dotted.ok === hex.ok,
        JSON.stringify(_kinds(dotted)) + " vs " + JSON.stringify(_kinds(hex)));
    });
  });
  var mappedStrict = b.guardCidr.validate("::ffff:192.0.2.1/128", { profile: "strict" });
  check("guardCidr.validate ::ffff:192.0.2.1 is ipv4-mapped-ipv6 under strict",
    mappedStrict.ok === false && _kinds(mappedStrict).indexOf("ipv4-mapped-ipv6") !== -1);
  var mappedBalanced = b.guardCidr.validate("::ffff:192.0.2.1/128", { profile: "balanced" });
  check("guardCidr.validate ::ffff:192.0.2.1 audits ipv4-mapped-ipv6 under balanced",
    mappedBalanced.issues.some(function (i) { return i.kind === "ipv4-mapped-ipv6" && i.severity === "warn"; }));
  var publicPermissive = b.guardCidr.validate("64:ff9b::8.8.8.8/128", { profile: "permissive" });
  check("guardCidr.validate 64:ff9b::8.8.8.8/128 is clean under permissive",
    publicPermissive.ok === true && publicPermissive.issues.length === 0, JSON.stringify(publicPermissive.issues));

  [
    "::ffff:192.0.2.256/128", "::ffff:192.0.2/128", "::ffff:192.0.2.1.5/128",
    "::ffff:01.2.3.4/128", "::ffff:0x7f.0.0.1/128", "::ffff:192.0.2./128",
    "::ffff:.192.0.2.1/128", "::ffff:192..0.2/128", "::ffff:+1.2.3.4/128",
    "::ffff: 192.0.2.1/128", "::ffff:192.0.2.1%eth0/128",
    "192.0.2.1::/128", "::192.0.2.1:ffff/128", "1:192.0.2.1::/128",
    "1:2:3:4:5:6:7:192.0.2.1/128", "1:2:3:4:5:6::192.0.2.1/128",
    "1:2:3:4:5:192.0.2.1/128", ":ffff:192.0.2.1/128", "ffff:192.0.2.1/128",
    "::ffff:192.0.2.1:/128", "::ffff:192.0.2.1::/128", "::1.2.3.4.5.6.7.8/128",
    "::ffff:1.2.3.4" + "\u0000" + "/128",
  ].forEach(function (c) {
    var rv = b.guardCidr.validate(c, { profile: "permissive" });
    check("guardCidr.validate refuses " + JSON.stringify(c), rv.ok === false, JSON.stringify(rv.issues));
  });
  [
    "::ffff:192.0.2.256/128", "::ffff:01.2.3.4/128", "1:2:3:4:5:6:7:192.0.2.1/128",
    "::192.0.2.1:ffff/128", "1:2:3:4:5:6::192.0.2.1/128", "::ffff:192.0.2.1%eth0/128",
  ].forEach(function (c) {
    var rv = b.guardCidr.validate(c, { profile: "permissive" });
    check("guardCidr.validate " + c + " is address-shape",
      _kinds(rv).indexOf("address-shape") !== -1, JSON.stringify(rv.issues));
  });
  var cap = b.guardCidr.validate("::ffff:192.0.2.1/129", { profile: "permissive" });
  check("guardCidr.validate ::ffff:192.0.2.1/129 is mask-cap against the IPv6 maximum",
    _kinds(cap).indexOf("mask-cap") !== -1, JSON.stringify(cap.issues));

  var lowered = b.guardCidr.sanitize("::FFFF:8.8.8.8/128", { profile: "permissive" });
  check("guardCidr.sanitize lowercases the hex groups of a dotted-tail address",
    lowered === "::ffff:8.8.8.8/128", lowered);
}

// An address in the NAT64 well-known prefix 64:ff9b::/96 (RFC 6052) reaches
// the IPv4 address in its low 32 bits through a translator, so a reserved
// IPv4 address there is a reserved destination, in either spelling. RFC 6052
// section 3.1 forbids the well-known prefix for non-global IPv4 addresses.
// The local-use prefix 64:ff9b:1::/48 (RFC 8215) is not globally reachable.
function testNat64EmbeddedReserved() {
  [
    "64:ff9b::7f00:1/128", "64:ff9b::127.0.0.1/128", "64:ff9b::10.0.0.0/104",
    "64:ff9b::a9fe:a9fe/128", "64:ff9b::169.254.169.254/128", "64:ff9b::192.168.1.0/120",
    "64:ff9b:1::/48", "64:ff9b:1:2::/64",
  ].forEach(function (c) {
    var strict = b.guardCidr.validate(c, { profile: "strict" });
    check("guardCidr.validate " + c + " is reserved-range under strict",
      strict.ok === false && _kinds(strict).indexOf("reserved-range") !== -1, JSON.stringify(strict.issues));
    var balanced = b.guardCidr.validate(c, { profile: "balanced" });
    check("guardCidr.validate " + c + " audits reserved-range under balanced",
      balanced.issues.some(function (i) { return i.kind === "reserved-range" && i.severity === "warn"; }),
      JSON.stringify(balanced.issues));
    var permissive = b.guardCidr.validate(c, { profile: "permissive" });
    check("guardCidr.validate " + c + " is allowed under permissive", permissive.ok === true,
      JSON.stringify(permissive.issues));
  });
  var nat64Loop = b.guardCidr.validate("64:ff9b::127.0.0.1/128", { profile: "strict" });
  check("the reserved-range finding for 64:ff9b::127.0.0.1 names the embedded range",
    nat64Loop.issues.some(function (i) { return i.kind === "reserved-range" && i.snippet.indexOf("nat64:loopback") !== -1; }),
    JSON.stringify(nat64Loop.issues));
  // Controls: a public IPv4 behind the prefix, the whole /96, and a /96 under
  // a different prefix are not reserved.
  ["64:ff9b::808:808/128", "64:ff9b::8.8.8.0/120", "64:ff9b::/96", "2606:4700::7f00:1/128"].forEach(function (c) {
    var rv = b.guardCidr.validate(c, { profile: "strict" });
    check("guardCidr.validate " + c + " is clean under strict", rv.ok === true, JSON.stringify(rv.issues));
  });
}

// The deprecated IPv4-compatible block ::/96 (RFC 4291 section 2.5.5.1) and
// the SIIT IPv4-translated block ::ffff:0:0:0/96 (RFC 2765) carry an IPv4
// address in their low 32 bits. Each block is reserved, and a CIDR of /96
// or longer under it has the embedded IPv4 address checked against the IPv4
// ranges, in the dotted and the all-hex spelling. ::/128 and ::1/128 keep
// their own labels and are not reported as IPv4-compatible.
function testIpv4CompatibleAndTranslatedReserved() {
  [
    ["::127.0.0.1/128",          "ipv4-compatible:loopback"],
    ["::7f00:1/128",             "ipv4-compatible:loopback"],
    ["::10.0.0.0/104",           "ipv4-compatible:rfc1918-private-10"],
    ["::8.8.8.8/128",            "ipv4-compatible-deprecated"],
    ["::/96",                    "ipv4-compatible-deprecated"],
    ["::ffff:0:127.0.0.1/128",   "ipv4-translated:loopback"],
    ["::ffff:0:7f00:1/128",      "ipv4-translated:loopback"],
    ["::ffff:0:169.254.169.254/128", "ipv4-translated:link-local"],
    ["::ffff:0:8.8.8.8/128",     "ipv4-translated"],
    ["::ffff:0:0:0/96",          "ipv4-translated"],
  ].forEach(function (row) {
    var strict = b.guardCidr.validate(row[0], { profile: "strict" });
    check("guardCidr.validate " + row[0] + " is reserved-range under strict",
      strict.ok === false && _kinds(strict).indexOf("reserved-range") !== -1, JSON.stringify(strict.issues));
    check("guardCidr.validate " + row[0] + " names " + row[1],
      strict.issues.some(function (i) { return i.kind === "reserved-range" && i.snippet.indexOf(row[1]) !== -1; }),
      JSON.stringify(strict.issues));
    var balanced = b.guardCidr.validate(row[0], { profile: "balanced" });
    check("guardCidr.validate " + row[0] + " audits reserved-range under balanced",
      balanced.issues.some(function (i) { return i.kind === "reserved-range" && i.severity === "warn"; }),
      JSON.stringify(balanced.issues));
    var permissive = b.guardCidr.validate(row[0], { profile: "permissive" });
    check("guardCidr.validate " + row[0] + " is allowed under permissive", permissive.ok === true,
      JSON.stringify(permissive.issues));
  });
  [["::/128", "unspecified"], ["::1/128", "loopback"]].forEach(function (row) {
    var rv = b.guardCidr.validate(row[0], { profile: "strict" });
    var snippet = rv.issues.filter(function (i) { return i.kind === "reserved-range"; })
      .map(function (i) { return i.snippet; }).join(" | ");
    check("guardCidr.validate " + row[0] + " is reported as " + row[1] + " only",
      snippet === "cidr falls inside reserved range(s): " + row[1], snippet);
  });
  // ::/127 holds only :: and ::1, so it carries their labels. ::2/127 holds
  // ::2 and ::3, two IPv4-compatible addresses whose embedded IPv4 is in 0/8.
  [["::/127", "loopback, unspecified"],
   ["::2/127", "ipv4-compatible-deprecated, ipv4-compatible:this-network"]].forEach(function (row) {
    var rv = b.guardCidr.validate(row[0], { profile: "strict" });
    var snippet = rv.issues.filter(function (i) { return i.kind === "reserved-range"; })
      .map(function (i) { return i.snippet; }).join(" | ");
    check("guardCidr.validate " + row[0] + " is refused under strict", rv.ok === false, JSON.stringify(rv.issues));
    check("guardCidr.validate " + row[0] + " is reported as " + row[1],
      snippet === "cidr falls inside reserved range(s): " + row[1], snippet);
  });
  // Controls: an address next to each block is not reported under it.
  ["::1:0:0/96", "::fffe:0:0/96", "1::127.0.0.1/128"].forEach(function (c) {
    var rv = b.guardCidr.validate(c, { profile: "strict" });
    check("guardCidr.validate " + c + " is not ipv4-compatible or ipv4-translated",
      !rv.issues.some(function (i) { return /ipv4-compatible|ipv4-translated/.test(i.snippet); }),
      JSON.stringify(rv.issues));
  });
}

// Every block the IANA special-purpose registries mark not globally reachable
// is reported as reserved under strict; the globally reachable assignments
// inside or next to them stay clean.
// IPv4: https://www.iana.org/assignments/iana-ipv4-special-registry/
// IPv6: https://www.iana.org/assignments/iana-ipv6-special-registry/
function testIanaSpecialPurposeBlocks() {
  var reserved = [
    ["192.0.0.0/29",       "ipv4-service-continuity"],
    ["192.0.0.8/32",       "ipv4-dummy"],
    ["192.0.0.170/31",     "nat64-dns64-discovery"],
    ["192.0.0.171/32",     "nat64-dns64-discovery"],
    ["192.88.99.0/24",     "deprecated-6to4-relay"],
    ["192.88.99.2/32",     "deprecated-6to4-relay"],
    ["100::/64",           "discard-only"],
    ["100::1/128",         "discard-only"],
    ["100:0:0:1::/64",     "dummy-prefix"],
    ["2001:2::/48",        "benchmarking"],
    ["2001:10::/28",       "deprecated-orchid"],
    ["3fff::/20",          "documentation-3fff"],
    ["3fff:fff::1/128",    "documentation-3fff"],
    ["5f00::/16",          "srv6-sid"],
  ];
  reserved.forEach(function (row) {
    var rv = b.guardCidr.validate(row[0], { profile: "strict" });
    check("guardCidr.validate " + row[0] + " is reserved under strict",
      rv.ok === false && _kinds(rv).indexOf("reserved-range") !== -1, JSON.stringify(rv.issues));
    check("guardCidr.validate " + row[0] + " names " + row[1],
      rv.issues.some(function (i) { return i.kind === "reserved-range" && i.snippet.indexOf(row[1]) !== -1; }),
      JSON.stringify(rv.issues));
  });
  var global = [
    "192.0.0.9/32", "192.0.0.10/32", "192.31.196.0/24", "192.52.193.0/24", "192.175.48.0/24",
    "2001:1::1/128", "2001:3::/32", "2001:4:112::/48", "2001:20::/28", "2001:30::/28",
    "2620:4f:8000::/48", "64:ff9b::/96", "3ffe::/16", "5f01::/16", "101::/64",
  ];
  global.forEach(function (c) {
    var rv = b.guardCidr.validate(c, { profile: "strict" });
    check("guardCidr.validate " + c + " (globally reachable) is clean under strict",
      rv.ok === true, JSON.stringify(rv.issues));
  });
}

async function run() {
  testValidate();
  testIanaSpecialPurposeBlocks();
  testNat64EmbeddedReserved();
  testIpv4CompatibleAndTranslatedReserved();
  testSanitize();
  testIpv6ReservedNibbleMisaligned();
  testIpv6DottedIpv4Tail();
  testPolicyVocabularyIsEnforced();
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
