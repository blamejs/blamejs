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

async function run() {
  testValidate();
  testSanitize();
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
