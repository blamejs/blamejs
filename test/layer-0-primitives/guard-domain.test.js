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

function testSanitize() {
  // Benign: mixed-case FQDN with trailing dot. Safe transforms are ASCII
  // lowercasing + trailing-dot strip, so the allowlist comparison key is
  // canonical — neutralizing case / FQDN-marker mismatch.
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

  // Hostile: mixed-script homograph label (Cyrillic `а` + Latin) — a raw
  // Unicode IDN label is refused under strict; the spoof never round-trips
  // to a canonical form the framework would silently trust.
  var homoErr = expectThrows("guardDomain.sanitize homograph throws",
    function () { b.guardDomain.sanitize("аpple.com", { profile: "strict" }); },
    "domain.raw-unicode-label");
  check("guardDomain.sanitize homograph GuardDomainError",
    homoErr instanceof b.guardDomain.GuardDomainError);
}

async function run() {
  testSanitize();
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
