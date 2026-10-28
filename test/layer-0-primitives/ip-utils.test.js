// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * lib/ip-utils — internal IP-address textual helpers shared across the
 * mail (greylist / rbl / helo), guard-domain, and safe-schema consumers.
 * Covers the strict dotted-quad IPv4 validator, the RFC 5321 bracketed
 * address-literal form, and the bounded loose-IPv6 pre-filter that were
 * consolidated here from five hand-rolled regex spellings.
 */

var helpers = require("../helpers");
var check   = helpers.check;
var ip      = require("../../lib/ip-utils");

function run() {
  // ---- isIPv4 / IPV4_RE — strict RFC 791 dotted-quad ----
  ["0.0.0.0", "255.255.255.255", "1.2.3.4", "192.168.0.1", "10.0.0.255",
   "203.0.113.42", "9.9.9.9", "199.199.199.199", "250.250.250.250"]
    .forEach(function (s) {
      check("isIPv4 accepts " + s, ip.isIPv4(s) === true);
      check("IPV4_RE matches isIPv4 for " + s, ip.IPV4_RE.test(s) === ip.isIPv4(s));
    });

  ["256.0.0.1", "1.2.3", "1.2.3.4.5", "01.2.3.4", "1.2.3.256", "300.1.1.1",
   "", "abc", "1.2.3.4 ", " 1.2.3.4", "1.2.3.x", "999.0.0.0", "1.2.3.04",
   "0xC0.0.0.1"]
    .forEach(function (s) {
      check("isIPv4 rejects " + JSON.stringify(s), ip.isIPv4(s) === false);
    });

  // Non-string inputs never throw, always false.
  [null, undefined, 1234, {}, [], Buffer.from("1.2.3.4")].forEach(function (v) {
    check("isIPv4 false on non-string " + Object.prototype.toString.call(v),
      ip.isIPv4(v) === false);
  });

  // ---- IPV4_ADDR_LITERAL_RE — RFC 5321 §4.1.3 bracketed form ----
  var lit = "[203.0.113.42]".match(ip.IPV4_ADDR_LITERAL_RE);
  check("IPV4_ADDR_LITERAL_RE matches bracketed literal", lit !== null);
  check("IPV4_ADDR_LITERAL_RE captures inner dotted-quad", lit && lit[1] === "203.0.113.42");
  check("IPV4_ADDR_LITERAL_RE rejects out-of-range octet",
    ip.IPV4_ADDR_LITERAL_RE.test("[256.0.0.1]") === false);
  check("IPV4_ADDR_LITERAL_RE rejects unbracketed", ip.IPV4_ADDR_LITERAL_RE.test("1.2.3.4") === false);

  // ---- looksLikeIPv6Hex — bounded hex-colon pre-filter ----
  ["::1", "2001:db8::1", "fe80::1", "0:0:0:0:0:0:0:0",
   "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"]   // 39 chars — the upper bound
    .forEach(function (s) {
      check("looksLikeIPv6Hex accepts " + s, ip.looksLikeIPv6Hex(s) === true);
    });
  check("looksLikeIPv6Hex boundary is exactly 39",
    "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".length === ip.IPV6_TEXT_MAX_LEN);

  ["::ffff:1.2.3.4",                              // dotted IPv4-mapped tail — excluded
   "gggg::1", "nothex", "", "1.2.3.4",
   "aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa"]  // 44 chars — over the bound
    .forEach(function (s) {
      check("looksLikeIPv6Hex rejects " + JSON.stringify(s), ip.looksLikeIPv6Hex(s) === false);
    });
  [null, undefined, 42, {}].forEach(function (v) {
    check("looksLikeIPv6Hex false on non-string", ip.looksLikeIPv6Hex(v) === false);
  });

  // A valid IPv6 that passes the pre-filter still expands cleanly.
  check("pre-filter then expandIpv6Hex parses ::1",
    ip.looksLikeIPv6Hex("::1") && ip.expandIpv6Hex("::1") === "00000000000000000000000000000001");

  // ---- RFC 4291 §2.2: '::' abbreviates ONE OR MORE all-zero groups ----
  // A '::' adjacent to a full 8 explicit groups compresses ZERO groups, which
  // is malformed IPv6 text — net.isIP rejects all of these. The expander must
  // too (return null), or it diverges from the kernel/peer parser on a whole
  // input class. Covers trailing / leading / interior placements.
  ["1:2:3:4:5:6:7:8::", "::1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7::8",
   "1:2:3:4::5:6:7:8", "0:0:0:0:0:0:0:0::"]
    .forEach(function (s) {
      check("expandIpv6Hex rejects zero-group '::' " + JSON.stringify(s), ip.expandIpv6Hex(s) === null);
      check("expandIpv6Groups rejects zero-group '::' " + JSON.stringify(s), ip.expandIpv6Groups(s) === null);
    });
  // A '::' compressing at least one group stays valid (the fix must not
  // over-reject the legitimate abbreviation).
  check("expandIpv6Hex accepts one-group '::' 1:2:3:4:5:6:7::",
    ip.expandIpv6Hex("1:2:3:4:5:6:7::") === "00010002000300040005000600070000");
  check("expandIpv6Hex accepts one-group '::' ::1:2:3:4:5:6:7",
    ip.expandIpv6Hex("::1:2:3:4:5:6:7") === "00000001000200030004000500060007");
  check("expandIpv6Hex accepts all-zero ::", ip.expandIpv6Hex("::") === "00000000000000000000000000000000");

  // ---- Embedded IPv4 tail is a STRICT dotted-quad (matches net.isIP) ----
  // A leading-zero octet in the ::ffff: / dual-stack tail is octal-ambiguous
  // and rejected by net.isIP; the expander reuses the canonical strict isIPv4
  // so the two validators don't diverge. >255 octets are likewise refused.
  ["::ffff:01.2.3.4", "::ffff:1.2.3.04", "::ffff:010.0.0.7", "::ffff:256.0.0.1"]
    .forEach(function (s) {
      check("expandIpv6Hex rejects loose IPv4 tail " + JSON.stringify(s), ip.expandIpv6Hex(s) === null);
    });
  check("expandIpv6Hex accepts strict IPv4-mapped ::ffff:192.0.2.1",
    ip.expandIpv6Hex("::ffff:192.0.2.1") === "00000000000000000000ffffc0000201");

  // ---- regression: existing helpers unchanged ----
  check("isIPv4Shape loose still true for 999.0.0.0", ip.isIPv4Shape("999.0.0.0") === true);
  check("isIPv4Shape false for non-dotted", ip.isIPv4Shape("notip") === false);
  check("expandIpv6Hex(bad) null", ip.expandIpv6Hex("bad") === null);
  check("expandIpv6Groups ::1", JSON.stringify(ip.expandIpv6Groups("::1")) === JSON.stringify([0, 0, 0, 0, 0, 0, 0, 1]));

  testEndsInANumber();

  return Promise.resolve();
}

// WHATWG URL "ends in a number": the last label, after one trailing empty
// label is dropped, is all ASCII digits or an IPv4 hex number (0x / 0X then
// zero or more hex digits).
function testEndsInANumber() {
  check("endsInANumber is a function", typeof ip.endsInANumber === "function");
  if (typeof ip.endsInANumber !== "function") return;
  ["1", "127.0.0.1", "127.1", "2130706433", "0x7f.0.0.1", "foo.0x", "a.b.0X1F", "127.0.0.1.",
   "999.1.1.1", "a.08", "x.0xABCdef"]
    .forEach(function (s) {
      check("endsInANumber is true for " + JSON.stringify(s), ip.endsInANumber(s) === true);
    });
  ["", ".", "example.com", "a.0xg", "0x7f.example.com", "127.0.0.1..", "127.0.0.1.example.com",
   "a.1b", "a.0x\u0010", "a.0x\u0019", "a." + String.fromCharCode(0x0660), "a.1 ", "a.0y1"]
    .forEach(function (s) {
      check("endsInANumber is false for " + JSON.stringify(s), ip.endsInANumber(s) === false);
    });
  [null, undefined, 1, {}].forEach(function (v) {
    check("endsInANumber is false for a non-string", ip.endsInANumber(v) === false);
  });
}

module.exports = { run: run };

if (require.main === module) run().then(function () {
  process.stdout.write("OK — ip-utils\n");
}).catch(function (e) {
  process.stderr.write("FAIL: " + (e && e.stack || e) + "\n");
  process.exit(1);
});
