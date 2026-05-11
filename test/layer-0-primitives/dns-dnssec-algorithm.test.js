"use strict";
/**
 * b.network.dns.classifyDnskeyAlgorithm / classifyDsDigestType —
 * RFC 9905 DNSSEC SHA-1 deprecation classifier + adjacent algorithm
 * registry inspection.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function testSurface() {
  check("classifyDnskeyAlgorithm is fn",
        typeof b.network.dns.classifyDnskeyAlgorithm === "function");
  check("classifyDsDigestType is fn",
        typeof b.network.dns.classifyDsDigestType === "function");
  check("DNSKEY_ALGORITHMS is an object",
        typeof b.network.dns.DNSKEY_ALGORITHMS === "object");
  check("DS_DIGEST_TYPES is an object",
        typeof b.network.dns.DS_DIGEST_TYPES === "object");
}

function testRfc9905SHA1Family() {
  // Per RFC 9905 §3 — DNSKEY algorithms 5, 7, 10 use SHA-1 and are
  // deprecated. Algorithm 6 (DSA-NSEC3-SHA1) also uses SHA-1 + DSA;
  // both reasons apply.
  var a5  = b.network.dns.classifyDnskeyAlgorithm(5);
  check("algo 5 RSASHA1 deprecated",         a5.deprecated === true);
  check("algo 5 name",                       a5.name === "RSASHA1");
  check("algo 5 cites RFC 9905",             /RFC 9905/.test(a5.reason));
  var a6  = b.network.dns.classifyDnskeyAlgorithm(6);
  check("algo 6 DSA-NSEC3-SHA1 deprecated",  a6.deprecated === true);
  var a7  = b.network.dns.classifyDnskeyAlgorithm(7);
  check("algo 7 RSASHA1-NSEC3-SHA1 deprecated", a7.deprecated === true);
}

function testCurrentAlgorithms() {
  var a8  = b.network.dns.classifyDnskeyAlgorithm(8);
  check("algo 8 RSASHA256 NOT deprecated",   a8.deprecated === false);
  var a13 = b.network.dns.classifyDnskeyAlgorithm(13);
  check("algo 13 ECDSAP256SHA256 current",   a13.deprecated === false && a13.name === "ECDSAP256SHA256");
  var a15 = b.network.dns.classifyDnskeyAlgorithm(15);
  check("algo 15 ED25519 current",           a15.deprecated === false && a15.name === "ED25519");
  var a16 = b.network.dns.classifyDnskeyAlgorithm(16);
  check("algo 16 ED448 current",             a16.deprecated === false);
}

function testOtherDeprecated() {
  var a1 = b.network.dns.classifyDnskeyAlgorithm(1);
  check("algo 1 RSAMD5 deprecated",          a1.deprecated === true && /MD5/.test(a1.reason));
  var a3 = b.network.dns.classifyDnskeyAlgorithm(3);
  check("algo 3 DSA deprecated",             a3.deprecated === true);
  var a12 = b.network.dns.classifyDnskeyAlgorithm(12);
  check("algo 12 ECC-GOST deprecated",       a12.deprecated === true);
}

function testUnknownAndBadInput() {
  var aUnknown = b.network.dns.classifyDnskeyAlgorithm(99);
  check("algo 99 unknown returns shape",
        aUnknown.algorithm === 99 && aUnknown.known === false && aUnknown.deprecated === false);

  check("non-integer returns null",
        b.network.dns.classifyDnskeyAlgorithm(1.5) === null);
  check("string returns null",
        b.network.dns.classifyDnskeyAlgorithm("5") === null);
  check("null returns null",
        b.network.dns.classifyDnskeyAlgorithm(null) === null);
  check("undefined returns null",
        b.network.dns.classifyDnskeyAlgorithm(undefined) === null);
  check("NaN returns null",
        b.network.dns.classifyDnskeyAlgorithm(NaN) === null);
  check("Infinity returns null",
        b.network.dns.classifyDnskeyAlgorithm(Infinity) === null);
}

function testDsDigestTypeClassifier() {
  // RFC 9905 §4 — DS digest type 1 (SHA-1) deprecated.
  var d1 = b.network.dns.classifyDsDigestType(1);
  check("DS digest 1 SHA-1 deprecated",
        d1.deprecated === true && /RFC 9905/.test(d1.reason));
  var d2 = b.network.dns.classifyDsDigestType(2);
  check("DS digest 2 SHA-256 current",
        d2.deprecated === false && d2.name === "SHA-256");
  var d4 = b.network.dns.classifyDsDigestType(4);
  check("DS digest 4 SHA-384 current",
        d4.deprecated === false);
  var d3 = b.network.dns.classifyDsDigestType(3);
  check("DS digest 3 GOST deprecated",
        d3.deprecated === true);

  var dUnknown = b.network.dns.classifyDsDigestType(99);
  check("DS digest 99 unknown returns shape",
        dUnknown.digestType === 99 && dUnknown.known === false);
  check("DS digest non-integer returns null",
        b.network.dns.classifyDsDigestType(1.5) === null);
  check("DS digest null returns null",
        b.network.dns.classifyDsDigestType(null) === null);
}

function run() {
  testSurface();
  testRfc9905SHA1Family();
  testCurrentAlgorithms();
  testOtherDeprecated();
  testUnknownAndBadInput();
  testDsDigestTypeClassifier();
}

module.exports = { run: run };

if (require.main === module) {
  run();
  console.log("OK");
}
