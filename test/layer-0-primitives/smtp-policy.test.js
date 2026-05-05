"use strict";
/**
 * b.network.smtp.policy — MTA-STS + DANE + TLS-RPT operator surface.
 *
 * Live HTTPS / DNS lookups are not exercised in smoke (network-bound
 * tests live in test/integration). What's covered here is the parser
 * shape, MX-match logic, TLSA decode, and TLS-RPT JSON shape generator.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function testSurface() {
  check("network.smtp.mtaSts exposed", typeof b.network.smtp.mtaSts === "object");
  check("network.smtp.dane exposed",   typeof b.network.smtp.dane === "object");
  check("network.smtp.tlsRpt exposed", typeof b.network.smtp.tlsRpt === "object");
  check("frameworkError.SmtpPolicyError exposed",
        typeof b.frameworkError.SmtpPolicyError === "function");
}

function testMtaStsParse() {
  var text = "version: STSv1\nmode: enforce\nmx: mx1.example.com\nmx: *.mx.example.com\nmax_age: 86400\n";
  var policy = b.network.smtp.mtaSts.parsePolicy(text);
  check("parsePolicy returns version + mode + mx + max_age",
        policy.version === "STSv1" && policy.mode === "enforce" &&
        policy.mx.length === 2 && policy.max_age === 86400);
}

function testMtaStsParseRejectsBadVersion() {
  var threw = null;
  try { b.network.smtp.mtaSts.parsePolicy("version: STSv2\nmode: enforce\n"); }
  catch (e) { threw = e; }
  check("parsePolicy throws on bad version",
        threw && /bad-version/.test(threw.code || ""));
}

function testMtaStsMatchMx() {
  var mxList = ["mx1.example.com", "*.mail.example.com"];
  check("exact match",
        b.network.smtp.mtaSts.matchMx("mx1.example.com", mxList) === true);
  check("wildcard single-label match",
        b.network.smtp.mtaSts.matchMx("alpha.mail.example.com", mxList) === true);
  check("wildcard does NOT match deeper",
        b.network.smtp.mtaSts.matchMx("a.b.mail.example.com", mxList) === false);
  check("wildcard does NOT match parent",
        b.network.smtp.mtaSts.matchMx("mail.example.com", mxList) === false);
  check("non-listed host → false",
        b.network.smtp.mtaSts.matchMx("attacker.example.com", mxList) === false);
}

function testDaneRecordShape() {
  var rec = { usage: 3, selector: 1, mtype: 1, dataHex: "abcd" };
  var shaped = b.network.smtp.dane.recordShape(rec);
  check("DANE-EE/SPKI/SHA-256 labels resolve",
        shaped.usageLabel === "DANE-EE" &&
        shaped.selectorLabel === "SPKI" &&
        shaped.mtypeLabel === "SHA-256");
}

function testTlsRptRecordShape() {
  var rpt = b.network.smtp.tlsRpt.recordShape({
    organization: "example.com",
    contact:      "tls-reports@example.com",
    policies: [
      {
        type:        "sts",
        domain:      "example.com",
        mxHosts:     ["mx1.example.com"],
        successCount: 100,
        failureCount: 2,
      },
    ],
  });
  check("tlsRpt.recordShape produces RFC 8460 JSON",
        rpt["organization-name"] === "example.com" &&
        Array.isArray(rpt.policies) &&
        rpt.policies[0].summary["total-successful-session-count"] === 100);
}

async function run() {
  testSurface();
  testMtaStsParse();
  testMtaStsParseRejectsBadVersion();
  testMtaStsMatchMx();
  testDaneRecordShape();
  testTlsRptRecordShape();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
