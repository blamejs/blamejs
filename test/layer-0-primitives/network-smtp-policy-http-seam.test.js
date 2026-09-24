// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * `mtaSts.fetch` takes the same HTTPS-client seam its sibling in the same
 * file already takes.
 *
 * `tlsRpt.submit` declares `httpClient` among its options and reads
 * `opts.httpClient || httpClient()`, so a consumer can drive it in a test.
 * `mtaSts.fetch` built its client inline, so nothing that depends on a
 * fetched MTA-STS policy document could be exercised without a live network:
 * the same question answered two ways in one module.
 *
 * The policy document decides whether mail to a domain goes out under an
 * enforced TLS policy, so it is exactly the path a consumer needs to cover.
 */

var helpers = require("../helpers");
var check   = helpers.check;
var b       = helpers.b;

var POLICY = [
  "version: STSv1",
  "mode: enforce",
  "mx: mail.example.com",
  "max_age: 604800",
].join("\r\n");

function _txtLookup(record) {
  return function (qname, type) {
    if (type !== "TXT") return Promise.resolve([]);
    void qname;
    return Promise.resolve([[record]]);
  };
}

function _recordingClient(body) {
  var asked = [];
  return {
    asked:   asked,
    request: function (reqOpts) {
      asked.push(reqOpts.url);
      return Promise.resolve({
        statusCode: 200,
        body:       Buffer.from(body, "utf8"),
        headers:    { "content-type": "text/plain" },
      });
    },
  };
}

async function testTheFetchUsesTheSuppliedClient() {
  var client = _recordingClient(POLICY);
  var policy = await b.network.smtp.policy.mtaSts.fetch("example.com", {
    dnsLookup:  _txtLookup("v=STSv1; id=20260919T000000"),
    httpClient: client,
  });
  check("the supplied client is the one that fetched the policy",
        client.asked.length === 1 &&
        client.asked[0] === "https://mta-sts.example.com/.well-known/mta-sts.txt",
        JSON.stringify(client.asked));
  check("and the policy it returned was parsed",
        policy !== null && policy.mode === "enforce" &&
        Array.isArray(policy.mx) && policy.mx.indexOf("mail.example.com") !== -1,
        JSON.stringify(policy && { mode: policy.mode, mx: policy.mx }));
}

async function testAConsumerCanDriveAnEnforcedPolicyEndToEnd() {
  // The reason the seam matters: with it, the enforce path is reachable in a
  // test, so a consumer can prove its own delivery refuses a non-matching MX.
  var policy = await b.network.smtp.policy.mtaSts.fetch("strict.example", {
    dnsLookup:  _txtLookup("v=STSv1; id=20260919T000001"),
    httpClient: _recordingClient([
      "version: STSv1", "mode: enforce", "mx: mail.strict.example", "max_age: 86400",
    ].join("\r\n")),
  });
  check("an enforce policy is readable without a live network",
        policy !== null && policy.mode === "enforce", JSON.stringify(policy && policy.mode));
  check("a matching MX is accepted under it",
        b.network.smtp.policy.mtaSts.matchMx("mail.strict.example", policy.mx) === true);
  check("and one the policy does not list is not",
        b.network.smtp.policy.mtaSts.matchMx("mx.elsewhere.example", policy.mx) === false);
}

async function testAnUnknownOptionIsStillRefused() {
  // The seam is declared, not a hole: a typo'd option is named rather than
  // silently ignored, which is how the sibling behaves.
  var threw = null;
  try {
    await b.network.smtp.policy.mtaSts.fetch("example.com", {
      dnsLookup: _txtLookup("v=STSv1; id=20260919T000000"),
      htpClient: _recordingClient(POLICY),
    });
  } catch (e) { threw = e; }
  check("a misspelled option is refused by name",
        threw !== null && /htpClient/.test((threw && threw.message) || ""),
        threw && threw.message);
}

async function run() {
  await testTheFetchUsesTheSuppliedClient();
  await testAConsumerCanDriveAnEnforcedPolicyEndToEnd();
  await testAnUnknownOptionIsStillRefused();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[network-smtp-policy-http-seam] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
