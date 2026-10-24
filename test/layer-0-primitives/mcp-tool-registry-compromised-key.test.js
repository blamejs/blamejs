// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.mcp.toolRegistry.create refuses a compromised signingKey or verifyingKey
 * with mcp/compromised-key, so no registry exists whose verifyCall accepts
 * envelopes anyone can sign. Every refusal is paired with a control key that
 * differs only in its private scalar.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var ck      = require("../helpers/compromised-keys");

var ALGS = [["es256", "prime256v1"], ["es384", "secp384r1"]];
var TOOLS = [{ name: "deleteAll", inputSchema: { type: "object" } }];

function _pems(pair) {
  return {
    priv: pair.privateKey.export({ type: "pkcs8", format: "pem" }),
    pub:  pair.publicKey.export({ type: "spki", format: "pem" }),
  };
}
function _code(fn) {
  try { fn(); return "NO-THROW"; } catch (e) { return e.code || e.message; }
}

function testControlRegistryRoundTrips() {
  ALGS.forEach(function (a) {
    var control = _pems(ck.ecKeyPair(a[1], ck.labelScalar(a[1], "mcp control")));
    var reg = b.mcp.toolRegistry.create({
      tools: TOOLS, alg: a[0], signingKey: control.priv, verifyingKey: control.pub,
    });
    var signed = reg.signCall({ toolName: "deleteAll", args: {} });
    check("mcp compromised key control: an " + a[0] + " registry with control keys verifies its own call",
          reg.verifyCall(signed, { args: {} }) === true);
  });
}

function testVerifyingKeyRefused() {
  ALGS.forEach(function (a) {
    var control = _pems(ck.ecKeyPair(a[1], ck.labelScalar(a[1], "mcp control")));
    var bad = _pems(ck.ecKeyPair(a[1], 1n));
    check("mcp compromised key: create refuses an " + a[0] + " verifyingKey whose private scalar is 1",
          _code(function () {
            b.mcp.toolRegistry.create({ tools: TOOLS, alg: a[0], signingKey: control.priv, verifyingKey: bad.pub });
          }) === "mcp/compromised-key");
  });
}

function testSigningKeyRefused() {
  ALGS.forEach(function (a) {
    var bad = _pems(ck.ecKeyPair(a[1], 1n));
    check("mcp compromised key: create refuses an " + a[0] + " signingKey whose private scalar is 1",
          _code(function () {
            b.mcp.toolRegistry.create({ tools: TOOLS, alg: a[0], signingKey: bad.priv });
          }) === "mcp/compromised-key");
  });
}

async function run() {
  testControlRegistryRoundTrips();
  testVerifyingKeyRefused();
  testSigningKeyRefused();
}

module.exports = {
  run:                            run,
  testControlRegistryRoundTrips:  testControlRegistryRoundTrips,
  testVerifyingKeyRefused:        testVerifyingKeyRefused,
  testSigningKeyRefused:          testSigningKeyRefused,
};

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
