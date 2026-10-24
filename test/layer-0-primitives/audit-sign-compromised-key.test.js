// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.auditSign.verify returns false for a signature by a compromised key
 * passed as its third argument. Every refusal is paired with a control key
 * that differs only in its private scalar. The key may be a string PEM, a
 * Buffer PEM, a { key: pem } object, or a PEM string that also carries an
 * ordinary certificate before or after the key.
 */

var helpers    = require("../helpers");
var b          = helpers.b;
var check      = helpers.check;
var nodeCrypto = require("node:crypto");
var ck         = require("../helpers/compromised-keys");

var PAYLOAD = Buffer.from("blamejs-chain-anchor-v1\n42\nabc\n\n1700000000000", "utf8");

function testVerifyRefusesCompromisedKey() {
  ["prime256v1", "secp384r1"].forEach(function (curve) {
    var control = ck.ecKeyPair(curve, ck.labelScalar(curve, "audit-sign control"));
    var controlPem = control.publicKey.export({ type: "spki", format: "pem" });
    check("audit-sign compromised key control: verify accepts a " + curve + " control signature",
          b.auditSign.verify(PAYLOAD, nodeCrypto.sign(null, PAYLOAD, control.privateKey), controlPem) === true);

    var bad = ck.ecKeyPair(curve, 1n);
    var badPem = bad.publicKey.export({ type: "spki", format: "pem" });
    check("audit-sign compromised key: verify refuses a " + curve + " signature by a scalar-1 key",
          b.auditSign.verify(PAYLOAD, nodeCrypto.sign(null, PAYLOAD, bad.privateKey), badPem) === false);
  });
}

var ORDINARY_CERT_PEM = ck.certPem(ck.P256_CONTROL_CA_DER);

function testVerifyKeyInputForms() {
  var control = ck.ecKeyPair("prime256v1", ck.labelScalar("prime256v1", "audit-sign control"));
  var controlPem = control.publicKey.export({ type: "spki", format: "pem" });
  var controlSig = nodeCrypto.sign(null, PAYLOAD, control.privateKey);
  var bad = ck.ecKeyPair("prime256v1", 1n);
  var badPem = bad.publicKey.export({ type: "spki", format: "pem" });
  var badSig = nodeCrypto.sign(null, PAYLOAD, bad.privateKey);
  var forms = {
    "Buffer PEM":                        function (pem) { return Buffer.from(pem, "utf8"); },
    "{ key: pem }":                      function (pem) { return { key: pem }; },
    "PEM followed by a certificate":     function (pem) { return pem + ORDINARY_CERT_PEM; },
    "PEM preceded by a certificate":     function (pem) { return ORDINARY_CERT_PEM + pem; },
  };
  Object.keys(forms).forEach(function (label) {
    check("audit-sign key input control: verify accepts a valid signature when the key is a " + label,
          b.auditSign.verify(PAYLOAD, controlSig, forms[label](controlPem)) === true);
    check("audit-sign key input: verify refuses a scalar-1 signature when the key is a " + label,
          b.auditSign.verify(PAYLOAD, badSig, forms[label](badPem)) === false);
  });
}

async function run() {
  testVerifyRefusesCompromisedKey();
  testVerifyKeyInputForms();
}

module.exports = {
  run:                              run,
  testVerifyRefusesCompromisedKey:  testVerifyRefusesCompromisedKey,
  testVerifyKeyInputForms:          testVerifyKeyInputForms,
};

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
