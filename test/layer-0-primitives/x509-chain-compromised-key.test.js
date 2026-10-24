// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.x509Chain never builds a path through a certificate whose key is
 * compromised: issuerValidlyIssued refuses a compromised issuer, and
 * resolveChain refuses a compromised leaf, intermediate or anchor.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var nodeCrypto = require("node:crypto");
var ck         = require("../helpers/compromised-keys");

function _cert(der) { return new nodeCrypto.X509Certificate(der); }

function testIssuerValidlyIssued() {
  check("x509Chain control: the control CA validly issued the control leaf",
        b.x509Chain.issuerValidlyIssued(_cert(ck.P256_CONTROL_CA_DER), _cert(ck.P256_CONTROL_LEAF_DER)) === true);
  var bad = _cert(ck.P256_COMPROMISED_CA_DER);
  var leaf = _cert(ck.P256_COMPROMISED_LEAF_DER);
  check("x509Chain fixture: the compromised CA's signature on its leaf verifies",
        leaf.checkIssued(bad) && leaf.verify(bad.publicKey));
  check("x509Chain: issuerValidlyIssued refuses an issuer whose private key is 1",
        b.x509Chain.issuerValidlyIssued(bad, leaf) === false);
}

function testResolveChainRefusesACompromisedAnchor() {
  var good = b.x509Chain.resolveChain(_cert(ck.P256_CONTROL_LEAF_DER), [], [_cert(ck.P256_CONTROL_CA_DER)]);
  check("x509Chain control: the control leaf anchors at the control CA",
        good.ok === true && good.reason === "anchored" && good.compromisedCert === null, JSON.stringify(good));
  var badCa = _cert(ck.P256_COMPROMISED_CA_DER);
  var bad = b.x509Chain.resolveChain(_cert(ck.P256_COMPROMISED_LEAF_DER), [], [badCa]);
  check("x509Chain: a leaf issued by a compromised anchor is refused as compromised",
        bad.ok === false && bad.reason === "compromised" &&
        bad.compromisedCert !== null && bad.compromisedCert.fingerprint256 === badCa.fingerprint256,
        JSON.stringify({ ok: bad.ok, reason: bad.reason }));
}

function testResolveChainRefusesACompromisedIntermediate() {
  var badCa = _cert(ck.P256_COMPROMISED_CA_DER);
  var res = b.x509Chain.resolveChain(_cert(ck.P256_COMPROMISED_LEAF_DER), [badCa], [_cert(ck.P256_CONTROL_CA_DER)]);
  check("x509Chain: a path through a compromised pool certificate is refused",
        res.ok === false && res.reason === "compromised", JSON.stringify({ ok: res.ok, reason: res.reason }));
}

function testResolveChainRefusesACompromisedLeaf() {
  var control = _cert(ck.P384_CONTROL_CA_DER);
  var good = b.x509Chain.resolveChain(control, [], [control]);
  check("x509Chain control: a self-anchored control certificate resolves", good.ok === true, JSON.stringify(good));
  [["small-scalar P-384", _cert(ck.P384_COMPROMISED_CA_DER)], ["listed eDellRoot", _cert(ck.EDELLROOT_CERT_PEM)]]
    .forEach(function (f) {
      var res = b.x509Chain.resolveChain(f[1], [], [f[1]]);
      check("x509Chain: a self-anchored " + f[0] + " certificate is refused as compromised",
            res.ok === false && res.reason === "compromised" &&
            res.compromisedCert.fingerprint256 === f[1].fingerprint256,
            JSON.stringify({ ok: res.ok, reason: res.reason }));
    });
}

function testCustomIssuedCallbackCannotBypass() {
  var badCa = _cert(ck.P256_COMPROMISED_CA_DER);
  var res = b.x509Chain.resolveChain(_cert(ck.P256_COMPROMISED_LEAF_DER), [], [badCa], {
    issued: function (issuer, subject) { return subject.checkIssued(issuer) && subject.verify(issuer.publicKey); },
  });
  check("x509Chain: an opts.issued callback that skips the key check still cannot anchor at a compromised CA",
        res.ok === false && res.reason === "compromised", JSON.stringify({ ok: res.ok, reason: res.reason }));
}

async function run() {
  testIssuerValidlyIssued();
  testResolveChainRefusesACompromisedAnchor();
  testResolveChainRefusesACompromisedIntermediate();
  testResolveChainRefusesACompromisedLeaf();
  testCustomIssuedCallbackCannotBypass();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
