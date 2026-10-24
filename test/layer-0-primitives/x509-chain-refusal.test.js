// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * x509Chain._chainRefusal turns a b.x509Chain.resolveChain result into the
 * caller's error code and message. A compromised certificate is reported
 * ahead of an expired one, a path-length overrun and a nameConstraints
 * violation, so a chain that fails several checks still names the
 * compromised key. Given the search inputs, it also reports a compromised
 * certificate that resolveChain did not reach because an expired one came
 * first. x509Chain._validAt is the validity-window test b.tsa and b.mdoc pass
 * to resolveChain.
 */

var helpers    = require("../helpers");
var check      = helpers.check;
var nodeCrypto = require("node:crypto");
var x509Chain  = require("../../lib/x509-chain");
var ck         = require("../helpers/compromised-keys");
var crafted    = require("../helpers/crafted-compromised-certs");

var CODES = {
  compromised:      "t/compromised-key",
  invalidCert:      "t/cert-expired",
  pathlen:          "t/chain-pathlen-exceeded",
  nameconstraint:   "t/name-constraint-violation",
  untrusted:        "t/untrusted-chain",
  untrustedMessage: "leaf does not chain to a supplied trust anchor",
};

var COMPROMISED = new nodeCrypto.X509Certificate(ck.P384_COMPROMISED_CA_DER);
var CONTROL     = new nodeCrypto.X509Certificate(ck.P384_CONTROL_CA_DER);

function _res(o) {
  return Object.assign({ ok: false, reason: "untrusted", compromisedCert: null, invalidCert: null, depthLimited: false }, o);
}

function testAResolvedChainHasNoRefusal() {
  check("x509 chain refusal: an anchored chain has no refusal",
        x509Chain._chainRefusal(_res({ ok: true, reason: "anchored" }), CODES) === null);
}

function testACompromisedCertificateOutranksEveryOtherFailure() {
  var r = x509Chain._chainRefusal(_res({ reason: "compromised", compromisedCert: COMPROMISED, invalidCert: CONTROL }), CODES);
  check("x509 chain refusal: a compromised certificate outranks an expired one",
        r.code === "t/compromised-key" && r.message.indexOf("certificate '" + COMPROMISED.subject + "' carries a compromised key: ") === 0 &&
        /private key is within 255 of zero or of the group order/.test(r.message), r.message);
  var withPathLen = x509Chain._chainRefusal(_res({ reason: "pathlen", compromisedCert: COMPROMISED }), CODES);
  check("x509 chain refusal: a compromised certificate outranks a path-length overrun",
        withPathLen.code === "t/compromised-key");
  var withNames = x509Chain._chainRefusal(_res({ reason: "nameconstraint", compromisedCert: COMPROMISED }), CODES);
  check("x509 chain refusal: a compromised certificate outranks a nameConstraints violation",
        withNames.code === "t/compromised-key");
}

function testTheRemainingFailuresInOrder() {
  var expired = x509Chain._chainRefusal(_res({ reason: "pathlen", invalidCert: CONTROL }), CODES);
  check("x509 chain refusal: an expired certificate outranks a path-length overrun",
        expired.code === "t/cert-expired" && expired.message === "certificate '" + CONTROL.subject +
        "' is not valid at the asserted time", expired.message);
  var noValidity = Object.assign({}, CODES);
  delete noValidity.invalidCert;
  check("x509 chain refusal: an invalidCert is not reported when the caller names no code for it",
        x509Chain._chainRefusal(_res({ reason: "pathlen", invalidCert: CONTROL }), noValidity).code === "t/chain-pathlen-exceeded");
  check("x509 chain refusal: a path-length overrun",
        x509Chain._chainRefusal(_res({ reason: "pathlen" }), CODES).code === "t/chain-pathlen-exceeded");
  check("x509 chain refusal: a nameConstraints violation",
        x509Chain._chainRefusal(_res({ reason: "nameconstraint" }), CODES).code === "t/name-constraint-violation");
  var untrusted = x509Chain._chainRefusal(_res({}), CODES);
  check("x509 chain refusal: an untrusted chain carries the caller's message",
        untrusted.code === "t/untrusted-chain" && untrusted.message === CODES.untrustedMessage);
}

function _refuseAt(leafDer, caDer, at, withSearch) {
  var leaf = new nodeCrypto.X509Certificate(leafDer);
  var anchors = [new nodeCrypto.X509Certificate(caDer)];
  var res = x509Chain.resolveChain(leaf, [], anchors, { validAt: x509Chain._validAt(at) });
  return x509Chain._chainRefusal(res, CODES, withSearch ? { leaf: leaf, pool: [], anchors: anchors } : undefined);
}

function testACompromisedAnchorBehindAnExpiredLeafIsReported() {
  var future = new Date("2200-01-01T00:00:00Z");
  check("x509 chain refusal control: an expired leaf under the control anchor is reported as expired",
        _refuseAt(ck.P256_CONTROL_LEAF_DER, ck.P256_CONTROL_CA_DER, future, true).code === "t/cert-expired");
  check("x509 chain refusal: an expired leaf under an anchor whose private key is 1 is reported as compromised",
        _refuseAt(ck.P256_COMPROMISED_LEAF_DER, ck.P256_COMPROMISED_CA_DER, future, true).code === "t/compromised-key");
  check("x509 chain refusal: without the search inputs the helper reports what resolveChain recorded",
        _refuseAt(ck.P256_COMPROMISED_LEAF_DER, ck.P256_COMPROMISED_CA_DER, future, false).code === "t/cert-expired");
}

// The search for a compromised certificate above an expired one shares the
// visit budget of the search that found the expired one.
function testTheSecondSearchSharesTheVisitBudget() {
  var future = new Date("2200-01-01T00:00:00Z");
  var leaf = new nodeCrypto.X509Certificate(ck.P256_COMPROMISED_LEAF_DER);
  var anchors = [new nodeCrypto.X509Certificate(ck.P256_COMPROMISED_CA_DER)];
  var res = x509Chain.resolveChain(leaf, [], anchors, { validAt: x509Chain._validAt(future) });
  check("x509 chain refusal: resolveChain reports the node expansions it made",
        typeof res.visits === "number" && res.visits >= 1, String(res.visits));
  var search = { leaf: leaf, pool: [], anchors: anchors };
  check("x509 chain refusal control: with visits left, the second search finds the compromised anchor",
        x509Chain._chainRefusal(res, CODES, search).code === "t/compromised-key");
  var spent = Object.assign({}, res, { visits: 4096 });
  check("x509 chain refusal: a first search that used the whole budget leaves none for the second",
        x509Chain._chainRefusal(spent, CODES, search).code === "t/cert-expired");
}

function _resolve(leafDer, anchorDer) {
  return x509Chain.resolveChain(new nodeCrypto.X509Certificate(leafDer), [],
    [new nodeCrypto.X509Certificate(anchorDer)]);
}

function testACertificatePkiCannotParseIsJudgedByItsKey() {
  var odd = crafted.explicitFalseExtension();
  var controlCa = crafted.selfSignedCa(crafted.CONTROL_CA, null);
  var control = _resolve(crafted.leafUnder(crafted.CONTROL_CA, crafted.LEAF, odd), controlCa);
  check("x509 chain control: a leaf whose extension encodes critical FALSE anchors under an ordinary CA",
        control.ok === true && control.reason === "anchored", JSON.stringify(control.reason));
  var badLeaf = _resolve(crafted.leafUnder(crafted.CONTROL_CA, crafted.COMPROMISED, odd), controlCa);
  check("x509 chain: a scalar-1 leaf whose extension encodes critical FALSE is refused as compromised",
        badLeaf.ok === false && badLeaf.reason === "compromised", JSON.stringify(badLeaf.reason));

  var controlAnchor = _resolve(crafted.leafUnder(crafted.CONTROL_CA, crafted.LEAF, null),
    crafted.selfSignedCa(crafted.CONTROL_CA, odd));
  check("x509 chain control: an ordinary anchor whose extension encodes critical FALSE anchors a leaf",
        controlAnchor.ok === true, JSON.stringify(controlAnchor.reason));
  var badAnchor = _resolve(crafted.leafUnder(crafted.COMPROMISED, crafted.LEAF, null),
    crafted.selfSignedCa(crafted.COMPROMISED, odd));
  check("x509 chain: a scalar-1 anchor whose extension encodes critical FALSE is refused as compromised",
        badAnchor.ok === false && badAnchor.reason === "compromised", JSON.stringify(badAnchor.reason));

  var issued = x509Chain.issuerValidlyIssued(
    new nodeCrypto.X509Certificate(crafted.selfSignedCa(crafted.COMPROMISED, odd)),
    new nodeCrypto.X509Certificate(crafted.leafUnder(crafted.COMPROMISED, crafted.LEAF, null)));
  check("x509 chain: issuerValidlyIssued is false for a scalar-1 issuer whose extension encodes critical FALSE",
        issued === false);
}

function testAnUnreadableCertificateIsRefusedAndNamedUnreadable() {
  var unreadable = new nodeCrypto.X509Certificate(crafted.unreadableCa());
  var verdict = x509Chain._compromiseVerdict(unreadable);
  check("x509 chain: a certificate neither node nor @blamejs/pki can judge has the verdict unreadable",
        verdict !== null && verdict.id === "unreadable" && /^the key could not be checked: /.test(verdict.reason),
        JSON.stringify(verdict));
  check("x509 chain control: an ordinary certificate has no verdict",
        x509Chain._compromiseVerdict(CONTROL) === null);
  check("x509 chain: a compromised certificate has its compromisedKey verdict",
        x509Chain._compromiseVerdict(COMPROMISED).id === "small-ec-scalar");

  var controlCa = new nodeCrypto.X509Certificate(crafted.selfSignedCa(crafted.CONTROL_CA, null));
  check("x509 chain fixture: the ordinary CA's signature on the unreadable certificate verifies",
        unreadable.verify(controlCa.publicKey) === true);
  var res = x509Chain.resolveChain(unreadable, [], [controlCa]);
  check("x509 chain: a leaf whose key cannot be checked is not anchored, and is reported",
        res.ok === false && res.reason === "compromised" && res.compromisedCert === unreadable, JSON.stringify(res.reason));
  var r = x509Chain._chainRefusal(res, CODES);
  check("x509 chain refusal: an unreadable certificate is reported as one that could not be checked",
        r.code === "t/compromised-key" &&
        r.message.indexOf("certificate '" + unreadable.subject + "' could not be checked for a compromised key: ") === 0,
        r.message);
  var anchorOnly = x509Chain.resolveChain(
    new nodeCrypto.X509Certificate(crafted.leafUnder(crafted.CONTROL_CA, crafted.LEAF, null)), [], [unreadable]);
  check("x509 chain: an anchor whose key cannot be checked anchors nothing",
        anchorOnly.ok === false && anchorOnly.reason === "untrusted", JSON.stringify(anchorOnly.reason));
}

function testValidAtIsInclusiveOfBothEnds() {
  var from = CONTROL.validFromDate, to = CONTROL.validToDate;
  check("x509 chain validAt: the first valid instant", x509Chain._validAt(from)(CONTROL) === true);
  check("x509 chain validAt: the last valid instant", x509Chain._validAt(to)(CONTROL) === true);
  check("x509 chain validAt: before notBefore", x509Chain._validAt(new Date(from.getTime() - 1))(CONTROL) === false);
  check("x509 chain validAt: after notAfter", x509Chain._validAt(new Date(to.getTime() + 1))(CONTROL) === false);
}

async function run() {
  testAResolvedChainHasNoRefusal();
  testACompromisedCertificateOutranksEveryOtherFailure();
  testTheRemainingFailuresInOrder();
  testACompromisedAnchorBehindAnExpiredLeafIsReported();
  testTheSecondSearchSharesTheVisitBudget();
  testValidAtIsInclusiveOfBothEnds();
  testACertificatePkiCannotParseIsJudgedByItsKey();
  testAnUnreadableCertificateIsRefusedAndNamedUnreadable();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
