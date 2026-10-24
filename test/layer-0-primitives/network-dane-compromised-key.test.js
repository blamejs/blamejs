// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.network.dns.dane.matchCertificate refuses a TLSA match that rests on a
 * certificate whose private key anyone can hold, with `dane/compromised-key`:
 * a DANE-EE or PKIX-EE match on such a leaf, a DANE-TA match on such an
 * anchor, and any match when the leaf itself carries such a key. Each refusal
 * has a control whose certificates differ only in the private scalar.
 */

var nodeCrypto = require("node:crypto");
var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var ck      = require("../helpers/compromised-keys");
var composite = require("../helpers/composite-key-cert");

var dane = b.network.dns.dane;

function _tlsa(usage, selector, der) {
  var data = selector === 0 ? der : new nodeCrypto.X509Certificate(der).publicKey.export({ type: "spki", format: "der" });
  return { usage: usage, selector: selector, matchingType: 1, data: nodeCrypto.createHash("sha256").update(data).digest() };
}

function _attempt(opts) {
  try { return { ok: true, value: dane.matchCertificate(opts) }; }
  catch (e) { return { ok: false, code: e && e.code, message: e && e.message }; }
}

function testEndEntityMatchOnACompromisedKey() {
  [3, 1].forEach(function (usage) {
    [0, 1].forEach(function (selector) {
      var label = "usage " + usage + " selector " + selector;
      var control = _attempt({ tlsa: [_tlsa(usage, selector, ck.P256_CONTROL_CA_DER)], certificate: ck.P256_CONTROL_CA_DER });
      check("dane compromised key control: " + label + " matches an ordinary certificate",
            control.ok === true && control.value.matched.usage === usage, JSON.stringify(control));
      var bad = _attempt({ tlsa: [_tlsa(usage, selector, ck.P256_COMPROMISED_CA_DER)], certificate: ck.P256_COMPROMISED_CA_DER });
      check("dane compromised key: " + label + " refuses a certificate whose private key is 1",
            bad.ok === false && bad.code === "dane/compromised-key", JSON.stringify(bad));
    });
  });
}

function testListedRsaKey() {
  var ordinary = helpers.selfSignedPair().cert;
  var ordinaryDer = new nodeCrypto.X509Certificate(ordinary).raw;
  var control = _attempt({ tlsa: [_tlsa(3, 1, ordinaryDer)], certificate: ordinaryDer });
  check("dane compromised key control: DANE-EE matches an ordinary self-signed certificate",
        control.ok === true && control.value.daneAuthenticated === true, JSON.stringify(control));
  var edell = new nodeCrypto.X509Certificate(ck.EDELLROOT_CERT_PEM).raw;
  var bad = _attempt({ tlsa: [_tlsa(3, 0, edell)], certificate: edell });
  check("dane compromised key: DANE-EE refuses the listed eDellRoot certificate",
        bad.ok === false && bad.code === "dane/compromised-key", JSON.stringify(bad));
}

function testTrustAnchorMatchOnACompromisedAnchor() {
  [2, 0].forEach(function (usage) {
    var control = _attempt({ tlsa: [_tlsa(usage, 1, ck.P256_CONTROL_CA_DER)],
      certificate: ck.P256_CONTROL_LEAF_DER, chain: [ck.P256_CONTROL_CA_DER] });
    check("dane compromised key control: usage " + usage + " matches an ordinary anchor in the chain",
          control.ok === true && control.value.trustAnchorMatch === true && control.value.matchedCertIndex === 1,
          JSON.stringify(control));
    var bad = _attempt({ tlsa: [_tlsa(usage, 1, ck.P256_COMPROMISED_CA_DER)],
      certificate: ck.P256_COMPROMISED_LEAF_DER, chain: [ck.P256_COMPROMISED_CA_DER] });
    check("dane compromised key: usage " + usage + " refuses an anchor whose private key is 1",
          bad.ok === false && bad.code === "dane/compromised-key", JSON.stringify(bad));
  });
}

function testCompromisedLeafUnderAnOrdinaryAnchor() {
  var control = _attempt({ tlsa: [_tlsa(2, 1, ck.P256_CONTROL_CA_DER)],
    certificate: ck.P256_CONTROL_LEAF_DER, chain: [ck.P256_CONTROL_CA_DER] });
  check("dane compromised key control: DANE-TA accepts an ordinary leaf under the pinned anchor",
        control.ok === true, JSON.stringify(control));
  var bad = _attempt({ tlsa: [_tlsa(2, 1, ck.P256_CONTROL_CA_DER)],
    certificate: ck.P256_COMPROMISED_CA_DER, chain: [ck.P256_CONTROL_CA_DER] });
  check("dane compromised key: DANE-TA refuses a leaf whose private key is 1, though the anchor matches",
        bad.ok === false && bad.code === "dane/compromised-key", JSON.stringify(bad));
}

function testAnOrdinaryMatchStillWinsOverACompromisedAnchor() {
  var r = _attempt({
    tlsa: [_tlsa(2, 1, ck.P256_COMPROMISED_CA_DER), _tlsa(3, 1, ck.P256_COMPROMISED_LEAF_DER)],
    certificate: ck.P256_COMPROMISED_LEAF_DER, chain: [ck.P256_COMPROMISED_CA_DER],
  });
  check("dane compromised key: a DANE-EE match on an ordinary leaf is returned when the DANE-TA anchor is compromised",
        r.ok === true && r.value.matched.usage === 3 && r.value.daneAuthenticated === true, JSON.stringify(r));
}

function testTrustAnchorMatchScreensTheChainBelowThePinnedRoot() {
  [2, 0].forEach(function (usage) {
    var control = _attempt({ tlsa: [_tlsa(usage, 1, ck.TLS_ROOT_DER)],
      certificate: ck.TLS_CONTROL_LEAF_DER, chain: [ck.TLS_CONTROL_INTERMEDIATE_DER, ck.TLS_ROOT_DER] });
    check("dane compromised key control: usage " + usage + " pinning the root matches over an ordinary intermediate",
          control.ok === true && control.value.trustAnchorMatch === true && control.value.matchedCertIndex === 2,
          JSON.stringify(control));
    var bad = _attempt({ tlsa: [_tlsa(usage, 1, ck.TLS_ROOT_DER)],
      certificate: ck.TLS_COMPROMISED_LEAF_DER, chain: [ck.TLS_COMPROMISED_INTERMEDIATE_DER, ck.TLS_ROOT_DER] });
    check("dane compromised key: usage " + usage + " pinning the root refuses an intermediate below it whose private key is 1",
          bad.ok === false && bad.code === "dane/compromised-key", JSON.stringify(bad));
  });
}

function testAnUnreadableKeyIsNotReportedAsCompromised() {
  var bCrypto = require("../../lib/crypto");
  var real = bCrypto.compromisedKey;
  var control = _attempt({ tlsa: [_tlsa(3, 1, ck.P256_CONTROL_CA_DER)], certificate: ck.P256_CONTROL_CA_DER });
  var r;
  bCrypto.compromisedKey = function () {
    var e = new Error("crypto.compromisedKey: the value could not be read as a public key, private key or certificate");
    e.code = "crypto/bad-key";
    throw e;
  };
  try { r = _attempt({ tlsa: [_tlsa(3, 1, ck.P256_CONTROL_CA_DER)], certificate: ck.P256_CONTROL_CA_DER }); }
  finally { bCrypto.compromisedKey = real; }
  check("dane unreadable key control: the certificate matches when its key can be judged",
        control.ok === true, JSON.stringify(control));
  check("dane unreadable key: a certificate whose key cannot be judged throws dane/bad-certificate, not dane/compromised-key",
        r.ok === false && r.code === "dane/bad-certificate", JSON.stringify(r));
}

function testACompositeKeyCertificateMatches() {
  [0, 1].forEach(function (selector) {
    var data = selector === 0 ? composite.COMPOSITE_CERT_DER : composite.COMPOSITE_SPKI_DER;
    var r = _attempt({
      tlsa: [{ usage: 3, selector: selector, matchingType: 1, data: nodeCrypto.createHash("sha256").update(data).digest() }],
      certificate: composite.COMPOSITE_CERT_DER,
    });
    check("dane composite key: DANE-EE selector " + selector + " matches a composite ML-DSA certificate",
          r.ok === true && r.value.daneAuthenticated === true, JSON.stringify(r));
  });
}

function _countResolveChainCalls(fn) {
  var x509Chain = require("../../lib/x509-chain");
  var real = x509Chain.resolveChain;
  var calls = 0;
  x509Chain.resolveChain = function () { calls += 1; return real.apply(this, arguments); };
  try { return { result: fn(), calls: calls }; }
  finally { x509Chain.resolveChain = real; }
}

function testThePathIsSearchedOnlyWhenTheChainCarriesACompromisedKey() {
  var clean = _countResolveChainCalls(function () {
    return _attempt({ tlsa: [_tlsa(2, 1, ck.TLS_ROOT_DER)],
      certificate: ck.TLS_CONTROL_LEAF_DER, chain: [ck.TLS_CONTROL_INTERMEDIATE_DER, ck.TLS_ROOT_DER] });
  });
  check("dane anchor search: a trust-anchor match over a chain with no compromised key runs no path search",
        clean.result.ok === true && clean.result.value.matchedCertIndex === 2 && clean.calls === 0,
        JSON.stringify({ calls: clean.calls, r: clean.result }));
  var unrelated = _countResolveChainCalls(function () {
    return _attempt({ tlsa: [_tlsa(2, 1, ck.P256_CONTROL_CA_DER)],
      certificate: ck.TLS_CONTROL_LEAF_DER, chain: [ck.TLS_CONTROL_INTERMEDIATE_DER, ck.P256_CONTROL_CA_DER] });
  });
  check("dane anchor search: a match on a supplied anchor the leaf does not chain to still returns the match without a search",
        unrelated.result.ok === true && unrelated.result.value.matchedCertIndex === 2 && unrelated.calls === 0,
        JSON.stringify({ calls: unrelated.calls, r: unrelated.result }));
  var offPath = _countResolveChainCalls(function () {
    return _attempt({ tlsa: [_tlsa(2, 1, ck.TLS_ROOT_DER), _tlsa(2, 0, ck.TLS_ROOT_DER)],
      certificate: ck.TLS_CONTROL_LEAF_DER,
      chain: [ck.TLS_CONTROL_INTERMEDIATE_DER, ck.P256_COMPROMISED_CA_DER, ck.TLS_ROOT_DER] });
  });
  check("dane anchor search: a compromised certificate off the path is searched once and does not refuse the match",
        offPath.result.ok === true && offPath.result.value.matchedCertIndex === 3 && offPath.calls === 1,
        JSON.stringify({ calls: offPath.calls, r: offPath.result }));
  var onPath = _countResolveChainCalls(function () {
    return _attempt({ tlsa: [_tlsa(2, 1, ck.TLS_ROOT_DER), _tlsa(0, 0, ck.TLS_ROOT_DER)],
      certificate: ck.TLS_COMPROMISED_LEAF_DER, chain: [ck.TLS_COMPROMISED_INTERMEDIATE_DER, ck.TLS_ROOT_DER] });
  });
  check("dane anchor search: two records pinning a root above a compromised intermediate are refused from one search",
        onPath.result.ok === false && onPath.result.code === "dane/compromised-key" && onPath.calls === 1,
        JSON.stringify({ calls: onPath.calls, r: onPath.result }));
}

// TLS_CONTROL_LEAF_DER with its subjectPublicKeyInfo SEQUENCE length written
// in the long form 0x81 0x59 instead of 0x59, and the enclosing lengths
// adjusted. node:crypto parses it and loads its P-256 key.
function _nonMinimalSpkiLeaf() {
  var hex = ck.TLS_CONTROL_LEAF_DER.toString("hex");
  var at = hex.indexOf("3059301306072a8648ce3d0201");
  var buf = Buffer.from(hex.slice(0, at) + "308159" + hex.slice(at + 4), "hex");
  buf.writeUInt16BE(buf.readUInt16BE(2) + 1, 2);
  buf.writeUInt16BE(buf.readUInt16BE(6) + 1, 6);
  return buf;
}

function testSelectorOneReadsAKeyNodeLoadsFromANonMinimalSpki() {
  var leaf = _nonMinimalSpkiLeaf();
  var x509 = new nodeCrypto.X509Certificate(leaf);
  check("dane non-minimal SPKI premise: node:crypto parses the certificate and loads an ec key",
        x509.publicKey.asymmetricKeyType === "ec", x509.publicKey.asymmetricKeyType);
  var control = _attempt({ tlsa: [_tlsa(3, 1, ck.TLS_CONTROL_LEAF_DER)], certificate: ck.TLS_CONTROL_LEAF_DER });
  check("dane non-minimal SPKI control: DANE-EE selector 1 matches the DER-encoded certificate",
        control.ok === true, JSON.stringify(control));
  var r = _attempt({ tlsa: [_tlsa(3, 1, leaf)], certificate: leaf });
  check("dane non-minimal SPKI: DANE-EE selector 1 matches the key node:crypto reads from the certificate",
        r.ok === true && r.value.daneAuthenticated === true, JSON.stringify(r));
}

async function run() {
  testEndEntityMatchOnACompromisedKey();
  testListedRsaKey();
  testTrustAnchorMatchOnACompromisedAnchor();
  testCompromisedLeafUnderAnOrdinaryAnchor();
  testAnOrdinaryMatchStillWinsOverACompromisedAnchor();
  testTrustAnchorMatchScreensTheChainBelowThePinnedRoot();
  testAnUnreadableKeyIsNotReportedAsCompromised();
  testACompositeKeyCertificateMatches();
  testSelectorOneReadsAKeyNodeLoadsFromANonMinimalSpki();
  testThePathIsSearchedOnlyWhenTheChainCarriesACompromisedKey();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
