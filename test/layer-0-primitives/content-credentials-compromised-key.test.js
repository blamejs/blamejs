// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.contentCredentials refuses a compromised key wherever one enters: the
 * provider key in verify and verifyCose, the claim key in
 * verifyIdentityAssertion, every certificate on its x509 identity chain
 * (anchor, self-anchored certificate, chain certificate), and the signing
 * key in sign, signCose and attachIdentityAssertion. Each refusal is paired
 * with a control that differs only in the private scalar.
 */

var helpers    = require("../helpers");
var b          = helpers.b;
var check      = helpers.check;
var nodeCrypto = require("node:crypto");
var asn1       = require("../../lib/asn1-der");
var ck         = require("../helpers/compromised-keys");
var rawCose    = require("../helpers/raw-cose-sign1");

var BAD     = ck.ecKeyPair("prime256v1", 1n);
var CONTROL = ck.ecKeyPair("prime256v1", ck.labelScalar("prime256v1", "blamejs content-credentials control"));
var ASSERTIONS = [{ label: "c2pa.actions", data: { action: "c2pa.created" } }];

function _pem(pair) {
  return {
    priv: pair.privateKey.export({ type: "pkcs8", format: "pem" }),
    pub:  pair.publicKey.export({ type: "spki", format: "pem" }),
  };
}

function _manifest() {
  return b.contentCredentials.build({
    provider: "Acme AI", system: "acme-v3", systemVersion: "3.2.1", contentId: "img-compromised" });
}

function _code(fn) {
  try { fn(); return "NO-THROW"; } catch (e) { return e.code || e.message; }
}

function _rawSign(obj, pair) {
  return nodeCrypto.sign(null, Buffer.from(b.canonicalJson.stringify(obj), "utf8"), pair.privateKey).toString("base64");
}

function _digestPair(curve, hash, label) {
  return ck.ecKeyPair(curve, BigInt("0x" + nodeCrypto.createHash(hash).update(label, "utf8").digest("hex")));
}

function _assertion(pair, subject) {
  var sp = { binding: "x509", subject: subject || { name: "Acme Newsroom" },
    referenced_assertions: ASSERTIONS.map(function (a) {
      return { hash: nodeCrypto.createHash("sha3-512").update(b.canonicalJson.stringify(a), "utf8").digest("hex"),
        alg: "sha3-512" };
    }) };
  return { type: "cawg.identity", version: "1.2", signer_payload: sp, signature: _rawSign(sp, pair) };
}

function testVerifyRefusesACompromisedProviderKey() {
  var m = _manifest();
  var good = b.contentCredentials.verify({ manifest: m, signature: _rawSign(m, CONTROL) }, _pem(CONTROL).pub, { audit: false });
  check("content credentials compromised key control: verify accepts the control provider key", good.valid === true);
  var bad = b.contentCredentials.verify({ manifest: m, signature: _rawSign(m, BAD) }, _pem(BAD).pub, { audit: false });
  check("content credentials compromised key: verify refuses a provider key whose private key is 1",
        bad.valid === false && bad.reason === "compromised-key", bad.reason);
}

function testVerifyCoseRefusesACompromisedProviderKey() {
  var payload = Buffer.from(b.canonicalJson.stringify(_manifest()), "utf8");
  function verify(pair) {
    var cose = rawCose.sign1(payload, { alg: "ES256", privateKey: pair.privateKey });
    return b.contentCredentials.verifyCose(cose, _pem(pair).pub, { requireTimestamp: false, audit: false });
  }
  var good = verify(CONTROL);
  check("content credentials compromised key control: verifyCose accepts the control provider key", good.valid === true, good.reason);
  var bad = verify(BAD);
  check("content credentials compromised key: verifyCose refuses a provider key whose private key is 1",
        bad.valid === false && bad.reason === "compromised-key", bad.reason);
}

function testVerifyIdentityAssertionRefusesACompromisedClaimKey() {
  var opts = { referencedAssertions: ASSERTIONS, audit: false };
  var good = b.contentCredentials.verifyIdentityAssertion(_assertion(CONTROL), _pem(CONTROL).pub, opts);
  check("content credentials compromised key control: the control claim key is valid", good.valid === true, good.reason);
  var bad = b.contentCredentials.verifyIdentityAssertion(_assertion(BAD), _pem(BAD).pub, opts);
  check("content credentials compromised key: a claim key whose private key is 1 is refused",
        bad.valid === false && bad.reason === "compromised-key", bad.reason);
}

function testIdentityChainRefusesACompromisedCertificate() {
  var p256Leaf = { privateKey: ck.p256AttestationLeafKey() };
  var cases = [
    ["an anchor", p256Leaf, "Test Authenticator",
      [ck.P256_CONTROL_LEAF_DER], ck.P256_CONTROL_CA_DER, [ck.P256_COMPROMISED_LEAF_DER], ck.P256_COMPROMISED_CA_DER],
    ["a self-anchored certificate", _digestPair("secp384r1", "sha384", "blamejs mtls-ca fixture CA"), "blamejs CA",
      [ck.P384_CONTROL_CA_DER], ck.P384_CONTROL_CA_DER, [ck.P384_COMPROMISED_CA_DER], ck.P384_COMPROMISED_CA_DER],
    ["the top chain certificate", _digestPair("prime256v1", "sha256", "blamejs tls fixture intermediate"),
      "blamejs TLS fixture intermediate",
      [ck.TLS_CONTROL_INTERMEDIATE_DER], ck.TLS_ROOT_DER, [ck.TLS_COMPROMISED_INTERMEDIATE_DER], ck.TLS_ROOT_DER],
    ["an intermediate chain certificate", _digestPair("prime256v1", "sha256", "blamejs tls fixture leaf"), "localhost",
      [ck.TLS_CONTROL_LEAF_DER, ck.TLS_CONTROL_INTERMEDIATE_DER], ck.TLS_ROOT_DER,
      [ck.TLS_COMPROMISED_LEAF_DER, ck.TLS_COMPROMISED_INTERMEDIATE_DER], ck.TLS_ROOT_DER],
  ];
  cases.forEach(function (c) {
    var claimKey = c[1].privateKey;
    var assertion = _assertion({ privateKey: claimKey }, { name: c[2] });
    var pub = nodeCrypto.createPublicKey(claimKey).export({ type: "spki", format: "pem" });
    function verify(chain, anchor) {
      return b.contentCredentials.verifyIdentityAssertion(assertion, pub, {
        referencedAssertions: ASSERTIONS, audit: false,
        identityCertChainPem: chain.map(ck.certPem), identityTrustAnchorsPem: ck.certPem(anchor),
      });
    }
    var good = verify(c[3], c[4]);
    check("content credentials compromised key control: the control chain for " + c[0] + " is verified",
          good.verified === true && good.reason === "x509-chain-verified", good.reason);
    var bad = verify(c[5], c[6]);
    check("content credentials compromised key: a chain whose key at " + c[0] + " is compromised is not verified",
          bad.verified === false && bad.reason === "compromised-key", bad.reason);
  });
}

function testAnUnrelatedCompromisedAnchorDoesNotBlockAValidChain() {
  var leafKey = ck.p256AttestationLeafKey();
  var assertion = _assertion({ privateKey: leafKey }, { name: "Test Authenticator" });
  var pub = nodeCrypto.createPublicKey(leafKey).export({ type: "spki", format: "pem" });
  function verify(anchors) {
    return b.contentCredentials.verifyIdentityAssertion(assertion, pub, {
      referencedAssertions: ASSERTIONS, audit: false,
      identityCertChainPem: ck.certPem(ck.P256_CONTROL_LEAF_DER), identityTrustAnchorsPem: anchors.map(ck.certPem),
    });
  }
  [["after", false], ["before", true]].forEach(function (order) {
    function list(other) {
      return order[1] ? [other, ck.P256_CONTROL_CA_DER] : [ck.P256_CONTROL_CA_DER, other];
    }
    var good = verify(list(ck.P384_CONTROL_CA_DER));
    check("content credentials compromised key control: an unrelated control anchor listed " + order[0] +
          " the issuing anchor leaves the chain verified", good.verified === true, good.reason);
    var bad = verify(list(ck.P384_COMPROMISED_CA_DER));
    check("content credentials compromised key: an unrelated compromised anchor listed " + order[0] +
          " the issuing anchor leaves the chain verified", bad.verified === true && bad.reason === "x509-chain-verified",
          bad.reason);
  });
}

function _certDer(o) {
  function name(cn) {
    return asn1.writeSequence([asn1.writeSet([asn1.writeSequence([asn1.writeOid("2.5.4.3"), asn1.writeUtf8String(cn)])])]);
  }
  function utc(iso) {
    return asn1.writeNode(0x17, Buffer.from(iso.replace(/[-:T]/g, "").slice(2, 14) + "Z", "ascii"));
  }
  var sigAlg = asn1.writeSequence([asn1.writeOid("1.2.840.10045.4.3.2")]);
  var basic = asn1.writeSequence([asn1.writeOid("2.5.29.19"), asn1.writeBoolean(true),
    asn1.writeOctetString(asn1.writeSequence(o.ca ? [asn1.writeBoolean(true)] : []))]);
  var tbs = asn1.writeSequence([
    asn1.writeContextExplicit(0, asn1.writeInteger(Buffer.from([2]))),
    asn1.writeInteger(Buffer.from([o.serial])), sigAlg, name(o.issuer),
    asn1.writeSequence([utc(o.from), utc(o.to)]), name(o.subject),
    o.pair.publicKey.export({ type: "spki", format: "der" }),
    asn1.writeContextExplicit(3, asn1.writeSequence([basic])),
  ]);
  return asn1.writeSequence([tbs, sigAlg, asn1.writeBitString(nodeCrypto.sign("sha256", tbs, o.issuerKey), 0)]);
}

// The leaf certificate expired in 2021. Its anchor's private scalar is 1 when
// `compromised` is set.
function _expiredLeafUnderAnchor(compromised) {
  var root = compromised ? BAD : ck.ecKeyPair("prime256v1", ck.labelScalar("prime256v1", "blamejs cc identity root"));
  var leaf = ck.ecKeyPair("prime256v1", ck.labelScalar("prime256v1", "blamejs cc identity expired leaf"));
  var rootDer = _certDer({ ca: true, serial: 1, issuer: "Identity Root", subject: "Identity Root", pair: root,
    issuerKey: root.privateKey, from: "2020-01-01T00:00:00Z", to: "2040-01-01T00:00:00Z" });
  var leafDer = _certDer({ ca: false, serial: 2, issuer: "Identity Root", subject: "Identity Leaf", pair: leaf,
    issuerKey: root.privateKey, from: "2020-01-01T00:00:00Z", to: "2021-01-01T00:00:00Z" });
  return b.contentCredentials.verifyIdentityAssertion(_assertion(leaf, { name: "Identity Leaf" }),
    leaf.publicKey.export({ type: "spki", format: "pem" }), {
      referencedAssertions: ASSERTIONS, audit: false,
      identityCertChainPem: ck.certPem(leafDer), identityTrustAnchorsPem: ck.certPem(rootDer),
    });
}

function testACompromisedAnchorOutranksAnExpiredLeaf() {
  var good = _expiredLeafUnderAnchor(false);
  check("content credentials compromised key control: an expired leaf under the control anchor is reported as leaf-expired",
        good.verified === false && good.reason === "leaf-expired", good.reason);
  var bad = _expiredLeafUnderAnchor(true);
  check("content credentials compromised key: an expired leaf under an anchor whose private key is 1 is reported as compromised-key",
        bad.verified === false && bad.reason === "compromised-key", bad.reason);
}

function testSignersRefuseACompromisedKey() {
  var m = _manifest();
  var signers = [
    ["sign", function (pem) { return b.contentCredentials.sign(m, { privateKeyPem: pem, audit: false }); }],
    ["signCose", function (pem) {
      return b.contentCredentials.signCose(m, { privateKeyPem: pem, alg: "es256", timestamp: false,
        timestampOptOutReason: "compromised-key test", audit: false });
    }],
    ["attachIdentityAssertion", function (pem) {
      return b.contentCredentials.attachIdentityAssertion({ binding: "x509", subject: { name: "Acme" },
        referencedAssertions: ASSERTIONS, privateKeyPem: pem, audit: false });
    }],
  ];
  signers.forEach(function (s) {
    check("content credentials compromised key control: " + s[0] + " with the control key succeeds",
          _code(function () { s[1](_pem(CONTROL).priv); }) === "NO-THROW");
    check("content credentials compromised key: " + s[0] + " refuses a key whose private key is 1",
          _code(function () { s[1](_pem(BAD).priv); }) === "content-credentials/compromised-key");
  });
}

async function run() {
  testVerifyRefusesACompromisedProviderKey();
  testVerifyCoseRefusesACompromisedProviderKey();
  testVerifyIdentityAssertionRefusesACompromisedClaimKey();
  testIdentityChainRefusesACompromisedCertificate();
  testAnUnrelatedCompromisedAnchorDoesNotBlockAValidChain();
  testACompromisedAnchorOutranksAnExpiredLeaf();
  testSignersRefuseACompromisedKey();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
