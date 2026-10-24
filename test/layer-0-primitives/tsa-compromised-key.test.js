// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.tsa.verifyToken refuses a timestamp vouched for by a compromised key: a
 * trust anchor whose private key is 1, and a TSA signer certificate whose
 * private key is 1 (with and without trust anchors).
 * b.contentCredentials.verifyCose reports the same refusal for its sigTst2
 * timestamp. Each refusal is paired with a control that differs only in the
 * private scalar.
 */

var helpers    = require("../helpers");
var b          = helpers.b;
var check      = helpers.check;
var nodeCrypto = require("node:crypto");
var asn1       = require("../../lib/asn1-der");
var ck         = require("../helpers/compromised-keys");

var OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2";
var OID_SHA512       = "2.16.840.1.101.3.4.2.3";
var OID_TST_INFO     = "1.2.840.113549.1.9.16.1.4";
var GEN_TIME         = new Date("2026-03-04T05:06:07Z");

function _pair(label, compromised) {
  return ck.ecKeyPair("prime256v1", compromised ? 1n : ck.labelScalar("prime256v1", "blamejs tsa " + label));
}

function _name(cn) {
  return asn1.writeSequence([asn1.writeSet([asn1.writeSequence([asn1.writeOid("2.5.4.3"), asn1.writeUtf8String(cn)])])]);
}
function _utc(d) {
  return asn1.writeNode(0x17, Buffer.from(d.toISOString().replace(/[-:T]/g, "").slice(2, 14) + "Z", "ascii"));
}
function _ext(oid, value) {
  return asn1.writeSequence([asn1.writeOid(oid), asn1.writeBoolean(true), asn1.writeOctetString(value)]);
}

function _cert(o) {
  var sigAlg = asn1.writeSequence([asn1.writeOid(OID_ECDSA_SHA256)]);
  var ext = o.ca
    ? _ext("2.5.29.19", asn1.writeSequence([asn1.writeBoolean(true)]))
    : _ext("2.5.29.37", asn1.writeSequence([asn1.writeOid(o.eku || "1.3.6.1.5.5.7.3.8")]));
  var tbs = asn1.writeSequence([
    asn1.writeContextExplicit(0, asn1.writeInteger(Buffer.from([2]))),
    asn1.writeInteger(Buffer.from([o.serial])), sigAlg, _name(o.issuer), asn1.writeSequence([
      _utc(new Date(o.from || "2026-01-01T00:00:00Z")), _utc(new Date(o.to || "2040-01-01T00:00:00Z"))]),
    _name(o.subject), o.pair.publicKey.export({ type: "spki", format: "der" }),
    asn1.writeContextExplicit(3, asn1.writeSequence([ext])),
  ]);
  return asn1.writeSequence([tbs, sigAlg, asn1.writeBitString(nodeCrypto.sign("sha256", tbs, o.issuerKey), 0)]);
}

function _chain(rootCompromised, leafCompromised) {
  var root = _pair("root", rootCompromised);
  var leaf = _pair("leaf", leafCompromised);
  var rootDer = _cert({ ca: true, serial: 1, issuer: "TSA Root", subject: "TSA Root", pair: root, issuerKey: root.privateKey });
  var leafDer = _cert({ ca: false, serial: 2, issuer: "TSA Root", subject: "TSA Signer", pair: leaf, issuerKey: root.privateKey });
  return { rootPem: ck.certPem(rootDer), leafDer: leafDer, leafKey: leaf.privateKey };
}

function _token(chain, imprint) {
  var tstInfo = asn1.writeSequence([
    asn1.writeInteger(Buffer.from([1])), asn1.writeOid("1.2.3.4.1"),
    asn1.writeSequence([asn1.writeSequence([asn1.writeOid(OID_SHA512), asn1.writeNull()]), asn1.writeOctetString(imprint)]),
    asn1.writeInteger(Buffer.from([5])),
    asn1.writeNode(0x18, Buffer.from(GEN_TIME.toISOString().replace(/[-:T]/g, "").slice(0, 14) + "Z", "ascii")),
  ]);
  var signedSet = asn1.writeSet([
    asn1.writeSequence([asn1.writeOid("1.2.840.113549.1.9.3"), asn1.writeSet([asn1.writeOid(OID_TST_INFO)])]),
    asn1.writeSequence([asn1.writeOid("1.2.840.113549.1.9.4"),
      asn1.writeSet([asn1.writeOctetString(nodeCrypto.createHash("sha512").update(tstInfo).digest())])]),
  ]);
  var signerInfo = asn1.writeSequence([
    asn1.writeInteger(Buffer.from([1])),
    asn1.writeSequence([_name("TSA Root"), asn1.writeInteger(Buffer.from([2]))]),
    asn1.writeSequence([asn1.writeOid(OID_SHA512), asn1.writeNull()]),
    Buffer.concat([Buffer.from([0xa0]), signedSet.slice(1)]),
    asn1.writeSequence([asn1.writeOid(OID_ECDSA_SHA256)]),
    asn1.writeOctetString(nodeCrypto.sign("sha256", signedSet, chain.leafKey)),
  ]);
  var signedData = asn1.writeSequence([
    asn1.writeInteger(Buffer.from([3])),
    asn1.writeSet([asn1.writeSequence([asn1.writeOid(OID_SHA512), asn1.writeNull()])]),
    asn1.writeSequence([asn1.writeOid(OID_TST_INFO), asn1.writeContextExplicit(0, asn1.writeOctetString(tstInfo))]),
    asn1.writeContextImplicit(0, Buffer.concat([chain.leafDer].concat(chain.poolDers || [])), { constructed: true }),
    asn1.writeSet([signerInfo]),
  ]);
  return asn1.writeSequence([asn1.writeOid("1.2.840.113549.1.7.2"), asn1.writeContextExplicit(0, signedData)]);
}

function _code(fn) {
  try { fn(); return "NO-THROW"; } catch (e) { return e.code || e.message; }
}

var DATA = Buffer.from("timestamped artifact");

function _verify(chain, anchored) {
  var opts = { data: DATA, hashAlg: "SHA-512" };
  if (anchored) opts.trustAnchorsPem = chain.rootPem;
  else opts.allowUntrustedIssuer = true;
  return b.tsa.verifyToken(_token(chain, nodeCrypto.createHash("sha512").update(DATA).digest()), opts);
}

function testVerifyTokenRefusesACompromisedKey() {
  var control = _chain(false, false);
  var out = _verify(control, true);
  check("tsa compromised key control: a token from the control TSA under the control anchor is trusted",
        out.issuerTrusted === true && out.genTime.getTime() === GEN_TIME.getTime());
  check("tsa compromised key control: the control token verifies with allowUntrustedIssuer",
        _code(function () { _verify(control, false); }) === "NO-THROW");
  check("tsa compromised key: a TSA certificate issued by an anchor whose private key is 1 is refused",
        _code(function () { _verify(_chain(true, false), true); }) === "tsa/compromised-key");
  check("tsa compromised key: a TSA signer whose private key is 1 is refused under a trusted anchor",
        _code(function () { _verify(_chain(false, true), true); }) === "tsa/compromised-key");
  check("tsa compromised key: a TSA signer whose private key is 1 is refused with allowUntrustedIssuer",
        _code(function () { _verify(_chain(false, true), false); }) === "tsa/compromised-key");
}

// Root "TSA Root" -> intermediate "TSA Intermediate" -> signer "TSA Signer".
// The intermediate's private scalar is 1 when `compromised` is set.
function _intermediateChain(compromised) {
  var root = _pair("root", false);
  var inter = _pair("intermediate", compromised);
  var leaf = _pair("leaf", false);
  var rootDer = _cert({ ca: true, serial: 1, issuer: "TSA Root", subject: "TSA Root", pair: root, issuerKey: root.privateKey });
  var interDer = _cert({ ca: true, serial: 3, issuer: "TSA Root", subject: "TSA Intermediate", pair: inter,
    issuerKey: root.privateKey });
  var leafDer = _cert({ ca: false, serial: 2, issuer: "TSA Intermediate", subject: "TSA Signer", pair: leaf,
    issuerKey: inter.privateKey });
  return { rootPem: ck.certPem(rootDer), leafDer: leafDer, leafKey: leaf.privateKey, poolDers: [interDer] };
}

// The signer names "TSA Intermediate" as its issuer and two certificates in
// the token carry that name. The one whose key signed the signer expired in
// 2021. The other is valid and its private scalar is 1 when `compromised`
// is set, so anyone could have issued the signer under it.
function _expiredAndSecondIssuerChain(compromised) {
  var root = _pair("root", false);
  var expired = _pair("expired intermediate", false);
  var second = _pair("second intermediate", compromised);
  var leaf = _pair("leaf", false);
  var rootDer = _cert({ ca: true, serial: 1, issuer: "TSA Root", subject: "TSA Root", pair: root, issuerKey: root.privateKey });
  var expiredDer = _cert({ ca: true, serial: 3, issuer: "TSA Root", subject: "TSA Intermediate", pair: expired,
    issuerKey: root.privateKey, from: "2020-01-01T00:00:00Z", to: "2021-01-01T00:00:00Z" });
  var secondDer = _cert({ ca: true, serial: 4, issuer: "TSA Root", subject: "TSA Intermediate", pair: second,
    issuerKey: root.privateKey });
  var leafDer = _cert({ ca: false, serial: 2, issuer: "TSA Intermediate", subject: "TSA Signer", pair: leaf,
    issuerKey: expired.privateKey });
  return { rootPem: ck.certPem(rootDer), leafDer: leafDer, leafKey: leaf.privateKey, poolDers: [expiredDer, secondDer] };
}

function testVerifyTokenRefusesACompromisedChainCertificate() {
  var control = _verify(_intermediateChain(false), true);
  check("tsa compromised key control: a token whose signer chains through the control intermediate is trusted",
        control.issuerTrusted === true);
  check("tsa compromised key: a token whose signer chains through an intermediate whose private key is 1 is refused",
        _code(function () { _verify(_intermediateChain(true), true); }) === "tsa/compromised-key");
}

function testACompromisedIssuerOutranksAnExpiredOne() {
  check("tsa compromised key control: an expired issuer beside a valid control issuer is reported as cert-expired",
        _code(function () { _verify(_expiredAndSecondIssuerChain(false), true); }) === "tsa/cert-expired");
  check("tsa compromised key: an expired issuer beside an issuer whose private key is 1 is reported as compromised-key",
        _code(function () { _verify(_expiredAndSecondIssuerChain(true), true); }) === "tsa/compromised-key");
}

// A signer certificate whose extendedKeyUsage is serverAuth rather than
// timeStamping. Its private scalar is 1 when `compromised` is set.
function _wrongEkuChain(compromised) {
  var root = _pair("root", false);
  var leaf = _pair("wrong eku leaf", compromised);
  var rootDer = _cert({ ca: true, serial: 1, issuer: "TSA Root", subject: "TSA Root", pair: root, issuerKey: root.privateKey });
  var leafDer = _cert({ ca: false, serial: 2, issuer: "TSA Root", subject: "TSA Signer", pair: leaf,
    issuerKey: root.privateKey, eku: "1.3.6.1.5.5.7.3.1" });
  return { rootPem: ck.certPem(rootDer), leafDer: leafDer, leafKey: leaf.privateKey };
}

// A signer certificate that expired in 2021, issued by a root whose private
// scalar is 1 when `compromised` is set.
function _expiredSignerChain(compromised) {
  var root = _pair("root", compromised);
  var leaf = _pair("expired leaf", false);
  var rootDer = _cert({ ca: true, serial: 1, issuer: "TSA Root", subject: "TSA Root", pair: root, issuerKey: root.privateKey,
    from: "2020-01-01T00:00:00Z" });
  var leafDer = _cert({ ca: false, serial: 2, issuer: "TSA Root", subject: "TSA Signer", pair: leaf,
    issuerKey: root.privateKey, from: "2020-01-01T00:00:00Z", to: "2021-01-01T00:00:00Z" });
  return { rootPem: ck.certPem(rootDer), leafDer: leafDer, leafKey: leaf.privateKey };
}

function testACompromisedKeyOutranksTheSignerChecks() {
  check("tsa compromised key control: a control signer without the timestamping EKU is reported as bad-eku",
        _code(function () { _verify(_wrongEkuChain(false), false); }) === "tsa/bad-eku");
  check("tsa compromised key: a signer whose private key is 1 and that lacks the timestamping EKU is reported as compromised-key",
        _code(function () { _verify(_wrongEkuChain(true), false); }) === "tsa/compromised-key");
  check("tsa compromised key control: an expired signer under the control anchor is reported as cert-expired",
        _code(function () { _verify(_expiredSignerChain(false), true); }) === "tsa/cert-expired");
  check("tsa compromised key: an expired signer under an anchor whose private key is 1 is reported as compromised-key",
        _code(function () { _verify(_expiredSignerChain(true), true); }) === "tsa/compromised-key");
}

function testContentCredentialsTimestampRefusesACompromisedAnchor() {
  var signer = ck.ecKeyPair("prime256v1", ck.labelScalar("prime256v1", "blamejs tsa content-credentials signer"));
  var privPem = signer.privateKey.export({ type: "pkcs8", format: "pem" });
  var pubPem = signer.publicKey.export({ type: "spki", format: "pem" });
  var manifest = b.contentCredentials.build({
    provider: "Acme AI", system: "acme-v3", systemVersion: "3.2.1", contentId: "img-tsa-compromised" });
  var req = b.contentCredentials.signCose(manifest, { privateKeyPem: privPem, alg: "es256", timestamp: {}, audit: false });
  function attach(chain) {
    var token = _token(chain, nodeCrypto.createHash("sha512").update(req.timestampRequest.toBeSigned).digest());
    var cose = b.contentCredentials.signCose(manifest, { privateKeyPem: privPem, alg: "es256", audit: false,
      timestamp: { token: token, signature: req.timestampRequest.signature } });
    return b.contentCredentials.verifyCose(cose.coseSign1, pubPem, { timestampTrustAnchorsPem: chain.rootPem, audit: false });
  }
  var good = attach(_chain(false, false));
  check("tsa compromised key control: verifyCose accepts a timestamp from the control TSA",
        good.valid === true && good.timestamp.valid === true, JSON.stringify(good.timestamp));
  var bad = attach(_chain(true, false));
  check("tsa compromised key: verifyCose refuses a timestamp under an anchor whose private key is 1",
        bad.valid === false && bad.reason === "timestamp-invalid:tsa/compromised-key", bad.reason);
}

async function run() {
  testVerifyTokenRefusesACompromisedKey();
  testVerifyTokenRefusesACompromisedChainCertificate();
  testACompromisedIssuerOutranksAnExpiredOne();
  testACompromisedKeyOutranksTheSignerChecks();
  testContentCredentialsTimestampRefusesACompromisedAnchor();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
