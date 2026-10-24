// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.mail.crypto.smime refuses a certificate whose key is compromised: a trust
 * anchor in trustAnchorCertsPem, an intermediate carried in the envelope's
 * SignedData.certificates, and a certificate given to checkCert. Every refusal
 * is paired with a control chain that differs only in the CA's private scalar.
 *
 * A trust anchor whose key b.crypto.compromisedKey cannot check is refused
 * with mail-crypto/smime/bad-trust-anchor. The case makes the vendored
 * certificate lint fail for that one anchor, whose curve OID node does not
 * know; the control leaves the lint in place. checkCert judges a certificate
 * whose public key node cannot read through the lint and returns it with
 * keyType null, and refuses it with mail-crypto/smime/bad-cert only when the
 * lint cannot read it either. A compromised intermediate above an expired one
 * is reported as compromised rather than as expired.
 */

var helpers    = require("../helpers");
var b          = helpers.b;
var check      = helpers.check;
var nodeCrypto = require("node:crypto");
var asn1       = require("../../lib/asn1-der");
var pqc        = require("../../lib/pqc-software");
var ck         = require("../helpers/compromised-keys");
var composite  = require("../helpers/composite-key-cert");
var pki        = require("../../lib/vendor/blamejs-pki.cjs");

var smime = b.mail.crypto.smime;

var OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2";
var OID_ML_DSA_65    = "2.16.840.1.101.3.4.3.18";

function _sha256Scalar(label) {
  return BigInt("0x" + nodeCrypto.createHash("sha256").update(label, "utf8").digest("hex"));
}

var CA = {
  compromised: { der: ck.P256_COMPROMISED_CA_DER, key: ck.ecKeyPair("prime256v1", 1n).privateKey },
  control:     { der: ck.P256_CONTROL_CA_DER,
                 key: ck.ecKeyPair("prime256v1", _sha256Scalar("blamejs passkey attestation fixture CA")).privateKey },
};

function _name(cn) {
  return asn1.writeSequence([asn1.writeSet([
    asn1.writeSequence([asn1.writeOid("2.5.4.3"), asn1.writeUtf8String(cn)]),
  ])]);
}
function _subjectOf(der) {
  return asn1.writeNode(0x30, Buffer.from(asn1.readCertificateTbsFields(der).subject.value));
}
function _ext(oid, critical, valueDer) {
  var kids = [asn1.writeOid(oid)];
  if (critical) kids.push(asn1.writeBoolean(true));
  kids.push(asn1.writeOctetString(valueDer));
  return asn1.writeSequence(kids);
}

// An X.509 v3 certificate signed with ecdsa-with-SHA256 by issuer.key, naming
// issuer.name as its issuer when given and issuer.der's subject otherwise, valid
// 2026-01-01 .. 2099-12-31 unless `expired` sets 2020-01-01 .. 2021-01-01.
function _issue(serial, issuer, subjectName, spkiDer, extensions, expired) {
  var tbs = asn1.writeSequence([
    asn1.writeContextExplicit(0, asn1.writeInteger(Buffer.from([2]))),
    asn1.writeInteger(Buffer.from([serial])),
    asn1.writeSequence([asn1.writeOid(OID_ECDSA_SHA256)]),
    issuer.name || _subjectOf(issuer.der),
    asn1.writeSequence(expired ? [
      asn1.writeNode(0x17, Buffer.from("200101000000Z", "latin1")),
      asn1.writeNode(0x17, Buffer.from("210101000000Z", "latin1")),
    ] : [
      asn1.writeNode(0x17, Buffer.from("260101000000Z", "latin1")),
      asn1.writeNode(0x18, Buffer.from("20991231000000Z", "latin1")),
    ]),
    subjectName,
    spkiDer,
    asn1.writeContextExplicit(3, asn1.writeSequence(extensions)),
  ]);
  return asn1.writeSequence([
    tbs,
    asn1.writeSequence([asn1.writeOid(OID_ECDSA_SHA256)]),
    asn1.writeBitString(nodeCrypto.sign("sha256", tbs, issuer.key)),
  ]);
}

// A CA intermediate under `parent` whose P-256 key has private scalar d.
function _intermediate(parent, d, cn, expired) {
  var pair = ck.ecKeyPair("prime256v1", d);
  var der = _issue(3, parent, _name(cn || "Mail Fixture Intermediate"),
    pair.publicKey.export({ type: "spki", format: "der" }), [
      _ext("2.5.29.19", true, asn1.writeSequence([asn1.writeBoolean(true)])),
      _ext("2.5.29.15", true, asn1.writeBitString(Buffer.from([0x04]), 2)),
    ], expired);
  return { der: der, key: pair.privateKey };
}

// An ML-DSA-65 signer certificate under `issuer`, plus the signing key pair.
function _signer(issuer) {
  var kp = pqc.ml_dsa_65.keygen();
  var spki = asn1.writeSequence([
    asn1.writeSequence([asn1.writeOid(OID_ML_DSA_65)]),
    asn1.writeBitString(Buffer.from(kp.publicKey)),
  ]);
  var der = _issue(4, issuer, _name("signer@mail.example"), spki, [
    _ext("2.5.29.19", true, asn1.writeSequence([])),
  ]);
  return { der: der, kp: kp };
}

// A detached S/MIME SignedData over msg, carrying certsDer.
function _envelope(signer, msg, certsDer) {
  return b.cms.encodeSignedData({
    encapContent: msg,
    detached:     true,
    certificates: certsDer,
    signers: [{ certificate: signer.der, secretKey: signer.kp.secretKey, sigAlg: "ML-DSA-65" }],
  });
}

function _code(fn) {
  try { fn(); return "NO-THROW"; } catch (e) { return e.code || e.message; }
}

var MSG = Buffer.from("From: signer@mail.example\r\nSubject: wire\r\n\r\nPay now.\r\n");

function testFixturesCarryTheKeysTheyClaim() {
  ["compromised", "control"].forEach(function (which) {
    var certSpki = new nodeCrypto.X509Certificate(CA[which].der).publicKey.export({ type: "spki", format: "der" });
    var keySpki = nodeCrypto.createPublicKey(CA[which].key).export({ type: "spki", format: "der" });
    check("smime compromised key: the " + which + " CA fixture carries the derived key",
          Buffer.from(certSpki).equals(Buffer.from(keySpki)));
  });
}

function _pems(anchors) {
  return anchors.map(function (a) { return typeof a === "string" ? a : ck.certPem(a); });
}
function _verify(signer, certsDer, anchors) {
  return smime.verify({
    message:             MSG,
    signature:           _envelope(signer, MSG, certsDer),
    signerPublicKey:     signer.kp.publicKey,
    trustAnchorCertsPem: _pems(anchors),
  });
}
function _verifyAll(signer, certsDer, anchors) {
  var keys = {};
  keys[Buffer.from(asn1.readCertificateTbsFields(signer.der).serialNumber.value).toString("hex")] = signer.kp.publicKey;
  return smime.verifyAll({
    message:             MSG,
    signature:           _envelope(signer, MSG, certsDer),
    signerPublicKeys:    keys,
    trustAnchorCertsPem: _pems(anchors),
  });
}
function _refused(label, fn) {
  var code = _code(fn);
  check(label, code === "mail-crypto/smime/compromised-key", code);
}

function testCompromisedAnchorIsRefused() {
  var good = _signer(CA.control);
  var rv = _verify(good, [good.der], [CA.control.der]);
  check("smime compromised key control: verify anchors a signer issued by the control CA",
        rv.valid === true && rv.chainVerified === true, JSON.stringify(rv));
  var rvAll = _verifyAll(good, [good.der], [CA.control.der]);
  check("smime compromised key control: verifyAll anchors a signer issued by the control CA",
        rvAll.valid === true && rvAll.chainVerified === true, JSON.stringify(rvAll));

  var bad = _signer(CA.compromised);
  _refused("smime compromised key: verify refuses a trust anchor whose private key is 1",
    function () { _verify(bad, [bad.der], [CA.compromised.der]); });
  _refused("smime compromised key: verifyAll refuses a trust anchor whose private key is 1",
    function () { _verifyAll(bad, [bad.der], [CA.compromised.der]); });
  _refused("smime compromised key: a listed anchor next to the control anchor is refused",
    function () { _verify(good, [good.der], [CA.control.der, ck.EDELLROOT_CERT_PEM]); });
}

// An intermediate whose issuer name is the anchor's name in capitals chains to
// that anchor under X.509 name comparison.
function testIssuerNamesCompareAsX509Names() {
  var upper = { der: CA.control.der, key: CA.control.key, name: _name("TEST ATTESTATION CA") };
  var inter = _intermediate(upper, ck.labelScalar("prime256v1", "blamejs smime case intermediate"));
  var signer = _signer(inter);
  var rv;
  try { rv = _verify(signer, [signer.der, inter.der], [CA.control.der]); }
  catch (e) { rv = { threw: e.code || e.message }; }
  check("smime: an intermediate naming its anchor in capitals anchors the chain",
        rv.valid === true && rv.chainVerified === true, JSON.stringify(rv));
}

function testCompromisedIntermediateInTheEnvelopeIsRefused() {
  var goodInter = _intermediate(CA.control, ck.labelScalar("prime256v1", "blamejs smime fixture intermediate"));
  var good = _signer(goodInter);
  var rv = _verify(good, [good.der, goodInter.der], [CA.control.der]);
  check("smime compromised key control: verify anchors through a control intermediate in the envelope",
        rv.valid === true && rv.chainVerified === true, JSON.stringify(rv));

  var badInter = _intermediate(CA.control, 1n);
  var bad = _signer(badInter);
  _refused("smime compromised key: verify refuses a chain through an envelope intermediate whose private key is 1",
    function () { _verify(bad, [bad.der, badInter.der], [CA.control.der]); });
  _refused("smime compromised key: verifyAll refuses a chain through an envelope intermediate whose private key is 1",
    function () { _verifyAll(bad, [bad.der, badInter.der], [CA.control.der]); });
}

function testCheckCertRefusesACompromisedKey() {
  var info = smime.checkCert({ certPem: ck.certPem(CA.control.der) });
  check("smime compromised key control: checkCert accepts the control CA certificate",
        info && info.keyType === "ec", JSON.stringify(info));
  var p384 = smime.checkCert({ certPem: ck.certPem(ck.P384_CONTROL_CA_DER) });
  check("smime compromised key control: checkCert accepts the P-384 control CA certificate",
        p384 && p384.keyType === "ec", JSON.stringify(p384));
  _refused("smime compromised key: checkCert refuses a P-256 certificate whose private key is 1",
    function () { smime.checkCert({ certPem: ck.certPem(CA.compromised.der) }); });
  _refused("smime compromised key: checkCert refuses a P-384 certificate whose private key is 1",
    function () { smime.checkCert({ certPem: ck.certPem(ck.P384_COMPROMISED_CA_DER) }); });
  _refused("smime compromised key: checkCert refuses the listed eDellRoot certificate",
    function () { smime.checkCert({ certPem: ck.EDELLROOT_CERT_PEM }); });
}

function _unreadableAnchorDer() {
  var der = Buffer.from(CA.control.der);
  var curveOid = Buffer.from("06082a8648ce3d030107", "hex");
  der[der.indexOf(curveOid) + curveOid.length - 1] = 0x64;
  return der;
}

function _withLintFailingFor(der, fn) {
  var lint = pki.lint;
  var orig = lint.certificate;
  lint.certificate = function (input) {
    if (Buffer.isBuffer(input) && input.equals(der)) throw new Error("lint could not read the certificate");
    return orig.apply(lint, arguments);
  };
  try { return fn(); }
  finally { lint.certificate = orig; }
}

function testAnUnreadableAnchorIsABadTrustAnchor() {
  var good = _signer(CA.control);
  var unreadable = _unreadableAnchorDer();
  var code = _withLintFailingFor(unreadable, function () {
    return _code(function () { _verify(good, [good.der], [CA.control.der, unreadable]); });
  });
  check("smime unreadable anchor: an anchor whose key cannot be checked is refused as a bad trust anchor",
        code === "mail-crypto/smime/bad-trust-anchor", code);
  var allCode = _withLintFailingFor(unreadable, function () {
    return _code(function () { _verifyAll(good, [good.der], [CA.control.der, unreadable]); });
  });
  check("smime unreadable anchor: verifyAll refuses the same anchor as a bad trust anchor",
        allCode === "mail-crypto/smime/bad-trust-anchor", allCode);
  var rv = _verify(good, [good.der], [CA.control.der, unreadable]);
  check("smime unreadable anchor control: an anchor whose key node cannot load but lint reads is checked and passes",
        rv.valid === true && rv.chainVerified === true, JSON.stringify(rv));
}

function _checkCert(pem) {
  try { return { ok: true, value: smime.checkCert({ certPem: pem }) }; }
  catch (e) { return { ok: false, code: e.code || e.message, message: e.message }; }
}

function testCheckCertJudgesACertificateWhoseKeyNodeCannotRead() {
  var composed = _checkCert(composite.COMPOSITE_CERT_PEM);
  check("smime checkCert: a composite ML-DSA certificate whose key node cannot read is judged and returned with keyType null",
        composed.ok === true && composed.value.keyType === null && composed.value.subject === "CN=mx1.example.com",
        JSON.stringify(composed));
  var judged = _checkCert(ck.certPem(_unreadableAnchorDer()));
  check("smime checkCert: a certificate on a curve node does not know is judged and returned with keyType null",
        judged.ok === true && judged.value.keyType === null, JSON.stringify(judged));
  var otherCurve = Buffer.from(CA.control.der);
  var curveOid = Buffer.from("06082a8648ce3d030107", "hex");
  otherCurve[otherCurve.indexOf(curveOid) + curveOid.length - 1] = 0x65;
  var unjudged = _withLintFailingFor(otherCurve, function () { return _checkCert(ck.certPem(otherCurve)); });
  check("smime checkCert: a certificate whose key neither node nor the lint can read is refused as bad-cert",
        unjudged.ok === false && unjudged.code === "mail-crypto/smime/bad-cert", JSON.stringify(unjudged));
}

function testACompromisedIntermediateBehindAnExpiredOneIsReportedAsCompromised() {
  function chain(d) {
    var upper = _intermediate(CA.control, d);
    var expired = _intermediate(upper, ck.labelScalar("prime256v1", "blamejs smime fixture expired intermediate"),
      "Mail Fixture Expired Intermediate", true);
    var signer = _signer(expired);
    return { signer: signer, certs: [signer.der, expired.der, upper.der] };
  }
  var control = chain(ck.labelScalar("prime256v1", "blamejs smime fixture intermediate"));
  var controlCodes = [
    _code(function () { _verify(control.signer, control.certs, [CA.control.der]); }),
    _code(function () { _verifyAll(control.signer, control.certs, [CA.control.der]); }),
  ];
  check("smime expired intermediate control: an expired intermediate over an ordinary one is refused as cert-expired",
        controlCodes[0] === "mail-crypto/smime/cert-expired" && controlCodes[1] === "mail-crypto/smime/cert-expired",
        JSON.stringify(controlCodes));
  var bad = chain(1n);
  _refused("smime expired intermediate: verify refuses an expired intermediate over one whose private key is 1 as compromised",
    function () { _verify(bad.signer, bad.certs, [CA.control.der]); });
  _refused("smime expired intermediate: verifyAll refuses an expired intermediate over one whose private key is 1 as compromised",
    function () { _verifyAll(bad.signer, bad.certs, [CA.control.der]); });
}

async function run() {
  testFixturesCarryTheKeysTheyClaim();
  testIssuerNamesCompareAsX509Names();
  testCompromisedAnchorIsRefused();
  testCompromisedIntermediateInTheEnvelopeIsRefused();
  testCheckCertRefusesACompromisedKey();
  testAnUnreadableAnchorIsABadTrustAnchor();
  testCheckCertJudgesACertificateWhoseKeyNodeCannotRead();
  testACompromisedIntermediateBehindAnExpiredOneIsReportedAsCompromised();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
