// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.mail.bimi.fetchAndVerifyMark refuses a Verified Mark Certificate chain
 * that runs through a compromised key: a trust anchor in trustAnchorsPem and
 * an intermediate the sender serves with the VMC. Every refusal is paired with
 * a control chain that differs only in the CA's private scalar.
 *
 * A trust anchor whose key b.crypto.compromisedKey cannot check is refused
 * with bimi/vmc-chain-invalid, the code an anchor that does not parse gets.
 * The case makes the vendored certificate lint fail for that one anchor, whose
 * curve OID node does not know; the control leaves the lint in place.
 */

var helpers    = require("../helpers");
var b          = helpers.b;
var check      = helpers.check;
var nodeCrypto = require("node:crypto");
var asn1       = require("../../lib/asn1-der");
var ck         = require("../helpers/compromised-keys");
var pki        = require("../../lib/vendor/blamejs-pki.cjs");

var OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2";
var DOMAIN = "bank.example";

function _sha256Scalar(label) {
  return BigInt("0x" + nodeCrypto.createHash("sha256").update(label, "utf8").digest("hex"));
}

var CA = {
  compromised: { der: ck.P256_COMPROMISED_CA_DER, key: ck.ecKeyPair("prime256v1", 1n).privateKey },
  control:     { der: ck.P256_CONTROL_CA_DER,
                 key: ck.ecKeyPair("prime256v1", _sha256Scalar("blamejs passkey attestation fixture CA")).privateKey },
};

function _rdn(oid, value) {
  return asn1.writeSet([asn1.writeSequence([asn1.writeOid(oid), asn1.writeUtf8String(value)])]);
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

// An X.509 v3 certificate signed with ecdsa-with-SHA256 by issuer.key, valid
// 2026-01-01 .. 2099-12-31 unless `expired` sets 2020-01-01 .. 2021-01-01.
function _issue(serial, issuer, subjectName, publicKey, extensions, expired) {
  var tbs = asn1.writeSequence([
    asn1.writeContextExplicit(0, asn1.writeInteger(Buffer.from([2]))),
    asn1.writeInteger(Buffer.from([serial])),
    asn1.writeSequence([asn1.writeOid(OID_ECDSA_SHA256)]),
    _subjectOf(issuer.der),
    asn1.writeSequence(expired ? [
      asn1.writeNode(0x17, Buffer.from("200101000000Z", "latin1")),
      asn1.writeNode(0x17, Buffer.from("210101000000Z", "latin1")),
    ] : [
      asn1.writeNode(0x17, Buffer.from("260101000000Z", "latin1")),
      asn1.writeNode(0x18, Buffer.from("20991231000000Z", "latin1")),
    ]),
    subjectName,
    publicKey.export({ type: "spki", format: "der" }),
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
  var der = _issue(3, parent, asn1.writeSequence([_rdn("2.5.4.3", cn || "BIMI Fixture Intermediate")]), pair.publicKey, [
    _ext("2.5.29.19", true, asn1.writeSequence([asn1.writeBoolean(true)])),
    _ext("2.5.29.15", true, asn1.writeBitString(Buffer.from([0x04]), 2)),
  ], expired);
  return { der: der, key: pair.privateKey };
}

// A Verified Mark Certificate for DOMAIN under `issuer`: SAN dNSName, the BIMI
// mark-verification EKU, the Mark Certificate General Policy and one markType.
function _vmc(issuer) {
  var subject = asn1.writeSequence([
    _rdn("2.5.4.3", DOMAIN),
    _rdn("1.3.6.1.4.1.53087.1.13", "Registered Mark"),
  ]);
  var leafKey = ck.ecKeyPair("prime256v1", ck.labelScalar("prime256v1", "blamejs bimi fixture leaf")).publicKey;
  return _issue(4, issuer, subject, leafKey, [
    _ext("2.5.29.19", true, asn1.writeSequence([])),
    _ext("2.5.29.15", true, asn1.writeBitString(Buffer.from([0x80]), 7)),
    _ext("2.5.29.17", false, asn1.writeSequence([asn1.writeNode(0x82, Buffer.from(DOMAIN, "latin1"))])),
    _ext("2.5.29.37", false, asn1.writeSequence([asn1.writeOid("1.3.6.1.5.5.7.3.31")])),
    _ext("2.5.29.32", false, asn1.writeSequence([
      asn1.writeSequence([asn1.writeOid("1.3.6.1.4.1.99999.7.1")]),
      asn1.writeSequence([asn1.writeOid("1.3.6.1.4.1.53087.1.1")]),
    ])),
  ]);
}

function _pem(x) { return typeof x === "string" ? x : ck.certPem(x); }

async function _fetch(servedDers, anchors) {
  try {
    return await b.mail.bimi.fetchAndVerifyMark({
      domain:          DOMAIN,
      vmcUrl:          "https://" + DOMAIN + "/bimi/vmc.pem",
      trustAnchorsPem: anchors.map(_pem).join(""),
      audit:           false,
      httpClient: {
        request: async function () {
          return { statusCode: 200, body: Buffer.from(servedDers.map(_pem).join(""), "utf8") };
        },
      },
    });
  } catch (e) {
    return { ok: false, code: e.code || e.message };
  }
}

async function _refused(label, servedDers, anchors) {
  var rv = await _fetch(servedDers, anchors);
  check(label, rv.ok === false && rv.code === "bimi/compromised-key", JSON.stringify(rv));
}

async function testCompromisedAnchorIsRefused() {
  var good = await _fetch([_vmc(CA.control)], [CA.control.der]);
  check("bimi compromised key control: a VMC issued by the control anchor verifies",
        good.ok === true && good.vmcType === "vmc", JSON.stringify(good));

  await _refused("bimi compromised key: a VMC issued by an anchor whose private key is 1 is refused",
    [_vmc(CA.compromised)], [CA.compromised.der]);
  await _refused("bimi compromised key: a listed anchor next to the control anchor is refused",
    [_vmc(CA.control)], [CA.control.der, ck.EDELLROOT_CERT_PEM]);
}

async function testCompromisedServedIntermediateIsRefused() {
  var goodInter = _intermediate(CA.control, ck.labelScalar("prime256v1", "blamejs bimi fixture intermediate"));
  var good = await _fetch([_vmc(goodInter), goodInter.der], [CA.control.der]);
  check("bimi compromised key control: a VMC under a served control intermediate verifies",
        good.ok === true && good.vmcType === "vmc", JSON.stringify(good));

  var badInter = _intermediate(CA.control, 1n);
  await _refused("bimi compromised key: a VMC under a served intermediate whose private key is 1 is refused",
    [_vmc(badInter), badInter.der], [CA.control.der]);
}

async function testACompromisedIntermediateBehindAnExpiredOneIsReportedAsCompromised() {
  function served(d) {
    var upper = _intermediate(CA.control, d);
    var expired = _intermediate(upper, ck.labelScalar("prime256v1", "blamejs bimi fixture expired intermediate"),
      "BIMI Fixture Expired Intermediate", true);
    return [_vmc(expired), expired.der, upper.der];
  }
  var control = await _fetch(served(ck.labelScalar("prime256v1", "blamejs bimi fixture intermediate")), [CA.control.der]);
  check("bimi expired intermediate control: an expired intermediate over an ordinary one is refused as expired",
        control.ok === false && control.code === "bimi/vmc-chain-invalid", JSON.stringify(control));
  await _refused("bimi expired intermediate: an expired intermediate over one whose private key is 1 is refused as compromised",
    served(1n), [CA.control.der]);
}

function _unreadableAnchorDer() {
  var der = Buffer.from(CA.control.der);
  var curveOid = Buffer.from("06082a8648ce3d030107", "hex");
  var at = der.indexOf(curveOid);
  der[at + curveOid.length - 1] = 0x63;
  return der;
}

async function _withLintFailingFor(der, fn) {
  var lint = pki.lint;
  var orig = lint.certificate;
  lint.certificate = function (input) {
    if (Buffer.isBuffer(input) && input.equals(der)) throw new Error("lint could not read the certificate");
    return orig.apply(lint, arguments);
  };
  try { return await fn(); }
  finally { lint.certificate = orig; }
}

async function testAnUnreadableAnchorIsAConfigurationError() {
  var unreadable = _unreadableAnchorDer();
  var bad = await _withLintFailingFor(unreadable, function () {
    return _fetch([_vmc(CA.control)], [CA.control.der, unreadable]);
  });
  check("bimi unreadable anchor: an anchor whose key cannot be checked is refused as a bad trust anchor, " +
        "not as a compromised key",
        bad.ok === false && bad.code === "bimi/vmc-chain-invalid", JSON.stringify(bad));

  var good = await _fetch([_vmc(CA.control)], [CA.control.der, unreadable]);
  check("bimi unreadable anchor control: an anchor whose key node cannot load but lint reads is checked and passes",
        good.ok === true, JSON.stringify(good));
}

async function run() {
  await testCompromisedAnchorIsRefused();
  await testCompromisedServedIntermediateIsRefused();
  await testAnUnreadableAnchorIsAConfigurationError();
  await testACompromisedIntermediateBehindAnExpiredOneIsReportedAsCompromised();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
