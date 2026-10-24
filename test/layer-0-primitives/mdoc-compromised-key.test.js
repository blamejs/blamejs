// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.mdoc refuses issuer-signed data that a compromised key vouches for: an
 * IACA trust anchor whose private key is 1, a document-signer certificate
 * whose key is compromised (with and without trust anchors), and a device
 * key whose private key is 1 in verifyDeviceAuth. Each refusal is paired with
 * a control that differs only in the private scalar.
 */

var helpers    = require("../helpers");
var b          = helpers.b;
var check      = helpers.check;
var nodeCrypto = require("node:crypto");
var asn1       = require("../../lib/asn1-der");
var ck         = require("../helpers/compromised-keys");
var rawCose    = require("../helpers/raw-cose-sign1");
var nodeTypes  = require("node:util").types;

var cbor    = b.cbor;
var NS      = "org.iso.18013.5.1";
var DOCTYPE = "org.iso.18013.5.1.mDL";
var DAY_MS  = b.constants.TIME.days(1);

var DEVICE_BAD     = ck.ecKeyPair("prime256v1", 1n);
var DEVICE_CONTROL = ck.ecKeyPair("prime256v1", ck.labelScalar("prime256v1", "blamejs mdoc compromised-key device"));

async function _code(fn) {
  try { await fn(); return "NO-THROW"; } catch (e) { return e.code || e.message; }
}

function _coseKey(publicKey) {
  return cbor.decode(b.cose.exportKey(publicKey));
}

function _issuerSigned(dsCertDer, dsKey, alg, devicePublicKey) {
  var now = Date.now();
  var inner = cbor.encode(new Map([["digestID", 0], ["random", nodeCrypto.randomBytes(16)],
    ["elementIdentifier", "age_over_18"], ["elementValue", true]]));
  var item = new cbor.Tag(24, inner);
  var digest = nodeCrypto.createHash("sha256").update(cbor.encode(item)).digest();
  var mso = new Map([
    ["version", "1.0"], ["digestAlgorithm", "SHA-256"], ["docType", DOCTYPE],
    ["valueDigests", new Map([[NS, new Map([[0, digest]])]])],
    ["validityInfo", new Map([
      ["signed",     new cbor.Tag(0, new Date(now).toISOString())],
      ["validFrom",  new cbor.Tag(0, new Date(now - DAY_MS).toISOString())],
      ["validUntil", new cbor.Tag(0, new Date(now + 30 * DAY_MS).toISOString())],
    ])],
    ["deviceKeyInfo", new Map([["deviceKey", _coseKey(devicePublicKey)]])],
  ]);
  var signed = rawCose.sign1(cbor.encode(new cbor.Tag(24, cbor.encode(mso))), {
    alg: alg, privateKey: dsKey, unprotectedHeaders: new Map([[33, dsCertDer]]),
  });
  var issuerAuth = cbor.decode(signed, { allowedTags: [18, 24, 0] }).value;
  return cbor.encode(new Map([["nameSpaces", new Map([[NS, [item]]])], ["issuerAuth", issuerAuth]]));
}

function _verify(bytes, alg, anchorsPem) {
  var opts = { algorithms: [alg], expectedDocType: DOCTYPE };
  if (anchorsPem) opts.trustAnchorsPem = anchorsPem;
  else opts.allowUntrustedIssuer = true;
  return b.mdoc.verifyIssuerSigned(bytes, opts);
}

async function testCompromisedTrustAnchorIsRefused() {
  var leafKey = ck.p256AttestationLeafKey();
  var good = _issuerSigned(ck.P256_CONTROL_LEAF_DER, leafKey, "ES256", DEVICE_CONTROL.publicKey);
  var out = await _verify(good, "ES256", ck.certPem(ck.P256_CONTROL_CA_DER));
  check("mdoc compromised key control: a DS certificate issued by the control IACA is trusted",
        out.issuerTrusted === true && out.namespaces[NS].age_over_18 === true);
  var bad = _issuerSigned(ck.P256_COMPROMISED_LEAF_DER, leafKey, "ES256", DEVICE_CONTROL.publicKey);
  check("mdoc compromised key: a DS certificate issued by an IACA whose private key is 1 is refused",
        (await _code(function () { return _verify(bad, "ES256", ck.certPem(ck.P256_COMPROMISED_CA_DER)); })) ===
        "mdoc/compromised-key");
}

async function testCompromisedDocumentSignerIsRefused() {
  var control = ck.p384ControlCa();
  var compromised = ck.p384CompromisedCa();
  var good = _issuerSigned(ck.P384_CONTROL_CA_DER, nodeCrypto.createPrivateKey(control.caKeyPem), "ES384",
    DEVICE_CONTROL.publicKey);
  var bad = _issuerSigned(ck.P384_COMPROMISED_CA_DER, nodeCrypto.createPrivateKey(compromised.caKeyPem), "ES384",
    DEVICE_CONTROL.publicKey);
  var outTrusted = await _verify(good, "ES384", control.caCertPem);
  check("mdoc compromised key control: a self-anchored control DS certificate verifies", outTrusted.issuerTrusted === true);
  var outUntrusted = await _verify(good, "ES384", null);
  check("mdoc compromised key control: the control DS certificate verifies with allowUntrustedIssuer",
        outUntrusted.issuerTrusted === false);
  check("mdoc compromised key: a DS certificate whose private key is 1 is refused with trust anchors",
        (await _code(function () { return _verify(bad, "ES384", compromised.caCertPem); })) === "cose/compromised-key");
  check("mdoc compromised key: a DS certificate whose private key is 1 is refused with allowUntrustedIssuer",
        (await _code(function () { return _verify(bad, "ES384", null); })) === "cose/compromised-key");
}

function _name(cn) {
  return asn1.writeSequence([asn1.writeSet([asn1.writeSequence([asn1.writeOid("2.5.4.3"), asn1.writeUtf8String(cn)])])]);
}
function _utc(d) {
  return asn1.writeNode(0x17, Buffer.from(d.toISOString().replace(/[-:T]/g, "").slice(2, 14) + "Z", "ascii"));
}

function _cert(o) {
  var sigAlg = asn1.writeSequence([asn1.writeOid("1.2.840.10045.4.3.2")]);
  var exts = o.ca ? [asn1.writeSequence([asn1.writeOid("2.5.29.19"), asn1.writeBoolean(true),
    asn1.writeOctetString(asn1.writeSequence([asn1.writeBoolean(true)]))])] : [];
  var children = [
    asn1.writeContextExplicit(0, asn1.writeInteger(Buffer.from([2]))),
    asn1.writeInteger(Buffer.from([o.serial])), sigAlg, _name(o.issuer),
    asn1.writeSequence([_utc(new Date(o.from || Date.now() - DAY_MS)), _utc(new Date(o.to || Date.now() + 365 * DAY_MS))]),
    _name(o.subject), o.pair.publicKey.export({ type: "spki", format: "der" }),
  ];
  if (exts.length) children.push(asn1.writeContextExplicit(3, asn1.writeSequence(exts)));
  var tbs = asn1.writeSequence(children);
  return asn1.writeSequence([tbs, sigAlg, asn1.writeBitString(nodeCrypto.sign("sha256", tbs, o.issuerKey), 0)]);
}

function _pair(label, compromised) {
  return ck.ecKeyPair("prime256v1", compromised ? 1n : ck.labelScalar("prime256v1", "blamejs mdoc chain " + label));
}

// The DS certificate names "IACA Intermediate" as its issuer and the x5chain
// carries two certificates under that name. The one whose key signed the DS
// certificate has expired. The other is valid and its private scalar is 1
// when `compromised` is set, so anyone could have issued the DS certificate
// under it.
async function _expiredAndSecondIssuer(compromised) {
  var root = _pair("root", false);
  var expired = _pair("expired intermediate", false);
  var second = _pair("second intermediate", compromised);
  var ds = _pair("document signer", false);
  var rootDer = _cert({ ca: true, serial: 1, issuer: "IACA Root", subject: "IACA Root", pair: root, issuerKey: root.privateKey });
  var expiredDer = _cert({ ca: true, serial: 3, issuer: "IACA Root", subject: "IACA Intermediate", pair: expired,
    issuerKey: root.privateKey, from: Date.now() - 400 * DAY_MS, to: Date.now() - 30 * DAY_MS });
  var secondDer = _cert({ ca: true, serial: 4, issuer: "IACA Root", subject: "IACA Intermediate", pair: second,
    issuerKey: root.privateKey });
  var dsDer = _cert({ ca: false, serial: 2, issuer: "IACA Intermediate", subject: "Document Signer", pair: ds,
    issuerKey: expired.privateKey });
  var bytes = _issuerSigned([dsDer, expiredDer, secondDer], ds.privateKey, "ES256", DEVICE_CONTROL.publicKey);
  return _code(function () { return _verify(bytes, "ES256", ck.certPem(rootDer)); });
}

// The DS certificate expired 30 days ago. Its IACA's private scalar is 1 when
// `compromised` is set.
async function _expiredSignerUnderRoot(compromised) {
  var root = _pair("root", compromised);
  var ds = _pair("expired document signer", false);
  var rootDer = _cert({ ca: true, serial: 1, issuer: "IACA Root", subject: "IACA Root", pair: root, issuerKey: root.privateKey,
    from: Date.now() - 400 * DAY_MS });
  var dsDer = _cert({ ca: false, serial: 2, issuer: "IACA Root", subject: "Document Signer", pair: ds,
    issuerKey: root.privateKey, from: Date.now() - 400 * DAY_MS, to: Date.now() - 30 * DAY_MS });
  var bytes = _issuerSigned(dsDer, ds.privateKey, "ES256", DEVICE_CONTROL.publicKey);
  return _code(function () { return _verify(bytes, "ES256", ck.certPem(rootDer)); });
}

async function testACompromisedIssuerOutranksAnExpiredOne() {
  check("mdoc compromised key control: an expired issuer beside a valid control issuer is reported as cert-expired",
        (await _expiredAndSecondIssuer(false)) === "mdoc/cert-expired");
  check("mdoc compromised key: an expired issuer beside an issuer whose private key is 1 is reported as compromised-key",
        (await _expiredAndSecondIssuer(true)) === "mdoc/compromised-key");
  check("mdoc compromised key control: an expired DS certificate under the control IACA is reported as cert-expired",
        (await _expiredSignerUnderRoot(false)) === "mdoc/cert-expired");
  check("mdoc compromised key: an expired DS certificate under an IACA whose private key is 1 is reported as compromised-key",
        (await _expiredSignerUnderRoot(true)) === "mdoc/compromised-key");
}

async function testIssuerSignedRefusesACompromisedDeviceKey() {
  var leafKey = ck.p256AttestationLeafKey();
  async function issue(devicePublicKey) {
    return _code(function () {
      return _verify(_issuerSigned(ck.P256_CONTROL_LEAF_DER, leafKey, "ES256", devicePublicKey), "ES256",
        ck.certPem(ck.P256_CONTROL_CA_DER));
    });
  }
  check("mdoc compromised key control: verifyIssuerSigned accepts an MSO carrying the control device key",
        (await issue(DEVICE_CONTROL.publicKey)) === "NO-THROW");
  check("mdoc compromised key: verifyIssuerSigned refuses an MSO carrying a device key whose private key is 1",
        (await issue(DEVICE_BAD.publicKey)) === "mdoc/compromised-key");
  var x25519 = nodeCrypto.generateKeyPairSync("x25519").publicKey.export({ format: "jwk" });
  var ecdhDeviceKey = new Map([[1, 1], [-1, 4], [-2, Buffer.from(x25519.x, "base64url")]]);
  var bytes = _issuerSigned(ck.P256_CONTROL_LEAF_DER, leafKey, "ES256", DEVICE_CONTROL.publicKey);
  var decoded = cbor.decode(bytes, { allowedTags: [18, 24, 0] });
  var issuerAuth = decoded.get("issuerAuth");
  var mso = cbor.decode(cbor.decode(issuerAuth[2], { allowedTags: [24] }).value, { allowedTags: [0] });
  mso.set("deviceKeyInfo", new Map([["deviceKey", ecdhDeviceKey]]));
  var resigned = rawCose.sign1(cbor.encode(new cbor.Tag(24, cbor.encode(mso))), {
    alg: "ES256", privateKey: leafKey, unprotectedHeaders: new Map([[33, ck.P256_CONTROL_LEAF_DER]]),
  });
  decoded.set("issuerAuth", cbor.decode(resigned, { allowedTags: [18, 24, 0] }).value);
  var out = await _verify(cbor.encode(decoded), "ES256", ck.certPem(ck.P256_CONTROL_CA_DER));
  check("mdoc compromised key control: verifyIssuerSigned returns a device key COSE cannot import unchanged",
        nodeTypes.isMap(out.deviceKey) && out.deviceKey.get(-1) === 4);
}

async function testCompromisedDeviceKeyIsRefused() {
  var transcript = cbor.encode([null, null, "compromised-key handover"]);
  var dns = new cbor.Tag(24, cbor.encode(new Map()));
  var st = cbor.decode(transcript);
  var authBytes = cbor.encode(new cbor.Tag(24, cbor.encode(["DeviceAuthentication", st, DOCTYPE, dns])));
  async function run(pair) {
    var sig = rawCose.sign1(authBytes, { alg: "ES256", privateKey: pair.privateKey, detached: true });
    var deviceSigned = cbor.encode(new Map([["nameSpaces", dns],
      ["deviceAuth", new Map([["deviceSignature", cbor.decode(sig, { allowedTags: [18] }).value]])]]));
    var forms = [["COSE_Key", _coseKey(pair.publicKey)], ["KeyObject", pair.publicKey],
      ["PEM", pair.publicKey.export({ type: "spki", format: "pem" })]];
    var codes = [];
    for (var i = 0; i < forms.length; i += 1) {
      var key = forms[i][1];
      codes.push(forms[i][0] + "=" + await _code(function () {
        return b.mdoc.verifyDeviceAuth({ deviceKey: key, deviceSigned: deviceSigned, docType: DOCTYPE,
          sessionTranscript: transcript, algorithms: ["ES256"] });
      }));
    }
    return codes.join(",");
  }
  check("mdoc compromised key control: verifyDeviceAuth accepts the control device key in every form",
        (await run(DEVICE_CONTROL)) === "COSE_Key=NO-THROW,KeyObject=NO-THROW,PEM=NO-THROW");
  var badCodes = await run(DEVICE_BAD);
  check("mdoc compromised key: verifyDeviceAuth refuses a device key whose private key is 1 in every form",
        badCodes === "COSE_Key=cose/compromised-key,KeyObject=cose/compromised-key,PEM=cose/compromised-key", badCodes);
}

async function run() {
  await testCompromisedTrustAnchorIsRefused();
  await testCompromisedDocumentSignerIsRefused();
  await testACompromisedIssuerOutranksAnExpiredOne();
  await testIssuerSignedRefusesACompromisedDeviceKey();
  await testCompromisedDeviceKeyIsRefused();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
