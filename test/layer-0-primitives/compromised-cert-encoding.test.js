// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The verifiers that judge certificates for a compromised key read each
 * certificate the way the signature check reads it, whatever its encoding:
 *
 * - a certificate @blamejs/pki cannot parse (an extension that encodes its
 *   critical flag as an explicit FALSE) is judged by the key node loads;
 * - a DER certificate is read as DER even when it carries PEM text, so an
 *   ordinary key's PEM inside a scalar-1 certificate does not stand in for
 *   the certificate's own key, and a "-----BEGIN junk" line inside an
 *   ordinary certificate does not make it unreadable.
 *
 * Covered: b.tsa.verifyToken (anchored and allowUntrustedIssuer),
 * b.auth.fidoMds3.fetch (caCertificate and x5c), b.auth.passkey
 * (attestationRoots, safetyNetRoots, packed and SafetyNet x5c),
 * b.mdoc.verifyIssuerSigned and the b.contentCredentials identity chain.
 * Every refusal has a control that differs only in the key.
 */

var helpers    = require("../helpers");
var b          = helpers.b;
var check      = helpers.check;
var nodeCrypto = require("node:crypto");
var asn1       = require("../../lib/asn1-der");
var pki        = require("../../lib/vendor/blamejs-pki.cjs");
var ck         = require("../helpers/compromised-keys");
var crafted    = require("../helpers/crafted-compromised-certs");
var rawCose    = require("../helpers/raw-cose-sign1");

var COMPROMISED = crafted.COMPROMISED;
var CONTROL_CA  = crafted.CONTROL_CA;
var LEAF        = crafted.LEAF;

async function _outcome(fn) {
  try { return { ok: true, rv: await fn() }; }
  catch (e) { return { ok: false, code: e.code || e.message, name: e.constructor && e.constructor.name }; }
}

// ---- b.tsa.verifyToken ----------------------------------------------------

var OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2";
var OID_SHA512 = "2.16.840.1.101.3.4.2.3";
var OID_TST_INFO = "1.2.840.113549.1.9.16.1.4";
var GEN_TIME = new Date("2026-03-04T05:06:07Z");
var TSA_ROOT = ck.ecKeyPair("prime256v1", ck.labelScalar("prime256v1", "blamejs cert encoding tsa root"));
var TSA_LEAF = ck.ecKeyPair("prime256v1", ck.labelScalar("prime256v1", "blamejs cert encoding tsa leaf"));

function _name(cn) {
  return asn1.writeSequence([asn1.writeSet([asn1.writeSequence([asn1.writeOid("2.5.4.3"), asn1.writeUtf8String(cn)])])]);
}
function _utc(d) {
  return asn1.writeNode(0x17, Buffer.from(d.toISOString().replace(/[-:T]/g, "").slice(2, 14) + "Z", "ascii"));
}
function _tsaCert(o) {
  var sigAlg = asn1.writeSequence([asn1.writeOid(OID_ECDSA_SHA256)]);
  var exts = [o.ca
    ? asn1.writeSequence([asn1.writeOid("2.5.29.19"), asn1.writeBoolean(true),
      asn1.writeOctetString(asn1.writeSequence([asn1.writeBoolean(true)]))])
    : asn1.writeSequence([asn1.writeOid("2.5.29.37"), asn1.writeBoolean(true),
      asn1.writeOctetString(asn1.writeSequence([asn1.writeOid("1.3.6.1.5.5.7.3.8")]))])];
  if (o.extension) exts.push(o.extension);
  var tbs = asn1.writeSequence([
    asn1.writeContextExplicit(0, asn1.writeInteger(Buffer.from([2]))),
    asn1.writeInteger(Buffer.from([o.serial])), sigAlg, _name(o.issuer),
    asn1.writeSequence([_utc(new Date("2026-01-01T00:00:00Z")), _utc(new Date("2040-01-01T00:00:00Z"))]),
    _name(o.subject), o.pair.publicKey.export({ type: "spki", format: "der" }),
    asn1.writeContextExplicit(3, asn1.writeSequence(exts)),
  ]);
  return asn1.writeSequence([tbs, sigAlg, asn1.writeBitString(nodeCrypto.sign("sha256", tbs, o.issuerKey), 0)]);
}
function _tsaRootDer() {
  return _tsaCert({ ca: true, serial: 1, issuer: "TSA Root", subject: "TSA Root", pair: TSA_ROOT, issuerKey: TSA_ROOT.privateKey });
}
function _tsaSigner(pair, extension) {
  return _tsaCert({ ca: false, serial: 2, issuer: "TSA Root", subject: "TSA Signer", pair: pair,
    issuerKey: TSA_ROOT.privateKey, extension: extension });
}
function _token(leafDer, signingKey, imprint) {
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
    Buffer.concat([Buffer.from([0xa0]), signedSet.subarray(1)]),
    asn1.writeSequence([asn1.writeOid(OID_ECDSA_SHA256)]),
    asn1.writeOctetString(nodeCrypto.sign("sha256", signedSet, signingKey)),
  ]);
  var signedData = asn1.writeSequence([
    asn1.writeInteger(Buffer.from([3])),
    asn1.writeSet([asn1.writeSequence([asn1.writeOid(OID_SHA512), asn1.writeNull()])]),
    asn1.writeSequence([asn1.writeOid(OID_TST_INFO), asn1.writeContextExplicit(0, asn1.writeOctetString(tstInfo))]),
    asn1.writeContextImplicit(0, leafDer, { constructed: true }),
    asn1.writeSet([signerInfo]),
  ]);
  return asn1.writeSequence([asn1.writeOid("1.2.840.113549.1.7.2"), asn1.writeContextExplicit(0, signedData)]);
}

var TSA_DATA = Buffer.from("timestamped artifact", "utf8");

function _verifyTsa(leafDer, signingKey, anchored) {
  var opts = { data: TSA_DATA, hashAlg: "SHA-512" };
  if (anchored) opts.trustAnchorsPem = ck.certPem(_tsaRootDer());
  else opts.allowUntrustedIssuer = true;
  var token = _token(leafDer, signingKey, nodeCrypto.createHash("sha512").update(TSA_DATA).digest());
  return _outcome(function () { return b.tsa.verifyToken(token, opts); });
}

async function testTsaJudgesTheSignerCertificateItVerifies() {
  var modes = [["anchored", true], ["allowUntrustedIssuer", false]];
  var odd = crafted.explicitFalseExtension();
  var keyText = crafted.textExtension(crafted.KEY_PEM_TEXT);
  var junk = crafted.textExtension(crafted.BEGIN_JUNK_TEXT);
  for (var i = 0; i < modes.length; i += 1) {
    var mode = modes[i][0], anchored = modes[i][1];
    var control = await _verifyTsa(_tsaSigner(TSA_LEAF, odd), TSA_LEAF.privateKey, anchored);
    check("tsa cert encoding control (" + mode + "): an ordinary signer whose extension encodes critical FALSE verifies",
          control.ok === true, JSON.stringify(control));
    var bad = await _verifyTsa(_tsaSigner(COMPROMISED, odd), COMPROMISED.privateKey, anchored);
    check("tsa cert encoding (" + mode + "): a scalar-1 signer whose extension encodes critical FALSE is refused",
          bad.ok === false && bad.code === "tsa/compromised-key", JSON.stringify(bad));

    var controlText = await _verifyTsa(_tsaSigner(TSA_LEAF, keyText), TSA_LEAF.privateKey, anchored);
    check("tsa cert encoding control (" + mode + "): an ordinary signer carrying a key's PEM text verifies",
          controlText.ok === true, JSON.stringify(controlText));
    var badText = await _verifyTsa(_tsaSigner(COMPROMISED, keyText), COMPROMISED.privateKey, anchored);
    check("tsa cert encoding (" + mode + "): a scalar-1 signer carrying an ordinary key's PEM text is refused",
          badText.ok === false && badText.code === "tsa/compromised-key", JSON.stringify(badText));

    var withJunk = await _verifyTsa(_tsaSigner(TSA_LEAF, junk), TSA_LEAF.privateKey, anchored);
    check("tsa cert encoding (" + mode + "): an ordinary signer carrying a '-----BEGIN junk' line verifies",
          withJunk.ok === true, JSON.stringify(withJunk));
  }

  var innerBad = _tsaSigner(COMPROMISED, null);
  var outer = _tsaSigner(TSA_LEAF, crafted.textExtension("\n" + ck.certPem(innerBad)));
  check("tsa cert encoding fixture: node's X509Certificate(buffer) reads the scalar-1 certificate inside the signer",
        Buffer.from(new nodeCrypto.X509Certificate(outer).raw).equals(innerBad));
  var outerSigned = await _verifyTsa(outer, TSA_LEAF.privateKey, false);
  check("tsa cert encoding: a token signed by the signer certificate's own key verifies whatever certificate it carries " +
        "as text, and reports that certificate",
        outerSigned.ok === true && outerSigned.rv.signerCertPem === new nodeCrypto.X509Certificate(ck.certPem(outer)).toString(),
        JSON.stringify(outerSigned.ok ? outerSigned.rv.signerCertPem.slice(0, 80) : outerSigned));
  var innerSigned = await _verifyTsa(outer, COMPROMISED.privateKey, false);
  check("tsa cert encoding: a token signed by the key of a scalar-1 certificate written inside the signer certificate " +
        "is refused", innerSigned.ok === false, JSON.stringify(innerSigned));
}

// ---- b.auth.fidoMds3.fetch ------------------------------------------------

function _blob(x5cDers, signingKey) {
  var header = { alg: "ES256", typ: "JWT", x5c: x5cDers.map(function (d) { return Buffer.from(d).toString("base64"); }) };
  var payload = {
    legalHeader: "Test BLOB", no: 7,
    nextUpdate: new Date(Date.now() + b.constants.TIME.days(7)).toISOString().slice(0, 10),
    entries: [],
  };
  var input = Buffer.from(JSON.stringify(header)).toString("base64url") + "." +
    Buffer.from(JSON.stringify(payload)).toString("base64url");
  var sig = nodeCrypto.sign("sha256", Buffer.from(input, "ascii"), { key: signingKey, dsaEncoding: "ieee-p1363" });
  return input + "." + sig.toString("base64url");
}

var _seq = 0;
async function _fetch(token, caCertificate) {
  var hcPath = require.resolve("../../lib/http-client");
  var origHc = require.cache[hcPath].exports;
  require.cache[hcPath].exports = Object.assign({}, origHc, {
    request: async function () {
      return { statusCode: 200, headers: {}, body: Buffer.from(token, "ascii") };            // allow:raw-byte-literal (HTTP success)
    },
  });
  var fmPath = require.resolve("../../lib/auth/fido-mds3");
  delete require.cache[fmPath];
  var fm = require(fmPath);
  _seq += 1;
  try {
    return await _outcome(function () {
      return fm.fetch({ url: "https://mds3-encoding-" + _seq + ".test.invalid/", caCertificate: caCertificate, force: true });
    });
  } finally {
    require.cache[hcPath].exports = origHc;
    delete require.cache[fmPath];
  }
}

async function testFidoMds3JudgesEachCertificateAsItIsRead() {
  var shapes = [["carrying an ordinary certificate's PEM", crafted.textExtension(crafted.CERT_PEM_TEXT)],
                ["whose extension encodes critical FALSE", crafted.explicitFalseExtension()]];
  for (var i = 0; i < shapes.length; i += 1) {
    var badCa = crafted.selfSignedCa(COMPROMISED, shapes[i][1]);
    var goodCa = crafted.selfSignedCa(CONTROL_CA, shapes[i][1]);
    var control = await _fetch(_blob([goodCa], CONTROL_CA.privateKey), ck.certPem(goodCa));
    check("fido mds3 cert encoding control: an ordinary root " + shapes[i][0] + " anchors a BLOB",
          control.ok === true, JSON.stringify(control));
    var bad = await _fetch(_blob([badCa], COMPROMISED.privateKey), ck.certPem(badCa));
    check("fido mds3 cert encoding: a scalar-1 caCertificate " + shapes[i][0] + " is refused",
          bad.ok === false && bad.code === "fido-mds3/compromised-key", JSON.stringify(bad));

    var root = ck.certPem(crafted.selfSignedCa(CONTROL_CA, null));
    var controlLeaf = await _fetch(_blob([crafted.leafUnder(CONTROL_CA, LEAF, shapes[i][1])], LEAF.privateKey), root);
    check("fido mds3 cert encoding control: an ordinary x5c leaf " + shapes[i][0] + " verifies",
          controlLeaf.ok === true, JSON.stringify(controlLeaf));
    var badLeaf = await _fetch(_blob([crafted.leafUnder(CONTROL_CA, COMPROMISED, shapes[i][1])], COMPROMISED.privateKey), root);
    check("fido mds3 cert encoding: a scalar-1 x5c leaf " + shapes[i][0] + " is refused",
          badLeaf.ok === false && badLeaf.code === "fido-mds3/compromised-key", JSON.stringify(badLeaf));
  }
  var junkLeaf = crafted.leafUnder(CONTROL_CA, LEAF, crafted.textExtension(crafted.BEGIN_JUNK_TEXT));
  var junk = await _fetch(_blob([junkLeaf], LEAF.privateKey), ck.certPem(crafted.selfSignedCa(CONTROL_CA, null)));
  check("fido mds3 cert encoding: an ordinary x5c leaf carrying a '-----BEGIN junk' line verifies",
        junk.ok === true, JSON.stringify(junk));
}

// ---- b.auth.passkey -------------------------------------------------------

function _register(opts, extra) {
  var reg = helpers.registerCredential(Object.assign({ rpId: "example.test" }, opts));
  return _outcome(function () {
    return b.auth.passkey.verifyRegistration(Object.assign({
      response: reg.response, expectedChallenge: reg.challenge,
      expectedOrigin: reg.origin, expectedRPID: reg.rpId,
    }, extra || {}));
  });
}

async function testPasskeyRootsAreReadAsTheVerifierReadsThem() {
  var keyLabel = "blamejs passkey cert encoding control";
  var credential = ck.ecKeyPair("prime256v1", ck.labelScalar("prime256v1", keyLabel));
  var badCa = ck.certPem(crafted.selfSignedCa(COMPROMISED, crafted.textExtension(crafted.CERT_PEM_TEXT)));
  var goodCa = ck.certPem(crafted.selfSignedCa(CONTROL_CA, crafted.textExtension(crafted.CERT_PEM_TEXT)));
  var junkCa = ck.certPem(crafted.selfSignedCa(CONTROL_CA, crafted.textExtension(crafted.BEGIN_JUNK_TEXT)));
  var fields = ["attestationRoots", "safetyNetRoots"];
  for (var i = 0; i < fields.length; i += 1) {
    var extra = {};
    extra[fields[i]] = [goodCa];
    var control = await _register({ keyPair: credential }, extra);
    check("passkey cert encoding control: " + fields[i] + " with an ordinary CA carrying a certificate's PEM is accepted",
          control.ok === true && control.rv.verified === true, JSON.stringify(control));
    extra[fields[i]] = [badCa];
    var bad = await _register({ keyPair: credential }, extra);
    check("passkey cert encoding: " + fields[i] + " with a scalar-1 CA carrying an ordinary certificate's PEM is refused",
          bad.ok === false && bad.code === "auth-passkey/compromised-key", JSON.stringify(bad));
    extra[fields[i]] = [junkCa];
    var junk = await _register({ keyPair: credential }, extra);
    check("passkey cert encoding: " + fields[i] + " with an ordinary CA carrying a '-----BEGIN junk' line is accepted",
          junk.ok === true && junk.rv.verified === true, JSON.stringify(junk));
  }
}

async function testPasskeyPackedChainIsReadAsDer() {
  var caDer = crafted.selfSignedCa(CONTROL_CA, null);
  function packed(leafPair, extension) {
    return _register({ attestation: { fmt: "packed", x5c: [crafted.leafUnder(CONTROL_CA, leafPair, extension), caDer],
      signingKey: leafPair.privateKey } });
  }
  var certText = crafted.textExtension(crafted.CERT_PEM_TEXT);
  var control = await packed(LEAF, certText);
  check("passkey cert encoding control: a packed leaf carrying a certificate's PEM verifies",
        control.ok === true && control.rv.verified === true, JSON.stringify(control));
  var bad = await packed(COMPROMISED, certText);
  check("passkey cert encoding: a scalar-1 packed leaf carrying an ordinary certificate's PEM is refused",
        bad.ok === false && bad.code === "auth-passkey/compromised-key", JSON.stringify(bad));
  var junk = await packed(LEAF, crafted.textExtension(crafted.BEGIN_JUNK_TEXT));
  check("passkey cert encoding: an ordinary packed leaf carrying a '-----BEGIN junk' line verifies",
        junk.ok === true && junk.rv.verified === true, JSON.stringify(junk));
}

// An RSA attest.android.com leaf issued under the control CA's name and key
// identifier and signed by `issuerKey`.
async function _safetyNetLeaf(issuerKey) {
  var leafPair = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });         // allow:raw-byte-literal — RSA key size
  var caKey = await pki.webcrypto.subtle.importKey("jwk", CONTROL_CA.privateKey.export({ format: "jwk" }),
    { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  var leaf = Buffer.from(await pki.x509.sign({
    subject:          [{ commonName: "attest.android.com" }],
    subjectPublicKey: leafPair.publicKey.export({ type: "spki", format: "der" }),
    serialNumber:     "0x03",
    notBefore:        new Date(Date.now() - b.constants.TIME.days(1)),
    notAfter:         new Date(Date.now() + b.constants.TIME.days(365)),
    extensions:       { basicConstraints: { cA: false } },
  }, { cert: ck.P256_CONTROL_CA_DER, key: caKey }));
  return { leaf: crafted.rebuild(leaf, { signingKey: issuerKey }), signingKey: leafPair.privateKey };
}

async function testPasskeySafetyNetChainIsReadAsDer() {
  var certText = crafted.textExtension(crafted.CERT_PEM_TEXT);
  async function safetyNet(caPair) {
    var caDer = crafted.rebuild(ck.P256_CONTROL_CA_DER,
      { publicKey: caPair.publicKey, signingKey: CONTROL_CA.privateKey, extension: certText });
    var leaf = await _safetyNetLeaf(caPair.privateKey);
    return _register({ attestation: { fmt: "android-safetynet", x5c: [leaf.leaf, caDer], signingKey: leaf.signingKey } },
      { safetyNetRoots: [ck.certPem(crafted.selfSignedCa(CONTROL_CA, null))] });
  }
  var control = await safetyNet(CONTROL_CA);
  check("passkey cert encoding control: a SafetyNet chain whose CA carries a certificate's PEM verifies",
        control.ok === true && control.rv.verified === true, JSON.stringify(control));
  var bad = await safetyNet(COMPROMISED);
  check("passkey cert encoding: a SafetyNet chain whose scalar-1 CA carries an ordinary certificate's PEM is refused",
        bad.ok === false && bad.code === "auth-passkey/compromised-key", JSON.stringify(bad));
}

// ---- b.mdoc.verifyIssuerSigned --------------------------------------------

var MDOC_NS = "org.iso.18013.5.1";
var MDOC_DOCTYPE = "org.iso.18013.5.1.mDL";
var MDOC_DEVICE = ck.ecKeyPair("prime256v1", ck.labelScalar("prime256v1", "blamejs cert encoding mdoc device"));

function _issuerSigned(dsCertDer, dsKey) {
  var cbor = b.cbor;
  var now = Date.now();
  var inner = cbor.encode(new Map([["digestID", 0], ["random", nodeCrypto.randomBytes(16)],
    ["elementIdentifier", "age_over_18"], ["elementValue", true]]));
  var item = new cbor.Tag(24, inner);
  var digest = nodeCrypto.createHash("sha256").update(cbor.encode(item)).digest();
  var mso = new Map([
    ["version", "1.0"], ["digestAlgorithm", "SHA-256"], ["docType", MDOC_DOCTYPE],
    ["valueDigests", new Map([[MDOC_NS, new Map([[0, digest]])]])],
    ["validityInfo", new Map([
      ["signed",     new cbor.Tag(0, new Date(now).toISOString())],
      ["validFrom",  new cbor.Tag(0, new Date(now - b.constants.TIME.days(1)).toISOString())],
      ["validUntil", new cbor.Tag(0, new Date(now + b.constants.TIME.days(30)).toISOString())],
    ])],
    ["deviceKeyInfo", new Map([["deviceKey", cbor.decode(b.cose.exportKey(MDOC_DEVICE.publicKey))]])],
  ]);
  var signed = rawCose.sign1(cbor.encode(new cbor.Tag(24, cbor.encode(mso))), {
    alg: "ES256", privateKey: dsKey, unprotectedHeaders: new Map([[33, dsCertDer]]),
  });
  var issuerAuth = cbor.decode(signed, { allowedTags: [18, 24, 0] }).value;
  return cbor.encode(new Map([["nameSpaces", new Map([[MDOC_NS, [item]]])], ["issuerAuth", issuerAuth]]));
}

function _verifyMdoc(dsCertDer, dsKey, anchorDer) {
  return _outcome(function () {
    return b.mdoc.verifyIssuerSigned(_issuerSigned(dsCertDer, dsKey),
      { algorithms: ["ES256"], expectedDocType: MDOC_DOCTYPE, trustAnchorsPem: ck.certPem(anchorDer) });
  });
}

async function testMdocJudgesTheCertificatesItVerifies() {
  var odd = crafted.explicitFalseExtension();
  var control = await _verifyMdoc(crafted.leafUnder(CONTROL_CA, LEAF, null), LEAF.privateKey,
    crafted.selfSignedCa(CONTROL_CA, odd));
  check("mdoc cert encoding control: an ordinary IACA whose extension encodes critical FALSE anchors the DS certificate",
        control.ok === true && control.rv.issuerTrusted === true, JSON.stringify(control));
  var bad = await _verifyMdoc(crafted.leafUnder(COMPROMISED, LEAF, null), LEAF.privateKey,
    crafted.selfSignedCa(COMPROMISED, odd));
  check("mdoc cert encoding: a scalar-1 IACA whose extension encodes critical FALSE is refused",
        bad.ok === false && bad.code === "mdoc/compromised-key", JSON.stringify(bad));

  var carrying = crafted.leafUnder(CONTROL_CA, LEAF, crafted.textExtension("\n" + ck.certPem(ck.P256_COMPROMISED_CA_DER)));
  var ownKey = await _verifyMdoc(carrying, LEAF.privateKey, crafted.selfSignedCa(CONTROL_CA, null));
  check("mdoc cert encoding: a DS certificate carrying a scalar-1 certificate's PEM verifies with its own key",
        ownKey.ok === true && ownKey.rv.issuerTrusted === true, JSON.stringify(ownKey));
  var textKey = await _verifyMdoc(carrying, COMPROMISED.privateKey, crafted.selfSignedCa(CONTROL_CA, null));
  check("mdoc cert encoding: a signature by the key of the certificate written inside the DS certificate is refused",
        textKey.ok === false, JSON.stringify(textKey));
}

// ---- b.contentCredentials identity chain ----------------------------------

async function testContentCredentialsNamesAnUnreadableCertificate() {
  var cc = b.contentCredentials;
  var pair = b.crypto.generateSigningKeyPair();
  var refs = [{ label: "c2pa.actions", data: { action: "c2pa.created" } }];
  var ia = cc.attachIdentityAssertion({
    binding: "x509", subject: { name: "n" }, referencedAssertions: refs, privateKeyPem: pair.privateKey, audit: false,
  });
  var leafPem = ck.certPem(crafted.leafUnder(CONTROL_CA, LEAF, null));
  var unreadablePem = ck.certPem(crafted.unreadableCa());
  function verify(chain, anchors) {
    return cc.verifyIdentityAssertion(ia, pair.publicKey, {
      referencedAssertions: refs, identityCertChainPem: chain, identityTrustAnchorsPem: anchors, audit: false,
    });
  }
  var control = verify([leafPem], [ck.certPem(crafted.selfSignedCa(CONTROL_CA, null))]);
  check("content credentials cert encoding control: the leaf chains to the ordinary anchor and stops at the claim key",
        control.valid === true && control.reason === "leaf-key-mismatch", JSON.stringify(control.reason));
  var chainUnreadable = verify([unreadablePem], [ck.certPem(crafted.selfSignedCa(CONTROL_CA, null))]);
  check("content credentials cert encoding: a chain certificate whose key cannot be checked is bad-chain-cert",
        chainUnreadable.valid === true && chainUnreadable.verified === false &&
        chainUnreadable.reason === "bad-chain-cert", JSON.stringify(chainUnreadable.reason));
  var anchorUnreadable = verify([leafPem], [unreadablePem]);
  check("content credentials cert encoding: an anchor whose key cannot be checked anchors nothing",
        anchorUnreadable.valid === true && anchorUnreadable.verified === false &&
        anchorUnreadable.reason === "untrusted-chain", JSON.stringify(anchorUnreadable.reason));
}

async function run() {
  await testTsaJudgesTheSignerCertificateItVerifies();
  await testFidoMds3JudgesEachCertificateAsItIsRead();
  await testPasskeyRootsAreReadAsTheVerifierReadsThem();
  await testPasskeyPackedChainIsReadAsDer();
  await testPasskeySafetyNetChainIsReadAsDer();
  await testMdocJudgesTheCertificatesItVerifies();
  await testContentCredentialsNamesAnUnreadableCertificate();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
