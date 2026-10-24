// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.auth.saml refuses a compromised key on every path that trusts or uses
 * one: the IdP certificate given to sp.create (and one swapped in after
 * create), the federation certificate fetchMdq verifies metadata with, the
 * Single Logout verification key on the redirect and embedded-signature
 * bindings, the SP's own logout signing key, the SP key that decrypts an
 * EncryptedAssertion, and the holder-of-key certificate an assertion binds. Each compromised key is the P-256 key
 * whose private scalar is 1; each control differs only in the key.
 */

var helpers    = require("../helpers");
var b          = helpers.b;
var check      = helpers.check;
var nodeCrypto = require("node:crypto");
var zlib       = require("node:zlib");
var c14n       = require("../../lib/xml-c14n");
var ck         = require("../helpers/compromised-keys");

var DS  = "http://www.w3.org/2000/09/xmldsig#";
var EXC = "http://www.w3.org/2001/10/xml-exc-c14n#";
var MD  = "urn:oasis:names:tc:SAML:2.0:metadata";
var ECDSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
var BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
var HOK    = "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key";
var SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";

var IDP_ENTITY_ID = "https://idp.example";
var SP_ENTITY_ID  = "https://sp.example";
var ACS_URL       = "https://sp.example/saml/acs";

var CA_SCALAR = BigInt("0x" + nodeCrypto.createHash("sha256")
  .update("blamejs passkey attestation fixture CA", "utf8").digest("hex"));

// { certPem, privateKey, publicPem } for the P-256 CA fixtures: a certificate
// whose key has private scalar 1, and its control twin.
var COMPROMISED = {
  certPem:    ck.certPem(ck.P256_COMPROMISED_CA_DER),
  privateKey: ck.ecKeyPair("prime256v1", 1n).privateKey,
  publicPem:  ck.ecKeyPair("prime256v1", 1n).publicKey.export({ type: "spki", format: "pem" }),
};
var CONTROL = {
  certPem:    ck.certPem(ck.P256_CONTROL_CA_DER),
  privateKey: ck.ecKeyPair("prime256v1", CA_SCALAR).privateKey,
  publicPem:  ck.ecKeyPair("prime256v1", CA_SCALAR).publicKey.export({ type: "spki", format: "pem" }),
};

function iso(ms) { return new Date(Date.now() + ms).toISOString(); }
function _certBody(pem) {
  return pem.replace(/-----(BEGIN|END) CERTIFICATE-----/g, "").replace(/\s+/g, "");
}
function _code(fn) {
  try { fn(); return "NO-THROW"; } catch (e) { return e.code || e.message; }
}
async function _codeAsync(fn) {
  try { await fn(); return "NO-THROW"; } catch (e) { return e.code || e.message; }
}
function _spOpts(idpCertPem) {
  return {
    entityId: SP_ENTITY_ID, assertionConsumerServiceUrl: ACS_URL,
    idpEntityId: IDP_ENTITY_ID, idpSsoUrl: "https://idp.example/sso",
    idpSloUrl: "https://idp.example/slo", idpCertPem: idpCertPem,
  };
}

// An enveloped ecdsa-sha256 ds:Signature over `elementXml` (whose ID is
// refId), canonicalized through b.xmlC14n as the verifier does.
function _signature(privateKey, refId, elementXml) {
  var digest = nodeCrypto.createHash("sha256").update(c14n.canonicalize(elementXml)).digest("base64");
  var signedInfo =
    "<ds:SignedInfo xmlns:ds=\"" + DS + "\">" +
    "<ds:CanonicalizationMethod Algorithm=\"" + EXC + "\"></ds:CanonicalizationMethod>" +
    "<ds:SignatureMethod Algorithm=\"" + ECDSA_SHA256 + "\"></ds:SignatureMethod>" +
    "<ds:Reference URI=\"#" + refId + "\"><ds:Transforms>" +
    "<ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"></ds:Transform>" +
    "<ds:Transform Algorithm=\"" + EXC + "\"></ds:Transform></ds:Transforms>" +
    "<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"></ds:DigestMethod>" +
    "<ds:DigestValue>" + digest + "</ds:DigestValue></ds:Reference></ds:SignedInfo>";
  var sig = nodeCrypto.sign("sha256", c14n.canonicalize(signedInfo), { key: privateKey, dsaEncoding: "der" });
  return "<ds:Signature xmlns:ds=\"" + DS + "\">" + signedInfo +
    "<ds:SignatureValue>" + sig.toString("base64") + "</ds:SignatureValue></ds:Signature>";
}

// A SAML Response whose Assertion carries `confirmationXml` and an
// assertion-level signature by `privateKey`.
function _response(privateKey, confirmationXml) {
  var id = "_a" + nodeCrypto.randomBytes(8).toString("hex");
  var open = "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"" + id +
    "\" Version=\"2.0\" IssueInstant=\"" + iso(0) + "\">";
  var body = "<saml:Subject><saml:NameID>victim@example.com</saml:NameID>" + confirmationXml +
    "</saml:Subject><saml:Conditions NotBefore=\"" + iso(-60000) + "\" NotOnOrAfter=\"" + iso(300000) + "\">" +
    "<saml:AudienceRestriction><saml:Audience>" + SP_ENTITY_ID + "</saml:Audience></saml:AudienceRestriction>" +
    "</saml:Conditions>";
  var issuer = "<saml:Issuer>" + IDP_ENTITY_ID + "</saml:Issuer>";
  var unsigned = open + issuer + body + "</saml:Assertion>";
  var signed = open + issuer + _signature(privateKey, id, unsigned) + body + "</saml:Assertion>";
  var xml = "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" " +
    "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_r" + id + "\" Version=\"2.0\" IssueInstant=\"" +
    iso(0) + "\" Destination=\"" + ACS_URL + "\"><saml:Issuer>" + IDP_ENTITY_ID + "</saml:Issuer>" +
    "<samlp:Status><samlp:StatusCode Value=\"" + SUCCESS + "\"/></samlp:Status>" + signed + "</samlp:Response>";
  return Buffer.from(xml, "utf8").toString("base64");
}

function _bearer() {
  return "<saml:SubjectConfirmation Method=\"" + BEARER + "\"><saml:SubjectConfirmationData NotOnOrAfter=\"" +
    iso(300000) + "\" Recipient=\"" + ACS_URL + "\"/></saml:SubjectConfirmation>";
}
function _holderOfKey(certPem) {
  return "<saml:SubjectConfirmation Method=\"" + HOK + "\"><saml:SubjectConfirmationData NotOnOrAfter=\"" +
    iso(300000) + "\" Recipient=\"" + ACS_URL + "\"><ds:KeyInfo xmlns:ds=\"" + DS + "\"><ds:X509Data>" +
    "<ds:X509Certificate>" + _certBody(certPem) + "</ds:X509Certificate></ds:X509Data></ds:KeyInfo>" +
    "</saml:SubjectConfirmationData></saml:SubjectConfirmation>";
}

function testCreateRefusesACompromisedIdpCertificate() {
  check("saml compromised key control: create accepts an ordinary IdP certificate",
        _code(function () { b.auth.saml.sp.create(_spOpts(CONTROL.certPem)); }) === "NO-THROW");
  check("saml compromised key: create refuses an IdP certificate whose private key is 1",
        _code(function () { b.auth.saml.sp.create(_spOpts(COMPROMISED.certPem)); }) === "auth-saml/compromised-key");
  check("saml compromised key: create refuses the IdP key given as a bare public-key PEM",
        _code(function () { b.auth.saml.sp.create(_spOpts(COMPROMISED.publicPem)); }) === "auth-saml/compromised-key");
  check("saml compromised key: create refuses the eDellRoot certificate",
        _code(function () { b.auth.saml.sp.create(_spOpts(ck.EDELLROOT_CERT_PEM)); }) === "auth-saml/compromised-key");
}

function testVerifyResponseRefusesAKeySwappedInAfterCreate() {
  var opts = _spOpts(CONTROL.certPem);
  var sp = b.auth.saml.sp.create(opts);
  var good = sp.verifyResponse(_response(CONTROL.privateKey, _bearer()));
  check("saml compromised key control: a response signed by the ordinary IdP key verifies",
        good.nameId === "victim@example.com");
  opts.idpCertPem = COMPROMISED.certPem;
  check("saml compromised key: a response verified against a compromised IdP certificate set after create is refused",
        _code(function () { sp.verifyResponse(_response(COMPROMISED.privateKey, _bearer())); }) ===
          "auth-saml/compromised-key");
}

function testHolderOfKeyRefusesACompromisedBoundKey() {
  var idp = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var sp = b.auth.saml.sp.create(_spOpts(idp.publicKey.export({ type: "spki", format: "pem" })));
  var good = sp.verifyResponse(_response(idp.privateKey, _holderOfKey(CONTROL.certPem)),
    { holderOfKey: { presentedCertPem: CONTROL.certPem } });
  check("saml compromised key control: a holder-of-key assertion bound to an ordinary key verifies",
        good.nameId === "victim@example.com");
  check("saml compromised key: a holder-of-key assertion bound to a key whose private key is 1 is refused",
        _code(function () {
          sp.verifyResponse(_response(idp.privateKey, _holderOfKey(COMPROMISED.certPem)),
            { holderOfKey: { presentedCertPem: COMPROMISED.certPem } });
        }) === "auth-saml/compromised-key");
}

// A Response carrying an RSA-OAEP-SHA256 + AES-256-GCM EncryptedAssertion
// whose wrapped key no SP key unwraps.
function _encryptedResponse() {
  var XENC = "http://www.w3.org/2001/04/xmlenc#";
  var enc = "<saml:EncryptedAssertion><xenc:EncryptedData xmlns:xenc=\"" + XENC + "\">" +
    "<xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#aes256-gcm\"></xenc:EncryptionMethod>" +
    "<ds:KeyInfo xmlns:ds=\"" + DS + "\"><xenc:EncryptedKey xmlns:xenc=\"" + XENC + "\">" +
    "<xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#rsa-oaep\">" +
    "<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"></ds:DigestMethod>" +
    "</xenc:EncryptionMethod><xenc:CipherData><xenc:CipherValue>" +
    nodeCrypto.randomBytes(256).toString("base64") +                                               // allow:raw-byte-literal — RSA-2048 block
    "</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo>" +
    "<xenc:CipherData><xenc:CipherValue>AA==</xenc:CipherValue></xenc:CipherData>" +
    "</xenc:EncryptedData></saml:EncryptedAssertion>";
  var xml = "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" " +
    "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_renc\" Version=\"2.0\" IssueInstant=\"" +
    iso(0) + "\" Destination=\"" + ACS_URL + "\"><saml:Issuer>" + IDP_ENTITY_ID + "</saml:Issuer>" +
    "<samlp:Status><samlp:StatusCode Value=\"" + SUCCESS + "\"/></samlp:Status>" + enc + "</samlp:Response>";
  return Buffer.from(xml, "utf8").toString("base64");
}

function testEncryptedAssertionRefusesACompromisedSpKey() {
  var sp = b.auth.saml.sp.create(_spOpts(CONTROL.certPem));
  var controlPem = CONTROL.privateKey.export({ type: "pkcs8", format: "pem" });
  var badPem = COMPROMISED.privateKey.export({ type: "pkcs8", format: "pem" });
  check("saml compromised key control: an ordinary spPrivateKeyPem reaches the key unwrap",
        _code(function () { sp.verifyResponse(_encryptedResponse(), { spPrivateKeyPem: controlPem }); }) ===
          "auth-saml/encrypted-key-unwrap-failed");
  check("saml compromised key: an spPrivateKeyPem whose private key is 1 is refused before it decrypts anything",
        _code(function () { sp.verifyResponse(_encryptedResponse(), { spPrivateKeyPem: badPem }); }) ===
          "auth-saml/compromised-key");
  check("saml compromised key control: an spPrivateKeyPem that does not parse keeps its own refusal",
        _code(function () { sp.verifyResponse(_encryptedResponse(), { spPrivateKeyPem: "not-a-key" }); }) ===
          "auth-saml/encrypted-bad-sp-key");
}

async function _fetchMdqWith(metadataXml, trustCertPem) {
  var hcPath = require.resolve("../../lib/http-client");
  var origHc = require.cache[hcPath].exports;
  require.cache[hcPath].exports = Object.assign({}, origHc, {
    request: async function () {
      return { statusCode: 200, headers: {}, body: Buffer.from(metadataXml, "utf8") };
    },
  });
  var samlPath = require.resolve("../../lib/auth/saml");
  delete require.cache[samlPath];
  var saml = require(samlPath);
  try {
    return await _codeAsync(function () {
      return saml.fetchMdq({ baseUrl: "https://mdq.test.invalid", entityId: IDP_ENTITY_ID, trustCertPem: trustCertPem });
    });
  } finally {
    require.cache[hcPath].exports = origHc;
    delete require.cache[samlPath];
  }
}

function _signedMetadata(privateKey) {
  var entity = "<md:EntityDescriptor xmlns:md=\"" + MD + "\" ID=\"M1\" entityID=\"" + IDP_ENTITY_ID + "\">" +
    "<md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">" +
    "<md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" " +
    "Location=\"https://attacker.example/sso\"/></md:IDPSSODescriptor></md:EntityDescriptor>";
  var at = entity.indexOf(">") + 1;
  return entity.slice(0, at) + _signature(privateKey, "M1", entity) + entity.slice(at);
}

async function testFetchMdqRefusesACompromisedFederationCertificate() {
  check("saml compromised key control: fetchMdq accepts metadata signed by an ordinary federation key",
        (await _fetchMdqWith(_signedMetadata(CONTROL.privateKey), CONTROL.certPem)) === "NO-THROW");
  check("saml compromised key: fetchMdq refuses a federation certificate whose private key is 1",
        (await _fetchMdqWith(_signedMetadata(COMPROMISED.privateKey), COMPROMISED.certPem)) ===
          "auth-saml/compromised-key");
}

function _redirect(kind, xml, privateKey) {
  var query = kind + "=" + encodeURIComponent(zlib.deflateRawSync(Buffer.from(xml, "utf8")).toString("base64")) +
    "&SigAlg=" + encodeURIComponent(ECDSA_SHA256);
  var sig = nodeCrypto.sign("sha256", Buffer.from(query, "utf8"), { key: privateKey, dsaEncoding: "der" });
  return { samlB64: zlib.deflateRawSync(Buffer.from(xml, "utf8")).toString("base64"),
           queryString: query + "&Signature=" + encodeURIComponent(sig.toString("base64")) };
}

function testRedirectLogoutRefusesACompromisedVerifyKey() {
  var sp = b.auth.saml.sp.create(_spOpts(CONTROL.certPem));
  var request = sp.buildLogoutRequest({ nameId: "victim@idp", sessionIndex: "_s-any" }).raw;
  var response = sp.buildLogoutResponse({ inResponseTo: "_x", destination: "https://idp.example/slo" }).raw;
  [["SAMLRequest", request, "parseLogoutRequest"], ["SAMLResponse", response, "parseLogoutResponse"]]
    .forEach(function (c) {
      var good = _redirect(c[0], c[1], CONTROL.privateKey);
      check("saml compromised key control: " + c[2] + " verifies a redirect signed by an ordinary key",
            _code(function () {
              sp[c[2]](good.samlB64, { queryString: good.queryString, idpVerifyKey: CONTROL.publicPem, idpVerifyAlg: "ecdsa-sha256" });
            }) === "NO-THROW");
      var bad = _redirect(c[0], c[1], COMPROMISED.privateKey);
      check("saml compromised key: " + c[2] + " refuses a verify key whose private key is 1",
            _code(function () {
              sp[c[2]](bad.samlB64, { queryString: bad.queryString, idpVerifyKey: COMPROMISED.publicPem, idpVerifyAlg: "ecdsa-sha256" });
            }) === "auth-saml/compromised-key");
    });
}

// The POST-binding LogoutRequest the SP builds, re-signed by `privateKey`.
function _postLogoutRequest(sp, privateKey) {
  var built = sp.buildLogoutRequestPost({
    nameId: "victim@idp", sessionIndex: "_s-any",
    signingKey: CONTROL.privateKey, signingAlg: "ecdsa-sha256",
  });
  var xml = Buffer.from(built.samlRequest, "base64").toString("utf8");
  var siStart = xml.indexOf("<ds:SignedInfo");
  var siEnd = xml.indexOf("</ds:SignedInfo>") + "</ds:SignedInfo>".length;
  var signedInfo = xml.slice(siStart, siEnd);
  var sig = nodeCrypto.sign("sha256", c14n.canonicalize(c14n.parse(signedInfo)), { key: privateKey, dsaEncoding: "der" });
  var resigned = xml.replace(/<ds:SignatureValue>[^<]*<\/ds:SignatureValue>/,
    "<ds:SignatureValue>" + sig.toString("base64") + "</ds:SignatureValue>");
  return Buffer.from(resigned, "utf8").toString("base64");
}

function testEmbeddedLogoutRefusesACompromisedVerifyKey() {
  var sp = b.auth.saml.sp.create(_spOpts(CONTROL.certPem));
  check("saml compromised key control: parseLogoutRequestPost verifies an embedded signature by an ordinary key",
        _code(function () {
          sp.parseLogoutRequestPost(_postLogoutRequest(sp, CONTROL.privateKey),
            { idpVerifyKey: CONTROL.publicPem, idpVerifyAlg: "ecdsa-sha256" });
        }) === "NO-THROW");
  check("saml compromised key: parseLogoutRequestPost refuses a verify key whose private key is 1",
        _code(function () {
          sp.parseLogoutRequestPost(_postLogoutRequest(sp, COMPROMISED.privateKey),
            { idpVerifyKey: COMPROMISED.publicPem, idpVerifyAlg: "ecdsa-sha256" });
        }) === "auth-saml/compromised-key");
}

function testLogoutSigningRefusesACompromisedKey() {
  var sp = b.auth.saml.sp.create(_spOpts(CONTROL.certPem));
  var badPem = COMPROMISED.privateKey.export({ type: "pkcs8", format: "pem" });
  check("saml compromised key control: buildLogoutRequest signs with an ordinary key",
        _code(function () {
          sp.buildLogoutRequest({ nameId: "a", signingKey: CONTROL.privateKey, signingAlg: "ecdsa-sha256" });
        }) === "NO-THROW");
  check("saml compromised key: buildLogoutRequest refuses to sign with a key whose private key is 1",
        _code(function () {
          sp.buildLogoutRequest({ nameId: "a", signingKey: badPem, signingAlg: "ecdsa-sha256" });
        }) === "auth-saml/compromised-key");
  check("saml compromised key: buildLogoutResponse refuses the compromised signing key",
        _code(function () {
          sp.buildLogoutResponse({ inResponseTo: "_x", destination: "https://idp.example/slo",
            signingKey: COMPROMISED.privateKey, signingAlg: "ecdsa-sha256" });
        }) === "auth-saml/compromised-key");
  check("saml compromised key: buildLogoutRequestPost refuses the compromised signing key",
        _code(function () {
          sp.buildLogoutRequestPost({ nameId: "a", signingKey: COMPROMISED.privateKey, signingAlg: "ecdsa-sha256" });
        }) === "auth-saml/compromised-key");
}

async function run() {
  testCreateRefusesACompromisedIdpCertificate();
  testVerifyResponseRefusesAKeySwappedInAfterCreate();
  testHolderOfKeyRefusesACompromisedBoundKey();
  testEncryptedAssertionRefusesACompromisedSpKey();
  await testFetchMdqRefusesACompromisedFederationCertificate();
  testRedirectLogoutRefusesACompromisedVerifyKey();
  testEmbeddedLogoutRefusesACompromisedVerifyKey();
  testLogoutSigningRefusesACompromisedKey();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
