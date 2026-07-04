// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.auth.saml.sp — supplementary branch-coverage sweep.
 *
 * auth-saml-coverage.test.js already drives the create() validation, the
 * buildAuthnRequest / metadata escaping, the pre-signature structural
 * refusals, the assertion-level happy path, and the SLO redirect/POST/SOAP
 * validation surface. This file closes the remaining error / defensive /
 * adversarial branches that suite leaves untouched:
 *
 *   - _verifyXmldsig structural refusals reached through a hostile Signature
 *     block (missing SignedInfo, unsupported c14n / sig-alg / digest / transform,
 *     external Reference, empty DigestValue, zero-match + duplicate-ID anti-
 *     wrapping, empty SignatureValue), the ECDSA verify path, and the
 *     exclusive-c14n WithComments variant;
 *   - verifyResponse post-signature branches: Response-level signature, the
 *     assertion/response signed-different-element wrapping guard, every Bearer
 *     SubjectConfirmation fail-closed skip → no-valid-confirmation, the full
 *     holder-of-key possession-proof path (success + every refusal), Conditions
 *     unparseable-timestamp refusals, AND-combined AudienceRestriction, and the
 *     no-AuthnStatement / no-Conditions shapes;
 *   - EncryptedAssertion decrypt: the RSA-OAEP-SHA256 + AES-256-GCM round trip
 *     plus every structural / unwrap / content-length / tag-mismatch refusal;
 *   - the SLO embedded-XMLDSig classical (RSA/ECDSA) + Ed25519 sign/verify round
 *     trips, the redirect Ed25519 + parseLogoutResponse signature paths, and the
 *     parse-side error branches (wrong-root, no-nameid, bad-verify-alg, digest-
 *     mismatch, wrong-sig-alg, not-a-logout-*);
 *   - fetchMdq transport + verification branches (non-2xx, empty body, no-trust
 *     skip, unsigned, duplicate-signature, entity-mismatch) driven through a
 *     require-cache transport fake — no external endpoint.
 *
 * Signed fixtures build each assertion body ONCE with a signature placeholder,
 * so the signed bytes and the verified bytes are identical; the IdP signature +
 * digest + SignedInfo are computed through the framework's own b.xmlC14n so
 * verifyResponse's recomputation matches with no test bypass of the crypto gate.
 */

var helpers    = require("../helpers");
var check      = helpers.check;
var b          = helpers.b;
var nodeCrypto = require("node:crypto");
var zlib       = require("node:zlib");
var c14n       = require("../../lib/xml-c14n");
var pq         = require("../../lib/pqc-software");

var C = b.constants;

var DS  = "http://www.w3.org/2000/09/xmldsig#";
var EXC = "http://www.w3.org/2001/10/xml-exc-c14n#";
var SAML_A = "urn:oasis:names:tc:SAML:2.0:assertion";
var SAML_P = "urn:oasis:names:tc:SAML:2.0:protocol";
var XENC = "http://www.w3.org/2001/04/xmlenc#";

var IDP_ENTITY_ID = "https://idp.example";
var SP_ENTITY_ID  = "https://sp.example";
var ACS_URL       = "https://sp.example/saml/acs";
var IDP_SSO_URL   = "https://idp.example/sso";
var IDP_SLO_URL   = "https://idp.example/slo";
var FAKE_CERT     = "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----";

var BEARER  = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
var HOK     = "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key";
var SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";
var EMAIL   = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
var STATUS_OK = "<samlp:Status><samlp:StatusCode Value=\"" + SUCCESS + "\"/></samlp:Status>";
var RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
var ENVELOPED  = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
var MLDSA65_URN = "urn:blamejs:experimental:saml-sig-alg:ml-dsa-65";
var SHA3_512    = "http://www.w3.org/2007/05/xmldsig-more#sha3-512";
var XCHACHA_URN = "urn:blamejs:experimental:xmlenc:xchacha20-poly1305";

function iso(ms) { return new Date(Date.now() + ms).toISOString(); }
function b64(xml) { return Buffer.from(xml, "utf8").toString("base64"); }
function _codeOf(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code || e.message; } }
function _verifyCode(sp, xmlB64, vopts) { return _codeOf(function () { sp.verifyResponse(xmlB64, vopts || {}); }); }
function _response(inner) {
  return "<samlp:Response xmlns:samlp=\"" + SAML_P + "\" xmlns:saml=\"" + SAML_A + "\" ID=\"_r\">" + inner + "</samlp:Response>";
}
function _certBody(pem) {
  return pem.replace(/-----BEGIN CERTIFICATE-----/, "").replace(/-----END CERTIFICATE-----/, "").replace(/\s+/g, "");
}

// Mint a self-signed cert via the vendored @peculiar/x509 bundle — the same
// shape the sibling SAML suites use. verifyResponse parses idpCertPem with
// nodeCrypto.createPublicKey and verifies the assertion signature against it.
async function _mint(cn, alg) {
  var pki  = require("../../lib/vendor/pki.cjs");
  var x509 = pki.x509;
  var genAlg = alg === "ec"
    ? { name: "ECDSA", namedCurve: "P-256" }
    : { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048,                                          // allow:raw-byte-literal — RFC 8301 §3.1 RSA bit floor
        publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" };
  var keys = await nodeCrypto.webcrypto.subtle.generateKey(genAlg, true, ["sign", "verify"]);
  var now = new Date();
  var cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber:     "01",
    name:             "CN=" + cn,
    notBefore:        now,
    notAfter:         new Date(now.getTime() + C.TIME.days(365)),
    signingAlgorithm: alg === "ec" ? { name: "ECDSA", hash: "SHA-256" } : { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    keys:             keys,
  });
  var pkcs8 = await nodeCrypto.webcrypto.subtle.exportKey("pkcs8", keys.privateKey);
  var keyPem = "-----BEGIN PRIVATE KEY-----\n" +
    Buffer.from(pkcs8).toString("base64").match(/.{1,64}/g).join("\n") +
    "\n-----END PRIVATE KEY-----\n";
  return { certPem: cert.toString("pem"), keyPem: keyPem };
}

function _mkSp(certPem, extra) {
  var opts = {
    entityId:                    SP_ENTITY_ID,
    assertionConsumerServiceUrl: ACS_URL,
    idpEntityId:                 IDP_ENTITY_ID,
    idpSsoUrl:                   IDP_SSO_URL,
    idpSloUrl:                   IDP_SLO_URL,
    idpCertPem:                  certPem,
  };
  if (extra) { for (var k in extra) { opts[k] = extra[k]; } }
  return b.auth.saml.sp.create(opts);
}

// Build a <ds:Signature> that VERIFIES: digest over the canonicalized target,
// SignatureValue over the canonicalized SignedInfo, both through b.xmlC14n.
function _validSig(keyPem, refId, target, o) {
  o = o || {};
  var wc = !!o.withComments;
  var canonUri = wc ? (EXC + "WithComments") : EXC;
  var refTransform = wc ? (EXC + "WithComments") : EXC;
  var sm = o.sigMethod || RSA_SHA256;
  var hn = o.hashName || "sha256";
  var du = o.digestUri || "http://www.w3.org/2001/04/xmlenc#sha256";
  var dh = o.digestHash || "sha256";
  var dg = nodeCrypto.createHash(dh).update(c14n.canonicalize(target, { withComments: wc })).digest("base64");
  var si = "<ds:SignedInfo xmlns:ds=\"" + DS + "\">" +
    "<ds:CanonicalizationMethod Algorithm=\"" + canonUri + "\"></ds:CanonicalizationMethod>" +
    "<ds:SignatureMethod Algorithm=\"" + sm + "\"></ds:SignatureMethod>" +
    "<ds:Reference URI=\"#" + refId + "\">" +
    "<ds:Transforms>" +
    "<ds:Transform Algorithm=\"" + ENVELOPED + "\"></ds:Transform>" +
    "<ds:Transform Algorithm=\"" + refTransform + "\"></ds:Transform>" +
    "</ds:Transforms>" +
    "<ds:DigestMethod Algorithm=\"" + du + "\"></ds:DigestMethod>" +
    "<ds:DigestValue>" + dg + "</ds:DigestValue>" +
    "</ds:Reference></ds:SignedInfo>";
  var priv = nodeCrypto.createPrivateKey({ key: keyPem, format: "pem" });
  var so = { key: priv };
  if (o.ec) so.dsaEncoding = "der"; else so.padding = nodeCrypto.constants.RSA_PKCS1_PADDING;
  var sv = nodeCrypto.sign(hn, c14n.canonicalize(si, { withComments: wc }), so).toString("base64");
  return "<ds:Signature xmlns:ds=\"" + DS + "\">" + si + "<ds:SignatureValue>" + sv + "</ds:SignatureValue></ds:Signature>";
}

// A structurally-valid-until-the-target-defect <ds:Signature>, used for the
// _verifyXmldsig refusals that fire BEFORE the digest/signature is checked.
function _craftSig(o) {
  o = o || {};
  if (o.noSignedInfo) return "<ds:Signature xmlns:ds=\"" + DS + "\"><ds:SignatureValue>AA==</ds:SignatureValue></ds:Signature>";
  var canon = o.canon !== undefined ? o.canon : EXC;
  var parts = "<ds:CanonicalizationMethod Algorithm=\"" + canon + "\"></ds:CanonicalizationMethod>";
  if (!o.omitSigMethod) parts += "<ds:SignatureMethod Algorithm=\"" + (o.sigMethod || RSA_SHA256) + "\"></ds:SignatureMethod>";
  if (!o.omitReference) {
    var refUri = o.refUri !== undefined ? o.refUri : ("#" + o.refId);
    var refInner = "";
    if (o.transforms !== undefined) refInner += o.transforms;
    if (!o.omitDigestMethod) refInner += "<ds:DigestMethod Algorithm=\"" + (o.digestMethod || "http://www.w3.org/2001/04/xmlenc#sha256") + "\"></ds:DigestMethod>";
    var dv = o.digestValue !== undefined ? o.digestValue : "AA==";
    refInner += "<ds:DigestValue>" + dv + "</ds:DigestValue>";
    parts += "<ds:Reference URI=\"" + refUri + "\">" + refInner + "</ds:Reference>";
  }
  return "<ds:Signature xmlns:ds=\"" + DS + "\"><ds:SignedInfo xmlns:ds=\"" + DS + "\">" + parts +
    "</ds:SignedInfo><ds:SignatureValue>AA==</ds:SignatureValue></ds:Signature>";
}

function _defSubject() {
  return "<saml:Subject><saml:NameID Format=\"" + EMAIL + "\">alice@example.com</saml:NameID>" +
    "<saml:SubjectConfirmation Method=\"" + BEARER + "\">" +
    "<saml:SubjectConfirmationData NotOnOrAfter=\"" + iso(C.TIME.minutes(5)) + "\" Recipient=\"" + ACS_URL + "\"/>" +
    "</saml:SubjectConfirmation></saml:Subject>";
}
function _defCond() {
  return "<saml:Conditions NotBefore=\"" + iso(-C.TIME.minutes(5)) + "\" NotOnOrAfter=\"" + iso(C.TIME.minutes(5)) + "\">" +
    "<saml:AudienceRestriction><saml:Audience>" + SP_ENTITY_ID + "</saml:Audience></saml:AudienceRestriction></saml:Conditions>";
}
function _defAuthn(ii) {
  return "<saml:AuthnStatement SessionIndex=\"_sess-1\" AuthnInstant=\"" + ii + "\">" +
    "<saml:AuthnContext><saml:AuthnContextClassRef>" +
    "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport" +
    "</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>";
}

// Build a signed Assertion. inner is assembled ONCE with a SIG placeholder so
// the bytes signed == the bytes verified. Overrides let each test shape the
// subject / conditions / signature.
function _buildAssertion(idp, o) {
  o = o || {};
  var ii = iso(0);
  var aid = o.assertionId || ("_assertion-" + (o.tag || "t"));
  var issuer = o.issuer !== undefined ? o.issuer : IDP_ENTITY_ID;
  var issuerXml = issuer === null ? "" : ("<saml:Issuer>" + issuer + "</saml:Issuer>");
  var subjectXml = o.subjectXml !== undefined ? o.subjectXml : _defSubject();
  var conditions = o.conditions !== undefined ? o.conditions : _defCond();
  var authnStmt = o.authnStmt !== undefined ? o.authnStmt : _defAuthn(ii);
  var attrStmt = o.attrStmt || "";
  var decoy = o.decoy || "";
  var open = "<saml:Assertion xmlns:saml=\"" + SAML_A + "\" ID=\"" + aid + "\" Version=\"2.0\" IssueInstant=\"" + ii + "\">";
  var close = "</saml:Assertion>";
  var inner = issuerXml + "SIGPH" + subjectXml + conditions + authnStmt + attrStmt + decoy;
  var noSig = open + inner.replace("SIGPH", "") + close;
  var sigXml;
  if (o.signatureXml !== undefined) {
    sigXml = o.signatureXml;
  } else {
    var refId = o.refId || aid;
    var digestTarget = o.digestTarget !== undefined ? o.digestTarget : noSig;
    sigXml = _validSig((o.signKeyPem || idp.keyPem), refId, digestTarget, o.sigOpts);
  }
  return { full: open + inner.replace("SIGPH", sigXml) + close, assertionId: aid };
}

function _mkAssertionResponse(idp, o) {
  o = o || {};
  var a = _buildAssertion(idp, o);
  var rid = "_response-" + (o.tag || "t");
  var xml = "<samlp:Response xmlns:samlp=\"" + SAML_P + "\" xmlns:saml=\"" + SAML_A + "\" ID=\"" + rid +
    "\" Version=\"2.0\" IssueInstant=\"" + iso(0) + "\" Destination=\"" + ACS_URL + "\">" +
    "<saml:Issuer>" + IDP_ENTITY_ID + "</saml:Issuer>" + STATUS_OK + a.full + "</samlp:Response>";
  return { xml: xml, b64: b64(xml), assertionId: a.assertionId, responseId: rid };
}

// Response-level signature (Assertion carries no Signature of its own).
function _mkResponseLevel(idp, o) {
  o = o || {};
  var ii = iso(0);
  var rid = "_response-" + (o.tag || "rl");
  var aid = "_assertion-" + (o.tag || "rl");
  var assertion = "<saml:Assertion xmlns:saml=\"" + SAML_A + "\" ID=\"" + aid + "\" Version=\"2.0\" IssueInstant=\"" + ii + "\">" +
    "<saml:Issuer>" + IDP_ENTITY_ID + "</saml:Issuer>" + _defSubject() + _defCond() + _defAuthn(ii) + "</saml:Assertion>";
  var decoy = o.decoy || "";
  var open = "<samlp:Response xmlns:samlp=\"" + SAML_P + "\" xmlns:saml=\"" + SAML_A + "\" ID=\"" + rid +
    "\" Version=\"2.0\" IssueInstant=\"" + ii + "\" Destination=\"" + ACS_URL + "\">";
  var close = "</samlp:Response>";
  var inner = "<saml:Issuer>" + IDP_ENTITY_ID + "</saml:Issuer>" + "RSIGPH" + STATUS_OK + assertion + decoy;
  var noSig = open + inner.replace("RSIGPH", "") + close;
  var refId = o.refId || rid;
  var digestTarget = o.digestTarget !== undefined ? o.digestTarget : noSig;
  var sig = _validSig(idp.keyPem, refId, digestTarget, o.sigOpts);
  var full = open + inner.replace("RSIGPH", sig) + close;
  return { b64: b64(full), responseId: rid, assertionId: aid };
}

// ---------------------------------------------------------------------------
// _verifyXmldsig — structural refusals via a hostile assertion Signature
// ---------------------------------------------------------------------------

function testVerifyXmldsigStructural(idp) {
  var sp = _mkSp(idp.certPem);
  function code(sigXml, extra) {
    var o = { tag: "vx", signatureXml: sigXml };
    if (extra) { for (var k in extra) o[k] = extra[k]; }
    return _verifyCode(sp, _mkAssertionResponse(idp, o).b64);
  }
  var aid = "_assertion-vx";
  var goodTransforms = "<ds:Transforms><ds:Transform Algorithm=\"" + ENVELOPED + "\"></ds:Transform>" +
    "<ds:Transform Algorithm=\"" + EXC + "\"></ds:Transform></ds:Transforms>";

  check("vxmldsig: Signature without SignedInfo -> no-signed-info",
    code(_craftSig({ noSignedInfo: true })) === "auth-saml/no-signed-info");
  check("vxmldsig: unsupported CanonicalizationMethod -> unsupported-c14n",
    code(_craftSig({ canon: "http://example/bogus-c14n", refId: aid })) === "auth-saml/unsupported-c14n");
  check("vxmldsig: unsupported SignatureMethod -> unsupported-sig-alg",
    code(_craftSig({ sigMethod: "http://example/bogus-sig", refId: aid })) === "auth-saml/unsupported-sig-alg");
  check("vxmldsig: SignedInfo without Reference -> no-reference",
    code(_craftSig({ omitReference: true })) === "auth-saml/no-reference");
  check("vxmldsig: non-fragment Reference URI -> external-reference",
    code(_craftSig({ refUri: "https://evil.example/x" })) === "auth-saml/external-reference");
  check("vxmldsig: unsupported DigestMethod -> unsupported-digest",
    code(_craftSig({ refId: aid, digestMethod: "http://example/bogus-digest" })) === "auth-saml/unsupported-digest");
  check("vxmldsig: empty DigestValue -> no-digest-value",
    code(_craftSig({ refId: aid, digestValue: "" })) === "auth-saml/no-digest-value");
  check("vxmldsig: unsupported Transform -> unsupported-transform",
    code(_craftSig({ refId: aid, transforms: "<ds:Transforms><ds:Transform Algorithm=\"http://example/bogus-xform\"></ds:Transform></ds:Transforms>" }))
      === "auth-saml/unsupported-transform");
  check("vxmldsig: Reference URI matching no element -> no-id-match",
    code(_craftSig({ refUri: "#does-not-exist", transforms: goodTransforms })) === "auth-saml/no-id-match");
  check("vxmldsig: Reference URI matching two elements -> duplicate-id (anti-wrapping)",
    code(_craftSig({ refId: "dupid", transforms: goodTransforms }),
      { assertionId: "dupid", decoy: "<saml:Advice xmlns:saml=\"" + SAML_A + "\" ID=\"dupid\">x</saml:Advice>" })
      === "auth-saml/duplicate-id");
}

function testVerifyXmldsigNoSignatureValue(idp) {
  var sp = _mkSp(idp.certPem);
  var good = _mkAssertionResponse(idp, { tag: "nsv" }).b64;
  var xml = Buffer.from(good, "base64").toString("utf8")
    .replace(/<ds:SignatureValue>[^<]*<\/ds:SignatureValue>/, "<ds:SignatureValue></ds:SignatureValue>");
  check("vxmldsig: empty SignatureValue (valid digest) -> no-signature-value",
    _verifyCode(sp, b64(xml)) === "auth-saml/no-signature-value");
}

function testVerifyXmldsigBadSignature(idp, otherIdp) {
  // Valid digest but SignedInfo signed by a DIFFERENT key -> bad-signature.
  var sp = _mkSp(idp.certPem);
  var resp = _mkAssertionResponse(idp, { tag: "bs", signKeyPem: otherIdp.keyPem }).b64;
  check("vxmldsig: SignedInfo signed by wrong key -> bad-signature",
    _verifyCode(sp, resp) === "auth-saml/bad-signature");
}

async function testVerifyXmldsigEcdsa() {
  var ec = await _mint("ec-idp.example", "ec");
  var sp = _mkSp(ec.certPem);
  var info = _mkAssertionResponse(ec, {
    tag: "ec",
    sigOpts: { sigMethod: "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256", hashName: "sha256", ec: true },
  });
  check("vxmldsig: ECDSA-SHA256 assertion signature verifies (dsaEncoding der path)",
    sp.verifyResponse(info.b64).nameId === "alice@example.com");
}

function testVerifyXmldsigWithComments(idp) {
  var sp = _mkSp(idp.certPem);
  var info = _mkAssertionResponse(idp, { tag: "wc", sigOpts: { withComments: true } });
  check("vxmldsig: exclusive-c14n WithComments assertion signature verifies",
    sp.verifyResponse(info.b64).nameId === "alice@example.com");
}

// ---------------------------------------------------------------------------
// verifyResponse — Response-level signature + signed-different-element
// ---------------------------------------------------------------------------

function testResponseLevelSignature(idp) {
  var sp = _mkSp(idp.certPem);
  var ok = _mkResponseLevel(idp, { tag: "rl-ok" });
  check("verify: Response-level signature verifies (assertion unsigned)",
    sp.verifyResponse(ok.b64).nameId === "alice@example.com");

  var decoy = "<saml:Advice xmlns:saml=\"" + SAML_A + "\" ID=\"_rdecoy\">x</saml:Advice>";
  var wrapped = _mkResponseLevel(idp, { tag: "rl-w", decoy: decoy, refId: "_rdecoy", digestTarget: decoy });
  check("verify: Response signature over a different element -> signed-different-element",
    _verifyCode(sp, wrapped.b64) === "auth-saml/signed-different-element");
}

function testAssertionSignedDifferentElement(idp) {
  var sp = _mkSp(idp.certPem);
  var decoy = "<saml:Advice xmlns:saml=\"" + SAML_A + "\" ID=\"_decoyA\">payload</saml:Advice>";
  var resp = _mkAssertionResponse(idp, { tag: "sde", decoy: decoy, refId: "_decoyA", digestTarget: decoy });
  check("verify: Assertion signature over a different element -> signed-different-element",
    _verifyCode(sp, resp.b64) === "auth-saml/signed-different-element");
}

// ---------------------------------------------------------------------------
// verifyResponse — Bearer SubjectConfirmation fail-closed skips
// ---------------------------------------------------------------------------

function _bearerSubject(scd, method) {
  return "<saml:Subject><saml:NameID Format=\"" + EMAIL + "\">alice@example.com</saml:NameID>" +
    "<saml:SubjectConfirmation Method=\"" + (method || BEARER) + "\">" + scd + "</saml:SubjectConfirmation></saml:Subject>";
}

function testNoValidConfirmation(idp) {
  var sp = _mkSp(idp.certPem);
  function code(subjectXml) {
    return _verifyCode(sp, _mkAssertionResponse(idp, { tag: "nvc" + (testNoValidConfirmation._n = (testNoValidConfirmation._n || 0) + 1), subjectXml: subjectXml }).b64);
  }
  var expect = "auth-saml/no-valid-confirmation";
  check("verify: Bearer Recipient mismatch -> no-valid-confirmation",
    code(_bearerSubject("<saml:SubjectConfirmationData NotOnOrAfter=\"" + iso(C.TIME.minutes(5)) + "\" Recipient=\"https://evil.example\"/>")) === expect);
  check("verify: Bearer without SubjectConfirmationData -> no-valid-confirmation",
    code(_bearerSubject("")) === expect);
  check("verify: Bearer without NotOnOrAfter -> no-valid-confirmation",
    code(_bearerSubject("<saml:SubjectConfirmationData Recipient=\"" + ACS_URL + "\"/>")) === expect);
  check("verify: Bearer expired NotOnOrAfter -> no-valid-confirmation",
    code(_bearerSubject("<saml:SubjectConfirmationData NotOnOrAfter=\"" + iso(-C.TIME.hours(1)) + "\" Recipient=\"" + ACS_URL + "\"/>")) === expect);
  check("verify: Bearer unparseable NotOnOrAfter -> no-valid-confirmation",
    code(_bearerSubject("<saml:SubjectConfirmationData NotOnOrAfter=\"not-a-date\" Recipient=\"" + ACS_URL + "\"/>")) === expect);
  check("verify: Bearer NotBefore in the future -> no-valid-confirmation",
    code(_bearerSubject("<saml:SubjectConfirmationData NotBefore=\"" + iso(C.TIME.hours(1)) + "\" NotOnOrAfter=\"" + iso(C.TIME.hours(2)) + "\" Recipient=\"" + ACS_URL + "\"/>")) === expect);
  check("verify: Bearer unparseable NotBefore -> no-valid-confirmation",
    code(_bearerSubject("<saml:SubjectConfirmationData NotBefore=\"not-a-date\" NotOnOrAfter=\"" + iso(C.TIME.minutes(5)) + "\" Recipient=\"" + ACS_URL + "\"/>")) === expect);
  check("verify: non-Bearer/non-HoK Method -> no-valid-confirmation",
    code(_bearerSubject("<saml:SubjectConfirmationData NotOnOrAfter=\"" + iso(C.TIME.minutes(5)) + "\" Recipient=\"" + ACS_URL + "\"/>",
      "urn:oasis:names:tc:SAML:2.0:cm:sender-vouches")) === expect);
}

// ---------------------------------------------------------------------------
// verifyResponse — holder-of-key possession proof
// ---------------------------------------------------------------------------

function _hokScd(certB64, attrs) {
  var a = attrs !== undefined ? attrs : (" NotOnOrAfter=\"" + iso(C.TIME.minutes(5)) + "\" Recipient=\"" + ACS_URL + "\"");
  var keyInfo = certB64 === null ? "" :
    "<ds:KeyInfo xmlns:ds=\"" + DS + "\"><ds:X509Data><ds:X509Certificate>" + certB64 + "</ds:X509Certificate></ds:X509Data></ds:KeyInfo>";
  return "<saml:SubjectConfirmationData" + a + ">" + keyInfo + "</saml:SubjectConfirmationData>";
}
function _hokSubject(scd) {
  return "<saml:Subject><saml:NameID Format=\"" + EMAIL + "\">alice@example.com</saml:NameID>" +
    "<saml:SubjectConfirmation Method=\"" + HOK + "\">" + (scd === null ? "" : scd) + "</saml:SubjectConfirmation></saml:Subject>";
}

function testHolderOfKey(idp, client, other) {
  var sp = _mkSp(idp.certPem);
  var clientB64 = _certBody(client.certPem);
  var otherB64 = _certBody(other.certPem);
  var presented = { presentedCertPem: client.certPem };
  function verify(subjectXml, vopts, tag) {
    return _mkAssertionResponse(idp, { tag: "hok-" + tag, subjectXml: subjectXml });
  }

  // Success — embedded X509 matches the presented possession-proof cert.
  var okInfo = sp.verifyResponse(verify(_hokSubject(_hokScd(clientB64)), null, "ok").b64, { holderOfKey: presented });
  check("HoK: matching possession cert -> confirmed, nameId returned", okInfo.nameId === "alice@example.com");
  check("HoK: HoK confirmation returns null inResponseTo (bearerOk false)", okInfo.inResponseTo === null);

  // Assertion uses HoK but the operator supplied no presented key.
  check("HoK: HoK confirmation without holderOfKey opt -> hok-no-presented-key",
    _verifyCode(sp, verify(_hokSubject(_hokScd(clientB64)), null, "npk").b64) === "auth-saml/hok-no-presented-key");

  // presentedCertPem itself unparseable -> bad-hok-cert (fires before the loop).
  check("HoK: unparseable presentedCertPem -> bad-hok-cert",
    _verifyCode(sp, verify(_hokSubject(_hokScd(clientB64)), null, "bad").b64, { holderOfKey: { presentedCertPem: "not-a-cert" } })
      === "auth-saml/bad-hok-cert");

  // Embedded cert is a different key than presented -> key mismatch.
  check("HoK: embedded X509 != presented key -> hok-key-mismatch",
    _verifyCode(sp, verify(_hokSubject(_hokScd(otherB64)), null, "mm").b64, { holderOfKey: presented })
      === "auth-saml/hok-key-mismatch");

  // KeyInfo shapes.
  check("HoK: SubjectConfirmationData without KeyInfo -> hok-no-keyinfo",
    _verifyCode(sp, verify(_hokSubject(_hokScd(null)), null, "nki").b64, { holderOfKey: presented })
      === "auth-saml/hok-no-keyinfo");
  check("HoK: KeyInfo without X509Data/X509Certificate -> hok-unsupported-keyinfo",
    _verifyCode(sp, verify(_hokSubject("<saml:SubjectConfirmationData NotOnOrAfter=\"" + iso(C.TIME.minutes(5)) + "\" Recipient=\"" + ACS_URL +
      "\"><ds:KeyInfo xmlns:ds=\"" + DS + "\"><ds:KeyValue><ds:RSAKeyValue></ds:RSAKeyValue></ds:KeyValue></ds:KeyInfo></saml:SubjectConfirmationData>"), null, "uki").b64,
      { holderOfKey: presented }) === "auth-saml/hok-unsupported-keyinfo");
  check("HoK: empty X509Certificate -> hok-no-cert",
    _verifyCode(sp, verify(_hokSubject(_hokScd("")), null, "nc").b64, { holderOfKey: presented })
      === "auth-saml/hok-no-cert");
  check("HoK: garbage X509Certificate -> hok-bad-cert",
    _verifyCode(sp, verify(_hokSubject(_hokScd(Buffer.from("not a cert").toString("base64"))), null, "bc").b64, { holderOfKey: presented })
      === "auth-saml/hok-bad-cert");

  // Matching key but time / recipient / SCD fail-closed skips -> no confirmation.
  var nvc = "auth-saml/no-valid-confirmation";
  check("HoK: matched key but no SubjectConfirmationData -> no-valid-confirmation",
    _verifyCode(sp, verify(_hokSubject(null), null, "noscd").b64, { holderOfKey: presented }) === nvc);
  check("HoK: matched key but no NotOnOrAfter -> no-valid-confirmation",
    _verifyCode(sp, verify(_hokSubject(_hokScd(clientB64, " Recipient=\"" + ACS_URL + "\"")), null, "nnoa").b64, { holderOfKey: presented }) === nvc);
  check("HoK: matched key but expired NotOnOrAfter -> no-valid-confirmation",
    _verifyCode(sp, verify(_hokSubject(_hokScd(clientB64, " NotOnOrAfter=\"" + iso(-C.TIME.hours(1)) + "\" Recipient=\"" + ACS_URL + "\"")), null, "exp").b64, { holderOfKey: presented }) === nvc);
  check("HoK: matched key but NotBefore in the future -> no-valid-confirmation",
    _verifyCode(sp, verify(_hokSubject(_hokScd(clientB64, " NotBefore=\"" + iso(C.TIME.hours(1)) + "\" NotOnOrAfter=\"" + iso(C.TIME.hours(2)) + "\" Recipient=\"" + ACS_URL + "\"")), null, "nbf").b64, { holderOfKey: presented }) === nvc);
  check("HoK: matched key but Recipient mismatch -> no-valid-confirmation",
    _verifyCode(sp, verify(_hokSubject(_hokScd(clientB64, " NotOnOrAfter=\"" + iso(C.TIME.minutes(5)) + "\" Recipient=\"https://evil.example\"")), null, "rcp").b64, { holderOfKey: presented }) === nvc);
}

// ---------------------------------------------------------------------------
// verifyResponse — Conditions, Audience, AuthnStatement variants
// ---------------------------------------------------------------------------

function testConditionsAndAudience(idp) {
  var sp = _mkSp(idp.certPem);
  var ar = "<saml:AudienceRestriction><saml:Audience>" + SP_ENTITY_ID + "</saml:Audience></saml:AudienceRestriction>";

  check("verify: unparseable Conditions/NotBefore -> conditions-bad-timestamp",
    _verifyCode(sp, _mkAssertionResponse(idp, { tag: "cbt1",
      conditions: "<saml:Conditions NotBefore=\"not-a-date\" NotOnOrAfter=\"" + iso(C.TIME.minutes(5)) + "\">" + ar + "</saml:Conditions>" }).b64)
      === "auth-saml/conditions-bad-timestamp");
  check("verify: unparseable Conditions/NotOnOrAfter -> conditions-bad-timestamp",
    _verifyCode(sp, _mkAssertionResponse(idp, { tag: "cbt2",
      conditions: "<saml:Conditions NotBefore=\"" + iso(-C.TIME.minutes(5)) + "\" NotOnOrAfter=\"not-a-date\">" + ar + "</saml:Conditions>" }).b64)
      === "auth-saml/conditions-bad-timestamp");

  // No Conditions element at all -> the audience binding is absent.
  check("verify: no Conditions element -> no-audience-restriction",
    _verifyCode(sp, _mkAssertionResponse(idp, { tag: "nocond", conditions: "" }).b64)
      === "auth-saml/no-audience-restriction");

  // AND-combined AudienceRestriction (SAML core 2.5.1.4): SP must be in EVERY one.
  var bothOk = "<saml:Conditions NotBefore=\"" + iso(-C.TIME.minutes(5)) + "\" NotOnOrAfter=\"" + iso(C.TIME.minutes(5)) + "\">" +
    ar + "<saml:AudienceRestriction><saml:Audience>" + SP_ENTITY_ID + "</saml:Audience></saml:AudienceRestriction></saml:Conditions>";
  check("verify: two AudienceRestrictions both naming SP -> accepted",
    sp.verifyResponse(_mkAssertionResponse(idp, { tag: "ars-ok", conditions: bothOk }).b64).nameId === "alice@example.com");
  var secondBad = "<saml:Conditions NotBefore=\"" + iso(-C.TIME.minutes(5)) + "\" NotOnOrAfter=\"" + iso(C.TIME.minutes(5)) + "\">" +
    ar + "<saml:AudienceRestriction><saml:Audience>https://other.example</saml:Audience></saml:AudienceRestriction></saml:Conditions>";
  check("verify: SP absent from a later AudienceRestriction -> wrong-audience",
    _verifyCode(sp, _mkAssertionResponse(idp, { tag: "ars-bad", conditions: secondBad }).b64) === "auth-saml/wrong-audience");

  // No AuthnStatement -> sessionIndex null.
  var noAuthn = sp.verifyResponse(_mkAssertionResponse(idp, { tag: "noauthn", authnStmt: "" }).b64);
  check("verify: assertion without AuthnStatement -> sessionIndex null", noAuthn.sessionIndex === null);
}

// ---------------------------------------------------------------------------
// verifyResponse — EncryptedAssertion (RSA-OAEP-SHA256 + AES-256-GCM)
// ---------------------------------------------------------------------------

function _encData(o) {
  o = o || {};
  var contentAlg = o.contentAlg || "http://www.w3.org/2009/xmlenc11#aes256-gcm";
  var keyAlg = o.keyAlg || "http://www.w3.org/2009/xmlenc11#rsa-oaep";
  var digestXml = o.oaepDigest === null ? "" :
    "<ds:DigestMethod Algorithm=\"" + (o.oaepDigest || "http://www.w3.org/2001/04/xmlenc#sha256") + "\"></ds:DigestMethod>";
  return "<saml:EncryptedAssertion><xenc:EncryptedData xmlns:xenc=\"" + XENC + "\">" +
    "<xenc:EncryptionMethod Algorithm=\"" + contentAlg + "\"></xenc:EncryptionMethod>" +
    "<ds:KeyInfo xmlns:ds=\"" + DS + "\"><xenc:EncryptedKey xmlns:xenc=\"" + XENC + "\">" +
    "<xenc:EncryptionMethod Algorithm=\"" + keyAlg + "\">" + digestXml + "</xenc:EncryptionMethod>" +
    "<xenc:CipherData><xenc:CipherValue>" + o.wrapped + "</xenc:CipherValue></xenc:CipherData>" +
    "</xenc:EncryptedKey></ds:KeyInfo>" +
    "<xenc:CipherData><xenc:CipherValue>" + o.content + "</xenc:CipherValue></xenc:CipherData>" +
    "</xenc:EncryptedData></saml:EncryptedAssertion>";
}

function testEncryptedAssertion(idp) {
  var sp = _mkSp(idp.certPem);
  var spKp = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });                     // allow:raw-byte-literal — RFC 8301 §3.1 RSA bit floor
  var spPriv = spKp.privateKey.export({ type: "pkcs8", format: "pem" });
  var spPub = spKp.publicKey.export({ type: "spki", format: "pem" });
  function wrap(cek) { return nodeCrypto.publicEncrypt({ key: spPub, padding: nodeCrypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" }, cek).toString("base64"); }
  function gcm(cek, buf) {
    var iv = nodeCrypto.randomBytes(12);                                                          // allow:raw-byte-literal — GCM 96-bit IV
    var cipher = nodeCrypto.createCipheriv("aes-256-gcm", cek, iv);
    var ct = Buffer.concat([cipher.update(buf), cipher.final()]);
    return Buffer.concat([iv, ct, cipher.getAuthTag()]).toString("base64");
  }
  function verifyEnc(encInner, key) { return _verifyCode(sp, b64(_response(STATUS_OK + encInner)), { spPrivateKeyPem: key }); }

  // Happy path: decrypt -> splice -> verify the recovered signed assertion.
  var cek = nodeCrypto.randomBytes(32);                                                           // allow:raw-byte-literal — AES-256 key
  var clear = _buildAssertion(idp, { tag: "enc" }).full;
  var okXml = b64(_response(STATUS_OK + _encData({ wrapped: wrap(cek), content: gcm(cek, Buffer.from(clear, "utf8")) })));
  check("encrypted: RSA-OAEP-SHA256 + AES-256-GCM round trip -> nameId",
    sp.verifyResponse(okXml, { spPrivateKeyPem: spPriv }).nameId === "alice@example.com");

  // Structural refusals (no crypto reached — any non-empty spPrivateKeyPem).
  check("encrypted: EncryptedAssertion without EncryptedData -> encrypted-no-encrypted-data",
    verifyEnc("<saml:EncryptedAssertion></saml:EncryptedAssertion>", "x") === "auth-saml/encrypted-no-encrypted-data");
  check("encrypted: EncryptedData without EncryptionMethod -> encrypted-no-method",
    verifyEnc("<saml:EncryptedAssertion><xenc:EncryptedData xmlns:xenc=\"" + XENC + "\"></xenc:EncryptedData></saml:EncryptedAssertion>", "x")
      === "auth-saml/encrypted-no-method");
  check("encrypted: EncryptedData without KeyInfo -> encrypted-no-keyinfo",
    verifyEnc("<saml:EncryptedAssertion><xenc:EncryptedData xmlns:xenc=\"" + XENC + "\"><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#aes256-gcm\"></xenc:EncryptionMethod></xenc:EncryptedData></saml:EncryptedAssertion>", "x")
      === "auth-saml/encrypted-no-keyinfo");
  check("encrypted: KeyInfo without EncryptedKey -> encrypted-no-encrypted-key",
    verifyEnc("<saml:EncryptedAssertion><xenc:EncryptedData xmlns:xenc=\"" + XENC + "\"><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#aes256-gcm\"></xenc:EncryptionMethod><ds:KeyInfo xmlns:ds=\"" + DS + "\"></ds:KeyInfo></xenc:EncryptedData></saml:EncryptedAssertion>", "x")
      === "auth-saml/encrypted-no-encrypted-key");
  check("encrypted: EncryptedKey without EncryptionMethod -> encrypted-no-key-alg",
    verifyEnc("<saml:EncryptedAssertion><xenc:EncryptedData xmlns:xenc=\"" + XENC + "\"><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#aes256-gcm\"></xenc:EncryptionMethod><ds:KeyInfo xmlns:ds=\"" + DS + "\"><xenc:EncryptedKey xmlns:xenc=\"" + XENC + "\"></xenc:EncryptedKey></ds:KeyInfo></xenc:EncryptedData></saml:EncryptedAssertion>", "x")
      === "auth-saml/encrypted-no-key-alg");
  check("encrypted: EncryptedKey without CipherValue -> encrypted-no-key-cipher-value",
    verifyEnc("<saml:EncryptedAssertion><xenc:EncryptedData xmlns:xenc=\"" + XENC + "\"><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#aes256-gcm\"></xenc:EncryptionMethod><ds:KeyInfo xmlns:ds=\"" + DS + "\"><xenc:EncryptedKey xmlns:xenc=\"" + XENC + "\"><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#rsa-oaep\"></xenc:EncryptionMethod></xenc:EncryptedKey></ds:KeyInfo></xenc:EncryptedData></saml:EncryptedAssertion>", "x")
      === "auth-saml/encrypted-no-key-cipher-value");
  check("encrypted: unsupported key-transport alg -> encrypted-unsupported-key-alg",
    verifyEnc(_encData({ keyAlg: "http://example/bogus-key-alg", wrapped: "AA==", content: "AA==" }), "x")
      === "auth-saml/encrypted-unsupported-key-alg");
  check("encrypted: unsupported OAEP DigestMethod -> encrypted-unsupported-oaep-digest",
    verifyEnc(_encData({ oaepDigest: "http://example/bogus-digest", wrapped: "AA==", content: "AA==" }), "x")
      === "auth-saml/encrypted-unsupported-oaep-digest");
  check("encrypted: SHA-1 OAEP (default) -> encrypted-weak-oaep-digest",
    verifyEnc(_encData({ oaepDigest: null, wrapped: "AA==", content: "AA==" }), "x")
      === "auth-saml/encrypted-weak-oaep-digest");
  check("encrypted: unparseable spPrivateKeyPem -> encrypted-bad-sp-key",
    verifyEnc(_encData({ wrapped: "AA==", content: "AA==" }), "not-a-key") === "auth-saml/encrypted-bad-sp-key");

  // Crypto-reaching refusals (need the real SP key).
  check("encrypted: undecryptable wrapped key -> encrypted-key-unwrap-failed",
    verifyEnc(_encData({ wrapped: nodeCrypto.randomBytes(256).toString("base64"), content: "AA==" }), spPriv)
      === "auth-saml/encrypted-key-unwrap-failed");
  check("encrypted: wrong CEK length for AES-256-GCM -> encrypted-wrong-cek-len",
    verifyEnc(_encData({ wrapped: wrap(nodeCrypto.randomBytes(16)), content: "AA==" }), spPriv)
      === "auth-saml/encrypted-wrong-cek-len");
  check("encrypted: content shorter than IV+tag -> encrypted-content-too-short",
    verifyEnc(_encData({ wrapped: wrap(nodeCrypto.randomBytes(32)), content: Buffer.alloc(10).toString("base64") }), spPriv)
      === "auth-saml/encrypted-content-too-short");
  check("encrypted: AES-GCM tag mismatch -> encrypted-content-tag-mismatch",
    verifyEnc(_encData({ wrapped: wrap(nodeCrypto.randomBytes(32)),
      content: Buffer.concat([nodeCrypto.randomBytes(12), nodeCrypto.randomBytes(20), nodeCrypto.randomBytes(16)]).toString("base64") }), spPriv)
      === "auth-saml/encrypted-content-tag-mismatch");
  check("encrypted: AES-CBC content alg refused -> encrypted-unsupported-content-alg",
    verifyEnc(_encData({ contentAlg: "http://www.w3.org/2001/04/xmlenc#aes256-cbc", wrapped: wrap(nodeCrypto.randomBytes(32)), content: "AA==" }), spPriv)
      === "auth-saml/encrypted-unsupported-content-alg");

  var cek2 = nodeCrypto.randomBytes(32);
  check("encrypted: cleartext root is not an Assertion -> encrypted-not-assertion",
    verifyEnc(_encData({ wrapped: wrap(cek2), content: gcm(cek2, Buffer.from("<saml:Foo xmlns:saml=\"" + SAML_A + "\">x</saml:Foo>", "utf8")) }), spPriv)
      === "auth-saml/encrypted-not-assertion");
  var cek3 = nodeCrypto.randomBytes(32);
  check("encrypted: cleartext is not parseable XML -> encrypted-bad-cleartext",
    verifyEnc(_encData({ wrapped: wrap(cek3), content: gcm(cek3, Buffer.from("garbage-no-xml", "utf8")) }), spPriv)
      === "auth-saml/encrypted-bad-cleartext");
}

// ---------------------------------------------------------------------------
// SLO — embedded XMLDSig (POST) classical + Ed25519, and error branches
// ---------------------------------------------------------------------------

function _ed25519Raw() {
  var ed = nodeCrypto.generateKeyPairSync("ed25519");
  var pk8 = ed.privateKey.export({ type: "pkcs8", format: "der" });
  var spki = ed.publicKey.export({ type: "spki", format: "der" });
  return { seed: new Uint8Array(pk8.subarray(pk8.length - 32)), pub: new Uint8Array(spki.subarray(spki.length - 32)) };
}

function testSloPostBindings() {
  var sp = _mkSp(FAKE_CERT);
  var rsa = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });                       // allow:raw-byte-literal — RFC 8301 §3.1 RSA bit floor
  var skPem = rsa.privateKey.export({ type: "pkcs8", format: "pem" });
  var pkPem = rsa.publicKey.export({ type: "spki", format: "pem" });
  var ed = _ed25519Raw();

  function roundTrip(alg, sk, pk) {
    var post = sp.buildLogoutRequestPost({ nameId: "alice@idp", sessionIndex: "_s-9", signingKey: sk, signingAlg: alg });
    var parsed = sp.parseLogoutRequestPost(post.samlRequest, { idpVerifyKey: pk, idpVerifyAlg: alg });
    return parsed.nameId === "alice@idp" && parsed.sessionIndex === "_s-9";
  }
  check("SLO POST: rsa-sha256 embedded XMLDSig round trip (PEM)", roundTrip("rsa-sha256", skPem, pkPem));
  check("SLO POST: rsa-sha256 embedded XMLDSig round trip (KeyObject)", roundTrip("rsa-sha256", rsa.privateKey, rsa.publicKey));
  check("SLO POST: rsa-sha384 embedded XMLDSig round trip", roundTrip("rsa-sha384", skPem, pkPem));
  check("SLO POST: rsa-sha512 embedded XMLDSig round trip", roundTrip("rsa-sha512", skPem, pkPem));
  check("SLO POST: ed25519 embedded XMLDSig round trip (raw key)", roundTrip("ed25519", ed.seed, ed.pub));

  // _embedXmlDsig key/alg validation (buildLogoutRequestPost calls it directly).
  check("SLO POST: unknown signingAlg -> bad-signing-alg",
    _codeOf(function () { sp.buildLogoutRequestPost({ nameId: "a", signingAlg: "bogus" }); }) === "auth-saml/bad-signing-alg");
  check("SLO POST: classical signingKey not a PEM/KeyObject -> bad-signing-key",
    _codeOf(function () { sp.buildLogoutRequestPost({ nameId: "a", signingKey: 123, signingAlg: "rsa-sha256" }); }) === "auth-saml/bad-signing-key");
  check("SLO POST: ml-dsa signingKey not a Uint8Array -> bad-signing-key",
    _codeOf(function () { sp.buildLogoutRequestPost({ nameId: "a", signingKey: "nope", signingAlg: "ml-dsa-65" }); }) === "auth-saml/bad-signing-key");

  // _verifyEmbeddedXmlDsig error branches.
  var unsigned = sp.buildLogoutRequestPost({ nameId: "a@idp" });
  var kp = pq.ml_dsa_65.keygen();
  check("SLO POST: verify requested but body unsigned -> no-signature",
    _codeOf(function () { sp.parseLogoutRequestPost(unsigned.samlRequest, { idpVerifyKey: kp.publicKey, idpVerifyAlg: "ml-dsa-65" }); }) === "auth-saml/no-signature");

  var signed65 = sp.buildLogoutRequestPost({ nameId: "a@idp", signingKey: kp.secretKey, signingAlg: "ml-dsa-65" });
  var kp87 = pq.ml_dsa_87.keygen();
  check("SLO POST: SignatureMethod URN != expected -> wrong-sig-alg",
    _codeOf(function () { sp.parseLogoutRequestPost(signed65.samlRequest, { idpVerifyKey: kp87.publicKey, idpVerifyAlg: "ml-dsa-87" }); }) === "auth-saml/wrong-sig-alg");

  var respRaw = sp.buildLogoutResponse({ inResponseTo: "_x", destination: IDP_SLO_URL }).raw;
  check("SLO POST: verify a LogoutResponse as a LogoutRequest -> wrong-root",
    _codeOf(function () { sp.parseLogoutRequestPost(b64(respRaw), { idpVerifyKey: kp.publicKey, idpVerifyAlg: "ml-dsa-65" }); }) === "auth-saml/wrong-root");

  var tampered = Buffer.from(signed65.samlRequest, "base64").toString("utf8").replace("a@idp", "b@idp");
  check("SLO POST: tampered signed content -> digest-mismatch",
    _codeOf(function () { sp.parseLogoutRequestPost(b64(tampered), { idpVerifyKey: kp.publicKey, idpVerifyAlg: "ml-dsa-65" }); }) === "auth-saml/digest-mismatch");

  var noNameId = "<samlp:LogoutRequest xmlns:samlp=\"" + SAML_P + "\" xmlns:saml=\"" + SAML_A + "\" ID=\"_x\"><saml:Issuer>i</saml:Issuer></samlp:LogoutRequest>";
  check("SLO POST: LogoutRequest without NameID -> no-nameid",
    _codeOf(function () { sp.parseLogoutRequestPost(b64(noNameId)); }) === "auth-saml/no-nameid");
}

function testSloRedirectAndParse() {
  var sp = _mkSp(FAKE_CERT);
  var ed = _ed25519Raw();
  var kp = pq.ml_dsa_65.keygen();

  // Ed25519 redirect-binding round trip (raw key sign + verify paths).
  var lr = sp.buildLogoutRequest({ nameId: "a@idp", sessionIndex: "_s", signingKey: ed.seed, signingAlg: "ed25519" });
  var q = lr.redirectUrl.split("?")[1];
  var samlReq = decodeURIComponent(q.split("&")[0].slice("SAMLRequest=".length));
  check("SLO redirect: ed25519 raw-key round trip",
    sp.parseLogoutRequest(samlReq, { queryString: q, idpVerifyKey: ed.pub, idpVerifyAlg: "ed25519" }).nameId === "a@idp");
  check("SLO redirect: verify requested without queryString -> no-query-string",
    _codeOf(function () { sp.parseLogoutRequest(samlReq, { idpVerifyKey: ed.pub, idpVerifyAlg: "ed25519" }); }) === "auth-saml/no-query-string");
  check("SLO redirect: unknown idpVerifyAlg -> bad-verify-alg",
    _codeOf(function () { sp.parseLogoutRequest(samlReq, { queryString: q, idpVerifyKey: ed.pub, idpVerifyAlg: "bogus" }); }) === "auth-saml/bad-verify-alg");

  // buildLogoutRequest classical bad key.
  check("SLO redirect: classical signingKey not a PEM/KeyObject -> bad-signing-key",
    _codeOf(function () { sp.buildLogoutRequest({ nameId: "a", signingKey: 123, signingAlg: "rsa-sha256" }); }) === "auth-saml/bad-signing-key");

  // parseLogoutResponse signed round trip + error branches.
  var resp = sp.buildLogoutResponse({ inResponseTo: "_o", destination: IDP_SLO_URL, signingKey: kp.secretKey, signingAlg: "ml-dsa-65" });
  var rq = resp.redirectUrl.split("?")[1];
  var samlResp = decodeURIComponent(rq.split("&")[0].slice("SAMLResponse=".length));
  check("SLO redirect: parseLogoutResponse signed round trip -> success",
    sp.parseLogoutResponse(samlResp, { queryString: rq, idpVerifyKey: kp.publicKey, idpVerifyAlg: "ml-dsa-65" }).success === true);
  check("SLO redirect: parseLogoutResponse verify without queryString -> no-query-string",
    _codeOf(function () { sp.parseLogoutResponse(samlResp, { idpVerifyKey: kp.publicKey, idpVerifyAlg: "ml-dsa-65" }); }) === "auth-saml/no-query-string");
  check("SLO redirect: parseLogoutResponse unknown idpVerifyAlg -> bad-verify-alg",
    _codeOf(function () { sp.parseLogoutResponse(samlResp, { queryString: rq, idpVerifyKey: kp.publicKey, idpVerifyAlg: "bogus" }); }) === "auth-saml/bad-verify-alg");

  // buildLogoutResponse signing validation.
  check("SLO: buildLogoutResponse unknown signingAlg -> bad-signing-alg",
    _codeOf(function () { sp.buildLogoutResponse({ inResponseTo: "_x", destination: IDP_SLO_URL, signingAlg: "bogus" }); }) === "auth-saml/bad-signing-alg");
  check("SLO: buildLogoutResponse classical bad signingKey -> bad-signing-key",
    _codeOf(function () { sp.buildLogoutResponse({ inResponseTo: "_x", destination: IDP_SLO_URL, signingKey: 123, signingAlg: "rsa-sha256" }); }) === "auth-saml/bad-signing-key");

  // Wrong-document parse refusals.
  var respQuery = sp.buildLogoutResponse({ inResponseTo: "_x", destination: IDP_SLO_URL }).redirectUrl.split("?")[1];
  var respOnly = decodeURIComponent(respQuery.split("&")[0].slice("SAMLResponse=".length));
  check("SLO: parseLogoutRequest given a LogoutResponse -> not-logout-request",
    _codeOf(function () { sp.parseLogoutRequest(respOnly); }) === "auth-saml/not-logout-request");
  var reqQuery = sp.buildLogoutRequest({ nameId: "a", sessionIndex: "_s" }).redirectUrl.split("?")[1];
  var reqOnly = decodeURIComponent(reqQuery.split("&")[0].slice("SAMLRequest=".length));
  check("SLO: parseLogoutResponse given a LogoutRequest -> not-logout-response",
    _codeOf(function () { sp.parseLogoutResponse(reqOnly); }) === "auth-saml/not-logout-response");
  var noNameIdReq = zlib.deflateRawSync(Buffer.from(
    "<samlp:LogoutRequest xmlns:samlp=\"" + SAML_P + "\" xmlns:saml=\"" + SAML_A + "\" ID=\"_x\"><saml:Issuer>i</saml:Issuer></samlp:LogoutRequest>", "utf8")).toString("base64");
  check("SLO: parseLogoutRequest LogoutRequest without NameID -> no-nameid",
    _codeOf(function () { sp.parseLogoutRequest(noNameIdReq); }) === "auth-saml/no-nameid");

  // SOAP parse-side branches.
  check("SLO SOAP: unparseable envelope -> bad-soap",
    _codeOf(function () { sp.parseLogoutResponseSoap("<not-closed"); }) === "auth-saml/bad-soap");
  var soapWrongInner = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\"><soapenv:Body>" +
    "<samlp:Foo xmlns:samlp=\"" + SAML_P + "\"></samlp:Foo></soapenv:Body></soapenv:Envelope>";
  check("SLO SOAP: body element is not a LogoutResponse -> wrong-root",
    _codeOf(function () { sp.parseLogoutResponseSoap(soapWrongInner); }) === "auth-saml/wrong-root");
  var lrResp = sp.buildLogoutResponse({ inResponseTo: "_o", destination: IDP_SLO_URL }).raw;
  var soapUnsigned = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\"><soapenv:Body>" + lrResp + "</soapenv:Body></soapenv:Envelope>";
  check("SLO SOAP: verify requested but LogoutResponse unsigned -> no-signature",
    _codeOf(function () { sp.parseLogoutResponseSoap(soapUnsigned, { idpVerifyKey: kp.publicKey, idpVerifyAlg: "ml-dsa-65" }); }) === "auth-saml/no-signature");
}

// ---------------------------------------------------------------------------
// fetchMdq — transport + verification branches (require-cache transport fake)
// ---------------------------------------------------------------------------

function _fedSignature(fed, refId, elementXml) {
  var digest = nodeCrypto.createHash("sha256").update(c14n.canonicalize(elementXml)).digest("base64");
  var signedInfo = "<ds:SignedInfo xmlns:ds=\"" + DS + "\">" +
    "<ds:CanonicalizationMethod Algorithm=\"" + EXC + "\"></ds:CanonicalizationMethod>" +
    "<ds:SignatureMethod Algorithm=\"" + RSA_SHA256 + "\"></ds:SignatureMethod>" +
    "<ds:Reference URI=\"#" + refId + "\"><ds:Transforms>" +
    "<ds:Transform Algorithm=\"" + ENVELOPED + "\"></ds:Transform>" +
    "<ds:Transform Algorithm=\"" + EXC + "\"></ds:Transform></ds:Transforms>" +
    "<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"></ds:DigestMethod>" +
    "<ds:DigestValue>" + digest + "</ds:DigestValue></ds:Reference></ds:SignedInfo>";
  var priv = nodeCrypto.createPrivateKey({ key: fed.keyPem, format: "pem" });
  var sig = nodeCrypto.sign("sha256", c14n.canonicalize(signedInfo), { key: priv, padding: nodeCrypto.constants.RSA_PKCS1_PADDING }).toString("base64");
  return "<ds:Signature xmlns:ds=\"" + DS + "\">" + signedInfo + "<ds:SignatureValue>" + sig + "</ds:SignatureValue></ds:Signature>";
}

async function _fetchMdqWith(status, body, trustCertPem) {
  var hcPath = require.resolve("../../lib/http-client");
  var origHc = require.cache[hcPath].exports;
  require.cache[hcPath].exports = Object.assign({}, origHc, {
    request: async function () { return { statusCode: status, headers: {}, body: body == null ? body : Buffer.from(body, "utf8") }; },
  });
  var samlPath = require.resolve("../../lib/auth/saml");
  delete require.cache[samlPath];
  var saml = require(samlPath);
  try {
    var xml = await saml.fetchMdq({ baseUrl: "https://mdq.test.invalid", entityId: IDP_ENTITY_ID, trustCertPem: trustCertPem });
    return { xml: xml, code: null };
  } catch (e) {
    return { xml: null, code: e.code || e.message };
  } finally {
    require.cache[hcPath].exports = origHc;
    delete require.cache[samlPath];
  }
}

async function testFetchMdqBranches(fed) {
  var r1 = await _fetchMdqWith(500, "<x/>", null);
  check("fetchMdq: non-2xx status -> mdq-fetch-failed", r1.code === "auth-saml/mdq-fetch-failed");
  var r2 = await _fetchMdqWith(200, "", null);
  check("fetchMdq: empty body -> mdq-empty", r2.code === "auth-saml/mdq-empty");

  var plainEd = "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"" + IDP_ENTITY_ID + "\"></md:EntityDescriptor>";
  var r3 = await _fetchMdqWith(200, plainEd, null);
  check("fetchMdq: no trustCertPem -> returns metadata unverified", r3.code === null && r3.xml === plainEd);

  var r4 = await _fetchMdqWith(200, plainEd, fed.certPem);
  check("fetchMdq: trustCertPem supplied but metadata unsigned -> mdq-unsigned", r4.code === "auth-saml/mdq-unsigned");

  var dupSig = "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" ID=\"G1\" entityID=\"" + IDP_ENTITY_ID + "\">" +
    "<ds:Signature xmlns:ds=\"" + DS + "\"></ds:Signature><ds:Signature xmlns:ds=\"" + DS + "\"></ds:Signature></md:EntityDescriptor>";
  var r5 = await _fetchMdqWith(200, dupSig, fed.certPem);
  check("fetchMdq: duplicate top-level Signature -> mdq-duplicate-signature", r5.code === "auth-saml/mdq-duplicate-signature");

  // Federation-signed descriptor whose entityID differs from the requested one.
  var mismatchEntity = "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" ID=\"G1\" entityID=\"https://other.example\">" +
    "<md:IDPSSODescriptor protocolSupportEnumeration=\"" + SAML_P + "\"></md:IDPSSODescriptor></md:EntityDescriptor>";
  var sig = _fedSignature(fed, "G1", mismatchEntity);
  var signedMismatch = mismatchEntity.slice(0, mismatchEntity.indexOf(">") + 1) + sig + mismatchEntity.slice(mismatchEntity.indexOf(">") + 1);
  var r6 = await _fetchMdqWith(200, signedMismatch, fed.certPem);
  check("fetchMdq: signed EntityDescriptor entityID != requested -> mdq-entity-mismatch", r6.code === "auth-saml/mdq-entity-mismatch");
}

// ---------------------------------------------------------------------------
// verifyResponse — duplicate NameID + undeclared-prefix namespace resolution
// ---------------------------------------------------------------------------

function testMoreVerifyResponse(idp) {
  var sp = _mkSp(idp.certPem);
  var twoNameId = "<saml:Subject>" +
    "<saml:NameID Format=\"" + EMAIL + "\">alice@example.com</saml:NameID>" +
    "<saml:NameID>mallory@evil.example</saml:NameID>" +
    "<saml:SubjectConfirmation Method=\"" + BEARER + "\">" +
    "<saml:SubjectConfirmationData NotOnOrAfter=\"" + iso(C.TIME.minutes(5)) + "\" Recipient=\"" + ACS_URL + "\"/>" +
    "</saml:SubjectConfirmation></saml:Subject>";
  check("verify: Subject with two NameID children -> duplicate-nameid (XSW)",
    _verifyCode(sp, _mkAssertionResponse(idp, { tag: "dnid", subjectXml: twoNameId }).b64) === "auth-saml/duplicate-nameid");

  // A Status carried under an UNDECLARED namespace prefix does not resolve to
  // the SAML protocol namespace, so it is treated as absent -> bad-status. This
  // drives the prefix->namespace lookup returning null for an undeclared prefix.
  var undeclared = "<samlp:Response xmlns:samlp=\"" + SAML_P + "\" ID=\"_r\">" +
    "<zz:Status><zz:StatusCode Value=\"" + SUCCESS + "\"/></zz:Status></samlp:Response>";
  check("verify: Status under an undeclared prefix -> bad-status",
    _verifyCode(_mkSp(FAKE_CERT), b64(undeclared)) === "auth-saml/bad-status");
}

// ---------------------------------------------------------------------------
// SLO — remaining redirect + response build/parse branches
// ---------------------------------------------------------------------------

function testSloExtraBranches() {
  var sp = _mkSp(FAKE_CERT);
  var kp = pq.ml_dsa_65.keygen();

  var lrRs = sp.buildLogoutRequest({ nameId: "a@idp", sessionIndex: "_s", relayState: "/back&x=1" });
  check("SLO: buildLogoutRequest appends RelayState",
    lrRs.redirectUrl.indexOf("RelayState=" + encodeURIComponent("/back&x=1")) !== -1);
  var respRs = sp.buildLogoutResponse({ inResponseTo: "_o", destination: IDP_SLO_URL, relayState: "/back" });
  check("SLO: buildLogoutResponse appends RelayState",
    respRs.redirectUrl.indexOf("RelayState=" + encodeURIComponent("/back")) !== -1);

  check("SLO: buildLogoutResponse ml-dsa signingKey not a Uint8Array -> bad-signing-key",
    _codeOf(function () { sp.buildLogoutResponse({ inResponseTo: "_o", destination: IDP_SLO_URL, signingKey: "nope", signingAlg: "ml-dsa-65" }); }) === "auth-saml/bad-signing-key");

  check("SLO: parseLogoutResponse undeflatable base64 -> bad-saml-response",
    _codeOf(function () { sp.parseLogoutResponse(b64("this is not deflate-raw data")); }) === "auth-saml/bad-saml-response");

  var lrSigned = sp.buildLogoutRequest({ nameId: "a@idp", sessionIndex: "_s", signingKey: kp.secretKey, signingAlg: "ml-dsa-65" });
  var lq = lrSigned.redirectUrl.split("?")[1];
  var lreq = decodeURIComponent(lq.split("&")[0].slice("SAMLRequest=".length));
  check("SLO: parseLogoutRequest verify throws on malformed key -> verify-threw",
    _codeOf(function () { sp.parseLogoutRequest(lreq, { queryString: lq, idpVerifyKey: new Uint8Array(5), idpVerifyAlg: "ml-dsa-65" }); }) === "auth-saml/verify-threw");

  var unsignedResp = sp.buildLogoutResponse({ inResponseTo: "_o", destination: IDP_SLO_URL });
  var urq = unsignedResp.redirectUrl.split("?")[1];
  var uresp = decodeURIComponent(urq.split("&")[0].slice("SAMLResponse=".length));
  check("SLO: parseLogoutResponse verify but query lacks Signature -> no-signature",
    _codeOf(function () { sp.parseLogoutResponse(uresp, { queryString: urq, idpVerifyKey: kp.publicKey, idpVerifyAlg: "ml-dsa-65" }); }) === "auth-saml/no-signature");

  var signedResp = sp.buildLogoutResponse({ inResponseTo: "_o", destination: IDP_SLO_URL, signingKey: kp.secretKey, signingAlg: "ml-dsa-65" });
  var srq = signedResp.redirectUrl.split("?")[1];
  var sresp = decodeURIComponent(srq.split("&")[0].slice("SAMLResponse=".length));
  check("SLO: parseLogoutResponse verify throws on malformed key -> verify-threw",
    _codeOf(function () { sp.parseLogoutResponse(sresp, { queryString: srq, idpVerifyKey: new Uint8Array(5), idpVerifyAlg: "ml-dsa-65" }); }) === "auth-saml/verify-threw");
  check("SLO: parseLogoutResponse wrong verify key -> bad-signature",
    _codeOf(function () { sp.parseLogoutResponse(sresp, { queryString: srq, idpVerifyKey: pq.ml_dsa_65.keygen().publicKey, idpVerifyAlg: "ml-dsa-65" }); }) === "auth-saml/bad-signature");

  var noBody = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\">" +
    "<soapenv:Header></soapenv:Header></soapenv:Envelope>";
  check("SLO SOAP: Envelope without a Body child -> bad-soap",
    _codeOf(function () { sp.parseLogoutResponseSoap(noBody); }) === "auth-saml/bad-soap");
}

// ---------------------------------------------------------------------------
// _verifyEmbeddedXmlDsig — structural refusals via a crafted embedded Signature
// ---------------------------------------------------------------------------

function _craftReq(sigXml, rootId) {
  return b64("<samlp:LogoutRequest xmlns:samlp=\"" + SAML_P + "\" xmlns:saml=\"" + SAML_A + "\" ID=\"" + (rootId || "_x") +
    "\" Version=\"2.0\" IssueInstant=\"" + iso(0) + "\" Destination=\"" + IDP_SLO_URL + "\">" +
    "<saml:Issuer>i</saml:Issuer>" + sigXml + "<saml:NameID>a</saml:NameID></samlp:LogoutRequest>");
}

function testEmbeddedXmlDsigStructural() {
  var sp = _mkSp(FAKE_CERT);
  var kp = pq.ml_dsa_65.keygen();
  function code(sigXml, rootId, alg) {
    return _codeOf(function () { sp.parseLogoutRequestPost(_craftReq(sigXml, rootId), { idpVerifyKey: kp.publicKey, idpVerifyAlg: alg || "ml-dsa-65" }); });
  }
  check("embedded: unknown idpVerifyAlg -> bad-verify-alg",
    code(_craftSig({ noSignedInfo: true }), "_x", "bogus") === "auth-saml/bad-verify-alg");
  check("embedded: Signature without SignedInfo -> no-signed-info",
    code(_craftSig({ noSignedInfo: true })) === "auth-saml/no-signed-info");
  check("embedded: unsupported CanonicalizationMethod -> unsupported-c14n",
    code(_craftSig({ canon: "http://example/bogus-c14n" })) === "auth-saml/unsupported-c14n");
  check("embedded: SignedInfo without Reference -> no-reference",
    code(_craftSig({ sigMethod: MLDSA65_URN, omitReference: true })) === "auth-saml/no-reference");
  check("embedded: non-fragment Reference URI -> external-reference",
    code(_craftSig({ sigMethod: MLDSA65_URN, refUri: "https://evil.example/x" })) === "auth-saml/external-reference");
  check("embedded: Reference URI != root ID -> ref-mismatch",
    code(_craftSig({ sigMethod: MLDSA65_URN, refUri: "#other" }), "_x") === "auth-saml/ref-mismatch");
  check("embedded: unsupported DigestMethod -> unsupported-digest",
    code(_craftSig({ sigMethod: MLDSA65_URN, refId: "_x", digestMethod: "http://example/bogus-digest" }), "_x") === "auth-saml/unsupported-digest");
  check("embedded: empty DigestValue -> no-digest-value",
    code(_craftSig({ sigMethod: MLDSA65_URN, refId: "_x", digestMethod: SHA3_512, digestValue: "" }), "_x") === "auth-saml/no-digest-value");

  // no-signature-value: a validly-signed post whose SignatureValue is blanked
  // (the digest still matches, so the branch after the digest gate fires).
  var rsa = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });                       // allow:raw-byte-literal — RFC 8301 §3.1 RSA bit floor
  var skPem = rsa.privateKey.export({ type: "pkcs8", format: "pem" });
  var pkPem = rsa.publicKey.export({ type: "spki", format: "pem" });
  var post = sp.buildLogoutRequestPost({ nameId: "a@idp", signingKey: skPem, signingAlg: "rsa-sha256" });
  var blanked = Buffer.from(post.samlRequest, "base64").toString("utf8")
    .replace(/<ds:SignatureValue>[^<]*<\/ds:SignatureValue>/, "<ds:SignatureValue></ds:SignatureValue>");
  check("embedded: empty SignatureValue (valid digest) -> no-signature-value",
    _codeOf(function () { sp.parseLogoutRequestPost(b64(blanked), { idpVerifyKey: pkPem, idpVerifyAlg: "rsa-sha256" }); }) === "auth-saml/no-signature-value");

  // sig-verify-threw: valid signed post, verify with a malformed ml-dsa key.
  var post2 = sp.buildLogoutRequestPost({ nameId: "a@idp", signingKey: kp.secretKey, signingAlg: "ml-dsa-65" });
  check("embedded: signature verify throws on malformed key -> sig-verify-threw",
    _codeOf(function () { sp.parseLogoutRequestPost(post2.samlRequest, { idpVerifyKey: new Uint8Array(5), idpVerifyAlg: "ml-dsa-65" }); }) === "auth-saml/sig-verify-threw");
}

// ---------------------------------------------------------------------------
// EncryptedAssertion — content-cipher + XChaCha20 length pre-checks
// ---------------------------------------------------------------------------

function testEncryptedExtra(idp) {
  var sp = _mkSp(idp.certPem);
  var rsa = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });                       // allow:raw-byte-literal — RFC 8301 §3.1 RSA bit floor
  var spPriv = rsa.privateKey.export({ type: "pkcs8", format: "pem" });
  var spPub = rsa.publicKey.export({ type: "spki", format: "pem" });
  function wrap(cek) { return nodeCrypto.publicEncrypt({ key: spPub, padding: nodeCrypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" }, cek).toString("base64"); }
  function verifyEnc(encInner) { return _verifyCode(sp, b64(_response(STATUS_OK + encInner)), { spPrivateKeyPem: spPriv }); }

  var noContent = "<saml:EncryptedAssertion><xenc:EncryptedData xmlns:xenc=\"" + XENC + "\">" +
    "<xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#aes256-gcm\"></xenc:EncryptionMethod>" +
    "<ds:KeyInfo xmlns:ds=\"" + DS + "\"><xenc:EncryptedKey xmlns:xenc=\"" + XENC + "\">" +
    "<xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#rsa-oaep\"><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"></ds:DigestMethod></xenc:EncryptionMethod>" +
    "<xenc:CipherData><xenc:CipherValue>" + wrap(nodeCrypto.randomBytes(32)) + "</xenc:CipherValue></xenc:CipherData>" +   // allow:raw-byte-literal — AES-256 key
    "</xenc:EncryptedKey></ds:KeyInfo></xenc:EncryptedData></saml:EncryptedAssertion>";
  check("encrypted: EncryptedData without content CipherValue -> encrypted-no-content-cipher-value",
    verifyEnc(noContent) === "auth-saml/encrypted-no-content-cipher-value");

  // XChaCha20-Poly1305 length pre-checks (fire before the AEAD call).
  check("encrypted: XChaCha20 wrong CEK length -> encrypted-wrong-cek-len",
    verifyEnc(_encData({ contentAlg: XCHACHA_URN, wrapped: wrap(nodeCrypto.randomBytes(16)), content: "AA==" })) === "auth-saml/encrypted-wrong-cek-len");
  check("encrypted: XChaCha20 content shorter than nonce+tag -> encrypted-content-too-short",
    verifyEnc(_encData({ contentAlg: XCHACHA_URN, wrapped: wrap(nodeCrypto.randomBytes(32)), content: Buffer.alloc(10).toString("base64") })) === "auth-saml/encrypted-content-too-short");
}

// ---------------------------------------------------------------------------
// EncryptedAssertion — PQC-first key transport + content encryption round trips
//   ML-KEM-1024 key transport (urn:blamejs:experimental:xmlenc:ml-kem-1024)
//   XChaCha20-Poly1305 content (urn:blamejs:experimental:xmlenc:xchacha20-poly1305)
// These exercise the two framework-experimental decrypt paths end to end:
// _decryptEncryptedAssertion must call real, exported b.crypto primitives
// (the envelope opener + the packed XChaCha20-Poly1305 AEAD), not symbols
// crypto.js never exposed.
// ---------------------------------------------------------------------------

var MLKEM_URN = "urn:blamejs:experimental:xmlenc:ml-kem-1024";

// AES-256-GCM content framing (nonce(12) || ciphertext || tag(16)) — the wire
// shape _decryptEncryptedAssertion reads for the AES-GCM content branch.
function _gcmContent(cek, buf) {
  var iv = nodeCrypto.randomBytes(12);                                                            // allow:raw-byte-literal — GCM 96-bit IV
  var cipher = nodeCrypto.createCipheriv("aes-256-gcm", cek, iv);
  var ct = Buffer.concat([cipher.update(buf), cipher.final()]);
  return Buffer.concat([iv, ct, cipher.getAuthTag()]).toString("base64");
}

// XChaCha20-Poly1305 content framing (nonce(24) || ciphertext || tag(16)).
// b.crypto.encryptPacked emits a 1-byte format tag + that exact tail; strip
// the format byte to leave the XMLEnc CipherValue the SAML reader expects.
function _xchachaContent(cek, buf) {
  var packed = b.crypto.encryptPacked(buf, cek);                                                  // [fmt(1) | nonce(24) | ct+tag]
  return packed.subarray(1).toString("base64");
}

// Wrap a CEK in the framework ML-KEM-1024 KEM-only envelope; the envelope's
// plaintext IS the CEK. Passing only the ML-KEM public key selects the
// KEM-only suite (no P-384 hybrid leg) that the SAML urn expects.
function _wrapMlkem(spPubMlkem, cek) { return b.crypto.encrypt(cek, spPubMlkem); }

function testEncryptedAssertionPqc(idp) {
  var sp = _mkSp(idp.certPem);
  var clear = _buildAssertion(idp, { tag: "pqc-enc" }).full;

  // SP holds an ML-KEM-1024 keypair for PQC key transport.
  var mlkemKp = b.crypto.generateEncryptionKeyPair();       // { publicKey: ml-kem-1024, privateKey, ec... }

  // RSA keypair for the mixed RSA-transport + XChaCha-content case.
  var rsa = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });                       // allow:raw-byte-literal — RFC 8301 §3.1 RSA bit floor
  var rsaPriv = rsa.privateKey.export({ type: "pkcs8", format: "pem" });
  var rsaPub = rsa.publicKey.export({ type: "spki", format: "pem" });
  function wrapRsa(cek) {
    return nodeCrypto.publicEncrypt({ key: rsaPub, padding: nodeCrypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" }, cek).toString("base64");
  }

  // Case A — ML-KEM-1024 key transport + AES-256-GCM content. Isolates the
  // envelope-unwrap primitive (bug 1): pre-fix, the ml-kem branch called the
  // never-exported bCrypto.decryptEnvelope and threw encrypted-key-unwrap-failed.
  var cekA = nodeCrypto.randomBytes(32);                                                          // allow:raw-byte-literal — AES-256 key
  var xmlA = b64(_response(STATUS_OK + _encData({
    keyAlg: MLKEM_URN, oaepDigest: null,
    wrapped: _wrapMlkem(mlkemKp.publicKey, cekA),
    content: _gcmContent(cekA, Buffer.from(clear, "utf8")),
  })));
  check("encrypted(pqc): ML-KEM-1024 key transport + AES-256-GCM -> nameId",
    sp.verifyResponse(xmlA, { spPrivateKeyPem: mlkemKp.privateKey }).nameId === "alice@example.com");

  // Case B — RSA-OAEP-SHA256 key transport + XChaCha20-Poly1305 content.
  // Isolates the AEAD content primitive (bug 2): pre-fix, the xchacha branch
  // called the never-exported bCrypto.aeadDecrypt and threw content-tag-mismatch.
  var cekB = nodeCrypto.randomBytes(32);                                                          // allow:raw-byte-literal — XChaCha20 key
  var xmlB = b64(_response(STATUS_OK + _encData({
    contentAlg: XCHACHA_URN,
    wrapped: wrapRsa(cekB),
    content: _xchachaContent(cekB, Buffer.from(clear, "utf8")),
  })));
  check("encrypted(pqc): RSA-OAEP-SHA256 + XChaCha20-Poly1305 content -> nameId",
    sp.verifyResponse(xmlB, { spPrivateKeyPem: rsaPriv }).nameId === "alice@example.com");

  // Case C — full PQC-first path: ML-KEM-1024 key transport + XChaCha20-Poly1305
  // content (both fixed primitives in one assertion).
  var cekC = nodeCrypto.randomBytes(32);                                                          // allow:raw-byte-literal — XChaCha20 key
  var xmlC = b64(_response(STATUS_OK + _encData({
    keyAlg: MLKEM_URN, oaepDigest: null, contentAlg: XCHACHA_URN,
    wrapped: _wrapMlkem(mlkemKp.publicKey, cekC),
    content: _xchachaContent(cekC, Buffer.from(clear, "utf8")),
  })));
  check("encrypted(pqc): ML-KEM-1024 + XChaCha20-Poly1305 full PQC path -> nameId",
    sp.verifyResponse(xmlC, { spPrivateKeyPem: mlkemKp.privateKey }).nameId === "alice@example.com");

  // Authentication must still hold: a single flipped byte in the XChaCha20
  // ciphertext+tag fails the Poly1305 verification (the fix routes through
  // the real AEAD, it does not skip the tag check).
  var packedBad = b.crypto.encryptPacked(Buffer.from(clear, "utf8"), cekC);                       // [fmt(1) | nonce(24) | ct+tag]
  packedBad[packedBad.length - 1] ^= 0xff;                                                        // allow:raw-byte-literal — corrupt the Poly1305 tag
  var xmlBad = b64(_response(STATUS_OK + _encData({
    keyAlg: MLKEM_URN, oaepDigest: null, contentAlg: XCHACHA_URN,
    wrapped: _wrapMlkem(mlkemKp.publicKey, cekC),
    content: packedBad.subarray(1).toString("base64"),
  })));
  check("encrypted(pqc): XChaCha20 tampered tag -> encrypted-content-tag-mismatch",
    _verifyCode(sp, xmlBad, { spPrivateKeyPem: mlkemKp.privateKey }) === "auth-saml/encrypted-content-tag-mismatch");

  // A corrupt ML-KEM envelope still fails closed as an unwrap error (no
  // silent accept of an undecryptable key transport).
  check("encrypted(pqc): corrupt ML-KEM envelope -> encrypted-key-unwrap-failed",
    _verifyCode(sp, b64(_response(STATUS_OK + _encData({
      keyAlg: MLKEM_URN, oaepDigest: null, contentAlg: XCHACHA_URN,
      wrapped: nodeCrypto.randomBytes(64).toString("base64"),
      content: _xchachaContent(cekC, Buffer.from(clear, "utf8")),
    }))), { spPrivateKeyPem: mlkemKp.privateKey }) === "auth-saml/encrypted-key-unwrap-failed");
}

async function run() {
  var idp   = await _mint("idp.example");
  var other = await _mint("other-idp.example");
  var client = await _mint("client.example");
  var otherClient = await _mint("other-client.example");
  var fed   = await _mint("federation.example");

  // _verifyXmldsig
  testVerifyXmldsigStructural(idp);
  testVerifyXmldsigNoSignatureValue(idp);
  testVerifyXmldsigBadSignature(idp, other);
  await testVerifyXmldsigEcdsa();
  testVerifyXmldsigWithComments(idp);
  // verifyResponse signed-path
  testResponseLevelSignature(idp);
  testAssertionSignedDifferentElement(idp);
  testNoValidConfirmation(idp);
  testHolderOfKey(idp, client, otherClient);
  testConditionsAndAudience(idp);
  testMoreVerifyResponse(idp);
  testEncryptedAssertion(idp);
  testEncryptedExtra(idp);
  testEncryptedAssertionPqc(idp);
  // SLO
  testSloPostBindings();
  testSloRedirectAndParse();
  testSloExtraBranches();
  testEmbeddedXmlDsigStructural();
  // fetchMdq
  await testFetchMdqBranches(fed);
}

if (require.main === module) {
  run().then(function () {
    console.log("OK — " + helpers.getChecks() + " checks passed");
    process.exit(0);
  }).catch(function (e) { console.error(e && e.stack || e); process.exit(1); });
}
module.exports = { run: run };
