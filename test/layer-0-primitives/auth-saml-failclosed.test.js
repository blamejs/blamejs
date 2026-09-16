// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.auth.saml.sp SLO — verification-config fail-closed.
 *
 * Every Single-Logout parse path (HTTP-Redirect, HTTP-POST, SOAP)
 * authenticates the inbound LogoutRequest / LogoutResponse against the
 * IdP key (idpVerifyKey + idpVerifyAlg). Verification is mandatory by
 * default: a parse with no verify key configured refuses the message
 * (a forged unsigned LogoutRequest would otherwise force-logout any
 * user). An operator accepts unsigned messages only by passing
 * allowUnsigned:true explicitly. A HALF-supplied pair (key without alg,
 * or alg without key) is an operator configuration mistake — it must
 * fail CLOSED (throw), never silently skip signature verification and
 * accept a forged, unsigned message.
 *
 * Regression guard for the fail-open where the HTTP-POST / SOAP paths
 * gated verification on `key || alg` but the underlying helper returned
 * without verifying whenever either half was missing, so a hostile
 * original sender or a malicious peer MX could smuggle an unsigned
 * LogoutRequest past a verifier that supplied a key but forgot the alg.
 * The redirect binding had the mirror-image gap for alg-without-key.
 */

var helpers = require("../helpers");
var check = helpers.check;
var b = helpers.b;
var pq = require("../../lib/pqc-software");

function _newSp() {
  return b.auth.saml.sp.create({
    entityId:                    "https://sp.example/saml",
    assertionConsumerServiceUrl: "https://sp.example/acs",
    idpEntityId:                 "https://idp.example/saml",
    idpSsoUrl:                   "https://idp.example/sso",
    idpSloUrl:                   "https://idp.example/slo",
    idpCertPem:                  "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----",
  });
}

function _stripQuery(url) { return url.split("?")[1]; }
function _samlReq(query)  { return decodeURIComponent(query.split("&")[0].slice("SAMLRequest=".length)); }
function _samlResp(query) { return decodeURIComponent(query.split("&")[0].slice("SAMLResponse=".length)); }

function _codeOf(fn) {
  var threw = null;
  try { fn(); } catch (e) { threw = e && e.code; }
  return threw;
}

// ---- HTTP-POST binding: the reported fail-open ----

function testPostLogoutRequestKeyWithoutAlgFailsClosed() {
  // A hostile sender POSTs an UNSIGNED LogoutRequest. The SP intends to
  // verify (supplies idpVerifyKey) but the operator omitted idpVerifyAlg.
  // The parse must refuse, not silently accept the forged NameID.
  var sp = _newSp();
  var forged = sp.buildLogoutRequestPost({ nameId: "attacker@evil", sessionIndex: "_s" });
  var idpKp = pq.ml_dsa_65.keygen();
  var code = _codeOf(function () {
    sp.parseLogoutRequestPost(forged.samlRequest, { idpVerifyKey: idpKp.publicKey });
  });
  check("POST parseLogoutRequestPost key-without-alg fails closed",
    code === "auth-saml/no-verify-alg");
}

function testPostLogoutRequestAlgWithoutKeyFailsClosed() {
  var sp = _newSp();
  var forged = sp.buildLogoutRequestPost({ nameId: "attacker@evil", sessionIndex: "_s" });
  var code = _codeOf(function () {
    sp.parseLogoutRequestPost(forged.samlRequest, { idpVerifyAlg: "ml-dsa-65" });
  });
  check("POST parseLogoutRequestPost alg-without-key fails closed",
    code === "auth-saml/no-verify-key");
}

// ---- SOAP back-channel binding: same helper, same class ----

function _forgedSoapLogoutResponse(sp) {
  var lr = sp.buildLogoutResponse({
    inResponseTo: "_orig-id-123",
    destination:  "https://idp.example/slo",
  });
  return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
    "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\">" +
    "<soapenv:Body>" + lr.raw + "</soapenv:Body>" +
    "</soapenv:Envelope>";
}

function testSoapLogoutResponseKeyWithoutAlgFailsClosed() {
  var sp = _newSp();
  var soap = _forgedSoapLogoutResponse(sp);
  var idpKp = pq.ml_dsa_65.keygen();
  var code = _codeOf(function () {
    sp.parseLogoutResponseSoap(soap, { idpVerifyKey: idpKp.publicKey });
  });
  check("SOAP parseLogoutResponseSoap key-without-alg fails closed",
    code === "auth-saml/no-verify-alg");
}

function testSoapLogoutResponseAlgWithoutKeyFailsClosed() {
  var sp = _newSp();
  var soap = _forgedSoapLogoutResponse(sp);
  var code = _codeOf(function () {
    sp.parseLogoutResponseSoap(soap, { idpVerifyAlg: "ml-dsa-65" });
  });
  check("SOAP parseLogoutResponseSoap alg-without-key fails closed",
    code === "auth-saml/no-verify-key");
}

// ---- HTTP-Redirect binding: mirror-image gap (alg-without-key) ----

function testRedirectLogoutRequestAlgWithoutKeyFailsClosed() {
  // The redirect gate keyed only on idpVerifyKey, so an alg supplied
  // without a key silently skipped verification of an unsigned request.
  var sp = _newSp();
  var lr = sp.buildLogoutRequest({ nameId: "attacker@evil", sessionIndex: "_s" });
  var q = _stripQuery(lr.redirectUrl);
  var code = _codeOf(function () {
    sp.parseLogoutRequest(_samlReq(q), { queryString: q, idpVerifyAlg: "ml-dsa-65" });
  });
  check("redirect parseLogoutRequest alg-without-key fails closed",
    code === "auth-saml/no-verify-key");
}

function testRedirectLogoutResponseAlgWithoutKeyFailsClosed() {
  var sp = _newSp();
  var lr = sp.buildLogoutResponse({
    inResponseTo: "_orig-id-123",
    destination:  "https://idp.example/slo",
  });
  var q = _stripQuery(lr.redirectUrl);
  var code = _codeOf(function () {
    sp.parseLogoutResponse(_samlResp(q), { queryString: q, idpVerifyAlg: "ml-dsa-65" });
  });
  check("redirect parseLogoutResponse alg-without-key fails closed",
    code === "auth-saml/no-verify-key");
}

// ---- Positive controls: complete config verifies; no config skips ----

function testPostRoundtripStillVerifies() {
  var sp = _newSp();
  var kp = pq.ml_dsa_65.keygen();
  var lr = sp.buildLogoutRequestPost({
    nameId: "alice@idp", sessionIndex: "_s-42",
    signingKey: kp.secretKey, signingAlg: "ml-dsa-65",
  });
  var parsed = sp.parseLogoutRequestPost(lr.samlRequest, {
    idpVerifyKey: kp.publicKey, idpVerifyAlg: "ml-dsa-65",
  });
  check("POST roundtrip with full verify-config recovers nameId",
    parsed.nameId === "alice@idp");
}

function testPostUnsignedRefusedByDefault() {
  // Neither key nor alg → verification not configured. By default the parse
  // MUST refuse (a forged unsigned LogoutRequest would force-logout any user);
  // it no longer silently accepts the message.
  var sp = _newSp();
  var lr = sp.buildLogoutRequestPost({ nameId: "attacker@evil", sessionIndex: "_s" });
  var code = _codeOf(function () { sp.parseLogoutRequestPost(lr.samlRequest); });
  check("POST unsigned + no verify-config refused by default",
    code === "auth-saml/slo-verification-required");
}

function testPostUnsignedAllowUnsignedOptOut() {
  // The operator opts into unsigned acceptance explicitly.
  var sp = _newSp();
  var lr = sp.buildLogoutRequestPost({ nameId: "bob@idp", sessionIndex: "_s" });
  var parsed = sp.parseLogoutRequestPost(lr.samlRequest, { allowUnsigned: true });
  check("POST unsigned parses with explicit allowUnsigned:true opt-out",
    parsed.nameId === "bob@idp");
}

function testRedirectLogoutRequestUnsignedRefusedByDefault() {
  var sp = _newSp();
  var lr = sp.buildLogoutRequest({ nameId: "attacker@evil", sessionIndex: "_s" });
  var q = _stripQuery(lr.redirectUrl);
  var code = _codeOf(function () { sp.parseLogoutRequest(_samlReq(q), { queryString: q }); });
  check("redirect parseLogoutRequest unsigned + no key refused by default",
    code === "auth-saml/slo-verification-required");
}

function testRedirectLogoutRequestAllowUnsignedOptOut() {
  var sp = _newSp();
  var lr = sp.buildLogoutRequest({ nameId: "carol@idp", sessionIndex: "_s" });
  var q = _stripQuery(lr.redirectUrl);
  var parsed = sp.parseLogoutRequest(_samlReq(q), { queryString: q, allowUnsigned: true });
  check("redirect parseLogoutRequest parses with allowUnsigned:true",
    parsed.nameId === "carol@idp");
}

function testRedirectLogoutResponseUnsignedRefusedByDefault() {
  var sp = _newSp();
  var lr = sp.buildLogoutResponse({ inResponseTo: "_orig-id-123", destination: "https://idp.example/slo" });
  var q = _stripQuery(lr.redirectUrl);
  var code = _codeOf(function () { sp.parseLogoutResponse(_samlResp(q), { queryString: q }); });
  check("redirect parseLogoutResponse unsigned + no key refused by default",
    code === "auth-saml/slo-verification-required");
}

function testSoapLogoutResponseUnsignedRefusedByDefault() {
  var sp = _newSp();
  var soap = _forgedSoapLogoutResponse(sp);
  var code = _codeOf(function () { sp.parseLogoutResponseSoap(soap); });
  check("SOAP parseLogoutResponseSoap unsigned + no key refused by default",
    code === "auth-saml/slo-verification-required");
}

function run() {
  testPostLogoutRequestKeyWithoutAlgFailsClosed();
  testPostLogoutRequestAlgWithoutKeyFailsClosed();
  testSoapLogoutResponseKeyWithoutAlgFailsClosed();
  testSoapLogoutResponseAlgWithoutKeyFailsClosed();
  testRedirectLogoutRequestAlgWithoutKeyFailsClosed();
  testRedirectLogoutResponseAlgWithoutKeyFailsClosed();
  testPostRoundtripStillVerifies();
  testPostUnsignedRefusedByDefault();
  testPostUnsignedAllowUnsignedOptOut();
  testRedirectLogoutRequestUnsignedRefusedByDefault();
  testRedirectLogoutRequestAllowUnsignedOptOut();
  testRedirectLogoutResponseUnsignedRefusedByDefault();
  testSoapLogoutResponseUnsignedRefusedByDefault();
}

if (require.main === module) {
  try { run(); }
  catch (e) { console.error(e); process.exit(1); }
}
module.exports = { run: run };
