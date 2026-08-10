// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.network.tls.ocsp.evaluate — the refusal paths.
 *
 * A revocation check is only worth the bytes it costs if it says NO for every
 * reason it should. The accept path has been covered since the primitive
 * shipped; most of what evaluate() actually contains is refusal, and this
 * suite drives each one through the real consumer call with a response that is
 * well-formed in every respect except the thing under test:
 *
 *   - certStatus revoked / unknown (the answers the whole check exists for);
 *   - a responseStatus that is not 'successful';
 *   - ResponseData carrying no responses at all;
 *   - a nonce that does not echo, and one that is absent when required —
 *     both shapes of the extension (RFC 8954 raw, RFC 6960 double-wrapped);
 *   - a signature that does not verify;
 *   - a signatureAlgorithm that disagrees with the issuer key;
 *   - a CertID under a hash the verifier does not recognise, and one that
 *     names a different issuer than the certificate under validation.
 *
 * Responses come from helpers.buildOcspResponse so a new case is an option
 * rather than another copy of the DER assembly.
 *
 * Run standalone: node test/layer-0-primitives/tls-ocsp-refusals.test.js
 */

var nodeCrypto = require("node:crypto");
var helpers    = require("../helpers");
var b          = helpers.b;
var check      = helpers.check;
var buildOcsp  = helpers.buildOcspResponse;

// Fixed reference time — every response is dated relative to it and passed to
// evaluate as opts.now, so nothing here depends on the wall clock.
var NOW        = Date.parse("2025-06-15T00:00:01Z");
var PRODUCED   = NOW - 1000;
var NEXT       = NOW + 86400000;                                                                 // allow:raw-byte-literal — +1 day, a fresh response

function _evaluate(buildOpts, evalOpts) {
  var r = buildOcsp(Object.assign({ producedAtMs: PRODUCED, nextUpdateMs: NEXT }, buildOpts || {}));
  var out = b.network.tls.ocsp.evaluate(r.der, Object.assign(
    { issuerPem: r.issuerPem, serialHex: r.serialHex, now: NOW }, evalOpts || {}));
  return { r: r, ev: out };
}

function _errorsSay(ev, re) {
  return (ev.errors || []).some(function (m) { return re.test(String(m)); });
}

// Positive control. Everything below differs from this by exactly one thing,
// so a refusal that fires here would make every other case meaningless.
function testGoodResponseIsAccepted() {
  var ev = _evaluate().ev;
  check("a fresh, signed, good response is accepted", ev.ok === true);
  check("the accepted response reports certStatus good", ev.certStatus === "good");
  check("the accepted response reports no errors", (ev.errors || []).length === 0);
}

function testRevokedAndUnknownAreRefused() {
  var revoked = _evaluate({ certStatus: "revoked", revocationTimeMs: PRODUCED }).ev;
  check("a revoked certificate is refused", revoked.ok === false);
  check("the refusal reports certStatus revoked", revoked.certStatus === "revoked");
  check("the refusal names the status rather than a parse problem",
        _errorsSay(revoked, /certStatus=revoked/));

  // A responder that carries a revocation reason must not parse differently
  // from one that omits it — the [0] EXPLICIT CRLReason is optional.
  var withReason = _evaluate({ certStatus: "revoked", revocationTimeMs: PRODUCED,
                               revocationReason: 1 }).ev;
  check("a revocation carrying a CRLReason is still read as revoked",
        withReason.ok === false && withReason.certStatus === "revoked");

  var unknown = _evaluate({ certStatus: "unknown" }).ev;
  check("an unknown certificate is refused", unknown.ok === false);
  check("the refusal reports certStatus unknown", unknown.certStatus === "unknown");
}

// "unauthorized" is what a responder returns for a certificate it does not
// serve. Treating that as anything but a refusal would turn "I cannot answer"
// into "not revoked".
function testNonSuccessfulStatusIsRefused() {
  var ev = _evaluate({ responseStatus: 6 }).ev;
  check("a non-successful responseStatus is refused", ev.ok === false);
  check("the refusal names the status", _errorsSay(ev, /responseStatus=unauthorized/));

  var tryLater = _evaluate({ responseStatus: 3 }).ev;
  check("tryLater is refused too", tryLater.ok === false);
}

function testResponseDataWithoutResponsesIsRefused() {
  var ev = _evaluate({ omitResponses: true }).ev;
  check("a ResponseData with no responses is refused", ev.ok === false);
  check("the refusal names the missing SEQUENCE",
        _errorsSay(ev, /missing responses SEQUENCE/));
}

// RFC 8954 carries the nonce as raw bytes in the extnValue OCTET STRING; RFC
// 6960 wrapped it in a second one. A verifier that reads only one shape scores
// a live responder's echo as a mismatch and refuses a perfectly good response.
function testBothNonceEncodingsAreRead() {
  var nonce = Buffer.from("abcdef0123456789", "hex");
  var raw = _evaluate({ nonce: nonce }, { expectedNonce: nonce }).ev;
  check("an RFC 8954 raw nonce echo is accepted", raw.ok === true);
  check("the raw-nonce result reports the match", raw.nonce === "matched");

  var wrapped = _evaluate({ nonce: nonce, nonceWrapped: true }, { expectedNonce: nonce }).ev;
  check("an RFC 6960 double-wrapped nonce echo is accepted", wrapped.ok === true);
  check("the wrapped-nonce result reports the match", wrapped.nonce === "matched");
}

// The nonce is the replay defence: without it a "good" captured before
// revocation stays convincing forever.
function testNonceMismatchAndAbsenceAreRefused() {
  var expected = Buffer.from("abcdef0123456789", "hex");
  var wrong = _evaluate({ nonce: Buffer.from("1111111111111111", "hex") },
                        { expectedNonce: expected }).ev;
  check("a nonce that does not echo is refused", wrong.ok === false);
  check("the refusal names replay as the reason", _errorsSay(wrong, /nonce mismatch/i));

  var absent = _evaluate({}, { expectedNonce: expected }).ev;
  check("a response with no nonce is refused when one was required",
        absent.ok === false);
  check("the refusal says the extension is missing",
        _errorsSay(absent, /missing nonce extension/i));
}

function testBadSignatureIsRefused() {
  var ev = _evaluate({ corruptSignature: true }).ev;
  check("a signature that does not verify is refused", ev.ok === false);
  check("the refusal reports signatureValid false", ev.signatureValid === false);

  // A response signed by a key that is not the issuer's must fail even though
  // the signature is internally well-formed.
  var other = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var mine = buildOcsp({ producedAtMs: PRODUCED, nextUpdateMs: NEXT });
  var theirs = buildOcsp({ producedAtMs: PRODUCED, nextUpdateMs: NEXT, keyPair: other });
  var crossed = b.network.tls.ocsp.evaluate(theirs.der,
    { issuerPem: mine.issuerPem, serialHex: theirs.serialHex, now: NOW });
  check("a response signed by a different key is refused", crossed.ok === false);
  check("the wrong-signer refusal reports signatureValid false",
        crossed.signatureValid === false);
}

// RFC 6960 §4.2.1: signatureAlgorithm identifies the algorithm the responder
// used. Accepting a response that declares RSA and carries ECDSA (or the
// reverse) is not a forgery path — the issuer's private key is still required
// either way — but it means the verifier is deriving the digest from a field
// it never checked against the key, and a verifier that will not say what it
// verified cannot be reasoned about.
function testSignatureAlgorithmMustAgreeWithTheIssuerKey() {
  var ecKeyRsaOid = _evaluate({ signatureAlgOid: "1.2.840.113549.1.1.11" }).ev;
  check("an EC-signed response declaring an RSA algorithm is refused",
        ecKeyRsaOid.ok === false);
  check("the refusal names the disagreement",
        _errorsSay(ecKeyRsaOid, /signatureAlgorithm|does not match the issuer key/i));

  var rsa = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  var rsaKeyEcOid = _evaluate({ keyPair: rsa, signatureAlgOid: "1.2.840.10045.4.3.2" }).ev;
  check("an RSA-signed response declaring an ECDSA algorithm is refused",
        rsaKeyEcOid.ok === false);

  // The matching pairings still verify — the check must not cost a real
  // responder its answer.
  var rsaMatched = _evaluate({ keyPair: rsa, signatureAlgOid: "1.2.840.113549.1.1.11" }).ev;
  check("an RSA responder declaring its own algorithm is still accepted",
        rsaMatched.ok === true);
  var ecMatched = _evaluate().ev;
  check("an EC responder declaring its own algorithm is still accepted",
        ecMatched.ok === true);
}

function testUnsupportedSignatureAlgorithmIsRefused() {
  var ev = _evaluate({ signatureAlgOid: "1.2.840.113549.1.1.5" }).ev;      // sha1WithRSA
  check("a signatureAlgorithm the verifier does not support is refused",
        ev.ok === false);
  check("the refusal names the OID", _errorsSay(ev, /not supported by the verifier/));
}

// The CertID binding is what stops a "good" for some other certificate of the
// same responder being replayed as proof for this one.
function testCertIdBindingRefusals() {
  var issuerDer = helpers.synthCertForOcsp(Buffer.from([0x0a]), Buffer.from("Issuer"),
                                           Buffer.from("issuer-key-bytes-bbbbbbbbbbbbbbbb"));
  var badHash = _evaluate({ certIdHashOid: "1.2.3.4.5.6.7.8", certIdIssuerDer: null },
                          { issuerCertDer: issuerDer }).ev;
  check("a CertID under an unrecognised hash algorithm is refused", badHash.ok === false);
  check("the refusal names the hash algorithm",
        _errorsSay(badHash, /hashAlgorithm|not a recognized hash/i));

  var notABuffer = _evaluate({}, { issuerCertDer: "not-der" }).ev;
  check("a non-Buffer issuerCertDer is refused rather than coerced",
        notABuffer.ok === false);

  // Filler hashes cannot match a real issuer cert, which is the wrong-issuer
  // shape the binding exists to catch.
  var wrongIssuer = _evaluate({}, { issuerCertDer: issuerDer }).ev;
  check("a CertID naming a different issuer is refused", wrongIssuer.ok === false);
  check("the refusal cites the issuer binding",
        _errorsSay(wrongIssuer, /issuerNameHash|issuerKeyHash/));
}

function testMissingThisUpdateIsRefused() {
  var ev = _evaluate({ omitThisUpdate: true }).ev;
  check("a SingleResponse with no thisUpdate is refused", ev.ok === false);
  check("the refusal names thisUpdate", _errorsSay(ev, /missing thisUpdate/));
}

async function run() {
  testGoodResponseIsAccepted();
  testRevokedAndUnknownAreRefused();
  testNonSuccessfulStatusIsRefused();
  testResponseDataWithoutResponsesIsRefused();
  testBothNonceEncodingsAreRead();
  testNonceMismatchAndAbsenceAreRefused();
  testBadSignatureIsRefused();
  testSignatureAlgorithmMustAgreeWithTheIssuerKey();
  testUnsupportedSignatureAlgorithmIsRefused();
  testCertIdBindingRefusals();
  testMissingThisUpdateIsRefused();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.message) || e); process.exit(1); }
  );
}
