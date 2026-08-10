// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * OCSP response builder for tests — one parameterized RFC 6960 responder.
 *
 * The verifier's interesting behaviour is almost all REFUSAL: a status that
 * isn't successful, a CertID under a hash the verifier doesn't recognise, a
 * nonce that doesn't echo, a revoked or unknown certStatus, a ResponseData
 * with no responses at all. Reaching those needs a response that is
 * well-formed in every respect except the one under test, which is why each
 * suite that tried grew its own near-identical builder — and why they only
 * ever built the shapes that suite happened to need.
 *
 * One builder with knobs covers all of them, and a new refusal path costs an
 * option rather than a third copy of the DER assembly.
 *
 * Everything is deterministic: pass `producedAtMs` / `thisUpdateMs` /
 * `nextUpdateMs` and the bytes do not depend on the wall clock.
 */

var nodeCrypto = require("node:crypto");
var asn1       = require("../../lib/asn1-der");

var OID_SHA1             = "1.3.14.3.2.26";
var OID_ECDSA_SHA256     = "1.2.840.10045.4.3.2";
var OID_OCSP_BASIC       = "1.3.6.1.5.5.7.48.1.1";
var OID_OCSP_NONCE       = "1.3.6.1.5.5.7.48.1.2";

function _pad(n, width) {
  var s = String(n);
  while (s.length < width) s = "0" + s;
  return s;
}

// unix-ms → GeneralizedTime "YYYYMMDDhhmmssZ" — the on-the-wire shape the
// parser accepts. Whole seconds; every offset a test uses is minutes or more.
function generalizedTime(ms) {
  var d = new Date(ms);
  return asn1.writeNode(0x18, Buffer.from(
    _pad(d.getUTCFullYear(), 4) + _pad(d.getUTCMonth() + 1, 2) + _pad(d.getUTCDate(), 2) +
    _pad(d.getUTCHours(), 2) + _pad(d.getUTCMinutes(), 2) + _pad(d.getUTCSeconds(), 2) + "Z",
    "ascii"));
}

// A minimal but structurally-valid X.509 cert, enough for the issuer-DN and
// issuer-key hashing the CertID binding does.
function synthCert(serialBytes, cnBytes, pubKeyBytes) {
  var algId    = asn1.writeSequence([asn1.writeOid("1.2.840.113549.1.1.1"), asn1.writeNull()]);
  var cn       = asn1.writeSequence([asn1.writeOid("2.5.4.3"), asn1.writeNode(0x0c, cnBytes)]);
  var name     = asn1.writeSequence([asn1.writeNode(0x31, cn)]);
  var validity = asn1.writeSequence([
    asn1.writeNode(0x17, Buffer.from("260101000000Z")),
    asn1.writeNode(0x17, Buffer.from("270101000000Z")),
  ]);
  var spki     = asn1.writeSequence([algId,
    asn1.writeNode(0x03, Buffer.concat([Buffer.from([0]), pubKeyBytes]))]);
  var version  = asn1.writeContextExplicit(0, asn1.writeInteger(Buffer.from([2])));
  var tbs = asn1.writeSequence([version, asn1.writeInteger(serialBytes), algId,
                                name, validity, name, spki]);
  return asn1.writeSequence([tbs, algId, asn1.writeNode(0x03, Buffer.from([0, 0, 0, 0]))]);
}

// certStatus: [0] IMPLICIT NULL good / [1] IMPLICIT RevokedInfo / [2] IMPLICIT unknown.
function _certStatusNode(opts) {
  if (opts.certStatus === "revoked") {
    var revokedAt = generalizedTime(
      typeof opts.revocationTimeMs === "number" ? opts.revocationTimeMs : opts.producedAtMs);
    var body = typeof opts.revocationReason === "number"
      ? Buffer.concat([revokedAt, asn1.writeContextExplicit(0, asn1.writeNode(0x0a, Buffer.from([opts.revocationReason])))])
      : revokedAt;
    return asn1.writeContextImplicit(1, body);
  }
  if (opts.certStatus === "unknown") return asn1.writeContextImplicit(2, Buffer.alloc(0));
  return asn1.writeContextImplicit(0, Buffer.alloc(0));
}

/**
 * buildOcspResponse(opts?) — assemble a signed OCSP response.
 *
 * Defaults produce a valid, successful, certStatus-good response the verifier
 * accepts; every option below breaks exactly one thing so a refusal path can
 * be reached without disturbing the rest.
 *
 * @param opts.responseStatus  {number}  OCSPResponseStatus (default 0, successful)
 * @param opts.certStatus      {string}  "good" | "revoked" | "unknown"
 * @param opts.revocationTimeMs {number} for certStatus "revoked"
 * @param opts.revocationReason {number} CRLReason, adds the [0] EXPLICIT field
 * @param opts.producedAtMs    {number}  ResponseData.producedAt
 * @param opts.thisUpdateMs    {number}  SingleResponse.thisUpdate
 * @param opts.nextUpdateMs    {number}  SingleResponse.nextUpdate (omitted if absent)
 * @param opts.omitThisUpdate  {boolean} emit a SingleResponse with no thisUpdate
 * @param opts.rawThisUpdate   {string}  literal time body — for malformed-time
 *   cases a millisecond value cannot express (too short, wrong form)
 * @param opts.rawNextUpdate   {string}  literal nextUpdate body; null omits it
 * @param opts.timeTag         {number}  time tag (0x18 GeneralizedTime default,
 *   0x17 UTCTime — the two-digit-year form a responder may still emit)
 * @param opts.serial          {Buffer}  CertID serialNumber
 * @param opts.certIdHashOid   {string}  CertID hashAlgorithm OID (default SHA-1)
 * @param opts.issuerNameHash  {Buffer}  CertID issuerNameHash (default filler)
 * @param opts.issuerKeyHash   {Buffer}  CertID issuerKeyHash (default filler)
 * @param opts.certIdIssuerDer {Buffer}  derive the CertID hashes from this issuer cert
 * @param opts.nonce           {Buffer}  add an OCSP nonce responseExtension
 * @param opts.nonceWrapped    {boolean} RFC 6960 double-OCTET-STRING shape (default RFC 8954 raw)
 * @param opts.omitResponses   {boolean} ResponseData with NO responses SEQUENCE
 * @param opts.signatureAlgOid {string}  signatureAlgorithm OID (default ecdsa-with-SHA256)
 * @param opts.corruptSignature {boolean} flip a signature byte
 * @param opts.badSignatureBytes {boolean} replace the signature with zeroes —
 *   structurally present, cryptographically meaningless
 * @param opts.keyPair         {object}  sign with this key instead of a fresh one
 * @returns {object} { der, issuerPem, serialHex, serial, keyPair, certIdDer }
 *
 * @example
 *   var r = helpers.buildOcspResponse({ certStatus: "revoked", producedAtMs: NOW });
 *   var ev = b.network.tls.ocsp.evaluate(r.der, { issuerPem: r.issuerPem, now: NOW });
 *   // → ev.ok === false, ev.certStatus === "revoked"
 */
function buildOcspResponse(opts) {
  opts = Object.assign({
    responseStatus: 0,
    certStatus:     "good",
    producedAtMs:   Date.parse("2025-06-15T00:00:00Z"),
    serial:         Buffer.from([0x12, 0x34, 0x56, 0x78]),
    certIdHashOid:  OID_SHA1,
    signatureAlgOid: OID_ECDSA_SHA256,
  }, opts || {});
  if (typeof opts.thisUpdateMs !== "number") opts.thisUpdateMs = opts.producedAtMs;

  var kp = opts.keyPair || nodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var issuerPem = kp.publicKey.export({ type: "spki", format: "pem" });

  // CertID — either derived from a real issuer cert (so the binding check can
  // pass) or assembled from explicit hashes (so it can be made to fail).
  var certId;
  if (opts.certIdIssuerDer) {
    var iss = _hashesFor(opts.certIdIssuerDer, opts.certIdHashOid);
    certId = asn1.writeSequence([
      asn1.writeSequence([asn1.writeOid(opts.certIdHashOid), asn1.writeNull()]),
      asn1.writeOctetString(iss.nameHash),
      asn1.writeOctetString(iss.keyHash),
      asn1.writeInteger(opts.serial),
    ]);
  } else {
    certId = asn1.writeSequence([
      asn1.writeSequence([asn1.writeOid(opts.certIdHashOid), asn1.writeNull()]),
      asn1.writeOctetString(opts.issuerNameHash || Buffer.alloc(20, 0xaa)),
      asn1.writeOctetString(opts.issuerKeyHash || Buffer.alloc(20, 0xbb)),
      asn1.writeInteger(opts.serial),
    ]);
  }

  var timeTag = typeof opts.timeTag === "number" ? opts.timeTag : 0x18;
  var srChildren = [certId, _certStatusNode(opts)];
  if (!opts.omitThisUpdate) {
    srChildren.push(typeof opts.rawThisUpdate === "string"
      ? asn1.writeNode(timeTag, Buffer.from(opts.rawThisUpdate, "ascii"))
      : generalizedTime(opts.thisUpdateMs));
  }
  if (typeof opts.rawNextUpdate === "string") {
    srChildren.push(asn1.writeContextExplicit(0,
      asn1.writeNode(timeTag, Buffer.from(opts.rawNextUpdate, "ascii"))));
  } else if (opts.rawNextUpdate !== null && typeof opts.nextUpdateMs === "number") {
    srChildren.push(asn1.writeContextExplicit(0, generalizedTime(opts.nextUpdateMs)));
  }
  var singleResponse = asn1.writeSequence(srChildren);

  var tbsChildren = [
    asn1.writeContextExplicit(2, asn1.writeOctetString(Buffer.alloc(20, 0xcc))),   // responderID [2] KeyHash
    generalizedTime(opts.producedAtMs),
  ];
  if (!opts.omitResponses) tbsChildren.push(asn1.writeSequence([singleResponse]));
  if (opts.nonce) {
    var extnValue = opts.nonceWrapped ? asn1.writeOctetString(opts.nonce) : opts.nonce;
    tbsChildren.push(asn1.writeContextExplicit(1, asn1.writeSequence([
      asn1.writeSequence([asn1.writeOid(OID_OCSP_NONCE), asn1.writeOctetString(extnValue)]),
    ])));
  }
  var tbs = asn1.writeSequence(tbsChildren);

  var sig = opts.badSignatureBytes
    ? Buffer.alloc(70, 0x00)
    : nodeCrypto.sign("sha256", tbs, kp.privateKey);
  if (opts.corruptSignature) { sig = Buffer.from(sig); sig[sig.length - 1] ^= 0xff; }

  var basic = asn1.writeSequence([
    tbs,
    asn1.writeSequence([asn1.writeOid(opts.signatureAlgOid)]),
    asn1.writeBitString(sig),
  ]);
  var der = asn1.writeSequence([
    asn1.writeNode(0x0a, Buffer.from([opts.responseStatus])),
    asn1.writeContextExplicit(0, asn1.writeSequence([
      asn1.writeOid(OID_OCSP_BASIC),
      asn1.writeOctetString(basic),
    ])),
  ]);

  return {
    der:       der,
    issuerPem: issuerPem,
    serial:    opts.serial,
    serialHex: opts.serial.toString("hex"),
    keyPair:   kp,
    certIdDer: certId,
  };
}

// RFC 6960 §4.1.1 CertID hashes for an issuer cert, matching what the verifier
// recomputes. Uses the framework's own request builder so the two agree by
// construction rather than by a second implementation here.
function _hashesFor(issuerCertDer, hashOid) {
  var b = require("../../index.js");
  var req = b.network.tls.ocsp.buildRequest({
    leafCertDer:   synthCert(Buffer.from([0x01]), Buffer.from("Leaf"),
                             Buffer.from("leaf-key-bytes-aaaaaaaaaaaaaaaa")),
    issuerCertDer: issuerCertDer,
    nonce:         false,
  });
  var reqTop  = asn1.readNode(req.requestDer);
  var reqTbs  = asn1.readSequence(reqTop.value)[0];
  var reqList = asn1.readSequence(reqTbs.value)[0];
  var reqOne  = asn1.readSequence(reqList.value)[0];
  var certId  = asn1.readSequence(reqOne.value)[0];
  var kids    = asn1.readSequence(certId.value);
  if (hashOid !== OID_SHA1) {
    throw new Error("buildOcspResponse: certIdIssuerDer derivation only covers SHA-1 " +
                    "(what buildRequest emits); pass explicit issuerNameHash/issuerKeyHash instead");
  }
  return { nameHash: asn1.readOctetString(kids[1]), keyHash: asn1.readOctetString(kids[2]) };
}

module.exports = {
  buildOcspResponse: buildOcspResponse,
  synthCert:         synthCert,
  generalizedTime:   generalizedTime,
};
