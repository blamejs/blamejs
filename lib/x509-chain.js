// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var asn1 = require("./asn1-der");

var OID_BASIC_CONSTRAINTS = "2.5.29.19";

/**
 * @module b.x509Chain
 * @nav    Crypto
 * @title  X.509 chain (CA-bit issuer test)
 *
 * @intro
 *   The basicConstraints-enforcing issuer test the framework's own
 *   certificate-chain walkers route through (<code>b.tsa.verifyToken</code>,
 *   <code>b.mail.bimi</code> VMC/CMC, <code>b.mail.crypto.smime</code>,
 *   <code>b.mdoc</code>, <code>b.contentCredentials</code>,
 *   <code>b.auth.fido</code>). It exists because node:crypto's
 *   <code>X509Certificate.checkIssued()</code> validates the issuer/subject
 *   DN match, the AKI/SKI linkage, and — only when a keyUsage extension is
 *   present — keyCertSign, but it does <strong>not</strong> enforce
 *   basicConstraints cA:TRUE. A leaf / end-entity certificate (cA:FALSE)
 *   that omits keyUsage is therefore wrongly accepted as a signing CA for
 *   the next certificate in the chain — the classic basicConstraints bypass
 *   (CVE-2002-0862 class). Every in-tree walker routes its issuer test
 *   through these helpers so the cA enforcement can never be forgotten in
 *   one walker but present in another.
 *
 *   Exposed so a consumer validating an X.509 chain <em>outside</em> a TLS
 *   handshake — an operator-uploaded CA bundle, a non-handshake PQ-signed
 *   certificate — has the same hardened, fail-closed test instead of being
 *   pushed toward the raw <code>checkIssued()</code> path this module
 *   exists to prevent. Both helpers fail closed: any malformed input or
 *   unsupported key type returns false rather than throwing.
 *
 * @card
 *   basicConstraints cA:TRUE-enforcing X.509 issuer test, fail-closed —
 *   the hardened alternative to node's checkIssued() for chains built
 *   outside a TLS handshake.
 */

/**
 * @primitive b.x509Chain.isCaCert
 * @signature b.x509Chain.isCaCert(cert)
 * @since     0.15.15
 * @status    stable
 * @related   b.x509Chain.issuerValidlyIssued
 *
 * True only when <code>cert</code> asserts basicConstraints cA:TRUE.
 * node's <code>X509Certificate</code> exposes <code>.ca</code> (a boolean);
 * a certificate with no basicConstraints extension or with cA:FALSE
 * returns false. A missing cert or a non-boolean <code>.ca</code> (parse
 * failure / unsupported runtime) fails closed to false.
 *
 * @example
 *   var crypto = require("crypto");
 *   var ca = new crypto.X509Certificate(caPem);
 *   b.x509Chain.isCaCert(ca);   // → true only if basicConstraints cA:TRUE
 */
function isCaCert(cert) {
  return !!cert && cert.ca === true;
}

/**
 * @primitive b.x509Chain.issuerValidlyIssued
 * @signature b.x509Chain.issuerValidlyIssued(issuer, subject)
 * @since     0.15.15
 * @status    stable
 * @related   b.x509Chain.isCaCert
 *
 * True when <code>issuer</code> validly issued <code>subject</code> AND is
 * itself a CA: the DN / AKI-SKI / keyUsage linkage (checkIssued), the
 * cryptographic signature (verify), and basicConstraints cA:TRUE
 * (isCaCert). The cA check runs first so a non-CA certificate is rejected
 * before the expensive signature verification. Any exception (malformed
 * cert, unsupported key type) fails closed to false.
 *
 * @example
 *   var crypto = require("crypto");
 *   var issuer  = new crypto.X509Certificate(issuerPem);
 *   var subject = new crypto.X509Certificate(leafPem);
 *   b.x509Chain.issuerValidlyIssued(issuer, subject);   // → boolean
 */
function issuerValidlyIssued(issuer, subject) {
  try {
    return isCaCert(issuer) &&
      subject.checkIssued(issuer) &&
      subject.verify(issuer.publicKey);
  } catch (_e) {
    return false;
  }
}

function _certExtensionValue(certDer, oid) {
  var certKids = asn1.readSequence(asn1.readNode(certDer, 0).value);
  var tbsKids = asn1.readSequence(certKids[0].value);
  var extsWrapper = null;
  for (var i = 0; i < tbsKids.length; i += 1) {
    if (tbsKids[i].tagClass === asn1.TAG_CLASS.CONTEXT_SPECIFIC && tbsKids[i].tag === 3) {
      extsWrapper = tbsKids[i];
      break;
    }
  }
  if (!extsWrapper) return null;
  var exts = asn1.readSequence(asn1.readNode(extsWrapper.value, 0).value);
  for (var j = 0; j < exts.length; j += 1) {
    if (exts[j].tag !== asn1.TAG.SEQUENCE) continue;
    var extKids = asn1.readSequence(exts[j].value);
    if (extKids.length < 2) continue;
    var extOid;
    try { extOid = asn1.readOid(extKids[0]); } catch (_e) { continue; }
    if (extOid !== oid) continue;
    return asn1.readOctetString(extKids[extKids.length - 1]);
  }
  return null;
}

function basicConstraintsPathLen(cert) {
  if (!cert || !Buffer.isBuffer(cert.raw)) return null;
  var extnValue;
  try { extnValue = _certExtensionValue(cert.raw, OID_BASIC_CONSTRAINTS); }
  catch (_e) { return null; }
  if (!extnValue) return null;
  try {
    var bc = asn1.readNode(extnValue, 0);
    if (bc.tag !== asn1.TAG.SEQUENCE) return null;
    var kids = asn1.readSequence(bc.value);
    for (var k = 0; k < kids.length; k += 1) {
      if (kids[k].tag === asn1.TAG.INTEGER && kids[k].tagClass === asn1.TAG_CLASS.UNIVERSAL) {
        return asn1.readUnsignedInt(kids[k]);
      }
    }
    return null;
  } catch (_e) {
    return null;
  }
}

function _normalizeDn(dn) {
  return String(dn).split("\n").map(function (rdn) {
    return rdn.replace(/\s+/g, " ").trim().toLowerCase();
  }).join("\n");
}

function _isSelfIssued(cert) {
  try {
    return !!cert && typeof cert.subject === "string" &&
      typeof cert.issuer === "string" &&
      _normalizeDn(cert.subject) === _normalizeDn(cert.issuer);
  } catch (_e) {
    return false;
  }
}

/**
 * @primitive b.x509Chain.pathLenSatisfied
 * @signature b.x509Chain.pathLenSatisfied(chain)
 * @since     0.20.21
 * @status    stable
 * @related   b.x509Chain.issuerValidlyIssued
 *
 * True when every CA in an ordered certificate chain honors its
 * basicConstraints pathLenConstraint (RFC 5280 §4.2.1.9 / §6.1.4).
 * <code>chain</code> is an array of node <code>X509Certificate</code>
 * objects ordered leaf-first (index 0 is the end-entity, the last element
 * is the topmost CA), the same order the framework's chain walkers build.
 * A CA that asserts pathLenConstraint N permits at most N non-self-issued
 * intermediate CAs between it and the end-entity; a chain that exceeds any
 * such limit returns false. node's <code>X509Certificate</code> does not
 * expose pathLenConstraint, so a chain built from otherwise-valid links can
 * silently exceed it; this reads the constraint from each certificate's DER
 * and enforces it. A chain shorter than two certificates has no CA link to
 * constrain and returns true. A missing certificate in the array fails
 * closed to false; a certificate with no pathLenConstraint imposes no limit.
 *
 * @example
 *   var crypto = require("crypto");
 *   var chain = [leafCert, intermediateCert, rootCert].map(function (pem) {
 *     return new crypto.X509Certificate(pem);
 *   });
 *   b.x509Chain.pathLenSatisfied(chain);   // → boolean
 */
function pathLenSatisfied(chain) {
  if (!Array.isArray(chain) || chain.length < 2) return true;
  var maxPathLen = Infinity;
  for (var i = chain.length - 1; i >= 0; i -= 1) {
    var cert = chain[i];
    if (!cert) return false;
    if (i >= 1 && !_isSelfIssued(cert)) {
      if (maxPathLen <= 0) return false;
      maxPathLen -= 1;
    }
    if (isCaCert(cert)) {
      var pl = basicConstraintsPathLen(cert);
      if (pl !== null && pl < maxPathLen) maxPathLen = pl;
    }
  }
  return true;
}

module.exports = {
  isCaCert:            isCaCert,
  issuerValidlyIssued: issuerValidlyIssued,
  pathLenSatisfied:    pathLenSatisfied,
};
