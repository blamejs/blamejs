// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var nodeCrypto = require("node:crypto");
var asn1 = require("./asn1-der");
var numericBounds = require("./numeric-bounds");

var OID_BASIC_CONSTRAINTS = "2.5.29.19";

function _certLike(cert) {
  return cert instanceof nodeCrypto.X509Certificate;
}

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
  var tbsKids = asn1.readCertificateTbsFields(certDer).tbsKids;
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

var CASE_IGNORE_OIDS = {
  "2.5.4.3": 1, "2.5.4.4": 1, "2.5.4.5": 1, "2.5.4.6": 1, "2.5.4.7": 1,
  "2.5.4.8": 1, "2.5.4.9": 1, "2.5.4.10": 1, "2.5.4.11": 1, "2.5.4.12": 1,
  "2.5.4.13": 1, "2.5.4.15": 1, "2.5.4.17": 1, "2.5.4.18": 1, "2.5.4.19": 1,
  "2.5.4.27": 1, "2.5.4.41": 1, "2.5.4.42": 1, "2.5.4.43": 1, "2.5.4.44": 1,
  "2.5.4.46": 1, "2.5.4.51": 1, "2.5.4.65": 1,
  "0.9.2342.19200300.100.1.1": 1, "0.9.2342.19200300.100.1.25": 1,
  "1.2.840.113549.1.9.1": 1,
};

function _attrValueKey(node, caseIgnore) {
  var buf = node.value;
  if (!caseIgnore) return "b:" + node.tag.toString(16) + ":" + buf.toString("hex");
  var s = null;
  if (node.tag === 0x13 || node.tag === 0x16 || node.tag === 0x14) {
    s = buf.toString("latin1");
  } else if (node.tag === 0x0c) {
    s = buf.toString("utf8");
    if (!Buffer.from(s, "utf8").equals(buf)) s = null;
  } else if (node.tag === 0x1e && buf.length % 2 === 0) {
    var b2 = Buffer.from(buf); b2.swap16(); s = b2.toString("utf16le");
  } else if (node.tag === 0x1c && buf.length % 4 === 0) {
    s = "";
    for (var i = 0; i < buf.length; i += 4) s += String.fromCodePoint(buf.readUInt32BE(i));
  }
  if (s === null) return "b:" + buf.toString("hex");
  try { s = s.normalize("NFKC").toLowerCase().replace(/ +/g, " ").trim(); }
  catch (_e) { /* lone surrogate: keep as-is */ }
  return "s:" + s;
}

function _canonicalName(nameNode) {
  return asn1.readSequence(nameNode.value).map(function (rdn) {
    var entries = asn1.readSequence(rdn.value).map(function (atv) {
      var kids = asn1.readSequence(atv.value);
      var oid = asn1.readOid(kids[0]);
      return oid + "=" + _attrValueKey(kids[1], Object.prototype.hasOwnProperty.call(CASE_IGNORE_OIDS, oid));
    });
    entries.sort();
    return entries;
  });
}

function _isSelfIssued(cert) {
  if (!cert || !Buffer.isBuffer(cert.raw)) return false;
  try {
    var f = asn1.readCertificateTbsFields(cert.raw);
    return !!f.subject && !!f.issuer &&
      JSON.stringify(_canonicalName(f.subject)) === JSON.stringify(_canonicalName(f.issuer));
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
  if (!Array.isArray(chain)) return false;
  for (var k = 0; k < chain.length; k += 1) {
    if (!_certLike(chain[k])) return false;
  }
  if (chain.length < 2) return true;
  var maxPathLen = Infinity;
  for (var i = chain.length - 1; i >= 0; i -= 1) {
    var cert = chain[i];
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

function _certInPath(path, fp) {
  for (var i = 0; i < path.length; i += 1) {
    if (path[i].fingerprint256 === fp) return true;
  }
  return false;
}

function _hasPoolParent(current, path, pool, issued) {
  for (var p = 0; p < pool.length; p += 1) {
    var cand = pool[p];
    if (!_certLike(cand)) continue;
    if (_certInPath(path, cand.fingerprint256)) continue;
    if (issued(cand, current)) return true;
  }
  return false;
}

function _searchChain(current, path, anchors, pool, issued, validAt, maxDepth, state) {
  state.visits += 1;
  if (state.visits > state.maxVisits) return false;
  if (!validAt(current)) {
    if (!state.invalidCert) state.invalidCert = current;
    return false;
  }
  for (var a = 0; a < anchors.length; a += 1) {
    if (!_certLike(anchors[a])) continue;
    var isIssuer = issued(anchors[a], current);
    var isSelf = current.fingerprint256 === anchors[a].fingerprint256;
    if (!isIssuer && !isSelf) continue;
    if (!pathLenSatisfied(isIssuer ? path.concat([anchors[a]]) : path)) {
      state.pathLen = true;
      continue;
    }
    if (isIssuer && !validAt(anchors[a])) {
      if (!state.invalidCert) state.invalidCert = anchors[a];
      continue;
    }
    return true;
  }
  if (path.length >= maxDepth) {
    if (_hasPoolParent(current, path, pool, issued)) state.depthLimited = true;
    return false;
  }
  for (var p = 0; p < pool.length; p += 1) {
    var cand = pool[p];
    if (!_certLike(cand)) continue;
    if (_certInPath(path, cand.fingerprint256)) continue;
    if (!issued(cand, current)) continue;
    if (_searchChain(cand, path.concat([cand]), anchors, pool, issued, validAt, maxDepth, state)) return true;
  }
  return false;
}

/**
 * @primitive b.x509Chain.resolveChain
 * @signature b.x509Chain.resolveChain(leaf, pool, anchors, opts?)
 * @since     0.20.21
 * @status    stable
 * @related   b.x509Chain.issuerValidlyIssued, b.x509Chain.pathLenSatisfied
 *
 * Searches for a certification path from <code>leaf</code> through the candidate
 * certificates in <code>pool</code> to any certificate in <code>anchors</code>,
 * honoring basicConstraints pathLenConstraint. Every node on an accepted path
 * passes <code>opts.validAt</code>, every adjacent pair passes
 * <code>opts.issued</code>, and the assembled path satisfies
 * <code>pathLenSatisfied</code>. When one candidate issuer overruns a
 * path-length constraint the search tries the remaining candidates, so an
 * interchangeable issuer (same subject and key, different pathLenConstraint)
 * that completes a within-limit path is not preempted by a stricter one that
 * appears earlier in the pool. A certificate already on the path under
 * construction is never revisited, and the search stops after
 * <code>opts.maxVisits</code> node expansions to bound work on a crafted pool.
 *
 * The result carries <code>reason</code> "anchored" on success, "pathlen" when a
 * matching anchor was rejected only for path length, otherwise "untrusted".
 * <code>invalidCert</code> is the first certificate that failed
 * <code>validAt</code> (null when none did). <code>depthLimited</code> is true
 * when a branch was cut at <code>maxDepth</code> with an issuer still available.
 *
 * @opts
 *   issued:    function,  // (issuer, subject) → boolean; default issuerValidlyIssued
 *   validAt:   function,  // (cert) → boolean; default () => true
 *   maxDepth:  number,    // default: pool.length + 1; caps the path length
 *   maxVisits: number,    // default: 4096; caps node expansions
 *
 * @example
 *   var res = b.x509Chain.resolveChain(leaf, [subCa, issuer], [root]);
 *   // → { ok: true, reason: "anchored", invalidCert: null, depthLimited: false }
 */
function resolveChain(leaf, pool, anchors, opts) {
  opts = opts || {};
  var issued = typeof opts.issued === "function" ? opts.issued : issuerValidlyIssued;
  var validAt = typeof opts.validAt === "function" ? opts.validAt : function () { return true; };
  var candidates = Array.isArray(pool) ? pool : [];
  var trust = Array.isArray(anchors) ? anchors : [];
  var maxDepth = numericBounds.isPositiveFiniteInt(opts.maxDepth) ? opts.maxDepth : candidates.length + 1;
  var state = {
    pathLen: false,
    invalidCert: null,
    depthLimited: false,
    visits: 0,
    maxVisits: numericBounds.isPositiveFiniteInt(opts.maxVisits) ? opts.maxVisits : 4096,
  };
  var ok = _certLike(leaf) &&
    _searchChain(leaf, [leaf], trust, candidates, issued, validAt, maxDepth, state);
  return {
    ok: ok,
    reason: ok ? "anchored" : (state.pathLen ? "pathlen" : "untrusted"),
    invalidCert: state.invalidCert,
    depthLimited: state.depthLimited,
  };
}

module.exports = {
  isCaCert:            isCaCert,
  issuerValidlyIssued: issuerValidlyIssued,
  pathLenSatisfied:    pathLenSatisfied,
  resolveChain:        resolveChain,
};
