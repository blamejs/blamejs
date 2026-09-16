// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var nodeCrypto = require("node:crypto");
var asn1 = require("./asn1-der");
var numericBounds = require("./numeric-bounds");
var codepointClass = require("./codepoint-class");

var OID_BASIC_CONSTRAINTS = "2.5.29.19";
var OID_SUBJECT_ALT_NAME = "2.5.29.17";
var OID_NAME_CONSTRAINTS = "2.5.29.30";

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
  if (!extsWrapper) return { value: null, duplicate: false };
  var exts = asn1.readSequence(asn1.readNode(extsWrapper.value, 0).value);
  var value = null;
  var count = 0;
  for (var j = 0; j < exts.length; j += 1) {
    if (exts[j].tag !== asn1.TAG.SEQUENCE) continue;
    var extKids = asn1.readSequence(exts[j].value);
    if (extKids.length < 2) continue;
    var extOid;
    try { extOid = asn1.readOid(extKids[0]); } catch (_e) { continue; }
    if (extOid !== oid) continue;
    count += 1;
    if (value === null) value = asn1.readOctetString(extKids[extKids.length - 1]);
  }
  return { value: value, duplicate: count > 1 };
}

function basicConstraintsPathLen(cert) {
  if (!cert || !Buffer.isBuffer(cert.raw)) return null;
  var ext;
  try { ext = _certExtensionValue(cert.raw, OID_BASIC_CONSTRAINTS); }
  catch (_e) { return null; }
  if (ext.duplicate) return -1;
  var extnValue = ext.value;
  if (!extnValue) return null;
  try {
    var bc = asn1.readNode(extnValue, 0);
    if (bc.tag !== asn1.TAG.SEQUENCE) return null;
    var kids = asn1.readSequence(bc.value);
    for (var k = 0; k < kids.length; k += 1) {
      if (kids[k].tag === asn1.TAG.INTEGER && kids[k].tagClass === asn1.TAG_CLASS.UNIVERSAL) {
        var intBuf = kids[k].value;
        if (!intBuf || intBuf.length === 0 || (intBuf[0] & 0x80)) return -1;
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
      if (pl !== null) {
        if (pl < 0) return false;
        if (pl < maxPathLen) maxPathLen = pl;
      }
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
    var full = isIssuer ? path.concat([anchors[a]]) : path;
    if (!pathLenSatisfied(full)) {
      state.pathLen = true;
      continue;
    }
    if (!nameConstraintsSatisfied(full)) {
      state.nameBlocked = true;
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
 * matching anchor was rejected only for path length, "nameconstraint" when it was
 * rejected only for a CA nameConstraints violation, otherwise "untrusted".
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
    nameBlocked: false,
    invalidCert: null,
    depthLimited: false,
    visits: 0,
    maxVisits: numericBounds.isPositiveFiniteInt(opts.maxVisits) ? opts.maxVisits : 4096,
  };
  var ok = _certLike(leaf) &&
    _searchChain(leaf, [leaf], trust, candidates, issued, validAt, maxDepth, state);
  var reason = "untrusted";
  if (ok) reason = "anchored";
  else if (state.pathLen) reason = "pathlen";
  else if (state.nameBlocked) reason = "nameconstraint";
  return {
    ok: ok,
    reason: reason,
    invalidCert: state.invalidCert,
    depthLimited: state.depthLimited,
  };
}

function _isSequence(node) {
  return node.tag === asn1.TAG.SEQUENCE && node.tagClass === asn1.TAG_CLASS.UNIVERSAL && node.constructed;
}

function _isAscii(buf) {
  for (var i = 0; i < buf.length; i += 1) {
    if (buf[i] > 0x7f) return false;
  }
  return true;
}

function _validDnsLabel(label) {
  if (label.length === 0 || label.length > 63) return false;
  for (var i = 0; i < label.length; i += 1) {
    var c = label.charCodeAt(i);
    if (!codepointClass.isAsciiAlnum(c) && c !== 0x2d && c !== 0x5f && c !== 0x2a) return false;
  }
  return label.charAt(0) !== "-" && label.charAt(label.length - 1) !== "-";
}

function _validSanDnsName(s) {
  if (s.length === 0 || s.length > 253) return false;
  var labels = s.split(".");
  for (var i = 0; i < labels.length; i += 1) {
    if (!_validDnsLabel(labels[i])) return false;
  }
  return true;
}

function _validConstraintDnsBase(s) {
  if (s.charAt(0) === ".") return _validSanDnsName(s.slice(1));
  return _validSanDnsName(s);
}

function _validSkippedGeneralName(node) {
  try {
    if (node.tag === 1 || node.tag === 6) return node.value.length > 0 && _isAscii(node.value);
    if (node.tag === 8) return node.value.length > 0;
    if (node.tag === 4) return _isSequence(asn1.readNodeStrict(node.value));
    var kids = asn1.readSequence(node.value);
    if (node.tag === 0) {
      return kids.length === 2 &&
        kids[0].tag === asn1.TAG.OID && kids[0].tagClass === asn1.TAG_CLASS.UNIVERSAL &&
        kids[1].tagClass === asn1.TAG_CLASS.CONTEXT_SPECIFIC && kids[1].tag === 0;
    }
    return kids.length >= 1;
  } catch (_e) {
    return false;
  }
}

function _constraintName(node) {
  if (node.tagClass !== asn1.TAG_CLASS.CONTEXT_SPECIFIC) return { type: "malformed" };
  if (node.tag === 2) {
    if (node.constructed || node.value.length === 0 || !_isAscii(node.value)) return { type: "malformed" };
    return { type: "dns", value: node.value.toString("latin1") };
  }
  if (node.tag === 7) return node.constructed ? { type: "malformed" } : { type: "ip", value: Buffer.from(node.value) };
  if (node.tag === 0 || node.tag === 3 || node.tag === 4 || node.tag === 5) {
    if (!node.constructed) return { type: "malformed" };
    return _validSkippedGeneralName(node) ? { type: "other" } : { type: "malformed" };
  }
  if (node.tag === 1 || node.tag === 6 || node.tag === 8) {
    if (node.constructed) return { type: "malformed" };
    return _validSkippedGeneralName(node) ? { type: "other" } : { type: "malformed" };
  }
  return { type: "malformed" };
}

function _subjectAltConstraintNames(cert) {
  var out = [];
  var ext;
  try { ext = _certExtensionValue(cert.raw, OID_SUBJECT_ALT_NAME); } catch (_e) { return { names: out, malformed: true }; }
  if (ext.duplicate) return { names: out, malformed: true };
  var extnValue = ext.value;
  if (!extnValue) return { names: out, malformed: false };
  try {
    var seq = asn1.readNodeStrict(extnValue);
    if (!_isSequence(seq)) return { names: out, malformed: true };
    var names = asn1.readSequence(seq.value);
    if (!names.length) return { names: out, malformed: true };
    for (var i = 0; i < names.length; i += 1) {
      var gn = _constraintName(names[i]);
      if (gn.type === "malformed") return { names: out, malformed: true };
      if (gn.type === "other") continue;
      if (gn.type === "ip" && gn.value.length !== 4 && gn.value.length !== 16) return { names: out, malformed: true };
      if (gn.type === "dns" && !_validSanDnsName(gn.value)) return { names: out, malformed: true };
      out.push(gn);
    }
  } catch (_e) { return { names: out, malformed: true }; }
  return { names: out, malformed: false };
}

function _nameConstraintsOf(cert) {
  var ext;
  try { ext = _certExtensionValue(cert.raw, OID_NAME_CONSTRAINTS); } catch (_e) { return { error: true }; }
  if (ext.duplicate) return { error: true };
  var extnValue = ext.value;
  if (!extnValue) return null;
  try {
    var seq = asn1.readNodeStrict(extnValue);
    if (!_isSequence(seq)) return { error: true };
    var fields = asn1.readSequence(seq.value);
    if (!fields.length) return { error: true };
    var res = { permitted: null, excluded: null, unsupported: false };
    var prevTag = -1;
    for (var i = 0; i < fields.length; i += 1) {
      var f = fields[i];
      if (f.tagClass !== asn1.TAG_CLASS.CONTEXT_SPECIFIC || !f.constructed || (f.tag !== 0 && f.tag !== 1)) return { error: true };
      if (f.tag <= prevTag) return { error: true };
      prevTag = f.tag;
      var subtrees = asn1.readSequence(f.value);
      if (!subtrees.length) return { error: true };
      var bucket = { dns: [], ip: [] };
      for (var s = 0; s < subtrees.length; s += 1) {
        if (!_isSequence(subtrees[s])) return { error: true };
        var gsKids = asn1.readSequence(subtrees[s].value);
        if (!gsKids.length) return { error: true };
        if (gsKids.length > 1) { res.unsupported = true; continue; }
        var gn = _constraintName(gsKids[0]);
        if (gn.type !== "dns" && gn.type !== "ip") { res.unsupported = true; continue; }
        if (gn.type === "ip" && gn.value.length !== 8 && gn.value.length !== 32) { res.unsupported = true; continue; }
        if (gn.type === "ip" && !_validIpConstraintMask(gn.value)) { res.unsupported = true; continue; }
        if (gn.type === "dns" && !_validConstraintDnsBase(gn.value)) { res.unsupported = true; continue; }
        bucket[gn.type].push(gn.value);
      }
      if (f.tag === 0) res.permitted = bucket; else res.excluded = bucket;
    }
    return res;
  } catch (_e) { return { error: true }; }
}

function _withinDnsSubtree(name, base) {
  var n = String(name).toLowerCase();
  var b = String(base).toLowerCase();
  if (b === "") return false;
  if (b.charAt(0) === ".") {
    return n.length > b.length && n.slice(n.length - b.length) === b;
  }
  if (n === b) return true;
  return n.length > b.length && n.slice(n.length - b.length - 1) === "." + b;
}

function _validIpConstraintMask(baseBuf) {
  var addrLen = baseBuf.length / 2;
  var seenZero = false;
  for (var i = addrLen; i < baseBuf.length; i += 1) {
    for (var bit = 7; bit >= 0; bit -= 1) {
      if ((baseBuf[i] >> bit) & 1) {
        if (seenZero) return false;
      } else {
        seenZero = true;
      }
    }
  }
  return true;
}

function _withinIpSubtree(nameBuf, baseBuf) {
  if (!Buffer.isBuffer(nameBuf) || !Buffer.isBuffer(baseBuf)) return false;
  if (baseBuf.length !== nameBuf.length * 2) return false;
  for (var i = 0; i < nameBuf.length; i += 1) {
    var mask = baseBuf[nameBuf.length + i];
    if ((nameBuf[i] & mask) !== (baseBuf[i] & mask)) return false;
  }
  return true;
}

function _nameWithin(name, base) {
  if (name.type === "dns") return _withinDnsSubtree(name.value, base);
  if (name.type === "ip") return _withinIpSubtree(name.value, base);
  return false;
}

function _certNamesSatisfy(cert, permittedReqs, excluded) {
  var hasConstraint = permittedReqs.dns.length || permittedReqs.ip.length ||
    excluded.dns.length || excluded.ip.length;
  var san = _subjectAltConstraintNames(cert);
  if (san.malformed) return !hasConstraint;
  var names = san.names;
  for (var n = 0; n < names.length; n += 1) {
    var name = names[n];
    var ex = excluded[name.type];
    for (var e = 0; e < ex.length; e += 1) if (_nameWithin(name, ex[e])) return false;
    var reqs = permittedReqs[name.type];
    for (var r = 0; r < reqs.length; r += 1) {
      var within = false;
      for (var g = 0; g < reqs[r].length; g += 1) if (_nameWithin(name, reqs[r][g])) { within = true; break; }
      if (!within) return false;
    }
  }
  return true;
}

/**
 * @primitive b.x509Chain.nameConstraintsSatisfied
 * @signature b.x509Chain.nameConstraintsSatisfied(chain)
 * @since     0.20.22
 * @status    stable
 * @related   b.x509Chain.pathLenSatisfied, b.x509Chain.resolveChain
 *
 * Enforces X.509 nameConstraints (RFC 5280 §4.2.1.10 / §6.1.4) over an ordered
 * chain <code>[leaf, …intermediates, anchor]</code>. Each CA's permittedSubtrees
 * and excludedSubtrees accumulate down the chain (permitted intersect, excluded
 * union) and are applied to the subjectAltName of every certificate below it
 * (self-issued intermediates are exempt; the leaf is always checked). A
 * dNSName is matched by the add-labels rule (base <code>example.com</code> is
 * satisfied by <code>example.com</code> and <code>host.example.com</code>, not
 * <code>notexample.com</code>); an iPAddress by the address/mask CIDR.
 *
 * dNSName and iPAddress constraints are evaluated. A nameConstraints extension
 * carrying any other subtree form (directoryName, rfc822Name, URI, otherName) or
 * a non-default minimum/maximum, or one that does not parse, fails CLOSED (the
 * chain is rejected) rather than being ignored. Returns a boolean; a non-array,
 * or any entry that is not an X509Certificate, is false.
 *
 * @example
 *   b.x509Chain.nameConstraintsSatisfied([leaf, intermediate, root]);
 *   // → false when the leaf SAN is outside the intermediate's permitted subtree
 */
function nameConstraintsSatisfied(chain) {
  if (!Array.isArray(chain)) return false;
  for (var k = 0; k < chain.length; k += 1) {
    if (!_certLike(chain[k])) return false;
  }
  var permittedReqs = { dns: [], ip: [] };
  var excluded = { dns: [], ip: [] };
  for (var i = chain.length - 1; i >= 0; i -= 1) {
    var cert = chain[i];
    if (i !== chain.length - 1 && (i === 0 || !_isSelfIssued(cert))) {
      if (!_certNamesSatisfy(cert, permittedReqs, excluded)) return false;
    }
    var nc = _nameConstraintsOf(cert);
    if (nc && nc.error) return false;
    if (nc) {
      if (nc.unsupported) return false;
      if (nc.permitted) {
        if (nc.permitted.dns.length) permittedReqs.dns.push(nc.permitted.dns);
        if (nc.permitted.ip.length) permittedReqs.ip.push(nc.permitted.ip);
      }
      if (nc.excluded) {
        excluded.dns = excluded.dns.concat(nc.excluded.dns);
        excluded.ip = excluded.ip.concat(nc.excluded.ip);
      }
    }
  }
  return true;
}

module.exports = {
  isCaCert:                isCaCert,
  issuerValidlyIssued:     issuerValidlyIssued,
  pathLenSatisfied:        pathLenSatisfied,
  resolveChain:            resolveChain,
  nameConstraintsSatisfied: nameConstraintsSatisfied,
};
