"use strict";
/**
 * @module b.mdoc
 * @nav    Crypto
 * @title  ISO mdoc / mDL (ISO 18013-5)
 *
 * @intro
 *   Verify the issuer-signed data of an ISO/IEC 18013-5 mdoc — the
 *   credential format behind mobile driving licences (mDL) and the ISO
 *   track of the EU Digital Identity Wallet. This is the relying-party
 *   side: confirm that the data elements a holder presents were signed
 *   by the issuer and have not been altered.
 *
 *   An mdoc's <code>IssuerSigned</code> structure carries the disclosed
 *   data elements (<code>nameSpaces</code>) and an <code>issuerAuth</code>
 *   that is a COSE_Sign1 (<code>b.cose</code>) over a Mobile Security
 *   Object (MSO). The MSO holds, per namespace, a SHA-256/384/512 digest
 *   of every issued element. <code>b.mdoc.verifyIssuerSigned</code>
 *   verifies the COSE signature with the issuer certificate carried in
 *   the COSE <code>x5chain</code> (label 33), parses the MSO, enforces
 *   its <code>validityInfo</code> window, and — the integrity check that
 *   makes selective disclosure trustworthy — recomputes the digest of
 *   every disclosed element (the full Tag-24 <code>IssuerSignedItemBytes</code>)
 *   and matches it against the MSO, constant-time. A disclosed element
 *   whose digest is absent or mismatched is refused.
 *
 *   Signing algorithms follow <code>b.cose</code> verification: the
 *   classical ES256 / 384 / 512 and EdDSA that real mDL issuers use are
 *   accepted (consume-what-exists; the caller names the allowlist).
 *   <code>opts.trustAnchorsPem</code> additionally verifies the issuer
 *   certificate chain and its validity at the asserted time.
 *
 *   <strong>Scope.</strong> This is issuer-data authentication
 *   (ISO 18013-5 §9.1.2.4) — the data is genuine and issuer-signed. The
 *   mdoc <em>device authentication</em> half (DeviceSigned / the
 *   SessionTranscript-bound holder-binding proof, §9.1.3) is deferred:
 *   it needs the live session transcript a verifier negotiates, so it is
 *   a presentation-protocol concern rather than a credential check.
 *   Composes <code>b.cose</code> + <code>b.cbor</code>; no new runtime
 *   dependency. Distinct from W3C VCDM (<code>b.vc</code>) and IETF
 *   SD-JWT VC (<code>b.auth.sdJwtVc</code>) — the three credential
 *   ecosystems.
 *
 * @card
 *   ISO 18013-5 mdoc / mDL issuer-data verification — checks the
 *   COSE_Sign1 IssuerAuth, the MSO validity window, and every disclosed
 *   element's digest against the Mobile Security Object. Composes
 *   b.cose + b.cbor; device-auth holder-binding deferred.
 */

var nodeCrypto = require("node:crypto");
var C = require("./constants");
var cbor = require("./cbor");
var cose = require("./cose");
var bCrypto = require("./crypto");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var MdocError = defineClass("MdocError", { alwaysPermanent: true });

var HDR_X5CHAIN = 33;                                  // allow:raw-byte-literal allow:raw-time-literal — x5chain COSE header label (RFC 9360 is a spec number, not a size/duration)
var TAG_ENCODED_CBOR = 24;                             // allow:raw-byte-literal — RFC 8949 §3.4.5.1 embedded-CBOR tag
// Tags ISO 18013-5 uses in issuer data: tdate(0), epoch(1), embedded
// CBOR(24), full-date(1004, RFC 8943). Bounded — others are refused.
var ALLOWED_TAGS = [0, 1, TAG_ENCODED_CBOR, 1004];
var DIGEST_ALGS = { "SHA-256": "sha256", "SHA-384": "sha384", "SHA-512": "sha512" };

function _bytes(x, what) {
  if (Buffer.isBuffer(x)) return x;
  if (x instanceof Uint8Array) return Buffer.from(x);
  throw new MdocError("mdoc/bad-input", "mdoc: " + what + " must be a Buffer / Uint8Array of CBOR");
}

// validityInfo dates are tdate (Tag 0, an RFC 3339 string) or epoch
// (Tag 1). Returns epoch-ms; fails closed on a malformed value.
function _validityMs(v, name) {
  var raw = (v instanceof cbor.Tag) ? v.value : v;
  if (typeof raw === "string") {
    var ms = Date.parse(raw);
    if (!isFinite(ms)) throw new MdocError("mdoc/bad-validity", "mdoc: validityInfo." + name + " is not a valid date: " + raw);
    return ms;
  }
  if (typeof raw === "number" && isFinite(raw)) return raw * C.TIME.seconds(1);    // epoch seconds → ms
  throw new MdocError("mdoc/bad-validity", "mdoc: validityInfo." + name + " is missing or malformed");
}

function _mapGet(m, k) { return m instanceof Map ? m.get(k) : (m ? m[k] : undefined); }

/**
 * @primitive b.mdoc.verifyIssuerSigned
 * @signature b.mdoc.verifyIssuerSigned(issuerSigned, opts)
 * @since     0.12.40
 * @status    experimental
 * @compliance gdpr, soc2
 * @related   b.cose.verify, b.vc.verify
 *
 * Verify the issuer-signed data of an ISO 18013-5 mdoc and return the
 * disclosed elements. <code>issuerSigned</code> is the CBOR
 * <code>IssuerSigned</code> map (the operator extracts it from the
 * device response / QR). The COSE_Sign1 <code>issuerAuth</code> is
 * verified with the issuer certificate from its <code>x5chain</code>
 * header against the mandatory <code>opts.algorithms</code> allowlist;
 * the MSO <code>validityInfo</code> window is enforced; and every
 * disclosed element's digest is matched against the Mobile Security
 * Object (a mismatch or absence is refused). Pass
 * <code>opts.trustAnchorsPem</code> to also verify the issuer
 * certificate chain.
 *
 * @opts
 *   {
 *     algorithms:      string[],  // required — accepted COSE alg names (ES256/384/512, EdDSA)
 *     trustAnchorsPem: string|string[], // optional issuer roots — enables chain + validity verification
 *     expectedDocType: string,    // require the MSO docType to match (e.g. "org.iso.18013.5.1.mDL")
 *     at:              Date,      // validity instant (default now); must be a valid Date
 *     maxBytes:        number,    // forwarded to b.cbor.decode
 *     maxDepth:        number,
 *   }
 *
 * @example
 *   var out = await b.mdoc.verifyIssuerSigned(issuerSignedBytes, {
 *     algorithms: ["ES256"], expectedDocType: "org.iso.18013.5.1.mDL",
 *   });
 *   // → { docType, validityInfo, namespaces: { "org.iso.18013.5.1": { family_name, age_over_18, … } }, signerCert, alg }
 */
async function verifyIssuerSigned(issuerSigned, opts) {
  validateOpts.requireObject(opts, "mdoc.verifyIssuerSigned", MdocError);
  validateOpts(opts, ["algorithms", "trustAnchorsPem", "expectedDocType", "at", "maxBytes", "maxDepth"], "mdoc.verifyIssuerSigned");
  if (!Array.isArray(opts.algorithms) || opts.algorithms.length === 0) {
    throw new MdocError("mdoc/algorithms-required", "mdoc.verifyIssuerSigned: opts.algorithms is required");
  }
  var at = new Date();
  if (opts.at !== undefined && opts.at !== null) {
    if (!(opts.at instanceof Date) || !isFinite(opts.at.getTime())) {
      throw new MdocError("mdoc/bad-at", "mdoc.verifyIssuerSigned: opts.at must be a valid Date");
    }
    at = opts.at;
  }
  var decodeOpts = { allowedTags: ALLOWED_TAGS, maxBytes: opts.maxBytes, maxDepth: opts.maxDepth };

  var top = cbor.decode(_bytes(issuerSigned, "issuerSigned"), decodeOpts);
  var nameSpaces = _mapGet(top, "nameSpaces");
  var issuerAuth = _mapGet(top, "issuerAuth");
  if (!Array.isArray(issuerAuth) || issuerAuth.length !== 4) {
    throw new MdocError("mdoc/malformed", "mdoc.verifyIssuerSigned: issuerAuth must be a COSE_Sign1 (4-element array)");
  }

  // The signer certificate rides in the COSE x5chain (label 33): a
  // single cert bstr or an array of bstrs, leaf first.
  var unprotected = issuerAuth[1];
  var x5 = _mapGet(unprotected, HDR_X5CHAIN);
  var chain = Array.isArray(x5) ? x5 : (x5 != null ? [x5] : []);
  if (!chain.length || !Buffer.isBuffer(chain[0])) {
    throw new MdocError("mdoc/no-cert", "mdoc.verifyIssuerSigned: issuerAuth has no x5chain certificate (label 33)");
  }
  // The x5chain certificate is attacker-controlled — a malformed DER
  // must surface as a clean error, not a raw OpenSSL throw.
  var signerCert;
  try { signerCert = new nodeCrypto.X509Certificate(chain[0]); }
  catch (e) {
    throw new MdocError("mdoc/bad-cert", "mdoc.verifyIssuerSigned: x5chain certificate is not valid DER: " + ((e && e.message) || e));
  }

  // Verify the COSE_Sign1 signature with the embedded signer key.
  var coseBytes = cbor.encode(issuerAuth);
  var verified = await cose.verify(coseBytes, {
    algorithms:  opts.algorithms,
    keyResolver: function () { return signerCert.publicKey; },
    maxBytes:    opts.maxBytes,
    maxDepth:    opts.maxDepth,
  });

  // payload = Tag 24 ( bstr .cbor MSO ).
  var payloadTag = cbor.decode(verified.payload, decodeOpts);
  var msoBytes = (payloadTag instanceof cbor.Tag && payloadTag.tag === TAG_ENCODED_CBOR) ? payloadTag.value : null;
  if (!Buffer.isBuffer(msoBytes)) {
    throw new MdocError("mdoc/malformed", "mdoc.verifyIssuerSigned: issuerAuth payload is not a Tag-24 MobileSecurityObject");
  }
  var mso = cbor.decode(msoBytes, decodeOpts);

  var digestAlgName = _mapGet(mso, "digestAlgorithm");
  var digestNode = DIGEST_ALGS[digestAlgName];
  if (!digestNode) {
    throw new MdocError("mdoc/bad-digest-alg", "mdoc.verifyIssuerSigned: unsupported MSO digestAlgorithm '" + digestAlgName + "'");
  }
  var docType = _mapGet(mso, "docType");
  if (opts.expectedDocType !== undefined && docType !== opts.expectedDocType) {
    throw new MdocError("mdoc/doctype-mismatch", "mdoc.verifyIssuerSigned: MSO docType '" + docType + "' does not match expectedDocType");
  }

  // validityInfo window (fail closed on malformed dates).
  var vi = _mapGet(mso, "validityInfo");
  if (!(vi instanceof Map) && (!vi || typeof vi !== "object")) {
    throw new MdocError("mdoc/malformed", "mdoc.verifyIssuerSigned: MSO has no validityInfo");
  }
  var nowMs = at.getTime();
  var validFromMs = _validityMs(_mapGet(vi, "validFrom"), "validFrom");
  var validUntilMs = _validityMs(_mapGet(vi, "validUntil"), "validUntil");
  if (nowMs < validFromMs) throw new MdocError("mdoc/not-yet-valid", "mdoc.verifyIssuerSigned: credential not yet valid");
  if (nowMs > validUntilMs) throw new MdocError("mdoc/expired", "mdoc.verifyIssuerSigned: credential validity has passed");

  // Match every disclosed element's digest against the MSO. The digest
  // covers the full Tag-24 IssuerSignedItemBytes (ISO 18013-5 §9.1.2.5).
  var valueDigests = _mapGet(mso, "valueDigests");
  var out = {};
  if (nameSpaces instanceof Map) {
    var nsNames = Array.from(nameSpaces.keys());
    for (var ni = 0; ni < nsNames.length; ni += 1) {
      var ns = nsNames[ni];
      var items = nameSpaces.get(ns);
      var nsDigests = _mapGet(valueDigests, ns);
      if (!Array.isArray(items) || !(nsDigests instanceof Map)) {
        throw new MdocError("mdoc/malformed", "mdoc.verifyIssuerSigned: namespace '" + ns + "' has no matching valueDigests");
      }
      out[ns] = {};
      var seen = Object.create(null);                 // dup-elementIdentifier guard (proto-safe)
      for (var ii = 0; ii < items.length; ii += 1) {
        var item = items[ii];
        if (!(item instanceof cbor.Tag) || item.tag !== TAG_ENCODED_CBOR || !Buffer.isBuffer(item.value)) {
          throw new MdocError("mdoc/malformed", "mdoc.verifyIssuerSigned: IssuerSignedItem is not a Tag-24 byte string");
        }
        var itemBytes = cbor.encode(new cbor.Tag(TAG_ENCODED_CBOR, item.value));
        var digest = nodeCrypto.createHash(digestNode).update(itemBytes).digest();
        var inner = cbor.decode(item.value, decodeOpts);
        var digestID = _mapGet(inner, "digestID");
        var expected = nsDigests.get(digestID);
        if (!Buffer.isBuffer(expected) || !bCrypto.timingSafeEqual(digest, expected)) {
          throw new MdocError("mdoc/digest-mismatch",
            "mdoc.verifyIssuerSigned: disclosed element (digestID " + digestID + ", namespace " + ns + ") does not match the MSO");
        }
        // Refuse a duplicate elementIdentifier within a namespace — two
        // signed values for one element is ambiguous; fail closed rather
        // than silently keep the last.
        var elementId = _mapGet(inner, "elementIdentifier");
        if (seen[elementId]) {
          throw new MdocError("mdoc/duplicate-element",
            "mdoc.verifyIssuerSigned: namespace '" + ns + "' has duplicate elementIdentifier '" + elementId + "'");
        }
        seen[elementId] = true;
        out[ns][elementId] = _mapGet(inner, "elementValue");
      }
    }
  }

  // Optional issuer chain + validity at the asserted time.
  if (opts.trustAnchorsPem !== undefined && opts.trustAnchorsPem !== null) {
    var anchors = typeof opts.trustAnchorsPem === "string" ? [opts.trustAnchorsPem] : opts.trustAnchorsPem;
    if (!Array.isArray(anchors) || anchors.length === 0 ||
        !anchors.every(function (a) { return typeof a === "string" && a.length > 0; })) {
      throw new MdocError("mdoc/bad-trust-anchors", "mdoc.verifyIssuerSigned: trustAnchorsPem must be a non-empty PEM string or array");
    }
    _verifyChain(chain, anchors, at);
  }

  return {
    docType:      docType,
    version:      _mapGet(mso, "version"),
    digestAlgorithm: digestAlgName,
    validityInfo: { validFrom: new Date(validFromMs), validUntil: new Date(validUntilMs) },
    namespaces:   out,
    signerCert:   signerCert.toString(),
    alg:          verified.alg,
  };
}

// Verify the leaf (chain[0]) chains to a supplied anchor and every cert
// is valid at `at`. Intermediates in the x5chain are consulted.
function _verifyChain(chainDer, anchorsPem, at) {
  var anchors = anchorsPem.map(function (p) { return new nodeCrypto.X509Certificate(p); });
  var pool = chainDer.map(function (d) { return new nodeCrypto.X509Certificate(d); });
  var current = pool[0];
  var atMs = at.getTime();
  var steps = 0;
  while (steps <= pool.length + 1) {
    _assertValidAt(current, atMs);
    for (var a = 0; a < anchors.length; a += 1) {
      if (_issued(anchors[a], current)) { _assertValidAt(anchors[a], atMs); return; }
      if (current.fingerprint256 === anchors[a].fingerprint256) return;
    }
    var parent = null;
    for (var p = 0; p < pool.length; p += 1) {
      if (pool[p].fingerprint256 !== current.fingerprint256 && _issued(pool[p], current)) { parent = pool[p]; break; }
    }
    if (!parent) {
      throw new MdocError("mdoc/untrusted-chain", "mdoc.verifyIssuerSigned: issuer certificate does not chain to a supplied trust anchor");
    }
    current = parent;
    steps += 1;
  }
  throw new MdocError("mdoc/chain-loop", "mdoc.verifyIssuerSigned: certificate chain did not terminate");
}
function _issued(issuer, subject) {
  try { return subject.checkIssued(issuer) && subject.verify(issuer.publicKey); }
  catch (_e) { return false; }
}
function _assertValidAt(cert, atMs) {
  if (atMs < cert.validFromDate.getTime() || atMs > cert.validToDate.getTime()) {
    throw new MdocError("mdoc/cert-expired", "mdoc.verifyIssuerSigned: certificate '" + cert.subject + "' is not valid at the asserted time");
  }
}

module.exports = {
  verifyIssuerSigned: verifyIssuerSigned,
  DIGEST_ALGS:        DIGEST_ALGS,
  MdocError:          MdocError,
};
