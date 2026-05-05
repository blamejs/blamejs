"use strict";

var tls = require("node:tls");
var fs = require("node:fs");
var path = require("node:path");
var nodeCrypto = require("node:crypto");

var C = require("./constants");
var safeBuffer = require("./safe-buffer");
var validateOpts = require("./validate-opts");
var lazyRequire = require("./lazy-require");
var { defineClass } = require("./framework-error");

var TlsTrustError = defineClass("TlsTrustError", { alwaysPermanent: true });

var observability = lazyRequire(function () { return require("./observability"); });
var audit = lazyRequire(function () { return require("./audit"); });
var asn1 = require("./asn1-der");

var STATE = {
  cas:             [],
  systemTrust:     false,
  baselineFingerprints: null,
};

function _normalizePem(pem) {
  if (Buffer.isBuffer(pem)) pem = pem.toString("utf8");
  if (typeof pem !== "string") {
    throw new TlsTrustError("tls/bad-ca", "CA must be a PEM string or path, got " + typeof pem);
  }
  return pem.replace(/\r\n/g, "\n").trim();
}

function _splitPemBundle(pem) {
  var blocks = [];
  var lines = pem.split("\n");
  var current = null;
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i];
    if (line.indexOf("-----BEGIN CERTIFICATE-----") === 0) {
      current = [line];
    } else if (current) {
      current.push(line);
      if (line.indexOf("-----END CERTIFICATE-----") === 0) {
        blocks.push(current.join("\n"));
        current = null;
      }
    }
  }
  return blocks;
}

function _certMetadata(pem) {
  try {
    var x = new nodeCrypto.X509Certificate(pem);
    return {
      subject:     x.subject,
      issuer:      x.issuer,
      validFrom:   x.validFrom,
      validTo:     x.validTo,
      fingerprint256: x.fingerprint256,
      serialNumber: x.serialNumber,
      isSelfSigned: x.subject === x.issuer,
    };
  } catch (e) {
    throw new TlsTrustError("tls/bad-ca-pem", "CA PEM not parseable: " + e.message);
  }
}

function _isPathLike(s) {
  if (s.indexOf("-----BEGIN") !== -1) return false;
  if (s.length > C.BYTES.kib(1)) return false;
  if (safeBuffer.hasCrlf(s)) return false;
  return true;
}

function _readPath(p) {
  var stat = fs.statSync(p);
  if (stat.isDirectory()) {
    var files = fs.readdirSync(p)
      .filter(function (f) { return /\.(pem|crt|cer)$/i.test(f); })
      .sort();
    return files.map(function (f) { return fs.readFileSync(path.join(p, f), "utf8"); }).join("\n");
  }
  return fs.readFileSync(p, "utf8");
}

function addCa(pemOrPath, opts) {
  opts = opts || {};
  validateOpts(opts, ["label", "audit"], "tls.addCa");
  var raw = pemOrPath;
  if (typeof pemOrPath === "string" && _isPathLike(pemOrPath)) {
    var stat;
    try { stat = fs.statSync(pemOrPath); } catch (_e) {
      throw new TlsTrustError("tls/empty-pem", "tls.addCa: input has no PEM marker and is not a readable path: " +
        pemOrPath);
    }
    raw = _readPath(pemOrPath);
    if (!stat) raw = "";
  }
  raw = _normalizePem(raw);
  var blocks = _splitPemBundle(raw);
  if (blocks.length === 0) {
    throw new TlsTrustError("tls/empty-pem", "no CERTIFICATE blocks found in PEM input");
  }
  var added = [];
  for (var i = 0; i < blocks.length; i++) {
    var meta = _certMetadata(blocks[i]);
    STATE.cas.push({ pem: blocks[i], meta: meta, label: opts.label || null, addedAt: Date.now() });
    added.push(meta);
  }
  _emitAuditAdd(added, opts);
  _emitObs("network.tls.ca.added", { count: added.length });
  return added;
}

function addCaBundle(p, opts) {
  return addCa(p, opts);
}

function useSystemTrust(enable) {
  STATE.systemTrust = enable !== false;
  _emitObs("network.tls.system_trust.set", { enabled: STATE.systemTrust });
}

function isSystemTrustEnabled() { return !!STATE.systemTrust; }

function getTrustStore() {
  return STATE.cas.map(function (entry) {
    return {
      label:        entry.label,
      addedAt:      entry.addedAt,
      subject:      entry.meta.subject,
      issuer:       entry.meta.issuer,
      validFrom:    entry.meta.validFrom,
      validTo:      entry.meta.validTo,
      fingerprint256: entry.meta.fingerprint256,
      serialNumber: entry.meta.serialNumber,
      isSelfSigned: entry.meta.isSelfSigned,
    };
  });
}

function _emitAuditRemove(metaList, reason) {
  var sink;
  try { sink = audit(); } catch (_e) { sink = null; }
  if (!sink || typeof sink.safeEmit !== "function") return;
  for (var i = 0; i < metaList.length; i++) {
    var m = metaList[i];
    try {
      sink.safeEmit({
        action:   "network.tls.ca.removed",
        outcome:  "success",
        metadata: {
          subject:        m.subject,
          issuer:         m.issuer,
          fingerprint256: m.fingerprint256,
          validFrom:      m.validFrom,
          validTo:        m.validTo,
          isSelfSigned:   m.isSelfSigned,
          label:          m.label,
          reason:         reason || "operator",
        },
      });
    } catch (_e) { /* audit best-effort — never break the caller */ }
  }
}

function removeCa(fingerprint256, opts) {
  if (typeof fingerprint256 !== "string" || fingerprint256.length === 0) {
    throw new TlsTrustError("tls/bad-fingerprint", "tls.removeCa: fingerprint256 must be a non-empty string");
  }
  var fp = fingerprint256.toUpperCase();
  var removed = [];
  STATE.cas = STATE.cas.filter(function (entry) {
    var entryFp = (entry.meta.fingerprint256 || "").toUpperCase();
    if (entryFp === fp) {
      removed.push(Object.assign({ label: entry.label }, entry.meta));
      return false;
    }
    return true;
  });
  if (removed.length === 0) return 0;
  if (!opts || opts.audit !== false) _emitAuditRemove(removed, "operator-remove");
  _emitObs("network.tls.ca.removed", { count: removed.length, reason: "operator" });
  return removed.length;
}

function removeCaByLabel(label, opts) {
  if (typeof label !== "string" || label.length === 0) {
    throw new TlsTrustError("tls/bad-label", "tls.removeCaByLabel: label must be a non-empty string");
  }
  var removed = [];
  STATE.cas = STATE.cas.filter(function (entry) {
    if (entry.label === label) {
      removed.push(Object.assign({ label: entry.label }, entry.meta));
      return false;
    }
    return true;
  });
  if (removed.length === 0) return 0;
  if (!opts || opts.audit !== false) _emitAuditRemove(removed, "operator-remove-by-label");
  _emitObs("network.tls.ca.removed", { count: removed.length, reason: "label" });
  return removed.length;
}

function clearAll(opts) {
  if (STATE.cas.length === 0) return 0;
  var removed = STATE.cas.map(function (e) { return Object.assign({ label: e.label }, e.meta); });
  STATE.cas = [];
  if (!opts || opts.audit !== false) _emitAuditRemove(removed, "operator-clear-all");
  _emitObs("network.tls.ca.cleared", { count: removed.length });
  return removed.length;
}

function purgeExpired(opts) {
  var nowMs = Date.now();
  var removed = [];
  STATE.cas = STATE.cas.filter(function (entry) {
    var validToMs = entry.meta.validTo ? Date.parse(entry.meta.validTo) : NaN;
    if (isFinite(validToMs) && validToMs < nowMs) {
      removed.push(Object.assign({ label: entry.label }, entry.meta));
      return false;
    }
    return true;
  });
  if (removed.length === 0) return 0;
  if (!opts || opts.audit !== false) _emitAuditRemove(removed, "expired");
  _emitObs("network.tls.ca.purged_expired", { count: removed.length });
  return removed.length;
}

function expiringSoon(windowMs) {
  if (typeof windowMs !== "number" || !isFinite(windowMs) || windowMs < 0) {
    throw new TlsTrustError("tls/bad-window", "tls.expiringSoon: windowMs must be a non-negative finite number");
  }
  var threshold = Date.now() + windowMs;
  return STATE.cas.filter(function (entry) {
    var validToMs = entry.meta.validTo ? Date.parse(entry.meta.validTo) : NaN;
    return isFinite(validToMs) && validToMs <= threshold;
  }).map(function (entry) {
    return Object.assign({ label: entry.label }, entry.meta);
  });
}

function captureBaselineFingerprints() {
  STATE.baselineFingerprints = STATE.cas.map(function (e) { return e.meta.fingerprint256; });
}

function detectBaselineDrift() {
  if (!STATE.baselineFingerprints) return null;
  var current = STATE.cas.map(function (e) { return e.meta.fingerprint256; });
  var added = current.filter(function (fp) { return STATE.baselineFingerprints.indexOf(fp) === -1; });
  var removed = STATE.baselineFingerprints.filter(function (fp) { return current.indexOf(fp) === -1; });
  return { added: added, removed: removed, drifted: added.length > 0 || removed.length > 0 };
}

function applyToContext(opts) {
  opts = opts || {};
  validateOpts(opts, ["base"], "tls.applyToContext");
  var base = Object.assign({}, opts.base || {});
  var caStrings = STATE.cas.map(function (e) { return e.pem; });
  if (STATE.systemTrust) {
    var rootCAs = tls.rootCertificates;
    if (Array.isArray(rootCAs)) {
      caStrings = caStrings.concat(rootCAs);
    }
  }
  if (caStrings.length > 0) base.ca = caStrings;
  return base;
}

function getCaPems() {
  return STATE.cas.map(function (e) { return e.pem; });
}

function _emitAuditAdd(metaList, opts) {
  if (opts.audit === false) return;
  var sink;
  try { sink = audit(); } catch (_e) { sink = null; }
  if (!sink || typeof sink.safeEmit !== "function") return;
  for (var i = 0; i < metaList.length; i++) {
    var m = metaList[i];
    try {
      sink.safeEmit({
        action:   "network.tls.ca.added",
        outcome:  "success",
        metadata: {
          subject:        m.subject,
          issuer:         m.issuer,
          fingerprint256: m.fingerprint256,
          validFrom:      m.validFrom,
          validTo:        m.validTo,
          isSelfSigned:   m.isSelfSigned,
          label:          opts.label || null,
        },
      });
    } catch (_e) { /* audit best-effort — never break the caller */ }
  }
}

function _emitObs(name, fields) {
  try { observability().emit(name, fields || {}); } catch (_e) { /* obs best-effort */ }
}

function _resetForTest() {
  STATE.cas = [];
  STATE.systemTrust = false;
  STATE.baselineFingerprints = null;
}

// ---- OCSP / OCSP-stapling wrappers around node:tls ----------------
//
// node:tls exposes two OCSP affordances:
//   - tls.connect({ requestOCSP: true })       → emits 'OCSPResponse' event
//   - https.createServer({ ... requestOCSP }) → server-side stapling
//
// b.network.tls.ocsp wraps these. The names reflect what the wrapper
// actually does at this stage:
//
//   - ocsp.connect(opts)        — connect with requestOCSP:true; resolve
//                                 with { authorized, ocspBytes, peerCert }.
//   - ocsp.requireStapled(opts) — refuse if peer doesn't staple an
//                                 OCSP response (presence + non-empty
//                                 byte check). DOES NOT verify the OCSP
//                                 response signature against the issuer
//                                 cert — that requires DER OCSPResponse
//                                 parsing which lands in the next patch
//                                 alongside the ASN.1 DER helper. The
//                                 honest name keeps the surface from
//                                 claiming "good" while only checking
//                                 stapling.
//
// node:tls validates the cert chain itself; OCSP staple validation is
// the application's job once the response bytes are received.

function _connectAndCheckOcsp(opts, requireStapled) {
  return new Promise(function (resolve, reject) {
    var connectOpts = Object.assign({}, opts, { requestOCSP: true });
    var sock;
    try {
      sock = tls.connect(connectOpts);
    } catch (e) {
      reject(new TlsTrustError("tls/connect-failed",
        "tls.connect threw: " + ((e && e.message) || String(e))));
      return;
    }
    var ocspResponseSeen = false;
    sock.on("OCSPResponse", function (response) {
      ocspResponseSeen = true;
      if (!response || response.length === 0) {
        if (requireStapled) {
          sock.destroy();
          reject(new TlsTrustError("tls/ocsp-empty",
            "OCSP response was empty and requireStapled is set"));
          return;
        }
      }
      // Operator can post-process the DER OCSPResponse via the resolved
      // callback; the framework doesn't parse the ASN.1 itself.
      sock.once("secureConnect", function () {
        var rv = {
          authorized: sock.authorized,
          ocspBytes:  response || null,
          peerCert:   sock.getPeerCertificate(true),
        };
        sock.destroy();
        resolve(rv);
      });
    });
    sock.on("secureConnect", function () {
      // 'OCSPResponse' fires BEFORE 'secureConnect' when the server
      // replied with stapled OCSP. If we got here without seeing an
      // OCSPResponse event AND requireStapled is set, refuse.
      if (!ocspResponseSeen) {
        if (requireStapled) {
          sock.destroy();
          reject(new TlsTrustError("tls/ocsp-not-stapled",
            "TLS peer did not staple an OCSP response and requireStapled is set"));
          return;
        }
        var rv = {
          authorized: sock.authorized,
          ocspBytes:  null,
          peerCert:   sock.getPeerCertificate(true),
        };
        sock.destroy();
        resolve(rv);
      }
    });
    sock.on("error", function (e) { reject(e); });
  });
}

// ---- OCSP response parser (RFC 6960) ----
//
// Decodes a DER OCSPResponse into:
//   {
//     status:    "successful" | "malformedRequest" | "internalError" |
//                "tryLater" | "sigRequired" | "unauthorized",
//     basic: {                  // present when status === "successful"
//       tbsResponseDataDer: Buffer,    // the bytes signed
//       signatureAlgorithmOid: string,
//       signature: Buffer,
//       responses: [{ certIdSerialHex, certStatus, thisUpdate, nextUpdate }, ...],
//     }
//   }
//
// Cherry-picks the fields the framework needs to verify the response —
// the signed bytes (tbsResponseData) + the signature + each response
// entry's status. Out of scope: ResponderID / extensions / nonce
// validation (operators relying on those wire their own parser).

var OID_BASIC_OCSP_RESPONSE = "1.3.6.1.5.5.7.48.1.1";
var OID_RSA_SHA256          = "1.2.840.113549.1.1.11";
var OID_RSA_SHA384          = "1.2.840.113549.1.1.12";
var OID_RSA_SHA512          = "1.2.840.113549.1.1.13";
var OID_ECDSA_SHA256        = "1.2.840.10045.4.3.2";
var OID_ECDSA_SHA384        = "1.2.840.10045.4.3.3";
var OID_ECDSA_SHA512        = "1.2.840.10045.4.3.4";

function _parseTime(node) {
  // Parse UTCTime ("YYMMDDhhmmssZ") or GeneralizedTime
  // ("YYYYMMDDhhmmssZ") into ms-since-epoch.
  var s = node.value.toString("ascii");
  var year, month, day, hour, min, sec;
  if (s.length === 13 && s.charAt(12) === "Z") {                                 // allow:raw-byte-literal — UTCTime length per X.690
    // UTCTime YYMMDDhhmmssZ — 50+ → 19xx, else 20xx (RFC 5280 §4.1.2.5).
    year  = parseInt(s.slice(0, 2), 10);
    year += year >= 50 ? 1900 : 2000;                                            // allow:raw-byte-literal allow:raw-time-literal — RFC 5280 century pivot, calendar years
    month = parseInt(s.slice(2, 4), 10);
    day   = parseInt(s.slice(4, 6), 10);
    hour  = parseInt(s.slice(6, 8), 10);                                         // allow:raw-byte-literal — UTCTime hour-byte offsets
    min   = parseInt(s.slice(8, 10), 10);                                        // allow:raw-byte-literal — UTCTime minute-byte offsets
    sec   = parseInt(s.slice(10, 12), 10);
  } else if (s.length >= 15 && s.charAt(s.length - 1) === "Z") {                 // allow:raw-byte-literal — GeneralizedTime length per X.690
    // GeneralizedTime YYYYMMDDhhmmssZ.
    year  = parseInt(s.slice(0, 4), 10);
    month = parseInt(s.slice(4, 6), 10);
    day   = parseInt(s.slice(6, 8), 10);                                         // allow:raw-byte-literal — GeneralizedTime day-byte offsets
    hour  = parseInt(s.slice(8, 10), 10);                                        // allow:raw-byte-literal — GeneralizedTime hour-byte offsets
    min   = parseInt(s.slice(10, 12), 10);
    sec   = parseInt(s.slice(12, 14), 10);
  } else {
    throw new TlsTrustError("tls/ocsp-bad-time",
      "OCSP time field is not UTCTime or GeneralizedTime: " + JSON.stringify(s));
  }
  return Date.UTC(year, month - 1, day, hour, min, sec);
}

var OCSP_RESPONSE_STATUS = {
  0: "successful",
  1: "malformedRequest",
  2: "internalError",
  3: "tryLater",
  // 4 reserved
  5: "sigRequired",
  6: "unauthorized",
};

function parseOcspResponse(der) {
  if (!Buffer.isBuffer(der) || der.length === 0) {
    throw new TlsTrustError("tls/ocsp-bad-input",
      "parseOcspResponse: expected non-empty Buffer");
  }
  var top = asn1.readNode(der);                                                  // OCSPResponse SEQUENCE
  if (top.tag !== asn1.TAG.SEQUENCE) {
    throw new TlsTrustError("tls/ocsp-bad-shape", "OCSPResponse is not a SEQUENCE");
  }
  var topChildren = asn1.readSequence(top.value);
  if (topChildren.length === 0) {
    throw new TlsTrustError("tls/ocsp-bad-shape", "OCSPResponse has no responseStatus");
  }
  var statusInt = asn1.readUnsignedInt(topChildren[0]);
  var status = OCSP_RESPONSE_STATUS[statusInt] || ("unknown:" + statusInt);
  if (status !== "successful") {
    return { status: status };
  }
  // responseBytes [0] EXPLICIT ResponseBytes
  if (topChildren.length < 2) {
    throw new TlsTrustError("tls/ocsp-bad-shape",
      "successful OCSP response missing responseBytes");
  }
  var responseBytes = asn1.unwrapExplicit(topChildren[1], 0);                   // [0] EXPLICIT
  if (responseBytes.tag !== asn1.TAG.SEQUENCE) {
    throw new TlsTrustError("tls/ocsp-bad-shape", "responseBytes is not a SEQUENCE");
  }
  var rbChildren = asn1.readSequence(responseBytes.value);
  if (rbChildren.length < 2) {
    throw new TlsTrustError("tls/ocsp-bad-shape",
      "responseBytes missing responseType or response");
  }
  var responseTypeOid = asn1.readOid(rbChildren[0]);
  if (responseTypeOid !== OID_BASIC_OCSP_RESPONSE) {
    throw new TlsTrustError("tls/ocsp-unsupported-response-type",
      "OCSP responseType is not id-pkix-ocsp-basic: " + responseTypeOid);
  }
  // The OCTET STRING wraps a DER BasicOCSPResponse.
  var basicDer = asn1.readOctetString(rbChildren[1]);
  var basic    = asn1.readNode(basicDer);
  if (basic.tag !== asn1.TAG.SEQUENCE) {
    throw new TlsTrustError("tls/ocsp-bad-shape",
      "BasicOCSPResponse is not a SEQUENCE");
  }
  var basicChildren = asn1.readSequence(basic.value);
  if (basicChildren.length < 3) {                                                // allow:raw-byte-literal — minimum BasicOCSPResponse fields (tbs + alg + sig)
    throw new TlsTrustError("tls/ocsp-bad-shape",
      "BasicOCSPResponse needs tbsResponseData + signatureAlgorithm + signature");
  }
  var tbsNode = basicChildren[0];
  var sigAlgChildren = asn1.readSequence(basicChildren[1].value);
  var sigAlgOid = asn1.readOid(sigAlgChildren[0]);
  var signatureBytes = asn1.readBitString(basicChildren[2]);

  // Slice the tbsResponseData bytes (header + value) — that's what the
  // signature covers per RFC 6960 §4.2.1. tbsResponseData is the FIRST
  // child of BasicOCSPResponse; its bytes start at basic.valueStart
  // within the raw basicDer buffer (offset 0).
  var basicValueStart = basicDer.length - basic.value.length;
  var tbsDer = basicDer.slice(basicValueStart, basicValueStart + tbsNode.totalLength);

  // Walk responseData (SEQUENCE) for the per-cert responses.
  var rdChildren = asn1.readSequence(tbsNode.value);
  // Find the SEQUENCE of SingleResponse — it's the LAST SEQUENCE before
  // optional [1] EXPLICIT extensions. Per RFC 6960:
  //   ResponseData ::= SEQUENCE {
  //     version          [0] EXPLICIT Version DEFAULT v1,
  //     responderID      ResponderID,
  //     producedAt       GeneralizedTime,
  //     responses        SEQUENCE OF SingleResponse,
  //     responseExtensions [1] EXPLICIT Extensions OPTIONAL
  //   }
  // ResponderID is itself a CHOICE (byName [1] / byKey [2]), then a
  // GeneralizedTime, then the responses SEQUENCE-OF.
  var responsesNode = null;
  for (var rdi = rdChildren.length - 1; rdi >= 0; rdi -= 1) {
    var ch = rdChildren[rdi];
    if (ch.tag === asn1.TAG.SEQUENCE && ch.tagClass === asn1.TAG_CLASS.UNIVERSAL) {
      responsesNode = ch;
      break;
    }
  }
  if (!responsesNode) {
    throw new TlsTrustError("tls/ocsp-bad-shape",
      "ResponseData missing responses SEQUENCE OF");
  }
  var singleResponses = asn1.readSequence(responsesNode.value);
  var responses = [];
  for (var sri = 0; sri < singleResponses.length; sri += 1) {
    var sr = asn1.readSequence(singleResponses[sri].value);
    if (sr.length < 3) continue;                                                 // allow:raw-byte-literal — minimum SingleResponse fields
    // sr[0] = certID SEQUENCE, sr[1] = certStatus CHOICE, sr[2] = thisUpdate.
    var certIdChildren = asn1.readSequence(sr[0].value);
    // certID = SEQUENCE { hashAlgorithm, issuerNameHash, issuerKeyHash, serialNumber }
    var serialHex = certIdChildren.length >= 4
      ? certIdChildren[3].value.toString("hex")
      : null;
    var certStatus;
    var statusNode = sr[1];
    if (statusNode.tagClass === asn1.TAG_CLASS.CONTEXT_SPECIFIC) {
      certStatus = statusNode.tag === 0 ? "good" :
                   statusNode.tag === 1 ? "revoked" :
                   statusNode.tag === 2 ? "unknown" : "unknown";
    } else if (statusNode.tag === asn1.TAG.NULL) {
      certStatus = "good";
    } else {
      certStatus = "unknown";
    }
    var thisUpdate = _parseTime(sr[2]);
    var nextUpdate = null;
    if (sr.length >= 4 && sr[3].tagClass === asn1.TAG_CLASS.CONTEXT_SPECIFIC && sr[3].tag === 0) {
      nextUpdate = _parseTime(asn1.readNode(sr[3].value, 0));
    }
    responses.push({
      certIdSerialHex: serialHex,
      certStatus:      certStatus,
      thisUpdate:      thisUpdate,
      nextUpdate:      nextUpdate,
    });
  }

  return {
    status: status,
    basic: {
      tbsResponseDataDer:    tbsDer,
      signatureAlgorithmOid: sigAlgOid,
      signature:             signatureBytes,
      responses:             responses,
    },
  };
}

function _verifyOcspSignature(parsed, issuerPem) {
  if (!parsed || !parsed.basic) {
    throw new TlsTrustError("tls/ocsp-not-successful",
      "OCSP response status is not 'successful' (got " +
      (parsed && parsed.status) + ")");
  }
  var algOid = parsed.basic.signatureAlgorithmOid;
  var nodeAlgo = algOid === OID_RSA_SHA256   ? "sha256" :
                 algOid === OID_RSA_SHA384   ? "sha384" :
                 algOid === OID_RSA_SHA512   ? "sha512" :
                 algOid === OID_ECDSA_SHA256 ? "sha256" :
                 algOid === OID_ECDSA_SHA384 ? "sha384" :
                 algOid === OID_ECDSA_SHA512 ? "sha512" : null;
  if (nodeAlgo === null) {
    throw new TlsTrustError("tls/ocsp-unsupported-sig-alg",
      "OCSP signatureAlgorithm OID '" + algOid + "' is not supported by the verifier");
  }
  var keyObj;
  try { keyObj = nodeCrypto.createPublicKey(issuerPem); }
  catch (e) {
    throw new TlsTrustError("tls/ocsp-bad-issuer-key",
      "issuer public key parse failed: " + ((e && e.message) || String(e)));
  }
  // ECDSA OCSP signatures use DER-encoded ECDSA-Sig-Value (the ASN.1
  // shape that node:crypto.verify accepts by default — no dsaEncoding
  // option needed).
  var verified;
  try {
    verified = nodeCrypto.verify(nodeAlgo, parsed.basic.tbsResponseDataDer, keyObj,
                                 parsed.basic.signature);
  } catch (e) {
    throw new TlsTrustError("tls/ocsp-verify-threw",
      "OCSP signature verify threw: " + ((e && e.message) || String(e)));
  }
  return verified;
}

// Operator-side OCSP response evaluator. Takes the DER bytes (from
// `ocsp.requireStapled` or any other source) plus the issuer cert PEM
// and returns a structured outcome:
//   { ok, status, certStatus, thisUpdate, nextUpdate, signatureValid, errors }
function evaluateOcspResponse(ocspDer, opts) {
  opts = opts || {};
  var issuerPem = opts.issuerPem;
  if (!issuerPem) {
    throw new TlsTrustError("tls/ocsp-missing-issuer",
      "evaluateOcspResponse requires opts.issuerPem (PEM of the cert that signed the OCSP response — typically the leaf's CA OR a delegated id-kp-OCSPSigning responder cert)");
  }
  var parsed;
  try { parsed = parseOcspResponse(ocspDer); }
  catch (e) {
    return { ok: false, status: "parse-error",
             errors: [(e && e.message) || String(e)] };
  }
  if (parsed.status !== "successful") {
    return { ok: false, status: parsed.status, errors: ["responseStatus=" + parsed.status] };
  }
  var sigOk = false;
  try { sigOk = _verifyOcspSignature(parsed, issuerPem); }
  catch (e) {
    return { ok: false, status: parsed.status,
             signatureValid: false,
             errors: [(e && e.message) || String(e)] };
  }
  if (!sigOk) {
    return { ok: false, status: parsed.status, signatureValid: false,
             errors: ["OCSP signature did not verify against the issuer key"] };
  }
  // Look up the requested cert serial in the responses; "good" wins.
  var serial = opts.serialHex || (parsed.basic.responses[0] && parsed.basic.responses[0].certIdSerialHex);
  var match = null;
  for (var i = 0; i < parsed.basic.responses.length; i += 1) {
    var r = parsed.basic.responses[i];
    if (!serial || r.certIdSerialHex === serial) { match = r; break; }
  }
  if (!match) {
    return { ok: false, status: parsed.status, signatureValid: true,
             errors: ["OCSP response has no entry for the requested cert serial"] };
  }
  return {
    ok:             match.certStatus === "good",
    status:         parsed.status,
    certStatus:     match.certStatus,
    thisUpdate:     match.thisUpdate,
    nextUpdate:     match.nextUpdate,
    signatureValid: true,
    errors:         match.certStatus === "good" ? [] :
                    ["certStatus=" + match.certStatus],
  };
}

var ocsp = Object.freeze({
  // Connect with OCSP requested. Returns { authorized, ocspBytes,
  // peerCert }. requireStapled: true makes empty / not-stapled responses
  // refuse instead of resolve. NOTE: requireStapled does NOT verify the
  // OCSP response signature — pair it with evaluateOcspResponse(bytes,
  // { issuerPem }) for full verification, OR use requireGood below.
  connect: function (opts) {
    return _connectAndCheckOcsp(opts || {}, false);
  },
  requireStapled: function (opts) {
    return _connectAndCheckOcsp(opts || {}, true);
  },
  // requireGood: connect + parse + verify signature + check certStatus.
  // Operator passes opts.issuerPem (the cert that signed the OCSP
  // response — typically the leaf's CA OR a delegated OCSP responder
  // cert). Throws TlsTrustError on any failure (no-staple, parse error,
  // signature mismatch, certStatus=revoked/unknown).
  requireGood: async function (opts) {
    opts = opts || {};
    if (!opts.issuerPem) {
      throw new TlsTrustError("tls/ocsp-missing-issuer",
        "ocsp.requireGood requires opts.issuerPem (PEM of the OCSP-signing cert)");
    }
    var rv = await _connectAndCheckOcsp(opts, true);
    if (!rv.ocspBytes || rv.ocspBytes.length === 0) {
      throw new TlsTrustError("tls/ocsp-empty",
        "OCSP response was empty");
    }
    var evald = evaluateOcspResponse(rv.ocspBytes, {
      issuerPem: opts.issuerPem,
      serialHex: opts.serialHex || null,
    });
    if (!evald.ok) {
      throw new TlsTrustError("tls/ocsp-not-good",
        "OCSP evaluation failed: " + evald.errors.join("; "));
    }
    return Object.assign({}, rv, { ocspEvaluation: evald });
  },
  parseResponse:        parseOcspResponse,
  evaluate:             evaluateOcspResponse,
  // inspectMustStaple — read the RFC 7633 TLS Feature extension on a
  // peer cert. Returns { mustStaple, features }. mustStaple === true
  // when status_request (5) is in the feature list; the cert is then
  // contractually required to ship an OCSP staple on every connection.
  inspectMustStaple: function (rawDer) {
    if (!Buffer.isBuffer(rawDer)) {
      throw new TlsTrustError("tls/ocsp-bad-input",
        "ocsp.inspectMustStaple: rawDer must be a Buffer (cert.raw)");
    }
    return _extractTlsFeatureExtensionFromCert(rawDer);
  },
  // requireMustStaple(peerCert, opts) — operator predicate. Refuses
  // when the cert advertises must-staple but no OCSP staple was
  // delivered (opts.ocspBytes empty/missing). When the cert does NOT
  // advertise must-staple, the predicate returns null (operator opted
  // in by setting opts.enforceUnconditional to also require staples
  // on certs that don't carry the extension).
  requireMustStaple: function (opts) {
    opts = opts || {};
    var enforceUnconditional = opts.enforceUnconditional === true;
    return function (peerCert, ctx) {
      if (!peerCert || !peerCert.raw) {
        return new TlsTrustError("tls/ocsp-no-cert",
          "requireMustStaple: peer cert.raw missing");
      }
      var feat = _extractTlsFeatureExtensionFromCert(peerCert.raw);
      var stapled = ctx && Buffer.isBuffer(ctx.ocspBytes) && ctx.ocspBytes.length > 0;
      if (feat.mustStaple && !stapled) {
        return new TlsTrustError("tls/ocsp-must-staple-violated",
          "cert advertises must-staple (RFC 7633) but no OCSP staple was delivered");
      }
      if (!feat.mustStaple && enforceUnconditional && !stapled) {
        return new TlsTrustError("tls/ocsp-staple-required",
          "operator policy requires OCSP staple but server did not provide one");
      }
      return null;
    };
  },
});

// ---- Certificate Transparency (RFC 6962 + RFC 9162) SCT verifier --
//
// CT requires every TLS server certificate to carry at least 2 Signed
// Certificate Timestamps (SCTs) from approved logs. Modern browsers
// (Chrome / Safari) refuse certificates without sufficient SCTs.
//
// node:tls surfaces SCTs via TLSSocket.getPeerX509Certificate() →
// X509Certificate.raw (the DER cert). The SCTs sit inside the cert as
// the OCSP-aware extension OID 1.3.6.1.4.1.11129.2.4.2.
//
// b.network.tls.ct.verify(cert, opts) checks that the cert has at
// least `minScts` SCTs and that each SCT references a log in
// `approvedLogs`. Full SCT-signature verification against the log's
// pubkey is OUT of scope for this patch — that requires log-pubkey
// distribution + ASN.1 SCT parsing. The framework provides the
// SCT-presence + log-id check; signature verification is a follow-up
// when the ASN.1 dependency lands.

// SCT extension OID per RFC 6962 §3.3.
var OID_CT_SCT_LIST = "1.3.6.1.4.1.11129.2.4.2";

// Walk a DER X.509 cert and locate the SCT extension's OCTET STRING
// content. Returns { sctListRaw } or { sctListRaw: null } when no SCT
// extension is present.
function _extractSctExtensionFromCert(certDer) {
  // Tolerant of malformed cert buffers — return null sctListRaw when
  // the ASN.1 walk fails. Callers (parseScts / verifyScts) treat that
  // as "no SCT extension" rather than throwing on broken input.
  var top;
  try { top = asn1.readNode(certDer); }
  catch (_e) { return { sctListRaw: null }; }
  if (top.tag !== asn1.TAG.SEQUENCE) return { sctListRaw: null };
  var children;
  try { children = asn1.readSequence(top.value); }
  catch (_e) { return { sctListRaw: null }; }
  if (children.length === 0) return { sctListRaw: null };
  // Cert ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
  var tbs = children[0];
  if (tbs.tag !== asn1.TAG.SEQUENCE) return { sctListRaw: null };
  // tbsCertificate ::= SEQUENCE { ..., extensions [3] EXPLICIT ... }
  var tbsChildren;
  try { tbsChildren = asn1.readSequence(tbs.value); }
  catch (_e) { return { sctListRaw: null }; }
  var extensionsNode = null;
  for (var i = 0; i < tbsChildren.length; i += 1) {
    var ch = tbsChildren[i];
    if (ch.tagClass === asn1.TAG_CLASS.CONTEXT_SPECIFIC && ch.tag === 3) {       // allow:raw-byte-literal — X.509 [3] EXPLICIT extensions tag
      extensionsNode = asn1.readNode(ch.value, 0);
      break;
    }
  }
  if (!extensionsNode || extensionsNode.tag !== asn1.TAG.SEQUENCE) {
    return { sctListRaw: null };
  }
  var extensions = asn1.readSequence(extensionsNode.value);
  for (var e = 0; e < extensions.length; e += 1) {
    var ext = extensions[e];                                                     // Extension ::= SEQUENCE { extnID OID, critical BOOL OPTIONAL, extnValue OCTET STRING }
    if (ext.tag !== asn1.TAG.SEQUENCE) continue;
    var extChildren = asn1.readSequence(ext.value);
    if (extChildren.length === 0) continue;
    var extOid = asn1.readOid(extChildren[0]);
    if (extOid !== OID_CT_SCT_LIST) continue;
    // The last child is the OCTET STRING extnValue. Per RFC 6962 §3.3
    // that OCTET STRING wraps a SECOND OCTET STRING which contains the
    // raw SignedCertificateTimestampList (TLS-encoded).
    var extnValueOuter = asn1.readOctetString(extChildren[extChildren.length - 1]);
    var inner = asn1.readNode(extnValueOuter);
    if (inner.tag !== asn1.TAG.OCTET_STRING) {
      throw new TlsTrustError("tls/ct-bad-extension",
        "SCT extension extnValue does not wrap a second OCTET STRING");
    }
    return { sctListRaw: inner.value };
  }
  return { sctListRaw: null };
}

// TLS Feature extension OID per RFC 7633 §6. The extension value is
// SEQUENCE OF INTEGER; the integer 5 == status_request == "must-staple".
var OID_TLS_FEATURE = "1.3.6.1.5.5.7.1.24";
var TLS_FEATURE_STATUS_REQUEST = 5;

// Walk a DER X.509 cert and return the TLS Feature extension's
// integer list. Returns { mustStaple, features }. Tolerant of
// malformed cert input — mirrors _extractSctExtensionFromCert's
// try/catch tolerance.
function _extractTlsFeatureExtensionFromCert(certDer) {
  var none = { mustStaple: false, features: [] };
  var top;
  try { top = asn1.readNode(certDer); }
  catch (_e) { return none; }
  if (top.tag !== asn1.TAG.SEQUENCE) return none;
  var children;
  try { children = asn1.readSequence(top.value); }
  catch (_e) { return none; }
  if (children.length === 0) return none;
  var tbs = children[0];
  if (tbs.tag !== asn1.TAG.SEQUENCE) return none;
  var tbsChildren;
  try { tbsChildren = asn1.readSequence(tbs.value); }
  catch (_e) { return none; }
  var extensionsNode = null;
  for (var i = 0; i < tbsChildren.length; i += 1) {
    var ch = tbsChildren[i];
    if (ch.tagClass === asn1.TAG_CLASS.CONTEXT_SPECIFIC && ch.tag === 3) {       // allow:raw-byte-literal — X.509 [3] EXPLICIT extensions tag
      extensionsNode = asn1.readNode(ch.value, 0);
      break;
    }
  }
  if (!extensionsNode || extensionsNode.tag !== asn1.TAG.SEQUENCE) return none;
  var extensions = asn1.readSequence(extensionsNode.value);
  for (var e = 0; e < extensions.length; e += 1) {
    var ext = extensions[e];
    if (ext.tag !== asn1.TAG.SEQUENCE) continue;
    var extChildren = asn1.readSequence(ext.value);
    if (extChildren.length === 0) continue;
    var extOid;
    try { extOid = asn1.readOid(extChildren[0]); }
    catch (_e2) { continue; }
    if (extOid !== OID_TLS_FEATURE) continue;
    var extnValue = asn1.readOctetString(extChildren[extChildren.length - 1]);
    // extnValue wraps SEQUENCE OF INTEGER.
    var seq;
    try { seq = asn1.readNode(extnValue); }
    catch (_e3) { return none; }
    if (seq.tag !== asn1.TAG.SEQUENCE) return none;
    var feats = asn1.readSequence(seq.value);
    var ints = [];
    var mustStaple = false;
    for (var f = 0; f < feats.length; f += 1) {
      try {
        var n = asn1.readUnsignedInt(feats[f]);
        ints.push(n);
        if (n === TLS_FEATURE_STATUS_REQUEST) mustStaple = true;
      } catch (_e4) { /* ignore non-integer entries */ }
    }
    return { mustStaple: mustStaple, features: ints };
  }
  return none;
}

// Parse the TLS-encoded SignedCertificateTimestampList (RFC 6962 §3.3).
// Format: 2-byte length + concatenation of individual SCTs, each
// itself prefixed by a 2-byte length.
function _parseSctList(sctListRaw) {
  if (!Buffer.isBuffer(sctListRaw) || sctListRaw.length < 2) {                   // allow:raw-byte-literal — outer 2-byte length prefix
    throw new TlsTrustError("tls/ct-bad-list",
      "SCT list shorter than the outer length prefix");
  }
  var totalLen = sctListRaw.readUInt16BE(0);
  if (totalLen + 2 !== sctListRaw.length) {                                      // allow:raw-byte-literal — outer length prefix
    throw new TlsTrustError("tls/ct-bad-list",
      "SCT list outer length " + totalLen + " does not match buffer " +
      (sctListRaw.length - 2));
  }
  var pos = 2;                                                                   // allow:raw-byte-literal — past the outer prefix
  var scts = [];
  while (pos < sctListRaw.length) {
    var sctLen = sctListRaw.readUInt16BE(pos);
    pos += 2;
    if (pos + sctLen > sctListRaw.length) {
      throw new TlsTrustError("tls/ct-bad-list",
        "SCT[" + scts.length + "] declared length " + sctLen +
        " extends past the list buffer");
    }
    var sctBytes = sctListRaw.slice(pos, pos + sctLen);
    scts.push(_parseSct(sctBytes));
    pos += sctLen;
  }
  return scts;
}

// Per RFC 6962 §3.2 — a single SCT:
//   sct_version          (1 byte)         — 0 = v1
//   id (LogID)           (32 bytes)       — SHA-256 of log's pubkey
//   timestamp            (8 bytes)        — uint64 ms since epoch
//   ct_extensions        (2-byte len + N) — usually empty
//   signature            DigitallySigned  (hash + sig algo + 2-byte len + N)
function _parseSct(sctBuf) {
  if (sctBuf.length < 1 + 32 + 8 + 2 + 4) {                                      // allow:raw-byte-literal — minimum SCT v1 byte total
    throw new TlsTrustError("tls/ct-sct-too-short",
      "SCT is shorter than the minimum v1 layout (" + sctBuf.length + " bytes)");
  }
  var version = sctBuf[0];
  if (version !== 0) {
    throw new TlsTrustError("tls/ct-sct-bad-version",
      "SCT version is not 0 (v1): got " + version);
  }
  var logId = sctBuf.slice(1, 1 + 32);                                           // allow:raw-byte-literal — RFC 6962 32-byte LogID
  var timestamp = Number(sctBuf.readBigUInt64BE(1 + 32));                        // allow:raw-byte-literal — past LogID
  var extLen = sctBuf.readUInt16BE(1 + 32 + 8);                                  // allow:raw-byte-literal — past LogID + timestamp
  var pos = 1 + 32 + 8 + 2;                                                      // allow:raw-byte-literal — past extLen field
  var extensions = sctBuf.slice(pos, pos + extLen);
  pos += extLen;
  if (pos + 4 > sctBuf.length) {                                                 // allow:raw-byte-literal — DigitallySigned header (hash + alg + len)
    throw new TlsTrustError("tls/ct-sct-truncated",
      "SCT truncated before DigitallySigned");
  }
  var hashAlgo = sctBuf[pos];
  var sigAlgo  = sctBuf[pos + 1];
  pos += 2;                                                                      // allow:raw-byte-literal — past hash+alg pair
  var sigLen = sctBuf.readUInt16BE(pos);
  pos += 2;                                                                      // allow:raw-byte-literal — past sig length
  if (pos + sigLen !== sctBuf.length) {
    throw new TlsTrustError("tls/ct-sct-truncated",
      "SCT signature length " + sigLen + " does not match remaining bytes " +
      (sctBuf.length - pos));
  }
  var signature = sctBuf.slice(pos, pos + sigLen);
  return {
    version:    version,
    logId:      logId,
    logIdHex:   logId.toString("hex"),
    timestamp:  timestamp,
    extensions: extensions,
    hashAlgo:   hashAlgo,    // RFC 5246 HashAlgorithm enum (4=sha256, 5=sha384, 6=sha512)
    sigAlgo:    sigAlgo,     // RFC 5246 SignatureAlgorithm enum (1=rsa, 3=ecdsa)
    signature:  signature,
  };
}

// Build the canonical signed-entry per RFC 6962 §3.2 for X.509
// pre-cert-free chains (issued cert path):
//   sct_version (1) || signature_type (1=certificate_timestamp) ||
//   timestamp (8) || entry_type (0=x509_entry) ||
//   signed_entry (3-byte length || ASN.1 cert without SCT extension) ||
//   ct_extensions (2-byte length || N)
function _buildSctSignedEntry(certWithoutSctDer, sct) {
  var head = Buffer.alloc(1 + 1 + 8 + 2);                                        // allow:raw-byte-literal — fixed-shape header bytes
  head[0] = sct.version;
  head[1] = 0;                                                                   // signature_type = certificate_timestamp
  head.writeBigUInt64BE(BigInt(sct.timestamp), 2);                               // allow:raw-byte-literal — past version+sig-type
  head.writeUInt16BE(0, 10);                                                     // allow:raw-byte-literal — entry_type = x509_entry (2 bytes; high byte = 0, low byte = 0)
  // signed_entry: 3-byte length prefix + cert DER.
  var lenBytes = Buffer.alloc(3);                                                // allow:raw-byte-literal — RFC 6962 24-bit length prefix
  lenBytes[0] = (certWithoutSctDer.length >> 16) & 0xff;                         // allow:raw-byte-literal — base-256 length high byte
  lenBytes[1] = (certWithoutSctDer.length >> 8) & 0xff;                          // allow:raw-byte-literal — base-256 length mid byte
  lenBytes[2] = certWithoutSctDer.length & 0xff;                                 // allow:raw-byte-literal — base-256 length low byte
  // ct_extensions: 2-byte length + bytes.
  var extHead = Buffer.alloc(2);                                                 // allow:raw-byte-literal — RFC 6962 2-byte ct_extensions length prefix
  extHead.writeUInt16BE(sct.extensions.length, 0);
  return Buffer.concat([head, lenBytes, certWithoutSctDer, extHead, sct.extensions]);
}

// Strip the SCT extension from a DER cert + return the rebuilt cert
// bytes for SCT signing per RFC 6962 §3.2. The strip is byte-precise:
// walk the TBSCertificate extensions list, drop the SCT extension,
// and re-encode just enough of the chain to reproduce the original
// shape minus that one extension. This is non-trivial because the
// tbsCertificate length, certificate length, and signature-bytes
// boundaries all shift.
//
// Simpler: rebuild only the tbsCertificate extensions SEQUENCE without
// the SCT entry, recompute lengths above it, and replace the cert's
// SignedCertificate (BIT STRING) with the original's signature too —
// but that's incorrect since the original signature was computed over
// the WITH-SCT TBS. The CT log signed an entry built from the
// without-SCT pre-issuance shape, NOT the issued cert's tbs.
//
// Per RFC 6962 §3.1, log servers receive a "TBSCertificate" minus the
// SCT extension from the CA. The signed_entry the framework
// reconstructs is that pre-extension TBSCertificate. We compute it by
// removing the SCT extension at the byte level and rebuilding all
// outer length prefixes.
function _stripSctExtensionFromCert(certDer) {
  var top = asn1.readNode(certDer);
  if (top.tag !== asn1.TAG.SEQUENCE) {
    throw new TlsTrustError("tls/ct-bad-cert", "Certificate is not a SEQUENCE");
  }
  var topChildren = asn1.readSequence(top.value);
  var tbs = topChildren[0];
  if (tbs.tag !== asn1.TAG.SEQUENCE) {
    throw new TlsTrustError("tls/ct-bad-cert", "tbsCertificate is not a SEQUENCE");
  }
  // Walk tbsCertificate to find the [3] EXPLICIT extensions wrapper.
  var tbsChildren = asn1.readSequence(tbs.value);
  var newTbsChildrenBytes = [];
  var foundExtensions = false;
  for (var i = 0; i < tbsChildren.length; i += 1) {
    var ch = tbsChildren[i];
    if (ch.tagClass === asn1.TAG_CLASS.CONTEXT_SPECIFIC && ch.tag === 3) {       // allow:raw-byte-literal — [3] EXPLICIT extensions tag
      foundExtensions = true;
      // Inner SEQUENCE OF Extensions.
      var inner = asn1.readNode(ch.value, 0);
      var extList = asn1.readSequence(inner.value);
      var keptExtBytes = [];
      for (var j = 0; j < extList.length; j += 1) {
        var ext = extList[j];
        var extBytes = ext.value;
        var extDescChildren = asn1.readSequence(ext.value);
        if (extDescChildren.length > 0) {
          try {
            var oid = asn1.readOid(extDescChildren[0]);
            if (oid === OID_CT_SCT_LIST) continue;                               // drop the SCT extension
          } catch (_e) { /* not an OID — keep the extension as-is */ }
        }
        // Re-encode this extension verbatim (we have the original bytes).
        var origExt = certDer.slice(0, 0);                                       // placeholder; we rebuild from the parsed node below
        void origExt;
        keptExtBytes.push(_encodeAsn1(asn1.TAG.SEQUENCE, true, extBytes));
        void extBytes;
      }
      var newExtSeq = _encodeAsn1(asn1.TAG.SEQUENCE, true, Buffer.concat(keptExtBytes));
      var newExplicit3 = _encodeContextExplicit(3, newExtSeq);
      newTbsChildrenBytes.push(newExplicit3);
    } else {
      // Re-encode the original child verbatim by slicing its bytes from
      // the parent's value buffer.
      var childDer = _encodeAsn1FromNode(ch);
      newTbsChildrenBytes.push(childDer);
    }
  }
  if (!foundExtensions) {
    // Cert has no extensions at all — caller's SCT lookup would have
    // returned no SCT bytes, so this path shouldn't run. Surface anyway.
    throw new TlsTrustError("tls/ct-no-extensions",
      "cert has no extensions to strip from");
  }
  var newTbsValue = Buffer.concat(newTbsChildrenBytes);
  var newTbs = _encodeAsn1(asn1.TAG.SEQUENCE, true, newTbsValue);
  return newTbs;
}

// Minimal DER encoder helpers — enough to rebuild a TBS without the
// SCT extension. Tag class is universal for SEQUENCE; constructed
// flag wired explicitly.
function _encodeLength(len) {
  if (len < 0x80) return Buffer.from([len]);                                     // allow:raw-byte-literal — DER short-form length threshold
  var tmp = [];
  var n = len;
  while (n > 0) {
    tmp.unshift(n & 0xff);                                                       // allow:raw-byte-literal — base-256 byte
    n = n >>> 8;                                                                 // allow:raw-byte-literal — byte shift
  }
  return Buffer.concat([Buffer.from([0x80 | tmp.length]), Buffer.from(tmp)]);    // allow:raw-byte-literal — DER long-form length flag
}
function _encodeAsn1(tag, constructed, value) {
  var tagByte = (constructed ? 0x20 : 0x00) | tag;                               // allow:raw-byte-literal — DER constructed bit + universal tag
  return Buffer.concat([Buffer.from([tagByte]), _encodeLength(value.length), value]);
}
function _encodeContextExplicit(num, value) {
  // Context-specific class (10) + constructed (20) | tag.
  var tagByte = 0xa0 | num;                                                      // allow:raw-byte-literal — DER context-specific + constructed
  return Buffer.concat([Buffer.from([tagByte]), _encodeLength(value.length), value]);
}
function _encodeAsn1FromNode(node) {
  // Re-encode a parsed node verbatim by replaying the tag + length +
  // value. Universal-class shortcut: if class is universal, set the
  // tag byte from the universal table; if constructed, set the bit.
  // Context-specific / application / private classes get their bytes
  // restored directly. This works for the simple shapes we walk.
  var tagByte;
  if (node.tagClass === asn1.TAG_CLASS.UNIVERSAL) {
    tagByte = (node.constructed ? 0x20 : 0x00) | (node.tag & 0x1f);              // allow:raw-byte-literal — DER constructed bit + universal tag
  } else {
    var classBits = (node.tagClass & 0x03) << 6;                                 // allow:raw-byte-literal — DER tag-class bits
    tagByte = classBits | (node.constructed ? 0x20 : 0x00) | (node.tag & 0x1f);  // allow:raw-byte-literal — DER constructed bit + low-tag
  }
  return Buffer.concat([Buffer.from([tagByte]), _encodeLength(node.value.length), node.value]);
}

// SCT signature verification per RFC 6962 §3.2. opts.logKeys maps
// log_id (hex) → PEM public key. Operators populate from the Chrome
// CT log list (https://www.gstatic.com/ct/log_list/v3/log_list.json
// or equivalent) — log keys rotate, so the framework does NOT bake
// them in; that drift is the operator's to manage.
function verifyScts(certDer, opts) {
  opts = opts || {};
  if (!Buffer.isBuffer(certDer)) {
    throw new TlsTrustError("tls/ct-bad-input",
      "verifyScts: certDer must be a Buffer");
  }
  var logKeys = opts.logKeys || {};
  var minScts = typeof opts.minScts === "number" ? opts.minScts : 2;             // allow:raw-byte-literal — Chrome CT policy min-2-SCTs
  var ext = _extractSctExtensionFromCert(certDer);
  if (!ext.sctListRaw) {
    return { ok: false, reason: "no-sct-extension", scts: [] };
  }
  var scts;
  try { scts = _parseSctList(ext.sctListRaw); }
  catch (e) {
    return { ok: false, reason: "parse-error",
             error: (e && e.message) || String(e), scts: [] };
  }
  // Strip the SCT extension to compute the signed-entry per §3.2.
  var stripped;
  try { stripped = _stripSctExtensionFromCert(certDer); }
  catch (e) {
    return { ok: false, reason: "strip-failed",
             error: (e && e.message) || String(e), scts: scts };
  }
  var verifiedCount = 0;
  var perSctResults = [];
  for (var s = 0; s < scts.length; s += 1) {
    var sct = scts[s];
    var pem = logKeys[sct.logIdHex];
    if (!pem) {
      perSctResults.push({ logIdHex: sct.logIdHex, verified: false,
        reason: "log-key-missing" });
      continue;
    }
    var signedEntry;
    try { signedEntry = _buildSctSignedEntry(stripped, sct); }
    catch (e) {
      perSctResults.push({ logIdHex: sct.logIdHex, verified: false,
        reason: "build-entry-failed",
        error: (e && e.message) || String(e) });
      continue;
    }
    var nodeAlgo = sct.hashAlgo === 4 ? "sha256" :                               // allow:raw-byte-literal — TLS 1.2 HashAlgorithm enum sha256
                   sct.hashAlgo === 5 ? "sha384" :                               // allow:raw-byte-literal — TLS 1.2 HashAlgorithm enum sha384
                   sct.hashAlgo === 6 ? "sha512" :                               // allow:raw-byte-literal — TLS 1.2 HashAlgorithm enum sha512
                   null;
    if (nodeAlgo === null) {
      perSctResults.push({ logIdHex: sct.logIdHex, verified: false,
        reason: "unsupported-hash-algo", hashAlgo: sct.hashAlgo });
      continue;
    }
    var keyObj;
    try { keyObj = nodeCrypto.createPublicKey(pem); }
    catch (e) {
      perSctResults.push({ logIdHex: sct.logIdHex, verified: false,
        reason: "log-key-parse-failed",
        error: (e && e.message) || String(e) });
      continue;
    }
    var verified;
    try { verified = nodeCrypto.verify(nodeAlgo, signedEntry, keyObj, sct.signature); }
    catch (e) {
      perSctResults.push({ logIdHex: sct.logIdHex, verified: false,
        reason: "verify-threw",
        error: (e && e.message) || String(e) });
      continue;
    }
    perSctResults.push({ logIdHex: sct.logIdHex, verified: verified });
    if (verified) verifiedCount += 1;
  }
  return {
    ok:             verifiedCount >= minScts,
    reason:         verifiedCount >= minScts ? null : "insufficient-verified",
    minScts:        minScts,
    verifiedCount:  verifiedCount,
    totalScts:      scts.length,
    scts:           perSctResults,
  };
}

function _findSctOid(rawDer) {
  // Cheap presence check — used by inspect() before ASN.1 walking.
  // OID 1.3.6.1.4.1.11129.2.4.2 = 06 0A 2B 06 01 04 01 D6 79 02 04 02.
  var oidBytes = Buffer.from([
    0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, 0x02,
  ]);
  return rawDer.indexOf(oidBytes) !== -1;
}

var ct = Object.freeze({
  // inspect — quick presence check for the SCT extension.
  inspect: function (rawDer) {
    if (!Buffer.isBuffer(rawDer)) {
      throw new TlsTrustError("tls/ct-bad-input",
        "ct.inspect: rawDer must be a Buffer (cert.raw)");
    }
    return {
      hasSctExtension: _findSctOid(rawDer),
      rawLength:       rawDer.length,
    };
  },
  // parseScts — full ASN.1 walk + SCT-list parse. Returns
  // [{ version, logIdHex, timestamp, signature, ... }, ...] or [] when
  // no SCT extension is present.
  parseScts: function (rawDer) {
    if (!Buffer.isBuffer(rawDer)) {
      throw new TlsTrustError("tls/ct-bad-input",
        "ct.parseScts: rawDer must be a Buffer");
    }
    var ext = _extractSctExtensionFromCert(rawDer);
    if (!ext.sctListRaw) return [];
    return _parseSctList(ext.sctListRaw);
  },
  // verifyScts — full RFC 6962 verification. opts.logKeys maps
  // log_id (hex SHA-256 of the log's pubkey) → PEM public key.
  // Operators populate from the Chrome CT log list. Returns
  // { ok, verifiedCount, totalScts, scts: [{ logIdHex, verified, ... }] }.
  verifyScts: verifyScts,
  // Operator middleware predicate: refuse a peer cert lacking SCT
  // verification. Composes verifyScts under the hood.
  requireScts: function (opts) {
    opts = opts || {};
    return function (peerCert) {
      if (!peerCert || !peerCert.raw) {
        return new TlsTrustError("tls/ct-no-cert",
          "requireScts: peer cert.raw missing");
      }
      var rv = verifyScts(peerCert.raw, opts);
      if (!rv.ok) {
        // Map verifier reason → operator-facing error code so call
        // sites can distinguish "no SCT extension at all" from
        // "extension present but verification short of minScts".
        var code = "tls/ct-not-verified";
        if (rv.reason === "no-sct-extension") code = "tls/ct-no-sct-extension";
        else if (rv.reason === "insufficient-verified") code = "tls/ct-insufficient-verified";
        return new TlsTrustError(code,
          "SCT verification failed: " + (rv.reason || "unknown") +
          " (" + rv.verifiedCount + "/" + rv.totalScts + " verified)");
      }
      return null;
    };
  },
});

module.exports = {
  addCa:               addCa,
  addCaBundle:         addCaBundle,
  removeCa:            removeCa,
  removeCaByLabel:     removeCaByLabel,
  clearAll:            clearAll,
  purgeExpired:        purgeExpired,
  expiringSoon:        expiringSoon,
  useSystemTrust:      useSystemTrust,
  isSystemTrustEnabled: isSystemTrustEnabled,
  getTrustStore:       getTrustStore,
  captureBaselineFingerprints: captureBaselineFingerprints,
  detectBaselineDrift: detectBaselineDrift,
  applyToContext:      applyToContext,
  getCaPems:           getCaPems,
  ocsp:                ocsp,
  ct:                  ct,
  TlsTrustError:       TlsTrustError,
  _resetForTest:       _resetForTest,
};
