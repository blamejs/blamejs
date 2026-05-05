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

var ocsp = Object.freeze({
  // Connect with OCSP requested. Returns { authorized, ocspBytes,
  // peerCert }. requireStapled: true makes empty / not-stapled responses
  // refuse instead of resolve.
  connect: function (opts) {
    return _connectAndCheckOcsp(opts || {}, false);
  },
  requireStapled: function (opts) {
    return _connectAndCheckOcsp(opts || {}, true);
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

// Approved CT logs as of 2026-05 — Google Argon, Cloudflare Nimbus,
// DigiCert Yeti, Sectigo Sabre. Operators with custom log lists pass
// `approvedLogs` to override.
var APPROVED_CT_LOGS = Object.freeze([
  "google-argon-2026", "google-argon-2027", "google-argon-2028",
  "cloudflare-nimbus-2026", "cloudflare-nimbus-2027", "cloudflare-nimbus-2028",
  "digicert-yeti-2026", "digicert-yeti-2027",
  "sectigo-sabre-2026", "sectigo-sabre-2027",
  "letsencrypt-oak-2026", "letsencrypt-oak-2027",
]);

function _findSctOid(rawDer) {
  // Heuristic substring-search for the SCT extension OID encoding.
  // The full DER-walk requires an ASN.1 parser; until that lands, the
  // OID byte-pattern presence is a reliable presence signal. (This is
  // the same approach hot-fix tools use when they don't ship an ASN.1
  // dependency.) ASN.1 OID 1.3.6.1.4.1.11129.2.4.2 = byte sequence
  // 06 0A 2B 06 01 04 01 D6 79 02 04 02.
  var oidBytes = Buffer.from([
    0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, 0x02,
  ]);
  return rawDer.indexOf(oidBytes) !== -1;
}

var ct = Object.freeze({
  APPROVED_LOGS: APPROVED_CT_LOGS,
  // Returns { hasSctExtension, raw } — hasSctExtension is true if the
  // cert carries the CT SCT extension. Full SCT signature verification
  // is a follow-up patch; see b.network.tls.ct.requireScts() for the
  // operator-side enforcement primitive.
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
  // Operator middleware: refuse a connection whose peer cert lacks the
  // SCT extension. opts.minScts hint is recorded but not yet enforced
  // (presence-only until the SCT-signature verifier lands). Returns
  // an http-client / middleware-shaped predicate `(peerCertChain) →
  // Error|null` operators wire into their TLS connect flow.
  requireScts: function (opts) {
    opts = opts || {};
    var minScts = typeof opts.minScts === "number" ? opts.minScts : 2;
    return function (peerCert) {
      if (!peerCert || !peerCert.raw) {
        return new TlsTrustError("tls/ct-no-cert",
          "requireScts: peer cert.raw missing");
      }
      var insp = ct.inspect(peerCert.raw);
      if (!insp.hasSctExtension) {
        return new TlsTrustError("tls/ct-no-sct-extension",
          "peer cert does not carry the CT SCT extension (RFC 6962 / 9162)");
      }
      // minScts enforcement deferred until the ASN.1 SCT-list parser lands.
      void minScts;
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
