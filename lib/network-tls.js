"use strict";

var tls = require("node:tls");
var fs = require("node:fs");
var path = require("node:path");
var nodeCrypto = require("node:crypto");

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
    throw new TlsTrustError("CA must be a PEM string or path, got " + typeof pem, "tls/bad-ca");
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
    throw new TlsTrustError("CA PEM not parseable: " + e.message, "tls/bad-ca-pem");
  }
}

function _isPathLike(s) {
  if (s.indexOf("-----BEGIN") !== -1) return false;
  if (s.length > 1024) return false;
  if (/[\r\n]/.test(s)) return false;
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
      throw new TlsTrustError("tls.addCa: input has no PEM marker and is not a readable path: " +
        pemOrPath, "tls/empty-pem");
    }
    raw = _readPath(pemOrPath);
    if (!stat) raw = "";
  }
  raw = _normalizePem(raw);
  var blocks = _splitPemBundle(raw);
  if (blocks.length === 0) {
    throw new TlsTrustError("no CERTIFICATE blocks found in PEM input", "tls/empty-pem");
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
    } catch (_e) {}
  }
}

function _emitObs(name, fields) {
  try { observability().emit(name, fields || {}); } catch (_e) {}
}

function _resetForTest() {
  STATE.cas = [];
  STATE.systemTrust = false;
  STATE.baselineFingerprints = null;
}

module.exports = {
  addCa:               addCa,
  addCaBundle:         addCaBundle,
  useSystemTrust:      useSystemTrust,
  isSystemTrustEnabled: isSystemTrustEnabled,
  getTrustStore:       getTrustStore,
  captureBaselineFingerprints: captureBaselineFingerprints,
  detectBaselineDrift: detectBaselineDrift,
  applyToContext:      applyToContext,
  getCaPems:           getCaPems,
  TlsTrustError:       TlsTrustError,
  _resetForTest:       _resetForTest,
};
