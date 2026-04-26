"use strict";
/**
 * Storage abstraction — multi-backend, classification-routed, residency-
 * enforced file storage with per-file vault-sealed encryption.
 *
 * Two configuration shapes (both supported, internally normalized to
 * the multi-backend form):
 *
 *   1. Single-backend (legacy shape — preserved):
 *        storage.init({ backend: 'local', uploadDir: './data/uploads' })
 *
 *   2. Multi-backend:
 *        storage.init({
 *          backends: {
 *            'eu-private': { protocol: 'http-put', baseUrl: '...',
 *                            classifications: ['personal'], residencyTag: 'EU' },
 *            'us-ops':     { protocol: 'local', rootDir: '/data/ops',
 *                            classifications: ['operational', 'public'],
 *                            residencyTag: 'US' },
 *          },
 *          defaultClassification: 'personal',
 *          refuseUnclassified:    true,
 *        });
 *
 * Classification routing (per-call):
 *   storage.saveFile(buf, 'invoice.pdf', { classification: 'personal' })
 *     → routes to a backend whose `classifications` includes 'personal'.
 *   storage.saveFile(buf, 'logo.png', { backend: 'us-ops' })
 *     → explicit backend; framework still validates the backend serves
 *        the classification.
 *
 * Residency enforcement (boot-time):
 *   - If db.getDataResidency() declares a region, every backend serving the
 *     'personal' classification must have residencyTag === region (or be
 *     listed in dataResidency.allowedStorageRegions).
 *   - Refuses to boot otherwise — catches operator misconfiguration where
 *     a US-region backend was configured for personal data in an EU app.
 *
 * Audit hooks:
 *   - Every saveFile records a 'system.storage.write' event with metadata
 *     { backend, classification, residencyTag, sizeBytes }.
 *   - getFile records 'system.storage.read'.
 *   - delete records 'system.storage.delete'.
 *
 * Public API (sync entry, async ops since backends may be remote):
 *   storage.init(opts)                                            (sync)
 *   storage.saveFile(buffer, key, opts?)        async →  { storedPath, encryptionKey, backend, classification }
 *   storage.getFileBuffer(storedPath, sealedKey, opts?) async → Buffer
 *   storage.getFileStream(storedPath, sealedKey, opts?) async → Readable
 *   storage.saveRaw(buffer, key, opts?)         async → { storedPath, backend }
 *   storage.getRawBuffer(storedPath, opts?)     async → Buffer
 *   storage.deleteFile(storedPath, opts?)       async → boolean
 *   storage.exists(storedPath, opts?)           async → boolean
 *   storage.listBackends()                              → [{ name, protocol, classifications, residencyTag }]
 *   storage.getBackend(name)                            → backend instance (or null)
 */
var path = require("path");
var { generateBytes, encryptPacked, decryptPacked } = require("./crypto");
var objectStore = require("./object-store");

var _vault = null;
function vault() { if (!_vault) _vault = require("./vault"); return _vault; }

var _audit = null;
function audit() { if (!_audit) _audit = require("./audit"); return _audit; }

var _db = null;
function db() { if (!_db) _db = require("./db"); return _db; }

var initialized = false;
var backends = {};                    // name → backend instance from object-store
var defaultClassification = null;
var refuseUnclassified = false;

function _err(code, message, permanent) {
  var e = new Error(message);
  e.code = code;
  e.permanent = !!permanent;
  e.isStorageError = true;
  return e;
}

// ---- Init ----

function init(opts) {
  if (initialized) return;
  if (!opts) throw new Error("storage.init() requires options");

  // Normalize single-backend config into multi-backend form
  var normalized = _normalizeConfig(opts);

  defaultClassification = normalized.defaultClassification;
  refuseUnclassified    = !!normalized.refuseUnclassified;

  backends = {};
  for (var name in normalized.backends) {
    var cfg = Object.assign({}, normalized.backends[name], { name: name });
    backends[name] = objectStore.buildBackend(cfg);
  }

  // Boot-time residency validation
  _validateResidency();

  initialized = true;
}

function _normalizeConfig(opts) {
  if (opts.backends) {
    return {
      backends:              opts.backends,
      defaultClassification: opts.defaultClassification || null,
      refuseUnclassified:    !!opts.refuseUnclassified,
    };
  }
  // Single-backend syntax: { backend, uploadDir, ... }
  if (opts.backend) {
    if (opts.backend === "s3") {
      throw new Error(
        "storage backend 's3' is now spelled 'sigv4' (covers AWS S3, R2, B2, " +
        "MinIO, Wasabi, Tigris, DO Spaces, IDrive e2, Storj, Linode). " +
        "Use { backend: 'sigv4', endpoint, region, bucket, accessKeyId, secretAccessKey }."
      );
    }
    if (opts.backend === "local") {
      return {
        backends: {
          "default": {
            protocol:        "local",
            rootDir:         opts.uploadDir,
            classifications: ["*"],
            residencyTag:    "unrestricted",
          },
        },
        defaultClassification: null,
        refuseUnclassified:    false,
      };
    }
    if (opts.backend === "http-put" || opts.backend === "sigv4" || opts.backend === "gcs" || opts.backend === "azure-blob") {
      // Forward as-is; user provided a single-backend spec for a remote protocol
      return {
        backends: { "default": Object.assign({}, opts, { name: undefined }) },
        defaultClassification: null,
        refuseUnclassified:    false,
      };
    }
    throw new Error("storage.init: unknown backend '" + opts.backend + "'");
  }
  throw new Error("storage.init: must provide either { backend } or { backends }");
}

function _validateResidency() {
  var residency;
  try { residency = db().getDataResidency(); } catch (_e) { residency = null; }
  if (!residency || !residency.region) return;

  var allowed = [residency.region].concat(residency.allowedStorageRegions || []);

  for (var name in backends) {
    var b = backends[name];
    var serves = b.classifications.indexOf("*") !== -1 || b.classifications.indexOf("personal") !== -1;
    if (!serves) continue;
    if (allowed.indexOf(b.residencyTag) === -1) {
      throw _err(
        "RESIDENCY_VIOLATION",
        "backend '" + name + "' serves 'personal' data with residencyTag '" + b.residencyTag +
        "' but app's dataResidency.region is '" + residency.region + "' (allowed: " + allowed.join(", ") + ")",
        true
      );
    }
  }

  // If defaultClassification is 'personal', confirm at least one backend serves it
  if (defaultClassification === "personal") {
    var found = false;
    for (var n in backends) {
      if (backends[n].servesClassification("personal")) { found = true; break; }
    }
    if (!found) {
      throw _err("NO_PERSONAL_BACKEND",
        "defaultClassification='personal' but no backend declares 'personal' in classifications", true);
    }
  }
}

// ---- Backend selection ----

function _pickBackend(opts) {
  opts = opts || {};
  if (opts.backend) {
    var b = backends[opts.backend];
    if (!b) throw _err("UNKNOWN_BACKEND", "no backend named '" + opts.backend + "'", true);
    if (opts.classification && !b.servesClassification(opts.classification)) {
      throw _err("CLASSIFICATION_MISMATCH",
        "backend '" + opts.backend + "' does not serve classification '" + opts.classification + "'", true);
    }
    return { backend: b, classification: opts.classification || null };
  }

  // refuseUnclassified forces every call to declare classification explicitly,
  // even when defaultClassification is configured. The default is for
  // convenience; refuseUnclassified is for explicit boundary enforcement.
  if (refuseUnclassified && !opts.classification) {
    throw _err("UNCLASSIFIED",
      "saveFile requires { classification } (or set { backend } explicitly); " +
      "framework is configured with refuseUnclassified: true", true);
  }
  var classification = opts.classification || defaultClassification;
  if (!classification) {
    // No classification + no refusal → pick any backend
    for (var n in backends) return { backend: backends[n], classification: null };
    throw _err("NO_BACKENDS", "no backends configured", true);
  }

  for (var name in backends) {
    if (backends[name].servesClassification(classification)) {
      return { backend: backends[name], classification: classification };
    }
  }
  throw _err("NO_BACKEND_FOR_CLASSIFICATION",
    "no backend serves classification '" + classification + "'", true);
}

// ---- File encryption helpers ----

function _encryptBuffer(buffer) {
  var key = generateBytes(32);
  var packed = encryptPacked(buffer, key);
  var sealedKey = vault().seal(key.toString("base64"));
  return { data: packed, encryptionKey: sealedKey };
}

function _decryptBuffer(packed, sealedKey) {
  if (!sealedKey) {
    throw _err("KEY_REQUIRED", "encryptionKey is required (no legacy plaintext support)", true);
  }
  var key = Buffer.from(vault().unseal(sealedKey), "base64");
  return decryptPacked(packed, key);
}

// ---- Audit emission ----

function _emit(action, info) {
  try {
    audit().emit({
      actor:    info.actor || {},
      action:   action,
      resource: info.resource || null,
      outcome:  info.outcome || "success",
      reason:   info.reason || null,
      metadata: info.metadata || null,
      requestId: info.requestId || null,
    });
  } catch (_e) {
    // Audit must never block storage operations. Log nothing — caller's
    // application will see the storage call succeed/fail; the missing
    // audit entry shows up at next chain verify if it indicates corruption.
  }
}

// ---- Public API ----

async function saveFile(buffer, key, opts) {
  _requireInit();
  if (!Buffer.isBuffer(buffer)) throw _err("INVALID_BODY", "saveFile body must be a Buffer", true);
  opts = opts || {};
  var picked = _pickBackend(opts);
  var enc = _encryptBuffer(buffer);
  var result = await picked.backend.put(key, enc.data, opts);
  _emit("system.storage.write", {
    metadata: {
      backend:        picked.backend.name,
      classification: picked.classification,
      residencyTag:   picked.backend.residencyTag,
      key:            key,
      sizeBytes:      result.size != null ? result.size : enc.data.length,
    },
  });
  return {
    storedPath:    key,
    encryptionKey: enc.encryptionKey,
    backend:       picked.backend.name,
    classification: picked.classification,
  };
}

async function getFileBuffer(key, sealedKey, opts) {
  _requireInit();
  opts = opts || {};
  var picked = _pickBackend(opts);
  var packed = await picked.backend.get(key);
  var decrypted = _decryptBuffer(packed, sealedKey);
  _emit("system.storage.read", {
    metadata: {
      backend: picked.backend.name,
      key:     key,
      sizeBytes: decrypted.length,
    },
  });
  return decrypted;
}

async function getFileStream(key, sealedKey, opts) {
  // Buffer-then-stream: per-file XChaCha20 encryption needs the whole
  // ciphertext to verify the AEAD tag before any plaintext can be released
  // to the consumer. Chunked-encryption with per-chunk AEAD would let us
  // stream end-to-end, but at the cost of finer-grained tampering windows.
  var buf = await getFileBuffer(key, sealedKey, opts);
  return require("stream").Readable.from(buf);
}

async function saveRaw(buffer, key, opts) {
  _requireInit();
  if (!Buffer.isBuffer(buffer)) throw _err("INVALID_BODY", "saveRaw body must be a Buffer", true);
  opts = opts || {};
  var picked = _pickBackend(opts);
  var result = await picked.backend.put(key, buffer, opts);
  _emit("system.storage.write", {
    metadata: {
      backend:        picked.backend.name,
      classification: picked.classification,
      residencyTag:   picked.backend.residencyTag,
      key:            key,
      sizeBytes:      result.size != null ? result.size : buffer.length,
      raw:            true,
    },
  });
  return { storedPath: key, backend: picked.backend.name };
}

async function getRawBuffer(key, opts) {
  _requireInit();
  opts = opts || {};
  var picked = _pickBackend(opts);
  return picked.backend.get(key);
}

async function deleteFile(key, opts) {
  _requireInit();
  opts = opts || {};
  var picked = _pickBackend(opts);
  var result = await picked.backend.delete(key);
  _emit("system.storage.delete", {
    metadata: {
      backend: picked.backend.name,
      key:     key,
      existed: result,
    },
  });
  return result;
}

async function exists(key, opts) {
  _requireInit();
  opts = opts || {};
  var picked = _pickBackend(opts);
  try {
    await picked.backend.head(key);
    return true;
  } catch (e) {
    if (e && e.code === "NOT_FOUND") return false;
    throw e;
  }
}

function listBackends() {
  _requireInit();
  var out = [];
  for (var name in backends) {
    out.push({
      name:            name,
      protocol:        backends[name].protocol,
      classifications: backends[name].classifications.slice(),
      residencyTag:    backends[name].residencyTag,
      breakerState:    backends[name].breaker.getState(),
    });
  }
  return out;
}

function getBackend(name) {
  _requireInit();
  return backends[name] || null;
}

function _requireInit() {
  if (!initialized) throw _err("NOT_INITIALIZED", "storage.init() must be called before any file operation", true);
}

function _resetForTest() {
  initialized = false;
  backends = {};
  defaultClassification = null;
  refuseUnclassified = false;
  _vault = null;
  _audit = null;
  _db = null;
}

module.exports = {
  init:           init,
  saveFile:       saveFile,
  getFileBuffer:  getFileBuffer,
  getFileStream:  getFileStream,
  saveRaw:        saveRaw,
  getRawBuffer:   getRawBuffer,
  deleteFile:     deleteFile,
  exists:         exists,
  listBackends:   listBackends,
  getBackend:     getBackend,
  _resetForTest:  _resetForTest,
};
