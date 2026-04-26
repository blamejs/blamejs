"use strict";
/**
 * Object-store dispatcher — protocol-agnostic remote (and local) storage.
 *
 * The framework's storage abstraction (lib/storage.js) routes per-classification
 * requests to one or more configured backends. Each backend is constructed
 * here from a config object that picks a protocol and provides its options:
 *
 *   protocol: 'local'                   → lib/object-store-local.js
 *   protocol: 'http-put'                → lib/object-store-http-put.js
 *   protocol: 'sigv4'  (S3 / R2 / B2 / MinIO / Wasabi / Tigris / DO Spaces /
 *                       IDrive e2 / Linode Object Storage / Storj / etc.)
 *                                       → lib/object-store-sigv4.js (v0.0.10)
 *   protocol: 'gcs'    (Google Cloud Storage native — HMAC + native API)
 *                                       → v0.0.11+
 *   protocol: 'azure-blob'              → v0.0.11+
 *
 * Every backend is wrapped with retry + circuit-breaker so transient
 * failures don't surface as call-site errors and persistent failures
 * don't pile up retry storms.
 *
 * Common API across protocols:
 *   put(key, body, opts?)       → { size, etag? }
 *   get(key)                    → Buffer
 *   getStream(key)              → Readable
 *   head(key)                   → { size, etag?, lastModified? }
 *   delete(key)                 → boolean (true if deleted, false if missing)
 *   list(prefix, opts?)         → { items: [{ key, size, lastModified }], truncated }
 */
var localProto    = require("./object-store-local");
var httpPutProto  = require("./object-store-http-put");
var sigv4Proto    = require("./object-store-sigv4");
var retry         = require("./object-store-retry");

var PROTOCOLS = {
  "local":    localProto,
  "http-put": httpPutProto,
  "sigv4":    sigv4Proto,
};

function _err(code, message, permanent) {
  var e = new Error(message);
  e.code = code;
  e.permanent = !!permanent;
  e.isObjectStoreError = true;
  return e;
}

// Lazy-resolve protocols not bundled in v0.0.9 — clear "not yet implemented"
// message rather than a confusing "unknown protocol" trap.
var DEFERRED_PROTOCOLS = {
  "gcs":        { since: "v0.0.11", description: "Google Cloud Storage (native HMAC + native API)" },
  "azure-blob": { since: "v0.0.11", description: "Azure Blob Storage (shared-key auth)" },
};

/**
 * Build a backend instance from a backend config block.
 *
 * config:
 *   {
 *     protocol:        'local' | 'http-put' | 'sigv4' | 'gcs' | 'azure-blob',
 *     // protocol-specific config (rootDir for local, baseUrl for http-put, etc.)
 *     classifications: ['personal' | 'operational' | 'public' | <custom>],
 *     residencyTag:    'EU' | 'US' | 'UK' | 'CA' | 'unrestricted' | <custom>,
 *     retry:           { maxAttempts, baseDelayMs, maxDelayMs, jitterFactor },
 *     breaker:         { failureThreshold, cooldownMs, successThreshold },
 *     name:            <stable-id-for-circuit-breaker>,
 *   }
 */
function buildBackend(config) {
  if (!config || !config.protocol) {
    throw new Error("object-store backend requires { protocol }");
  }
  if (DEFERRED_PROTOCOLS[config.protocol]) {
    var d = DEFERRED_PROTOCOLS[config.protocol];
    throw _err(
      "PROTOCOL_NOT_IMPLEMENTED",
      "object-store protocol '" + config.protocol + "' is deferred to " + d.since +
      " (" + d.description + "). Use protocol: 'local' or 'http-put' for now.",
      true
    );
  }
  var proto = PROTOCOLS[config.protocol];
  if (!proto) {
    throw _err("UNKNOWN_PROTOCOL", "unknown object-store protocol: '" + config.protocol + "'", true);
  }

  var raw = proto.create(config);

  // Validate classifications + residencyTag
  var classifications = Array.isArray(config.classifications) && config.classifications.length > 0
    ? config.classifications.slice()
    : ["*"];   // wildcard: backend serves any classification
  var residencyTag = config.residencyTag || "unrestricted";

  // Wrap protocol calls with retry + circuit breaker
  var breaker = new retry.CircuitBreaker(
    config.name || (config.protocol + ":" + (raw.rootDir || raw.baseUrl || "anonymous")),
    config.breaker
  );

  function wrap(name) {
    var inner = raw[name];
    if (typeof inner !== "function") return inner;
    return function () {
      var args = Array.prototype.slice.call(arguments);
      // For sync methods (getStream returns a Readable directly, not a Promise):
      if (name === "getStream") {
        // Apply circuit breaker only — getStream is sync, retry doesn't apply.
        // The Readable will surface its own errors as the consumer reads it.
        return inner.apply(raw, args);
      }
      return retry.withRetry(function () {
        return breaker.wrap(function () {
          return inner.apply(raw, args);
        });
      }, config.retry);
    };
  }

  return {
    name:            config.name || config.protocol,
    protocol:        config.protocol,
    classifications: classifications,
    residencyTag:    residencyTag,
    breaker:         breaker,
    raw:             raw,
    put:             wrap("put"),
    get:             wrap("get"),
    getStream:       wrap("getStream"),
    head:            wrap("head"),
    delete:          wrap("delete"),
    list:            wrap("list"),
    servesClassification: function (cls) {
      return classifications.indexOf("*") !== -1 || classifications.indexOf(cls) !== -1;
    },
  };
}

module.exports = {
  buildBackend:        buildBackend,
  PROTOCOLS:           Object.keys(PROTOCOLS),
  DEFERRED_PROTOCOLS:  DEFERRED_PROTOCOLS,
};
