"use strict";
/**
 * Object-store dispatcher — protocol-agnostic remote (and local) storage.
 *
 * The framework's storage abstraction (lib/storage.js) routes per-classification
 * requests to one or more configured backends. Each backend is constructed
 * here from a config object that picks a protocol and provides its options:
 *
 *   protocol: 'local'                   → lib/object-store/local.js
 *   protocol: 'http-put'                → lib/object-store/http-put.js
 *   protocol: 'sigv4'  (S3 / R2 / B2 / MinIO / Wasabi / Tigris / DO Spaces /
 *                       IDrive e2 / Linode Object Storage / Storj / etc.)
 *                                       → lib/object-store/sigv4.js
 *   protocol: 'gcs'    (Google Cloud Storage native — HMAC + native API)
 *                                       → lib/object-store/gcs.js
 *   protocol: 'azure-blob'              → lib/object-store/azure-blob.js
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
var localProto      = require("./local");
var httpPutProto    = require("./http-put");
var sigv4Proto      = require("./sigv4");
var sigv4BucketOps  = require("./sigv4-bucket-ops");
var gcsProto        = require("./gcs");
var azureBlobProto  = require("./azure-blob");
var retryHelper     = require("./retry");
var protocolDispatcher = require("../protocol-dispatcher");
var { ObjectStoreError } = require("../framework-error");

// All currently advertised protocols are bundled. The dispatcher's
// `deferred` slot is the hook for adding deferred ones later.
var dispatcher = protocolDispatcher.create({
  name:       "object-store",
  errorClass: ObjectStoreError,
  protocols: {
    "local":      localProto,
    "http-put":   httpPutProto,
    "sigv4":      sigv4Proto,
    "gcs":        gcsProto,
    "azure-blob": azureBlobProto,
  },
  deferred:         {},
  fallbackProtocol: "local",
});

var _err = ObjectStoreError.factory;

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
  if (!config) {
    throw new Error("object-store backend requires { protocol }");
  }
  var proto = dispatcher.resolve(config.protocol);
  var raw = proto.create(config);

  // Validate classifications + residencyTag
  var classifications = Array.isArray(config.classifications) && config.classifications.length > 0
    ? config.classifications.slice()
    : ["*"];   // wildcard: backend serves any classification
  var residencyTag = config.residencyTag || "unrestricted";

  // Wrap protocol calls with retry + circuit breaker
  var breaker = new retryHelper.CircuitBreaker(
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
      return retryHelper.withRetry(function () {
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
    // presigned*Url are sync URL-builders (no network call), so they
    // bypass retry + circuit-breaker — propagate any throw directly.
    presignedUploadUrl: typeof raw.presignedUploadUrl === "function"
      ? raw.presignedUploadUrl.bind(raw) : null,
    presignedDownloadUrl: typeof raw.presignedDownloadUrl === "function"
      ? raw.presignedDownloadUrl.bind(raw) : null,
    presignedUploadPolicy: typeof raw.presignedUploadPolicy === "function"
      ? raw.presignedUploadPolicy.bind(raw) : null,
    servesClassification: function (cls) {
      return classifications.indexOf("*") !== -1 || classifications.indexOf(cls) !== -1;
    },
  };
}

module.exports = {
  buildBackend:        buildBackend,
  PROTOCOLS:           dispatcher.protocols,
  DEFERRED_PROTOCOLS:  dispatcher.deferred,
  // Bucket-level (lifecycle / CORS / create / delete / list) ops are
  // service-scoped, not bucket-scoped — they get their own factory.
  // SigV4 only; GCS / Azure bucket lifecycle differs substantially per
  // cloud and is operator-managed (Terraform / CDK / Pulumi).
  bucketOps:           sigv4BucketOps,
};
