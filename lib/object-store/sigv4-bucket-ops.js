"use strict";
/**
 * sigv4-bucket-ops — bucket-level operations for SigV4 backends.
 *
 * Per-object ops (put / get / list / delete / multipart) live in
 * lib/object-store/sigv4.js and are bound to a single bucket at
 * create() time. Bucket lifecycle ops are at a different level —
 * they need a service-scoped client that addresses arbitrary
 * buckets — so they get their own factory.
 *
 * Operators with multi-cloud ambitions reach for Terraform / CDK /
 * Pulumi. The framework's bucket-ops surface is the operator-from-app
 * path: create the bucket your app needs at boot, attach a lifecycle
 * rule that aborts incomplete multiparts after a week, etc. Niche ops
 * (Object Lock, Replication, Inventory, Notification) are deferred —
 * they're well into Terraform territory.
 *
 * Public API:
 *
 *   var ops = b.objectStore.bucketOps.create({
 *     protocol:        "sigv4",
 *     region:          "us-east-1",
 *     accessKeyId:     env("AWS_ACCESS_KEY_ID"),
 *     secretAccessKey: env("AWS_SECRET_ACCESS_KEY"),
 *     endpoint:        "https://s3.us-east-1.amazonaws.com",  // optional
 *     pathStyle:       false,
 *     timeoutMs:       30000,
 *   });
 *
 *   await ops.create("my-bucket", { region: "eu-west-1" });
 *   await ops.delete("my-bucket");
 *   var buckets = await ops.list();          // [{ name, creationDate }]
 *   await ops.setLifecycle("my-bucket", [{
 *     id:     "abort-stale-multiparts",
 *     status: "Enabled",
 *     prefix: "",
 *     abortIncompleteMultipartUpload: { daysAfterInitiation: 7 },
 *   }]);
 *   await ops.setCorsRules("my-bucket", [{
 *     allowedOrigins: ["https://app.example.com"],
 *     allowedMethods: ["GET", "PUT", "POST"],
 *     allowedHeaders: ["*"],
 *     exposeHeaders:  ["ETag"],
 *     maxAgeSeconds:  3600,
 *   }]);
 *
 * Validation rejects every bad input shape at the call site rather
 * than producing a server-side 400. Errors surface as ObjectStoreError
 * with codes (BUCKET_INVALID_NAME, INVALID_LIFECYCLE, INVALID_CORS_RULE,
 * BUCKET_ALREADY_OWNED, BUCKET_NOT_EMPTY, etc.).
 */
var { URL } = require("url");
var nodeCrypto = require("crypto");
var C = require("../constants");
var sigv4 = require("./sigv4");
var safeXml = require("../parsers/safe-xml");
var safeUrl = require("../safe-url");
var template = require("../template");
var httpClient = require("../http-client");
var { ObjectStoreError } = require("../framework-error");

var _err = ObjectStoreError.factory;

// S3 bucket-name rules (general purpose). Source: AWS docs
// "Bucket naming rules". Lowercase letters, digits, hyphens; 3..63
// chars; no consecutive dots; cannot end in -s3alias / -ol-s3 etc.
// We catch the common-mistake cases at config time; AWS catches the
// rest at request time.
var BUCKET_NAME_RE = /^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/;

function _validateBucketName(name) {
  if (typeof name !== "string" || name.length < 3 || name.length > 63) {
    throw _err("BUCKET_INVALID_NAME",
      "bucket name must be a string of length 3..63, got " +
      (typeof name === "string" ? "length " + name.length : typeof name), true);
  }
  if (!BUCKET_NAME_RE.test(name)) {
    throw _err("BUCKET_INVALID_NAME",
      "bucket name '" + name + "' violates S3 naming rules " +
      "(lowercase, digits, hyphens, dots — no leading/trailing punct)", true);
  }
  if (name.indexOf("..") !== -1) {
    throw _err("BUCKET_INVALID_NAME",
      "bucket name '" + name + "' contains consecutive dots", true);
  }
}

// XML body strings flow through template.escapeHtml — `&#x27;` (which
// it emits for the apostrophe) is a numeric character reference and
// is valid in both XML and HTML, where `&apos;` is XML-only. AWS S3
// accepts both; using the shared HTML escape keeps the framework
// down to one canonical escape primitive.
var _xmlEscape = template.escapeHtml;

// AWS PutBucketLifecycle / PutBucketCors require a Content-MD5 header
// for body integrity (legacy AWS API requirement; SigV4 already covers
// integrity via x-amz-content-sha256 but the API still validates this).
// MD5 here is NOT a credential or security primitive — it's an AWS API
// shape. b.credentialHash is the wrong tool.
function _md5Base64(buf) {
  return nodeCrypto.createHash("md5").update(buf).digest("base64");
}

// ---- Lifecycle XML ----

var ALLOWED_STORAGE_CLASSES = [
  "STANDARD", "REDUCED_REDUNDANCY", "STANDARD_IA", "ONEZONE_IA",
  "INTELLIGENT_TIERING", "GLACIER", "DEEP_ARCHIVE", "GLACIER_IR",
  "EXPRESS_ONEZONE",
];

function _buildLifecycleXml(rules) {
  if (!Array.isArray(rules) || rules.length === 0) {
    throw _err("INVALID_LIFECYCLE",
      "setLifecycle: rules must be a non-empty array", true);
  }
  if (rules.length > 1000) {
    throw _err("INVALID_LIFECYCLE",
      "setLifecycle: maximum 1000 rules per bucket (S3 spec)", true);
  }
  var body = '<?xml version="1.0" encoding="UTF-8"?>';
  body += '<LifecycleConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">';
  for (var i = 0; i < rules.length; i++) {
    var rule = rules[i];
    if (!rule || typeof rule !== "object") {
      throw _err("INVALID_LIFECYCLE",
        "rules[" + i + "] must be an object", true);
    }
    var status = rule.status || "Enabled";
    if (status !== "Enabled" && status !== "Disabled") {
      throw _err("INVALID_LIFECYCLE",
        "rules[" + i + "].status must be 'Enabled' or 'Disabled'", true);
    }
    if (!rule.expiration && !rule.transition && !rule.abortIncompleteMultipartUpload) {
      throw _err("INVALID_LIFECYCLE",
        "rules[" + i + "] must specify at least one of " +
        "expiration / transition / abortIncompleteMultipartUpload", true);
    }
    body += "<Rule>";
    if (rule.id !== undefined) {
      if (typeof rule.id !== "string" || rule.id.length === 0) {
        throw _err("INVALID_LIFECYCLE",
          "rules[" + i + "].id must be a non-empty string when set", true);
      }
      body += "<ID>" + _xmlEscape(rule.id) + "</ID>";
    }
    body += "<Filter><Prefix>" + _xmlEscape(rule.prefix || "") + "</Prefix></Filter>";
    body += "<Status>" + status + "</Status>";
    if (rule.expiration) {
      body += "<Expiration>";
      if (rule.expiration.days !== undefined) {
        if (typeof rule.expiration.days !== "number" || rule.expiration.days < 1) {
          throw _err("INVALID_LIFECYCLE",
            "rules[" + i + "].expiration.days must be a positive integer", true);
        }
        body += "<Days>" + rule.expiration.days + "</Days>";
      }
      if (rule.expiration.date !== undefined) {
        body += "<Date>" + _xmlEscape(rule.expiration.date) + "</Date>";
      }
      if (rule.expiration.expiredObjectDeleteMarker !== undefined) {
        body += "<ExpiredObjectDeleteMarker>" +
          (rule.expiration.expiredObjectDeleteMarker ? "true" : "false") +
          "</ExpiredObjectDeleteMarker>";
      }
      body += "</Expiration>";
    }
    if (rule.transition) {
      if (ALLOWED_STORAGE_CLASSES.indexOf(rule.transition.storageClass) === -1) {
        throw _err("INVALID_LIFECYCLE",
          "rules[" + i + "].transition.storageClass must be one of: " +
          ALLOWED_STORAGE_CLASSES.join(", "), true);
      }
      body += "<Transition>";
      if (rule.transition.days !== undefined) {
        body += "<Days>" + rule.transition.days + "</Days>";
      }
      if (rule.transition.date !== undefined) {
        body += "<Date>" + _xmlEscape(rule.transition.date) + "</Date>";
      }
      body += "<StorageClass>" + rule.transition.storageClass + "</StorageClass>";
      body += "</Transition>";
    }
    if (rule.abortIncompleteMultipartUpload) {
      var dai = rule.abortIncompleteMultipartUpload.daysAfterInitiation;
      if (typeof dai !== "number" || dai < 1) {
        throw _err("INVALID_LIFECYCLE",
          "rules[" + i + "].abortIncompleteMultipartUpload.daysAfterInitiation " +
          "must be a positive integer", true);
      }
      body += "<AbortIncompleteMultipartUpload>";
      body += "<DaysAfterInitiation>" + dai + "</DaysAfterInitiation>";
      body += "</AbortIncompleteMultipartUpload>";
    }
    body += "</Rule>";
  }
  body += "</LifecycleConfiguration>";
  return body;
}

// ---- CORS XML ----

var ALLOWED_CORS_METHODS = ["GET", "PUT", "POST", "DELETE", "HEAD"];

function _buildCorsXml(rules) {
  if (!Array.isArray(rules) || rules.length === 0) {
    throw _err("INVALID_CORS_RULE",
      "setCorsRules: rules must be a non-empty array", true);
  }
  if (rules.length > 100) {
    throw _err("INVALID_CORS_RULE",
      "setCorsRules: maximum 100 rules per bucket (S3 spec)", true);
  }
  var body = '<?xml version="1.0" encoding="UTF-8"?>';
  body += '<CORSConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">';
  for (var i = 0; i < rules.length; i++) {
    var rule = rules[i];
    if (!rule || typeof rule !== "object") {
      throw _err("INVALID_CORS_RULE",
        "rules[" + i + "] must be an object", true);
    }
    if (!Array.isArray(rule.allowedOrigins) || rule.allowedOrigins.length === 0) {
      throw _err("INVALID_CORS_RULE",
        "rules[" + i + "].allowedOrigins must be a non-empty array", true);
    }
    if (!Array.isArray(rule.allowedMethods) || rule.allowedMethods.length === 0) {
      throw _err("INVALID_CORS_RULE",
        "rules[" + i + "].allowedMethods must be a non-empty array", true);
    }
    for (var m = 0; m < rule.allowedMethods.length; m++) {
      if (ALLOWED_CORS_METHODS.indexOf(rule.allowedMethods[m]) === -1) {
        throw _err("INVALID_CORS_RULE",
          "rules[" + i + "].allowedMethods[" + m + "] must be one of: " +
          ALLOWED_CORS_METHODS.join(", "), true);
      }
    }
    body += "<CORSRule>";
    if (rule.id !== undefined) body += "<ID>" + _xmlEscape(rule.id) + "</ID>";
    rule.allowedOrigins.forEach(function (o) {
      body += "<AllowedOrigin>" + _xmlEscape(o) + "</AllowedOrigin>";
    });
    rule.allowedMethods.forEach(function (m) {
      body += "<AllowedMethod>" + _xmlEscape(m) + "</AllowedMethod>";
    });
    if (Array.isArray(rule.allowedHeaders)) {
      rule.allowedHeaders.forEach(function (h) {
        body += "<AllowedHeader>" + _xmlEscape(h) + "</AllowedHeader>";
      });
    }
    if (Array.isArray(rule.exposeHeaders)) {
      rule.exposeHeaders.forEach(function (h) {
        body += "<ExposeHeader>" + _xmlEscape(h) + "</ExposeHeader>";
      });
    }
    if (rule.maxAgeSeconds !== undefined) {
      if (typeof rule.maxAgeSeconds !== "number" || rule.maxAgeSeconds < 0) {
        throw _err("INVALID_CORS_RULE",
          "rules[" + i + "].maxAgeSeconds must be a non-negative number", true);
      }
      body += "<MaxAgeSeconds>" + rule.maxAgeSeconds + "</MaxAgeSeconds>";
    }
    body += "</CORSRule>";
  }
  body += "</CORSConfiguration>";
  if (Buffer.byteLength(body, "utf8") > C.BYTES.kib(64)) {
    throw _err("INVALID_CORS_RULE",
      "CORS configuration exceeds 64 KB (S3 spec)", true);
  }
  return body;
}

// ---- Object Lock + Retention + LegalHold validators / XML ----

var OBJECT_LOCK_MODES = ["GOVERNANCE", "COMPLIANCE"];
var LEGAL_HOLD_STATES = ["ON", "OFF"];

function _validateObjectLockConfig(cfg) {
  if (!cfg || typeof cfg !== "object") {
    throw _err("INVALID_OBJECT_LOCK",
      "setObjectLockConfiguration: opts must be an object " +
      "with { mode, days|years }", true);
  }
  if (OBJECT_LOCK_MODES.indexOf(cfg.mode) === -1) {
    throw _err("INVALID_OBJECT_LOCK",
      "mode must be one of " + OBJECT_LOCK_MODES.join(", ") +
      "; got " + JSON.stringify(cfg.mode), true);
  }
  var hasDays  = cfg.days  != null;
  var hasYears = cfg.years != null;
  if (hasDays && hasYears) {
    throw _err("INVALID_OBJECT_LOCK",
      "specify either days OR years, not both (S3 rule)", true);
  }
  if (!hasDays && !hasYears) {
    throw _err("INVALID_OBJECT_LOCK",
      "default retention requires days or years", true);
  }
  if (hasDays) {
    if (typeof cfg.days !== "number" || !Number.isInteger(cfg.days) ||
        cfg.days <= 0) {
      throw _err("INVALID_OBJECT_LOCK",
        "days must be a positive integer; got " + JSON.stringify(cfg.days), true);
    }
  } else {
    if (typeof cfg.years !== "number" || !Number.isInteger(cfg.years) ||
        cfg.years <= 0) {
      throw _err("INVALID_OBJECT_LOCK",
        "years must be a positive integer; got " + JSON.stringify(cfg.years), true);
    }
  }
}

function _buildObjectLockConfigXml(cfg) {
  var body = '<?xml version="1.0" encoding="UTF-8"?>';
  body += '<ObjectLockConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">';
  body += '<ObjectLockEnabled>Enabled</ObjectLockEnabled>';
  body += '<Rule><DefaultRetention>';
  body += '<Mode>' + cfg.mode + '</Mode>';
  if (cfg.days != null)  body += '<Days>'  + cfg.days  + '</Days>';
  if (cfg.years != null) body += '<Years>' + cfg.years + '</Years>';
  body += '</DefaultRetention></Rule>';
  body += '</ObjectLockConfiguration>';
  return body;
}

function _validateRetention(opts) {
  if (!opts || typeof opts !== "object") {
    throw _err("INVALID_RETENTION",
      "setObjectRetention: opts must be an object " +
      "with { mode, retainUntil }", true);
  }
  if (OBJECT_LOCK_MODES.indexOf(opts.mode) === -1) {
    throw _err("INVALID_RETENTION",
      "mode must be one of " + OBJECT_LOCK_MODES.join(", ") +
      "; got " + JSON.stringify(opts.mode), true);
  }
  if (!(opts.retainUntil instanceof Date) || isNaN(opts.retainUntil.getTime())) {
    throw _err("INVALID_RETENTION",
      "retainUntil must be a valid Date instance", true);
  }
  if (opts.retainUntil.getTime() <= Date.now()) {
    throw _err("INVALID_RETENTION",
      "retainUntil must be in the future", true);
  }
}

function _buildRetentionXml(opts) {
  return '<?xml version="1.0" encoding="UTF-8"?>' +
         '<Retention xmlns="http://s3.amazonaws.com/doc/2006-03-01/">' +
         '<Mode>' + opts.mode + '</Mode>' +
         '<RetainUntilDate>' + opts.retainUntil.toISOString() + '</RetainUntilDate>' +
         '</Retention>';
}

function _validateLegalHoldStatus(status) {
  if (LEGAL_HOLD_STATES.indexOf(status) === -1) {
    throw _err("INVALID_LEGAL_HOLD",
      "legal-hold status must be one of " + LEGAL_HOLD_STATES.join(", ") +
      "; got " + JSON.stringify(status), true);
  }
}

function _buildLegalHoldXml(status) {
  return '<?xml version="1.0" encoding="UTF-8"?>' +
         '<LegalHold xmlns="http://s3.amazonaws.com/doc/2006-03-01/">' +
         '<Status>' + status + '</Status>' +
         '</LegalHold>';
}

function _validateObjectKey(key) {
  if (typeof key !== "string" || key.length === 0) {
    throw _err("INVALID_KEY", "object key must be a non-empty string", true);
  }
  if (key.length > 1024) {
    throw _err("INVALID_KEY", "object key exceeds 1024 bytes (S3 limit)", true);
  }
}

// ---- Public factory ----

function create(config) {
  if (!config || typeof config !== "object") {
    throw _err("INVALID_CONFIG", "bucketOps.create requires a config object", true);
  }
  if (config.protocol && config.protocol !== "sigv4") {
    throw _err("INVALID_CONFIG",
      "bucketOps currently only supports protocol 'sigv4'; got '" +
      config.protocol + "'. GCS and Azure bucket lifecycle differs " +
      "substantially per cloud and is operator-managed (Terraform / " +
      "CDK / Pulumi).", true);
  }
  if (!config.region) throw _err("INVALID_CONFIG", "bucketOps: region is required", true);
  if (!config.accessKeyId) throw _err("INVALID_CONFIG", "bucketOps: accessKeyId is required", true);
  if (!config.secretAccessKey) throw _err("INVALID_CONFIG", "bucketOps: secretAccessKey is required", true);

  var endpoint = config.endpoint || ("https://s3." + config.region + ".amazonaws.com");
  if (endpoint.endsWith("/")) endpoint = endpoint.slice(0, -1);
  var pathStyle = !!(config.pathStyle || config.forcePathStyle);
  var allowedProtocols = config.allowedProtocols || safeUrl.ALLOW_HTTP_TLS;
  var allowInternal    = config.allowInternal != null ? config.allowInternal : null;
  safeUrl.parse(endpoint, {
    allowedProtocols: allowedProtocols,
    errorClass:       ObjectStoreError,
  });
  var reqOpts = { timeoutMs: config.timeoutMs, allowedProtocols: allowedProtocols };
  if (allowInternal !== null) reqOpts.allowInternal = allowInternal;

  function _bucketUrl(name, query) {
    var u;
    if (pathStyle) {
      u = new URL(endpoint + "/" + name + "/");
    } else {
      u = new URL(endpoint);
      u.hostname = name + "." + u.hostname;
      u.pathname = "/";
    }
    if (query) {
      Object.keys(query).forEach(function (k) {
        u.searchParams.set(k, query[k] != null ? query[k] : "");
      });
    }
    return u;
  }

  function _objectUrl(name, key, query) {
    // Per-object URL — same path-style vs vhost-style logic as the bucket
    // URL, but the path includes the percent-encoded object key.
    // Each key segment is encoded individually so that legitimate "/"
    // separators in the key are preserved (S3 treats keys with slashes
    // as flat names, not directories).
    var encKey = key.split("/").map(encodeURIComponent).join("/");
    var u;
    if (pathStyle) {
      u = new URL(endpoint + "/" + name + "/" + encKey);
    } else {
      u = new URL(endpoint);
      u.hostname = name + "." + u.hostname;
      u.pathname = "/" + encKey;
    }
    if (query) {
      Object.keys(query).forEach(function (k) {
        u.searchParams.set(k, query[k] != null ? query[k] : "");
      });
    }
    return u;
  }

  function _serviceUrl(query) {
    // ListBuckets — service-level, no bucket prefix.
    var u = new URL(endpoint);
    u.pathname = "/";
    if (query) {
      Object.keys(query).forEach(function (k) { u.searchParams.set(k, query[k]); });
    }
    return u;
  }

  function _signed(method, url, payloadHash, extraHeaders) {
    var signed = sigv4.signRequest({
      method:          method,
      url:             url,
      headers:         extraHeaders || {},
      payloadHash:     payloadHash,
      region:          config.region,
      accessKeyId:     config.accessKeyId,
      secretAccessKey: config.secretAccessKey,
      sessionToken:    config.sessionToken,
    });
    return signed.headers;
  }

  function _request(method, url, headers, body) {
    return httpClient.request({
      method:           method,
      url:              url,
      headers:          headers,
      body:             body,
      idleTimeoutMs:    reqOpts.timeoutMs,
      errorClass:       ObjectStoreError,
      allowedProtocols: reqOpts.allowedProtocols,
    ...((reqOpts.allowInternal !== undefined) ? { allowInternal: reqOpts.allowInternal } : {}),
    });
  }

  // ---- create ----

  function createBucket(name, opts) {
    _validateBucketName(name);
    opts = opts || {};
    var targetRegion = opts.region || config.region;
    var url = _bucketUrl(name);
    var bodyBuf;
    var extra = {};
    // us-east-1 takes an empty body. Other regions need
    // CreateBucketConfiguration with a LocationConstraint.
    if (targetRegion && targetRegion !== "us-east-1") {
      bodyBuf = Buffer.from(
        '<?xml version="1.0" encoding="UTF-8"?>' +
        '<CreateBucketConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">' +
        '<LocationConstraint>' + _xmlEscape(targetRegion) + '</LocationConstraint>' +
        '</CreateBucketConfiguration>',
        "utf8"
      );
      extra["Content-Type"] = "application/xml";
      extra["Content-Length"] = String(bodyBuf.length);
    } else {
      bodyBuf = Buffer.alloc(0);
      extra["Content-Length"] = "0";
    }
    // Object Lock can ONLY be enabled at create time — flipping it on
    // a live bucket isn\'t an S3 API. Setting the header on PutBucket
    // turns on the underlying versioning + write-once-read-many
    // semantics so subsequent setObjectLockConfiguration / Retention
    // / LegalHold calls actually do something.
    if (opts.objectLockEnabled === true) {
      extra["x-amz-bucket-object-lock-enabled"] = "true";
    }
    var payloadHash = sigv4.sha256Hex(bodyBuf);
    var headers = _signed("PUT", url, payloadHash, extra);
    return _request("PUT", url, headers, bodyBuf).then(
      function () { return { created: true, name: name, region: targetRegion }; },
      function (e) {
        // Map S3 conflict response codes into stable framework codes.
        if (e.statusCode === 409 && /BucketAlreadyOwnedByYou/.test(e.message || "")) {
          throw _err("BUCKET_ALREADY_OWNED",
            "bucket '" + name + "' already exists and is owned by this account", true);
        }
        if (e.statusCode === 409) {
          throw _err("BUCKET_NAME_TAKEN",
            "bucket name '" + name + "' is taken in S3's global namespace", true);
        }
        throw e;
      }
    );
  }

  // ---- delete ----

  function deleteBucket(name) {
    _validateBucketName(name);
    var url = _bucketUrl(name);
    var payloadHash = sigv4.sha256Hex(Buffer.alloc(0));
    var headers = _signed("DELETE", url, payloadHash);
    return _request("DELETE", url, headers, null).then(
      function () { return true; },
      function (e) {
        if (e.statusCode === 404) return false;
        if (e.statusCode === 409 && /BucketNotEmpty/.test(e.message || "")) {
          throw _err("BUCKET_NOT_EMPTY",
            "bucket '" + name + "' is not empty; delete all objects + " +
            "noncurrent versions + delete-markers first", true);
        }
        throw e;
      }
    );
  }

  // ---- list ----

  function listBuckets() {
    var url = _serviceUrl();
    var payloadHash = sigv4.sha256Hex(Buffer.alloc(0));
    var headers = _signed("GET", url, payloadHash);
    return _request("GET", url, headers, null).then(function (res) {
      var doc = safeXml.parse(res.body);
      var result = doc.ListAllMyBucketsResult || {};
      var bucketsContainer = result.Buckets || {};
      var raw = bucketsContainer.Bucket;
      if (!raw) return [];
      var arr = Array.isArray(raw) ? raw : [raw];
      return arr.map(function (b) {
        return {
          name:         b.Name,
          creationDate: b.CreationDate ? Date.parse(b.CreationDate) : null,
          region:       b.BucketRegion || null,
        };
      });
    });
  }

  // ---- setLifecycle ----

  function setLifecycle(name, rules) {
    _validateBucketName(name);
    var bodyXml = _buildLifecycleXml(rules);
    var bodyBuf = Buffer.from(bodyXml, "utf8");
    var url = _bucketUrl(name, { lifecycle: "" });
    var payloadHash = sigv4.sha256Hex(bodyBuf);
    var headers = _signed("PUT", url, payloadHash, {
      "Content-Type":   "application/xml",
      "Content-Length": String(bodyBuf.length),
      "Content-MD5":    _md5Base64(bodyBuf),
    });
    return _request("PUT", url, headers, bodyBuf).then(function () {
      return { applied: true, name: name, ruleCount: rules.length };
    });
  }

  // ---- setCorsRules ----

  function setCorsRules(name, rules) {
    _validateBucketName(name);
    var bodyXml = _buildCorsXml(rules);
    var bodyBuf = Buffer.from(bodyXml, "utf8");
    var url = _bucketUrl(name, { cors: "" });
    var payloadHash = sigv4.sha256Hex(bodyBuf);
    var headers = _signed("PUT", url, payloadHash, {
      "Content-Type":   "application/xml",
      "Content-Length": String(bodyBuf.length),
      "Content-MD5":    _md5Base64(bodyBuf),
    });
    return _request("PUT", url, headers, bodyBuf).then(function () {
      return { applied: true, name: name, ruleCount: rules.length };
    });
  }

  // ---- Object Lock configuration (bucket-level) ----

  function setObjectLockConfiguration(name, opts) {
    _validateBucketName(name);
    _validateObjectLockConfig(opts);
    var bodyXml = _buildObjectLockConfigXml(opts);
    var bodyBuf = Buffer.from(bodyXml, "utf8");
    var url = _bucketUrl(name, { "object-lock": "" });
    var payloadHash = sigv4.sha256Hex(bodyBuf);
    var headers = _signed("PUT", url, payloadHash, {
      "Content-Type":   "application/xml",
      "Content-Length": String(bodyBuf.length),
      "Content-MD5":    _md5Base64(bodyBuf),
    });
    return _request("PUT", url, headers, bodyBuf).then(function () {
      return {
        applied: true, name: name,
        mode:    opts.mode,
        days:    opts.days  != null ? opts.days  : null,
        years:   opts.years != null ? opts.years : null,
      };
    });
  }

  function getObjectLockConfiguration(name) {
    _validateBucketName(name);
    var url = _bucketUrl(name, { "object-lock": "" });
    var payloadHash = sigv4.sha256Hex(Buffer.alloc(0));
    var headers = _signed("GET", url, payloadHash);
    return _request("GET", url, headers, null).then(function (res) {
      var doc = safeXml.parse(res.body);
      var olc = doc.ObjectLockConfiguration || {};
      var enabled = olc.ObjectLockEnabled === "Enabled";
      var rule = olc.Rule || {};
      var def  = rule.DefaultRetention || {};
      return {
        enabled: enabled,
        mode:    def.Mode || null,
        days:    def.Days  != null ? Number(def.Days)  : null,
        years:   def.Years != null ? Number(def.Years) : null,
      };
    });
  }

  // ---- Per-object retention ----

  function setObjectRetention(name, key, opts) {
    _validateBucketName(name);
    _validateObjectKey(key);
    _validateRetention(opts);
    var bodyXml = _buildRetentionXml(opts);
    var bodyBuf = Buffer.from(bodyXml, "utf8");
    var url = _objectUrl(name, key, { retention: "" });
    var extra = {
      "Content-Type":   "application/xml",
      "Content-Length": String(bodyBuf.length),
      "Content-MD5":    _md5Base64(bodyBuf),
    };
    if (opts.bypassGovernance === true) {
      extra["x-amz-bypass-governance-retention"] = "true";
    }
    var payloadHash = sigv4.sha256Hex(bodyBuf);
    var headers = _signed("PUT", url, payloadHash, extra);
    return _request("PUT", url, headers, bodyBuf).then(function () {
      return {
        applied:     true,
        name:        name,
        key:         key,
        mode:        opts.mode,
        retainUntil: opts.retainUntil,
      };
    });
  }

  function getObjectRetention(name, key) {
    _validateBucketName(name);
    _validateObjectKey(key);
    var url = _objectUrl(name, key, { retention: "" });
    var payloadHash = sigv4.sha256Hex(Buffer.alloc(0));
    var headers = _signed("GET", url, payloadHash);
    return _request("GET", url, headers, null).then(function (res) {
      var doc = safeXml.parse(res.body);
      var ret = doc.Retention || {};
      var until = ret.RetainUntilDate ? new Date(ret.RetainUntilDate) : null;
      return {
        mode:        ret.Mode || null,
        retainUntil: until,
      };
    });
  }

  // ---- Per-object legal hold ----

  function setObjectLegalHold(name, key, status) {
    _validateBucketName(name);
    _validateObjectKey(key);
    _validateLegalHoldStatus(status);
    var bodyXml = _buildLegalHoldXml(status);
    var bodyBuf = Buffer.from(bodyXml, "utf8");
    var url = _objectUrl(name, key, { "legal-hold": "" });
    var payloadHash = sigv4.sha256Hex(bodyBuf);
    var headers = _signed("PUT", url, payloadHash, {
      "Content-Type":   "application/xml",
      "Content-Length": String(bodyBuf.length),
      "Content-MD5":    _md5Base64(bodyBuf),
    });
    return _request("PUT", url, headers, bodyBuf).then(function () {
      return { applied: true, name: name, key: key, status: status };
    });
  }

  function getObjectLegalHold(name, key) {
    _validateBucketName(name);
    _validateObjectKey(key);
    var url = _objectUrl(name, key, { "legal-hold": "" });
    var payloadHash = sigv4.sha256Hex(Buffer.alloc(0));
    var headers = _signed("GET", url, payloadHash);
    return _request("GET", url, headers, null).then(function (res) {
      var doc = safeXml.parse(res.body);
      var lh = doc.LegalHold || {};
      return { status: lh.Status || null };
    });
  }

  return {
    protocol:                       "sigv4",
    create:                         createBucket,
    delete:                         deleteBucket,
    list:                           listBuckets,
    setLifecycle:                   setLifecycle,
    setCorsRules:                   setCorsRules,
    setObjectLockConfiguration:     setObjectLockConfiguration,
    getObjectLockConfiguration:     getObjectLockConfiguration,
    setObjectRetention:             setObjectRetention,
    getObjectRetention:             getObjectRetention,
    setObjectLegalHold:             setObjectLegalHold,
    getObjectLegalHold:             getObjectLegalHold,
  };
}

module.exports = {
  create: create,
  // Test-only exports for unit-testing the XML builders without
  // standing up a fake S3 server.
  _buildLifecycleXmlForTest:        _buildLifecycleXml,
  _buildCorsXmlForTest:             _buildCorsXml,
  _validateBucketNameForTest:       _validateBucketName,
};
