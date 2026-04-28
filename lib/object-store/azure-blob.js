"use strict";
/**
 * Azure Blob Storage protocol adapter — Shared Key auth (account-level).
 *
 * Auth: HMAC-SHA256 over a canonicalized string-to-sign (different format
 *       from AWS SigV4 — Azure has its own signing scheme). Signature is
 *       base64-encoded; Authorization header: "SharedKey <account>:<sig>".
 *
 * Endpoint: https://<account>.blob.core.windows.net (override via
 * config.endpoint for Azurite emulator / Azure Stack / private endpoints).
 *
 * Config:
 *   {
 *     accountName:  'mystorage'              // required
 *     accountKey:   '<base64 storage key>'    // required (REST shared key)
 *     container:    'my-container'            // required
 *     endpoint:     'https://...'             // optional override
 *     apiVersion:   '2024-08-04'              // x-ms-version header
 *     timeoutMs:    C.TIME.seconds(30)
 *   }
 *
 * Reference:
 *   https://learn.microsoft.com/en-us/rest/api/storageservices/authorize-with-shared-key
 *   https://learn.microsoft.com/en-us/rest/api/storageservices/blob-service-rest-api
 *
 * Scope notes:
 *   - Auth: Shared Key only. SAS tokens (Shared Access Signatures) and
 *     Azure AD OAuth2 are not implemented; this covers the common
 *     server-to-storage case with rotated keys.
 *   - PutBlock + PutBlockList (multipart for >256MB blobs) is not
 *     implemented; uploads above that ceiling will fail at the API.
 */
var nodeCrypto = require("crypto");
var { URL } = require("url");
var { Readable } = require("stream");
var safeXml = require("../parsers/safe-xml");
var C = require("../constants");
var { ObjectStoreError } = require("../framework-error");
var httpClient = require("../http-client");
var safeUrl = require("../safe-url");

// Azure Blob list responses are commonly multi-thousand-key paginated
// payloads — well above the parser's default 1 MiB / 10K element ceilings.
var LIST_PARSE_OPTS = {
  maxBytes:    C.BYTES.mib(8),
  maxElements: 50000,
};

function _arrayify(value) {
  if (value == null) return [];
  return Array.isArray(value) ? value : [value];
}

var DEFAULT_API_VERSION = "2024-08-04";

// Service SAS expiry bounds. Azure doesn't enforce a hard max, but
// matching the SigV4 / V4 7-day cap keeps semantics uniform across
// backends and reflects best practice (long-lived SAS tokens are
// effectively credentials).
var SAS_DEFAULT_EXPIRES_SECONDS = 15 * 60;
var SAS_MAX_EXPIRES_SECONDS     = 7 * 24 * 60 * 60;
var SAS_MIN_EXPIRES_SECONDS     = 1;

var _err = ObjectStoreError.factory;

function _httpRequest(method, urlObj, headers, body, opts) {
  return httpClient.request({
    method:           method,
    url:              urlObj,
    headers:          headers,
    body:             body,
    idleTimeoutMs:    opts && opts.timeoutMs,
    maxResponseBytes: opts && opts.maxResponseBytes,
    errorClass:       ObjectStoreError,
    allowedProtocols: opts && opts.allowedProtocols,
  });
}

// ---- Shared Key signing ----
//
// StringToSign for Blob (Shared Key):
//   VERB + "\n" +
//   Content-Encoding + "\n" +
//   Content-Language + "\n" +
//   Content-Length + "\n" +
//   Content-MD5 + "\n" +
//   Content-Type + "\n" +
//   Date + "\n" +
//   If-Modified-Since + "\n" +
//   If-Match + "\n" +
//   If-None-Match + "\n" +
//   If-Unmodified-Since + "\n" +
//   Range + "\n" +
//   CanonicalizedHeaders +
//   CanonicalizedResource
//
// CanonicalizedHeaders: x-ms-* headers, lowercased, sorted, "key:value\n"
// CanonicalizedResource: "/<account>/<container>/<blob>" + sorted query
//                         params each on their own line as "param:value\n"

function buildStringToSign(opts) {
  var headers = opts.headers || {};
  var url = opts.url instanceof URL ? opts.url : new URL(opts.url);

  var canonicalHeaders = (function () {
    var pairs = [];
    Object.keys(headers).forEach(function (k) {
      var lk = k.toLowerCase();
      if (lk.indexOf("x-ms-") === 0) {
        pairs.push([lk, String(headers[k]).trim().replace(/\s+/g, " ")]);
      }
    });
    pairs.sort(function (a, b) { return a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0; });
    return pairs.map(function (p) { return p[0] + ":" + p[1]; }).join("\n");
  })();

  var canonicalResource = (function () {
    // /<account>/<rest of path>
    // Plus sorted query params, each "name:value\n"
    var resourcePath = "/" + opts.accountName + url.pathname;
    var paramPairs = [];
    url.searchParams.forEach(function (v, k) {
      paramPairs.push([k.toLowerCase(), v]);
    });
    paramPairs.sort(function (a, b) {
      if (a[0] !== b[0]) return a[0] < b[0] ? -1 : 1;
      return a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0;
    });
    // Group by name; multiple values comma-separated per Azure rules
    var grouped = {};
    paramPairs.forEach(function (p) {
      if (!grouped[p[0]]) grouped[p[0]] = [];
      grouped[p[0]].push(p[1]);
    });
    var queryLines = Object.keys(grouped).sort().map(function (name) {
      return "\n" + name + ":" + grouped[name].join(",");
    }).join("");
    return resourcePath + queryLines;
  })();

  return [
    opts.method.toUpperCase(),
    headers["Content-Encoding"]      || "",
    headers["Content-Language"]      || "",
    headers["Content-Length"] && headers["Content-Length"] !== "0"
      ? headers["Content-Length"] : "",       // "0" → empty (Azure quirk)
    headers["Content-MD5"]           || "",
    headers["Content-Type"]          || "",
    "",                                       // Date line — empty when x-ms-date is set
    headers["If-Modified-Since"]     || "",
    headers["If-Match"]              || "",
    headers["If-None-Match"]         || "",
    headers["If-Unmodified-Since"]   || "",
    headers["Range"]                 || "",
    canonicalHeaders,
    canonicalResource,
  ].join("\n");
}

function signRequest(opts) {
  var headers = Object.assign({}, opts.headers || {});
  if (!headers["x-ms-version"]) headers["x-ms-version"] = opts.apiVersion || DEFAULT_API_VERSION;
  if (!headers["x-ms-date"])    headers["x-ms-date"]    = new Date().toUTCString();

  var url = opts.url instanceof URL ? opts.url : new URL(opts.url);
  if (!headers["host"])         headers["host"]         = url.host;

  var sts = buildStringToSign({
    method:      opts.method,
    url:         url,
    headers:     headers,
    accountName: opts.accountName,
  });
  var keyBytes = Buffer.from(opts.accountKey, "base64");
  var signature = nodeCrypto.createHmac("sha256", keyBytes).update(sts, "utf8").digest("base64");
  headers["Authorization"] = "SharedKey " + opts.accountName + ":" + signature;

  return { headers: headers, stringToSign: sts, signature: signature };
}

// ---- Public adapter factory ----

function create(config) {
  if (!config) throw new Error("azure-blob protocol requires config");
  if (!config.accountName) throw new Error("azure-blob: accountName is required");
  if (!config.accountKey)  throw new Error("azure-blob: accountKey is required");
  if (!config.container)   throw new Error("azure-blob: container is required");

  var endpoint = config.endpoint || ("https://" + config.accountName + ".blob.core.windows.net");
  if (endpoint.endsWith("/")) endpoint = endpoint.slice(0, -1);
  var apiVersion = config.apiVersion || DEFAULT_API_VERSION;
  var timeoutMs = config.timeoutMs;
  // HTTPS-only by default — real Azure is always HTTPS. Operators with
  // an Azurite emulator endpoint opt in via config.allowedProtocols.
  var allowedProtocols = config.allowedProtocols || safeUrl.ALLOW_HTTP_TLS;
  safeUrl.parse(endpoint, { allowedProtocols: allowedProtocols, errorClass: ObjectStoreError });
  var reqOpts = { timeoutMs: timeoutMs, allowedProtocols: allowedProtocols };

  function _blobUrl(key, params) {
    var u = new URL(endpoint + "/" + config.container + "/" + key);
    if (params) {
      Object.keys(params).forEach(function (k) { u.searchParams.set(k, params[k]); });
    }
    return u;
  }

  function _containerUrl(params) {
    var u = new URL(endpoint + "/" + config.container);
    if (params) {
      Object.keys(params).forEach(function (k) { u.searchParams.set(k, params[k]); });
    }
    return u;
  }

  function _signed(method, url, headers) {
    var s = signRequest({
      method:      method,
      url:         url,
      headers:     headers || {},
      accountName: config.accountName,
      accountKey:  config.accountKey,
      apiVersion:  apiVersion,
    });
    return s.headers;
  }

  function put(key, body, opts) {
    var url = _blobUrl(key);
    var buf = Buffer.isBuffer(body) ? body : Buffer.from(typeof body === "string" ? body : "", "utf8");
    var contentType = (opts && opts.contentType) || "application/octet-stream";
    var headers = _signed("PUT", url, {
      "Content-Type":   contentType,
      "Content-Length": String(buf.length),
      "x-ms-blob-type": "BlockBlob",
    });
    return _httpRequest("PUT", url, headers, buf, reqOpts).then(function (res) {
      return { size: buf.length, etag: res.headers.etag };
    });
  }

  function get(key) {
    var url = _blobUrl(key);
    var headers = _signed("GET", url, {});
    return _httpRequest("GET", url, headers, null, reqOpts).then(function (res) {
      return res.body;
    });
  }

  function getStream(key) { return Readable.from(get(key)); }

  function head(key) {
    var url = _blobUrl(key);
    var headers = _signed("HEAD", url, {});
    return _httpRequest("HEAD", url, headers, null, reqOpts).then(function (res) {
      return {
        size:         res.headers["content-length"] ? parseInt(res.headers["content-length"], 10) : null,
        etag:         res.headers.etag,
        lastModified: res.headers["last-modified"] ? Date.parse(res.headers["last-modified"]) : null,
      };
    });
  }

  function deleteKey(key) {
    var url = _blobUrl(key);
    var headers = _signed("DELETE", url, {});
    return _httpRequest("DELETE", url, headers, null, reqOpts).then(
      function () { return true; },
      function (e) { if (e.statusCode === 404) return false; throw e; }
    );
  }

  function list(prefix, opts) {
    opts = opts || {};
    var params = { restype: "container", comp: "list" };
    if (prefix)                   params.prefix = prefix;
    if (opts.maxResults)          params.maxresults = String(opts.maxResults);
    if (opts.continuationToken)   params.marker = opts.continuationToken;
    var url = _containerUrl(params);
    var headers = _signed("GET", url, {});
    return _httpRequest("GET", url, headers, null, reqOpts).then(function (res) {
      var doc = safeXml.parse(res.body, LIST_PARSE_OPTS);
      var result = doc.EnumerationResults || {};
      var blobsContainer = result.Blobs || {};
      var blobs = _arrayify(blobsContainer.Blob);
      var items = blobs.map(function (b) {
        var props = b.Properties || {};
        var size = props["Content-Length"];
        var lm = props["Last-Modified"];
        return {
          key:          b.Name,
          size:         size != null ? parseInt(size, 10) : null,
          lastModified: lm ? Date.parse(lm) : null,
        };
      }).filter(function (it) { return it.key; });
      // <NextMarker/> (self-closing) parses to "" — falsy. A real token
      // is a non-empty string, which is truthy.
      var marker = (typeof result.NextMarker === "string") ? result.NextMarker : "";
      return {
        items:             items,
        truncated:         marker.length > 0,
        continuationToken: marker.length > 0 ? marker : null,
      };
    });
  }

  // Service SAS (Shared Access Signature) generator for blob endpoints.
  // The string-to-sign layout is fixed by API version — see Azure docs
  // "Create a service SAS". We sign with the account key (HMAC-SHA256
  // over the canonical string) and emit the token as URL query params.
  function _buildSasToken(permissions, opts) {
    var expiresIn = opts.expiresIn != null ? opts.expiresIn : SAS_DEFAULT_EXPIRES_SECONDS;
    if (typeof expiresIn !== "number" ||
        expiresIn < SAS_MIN_EXPIRES_SECONDS ||
        expiresIn > SAS_MAX_EXPIRES_SECONDS) {
      throw _err("INVALID_EXPIRES",
        "presigned URL: expiresIn must be a number of seconds between " +
        SAS_MIN_EXPIRES_SECONDS + " and " + SAS_MAX_EXPIRES_SECONDS +
        " (7 days)", true);
    }
    var nowDate = opts.date || new Date();
    var expiry = new Date(nowDate.getTime() + C.TIME.seconds(expiresIn));
    // Azure accepts ISO 8601 with second precision; strip ms.
    var signedExpiry = expiry.toISOString().replace(/\.\d{3}Z$/, "Z");
    var signedStart  = "";  // omitted = SAS valid immediately
    var signedVersion = apiVersion;
    var signedResource = "b";  // blob
    var signedProtocol = "https";
    var canonicalizedResource = "/blob/" + config.accountName + "/" +
                                config.container + "/" + opts.key;
    var signedContentType = opts.contentType || "";

    // String-to-sign layout for Service SAS (blob), API version 2018-11-09+:
    //   signedPermissions \n signedStart \n signedExpiry \n
    //   canonicalizedResource \n signedIdentifier \n signedIP \n
    //   signedProtocol \n signedVersion \n signedResource \n
    //   signedSnapshotTime \n signedEncryptionScope \n
    //   rscc \n rscd \n rsce \n rscl \n rsct
    var stringToSign = [
      permissions,
      signedStart,
      signedExpiry,
      canonicalizedResource,
      "",                    // signedIdentifier
      "",                    // signedIP
      signedProtocol,
      signedVersion,
      signedResource,
      "",                    // signedSnapshotTime
      "",                    // signedEncryptionScope
      "",                    // rscc — Cache-Control
      "",                    // rscd — Content-Disposition
      "",                    // rsce — Content-Encoding
      "",                    // rscl — Content-Language
      signedContentType,     // rsct — Content-Type (signed when supplied)
    ].join("\n");

    var keyBuf = Buffer.from(config.accountKey, "base64");
    var signature = nodeCrypto.createHmac("sha256", keyBuf)
      .update(stringToSign, "utf8").digest("base64");

    var sas = new URLSearchParams();
    sas.set("sv",  signedVersion);
    sas.set("sr",  signedResource);
    sas.set("sp",  permissions);
    sas.set("se",  signedExpiry);
    sas.set("spr", signedProtocol);
    if (signedContentType) sas.set("rsct", signedContentType);
    sas.set("sig", signature);

    return { sas: sas.toString(), expiresAt: expiry.getTime() };
  }

  function _presign(method, permissions, opts) {
    opts = opts || {};
    if (!opts.key || typeof opts.key !== "string") {
      throw _err("INVALID_KEY", "presigned URL: key is required", true);
    }
    if (opts.key.indexOf("\0") !== -1) {
      throw _err("INVALID_KEY", "null byte in key", true);
    }

    var token = _buildSasToken(permissions, opts);
    var url = new URL(endpoint + "/" + config.container + "/" + opts.key + "?" + token.sas);

    var clientHeaders = {};
    if (opts.contentType) clientHeaders["Content-Type"] = opts.contentType;
    if (method === "PUT") clientHeaders["x-ms-blob-type"] = "BlockBlob";

    return {
      url:       url.toString(),
      method:    method,
      headers:   clientHeaders,
      expiresAt: token.expiresAt,
    };
  }

  function presignedUploadUrl(opts)   { return _presign("PUT", "cw", opts); }
  function presignedDownloadUrl(opts) { return _presign("GET", "r",  opts); }

  // Azure SAS doesn't support an equivalent of S3 / GCS POST policy
  // with a content-length-range constraint. The SAS spec carries
  // permissions / start / expiry / IP / protocol / resource-content-
  // headers but no body-size cap — Azure validates the upload at the
  // service level only via the operator's optional Block Blob size
  // limit applied at storage-account or container scope, not via the
  // SAS token itself.
  //
  // Rather than throw NOT_SUPPORTED, this returns the same SAS PUT
  // shape as presignedUploadUrl with an `enforcement: 'client-only'`
  // marker so operators making cross-vendor decisions know the
  // body-size guard is advisory on Azure and must be enforced on the
  // client side or via a server-side post-upload check.
  //
  // For strict server-side body-size enforcement on Azure, the
  // canonical pattern is: SAS-authorize the upload, then have the
  // operator's app issue a HEAD on the resulting blob and delete +
  // 4xx the requester if Content-Length > opts.maxBytes.
  function presignedUploadPolicy(opts) {
    opts = opts || {};
    if (typeof opts.maxBytes !== "number" || !Number.isFinite(opts.maxBytes) ||
        opts.maxBytes <= 0) {
      throw _err("INVALID_MAX_BYTES",
        "presignedUploadPolicy: maxBytes (positive number of bytes) is required " +
        "(advisory on Azure — see docstring for server-side enforcement)", true);
    }
    var underlying = _presign("PUT", "cw", opts);
    return {
      url:           underlying.url,
      method:        "PUT",
      // SAS uploads are PUT, not multipart POST — there are no form
      // fields. Operators uploading attach the body directly to the
      // returned URL with the headers in `headers`.
      fields:        null,
      headers:       underlying.headers,
      expiresAt:     underlying.expiresAt,
      maxBytes:      opts.maxBytes,
      enforcement:   "client-only",
      enforcementNote:
        "Azure SAS does not natively cap upload size. Operators needing " +
        "strict size enforcement must HEAD the blob post-upload and reject " +
        "if Content-Length exceeds maxBytes.",
    };
  }

  return {
    protocol:    "azure-blob",
    endpoint:    endpoint,
    container:   config.container,
    accountName: config.accountName,
    put:         put,
    get:         get,
    getStream:   getStream,
    head:        head,
    delete:      deleteKey,
    list:        list,
    presignedUploadUrl:    presignedUploadUrl,
    presignedDownloadUrl:  presignedDownloadUrl,
    presignedUploadPolicy: presignedUploadPolicy,
  };
}

module.exports = {
  create:             create,
  signRequest:        signRequest,
  buildStringToSign:  buildStringToSign,
  DEFAULT_API_VERSION: DEFAULT_API_VERSION,
};
