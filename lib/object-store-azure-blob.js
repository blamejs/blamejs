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
 *   - SAS tokens (Shared Access Signatures) and Azure AD OAuth2 are
 *     deferred to a later release. Shared Key covers the most common
 *     framework use case (server-to-storage with rotated keys).
 *   - PutBlock + PutBlockList (multipart for >256MB blobs) deferred.
 */
var nodeCrypto = require("crypto");
var { URL } = require("url");
var http = require("http");
var https = require("https");
var { Readable } = require("stream");
var C = require("./constants");

var DEFAULT_API_VERSION = "2024-08-04";

function _err(code, message, permanent, statusCode) {
  var e = new Error(message);
  e.code = code;
  e.permanent = !!permanent;
  e.statusCode = statusCode;
  e.isObjectStoreError = true;
  return e;
}

function _httpRequest(method, urlObj, headers, body, opts) {
  return new Promise(function (resolve, reject) {
    var u = urlObj instanceof URL ? urlObj : new URL(urlObj);
    var lib = u.protocol === "https:" ? https : http;
    var reqOpts = {
      method:   method,
      hostname: u.hostname,
      port:     u.port || (u.protocol === "https:" ? 443 : 80),
      path:     u.pathname + (u.search || ""),
      headers:  headers || {},
      timeout:  (opts && opts.timeoutMs) || C.TIME.seconds(30),
    };
    if (u.protocol === "https:") {
      reqOpts.ecdhCurve = C.TLS_GROUP_CURVE_STR;
    }
    var req = lib.request(reqOpts, function (res) {
      var chunks = [];
      res.on("data", function (c) { chunks.push(c); });
      res.on("end", function () {
        var buf = Buffer.concat(chunks);
        if (res.statusCode >= 200 && res.statusCode < 300) {
          resolve({ statusCode: res.statusCode, headers: res.headers, body: buf });
        } else {
          var permanent = res.statusCode >= 400 && res.statusCode < 500
                          && res.statusCode !== 408 && res.statusCode !== 425 && res.statusCode !== 429;
          reject(_err("HTTP_ERROR", "HTTP " + res.statusCode + ": " + buf.toString("utf8").slice(0, 500), permanent, res.statusCode));
        }
      });
      res.on("error", function (e) { reject(_err(e.code || "RES_ERROR", e.message, false)); });
    });
    req.on("timeout", function () { req.destroy(); reject(_err("ETIMEDOUT", "request timeout", false)); });
    req.on("error", function (e) { reject(_err(e.code || "REQ_ERROR", e.message, false)); });
    if (Buffer.isBuffer(body)) req.end(body);
    else if (typeof body === "string") req.end(Buffer.from(body, "utf8"));
    else req.end();
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
    return _httpRequest("PUT", url, headers, buf, { timeoutMs: timeoutMs }).then(function (res) {
      return { size: buf.length, etag: res.headers.etag };
    });
  }

  function get(key) {
    var url = _blobUrl(key);
    var headers = _signed("GET", url, {});
    return _httpRequest("GET", url, headers, null, { timeoutMs: timeoutMs }).then(function (res) {
      return res.body;
    });
  }

  function getStream(key) { return Readable.from(get(key)); }

  function head(key) {
    var url = _blobUrl(key);
    var headers = _signed("HEAD", url, {});
    return _httpRequest("HEAD", url, headers, null, { timeoutMs: timeoutMs }).then(function (res) {
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
    return _httpRequest("DELETE", url, headers, null, { timeoutMs: timeoutMs }).then(
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
    return _httpRequest("GET", url, headers, null, { timeoutMs: timeoutMs }).then(function (res) {
      var xml = res.body.toString("utf8");
      var items = [];
      var blobMatches = xml.matchAll(/<Blob>([\s\S]*?)<\/Blob>/g);
      for (var m of blobMatches) {
        var inner = m[1];
        var nameMatch = inner.match(/<Name>([\s\S]*?)<\/Name>/);
        var sizeMatch = inner.match(/<Content-Length>(\d+)<\/Content-Length>/);
        var lmMatch = inner.match(/<Last-Modified>([\s\S]*?)<\/Last-Modified>/);
        if (nameMatch) {
          items.push({
            key:          nameMatch[1],
            size:         sizeMatch ? parseInt(sizeMatch[1], 10) : null,
            lastModified: lmMatch ? Date.parse(lmMatch[1]) : null,
          });
        }
      }
      var nextMarker = xml.match(/<NextMarker>([\s\S]*?)<\/NextMarker>/);
      var truncated = nextMarker && nextMarker[1].length > 0;
      return {
        items:             items,
        truncated:         !!truncated,
        continuationToken: nextMarker ? nextMarker[1] : null,
      };
    });
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
  };
}

module.exports = {
  create:             create,
  signRequest:        signRequest,
  buildStringToSign:  buildStringToSign,
  DEFAULT_API_VERSION: DEFAULT_API_VERSION,
};
