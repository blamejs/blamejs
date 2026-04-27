"use strict";
/**
 * Generic HTTP PUT/GET protocol adapter.
 *
 * For backends that aren't S3-compatible but expose a simple HTTP key-value
 * surface: internal stores, NAS appliances with HTTP frontends, or custom
 * services. Uses Node's native https / http; PQC TLS group preference is
 * applied to outbound connections via constants.TLS_GROUP_CURVE_STR.
 *
 * Authentication options:
 *   { auth: 'none' }                                 (no Authorization header)
 *   { auth: 'bearer', token: '...' }                 (Authorization: Bearer ...)
 *   { auth: 'basic',  username: '...', password: '...' }
 *   { auth: 'header', headers: { 'X-Auth-Key': '...' } }   (arbitrary headers)
 *
 * Errors are surfaced as object-store errors with statusCode set so the
 * retry layer can classify retryable vs permanent.
 */
var { URL } = require("url");
var { Readable } = require("stream");
var { ObjectStoreError } = require("./framework-error");
var httpClient = require("./http-client");
var safeUrl = require("./safe-url");
var authHeader = require("./auth-header");

function _err(code, message, permanent, statusCode) {
  return new ObjectStoreError(code, message, permanent, statusCode);
}

// Auth-header construction is delegated to lib/auth-header for the
// none/bearer/basic triple. The "header" mode (pass-through arbitrary
// headers) is just header merging; kept here because it's documented as
// a value of the same config.auth knob.
function _authHeaders(authConfig) {
  if (authConfig && authConfig.auth === "header") {
    return Object.assign({}, authConfig.headers || {});
  }
  return authHeader.fromConfig(authConfig);
}

function _request(method, url, body, headers, opts) {
  return httpClient.request({
    method:           method,
    url:              url,
    headers:          headers,
    body:             body,
    idleTimeoutMs:    opts && opts.timeoutMs,
    errorClass:       ObjectStoreError,
    allowedProtocols: opts && opts.allowedProtocols,
  });
}

function _keyToUrl(baseUrl, key) {
  // Append key to baseUrl, ensuring exactly one slash between them.
  // Disallow ../ to prevent path traversal at the URL level.
  if (key.includes("..") || key.includes("\0")) {
    throw _err("INVALID_KEY", "invalid characters in key", true);
  }
  var b = baseUrl.endsWith("/") ? baseUrl.slice(0, -1) : baseUrl;
  var k = key.startsWith("/") ? key.slice(1) : key;
  return b + "/" + k;
}

function create(config) {
  if (!config || !config.baseUrl) {
    throw new Error("http-put protocol requires { baseUrl }");
  }
  var baseUrl = config.baseUrl;
  // Fail fast on misconfigured baseUrl — validate scheme + shape now, not
  // at first put(). HTTPS-only by default; cleartext appliances opt in
  // via config.allowedProtocols (safeUrl.ALLOW_HTTP_ALL).
  var allowedProtocols = config.allowedProtocols || safeUrl.ALLOW_HTTP_TLS;
  safeUrl.parse(baseUrl, {
    allowedProtocols: allowedProtocols,
    errorClass:       ObjectStoreError,
  });
  var headers = _authHeaders(config);
  var timeoutMs = config.timeoutMs;
  var reqOpts = { timeoutMs: timeoutMs, allowedProtocols: allowedProtocols };

  function put(key, body, _opts) {
    var url = _keyToUrl(baseUrl, key);
    var h = Object.assign({ "Content-Type": "application/octet-stream" }, headers);
    return _request("PUT", url, body, h, reqOpts).then(function (res) {
      var size = Buffer.isBuffer(body) ? body.length : null;
      return { size: size, etag: res.headers.etag };
    });
  }

  function get(key) {
    var url = _keyToUrl(baseUrl, key);
    return _request("GET", url, null, headers, reqOpts).then(function (res) {
      return res.body;
    });
  }

  function getStream(key) {
    // Generic HTTP PUT has no streaming ergonomic path through Node's
    // https that doesn't buffer; return a Readable wrapping the buffered
    // body. Backends that support chunked transfer (e.g. SigV4) implement
    // a real streaming getStream in their own adapter.
    return Readable.from(get(key));
  }

  function head(key) {
    var url = _keyToUrl(baseUrl, key);
    return _request("HEAD", url, null, headers, reqOpts).then(function (res) {
      return {
        size:         res.headers["content-length"] ? parseInt(res.headers["content-length"], 10) : null,
        etag:         res.headers.etag,
        lastModified: res.headers["last-modified"] ? Date.parse(res.headers["last-modified"]) : null,
      };
    });
  }

  function deleteKey(key) {
    var url = _keyToUrl(baseUrl, key);
    return _request("DELETE", url, null, headers, reqOpts).then(
      function () { return true; },
      function (e) {
        if (e.statusCode === 404) return false;
        throw e;
      }
    );
  }

  function list(_prefix, _opts) {
    // Generic HTTP PUT protocol has no listing convention. SigV4 will.
    return Promise.reject(_err("NOT_SUPPORTED", "list() not supported by http-put protocol", true));
  }

  return {
    protocol:  "http-put",
    baseUrl:   baseUrl,
    put:       put,
    get:       get,
    getStream: getStream,
    head:      head,
    delete:    deleteKey,
    list:      list,
  };
}

module.exports = { create: create };
