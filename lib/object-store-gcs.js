"use strict";
/**
 * Google Cloud Storage (GCS) protocol adapter — native JSON API.
 *
 * Auth: service-account JSON (RSA-SHA256 signed JWT exchanged for an
 *       OAuth2 access token; tokens cached until ~5 min before expiry).
 *
 * Endpoint: https://storage.googleapis.com (override via config.endpoint
 * for emulators / private endpoints).
 *
 * Config:
 *   {
 *     bucket:         'my-bucket'                        // required
 *     serviceAccount: { client_email, private_key, ... } // OR
 *     serviceAccountFile: '/path/to/sa.json'             // OR
 *     scope:          'https://www.googleapis.com/auth/devstorage.read_write'
 *     endpoint:       'https://storage.googleapis.com'
 *     timeoutMs:      30000
 *   }
 *
 * Reference:
 *   https://cloud.google.com/storage/docs/json_api/v1
 *   https://developers.google.com/identity/protocols/oauth2/service-account
 */
var fs = require("fs");
var nodeCrypto = require("crypto");
var { URL } = require("url");
var http = require("http");
var https = require("https");
var { Readable } = require("stream");
var C = require("./constants");

var DEFAULT_ENDPOINT     = "https://storage.googleapis.com";
var TOKEN_ENDPOINT       = "https://oauth2.googleapis.com/token";
var DEFAULT_SCOPE        = "https://www.googleapis.com/auth/devstorage.read_write";
var TOKEN_REFRESH_BUFFER = 5 * 60 * 1000; // refresh 5 min before expiry

function _err(code, message, permanent, statusCode) {
  var e = new Error(message);
  e.code = code;
  e.permanent = !!permanent;
  e.statusCode = statusCode;
  e.isObjectStoreError = true;
  return e;
}

// ---- Generic HTTP helper (separate from sigv4's; no signing here) ----

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
      timeout:  (opts && opts.timeoutMs) || 30000,
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

// ---- JWT signing for service-account auth ----

function _base64UrlEncode(buf) {
  return Buffer.from(buf).toString("base64")
    .replace(/=+$/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function _signJwt(serviceAccount, scope, audience) {
  var nowSec = Math.floor(Date.now() / 1000);
  var header = { alg: "RS256", typ: "JWT" };
  var claim = {
    iss:   serviceAccount.client_email,
    scope: scope,
    aud:   audience || TOKEN_ENDPOINT,
    iat:   nowSec,
    exp:   nowSec + 3600,
  };
  var headerB64 = _base64UrlEncode(JSON.stringify(header));
  var claimB64  = _base64UrlEncode(JSON.stringify(claim));
  var signingInput = headerB64 + "." + claimB64;

  var signer = nodeCrypto.createSign("RSA-SHA256");
  signer.update(signingInput);
  signer.end();
  var signature = signer.sign(serviceAccount.private_key);
  return signingInput + "." + _base64UrlEncode(signature);
}

// ---- Public adapter factory ----

function create(config) {
  if (!config) throw new Error("gcs protocol requires config");
  if (!config.bucket) throw new Error("gcs: bucket is required");

  var serviceAccount = config.serviceAccount;
  if (!serviceAccount && config.serviceAccountFile) {
    try {
      serviceAccount = JSON.parse(fs.readFileSync(config.serviceAccountFile, "utf8"));
    } catch (e) {
      throw new Error("gcs: failed to read serviceAccountFile '" + config.serviceAccountFile + "': " + e.message);
    }
  }
  if (!serviceAccount || !serviceAccount.client_email || !serviceAccount.private_key) {
    throw new Error("gcs: serviceAccount with { client_email, private_key } is required (or serviceAccountFile pointing to one)");
  }

  var endpoint = config.endpoint || DEFAULT_ENDPOINT;
  if (endpoint.endsWith("/")) endpoint = endpoint.slice(0, -1);
  var tokenEndpoint = config.tokenEndpoint || TOKEN_ENDPOINT;
  var bucket    = config.bucket;
  var scope     = config.scope || DEFAULT_SCOPE;
  var timeoutMs = config.timeoutMs;

  // ---- Token cache ----
  var cachedToken = null;       // { accessToken, expiresAt }

  async function _ensureToken() {
    if (cachedToken && Date.now() < cachedToken.expiresAt - TOKEN_REFRESH_BUFFER) {
      return cachedToken.accessToken;
    }
    var assertion = _signJwt(serviceAccount, scope, tokenEndpoint);
    var bodyStr = "grant_type=" + encodeURIComponent("urn:ietf:params:oauth:grant-type:jwt-bearer") +
                  "&assertion=" + encodeURIComponent(assertion);
    var bodyBuf = Buffer.from(bodyStr, "utf8");
    var res = await _httpRequest(
      "POST",
      new URL(tokenEndpoint),
      {
        "Content-Type":   "application/x-www-form-urlencoded",
        "Content-Length": String(bodyBuf.length),
      },
      bodyBuf,
      { timeoutMs: timeoutMs }
    );
    var json = JSON.parse(res.body.toString("utf8"));
    if (!json.access_token) {
      throw _err("AUTH_FAILED", "GCS token endpoint returned no access_token: " + res.body.toString("utf8"), true);
    }
    var expiresInMs = (json.expires_in || 3600) * 1000;
    cachedToken = {
      accessToken: json.access_token,
      expiresAt:   Date.now() + expiresInMs,
    };
    return cachedToken.accessToken;
  }

  function _objectUrl(key, params) {
    var u = new URL(endpoint + "/storage/v1/b/" + encodeURIComponent(bucket) +
                    "/o/" + encodeURIComponent(key));
    if (params) {
      Object.keys(params).forEach(function (k) { u.searchParams.set(k, params[k]); });
    }
    return u;
  }

  function _uploadUrl(key) {
    var u = new URL(endpoint + "/upload/storage/v1/b/" + encodeURIComponent(bucket) + "/o");
    u.searchParams.set("uploadType", "media");
    u.searchParams.set("name", key);
    return u;
  }

  function _listUrl(prefix, opts) {
    var u = new URL(endpoint + "/storage/v1/b/" + encodeURIComponent(bucket) + "/o");
    if (prefix)                      u.searchParams.set("prefix", prefix);
    if (opts && opts.maxResults)     u.searchParams.set("maxResults", String(opts.maxResults));
    if (opts && opts.pageToken)      u.searchParams.set("pageToken", opts.pageToken);
    return u;
  }

  // ---- Operations ----

  async function put(key, body, opts) {
    var token = await _ensureToken();
    var url = _uploadUrl(key);
    var buf = Buffer.isBuffer(body) ? body : Buffer.from(typeof body === "string" ? body : "", "utf8");
    var contentType = (opts && opts.contentType) || "application/octet-stream";
    var res = await _httpRequest("POST", url, {
      "Authorization":  "Bearer " + token,
      "Content-Type":   contentType,
      "Content-Length": String(buf.length),
    }, buf, { timeoutMs: timeoutMs });
    var meta = JSON.parse(res.body.toString("utf8"));
    return { size: parseInt(meta.size || buf.length, 10), etag: meta.etag };
  }

  async function get(key) {
    var token = await _ensureToken();
    var url = _objectUrl(key, { alt: "media" });
    var res = await _httpRequest("GET", url, { "Authorization": "Bearer " + token }, null, { timeoutMs: timeoutMs });
    return res.body;
  }

  function getStream(key) {
    return Readable.from(get(key));
  }

  async function head(key) {
    var token = await _ensureToken();
    var url = _objectUrl(key);
    var res = await _httpRequest("GET", url, { "Authorization": "Bearer " + token }, null, { timeoutMs: timeoutMs });
    var meta = JSON.parse(res.body.toString("utf8"));
    return {
      size:         parseInt(meta.size, 10),
      etag:         meta.etag,
      lastModified: meta.updated ? Date.parse(meta.updated) : null,
    };
  }

  async function deleteKey(key) {
    var token = await _ensureToken();
    var url = _objectUrl(key);
    try {
      await _httpRequest("DELETE", url, { "Authorization": "Bearer " + token }, null, { timeoutMs: timeoutMs });
      return true;
    } catch (e) {
      if (e.statusCode === 404) return false;
      throw e;
    }
  }

  async function list(prefix, opts) {
    opts = opts || {};
    var token = await _ensureToken();
    var url = _listUrl(prefix, { maxResults: opts.maxResults, pageToken: opts.continuationToken });
    var res = await _httpRequest("GET", url, { "Authorization": "Bearer " + token }, null, { timeoutMs: timeoutMs });
    var json = JSON.parse(res.body.toString("utf8"));
    var items = (json.items || []).map(function (item) {
      return {
        key:          item.name,
        size:         parseInt(item.size, 10),
        lastModified: item.updated ? Date.parse(item.updated) : null,
      };
    });
    return {
      items:             items,
      truncated:         !!json.nextPageToken,
      continuationToken: json.nextPageToken || null,
    };
  }

  return {
    protocol:  "gcs",
    endpoint:  endpoint,
    bucket:    bucket,
    put:       put,
    get:       get,
    getStream: getStream,
    head:      head,
    delete:    deleteKey,
    list:      list,
    // Internal accessors for tests
    _ensureToken: _ensureToken,
    _signJwt:     function () { return _signJwt(serviceAccount, scope, TOKEN_ENDPOINT); },
  };
}

module.exports = {
  create:                create,
  _signJwt:              _signJwt,
  _base64UrlEncode:      _base64UrlEncode,
  DEFAULT_ENDPOINT:      DEFAULT_ENDPOINT,
  TOKEN_ENDPOINT:        TOKEN_ENDPOINT,
  DEFAULT_SCOPE:         DEFAULT_SCOPE,
};
