"use strict";
/**
 * SigV4 protocol adapter — AWS Signature Version 4.
 *
 * One signing implementation covers the entire S3-API-compatible family:
 *   AWS S3, Cloudflare R2, Backblaze B2 (S3 endpoint), MinIO, Wasabi,
 *   Tigris, DigitalOcean Spaces, IDrive e2, Linode Object Storage, Storj
 *   (S3 gateway). Service identifier is always "s3" for object storage.
 *
 * Config:
 *   {
 *     endpoint:        'https://s3.us-west-2.amazonaws.com'  // or R2/MinIO/etc.
 *     region:          'us-west-2'                            // required
 *     bucket:          'my-bucket'                            // required
 *     accessKeyId:     '...'                                  // required
 *     secretAccessKey: '...'                                  // required
 *     sessionToken:    '...'                                  // optional (STS)
 *     pathStyle:       false                                  // virtual-hosted
 *                                                             //  by default
 *     timeoutMs:       C.TIME.seconds(30)
 *   }
 *
 * Reference:
 *   https://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html
 */
var nodeCrypto = require("crypto");
var { URL } = require("url");
var http = require("http");
var https = require("https");
var { Readable } = require("stream");
var xmlSafe = require("./parsers/xml-safe");
var C = require("./constants");

// S3 list responses are commonly 1000-key paginated payloads — well above
// the parser's default 1 MiB / 10K element ceilings. These overrides
// give headroom for normal responses without uncapping the parser.
var LIST_PARSE_OPTS = {
  maxBytes:    C.BYTES.mib(8),
  maxElements: 50000,
};

function _arrayify(value) {
  // xml-safe maps multiple same-tag children to an array; a single child
  // stays as the bare object; zero children means the property is absent.
  // List traversal needs a uniform array, so normalize.
  if (value == null) return [];
  return Array.isArray(value) ? value : [value];
}

var SERVICE = "s3";
var ALGORITHM = "AWS4-HMAC-SHA256";

function _err(code, message, permanent, statusCode) {
  var e = new Error(message);
  e.code = code;
  e.permanent = !!permanent;
  e.statusCode = statusCode;
  e.isObjectStoreError = true;
  return e;
}

// ---- SigV4 primitives ----

function sha256Hex(buf) {
  return nodeCrypto.createHash("sha256").update(buf).digest("hex");
}
function hmacSha256(key, data) {
  return nodeCrypto.createHmac("sha256", key).update(data).digest();
}

// AWS-style URI encoding: same as RFC 3986 except path '/' may be preserved.
function awsUriEncode(str, encodeSlash) {
  var out = "";
  for (var i = 0; i < str.length; i++) {
    var c = str.charCodeAt(i);
    var ch = str.charAt(i);
    if ((c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A) ||
        (c >= 0x30 && c <= 0x39) ||
        ch === "-" || ch === "_" || ch === "." || ch === "~") {
      out += ch;
    } else if (ch === "/" && !encodeSlash) {
      out += "/";
    } else {
      var enc = encodeURIComponent(ch).replace(/!/g, "%21").replace(/\*/g, "%2A").replace(/'/g, "%27").replace(/\(/g, "%28").replace(/\)/g, "%29");
      out += enc;
    }
  }
  return out;
}

function canonicalQueryString(searchParams) {
  if (!searchParams || searchParams.toString() === "") return "";
  var pairs = [];
  searchParams.forEach(function (v, k) { pairs.push([k, v]); });
  pairs.sort(function (a, b) {
    if (a[0] < b[0]) return -1;
    if (a[0] > b[0]) return 1;
    if (a[1] < b[1]) return -1;
    if (a[1] > b[1]) return 1;
    return 0;
  });
  return pairs.map(function (p) {
    return awsUriEncode(p[0], true) + "=" + awsUriEncode(p[1], true);
  }).join("&");
}

function canonicalHeaders(headers) {
  var pairs = [];
  for (var k in headers) {
    if (headers[k] === undefined || headers[k] === null) continue;
    var lk = k.toLowerCase();
    var v = String(headers[k]).trim().replace(/\s+/g, " ");
    pairs.push([lk, v]);
  }
  pairs.sort(function (a, b) { return a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0; });
  var canon = "";
  var signed = [];
  for (var i = 0; i < pairs.length; i++) {
    canon += pairs[i][0] + ":" + pairs[i][1] + "\n";
    signed.push(pairs[i][0]);
  }
  return { canonical: canon, signed: signed.join(";") };
}

function canonicalRequest(method, urlObj, headers, payloadHash) {
  var canonHeaders = canonicalHeaders(headers);
  var path = urlObj.pathname;
  if (!path) path = "/";
  return [
    method.toUpperCase(),
    awsUriEncode(path, false),
    canonicalQueryString(urlObj.searchParams),
    canonHeaders.canonical,
    canonHeaders.signed,
    payloadHash,
  ].join("\n");
}

function stringToSign(amzDate, credentialScope, canonicalReq) {
  return [
    ALGORITHM,
    amzDate,
    credentialScope,
    sha256Hex(canonicalReq),
  ].join("\n");
}

function deriveSigningKey(secretAccessKey, dateStamp, region, service) {
  var kDate    = hmacSha256("AWS4" + secretAccessKey, dateStamp);
  var kRegion  = hmacSha256(kDate, region);
  var kService = hmacSha256(kRegion, service);
  return hmacSha256(kService, "aws4_request");
}

function _formatAmzDate(d) {
  var iso = d.toISOString().replace(/[-:]/g, "");
  return iso.slice(0, 8) + "T" + iso.slice(9, 15) + "Z";
}
function _formatDateStamp(d) {
  return d.toISOString().slice(0, 10).replace(/-/g, "");
}

function signRequest(opts) {
  var date = opts.date || new Date();
  var amzDate = _formatAmzDate(date);
  var dateStamp = _formatDateStamp(date);
  var url = opts.url instanceof URL ? opts.url : new URL(opts.url);

  var headers = Object.assign({}, opts.headers || {});
  headers["host"] = url.host;
  headers["x-amz-date"] = amzDate;
  if (!headers["x-amz-content-sha256"]) {
    headers["x-amz-content-sha256"] = opts.payloadHash;
  }
  if (opts.sessionToken) {
    headers["x-amz-security-token"] = opts.sessionToken;
  }

  var canon = canonicalRequest(opts.method, url, headers, opts.payloadHash);
  var credentialScope = dateStamp + "/" + opts.region + "/" + SERVICE + "/aws4_request";
  var sts = stringToSign(amzDate, credentialScope, canon);
  var signingKey = deriveSigningKey(opts.secretAccessKey, dateStamp, opts.region, SERVICE);
  var signature = nodeCrypto.createHmac("sha256", signingKey).update(sts).digest("hex");

  var canonHeaders = canonicalHeaders(headers);
  var auth = ALGORITHM +
    " Credential=" + opts.accessKeyId + "/" + credentialScope +
    ", SignedHeaders=" + canonHeaders.signed +
    ", Signature=" + signature;
  headers["Authorization"] = auth;

  return { headers: headers, signature: signature, canonicalRequest: canon, stringToSign: sts };
}

// ---- HTTP request helper ----

function _request(method, url, headers, body, opts) {
  return new Promise(function (resolve, reject) {
    var u = url instanceof URL ? url : new URL(url);
    var lib = u.protocol === "https:" ? https : http;
    var reqOpts = {
      method:   method,
      hostname: u.hostname,
      port:     u.port || (u.protocol === "https:" ? 443 : 80),
      path:     u.pathname + (u.search || ""),
      headers:  headers,
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

// ---- Public adapter factory ----

function create(config) {
  if (!config) throw new Error("sigv4 protocol requires config");
  if (!config.region)          throw new Error("sigv4: region is required");
  if (!config.bucket)          throw new Error("sigv4: bucket is required");
  if (!config.accessKeyId)     throw new Error("sigv4: accessKeyId is required");
  if (!config.secretAccessKey) throw new Error("sigv4: secretAccessKey is required");

  var endpoint = config.endpoint || ("https://s3." + config.region + ".amazonaws.com");
  if (endpoint.endsWith("/")) endpoint = endpoint.slice(0, -1);
  var pathStyle = !!(config.pathStyle || config.forcePathStyle);

  function _keyToUrl(key) {
    if (key.indexOf("\0") !== -1) throw _err("INVALID_KEY", "null byte in key", true);
    var encoded = key.split("/").map(function (s) { return awsUriEncode(s, true); }).join("/");
    if (pathStyle) {
      return new URL(endpoint + "/" + config.bucket + "/" + encoded);
    }
    var u = new URL(endpoint);
    u.hostname = config.bucket + "." + u.hostname;
    u.pathname = "/" + encoded;
    return u;
  }

  function _bucketUrl(searchParams) {
    var u;
    if (pathStyle) {
      u = new URL(endpoint + "/" + config.bucket + "/");
    } else {
      u = new URL(endpoint);
      u.hostname = config.bucket + "." + u.hostname;
      u.pathname = "/";
    }
    if (searchParams) {
      Object.keys(searchParams).forEach(function (k) { u.searchParams.set(k, searchParams[k]); });
    }
    return u;
  }

  function _makeSigned(method, url, payloadHash, extraHeaders) {
    var signed = signRequest({
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

  function put(key, body, opts) {
    var url = _keyToUrl(key);
    var buf = Buffer.isBuffer(body) ? body : Buffer.from(typeof body === "string" ? body : "", "utf8");
    var payloadHash = sha256Hex(buf);
    var contentType = (opts && opts.contentType) || "application/octet-stream";
    var headers = _makeSigned("PUT", url, payloadHash, {
      "Content-Type":   contentType,
      "Content-Length": String(buf.length),
    });
    return _request("PUT", url, headers, buf, { timeoutMs: config.timeoutMs }).then(function (res) {
      return { size: buf.length, etag: res.headers.etag };
    });
  }

  function get(key) {
    var url = _keyToUrl(key);
    var headers = _makeSigned("GET", url, sha256Hex(Buffer.alloc(0)));
    return _request("GET", url, headers, null, { timeoutMs: config.timeoutMs }).then(function (res) {
      return res.body;
    });
  }

  function getStream(key) {
    return Readable.from(get(key));
  }

  function head(key) {
    var url = _keyToUrl(key);
    var headers = _makeSigned("HEAD", url, sha256Hex(Buffer.alloc(0)));
    return _request("HEAD", url, headers, null, { timeoutMs: config.timeoutMs }).then(function (res) {
      return {
        size:         res.headers["content-length"] ? parseInt(res.headers["content-length"], 10) : null,
        etag:         res.headers.etag,
        lastModified: res.headers["last-modified"] ? Date.parse(res.headers["last-modified"]) : null,
      };
    });
  }

  function deleteKey(key) {
    var url = _keyToUrl(key);
    var headers = _makeSigned("DELETE", url, sha256Hex(Buffer.alloc(0)));
    return _request("DELETE", url, headers, null, { timeoutMs: config.timeoutMs }).then(
      function () { return true; },
      function (e) { if (e.statusCode === 404) return false; throw e; }
    );
  }

  function list(prefix, opts) {
    opts = opts || {};
    var params = { "list-type": "2" };
    if (prefix) params["prefix"] = prefix;
    if (opts.maxResults) params["max-keys"] = String(opts.maxResults);
    if (opts.continuationToken) params["continuation-token"] = opts.continuationToken;

    var url = _bucketUrl(params);
    var headers = _makeSigned("GET", url, sha256Hex(Buffer.alloc(0)));
    return _request("GET", url, headers, null, { timeoutMs: config.timeoutMs }).then(function (res) {
      var doc = xmlSafe.parse(res.body, LIST_PARSE_OPTS);
      var result = doc.ListBucketResult || {};
      var contents = _arrayify(result.Contents);
      var items = contents.map(function (c) {
        return {
          key:          c.Key,
          size:         c.Size != null ? parseInt(c.Size, 10) : null,
          lastModified: c.LastModified ? Date.parse(c.LastModified) : null,
        };
      }).filter(function (it) { return it.key; });
      return {
        items:             items,
        truncated:         result.IsTruncated === "true",
        continuationToken: result.NextContinuationToken || null,
      };
    });
  }

  return {
    protocol:  "sigv4",
    endpoint:  endpoint,
    bucket:    config.bucket,
    region:    config.region,
    pathStyle: pathStyle,
    put:       put,
    get:       get,
    getStream: getStream,
    head:      head,
    delete:    deleteKey,
    list:      list,
  };
}

module.exports = {
  create:               create,
  signRequest:          signRequest,
  canonicalRequest:     canonicalRequest,
  stringToSign:         stringToSign,
  deriveSigningKey:     deriveSigningKey,
  canonicalQueryString: canonicalQueryString,
  canonicalHeaders:     canonicalHeaders,
  awsUriEncode:         awsUriEncode,
  sha256Hex:            sha256Hex,
  SERVICE:              SERVICE,
  ALGORITHM:            ALGORITHM,
};
