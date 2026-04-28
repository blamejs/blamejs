"use strict";
/**
 * b.webhook — outbound webhook signing + inbound verification.
 *
 *   var signer = b.webhook.signer({
 *     algo:       "hmac-sha3-512",
 *     keys:       { v1: secretBytes },
 *     defaultKid: "v1",
 *   });
 *
 *   await signer.send({ url: "https://example.com/hook", body: jsonString });
 *   // POSTs with:
 *   //   Webhook-Signature: t=<unix-seconds>,id=<uuid>,v1=<sig-hex>
 *
 *   var verifier = b.webhook.verifier({
 *     algo:        "hmac-sha3-512",
 *     keys:        { v1: secret, v0: oldSecret },     // multi-key for rotation
 *     toleranceMs: 5 * 60 * 1000,
 *     nonceStore:  b.nonceStore.create({ ... }),      // optional replay defense
 *   });
 *
 *   router.use(b.middleware.bodyParser({ keepRawBody: true }));   // REQUIRED
 *   router.post("/inbound-webhook", verifier.middleware(), function (req, res) {
 *     // req.webhook = { algo, kid, timestamp, id }
 *   });
 *
 * Algorithms:
 *   "hmac-sha3-512" — symmetric. keys: { kid → Buffer/string secret }
 *   "pqc-pem"       — asymmetric. keys map for signer:
 *                       { kid → { privateKey, publicKey } }   (PEM)
 *                     keys map for verifier:
 *                       { kid → publicKey }                   (PEM)
 *                     Algorithm (SLH-DSA-SHAKE-256f / ML-DSA-87) is
 *                     auto-detected by Node from the PEM. No classical
 *                     (Ed25519, RSA, ECDSA) signature scheme is exposed
 *                     here per CLAUDE.md PQC-first rule.
 *
 * Signed string (deterministic, prefix-bound to defend against algorithm-
 * substitution and key-substitution attacks):
 *
 *     <algo>.<kid>.<timestamp>.<id>.<body>
 *
 * Header format (single combined header, Stripe-shape):
 *
 *     Webhook-Signature: t=<unix-seconds>,id=<uuid>,<kid>=<sig-hex>
 *
 * `t` and `id` are reserved segment names; every other `<name>=<value>`
 * pair is treated as a kid → signature mapping. Multiple kid pairs are
 * accepted on the verifier side; the signer emits exactly one. Operators
 * rotating keys point the verifier at both old + new keys and migrate
 * signers progressively.
 *
 * Replay defense:
 *   - `id` is included in the signed string, so a captured signature
 *     cannot be reused with a fresh id.
 *   - Optional `nonceStore` records seen ids; second delivery with the
 *     same id rejects with REPLAY. The framework's b.nonceStore is the
 *     reference impl; operators plug in Redis/SQL by passing any object
 *     with `checkAndInsert(nonce, expireAt) → bool/Promise<bool>`.
 *
 * Validation tiers (per feedback_validation_tier_policy.md):
 *
 *   - signer/verifier creation opts → Tier A (throw)
 *   - signer.sign body type         → Tier A (throw)
 *   - signer.send url shape         → Tier A (throw via safeUrl)
 *   - verifier.verify input shape   → Tier A (throw WebhookError)
 *   - nonceStore.checkAndInsert err → propagates (fail-closed)
 */

var nodeCrypto = require("crypto");
var crypto = require("./crypto");
var httpClient = require("./http-client");
var safeUrl = require("./safe-url");
var retry = require("./retry");
var { WebhookError } = require("./framework-error");

var _err = WebhookError.factory;

// ---- Constants ----

var ALGOS = Object.freeze({
  HMAC_SHA3_512: "hmac-sha3-512",
  PQC_PEM:       "pqc-pem",
});

var HEADER = Object.freeze({
  SIGNATURE: "Webhook-Signature",
});

var DEFAULTS = Object.freeze({
  toleranceMs:     5 * 60 * 1000,    // 5 minutes
  clockSkewMs:     60 * 1000,        // 1 minute future tolerance
  signatureHeader: HEADER.SIGNATURE,
});

// ---- Tier-A validation helpers ----

function _isPositiveInt(n) {
  return typeof n === "number" && isFinite(n) && n >= 1 && Math.floor(n) === n;
}
function _isNonNegFinite(n) {
  return typeof n === "number" && isFinite(n) && n >= 0;
}
function _hasOwn(obj, k) { return Object.prototype.hasOwnProperty.call(obj, k); }
function _objectKeys(obj) { return Object.keys(obj); }

function _validateAlgo(algo) {
  if (algo !== ALGOS.HMAC_SHA3_512 && algo !== ALGOS.PQC_PEM) {
    throw _err("BAD_OPT", "webhook: algo must be one of " +
      JSON.stringify([ALGOS.HMAC_SHA3_512, ALGOS.PQC_PEM]) + ", got " + JSON.stringify(algo));
  }
}

function _validateKeysShape(name, algo, keys, side) {
  if (!keys || typeof keys !== "object" || Array.isArray(keys)) {
    throw _err("BAD_OPT", name + ": keys must be a non-empty object map of kid → key, got " +
      typeof keys);
  }
  var kids = _objectKeys(keys);
  if (kids.length === 0) {
    throw _err("BAD_OPT", name + ": keys must have at least one kid entry");
  }
  for (var i = 0; i < kids.length; i++) {
    var kid = kids[i];
    if (kid.length === 0 || /[,=\s]/.test(kid)) {
      throw _err("BAD_OPT", name + ": kid must be non-empty and contain no comma/equals/whitespace, got " +
        JSON.stringify(kid));
    }
    if (kid === "t" || kid === "id") {
      throw _err("BAD_OPT", name + ": kid '" + kid + "' is reserved (collides with header field)");
    }
    var k = keys[kid];
    if (algo === ALGOS.HMAC_SHA3_512) {
      if (!Buffer.isBuffer(k) && typeof k !== "string") {
        throw _err("BAD_OPT", name + ": HMAC key for kid '" + kid +
          "' must be a Buffer or string, got " + typeof k);
      }
      if (k.length === 0) {
        throw _err("BAD_OPT", name + ": HMAC key for kid '" + kid + "' must be non-empty");
      }
    } else if (algo === ALGOS.PQC_PEM) {
      if (side === "signer") {
        if (!k || typeof k !== "object" || Array.isArray(k) ||
            (typeof k.privateKey !== "string" && !Buffer.isBuffer(k.privateKey)) ||
            (typeof k.publicKey  !== "string" && !Buffer.isBuffer(k.publicKey))) {
          throw _err("BAD_OPT", name + ": PQC signer key for kid '" + kid +
            "' must be { privateKey, publicKey } as PEM strings/Buffers");
        }
      } else {
        if (typeof k !== "string" && !Buffer.isBuffer(k)) {
          throw _err("BAD_OPT", name + ": PQC verifier key for kid '" + kid +
            "' must be a PEM string/Buffer (public key)");
        }
      }
    }
  }
}

function _validateBody(body) {
  if (typeof body !== "string" && !Buffer.isBuffer(body)) {
    throw _err("BAD_BODY", "webhook: body must be a string or Buffer, got " + typeof body);
  }
}

// ---- Signed-string composition ----

function _composeSignedString(algo, kid, timestamp, id, body) {
  var prefix = algo + "." + kid + "." + timestamp + "." + id + ".";
  if (Buffer.isBuffer(body)) {
    return Buffer.concat([Buffer.from(prefix, "utf8"), body]);
  }
  return Buffer.from(prefix + body, "utf8");
}

// ---- Sign / verify primitives ----

function _hmacSign(key, data) {
  return crypto.hmacSha3(key, data);    // hex string
}

function _hmacVerify(key, data, expectedHex) {
  if (typeof expectedHex !== "string" || !/^[0-9a-fA-F]+$/.test(expectedHex)) return false;
  var actualHex = crypto.hmacSha3(key, data);
  return crypto.timingSafeEqual(actualHex, expectedHex);
}

function _pqcSign(privateKeyPem, data) {
  return crypto.sign(data, privateKeyPem).toString("hex");
}

function _pqcVerify(publicKeyPem, data, expectedHex) {
  if (typeof expectedHex !== "string" || expectedHex.length === 0 ||
      !/^[0-9a-fA-F]+$/.test(expectedHex) || (expectedHex.length % 2) !== 0) {
    return false;
  }
  var sigBuf;
  try { sigBuf = Buffer.from(expectedHex, "hex"); }
  catch (_e) { return false; }
  try { return crypto.verify(data, sigBuf, publicKeyPem); }
  catch (_e) { return false; }
}

// ---- Header parsing ----
//
// Format:  t=<seconds>,id=<uuid>,<kid>=<hex>[,<kid>=<hex>]*
// `t` and `id` are reserved segment names; everything else is treated as
// a kid → signature pair. Whitespace tolerated around commas.

function _parseSignatureHeader(headerValue) {
  var parts = headerValue.split(",");
  var t = null, id = null, sigs = {};
  for (var i = 0; i < parts.length; i++) {
    var seg = parts[i].trim();
    var eq = seg.indexOf("=");
    if (eq <= 0) continue;            // skip malformed segments rather than failing whole header
    var name = seg.slice(0, eq);
    var value = seg.slice(eq + 1);
    if (name === "t") t = value;
    else if (name === "id") id = value;
    else if (name.length > 0) sigs[name] = value;   // kid → sig hex
  }
  return { t: t, id: id, sigs: sigs };
}

// ---- Signer ----

function _validateSignerOpts(opts) {
  if (!opts || typeof opts !== "object") {
    throw _err("BAD_OPT", "webhook.signer: opts must be an object");
  }
  _validateAlgo(opts.algo);
  _validateKeysShape("webhook.signer", opts.algo, opts.keys, "signer");
  var kids = _objectKeys(opts.keys);
  if (opts.defaultKid !== undefined) {
    if (!_hasOwn(opts.keys, opts.defaultKid)) {
      throw _err("BAD_OPT", "webhook.signer: defaultKid '" + opts.defaultKid +
        "' not present in keys (have: " + JSON.stringify(kids) + ")");
    }
  } else if (kids.length > 1) {
    throw _err("BAD_OPT", "webhook.signer: defaultKid required when keys has " +
      kids.length + " entries");
  }
  if (opts.signatureHeader !== undefined &&
      (typeof opts.signatureHeader !== "string" || opts.signatureHeader.length === 0)) {
    throw _err("BAD_OPT", "webhook.signer: signatureHeader must be a non-empty string");
  }
  if (opts.idGenerator !== undefined && typeof opts.idGenerator !== "function") {
    throw _err("BAD_OPT", "webhook.signer: idGenerator must be a function or undefined");
  }
  if (opts.now !== undefined && typeof opts.now !== "function") {
    throw _err("BAD_OPT", "webhook.signer: now must be a function or undefined");
  }
}

function signer(opts) {
  _validateSignerOpts(opts);
  var algo = opts.algo;
  var keys = opts.keys;
  var kids = _objectKeys(keys);
  var defaultKid = opts.defaultKid || kids[0];
  var sigHeader = opts.signatureHeader || HEADER.SIGNATURE;
  var idGen = opts.idGenerator || function () { return crypto.generateToken(16); };
  var nowFn = opts.now || function () { return Date.now(); };
  var retryOpts = opts.retry || retry.DEFAULT_RETRY;
  var httpOpts = opts.http || {};

  function _signOne(body, kid) {
    _validateBody(body);
    var keyForKid = kids.indexOf(kid) === -1 ? null : keys[kid];
    if (keyForKid == null) {
      throw _err("BAD_OPT", "webhook.signer: unknown kid '" + kid + "'");
    }
    var timestamp = Math.floor(nowFn() / 1000);
    var id = idGen();
    if (typeof id !== "string" || id.length === 0 || /[,=\s]/.test(id)) {
      throw _err("BAD_OPT", "webhook.signer: idGenerator must return a non-empty string with no comma/equals/whitespace, got " + JSON.stringify(id));
    }
    var signed = _composeSignedString(algo, kid, timestamp, id, body);
    var sigHex;
    if (algo === ALGOS.HMAC_SHA3_512) {
      sigHex = _hmacSign(keyForKid, signed);
    } else {
      sigHex = _pqcSign(keyForKid.privateKey, signed);
    }
    return { kid: kid, timestamp: timestamp, id: id, signature: sigHex };
  }

  function sign(body, callOpts) {
    var kid = (callOpts && callOpts.kid) || defaultKid;
    var s = _signOne(body, kid);
    var headerValue = "t=" + s.timestamp + ",id=" + s.id + "," + s.kid + "=" + s.signature;
    var headers = {};
    headers[sigHeader] = headerValue;
    return {
      headers:   headers,
      timestamp: s.timestamp,
      id:        s.id,
      kid:       s.kid,
      signature: s.signature,
    };
  }

  function headers(body, callOpts) {
    return sign(body, callOpts).headers;
  }

  async function send(input) {
    if (!input || typeof input !== "object") {
      throw _err("BAD_OPT", "webhook.signer.send: input must be { url, body, headers? }");
    }
    var url = input.url;
    var body = input.body;
    safeUrl.parse(url, {
      allowedProtocols: httpOpts.allowedProtocols || safeUrl.ALLOW_HTTP_TLS,
      errorClass:       WebhookError,
    });
    _validateBody(body);
    var signed = sign(body, { kid: input.kid });
    var mergedHeaders = Object.assign({}, input.headers || {}, signed.headers);
    if (!mergedHeaders["Content-Type"] && !mergedHeaders["content-type"]) {
      mergedHeaders["Content-Type"] = Buffer.isBuffer(body)
        ? "application/octet-stream"
        : "application/json";
    }
    var requestOpts = Object.assign({
      method:           "POST",
      url:              url,
      headers:          mergedHeaders,
      body:             body,
      allowedProtocols: safeUrl.ALLOW_HTTP_TLS,
      errorClass:       WebhookError,
    }, httpOpts);
    requestOpts.headers = mergedHeaders;
    requestOpts.url = url;
    requestOpts.body = body;
    requestOpts.method = "POST";
    return retry.withRetry(function () {
      return httpClient.request(requestOpts);
    }, retryOpts);
  }

  return {
    sign:    sign,
    headers: headers,
    send:    send,
  };
}

// ---- Verifier ----

function _validateVerifierOpts(opts) {
  if (!opts || typeof opts !== "object") {
    throw _err("BAD_OPT", "webhook.verifier: opts must be an object");
  }
  _validateAlgo(opts.algo);
  _validateKeysShape("webhook.verifier", opts.algo, opts.keys, "verifier");
  if (opts.toleranceMs !== undefined && !_isNonNegFinite(opts.toleranceMs)) {
    throw _err("BAD_OPT", "webhook.verifier: toleranceMs must be a non-negative finite number");
  }
  if (opts.clockSkewMs !== undefined && !_isNonNegFinite(opts.clockSkewMs)) {
    throw _err("BAD_OPT", "webhook.verifier: clockSkewMs must be a non-negative finite number");
  }
  if (opts.signatureHeader !== undefined &&
      (typeof opts.signatureHeader !== "string" || opts.signatureHeader.length === 0)) {
    throw _err("BAD_OPT", "webhook.verifier: signatureHeader must be a non-empty string");
  }
  if (opts.nonceStore !== undefined && opts.nonceStore !== null) {
    if (typeof opts.nonceStore !== "object" ||
        typeof opts.nonceStore.checkAndInsert !== "function") {
      throw _err("BAD_OPT", "webhook.verifier: nonceStore must implement checkAndInsert(nonce, expireAt)");
    }
  }
  if (opts.now !== undefined && typeof opts.now !== "function") {
    throw _err("BAD_OPT", "webhook.verifier: now must be a function or undefined");
  }
}

function verifier(opts) {
  _validateVerifierOpts(opts);
  var algo = opts.algo;
  var keys = opts.keys;
  var toleranceMs = (opts.toleranceMs !== undefined) ? opts.toleranceMs : DEFAULTS.toleranceMs;
  var clockSkewMs = (opts.clockSkewMs !== undefined) ? opts.clockSkewMs : DEFAULTS.clockSkewMs;
  var sigHeader = (opts.signatureHeader || HEADER.SIGNATURE).toLowerCase();
  var nonceStore = opts.nonceStore || null;
  var nowFn = opts.now || function () { return Date.now(); };

  async function verify(input) {
    if (!input || typeof input !== "object") {
      throw _err("BAD_OPT", "webhook.verifier.verify: input must be { body, headers }");
    }
    var headers = input.headers;
    if (!headers || typeof headers !== "object") {
      throw _err("BAD_OPT", "webhook.verifier.verify: headers must be an object");
    }
    var body = input.body;
    _validateBody(body);

    // Headers may be node-style (lowercased keys) or operator-supplied
    // (mixed case). Resolve case-insensitively.
    var headerValue = null;
    var headerKeys = Object.keys(headers);
    for (var i = 0; i < headerKeys.length; i++) {
      if (headerKeys[i].toLowerCase() === sigHeader) {
        headerValue = headers[headerKeys[i]];
        break;
      }
    }
    if (typeof headerValue !== "string" || headerValue.length === 0) {
      throw _err("MISSING_HEADER", "webhook: " + (opts.signatureHeader || HEADER.SIGNATURE) + " header missing");
    }

    var parsed = _parseSignatureHeader(headerValue);
    if (parsed.t === null && parsed.id === null && Object.keys(parsed.sigs).length === 0) {
      throw _err("BAD_HEADER_FORMAT", "webhook: signature header could not be parsed");
    }
    if (parsed.t === null) {
      throw _err("MISSING_TIMESTAMP", "webhook: t= field missing from signature header");
    }
    var ts = Number(parsed.t);
    if (!isFinite(ts) || ts < 0 || Math.floor(ts) !== ts) {
      throw _err("BAD_TIMESTAMP", "webhook: t= field is not a non-negative integer, got " + JSON.stringify(parsed.t));
    }
    if (parsed.id === null || parsed.id.length === 0) {
      throw _err("MISSING_ID", "webhook: id= field missing from signature header");
    }
    var sigKids = Object.keys(parsed.sigs);
    if (sigKids.length === 0) {
      throw _err("MISSING_SIGNATURE", "webhook: no v<kid>= segment found in signature header");
    }

    // Timestamp window: signed in seconds, compare to ms clock.
    var nowMs = nowFn();
    var ageMs = nowMs - (ts * 1000);
    if (ageMs > toleranceMs) {
      throw _err("EXPIRED", "webhook: timestamp older than toleranceMs (age=" + ageMs + "ms)");
    }
    if (-ageMs > clockSkewMs) {
      throw _err("FUTURE", "webhook: timestamp in the future beyond clockSkewMs (skew=" + (-ageMs) + "ms)");
    }

    // Find the first kid the verifier holds a key for.
    var matchedKid = null;
    for (var j = 0; j < sigKids.length; j++) {
      if (_hasOwn(keys, sigKids[j])) { matchedKid = sigKids[j]; break; }
    }
    if (matchedKid === null) {
      throw _err("UNKNOWN_KID", "webhook: no registered key matches signed kids " +
        JSON.stringify(sigKids));
    }

    var signed = _composeSignedString(algo, matchedKid, ts, parsed.id, body);
    var ok;
    if (algo === ALGOS.HMAC_SHA3_512) {
      ok = _hmacVerify(keys[matchedKid], signed, parsed.sigs[matchedKid]);
    } else {
      ok = _pqcVerify(keys[matchedKid], signed, parsed.sigs[matchedKid]);
    }
    if (!ok) {
      throw _err("BAD_SIGNATURE", "webhook: cryptographic verification failed");
    }

    if (nonceStore) {
      var expireAt = (ts * 1000) + toleranceMs;
      var fresh = await nonceStore.checkAndInsert(parsed.id, expireAt);
      if (!fresh) {
        throw _err("REPLAY", "webhook: id '" + parsed.id + "' has been seen before");
      }
    }

    return { algo: algo, kid: matchedKid, timestamp: ts, id: parsed.id };
  }

  function middleware() {
    return function (req, res, next) {
      var raw = req.bodyRaw;
      if (raw === undefined) {
        if (Buffer.isBuffer(req.body)) raw = req.body;
        else if (typeof req.body === "string") raw = req.body;
      }
      if (raw === undefined) {
        return _writeError(res, 401, "MISSING_RAW_BODY",
          "webhook verifier middleware requires bodyParser({ keepRawBody: true })");
      }
      verify({ body: raw, headers: req.headers }).then(
        function (info) {
          req.webhook = info;
          next();
        },
        function (err) {
          if (err && err.isWebhookError) {
            _writeError(res, 401, err.code, err.message);
          } else {
            _writeError(res, 500, "VERIFY_ERROR", "webhook verification error");
          }
        }
      );
    };
  }

  return {
    verify:     verify,
    middleware: middleware,
  };
}

function _writeError(res, status, code, message) {
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8" });
  res.end(JSON.stringify({ error: code, message: message }));
}

// ---- Public surface ----

module.exports = {
  signer:       signer,
  verifier:     verifier,
  ALGOS:        ALGOS,
  HEADER:       HEADER,
  DEFAULTS:     DEFAULTS,
  WebhookError: WebhookError,
};
