"use strict";
/**
 * api-encrypt — end-to-end PQC payload encryption for operator-
 * controlled clients.
 *
 * TLS protects browser ↔ load-balancer; api-encrypt protects request
 * and response bodies *end-to-end* through every intermediate hop
 * (LB → app cleartext segment, sidecar proxy, queue, log aggregator,
 * APM tooling). A tampered byte anywhere downstream of the encrypted
 * boundary fails the AEAD tag at this middleware before the route
 * handler runs.
 *
 * Threat model targets:
 *   - Stripped-or-MITM TLS at any internal hop
 *   - Body capture at log aggregators / APM tooling
 *   - Replay (timestamp + nonce window catches it)
 *   - Forged client requests (no key holder = no valid ciphertext)
 *
 * What it does NOT defend against:
 *   - Semantic attacks from authorized clients (a key-holder can
 *     encrypt a malicious payload validly — safe-schema is the next
 *     layer)
 *   - Server-side key compromise
 *   - Application logic bugs in handlers
 *
 * The encryption layer is for operator-controlled clients (your
 * mobile app, your service-to-service traffic). Public APIs that
 * accept third-party callers should use TLS + webhook signatures
 * instead — the encryption requires a key bootstrap step.
 *
 * Wire format (request body, JSON):
 *
 *   {
 *     _ek:    "<base64 envelope>",   // session key wrapped to server pubkey
 *     _ct:    "<base64 packed>",     // payload encrypted with session key
 *     _ts:    1738000000000,         // unix ms
 *     _nonce: "<32 hex>"             // 16 random bytes, replay-checked
 *   }
 *
 * Wire format (response body, JSON):
 *
 *   { _ct: "<base64 packed>" }       // same session key, fresh nonce
 *
 * Crypto:
 *   - _ek is the framework's standard envelope encrypt:
 *       ML-KEM-1024 + P-384 ECDH hybrid → SHAKE256 KDF → XChaCha20-Poly1305
 *     The plaintext inside the envelope is the base64-encoded session key.
 *   - _ct is the framework's encryptPacked symmetric format:
 *       1-byte version + 24-byte XChaCha20-Poly1305 nonce + ciphertext + tag
 *     Keyed by the session key recovered from _ek.
 *
 * Operator API:
 *
 *   var apiEncrypt = b.middleware.apiEncrypt({
 *     keypair:        { publicKey, privateKey, ecPublicKey, ecPrivateKey },
 *     replayWindowMs: C.TIME.minutes(5),
 *     nonceStore:     b.nonceStore.create({ backend: 'cluster' }),
 *     exemptPaths:    ["/healthz", "/.well-known/blamejs-pubkey"],
 *     contentTypes:   ["application/json"],   // default; pass null to disable
 *   });
 *   router.use(apiEncrypt);
 *   router.get("/.well-known/blamejs-pubkey", apiEncrypt.publishPublicKey());
 *
 *   // Outbound (server-to-server, browser/mobile, etc.):
 *   var client = b.middleware.apiEncrypt.client({ pubkey });
 *   var { body, decryptResponse } = client.encryptRequest({ msg: "hi" });
 *
 *   // Server-to-server with framework HTTP client:
 *   var enc = b.httpClient.encrypted({ pubkey, baseUrl: "https://service" });
 *   var resp = await enc.request({ method: "POST", path: "/api/widget", body: { ... } });
 *
 * Key rotation:
 *   To rotate the server keypair, generate a new keypair and pass BOTH
 *   the new and the previous keypair to the middleware as `keypairs`:
 *
 *     b.middleware.apiEncrypt({
 *       keypairs: [newKeypair, prevKeypair],
 *       ...
 *     });
 *
 *   keypairs[0] is the "active" keypair — published by publishPublicKey()
 *   so new client-side bootstraps pin to it. Both keypairs are tried
 *   when decrypting `_ek`, so in-flight requests still encrypted to the
 *   previous keypair continue to decrypt for as long as the previous
 *   keypair stays in the array. Operators drop the previous keypair
 *   from the array once the rotation overlap window has elapsed.
 *
 * Failure surfacing:
 *   AEAD tag failure / stale timestamp / replay / malformed envelope
 *   all return 400 with the same body { error: "encrypted-payload-rejected" }.
 *   The category that actually matched lands in the audit event +
 *   b.events.API_ENCRYPT_FAILURE so operators get metrics / alerting
 *   without leaking which check the attacker tripped. Missing _ek /
 *   _ct / _ts / _nonce on a non-exempt path is distinguishable in the
 *   response ("encrypted-payload-required") so operators with hybrid
 *   public/private routes can debug their wiring.
 */

var crypto = require("../crypto");
var C = require("../constants");
var lazyRequire = require("../lazy-require");
var nonceStoreLib = require("../nonce-store");
var validateOpts = require("../validate-opts");
var { defineClass } = require("../framework-error");

var audit      = lazyRequire(function () { return require("../audit"); });
var events     = lazyRequire(function () { return require("../events"); });
var httpClient = lazyRequire(function () { return require("../http-client"); });
var logger     = lazyRequire(function () { return require("../log").boot("api-encrypt"); });

var ApiEncryptError = defineClass("ApiEncryptError", { withStatusCode: true });

var DEFAULT_REPLAY_WINDOW_MS = C.TIME.minutes(5);
var DEFAULT_CONTENT_TYPES = ["application/json"];
var SESSION_KEY_BYTES = 32;
var REQUEST_NONCE_BYTES = 16;

function _err(code, message, statusCode) {
  return new ApiEncryptError(code, message, true, statusCode || 400);
}

function _validateKeypair(kp, label) {
  if (!kp || typeof kp !== "object") {
    throw _err("INVALID_KEYPAIR", "apiEncrypt: " + label + " is required", 500);
  }
  if (typeof kp.publicKey !== "string" || typeof kp.privateKey !== "string") {
    throw _err("INVALID_KEYPAIR",
      "apiEncrypt: " + label + ".publicKey + .privateKey are required (ML-KEM-1024 PEM)", 500);
  }
  if (typeof kp.ecPublicKey !== "string" || typeof kp.ecPrivateKey !== "string") {
    throw _err("INVALID_KEYPAIR",
      "apiEncrypt: " + label + ".ecPublicKey + .ecPrivateKey are required (P-384 PEM hybrid)", 500);
  }
}

// Resolve the operator's keypair input into an ordered array. The
// first keypair is "active" — used by publishPublicKey() and as the
// hint for response encryption (responses use the per-request session
// key, so the active keypair only matters for what the bootstrap
// endpoint advertises). Every keypair in the array is tried in order
// when decrypting `_ek` so that during a rotation overlap window,
// in-flight requests encrypted to a previous keypair still decrypt
// successfully.
function _resolveKeypairs(opts) {
  if (Array.isArray(opts.keypairs)) {
    if (opts.keypairs.length === 0) {
      throw _err("INVALID_KEYPAIR", "apiEncrypt: keypairs must be a non-empty array", 500);
    }
    opts.keypairs.forEach(function (kp, i) { _validateKeypair(kp, "keypairs[" + i + "]"); });
    return opts.keypairs.slice();
  }
  if (opts.keypair) {
    _validateKeypair(opts.keypair, "keypair");
    return [opts.keypair];
  }
  throw _err("INVALID_KEYPAIR",
    "apiEncrypt: { keypair } or { keypairs: [...] } is required", 500);
}

function _writeRejection(res, code, body) {
  if (res.headersSent || res.writableEnded) return;
  if (typeof res.writeHead === "function") {
    res.writeHead(code, { "Content-Type": "application/json" });
    res.end(JSON.stringify(body));
  }
}

// ---- Server-side middleware ----

function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "keypair", "keypairs", "replayWindowMs", "pruneIntervalMs",
    "nonceStore", "exemptPaths", "contentTypes", "audit",
  ], "middleware.apiEncrypt");
  var keypairs       = _resolveKeypairs(opts);
  var activeKeypair  = keypairs[0];
  var replayWindowMs = opts.replayWindowMs || DEFAULT_REPLAY_WINDOW_MS;
  // The spec calls for a sweep cadence of replayWindowMs/2 — short
  // enough that expired nonces don't pile up but not so frequent the
  // sweep query becomes a hot path. Operators can override.
  var pruneIntervalMs = opts.pruneIntervalMs != null
    ? opts.pruneIntervalMs : Math.max(C.TIME.seconds(30), Math.floor(replayWindowMs / 2));
  var nonceStore     = opts.nonceStore || nonceStoreLib.create({ backend: "memory" });
  var exemptPaths    = Array.isArray(opts.exemptPaths) ? opts.exemptPaths.slice() : [];
  // contentTypes scoping — middleware only operates on requests whose
  // Content-Type is in this list. Default JSON; operators with more
  // exotic clients (form-encoded, gRPC-web, etc.) widen the list.
  // Set to null/false/empty array to disable content-type filtering
  // (treat every non-exempt request as encrypted).
  var contentTypes   = opts.contentTypes === null || opts.contentTypes === false
    ? null
    : (Array.isArray(opts.contentTypes) && opts.contentTypes.length > 0
        ? opts.contentTypes.slice()
        : DEFAULT_CONTENT_TYPES.slice());
  var auditOn        = opts.audit !== false;
  var lastPruneAt    = 0;

  function _isExempt(req) {
    var p = req.pathname || (req.url || "/").split("?")[0];
    for (var i = 0; i < exemptPaths.length; i++) {
      var rule = exemptPaths[i];
      if (typeof rule === "string" ? p === rule || p.indexOf(rule + "/") === 0 : rule.test(p)) {
        return true;
      }
    }
    return false;
  }

  function _matchesContentType(req) {
    if (!contentTypes) return true;  // filtering disabled
    var ct = req.headers && (req.headers["content-type"] || req.headers["Content-Type"]);
    if (typeof ct !== "string") return false;
    // Strip parameters like "; charset=utf-8"
    var bare = ct.split(";")[0].trim().toLowerCase();
    for (var i = 0; i < contentTypes.length; i++) {
      if (contentTypes[i].toLowerCase() === bare) return true;
    }
    return false;
  }

  function _emitFailure(req, reason) {
    var info = {
      reason:    reason,
      ip:        (req.socket && req.socket.remoteAddress) || null,
      path:      req.pathname || (req.url || "/").split("?")[0],
      method:    req.method,
      ts:        new Date().toISOString(),
      requestId: req.requestId || null,
    };
    if (auditOn) {
      audit().safeEmit({
        actor:    { ip: info.ip },
        action:   "system.api_encrypt.failure",
        outcome:  "denied",
        reason:   reason,
        metadata: { reason: reason, path: info.path, method: info.method },
        requestId: info.requestId,
      });
    }
    try { events().emit(events().EVENTS.API_ENCRYPT_FAILURE, info); }
    catch (_e) { /* events best-effort */ }
  }

  function _maybePrune() {
    var now = Date.now();
    if (now - lastPruneAt < pruneIntervalMs) return;
    lastPruneAt = now;
    nonceStore.purgeExpired().catch(function (e) {
      try {
        logger().warn("nonce-store prune failed: " + ((e && e.message) || String(e)));
      } catch (_e) { /* logger best-effort */ }
    });
  }

  function _wrapResJson(res, sessionKey) {
    var origJson = res.json;
    res.json = function (data) {
      try {
        var ptBuf = Buffer.from(JSON.stringify(data), "utf8");
        var ctBuf = crypto.encryptPacked(ptBuf, sessionKey);
        var encrypted = { _ct: ctBuf.toString("base64") };
        if (typeof origJson === "function") {
          return origJson.call(res, encrypted);
        }
        // Fallback if router didn't install res.json yet.
        if (!res.headersSent) {
          res.writeHead(res.statusCode || 200, { "Content-Type": "application/json" });
        }
        res.end(JSON.stringify(encrypted));
      } catch (e) {
        try {
          logger().error("response encryption failed: " + ((e && e.message) || String(e)));
        } catch (_e) {}
        if (!res.headersSent) {
          res.writeHead(500, { "Content-Type": "application/json" });
        }
        res.end(JSON.stringify({ error: "response-encryption-failed" }));
      }
    };
  }

  async function middleware(req, res, next) {
    if (_isExempt(req)) return next();
    if (!_matchesContentType(req)) return next();

    var body = req.body;
    if (!body || typeof body !== "object") {
      _emitFailure(req, "shape");
      return _writeRejection(res, 400, { error: "encrypted-payload-required" });
    }
    var ek = body._ek, ct = body._ct, ts = body._ts, nonce = body._nonce;
    if (typeof ek !== "string" || typeof ct !== "string" ||
        typeof ts !== "number" || typeof nonce !== "string") {
      _emitFailure(req, "shape");
      return _writeRejection(res, 400, { error: "encrypted-payload-required" });
    }

    // Replay window — must be within ±replayWindowMs of server clock.
    var now = Date.now();
    if (Math.abs(now - ts) > replayWindowMs) {
      _emitFailure(req, "stale");
      return _writeRejection(res, 400, { error: "encrypted-payload-rejected" });
    }

    // Nonce check + insert atomically. Loser of the insert race
    // (= already-seen nonce within the replay window) is a replay.
    // Hash the nonce before storage so a leaked DB / table dump
    // doesn't reveal the original 16-byte client nonces (the spec's
    // "sealed nonce hash"). SHA3 is deterministic so PRIMARY KEY
    // conflict detection still works.
    var nonceHash = crypto.sha3Hash(nonce, "hex");
    var expireAt = now + replayWindowMs;
    var freshNonce;
    try { freshNonce = await nonceStore.checkAndInsert(nonceHash, expireAt); }
    catch (_e) {
      _emitFailure(req, "nonce-store-error");
      return _writeRejection(res, 500, { error: "nonce-store-unavailable" });
    }
    if (!freshNonce) {
      _emitFailure(req, "replay");
      return _writeRejection(res, 400, { error: "encrypted-payload-rejected" });
    }

    // Decrypt _ek → session key. During a rotation overlap window,
    // some clients still hold the previous server pubkey — try each
    // keypair in order. The active keypair is keypairs[0]; older
    // rotated-out keypairs follow. AEAD failure on every keypair =
    // genuine bad ciphertext.
    var sessionKey = null;
    for (var ki = 0; ki < keypairs.length; ki++) {
      try {
        var sessionKeyB64 = crypto.decrypt(ek, keypairs[ki]);
        var candidate = Buffer.from(sessionKeyB64, "base64");
        if (candidate.length === SESSION_KEY_BYTES) {
          sessionKey = candidate;
          break;
        }
      } catch (_e) { /* try next keypair */ }
    }
    if (!sessionKey) {
      _emitFailure(req, "tag");
      return _writeRejection(res, 400, { error: "encrypted-payload-rejected" });
    }

    // Decrypt _ct → cleartext payload bytes → JSON object.
    var clearObj;
    try {
      var ctBuf = Buffer.from(ct, "base64");
      var ptBuf = crypto.decryptPacked(ctBuf, sessionKey);
      clearObj = JSON.parse(ptBuf.toString("utf8"));
    } catch (_e) {
      _emitFailure(req, "tag");
      return _writeRejection(res, 400, { error: "encrypted-payload-rejected" });
    }

    // Replace req.body with cleartext, stash session key for any
    // operator code that wants to attach extra encrypted side-channel
    // data (e.g. send a follow-up encrypted SSE event).
    req.body = clearObj;
    req.apiEncryptSessionKey = sessionKey;

    _wrapResJson(res, sessionKey);
    _maybePrune();

    return next();
  }

  // Route handler that publishes the server's public keys for client
  // bootstrap. Returns the PEM strings + KEM ID + a stable cache hint
  // so clients can pin / rotate based on the published keys.
  function publishPublicKey() {
    return function publishHandler(_req, res) {
      var body = {
        publicKey:    activeKeypair.publicKey,
        ecPublicKey:  activeKeypair.ecPublicKey,
        kemId:        C.ACTIVE.KEM,
        cipherId:     C.ACTIVE.CIPHER,
        kdfId:        C.ACTIVE.KDF,
      };
      if (typeof res.json === "function") return res.json(body);
      if (!res.headersSent) {
        res.writeHead(200, { "Content-Type": "application/json" });
      }
      res.end(JSON.stringify(body));
    };
  }

  middleware.publishPublicKey = publishPublicKey;
  middleware.close = function () {
    if (typeof nonceStore.close === "function") nonceStore.close();
  };

  return middleware;
}

// ---- Client-side helper ----
//
// Operators import this in their browser/mobile/native code or in
// service-to-service callers. The pubkey shape MUST match what
// publishPublicKey() returns: { publicKey, ecPublicKey, kemId,
// cipherId, kdfId }.

function client(opts) {
  opts = opts || {};
  validateOpts(opts, ["pubkey"], "middleware.apiEncrypt.client");
  if (!opts.pubkey || typeof opts.pubkey !== "object") {
    throw _err("CLIENT_INVALID_PUBKEY",
      "apiEncrypt.client: opts.pubkey is required ({ publicKey, ecPublicKey })", 500);
  }
  if (typeof opts.pubkey.publicKey !== "string" ||
      typeof opts.pubkey.ecPublicKey !== "string") {
    throw _err("CLIENT_INVALID_PUBKEY",
      "apiEncrypt.client: pubkey.publicKey + ecPublicKey must be PEM strings", 500);
  }
  var pubkey = opts.pubkey;

  function encryptRequest(payload) {
    if (payload === undefined) payload = null;
    var sessionKey = crypto.generateBytes(SESSION_KEY_BYTES);
    var ek = crypto.encrypt(sessionKey.toString("base64"), pubkey);
    var ptBuf = Buffer.from(JSON.stringify(payload), "utf8");
    var ctBuf = crypto.encryptPacked(ptBuf, sessionKey);
    var requestNonce = crypto.generateBytes(REQUEST_NONCE_BYTES).toString("hex");
    var ts = Date.now();
    return {
      body: {
        _ek:    ek,
        _ct:    ctBuf.toString("base64"),
        _ts:    ts,
        _nonce: requestNonce,
      },
      // Captured-closure decrypt — safe to pass back to the caller.
      // sessionKey lives only in this closure; once the closure goes
      // out of scope it can be garbage-collected.
      decryptResponse: function (responseBody) {
        if (!responseBody || typeof responseBody !== "object" ||
            typeof responseBody._ct !== "string") {
          throw _err("CLIENT_RESPONSE_SHAPE",
            "apiEncrypt.client: response missing _ct field");
        }
        var resCtBuf = Buffer.from(responseBody._ct, "base64");
        var resPtBuf = crypto.decryptPacked(resCtBuf, sessionKey);
        return JSON.parse(resPtBuf.toString("utf8"));
      },
    };
  }

  return { encryptRequest: encryptRequest };
}

// ---- Server-to-server convenience ----
//
// Wraps the framework's HTTP client so service-to-service callers
// don't have to juggle encryptRequest + httpClient.request +
// JSON parsing + decryptResponse on every call. The pubkey is the
// callee's public bootstrap document (the JSON `publishPublicKey()`
// returns) so this helper works between any two blamejs instances.
//
//   var enc = b.httpClient.encrypted({
//     pubkey:  callee.pubkey,           // { publicKey, ecPublicKey }
//     baseUrl: "https://callee.example",
//     headers: { Authorization: "Bearer ..." },
//   });
//   var resp = await enc.request({
//     method: "POST",
//     path:   "/api/widget",
//     body:   { user: "alice" },
//   });
//   resp.body  // → decrypted plaintext object
//
// The helper handles only JSON-shaped request/response payloads,
// matching the middleware's contentTypes default.
function httpClientEncrypted(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "pubkey", "baseUrl", "headers", "method",
  ], "middleware.apiEncrypt.httpClient");
  if (!opts.pubkey) {
    throw _err("CLIENT_INVALID_PUBKEY",
      "httpClient.encrypted: opts.pubkey is required (the callee's bootstrap doc)", 500);
  }
  var clientCtx     = client({ pubkey: opts.pubkey });
  var baseUrl       = opts.baseUrl ? String(opts.baseUrl).replace(/\/$/, "") : "";
  var defaultHdrs   = opts.headers || {};
  var defaultMethod = opts.method  || "POST";

  function _resolveUrl(reqOpts) {
    if (typeof reqOpts.url === "string" && reqOpts.url.length > 0) return reqOpts.url;
    if (typeof reqOpts.path === "string" && reqOpts.path.length > 0) {
      if (!baseUrl) {
        throw _err("CLIENT_INVALID_URL",
          "httpClient.encrypted.request: { path } requires opts.baseUrl at create time", 500);
      }
      return baseUrl + (reqOpts.path[0] === "/" ? reqOpts.path : "/" + reqOpts.path);
    }
    throw _err("CLIENT_INVALID_URL",
      "httpClient.encrypted.request: requires { url } or { path } (with opts.baseUrl)", 500);
  }

  async function request(reqOpts) {
    reqOpts = reqOpts || {};
    var url = _resolveUrl(reqOpts);
    var encrypted = clientCtx.encryptRequest(
      reqOpts.body !== undefined ? reqOpts.body : null
    );

    // Merge headers — operator's per-request headers win over default
    // headers, but Content-Type is forced because the encrypted body
    // is always JSON.
    var headers = Object.assign({}, defaultHdrs, reqOpts.headers || {});
    headers["Content-Type"] = "application/json";

    var passThrough = {};
    var passable = ["allowedProtocols", "idleTimeoutMs", "maxResponseBytes",
                    "agent", "errorClass"];
    for (var i = 0; i < passable.length; i++) {
      if (reqOpts[passable[i]] !== undefined) passThrough[passable[i]] = reqOpts[passable[i]];
    }

    var rawBody = Buffer.from(JSON.stringify(encrypted.body), "utf8");
    var resp = await httpClient().request(Object.assign({
      url:     url,
      method:  reqOpts.method || defaultMethod,
      headers: headers,
      body:    rawBody,
    }, passThrough));

    // Empty body → no decryption (e.g. 204 No Content).
    if (!resp.body || resp.body.length === 0) {
      return { statusCode: resp.statusCode, headers: resp.headers, body: null };
    }
    var parsed;
    try { parsed = JSON.parse(resp.body.toString("utf8")); }
    catch (e) {
      throw _err("CLIENT_RESPONSE_NOT_JSON",
        "httpClient.encrypted: response body is not valid JSON: " + e.message);
    }
    return {
      statusCode: resp.statusCode,
      headers:    resp.headers,
      body:       encrypted.decryptResponse(parsed),
    };
  }

  return { request: request };
}

module.exports = Object.assign(create, {
  client:           client,
  httpClient:       httpClientEncrypted,
  ApiEncryptError:  ApiEncryptError,
});
