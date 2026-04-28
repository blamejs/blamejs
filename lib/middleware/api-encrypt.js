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
 *   });
 *   router.use(apiEncrypt);
 *   router.get("/.well-known/blamejs-pubkey", apiEncrypt.publishPublicKey());
 *
 *   // Outbound (server-to-server, browser/mobile, etc.):
 *   var client = b.middleware.apiEncrypt.client({ pubkey });
 *   var { body, decryptResponse } = client.encryptRequest({ msg: "hi" });
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
var { defineClass } = require("../framework-error");

var audit  = lazyRequire(function () { return require("../audit"); });
var events = lazyRequire(function () { return require("../events"); });
var logger = lazyRequire(function () { return require("../log").boot("api-encrypt"); });

var ApiEncryptError = defineClass("ApiEncryptError", { withStatusCode: true });

var DEFAULT_REPLAY_WINDOW_MS = C.TIME.minutes(5);
var DEFAULT_PRUNE_INTERVAL_MS = C.TIME.minutes(2);
var SESSION_KEY_BYTES = 32;
var REQUEST_NONCE_BYTES = 16;

function _err(code, message, statusCode) {
  return new ApiEncryptError(code, message, true, statusCode || 400);
}

function _validateKeypair(kp) {
  if (!kp || typeof kp !== "object") {
    throw _err("INVALID_KEYPAIR", "apiEncrypt: { keypair } is required", 500);
  }
  if (typeof kp.publicKey !== "string" || typeof kp.privateKey !== "string") {
    throw _err("INVALID_KEYPAIR",
      "apiEncrypt: keypair.publicKey + .privateKey are required (ML-KEM-1024 PEM)", 500);
  }
  if (typeof kp.ecPublicKey !== "string" || typeof kp.ecPrivateKey !== "string") {
    throw _err("INVALID_KEYPAIR",
      "apiEncrypt: keypair.ecPublicKey + .ecPrivateKey are required (P-384 PEM hybrid)", 500);
  }
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
  _validateKeypair(opts.keypair);
  var keypair        = opts.keypair;
  var replayWindowMs = opts.replayWindowMs || DEFAULT_REPLAY_WINDOW_MS;
  var pruneIntervalMs = opts.pruneIntervalMs || DEFAULT_PRUNE_INTERVAL_MS;
  var nonceStore     = opts.nonceStore || nonceStoreLib.create({ backend: "memory" });
  var exemptPaths    = Array.isArray(opts.exemptPaths) ? opts.exemptPaths.slice() : [];
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
      try {
        audit().emit({
          actor:    { ip: info.ip },
          action:   "system.api_encrypt.failure",
          outcome:  "denied",
          reason:   reason,
          metadata: { reason: reason, path: info.path, method: info.method },
          requestId: info.requestId,
        });
      } catch (_e) { /* audit best-effort */ }
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
    var expireAt = now + replayWindowMs;
    var freshNonce;
    try { freshNonce = await nonceStore.checkAndInsert(nonce, expireAt); }
    catch (_e) {
      _emitFailure(req, "nonce-store-error");
      return _writeRejection(res, 500, { error: "nonce-store-unavailable" });
    }
    if (!freshNonce) {
      _emitFailure(req, "replay");
      return _writeRejection(res, 400, { error: "encrypted-payload-rejected" });
    }

    // Decrypt _ek → session key (base64-encoded inside the envelope).
    var sessionKey;
    try {
      var sessionKeyB64 = crypto.decrypt(ek, keypair);
      sessionKey = Buffer.from(sessionKeyB64, "base64");
      if (sessionKey.length !== SESSION_KEY_BYTES) {
        throw new Error("session key length " + sessionKey.length + " != " + SESSION_KEY_BYTES);
      }
    } catch (_e) {
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
        publicKey:    keypair.publicKey,
        ecPublicKey:  keypair.ecPublicKey,
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

module.exports = Object.assign(create, {
  client:           client,
  ApiEncryptError:  ApiEncryptError,
});
