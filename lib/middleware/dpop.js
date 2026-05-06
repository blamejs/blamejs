"use strict";
/**
 * dpop middleware — RFC 9449 Demonstrating Proof of Possession.
 *
 * Verifies the `DPoP` header on inbound requests, attaches the result
 * to `req.dpop = { header, payload, jkt }` for downstream handlers, and
 * rejects with 401 + `WWW-Authenticate: DPoP` on any failure.
 *
 *   var dpop = b.middleware.dpop({
 *     replayStore:    b.nonceStore.create({ backend: "memory" }),
 *     algorithms:     ["ES256", "EdDSA", "ML-DSA-87"],
 *     iatWindowSec:   60,
 *     getAccessToken: function (req) {
 *       // optional — extract Bearer token to bind ath
 *       var h = req.headers.authorization || "";
 *       return h.toLowerCase().startsWith("bearer ") ? h.slice(7) : null;
 *     },
 *     getNonce: async function (req) {
 *       // optional — server-issued challenge (RFC 9449 §8); return null
 *       // to skip nonce enforcement
 *       return null;
 *     },
 *     audit: true,
 *   });
 *   router.use("/api", dpop);
 *
 * On success:
 *   - req.dpop = { header, payload, jkt }
 *   - downstream handlers can compare req.dpop.jkt to the cnf claim
 *     of the access token to enforce key-bound bearer semantics
 *
 * On failure:
 *   - 401 with WWW-Authenticate: DPoP error="invalid_dpop_proof",
 *     error_description="<reason>"
 *   - audit.bearer.failure event when audit: true (default)
 */

var lazyRequire = require("../lazy-require");
var requestHelpers = require("../request-helpers");
var validateOpts = require("../validate-opts");
var { AuthError } = require("../framework-error");

var dpop = lazyRequire(function () { return require("../auth/dpop"); });
var audit = lazyRequire(function () { return require("../audit"); });

function _writeUnauthorized(res, errorCode, description) {
  if (res.headersSent) return;
  var body = JSON.stringify({ error: errorCode, error_description: description });
  // RFC 9449 §7 — error code is invalid_dpop_proof OR use_dpop_nonce.
  var challenge = 'DPoP error="' + errorCode + '", error_description="' +
                  description.replace(/"/g, "'") + '"';
  res.writeHead(401, {                                                             // allow:raw-byte-literal — HTTP 401 status
    "Content-Type":     "application/json; charset=utf-8",
    "Content-Length":   Buffer.byteLength(body),
    "WWW-Authenticate": challenge,
  });
  res.end(body);
}

function _reconstructHtu(req) {
  // The proof's htu is the request URI WITHOUT query/fragment. Behind
  // a reverse proxy the operator may need to override via opts.htu /
  // opts.getHtu — defaults read X-Forwarded-* if present.
  var proto = req.headers["x-forwarded-proto"] || (req.socket && req.socket.encrypted ? "https" : "http");
  var host = req.headers["x-forwarded-host"] || req.headers.host;
  if (!host) return null;
  var path = req.url || "/";
  var qIdx = path.indexOf("?");
  if (qIdx !== -1) path = path.slice(0, qIdx);
  var hIdx = path.indexOf("#");
  if (hIdx !== -1) path = path.slice(0, hIdx);
  return proto + "://" + host + path;
}

function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "replayStore", "algorithms", "iatWindowSec",
    "getAccessToken", "getNonce", "getHtu", "audit",
  ], "middleware.dpop");

  var auditOn = opts.audit !== false;
  var algorithms = opts.algorithms;
  var iatWindowSec = opts.iatWindowSec;
  var replayStore = opts.replayStore;

  validateOpts.optionalFunction(opts.getAccessToken,
    "middleware.dpop: getAccessToken", AuthError, "auth-dpop/bad-opt");
  validateOpts.optionalFunction(opts.getNonce,
    "middleware.dpop: getNonce", AuthError, "auth-dpop/bad-opt");
  validateOpts.optionalFunction(opts.getHtu,
    "middleware.dpop: getHtu", AuthError, "auth-dpop/bad-opt");

  return async function dpopMiddleware(req, res, next) {
    var proofHeader = req.headers && req.headers.dpop;
    if (typeof proofHeader !== "string" || proofHeader.length === 0) {
      return _writeUnauthorized(res, "invalid_dpop_proof", "DPoP header required");
    }
    // RFC 9449 §4.1 — only ONE DPoP header value per request.
    if (Array.isArray(proofHeader)) {
      return _writeUnauthorized(res, "invalid_dpop_proof",
        "multiple DPoP headers are not allowed");
    }

    var htu = (typeof opts.getHtu === "function" ? opts.getHtu(req) : _reconstructHtu(req));
    if (!htu) {
      return _writeUnauthorized(res, "invalid_dpop_proof", "could not reconstruct htu");
    }
    var htm = (req.method || "").toUpperCase();

    var accessToken = null;
    if (typeof opts.getAccessToken === "function") {
      try { accessToken = await opts.getAccessToken(req); }
      catch (_e) { accessToken = null; }
    }
    var nonce = null;
    if (typeof opts.getNonce === "function") {
      try { nonce = await opts.getNonce(req); }
      catch (_e) { nonce = null; }
    }

    var verifyOpts = { htm: htm, htu: htu };
    if (algorithms) verifyOpts.algorithms = algorithms;
    if (iatWindowSec !== undefined) verifyOpts.iatWindowSec = iatWindowSec;
    if (accessToken) verifyOpts.accessToken = accessToken;
    if (nonce) verifyOpts.nonce = nonce;
    if (replayStore) verifyOpts.replayStore = replayStore;

    var result;
    try { result = await dpop().verify(proofHeader, verifyOpts); }
    catch (e) {
      if (auditOn) {
        try {
          audit().safeEmit({
            action:  "auth.bearer.failure",
            actor:   { clientIp: requestHelpers.clientIp(req) },
            outcome: "fail",
            metadata: {
              method: "dpop",
              reason: (e && e.code) || "verify-failed",
              route:  req.url,
            },
          });
        } catch (_ignored) { /* drop-silent — observability sink failure */ }
      }
      var errorCode = "invalid_dpop_proof";
      // RFC 9449 §8 — when nonce is missing/invalid the server SHOULD use
      // use_dpop_nonce to signal the client to retry with a new nonce.
      if (e && (e.code === "auth-dpop/missing-nonce" || e.code === "auth-dpop/nonce-mismatch")) {
        errorCode = "use_dpop_nonce";
      }
      return _writeUnauthorized(res, errorCode,
        (e && e.message) || "DPoP proof verification failed");
    }

    req.dpop = result;
    if (auditOn) {
      try {
        audit().safeEmit({
          action:  "auth.bearer.success",
          actor:   { clientIp: requestHelpers.clientIp(req) },
          outcome: "ok",
          metadata: { method: "dpop", jkt: result.jkt, route: req.url },
        });
      } catch (_ignored) { /* drop-silent */ }
    }
    return next();
  };
}

module.exports = {
  create: create,
};
