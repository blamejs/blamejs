"use strict";
/**
 * b.tlsExporter — RFC 9266 TLS-Exporter channel binding.
 *
 * RFC 9266 defines "tls-exporter" as a channel-binding identifier for
 * use with TLS 1.3 (RFC 8446). Application-layer authentication tokens
 * (bearer tokens, DPoP proofs, mTLS-derived auth headers) bind to a
 * 32-byte exporter pulled from the active TLS keying material so a
 * captured token cannot be replayed across a different TLS session.
 *
 * Per RFC 9266 §4 the exporter is:
 *
 *   TLS-Exporter("EXPORTER-Channel-Binding", "", 32)
 *
 * Node's TLSSocket.exportKeyingMaterial is the matching primitive
 * (length=32, label="EXPORTER-Channel-Binding", context=null per RFC
 * 8446 §7.5 + RFC 9266 §4).
 *
 * Operator API:
 *
 *   var exporter = b.tlsExporter.fromSocket(req.socket);
 *   // → 32-byte Buffer (binding identifier)
 *
 *   // Bind to a token:
 *   var bound = b.tlsExporter.bindToken(req.socket, token);
 *
 *   // Verify on next request (token must include the exporter the
 *   // server saw at issue time):
 *   var ok = b.tlsExporter.verifyTokenBinding(req.socket, claimedExporter);
 *
 * Use cases:
 *   - Pin a session cookie to the TLS session that issued it (defends
 *     against replay across separate TLS connections).
 *   - DPoP-style cnf claim (RFC 9449 §6.2 alternative): include the
 *     tls-exporter in the access-token's `cnf.tbh` so the resource
 *     server rejects cross-session replay.
 *   - mTLS-derived headers (RFC 8705): the exporter binding survives
 *     proxy intermediaries that re-terminate TLS.
 *
 * Validation policy: throw at call site for sockets that aren't TLS
 * (channel binding has no meaning over plaintext) or sockets with no
 * active session.
 */

var crypto = require("./crypto");
var C = require("./constants");
var lazyRequire = require("./lazy-require");
var nb = require("./numeric-bounds");
var { TlsExporterError } = require("./framework-error");

var _err = TlsExporterError.factory;

var observability = lazyRequire(function () { return require("./observability"); });

var EXPORTER_LABEL = "EXPORTER-Channel-Binding";
var EXPORTER_LENGTH = C.BYTES.bytes(32);

// _resolveTlsSocket — accept either a TLSSocket directly OR an http2/
// http(s) request whose .socket property is the TLSSocket. Operators
// almost always pass req.socket; the helper normalizes to the
// underlying socket so the exportKeyingMaterial call lands on the
// right object.
function _resolveTlsSocket(socketOrReq) {
  if (!socketOrReq) {
    throw _err("BAD_INPUT", "tlsExporter: socket or request object required");
  }
  // Express/Node http req → req.socket is the TLSSocket
  var sock = socketOrReq;
  if (typeof socketOrReq.exportKeyingMaterial !== "function" &&
      socketOrReq.socket &&
      typeof socketOrReq.socket.exportKeyingMaterial === "function") {
    sock = socketOrReq.socket;
  }
  if (typeof sock.exportKeyingMaterial !== "function") {
    throw _err("NOT_TLS",
      "tlsExporter: socket has no exportKeyingMaterial — channel binding requires TLS");
  }
  // Per RFC 9266 §4 the exporter is only defined for TLS 1.3. Older
  // protocol versions on the same API would technically return bytes
  // but the channel-binding semantics are NOT RFC 9266 conformant —
  // refuse so an operator-built check doesn't silently fall back to a
  // weaker binding.
  if (typeof sock.getProtocol === "function") {
    var proto = sock.getProtocol();
    if (proto && proto !== "TLSv1.3") {
      throw _err("NOT_TLS_1_3",
        "tlsExporter: TLS protocol is " + proto + ", RFC 9266 requires TLS 1.3");
    }
  }
  return sock;
}

// fromSocket — RFC 9266 §4 channel-binding extraction.
//
//   opts: { label?: string, length?: number, context?: Buffer }
//
// Operators rarely override these — the defaults match the RFC 9266
// "tls-exporter" channel-binding identifier. Custom labels surface for
// applications defining their own exporter-derived identifiers (e.g.,
// RFC 9438 "EXPORTER-Token-Binding"); explicit opts pass through.
function fromSocket(socketOrReq, opts) {
  opts = opts || {};
  var label = typeof opts.label === "string" && opts.label.length > 0
    ? opts.label : EXPORTER_LABEL;
  // length is operator-tunable; validate-when-present via numeric-bounds
  // so a non-finite / negative / NaN input surfaces with the same error
  // shape every other framework primitive uses for numeric opts.
  nb.requirePositiveFiniteIntIfPresent(opts.length,
    "tlsExporter.fromSocket: length", TlsExporterError, "BAD_LENGTH");
  var length = opts.length !== undefined ? opts.length : EXPORTER_LENGTH;
  if (length < C.BYTES.bytes(16) || length > C.BYTES.bytes(255)) {
    throw _err("BAD_LENGTH",
      "tlsExporter.fromSocket: length must be 16..255 bytes (got " + length + ")");
  }
  var context = opts.context;
  if (context !== undefined && context !== null && !Buffer.isBuffer(context)) {
    throw _err("BAD_CONTEXT",
      "tlsExporter.fromSocket: context must be Buffer or null");
  }

  var sock = _resolveTlsSocket(socketOrReq);
  var bytes;
  try {
    // Node's exportKeyingMaterial signature: (length, label, [context]).
    // Passing context=null (the default) corresponds to the RFC 8446
    // §7.5 "no context" case which RFC 9266 §4 mandates for channel
    // binding.
    bytes = context
      ? sock.exportKeyingMaterial(length, label, context)
      : sock.exportKeyingMaterial(length, label);
  } catch (e) {
    throw _err("EXPORT_FAILED",
      "tlsExporter.fromSocket: exportKeyingMaterial threw: " + e.message);
  }
  if (!Buffer.isBuffer(bytes) || bytes.length !== length) {
    throw _err("EXPORT_SHORT",
      "tlsExporter.fromSocket: short exporter (got " + (bytes && bytes.length) + " bytes, want " + length + ")");
  }

  try { observability().safeEvent("tlsExporter.fromSocket", 1, { outcome: "success" }); }
  catch (_e) { /* drop-silent */ }
  return bytes;
}

// bindToken — bind an opaque token to the current TLS session by
// concatenating the exporter and hashing. Operators can store the
// resulting binding alongside the token; verifyTokenBinding compares
// constant-time on the next request.
function bindToken(socketOrReq, token) {
  if (typeof token !== "string" && !Buffer.isBuffer(token)) {
    throw _err("BAD_TOKEN",
      "tlsExporter.bindToken: token must be a string or Buffer");
  }
  var exporter = fromSocket(socketOrReq);
  var tokenBuf = Buffer.isBuffer(token) ? token : Buffer.from(token, "utf8");
  // SHA3-512 of (label || exporter || token). The label binds the
  // hash to "tls-exporter binding" so the same token + exporter pair
  // does NOT produce the same hash if used in another framework
  // primitive (e.g., the audit-chain row hash).
  var labelBuf = Buffer.from("blamejs/tls-exporter/bind/v1", "utf8");
  return crypto.sha3Hash(Buffer.concat([labelBuf, exporter, tokenBuf]));
}

// verifyTokenBinding — constant-time compare of a previously-issued
// binding against the current TLS session. Returns boolean; never
// throws on mismatch (token-binding mismatch is a normal request-time
// outcome, not a config bug). Throws only on bad input or non-TLS.
function verifyTokenBinding(socketOrReq, token, claimedBinding) {
  var actual = bindToken(socketOrReq, token);
  if (typeof claimedBinding !== "string" || claimedBinding.length === 0) {
    return false;
  }
  return crypto.timingSafeEqual(actual, claimedBinding);
}

module.exports = {
  fromSocket:           fromSocket,
  bindToken:            bindToken,
  verifyTokenBinding:   verifyTokenBinding,
  EXPORTER_LABEL:       EXPORTER_LABEL,
  EXPORTER_LENGTH:      EXPORTER_LENGTH,
  TlsExporterError:     TlsExporterError,
};
