"use strict";
/**
 * URL-safe — validate URL scheme + shape against an allowlist.
 *
 * Per the framework's modernity stance: outbound network calls
 * REQUIRE TLS by default. Operators with internal cleartext
 * endpoints (development, behind-VPN services, internal mesh) opt in
 * explicitly via opts.allowedProtocols. The framework refuses to
 * silently drop bytes on the wire as cleartext.
 *
 * Public API:
 *
 *   urlSafe.parse(url, opts?) → URL
 *     Returns a parsed URL object. Throws if the URL is malformed
 *     or its protocol is not in the allowlist.
 *
 *   opts:
 *     allowedProtocols  — array of accepted protocol strings
 *                         (e.g. ["https:"] or urlSafe.ALLOW_HTTP_TLS).
 *                         Default: ALLOW_HTTP_TLS.
 *     errorClass        — FrameworkError subclass for the thrown
 *                         error. Lets callers (object-store,
 *                         log-stream, http-client) surface their
 *                         own decorated error class. Default:
 *                         UrlSafeError.
 *
 * Constants — pre-baked allowlists for the common caller cases:
 *
 *   ALLOW_HTTP_TLS   ["https:"]                       (the secure HTTP default)
 *   ALLOW_HTTP_ALL   ["http:", "https:"]              (HTTP + cleartext opt-in)
 *   ALLOW_WS_TLS     ["wss:"]                         (the secure WS default)
 *   ALLOW_WS_ALL     ["ws:", "wss:"]                  (WS + cleartext opt-in)
 *   ALLOW_ANY        ["http:", "https:", "ws:", "wss:"]
 *
 * Why per-call constants instead of one global "secure" list:
 *   The http-client only speaks HTTP, so wss:// is a category error
 *   (operator passed a WebSocket URL to a non-WebSocket client). Each
 *   caller declares its own narrow allowlist; an off-protocol URL
 *   fails with a clear "protocol not allowed here" error rather than
 *   trying and failing weirdly later.
 */

var { FrameworkError } = require("./framework-error");
var { URL } = require("url");

var ALLOW_HTTP_TLS = Object.freeze(["https:"]);
var ALLOW_HTTP_ALL = Object.freeze(["http:", "https:"]);
var ALLOW_WS_TLS   = Object.freeze(["wss:"]);
var ALLOW_WS_ALL   = Object.freeze(["ws:", "wss:"]);
var ALLOW_ANY      = Object.freeze(["http:", "https:", "ws:", "wss:"]);

class UrlSafeError extends FrameworkError {
  constructor(code, message) {
    super(message, code);
    this.name = "UrlSafeError";
    this.isUrlSafeError = true;
  }
}

function _makeError(errorClass, code, message) {
  if (!errorClass || errorClass === UrlSafeError) {
    return new UrlSafeError(code, message);
  }
  // Convention for operational classes (ObjectStoreError,
  // LogStreamError, etc.): (code, message, permanent[, statusCode]).
  // A protocol-violation URL is "permanent" — retry won't help.
  return new errorClass(code, message, true);
}

function parse(url, opts) {
  opts = opts || {};
  var allowed = Array.isArray(opts.allowedProtocols) && opts.allowedProtocols.length > 0
    ? opts.allowedProtocols
    : ALLOW_HTTP_TLS;
  var errClass = opts.errorClass;

  if (url == null || url === "") {
    throw _makeError(errClass, "safe-url/missing", "url is required");
  }

  var parsed;
  if (url instanceof URL) {
    parsed = url;
  } else {
    try {
      parsed = new URL(String(url));
    } catch (e) {
      throw _makeError(errClass, "safe-url/malformed", "malformed URL: " + e.message);
    }
  }

  if (allowed.indexOf(parsed.protocol) === -1) {
    throw _makeError(errClass, "safe-url/protocol-disallowed",
      "protocol '" + parsed.protocol + "' not in allowlist [" + allowed.join(", ") +
      "]. Pass opts.allowedProtocols to override (e.g. urlSafe.ALLOW_HTTP_ALL for cleartext endpoints).");
  }

  return parsed;
}

module.exports = {
  parse:           parse,
  UrlSafeError:    UrlSafeError,
  ALLOW_HTTP_TLS:  ALLOW_HTTP_TLS,
  ALLOW_HTTP_ALL:  ALLOW_HTTP_ALL,
  ALLOW_WS_TLS:    ALLOW_WS_TLS,
  ALLOW_WS_ALL:    ALLOW_WS_ALL,
  ALLOW_ANY:       ALLOW_ANY,
};
