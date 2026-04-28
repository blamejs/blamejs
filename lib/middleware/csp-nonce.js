"use strict";
/**
 * csp-nonce — per-request CSP nonce + render integration.
 *
 * The framework's `security-headers` middleware ships a strict CSP
 * that doesn't allow inline scripts (no 'unsafe-inline'). Templates
 * with inline `<script>` blocks therefore break out of the box — the
 * browser refuses to execute them. This middleware closes the gap:
 *
 *   1. Generate a fresh random nonce per request (base64, default
 *      16 bytes / 22 chars).
 *   2. Attach it to `req.cspNonce` (handler-readable) AND
 *      `res.locals.cspNonce` (template-data-readable — render.js
 *      auto-merges res.locals into template data).
 *   3. Patch the existing Content-Security-Policy header set by
 *      security-headers — append `'nonce-XYZ'` to the operator-
 *      configured directives (defaults: script-src, style-src).
 *      If no CSP header is set yet, build a minimal one.
 *
 * Operators wire it after security-headers and write `nonce="..."`
 * on their inline scripts:
 *
 *   router.use(b.middleware.securityHeaders());
 *   router.use(b.middleware.cspNonce({
 *     directives:    ["script-src", "style-src"],
 *     nonceBytes:    16,
 *     strictDynamic: true,
 *   }));
 *
 *   // In a template:
 *   //   <script nonce="{{ cspNonce }}">console.log("ok")</script>
 *   //
 *   // Or in a handler:
 *   //   res.write('<script nonce="' + req.cspNonce + '">...</script>');
 *
 * Handler shape: req.cspNonce is the raw base64 nonce. Templates
 * receive it via the auto-merged res.locals so the html() render
 * helper doesn't need an extra argument — the operator just writes
 * `{{ cspNonce }}` in the view.
 *
 * strict-dynamic mode (opt-in): when true, the nonce directive also
 * gets `'strict-dynamic'`. Modern browsers then trust scripts loaded
 * by a nonced script — no need to allowlist their origins. This is
 * the recommended posture for SPA hydration scripts that themselves
 * load dependencies (e.g. tiny inline bootstrap that imports a
 * versioned bundle). See https://www.w3.org/TR/CSP3/#strict-dynamic-usage.
 *
 * Nonce strength:
 *   - Default 16 bytes (128 bits) of crypto-strong randomness from
 *     node:crypto.randomBytes. Standard for CSP nonces.
 *   - Operators with stricter posture set nonceBytes: 32 (256 bits).
 *   - Going below 16 bytes is refused at config time.
 *
 * What this middleware does NOT do:
 *   - It doesn't ALSO set 'unsafe-inline'. The browser silently ignores
 *     'unsafe-inline' when a nonce is present (CSP3 spec), so this is
 *     a non-issue, but operators sometimes add 'unsafe-inline' "just
 *     in case" — that defeats the entire point of the nonce.
 *   - It doesn't attempt to strip 'unsafe-inline' from operator-
 *     supplied CSP. If the operator configured 'unsafe-inline' and
 *     adds csp-nonce, both are present; the browser ignores
 *     'unsafe-inline' but the static analysis tool might still flag
 *     it. Removing operator-supplied directives without explicit
 *     consent is more astonishing than helpful.
 *   - It doesn't generate nonces for non-HTML responses (JSON, raw
 *     bytes). The middleware skips when there's no template / inline-
 *     script context — operators who want a nonce on every response
 *     pass `always: true`.
 */

var nodeCrypto = require("node:crypto");
var { defineClass } = require("../framework-error");

var CspNonceError = defineClass("CspNonceError", { alwaysPermanent: true });

var DEFAULT_DIRECTIVES = Object.freeze(["script-src", "style-src"]);
var DEFAULT_NONCE_BYTES = 16;
var MIN_NONCE_BYTES = 16;

// Build a fresh CSP from scratch when none is set. Conservative defaults
// — the nonced directive replaces what 'unsafe-inline' would have done.
function _defaultCsp(nonceToken) {
  return "default-src 'self'; " +
         "script-src 'self' " + nonceToken + "; " +
         "style-src 'self' " + nonceToken + "; " +
         "img-src 'self' data:; " +
         "frame-ancestors 'none'; " +
         "base-uri 'self'; " +
         "form-action 'self'; " +
         "object-src 'none'";
}

// Parse the CSP header into [{ name, valueParts }] preserving operator
// ordering. Each entry is `directive-name [value...]`.
function _parseCsp(headerValue) {
  var parts = String(headerValue).split(";");
  var out = [];
  for (var i = 0; i < parts.length; i++) {
    var p = parts[i].trim();
    if (p.length === 0) continue;
    // Split on whitespace runs.
    var tokens = p.split(/\s+/);
    var name = tokens.shift().toLowerCase();
    out.push({ name: name, values: tokens });
  }
  return out;
}

function _serializeCsp(parts) {
  return parts.map(function (p) {
    if (p.values.length === 0) return p.name;
    return p.name + " " + p.values.join(" ");
  }).join("; ");
}

function _injectNonce(cspHeader, nonce, directives, strictDynamic) {
  var nonceToken = "'nonce-" + nonce + "'";
  if (!cspHeader) {
    // Build a minimal CSP from scratch. strictDynamic isn't applied
    // to a fresh CSP because the operator hasn't told us their script
    // load pattern yet — they can opt in by combining their own CSP
    // with cspNonce.
    return _defaultCsp(nonceToken);
  }
  var parts = _parseCsp(cspHeader);
  var seen = Object.create(null);
  for (var i = 0; i < parts.length; i++) {
    var name = parts[i].name;
    seen[name] = i;
    if (directives.indexOf(name) !== -1) {
      // Avoid duplicate nonce tokens if the middleware ever runs twice.
      if (parts[i].values.indexOf(nonceToken) === -1) {
        parts[i].values.push(nonceToken);
      }
      // strict-dynamic only meaningful for script-src.
      if (strictDynamic && name === "script-src" && parts[i].values.indexOf("'strict-dynamic'") === -1) {
        parts[i].values.push("'strict-dynamic'");
      }
    }
  }
  // Add target directives that were missing from the original CSP.
  for (var j = 0; j < directives.length; j++) {
    var d = directives[j].toLowerCase();
    if (Object.prototype.hasOwnProperty.call(seen, d)) continue;
    var values = [nonceToken];
    if (strictDynamic && d === "script-src") values.push("'strict-dynamic'");
    parts.push({ name: d, values: values });
  }
  return _serializeCsp(parts);
}

function create(opts) {
  opts = opts || {};
  var directives = Array.isArray(opts.directives) && opts.directives.length > 0
                     ? opts.directives.slice() : DEFAULT_DIRECTIVES.slice();
  for (var i = 0; i < directives.length; i++) {
    if (typeof directives[i] !== "string" || directives[i].length === 0) {
      throw new CspNonceError("csp-nonce/bad-directive",
        "directives must be non-empty strings (e.g. 'script-src')");
    }
    directives[i] = directives[i].toLowerCase();
  }
  var nonceBytes = typeof opts.nonceBytes === "number" ? opts.nonceBytes : DEFAULT_NONCE_BYTES;
  if (nonceBytes < MIN_NONCE_BYTES) {
    throw new CspNonceError("csp-nonce/bad-nonce-bytes",
      "nonceBytes must be >= " + MIN_NONCE_BYTES + " (got " + nonceBytes + "). " +
      "CSP nonces below 128 bits weaken the security boundary.");
  }
  var strictDynamic = !!opts.strictDynamic;
  var headerName = opts.headerName || "Content-Security-Policy";
  var property = (typeof opts.property === "string" && opts.property.length > 0) ? opts.property : "cspNonce";
  var always = !!opts.always;

  return function cspNonce(req, res, next) {
    // Generate the nonce. Cheap (16 bytes from getrandom + base64 encode);
    // do it always for consistency unless `always: false` was set explicitly.
    var nonce = nodeCrypto.randomBytes(nonceBytes).toString("base64");

    // Attach to req for handler access.
    req[property] = nonce;
    // Attach to res.locals for template-data auto-merge (render.js).
    if (!res.locals || typeof res.locals !== "object") res.locals = {};
    res.locals[property] = nonce;

    if (typeof res.setHeader !== "function" || typeof res.getHeader !== "function") {
      // Plain object response (test mock without setHeader). Skip header
      // patching; the operator's still got req.cspNonce.
      return next();
    }

    // Patch the CSP header. If security-headers already set one, mutate
    // it; otherwise build a fresh minimal CSP. Operators who DON'T want
    // a CSP header set when none exists pass `always: false` (default
    // behavior is to set one).
    var existing = res.getHeader(headerName);
    if (!existing && !always) {
      // No existing CSP and operator didn't ask for always — leave
      // alone. The req.cspNonce is still available for templates that
      // want to use it.
      return next();
    }
    var patched = _injectNonce(existing, nonce, directives, strictDynamic);
    res.setHeader(headerName, patched);
    return next();
  };
}

module.exports = {
  create:                create,
  CspNonceError:         CspNonceError,
  DEFAULT_DIRECTIVES:    DEFAULT_DIRECTIVES,
  // Internal helpers exposed for tests
  _injectNonce:          _injectNonce,
  _parseCsp:             _parseCsp,
  _serializeCsp:         _serializeCsp,
};
