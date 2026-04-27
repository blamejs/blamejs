"use strict";
/**
 * cookies — cookie parse/serialize + access-gated sealed cookies.
 *
 * RFC 6265 cookie plumbing the framework was duplicating across
 * middleware: a parser in attach-user, ad-hoc Set-Cookie strings in
 * route handlers, no shared place for attribute defaults. This is the
 * single primitive.
 *
 * Two surfaces:
 *
 *   1. Module-level (stateless): cookies.parse / cookies.serialize.
 *      Useful in test fixtures and code that doesn't have a vault.
 *
 *   2. Instance (cookies.create): bound defaults for cookie attributes,
 *      a wired vault for sealed reads/writes, and req/res helpers.
 *
 *   var cookies = b.cookies.create({
 *     vault: b.vault,                  // required for sealed* methods
 *     defaults: {
 *       httpOnly: true,
 *       secure:   true,                // default true; HTTPS expected
 *       sameSite: "Lax",
 *       path:     "/",
 *       maxAge:   7 * 86400,           // seconds
 *     },
 *   });
 *
 *   cookies.parse("a=1; b=2")           → { a: "1", b: "2" }
 *   cookies.serialize("name", "v",
 *     { maxAge: 3600 })                 → "name=v; Max-Age=3600; Path=/; HttpOnly; SameSite=Lax; Secure"
 *
 *   cookies.read(req, "name")           → "v" or null
 *   cookies.write(res, "name", "v", {}) // appends to existing Set-Cookie
 *   cookies.clear(res, "name", {})      // expire by Max-Age=0
 *
 *   cookies.writeSealed(res, "session", sid)  // vault.seal then write
 *   cookies.readSealed(req, "session")        // read then vault.unseal
 *
 * Sealed-cookie purpose: the cookie value is a vault.seal of the real
 * value. Without the framework's vault key, no client can hand-craft a
 * valid cookie value, so the API is unreachable via curl-with-arbitrary-
 * cookies or any tool that hasn't been through the framework's crypto
 * flow. The vault prefix is stripped on write and re-added on read so
 * the cookie carries only the base64 envelope.
 *
 * Defense in serialize/parse:
 *   - Cookie name must be a valid token (no CTLs, no separator chars).
 *   - Cookie value must not contain CRLF, semicolon, or comma.
 *   - Value is percent-encoded on write, percent-decoded on read.
 *   - Domain / Path are CRLF-stripped to defeat header injection
 *     attempts via operator-controlled but improperly-escaped inputs.
 */

var C = require("./constants");
var { FrameworkError } = require("./framework-error");

class CookieError extends FrameworkError {
  constructor(code, message) {
    super(message, code);
    this.name = "CookieError";
    this.permanent = true;
    this.isCookieError = true;
  }
}

// RFC 6265 cookie-name token: VCHAR minus separators. Reject anything
// outside this range — embeddings of CTLs / separators / whitespace
// would break parsing on the next hop.
var TOKEN_RE = /^[!#$%&'*+\-.0-9A-Z^_`a-z|~]+$/;
// Reject CRLF, NUL, semicolon, comma in cookie value pre-encoding.
var FORBIDDEN_VALUE_RE = /[\r\n\0;,]/;

function _validateName(name) {
  if (typeof name !== "string" || name.length === 0) {
    throw new CookieError("cookies/invalid-name",
      "cookie name must be a non-empty string");
  }
  if (!TOKEN_RE.test(name)) {
    throw new CookieError("cookies/invalid-name",
      "cookie name '" + name + "' contains forbidden characters");
  }
}

function _validateValue(value) {
  if (typeof value !== "string") {
    throw new CookieError("cookies/invalid-value",
      "cookie value must be a string");
  }
  if (FORBIDDEN_VALUE_RE.test(value)) {
    throw new CookieError("cookies/invalid-value",
      "cookie value contains forbidden control character (CRLF/NUL/;/,)");
  }
}

// Strip CRLF/NUL defensively from operator-supplied attribute strings
// (Domain, Path, SameSite). Even if the attribute is constant in the
// caller's code, attribute strings flow into Set-Cookie which is a
// header — never trust unscrubbed values reach the wire.
function _scrubAttr(s) {
  if (typeof s !== "string") return s;
  return s.replace(/[\r\n\0]/g, "");
}

function parse(cookieHeader) {
  var out = {};
  if (typeof cookieHeader !== "string" || cookieHeader.length === 0) return out;
  var pairs = cookieHeader.split(/;\s*/);
  for (var i = 0; i < pairs.length; i++) {
    var pair = pairs[i];
    if (!pair) continue;
    var eq = pair.indexOf("=");
    if (eq < 0) continue;
    var k = pair.slice(0, eq).trim();
    if (!k) continue;
    var v = pair.slice(eq + 1).trim();
    // Strip surrounding double-quotes per RFC 6265 §5.2.
    if (v.length >= 2 && v.charAt(0) === '"' && v.charAt(v.length - 1) === '"') {
      v = v.slice(1, -1);
    }
    try { v = decodeURIComponent(v); }
    catch (_e) { /* malformed encoding — keep raw */ }
    // Last write wins per RFC; matches every browser's behavior.
    out[k] = v;
  }
  return out;
}

function serialize(name, value, attrs) {
  _validateName(name);
  _validateValue(value);
  attrs = attrs || {};

  var parts = [name + "=" + encodeURIComponent(value)];

  if (attrs.maxAge !== undefined && attrs.maxAge !== null) {
    var maxAge = Number(attrs.maxAge);
    if (!Number.isFinite(maxAge) || Math.floor(maxAge) !== maxAge) {
      throw new CookieError("cookies/invalid-attr",
        "cookie attr maxAge must be an integer (seconds)");
    }
    parts.push("Max-Age=" + maxAge);
  }
  if (attrs.expires !== undefined && attrs.expires !== null) {
    var d = attrs.expires instanceof Date ? attrs.expires : new Date(attrs.expires);
    if (isNaN(d.getTime())) {
      throw new CookieError("cookies/invalid-attr",
        "cookie attr expires must be a Date or parseable date string");
    }
    parts.push("Expires=" + d.toUTCString());
  }
  if (attrs.domain) {
    parts.push("Domain=" + _scrubAttr(String(attrs.domain)));
  }
  if (attrs.path !== undefined && attrs.path !== null) {
    parts.push("Path=" + _scrubAttr(String(attrs.path)));
  }
  if (attrs.httpOnly) parts.push("HttpOnly");
  if (attrs.sameSite) {
    var ss = String(attrs.sameSite);
    var ssLow = ss.toLowerCase();
    var ssNorm;
    if      (ssLow === "strict") ssNorm = "Strict";
    else if (ssLow === "lax")    ssNorm = "Lax";
    else if (ssLow === "none")   ssNorm = "None";
    else throw new CookieError("cookies/invalid-attr",
      "cookie attr sameSite must be Strict, Lax, or None");
    parts.push("SameSite=" + ssNorm);
    // SameSite=None requires Secure per spec; force it on so operators
    // don't ship a cookie that browsers silently drop.
    if (ssNorm === "None") attrs = Object.assign({}, attrs, { secure: true });
  }
  if (attrs.secure) parts.push("Secure");
  if (attrs.partitioned) parts.push("Partitioned");
  if (attrs.priority) {
    var p = String(attrs.priority);
    var pLow = p.toLowerCase();
    var pNorm;
    if      (pLow === "low")    pNorm = "Low";
    else if (pLow === "medium") pNorm = "Medium";
    else if (pLow === "high")   pNorm = "High";
    else throw new CookieError("cookies/invalid-attr",
      "cookie attr priority must be Low, Medium, or High");
    parts.push("Priority=" + pNorm);
  }
  return parts.join("; ");
}

// Append a Set-Cookie header preserving any already on the response.
function _appendSetCookie(res, header) {
  if (!res || typeof res.setHeader !== "function") {
    throw new CookieError("cookies/no-set-header",
      "response object has no setHeader (not a Node http.ServerResponse?)");
  }
  var existing;
  if (typeof res.getHeader === "function") existing = res.getHeader("Set-Cookie");
  var arr;
  if (Array.isArray(existing))      arr = existing.slice();
  else if (existing !== undefined)  arr = [existing];
  else                              arr = [];
  arr.push(header);
  res.setHeader("Set-Cookie", arr);
}

function _readCookieFromReq(req, name) {
  if (!req || !req.headers) return null;
  var header = req.headers.cookie;
  if (!header) return null;
  var jar = parse(header);
  return Object.prototype.hasOwnProperty.call(jar, name) ? jar[name] : null;
}

function create(opts) {
  opts = opts || {};
  var vault = opts.vault || null;
  // Defaults applied on every write unless the per-call attrs override.
  // secure defaults to true: cookies should never be sent in cleartext;
  // operators developing locally over http opt out explicitly.
  var defaults = Object.assign({
    httpOnly: true,
    secure:   true,
    sameSite: "Lax",
    path:     "/",
  }, opts.defaults || {});

  function _mergeAttrs(callerAttrs) {
    return Object.assign({}, defaults, callerAttrs || {});
  }

  function read(req, name)               { return _readCookieFromReq(req, name); }
  function write(res, name, value, attrs) {
    _appendSetCookie(res, serialize(name, value, _mergeAttrs(attrs)));
  }
  function clear(res, name, attrs) {
    // Expire-now cookie. Domain + Path must match the original write
    // for the browser to actually delete it — operators pass the same
    // attrs they used on write (or rely on the same defaults).
    var attrsExp = Object.assign({}, _mergeAttrs(attrs), { maxAge: 0 });
    delete attrsExp.expires;
    _appendSetCookie(res, serialize(name, "", attrsExp));
  }

  function _requireVault() {
    if (!vault || typeof vault.seal !== "function" || typeof vault.unseal !== "function") {
      throw new CookieError("cookies/no-vault",
        "sealed cookies require opts.vault (a value with .seal/.unseal)");
    }
  }

  // Vault.seal returns "vault:<base64>". We strip the constant prefix
  // on the wire to keep cookies short, and re-add it before unseal.
  // Within a vault major version the prefix is stable for the cookie's
  // entire Max-Age window, so this is safe.
  function writeSealed(res, name, value, attrs) {
    _requireVault();
    if (typeof value !== "string") {
      throw new CookieError("cookies/invalid-value",
        "sealed cookie value must be a string before sealing");
    }
    var sealed = vault.seal(value);
    var stripped = sealed.startsWith(C.VAULT_PREFIX)
      ? sealed.substring(C.VAULT_PREFIX.length)
      : sealed;
    write(res, name, stripped, attrs);
  }
  function readSealed(req, name) {
    _requireVault();
    var raw = _readCookieFromReq(req, name);
    if (raw === null) return null;
    try { return vault.unseal(C.VAULT_PREFIX + raw); }
    catch (_e) { return null; }
  }

  return {
    parse:       parse,
    serialize:   function (n, v, a) { return serialize(n, v, _mergeAttrs(a)); },
    read:        read,
    write:       write,
    clear:       clear,
    writeSealed: writeSealed,
    readSealed:  readSealed,
    defaults:    defaults,
  };
}

module.exports = {
  create:       create,
  parse:        parse,
  serialize:    serialize,
  CookieError:  CookieError,
};
