"use strict";
/**
 * b.httpClient.cookieJar — outbound HTTP cookie store.
 *
 * Holds Set-Cookie state across requests so successive calls in a flow
 * (login → list → mutate → logout, OAuth code-exchange → userinfo, etc.)
 * carry the right Cookie header without operators threading it by hand.
 * RFC 6265 attribute coverage: Domain / Path / Expires / Max-Age /
 * HttpOnly / Secure / SameSite. Public Suffix List awareness is
 * deliberately deferred — operators wiring jars against trusted
 * domains don't need it; re-open if a real cross-eTLD bug surfaces.
 *
 *   var jar = b.httpClient.cookieJar.create();      // in-memory
 *   await b.httpClient.request({ url: loginUrl, method: "POST", body, jar });
 *   await b.httpClient.request({ url: meUrl, jar });   // session cookie attaches
 *
 * Vault-encrypted persistence — every cookie value is sealed via
 * b.vault.seal before it lands in the jar's store, so a memory dump or
 * core file doesn't expose plaintext values:
 *
 *   var jar = b.httpClient.cookieJar.create({ persist: "vault", vault: b.vault });
 *
 * The jar's lifecycle is per-process — restart loses cookies regardless
 * of persist mode. File-backed and cluster-shared persistence are
 * deferred; operators wanting durability serialize via getAll() and
 * restore via setFromSerialized() at boot.
 *
 * Outbound filtering follows RFC 6265 §5.4:
 *   - Domain: exact-host match by default; Domain attribute allows
 *     subdomain match (host must be a suffix of cookie.domain).
 *   - Path: request path must equal cookie.path or be path-below.
 *   - Secure: cookie only attaches when the request URL is https:.
 *   - Expiry: rows past Expires / Max-Age don't attach.
 *   - Sort: longer path first, then earlier creation time.
 *
 * Cookie shape returned from getAll():
 *
 *   {
 *     name, value, domain, path, hostOnly,
 *     expiresAt, // unix ms, or null for session cookies
 *     httpOnly, secure, sameSite, // attributes
 *     createdAt, updatedAt,
 *   }
 */

var safeUrl = require("./safe-url");
var { defineClass } = require("./framework-error");

var CookieJarError = defineClass("CookieJarError", { alwaysPermanent: true });
var _err = CookieJarError.factory;

var DEFAULTS = Object.freeze({
  persist: "memory",
});

var VALID_PERSIST = new Set(["memory", "vault"]);
var VALID_SAMESITE = new Set(["Strict", "Lax", "None"]);

// ---- Set-Cookie parser ----

function _parseHttpDate(s) {
  // node:Date handles RFC 1123 / 850 / asctime — sufficient for HTTP-date.
  var t = Date.parse(s);
  return isNaN(t) ? null : t;
}

function _parseSetCookie(line) {
  if (typeof line !== "string" || line.length === 0) return null;
  var semi = line.indexOf(";");
  var head = (semi === -1 ? line : line.slice(0, semi)).trim();
  var eq = head.indexOf("=");
  if (eq <= 0) return null;
  var name = head.slice(0, eq).trim();
  var value = head.slice(eq + 1).trim();
  if (!name) return null;

  var attrs = {};
  if (semi !== -1) {
    var rest = line.slice(semi + 1);
    var parts = rest.split(";");
    for (var i = 0; i < parts.length; i++) {
      var p = parts[i].trim();
      if (!p) continue;
      var pi = p.indexOf("=");
      var k, v;
      if (pi === -1) { k = p; v = ""; }
      else { k = p.slice(0, pi).trim(); v = p.slice(pi + 1).trim(); }
      attrs[k.toLowerCase()] = v;
    }
  }
  return { name: name, value: value, attrs: attrs };
}

// ---- Domain / Path matching ----

function _domainMatch(host, cookieDomain) {
  if (host === cookieDomain) return true;
  if (host.length > cookieDomain.length &&
      host.endsWith(cookieDomain) &&
      host.charAt(host.length - cookieDomain.length - 1) === ".") {
    return true;
  }
  return false;
}

function _pathMatch(reqPath, cookiePath) {
  if (cookiePath === reqPath) return true;
  if (reqPath.indexOf(cookiePath) === 0) {
    if (cookiePath.charAt(cookiePath.length - 1) === "/") return true;
    if (reqPath.charAt(cookiePath.length) === "/") return true;
  }
  return false;
}

function _defaultPath(reqPath) {
  // RFC 6265 §5.1.4: take everything up to the last "/", or "/" if none.
  if (typeof reqPath !== "string" || reqPath.length === 0) return "/";
  var qm = reqPath.indexOf("?");
  var p = qm === -1 ? reqPath : reqPath.slice(0, qm);
  if (p.charAt(0) !== "/") return "/";
  var lastSlash = p.lastIndexOf("/");
  if (lastSlash <= 0) return "/";
  return p.slice(0, lastSlash);
}

// ---- Public create ----

function create(opts) {
  opts = opts || {};
  var persist = opts.persist === undefined ? DEFAULTS.persist : opts.persist;
  if (!VALID_PERSIST.has(persist)) {
    throw _err("BAD_OPT", "cookieJar.create: persist must be 'memory' or 'vault', got " +
      JSON.stringify(persist));
  }
  var vault = opts.vault || null;
  if (persist === "vault") {
    if (!vault || typeof vault.seal !== "function" || typeof vault.unseal !== "function") {
      throw _err("BAD_OPT",
        "cookieJar.create: persist: 'vault' requires opts.vault with seal/unseal (pass b.vault)");
    }
  }
  var clock = typeof opts.clock === "function" ? opts.clock : Date.now;

  // Storage map keyed by `<domain>|<path>|<name>` so a (domain, path)
  // tuple can hold multiple cookies, but a same-tuple-same-name update
  // replaces the prior row per RFC 6265 §5.3.
  var store = new Map();

  function _seal(plain) {
    if (persist !== "vault" || plain === undefined || plain === null) return String(plain == null ? "" : plain);
    return vault.seal(String(plain));
  }
  function _unseal(blob) {
    if (persist !== "vault" || blob === undefined || blob === null) return blob == null ? "" : String(blob);
    return String(vault.unseal(blob));
  }

  function _setOne(reqUrl, parsed) {
    var u;
    try { u = new URL(reqUrl); } catch (_e) { return; }
    var host = u.hostname.toLowerCase();
    var attrs = parsed.attrs || {};

    // Domain attribute: lower-case, leading-dot stripped (RFC 6265bis).
    var domainAttr = attrs.domain;
    var domain;
    var hostOnly;
    if (domainAttr) {
      var d = String(domainAttr).toLowerCase();
      if (d.charAt(0) === ".") d = d.slice(1);
      // Don't accept a Domain that the request host doesn't match.
      if (!_domainMatch(host, d)) return;
      domain = d;
      hostOnly = false;
    } else {
      domain = host;
      hostOnly = true;
    }

    var path = (typeof attrs.path === "string" && attrs.path.charAt(0) === "/")
      ? attrs.path : _defaultPath(u.pathname);

    // Expires / Max-Age. Max-Age wins when both present (RFC 6265 §5.2.2).
    var now = clock();
    var expiresAt = null;
    if (attrs["max-age"] !== undefined) {
      var maxAge = parseInt(attrs["max-age"], 10);
      if (!isNaN(maxAge)) {
        expiresAt = maxAge <= 0 ? 0 : (now + maxAge * 1000);
      }
    } else if (attrs.expires) {
      expiresAt = _parseHttpDate(attrs.expires);
    }

    // Max-Age=0 / past Expires → delete an existing matching row.
    var key = domain + "|" + path + "|" + parsed.name;
    if (expiresAt !== null && expiresAt <= now) {
      store.delete(key);
      return;
    }

    var sameSiteRaw = attrs.samesite;
    var sameSite = null;
    if (typeof sameSiteRaw === "string") {
      var ssLc = sameSiteRaw.toLowerCase();
      if (ssLc === "strict") sameSite = "Strict";
      else if (ssLc === "lax") sameSite = "Lax";
      else if (ssLc === "none") sameSite = "None";
    }

    var prior = store.get(key);
    store.set(key, {
      name:      parsed.name,
      value:     _seal(parsed.value),
      domain:    domain,
      path:      path,
      hostOnly:  hostOnly,
      expiresAt: expiresAt,
      httpOnly:  Object.prototype.hasOwnProperty.call(attrs, "httponly"),
      secure:    Object.prototype.hasOwnProperty.call(attrs, "secure"),
      sameSite:  sameSite,
      createdAt: prior ? prior.createdAt : now,
      updatedAt: now,
    });
  }

  // ---- Public API ----

  function setFromResponse(reqUrl, setCookieHeader) {
    if (!setCookieHeader) return;
    var lines = Array.isArray(setCookieHeader) ? setCookieHeader : [setCookieHeader];
    for (var i = 0; i < lines.length; i++) {
      var parsed = _parseSetCookie(lines[i]);
      if (parsed) _setOne(reqUrl, parsed);
    }
  }

  function cookieHeaderFor(reqUrl) {
    var u;
    try { u = new URL(reqUrl); } catch (_e) { return null; }
    var host = u.hostname.toLowerCase();
    var path = u.pathname || "/";
    var isSecure = u.protocol === "https:";
    var now = clock();

    var matches = [];
    for (var entry of store.values()) {
      // Expiry
      if (entry.expiresAt !== null && entry.expiresAt <= now) continue;
      // Domain
      if (entry.hostOnly) {
        if (entry.domain !== host) continue;
      } else {
        if (!_domainMatch(host, entry.domain)) continue;
      }
      // Path
      if (!_pathMatch(path, entry.path)) continue;
      // Secure
      if (entry.secure && !isSecure) continue;
      matches.push(entry);
    }
    if (matches.length === 0) return null;

    // Sort: longer path first, then earlier creation time.
    matches.sort(function (a, b) {
      if (a.path.length !== b.path.length) return b.path.length - a.path.length;
      return a.createdAt - b.createdAt;
    });
    var pieces = matches.map(function (e) {
      return e.name + "=" + _unseal(e.value);
    });
    return pieces.join("; ");
  }

  function getAll() {
    var now = clock();
    var out = [];
    for (var entry of store.values()) {
      if (entry.expiresAt !== null && entry.expiresAt <= now) continue;
      out.push({
        name:      entry.name,
        value:     _unseal(entry.value),
        domain:    entry.domain,
        path:      entry.path,
        hostOnly:  entry.hostOnly,
        expiresAt: entry.expiresAt,
        httpOnly:  entry.httpOnly,
        secure:    entry.secure,
        sameSite:  entry.sameSite,
        createdAt: entry.createdAt,
        updatedAt: entry.updatedAt,
      });
    }
    return out;
  }

  function clear(filter) {
    if (!filter) {
      var n = store.size;
      store.clear();
      return n;
    }
    if (typeof filter !== "object") {
      throw _err("BAD_OPT", "cookieJar.clear: filter must be an object or undefined");
    }
    var purged = 0;
    var keysToDelete = [];
    for (var pair of store.entries()) {
      var key = pair[0];
      var entry = pair[1];
      if (filter.domain && entry.domain !== filter.domain) continue;
      if (filter.name && entry.name !== filter.name) continue;
      if (filter.path && entry.path !== filter.path) continue;
      keysToDelete.push(key);
    }
    for (var i = 0; i < keysToDelete.length; i++) {
      store.delete(keysToDelete[i]);
      purged++;
    }
    return purged;
  }

  function size() {
    var now = clock();
    var n = 0;
    for (var entry of store.values()) {
      if (entry.expiresAt !== null && entry.expiresAt <= now) continue;
      n++;
    }
    return n;
  }

  // Round-trip helpers — operators with restart-survival needs serialize
  // via getAll(), persist however they like, restore via setFromSerialized.
  function setFromSerialized(rows) {
    if (!Array.isArray(rows)) {
      throw _err("BAD_OPT", "cookieJar.setFromSerialized: rows must be an array");
    }
    var now = clock();
    for (var i = 0; i < rows.length; i++) {
      var r = rows[i];
      if (!r || typeof r.name !== "string" || typeof r.domain !== "string" || typeof r.path !== "string") continue;
      var key = r.domain + "|" + r.path + "|" + r.name;
      if (r.expiresAt !== null && r.expiresAt !== undefined && r.expiresAt <= now) continue;
      store.set(key, {
        name:      r.name,
        value:     _seal(r.value),
        domain:    r.domain,
        path:      r.path,
        hostOnly:  !!r.hostOnly,
        expiresAt: typeof r.expiresAt === "number" ? r.expiresAt : null,
        httpOnly:  !!r.httpOnly,
        secure:    !!r.secure,
        sameSite:  VALID_SAMESITE.has(r.sameSite) ? r.sameSite : null,
        createdAt: typeof r.createdAt === "number" ? r.createdAt : now,
        updatedAt: typeof r.updatedAt === "number" ? r.updatedAt : now,
      });
    }
  }

  // Raw-store accessor for tests — returns the literal Map entries with
  // the value field as it sits in memory (sealed when persist === "vault").
  // Operators don't call this; if they need stored state, getAll() returns
  // the unsealed form. Exposed so the no-plaintext assertion is verifiable.
  function _storeForTest() {
    var rows = [];
    for (var entry of store.values()) {
      rows.push({
        name:      entry.name,
        valueRaw:  entry.value,
        domain:    entry.domain,
        path:      entry.path,
        expiresAt: entry.expiresAt,
      });
    }
    return rows;
  }

  return {
    setFromResponse:    setFromResponse,
    cookieHeaderFor:    cookieHeaderFor,
    getAll:             getAll,
    clear:              clear,
    size:               size,
    setFromSerialized:  setFromSerialized,
    persist:            persist,
    _storeForTest:      _storeForTest,
  };
}

module.exports = {
  create:         create,
  CookieJarError: CookieJarError,
  DEFAULTS:       DEFAULTS,
  // Exposed for tests + advanced operator wiring.
  _parseSetCookie: _parseSetCookie,
};
// safeUrl reserved for future scheme validation hooks (e.g. operator-supplied
// allowedProtocols filter on cookie attachment paths).
void safeUrl;
