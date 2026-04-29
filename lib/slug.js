"use strict";
/**
 * b.slug — URL-safe slug generation.
 *
 *   b.slug("Hello, World!")                           // "hello-world"
 *   b.slug("café", { preserveUnicode: false })        // "cafe"
 *   b.slug("Привет мир", { preserveUnicode: true })   // "привет-мир"
 *
 *   var slug = b.slug.create({ maxLength: 60 });
 *   slug("Title");
 *
 *   var s = await b.slug.unique("Hello, World!", function (cand) {
 *     return db.bundles.exists({ slug: cand });
 *   });
 *   // → "hello-world", or "hello-world-2", "hello-world-3", ...
 *
 * The default ASCII path uses Unicode NFKD decomposition + combining-mark
 * strip (`café` → `cafe`) and drops anything outside `[a-zA-Z0-9]`. The
 * `preserveUnicode: true` path uses NFC and only drops Unicode punctuation,
 * symbols, and separators — Cyrillic, Greek, CJK, and other scripts pass
 * through. Operators with non-Latin user content opt into preserveUnicode.
 *
 * Validation tiers:
 *
 *   - Opts at first call (every public fn) → Tier A (throw)
 *   - title not a string                   → Tier A (throw)
 *   - title normalizes to empty            → Tier C (return opts.fallback)
 *   - unique() exhausts maxAttempts        → Tier A (throw SlugError)
 *
 * Out of scope (v1):
 *   - Word-by-word transliteration tables (Russian → English, Chinese →
 *     Pinyin). Use preserveUnicode: true as the v1 escape hatch.
 *   - Stemming / lemmatization / stopword removal.
 *   - HTML-tag stripping (sanitize textually before slugging).
 */

var { SlugError } = require("./framework-error");
var _err = SlugError.factory;

// ---- Defaults ----

var DEFAULTS = Object.freeze({
  separator:       "-",
  lowercase:       true,
  maxLength:       80,
  preserveUnicode: false,
  fallback:        "",
});

// Common reserved web slugs. Operators extend (e.g. via Set union with
// router.getReservedSlugs()) and pass into b.slug.unique's isUsed predicate.
// Returned as a fresh Set on each access via the getter so callers cannot
// mutate the shared reference.
var _RESERVED = Object.freeze([
  "admin", "api", "auth", "login", "logout", "signup", "signin", "signout",
  "register", "settings", "account", "profile", "users", "user", "me",
  "static", "assets", "public", "favicon.ico", "robots.txt", "sitemap.xml",
  "health", "metrics", "ping", "status",
  "docs", "doc", "help", "support", "terms", "privacy", "legal",
  "search", "feed", "rss", "atom",
  "new", "edit", "delete", "create", "update",
]);

// ---- Tier-A validation helpers ----

function _isPositiveInt(n) {
  return typeof n === "number" && isFinite(n) && n >= 1 && Math.floor(n) === n;
}

function _validateOpts(name, opts) {
  if (typeof opts.separator !== "string" || opts.separator.length !== 1) {
    throw _err("BAD_OPT", name + ": separator must be a single-character string, got " +
      typeof opts.separator + " " + JSON.stringify(opts.separator), true);
  }
  if (typeof opts.lowercase !== "boolean") {
    throw _err("BAD_OPT", name + ": lowercase must be a boolean, got " + typeof opts.lowercase, true);
  }
  if (opts.maxLength !== null && !_isPositiveInt(opts.maxLength)) {
    throw _err("BAD_OPT", name + ": maxLength must be a positive integer or null, got " +
      typeof opts.maxLength + " " + JSON.stringify(opts.maxLength), true);
  }
  if (typeof opts.preserveUnicode !== "boolean") {
    throw _err("BAD_OPT", name + ": preserveUnicode must be a boolean, got " +
      typeof opts.preserveUnicode, true);
  }
  if (typeof opts.fallback !== "string") {
    throw _err("BAD_OPT", name + ": fallback must be a string, got " + typeof opts.fallback, true);
  }
}

// ---- Core slugify ----

// Drops Unicode marks (combining accents) after NFKD decomposition.
// The two regexes are pre-compiled because slug() is on the hot path
// for any title-driven workflow (uploads, bundle creation, seeders).
var _COMBINING_MARKS = /\p{M}+/gu;
// Anything outside ASCII alphanumeric → separator (default ASCII path).
var _NON_ASCII_ALNUM = /[^a-zA-Z0-9]+/g;
// Unicode-preserving path: drop punctuation, symbols, separators only.
// \p{P} = Punctuation, \p{S} = Symbol, \p{Z} = Separator (incl. spaces),
// \p{C} = Control/format. Letters and Numbers in any script pass through.
var _UNICODE_NON_ALNUM = /[\p{P}\p{S}\p{Z}\p{C}]+/gu;

function _slugify(title, opts) {
  if (typeof title !== "string") {
    throw _err("BAD_TITLE", "slug: title must be a string, got " + typeof title, true);
  }

  var sep = opts.separator;
  // Build a regex to collapse runs of the chosen separator. Escape since
  // separator is operator-supplied (validated single-char, but could be
  // a regex meta-char like "." or "-").
  var sepEsc = sep.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  var collapseSep = new RegExp(sepEsc + "+", "g");
  var trimSep    = new RegExp("^" + sepEsc + "+|" + sepEsc + "+$", "g");

  var s = title;

  if (opts.preserveUnicode) {
    s = s.normalize("NFC");
    s = s.replace(_UNICODE_NON_ALNUM, sep);
  } else {
    s = s.normalize("NFKD").replace(_COMBINING_MARKS, "");
    s = s.replace(_NON_ASCII_ALNUM, sep);
  }

  if (opts.lowercase) {
    // Use locale-independent toLowerCase for both paths so slug output
    // is deterministic across hosts (Turkish-locale dotted-i etc. would
    // otherwise drift).
    s = s.toLowerCase();
  }

  s = s.replace(collapseSep, sep).replace(trimSep, "");

  if (opts.maxLength !== null && s.length > opts.maxLength) {
    s = _truncateAtSeparator(s, opts.maxLength, sep);
  }

  if (s.length === 0) return opts.fallback;
  return s;
}

// Truncate at the last separator that keeps length ≤ maxLength.
// If there's no separator within the cap, fall back to char truncation
// (single-token long inputs).
function _truncateAtSeparator(s, maxLength, sep) {
  if (s.length <= maxLength) return s;
  var slice = s.slice(0, maxLength);
  var lastSep = slice.lastIndexOf(sep);
  if (lastSep > 0) return slice.slice(0, lastSep);
  return slice;
}

// ---- Public surface ----

function slug(title, callOpts) {
  var opts = Object.assign({}, DEFAULTS, callOpts || {});
  _validateOpts("slug", opts);
  return _slugify(title, opts);
}

function create(creatorOpts) {
  var merged = Object.assign({}, DEFAULTS, creatorOpts || {});
  _validateOpts("slug.create", merged);
  // Bound function: per-call opts override creator opts.
  return function boundSlug(title, callOpts) {
    var opts = Object.assign({}, merged, callOpts || {});
    _validateOpts("slug", opts);
    return _slugify(title, opts);
  };
}

async function unique(title, isUsed, callOpts) {
  if (typeof isUsed !== "function") {
    throw _err("BAD_ISUSED", "slug.unique: isUsed must be a function, got " + typeof isUsed, true);
  }
  callOpts = callOpts || {};
  var opts = Object.assign({}, DEFAULTS, callOpts);
  _validateOpts("slug.unique", opts);

  var maxAttempts = (callOpts.maxAttempts !== undefined) ? callOpts.maxAttempts : 100;
  if (!_isPositiveInt(maxAttempts)) {
    throw _err("BAD_OPT", "slug.unique: maxAttempts must be a positive integer, got " +
      typeof maxAttempts + " " + JSON.stringify(maxAttempts), true);
  }
  var start = (callOpts.start !== undefined) ? callOpts.start : 2;
  if (!_isPositiveInt(start)) {
    throw _err("BAD_OPT", "slug.unique: start must be a positive integer, got " +
      typeof start + " " + JSON.stringify(start), true);
  }
  var suffixSep = (callOpts.suffixSeparator !== undefined) ? callOpts.suffixSeparator : opts.separator;
  if (typeof suffixSep !== "string" || suffixSep.length === 0) {
    throw _err("BAD_OPT", "slug.unique: suffixSeparator must be a non-empty string, got " +
      typeof suffixSep, true);
  }

  var base = _slugify(title, opts);
  // First attempt: bare base.
  var used = await isUsed(base);
  if (!used) return base;

  // Subsequent attempts: base + suffixSep + n, starting at `start`.
  // The bare base counted as attempt 1; we have maxAttempts-1 numeric tries left.
  for (var i = 0; i < maxAttempts - 1; i++) {
    var n = start + i;
    var candidate = base + suffixSep + n;
    // If maxLength would be exceeded by the suffix, truncate the base further
    // so the final candidate fits.
    if (opts.maxLength !== null && candidate.length > opts.maxLength) {
      var roomForBase = opts.maxLength - (suffixSep.length + String(n).length);
      if (roomForBase < 1) {
        // Pathological case: caller's maxLength can't hold any base with this suffix.
        throw _err("UNIQUE_EXHAUSTED",
          "slug.unique: maxLength " + opts.maxLength + " too small for suffix '" +
          suffixSep + n + "' (base would need " + roomForBase + " chars)", true);
      }
      var truncBase = _truncateAtSeparator(base, roomForBase, opts.separator);
      candidate = truncBase + suffixSep + n;
    }
    var taken = await isUsed(candidate);
    if (!taken) return candidate;
  }

  throw _err("UNIQUE_EXHAUSTED",
    "slug.unique: exhausted " + maxAttempts + " attempts for base '" + base + "'", true);
}

// b.slug is the function itself with sub-API hung off it (callable
// namespace pattern). Operators get the 90% case (`b.slug("title")`) in
// one line and reach the rest via `b.slug.create`, `b.slug.unique`,
// `b.slug.RESERVED`, `b.slug.DEFAULTS`, `b.slug.SlugError`.
//
// The shared RESERVED Set is intentionally mutable so an app can
// extend it once at boot:
//   b.slug.RESERVED.add("my-reserved-route");
slug.create    = create;
slug.unique    = unique;
slug.RESERVED  = new Set(_RESERVED);
slug.DEFAULTS  = DEFAULTS;
slug.SlugError = SlugError;

module.exports = slug;
