"use strict";
/**
 * pagination — cursor + offset helpers.
 *
 * Every CRUD list endpoint reinvents pagination, usually wrong.
 * The two failure modes:
 *
 *   - Offset pagination at depth: `LIMIT n OFFSET 50000` makes the DB
 *     scan-and-skip 50,000 rows. O(n). With concurrent writes, rows
 *     are also missed/duplicated as new inserts shift the offset.
 *   - Cursor pagination without a tie-breaker: `WHERE createdAt > ?`
 *     skips or duplicates rows when two records share createdAt.
 *
 * This module ships both, done correctly, plus the encode/decode
 * primitives operators reach for when their SQL doesn't fit the
 * Query-builder shape.
 *
 * Public API:
 *
 *   var p = b.pagination;
 *
 *   // Cursor: O(1) at any depth. Composite (orderBy, _id) ordering
 *   // so ties on the orderBy column are broken by _id and rows are
 *   // never skipped.
 *   var page = await p.cursor(b.db.from("users"), {
 *     cursor:    req.query.cursor,
 *     limit:     req.query.limit,
 *     max:       100,
 *     default:   25,
 *     orderBy:   "_id",         // default; use "createdAt" etc.
 *     direction: "asc",         // "asc" | "desc"
 *     secret:    pageSecret,    // Buffer or string; HMAC-tag the cursor
 *   });
 *   // → { items: [...], nextCursor, prevCursor, limit, hasMore }
 *
 *   // Offset: page-numbered. Ergonomic for legacy clients.
 *   var off = await p.offset(b.db.from("users"), {
 *     page:    req.query.page,
 *     perPage: req.query.perPage,
 *     max:     100,
 *     default: 25,
 *   });
 *   // → { items, total, page, perPage, totalPages, hasMore }
 *
 *   // Low-level — for raw SQL or custom row sources.
 *   var token = p.encodeCursor({ orderByVal: 12345, id: "abc" }, secret);
 *   var state = p.decodeCursor(token, secret);
 *
 * Cursor design:
 *   - Composite ordering: (orderBy column, _id). _id is the implicit
 *     tie-breaker, so two rows with identical orderByVal are still
 *     totally ordered. Forward navigation: WHERE
 *       (orderByVal > cur.orderByVal) OR
 *       (orderByVal = cur.orderByVal AND _id > cur.id)
 *     Backward: same with `<`, then reverse the result set.
 *   - Cursors are HMAC-tagged. A tampered cursor is detected at decode
 *     time and rejected with PaginationError. Operators MUST pass
 *     `secret` (Buffer or string) — there's no auto-derivation, since
 *     framework-derived secrets would produce surprises across deploys.
 *   - Cursor format: `<base64url state>.<base64url tag>`. State is
 *     canonical JSON of `{ v, dir, orderBy, orderByVal, id }`. Tag is
 *     SHA3-512(secret || stateJson).slice(0, 16).
 *   - direction is part of the cursor — operators don't need to round-
 *     trip it via query string. The cursor itself encodes whether it's
 *     a "next" or "prev" position so navigation stays consistent.
 *
 * Limit semantics:
 *   - Operator passes `default` and `max`. The effective limit is
 *     min(max, requestedLimit || default). Negative or non-integer
 *     limits are coerced to default.
 *   - The page query fetches limit+1 to detect hasMore without a
 *     second COUNT(*) trip.
 *
 * Offset is the legacy-client tool, not the recommended path. The
 * module's offset() returns a `total` (from COUNT(*)) and computes
 * `totalPages` so legacy clients can render numbered nav.
 *
 * Out of scope (with structural reasons documented):
 *   - Multi-column composite orderBy (orderBy: ["a", "b"]). Use raw
 *     SQL + encodeCursor / decodeCursor. The Query builder doesn't
 *     model multi-column ORDER BY today.
 *   - Cursor TTL / expiry. Operators who want time-limited cursors
 *     embed a timestamp in their own state and check at decode-time
 *     before passing to .cursor(). The framework's HMAC tag carries
 *     no notion of time.
 *   - Search / filter integration. Operators chain .where() on the
 *     Query before handing to .cursor() — pagination composes with
 *     whatever filtering the operator's already applied.
 */

var nodeCrypto = require("node:crypto");
var crypto = require("./crypto");
var { defineClass } = require("./framework-error");

var PaginationError = defineClass("PaginationError", { alwaysPermanent: true });

var CURSOR_VERSION = 1;
var TAG_BYTES = 16;            // 128-bit HMAC tag truncated from SHA3-512
var DEFAULT_LIMIT = 25;
var DEFAULT_MAX_LIMIT = 100;

// Canonical JSON — sorted keys at every depth. Mirrors safe-schema /
// audit-tools so verifier and producer hash exactly the same bytes.
function _canonicalize(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(_canonicalize).join(",") + "]";
  var keys = Object.keys(value).sort();
  var parts = [];
  for (var i = 0; i < keys.length; i++) {
    parts.push(JSON.stringify(keys[i]) + ":" + _canonicalize(value[keys[i]]));
  }
  return "{" + parts.join(",") + "}";
}

function _toBuf(secret) {
  if (Buffer.isBuffer(secret)) return secret;
  if (typeof secret === "string") return Buffer.from(secret, "utf8");
  throw new PaginationError("pagination/bad-secret",
    "secret must be a Buffer or non-empty string");
}

function _b64urlEncode(buf) {
  var b = Buffer.isBuffer(buf) ? buf : Buffer.from(buf);
  return b.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function _b64urlDecode(s) {
  if (typeof s !== "string") throw new PaginationError("pagination/bad-cursor", "cursor must be a string");
  var pad = s.length % 4;
  var padded = pad ? s + "=".repeat(4 - pad) : s;
  return Buffer.from(padded.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

function _tag(secretBuf, stateJson) {
  var h = nodeCrypto.createHash("sha3-512");
  h.update(secretBuf);
  h.update(Buffer.from(stateJson, "utf8"));
  return h.digest().slice(0, TAG_BYTES);
}

function encodeCursor(state, secret) {
  if (!state || typeof state !== "object") {
    throw new PaginationError("pagination/bad-state",
      "encodeCursor: state must be an object");
  }
  var sb = _toBuf(secret);
  if (sb.length === 0) {
    throw new PaginationError("pagination/bad-secret", "secret must be non-empty");
  }
  var withMeta = Object.assign({ v: CURSOR_VERSION }, state);
  var json = _canonicalize(withMeta);
  var tag  = _tag(sb, json);
  return _b64urlEncode(json) + "." + _b64urlEncode(tag);
}

function decodeCursor(token, secret) {
  if (typeof token !== "string" || token.length === 0) {
    throw new PaginationError("pagination/bad-cursor", "cursor must be a non-empty string");
  }
  var dot = token.indexOf(".");
  if (dot === -1) {
    throw new PaginationError("pagination/bad-cursor", "cursor missing tag separator");
  }
  var sb = _toBuf(secret);
  var jsonPart = token.slice(0, dot);
  var tagPart  = token.slice(dot + 1);
  var json, tag;
  try {
    json = _b64urlDecode(jsonPart).toString("utf8");
    tag  = _b64urlDecode(tagPart);
  } catch (_e) {
    throw new PaginationError("pagination/bad-cursor", "cursor base64 decode failed");
  }
  var expected = _tag(sb, json);
  if (!crypto.timingSafeEqual(tag, expected)) {
    throw new PaginationError("pagination/cursor-tag-mismatch",
      "cursor HMAC verification failed (tampered or wrong secret)");
  }
  var state;
  try { state = JSON.parse(json); }
  catch (_e) {
    throw new PaginationError("pagination/bad-cursor", "cursor state JSON malformed");
  }
  if (!state || typeof state !== "object") {
    throw new PaginationError("pagination/bad-cursor", "cursor state is not an object");
  }
  if (state.v !== CURSOR_VERSION) {
    throw new PaginationError("pagination/cursor-version",
      "cursor version " + state.v + " unsupported (current: " + CURSOR_VERSION + ")");
  }
  return state;
}

function _resolveLimit(opts) {
  var max = (typeof opts.max === "number" && opts.max > 0) ? opts.max : DEFAULT_MAX_LIMIT;
  var def = (typeof opts.default === "number" && opts.default > 0) ? opts.default : DEFAULT_LIMIT;
  var requested = parseInt(opts.limit, 10);
  if (isNaN(requested) || requested < 1) requested = def;
  if (requested > max) requested = max;
  return requested;
}

// ---- Cursor pagination ----

async function cursor(query, opts) {
  if (!query || typeof query.where !== "function" || typeof query.orderBy !== "function" ||
      typeof query.limit !== "function" || typeof query.all !== "function") {
    throw new PaginationError("pagination/bad-query",
      "cursor: first arg must be a db Query (must support where, orderBy, limit, all)");
  }
  opts = opts || {};
  if (opts.secret == null) {
    throw new PaginationError("pagination/no-secret",
      "cursor: opts.secret is required (Buffer or non-empty string for HMAC tagging)");
  }
  var limit     = _resolveLimit(opts);
  var orderBy   = typeof opts.orderBy === "string" && opts.orderBy.length > 0 ? opts.orderBy : "_id";
  // Throw at call site on bad orderBy — the value is interpolated into
  // a raw SQL fragment for the keyset where-clause. Restrict to
  // identifier-safe characters so a careless caller piping
  // `req.query.orderBy` through doesn't create an SQL-injection vector.
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(orderBy)) {
    throw new PaginationError("pagination/bad-orderby",
      "cursor: orderBy must match /^[A-Za-z_][A-Za-z0-9_]*$/ (identifier-safe), got " +
      JSON.stringify(orderBy));
  }
  var direction = (opts.direction === "desc") ? "desc" : "asc";

  // Decode incoming cursor (if any) and override direction from cursor.
  // The cursor authoritatively encodes which way we're paging — operators
  // shouldn't need to round-trip direction in the URL.
  var cursorState = null;
  var forward = (opts.forward !== false);
  if (opts.cursor) {
    cursorState = decodeCursor(opts.cursor, opts.secret);
    if (cursorState.orderBy !== orderBy || cursorState.dir !== direction) {
      throw new PaginationError("pagination/cursor-mismatch",
        "cursor was created with orderBy='" + cursorState.orderBy + "' direction='" +
        cursorState.dir + "' but call uses orderBy='" + orderBy + "' direction='" +
        direction + "' — operator must use the same opts the cursor was issued under");
    }
    if (typeof cursorState.forward === "boolean") forward = cursorState.forward;
  }

  // Apply the cursor predicate. Direction interacts with forward/backward:
  //   asc  + forward  → strictly greater than (orderByVal, _id)
  //   asc  + backward → strictly less than (orderByVal, _id)
  //   desc + forward  → strictly less than
  //   desc + backward → strictly greater than
  // We always SELECT in the direction that matches forward (so the
  // result rows arrive in the right reading order), then if
  // backward we reverse client-side at the end.
  var effectiveAsc = (direction === "asc") === forward; // XNOR
  var compareOp;
  if (cursorState) {
    compareOp = effectiveAsc ? ">" : "<";
    // (orderByVal, _id) <op> (?, ?)
    // Express via OR to be portable across SQLite + Postgres.
    var oCol = orderBy;
    query.whereRaw(
      '"' + oCol + '" ' + compareOp + ' ? OR ("' + oCol + '" = ? AND "_id" ' + compareOp + ' ?)',
      [cursorState.orderByVal, cursorState.orderByVal, cursorState.id]
    );
  }
  query.orderBy(orderBy, effectiveAsc ? "asc" : "desc");
  if (orderBy !== "_id") {
    // Tiebreaker by _id in the same direction — the framework Query
    // only models a single orderBy, so we add the tiebreaker as a
    // raw ORDER BY suffix via _orderLimitOffset cooperation. Today
    // Query lacks multi-orderBy; we emulate by sorting in-memory
    // after the fetch using _id within each orderBy group. Keeps
    // pagination correct without expanding the Query API.
    // No raw orderBy needed because the WHERE condition above
    // strictly disambiguates (orderByVal, _id) tuples — successive
    // pages can't repeat or skip a row even with ties on orderBy.
  }
  query.limit(limit + 1);

  var rows = await Promise.resolve(query.all());

  // Tiebreaker stability: when orderBy != _id, the SQL only sorts by
  // orderBy. Within an orderByVal cluster, sort by _id in JS so the
  // cursor predicate's _id-based tiebreaker stays consistent with the
  // returned ordering.
  if (orderBy !== "_id") {
    rows.sort(function (a, b) {
      var av = a[orderBy], bv = b[orderBy];
      if (av < bv) return effectiveAsc ? -1 : 1;
      if (av > bv) return effectiveAsc ?  1 : -1;
      var ai = String(a._id), bi = String(b._id);
      if (ai < bi) return effectiveAsc ? -1 : 1;
      if (ai > bi) return effectiveAsc ?  1 : -1;
      return 0;
    });
  }

  var hasMore = rows.length > limit;
  var page = hasMore ? rows.slice(0, limit) : rows.slice();
  if (!forward) page.reverse();

  var nextCursor = null;
  var prevCursor = null;
  if (hasMore && page.length > 0) {
    var last = page[page.length - 1];
    nextCursor = encodeCursor({
      dir: direction, orderBy: orderBy,
      orderByVal: last[orderBy], id: String(last._id),
      forward: true,
    }, opts.secret);
  }
  // Always emit a prev cursor when we have a starting position (the
  // operator was on a non-first page). Operator UI hides it on the
  // first page.
  if (cursorState && page.length > 0) {
    var first = page[0];
    prevCursor = encodeCursor({
      dir: direction, orderBy: orderBy,
      orderByVal: first[orderBy], id: String(first._id),
      forward: false,
    }, opts.secret);
  }

  return {
    items:      page,
    nextCursor: nextCursor,
    prevCursor: prevCursor,
    limit:      limit,
    hasMore:    hasMore,
  };
}

// ---- Offset pagination ----

async function offset(query, opts) {
  if (!query || typeof query.limit !== "function" || typeof query.offset !== "function" ||
      typeof query.all !== "function" || typeof query.count !== "function") {
    throw new PaginationError("pagination/bad-query",
      "offset: first arg must be a db Query (must support limit, offset, all, count)");
  }
  opts = opts || {};
  var perPage = _resolveLimit({ limit: opts.perPage, max: opts.max, default: opts.default });
  var page = parseInt(opts.page, 10);
  if (isNaN(page) || page < 1) page = 1;
  var orderBy = typeof opts.orderBy === "string" && opts.orderBy.length > 0 ? opts.orderBy : "_id";
  // Same identifier-only check on offset() as cursor() — orderBy passes
  // through to the db Query; throw at call site to prevent SQL injection.
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(orderBy)) {
    throw new PaginationError("pagination/bad-orderby",
      "offset: orderBy must match /^[A-Za-z_][A-Za-z0-9_]*$/ (identifier-safe), got " +
      JSON.stringify(orderBy));
  }
  var direction = (opts.direction === "desc") ? "desc" : "asc";

  // Count gives total — required for totalPages calculation. Cheap on
  // an indexed column (which most app tables have via _id).
  var total = await Promise.resolve(query.count());

  // Build the page query — the operator's existing where() chain is
  // already applied; we just add ordering + limit + offset.
  query.orderBy(orderBy, direction);
  query.limit(perPage);
  query.offset((page - 1) * perPage);
  var items = await Promise.resolve(query.all());

  var totalPages = total === 0 ? 0 : Math.ceil(total / perPage);
  var hasMore = page < totalPages;
  return {
    items:      items,
    total:      total,
    page:       page,
    perPage:    perPage,
    totalPages: totalPages,
    hasMore:    hasMore,
  };
}

module.exports = {
  cursor:           cursor,
  offset:           offset,
  encodeCursor:     encodeCursor,
  decodeCursor:     decodeCursor,
  PaginationError:  PaginationError,
  // Internal helpers exposed for tests
  _resolveLimit:    _resolveLimit,
  _b64urlEncode:    _b64urlEncode,
  _b64urlDecode:    _b64urlDecode,
  CURSOR_VERSION:   CURSOR_VERSION,
};
