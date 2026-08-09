// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.render
 * @nav    HTTP
 * @title  Render
 *
 * @intro
 *   Server-side HTML / JSON / XML response helpers. Each helper picks
 *   the right Content-Type, sets a sensible Cache-Control + security
 *   header default, and ends the response in one call — replacing the
 *   five-line writeHead / stringify / Content-Length / end ritual that
 *   every route handler otherwise reimplements.
 *
 *   Module-level helpers (`json` / `text` / `htmlString` / `redirect`)
 *   work without a template engine. `create({ engine })` wraps a
 *   `b.template.create` instance and returns the same helpers plus
 *   `html(res, viewName, data?)` for engine-rendered pages. Operators
 *   who never render server-side HTML import only the module-level
 *   helpers and skip the engine wiring entirely.
 *
 *   All helpers fall through silently when `res.writableEnded === true`,
 *   so a late Promise rejection after `res.end` can't corrupt the wire
 *   with a half-written second body. The default `Cache-Control` is
 *   `private, no-cache, must-revalidate` — overridable via
 *   `opts.headers["Cache-Control"]` for CDN-cacheable responses.
 *
 * @card
 *   Server-side HTML / JSON / XML response helpers.
 */

var lazyRequire  = require("./lazy-require");
var validateOpts = require("./validate-opts");

// safe-async — lazy because render is required during boot by the router and
// only the streaming helper needs it, so an operator who never streams does
// not pull the async toolkit in at load.
var safeAsync = lazyRequire(function () { return require("./safe-async"); });
// request-helpers — lazy for the same reason, and because it requires render's
// siblings; only the streaming and error paths need it.
var requestHelpers = lazyRequire(function () { return require("./request-helpers"); });

var DEFAULT_CHARSET = "utf-8";

function _alreadyDone(res) {
  return res && res.writableEnded === true;
}

function _writeResponse(res, status, headers, body) {
  if (_alreadyDone(res)) return;
  // The headers are already on the wire — writeHead would throw
  // ERR_HTTP_HEADERS_SENT and take the caller's error path with it. This is
  // the natural recovery after a streaming failure ("catch, then render a
  // 500"), so it has to fail as an incomplete transfer rather than a crash.
  if (res.headersSent === true && requestHelpers().failAfterHeaders(res)) return;
  if (typeof res.writeHead === "function") {
    res.writeHead(status, headers);
  } else {
    // Plain object response (for tests). Best-effort header set.
    res.statusCode = status;
    if (typeof res.setHeader === "function") {
      for (var k in headers) {
        if (Object.prototype.hasOwnProperty.call(headers, k)) res.setHeader(k, headers[k]);
      }
    }
  }
  if (typeof res.end === "function") res.end(body);
}

function _mergedHeaders(base, extra) {
  if (!extra) return base;
  var out = {};
  validateOpts.assignOwnEnumerable(out, base);
  validateOpts.assignOwnEnumerable(out, extra);
  return out;
}

// Default Cache-Control for dynamic responses. Browsers heuristically
// cache HTML responses without explicit headers, which causes "saved
// changes don't appear" bugs after a POST/redirect. `no-cache` permits
// caching but forces revalidation on every access — server returns 200
// with fresh content (or 304 if unchanged) instead of the browser
// silently serving stale. Operators wanting a public CDN cacheable
// response override via `opts.headers["Cache-Control"]`.
var DEFAULT_DYNAMIC_CACHE_CONTROL = "private, no-cache, must-revalidate";

/**
 * @primitive b.render.json
 * @signature b.render.json(res, body, opts)
 * @since     0.1.0
 * @status    stable
 * @related   b.render.text, b.render.htmlString, b.render.create
 *
 * JSON-stringifies `body` and writes it to `res` with Content-Type
 * `application/json; charset=utf-8`, an explicit `Content-Length`,
 * and the dynamic-response Cache-Control. Status defaults to 200;
 * any custom headers in `opts.headers` merge over the defaults so
 * operators can pin a different Cache-Control or add CORS headers
 * without losing Content-Type. Returns `undefined` — the response
 * is fully written by the time the call returns.
 *
 * `opts.replacer` is forwarded to `JSON.stringify` (ECMA-262 §25.5.2,
 * the second argument) so handlers can serialize values that have no
 * native JSON form — `BigInt` (which otherwise throws), `Date` in a
 * custom shape, `Map` / `Set`, or a redaction filter over secret-
 * shaped keys — without pre-walking the body. Accepts the same
 * function or property-name array `JSON.stringify` does; a non-
 * function / non-array value is a config typo and throws.
 *
 * @opts
 *   status:   200,                  // numeric HTTP status (200/201/202/4xx/5xx)
 *   headers:  {},                   // merged over defaults; later wins
 *   replacer: function|string[],    // JSON.stringify replacer (BigInt/Date/redaction)
 *
 * @example
 *   b.render.json(res, { ok: true, id: 42 }, { status: 201 });
 *   // → response: 201, application/json, body `{"ok":true,"id":42}`
 *
 *   b.render.json(res, { total: 9007199254740993n }, {
 *     replacer: function (k, v) { return typeof v === "bigint" ? v.toString() : v; },
 *   });
 *   // → body `{"total":"9007199254740993"}`
 */
function json(res, body, opts) {
  opts = opts || {};
  if (opts.replacer !== undefined && opts.replacer !== null &&
      typeof opts.replacer !== "function" && !Array.isArray(opts.replacer)) {
    throw new TypeError("render.json: opts.replacer must be a function or an array of keys");
  }
  var encoded = JSON.stringify(body, opts.replacer);
  var headers = _mergedHeaders({
    "Content-Type":   "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(encoded, "utf8"),
    "Cache-Control":  DEFAULT_DYNAMIC_CACHE_CONTROL,
  }, opts.headers);
  _writeResponse(res, opts.status || 200, headers, encoded);
}

/**
 * @primitive b.render.stream
 * @signature b.render.stream(res, iterable, opts?)
 * @since     0.18.19
 * @status    stable
 * @related   b.render.json, b.safeAsync.writeChunk
 *
 * Write an async (or sync) iterable to a response, one chunk at a time, and
 * end it. For a generated download — a CSV export, an NDJSON dump, a receipt —
 * where the source is a generator over a cursor rather than a `Readable` that
 * could simply be piped.
 *
 * The obvious loop is wrong in three ways that testing does not surface.
 * `res.write()` returning `false` is easy to discard, and a local client
 * drains instantly, so a bounded-memory export becomes unbounded only under a
 * slow client. Always awaiting `'drain'` then hangs forever when the peer has
 * gone, because a closed socket never emits it. And a producer that throws
 * after the first byte cannot be turned into an error page: the status line is
 * already sent, so the handler appends its message to the partial body and the
 * client receives a 200 whose last row reads "Internal Server Error" — a
 * truncated export that every consumer reads as complete.
 *
 * So: back-pressure is awaited, a closed peer stops the loop instead of
 * stalling it, and a mid-stream throw destroys the connection. Destroying ends
 * a chunked response without its terminating chunk, which is the only signal
 * left that says "this transfer is incomplete" once bytes are on the wire. The
 * error is re-thrown either way, so the caller still logs it.
 *
 * Headers are written from `opts` before the first chunk unless the caller has
 * already sent them. Nothing is buffered: a chunk is handed to the socket as
 * the producer yields it.
 *
 * @opts
 *   status:   200,        // numeric HTTP status, sent with the first chunk
 *   headers:  {},         // merged over the dynamic-response defaults
 *   onError:  "destroy",  // "destroy" (default) or "rethrow" to leave the socket alone
 *   signal:   AbortSignal, // stop producing when it aborts
 *
 * @example
 *   await b.render.stream(res, rows(), {
 *     headers: { "Content-Type": "text/csv; charset=utf-8" },
 *   });
 *
 *   async function* rows() {
 *     yield "order_id,total\n";
 *     for await (var r of cursor) yield r.id + "," + r.total + "\n";
 *   }
 */
async function stream(res, iterable, opts) {
  opts = opts || {};
  validateOpts(opts, ["status", "headers", "onError", "signal"], "render.stream");
  if (!iterable || (typeof iterable[Symbol.asyncIterator] !== "function" &&
                    typeof iterable[Symbol.iterator] !== "function")) {
    throw new TypeError("render.stream: expected an async or sync iterable of chunks");
  }
  if (opts.onError !== undefined && opts.onError !== "destroy" && opts.onError !== "rethrow") {
    throw new TypeError("render.stream: opts.onError must be \"destroy\" or \"rethrow\"");
  }
  if (_alreadyDone(res)) return;

  var headers = _mergedHeaders({
    "Content-Type":  "application/octet-stream",
    "Cache-Control": DEFAULT_DYNAMIC_CACHE_CONTROL,
  }, opts.headers);
  if (res.headersSent !== true && typeof res.writeHead === "function") {
    res.writeHead(opts.status || 200, headers);
  }

  // The status line went out above, so from here the response is committed
  // whether or not a chunk has been written yet. Treating "committed" as "at
  // least one chunk landed" left a producer that failed on its first row with
  // a response that was neither ended nor destroyed — headers and
  // `Transfer-Encoding: chunked` on the wire and nothing to follow, so the
  // client waited forever.
  var aborted = false;
  try {
    for await (var chunk of _withAbort(iterable, opts.signal)) {
      if (opts.signal && opts.signal.aborted) { aborted = true; break; }
      // The peer is gone: stop pulling from the producer rather than writing
      // rows nobody will read, and do not wait for a drain that never comes.
      if (_peerGone(res)) break;
      if (chunk === null || chunk === undefined) continue;
      await _raceAbort(safeAsync().writeChunk(res, chunk), opts.signal);
      if (opts.signal && opts.signal.aborted) { aborted = true; break; }
    }
  } catch (e) {
    if (_isAbort(e, opts.signal)) aborted = true;
    else {
      if (opts.onError !== "rethrow") requestHelpers().failAfterHeaders(res);
      throw e;
    }
  }
  // An abort is a truncation too. Ending normally would write the terminating
  // chunk and hand the client four rows of a fifty-row export as a complete,
  // successful 200 — the very outcome this primitive exists to prevent, and
  // the caller would not hear about it either.
  if (aborted) {
    requestHelpers().failAfterHeaders(res);
    return;
  }
  if (typeof res.end === "function" && !_alreadyDone(res)) res.end();
}

// Stop waiting on the producer when the signal fires. Without this the abort
// is only seen between chunks, so a generator blocked on a query that never
// returns pins the request no matter what the caller does with the signal.
function _withAbort(iterable, signal) {
  if (!signal) return iterable;
  var inner = typeof iterable[Symbol.asyncIterator] === "function"
    ? iterable[Symbol.asyncIterator]()
    : iterable[Symbol.iterator]();
  var wrapped = {};
  wrapped[Symbol.asyncIterator] = function () {
    return {
      next: function () {
        if (signal.aborted) return Promise.resolve({ done: true, value: undefined });
        return _raceAbort(Promise.resolve(inner.next()), signal);
      },
      return: function (v) {
        if (typeof inner.return === "function") return Promise.resolve(inner.return(v));
        return Promise.resolve({ done: true, value: v });
      },
    };
  };
  return wrapped;
}

// Settle as soon as the signal fires, so a wait for `drain` from a peer that
// stopped reading does not outlive the abort.
function _raceAbort(promise, signal) {
  if (!signal) return promise;
  if (signal.aborted) return Promise.reject(_abortError(signal));
  return new Promise(function (resolve, reject) {
    function onAbort() { reject(_abortError(signal)); }
    signal.addEventListener("abort", onAbort, { once: true });
    promise.then(function (v) {
      signal.removeEventListener("abort", onAbort);
      resolve(v);
    }, function (e) {
      signal.removeEventListener("abort", onAbort);
      reject(e);
    });
  });
}

function _abortError(signal) {
  var err = new Error("render.stream: aborted");
  err.code = "render/aborted";
  err.cause = signal && signal.reason;
  return err;
}

function _isAbort(e, signal) {
  if (signal && signal.aborted) return true;
  return !!(e && e.code === "render/aborted");
}

// A response whose socket has been destroyed or whose peer has hung up. Both
// are reported differently across Node versions and response doubles, so all
// three signals are consulted.
function _peerGone(res) {
  if (!res) return true;
  if (res.destroyed === true || res.writableEnded === true) return true;
  return !!(res.socket && res.socket.destroyed === true);
}

/**
 * @primitive b.render.text
 * @signature b.render.text(res, body, opts)
 * @since     0.1.0
 * @status    stable
 * @related   b.render.json, b.render.htmlString
 *
 * Coerces `body` to a string and writes it as `text/plain` with the
 * supplied charset (default `utf-8`). `null` / `undefined` body
 * becomes the empty string rather than the literal text `"null"` —
 * a common gotcha when forwarding a value-or-nothing handler result.
 *
 * @opts
 *   status:  200,
 *   headers: {},
 *   charset: "utf-8",
 *
 * @example
 *   b.render.text(res, "OK");
 *   // → 200, Content-Type "text/plain; charset=utf-8", body "OK"
 */
function text(res, body, opts) {
  opts = opts || {};
  var encoded = body == null ? "" : String(body);
  var charset = opts.charset || DEFAULT_CHARSET;
  var headers = _mergedHeaders({
    "Content-Type":   "text/plain; charset=" + charset,
    "Content-Length": Buffer.byteLength(encoded, charset),
    "Cache-Control":  DEFAULT_DYNAMIC_CACHE_CONTROL,
  }, opts.headers);
  _writeResponse(res, opts.status || 200, headers, encoded);
}

/**
 * @primitive b.render.htmlString
 * @signature b.render.htmlString(res, htmlBody, opts)
 * @since     0.1.0
 * @status    stable
 * @related   b.render.json, b.render.create
 *
 * Writes a pre-rendered HTML string with `Content-Type: text/html;
 * charset=<charset>`. Use when an HTML body is already in hand — for
 * engine-bound view rendering, prefer `b.render.create({ engine })`
 * and the returned `html(res, viewName, data)` helper which threads
 * `res.locals` (CSP nonce, request id, current user) into the view.
 *
 * @opts
 *   status:  200,
 *   headers: {},
 *   charset: "utf-8",
 *
 * @example
 *   b.render.htmlString(res, "<h1>Hi</h1>");
 *   // → 200, text/html; charset=utf-8, body "<h1>Hi</h1>"
 */
function htmlString(res, htmlBody, opts) {
  opts = opts || {};
  var encoded = htmlBody == null ? "" : String(htmlBody);
  var charset = opts.charset || DEFAULT_CHARSET;
  var headers = _mergedHeaders({
    "Content-Type":   "text/html; charset=" + charset,
    "Content-Length": Buffer.byteLength(encoded, charset),
    "Cache-Control":  DEFAULT_DYNAMIC_CACHE_CONTROL,
  }, opts.headers);
  _writeResponse(res, opts.status || 200, headers, encoded);
}

/**
 * @primitive b.render.redirect
 * @signature b.render.redirect(res, location, opts)
 * @since     0.1.0
 * @status    stable
 * @related   b.safeRedirect, b.render.json
 *
 * Sends a 3xx response with the given `Location` header and an empty
 * body. Throws when `location` is empty or when `opts.status` falls
 * outside the 300–399 range. Default status is 302; pass 301 / 303 /
 * 307 / 308 for the other RFC 7231 / 7538 redirect semantics. For
 * untrusted user-supplied destinations, validate first via
 * `b.safeRedirect` before passing the result here.
 *
 * @opts
 *   status:  302,   // 301 / 302 / 303 / 307 / 308
 *   headers: {},
 *
 * @example
 *   b.render.redirect(res, "/login", { status: 303 });
 *   // → 303, Location "/login", empty body
 */
function redirect(res, location, opts) {
  opts = opts || {};
  if (typeof location !== "string" || location.length === 0) {
    throw new Error("render.redirect: location is required");
  }
  var status = opts.status || 302;
  if (status < 300 || status > 399) {
    throw new Error("render.redirect: status must be 3xx (got " + status + ")");
  }
  var headers = _mergedHeaders({
    "Location":       location,
    "Content-Length": 0,
    "Cache-Control":  DEFAULT_DYNAMIC_CACHE_CONTROL,
  }, opts.headers);
  _writeResponse(res, status, headers, "");
}

// ---- Engine-bound instance ----

/**
 * @primitive b.render.create
 * @signature b.render.create(opts)
 * @since     0.1.0
 * @status    stable
 * @related   b.template.create, b.render.htmlString
 *
 * Binds a template engine to a renderer and returns the module-level
 * helpers (`json` / `text` / `htmlString` / `redirect`) plus
 * `html(res, viewName, data?, opts?)`. The `html` helper auto-merges
 * `res.locals` into the template data so request-scoped values
 * (CSP nonce, request id, current user) thread through every render
 * without per-route plumbing. Operator-supplied `data` keys take
 * precedence over locals — explicit beats implicit. Throws when
 * `opts.engine.render` is not a function.
 *
 * @opts
 *   engine: <required>,   // a template engine instance from b.template.create({ viewsDir })
 *
 * @example
 *   var engine = b.template.create({ viewsDir: "/srv/views" });
 *   var r      = b.render.create({ engine: engine });
 *   r.html(res, "home", { user: "ada" });
 *   // → 200, text/html; charset=utf-8, body = engine.render("home", merged-locals)
 */
function create(opts) {
  opts = opts || {};
  if (!opts.engine || typeof opts.engine.render !== "function") {
    throw new Error("render.create({ engine }): engine.render must be a function " +
      "(pass a template engine from b.template.create)");
  }
  var engine = opts.engine;

  function html(res, viewName, data, htmlOpts) {
    htmlOpts = htmlOpts || {};
    // Auto-merge res.locals into template data — the framework's
    // request-scoped surface (cspNonce, requestId, current user, etc.)
    // lands in res.locals via middleware (csp-nonce, attach-user, etc.).
    // Operators no longer have to thread these through every render
    // call. Operator-supplied `data` keys take precedence over locals
    // — explicit > implicit.
    var merged;
    if (res && res.locals && typeof res.locals === "object") {
      merged = {};
      var lk = Object.keys(res.locals);
      for (var li = 0; li < lk.length; li++) merged[lk[li]] = res.locals[lk[li]];
      if (data) {
        var dk = Object.keys(data);
        for (var di = 0; di < dk.length; di++) merged[dk[di]] = data[dk[di]];
      }
    } else {
      merged = data || {};
    }
    var body = engine.render(viewName, merged);
    return htmlString(res, body, htmlOpts);
  }

  return {
    html:        html,
    htmlString:  htmlString,
    json:        json,
    text:        text,
    redirect:    redirect,
    engine:      engine,
  };
}

module.exports = {
  create:      create,
  json:        json,
  stream:      stream,
  text:        text,
  htmlString:  htmlString,
  redirect:    redirect,
};
