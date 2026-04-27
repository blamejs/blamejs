"use strict";
/**
 * HTTP client primitive — Promise-returning, AbortSignal-aware,
 * connection-pooled, streaming-capable, HTTP/2-capable.
 *
 * Built on node:http, node:https, and node:http2. Zero npm runtime
 * dependency. Same caller surface for h1 and h2; the protocol version
 * is negotiated per-origin via ALPN (h2 preferred, h1 fallback).
 *
 * Single entry point:
 *
 *   await httpClient.request({
 *     method,             // string, default GET
 *     url,                // string or URL
 *     headers,            // object, default {}
 *     body,               // Buffer | string | Readable | undefined
 *     timeoutMs,          // wall-clock cap (caller-chosen, no default)
 *     idleTimeoutMs,      // zero-progress idle cap (default 30s)
 *     responseMode,       // "buffer" (default) | "stream"
 *     maxResponseBytes,   // for buffer mode (default 16 MiB control,
 *                         //   1 GiB GET — operators with > 1 GiB
 *                         //   stored objects must use stream mode)
 *     signal,             // AbortSignal — propagated to req/stream
 *     errorClass,         // FrameworkError subclass
 *     observer,           // optional (stage, info) => void hook
 *     agent,              // override per-origin pool (h1 only)
 *     preferH2,           // bool — for cleartext h2 (h2c). HTTPS origins
 *                         //   already attempt h2 via ALPN; this flag is
 *                         //   for HTTP origins (internal services, tests)
 *                         //   that explicitly speak h2c.
 *   })
 *     → { statusCode, headers, body }
 *
 * Protocol selection:
 *
 *   - HTTPS origin: TLS handshake with ALPN ['h2', 'http/1.1']. If
 *     server picks 'h2', subsequent requests to that origin multiplex
 *     over the same h2 session. If server picks 'h1', the cached
 *     transport is an https.Agent with keepAlive.
 *
 *   - HTTP origin without preferH2: h1 only.
 *   - HTTP origin with preferH2: h2c (cleartext h2). No ALPN — caller
 *     attests the server speaks h2c. Used by internal services and
 *     test fixtures (mock h2 server).
 *
 * Per-origin transport cache:
 *
 *   key = "<protocol>//<hostname>:<port>"
 *   value = { kind: 'h1', lib, agent } | { kind: 'h2', session }
 *
 *   While a transport is being negotiated (TLS handshake / h2 connect)
 *   the cache holds the in-flight Promise so concurrent calls to a
 *   new origin coalesce onto the same connection.
 *
 * Resiliency:
 *   - Wall-clock + idle timeouts (split — slow-progress vs zero-progress)
 *   - AbortSignal propagated to req.destroy / stream.close
 *   - TLS 1.3 minimum + PQC ecdhCurve preference
 *   - h2 session GOAWAY / error → cache eviction; next request reconnects
 *   - h2 stream cancellation via NGHTTP2_CANCEL on abort (clean, not destroy)
 *   - Request-body stream errors propagated to Promise rejection
 */

var http  = require("http");
var https = require("https");
var http2 = require("http2");
var { URL } = require("url");
var C = require("./constants");
var bufferSafe = require("./buffer-safe");
var urlSafe = require("./url-safe");
var asyncSafe = require("./async-safe");
var pqcAgent = require("./pqc-agent");
var { FrameworkError } = require("./framework-error");

// Per-origin transport cache. Entry is either the resolved transport
// object or a pending Promise that resolves to one. The Promise form
// lets concurrent calls to a new origin coalesce on the same connect.
//
// Transport shapes the cache currently holds:
//
//   { kind: "h1", lib, agent }            — node:http(s) + keepAlive Agent
//   { kind: "h2", session }               — node:http2 ClientHttp2Session
//
// Reserved for the future (when node:http3 ships stable — currently
// behind --experimental-quic, no http3 module yet):
//
//   { kind: "h3", session }               — node:http3 ClientHttp3Session
//
// Adding the h3 case won't change the caller-facing surface: ALPN
// negotiation gains "h3" as the highest-preference protocol over QUIC,
// _getTransport branches on the resolved transport, and a new
// _requestH3 mirrors _requestH2's stream-based shape. h3's design
// gives 0-RTT first-class (vs. h1/h2 where 0-RTT is opaque under
// node's TLS layer — see TLS_SESSION_RESUMPTION_NOTES below).
var _transports = new Map();

// TLS session resumption notes — what we get for free vs. what's
// out of reach today:
//
//   keepAlive Agent (h1) / long-lived ClientHttp2Session (h2) means
//   the WARM-CONNECTION case is zero-handshake — better than 0-RTT.
//   We pay the TLS handshake once per origin, then amortize.
//
//   When a pool socket is recycled, node's tls layer caches session
//   tickets and does 1-RTT resumption automatically. We don't
//   expose 0-RTT (early_data) — node's https.Agent has no clean API
//   for it, and 0-RTT is REPLAY-RISKY for non-idempotent requests
//   (server can't distinguish original from replay until the
//   handshake completes). Operators who need 0-RTT for a specific
//   idempotent path can pass their own agent via opts.agent.
//
//   QUIC/h3 changes this calculus: 0-RTT is a first-class feature
//   built into the protocol, with replay protection at the QUIC
//   layer. We'll plumb it through when h3 lands.

// Pool tuning for the HTTP-client transport cache. Keep-alive is
// shorter than the standalone pqc-agent default (1s vs 30s) because
// the cache layer manages its own warm-connection reuse and we want
// idle sockets reaped quickly between bursts. ecdhCurve / minVersion
// come from pqc-agent and cannot be set here — the framework's
// PQC-only TLS posture is one place, in lib/pqc-agent.js.
var HTTP_CLIENT_AGENT_OPTS = {
  keepAlive:        true,
  keepAliveMsecs:   1000,
  maxSockets:       16,
  maxFreeSockets:   8,
  scheduling:       "lifo",
};

// h2 session connect options. Same TLS posture as h1 Agent.
var DEFAULT_H2_TLS_OPTS = {
  ALPNProtocols:    ["h2", "http/1.1"],
  ecdhCurve:        C.TLS_GROUP_CURVE_STR,
  minVersion:       "TLSv1.3",
};

var DEFAULT_CONTROL_PLANE_CAP = C.BYTES.mib(16);
var DEFAULT_GET_CAP           = C.BYTES.gib(1);
var DEFAULT_IDLE_TIMEOUT_MS   = C.TIME.seconds(30);

// h2 session idle close. After this much idle time with no streams,
// close the session — long-running processes don't pin one TLS
// connection forever.
var H2_SESSION_IDLE_TIMEOUT_MS = C.TIME.minutes(5);

function _originKey(u) {
  return u.protocol + "//" + u.hostname + ":" +
    (u.port || (u.protocol === "https:" ? 443 : 80));
}

function _makeH1Transport(u) {
  var lib = u.protocol === "https:" ? https : http;
  // HTTPS path goes through pqcAgent.create so the framework's PQC-only
  // posture is enforced via the single primitive. Cleartext HTTP stays
  // on http.Agent because there's no TLS posture to enforce.
  var agent = u.protocol === "https:"
    ? pqcAgent.create(HTTP_CLIENT_AGENT_OPTS)
    : new lib.Agent(HTTP_CLIENT_AGENT_OPTS);
  return { kind: "h1", lib: lib, agent: agent };
}

// Connect an h2 session to an HTTPS origin via ALPN. If the server picks
// http/1.1, fall back to an h1 transport for that origin.
function _connectHttpsWithAlpn(u) {
  return new Promise(function (resolve, reject) {
    var session = http2.connect(u.protocol + "//" + u.host, DEFAULT_H2_TLS_OPTS);
    var settled = false;
    function _done(t)   { if (!settled) { settled = true; resolve(t); } }
    function _fail(err) { if (!settled) { settled = true; reject(err); } }

    session.once("connect", function () {
      var alpn = session.alpnProtocol;
      if (alpn === "h2") {
        _wireH2Session(session, _originKey(u));
        _done({ kind: "h2", session: session });
        return;
      }
      // Server picked http/1.1 — close the h2 session, return h1 transport.
      try { session.close(); } catch (_e) {}
      _done(_makeH1Transport(u));
    });
    session.once("error", function (err) {
      try { session.close(); } catch (_e) {}
      _fail(err);
    });
  });
}

// Connect an h2c session (cleartext h2). No ALPN, no fallback — caller
// has attested via preferH2 that the server speaks h2c.
function _connectH2c(u) {
  return new Promise(function (resolve, reject) {
    var session = http2.connect(u.protocol + "//" + u.host);
    session.once("connect", function () {
      _wireH2Session(session, _originKey(u));
      resolve({ kind: "h2", session: session });
    });
    session.once("error", function (err) {
      try { session.close(); } catch (_e) {}
      reject(err);
    });
  });
}

// Common h2 session wiring — idle close + cache eviction on error/close.
function _wireH2Session(session, key) {
  session.setTimeout(H2_SESSION_IDLE_TIMEOUT_MS, function () {
    try { session.close(); } catch (_e) {}
  });
  session.once("close", function () { _transports.delete(key); });
  session.once("error", function () { _transports.delete(key); });
  session.once("goaway", function () {
    // Server signalling 'no new streams' — let in-flight finish, evict cache.
    _transports.delete(key);
  });
}

// Async transport selection. Returns Promise<transport>.
function _getTransport(u, opts) {
  var key = _originKey(u);
  var cached = _transports.get(key);
  if (cached) {
    // Could be a resolved transport OR a pending Promise.
    return Promise.resolve(cached);
  }

  var promise;
  if (u.protocol === "https:") {
    promise = _connectHttpsWithAlpn(u);
  } else if (opts && opts.preferH2) {
    promise = _connectH2c(u);
  } else {
    // HTTP without preferH2 → h1 only.
    promise = Promise.resolve(_makeH1Transport(u));
  }

  // Cache the in-flight Promise immediately so concurrent calls
  // coalesce. On resolve, replace with the transport. On reject, evict.
  _transports.set(key, promise);
  promise.then(
    function (t)   { _transports.set(key, t); },
    function (_err) { _transports.delete(key); }
  );

  return promise;
}

function _makeError(errorClass, code, message, permanent, statusCode) {
  if (!errorClass) return new FrameworkError(message, code);
  return new errorClass(code, message, permanent, statusCode);
}

function _isPermanentStatus(statusCode) {
  if (statusCode >= 400 && statusCode < 500) {
    return statusCode !== 408 && statusCode !== 425 && statusCode !== 429;
  }
  return false;
}

// h2 sends headers as lowercased keys plus :method / :path / :scheme /
// :authority pseudo-headers. Convert from h1-shaped headers.
function _toH2Headers(method, u, headers) {
  var h2Headers = Object.create(null);
  h2Headers[":method"]    = method;
  h2Headers[":path"]      = u.pathname + (u.search || "");
  h2Headers[":scheme"]    = u.protocol === "https:" ? "https" : "http";
  h2Headers[":authority"] = u.host;
  for (var k in headers) {
    if (!Object.prototype.hasOwnProperty.call(headers, k)) continue;
    var lk = k.toLowerCase();
    // h2 forbids the connection-specific headers
    if (lk === "connection" || lk === "host" ||
        lk === "keep-alive" || lk === "transfer-encoding" ||
        lk === "upgrade" || lk === "proxy-connection") continue;
    h2Headers[lk] = headers[k];
  }
  return h2Headers;
}

function _fromH2Headers(h2Headers) {
  // Strip pseudo-headers from the response — caller doesn't want them
  // mixed with normal headers.
  var out = {};
  for (var k in h2Headers) {
    if (!Object.prototype.hasOwnProperty.call(h2Headers, k)) continue;
    if (k.charAt(0) === ":") continue;
    out[k] = h2Headers[k];
  }
  return out;
}

// ---- request() ----

function request(opts) {
  if (!opts || !opts.url) {
    return Promise.reject(_makeError(opts && opts.errorClass, "BAD_ARG", "url is required", true));
  }
  // Validate scheme + shape via url-safe. Default is HTTPS-only — the
  // framework refuses to silently drop bytes on the wire as cleartext.
  // Callers with cleartext endpoints (h2c, internal services, test
  // fixtures) explicitly opt in via opts.allowedProtocols
  // (urlSafe.ALLOW_HTTP_ALL accepts both http: and https:).
  var u;
  try {
    u = urlSafe.parse(opts.url, {
      allowedProtocols: opts.allowedProtocols || urlSafe.ALLOW_HTTP_TLS,
      errorClass:       opts.errorClass,
    });
  } catch (e) {
    return Promise.reject(e);
  }

  // Caller-supplied agent bypasses transport cache (h1 only).
  if (opts.agent) {
    return _requestH1({
      kind: "h1",
      lib:  u.protocol === "https:" ? https : http,
      agent: opts.agent,
    }, u, opts);
  }

  return _getTransport(u, opts).then(function (transport) {
    if (transport.kind === "h2") return _requestH2(transport, u, opts);
    return _requestH1(transport, u, opts);
  });
}

// ---- _requestH1: existing node:http(s) path ----

function _requestH1(transport, u, opts) {
  return new Promise(function (resolve, reject) {
    var method = (opts.method || "GET").toUpperCase();
    var headers = Object.assign({}, opts.headers || {});
    var responseMode = opts.responseMode || "buffer";
    var maxResponseBytes = opts.maxResponseBytes ||
      (method === "GET" ? DEFAULT_GET_CAP : DEFAULT_CONTROL_PLANE_CAP);
    var observer = typeof opts.observer === "function" ? opts.observer : null;
    var startedAt = Date.now();

    var signal = asyncSafe.withTimeoutSignal(opts.signal || null, opts.timeoutMs);
    if (signal && signal.aborted) {
      var r0 = signal.reason;
      var code0 = (r0 && r0.name === "TimeoutError") ? "ETIMEDOUT" : "ABORT";
      return reject(_makeError(opts.errorClass, code0,
        (r0 && r0.message) || "request aborted before start", false));
    }

    if (Buffer.isBuffer(opts.body)) {
      headers["Content-Length"] = opts.body.length;
    }

    var reqOpts = {
      method:   method,
      hostname: u.hostname,
      port:     u.port || (u.protocol === "https:" ? 443 : 80),
      path:     u.pathname + (u.search || ""),
      headers:  headers,
      agent:    transport.agent,
      timeout:  typeof opts.idleTimeoutMs === "number" ? opts.idleTimeoutMs : DEFAULT_IDLE_TIMEOUT_MS,
    };

    if (observer) observer("request:start", { method: method, url: String(opts.url), protocol: "h1" });

    var settled = false;
    function _resolve(value) { if (!settled) { settled = true; resolve(value); } }
    function _reject(err)    { if (!settled) { settled = true; reject(err); } }

    var req = transport.lib.request(reqOpts, function (res) {
      if (observer) observer("response:headers", { statusCode: res.statusCode, headers: res.headers });

      if (responseMode === "stream") {
        if (res.statusCode >= 400) {
          res.resume();
          return _reject(_makeError(opts.errorClass, "HTTP_ERROR",
            "HTTP " + res.statusCode + " " + (res.statusMessage || ""),
            _isPermanentStatus(res.statusCode), res.statusCode));
        }
        return _resolve({ statusCode: res.statusCode, headers: res.headers, body: res });
      }

      var collector = bufferSafe.boundedChunkCollector({ maxBytes: maxResponseBytes });
      var capExceeded = false;

      res.on("data", function (chunk) {
        if (capExceeded) return;
        try { collector.push(chunk); }
        catch (_e) {
          capExceeded = true;
          req.destroy();
          _reject(_makeError(opts.errorClass, "RESPONSE_TOO_LARGE",
            "response body exceeds " + maxResponseBytes + " bytes", true));
        }
      });
      res.on("end", function () {
        if (capExceeded) return;
        var buf = collector.result();
        if (observer) observer("response:end", {
          statusCode: res.statusCode,
          durationMs: Date.now() - startedAt,
          bytes:      buf.length,
        });
        if (res.statusCode >= 200 && res.statusCode < 300) {
          _resolve({ statusCode: res.statusCode, headers: res.headers, body: buf });
        } else {
          var msg = "HTTP " + res.statusCode + ": " + buf.toString("utf8").slice(0, 500);
          _reject(_makeError(opts.errorClass, "HTTP_ERROR", msg,
            _isPermanentStatus(res.statusCode), res.statusCode));
        }
      });
      res.on("error", function (e) {
        if (capExceeded) return;
        if (observer) observer("error", { phase: "response", message: e.message });
        _reject(_makeError(opts.errorClass, e.code || "RES_ERROR", e.message, false));
      });
    });

    req.on("timeout", function () {
      req.destroy();
      _reject(_makeError(opts.errorClass, "ETIMEDOUT",
        "request idle timeout (no data for " + reqOpts.timeout + "ms)", false));
    });

    req.on("error", function (e) {
      if (observer) observer("error", { phase: "request", message: e.message });
      _reject(_makeError(opts.errorClass, e.code || "REQ_ERROR", e.message, false));
    });

    if (signal) {
      var onAbort = function () {
        var r = signal.reason;
        var code = (r && r.name === "TimeoutError") ? "ETIMEDOUT" : "ABORT";
        var msg = (r && r.message) || "request aborted";
        try { req.destroy(r || new Error(msg)); } catch (_e) {}
        _reject(_makeError(opts.errorClass, code, msg, false));
      };
      signal.addEventListener("abort", onAbort, { once: true });
    }

    if (opts.body && typeof opts.body.pipe === "function") {
      opts.body.on("error", function (e) {
        try { req.destroy(); } catch (_) {}
        _reject(_makeError(opts.errorClass, "REQ_BODY_ERROR",
          "request body stream error: " + e.message, false));
      });
      opts.body.pipe(req);
    } else if (Buffer.isBuffer(opts.body)) {
      req.end(opts.body);
    } else if (typeof opts.body === "string") {
      req.end(Buffer.from(opts.body, "utf8"));
    } else {
      req.end();
    }
  });
}

// ---- _requestH2: node:http2 path ----

function _requestH2(transport, u, opts) {
  return new Promise(function (resolve, reject) {
    var method = (opts.method || "GET").toUpperCase();
    var responseMode = opts.responseMode || "buffer";
    var maxResponseBytes = opts.maxResponseBytes ||
      (method === "GET" ? DEFAULT_GET_CAP : DEFAULT_CONTROL_PLANE_CAP);
    var observer = typeof opts.observer === "function" ? opts.observer : null;
    var startedAt = Date.now();

    var signal = asyncSafe.withTimeoutSignal(opts.signal || null, opts.timeoutMs);
    if (signal && signal.aborted) {
      var r0 = signal.reason;
      var code0 = (r0 && r0.name === "TimeoutError") ? "ETIMEDOUT" : "ABORT";
      return reject(_makeError(opts.errorClass, code0,
        (r0 && r0.message) || "request aborted before start", false));
    }

    var headers = _toH2Headers(method, u, opts.headers || {});
    if (Buffer.isBuffer(opts.body)) headers["content-length"] = String(opts.body.length);

    if (observer) observer("request:start", { method: method, url: String(opts.url), protocol: "h2" });

    var stream;
    try {
      stream = transport.session.request(headers, {
        endStream: opts.body == null,
      });
    } catch (e) {
      return reject(_makeError(opts.errorClass, e.code || "H2_REQUEST_ERROR", e.message, false));
    }

    var settled = false;
    function _resolve(v) { if (!settled) { settled = true; resolve(v); } }
    function _reject(e)  { if (!settled) { settled = true; reject(e); } }

    // Idle timeout for the stream itself (zero-progress detector).
    var idleMs = typeof opts.idleTimeoutMs === "number" ? opts.idleTimeoutMs : DEFAULT_IDLE_TIMEOUT_MS;
    stream.setTimeout(idleMs, function () {
      try { stream.close(http2.constants.NGHTTP2_CANCEL); } catch (_e) {}
      _reject(_makeError(opts.errorClass, "ETIMEDOUT",
        "h2 stream idle timeout (no data for " + idleMs + "ms)", false));
    });

    stream.on("response", function (resHeaders) {
      var statusCode = resHeaders[":status"];
      var responseHeaders = _fromH2Headers(resHeaders);

      if (observer) observer("response:headers", { statusCode: statusCode, headers: responseHeaders });

      if (responseMode === "stream") {
        if (statusCode >= 400) {
          stream.resume();
          return _reject(_makeError(opts.errorClass, "HTTP_ERROR",
            "HTTP " + statusCode, _isPermanentStatus(statusCode), statusCode));
        }
        return _resolve({ statusCode: statusCode, headers: responseHeaders, body: stream });
      }

      var collector = bufferSafe.boundedChunkCollector({ maxBytes: maxResponseBytes });
      var capExceeded = false;

      stream.on("data", function (chunk) {
        if (capExceeded) return;
        try { collector.push(chunk); }
        catch (_e) {
          capExceeded = true;
          try { stream.close(http2.constants.NGHTTP2_CANCEL); } catch (_e2) {}
          _reject(_makeError(opts.errorClass, "RESPONSE_TOO_LARGE",
            "response body exceeds " + maxResponseBytes + " bytes", true));
        }
      });
      stream.on("end", function () {
        if (capExceeded) return;
        var buf = collector.result();
        if (observer) observer("response:end", {
          statusCode: statusCode,
          durationMs: Date.now() - startedAt,
          bytes:      buf.length,
        });
        if (statusCode >= 200 && statusCode < 300) {
          _resolve({ statusCode: statusCode, headers: responseHeaders, body: buf });
        } else {
          var msg = "HTTP " + statusCode + ": " + buf.toString("utf8").slice(0, 500);
          _reject(_makeError(opts.errorClass, "HTTP_ERROR", msg,
            _isPermanentStatus(statusCode), statusCode));
        }
      });
    });

    stream.on("error", function (e) {
      if (observer) observer("error", { phase: "stream", message: e.message });
      _reject(_makeError(opts.errorClass, e.code || "H2_STREAM_ERROR", e.message, false));
    });

    if (signal) {
      var onAbort = function () {
        var r = signal.reason;
        var code = (r && r.name === "TimeoutError") ? "ETIMEDOUT" : "ABORT";
        var msg = (r && r.message) || "request aborted";
        // NGHTTP2_CANCEL is the protocol-level "I gave up" signal —
        // cleaner than destroying the stream.
        try { stream.close(http2.constants.NGHTTP2_CANCEL); } catch (_e) {}
        _reject(_makeError(opts.errorClass, code, msg, false));
      };
      signal.addEventListener("abort", onAbort, { once: true });
    }

    if (opts.body && typeof opts.body.pipe === "function") {
      opts.body.on("error", function (e) {
        try { stream.close(http2.constants.NGHTTP2_INTERNAL_ERROR); } catch (_) {}
        _reject(_makeError(opts.errorClass, "REQ_BODY_ERROR",
          "request body stream error: " + e.message, false));
      });
      opts.body.pipe(stream);
    } else if (Buffer.isBuffer(opts.body)) {
      stream.end(opts.body);
    } else if (typeof opts.body === "string") {
      stream.end(Buffer.from(opts.body, "utf8"));
    }
    // If body is null/undefined, endStream:true was set in session.request()
  });
}

// ---- Test helpers ----

function _resetForTest() {
  _transports.forEach(function (t) {
    if (t && t.kind === "h1" && t.agent && typeof t.agent.destroy === "function") {
      try { t.agent.destroy(); } catch (_e) {}
    }
    if (t && t.kind === "h2" && t.session) {
      try { t.session.close(); } catch (_e) {}
    }
  });
  _transports.clear();
}

function _getCachedTransportCount() {
  return _transports.size;
}

// Diagnostic — returns 'h1' | 'h2' | null for a given URL's cached transport.
function _getCachedTransportKind(url) {
  var u = url instanceof URL ? url : new URL(url);
  var t = _transports.get(_originKey(u));
  if (!t) return null;
  if (t.then) return "pending";
  return t.kind;
}

module.exports = {
  request:                    request,
  DEFAULT_CONTROL_PLANE_CAP:  DEFAULT_CONTROL_PLANE_CAP,
  DEFAULT_GET_CAP:            DEFAULT_GET_CAP,
  _resetForTest:              _resetForTest,
  _getCachedTransportCount:   _getCachedTransportCount,
  _getCachedTransportKind:    _getCachedTransportKind,
};
