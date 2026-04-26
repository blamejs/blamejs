"use strict";
/**
 * HTTP client primitive — Promise-returning, AbortSignal-aware,
 * connection-pooled, streaming-capable.
 *
 * Built on node:http / node:https (zero npm runtime dep). v0.1.33 will
 * add HTTP/2 support behind the same surface; the transport cache and
 * ALPN-negotiation hooks below are intentionally shaped so the h2
 * backend slots in without changing any caller.
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
 *     signal,             // AbortSignal — propagated to req.destroy()
 *     errorClass,         // FrameworkError subclass (ObjectStoreError,
 *                         //   LogStreamError, etc.) — adapter-specific
 *                         //   error decoration without each adapter
 *                         //   reinventing the (code, msg, perm, status)
 *                         //   _err pattern
 *     observer,           // optional (stage, info) => void hook for
 *                         //   adapter-side audit / metrics — stages:
 *                         //   request:start, response:headers,
 *                         //   response:end, error
 *     agent,              // override per-origin pool (rare; tests use it)
 *   })
 *     → { statusCode, headers, body }
 *       (body: Buffer when responseMode='buffer'; Readable when 'stream')
 *
 * Resiliency notes:
 *
 *   - Wall-clock timeout uses AbortSignal.timeout(ms). When combined
 *     with a caller signal, AbortSignal.any merges them so either path
 *     can cancel. AbortSignal.timeout produces a TimeoutError reason
 *     that we surface as ETIMEDOUT.
 *
 *   - Idle timeout (reqOpts.timeout) is the secondary defense — fires
 *     when zero bytes flow for `idleTimeoutMs`. A slow-but-progressing
 *     response will still complete within the wall-clock cap.
 *
 *   - Per-origin Agent with keepAlive avoids re-handshaking TLS on
 *     every call. Pool sizes default to 16 concurrent + 8 idle per
 *     origin — enough for burst object-store calls without thundering-
 *     herd risk.
 *
 *   - TLS 1.3 minimum (modernity stance) + PQC ecdhCurve preference are
 *     baked into the Agent options. Old-TLS endpoints fail at handshake
 *     rather than silently downgrading.
 *
 *   - Streaming response mode returns the IncomingMessage directly. The
 *     caller drives backpressure via the native Readable. Non-2xx
 *     responses still reject the Promise (with a drain on the body to
 *     avoid socket leak).
 *
 *   - Streaming request bodies (Readable) wire .on('error') so an
 *     upstream error propagates to the Promise rejection cleanly.
 */

var http = require("http");
var https = require("https");
var { URL } = require("url");
var C = require("./constants");
var bufferSafe = require("./buffer-safe");
var { FrameworkError } = require("./framework-error");

// Per-origin transport cache. Key = "<protocol>//<hostname>:<port>".
// Value is currently { kind: "h1", lib, agent }. v0.1.33 will add
// { kind: "h2", session: ClientHttp2Session } variants under the same
// key shape — the cache is intentionally h2-ready.
var _transports = new Map();

// Default Agent options. Tuned for object-store burst: a TLS handshake
// per call is the previous baseline, so even a small pool (16/8) is a
// large win over zero pooling.
var DEFAULT_AGENT_OPTS = {
  keepAlive:        true,
  keepAliveMsecs:   1000,
  maxSockets:       16,
  maxFreeSockets:   8,
  scheduling:       "lifo",
  // PQC TLS group preference for HTTPS endpoints. Ignored for http://.
  ecdhCurve:        C.TLS_GROUP_CURVE_STR,
  // TLS 1.3 minimum. Older endpoints fail at handshake — modernity
  // stance, no silent downgrade. Operators stuck on TLS 1.2 endpoints
  // can pass their own agent via opts.agent.
  minVersion:       "TLSv1.3",
};

// Default response-body caps. Control-plane (PUT/HEAD/DELETE/POST) replies
// are status confirmations or small XML/JSON; 16 MiB is generous. GET
// returns the actual stored object — bound at 1 GiB, operators with
// larger files use streaming mode.
var DEFAULT_CONTROL_PLANE_CAP = C.BYTES.mib(16);
var DEFAULT_GET_CAP           = C.BYTES.gib(1);
var DEFAULT_IDLE_TIMEOUT_MS   = C.TIME.seconds(30);

function _originKey(u) {
  return u.protocol + "//" + u.hostname + ":" +
    (u.port || (u.protocol === "https:" ? 443 : 80));
}

function _getTransport(u) {
  var key = _originKey(u);
  var cached = _transports.get(key);
  if (cached) return cached;
  var lib = u.protocol === "https:" ? https : http;
  var agent = new lib.Agent(DEFAULT_AGENT_OPTS);
  var transport = { kind: "h1", lib: lib, agent: agent };
  _transports.set(key, transport);
  return transport;
}

// Construct a framework error. Convention: errorClass constructor is
// (code, message, permanent[, statusCode]) — matches ObjectStoreError,
// LogStreamError, QueueError, ExternalDbError, ClusterError,
// StorageError. If errorClass is omitted, fall back to the bare
// FrameworkError(message, code) shape.
function _makeError(errorClass, code, message, permanent, statusCode) {
  if (!errorClass) return new FrameworkError(message, code);
  return new errorClass(code, message, permanent, statusCode);
}

function _isPermanentStatus(statusCode) {
  // 4xx is permanent EXCEPT the well-known transient ones.
  if (statusCode >= 400 && statusCode < 500) {
    return statusCode !== 408 && statusCode !== 425 && statusCode !== 429;
  }
  return false;
}

function request(opts) {
  return new Promise(function (resolve, reject) {
    if (!opts || !opts.url) {
      return reject(_makeError(opts && opts.errorClass, "BAD_ARG", "url is required", true));
    }
    var method = (opts.method || "GET").toUpperCase();
    var u = opts.url instanceof URL ? opts.url : new URL(opts.url);

    // Transport selection. Caller-supplied `agent` bypasses the cache
    // (test fixtures, operator-custom pools).
    var transport;
    if (opts.agent) {
      transport = {
        kind: "h1",
        lib:  u.protocol === "https:" ? https : http,
        agent: opts.agent,
      };
    } else {
      transport = _getTransport(u);
    }

    var headers = Object.assign({}, opts.headers || {});
    var responseMode = opts.responseMode || "buffer";
    var maxResponseBytes = opts.maxResponseBytes ||
      (method === "GET" ? DEFAULT_GET_CAP : DEFAULT_CONTROL_PLANE_CAP);
    var observer = typeof opts.observer === "function" ? opts.observer : null;
    var startedAt = Date.now();

    // Compose final AbortSignal: caller's signal + wall-clock timeout.
    var signal = opts.signal || null;
    if (typeof opts.timeoutMs === "number" && opts.timeoutMs > 0) {
      var timeoutSignal = AbortSignal.timeout(opts.timeoutMs);
      signal = signal ? AbortSignal.any([signal, timeoutSignal]) : timeoutSignal;
    }
    if (signal && signal.aborted) {
      var reason = signal.reason;
      var code = (reason && reason.name === "TimeoutError") ? "ETIMEDOUT" : "ABORT";
      return reject(_makeError(opts.errorClass, code,
        (reason && reason.message) || "request aborted before start", false));
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
      // Idle timeout — zero-progress detector. Distinct from the
      // wall-clock signal-based timeout. A slow-but-progressing
      // response will run to completion within the signal cap.
      timeout:  typeof opts.idleTimeoutMs === "number" ? opts.idleTimeoutMs : DEFAULT_IDLE_TIMEOUT_MS,
    };

    if (observer) observer("request:start", { method: method, url: String(opts.url) });

    var settled = false;
    function _resolve(value) { if (!settled) { settled = true; resolve(value); } }
    function _reject(err)    { if (!settled) { settled = true; reject(err); } }

    var req = transport.lib.request(reqOpts, function (res) {
      if (observer) observer("response:headers", { statusCode: res.statusCode, headers: res.headers });

      // Streaming response — return the IncomingMessage directly.
      if (responseMode === "stream") {
        if (res.statusCode >= 400) {
          // Drain the body to release the socket + reject with status.
          res.resume();
          return _reject(_makeError(opts.errorClass, "HTTP_ERROR",
            "HTTP " + res.statusCode + " " + (res.statusMessage || ""),
            _isPermanentStatus(res.statusCode), res.statusCode));
        }
        return _resolve({ statusCode: res.statusCode, headers: res.headers, body: res });
      }

      // Buffered response — collect with cap.
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
      // Idle timeout fired (zero progress for idleTimeoutMs).
      req.destroy();
      _reject(_makeError(opts.errorClass, "ETIMEDOUT",
        "request idle timeout (no data for " + reqOpts.timeout + "ms)", false));
    });

    req.on("error", function (e) {
      if (observer) observer("error", { phase: "request", message: e.message });
      _reject(_makeError(opts.errorClass, e.code || "REQ_ERROR", e.message, false));
    });

    // Wire AbortSignal — destroy req on abort. The signal can fire from
    // user cancellation OR the wall-clock timeout; reason distinguishes.
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

    // Body write — Buffer | string | Readable | undefined.
    if (opts.body && typeof opts.body.pipe === "function") {
      // Readable → pipe with stream-error wiring so an upstream error
      // propagates to Promise rejection rather than dangling.
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

// For test isolation — destroy cached transports and clear the pool.
// Tests that exercise different mock servers per case should call this
// in setup/teardown to avoid agent reuse across origins.
function _resetForTest() {
  _transports.forEach(function (t) {
    if (t.agent && typeof t.agent.destroy === "function") {
      try { t.agent.destroy(); } catch (_e) {}
    }
  });
  _transports.clear();
}

// Diagnostic — exposed for tests that verify pool reuse.
function _getCachedTransportCount() {
  return _transports.size;
}

module.exports = {
  request:                    request,
  DEFAULT_CONTROL_PLANE_CAP:  DEFAULT_CONTROL_PLANE_CAP,
  DEFAULT_GET_CAP:            DEFAULT_GET_CAP,
  _resetForTest:              _resetForTest,
  _getCachedTransportCount:   _getCachedTransportCount,
};
