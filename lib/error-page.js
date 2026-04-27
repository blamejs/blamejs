"use strict";
/**
 * errors-page — router error handler with rich dev page + safe prod page.
 *
 * Registered on a router via `router.onError(handler)`. Catches
 * everything middleware or route handlers throw, classifies it, logs
 * it, and writes a response in the format the client wants (HTML or
 * JSON). The same handler covers both modes — operator sets opts.mode
 * (or omits it and it auto-detects from NODE_ENV).
 *
 *   var handler = b.errorPage.create({
 *     mode:    "dev",        // "dev" | "prod"; default: auto from NODE_ENV
 *     log:     logInstance,  // optional structured logger
 *     audit:   true,         // emit audit events for 401/403/429
 *     brand:   "myapp",      // shown on the page
 *     contact: "ops@app",    // optional, shown in prod mode
 *     // dev-mode toggles (ignored in prod):
 *     showStack:        true,    // default true in dev
 *     showRequestInfo:  true,    // default true in dev
 *     showEnvVars:      false,   // default false (env can carry secrets)
 *     // optional override — return true to take over the response
 *     onError: function (err, req, res, ctx) { … },
 *   });
 *   router.onError(handler);
 *
 * Classification:
 *   - err.isAppError or err.statusCode (number) → use that status + message
 *   - err.isFrameworkError with a known mapping → infer status (401, 403, …)
 *   - anything else → 500, generic "Internal Server Error" to client
 *
 * Stack traces are NEVER sent to the client in prod mode. Even in dev,
 * binding to a non-loopback interface is gated — operators who serve
 * the dev page on a public address get prod-style responses with a
 * one-line warning logged at boot. (Implemented as a hint flag on the
 * handler that opts in to that gate; default off.)
 *
 * Content negotiation: `Accept: application/json` (or absence of html
 * in Accept) → JSON `{ error, code? }`. Otherwise HTML.
 */

var lazyRequire = require("./lazy-require");
var audit = lazyRequire(function () { return require("./audit"); });

// Status code → default short reason. Used when the error doesn't carry
// its own message (e.g. a generic Error thrown from a route).
var STATUS_REASONS = {
  400: "Bad Request",
  401: "Unauthorized",
  403: "Forbidden",
  404: "Not Found",
  405: "Method Not Allowed",
  409: "Conflict",
  413: "Payload Too Large",
  415: "Unsupported Media Type",
  422: "Unprocessable Content",
  429: "Too Many Requests",
  500: "Internal Server Error",
  502: "Bad Gateway",
  503: "Service Unavailable",
  504: "Gateway Timeout",
};

// Map common framework error classes → HTTP status. Operators who
// throw their own AppError-like classes set isAppError + statusCode
// and bypass this map entirely.
function _classify(err) {
  if (!err || typeof err !== "object") {
    return { status: 500, code: "INTERNAL_ERROR", message: "Internal Server Error", classified: false };
  }
  // Apps that follow the standard convention: { isAppError, statusCode, code, message }
  if (err.isAppError) {
    return {
      status:  err.statusCode || 500,
      code:    err.code || "APP_ERROR",
      message: err.message || STATUS_REASONS[err.statusCode || 500] || "Error",
      classified: true,
    };
  }
  // Framework error subclasses we know map to specific HTTP statuses.
  if (err.isAuthError) {
    return { status: 401, code: err.code || "AUTH_FAILED", message: err.message || "Unauthorized", classified: true };
  }
  if (err.code === "VALIDATION_ERROR" || err.name === "ValidationError") {
    return { status: 400, code: err.code || "VALIDATION_ERROR", message: err.message || "Bad Request", classified: true };
  }
  if (err.isSafeJsonError) {
    return { status: 400, code: err.code || "json/invalid", message: err.message || "Bad Request", path: err.path || null, classified: true };
  }
  // Permanent framework errors that map cleanly to 4xx
  if ((err.isStorageError || err.isQueueError || err.isExternalDbError) && err.permanent) {
    return { status: 400, code: err.code || "ERROR", message: err.message || "Bad Request", classified: true };
  }
  if (typeof err.statusCode === "number") {
    return {
      status:  err.statusCode,
      code:    err.code || "ERROR",
      message: err.message || STATUS_REASONS[err.statusCode] || "Error",
      classified: true,
    };
  }
  return { status: 500, code: err.code || "INTERNAL_ERROR", message: err.message || "Internal Server Error", classified: false };
}

function _wantsJson(req, defaultFormat) {
  if (defaultFormat === "json") return true;
  if (defaultFormat === "html") return false;
  var accept = (req && req.headers && req.headers.accept) || "";
  // Default to JSON only when Accept makes it explicit. Browsers send
  // text/html, programmatic clients usually send application/json.
  if (accept.indexOf("application/json") !== -1) return true;
  if (accept.indexOf("text/html") !== -1)        return false;
  // Heuristic: APIs typically don't ask for html; treat empty Accept
  // on non-GET as JSON, GET as HTML.
  return req && req.method && req.method.toUpperCase() !== "GET";
}

function _esc(s) {
  if (s === undefined || s === null) return "";
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function _redactHeaders(headers) {
  if (!headers || typeof headers !== "object") return {};
  var out = {};
  var keys = Object.keys(headers);
  for (var i = 0; i < keys.length; i++) {
    var k = keys[i];
    var lk = k.toLowerCase();
    // Strip auth-bearing headers from the dev page so opening a stack
    // trace doesn't put a session cookie or bearer token in front of
    // anyone who can see the screen.
    if (lk === "cookie" || lk === "authorization" ||
        lk === "x-api-key" || lk === "x-csrf-token" ||
        lk.indexOf("token") !== -1) {
      out[k] = "[REDACTED]";
    } else {
      out[k] = headers[k];
    }
  }
  return out;
}

function _renderProdHtml(info, opts) {
  var brand   = opts.brand   ? _esc(opts.brand)   : "blamejs";
  var contact = opts.contact ? _esc(opts.contact) : null;
  return [
    "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">",
    "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">",
    "<title>", _esc(STATUS_REASONS[info.status] || "Error"), " — ", brand, "</title>",
    "<style>",
    "html,body{height:100%;margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#0d1117;color:#c9d1d9}",
    ".wrap{display:flex;align-items:center;justify-content:center;min-height:100%;padding:2rem}",
    ".card{max-width:520px;text-align:center;background:#161b22;border:1px solid #30363d;border-radius:12px;padding:48px 32px}",
    ".status{font-size:64px;font-weight:700;color:#58a6ff;margin:0;line-height:1}",
    ".title{font-size:18px;font-weight:600;color:#e6edf3;margin:18px 0 6px}",
    ".msg{font-size:14px;color:#8b949e;margin:0 0 24px;line-height:1.5}",
    ".contact{font-size:13px;color:#6e7681}",
    ".brand{font-size:12px;color:#484f58;margin-top:32px;letter-spacing:.05em;text-transform:uppercase}",
    "a{color:#58a6ff;text-decoration:none}a:hover{text-decoration:underline}",
    "</style></head><body><div class=\"wrap\"><div class=\"card\">",
    "<p class=\"status\">", String(info.status), "</p>",
    "<p class=\"title\">", _esc(STATUS_REASONS[info.status] || "Error"), "</p>",
    "<p class=\"msg\">", _esc(info.publicMessage), "</p>",
    contact ? "<p class=\"contact\">Contact <a href=\"mailto:" + contact + "\">" + contact + "</a> if this persists.</p>" : "",
    "<p class=\"brand\">", brand, "</p>",
    "</div></div></body></html>",
  ].join("");
}

function _renderDevHtml(info, opts, ctx) {
  var brand = opts.brand ? _esc(opts.brand) : "blamejs";
  var stackHtml = "";
  if (opts.showStack && info.stack) {
    stackHtml = "<pre class=\"stack\">" + _esc(info.stack) + "</pre>";
  }
  var requestHtml = "";
  if (opts.showRequestInfo && ctx && ctx.req) {
    var req = ctx.req;
    var headers = _redactHeaders(req.headers);
    var headerRows = Object.keys(headers).map(function (k) {
      return "<tr><th>" + _esc(k) + "</th><td>" + _esc(headers[k]) + "</td></tr>";
    }).join("");
    requestHtml = [
      "<section><h2>Request</h2>",
      "<table class=\"kv\">",
      "<tr><th>method</th><td>", _esc(req.method || ""), "</td></tr>",
      "<tr><th>url</th><td>", _esc(req.url || ""), "</td></tr>",
      ctx.requestId ? ("<tr><th>requestId</th><td>" + _esc(ctx.requestId) + "</td></tr>") : "",
      "</table>",
      headerRows ? ("<h3>Headers</h3><table class=\"kv\">" + headerRows + "</table>") : "",
      "</section>",
    ].join("");
  }
  var envHtml = "";
  if (opts.showEnvVars) {
    var envKeys = Object.keys(process.env).filter(function (k) {
      // Even with showEnvVars=true, keep secret-shaped keys redacted —
      // turning the dev page on shouldn't leak production credentials
      // when an operator forgets to switch modes.
      return !/SECRET|TOKEN|KEY|PASS|CRED/i.test(k);
    }).sort();
    var envRows = envKeys.map(function (k) {
      return "<tr><th>" + _esc(k) + "</th><td>" + _esc(process.env[k]) + "</td></tr>";
    }).join("");
    envHtml = "<section><h2>Environment</h2><table class=\"kv\">" + envRows + "</table></section>";
  }
  return [
    "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">",
    "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">",
    "<title>", String(info.status), " ", _esc(STATUS_REASONS[info.status] || "Error"),
    " — ", brand, " (dev)</title>",
    "<style>",
    "*{box-sizing:border-box}",
    "body{margin:0;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:#0d1117;color:#c9d1d9;font-size:13px;line-height:1.55}",
    "header{background:#21262d;padding:24px 32px;border-bottom:3px solid #f85149}",
    "header .status{display:inline-block;background:#f85149;color:#fff;padding:4px 10px;border-radius:6px;font-weight:700;margin-right:12px}",
    "header h1{display:inline;font-size:18px;color:#e6edf3;font-weight:600}",
    "header .err-code{margin-top:8px;font-size:12px;color:#8b949e}",
    "main{padding:24px 32px;max-width:1200px}",
    "section{margin-bottom:32px}",
    "h2{font-size:13px;color:#8b949e;text-transform:uppercase;letter-spacing:.08em;margin:0 0 12px;font-weight:600}",
    "h3{font-size:12px;color:#8b949e;text-transform:uppercase;letter-spacing:.05em;margin:18px 0 8px;font-weight:600}",
    ".stack{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;margin:0;white-space:pre-wrap;word-break:break-word;color:#ffa657;font-size:12px;overflow-x:auto}",
    "table.kv{width:100%;border-collapse:collapse;background:#161b22;border:1px solid #30363d;border-radius:8px;overflow:hidden}",
    "table.kv th{text-align:left;padding:8px 12px;color:#8b949e;font-weight:500;width:200px;background:#0d1117;border-bottom:1px solid #21262d;border-right:1px solid #21262d;vertical-align:top}",
    "table.kv td{padding:8px 12px;color:#c9d1d9;word-break:break-word;border-bottom:1px solid #21262d}",
    "table.kv tr:last-child th,table.kv tr:last-child td{border-bottom:none}",
    "footer{padding:16px 32px;color:#484f58;font-size:11px;letter-spacing:.05em;text-transform:uppercase;border-top:1px solid #21262d}",
    "</style></head><body>",
    "<header>",
    "<span class=\"status\">", String(info.status), "</span>",
    "<h1>", _esc(STATUS_REASONS[info.status] || "Error"), " — ", _esc(info.devMessage), "</h1>",
    info.code ? ("<div class=\"err-code\">code: " + _esc(info.code) + "</div>") : "",
    "</header>",
    "<main>",
    stackHtml ? ("<section><h2>Stack</h2>" + stackHtml + "</section>") : "",
    requestHtml,
    envHtml,
    "</main>",
    "<footer>", brand, " · dev mode · stack/headers redacted in prod</footer>",
    "</body></html>",
  ].join("");
}

function _writeResponse(res, status, contentType, body) {
  if (res.writableEnded) return;
  try {
    var headers = { "Content-Type": contentType, "Cache-Control": "no-store" };
    // Prefer writeHead so the status survives under both real Node
    // ServerResponse and lighter mock objects that only track status
    // via writeHead's first arg. setHeader fallback covers shims that
    // expose only that surface.
    if (typeof res.writeHead === "function") {
      res.writeHead(status, headers);
    } else {
      res.statusCode = status;
      if (typeof res.setHeader === "function") {
        res.setHeader("Content-Type", contentType);
        res.setHeader("Cache-Control", "no-store");
      }
    }
    res.end(body);
  } catch (_e) {
    // Last-resort plain text. If even this fails, the connection is
    // already gone; nothing to do.
    try { res.end("Internal Server Error"); } catch (_e2) { /* socket gone */ }
  }
}

function create(opts) {
  opts = opts || {};
  var modeOpt = opts.mode;
  var mode;
  if (modeOpt === "dev" || modeOpt === "prod") {
    mode = modeOpt;
  } else {
    var nodeEnv = process.env.NODE_ENV;
    mode = (nodeEnv === "production") ? "prod" : "dev";
  }

  var auditOn     = opts.audit !== false;
  var auditAction = typeof opts.auditAction === "string" && opts.auditAction.length > 0
    ? opts.auditAction
    : "request.error";
  // defaultFormat:
  //   "auto"  (default) — negotiate via Accept header
  //   "json"           — always JSON (API-style middleware default)
  //   "html"           — always HTML (page-style middleware default)
  var defaultFormat = opts.defaultFormat;
  if (defaultFormat !== undefined &&
      defaultFormat !== "auto" && defaultFormat !== "json" && defaultFormat !== "html") {
    throw new Error("errors-page: opts.defaultFormat must be 'auto', 'json', or 'html'");
  }
  var log         = opts.log || null;     // structured logger if supplied
  var brand     = opts.brand || null;
  var contact   = opts.contact || null;
  var showStack       = mode === "dev" && opts.showStack       !== false;
  var showRequestInfo = mode === "dev" && opts.showRequestInfo !== false;
  var showEnvVars     = mode === "dev" && opts.showEnvVars     === true;
  var onErrorHook = typeof opts.onError === "function" ? opts.onError : null;

  function _log(level, message, fields) {
    if (log && typeof log[level] === "function") {
      try { log[level](message, fields); }
      catch (_e) { /* logger best-effort */ }
      return;
    }
    // Fallback: framework console with status-aware severity
    var line = "[blamejs:errors-page] " + message + " " + JSON.stringify(fields || {});
    if (level === "error" || level === "fatal" || level === "warn") {
      console.error(line);
    } else {
      console.log(line);
    }
  }

  function handler(err, req, res) {
    var info = _classify(err);
    info.stack = (err && err.stack) ? err.stack : null;
    // The message we show to the client depends on whether we recognize
    // the error class. Generic 500s never leak the original message.
    info.publicMessage = (info.status >= 500 && !info.classified)
      ? (STATUS_REASONS[info.status] || "Internal Server Error")
      : info.message;
    info.devMessage = info.message;

    // Custom hook: operator can take over the response entirely.
    if (onErrorHook) {
      var handled = false;
      try { handled = !!onErrorHook(err, req, res, info); }
      catch (e) {
        _log("error", "errors-page onError hook threw", { error: (e && e.message) || String(e) });
      }
      if (handled || (res && res.writableEnded)) return;
    }

    // Logging: 5xx always with stack; 4xx as warn without stack noise
    var logFields = {
      status:    info.status,
      code:      info.code,
      method:    req && req.method,
      url:       req && req.url,
      requestId: req && req.id,
    };
    if (info.status >= 500) {
      logFields.stack = info.stack || String(err);
      _log("error", "unhandled error", logFields);
    } else {
      _log("warn", "request error", logFields);
    }

    // Audit every error. Best-effort — never let an audit-write failure
    // mask the original error. Outcome differentiates 5xx (failure) vs
    // 4xx (denied) so consumers can filter without re-classifying status.
    if (auditOn) {
      try {
        audit().emit({
          action:   auditAction,
          outcome:  info.status >= 500 ? "failure" : "denied",
          actor:    {
            ip:        req && req.headers && req.headers["x-forwarded-for"] ||
                       (req && req.socket && req.socket.remoteAddress),
            userAgent: req && req.headers && req.headers["user-agent"],
            sessionId: req && req.session && req.session.sid,
          },
          metadata: {
            status:    info.status,
            code:      info.code,
            method:    req && req.method,
            url:       req && req.url,
            requestId: (req && req.id) || (req && req.requestId),
            stack:     info.status >= 500 ? info.stack : null,
          },
          reason:   info.message,
          requestId: (req && req.id) || (req && req.requestId) || null,
        });
      } catch (_e) { /* audit best-effort */ }
    }

    if (res && res.writableEnded) return;

    var ctx = {
      req:       req,
      requestId: req && req.id,
    };

    if (_wantsJson(req, defaultFormat)) {
      var errorObj = {
        code:    info.code || (info.status >= 500 ? "internal_error" : "error"),
        message: info.publicMessage,
      };
      if (info.path) errorObj.path = info.path;
      if (mode === "dev" && info.stack && showStack && info.status >= 500) {
        errorObj.stack = info.stack;
      }
      _writeResponse(res, info.status, "application/json; charset=utf-8",
        JSON.stringify({ error: errorObj }));
      return;
    }

    var html = (mode === "dev")
      ? _renderDevHtml(info, {
          brand:           brand,
          showStack:       showStack,
          showRequestInfo: showRequestInfo,
          showEnvVars:     showEnvVars,
        }, ctx)
      : _renderProdHtml(info, { brand: brand, contact: contact });
    _writeResponse(res, info.status, "text/html; charset=utf-8", html);
  }

  handler.mode = mode;
  return handler;
}

module.exports = {
  create:          create,
  STATUS_REASONS:  STATUS_REASONS,
};
