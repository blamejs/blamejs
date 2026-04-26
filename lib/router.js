"use strict";
/**
 * Custom HTTP router — zero-dependency replacement for express/koa/fastify.
 *
 * Why rolled-our-own: blamejs principle #1 forbids npm runtime dependencies.
 * This router covers what a route concretely requires (path params,
 * middleware chain, static file serving, MIME sniffing) and leaves no
 * attack surface we haven't read.
 *
 * Middleware / handler dispatch (see roadmap "Naming conventions" — verb
 * conventions section, "on/off/emit" vs explicit chain control):
 *   - handler.length >= 3 → treated as middleware. Chain stops unless the
 *     handler calls next(). Using 2-arg handlers as middleware is
 *     structurally fragile and will silently fall through.
 *   - handler.length <= 2 → terminal handler. Always falls through to the
 *     next entry in the chain if it doesn't end the response.
 *
 * Patterns are compiled ONCE at registration time (compilePattern) — no
 * regex construction on the hot path. Route table is scanned linearly;
 * ordering matters (first match wins).
 */
var http  = require("http");
var http2 = require("http2");
var fs = require("fs");
var path = require("path");
var { URL } = require("url");
var C = require("./constants");
var websocket = require("./websocket");
var { createLogger } = require("./logger");

var log = createLogger("router");

function compilePattern(pattern) {
  var keys = [];
  var regexStr = pattern
    .replace(/:([^/]+)/g, function (_, key) { keys.push(key); return "([^/]+)"; })
    .replace(/\//g, "\\/");
  return { pattern: pattern, regex: new RegExp("^" + regexStr + "$"), keys: keys };
}

var MIME_TYPES = {
  ".html":  "text/html",
  ".css":   "text/css",
  ".js":    "application/javascript",
  ".json":  "application/json",
  ".png":   "image/png",
  ".jpg":   "image/jpeg",
  ".jpeg":  "image/jpeg",
  ".gif":   "image/gif",
  ".svg":   "image/svg+xml",
  ".ico":   "image/x-icon",
  ".woff2": "font/woff2",
  ".woff":  "font/woff",
};

class Router {
  constructor() {
    this.routes = [];
    this.middleware = [];
    // WebSocket routes are kept separate from HTTP routes — they're
    // matched on the upgrade / Extended CONNECT path, not on a method
    // verb. Map<path, { handler, opts }>.
    this._wsRoutes = new Map();
  }

  use(fn) {
    this.middleware.push(fn);
  }

  get(pattern, ...handlers) {
    this.routes.push({ method: "GET", ...compilePattern(pattern), handlers });
  }

  post(pattern, ...handlers) {
    this.routes.push({ method: "POST", ...compilePattern(pattern), handlers });
  }

  put(pattern, ...handlers) {
    this.routes.push({ method: "PUT", ...compilePattern(pattern), handlers });
  }

  patch(pattern, ...handlers) {
    this.routes.push({ method: "PATCH", ...compilePattern(pattern), handlers });
  }

  delete(pattern, ...handlers) {
    this.routes.push({ method: "DELETE", ...compilePattern(pattern), handlers });
  }

  // ---- WebSocket route registration ----
  //
  // ws(path, handler, opts?)
  //   path     — exact match. Path-param patterns aren't supported on
  //              upgrade requests; operators that need dynamic paths
  //              register one ws route per stable shape.
  //   handler  — function(conn, req) — called with the WebSocketConnection
  //              and the original HTTP request (req for h1, request
  //              headers object for h2 Extended CONNECT). Operator owns
  //              the conn lifecycle from there.
  //   opts:
  //     transport: "auto" (default) | "h1-only" | "h2-only"
  //       auto      — accept both transports per ALPN negotiation
  //       h1-only   — refuse h2 Extended CONNECT with :status 405
  //       h2-only   — refuse h1 upgrade with 426 Upgrade Required +
  //                   `Upgrade: h2c` advisory header
  //     origins:    string[] | "*" | undefined — operator allowlist;
  //                 omitted = accept all (a startup warning fires when
  //                 the path is registered, since omitting origin
  //                 policy on a public-facing path is rarely intended)
  //     subprotocols: string[] — first match wins
  //     maxMessageBytes / pingIntervalMs / pongTimeoutMs — passed
  //       through to WebSocketConnection
  ws(pathStr, handler, opts) {
    if (typeof pathStr !== "string" || pathStr.length === 0) {
      throw new Error("router.ws: path must be a non-empty string");
    }
    if (typeof handler !== "function") {
      throw new Error("router.ws: handler must be a function");
    }
    opts = opts || {};
    var transport = opts.transport || "auto";
    if (transport !== "auto" && transport !== "h1-only" && transport !== "h2-only") {
      throw new Error("router.ws: transport must be 'auto' | 'h1-only' | 'h2-only'");
    }
    if (!opts.origins) {
      log.warn("WebSocket route '" + pathStr + "' registered without origins allowlist — accepting all origins. Pass { origins: [...] } or { origins: '*' } to silence.");
    }
    this._wsRoutes.set(pathStr, { handler: handler, opts: opts, transport: transport });
  }

  _match(route, pathname) {
    var match = pathname.match(route.regex);
    if (!match) return null;
    var params = {};
    route.keys.forEach((key, i) => (params[key] = match[i + 1]));
    return params;
  }

  async handle(req, res) {
    var parsed = new URL(req.url, "http://" + req.headers.host);
    req.pathname = parsed.pathname;
    req.query = Object.fromEntries(parsed.searchParams);

    // Run middleware
    for (var mw of this.middleware) {
      var next = false;
      try {
        await mw(req, res, () => (next = true));
      } catch (mwErr) {
        console.error("[middleware error]", mw.name || "anonymous", req.method, req.url, mwErr.message,
          mwErr.stack ? mwErr.stack.split("\n").slice(0, 3).join(" | ") : "");
        throw mwErr;
      }
      if (!next || res.writableEnded) return;
    }

    // Match route
    for (var route of this.routes) {
      if (route.method !== req.method) continue;
      var params = this._match(route, req.pathname);
      if (!params) continue;
      req.params = params;

      for (var handler of route.handlers) {
        if (res.writableEnded) return;
        if (handler.length >= 3) {
          var proceeded = false;
          await handler(req, res, () => (proceeded = true));
          if (!proceeded) return;
        } else {
          await handler(req, res);
        }
      }
      return;
    }

    // Not found
    if (this.notFoundHandler) {
      this.notFoundHandler(req, res);
    } else {
      res.writeHead(404, { "Content-Type": "text/html" });
      res.end("<h1>404 Not Found</h1>");
    }
  }

  getReservedSlugs() {
    var slugs = new Set();
    for (var i = 0; i < this.routes.length; i++) {
      var parts = this.routes[i].pattern.split("/").filter(Boolean);
      if (parts.length > 0 && !parts[0].startsWith(":")) {
        slugs.add(parts[0].toLowerCase());
      }
    }
    return slugs;
  }

  onNotFound(handler) {
    this.notFoundHandler = handler;
  }

  onError(handler) {
    this.errorHandler = handler;
  }

  listen(port, cb, tlsOptions, host) {
    var self = this;
    var requestHandler = (req, res) => {
      // Response helpers
      res.json = (data) => {
        res.writeHead(res.statusCode || 200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(data));
      };
      res.redirect = (url) => {
        // Same-origin redirects only by default. Apps that need cross-origin
        // redirects (OAuth, SSO) wrap res.redirect with their own allowlist.
        var safe = "/";
        if (typeof url === "string" && url.startsWith("/") && !url.startsWith("//")) {
          safe = url;
        }
        res.writeHead(302, { Location: safe });
        res.end();
      };
      res.status = (code) => {
        res.statusCode = code;
        return res;
      };

      self.handle(req, res).catch((err) => {
        console.error("[route error]", req.method, req.url, err.message,
          err.stack ? err.stack.split("\n").slice(0, 5).join(" | ") : "");
        if (self.errorHandler) {
          try { self.errorHandler(err, req, res); } catch (_) {
            if (!res.writableEnded) {
              res.writeHead(500, { "Content-Type": "text/plain" });
              res.end("Internal Server Error");
            }
          }
        } else if (!res.writableEnded) {
          res.writeHead(500, { "Content-Type": "text/plain" });
          res.end("Internal Server Error");
        }
      });
    };
    var server;
    if (tlsOptions) {
      // h2-capable server with h1 fallback via ALPN. ["h2", "http/1.1"]
      // means modern clients negotiate h2 (preferred); legacy clients
      // fall back to h1. allowHTTP1: true is what makes the same server
      // accept both. enableConnectProtocol: true is what enables h2
      // WebSocket (RFC 8441) — clients refuse to issue Extended CONNECT
      // until they see this in the server's SETTINGS frame.
      server = http2.createSecureServer(Object.assign({
        allowHTTP1:    true,
        ALPNProtocols: ["h2", "http/1.1"],
        settings:      { enableConnectProtocol: true },
      }, tlsOptions), requestHandler);
    } else {
      // Cleartext path is h1-only. Operators wanting h2c on cleartext
      // are typically running behind a TLS-terminating LB that does
      // h1↔h2 translation; the framework's TLS path covers that.
      server = http.createServer(requestHandler);
    }

    // ---- WebSocket wiring ----
    // Only registers handlers when there are ws routes — keeps the
    // server's emitter list clean for HTTP-only deployments.
    if (self._wsRoutes.size > 0) {
      // h1 upgrade event — fires for "Upgrade: websocket" from h1
      // clients. Routes by path; refuses with 426 in h2-only mode.
      server.on("upgrade", function (req, socket, head) {
        var pathname = String(req.url || "/").split("?")[0];
        var route = self._wsRoutes.get(pathname);
        if (!route) {
          socket.destroy();
          return;
        }
        if (route.transport === "h2-only") {
          // RFC-correct way to say "use h2": 426 Upgrade Required plus
          // an Upgrade advisory pointing to h2c.
          var body = "WebSocket on this path requires HTTP/2";
          var resp =
            "HTTP/1.1 426 Upgrade Required\r\n" +
            "Upgrade: h2c\r\n" +
            "Connection: close\r\n" +
            "Content-Type: text/plain; charset=utf-8\r\n" +
            "Content-Length: " + Buffer.byteLength(body, "utf8") + "\r\n" +
            "\r\n" +
            body;
          try { socket.write(resp); } catch (_e) {}
          try { socket.destroy(); } catch (_e) {}
          return;
        }
        var conn = websocket.handleUpgrade(req, socket, head, route.opts);
        if (conn) {
          try { route.handler(conn, req); }
          catch (err) { log.error("ws handler threw: " + err.message); conn._abort(websocket.CLOSE_INTERNAL_ERROR, "handler error"); }
        }
      });

      // h2 Extended CONNECT — only fires on h2-capable (TLS) server.
      // The 'stream' event filter checks for :method=CONNECT,
      // :protocol=websocket. Other CONNECT methods (e.g. tunnel) and
      // ordinary requests pass through.
      if (tlsOptions) {
        server.on("stream", function (stream, headers) {
          if (headers[":method"] !== "CONNECT") return;
          if (headers[":protocol"] !== "websocket") return;
          var pathname = String(headers[":path"] || "/").split("?")[0];
          var route = self._wsRoutes.get(pathname);
          if (!route) {
            try { stream.respond({ ":status": 404 }); stream.end(); } catch (_e) {}
            return;
          }
          if (route.transport === "h1-only") {
            try {
              stream.respond({ ":status": 405, "content-type": "text/plain; charset=utf-8" });
              stream.end("WebSocket on this path requires HTTP/1.1 Upgrade");
            } catch (_e) {}
            return;
          }
          var conn = websocket.handleExtendedConnect(stream, headers, route.opts);
          if (conn) {
            try { route.handler(conn, headers); }
            catch (err) { log.error("ws handler threw: " + err.message); conn._abort(websocket.CLOSE_INTERNAL_ERROR, "handler error"); }
          }
        });
      }
    }

    if (host) server.listen(port, host, cb);
    else server.listen(port, cb);
    server.timeout = C.TIME.minutes(5);
    return server;
  }
}

// Static file serving middleware
function serveStatic(dir) {
  var root = path.resolve(dir);
  return (req, res, next) => {
    if (req.method !== "GET") return next();
    var rel = req.pathname;
    if (rel.includes("\0")) return next();
    var filePath = path.resolve(path.join(root, rel));
    if (!filePath.startsWith(root)) return next();
    if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) return next();

    var ext = path.extname(filePath).toLowerCase();
    var mime = MIME_TYPES[ext] || "application/octet-stream";
    var stat = fs.statSync(filePath);
    var hasVersion = req.url && req.url.includes("?v=");
    var cacheControl = hasVersion
      ? "public, max-age=31536000, immutable"
      : "public, max-age=3600";
    res.writeHead(200, {
      "Content-Type":   mime,
      "Content-Length": stat.size,
      "Cache-Control":  cacheControl,
    });
    fs.createReadStream(filePath).pipe(res);
  };
}

module.exports = {
  Router:       Router,
  serveStatic:  serveStatic,
};
