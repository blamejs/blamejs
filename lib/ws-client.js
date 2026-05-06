"use strict";
/**
 * b.wsClient — outbound WebSocket client (RFC 6455).
 *
 * Companion to b.websocket (server-side). Operators dial out to peer
 * WebSocket endpoints from Node — webhooks, pubsub bridges, integration
 * with external realtime services — without reaching for `ws` from
 * npm.
 *
 *   var client = b.wsClient.connect("wss://stream.example.com/v1", {
 *     subprotocols: ["json-stream-v1"],
 *     headers:      { "Authorization": "Bearer " + token },
 *     reconnect:    { maxAttempts: 10, baseMs: 500, maxMs: 30000 },
 *     pingMs:       30000,
 *     pongMs:       60000,
 *     maxMessageBytes: b.constants.BYTES.mib(8),
 *   });
 *
 *   client.on("open",    function () { client.send({ subscribe: ["orders"] }); });
 *   client.on("message", function (data, isBinary) { ... });
 *   client.on("close",   function (code, reason) { ... });
 *   client.on("error",   function (err) { ... });
 *
 *   client.send("text frame");
 *   client.send(Buffer.from("binary frame"));
 *   client.close(1000, "bye");
 *
 * Frame layer is the same RFC 6455 implementation b.websocket already
 * ships — we reuse `FrameParser` and `serializeFrame` from
 * lib/websocket.js. The client adds:
 *
 *   - Outbound HTTP/1.1 Upgrade with Sec-WebSocket-Key generation.
 *   - Sec-WebSocket-Accept verification (rejects on hash mismatch).
 *   - Subprotocol + permessage-deflate negotiation.
 *   - Client-side frame masking (RFC 6455 §5.3 — required for outbound).
 *   - TLS via b.network.tls.pqc (X25519MLKEM768 hybrid handshake).
 *   - Heartbeat: ping every `pingMs`, drop the connection if pong not
 *     received within `pongMs`.
 *   - Auto-reconnect with exponential backoff + jitter.
 *
 * Per the validation-tier policy: connect() throws on bad opts at
 * config time; runtime errors flow through 'error' events.
 *
 * Per the security-defaults stance: TLS verification ON by default
 * (operator opts in to mTLS via tlsOpts). HSTS-style, no soft-fail.
 */

var net          = require("net");
var url          = require("url");
var nodeCrypto   = require("crypto");
var EventEmitter = require("events");

var lazyRequire    = require("./lazy-require");
var validateOpts   = require("./validate-opts");
var safeAsync      = require("./safe-async");
var safeBuffer     = require("./safe-buffer");
var fwCrypto       = lazyRequire(function () { return require("./crypto"); });
var websocket      = lazyRequire(function () { return require("./websocket"); });
var audit          = lazyRequire(function () { return require("./audit"); });
var networkTls     = lazyRequire(function () { return require("./network-tls"); });
var C              = require("./constants");
var { defineClass } = require("./framework-error");

var WsClientError = defineClass("WsClientError", { alwaysPermanent: true });

var WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";   // RFC 6455 §1.3

var DEFAULT_PING_MS    = C.TIME.seconds(30);
var DEFAULT_PONG_MS    = C.TIME.seconds(60);
var DEFAULT_MAX_BYTES  = C.BYTES.mib(8);
var DEFAULT_MAX_FRAME  = C.BYTES.mib(8);
var DEFAULT_HANDSHAKE_TIMEOUT_MS = C.TIME.seconds(15);
var DEFAULT_RECONNECT_BASE_MS    = C.TIME.seconds(1) / 2;
var DEFAULT_RECONNECT_MAX_MS     = C.TIME.seconds(30);
var DEFAULT_RECONNECT_MAX_ATTEMPTS = 10;

var OPCODE_CONT   = 0x00;                                // allow:raw-byte-literal — RFC 6455 opcode
var OPCODE_TEXT   = 0x01;                                // allow:raw-byte-literal — RFC 6455 opcode
var OPCODE_BINARY = 0x02;                                // allow:raw-byte-literal — RFC 6455 opcode
var OPCODE_CLOSE  = 0x08;                                // allow:raw-byte-literal — RFC 6455 opcode
var OPCODE_PING   = 0x09;                                // allow:raw-byte-literal — RFC 6455 opcode
var OPCODE_PONG   = 0x0A;                                // allow:raw-byte-literal — RFC 6455 opcode

var CLOSE_NORMAL          = 1000;                        // allow:raw-byte-literal — RFC 6455 close code
var CLOSE_GOING_AWAY      = 1001;                        // allow:raw-byte-literal — RFC 6455 close code
var CLOSE_ABNORMAL        = 1006;                        // allow:raw-byte-literal — RFC 6455 close code (synthetic — never on wire)

function _generateKey() {
  return fwCrypto().generateBytes(C.BYTES.bytes(16)).toString("base64");
}

function _expectedAccept(secKey) {
  return nodeCrypto.createHash("sha1").update(secKey + WS_GUID).digest("base64");
}

function _parseUrl(target) {
  var parsed;
  try { parsed = new url.URL(target); }
  catch (e) {
    throw new WsClientError("ws-client/bad-url",
      "wsClient.connect: url is malformed - " + e.message);
  }
  var proto = parsed.protocol;
  if (proto !== "ws:" && proto !== "wss:") {
    throw new WsClientError("ws-client/bad-url",
      "wsClient.connect: url must start with ws:// or wss:// - got " + JSON.stringify(proto));
  }
  return parsed;
}

function connect(target, opts) {
  opts = opts || {};
  validateOpts(opts, [
    "subprotocols", "headers", "tlsOpts", "pingMs", "pongMs",
    "maxMessageBytes", "maxFrameBytes",
    "handshakeTimeoutMs", "reconnect",
    "permessageDeflate", "audit", "origin",
  ], "wsClient.connect");

  var parsed = _parseUrl(target);

  var subprotocols = Array.isArray(opts.subprotocols) ? opts.subprotocols.slice() : [];
  for (var sp = 0; sp < subprotocols.length; sp += 1) {
    if (typeof subprotocols[sp] !== "string" || subprotocols[sp].length === 0) {
      throw new WsClientError("ws-client/bad-subprotocol",
        "wsClient.connect: subprotocols[" + sp + "] must be a non-empty string");
    }
  }
  var pingMs = (typeof opts.pingMs === "number" && opts.pingMs > 0)              // allow:numeric-opt-Infinity
    ? opts.pingMs : DEFAULT_PING_MS;
  var pongMs = (typeof opts.pongMs === "number" && opts.pongMs > 0)              // allow:numeric-opt-Infinity
    ? opts.pongMs : DEFAULT_PONG_MS;
  var maxMessageBytes = (typeof opts.maxMessageBytes === "number" && opts.maxMessageBytes > 0)   // allow:numeric-opt-Infinity
    ? opts.maxMessageBytes : DEFAULT_MAX_BYTES;
  var maxFrameBytes = (typeof opts.maxFrameBytes === "number" && opts.maxFrameBytes > 0)         // allow:numeric-opt-Infinity
    ? opts.maxFrameBytes : DEFAULT_MAX_FRAME;
  var handshakeTimeoutMs = (typeof opts.handshakeTimeoutMs === "number" && opts.handshakeTimeoutMs > 0)  // allow:numeric-opt-Infinity
    ? opts.handshakeTimeoutMs : DEFAULT_HANDSHAKE_TIMEOUT_MS;

  var reconnectOpts = _normaliseReconnect(opts.reconnect);
  var permessageDeflate = opts.permessageDeflate !== false;
  var auditOn = opts.audit !== false;

  var client = new WsClient({
    target:             target,
    parsedUrl:          parsed,
    subprotocols:       subprotocols,
    headers:            opts.headers || {},
    tlsOpts:            opts.tlsOpts || null,
    origin:             opts.origin || null,
    pingMs:             pingMs,
    pongMs:             pongMs,
    maxMessageBytes:    maxMessageBytes,
    maxFrameBytes:      maxFrameBytes,
    handshakeTimeoutMs: handshakeTimeoutMs,
    reconnectOpts:      reconnectOpts,
    permessageDeflate:  permessageDeflate,
    auditOn:            auditOn,
  });
  client._dial();
  return client;
}

function _normaliseReconnect(input) {
  if (input === false || input == null) {
    return { enabled: false, maxAttempts: 0,
             baseMs: DEFAULT_RECONNECT_BASE_MS,
             maxMs:  DEFAULT_RECONNECT_MAX_MS };
  }
  if (typeof input !== "object") {
    throw new WsClientError("ws-client/bad-reconnect",
      "wsClient.connect: reconnect must be false / null / object");
  }
  validateOpts(input, ["maxAttempts", "baseMs", "maxMs", "enabled"], "wsClient.connect.reconnect");
  return {
    enabled:     input.enabled !== false,
    maxAttempts: (typeof input.maxAttempts === "number" && input.maxAttempts >= 0)            // allow:numeric-opt-Infinity
      ? input.maxAttempts : DEFAULT_RECONNECT_MAX_ATTEMPTS,
    baseMs:      (typeof input.baseMs === "number" && input.baseMs > 0)                       // allow:numeric-opt-Infinity
      ? input.baseMs : DEFAULT_RECONNECT_BASE_MS,
    maxMs:       (typeof input.maxMs === "number" && input.maxMs > 0)                         // allow:numeric-opt-Infinity
      ? input.maxMs : DEFAULT_RECONNECT_MAX_MS,
  };
}

class WsClient extends EventEmitter {
  constructor(opts) {
    super();
    this._opts            = opts;
    this._socket          = null;
    this._parser          = null;
    this._readyState      = "connecting";
    this._reconnectAttempt = 0;
    this._reconnectTimer   = null;
    this._handshakeTimer   = null;
    this._pingTimer        = null;
    this._pongDeadline     = 0;
    this._fragmentChunks   = [];
    this._fragmentOpcode   = null;
    this._closed           = false;
    this._negotiatedSubprotocol = null;
    this._negotiatedDeflate = false;
  }

  get readyState()             { return this._readyState; }
  get subprotocol()            { return this._negotiatedSubprotocol; }
  get url()                    { return this._opts.target; }

  _dial() {
    var self = this;
    var opts = this._opts;
    this._readyState = "connecting";

    var parsed = opts.parsedUrl;
    var port = parsed.port ? parseInt(parsed.port, 10) :
               (parsed.protocol === "wss:" ? 443 : 80);                                  // allow:raw-byte-literal — TLS / HTTP default port
    var host = parsed.hostname;

    function _onError(err) { self._handleSocketError(err); }

    var socket;
    if (parsed.protocol === "wss:") {
      var tls = require("tls");                                                          // allow:inline-require — node:tls only on TLS path
      var tlsOpts = Object.assign({
        host:         host,
        port:         port,
        servername:   host,
        rejectUnauthorized: true,
      }, opts.tlsOpts || {});
      try {
        var pqcShares = networkTls().pqc.getKeyShares();
        if (Array.isArray(pqcShares) && pqcShares.length > 0 && !tlsOpts.curves) {
          tlsOpts.curves = pqcShares.join(":");
        }
      } catch (_e) { /* drop-silent — tls module pre-init or non-Node */ }
      socket = tls.connect(tlsOpts);
    } else {
      socket = net.connect({ host: host, port: port });
    }
    this._socket = socket;
    socket.on("error", _onError);

    var connectEvent = parsed.protocol === "wss:" ? "secureConnect" : "connect";
    socket.once(connectEvent, function () {
      try { self._sendHandshake(); }
      catch (e) { self._handleSocketError(e); }
    });

    this._handshakeTimer = setTimeout(function () {
      self._handleSocketError(new WsClientError("ws-client/handshake-timeout",
        "Handshake exceeded " + opts.handshakeTimeoutMs + "ms"));
    }, opts.handshakeTimeoutMs);
    if (typeof this._handshakeTimer.unref === "function") this._handshakeTimer.unref();
  }

  _sendHandshake() {
    var opts = this._opts;
    var self = this;
    var parsed = opts.parsedUrl;
    var key = _generateKey();
    this._secKey = key;

    var hostHeader = parsed.host;
    var pathStr = parsed.pathname + (parsed.search || "");
    if (!pathStr) pathStr = "/";

    var lines = [
      "GET " + pathStr + " HTTP/1.1",
      "Host: " + hostHeader,
      "Upgrade: websocket",
      "Connection: Upgrade",
      "Sec-WebSocket-Key: " + key,
      "Sec-WebSocket-Version: 13",                                                       // allow:raw-byte-literal — RFC 6455 §1.9
    ];
    if (opts.origin) lines.push("Origin: " + opts.origin);
    if (opts.subprotocols.length > 0) {
      lines.push("Sec-WebSocket-Protocol: " + opts.subprotocols.join(", "));
    }
    if (opts.permessageDeflate) {
      lines.push("Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits");
    }
    var customHeaders = opts.headers || {};
    var forbidden = ["host", "upgrade", "connection", "sec-websocket-key",
                     "sec-websocket-version", "sec-websocket-protocol",
                     "sec-websocket-extensions", "sec-websocket-accept"];
    for (var hkey in customHeaders) {
      if (!Object.prototype.hasOwnProperty.call(customHeaders, hkey)) continue;
      if (forbidden.indexOf(hkey.toLowerCase()) !== -1) continue;
      var v = customHeaders[hkey];
      if (typeof v !== "string") continue;
      if (safeBuffer.hasCrlf(v)) {
        throw new WsClientError("ws-client/bad-header",
          "header " + JSON.stringify(hkey) + ": value contains CR/LF (injection refused)");
      }
      lines.push(hkey + ": " + v);
    }
    lines.push("");
    lines.push("");
    var request = lines.join("\r\n");
    this._handshakeBuf = Buffer.alloc(0);
    this._socket.write(request);
    this._socket.on("data", function (chunk) {
      if (self._readyState === "connecting") {
        self._consumeHandshake(chunk);
      } else {
        self._consumeFrames(chunk);
      }
    });
  }

  _consumeHandshake(chunk) {
    // allow:handrolled-buffer-collect — handshake header capped at 64 KiB below; once handshake parses we switch to FrameParser
    this._handshakeBuf = Buffer.concat([this._handshakeBuf, chunk]);
    var headerEnd = this._handshakeBuf.indexOf("\r\n\r\n");
    if (headerEnd === -1) {
      if (this._handshakeBuf.length > C.BYTES.kib(64)) {
        this._handleSocketError(new WsClientError("ws-client/handshake-too-large",
          "handshake response exceeded 64 KiB before CRLFCRLF"));
      }
      return;
    }
    var headerSection = this._handshakeBuf.subarray(0, headerEnd).toString("utf8");
    var rest = this._handshakeBuf.subarray(headerEnd + 4);

    var lines = headerSection.split("\r\n");
    var statusLine = lines[0] || "";
    var match = statusLine.match(/^HTTP\/1\.\d (\d{3})/);
    if (!match) {
      this._handleSocketError(new WsClientError("ws-client/bad-status-line",
        "handshake response status line malformed: " + JSON.stringify(statusLine)));
      return;
    }
    var status = parseInt(match[1], 10);
    if (status !== 101) {                                                                 // allow:raw-byte-literal — HTTP 101
      this._handleSocketError(new WsClientError("ws-client/bad-status",
        "handshake response status was " + status + " (expected 101 Switching Protocols)"));
      return;
    }

    var headers = Object.create(null);
    for (var i = 1; i < lines.length; i += 1) {
      var idx = lines[i].indexOf(":");
      if (idx === -1) continue;
      var hkey = lines[i].slice(0, idx).trim().toLowerCase();
      var hval = lines[i].slice(idx + 1).trim();
      headers[hkey] = hval;
    }

    if ((headers["upgrade"] || "").toLowerCase() !== "websocket" ||
        (headers["connection"] || "").toLowerCase().indexOf("upgrade") === -1) {
      this._handleSocketError(new WsClientError("ws-client/bad-upgrade",
        "handshake response missing Upgrade: websocket / Connection: Upgrade"));
      return;
    }

    var accept = headers["sec-websocket-accept"] || "";
    var expected = _expectedAccept(this._secKey);
    if (accept !== expected) {
      this._handleSocketError(new WsClientError("ws-client/accept-mismatch",
        "handshake response Sec-WebSocket-Accept mismatch: peer responded with a key " +
        "that does not match the SHA-1(key+RFC-6455-GUID) hash"));
      return;
    }

    var negotiatedSubprotocol = headers["sec-websocket-protocol"] || null;
    if (negotiatedSubprotocol && this._opts.subprotocols.indexOf(negotiatedSubprotocol) === -1) {
      this._handleSocketError(new WsClientError("ws-client/bad-subprotocol",
        "server selected subprotocol " + JSON.stringify(negotiatedSubprotocol) +
        " not in client offer"));
      return;
    }
    this._negotiatedSubprotocol = negotiatedSubprotocol;

    this._negotiatedDeflate = false;
    if (this._opts.permessageDeflate &&
        (headers["sec-websocket-extensions"] || "").indexOf("permessage-deflate") !== -1) {
      this._negotiatedDeflate = true;
    }

    if (this._handshakeTimer) {
      clearTimeout(this._handshakeTimer);
      this._handshakeTimer = null;
    }

    var fp = websocket().FrameParser;
    this._parser = new fp({ maxFrameBytes: this._opts.maxFrameBytes });
    this._readyState = "open";
    this._reconnectAttempt = 0;
    this._fragmentChunks = [];
    this._fragmentOpcode = null;

    this._startHeartbeat();
    if (this._opts.auditOn) {
      try {
        audit().safeEmit({
          action:  "wsclient.connected",
          outcome: "success",
          actor:   null,
          metadata: {
            host:        this._opts.parsedUrl.host,
            subprotocol: negotiatedSubprotocol,
            deflate:     this._negotiatedDeflate,
          },
        });
      } catch (_e) { /* drop-silent */ }
    }
    this.emit("open");

    if (rest.length > 0) this._consumeFrames(rest);
  }

  _consumeFrames(chunk) {
    if (!this._parser) return;
    try {
      var frames = this._parser.push(chunk) || [];
      for (var fi = 0; fi < frames.length; fi += 1) {
        this._handleFrame(frames[fi]);
      }
    } catch (e) {
      this._handleSocketError(e);
    }
  }

  _handleFrame(frame) {
    if (frame.opcode === OPCODE_PING) {
      this._sendFrame(OPCODE_PONG, frame.payload, { fin: true });
      return;
    }
    if (frame.opcode === OPCODE_PONG) {
      this._pongDeadline = Date.now() + this._opts.pongMs;
      return;
    }
    if (frame.opcode === OPCODE_CLOSE) {
      var code = CLOSE_NORMAL, reason = "";
      if (frame.payload.length >= 2) {
        code = frame.payload.readUInt16BE(0);
        reason = frame.payload.subarray(2).toString("utf8");                              // allow:raw-byte-literal — RFC 6455 close-frame layout
      }
      this._readyState = "closing";
      this._sendFrame(OPCODE_CLOSE, frame.payload, { fin: true });
      this._teardown(code, reason, false);
      return;
    }
    if (frame.opcode === OPCODE_TEXT || frame.opcode === OPCODE_BINARY) {
      if (this._fragmentOpcode != null) {
        this._handleSocketError(new WsClientError("ws-client/protocol-error",
          "received non-continuation opcode mid-fragmented-message"));
        return;
      }
      this._fragmentOpcode = frame.opcode;
      this._fragmentChunks = [frame.payload];
    } else if (frame.opcode === OPCODE_CONT) {
      if (this._fragmentOpcode == null) {
        this._handleSocketError(new WsClientError("ws-client/protocol-error",
          "received continuation opcode with no prior text/binary frame"));
        return;
      }
      this._fragmentChunks.push(frame.payload);
    }
    if (frame.fin) {
      var fullPayload = Buffer.concat(this._fragmentChunks);                              // allow:handrolled-buffer-collect — bounded by maxMessageBytes below
      if (fullPayload.length > this._opts.maxMessageBytes) {
        this._handleSocketError(new WsClientError("ws-client/message-too-big",
          "incoming message exceeds maxMessageBytes (" + this._opts.maxMessageBytes + ")"));
        return;
      }
      var isBinary = this._fragmentOpcode === OPCODE_BINARY;
      this._fragmentChunks = [];
      this._fragmentOpcode = null;
      if (this._negotiatedDeflate && frame.rsv1) {
        try {
          fullPayload = require("zlib").inflateRawSync(                                   // allow:inline-require — zlib only on deflate-negotiated path
            Buffer.concat([fullPayload, Buffer.from([0x00, 0x00, 0xff, 0xff])]));         // allow:raw-byte-literal — RFC 7692 §7.2.2 deflate trailer
        } catch (e) {
          this._handleSocketError(new WsClientError("ws-client/deflate-error",
            "permessage-deflate inflate failed: " + e.message));
          return;
        }
      }
      var data = isBinary ? fullPayload : fullPayload.toString("utf8");
      this.emit("message", data, isBinary);
    }
  }

  _sendFrame(opcode, payload, opts) {
    if (!this._socket || this._socket.destroyed) return;
    var serialize = websocket().serializeFrame;
    var frame = serialize(opcode, payload, Object.assign({ mask: true }, opts || {}));
    this._socket.write(frame);
  }

  send(data, opts) {
    if (this._readyState !== "open") {
      throw new WsClientError("ws-client/not-open",
        "send: socket is not open (readyState=" + this._readyState + ")");
    }
    opts = opts || {};
    var isBinary = Buffer.isBuffer(data);
    var payload;
    if (isBinary) {
      payload = data;
    } else if (typeof data === "string") {
      payload = Buffer.from(data, "utf8");
    } else {
      payload = Buffer.from(JSON.stringify(data), "utf8");
    }
    if (payload.length > this._opts.maxMessageBytes) {
      throw new WsClientError("ws-client/payload-too-big",
        "send: payload exceeds maxMessageBytes (" + this._opts.maxMessageBytes + ")");
    }
    this._sendFrame(isBinary ? OPCODE_BINARY : OPCODE_TEXT, payload, { fin: true });
  }

  ping(payload) {
    if (this._readyState !== "open") return;
    this._sendFrame(OPCODE_PING, payload || Buffer.alloc(0), { fin: true });
  }

  close(code, reason) {
    if (this._readyState === "closed" || this._readyState === "closing") return;
    code = (typeof code === "number") ? code : CLOSE_NORMAL;
    reason = (typeof reason === "string") ? reason : "";
    var rb = Buffer.from(reason, "utf8");
    var payload = Buffer.alloc(2 + rb.length);                                            // allow:raw-byte-literal — RFC 6455 close-frame layout
    payload.writeUInt16BE(code, 0);
    rb.copy(payload, 2);                                                                  // allow:raw-byte-literal — RFC 6455 close-frame layout
    this._readyState = "closing";
    this._sendFrame(OPCODE_CLOSE, payload, { fin: true });
    var self = this;
    setTimeout(function () { self._teardown(code, reason, false); }, 1000).unref();       // allow:raw-byte-literal — graceful close grace window
  }

  _teardown(code, reason, willReconnect) {
    if (this._closed && !willReconnect) return;
    this._closed = !willReconnect;
    if (this._socket && !this._socket.destroyed) {
      try { this._socket.destroy(); } catch (_e) { /* drop-silent */ }
    }
    if (this._pingTimer)      { try { this._pingTimer.stop(); } catch (_e) { /* drop-silent */ } this._pingTimer = null; }
    if (this._handshakeTimer) { clearTimeout(this._handshakeTimer); this._handshakeTimer = null; }
    this._readyState = "closed";
    this._parser = null;
    this._fragmentChunks = [];
    this._fragmentOpcode = null;
    if (this._opts.auditOn) {
      try {
        audit().safeEmit({
          action:  "wsclient.closed",
          outcome: "success",
          actor:   null,
          metadata: { code: code, reason: reason, host: this._opts.parsedUrl.host },
        });
      } catch (_e) { /* drop-silent */ }
    }
    this.emit("close", code, reason);
    if (willReconnect) this._scheduleReconnect();
  }

  _handleSocketError(err) {
    if (this._opts.auditOn) {
      try {
        audit().safeEmit({
          action:  "wsclient.error",
          outcome: "fail",
          actor:   null,
          metadata: {
            host: this._opts.parsedUrl.host,
            code: err && err.code || "unknown",
            message: err && err.message || String(err),
          },
        });
      } catch (_e) { /* drop-silent */ }
    }
    this.emit("error", err);
    var rOpts = this._opts.reconnectOpts;
    var willReconnect = rOpts.enabled &&
                        this._reconnectAttempt < rOpts.maxAttempts &&
                        !this._closed;
    this._teardown(CLOSE_ABNORMAL, err.message || "error", willReconnect);
  }

  _scheduleReconnect() {
    var rOpts = this._opts.reconnectOpts;
    this._reconnectAttempt += 1;
    var attempt = Math.min(this._reconnectAttempt, 30);                                   // allow:raw-byte-literal — clamp 2^attempt overflow
    var ceiling = Math.min(rOpts.maxMs, rOpts.baseMs * Math.pow(2, attempt - 1));
    var delay   = Math.floor(Math.random() * ceiling);                                    // allow:math-random-noncrypto — backoff jitter, not security
    var self = this;
    this._reconnectTimer = setTimeout(function () { self._dial(); }, delay);
    if (typeof this._reconnectTimer.unref === "function") this._reconnectTimer.unref();
    this.emit("reconnecting", { attempt: this._reconnectAttempt, delayMs: delay });
  }

  _startHeartbeat() {
    var self = this;
    this._pongDeadline = Date.now() + this._opts.pongMs;
    this._pingTimer = safeAsync.repeating(function () { self._heartbeat(); }, this._opts.pingMs);
  }

  _heartbeat() {
    if (this._readyState !== "open") return;
    if (Date.now() > this._pongDeadline) {
      this._handleSocketError(new WsClientError("ws-client/pong-timeout",
        "no pong received within " + this._opts.pongMs + "ms"));
      return;
    }
    this._sendFrame(OPCODE_PING, Buffer.alloc(0), { fin: true });
  }
}

module.exports = {
  connect:       connect,
  WsClientError: WsClientError,
  OPCODE_TEXT:   OPCODE_TEXT,
  OPCODE_BINARY: OPCODE_BINARY,
  CLOSE_NORMAL:  CLOSE_NORMAL,
  CLOSE_GOING_AWAY: CLOSE_GOING_AWAY,
  WS_GUID:       WS_GUID,
};
