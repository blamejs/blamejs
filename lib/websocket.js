"use strict";
/**
 * WebSocket server primitive — RFC 6455.
 *
 * Implements the server side of the WebSocket protocol on top of the
 * Node HTTP server's `'upgrade'` event. Built on node:net + node:crypto
 * with no npm runtime dep.
 *
 * Surface:
 *
 *   websocket.handleUpgrade(req, socket, head, opts)
 *     Wraps a TCP socket post-HTTP-upgrade. Validates the handshake,
 *     enforces origin policy, negotiates subprotocol, sends 101
 *     response, returns a WebSocketConnection. Throws / refuses on
 *     bad handshake.
 *
 *   new websocket.WebSocketConnection(socket, opts)
 *     EventEmitter wrapping a post-upgrade socket. State machine
 *     mirrors the browser WebSocket API:
 *       conn.readyState         'open' | 'closing' | 'closed'
 *       conn.lastError          last diagnosable error, if any
 *       conn.send(data)         — Buffer or string. Routes to binary
 *                                 or text frame. Throws if not OPEN.
 *       conn.ping(payload?)     — Send ping frame (no-op if not OPEN).
 *       conn.close(code?, reason?) — Send close frame, wait
 *                                 closeGraceMs for peer's echo, end
 *                                 socket.
 *     Events:
 *       'message' (data, isBinary)
 *       'ping'    (payload)
 *       'pong'    (payload)
 *       'close'   (code, reason, wasClean) — fires exactly once at
 *                                 lifecycle end. wasClean: true when
 *                                 the close handshake completed in
 *                                 both directions; false on socket
 *                                 errors / abnormal closure (code
 *                                 1006) / heartbeat timeout / etc.
 *                                 Operators usually only need this
 *                                 listener for full lifecycle tracking.
 *       'error'   (err)         — diagnosable issue. Always followed
 *                                 by 'close'. Optional listener;
 *                                 missing listener does NOT crash the
 *                                 process (gated by listenerCount).
 *
 *   websocket.serializeFrame(opcode, payload, opts), websocket.FrameParser
 *     Lower-level helpers exposed for tests + advanced callers.
 *
 * Spec compliance notes (the parts where naive impls get it wrong):
 *
 *   1. Mask handling (§5.3). All client→server frames MUST be masked.
 *      Unmasked client frames close the connection with code 1002.
 *      Server→client frames MUST NOT be masked. The serializer here
 *      defaults mask:false (server side); a `mask:true` opt exists
 *      for completeness / test fixtures only.
 *
 *   2. SHA-1 for Sec-WebSocket-Accept. RFC 6455 §1.3 mandates
 *      SHA-1(key + GUID). The framework uses SHA3-512 elsewhere; SHA-1
 *      here is NOT a security primitive — the GUID is publicly known
 *      and the hash is a protocol marker confirming both sides agree
 *      on the upgrade. Nothing about the WebSocket connection's
 *      security depends on SHA-1 collision resistance.
 *
 *   3. Close handshake reciprocity (§5.5.1). When the peer sends a
 *      close frame, we MUST echo a close frame back, then close the
 *      TCP socket. close() handles this; _handleClose echoes if we
 *      haven't already initiated.
 *
 *   4. Origin policy. Browser clients send `Origin: <scheme>://<host>`.
 *      The framework matches the CORS module's pattern: if the operator
 *      passes `origins: [...]`, enforce strictly. If `origins: "*"`,
 *      accept all (explicit operator opt-in to no checking). If
 *      `origins` is omitted, accept all but emit an audit warning at
 *      registration (the safety check) — see lib/router.js where the
 *      operator-facing API lives. Non-browser clients (Origin header
 *      absent) bypass origin checks since Origin is a browser-only
 *      enforcement signal.
 *
 *   5. Subprotocol negotiation. Server picks the FIRST entry from
 *      Sec-WebSocket-Protocol that's in the operator's `subprotocols`
 *      allowlist. If none match, the response omits the header (per
 *      §11.3.4) and the client decides whether to proceed.
 */

var nodeCrypto = require("crypto");
var { EventEmitter } = require("events");
var C = require("./constants");
var bufferSafe = require("./buffer-safe");
var { FrameworkError } = require("./framework-error");
var { createLogger } = require("./logger");

var log = createLogger("websocket");

// RFC 6455 §1.3
var GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

var OPCODE_CONTINUATION = 0x0;
var OPCODE_TEXT         = 0x1;
var OPCODE_BINARY       = 0x2;
var OPCODE_CLOSE        = 0x8;
var OPCODE_PING         = 0x9;
var OPCODE_PONG         = 0xA;

// Close codes (RFC 6455 §7.4.1)
var CLOSE_NORMAL              = 1000;
var CLOSE_GOING_AWAY          = 1001;
var CLOSE_PROTOCOL_ERROR      = 1002;
var CLOSE_UNSUPPORTED_DATA    = 1003;
// 1004 reserved
// 1005 no-status (must not be sent on the wire)
// 1006 abnormal-closure (must not be sent on the wire)
var CLOSE_INVALID_PAYLOAD     = 1007;
var CLOSE_POLICY_VIOLATION    = 1008;
var CLOSE_MESSAGE_TOO_BIG     = 1009;
var CLOSE_INTERNAL_ERROR      = 1011;

// Defaults — tuned for fast detection of dead/silent connections.
//
//   pingIntervalMs (30s): sends a ping every 30s. Aligned with most
//     load-balancer idle timeouts so the LB doesn't kill the
//     connection while we're still considering it healthy.
//
//   pongTimeoutMs (35s): if no pong arrives within 35s of the last
//     pong, abort with code 1011. Detection happens at ~35s — just
//     past one ping interval. Stays under AWS ALB's 60s default
//     idle so operators don't get LB-side disconnects fighting our
//     heartbeat. Tighter than the typical 60s default in other libs;
//     the cost of a false positive is a client reconnect, the cost
//     of a slow detection is wasted server resources for genuinely-
//     dead silent-failure connections.
//
//   closeGraceMs (2s): after we send a close frame, wait this long
//     for the peer's echo before forcibly ending the TCP socket.
//     A healthy peer echoes in <100ms; 2s is plenty. Operators on
//     slow networks override.
//
// All operator-overridable per connection via opts.{pingIntervalMs,
// pongTimeoutMs, closeGraceMs}.
var DEFAULT_MAX_MESSAGE_BYTES = C.BYTES.mib(1);
var DEFAULT_PING_INTERVAL_MS  = C.TIME.seconds(30);
var DEFAULT_PONG_TIMEOUT_MS   = C.TIME.seconds(35);
var CLOSE_GRACE_MS            = C.TIME.seconds(2);

// Connection lifecycle states — mirrors the browser WebSocket API +
// the npm `ws` library. Single-source-of-truth field; every state
// transition goes through _transitionToClosed (or set in the
// constructor for OPEN).
var STATE_OPEN    = "open";
var STATE_CLOSING = "closing";  // we sent a close frame, awaiting peer's echo
var STATE_CLOSED  = "closed";

class WebSocketError extends FrameworkError {
  constructor(code, message, closeCode) {
    super(message, code);
    this.name = "WebSocketError";
    this.closeCode = closeCode || CLOSE_PROTOCOL_ERROR;
    this.isWebSocketError = true;
  }
}

// ---- Handshake helpers ----

function computeAcceptKey(secWebSocketKey) {
  // SHA-1 required by RFC 6455 §1.3 — see file-level note 2 above.
  // This is a protocol marker, not a security primitive.
  var hash = nodeCrypto.createHash("sha1");
  hash.update(String(secWebSocketKey) + GUID);
  return hash.digest("base64");
}

function validateUpgradeRequest(req) {
  if (req.method !== "GET") {
    return { ok: false, status: 405, reason: "method must be GET" };
  }
  var h = req.headers || {};
  if ((h.upgrade || "").toLowerCase() !== "websocket") {
    return { ok: false, status: 400, reason: "missing Upgrade: websocket" };
  }
  // Connection header may carry multiple tokens (e.g. "keep-alive, Upgrade").
  // Match "upgrade" as a comma-separated token, case-insensitive.
  if (!/(^|,)\s*upgrade\s*(,|$)/i.test(h.connection || "")) {
    return { ok: false, status: 400, reason: "missing Connection: upgrade" };
  }
  if (!h["sec-websocket-key"]) {
    return { ok: false, status: 400, reason: "missing Sec-WebSocket-Key" };
  }
  if (h["sec-websocket-version"] !== "13") {
    return { ok: false, status: 400, reason: "Sec-WebSocket-Version must be 13" };
  }
  return { ok: true };
}

function negotiateSubprotocol(req, supported) {
  if (!supported || supported.length === 0) return null;
  var raw = (req.headers || {})["sec-websocket-protocol"] || "";
  var offered = raw.split(",").map(function (s) { return s.trim(); }).filter(Boolean);
  for (var i = 0; i < offered.length; i++) {
    if (supported.indexOf(offered[i]) !== -1) return offered[i];
  }
  return null;
}

// origins shapes:
//   array — strict allowlist, enforced
//   "*"   — explicit "accept all" (operator opt-in to no checking)
//   null/undefined — same as "*" but caller (router) is expected to
//                    have logged a startup warning. Origin policy is a
//                    framework-level decision; this primitive doesn't
//                    re-warn here.
function isOriginAllowed(req, origins) {
  if (!origins || origins === "*") return true;
  var origin = (req.headers || {}).origin;
  // Non-browser clients (curl, server-to-server, native apps) don't
  // send Origin. Origin enforcement only meaningfully applies to
  // browser-initiated upgrades — non-browser callers are gated by
  // the operator's network ACL / auth middleware, not Origin.
  if (!origin) return true;
  if (Array.isArray(origins)) return origins.indexOf(origin) !== -1;
  return false;
}

function buildUpgradeResponse(secWebSocketKey, subprotocol) {
  var lines = [
    "HTTP/1.1 101 Switching Protocols",
    "Upgrade: websocket",
    "Connection: Upgrade",
    "Sec-WebSocket-Accept: " + computeAcceptKey(secWebSocketKey),
  ];
  if (subprotocol) lines.push("Sec-WebSocket-Protocol: " + subprotocol);
  return lines.join("\r\n") + "\r\n\r\n";
}

// ---- Frame parser ----
//
// Incremental — push(chunk) accepts arbitrary buffer slices from the
// socket and emits zero-or-more complete frames as they arrive. Holds
// partial frame state across calls.

function FrameParser(opts) {
  opts = opts || {};
  this.maxFrameBytes = opts.maxFrameBytes || DEFAULT_MAX_MESSAGE_BYTES;
  this._buffer = Buffer.alloc(0);
}

FrameParser.prototype.push = function (chunk) {
  this._buffer = Buffer.concat([this._buffer, chunk]);
  var frames = [];
  while (true) {
    var frame = this._tryParseFrame();
    if (!frame) break;            // incomplete — wait for more bytes
    frames.push(frame);
  }
  return frames;
};

FrameParser.prototype._tryParseFrame = function () {
  if (this._buffer.length < 2) return null;
  var b0 = this._buffer[0];
  var b1 = this._buffer[1];
  var fin    = !!(b0 & 0x80);
  var rsv1   = !!(b0 & 0x40);
  var rsv2   = !!(b0 & 0x20);
  var rsv3   = !!(b0 & 0x10);
  var opcode = b0 & 0x0F;
  var masked = !!(b1 & 0x80);
  var lenInd = b1 & 0x7F;

  var headerLen = 2;
  if (lenInd === 126) headerLen += 2;
  else if (lenInd === 127) headerLen += 8;
  if (masked) headerLen += 4;
  if (this._buffer.length < headerLen) return null;

  var payloadLen;
  var off = 2;
  if (lenInd < 126) {
    payloadLen = lenInd;
  } else if (lenInd === 126) {
    payloadLen = this._buffer.readUInt16BE(off);
    off += 2;
  } else {
    // 64-bit. JS Number is 53-bit safe — reject lengths above
    // Number.MAX_SAFE_INTEGER explicitly rather than silently
    // truncating.
    var hi = this._buffer.readUInt32BE(off);
    var lo = this._buffer.readUInt32BE(off + 4);
    if (hi > 0x1FFFFF) {
      throw new WebSocketError("ws/frame-too-large",
        "frame length exceeds Number.MAX_SAFE_INTEGER", CLOSE_MESSAGE_TOO_BIG);
    }
    payloadLen = (hi * 0x100000000) + lo;
    off += 8;
  }

  if (payloadLen > this.maxFrameBytes) {
    throw new WebSocketError("ws/frame-too-large",
      "frame payload exceeds maxFrameBytes (" + this.maxFrameBytes + ")",
      CLOSE_MESSAGE_TOO_BIG);
  }

  var maskKey = null;
  if (masked) {
    maskKey = Buffer.from(this._buffer.subarray(off, off + 4));
    off += 4;
  }

  var totalLen = off + payloadLen;
  if (this._buffer.length < totalLen) return null;

  var payload = this._buffer.subarray(off, totalLen);
  if (masked) {
    var unmasked = Buffer.alloc(payloadLen);
    for (var i = 0; i < payloadLen; i++) {
      unmasked[i] = payload[i] ^ maskKey[i & 3];
    }
    payload = unmasked;
  } else {
    // Copy out — the underlying buffer is about to be sliced.
    payload = Buffer.from(payload);
  }

  this._buffer = this._buffer.subarray(totalLen);

  return {
    fin:    fin,
    rsv1:   rsv1,
    rsv2:   rsv2,
    rsv3:   rsv3,
    opcode: opcode,
    masked: masked,
    payload: payload,
  };
};

// ---- Frame serializer ----

function serializeFrame(opcode, payload, opts) {
  opts = opts || {};
  var fin  = opts.fin !== false;
  var mask = opts.mask === true;       // server-side defaults false
  payload = payload || Buffer.alloc(0);
  if (typeof payload === "string") payload = Buffer.from(payload, "utf8");
  if (!Buffer.isBuffer(payload)) {
    throw new WebSocketError("ws/invalid-payload",
      "frame payload must be Buffer or string");
  }
  var len = payload.length;

  var headerLen = 2;
  var lenByte;
  if (len < 126)             { lenByte = len; }
  else if (len < 65536)      { lenByte = 126; headerLen += 2; }
  else                       { lenByte = 127; headerLen += 8; }
  if (mask) headerLen += 4;

  var header = Buffer.alloc(headerLen);
  header[0] = (fin ? 0x80 : 0) | (opcode & 0x0F);
  header[1] = (mask ? 0x80 : 0) | lenByte;

  var off = 2;
  if (lenByte === 126) {
    header.writeUInt16BE(len, off);
    off += 2;
  } else if (lenByte === 127) {
    var hi = Math.floor(len / 0x100000000);
    var lo = len % 0x100000000;
    header.writeUInt32BE(hi, off);
    header.writeUInt32BE(lo, off + 4);
    off += 8;
  }

  if (mask) {
    var maskKey = nodeCrypto.randomBytes(4);
    maskKey.copy(header, off);
    var masked = Buffer.alloc(len);
    for (var i = 0; i < len; i++) masked[i] = payload[i] ^ maskKey[i & 3];
    return Buffer.concat([header, masked]);
  }
  return Buffer.concat([header, payload]);
}

// ---- Connection ----

class WebSocketConnection extends EventEmitter {
  constructor(socket, opts) {
    super();
    opts = opts || {};
    this.socket = socket;
    this.subprotocol = opts.subprotocol || null;
    this.maxMessageBytes = opts.maxMessageBytes || DEFAULT_MAX_MESSAGE_BYTES;
    // Transport selects mask-enforcement direction:
    //   h1 (RFC 6455): client→server frames MUST be masked. Default.
    //   h2 (RFC 8441): frames MUST NOT be masked — h2 already provides
    //                  the framing/security guarantees that masking
    //                  exists to protect against in h1 (proxy
    //                  cache-poisoning via raw text on the wire).
    this.transport = opts.transport === "h2" ? "h2" : "h1";
    var pingMs = opts.pingIntervalMs || DEFAULT_PING_INTERVAL_MS;
    var pongMs = opts.pongTimeoutMs  || DEFAULT_PONG_TIMEOUT_MS;
    // Grace period after we send a close frame before forcing the
    // socket end. Production default = 5s (give the peer time to ack).
    // Tests / latency-sensitive ops can pass a shorter value.
    this._closeGraceMs = opts.closeGraceMs != null ? opts.closeGraceMs : CLOSE_GRACE_MS;

    // Lifecycle state — single source of truth. Operators read
    // conn.readyState; internal code reads/writes this._state via
    // _transitionToClosed. All transitions emit 'close' exactly once.
    this._state      = STATE_OPEN;
    this._closeSent  = false;
    this._closeTimer = null;
    this.lastError   = null;        // last diagnosable error, if any
    // Fragmentation reassembly state.
    this._fragOpcode = null;
    this._fragChunks = null;
    this._fragLen    = 0;

    this._parser = new FrameParser({ maxFrameBytes: this.maxMessageBytes });
    this._lastPongAt = Date.now();

    var self = this;
    this._pingTimer = setInterval(function () { self._heartbeat(pongMs); }, pingMs);
    this._pingTimer.unref();

    socket.on("data",  function (chunk) { self._onData(chunk); });
    socket.on("error", function (err)   {
      // Network errors are LIFECYCLE events, not protocol errors —
      // route through _transitionToClosed with code 1006 (abnormal
      // closure). Mirrors the browser WebSocket API + ws npm
      // convention: operators listening on 'close' see the death;
      // 'error' is reserved for diagnosable protocol issues that
      // the operator may want to explicitly handle.
      self._transitionToClosed(1006, (err && err.message) || "socket error", false, err);
    });
    socket.on("close", function ()      {
      // Socket FIN/RST seen — if we haven't already transitioned via
      // a clean close-handshake, this is an abnormal closure.
      if (self._state !== STATE_CLOSED) {
        self._transitionToClosed(1006, "abnormal closure", false, null);
      }
    });
  }

  // Single state-transition method. Idempotent — repeat calls after
  // CLOSED are no-ops. Emits 'close' exactly once with (code, reason,
  // wasClean) signature matching the browser API.
  _transitionToClosed(code, reason, wasClean, error) {
    if (this._state === STATE_CLOSED) return;
    this._state = STATE_CLOSED;
    if (error) this.lastError = error;
    if (this._pingTimer)  { clearInterval(this._pingTimer);  this._pingTimer  = null; }
    if (this._closeTimer) { clearTimeout(this._closeTimer);  this._closeTimer = null; }
    // Surface diagnosable errors via 'error' first — but only if the
    // operator is listening AND this is a real diagnosable case.
    // EventEmitter throws "Unhandled 'error' event" on emit() with no
    // listener; gate the emit to avoid taking down the process.
    if (error && this.listenerCount("error") > 0) {
      try { this.emit("error", error); } catch (_e) { /* listener threw — ignore */ }
    }
    this.emit("close", code, reason, !!wasClean);
  }

  // Browser-style state field. 'open' | 'closing' | 'closed'.
  get readyState() { return this._state; }

  _onData(chunk) {
    var frames;
    try { frames = this._parser.push(chunk); }
    catch (err) {
      var code = err.closeCode || CLOSE_PROTOCOL_ERROR;
      return this._abort(code, err.message);
    }
    for (var i = 0; i < frames.length; i++) {
      this._handleFrame(frames[i]);
      if (this._state === STATE_CLOSED) return;
    }
  }

  _handleFrame(frame) {
    // Mask enforcement flips by transport (RFC 6455 §5.3 vs RFC 8441):
    //   h1: client→server frames MUST be masked
    //   h2: frames MUST NOT be masked (h2 transport provides the
    //       protections that masking exists for)
    if (this.transport === "h1" && !frame.masked) {
      return this._abort(CLOSE_PROTOCOL_ERROR, "client frame not masked (h1)");
    }
    if (this.transport === "h2" && frame.masked) {
      return this._abort(CLOSE_PROTOCOL_ERROR, "frame must not be masked (h2)");
    }
    // Reserved bits — must be zero unless a negotiated extension uses them.
    // We don't negotiate any extensions today (compression deferred), so
    // any RSV bit set is a protocol error.
    if (frame.rsv1 || frame.rsv2 || frame.rsv3) {
      return this._abort(CLOSE_PROTOCOL_ERROR, "reserved bits set without extension");
    }

    if (frame.opcode === OPCODE_CONTINUATION) {
      if (this._fragOpcode === null) {
        return this._abort(CLOSE_PROTOCOL_ERROR, "continuation without start");
      }
      this._appendFragment(frame);
    } else if (frame.opcode === OPCODE_TEXT || frame.opcode === OPCODE_BINARY) {
      if (this._fragOpcode !== null) {
        return this._abort(CLOSE_PROTOCOL_ERROR, "new message during fragmentation");
      }
      this._fragOpcode = frame.opcode;
      this._fragChunks = [frame.payload];
      this._fragLen    = frame.payload.length;
      if (frame.fin) this._emitMessage();
    } else if (frame.opcode === OPCODE_CLOSE) {
      this._handleClose(frame);
    } else if (frame.opcode === OPCODE_PING) {
      this.emit("ping", frame.payload);
      this._sendFrame(OPCODE_PONG, frame.payload);
    } else if (frame.opcode === OPCODE_PONG) {
      this._lastPongAt = Date.now();
      this.emit("pong", frame.payload);
    } else {
      this._abort(CLOSE_PROTOCOL_ERROR, "unknown opcode " + frame.opcode);
    }
  }

  _appendFragment(frame) {
    var newLen = this._fragLen + frame.payload.length;
    if (newLen > this.maxMessageBytes) {
      return this._abort(CLOSE_MESSAGE_TOO_BIG, "message exceeds maxMessageBytes");
    }
    this._fragChunks.push(frame.payload);
    this._fragLen = newLen;
    if (frame.fin) this._emitMessage();
  }

  _emitMessage() {
    var data = this._fragChunks.length === 1
      ? this._fragChunks[0]
      : Buffer.concat(this._fragChunks, this._fragLen);
    var opcode = this._fragOpcode;
    this._fragOpcode = null;
    this._fragChunks = null;
    this._fragLen    = 0;
    if (opcode === OPCODE_TEXT) {
      // §5.6: text frames MUST be valid UTF-8. Buffer.toString silently
      // replaces invalid sequences with U+FFFD; explicit validation
      // rejects malformed data per spec.
      var str;
      try { str = new TextDecoder("utf-8", { fatal: true }).decode(data); }
      catch (_e) { return this._abort(CLOSE_INVALID_PAYLOAD, "text frame is not valid UTF-8"); }
      this.emit("message", str, false);
    } else {
      this.emit("message", data, true);
    }
  }

  _handleClose(frame) {
    var code = CLOSE_NORMAL, reason = "";
    if (frame.payload.length >= 2) {
      code = frame.payload.readUInt16BE(0);
      if (frame.payload.length > 2) {
        try { reason = new TextDecoder("utf-8", { fatal: true }).decode(frame.payload.subarray(2)); }
        catch (_e) { return this._abort(CLOSE_INVALID_PAYLOAD, "close reason is not valid UTF-8"); }
      }
    }
    if (!this._closeSent) {
      // Echo close (§5.5.1) — peer initiated, we acknowledge.
      this._sendCloseFrame(code, reason);
      this._closeSent = true;
    }
    // Transition to CLOSED — clean handshake completed (wasClean=true).
    // The socket close will arrive shortly; _transitionToClosed is
    // idempotent so the socket-close handler running afterward is a
    // no-op.
    try { this.socket.end(); } catch (_e) {}
    this._transitionToClosed(code, reason, true, null);
  }

  _sendCloseFrame(code, reason) {
    var reasonBuf = reason ? Buffer.from(String(reason), "utf8") : Buffer.alloc(0);
    var payload = Buffer.alloc(2 + reasonBuf.length);
    payload.writeUInt16BE(code, 0);
    if (reasonBuf.length) reasonBuf.copy(payload, 2);
    this._sendFrame(OPCODE_CLOSE, payload);
  }

  _sendFrame(opcode, payload) {
    if (this._state === STATE_CLOSED) return;
    // Socket may have been destroyed by the peer between our last
    // 'close' event check and this write — Node's 'close' event is
    // async-after-destroy and there's a race window. Treat unwritable
    // socket as the abnormal-closure path so the operator's 'close'
    // handler fires consistently.
    if (this.socket.destroyed || this.socket.writable === false) {
      this._transitionToClosed(1006, "socket no longer writable", false, null);
      return;
    }
    try {
      this.socket.write(serializeFrame(opcode, payload));
    } catch (err) {
      this._transitionToClosed(1006, (err && err.message) || "write failed", false, err);
    }
  }

  send(data) {
    if (this._state !== STATE_OPEN) {
      throw new WebSocketError("ws/closed",
        "connection is " + this._state + ", cannot send");
    }
    if (typeof data === "string") {
      this._sendFrame(OPCODE_TEXT, Buffer.from(data, "utf8"));
    } else if (Buffer.isBuffer(data)) {
      this._sendFrame(OPCODE_BINARY, data);
    } else {
      data = bufferSafe.toBuffer(data, {
        errorClass: WebSocketError,
        typeCode:   "ws/invalid-payload",
        typeMessage: "send() requires Buffer, Uint8Array, or string",
      });
      this._sendFrame(OPCODE_BINARY, data);
    }
  }

  ping(payload) {
    if (this._state !== STATE_OPEN) return;
    this._sendFrame(OPCODE_PING, payload || Buffer.alloc(0));
  }

  close(code, reason) {
    if (this._state !== STATE_OPEN) return;
    code = code || CLOSE_NORMAL;
    this._sendCloseFrame(code, reason || "");
    this._closeSent = true;
    this._state = STATE_CLOSING;
    // Grace period — wait for peer's close echo before forcing socket end.
    var self = this;
    this._closeTimer = setTimeout(function () {
      try { self.socket.end(); } catch (_e) {}
      // If the peer never echoed, transition with the locally-sent code.
      // wasClean: false because the peer didn't acknowledge.
      self._transitionToClosed(code, reason || "", false, null);
    }, this._closeGraceMs);
    this._closeTimer.unref();
  }

  _abort(code, reason) {
    if (this._state === STATE_CLOSED) return;
    if (!this._closeSent) {
      try { this._sendCloseFrame(code, reason); this._closeSent = true; } catch (_e) {}
    }
    try { this.socket.destroy(); } catch (_e) {}
    // _abort is for protocol violations — wasClean: false.
    this._transitionToClosed(code, reason, false, null);
  }

  _heartbeat(pongTimeoutMs) {
    if (this._state !== STATE_OPEN) return;
    if (Date.now() - this._lastPongAt > pongTimeoutMs) {
      this._abort(CLOSE_INTERNAL_ERROR, "ping timeout — peer unresponsive");
      return;
    }
    this.ping();
  }
}

// ---- Server-side upgrade handler ----
//
// The framework's router wires the HTTP server's 'upgrade' event to
// this function. Operators usually don't call it directly; they pass
// a handler to router.ws(path, opts) (see lib/router.js, planned for
// v0.1.39).

function handleUpgrade(req, socket, head, opts) {
  opts = opts || {};

  // Validate handshake first — refusing here writes a plain HTTP/1.1
  // response and closes the socket, matching what the upgrade-event
  // consumer would expect for a malformed request.
  var v = validateUpgradeRequest(req);
  if (!v.ok) {
    _refuseUpgrade(socket, v.status || 400, v.reason);
    return null;
  }

  // Origin policy.
  if (!isOriginAllowed(req, opts.origins)) {
    _refuseUpgrade(socket, 403, "origin not allowed");
    return null;
  }

  // Subprotocol negotiation.
  var subprotocol = negotiateSubprotocol(req, opts.subprotocols);

  // Send 101.
  try {
    socket.write(buildUpgradeResponse(req.headers["sec-websocket-key"], subprotocol));
  } catch (err) {
    log.error("failed to write upgrade response: " + err.message);
    try { socket.destroy(); } catch (_e) {}
    return null;
  }

  // If the head buffer has any bytes (data that arrived between
  // headers and the upgrade handler), we pre-feed them into the
  // parser via a synthetic data event. Most clients don't send
  // anything before the 101 response, but the spec allows it.
  var conn = new WebSocketConnection(socket, {
    subprotocol:     subprotocol,
    maxMessageBytes: opts.maxMessageBytes,
    pingIntervalMs:  opts.pingIntervalMs,
    pongTimeoutMs:   opts.pongTimeoutMs,
  });
  if (head && head.length > 0) {
    // Manually invoke the data path with the pre-read bytes.
    conn._onData(head);
  }
  return conn;
}

// ---- h2 Extended CONNECT (RFC 8441) entry point ----
//
// Called by the router from an http2.Server's 'stream' event when the
// :method header is "CONNECT" and :protocol is "websocket". Validates
// origin + subprotocols (same policy as h1), responds with :status 200
// (NOT 101 — Extended CONNECT is a CONNECT, not an Upgrade), and
// returns a WebSocketConnection wrapping the h2 stream.
//
// The server side must advertise SETTINGS_ENABLE_CONNECT_PROTOCOL = 1
// in its h2 settings frame BEFORE clients can use Extended CONNECT.
// That's the operator's responsibility when constructing the h2 server
// — pass `settings: { enableConnectProtocol: true }` to
// http2.createServer / createSecureServer. The router will set this
// when v0.1.40 lands.

function handleExtendedConnect(stream, requestHeaders, opts) {
  opts = opts || {};

  // Verify it's actually a WebSocket Extended CONNECT (RFC 8441 §4).
  if (requestHeaders[":method"] !== "CONNECT") {
    _refuseH2Connect(stream, 400, "method must be CONNECT");
    return null;
  }
  if (requestHeaders[":protocol"] !== "websocket") {
    _refuseH2Connect(stream, 400, ":protocol must be websocket");
    return null;
  }

  // Origin + subprotocol policy — same as h1. Build a fake req object
  // so the helpers (which expect a Node http req shape) work uniformly.
  var fakeReq = { headers: requestHeaders, method: "CONNECT" };
  if (!isOriginAllowed(fakeReq, opts.origins)) {
    _refuseH2Connect(stream, 403, "origin not allowed");
    return null;
  }

  var subprotocol = negotiateSubprotocol(fakeReq, opts.subprotocols);

  // 200 response — Extended CONNECT does NOT use 101. Sec-WebSocket-Key
  // / Sec-WebSocket-Accept are NOT used (h2 stream identity replaces
  // the handshake nonce dance from h1).
  var responseHeaders = { ":status": 200 };
  if (subprotocol) responseHeaders["sec-websocket-protocol"] = subprotocol;
  try {
    stream.respond(responseHeaders);
  } catch (err) {
    log.error("failed to write h2 Extended CONNECT response: " + err.message);
    try { stream.close(); } catch (_e) {}
    return null;
  }

  return new WebSocketConnection(stream, {
    transport:       "h2",
    subprotocol:     subprotocol,
    maxMessageBytes: opts.maxMessageBytes,
    pingIntervalMs:  opts.pingIntervalMs,
    pongTimeoutMs:   opts.pongTimeoutMs,
  });
}

function _refuseH2Connect(stream, status, reason) {
  try {
    stream.respond({ ":status": status, "content-type": "text/plain; charset=utf-8" });
    stream.end(reason || ("HTTP " + status));
  } catch (_e) {
    try { stream.close(); } catch (_e2) {}
  }
}

function _refuseUpgrade(socket, status, reason) {
  var statusText = {
    400: "Bad Request",
    403: "Forbidden",
    405: "Method Not Allowed",
    426: "Upgrade Required",
  }[status] || "Bad Request";
  var body = reason || statusText;
  var resp =
    "HTTP/1.1 " + status + " " + statusText + "\r\n" +
    "Connection: close\r\n" +
    "Content-Type: text/plain; charset=utf-8\r\n" +
    "Content-Length: " + Buffer.byteLength(body, "utf8") + "\r\n" +
    "\r\n" +
    body;
  try { socket.write(resp); } catch (_e) {}
  try { socket.destroy(); } catch (_e) {}
}

module.exports = {
  // Handshake helpers
  computeAcceptKey:        computeAcceptKey,
  validateUpgradeRequest:  validateUpgradeRequest,
  negotiateSubprotocol:    negotiateSubprotocol,
  isOriginAllowed:         isOriginAllowed,
  buildUpgradeResponse:    buildUpgradeResponse,
  // Frame layer
  FrameParser:             FrameParser,
  serializeFrame:          serializeFrame,
  // Connection
  WebSocketConnection:     WebSocketConnection,
  WebSocketError:          WebSocketError,
  // Server-side entrypoints
  handleUpgrade:           handleUpgrade,           // h1 — RFC 6455 HTTP upgrade
  handleExtendedConnect:   handleExtendedConnect,   // h2 — RFC 8441 Extended CONNECT
  // Constants
  GUID:                    GUID,
  OPCODE_CONTINUATION:     OPCODE_CONTINUATION,
  OPCODE_TEXT:             OPCODE_TEXT,
  OPCODE_BINARY:           OPCODE_BINARY,
  OPCODE_CLOSE:            OPCODE_CLOSE,
  OPCODE_PING:             OPCODE_PING,
  OPCODE_PONG:             OPCODE_PONG,
  CLOSE_NORMAL:            CLOSE_NORMAL,
  CLOSE_GOING_AWAY:        CLOSE_GOING_AWAY,
  CLOSE_PROTOCOL_ERROR:    CLOSE_PROTOCOL_ERROR,
  CLOSE_UNSUPPORTED_DATA:  CLOSE_UNSUPPORTED_DATA,
  CLOSE_INVALID_PAYLOAD:   CLOSE_INVALID_PAYLOAD,
  CLOSE_POLICY_VIOLATION:  CLOSE_POLICY_VIOLATION,
  CLOSE_MESSAGE_TOO_BIG:   CLOSE_MESSAGE_TOO_BIG,
  CLOSE_INTERNAL_ERROR:    CLOSE_INTERNAL_ERROR,
};
