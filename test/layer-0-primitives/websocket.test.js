// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * websocket handshake helpers.
 *
 * b.websocket.WebSocketError — the protocol-violation error subclass with
 * an RFC 6455 §7.4.1 closeCode. b.websocket.buildUpgradeResponse — the
 * 101 Switching Protocols response builder, checked against the RFC 6455
 * §1.3 known-answer Sec-WebSocket-Accept vector.
 *
 * Run standalone: `node test/layer-0-primitives/websocket.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

// RFC 6455 §1.3 canonical example.
var RFC_KEY    = "dGhlIHNhbXBsZSBub25jZQ==";
var RFC_ACCEPT = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

function testWebSocketError() {
  var err = new b.websocket.WebSocketError("ws/closed", "send() on a closed connection", 1002);
  check("WebSocketError is an Error subclass",         err instanceof Error);
  check("WebSocketError carries the framework code",   err.code === "ws/closed");
  check("WebSocketError carries the message",          err.message === "send() on a closed connection");
  check("WebSocketError carries the RFC closeCode",    err.closeCode === 1002);
  check("WebSocketError flags isWebSocketError",       err.isWebSocketError === true);
  check("WebSocketError name is WebSocketError",       err.name === "WebSocketError");

  // Omitted closeCode defaults to 1002 (protocol error).
  var dflt = new b.websocket.WebSocketError("ws/proto", "bad frame");
  check("WebSocketError defaults closeCode to CLOSE_PROTOCOL_ERROR (1002)",
        dflt.closeCode === b.websocket.CLOSE_PROTOCOL_ERROR && dflt.closeCode === 1002);
}

function testBuildUpgradeResponse() {
  // Bare handshake (no subprotocol / no extension).
  var resp = b.websocket.buildUpgradeResponse(RFC_KEY, null, null);
  check("buildUpgradeResponse starts with 101 Switching Protocols",
        resp.indexOf("HTTP/1.1 101 Switching Protocols\r\n") === 0);
  check("buildUpgradeResponse emits Upgrade: websocket",
        /\r\nUpgrade: websocket\r\n/.test(resp));
  check("buildUpgradeResponse emits Connection: Upgrade",
        /\r\nConnection: Upgrade\r\n/.test(resp));
  check("buildUpgradeResponse computes the RFC 6455 Sec-WebSocket-Accept",
        resp.indexOf("Sec-WebSocket-Accept: " + RFC_ACCEPT + "\r\n") !== -1);
  check("buildUpgradeResponse terminates with a blank line",
        resp.slice(-4) === "\r\n\r\n");
  check("buildUpgradeResponse omits Sec-WebSocket-Protocol when subprotocol is null",
        resp.indexOf("Sec-WebSocket-Protocol") === -1);
  check("buildUpgradeResponse omits Sec-WebSocket-Extensions when null",
        resp.indexOf("Sec-WebSocket-Extensions") === -1);

  // Accept value agrees with the standalone computeAcceptKey primitive.
  check("buildUpgradeResponse Accept agrees with computeAcceptKey",
        resp.indexOf("Sec-WebSocket-Accept: " + b.websocket.computeAcceptKey(RFC_KEY) + "\r\n") !== -1);

  // With a negotiated subprotocol + extension echo.
  var resp2 = b.websocket.buildUpgradeResponse(RFC_KEY, "chat.v1", "permessage-deflate; server_no_context_takeover");
  check("buildUpgradeResponse includes Sec-WebSocket-Protocol when subprotocol given",
        /\r\nSec-WebSocket-Protocol: chat\.v1\r\n/.test(resp2));
  check("buildUpgradeResponse includes Sec-WebSocket-Extensions when given",
        resp2.indexOf("Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover\r\n") !== -1);
  check("buildUpgradeResponse with options still terminates with a blank line",
        resp2.slice(-4) === "\r\n\r\n");
}

async function run() {
  testWebSocketError();
  testBuildUpgradeResponse();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[websocket] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e); process.exit(1); }
  );
}
