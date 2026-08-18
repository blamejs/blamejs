// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Live WebSocket round-trip — pairs the framework's b.websocket
 * (server-side) with b.wsClient (outbound) over a real TCP socket.
 *
 * Exercises:
 *
 *   1. Plain ws:// handshake — Sec-WebSocket-Accept verification
 *      cross-checked end-to-end (client SHA-1(key+GUID) ↔ server
 *      computeAcceptKey).
 *   2. Subprotocol negotiation — client offers two, server selects
 *      one, both ends agree on the negotiated value.
 *   3. Text + binary message round-trip with the server's frame
 *      serializer / parser shared by b.websocket.
 *   4. Ping / pong heartbeat — client emits ping, server pongs back,
 *      pongDeadline advances.
 *   5. Close with 1000 / "bye" — code + reason flow both ways.
 *   6. permessage-deflate (RFC 7692) negotiation — when both sides
 *      offer it, the server compresses outbound text frames; the
 *      client inflates correctly.
 *
 * Lives under test/integration/ because the server boots a real
 * http.Server on an ephemeral port.
 */

var http = require("node:http");
var https = require("node:https");
var helpers = require("../helpers");
var check = helpers.check;

var b = require("../..");

function _buildServer(opts) {
  opts = opts || {};
  var server;
  if (opts.tls) {
    server = https.createServer({ key: opts.tls.key, cert: opts.tls.cert },
      function (req, res) { res.writeHead(404); res.end(); });
  } else {
    server = http.createServer(function (req, res) {
      res.writeHead(404);
      res.end();
    });
  }
  var ws = b.websocket;
  var negotiatedExt = null;
  if (opts.permessageDeflate) {
    negotiatedExt = "permessage-deflate";
  }
  server.on("upgrade", function (req, socket /*, head */) {
    var key = req.headers["sec-websocket-key"];
    if (!key) { socket.write("HTTP/1.1 400 Bad Request\r\n\r\n"); socket.destroy(); return; }
    var accept = ws.computeAcceptKey(key);
    var responseLines = [
      "HTTP/1.1 101 Switching Protocols",
      "Upgrade: websocket",
      "Connection: Upgrade",
      "Sec-WebSocket-Accept: " + accept,
    ];
    var clientSubprotocols = (req.headers["sec-websocket-protocol"] || "").split(",")
      .map(function (s) { return s.trim(); }).filter(Boolean);
    var negotiated = null;
    if (Array.isArray(opts.subprotocols) && opts.subprotocols.length > 0) {
      for (var i = 0; i < clientSubprotocols.length; i += 1) {
        if (opts.subprotocols.indexOf(clientSubprotocols[i]) !== -1) {
          negotiated = clientSubprotocols[i];
          break;
        }
      }
      if (negotiated) responseLines.push("Sec-WebSocket-Protocol: " + negotiated);
    }
    if (negotiatedExt) responseLines.push("Sec-WebSocket-Extensions: " + negotiatedExt);
    responseLines.push("");
    responseLines.push("");
    socket.write(responseLines.join("\r\n"));

    var fp = new ws.FrameParser({ maxFrameBytes: 1024 * 1024 });
    var deflate = !!opts.permessageDeflate;
    socket.on("data", function (chunk) {
      var frames = fp.push(chunk) || [];
      for (var fi = 0; fi < frames.length; fi += 1) {
        var frame = frames[fi];
        if (frame.opcode === 0x09) {                      // ping
          socket.write(ws.serializeFrame(0x0A, frame.payload, { fin: true }));
          continue;
        }
        if (frame.opcode === 0x08) {                      // close
          socket.write(ws.serializeFrame(0x08, frame.payload, { fin: true }));
          socket.end();
          continue;
        }
        if (frame.opcode === 0x01 || frame.opcode === 0x02) {
          var outPayload = frame.payload;
          var serializeOpts = { fin: true };
          if (deflate && frame.opcode === 0x01) {
            // Compress outbound text — strip the trailing 4 bytes per RFC 7692 §7.2.1
            try {
              var deflated = require("node:zlib").deflateRawSync(outPayload);
              if (deflated.length >= 4 &&
                  deflated[deflated.length - 4] === 0x00 &&
                  deflated[deflated.length - 3] === 0x00 &&
                  deflated[deflated.length - 2] === 0xff &&
                  deflated[deflated.length - 1] === 0xff) {
                outPayload = deflated.subarray(0, deflated.length - 4);
              } else {
                outPayload = deflated;
              }
              serializeOpts.rsv1 = true;
            } catch (_e) { /* drop-silent — fall through to uncompressed */ }
          }
          socket.write(ws.serializeFrame(frame.opcode, outPayload, serializeOpts));
        }
      }
    });
    socket.on("error", function () { /* drop-silent */ });
  });
  return new Promise(function (resolve) {
    server.listen(0, "127.0.0.1", function () { resolve(server); });
  });
}

async function run() {
  // --- (1) plain handshake + (3) text/binary echo + (5) close ----
  var server = await _buildServer({});
  var port = server.address().port;
  var client = b.wsClient.connect("ws://127.0.0.1:" + port + "/echo", {
    reconnect: false, audit: false, allowInternal: true,
  });
  var openSeen = false, msgSeen = null, closeSeen = null;
  client.on("open",    function () { openSeen = true; });
  client.on("message", function (data) { msgSeen = data; });
  client.on("close",   function (code, reason) { closeSeen = { code: code, reason: reason }; });

  await helpers.waitUntil(function () {
    return openSeen === true && client.readyState === "open";
  }, { label: "ws-roundtrip: handshake completed" });
  check("ws-roundtrip: handshake open",         openSeen === true);
  check("ws-roundtrip: readyState open",        client.readyState === "open");

  client.send("hello round trip");
  await helpers.waitUntil(function () {
    return msgSeen === "hello round trip";
  }, { label: "ws-roundtrip: text echo received" });
  check("ws-roundtrip: text echo",              msgSeen === "hello round trip");

  msgSeen = null;
  client.send(Buffer.from([0x01, 0x02, 0x03, 0x04]));                                     // allow:raw-byte-literal — test vector
  await helpers.waitUntil(function () {
    return Buffer.isBuffer(msgSeen) && msgSeen.length === 4;
  }, { label: "ws-roundtrip: binary echo received" });
  check("ws-roundtrip: binary echo",            Buffer.isBuffer(msgSeen) && msgSeen.length === 4);

  client.close(1000, "bye");
  await helpers.waitUntil(function () {
    return closeSeen && closeSeen.code === 1000 && client.readyState === "closed";
  }, { label: "ws-roundtrip: close round-trip completed" });
  check("ws-roundtrip: close round-trip",       closeSeen && closeSeen.code === 1000);
  check("ws-roundtrip: closed readyState",      client.readyState === "closed");
  server.close();

  // --- (2) subprotocol negotiation ----
  var server2 = await _buildServer({ subprotocols: ["proto-b", "proto-c"] });
  var port2 = server2.address().port;
  var client2 = b.wsClient.connect("ws://127.0.0.1:" + port2 + "/", {
    subprotocols: ["proto-a", "proto-b"],
    reconnect: false, audit: false, allowInternal: true,
  });
  await helpers.waitUntil(function () {
    return client2.subprotocol === "proto-b";
  }, { label: "ws-roundtrip: subprotocol intersection negotiated" });
  check("ws-roundtrip: subprotocol intersection chosen", client2.subprotocol === "proto-b");
  client2.close();
  await helpers.waitUntil(function () {
    return client2.readyState === "closed";
  }, { label: "ws-roundtrip: client2 closed before server2.close()" });
  server2.close();

  // --- (4) ping / pong ----
  var server3 = await _buildServer({});
  var port3 = server3.address().port;
  var client3 = b.wsClient.connect("ws://127.0.0.1:" + port3 + "/", {
    pingMs: 200,
    pongMs: 5000,
    reconnect: false, audit: false, allowInternal: true,
  });
  await helpers.waitUntil(function () {
    return client3.readyState === "open";
  }, { label: "ws-roundtrip: client3 open before ping" });
  client3.ping(Buffer.from("ping-data"));
  // Real-time passive observation: let the ping/pong machinery cycle
  // for ~800ms (pingMs=200 fires 4+ times) and verify no error fired.
  // Not a condition-wait — we want time to pass to confirm absence
  // of a pong-timeout event.
  var c3Err = null;
  client3.on("error", function (e) { c3Err = e; });
  await helpers.passiveObserve(800, "ws ping/pong: no pong-timeout fired across pingMs cycles");
  check("ws-roundtrip: ping/pong keeps connection alive", c3Err === null);
  client3.close();
  await helpers.waitUntil(function () {
    return client3.readyState === "closed";
  }, { label: "ws-roundtrip: client3 closed before server3.close()" });
  server3.close();

  // --- (6) permessage-deflate round-trip ----
  var server4 = await _buildServer({ permessageDeflate: true });
  var port4 = server4.address().port;
  var client4 = b.wsClient.connect("ws://127.0.0.1:" + port4 + "/", {
    permessageDeflate: true,
    reconnect: false, audit: false, allowInternal: true,
  });
  var msg4 = null;
  client4.on("message", function (data) { msg4 = data; });
  await helpers.waitUntil(function () {
    return client4.readyState === "open";
  }, { label: "ws-roundtrip: client4 open before deflate send" });
  // Send a highly-compressible payload so the round-trip exercises the
  // compress + inflate path, not the no-op fast-path.
  var bigText = "blamejs blamejs blamejs blamejs ".repeat(60);
  client4.send(bigText);
  await helpers.waitUntil(function () {
    return msg4 === bigText;
  }, { label: "ws-roundtrip: deflate round-trip echo received" });
  check("ws-roundtrip: deflate round-trip",     msg4 === bigText);
  client4.close();
  await helpers.waitUntil(function () {
    return client4.readyState === "closed";
  }, { label: "ws-roundtrip: client4 closed before server4.close()" });
  server4.close();

  // --- (7) wss:// over a real TLS handshake ------------------------------
  // The offline suite can only assert which options the dial builds. Only a
  // real handshake proves they reached the wire, and that is what was wrong:
  // the group preference was passed as `curves`, which node:tls accepts and
  // ignores, so every wss:// connection silently negotiated on Node's
  // defaults instead of the framework's. Read the negotiated group off the
  // socket and require a post-quantum hybrid.
  var pair = helpers.selfSignedPair();
  var server5 = await _buildServer({ tls: { key: pair.key, cert: pair.cert } });
  var port5 = server5.address().port;
  var client5 = b.wsClient.connect("wss://localhost:" + port5 + "/echo", {
    reconnect: false, audit: false, allowInternal: true,
    // Trust the fixture's certificate — verification stays on.
    tlsOpts: { ca: [pair.cert] },
  });
  var open5 = false, msg5 = null, err5 = null;
  client5.on("open",    function () { open5 = true; });
  client5.on("message", function (data) { msg5 = data; });
  client5.on("error",   function (e) { if (!err5) err5 = e; });
  await helpers.waitUntil(function () {
    return open5 === true || err5 !== null;
  }, { label: "ws-roundtrip: wss handshake completed" });
  check("ws-roundtrip: wss handshake open (no TLS error)", err5 === null && open5 === true);

  var tlsSock = client5._socket;
  var keyInfo = tlsSock && typeof tlsSock.getEphemeralKeyInfo === "function"
    ? (tlsSock.getEphemeralKeyInfo() || {})
    : {};
  check("ws-roundtrip: wss negotiated TLS 1.3",
        tlsSock && typeof tlsSock.getProtocol === "function" &&
        tlsSock.getProtocol() === "TLSv1.3");
  check("ws-roundtrip: wss negotiated a post-quantum hybrid group, so the " +
        "framework preference reached the handshake",
        typeof keyInfo.name === "string" && /MLKEM/i.test(keyInfo.name));

  // Node's own defaults already offer X25519MLKEM768, so the assertion above
  // holds whether or not the framework's preference was applied. Prove it IS
  // applied by narrowing the key shares to the classical group and requiring
  // the handshake to obey: an ignored preference falls back to Node's default
  // and negotiates the hybrid instead, which is exactly what the `curves`
  // spelling did.
  b.network.tls.pqc.setKeyShares(["X25519"]);
  try {
    var client6 = b.wsClient.connect("wss://localhost:" + port5 + "/echo", {
      reconnect: false, audit: false, allowInternal: true,
      tlsOpts: { ca: [pair.cert] },
    });
    var open6 = false, err6 = null;
    client6.on("open",  function () { open6 = true; });
    client6.on("error", function (e) { if (!err6) err6 = e; });
    await helpers.waitUntil(function () {
      return open6 === true || err6 !== null;
    }, { label: "ws-roundtrip: wss handshake with narrowed key shares" });
    check("ws-roundtrip: wss handshake opens with narrowed key shares", err6 === null);
    var narrowed = client6._socket && client6._socket.getEphemeralKeyInfo
      ? (client6._socket.getEphemeralKeyInfo() || {}) : {};
    check("ws-roundtrip: an operator-narrowed key-share list is honored on the wire",
          narrowed.name === "X25519");
    client6.close();
    await helpers.waitUntil(function () {
      return client6.readyState === "closed";
    }, { label: "ws-roundtrip: client6 closed" });
  } finally {
    b.network.tls.pqc.resetKeyShares();
  }

  client5.send("hello over tls");
  await helpers.waitUntil(function () {
    return msg5 === "hello over tls";
  }, { label: "ws-roundtrip: wss text echo received" });
  check("ws-roundtrip: wss text echo", msg5 === "hello over tls");
  client5.close();
  await helpers.waitUntil(function () {
    return client5.readyState === "closed";
  }, { label: "ws-roundtrip: client5 closed before server5.close()" });
  server5.close();

  console.log("OK — " + helpers.getChecks() + " checks passed");
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { process.exit(0); })
       .catch(function (err) { console.error(err); process.exit(1); });
}
