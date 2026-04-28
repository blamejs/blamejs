"use strict";
/**
 * websocket-channels — channel/room hub layered over `lib/websocket.js`.
 *
 * `lib/websocket.js` owns the wire protocol (RFC 6455 + 8441 frame
 * parsing, masking, control frames). This module owns the higher-level
 * pub/sub: connections subscribe to named channels, publish() fans out
 * a payload to every subscriber, and cluster mode coordinates fan-out
 * across nodes via a shared `_blamejs_ws_messages` table.
 *
 * Public API:
 *
 *   var hub = b.websocketChannels.create({
 *     backend:        'local' | 'cluster' | { publishRemote, start, stop },
 *     pollIntervalMs: C.TIME.ms? — cluster fan-out poll cadence (default 100ms)
 *     retentionMs:    C.TIME.ms? — fan-out row retention before prune (default 60s)
 *     audit:          true,      — emit system.ws.publish on each publish
 *   });
 *
 *   r.ws("/socket", function (conn) {
 *     hub.attach(conn);                       // tracks lifecycle, auto-detach on close
 *     hub.subscribe(conn, "chat:room-1");
 *     hub.subscribe(conn, "presence:user-42");
 *
 *     conn.on("message", function (msg) {
 *       // Operator-handled inbound; hub doesn't reflect inbound back.
 *     });
 *   });
 *
 *   await hub.publish("chat:room-1", { user: "alice", text: "hi" });
 *
 *   hub.localSubscribers("chat:room-1");      // → [conn, ...]
 *   hub.localSubscriberCount("chat:room-1");  // → number
 *   hub.channels();                           // → ["chat:room-1", ...]
 *   hub.connectionChannels(conn);             // → ["chat:room-1", ...]
 *
 * Cluster fan-out semantics:
 *   - Each publish() dispatches to local subscribers SYNCHRONOUSLY
 *     before returning. Local subscribers see the message with
 *     near-zero latency.
 *   - In cluster mode the publish ALSO writes a row to
 *     _blamejs_ws_messages. Other nodes poll the table on
 *     pollIntervalMs (default 100ms) and dispatch new rows past their
 *     last-seen id to their local subscribers.
 *   - The publishing node skips its own rows on poll (publishedBy =
 *     self) so each subscriber sees the message exactly once.
 *   - Latency-sensitive operators bring their own backend (Redis,
 *     NATS, MQTT) by passing { publishRemote, start, stop }.
 *
 * Single-node mode:
 *   - 'local' backend (default when opts.cluster is not wired). publish
 *     synchronously dispatches; no DB writes; no poll loop.
 *   - Operators on a single node pay zero coordination overhead.
 *
 * Channel naming is operator-defined — the hub treats names as opaque
 * strings. Common conventions: "chat:room-id", "presence:user-id",
 * "metrics:hostname". For pattern matching subscribe to multiple
 * specific channels rather than a wildcard — wildcards complicate
 * cross-node fan-out and are deferred.
 *
 * Error policy: a connection's send() that throws (closed socket, peer
 * gone) does NOT break dispatch to other subscribers. The throwing
 * subscriber is silently skipped; auto-detach on the connection's
 * 'close' event removes it from future fan-out.
 */

var lazyRequire = require("./lazy-require");
var clusterStorage = require("./cluster-storage");
var C = require("./constants");
var safeJson = require("./safe-json");
var { defineClass } = require("./framework-error");

var audit  = lazyRequire(function () { return require("./audit"); });
var logger = lazyRequire(function () { return require("./log").boot("websocket-channels"); });

var WebSocketChannelsError = defineClass("WebSocketChannelsError");

var DEFAULT_POLL_INTERVAL_MS = 100;
var DEFAULT_RETENTION_MS     = C.TIME.minutes(1);
var DEFAULT_PRUNE_EVERY_MS   = C.TIME.minutes(5);

function _err(code, message) {
  return new WebSocketChannelsError(code, message, true);
}

// ---- Backends ----

function _localBackend() {
  // Single-node: no remote fan-out. publish() goes only to local subs.
  return {
    name:           "local",
    publishRemote:  null,
    start:          null,
    stop:           null,
  };
}

function _clusterBackend(opts) {
  var clusterInstance = opts.cluster;
  var pollIntervalMs = opts.pollIntervalMs || DEFAULT_POLL_INTERVAL_MS;
  var retentionMs    = opts.retentionMs    || DEFAULT_RETENTION_MS;
  var pruneEveryMs   = opts.pruneEveryMs   || DEFAULT_PRUNE_EVERY_MS;
  var lastSeenId  = 0;
  var primed      = false;
  var lastPruneAt = 0;
  var pollTimer   = null;
  var stopped     = false;

  function _nodeId() {
    if (clusterInstance && typeof clusterInstance.currentNodeId === "function") {
      return clusterInstance.currentNodeId();
    }
    return "single-node-local";
  }

  async function publishRemote(channel, payload) {
    var serialized = JSON.stringify(payload);
    await clusterStorage.execute(
      "INSERT INTO _blamejs_ws_messages " +
      "(channel, payload, publishedAt, publishedBy) VALUES (?, ?, ?, ?)",
      [channel, serialized, Date.now(), _nodeId()]
    );
  }

  async function _poll(onRemoteMessage) {
    if (stopped) return;
    var nodeId = _nodeId();
    try {
      // First poll: prime lastSeenId to the current MAX so we don't
      // re-dispatch every historical row on startup. Tracked via the
      // `primed` flag separately from lastSeenId — when MAX(id) is 0
      // (empty table) the value-equality check would trip on every
      // poll without it.
      if (!primed) {
        var primer = await clusterStorage.execute(
          "SELECT COALESCE(MAX(id), 0) AS maxId FROM _blamejs_ws_messages",
          []
        );
        if (primer.rows && primer.rows[0]) {
          lastSeenId = Number(primer.rows[0].maxId) || 0;
        }
        primed = true;
        return;
      }
      var result = await clusterStorage.execute(
        "SELECT id, channel, payload FROM _blamejs_ws_messages " +
        "WHERE id > ? AND publishedBy <> ? ORDER BY id ASC",
        [lastSeenId, nodeId]
      );
      var rows = result.rows || [];
      for (var i = 0; i < rows.length; i++) {
        var row = rows[i];
        try {
          var payload = safeJson.parse(row.payload);
          onRemoteMessage(row.channel, payload);
        } catch (e) {
          try {
            logger().warn("malformed fan-out row id=" + row.id +
              ": " + ((e && e.message) || String(e)));
          } catch (_e) { /* logger best-effort */ }
        }
        if (Number(row.id) > lastSeenId) lastSeenId = Number(row.id);
      }

      // Rate-limited prune of expired rows.
      var now = Date.now();
      if (now - lastPruneAt >= pruneEveryMs) {
        lastPruneAt = now;
        await clusterStorage.execute(
          "DELETE FROM _blamejs_ws_messages WHERE publishedAt < ?",
          [now - retentionMs]
        );
      }
    } catch (e) {
      try {
        logger().warn("fan-out poll failed: " + ((e && e.message) || String(e)));
      } catch (_e) { /* logger best-effort */ }
    }
  }

  function start(onRemoteMessage) {
    if (pollTimer) return;
    stopped = false;
    var tick = function () {
      _poll(onRemoteMessage).then(function () {
        if (stopped) return;
        pollTimer = setTimeout(tick, pollIntervalMs);
        if (typeof pollTimer.unref === "function") pollTimer.unref();
      }, function () {
        if (stopped) return;
        pollTimer = setTimeout(tick, pollIntervalMs);
        if (typeof pollTimer.unref === "function") pollTimer.unref();
      });
    };
    // Prime lastSeenId immediately so the first publish on a brand-new
    // hub doesn't race the first poll-interval tick. Without this,
    // publishes that happen between create() and the first poll would
    // be missed by other nodes that haven't seeded their lastSeenId yet.
    pollTimer = setTimeout(tick, 0);
    if (typeof pollTimer.unref === "function") pollTimer.unref();
  }

  function stop() {
    stopped = true;
    if (pollTimer) { clearTimeout(pollTimer); pollTimer = null; }
  }

  return {
    name:           "cluster",
    publishRemote:  publishRemote,
    start:          start,
    stop:           stop,
  };
}

function _resolveBackend(opts) {
  var requested = opts.backend;
  if (requested && typeof requested === "object" &&
      typeof requested.publishRemote === "function") {
    return Object.assign({ name: "custom" }, requested);
  }
  if (requested === "cluster") return _clusterBackend(opts);
  if (!requested || requested === "local") return _localBackend();
  throw _err("UNKNOWN_BACKEND",
    "websocketChannels: unknown backend '" + requested +
    "' (must be 'local', 'cluster', or { publishRemote, start, stop })");
}

// ---- Hub ----

function create(opts) {
  opts = opts || {};
  var auditOn = !!opts.audit;
  var backend = _resolveBackend(opts);

  // channel -> Set<connection>
  var channelToConns = new Map();
  // connection -> Set<channel>  (WeakMap so dropped conns don't leak)
  var connToChannels = new WeakMap();
  // Tracked connection set for surface methods that need to enumerate
  // connections (e.g. close-all-on-shutdown). Connections leave this
  // set on detach. We hold strong refs intentionally — the hub is the
  // owner of this membership for as long as the operator hasn't said
  // detach.
  var attachedConns = new Set();

  function _localDispatch(channel, payload) {
    var subs = channelToConns.get(channel);
    if (!subs || subs.size === 0) return 0;
    var msg;
    try { msg = JSON.stringify({ channel: channel, payload: payload }); }
    catch (e) {
      throw _err("INVALID_PAYLOAD",
        "publish payload is not JSON-serializable: " + (e && e.message));
    }
    var sent = 0;
    for (var conn of subs) {
      try { conn.send(msg); sent++; }
      catch (_e) { /* dead connection — auto-detach handles cleanup */ }
    }
    return sent;
  }

  // Cluster backend invokes this when a remote node's row arrives.
  function _onRemoteMessage(channel, payload) {
    _localDispatch(channel, payload);
  }

  if (typeof backend.start === "function") backend.start(_onRemoteMessage);

  function attach(conn) {
    if (!conn || typeof conn.send !== "function") {
      throw _err("INVALID_CONN", "attach(conn) requires a connection with .send()");
    }
    if (connToChannels.has(conn)) return;  // idempotent
    connToChannels.set(conn, new Set());
    attachedConns.add(conn);
    if (typeof conn.on === "function") {
      conn.on("close", function () { detach(conn); });
    }
  }

  function detach(conn) {
    var chans = connToChannels.get(conn);
    if (!chans) return;
    for (var c of chans) {
      var subs = channelToConns.get(c);
      if (subs) {
        subs.delete(conn);
        if (subs.size === 0) channelToConns.delete(c);
      }
    }
    connToChannels.delete(conn);
    attachedConns.delete(conn);
  }

  function subscribe(conn, channel) {
    if (typeof channel !== "string" || channel.length === 0) {
      throw _err("INVALID_CHANNEL", "subscribe: channel must be a non-empty string");
    }
    if (!connToChannels.has(conn)) {
      throw _err("NOT_ATTACHED", "subscribe: connection must be attach()-ed first");
    }
    if (!channelToConns.has(channel)) channelToConns.set(channel, new Set());
    channelToConns.get(channel).add(conn);
    connToChannels.get(conn).add(channel);
  }

  function unsubscribe(conn, channel) {
    var subs = channelToConns.get(channel);
    if (subs) {
      subs.delete(conn);
      if (subs.size === 0) channelToConns.delete(channel);
    }
    var chans = connToChannels.get(conn);
    if (chans) chans.delete(channel);
  }

  async function publish(channel, payload) {
    if (typeof channel !== "string" || channel.length === 0) {
      throw _err("INVALID_CHANNEL", "publish: channel must be a non-empty string");
    }
    var localCount = _localDispatch(channel, payload);
    var remoteSent = false;
    if (typeof backend.publishRemote === "function") {
      try {
        await backend.publishRemote(channel, payload);
        remoteSent = true;
      } catch (e) {
        try {
          logger().error("publishRemote failed for channel '" + channel + "': " +
            ((e && e.message) || String(e)));
        } catch (_e) { /* logger best-effort */ }
      }
    }
    if (auditOn) {
      try {
        audit().emit({
          action:   "system.ws.publish",
          outcome:  "success",
          actor:    {},
          metadata: {
            channel:        channel,
            backend:        backend.name,
            localDelivered: localCount,
            remoteSent:     remoteSent,
          },
        });
      } catch (_e) { /* audit best-effort */ }
    }
    return { localDelivered: localCount, remoteSent: remoteSent };
  }

  function localSubscribers(channel) {
    var subs = channelToConns.get(channel);
    return subs ? Array.from(subs) : [];
  }

  function localSubscriberCount(channel) {
    var subs = channelToConns.get(channel);
    return subs ? subs.size : 0;
  }

  function channels() {
    return Array.from(channelToConns.keys());
  }

  function connectionChannels(conn) {
    var chans = connToChannels.get(conn);
    return chans ? Array.from(chans) : [];
  }

  function attachedCount() {
    return attachedConns.size;
  }

  function close() {
    if (typeof backend.stop === "function") backend.stop();
    // Drop all subscriptions. Connections are not closed — that's the
    // operator's call (`router.closeWebSockets()` is the framework's
    // hook for graceful shutdown).
    channelToConns.clear();
    for (var conn of attachedConns) connToChannels.delete(conn);
    attachedConns.clear();
  }

  return {
    backend:               backend.name,
    attach:                attach,
    detach:                detach,
    subscribe:             subscribe,
    unsubscribe:           unsubscribe,
    publish:               publish,
    localSubscribers:      localSubscribers,
    localSubscriberCount:  localSubscriberCount,
    channels:              channels,
    connectionChannels:    connectionChannels,
    attachedCount:         attachedCount,
    close:                 close,
    // Test hook — directly inject a remote message as if the cluster
    // backend's poll just received it.
    _injectRemoteMessage:  _onRemoteMessage,
  };
}

module.exports = {
  create:                  create,
  WebSocketChannelsError:  WebSocketChannelsError,
  // Backend factories exported for tests + advanced operator wiring.
  _localBackend:           _localBackend,
  _clusterBackend:         _clusterBackend,
};
