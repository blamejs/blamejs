"use strict";
/**
 * Minimal SNTP client for boot-time clock-drift verification.
 *
 * Why: the audit chain's monotonicCounter orders events deterministically
 * even if the wall clock jumps, but recordedAt is the human-readable
 * timestamp auditors will rely on. A clock that's silently off by hours
 * (container with no RTC sync, NTP daemon stopped) makes the audit trail
 * misleading.
 *
 * What this does:
 *   - Sends a single SNTPv4 query to a configured server (default
 *     pool.ntp.org) over UDP port 123.
 *   - Computes drift = (server's transmit timestamp) - (local clock).
 *   - Returns the drift in milliseconds.
 *
 * What this does NOT do:
 *   - Continuous synchronization (use the OS NTP daemon for that).
 *   - Authenticated NTP (NTS, autokey).
 *   - Querying multiple servers and taking median (single-shot only).
 *
 * The framework's policy in db.init():
 *   - drift |x| < 5min        → log info, continue
 *   - drift |x| in [5min,1hr) → log warning, continue
 *   - drift |x| >= 1hr        → log fatal, exit (BLAMEJS_NTP_STRICT=1) or warn
 *   - NTP unreachable         → log warning, continue (network may not allow UDP/123)
 */
var dgram = require("dgram");
var C = require("./constants");

// NTP epoch: 1900-01-01. Unix epoch: 1970-01-01. Offset: 70 years incl. 17
// leap days = 2,208,988,800 seconds.
var NTP_TO_UNIX_OFFSET_SECONDS = 2208988800;

var DEFAULT_SERVERS = ["pool.ntp.org", "time.cloudflare.com"];
var DEFAULT_PORT    = 123;
var DEFAULT_TIMEOUT_MS = 3000;

/**
 * Query an NTP server once. Resolves with { driftMs, serverTimeMs } or
 * rejects with { code, message } where code is one of:
 *   'ntp/timeout'   — server didn't reply within timeoutMs
 *   'ntp/refused'   — DNS/connection error
 *   'ntp/bad-reply' — packet structure wrong
 */
function querySingle(server, opts) {
  opts = opts || {};
  var port = opts.port || DEFAULT_PORT;
  var timeoutMs = opts.timeoutMs || DEFAULT_TIMEOUT_MS;

  return new Promise(function (resolve, reject) {
    var socket = dgram.createSocket("udp4");
    var settled = false;

    function done(err, result) {
      if (settled) return;
      settled = true;
      try { socket.close(); } catch (_e) { /* ignored */ }
      if (err) reject(err); else resolve(result);
    }

    var timer = setTimeout(function () {
      done({ code: "ntp/timeout", message: "no reply from " + server + " within " + timeoutMs + "ms" });
    }, timeoutMs);
    timer.unref();

    // SNTPv4 client request: 48-byte buffer, byte 0 = 0b00_100_011 = 0x23
    //   LI=0 (no warning), VN=4, Mode=3 (client). Other bytes zero.
    var req = Buffer.alloc(48);
    req[0] = 0x23;
    var sendTimeMs = Date.now();

    socket.on("error", function (e) {
      clearTimeout(timer);
      done({ code: "ntp/refused", message: server + ": " + e.message });
    });

    socket.on("message", function (msg) {
      clearTimeout(timer);
      var receiveTimeMs = Date.now();
      if (!Buffer.isBuffer(msg) || msg.length < 48) {
        return done({ code: "ntp/bad-reply", message: "reply too short (" + (msg && msg.length) + " bytes)" });
      }
      // Bytes 40-47 = Transmit Timestamp (NTP epoch seconds.fraction)
      var ntpSeconds  = msg.readUInt32BE(40);
      var ntpFraction = msg.readUInt32BE(44);
      var serverUnixSeconds = ntpSeconds - NTP_TO_UNIX_OFFSET_SECONDS;
      var fracMs = Math.round(ntpFraction / 0x100000000 * 1000);
      var serverTimeMs = serverUnixSeconds * 1000 + fracMs;

      // Round-trip-corrected drift: assume the server's reply transmit
      // timestamp is approximately at the midpoint of our send/receive.
      var midpointMs = sendTimeMs + (receiveTimeMs - sendTimeMs) / 2;
      var driftMs = serverTimeMs - midpointMs;

      done(null, { driftMs: driftMs, serverTimeMs: serverTimeMs, server: server });
    });

    socket.send(req, 0, req.length, port, server, function (err) {
      if (err) {
        clearTimeout(timer);
        done({ code: "ntp/refused", message: "send to " + server + ": " + err.message });
      }
    });
  });
}

/**
 * Try each server in turn; return the first successful drift measurement.
 * Resolves null if all servers fail (caller decides whether that's fatal).
 */
async function checkDrift(opts) {
  opts = opts || {};
  var servers = opts.servers || DEFAULT_SERVERS;
  var lastError = null;
  for (var i = 0; i < servers.length; i++) {
    try {
      return await querySingle(servers[i], opts);
    } catch (e) {
      lastError = e;
    }
  }
  return { driftMs: null, error: lastError };
}

/**
 * Boot-time check that integrates with the framework's logging policy.
 * Returns a result object with { ok, driftMs, severity, message }.
 * Caller (db.init) decides whether to exit.
 */
async function bootCheck(opts) {
  opts = opts || {};
  var result = await checkDrift(opts);
  if (result.driftMs === null) {
    return {
      ok:       true,             // unreachable NTP isn't a hard failure
      severity: "warning",
      driftMs:  null,
      message:  "NTP unreachable: " + (result.error && result.error.message) +
                " (continuing — set BLAMEJS_NTP_STRICT=1 to fail closed)",
    };
  }
  var absMs = Math.abs(result.driftMs);
  var driftStr = (result.driftMs >= 0 ? "+" : "") + result.driftMs + "ms";
  if (absMs >= C.TIME.hours(1)) {
    return {
      ok:       false,
      severity: "fatal",
      driftMs:  result.driftMs,
      server:   result.server,
      message:  "clock drift " + driftStr + " from " + result.server + " (>= 1 hour) — refuse to boot",
    };
  }
  if (absMs >= C.TIME.minutes(5)) {
    return {
      ok:       true,
      severity: "warning",
      driftMs:  result.driftMs,
      server:   result.server,
      message:  "clock drift " + driftStr + " from " + result.server + " (>= 5 minutes) — investigate",
    };
  }
  return {
    ok:       true,
    severity: "info",
    driftMs:  result.driftMs,
    server:   result.server,
    message:  "clock drift " + driftStr + " from " + result.server,
  };
}

module.exports = {
  querySingle:               querySingle,
  checkDrift:                checkDrift,
  bootCheck:                 bootCheck,
  DEFAULT_SERVERS:           DEFAULT_SERVERS,
  NTP_TO_UNIX_OFFSET_SECONDS: NTP_TO_UNIX_OFFSET_SECONDS,
};
