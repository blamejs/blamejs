// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.ntpCheck
 * @nav    Production
 * @title  NTP Check
 *
 * @intro
 *   Boot-time clock-drift verification against an external NTP / NTS-KE
 *   reference. The audit chain's `monotonicCounter` orders events
 *   deterministically even when the wall clock jumps, but `recordedAt`
 *   is the human-readable timestamp auditors rely on — a clock silently
 *   off by hours (container with no RTC sync, NTP daemon stopped)
 *   makes the audit trail misleading without ever surfacing as an
 *   error.
 *
 *   What this does: sends a single SNTPv4 query over UDP/123 (RFC 5905)
 *   to one or more configured servers, computes drift as
 *   `serverTransmit - localMidpoint` (round-trip-corrected), returns
 *   the drift in milliseconds. Falls through a server list in order;
 *   the first success wins.
 *
 *   What this does NOT do: continuous synchronization (the host OS's
 *   NTP daemon does that), authenticated NTP / NTS / autokey (the
 *   external reference is trust-on-first-query), or median-of-N
 *   server reconciliation (single-shot only).
 *
 *   Policy thresholds at boot — wired into `b.db.init`:
 *
 *     drift |x| < warnMs (5 min default)        → info, continue
 *     drift |x| in [warnMs, fatalMs)            → warning, continue
 *     drift |x| >= fatalMs (1 hr default)       → refuse to boot
 *                                                 (BLAMEJS_NTP_STRICT=0
 *                                                  downgrades to a log line)
 *     NTP unreachable                           → warning, continue
 *                                                 (network may not allow
 *                                                  UDP/123 outbound;
 *                                                  BLAMEJS_NTP_REQUIRE_REACHABLE=1
 *                                                  refuses the boot instead)
 *
 *   `b.ntpCheck.monitor` runs the same check on a recurring interval
 *   after boot and emits `system.ntp.checked` /
 *   `system.ntp.drift_warn` / `system.ntp.drift_fatal` /
 *   `system.ntp.unreachable` audit events plus an `ntp.drift_ms`
 *   observability gauge — so silent clock drift mid-flight surfaces
 *   in the same evidence stream as boot drift.
 *
 * @card
 *   Boot-time clock-drift verification against an external NTP / NTS-KE reference.
 */
var dgram = require("node:dgram");
var nodeCrypto = require("node:crypto");
var bCrypto = require("./crypto");
var C = require("./constants");
var lazyRequire = require("./lazy-require");
// Lazy: the NTS client pulls in the outbound-TLS posture, and this module is
// reached at boot before that is necessarily settled. Only the authenticated
// path needs it, and most hosts never take that path.
var networkNts = lazyRequire(function () { return require("./network-nts"); });
var safeAsync = require("./safe-async");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var audit = lazyRequire(function () { return require("./audit"); });
var observability = lazyRequire(function () { return require("./observability"); });

// Config-time misuse (a bad opts.port) throws a typed, permanent error so an
// operator catches the typo at boot rather than as a Promise rejection.
var NtpCheckError = defineClass("NtpCheckError", { alwaysPermanent: true });

// NTP epoch: 1900-01-01. Unix epoch: 1970-01-01. Offset: 70 years incl. 17
// leap days = 2,208,988,800 seconds.
var NTP_TO_UNIX_OFFSET_SECONDS = 2208988800;

var DEFAULT_SERVERS = ["pool.ntp.org", "time.cloudflare.com"];
var DEFAULT_PORT    = 123;
var DEFAULT_TIMEOUT_MS = C.TIME.seconds(3);
var NTP_PACKET_BYTES = C.BYTES.bytes(48);  // RFC 5905 §7.3

var DEFAULT_DRIFT_WARN_MS  = C.TIME.minutes(5);
var DEFAULT_DRIFT_FATAL_MS = C.TIME.hours(1);

var thresholds = {
  warnMs:  DEFAULT_DRIFT_WARN_MS,
  fatalMs: DEFAULT_DRIFT_FATAL_MS,
};

/**
 * @primitive b.ntpCheck.setThresholds
 * @signature b.ntpCheck.setThresholds(opts)
 * @since     0.7.30
 * @status    stable
 * @related   b.ntpCheck.getThresholds, b.ntpCheck.bootCheck
 *
 * Override the warn / fatal drift thresholds applied by `bootCheck`
 * and `monitor`. Validates that both values are non-negative finite
 * numbers and that `warnMs <= fatalMs` (a fatal floor below the
 * warning threshold would mean every warning is also fatal — likely
 * a typo). Throws `TypeError` on bad shapes and `RangeError` on the
 * ordering invariant.
 *
 * @opts
 *   warnMs:  300000,    // ms; absolute drift at-or-above this logs warn
 *   fatalMs: 3600000,   // ms; absolute drift at-or-above this refuses boot
 *
 * @example
 *   b.ntpCheck.setThresholds({
 *     warnMs:  60000,
 *     fatalMs: 600000,
 *   });
 *   var t = b.ntpCheck.getThresholds();
 *   // → { warnMs: 60000, fatalMs: 600000 }
 */
function setThresholds(opts) {
  opts = opts || {};
  if (opts.warnMs !== undefined) {
    if (typeof opts.warnMs !== "number" || !isFinite(opts.warnMs) || opts.warnMs < 0) {
      throw new TypeError("ntpCheck.setThresholds: warnMs must be non-negative finite number, got " + JSON.stringify(opts.warnMs));
    }
    thresholds.warnMs = opts.warnMs;
  }
  if (opts.fatalMs !== undefined) {
    if (typeof opts.fatalMs !== "number" || !isFinite(opts.fatalMs) || opts.fatalMs < 0) {
      throw new TypeError("ntpCheck.setThresholds: fatalMs must be non-negative finite number, got " + JSON.stringify(opts.fatalMs));
    }
    thresholds.fatalMs = opts.fatalMs;
  }
  if (thresholds.warnMs > thresholds.fatalMs && thresholds.fatalMs > 0) {
    throw new RangeError("ntpCheck.setThresholds: warnMs (" + thresholds.warnMs +
      ") must be <= fatalMs (" + thresholds.fatalMs + ")");
  }
}

/**
 * @primitive b.ntpCheck.getThresholds
 * @signature b.ntpCheck.getThresholds()
 * @since     0.7.30
 * @status    stable
 * @related   b.ntpCheck.setThresholds
 *
 * Read the currently-effective warn / fatal drift thresholds. Returns
 * a fresh object so mutating the result doesn't accidentally rewrite
 * framework state.
 *
 * @example
 *   var t = b.ntpCheck.getThresholds();
 *   // → { warnMs: 300000, fatalMs: 3600000 }
 */
function getThresholds() {
  return { warnMs: thresholds.warnMs, fatalMs: thresholds.fatalMs };
}

function _resetThresholdsForTest() {
  thresholds.warnMs  = DEFAULT_DRIFT_WARN_MS;
  thresholds.fatalMs = DEFAULT_DRIFT_FATAL_MS;
}

/**
 * @primitive b.ntpCheck.querySingle
 * @signature b.ntpCheck.querySingle(server, opts)
 * @since     0.0.7
 * @status    stable
 * @related   b.ntpCheck.checkDrift, b.ntpCheck.bootCheck
 *
 * Send one SNTPv4 query to a named server over UDP/123 and resolve
 * with `{ driftMs, serverTimeMs, server }` (round-trip-corrected
 * drift). Rejects with `{ code, message }` where `code` is one of
 * `ntp/timeout` (no reply within `timeoutMs`), `ntp/refused`
 * (DNS / connection error), `ntp/bad-reply` (packet too short), or
 * `ntp/unsynchronized` (Stratum-16 peer with zero transmit
 * timestamp). IPv4 / IPv6 socket family is selected from the host
 * literal so an `fd00::...` server doesn't fail with EINVAL.
 *
 * @opts
 *   port:      123,    // UDP port (almost always 123)
 *   timeoutMs: 3000,   // single-query timeout
 *
 * @example
 *   // requires: outbound NTP (udp/123) to the server named below
 *   b.ntpCheck.querySingle("time.cloudflare.com", { timeoutMs: 2000 })
 *     .then(function (r) { console.log("drift", r.driftMs, "ms"); })
 *     .catch(function (e) { console.error("ntp", e.code, e.message); });
 */
function querySingle(server, opts) {
  opts = opts || {};
  validateOpts.optionalPort(opts.port, "ntpCheck.querySingle: opts.port", NtpCheckError, "ntp/bad-port");
  var port = opts.port || DEFAULT_PORT;
  var timeoutMs = opts.timeoutMs || DEFAULT_TIMEOUT_MS;

  return new Promise(function (resolve, reject) {
    // SNTPv4 client request: NTP_PACKET_BYTES buffer, byte 0 = 0b00_100_011 = 0x23
    //   LI=0 (no warning), VN=4, Mode=3 (client). Other bytes zero.
    //
    // Built before the socket is opened, and inside this executor: entropy for
    // the nonce can fail, a socket acquired first would have nobody left to
    // close it, and a throw out here still reaches the caller as a rejection.
    var req = Buffer.alloc(NTP_PACKET_BYTES);
    req[0] = 0x23;
    // RFC 5905 §8 client-cookie: put a random 64-bit nonce in the request's
    // Transmit Timestamp (bytes 40-47). A conformant server copies it verbatim
    // into the reply's Originate Timestamp (bytes 24-31). Verifying that echo
    // rejects an off-path spoofed reply — without it ANY 48-byte UDP datagram
    // reaching our ephemeral port becomes the authoritative time, letting a
    // spoofer force a fatal-drift refuse-to-boot under BLAMEJS_NTP_STRICT.
    var originCookie = nodeCrypto.randomBytes(8);
    originCookie.copy(req, 40);

    // udp6 for IPv6 literals (`::1`, `fd00::…`), udp4 otherwise. Without
    // this branch a query to an IPv6 NTP host fails with EINVAL because
    // you can't send IPv6 packets through a udp4 socket.
    var family = server.indexOf(":") !== -1 ? "udp6" : "udp4";
    var socket = dgram.createSocket(family);
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
    var sendTimeMs = Date.now();

    socket.on("error", function (e) {
      clearTimeout(timer);
      done({ code: "ntp/refused", message: server + ": " + e.message });
    });

    socket.on("message", function (msg) {
      clearTimeout(timer);
      var receiveTimeMs = Date.now();
      if (!Buffer.isBuffer(msg) || msg.length < NTP_PACKET_BYTES) {
        return done({ code: "ntp/bad-reply", message: "reply too short (" + (msg && msg.length) + " bytes)" });
      }
      // Origin-cookie echo (RFC 5905 §8): the reply's Originate Timestamp
      // (bytes 24-31) MUST equal the nonce we sent. An off-path spoofer can't
      // know it, so this is the primary reply-authenticity check.
      if (!bCrypto.timingSafeEqual(msg.subarray(24, 32), originCookie)) {
        return done({ code: "ntp/origin-mismatch",
          message: server + ": reply Originate Timestamp does not echo the request nonce (spoofed/stale reply)" });
      }
      // Reject a non-server mode, an unsynchronized/kiss-o'-death stratum
      // (0 or >= 16), or LI=3 (alarm — clock not synchronized): such a peer
      // cannot supply a trustworthy time and must not drive drift.
      var mode = msg[0] & 0x07;
      var li = (msg[0] >> 6) & 0x03;
      var stratum = msg[1];
      if (mode !== 4 || li === 3 || stratum === 0 || stratum >= 16) {
        return done({ code: "ntp/unsynchronized",
          message: server + ": reply mode=" + mode + " stratum=" + stratum + " LI=" + li +
            " is not a synchronized server response" });
      }
      // Bytes 40-47 = Transmit Timestamp (NTP epoch seconds.fraction)
      var ntpSeconds  = msg.readUInt32BE(40);                                    // NTP packet offset
      var ntpFraction = msg.readUInt32BE(44);                                    // NTP packet offset
      // Refuse a reply whose Transmit Timestamp is zero or earlier than
      // the NTP epoch (1900-01-01). RFC 5905 §7.3 — a Stratum-16
      // unsynchronized server emits 0 here; fed to the Unix-offset
      // subtraction it produces a large-negative serverUnixSeconds
      // that crashes downstream C.TIME helpers (which require non-
      // negative finite). Treat as "unsynchronized peer — no drift
      // measurement possible" rather than throw out of the dgram
      // 'message' handler.
      if (ntpSeconds < NTP_TO_UNIX_OFFSET_SECONDS) {
        return done({ code: "ntp/unsynchronized",
          message: "server returned NTP transmit timestamp < Unix epoch (likely Stratum-16 unsynchronized)" });
      }
      var serverUnixSeconds = ntpSeconds - NTP_TO_UNIX_OFFSET_SECONDS;
      var fracMs = Math.round(C.TIME.seconds(ntpFraction / 0x100000000));       // NTP fraction divisor (2^32)
      var serverTimeMs = C.TIME.seconds(serverUnixSeconds) + fracMs;

      // Round-trip-corrected drift: assume the server's reply transmit
      // timestamp is approximately at the midpoint of our send/receive.
      var midpointMs = sendTimeMs + (receiveTimeMs - sendTimeMs) / 2;
      var driftMs = serverTimeMs - midpointMs;

      done(null, { driftMs: driftMs, serverTimeMs: serverTimeMs, server: server });
    });

    // send() rejects a malformed destination synchronously; routing that
    // through done() closes the socket rather than stranding it.
    try {
      socket.send(req, 0, req.length, port, server, function (err) {
        if (err) {
          clearTimeout(timer);
          done({ code: "ntp/refused", message: "send to " + server + ": " + err.message });
        }
      });
    } catch (e) {
      clearTimeout(timer);
      done({ code: "ntp/refused", message: "send to " + server + ": " + e.message });
    }
  });
}

/**
 * @primitive b.ntpCheck.checkDrift
 * @signature b.ntpCheck.checkDrift(opts)
 * @since     0.0.7
 * @status    stable
 * @related   b.ntpCheck.querySingle, b.ntpCheck.bootCheck
 *
 * Walk a server list in order; resolve with the first successful
 * drift measurement (`{ driftMs, serverTimeMs, server }`). When
 * every server in the list fails, resolves with
 * `{ driftMs: null, error }` so the caller — typically `bootCheck` —
 * can decide whether unreachable NTP is fatal or a soft warning.
 *
 * The result says which kind of answer it is: `authenticated: true` when it
 * came from an NTS server (RFC 8915), `false` from plain SNTP. Named NTS
 * servers are tried first; `requireNts` makes a failed authenticated query the
 * answer rather than a reason to fall back to an unauthenticated one.
 *
 * @opts
 *   servers:    ["time.cloudflare.com", "pool.ntp.org"],
 *   ntsServers: ["time.cloudflare.com", "nts.example:4460", "[2001:db8::1]:4460"],   // array; host, host:port or [v6]:port — tried first, authenticated (RFC 8915)
 *   requireNts: false,                     // boolean; no unauthenticated fallback when true
 *   port:      123,
 *   timeoutMs: 3000,
 *
 * Opts are validated against a schema. A field present with the wrong type is
 * refused rather than read as absent: a string `requireNts` would otherwise
 * drop the authenticated reading, a non-array `ntsServers` would attempt no
 * authenticated query at all, and a string `servers` has a length and indexes,
 * so it was walked CHARACTER BY CHARACTER — the configured server never
 * contacted, the result an ordinary unreachable warning. A key the schema does
 * not declare is refused too, so a typo cannot be silently consumed;
 * `bootCheck` and `monitor` forward their own opts through here and those are
 * allowed, validated where they are read.
 *
 * @example
 *   // requires: outbound NTP (udp/123) to the servers named below
 *   var result = await b.ntpCheck.checkDrift({
 *     servers: ["time.cloudflare.com", "pool.ntp.org"],
 *   });
 *   // → { driftMs: 12, serverTimeMs: 1714694400000,
 *   //     server: "time.cloudflare.com", authenticated: false }
 */
// `host`, `host:port`, or `[v6]:port` — the shape an operator writes in a
// server list. NTS-KE does not run on a port anyone should have to guess
// (4460), so a list that could only ever name a host would push every
// non-default deployment into supplying its own call site.
//
// Scanned rather than matched: this is parsing operator input, and the bracket
// form is the whole reason a naive split on ":" is wrong — an IPv6 literal is
// full of them.
function _parseEndpoint(entry) {
  var s = String(entry || "").trim();
  // An empty host is a configuration error too. Returned as a host, the query
  // failed and was counted as an unreachable NTS server — so an empty entry
  // in the list fell back to unauthenticated SNTP and reported a network
  // problem, which is the wrong place to send the operator to look.
  if (s === "") throw _badEndpoint(entry, "the entry is empty");
  if (s.charAt(0) === "[") {
    var close = s.indexOf("]");
    if (close === -1) throw _badEndpoint(entry, "the bracketed address is not closed");
    var host6 = s.slice(1, close);
    if (host6 === "") throw _badEndpoint(entry, "the bracketed address is empty");
    var rest = s.slice(close + 1);
    if (rest === "") return { host: host6, port: undefined };
    if (rest.charAt(0) !== ":") {
      throw _badEndpoint(entry, "trailing text after the closing bracket: " + JSON.stringify(rest));
    }
    return { host: host6, port: _requirePort(entry, rest.slice(1)) };
  }
  // A bare IPv6 literal has more than one colon and carries no port; only a
  // single colon can be a host/port separator.
  var first = s.indexOf(":");
  if (first === -1 || s.indexOf(":", first + 1) !== -1) return { host: s, port: undefined };
  if (first === 0) throw _badEndpoint(entry, "the host is empty");
  return { host: s.slice(0, first), port: _requirePort(entry, s.slice(first + 1)) };
}
// An explicit port that cannot be used is a configuration error, not an
// omission. Treating it as absent silently fell back to the NTS-KE default
// (4460), so an operator who wrote `:70000` — or mistyped one — was quietly
// pointed at a different endpoint than the one they configured, and nothing
// said so. Entry-point input: throw, so the typo surfaces at boot.
function _requirePort(entry, text) {
  if (!/^[0-9]{1,5}$/.test(text)) {                                                                    // allow:regex-no-length-cap — bounded by the 1-5 quantifier
    throw _badEndpoint(entry, "the port must be digits, got " + JSON.stringify(text));
  }
  var p = parseInt(text, 10);
  if (p < 1 || p > 65535) {                                                                            // allow:raw-byte-literal — the IANA port range
    throw _badEndpoint(entry, "the port must be 1-65535, got " + p);
  }
  return p;
}
function _badEndpoint(entry, why) {
  return new NtpCheckError(
    "ntp/bad-nts-endpoint",
    "invalid NTS server entry " + JSON.stringify(String(entry)) + ": " + why +
    ". Expected host, host:port, or [ipv6]:port");
}

// The opts checkDrift owns. Declared once and validated in a single shape call
// rather than a run of individual validateOpts.* lines: that run is the
// preamble `shape` exists to collapse, and hand-rolling it here reproduced a
// token shape a dozen other files already carry.
//
// Every entry closes a way of losing the answer in silence. `requireNts` is
// compared against `true`, so a config loader handing back "true" or 1 read as
// DISABLED and the unauthenticated fallback ran. A non-array `ntsServers` read
// as an empty list, so no authenticated query was attempted. `servers` was the
// one that reached a socket: a STRING has a length and indexes, so the loop
// below walked it by character — `servers: "zq"` queried the hosts "z" and "q"
// and reported an ordinary unreachable warning while the configured server was
// never contacted. A negative `timeoutMs` is truthy, so it passed the
// `|| DEFAULT` guard and armed a timer that fires at once.
var CHECK_DRIFT_SCHEMA = {
  servers:    { rule: "optional-string-array",    code: "ntp/bad-servers" },
  ntsServers: { rule: "optional-string-array",    code: "ntp/bad-nts-servers" },
  requireNts: { rule: "optional-boolean",         code: "ntp/bad-require-nts" },
  port:       { rule: "optional-port",            code: "ntp/bad-port" },
  timeoutMs:  { rule: "optional-positive-finite", code: "ntp/bad-timeout" },
};
// bootCheck and monitor forward their own opts through this function, so the
// keys THEY own are allowed rather than declared: each is validated where it is
// read, and declaring them here would make checkDrift the place a new monitor
// option has to be registered.
var CHECK_DRIFT_FORWARDED = ["driftWarnMs", "driftFatalMs", "intervalMs", "audit", "onDrift"];

// bootCheck owns the two threshold overrides on top of what checkDrift takes.
// It read them with `typeof x === "number"` and fell back to the registered
// thresholds otherwise, so a string `driftFatalMs` was IGNORED and the boot ran
// against a value the caller had not asked for. monitor refuses that same
// value, so the two disagreed about an option they share.
//
// Non-negative rather than positive, for the reason the thresholds are read
// with `> 0`: zero is how a caller disables one.
var BOOT_CHECK_SCHEMA = {
  servers:      { rule: "optional-string-array",    code: "ntp/bad-servers" },
  ntsServers:   { rule: "optional-string-array",    code: "ntp/bad-nts-servers" },
  requireNts:   { rule: "optional-boolean",         code: "ntp/bad-require-nts" },
  port:         { rule: "optional-port",            code: "ntp/bad-port" },
  timeoutMs:    { rule: "optional-positive-finite", code: "ntp/bad-timeout" },
  driftWarnMs:  { rule: "optional-non-negative",    code: "ntp/bad-threshold" },
  driftFatalMs: { rule: "optional-non-negative",    code: "ntp/bad-threshold" },
};
// monitor forwards its own tick controls through bootCheck; they are validated
// in monitor, where they are read.
var BOOT_CHECK_FORWARDED = ["intervalMs", "audit", "onDrift"];

// monitor owns the widest opts object of the three: everything checkDrift takes
// plus the threshold overrides bootCheck reads and its own tick controls. It is
// declared in full because monitor is the entry point that starts a timer and
// returns, so this is the last place a caller can be told they mistyped.
var MONITOR_SCHEMA = {
  servers:      { rule: "optional-string-array",    code: "ntp/bad-servers" },
  ntsServers:   { rule: "optional-string-array",    code: "ntp/bad-nts-servers" },
  requireNts:   { rule: "optional-boolean",         code: "ntp/bad-require-nts" },
  port:         { rule: "optional-port",            code: "ntp/bad-port" },
  timeoutMs:    { rule: "optional-positive-finite", code: "ntp/bad-timeout" },
  intervalMs:   { rule: "optional-positive-finite", code: "ntp/bad-interval" },
  // Non-negative, not positive: bootCheck applies each threshold only when it
  // is `> 0`, so ZERO is the documented way to disable one. A positive-only
  // rule would refuse an override bootCheck accepts, and monitor would reject
  // what the function it delegates to supports.
  driftWarnMs:  { rule: "optional-non-negative", code: "ntp/bad-threshold" },
  driftFatalMs: { rule: "optional-non-negative", code: "ntp/bad-threshold" },
  audit:        { rule: "optional-boolean",         code: "ntp/bad-audit" },
  onDrift:      { rule: "optional-function",        code: "ntp/bad-on-drift" },
};

async function checkDrift(opts) {
  opts = opts || {};
  // Config-time input, so a present option of the wrong TYPE is refused before
  // any query rather than coerced or ignored. Both of these took the guarantee
  // away in silence: `requireNts` is compared against `true`, so a config
  // loader handing back the string "true" or the number 1 read as DISABLED and
  // the unauthenticated fallback ran; and a non-array `ntsServers` read as an
  // empty list, so no authenticated query was attempted at all. `db.init`
  // builds a real boolean and a real array from the environment, so neither
  // reached it — only a direct caller lost the guarantee, and nothing said so.
  validateOpts.shape(opts, CHECK_DRIFT_SCHEMA, "ntpCheck.checkDrift",
    NtpCheckError, "ntp/bad-opts", { allow: CHECK_DRIFT_FORWARDED });
  var servers = opts.servers || DEFAULT_SERVERS;
  var lastError = null;

  // Authenticated first, when the operator has named NTS servers. A plain SNTP
  // reply is unauthenticated by construction — a spoofer on the path can hand
  // back any time it likes, and this reading decides whether the process
  // refuses to boot, so the answer is worth authenticating where it can be.
  // b.network.ntp.nts speaks RFC 8915 and returns the same shape this does.
  var ntsServers = Array.isArray(opts.ntsServers) ? opts.ntsServers : [];
  // Parsed BEFORE the first query, so a malformed entry is a configuration
  // error and not a failed attempt. Inside the loop its throw landed in the
  // same `lastError` an unreachable server does, and the run then reported an
  // unreachable NTS server — sending the operator to look at the network for
  // a typo in their own setting.
  var ntsEndpoints = ntsServers.map(_parseEndpoint);
  for (var n = 0; n < ntsServers.length; n += 1) {
    try {
      var ep = ntsEndpoints[n];
      var authed = await networkNts().query({
        host: ep.host, kePort: ep.port, timeoutMs: opts.timeoutMs,
      });
      return {
        driftMs:       authed.driftMs,
        serverTimeMs:  authed.serverTimeMs,
        server:        ntsServers[n],
        authenticated: true,
      };
    } catch (e) { lastError = e; }
  }
  // Falling back to unauthenticated SNTP is the DEFAULT, because most hosts
  // have no NTS server configured and refusing them would be a boot failure
  // nobody asked for. An operator who wants the guarantee rather than the
  // attempt sets requireNts, and then a failed authenticated query is the
  // answer rather than a reason to ask an unauthenticated one.
  if (opts.requireNts === true) {
    return { driftMs: null, error: lastError, authenticated: false };
  }

  for (var i = 0; i < servers.length; i++) {
    try {
      var plain = await querySingle(servers[i], opts);
      // Stated explicitly rather than left absent, so a caller cannot read a
      // missing field as "authenticated" — the distinction is the whole point
      // of having asked.
      plain.authenticated = false;
      return plain;
    } catch (e) {
      lastError = e;
    }
  }
  return { driftMs: null, error: lastError, authenticated: false };
}

/**
 * @primitive b.ntpCheck.bootCheck
 * @signature b.ntpCheck.bootCheck(opts)
 * @since     0.0.7
 * @status    stable
 * @related   b.ntpCheck.checkDrift, b.ntpCheck.monitor, b.ntpCheck.setThresholds
 *
 * Boot-time clock-drift check that integrates with the framework's
 * logging policy. Resolves with
 * `{ ok, severity, driftMs, server, authenticated, message }` where
 * `severity` is `info` / `warning` / `fatal` and `authenticated` says
 * whether the reading came from an authenticated (RFC 8915) server or
 * a plain SNTP reply anyone on the path could have written. The
 * framework's `b.db.init` calls this. Drift past the fatal threshold
 * refuses the boot by default, and `BLAMEJS_NTP_STRICT=0` downgrades
 * that refusal to a log line.
 *
 * Opts are forwarded to `checkDrift`, so `ntsServers` and `requireNts`
 * apply here as well, and they are validated against a schema: a field
 * present with the wrong type is refused rather than ignored. That includes
 * the two threshold overrides, which were read with a `typeof` test and
 * silently dropped when they were not numbers — the boot then ran against the
 * registered threshold rather than the one passed. Zero remains valid on
 * both: it disables that threshold.
 *
 * An unreachable server is a different question and answers
 * `severity: "warning"`, because a network that does not allow
 * outbound UDP/123 is ordinary and refusing every such host by
 * default would be a boot failure nobody asked for. An operator who
 * does want it refused sets `BLAMEJS_NTP_REQUIRE_REACHABLE=1`; that
 * is the only setting that turns an unanswered query into a refusal,
 * and `BLAMEJS_NTP_STRICT` has no bearing on it.
 *
 * @opts
 *   servers:      ["time.cloudflare.com", "pool.ntp.org"],
 *   port:         123,
 *   timeoutMs:    3000,
 *   driftWarnMs:  300000,    // override registered warn threshold
 *   driftFatalMs: 3600000,   // override registered fatal threshold
 *
 * @example
 *   // requires: outbound NTP (udp/123) to the servers named below
 *   var result = await b.ntpCheck.bootCheck({
 *     servers:      ["time.cloudflare.com"],
 *     driftWarnMs:  60000,
 *     driftFatalMs: 600000,
 *   });
 *   // → { ok: true, severity: "info", driftMs: 12,
 *   //     server: "time.cloudflare.com", authenticated: false,
 *   //     message: "clock drift +12ms from time.cloudflare.com" }
 */
async function bootCheck(opts) {
  opts = opts || {};
  validateOpts.shape(opts, BOOT_CHECK_SCHEMA, "ntpCheck.bootCheck",
    NtpCheckError, "ntp/bad-opts", { allow: BOOT_CHECK_FORWARDED });
  var result = await checkDrift(opts);
  // Each branch below builds a NEW result rather than returning this one, so
  // anything the reading carries has to be copied deliberately. `authenticated`
  // is read by the boot path to decide whether a required-NTS deployment may
  // start: dropped, it reads as "not authenticated" on every branch and the
  // requirement refuses even a reading that satisfied it.
  var authenticated = result.authenticated === true;
  if (result.driftMs === null) {
    return {
      ok:       true,             // unreachable NTP isn't a hard failure
      severity: "warning",
      driftMs:  null,
      authenticated: authenticated,
      message:  "NTP unreachable: " + (result.error && result.error.message) +
                " (continuing — set BLAMEJS_NTP_REQUIRE_REACHABLE=1 to refuse the boot instead)",
    };
  }
  var absMs = Math.abs(result.driftMs);
  var driftStr = (result.driftMs >= 0 ? "+" : "") + result.driftMs + "ms";
  var fatalMs = (opts && typeof opts.driftFatalMs === "number") ? opts.driftFatalMs : thresholds.fatalMs;
  var warnMs  = (opts && typeof opts.driftWarnMs  === "number") ? opts.driftWarnMs  : thresholds.warnMs;
  if (fatalMs > 0 && absMs >= fatalMs) {
    return {
      ok:       false,
      severity: "fatal",
      driftMs:  result.driftMs,
      server:   result.server,
      authenticated: authenticated,
      message:  "clock drift " + driftStr + " from " + result.server +
                " (>= " + fatalMs + "ms) — refuse to boot",
    };
  }
  if (warnMs > 0 && absMs >= warnMs) {
    return {
      ok:       true,
      severity: "warning",
      driftMs:  result.driftMs,
      server:   result.server,
      authenticated: authenticated,
      message:  "clock drift " + driftStr + " from " + result.server +
                " (>= " + warnMs + "ms) — investigate",
    };
  }
  return {
    ok:       true,
    severity: "info",
    driftMs:  result.driftMs,
    server:   result.server,
    authenticated: authenticated,
    message:  "clock drift " + driftStr + " from " + result.server,
  };
}

/**
 * @primitive b.ntpCheck.monitor
 * @signature b.ntpCheck.monitor(opts)
 * @since     0.7.30
 * @status    stable
 * @related   b.ntpCheck.bootCheck, b.audit.safeEmit, b.observability.safeEvent
 *
 * Periodic drift monitor — runs `bootCheck` on a recurring interval
 * and emits audit + observability events on threshold crossings.
 * Returns a handle with `.stop()` for graceful shutdown. Audit
 * emissions: `system.ntp.checked` on every tick,
 * `system.ntp.drift_warn` and `system.ntp.drift_fatal` on threshold
 * crossings, `system.ntp.unreachable` when every server in the list
 * failed. Observability gauge `ntp.drift_ms` rides every successful
 * check. The optional `onDrift` hook fires only when `severity`
 * is `warning` or `fatal`, so operators can page on drift without
 * inspecting every healthy tick.
 *
 * @opts
 *   intervalMs:   900000,                            // tick cadence
 *   servers:      ["time.cloudflare.com", "pool.ntp.org"],
 *   driftWarnMs:  2000,
 *   driftFatalMs: 30000,
 *   audit:        true,                              // emit audit events
 *   onDrift:      function (result) {},              // operator hook
 *
 * @example
 *   // requires: outbound NTP (udp/123) to the servers named below
 *   var mon = b.ntpCheck.monitor({
 *     intervalMs:   900000,
 *     servers:      ["time.cloudflare.com", "pool.ntp.org"],
 *     driftWarnMs:  2000,
 *     driftFatalMs: 30000,
 *     onDrift: function (r) { console.warn("ntp drift", r.driftMs); },
 *   });
 *   await mon.stop();
 */
function monitor(opts) {
  opts = opts || {};
  var intervalMs = opts.intervalMs || C.TIME.minutes(15);
  var auditOn = opts.audit !== false;
  if (typeof intervalMs !== "number" || !isFinite(intervalMs) || intervalMs <= 0) {
    throw new TypeError("ntpCheck.monitor: intervalMs must be a positive finite number");
  }
  // Validated HERE, where the caller is still on the stack. These opts are
  // forwarded to bootCheck and validated again inside `_tick`, which catches
  // and returns — so a typo or a wrong type produced a live-looking handle
  // whose every check failed, and the only trace was an audit row nobody was
  // waiting for. A refusal a caller cannot see is not a refusal.
  validateOpts.shape(opts, MONITOR_SCHEMA, "ntpCheck.monitor",
    NtpCheckError, "ntp/bad-opts");

  function _emit(action, metadata) {
    if (!auditOn) return;
    try {
      audit().safeEmit({
        action:   action,
        outcome:  metadata && metadata.severity === "fatal" ? "fail" : "ok",
        metadata: metadata || {},
      });
    } catch (_e) { /* drop-silent */ }
  }

  async function _tick() {
    var res;
    try { res = await bootCheck(opts); }
    catch (e) {
      _emit("system.ntp.checked", { severity: "fatal", error: (e && e.message) || String(e) });
      return;
    }
    if (res.driftMs === null) {
      _emit("system.ntp.unreachable", { severity: "warning", message: res.message });
      return;
    }
    try { observability().safeEvent("ntp.drift_ms", res.driftMs, { server: res.server || "unknown" }); }
    catch (_e) { /* drop-silent */ }
    // The audit record carries whether the reading was authenticated: a drift
    // figure read off a plain SNTP reply and one read over NTS are different
    // evidence, and an auditor looking at the trail afterwards cannot tell them
    // apart from the number alone.
    _emit("system.ntp.checked", {
      severity: res.severity, driftMs: res.driftMs, server: res.server,
      authenticated: res.authenticated === true,
    });
    if (res.severity === "fatal") {
      _emit("system.ntp.drift_fatal", { driftMs: res.driftMs, server: res.server });
    } else if (res.severity === "warning") {
      _emit("system.ntp.drift_warn", { driftMs: res.driftMs, server: res.server });
    }
    if (typeof opts.onDrift === "function" && res.severity !== "info") {
      try { await opts.onDrift(res); } catch (_e) { /* operator hook — drop-silent */ }
    }
  }

  var handle = safeAsync.repeating(_tick, intervalMs, { name: "ntp-monitor" });
  return {
    stop: function () { if (handle) { handle.stop(); handle = null; } },
  };
}

module.exports = {
  querySingle:               querySingle,
  NtpCheckError:             NtpCheckError,
  checkDrift:                checkDrift,
  bootCheck:                 bootCheck,
  monitor:                   monitor,
  setThresholds:             setThresholds,
  getThresholds:             getThresholds,
  DEFAULT_SERVERS:           DEFAULT_SERVERS,
  DEFAULT_DRIFT_WARN_MS:     DEFAULT_DRIFT_WARN_MS,
  DEFAULT_DRIFT_FATAL_MS:    DEFAULT_DRIFT_FATAL_MS,
  NTP_TO_UNIX_OFFSET_SECONDS: NTP_TO_UNIX_OFFSET_SECONDS,
  _resetThresholdsForTest:   _resetThresholdsForTest,
  // Endpoint parsing is operator-input handling with an IPv6 case that a naive
  // split gets wrong, so its table is drivable directly rather than only
  // through a live NTS server. Not part of the public surface.
  _parseEndpointForTest:     _parseEndpoint,
};
