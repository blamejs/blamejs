"use strict";
/**
 * scripts/check-services.js
 *
 * Pre-test gate. Verifies every backend declared in
 * docker-compose.test.yml is reachable from the host BEFORE the
 * integration test suite runs. Two-level probe per service:
 *
 *   1. TCP connect to the published port — proves the container
 *      mapped the port and the service is listening.
 *   2. Protocol-aware ping where cheap to add (HTTP /health for
 *      MinIO + NATS; PING for Redis; nothing more invasive than that).
 *
 * The probe is intentionally shallow — full auth + query roundtrips
 * belong in the test bodies themselves via test/helpers/services.js.
 * This script's job is to fail loudly and early when the operator
 * forgot to bring the compose stack up, not to substitute for tests.
 *
 * Exit codes:
 *   0  — every service responded
 *   1  — one or more services unreachable (table printed)
 *   2  — script-level error
 *
 * Usage:
 *   node scripts/check-services.js                — checks all 8 services
 *   node scripts/check-services.js redis postgres — checks named subset
 */
var net  = require("node:net");
var http = require("node:http");

var SERVICES = [
  { name: "redis",    host: "127.0.0.1", port:  6379, http: null,                                      label: "redis-cli ping"   },
  { name: "postgres", host: "127.0.0.1", port:  5432, http: null,                                      label: "tcp"              },
  { name: "mysql",    host: "127.0.0.1", port:  3306, http: null,                                      label: "tcp"              },
  { name: "mongodb",  host: "127.0.0.1", port: 27017, http: null,                                      label: "tcp"              },
  { name: "minio",    host: "127.0.0.1", port:  9000, http: "http://127.0.0.1:9000/minio/health/live", label: "GET /health/live" },
  { name: "rabbitmq", host: "127.0.0.1", port:  5672, http: null,                                      label: "tcp"              },
  { name: "nats",     host: "127.0.0.1", port:  4222, http: "http://127.0.0.1:8222/healthz",           label: "GET /healthz"     },
  { name: "syslog",   host: "127.0.0.1", port:  5514, http: null,                                      label: "tcp"              },
];

function probeTcp(host, port, timeoutMs) {
  return new Promise(function (resolve) {
    var sock = net.connect({ host: host, port: port });
    var done = false;
    var timer = setTimeout(function () {
      if (done) return;
      done = true;
      try { sock.destroy(); } catch (_e) {}
      resolve({ ok: false, reason: "tcp connect timeout after " + timeoutMs + "ms" });
    }, timeoutMs);
    sock.once("connect", function () {
      if (done) return;
      done = true;
      clearTimeout(timer);
      try { sock.end(); } catch (_e) {}
      resolve({ ok: true });
    });
    sock.once("error", function (err) {
      if (done) return;
      done = true;
      clearTimeout(timer);
      var msg = (err && err.code) || (err && err.message) || String(err);
      resolve({ ok: false, reason: "tcp connect failed: " + msg });
    });
  });
}

function probeHttp(url, timeoutMs) {
  return new Promise(function (resolve) {
    var req = http.get(url, function (res) {
      // Drain so socket frees and process can exit.
      res.on("data", function () {});
      res.on("end", function () {
        if (res.statusCode >= 200 && res.statusCode < 400) {
          resolve({ ok: true, status: res.statusCode });
        } else {
          resolve({ ok: false, reason: "http " + res.statusCode + " from " + url });
        }
      });
    });
    var done = false;
    var timer = setTimeout(function () {
      if (done) return;
      done = true;
      try { req.destroy(); } catch (_e) {}
      resolve({ ok: false, reason: "http request timeout after " + timeoutMs + "ms" });
    }, timeoutMs);
    req.once("error", function (err) {
      if (done) return;
      done = true;
      clearTimeout(timer);
      var msg = (err && err.code) || (err && err.message) || String(err);
      resolve({ ok: false, reason: "http request failed: " + msg });
    });
    req.once("close", function () { done = true; clearTimeout(timer); });
  });
}

// Redis-specific probe — TCP connect, send PING, expect +PONG.
// Catches the failure mode where the container is up but redis-server
// is still loading its dataset (rare but real) or auth-wall is blocking.
function probeRedis(host, port, timeoutMs) {
  return new Promise(function (resolve) {
    var sock = net.connect({ host: host, port: port });
    var buf = Buffer.alloc(0);
    var done = false;
    var timer = setTimeout(function () {
      if (done) return;
      done = true;
      try { sock.destroy(); } catch (_e) {}
      resolve({ ok: false, reason: "redis ping timeout after " + timeoutMs + "ms" });
    }, timeoutMs);
    sock.once("connect", function () {
      sock.write("*1\r\n$4\r\nPING\r\n");
    });
    sock.on("data", function (chunk) {
      if (done) return;
      buf = Buffer.concat([buf, chunk]);
      var s = buf.toString("utf8");
      if (s.indexOf("+PONG\r\n") !== -1) {
        done = true;
        clearTimeout(timer);
        try { sock.end(); } catch (_e) {}
        resolve({ ok: true });
      } else if (s.charAt(0) === "-") {
        // Server replied with error (-NOAUTH / -LOADING etc.)
        done = true;
        clearTimeout(timer);
        try { sock.end(); } catch (_e) {}
        var crlf = s.indexOf("\r\n");
        var line = crlf === -1 ? s : s.slice(0, crlf);
        resolve({ ok: false, reason: "redis replied " + line });
      }
    });
    sock.once("error", function (err) {
      if (done) return;
      done = true;
      clearTimeout(timer);
      var msg = (err && err.code) || (err && err.message) || String(err);
      resolve({ ok: false, reason: "redis tcp failed: " + msg });
    });
  });
}

async function probeService(svc, timeoutMs) {
  if (svc.name === "redis") return await probeRedis(svc.host, svc.port, timeoutMs);
  var tcp = await probeTcp(svc.host, svc.port, timeoutMs);
  if (!tcp.ok) return tcp;
  if (svc.http) {
    var http = await probeHttp(svc.http, timeoutMs);
    if (!http.ok) return http;
  }
  return { ok: true };
}

function _padEnd(s, w) {
  s = String(s);
  return s.length >= w ? s : s + new Array(w - s.length + 1).join(" ");
}

(async function main() {
  var requested = process.argv.slice(2);
  var targets = SERVICES;
  if (requested.length > 0) {
    var byName = {};
    SERVICES.forEach(function (s) { byName[s.name] = s; });
    var missing = requested.filter(function (n) { return !byName[n]; });
    if (missing.length > 0) {
      console.error("[check-services] unknown service name(s): " + missing.join(", "));
      console.error("[check-services] valid: " + SERVICES.map(function (s) { return s.name; }).join(", "));
      process.exit(2);
    }
    targets = requested.map(function (n) { return byName[n]; });
  }

  console.log("[check-services] probing " + targets.length + " service" +
              (targets.length === 1 ? "" : "s") + "...");
  var timeoutMs = Number(process.env.BLAMEJS_SERVICE_PROBE_TIMEOUT_MS) || 3000;

  var results = await Promise.all(targets.map(function (svc) {
    return probeService(svc, timeoutMs).then(function (r) {
      return { svc: svc, result: r };
    });
  }));

  var down = 0;
  results.forEach(function (entry) {
    var nameCol  = _padEnd(entry.svc.name, 10);
    var portCol  = _padEnd(entry.svc.host + ":" + entry.svc.port, 18);
    var labelCol = _padEnd(entry.svc.label, 22);
    if (entry.result.ok) {
      console.log("  " + nameCol + portCol + labelCol + "OK");
    } else {
      down += 1;
      console.log("  " + nameCol + portCol + labelCol + "DOWN — " + entry.result.reason);
    }
  });

  if (down === 0) {
    console.log("[check-services] all " + targets.length + " responding");
    process.exit(0);
  }
  console.error("[check-services] " + down + " of " + targets.length + " unreachable");
  console.error("[check-services] bring the stack up with:");
  console.error("  docker compose -f docker-compose.test.yml up --wait");
  process.exit(1);
})().catch(function (err) {
  console.error("[check-services] script error: " + ((err && err.stack) || err));
  process.exit(2);
});
