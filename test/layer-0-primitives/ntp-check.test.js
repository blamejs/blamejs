// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * ntpCheck.monitor — periodic clock-drift monitor.
 *
 * Drives b.ntpCheck.monitor against a LOCAL (loopback-only) SNTP
 * responder that echoes the request's origin cookie and reports a large
 * positive drift, so a real tick runs bootCheck → checkDrift →
 * querySingle end-to-end and crosses the fatal threshold. No packets
 * leave the host. Asserts the advertised surface: the onDrift hook fires,
 * the audit events (`system.ntp.checked` + `system.ntp.drift_fatal`) are
 * emitted, and stop() halts further ticks.
 *
 * Run standalone: `node test/layer-0-primitives/ntp-check.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var dgram = require("node:dgram");

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

// NTP epoch (1900) → Unix epoch (1970) offset in seconds.
var NTP_TO_UNIX_OFFSET_SECONDS = 2208988800;

// Stand up a loopback SNTP responder that replies to every request with a
// synchronized-server packet echoing the client's origin cookie and a
// transmit timestamp ~100s in the future (a fatal-magnitude drift).
function _startFakeNtpServer() {
  var srv = dgram.createSocket("udp4");
  srv.on("message", function (msg, rinfo) {
    var reply = Buffer.alloc(48);
    reply[0] = 0x24;                 // LI=0, VN=4, Mode=4 (server)
    reply[1] = 1;                    // stratum 1 (synchronized)
    msg.copy(reply, 24, 40, 48);     // Originate = the request's Transmit Timestamp (cookie echo)
    var serverSec = Math.floor((Date.now() + 100000) / 1000) + NTP_TO_UNIX_OFFSET_SECONDS;
    reply.writeUInt32BE(serverSec, 40);
    reply.writeUInt32BE(0, 44);
    try { srv.send(reply, 0, reply.length, rinfo.port, rinfo.address); } catch (_e) { /* closing */ }
  });
  return new Promise(function (resolve) {
    srv.bind(0, "127.0.0.1", function () { resolve({ srv: srv, port: srv.address().port }); });
  });
}

// The message an operator reads when no server answers has to name a setting
// that exists. It named BLAMEJS_NTP_STRICT, which is consulted only on the
// FATAL-drift branch and already defaults to on — so following the advice set a
// variable to the value it already held, on a branch this result never reaches,
// and a host with UDP/123 blocked went on booting with an unchecked clock while
// being told it had a way to prevent that.
//
// Asserted against the ACTUAL env var name rather than a copy of the string, so
// a message that drifts back to naming a setting nothing reads fails here.
async function testUnreachableMessageNamesAReadableSetting() {
  // Port 1 on loopback answers nothing, and the short timeout keeps it quick.
  var result = await b.ntpCheck.bootCheck({
    servers: ["127.0.0.1"], port: 1, timeoutMs: 250,                                                   // allow:raw-time-literal — test-only short probe
  });
  check("ntpCheck.bootCheck: an unanswered query is a warning, not a hard failure",
    result.ok === true && result.severity === "warning" && result.driftMs === null,
    JSON.stringify(result));

  var named = /BLAMEJS_[A-Z_]+/.exec(result.message || "");
  check("ntpCheck.bootCheck: the unreachable message names a setting",
    named !== null, JSON.stringify(result.message));
  if (!named) return;
  // The one it names must be the one the boot path actually reads for THIS
  // result. BLAMEJS_NTP_STRICT is not it: db.js consults that only where
  // severity is "fatal".
  check("ntpCheck.bootCheck: and names the setting that governs an unreachable " +
        "server, not the one that governs excess drift",
    named[0] === "BLAMEJS_NTP_REQUIRE_REACHABLE", named[0]);
  check("ntpCheck.bootCheck: the named setting is read by the boot path",
    require("node:fs").readFileSync(
      require("node:path").join(__dirname, "..", "..", "lib", "db.js"), "utf8")
      .indexOf('readVar("' + named[0] + '"') !== -1,
    named[0] + " is not read anywhere in lib/db.js");
}

function testMonitorRejectsBadInterval() {
  var t1 = null;
  try { b.ntpCheck.monitor({ intervalMs: -1 }); } catch (e) { t1 = e; }
  check("ntpCheck.monitor rejects non-positive intervalMs", t1 instanceof TypeError);
  var t2 = null;
  try { b.ntpCheck.monitor({ intervalMs: "soon" }); } catch (e) { t2 = e; }
  check("ntpCheck.monitor rejects non-number intervalMs", t2 instanceof TypeError);
}

async function testMonitorFiresOnDriftAndAudits() {
  b.ntpCheck._resetThresholdsForTest();
  var fake = await _startFakeNtpServer();

  var auditEvents  = [];
  var realSafeEmit = b.audit.safeEmit;
  b.audit.safeEmit = function (ev) { auditEvents.push(ev); };

  var drifts = [];
  var mon = b.ntpCheck.monitor({
    intervalMs:   40,
    servers:      ["127.0.0.1"],
    port:         fake.port,
    timeoutMs:    3000,
    driftWarnMs:  2000,
    driftFatalMs: 30000,
    audit:        true,
    onDrift:      function (r) { drifts.push(r); },
  });
  try {
    await helpers.waitUntil(function () { return drifts.length >= 1; },
      { timeoutMs: 6000, label: "ntpCheck.monitor: onDrift fired on fatal drift" });
    var r0 = drifts[0];
    check("monitor onDrift severity is fatal for +100s drift", r0.severity === "fatal");
    check("monitor onDrift reports the queried server",        r0.server === "127.0.0.1");
    check("monitor onDrift driftMs is large-positive",         r0.driftMs > 30000);

    await helpers.waitUntil(function () {
      return auditEvents.some(function (e) { return e.action === "system.ntp.drift_fatal"; });
    }, { timeoutMs: 6000, label: "ntpCheck.monitor: system.ntp.drift_fatal emitted" });
    check("monitor emits system.ntp.checked each tick",
          auditEvents.some(function (e) { return e.action === "system.ntp.checked"; }));
    check("monitor system.ntp.checked outcome is fail on fatal drift",
          auditEvents.some(function (e) { return e.action === "system.ntp.checked" && e.outcome === "fail"; }));
    var fatal = auditEvents.find(function (e) { return e.action === "system.ntp.drift_fatal"; });
    check("monitor drift_fatal audit carries driftMs metadata",
          fatal && fatal.metadata && typeof fatal.metadata.driftMs === "number");

    // stop() halts the ticker — over a 10-interval window a running monitor
    // would fire ~10 more onDrifts; a stopped one fires at most one straggler
    // (a tick already in-flight past the stopped-guard when stop() ran).
    mon.stop();
    var before = drifts.length;
    await helpers.passiveObserve(400, "ntpCheck.monitor: no ticks after stop()");
    check("monitor stop() halts further ticks", drifts.length - before <= 1);
  } finally {
    mon.stop();
    b.audit.safeEmit = realSafeEmit;
    await new Promise(function (resolve) { fake.srv.close(resolve); });
    b.ntpCheck._resetThresholdsForTest();
  }
}

async function run() {
  testMonitorRejectsBadInterval();
  await testMonitorFiresOnDriftAndAudits();
  await testUnreachableMessageNamesAReadableSetting();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[ntp-check] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e); process.exit(1); }
  );
}
