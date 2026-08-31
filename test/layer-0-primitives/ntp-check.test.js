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

// A plain SNTP reply is unauthenticated by construction, and this reading
// decides whether the process refuses to boot — so a spoofer on the path can
// force a refusal, or mask real drift, and the check cannot tell. The framework
// ships an RFC 8915 client for exactly this, and BLAMEJS_NTS_SERVERS was
// declared in the shipped compose files while nothing anywhere read it: an
// operator who set it got the unauthenticated check they were trying to
// replace, with no signal that the setting had done nothing.
async function testCheckDriftPrefersAuthenticatedTime() {
  // Nothing answers on port 1, so the NTS attempt fails and the fallback runs.
  // What is pinned is the ORDER and the reporting, not a live NTS server.
  var fellBack = await b.ntpCheck.checkDrift({
    ntsServers: ["127.0.0.1"], servers: ["127.0.0.1"], port: 1, timeoutMs: 250,                        // allow:raw-time-literal — test-only short probe
  });
  check("checkDrift: an unreachable NTS server falls back rather than failing closed",
    fellBack && fellBack.driftMs === null, JSON.stringify(fellBack));
  check("checkDrift: and says the answer was not authenticated",
    fellBack.authenticated === false, JSON.stringify(fellBack.authenticated));

  // requireNts turns a failed authenticated query into the answer, rather than
  // a reason to ask an unauthenticated one. An operator who asks for the
  // guarantee gets the guarantee or nothing.
  var required = await b.ntpCheck.checkDrift({
    ntsServers: ["127.0.0.1"], servers: ["127.0.0.1"], port: 1, timeoutMs: 250,                        // allow:raw-time-literal — test-only short probe
    requireNts: true,
  });
  check("checkDrift: requireNts does not fall back to unauthenticated time",
    required && required.driftMs === null && required.authenticated === false,
    JSON.stringify(required));

  // And the boot path reads the knob the compose files advertise, which is what
  // was missing: the variable existed, was documented, and reached no code.
  var dbSrc = require("node:fs").readFileSync(
    require("node:path").join(__dirname, "..", "..", "lib", "db.js"), "utf8");
  check("checkDrift: the boot path reads BLAMEJS_NTS_SERVERS",
    dbSrc.indexOf('readVar("BLAMEJS_NTS_SERVERS"') !== -1);
  check("checkDrift: and BLAMEJS_NTS_REQUIRE",
    dbSrc.indexOf('readVar("BLAMEJS_NTS_REQUIRE"') !== -1);

  // Requiring authenticated time has to REFUSE the boot, not merely decline to
  // fall back. Disabling the fallback alone left bootCheck reporting an
  // unreachable warning with ok:true, so a deployment that asked for the
  // guarantee booted anyway unless a second, unrelated variable happened to be
  // set — the same shape as a setting that names itself fail-closed and is not.
  //
  // That refusal is asserted where it can actually be observed, by starting the
  // framework: test/layer-0-primitives/db-nts-required-boot.test.js. Matching
  // the source text here would only pin a spelling.

  // An NTS-KE endpoint does not run on a port anyone should have to guess, so
  // a server list that could only name a host would push every non-default
  // deployment into writing its own call site. A naive split on ":" is wrong
  // for the IPv6 form, which is full of them.
  var parse = b.ntpCheck._parseEndpointForTest;
  check("checkDrift: a bare host takes the default port",
    parse("time.example").host === "time.example" &&
    parse("time.example").port === undefined, JSON.stringify(parse("time.example")));
  check("checkDrift: host:port splits",
    parse("nts.example:4460").host === "nts.example" &&
    parse("nts.example:4460").port === 4460, JSON.stringify(parse("nts.example:4460")));
  check("checkDrift: a bracketed IPv6 literal with a port splits at the bracket",
    parse("[2001:db8::1]:4460").host === "2001:db8::1" &&
    parse("[2001:db8::1]:4460").port === 4460, JSON.stringify(parse("[2001:db8::1]:4460")));
  check("checkDrift: a bare IPv6 literal is not mistaken for host:port",
    parse("2001:db8::1").host === "2001:db8::1" &&
    parse("2001:db8::1").port === undefined, JSON.stringify(parse("2001:db8::1")));
  // An explicit port that cannot be used is a typo, not an omission. Reading it
  // as absent fell back to the NTS-KE default, so `:70000` quietly contacted a
  // different endpoint than the one configured and nothing reported it.
  var BAD_ENDPOINTS = [
    ["a port above the IANA range", "time.example:70000"],
    ["a non-numeric port",          "time.example:abc"],
    ["an empty port",               "time.example:"],
    ["an unclosed bracket",         "[2001:db8::1"],
    ["trailing text after ]",       "[2001:db8::1]junk"],
    ["a bracketed bad port",        "[2001:db8::1]:70000"],
    // An empty host is a configuration error, not an unreachable server: read
    // as a host it produced a failed query, which fell back to unauthenticated
    // SNTP and pointed the operator at the network instead of the setting.
    ["an empty entry",              ""],
    ["a whitespace-only entry",     "   "],
    ["a null entry",                null],
    ["empty brackets",              "[]"],
    ["empty brackets with a port",  "[]:4460"],
    ["a missing host before :port", ":4460"],
  ];
  BAD_ENDPOINTS.forEach(function (c) {
    var err = null;
    try { parse(c[1]); } catch (e) { err = e; }
    check("checkDrift: " + c[0] + " is refused rather than silently defaulted",
      err !== null && err.code === "ntp/bad-nts-endpoint",
      c[1] + " → " + String(err && (err.code || err.message)));
  });
  // The control: a bracketed address with no port at all is still valid.
  check("checkDrift: a bracketed IPv6 literal with no port takes the default",
    parse("[2001:db8::1]").host === "2001:db8::1" &&
    parse("[2001:db8::1]").port === undefined,
    JSON.stringify(parse("[2001:db8::1]")));

  // A present option of the wrong TYPE is refused, never coerced and never
  // ignored. Both of these took the guarantee away silently: `requireNts` was
  // compared against `true`, so a config loader handing back the string "true"
  // or the number 1 read as DISABLED and the unauthenticated fallback ran; and
  // a non-array `ntsServers` read as an empty list, so no authenticated query
  // was attempted at all. db.init builds a real boolean and a real array, so
  // neither reached it — a direct caller lost the guarantee and was told
  // nothing.
  var BAD_OPTS = [
    ["requireNts as a string",  { requireNts: "true" },  "ntp/bad-require-nts"],
    ["requireNts as a number",  { requireNts: 1 },       "ntp/bad-require-nts"],
    // `servers` is the same shape one field over, and it was the one that
    // actually reached a socket: a string is iterated by CHARACTER, so
    // `servers: "zq"` queried the hosts "z" and "q" and reported an ordinary
    // unreachable warning. The configured server was never contacted, and the
    // clock went unchecked with nothing saying why. Measured, not assumed —
    // the returned error read `no reply from q`.
    ["servers as a string",     { servers: "time.example" },    "ntp/bad-servers"],
    ["servers as an object",    { servers: { host: "x" } },     "ntp/bad-servers"],
    ["an empty entry in servers", { servers: ["time.example", ""] }, "ntp/bad-servers"],
    // A negative timeout is truthy, so it passed the `|| DEFAULT` guard and
    // armed a timer that fires immediately — every query "times out" at once.
    ["a negative timeoutMs",    { timeoutMs: -1 },              "ntp/bad-timeout"],
    ["a non-numeric timeoutMs", { timeoutMs: "soon" },          "ntp/bad-timeout"],
    ["ntsServers as a string",  { ntsServers: "time.example" }, "ntp/bad-nts-servers"],
    ["ntsServers as an object", { ntsServers: { host: "x" } },  "ntp/bad-nts-servers"],
    // The shared validator checks the ELEMENTS too, so a list with a hole in
    // it is refused where it is configured rather than at the first query.
    ["an empty entry in the list", { ntsServers: ["time.example", ""] }, "ntp/bad-nts-servers"],
    ["a non-string entry",         { ntsServers: [{ host: "x" }] },      "ntp/bad-nts-servers"],
  ];
  for (var bi = 0; bi < BAD_OPTS.length; bi += 1) {
    var badErr = null;
    try {
      await b.ntpCheck.checkDrift(Object.assign(
        { servers: ["127.0.0.1"], port: 1, timeoutMs: 250 }, BAD_OPTS[bi][1]));                        // allow:raw-time-literal — test-only short probe
    } catch (e) { badErr = e; }
    check("checkDrift: " + BAD_OPTS[bi][0] + " is refused rather than read as absent",
      badErr !== null && badErr.code === BAD_OPTS[bi][2],
      String(badErr && (badErr.code || badErr.message)));
  }
  // `null` is the framework's "absent, use the default" across every
  // optionalX validator, so it is accepted here rather than refused — the one
  // shape that is deliberately NOT a type error.
  var nullOk = await b.ntpCheck.checkDrift({
    servers: ["127.0.0.1"], port: 1, timeoutMs: 250,                                                   // allow:raw-time-literal — test-only short probe
    requireNts: null, ntsServers: null,
  });
  check("checkDrift: a null option reads as absent, matching every other optional opt",
    nullOk && nullOk.driftMs === null, JSON.stringify(nullOk));

  // The controls: the documented types still work, and so does omitting them.
  // Without these the assertions above would pass on a checkDrift that refused
  // every call.
  var okTrue = await b.ntpCheck.checkDrift({
    ntsServers: ["127.0.0.1"], servers: ["127.0.0.1"], port: 1, timeoutMs: 250,                        // allow:raw-time-literal — test-only short probe
    requireNts: true,
  });
  check("checkDrift: a boolean true requireNts is accepted",
    okTrue && okTrue.authenticated === false, JSON.stringify(okTrue));
  var okFalse = await b.ntpCheck.checkDrift({
    ntsServers: [], servers: ["127.0.0.1"], port: 1, timeoutMs: 250, requireNts: false,                // allow:raw-time-literal — test-only short probe
  });
  check("checkDrift: a boolean false requireNts and an empty list are accepted",
    okFalse && okFalse.driftMs === null, JSON.stringify(okFalse));

  // And the refusal reaches the caller through the real entry point, not only
  // the parser: checkDrift is what an operator's configuration flows into.
  var listErr = null;
  try {
    await b.ntpCheck.checkDrift({ ntsServers: ["time.example:70000"], servers: ["127.0.0.1"],
      port: 1, timeoutMs: 250 });                                                                      // allow:raw-time-literal — test-only short probe
  } catch (e) { listErr = e; }
  check("checkDrift: a malformed entry in the server list surfaces, not swallowed",
    listErr !== null && listErr.code === "ntp/bad-nts-endpoint",
    String(listErr && (listErr.code || listErr.message)));
}

// bootCheck does not return checkDrift's result — it builds a NEW object on
// each of its four branches. Every field it forgets to copy is silently absent,
// and `authenticated` is the one the boot decision now reads: with it dropped,
// `authenticated !== true` holds even for a genuinely authenticated reading, so
// requiring NTS refused every boot instead of the unauthenticated ones. The
// mode was unusable in exactly the configuration it exists for.
//
// Asserted on all four branches rather than the one that had the bug, because
// the defect is the rebuild, and each branch rebuilds separately.
async function testBootCheckCarriesAuthenticationThrough() {
  var fake = await _startFakeNtpServer();
  b.ntpCheck._resetThresholdsForTest();
  try {
    // Reachable, and far enough out to cross the fatal line.
    var fatal = await b.ntpCheck.bootCheck({
      servers: ["127.0.0.1"], port: fake.port, timeoutMs: 3000,
      driftWarnMs: 2000, driftFatalMs: 30000,
    });
    check("bootCheck: a fatal-drift result still reports whether the reading was authenticated",
      typeof fatal.authenticated === "boolean", JSON.stringify(fatal));
    check("bootCheck: and a plain SNTP reply is reported as unauthenticated",
      fatal.authenticated === false, JSON.stringify(fatal.authenticated));

    // Same reading, thresholds raised so it lands on the warning branch.
    var warn = await b.ntpCheck.bootCheck({
      servers: ["127.0.0.1"], port: fake.port, timeoutMs: 3000,
      driftWarnMs: 2000, driftFatalMs: 600000,
    });
    check("bootCheck: a warning result carries it too",
      warn.severity === "warning" && warn.authenticated === false,
      JSON.stringify(warn));

    // And again with both thresholds above the drift, for the info branch.
    var info = await b.ntpCheck.bootCheck({
      servers: ["127.0.0.1"], port: fake.port, timeoutMs: 3000,
      driftWarnMs: 600000, driftFatalMs: 900000,
    });
    check("bootCheck: an in-tolerance result carries it too",
      info.severity === "info" && info.authenticated === false,
      JSON.stringify(info));

    // Nothing answered, so nothing was authenticated — still a stated false
    // rather than an absent field, because the boot reads it on this path too.
    var unreachable = await b.ntpCheck.bootCheck({
      servers: ["127.0.0.1"], port: 1, timeoutMs: 250,                                                 // allow:raw-time-literal — test-only short probe
    });
    check("bootCheck: an unreachable server reports unauthenticated, not undefined",
      unreachable.authenticated === false, JSON.stringify(unreachable));
  } finally {
    await new Promise(function (resolve) { fake.srv.close(resolve); });
    b.ntpCheck._resetThresholdsForTest();
  }
}

// monitor() starts a timer and hands back a handle. Its opts are validated
// inside _tick, which CATCHES and returns — so a typo or a wrong type left the
// caller holding a live-looking monitor whose every check failed, and the only
// trace was an audit row nobody was watching for. The refusal has to happen
// where the caller is still on the stack.
function testMonitorRejectsBadOptsSynchronously() {
  var BAD = [
    ["an unknown option",        { intervalMs: 40, bogusOption: 1 }],                                  // allow:raw-time-literal — fixture interval, not a runtime budget
    ["a string servers",         { intervalMs: 40, servers: "time.example" }],                         // allow:raw-time-literal — fixture interval, not a runtime budget
    ["a string requireNts",      { intervalMs: 40, requireNts: "true" }],                              // allow:raw-time-literal — fixture interval, not a runtime budget
    ["a non-array ntsServers",   { intervalMs: 40, ntsServers: "nts.example" }],                       // allow:raw-time-literal — fixture interval, not a runtime budget
    ["a negative timeoutMs",     { intervalMs: 40, timeoutMs: -1 }],                                   // allow:raw-time-literal — fixture interval, not a runtime budget
  ];
  BAD.forEach(function (c) {
    var mon = null;
    var threw = null;
    try { mon = b.ntpCheck.monitor(c[1]); } catch (e) { threw = e; }
    if (mon && typeof mon.stop === "function") mon.stop();
    check("monitor: " + c[0] + " is refused before the timer starts",
      threw !== null, "monitor() returned a handle instead of throwing");
  });

  // Zero DISABLES a threshold — bootCheck applies each one only when it is
  // `> 0`, so `driftFatalMs: 0` is a supported override, not a bad value. A
  // positive-only rule would refuse it and make monitor reject what bootCheck
  // accepts for the same option.
  var zeroed = null;
  var zeroErr = null;
  try {
    zeroed = b.ntpCheck.monitor({
      intervalMs: 60000, servers: ["127.0.0.1"], port: 1, timeoutMs: 250,                              // allow:raw-time-literal — fixture interval, not a runtime budget
      driftWarnMs: 0, driftFatalMs: 0, audit: false,
    });
  } catch (e) { zeroErr = e; }
  if (zeroed && typeof zeroed.stop === "function") zeroed.stop();
  check("monitor: a zeroed threshold is accepted, because zero disables it",
    zeroErr === null, String(zeroErr && (zeroErr.code || zeroErr.message)));

  // The control: a fully-valid opts object still builds a monitor, so the
  // assertions above are about the bad values and not about monitor refusing
  // everything.
  var ok = b.ntpCheck.monitor({
    intervalMs: 60000, servers: ["127.0.0.1"], port: 1, timeoutMs: 250,                                // allow:raw-time-literal — fixture interval, not a runtime budget
    driftWarnMs: 2000, driftFatalMs: 30000, audit: false,                                              // allow:raw-time-literal — fixture thresholds, not a runtime budget
    onDrift: function () {},
  });
  check("monitor: a valid opts object still returns a handle",
    ok && typeof ok.stop === "function");
  ok.stop();
}

// bootCheck reads its two threshold overrides with `typeof x === "number"` and
// falls back to the registered thresholds otherwise, so a string
// `driftFatalMs` was IGNORED and the boot ran against the registered value
// instead of the one the caller passed. monitor refuses the same value, so the
// two disagreed about an option they share — the mirror of the inconsistency
// that made a zeroed threshold worth allowing.
async function testBootCheckRefusesMistypedThresholds() {
  var BAD = [
    ["a string driftFatalMs", { driftFatalMs: "60000" }],
    ["a string driftWarnMs",  { driftWarnMs: "1000" }],
    ["a negative driftWarnMs", { driftWarnMs: -1 }],
  ];
  for (var i = 0; i < BAD.length; i += 1) {
    var err = null;
    try {
      await b.ntpCheck.bootCheck(Object.assign(
        { servers: ["127.0.0.1"], port: 1, timeoutMs: 250 }, BAD[i][1]));                              // allow:raw-time-literal — test-only short probe
    } catch (e) { err = e; }
    check("bootCheck: " + BAD[i][0] + " is refused rather than ignored",
      err !== null && err.code === "ntp/bad-threshold",
      String(err && (err.code || err.message)));
  }

  // Controls: a numeric override is honoured, and zero still disables — the
  // same contract monitor now enforces, so the two agree.
  var numeric = await b.ntpCheck.bootCheck({
    servers: ["127.0.0.1"], port: 1, timeoutMs: 250, driftFatalMs: 60000, driftWarnMs: 1000,           // allow:raw-time-literal — test-only short probe
  });
  check("bootCheck: a numeric threshold override is accepted",
    numeric && numeric.driftMs === null, JSON.stringify(numeric));
  var zeroed = await b.ntpCheck.bootCheck({
    servers: ["127.0.0.1"], port: 1, timeoutMs: 250, driftFatalMs: 0, driftWarnMs: 0,                  // allow:raw-time-literal — test-only short probe
  });
  check("bootCheck: a zeroed threshold is accepted, because zero disables it",
    zeroed && zeroed.driftMs === null, JSON.stringify(zeroed));
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
    // A drift figure alone does not say whether the source could be spoofed,
    // and the audit trail is read long after the tick.
    var checked = auditEvents.find(function (e) { return e.action === "system.ntp.checked"; });
    check("monitor system.ntp.checked records whether the reading was authenticated",
          checked && checked.metadata && checked.metadata.authenticated === false,
          JSON.stringify(checked && checked.metadata));

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
  testMonitorRejectsBadOptsSynchronously();
  await testBootCheckRefusesMistypedThresholds();
  await testMonitorFiresOnDriftAndAudits();
  await testUnreachableMessageNamesAReadableSetting();
  await testCheckDriftPrefersAuthenticatedTime();
  await testBootCheckCarriesAuthenticationThrough();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[ntp-check] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e); process.exit(1); }
  );
}
