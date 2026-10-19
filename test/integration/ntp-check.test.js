// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Live SNTPv4 round-trip against the docker-compose chrony NTP fixture.
 *
 * Exercises lib/ntp-check.js querySingle / checkDrift / bootCheck against
 * a real NTP server that's syncing from public pools. Drift should be
 * tiny (sub-second) since the container's clock and the host's clock
 * both anchor to the same upstream sources within a few seconds.
 *
 * The fixture binds host port 12300 (privileged port 123 isn't allowed
 * to bind on Windows without admin), so tests pass `port: 12300` to
 * the framework.
 */
var helpers = require("../helpers");
var check = helpers.check;
var services = require("../helpers/services");
var b = require("../../");

async function run() {
  var svc = await services.requireService("ntp");
  if (!svc.ok) throw new Error("ntp unreachable: " + svc.reason);

  // ---- querySingle: raw SNTP query, expects a non-zero drift back ----
  var single = await b.ntpCheck.querySingle("127.0.0.1", { port: 12300, timeoutMs: 4000 });
  check("querySingle: returns server name",       single.server === "127.0.0.1");
  check("querySingle: returns finite drift ms",   typeof single.driftMs === "number" && isFinite(single.driftMs));
  check("querySingle: returns serverTimeMs",       typeof single.serverTimeMs === "number" &&
                                                   single.serverTimeMs > 1700000000000);
  check("querySingle: drift is sub-minute (server is in sync)",
        Math.abs(single.driftMs) < 60000);

  // ---- checkDrift: tries servers in order, returns first success ----
  var drift = await b.ntpCheck.checkDrift({
    servers: ["127.0.0.1"],
    port:     12300,
    timeoutMs: 4000,
  });
  check("checkDrift: returns drift object",  drift && typeof drift.driftMs === "number");
  check("checkDrift: drift is sub-minute",   Math.abs(drift.driftMs) < 60000);

  // ---- bootCheck: integrates with the framework's logging policy ----
  // Set thresholds tight to prove the policy logic works on real data.
  // 60 minute fatal so it never triggers on real drift; 5 minute warn.
  var boot = await b.ntpCheck.bootCheck({
    servers:       ["127.0.0.1"],
    port:          12300,
    timeoutMs:     4000,
    driftWarnMs:   60 * 60 * 1000,
    driftFatalMs:  60 * 60 * 1000,
  });
  check("bootCheck: ok=true on healthy NTP",   boot.ok === true);
  check("bootCheck: severity is info",          boot.severity === "info");
  check("bootCheck: server is the one we asked", boot.server === "127.0.0.1");
  check("bootCheck: message references drift",  /drift/.test(boot.message));

  // ---- IPv6 path — must work because the compose file dual-binds
  //      every host port onto [::1] and SNTPv4 is address-family agnostic.
  //      A failure here is a real coverage gap, not "expected drift".
  var v6 = await b.ntpCheck.querySingle("::1", { port: 12300, timeoutMs: 4000 });
  check("querySingle v6: returned an object",
        typeof v6 === "object" && v6 !== null);
  check("querySingle v6: drift is sub-minute (server in sync)",
        typeof v6.driftMs === "number" && Math.abs(v6.driftMs) < 60000);
  check("querySingle v6: serverTimeMs is realistic (post-2024)",
        typeof v6.serverTimeMs === "number" && v6.serverTimeMs > 1700000000000);

  // The reply's source is reported as "::1"; a server written in another
  // spelling of that address still matches it.
  var v6Long = await b.ntpCheck.querySingle("0:0:0:0:0:0:0:1", { port: 12300, timeoutMs: 4000 })
    .catch(function (e) { return { _err: e }; });
  check("querySingle v6: a non-canonical IPv6 literal receives the reply",
        v6Long && typeof v6Long.driftMs === "number" && Math.abs(v6Long.driftMs) < 60000,
        v6Long && v6Long._err ? (v6Long._err.code + " :: " + v6Long._err.message) : "");

  // ---- bad host: must surface a clean error code, not a hang ----
  var badHost = await b.ntpCheck.querySingle("127.0.0.99", {
    port: 12300, timeoutMs: 1500,
  }).catch(function (e) { return { _err: e }; });
  check("querySingle: unreachable host throws ntp/timeout",
        badHost._err && badHost._err.code === "ntp/timeout");

  // ---- bad port: cleanly times out (no NTP server on this port) ----
  var badPort = await b.ntpCheck.querySingle("127.0.0.1", {
    port: 11999, timeoutMs: 1500,
  }).catch(function (e) { return { _err: e }; });
  check("querySingle: unbound port throws ntp/timeout",
        badPort._err && badPort._err.code === "ntp/timeout");

  await runNts();
}

// ---- NTS (RFC 8915) against real chrony NTS servers (cturra/ntp) ----
//
//   nts           127.0.0.1 / [::1] KE 14460, NTP 12301 (advertised in a Port record)
//   nts-gcmsiv    KE 14461, accepts only AEAD 30 (AES-128-GCM-SIV)
//   nts-unsynced  KE 14462, no reference clock: replies carry LI=3, stratum 0
//
// Each certificate chains to the stack's test CA and names nts, localhost,
// 127.0.0.1 and ::1. The runner (scripts/test-integration.js) exports that CA
// and sets NODE_EXTRA_CA_CERTS, which is how b.ntpCheck.checkDrift, which has
// no `ca` option, trusts it.
var NTS_KE_PORT          = 14460;
var NTS_GCMSIV_KE_PORT   = 14461;
var NTS_UNSYNCED_KE_PORT = 14462;
var NTS_NTP_PORT         = 12301;

function _testCa() {
  var p = process.env.BLAMEJS_TEST_CA_PATH;
  if (!p) return null;
  return require("node:fs").readFileSync(p, "utf8");
}

async function _settle(promise) {
  try { return { res: await promise }; } catch (e) { return { err: e }; }
}

function _describe(r) {
  return r.err ? (r.err.code + " :: " + r.err.message) : JSON.stringify(r.res && {
    authenticated: r.res.authenticated, aeadId: r.res.aeadId, server: r.res.server, driftMs: r.res.driftMs,
  });
}

async function runNts() {
  var nts = b.network.ntp.nts;
  var ca = _testCa();
  if (!ca) {
    helpers.unavailable("live NTS", "BLAMEJS_TEST_CA_PATH is not set; run through scripts/test-integration.js ntp-check");
    return;
  }

  // The default offer negotiates AES-SIV-CMAC-256 with chrony, follows the
  // Port record to 12301 and returns authenticated time. The KE host is an IP
  // literal with no servername, so the dial sends no SNI and the certificate
  // is checked against its IP SAN.
  var ke = await _settle(nts.performKeHandshake({ host: "127.0.0.1", port: NTS_KE_PORT, ca: ca, timeoutMs: 5000 }));
  check("nts live: KE to 127.0.0.1 with no servername completes", ke.res && ke.res.aeadId === 15, _describe(ke));
  check("nts live: chrony advertises its NTP port in a Port record", ke.res && ke.res.ntpPort === NTS_NTP_PORT,
        ke.res && String(ke.res.ntpPort));
  check("nts live: with no Server record the NTP server is the KE address",
        ke.res && ke.res.ntpServer === "127.0.0.1", ke.res && String(ke.res.ntpServer));
  check("nts live: chrony issues a pool of cookies", ke.res && ke.res.cookies.length >= 1);

  var hosts = ["127.0.0.1", "::1"];
  for (var i = 0; i < hosts.length; i++) {
    var q = await _settle(nts.query({ host: hosts[i], kePort: NTS_KE_PORT, ca: ca, timeoutMs: 5000 }));
    check("nts live: query() to " + hosts[i] + " returns authenticated time",
          q.res && q.res.authenticated === true && q.res.aeadId === 15, _describe(q));
    check("nts live: query() to " + hosts[i] + " drift is sub-minute",
          q.res && typeof q.res.driftMs === "number" && Math.abs(q.res.driftMs) < 60000, _describe(q));
  }
  // The protected query to a non-canonical spelling of ::1 matches the
  // reply's source.
  var keV6 = await _settle(nts.performKeHandshake({ host: "::1", port: NTS_KE_PORT, ca: ca, timeoutMs: 5000 }));
  var qsLong = keV6.res ? await _settle(nts.querySingle({
    host: "0:0:0:0:0:0:0:1", port: keV6.res.ntpPort, aeadId: keV6.res.aeadId,
    c2sKey: keV6.res.c2sKey, s2cKey: keV6.res.s2cKey, cookies: keV6.res.cookies, timeoutMs: 5000,
  })) : keV6;
  check("nts live: querySingle to 0:0:0:0:0:0:0:1 returns authenticated time",
        qsLong.res && qsLong.res.authenticated === true, _describe(qsLong));

  var byName = await _settle(nts.query({ host: "localhost", kePort: NTS_KE_PORT, ca: ca, timeoutMs: 5000 }));
  check("nts live: query() to localhost (SNI sent) returns authenticated time",
        byName.res && byName.res.authenticated === true, _describe(byName));

  // chrony implements no ChaCha20-Poly1305, so an offer of only that id gets
  // an empty AEAD record.
  var chachaOnly = await _settle(nts.performKeHandshake({ host: "127.0.0.1", port: NTS_KE_PORT, ca: ca,
    aead: [nts.AEAD_CHACHA20_POLY1305], timeoutMs: 5000 }));
  check("nts live: an offer of only ChaCha20-Poly1305 is refused as nts/no-aead",
        chachaOnly.err && chachaOnly.err.code === "nts/no-aead", _describe(chachaOnly));

  // The drift check end to end, IPv4 and the bracketed IPv6 endpoint form,
  // with no unauthenticated fallback.
  var endpoints = ["127.0.0.1:" + NTS_KE_PORT, "[::1]:" + NTS_KE_PORT];
  for (var e = 0; e < endpoints.length; e++) {
    var drift = await b.ntpCheck.checkDrift({ ntsServers: [endpoints[e]], requireNts: true, timeoutMs: 5000 });
    check("nts live: checkDrift requireNts via " + endpoints[e] + " is authenticated",
          drift && drift.authenticated === true && typeof drift.driftMs === "number",
          JSON.stringify(drift && { authenticated: drift.authenticated, driftMs: drift.driftMs,
            error: drift.error && (drift.error.code + " " + drift.error.message) }));
  }

  // A server whose only AEAD is AES-128-GCM-SIV (30). The client does not
  // offer 30, so chrony answers with an empty AEAD record.
  var gcm = await _settle(nts.query({ host: "localhost", kePort: NTS_GCMSIV_KE_PORT, ca: ca, timeoutMs: 5000 }));
  check("nts live: a GCM-SIV-only server is refused as nts/no-aead", gcm.err && gcm.err.code === "nts/no-aead",
        _describe(gcm));

  // An unsynchronized server's authenticated reply is not a time source.
  var unsynced = await _settle(nts.query({ host: "localhost", kePort: NTS_UNSYNCED_KE_PORT, ca: ca, timeoutMs: 5000 }));
  check("nts live: an unsynchronized server is refused as nts/unsynchronized",
        unsynced.err && unsynced.err.code === "nts/unsynchronized", _describe(unsynced));
  var unsyncedDrift = await b.ntpCheck.checkDrift({
    ntsServers: ["127.0.0.1:" + NTS_UNSYNCED_KE_PORT], requireNts: true, timeoutMs: 5000,
  });
  check("nts live: checkDrift requireNts against an unsynchronized server reports no reading",
        unsyncedDrift && unsyncedDrift.driftMs === null && unsyncedDrift.authenticated === false &&
        unsyncedDrift.error && unsyncedDrift.error.code === "nts/unsynchronized",
        JSON.stringify(unsyncedDrift && { driftMs: unsyncedDrift.driftMs,
          error: unsyncedDrift.error && unsyncedDrift.error.code }));
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
