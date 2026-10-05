// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.router.create({ tls0Rtt }) — RFC 8446 §8 / RFC 8470 anti-replay
 * posture surface tests.
 *
 * Validates that:
 *   - tls0Rtt defaults to "refuse"
 *   - tls0Rtt accepts "refuse" / "replay-cache" only
 *   - replay-cache fail-closes under pci-dss / fapi2 postures
 *   - Early-Data: 1 inbound requests are gated per posture
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function _mockReq(method, url, headers) {
  return {
    method:  method || "POST",
    url:     url    || "/",
    headers: headers || {},
  };
}

function testCreateDefaultsToRefuse() {
  var r = b.router.create();
  check("router.create() defaults tls0Rtt to 'refuse'",
        r.tls0RttPosture() === "refuse");
}

function testCreateRefusesUnknownPosture() {
  var threw = null;
  try { b.router.create({ tls0Rtt: "allow-everything" }); }
  catch (e) { threw = e; }
  check("router.create({ tls0Rtt: 'allow-everything' }) throws TypeError",
        threw instanceof TypeError);
}

function testCreateAcceptsValidPostures() {
  var refuse = b.router.create({ tls0Rtt: "refuse" });
  var replay = b.router.create({ tls0Rtt: "replay-cache" });
  check("router.create accepts 'refuse'", refuse.tls0RttPosture() === "refuse");
  check("router.create accepts 'replay-cache'", replay.tls0RttPosture() === "replay-cache");
}

function testRefusePostureRejectsEarlyData() {
  var r = b.router.create({ tls0Rtt: "refuse" });
  var verdict = r._check0RttReplay(_mockReq("POST", "/api/charge",
    { "early-data": "1" }));
  check("refuse posture refuses Early-Data: 1 with 425",
        verdict && verdict.status === 425 && verdict.reason === "early-data-refused");
}

function testRefusePostureAllowsNonEarlyData() {
  var r = b.router.create({ tls0Rtt: "refuse" });
  var verdict = r._check0RttReplay(_mockReq("POST", "/api/charge", {}));
  check("refuse posture allows non-Early-Data request",
        verdict === null);
}

function testReplayCacheAdmitsFirstRequest() {
  var r = b.router.create({ tls0Rtt: "replay-cache" });
  var verdict = r._check0RttReplay(_mockReq("POST", "/api/charge",
    { "early-data": "1", host: "api.example.com",
      authorization: "Bearer abc", date: "Fri, 01 Jan 2026 00:00:00 GMT" }));
  check("replay-cache admits first Early-Data: 1 request",
        verdict === null);
}

function testReplayCacheRefusesSecondIdentical() {
  var r = b.router.create({ tls0Rtt: "replay-cache" });
  var headers = { "early-data": "1", host: "api.example.com",
                  authorization: "Bearer abc", date: "Fri, 01 Jan 2026 00:00:00 GMT" };
  r._check0RttReplay(_mockReq("POST", "/api/charge", headers));
  var second = r._check0RttReplay(_mockReq("POST", "/api/charge", headers));
  check("replay-cache refuses identical-bytes replay with 425",
        second && second.status === 425 && second.reason === "early-data-replay");
}

function testReplayCacheDistinguishesDifferentRequests() {
  var r = b.router.create({ tls0Rtt: "replay-cache" });
  r._check0RttReplay(_mockReq("POST", "/api/charge",
    { "early-data": "1", "idempotency-key": "key-1" }));
  var second = r._check0RttReplay(_mockReq("POST", "/api/charge",
    { "early-data": "1", "idempotency-key": "key-2" }));
  check("replay-cache admits different idempotency-keyed requests",
        second === null);
}

// The replay key must be computed from the same canonical target the router
// dispatches, so a replay that only varies the leading-slash run (which the
// router normalizes to the same path) cannot mint a fresh key and slip through
// the window.
function testReplayCacheCanonicalizesLeadingSlashes() {
  var r = b.router.create({ tls0Rtt: "replay-cache" });
  var headers = { "early-data": "1", host: "api.example.com" };
  // First Early-Data request for /api/charge is admitted + cached.
  var first = r._check0RttReplay(_mockReq("POST", "/api/charge", headers));
  check("replay-cache admits the first /api/charge Early-Data", first === null);
  // "//api/charge" routes to the SAME endpoint, so it must hit the same key.
  var replayDouble = r._check0RttReplay(_mockReq("POST", "//api/charge", headers));
  check("replay-cache: //api/charge is caught as a replay of /api/charge (canonical key)",
        replayDouble && replayDouble.status === 425 && replayDouble.reason === "early-data-replay");
  // A triple-slash variant too.
  var replayTriple = r._check0RttReplay(_mockReq("POST", "///api/charge", headers));
  check("replay-cache: ///api/charge is also caught as a replay",
        replayTriple && replayTriple.status === 425 && replayTriple.reason === "early-data-replay");
}

function testReplayCacheFailClosesUnderPciDss() {
  var compliance = b.compliance;
  var prior = null;
  try { prior = compliance.current ? compliance.current() : null; } catch (_e) {}
  if (prior) {
    // Posture is sticky once set; can't toggle in a test. Skip.
    check("replay-cache fail-close under pci-dss (skipped: posture already set to '" +
          prior + "')", true);
    return;
  }
  try { compliance.set("pci-dss"); }
  catch (e) {
    check("replay-cache fail-close under pci-dss (skipped: " + e.message + ")", true);
    return;
  }
  try {
    var r = b.router.create({ tls0Rtt: "replay-cache" });
    var posture = r._effective0RttPosture();
    check("replay-cache → refuse under pci-dss posture",
          posture === "refuse");
  } finally {
    try { if (typeof compliance.clear === "function") compliance.clear(); }
    catch (_e) { /* clear best-effort */ }
  }
}

async function run() {
  testCreateDefaultsToRefuse();
  testCreateRefusesUnknownPosture();
  testCreateAcceptsValidPostures();
  testRefusePostureRejectsEarlyData();
  testRefusePostureAllowsNonEarlyData();
  testReplayCacheAdmitsFirstRequest();
  testReplayCacheRefusesSecondIdentical();
  testReplayCacheDistinguishesDifferentRequests();
  testReplayCacheCanonicalizesLeadingSlashes();
  testReplayCacheFailClosesUnderPciDss();
  testEarlyDataAuditRecordsTheRouteNotTheCapability();
}

// The 0-RTT check runs from `listen()` before `handle()` matches a route, so
// `req.routePattern` is unset and resolving the target falls back to the
// concrete path. A capability sitting in a path segment therefore reached the
// signed audit chain, which cannot be redacted after the fact. The router has
// its own route table at this point, so the record can name the registered
// route instead.
function testEarlyDataAuditRecordsTheRouteNotTheCapability() {
  var auditMod = require("../../lib/audit");
  var SECRET = "RESETCAP0123456789abcdef";
  var realSafeEmit = auditMod.safeEmit;
  var captured = [];
  auditMod.safeEmit = function (ev) { captured.push(ev); };
  try {
    var r = b.router.create({ tls0Rtt: "replay-cache" });
    r.get("/reset/:token", function (req, res) { res.end("ok"); });
    r._check0RttReplay(_mockReq("GET", "/reset/" + SECRET + "?next=/account",
      { "early-data": "1", host: "api.example.com" }));
    check("an early-data request is audited", captured.length >= 1, "none captured");
    var blob = JSON.stringify(captured);
    check("  and the record carries no capability out of the path",
      blob.indexOf(SECRET) === -1, blob.slice(0, 400));
    check("  nor the query string",
      blob.indexOf("next=/account") === -1, blob.slice(0, 400));
    check("  naming the registered route instead",
      blob.indexOf("/reset/:token") !== -1, blob.slice(0, 400));

    // A path no route claims still must not carry the capability.
    captured.length = 0;
    r._check0RttReplay(_mockReq("GET", "/nothing/" + SECRET,
      { "early-data": "1", host: "api.example.com" }));
    var unrouted = JSON.stringify(captured);
    check("an unrouted early-data path is audited without the capability",
      captured.length >= 1 && unrouted.indexOf(SECRET) === -1,
      unrouted.slice(0, 400));

    // `handle` canonicalizes the target before it matches, so a request whose
    // path differs only in its leading-slash run reaches the same route. The
    // record has to read the same pathname `handle` will, or it names
    // `(unrouted)` for a request that routes, and resolves a `%2F` the request
    // itself is refused for.
    captured.length = 0;
    r._check0RttReplay(_mockReq("GET", "//reset/" + SECRET,
      { "early-data": "1", host: "api.example.com" }));
    var doubled = JSON.stringify(captured);
    check("a target handle canonicalizes resolves to the route it will reach",
      captured.length >= 1 && doubled.indexOf("/reset/:token") !== -1 &&
      doubled.indexOf(SECRET) === -1, doubled.slice(0, 400));

    captured.length = 0;
    r._check0RttReplay(_mockReq("GET", "/reset%2F" + SECRET,
      { "early-data": "1", host: "api.example.com" }));
    var encoded = JSON.stringify(captured);
    check("an encoded separator resolves to no route, as the request is refused",
      captured.length >= 1 && encoded.indexOf("/reset/:token") === -1 &&
      encoded.indexOf(SECRET) === -1, encoded.slice(0, 400));

    // Dispatch skips a route whose method does not match before it compares the
    // path, so a record resolved from the path alone can name a route the
    // request would never reach.
    captured.length = 0;
    var byMethod = b.router.create({ tls0Rtt: "replay-cache" });
    byMethod.get("/users/:id", function (req, res) { res.end("ok"); });
    byMethod.post("/users/invite", function (req, res) { res.end("ok"); });
    byMethod._check0RttReplay(_mockReq("POST", "/users/invite",
      { "early-data": "1", host: "api.example.com" }));
    var methodBlob = JSON.stringify(captured);
    check("the record names the route the method would reach",
      captured.length >= 1 && methodBlob.indexOf("/users/invite") !== -1 &&
      methodBlob.indexOf("/users/:id") === -1, methodBlob.slice(0, 400));

    // And a path that matches only under another method reaches no route.
    captured.length = 0;
    byMethod._check0RttReplay(_mockReq("DELETE", "/users/42",
      { "early-data": "1", host: "api.example.com" }));
    var wrongMethod = JSON.stringify(captured);
    check("a path no route claims under this method records no pattern",
      captured.length >= 1 && wrongMethod.indexOf("/users/:id") === -1,
      wrongMethod.slice(0, 400));

    // The refuse posture audits on a different branch, with the same problem.
    captured.length = 0;
    var refuse = b.router.create({ tls0Rtt: "refuse" });
    refuse.get("/reset/:token", function (req, res) { res.end("ok"); });
    refuse._check0RttReplay(_mockReq("GET", "/reset/" + SECRET,
      { "early-data": "1", host: "api.example.com" }));
    var refusedBlob = JSON.stringify(captured);
    check("the refuse posture's record carries no capability either",
      captured.length >= 1 && refusedBlob.indexOf(SECRET) === -1,
      refusedBlob.slice(0, 400));
  } finally {
    auditMod.safeEmit = realSafeEmit;
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[router-tls0rtt] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
