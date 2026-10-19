// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var helpers = require("../helpers");
var b      = helpers.b;
var check  = helpers.check;
var _mockReq = helpers._mockReq;
var _mockRes = helpers._mockRes;

async function run() {
  check("middleware.networkAllowlist is fn",  typeof b.middleware.networkAllowlist === "function");

  // ---- Validation ----
  var threwNoPaths = null;
  try { b.middleware.networkAllowlist({ allowedCidrs: ["127.0.0.0/8"] }); }
  catch (e) { threwNoPaths = e; }
  check("create: rejects missing paths",      threwNoPaths !== null);

  var threwNoCidrs = null;
  try { b.middleware.networkAllowlist({ paths: ["/admin"] }); }
  catch (e) { threwNoCidrs = e; }
  check("create: rejects missing allowedCidrs", threwNoCidrs !== null);

  var threwBadCidr = null;
  try { b.middleware.networkAllowlist({ paths: ["/admin"], allowedCidrs: ["nope"] }); }
  catch (e) { threwBadCidr = e; }
  check("create: rejects malformed CIDR",     threwBadCidr !== null);

  var threwBadPath = null;
  try { b.middleware.networkAllowlist({ paths: ["admin"], allowedCidrs: ["10.0.0.0/8"] }); }
  catch (e) { threwBadPath = e; }
  check("create: rejects path missing leading /", threwBadPath !== null);

  // ---- Behaviour ----
  var fence = b.middleware.networkAllowlist({
    paths:        ["/admin", "/healthz/internal"],
    allowedCidrs: ["10.0.0.0/8", "127.0.0.0/8"],
    audit:        b.audit,
  });

  function _runMw(mw, req) {
    return new Promise(function (resolve) {
      var res = _mockRes();
      var nextCalled = false;
      var maybe = mw(req, res, function () { nextCalled = true; resolve({ res: res, next: true }); });
      if (maybe && typeof maybe.then === "function") maybe.then(function () {
        // synchronous path may have already resolved
      });
      // Allow microtask flush so async middleware completes.
      setImmediate(function () {
        if (nextCalled) return;
        resolve({ res: res, next: false });
      });
    });
  }

  // Request from allowed CIDR (127.0.0.1) to admin path → next() called
  var req1 = _mockReq({ url: "/admin/dashboard", method: "GET" });
  req1.pathname = "/admin/dashboard";
  req1.socket = { remoteAddress: "127.0.0.1" };
  var r1 = await _runMw(fence, req1);
  check("allowed IP + gated path → next()",     r1.next === true);

  // Request from disallowed CIDR (192.168.x.x) to admin → 404 (default denyStatus)
  var req2 = _mockReq({ url: "/admin/dashboard", method: "GET" });
  req2.pathname = "/admin/dashboard";
  req2.socket = { remoteAddress: "192.168.1.50" };
  var r2 = await _runMw(fence, req2);
  check("disallowed IP + gated path → blocked",   r2.next === false);
  check("disallowed IP + gated path → 404",       r2.res._captured().status === 404);

  // Request to NON-gated path passes regardless of IP
  var req3 = _mockReq({ url: "/public", method: "GET" });
  req3.pathname = "/public";
  req3.socket = { remoteAddress: "192.168.1.50" };
  var r3 = await _runMw(fence, req3);
  check("non-gated path → next() regardless of IP", r3.next === true);

  // Boundary check — /administer must NOT match /admin
  var req4 = _mockReq({ url: "/administer", method: "GET" });
  req4.pathname = "/administer";
  req4.socket = { remoteAddress: "192.168.1.50" };
  var r4 = await _runMw(fence, req4);
  check("/administer not gated by /admin prefix",  r4.next === true);

  // Custom denyStatus / denyBody
  var fence403 = b.middleware.networkAllowlist({
    paths:        ["/admin"],
    allowedCidrs: ["10.0.0.0/8"],
    denyStatus:   403,
    denyBody:     "Forbidden",
  });
  var req5 = _mockReq({ url: "/admin", method: "GET" });
  req5.pathname = "/admin";
  req5.socket = { remoteAddress: "192.168.1.1" };
  var r5 = await _runMw(fence403, req5);
  check("custom denyStatus = 403",                  r5.res._captured().status === 403);

  // ---- X-Forwarded-For spoofing (CWE-290/348) ----
  // A bare trustProxy honored the leftmost XFF hop, which a direct caller
  // fully controls — forging an allowed IP walked through the gate. The gate
  // now refuses that spoofable config at construction and peer-gates XFF.

  // Construction fails closed: trustProxy without trustedProxies/resolver.
  var threwBareTrust = null;
  try { b.middleware.networkAllowlist({ paths: ["/admin"], allowedCidrs: ["203.0.113.0/24"], trustProxy: true }); }
  catch (e) { threwBareTrust = e; }
  check("create: bare trustProxy refused (spoofable gate)", threwBareTrust !== null);
  var threwBareNum = null;
  try { b.middleware.networkAllowlist({ paths: ["/admin"], allowedCidrs: ["203.0.113.0/24"], trustProxy: 1 }); }
  catch (e) { threwBareNum = e; }
  check("create: bare trustProxy:N refused too",            threwBareNum !== null);
  var threwBadResolver = null;
  try { b.middleware.networkAllowlist({ paths: ["/admin"], allowedCidrs: ["203.0.113.0/24"], clientIpResolver: 123 }); }
  catch (e) { threwBadResolver = e; }
  check("create: non-function clientIpResolver refused",    threwBadResolver !== null);

  function _xffReq(sock, xff) {
    var rq = _mockReq({ url: "/admin/x", method: "GET" });
    rq.pathname = "/admin/x";
    rq.socket = { remoteAddress: sock };
    rq.headers["x-forwarded-for"] = xff;
    return rq;
  }

  // Peer-gated via trustedProxies.
  var pgFence = b.middleware.networkAllowlist({
    paths:          ["/admin"],
    allowedCidrs:   ["203.0.113.0/24"],
    trustedProxies: ["10.0.0.0/8"],
  });
  // Direct attacker (untrusted peer) forging an allowed IP → DENIED.
  var rSpoof = await _runMw(pgFence, _xffReq("198.51.100.66", "203.0.113.7"));
  check("spoofed XFF from untrusted peer → blocked",    rSpoof.next === false);
  // Trusted proxy forwarding a real allowed client → allowed.
  var rTrusted = await _runMw(pgFence, _xffReq("10.0.0.9", "203.0.113.7"));
  check("trusted proxy + allowed client → next()",      rTrusted.next === true);
  // Trusted proxy forwarding a non-allowed client → blocked (real IP honored).
  var rTrustedBad = await _runMw(pgFence, _xffReq("10.0.0.9", "198.51.100.66"));
  check("trusted proxy + non-allowed client → blocked", rTrustedBad.next === false);

  // clientIpResolver: operator owns resolution entirely.
  var resFence = b.middleware.networkAllowlist({
    paths:            ["/admin"],
    allowedCidrs:     ["203.0.113.0/24"],
    clientIpResolver: function (rq) { return rq.headers["true-client-ip"]; },
  });
  var resReq = _mockReq({ url: "/admin/x", method: "GET" });
  resReq.pathname = "/admin/x";
  resReq.socket = { remoteAddress: "1.2.3.4" };
  resReq.headers["true-client-ip"] = "203.0.113.50";
  var rRes = await _runMw(resFence, resReq);
  check("clientIpResolver resolves allowed client → next()", rRes.next === true);

  // Default (no trust config): socket address governs, forged XFF ignored.
  var defFence = b.middleware.networkAllowlist({ paths: ["/admin"], allowedCidrs: ["203.0.113.0/24"] });
  var rDefSpoof = await _runMw(defFence, _xffReq("198.51.100.66", "203.0.113.7"));
  check("default: forged XFF ignored, attacker socket blocked", rDefSpoof.next === false);

  await testEverySpellingOfADeniedAddressIsDenied(_runMw);
  await testAMappedEntryOrPeerMatchesItsIpv4Form(_runMw);
  testAMalformedCidrIsRefusedAtConstruction();
  await testADualStackListenerDeniesAnIpv4Client();
}

function _peerReq(addr) {
  var rq = _mockReq({ url: "/admin/x", method: "GET" });
  rq.pathname = "/admin/x";
  rq.socket = { remoteAddress: addr };
  return rq;
}

// A dual-stack listener reports an IPv4 client as ::ffff:a.b.c.d, and NAT64
// (64:ff9b::/96) and 6to4 (2002::/16) addresses carry an IPv4 address too.
// Each is the denied address, so each is denied.
async function testEverySpellingOfADeniedAddressIsDenied(_runMw) {
  var fence = b.middleware.networkAllowlist({
    paths:        ["/admin"],
    allowedCidrs: ["0.0.0.0/0", "::/0"],
    deniedCidrs:  ["10.0.0.0/8"],
  });
  var spellings = ["10.0.0.1", "::ffff:10.0.0.1", "::FFFF:10.0.0.1", "::ffff:a00:1",
                   "0:0:0:0:0:ffff:a00:1", "64:ff9b::a00:1", "2002:a00:1::1"];
  for (var i = 0; i < spellings.length; i++) {
    var r = await _runMw(fence, _peerReq(spellings[i]));
    check("deniedCidrs 10.0.0.0/8 denies the peer " + spellings[i], r.next === false);
  }
  var rOther = await _runMw(fence, _peerReq("::ffff:11.0.0.1"));
  check("deniedCidrs 10.0.0.0/8 passes the mapped peer 11.0.0.1", rOther.next === true);
  var rV6 = await _runMw(fence, _peerReq("2001:db8::1"));
  check("deniedCidrs 10.0.0.0/8 passes an unrelated IPv6 peer", rV6.next === true);

  var mappedDeny = b.middleware.networkAllowlist({
    paths:        ["/admin"],
    allowedCidrs: ["0.0.0.0/0", "::/0"],
    deniedCidrs:  ["::ffff:10.0.0.0/104"],
  });
  var rPlain = await _runMw(mappedDeny, _peerReq("10.0.0.1"));
  check("deniedCidrs ::ffff:10.0.0.0/104 denies the IPv4 peer 10.0.0.1", rPlain.next === false);
}

async function testAMappedEntryOrPeerMatchesItsIpv4Form(_runMw) {
  var v4Allow = b.middleware.networkAllowlist({ paths: ["/admin"], allowedCidrs: ["10.0.0.0/8"] });
  var rMapped = await _runMw(v4Allow, _peerReq("::ffff:10.0.0.1"));
  check("allowedCidrs 10.0.0.0/8 admits the dual-stack peer ::ffff:10.0.0.1", rMapped.next === true);
  var rNat64 = await _runMw(v4Allow, _peerReq("64:ff9b::a00:1"));
  check("allowedCidrs 10.0.0.0/8 does not admit the NAT64 peer 64:ff9b::a00:1", rNat64.next === false);

  var mappedAllow = b.middleware.networkAllowlist({ paths: ["/admin"], allowedCidrs: ["::ffff:10.0.0.0/104"] });
  var rPlain = await _runMw(mappedAllow, _peerReq("10.0.0.1"));
  check("allowedCidrs ::ffff:10.0.0.0/104 admits the IPv4 peer 10.0.0.1", rPlain.next === true);
  var rOut = await _runMw(mappedAllow, _peerReq("11.0.0.1"));
  check("allowedCidrs ::ffff:10.0.0.0/104 does not admit 11.0.0.1", rOut.next === false);
}

function testAMalformedCidrIsRefusedAtConstruction() {
  var bad = ["10.0.0.0/33", "10.0.0/8", "010.0.0.0/8", "10.0.0.0/8x", "10.0.0.0/08",
             "10.0.0.0/", "/8", "10.0.0.1", "::/129", "10.0.0.0/-1", " 10.0.0.0/8", "", 42, null];
  ["deniedCidrs", "allowedCidrs"].forEach(function (field) {
    for (var i = 0; i < bad.length; i++) {
      var o = { paths: ["/admin"], allowedCidrs: ["10.0.0.0/8"] };
      o[field] = [bad[i]];
      var code = null;
      try { b.middleware.networkAllowlist(o); } catch (e) { code = e.code; }
      check(field + " " + JSON.stringify(bad[i]) + " is refused with network-allowlist/bad-opt",
            code === "network-allowlist/bad-opt", String(code));
    }
  });
  var notArray = null;
  try {
    b.middleware.networkAllowlist({ paths: ["/admin"], allowedCidrs: ["0.0.0.0/0"], deniedCidrs: "10.0.0.0/8" });
  } catch (e) { notArray = e.code; }
  check("deniedCidrs given as a bare string is refused rather than ignored",
        notArray === "network-allowlist/bad-opt", String(notArray));
}

// The real listener path: on "::" with IPv6-only off, Node reports an IPv4
// client's address as ::ffff:127.0.0.1.
async function testADualStackListenerDeniesAnIpv4Client() {
  var http = require("node:http");
  var seen = null;
  var fence = b.middleware.networkAllowlist({
    paths:        ["/admin"],
    allowedCidrs: ["0.0.0.0/0", "::/0"],
    deniedCidrs:  ["127.0.0.0/8"],
  });
  var server = http.createServer(function (req, res) {
    seen = req.socket.remoteAddress;
    fence(req, res, function () { res.writeHead(200); res.end("passed"); });
  });
  try {
    await new Promise(function (resolve, reject) {
      server.once("error", reject);
      server.listen({ host: "::", port: 0, ipv6Only: false }, resolve);
    });
  } catch (e) {
    helpers.unavailable("network-allowlist dual-stack listener", "cannot listen on :: (" + e.code + ")");
    return;
  }
  try {
    var port = server.address().port;
    var status;
    try {
      status = await new Promise(function (resolve, reject) {
        var rq = http.get({ host: "127.0.0.1", port: port, path: "/admin/x", agent: false }, function (res) {
          res.resume();
          res.on("end", function () { resolve(res.statusCode); });
        });
        rq.on("error", reject);
      });
    } catch (e) {
      helpers.unavailable("network-allowlist dual-stack listener", "IPv4 connect to :: refused (" + e.code + ")");
      return;
    }
    check("the dual-stack listener reported the IPv4 client in its mapped form",
          typeof seen === "string" && seen.toLowerCase().indexOf("::ffff:") === 0, String(seen));
    check("deniedCidrs 127.0.0.0/8 denies an IPv4 client of a dual-stack listener",
          status === 404, String(status));
  } finally {
    await new Promise(function (resolve) { server.close(function () { resolve(); }); });
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[network-allowlist] OK"); },
    function (e) { console.error(e); process.exit(1); }
  );
}
