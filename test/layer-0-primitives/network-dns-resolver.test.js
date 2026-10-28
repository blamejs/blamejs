// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.network.dns.resolver — validating stub resolver composing
 * b.safeDns. Tests use a fake transport so no real DoH traffic
 * leaves the box. Verifies TTL cache + serve-stale + CNAME chain
 * following + AD-bit surfacing + DNSSEC opt-in validate refusal.
 */

var nodeHttps = require("node:https");
var nodeNet   = require("node:net");

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var ck      = require("../helpers/compromised-keys");

// ---- Wire-format helpers (mirror safe-dns.test.js) ----

function _hdr(id, flags, qd, an, ns, ar) {
  var h = Buffer.alloc(12);
  h.writeUInt16BE(id, 0);
  h.writeUInt16BE(flags, 2);
  h.writeUInt16BE(qd, 4);
  h.writeUInt16BE(an, 6);
  h.writeUInt16BE(ns, 8);
  h.writeUInt16BE(ar, 10);
  return h;
}

function _encName(name) {
  var labels = name.split(".").filter(Boolean);
  var parts = [];
  labels.forEach(function (l) {
    var b2 = Buffer.from(l, "ascii");
    parts.push(Buffer.from([b2.length]));
    parts.push(b2);
  });
  parts.push(Buffer.from([0]));
  return Buffer.concat(parts);
}

function _q(name, qtype) {
  var nm = _encName(name);
  var tail = Buffer.alloc(4);
  tail.writeUInt16BE(qtype, 0);
  tail.writeUInt16BE(1, 2);
  return Buffer.concat([nm, tail]);
}

function _rr(name, rtype, ttl, rdata) {
  var nm = _encName(name);
  var fixed = Buffer.alloc(10);
  fixed.writeUInt16BE(rtype, 0);
  fixed.writeUInt16BE(1, 2);
  fixed.writeUInt32BE(ttl, 4);
  fixed.writeUInt16BE(rdata.length, 8);
  return Buffer.concat([nm, fixed, rdata]);
}

// adBit = true sets bit 5 of byte 3 (low byte of 16-bit flags at offset 2..3)
function _aRecordResponse(name, ip, ttl, adBit) {
  var octets = ip.split(".").map(function (s) { return parseInt(s, 10); });
  var rdata = Buffer.from(octets);
  var flags = 0x8180 | (adBit ? 0x0020 : 0);
  return Buffer.concat([
    _hdr(0, flags, 1, 1, 0, 0),
    _q(name, 1),
    _rr(name, 1, ttl, rdata),
  ]);
}

function _cnameResponse(name, target, ttl) {
  return Buffer.concat([
    _hdr(0, 0x8180, 1, 1, 0, 0),
    _q(name, 1),
    _rr(name, 5, ttl, _encName(target)),
  ]);
}

function _nxResponse(name) {
  // NXDOMAIN — RCODE 3 in flags; question echoed; zero answers.
  return Buffer.concat([
    _hdr(0, 0x8183, 1, 0, 0, 0),
    _q(name, 1),
  ]);
}

// Any other non-zero RCODE, in the same shape. RFC 1035 §4.1.1 puts the code in
// the low nibble of the flags word, so SERVFAIL (2) is 0x8182 where NXDOMAIN
// (3) is 0x8183 — one bit apart on the wire, and two entirely different
// answers: "this name does not exist" against "I could not tell you".
function _rcodeResponse(name, rcode) {
  return Buffer.concat([
    _hdr(0, 0x8180 | (rcode & 0x000f), 1, 0, 0, 0),
    _q(name, 1),
  ]);
}

// ---- Fake transport ----

function _fakeTransport(map) {
  var calls = [];
  return {
    lookup: function (name, qtype) {
      var key = name.toLowerCase() + "|" + qtype;
      calls.push({ name: name, qtype: qtype });
      if (typeof map[key] === "function") return Promise.resolve(map[key]());
      if (map[key] === "__throw__") return Promise.reject(new Error("upstream-boom"));
      return Promise.resolve(map[key] || _hdr(0, 0x8180, 1, 0, 0, 0));
    },
    _calls: calls,
  };
}

// ---- Tests ----

async function testSurface() {
  check("resolver.create is fn", typeof b.network.dns.resolver.create === "function");
  var r = b.network.dns.resolver.create({ transport: _fakeTransport({}) });
  check("instance has query",        typeof r.query === "function");
  check("instance has followCnames", typeof r.followCnames === "function");
  check("instance has queryA",       typeof r.queryA === "function");
  check("instance has queryTxt",     typeof r.queryTxt === "function");
  check("instance has clearCache",   typeof r.clearCache === "function");
  check("instance has cacheSize",    typeof r.cacheSize === "function");
}

async function testResolvesAndCaches() {
  var transport = _fakeTransport({
    "example.com|1": _aRecordResponse("example.com", "192.0.2.1", 300, false),
  });
  var r = b.network.dns.resolver.create({ transport: transport });
  var r1 = await r.queryA("example.com");
  check("first call: fromCache=false",   r1.fromCache === false);
  check("first call: stale=false",       r1.stale === false);
  check("first call: rrs has A",         r1.rrs[0].decoded === "192.0.2.1");
  check("first call: ttl in ms",         r1.ttl >= 300000);
  check("first call: validated=false",   r1.validated === false);
  check("transport called once",         transport._calls.length === 1);

  var r2 = await r.queryA("example.com");
  check("second call: fromCache=true",   r2.fromCache === true);
  check("second call: stale=false",      r2.stale === false);
  check("second call: rrs same",         r2.rrs[0].decoded === "192.0.2.1");
  check("transport NOT called again",    transport._calls.length === 1);
}

async function testSingleFlightCoalescesConcurrentMisses() {
  // N concurrent queries for the same name that all miss the cache must
  // trigger ONE upstream lookup, not a thundering herd (cache stampede).
  var resp = _aRecordResponse("example.com", "192.0.2.5", 300, false);
  var calls = 0;
  // The five queries are fired synchronously (Promise.all's array is built in
  // one tick), so all four followers hit the inflight map the winner set
  // before any microtask resolves — an immediate Promise suffices; no timer
  // sleep is needed to force the overlap.
  var transport = {
    lookup: function () {
      calls += 1;
      return Promise.resolve(resp);
    },
  };
  var r = b.network.dns.resolver.create({ transport: transport });
  var results = await Promise.all([
    r.queryA("example.com"), r.queryA("example.com"), r.queryA("example.com"),
    r.queryA("example.com"), r.queryA("example.com"),
  ]);
  check("single-flight: 5 concurrent misses trigger ONE upstream lookup", calls === 1);
  check("single-flight: all 5 callers receive the answer",
    results.every(function (x) { return x.rrs[0].decoded === "192.0.2.5"; }));
}

async function testValidateOptInRefusesAdZero() {
  var transport = _fakeTransport({
    "example.com|1": _aRecordResponse("example.com", "192.0.2.1", 300, false),
  });
  var r = b.network.dns.resolver.create({ transport: transport });
  var threw = null;
  try { await r.queryA("example.com", { validate: true }); }
  catch (e) { threw = e; }
  check("validate=true with AD=0 refused", threw && threw.code === "resolver/validate-failed");
}

async function testValidateOptInRefusesCachedAdZero() {
  // PR #58 Codex P1: a cache warmed by a non-validating call must not
  // serve to a later validate: true caller. The verdict (AD bit) is
  // per-response (RFC 4035 §3.2.3), so the cached entry's stored
  // `validated: false` must trip the validate-failed throw.
  var transport = _fakeTransport({
    "example.com|1": _aRecordResponse("example.com", "192.0.2.1", 300, false),
  });
  var r = b.network.dns.resolver.create({ transport: transport });
  await r.queryA("example.com");                   // warm cache (no validate)
  check("first call: cache size 1", r.cacheSize() === 1);
  var threw = null;
  try { await r.queryA("example.com", { validate: true }); }
  catch (e) { threw = e; }
  check("validate=true on cached AD=0 refused (cache-bypass defense)",
    threw && threw.code === "resolver/validate-failed");
}

async function testValidateOptInAcceptsAdOne() {
  var transport = _fakeTransport({
    "example.com|1": _aRecordResponse("example.com", "192.0.2.1", 300, true),
  });
  var r = b.network.dns.resolver.create({ transport: transport });
  var got = await r.queryA("example.com", { validate: true });
  check("validate=true with AD=1 succeeds", got.rrs[0].decoded === "192.0.2.1");
  check("validate=true sets validated=true", got.validated === true);
}

async function testFollowsCnameChain() {
  var transport = _fakeTransport({
    "alias.example.com|1": _cnameResponse("alias.example.com", "real.example.com", 300),
    "real.example.com|1":  _aRecordResponse("real.example.com", "192.0.2.5", 300, false),
  });
  var r = b.network.dns.resolver.create({ transport: transport });
  var got = await r.followCnames("alias.example.com", "A");
  check("followCnames: chain length 2",   got.chain.length === 2);
  check("followCnames: chain start",      got.chain[0] === "alias.example.com");
  check("followCnames: chain end",        got.chain[1] === "real.example.com");
  check("followCnames: rr.decoded",       got.rrs[0].decoded === "192.0.2.5");
}

// A CNAME target whose single label is "real.example" followed by "com" is a
// different wire name from real.example.com. The decoded target keeps the
// label boundary, and followCnames refuses it instead of querying the
// three-label name.
async function testCnameTargetWithDottedLabelIsNotFollowed() {
  var target = Buffer.concat([
    Buffer.from([12]), Buffer.from("real.example", "latin1"),
    Buffer.from([3]), Buffer.from("com", "latin1"), Buffer.from([0]),
  ]);
  var resp = Buffer.concat([
    _hdr(0, 0x8180, 1, 1, 0, 0),
    _q("alias.example.com", 1),
    _rr("alias.example.com", 5, 300, target),
  ]);
  var transport = _fakeTransport({
    "alias.example.com|1": resp,
    "alias.example.com|5": resp,
    "real.example.com|1":  _aRecordResponse("real.example.com", "192.0.2.5", 300, false),
  });
  var r = b.network.dns.resolver.create({ transport: transport });
  var c = await r.queryCname("alias.example.com");
  check("CNAME target keeps its label boundary (got " + JSON.stringify(c.rrs[0] && c.rrs[0].decoded) + ")",
    c.rrs[0].decoded === "real\\.example.com");
  var threw = null;
  try { await r.followCnames("alias.example.com", "A"); }
  catch (e) { threw = e; }
  check("followCnames refuses an escaped target with resolver/bad-input",
    threw && threw.code === "resolver/bad-input");
  check("followCnames does not query the three-label name",
    !transport._calls.some(function (cl) { return cl.name.toLowerCase() === "real.example.com"; }));
}

async function testCnameChainCap() {
  // Build a chain longer than the strict cap (8). Each hop CNAMEs to the next.
  var map = {};
  for (var i = 0; i < 20; i += 1) {
    var from = "h" + i + ".example.com";
    var to   = "h" + (i + 1) + ".example.com";
    map[from + "|1"] = _cnameResponse(from, to, 300);
  }
  var transport = _fakeTransport(map);
  var r = b.network.dns.resolver.create({ transport: transport });
  var threw = null;
  try { await r.followCnames("h0.example.com", "A"); }
  catch (e) { threw = e; }
  check("CNAME chain cap throws",  threw !== null);
  check("CNAME chain cap code",    threw && threw.code === "safe-dns/oversize-cname-depth");
}

async function testServeStaleOnUpstreamFailure() {
  // First call succeeds; second call fails; should serve stale.
  var callCount = 0;
  var transport = {
    _calls: [],
    lookup: function (name, qtype) {
      transport._calls.push({ name: name, qtype: qtype });
      callCount += 1;
      if (callCount === 1) {
        return Promise.resolve(_aRecordResponse("example.com", "192.0.2.1", 1, false));
      }
      return Promise.reject(new Error("upstream-down"));
    },
  };
  var r = b.network.dns.resolver.create({
    transport:  transport,
    minTtlMs:   1,
    maxTtlMs:   20,
    serveStale: 60000,
  });
  var r1 = await r.queryA("example.com");
  check("first call returns",          r1.rrs[0].decoded === "192.0.2.1");

  // Wait for the maxTtlMs=20 cache entry to expire.
  await helpers.passiveObserve(80, "dns-resolver: cache TTL elapsed for serve-stale test");

  var r2 = await r.queryA("example.com");
  check("serve-stale on failure",      r2.rrs[0].decoded === "192.0.2.1");
  check("serve-stale marks stale=true", r2.stale === true);
  check("serve-stale marks fromCache=true", r2.fromCache === true);
}

async function testServeStaleDoesNotBypassValidate() {
  // The `validate: true` gate (RFC 4035 §3.2.3 AD bit) must hold on the
  // serve-stale path too: a stale entry that was cached AD=0 must be
  // REFUSED for a validating caller, not returned as a silent success.
  // Otherwise an attacker who can force an upstream outage downgrades a
  // DNSSEC-strict lookup (DANE TLSA / DS) to unauthenticated stale data.
  var callCount = 0;
  var transport = {
    lookup: function (name, qtype) {
      callCount += 1;
      if (callCount === 1) {
        return Promise.resolve(_aRecordResponse("example.com", "192.0.2.1", 1, false));  // AD=0
      }
      return Promise.reject(new Error("upstream-down"));
    },
  };
  var r = b.network.dns.resolver.create({
    transport:  transport,
    minTtlMs:   1,
    maxTtlMs:   20,
    serveStale: 60000,
  });
  await r.queryA("example.com");                         // warm cache (no validate), AD=0
  await helpers.passiveObserve(80, "dns-resolver: cache TTL elapsed for stale-validate test");

  var threw = null;
  var got = null;
  try { got = await r.queryA("example.com", { validate: true }); }
  catch (e) { threw = e; }
  check("stale-serve does not bypass validate (AD=0 refused)",
    threw && threw.code === "resolver/validate-failed");
  check("stale-serve never returns an unvalidated response to a validating caller",
    got === null);
}

async function testServeStaleValidateAcceptsAdOne() {
  // Complement: a stale entry that WAS AD=1 stays acceptable to a
  // validating caller — the gate refuses AD=0, not serve-stale itself.
  var callCount = 0;
  var transport = {
    lookup: function (name, qtype) {
      callCount += 1;
      if (callCount === 1) {
        return Promise.resolve(_aRecordResponse("example.com", "192.0.2.1", 1, true));   // AD=1
      }
      return Promise.reject(new Error("upstream-down"));
    },
  };
  var r = b.network.dns.resolver.create({
    transport:  transport,
    minTtlMs:   1,
    maxTtlMs:   20,
    serveStale: 60000,
  });
  await r.queryA("example.com", { validate: true });     // warm cache, AD=1
  await helpers.passiveObserve(80, "dns-resolver: cache TTL elapsed for stale-validate-ad1 test");

  var got = await r.queryA("example.com", { validate: true });
  check("stale-serve AD=1 accepted by validating caller", got.rrs[0].decoded === "192.0.2.1");
  check("stale-serve AD=1 marks stale=true", got.stale === true);
  check("stale-serve AD=1 keeps validated=true", got.validated === true);
}

async function testServeStaleDisabled() {
  // With serveStale: false, upstream failure throws even with cache.
  var callCount = 0;
  var transport = {
    _calls: [],
    lookup: function (name, qtype) {
      callCount += 1;
      if (callCount === 1) return Promise.resolve(_aRecordResponse("example.com", "192.0.2.1", 1, false));
      return Promise.reject(new Error("upstream-down"));
    },
  };
  var r = b.network.dns.resolver.create({
    transport:  transport,
    minTtlMs:   1,
    maxTtlMs:   20,
    serveStale: false,
  });
  await r.queryA("example.com");
  // Wait for the maxTtlMs=20 cache entry to expire so the second call
  // misses the cache and hits the failing upstream.
  await helpers.passiveObserve(80, "dns-resolver: cache TTL elapsed for serveStale-false test");
  var threw = null;
  try { await r.queryA("example.com"); }
  catch (e) { threw = e; }
  check("serveStale=false: upstream-failed surfaces", threw && threw.code === "resolver/upstream-failed");
}

async function testNxdomainRefused() {
  var transport = _fakeTransport({
    "nx.example.com|1": _nxResponse("nx.example.com"),
  });
  var r = b.network.dns.resolver.create({ transport: transport });
  var threw = null;
  try { await r.queryA("nx.example.com"); }
  catch (e) { threw = e; }
  check("NXDOMAIN surfaces under its own code",
        threw && threw.code === "resolver/nxdomain", String(threw && threw.code));

  // NXDOMAIN and SERVFAIL are different answers and no longer share a code.
  // One name for both forced every caller to pick a reading, and both callers
  // picked absence: `safeResolveTxt` could not match it so the commonest form
  // of absence threw, and `b.mail.rbl` matched it and called a failed lookup
  // "not listed". Reading a failure as absence is the direction an attacker
  // wants — break the query and the policy that would have refused them is
  // gone — so the two are separated at the source.
  var servfail = _fakeTransport({
    "sf.example.com|1": _rcodeResponse("sf.example.com", 2),   // SERVFAIL
  });
  var r2 = b.network.dns.resolver.create({ transport: servfail });
  var threw2 = null;
  try { await r2.queryA("sf.example.com"); }
  catch (e) { threw2 = e; }
  check("a SERVFAIL reply surfaces as the server failure, not as absence",
        threw2 && threw2.code === "resolver/server-failure",
        String(threw2 && threw2.code));
  check("a SERVFAIL rejection is transient, so b.retry retries it",
        threw2 && threw2.permanent === false && b.retry.isRetryable(threw2) === true,
        String(threw2 && threw2.permanent));

  var refused = _fakeTransport({
    "rf.example.com|1": _rcodeResponse("rf.example.com", 5),   // REFUSED
  });
  var threw3 = null;
  try { await b.network.dns.resolver.create({ transport: refused }).queryA("rf.example.com"); }
  catch (e) { threw3 = e; }
  check("a REFUSED reply surfaces as the transient server failure",
        threw3 && threw3.code === "resolver/server-failure" && threw3.permanent === false,
        String(threw3 && threw3.code) + " permanent=" + String(threw3 && threw3.permanent));

  var formerr = _fakeTransport({
    "fe.example.com|1": _rcodeResponse("fe.example.com", 1),   // FORMERR
  });
  var threw4 = null;
  try { await b.network.dns.resolver.create({ transport: formerr }).queryA("fe.example.com"); }
  catch (e) { threw4 = e; }
  check("any other non-zero RCODE surfaces as the permanent query failure",
        threw4 && threw4.code === "resolver/query-failed" && threw4.permanent === true,
        String(threw4 && threw4.code) + " permanent=" + String(threw4 && threw4.permanent));
  check("an NXDOMAIN rejection stays permanent", threw && threw.permanent === true);
  check("an NXDOMAIN rejection is not retried by b.retry", b.retry.isRetryable(threw) === false);

  var calls = 0;
  var flaky = {
    lookup: function () {
      calls += 1;
      return Promise.resolve(calls === 1
        ? _aRecordResponse("st.example.com", "192.0.2.9", 1, false)
        : _rcodeResponse("st.example.com", 2));
    },
  };
  var rs = b.network.dns.resolver.create({ transport: flaky, minTtlMs: 1, maxTtlMs: 20, serveStale: 60000 });
  await rs.queryA("st.example.com");
  await helpers.passiveObserve(80, "dns-resolver: cache TTL elapsed for serve-stale-on-SERVFAIL test");
  var staleOnServfail = await rs.queryA("st.example.com");
  check("a SERVFAIL reply is answered from the serve-stale window like any upstream failure",
        staleOnServfail.stale === true && staleOnServfail.rrs[0].decoded === "192.0.2.9",
        JSON.stringify({ stale: staleOnServfail.stale }));
}

async function testBadInput() {
  var r = b.network.dns.resolver.create({ transport: _fakeTransport({}) });
  var threw = null;
  try { await r.query("", "A"); }
  catch (e) { threw = e; }
  check("empty name refused", threw && threw.code === "resolver/bad-input");

  var threw2 = null;
  try { await r.query("example.com", "BOGUS"); }
  catch (e) { threw2 = e; }
  check("unknown qtype refused", threw2 && threw2.code === "resolver/bad-input");
}

async function testProfileResolution() {
  var r = b.network.dns.resolver.create({ transport: _fakeTransport({}), profile: "balanced" });
  check("profile balanced", r.profile === "balanced");

  var threw = null;
  try { b.network.dns.resolver.create({ transport: _fakeTransport({}), profile: "lax" }); }
  catch (e) { threw = e; }
  check("bad profile refused", threw && threw.code === "resolver/bad-profile");
}

async function testPostureResolvesToStrict() {
  var r = b.network.dns.resolver.create({ transport: _fakeTransport({}), posture: "hipaa" });
  check("posture hipaa → strict", r.profile === "strict");
}

async function testBadTransport() {
  var threw = null;
  try { b.network.dns.resolver.create({ transport: {} }); }
  catch (e) { threw = e; }
  check("missing lookup refused", threw && threw.code === "resolver/bad-transport");
}

async function testResolverCanonicalizesTheQueryName() {
  // The resolver backs DKIM TXT, MTA-STS, DANE TLSA and BIMI discovery, and it
  // caches on the name it was handed. A U-label and its A-label are the same
  // DNS name, so handing both through must query and cache once — and the name
  // that goes upstream has to be the A-label, which is what the zone answers
  // for. Keying on the raw string instead splits one name across two entries
  // and asks for a U-label nothing will answer.
  var transport = _fakeTransport({
    "xn--caf-dma.example|1": _aRecordResponse("xn--caf-dma.example", "192.0.2.7", 300, false),
    // Answering the U-label spelling too, so the check that fails is the one
    // about WHICH name went upstream rather than a parse error on a fixture
    // the map happens not to cover.
    "café.example|1":        _aRecordResponse("xn--caf-dma.example", "192.0.2.7", 300, false),
  });
  var r = b.network.dns.resolver.create({ transport: transport });
  await r.queryA("café.example");
  check("resolver: a U-label is queried in its A-label form",
        transport._calls.length === 1 && transport._calls[0].name === "xn--caf-dma.example",
        "calls=" + JSON.stringify(transport._calls.map(function (c) { return c.name; })));
  await r.queryA("xn--caf-dma.example");
  check("resolver: both spellings share one cache entry",
        r.cacheSize() === 1 && transport._calls.length === 1,
        "cacheSize=" + r.cacheSize() + " calls=" + transport._calls.length);

  // An empty label makes the name invalid; it must be refused rather than
  // repaired into the neighbouring domain the collapse would produce.
  // Asserting the CODE, not merely that something threw: the validation lives
  // in b.network.dns, which raises its own DnsError, and this API's contract is
  // a ResolverError with a `resolver/*` code. A bare "it threw" check passes
  // either way and would let the transport's error class out through the
  // resolver's surface unnoticed.
  var bad = null;
  try { await r.queryA("evil..example"); } catch (e) { bad = e; }
  check("resolver: a name with an empty label is refused as resolver/bad-input",
        bad !== null && bad.code === "resolver/bad-input" &&
        bad.constructor.name === "ResolverError",
        bad ? "code=" + bad.code + " class=" + bad.constructor.name
            : "no throw — calls=" + transport._calls.length);
}

async function testClearCache() {
  var transport = _fakeTransport({
    "example.com|1": _aRecordResponse("example.com", "192.0.2.1", 300, false),
  });
  var r = b.network.dns.resolver.create({ transport: transport });
  await r.queryA("example.com");
  check("cache size 1", r.cacheSize() === 1);
  r.clearCache();
  check("cache size 0 after clear", r.cacheSize() === 0);
  await r.queryA("example.com");
  check("re-fetched after clear", transport._calls.length === 2);
}

async function testTtlCapping() {
  // Upstream returns TTL=999999 seconds; resolver should clamp to maxTtlMs.
  var transport = _fakeTransport({
    "example.com|1": _aRecordResponse("example.com", "192.0.2.1", 999999, false),
  });
  var r = b.network.dns.resolver.create({
    transport: transport,
    maxTtlMs:  5000,
    minTtlMs:  100,
  });
  var got = await r.queryA("example.com");
  check("TTL clamped to maxTtlMs", got.ttl <= 5000);
}

async function testTtlFloor() {
  // Upstream returns TTL=1 second; resolver should floor to minTtlMs.
  var transport = _fakeTransport({
    "example.com|1": _aRecordResponse("example.com", "192.0.2.1", 1, false),
  });
  var r = b.network.dns.resolver.create({
    transport: transport,
    minTtlMs:  30000,
  });
  var got = await r.queryA("example.com");
  check("TTL floored to minTtlMs", got.ttl >= 30000);
}

async function run() {
  await testSurface();
  await testResolvesAndCaches();
  await testSingleFlightCoalescesConcurrentMisses();
  await testValidateOptInRefusesAdZero();
  await testValidateOptInAcceptsAdOne();
  await testValidateOptInRefusesCachedAdZero();
  await testFollowsCnameChain();
  await testCnameTargetWithDottedLabelIsNotFollowed();
  await testCnameChainCap();
  await testServeStaleOnUpstreamFailure();
  await testServeStaleDoesNotBypassValidate();
  await testServeStaleValidateAcceptsAdOne();
  await testServeStaleDisabled();
  await testNxdomainRefused();
  await testBadInput();
  await testProfileResolution();
  await testPostureResolvesToStrict();
  await testBadTransport();
  await testResolverCanonicalizesTheQueryName();
  await testClearCache();
  await testTtlCapping();
  await testTtlFloor();
  await testSafeResolveTxtTreatsAbsenceAsAbsence();
  await testUpstreamFailureClassification();
}

function _questionName(query) {
  var labels = [];
  var off = 12;
  while (query[off] !== 0) {
    labels.push(query.toString("ascii", off + 1, off + 1 + query[off]));
    off += query[off] + 1;
  }
  return labels.join(".");
}

function _startStatusDoh(chain) {
  var server = nodeHttps.createServer({ key: chain.key, cert: chain.cert }, function (req, res) {
    var u = new URL(req.url, "https://localhost");
    var name = _questionName(Buffer.from(u.searchParams.get("dns"), "base64url"));
    var status = { "notfound.example.com": 404, "forbidden.example.com": 403,
      "limited.example.com": 429, "unavailable.example.com": 503 }[name];
    if (status) { res.statusCode = status; res.end("no"); return; }
    res.setHeader("content-type", "application/dns-message");
    if (name === "big.example.com") { res.end(Buffer.alloc(70000)); return; }
    res.end(_aRecordResponse(name, "192.0.2.44", 60, false));
  });
  server.on("tlsClientError", function () { /* the client refused the chain */ });
  return new Promise(function (resolve) {
    server.listen(0, "127.0.0.1", function () { resolve(server); });
  });
}

function _closedPort() {
  return new Promise(function (resolve) {
    var probe = nodeNet.createServer();
    probe.listen(0, "127.0.0.1", function () {
      var port = probe.address().port;
      probe.close(function () { resolve(port); });
    });
  });
}

async function _rejection(promise) {
  try { await promise; return { code: "no-throw" }; }
  catch (e) { return { code: e && e.code, permanent: e && e.permanent, statusCode: e && e.statusCode, error: e }; }
}

async function testUpstreamFailureClassification() {
  var chain = ck.tlsChain("control");
  var server = await _startStatusDoh(chain);
  var dns = b.network.dns;
  dns._resetForTest();
  dns.useDnsOverHttps({ url: "https://127.0.0.1:" + server.address().port + "/dns-query", ca: chain.rootCa });
  try {
    var r = dns.resolver.create({ serveStale: false });
    var ok = await r.queryA("ok.example.com");
    check("resolver (DoH): an answer is returned", ok.rrs[0].decoded === "192.0.2.44");
    var cases = [
      ["HTTP 404",             "notfound.example.com",    "resolver/upstream-rejected",  true,  404],
      ["HTTP 403",             "forbidden.example.com",   "resolver/upstream-rejected",  true,  403],
      ["HTTP 429",             "limited.example.com",     "resolver/upstream-http",      false, 429],
      ["HTTP 503",             "unavailable.example.com", "resolver/upstream-http",      false, 503],
      ["a reply over 64 KiB",  "big.example.com",         "resolver/upstream-too-large", true,  undefined],
    ];
    for (var i = 0; i < cases.length; i++) {
      var c = cases[i];
      var got = await _rejection(r.queryA(c[1]));
      check("resolver (DoH): " + c[0] + " rejects with " + c[2] + " (got " + got.code + ")", got.code === c[2]);
      check("resolver (DoH): " + c[0] + " has permanent=" + c[3] + " (got " + got.permanent + ")",
            got.permanent === c[3]);
      check("resolver (DoH): b.retry.isRetryable is " + !c[3] + " for " + c[0],
            got.error !== undefined && b.retry.isRetryable(got.error) === !c[3]);
      if (c[4] !== undefined) {
        check("resolver (DoH): " + c[0] + " carries statusCode " + c[4] + " (got " + got.statusCode + ")",
              got.statusCode === c[4]);
      }
    }

    var port = await _closedPort();
    dns.useDnsOverHttps({ url: "https://127.0.0.1:" + port + "/dns-query", ca: chain.rootCa });
    var refused = await _rejection(dns.resolver.create({ serveStale: false }).queryA("ok.example.com"));
    check("resolver (DoH): a refused connection rejects with the transient resolver/upstream-connection-failed " +
          "(got " + refused.code + ", permanent=" + refused.permanent + ")",
          refused.code === "resolver/upstream-connection-failed" && refused.permanent === false &&
          b.retry.isRetryable(refused.error) === true);
  } finally {
    server.close();
    if (typeof server.closeAllConnections === "function") server.closeAllConnections();
    dns._resetForTest();
  }

  function custom(lookup, timeoutMs) {
    return dns.resolver.create({ serveStale: false, timeoutMs: timeoutMs || 2000, transport: { lookup: lookup } });
  }
  var operatorBug = await _rejection(custom(function () {
    return Promise.reject(new TypeError("x is undefined"));
  }).queryA("a.example.com"));
  check("resolver (custom transport): an error that is not a network failure rejects with the permanent " +
        "resolver/upstream-failed (got " + operatorBug.code + ", permanent=" + operatorBug.permanent + ")",
        operatorBug.code === "resolver/upstream-failed" && operatorBug.permanent === true &&
        b.retry.isRetryable(operatorBug.error) === false);

  var reset = await _rejection(custom(function () {
    var e = new Error("socket hang up");
    e.code = "ECONNRESET";
    return Promise.reject(e);
  }).queryA("a.example.com"));
  check("resolver (custom transport): an ECONNRESET rejects with the transient " +
        "resolver/upstream-connection-failed (got " + reset.code + ", permanent=" + reset.permanent + ")",
        reset.code === "resolver/upstream-connection-failed" && reset.permanent === false);

  var hung = await _rejection(custom(function () { return new Promise(function () { /* never settles */ }); }, 50)
    .queryA("a.example.com"));
  check("resolver (custom transport): a transport that does not answer within timeoutMs rejects with the " +
        "transient resolver/upstream-timeout (got " + hung.code + ", permanent=" + hung.permanent + ")",
        hung.code === "resolver/upstream-timeout" && hung.permanent === false);

  var http503 = await _rejection(custom(function () {
    var e = new Error("upstream answered 503");
    e.statusCode = 503;
    return Promise.reject(e);
  }).queryA("a.example.com"));
  check("resolver (custom transport): an error carrying statusCode 503 rejects with the transient " +
        "resolver/upstream-http (got " + http503.code + ")",
        http503.code === "resolver/upstream-http" && http503.permanent === false && http503.statusCode === 503);

  var rethrown = [
    ["dns/server-failure", "resolver/server-failure"],
    ["dns/lookup-timeout", "resolver/upstream-timeout"],
  ];
  for (var ri = 0; ri < rethrown.length; ri++) {
    var dnsCode = rethrown[ri][0];
    var resolverCode = rethrown[ri][1];
    var mapped = await _rejection(custom(function () {
      return Promise.reject(new dns.DnsError(dnsCode, "rethrown from b.network.dns"));
    }).queryA("a.example.com"));
    check("resolver (custom transport): a rethrown " + dnsCode + " rejects with the transient " + resolverCode +
          " (got " + mapped.code + ", permanent=" + mapped.permanent + ")",
          mapped.code === resolverCode && mapped.permanent === false && b.retry.isRetryable(mapped.error) === true);
  }
}

// `safeResolveTxt` documents itself as the policy-fetch convention where
// absence is not an error, and for the commonest form of absence it threw. Its
// guard listed ENOTFOUND and ENODATA — the codes node's stub resolver uses — so
// the convention held for an operator-supplied `dnsLookup` and not for the
// resolver the module ships with, whose NXDOMAIN carries its own code.
async function testSafeResolveTxtTreatsAbsenceAsAbsence() {
  var absent = _fakeTransport({ "none.example.com|16": _nxResponse("none.example.com") });
  var r = b.network.dns.resolver.create({ transport: absent });
  var threw = null, out;
  try {
    out = await b.network.dns.resolver.safeResolveTxt("none.example.com", {
      dnsLookup: function (n) { return r.queryTxt(n).then(function () { return []; }); },
    });
  } catch (e) { threw = e; }
  // Driven through the shipped resolver rather than a stub, because the whole
  // defect was that the two report absence differently.
  var direct = null, directThrew = null;
  try { direct = await b.network.dns.resolver.safeResolveTxt("none.example.com", {
    dnsLookup: function (n) { return r.queryTxt(n); },
  }); } catch (e) { directThrew = e; }
  check("safeResolveTxt returns null when the name does not exist",
        direct === null && directThrew === null,
        String(directThrew && directThrew.code));

  // CONTROL: a lookup that FAILED is not a record that is absent, and must
  // still throw — returning null there would let anyone who can break the query
  // delete the policy that would have refused them.
  var broken = _fakeTransport({ "sf2.example.com|16": _rcodeResponse("sf2.example.com", 2) });
  var r2 = b.network.dns.resolver.create({ transport: broken });
  var failThrew = null;
  try {
    await b.network.dns.resolver.safeResolveTxt("sf2.example.com", {
      dnsLookup: function (n) { return r2.queryTxt(n); },
    });
  } catch (e) { failThrew = e; }
  check("CONTROL — but a SERVFAIL still throws rather than reading as absence",
        failThrew !== null, String(failThrew && failThrew.code));
  void threw; void out;
}

module.exports = { run: run };

if (require.main === module) run().catch(function (e) {
  process.stderr.write("FAIL: " + (e && e.stack || e) + "\n");
  process.exit(1);
});
