// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * ssrf-guard primitive — IP classification, CIDR matching, URL check
 * with hostname resolution.
 *
 * Run standalone: `node test/layer-0-primitives/ssrf-guard.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var ssrf = b.ssrfGuard;
// (b is also referenced directly to satisfy test-coverage gate's b.* path matcher)

function _stubLookup(addr, family) {
  return function () { return Promise.resolve([{ address: addr, family: family || 4 }]); };
}

async function run() {
  // ---- classify: IPv4 ----
  check("classify 127.0.0.1 → loopback",        ssrf.classify("127.0.0.1") === "loopback");
  check("classify 127.255.255.254 → loopback",  ssrf.classify("127.255.255.254") === "loopback");
  check("classify 10.0.0.1 → private",          ssrf.classify("10.0.0.1") === "private");
  check("classify 172.16.5.10 → private",       ssrf.classify("172.16.5.10") === "private");
  check("classify 172.31.255.254 → private",    ssrf.classify("172.31.255.254") === "private");
  check("classify 172.32.0.1 → null (outside private range)",
        ssrf.classify("172.32.0.1") === null);
  check("classify 192.168.1.1 → private",       ssrf.classify("192.168.1.1") === "private");
  check("classify 169.254.0.1 → link-local",    ssrf.classify("169.254.0.1") === "link-local");
  check("classify 169.254.169.254 → cloud-metadata (overrides link-local)",
        ssrf.classify("169.254.169.254") === "cloud-metadata");
  check("classify 169.254.170.2 → cloud-metadata (AWS ECS task role)",
        ssrf.classify("169.254.170.2") === "cloud-metadata");
  check("classify 0.0.0.0 → reserved",          ssrf.classify("0.0.0.0") === "reserved");
  check("classify 100.64.0.1 → reserved (CGNAT)", ssrf.classify("100.64.0.1") === "reserved");
  check("classify 192.0.2.1 → reserved (TEST-NET-1)", ssrf.classify("192.0.2.1") === "reserved");
  check("classify 224.0.0.1 → reserved (multicast)",  ssrf.classify("224.0.0.1") === "reserved");
  check("classify 255.255.255.255 → reserved (broadcast)",
        ssrf.classify("255.255.255.255") === "reserved");

  // ---- classify: external (returns null) ----
  check("classify 8.8.8.8 → null (Google DNS)",      ssrf.classify("8.8.8.8") === null);
  check("classify 1.1.1.1 → null (Cloudflare DNS)",  ssrf.classify("1.1.1.1") === null);
  check("classify 93.184.216.34 → null (example.com)", ssrf.classify("93.184.216.34") === null);

  // ---- classify: IPv6 ----
  check("classify ::1 → loopback",              ssrf.classify("::1") === "loopback");
  check("classify fe80::1 → link-local",        ssrf.classify("fe80::1") === "link-local");
  check("classify fc00::1 → private",           ssrf.classify("fc00::1") === "private");
  check("classify fd00::1 → private (ULA)",     ssrf.classify("fd00::1") === "private");
  check("classify 2001:db8::1 → reserved (documentation)",
        ssrf.classify("2001:db8::1") === "reserved");
  check("classify 2606:4700:4700::1111 → null (Cloudflare DNS6)",
        ssrf.classify("2606:4700:4700::1111") === null);
  check("classify fd00:ec2::254 → cloud-metadata", ssrf.classify("fd00:ec2::254") === "cloud-metadata");
  // IPv4-mapped IPv6 → reclassify the v4 portion
  check("classify ::ffff:127.0.0.1 → loopback (IPv4-mapped)",
        ssrf.classify("::ffff:127.0.0.1") === "loopback");
  check("classify ::ffff:8.8.8.8 → null (IPv4-mapped public)",
        ssrf.classify("::ffff:8.8.8.8") === null);

  // ---- classify: IPv6 special-use ranges ----
  // Multicast ff00::/8 — RFC 4291.
  check("classify ff02::1 → reserved (multicast)",     ssrf.classify("ff02::1") === "reserved");
  check("classify ff05::1 → reserved (multicast site-local)", ssrf.classify("ff05::1") === "reserved");
  check("classify ffff::1 → reserved (multicast)",     ssrf.classify("ffff::1") === "reserved");
  // Discard prefix 100::/64 — RFC 6666.
  check("classify 100::1 → reserved (discard)",        ssrf.classify("100::1") === "reserved");
  check("classify 100::ffff:ffff:ffff:ffff → reserved (discard)",
        ssrf.classify("100::ffff:ffff:ffff:ffff") === "reserved");
  // 6to4 2002::/16 — should re-classify the embedded v4 (RFC 3056).
  // 2002:0a00:0001:: → 10.0.0.1 (private)
  check("classify 2002:0a00:0001:: → private (6to4 wrapping 10.0.0.1)",
        ssrf.classify("2002:0a00:0001::") === "private");
  // 2002:7f00:0001:: → 127.0.0.1 (loopback)
  check("classify 2002:7f00:0001:: → loopback (6to4 wrapping 127.0.0.1)",
        ssrf.classify("2002:7f00:0001::") === "loopback");
  // 2002:a9fe:a9fe:: → 169.254.169.254 (cloud-metadata)
  check("classify 2002:a9fe:a9fe:: → cloud-metadata (6to4 wrapping 169.254.169.254)",
        ssrf.classify("2002:a9fe:a9fe::") === "cloud-metadata");
  // NAT64 64:ff9b::/96 — should re-classify the embedded v4 (RFC 6052).
  check("classify 64:ff9b::a00:1 → private (NAT64 wrapping 10.0.0.1)",
        ssrf.classify("64:ff9b::a00:1") === "private");
  check("classify 64:ff9b::a9fe:a9fe → cloud-metadata (NAT64 wrapping 169.254.169.254)",
        ssrf.classify("64:ff9b::a9fe:a9fe") === "cloud-metadata");

  // ---- classify: bad input ----
  check("classify '' → null",                   ssrf.classify("") === null);
  check("classify 'not-an-ip' → null",          ssrf.classify("not-an-ip") === null);
  check("classify null → null",                 ssrf.classify(null) === null);
  check("classify 1.2.3 → null (too few octets)", ssrf.classify("1.2.3") === null);

  // ---- isPrivate / isLoopback / etc. shortcuts ----
  check("isPrivate(10.0.0.1) === true",         ssrf.isPrivate("10.0.0.1") === true);
  check("isPrivate(8.8.8.8) === false",         ssrf.isPrivate("8.8.8.8") === false);
  check("isLoopback(127.0.0.1) === true",       ssrf.isLoopback("127.0.0.1") === true);
  check("isLinkLocal(169.254.0.1) === true",    ssrf.isLinkLocal("169.254.0.1") === true);
  check("isCloudMetadata(169.254.169.254) === true",
        ssrf.isCloudMetadata("169.254.169.254") === true);
  check("isReserved(0.0.0.0) === true",         ssrf.isReserved("0.0.0.0") === true);

  // ---- cidrContains: IPv4 ----
  check("cidrContains 10.0.0.0/8 contains 10.255.255.254",
        ssrf.cidrContains("10.0.0.0/8", "10.255.255.254") === true);
  check("cidrContains 10.0.0.0/8 does NOT contain 11.0.0.1",
        ssrf.cidrContains("10.0.0.0/8", "11.0.0.1") === false);
  check("cidrContains 192.168.1.0/24 contains 192.168.1.42",
        ssrf.cidrContains("192.168.1.0/24", "192.168.1.42") === true);
  check("cidrContains 192.168.1.0/24 does NOT contain 192.168.2.1",
        ssrf.cidrContains("192.168.1.0/24", "192.168.2.1") === false);
  check("cidrContains 0.0.0.0/0 matches anything",
        ssrf.cidrContains("0.0.0.0/0", "203.0.113.5") === true);

  // ---- cidrContains: IPv6 ----
  check("cidrContains fc00::/7 contains fd12::1",
        ssrf.cidrContains("fc00::/7", "fd12::1") === true);
  check("cidrContains fc00::/7 does NOT contain ::1",
        ssrf.cidrContains("fc00::/7", "::1") === false);
  check("cidrContains 2001:db8::/32 contains 2001:db8:abcd::1",
        ssrf.cidrContains("2001:db8::/32", "2001:db8:abcd::1") === true);

  // ---- cidrContains: bad input ----
  check("cidrContains rejects mixed-family pairing",
        ssrf.cidrContains("10.0.0.0/8", "::1") === false);
  check("cidrContains rejects malformed cidr (no slash)",
        ssrf.cidrContains("10.0.0.0", "10.0.0.1") === false);
  check("cidrContains rejects bad prefix (>32 for v4)",
        ssrf.cidrContains("10.0.0.0/64", "10.0.0.1") === false);

  // ---- checkUrl: IP-literal hostnames (no DNS) ----
  var threw = null;
  try { await ssrf.checkUrl("http://127.0.0.1/path"); }
  catch (e) { threw = e; }
  check("checkUrl: loopback IP literal blocked",
        threw && threw.code === "ssrf-guard/blocked-loopback");
  check("checkUrl: error carries url + ip + category",
        threw && threw.url === "http://127.0.0.1/path" &&
        threw.ip === "127.0.0.1" && threw.category === "loopback");

  threw = null;
  try { await ssrf.checkUrl("http://10.5.6.7/x"); }
  catch (e) { threw = e; }
  check("checkUrl: private IPv4 literal blocked",
        threw && threw.code === "ssrf-guard/blocked-private");

  threw = null;
  try { await ssrf.checkUrl("http://169.254.169.254/latest/meta-data/"); }
  catch (e) { threw = e; }
  check("checkUrl: AWS metadata IP literal blocked with cloud-metadata code",
        threw && threw.code === "ssrf-guard/blocked-cloud-metadata");

  threw = null;
  try { await ssrf.checkUrl("http://[::1]/path"); }
  catch (e) { threw = e; }
  check("checkUrl: IPv6 loopback literal blocked",
        threw && threw.code === "ssrf-guard/blocked-loopback");

  // ---- checkUrl: hostname resolution via stubbed dnsLookup ----
  threw = null;
  try {
    await ssrf.checkUrl("http://attacker.example/", {
      dnsLookup: _stubLookup("10.0.5.1"),
    });
  } catch (e) { threw = e; }
  check("checkUrl: hostname resolving to private IP blocked",
        threw && threw.code === "ssrf-guard/blocked-private");

  threw = null;
  try {
    await ssrf.checkUrl("http://malicious.host/", {
      dnsLookup: _stubLookup("169.254.169.254"),
    });
  } catch (e) { threw = e; }
  check("checkUrl: hostname resolving to metadata IP blocked",
        threw && threw.code === "ssrf-guard/blocked-cloud-metadata");

  // ---- checkUrl: allowInternal:true bypasses entirely ----
  var r = await ssrf.checkUrl("http://127.0.0.1/x", { allowInternal: true });
  check("checkUrl: allowInternal:true returns the resolved URL+IP",
        r && r.ips && r.ips[0].address === "127.0.0.1");

  // ---- checkUrl: allowInternal CIDR list (narrower than 'true') ----
  threw = null;
  try {
    await ssrf.checkUrl("http://10.0.5.1/", {
      allowInternal: ["10.0.0.0/8"],
    });
  } catch (e) { threw = e; }
  check("checkUrl: allowInternal CIDR list permits matching range",
        threw === null);

  threw = null;
  try {
    await ssrf.checkUrl("http://192.168.1.1/", {
      allowInternal: ["10.0.0.0/8"],   // doesn't include 192.168/16
    });
  } catch (e) { threw = e; }
  check("checkUrl: allowInternal CIDR list rejects out-of-range",
        threw && threw.code === "ssrf-guard/blocked-private");

  // An address resolved or written in its IPv4-mapped spelling is waived by
  // the IPv4 CIDR naming it, and an IPv4-mapped CIDR waives the IPv4 address.
  var mappedWaivers = [
    { url: "http://[::ffff:10.0.5.1]/", list: ["10.0.0.0/8"] },
    { url: "http://10.0.5.1/",          list: ["::ffff:10.0.0.0/104"] },
    { url: "http://x.test/",            list: ["10.0.0.0/8"], lookup: _stubLookup("::ffff:10.0.5.1", 6) },
  ];
  for (var mw = 0; mw < mappedWaivers.length; mw += 1) {
    threw = null;
    try {
      await ssrf.checkUrl(mappedWaivers[mw].url, {
        allowInternal: mappedWaivers[mw].list,
        dnsLookup:     mappedWaivers[mw].lookup,
      });
    } catch (e) { threw = e; }
    check("checkUrl: allowInternal " + JSON.stringify(mappedWaivers[mw].list) + " waives " +
          mappedWaivers[mw].url + (mappedWaivers[mw].lookup ? " (resolved ::ffff:10.0.5.1)" : ""),
          threw === null, threw ? threw.code : "");
  }

  // ---- checkUrl: external IP passes ----
  var r2 = await ssrf.checkUrl("https://example.com/", {
    dnsLookup: _stubLookup("93.184.216.34"),
  });
  check("checkUrl: public IP passes",
        r2 && r2.ips[0].address === "93.184.216.34");

  // ---- cloud-metadata IPv6 matched on canonical bytes, not string ----
  // The IMDS-over-IPv6 address fd00:ec2::254 has many textual spellings.
  // A non-canonical / mixed-case spelling must still classify as
  // cloud-metadata — a string-equality membership test caught one
  // spelling only, and the DoH resolver decodes AAAA to the expanded
  // fd00:ec2:0:0:0:0:0:254 form, which slipped past as "private".
  check("classify fd00:ec2:0:0:0:0:0:254 → cloud-metadata (expanded zero-run)",
        ssrf.classify("fd00:ec2:0:0:0:0:0:254") === "cloud-metadata");
  check("classify FD00:EC2::254 → cloud-metadata (mixed-case compressed)",
        ssrf.classify("FD00:EC2::254") === "cloud-metadata");
  check("classify fd00:0ec2::0254 → cloud-metadata (leading-zero groups)",
        ssrf.classify("fd00:0ec2::0254") === "cloud-metadata");
  // A genuine ULA private address that is NOT metadata must stay "private".
  check("classify fd00::1 → private (NOT metadata)",
        ssrf.classify("fd00::1") === "private");

  // PoC: allowInternal:true MUST NOT override the unconditional metadata
  // block, even when DNS resolves to the non-canonical IMDS-over-IPv6
  // spelling. Pre-fix this RESOLVED (credentials reachable); now refused.
  threw = null;
  try {
    await ssrf.checkUrl("http://imds.attacker.example/latest/meta-data/iam/", {
      allowInternal: true,
      dnsLookup: _stubLookup("fd00:ec2:0:0:0:0:0:254", 6),
    });
  } catch (e) { threw = e; }
  check("checkUrl: allowInternal:true does NOT override non-canonical IMDS-over-IPv6",
        threw && threw.code === "ssrf-guard/blocked-cloud-metadata");

  // Compressed + mixed-case spellings refused too (wire not reached).
  threw = null;
  try {
    await ssrf.checkUrl("http://imds.attacker.example/", {
      allowInternal: true,
      dnsLookup: _stubLookup("FD00:EC2::254", 6),
    });
  } catch (e) { threw = e; }
  check("checkUrl: allowInternal:true does NOT override mixed-case IMDS-over-IPv6",
        threw && threw.code === "ssrf-guard/blocked-cloud-metadata");

  // A genuine private IPv6 (fd00::1, NOT metadata) still respects
  // allowInternal — the metadata gate is the only unconditional class.
  threw = null;
  var rPriv6 = null;
  try {
    rPriv6 = await ssrf.checkUrl("http://internal.mesh/", {
      allowInternal: true,
      dnsLookup: _stubLookup("fd00::1", 6),
    });
  } catch (e) { threw = e; }
  check("checkUrl: genuine private IPv6 still honors allowInternal:true",
        threw === null && rPriv6 && rPriv6.ips[0].address === "fd00::1");

  // checkUrlTextual: the same byte-canonical gate at the textual layer.
  threw = null;
  try { ssrf.checkUrlTextual("http://[fd00:ec2:0:0:0:0:0:254]/x"); }
  catch (e) { threw = e; }
  check("checkUrlTextual: non-canonical IMDS-over-IPv6 refused",
        threw && threw.code === "ssrf-guard/blocked-cloud-metadata");
  threw = null;
  try { ssrf.checkUrlTextual("http://[FD00:EC2::254]/x"); }
  catch (e) { threw = e; }
  check("checkUrlTextual: mixed-case IMDS-over-IPv6 refused",
        threw && threw.code === "ssrf-guard/blocked-cloud-metadata");
  // A non-metadata internal host stays accepted at the textual layer.
  var txtOk = ssrf.checkUrlTextual("http://[fd00::1]/x");
  check("checkUrlTextual: non-metadata IPv6 literal accepted",
        txtOk && txtOk.host === "fd00::1");

  // ---- checkUrl: bad input ----
  threw = null;
  try { await ssrf.checkUrl("not-a-url"); }
  catch (e) { threw = e; }
  check("checkUrl: malformed URL rejected", threw && threw instanceof Error);

  // ---- SsrfError shape ----
  check("SsrfError is a class",                 typeof ssrf.SsrfError === "function");
  var e = new ssrf.SsrfError("msg", "ssrf-guard/test");
  check("SsrfError has isSsrfError flag",       e.isSsrfError === true);
  check("SsrfError marks permanent (no retry)", e.permanent === true);

  // ---- Pinned-lookup callback (TOCTOU defense) ----
  // After ssrf-guard validates an IP, http-client pins the actual TCP
  // connect to that IP via a custom `lookup` callback (closes the DNS
  // rebinding window). Verify the callback honors Node's documented
  // shape: callback(err, address, family) for single, callback(err,
  // [{ address, family }]) when options.all is set.
  var httpClient = require("../../lib/http-client");
  var pinned = httpClient._pinnedLookupForTest([
    { address: "203.0.113.5", family: 4 },
    { address: "2001:db8::1", family: 6 },
  ]);
  check("pinned-lookup: returns a function",   typeof pinned === "function");

  var singleAddr, singleFamily;
  pinned("evil.example.invalid", {}, function (err, addr, family) {
    singleAddr = addr; singleFamily = family;
  });
  check("pinned-lookup: single returns first IP regardless of hostname",
        singleAddr === "203.0.113.5" && singleFamily === 4);

  var allList;
  pinned("any-hostname-here", { all: true }, function (err, list) { allList = list; });
  check("pinned-lookup: all=true returns full list",
        Array.isArray(allList) && allList.length === 2);
  check("pinned-lookup: all=true preserves order",
        allList[0].address === "203.0.113.5" && allList[1].address === "2001:db8::1");
  check("pinned-lookup: all=true preserves family",
        allList[1].family === 6);

  // Empty IP list → no lookup callback (caller falls back to Node's DNS)
  var noPin = httpClient._pinnedLookupForTest([]);
  check("pinned-lookup: empty ips → undefined (let Node resolve)",
        noPin === undefined);

  // #503 — hostname-aware loopback classifier so consumers stop re-rolling the
  // localhost/127.0.0.1/::1 triad. Two forms: isLoopbackHost includes the RFC
  // 6761 `*.localhost` reservation; isExactLoopbackName does NOT (the OAuth
  // cleartext-redirect loopback exception must not widen to a subdomain).
  check("isLoopbackHost: localhost",              ssrf.isLoopbackHost("localhost") === true);
  check("isLoopbackHost: LOCALHOST. (case + trailing dot)", ssrf.isLoopbackHost("LOCALHOST.") === true);
  check("isLoopbackHost: [::1] bracketed IPv6",   ssrf.isLoopbackHost("[::1]") === true);
  check("isLoopbackHost: 127.0.0.1",              ssrf.isLoopbackHost("127.0.0.1") === true);
  check("isLoopbackHost: 127.5.5.5 (127/8)",      ssrf.isLoopbackHost("127.5.5.5") === true);
  check("isLoopbackHost: ::ffff:127.0.0.1 (v4-mapped)", ssrf.isLoopbackHost("::ffff:127.0.0.1") === true);
  check("isLoopbackHost: app.localhost (RFC 6761 §6.3)", ssrf.isLoopbackHost("app.localhost") === true);
  check("isLoopbackHost: example.com → false",    ssrf.isLoopbackHost("example.com") === false);
  check("isLoopbackHost: 8.8.8.8 → false",        ssrf.isLoopbackHost("8.8.8.8") === false);
  check("isLoopbackHost: empty / non-string → false",
        ssrf.isLoopbackHost("") === false && ssrf.isLoopbackHost(null) === false);
  check("isExactLoopbackName: localhost",         ssrf.isExactLoopbackName("localhost") === true);
  check("isExactLoopbackName: 127.0.0.1",         ssrf.isExactLoopbackName("127.0.0.1") === true);
  check("isExactLoopbackName: app.localhost → false (no subdomain widening)",
        ssrf.isExactLoopbackName("app.localhost") === false);
  check("isExactLoopbackName: evil.localhost → false", ssrf.isExactLoopbackName("evil.localhost") === false);
}

async function _testCreateAllowlist() {
  var threw;
  try { b.ssrfGuard.createAllowlist({}); } catch (e) { threw = e; }
  check("createAllowlist: empty allow throws",
        threw && threw.code === "ssrf-guard/empty-allowlist");

  var egress = b.ssrfGuard.createAllowlist({
    allow: ["api.partner.example.com", "192.0.2.0/24"],
    deny:  ["bad.example.com"],
  });
  check("createAllowlist: returns assert function",
        typeof egress.assert === "function");

  var rejected;
  try { await egress.assert("https://other.example.com/x"); }
  catch (e) { rejected = e; }
  check("createAllowlist: hostname not on allowlist refused",
        rejected && rejected.code === "ssrf-guard/not-on-allowlist");

  // The URL parser lowercases the host, but the operator allow/deny entries
  // were compared raw — so a mixed-case (or trailing-dot) entry silently did
  // not match, letting a denied host through. Both sides must canonicalize.
  var cased = b.ssrfGuard.createAllowlist({
    allow: ["evil.example.com"],          // host is allowed...
    deny:  ["EVIL.EXAMPLE.COM"],          // ...but explicitly denied (mixed case)
  });
  var denyHit;
  try { await cased.assert("https://evil.example.com/x"); }
  catch (e) { denyHit = e; }
  check("createAllowlist: denylist blocks a host case-insensitively",
        denyHit && denyHit.code === "ssrf-guard/on-denylist");

  // And a mixed-case ALLOW entry still admits the lowercased host (no wrong-reject).
  var casedAllow = b.ssrfGuard.createAllowlist({ allow: ["API.Partner.Example.com."] });
  var allowOk = true;
  try { await casedAllow.assert("https://api.partner.example.com/x"); }
  catch (e) { allowOk = (e.code === "ssrf-guard/not-on-allowlist") ? false : true; }
  check("createAllowlist: mixed-case/trailing-dot allow entry admits the host", allowOk === true);

  // A URL writes an IPv6 host in brackets (`http://[fd00::5]/` has hostname
  // `[fd00::5]`), and a CIDR entry is compared with the address. A deny CIDR
  // that missed the bracketed host let the host through, and an allow CIDR
  // refused it.
  async function outcome(list, url) {
    try { await b.ssrfGuard.createAllowlist(list).assert(url); return "allowed"; }
    catch (e) { return e.code; }
  }
  var v6Deny = await outcome({ allow: ["[fd00::5]"], deny: ["fd00::/8"] }, "http://[fd00::5]/");
  check("createAllowlist: an IPv6 deny CIDR blocks a bracketed IPv6 URL host",
        v6Deny === "ssrf-guard/on-denylist", v6Deny);
  var v6Allow = await outcome({ allow: ["fd00::/8"] }, "http://[fd00::5]/");
  check("createAllowlist: an IPv6 allow CIDR admits a bracketed IPv6 URL host",
        v6Allow === "allowed", v6Allow);
  var v6Outside = await outcome({ allow: ["fd00::/8"] }, "http://[fe00::5]/");
  check("createAllowlist: an IPv6 address outside the allow CIDR is refused",
        v6Outside === "ssrf-guard/not-on-allowlist", v6Outside);

  // An IPv4 address has an IPv4-mapped IPv6 spelling (::ffff:10.0.0.1) and
  // a NAT64 spelling (64:ff9b::a00:1). A deny entry written in one family
  // blocks the address in every spelling, and an allow entry written as an
  // IPv4-mapped CIDR admits the address it names.
  var everyAddr = ["0.0.0.0/0", "::/0"];
  var mappedDenyCases = [
    { deny: ["::ffff:10.0.0.0/104"], url: "http://[::ffff:10.0.0.1]/" },
    { deny: ["::ffff:10.0.0.0/104"], url: "http://10.0.0.1/" },
    { deny: ["::ffff:0:0/96"],       url: "http://10.0.0.1/" },
    { deny: ["::ffff:0:0/96"],       url: "http://[::ffff:a00:1]/" },
    { deny: ["::/0"],                url: "http://10.0.0.1/" },
    { deny: ["::ffff:10.0.0.1"],     url: "http://10.0.0.1/" },
    { deny: ["10.0.0.0/8"],          url: "http://[64:ff9b::a00:1]/" },
    { deny: ["10.0.0.0/8"],          url: "http://[64:ff9b::10.0.0.1]/" },
    { deny: ["::ffff:10.0.0.0/104"], url: "http://[64:ff9b::a00:1]/" },
    { deny: ["10.0.0.1"],            url: "http://[64:ff9b::a00:1]/" },
    { deny: ["10.0.0.0/8"],          url: "http://[2002:a00:1::1]/" },
  ];
  for (var mi = 0; mi < mappedDenyCases.length; mi += 1) {
    var mc = mappedDenyCases[mi];
    var got = await outcome({ allow: everyAddr, deny: mc.deny }, mc.url);
    check("createAllowlist: deny " + JSON.stringify(mc.deny) + " blocks " + mc.url,
          got === "ssrf-guard/on-denylist", got);
  }
  var mappedAllow = await outcome({ allow: ["::ffff:10.0.0.0/104"] }, "http://10.0.0.1/");
  check("createAllowlist: an IPv4-mapped allow CIDR admits the IPv4 address it names",
        mappedAllow === "allowed", mappedAllow);
  var mappedAllowBracket = await outcome({ allow: ["::ffff:10.0.0.0/104"] }, "http://[::ffff:10.0.0.1]/");
  check("createAllowlist: an IPv4-mapped allow CIDR admits the mapped spelling",
        mappedAllowBracket === "allowed", mappedAllowBracket);
  // Controls: an allow entry does not widen to other families, and an
  // unrelated deny entry does not block.
  var v6AllowV4 = await outcome({ allow: ["::/0"] }, "http://10.0.0.1/");
  check("createAllowlist: an IPv6 allow-all does not admit an IPv4 host",
        v6AllowV4 === "ssrf-guard/not-on-allowlist", v6AllowV4);
  var nat64Allow = await outcome({ allow: ["10.0.0.0/8"] }, "http://[64:ff9b::a00:1]/");
  check("createAllowlist: an IPv4 allow CIDR does not admit a NAT64 host",
        nat64Allow === "ssrf-guard/not-on-allowlist", nat64Allow);
  var otherDeny = await outcome({ allow: everyAddr, deny: ["::ffff:10.0.0.0/104", "10.0.0.0/8"] },
    "http://[64:ff9b::b00:1]/");
  check("createAllowlist: a NAT64 host outside the IPv4 deny CIDR is not blocked by it",
        otherDeny !== "ssrf-guard/on-denylist", otherDeny);
  // An IPv6 deny CIDR that contains ::ffff:0:0/96 denies every IPv4 host.
  var reservedV6Deny = await outcome({ allow: ["0.0.0.0/0"], deny: ["::/8"] }, "http://8.8.8.8/");
  check("createAllowlist: deny ['::/8'] covers ::ffff:0:0/96 and blocks an IPv4 host",
        reservedV6Deny === "ssrf-guard/on-denylist", reservedV6Deny);
  var narrowV6Deny = await outcome({ allow: ["0.0.0.0/0"], deny: ["2001:db8::/32"] }, "http://8.8.8.8/");
  check("createAllowlist: an IPv6 deny CIDR outside ::ffff:0:0/96 does not block an IPv4 host",
        narrowV6Deny !== "ssrf-guard/on-denylist", narrowV6Deny);
}

// A deny entry applies to the addresses a host name resolves to, not only to
// a literal address in the URL. Without that, allow ["localhost"] with deny
// ["127.0.0.0/8", "::1/128"] reached loopback.
async function _testCreateAllowlistDenyAppliesToResolvedAddresses() {
  async function outcome(list, url) {
    try { await b.ssrfGuard.createAllowlist(list).assert(url); return "allowed"; }
    catch (e) { return e.code + (e.ip ? " " + e.ip : ""); }
  }
  var loopbackDenies = [
    ["127.0.0.0/8", "::1/128"],
    ["::ffff:127.0.0.0/104", "::1"],
    ["::ffff:0:0/96", "::1/128"],
  ];
  for (var i = 0; i < loopbackDenies.length; i += 1) {
    var got = await outcome({ allow: ["localhost"], deny: loopbackDenies[i] }, "http://localhost:8080/");
    check("createAllowlist: deny " + JSON.stringify(loopbackDenies[i]) +
          " blocks a host name that resolves into it",
          got.indexOf("ssrf-guard/on-denylist ") === 0, got);
  }
  var unrelated = await outcome({ allow: ["localhost"], deny: ["10.0.0.0/8", "fd00::/8"] },
    "http://localhost:8080/");
  check("createAllowlist: a deny CIDR the resolved addresses are outside does not block",
        unrelated === "allowed", unrelated);
}

// Entries are checked when the allowlist is built. A malformed deny entry
// used to match nothing, so the denylist failed open, and a non-string entry
// threw a TypeError from every assert() call.
function _testCreateAllowlistRefusesMalformedEntries() {
  function buildCode(opts) {
    try { b.ssrfGuard.createAllowlist(opts); return "built"; }
    catch (e) { return e.code || e.message; }
  }
  var bad = [
    "10.0.0.0/33", "10.0.0/8", "010.0.0.0/8", "10.0.0.0/-1", " 10.0.0.0/8", "10.0.0.0/8 ",
    "10.0.0.0/08", "10.0.0.0/", "/8", "10.0.0.0/8/8", "fd00::/129", "[fd00::]/8", "fd00::/1e2",
    "", "10.0.0", "010.0.0.1", " evil.example.com", "api.example.com:443", "user@evil.example.com",
    "evil.example.com/path", "bücher.example", 123, null, {},
  ];
  for (var i = 0; i < bad.length; i += 1) {
    var label = JSON.stringify(bad[i]);
    var denyGot = buildCode({ allow: ["0.0.0.0/0"], deny: [bad[i]] });
    check("createAllowlist: deny entry " + label + " is refused at create time",
          denyGot === "ssrf-guard/bad-entry", denyGot);
    var allowGot = buildCode({ allow: [bad[i]] });
    check("createAllowlist: allow entry " + label + " is refused at create time",
          allowGot === "ssrf-guard/bad-entry", allowGot);
  }
  var notArray = buildCode({ allow: ["0.0.0.0/0"], deny: "10.0.0.0/8" });
  check("createAllowlist: a deny value that is not an array is refused",
        notArray === "ssrf-guard/bad-entry", notArray);
  var allowNotArray = buildCode({ allow: "10.0.0.0/8" });
  check("createAllowlist: an allow value that is not an array is refused",
        allowNotArray === "ssrf-guard/bad-entry", allowNotArray);
  var unknownKey = buildCode({ allow: ["0.0.0.0/0"], denied: ["10.0.0.0/8"] });
  check("createAllowlist: an unknown option is refused",
        unknownKey !== "built", unknownKey);
  var good = [
    "10.0.0.1/8", "0.0.0.0/0", "::/0", "fd00::/8", "::ffff:10.0.0.0/104", "10.0.0.1",
    "::ffff:10.0.0.1", "fd00::5", "[fd00::5]", "API.Partner.Example.com.", "xn--bcher-kva.example",
    "localhost",
  ];
  for (var g = 0; g < good.length; g += 1) {
    var built = buildCode({ allow: [good[g]], deny: [good[g]] });
    check("createAllowlist: entry " + JSON.stringify(good[g]) + " is accepted", built === "built", built);
  }
}

// checkUrl built every refusal as `new ErrorClass(message, code, ctx)`, which
// fits SsrfError. b.wsClient passes WsClientError, built by defineClass, whose
// constructor takes the code first, so a refused dial arrived with err.code
// holding the human-readable text and err.message holding the code. A consumer
// matching err.code.startsWith("ssrf-guard/") missed every refusal, including
// the cloud-metadata block that allowInternal cannot override.
async function _testRefusalCarriesTheCodeForAnyErrorClass() {
  var CodeFirst = b.frameworkError.defineClass("SsrfArgOrderProbeError");
  var cases = [
    { url: "https://169.254.169.254/x", opts: { allowInternal: true },
      code: "ssrf-guard/blocked-cloud-metadata", label: "the cloud-metadata block" },
    { url: "https://10.0.0.5/x", opts: {},
      code: "ssrf-guard/blocked-private", label: "a private-range refusal" },
  ];
  for (var i = 0; i < cases.length; i++) {
    var c = cases[i];
    var caught = null;
    try {
      await b.ssrfGuard.checkUrl(c.url, Object.assign({ errorClass: CodeFirst }, c.opts));
    } catch (e) { caught = e; }
    check(c.label + " refuses", caught !== null, "no throw for " + c.url);
    if (!caught) continue;
    check(c.label + " puts the code in err.code",
      caught.code === c.code, "code=" + JSON.stringify(String(caught.code)).slice(0, 80));
    check(c.label + " puts the text in err.message",
      /^URL /.test(String(caught.message)),
      "message=" + JSON.stringify(String(caught.message)).slice(0, 70));
  }

  // The control: the message-first class the guard was written around is
  // unaffected, so the fix normalizes the order rather than inverting it.
  var sameShape = null;
  try { await b.ssrfGuard.checkUrl("https://10.0.0.5/x", {}); }
  catch (e) { sameShape = e; }
  check("the guard's own SsrfError keeps code and message as before",
    sameShape !== null && sameShape.code === "ssrf-guard/blocked-private" &&
    /^URL /.test(String(sameShape.message)),
    sameShape ? sameShape.code + " | " + String(sameShape.message).slice(0, 40) : "no throw");

  // The same disagreement ran the other way through b.safeUrl, which builds
  // the class it is handed code-first. checkUrl parses through it and passes
  // SsrfError, so a malformed URL inverted on the DEFAULT error class.
  var malformed = null;
  try { await b.ssrfGuard.checkUrl("ht!tp://%%%bad", {}); }
  catch (e) { malformed = e; }
  check("a malformed URL carries the safe-url code in err.code",
    malformed !== null && String(malformed.code).indexOf("safe-url/") === 0,
    malformed ? JSON.stringify(String(malformed.code)).slice(0, 70) : "no throw");
  check("and its message is the text, not the code",
    malformed !== null && String(malformed.message).indexOf("safe-url/") !== 0,
    malformed ? JSON.stringify(String(malformed.message)).slice(0, 70) : "no throw");
}

// An IPv6 address with a dotted IPv4 tail and a zone id parsed the zone into
// the IPv4 tail, so ::ffff:10.0.0.1%eth0 canonicalized to 0.0.0.0 and
// 2001:db8::10.0.0.1%1 to 2001:db8::. A peer list then compared the wrong
// address: deniedCidrs 10.0.0.0/8 missed it and an exact 0.0.0.0 matched it.
function _testAZoneIdDoesNotChangeTheAddress() {
  var cases = [
    ["::ffff:10.0.0.1%eth0",  "10.0.0.1"],
    ["2001:db8::10.0.0.1%1",  "2001:db8::a00:1"],
    ["::ffff:a00:1%eth0",     "10.0.0.1"],
    ["fe80::1%eth0",          "fe80::1"],
  ];
  for (var i = 0; i < cases.length; i++) {
    var got = ssrf.canonicalizeHost(cases[i][0]);
    check("canonicalizeHost(" + cases[i][0] + ") is " + cases[i][1], got === cases[i][1], got);
  }
  check("classify(::ffff:10.0.0.1%eth0) is private",
    ssrf.classify("::ffff:10.0.0.1%eth0") === "private", ssrf.classify("::ffff:10.0.0.1%eth0"));
  check("a 10.0.0.0/8 list matches ::ffff:10.0.0.1%eth0",
    ssrf._listMatches(["10.0.0.0/8"], "::ffff:10.0.0.1%eth0", true) === true);
  check("::ffff:10.0.0.1%eth0 is not the address 0.0.0.0",
    ssrf._sameAddress("::ffff:10.0.0.1%eth0", "0.0.0.0") === false);
  check("fe80::1%eth0 and fe80::1%eth1 are different addresses",
    ssrf._sameAddress("fe80::1%eth0", "fe80::1%eth1") === false);
  check("fe80::1%eth0 is the same address as FE80::0:1%eth0",
    ssrf._sameAddress("fe80::1%eth0", "FE80::0:1%eth0") === true);
  check("fe80::1%eth0 is the same address as [fe80::1%eth0]",
    ssrf._sameAddress("fe80::1%eth0", "[fe80::1%eth0]") === true);
  check("the control: a zone-free mapped peer is its IPv4 address",
    ssrf._sameAddress("::ffff:10.0.0.1", "10.0.0.1") === true);
}

module.exports = { run: async function () {
  await run();
  _testAZoneIdDoesNotChangeTheAddress();
  await _testCreateAllowlist();
  await _testCreateAllowlistDenyAppliesToResolvedAddresses();
  _testCreateAllowlistRefusesMalformedEntries();
  await _testRefusalCarriesTheCodeForAnyErrorClass();
} };

if (require.main === module) {
  module.exports.run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (err) { console.error("FAIL:", err.stack || err); process.exit(1); }
  );
}
