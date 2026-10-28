// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * TLS Server Name Indication on outbound dials whose host is an IP literal.
 *
 * RFC 6066 section 3 does not permit a literal IPv4 or IPv6 address in SNI,
 * and Node refuses one: on Node 26 `tls.connect({ servername: "127.0.0.1" })`
 * throws ERR_INVALID_ARG_VALUE before a ClientHello is written, and older
 * releases send it with a DEP0123 warning. Every outbound dial that derives
 * the server name from its host goes through `b.network.tls.sniFor`, which
 * returns the host for a name and nothing for an address; with no server
 * name the certificate is checked against its IP SANs.
 *
 * Each dial is driven through its shipped entry point against a loopback
 * TLS server that records whether a ClientHello arrived and which SNI it
 * carried:
 *
 *   - b.network.tls.sniFor itself
 *   - b.network.tls.connectWithEch to 127.0.0.1 and ::1
 *   - b.network.dns DNS-over-TLS to 127.0.0.1, and the
 *     BLAMEJS_DNS_TRANSPORT=dot default resolver (1.1.1.1)
 *   - b.network.proxy: an https proxy at 127.0.0.1 and at [::1], and the
 *     TLS session to an IP-literal target through the tunnel, including the
 *     certificate check against the target rather than the proxy
 *
 * Each address case has a control that dials the same entry point by host
 * name (or with an explicit `servername`) and asserts the server received
 * that name, and a `servername` of the wrong type is refused at
 * configuration.
 *
 * The file also covers b.network.tls.identityFor and checkServerIdentity9525
 * on every IPv6 spelling (dotted IPv4 tails, zone IDs), identityFor's own
 * option checks, operator hosts written as `[::1]` on connectWithEch,
 * DNS-over-TLS, NTS-KE, ocsp.connect, the SMTP transport and the Redis
 * client, NO_PROXY matching for IPv6 targets, and an https proxy that closes
 * the connection before the TLS handshake.
 */

var helpers  = require("../helpers");
var b        = helpers.b;
var check    = helpers.check;
var nodeTls  = require("node:tls");
var net      = require("node:net");
var https    = require("node:https");
var nodeDns  = require("node:dns");

var networkDns   = require("../../lib/network-dns");
var networkProxy = require("../../lib/network-proxy");
var networkNts   = require("../../lib/network-nts");
var redisClient  = require("../../lib/redis-client");

function _hasIpv6Loopback() {
  var ifaces = require("node:os").networkInterfaces();
  return Object.keys(ifaces).some(function (name) {
    return (ifaces[name] || []).some(function (a) {
      return (a.family === "IPv6" || a.family === 6) && a.address === "::1";
    });
  });
}

async function _makeCa() {
  return b.mtlsEngine.generateCa({ name: "sni-test-ca" });
}

async function _leaf(ca, sans) {
  return b.mtlsEngine.signClientCert({
    cn: "localhost", caCertPem: ca.caCertPem, caKeyPem: ca.caKeyPem,
    usage: "server", sans: sans, validityDays: 1,
  });
}

// A TLS server that records each connection, the SNI its ClientHello
// carried, and how many clients have closed their side. onSecure(sock)
// handles the application bytes.
function _startTlsServer(leaf, host, onSecure) {
  return new Promise(function (resolve) {
    var handle = { connections: 0, peerClosed: 0, sni: [], secure: [], sockets: [] };
    var server = nodeTls.createServer({
      key: leaf.key, cert: leaf.cert, minVersion: "TLSv1.3",
      SNICallback: function (name, cb) { handle.sni.push(name); cb(null, null); },
    }, function (sock) {
      handle.secure.push(sock.servername);
      var counted = false;
      function peerClosed() { if (!counted) { counted = true; handle.peerClosed += 1; } }
      sock.on("end", peerClosed);
      sock.on("close", peerClosed);
      sock.on("error", function () { /* client teardown */ });
      if (onSecure) onSecure(sock);
    });
    server.on("connection", function (raw) {
      handle.connections += 1;
      handle.sockets.push(raw);
    });
    server.on("tlsClientError", function () { /* recorded through connections */ });
    server.on("error", function () { /* best-effort loopback listener */ });
    server.listen(0, host, function () {
      handle.server = server;
      handle.port = server.address().port;
      resolve(handle);
    });
  });
}

function _close(h) {
  if (!h || !h.server) return;
  h.sockets.forEach(function (s) { try { s.destroy(); } catch (_e) { /* best-effort */ } });
  try { h.server.close(); } catch (_e) { /* best-effort */ }
}

// Trust the test CA for dials that take no `ca` option (the proxy hops use
// the process default store).
function _trustCa(caPem) {
  if (typeof nodeTls.setDefaultCACertificates !== "function") return null;
  var before = nodeTls.getCACertificates("default");
  nodeTls.setDefaultCACertificates(before.concat([caPem]));
  return function () { nodeTls.setDefaultCACertificates(before); };
}

function testSniForHelper() {
  var sniFor = b.network.tls.sniFor;
  check("b.network.tls.sniFor is exported", typeof sniFor === "function");
  if (typeof sniFor !== "function") return;
  check("sniFor returns a hostname unchanged", sniFor("example.com") === "example.com");
  check("sniFor omits an IPv4 literal", sniFor("127.0.0.1") === undefined);
  check("sniFor omits an IPv6 literal", sniFor("::1") === undefined);
  check("sniFor omits a bracketed IPv6 literal", sniFor("[::1]") === undefined);
  check("sniFor omits an IPv4-mapped IPv6 literal", sniFor("::ffff:127.0.0.1") === undefined);
  check("sniFor omits an empty host", sniFor("") === undefined);
  check("sniFor omits a non-string host", sniFor(null) === undefined && sniFor(42) === undefined);
}

// b.network.tls.identityFor answers "what identity options does this dial
// send" for every framework dial that takes a host and an optional
// servername.
function testIdentityForHelper() {
  var identityFor = b.network.tls.identityFor;
  check("b.network.tls.identityFor is exported", typeof identityFor === "function");
  if (typeof identityFor !== "function") return;
  function same(a, e) { return JSON.stringify(a) === JSON.stringify(e); }
  function thrown(fn) { try { fn(); return null; } catch (e) { return e; } }
  check("identityFor: a host name is the server name",
        same(identityFor("example.com"), { servername: "example.com" }));
  check("identityFor: an IPv4 host has no server name", same(identityFor("192.0.2.10"), {}));
  check("identityFor: a bracketed IPv6 host has no server name", same(identityFor("[2001:db8::1]"), {}));
  check("identityFor: a name in servername is the server name on an address host",
        same(identityFor("192.0.2.10", "api.example.com"), { servername: "api.example.com" }));
  check("identityFor: a null servername falls back to the host",
        same(identityFor("example.com", null), { servername: "example.com" }));
  check("identityFor: the host's own address in servername gives no server name",
        same(identityFor("192.0.2.10", "192.0.2.10"), {}));
  check("identityFor: the same IPv6 address in another spelling gives no server name",
        same(identityFor("::1", "0:0:0:0:0:0:0:1"), {}) && same(identityFor("[::1]", "::1"), {}) &&
        same(identityFor("2001:DB8::1", "[2001:db8:0::1]"), {}));
  var other = thrown(function () { identityFor("192.0.2.10", "192.0.2.11"); });
  check("identityFor: an address other than the host is refused as tls/bad-servername",
        other && other.code === "tls/bad-servername" && other instanceof b.network.tls.NetworkTlsError,
        other ? other.code + " " + other.message : "accepted");
  var onName = thrown(function () { identityFor("example.com", "192.0.2.10"); });
  check("identityFor: an address servername on a named host is refused",
        onName && onName.code === "tls/bad-servername", onName ? onName.code : "accepted");
  var mixed = thrown(function () { identityFor("127.0.0.1", "::ffff:127.0.0.2"); });
  check("identityFor: an IPv4-mapped address other than the host is refused",
        mixed && mixed.code === "tls/bad-servername", mixed ? mixed.code : "accepted");
  [42, "", {}].forEach(function (sn) {
    var e = thrown(function () { identityFor("example.com", sn); });
    check("identityFor: servername " + JSON.stringify(sn) + " is refused",
          e && e.code === "tls/bad-servername", e ? e.code : "accepted");
  });
  var custom = thrown(function () {
    identityFor("127.0.0.1", "127.0.0.2", { label: "x.create: opts.servername",
      errorClass: b.network.dns.DnsError, code: "dns/bad-dot-servername" });
  });
  check("identityFor: opts.errorClass and opts.code name the refusal",
        custom && custom.code === "dns/bad-dot-servername" && /x\.create: opts\.servername/.test(custom.message),
        custom ? custom.code + " " + custom.message : "accepted");
  var badOpt = thrown(function () { identityFor("example.com", undefined, { nope: 1 }); });
  check("identityFor: an unknown option is refused", badOpt !== null);
}

// One address has one identity however it is written, including an IPv6
// literal that ends in a dotted IPv4 part (IPv4-mapped, NAT64). A zone ID
// names a link, so the same address on two zones is two addresses.
function testIdentityForEveryIpv6Spelling() {
  var identityFor = b.network.tls.identityFor;
  function outcome(host, sn) {
    try { return JSON.stringify(identityFor(host, sn)); } catch (e) { return String(e && e.code); }
  }
  [
    ["::ffff:127.0.0.1", "::ffff:127.0.0.1"],
    ["64:ff9b::192.0.2.1", "64:ff9b::192.0.2.1"],
    ["::ffff:7f00:1", "::ffff:127.0.0.1"],
    ["[::ffff:127.0.0.1]", "0:0:0:0:0:ffff:7f00:1"],
    ["64:ff9b::c000:201", "[64:ff9b::192.0.2.1]"],
    ["fe80::1%eth0", "fe80::1%eth0"],
  ].forEach(function (p) {
    var o = outcome(p[0], p[1]);
    check("identityFor: servername " + p[1] + " is the host " + p[0] + " and sends no server name",
          o === "{}", o);
  });
  [
    ["fe80::1%eth0", "fe80::1%eth1"],
    ["fe80::1%eth0", "fe80::1"],
    ["::ffff:127.0.0.1", "::ffff:127.0.0.2"],
    ["64:ff9b::192.0.2.1", "64:ff9b::192.0.2.2"],
  ].forEach(function (p) {
    var o = outcome(p[0], p[1]);
    check("identityFor: servername " + p[1] + " is not the host " + p[0] + " and is refused",
          o === "tls/bad-servername", o);
  });
  var smtpErr = null;
  try {
    b.mail.transports.smtp({ host: "::ffff:127.0.0.1", port: 2525, servername: "::ffff:127.0.0.1" });
  } catch (e) { smtpErr = e; }
  check("the SMTP transport accepts the host's own IPv4-mapped address as servername",
        smtpErr === null, smtpErr ? smtpErr.code + " " + smtpErr.message : "");
}

// checkServerIdentity9525 reads the same IPv6 spellings: a host with a
// dotted IPv4 tail matches the expanded text Node writes for the iPAddress
// SAN, and a zone ID on the host is not part of the certificate's address.
function testCheckServerIdentity9525DottedHost() {
  var cases = [
    ["::ffff:127.0.0.1", "IP Address:0:0:0:0:0:FFFF:7F00:1"],
    ["64:ff9b::192.0.2.1", "IP Address:64:FF9B:0:0:0:0:C000:201"],
    ["fe80::1%eth0", "IP Address:FE80:0:0:0:0:0:0:1"],
  ];
  cases.forEach(function (c) {
    var cert = { subject: { CN: "x" }, subjectaltname: c[1] };
    var err = b.network.tls.checkServerIdentity9525(c[0], cert);
    check("checkServerIdentity9525 matches " + c[0] + " against " + c[1],
          err === undefined, err ? err.code + " " + err.message : "");
  });
  var mapped = { subject: { CN: "x" }, subjectaltname: cases[0][1] };
  check("node:tls checkServerIdentity agrees on the IPv4-mapped host",
        nodeTls.checkServerIdentity("::ffff:127.0.0.1", mapped) === undefined);
  var other = b.network.tls.checkServerIdentity9525("::ffff:127.0.0.2", mapped);
  check("checkServerIdentity9525 refuses another IPv4-mapped address",
        other && other.code === "tls/pkix-hostname-mismatch", other ? other.code : "matched");
}

// A host that the OS resolver or the WHATWG URL parser reads as an IPv4
// address is an address, whatever its spelling: octal or hex octets, fewer
// than four parts, a single 32-bit number, a trailing dot, or digits written
// in fullwidth. Such a host must never be matched against a dNSName SAN.
var NON_CANONICAL_IPV4_HOSTS = [
  "0177.0.0.1", "0127.0.0.1", "087.0.0.1", "0x7f.0.0.1", "0X7F.0.0.1",
  "2130706433", "0x7f000001", "127.1", "127.0.1", "127.0.0.1.",
  "１２７.0.0.1", "127．0．0．1", "127.0.0.１",
  "foo.0x", "a.b.0X1F",
].concat([0xad, 0x200b, 0x2060, 0x34f, 0xfe0f, 0x180b, 0xfeff].map(function (code) {
  return "127.0.0.1" + String.fromCharCode(code);
}), ["12" + String.fromCharCode(0xad) + "7.0.0.1", "0x7f.0.0.1" + String.fromCharCode(0x200b)]);

// A host that is not a usable name: a control character or white space, an
// empty label (two trailing dots, a leading dot, two dots in a row), or a
// code point the WHATWG host parser refuses. Node's matcher strips one
// trailing dot and then accepts "127.0.0.1.." against DNS:127.0.0.1 on
// every release, and on 24.21.0 it accepts "127.0.0.1\t" as well.
var MALFORMED_HOSTS = [
  "127.0.0.1..", "example.com..", "a..b.com", ".example.com", "127.0.0.1\t", "127.0.0.1\n",
  "127.0.0.1\r", "127.0.0.1 ", "exa mple.com", "127.0.0.1\u0000", "a|b.com", "a%41.com",
  "127.0.0%2e1",
].concat([0x85, 0xa0, 0x3000].map(function (code) { return "x" + String.fromCharCode(code) + "y.com"; }),
  ["127.0.0.1" + String.fromCharCode(0x200c)]);

// The dial-host classifier reads a host the way the resolver and the WHATWG
// host parser read it, after full UTS46 mapping: an IP literal, an IPv4
// address in another spelling, a name, or a host that is not a usable name.
function testDialHostForm() {
  var form = b.network.tls._dialHostForm;
  check("network-tls exposes the dial-host classifier", typeof form === "function");
  if (typeof form !== "function") return;
  var ch = String.fromCharCode;
  [["127.0.0.1", "ip"], ["::1", "ip"], ["fe80::1%eth0", "ip"], ["2001:db8::1", "ip"], ["[::1]", "ip"],
   ["[2001:db8:0::1]", "ip"], ["[127.0.0.1]", "malformed"], ["[::1", "malformed"]]
    .forEach(function (c) {
      check("_dialHostForm(" + JSON.stringify(c[0]) + ") is " + c[1], form(c[0]) === c[1], form(c[0]));
    });
  ["127.1", "0x7f.0.0.1", "0177.0.0.1", "2130706433", "127.0.0.1.", "foo.0x", "a.b.0X1F", "999.1.1.1",
   ch(0xff11, 0xff12, 0xff17) + ".0.0.1", ["127", "0", "0", "1"].join(ch(0xff0e)),
   ["127", "0", "0", "1"].join(ch(0x3002)), "127.0.0.1" + ch(0xad) + ".", "12" + ch(0xad) + "7.0.0.1",
   "127.0.0.1" + ch(0xad, 0x200b), "127.0.0.1" + ch(0x3002)]
    .concat([0xad, 0x200b, 0x2060, 0x34f, 0xfe0f, 0x180b, 0xfeff].map(function (code) {
      return "127.0.0.1" + ch(code);
    }))
    .forEach(function (h) {
      check("_dialHostForm(" + JSON.stringify(h) + ") is ip-spelling", form(h) === "ip-spelling", form(h));
    });
  ["", ".", "..", "127.0.0.1..", "example.com..", "a..b.com", ".example.com", "127.0.0.1\t", "127.0.0.1\n",
   "127.0.0.1\r", "127.0.0.1 ", " 127.0.0.1", "exa mple.com", ch(0), "127.0.0.1" + ch(0), "a" + ch(0x7f) + "b.com",
   "a|b.com", "a%41.com", "127.0.0%2e1", "ex%61mple.com", "a<b.com", "a*b.com", "a".repeat(64) + ".com",
   "127.0.0.1" + ch(0x200c), "127.0.0.1" + ch(0x200d)]
    .concat([0x85, 0xa0, 0x3000, 0x2028, 0xd800].map(function (code) { return "x" + ch(code) + "y.com"; }))
    .forEach(function (h) {
      check("_dialHostForm(" + JSON.stringify(h) + ") is malformed", form(h) === "malformed", form(h));
    });
  ["example.com", "EXAMPLE.com", "example.com.", "localhost", "_dmarc.example.com", "xn--bcher-kva.de",
   "b" + ch(0xfc) + "cher.de", "a.0xg", "0x7f.example.com", "127.0.0.1.example.com", "1.example", "123.com",
   "-foo.example.com", "a".repeat(63) + ".com"]
    .forEach(function (h) {
      check("_dialHostForm(" + JSON.stringify(h) + ") is name", form(h) === "name", form(h));
    });
  [null, undefined, 1, {}].forEach(function (v) {
    check("_dialHostForm is malformed for a non-string", form(v) === "malformed");
  });
}

function testCheckServerIdentity9525NonCanonicalIpv4() {
  var csi = b.network.tls.checkServerIdentity9525;
  NON_CANONICAL_IPV4_HOSTS.forEach(function (host) {
    var spellings = [host];
    if (host.charAt(host.length - 1) !== ".") spellings.push(host + ".");
    spellings.forEach(function (h) {
      ["DNS:" + h, "DNS:127.0.0.1", "DNS:*.0.0.1", "IP Address:127.0.0.1",
       "DNS:" + h + ", IP Address:127.0.0.1"].forEach(function (san) {
        var err = csi(h, { subject: {}, subjectaltname: san });
        check("checkServerIdentity9525 refuses the non-canonical IPv4 host " + JSON.stringify(h) +
              " against " + san,
              err instanceof Error && err.code === "tls/pkix-hostname-mismatch",
              err ? err.code : "matched");
      });
    });
  });
  MALFORMED_HOSTS.forEach(function (h) {
    ["DNS:127.0.0.1", "DNS:example.com", "DNS:a..b.com", "DNS:*.example.com", "IP Address:127.0.0.1"]
      .forEach(function (san) {
        var err = csi(h, { subject: {}, subjectaltname: san });
        check("checkServerIdentity9525 refuses the malformed host " + JSON.stringify(h) + " against " + san,
              err instanceof Error && err.code === "tls/pkix-hostname-mismatch",
              err ? err.code : "matched");
      });
  });
  var ok = csi("127.0.0.1", { subject: {}, subjectaltname: "IP Address:127.0.0.1" });
  check("checkServerIdentity9525 still matches 127.0.0.1 against its iPAddress SAN", ok === undefined,
        ok ? ok.code + " " + ok.message : "");
  [["example.com", "DNS:example.com"], ["a.0xg", "DNS:a.0xg"], ["v1.example.com", "DNS:*.example.com"],
   ["0x7f.example.com", "DNS:0x7f.example.com"], ["127.0.0.1.example.com", "DNS:127.0.0.1.example.com"]]
    .forEach(function (c) {
      var e = csi(c[0], { subject: {}, subjectaltname: c[1] });
      check("checkServerIdentity9525 matches the DNS name " + c[0] + " against " + c[1], e === undefined,
            e ? e.code + " " + e.message : "");
    });
}

function testSniForNonCanonicalIpv4() {
  NON_CANONICAL_IPV4_HOSTS.forEach(function (host) {
    check("sniFor sends no SNI for the non-canonical IPv4 host " + JSON.stringify(host),
          b.network.tls.sniFor(host) === undefined, String(b.network.tls.sniFor(host)));
    var id = b.network.tls.identityFor(host);
    check("identityFor gives no server name for " + JSON.stringify(host), JSON.stringify(id) === "{}",
          JSON.stringify(id));
  });
  ["0x0a.0.0.5", "10.5", "012.0.0.5", "10.0.0.5" + String.fromCharCode(0xad),
   "10.0.0.5" + String.fromCharCode(0x200b)].forEach(function (sn) {
    var e = null;
    try { b.network.tls.identityFor("10.0.0.5", sn); } catch (err) { e = err; }
    check("identityFor refuses servername " + sn + " on host 10.0.0.5 as tls/bad-servername",
          e && e.code === "tls/bad-servername", e ? e.code : "accepted");
  });
  MALFORMED_HOSTS.forEach(function (sn) {
    var e = null;
    try { b.network.tls.identityFor("example.com", sn); } catch (err) { e = err; }
    check("identityFor refuses the malformed servername " + JSON.stringify(sn) + " as tls/bad-servername",
          e && e.code === "tls/bad-servername", e ? e.code : "accepted");
  });
  check("sniFor returns a DNS name whose last label is not a number",
        b.network.tls.sniFor("a.0xg") === "a.0xg" && b.network.tls.sniFor("0x7f.example.com") === "0x7f.example.com");
}

// Every framework dial checks the server through the compromised-chain
// wrapper, which falls back to Node's tls.checkServerIdentity. On a Node
// below 24.22.1 that matcher accepted a non-canonical IPv4 host against a
// dNSName SAN, so the wrapper refuses the host before any matcher runs.
async function testDialRefusesNonCanonicalIpv4Host(ca) {
  var innerCalls = 0;
  var wrapped = b.network.tls._withCompromisedChainCheck(function () { innerCalls += 1; return undefined; },
    ca.caCertPem);
  NON_CANONICAL_IPV4_HOSTS.forEach(function (host) {
    var err = wrapped.call(null, host, {});
    check("the dial identity check refuses " + JSON.stringify(host) + " as tls/non-canonical-ip-host",
          err instanceof Error && err.code === "tls/non-canonical-ip-host",
          err ? err.code + " " + err.message : "accepted");
  });
  check("the identity function a caller supplied is not consulted for a non-canonical IPv4 host",
        innerCalls === 0, String(innerCalls));
  MALFORMED_HOSTS.forEach(function (host) {
    var err = wrapped.call(null, host, {});
    check("the dial identity check refuses the malformed host " + JSON.stringify(host) + " as tls/bad-host",
          err instanceof Error && err.code === "tls/bad-host",
          err ? err.code + " " + err.message : "accepted");
  });
  check("the identity function a caller supplied is not consulted for a malformed host",
        innerCalls === 0, String(innerCalls));
  ["example.com", "example.com.", "b" + String.fromCharCode(0xfc) + "cher.de", "xn--bcher-kva.de", "_dmarc.example.com"].forEach(function (host) {
    wrapped.call(null, host, {});
  });
  check("the identity function a caller supplied is consulted for a name", innerCalls === 5, String(innerCalls));

  var leaf = await _leaf(ca, ["DNS:localhost", "DNS:127.0.0.1", "DNS:0177.0.0.1", "DNS:127.1",
    "DNS:2130706433"]);
  var srv = await _startTlsServer(leaf, "127.0.0.1", function (s) { s.end(); });
  function lookup(_h, o, cb) {
    if (o && o.all) cb(null, [{ address: "127.0.0.1", family: 4 }]);
    else cb(null, "127.0.0.1", 4);
  }
  function dial(host) {
    return new Promise(function (resolve) {
      var opts = Object.assign(b.network.tls.buildOptions({ ca: ca.caCertPem }),
        { host: host, port: srv.port, lookup: lookup });
      var sock = nodeTls.connect(opts); // allow:outbound-tls-posture — buildOptions carries the posture
      sock.once("secureConnect", function () { sock.destroy(); resolve(null); });
      sock.once("error", function (e) { sock.destroy(); resolve(e); });
    });
  }
  try {
    var hosts = ["0177.0.0.1", "127.1", "2130706433"].concat([0xad, 0x200b, 0xfe0f].map(function (code) {
      return "127.0.0.1" + String.fromCharCode(code);
    }));
    for (var i = 0; i < hosts.length; i++) {
      var e = await dial(hosts[i]);
      check("a dial to " + JSON.stringify(hosts[i]) + " is refused as tls/non-canonical-ip-host",
            e && e.code === "tls/non-canonical-ip-host", e ? e.code + " " + e.message : "connected");
    }
    var badHosts = ["127.0.0.1..", "127.0.0.1\t", "127.0.0.1\n"];
    for (var bi = 0; bi < badHosts.length; bi++) {
      var be = await dial(badHosts[bi]);
      check("a dial to " + JSON.stringify(badHosts[bi]) + " is refused as tls/bad-host",
            be && be.code === "tls/bad-host", be ? be.code + " " + be.message : "connected");
    }
    var named = await dial("localhost");
    check("a dial to the same server by name completes", named === null,
          named ? named.code + " " + named.message : "");
    var httpsLookups = 0;
    var origQueryHttps = networkDns.queryHttps;
    networkDns.queryHttps = function () { httpsLookups += 1; return Promise.reject(new Error("not consulted")); };
    var echErr = null; var echSock = null;
    try {
      echSock = await b.network.tls.connectWithEch({ host: "127.1", port: srv.port, ca: ca.caCertPem,
        timeoutMs: 4000 });
    } catch (e) { echErr = e; } finally { networkDns.queryHttps = origQueryHttps; }
    if (echSock) { try { echSock.destroy(); } catch (_e) { /* best-effort */ } }
    check("connectWithEch to 127.1 does not look up an HTTPS record for an address",
          httpsLookups === 0, String(httpsLookups));
    check("connectWithEch to 127.1 rejects with tls/non-canonical-ip-host",
          echErr && echErr.code === "tls/non-canonical-ip-host", echErr ? echErr.code : "connected");
  } finally { _close(srv); }
}

// With an explicit servername, Node hands the certificate check the servername
// and not the dial host, so the dial host is checked on its own. Each dial is
// driven against a leaf for DNS:localhost and IP:127.0.0.1 with servername
// "localhost"; a lookup stub maps every name to 127.0.0.1 so the dial reaches
// the handshake on every platform.
var SERVERNAME_DIAL_CASES = [
  ["127.1", "tls/non-canonical-ip-host"], ["0x7f.0.0.1", "tls/non-canonical-ip-host"],
  ["127.0.0.1.", "tls/non-canonical-ip-host"], ["2130706433", "tls/non-canonical-ip-host"],
  ["127.0.0.1..", "tls/bad-host"], ["127.0.0.1\t", "tls/bad-host"], ["localhost..", "tls/bad-host"],
];

function _stubAddressLookup() {
  var asked = [];
  var origLookup = nodeDns.lookup;
  var origNdLookup = networkDns.lookup;
  nodeDns.lookup = function (h, o, cb) {
    asked.push(h);
    var done = typeof o === "function" ? o : cb;
    if (o && typeof o === "object" && o.all) done(null, [{ address: "127.0.0.1", family: 4 }]);
    else done(null, "127.0.0.1", 4);
  };
  networkDns.lookup = function (h) {
    asked.push(h);
    return Promise.resolve([{ address: "127.0.0.1", family: 4 }]);
  };
  return {
    asked: asked,
    restore: function () { nodeDns.lookup = origLookup; networkDns.lookup = origNdLookup; },
  };
}

async function testDialHostCheckedWhenAServernameIsSet(ca) {
  var leaf = await _leaf(ca, ["DNS:localhost", "IP:127.0.0.1"]);
  var srv = await _startTlsServer(leaf, "127.0.0.1", function (s) {
    s.on("data", function () {
      try { s.end("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"); }
      catch (_e) { /* client gone */ }
    });
  });
  var stub = _stubAddressLookup();
  function rawDial(host) {
    return new Promise(function (resolve) {
      var opts;
      try {
        opts = Object.assign({ host: host, port: srv.port }, b.network.tls.identityFor(host, "localhost"),
          b.network.tls.buildOptions({ ca: ca.caCertPem }));
      } catch (e) { resolve(e); return; }
      var sock = nodeTls.connect(opts); // allow:outbound-tls-posture — buildOptions carries the posture
      sock.once("secureConnect", function () { sock.destroy(); resolve(null); });
      sock.once("error", function (e) { sock.destroy(); resolve(e); });
    });
  }
  async function redisDial(host) {
    var rc = null;
    try {
      rc = redisClient.create({ url: "rediss://localhost:" + srv.port + "/0", host: host, servername: "localhost",
        ca: ca.caCertPem, connectTimeoutMs: 4000, maxReconnectAttempts: 0 });
      await rc.connect();
      return null;
    } catch (e) { return e; }
    finally { if (rc) await rc.close().catch(function () { /* best-effort */ }); }
  }
  async function httpClientDial(host) {
    var agent = new https.Agent({ ca: [ca.caCertPem], servername: "localhost", keepAlive: false });
    try {
      await b.httpClient.request({ url: "https://" + host + ":" + srv.port + "/", allowInternal: true,
        agent: agent, timeoutMs: 4000 });
      return null;
    } catch (e) { return e; }
    finally { agent.destroy(); }
  }
  function socketDial(host) {
    return new Promise(function (resolve) {
      var plain = net.connect({ host: host, port: srv.port });
      plain.once("error", function (e) { resolve(e); });
      plain.once("connect", function () {
        var opts = Object.assign(b.network.tls.buildOptions({ ca: ca.caCertPem }),
          { socket: plain, servername: "localhost" });
        var sock = nodeTls.connect(opts); // allow:outbound-tls-posture — buildOptions carries the posture
        sock.once("secureConnect", function () { sock.destroy(); resolve(null); });
        sock.once("error", function (e) { sock.destroy(); plain.destroy(); resolve(e); });
      });
    });
  }
  function codeOf(e) {
    if (!e) return null;
    if (typeof e.code === "string" && e.code.indexOf("tls/") === 0) return e.code;
    return e.cause && typeof e.cause.code === "string" ? e.cause.code : e.code;
  }
  function seen(e) { return e ? codeOf(e) + " " + e.message : "connected"; }
  try {
    for (var i = 0; i < SERVERNAME_DIAL_CASES.length; i++) {
      var host = SERVERNAME_DIAL_CASES[i][0];
      var want = SERVERNAME_DIAL_CASES[i][1];
      var raw = await rawDial(host);
      check("a buildOptions dial to " + JSON.stringify(host) + " with servername localhost is refused as " + want,
            codeOf(raw) === want, seen(raw));
      if (host.indexOf("\t") === -1) {
        var sd = await socketDial(host);
        check("a buildOptions dial over a socket connected to " + JSON.stringify(host) +
              " with servername localhost and no host is refused as " + want, codeOf(sd) === want, seen(sd));
      }
      var re = await redisDial(host);
      var reason = want === "tls/bad-host" ? "is not a valid host name" : "non-canonical spelling";
      check("b.redis to " + JSON.stringify(host) + " with servername localhost is refused as redis-client/connect " +
            "carrying the " + want + " reason",
            re !== null && re.code === "redis-client/connect" && String(re.message).indexOf(reason) !== -1, seen(re));
      if (host === "localhost..") {
        var he = await httpClientDial(host);
        check("b.httpClient to " + JSON.stringify(host) + " through an agent with servername localhost is " +
              "refused as " + want, codeOf(he) === want || String(he && he.message).indexOf(want) !== -1, seen(he));
      }
    }
    var rawOk = await rawDial("127.0.0.1");
    check("control: a buildOptions dial to 127.0.0.1 with servername localhost completes", rawOk === null, seen(rawOk));
    var socketOk = await socketDial("127.0.0.1");
    check("control: a buildOptions dial over a socket connected to 127.0.0.1 with servername localhost completes",
          socketOk === null, seen(socketOk));
    var redisOk = await redisDial("127.0.0.1");
    check("control: b.redis to 127.0.0.1 with servername localhost completes", redisOk === null, seen(redisOk));
    var httpOk = await httpClientDial("localhost");
    check("control: b.httpClient to localhost through an agent with servername localhost completes",
          httpOk === null, seen(httpOk));
  } finally { stub.restore(); _close(srv); }
}

// connectWithEch refuses a malformed host before it asks DNS for an HTTPS
// record, so no query leaves the process for a name the dial would refuse.
async function testConnectWithEchRefusesAMalformedHostBeforeTheLookup() {
  var hosts = ["127.0.0.1..", "a..b.com", ".example.com", "127.0.0.1\t", "exa mple.com", "a%41.com"];
  var asked = [];
  var origQueryHttps = networkDns.queryHttps;
  networkDns.queryHttps = function (h) { asked.push(h); return Promise.reject(new Error("not consulted")); };
  try {
    for (var i = 0; i < hosts.length; i++) {
      var err = null;
      var sock = null;
      try {
        sock = await b.network.tls.connectWithEch({ host: hosts[i], port: 1, timeoutMs: 2000 });
      } catch (e) { err = e; }
      if (sock) { try { sock.destroy(); } catch (_e) { /* best-effort */ } }
      check("connectWithEch rejects the malformed host " + JSON.stringify(hosts[i]) + " with tls/bad-host",
            err && err.code === "tls/bad-host", err ? err.code + " " + err.message : "connected");
    }
  } finally { networkDns.queryHttps = origQueryHttps; }
  check("connectWithEch asks for no HTTPS record for a malformed host", asked.length === 0, JSON.stringify(asked));
}

// connectWithEch refuses a host that the resolver reads as an IPv4 address in
// a non-canonical spelling before any lookup: no HTTPS-record query and no
// A/AAAA lookup leaves the process, with or without an echOverride.
async function testConnectWithEchRefusesANonCanonicalIpv4HostBeforeAnyLookup() {
  var httpsAsked = [];
  var addrAsked = [];
  var origQueryHttps = networkDns.queryHttps;
  var origLookup = nodeDns.lookup;
  networkDns.queryHttps = function (h) { httpsAsked.push(h); return Promise.reject(new Error("not consulted")); };
  nodeDns.lookup = function (h, o, cb) {
    addrAsked.push(h);
    var done = typeof o === "function" ? o : cb;
    var e = new Error("lookup refused in this test");
    e.code = "ENOTFOUND";
    process.nextTick(function () { done(e); });
  };
  var override = Buffer.from([0x00, 0x00]);
  try {
    for (var i = 0; i < NON_CANONICAL_IPV4_HOSTS.length; i++) {
      var host = NON_CANONICAL_IPV4_HOSTS[i];
      var variants = [{ host: host, port: 1, timeoutMs: 2000 },
        { host: host, port: 1, timeoutMs: 2000, echOverride: override }];
      for (var v = 0; v < variants.length; v++) {
        var err = null;
        var sock = null;
        try { sock = await b.network.tls.connectWithEch(variants[v]); }
        catch (e) { err = e; }
        if (sock) { try { sock.destroy(); } catch (_e) { /* best-effort */ } }
        check("connectWithEch" + (v === 1 ? " with an echOverride" : "") + " rejects " + JSON.stringify(host) +
              " with tls/non-canonical-ip-host",
              err && err.code === "tls/non-canonical-ip-host", err ? err.code + " " + err.message : "connected");
      }
    }
  } finally { networkDns.queryHttps = origQueryHttps; nodeDns.lookup = origLookup; }
  check("connectWithEch asks for no HTTPS record for a non-canonical IPv4 host", httpsAsked.length === 0,
        JSON.stringify(httpsAsked));
  check("connectWithEch looks up no address for a non-canonical IPv4 host", addrAsked.length === 0,
        JSON.stringify(addrAsked));
}

// identityFor is configuration-time: its own options are checked whether or
// not the servername would be refused.
function testIdentityForValidatesItsOpts() {
  var identityFor = b.network.tls.identityFor;
  function thrown(fn) { try { fn(); return null; } catch (e) { return e; } }
  [
    ["errorClass \"x\"", { errorClass: "x" }],
    ["errorClass {}", { errorClass: {} }],
    ["code 5", { code: 5 }],
    ["code \"\"", { code: "" }],
    ["label 7", { label: 7 }],
    ["label \"\"", { label: "" }],
  ].forEach(function (c) {
    ["::1", "::2"].forEach(function (sn) {
      var e = thrown(function () { identityFor("::1", sn, c[1]); });
      check("identityFor refuses opts." + c[0] + " (servername " + sn + ") as tls/bad-identity-opts",
            e && e.code === "tls/bad-identity-opts" && e instanceof b.network.tls.NetworkTlsError,
            e ? e.code + " " + e.message : "accepted");
    });
  });
  var viaFactory = thrown(function () {
    identityFor("::1", "::2", { errorClass: { factory: function (code, msg) { var e = new Error(msg); e.code = code; return e; } },
      code: "x/bad" });
  });
  check("identityFor accepts an errorClass carrying factory()", viaFactory && viaFactory.code === "x/bad",
        viaFactory ? viaFactory.code : "accepted");
  check("identityFor accepts an error class constructor",
        thrown(function () { identityFor("::1", "::1", { errorClass: b.network.dns.DnsError, code: "dns/x", label: "l" }); }) === null);
}

// buildOptions builds dial options without a host, so an address in `sni`
// cannot be compared to one and is refused.
function testBuildOptionsSni() {
  var named = b.network.tls.buildOptions({ sni: "example.com" });
  check("buildOptions: a name in sni is the server name", named.servername === "example.com",
        String(named.servername));
  ["127.0.0.1", "::1", "[::1]"].forEach(function (addr) {
    var err = null; var out = null;
    try { out = b.network.tls.buildOptions({ sni: addr }); } catch (e) { err = e; }
    check("buildOptions: an address in sni (" + addr + ") is refused",
          err && err.code === "network-tls/bad-tls-options" && /sni/.test(err.message),
          err ? err.code : "servername=" + JSON.stringify(out && out.servername));
  });
  ["127.0.0.1" + String.fromCharCode(0xad), "0x7f.0.0.1"].concat(MALFORMED_HOSTS).forEach(function (sni) {
    var err = null; var out = null;
    try { out = b.network.tls.buildOptions({ sni: sni }); } catch (e) { err = e; }
    check("buildOptions: sni " + JSON.stringify(sni) + " is refused",
          err && err.code === "network-tls/bad-tls-options" && /sni/.test(err.message),
          err ? err.code : "servername=" + JSON.stringify(out && out.servername));
  });
}

// An explicit servername that names an address other than the host is
// refused before the dial: the certificate would otherwise be checked
// against the host, an identity the caller did not name.
async function testServernameNamingAnotherAddress(ca) {
  var leaf = await _leaf(ca, ["DNS:localhost", "IP:127.0.0.1"]);
  var srv = await _startTlsServer(leaf, "127.0.0.1");
  try {
    var echErr = null;
    try {
      var p = b.network.tls.connectWithEch({ host: "127.0.0.1", servername: "127.0.0.2", port: srv.port,
        ca: ca.caCertPem, timeoutMs: 4000 });
      var s = await p.catch(function (e) { echErr = e; return null; });
      if (s) s.destroy();
    } catch (e) { echErr = e; }
    check("connectWithEch: a servername naming another address is refused as tls/ech-bad-opts",
          echErr && echErr.code === "tls/ech-bad-opts" && /servername/.test(echErr.message),
          echErr ? echErr.code + " " + echErr.message : "connected");

    var dotErr = null;
    networkDns._resetForTest();
    try { networkDns.useDnsOverTls({ host: "127.0.0.1", port: srv.port, servername: "127.0.0.2", ca: ca.caCertPem }); }
    catch (e) { dotErr = e; }
    networkDns._resetForTest();
    check("useDnsOverTls: a servername naming another address is refused as dns/bad-dot-servername",
          dotErr && dotErr.code === "dns/bad-dot-servername", dotErr ? dotErr.code : "accepted");

    var ntsErr = null;
    try {
      await networkNts.performKeHandshake({ host: "127.0.0.1", port: srv.port, servername: "127.0.0.2",
        ca: ca.caCertPem, timeoutMs: 2000 });
    } catch (e) { ntsErr = e; }
    check("nts.performKeHandshake: a servername naming another address is refused as nts/bad-servername",
          ntsErr && ntsErr.code === "nts/bad-servername", ntsErr ? ntsErr.code + " " + ntsErr.message : "accepted");

    var ocspErr = null;
    try {
      await b.network.tls.ocsp.connect({ host: "127.0.0.1", port: srv.port, servername: "127.0.0.2",
        ca: ca.caCertPem });
    } catch (e) { ocspErr = e; }
    check("ocsp.connect: a servername naming another address is refused as tls/bad-servername",
          ocspErr && ocspErr.code === "tls/bad-servername", ocspErr ? ocspErr.code + " " + ocspErr.message : "accepted");
    await helpers.passiveObserve(100, "servername naming another address: no dial");
    check("a servername naming another address opens no connection", srv.connections === 0,
          String(srv.connections));
  } finally { _close(srv); }
}

// The OCSP probe dials with the caller's options. A host name is sent as
// SNI, and an IP literal (as the host or as servername) sends none.
async function testOcspConnectIdentity(ca) {
  var leaf = await _leaf(ca, ["DNS:localhost", "IP:127.0.0.1"]);
  var cases = [
    { label: "a host name", opts: { host: "localhost", family: 4 }, sni: ["localhost"] },
    { label: "an IPv4 servername equal to the host", opts: { host: "127.0.0.1", servername: "127.0.0.1" }, sni: [] },
  ];
  for (var i = 0; i < cases.length; i++) {
    var srv = await _startTlsServer(leaf, "127.0.0.1");
    var err = null; var rv = null;
    try {
      rv = await b.network.tls.ocsp.connect(Object.assign({ port: srv.port, ca: ca.caCertPem }, cases[i].opts));
    } catch (e) { err = e; }
    finally { _close(srv); }
    check("ocsp.connect with " + cases[i].label + " completes the handshake",
          rv && rv.authorized === true, err ? err.code + " " + err.message : JSON.stringify(rv && rv.authorized));
    check("ocsp.connect with " + cases[i].label + " sends SNI " + JSON.stringify(cases[i].sni),
          JSON.stringify(srv.sni) === JSON.stringify(cases[i].sni), JSON.stringify(srv.sni));
  }
}

// The https proxy agent takes servername from the request. One naming an
// address other than the target is refused through the callback, before any
// connection is made.
async function testProxyAgentServernameNamingAnotherAddress() {
  networkProxy._resetForTest();
  networkProxy.set({ https: "https://127.0.0.1:9" });
  var agent = networkProxy.agentFor("https://127.0.0.1:9/");
  var err = null;
  try {
    await helpers.withTestTimeout("proxy agent: servername naming another address", function () {
      return new Promise(function (resolve) {
        agent.createConnection({ host: "127.0.0.1", port: 9, servername: "127.0.0.2" }, function (e, s) {
          err = e;
          if (s) { try { s.destroy(); } catch (_e) { /* best-effort */ } }
          resolve();
        });
      });
    }, { timeoutMs: 9000 });
  } finally { networkProxy._resetForTest(); }
  check("the proxy agent refuses a servername naming another address as proxy/bad-servername",
        err && err.code === "proxy/bad-servername", err ? err.code + " " + err.message : "no error");
}

async function testConnectWithEchToAnIpLiteral(ca) {
  var leaf = await _leaf(ca, ["DNS:localhost", "IP:127.0.0.1", "IP:::1"]);
  var targets = ["127.0.0.1"];
  if (_hasIpv6Loopback()) targets.push("::1");
  else helpers.unavailable("connectWithEch to ::1", "no ::1 loopback on this host");
  // An address has no HTTPS record to carry an ECH config, so the dial does
  // not look one up.
  var httpsLookups = 0;
  var origQueryHttps = networkDns.queryHttps;
  networkDns.queryHttps = function () { httpsLookups += 1; return Promise.reject(new Error("not consulted")); };
  var results = [];
  try {
    for (var i = 0; i < targets.length; i++) {
      var srv = await _startTlsServer(leaf, targets[i]);
      var sock = null; var err = null;
      try {
        sock = await b.network.tls.connectWithEch({ host: targets[i], port: srv.port, ca: ca.caCertPem, timeoutMs: 4000 });
      } catch (e) { err = e; }
      if (sock) { try { sock.destroy(); } catch (_e) { /* best-effort */ } }
      _close(srv);
      results.push({ host: targets[i], sock: sock, err: err, srv: srv, lookups: httpsLookups });
    }
  } finally { networkDns.queryHttps = origQueryHttps; }
  results.forEach(function (r) {
    check("connectWithEch to " + r.host + " does not look up an HTTPS record for an address",
          r.lookups === 0, String(r.lookups));
    check("connectWithEch to " + r.host + " completes the handshake", r.sock !== null,
          r.err ? (r.err.code + " :: " + r.err.message) : "");
    check("connectWithEch to " + r.host + " sent no SNI",
          r.srv.connections === 1 && r.srv.sni.length === 0, JSON.stringify({ c: r.srv.connections, sni: r.srv.sni }));
  });
}

async function testDnsOverTlsToAnIpLiteral(ca) {
  var leaf = await _leaf(ca, ["DNS:localhost", "IP:127.0.0.1"]);
  var srv = await _startTlsServer(leaf, "127.0.0.1", function () { /* never answers */ });
  networkDns._resetForTest();
  networkDns.setLookupTimeoutMs(1000);
  var err = null;
  try {
    networkDns.useDnsOverTls({ host: "127.0.0.1", port: srv.port, ca: ca.caCertPem });
    await networkDns.resolve4("example.com").catch(function (e) { err = e; });
    await helpers.waitUntil(function () { return srv.connections >= 1 || err !== null; },
      { timeoutMs: 5000, label: "dns-over-tls: dial to 127.0.0.1" });
  } finally {
    networkDns._resetForTest();
    _close(srv);
  }
  check("DNS-over-TLS to 127.0.0.1 reaches the server", srv.connections >= 1,
        err ? (err.code + " :: " + err.message) : "");
  check("DNS-over-TLS to 127.0.0.1 completes the handshake with no SNI",
        srv.secure.length >= 1 && srv.secure[0] === false && srv.sni.length === 0,
        JSON.stringify({ secure: srv.secure, sni: srv.sni }));
}

// The default DoT resolver is an address (1.1.1.1). Its dial options are
// captured rather than sent, so this does not touch the network.
async function testDnsOverTlsDefaultResolverCarriesNoIpSni() {
  var origConnect = nodeTls.connect;
  var captured = null;
  var prevEnv = process.env.BLAMEJS_DNS_TRANSPORT;
  networkDns._resetForTest();
  process.env.BLAMEJS_DNS_TRANSPORT = "dot";
  nodeTls.connect = function (opts) {
    if (captured === null && opts && typeof opts === "object") captured = Object.assign({}, opts);
    var s = origConnect.call(nodeTls, { host: "127.0.0.1", port: 1 });
    s.on("error", function () { /* nothing listens on port 1 */ });
    return s;
  };
  try {
    networkDns.setLookupTimeoutMs(500);
    await networkDns.lookup("example.com").catch(function () { /* expected */ });
    await helpers.waitUntil(function () { return captured !== null; },
      { timeoutMs: 5000, label: "dns-over-tls default: dial captured" });
  } catch (_e) { /* asserted below */ }
  finally {
    nodeTls.connect = origConnect;
    if (prevEnv === undefined) delete process.env.BLAMEJS_DNS_TRANSPORT;
    else process.env.BLAMEJS_DNS_TRANSPORT = prevEnv;
    networkDns._resetForTest();
  }
  check("the BLAMEJS_DNS_TRANSPORT=dot default dials 1.1.1.1", captured && captured.host === "1.1.1.1",
        JSON.stringify(captured && captured.host));
  check("the BLAMEJS_DNS_TRANSPORT=dot default sets no IP-literal server name",
        captured && (captured.servername === undefined || captured.servername === null),
        JSON.stringify(captured && captured.servername));
}

// The controls for the address cases above: a dial to a host name, or with
// an explicit name in `servername`, still sends that name as SNI.
async function testDialsByNameSendTheName(ca) {
  var leaf = await _leaf(ca, ["DNS:localhost", "IP:127.0.0.1", "IP:::1"]);

  var origQueryHttps = networkDns.queryHttps;
  networkDns.queryHttps = function () { return Promise.reject(new Error("no HTTPS record in this test")); };
  var ech = await _startTlsServer(leaf, "127.0.0.1");
  var echIp = await _startTlsServer(leaf, "127.0.0.1");
  var echErr = null; var echIpErr = null;
  try {
    var s1 = await b.network.tls.connectWithEch({ host: "localhost", port: ech.port, ca: ca.caCertPem, ipFamily: 4, timeoutMs: 4000 })
      .catch(function (e) { echErr = e; return null; });
    if (s1) s1.destroy();
    var s2 = await b.network.tls.connectWithEch({ host: "127.0.0.1", servername: "localhost", port: echIp.port, ca: ca.caCertPem, timeoutMs: 4000 })
      .catch(function (e) { echIpErr = e; return null; });
    if (s2) s2.destroy();
  } finally { networkDns.queryHttps = origQueryHttps; _close(ech); _close(echIp); }
  check("connectWithEch to localhost sends SNI localhost",
        ech.sni.length === 1 && ech.sni[0] === "localhost",
        echErr ? (echErr.code + " :: " + echErr.message) : JSON.stringify(ech.sni));
  check("connectWithEch to 127.0.0.1 with servername localhost sends SNI localhost",
        echIp.sni.length === 1 && echIp.sni[0] === "localhost",
        echIpErr ? (echIpErr.code + " :: " + echIpErr.message) : JSON.stringify(echIp.sni));

  var dotCases = [
    ["DNS-over-TLS to localhost", { host: "localhost" }],
    ["DNS-over-TLS to 127.0.0.1 with servername localhost", { host: "127.0.0.1", servername: "localhost" }],
  ];
  for (var i = 0; i < dotCases.length; i++) {
    var srv = await _startTlsServer(leaf, "127.0.0.1", function () { /* never answers */ });
    networkDns._resetForTest();
    networkDns.setLookupTimeoutMs(1000);
    try {
      networkDns.useDnsOverTls(Object.assign({ port: srv.port, ca: ca.caCertPem }, dotCases[i][1]));
      var lookup = networkDns.resolve4("example.com").catch(function () { /* the server never answers */ });
      await helpers.waitUntil(function () { return srv.sni.length >= 1; },
        { timeoutMs: 5000, label: dotCases[i][0] + ": ClientHello received" }).catch(function () { /* asserted below */ });
      await lookup;
    } finally {
      networkDns._resetForTest();
      _close(srv);
    }
    check(dotCases[i][0] + " sends SNI localhost", srv.sni.length >= 1 && srv.sni[0] === "localhost",
          JSON.stringify(srv.sni));
  }
}

// servername is configuration, so a value of the wrong type is refused where
// it is set rather than dialed without SNI.
function testServernameMustBeAString() {
  [42, {}, ""].forEach(function (sn) {
    var code = null;
    try { networkDns.useDnsOverTls({ host: "127.0.0.1", servername: sn }); } catch (e) { code = e && e.code; }
    networkDns._resetForTest();
    check("useDnsOverTls refuses servername " + JSON.stringify(sn), code === "dns/bad-dot-servername", String(code));
    var echCode = null;
    try {
      var p = b.network.tls.connectWithEch({ host: "127.0.0.1", port: 1, servername: sn });
      if (p && p.catch) p.catch(function () { /* not reached when the opts are refused */ });
    } catch (e) { echCode = e && e.code; }
    check("connectWithEch refuses servername " + JSON.stringify(sn), echCode === "tls/ech-bad-opts", String(echCode));
  });
}

// A `ca` entry that is neither a string nor a Buffer rejects the promise
// connectWithEch returns with network-tls/bad-tls-options, for a host name
// (dialed after the HTTPS-record lookup) as for an address. For a host name
// the failure was raised inside the lookup's handlers: the promise never
// settled and the error surfaced as an unhandled rejection.
async function testConnectWithEchBadCaRejects() {
  var unhandled = [];
  function onUnhandled(e) { unhandled.push(e); }
  process.on("unhandledRejection", onUnhandled);
  var results = [];
  try {
    var hosts = ["localhost", "127.0.0.1"];
    for (var i = 0; i < hosts.length; i += 1) {
      var outcome = "pending";
      try {
        await helpers.withTestTimeout("connectWithEch bad ca to " + hosts[i], function () {
          return b.network.tls.connectWithEch({ host: hosts[i], port: 1, ca: [123], timeoutMs: 2000 })
            .then(function (s) { outcome = "resolved"; try { s.destroy(); } catch (_e) { /* best-effort */ } },
                  function (e) { outcome = "rejected:" + (e && e.code); });
        }, { timeoutMs: 8000 });
      } catch (_e) { /* outcome stays pending */ }
      results.push({ host: hosts[i], outcome: outcome });
    }
    await helpers.passiveObserve(100, "connectWithEch bad ca: no late unhandled rejection");
  } finally {
    process.removeListener("unhandledRejection", onUnhandled);
  }
  results.forEach(function (r) {
    check("connectWithEch to " + r.host + " with a non-PEM ca entry rejects with network-tls/bad-tls-options",
          r.outcome === "rejected:network-tls/bad-tls-options", r.outcome);
  });
  check("connectWithEch with a non-PEM ca entry leaves no unhandled rejection",
        unhandled.length === 0, unhandled.map(function (e) { return (e && e.code) + " :: " + (e && e.message); }).join(" | "));
}

// An operator host written as a bracketed IPv6 literal (`[::1]`) is dialed
// as the address. Handed to tls.connect with the brackets, Node checks the
// certificate against the text `[::1]` and the handshake fails with
// ERR_TLS_CERT_ALTNAME_INVALID. The server presents a certificate carrying
// only IP:::1, and each dial must complete its handshake.
async function testBracketedIpv6HostDials(ca) {
  if (!_hasIpv6Loopback()) {
    helpers.unavailable("dials to a bracketed IPv6 host", "no ::1 loopback on this host");
    return;
  }
  var leaf = await _leaf(ca, ["IP:::1"]);
  var srv;

  srv = await _startTlsServer(leaf, "::1");
  var echErr = null;
  try {
    var s = await b.network.tls.connectWithEch({ host: "[::1]", port: srv.port, ca: ca.caCertPem, timeoutMs: 4000 })
      .catch(function (e) { echErr = e; return null; });
    if (s) {
      await helpers.waitUntil(function () { return srv.secure.length >= 1; },
        { timeoutMs: 5000, label: "connectWithEch to [::1]: server side of the handshake" }).catch(function () { /* asserted below */ });
      s.destroy();
    }
  } finally { _close(srv); }
  check("connectWithEch to host [::1] verifies the IP:::1 certificate",
        echErr === null && srv.secure.length === 1, echErr ? echErr.code + " :: " + echErr.message : JSON.stringify(srv.secure));

  srv = await _startTlsServer(leaf, "::1", function () { /* never answers */ });
  networkDns._resetForTest();
  networkDns.setLookupTimeoutMs(1000);
  var dotState = null;
  try {
    networkDns.useDnsOverTls({ host: "[::1]", port: srv.port, ca: ca.caCertPem });
    dotState = networkDns._stateForTest ? networkDns._stateForTest() : null;
    var lookup = networkDns.resolve4("example.com").catch(function () { /* the server never answers */ });
    await helpers.waitUntil(function () { return srv.secure.length >= 1 || srv.peerClosed >= 1; },
      { timeoutMs: 5000, label: "dns-over-tls to [::1]: handshake settles" }).catch(function () { /* asserted below */ });
    await lookup;
  } finally { networkDns._resetForTest(); _close(srv); }
  check("DNS-over-TLS to host [::1] verifies the IP:::1 certificate", srv.secure.length >= 1,
        JSON.stringify({ c: srv.connections, secure: srv.secure, state: dotState && dotState.dot }));

  srv = await _startTlsServer(leaf, "::1");
  var ntsErr = null;
  try {
    await networkNts.performKeHandshake({ host: "[::1]", port: srv.port, ca: ca.caCertPem, timeoutMs: 4000 });
  } catch (e) { ntsErr = e; }
  finally { _close(srv); }
  check("NTS-KE to host [::1] verifies the IP:::1 certificate (stops at ALPN, after the handshake)",
        ntsErr && ntsErr.code === "nts/bad-alpn", ntsErr ? ntsErr.code + " :: " + ntsErr.message : "resolved");

  srv = await _startTlsServer(leaf, "::1");
  var ocspErr = null; var rv = null;
  try { rv = await b.network.tls.ocsp.connect({ host: "[::1]", port: srv.port, ca: ca.caCertPem }); }
  catch (e) { ocspErr = e; }
  finally { _close(srv); }
  check("ocsp.connect to host [::1] verifies the IP:::1 certificate", rv && rv.authorized === true,
        ocspErr ? ocspErr.code + " :: " + ocspErr.message : JSON.stringify(rv && rv.authorized));

  srv = await _startTlsServer(leaf, "::1", function () { /* never greets */ });
  try {
    await b.mail.transports.smtp({ host: "[::1]", port: srv.port, implicitTls: true, ca: ca.caCertPem,
      preferFamily: 6, timeoutMs: 1500 })
      .send({ from: "s@a.test", to: "r@b.test", subject: "s", text: "t" })
      .catch(function () { /* the server never greets */ });
  } finally { _close(srv); }
  check("the SMTP transport to host [::1] verifies the IP:::1 certificate", srv.secure.length >= 1,
        JSON.stringify({ c: srv.connections, secure: srv.secure }));

  srv = await _startTlsServer(leaf, "::1");
  var redisErr = null; var rc = null;
  try {
    rc = redisClient.create({ url: "rediss://localhost:" + srv.port + "/0", host: "[::1]", ca: ca.caCertPem,
      connectTimeoutMs: 4000, maxReconnectAttempts: 0 });
    await rc.connect();
  } catch (e) { redisErr = e; }
  finally { if (rc) await rc.close().catch(function () { /* best-effort */ }); _close(srv); }
  check("the Redis client to host [::1] verifies the IP:::1 certificate", redisErr === null,
        redisErr ? redisErr.code + " :: " + redisErr.message : "");
}

// NO_PROXY entries name IPv6 targets the way they are written in a URL or
// without brackets, by address, and as IPv6 CIDR ranges.
function testNoProxyMatchesIpv6Targets() {
  networkProxy._resetForTest();
  networkProxy.set({
    http: "http://127.0.0.1:3128", https: "http://127.0.0.1:3128",
    no: "localhost,127.0.0.1,::1,[2001:db8::5],fd00::/8,0:0:0:0:0:0:0:2,::ffff:192.0.2.9,EXAMPLE.ORG",
  });
  try {
    [
      ["http://127.0.0.1:8080/", false],
      ["http://localhost:8080/", false],
      ["http://[::1]:8080/", false],
      ["https://[::1]:8443/", false],
      ["https://[2001:db8::5]/", false],
      ["http://[fd00::5]/", false],
      ["http://[::2]/", false],
      ["http://[::ffff:c000:209]/", false],
      ["https://www.example.org/", false],
      ["https://[2001:db8::6]/", true],
      ["http://[fe00::1]/", true],
      ["http://[::ffff:c000:20a]/", true],
      ["https://example.com/", true],
    ].forEach(function (c) {
      var got = networkProxy.shouldProxy(c[0]);
      check("NO_PROXY: shouldProxy(" + c[0] + ") is " + c[1], got === c[1], String(got));
    });
  } finally { networkProxy._resetForTest(); }
}

// A proxy that closes the connection before the TLS handshake to it
// completes ends the attempt with Node's handshake error (ECONNRESET) on
// every platform. On Linux the FIN arrives as an 'end' event before Node
// raises that error, and a CONNECT-reply check listening on 'end' reported
// proxy/connect-closed for a proxy that never finished TLS.
async function testHttpsProxyClosingBeforeTheTlsHandshake() {
  var proxy = net.createServer(function (sock) { sock.destroy(); });
  await new Promise(function (res) { proxy.listen(0, "127.0.0.1", res); });
  networkProxy._resetForTest();
  networkProxy._setConnectTimeoutForTest(4000);
  networkProxy.set({ https: "https://127.0.0.1:" + proxy.address().port });
  var agent = networkProxy.agentFor("https://127.0.0.1:9/");
  var err = null;
  try {
    await helpers.withTestTimeout("https proxy closed before the TLS handshake", function () {
      return new Promise(function (resolve) {
        agent.createConnection({ host: "127.0.0.1", port: 9 }, function (e, s) {
          err = e;
          if (s) { try { s.destroy(); } catch (_e) { /* best-effort */ } }
          resolve();
        });
      });
    }, { timeoutMs: 9000 });
  } finally {
    networkProxy._setConnectTimeoutForTest(null);
    networkProxy._resetForTest();
    try { proxy.close(); } catch (_e) { /* best-effort */ }
  }
  check("an https proxy that closes before the TLS handshake reports the handshake failure (ECONNRESET)",
        err && err.code === "ECONNRESET", err ? (err.code + " :: " + err.message) : "no error");
}

// An HTTP CONNECT proxy over TLS that tunnels to the requested target.
function _startTlsProxy(leaf, host) {
  return _startTlsServer(leaf, host, function (sock) {
    var buf = Buffer.alloc(0);
    function onData(chunk) {
      buf = Buffer.concat([buf, chunk]);
      var idx = buf.indexOf("\r\n\r\n");
      if (idx === -1) return;
      sock.removeListener("data", onData);
      var first = buf.slice(0, idx).toString("ascii").split("\r\n")[0];
      var target = first.split(" ")[1] || "";
      var colon = target.lastIndexOf(":");
      var tHost = target.slice(0, colon).replace(/^\[|\]$/g, "");
      var tPort = parseInt(target.slice(colon + 1), 10);
      var up = net.connect({ host: tHost, port: tPort }, function () {
        sock.write("HTTP/1.1 200 Connection Established\r\n\r\n");
        sock.pipe(up); up.pipe(sock, { end: false });
      });
      // Keep reading the client side after the target closes, so the proxy
      // sees the client close its tunnel.
      up.on("close", function () { sock.resume(); });
      up.on("error", function () { try { sock.destroy(); } catch (_e) { /* best-effort */ } });
    }
    sock.on("data", onData);
  });
}

function _startHttpsTarget(leaf, host) {
  return _startTlsServer(leaf, host, function (sock) {
    sock.once("data", function () {
      sock.end("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
    });
  });
}

function _getThroughProxy(targetHost, targetPort) {
  var urlHost = targetHost.indexOf(":") !== -1 ? "[" + targetHost + "]" : targetHost;
  var agent = networkProxy.agentFor("https://" + urlHost + ":" + targetPort + "/");
  return new Promise(function (resolve) {
    function finish(r) { try { agent.destroy(); } catch (_e) { /* best-effort */ } resolve(r); }
    var req = https.request({ host: targetHost, port: targetPort, path: "/", agent: agent }, function (res) {
      res.resume();
      res.on("end", function () { finish({ status: res.statusCode }); });
    });
    req.on("error", function (e) { finish({ err: e }); });
    req.setTimeout(5000, function () { req.destroy(new Error("request timed out")); });
    req.end();
  });
}

async function testProxyToIpLiterals(ca) {
  var restore = _trustCa(ca.caCertPem);
  if (!restore) {
    helpers.unavailable("https proxy to IP literals", "tls.setDefaultCACertificates is not available on this runtime");
    return;
  }
  var leafBoth = await _leaf(ca, ["DNS:localhost", "IP:127.0.0.1", "IP:::1"]);
  try {
    var proxyHosts = [["127.0.0.1", "127.0.0.1"]];
    if (_hasIpv6Loopback()) proxyHosts.push(["[::1]", "::1"]);
    else helpers.unavailable("https proxy at [::1]", "no ::1 loopback on this host");
    for (var i = 0; i < proxyHosts.length; i++) {
      var proxy = await _startTlsProxy(leafBoth, proxyHosts[i][1]);
      var target = await _startHttpsTarget(leafBoth, "127.0.0.1");
      networkProxy._resetForTest();
      networkProxy.set({ https: "https://" + proxyHosts[i][0] + ":" + proxy.port });
      var r;
      var released = true;
      try {
        r = await _getThroughProxy("127.0.0.1", target.port);
        // Destroying the agent closes the TLS session, and the tunnel under
        // it has to close with it.
        try {
          await helpers.waitUntil(function () {
            return proxy.secure.length >= 1 && proxy.peerClosed >= proxy.secure.length;
          }, { timeoutMs: 5000, label: "https proxy: tunnel released after the agent is destroyed" });
        } catch (_e) { released = false; }
      } finally { networkProxy._resetForTest(); _close(proxy); _close(target); }
      check("the tunnel to the proxy at " + proxyHosts[i][0] + " closes with the TLS session over it",
            released, "tunnels=" + proxy.secure.length + " closedByClient=" + proxy.peerClosed);
      check("an https request through the proxy at " + proxyHosts[i][0] + " succeeds",
            r.status === 200, r.err ? (r.err.code + " :: " + r.err.message) : String(r.status));
      check("the proxy at " + proxyHosts[i][0] + " received no SNI",
            proxy.connections >= 1 && proxy.sni.length === 0, JSON.stringify({ c: proxy.connections, sni: proxy.sni }));
      check("the IP-literal target behind the proxy at " + proxyHosts[i][0] + " received no SNI",
            target.connections >= 1 && target.sni.length === 0, JSON.stringify({ c: target.connections, sni: target.sni }));
    }

    // The tunneled session checks the TARGET's certificate against the target
    // address, not the proxy's. With the proxy on ::1 and the target on
    // 127.0.0.1, a target certificate naming only ::1 must be refused.
    if (_hasIpv6Loopback()) {
      var leafV6Only = await _leaf(ca, ["IP:::1"]);
      var proxy2 = await _startTlsProxy(leafBoth, "::1");
      var badTarget = await _startHttpsTarget(leafV6Only, "127.0.0.1");
      networkProxy._resetForTest();
      networkProxy.set({ https: "https://[::1]:" + proxy2.port });
      var r2;
      try { r2 = await _getThroughProxy("127.0.0.1", badTarget.port); }
      finally { networkProxy._resetForTest(); _close(proxy2); _close(badTarget); }
      check("a tunneled target whose certificate does not name its address is refused",
            r2.err && /IP|altnames|ERR_TLS_CERT_ALTNAME_INVALID/i.test(String(r2.err.code) + " " + String(r2.err.message)),
            r2.err ? (r2.err.code + " :: " + r2.err.message) : String(r2.status));
    }
  } finally { restore(); }
}

// The control for the proxy cases: a proxy and a target named by host name
// each receive that name as SNI.
async function testProxyByNameSendsTheName(ca) {
  var restore = _trustCa(ca.caCertPem);
  if (!restore) {
    helpers.unavailable("https proxy by name", "tls.setDefaultCACertificates is not available on this runtime");
    return;
  }
  var leaf = await _leaf(ca, ["DNS:localhost", "IP:127.0.0.1", "IP:::1"]);
  var proxy = await _startTlsProxy(leaf, "127.0.0.1");
  var target = await _startHttpsTarget(leaf, "127.0.0.1");
  var r;
  try {
    networkProxy._resetForTest();
    networkProxy.set({ https: "https://localhost:" + proxy.port });
    r = await _getThroughProxy("localhost", target.port);
  } finally { networkProxy._resetForTest(); _close(proxy); _close(target); restore(); }
  check("an https request through the proxy at localhost succeeds",
        r.status === 200, r.err ? (r.err.code + " :: " + r.err.message) : String(r.status));
  check("the proxy at localhost received SNI localhost",
        proxy.sni.length >= 1 && proxy.sni[0] === "localhost", JSON.stringify(proxy.sni));
  check("the target localhost behind the proxy received SNI localhost",
        target.sni.length >= 1 && target.sni[0] === "localhost", JSON.stringify(target.sni));
}

// The same tunnel dial: a proxy that closes the connection before finishing
// its CONNECT reply ends the attempt with proxy/connect-closed instead of
// leaving it to the connect timeout.
async function testProxyClosingBeforeTheConnectReply() {
  var proxy = net.createServer(function (sock) {
    sock.on("error", function () { /* client teardown */ });
    sock.once("data", function () { sock.end("HTTP/1.1 200 Conn"); });
  });
  await new Promise(function (res) { proxy.listen(0, "127.0.0.1", res); });
  networkProxy._resetForTest();
  networkProxy._setConnectTimeoutForTest(4000);
  networkProxy.set({ http: "http://127.0.0.1:" + proxy.address().port });
  var agent = networkProxy.agentFor("http://127.0.0.1:9/");
  var err = null;
  try {
    await helpers.withTestTimeout("proxy closed before the CONNECT reply", function () {
      return new Promise(function (resolve) {
        agent.createConnection({ host: "127.0.0.1", port: 9 }, function (e, s) {
          err = e;
          if (s) { try { s.destroy(); } catch (_e) { /* best-effort */ } }
          resolve();
        });
      });
    }, { timeoutMs: 9000 });
  } finally {
    networkProxy._setConnectTimeoutForTest(null);
    networkProxy._resetForTest();
    try { proxy.close(); } catch (_e) { /* best-effort */ }
  }
  check("a proxy that closes before its CONNECT reply ends the attempt as proxy/connect-closed",
        err && err.code === "proxy/connect-closed", err ? (err.code + " :: " + err.message) : "no error");
}

// An https request through the proxy with TLS credentials that Node cannot
// load (a key and certificate that are not PEM) fails the request with an
// 'error' event. The TLS session over the tunnel is built inside the
// handler for the proxy's CONNECT reply, so a synchronous throw there
// escaped as an uncaught exception, the request never settled, and the
// tunnel to the proxy stayed open.
async function testProxyTunnelWithUnloadableCredentials() {
  var proxySockets = [];
  var proxy = net.createServer(function (sock) {
    proxySockets.push({ sock: sock, closed: false });
    var rec = proxySockets[proxySockets.length - 1];
    sock.on("error", function () { /* client teardown */ });
    sock.on("close", function () { rec.closed = true; });
    sock.once("data", function () { sock.write("HTTP/1.1 200 Connection Established\r\n\r\n"); });
  });
  await new Promise(function (res) { proxy.listen(0, "127.0.0.1", res); });
  var uncaught = [];
  function onUncaught(e) { uncaught.push(e); }
  var priorListeners = process.listeners("uncaughtException");
  process.removeAllListeners("uncaughtException");
  process.on("uncaughtException", onUncaught);
  networkProxy._resetForTest();
  networkProxy._setConnectTimeoutForTest(4000);
  networkProxy.set({ https: "http://127.0.0.1:" + proxy.address().port });
  var agent = networkProxy.agentFor("https://example.test/");
  var reqErr = null;
  var errorEvents = 0;
  var closedAll = false;
  try {
    await helpers.withTestTimeout("proxied request with unloadable credentials", function () {
      return new Promise(function (resolve) {
        var req = https.request({
          hostname: "example.test", port: 443, path: "/", agent: agent,
          key: "not a pem key", cert: "not a pem cert",
        }, function (res) { res.resume(); resolve(); });
        req.on("error", function (e) { errorEvents += 1; reqErr = e; resolve(); });
        req.end();
      });
    }, { timeoutMs: 9000 }).catch(function () { /* recorded below */ });
    try {
      await helpers.waitUntil(function () {
        return proxySockets.length >= 1 && proxySockets.every(function (r) { return r.closed; });
      }, { timeoutMs: 5000, label: "proxy tunnel closed after a credential failure" });
      closedAll = true;
    } catch (_e) { closedAll = false; }
    await helpers.passiveObserve(100, "no second error event on the proxied request");
  } finally {
    process.removeListener("uncaughtException", onUncaught);
    priorListeners.forEach(function (l) { process.on("uncaughtException", l); });
    networkProxy._setConnectTimeoutForTest(null);
    try { agent.destroy(); } catch (_e) { /* best-effort */ }
    networkProxy._resetForTest();
    proxySockets.forEach(function (r) { try { r.sock.destroy(); } catch (_e) { /* best-effort */ } });
    try { proxy.close(); } catch (_e) { /* best-effort */ }
  }
  check("unloadable TLS credentials on a proxied request raise no uncaught exception",
        uncaught.length === 0, uncaught.map(function (e) { return e.code + " :: " + e.message; }).join(" | "));
  check("unloadable TLS credentials on a proxied request emit 'error' on the request once",
        reqErr !== null && errorEvents === 1,
        reqErr ? (errorEvents + "x " + reqErr.code + " :: " + reqErr.message) : "no error event");
  check("unloadable TLS credentials on a proxied request close the tunnel to the proxy",
        closedAll, "proxy sockets=" + proxySockets.length + " closed=" +
          proxySockets.filter(function (r) { return r.closed; }).length);
}

async function run() {
  await helpers.withDrain("network-tls-sni", async function () {
    await testProxyTunnelWithUnloadableCredentials();
    await testConnectWithEchBadCaRejects();
    await testProxyClosingBeforeTheConnectReply();
    await testHttpsProxyClosingBeforeTheTlsHandshake();
    testNoProxyMatchesIpv6Targets();
    testSniForHelper();
    testIdentityForHelper();
    testIdentityForEveryIpv6Spelling();
    testCheckServerIdentity9525DottedHost();
    testDialHostForm();
    testCheckServerIdentity9525NonCanonicalIpv4();
    testSniForNonCanonicalIpv4();
    testIdentityForValidatesItsOpts();
    testBuildOptionsSni();
    testServernameMustBeAString();
    await testConnectWithEchRefusesAMalformedHostBeforeTheLookup();
    await testConnectWithEchRefusesANonCanonicalIpv4HostBeforeAnyLookup();
    await testProxyAgentServernameNamingAnotherAddress();
    var ca = await _makeCa();
    await testServernameNamingAnotherAddress(ca);
    await testDialRefusesNonCanonicalIpv4Host(ca);
    await testDialHostCheckedWhenAServernameIsSet(ca);
    await testOcspConnectIdentity(ca);
    await testConnectWithEchToAnIpLiteral(ca);
    await testDnsOverTlsToAnIpLiteral(ca);
    await testDnsOverTlsDefaultResolverCarriesNoIpSni();
    await testDialsByNameSendTheName(ca);
    await testProxyToIpLiterals(ca);
    await testProxyByNameSendsTheName(ca);
    await testBracketedIpv6HostDials(ca);
  });
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
