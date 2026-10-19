// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Outbound dials to a URL whose host is an IPv6 literal.
 *
 * A URL writes an IPv6 host in square brackets, and `URL.hostname` keeps
 * them (`https://[::1]/` has hostname `[::1]`). Handed to `https.request` or
 * `tls.connect` as the host, the bracketed form is not an IP literal to
 * Node's identity check, so a certificate whose subjectAltName carries
 * `IP:::1` fails with ERR_TLS_CERT_ALTNAME_INVALID. Every dial that takes its
 * host from a URL removes the brackets for the connect and keeps them in the
 * Host header and the CONNECT authority.
 *
 * Each dial is driven through its shipped entry point against a loopback
 * server on ::1 that presents a certificate carrying only `IP:::1`:
 *
 *   - b.httpClient.request to https://[::1]:port/, with an operator agent,
 *     and with no agent against an HTTP/1.1-only server, an h2-capable
 *     server and through a CONNECT proxy, trusting a CA registered with
 *     b.network.tls.addCa
 *   - b.network.dns DNS-over-HTTPS (lookup, resolveSecure, queryHttps) with
 *     an https://[::1]:port/ endpoint
 *   - b.network.dns.resolver over the same endpoint
 *   - b.network.proxy: the CONNECT request line and Host header for an IPv6
 *     target
 */

var helpers  = require("../helpers");
var b        = helpers.b;
var check    = helpers.check;
var https    = require("node:https");
var http2    = require("node:http2");
var net      = require("node:net");
var os       = require("node:os");

var networkDns   = require("../../lib/network-dns");
var networkProxy = require("../../lib/network-proxy");
var ipUtils      = require("../../lib/ip-utils");

function _hasIpv6Loopback() {
  var ifaces = os.networkInterfaces();
  return Object.keys(ifaces).some(function (name) {
    return (ifaces[name] || []).some(function (a) {
      return (a.family === "IPv6" || a.family === 6) && a.address === "::1";
    });
  });
}

async function _v6Leaf() {
  var ca = await b.mtlsEngine.generateCa({ name: "url-ipv6-test-ca" });
  var leaf = await b.mtlsEngine.signClientCert({
    cn: "v6", caCertPem: ca.caCertPem, caKeyPem: ca.caKeyPem,
    usage: "server", sans: ["IP:::1"], validityDays: 1,
  });
  return { ca: ca, leaf: leaf };
}

// Builds a DNS reply to `query`: the question echoed, with one A record
// (192.0.2.1) when the question is for an A record and no answers otherwise.
function _dnsReplyTo(query) {
  var off = 12;
  while (off < query.length && query[off] !== 0) off += query[off] + 1;
  var question = query.slice(12, off + 5);
  var qtype = query.readUInt16BE(off + 1);
  var hdr = Buffer.alloc(12);
  query.copy(hdr, 0, 0, 2);
  hdr.writeUInt16BE(0x8180, 2);
  hdr.writeUInt16BE(1, 4);
  hdr.writeUInt16BE(qtype === 1 ? 1 : 0, 6);
  if (qtype !== 1) return Buffer.concat([hdr, question]);
  var ans = Buffer.from([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1]);
  return Buffer.concat([hdr, question, ans]);
}

function _startV6Https(leaf, handler) {
  return new Promise(function (resolve) {
    var h = { requests: [], tlsErrors: 0, sockets: [] };
    var srv = https.createServer({ key: leaf.key, cert: leaf.cert, minVersion: "TLSv1.3" }, function (req, res) {
      var chunks = [];
      req.on("data", function (c) { chunks.push(c); });
      req.on("end", function () {
        var entry = { method: req.method, url: req.url, host: req.headers.host, body: Buffer.concat(chunks) };
        h.requests.push(entry);
        handler(entry, res);
      });
    });
    srv.on("connection", function (s) { h.sockets.push(s); });
    srv.on("tlsClientError", function () { h.tlsErrors += 1; });
    srv.on("error", function () { /* best-effort loopback listener */ });
    srv.listen(0, "::1", function () {
      h.port = srv.address().port;
      h.close = function () {
        h.sockets.forEach(function (s) { try { s.destroy(); } catch (_e) { /* best-effort */ } });
        return new Promise(function (r) { srv.close(r); });
      };
      resolve(h);
    });
  });
}

function _dohHandler(entry, res) {
  var q;
  if (entry.method === "POST") q = entry.body;
  else {
    var m = /[?&]dns=([^&]*)/.exec(entry.url);
    q = Buffer.from((m ? m[1] : "").replace(/-/g, "+").replace(/_/g, "/"), "base64");
  }
  res.writeHead(200, { "content-type": "application/dns-message" });
  res.end(q.length >= 17 ? _dnsReplyTo(q) : Buffer.alloc(0));
}

function testDialHostHelper() {
  check("ip-utils carries dialHost", typeof ipUtils.dialHost === "function");
  if (typeof ipUtils.dialHost !== "function") return;
  check("dialHost removes the brackets of an IPv6 literal", ipUtils.dialHost("[::1]") === "::1");
  check("dialHost leaves a bare IPv6 literal", ipUtils.dialHost("::1") === "::1");
  check("dialHost leaves a host name", ipUtils.dialHost("example.com") === "example.com");
  check("dialHost leaves an IPv4 literal", ipUtils.dialHost("192.0.2.1") === "192.0.2.1");
  check("dialHost leaves an empty host", ipUtils.dialHost("") === "");
  check("ip-utils carries hostPort", typeof ipUtils.hostPort === "function");
  if (typeof ipUtils.hostPort !== "function") return;
  check("hostPort brackets an IPv6 literal", ipUtils.hostPort("::1", 443) === "[::1]:443");
  check("hostPort keeps an already-bracketed IPv6 literal", ipUtils.hostPort("[::1]", 443) === "[::1]:443");
  check("hostPort leaves a host name", ipUtils.hostPort("example.com", 8443) === "example.com:8443");
  check("hostPort leaves an IPv4 literal", ipUtils.hostPort("192.0.2.1", 80) === "192.0.2.1:80");
  check("authorityHost brackets a bare or bracketed IPv6 literal",
        ipUtils.authorityHost("::1") === "[::1]" && ipUtils.authorityHost("[::1]") === "[::1]");
  check("authorityHost leaves a host name", ipUtils.authorityHost("example.com") === "example.com");
  check("sameAddress reads a dotted IPv4 tail", ipUtils.sameAddress("::ffff:127.0.0.1", "[::ffff:7f00:1]"));
  check("sameAddress keeps the zone ID", !ipUtils.sameAddress("fe80::1%eth0", "fe80::1%eth1") &&
        ipUtils.sameAddress("fe80::1%eth0", "fe80:0::1%eth0"));
  check("sameAddress keeps IPv4 and IPv4-mapped apart", !ipUtils.sameAddress("127.0.0.1", "::ffff:127.0.0.1"));
  check("sameAddress refuses a name", !ipUtils.sameAddress("localhost", "localhost"));
}

async function testHttpClientToIpv6Literal(pki) {
  var srv = await _startV6Https(pki.leaf, function (entry, res) { res.end("ok"); });
  var agent = new https.Agent({ ca: pki.ca.caCertPem });
  var r = null; var err = null;
  try {
    r = await b.httpClient.request({ url: "https://[::1]:" + srv.port + "/", allowInternal: true, agent: agent });
  } catch (e) { err = e; }
  finally { agent.destroy(); await srv.close(); }
  check("b.httpClient.request to https://[::1] verifies against the IP:::1 certificate",
        r && r.statusCode === 200, err ? (err.code + " :: " + err.message) : String(r && r.statusCode));
  check("b.httpClient.request to https://[::1] sends the bracketed Host header",
        srv.requests.length === 1 && srv.requests[0].host === "[::1]:" + srv.port,
        JSON.stringify(srv.requests[0] && srv.requests[0].host));
}

// The default b.httpClient path, with no operator agent, trusts the CAs
// registered through b.network.tls.addCa: the HTTP/1.1 path, the ALPN
// dial that negotiates h2, and the TLS session through a CONNECT proxy.
function _startV6H2(leaf) {
  return new Promise(function (resolve) {
    var h = { requests: [], sockets: [] };
    var srv = http2.createSecureServer({ key: leaf.key, cert: leaf.cert, minVersion: "TLSv1.3", allowHTTP1: true },
      function (req, res) {
        h.requests.push({ version: req.httpVersion, authority: req.headers[":authority"] || req.headers.host });
        res.end("ok");
      });
    srv.on("connection", function (s) { h.sockets.push(s); });
    srv.on("error", function () { /* best-effort loopback listener */ });
    srv.listen(0, "::1", function () {
      h.port = srv.address().port;
      h.close = function () {
        h.sockets.forEach(function (s) { try { s.destroy(); } catch (_e) { /* best-effort */ } });
        return new Promise(function (r) { srv.close(function () { r(); }); });
      };
      resolve(h);
    });
  });
}

function _startTunnelProxy() {
  return new Promise(function (resolve) {
    var h = { connects: [], sockets: [] };
    var srv = net.createServer(function (sock) {
      h.sockets.push(sock);
      sock.on("error", function () { /* client teardown */ });
      var buf = Buffer.alloc(0);
      function onData(chunk) {
        buf = Buffer.concat([buf, chunk]);
        var idx = buf.indexOf("\r\n\r\n");
        if (idx === -1) return;
        sock.removeListener("data", onData);
        var first = buf.slice(0, idx).toString("latin1").split("\r\n")[0];
        h.connects.push(first);
        var target = first.split(" ")[1] || "";
        var colon = target.lastIndexOf(":");
        var up = net.connect({ host: target.slice(0, colon).replace(/^\[|\]$/g, ""), port: Number(target.slice(colon + 1)) },
          function () {
            sock.write("HTTP/1.1 200 Connection Established\r\n\r\n");
            sock.pipe(up); up.pipe(sock);
          });
        h.sockets.push(up);
        up.on("error", function () { try { sock.destroy(); } catch (_e) { /* best-effort */ } });
      }
      sock.on("data", onData);
    });
    srv.listen(0, "127.0.0.1", function () {
      h.port = srv.address().port;
      h.close = function () {
        h.sockets.forEach(function (s) { try { s.destroy(); } catch (_e) { /* best-effort */ } });
        return new Promise(function (r) { srv.close(function () { r(); }); });
      };
      resolve(h);
    });
  });
}

async function testHttpClientTrustsRegisteredCas(pki) {
  var label = "url-ipv6-dial-host-test-ca";
  b.network.tls.addCa(pki.ca.caCertPem, { label: label });
  try {
    var cases = [
      ["an HTTP/1.1-only server", function () { return _startV6Https(pki.leaf, function (entry, res) { res.end("ok"); }); }],
      ["an h2-capable server", function () { return _startV6H2(pki.leaf); }],
    ];
    for (var i = 0; i < cases.length; i++) {
      var srv = await cases[i][1]();
      var r = null; var err = null;
      try { r = await b.httpClient.request({ url: "https://[::1]:" + srv.port + "/", allowInternal: true }); }
      catch (e) { err = e; }
      finally { b.httpClient._resetForTest && b.httpClient._resetForTest(); await srv.close(); }
      check("b.httpClient.request with no agent to " + cases[i][0] + " on [::1] trusts the registered CA",
            r && r.statusCode === 200, err ? (err.code + " :: " + err.message) : String(r && r.statusCode));
    }

    var target = await _startV6Https(pki.leaf, function (entry, res) { res.end("ok"); });
    var proxy = await _startTunnelProxy();
    networkProxy._resetForTest();
    networkProxy.set({ https: "http://127.0.0.1:" + proxy.port });
    var pr = null; var perr = null;
    try { pr = await b.httpClient.request({ url: "https://[::1]:" + target.port + "/", allowInternal: true }); }
    catch (e) { perr = e; }
    finally { networkProxy._resetForTest(); await proxy.close(); await target.close(); }
    check("b.httpClient.request through a CONNECT proxy to https://[::1] trusts the registered CA",
          pr && pr.statusCode === 200, perr ? (perr.code + " :: " + perr.message) : String(pr && pr.statusCode));
    check("the CONNECT request line for the proxied [::1] target brackets it",
          proxy.connects[0] === "CONNECT [::1]:" + target.port + " HTTP/1.1", JSON.stringify(proxy.connects));
  } finally {
    b.network.tls.removeCaByLabel(label);
  }
}

async function testDohToIpv6Literal(pki) {
  var cases = [
    ["lookup over GET", "GET", function () { return networkDns.resolve4("example.com"); }],
    ["lookup over POST", "POST", function () { return networkDns.resolve4("example.com"); }],
    ["resolveSecure", "GET", function () { return networkDns.resolveSecure("example.com", "A"); }],
    ["queryHttps", "GET", function () { return networkDns.queryHttps("example.com"); }],
    ["the wire resolver", "GET", function () {
      return b.network.dns.resolver.create({ timeoutMs: 4000 }).queryHttps("example.com");
    }],
  ];
  for (var i = 0; i < cases.length; i++) {
    var srv = await _startV6Https(pki.leaf, _dohHandler);
    networkDns._resetForTest();
    networkDns.setLookupTimeoutMs(4000);
    var err = null;
    try {
      networkDns.useDnsOverHttps({ url: "https://[::1]:" + srv.port + "/dns-query", method: cases[i][1], ca: pki.ca.caCertPem });
      await cases[i][2]();
    } catch (e) { err = e; }
    finally { networkDns._resetForTest(); await srv.close(); }
    check("DNS-over-HTTPS " + cases[i][0] + " to https://[::1] verifies against the IP:::1 certificate",
          srv.requests.length >= 1 && srv.tlsErrors === 0,
          (err ? err.code + " :: " + err.message : "") + " requests=" + srv.requests.length + " tlsErrors=" + srv.tlsErrors);
    check("DNS-over-HTTPS " + cases[i][0] + " to https://[::1] completes",
          err === null, err ? err.code + " :: " + err.message : "");
  }
}

// A CONNECT request names its target in authority form, so an IPv6 target
// is written in brackets: `CONNECT [::1]:443 HTTP/1.1`.
async function testProxyConnectAuthorityForIpv6Target() {
  var seen = null;
  var proxy = net.createServer(function (sock) {
    sock.on("error", function () { /* client teardown */ });
    sock.once("data", function (d) {
      seen = d.toString("latin1").split("\r\n");
      sock.end("HTTP/1.1 403 Forbidden\r\n\r\n");
    });
  });
  await new Promise(function (r) { proxy.listen(0, "127.0.0.1", r); });
  networkProxy._resetForTest();
  networkProxy.set({ http: "http://127.0.0.1:" + proxy.address().port });
  var agent = networkProxy.agentFor("http://[::1]:8080/");
  try {
    await helpers.withTestTimeout("proxy CONNECT to an IPv6 target", function () {
      return new Promise(function (resolve) {
        agent.createConnection({ host: "::1", port: 8080 }, function (_e, s) {
          if (s) { try { s.destroy(); } catch (_e2) { /* best-effort */ } }
          resolve();
        });
      });
    }, { timeoutMs: 9000 });
  } finally {
    networkProxy._resetForTest();
    try { proxy.close(); } catch (_e) { /* best-effort */ }
  }
  check("the CONNECT request line brackets an IPv6 target",
        seen && seen[0] === "CONNECT [::1]:8080 HTTP/1.1", JSON.stringify(seen && seen[0]));
  check("the CONNECT Host header brackets an IPv6 target",
        seen && seen[1] === "Host: [::1]:8080", JSON.stringify(seen && seen[1]));
}

async function run() {
  testDialHostHelper();
  await testProxyConnectAuthorityForIpv6Target();
  if (!_hasIpv6Loopback()) {
    helpers.unavailable("dials to https://[::1]", "no ::1 loopback on this host");
    return;
  }
  var pki = await _v6Leaf();
  await testHttpClientToIpv6Literal(pki);
  await testHttpClientTrustsRegisteredCas(pki);
  await testDohToIpv6Literal(pki);
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("[url-ipv6-dial-host] OK: " + helpers.getChecks() + " checks passed"); },
             function (e) { console.error(e.stack || e); process.exit(1); });
}
