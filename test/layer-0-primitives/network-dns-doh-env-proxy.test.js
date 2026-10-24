// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * With NODE_USE_ENV_PROXY=1, Node's https.globalAgent sends requests through
 * HTTPS_PROXY. b.network.dns DNS-over-HTTPS queries, and the
 * b.network.dns.resolver default transport that shares them, go through the
 * same proxy, and the chain the DoH server sends behind the tunnel is still
 * checked for compromised keys. Each case runs in a child process with the
 * proxy variables set. The proxy records every CONNECT line and tunnels it to
 * a local DoH server that answers one A record, 192.0.2.7.
 */

var nodeHttps = require("node:https");
var nodeNet   = require("node:net");
var nodeCp    = require("node:child_process");

async function _childMain(url, rootPem) {
  var b = require("../../index.js");
  var out = {};
  out.globalAgent = await new Promise(function (resolve) {
    var req = nodeHttps.request(url + "?probe=1", { ca: rootPem }, function (res) {
      res.resume();
      res.on("end", function () { resolve({ status: res.statusCode }); });
    });
    req.on("error", function (e) { resolve({ error: (e && e.code) || String(e) }); });
    req.end();
  });
  b.network.dns.useDnsOverHttps({ url: url, ca: rootPem });
  try {
    out.resolve4 = { answer: await b.network.dns.resolve4("bank.example.com", { transport: "doh" }), code: null };
  } catch (e) {
    out.resolve4 = { answer: null, code: (e && e.code) || String(e) };
  }
  try {
    var r = await b.network.dns.resolver.create({ serveStale: false }).queryA("bank.example.com");
    out.resolver = { answer: r.rrs.map(function (rr) { return rr.decoded; }), code: null };
  } catch (e) {
    out.resolver = { answer: null, code: (e && e.code) || String(e) };
  }
  process.stdout.write("RESULT " + JSON.stringify(out) + "\n");
  process.exit(0);
}

if (require.main === module && process.argv[2] === "child") {
  _childMain(process.argv[3], process.argv[4])
    .catch(function (e) { process.stderr.write(String((e && e.stack) || e)); process.exit(1); });
  return;
}

var helpers = require("../helpers");
var check   = helpers.check;
var ck      = require("../helpers/compromised-keys");

function _dnsAnswer(query) {
  var hdr = Buffer.from(query.subarray(0, 12));
  hdr.writeUInt16BE(0x8180, 2);
  hdr.writeUInt16BE(1, 6);
  var end = 12;
  while (query[end] !== 0) end += query[end] + 1;
  end += 5;
  var answer = Buffer.from([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 7]);
  return Buffer.concat([hdr, query.subarray(12, end), answer]);
}

function _dohServer(which) {
  var chain = ck.tlsChain(which);
  var server = nodeHttps.createServer({ key: chain.key, cert: chain.cert }, function (req, res) {
    var u = new URL(req.url, "https://localhost");
    if (u.searchParams.get("probe")) { res.end("ok"); return; }
    function reply(q) {
      res.setHeader("Content-Type", "application/dns-message");
      res.end(_dnsAnswer(q));
    }
    var dns = u.searchParams.get("dns");
    if (dns) { reply(Buffer.from(dns, "base64url")); return; }
    var body = [];
    req.on("data", function (c) { body.push(c); });
    req.on("end", function () { reply(Buffer.concat(body)); });
  });
  server.on("tlsClientError", function () { /* the client refused the chain */ });
  return new Promise(function (resolve) { server.listen(0, "127.0.0.1", function () { resolve(server); }); });
}

function _proxy(targetPort) {
  var seen = [];
  var sockets = [];
  var proxy = nodeNet.createServer(function (client) {
    sockets.push(client);
    client.on("error", function () { /* the child closed */ });
    client.once("data", function (d) {
      seen.push(String(d).split("\r\n")[0]);
      var up = nodeNet.connect(targetPort, "127.0.0.1", function () {
        client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
        up.pipe(client);
        client.pipe(up);
      });
      sockets.push(up);
      up.on("error", function () { client.destroy(); });
    });
  });
  return new Promise(function (resolve) {
    proxy.listen(0, "127.0.0.1", function () { resolve({ server: proxy, seen: seen, sockets: sockets }); });
  });
}

function _runChild(proxyPort, url) {
  return new Promise(function (resolve) {
    var env = Object.assign({}, process.env, {
      NODE_USE_ENV_PROXY: "1", HTTPS_PROXY: "http://127.0.0.1:" + proxyPort, NO_PROXY: "",
    });
    delete env.NODE_OPTIONS;
    delete env.https_proxy;
    delete env.no_proxy;
    var child = nodeCp.spawn(process.execPath, [__filename, "child", url, ck.certPem(ck.TLS_ROOT_DER)], {
      env: env, stdio: ["ignore", "pipe", "pipe"],
    });
    var so = "";
    var se = "";
    child.stdout.on("data", function (d) { so += d; });
    child.stderr.on("data", function (d) { se += d; });
    child.on("close", function (code) {
      var line = so.split("\n").filter(function (l) { return l.indexOf("RESULT ") === 0; })[0];
      var parsed = null;
      if (line) { try { parsed = JSON.parse(line.slice("RESULT ".length)); } catch (_e) { parsed = null; } }
      resolve({ code: code, result: parsed, stderr: se.slice(0, 2000) });
    });
  });
}

async function _case(which) {
  var doh = await _dohServer(which);
  var proxy = await _proxy(doh.address().port);
  var url = "https://localhost:" + doh.address().port + "/dns-query";
  try {
    var run = await _runChild(proxy.server.address().port, url);
    return { result: run.result, stderr: run.stderr, connects: proxy.seen.slice() };
  } finally {
    proxy.sockets.forEach(function (s) { s.destroy(); });
    await new Promise(function (resolve) { proxy.server.close(function () { resolve(); }); });
    await new Promise(function (resolve) { doh.close(function () { resolve(); }); });
  }
}

async function testDohUsesTheEnvironmentProxy() {
  var ok = await _case("control");
  var r = ok.result;
  check("DoH env proxy: the child reports a result", r !== null, ok.stderr);
  if (r === null) return;
  check("DoH env proxy premise: a globalAgent request goes through the proxy",
        r.globalAgent.status === 200 && ok.connects.length >= 1, JSON.stringify({ r: r.globalAgent, connects: ok.connects }));
  var connects = ok.connects.filter(function (l) { return l.indexOf("CONNECT localhost:") === 0; });
  check("DoH env proxy control: resolve4 answers through the proxy",
        Array.isArray(r.resolve4.answer) && r.resolve4.answer[0] === "192.0.2.7", JSON.stringify(r.resolve4));
  check("DoH env proxy control: resolver.queryA answers through the proxy",
        Array.isArray(r.resolver.answer) && r.resolver.answer[0] === "192.0.2.7", JSON.stringify(r.resolver));
  check("DoH env proxy: every request, the DoH ones included, opened a CONNECT tunnel at the proxy",
        connects.length >= 2, JSON.stringify(ok.connects));

  var bad = await _case("compromised");
  var x = bad.result;
  check("DoH env proxy: the compromised-chain child reports a result", x !== null, bad.stderr);
  if (x === null) return;
  check("DoH env proxy: a DoH server behind the tunnel whose intermediate's private key is 1 is refused",
        x.resolve4.answer === null && /compromised-key/.test(String(x.resolve4.code)) &&
          x.resolver.answer === null && /compromised-key/.test(String(x.resolver.code)) &&
          bad.connects.filter(function (l) { return l.indexOf("CONNECT localhost:") === 0; }).length >= 2,
        JSON.stringify({ resolve4: x.resolve4, resolver: x.resolver, connects: bad.connects }));
}

var TESTS = [testDohUsesTheEnvironmentProxy];

async function run() {
  for (var i = 0; i < TESTS.length; i += 1) await TESTS[i]();
}

module.exports = { run: run, TESTS: TESTS };

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
