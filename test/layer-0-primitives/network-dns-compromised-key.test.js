// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.network.dns refuses a compromised key on the encrypted resolver paths:
 * a `ca` for DoH, DoT or a designated resolver whose certificate carries a
 * compromised key is refused when it is configured, and a DoH or DoT server
 * whose verified chain carries a compromised key fails the query with
 * dns/compromised-key (resolver/compromised-key for b.network.dns.resolver).
 * The loopback servers present a chain whose intermediate's private key is 1;
 * the control chain differs only in that key.
 *
 * A compromised anchor in the default CA store is refused even when the
 * server sends a decoy in its place, a `ca` is screened under every PEM label
 * OpenSSL trusts, and a DoH query never travels over a connection or a TLS
 * session that another caller of node's global https agent opened without
 * the chain check. DoH queries from b.network.dns and its resolver share one
 * kept-alive TLS connection.
 */

var helpers  = require("../helpers");
var check    = helpers.check;
var b        = helpers.b;
var nodeTls  = require("node:tls");
var nodeHttps = require("node:https");
var ck       = require("../helpers/compromised-keys");
var ca       = require("../helpers/compromised-anchor");

var dns = b.network.dns;

var COMPROMISED_CA = ck.certPem(ck.P384_COMPROMISED_CA_DER);
var CONTROL_CA     = ck.certPem(ck.P384_CONTROL_CA_DER);
var ANSWER         = [192, 0, 2, 77];

function _reset() { dns._resetForTest(); }

function _code(fn) {
  try { fn(); return "NO-THROW"; } catch (e) { return e.code || e.message; }
}
async function _codeAsync(fn) {
  try { await fn(); return "NO-THROW"; } catch (e) { return e.code || e.message; }
}

function _qname(name) {
  var parts = name.split(".");
  var bufs = parts.map(function (p) { return Buffer.concat([Buffer.from([p.length]), Buffer.from(p, "ascii")]); });
  bufs.push(Buffer.from([0]));
  return Buffer.concat(bufs);
}

// One A answer for "ok.example.com", whatever the question was.
function _aReply() {
  var hdr = Buffer.alloc(12);
  hdr.writeUInt16BE(0, 0);
  hdr.writeUInt16BE(0x8180, 2);
  hdr.writeUInt16BE(1, 4);
  hdr.writeUInt16BE(1, 6);
  var qtail = Buffer.from([0, 1, 0, 1]);
  var ans = Buffer.alloc(12);
  ans.writeUInt16BE(0xc00c, 0);
  ans.writeUInt16BE(1, 2);
  ans.writeUInt16BE(1, 4);
  ans.writeUInt32BE(60, 6);
  ans.writeUInt16BE(4, 10);
  return Buffer.concat([hdr, _qname("ok.example.com"), qtail, ans, Buffer.from(ANSWER)]);
}

function _chainOf(which) {
  return typeof which === "string" ? ck.tlsChain(which) : which;
}

function _startDoh(which) {
  var chain = _chainOf(which);
  var handle = { requests: 0, connections: 0 };
  return new Promise(function (resolve) {
    var srv = nodeHttps.createServer({ key: chain.key, cert: chain.cert }, function (req, res) {
      req.on("data", function () { /* drain */ });
      req.on("end", function () {
        handle.requests += 1;
        res.writeHead(200, { "content-type": "application/dns-message" });
        res.end(_aReply());
      });
    });
    srv.on("secureConnection", function () { handle.connections += 1; });
    srv.on("error", function () { /* fixture best-effort */ });
    srv.on("tlsClientError", function () { /* the client refused the chain */ });
    srv.listen(0, "127.0.0.1", function () {
      handle.server = srv;
      handle.port = srv.address().port;
      handle.rootCa = chain.rootCa;
      resolve(handle);
    });
  });
}

function _startDot(which) {
  var chain = _chainOf(which);
  var handle = { queries: 0 };
  return new Promise(function (resolve) {
    var srv = nodeTls.createServer({ key: chain.key, cert: chain.cert }, function (sock) {
      sock.on("error", function () { /* the client tears down on refusal */ });
      var got = Buffer.alloc(0);
      sock.on("data", function (chunk) {
        got = Buffer.concat([got, chunk]);
        while (got.length >= 2 && got.length >= got.readUInt16BE(0) + 2) {
          got = got.subarray(got.readUInt16BE(0) + 2);
          handle.queries += 1;
          var reply = _aReply();
          var len = Buffer.alloc(2);
          len.writeUInt16BE(reply.length, 0);
          sock.write(Buffer.concat([len, reply]));
        }
      });
    });
    srv.on("error", function () { /* fixture best-effort */ });
    srv.on("tlsClientError", function () { /* the client refused the chain */ });
    srv.listen(0, "127.0.0.1", function () {
      handle.server = srv;
      handle.port = srv.address().port;
      handle.rootCa = chain.rootCa;
      resolve(handle);
    });
  });
}

function _close(h) {
  try { h.server.close(); } catch (_e) { /* best-effort */ }
  try { if (typeof h.server.closeAllConnections === "function") h.server.closeAllConnections(); }
  catch (_e) { /* best-effort */ }
}

function testConfigRefusesCompromisedCa() {
  _reset();
  check("dns compromised ca control: useDnsOverHttps accepts a bundle with an ordinary CA",
        _code(function () { dns.useDnsOverHttps({ url: "https://doh.example/dns-query", ca: [CONTROL_CA] }); }) ===
          "NO-THROW");
  _reset();
  check("dns compromised ca: useDnsOverHttps refuses a bundle holding a CA whose private key is 1",
        _code(function () { dns.useDnsOverHttps({ url: "https://doh.example/dns-query", ca: [COMPROMISED_CA] }); }) ===
          "dns/compromised-key");
  _reset();
  check("dns compromised ca: useDnsOverHttps refuses the listed eDellRoot certificate",
        _code(function () { dns.useDnsOverHttps({ url: "https://doh.example/dns-query", ca: ck.EDELLROOT_CERT_PEM }); }) ===
          "dns/compromised-key");
  _reset();
  check("dns compromised ca control: useDnsOverTls accepts a PEM Buffer of an ordinary CA",
        _code(function () { dns.useDnsOverTls({ host: "127.0.0.1", ca: Buffer.from(CONTROL_CA) }); }) === "NO-THROW");
  _reset();
  check("dns compromised ca: useDnsOverTls refuses a PEM Buffer of a CA whose private key is 1",
        _code(function () { dns.useDnsOverTls({ host: "127.0.0.1", ca: Buffer.from(COMPROMISED_CA) }); }) ===
          "dns/compromised-key");
  _reset();
  var dnrErr = null;
  try {
    dns.useDesignatedResolvers([
      { transport: "doh", url: "https://a.example/dns-query", ca: COMPROMISED_CA },
      { transport: "dot", host: "127.0.0.1", ca: COMPROMISED_CA },
    ]);
  } catch (e) { dnrErr = e; }
  check("dns compromised ca: useDesignatedResolvers configures no entry whose ca is compromised",
        dnrErr !== null && dnrErr.code === "dns/dnr-no-resolvers" && /compromised key/.test(dnrErr.message) &&
          dns._stateForTest().doh === null && dns._stateForTest().dot === null,
        dnrErr && dnrErr.message);
  _reset();
  var dnr = dns.useDesignatedResolvers([
    { transport: "doh", url: "https://a.example/dns-query", ca: COMPROMISED_CA },
    { transport: "doh", url: "https://b.example/dns-query", ca: CONTROL_CA },
  ]);
  check("dns compromised ca control: useDesignatedResolvers moves on to the entry with an ordinary ca",
        dnr.active === 1 && dns._stateForTest().doh.url === "https://b.example/dns-query");
  _reset();
}

async function testDohRefusesCompromisedChain() {
  var paths = [
    ["resolve4", function () { return dns.resolve4("bank.example.com"); },
      function (r) { return Array.isArray(r) && r[0] === ANSWER.join("."); }],
    ["resolveSecure", function () { return dns.resolveSecure("bank.example.com", "A"); },
      function (r) { return r && Array.isArray(r.rrs) && r.rrs[0] === ANSWER.join("."); }],
    ["querySvcb", function () { return dns.querySvcb("bank.example.com", { transport: "doh" }); },
      function (r) { return Array.isArray(r); }],
    ["resolver.queryA", function () { return dns.resolver.create({ serveStale: false }).queryA("bank.example.com"); },
      function (r) { return r && Array.isArray(r.rrs) && r.rrs.length === 1; }],
  ];
  for (var i = 0; i < paths.length; i += 1) {
    var name = paths[i][0];
    var ctl = await _startDoh("control");
    _reset();
    dns.useDnsOverHttps({ url: "https://127.0.0.1:" + ctl.port + "/dns-query", ca: ctl.rootCa });
    var okResult = null;
    var okErr = null;
    try { okResult = await paths[i][1](); } catch (e) { okErr = e; }
    _close(ctl);
    check("dns doh control: " + name + " answers through a chain of ordinary keys",
          okErr === null && paths[i][2](okResult), okErr && (okErr.code + " " + okErr.message));

    var bad = await _startDoh("compromised");
    _reset();
    dns.useDnsOverHttps({ url: "https://127.0.0.1:" + bad.port + "/dns-query", ca: bad.rootCa });
    var code = await _codeAsync(paths[i][1]);
    _close(bad);
    var want = name === "resolver.queryA" ? "resolver/compromised-key" : "dns/compromised-key";
    check("dns doh compromised chain: " + name + " fails with " + want + " and the server is never asked",
          code === want && bad.requests === 0, code + " requests=" + bad.requests);
  }
  _reset();
}

async function testDotRefusesCompromisedChain() {
  var paths = [
    ["resolve4", function () { return dns.resolve4("bank.example.com", { transport: "dot" }); },
      function (r) { return Array.isArray(r) && r[0] === ANSWER.join("."); }],
    ["querySvcb", function () { return dns.querySvcb("bank.example.com", { transport: "dot" }); },
      function (r) { return Array.isArray(r); }],
  ];
  for (var i = 0; i < paths.length; i += 1) {
    var name = paths[i][0];
    var ctl = await _startDot("control");
    _reset();
    dns.useDnsOverTls({ host: "127.0.0.1", port: ctl.port, servername: "localhost", ca: ctl.rootCa });
    var okResult = null;
    var okErr = null;
    try { okResult = await paths[i][1](); } catch (e) { okErr = e; }
    _reset();
    _close(ctl);
    check("dns dot control: " + name + " answers through a chain of ordinary keys",
          okErr === null && paths[i][2](okResult), okErr && (okErr.code + " " + okErr.message));

    var bad = await _startDot("compromised");
    _reset();
    dns.useDnsOverTls({ host: "127.0.0.1", port: bad.port, servername: "localhost", ca: bad.rootCa });
    var code = await _codeAsync(paths[i][1]);
    _reset();
    _close(bad);
    check("dns dot compromised chain: " + name + " fails with dns/compromised-key and the server is never asked",
          code === "dns/compromised-key" && bad.queries === 0, code + " queries=" + bad.queries);
  }
}

function testConfigReadsEveryCertificateLabel() {
  var bad = ca.caLabels(ck.P384_COMPROMISED_CA_DER);
  var ok = ca.caLabels(ck.P384_CONTROL_CA_DER);
  Object.keys(bad).forEach(function (label) {
    _reset();
    check("dns ca label control: useDnsOverHttps accepts an ordinary CA under the " + label + " label",
          _code(function () { dns.useDnsOverHttps({ url: "https://doh.example/dns-query", ca: ok[label] }); }) ===
            "NO-THROW");
    _reset();
    check("dns ca label: useDnsOverHttps refuses a CA whose private key is 1 under the " + label + " label",
          _code(function () { dns.useDnsOverHttps({ url: "https://doh.example/dns-query", ca: bad[label] }); }) ===
            "dns/compromised-key");
    _reset();
    check("dns ca label: useDnsOverTls refuses a CA whose private key is 1 under the " + label + " label",
          _code(function () { dns.useDnsOverTls({ host: "127.0.0.1", ca: [CONTROL_CA, bad[label]] }); }) ===
            "dns/compromised-key");
  });
  _reset();
}

function testConfigAcceptsACaWithoutACertificate() {
  [["an empty Buffer", Buffer.alloc(0)], ["a Buffer of comments", Buffer.from("# no certificate here\n")]]
    .forEach(function (f) {
      _reset();
      check("dns ca without a certificate: useDnsOverTls accepts " + f[0] + " as node does",
            _code(function () { dns.useDnsOverTls({ host: "127.0.0.1", ca: f[1] }); }) === "NO-THROW");
      _reset();
      check("dns ca without a certificate: useDnsOverHttps accepts " + f[0] + " as node does",
            _code(function () { dns.useDnsOverHttps({ url: "https://doh.example/dns-query", ca: f[1] }); }) ===
              "NO-THROW");
    });
  _reset();
}

async function testDecoyForACompromisedDefaultAnchorIsRefused() {
  var paths = [
    ["doh resolve4", "doh", function () { return dns.resolve4("bank.example.com"); }, "dns/doh-failed"],
    ["doh resolver.queryA", "doh",
      function () { return dns.resolver.create({ serveStale: false }).queryA("bank.example.com"); },
      "resolver/upstream-failed"],
    ["dot resolve4", "dot", function () { return dns.resolve4("bank.example.com", { transport: "dot" }); },
      "dns/dot-handshake-failed"],
  ];
  for (var i = 0; i < paths.length; i += 1) {
    var name = paths[i][0];
    var transport = paths[i][1];
    var run1 = paths[i][2];
    for (var w = 0; w < 2; w += 1) {
      var which = w === 0 ? "control" : "compromised";
      var chain = ca.decoyChain(which);
      var srv = transport === "doh" ? await _startDoh(chain) : await _startDot(chain);
      var outcome = await ca.withDefaultAnchor(chain.anchor, async function () {
        _reset();
        if (transport === "doh") dns.useDnsOverHttps({ url: "https://127.0.0.1:" + srv.port + "/dns-query" });
        else dns.useDnsOverTls({ host: "127.0.0.1", port: srv.port, servername: "localhost" });
        try { await run1(); return "answered"; } catch (e) { return (e.code || "no-code") + ": " + e.message; }
      });
      _reset();
      _close(srv);
      var asked = transport === "doh" ? srv.requests : srv.queries;
      if (which === "control") {
        check("dns default-store anchor control: " + name + " answers through an ordinary anchor",
              outcome === "answered" && asked === 1, outcome + " asked=" + asked);
      } else {
        check("dns default-store anchor: " + name + " does not trust an anchor whose private key is 1, so a server " +
              "that sends a decoy for it fails certificate verification with " + paths[i][3] +
              " and is never asked",
              outcome.indexOf(paths[i][3] + ": ") === 0 && /certificate/i.test(outcome) && asked === 0,
              outcome + " asked=" + asked);
      }
    }
  }
}

function _foreignDohRequest(port, rootCa) {
  return new Promise(function (resolve) {
    var req = nodeHttps.request(Object.assign({
      hostname: "127.0.0.1", port: port, path: "/dns-query", method: "GET",
      headers: { "accept": "application/dns-message" },
    }, b.network.tls.outboundPosture(), { ca: rootCa }), function (res) {
      res.resume();
      res.on("end", function () { resolve(res.statusCode); });
    });
    req.on("error", function (e) { resolve(e.code || e.message); });
    req.end();
  });
}

async function testDohDoesNotRideAnUncheckedConnection() {
  var paths = [
    ["resolve4", function () { return dns.resolve4("bank.example.com"); }, "dns/compromised-key"],
    ["resolver.queryA", function () { return dns.resolver.create({ serveStale: false }).queryA("bank.example.com"); },
      "resolver/compromised-key"],
  ];
  var modes = ["kept-alive socket", "resumed session"];
  for (var i = 0; i < paths.length; i += 1) {
    for (var m = 0; m < modes.length; m += 1) {
      var bad = await _startDoh("compromised");
      var foreign = await _foreignDohRequest(bad.port, bad.rootCa);
      if (m === 1) nodeHttps.globalAgent.destroy();
      _reset();
      dns.useDnsOverHttps({ url: "https://127.0.0.1:" + bad.port + "/dns-query", ca: bad.rootCa });
      var code = await _codeAsync(paths[i][1]);
      _reset();
      nodeHttps.globalAgent.destroy();
      _close(bad);
      check("dns doh unchecked " + modes[m] + ": " + paths[i][0] + " fails with " + paths[i][2] +
            " after node's global agent reached the server without the chain check",
            foreign === 200 && code === paths[i][2] && bad.requests === 1,
            "foreign=" + foreign + " code=" + code + " requests=" + bad.requests);
    }
  }
}

async function testDohIgnoresGlobalAgentOptions() {
  var global = nodeHttps.globalAgent.options;
  var paths = [
    ["resolve4", function () { return dns.resolve4("bank.example.com"); }, "dns/compromised-key"],
    ["resolver.queryA", function () { return dns.resolver.create({ serveStale: false }).queryA("bank.example.com"); },
      "resolver/compromised-key"],
  ];
  for (var i = 0; i < paths.length; i += 1) {
    for (var w = 0; w < 2; w += 1) {
      var which = w === 0 ? "control" : "compromised";
      var srv = await _startDoh(which);
      _reset();
      global.rejectUnauthorized = false;
      var outcome;
      try {
        dns.useDnsOverHttps({ url: "https://127.0.0.1:" + srv.port + "/dns-query", ca: srv.rootCa });
        outcome = await _codeAsync(paths[i][1]);
      } finally {
        delete global.rejectUnauthorized;
      }
      _reset();
      _close(srv);
      if (which === "control") {
        check("dns doh global agent options control: " + paths[i][0] + " answers through a chain of ordinary keys",
              outcome === "NO-THROW" && srv.requests === 1, outcome + " requests=" + srv.requests);
      } else {
        check("dns doh global agent options: " + paths[i][0] + " fails with " + paths[i][2] + " and the server " +
              "is never asked, although https.globalAgent.options.rejectUnauthorized is false",
              outcome === paths[i][2] && srv.requests === 0, outcome + " requests=" + srv.requests);
      }
    }
  }
}

async function testDohQueriesEachOpenACheckedConnection() {
  var ctl = await _startDoh("control");
  _reset();
  dns.useDnsOverHttps({ url: "https://127.0.0.1:" + ctl.port + "/dns-query", ca: ctl.rootCa });
  var resolver = dns.resolver.create({ serveStale: false });
  var answered = 0;
  var firstErr = null;
  for (var i = 0; i < 4; i += 1) {
    try {
      await dns.resolve4("pool" + i + ".example.com");
      await resolver.queryA("pool-r" + i + ".example.com");
      answered += 2;
    } catch (e) { if (firstErr === null) firstErr = e; }
  }
  _reset();
  _close(ctl);
  check("dns doh connections: eight DoH queries through b.network.dns and its resolver each open their own TLS connection",
        answered === 8 && ctl.requests === 8 && ctl.connections === 8,
        "answered=" + answered + " requests=" + ctl.requests + " connections=" + ctl.connections +
          (firstErr ? " " + firstErr.code + " " + firstErr.message : ""));

  var bad = await _startDoh("compromised");
  _reset();
  dns.useDnsOverHttps({ url: "https://127.0.0.1:" + bad.port + "/dns-query", ca: bad.rootCa });
  var codes = [];
  for (var j = 0; j < 2; j += 1) {
    codes.push(await _codeAsync(function () { return dns.resolve4("pool-bad" + j + ".example.com"); }));
  }
  _reset();
  _close(bad);
  check("dns doh pooling: every query to a server whose chain carries a compromised key fails, and none is asked",
        codes[0] === "dns/compromised-key" && codes[1] === "dns/compromised-key" && bad.requests === 0,
        codes.join(",") + " requests=" + bad.requests);
}

async function run() {
  testConfigRefusesCompromisedCa();
  testConfigReadsEveryCertificateLabel();
  testConfigAcceptsACaWithoutACertificate();
  await testDohRefusesCompromisedChain();
  await testDotRefusesCompromisedChain();
  await testDecoyForACompromisedDefaultAnchorIsRefused();
  await testDohDoesNotRideAnUncheckedConnection();
  await testDohIgnoresGlobalAgentOptions();
  await testDohQueriesEachOpenACheckedConnection();
  _reset();
}

module.exports = {
  run:                               run,
  testConfigRefusesCompromisedCa:    testConfigRefusesCompromisedCa,
  testConfigReadsEveryCertificateLabel:            testConfigReadsEveryCertificateLabel,
  testConfigAcceptsACaWithoutACertificate:         testConfigAcceptsACaWithoutACertificate,
  testDohRefusesCompromisedChain:    testDohRefusesCompromisedChain,
  testDotRefusesCompromisedChain:    testDotRefusesCompromisedChain,
  testDecoyForACompromisedDefaultAnchorIsRefused:  testDecoyForACompromisedDefaultAnchorIsRefused,
  testDohDoesNotRideAnUncheckedConnection:         testDohDoesNotRideAnUncheckedConnection,
  testDohIgnoresGlobalAgentOptions:                testDohIgnoresGlobalAgentOptions,
  testDohQueriesEachOpenACheckedConnection:        testDohQueriesEachOpenACheckedConnection,
};

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); process.exit(0); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
