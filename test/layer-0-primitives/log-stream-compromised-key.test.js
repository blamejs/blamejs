// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The syslog-over-TLS and OTLP/gRPC log sinks refuse a compromised key: a
 * sink `ca` holding a certificate with a compromised key is refused by
 * b.logStream.init, and a collector whose verified chain carries a
 * compromised key never receives a record. The loopback collectors present a
 * chain whose intermediate's private key is 1; the control chain differs only
 * in that key.
 *
 * A compromised anchor in the default CA store is refused even when the
 * collector sends a decoy in its place, a sink `ca` is screened under every
 * PEM label OpenSSL trusts, and a sink `ca` with no certificate in it is
 * accepted as node accepts it.
 */

var helpers  = require("../helpers");
var check    = helpers.check;
var b        = helpers.b;
var nodeTls  = require("node:tls");
var http2    = require("node:http2");
var ck       = require("../helpers/compromised-keys");
var anchors  = require("../helpers/compromised-anchor");

var COMPROMISED_CA = ck.certPem(ck.P384_COMPROMISED_CA_DER);
var CONTROL_CA     = ck.certPem(ck.P384_CONTROL_CA_DER);

function _code(fn) {
  try { fn(); return "NO-THROW"; } catch (e) { return e.code || e.message; }
}

async function _initCode(sinkCfg) {
  var code = _code(function () { b.logStream.init({ sinks: { s: sinkCfg } }); });
  await b.logStream.shutdown();
  return code;
}

function _startSyslog(which) {
  var chain = typeof which === "string" ? ck.tlsChain(which) : which;
  var handle = { bytes: 0, secured: 0, closed: 0 };
  return new Promise(function (resolve) {
    var srv = nodeTls.createServer({ key: chain.key, cert: chain.cert }, function (sock) {
      handle.secured += 1;
      sock.on("error", function () { /* the client tears down on refusal */ });
      sock.on("data", function (chunk) { handle.bytes += chunk.length; });
      sock.on("close", function () { handle.closed += 1; });
    });
    srv.on("error", function () { /* fixture best-effort */ });
    srv.on("tlsClientError", function () { handle.closed += 1; });
    srv.listen(0, "127.0.0.1", function () {
      handle.server = srv;
      handle.port = srv.address().port;
      handle.rootCa = chain.rootCa;
      resolve(handle);
    });
  });
}

function _startCollector(which) {
  var chain = typeof which === "string" ? ck.tlsChain(which) : which;
  var handle = { exports: 0, sessions: 0, closed: 0 };
  return new Promise(function (resolve) {
    var srv = http2.createSecureServer({ key: chain.key, cert: chain.cert });
    srv.on("session", function (session) {
      handle.sessions += 1;
      session.on("close", function () { handle.closed += 1; });
      session.on("error", function () { /* the client tears down on refusal */ });
    });
    srv.on("stream", function (stream, headers) {
      stream.on("error", function () { /* client teardown */ });
      stream.on("data", function () { /* drain */ });
      stream.on("end", function () {
        if (headers[":path"] === "/opentelemetry.proto.collector.logs.v1.LogsService/Export") handle.exports += 1;
        stream.respond({ ":status": 200, "content-type": "application/grpc" }, { waitForTrailers: true });
        stream.on("wantTrailers", function () { stream.sendTrailers({ "grpc-status": "0" }); });
        stream.end();
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

async function testInitRefusesCompromisedCa() {
  var syslog = { protocol: "syslog", url: "tls://127.0.0.1:1", servername: "localhost", reconnectBaseMs: 60000 };
  check("log-stream compromised ca control: a syslog sink accepts a ca bundle with an ordinary CA",
        await _initCode(Object.assign({ ca: [CONTROL_CA] }, syslog)) === "NO-THROW");
  check("log-stream compromised ca: a syslog sink refuses a ca bundle holding a CA whose private key is 1",
        await _initCode(Object.assign({ ca: [CONTROL_CA, COMPROMISED_CA] }, syslog)) ===
          "log-stream-syslog/compromised-key");
  var grpc = { protocol: "otlp-grpc", url: "https://127.0.0.1:1", servername: "localhost" };
  check("log-stream compromised ca control: an otlp-grpc sink accepts an ordinary DER ca",
        await _initCode(Object.assign({ ca: ck.P384_CONTROL_CA_DER }, grpc)) === "NO-THROW");
  check("log-stream compromised ca: an otlp-grpc sink refuses a ca that is the listed eDellRoot certificate",
        await _initCode(Object.assign({ ca: ck.EDELLROOT_CERT_PEM }, grpc)) === "log-stream-otlp-grpc/compromised-key");
}

async function testSyslogRefusesCompromisedChain() {
  var ctl = await _startSyslog("control");
  b.logStream.init({ sinks: { s: {
    protocol: "syslog", url: "tls://127.0.0.1:" + ctl.port, servername: "localhost", ca: ctl.rootCa,
  } } });
  b.logStream.info("compromised-key control record");
  await helpers.waitUntil(function () { return ctl.bytes > 0; },
    { timeoutMs: 5000, label: "syslog compromised-key control: the collector receives the record" });
  await b.logStream.shutdown();
  ctl.server.close();
  check("log-stream syslog control: a chain of ordinary keys receives the record", ctl.bytes > 0);

  var bad = await _startSyslog("compromised");
  b.logStream.init({ sinks: { s: {
    protocol: "syslog", url: "tls://127.0.0.1:" + bad.port, servername: "localhost", ca: bad.rootCa,
    reconnectBaseMs: 60000,
  } } });
  b.logStream.info("compromised-key record");
  await helpers.waitUntil(function () { return bad.closed >= 1 || bad.bytes > 0; },
    { timeoutMs: 5000, label: "syslog compromised-key: the client ends the connection or sends the record" });
  await b.logStream.shutdown();
  bad.server.close();
  check("log-stream syslog compromised chain: the client ends the connection and the collector receives no bytes",
        bad.bytes === 0 && bad.closed >= 1, "bytes=" + bad.bytes + " closed=" + bad.closed);
}

async function testOtlpGrpcRefusesCompromisedChain() {
  var drops = [];
  function onDrop(info) {
    drops.push({ reason: info.reason, code: info.error && info.error.code, message: info.error && info.error.message });
  }

  var ctl = await _startCollector("control");
  b.logStream.init({ sinks: { g: {
    protocol: "otlp-grpc", url: "https://127.0.0.1:" + ctl.port, servername: "localhost", ca: ctl.rootCa,
    batchSize: 1, onDrop: onDrop,
  } } });
  b.logStream.info("compromised-key control record");
  await helpers.waitUntil(function () { return ctl.exports >= 1; },
    { timeoutMs: 5000, label: "otlp-grpc compromised-key control: the collector receives an Export" });
  await b.logStream.shutdown();
  ctl.server.close();
  check("log-stream otlp-grpc control: a chain of ordinary keys receives the Export",
        ctl.exports >= 1, JSON.stringify(drops));

  drops.length = 0;
  var bad = await _startCollector("compromised");
  b.logStream.init({ sinks: { g: {
    protocol: "otlp-grpc", url: "https://127.0.0.1:" + bad.port, servername: "localhost", ca: bad.rootCa,
    batchSize: 1, onDrop: onDrop,
  } } });
  b.logStream.info("compromised-key record");
  await helpers.waitUntil(function () { return drops.length >= 1 || bad.exports >= 1; },
    { timeoutMs: 5000, label: "otlp-grpc compromised-key: the batch is dropped or exported" });
  await b.logStream.shutdown();
  bad.server.close();
  check("log-stream otlp-grpc compromised chain: the batch is dropped and the collector receives no Export",
        bad.exports === 0 && drops.length >= 1 && drops[0].reason === "send-failed" &&
          drops[0].code === "log-stream-otlp-grpc/compromised-key",
        "exports=" + bad.exports + " " + JSON.stringify(drops));
}

var SYSLOG_SINK = { protocol: "syslog", url: "tls://127.0.0.1:1", servername: "localhost", reconnectBaseMs: 60000 };
var GRPC_SINK   = { protocol: "otlp-grpc", url: "https://127.0.0.1:1", servername: "localhost" };

async function testInitReadsEveryCertificateLabel() {
  var bad = anchors.caLabels(ck.P384_COMPROMISED_CA_DER);
  var ok = anchors.caLabels(ck.P384_CONTROL_CA_DER);
  var labels = Object.keys(bad);
  for (var i = 0; i < labels.length; i += 1) {
    var label = labels[i];
    check("log-stream ca label control: a syslog sink accepts an ordinary CA under the " + label + " label",
          await _initCode(Object.assign({ ca: ok[label] }, SYSLOG_SINK)) === "NO-THROW");
    check("log-stream ca label: a syslog sink refuses a CA whose private key is 1 under the " + label + " label",
          await _initCode(Object.assign({ ca: [CONTROL_CA, bad[label]] }, SYSLOG_SINK)) ===
            "log-stream-syslog/compromised-key");
    check("log-stream ca label control: an otlp-grpc sink accepts an ordinary CA under the " + label + " label",
          await _initCode(Object.assign({ ca: ok[label] }, GRPC_SINK)) === "NO-THROW");
    check("log-stream ca label: an otlp-grpc sink refuses a CA whose private key is 1 under the " + label + " label",
          await _initCode(Object.assign({ ca: bad[label] }, GRPC_SINK)) === "log-stream-otlp-grpc/compromised-key");
  }
}

async function testInitAcceptsACaWithoutACertificate() {
  var fixtures = [["an empty Buffer", Buffer.alloc(0)], ["a Buffer of comments", Buffer.from("# no certificate here\n")]];
  for (var i = 0; i < fixtures.length; i += 1) {
    check("log-stream ca without a certificate: a syslog sink accepts " + fixtures[i][0] + " as node does",
          await _initCode(Object.assign({ ca: fixtures[i][1] }, SYSLOG_SINK)) === "NO-THROW");
    check("log-stream ca without a certificate: an otlp-grpc sink accepts " + fixtures[i][0] + " as node does",
          await _initCode(Object.assign({ ca: fixtures[i][1] }, GRPC_SINK)) === "NO-THROW");
  }
}

async function testSyslogRefusesADecoyForACompromisedDefaultAnchor() {
  for (var w = 0; w < 2; w += 1) {
    var which = w === 0 ? "control" : "compromised";
    var chain = anchors.decoyChain(which);
    var srv = await _startSyslog(chain);
    await anchors.withDefaultAnchor(chain.anchor, async function () {
      b.logStream.init({ sinks: { s: {
        protocol: "syslog", url: "tls://127.0.0.1:" + srv.port, servername: "localhost", reconnectBaseMs: 60000,
      } } });
      b.logStream.info("default-store anchor record");
      await helpers.waitUntil(function () { return srv.bytes > 0 || srv.closed >= 1; },
        { timeoutMs: 5000, label: "syslog default-store anchor " + which + ": the record arrives or the client hangs up" });
      await b.logStream.shutdown();
    });
    srv.server.close();
    if (which === "control") {
      check("log-stream syslog default-store anchor control: an ordinary anchor receives the record", srv.bytes > 0,
            "bytes=" + srv.bytes + " closed=" + srv.closed);
    } else {
      check("log-stream syslog default-store anchor: a collector that sends a decoy for an anchor whose private " +
            "key is 1 receives no bytes and the client ends the connection",
            srv.bytes === 0 && srv.closed >= 1, "bytes=" + srv.bytes + " closed=" + srv.closed);
    }
  }
}

async function testOtlpGrpcRefusesADecoyForACompromisedDefaultAnchor() {
  for (var w = 0; w < 2; w += 1) {
    var which = w === 0 ? "control" : "compromised";
    var chain = anchors.decoyChain(which);
    var srv = await _startCollector(chain);
    var drops = [];
    await anchors.withDefaultAnchor(chain.anchor, async function () {
      b.logStream.init({ sinks: { g: {
        protocol: "otlp-grpc", url: "https://127.0.0.1:" + srv.port, servername: "localhost", batchSize: 1,
        onDrop: function (info) { drops.push(info.error && (info.error.code + ": " + info.error.message)); },
      } } });
      b.logStream.info("default-store anchor record");
      await helpers.waitUntil(function () { return srv.exports >= 1 || drops.length >= 1; },
        { timeoutMs: 5000, label: "otlp-grpc default-store anchor " + which + ": the batch is exported or dropped" });
      await b.logStream.shutdown();
    });
    srv.server.close();
    if (which === "control") {
      check("log-stream otlp-grpc default-store anchor control: an ordinary anchor receives the Export",
            srv.exports >= 1, JSON.stringify(drops));
    } else {
      check("log-stream otlp-grpc default-store anchor: an anchor whose private key is 1 is not trusted, so a " +
            "collector that sends a decoy for it receives no Export and the batch is dropped with " +
            "log-stream-otlp-grpc/http2-error for a failed certificate verification",
            srv.exports === 0 && typeof drops[0] === "string" &&
              drops[0].indexOf("log-stream-otlp-grpc/http2-error: ") === 0 && /certificate/i.test(drops[0]),
            "exports=" + srv.exports + " " + JSON.stringify(drops));
    }
  }
}

async function run() {
  await testInitRefusesCompromisedCa();
  await testInitReadsEveryCertificateLabel();
  await testInitAcceptsACaWithoutACertificate();
  await testSyslogRefusesCompromisedChain();
  await testOtlpGrpcRefusesCompromisedChain();
  await testSyslogRefusesADecoyForACompromisedDefaultAnchor();
  await testOtlpGrpcRefusesADecoyForACompromisedDefaultAnchor();
}

module.exports = {
  run:                                 run,
  testInitRefusesCompromisedCa:        testInitRefusesCompromisedCa,
  testInitReadsEveryCertificateLabel:  testInitReadsEveryCertificateLabel,
  testInitAcceptsACaWithoutACertificate: testInitAcceptsACaWithoutACertificate,
  testSyslogRefusesCompromisedChain:   testSyslogRefusesCompromisedChain,
  testOtlpGrpcRefusesCompromisedChain: testOtlpGrpcRefusesCompromisedChain,
  testSyslogRefusesADecoyForACompromisedDefaultAnchor:   testSyslogRefusesADecoyForACompromisedDefaultAnchor,
  testOtlpGrpcRefusesADecoyForACompromisedDefaultAnchor: testOtlpGrpcRefusesADecoyForACompromisedDefaultAnchor,
};

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); process.exit(0); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
