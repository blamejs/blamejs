// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.mail.transports.smtp refuses a compromised key: a `ca` holding a
 * certificate with a compromised key is refused when the transport is built,
 * and a relay whose verified chain carries a compromised key fails the send
 * with mail/compromised-key before AUTH, on both the implicit-TLS and the
 * STARTTLS paths. A DANE-TA record that pins a compromised trust anchor fails
 * the send with mail/compromised-key as well, and a PKIX-TA or PKIX-EE match
 * delivers only when the handshake validated the PKIX path. The loopback
 * relays present a chain whose intermediate's private key is 1; the control
 * chain differs only in that key.
 *
 * A compromised anchor in the default CA store is refused even when the relay
 * sends a decoy in its place, a `ca` is screened under every PEM label
 * OpenSSL trusts, and a `ca` with no certificate in it is accepted as node
 * accepts it.
 */

var helpers    = require("../helpers");
var check      = helpers.check;
var b          = helpers.b;
var net        = require("node:net");
var nodeTls    = require("node:tls");
var nodeCrypto = require("node:crypto");
var ck         = require("../helpers/compromised-keys");
var anchors    = require("../helpers/compromised-anchor");

var COMPROMISED_CA = ck.certPem(ck.P384_COMPROMISED_CA_DER);
var CONTROL_CA     = ck.certPem(ck.P384_CONTROL_CA_DER);
var MESSAGE        = { from: "s@a.test", to: "r@b.test", subject: "s", text: "hi" };

function _code(fn) {
  try { fn(); return "NO-THROW"; } catch (e) { return e.code || e.message; }
}

function _smtpDialog(sock, handle) {
  var buf = "";
  var inData = false;
  var authStage = -1;
  sock.setEncoding("utf8");
  sock.on("error", function () { /* the client tears down on refusal */ });
  sock.on("data", function (d) {
    buf += d;
    var idx;
    while ((idx = buf.indexOf("\r\n")) >= 0) {
      var line = buf.slice(0, idx);
      buf = buf.slice(idx + 2);
      handle.lines.push(line);
      if (inData) {
        if (line === ".") { inData = false; sock.write("250 queued\r\n"); }
        continue;
      }
      var u = line.toUpperCase();
      if (authStage === 0) { authStage = 1; handle.auth.push(line); sock.write("334 UGFzc3dvcmQ6\r\n"); continue; }
      if (authStage === 1) { authStage = 2; handle.auth.push(line); sock.write("235 ok\r\n"); continue; }
      if (u.indexOf("EHLO") === 0) sock.write("250-mock\r\n250 AUTH LOGIN\r\n");
      else if (u === "AUTH LOGIN") { authStage = 0; sock.write("334 VXNlcm5hbWU6\r\n"); }
      else if (u === "DATA") { inData = true; sock.write("354 go\r\n"); }
      else if (u === "QUIT") { sock.write("221 bye\r\n"); sock.end(); }
      else sock.write("250 ok\r\n");
    }
  });
}

function _listen(srv, chain, handle) {
  return new Promise(function (resolve) {
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

function _chainOf(which) {
  return typeof which === "string" ? ck.tlsChain(which) : which;
}

function _startImplicit(which) {
  var chain = _chainOf(which);
  var handle = { lines: [], auth: [] };
  var srv = nodeTls.createServer({ key: chain.key, cert: chain.cert }, function (sock) {
    sock.write("220 mock ESMTP\r\n");
    _smtpDialog(sock, handle);
  });
  return _listen(srv, chain, handle);
}

function _startStarttls(which) {
  var chain = _chainOf(which);
  var handle = { lines: [], auth: [] };
  var srv = net.createServer(function (raw) {
    raw.setEncoding("utf8");
    raw.on("error", function () { /* client teardown */ });
    raw.write("220 mock ESMTP\r\n");
    var buf = "";
    raw.on("data", function onData(d) {
      buf += d;
      var idx;
      while ((idx = buf.indexOf("\r\n")) >= 0) {
        var line = buf.slice(0, idx).toUpperCase();
        buf = buf.slice(idx + 2);
        if (line.indexOf("EHLO") === 0) raw.write("250-mock\r\n250 STARTTLS\r\n");
        else if (line === "STARTTLS") {
          raw.write("220 go ahead\r\n");
          raw.removeListener("data", onData);
          _smtpDialog(new nodeTls.TLSSocket(raw, { isServer: true, key: chain.key, cert: chain.cert }), handle);
          return;
        }
      }
    });
  });
  return _listen(srv, chain, handle);
}

function _transport(port, ca, extra) {
  return b.mail.transports.smtp(Object.assign({
    host: "127.0.0.1", port: port, servername: "localhost", ca: ca, preferFamily: 4,
    user: "alice@example.com", pass: "hunter2-secret", timeoutMs: 4000,
  }, extra || {}));
}

async function _send(transport) {
  try { await transport.send(MESSAGE); return { ok: true, code: null, message: null }; }
  catch (e) { return { ok: false, code: e.code || null, message: e.message }; }
}

function testTransportRefusesCompromisedCa() {
  check("mail compromised ca control: the smtp transport accepts a ca bundle with an ordinary CA",
        _code(function () { _transport(1, [CONTROL_CA]); }) === "NO-THROW");
  check("mail compromised ca: the smtp transport refuses a ca bundle holding a CA whose private key is 1",
        _code(function () { _transport(1, [CONTROL_CA, COMPROMISED_CA]); }) === "mail/compromised-key");
  check("mail compromised ca: the smtp transport refuses a ca that is the listed eDellRoot certificate",
        _code(function () { _transport(1, ck.EDELLROOT_CERT_PEM); }) === "mail/compromised-key");
}

async function _pathCase(label, start, extra) {
  var ctl = await start("control");
  var ok = await _send(_transport(ctl.port, ctl.rootCa, extra));
  ctl.server.close();
  check("mail " + label + " control: a relay with a chain of ordinary keys takes the message",
        ok.ok === true && ctl.auth.length === 2, JSON.stringify(ok));

  var bad = await start("compromised");
  var r = await _send(_transport(bad.port, bad.rootCa, extra));
  bad.server.close();
  check("mail " + label + " compromised chain: the send fails with mail/compromised-key before AUTH",
        r.ok === false && r.code === "mail/compromised-key" && bad.auth.length === 0,
        JSON.stringify(r) + " auth=" + bad.auth.length);
}

async function testImplicitTlsRefusesCompromisedChain() {
  await _pathCase("implicit tls", _startImplicit, { implicitTls: true });
}

async function testStarttlsRefusesCompromisedChain() {
  await _pathCase("starttls", _startStarttls, null);
}

function _daneTaRecord(interDer) {
  var spki = new nodeCrypto.X509Certificate(interDer).publicKey.export({ type: "spki", format: "der" });
  return { usage: 2, selector: 1, mtype: 1, dataHex: nodeCrypto.createHash("sha256").update(spki).digest("hex") };
}

async function testDaneTaRefusesCompromisedAnchor() {
  var ctl = await _startImplicit("control");
  var ok = await _send(_transport(ctl.port, undefined,
    { implicitTls: true, dane: [_daneTaRecord(ck.TLS_CONTROL_INTERMEDIATE_DER)] }));
  ctl.server.close();
  check("mail dane-ta control: a TLSA record pinning an ordinary intermediate delivers",
        ok.ok === true && ctl.auth.length === 2, JSON.stringify(ok));

  var bad = await _startImplicit("compromised");
  var r = await _send(_transport(bad.port, undefined,
    { implicitTls: true, dane: [_daneTaRecord(ck.TLS_COMPROMISED_INTERMEDIATE_DER)] }));
  bad.server.close();
  check("mail dane-ta compromised anchor: a TLSA record pinning an intermediate whose private key is 1 fails the " +
        "send with mail/compromised-key before AUTH",
        r.ok === false && r.code === "mail/compromised-key" && /compromised/.test(r.message || "") &&
          bad.auth.length === 0,
        JSON.stringify(r) + " auth=" + bad.auth.length);
}

function _spkiRecord(usage, der) {
  var spki = new nodeCrypto.X509Certificate(der).publicKey.export({ type: "spki", format: "der" });
  return { usage: usage, selector: 1, mtype: 1, dataHex: nodeCrypto.createHash("sha256").update(spki).digest("hex") };
}

function _leafSpkiRecord(usage) {
  return _spkiRecord(usage, ck.TLS_CONTROL_LEAF_DER);
}

var UNMATCHED_DANE_EE = { usage: 3, selector: 1, mtype: 1, dataHex: "00".repeat(32) };

async function testDanePkixMatchNeedsAValidatedPath() {
  var cases = [
    ["a PKIX-EE match beside a DANE-EE record, with the relay's root as ca", "control", true,
      [UNMATCHED_DANE_EE, _leafSpkiRecord(1)], {}, "delivered"],
    ["a PKIX-EE match beside a DANE-EE record, with no ca that reaches the relay's root", "control", false,
      [UNMATCHED_DANE_EE, _leafSpkiRecord(1)], {}, "mail/smtp-failed"],
    ["a PKIX-EE match beside a DANE-EE record, on a chain whose intermediate's private key is 1", "compromised", true,
      [UNMATCHED_DANE_EE, _leafSpkiRecord(1)], {}, "mail/compromised-key"],
    ["a PKIX-EE match with rejectUnauthorized: false and no ca that reaches the relay's root", "control", false,
      [_leafSpkiRecord(1)], { rejectUnauthorized: false }, "mail/smtp-failed"],
    ["a PKIX-EE match with rejectUnauthorized: false and the relay's root as ca", "control", true,
      [_leafSpkiRecord(1)], { rejectUnauthorized: false }, "delivered"],
    ["a PKIX-TA match on the relay's root beside a DANE-EE record, with the root as ca", "control", true,
      [UNMATCHED_DANE_EE, _spkiRecord(0, ck.TLS_ROOT_DER)], {}, "delivered"],
    ["a PKIX-TA match on the relay's root beside a DANE-EE record, on a chain whose intermediate's private key " +
      "is 1", "compromised", true,
      [UNMATCHED_DANE_EE, _spkiRecord(0, ck.TLS_ROOT_DER)], {}, "mail/compromised-key"],
    ["a PKIX-TA match on the relay's root with rejectUnauthorized: false, on a chain whose intermediate's " +
      "private key is 1", "compromised", true,
      [_spkiRecord(0, ck.TLS_ROOT_DER)], { rejectUnauthorized: false }, "mail/compromised-key"],
  ];
  for (var i = 0; i < cases.length; i += 1) {
    var c = cases[i];
    var srv = await _startImplicit(c[1]);
    var r = await _send(_transport(srv.port, c[2] ? srv.rootCa : undefined,
      Object.assign({ implicitTls: true, dane: c[3], daneAllowPkixModes: true }, c[4])));
    srv.server.close();
    var outcome = r.ok ? "delivered" : r.code;
    var want = c[5];
    check("mail dane pkix: " + c[0] + (want === "delivered" ? " delivers" : " fails with " + want + " before AUTH"),
          outcome === want && (want === "delivered" ? srv.auth.length === 2 : srv.auth.length === 0),
          JSON.stringify(r) + " auth=" + srv.auth.length);
  }
}

function testTransportReadsEveryCertificateLabel() {
  var bad = anchors.caLabels(ck.P384_COMPROMISED_CA_DER);
  var ok = anchors.caLabels(ck.P384_CONTROL_CA_DER);
  Object.keys(bad).forEach(function (label) {
    check("mail ca label control: the smtp transport accepts an ordinary CA under the " + label + " label",
          _code(function () { _transport(1, ok[label]); }) === "NO-THROW");
    check("mail ca label: the smtp transport refuses a CA whose private key is 1 under the " + label + " label",
          _code(function () { _transport(1, [CONTROL_CA, bad[label]]); }) === "mail/compromised-key");
  });
}

function testTransportAcceptsACaWithoutACertificate() {
  [["an empty Buffer", Buffer.alloc(0)], ["a Buffer of comments", Buffer.from("# no certificate here\n")]]
    .forEach(function (f) {
      check("mail ca without a certificate: the smtp transport accepts " + f[0] + " as node does",
            _code(function () { _transport(1, f[1]); }) === "NO-THROW");
    });
}

async function testDecoyForACompromisedDefaultAnchorIsRefused() {
  var paths = [["implicit tls", _startImplicit, { implicitTls: true }], ["starttls", _startStarttls, null]];
  for (var p = 0; p < paths.length; p += 1) {
    for (var w = 0; w < 2; w += 1) {
      var which = w === 0 ? "control" : "compromised";
      var chain = anchors.decoyChain(which);
      var srv = await paths[p][1](chain);
      var extra = paths[p][2];
      var r = await anchors.withDefaultAnchor(chain.anchor, function () {
        return _send(_transport(srv.port, undefined, extra));
      });
      srv.server.close();
      if (which === "control") {
        check("mail " + paths[p][0] + " default-store anchor control: a relay with an ordinary anchor takes the message",
              r.ok === true && srv.auth.length === 2, JSON.stringify(r));
      } else {
        check("mail " + paths[p][0] + " default-store anchor: an anchor whose private key is 1 is not trusted, so " +
              "a relay that sends a decoy for it fails certificate verification with mail/smtp-failed before AUTH",
              r.ok === false && r.code === "mail/smtp-failed" && /certificate/i.test(r.message || "") &&
                srv.auth.length === 0,
              JSON.stringify(r) + " auth=" + srv.auth.length);
      }
    }
  }
}

async function run() {
  testTransportRefusesCompromisedCa();
  testTransportReadsEveryCertificateLabel();
  testTransportAcceptsACaWithoutACertificate();
  await testImplicitTlsRefusesCompromisedChain();
  await testStarttlsRefusesCompromisedChain();
  await testDaneTaRefusesCompromisedAnchor();
  await testDanePkixMatchNeedsAValidatedPath();
  await testDecoyForACompromisedDefaultAnchorIsRefused();
}

module.exports = {
  run:                                    run,
  testTransportRefusesCompromisedCa:      testTransportRefusesCompromisedCa,
  testTransportReadsEveryCertificateLabel: testTransportReadsEveryCertificateLabel,
  testTransportAcceptsACaWithoutACertificate: testTransportAcceptsACaWithoutACertificate,
  testImplicitTlsRefusesCompromisedChain: testImplicitTlsRefusesCompromisedChain,
  testStarttlsRefusesCompromisedChain:    testStarttlsRefusesCompromisedChain,
  testDaneTaRefusesCompromisedAnchor:     testDaneTaRefusesCompromisedAnchor,
  testDanePkixMatchNeedsAValidatedPath:   testDanePkixMatchNeedsAValidatedPath,
  testDecoyForACompromisedDefaultAnchorIsRefused: testDecoyForACompromisedDefaultAnchorIsRefused,
};

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); process.exit(0); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
