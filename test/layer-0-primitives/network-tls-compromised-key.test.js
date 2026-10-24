// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.network.tls refuses a compromised key on every path that trusts one:
 * trust anchors added with addCa / addCaBundle / bootFromEnv, a `ca` passed to
 * buildOptions / connectWithEch / ocsp.connect / applyToContext, the server
 * chain of every client dial built from those options, an OCSP response signed
 * by a compromised issuer key, an SCT signed by a compromised log key, and the
 * system roots useSystemTrust adds. Every refusal has a control that differs
 * only in the key.
 */

var nodeFs  = require("node:fs");
var nodeOs  = require("node:os");
var nodePath = require("node:path");
var nodeTls = require("node:tls");
var nodeCrypto = require("node:crypto");
var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var ck      = require("../helpers/compromised-keys");
var asn1    = require("../../lib/asn1-der");

var COMPROMISED_CA_PEM = ck.certPem(ck.P384_COMPROMISED_CA_DER);
var CONTROL_CA_PEM     = ck.certPem(ck.P384_CONTROL_CA_DER);

function _codeOf(fn) {
  try { fn(); return null; } catch (e) { return (e && e.code) || String(e); }
}

async function _rejection(promise) {
  try { await promise; return null; } catch (e) { return e; }
}

function _tlsServer(which) {
  var chain = ck.tlsChain(which);
  return new Promise(function (resolve) {
    var server = nodeTls.createServer({ key: chain.key, cert: chain.cert }, function (s) {
      s.on("error", function () { /* the client tears the socket down */ });
      s.end("hello");
    });
    server._fixtureSockets = [];
    server.on("connection", function (s) { server._fixtureSockets.push(s); });
    server.on("tlsClientError", function () { /* the client refused the chain */ });
    server.listen(0, "127.0.0.1", function () { resolve({ server: server, port: server.address().port, rootCa: chain.rootCa }); });
  });
}

function _close(server) {
  (server._fixtureSockets || []).forEach(function (s) { s.destroy(); });
  return new Promise(function (resolve) { server.close(function () { resolve(); }); });
}

async function _echOutcome(opts) {
  var sock = null;
  var err = await _rejection(b.network.tls.connectWithEch(opts).then(function (s) { sock = s; }));
  if (sock) sock.destroy();
  return { connected: sock !== null, err: err };
}

function _connect(opts) {
  return new Promise(function (resolve) {
    var settled = false;
    function done(v) { if (!settled) { settled = true; resolve(v); } }
    var sock = nodeTls.connect(opts, function () { sock.end(); done({ ok: true, code: null }); });
    sock.on("error", function (e) { done({ ok: false, code: (e && e.code) || e.message }); });
  });
}

function testAddCa() {
  var nt = b.network.tls;
  nt._resetForTest();
  var control = nt.addCa(CONTROL_CA_PEM, { label: "control", audit: false });
  check("addCa control: an ordinary CA is added", Array.isArray(control) && control.length === 1 &&
        nt.getTrustStore().length === 1);
  check("addCa: a CA whose P-384 private key is 1 is refused with tls/compromised-key",
        _codeOf(function () { nt.addCa(COMPROMISED_CA_PEM, { label: "bad", audit: false }); }) === "tls/compromised-key");
  check("addCa: the listed eDellRoot certificate is refused with tls/compromised-key",
        _codeOf(function () { nt.addCa(ck.EDELLROOT_CERT_PEM, { audit: false }); }) === "tls/compromised-key");
  check("addCa: a bundle carrying one compromised CA is refused whole",
        _codeOf(function () { nt.addCa(CONTROL_CA_PEM + COMPROMISED_CA_PEM, { audit: false }); }) === "tls/compromised-key" &&
        nt.getTrustStore().length === 1);
  nt._resetForTest();
}

function testAddCaBundle() {
  var nt = b.network.tls;
  var dir = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), "blamejs-ck-"));
  var goodDir = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), "blamejs-ck-"));
  try {
    nodeFs.writeFileSync(nodePath.join(dir, "a-control.pem"), CONTROL_CA_PEM);
    nodeFs.writeFileSync(nodePath.join(dir, "b-compromised.crt"), COMPROMISED_CA_PEM);
    nodeFs.writeFileSync(nodePath.join(goodDir, "a-control.pem"), CONTROL_CA_PEM);
    nt._resetForTest();
    check("addCaBundle control: a directory of ordinary CAs is added",
          nt.addCaBundle(goodDir, { audit: false }).length === 1);
    nt._resetForTest();
    check("addCaBundle: a directory holding a compromised CA is refused and adds nothing",
          _codeOf(function () { nt.addCaBundle(dir, { audit: false }); }) === "tls/compromised-key" &&
          nt.getTrustStore().length === 0);
  } finally {
    nt._resetForTest();
    nodeFs.rmSync(dir, { recursive: true, force: true });
    nodeFs.rmSync(goodDir, { recursive: true, force: true });
  }
}

function testBootFromEnv() {
  var nt = b.network.tls;
  var dir = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), "blamejs-ck-"));
  var goodDir = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), "blamejs-ck-"));
  try {
    nodeFs.writeFileSync(nodePath.join(dir, "a-control.pem"), CONTROL_CA_PEM);
    nodeFs.writeFileSync(nodePath.join(dir, "b-compromised.crt"), COMPROMISED_CA_PEM);
    nodeFs.writeFileSync(nodePath.join(goodDir, "a-control.pem"), CONTROL_CA_PEM);
    var badFile = nodePath.join(dir, "b-compromised.crt");
    var goodFile = nodePath.join(goodDir, "a-control.pem");
    nt._resetForTest();
    var applied = b.network.bootFromEnv({ env: { BLAMEJS_EXTRA_CA_CERTS: goodFile }, audit: false });
    check("bootFromEnv control: BLAMEJS_EXTRA_CA_CERTS with an ordinary CA is loaded",
          applied.tls.fileLoaded === goodFile && nt.getTrustStore().length === 1);
    nt._resetForTest();
    check("bootFromEnv: BLAMEJS_EXTRA_CA_CERTS naming a compromised CA throws tls/compromised-key",
          _codeOf(function () { b.network.bootFromEnv({ env: { BLAMEJS_EXTRA_CA_CERTS: badFile }, audit: false }); }) ===
            "tls/compromised-key" && nt.getTrustStore().length === 0);
    check("bootFromEnv: BLAMEJS_EXTRA_CA_CERTS_DIR holding a compromised CA throws tls/compromised-key",
          _codeOf(function () { b.network.bootFromEnv({ env: { BLAMEJS_EXTRA_CA_CERTS_DIR: dir }, audit: false }); }) ===
            "tls/compromised-key" && nt.getTrustStore().length === 0);
  } finally {
    nt._resetForTest();
    nodeFs.rmSync(dir, { recursive: true, force: true });
    nodeFs.rmSync(goodDir, { recursive: true, force: true });
  }
}

async function testBuildOptions() {
  var nt = b.network.tls;
  check("buildOptions control: an ordinary ca is returned",
        typeof nt.buildOptions({ ca: CONTROL_CA_PEM }).ca === "string");
  check("buildOptions: a compromised ca throws tls/compromised-key",
        _codeOf(function () { nt.buildOptions({ ca: COMPROMISED_CA_PEM }); }) === "tls/compromised-key");
  check("buildOptions: a compromised ca inside an array throws tls/compromised-key",
        _codeOf(function () { nt.buildOptions({ ca: [CONTROL_CA_PEM, Buffer.from(ck.EDELLROOT_CERT_PEM)] }); }) ===
          "tls/compromised-key");
}

async function testBuildOptionsChain() {
  var nt = b.network.tls;
  var control = await _tlsServer("control");
  var bad = await _tlsServer("compromised");
  try {
    var okRv = await _connect(Object.assign({ host: "127.0.0.1", port: control.port },
      nt.buildOptions({ ca: control.rootCa, sni: "localhost" })));
    check("buildOptions control: a dial with its options completes against the control chain",
          okRv.ok === true, JSON.stringify(okRv));
    var badRv = await _connect(Object.assign({ host: "127.0.0.1", port: bad.port },
      nt.buildOptions({ ca: bad.rootCa, sni: "localhost" })));
    check("buildOptions: a dial with its options refuses a chain whose intermediate's private key is 1",
          badRv.ok === false && badRv.code === "tls/compromised-key", JSON.stringify(badRv));
  } finally {
    await _close(control.server);
    await _close(bad.server);
  }
}

async function testConnectWithEch() {
  var nt = b.network.tls;
  var err = await _rejection(nt.connectWithEch({ host: "127.0.0.1", port: 1, ca: COMPROMISED_CA_PEM, timeoutMs: 2000 }));
  check("connectWithEch: a compromised ca rejects with tls/compromised-key",
        err && err.code === "tls/compromised-key", err && (err.code + " " + err.message));
}

async function testConnectWithEchChain() {
  var control = await _tlsServer("control");
  var bad = await _tlsServer("compromised");
  try {
    var hookCalls = 0;
    function hook(host, cert) { hookCalls += 1; return nodeTls.checkServerIdentity(host, cert); }
    var ok = await _echOutcome({ host: "127.0.0.1", servername: "localhost", port: control.port,
      ca: control.rootCa, checkServerIdentity: hook, timeoutMs: 4000 });
    check("connectWithEch control: the control chain connects and the operator's checkServerIdentity runs",
          ok.connected === true && hookCalls === 1, ok.err && ok.err.message);
    var bad2 = await _echOutcome({ host: "127.0.0.1", servername: "localhost", port: bad.port,
      ca: bad.rootCa, checkServerIdentity: hook, timeoutMs: 4000 });
    check("connectWithEch: a chain whose intermediate's private key is 1 is refused with tls/compromised-key",
          bad2.connected === false && bad2.err && bad2.err.code === "tls/compromised-key",
          bad2.err ? bad2.err.code + " " + bad2.err.message : "connected");
  } finally {
    await _close(control.server);
    await _close(bad.server);
  }
}

async function testOcspConnect() {
  var nt = b.network.tls;
  var err = await _rejection(nt.ocsp.connect({ host: "127.0.0.1", port: 1, ca: COMPROMISED_CA_PEM }));
  check("ocsp.connect: a compromised ca rejects with tls/compromised-key",
        err && err.code === "tls/compromised-key", err && (err.code + " " + err.message));
}

async function testOcspConnectChain() {
  var nt = b.network.tls;
  var control = await _tlsServer("control");
  var bad = await _tlsServer("compromised");
  try {
    var okErr = await _rejection(nt.ocsp.connect({ host: "127.0.0.1", servername: "localhost", port: control.port,
      ca: control.rootCa }));
    check("ocsp.connect control: the control chain connects", okErr === null, okErr && okErr.message);
    var badErr = await _rejection(nt.ocsp.connect({ host: "127.0.0.1", servername: "localhost", port: bad.port,
      ca: bad.rootCa }));
    check("ocsp.connect: a chain whose intermediate's private key is 1 is refused with tls/compromised-key",
          badErr && badErr.code === "tls/compromised-key", badErr && (badErr.code + " " + badErr.message));
  } finally {
    await _close(control.server);
    await _close(bad.server);
  }
}

async function testApplyToContextClient() {
  var nt = b.network.tls;
  check("applyToContext: a compromised ca in base throws tls/compromised-key",
        _codeOf(function () { nt.applyToContext({ base: { ca: COMPROMISED_CA_PEM }, role: "client" }); }) ===
          "tls/compromised-key");
  check("applyToContext control: an ordinary ca in base is kept",
        nt.applyToContext({ base: { ca: CONTROL_CA_PEM }, role: "client" }).ca === CONTROL_CA_PEM);
}

async function testApplyToContextClientChain() {
  var nt = b.network.tls;
  var hostCalls = 0;
  var wrapped = nt.applyToContext({ base: { checkServerIdentity: function () { hostCalls += 1; } }, role: "client" });
  var control = await _tlsServer("control");
  var bad = await _tlsServer("compromised");
  try {
    var okRv = await _connect(Object.assign({ host: "127.0.0.1", port: control.port, servername: "localhost",
      ca: [control.rootCa] }, { checkServerIdentity: wrapped.checkServerIdentity }));
    check("applyToContext control: role client keeps the operator's checkServerIdentity and accepts the control chain",
          okRv.ok === true && hostCalls === 1, JSON.stringify(okRv));
    var badRv = await _connect(Object.assign({ host: "127.0.0.1", port: bad.port, servername: "localhost",
      ca: [bad.rootCa] }, { checkServerIdentity: wrapped.checkServerIdentity }));
    check("applyToContext: role client refuses a server chain carrying a compromised key",
          badRv.ok === false && badRv.code === "tls/compromised-key", JSON.stringify(badRv));
  } finally {
    await _close(control.server);
    await _close(bad.server);
  }
}

function testSystemTrustRoots() {
  var nt = b.network.tls;
  var kept = typeof nt._systemTrustRoots === "function"
    ? nt._systemTrustRoots([ck.EDELLROOT_CERT_PEM, CONTROL_CA_PEM, COMPROMISED_CA_PEM]) : null;
  check("useSystemTrust: system roots with a compromised key are left out and ordinary roots kept",
        Array.isArray(kept) && kept.length === 1 && kept[0] === CONTROL_CA_PEM, JSON.stringify(kept && kept.length));
  nt._resetForTest();
  nt.useSystemTrust(true);
  var ca = nt.applyToContext({ role: "client" }).ca;
  check("useSystemTrust control: the bundled roots are added",
        Array.isArray(ca) && ca.length > 0 && ca.length === nodeTls.rootCertificates.length);
  nt._resetForTest();
}

function testOcspEvaluate() {
  var nt = b.network.tls;
  var produced = Date.parse("2025-06-15T00:00:00Z");
  function evaluate(kp) {
    var r = helpers.buildOcspResponse({ keyPair: kp, producedAtMs: produced,
      thisUpdateMs: produced - 60000, nextUpdateMs: produced + 3600000 });
    return nt.ocsp.evaluate(r.der, { issuerPem: r.issuerPem, serialHex: r.serialHex, now: produced });
  }
  var control = evaluate(ck.ecKeyPair("prime256v1", ck.labelScalar("prime256v1", "blamejs ocsp control issuer")));
  check("ocsp.evaluate control: a response signed by an ordinary issuer key is good",
        control.ok === true && control.certStatus === "good", JSON.stringify(control.errors));
  var bad = evaluate(ck.ecKeyPair("prime256v1", 1n));
  check("ocsp.evaluate: a response signed by an issuer whose private key is 1 is refused as a compromised key",
        bad.ok === false && bad.signatureValid === false &&
        /compromised key/.test((bad.errors || []).join(" ")), JSON.stringify(bad));
}

var OID_CT_SCT_LIST = "1.3.6.1.4.1.11129.2.4.2";

function _sctCert(exts) {
  var algId = asn1.writeSequence([asn1.writeOid("1.2.840.113549.1.1.1"), asn1.writeNull()]);
  var cnrdn = asn1.writeSequence([asn1.writeOid("2.5.4.3"), asn1.writeNode(0x0c, Buffer.from("ct.example", "ascii"))]);
  var name = asn1.writeSequence([asn1.writeNode(0x31, cnrdn)]);
  var validity = asn1.writeSequence([
    asn1.writeNode(0x17, Buffer.from("260101000000Z", "ascii")),
    asn1.writeNode(0x17, Buffer.from("270101000000Z", "ascii")),
  ]);
  var spki = asn1.writeSequence([algId, asn1.writeNode(0x03,
    Buffer.concat([Buffer.from([0]), Buffer.from("k-bytes-aaaaaaaaaaaaaaaaaaaaaaaa")]))]);
  var version = asn1.writeContextExplicit(0, asn1.writeInteger(Buffer.from([2])));
  var kids = [version, asn1.writeInteger(Buffer.from([0x12, 0x34])), algId, name, validity, name, spki,
    asn1.writeContextExplicit(3, asn1.writeSequence(exts))];
  return asn1.writeSequence([asn1.writeSequence(kids), algId, asn1.writeNode(0x03, Buffer.from([0, 0, 0, 0]))]);
}

function _signedSctCert(privateKey, logId, issuerKeyHash, ts) {
  function sct(sig) {
    var t = Buffer.alloc(8); t.writeBigUInt64BE(BigInt(ts));
    var sl = Buffer.alloc(2); sl.writeUInt16BE(sig.length);
    return Buffer.concat([Buffer.from([0]), logId, t, Buffer.from([0, 0]), Buffer.from([4, 3]), sl, sig]);
  }
  function certWith(sig) {
    var one = sct(sig);
    var l = Buffer.alloc(2); l.writeUInt16BE(one.length);
    var body = Buffer.concat([l, one]);
    var o = Buffer.alloc(2); o.writeUInt16BE(body.length);
    return _sctCert([asn1.writeSequence([asn1.writeOid(OID_CT_SCT_LIST),
      asn1.writeOctetString(asn1.writeOctetString(Buffer.concat([o, body])))])]);
  }
  var nt = b.network.tls;
  var placeholder = certWith(Buffer.from("x"));
  var parsed = nt.ct.parseScts(placeholder)[0];
  var entry = nt._buildSctSignedEntry(nt._stripSctExtensionFromCert(placeholder), parsed, issuerKeyHash);
  return certWith(nodeCrypto.sign("sha256", entry, privateKey));
}

function testCtLogKeys() {
  var nt = b.network.tls;
  var issuerKeyHash = nodeCrypto.createHash("sha256").update("blamejs ct fixture issuer").digest();
  var ts = Date.now() - 60000;
  function verify(kp) {
    var spki = kp.publicKey.export({ type: "spki", format: "der" });
    var logId = nodeCrypto.createHash("sha256").update(spki).digest();
    var logKeys = {};
    logKeys[logId.toString("hex")] = kp.publicKey.export({ type: "spki", format: "pem" });
    var cert = _signedSctCert(kp.privateKey, logId, issuerKeyHash, ts);
    var opts = { logKeys: logKeys, minScts: 1, issuerKeyHash: issuerKeyHash };
    return { rv: nt.ct.verifyScts(cert, opts), hook: nt.ct.requireScts(opts)({ raw: cert }) };
  }
  var control = verify(ck.ecKeyPair("prime256v1", ck.labelScalar("prime256v1", "blamejs ct control log")));
  check("ct.verifyScts control: an SCT signed by an ordinary log key verifies",
        control.rv.ok === true && control.rv.verifiedCount === 1 && control.hook === null, JSON.stringify(control.rv));
  var bad = verify(ck.ecKeyPair("prime256v1", 1n));
  check("ct.verifyScts: an SCT signed by a log key whose private key is 1 does not count",
        bad.rv.ok === false && bad.rv.verifiedCount === 0 &&
        bad.rv.scts[0] && bad.rv.scts[0].reason === "log-key-compromised", JSON.stringify(bad.rv));
  check("ct.requireScts: the hook refuses a certificate whose only SCT comes from a compromised log key",
        bad.hook instanceof Error);
}

var TESTS = [
  testAddCa, testAddCaBundle, testBootFromEnv, testBuildOptions, testBuildOptionsChain, testConnectWithEch,
  testConnectWithEchChain, testOcspConnect, testOcspConnectChain, testApplyToContextClient,
  testApplyToContextClientChain, testSystemTrustRoots, testOcspEvaluate,
  testCtLogKeys,
];

async function run() {
  for (var i = 0; i < TESTS.length; i += 1) await TESTS[i]();
}

module.exports = { run: run, TESTS: TESTS };

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
