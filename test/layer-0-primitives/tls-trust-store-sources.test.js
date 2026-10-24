// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The TLS chain check follows the trust OpenSSL used for the handshake:
 *
 * - a root OpenSSL accepts as an issuer without basicConstraints cA:TRUE (an
 *   X.509 v1 root, or a v3 root carrying only keyUsage keyCertSign) anchors
 *   the chain it issued;
 * - a dial that trusts its CA through a prebuilt secureContext or a pfx, and a
 *   listener that serves its client CA from an SNI context, connect an
 *   ordinary chain and still refuse one with a compromised key;
 * - a `ca` holding a TRUSTED CERTIFICATE block the check cannot read does not
 *   throw out of the handshake.
 *
 * Every refusal has a control that differs only in the key.
 */

var nodeTls    = require("node:tls");
var https      = require("node:https");
var nodeCrypto = require("node:crypto");
var v8         = require("node:v8");
var vm         = require("node:vm");
var helpers    = require("../helpers");
var b          = helpers.b;
var check      = helpers.check;
var asn1       = require("../../lib/asn1-der");
var pki        = require("../../lib/vendor/blamejs-pki.cjs");
var networkTls = require("../../lib/network-tls");
var ck         = require("../helpers/compromised-keys");
var paths      = require("../helpers/chain-path");

var ROOT_PEM = ck.certPem(ck.TLS_ROOT_DER);
var LEAF_KEY_PEM = ck.tlsChain("control").key;

function _name(cn) {
  return asn1.writeSequence([asn1.writeSet([asn1.writeSequence([asn1.writeOid("2.5.4.3"), asn1.writeUtf8String(cn)])])]);
}
function _time(d) {
  return asn1.writeNode(0x18, Buffer.from(d.toISOString().replace(/[-:T]/g, "").slice(0, 14) + "Z", "ascii"));
}
function _ext(oid, critical, valueDer) {
  var kids = [asn1.writeOid(oid)];
  if (critical) kids.push(asn1.writeBoolean(true));
  kids.push(asn1.writeOctetString(valueDer));
  return asn1.writeSequence(kids);
}

// A P-256 ECDSA-SHA256 certificate. `version: 1` writes no version field and
// no extensions, as an X.509 v1 certificate carries neither.
function _cert(o) {
  var sigAlg = asn1.writeSequence([asn1.writeOid("1.2.840.10045.4.3.2")]);
  var fields = [];
  if (o.version !== 1) fields.push(asn1.writeContextExplicit(0, asn1.writeInteger(Buffer.from([2]))));
  fields.push(asn1.writeInteger(Buffer.from([o.serial])), sigAlg, _name(o.issuer),
    asn1.writeSequence([_time(new Date("2026-01-01T00:00:00Z")), _time(new Date("2099-12-31T00:00:00Z"))]),
    _name(o.subject), o.publicKey.export({ type: "spki", format: "der" }));
  if (o.version !== 1 && o.extensions && o.extensions.length > 0) {
    fields.push(asn1.writeContextExplicit(3, asn1.writeSequence(o.extensions)));
  }
  var tbs = asn1.writeSequence(fields);
  return asn1.writeSequence([tbs, sigAlg, asn1.writeBitString(nodeCrypto.sign("sha256", tbs, o.signingKey), 0)]);
}

var LEAF_EXTENSIONS = [
  _ext("2.5.29.15", true, asn1.writeBitString(Buffer.from([0x80]), 7)),
  _ext("2.5.29.37", false, asn1.writeSequence([asn1.writeOid("1.3.6.1.5.5.7.3.1"), asn1.writeOid("1.3.6.1.5.5.7.3.2")])),
  _ext("2.5.29.17", false, asn1.writeSequence([asn1.writeNode(0x82, Buffer.from("localhost", "ascii")),
    asn1.writeNode(0x87, Buffer.from([127, 0, 0, 1]))])),
];

// A root of the given shape for `pair`, and a "localhost" leaf it issued
// directly to the TLS fixture leaf key.
function _rootAndLeaf(shape, pair) {
  var root = shape === "v1"
    ? _cert({ version: 1, serial: 1, issuer: "blamejs v1 root", subject: "blamejs v1 root",
      publicKey: pair.publicKey, signingKey: pair.privateKey })
    : _cert({ version: 3, serial: 1, issuer: "blamejs key-usage root", subject: "blamejs key-usage root",
      publicKey: pair.publicKey, signingKey: pair.privateKey,
      extensions: [_ext("2.5.29.15", true, asn1.writeBitString(Buffer.from([0x06]), 1))] });
  var leaf = _cert({ version: 3, serial: 2, issuer: shape === "v1" ? "blamejs v1 root" : "blamejs key-usage root",
    subject: "localhost", publicKey: nodeCrypto.createPublicKey(LEAF_KEY_PEM), signingKey: pair.privateKey,
    extensions: LEAF_EXTENSIONS });
  return { rootPem: ck.certPem(root), leafPem: ck.certPem(leaf) };
}

function _serve(serverOpts, dialOpts) {
  return new Promise(function (resolve) {
    var server = nodeTls.createServer(serverOpts, function (s) {
      s.on("error", function () { /* the client closed */ });
      s.end();
    });
    server.on("tlsClientError", function () { /* the client refused the chain */ });
    server.listen(0, "127.0.0.1", function () {
      var settled = false;
      function done(r) {
        if (settled) return;
        settled = true;
        server.close();
        resolve(r);
      }
      var sock = nodeTls.connect(Object.assign({ host: "127.0.0.1", port: server.address().port, servername: "localhost" },
        dialOpts), function () { sock.end(); done({ ok: true, code: null }); });
      sock.on("error", function (e) { done({ ok: false, code: (e && (e.code || e.message)) || "error" }); });
    });
  });
}

async function testRootsWithoutTheCaBitAnchorTheirChain() {
  var shapes = ["v1", "key-usage"];
  for (var i = 0; i < shapes.length; i += 1) {
    var shape = shapes[i];
    var control = _rootAndLeaf(shape, ck.ecKeyPair("prime256v1", ck.labelScalar("prime256v1", "trust store root " + shape)));
    var plain = await _serve({ key: LEAF_KEY_PEM, cert: control.leafPem }, { ca: [control.rootPem] });
    check("trust store premise: node verifies a chain under a " + shape + " root", plain.ok === true, JSON.stringify(plain));
    var ok = await _serve({ key: LEAF_KEY_PEM, cert: control.leafPem }, { ca: [control.rootPem],
      checkServerIdentity: networkTls._withCompromisedChainCheck(nodeTls.checkServerIdentity, [control.rootPem]) });
    check("trust store: a chain under an ordinary " + shape + " root connects", ok.ok === true, JSON.stringify(ok));
    var bad = _rootAndLeaf(shape, ck.ecKeyPair("prime256v1", 1n));
    var refused = await _serve({ key: LEAF_KEY_PEM, cert: bad.leafPem }, { ca: [bad.rootPem],
      checkServerIdentity: networkTls._withCompromisedChainCheck(nodeTls.checkServerIdentity, [bad.rootPem]) });
    check("trust store: a chain under a " + shape + " root whose key is 1 is refused",
          refused.ok === false && refused.code === "tls/compromised-key", JSON.stringify(refused));
  }
}

// A leaf whose issuer name differs from its root's subject only in case is
// issued by that root under X.509 name comparison, as OpenSSL reads it.
async function testAnchorNamesCompareAsX509Names() {
  var pair = ck.ecKeyPair("prime256v1", ck.labelScalar("prime256v1", "trust store case root"));
  var root = _cert({ version: 3, serial: 1, issuer: "blamejs Case Root", subject: "blamejs Case Root",
    publicKey: pair.publicKey, signingKey: pair.privateKey,
    extensions: [_ext("2.5.29.19", true, asn1.writeSequence([asn1.writeBoolean(true)]))] });
  var leaf = _cert({ version: 3, serial: 2, issuer: "BLAMEJS CASE ROOT", subject: "localhost",
    publicKey: nodeCrypto.createPublicKey(LEAF_KEY_PEM), signingKey: pair.privateKey, extensions: LEAF_EXTENSIONS });
  var rootPem = ck.certPem(root);
  var plain = await _serve({ key: LEAF_KEY_PEM, cert: ck.certPem(leaf) }, { ca: [rootPem] });
  check("trust store premise: node verifies a leaf whose issuer name differs from its root's only in case",
        plain.ok === true, JSON.stringify(plain));
  var ok = await _serve({ key: LEAF_KEY_PEM, cert: ck.certPem(leaf) }, { ca: [rootPem],
    checkServerIdentity: networkTls._withCompromisedChainCheck(nodeTls.checkServerIdentity, [rootPem]) });
  check("trust store: a leaf whose issuer name differs from its root's only in case connects",
        ok.ok === true, JSON.stringify(ok));

  var newRoot = ck.ecKeyPair("prime256v1", BigInt("0x" + nodeCrypto.createHash("sha256")
    .update("blamejs path fixture new root", "utf8").digest("hex")));
  check("trust store premise: the path fixture's new root carries the derived key",
        Buffer.from(newRoot.publicKey.export({ type: "spki", format: "der" })).equals(
          b.crypto._x509(paths.NEW_ROOT_DER).publicKey.export({ type: "spki", format: "der" })));
  var upperRoot = ck.certPem(_cert({ version: 3, serial: 9, issuer: "BLAMEJS PATH FIXTURE NEW ROOT",
    subject: "BLAMEJS PATH FIXTURE NEW ROOT", publicKey: newRoot.publicKey, signingKey: newRoot.privateKey,
    extensions: [_ext("2.5.29.19", true, asn1.writeSequence([asn1.writeBoolean(true)]))] }));
  var cross = paths.crossChain("cross");
  var crossPlain = await _serve({ key: cross.key, cert: cross.cert }, { ca: [upperRoot] });
  check("trust store premise: node verifies the cross-signed chain under the new root's key named in capitals",
        crossPlain.ok === true, JSON.stringify(crossPlain));
  var crossOk = await _serve({ key: cross.key, cert: cross.cert }, { ca: [upperRoot],
    checkServerIdentity: networkTls._withCompromisedChainCheck(nodeTls.checkServerIdentity, [upperRoot]) });
  check("trust store: a cross-signed chain whose anchor names the root in capitals connects",
        crossOk.ok === true, JSON.stringify(crossOk));
}

// The wrapped identity callback runs with the dial options as its receiver,
// as Node calls checkServerIdentity.
async function testIdentityCallbackKeepsItsReceiver() {
  var control = ck.tlsChain("control");
  var seen = null;
  var identity = networkTls._withCompromisedChainCheck(function (host, cert) {
    seen = this && this.servername;
    return nodeTls.checkServerIdentity(this.servername, cert);
  }, [ROOT_PEM]);
  var ok = await _serve({ key: control.key, cert: control.cert }, { ca: [ROOT_PEM], checkServerIdentity: identity });
  check("trust store: an identity callback that reads this.servername runs with the dial options",
        ok.ok === true && seen === "localhost", JSON.stringify({ ok: ok, seen: seen }));
}

async function testSecureContextDial() {
  var identity = networkTls._withCompromisedChainCheck(nodeTls.checkServerIdentity);
  var context = nodeTls.createSecureContext({ ca: [ROOT_PEM] });
  var control = ck.tlsChain("control");
  var ok = await _serve({ key: control.key, cert: control.cert }, { secureContext: context, checkServerIdentity: identity });
  check("trust store: a dial trusting its CA through a secureContext connects an ordinary chain",
        ok.ok === true, JSON.stringify(ok));
  var bad = ck.tlsChain("compromised");
  var refused = await _serve({ key: bad.key, cert: bad.cert }, { secureContext: context, checkServerIdentity: identity });
  check("trust store: a secureContext dial refuses a chain whose intermediate key is 1",
        refused.ok === false && refused.code === "tls/compromised-key", JSON.stringify(refused));
  var pin = b.crypto.spkiPinVerifier({ pins: [b.crypto.spkiPin(ck.TLS_CONTROL_LEAF_DER).sha256,
    b.crypto.spkiPin(ck.TLS_ROOT_DER).sha256], hostname: "localhost" });
  var pinned = await _serve({ key: control.key, cert: control.cert }, { secureContext: context, checkServerIdentity: pin });
  check("trust store: spkiPinVerifier on a secureContext dial accepts a pinned ordinary chain",
        pinned.ok === true, JSON.stringify(pinned));
}

async function testHttpClientAgentWithSecureContext() {
  var control = ck.tlsChain("control");
  var server = https.createServer({ key: control.key, cert: control.cert }, function (req, res) { res.end("hi"); });
  await new Promise(function (resolve) { server.listen(0, "127.0.0.1", resolve); });
  var agent = new https.Agent({ secureContext: nodeTls.createSecureContext({ ca: [ROOT_PEM] }), servername: "localhost" });
  var out;
  try {
    var res = await b.httpClient.request({ url: "https://localhost:" + server.address().port + "/", agent: agent,
      allowInternal: true });
    out = { ok: true, status: res.statusCode };
  } catch (e) { out = { ok: false, code: e.code || e.message }; }
  agent.destroy();
  server.close();
  check("trust store: b.httpClient through an agent trusting its CA by secureContext gets the reply",
        out.ok === true && out.status === 200, JSON.stringify(out));
}

async function _clientPfx(withRoot) {
  var client = ck.tlsClient("control");
  var parts = client.cert.split(/(?=-----BEGIN)/);
  var pbe = { password: "pw", cipher: "aes-256-cbc", iterations: 2048, prf: "hmacWithSHA512" };
  var certs = [{ type: "cert", cert: parts[0] }, { type: "cert", cert: parts[1] }];
  if (withRoot) certs.push({ type: "cert", cert: ROOT_PEM });
  return pki.pkcs12.build({ safeContents: [{ bags: [{ type: "shroudedKey", key: client.key, encrypt: pbe }] },
    { encrypt: pbe, bags: certs }] }, { password: "pw", mac: { algorithm: "hmac", hash: "sha512", iterations: 2048 } });
}

async function testPfxDial() {
  var pfx = await _clientPfx(true);
  var identity = networkTls._withCompromisedChainCheck(nodeTls.checkServerIdentity);
  var control = ck.tlsChain("control");
  var plain = await _serve({ key: control.key, cert: control.cert }, { pfx: pfx, passphrase: "pw" });
  check("trust store premise: node trusts the CA a dial's pfx carries", plain.ok === true, JSON.stringify(plain));
  var ok = await _serve({ key: control.key, cert: control.cert }, { pfx: pfx, passphrase: "pw", checkServerIdentity: identity });
  check("trust store: a dial whose pfx carries its CA connects an ordinary chain", ok.ok === true, JSON.stringify(ok));
  var bad = ck.tlsChain("compromised");
  var refused = await _serve({ key: bad.key, cert: bad.cert }, { pfx: pfx, passphrase: "pw", checkServerIdentity: identity });
  check("trust store: a pfx dial refuses a chain whose intermediate key is 1",
        refused.ok === false && refused.code === "tls/compromised-key", JSON.stringify(refused));
}

function _sniListener(clientMaterial) {
  var server = ck.tlsChain("control");
  var context = nodeTls.createSecureContext({ key: server.key, cert: server.cert,
    ca: [ROOT_PEM, ck.certPem(ck.TLS_CONTROL_INTERMEDIATE_DER), ck.certPem(ck.TLS_COMPROMISED_INTERMEDIATE_DER)] });
  return new Promise(function (resolve) {
    var listener = nodeTls.createServer({ SNICallback: function (name, cb) { cb(null, context); },
      requestCert: true, rejectUnauthorized: false }, function (s) {
      s.on("error", function () { /* the client closed */ });
      s.end(JSON.stringify({ authorized: s.authorized, error: s.authorizationError || null }));
    });
    networkTls.checkClientChains(listener);
    listener.listen(0, "127.0.0.1", function () {
      var out = "";
      var sock = nodeTls.connect({ host: "127.0.0.1", port: listener.address().port, servername: "localhost",
        ca: [ROOT_PEM], cert: clientMaterial.cert, key: clientMaterial.key });
      sock.on("data", function (c) { out += c; });
      sock.on("error", function () { /* resolved on close */ });
      sock.on("close", function () {
        listener.close();
        var parsed = null;
        try { parsed = JSON.parse(out); } catch (_e) { parsed = null; }
        resolve(parsed);
      });
    });
  });
}

async function _listenerSeesClientChain() {
  var server = ck.tlsChain("control");
  var seen = null;
  var listener = nodeTls.createServer({ key: server.key, cert: server.cert, ca: ROOT_PEM, requestCert: true,
    rejectUnauthorized: false }, function (s) {
    var peer = s.getPeerCertificate(true);
    seen = !!(peer && peer.issuerCertificate && peer.issuerCertificate !== peer && peer.issuerCertificate.raw);
    s.end();
  });
  await new Promise(function (resolve) { listener.listen(0, "127.0.0.1", resolve); });
  var client = ck.tlsClient("control");
  await new Promise(function (resolve) {
    var sock = nodeTls.connect({ host: "127.0.0.1", port: listener.address().port, servername: "localhost",
      ca: ROOT_PEM, cert: client.cert, key: client.key });
    sock.on("data", function () { /* drain */ });
    sock.on("error", function () { /* resolved on close */ });
    sock.on("close", resolve);
  });
  listener.close();
  return seen === true;
}

async function testSniListener() {
  var sees = await _listenerSeesClientChain();
  var ok = await _sniListener(ck.tlsClient("control"));
  check("trust store: a listener serving its client CA from an SNI context authorizes an ordinary client",
        ok !== null && ok.authorized === true, JSON.stringify(ok));
  var bad = await _sniListener(ck.tlsClient("compromised"));
  if (sees) {
    check("trust store: an SNI listener refuses a client chain whose intermediate key is 1",
          bad !== null && bad.authorized === false && bad.error === "tls/compromised-key", JSON.stringify(bad));
  } else {
    check("trust store: on a Node that shows a listener only the client leaf, an SNI listener cannot see the " +
          "intermediate and authorizes the client", bad !== null && bad.authorized === true, JSON.stringify(bad));
  }
}

async function testUnreadableTrustedCertificateBlockInCa() {
  var junk = "-----BEGIN TRUSTED CERTIFICATE-----\nMIIB\n-----END TRUSTED CERTIFICATE-----\n";
  var ca = ROOT_PEM + junk;
  var accepted = true;
  try { nodeTls.createSecureContext({ ca: ca }); } catch (_e) { accepted = false; }
  check("trust store premise: node accepts a ca holding an unreadable TRUSTED CERTIFICATE block", accepted);
  var control = ck.tlsChain("control");
  var ok = await _serve({ key: control.key, cert: control.cert }, { ca: ca,
    checkServerIdentity: networkTls._withCompromisedChainCheck(nodeTls.checkServerIdentity, ca) });
  check("trust store: a dial whose ca holds an unreadable TRUSTED CERTIFICATE block connects an ordinary chain",
        ok.ok === true, JSON.stringify(ok));
}

// Distinct ca texts that list the same certificates share one parsed entry per
// certificate, so a dial per tenant with its own bundle text does not keep a
// copy of every root for each text.
function testAnchorEntriesAreSharedAcrossCaTexts() {
  var bundle = nodeTls.rootCertificates.join("\n") + "\n" + ROOT_PEM;
  var first = networkTls._anchorIndexFor(bundle + "\n");
  var second = networkTls._anchorIndexFor(bundle + "\n\n");
  var fp = nodeCrypto.createHash("sha256").update(ck.TLS_ROOT_DER).digest("hex");
  check("trust store: two ca texts listing one certificate share its anchor entry",
        first.byFingerprint.get(fp) !== undefined && first.byFingerprint.get(fp) === second.byFingerprint.get(fp));
  v8.setFlagsFromString("--expose_gc");
  var gc = vm.runInNewContext("gc");
  gc();
  var before = process.memoryUsage();
  for (var i = 0; i < 64; i += 1) networkTls._anchorIndexFor(bundle + "\n".repeat(i + 3));
  gc();
  var after = process.memoryUsage();
  var grownMb = ((after.heapUsed - before.heapUsed) + (after.external - before.external)) / (1024 * 1024);
  check("trust store: 64 distinct ca texts of one bundle add less than 16 MB", grownMb < 16, grownMb.toFixed(1) + " MB");
}

var TESTS = [
  testAnchorEntriesAreSharedAcrossCaTexts,
  testRootsWithoutTheCaBitAnchorTheirChain,
  testAnchorNamesCompareAsX509Names,
  testIdentityCallbackKeepsItsReceiver,
  testSecureContextDial,
  testHttpClientAgentWithSecureContext,
  testPfxDial,
  testSniListener,
  testUnreadableTrustedCertificateBlockInCa,
];

async function run() {
  for (var i = 0; i < TESTS.length; i += 1) await TESTS[i]();
}

module.exports = { run: run, TESTS: TESTS };

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
