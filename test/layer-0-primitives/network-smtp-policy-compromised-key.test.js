// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.network.smtp.policy.dane.verifyChain does not count a TLSA match that
 * rests on a certificate whose private key anyone can hold: the result is
 * `ok: false` with an error whose reason is `dane-compromised-key`. The
 * transport path is driven too: b.mail.transports.smtp({ dane }) against a
 * loopback SMTP peer whose DANE-EE leaf, or whose DANE-TA anchor, has the
 * private key 1 refuses to send, and the control peer receives the message.
 */

var nodeCrypto = require("node:crypto");
var nodeTls    = require("node:tls");
var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var C       = require("../../lib/constants");
var ck      = require("../helpers/compromised-keys");
var composite = require("../helpers/composite-key-cert");

var verifyChain = b.network.smtp.policy.dane.verifyChain;

// Self-signed P-256 "localhost" server certificates (SAN localhost +
// 127.0.0.1, serverAuth, 2026-01-01 .. 2099-12-31) minted with
// @blamejs/pki 0.9.5. The private scalar is 1 for the compromised one and
// SHA-256("blamejs dane-ee fixture leaf") for the control.
var DANE_EE_COMPROMISED_DER = Buffer.from(
  "MIIBijCCAS+gAwIBAgIBBDAKBggqhkjOPQQDAjAUMRIwEAYDVQQDDAlsb2NhbGhv" +
  "c3QwIBcNMjYwMTAxMDAwMDAwWhgPMjA5OTEyMzEwMDAwMDBaMBQxEjAQBgNVBAMM" +
  "CWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABGsX0fLhLEJH+Lzm" +
  "5WOkQPJ3A32BLeszoPShOUXYmMKWT+NC4v4af5uO5+tKfA+eFivOM1drMV7Oy7ZA" +
  "aDe/UfWjcDBuMB0GA1UdDgQWBBS0Z6OZnrXvpnHeADLwipyeXv2g4TAOBgNVHQ8B" +
  "Af8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADAaBgNV" +
  "HREEEzARgglsb2NhbGhvc3SHBH8AAAEwCgYIKoZIzj0EAwIDSQAwRgIhALcAVFHZ" +
  "pkuOsaazv7Ju57WwKwKwcZtmkx9KNqtn0F0WAiEA5WHfyH65Zq5oIobFNPXppEgv" +
  "AFLGQlEnaSWe7eq3ZaI=", "base64");
var DANE_EE_CONTROL_DER = Buffer.from(
  "MIIBijCCAS+gAwIBAgIBBDAKBggqhkjOPQQDAjAUMRIwEAYDVQQDDAlsb2NhbGhv" +
  "c3QwIBcNMjYwMTAxMDAwMDAwWhgPMjA5OTEyMzEwMDAwMDBaMBQxEjAQBgNVBAMM" +
  "CWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABFmprv37K9aJgrwq" +
  "6eYpqzvaTDrUaosYXOLpcJG91OovB9xzdWlmYT5SwYvEIGG/cd7YK49jEkPEgCel" +
  "K8ixKkSjcDBuMB0GA1UdDgQWBBT19YK28aEGqbUgRj1V5zD1PO9ntTAOBgNVHQ8B" +
  "Af8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADAaBgNV" +
  "HREEEzARgglsb2NhbGhvc3SHBH8AAAEwCgYIKoZIzj0EAwIDSQAwRgIhANB8/SqE" +
  "XH7+FEs//7Qbh5jwG88NoaoMC3iecSWwgQbfAiEAuWG50FWqUlDrkfB6wTVWLNoK" +
  "W2jhi0tEkYO/wYmZh8M=", "base64");

function _daneEePeer(which) {
  var d = which === "compromised" ? 1n
    : BigInt("0x" + nodeCrypto.createHash("sha256").update("blamejs dane-ee fixture leaf", "utf8").digest("hex"));
  var der = which === "compromised" ? DANE_EE_COMPROMISED_DER : DANE_EE_CONTROL_DER;
  return {
    key:  ck.ecKeyPair("prime256v1", d).privateKey.export({ type: "pkcs8", format: "pem" }),
    cert: ck.certPem(der),
    der:  der,
  };
}

function _record(usage, selector, der) {
  var data = selector === 0 ? der : new nodeCrypto.X509Certificate(der).publicKey.export({ type: "spki", format: "der" });
  return { usage: usage, selector: selector, mtype: 1, dataHex: nodeCrypto.createHash("sha256").update(data).digest("hex") };
}

function _compromisedRefusal(rv) {
  return rv.ok === false && rv.matches.length === 0 &&
    rv.errors.some(function (e) { return e.reason === "dane-compromised-key"; });
}

function testDaneEeRefusesACompromisedLeaf() {
  [0, 1].forEach(function (selector) {
    var control = verifyChain([DANE_EE_CONTROL_DER], [_record(3, selector, DANE_EE_CONTROL_DER)]);
    check("smtp dane compromised key control: DANE-EE selector " + selector + " matches an ordinary leaf",
          control.ok === true && control.matches[0].usage === "DANE-EE", JSON.stringify(control));
    var bad = verifyChain([DANE_EE_COMPROMISED_DER], [_record(3, selector, DANE_EE_COMPROMISED_DER)]);
    check("smtp dane compromised key: DANE-EE selector " + selector + " refuses a leaf whose private key is 1",
          _compromisedRefusal(bad), JSON.stringify(bad));
  });
  var edell = new nodeCrypto.X509Certificate(ck.EDELLROOT_CERT_PEM).raw;
  var listed = verifyChain([edell], [_record(3, 1, edell)]);
  check("smtp dane compromised key: DANE-EE refuses the listed eDellRoot certificate",
        _compromisedRefusal(listed), JSON.stringify(listed));
}

function testDaneTaRefusesACompromisedAnchor() {
  var control = verifyChain([ck.TLS_CONTROL_LEAF_DER, ck.TLS_CONTROL_INTERMEDIATE_DER],
    [_record(2, 1, ck.TLS_CONTROL_INTERMEDIATE_DER)]);
  check("smtp dane compromised key control: DANE-TA accepts a leaf issued by an ordinary pinned anchor",
        control.ok === true && control.matches[0].usage === "DANE-TA", JSON.stringify(control));
  var bad = verifyChain([ck.TLS_COMPROMISED_LEAF_DER, ck.TLS_COMPROMISED_INTERMEDIATE_DER],
    [_record(2, 1, ck.TLS_COMPROMISED_INTERMEDIATE_DER)]);
  check("smtp dane compromised key: DANE-TA refuses a pinned anchor whose private key is 1",
        _compromisedRefusal(bad), JSON.stringify(bad));
}

function testPkixUsagesRefuseACompromisedKey() {
  var eeControl = verifyChain([DANE_EE_CONTROL_DER], [_record(1, 1, DANE_EE_CONTROL_DER)], { allowPkixModes: true });
  check("smtp dane compromised key control: PKIX-EE matches an ordinary leaf",
        eeControl.ok === true && eeControl.matches[0].usage === "PKIX-EE", JSON.stringify(eeControl));
  var eeBad = verifyChain([DANE_EE_COMPROMISED_DER], [_record(1, 1, DANE_EE_COMPROMISED_DER)], { allowPkixModes: true });
  check("smtp dane compromised key: PKIX-EE refuses a leaf whose private key is 1",
        _compromisedRefusal(eeBad), JSON.stringify(eeBad));
  var taControl = verifyChain([ck.TLS_CONTROL_LEAF_DER, ck.TLS_CONTROL_INTERMEDIATE_DER],
    [_record(0, 1, ck.TLS_CONTROL_INTERMEDIATE_DER)], { allowPkixModes: true });
  check("smtp dane compromised key control: PKIX-TA matches an ordinary anchor",
        taControl.ok === true && taControl.matches[0].usage === "PKIX-TA", JSON.stringify(taControl));
  var taBad = verifyChain([ck.TLS_COMPROMISED_LEAF_DER, ck.TLS_COMPROMISED_INTERMEDIATE_DER],
    [_record(0, 1, ck.TLS_COMPROMISED_INTERMEDIATE_DER)], { allowPkixModes: true });
  check("smtp dane compromised key: PKIX-TA refuses an anchor whose private key is 1",
        _compromisedRefusal(taBad), JSON.stringify(taBad));
}

function testTrustAnchorUsagesScreenThePathBelowThePinnedRoot() {
  [[2, "DANE-TA"], [0, "PKIX-TA"]].forEach(function (u) {
    var opts = { allowPkixModes: true };
    var control = verifyChain([ck.TLS_CONTROL_LEAF_DER, ck.TLS_CONTROL_INTERMEDIATE_DER, ck.TLS_ROOT_DER],
      [_record(u[0], 1, ck.TLS_ROOT_DER)], opts);
    check("smtp dane compromised key control: " + u[1] + " pinning the root accepts an ordinary intermediate below it",
          control.ok === true && control.matches[0].usage === u[1] && control.matches[0].certIndex === 2,
          JSON.stringify(control));
    var bad = verifyChain([ck.TLS_COMPROMISED_LEAF_DER, ck.TLS_COMPROMISED_INTERMEDIATE_DER, ck.TLS_ROOT_DER],
      [_record(u[0], 1, ck.TLS_ROOT_DER)], opts);
    check("smtp dane compromised key: " + u[1] + " pinning the root refuses an intermediate below it whose private key is 1",
          _compromisedRefusal(bad), JSON.stringify(bad));
  });
}

function testPkixTaCountsAMatchOnlyOnAVerifiedPath() {
  var opts = { allowPkixModes: true };
  var control = verifyChain([ck.TLS_CONTROL_LEAF_DER, ck.TLS_CONTROL_INTERMEDIATE_DER],
    [_record(0, 0, ck.TLS_CONTROL_INTERMEDIATE_DER)], opts);
  check("smtp dane PKIX-TA control: a record pinning the leaf's issuer matches",
        control.ok === true && control.matches[0].usage === "PKIX-TA" && control.matches[0].pkixPathRequired === true,
        JSON.stringify(control));
  var decoy = verifyChain([ck.TLS_CONTROL_LEAF_DER, ck.P256_CONTROL_CA_DER],
    [_record(0, 0, ck.P256_CONTROL_CA_DER)], opts);
  check("smtp dane PKIX-TA: a record pinning a certificate that did not issue the leaf is not counted",
        decoy.ok === false && decoy.matches.length === 0 &&
        decoy.errors.some(function (e) { return e.reason === "pkix-ta-path-not-validated" && e.certIndex === 1; }),
        JSON.stringify(decoy));
  var missing = verifyChain([ck.TLS_CONTROL_LEAF_DER, ck.TLS_ROOT_DER], [_record(0, 1, ck.TLS_ROOT_DER)], opts);
  check("smtp dane PKIX-TA: a record pinning the root is not counted when the intermediate is missing from the chain",
        missing.ok === false && missing.errors.some(function (e) { return e.reason === "pkix-ta-path-not-validated"; }),
        JSON.stringify(missing));
}

function testAnUnreadableKeyIsNotReportedAsCompromised() {
  var bCrypto = require("../../lib/crypto");
  var real = bCrypto.compromisedKey;
  var control = verifyChain([DANE_EE_CONTROL_DER], [_record(3, 1, DANE_EE_CONTROL_DER)]);
  var rv;
  bCrypto.compromisedKey = function () {
    var e = new Error("crypto.compromisedKey: the value could not be read as a public key, private key or certificate");
    e.code = "crypto/bad-key";
    throw e;
  };
  try { rv = verifyChain([DANE_EE_CONTROL_DER], [_record(3, 1, DANE_EE_CONTROL_DER)]); }
  finally { bCrypto.compromisedKey = real; }
  check("smtp dane unreadable key control: DANE-EE matches the leaf when its key can be judged",
        control.ok === true, JSON.stringify(control));
  check("smtp dane unreadable key: a leaf whose key cannot be judged is refused as dane-unreadable-key, not dane-compromised-key",
        rv.ok === false && rv.errors.length === 1 && rv.errors[0].reason === "dane-unreadable-key",
        JSON.stringify(rv));
}

// The certificate's tbsCertificate wrapped in a Certificate SEQUENCE with no
// signatureAlgorithm or signature: node:crypto cannot parse it, while the
// subjectPublicKeyInfo inside is the one the well-formed certificate carries.
function _signaturelessCertificate(der) {
  var asn1 = require("../../lib/asn1-der");
  var tbs = asn1.readSequence(asn1.readNode(der, 0).value)[0].raw;
  var len = tbs.length < 128 ? Buffer.from([tbs.length])
    : tbs.length < 256 ? Buffer.from([0x81, tbs.length]) : Buffer.from([0x82, tbs.length >> 8, tbs.length & 255]);
  return Buffer.concat([Buffer.from([0x30]), len, tbs]);
}

function testAnEndEntityLeafNodeCannotParseIsStillJudged() {
  [[3, "DANE-EE", {}], [1, "PKIX-EE", { allowPkixModes: true }]].forEach(function (u) {
    var controlLeaf = _signaturelessCertificate(DANE_EE_CONTROL_DER);
    var badLeaf = _signaturelessCertificate(DANE_EE_COMPROMISED_DER);
    var parses = [controlLeaf, badLeaf].map(function (der) {
      try { return new nodeCrypto.X509Certificate(der) instanceof nodeCrypto.X509Certificate; } catch (_e) { return false; }
    });
    check("smtp dane unparseable leaf premise: node:crypto parses neither signature-less leaf",
          parses[0] === false && parses[1] === false, JSON.stringify(parses));
    var control = verifyChain([controlLeaf], [_record(u[0], 1, DANE_EE_CONTROL_DER)], u[2]);
    check("smtp dane unparseable leaf control: " + u[1] + " matches a signature-less leaf carrying an ordinary key",
          control.ok === true && control.matches[0].usage === u[1], JSON.stringify(control));
    var bad = verifyChain([badLeaf], [_record(u[0], 1, DANE_EE_COMPROMISED_DER)], u[2]);
    check("smtp dane unparseable leaf: " + u[1] + " refuses a signature-less leaf whose private key is 1",
          _compromisedRefusal(bad), JSON.stringify(bad));
    var whole = verifyChain([badLeaf], [_record(u[0], 0, badLeaf)], u[2]);
    check("smtp dane unparseable leaf: " + u[1] + " selector 0 refuses a signature-less leaf whose private key is 1",
          _compromisedRefusal(whole), JSON.stringify(whole));
    var noKey = Buffer.from("bytes that are not a certificate", "utf8");
    var keyless = verifyChain([noKey], [_record(u[0], 0, noKey)], u[2]);
    check("smtp dane unparseable leaf: " + u[1] + " refuses a full match on bytes that carry no readable key as dane-unreadable-key",
          keyless.ok === false && keyless.matches.length === 0 && keyless.errors.length === 1 &&
          keyless.errors[0].reason === "dane-unreadable-key", JSON.stringify(keyless));
  });
}

function _countResolveChainCalls(fn) {
  var x509Chain = require("../../lib/x509-chain");
  var real = x509Chain.resolveChain;
  var calls = 0;
  x509Chain.resolveChain = function () { calls += 1; return real.apply(this, arguments); };
  try { return { value: fn(), calls: calls }; }
  finally { x509Chain.resolveChain = real; }
}

function testOneTrustAnchorIsSearchedOncePerCall() {
  var opts = { allowPkixModes: true };
  var chain = [ck.TLS_CONTROL_LEAF_DER, ck.TLS_CONTROL_INTERMEDIATE_DER, ck.TLS_ROOT_DER];
  var one = _countResolveChainCalls(function () {
    return verifyChain(chain, [_record(2, 1, ck.TLS_ROOT_DER)], opts);
  });
  check("smtp dane anchor search control: one DANE-TA record pinning the root searches one path and matches",
        one.value.ok === true && one.calls === 1, JSON.stringify({ calls: one.calls, rv: one.value }));
  var three = _countResolveChainCalls(function () {
    return verifyChain(chain, [_record(2, 1, ck.TLS_ROOT_DER), _record(2, 0, ck.TLS_ROOT_DER),
      _record(0, 1, ck.TLS_ROOT_DER)], opts);
  });
  check("smtp dane anchor search: three records pinning the same root search the path to it once",
        three.value.ok === true && three.value.matches.length === 3 && three.calls === 1,
        JSON.stringify({ calls: three.calls, rv: three.value }));
  var refused = _countResolveChainCalls(function () {
    return verifyChain([ck.TLS_COMPROMISED_LEAF_DER, ck.TLS_COMPROMISED_INTERMEDIATE_DER, ck.TLS_ROOT_DER],
      [_record(2, 1, ck.TLS_ROOT_DER), _record(0, 1, ck.TLS_ROOT_DER)], opts);
  });
  check("smtp dane anchor search: both records pinning a root above a compromised intermediate are refused from one search",
        refused.value.ok === false && refused.calls === 1 && refused.value.errors.length === 2 &&
        refused.value.errors.every(function (e) { return e.reason === "dane-compromised-key"; }),
        JSON.stringify({ calls: refused.calls, rv: refused.value }));
}

function testACompositeKeyLeafIsNotRefused() {
  [0, 1].forEach(function (selector) {
    var data = selector === 0 ? composite.COMPOSITE_CERT_DER : composite.COMPOSITE_SPKI_DER;
    var rv = verifyChain([composite.COMPOSITE_CERT_DER],
      [{ usage: 3, selector: selector, mtype: 1, dataHex: nodeCrypto.createHash("sha256").update(data).digest("hex") }]);
    check("smtp dane composite key: DANE-EE selector " + selector + " matches a composite ML-DSA certificate",
          rv.ok === true && rv.matches[0].usage === "DANE-EE", JSON.stringify(rv));
  });
}

function _startSmtpPeer(peer) {
  var seen = { data: "" };
  var server = nodeTls.createServer({ key: peer.key, cert: peer.cert }, function (sock) {
    sock.setEncoding("utf8");
    sock.on("error", function () {});
    var buf = "", inData = false;
    sock.write("220 peer ESMTP\r\n");
    sock.on("data", function (chunk) {
      buf += chunk;
      for (;;) {
        if (inData) {
          var end = buf.indexOf("\r\n.\r\n");
          if (end === -1) return;
          seen.data += buf.slice(0, end);
          buf = buf.slice(end + 5);
          inData = false;
          sock.write("250 queued\r\n");
          continue;
        }
        var nl = buf.indexOf("\r\n");
        if (nl === -1) return;
        var line = buf.slice(0, nl).toUpperCase();
        buf = buf.slice(nl + 2);
        if (line.indexOf("EHLO") === 0) sock.write("250 peer\r\n");
        else if (line === "DATA") { inData = true; sock.write("354 go\r\n"); }
        else if (line === "QUIT") { sock.write("221 bye\r\n"); sock.end(); }
        else sock.write("250 OK\r\n");
      }
    });
  });
  return new Promise(function (resolve) {
    server.listen(0, "127.0.0.1", function () { resolve({ server: server, port: server.address().port, seen: seen }); });
  });
}

async function _send(peer, record, extra) {
  var s = await _startSmtpPeer(peer);
  var out = { ok: false, message: null, received: false };
  try {
    var t = b.mail.transports.smtp(Object.assign({
      host: "127.0.0.1", port: s.port, implicitTls: true, servername: "localhost",
      preferFamily: 4, timeoutMs: C.TIME.seconds(5), dane: Array.isArray(record) ? record : [record],
    }, extra || {}));
    var r = await t.send({ from: "s@a.test", to: "r@b.test", subject: "s", text: "dane fixture body" });
    out.ok = r && r.code === 250;
  } catch (e) {
    out.message = (e && e.message) || String(e);
  }
  await new Promise(function (resolve) { s.server.close(function () { resolve(); }); });
  out.received = s.seen.data.indexOf("dane fixture body") !== -1;
  return out;
}

async function testTransportRefusesACompromisedDaneEePeer() {
  var good = _daneEePeer("control");
  var control = await _send(good, _record(3, 1, good.der));
  check("smtp dane compromised key control: the transport delivers to a DANE-EE peer with an ordinary key",
        control.ok === true && control.received === true, JSON.stringify(control));
  var weak = _daneEePeer("compromised");
  var bad = await _send(weak, _record(3, 1, weak.der));
  check("smtp dane compromised key: the transport refuses a DANE-EE peer whose private key is 1 and sends no message",
        bad.ok === false && bad.received === false && /dane-compromised-key/.test(bad.message || ""),
        JSON.stringify(bad));
}

async function testTransportRefusesACompromisedDaneTaPeer() {
  var goodChain = ck.tlsChain("control");
  var control = await _send(goodChain, _record(2, 1, ck.TLS_CONTROL_INTERMEDIATE_DER));
  check("smtp dane compromised key control: the transport delivers to a DANE-TA peer under an ordinary anchor",
        control.ok === true && control.received === true, JSON.stringify(control));
  var weakChain = ck.tlsChain("compromised");
  var bad = await _send(weakChain, _record(2, 1, ck.TLS_COMPROMISED_INTERMEDIATE_DER));
  check("smtp dane compromised key: the transport refuses a DANE-TA peer whose anchor's private key is 1",
        bad.ok === false && bad.received === false && /dane-compromised-key/.test(bad.message || ""),
        JSON.stringify(bad));
}

async function testTransportRefusesACompromisedIntermediateUnderAPkixTaRoot() {
  var records = [
    { usage: 3, selector: 1, mtype: 1, dataHex: "00".repeat(32) },
    _record(0, 1, ck.TLS_ROOT_DER),
  ];
  function peer(which) {
    var chain = ck.tlsChain(which);
    return { key: chain.key, cert: chain.cert + chain.rootCa };
  }
  var pkixOpts = { daneAllowPkixModes: true, ca: ck.certPem(ck.TLS_ROOT_DER) };
  var control = await _send(peer("control"), records, pkixOpts);
  check("smtp dane compromised key control: the transport delivers to a peer whose chain reaches the PKIX-TA root",
        control.ok === true && control.received === true, JSON.stringify(control));
  var bad = await _send(peer("compromised"), records, pkixOpts);
  check("smtp dane compromised key: the transport refuses a peer whose intermediate under the PKIX-TA root has private key 1",
        bad.ok === false && bad.received === false && /dane-compromised-key/.test(bad.message || ""),
        JSON.stringify(bad));
}

async function run() {
  testDaneEeRefusesACompromisedLeaf();
  testDaneTaRefusesACompromisedAnchor();
  testPkixUsagesRefuseACompromisedKey();
  testTrustAnchorUsagesScreenThePathBelowThePinnedRoot();
  testPkixTaCountsAMatchOnlyOnAVerifiedPath();
  testAnUnreadableKeyIsNotReportedAsCompromised();
  testACompositeKeyLeafIsNotRefused();
  testAnEndEntityLeafNodeCannotParseIsStillJudged();
  testOneTrustAnchorIsSearchedOncePerCall();
  await testTransportRefusesACompromisedDaneEePeer();
  await testTransportRefusesACompromisedDaneTaPeer();
  await testTransportRefusesACompromisedIntermediateUnderAPkixTaRoot();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
