// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A DER certificate that carries another certificate's PEM text in an
 * extension is read as itself wherever the framework builds a certificate
 * from bytes. node's X509Certificate(buffer) reads the embedded PEM block
 * ahead of the DER around it, so a verifier that built its certificate that
 * way judged and trusted the embedded certificate:
 *
 * - the TLS chain check matched a leaf carrying the trust root's PEM as the
 *   root itself and stopped before the compromised intermediate that issued
 *   the leaf;
 * - DANE matchCertificate and the SMTP DANE verifyChain judged the embedded
 *   certificate's key instead of the certificate's own;
 * - an OID4VCI proof x5c was verified with the embedded certificate's key;
 * - requireMtls looked up the embedded certificate's serial for revocation.
 *
 * Every refusal has a control that carries the same text and an ordinary key.
 */

var nodeCrypto = require("node:crypto");
var nodeTls    = require("node:tls");
var helpers    = require("../helpers");
var b          = helpers.b;
var check      = helpers.check;
var ck         = require("../helpers/compromised-keys");
var crafted    = require("../helpers/crafted-compromised-certs");
var networkTls = require("../../lib/network-tls");

var COMPROMISED = crafted.COMPROMISED;
var CONTROL_CA  = crafted.CONTROL_CA;
var ROOT_PEM    = ck.certPem(ck.TLS_ROOT_DER);

var CONTROL_INTERMEDIATE = ck.ecKeyPair("prime256v1", BigInt("0x" + nodeCrypto.createHash("sha256")
  .update("blamejs tls fixture intermediate", "utf8").digest("hex")));

function _spki(key) {
  return Buffer.from(key.export({ type: "spki", format: "der" }));
}

function testHelperReadsDerAsDer() {
  var der = crafted.selfSignedCa(COMPROMISED, crafted.textExtension(crafted.CERT_PEM_TEXT));
  check("x509 der construction premise: node reads the embedded certificate from the buffer",
        !Buffer.from(new nodeCrypto.X509Certificate(der).raw).equals(der));
  check("x509 der construction: b.crypto._x509 reads a DER buffer as the certificate it encodes",
        Buffer.from(b.crypto._x509(der).raw).equals(der));
  check("x509 der construction: b.crypto._x509 reads a Uint8Array the same way",
        Buffer.from(b.crypto._x509(new Uint8Array(der)).raw).equals(der));
  check("x509 der construction: b.crypto._x509 reads a PEM string as its first certificate",
        Buffer.from(b.crypto._x509(ROOT_PEM).raw).equals(ck.TLS_ROOT_DER));
  check("x509 der construction: b.crypto._x509 reads a PEM buffer as its first certificate",
        Buffer.from(b.crypto._x509(Buffer.from(ROOT_PEM, "utf8")).raw).equals(ck.TLS_ROOT_DER));
}

function _serve(certPem, keyPem, identity) {
  return new Promise(function (resolve) {
    var server = nodeTls.createServer({ key: keyPem, cert: certPem }, function (s) {
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
      var sock = nodeTls.connect({
        host: "127.0.0.1", port: server.address().port, servername: "localhost",
        ca: [ROOT_PEM], checkServerIdentity: identity,
      }, function () { sock.end(); done({ ok: true, code: null }); });
      sock.on("error", function (e) { done({ ok: false, code: (e && (e.code || e.message)) || "error" }); });
    });
  });
}

async function testTlsLeafCarryingTheRootPem() {
  check("x509 der construction premise: the control intermediate key is the fixture's",
        _spki(CONTROL_INTERMEDIATE.publicKey).equals(_spki(b.crypto._certificateFromDer(ck.TLS_CONTROL_INTERMEDIATE_DER).publicKey)));
  check("x509 der construction premise: the compromised intermediate key is 1",
        _spki(COMPROMISED.publicKey).equals(_spki(b.crypto._certificateFromDer(ck.TLS_COMPROMISED_INTERMEDIATE_DER).publicKey)));
  var text = crafted.textExtension("\n" + ROOT_PEM);
  var leafKey = ck.tlsChain("control").key;
  var identity = networkTls._withCompromisedChainCheck(nodeTls.checkServerIdentity, [ROOT_PEM]);
  var controlLeaf = crafted.rebuild(ck.TLS_CONTROL_LEAF_DER, { signingKey: CONTROL_INTERMEDIATE.privateKey, extension: text });
  var control = await _serve(ck.certPem(controlLeaf) + ck.certPem(ck.TLS_CONTROL_INTERMEDIATE_DER), leafKey, identity);
  check("x509 der construction control: a leaf carrying the root's PEM under an ordinary intermediate connects",
        control.ok === true, JSON.stringify(control));
  var badLeaf = crafted.rebuild(ck.TLS_COMPROMISED_LEAF_DER, { signingKey: COMPROMISED.privateKey, extension: text });
  var bad = await _serve(ck.certPem(badLeaf) + ck.certPem(ck.TLS_COMPROMISED_INTERMEDIATE_DER), leafKey, identity);
  check("x509 der construction: a leaf carrying the root's PEM under an intermediate whose key is 1 is refused",
        bad.ok === false && bad.code === "tls/compromised-key", JSON.stringify(bad));
}

function _sha256(buf) {
  return nodeCrypto.createHash("sha256").update(buf).digest();
}

function testDaneJudgesTheCertificateItself() {
  var text = crafted.textExtension(crafted.CERT_PEM_TEXT);
  var control = crafted.selfSignedCa(CONTROL_CA, text);
  var bad = crafted.selfSignedCa(COMPROMISED, text);
  function match(der) {
    try {
      return { ok: true, rv: b.network.dns.dane.matchCertificate({
        tlsa: [{ usage: 3, selector: 0, matchingType: 1, data: _sha256(der) }], certificate: der }) };
    } catch (e) { return { ok: false, code: e && e.code }; }
  }
  var c = match(control);
  check("x509 der construction control: DANE-EE matches an ordinary certificate carrying PEM text",
        c.ok === true && c.rv.matched !== null, JSON.stringify(c));
  var r = match(bad);
  check("x509 der construction: DANE-EE refuses a certificate whose key is 1 when it carries another's PEM",
        r.ok === false && r.code === "dane/compromised-key", JSON.stringify(r));
}

function testSmtpDaneJudgesTheCertificateItself() {
  var text = crafted.textExtension(crafted.CERT_PEM_TEXT);
  var control = crafted.selfSignedCa(CONTROL_CA, text);
  var bad = crafted.selfSignedCa(COMPROMISED, text);
  function verify(der) {
    return b.network.smtp.policy.dane.verifyChain([der], [{ usage: 3, selector: 0, mtype: 1, dataHex: _sha256(der).toString("hex") }]);
  }
  var c = verify(control);
  check("x509 der construction control: SMTP DANE-EE accepts an ordinary certificate carrying PEM text",
        c.ok === true, JSON.stringify(c));
  var r = verify(bad);
  check("x509 der construction: SMTP DANE-EE refuses a certificate whose key is 1 when it carries another's PEM",
        r.ok === false && r.errors.some(function (e) { return e.reason === "dane-compromised-key"; }), JSON.stringify(r));
}

var ISSUER_URL = "https://issuer.example.com";

function _b64uJson(o) { return Buffer.from(JSON.stringify(o), "utf8").toString("base64url"); }

function _proof(privateKey, x5cDer, nonce) {
  var header = { typ: "openid4vci-proof+jwt", alg: "ES256", x5c: [x5cDer.toString("base64")] };
  var input = _b64uJson(header) + "." + _b64uJson({ aud: ISSUER_URL, nonce: nonce, iat: Math.floor(Date.now() / 1000) });
  var sig = nodeCrypto.sign("sha256", Buffer.from(input, "ascii"), { key: privateKey, dsaEncoding: "ieee-p1363" });
  return input + "." + sig.toString("base64url");
}

async function _issueWith(x5cDer) {
  var signing = ck.ecKeyPair("prime256v1", ck.labelScalar("prime256v1", "blamejs x509 der construction issuer"));
  var issuer = b.auth.oid4vci.issuer.create({
    credentialIssuerUrl: ISSUER_URL,
    credentialEndpoint:  ISSUER_URL + "/credential",
    tokenEndpoint:       ISSUER_URL + "/token",
    sdJwtIssuer: b.auth.sdJwtVc.issuer.create({ issuerUrl: ISSUER_URL,
      keys: [{ kid: "k1", privateKey: signing.privateKey, algorithm: "ES256" }] }),
    supportedCredentials: { "id-card-1": { format: "vc+sd-jwt", vct: "https://example.com/vct/id",
      claims: { given_name: {} } } },
  });
  var offer = await issuer.createCredentialOffer({ subject: "user-1", credentialIds: ["id-card-1"] });
  var tokens = await issuer.exchangePreAuthorizedCode({ preAuthCode: offer.preAuthCode });
  try {
    await issuer.issueCredential({ accessToken: tokens.access_token, credentialIdentifier: "id-card-1",
      proof: _proof(CONTROL_CA.privateKey, x5cDer, tokens.c_nonce), claims: { given_name: "Alice" } });
    return "NO-THROW";
  } catch (e) { return e.code || e.message; }
}

async function testOid4vciProofIsVerifiedWithTheCertificateItself() {
  var text = crafted.textExtension(crafted.CERT_PEM_TEXT);
  var control = await _issueWith(crafted.selfSignedCa(CONTROL_CA, text));
  check("x509 der construction control: an OID4VCI proof under an ordinary x5c carrying PEM text is accepted",
        control === "NO-THROW", control);
  var bad = await _issueWith(crafted.selfSignedCa(COMPROMISED, text));
  check("x509 der construction: an OID4VCI x5c whose key is 1 is refused when it carries the signer's certificate PEM",
        bad === "auth-oid4vci/compromised-key", bad);
}

function testRequireMtlsLooksUpTheCertificatesOwnSerial() {
  var der = crafted.selfSignedCa(CONTROL_CA, crafted.textExtension("\n" + ck.EDELLROOT_CERT_PEM));
  var ownSerial = new nodeCrypto.X509Certificate(ck.certPem(der)).serialNumber;
  var decoySerial = new nodeCrypto.X509Certificate(ck.EDELLROOT_CERT_PEM).serialNumber;
  check("x509 der construction premise: the embedded certificate has another serial", ownSerial !== decoySerial);
  var denied = null;
  var passed = false;
  var gate = b.middleware.requireMtls({
    audit: false,
    revocationSource: {
      isRevoked:       function () { return false; },
      isSerialRevoked: function (serial) { return serial === ownSerial; },
    },
    onDeny: function (req, res, info) { denied = info; },
  });
  var req = { url: "/", method: "GET", headers: {}, socket: { authorized: true, authorizationError: null,
    getPeerCertificate: function () { return { raw: der, subject: { CN: "crafted" } }; } } };
  var res = { writableEnded: false, writeHead: function () {}, end: function () { this.writableEnded = true; } };
  gate(req, res, function () { passed = true; });
  check("x509 der construction: requireMtls refuses a certificate whose own serial is revoked",
        passed === false && denied !== null, JSON.stringify({ passed: passed, denied: denied }));
}

// A req.peerCert whose raw is not DER cannot be walked as a chain, so the gate
// refuses it whatever its fingerprint is; a DER raw that is the socket's own
// certificate is the control.
function testRequireMtlsRefusesAPeerCertWhoseRawIsNotDer() {
  var edell = new nodeCrypto.X509Certificate(ck.EDELLROOT_CERT_PEM);
  var pin = b.crypto.hashCertFingerprint(Buffer.from(edell.raw)).colon;
  function gate(raw) {
    var denied = null;
    var passed = false;
    var mw = b.middleware.requireMtls({ audit: false, fingerprintAllowList: [pin],
      onDeny: function (req, res, info) { denied = info; } });
    var req = { url: "/", method: "GET", headers: {}, peerCert: { raw: raw, subject: { CN: "forwarded" } },
      socket: { authorized: true, authorizationError: null, getPeerCertificate: function () { return {}; } } };
    var res = { writableEnded: false, writeHead: function () {}, end: function () { this.writableEnded = true; } };
    mw(req, res, function () { passed = true; });
    return { passed: passed, reason: denied && denied.reason };
  }
  var der = gate(Buffer.from(edell.raw));
  check("x509 der construction control: requireMtls refuses the listed eDellRoot certificate forwarded as DER",
        der.passed === false && der.reason === "compromised-key", JSON.stringify(der));
  [["PEM string", ck.EDELLROOT_CERT_PEM], ["PEM Buffer", Buffer.from(ck.EDELLROOT_CERT_PEM, "utf8")]].forEach(function (form) {
    var r = gate(form[1]);
    check("x509 der construction: requireMtls refuses the eDellRoot certificate forwarded as " + form[0],
          r.passed === false && r.reason === "compromised-key", JSON.stringify(r));
  });
}

var TESTS = [
  testRequireMtlsRefusesAPeerCertWhoseRawIsNotDer,
  testHelperReadsDerAsDer,
  testTlsLeafCarryingTheRootPem,
  testDaneJudgesTheCertificateItself,
  testSmtpDaneJudgesTheCertificateItself,
  testOid4vciProofIsVerifiedWithTheCertificateItself,
  testRequireMtlsLooksUpTheCertificatesOwnSerial,
];

async function run() {
  for (var i = 0; i < TESTS.length; i += 1) await TESTS[i]();
}

module.exports = { run: run, TESTS: TESTS };

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
