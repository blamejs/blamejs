// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.network.tls.ocsp.parseResponse + .evaluate + .requireGood — RFC 6960
 * OCSP response parser + signature verifier. Live-server round-trip
 * tests live in test/integration/; this layer-0 suite exercises the
 * parser's malformed-input rejection + the surface contract.
 */

var helpers    = require("../helpers");
var b          = helpers.b;
var check      = helpers.check;

function testSurface() {
  check("ocsp.parseResponse is a function",
        typeof b.network.tls.ocsp.parseResponse === "function");
  check("ocsp.evaluate is a function",
        typeof b.network.tls.ocsp.evaluate === "function");
  check("ocsp.requireGood is a function",
        typeof b.network.tls.ocsp.requireGood === "function");
  check("ocsp.requireStapled (presence-only) is a function",
        typeof b.network.tls.ocsp.requireStapled === "function");
}

function testParseRejectsBadInput() {
  var threw = null;
  try { b.network.tls.ocsp.parseResponse("not a buffer"); }
  catch (e) { threw = e; }
  check("parseResponse(non-buffer) throws ocsp-bad-input",
        threw && /ocsp-bad-input/.test(threw.code || ""));
}

function testParseRejectsNonSequence() {
  // 0x02 = INTEGER, not a SEQUENCE.
  var threw = null;
  try { b.network.tls.ocsp.parseResponse(Buffer.from([0x02, 0x01, 0x05])); }
  catch (e) { threw = e; }
  check("parseResponse(non-SEQUENCE) throws ocsp-bad-shape",
        threw && /ocsp-bad-shape|ocsp-bad-input|asn1\/wrong/.test(threw.code || threw.message || ""));
}

function testParseTryLater() {
  // OCSPResponse { responseStatus 3 } — "tryLater". No responseBytes.
  // Hand-crafted DER: 0x30 0x03 0x0a 0x01 0x03
  //                   SEQ  len  ENUM len status=3
  var rv = b.network.tls.ocsp.parseResponse(Buffer.from([0x30, 0x03, 0x0a, 0x01, 0x03]));
  check("parseResponse: tryLater (status 3)",
        rv.status === "tryLater" && rv.basic === undefined);
}

function testParseUnauthorized() {
  // Status 6 = unauthorized.
  var rv = b.network.tls.ocsp.parseResponse(Buffer.from([0x30, 0x03, 0x0a, 0x01, 0x06]));
  check("parseResponse: unauthorized (status 6)",
        rv.status === "unauthorized");
}

function testEvaluateRequiresIssuerPem() {
  var threw = null;
  try { b.network.tls.ocsp.evaluate(Buffer.from([0x30, 0x03, 0x0a, 0x01, 0x03])); }
  catch (e) { threw = e; }
  check("evaluate without issuerPem throws ocsp-missing-issuer",
        threw && /ocsp-missing-issuer/.test(threw.code || ""));
}

function testEvaluateNonSuccessful() {
  // Status=tryLater — evaluate returns ok:false with the status surfaced.
  var rv = b.network.tls.ocsp.evaluate(Buffer.from([0x30, 0x03, 0x0a, 0x01, 0x03]),
                                       { issuerPem: "-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----\n" });
  check("evaluate: non-successful response surfaces status without verify",
        rv.ok === false && rv.status === "tryLater");
}

function testEvaluateMalformed() {
  var rv = b.network.tls.ocsp.evaluate(Buffer.from([0x99, 0x99]),
                                       { issuerPem: "-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----\n" });
  check("evaluate: malformed bytes → ok:false, status:'parse-error'",
        rv.ok === false && rv.status === "parse-error");
}

async function testRequireGoodRequiresIssuerPem() {
  var threw = null;
  try { await b.network.tls.ocsp.requireGood({ host: "127.0.0.1", port: 1 }); }
  catch (e) { threw = e; }
  check("requireGood without issuerPem throws ocsp-missing-issuer",
        threw && /ocsp-missing-issuer/.test(threw.code || ""));
}

// ---- CertID issuer binding (RFC 6960 §4.1.1) ----------------------------
// A "good" SingleResponse whose serial matches the cert under validation but
// whose issuerNameHash/issuerKeyHash belong to a DIFFERENT issuer must be
// REFUSED — a serial is unique only per issuer, so a delegated responder /
// shared CA key could otherwise have a "good" for serial-S under issuer-Y
// accepted as proof for serial-S under issuer-X.

// Minimal RFC 5280-shaped X.509 cert (issuer DN = one CN + the given key bytes).
// Shape only — the binding hashes its DN + SPKI BIT STRING, never verifies its
// own signature.
var _OCSP_SERIAL = Buffer.from([0x12, 0x34, 0x56, 0x78]);
var _OCSP_NOW    = Date.parse("2025-06-15T00:00:01Z");

// Positive control — CertID issuer == cert-under-validation issuer → accepted.
function testCertIdIssuerMatchAccepted() {
  var issuer = helpers.synthCertForOcsp(Buffer.from([0x01]), Buffer.from("Real CA"),
                          Buffer.from("real-ca-key-bytes-aaaaaaaaaaaaaa"));
  var fx = helpers.buildOcspResponse({ serial: _OCSP_SERIAL, certIdIssuerDer: issuer,
                              producedAtMs: _OCSP_NOW - 1000, nextUpdateMs: _OCSP_NOW + 86400000 });
  var rv = b.network.tls.ocsp.evaluate(fx.der, {
    issuerPem:     fx.issuerPem,
    issuerCertDer: issuer,
    serialHex:     _OCSP_SERIAL.toString("hex"),
    now:           _OCSP_NOW,
  });
  check("certID match: accepted (ok=true)", rv.ok === true);
  check("certID match: no errors", Array.isArray(rv.errors) && rv.errors.length === 0);
}

// RED today — CertID issuer is a DIFFERENT CA than the cert under validation
// but the serial collides. Bound only by serial → accepted today; must be
// REFUSED for the wrong-issuer reason after the fix.
function testCrossIssuerCertIdRefused() {
  var realIssuer = helpers.synthCertForOcsp(Buffer.from([0x01]), Buffer.from("Real CA"),
                              Buffer.from("real-ca-key-bytes-aaaaaaaaaaaaaa"));
  var otherIssuer = helpers.synthCertForOcsp(Buffer.from([0x02]), Buffer.from("Evil CA"),
                               Buffer.from("evil-ca-key-bytes-bbbbbbbbbbbbbb"));
  var fx = helpers.buildOcspResponse({ serial: _OCSP_SERIAL, certIdIssuerDer: otherIssuer,
                              producedAtMs: _OCSP_NOW - 1000, nextUpdateMs: _OCSP_NOW + 86400000 });
  var rv = b.network.tls.ocsp.evaluate(fx.der, {
    issuerPem:     fx.issuerPem,
    issuerCertDer: realIssuer,                  // the issuer we actually asked about
    serialHex:     _OCSP_SERIAL.toString("hex"), // same serial → matches on serial alone
    now:           _OCSP_NOW,
  });
  check("cross-issuer: REFUSED (ok=false) — not bound on serial alone", rv.ok === false);
  check("cross-issuer: signature still verified (reached the binding gate)",
        rv.signatureValid === true);
  check("cross-issuer: refused for the wrong-issuer reason",
        /issuerNameHash|issuerKeyHash|wrong-issuer/i.test((rv.errors || []).join(" ; ")));
}

// Without issuerCertDer the binding is not enforced (serial-only legacy path).
function testNoIssuerCertDerStaysSerialBound() {
  var otherIssuer = helpers.synthCertForOcsp(Buffer.from([0x02]), Buffer.from("Evil CA"),
                               Buffer.from("evil-ca-key-bytes-bbbbbbbbbbbbbb"));
  var fx = helpers.buildOcspResponse({ serial: _OCSP_SERIAL, certIdIssuerDer: otherIssuer,
                              producedAtMs: _OCSP_NOW - 1000, nextUpdateMs: _OCSP_NOW + 86400000 });
  var rv = b.network.tls.ocsp.evaluate(fx.der, {
    issuerPem: fx.issuerPem, serialHex: _OCSP_SERIAL.toString("hex"), now: _OCSP_NOW,
  });
  check("no issuerCertDer: serial-only bind still resolves (ok=true)", rv.ok === true);
}

async function run() {
  testSurface();
  testParseRejectsBadInput();
  testParseRejectsNonSequence();
  testParseTryLater();
  testParseUnauthorized();
  testEvaluateRequiresIssuerPem();
  testEvaluateNonSuccessful();
  testEvaluateMalformed();
  await testRequireGoodRequiresIssuerPem();
  testCertIdIssuerMatchAccepted();
  testCrossIssuerCertIdRefused();
  testNoIssuerCertDerStaysSerialBound();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
