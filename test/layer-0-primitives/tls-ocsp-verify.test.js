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

// Without issuerCertDer the CertID issuerKeyHash is bound against opts.issuerPem's
// key: the RFC 6960 §4.1.1 binding is mandatory, not opt-in. A response whose
// CertID names a DIFFERENT issuer key than the responder that signed it (issuerPem)
// is refused, closing the serial-only replay across a shared responder or a
// colliding serial. RED before the fix: the binding was skipped without
// issuerCertDer, so the cross-key response resolved ok:true on serial alone.
function testNoIssuerCertDerStillBindsOnKey() {
  var otherIssuer = helpers.synthCertForOcsp(Buffer.from([0x02]), Buffer.from("Evil CA"),
                               Buffer.from("evil-ca-key-bytes-bbbbbbbbbbbbbb"));
  var fx = helpers.buildOcspResponse({ serial: _OCSP_SERIAL, certIdIssuerDer: otherIssuer,
                              producedAtMs: _OCSP_NOW - 1000, nextUpdateMs: _OCSP_NOW + 86400000 });
  var rv = b.network.tls.ocsp.evaluate(fx.der, {
    issuerPem: fx.issuerPem, serialHex: _OCSP_SERIAL.toString("hex"), now: _OCSP_NOW,
  });
  check("no issuerCertDer: cross-key CertID is refused (mandatory key binding)", rv.ok === false);
  check("no issuerCertDer: signature still verified (reached the binding)",
        rv.signatureValid === true);
  check("no issuerCertDer: refused for the issuerKeyHash reason",
        /issuerKeyHash|wrong-issuer/i.test((rv.errors || []).join(" ; ")));
}

// Positive control — without issuerCertDer, a CertID whose issuerKeyHash matches
// opts.issuerPem's key (the builder derives the default from the signing key) is
// accepted. Guards the mandatory binding against over-refusing the common
// non-delegated case where issuerPem IS the issuer.
function testNoIssuerCertDerMatchingKeyAccepted() {
  var fx = helpers.buildOcspResponse({ serial: _OCSP_SERIAL,
                              producedAtMs: _OCSP_NOW - 1000, nextUpdateMs: _OCSP_NOW + 86400000 });
  var rv = b.network.tls.ocsp.evaluate(fx.der, {
    issuerPem: fx.issuerPem, serialHex: _OCSP_SERIAL.toString("hex"), now: _OCSP_NOW,
  });
  check("no issuerCertDer + matching key: accepted", rv.ok === true);
}

// A well-formed OCSPResponse followed by extra bytes must be refused, not read
// as the leading structure with the remainder ignored. The signature covers
// only tbsResponseData, so trailing bytes forge no status, but a parser that
// silently drops them is one a caller cannot reason about — the same DER
// strictness enforced for CMS/TSA. RED before the fix: parseResponse reads the
// leading response and returns it; evaluate reports ok:true.
function testParseRejectsTrailingData() {
  var fx = helpers.buildOcspResponse({
    producedAtMs: Date.parse("2025-06-15T00:00:00Z"),
    nextUpdateMs: Date.parse("2025-06-16T00:00:00Z"),
  });
  var withTrailer = Buffer.concat([fx.der, Buffer.from([0, 0, 0, 0, 0, 0, 0, 0])]);
  var threw = null;
  try { b.network.tls.ocsp.parseResponse(withTrailer); }
  catch (e) { threw = e; }
  check("parseResponse(response + trailing bytes) throws ocsp-trailing-data",
        threw && /ocsp-trailing-data/.test(threw.code || ""));
}

function testEvaluateRejectsTrailingData() {
  var now = Date.parse("2025-06-15T00:00:01Z");
  var fx = helpers.buildOcspResponse({
    producedAtMs: now - 1000,
    nextUpdateMs: now + 86400000,
  });
  var withTrailer = Buffer.concat([fx.der, Buffer.from([0, 0, 0, 0, 0, 0, 0, 0])]);
  var rv = b.network.tls.ocsp.evaluate(withTrailer, {
    issuerPem: fx.issuerPem, serialHex: fx.serialHex, now: now,
  });
  check("evaluate(response + trailing bytes) → ok:false, status:'parse-error'",
        rv.ok === false && rv.status === "parse-error");
}

// A tuning knob added to evaluate is a silent lie if the high-level wrappers
// that call evaluate rebuild its options and drop the knob. ocsp.fetch must
// forward opts.maxAgeMs so a caller can widen the age at which a no-nextUpdate
// response is accepted. Drives the real fetch consumer path through a stubbed
// responder. RED before the fix: fetch rebuilds the evaluate options without
// maxAgeMs, so an 8-day-old no-nextUpdate response is refused with
// tls/ocsp-not-good even though the widened window would accept it.
async function testFetchForwardsMaxAgeMs() {
  var httpClient = require("../../lib/http-client");
  var pair = helpers.selfSignedPair();
  var built = helpers.buildOcspResponse({
    keyPair:         pair.keyPair,
    certIdIssuerDer: pair.certDer,
    serial:          Buffer.from([0x12, 0x34, 0x56, 0x78]),   // matches the cert serial
    thisUpdateMs:    Date.now() - 8 * 86400000,               // 8 days old, NO nextUpdate
  });
  var origRequest = httpClient.request;
  httpClient.request = async function () { return { status: 200, body: built.der }; };

  var widened = null, widenedErr = null, dfltErr = null;
  try {
    try {
      widened = await b.network.tls.ocsp.fetch({
        leafPem: pair.cert, issuerPem: pair.cert, responderUrl: "http://ocsp.test/",
        serialHex: "12345678", nonce: false, maxAgeMs: 30 * 86400000,
      });
    } catch (e) { widenedErr = e; }
    // Control: the same response WITHOUT the override is refused at the 24h default.
    try {
      await b.network.tls.ocsp.fetch({
        leafPem: pair.cert, issuerPem: pair.cert, responderUrl: "http://ocsp.test/",
        serialHex: "12345678", nonce: false,
      });
    } catch (e) { dfltErr = e; }
  } finally {
    httpClient.request = origRequest;
  }
  check("fetch forwards maxAgeMs: widened window accepts the no-nextUpdate response",
        widened && widened.evaluation && widened.evaluation.ok === true, widenedErr);
  check("fetch default (no maxAgeMs): the same 8-day-old response is refused",
        dfltErr && /ocsp-not-good/.test(dfltErr.code || ""));
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
  testNoIssuerCertDerStillBindsOnKey();
  testNoIssuerCertDerMatchingKeyAccepted();
  testParseRejectsTrailingData();
  testEvaluateRejectsTrailingData();
  await testFetchForwardsMaxAgeMs();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
