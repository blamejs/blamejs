// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * object-store presign hardening.
 *
 * Three input-handling gaps in the presigned-URL surface, each proven through
 * the real backend consumer path:
 *
 *  - contentType is folded into the request signature and handed back to the
 *    caller in the returned header map / POST fields. A CR, LF, or NUL in it is
 *    a header-injection vector at the returned-contract boundary and desyncs the
 *    value the caller sends from the value that was signed. The sibling
 *    responseHeaders field is already refused for the same characters; every
 *    presign backend (SigV4, GOOG4, SharedKey) must refuse contentType the same way.
 *  - The wire query must carry the same percent-encoding the signature was
 *    computed over. URLSearchParams and the SigV4 canonical encoder disagree on
 *    "*" (wire leaves bare, canonical uses %2A) and "~" (wire uses %7E, canonical
 *    leaves bare); a mismatch is a server-side signature rejection for any query
 *    value (a list prefix, a response-header override) containing those bytes.
 *  - expiresIn is an advertised 1..604800 bound. NaN passes the numeric guard
 *    (typeof NaN === "number", both comparisons false) and a non-integer produces
 *    a fractional X-Amz-Expires; the bound must reject both.
 *
 * Run standalone: `node test/layer-0-primitives/object-store-presign-hardening.test.js`
 */
var nodeCrypto = require("crypto");
var helpers    = require("../helpers");
var check      = helpers.check;
var sigv4      = require("../../lib/object-store/sigv4");
var azure      = require("../../lib/object-store/azure-blob");
var gcs        = require("../../lib/object-store/gcs");

function _code(fn) {
  try { fn(); return "OK"; }
  catch (e) { return e && e.code; }
}

var CRLF_CT = "text/plain\r\nX-Injected: pwned";
var NUL_CT  = "text/plain" + String.fromCharCode(0) + "x";

function _sigv4() {
  return sigv4.create({
    region:          "us-east-1",
    bucket:          "mybucket",
    accessKeyId:     "AKIAIOSFODNN7EXAMPLE",
    secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    endpoint:        "https://s3.us-east-1.amazonaws.com",
    pathStyle:       true,
  });
}
function _gcs() {
  var pair = nodeCrypto.generateKeyPairSync("rsa", {
    modulusLength:      2048,
    publicKeyEncoding:  { type: "spki",  format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return gcs.create({
    bucket:         "mybucket",
    serviceAccount: {
      client_email: "test-sa@test-project.iam.gserviceaccount.com",
      private_key:  pair.privateKey,
    },
  });
}
function _azure() {
  var accountKey = Buffer.from("test-shared-key-32-bytes-padded__", "utf8").toString("base64");
  return azure.create({
    accountName: "blamejstest",
    accountKey:  accountKey,
    container:   "cont",
    endpoint:    "https://blamejstest.blob.core.windows.net",
  });
}

// ---- contentType header-injection refusal, every presign backend ----

function testPresignContentTypeRejectsCrlf() {
  var s = _sigv4();
  check("sigv4 presignedUploadUrl refuses a CRLF contentType",
        _code(function () { s.presignedUploadUrl({ key: "up.bin", contentType: CRLF_CT, expiresIn: 300 }); }) === "objectstore/invalid-content-type");
  check("sigv4 presignedUploadPolicy refuses a CRLF contentType",
        _code(function () { s.presignedUploadPolicy({ key: "up.bin", contentType: CRLF_CT, maxBytes: 1024, expiresIn: 300 }); }) === "objectstore/invalid-content-type");
  check("sigv4 presign refuses a NUL contentType",
        _code(function () { s.presignedDownloadUrl({ key: "d.bin", contentType: NUL_CT, expiresIn: 300 }); }) === "objectstore/invalid-content-type");

  var g = _gcs();
  check("gcs presignedUploadUrl refuses a CRLF contentType",
        _code(function () { g.presignedUploadUrl({ key: "up.bin", contentType: CRLF_CT, expiresIn: 300 }); }) === "objectstore/invalid-content-type");
  check("gcs presignedUploadPolicy refuses a CRLF contentType",
        _code(function () { g.presignedUploadPolicy({ key: "up.bin", contentType: CRLF_CT, maxBytes: 1024, expiresIn: 300 }); }) === "objectstore/invalid-content-type");

  var a = _azure();
  check("azure presignedUploadUrl refuses a CRLF contentType",
        _code(function () { a.presignedUploadUrl({ key: "up.bin", contentType: CRLF_CT, expiresIn: 300 }); }) === "objectstore/invalid-content-type");

  // CONTROL: a normal contentType still presigns and round-trips.
  var ok = s.presignedUploadUrl({ key: "up.bin", contentType: "image/png", expiresIn: 300 });
  check("sigv4 presign accepts a normal contentType",
        ok.headers["Content-Type"] === "image/png");
}

// ---- wire query encoding matches the signed canonical encoding ----

function testPresignWireQueryMatchesCanonical() {
  var s = _sigv4();
  var r = s.presignedDownloadUrl({
    key:             "d.bin",
    responseHeaders: { cacheControl: "no-cache*~" },
    expiresIn:       300,
  });
  var raw = new URL(r.url).search;
  check("sigv4 presign wire query encodes '*' as %2A (matches the signature)",
        raw.indexOf("%2A") !== -1 && raw.indexOf("*") === -1, raw);
  check("sigv4 presign wire query leaves '~' unescaped (matches the signature)",
        raw.indexOf("%7E") === -1, raw);
}

// ---- expiresIn bound rejects NaN / non-integer / non-finite ----

function testPresignExpiryValidation() {
  var s = _sigv4();
  check("presign refuses NaN expiresIn",
        _code(function () { s.presignedDownloadUrl({ key: "d.bin", expiresIn: NaN }); }) === "objectstore/invalid-expires");
  check("presign refuses a non-integer expiresIn",
        _code(function () { s.presignedDownloadUrl({ key: "d.bin", expiresIn: 1.9999 }); }) === "objectstore/invalid-expires");
  check("presign refuses Infinity expiresIn",
        _code(function () { s.presignedDownloadUrl({ key: "d.bin", expiresIn: Infinity }); }) === "objectstore/invalid-expires");

  // CONTROL: the advertised boundary values still work.
  check("presign accepts expiresIn=1 (lower bound)",
        typeof s.presignedDownloadUrl({ key: "d.bin", expiresIn: 1 }).url === "string");
  check("presign accepts expiresIn=604800 (upper bound)",
        typeof s.presignedDownloadUrl({ key: "d.bin", expiresIn: 604800 }).url === "string");
}

async function run() {
  testPresignContentTypeRejectsCrlf();
  testPresignWireQueryMatchesCanonical();
  testPresignExpiryValidation();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
