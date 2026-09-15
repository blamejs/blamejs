// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * object-store key traversal.
 *
 * An operator/app-supplied object key must not escape the configured
 * bucket/container/prefix. Each remote backend builds the wire path by
 * percent-encoding every "/"-separated key segment, joining with "/", then
 * parsing the result as a URL. A URL parser normalizes "." / ".." dot-segments,
 * so a key like "../../otherbucket/object" resolves ABOVE the configured bucket:
 * in path-style S3 it reaches a different bucket, and because the request
 * signature is computed over the already-normalized path, the server honors it
 * rather than returning 403. The shared sigv4.encodeObjectKeyPath refuses a key
 * with a "." or ".." path segment (and a null byte), and every path-building
 * sink routes through it. The local and http-put backends already refuse
 * traversal keys; this asserts the SigV4 / GOOG4 / SharedKey backends do too.
 *
 * Run standalone: `node test/layer-0-primitives/object-store-key-traversal.test.js`
 */
var nodeCrypto = require("crypto");
var helpers    = require("../helpers");
var check      = helpers.check;
var b          = helpers.b;
var sigv4      = require("../../lib/object-store/sigv4");
var azure      = require("../../lib/object-store/azure-blob");
var gcs        = require("../../lib/object-store/gcs");
var bucketOps  = require("../../lib/object-store/sigv4-bucket-ops");

var NUL = String.fromCharCode(0);

// Keys whose "/"-split contains a "." or ".." segment (the escape vectors).
var TRAVERSAL_KEYS = [
  "../secret", "../../otherbucket/object", "a/../../../escape",
  "dir/../..", "./x", "a/./b", "..", ".",
];

function _code(fn) {
  try { fn(); return "OK"; }
  catch (e) { return e && e.code; }
}

// Swallow a rejected promise produced on the CURRENT (unfixed) tree, where the
// call proceeds past key validation to a network attempt instead of throwing.
function _swallow(ret) {
  if (ret && typeof ret.then === "function") ret.catch(function () {});
}

// ---- the shared mechanism: sigv4.encodeObjectKeyPath ----

function testEncodeObjectKeyPathRejectsDotSegments() {
  check("sigv4.encodeObjectKeyPath is exported",
        typeof sigv4.encodeObjectKeyPath === "function");
  TRAVERSAL_KEYS.forEach(function (k) {
    check("encodeObjectKeyPath refuses dot-segment key " + JSON.stringify(k),
          _code(function () { sigv4.encodeObjectKeyPath(k); }) === "objectstore/invalid-key");
  });
  check("encodeObjectKeyPath refuses a null byte",
        _code(function () { sigv4.encodeObjectKeyPath("a" + NUL + "b"); }) === "objectstore/invalid-key");
  check("encodeObjectKeyPath refuses a non-string",
        _code(function () { sigv4.encodeObjectKeyPath(42); }) === "objectstore/invalid-key");
  check("encodeObjectKeyPath refuses an empty key",
        _code(function () { sigv4.encodeObjectKeyPath(""); }) === "objectstore/invalid-key");

  // CONTROL: dots INSIDE a segment (not a whole-segment "." / "..") are legal
  // and preserved; the "/" hierarchy and reserved-char encoding are intact.
  check("encodeObjectKeyPath keeps dots inside a segment",
        sigv4.encodeObjectKeyPath("a.b/c..d/e.txt") === "a.b/c..d/e.txt",
        sigv4.encodeObjectKeyPath("a.b/c..d/e.txt"));
  check("encodeObjectKeyPath encodes a space and preserves the separator",
        sigv4.encodeObjectKeyPath("dir/a b.txt") === "dir/a%20b.txt",
        sigv4.encodeObjectKeyPath("dir/a b.txt"));
}

// ---- sigv4 (S3-compatible) presign ----

function testSigv4PresignRejectsTraversal() {
  var store = sigv4.create({
    region:          "us-east-1",
    bucket:          "mybucket",
    accessKeyId:     "AKIAIOSFODNN7EXAMPLE",
    secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    endpoint:        "https://s3.us-east-1.amazonaws.com",
    pathStyle:       true,
  });
  check("sigv4 presignedDownloadUrl refuses a traversal key",
        _code(function () { store.presignedDownloadUrl({ key: "../../otherbucket/secret", expiresIn: 300 }); }) === "objectstore/invalid-key");
  check("sigv4 presignedUploadUrl refuses a traversal key",
        _code(function () { store.presignedUploadUrl({ key: "../secret", expiresIn: 300 }); }) === "objectstore/invalid-key");

  // CONTROL: a legit key presigns to a path UNDER the configured bucket.
  var ok = store.presignedDownloadUrl({ key: "dir/file.txt", expiresIn: 300 });
  check("sigv4 legit key presigns under the bucket",
        new URL(ok.url).pathname === "/mybucket/dir/file.txt", ok.url);
}

// ---- azure-blob (SharedKey) direct + presign ----

function testAzureRejectsTraversal() {
  var accountKey = Buffer.from("test-shared-key-32-bytes-padded__", "utf8").toString("base64");
  var c = azure.create({
    accountName:      "blamejstest",
    accountKey:       accountKey,
    container:        "cont",
    endpoint:         "http://127.0.0.1:1",
    allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
    allowInternal:    true,
    timeoutMs:        1000,
  });

  // Direct put builds _blobUrl synchronously before any network I/O.
  var putErr = null, putRet;
  try { putRet = c.put("../../othercontainer/object", Buffer.from("x", "utf8")); }
  catch (e) { putErr = e; }
  _swallow(putRet);
  check("azure put refuses a traversal key",
        putErr && putErr.code === "objectstore/invalid-key");

  check("azure presignedDownloadUrl refuses a traversal key",
        _code(function () { c.presignedDownloadUrl({ key: "../../othercontainer/object", expiresIn: 300 }); }) === "objectstore/invalid-key");

  // CONTROL: a legit key presigns to a path UNDER the configured container.
  var ok = c.presignedDownloadUrl({ key: "dir/file.txt", expiresIn: 300 });
  check("azure legit key presigns under the container",
        ok.url.indexOf("/cont/dir/file.txt") !== -1, ok.url);
}

// ---- gcs (GOOG4-RSA) presign ----

function testGcsPresignRejectsTraversal() {
  var pair = nodeCrypto.generateKeyPairSync("rsa", {
    modulusLength:      2048,
    publicKeyEncoding:  { type: "spki",  format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  var g = gcs.create({
    bucket:         "mybucket",
    serviceAccount: {
      client_email: "test-sa@test-project.iam.gserviceaccount.com",
      private_key:  pair.privateKey,
    },
  });
  check("gcs presignedDownloadUrl refuses a traversal key",
        _code(function () { g.presignedDownloadUrl({ key: "../../otherbucket/object", expiresIn: 300 }); }) === "objectstore/invalid-key");
  check("gcs presignedUploadUrl refuses a traversal key",
        _code(function () { g.presignedUploadUrl({ key: "../secret", expiresIn: 300 }); }) === "objectstore/invalid-key");

  // CONTROL: a legit key presigns to a path UNDER the configured bucket.
  var ok = g.presignedDownloadUrl({ key: "dir/file.txt", expiresIn: 300 });
  check("gcs legit key presigns under the bucket",
        ok.url.indexOf("/mybucket/dir/file.txt") !== -1, ok.url);
}

// ---- sigv4 bucket-ops (object-lock / retention / legal-hold) ----

function testBucketOpsRejectsTraversal() {
  var ops = bucketOps.create({
    protocol:         "sigv4",
    region:           "us-east-1",
    accessKeyId:      "AKIAIOSFODNN7EXAMPLE",
    secretAccessKey:  "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    endpoint:         "http://127.0.0.1:1",
    pathStyle:        true,
    allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
    allowInternal:    true,
    timeoutMs:        1000,
  });

  // getObjectRetention validates and builds _objectUrl synchronously before the
  // network round-trip, so a traversal key throws synchronously.
  var err = null, ret;
  try { ret = ops.getObjectRetention("mybucket", "../../otherbucket/object"); }
  catch (e) { err = e; }
  _swallow(ret);
  check("sigv4 bucketOps getObjectRetention refuses a traversal key",
        err && err.code === "objectstore/invalid-key");

  // CONTROL: a legit key is NOT rejected as invalid (it proceeds to the network,
  // which we swallow); the key guard must not over-refuse an ordinary key.
  var okErr = null, okRet;
  try { okRet = ops.getObjectRetention("mybucket", "dir/file.txt"); }
  catch (e) { okErr = e; }
  _swallow(okRet);
  check("sigv4 bucketOps accepts a legit key (no invalid-key throw)",
        okErr === null);
}

async function run() {
  testEncodeObjectKeyPathRejectsDotSegments();
  testSigv4PresignRejectsTraversal();
  testAzureRejectsTraversal();
  testGcsPresignRejectsTraversal();
  testBucketOpsRejectsTraversal();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
