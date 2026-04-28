"use strict";
/**
 * storage — presigned upload URL (Phase 9.11k).
 *
 * Operators handing browser/mobile clients a direct path to object
 * storage need a signed PUT URL the client can use without holding
 * AWS credentials. SigV4 backends (S3, R2, MinIO, Wasabi, Tigris,
 * DO Spaces, IDrive e2, Linode, Storj) implement query-string SigV4
 * presigning; non-S3-compatible backends (local, http-put, gcs,
 * azure-blob) throw PRESIGN_NOT_SUPPORTED with guidance.
 *
 * Run standalone: `node test/layer-0-primitives/storage-presigned-url.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b              = helpers.b;
var fs             = helpers.fs;
var os             = helpers.os;
var path           = helpers.path;
var check          = helpers.check;
var setupTestDb    = helpers.setupTestDb;
var teardownTestDb = helpers.teardownTestDb;

var SIGV4_CONFIG = {
  protocol:        "sigv4",
  region:          "us-east-1",
  bucket:          "blamejs-test",
  accessKeyId:     "AKIAIOSFODNN7EXAMPLE",
  secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  classifications: ["operational"],
};

async function testSurface() {
  check("storage.presignedUploadUrl is a function",
        typeof b.storage.presignedUploadUrl === "function");
}

async function testSigv4ProducesPresignedUrl() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-presign-"));
  try {
    await setupTestDb(tmpDir);
    b.storage._resetForTest();
    await b.vault.init({ dataDir: tmpDir, mode: "plaintext" }); // re-init after _resetForTest reset vault
    b.storage.init({
      backends: { "s3": SIGV4_CONFIG },
      defaultClassification: "operational",
    });

    // Fixed date so the signature is deterministic for assertion.
    var fixed = new Date("2026-04-27T12:34:56Z");
    var result = b.storage.presignedUploadUrl("uploads/abc.bin", {
      classification: "operational",
      expiresIn:      900,
      contentType:    "application/octet-stream",
      date:           fixed,
    });

    check("returns object",                          typeof result === "object" && result !== null);
    check("method is PUT",                           result.method === "PUT");
    check("expiresAt = date + expiresIn*1000",       result.expiresAt === fixed.getTime() + 900000);
    check("Content-Type header propagated",          result.headers["Content-Type"] === "application/octet-stream");

    var url = new URL(result.url);
    check("URL targets the bucket virtual host",     url.hostname.startsWith("blamejs-test."));
    check("URL path encodes the key",                url.pathname === "/uploads/abc.bin");
    check("X-Amz-Algorithm = AWS4-HMAC-SHA256",      url.searchParams.get("X-Amz-Algorithm") === "AWS4-HMAC-SHA256");
    check("X-Amz-Expires reflects expiresIn",        url.searchParams.get("X-Amz-Expires") === "900");
    check("X-Amz-SignedHeaders = host",              url.searchParams.get("X-Amz-SignedHeaders") === "host");
    check("X-Amz-Date is iso compact form",          url.searchParams.get("X-Amz-Date") === "20260427T123456Z");
    var cred = url.searchParams.get("X-Amz-Credential") || "";
    check("X-Amz-Credential includes accessKeyId",   cred.indexOf("AKIAIOSFODNN7EXAMPLE/") === 0);
    check("X-Amz-Credential ends with aws4_request", cred.endsWith("/aws4_request"));
    check("X-Amz-Signature is 64 hex chars",         /^[0-9a-f]{64}$/.test(url.searchParams.get("X-Amz-Signature")));
  } finally {
    b.storage._resetForTest();
    await teardownTestDb(tmpDir);
  }
}

async function testSigv4SignatureIsDeterministic() {
  // Two calls with identical inputs must produce identical URLs — the
  // signature is a pure function of (key, date, secret, region, expiry).
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-presign-"));
  try {
    await setupTestDb(tmpDir);
    b.storage._resetForTest();
    await b.vault.init({ dataDir: tmpDir, mode: "plaintext" });
    b.storage.init({
      backends: { "s3": SIGV4_CONFIG },
      defaultClassification: "operational",
    });

    var fixed = new Date("2026-04-27T00:00:00Z");
    var a = b.storage.presignedUploadUrl("k.bin",
      { classification: "operational", expiresIn: 600, date: fixed });
    var c = b.storage.presignedUploadUrl("k.bin",
      { classification: "operational", expiresIn: 600, date: fixed });
    check("same inputs → same URL",                  a.url === c.url);

    // Different expiry → different signature
    var d = b.storage.presignedUploadUrl("k.bin",
      { classification: "operational", expiresIn: 601, date: fixed });
    check("different expiresIn → different URL",     a.url !== d.url);
  } finally {
    b.storage._resetForTest();
    await teardownTestDb(tmpDir);
  }
}

async function testInvalidExpiresInRejected() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-presign-"));
  try {
    await setupTestDb(tmpDir);
    b.storage._resetForTest();
    await b.vault.init({ dataDir: tmpDir, mode: "plaintext" });
    b.storage.init({
      backends: { "s3": SIGV4_CONFIG },
      defaultClassification: "operational",
    });

    var threw = null;
    try { b.storage.presignedUploadUrl("k.bin", { expiresIn: 0 }); } catch (e) { threw = e; }
    check("expiresIn = 0 rejected",                  threw && /between 1 and 604800/.test(threw.message));

    threw = null;
    try { b.storage.presignedUploadUrl("k.bin", { expiresIn: 604801 }); } catch (e) { threw = e; }
    check("expiresIn > 7 days rejected",             threw && /between 1 and 604800/.test(threw.message));

    threw = null;
    try { b.storage.presignedUploadUrl("", {}); } catch (e) { threw = e; }
    check("empty key rejected",                      threw && /key is required/i.test(threw.message));
  } finally {
    b.storage._resetForTest();
    await teardownTestDb(tmpDir);
  }
}

async function testLocalBackendThrowsNotSupported() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-presign-"));
  try {
    await setupTestDb(tmpDir);
    b.storage._resetForTest();
    await b.vault.init({ dataDir: tmpDir, mode: "plaintext" });
    b.storage.init({ backend: "local", uploadDir: path.join(tmpDir, "uploads") });

    var threw = null;
    try { b.storage.presignedUploadUrl("k.bin", {}); } catch (e) { threw = e; }
    check("local backend rejects presigned",         threw && threw.code === "PRESIGN_NOT_SUPPORTED");
    check("error message mentions local + saveFile", threw && /local backend/i.test(threw.message) && /saveFile/i.test(threw.message));
  } finally {
    b.storage._resetForTest();
    await teardownTestDb(tmpDir);
  }
}

async function testHttpPutBackendThrowsNotSupported() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-presign-"));
  try {
    await setupTestDb(tmpDir);
    b.storage._resetForTest();
    await b.vault.init({ dataDir: tmpDir, mode: "plaintext" });
    b.storage.init({
      backends: {
        "edge": {
          protocol:        "http-put",
          baseUrl:         "https://upload.example.com",
          classifications: ["operational"],
        },
      },
      defaultClassification: "operational",
    });

    var threw = null;
    try { b.storage.presignedUploadUrl("k.bin", {}); } catch (e) { threw = e; }
    check("http-put backend rejects presigned",      threw && threw.code === "PRESIGN_NOT_SUPPORTED");
    check("error message points to sigv4 alternative", threw && /sigv4/i.test(threw.message));
  } finally {
    b.storage._resetForTest();
    await teardownTestDb(tmpDir);
  }
}

async function testAuditEventEmitted() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-presign-"));
  try {
    await setupTestDb(tmpDir);
    b.storage._resetForTest();
    await b.vault.init({ dataDir: tmpDir, mode: "plaintext" });
    b.storage.init({
      backends: { "s3": SIGV4_CONFIG },
      defaultClassification: "operational",
    });

    b.storage.presignedUploadUrl("audited.bin", { classification: "operational", expiresIn: 60 });
    await b.audit.flush();
    var rows = await b.audit.query({ action: "system.storage.presign" });
    check("system.storage.presign audit emitted",    rows.length === 1);
    var meta = typeof rows[0].metadata === "string" ? JSON.parse(rows[0].metadata) : rows[0].metadata;
    check("audit row carries backend metadata",      meta && meta.backend === "s3");
    check("audit row carries key",                   meta && meta.key === "audited.bin");
  } finally {
    b.storage._resetForTest();
    await teardownTestDb(tmpDir);
  }
}

async function run() {
  await testSurface();
  await testSigv4ProducesPresignedUrl();
  await testSigv4SignatureIsDeterministic();
  await testInvalidExpiresInRejected();
  await testLocalBackendThrowsNotSupported();
  await testHttpPutBackendThrowsNotSupported();
  await testAuditEventEmitted();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.message); process.exit(1); }
  );
}
