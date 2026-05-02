"use strict";
/**
 * Live S3 round-trip against the docker-compose MinIO fixtures.
 * Covers BOTH the plain HTTP listener (minio:9000) and the TLS listener
 * (minio-tls:9443) so the framework's sigv4 signer + S3 client are
 * exercised end-to-end against real AWS-compatible servers.
 *
 * No security bypass: the TLS leg pins the test CA via opts.ca on
 * the request layer (rejectUnauthorized stays on by default).
 */
var fs = require("node:fs");
var helpers = require("../helpers");
var check = helpers.check;
var services = require("../helpers/services");
var b = require("../../");

var REGION = "us-east-1";
var ACCESS = "blamejs";
var SECRET = "blamejs_test_password";

function _runOnEndpoint(label, endpoint, extraConfig) {
  var bucket = "blamejs-test-" + label + "-" + Date.now();
  var key    = "obj-" + Math.floor(Math.random() * 1e6) + ".txt";
  var payload = Buffer.from("integration payload " + new Date().toISOString(), "utf8");

  return (async function () {
    var opsCfg = Object.assign({
      endpoint:        endpoint,
      region:          REGION,
      accessKeyId:     ACCESS,
      secretAccessKey: SECRET,
      allowInternal:   true,
      forcePathStyle:  true,
    }, extraConfig);
    var ops = b.objectStore.bucketOps.create(opsCfg);
    await ops.create(bucket);
    check("[" + label + "] bucketOps.create: bucket created", true);

    var beCfg = Object.assign({
      name:            "minio-" + label,
      protocol:        "sigv4",
      endpoint:        endpoint,
      region:          REGION,
      bucket:          bucket,
      accessKeyId:     ACCESS,
      secretAccessKey: SECRET,
      allowInternal:   true,
      forcePathStyle:  true,
      classifications: ["operational"],
      residencyTag:    "unrestricted",
    }, extraConfig);
    var backend = b.objectStore.buildBackend(beCfg);

    // ---- put + get round-trip ----
    var putRv = await backend.put(key, payload, { contentType: "text/plain" });
    check("[" + label + "] put: returned (no throw)", true);
    check("[" + label + "] put: surfaced an etag or key",
          !!(putRv && (putRv.key === key || putRv.etag || putRv.location)));

    var got = await backend.get(key);
    var gotBuf = Buffer.isBuffer(got) ? got : (got && got.body);
    check("[" + label + "] get: bytes round-trip exactly",
          Buffer.isBuffer(gotBuf) && Buffer.compare(gotBuf, payload) === 0);

    // ---- list (correct signature: list(prefix, opts), prefix is a string) ----
    var listing = await backend.list("obj-");
    check("[" + label + "] list: returns { items } shape",
          listing && Array.isArray(listing.items));
    check("[" + label + "] list: surfaces the just-put object",
          listing.items.some(function (it) { return it.key === key; }));
    check("[" + label + "] list: item has size matching the payload",
          listing.items.some(function (it) {
            return it.key === key && it.size === payload.length;
          }));

    // ---- list with non-matching prefix returns empty ----
    var emptyListing = await backend.list("does-not-exist-");
    check("[" + label + "] list: non-matching prefix returns empty items",
          emptyListing && Array.isArray(emptyListing.items) && emptyListing.items.length === 0);

    // ---- delete + verify gone ----
    await backend.delete(key);
    check("[" + label + "] delete: returned (no throw)", true);
    var afterDelete = await backend.list("obj-");
    check("[" + label + "] list after delete: object gone",
          !afterDelete.items.some(function (it) { return it.key === key; }));

    await ops.delete(bucket);
    check("[" + label + "] bucketOps.delete: bucket dropped", true);
  })();
}

async function run() {
  var svc = await services.requireService("minio");
  if (!svc.ok) throw new Error("minio unreachable: " + svc.reason);
  var svcTls = await services.requireService("minioTls");
  if (!svcTls.ok) throw new Error("minio-tls unreachable: " + svcTls.reason);

  var caPath = await services.exportCaCert();
  var caPem = fs.readFileSync(caPath, "utf8");

  // ---- plain HTTP variant ----
  await _runOnEndpoint("http", "http://127.0.0.1:9000", {
    allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
  });

  // ---- TLS variant — strict CA pinning, no rejectUnauthorized override ----
  // Endpoint uses "localhost" so SNI works (cert SAN covers localhost +
  // 127.0.0.1; node:tls forbids IP literals as servername).
  await _runOnEndpoint("tls", "https://localhost:9443", {
    ca: caPem,
  });
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); process.exit(0); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
