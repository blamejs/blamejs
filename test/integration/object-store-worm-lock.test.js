"use strict";
/**
 * S3 Object Lock WORM enforcement — does COMPLIANCE-mode retention
 * actually REFUSE a delete on real MinIO (which enforces Object Lock)?
 *
 * The existing object-store-sigv4 test only round-trips the retention /
 * legal-hold CONFIG (set → get echoes the value back). It explicitly
 * does NOT assert that a delete is blocked, with the rationale that
 * Object-Lock buckets are versioned and an unversioned DELETE just
 * writes a delete-marker. That leaves the headline WORM guarantee
 * ("a record cannot be deleted before its retainUntil by anyone") never
 * proven against a backend that enforces it.
 *
 * This test proves enforcement directly: it puts an object into an
 * Object-Lock-enabled bucket, applies a COMPLIANCE retention with
 * retainUntil in the future, then attempts to delete the PROTECTED
 * VERSION and asserts MinIO refuses. A control object with no retention
 * has its version deleted successfully, proving the refusal is the lock
 * and not a blanket failure.
 *
 * Why the versioned delete matters — and what it exposes about the
 * framework: WORM protects a specific object VERSION. An unversioned
 * `DELETE /key` on a versioned bucket always succeeds (it writes a
 * delete-marker; the protected version survives untouched). The
 * framework's object-store delete (`backend.delete(key)` /
 * `bucketOps.delete`) issues ONLY the unversioned form — there is no
 * versionId surface anywhere in lib/object-store. So:
 *
 *   (a) the framework's own delete() on a retained object SUCCEEDS and
 *       returns a clean result, masking the fact that the data version
 *       is still there — the framework delete path is not WORM-aware;
 *   (b) the operation WORM actually blocks (delete the protected version)
 *       can only be issued by hand-signing `DELETE /key?versionId=<v>`.
 *
 * This test hand-signs that versioned delete with the framework's OWN
 * SigV4 signer (lib/object-store/sigv4.signRequest) so the proof is that
 * MinIO enforces the lock under a request the framework signed correctly
 * — no security bypass, real handshake, real signature.
 *
 * Observed MinIO behaviour (ground truth, captured live): the versioned
 * delete of a COMPLIANCE-retained version is refused with HTTP 400
 * InvalidRequest, body "Object is WORM protected and cannot be
 * overwritten" — both with and without x-amz-bypass-governance-retention
 * (COMPLIANCE cannot be bypassed by anyone). A no-retention version
 * deletes with HTTP 204. AWS S3 uses 403 AccessDenied for the same
 * refusal; the assertion accepts any 4xx refusal carrying the WORM
 * signal so it holds on both backends.
 *
 * MinIO note: an Object-Lock bucket MUST be created with the
 * x-amz-bucket-object-lock-enabled:true header at create time (object
 * lock cannot be added later). bucketOps.create({ objectLockEnabled:true })
 * sends that header. MinIO genuinely ENFORCES COMPLIANCE retention; it is
 * the right backend for this proof. LocalStack's community S3 does not
 * verify SigV4 and its Object-Lock enforcement is not authoritative — we
 * target MinIO only.
 */
var helpers = require("../helpers");
var check = helpers.check;
var services = require("../helpers/services");
var b = require("../../");
var sigv4 = require("../../lib/object-store/sigv4");

var REGION = "us-east-1";
var ACCESS = "blamejs";
var SECRET = "blamejs_test_password";

// Hand-sign a raw S3 request with the framework's signer and send it via
// the framework's httpClient in always-resolve mode, so EVERY HTTP
// response — including a 4xx WORM refusal — comes back as
// { statusCode, headers, body } rather than a thrown error. Only a
// transport-level failure rejects. extraHeaders lets a caller add e.g.
// x-amz-bypass-governance-retention into the signed set.
function _rawSigned(method, urlStr, bodyBuf, extraHeaders) {
  var payloadHash = sigv4.sha256Hex(bodyBuf || Buffer.alloc(0));
  var extra = Object.assign({}, extraHeaders || {});
  if (bodyBuf && bodyBuf.length > 0) {
    extra["Content-Length"] = String(bodyBuf.length);
    if (!extra["Content-Type"]) extra["Content-Type"] = "application/octet-stream";
  }
  var signed = sigv4.signRequest({
    method:           method,
    url:              urlStr,
    headers:          extra,
    payloadHash:      payloadHash,
    region:           REGION,
    accessKeyId:      ACCESS,
    secretAccessKey:  SECRET,
    allowedProtocols: ["http:", "https:"],
  });
  return b.httpClient.request({
    method:           method,
    url:              urlStr,
    headers:          signed.headers,
    body:             bodyBuf && bodyBuf.length > 0 ? bodyBuf : null,
    allowedProtocols: ["http:", "https:"],
    allowInternal:    true,
    responseMode:     "always-resolve",
  });
}

function _objUrl(endpoint, bucket, key, versionId) {
  var u = endpoint + "/" + bucket + "/" + encodeURIComponent(key);
  if (versionId) u += "?versionId=" + encodeURIComponent(versionId);
  return u;
}

function _bodyText(res) {
  return res && res.body ? Buffer.from(res.body).toString("utf8") : "";
}

// A genuine WORM refusal: a 4xx whose body carries the lock signal.
// MinIO → 400 InvalidRequest "Object is WORM protected"; AWS S3 → 403
// AccessDenied. Accept either, but require the WORM/retention signal so a
// generic 400 (bad request shape) can't masquerade as enforcement.
function _isWormRefusal(res) {
  if (!res || (res.statusCode !== 400 && res.statusCode !== 403)) return false;
  var t = _bodyText(res);
  return /WORM|retention|object lock|AccessDenied|cannot be overwritten|protected/i.test(t);
}

async function _runWormOnEndpoint(label, endpoint, extraConfig) {
  var bucket = "blamejs-worm-" + label + "-" + Date.now();
  var opsCfg = Object.assign({
    protocol:        "sigv4",
    endpoint:        endpoint,
    region:          REGION,
    accessKeyId:     ACCESS,
    secretAccessKey: SECRET,
    allowInternal:   true,
    forcePathStyle:  true,
  }, extraConfig);
  var ops = b.objectStore.bucketOps.create(opsCfg);

  // ---- 1. Object-Lock-enabled bucket (header at create time) ----
  await ops.create(bucket, { objectLockEnabled: true });
  var lockCfg = await ops.getObjectLockConfiguration(bucket);
  check("[" + label + "] bucket reports object-lock enabled", lockCfg.enabled === true);

  var backend = b.objectStore.buildBackend(Object.assign({
    name:            "minio-worm-" + label,
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
  }, extraConfig));

  // ============================================================
  // PROTECTED OBJECT — COMPLIANCE retention in the future
  // ============================================================
  var key = "worm-doc-" + Math.floor(Math.random() * 1e6) + ".txt";
  var payload = Buffer.from("immutable filing " + new Date().toISOString(), "utf8");

  // Capture the versionId from a hand-signed PUT (backend.put discards
  // x-amz-version-id; we need the version to target the protected delete).
  var putRes = await _rawSigned("PUT", _objUrl(endpoint, bucket, key), payload);
  check("[" + label + "] protected object PUT succeeds", putRes.statusCode === 200);
  var versionId = putRes.headers && putRes.headers["x-amz-version-id"];
  check("[" + label + "] PUT returned a versionId (bucket is versioned)",
        typeof versionId === "string" && versionId.length > 0);

  // Apply COMPLIANCE retention 1 hour into the future — long enough that
  // it cannot lapse during the test. COMPLIANCE = nobody can delete the
  // version before retainUntil, not even with bypassGovernance.
  var retainUntil = new Date(Date.now() + b.constants.TIME.hours(1));
  var setRet = await ops.setObjectRetention(bucket, key, {
    mode:        "COMPLIANCE",
    retainUntil: retainUntil,
  });
  check("[" + label + "] setObjectRetention COMPLIANCE applied", setRet.applied === true);

  var gotRet = await ops.getObjectRetention(bucket, key);
  check("[" + label + "] retention reads back COMPLIANCE", gotRet.mode === "COMPLIANCE");
  check("[" + label + "] retainUntil reads back in the future",
        gotRet.retainUntil instanceof Date && gotRet.retainUntil.getTime() > Date.now());

  // ---- 2. The framework's own delete() is NOT WORM-aware ----
  // backend.delete(key) issues an unversioned DELETE → MinIO writes a
  // delete-marker and returns success. The protected DATA version is
  // untouched, but the framework caller is told the delete "worked".
  // This documents that the framework delete path cannot enforce — and
  // cannot even attempt — the WORM-blocked operation.
  var fwDeleteResult = await backend.delete(key);
  check("[" + label + "] framework backend.delete() returns success on a retained object " +
        "(unversioned DELETE writes a delete-marker; data version survives)",
        fwDeleteResult === true);
  // Prove the data version actually survived the framework delete: a
  // versioned GET of the protected version still returns the bytes.
  var stillThere = await _rawSigned("GET", _objUrl(endpoint, bucket, key, versionId), null);
  check("[" + label + "] protected DATA version still readable after framework delete() " +
        "(framework delete only wrote a delete-marker)",
        stillThere.statusCode === 200 &&
        Buffer.compare(Buffer.from(stillThere.body || []), payload) === 0);

  // ---- 3. THE WORM PROOF: deleting the protected VERSION is REFUSED ----
  // This is the operation WORM exists to block. Hand-sign
  // DELETE /key?versionId=<v> with the framework's signer. MinIO must
  // refuse because the version is under COMPLIANCE retention.
  var wormDel = await _rawSigned("DELETE", _objUrl(endpoint, bucket, key, versionId), null);
  check("[" + label + "] WORM ENFORCED: delete of the COMPLIANCE-retained version is REFUSED " +
        "(got " + wormDel.statusCode + " " + _bodyText(wormDel).replace(/\s+/g, " ").slice(0, 80) + ")",
        _isWormRefusal(wormDel));

  // ---- 3b. bypassGovernance does NOT defeat COMPLIANCE ----
  // x-amz-bypass-governance-retention can shorten/delete GOVERNANCE
  // retention with the right permission, but COMPLIANCE is immutable to
  // everyone. Assert the version delete is STILL refused even with the
  // bypass header signed in.
  var wormDelBypass = await _rawSigned("DELETE", _objUrl(endpoint, bucket, key, versionId), null, {
    "x-amz-bypass-governance-retention": "true",
  });
  check("[" + label + "] COMPLIANCE cannot be bypassed: versioned delete with " +
        "x-amz-bypass-governance-retention is STILL refused (got " + wormDelBypass.statusCode + ")",
        _isWormRefusal(wormDelBypass));

  // And the version is verifiably still present after both refused deletes.
  var afterRefuse = await _rawSigned("GET", _objUrl(endpoint, bucket, key, versionId), null);
  check("[" + label + "] retained version still present after the refused deletes",
        afterRefuse.statusCode === 200 &&
        Buffer.compare(Buffer.from(afterRefuse.body || []), payload) === 0);

  // ============================================================
  // CONTROL — no retention: the version deletes fine
  // ============================================================
  var ctlKey = "control-" + Math.floor(Math.random() * 1e6) + ".txt";
  var ctlPayload = Buffer.from("disposable", "utf8");
  var ctlPut = await _rawSigned("PUT", _objUrl(endpoint, bucket, ctlKey), ctlPayload);
  check("[" + label + "] control object PUT succeeds", ctlPut.statusCode === 200);
  var ctlVersion = ctlPut.headers && ctlPut.headers["x-amz-version-id"];
  check("[" + label + "] control PUT returned a versionId",
        typeof ctlVersion === "string" && ctlVersion.length > 0);

  var ctlDel = await _rawSigned("DELETE", _objUrl(endpoint, bucket, ctlKey, ctlVersion), null);
  check("[" + label + "] CONTROL: no-retention version deletes fine (2xx) — the refusal above " +
        "is the lock, not a blanket failure (got " + ctlDel.statusCode + ")",
        ctlDel.statusCode === 204 || ctlDel.statusCode === 200);
  var ctlGone = await _rawSigned("GET", _objUrl(endpoint, bucket, ctlKey, ctlVersion), null);
  check("[" + label + "] control version is gone after delete (404)",
        ctlGone.statusCode === 404);

  // ---- Cleanup is impossible while COMPLIANCE retention holds: the
  // protected version cannot be removed before retainUntil by anyone,
  // and bucketOps.delete refuses a non-empty bucket. That is the WORM
  // guarantee working as designed. Confirm the bucket delete refuses,
  // then leave the bucket; the name carries Date.now() so re-runs don't
  // collide and the MinIO container reset sweeps it. ----
  var bucketDropped = true;
  try {
    await ops.delete(bucket);
  } catch (_e) {
    bucketDropped = false;
  }
  check("[" + label + "] bucket with a COMPLIANCE-retained version cannot be dropped " +
        "(WORM holds the bytes)",
        bucketDropped === false);
}

async function run() {
  var svc = await services.requireService("minio");
  var svcTls = await services.requireService("minioTls");
  if (!svc.ok && !svcTls.ok) {
    throw new Error("minio unreachable (need plain or TLS): " +
      (svc.reason || "") + " / " + (svcTls.reason || ""));
  }

  // MinIO over the plain HTTP listener — it enforces Object Lock + verifies
  // SigV4 (unlike LocalStack). We use the plain endpoint for the WORM proof
  // since the enforcement, not the transport, is the subject; the runner's
  // NODE_EXTRA_CA_CERTS covers the TLS leg if only that one is up.
  if (svc.ok) {
    await _runWormOnEndpoint("http", "http://127.0.0.1:9000", {
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
    });
  } else {
    await _runWormOnEndpoint("tls", "https://localhost:9443", {});
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); process.exit(0); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
