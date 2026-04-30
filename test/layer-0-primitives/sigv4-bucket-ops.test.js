"use strict";
/**
 * sigv4-bucket-ops — bucket-level lifecycle ops for SigV4 backends.
 *
 * Stands up a fake S3 server and exercises the create / delete / list /
 * setLifecycle / setCorsRules surface end-to-end. XML body shape +
 * Tier-A validation are also exercised through the test-only exports
 * so the asserts can be tight without TCP plumbing in the loop.
 *
 * Run standalone: `node test/layer-0-primitives/sigv4-bucket-ops.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var http               = require("http");
var bucketOps          = require("../../lib/object-store/sigv4-bucket-ops");
var b                  = helpers.b;
var check              = helpers.check;
var listenOnRandomPort = helpers.listenOnRandomPort;

function _baseConfig(port, overrides) {
  var cfg = {
    region:           "us-east-1",
    accessKeyId:      "AKIAIOSFODNN7EXAMPLE",
    secretAccessKey:  "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    endpoint:         "http://127.0.0.1:" + port,
    pathStyle:        true,
    allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
    allowInternal:    true,
    timeoutMs:        5000,
  };
  if (overrides) Object.assign(cfg, overrides);
  return cfg;
}

function _fakeS3(behavior) {
  behavior = behavior || {};
  var requests = [];
  var server = http.createServer(function (req, res) {
    var chunks = [];
    req.on("data", function (c) { chunks.push(c); });
    req.on("end", function () {
      var body = Buffer.concat(chunks);
      var rec = { method: req.method, url: req.url, headers: req.headers, body: body };
      requests.push(rec);

      var parsed = new URL("http://x" + req.url);
      var path = parsed.pathname;

      // ListBuckets — GET / on the service URL.
      if (req.method === "GET" && path === "/" && !req.headers.host.startsWith("test-bucket")) {
        res.writeHead(200, { "Content-Type": "application/xml" });
        res.end(
          "<?xml version='1.0' encoding='UTF-8'?>" +
          "<ListAllMyBucketsResult>" +
          "<Buckets>" +
          "<Bucket><Name>alpha</Name><CreationDate>2026-01-01T00:00:00.000Z</CreationDate><BucketRegion>us-east-1</BucketRegion></Bucket>" +
          "<Bucket><Name>beta</Name><CreationDate>2026-02-01T00:00:00.000Z</CreationDate><BucketRegion>eu-west-1</BucketRegion></Bucket>" +
          "</Buckets>" +
          "<Owner><ID>op-id</ID><DisplayName>op</DisplayName></Owner>" +
          "</ListAllMyBucketsResult>"
        );
        return;
      }

      if (req.method === "PUT" && parsed.searchParams.has("lifecycle")) {
        if (behavior.lifecycleErr) {
          res.writeHead(behavior.lifecycleErr.status, { "Content-Type": "application/xml" });
          res.end("<Error><Code>" + behavior.lifecycleErr.code + "</Code></Error>");
          return;
        }
        res.writeHead(200);
        res.end();
        return;
      }
      if (req.method === "PUT" && parsed.searchParams.has("cors")) {
        res.writeHead(200);
        res.end();
        return;
      }
      // CreateBucket — PUT /<bucket>/ (path-style) with optional XML body.
      if (req.method === "PUT") {
        if (behavior.createErr) {
          res.writeHead(behavior.createErr.status, { "Content-Type": "application/xml" });
          res.end(
            "<Error><Code>" + behavior.createErr.code + "</Code>" +
            "<Message>" + behavior.createErr.code + "</Message></Error>"
          );
          return;
        }
        res.writeHead(200, { Location: path });
        res.end();
        return;
      }
      // DeleteBucket — DELETE /<bucket>/ (path-style).
      if (req.method === "DELETE") {
        if (behavior.deleteErr) {
          res.writeHead(behavior.deleteErr.status, { "Content-Type": "application/xml" });
          res.end(
            "<Error><Code>" + behavior.deleteErr.code + "</Code>" +
            "<Message>" + behavior.deleteErr.code + "</Message></Error>"
          );
          return;
        }
        res.writeHead(204);
        res.end();
        return;
      }
      res.writeHead(400);
      res.end();
    });
  });
  return { server: server, requests: requests };
}

// ---- Surface ----

function testSurface() {
  check("b.objectStore.bucketOps namespace present",
        typeof b.objectStore.bucketOps === "object");
  check("bucketOps.create is a function",
        typeof b.objectStore.bucketOps.create === "function");
  var ops = b.objectStore.bucketOps.create({
    region: "us-east-1", accessKeyId: "x", secretAccessKey: "y",
    endpoint: "http://127.0.0.1:1",
    allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
  });
  check("instance.create is fn",       typeof ops.create === "function");
  check("instance.delete is fn",       typeof ops.delete === "function");
  check("instance.list is fn",         typeof ops.list === "function");
  check("instance.setLifecycle is fn", typeof ops.setLifecycle === "function");
  check("instance.setCorsRules is fn", typeof ops.setCorsRules === "function");
}

// ---- Config validation ----

function testFactoryValidation() {
  function shouldThrow(label, opts, codeRe) {
    var threw = null;
    try { bucketOps.create(opts); } catch (e) { threw = e; }
    check("factory: " + label,  threw && codeRe.test(threw.code || ""));
  }
  shouldThrow("rejects null opts",      null, /INVALID_CONFIG/);
  shouldThrow("rejects missing region",
    { accessKeyId: "x", secretAccessKey: "y" }, /INVALID_CONFIG/);
  shouldThrow("rejects missing accessKeyId",
    { region: "us-east-1", secretAccessKey: "y" }, /INVALID_CONFIG/);
  shouldThrow("rejects unsupported protocol",
    { protocol: "gcs", region: "us-east-1", accessKeyId: "x", secretAccessKey: "y" },
    /INVALID_CONFIG/);
}

// ---- Bucket name validation ----

function testBucketNameValidation() {
  var v = bucketOps._validateBucketNameForTest;
  function shouldThrow(label, name) {
    var threw = null;
    try { v(name); } catch (e) { threw = e; }
    check("bucket-name: " + label,  threw && /BUCKET_INVALID_NAME/.test(threw.code));
  }
  shouldThrow("rejects too short",        "ab");
  shouldThrow("rejects too long",         new Array(65).join("a"));
  shouldThrow("rejects uppercase",        "MyBucket");
  shouldThrow("rejects leading hyphen",   "-bucket");
  shouldThrow("rejects trailing hyphen",  "bucket-");
  shouldThrow("rejects underscore",       "my_bucket");
  shouldThrow("rejects consecutive dots", "my..bucket");
  // Valid names should not throw.
  v("valid-bucket-name");
  v("vbn1");
  v("a.b.c");
  check("bucket-name: valid names pass",  true);
}

// ---- Lifecycle XML builder ----

function testLifecycleXml() {
  var b1 = bucketOps._buildLifecycleXmlForTest([{
    id: "abort-stale", status: "Enabled", prefix: "",
    abortIncompleteMultipartUpload: { daysAfterInitiation: 7 },
  }]);
  check("lifecycle: root LifecycleConfiguration",
        /<LifecycleConfiguration/.test(b1));
  check("lifecycle: ID present",
        /<ID>abort-stale<\/ID>/.test(b1));
  check("lifecycle: Status Enabled",
        /<Status>Enabled<\/Status>/.test(b1));
  check("lifecycle: AbortIncompleteMultipartUpload present",
        /<AbortIncompleteMultipartUpload><DaysAfterInitiation>7<\/DaysAfterInitiation>/.test(b1));

  var b2 = bucketOps._buildLifecycleXmlForTest([{
    prefix: "tmp/", status: "Enabled",
    expiration: { days: 30 },
    transition: { days: 90, storageClass: "GLACIER" },
  }]);
  check("lifecycle: prefix + expiration days",
        /<Prefix>tmp\/<\/Prefix>/.test(b2) && /<Expiration><Days>30<\/Days><\/Expiration>/.test(b2));
  check("lifecycle: transition storageClass",
        /<Transition><Days>90<\/Days><StorageClass>GLACIER<\/StorageClass><\/Transition>/.test(b2));

  function shouldThrow(label, rules, codeRe) {
    var threw = null;
    try { bucketOps._buildLifecycleXmlForTest(rules); } catch (e) { threw = e; }
    check("lifecycle: " + label,  threw && codeRe.test(threw.code || ""));
  }
  shouldThrow("rejects empty rules",            [],
    /INVALID_LIFECYCLE/);
  shouldThrow("rejects non-array rules",        "no",
    /INVALID_LIFECYCLE/);
  shouldThrow("rejects bad status",
    [{ prefix: "", status: "Mid", expiration: { days: 1 } }],
    /INVALID_LIFECYCLE/);
  shouldThrow("rejects rule with no action",
    [{ prefix: "", status: "Enabled" }],
    /INVALID_LIFECYCLE/);
  shouldThrow("rejects unknown storageClass",
    [{ prefix: "", status: "Enabled",
       transition: { days: 90, storageClass: "ICE" } }],
    /INVALID_LIFECYCLE/);
  shouldThrow("rejects expiration.days = 0",
    [{ prefix: "", status: "Enabled", expiration: { days: 0 } }],
    /INVALID_LIFECYCLE/);
}

// ---- CORS XML builder ----

function testCorsXml() {
  var x = bucketOps._buildCorsXmlForTest([{
    allowedOrigins: ["https://app.example.com"],
    allowedMethods: ["GET", "PUT"],
    allowedHeaders: ["*"],
    exposeHeaders:  ["ETag"],
    maxAgeSeconds:  3600,
  }]);
  check("cors: root CORSConfiguration",   /<CORSConfiguration/.test(x));
  check("cors: AllowedOrigin escaped",
        /<AllowedOrigin>https:\/\/app\.example\.com<\/AllowedOrigin>/.test(x));
  check("cors: methods listed",
        /<AllowedMethod>GET<\/AllowedMethod><AllowedMethod>PUT<\/AllowedMethod>/.test(x));
  check("cors: AllowedHeader wildcard",   /<AllowedHeader>\*<\/AllowedHeader>/.test(x));
  check("cors: ExposeHeader present",     /<ExposeHeader>ETag<\/ExposeHeader>/.test(x));
  check("cors: MaxAgeSeconds present",    /<MaxAgeSeconds>3600<\/MaxAgeSeconds>/.test(x));

  function shouldThrow(label, rules, codeRe) {
    var threw = null;
    try { bucketOps._buildCorsXmlForTest(rules); } catch (e) { threw = e; }
    check("cors: " + label,  threw && codeRe.test(threw.code || ""));
  }
  shouldThrow("rejects empty rules array",  [], /INVALID_CORS_RULE/);
  shouldThrow("rejects missing allowedOrigins",
    [{ allowedMethods: ["GET"] }],
    /INVALID_CORS_RULE/);
  shouldThrow("rejects missing allowedMethods",
    [{ allowedOrigins: ["*"] }],
    /INVALID_CORS_RULE/);
  shouldThrow("rejects bad allowedMethod",
    [{ allowedOrigins: ["*"], allowedMethods: ["TRACE"] }],
    /INVALID_CORS_RULE/);
  shouldThrow("rejects negative maxAgeSeconds",
    [{ allowedOrigins: ["*"], allowedMethods: ["GET"], maxAgeSeconds: -1 }],
    /INVALID_CORS_RULE/);
}

// ---- create / delete / list / setLifecycle / setCorsRules over the wire ----

async function testCreateBucketUsEast1NoBody() {
  var fake = _fakeS3();
  var port = await listenOnRandomPort(fake.server);
  try {
    var ops = bucketOps.create(_baseConfig(port));
    var result = await ops.create("my-bucket");
    check("create us-east-1: result.created",     result.created === true);
    check("create us-east-1: result.name",        result.name === "my-bucket");
    var req = fake.requests[0];
    check("create us-east-1: PUT method",         req.method === "PUT");
    check("create us-east-1: empty body",         req.body.length === 0);
  } finally {
    await new Promise(function (r) { fake.server.close(function () { r(); }); });
  }
}

async function testCreateBucketOtherRegionSendsLocationConstraint() {
  var fake = _fakeS3();
  var port = await listenOnRandomPort(fake.server);
  try {
    var ops = bucketOps.create(_baseConfig(port));
    await ops.create("eu-bucket", { region: "eu-west-1" });
    var req = fake.requests[0];
    check("create eu: body has CreateBucketConfiguration",
          /CreateBucketConfiguration/.test(req.body.toString("utf8")));
    check("create eu: LocationConstraint present",
          /<LocationConstraint>eu-west-1<\/LocationConstraint>/.test(req.body.toString("utf8")));
  } finally {
    await new Promise(function (r) { fake.server.close(function () { r(); }); });
  }
}

async function testCreateBucketAlreadyOwnedMaps() {
  var fake = _fakeS3({
    createErr: { status: 409, code: "BucketAlreadyOwnedByYou" },
  });
  var port = await listenOnRandomPort(fake.server);
  try {
    var ops = bucketOps.create(_baseConfig(port));
    var threw = null;
    try { await ops.create("mine"); } catch (e) { threw = e; }
    check("create owned: maps to BUCKET_ALREADY_OWNED",
          threw && /BUCKET_ALREADY_OWNED/.test(threw.code || ""));
  } finally {
    await new Promise(function (r) { fake.server.close(function () { r(); }); });
  }
}

async function testCreateBucketTakenMaps() {
  var fake = _fakeS3({
    createErr: { status: 409, code: "BucketAlreadyExists" },
  });
  var port = await listenOnRandomPort(fake.server);
  try {
    var ops = bucketOps.create(_baseConfig(port));
    var threw = null;
    try { await ops.create("taken"); } catch (e) { threw = e; }
    check("create taken: maps to BUCKET_NAME_TAKEN",
          threw && /BUCKET_NAME_TAKEN/.test(threw.code || ""));
  } finally {
    await new Promise(function (r) { fake.server.close(function () { r(); }); });
  }
}

async function testDeleteBucketHappyAndMissing() {
  var fake = _fakeS3();
  var port = await listenOnRandomPort(fake.server);
  try {
    var ops = bucketOps.create(_baseConfig(port));
    var ok = await ops.delete("gone");
    check("delete: returns true on 204",  ok === true);
  } finally {
    await new Promise(function (r) { fake.server.close(function () { r(); }); });
  }

  var fake2 = _fakeS3({ deleteErr: { status: 404, code: "NoSuchBucket" } });
  var port2 = await listenOnRandomPort(fake2.server);
  try {
    var ops2 = bucketOps.create(_baseConfig(port2));
    var ok2 = await ops2.delete("missing");
    check("delete: returns false on 404",  ok2 === false);
  } finally {
    await new Promise(function (r) { fake2.server.close(function () { r(); }); });
  }
}

async function testDeleteBucketNotEmptyMaps() {
  var fake = _fakeS3({ deleteErr: { status: 409, code: "BucketNotEmpty" } });
  var port = await listenOnRandomPort(fake.server);
  try {
    var ops = bucketOps.create(_baseConfig(port));
    var threw = null;
    try { await ops.delete("full"); } catch (e) { threw = e; }
    check("delete not-empty: maps to BUCKET_NOT_EMPTY",
          threw && /BUCKET_NOT_EMPTY/.test(threw.code || ""));
  } finally {
    await new Promise(function (r) { fake.server.close(function () { r(); }); });
  }
}

async function testListBuckets() {
  var fake = _fakeS3();
  var port = await listenOnRandomPort(fake.server);
  try {
    var ops = bucketOps.create(_baseConfig(port));
    var buckets = await ops.list();
    check("list: returns 2 buckets",       buckets.length === 2);
    check("list: bucket name parsed",      buckets[0].name === "alpha");
    check("list: bucket region parsed",    buckets[1].region === "eu-west-1");
    check("list: creationDate is a ms ts", typeof buckets[0].creationDate === "number");
  } finally {
    await new Promise(function (r) { fake.server.close(function () { r(); }); });
  }
}

async function testSetLifecycleSendsXml() {
  var fake = _fakeS3();
  var port = await listenOnRandomPort(fake.server);
  try {
    var ops = bucketOps.create(_baseConfig(port));
    var result = await ops.setLifecycle("logs", [{
      id: "abort", status: "Enabled", prefix: "",
      abortIncompleteMultipartUpload: { daysAfterInitiation: 7 },
    }]);
    check("setLifecycle: applied=true",          result.applied === true);
    check("setLifecycle: ruleCount echoed",      result.ruleCount === 1);
    var req = fake.requests[0];
    check("setLifecycle: ?lifecycle in url",     req.url.indexOf("lifecycle") !== -1);
    check("setLifecycle: Content-MD5 sent",      typeof req.headers["content-md5"] === "string");
    check("setLifecycle: body has root element", /<LifecycleConfiguration/.test(req.body.toString("utf8")));
  } finally {
    await new Promise(function (r) { fake.server.close(function () { r(); }); });
  }
}

async function testSetCorsRulesSendsXml() {
  var fake = _fakeS3();
  var port = await listenOnRandomPort(fake.server);
  try {
    var ops = bucketOps.create(_baseConfig(port));
    var result = await ops.setCorsRules("public", [{
      allowedOrigins: ["https://wiki.example.com"],
      allowedMethods: ["GET", "HEAD"],
      maxAgeSeconds:  86400,
    }]);
    check("setCorsRules: applied=true",          result.applied === true);
    var req = fake.requests[0];
    check("setCorsRules: ?cors in url",          req.url.indexOf("cors") !== -1);
    check("setCorsRules: Content-MD5 sent",      typeof req.headers["content-md5"] === "string");
    check("setCorsRules: body has CORSRule",     /<CORSRule>/.test(req.body.toString("utf8")));
  } finally {
    await new Promise(function (r) { fake.server.close(function () { r(); }); });
  }
}

async function run() {
  testSurface();
  testFactoryValidation();
  testBucketNameValidation();
  testLifecycleXml();
  testCorsXml();
  await testCreateBucketUsEast1NoBody();
  await testCreateBucketOtherRegionSendsLocationConstraint();
  await testCreateBucketAlreadyOwnedMaps();
  await testCreateBucketTakenMaps();
  await testDeleteBucketHappyAndMissing();
  await testDeleteBucketNotEmptyMaps();
  await testListBuckets();
  await testSetLifecycleSendsXml();
  await testSetCorsRulesSendsXml();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
