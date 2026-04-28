"use strict";
/**
 * api-encrypt — end-to-end PQC payload encryption middleware.
 *
 * Covers nonce-store backends (memory, cluster, custom), the round-
 * trip request/response shape, replay rejection, stale-timestamp
 * rejection, AEAD tampering rejection, exempt-path bypass, and the
 * client helper.
 *
 * Run standalone: `node test/layer-0-primitives/api-encrypt.test.js`
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
var _bodyReq       = helpers._bodyReq;
var _bodyRes       = helpers._bodyRes;

// Register the finish listener BEFORE the middleware runs, otherwise
// res.end() fires synchronously inside the route handler and the
// listener attached afterward never sees it.
function _newFinish(res) {
  return new Promise(function (resolve) { res.on("finish", resolve); });
}

function _mkRes() {
  var res = _bodyRes();
  // Mirror the router's res.json convention so api-encrypt's wrap
  // chains correctly. The router would normally install this.
  res.json = function (data) {
    res.writeHead(res.statusCode || 200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(data));
  };
  res.statusCode = 200;
  return res;
}

function _serverKeypair() {
  return b.crypto.generateEncryptionKeyPair();
}

// ---- Nonce-store ----

async function testNonceStoreSurface() {
  check("b.nonceStore exposed",                  typeof b.nonceStore === "object");
  check("b.nonceStore.create is fn",             typeof b.nonceStore.create === "function");
  check("NonceStoreError is a class",            typeof b.nonceStore.NonceStoreError === "function");
}

async function testNonceStoreMemoryBasics() {
  var store = b.nonceStore.create({ backend: "memory" });
  check("memory backend reports name",           store.name === "memory");
  var expireAt = Date.now() + 60_000;
  check("first sighting returns true",           (await store.checkAndInsert("a", expireAt)) === true);
  check("repeat returns false (replay)",         (await store.checkAndInsert("a", expireAt)) === false);
  check("different nonce returns true",          (await store.checkAndInsert("b", expireAt)) === true);
  store.close();
}

async function testNonceStoreMemoryRejectsBadInput() {
  var store = b.nonceStore.create({ backend: "memory" });
  var threw = null;
  try { await store.checkAndInsert("", Date.now() + 60_000); } catch (e) { threw = e; }
  check("empty nonce rejected",                  threw && threw.code === "INVALID_NONCE");
  threw = null;
  try { await store.checkAndInsert("x", "later"); } catch (e) { threw = e; }
  check("non-number expireAt rejected",          threw && threw.code === "INVALID_EXPIRE");
  store.close();
}

async function testNonceStoreMemoryPurge() {
  var store = b.nonceStore.create({ backend: "memory" });
  var now = Date.now();
  await store.checkAndInsert("expiredA", now - 1000);
  await store.checkAndInsert("expiredB", now - 1);
  await store.checkAndInsert("fresh",    now + 60_000);
  check("size before purge: 3",                  store._size() === 3);
  var removed = await store.purgeExpired();
  check("purgeExpired returned 2",               removed === 2);
  check("size after purge: 1",                   store._size() === 1);
  // Expired nonce becomes reusable after purge — the framework
  // refuses replay only WITHIN the window.
  check("post-purge insert returns true",        (await store.checkAndInsert("expiredA", now + 60_000)) === true);
  store.close();
}

async function testNonceStoreClusterBasics() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-ns-"));
  try {
    await setupTestDb(tmpDir);
    var store = b.nonceStore.create({ backend: "cluster" });
    check("cluster backend reports name",          store.name === "cluster");
    var expireAt = Date.now() + 60_000;
    check("cluster first sighting true",          (await store.checkAndInsert("c1", expireAt)) === true);
    check("cluster replay false",                 (await store.checkAndInsert("c1", expireAt)) === false);

    // A SECOND cluster store talking to the same DB sees the row too —
    // that's the whole point of cluster mode.
    var store2 = b.nonceStore.create({ backend: "cluster" });
    check("second instance sees the same row",    (await store2.checkAndInsert("c1", expireAt)) === false);
    check("second instance accepts new nonce",    (await store2.checkAndInsert("c2", expireAt)) === true);

    // Purge respects expireAt
    await store.checkAndInsert("oldA", Date.now() - 5000);
    var removed = await store.purgeExpired();
    check("cluster purgeExpired removed >= 1",    removed >= 1);

    store.close();
    store2.close();
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testNonceStoreCustomBackend() {
  var calls = [];
  var custom = {
    checkAndInsert: function (n, e) {
      calls.push({ nonce: n, expireAt: e });
      return Promise.resolve(calls.length === 1);
    },
  };
  var store = b.nonceStore.create({ backend: custom });
  check("custom backend name='custom'",          store.name === "custom");
  check("first call returns true",               (await store.checkAndInsert("x", Date.now() + 60_000)) === true);
  check("second call returns false",             (await store.checkAndInsert("x", Date.now() + 60_000)) === false);
  check("custom backend got both calls",         calls.length === 2);
  // Default purgeExpired stub returns 0
  check("default purgeExpired returns 0",        (await store.purgeExpired()) === 0);
  store.close();
}

async function testNonceStoreUnknownBackend() {
  var threw = null;
  try { b.nonceStore.create({ backend: "memcached" }); } catch (e) { threw = e; }
  check("unknown backend rejected",              threw && threw.code === "UNKNOWN_BACKEND");
}

// ---- api-encrypt middleware ----

async function testApiEncryptKeypairValidated() {
  var threw = null;
  try { b.middleware.apiEncrypt({}); } catch (e) { threw = e; }
  check("missing keypair rejected at create",   threw && threw.code === "INVALID_KEYPAIR");
  threw = null;
  try {
    b.middleware.apiEncrypt({ keypair: { publicKey: "pem", privateKey: "pem" } });
  } catch (e) { threw = e; }
  check("non-hybrid keypair rejected",           threw && threw.code === "INVALID_KEYPAIR");
}

async function testApiEncryptRoundTrip() {
  var keypair = _serverKeypair();
  var mw = b.middleware.apiEncrypt({ keypair: keypair, audit: false });
  var clientCtx = b.middleware.apiEncrypt.client({ pubkey: keypair });

  var clientCall = clientCtx.encryptRequest({ user: "alice", action: "ping" });
  check("client.body has _ek/_ct/_ts/_nonce",
        typeof clientCall.body._ek === "string" &&
        typeof clientCall.body._ct === "string" &&
        typeof clientCall.body._ts === "number" &&
        typeof clientCall.body._nonce === "string");

  // Simulate a request that bodyParser already parsed.
  var req = _bodyReq("POST", { "content-type": "application/json" }, "");
  req.body = clientCall.body;
  var res = _mkRes();
  var fin = _newFinish(res);

  var nextCalled = false;
  await mw(req, res, function () {
    nextCalled = true;
    check("middleware: req.body replaced with cleartext",
          req.body && req.body.user === "alice" && req.body.action === "ping");
    check("middleware: req.apiEncryptSessionKey stashed",
          Buffer.isBuffer(req.apiEncryptSessionKey) &&
          req.apiEncryptSessionKey.length === 32);
    res.json({ ok: true, echo: req.body });
  });
  await fin;

  check("middleware called next()",              nextCalled === true);
  check("response status 200",                   res._endedStatus === 200);

  var responseBody = JSON.parse(res._captured);
  check("response body has _ct only",            typeof responseBody._ct === "string" && !responseBody._ek);
  var plain = clientCall.decryptResponse(responseBody);
  check("client decrypted response",             plain && plain.ok === true && plain.echo.user === "alice");
}

async function testApiEncryptRejectsMissingShape() {
  var keypair = _serverKeypair();
  var mw = b.middleware.apiEncrypt({ keypair: keypair, audit: false });
  var req = _bodyReq("POST", { "content-type": "application/json" }, "");
  req.body = { msg: "not encrypted" };
  var res = _mkRes();
  var fin = _newFinish(res);
  await mw(req, res, function () {
    check("middleware did NOT call next on missing shape", false);
  });
  await fin;
  check("missing-shape returns 400",             res._endedStatus === 400);
  check("missing-shape body says 'required'",    /encrypted-payload-required/.test(res._captured));
}

async function testApiEncryptRejectsStaleTimestamp() {
  var keypair = _serverKeypair();
  var mw = b.middleware.apiEncrypt({
    keypair:        keypair,
    audit:          false,
    replayWindowMs: 1000,   // 1 second window
  });
  var clientCtx = b.middleware.apiEncrypt.client({ pubkey: keypair });
  var clientCall = clientCtx.encryptRequest({ x: 1 });
  // Backdate the timestamp past the window
  clientCall.body._ts = Date.now() - 10_000;

  var req = _bodyReq("POST", {}, "");
  req.body = clientCall.body;
  var res = _mkRes();
  var fin = _newFinish(res);
  await mw(req, res, function () { check("should not have called next", false); });
  await fin;
  check("stale ts returns 400",                  res._endedStatus === 400);
  check("stale ts uses generic rejection body",  /encrypted-payload-rejected/.test(res._captured));
}

async function testApiEncryptRejectsReplay() {
  var keypair = _serverKeypair();
  var nonceStore = b.nonceStore.create({ backend: "memory" });
  var mw = b.middleware.apiEncrypt({
    keypair:    keypair,
    audit:      false,
    nonceStore: nonceStore,
  });
  var clientCtx = b.middleware.apiEncrypt.client({ pubkey: keypair });
  var clientCall = clientCtx.encryptRequest({ x: 1 });

  // First request: succeeds.
  var req1 = _bodyReq("POST", {}, "");
  req1.body = clientCall.body;
  var res1 = _mkRes();
  var fin1 = _newFinish(res1);
  await mw(req1, res1, function () { res1.json({ ok: true }); });
  await fin1;
  check("first request: 200",                    res1._endedStatus === 200);

  // Replay the same body (same _ek, _ct, _ts, _nonce) → rejected.
  var req2 = _bodyReq("POST", {}, "");
  req2.body = clientCall.body;
  var res2 = _mkRes();
  var fin2 = _newFinish(res2);
  await mw(req2, res2, function () { check("replay should not call next", false); });
  await fin2;
  check("replay: 400",                           res2._endedStatus === 400);
  check("replay uses generic rejection body",    /encrypted-payload-rejected/.test(res2._captured));

  nonceStore.close();
  mw.close();
}

async function testApiEncryptRejectsTamperedCiphertext() {
  var keypair = _serverKeypair();
  var mw = b.middleware.apiEncrypt({ keypair: keypair, audit: false });
  var clientCtx = b.middleware.apiEncrypt.client({ pubkey: keypair });
  var clientCall = clientCtx.encryptRequest({ x: 1 });

  // Flip a byte deep inside the ciphertext.
  var ctBuf = Buffer.from(clientCall.body._ct, "base64");
  ctBuf[ctBuf.length - 5] ^= 0xff;
  clientCall.body._ct = ctBuf.toString("base64");

  var req = _bodyReq("POST", {}, "");
  req.body = clientCall.body;
  var res = _mkRes();
  var fin = _newFinish(res);
  await mw(req, res, function () { check("tampered ct should not reach handler", false); });
  await fin;
  check("tampered ct: 400",                      res._endedStatus === 400);
}

async function testApiEncryptExemptPathBypass() {
  var keypair = _serverKeypair();
  var mw = b.middleware.apiEncrypt({
    keypair:     keypair,
    audit:       false,
    exemptPaths: ["/healthz", "/.well-known"],
  });
  var req = _bodyReq("GET", {}, "");
  req.url = "/healthz";
  req.pathname = "/healthz";
  req.body = undefined;
  var res = _mkRes();
  var fin = _newFinish(res);
  var nextCalled = false;
  await mw(req, res, function () { nextCalled = true; });
  check("exempt path: next called",              nextCalled === true);

  // /.well-known/blamejs-pubkey is also exempt because of the prefix rule.
  var req2 = _bodyReq("GET", {}, "");
  req2.url = "/.well-known/blamejs-pubkey";
  req2.pathname = "/.well-known/blamejs-pubkey";
  var res2 = _mkRes();
  var fin2 = _newFinish(res2);
  var nextCalled2 = false;
  await mw(req2, res2, function () { nextCalled2 = true; });
  check("exempt prefix: next called",            nextCalled2 === true);
}

async function testApiEncryptPublishPublicKey() {
  var keypair = _serverKeypair();
  var mw = b.middleware.apiEncrypt({ keypair: keypair, audit: false });
  var handler = mw.publishPublicKey();
  check("publishPublicKey returns a fn",         typeof handler === "function");

  var req = _bodyReq("GET", {}, "");
  var res = _mkRes();
  var fin = _newFinish(res);
  handler(req, res);
  // res.json is sync in our mock — read what it wrote.
  var body = JSON.parse(res._captured);
  check("published publicKey matches",           body.publicKey === keypair.publicKey);
  check("published ecPublicKey matches",         body.ecPublicKey === keypair.ecPublicKey);
  check("published kemId is hybrid",             body.kemId === b.constants.ACTIVE.KEM);
  check("private keys NOT published",
        !("privateKey" in body) && !("ecPrivateKey" in body));
}

async function testApiEncryptEventOnFailure() {
  var keypair = _serverKeypair();
  var mw = b.middleware.apiEncrypt({ keypair: keypair, audit: false });
  var captured = [];
  var listener = function (info) { captured.push(info); };
  b.events.on(b.events.EVENTS.API_ENCRYPT_FAILURE, listener);
  try {
    var req = _bodyReq("POST", {}, "");
    req.body = { msg: "oops" };
    req.url = "/api/x";
    req.pathname = "/api/x";
    var res = _mkRes();
    var fin = _newFinish(res);
    await mw(req, res, function () {});
    await fin;
    check("event fired on failure",                captured.length === 1);
    check("event payload carries reason",          captured[0].reason === "shape");
    check("event payload carries path",            captured[0].path === "/api/x");
  } finally {
    b.events.off(b.events.EVENTS.API_ENCRYPT_FAILURE, listener);
  }
}

async function testApiEncryptAuditEmit() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-ae-"));
  try {
    await setupTestDb(tmpDir);
    var keypair = _serverKeypair();
    var mw = b.middleware.apiEncrypt({ keypair: keypair, audit: true });

    // Tampered ct → audit emits failure
    var clientCtx = b.middleware.apiEncrypt.client({ pubkey: keypair });
    var call = clientCtx.encryptRequest({ x: 1 });
    var ctBuf = Buffer.from(call.body._ct, "base64");
    ctBuf[ctBuf.length - 1] ^= 0xff;
    call.body._ct = ctBuf.toString("base64");

    var req = _bodyReq("POST", {}, "");
    req.body = call.body;
    req.url = "/api/y";
    req.pathname = "/api/y";
    var res = _mkRes();
    var fin = _newFinish(res);
    await mw(req, res, function () {});
    await fin;

    await b.audit.flush();
    var rows = await b.audit.query({ action: "system.api_encrypt.failure" });
    check("audit row written for failure",         rows.length === 1);
    var meta = typeof rows[0].metadata === "string"
      ? JSON.parse(rows[0].metadata) : rows[0].metadata;
    check("audit metadata carries reason=tag",     meta.reason === "tag");
    check("audit metadata carries path",           meta.path === "/api/y");
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testApiEncryptClientRejectsBadPubkey() {
  var threw = null;
  try { b.middleware.apiEncrypt.client({ pubkey: null }); } catch (e) { threw = e; }
  check("client rejects null pubkey",             threw && threw.code === "CLIENT_INVALID_PUBKEY");
  threw = null;
  try { b.middleware.apiEncrypt.client({ pubkey: { publicKey: "pem" } }); } catch (e) { threw = e; }
  check("client rejects non-hybrid pubkey",       threw && threw.code === "CLIENT_INVALID_PUBKEY");
}

async function testApiEncryptClientRejectsBadResponse() {
  var keypair = _serverKeypair();
  var clientCtx = b.middleware.apiEncrypt.client({ pubkey: keypair });
  var call = clientCtx.encryptRequest({ x: 1 });
  var threw = null;
  try { call.decryptResponse({}); } catch (e) { threw = e; }
  check("client rejects response missing _ct",    threw && threw.code === "CLIENT_RESPONSE_SHAPE");
}

async function run() {
  await testNonceStoreSurface();
  await testNonceStoreMemoryBasics();
  await testNonceStoreMemoryRejectsBadInput();
  await testNonceStoreMemoryPurge();
  await testNonceStoreClusterBasics();
  await testNonceStoreCustomBackend();
  await testNonceStoreUnknownBackend();

  await testApiEncryptKeypairValidated();
  await testApiEncryptRoundTrip();
  await testApiEncryptRejectsMissingShape();
  await testApiEncryptRejectsStaleTimestamp();
  await testApiEncryptRejectsReplay();
  await testApiEncryptRejectsTamperedCiphertext();
  await testApiEncryptExemptPathBypass();
  await testApiEncryptPublishPublicKey();
  await testApiEncryptEventOnFailure();
  await testApiEncryptAuditEmit();
  await testApiEncryptClientRejectsBadPubkey();
  await testApiEncryptClientRejectsBadResponse();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.message); console.error(e.stack); process.exit(1); }
  );
}
