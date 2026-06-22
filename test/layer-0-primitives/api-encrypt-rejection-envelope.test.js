"use strict";
/**
 * api-encrypt — protocol-level rejection bodies must ride the session
 * envelope on an ESTABLISHED per-session encrypted channel (#361).
 *
 * A client on a keyed per-session channel that sends a stale / replayed
 * / malformed request used to get an UNENCRYPTED { error: <code> } back,
 * leaking — in cleartext, over an otherwise-encrypted channel — which
 * validation tripped. The rejection must instead be wrapped exactly like
 * a successful response ({ _ct, _sid, _ctr }), with plaintext reserved
 * for pre-session handshake errors where no session context exists yet.
 *
 * Run standalone:
 *   node test/layer-0-primitives/api-encrypt-rejection-envelope.test.js
 * Or via smoke: node test/smoke.js
 */

var helpers  = require("../helpers");
var b        = helpers.b;
var check    = helpers.check;
var _bodyReq = helpers._bodyReq;
var _bodyRes = helpers._bodyRes;

function _newFinish(res) {
  return new Promise(function (resolve) { res.on("finish", resolve); });
}

function _mkRes() {
  var res = _bodyRes();
  // Mirror the router's res.json convention so the response-encryption
  // wrap chains correctly (the router installs this in production).
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

// On an established per-session channel a replayed subsequent request is
// refused — and that refusal MUST be an encrypted envelope, not a
// plaintext { error }. RED on the current tree (rejection emitted as
// plaintext JSON); GREEN once _writeRejection wraps it in the session
// envelope.
async function testRejectionEncryptedOnEstablishedSession() {
  var keypair = _serverKeypair();
  var mw = b.middleware.apiEncrypt({
    keypair:      keypair,
    audit:        false,
    keying:       "per-session",
    sessionTtlMs: 60_000,
  });
  var clientCtx = b.middleware.apiEncrypt.client({
    pubkey: keypair, keying: "per-session",
  });

  // Bootstrap the session (ctr=1) — establishes the keyed channel.
  var first = clientCtx.encryptRequest({ user: "alice" });
  var req1 = _bodyReq("POST", { "content-type": "application/json" }, "");
  req1.body = first.body;
  var res1 = _mkRes();
  var fin1 = _newFinish(res1);
  await mw(req1, res1, function () { res1.json({ ok: true, n: 1 }); });
  await fin1;
  check("bootstrap returns 200", res1._endedStatus === 200);
  var resp1 = JSON.parse(res1._captured);
  check("bootstrap response is encrypted", typeof resp1._ct === "string");
  first.decryptResponse(resp1);   // advances the client's response counter

  // Valid second request (ctr=2) — server now expects ctr>2.
  var second = clientCtx.encryptRequest({ user: "alice", action: "ping" });
  var req2 = _bodyReq("POST", { "content-type": "application/json" }, "");
  req2.body = second.body;
  var res2 = _mkRes();
  var fin2 = _newFinish(res2);
  await mw(req2, res2, function () { res2.json({ ok: true, n: 2 }); });
  await fin2;
  check("second request returns 200", res2._endedStatus === 200);
  second.decryptResponse(JSON.parse(res2._captured));

  // REPLAY the second request verbatim (same _ctr=2) — refused with the
  // counter-replay shape. This is the leak vector: the rejection rides
  // the established channel and MUST be encrypted.
  var req3 = _bodyReq("POST", { "content-type": "application/json" }, "");
  req3.body = JSON.parse(JSON.stringify(second.body));
  var res3 = _mkRes();
  var fin3 = _newFinish(res3);
  await mw(req3, res3, function () {
    check("replay must NOT reach next()", false);
  });
  await fin3;

  check("replay on established session returns 400", res3._endedStatus === 400);

  var rejBody = JSON.parse(res3._captured);
  // The core assertion: the rejection is an ENCRYPTED envelope, NOT a
  // plaintext { error: ... }. On the buggy tree rejBody.error is the
  // cleartext code and rejBody._ct is absent.
  check("rejection body carries NO plaintext error field",
        rejBody.error === undefined);
  check("rejection body is an encrypted envelope (_ct present)",
        typeof rejBody._ct === "string");
  check("rejection envelope is bound to the session sid",
        rejBody._sid === first.body._sid);
  check("rejection envelope carries a response counter",
        typeof rejBody._ctr === "number");

  // The encrypted rejection must decrypt under the session key to reveal
  // the error code only to the legitimate key-holder.
  var plain = second.decryptResponse(rejBody);
  check("decrypted rejection reveals the error code to the key-holder",
        plain && typeof plain.error === "string" && plain.error.length > 0);
}

// A pre-session handshake error — a bootstrap envelope whose _ek does not
// decrypt — has no session context yet, so the rejection MUST stay
// plaintext (the client cannot derive a session key to read an encrypted
// body it never established).
async function testHandshakeErrorStaysPlaintext() {
  var keypair = _serverKeypair();
  var mw = b.middleware.apiEncrypt({
    keypair: keypair, audit: false, keying: "per-session", sessionTtlMs: 60_000,
  });
  var clientCtx = b.middleware.apiEncrypt.client({
    pubkey: keypair, keying: "per-session",
  });

  // Bootstrap shape, but corrupt _ek so it fails to decrypt to a session
  // key — no session is ever established.
  var first = clientCtx.encryptRequest({ user: "mallory" });
  var req = _bodyReq("POST", { "content-type": "application/json" }, "");
  req.body = JSON.parse(JSON.stringify(first.body));
  req.body._ek = Buffer.from("not-a-valid-envelope").toString("base64");
  var res = _mkRes();
  var fin = _newFinish(res);
  await mw(req, res, function () {
    check("handshake failure must NOT reach next()", false);
  });
  await fin;

  check("handshake error returns 400", res._endedStatus === 400);
  var body = JSON.parse(res._captured);
  check("pre-session handshake error stays PLAINTEXT (has error field)",
        typeof body.error === "string" && body.error.length > 0);
  check("pre-session handshake error is NOT an encrypted envelope",
        body._ct === undefined);
}

// A subsequent-shape request with a sid the server never saw is also a
// pre-session error (no key to encrypt under) — must stay plaintext.
async function testUnknownSidStaysPlaintext() {
  var keypair = _serverKeypair();
  var mw = b.middleware.apiEncrypt({
    keypair: keypair, audit: false, keying: "per-session",
  });
  var req = _bodyReq("POST", { "content-type": "application/json" }, "");
  req.body = {
    _ct:  Buffer.from("nope").toString("base64"),
    _ts:  Date.now(),
    _sid: "12345678-1234-4234-8234-123456789012",
    _ctr: 5,
  };
  var res = _mkRes();
  var fin = _newFinish(res);
  await mw(req, res, function () {
    check("unknown sid must NOT reach next()", false);
  });
  await fin;
  check("unknown-sid returns 401", res._endedStatus === 401);
  var body = JSON.parse(res._captured);
  check("unknown-sid rejection stays plaintext (no session to key under)",
        typeof body.error === "string" && body._ct === undefined);
}

// Per-request mode never establishes a session, so its rejections stay
// plaintext (regression guard: the fix must not encrypt per-request
// errors, which have no session key on req).
async function testPerRequestModeRejectionStaysPlaintext() {
  var keypair = _serverKeypair();
  var mw = b.middleware.apiEncrypt({ keypair: keypair, audit: false });
  var req = _bodyReq("POST", { "content-type": "application/json" }, "");
  req.body = { _ct: "garbage", _ts: Date.now() };   // no _ek/_nonce → shape error
  var res = _mkRes();
  var fin = _newFinish(res);
  await mw(req, res, function () {
    check("per-request shape error must NOT reach next()", false);
  });
  await fin;
  check("per-request rejection returns 400", res._endedStatus === 400);
  var body = JSON.parse(res._captured);
  check("per-request rejection stays plaintext",
        typeof body.error === "string" && body._ct === undefined);
}

async function run() {
  await testRejectionEncryptedOnEstablishedSession();
  await testHandshakeErrorStaysPlaintext();
  await testUnknownSidStaysPlaintext();
  await testPerRequestModeRejectionStaysPlaintext();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.message); console.error(e.stack); process.exit(1); }
  );
}
