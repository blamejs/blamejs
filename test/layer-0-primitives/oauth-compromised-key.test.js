// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.auth.oauth and b.auth.ciba refuse a compromised key: a key anyone can
 * hold the private half of. The compromised key is the P-256 key whose
 * private scalar is 1; the control is a P-256 key derived from a label, and
 * every refusal is paired with the same input under the control key.
 *
 * The OP's JWKS is served from a 127.0.0.1 stand-in and carries both keys,
 * so an ID token, a JARM response and a back-channel logout token signed by
 * the compromised key are refused while the same token signed by the control
 * key verifies. CIBA reaches the same verifier through discovery. Client
 * attestation is refused for a compromised Attester key, a compromised `cnf`
 * instance key, and when a compromised key is offered for signing.
 */

var helpers    = require("../helpers");
var b          = helpers.b;
var check      = helpers.check;
var http       = require("node:http");
var nodeCrypto = require("node:crypto");
var ck         = require("../helpers/compromised-keys");

var BAD   = ck.ecKeyPair("prime256v1", 1n);
var GOOD  = ck.ecKeyPair("prime256v1", ck.labelScalar("prime256v1", "blamejs oauth compromised-key control"));
var GOOD2 = ck.ecKeyPair("prime256v1", ck.labelScalar("prime256v1", "blamejs oauth compromised-key instance"));

var P256_GENERATOR_X = "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY";
var CLIENT_ID = "rp-1";
var AS_ISSUER = "https://as.example.com";

function _jwk(kp, kid) {
  var j = kp.publicKey.export({ format: "jwk" });
  if (kid) j.kid = kid;
  return j;
}

function _b64uJson(o) { return Buffer.from(JSON.stringify(o), "utf8").toString("base64url"); }

function _es256(header, payload, privateKey) {
  var input = _b64uJson(header) + "." + _b64uJson(payload);
  var sig = nodeCrypto.sign("sha256", Buffer.from(input, "ascii"), { key: privateKey, dsaEncoding: "ieee-p1363" });
  return input + "." + sig.toString("base64url");
}

async function _err(fn) {
  try { await fn(); return null; } catch (e) { return e; }
}

function _syncCode(fn) {
  try { fn(); return "NO-THROW"; } catch (e) { return e.code || e.message; }
}

function _startOp() {
  var routes = {};
  var server = http.createServer(function (req, res) {
    var u = new URL(req.url, "http://127.0.0.1");
    var body = routes[u.pathname];
    if (body === undefined) { res.writeHead(404); res.end("{}"); return; }
    var text = JSON.stringify(body);
    res.writeHead(200, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(text) });
    res.end(text);
  });
  return new Promise(function (resolve) {
    server.listen(0, "127.0.0.1", function () {
      var base = "http://127.0.0.1:" + server.address().port;
      routes["/jwks"] = { keys: [_jwk(BAD, "bad"), _jwk(GOOD, "good")] };
      routes["/.well-known/openid-configuration"] = {
        issuer: base, jwks_uri: base + "/jwks", token_endpoint: base + "/token",
        authorization_endpoint: base + "/auth",
      };
      resolve({ server: server, base: base });
    });
  });
}

function _client(base) {
  return b.auth.oauth.create({
    issuer:             base,
    clientId:           CLIENT_ID,
    clientSecret:       "sec",
    redirectUri:        "https://rp.example/cb",
    isOidc:             true,
    allowHttp:          true,
    allowInternal:      true,
    jwksUri:            base + "/jwks",
    acceptedAlgorithms: ["ES256"],
  });
}

function _nowSec() { return Math.floor(Date.now() / 1000); }

function testFixtureIsTheScalarOneKey() {
  check("oauth compromised key: the fixture public key is the P-256 generator",
        BAD.publicKey.export({ format: "jwk" }).x === P256_GENERATOR_X);
  check("oauth compromised key control: the control public key is not the generator",
        GOOD.publicKey.export({ format: "jwk" }).x !== P256_GENERATOR_X);
}

async function testIdTokenJarmAndLogoutRefuseCompromisedJwksKey(base) {
  var client = _client(base);
  function idToken(kp, kid) {
    var now = _nowSec();
    return _es256({ alg: "ES256", kid: kid }, { iss: base, aud: CLIENT_ID, sub: "admin", iat: now, exp: now + 300 },
      kp.privateKey);
  }
  check("oauth compromised key control: an ID token under the control JWKS key verifies",
        (await _err(function () { return client.verifyIdToken(idToken(GOOD, "good")); })) === null);
  var e = await _err(function () { return client.verifyIdToken(idToken(BAD, "bad")); });
  check("oauth compromised key: an ID token under a compromised JWKS key is refused",
        e !== null && e.code === "auth-oauth/compromised-key", e && e.code);

  function jarm(kp, kid) {
    var now = _nowSec();
    return _es256({ alg: "ES256", kid: kid },
      { iss: base, aud: CLIENT_ID, exp: now + 300, iat: now, code: "c-1", state: "s-1" }, kp.privateKey);
  }
  check("oauth compromised key control: a JARM response under the control key parses",
        (await _err(function () { return client.parseJarmResponse(jarm(GOOD, "good"), { expectedState: "s-1" }); })) === null);
  e = await _err(function () { return client.parseJarmResponse(jarm(BAD, "bad"), { expectedState: "s-1" }); });
  check("oauth compromised key: a JARM response under a compromised key is refused",
        e !== null && e.code === "auth-oauth/compromised-key", e && e.code);

  function logout(kp, kid) {
    return _es256({ alg: "ES256", kid: kid, typ: "logout+jwt" }, {
      iss: base, aud: CLIENT_ID, iat: _nowSec(), jti: nodeCrypto.randomUUID(), sub: "victim",
      events: { "http://schemas.openid.net/event/backchannel-logout": {} },
    }, kp.privateKey);
  }
  check("oauth compromised key control: a back-channel logout token under the control key verifies",
        (await _err(function () { return client.verifyBackchannelLogoutToken(logout(GOOD, "good")); })) === null);
  e = await _err(function () { return client.verifyBackchannelLogoutToken(logout(BAD, "bad")); });
  check("oauth compromised key: a back-channel logout token under a compromised key is refused",
        e !== null && e.code === "auth-oauth/compromised-key", e && e.code);
}

async function testCibaRefusesCompromisedIdToken(base) {
  var notificationToken = "n".repeat(40);
  var ciba = b.auth.ciba.client.create({
    issuer: base, clientId: CLIENT_ID, clientSecret: "sec", deliveryMode: "push",
    clientNotificationToken: notificationToken, allowHttp: true, allowInternal: true,
  });
  function push(kp, kid) {
    var now = _nowSec();
    var idt = _es256({ alg: "ES256", kid: kid }, {
      iss: base, aud: CLIENT_ID, sub: "victim", iat: now, exp: now + 300,
      "urn:openid:params:jwt:claim:auth_req_id": "req-1",
    }, kp.privateKey);
    return ciba.parseNotification({ headers: { authorization: "Bearer " + notificationToken } },
      { body: { auth_req_id: "req-1", access_token: "at", id_token: idt } });
  }
  var ok = null;
  try { ok = await push(GOOD, "good"); } catch (_e) { ok = null; }
  check("ciba compromised key control: a pushed id_token under the control key yields claims",
        ok !== null && ok.claims && ok.claims.claims.sub === "victim");
  var e = await _err(function () { return push(BAD, "bad"); });
  check("ciba compromised key: a pushed id_token under a compromised key is refused",
        e !== null && e.code === "auth-ciba/id-token-invalid" &&
          String(e.message).indexOf("auth-oauth/compromised-key") !== -1, e && (e.code + " " + e.message));
}

function _attestation(attesterKp, instanceKp) {
  var now = _nowSec();
  return _es256({ typ: "oauth-client-attestation+jwt", alg: "ES256" },
    { sub: "victim-client", iat: now, exp: now + 300, cnf: { jwk: _jwk(instanceKp) } }, attesterKp.privateKey);
}

function _pop(instanceKp) {
  return _es256({ typ: "oauth-client-attestation-pop+jwt", alg: "ES256" },
    { aud: AS_ISSUER, jti: nodeCrypto.randomUUID(), iat: _nowSec() }, instanceKp.privateKey);
}

async function testVerifyClientAttestationRefusesCompromisedKeys() {
  function verify(attesterKp, instanceKp) {
    return b.auth.oauth.verifyClientAttestation(_attestation(attesterKp, instanceKp), _pop(instanceKp), {
      attesterJwk: _jwk(attesterKp), expectedAudience: AS_ISSUER, expectedClientId: "victim-client",
    });
  }
  check("oauth attestation compromised key control: an attestation under control keys verifies",
        (await _err(function () { return verify(GOOD, GOOD2); })) === null);
  var e = await _err(function () { return verify(BAD, GOOD2); });
  check("oauth attestation compromised key: a compromised trusted Attester key is refused",
        e !== null && e.code === "auth-oauth/compromised-key", e && e.code);
  e = await _err(function () { return verify(GOOD, BAD); });
  check("oauth attestation compromised key: a compromised cnf instance key is refused",
        e !== null && e.code === "auth-oauth/compromised-key", e && e.code);
}

function testBuildClientAttestationRefusesCompromisedKeys() {
  function build(attesterKp, instanceKp) {
    return function () {
      b.auth.oauth.buildClientAttestation({
        clientId: "c", attesterPrivateKey: attesterKp.privateKey, instanceKeyJwk: _jwk(instanceKp),
      });
    };
  }
  check("oauth attestation compromised key control: buildClientAttestation signs with control keys",
        _syncCode(build(GOOD, GOOD2)) === "NO-THROW");
  check("oauth attestation compromised key: buildClientAttestation refuses a compromised Attester signing key",
        _syncCode(build(BAD, GOOD2)) === "auth-oauth/compromised-key");
  check("oauth attestation compromised key: buildClientAttestation refuses binding a compromised instance key",
        _syncCode(build(GOOD, BAD)) === "auth-oauth/compromised-key");

  function pop(kp) {
    return function () {
      b.auth.oauth.buildClientAttestationPop({ instancePrivateKey: kp.privateKey, audience: AS_ISSUER });
    };
  }
  check("oauth attestation compromised key control: buildClientAttestationPop signs with the control key",
        _syncCode(pop(GOOD2)) === "NO-THROW");
  check("oauth attestation compromised key: buildClientAttestationPop refuses a compromised instance key",
        _syncCode(pop(BAD)) === "auth-oauth/compromised-key");
}

async function run() {
  testFixtureIsTheScalarOneKey();
  var op = await _startOp();
  try {
    await testIdTokenJarmAndLogoutRefuseCompromisedJwksKey(op.base);
    await testCibaRefusesCompromisedIdToken(op.base);
  } finally {
    await new Promise(function (r) { op.server.close(r); });
  }
  await testVerifyClientAttestationRefusesCompromisedKeys();
  testBuildClientAttestationRefusesCompromisedKeys();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
