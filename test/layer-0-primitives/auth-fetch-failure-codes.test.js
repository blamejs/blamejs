// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The fetch-failure codes the auth primitives document are the codes a failed
 * fetch raises through the real b.httpClient.request:
 *
 * - b.auth.openidFederation.buildTrustChain's default fetcher raises
 *   `auth-openid-federation/fetch-failed` for a reply outside 2xx.
 * - b.auth.jwt.verifyExternal raises `auth-jwt-external/jwks-fetch-failed`
 *   for a `jwksUri` reply outside 2xx.
 * - b.auth.oauth verifyIdToken raises the b.httpClient.request code for a
 *   JWKS reply outside 2xx, and the oauth discovery codes for a discovery
 *   document it refuses.
 *
 * Each request goes to a loopback server through the real httpClient: the
 * test rewrites only the URL, `allowInternal` and `allowedProtocols`, so the
 * status handling is the shipped one. Every refusal has a control whose server
 * answers 200.
 */

var nodeHttp   = require("node:http");
var nodeCrypto = require("node:crypto");
var helpers    = require("../helpers");
var b          = helpers.b;
var check      = helpers.check;
var C          = require("../../lib/constants");
var httpClient = require("../../lib/http-client");

function _b64u(s) { return Buffer.from(s, "utf8").toString("base64url"); }

function _server(route) {
  return new Promise(function (resolve) {
    var server = nodeHttp.createServer(function (req, res) {
      var out = route(req.url);
      res.writeHead(out.status, { "Content-Type": out.type || "application/json" });
      res.end(out.body);
    });
    server.listen(0, "127.0.0.1", function () {
      resolve({ server: server, base: "http://127.0.0.1:" + server.address().port });
    });
  });
}

async function _withLoopback(route, fn) {
  var s = await _server(route);
  var real = httpClient.request;
  httpClient.request = function (opts) {
    var u = new URL(opts.url);
    return real.call(httpClient, Object.assign({}, opts, {
      url: s.base + u.pathname + u.search, allowInternal: true, allowedProtocols: ["http:", "https:"],
    }));
  };
  try { return await fn(s.base); }
  finally {
    httpClient.request = real;
    await new Promise(function (r) { s.server.close(r); });
  }
}

async function _code(fn) {
  try { await fn(); return "NO-THROW"; }
  catch (e) { return (e && e.code) || ("uncoded: " + (e && e.message)); }
}

async function testFederationDefaultFetcherNon2xxIsFetchFailed() {
  var anchors = { "https://anchor.example": { keys: [] } };
  var control = await _withLoopback(function () { return { status: 200, body: "" }; }, function () {
    return _code(function () {
      return b.auth.openidFederation.buildTrustChain({ leafEntityId: "https://leaf.example", trustAnchors: anchors });
    });
  });
  check("federation fetch control: a 200 reply with an empty body reaches the empty-response check",
        control === "auth-openid-federation/empty-response", control);
  var bad = await _withLoopback(function () { return { status: 500, body: "boom" }; }, function () {
    return _code(function () {
      return b.auth.openidFederation.buildTrustChain({ leafEntityId: "https://leaf.example", trustAnchors: anchors });
    });
  });
  check("federation fetch: the default fetcher raises auth-openid-federation/fetch-failed for a 500 reply",
        bad === "auth-openid-federation/fetch-failed", bad);
}

async function testJwksUriNon2xxIsJwksFetchFailed() {
  var pair = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var jwk = Object.assign(pair.publicKey.export({ format: "jwk" }), { kid: "k1", alg: "ES256" });
  var nowSec = Math.floor(Date.now() / C.TIME.seconds(1));
  var input = _b64u(JSON.stringify({ alg: "ES256", kid: "k1" })) + "." + _b64u(JSON.stringify({ sub: "u1", exp: nowSec + 300 }));
  var token = input + "." + nodeCrypto.sign("sha256", Buffer.from(input, "ascii"),
    { key: pair.privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url");
  var control = await _withLoopback(function () { return { status: 200, body: JSON.stringify({ keys: [jwk] }) }; }, function () {
    return _code(function () {
      return b.auth.jwt.verifyExternal(token, { algorithms: ["ES256"], jwksUri: "https://idp.example/jwks-ok", jwksCacheMs: 0 });
    });
  });
  check("jwksUri fetch control: a 200 JWKS verifies the token", control === "NO-THROW", control);
  var bad = await _withLoopback(function () { return { status: 503, body: "down" }; }, function () {
    return _code(function () {
      return b.auth.jwt.verifyExternal(token, { algorithms: ["ES256"], jwksUri: "https://idp.example/jwks-down", jwksCacheMs: 0 });
    });
  });
  check("jwksUri fetch: a 503 JWKS reply raises auth-jwt-external/jwks-fetch-failed",
        bad === "auth-jwt-external/jwks-fetch-failed", bad);
}

async function testVerifyIdTokenFetchCodes() {
  var token = _b64u(JSON.stringify({ alg: "ES256", kid: "k" })) + "." + _b64u(JSON.stringify({ iss: "x" })) + ".AAAA";
  async function run(mode) {
    var s = await _server(function (url) {
      if (url === "/.well-known/openid-configuration") {
        if (mode === "null-discovery") return { status: 200, body: "null" };
        var jwksUri = s.base + "/jwks";
        if (mode === "no-jwks") jwksUri = undefined;
        if (mode === "ftp-jwks") jwksUri = "ftp://jwks.example/keys";
        if (mode === "bad-jwks-url") jwksUri = "::not a url";
        return { status: 200, body: JSON.stringify({
          issuer: mode === "issuer" ? "https://elsewhere.example" : s.base,
          jwks_uri: jwksUri,
          authorization_endpoint: s.base + "/a", token_endpoint: s.base + "/t",
        }) };
      }
      if (url === "/jwks") {
        if (mode === "500") return { status: 500, body: "{}" };
        if (mode === "json") return { status: 200, body: "not json", type: "text/plain" };
        return { status: 200, body: JSON.stringify({ keys: [] }) };
      }
      return { status: 404, body: "{}" };
    });
    try {
      var client = b.auth.oauth.create({ issuer: s.base, clientId: "c", clientSecret: "s",
        redirectUri: "https://rp.example/cb", isOidc: true, allowHttp: true, allowInternal: true,
        acceptedAlgorithms: ["ES256"] });
      return await _code(function () { return client.verifyIdToken(token); });
    } finally {
      await new Promise(function (r) { s.server.close(r); });
    }
  }
  var control = await run("ok");
  check("verifyIdToken fetch control: a reachable OP with an empty JWKS refuses the token as no-matching-key",
        control === "auth-oauth/no-matching-key", control);
  var expect = { "500": "http-client/http-error", "json": "auth-oauth/bad-json",
    "issuer": "auth-oauth/issuer-mismatch", "no-jwks": "auth-oauth/no-endpoint",
    "null-discovery": "auth-oauth/bad-discovery", "ftp-jwks": "auth-oauth/insecure-url",
    "bad-jwks-url": "auth-oauth/bad-url" };
  var modes = Object.keys(expect);
  for (var i = 0; i < modes.length; i += 1) {
    var got = await run(modes[i]);
    check("verifyIdToken fetch: mode " + modes[i] + " raises " + expect[modes[i]], got === expect[modes[i]], got);
  }
}

async function run() {
  await testFederationDefaultFetcherNon2xxIsFetchFailed();
  await testJwksUriNon2xxIsJwksFetchFailed();
  await testVerifyIdTokenFetchCodes();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
