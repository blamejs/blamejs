// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Every signer that writes an algorithm identifier into its output (a JWS
 * `alg`, a DKIM / ARC `a=`, a SAML `SigAlg`, a GCS `X-Goog-Algorithm`, an MCP
 * `alg`, a webhook scheme, an audit-sign key file's `algorithm`) refuses a
 * key whose type does not match that identifier.
 *
 * node:crypto sign() runs whatever algorithm the key carries: an RSA key
 * under `createSign("RSA-SHA256")` with an EC key yields ECDSA, and
 * `sign(null, ...)` with an ML-DSA key yields ML-DSA. Without the check the
 * output named one algorithm and carried a signature made with another.
 */

var fs         = require("node:fs");
var os         = require("node:os");
var path       = require("node:path");
var nodeCrypto = require("node:crypto");
var helpers    = require("../helpers");
var b          = helpers.b;
var check      = helpers.check;
var gcs        = require("../../lib/object-store/gcs");
var gcsBucketOps = require("../../lib/object-store/gcs-bucket-ops");
var canonicalJson = require("../../lib/canonical-json");

var PEM = { publicKeyEncoding: { type: "spki", format: "pem" },
            privateKeyEncoding: { type: "pkcs8", format: "pem" } };

function _pair(type, extra) {
  return nodeCrypto.generateKeyPairSync(type, Object.assign({}, extra || {}, PEM));
}

async function _codeOf(fn) {
  try { await fn(); return "no-throw"; }
  catch (e) { return e && e.code ? e.code : "untyped:" + ((e && e.message) || String(e)).slice(0, 80); }
}

var KEYS = {};
function _keys() {
  if (KEYS.rsa) return KEYS;
  KEYS.p256 = _pair("ec", { namedCurve: "P-256" });
  KEYS.p384 = _pair("ec", { namedCurve: "P-384" });
  KEYS.rsa  = _pair("rsa", { modulusLength: 2048 });
  KEYS.ed   = _pair("ed25519");
  KEYS.d44  = _pair("ml-dsa-44");
  KEYS.d65  = _pair("ml-dsa-65");
  KEYS.d87  = _pair("ml-dsa-87");
  return KEYS;
}

var CRED = {
  "@context": ["https://www.w3.org/ns/credentials/v2"],
  type: ["VerifiableCredential"],
  issuer: "https://issuer.example",
  credentialSubject: { id: "did:example:1" },
  validFrom: "2026-01-01T00:00:00Z",
};

async function testVcJoseIssue() {
  var k = _keys();
  var c1 = await _codeOf(function () {
    return b.vc.issue(CRED, { securing: "jose", alg: "ES256", privateKey: k.p384.privateKey });
  });
  check("vc.issue JOSE ES256 refuses a P-384 key", c1 === "vc/alg-key-mismatch", c1);
  var c2 = await _codeOf(function () {
    return b.vc.issue(CRED, { securing: "jose", alg: "EdDSA", privateKey: k.d65.privateKey });
  });
  check("vc.issue JOSE EdDSA refuses an ML-DSA-65 key", c2 === "vc/alg-key-mismatch", c2);
  var jws = await b.vc.issue(CRED, { securing: "jose", alg: "ES384", privateKey: k.p384.privateKey });
  check("vc.issue JOSE ES384 with a P-384 key still signs", typeof jws === "string" && jws.split(".").length === 3);
}

async function testSdJwtVcIssue() {
  var k = _keys();
  var base = { issuer: "https://issuer.example", subject: "s", vct: "https://vct.example", claims: { a: 1 } };
  var c1 = await _codeOf(function () {
    return b.auth.sdJwtVc.issue(Object.assign({}, base, { issuerKey: k.d65.privateKey, algorithm: "ML-DSA-87" }));
  });
  check("sdJwtVc.issue ML-DSA-87 refuses an ML-DSA-65 key", c1 === "auth-sd-jwt-vc/alg-key-mismatch", c1);
  var derived = b.auth.sdJwtVc.issue(Object.assign({}, base, { issuerKey: k.d65.privateKey }));
  check("sdJwtVc.issue without an algorithm labels an ML-DSA-65 key ML-DSA-65", derived.header.alg === "ML-DSA-65");
  var derivedEc = b.auth.sdJwtVc.issue(Object.assign({}, base, { issuerKey: k.p256.privateKey }));
  check("sdJwtVc.issue without an algorithm labels a P-256 key ES256", derivedEc.header.alg === "ES256");
  var c2 = await _codeOf(function () {
    return b.auth.sdJwtVc.issue(Object.assign({}, base, { issuerKey: k.p384.privateKey, algorithm: "ES256" }));
  });
  check("sdJwtVc.issue ES256 refuses a P-384 key", c2 === "auth-sd-jwt-vc/alg-key-mismatch", c2);
  var ok = b.auth.sdJwtVc.issue(Object.assign({}, base, { issuerKey: k.d87.privateKey }));
  check("sdJwtVc.issue default ML-DSA-87 with an ML-DSA-87 key still signs", typeof ok.token === "string");
  var c3 = await _codeOf(function () {
    var holderJwk = nodeCrypto.createPublicKey(k.p256.publicKey).export({ format: "jwk" });
    var issued = b.auth.sdJwtVc.issue(Object.assign({}, base, {
      issuerKey: k.d87.privateKey, holderKey: holderJwk, selectivelyDisclosed: ["a"],
    }));
    return b.auth.sdJwtVc.present({
      sdJwt: issued.token, disclosedClaimNames: ["a"], audience: "https://v.example", nonce: "n",
      holderKey: k.rsa.privateKey, algorithm: "ES256",
    });
  });
  check("sdJwtVc.present ES256 refuses an RSA holder key", c3 === "auth-sd-jwt-vc/alg-key-mismatch", c3);
  var p521 = _pair("ec", { namedCurve: "P-521" });
  var unmapped = [["a P-521 key", p521.privateKey], ["an ML-DSA-44 key", k.d44.privateKey],
                  ["an RSA key", k.rsa.privateKey], ["a value that is not a key", "not a key"]];
  for (var i = 0; i < unmapped.length; i += 1) {
    var row = unmapped[i];
    var c4 = await _codeOf(function () {
      return b.auth.sdJwtVc.issue(Object.assign({}, base, { issuerKey: row[1] }));
    });
    check("sdJwtVc.issue without an algorithm refuses " + row[0] + " as an unsupported key",
      c4 === "auth-sd-jwt-vc/unsupported-key", c4);
    var c5 = await _codeOf(function () {
      var issuedFor = b.auth.sdJwtVc.issue(Object.assign({}, base, {
        issuerKey: k.d87.privateKey,
        holderKey: nodeCrypto.createPublicKey(k.p256.publicKey).export({ format: "jwk" }),
        selectivelyDisclosed: ["a"],
      }));
      return b.auth.sdJwtVc.present({
        sdJwt: issuedFor.token, disclosedClaimNames: ["a"], audience: "https://v.example", nonce: "n",
        holderKey: row[1],
      });
    });
    check("sdJwtVc.present without an algorithm refuses " + row[0] + " as an unsupported key",
      c5 === "auth-sd-jwt-vc/unsupported-key", c5);
  }
  var cryptoKey = nodeCrypto.createPrivateKey(k.p256.privateKey)
    .toCryptoKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]);
  var fromCryptoKey = b.auth.sdJwtVc.issue(Object.assign({}, base, { issuerKey: cryptoKey, algorithm: "ES256" }));
  check("sdJwtVc.issue ES256 signs with a P-256 WebCrypto CryptoKey",
    typeof fromCryptoKey.token === "string" && fromCryptoKey.header.alg === "ES256");
  var derivedFromCryptoKey = b.auth.sdJwtVc.issue(Object.assign({}, base, { issuerKey: cryptoKey }));
  check("sdJwtVc.issue without an algorithm labels a P-256 CryptoKey ES256", derivedFromCryptoKey.header.alg === "ES256");
  var cryptoKey384 = nodeCrypto.createPrivateKey(k.p384.privateKey)
    .toCryptoKey({ name: "ECDSA", namedCurve: "P-384" }, true, ["sign"]);
  var c6 = await _codeOf(function () {
    return b.auth.sdJwtVc.issue(Object.assign({}, base, { issuerKey: cryptoKey384, algorithm: "ES256" }));
  });
  check("sdJwtVc.issue ES256 refuses a P-384 WebCrypto CryptoKey", c6 === "auth-sd-jwt-vc/alg-key-mismatch", c6);
}

async function testDpopBuildProof() {
  var k = _keys();
  var base = { htm: "GET", htu: "https://api.example/x" };
  var rows = [
    ["ES256", k.rsa.privateKey, "an RSA key"],
    ["ES256", k.p384.privateKey, "a P-384 key"],
    ["ML-DSA-87", k.d44.privateKey, "an ML-DSA-44 key"],
    ["EdDSA", k.d44.privateKey, "an ML-DSA-44 key"],
    ["RS256", k.p256.privateKey, "a P-256 key"],
  ];
  for (var i = 0; i < rows.length; i += 1) {
    var row = rows[i];
    var code = await _codeOf(function () {
      return b.auth.dpop.buildProof(Object.assign({}, base, { privateKey: row[1], algorithm: row[0] }));
    });
    check("dpop.buildProof " + row[0] + " refuses " + row[2], code === "auth-dpop/alg-key-mismatch", code);
  }
  var proof = await b.auth.dpop.buildProof(Object.assign({}, base, { privateKey: k.p256.privateKey, algorithm: "ES256" }));
  check("dpop.buildProof ES256 with a P-256 key still signs", typeof proof === "string");

  function _jwkOf(pem) { return nodeCrypto.createPublicKey(pem).export({ format: "jwk" }); }
  var otherP256 = _pair("ec", { namedCurve: "P-256" });
  var jwkRows = [
    ["the public JWK of a different P-256 key", k.p256.privateKey, "ES256", _jwkOf(otherP256.publicKey)],
    ["a P-384 JWK for a P-256 key", k.p256.privateKey, "ES256", _jwkOf(k.p384.publicKey)],
    ["an RSA JWK for a P-256 key", k.p256.privateKey, "ES256", _jwkOf(k.rsa.publicKey)],
    ["an Ed25519 JWK for an ML-DSA-87 key", k.d87.privateKey, "ML-DSA-87", _jwkOf(k.ed.publicKey)],
    ["the public JWK of a different ML-DSA-87 key", k.d87.privateKey, "ML-DSA-87", _jwkOf(_pair("ml-dsa-87").publicKey)],
  ];
  for (var j = 0; j < jwkRows.length; j += 1) {
    var jr = jwkRows[j];
    var jcode = await _codeOf(function () {
      return b.auth.dpop.buildProof(Object.assign({}, base, { privateKey: jr[1], algorithm: jr[2], jwk: jr[3] }));
    });
    check("dpop.buildProof refuses " + jr[0], jcode === "auth-dpop/jwk-key-mismatch", jcode);
  }
  var bogus = await _codeOf(function () {
    return b.auth.dpop.buildProof(Object.assign({}, base, { privateKey: k.p256.privateKey, jwk: { kty: "EC", crv: "P-256" } }));
  });
  check("dpop.buildProof refuses a JWK that cannot be imported", bogus === "auth-dpop/bad-jwk", bogus);
  var withJwk = await b.auth.dpop.buildProof(Object.assign({}, base, {
    privateKey: k.p256.privateKey, algorithm: "ES256", jwk: _jwkOf(k.p256.publicKey),
  }));
  var headerWithJwk = JSON.parse(Buffer.from(withJwk.split(".")[0], "base64url").toString("utf8"));
  check("dpop.buildProof with the matching public JWK still signs",
    headerWithJwk.jwk.x === _jwkOf(k.p256.publicKey).x);
  var withPqcJwk = await b.auth.dpop.buildProof(Object.assign({}, base, {
    privateKey: k.d87.privateKey, algorithm: "ML-DSA-87", jwk: _jwkOf(k.d87.publicKey),
  }));
  check("dpop.buildProof with the matching ML-DSA-87 public JWK still signs", typeof withPqcJwk === "string");
}

async function testProtectedResourceMetadata() {
  var k = _keys();
  var base = { resource: "https://api.example.com", authorizationServers: ["https://idp.example.com"] };
  var rows = [["ES256", k.p384.privateKey, "a P-384 key"], ["ES256", k.rsa.privateKey, "an RSA key"],
              ["PS256", k.p256.privateKey, "a P-256 key"]];
  for (var i = 0; i < rows.length; i += 1) {
    var row = rows[i];
    var code = await _codeOf(function () {
      return b.middleware.protectedResourceMetadata(Object.assign({}, base, {
        signMetadata: { key: row[1], alg: row[0] },
      }));
    });
    check("protectedResourceMetadata signMetadata " + row[0] + " refuses " + row[2],
      code === "middleware/protected-resource-metadata/bad-sign-key", code);
  }
  var mw = b.middleware.protectedResourceMetadata(Object.assign({}, base, {
    signMetadata: { key: k.p384.privateKey, alg: "ES384" },
  }));
  check("protectedResourceMetadata ES384 with a P-384 key still signs", typeof mw.signedMetadata === "string");
}

var MSG = "From: a@x.example\r\nTo: b@y.example\r\nSubject: s\r\n" +
          "Date: Wed, 06 May 2026 12:00:00 +0000\r\nMessage-ID: <m@x.example>\r\n\r\nbody\r\n";

async function testArcSign() {
  var k = _keys();
  var base = { rfc822: MSG, instance: 1, authservId: "x.example", domain: "x.example",
               selector: "s", cv: "none", authResults: "spf=pass" };
  var c1 = await _codeOf(function () {
    return b.mail.arc.sign(Object.assign({}, base, { privateKey: k.p256.privateKey, algorithm: "rsa-sha256" }));
  });
  check("arc.sign rsa-sha256 refuses a P-256 key", c1 === "arc-sign/key-algorithm-mismatch", c1);
  var c2 = await _codeOf(function () {
    return b.mail.arc.sign(Object.assign({}, base, { privateKey: k.d65.privateKey, algorithm: "ed25519-sha256" }));
  });
  check("arc.sign ed25519-sha256 refuses an ML-DSA-65 key", c2 === "arc-sign/key-algorithm-mismatch", c2);
  var hop = b.mail.arc.sign(Object.assign({}, base, { privateKey: k.ed.privateKey, algorithm: "ed25519-sha256" }));
  check("arc.sign ed25519-sha256 with an Ed25519 key still seals", /a=ed25519-sha256/.test(hop.as));
}

async function testDkimKeyObjectShapes() {
  var k = _keys();
  var code = await _codeOf(function () {
    return b.mail.dkim.create({ domain: "x.example", selector: "s", algorithm: "rsa-sha256",
      privateKey: { key: k.p256.privateKey } }).sign(MSG);
  });
  check("dkim rsa-sha256 refuses a P-256 key given as { key: pem }", code === "dkim/key-algorithm-mismatch", code);
  var signed = await b.mail.dkim.create({ domain: "x.example", selector: "s", algorithm: "rsa-sha256",
    privateKey: { key: k.rsa.privateKey } }).sign(MSG);
  check("dkim rsa-sha256 with an RSA key given as { key: pem } still signs", /a=rsa-sha256/.test(String(signed)));
}

function _sp() {
  return b.auth.saml.sp.create({
    entityId:                    "https://sp.example/saml",
    assertionConsumerServiceUrl: "https://sp.example/acs",
    idpEntityId:                 "https://idp.example/saml",
    idpSsoUrl:                   "https://idp.example/sso",
    idpSloUrl:                   "https://idp.example/slo",
    idpCertPem:                  "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----",
  });
}

async function testSamlSigning() {
  var k = _keys();
  var sp = _sp();
  var rows = [
    ["rsa-sha256", k.p256.privateKey, "a P-256 key"],
    ["ecdsa-sha256", k.rsa.privateKey, "an RSA key"],
    ["ed25519", nodeCrypto.createPrivateKey(k.d65.privateKey), "an ML-DSA-65 KeyObject"],
    ["ed25519", k.p256.privateKey, "a P-256 PEM"],
  ];
  for (var i = 0; i < rows.length; i += 1) {
    var row = rows[i];
    var code = await _codeOf(function () {
      return sp.buildLogoutRequest({ nameId: "a", sessionIndex: "_s", signingKey: row[1], signingAlg: row[0] });
    });
    check("saml buildLogoutRequest " + row[0] + " refuses " + row[2], code === "auth-saml/bad-signing-key", code);
  }
  var builders = [
    ["buildLogoutRequestPost", function (key, alg) {
      return sp.buildLogoutRequestPost({ nameId: "a", sessionIndex: "_s", signingKey: key, signingAlg: alg });
    }],
    ["buildLogoutRequestSoap", function (key, alg) {
      return sp.buildLogoutRequestSoap({ nameId: "a", sessionIndex: "_s", signingKey: key, signingAlg: alg });
    }],
    ["buildLogoutResponse", function (key, alg) {
      return sp.buildLogoutResponse({ inResponseTo: "_r1", destination: "https://idp.example/slo",
        signingKey: key, signingAlg: alg });
    }],
  ];
  for (var bi = 0; bi < builders.length; bi += 1) {
    var builder = builders[bi];
    var bcode = await _codeOf(function () { return builder[1](k.p256.privateKey, "ed25519"); });
    check("saml " + builder[0] + " ed25519 refuses a P-256 key", bcode === "auth-saml/bad-signing-key", bcode);
    var built = await _codeOf(function () { return builder[1](k.ed.privateKey, "ed25519"); });
    check("saml " + builder[0] + " ed25519 with an Ed25519 key still signs", built === "no-throw", built);
  }
  var lr = sp.buildLogoutRequest({ nameId: "a", sessionIndex: "_s", signingKey: k.p256.privateKey, signingAlg: "ecdsa-sha256" });
  check("saml buildLogoutRequest ecdsa-sha256 with a P-256 key still signs", lr.redirectUrl.indexOf("&Signature=") !== -1);
}

async function testGcsServiceAccountKey() {
  var k = _keys();
  var code = await _codeOf(function () {
    return gcs.create({ bucket: "mybucket",
      serviceAccount: { client_email: "sa@p.iam.gserviceaccount.com", private_key: k.p256.privateKey } });
  });
  check("gcs refuses a service-account key that is not RSA", code === "objectstore/gcs-bad-key", code);
  var opsCode = await _codeOf(function () {
    return gcsBucketOps.create({ projectId: "p", endpoint: "https://storage.example",
      serviceAccount: { client_email: "sa@p.iam.gserviceaccount.com", private_key: k.p256.privateKey } });
  });
  check("gcs bucketOps refuses a service-account key that is not RSA", opsCode === "objectstore/gcs-bad-key", opsCode);
  var store = gcs.create({ bucket: "mybucket",
    serviceAccount: { client_email: "sa@p.iam.gserviceaccount.com", private_key: k.rsa.privateKey } });
  var url = store.presignedDownloadUrl({ key: "a.txt", expiresIn: 60 });
  check("gcs with an RSA key still presigns", /X-Goog-Algorithm=GOOG4-RSA-SHA256/.test(String(url.url || url)));
}

async function testMcpToolRegistry() {
  var k = _keys();
  var tools = [{ name: "search", inputSchema: { type: "object" } }];
  var c1 = await _codeOf(function () { return b.mcp.toolRegistry.create({ tools: tools, signingKey: k.ed.privateKey }); });
  check("mcp toolRegistry default ml-dsa-87 refuses an Ed25519 signingKey", c1 === "mcp/bad-signing-key", c1);
  var c2 = await _codeOf(function () {
    return b.mcp.toolRegistry.create({ tools: tools, signingKey: k.p256.privateKey, alg: "es384" });
  });
  check("mcp toolRegistry es384 refuses a P-256 signingKey", c2 === "mcp/bad-signing-key", c2);
  var c3 = await _codeOf(function () {
    return b.mcp.toolRegistry.create({ tools: tools, signingKey: k.d87.privateKey, verifyingKey: k.ed.publicKey });
  });
  check("mcp toolRegistry ml-dsa-87 refuses an Ed25519 verifyingKey", c3 === "mcp/bad-verifying-key", c3);
  var r = b.mcp.toolRegistry.create({ tools: tools, signingKey: k.p256.privateKey, alg: "es256", verifyingKey: k.p256.publicKey });
  var signed = r.signCall({ toolName: "search", args: {} });
  check("mcp toolRegistry es256 with P-256 keys still signs and verifies",
    signed.alg === "es256" && r.verifyCall(signed, { seen: function () { return false; } }) !== false);
  var r384 = b.mcp.toolRegistry.create({ tools: tools, signingKey: k.p384.privateKey, alg: "es384", verifyingKey: k.p384.publicKey });
  var s384 = r384.signCall({ toolName: "search", args: {} });
  var bytes = Buffer.from(canonicalJson.stringify(s384.envelope), "utf8");
  check("mcp toolRegistry es384 signs with SHA-384, the digest its label names",
    nodeCrypto.verify("sha384", bytes, k.p384.publicKey, Buffer.from(s384.signature, "base64")) === true);
  check("mcp toolRegistry es384 verifies its own signature",
    r384.verifyCall(s384, { seen: function () { return false; } }) !== false);
}

async function testWebhookPqcPem() {
  var k = _keys();
  var c1 = await _codeOf(function () {
    return b.webhook.signer({ algo: "pqc-pem", keys: { v1: { privateKey: k.ed.privateKey, publicKey: k.ed.publicKey } } });
  });
  check("webhook signer pqc-pem refuses an Ed25519 key", c1 === "webhook/bad-opt", c1);
  var c2 = await _codeOf(function () { return b.webhook.verifier({ algo: "pqc-pem", keys: { v1: k.p256.publicKey } }); });
  check("webhook verifier pqc-pem refuses a P-256 key", c2 === "webhook/bad-opt", c2);
  var c3 = await _codeOf(function () {
    return b.webhook.signer({ algo: "pqc-pem", keys: { v1: { privateKey: k.d87.privateKey, publicKey: k.d65.publicKey } } });
  });
  check("webhook signer pqc-pem refuses a privateKey and publicKey of different types", c3 === "webhook/bad-opt", c3);
  var s = b.webhook.signer({ algo: "pqc-pem", keys: { v1: { privateKey: k.d65.privateKey, publicKey: k.d65.publicKey } } });
  check("webhook signer pqc-pem with an ML-DSA-65 key still signs", typeof s.sign("body").headers === "object");
}

async function testVapidCurve() {
  var k = _keys();
  var code = await _codeOf(function () {
    return b.webPush.buildVapidAuthHeader({
      subscription: { endpoint: "https://push.example.com/x" }, contact: "mailto:a@x.example",
      privateKeyPem: k.p384.privateKey, publicKeyB64Url: "AAAA",
    });
  });
  check("webPush.buildVapidAuthHeader refuses a P-384 key", code === "web-push/bad-key", code);
}

async function testAuditSignKeyFile() {
  var k = _keys();
  var tmp = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-audit-sign-label-"));
  try {
    fs.writeFileSync(path.join(tmp, "audit-sign.key"), JSON.stringify({
      algorithm: "slh-dsa-shake-256f", publicKey: k.ed.publicKey, privateKey: k.ed.privateKey,
    }));
    b.auditSign._resetForTest();
    var code = await _codeOf(function () { return b.auditSign.init({ dataDir: tmp, mode: "plaintext" }); });
    check("auditSign.init refuses a key file whose algorithm does not match its key",
      code === "audit-sign/key-algorithm-mismatch", code);
    b.auditSign._resetForTest();
    fs.writeFileSync(path.join(tmp, "audit-sign.key"), JSON.stringify({
      algorithm: "ml-dsa-65", publicKey: k.d65.publicKey, privateKey: k.d65.privateKey,
    }));
    await b.auditSign.init({ dataDir: tmp, mode: "plaintext" });
    check("auditSign.init loads a key file whose algorithm matches its key",
      b.auditSign.getAlgorithm() === "ml-dsa-65" && b.auditSign.verify("p", b.auditSign.sign("p")) === true);
    b.auditSign._resetForTest();
    var other65 = _pair("ml-dsa-65");
    fs.writeFileSync(path.join(tmp, "audit-sign.key"), JSON.stringify({
      algorithm: "ml-dsa-65", publicKey: other65.publicKey, privateKey: k.d65.privateKey,
    }));
    var pairCode = await _codeOf(function () { return b.auditSign.init({ dataDir: tmp, mode: "plaintext" }); });
    check("auditSign.init refuses a key file whose private and public keys are not a pair",
      pairCode === "audit-sign/key-pair-mismatch", pairCode);
  } finally {
    b.auditSign._resetForTest();
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

async function testAuditSignRotate() {
  var k = _keys();
  var tmp = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-audit-sign-rotate-"));
  var keyPath = path.join(tmp, "audit-sign.key");
  try {
    fs.writeFileSync(keyPath, JSON.stringify({
      algorithm: "ml-dsa-87", publicKey: k.d87.publicKey, privateKey: k.d87.privateKey,
    }));
    b.auditSign._resetForTest();
    await b.auditSign.init({ dataDir: tmp, mode: "plaintext" });
    var fpBefore = b.auditSign.getPublicKeyFingerprint();
    var fileBefore = fs.readFileSync(keyPath, "utf8");
    var listingBefore = fs.readdirSync(tmp).sort().join(",");
    var otherA = _pair("ml-dsa-87");
    var otherB = _pair("ml-dsa-87");
    var rows = [
      ["an Ed25519 pair with no algorithm", { privateKeyPem: k.ed.privateKey, publicKeyPem: k.ed.publicKey },
       "audit-sign/key-algorithm-mismatch"],
      ["an ml-dsa-87 private key with an ml-dsa-65 public key",
       { privateKeyPem: otherA.privateKey, publicKeyPem: k.d65.publicKey }, "audit-sign/key-algorithm-mismatch"],
      ["an ml-dsa-65 pair labeled ml-dsa-87", { privateKeyPem: k.d65.privateKey, publicKeyPem: k.d65.publicKey,
       algorithm: "ml-dsa-87" }, "audit-sign/key-algorithm-mismatch"],
      ["two ml-dsa-87 keys that are not a pair", { privateKeyPem: otherA.privateKey, publicKeyPem: otherB.publicKey },
       "audit-sign/key-pair-mismatch"],
      ["a private key that cannot be parsed", { privateKeyPem: "not a key", publicKeyPem: otherB.publicKey },
       "audit-sign/rotate-bad-key"],
    ];
    for (var i = 0; i < rows.length; i += 1) {
      var row = rows[i];
      var code = await _codeOf(function () { return b.auditSign.rotateSigningKey(row[1]); });
      check("auditSign.rotateSigningKey refuses " + row[0], code === row[2], code);
    }
    check("refused rotations leave the key file unchanged", fs.readFileSync(keyPath, "utf8") === fileBefore);
    check("refused rotations write no history file", fs.readdirSync(tmp).sort().join(",") === listingBefore,
      fs.readdirSync(tmp).join(","));
    check("refused rotations keep the current key in memory",
      b.auditSign.getPublicKeyFingerprint() === fpBefore && b.auditSign.getAlgorithm() === "ml-dsa-87");
    b.auditSign._resetForTest();
    await b.auditSign.init({ dataDir: tmp, mode: "plaintext" });
    check("auditSign.init still loads the key file after refused rotations",
      b.auditSign.getPublicKeyFingerprint() === fpBefore && b.auditSign.getAlgorithm() === "ml-dsa-87");
    var rotated = await b.auditSign.rotateSigningKey({
      privateKeyPem: k.d65.privateKey, publicKeyPem: k.d65.publicKey, algorithm: "ml-dsa-65",
    });
    check("auditSign.rotateSigningKey accepts an ml-dsa-65 pair labeled ml-dsa-65", rotated.algorithm === "ml-dsa-65");
    b.auditSign._resetForTest();
    await b.auditSign.init({ dataDir: tmp, mode: "plaintext" });
    check("auditSign.init loads the key file the rotation wrote",
      b.auditSign.getAlgorithm() === "ml-dsa-65" && b.auditSign.verify("p", b.auditSign.sign("p")) === true);
  } finally {
    b.auditSign._resetForTest();
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

async function run() {
  await testVcJoseIssue();
  await testSdJwtVcIssue();
  await testDpopBuildProof();
  await testProtectedResourceMetadata();
  await testArcSign();
  await testDkimKeyObjectShapes();
  await testSamlSigning();
  await testGcsServiceAccountKey();
  await testMcpToolRegistry();
  await testWebhookPqcPem();
  await testVapidCurve();
  await testAuditSignKeyFile();
  await testAuditSignRotate();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[signature-label-key-binding] OK"); },
    function (e) { console.error(e); process.exit(1); }
  );
}
