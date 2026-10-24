// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.middleware.requireMtls and b.middleware.requireBoundKey refuse a client
 * whose verified certificate chain carries a compromised key, over a real
 * loopback mTLS handshake that OpenSSL accepts:
 *
 * - a client certificate whose own private key is 1, pinned by fingerprint
 *   (requireMtls fingerprintAllowList, requireBoundKey peerCertFingerprints);
 * - a client certificate issued by a client CA whose private key is 1, which
 *   the listener trusts.
 *
 * Each control differs only in the key.
 */

var helpers    = require("../helpers");
var b          = helpers.b;
var check      = helpers.check;
var https      = require("node:https");
var nodeCrypto = require("node:crypto");
var ck         = require("../helpers/compromised-keys");

function _scalar(label) {
  return BigInt("0x" + nodeCrypto.createHash("sha256").update(label, "utf8").digest("hex"));
}
function _pkcs8(pair) { return pair.privateKey.export({ type: "pkcs8", format: "pem" }); }

// Client certificates issued directly by the TLS fixture root (subject
// "blamejs TLS fixture client", EKU clientAuth, 2026-01-01 .. 2099-12-31),
// minted with @blamejs/pki 0.9.5. The compromised certificate's private key
// is 1; the control's is SHA-256("blamejs tls fixture client").
var TLS_COMPROMISED_CLIENT_DER = Buffer.from(
  "MIIBrjCCAVSgAwIBAgIBBDAKBggqhkjOPQQDAjAjMSEwHwYDVQQDDBhibGFtZWpz" +
  "IFRMUyBmaXh0dXJlIHJvb3QwIBcNMjYwMTAxMDAwMDAwWhgPMjA5OTEyMzEwMDAw" +
  "MDBaMCUxIzAhBgNVBAMMGmJsYW1lanMgVExTIGZpeHR1cmUgY2xpZW50MFkwEwYH" +
  "KoZIzj0CAQYIKoZIzj0DAQcDQgAEaxfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5" +
  "RdiYwpZP40Li/hp/m47n60p8D54WK84zV2sxXs7LtkBoN79R9aN1MHMwHQYDVR0O" +
  "BBYEFLRno5mete+mcd4AMvCKnJ5e/aDhMB8GA1UdIwQYMBaAFPJtSuBdKpki5ZX6" +
  "uv1XNOBB+kgjMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAjAM" +
  "BgNVHRMBAf8EAjAAMAoGCCqGSM49BAMCA0gAMEUCIQCsEOqGjadcCMbwfE5r3sdU" +
  "2qTUcNw6C/vazUDrxAcvQQIgGcZyxcnjPcPAGUpOLm8lRqaHxDoxGIJ0wM3L8s1T" +
  "VGw=", "base64");
var TLS_CONTROL_CLIENT_DER = Buffer.from(
  "MIIBrzCCAVSgAwIBAgIBBTAKBggqhkjOPQQDAjAjMSEwHwYDVQQDDBhibGFtZWpz" +
  "IFRMUyBmaXh0dXJlIHJvb3QwIBcNMjYwMTAxMDAwMDAwWhgPMjA5OTEyMzEwMDAw" +
  "MDBaMCUxIzAhBgNVBAMMGmJsYW1lanMgVExTIGZpeHR1cmUgY2xpZW50MFkwEwYH" +
  "KoZIzj0CAQYIKoZIzj0DAQcDQgAEU9N9EQ+94WIiOq7MJahGBEFiOVGV0ItYI70O" +
  "Bqrfk49DEocNyjiy/S2XvIgX5C72nXkMKk1RR6NZWLhscIHZaaN1MHMwHQYDVR0O" +
  "BBYEFLJzv1c6Wh8eXwqG+TU0m6jrVFHmMB8GA1UdIwQYMBaAFPJtSuBdKpki5ZX6" +
  "uv1XNOBB+kgjMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAjAM" +
  "BgNVHRMBAf8EAjAAMAoGCCqGSM49BAMCA0kAMEYCIQCvnhRuBiERpuESqeASN/Sn" +
  "GpPPzCrAL6X2vAXnCJ+dzQIhAKPvfSRAGBISIM/LladWCky5WVAch/8tuB+rEgL+" +
  "A0ig", "base64");

var PINNED = {
  compromised: { cert: ck.certPem(TLS_COMPROMISED_CLIENT_DER), key: _pkcs8(ck.ecKeyPair("prime256v1", 1n)),
                 der: TLS_COMPROMISED_CLIENT_DER, ca: ck.certPem(ck.TLS_ROOT_DER) },
  control:     { cert: ck.certPem(TLS_CONTROL_CLIENT_DER),
                 key: _pkcs8(ck.ecKeyPair("prime256v1", _scalar("blamejs tls fixture client"))),
                 der: TLS_CONTROL_CLIENT_DER, ca: ck.certPem(ck.TLS_ROOT_DER) },
};
var UNDER_CA = {
  compromised: { cert: ck.certPem(ck.P256_COMPROMISED_LEAF_DER),
                 key: ck.p256AttestationLeafKey().export({ type: "pkcs8", format: "pem" }),
                 ca: ck.certPem(ck.P256_COMPROMISED_CA_DER) },
  control:     { cert: ck.certPem(ck.P256_CONTROL_LEAF_DER),
                 key: ck.p256AttestationLeafKey().export({ type: "pkcs8", format: "pem" }),
                 ca: ck.certPem(ck.P256_CONTROL_CA_DER) },
};

// Runs `middleware` behind a loopback HTTPS listener that trusts `client.ca`
// and asks for a client certificate, sends one request presenting
// `client.cert`, and resolves { status, body }.
function _request(middleware, client) {
  var serverChain = ck.tlsChain("control");
  return new Promise(function (resolve, reject) {
    var server = https.createServer({
      key: serverChain.key, cert: serverChain.cert, ca: [client.ca],
      requestCert: true, rejectUnauthorized: true,
    }, function (req, res) {
      Promise.resolve(middleware(req, res, function () {
        res.writeHead(200, { "content-type": "text/plain" });                          // allow:raw-byte-literal (HTTP status)
        res.end("ok");
      })).catch(function (e) { res.writeHead(500); res.end(String(e && e.message)); });  // allow:raw-byte-literal (HTTP status)
    });
    server.listen(0, "127.0.0.1", function () {
      var req = https.request({
        host: "127.0.0.1", port: server.address().port, servername: "localhost", path: "/",
        method: "GET", agent: false, ca: [serverChain.rootCa], key: client.key, cert: client.cert,
        headers: { authorization: "Bearer key-1" },
      }, function (res) {
        var chunks = [];
        res.on("data", function (c) { chunks.push(c); });
        res.on("end", function () {
          server.close();
          resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString("utf8") });
        });
      });
      req.on("error", function (e) { server.close(); reject(e); });
      req.end();
    });
  });
}

function _reason(r) {
  try { return JSON.parse(r.body).reason; } catch (_e) { return r.body; }
}

function _requireMtls(extra) {
  return b.middleware.requireMtls(Object.assign({ audit: false }, extra || {}));
}

async function testPinnedClientCertificateIsRefused() {
  var controlFp = b.crypto.hashCertFingerprint(PINNED.control.der).colon;
  var control = await _request(_requireMtls({ fingerprintAllowList: [controlFp] }), PINNED.control);
  check("require-mtls compromised key control: a pinned ordinary client certificate is served",
        control.status === 200, JSON.stringify(control));
  var badFp = b.crypto.hashCertFingerprint(PINNED.compromised.der).colon;
  var bad = await _request(_requireMtls({ fingerprintAllowList: [badFp] }), PINNED.compromised);
  check("require-mtls compromised key: a pinned client certificate whose private key is 1 is refused",
        bad.status === 401 && _reason(bad) === "compromised-key", JSON.stringify(bad));
}

async function testClientCaIsRefused() {
  var control = await _request(_requireMtls(), UNDER_CA.control);
  check("require-mtls compromised key control: a client certificate under an ordinary client CA is served",
        control.status === 200, JSON.stringify(control));
  var bad = await _request(_requireMtls(), UNDER_CA.compromised);
  check("require-mtls compromised key: a client certificate under a client CA whose private key is 1 is refused",
        bad.status === 401 && _reason(bad) === "compromised-key", JSON.stringify(bad));
}

function _boundKey(pinnedDer) {
  var fp = b.crypto.hashCertFingerprint(pinnedDer).colon;
  var gate = b.middleware.requireBoundKey({
    audit: false,
    resolver: async function (apiKey) {
      return apiKey === "key-1" ? { id: "k1", ownerId: "svc", scopes: [], boundFields: {}, peerCertFingerprints: [fp] } : null;
    },
  });
  return function (req, res, next) {
    req.peerCert = req.socket.getPeerCertificate(true);
    return gate(req, res, next);
  };
}

async function testBoundKeyRefusesACompromisedPinnedCertificate() {
  var control = await _request(_boundKey(PINNED.control.der), PINNED.control);
  check("require-bound-key compromised key control: a key pinned to an ordinary client certificate is served",
        control.status === 200, JSON.stringify(control));
  var bad = await _request(_boundKey(PINNED.compromised.der), PINNED.compromised);
  check("require-bound-key compromised key: a key pinned to a client certificate whose private key is 1 is refused",
        bad.status === 403 && _reason(bad) === "compromised-key", JSON.stringify(bad));
}

async function run() {
  await testPinnedClientCertificateIsRefused();
  await testClientCaIsRefused();
  await testBoundKeyRefusesACompromisedPinnedCertificate();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
