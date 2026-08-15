// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// WebAuthn ceremony fixtures — a software authenticator with REAL keys.
//
// Shared so a suite that needs one genuine assertion does not roll its own
// CBOR writer. Anything that verifies a passkey needs the same handful of
// pieces, and the details are easy to get subtly wrong: the verifier enforces
// CTAP2 canonical map ordering (keys by length, then bytewise), so an
// out-of-order fixture is refused before the code under test ever runs, and a
// test can then "pass" against a refusal that means nothing.
//
// registerCredential() returns everything a consumer test needs: the response
// to verify, the credential id, and the private key to sign later assertions.

var crypto = require("node:crypto");

var FLAG_UP = 0x01;                                                                // allow:raw-byte-literal — WebAuthn user present
var FLAG_UV = 0x04;                                                                // allow:raw-byte-literal — user verified
var FLAG_AT = 0x40;                                                                // allow:raw-byte-literal — attested credential data

function _head(major, n) {
  if (n < 24) return Buffer.from([(major << 5) | n]);                              // allow:raw-byte-literal — CBOR immediate
  if (n < 256) return Buffer.from([(major << 5) | 24, n]);                         // allow:raw-byte-literal — CBOR uint8
  var b = Buffer.alloc(3);
  b[0] = (major << 5) | 25;                                                        // allow:raw-byte-literal — CBOR uint16
  b.writeUInt16BE(n, 1);
  return b;
}
function _int(n)   { return n >= 0 ? _head(0, n) : _head(1, -n - 1); }
function _bytes(b) { return Buffer.concat([_head(2, b.length), b]); }
function _text(s)  { var b = Buffer.from(s, "utf8"); return Buffer.concat([_head(3, b.length), b]); }
function _map(pairs) {
  var parts = [_head(5, pairs.length)];
  for (var i = 0; i < pairs.length; i++) parts.push(pairs[i][0], pairs[i][1]);
  return Buffer.concat(parts);
}

function _b64url(buf) { return Buffer.from(buf).toString("base64url"); }
function _sha256(buf) { return crypto.createHash("sha256").update(buf).digest(); }

// COSE_Key for an EC2 P-256 / ES256 public key: { 1:2, 3:-7, -1:1, -2:x, -3:y }.
function _coseEc2(publicKey) {
  var jwk = publicKey.export({ format: "jwk" });
  return _map([
    [_int(1),  _int(2)],
    [_int(3),  _int(-7)],
    [_int(-1), _int(1)],
    [_int(-2), _bytes(Buffer.from(jwk.x, "base64url"))],
    [_int(-3), _bytes(Buffer.from(jwk.y, "base64url"))],
  ]);
}

// authenticatorData = rpIdHash(32) || flags(1) || signCount(4) [|| attested]
function _authData(rpId, flags, signCount, attested) {
  var head = Buffer.concat([
    _sha256(Buffer.from(rpId, "utf8")),
    Buffer.from([flags & 0xff]),                                                   // allow:raw-byte-literal — flag byte
    Buffer.alloc(4),
  ]);
  head.writeUInt32BE(signCount >>> 0, 33);                                         // allow:raw-byte-literal — signCount offset
  return attested ? Buffer.concat([head, attested]) : head;
}

// A registration response for a fresh ES256 credential, `none` attestation.
// challenge is the base64url text the ceremony issued.
function registerCredential(opts) {
  opts = opts || {};
  var rpId      = opts.rpId || "example.test";
  var origin    = opts.origin || ("https://" + rpId);
  var challenge = opts.challenge || _b64url(crypto.randomBytes(32));
  var keyPair   = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var credId    = crypto.randomBytes(32);

  var idLen = Buffer.alloc(2); idLen.writeUInt16BE(credId.length, 0);
  var attested = Buffer.concat([Buffer.alloc(16), idLen, credId, _coseEc2(keyPair.publicKey)]);
  var authData = _authData(rpId, FLAG_UP | FLAG_UV | FLAG_AT, 0, attested);
  var attestationObject = _map([
    [_text("fmt"),      _text("none")],
    [_text("attStmt"),  _map([])],
    [_text("authData"), _bytes(authData)],
  ]);
  var clientData = Buffer.from(JSON.stringify({
    type: "webauthn.create", challenge: challenge, origin: origin, crossOrigin: false,
  }), "utf8");

  return {
    rpId: rpId, origin: origin, challenge: challenge,
    keyPair: keyPair, credId: credId,
    response: {
      id: _b64url(credId), rawId: _b64url(credId), type: "public-key",
      response: {
        clientDataJSON:    _b64url(clientData),
        attestationObject: _b64url(attestationObject),
      },
      clientExtensionResults: {},
    },
  };
}

// A genuine assertion for a registered credential, signed by its real key.
function assertCredential(reg, opts) {
  opts = opts || {};
  var challenge = opts.challenge || _b64url(crypto.randomBytes(32));
  var signCount = typeof opts.signCount === "number" ? opts.signCount : 1;
  var authData  = _authData(reg.rpId, FLAG_UP | FLAG_UV, signCount, null);
  var clientData = Buffer.from(JSON.stringify({
    type: "webauthn.get", challenge: challenge, origin: reg.origin, crossOrigin: false,
  }), "utf8");
  var signature = crypto.sign("sha256",
    Buffer.concat([authData, _sha256(clientData)]),
    { key: reg.keyPair.privateKey, dsaEncoding: "der" });

  return {
    challenge: challenge,
    response: {
      id: _b64url(reg.credId), rawId: _b64url(reg.credId), type: "public-key",
      response: {
        clientDataJSON:    _b64url(clientData),
        authenticatorData: _b64url(authData),
        signature:         _b64url(signature),
      },
      clientExtensionResults: {},
    },
  };
}

module.exports = {
  registerCredential: registerCredential,
  assertCredential:   assertCredential,
};
