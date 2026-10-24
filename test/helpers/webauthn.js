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

function _array(items) { return Buffer.concat([_head(4, items.length)].concat(items)); }

// The attestation statement opts.attestation asks for, over authData and the
// clientDataJSON hash:
//   { fmt: "packed", x5c: [der, ...], signingKey }  ES256 by the leaf key
//   { fmt: "android-safetynet", x5c: [der, ...], signingKey, payload? }
//     an RS256 JWS by the leaf key whose payload carries the nonce, a fresh
//     timestampMs and passing integrity verdicts; payload fields override them
function _attestationStatement(att, authData, clientDataHash) {
  var signed = Buffer.concat([authData, clientDataHash]);
  if (att.fmt === "packed") {
    return _map([
      [_text("alg"), _int(-7)],
      [_text("sig"), _bytes(crypto.sign("sha256", signed, { key: att.signingKey, dsaEncoding: "der" }))],
      [_text("x5c"), _array(att.x5c.map(function (der) { return _bytes(Buffer.from(der)); }))],
    ]);
  }
  if (att.fmt === "android-safetynet") {
    var header = { alg: "RS256", x5c: att.x5c.map(function (der) { return Buffer.from(der).toString("base64"); }) };
    var payload = Object.assign({
      nonce: _sha256(signed).toString("base64"), timestampMs: Date.now(),
      apkPackageName: "com.google.android.gms", ctsProfileMatch: true, basicIntegrity: true,
    }, att.payload || {});
    var input = _b64url(Buffer.from(JSON.stringify(header), "utf8")) + "." +
      _b64url(Buffer.from(JSON.stringify(payload), "utf8"));
    var jws = input + "." + _b64url(crypto.sign("sha256", Buffer.from(input, "ascii"), att.signingKey));
    return _map([
      [_text("ver"),      _text("1")],
      [_text("response"), _bytes(Buffer.from(jws, "utf8"))],
    ]);
  }
  throw new Error("webauthn helper: unknown attestation fmt " + JSON.stringify(att.fmt));
}

// A registration response for an ES256 credential. challenge is the base64url
// text the ceremony issued. opts.keyPair is the P-256 { privateKey, publicKey }
// pair the credential uses; a fresh pair is generated when it is omitted.
// opts.attestation selects a `packed` or `android-safetynet` statement (see
// _attestationStatement); `none` attestation is used when it is omitted.
function registerCredential(opts) {
  opts = opts || {};
  var rpId      = opts.rpId || "example.test";
  var origin    = opts.origin || ("https://" + rpId);
  var challenge = opts.challenge || _b64url(crypto.randomBytes(32));
  var keyPair   = opts.keyPair || crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var credId    = crypto.randomBytes(32);

  var idLen = Buffer.alloc(2); idLen.writeUInt16BE(credId.length, 0);
  var attested = Buffer.concat([Buffer.alloc(16), idLen, credId, _coseEc2(keyPair.publicKey)]);
  var authData = _authData(rpId, FLAG_UP | FLAG_UV | FLAG_AT, 0, attested);
  var clientData = Buffer.from(JSON.stringify({
    type: "webauthn.create", challenge: challenge, origin: origin, crossOrigin: false,
  }), "utf8");
  var attestationObject = _map([
    [_text("fmt"),      _text(opts.attestation ? opts.attestation.fmt : "none")],
    [_text("attStmt"),  opts.attestation
      ? _attestationStatement(opts.attestation, authData, _sha256(clientData)) : _map([])],
    [_text("authData"), _bytes(authData)],
  ]);

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
  coseEc2PublicKey:   _coseEc2,
};
