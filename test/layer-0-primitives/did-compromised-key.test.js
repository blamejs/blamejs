// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.did never resolves a compromised key to a verification method: did:key,
 * did:jwk and a did:web document (publicKeyJwk and publicKeyMultibase) are
 * refused, and keyToDid refuses to name one. Each refusal is paired with a
 * control key on the same curve that differs only in its private scalar.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var ck      = require("../helpers/compromised-keys");

var CURVES = [
  ["prime256v1", Buffer.from([0x80, 0x24])],
  ["secp384r1",  Buffer.from([0x81, 0x24])],
  ["secp256k1",  Buffer.from([0xe7, 0x01])],
];
var B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function _b58(buf) {
  var n = BigInt("0x" + (buf.toString("hex") || "0"));
  var out = "";
  while (n > 0n) { out = B58[Number(n % 58n)] + out; n /= 58n; }
  for (var i = 0; i < buf.length && buf[i] === 0; i += 1) out = "1" + out;
  return out;
}

function _publicJwk(pair) {
  var j = pair.publicKey.export({ format: "jwk" });
  return { kty: j.kty, crv: j.crv, x: j.x, y: j.y };
}

function _multibase(pair, prefix) {
  var j = _publicJwk(pair);
  var y = Buffer.from(j.y, "base64url");
  var point = Buffer.concat([Buffer.from([(y[y.length - 1] & 1) ? 3 : 2]), Buffer.from(j.x, "base64url")]);
  return "z" + _b58(Buffer.concat([prefix, point]));
}

function _didJwk(pair) {
  return "did:jwk:" + Buffer.from(JSON.stringify(_publicJwk(pair)), "utf8").toString("base64url");
}

function _code(fn) {
  try { fn(); return "NO-THROW"; } catch (e) { return e.code || e.message; }
}

function _pairs(curve) {
  return {
    bad:     ck.ecKeyPair(curve, 1n),
    control: ck.ecKeyPair(curve, ck.labelScalar(curve, "blamejs did compromised-key control")),
  };
}

function testDidKeyAndDidJwkRefuseACompromisedKey() {
  CURVES.forEach(function (c) {
    var p = _pairs(c[0]);
    var goodKey = "did:key:" + _multibase(p.control, c[1]);
    var resolved = b.did.resolve(goodKey);
    check("did compromised key control: the control " + c[0] + " did:key resolves to its key",
          resolved.verificationMethods[0].publicKey.export({ format: "jwk" }).x === _publicJwk(p.control).x);
    check("did compromised key control: the control " + c[0] + " did:jwk resolves",
          _code(function () { b.did.resolve(_didJwk(p.control)); }) === "NO-THROW");
    check("did compromised key: a " + c[0] + " did:key whose private key is 1 is refused",
          _code(function () { b.did.resolve("did:key:" + _multibase(p.bad, c[1])); }) === "did/compromised-key");
    check("did compromised key: a " + c[0] + " did:jwk whose private key is 1 is refused",
          _code(function () { b.did.resolve(_didJwk(p.bad)); }) === "did/compromised-key");
  });
}

function testDidWebDocumentRefusesACompromisedKey() {
  var did = "did:web:issuer.example";
  var p = _pairs("prime256v1");
  function doc(vm) { return { id: did, verificationMethod: [Object.assign({ id: did + "#k", controller: did }, vm)] }; }
  check("did compromised key control: a did:web document with the control publicKeyJwk resolves",
        _code(function () { b.did.resolve(did, { document: doc({ type: "JsonWebKey2020", publicKeyJwk: _publicJwk(p.control) }) }); }) === "NO-THROW");
  check("did compromised key: a did:web publicKeyJwk whose private key is 1 is refused",
        _code(function () { b.did.resolve(did, { document: doc({ type: "JsonWebKey2020", publicKeyJwk: _publicJwk(p.bad) }) }); }) ===
        "did/compromised-key");
  check("did compromised key control: a did:web document with the control publicKeyMultibase resolves",
        _code(function () { b.did.resolve(did, { document: doc({ type: "Multikey", publicKeyMultibase: _multibase(p.control, CURVES[0][1]) }) }); }) ===
        "NO-THROW");
  check("did compromised key: a did:web publicKeyMultibase whose private key is 1 is refused",
        _code(function () { b.did.resolve(did, { document: doc({ type: "Multikey", publicKeyMultibase: _multibase(p.bad, CURVES[0][1]) }) }); }) ===
        "did/compromised-key");
}

function testKeyToDidRefusesACompromisedKey() {
  var p = _pairs("prime256v1");
  ["key", "jwk"].forEach(function (method) {
    check("did compromised key control: keyToDid (" + method + ") names the control key",
          _code(function () { b.did.keyToDid(p.control.publicKey, { method: method }); }) === "NO-THROW");
    check("did compromised key: keyToDid (" + method + ") refuses a key whose private key is 1",
          _code(function () { b.did.keyToDid(p.bad.publicKey, { method: method }); }) === "did/compromised-key");
  });
}

async function run() {
  testDidKeyAndDidJwkRefuseACompromisedKey();
  testDidWebDocumentRefusesACompromisedKey();
  testKeyToDidRefusesACompromisedKey();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
