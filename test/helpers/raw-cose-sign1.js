// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// COSE_Sign1 built with node:crypto alone, so a test can produce a
// signature under a key b.cose.sign refuses to use (a compromised key) and
// show that every verifier refuses it.

var nodeCrypto = require("node:crypto");
var cbor       = require("../../lib/cbor");

var ALGS = Object.freeze({
  ES256: { id: -7,  hash: "sha256" },
  ES384: { id: -35, hash: "sha384" },
  ES512: { id: -36, hash: "sha512" },
  EdDSA: { id: -8,  hash: null },
});

// opts: { alg, privateKey, protectedHeaders?: Map, unprotectedHeaders?: Map,
//         detached?: boolean, externalAad?: Buffer }
// Returns the tagged COSE_Sign1 bytes.
function sign1(payload, opts) {
  var a = ALGS[opts.alg];
  var prot = new Map([[1, a.id]]);
  if (opts.protectedHeaders) opts.protectedHeaders.forEach(function (v, k) { prot.set(k, v); });
  var protBstr = cbor.encode(prot);
  var body = Buffer.from(payload);
  var tbs = cbor.encode(["Signature1", protBstr, opts.externalAad || Buffer.alloc(0), body]);
  var sig = a.hash === null
    ? nodeCrypto.sign(null, tbs, opts.privateKey)
    : nodeCrypto.sign(a.hash, tbs, { key: opts.privateKey, dsaEncoding: "ieee-p1363" });
  var arr = [protBstr, opts.unprotectedHeaders || new Map(), opts.detached ? null : body, sig];
  return cbor.encode(new cbor.Tag(18, arr));
}

module.exports = { sign1: sign1 };
