// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * TLS test helpers — a loopback server certificate.
 *
 * Several suites need a throwaway certificate to stand up a real TLS server
 * on 127.0.0.1. Each had grown its own ASN.1 assembly; this is the shared
 * one. It returns the CA material alongside the leaf so callers verify the
 * chain (`ca: [pair.cert]`) instead of reaching for rejectUnauthorized:false.
 *
 * The certificate is minted once per process and cached — building it costs
 * a keypair generation, and every caller wants the same "some valid cert for
 * localhost" fixture.
 *
 * Suites that need a certificate with SPECIFIC contents (a chosen serial, a
 * must-staple extension, embedded SCTs) build their own — that is a fixture
 * for the parser under test, not a stand-up-a-server convenience.
 */

var nodeCrypto = require("node:crypto");
var asn1 = require("../../lib/asn1-der");

var _cached = null;

// selfSignedPair(opts?) → { cert, key, commonName }
//   cert / key are PEM strings ready for tls.createServer({ key, cert }).
//   Pass `ca: [pair.cert]` on the client so verification stays ON.
function selfSignedPair(opts) {
  opts = opts || {};
  var commonName = opts.commonName || "localhost";
  if (_cached && _cached.commonName === commonName) return _cached;

  var kp = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var spkiDer = kp.publicKey.export({ type: "spki", format: "der" });
  var sigAlgId = asn1.writeSequence([asn1.writeOid("1.2.840.10045.4.3.2")]);      // ecdsa-with-SHA256
  var cnrdn = asn1.writeSequence([asn1.writeOid("2.5.4.3"),
    asn1.writeNode(0x0c, Buffer.from(commonName, "ascii"))]);
  var name = asn1.writeSequence([asn1.writeNode(0x31, cnrdn)]);
  var validity = asn1.writeSequence([
    asn1.writeNode(0x17, Buffer.from("250101000000Z", "ascii")),
    asn1.writeNode(0x17, Buffer.from("350101000000Z", "ascii")),
  ]);
  var version = asn1.writeContextExplicit(0, asn1.writeInteger(Buffer.from([2])));
  var tbs = asn1.writeSequence([version,
    asn1.writeInteger(Buffer.from([0x12, 0x34, 0x56, 0x78])),
    sigAlgId, name, validity, name, spkiDer]);
  var sig = nodeCrypto.sign("sha256", tbs, kp.privateKey);
  var certDer = asn1.writeSequence([tbs, sigAlgId, asn1.writeBitString(sig)]);

  _cached = {
    commonName: commonName,
    cert: "-----BEGIN CERTIFICATE-----\n" +
      certDer.toString("base64").replace(/(.{64})/g, "$1\n") +
      "\n-----END CERTIFICATE-----\n",
    key: kp.privateKey.export({ type: "pkcs8", format: "pem" }),
  };
  return _cached;
}

module.exports = { selfSignedPair: selfSignedPair };
