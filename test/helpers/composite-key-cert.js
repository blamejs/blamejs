// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A certificate whose subject key is a composite id-MLDSA65-ECDSA-P256-SHA512
 * key (OID 1.3.6.1.5.5.7.6.45), minted with @blamejs/pki: subject
 * "mx1.example.com", issuer "Issuer" (an ordinary P-256 key), serial 7,
 * 2026-01-01 .. 2030-01-01. node:crypto parses the certificate but cannot
 * load its public key, so `.publicKey` throws. `spki` is the
 * SubjectPublicKeyInfo DER the certificate carries.
 */

var asn1 = require("../../lib/asn1-der");

var COMPOSITE_CERT_DER = Buffer.from(
  "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", "base64");

function _spki(der) {
  var tbs = asn1.readSequence(asn1.readNode(der, 0).value)[0];
  var fields = asn1.readSequence(tbs.value);
  var first = fields[0].tagClass === asn1.TAG_CLASS.CONTEXT_SPECIFIC && fields[0].tag === 0 ? 1 : 0;
  return fields[first + 5].raw;
}

function certPem(der) {
  return "-----BEGIN CERTIFICATE-----\n" + der.toString("base64").match(/.{1,64}/g).join("\n") +
    "\n-----END CERTIFICATE-----\n";
}

module.exports = {
  COMPOSITE_CERT_DER: COMPOSITE_CERT_DER,
  COMPOSITE_CERT_PEM: certPem(COMPOSITE_CERT_DER),
  COMPOSITE_SPKI_DER: _spki(COMPOSITE_CERT_DER),
};
