// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// Certificates whose encoding leads a byte-level reader to judge a key other
// than the certificate's own, built at run time from the P-256 attestation
// fixtures in compromised-keys.js.
//
// - rebuild(der, o) re-signs a fixture certificate with o.signingKey after
//   replacing its subject key with o.publicKey and appending o.extension to
//   its extensions. Names, serials and key identifiers stay as they are, so a
//   rebuilt leaf still names the rebuilt CA as its issuer.
// - explicitFalseExtension() encodes its critical flag as an explicit
//   BOOLEAN FALSE. DER omits a default value, so @blamejs/pki refuses to parse
//   the certificate while node:crypto reads it.
// - textExtension(text) carries text in a UTF8String. With PEM text inside,
//   a reader that searches the certificate bytes for "-----BEGIN " finds a
//   different key or certificate; node's X509Certificate(buffer) reads an
//   embedded CERTIFICATE block ahead of the DER around it.
// - CERT_PEM_TEXT, KEY_PEM_TEXT and BEGIN_JUNK_TEXT are the texts the tests
//   embed: an ordinary CA certificate, an ordinary public key, and a
//   "-----BEGIN " line that starts no PEM block.

var nodeCrypto = require("node:crypto");
var asn1       = require("../../lib/asn1-der");
var ck         = require("./compromised-keys");

var COMPROMISED = ck.ecKeyPair("prime256v1", 1n);
var CONTROL_CA  = ck.ecKeyPair("prime256v1", BigInt("0x" + nodeCrypto.createHash("sha256")
  .update("blamejs passkey attestation fixture CA", "utf8").digest("hex")));
var LEAF        = { privateKey: ck.p256AttestationLeafKey() };
LEAF.publicKey  = nodeCrypto.createPublicKey(LEAF.privateKey);

var CERT_PEM_TEXT   = "\n" + ck.certPem(ck.P256_CONTROL_CA_DER);
var KEY_PEM_TEXT    = "\n" + ck.ecKeyPair("prime256v1", ck.labelScalar("prime256v1", "blamejs crafted cert decoy"))
  .publicKey.export({ type: "spki", format: "pem" });
var BEGIN_JUNK_TEXT = "\n-----BEGIN junk\n";

function explicitFalseExtension() {
  return asn1.writeSequence([asn1.writeOid("1.3.6.1.4.1.99999.1"), asn1.writeBoolean(false),
    asn1.writeOctetString(asn1.writeUtf8String("x"))]);
}

function textExtension(text) {
  return asn1.writeSequence([asn1.writeOid("1.3.6.1.4.1.99999.2"), asn1.writeOctetString(asn1.writeUtf8String(text))]);
}

function rebuild(der, o) {
  var outer = asn1.readNode(der, 0);
  var parts = asn1.readSequence(outer.value);
  var fields = asn1.readSequence(parts[0].value);
  var first = fields[0].tagClass === asn1.TAG_CLASS.CONTEXT_SPECIFIC && fields[0].tag === 0 ? 1 : 0;
  var raw = fields.map(function (n) { return n.raw; });
  if (o.publicKey) raw[first + 5] = o.publicKey.export({ type: "spki", format: "der" });
  if (o.extension) {
    var last = fields[fields.length - 1];
    var exts = asn1.readSequence(asn1.readNode(last.value, 0).value).map(function (n) { return n.raw; });
    raw[raw.length - 1] = asn1.writeContextExplicit(3, asn1.writeSequence(exts.concat([o.extension])));
  }
  var tbs = asn1.writeSequence(raw);
  var sig = nodeCrypto.sign("sha256", tbs, { key: o.signingKey, dsaEncoding: "der" });
  return asn1.writeSequence([tbs, parts[1].raw, asn1.writeBitString(sig)]);
}

// A self-signed "Test Attestation CA" for `pair` carrying `extension`.
function selfSignedCa(pair, extension) {
  return rebuild(ck.P256_CONTROL_CA_DER, { publicKey: pair.publicKey, signingKey: pair.privateKey, extension: extension });
}

// A "Test Authenticator" leaf for `leafPair`, issued by the CA key `caPair`,
// carrying `extension`.
function leafUnder(caPair, leafPair, extension) {
  return rebuild(ck.P256_CONTROL_LEAF_DER, { publicKey: leafPair.publicKey, signingKey: caPair.privateKey, extension: extension });
}

// The control CA with its key algorithm changed to an unknown OID and an
// explicit-FALSE extension: node parses it but cannot load its key, and
// @blamejs/pki cannot parse it.
function unreadableCa() {
  var der = Buffer.from(ck.P256_CONTROL_CA_DER);
  var ecOid = Buffer.from("06072a8648ce3d0201", "hex");
  var at = der.indexOf(ecOid);
  var odd = Buffer.concat([der.subarray(0, at), Buffer.from("06072a03040506070a", "hex"), der.subarray(at + ecOid.length)]);
  return rebuild(odd, { signingKey: CONTROL_CA.privateKey, extension: explicitFalseExtension() });
}

module.exports = {
  COMPROMISED:            COMPROMISED,
  CONTROL_CA:             CONTROL_CA,
  LEAF:                   LEAF,
  CERT_PEM_TEXT:          CERT_PEM_TEXT,
  KEY_PEM_TEXT:           KEY_PEM_TEXT,
  BEGIN_JUNK_TEXT:        BEGIN_JUNK_TEXT,
  explicitFalseExtension: explicitFalseExtension,
  textExtension:          textExtension,
  rebuild:                rebuild,
  selfSignedCa:           selfSignedCa,
  leafUnder:              leafUnder,
  unreadableCa:           unreadableCa,
};
