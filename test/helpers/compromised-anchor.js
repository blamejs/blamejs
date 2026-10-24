// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// Trust-anchor fixtures for the outbound TLS clients.
//
// - decoyChain(which) is a server chain for a trust anchor that sits in the
//   default CA store, which blamejs does not screen at configuration. In the
//   "compromised" chain the anchor's private key is 1 and the server sends its
//   leaf with a decoy: a self-signed certificate with the anchor's name and
//   key identifier but an ordinary key. OpenSSL validates the leaf against
//   the anchor in the store, while node shows the decoy as the leaf's issuer.
//   In the "control" chain the anchor has an ordinary key and the server sends
//   its leaf with that anchor.
// - withDefaultAnchor(pem, fn) runs fn with pem added to the default CA store
//   and restores the store afterwards.
// - caLabels(der) is one certificate written under each PEM label OpenSSL
//   loads as a trusted certificate.
//
// The certificates were minted with openssl 3.5 (subject "blamejs decoy
// fixture root", leaf "localhost" with SAN localhost + 127.0.0.1, serverAuth,
// 2026-01-01 .. 2099-12-31). The leaf key is the one ck.tlsChain uses; the
// control anchor's scalar is ck.labelScalar("prime256v1", "blamejs decoy
// fixture root") and the decoy's is ck.labelScalar("prime256v1", "blamejs
// decoy fixture decoy").

var nodeTls = require("node:tls");
var ck      = require("./compromised-keys");

var DECOY_ANCHOR_COMPROMISED_DER = Buffer.from(
  "MIIBfDCCASOgAwIBAgIBATAKBggqhkjOPQQDAjAlMSMwIQYDVQQDDBpibGFtZWpz" +
  "IGRlY295IGZpeHR1cmUgcm9vdDAgFw0yNjAxMDEwMDAwMDBaGA8yMDk5MTIzMTAw" +
  "MDAwMFowJTEjMCEGA1UEAwwaYmxhbWVqcyBkZWNveSBmaXh0dXJlIHJvb3QwWTAT" +
  "BgcqhkjOPQIBBggqhkjOPQMBBwNCAARrF9Hy4SxCR/i85uVjpEDydwN9gS3rM6D0" +
  "oTlF2JjClk/jQuL+Gn+bjufrSnwPnhYrzjNXazFezsu2QGg3v1H1o0IwQDAPBgNV" +
  "HRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUtGejmZ6176Zx" +
  "3gAy8Iqcnl79oOEwCgYIKoZIzj0EAwIDRwAwRAIgPbvEmlmb2KfpzZDSpYHHNwtZ" +
  "OQPDTPG2WNVWRPV8NSQCIHgKWKb+E6hTBC2n4CYUTwTfZZKO4RKW6SThIN97S0UN", "base64");
var DECOY_ANCHOR_CONTROL_DER = Buffer.from(
  "MIIBfTCCASOgAwIBAgIBATAKBggqhkjOPQQDAjAlMSMwIQYDVQQDDBpibGFtZWpz" +
  "IGRlY295IGZpeHR1cmUgcm9vdDAgFw0yNjAxMDEwMDAwMDBaGA8yMDk5MTIzMTAw" +
  "MDAwMFowJTEjMCEGA1UEAwwaYmxhbWVqcyBkZWNveSBmaXh0dXJlIHJvb3QwWTAT" +
  "BgcqhkjOPQIBBggqhkjOPQMBBwNCAARYTCN66VR1pGIhk1BB+chPMVBQFbANHBv6" +
  "U3osVCsVKnvGjpjVAgybZErZdZTt8GKPYWfldzDwchpA+RyItEUfo0IwQDAPBgNV" +
  "HRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUDbojoNDrUliT" +
  "TJiSzkL4/OedGxMwCgYIKoZIzj0EAwIDSAAwRQIgIbY42+oBbIotpM13pb//BU0P" +
  "MFqKnGWGUFiUKSFAC7sCIQDdEb71mNBlH53GM/26fuKAz/Q8voAx5MVQHwM5y2mK" +
  "KQ==", "base64");
var DECOY_DER = Buffer.from(
  "MIIBfjCCASOgAwIBAgIBATAKBggqhkjOPQQDAjAlMSMwIQYDVQQDDBpibGFtZWpz" +
  "IGRlY295IGZpeHR1cmUgcm9vdDAgFw0yNjAxMDEwMDAwMDBaGA8yMDk5MTIzMTAw" +
  "MDAwMFowJTEjMCEGA1UEAwwaYmxhbWVqcyBkZWNveSBmaXh0dXJlIHJvb3QwWTAT" +
  "BgcqhkjOPQIBBggqhkjOPQMBBwNCAAQOvkVWNA3ZIMV+CpB+WOcqT8AlQkJVy3HI" +
  "ykTiA41bXbGgflM5rsZeQfG9UibAF/2kkZxDKhPKPLJHYLFr6Rn0o0IwQDAPBgNV" +
  "HRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUtGejmZ6176Zx" +
  "3gAy8Iqcnl79oOEwCgYIKoZIzj0EAwIDSQAwRgIhAKDNVnlOAclJW7P+Azv82QyD" +
  "TCYtCYYcOpApTun2SdgoAiEA29EtTDPUQDUT14Na+CWJpnG0WaxtpmOFA3ceU4Ol" +
  "HLM=", "base64");
var DECOY_LEAF_COMPROMISED_DER = Buffer.from(
  "MIIBvTCCAWOgAwIBAgIBAjAKBggqhkjOPQQDAjAlMSMwIQYDVQQDDBpibGFtZWpz" +
  "IGRlY295IGZpeHR1cmUgcm9vdDAgFw0yNjAxMDEwMDAwMDBaGA8yMDk5MTIzMTAw" +
  "MDAwMFowFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0D" +
  "AQcDQgAEY6bH26RBrHWzxd7endpnqbuOCOFxl4G0deDo1MCK8ciQeOnrd9F27BsM" +
  "EPmTQgcz91TEMamJR2YZbhR0gPGibaOBkjCBjzAMBgNVHRMBAf8EAjAAMA4GA1Ud" +
  "DwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDATAdBgNVHQ4EFgQU0Lx+O6Ak" +
  "eZY9ba1IDpp4ao6KNiIwHwYDVR0jBBgwFoAUtGejmZ6176Zx3gAy8Iqcnl79oOEw" +
  "GgYDVR0RBBMwEYIJbG9jYWxob3N0hwR/AAABMAoGCCqGSM49BAMCA0gAMEUCIH9t" +
  "20z22yhqB3iJRvEkpi2XQVn+dX4X+RnCrpax62djAiEA62jPANXy9nwmUP8QuoXj" +
  "0bl75bZkAb5IWNCnDf2i+O4=", "base64");
var DECOY_LEAF_CONTROL_DER = Buffer.from(
  "MIIBvTCCAWOgAwIBAgIBAjAKBggqhkjOPQQDAjAlMSMwIQYDVQQDDBpibGFtZWpz" +
  "IGRlY295IGZpeHR1cmUgcm9vdDAgFw0yNjAxMDEwMDAwMDBaGA8yMDk5MTIzMTAw" +
  "MDAwMFowFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0D" +
  "AQcDQgAEY6bH26RBrHWzxd7endpnqbuOCOFxl4G0deDo1MCK8ciQeOnrd9F27BsM" +
  "EPmTQgcz91TEMamJR2YZbhR0gPGibaOBkjCBjzAMBgNVHRMBAf8EAjAAMA4GA1Ud" +
  "DwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDATAdBgNVHQ4EFgQU0Lx+O6Ak" +
  "eZY9ba1IDpp4ao6KNiIwHwYDVR0jBBgwFoAUDbojoNDrUliTTJiSzkL4/OedGxMw" +
  "GgYDVR0RBBMwEYIJbG9jYWxob3N0hwR/AAABMAoGCCqGSM49BAMCA0gAMEUCIDq+" +
  "aqeSZ9p11IU09b4gL4EybUba6kkc16QnY+2Gv+YeAiEAqK42fu0MRudqjVWBUR/3" +
  "B0jXGnmNSl5mqyohGf45HLc=", "base64");

// { key, cert, anchor } for one decoy fixture ("compromised" or "control"):
// the server's key and certificate list, and the anchor PEM the client trusts
// through the default CA store. rootCa is undefined so a harness that passes
// it as `ca` leaves the client on the default store.
function decoyChain(which) {
  var compromised = which === "compromised";
  var tls = ck.tlsChain("control");
  return {
    key:    tls.key,
    cert:   ck.certPem(compromised ? DECOY_LEAF_COMPROMISED_DER : DECOY_LEAF_CONTROL_DER) +
            ck.certPem(compromised ? DECOY_DER : DECOY_ANCHOR_CONTROL_DER),
    anchor: ck.certPem(compromised ? DECOY_ANCHOR_COMPROMISED_DER : DECOY_ANCHOR_CONTROL_DER),
    rootCa: undefined,
  };
}

async function withDefaultAnchor(anchorPem, fn) {
  var original = nodeTls.getCACertificates("default");
  nodeTls.setDefaultCACertificates(original.concat([anchorPem]));
  try { return await fn(); }
  finally { nodeTls.setDefaultCACertificates(original); }
}

function _pem(label, der) {
  return "-----BEGIN " + label + "-----\n" + der.toString("base64").match(/.{1,64}/g).join("\n") +
    "\n-----END " + label + "-----\n";
}

// { "CERTIFICATE": pem, "X509 CERTIFICATE": pem, "TRUSTED CERTIFICATE": pem }.
// The TRUSTED CERTIFICATE body is the certificate followed by an empty
// auxiliary-trust SEQUENCE.
function caLabels(der) {
  return {
    "CERTIFICATE":         _pem("CERTIFICATE", der),
    "X509 CERTIFICATE":    _pem("X509 CERTIFICATE", der),
    "TRUSTED CERTIFICATE": _pem("TRUSTED CERTIFICATE", Buffer.concat([der, Buffer.from("3000", "hex")])),
  };
}

module.exports = {
  DECOY_ANCHOR_COMPROMISED_DER: DECOY_ANCHOR_COMPROMISED_DER,
  DECOY_ANCHOR_CONTROL_DER:     DECOY_ANCHOR_CONTROL_DER,
  DECOY_DER:                    DECOY_DER,
  DECOY_LEAF_COMPROMISED_DER:   DECOY_LEAF_COMPROMISED_DER,
  DECOY_LEAF_CONTROL_DER:       DECOY_LEAF_CONTROL_DER,
  decoyChain:                   decoyChain,
  withDefaultAnchor:            withDefaultAnchor,
  caLabels:                     caLabels,
};
