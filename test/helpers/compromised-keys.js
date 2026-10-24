// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// Compromised-key fixtures: keys whose private half anyone can hold.
//
// - EDELLROOT_CERT_PEM is the eDellRoot certificate Dell shipped with its
//   private key in 2015. Its key is on the list @blamejs/pki publishes. Only
//   the certificate is stored here.
// - ecKeyPair(curve, d) derives an EC key pair from a private scalar, so a
//   test builds a key whose scalar is 1 (or n - 1) at run time instead of
//   storing a private key.
// - The certificates below were minted with @blamejs/pki 0.9.5, the last
//   release that certified a compromised key. Each COMPROMISED_* fixture has a
//   CONTROL_* twin that differs only in the private scalar, so a test can show
//   a refusal comes from the key and nothing else.

var crypto = require("node:crypto");

var EDELLROOT_CERT_PEM =
  "-----BEGIN CERTIFICATE-----\n" +
  "MIIC8zCCAd+gAwIBAgIQa8V7lRiTqpdLYkrAiPw7tjAJBgUrDgMCHQUAMBQxEjAQ\n" +
  "BgNVBAMTCWVEZWxsUm9vdDAeFw0xNTA0MDcxMDIzMjdaFw0zOTEyMzEyMzU5NTla\n" +
  "MBQxEjAQBgNVBAMTCWVEZWxsUm9vdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC\n" +
  "AQoCggEBAL3RJg1uzVuEX0Hw4XWGzs6oI9W+o7HZdVdBMMVb4Gzb4uZjCTNjbPx4\n" +
  "b8LNFL1uArUt+5VVMQDsOTY3Lg/Xe/UNukY2b+0llUOzzBYYpbsFcco4n6SsTvDh\n" +
  "Ni5t+kPo7c23ZrYBPmOu82eEJ6cavs/t39u+wFOkXXwvRCiHA/lWyNWNEPh17+bC\n" +
  "EP3q5N+JrV+6Ho3zQPEv5QUJYdmXsMmD2CMQojeQUj68J91P5w5BKjurG0xjivzh\n" +
  "Soie9ym7VRwLFjWScRuw/9XV6CLqTyL5xrqiiDp1uTOuqNj3uxyts9ocbsoJXuxj\n" +
  "5iEYkSM1nvLupEv+lgy9WqzIEFMm1l8CAwEAAaNJMEcwRQYDVR0BBD4wPIAQYA/f\n" +
  "EzPwmaRcZuSaa/VZ1KEWMBQxEjAQBgNVBAMTCWVEZWxsUm9vdIIQa8V7lRiTqpdL\n" +
  "YkrAiPw7tjAJBgUrDgMCHQUAA4IBAQArfdcScsezj8ooJ92UwwnPgg36noOgiUs5\n" +
  "XzPLP4h0JpUYQVKB9hY1WTDwRUfTKGh7oNOowd027a/rVSb/TNeoiJIvMKn4gbvV\n" +
  "CWAiHhO8u2u0RkHCDVsa7e0i4ncpueWsihjn6jBrY8T+7eDYwiFT/F03A8NJ7mK5\n" +
  "lZA8SFd5CTDy3EBUU5UwzXUc5HoIRUxXSPycu3aIBWawg3sCdKiAoikScPAWj0bM\n" +
  "0vmsP/8QSlTOBqO+QFQ6R82BtTvBNU3qbVICV4QObsxib++FAFL56NApPqskg7Vz\n" +
  "LfNIAjKabHUcjbuZkmg6jr4BfYW7+oQDHCsYgADjjKGdKz/8U/fP\n" +
  "-----END CERTIFICATE-----\n";

// node curve name -> [JWK crv, scalar width in bytes, group order n]
var CURVES = Object.freeze({
  "prime256v1": Object.freeze(["P-256", 32,
    BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")]),
  "secp384r1": Object.freeze(["P-384", 48,
    BigInt("0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf" +
           "581a0db248b0a77aecec196accc52973")]),
  "secp521r1": Object.freeze(["P-521", 66,
    BigInt("0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" +
           "fa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409")]),
  "secp256k1": Object.freeze(["secp256k1", 32,
    BigInt("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")]),
});

// The private scalar d (a BigInt, 1 <= d < n) as a big-endian buffer of the
// curve's width.
function scalarBytes(curve, d) {
  var width = CURVES[curve][1];
  return Buffer.from(d.toString(16).padStart(width * 2, "0"), "hex");
}

// { privateKey, publicKey } KeyObjects for the private scalar d on curve.
function ecKeyPair(curve, d) {
  var priv = scalarBytes(curve, d);
  var ecdh = crypto.createECDH(curve);
  ecdh.setPrivateKey(priv);
  var pub = ecdh.getPublicKey();
  var width = CURVES[curve][1];
  var jwk = {
    kty: "EC", crv: CURVES[curve][0],
    x: pub.subarray(1, 1 + width).toString("base64url"),
    y: pub.subarray(1 + width).toString("base64url"),
  };
  return {
    privateKey: crypto.createPrivateKey({ format: "jwk", key: Object.assign({ d: priv.toString("base64url") }, jwk) }),
    publicKey:  crypto.createPublicKey({ format: "jwk", key: jwk }),
  };
}

// A non-small private scalar derived from a label.
function labelScalar(curve, label) {
  var n = CURVES[curve][2];
  var h = crypto.createHash("sha512").update(label, "utf8").digest("hex");
  return (BigInt("0x" + h) % (n - 2n)) + 1n;
}

function certPem(der) {
  return "-----BEGIN CERTIFICATE-----\n" +
    der.toString("base64").match(/.{1,64}/g).join("\n") +
    "\n-----END CERTIFICATE-----\n";
}

// P-384 CA certificates (subject "blamejs CA", OU "CAv1", cA:true pathLen 0,
// keyCertSign + cRLSign, 2026-01-01 .. 2099-12-31). Private scalar 1 for the
// compromised CA; SHA-384("blamejs mtls-ca fixture CA") for the control.
var P384_COMPROMISED_CA_DER = Buffer.from(
  "MIIBujCCAUGgAwIBAgIBATAKBggqhkjOPQQDAzAkMRMwEQYDVQQDDApibGFtZWpz" +
  "IENBMQ0wCwYDVQQLDARDQXYxMCAXDTI2MDEwMTAwMDAwMFoYDzIwOTkxMjMxMDAw" +
  "MDAwWjAkMRMwEQYDVQQDDApibGFtZWpzIENBMQ0wCwYDVQQLDARDQXYxMHYwEAYH" +
  "KoZIzj0CAQYFK4EEACIDYgAEqofKIr6LBTeOscce8yCtdG4dO2KLp5uYWfdB4IJU" +
  "KjhVAvJdv1UpbDpUXjhydgq3NhfeSpYmLG9dnpi/kpLcKfj0Hb0omhR86doxE7Xw" +
  "uMAKYLHOHX6BnXpDHXyQ6g5fo0UwQzAdBgNVHQ4EFgQUKjNj8AWfLatMUdEFKssP" +
  "tjHYkMgwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAwCgYIKoZI" +
  "zj0EAwMDZwAwZAIwJfvdGHU4PnCbluXpdSi1XLxrp2CZNoiR5zbO6wlahvOFFWXx" +
  "TzXHFxTnaYE+IDMCAjBQPiV2/g+WlqETuaslRGO1RmAV0+l+k4bT2ijEliM6fW1h" +
  "ixCstPzwXOYQN6WLNpQ=", "base64");
var P384_CONTROL_CA_DER = Buffer.from(
  "MIIBvDCCAUGgAwIBAgIBATAKBggqhkjOPQQDAzAkMRMwEQYDVQQDDApibGFtZWpz" +
  "IENBMQ0wCwYDVQQLDARDQXYxMCAXDTI2MDEwMTAwMDAwMFoYDzIwOTkxMjMxMDAw" +
  "MDAwWjAkMRMwEQYDVQQDDApibGFtZWpzIENBMQ0wCwYDVQQLDARDQXYxMHYwEAYH" +
  "KoZIzj0CAQYFK4EEACIDYgAE3SkDaCM5p7VIkjpqgsVPiiWvUGr5nF5wzJ2UTghz" +
  "oRyGeyy52j7ia78myO2fv5YRxs7Ua8/t8izjFGIxhMi5hz5ZOxt5eRQCfqyyhG1Z" +
  "zwlsybfQTsgF9BCcuxt/q1TUo0UwQzAdBgNVHQ4EFgQUtACZ8QJfCMojW4TqLCyM" +
  "COs9pBcwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAwCgYIKoZI" +
  "zj0EAwMDaQAwZgIxAIBWG1jvHXq63d4QEUm7CyyySBA4Kbg8xjGF2Jwebc/ZGVuC" +
  "XoMuvUE4gaLoUxQtuAIxAJqXqYywjDFAtq8/+AtkA18XrjmivIoXyTvfc2/1rvT7" +
  "Q93OrbdWAMMuA6kp++DBbg==", "base64");

function _p384PrivatePem(d) {
  var e = crypto.createECDH("secp384r1");
  e.setPrivateKey(d);
  var p = e.getPublicKey();
  return crypto.createPrivateKey({ format: "jwk", key: {
    kty: "EC", crv: "P-384", d: d.toString("base64url"),
    x: p.subarray(1, 49).toString("base64url"),
    y: p.subarray(49).toString("base64url"),
  } }).export({ type: "pkcs8", format: "pem" });
}

// { caCertPem, caKeyPem } for each P-384 CA, the shape b.mtlsCa.commit takes.
function p384CompromisedCa() {
  return { caCertPem: certPem(P384_COMPROMISED_CA_DER), caKeyPem: _p384PrivatePem(scalarBytes("secp384r1", 1n)) };
}
function p384ControlCa() {
  return {
    caCertPem: certPem(P384_CONTROL_CA_DER),
    caKeyPem:  _p384PrivatePem(crypto.createHash("sha384").update("blamejs mtls-ca fixture CA").digest()),
  };
}

// P-256 packed-attestation chains (CA "Test Attestation CA" -> leaf "Test
// Authenticator", OU "Authenticator Attestation", 2026-01-01 .. 2099-12-31).
// CA private scalar 1 for the compromised chain; SHA-256("blamejs passkey
// attestation fixture CA") for the control. Both leaves carry the key whose
// scalar is SHA-256("blamejs passkey attestation fixture leaf").
var P256_COMPROMISED_CA_DER = Buffer.from(
  "MIIBbzCCARWgAwIBAgIBATAKBggqhkjOPQQDAjAeMRwwGgYDVQQDDBNUZXN0IEF0" +
  "dGVzdGF0aW9uIENBMCAXDTI2MDEwMTAwMDAwMFoYDzIwOTkxMjMxMDAwMDAwWjAe" +
  "MRwwGgYDVQQDDBNUZXN0IEF0dGVzdGF0aW9uIENBMFkwEwYHKoZIzj0CAQYIKoZI" +
  "zj0DAQcDQgAEaxfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpZP40Li/hp/" +
  "m47n60p8D54WK84zV2sxXs7LtkBoN79R9aNCMEAwHQYDVR0OBBYEFLRno5mete+m" +
  "cd4AMvCKnJ5e/aDhMA4GA1UdDwEB/wQEAwICBDAPBgNVHRMBAf8EBTADAQH/MAoG" +
  "CCqGSM49BAMCA0gAMEUCIQDPc1b/a+cSoHDdPcuiHAme0VJ9bMQBWh+fcDTavUg2" +
  "AQIgRZl7v2OLBBc3euLn5EYpexHN2lnlOy+vAox/gwJsuP0=", "base64");
var P256_COMPROMISED_LEAF_DER = Buffer.from(
  "MIIBuzCCAWKgAwIBAgIBAjAKBggqhkjOPQQDAjAeMRwwGgYDVQQDDBNUZXN0IEF0" +
  "dGVzdGF0aW9uIENBMCAXDTI2MDEwMTAwMDAwMFoYDzIwOTkxMjMxMDAwMDAwWjBd" +
  "MRswGQYDVQQDDBJUZXN0IEF1dGhlbnRpY2F0b3IxIjAgBgNVBAsMGUF1dGhlbnRp" +
  "Y2F0b3IgQXR0ZXN0YXRpb24xDTALBgNVBAoMBFRlc3QxCzAJBgNVBAYTAlVTMFkw" +
  "EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMENd85I/oNxmWYYx8xdIyO0sb4E6BdH/" +
  "IhgOEHabvTLAJedLQMJCFWUD0vP9SHqEmU7fwqrb70B6tMSbDZn/faNQME4wHQYD" +
  "VR0OBBYEFJ+PDowqTRvdNQ/HsGfHyML/IqUsMB8GA1UdIwQYMBaAFLRno5mete+m" +
  "cd4AMvCKnJ5e/aDhMAwGA1UdEwEB/wQCMAAwCgYIKoZIzj0EAwIDRwAwRAIgA5k+" +
  "CQglZ2UC+mce2FWRnVnbqCorJRyL6qx4++DE/a8CIHQJxoR4QbQTtX2+U0+cs0FT" +
  "byBdOfFZ97zw0/Jvxbrx", "base64");
var P256_CONTROL_CA_DER = Buffer.from(
  "MIIBbzCCARWgAwIBAgIBATAKBggqhkjOPQQDAjAeMRwwGgYDVQQDDBNUZXN0IEF0" +
  "dGVzdGF0aW9uIENBMCAXDTI2MDEwMTAwMDAwMFoYDzIwOTkxMjMxMDAwMDAwWjAe" +
  "MRwwGgYDVQQDDBNUZXN0IEF0dGVzdGF0aW9uIENBMFkwEwYHKoZIzj0CAQYIKoZI" +
  "zj0DAQcDQgAEP7tmSzDY9hQMfhmL2oux7XQqKXUefo6d2MzX8/GYBw5JYO9+J8+4" +
  "MsHLfGhVAs2i0QntShv0RN7lHR2N15QIU6NCMEAwHQYDVR0OBBYEFJERbgi4hqyL" +
  "mHG3Prr29nwdRBa8MA4GA1UdDwEB/wQEAwICBDAPBgNVHRMBAf8EBTADAQH/MAoG" +
  "CCqGSM49BAMCA0gAMEUCIQCJaeUVESw5PQNxk0yO60IPEzRhdhiYQklD+gxcsCmG" +
  "1AIgDlcOJoASyfjnL9cxhvgTKUr6zbgA9AQPHh9pmbc4G1E=", "base64");
var P256_CONTROL_LEAF_DER = Buffer.from(
  "MIIBvTCCAWKgAwIBAgIBAjAKBggqhkjOPQQDAjAeMRwwGgYDVQQDDBNUZXN0IEF0" +
  "dGVzdGF0aW9uIENBMCAXDTI2MDEwMTAwMDAwMFoYDzIwOTkxMjMxMDAwMDAwWjBd" +
  "MRswGQYDVQQDDBJUZXN0IEF1dGhlbnRpY2F0b3IxIjAgBgNVBAsMGUF1dGhlbnRp" +
  "Y2F0b3IgQXR0ZXN0YXRpb24xDTALBgNVBAoMBFRlc3QxCzAJBgNVBAYTAlVTMFkw" +
  "EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMENd85I/oNxmWYYx8xdIyO0sb4E6BdH/" +
  "IhgOEHabvTLAJedLQMJCFWUD0vP9SHqEmU7fwqrb70B6tMSbDZn/faNQME4wHQYD" +
  "VR0OBBYEFJ+PDowqTRvdNQ/HsGfHyML/IqUsMB8GA1UdIwQYMBaAFJERbgi4hqyL" +
  "mHG3Prr29nwdRBa8MAwGA1UdEwEB/wQCMAAwCgYIKoZIzj0EAwIDSQAwRgIhANgP" +
  "xR7XZ117BR43clf9j5qMaZcS0Fxxrzqb7qEEBLP9AiEAg7NSpMrTXzxWjkiTSx8/" +
  "U0AekOF2Wh44PTzhqyJiCKU=", "base64");

// P-256 TLS chains: root "blamejs TLS fixture root" -> intermediate "blamejs
// TLS fixture intermediate" (cA:true pathLen 0) -> leaf "localhost" (SAN
// localhost + 127.0.0.1, serverAuth), 2026-01-01 .. 2099-12-31. The root's
// scalar is SHA-256("blamejs tls fixture root"), the leaf's is
// SHA-256("blamejs tls fixture leaf"). The intermediate's scalar is 1 in the
// compromised chain and SHA-256("blamejs tls fixture intermediate") in the
// control chain. Both chains share the root and the leaf key.
var TLS_ROOT_DER = Buffer.from(
  "MIIBejCCAR+gAwIBAgIBATAKBggqhkjOPQQDAjAjMSEwHwYDVQQDDBhibGFtZWpz" +
  "IFRMUyBmaXh0dXJlIHJvb3QwIBcNMjYwMTAxMDAwMDAwWhgPMjA5OTEyMzEwMDAw" +
  "MDBaMCMxITAfBgNVBAMMGGJsYW1lanMgVExTIGZpeHR1cmUgcm9vdDBZMBMGByqG" +
  "SM49AgEGCCqGSM49AwEHA0IABL4V1a7B3xpGH4VWHNuQGDNBNW+oG18pTzF5aB0u" +
  "DwVtbJjTLoTVQuR2OfwvNzOzJ9Ei1IINw0A2P1y3JIgqiKajQjBAMB0GA1UdDgQW" +
  "BBTybUrgXSqZIuWV+rr9VzTgQfpIIzAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/" +
  "BAUwAwEB/zAKBggqhkjOPQQDAgNJADBGAiEA1K27x7aV2C7i/agva7FRZuzXDn1x" +
  "AGjuNVxIcA0F+H8CIQCGtks0Dhl3KK1liYq6bmDcnsIGySn4EwxzfCawv1F+Hg==", "base64");
var TLS_COMPROMISED_INTERMEDIATE_DER = Buffer.from(
  "MIIBpTCCAUugAwIBAgIBAjAKBggqhkjOPQQDAjAjMSEwHwYDVQQDDBhibGFtZWpz" +
  "IFRMUyBmaXh0dXJlIHJvb3QwIBcNMjYwMTAxMDAwMDAwWhgPMjA5OTEyMzEwMDAw" +
  "MDBaMCsxKTAnBgNVBAMMIGJsYW1lanMgVExTIGZpeHR1cmUgaW50ZXJtZWRpYXRl" +
  "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaxfR8uEsQkf4vOblY6RA8ncDfYEt" +
  "6zOg9KE5RdiYwpZP40Li/hp/m47n60p8D54WK84zV2sxXs7LtkBoN79R9aNmMGQw" +
  "HQYDVR0OBBYEFLRno5mete+mcd4AMvCKnJ5e/aDhMB8GA1UdIwQYMBaAFPJtSuBd" +
  "Kpki5ZX6uv1XNOBB+kgjMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/" +
  "AgEAMAoGCCqGSM49BAMCA0gAMEUCICeGo9Wy27HL2o8WHgYEOktsYrsAjhgBqEwS" +
  "Rpy8oFXzAiEA2rU05R3k54eLKbLySxutVb7OiYlcXw4hQMGjdHZylnI=", "base64");
var TLS_COMPROMISED_LEAF_DER = Buffer.from(
  "MIIBwjCCAWmgAwIBAgIBAzAKBggqhkjOPQQDAjArMSkwJwYDVQQDDCBibGFtZWpz" +
  "IFRMUyBmaXh0dXJlIGludGVybWVkaWF0ZTAgFw0yNjAxMDEwMDAwMDBaGA8yMDk5" +
  "MTIzMTAwMDAwMFowFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYI" +
  "KoZIzj0DAQcDQgAEY6bH26RBrHWzxd7endpnqbuOCOFxl4G0deDo1MCK8ciQeOnr" +
  "d9F27BsMEPmTQgcz91TEMamJR2YZbhR0gPGibaOBkjCBjzAdBgNVHQ4EFgQU0Lx+" +
  "O6AkeZY9ba1IDpp4ao6KNiIwHwYDVR0jBBgwFoAUtGejmZ6176Zx3gAy8Iqcnl79" +
  "oOEwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB" +
  "/wQCMAAwGgYDVR0RBBMwEYIJbG9jYWxob3N0hwR/AAABMAoGCCqGSM49BAMCA0cA" +
  "MEQCIAD8slwF17izg8i4hVfBtIkx4aBteFIONAnX5DPyPEE6AiA3wvMMVj5087eA" +
  "3A97bOvuibPHU8kJ+G6M4fhh1vwxdA==", "base64");
var TLS_CONTROL_INTERMEDIATE_DER = Buffer.from(
  "MIIBpTCCAUugAwIBAgIBAjAKBggqhkjOPQQDAjAjMSEwHwYDVQQDDBhibGFtZWpz" +
  "IFRMUyBmaXh0dXJlIHJvb3QwIBcNMjYwMTAxMDAwMDAwWhgPMjA5OTEyMzEwMDAw" +
  "MDBaMCsxKTAnBgNVBAMMIGJsYW1lanMgVExTIGZpeHR1cmUgaW50ZXJtZWRpYXRl" +
  "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEO6wouIGcwGGSHY9Cs2KPYuYCPmD7" +
  "yffmLnkQ272ET2t3jJKwbfRLDRX8d9bs9APKpXNS/E4CLOU2NnI980FB6KNmMGQw" +
  "HQYDVR0OBBYEFG45kPCUOLKWcN95AzuAnWuAuc5cMB8GA1UdIwQYMBaAFPJtSuBd" +
  "Kpki5ZX6uv1XNOBB+kgjMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/" +
  "AgEAMAoGCCqGSM49BAMCA0gAMEUCIFyS1UaUBwPn7efLl6GqqjBe1nxiZhFFZQ77" +
  "wGqcor2OAiEAhUkxOSTRbL5ltjFEcfo48BHKPke+K3mPXbpZGWQr9VM=", "base64");
var TLS_CONTROL_LEAF_DER = Buffer.from(
  "MIIBwjCCAWmgAwIBAgIBAzAKBggqhkjOPQQDAjArMSkwJwYDVQQDDCBibGFtZWpz" +
  "IFRMUyBmaXh0dXJlIGludGVybWVkaWF0ZTAgFw0yNjAxMDEwMDAwMDBaGA8yMDk5" +
  "MTIzMTAwMDAwMFowFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYI" +
  "KoZIzj0DAQcDQgAEY6bH26RBrHWzxd7endpnqbuOCOFxl4G0deDo1MCK8ciQeOnr" +
  "d9F27BsMEPmTQgcz91TEMamJR2YZbhR0gPGibaOBkjCBjzAdBgNVHQ4EFgQU0Lx+" +
  "O6AkeZY9ba1IDpp4ao6KNiIwHwYDVR0jBBgwFoAUbjmQ8JQ4spZw33kDO4Cda4C5" +
  "zlwwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB" +
  "/wQCMAAwGgYDVR0RBBMwEYIJbG9jYWxob3N0hwR/AAABMAoGCCqGSM49BAMCA0cA" +
  "MEQCICvdgWQ7tNW3rm2ODRpSYkHxcQPpkCPBmTOrb10BMfu3AiByuWhZUEUKj/06" +
  "HwBhezNdl+edepOpFO8yEl5Ui++Cog==", "base64");

// TLS server options { key, cert } for one fixture chain ("compromised" or
// "control"): the leaf key in PKCS#8 PEM and the leaf + intermediate PEM, and
// the root PEM a client passes as `ca`.
function tlsChain(which) {
  var tag = which === "compromised" ? "COMPROMISED" : "CONTROL";
  var leafD = crypto.createHash("sha256").update("blamejs tls fixture leaf", "utf8").digest();
  var leafKey = ecKeyPair("prime256v1", BigInt("0x" + leafD.toString("hex"))).privateKey;
  var inter = tag === "COMPROMISED" ? TLS_COMPROMISED_INTERMEDIATE_DER : TLS_CONTROL_INTERMEDIATE_DER;
  var leaf = tag === "COMPROMISED" ? TLS_COMPROMISED_LEAF_DER : TLS_CONTROL_LEAF_DER;
  return {
    key:    leafKey.export({ type: "pkcs8", format: "pem" }),
    cert:   certPem(leaf) + certPem(inter),
    rootCa: certPem(TLS_ROOT_DER),
  };
}

// P-256 clientAuth leaves "blamejs TLS fixture client" (2026-01-01 ..
// 2099-12-31), minted with @blamejs/pki 0.9.5. Both carry the private scalar
// SHA-256("blamejs tls fixture client"). The first is issued by
// TLS_COMPROMISED_INTERMEDIATE_DER (private key 1), the second by
// TLS_CONTROL_INTERMEDIATE_DER.
var TLS_CLIENT_UNDER_COMPROMISED_INTERMEDIATE_DER = Buffer.from(
  "MIIBtTCCAVygAwIBAgIBBjAKBggqhkjOPQQDAjArMSkwJwYDVQQDDCBibGFtZWpz" +
  "IFRMUyBmaXh0dXJlIGludGVybWVkaWF0ZTAgFw0yNjAxMDEwMDAwMDBaGA8yMDk5" +
  "MTIzMTAwMDAwMFowJTEjMCEGA1UEAwwaYmxhbWVqcyBUTFMgZml4dHVyZSBjbGll" +
  "bnQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAART030RD73hYiI6rswlqEYEQWI5" +
  "UZXQi1gjvQ4Gqt+Tj0MShw3KOLL9LZe8iBfkLvadeQwqTVFHo1lYuGxwgdlpo3Uw" +
  "czAdBgNVHQ4EFgQUsnO/VzpaHx5fCob5NTSbqOtUUeYwHwYDVR0jBBgwFoAUtGej" +
  "mZ6176Zx3gAy8Iqcnl79oOEwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsG" +
  "AQUFBwMCMAwGA1UdEwEB/wQCMAAwCgYIKoZIzj0EAwIDRwAwRAIgaaNGYGAdTyHs" +
  "geqFtVvT4VbTV7Ohe5iuflwFDqc4mrUCID/6xO9+jzqz//ZRqA+Mn2xgl95E+hdN" +
  "ETaiKaLyML7t", "base64");
var TLS_CLIENT_UNDER_CONTROL_INTERMEDIATE_DER = Buffer.from(
  "MIIBtzCCAVygAwIBAgIBBzAKBggqhkjOPQQDAjArMSkwJwYDVQQDDCBibGFtZWpz" +
  "IFRMUyBmaXh0dXJlIGludGVybWVkaWF0ZTAgFw0yNjAxMDEwMDAwMDBaGA8yMDk5" +
  "MTIzMTAwMDAwMFowJTEjMCEGA1UEAwwaYmxhbWVqcyBUTFMgZml4dHVyZSBjbGll" +
  "bnQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAART030RD73hYiI6rswlqEYEQWI5" +
  "UZXQi1gjvQ4Gqt+Tj0MShw3KOLL9LZe8iBfkLvadeQwqTVFHo1lYuGxwgdlpo3Uw" +
  "czAdBgNVHQ4EFgQUsnO/VzpaHx5fCob5NTSbqOtUUeYwHwYDVR0jBBgwFoAUbjmQ" +
  "8JQ4spZw33kDO4Cda4C5zlwwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsG" +
  "AQUFBwMCMAwGA1UdEwEB/wQCMAAwCgYIKoZIzj0EAwIDSQAwRgIhAIgYv5PAUIBb" +
  "BpfJ3ZSfWaItzaE95chH7dZQf2ETDL7wAiEAuWP2mS00fbU3TpIWqkOAVR5dn/Ft" +
  "HsXFAeKLSreS0o0=", "base64");

// TLS client options { cert, key } for one client chain ("compromised" or
// "control"): the client leaf + intermediate PEM and the leaf key.
function tlsClient(which) {
  var d = BigInt("0x" + crypto.createHash("sha256").update("blamejs tls fixture client", "utf8").digest("hex"));
  var compromised = which === "compromised";
  return {
    cert: certPem(compromised ? TLS_CLIENT_UNDER_COMPROMISED_INTERMEDIATE_DER : TLS_CLIENT_UNDER_CONTROL_INTERMEDIATE_DER) +
          certPem(compromised ? TLS_COMPROMISED_INTERMEDIATE_DER : TLS_CONTROL_INTERMEDIATE_DER),
    key:  ecKeyPair("prime256v1", d).privateKey.export({ type: "pkcs8", format: "pem" }),
  };
}

// The private key both P-256 leaves carry.
function p256AttestationLeafKey() {
  var d = crypto.createHash("sha256").update("blamejs passkey attestation fixture leaf", "utf8").digest();
  return ecKeyPair("prime256v1", BigInt("0x" + d.toString("hex"))).privateKey;
}

module.exports = {
  EDELLROOT_CERT_PEM:        EDELLROOT_CERT_PEM,
  CURVES:                    CURVES,
  scalarBytes:               scalarBytes,
  ecKeyPair:                 ecKeyPair,
  labelScalar:               labelScalar,
  certPem:                   certPem,
  P384_COMPROMISED_CA_DER:   P384_COMPROMISED_CA_DER,
  P384_CONTROL_CA_DER:       P384_CONTROL_CA_DER,
  p384CompromisedCa:         p384CompromisedCa,
  p384ControlCa:             p384ControlCa,
  P256_COMPROMISED_CA_DER:   P256_COMPROMISED_CA_DER,
  P256_COMPROMISED_LEAF_DER: P256_COMPROMISED_LEAF_DER,
  P256_CONTROL_CA_DER:       P256_CONTROL_CA_DER,
  P256_CONTROL_LEAF_DER:     P256_CONTROL_LEAF_DER,
  p256AttestationLeafKey:    p256AttestationLeafKey,
  TLS_ROOT_DER:                     TLS_ROOT_DER,
  TLS_COMPROMISED_INTERMEDIATE_DER: TLS_COMPROMISED_INTERMEDIATE_DER,
  TLS_COMPROMISED_LEAF_DER:         TLS_COMPROMISED_LEAF_DER,
  TLS_CONTROL_INTERMEDIATE_DER:     TLS_CONTROL_INTERMEDIATE_DER,
  TLS_CONTROL_LEAF_DER:             TLS_CONTROL_LEAF_DER,
  tlsChain:                         tlsChain,
  TLS_CLIENT_UNDER_COMPROMISED_INTERMEDIATE_DER: TLS_CLIENT_UNDER_COMPROMISED_INTERMEDIATE_DER,
  TLS_CLIENT_UNDER_CONTROL_INTERMEDIATE_DER:     TLS_CLIENT_UNDER_CONTROL_INTERMEDIATE_DER,
  tlsClient:                                     tlsClient,
};
