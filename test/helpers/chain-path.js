// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// Certificate chains whose sent order differs from the path OpenSSL verifies.
// Every key is P-256 with private scalar SHA-256(label), except the issuing
// CA in the compromised set, whose scalar is 1. The certificates were minted
// with @blamejs/pki 0.9.5 (2026-01-01 .. 2099-12-31 unless noted). Leaves are
// "localhost" with SAN localhost + 127.0.0.1 and both serverAuth and
// clientAuth, so one chain serves either end of a connection.
//
// - evasionChain(which) sits under the TLS fixture root (ck.TLS_ROOT_DER).
//   The path OpenSSL verifies is leaf <- attacker CA <- issuing CA <- root.
//   The issuing CA's key is 1 in "compromised" and ordinary in "control".
//   The "-evasion" variants send an expired alternate attacker CA (same key,
//   issued by a self-signed fake root, 2020-01-01 .. 2021-01-01) and the fake
//   root ahead of that path, so getPeerCertificate(true) shows leaf <-
//   expired alternate <- fake root.
// - crossChain(which) sits under NEW_ROOT_DER. "cross" sends leaf <-
//   intermediate <- an expired cross-certificate with the new root's name and
//   key issued by OLD_ROOT_DER (2020-01-01 .. 2021-01-01), the shape of a
//   root cross-signed by an older one. "intermediate" sends leaf <-
//   intermediate, and "direct" sends a leaf the new root issued.

var crypto = require("node:crypto");
var ck     = require("./compromised-keys");

var ISSUING_CA_COMPROMISED_DER = Buffer.from(
  "MIIBoDCCAUegAwIBAgIBETAKBggqhkjOPQQDAjAjMSEwHwYDVQQDDBhibGFtZWpz" +
  "IFRMUyBmaXh0dXJlIHJvb3QwIBcNMjYwMTAxMDAwMDAwWhgPMjA5OTEyMzEwMDAw" +
  "MDBaMCoxKDAmBgNVBAMMH2JsYW1lanMgcGF0aCBmaXh0dXJlIGlzc3VpbmcgQ0Ew" +
  "WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARrF9Hy4SxCR/i85uVjpEDydwN9gS3r" +
  "M6D0oTlF2JjClk/jQuL+Gn+bjufrSnwPnhYrzjNXazFezsu2QGg3v1H1o2MwYTAd" +
  "BgNVHQ4EFgQUtGejmZ6176Zx3gAy8Iqcnl79oOEwHwYDVR0jBBgwFoAU8m1K4F0q" +
  "mSLllfq6/Vc04EH6SCMwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8w" +
  "CgYIKoZIzj0EAwIDRwAwRAIgDHtZtPpwqku0izykpGa8TqcoV1Ng3PpDVvAyjOX5" +
  "7nUCIFSa9/AsQLCygd9XBbRooDp4+6/1ClXHWF77KGq3fA7N", "base64");
var ISSUING_CA_CONTROL_DER = Buffer.from(
  "MIIBojCCAUegAwIBAgIBEjAKBggqhkjOPQQDAjAjMSEwHwYDVQQDDBhibGFtZWpz" +
  "IFRMUyBmaXh0dXJlIHJvb3QwIBcNMjYwMTAxMDAwMDAwWhgPMjA5OTEyMzEwMDAw" +
  "MDBaMCoxKDAmBgNVBAMMH2JsYW1lanMgcGF0aCBmaXh0dXJlIGlzc3VpbmcgQ0Ew" +
  "WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAT0FjJBMW1GRGqnKS5WGjH6xqL+Q+rE" +
  "Wx8p5NRfFSmR5Di7q9dcuw8+4gLRH3mXYvucnnFPRwurpNNtNI5cGok5o2MwYTAd" +
  "BgNVHQ4EFgQUpX+Jg7v0rAOZ085NPinW9q4h7pYwHwYDVR0jBBgwFoAU8m1K4F0q" +
  "mSLllfq6/Vc04EH6SCMwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8w" +
  "CgYIKoZIzj0EAwIDSQAwRgIhAOTsVJmOChf9JokNzwWQ2R5P1/UgakKfVtdQwkQn" +
  "lY8GAiEAk8Ib1JdUEEfVU6jIa41j2EVhiSWVpVDDgwf5ruykcWU=", "base64");
var ATTACKER_CA_UNDER_COMPROMISED_DER = Buffer.from(
  "MIIBqjCCAU+gAwIBAgIBEzAKBggqhkjOPQQDAjAqMSgwJgYDVQQDDB9ibGFtZWpz" +
  "IHBhdGggZml4dHVyZSBpc3N1aW5nIENBMCAXDTI2MDEwMTAwMDAwMFoYDzIwOTkx" +
  "MjMxMDAwMDAwWjArMSkwJwYDVQQDDCBibGFtZWpzIHBhdGggZml4dHVyZSBhdHRh" +
  "Y2tlciBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABOuIS71VZSDcEXxnFDiB" +
  "hoGY5+bWZLPh7VthoTofaelCV6JvNnT9keaGjdNTpbd1FG17gPbOLMGHtwypJA3m" +
  "JfujYzBhMB0GA1UdDgQWBBTywRAkwowgv7t/s/5nclmMU39JyjAfBgNVHSMEGDAW" +
  "gBS0Z6OZnrXvpnHeADLwipyeXv2g4TAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/" +
  "BAUwAwEB/zAKBggqhkjOPQQDAgNJADBGAiEApMMtdyIQyZsgvTcVtPQhy5xfvt+t" +
  "WrUu52o4AFwBrKECIQCkEtb2dubxjTt6tc8BjEwFc/bKsQngM/y42w6wAfdmvw==", "base64");
var ATTACKER_CA_UNDER_CONTROL_DER = Buffer.from(
  "MIIBqjCCAU+gAwIBAgIBFDAKBggqhkjOPQQDAjAqMSgwJgYDVQQDDB9ibGFtZWpz" +
  "IHBhdGggZml4dHVyZSBpc3N1aW5nIENBMCAXDTI2MDEwMTAwMDAwMFoYDzIwOTkx" +
  "MjMxMDAwMDAwWjArMSkwJwYDVQQDDCBibGFtZWpzIHBhdGggZml4dHVyZSBhdHRh" +
  "Y2tlciBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABOuIS71VZSDcEXxnFDiB" +
  "hoGY5+bWZLPh7VthoTofaelCV6JvNnT9keaGjdNTpbd1FG17gPbOLMGHtwypJA3m" +
  "JfujYzBhMB0GA1UdDgQWBBTywRAkwowgv7t/s/5nclmMU39JyjAfBgNVHSMEGDAW" +
  "gBSlf4mDu/SsA5nTzk0+Kdb2riHuljAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/" +
  "BAUwAwEB/zAKBggqhkjOPQQDAgNJADBGAiEA+x6EDuoOAbCp+/bQNgP56Nuwqva6" +
  "M9/1dZsQvLmFatoCIQCnll3jdHGLBv+66vFrfUy0/lSvgO7tgpl+6HkQLZj7iQ==", "base64");
var FAKE_ROOT_DER = Buffer.from(
  "MIIBhjCCASugAwIBAgIBFTAKBggqhkjOPQQDAjApMScwJQYDVQQDDB5ibGFtZWpz" +
  "IHBhdGggZml4dHVyZSBmYWtlIHJvb3QwIBcNMjYwMTAxMDAwMDAwWhgPMjA5OTEy" +
  "MzEwMDAwMDBaMCkxJzAlBgNVBAMMHmJsYW1lanMgcGF0aCBmaXh0dXJlIGZha2Ug" +
  "cm9vdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABBfRzYi2sr8JehV9tv2W0bgA" +
  "rFHe9HmJruOxq6XK0BWA9jVa7jEQnmFXXWDwf8TFldYwqphEtnIQYIq+91mbuhqj" +
  "QjBAMB0GA1UdDgQWBBTGPceq9yCTWOH7sS9agSUwnSxj+zAOBgNVHQ8BAf8EBAMC" +
  "AQYwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNJADBGAiEAsV6AVEbBCJfF" +
  "05gdrQh57gac7W4aAsCdKy404QYgvRoCIQCHCvA8HwKcvB4zU3ladyDkdF5Suedc" +
  "FGmSKG2sl8OpRQ==", "base64");
var ATTACKER_CA_EXPIRED_ALTERNATE_DER = Buffer.from(
  "MIIBpTCCAUygAwIBAgIBFjAKBggqhkjOPQQDAjApMScwJQYDVQQDDB5ibGFtZWpz" +
  "IHBhdGggZml4dHVyZSBmYWtlIHJvb3QwHhcNMjAwMTAxMDAwMDAwWhcNMjEwMTAx" +
  "MDAwMDAwWjArMSkwJwYDVQQDDCBibGFtZWpzIHBhdGggZml4dHVyZSBhdHRhY2tl" +
  "ciBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABOuIS71VZSDcEXxnFDiBhoGY" +
  "5+bWZLPh7VthoTofaelCV6JvNnT9keaGjdNTpbd1FG17gPbOLMGHtwypJA3mJfuj" +
  "YzBhMB0GA1UdDgQWBBTywRAkwowgv7t/s/5nclmMU39JyjAfBgNVHSMEGDAWgBTG" +
  "Pceq9yCTWOH7sS9agSUwnSxj+zAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUw" +
  "AwEB/zAKBggqhkjOPQQDAgNHADBEAiAzx+HkGoqMWRMvA9JTlG3fOg54pf3w7v26" +
  "mxVYFJRnIwIgCmTB4/ZuZ31MsSo1OHByg3gAfnXyeK0lHVx/F1yQpec=", "base64");
var PATH_LEAF_DER = Buffer.from(
  "MIIBzDCCAXOgAwIBAgIBFzAKBggqhkjOPQQDAjArMSkwJwYDVQQDDCBibGFtZWpz" +
  "IHBhdGggZml4dHVyZSBhdHRhY2tlciBDQTAgFw0yNjAxMDEwMDAwMDBaGA8yMDk5" +
  "MTIzMTAwMDAwMFowFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYI" +
  "KoZIzj0DAQcDQgAEYw8uc3e9G0Wt2i4XgJ7lfL7dHYmQ2V7+qee6WwydYGw0BCOZ" +
  "1Ew9epdpAB0fKqZaspgZQBEhkUbiiJAznXCAC6OBnDCBmTAdBgNVHQ4EFgQUjDvv" +
  "GFSHoFojT9+xk7nU1oSUSi4wHwYDVR0jBBgwFoAU8sEQJMKMIL+7f7P+Z3JZjFN/" +
  "ScowDgYDVR0PAQH/BAQDAgeAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcD" +
  "AjAMBgNVHRMBAf8EAjAAMBoGA1UdEQQTMBGCCWxvY2FsaG9zdIcEfwAAATAKBggq" +
  "hkjOPQQDAgNHADBEAiBvlI0dlbVcEW/z+fpBwn0l7WJd9KG6yYdpudqQpzxy8wIg" +
  "OsF1gnvDwngtfzCQQ+kopU8eMw3d5MT/b9O32PzwHCU=", "base64");
var NEW_ROOT_DER = Buffer.from(
  "MIIBgzCCASmgAwIBAgIBGDAKBggqhkjOPQQDAjAoMSYwJAYDVQQDDB1ibGFtZWpz" +
  "IHBhdGggZml4dHVyZSBuZXcgcm9vdDAgFw0yNjAxMDEwMDAwMDBaGA8yMDk5MTIz" +
  "MTAwMDAwMFowKDEmMCQGA1UEAwwdYmxhbWVqcyBwYXRoIGZpeHR1cmUgbmV3IHJv" +
  "b3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR4xEYxVcae+d/BOGQZqsgo0+XX" +
  "L/AFwoq6HR3uQ4+G12L9vuxVklHJeaTlVBew2loIhkaJGEYwqtlEyM6WcRspo0Iw" +
  "QDAdBgNVHQ4EFgQUDnUfTMdztdNPxtGghcjMsOLljzgwDgYDVR0PAQH/BAQDAgEG" +
  "MA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIhANP4nQj6sCZzi+jG" +
  "Q3oDlhGLHaEldlmqcamtIVvCtJ32AiBYIoKDJt1Xm9fC5qvh1y4JElBG2Gs2LN41" +
  "jXEbF2bdkA==", "base64");
var OLD_ROOT_DER = Buffer.from(
  "MIIBgjCCASmgAwIBAgIBGTAKBggqhkjOPQQDAjAoMSYwJAYDVQQDDB1ibGFtZWpz" +
  "IHBhdGggZml4dHVyZSBvbGQgcm9vdDAgFw0yNjAxMDEwMDAwMDBaGA8yMDk5MTIz" +
  "MTAwMDAwMFowKDEmMCQGA1UEAwwdYmxhbWVqcyBwYXRoIGZpeHR1cmUgb2xkIHJv" +
  "b3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARh2p1Nh3zv8nsTdF/6+od7nIeb" +
  "Rw/+ikU/e8aJsnFxTE+ARDWZPALQ08plHGODP7PsTkjgoxEU7MYMgxTtSbnco0Iw" +
  "QDAdBgNVHQ4EFgQUG4bz1GQuZOHQ5kB7HFHy71oQstgwDgYDVR0PAQH/BAQDAgEG" +
  "MA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDRwAwRAIgfC3v57wPL1yMF/+q" +
  "iioUJTDqdxEmCjEQp43zrpwMGlwCIH79r8z1mMyVCyS/+nNHp7YCRGhV/+/9pXv7" +
  "O1fHYkdI", "base64");
var NEW_ROOT_CROSS_EXPIRED_DER = Buffer.from(
  "MIIBojCCAUigAwIBAgIBGjAKBggqhkjOPQQDAjAoMSYwJAYDVQQDDB1ibGFtZWpz" +
  "IHBhdGggZml4dHVyZSBvbGQgcm9vdDAeFw0yMDAxMDEwMDAwMDBaFw0yMTAxMDEw" +
  "MDAwMDBaMCgxJjAkBgNVBAMMHWJsYW1lanMgcGF0aCBmaXh0dXJlIG5ldyByb290" +
  "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeMRGMVXGnvnfwThkGarIKNPl1y/w" +
  "BcKKuh0d7kOPhtdi/b7sVZJRyXmk5VQXsNpaCIZGiRhGMKrZRMjOlnEbKaNjMGEw" +
  "HQYDVR0OBBYEFA51H0zHc7XTT8bRoIXIzLDi5Y84MB8GA1UdIwQYMBaAFBuG89Rk" +
  "LmTh0OZAexxR8u9aELLYMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/" +
  "MAoGCCqGSM49BAMCA0gAMEUCIBhSbh4Yutz2B2tOTwbuIl/o5weJSXW4MNbyUDtY" +
  "W4d7AiEA/KFRpX+u4VKj7Tj0zd1Ef9Da2WQr3Q6wuXy66xW0cRg=", "base64");
var NEW_ROOT_INTERMEDIATE_DER = Buffer.from(
  "MIIBqDCCAU6gAwIBAgIBGzAKBggqhkjOPQQDAjAoMSYwJAYDVQQDDB1ibGFtZWpz" +
  "IHBhdGggZml4dHVyZSBuZXcgcm9vdDAgFw0yNjAxMDEwMDAwMDBaGA8yMDk5MTIz" +
  "MTAwMDAwMFowLDEqMCgGA1UEAwwhYmxhbWVqcyBwYXRoIGZpeHR1cmUgaW50ZXJt" +
  "ZWRpYXRlMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEczzHi5N0vttdcyd2yKMv" +
  "2z1kTUFzKax6EiDSKJISp+SPDv7RemyXT75hk/PShWfG9+VncE6uV28o1bEh8OLe" +
  "taNjMGEwHQYDVR0OBBYEFJOfwA/cYpsqK4Q2XsT9LgSPc2riMB8GA1UdIwQYMBaA" +
  "FA51H0zHc7XTT8bRoIXIzLDi5Y84MA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8E" +
  "BTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIH5z4KtWpl2BCAlo8vGjLrUcgX91L8qs" +
  "Q/hnJaWqixcfAiEAucTWOn/eGMzqUN1z4CJ4h/xlaIgBIE0rDUINm8/mK4c=", "base64");
var NEW_ROOT_LEAF_DER = Buffer.from(
  "MIIBzjCCAXSgAwIBAgIBHDAKBggqhkjOPQQDAjAsMSowKAYDVQQDDCFibGFtZWpz" +
  "IHBhdGggZml4dHVyZSBpbnRlcm1lZGlhdGUwIBcNMjYwMTAxMDAwMDAwWhgPMjA5" +
  "OTEyMzEwMDAwMDBaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEG" +
  "CCqGSM49AwEHA0IABGMPLnN3vRtFrdouF4Ce5Xy+3R2JkNle/qnnulsMnWBsNAQj" +
  "mdRMPXqXaQAdHyqmWrKYGUARIZFG4oiQM51wgAujgZwwgZkwHQYDVR0OBBYEFIw7" +
  "7xhUh6BaI0/fsZO51NaElEouMB8GA1UdIwQYMBaAFJOfwA/cYpsqK4Q2XsT9LgSP" +
  "c2riMA4GA1UdDwEB/wQEAwIHgDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUH" +
  "AwIwDAYDVR0TAQH/BAIwADAaBgNVHREEEzARgglsb2NhbGhvc3SHBH8AAAEwCgYI" +
  "KoZIzj0EAwIDSAAwRQIhAOh6zMOt7WSqvrSZ00W/RBZ2ltWk15uXYAu+0dtRSz/u" +
  "AiBGQI82reefuDmwyPbu2knvH4yEazTOTqHzFtTbHRQ8lw==", "base64");
var NEW_ROOT_DIRECT_LEAF_DER = Buffer.from(
  "MIIByzCCAXCgAwIBAgIBHTAKBggqhkjOPQQDAjAoMSYwJAYDVQQDDB1ibGFtZWpz" +
  "IHBhdGggZml4dHVyZSBuZXcgcm9vdDAgFw0yNjAxMDEwMDAwMDBaGA8yMDk5MTIz" +
  "MTAwMDAwMFowFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZI" +
  "zj0DAQcDQgAEYw8uc3e9G0Wt2i4XgJ7lfL7dHYmQ2V7+qee6WwydYGw0BCOZ1Ew9" +
  "epdpAB0fKqZaspgZQBEhkUbiiJAznXCAC6OBnDCBmTAdBgNVHQ4EFgQUjDvvGFSH" +
  "oFojT9+xk7nU1oSUSi4wHwYDVR0jBBgwFoAUDnUfTMdztdNPxtGghcjMsOLljzgw" +
  "DgYDVR0PAQH/BAQDAgeAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAM" +
  "BgNVHRMBAf8EAjAAMBoGA1UdEQQTMBGCCWxvY2FsaG9zdIcEfwAAATAKBggqhkjO" +
  "PQQDAgNJADBGAiEAtFlFPuzD1t3umU/AQdGaWi3NpGy5SQmVPO1JfjFRVesCIQCJ" +
  "4pTS/HEcZ7hOQc+EJ+uq//W1j5zxsh59z1JWXb8xjA==", "base64");

// The PKCS#8 PEM private key every leaf here carries.
function leafKeyPem() {
  var d = crypto.createHash("sha256").update("blamejs path fixture leaf", "utf8").digest("hex");
  return ck.ecKeyPair("prime256v1", BigInt("0x" + d)).privateKey.export({ type: "pkcs8", format: "pem" });
}

var EVASION_CHAINS = {
  "compromised":         [PATH_LEAF_DER, ATTACKER_CA_UNDER_COMPROMISED_DER, ISSUING_CA_COMPROMISED_DER],
  "control":             [PATH_LEAF_DER, ATTACKER_CA_UNDER_CONTROL_DER, ISSUING_CA_CONTROL_DER],
  "compromised-evasion": [PATH_LEAF_DER, ATTACKER_CA_EXPIRED_ALTERNATE_DER, FAKE_ROOT_DER,
                          ATTACKER_CA_UNDER_COMPROMISED_DER, ISSUING_CA_COMPROMISED_DER],
  "control-evasion":     [PATH_LEAF_DER, ATTACKER_CA_EXPIRED_ALTERNATE_DER, FAKE_ROOT_DER,
                          ATTACKER_CA_UNDER_CONTROL_DER, ISSUING_CA_CONTROL_DER],
};

var CROSS_CHAINS = {
  "cross":        [NEW_ROOT_LEAF_DER, NEW_ROOT_INTERMEDIATE_DER, NEW_ROOT_CROSS_EXPIRED_DER],
  "intermediate": [NEW_ROOT_LEAF_DER, NEW_ROOT_INTERMEDIATE_DER],
  "direct":       [NEW_ROOT_DIRECT_LEAF_DER],
};

function _material(ders, anchorDer) {
  return {
    key:    leafKeyPem(),
    cert:   ders.map(ck.certPem).join(""),
    ders:   ders.slice(),
    anchor: ck.certPem(anchorDer),
  };
}

// { key, cert, ders, anchor } for one of "compromised", "control",
// "compromised-evasion" or "control-evasion".
function evasionChain(which) {
  if (!EVASION_CHAINS[which]) throw new Error("chain-path: unknown evasion chain " + which);
  return _material(EVASION_CHAINS[which], ck.TLS_ROOT_DER);
}

// { key, cert, ders, anchor } for one of "cross", "intermediate" or "direct".
function crossChain(which) {
  if (!CROSS_CHAINS[which]) throw new Error("chain-path: unknown cross chain " + which);
  return _material(CROSS_CHAINS[which], NEW_ROOT_DER);
}

module.exports = {
  ISSUING_CA_COMPROMISED_DER:        ISSUING_CA_COMPROMISED_DER,
  ISSUING_CA_CONTROL_DER:            ISSUING_CA_CONTROL_DER,
  ATTACKER_CA_UNDER_COMPROMISED_DER: ATTACKER_CA_UNDER_COMPROMISED_DER,
  ATTACKER_CA_UNDER_CONTROL_DER:     ATTACKER_CA_UNDER_CONTROL_DER,
  FAKE_ROOT_DER:                     FAKE_ROOT_DER,
  ATTACKER_CA_EXPIRED_ALTERNATE_DER: ATTACKER_CA_EXPIRED_ALTERNATE_DER,
  PATH_LEAF_DER:                     PATH_LEAF_DER,
  NEW_ROOT_DER:                      NEW_ROOT_DER,
  OLD_ROOT_DER:                      OLD_ROOT_DER,
  NEW_ROOT_CROSS_EXPIRED_DER:        NEW_ROOT_CROSS_EXPIRED_DER,
  NEW_ROOT_INTERMEDIATE_DER:         NEW_ROOT_INTERMEDIATE_DER,
  NEW_ROOT_LEAF_DER:                 NEW_ROOT_LEAF_DER,
  NEW_ROOT_DIRECT_LEAF_DER:          NEW_ROOT_DIRECT_LEAF_DER,
  leafKeyPem:                        leafKeyPem,
  evasionChain:                      evasionChain,
  crossChain:                        crossChain,
};
