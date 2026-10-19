// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Protocol codepoints against their registries.
 *
 * Each REGISTRIES entry is a hand transcription of one public registry, with
 * its URL and the date it was read. Every table in lib/ that carries values
 * from that registry is compared to it here, through the module's exports or
 * through the behavior that writes the value to the wire. The expected values
 * never come from the module under test, so a wrong value in lib/ cannot also
 * be the expected one.
 *
 * A lib/ table annotated `// registry: <url>` names itself in `anchors` as
 * `"<lib path>#<variable>"`; codebase-patterns.test.js refuses an annotated
 * table that no entry here lists, and an anchor whose table or URL is gone.
 *
 * To re-check a snapshot, open its URL and compare the rows. The test does
 * not fetch the registries, so it runs offline.
 *
 * Run standalone: `node test/layer-0-primitives/registry-codepoints.test.js`
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

var REGISTRIES = {
  aead: {
    url:       "https://www.iana.org/assignments/aead-parameters/aead-parameters.xhtml",
    retrieved: "2026-10-18",
    anchors:   ["lib/network-nts.js#AEADS"],
    rows: {
      AEAD_AES_SIV_CMAC_256:  15,
      AEAD_AES_SIV_CMAC_384:  16,
      AEAD_AES_SIV_CMAC_512:  17,
      AEAD_CHACHA20_POLY1305: 29,
      AEAD_AES_128_GCM_SIV:   30,
      AEAD_AES_256_GCM_SIV:   31,
    },
  },

  hpke: {
    url:       "https://www.iana.org/assignments/hpke/hpke.xhtml",
    retrieved: "2026-10-18",
    anchors:   ["lib/crypto-hpke-pq.js#KEM_IDS", "lib/crypto-hpke-pq.js#KDF_IDS",
      "lib/crypto-hpke-pq.js#AEAD_IDS"],
    kem: {
      "DHKEM(P-256, HKDF-SHA256)": 0x0010, "DHKEM(P-384, HKDF-SHA384)": 0x0011,
      "DHKEM(P-521, HKDF-SHA512)": 0x0012, "DHKEM(CP-256, HKDF-SHA256)": 0x0013,
      "DHKEM(CP-384, HKDF-SHA384)": 0x0014, "DHKEM(CP-521, HKDF-SHA512)": 0x0015,
      "DHKEM(secp256k1, HKDF-SHA256)": 0x0016, "DHKEM(X25519, HKDF-SHA256)": 0x0020,
      "DHKEM(X448, HKDF-SHA512)": 0x0021, "DHKEM(X25519+Elligator, HKDF-SHA256)": 0x0022,
      "X25519Kyber768Draft00": 0x0030,
      "ML-KEM-512": 0x0040, "ML-KEM-768": 0x0041, "ML-KEM-1024": 0x0042,
      "MLKEM768-P256": 0x0050, "MLKEM1024-P384": 0x0051, "X-Wing": 0x647A,
    },
    kdf: {
      "HKDF-SHA256": 0x0001, "HKDF-SHA384": 0x0002, "HKDF-SHA512": 0x0003,
      "SHAKE128": 0x0010, "SHAKE256": 0x0011, "TurboSHAKE128": 0x0012, "TurboSHAKE256": 0x0013,
    },
    aead: {
      "AES-128-GCM": 0x0001, "AES-256-GCM": 0x0002, "ChaCha20Poly1305": 0x0003, "Export-only": 0xFFFF,
    },
  },

  // RFC 9180 section 5, Table 1.
  hpkeModes: {
    url:       "https://www.rfc-editor.org/rfc/rfc9180#section-5",
    retrieved: "2026-10-18",
    anchors:   [],
    rows: { mode_base: 0x00, mode_psk: 0x01, mode_auth: 0x02, mode_auth_psk: 0x03 },
  },

  ntsKeRecordTypes: {
    url:       "https://www.iana.org/assignments/nts/nts.xhtml#nts-key-establishment-record-types",
    retrieved: "2026-10-18",
    anchors:   [],
    rows: {
      "End of Message": 0, "NTS Next Protocol Negotiation": 1, "Error": 2, "Warning": 3,
      "AEAD Algorithm Negotiation": 4, "New Cookie for NTPv4": 5,
      "NTPv4 Server Negotiation": 6, "NTPv4 Port Negotiation": 7,
    },
    critical: 0x8000,
  },

  ntsNextProtocols: {
    url:       "https://www.iana.org/assignments/nts/nts.xhtml#nts-next-protocols",
    retrieved: "2026-10-18",
    anchors:   [],
    rows: { "Network Time Protocol version 4 (NTPv4)": 0 },
  },

  ntsErrorCodes: {
    url:       "https://www.iana.org/assignments/nts/nts.xhtml#nts-error-codes",
    retrieved: "2026-10-18",
    anchors:   [],
    rows: { "Unrecognized Critical Record": 0, "Bad Request": 1, "Internal Server Error": 2 },
  },

  ntpExtensionFieldTypes: {
    url:       "https://www.iana.org/assignments/ntp-parameters/ntp-parameters.xhtml#ntp-parameters-3",
    retrieved: "2026-10-18",
    anchors:   [],
    rows: {
      "Unique Identifier": 0x0104, "NTS Cookie": 0x0204, "NTS Cookie Placeholder": 0x0304,
      "NTS Authenticator and Encrypted Extension Fields": 0x0404,
    },
  },

  tlsSupportedGroups: {
    url:       "https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8",
    retrieved: "2026-10-18",
    anchors:   ["lib/constants.js#PQC_GROUPS", "lib/pqc-agent.js#KNOWN_TLS_GROUPS"],
    rows: {
      secp256r1: 23, secp384r1: 24, secp521r1: 25,
      x25519: 29, x448: 30,
      brainpoolP256r1tls13: 31, brainpoolP384r1tls13: 32, brainpoolP512r1tls13: 33,
      ffdhe2048: 256, ffdhe3072: 257, ffdhe4096: 258, ffdhe6144: 259, ffdhe8192: 260,
      MLKEM512: 512, MLKEM768: 513, MLKEM1024: 514,
      SecP256r1MLKEM768: 4587, X25519MLKEM768: 4588, SecP384r1MLKEM1024: 4589,
    },
    postQuantum: ["MLKEM512", "MLKEM768", "MLKEM1024",
                  "SecP256r1MLKEM768", "X25519MLKEM768", "SecP384r1MLKEM1024"],
  },

  tlsAlerts: {
    url:       "https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-6",
    retrieved: "2026-10-18",
    anchors:   ["lib/pqc-gate.js#TLS_ALERT_HANDSHAKE_FAILURE"],
    rows:      { handshake_failure: 40 },
    contentTypes: { alert: 21, handshake: 22 },
    alertLevels:  { warning: 1, fatal: 2 },
  },

  coseAlgorithms: {
    url:       "https://www.iana.org/assignments/cose/cose.xhtml#algorithms",
    retrieved: "2026-10-18",
    anchors:   ["lib/content-credentials.js#COSE_ALGS"],
    rows: {
      "RS1": -65535, "RS512": -259, "RS384": -258, "RS256": -257,
      "Ed448": -53, "ESP512": -52, "ESP384": -51,
      "ML-DSA-87": -50, "ML-DSA-65": -49, "ML-DSA-44": -48,
      "PS512": -39, "PS384": -38, "PS256": -37,
      "ES512": -36, "ES384": -35, "Ed25519": -19, "ESP256": -9, "EdDSA": -8, "ES256": -7,
      "A128GCM": 1, "A192GCM": 2, "A256GCM": 3,
      "HMAC 256/64": 4, "HMAC 256/256": 5, "HMAC 384/384": 6, "HMAC 512/512": 7,
      "ChaCha20/Poly1305": 24,
    },
  },

  coseHeaderParameters: {
    url:       "https://www.iana.org/assignments/cose/cose.xhtml#header-parameters",
    retrieved: "2026-10-18",
    anchors:   [],
    rows: {
      "alg": 1, "crit": 2, "content type": 3, "kid": 4, "IV": 5, "Partial IV": 6,
      "CWT Claims": 15, "x5bag": 32, "x5chain": 33, "x5t": 34, "x5u": 35,
    },
  },

  cborTags: {
    url:       "https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml",
    retrieved: "2026-10-18",
    anchors:   [],
    rows: { COSE_Encrypt0: 16, COSE_Mac0: 17, COSE_Sign1: 18 },
  },

  cwtClaims: {
    url:       "https://www.iana.org/assignments/cwt/cwt.xhtml#claims-registry",
    retrieved: "2026-10-18",
    anchors:   [],
    rows: {
      iss: 1, sub: 2, aud: 3, exp: 4, nbf: 5, iat: 6, cti: 7, cnf: 8, scope: 9, Nonce: 10,
      ueid: 256, sueids: 257, oemid: 258, hwmodel: 259, hwversion: 260, uptime: 261,
      oemboot: 262, dbgstat: 263, location: 264, eat_profile: 265, submods: 266,
      bootcount: 267, bootseed: 268, dloas: 269, swname: 270, swversion: 271,
      manifests: 272, measurements: 273, measres: 274, intuse: 275,
    },
  },

  // RFC 9711 4.2.9 defines the dbgstat values; they have no IANA registry.
  eatDebugStatus: {
    url:       "https://www.rfc-editor.org/rfc/rfc9711#section-4.2.9",
    retrieved: "2026-10-18",
    anchors:   [],
    rows: {
      "enabled": 0, "disabled": 1, "disabled-since-boot": 2,
      "disabled-permanently": 3, "disabled-fully-and-permanently": 4,
    },
  },

  dnssecAlgorithms: {
    url:       "https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml",
    retrieved: "2026-10-18",
    anchors:   ["lib/network-dns.js#DNSKEY_ALGORITHMS"],
    rows: {
      0: "DELETE", 1: "RSAMD5", 2: "DH", 3: "DSA", 4: "Reserved", 5: "RSASHA1",
      6: "DSA-NSEC3-SHA1", 7: "RSASHA1-NSEC3-SHA1", 8: "RSASHA256", 9: "Reserved",
      10: "RSASHA512", 11: "Reserved", 12: "ECC-GOST", 13: "ECDSAP256SHA256",
      14: "ECDSAP384SHA384", 15: "ED25519", 16: "ED448", 17: "SM2SM3", 18: "MLDSA44",
      23: "ECC-GOST12", 252: "INDIRECT", 253: "PRIVATEDNS", 254: "PRIVATEOID", 255: "Reserved",
    },
    ranges: [
      { from: 19,  to: 22,  name: "unassigned" },
      { from: 24,  to: 122, name: "unassigned" },
      { from: 123, to: 251, name: "Reserved" },
    ],
  },

  dsDigestTypes: {
    url:       "https://www.iana.org/assignments/ds-rr-types/ds-rr-types.xhtml",
    retrieved: "2026-10-18",
    anchors:   ["lib/network-dns.js#DS_DIGEST_TYPES"],
    rows: {
      0: "Reserved", 1: "SHA-1", 2: "SHA-256", 3: "GOST R 34.11-94", 4: "SHA-384",
      5: "GOST R 34.11-2012", 6: "SM3",
    },
    references: { 5: "RFC 9558", 6: "RFC 9563" },
    ranges: [
      { from: 7,   to: 127, name: "unassigned" },
      { from: 128, to: 252, name: "Reserved" },
      { from: 253, to: 254, name: "Private Use" },
      { from: 255, to: 255, name: "unassigned" },
    ],
  },

  rootAnchors: {
    url:       "https://data.iana.org/root-anchors/root-anchors.xml",
    retrieved: "2026-10-18",
    anchors:   [],
    rows: {
      20326: { algorithm: 8, digestType: 2, digest: "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D" },
      38696: { algorithm: 8, digestType: 2, digest: "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16" },
    },
  },

  dnsRrTypes: {
    url:       "https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4",
    retrieved: "2026-10-18",
    anchors:   [],
    rows: {
      A: 1, NS: 2, CNAME: 5, SOA: 6, PTR: 12, MX: 15, TXT: 16, AAAA: 28, SRV: 33,
      OPT: 41, DS: 43, RRSIG: 46, NSEC: 47, DNSKEY: 48, NSEC3: 50, TLSA: 52,
      SVCB: 64, HTTPS: 65, TSIG: 250, ANY: 255,
    },
  },

  svcbKeys: {
    url:       "https://www.iana.org/assignments/dns-svcb/dns-svcb.xhtml",
    retrieved: "2026-10-18",
    anchors:   [],
    rows: {
      "mandatory": 0, "alpn": 1, "no-default-alpn": 2, "port": 3,
      "ipv4hint": 4, "ech": 5, "ipv6hint": 6, "dohpath": 7,
    },
  },

  tsigAlgorithmNames: {
    url:       "https://www.iana.org/assignments/tsig-algorithm-names/tsig-algorithm-names.xhtml",
    retrieved: "2026-10-18",
    anchors:   ["lib/network-tsig.js#ALGORITHMS", "lib/network-tsig.js#LEGACY_ALGORITHMS"],
    rows: [
      "gss-tsig", "HMAC-MD5.SIG-ALG.REG.INT", "hmac-sha1", "hmac-sha224", "hmac-sha256",
      "hmac-sha384", "hmac-sha512", "hmac-sha256-128", "hmac-sha384-192", "hmac-sha512-256",
    ],
  },

  websocketCloseCodes: {
    url:       "https://www.iana.org/assignments/websocket/websocket.xhtml#close-code-number",
    retrieved: "2026-10-18",
    anchors:   ["lib/websocket.js#ASSIGNED_CLOSE_CODES"],
    // RFC 6455 7.4.1: 1004 is reserved and 1005, 1006, 1015 MUST NOT be sent
    // in a Close frame, so they are listed apart from the codes a peer sends.
    rows: {
      1000: "Normal Closure", 1001: "Going Away", 1002: "Protocol error",
      1003: "Unsupported Data", 1007: "Invalid frame payload data",
      1008: "Policy Violation", 1009: "Message Too Big", 1010: "Mandatory Ext.",
      1011: "Internal Error", 1012: "Service Restart", 1013: "Try Again Later",
      1014: "Bad Gateway",
    },
    notOnTheWire: [1004, 1005, 1006, 1015],
    applicationRange: { from: 3000, to: 4999 },
  },

  websocketOpcodes: {
    url:       "https://www.iana.org/assignments/websocket/websocket.xhtml#opcode",
    retrieved: "2026-10-18",
    anchors:   [],
    rows: { CONTINUATION: 0, TEXT: 1, BINARY: 2, CLOSE: 8, PING: 9, PONG: 10 },
  },

  // The BIMI Group Mark Certificate Requirements, version 1.8 (2026-06-11),
  // 7.1.2.3 and 7.1.4; the EKU and logotype OIDs are RFC 9921 / RFC 3709.
  markCertificateOids: {
    url:       "https://bimigroup.org/resources/VMC_Requirements_latest.pdf",
    retrieved: "2026-10-18",
    anchors:   ["lib/mail-bimi.js#MC_GENERAL_POLICY_OID", "lib/mail-bimi.js#MARK_TYPE_OID"],
    rows: {
      "id-kp-BrandIndicatorforMessageIdentification": "1.3.6.1.5.5.7.3.31",
      "Mark Certificate General Policy Identifier":   "1.3.6.1.4.1.53087.1.1",
      "subject:trademarkOfficeName":                  "1.3.6.1.4.1.53087.1.2",
      "subject:markType":                             "1.3.6.1.4.1.53087.1.13",
    },
  },

  // C2PA Technical Specification 2.1, 10.3.2.5: the v2 time-stamp sits in the
  // unprotected header under the text label "sigTst2" as a tstContainer;
  // 14.5: x5chain sits in the protected header.
  c2paHeaders: {
    url:       "https://spec.c2pa.org/specifications/specifications/2.1/specs/C2PA_Specification.html",
    retrieved: "2026-10-18",
    anchors:   [],
    rows: { sigTst2: "sigTst2", tstTokens: "tstTokens", val: "val" },
  },
};

function _registryName(snapshotRows, value) {
  var names = Object.keys(snapshotRows);
  for (var i = 0; i < names.length; i += 1) if (snapshotRows[names[i]] === value) return names[i];
  return null;
}

function testAeadIdentifiers() {
  var rows = REGISTRIES.aead.rows;
  check("NTS AEAD_AES_SIV_CMAC_256 is the registry value",
        b.network.ntp.nts.AEAD_AES_SIV_CMAC_256 === rows.AEAD_AES_SIV_CMAC_256);
  check("NTS AEAD_CHACHA20_POLY1305 is the registry value",
        b.network.ntp.nts.AEAD_CHACHA20_POLY1305 === rows.AEAD_CHACHA20_POLY1305,
        "got " + b.network.ntp.nts.AEAD_CHACHA20_POLY1305);
}

function testTlsGroups() {
  var reg = REGISTRIES.tlsSupportedGroups;
  var lowerRows = {};
  Object.keys(reg.rows).forEach(function (k) { lowerRows[k.toLowerCase()] = reg.rows[k]; });
  Object.keys(b.constants.PQC_GROUPS).forEach(function (name) {
    check("PQC_GROUPS." + name + " is the registry codepoint",
          reg.rows[name] === b.constants.PQC_GROUPS[name], "got " + b.constants.PQC_GROUPS[name]);
    check("PQC_GROUPS." + name + " is a post-quantum group", reg.postQuantum.indexOf(name) !== -1);
  });
  reg.postQuantum.forEach(function (name) {
    check("PQC_GROUPS carries the registered post-quantum group " + name,
          b.constants.PQC_GROUPS[name] === reg.rows[name]);
  });
  b.pqcAgent.KNOWN_TLS_GROUPS.forEach(function (name) {
    check("pqcAgent.KNOWN_TLS_GROUPS entry " + name + " is a registered group name",
          Object.prototype.hasOwnProperty.call(lowerRows, name.toLowerCase()));
  });
  b.constants.TLS_GROUP_PREFERENCE.forEach(function (name) {
    check("TLS_GROUP_PREFERENCE entry " + name + " is a registered group name",
          Object.prototype.hasOwnProperty.call(lowerRows, name.toLowerCase()));
  });
  b.constants.TLS_SERVER_FALLBACK_CURVES.forEach(function (name) {
    check("TLS_SERVER_FALLBACK_CURVES entry " + name + " is a registered group name",
          Object.prototype.hasOwnProperty.call(lowerRows, name.toLowerCase()));
  });

  var alert = b.pqcGate.TLS_ALERT_HANDSHAKE_FAILURE;
  var tlsA = REGISTRIES.tlsAlerts;
  check("pqcGate alert record: content type alert(21), level fatal(2), description handshake_failure(40)",
        alert.length === 7 && alert[0] === tlsA.contentTypes.alert &&
        alert.readUInt16BE(3) === 2 && alert[5] === tlsA.alertLevels.fatal &&
        alert[6] === tlsA.rows.handshake_failure);
}

function testCoseAlgorithms() {
  var rows = REGISTRIES.coseAlgorithms.rows;
  // lib name -> registry name, per table.
  var contentCredentialsNames = {
    "ed25519": "EdDSA", "es256": "ES256", "es384": "ES384", "es512": "ES512",
    "ml-dsa-44": "ML-DSA-44", "ml-dsa-65": "ML-DSA-65", "ml-dsa-87": "ML-DSA-87",
  };
  var cc = b.contentCredentials.COSE_ALGS;
  Object.keys(cc).forEach(function (name) {
    var regName = contentCredentialsNames[name];
    check("contentCredentials.COSE_ALGS " + name + " has a registry row", regName !== undefined);
    if (regName === undefined) return;
    check("contentCredentials.COSE_ALGS " + name + " is " + regName + " (" + rows[regName] + ")",
          cc[name] === rows[regName], "got " + cc[name] + " (" + _registryName(rows, cc[name]) + ")");
  });
  Object.keys(b.cose.ALGORITHMS).forEach(function (name) {
    check("cose.ALGORITHMS " + name + " is the registry value",
          rows[name] !== undefined && b.cose.ALGORITHMS[name] === rows[name]);
  });
  var macNames = { "HMAC-256/256": "HMAC 256/256", "HMAC-384/384": "HMAC 384/384", "HMAC-512/512": "HMAC 512/512" };
  Object.keys(b.cose.MAC_ALGORITHMS).forEach(function (name) {
    check("cose.MAC_ALGORITHMS " + name + " is the registry value",
          macNames[name] !== undefined && b.cose.MAC_ALGORITHMS[name] === rows[macNames[name]]);
  });
  var aeadNames = { "ChaCha20-Poly1305": "ChaCha20/Poly1305", "A128GCM": "A128GCM", "A256GCM": "A256GCM" };
  Object.keys(b.cose.AEAD_ALGORITHMS).forEach(function (name) {
    check("cose.AEAD_ALGORITHMS " + name + " is the registry value",
          aeadNames[name] !== undefined && b.cose.AEAD_ALGORITHMS[name] === rows[aeadNames[name]]);
  });
  var tags = REGISTRIES.cborTags.rows;
  check("COSE_Sign1 / COSE_Mac0 / COSE_Encrypt0 tags are the registry values",
        b.cose.COSE_SIGN1_TAG === tags.COSE_Sign1 && b.cose.COSE_MAC0_TAG === tags.COSE_Mac0 &&
        b.cose.COSE_ENCRYPT0_TAG === tags.COSE_Encrypt0);
  check("scitt CWT Claims header label is the registry value",
        b.scitt.CWT_CLAIMS_LABEL === REGISTRIES.coseHeaderParameters.rows["CWT Claims"]);
}

function testCwtAndEatClaims() {
  var rows = REGISTRIES.cwtClaims.rows;
  var cwtNames = { iss: "iss", sub: "sub", aud: "aud", exp: "exp", nbf: "nbf", iat: "iat", cti: "cti" };
  Object.keys(b.cwt.CLAIM_LABELS).forEach(function (name) {
    check("cwt.CLAIM_LABELS " + name + " is the registry key",
          cwtNames[name] !== undefined && b.cwt.CLAIM_LABELS[name] === rows[cwtNames[name]]);
  });
  var eatNames = { nonce: "Nonce" };
  Object.keys(b.eat.CLAIM_LABELS).forEach(function (name) {
    var regName = eatNames[name] || name;
    check("eat.CLAIM_LABELS " + name + " is the registry key",
          rows[regName] !== undefined && b.eat.CLAIM_LABELS[name] === rows[regName],
          "got " + b.eat.CLAIM_LABELS[name]);
  });
  var dbg = REGISTRIES.eatDebugStatus.rows;
  Object.keys(b.eat.DBGSTAT).forEach(function (name) {
    check("eat.DBGSTAT " + name + " is the RFC 9711 value",
          dbg[name] !== undefined && b.eat.DBGSTAT[name] === dbg[name]);
  });
}

function testDnssecAlgorithms() {
  var reg = REGISTRIES.dnssecAlgorithms;
  var table = b.network.dns.DNSKEY_ALGORITHMS;
  Object.keys(table).forEach(function (n) {
    check("DNSKEY_ALGORITHMS " + n + " is " + reg.rows[n],
          reg.rows[n] !== undefined && table[n].name === reg.rows[n], "got " + table[n].name);
  });
  Object.keys(reg.rows).forEach(function (n) {
    var c = b.network.dns.classifyDnskeyAlgorithm(Number(n));
    check("classifyDnskeyAlgorithm(" + n + ") is known as " + reg.rows[n],
          c && c.known === true && c.name === reg.rows[n], c && c.name);
  });
  reg.ranges.forEach(function (r) {
    [r.from, Math.floor((r.from + r.to) / 2), r.to].forEach(function (n) {
      var c = b.network.dns.classifyDnskeyAlgorithm(n);
      check("classifyDnskeyAlgorithm(" + n + ") is " + r.name,
            c && c.name === r.name && c.known === (r.name !== "unassigned"), c && c.name);
    });
  });
  var validating = b.network.dns.dnssec.ALGORITHMS;
  Object.keys(validating).forEach(function (n) {
    check("dnssec.ALGORITHMS " + n + " is " + reg.rows[n],
          reg.rows[n] !== undefined && validating[n].name === reg.rows[n]);
  });

  var ds = REGISTRIES.dsDigestTypes;
  var dsTable = b.network.dns.DS_DIGEST_TYPES;
  Object.keys(dsTable).forEach(function (n) {
    check("DS_DIGEST_TYPES " + n + " is " + ds.rows[n],
          ds.rows[n] !== undefined && dsTable[n].name === ds.rows[n]);
  });
  Object.keys(ds.rows).forEach(function (n) {
    var c = b.network.dns.classifyDsDigestType(Number(n));
    check("classifyDsDigestType(" + n + ") is known as " + ds.rows[n],
          c && c.known === true && c.name === ds.rows[n]);
  });
  Object.keys(ds.references).forEach(function (n) {
    var c = b.network.dns.classifyDsDigestType(Number(n));
    check("classifyDsDigestType(" + n + ") cites " + ds.references[n],
          c && c.reason.indexOf(ds.references[n]) !== -1, c && c.reason);
  });
  ds.ranges.forEach(function (r) {
    [r.from, r.to].forEach(function (n) {
      var c = b.network.dns.classifyDsDigestType(n);
      check("classifyDsDigestType(" + n + ") is " + r.name,
            c && c.name === r.name && c.known === (r.name !== "unassigned"), c && c.name);
    });
  });

  var anchors = b.network.dns.dnssec.DEFAULT_ROOT_ANCHORS;
  var want = REGISTRIES.rootAnchors.rows;
  check("DEFAULT_ROOT_ANCHORS lists the current root KSKs", anchors.length === Object.keys(want).length);
  anchors.forEach(function (a) {
    var w = want[a.keyTag];
    check("root anchor " + a.keyTag + " matches root-anchors.xml",
          w && a.algorithm === w.algorithm && a.digestType === w.digestType &&
          a.digest.toString("hex").toUpperCase() === w.digest);
  });
}

function testDnsTypesAndSvcbKeys() {
  var rows = REGISTRIES.dnsRrTypes.rows;
  var names = b.safeDns.RTYPE_NAMES;
  Object.keys(names).forEach(function (n) {
    check("safeDns.RTYPE_NAMES " + n + " is " + names[n], rows[names[n]] === Number(n));
  });
  var q = b.network.dns.resolver.QTYPE_BY_NAME;
  Object.keys(q).forEach(function (name) {
    check("resolver.QTYPE_BY_NAME " + name + " is the registry value", rows[name] === q[name]);
  });

  var keys = REGISTRIES.svcbKeys.rows;
  function param(key, value) {
    var h = Buffer.alloc(4); h.writeUInt16BE(key, 0); h.writeUInt16BE(value.length, 2);
    return Buffer.concat([h, value]);
  }
  var port = Buffer.alloc(2); port.writeUInt16BE(8443, 0);
  var rdata = Buffer.concat([
    Buffer.from([0x00, 0x01, 0x00]),
    param(keys.alpn, Buffer.from([0x02, 0x68, 0x32])),
    param(keys["no-default-alpn"], Buffer.alloc(0)),
    param(keys.port, port),
    param(keys.ipv4hint, Buffer.from([192, 0, 2, 1])),
    param(keys.dohpath, Buffer.from("/dns-query{?dns}", "utf8")),
  ]);
  var parsed = b.network.dns._parseSvcbRdata(rdata, 0, rdata.length);
  var p = parsed.params || parsed;
  check("SVCB key 1 is alpn", Array.isArray(p.alpn) && p.alpn[0] === "h2");
  check("SVCB key 2 is no-default-alpn", p.noDefaultAlpn === true);
  check("SVCB key 3 is port", p.port === 8443);
  check("SVCB key 4 is ipv4hint", Array.isArray(p.ipv4hint) && p.ipv4hint[0] === "192.0.2.1");
  check("SVCB key 7 is dohpath", p.dohpath === "/dns-query{?dns}");
}

function testTsigNames() {
  var lower = REGISTRIES.tsigAlgorithmNames.rows.map(function (n) { return n.toLowerCase(); });
  Object.keys(b.network.dns.tsig.ALGORITHMS).forEach(function (name) {
    check("tsig.ALGORITHMS " + name + " is a registered TSIG algorithm name", lower.indexOf(name) !== -1);
  });
  var msg = Buffer.from("123401000001000000000000076578616d706c6503636f6d0000010001", "hex");
  [["hmac-md5", "HMAC-MD5.SIG-ALG.REG.INT"], ["hmac-sha1", "hmac-sha1"], ["hmac-sha256", "hmac-sha256"]].forEach(function (row) {
    var s = b.network.dns.tsig.sign(msg, { keyName: "k.", secret: Buffer.alloc(32, 1),
      algorithm: row[0], allowLegacy: true, time: 1700000000 });
    var wire = Buffer.concat(row[1].toLowerCase().split(".").map(function (l) {
      return Buffer.concat([Buffer.from([l.length]), Buffer.from(l, "ascii")]);
    }).concat([Buffer.from([0])]));
    check("tsig.sign '" + row[0] + "' writes the registered name " + row[1], s.wire.includes(wire));
  });
}

function testWebSocketCodes() {
  var reg = REGISTRIES.websocketCloseCodes;
  function allowedOnWire(code) {
    if (reg.notOnTheWire.indexOf(code) !== -1) return false;
    if (reg.rows[code] !== undefined) return true;
    return code >= reg.applicationRange.from && code <= reg.applicationRange.to;
  }
  var mismatches = [];
  for (var code = 0; code <= 0xFFFF; code += 1) {
    if (b.websocket.isValidCloseCode(code) !== allowedOnWire(code)) mismatches.push(code);
  }
  check("websocket.isValidCloseCode agrees with the registry for every 16-bit code",
        mismatches.length === 0, mismatches.slice(0, 20).join(","));
  var constNames = {
    CLOSE_NORMAL: 1000, CLOSE_GOING_AWAY: 1001, CLOSE_PROTOCOL_ERROR: 1002,
    CLOSE_UNSUPPORTED_DATA: 1003, CLOSE_INVALID_PAYLOAD: 1007, CLOSE_POLICY_VIOLATION: 1008,
    CLOSE_MESSAGE_TOO_BIG: 1009, CLOSE_INTERNAL_ERROR: 1011,
  };
  Object.keys(constNames).forEach(function (k) {
    check("websocket." + k + " is " + reg.rows[constNames[k]],
          b.websocket[k] === constNames[k] && reg.rows[constNames[k]] !== undefined);
  });
  check("wsClient close constants are registry values",
        b.wsClient.CLOSE_NORMAL === 1000 && b.wsClient.CLOSE_GOING_AWAY === 1001);
  var ops = REGISTRIES.websocketOpcodes.rows;
  Object.keys(ops).forEach(function (k) {
    check("websocket.OPCODE_" + k + " is " + ops[k], b.websocket["OPCODE_" + k] === ops[k]);
  });
  check("wsClient opcodes are registry values",
        b.wsClient.OPCODE_TEXT === ops.TEXT && b.wsClient.OPCODE_BINARY === ops.BINARY);
}

function testMarkCertificateOids() {
  var rows = REGISTRIES.markCertificateOids.rows;
  check("BIMI EKU is id-kp-BrandIndicatorforMessageIdentification",
        b.mail.bimi.BIMI_EKU_MARK_VERIFICATION === rows["id-kp-BrandIndicatorforMessageIdentification"]);
  check("MC_GENERAL_POLICY_OID is the Mark Certificate General Policy Identifier",
        b.mail.bimi.MC_GENERAL_POLICY_OID === rows["Mark Certificate General Policy Identifier"]);
  check("MARK_TYPE_OID is subject:markType",
        b.mail.bimi.MARK_TYPE_OID === rows["subject:markType"]);
  Object.keys(b.mail.bimi).forEach(function (k) {
    if (!/_OID$/.test(k)) return;
    check("mail.bimi." + k + " is not subject:trademarkOfficeName used as a policy",
          b.mail.bimi[k] !== rows["subject:trademarkOfficeName"]);
  });
}

function testC2paHeaders() {
  var rows = REGISTRIES.c2paHeaders.rows;
  var hdr = REGISTRIES.coseHeaderParameters.rows;
  var pair = b.crypto.generateSigningKeyPair("ml-dsa-87");
  var manifest = b.contentCredentials.build({ provider: "P", system: "s", systemVersion: "1.0.0", contentId: "c" });
  var token = Buffer.from([0x30, 0x03, 0x02, 0x01, 0x00]);
  var out = b.contentCredentials.signCose(manifest, { privateKeyPem: pair.privateKey,
    certChain: [Buffer.from([0x30, 0x00])], timestamp: { token: token }, audit: false });
  var arr = b.cbor.decode(out.coseSign1, { allowedTags: [18] }).value;
  var prot = b.cbor.decode(arr[0]);
  var unprot = arr[1];
  check("C2PA: alg (1) is in the protected header", prot.get(hdr.alg) === REGISTRIES.coseAlgorithms.rows["ML-DSA-87"]);
  check("C2PA: x5chain (33) is in the protected header", prot.has(hdr.x5chain) && !unprot.has(hdr.x5chain));
  check("C2PA: nothing is written under x5u (35)", !unprot.has(hdr.x5u) && !prot.has(hdr.x5u));
  var c = unprot.get(rows.sigTst2);
  check("C2PA: the time-stamp is a tstContainer under the text label sigTst2",
        c instanceof Map && Array.isArray(c.get(rows.tstTokens)) &&
        c.get(rows.tstTokens).length === 1 && c.get(rows.tstTokens)[0].get(rows.val).equals(token));
}

// Every suite either HPKE-PQ namespace accepts is named in the registry, and
// an envelope sealed under each one opens under an independent RFC 9180
// recipient context built from the registry codepoints. A wrong id in lib/
// changes the suite_id in the key schedule, so the open fails.
function testHpkeSuites() {
  var reg = REGISTRIES.hpke;
  var pki = require("../../lib/vendor/blamejs-pki.cjs");
  var modeBase = REGISTRIES.hpkeModes.rows.mode_base;
  ["connolly", "wg"].forEach(function (draftName) {
    var draft = b.crypto.hpke.pq[draftName];
    var sup = draft.SUPPORTED_SUITES;
    ["kem", "kdf", "aead"].forEach(function (kind) {
      sup[kind].forEach(function (name) {
        check("hpke.pq." + draftName + " " + kind + " " + name + " is a registered HPKE " + kind,
              Object.prototype.hasOwnProperty.call(reg[kind], name));
      });
      check("hpke.pq." + draftName + ".DEFAULT_SUITE." + kind + " is a supported registered " + kind,
            sup[kind].indexOf(draft.DEFAULT_SUITE[kind]) !== -1 &&
            Object.prototype.hasOwnProperty.call(reg[kind], draft.DEFAULT_SUITE[kind]),
            draft.DEFAULT_SUITE[kind]);
    });
    sup.kem.forEach(function (kem) {
      var pair = draft.generateKeyPair(draftName === "wg" ? { kem: kem } : undefined);
      sup.kdf.forEach(function (kdf) {
        sup.aead.forEach(function (aead) {
          var label = "hpke.pq." + draftName + " " + kem + " / " + kdf + " / " + aead;
          var ids = { kem: reg.kem[kem], kdf: reg.kdf[kdf], aead: reg.aead[aead] };
          var info = Buffer.from("registry-codepoints " + label, "utf8");
          var suiteOpts = { recipientPubKey: pair.publicKey, kdf: kdf, aead: aead, info: info };
          if (draftName === "wg") suiteOpts.kem = kem;
          var sender = draft.setupSender(suiteOpts);
          var ctx = pki.hpke.setupR(ids, sender.enc, { skm: pair.privateKey },
            { mode: modeBase, info: info, psk: Buffer.alloc(0), pskId: Buffer.alloc(0) });
          var exportCtx = Buffer.from("exporter", "utf8");
          check(label + ": the exported secret matches a recipient keyed by the registry codepoints",
                Buffer.from(ctx.export(exportCtx, 32)).equals(sender.export(exportCtx, 32)));
          if (aead === "Export-only") return;
          var pt = Buffer.from("plaintext " + label, "utf8");
          var aad = Buffer.from("aad", "utf8");
          var ct = sender.seal(pt, aad);
          var opened = null;
          try { opened = Buffer.from(ctx.open(aad, ct)); } catch (_e) { opened = null; }
          check(label + ": the envelope opens under the registry codepoints", opened !== null && opened.equals(pt));
        });
      });
    });
  });
}

function _keRecord(critical, type, body) {
  var hdr = Buffer.alloc(4);
  hdr.writeUInt16BE((critical ? REGISTRIES.ntsKeRecordTypes.critical : 0) | type, 0);
  hdr.writeUInt16BE(body.length, 2);
  return Buffer.concat([hdr, body]);
}

function _u16(v) { var out = Buffer.alloc(2); out.writeUInt16BE(v, 0); return out; }

function _parseKeRecords(buf) {
  var out = [];
  var off = 0;
  var critBit = REGISTRIES.ntsKeRecordTypes.critical;
  while (off + 4 <= buf.length) {
    var t = buf.readUInt16BE(off);
    var len = buf.readUInt16BE(off + 2);
    out.push({ critical: (t & critBit) !== 0, type: t & ~critBit & 0xFFFF, body: buf.slice(off + 4, off + 4 + len) });
    off += 4 + len;
  }
  return out;
}

// A loopback NTS-KE server answers each connection with the records
// `respond` returns and keeps the request bytes.
function _ntsKeServer(leaf, respond) {
  var nodeTls = require("node:tls");
  return new Promise(function (resolve) {
    var handle = { requests: [], sockets: [] };
    var server = nodeTls.createServer({
      key: leaf.key, cert: leaf.cert, minVersion: "TLSv1.3", ALPNProtocols: ["ntske/1"],
    }, function (sock) {
      handle.sockets.push(sock);
      sock.on("error", function () { /* client teardown */ });
      sock.once("data", function (request) {
        handle.requests.push(Buffer.from(request));
        sock.end(respond());
      });
    });
    server.on("tlsClientError", function () { /* the client result reports it */ });
    server.listen(0, "127.0.0.1", function () {
      handle.port = server.address().port;
      handle.close = function () {
        handle.sockets.forEach(function (s) { try { s.destroy(); } catch (_e) { /* best-effort */ } });
        return new Promise(function (r) { server.close(r); });
      };
      resolve(handle);
    });
  });
}

// The NTS-KE request the client writes, and the responses it reads, use the
// registry record types, next-protocol id, AEAD ids and error codes; the NTP
// request carries the registry extension field types.
async function testNtsWireCodepoints() {
  var rt = REGISTRIES.ntsKeRecordTypes.rows;
  var aead = REGISTRIES.aead.rows;
  var ntpv4 = REGISTRIES.ntsNextProtocols.rows["Network Time Protocol version 4 (NTPv4)"];
  var ca = await b.mtlsEngine.generateCa({ name: "registry-nts-ca" });
  var leaf = await b.mtlsEngine.signClientCert({
    cn: "localhost", caCertPem: ca.caCertPem, caKeyPem: ca.caKeyPem,
    usage: "server", sans: ["DNS:localhost", "IP:127.0.0.1"], validityDays: 1,
  });
  var respondWith = null;
  var ke = await _ntsKeServer(leaf, function () { return respondWith(); });
  function dial() {
    return b.network.ntp.nts.performKeHandshake({
      host: "127.0.0.1", port: ke.port, ca: ca.caCertPem, timeoutMs: 4000,
    });
  }
  try {
    respondWith = function () {
      var server = Buffer.from("127.0.0.1", "ascii");
      return Buffer.concat([
        _keRecord(true, rt["NTS Next Protocol Negotiation"], _u16(ntpv4)),
        _keRecord(true, rt["AEAD Algorithm Negotiation"], _u16(aead.AEAD_CHACHA20_POLY1305)),
        _keRecord(false, rt["NTPv4 Server Negotiation"], server),
        _keRecord(false, rt["NTPv4 Port Negotiation"], _u16(1234)),
        _keRecord(false, rt["New Cookie for NTPv4"], Buffer.alloc(32, 7)),
        _keRecord(true, rt["End of Message"], Buffer.alloc(0)),
      ]);
    };
    var res = await dial();
    check("NTS-KE: a response built from the registry record types is read",
          res.aeadId === aead.AEAD_CHACHA20_POLY1305 && res.ntpServer === "127.0.0.1" &&
          res.ntpPort === 1234 && res.cookies.length === 1, JSON.stringify({ aeadId: res.aeadId,
            ntpServer: res.ntpServer, ntpPort: res.ntpPort }));

    var recs = _parseKeRecords(ke.requests[0] || Buffer.alloc(0));
    var types = recs.map(function (r) { return r.type; });
    check("NTS-KE request: Next Protocol, AEAD Algorithm and End of Message records, all critical",
          types.length === 3 && types[0] === rt["NTS Next Protocol Negotiation"] &&
          types[1] === rt["AEAD Algorithm Negotiation"] && types[2] === rt["End of Message"] &&
          recs.every(function (r) { return r.critical; }), JSON.stringify(types));
    check("NTS-KE request: the next protocol is NTPv4 (0)",
          recs[0] && recs[0].body.length === 2 && recs[0].body.readUInt16BE(0) === ntpv4);
    var offered = [];
    for (var i = 0; recs[1] && i + 1 < recs[1].body.length; i += 2) offered.push(recs[1].body.readUInt16BE(i));
    check("NTS-KE request: the AEAD offer is AEAD_AES_SIV_CMAC_256 then AEAD_CHACHA20_POLY1305",
          offered.length === 2 && offered[0] === aead.AEAD_AES_SIV_CMAC_256 &&
          offered[1] === aead.AEAD_CHACHA20_POLY1305, JSON.stringify(offered));

    respondWith = function () {
      return Buffer.concat([
        _keRecord(true, rt.Error, _u16(REGISTRIES.ntsErrorCodes.rows["Bad Request"])),
        _keRecord(true, rt["End of Message"], Buffer.alloc(0)),
      ]);
    };
    var errResult = null;
    try { await dial(); } catch (e) { errResult = e; }
    check("NTS-KE: an Error record (2) carrying Bad Request (1) is reported as that error",
          errResult && errResult.code === "nts/ke-error" &&
          errResult.ntsErrorCode === REGISTRIES.ntsErrorCodes.rows["Bad Request"],
          errResult && (errResult.code + " " + errResult.message));

    respondWith = function () {
      return Buffer.concat([
        _keRecord(true, rt.Warning, _u16(0)),
        _keRecord(true, rt["End of Message"], Buffer.alloc(0)),
      ]);
    };
    var warnResult = null;
    try { await dial(); } catch (e) { warnResult = e; }
    check("NTS-KE: a Warning record (3) is read as a warning",
          warnResult && warnResult.code === "nts/ke-warning", warnResult && warnResult.code);
  } finally {
    await ke.close();
  }

  var fields = REGISTRIES.ntpExtensionFieldTypes.rows;
  var dgram = require("node:dgram");
  var captured = null;
  var udp = dgram.createSocket("udp4");
  udp.on("message", function (msg) { if (captured === null) captured = Buffer.from(msg); });
  await new Promise(function (r) { udp.bind(0, "127.0.0.1", r); });
  try {
    var qErr = null;
    try {
      await b.network.ntp.nts.querySingle({
        host: "127.0.0.1", port: udp.address().port, aeadId: aead.AEAD_AES_SIV_CMAC_256,
        c2sKey: Buffer.alloc(32, 1), s2cKey: Buffer.alloc(32, 2), cookies: [Buffer.alloc(32, 3)],
        timeoutMs: 300,
      });
    } catch (e) { qErr = e; }
    check("NTS query to a silent server times out", qErr && qErr.code === "nts/timeout", qErr && qErr.code);
    var seen = [];
    var off = 48;
    while (captured && off + 4 <= captured.length) {
      var len = captured.readUInt16BE(off + 2);
      if (len < 4 || off + len > captured.length) break;
      seen.push(captured.readUInt16BE(off));
      off += len;
    }
    check("NTP request: Unique Identifier, NTS Cookie, then NTS Authenticator extension fields",
          seen.length === 3 && seen[0] === fields["Unique Identifier"] && seen[1] === fields["NTS Cookie"] &&
          seen[2] === fields["NTS Authenticator and Encrypted Extension Fields"] &&
          captured !== null && off === captured.length,
          JSON.stringify(seen.map(function (t) { return "0x" + t.toString(16); })));
  } finally {
    await new Promise(function (r) { udp.close(r); });
  }
}

async function run() {
  testHpkeSuites();
  await testNtsWireCodepoints();
  testAeadIdentifiers();
  testTlsGroups();
  testCoseAlgorithms();
  testCwtAndEatClaims();
  testDnssecAlgorithms();
  testDnsTypesAndSvcbKeys();
  testTsigNames();
  testWebSocketCodes();
  testMarkCertificateOids();
  testC2paHeaders();
}

module.exports = { run: run, REGISTRIES: REGISTRIES };

if (require.main === module) {
  run().then(
    function () { console.log("[registry-codepoints] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
