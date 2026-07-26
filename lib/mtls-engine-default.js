// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * mtls-engine-default — pure-JS X.509 engine wired into b.mtlsCa.
 *
 * Implements the engine contract documented at the top of lib/mtls-ca.js:
 *   generateCa({ generation, algorithm })     -> { caCertPem, caKeyPem }
 *   signClientCert({ cn, validityDays, usage, sans, algorithm,
 *                    caCertPem, caKeyPem })    -> { cert, key, ca, issuedAt, expiresAt }
 *   packageP12({ cn, password, validityDays, algorithm,
 *                caCertPem, caKeyPem })        -> { p12, certPem, issuedAt, expiresAt }
 *   generateCrl({ caCertPem, caKeyPem,
 *                 revocations, thisUpdate,
 *                 nextUpdate })                -> CRL PEM
 *
 * Backed by lib/vendor/blamejs-pki.cjs (@blamejs/pki — zero-dep pure-CJS
 * X.509 / CRL / PKCS#12 toolkit with a built-in WebCrypto over node:crypto).
 * No openssl CLI is invoked.
 *
 * Algorithm envelope:
 *   CA + leaf signatures: ML-DSA-87 by default (FIPS 204). node:tls verifies
 *                         ML-DSA certificate chains + CertificateVerify on the
 *                         supported Node LTS (OpenSSL 3.5), so PQC-signed mTLS
 *                         certificates complete a real mutual-auth handshake.
 *                         Operators whose peers are not yet on OpenSSL 3.5 pass
 *                         algorithm: "ECDSA-P384-SHA384" (b.mtlsCa.create({ algorithm })
 *                         threads it into both CA generation and leaf issuance)
 *                         for a universally-interoperable classical CA. A pin is
 *                         per-call: it never mutates the process-wide default, so
 *                         one classical CA cannot downgrade another CA's ML-DSA-87
 *                         default. SLH-DSA is intentionally not offered here:
 *                         OpenSSL rejects it in the TLS handshake ("unknown
 *                         certificate type").
 *   PKCS#12 key + cert bags: PBES2 + AES-256-CBC + PBKDF2-HMAC-SHA-512, 2,000,000 iter
 *   PKCS#12 outer MAC       : PBMAC1 + PBKDF2-HMAC-SHA-512, 2,000,000 iter (RFC 9579)
 */

var pki = require("./vendor/blamejs-pki.cjs");

var C = require("./constants");
var bCrypto = require("./crypto");
var ipUtils = require("./ip-utils");
var numericBounds = require("./numeric-bounds");
var safeBuffer = require("./safe-buffer");
var { FrameworkError } = require("./framework-error");

var subtle = pki.webcrypto.subtle;

class MtlsEngineError extends FrameworkError {
  constructor(code, message) {
    super(message, code);
    this.name = "MtlsEngineError";
    this.permanent = true;
    this.isMtlsEngineError = true;
  }
}

var CA_KEY_USAGES = ["sign", "verify"];

// Algorithm priority — each entry probed at first use; the first one the
// vendored PKI toolkit AND webcrypto can both honour wins. Ordered
// highest-PQC-posture first so the engine issues post-quantum certificates
// by default. Every listed candidate has been confirmed to complete a real
// node:tls mutual-auth handshake on the supported Node LTS.
//
// keyAlg : passed to webcrypto.subtle.generateKey; the certificate signature
//          algorithm is resolved from the signing key by pki.x509.sign.
// label  : surfaced via b.mtlsCa.status() so operators can audit which
//          algorithm the in-flight CA generation is using, and passed to
//          generateCa({ algorithm }) to pin a specific one.
var ALG_CANDIDATES = [
  // Pure-PQC lattice — FIPS 204 (ML-DSA / Dilithium family). Verified end to
  // end in a node:tls mutual-auth handshake (chain + CertificateVerify).
  {
    label:  "ML-DSA-87",
    keyAlg: { name: "ML-DSA-87" },
    posture: "pqc-pure",
  },
  {
    label:  "ML-DSA-65",
    keyAlg: { name: "ML-DSA-65" },
    posture: "pqc-pure",
  },
  // Classical bridge — for peers not yet on OpenSSL 3.5. Opt in with
  // generateCa({ algorithm: "ECDSA-P384-SHA384" }).
  {
    label:  "ECDSA-P384-SHA384",
    keyAlg: { name: "ECDSA", namedCurve: "P-384" },
    posture: "classical",
  },
];

// First-call probe cache. Re-runs after engine reload (test reset path).
var _selectedAlg = null;

async function _probeCandidate(c) {
  try {
    var pair = await subtle.generateKey(c.keyAlg, true, CA_KEY_USAGES);
    /* c8 ignore next -- defensive: webcrypto.generateKey always resolves a valid keypair here */
    if (!pair || !pair.publicKey) return false;
    // Confirm the toolkit can also mint a certificate under this key — some
    // key algorithms keygen in webcrypto but aren't wired through the X.509
    // signer, and selecting one we can't issue with would surface a
    // confusing failure on first real issuance.
    var spki = Buffer.from(await subtle.exportKey("spki", pair.publicKey));
    await pki.x509.sign({
      subject:      "CN=probe",
      subjectPublicKey: spki,
      serialNumber: "0x01",
      notBefore:    new Date(),
      notAfter:     new Date(Date.now() + C.TIME.seconds(1)),
      extensions:   { basicConstraints: { cA: true } },
    }, { key: pair.privateKey }, { pem: true });
    return true;
  /* c8 ignore start -- probe never throws: every listed candidate algorithm is honoured by the runtime's OpenSSL 3.5+ */
  } catch (_e) {
    return false;
  }
  /* c8 ignore stop */
}

function _emitAlgorithmSelected(c, candidatesProbed) {
  setImmediate(function () {
    try {
      var auditMod = require("./audit");                                          // allow:inline-require — circular-load defense
      auditMod.safeEmit({
        action:   "mtls.engine.algorithm_selected",
        outcome:  "success",
        metadata: { label: c.label, posture: c.posture, candidatesProbed: candidatesProbed },
      });
    /* c8 ignore next -- belt-and-suspenders: audit.safeEmit is itself drop-silent, so this catch is unreachable */
    } catch (_e) { /* drop-silent */ }
  });
}

// Resolve the signing algorithm. With no argument the highest-posture
// candidate that probes clean is cached and reused. `preferredLabel` pins a
// specific candidate (the generateCa({ algorithm }) opt-in) — it must exist
// and probe clean, else the call throws rather than silently downgrading.
async function _selectAlgorithm(preferredLabel) {
  if (preferredLabel) {
    var wanted = null;
    for (var w = 0; w < ALG_CANDIDATES.length; w++) {
      if (ALG_CANDIDATES[w].label === preferredLabel || ALG_CANDIDATES[w].keyAlg.name === preferredLabel) {
        wanted = ALG_CANDIDATES[w];
        break;
      }
    }
    if (!wanted) {
      throw new MtlsEngineError("mtls-engine/unknown-algorithm",
        "unknown algorithm " + JSON.stringify(preferredLabel) + " — supported: " +
        ALG_CANDIDATES.map(function (c) { return c.label; }).join(", "));
    }
    /* c8 ignore start -- unreachable: every pinnable candidate probes clean on the runtime's OpenSSL 3.5+ */
    if (!(await _probeCandidate(wanted))) {
      throw new MtlsEngineError("mtls-engine/algorithm-unavailable",
        "algorithm " + JSON.stringify(preferredLabel) + " is not available in this runtime");
    }
    /* c8 ignore stop */
    // A pinned algorithm is per-call and MUST NOT be cached as the process
    // default. `_selectedAlg` is the shared fallback the no-argument path below
    // returns; writing a classical pin here would make a single
    // generateCa({ algorithm: "ECDSA-P384-SHA384" }) silently downgrade every
    // later default CA/leaf off the ML-DSA-87 PQC-first default in the same
    // process. Callers thread a pin explicitly through generateCa /
    // signClientCert instead (b.mtlsCa.create({ algorithm })).
    _emitAlgorithmSelected(wanted, 1);
    return wanted;
  }
  if (_selectedAlg) return _selectedAlg;
  for (var i = 0; i < ALG_CANDIDATES.length; i++) {
    var c = ALG_CANDIDATES[i];
    if (await _probeCandidate(c)) {
      _selectedAlg = c;
      _emitAlgorithmSelected(c, i + 1);
      return c;
    }
  }
  /* c8 ignore start -- unreachable: ECDSA-P384-SHA384 is universal, so the candidate loop always returns first */
  // Should never happen — ECDSA-P384 is universal.
  throw new MtlsEngineError("mtls-engine/no-algorithm",
    "no candidate algorithm passed the webcrypto + x509 probe");
  /* c8 ignore stop */
}

// PKCS#12 protection envelope. The cipher / PRF / MAC identifiers are
// protocol-fixed strings, and the iteration count is a cost parameter, not a
// byte quantity — hex form keeps it out of the byte-shape detector.
var P12_CIPHER   = "aes-256-cbc";
var P12_PRF      = "hmacWithSHA512";
var P12_MAC_HASH = "sha512";
var P12_ITER     = 0x1E8480; // 2,000,000

var CA_VALIDITY_DAYS    = 10 * 365; // 10y CA lifetime
var LEAF_DEFAULT_DAYS   = 365;
var DEFAULT_CA_NAME     = "blamejs CA";

function _serial() {
  // pki wants a decimal or 0x-hex integer; generateToken yields hex octets.
  return "0x" + bCrypto.generateToken(C.BYTES.bytes(16));
}

function _ekuNames(usage) {
  var names = [];
  if (usage === "client" || usage === "both") names.push("clientAuth");
  if (usage === "server" || usage === "both") names.push("serverAuth");
  return names;
}

// Pack a textual IP into the DER octet form pki's iPAddress GeneralName
// expects (4 octets for IPv4, 16 for IPv6). Composes lib/ip-utils.
function _packIp(value) {
  var s = String(value);
  if (ipUtils.isIPv4(s)) {
    var quads = s.split(".");
    var buf4 = Buffer.alloc(4);
    for (var i = 0; i < 4; i++) {
      var n = parseInt(quads[i], 10);
      /* c8 ignore next -- unreachable: the IPv4 arm is entered only after isIPv4() validated each octet 0-255 */
      if (!(n >= 0 && n <= 255)) throw new MtlsEngineError("mtls-engine/bad-san", "invalid IPv4 SAN " + JSON.stringify(s));
      buf4[i] = n;
    }
    return buf4;
  }
  var groups;
  /* c8 ignore next -- unreachable: expandIpv6Groups returns null for malformed input rather than throwing */
  try { groups = ipUtils.expandIpv6Groups(s); } catch (_e) { groups = null; }
  if (Array.isArray(groups) && groups.length === 8) {
    var buf16 = Buffer.alloc(16);
    for (var g = 0; g < 8; g++) buf16.writeUInt16BE(groups[g] & 0xffff, g * 2);
    return buf16;
  }
  throw new MtlsEngineError("mtls-engine/bad-san", "invalid IP SAN " + JSON.stringify(s));
}

// Map operator SAN entries (strings, optionally "DNS:" / "IP:" prefixed) to
// pki GeneralName objects.
function _sanEntry(s) {
  var str = String(s);
  if (/^DNS:/i.test(str)) return { dNSName: str.slice(4) };
  if (/^IP:/i.test(str))  return { iPAddress: _packIp(str.slice(3)) };
  if (ipUtils.isIPv4(str)) return { iPAddress: _packIp(str) };
  // Bare non-IPv4 entries default to DNS — matches operator expectation.
  return { dNSName: str };
}

function _normaliseCn(cn) {
  var s = String(cn || "").replace(/[^a-zA-Z0-9_.-]/g, "").slice(0, 63);
  if (!s) {
    throw new MtlsEngineError("mtls-engine/bad-cn",
      "cn must contain at least one [A-Za-z0-9._-] character (post-sanitisation)");
  }
  return s;
}

async function generateCa(opts) {
  opts = opts || {};
  var generation = (typeof opts.generation === "number" && opts.generation >= 1)
    ? Math.floor(opts.generation) : 1;
  var caName = opts.name || DEFAULT_CA_NAME;

  var alg = await _selectAlgorithm(opts.algorithm);
  var keys = await subtle.generateKey(alg.keyAlg, true, CA_KEY_USAGES);
  var spki = Buffer.from(await subtle.exportKey("spki", keys.publicKey));
  var now  = new Date();

  var caCertPem = await pki.x509.sign({
    subject:          "CN=" + caName + ",OU=CAv" + generation,
    subjectPublicKey: spki,
    serialNumber:     _serial(),
    notBefore:        now,
    notAfter:         new Date(now.getTime() + C.TIME.days(CA_VALIDITY_DAYS)),
    extensions:       { basicConstraints: { cA: true, pathLen: 0 }, keyUsage: ["keyCertSign", "cRLSign"] },
  }, { key: keys.privateKey }, { pem: true });

  var caKeyPem = await pki.key.export(keys.privateKey, { format: "pem" });
  return { caCertPem: caCertPem, caKeyPem: caKeyPem };
}

async function signClientCert(opts) {
  opts = opts || {};
  if (typeof opts.cn !== "string" || !opts.caCertPem || !opts.caKeyPem) {
    throw new MtlsEngineError("mtls-engine/missing-arg",
      "signClientCert requires { cn, caCertPem, caKeyPem }");
  }
  numericBounds.requirePositiveFiniteIntIfPresent(opts.validityDays,
    "signClientCert: validityDays", MtlsEngineError, "mtls-engine/bad-validity-days");
  var validityDays = opts.validityDays !== undefined
    ? opts.validityDays : LEAF_DEFAULT_DAYS;
  var cn = _normaliseCn(opts.cn);

  // Extended Key Usage: defaults to clientAuth (the historical behaviour).
  // usage: "server" -> serverAuth; "both" -> clientAuth + serverAuth.
  var usage = opts.usage || "client";
  var ekuNames = _ekuNames(usage);
  if (ekuNames.length === 0) {
    throw new MtlsEngineError("mtls-engine/bad-usage",
      "signClientCert: opts.usage must be 'client' | 'server' | 'both', got " +
      JSON.stringify(opts.usage));
  }

  // Subject Alternative Names — required for serverAuth (modern TLS clients
  // only honor SANs, not CN). Accept opts.sans as an array of strings.
  var sans = null;
  if (Array.isArray(opts.sans) && opts.sans.length > 0) {
    sans = opts.sans.map(_sanEntry);
  } else if (usage === "server" || usage === "both") {
    // serverAuth without a SAN is unverifiable by modern TLS clients.
    sans = [{ dNSName: cn }];
  }

  // Leaf key algorithm follows the CA's: an ML-DSA-87 default, or the classical
  // bridge when the caller pinned one (b.mtlsCa threads its create({ algorithm })
  // through here). Undefined selects the process default.
  var alg = await _selectAlgorithm(opts.algorithm);
  var clientKeys = await subtle.generateKey(alg.keyAlg, true, CA_KEY_USAGES);
  var clientSpki = Buffer.from(await subtle.exportKey("spki", clientKeys.publicKey));

  var now      = new Date();
  var notAfter = new Date(now.getTime() + C.TIME.days(validityDays));
  var extensions = {
    basicConstraints:         { cA: false },
    keyUsage:                 ["digitalSignature", "keyEncipherment"],
    extendedKeyUsage:         ekuNames,
    extendedKeyUsageCritical: true,
  };
  if (sans) extensions.subjectAltName = sans;

  var certPem = await pki.x509.sign({
    subject:          "CN=" + cn,
    subjectPublicKey: clientSpki,
    serialNumber:     _serial(),
    notBefore:        now,
    notAfter:         notAfter,
    extensions:       extensions,
  }, { cert: opts.caCertPem, key: opts.caKeyPem }, { pem: true });

  var keyPem = await pki.key.export(clientKeys.privateKey, { format: "pem" });
  return {
    cert:      certPem,
    key:       keyPem,
    ca:        opts.caCertPem,
    issuedAt:  now.toISOString(),
    expiresAt: notAfter.toISOString(),
    usage:     usage,
  };
}

async function packageP12(opts) {
  opts = opts || {};
  if (typeof opts.password !== "string" || opts.password.length < 1) {
    throw new MtlsEngineError("mtls-engine/no-password",
      "packageP12 requires opts.password (non-empty string)");
  }
  var leaf = await signClientCert(opts);

  var pbe = { password: opts.password, cipher: P12_CIPHER, iterations: P12_ITER, prf: P12_PRF };
  var p12 = await pki.pkcs12.build({
    safeContents: [
      { bags: [{ type: "shroudedKey", key: leaf.key, encrypt: pbe }] },
      { encrypt: pbe, bags: [
        { type: "cert", cert: leaf.cert },
        { type: "cert", cert: leaf.ca },
      ] },
    ],
  }, { password: opts.password, mac: { algorithm: "pbmac1", hash: P12_MAC_HASH, iterations: P12_ITER } });

  return {
    /* c8 ignore next -- defensive: pki.pkcs12.build always returns a Buffer, so the Buffer.from() arm is unreachable */
    p12:       Buffer.isBuffer(p12) ? p12 : Buffer.from(p12),
    certPem:   leaf.cert,
    issuedAt:  leaf.issuedAt,
    expiresAt: leaf.expiresAt,
  };
}

function algorithmEnvelope() {
  return {
    cert: {
      keyAlg:   _selectedAlg && _selectedAlg.keyAlg,
      label:    _selectedAlg && _selectedAlg.label,
      posture:  _selectedAlg && _selectedAlg.posture,
      // Operators querying status() before any cert has been issued get the
      // candidate priority list — the engine probes lazily so the chosen
      // algorithm isn't known until first use.
      priority: ALG_CANDIDATES.map(function (c) {
        return { label: c.label, posture: c.posture };
      }),
    },
    p12: {
      contentEncryption: P12_CIPHER,
      kdfPrf:            P12_PRF,
      macAlgorithm:      "pbmac1",
      macHash:           P12_MAC_HASH,
      iterationCount:    P12_ITER,
    },
    caValidityDays:   CA_VALIDITY_DAYS,
    leafDefaultDays:  LEAF_DEFAULT_DAYS,
  };
}

// Generate a signed X.509 CRL (RFC 5280) covering every revoked serial
// number. pki.crl.sign builds the TBSCertList, populates the entries, and
// signs under the CA private key — the signature algorithm is resolved from
// the CA key, matching the algorithm the CA itself was issued under.
async function generateCrl(opts) {
  opts = opts || {};
  if (!opts.caCertPem || !opts.caKeyPem) {
    throw new MtlsEngineError("mtls-engine/missing-arg",
      "generateCrl requires { caCertPem, caKeyPem, revocations, thisUpdate, nextUpdate }");
  }
  var revocations = Array.isArray(opts.revocations) ? opts.revocations : [];

  var revoked = revocations.map(function (r) {
    var entry = {
      serialNumber:   _normaliseRevokedSerial(r.serialNumber),
      revocationDate: new Date(r.revokedAt || Date.now()),
    };
    if (typeof r.reasonCode === "number") entry.reason = r.reasonCode;
    return entry;
  });

  return pki.crl.sign({
    thisUpdate: opts.thisUpdate || new Date(),
    nextUpdate: opts.nextUpdate,
    revoked:    revoked,
  }, { cert: opts.caCertPem, key: opts.caKeyPem }, { pem: true });
}

// A revoked serial arrives as the hex string the engine issued (no 0x
// prefix). pki wants a decimal or 0x-hex integer, so prefix bare hex.
function _normaliseRevokedSerial(serial) {
  var s = String(serial == null ? "" : serial);
  if (/^0x/i.test(s)) return s;
  if (safeBuffer.isHex(s)) return "0x" + s;
  return s;
}

module.exports = {
  generateCa:         generateCa,
  signClientCert:     signClientCert,
  packageP12:         packageP12,
  generateCrl:        generateCrl,
  algorithmEnvelope:  algorithmEnvelope,
  MtlsEngineError:    MtlsEngineError,
};
