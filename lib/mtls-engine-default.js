"use strict";
/**
 * mtls-engine-default — pure-JS X.509 engine wired into b.mtlsCa.
 *
 * Implements the engine contract documented at the top of lib/mtls-ca.js:
 *   generateCa({ generation })            -> { caCertPem, caKeyPem }
 *   signClientCert({ cn, validityDays,
 *                    caCertPem, caKeyPem })   -> { cert, key, ca, issuedAt, expiresAt }
 *   packageP12({ cn, password, validityDays,
 *                caCertPem, caKeyPem })       -> { p12, certPem, issuedAt, expiresAt }
 *
 * Backed by lib/vendor/pki.cjs (vendored @peculiar/x509 + pkijs +
 * reflect-metadata + ASN.1 schema chain). node:crypto.webcrypto is bound
 * inside the bundle entry; nothing here calls openssl CLI.
 *
 * Algorithm envelope:
 *   CA + leaf signatures: ECDSA P-384 + SHA-384
 *   PKCS#12 key bag      : PBES2 + AES-256-CBC + PBKDF2-HMAC-SHA-512, 2,000,000 iter
 *   PKCS#12 cert bag     : same as key bag
 *   PKCS#12 outer MAC    : HMAC-SHA-512 + PBKDF2, 2,000,000 iter
 *
 * The X.509 ecosystem doesn't yet accept SLH-DSA / ML-DSA on shipping
 * client certs, so the cert sigs stay classical ECDSA-P384 — matching
 * the framework's hybrid KEM posture rather than its standalone PQ
 * signing posture. Swap atomically when browsers + OS cert stores can
 * verify a PQ algorithm; bump CA_GENERATION on the same release so
 * b.mtlsCa.status reports legacy correctly.
 */

var nodeCrypto = require("node:crypto");

var pki = require("./vendor/pki.cjs");

var C = require("./constants");
var crypto = require("./crypto");
var { FrameworkError } = require("./framework-error");

var x509 = pki.x509;
var pkijs = pki.pkijs;
var webcrypto = pki.crypto;

class MtlsEngineError extends FrameworkError {
  constructor(code, message) {
    super(message, code);
    this.name = "MtlsEngineError";
    this.permanent = true;
    this.isMtlsEngineError = true;
  }
}

var CA_KEY_ALG    = { name: "ECDSA", namedCurve: "P-384" };
var CA_SIG_ALG    = { name: "ECDSA", hash: "SHA-384" };
var CA_KEY_USAGES = ["sign", "verify"];

var P12_CONTENT_ENC = { name: "AES-CBC", length: 256 };
var P12_KDF_HASH    = "SHA-512";
var P12_MAC_HASH    = "SHA-512";
var P12_ITER        = 2000000;

var CA_VALIDITY_DAYS    = 10 * 365; // 10y CA lifetime
var LEAF_DEFAULT_DAYS   = 365;
var DEFAULT_CA_NAME     = "blamejs CA";
var BAG_ID_KEY          = "1.2.840.113549.1.12.10.1.2"; // pkcs-12-pkcs-8ShroudedKeyBag
var BAG_ID_CERT         = "1.2.840.113549.1.12.10.1.3"; // pkcs-12-certBag
var EKU_CLIENT_AUTH_OID = "1.3.6.1.5.5.7.3.2";

function _pemBlock(label, der) {
  var b64 = Buffer.from(der).toString("base64");
  return "-----BEGIN " + label + "-----\n" + b64.match(/.{1,64}/g).join("\n") + "\n-----END " + label + "-----\n";
}

async function _exportKeyPairToPem(keyPair) {
  var pkcs8 = await webcrypto.subtle.exportKey("pkcs8", keyPair.privateKey);
  var spki  = await webcrypto.subtle.exportKey("spki",  keyPair.publicKey);
  return {
    privatePem: _pemBlock("PRIVATE KEY", pkcs8),
    publicPem:  _pemBlock("PUBLIC KEY",  spki),
  };
}

// Import a PEM private key regardless of its on-disk encoding.
// Existing keys may be SEC1, PKCS#1, or PKCS#8 — Node's createPrivateKey
// normalises all three; webcrypto.importKey then reads the PKCS#8 DER.
async function _importPemPrivateKey(pem, alg, usages, extractable) {
  var keyObj  = nodeCrypto.createPrivateKey(pem);
  var pkcs8   = keyObj.export({ format: "der", type: "pkcs8" });
  return webcrypto.subtle.importKey("pkcs8", pkcs8, alg, !!extractable, usages);
}

function _parseCertPem(pem) {
  return new x509.X509Certificate(pem);
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

  var keys = await webcrypto.subtle.generateKey(CA_KEY_ALG, true, CA_KEY_USAGES);
  var now  = new Date();
  var ca = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: crypto.generateToken(16),
    name: "CN=" + caName + ",OU=CAv" + generation,
    notBefore: now,
    notAfter: new Date(now.getTime() + C.TIME.days(CA_VALIDITY_DAYS)),
    signingAlgorithm: CA_SIG_ALG,
    keys: keys,
    extensions: [
      new x509.BasicConstraintsExtension(true, 0, true),
      new x509.KeyUsagesExtension(
        x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign,
        true
      ),
    ],
  });
  var pem = await _exportKeyPairToPem(keys);
  return { caCertPem: ca.toString("pem"), caKeyPem: pem.privatePem };
}

async function signClientCert(opts) {
  opts = opts || {};
  if (typeof opts.cn !== "string" || !opts.caCertPem || !opts.caKeyPem) {
    throw new MtlsEngineError("mtls-engine/missing-arg",
      "signClientCert requires { cn, caCertPem, caKeyPem }");
  }
  var validityDays = (typeof opts.validityDays === "number" && opts.validityDays > 0)
    ? Math.floor(opts.validityDays) : LEAF_DEFAULT_DAYS;
  var cn = _normaliseCn(opts.cn);

  var caKey   = await _importPemPrivateKey(opts.caKeyPem, CA_KEY_ALG, ["sign"]);
  var caCert  = _parseCertPem(opts.caCertPem);
  var clientKeys = await webcrypto.subtle.generateKey(CA_KEY_ALG, true, CA_KEY_USAGES);

  var now      = new Date();
  var notAfter = new Date(now.getTime() + C.TIME.days(validityDays));
  var clientCert = await x509.X509CertificateGenerator.create({
    serialNumber: crypto.generateToken(16),
    subject: "CN=" + cn,
    issuer: caCert.subject,
    notBefore: now,
    notAfter: notAfter,
    signingAlgorithm: CA_SIG_ALG,
    publicKey: clientKeys.publicKey,
    signingKey: caKey,
    extensions: [
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.KeyUsagesExtension(
        x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.keyEncipherment,
        true
      ),
      new x509.ExtendedKeyUsageExtension([EKU_CLIENT_AUTH_OID], true),
    ],
  });
  var pem = await _exportKeyPairToPem(clientKeys);
  return {
    cert:      clientCert.toString("pem"),
    key:       pem.privatePem,
    ca:        opts.caCertPem,
    issuedAt:  now.toISOString(),
    expiresAt: notAfter.toISOString(),
  };
}

async function packageP12(opts) {
  opts = opts || {};
  if (typeof opts.password !== "string" || opts.password.length < 1) {
    throw new MtlsEngineError("mtls-engine/no-password",
      "packageP12 requires opts.password (non-empty string)");
  }
  var leaf = await signClientCert(opts);

  // Re-import the leaf key as extractable so we can re-export PKCS#8 DER
  // for the shrouded key bag.
  var leafKey       = await _importPemPrivateKey(leaf.key, CA_KEY_ALG, ["sign"], true);
  var leafPkcs8     = await webcrypto.subtle.exportKey("pkcs8", leafKey);
  var privateKeyInfo = pkijs.PrivateKeyInfo.fromBER(leafPkcs8);

  var leafX509  = _parseCertPem(leaf.cert);
  var caX509    = _parseCertPem(leaf.ca);
  var leafPkijsCert = pkijs.Certificate.fromBER(leafX509.rawData);
  var caPkijsCert   = pkijs.Certificate.fromBER(caX509.rawData);

  var passwordBuf = Buffer.from(opts.password, "utf8");

  var pfx = new pkijs.PFX({
    parsedValue: {
      integrityMode: 0, // PasswordMode (outer HMAC-PBKDF2)
      authenticatedSafe: new pkijs.AuthenticatedSafe({
        parsedValue: {
          safeContents: [
            {
              privacyMode: 1, // PasswordPrivacyMode (PBES2)
              value: new pkijs.SafeContents({
                safeBags: [
                  new pkijs.SafeBag({
                    bagId: BAG_ID_KEY,
                    bagValue: new pkijs.PKCS8ShroudedKeyBag({ parsedValue: privateKeyInfo }),
                  }),
                ],
              }),
            },
            {
              privacyMode: 1,
              value: new pkijs.SafeContents({
                safeBags: [
                  new pkijs.SafeBag({
                    bagId: BAG_ID_CERT,
                    bagValue: new pkijs.CertBag({ parsedValue: leafPkijsCert }),
                  }),
                  new pkijs.SafeBag({
                    bagId: BAG_ID_CERT,
                    bagValue: new pkijs.CertBag({ parsedValue: caPkijsCert }),
                  }),
                ],
              }),
            },
          ],
        },
      }),
    },
  });

  // Inner protection on the shrouded-key bag itself.
  await pfx.parsedValue.authenticatedSafe.parsedValue.safeContents[0]
    .value.safeBags[0].bagValue.makeInternalValues({
      password: passwordBuf,
      contentEncryptionAlgorithm: P12_CONTENT_ENC,
      hmacHashAlgorithm: P12_KDF_HASH,
      iterationCount: P12_ITER,
    });

  // Encrypt each SafeContents envelope.
  await pfx.parsedValue.authenticatedSafe.makeInternalValues({
    safeContents: [
      { password: passwordBuf, contentEncryptionAlgorithm: P12_CONTENT_ENC, hmacHashAlgorithm: P12_KDF_HASH, iterationCount: P12_ITER },
      { password: passwordBuf, contentEncryptionAlgorithm: P12_CONTENT_ENC, hmacHashAlgorithm: P12_KDF_HASH, iterationCount: P12_ITER },
    ],
  });

  // Outer integrity MAC.
  await pfx.makeInternalValues({
    password: passwordBuf,
    iterations: P12_ITER,
    pbkdf2HashAlgorithm: P12_KDF_HASH,
    hmacHashAlgorithm: P12_MAC_HASH,
  });

  return {
    p12:       Buffer.from(pfx.toSchema().toBER(false)),
    certPem:   leaf.cert,
    issuedAt:  leaf.issuedAt,
    expiresAt: leaf.expiresAt,
  };
}

function algorithmEnvelope() {
  return {
    cert: { keyAlg: CA_KEY_ALG, sigAlg: CA_SIG_ALG },
    p12:  {
      contentEncryption: P12_CONTENT_ENC,
      kdfHash: P12_KDF_HASH,
      macHash: P12_MAC_HASH,
      iterationCount: P12_ITER,
    },
    caValidityDays:   CA_VALIDITY_DAYS,
    leafDefaultDays:  LEAF_DEFAULT_DAYS,
  };
}

module.exports = {
  generateCa:         generateCa,
  signClientCert:     signClientCert,
  packageP12:         packageP12,
  algorithmEnvelope:  algorithmEnvelope,
  MtlsEngineError:    MtlsEngineError,
};
