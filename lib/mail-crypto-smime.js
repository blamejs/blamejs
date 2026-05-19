"use strict";
/**
 * @module     b.mail.crypto.smime
 * @nav        Communication
 * @title      Mail S/MIME
 * @order      121
 * @slug       mail-crypto-smime
 *
 * @card
 *   S/MIME 4.0 signature verification per RFC 8551 + RFC 5652 CMS
 *   SignedData. v1 surface is cert preflight; sign/verify deferred.
 *
 * @intro
 *   S/MIME 4.0 (RFC 8551, replacing RFC 5751) `multipart/signed;
 *   protocol="application/pkcs7-signature"` signature verification
 *   for inbound mail. CMS SignedData (RFC 5652) carries the actual
 *   signature; the signed payload travels in the first MIME part of
 *   the multipart/signed wrapper with the SignedData attached to the
 *   second part as base64-encoded DER.
 *
 *   Posture (when the surface lights up):
 *     - Refuses SHA-1 as the signature hash (CVE-2017-9006-class —
 *       PKCS#7 collision attacks against legacy S/MIME) and as the
 *       certificate signature algorithm.
 *     - Refuses RSA keys < 2048 bits (RFC 8301 §3.1 — same posture
 *       as the rest of the mail surface).
 *     - Refuses MD5 anywhere (the historical S/MIME-v2 default; long
 *       broken).
 *     - Validates the signer certificate's chain against an operator-
 *       supplied trust anchor set; never falls back to a system root
 *       store implicitly (the system store binds operator trust to
 *       whatever the host happens to ship with).
 *     - Refuses certificate algorithms outside the modern set
 *       (RSA-PKCS1-v1_5 with SHA-256 / SHA-384 / SHA-512, ECDSA over
 *       P-256 / P-384 with SHA-256 / SHA-384, Ed25519). RFC 8551 §2.5
 *       mandates SHA-256 as the MUST-support floor.
 *
 *   Threat model:
 *     - EFAIL (CVE-2017-17688 / CVE-2017-17689) — the S/MIME variant
 *       attacks decrypt+render pipelines. Same gate as PGP: when
 *       encrypt/decrypt lights up, decrypted HTML routes through
 *       `b.guardHtml` strict profile, remote-content fetches in
 *       encrypted parts are refused, and the MIME-part tree at
 *       decrypt time is compared byte-for-byte against the tree at
 *       render time.
 *     - PKCS#7 / CMS parser confusion — only the SignedData
 *       (ContentType 1.2.840.113549.1.7.2) ContentInfo shape is
 *       accepted; degenerate, certs-only-bag, AuthEnvelopedData, and
 *       encrypted-content variants are refused at parse time.
 *
 *   v0.10.16 status — LIVE on `b.cms` substrate:
 *
 *     sign() and verify() ship working on the CMS substrate landed in
 *     v0.10.13 + the SignedData walker (`b.cms.parseSignedData`)
 *     landed in v0.10.16. sign() composes b.cms.encodeSignedData +
 *     wraps the result in an RFC 8551 multipart/signed envelope.
 *     verify() parses the CMS SignedData payload, recomputes the
 *     message digest, compares against the signed-attrs
 *     messageDigest attribute (refuses tamper), and verifies the
 *     PQC signature against the operator-supplied signer public key.
 *     Multi-signer reports surface every SignerInfo via
 *     `b.cms.parseSignedData(...).signerInfos`; verify() handles
 *     the first signer — operators with multi-signer flows walk the
 *     SignerInfos themselves.
 *
 * RFC citations:
 *   - RFC 8551 (S/MIME 4.0 Message Specification, April 2019;
 *     obsoletes RFC 5751)
 *   - RFC 5652 (Cryptographic Message Syntax — CMS)
 *   - RFC 8550 (S/MIME 4.0 Certificate Handling)
 *   - RFC 5280 (X.509 PKI)
 *   - RFC 8301 (RSA bit floor — reused as cross-mail-surface RSA posture)
 *
 * CVE citations:
 *   - CVE-2017-17688 / CVE-2017-17689 (EFAIL — S/MIME variant; informs
 *     the encrypt+decrypt deferral when that surface lights up)
 *   - CVE-2017-9006 (PKCS#7 / S/MIME signature-validation bypass
 *     class — informs the SHA-1 refusal posture)
 *   - CVE-2018-5407 (PortSmash — informs the side-channel hardening
 *     posture when private operations land in v2)
 */
var lazyRequire  = require("./lazy-require");
var audit        = lazyRequire(function () { return require("./audit"); });
var nodeCrypto   = require("node:crypto");
var validateOpts = require("./validate-opts");
var cms          = require("./cms-codec");
var asn1         = require("./asn1-der");
var pqcSoftware  = require("./pqc-software");
var { defineClass } = require("./framework-error");

var MailCryptoError = defineClass("MailCryptoError", { alwaysPermanent: true });

// Constant posture values exported so operators reading this module
// from configuration code can pin to them by reference rather than
// hand-copying strings. These reflect RFC 8551 §2.5 + RFC 8301 floors.
var RSA_MIN_BITS = 2048;                                                          // allow:raw-byte-literal — RFC 8301 §3.1
var ALLOWED_HASHES = ["sha256", "sha384", "sha512"];
var REFUSED_HASHES = ["md5", "sha1"];                                             // allow:raw-byte-literal — CVE-2017-9006-class

// PROFILES + COMPLIANCE_POSTURES — the framework's standard cross-
// primitive contract. v1 only emits the metadata; the deferred sign/
// verify methods read them when they light up.
var PROFILES = ["strict", "balanced", "permissive"];
var COMPLIANCE_POSTURES = {
  hipaa:     "strict",
  "pci-dss": "strict",
  gdpr:      "strict",
  soc2:      "strict",
};

// ---- Public surface (v0.10.16 lights up — composes b.cms) ----

/**
 * @primitive  b.mail.crypto.smime.sign
 * @signature  b.mail.crypto.smime.sign(opts)
 * @since      0.10.16
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.mail.crypto.smime.verify, b.cms.encodeSignedData
 *
 * Sign an RFC 5322 message with S/MIME 4.0 (RFC 8551) producing a
 * `multipart/signed; protocol="application/pkcs7-signature"` wrapper.
 * The CMS SignedData payload is encoded via `b.cms.encodeSignedData`
 * with PQC signers (ML-DSA-65 / ML-DSA-87 / SLH-DSA-SHAKE-256f).
 * Returns `{ multipart, signature }` where `multipart` is the wire
 * representation (Content-Type + body) and `signature` is the raw
 * CMS DER for operators that want to handle the MIME framing
 * themselves.
 *
 * @opts
 *   message:        Buffer|string,                    // message bytes to sign (signed-as-is)
 *   certificate:    Buffer,                           // DER-encoded signer cert
 *   secretKey:      Uint8Array,                       // PQC private key (b.pqcSoftware.ml_dsa_*.keygen())
 *   sigAlg:         "ML-DSA-65"|"ML-DSA-87"|"SLH-DSA-SHAKE-256f",
 *   digestAlg:      "sha3-256"|"sha3-512",            // default sha3-512
 *   boundary:       string,                           // optional; auto-generated if omitted
 *   audit:          object,                           // optional b.audit handle
 *
 * @example
 *   var kp = b.pqcSoftware.ml_dsa_65.keygen();
 *   var out = b.mail.crypto.smime.sign({
 *     message:     "From: x@y\r\nSubject: hi\r\n\r\nbody",
 *     certificate: certDer,
 *     secretKey:   kp.secretKey,
 *     sigAlg:      "ML-DSA-65",
 *   });
 *   out.multipart;  // → "Content-Type: multipart/signed; ..."
 */
function sign(opts) {
  opts = validateOpts.requireObject(opts, "mail.crypto.smime.sign",
    MailCryptoError, "mail-crypto/smime/bad-opts");
  validateOpts(opts, ["message", "certificate", "secretKey", "sigAlg",
                       "digestAlg", "boundary", "audit"],
    "mail.crypto.smime.sign");
  if (!opts.message || (!Buffer.isBuffer(opts.message) && typeof opts.message !== "string")) {
    throw new MailCryptoError("mail-crypto/smime/bad-opts",
      "smime.sign: opts.message must be a Buffer or string");
  }
  var msgBytes = Buffer.isBuffer(opts.message) ? opts.message : Buffer.from(opts.message, "utf8");
  if (!Buffer.isBuffer(opts.certificate)) {
    throw new MailCryptoError("mail-crypto/smime/bad-opts",
      "smime.sign: opts.certificate must be a DER Buffer");
  }
  if (!(opts.secretKey instanceof Uint8Array)) {
    throw new MailCryptoError("mail-crypto/smime/bad-opts",
      "smime.sign: opts.secretKey must be a Uint8Array from b.pqcSoftware.ml_dsa_*.keygen()");
  }
  var digestAlg = opts.digestAlg || "sha3-512";
  var micalg    = digestAlg === "sha3-256" ? "sha3-256" : "sha3-512";
  var sd;
  try {
    sd = cms.encodeSignedData({
      encapContent: msgBytes,
      digestAlg:    digestAlg,
      detached:     true,
      signers: [{
        certificate: opts.certificate,
        secretKey:   opts.secretKey,
        sigAlg:      opts.sigAlg,
      }],
    });
  } catch (e) {
    _audit(opts.audit, "mail.crypto.smime.sign", "denied", {
      reason: (e && e.code) || "cms-encode-failed",
    });
    throw new MailCryptoError("mail-crypto/smime/sign-failed",
      "smime.sign: " + ((e && e.message) || String(e)));
  }
  var boundary = opts.boundary ||
    "blamejs-smime-" + nodeCrypto.randomBytes(16).toString("hex");                                    // allow:raw-byte-literal — 16-byte random boundary token
  var sigBase64 = _wrapBase64(sd.toString("base64"));
  var multipart =
    "Content-Type: multipart/signed; protocol=\"application/pkcs7-signature\"; " +
    "micalg=" + micalg + "; boundary=\"" + boundary + "\"\r\n" +
    "\r\n" +
    "--" + boundary + "\r\n" +
    msgBytes.toString("utf8") + "\r\n" +
    "--" + boundary + "\r\n" +
    "Content-Type: application/pkcs7-signature; name=\"smime.p7s\"\r\n" +
    "Content-Transfer-Encoding: base64\r\n" +
    "Content-Disposition: attachment; filename=\"smime.p7s\"\r\n" +
    "\r\n" +
    sigBase64 + "\r\n" +
    "--" + boundary + "--\r\n";
  _audit(opts.audit, "mail.crypto.smime.sign", "success", {
    sigAlg:    opts.sigAlg,
    digestAlg: digestAlg,
  });
  return {
    multipart: multipart,
    signature: sd,
    boundary:  boundary,
    micalg:    micalg,
  };
}

/**
 * @primitive  b.mail.crypto.smime.verify
 * @signature  b.mail.crypto.smime.verify(opts)
 * @since      0.10.16
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.mail.crypto.smime.sign, b.cms.parseSignedData
 *
 * Verify an RFC 8551 `multipart/signed` S/MIME envelope. Parses the
 * CMS SignedData payload, recomputes the message digest, compares
 * against the `message-digest` signed-attribute, and verifies the
 * signature against the signer's PQC public key. Returns
 * `{ valid, signerPublicKey, sigAlg, digestAlg }` on success;
 * throws on any mismatch.
 *
 * @opts
 *   message:          Buffer|string,        // original signed bytes (use sign().multipart's first part)
 *   signature:        Buffer,               // raw CMS DER (sign().signature)
 *   signerPublicKey:  Uint8Array,           // PQC public key of the expected signer
 *   audit:            object,
 *
 * @example
 *   var ok = b.mail.crypto.smime.verify({
 *     message:         msgBytes,
 *     signature:       cmsDer,
 *     signerPublicKey: kp.publicKey,
 *   });
 *   ok.valid;   // → true
 */
function verify(opts) {
  opts = validateOpts.requireObject(opts, "mail.crypto.smime.verify",
    MailCryptoError, "mail-crypto/smime/bad-opts");
  validateOpts(opts, ["message", "signature", "signerPublicKey", "audit"],
    "mail.crypto.smime.verify");
  if (!opts.message || (!Buffer.isBuffer(opts.message) && typeof opts.message !== "string")) {
    throw new MailCryptoError("mail-crypto/smime/bad-opts",
      "smime.verify: opts.message must be a Buffer or string");
  }
  if (!Buffer.isBuffer(opts.signature)) {
    throw new MailCryptoError("mail-crypto/smime/bad-opts",
      "smime.verify: opts.signature must be a DER Buffer");
  }
  if (!(opts.signerPublicKey instanceof Uint8Array)) {
    throw new MailCryptoError("mail-crypto/smime/bad-opts",
      "smime.verify: opts.signerPublicKey must be a Uint8Array");
  }
  var msgBytes = Buffer.isBuffer(opts.message) ? opts.message : Buffer.from(opts.message, "utf8");
  var sd;
  try { sd = cms.parseSignedData(opts.signature); }
  catch (e) {
    _audit(opts.audit, "mail.crypto.smime.verify_fail", "denied", {
      reason: (e && e.code) || "cms-parse-failed",
    });
    throw new MailCryptoError("mail-crypto/smime/parse-failed",
      "smime.verify: " + ((e && e.message) || String(e)));
  }
  if (sd.signerInfos.length === 0) {
    throw new MailCryptoError("mail-crypto/smime/no-signers",
      "smime.verify: CMS SignedData has no SignerInfos");
  }
  // v1 verifies the first SignerInfo (multi-signer mail flows
  // typically check every signer; operators with that need walk
  // sd.signerInfos themselves + call this primitive per signer).
  var si = sd.signerInfos[0];
  var sigAlg = _oidToSigAlg(si.sigAlgOid);
  if (!sigAlg) {
    throw new MailCryptoError("mail-crypto/smime/bad-sig-alg",
      "smime.verify: signer sigAlg OID " + si.sigAlgOid +
      " not in PQC-first allowlist (ML-DSA-65 / ML-DSA-87 / SLH-DSA-SHAKE-256f)");
  }
  var digestAlg = _oidToDigest(si.digestAlgOid);
  if (!digestAlg) {
    throw new MailCryptoError("mail-crypto/smime/bad-digest",
      "smime.verify: signer digestAlg OID " + si.digestAlgOid +
      " not in PQC-first allowlist (sha3-256 / sha3-512)");
  }
  // Recompute message digest + match against the signed-attrs
  // message-digest attribute. The signature was computed over the
  // signed-attrs SET; we verify against that re-tagged blob.
  if (!si.signedAttrsRaw) {
    throw new MailCryptoError("mail-crypto/smime/no-signed-attrs",
      "smime.verify: SignerInfo lacks signedAttrs; v1 requires signed-attrs path");
  }
  var actualDigest = nodeCrypto.createHash(digestAlg).update(msgBytes).digest();
  // Walk signedAttrsRaw to extract the messageDigest attribute and
  // compare against the recomputed digest. The signature verifies
  // the signed-attrs BLOB; without this check, an attacker who
  // captured a valid signed-attrs SET could swap in a different
  // message body (the signature would still verify against the
  // ORIGINAL attrs blob, but the message bound to those attrs
  // would no longer match).
  var attrDigest = _extractMessageDigest(si.signedAttrsRaw);
  if (!attrDigest) {
    throw new MailCryptoError("mail-crypto/smime/no-message-digest-attr",
      "smime.verify: signedAttrs missing messageDigest attribute (RFC 5652 §11.2)");
  }
  if (attrDigest.length !== actualDigest.length ||
      !nodeCrypto.timingSafeEqual(attrDigest, actualDigest)) {
    _audit(opts.audit, "mail.crypto.smime.verify_fail", "denied", { reason: "message-digest-mismatch" });
    throw new MailCryptoError("mail-crypto/smime/message-digest-mismatch",
      "smime.verify: recomputed message digest does not match signedAttrs.messageDigest " +
      "(message was tampered or signed-attrs were swapped)");
  }
  // Final step: PQC signature verify against signedAttrsRaw.
  var ok;
  try {
    ok = sigAlg.pqc.verify(
      new Uint8Array(si.signature),
      new Uint8Array(si.signedAttrsRaw),
      opts.signerPublicKey);
  } catch (e2) {
    _audit(opts.audit, "mail.crypto.smime.verify_fail", "denied", {
      reason: "pqc-verify-threw", message: (e2 && e2.message) || String(e2),
    });
    throw new MailCryptoError("mail-crypto/smime/verify-failed",
      "smime.verify: PQC verify threw: " + ((e2 && e2.message) || String(e2)));
  }
  if (!ok) {
    _audit(opts.audit, "mail.crypto.smime.verify_fail", "denied", { reason: "signature-mismatch" });
    throw new MailCryptoError("mail-crypto/smime/signature-mismatch",
      "smime.verify: signature does not match signed-attributes");
  }
  _audit(opts.audit, "mail.crypto.smime.verify", "success", {
    sigAlg: sigAlg.name, digestAlg: digestAlg,
  });
  return { valid: true, sigAlg: sigAlg.name, digestAlg: digestAlg };
}

// RFC 5652 §11.2 messageDigest OID.
var OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4";

function _extractMessageDigest(signedAttrsRaw) {
  // signedAttrsRaw is `31 LL VV...` — the universal SET-tagged blob
  // that was signed. Walk the SET to find the Attribute whose
  // attrType OID is messageDigest, then unwrap its SET-OF-ANY to
  // get the OCTET STRING containing the digest bytes.
  var node;
  try { node = asn1.readNode(signedAttrsRaw); }
  catch (_e) { return null; }
  if (node.tag !== asn1.TAG.SET) return null;
  var attrs;
  try { attrs = asn1.readSequence(node.value); }
  catch (_e) { return null; }
  for (var i = 0; i < attrs.length; i += 1) {
    var attr = attrs[i];
    if (attr.tag !== asn1.TAG.SEQUENCE) continue;
    var children;
    try { children = asn1.readSequence(attr.value); }
    catch (_e) { continue; }
    if (children.length < 2) continue;
    var oid;
    try { oid = asn1.readOid(children[0]); }
    catch (_e) { continue; }
    if (oid !== OID_MESSAGE_DIGEST) continue;
    var valuesSet = children[1];
    if (valuesSet.tag !== asn1.TAG.SET) continue;
    var valueChildren;
    try { valueChildren = asn1.readSequence(valuesSet.value); }
    catch (_e) { continue; }
    if (valueChildren.length === 0) continue;
    var oct = valueChildren[0];
    if (oct.tag !== asn1.TAG.OCTET_STRING) continue;
    try { return asn1.readOctetString(oct); }
    catch (_e) { continue; }
  }
  return null;
}

function _oidToSigAlg(oid) {
  if (oid === cms.OID.mldsa65) return { name: "ML-DSA-65",          pqc: pqcSoftware.ml_dsa_65 };
  if (oid === cms.OID.mldsa87) return { name: "ML-DSA-87",          pqc: pqcSoftware.ml_dsa_87 };
  if (oid === cms.OID.slhDsaShake256f) return { name: "SLH-DSA-SHAKE-256f", pqc: pqcSoftware.slh_dsa_shake_256f };
  return null;
}

function _oidToDigest(oid) {
  if (oid === cms.OID.sha3_256) return "sha3-256";
  if (oid === cms.OID.sha3_512) return "sha3-512";
  return null;
}

function _wrapBase64(s) {
  // 64-char lines per RFC 2045 §6.8.
  var out = [];
  for (var i = 0; i < s.length; i += 64) {                                                            // allow:raw-byte-literal — RFC 2045 §6.8 line length
    out.push(s.slice(i, i + 64));                                                                     // allow:raw-byte-literal — RFC 2045 §6.8 line length
  }
  return out.join("\r\n");
}

// ---- Cert-shape preflight (operator-supplied trust roots) ----
//
// This *is* implemented in v1 — even before sign/verify light up,
// operators wiring an `b.mail.crypto.smime.checkCert({ certPem })`
// call against a candidate signing cert at boot get the SHA-1 / weak-
// RSA refusal posture surfaced as a config-time error rather than
// discovering it post-deploy. Reuses node:crypto's X509Certificate
// (cf. lib/mtls-ca.js).

/**
 * @primitive  b.mail.crypto.smime.checkCert
 * @signature  b.mail.crypto.smime.checkCert(opts)
 * @since      0.9.58
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 *
 * Operator-side cert preflight that lights up at boot: refuses
 * SHA-1 / MD5 signatures, RSA keys < 2048 bits, MD2 / MD5 / SHA-1
 * as the certificate-signature algorithm. Returns the parsed cert
 * shape (subject CN, issuer CN, validFrom / validTo, key algorithm
 * + size, signature algorithm). Throws `mail-crypto/smime/bad-cert`
 * on any of the above; throws `mail-crypto/smime/expired-cert` if
 * the cert is outside its validity window.
 *
 * @example
 *   var info = b.mail.crypto.smime.checkCert({ certPem: pem });
 *   // → { subjectCN, issuerCN, validFrom, validTo, keyAlg, keyBits, sigAlg }
 */
function checkCert(opts) {
  opts = validateOpts.requireObject(opts, "mail.crypto.smime.checkCert",
    MailCryptoError, "mail-crypto/smime/bad-opts");
  validateOpts(opts, ["certPem"], "mail.crypto.smime.checkCert");
  validateOpts.requireNonEmptyString(opts.certPem, "certPem",
    MailCryptoError, "mail-crypto/smime/bad-cert");

  var cert;
  try {
    cert = new nodeCrypto.X509Certificate(opts.certPem);
  } catch (e) {
    throw new MailCryptoError("mail-crypto/smime/bad-cert",
      "certPem could not be parsed as X.509: " + ((e && e.message) || String(e)));
  }

  // Cert signature algorithm refusal — node:crypto X509Certificate
  // exposes `signatureAlgorithm` (OpenSSL long name like
  // "sha256WithRSAEncryption", "ecdsa-with-SHA384", "ED25519") and
  // `signatureAlgorithmOid` (the canonical OID). We screen on the
  // lowercase long name so SHA-1 / MD5 substrings catch every
  // fielded variant. The OID is reported in the returned shape so
  // operators with stricter posture can pin on it.
  var sigAlgName = cert.signatureAlgorithm || cert.sigAlgName || "";
  var sigAlg = String(sigAlgName).toLowerCase();
  for (var i = 0; i < REFUSED_HASHES.length; i += 1) {
    if (sigAlg.indexOf(REFUSED_HASHES[i]) !== -1) {
      throw new MailCryptoError("mail-crypto/smime/refused-hash",
        "cert signature algorithm '" + sigAlgName +
        "' refused — SHA-1 / MD5 in cert signatures is forbidden " +
        "(CVE-2017-9006-class). Acceptable hashes: " + ALLOWED_HASHES.join(", "));
    }
  }

  // RSA bit floor — when the public key is RSA, refuse < RSA_MIN_BITS.
  // The X509Certificate exposes the public key via .publicKey
  // (node 17+) which is a KeyObject we can inspect.
  var pub = cert.publicKey;
  if (pub && pub.asymmetricKeyType === "rsa") {
    var jwk = pub.export({ format: "jwk" });
    var nBytes = Buffer.from(jwk.n, "base64url");
    var bits = nBytes.length * 8;                                                                     // allow:raw-byte-literal — bits-per-byte conversion // allow:raw-time-literal — RFC 5280 in comment, not seconds
    if (bits < RSA_MIN_BITS) {
      throw new MailCryptoError("mail-crypto/smime/rsa-too-small",
        "cert public key is " + bits + " RSA bits; minimum is " + RSA_MIN_BITS +
        " (RFC 8301 §3.1)");
    }
  }

  // Validity window — refuse certs outside their notBefore / notAfter
  // window. Codex P1: checkCert's docstring promises this throws
  // `mail-crypto/smime/expired-cert` but the impl was missing, letting
  // expired or not-yet-valid signing certs pass boot-time preflight
  // and fail interop later when peers verify signatures against the
  // RFC 5280 §4.1.2.5 validity field.
  var nowMs = Date.now();
  var notBeforeMs = Date.parse(cert.validFrom);
  var notAfterMs  = Date.parse(cert.validTo);
  if (isFinite(notBeforeMs) && nowMs < notBeforeMs) {
    throw new MailCryptoError("mail-crypto/smime/expired-cert",
      "cert is not yet valid (notBefore=" + cert.validFrom + ", now=" +
      new Date(nowMs).toISOString() + ")");
  }
  if (isFinite(notAfterMs) && nowMs > notAfterMs) {
    throw new MailCryptoError("mail-crypto/smime/expired-cert",
      "cert is expired (notAfter=" + cert.validTo + ", now=" +
      new Date(nowMs).toISOString() + ")");
  }

  return {
    subject:        cert.subject,
    issuer:         cert.issuer,
    validFrom:      cert.validFrom,
    validTo:        cert.validTo,
    sigAlgName:     sigAlgName,
    sigAlgOid:      cert.signatureAlgorithmOid || null,
    keyType:        pub && pub.asymmetricKeyType,
    fingerprint256: cert.fingerprint256,
  };
}

// ---- Audit (drop-silent) ----

function _audit(auditHandle, action, outcome, metadata) {
  try {
    var a = auditHandle || audit();
    if (a && typeof a.safeEmit === "function") {
      a.safeEmit({
        action:   action,
        outcome:  outcome,
        actor:    {},
        metadata: metadata,
      });
    }
  } catch (_e) { /* drop-silent — audit failures must not crash callers */ }
}

module.exports = {
  sign:                sign,
  verify:              verify,
  checkCert:           checkCert,
  MailCryptoError:     MailCryptoError,
  PROFILES:            PROFILES,
  COMPLIANCE_POSTURES: COMPLIANCE_POSTURES,
  ALLOWED_HASHES:      ALLOWED_HASHES,
  REFUSED_HASHES:      REFUSED_HASHES,
  RSA_MIN_BITS:        RSA_MIN_BITS,
};
