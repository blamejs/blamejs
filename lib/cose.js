"use strict";
/**
 * @module b.cose
 * @nav    Crypto
 * @title  COSE signing (RFC 9052)
 *
 * @intro
 *   COSE_Sign1 signing and verification (RFC 9052 / 9053), composing
 *   the in-tree <code>b.cbor</code> codec for the deterministic
 *   Sig_structure encoding. COSE is the signed-statement substrate
 *   under SCITT, CWT, and C2PA — a CBOR-native counterpart to JWS.
 *
 *   <strong>Signing</strong> supports the classical COSE signature
 *   algorithms that are interoperable today — ES256 / ES384 / ES512
 *   (ECDSA) and EdDSA (Ed25519), all with final IANA algorithm ids
 *   (RFC 9053) — alongside ML-DSA-87 (FIPS 204) for PQC-forward
 *   deployments. There is no classical <em>default</em>: the caller
 *   names the algorithm and supplies the key. <strong>Verification</strong>
 *   accepts the same set, so the framework both produces COSE other
 *   implementations can read today and consumes third-party COSE.
 *
 *   <strong>Standards-maturity caveat on the PQC algorithm:</strong>
 *   the COSE algorithm identifier for ML-DSA-87 is <code>-50</code>, a
 *   <em>requested</em> (non-final) IANA assignment from
 *   draft-ietf-cose-dilithium; it may change before that draft is
 *   published, so an ML-DSA-87 COSE_Sign1 is not yet broadly
 *   interoperable — pin the identifier deliberately, re-open on IANA
 *   finalization. SLH-DSA-SHAKE-256f (the framework's default PQC
 *   signature elsewhere) has <strong>no</strong> COSE algorithm
 *   identifier registered at all (the COSE SPHINCS+ draft registers
 *   only the Category-1 'small' sets), so it cannot be represented in
 *   COSE and is not offered here. The COSE_Sign1 mechanism itself, and
 *   the classical algorithms, are stable; ML-DSA-87 is the forward-
 *   looking opt-in.
 *
 *   <strong>Verify is bounded.</strong> The COSE_Sign1 bytes and the
 *   protected-header bstr are decoded through <code>b.cbor.decode</code>
 *   (depth + size caps, indefinite-length / tag / duplicate-key
 *   refusal). The protected header is the integrity-protected one;
 *   <code>alg</code> (label 1) lives there. A <code>crit</code> (label
 *   2) listing a header label the verifier does not understand is
 *   refused (RFC 9052 §3.1) — a crit-bypass defense.
 *
 *   v1 ships COSE_Sign1 (single-signer) with an attached payload.
 *   Detached payload, COSE_Sign (multi-signer), COSE_Mac0, and
 *   COSE_Encrypt are deferred-with-condition (operator demand).
 *
 * @card
 *   COSE_Sign1 sign / verify (RFC 9052) over the in-tree CBOR codec —
 *   ML-DSA-87 signing (experimental, draft alg id) + classical verify,
 *   bounded + crit-checked. The substrate under SCITT / CWT / C2PA.
 */

var nodeCrypto = require("node:crypto");
var cbor = require("./cbor");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var CoseError = defineClass("CoseError", { alwaysPermanent: true });

var COSE_SIGN1_TAG = 18;                                                               // allow:raw-byte-literal — RFC 9052 COSE_Sign1 CBOR tag
var HDR_ALG = 1;                                                                       // RFC 9052 §3.1 header label: alg
var HDR_CRIT = 2;                                                                      // header label: crit
var HDR_CONTENT_TYPE = 3;                                                              // header label: content type
var HDR_KID = 4;                                                                       // header label: kid

// COSE algorithm identifiers. ML-DSA-87 is a NON-FINAL requested
// assignment (draft-ietf-cose-dilithium) — pinned deliberately, re-open
// on IANA finalization. The classical ECDSA / EdDSA ids are final
// (RFC 9053). SLH-DSA is intentionally absent (no registered COSE id).
var ALG_NAME_TO_ID = {
  "ML-DSA-87": -50,
  "ES256": -7, "ES384": -35, "ES512": -36, "EdDSA": -8,                                // allow:raw-byte-literal — COSE algorithm identifiers (RFC 9053), not byte sizes
};
var ALG_ID_TO_NAME = {};
Object.keys(ALG_NAME_TO_ID).forEach(function (k) { ALG_ID_TO_NAME[ALG_NAME_TO_ID[k]] = k; });

// Signable algorithms: the classical ECDSA / EdDSA set (final COSE
// ids, interoperable today) plus ML-DSA-87 (draft id, PQC-forward).
// All are accepted for VERIFY as well. There is no classical default —
// the caller names the algorithm explicitly.
var SIGNABLE = ["ML-DSA-87", "ES256", "ES384", "ES512", "EdDSA"];

// Header labels this verifier understands — a `crit` entry naming any
// other label is refused (RFC 9052 §3.1 crit-bypass defense).
var UNDERSTOOD_LABELS = [HDR_ALG, HDR_CRIT, HDR_CONTENT_TYPE, HDR_KID];

function _toKeyObject(key, kind) {
  if (key && typeof key === "object" && typeof key.asymmetricKeyType === "string") return key;
  try {
    return kind === "private" ? nodeCrypto.createPrivateKey(key) : nodeCrypto.createPublicKey(key);
  } catch (e) {
    throw new CoseError("cose/bad-key", "cose: could not load " + kind + " key: " + e.message);
  }
}

function _algParamsFor(algId) {
  switch (algId) {
    case -50: return { nodeAlg: null };                                                // ML-DSA-87 (KeyObject specifies the hash)
    case -8:  return { nodeAlg: null };                                                // allow:raw-byte-literal — EdDSA COSE alg id (RFC 9053), not a size
    case -7:  return { nodeAlg: "sha256", dsaEncoding: "ieee-p1363" };                 // ES256
    case -35: return { nodeAlg: "sha384", dsaEncoding: "ieee-p1363" };                 // ES384
    case -36: return { nodeAlg: "sha512", dsaEncoding: "ieee-p1363" };                 // ES512
    default:
      throw new CoseError("cose/unknown-alg", "cose: unrecognized COSE algorithm id " + algId);
  }
}

function _bstr(x) {
  if (Buffer.isBuffer(x)) return x;
  if (x instanceof Uint8Array) return Buffer.from(x);
  if (typeof x === "string") return Buffer.from(x, "utf8");
  throw new CoseError("cose/bad-bytes", "cose: expected bytes (Buffer / Uint8Array / string)");
}

// Sig_structure (RFC 9052 §4.4) for COSE_Sign1:
//   [ "Signature1", body_protected (bstr), external_aad (bstr), payload (bstr) ]
// deterministically CBOR-encoded — the bytes that are signed / verified.
function _toBeSigned(protectedBstr, externalAad, payload) {
  return cbor.encode(["Signature1", protectedBstr, externalAad, payload]);
}

/**
 * @primitive b.cose.sign
 * @signature b.cose.sign(payload, opts)
 * @since     0.12.33
 * @status    stable
 * @related   b.cose.verify, b.cbor.encode
 *
 * Produce a tagged COSE_Sign1 (RFC 9052) over <code>payload</code>
 * (bytes). <code>alg</code> is one of the classical ECDSA / EdDSA
 * algorithms (final COSE ids, interoperable today) or
 * <code>"ML-DSA-87"</code> (draft id <code>-50</code>, PQC-forward).
 * <code>alg</code> is placed in the integrity-protected header.
 *
 * @opts
 *   {
 *     alg:                 string,    // "ES256" | "ES384" | "ES512" | "EdDSA" | "ML-DSA-87"
 *     privateKey:          object,    // matching KeyObject or PEM
 *     kid?:                string,    // → unprotected header label 4
 *     contentType?:        number,    // → protected header label 3
 *     externalAad?:        Buffer,    // default empty — bound into the signature
 *     unprotectedHeaders?: object,    // extra unprotected map entries (numeric keys)
 *   }
 *
 * @example
 *   var coseSign1 = await b.cose.sign(Buffer.from("statement"), {
 *     alg: "ES256", privateKey: ecKey, kid: "key-1",
 *   });
 */
async function sign(payload, opts) {
  validateOpts.requireObject(opts, "cose.sign", CoseError);
  validateOpts(opts, ["alg", "privateKey", "kid", "contentType", "externalAad", "unprotectedHeaders"], "cose.sign");
  if (SIGNABLE.indexOf(opts.alg) === -1) {
    throw new CoseError("cose/unsignable-alg",
      "cose.sign: alg must be one of " + SIGNABLE.join(" / ") +
      " (SLH-DSA has no COSE algorithm id and is not offered)");
  }
  if (!opts.privateKey) {
    throw new CoseError("cose/no-key", "cose.sign: opts.privateKey is required");
  }
  var algId = ALG_NAME_TO_ID[opts.alg];
  var params = _algParamsFor(algId);
  var key = _toKeyObject(opts.privateKey, "private");

  var protMap = new Map();
  protMap.set(HDR_ALG, algId);
  if (typeof opts.contentType === "number") protMap.set(HDR_CONTENT_TYPE, opts.contentType);
  var protectedBstr = cbor.encode(protMap);

  var unprot = new Map();
  if (typeof opts.kid === "string") unprot.set(HDR_KID, Buffer.from(opts.kid, "utf8"));
  if (opts.unprotectedHeaders && typeof opts.unprotectedHeaders === "object") {
    var uk = Object.keys(opts.unprotectedHeaders);
    for (var i = 0; i < uk.length; i++) unprot.set(Number(uk[i]), opts.unprotectedHeaders[uk[i]]);
  }

  var payloadBytes = _bstr(payload);
  var externalAad = opts.externalAad == null ? Buffer.alloc(0) : _bstr(opts.externalAad);
  var toBeSigned = _toBeSigned(protectedBstr, externalAad, payloadBytes);

  // ML-DSA-87 + EdDSA: the KeyObject specifies the algorithm, so a
  // null digest name is correct. ECDSA: a digest + the IEEE-P1363
  // fixed-width signature encoding COSE mandates (RFC 9053 §2.1, not
  // ASN.1 DER).
  var signature = (params.nodeAlg === null)
    ? nodeCrypto.sign(null, toBeSigned, key)
    : nodeCrypto.sign(params.nodeAlg, toBeSigned, { key: key, dsaEncoding: params.dsaEncoding });

  var sign1 = [protectedBstr, unprot, payloadBytes, signature];
  return cbor.encode(new cbor.Tag(COSE_SIGN1_TAG, sign1));
}

/**
 * @primitive b.cose.verify
 * @signature b.cose.verify(coseSign1, opts)
 * @since     0.12.33
 * @status    experimental
 * @related   b.cose.sign, b.cbor.decode
 *
 * Verify a COSE_Sign1 (RFC 9052) and return its payload + headers.
 * The bytes are decoded through the bounded <code>b.cbor</code> codec;
 * <code>alg</code> is read from the integrity-protected header and must
 * be in <code>opts.algorithms</code>; a <code>crit</code> header naming
 * a label the verifier does not understand is refused. Accepts ML-DSA-87
 * plus the classical ECDSA / EdDSA COSE algorithms.
 *
 * @opts
 *   {
 *     algorithms:   string[],  // required — accepted alg names (allowlist)
 *     publicKey?:   object,    // the verification key (KeyObject / PEM)
 *     keyResolver?: function,  // (protectedHeaders, unprotectedHeaders) → key
 *     externalAad?: Buffer,    // must match what was signed
 *     maxBytes?:    number,    // forwarded to b.cbor.decode
 *     maxDepth?:    number,
 *   }
 *
 * @example
 *   var out = await b.cose.verify(coseSign1, { algorithms: ["ML-DSA-87"], publicKey: pub });
 *   // → { payload: <Buffer>, alg: "ML-DSA-87", protectedHeaders: Map, unprotectedHeaders: Map }
 */
async function verify(coseSign1, opts) {
  validateOpts.requireObject(opts, "cose.verify", CoseError);
  validateOpts(opts, ["algorithms", "publicKey", "keyResolver", "externalAad", "maxBytes", "maxDepth"], "cose.verify");
  if (!Array.isArray(opts.algorithms) || opts.algorithms.length === 0) {
    throw new CoseError("cose/algorithms-required",
      "cose.verify: opts.algorithms is required (no defaults — name the accepted algorithms)");
  }
  for (var ai = 0; ai < opts.algorithms.length; ai++) {
    if (!(opts.algorithms[ai] in ALG_NAME_TO_ID)) {
      throw new CoseError("cose/unknown-alg", "cose.verify: unknown algorithm '" + opts.algorithms[ai] + "'");
    }
  }
  if (!opts.publicKey && typeof opts.keyResolver !== "function") {
    throw new CoseError("cose/no-key", "cose.verify: pass publicKey or keyResolver");
  }

  var decoded = cbor.decode(_bstr(coseSign1), {
    allowedTags: [COSE_SIGN1_TAG],
    maxBytes:    opts.maxBytes,
    maxDepth:    opts.maxDepth,
  });
  // Accept tagged (18) or bare COSE_Sign1 array.
  var arr = (decoded instanceof cbor.Tag && decoded.tag === COSE_SIGN1_TAG) ? decoded.value : decoded;
  if (!Array.isArray(arr) || arr.length !== 4) {
    throw new CoseError("cose/malformed", "cose.verify: not a COSE_Sign1 (expected a 4-element array)");
  }
  var protectedBstr = arr[0];
  var unprotected = arr[1];
  var payload = arr[2];
  var signature = arr[3];
  if (!Buffer.isBuffer(protectedBstr) || !Buffer.isBuffer(signature)) {
    throw new CoseError("cose/malformed", "cose.verify: protected header and signature must be byte strings");
  }
  if (payload === null || payload === undefined) {
    throw new CoseError("cose/detached-unsupported",
      "cose.verify: detached payload (nil) is not supported in v1 — attached payload only");
  }

  // Decode the protected header (bounded) — empty bstr means no protected headers.
  var protMap = protectedBstr.length === 0 ? new Map()
    : cbor.decode(protectedBstr, { maxBytes: opts.maxBytes, maxDepth: opts.maxDepth });
  if (!(protMap instanceof Map)) {
    throw new CoseError("cose/malformed", "cose.verify: protected header is not a CBOR map");
  }

  // crit-bypass defense: every label in a crit array must be one the
  // verifier understands AND must be present in the protected header.
  if (protMap.has(HDR_CRIT)) {
    var crit = protMap.get(HDR_CRIT);
    if (!Array.isArray(crit)) {
      throw new CoseError("cose/bad-crit", "cose.verify: crit (label 2) must be an array");
    }
    for (var ci = 0; ci < crit.length; ci++) {
      if (UNDERSTOOD_LABELS.indexOf(crit[ci]) === -1) {
        throw new CoseError("cose/crit-unknown",
          "cose.verify: crit lists header label " + crit[ci] + " which is not understood (RFC 9052 §3.1)");
      }
      if (!protMap.has(crit[ci])) {
        throw new CoseError("cose/crit-absent",
          "cose.verify: crit lists label " + crit[ci] + " not present in the protected header");
      }
    }
  }

  var algId = protMap.get(HDR_ALG);
  var algName = ALG_ID_TO_NAME[algId];
  if (algName === undefined) {
    throw new CoseError("cose/unknown-alg", "cose.verify: unrecognized protected alg id " + algId);
  }
  if (opts.algorithms.indexOf(algName) === -1) {
    throw new CoseError("cose/alg-not-allowed",
      "cose.verify: alg '" + algName + "' is not in the allowlist");
  }
  var params = _algParamsFor(algId);                                                    // throws cose/unknown-alg on an unrecognized id

  var key = opts.publicKey
    ? _toKeyObject(opts.publicKey, "public")
    : _toKeyObject(opts.keyResolver(protMap, unprotected), "public");

  var externalAad = opts.externalAad == null ? Buffer.alloc(0) : _bstr(opts.externalAad);
  var toBeSigned = _toBeSigned(protectedBstr, externalAad, payload);

  var ok;
  if (params.nodeAlg === null) {
    ok = nodeCrypto.verify(null, toBeSigned, key, signature);
  } else {
    ok = nodeCrypto.verify(params.nodeAlg, toBeSigned,
      { key: key, dsaEncoding: params.dsaEncoding }, signature);
  }
  if (!ok) {
    throw new CoseError("cose/bad-signature", "cose.verify: signature verification failed");
  }
  return {
    payload:             payload,
    alg:                 algName,
    protectedHeaders:    protMap,
    unprotectedHeaders:  (unprotected instanceof Map) ? unprotected : new Map(),
  };
}

module.exports = {
  sign:        sign,
  verify:      verify,
  ALGORITHMS:  ALG_NAME_TO_ID,
  COSE_SIGN1_TAG: COSE_SIGN1_TAG,
  CoseError:   CoseError,
};
