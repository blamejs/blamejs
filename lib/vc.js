"use strict";
/**
 * @module b.vc
 * @nav    Crypto
 * @title  Verifiable Credentials (W3C VCDM 2.0)
 *
 * @intro
 *   Issue and verify W3C Verifiable Credentials (VC Data Model 2.0, a
 *   W3C Recommendation) secured per "Securing Verifiable Credentials
 *   using JOSE and COSE" (VC-JOSE-COSE, also a W3C Recommendation). A
 *   verifiable credential is a tamper-evident, cryptographically-signed
 *   set of claims an issuer makes about a subject — a diploma, a
 *   membership, a license, an age assertion.
 *
 *   Two securing mechanisms are supported, both putting the credential
 *   itself (not a JWT/CWT claims wrapper) as the signed payload:
 *   <strong>JOSE</strong> produces a compact JWS with the <code>vc+jwt</code>
 *   media type (<code>typ</code> header <code>"vc+jwt"</code>), signed
 *   with the classical ES256 / 384 / 512 or EdDSA JOSE algorithms;
 *   <strong>COSE</strong> produces a COSE_Sign1 (<code>application/vc+cose</code>)
 *   over <code>b.cose</code>, adding ML-DSA-87 (PQC-forward) to that set.
 *   <code>b.vc.verify</code> auto-detects the form from the input (a
 *   compact-JWS string vs. COSE_Sign1 bytes).
 *
 *   <code>b.vc.issue(credential, opts)</code> validates the credential
 *   against the VCDM 2.0 structural rules (the <code>credentials/v2</code>
 *   context first, a <code>VerifiableCredential</code> type, an issuer,
 *   a credential subject) and signs it. <code>b.vc.verify(secured, opts)</code>
 *   verifies the signature (the algorithm allowlist is mandatory; the
 *   JOSE <code>none</code> algorithm is always refused), re-checks the
 *   structural rules, and enforces the <code>validFrom</code> /
 *   <code>validUntil</code> validity window. This is the W3C model and
 *   is distinct from the IETF SD-JWT VC at <code>b.auth.sdJwtVc</code>.
 *
 * @card
 *   W3C Verifiable Credentials 2.0 (VC-JOSE-COSE) — issue / verify a
 *   signed credential as a compact JWS (vc+jwt) or a COSE_Sign1
 *   (vc+cose), with VCDM structural + validity-window checks. Composes
 *   b.cose; the JOSE alg `none` is always refused.
 */

var nodeCrypto = require("node:crypto");
var cose = require("./cose");
var safeJson = require("./safe-json");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var VcError = defineClass("VcError", { alwaysPermanent: true });

var VCDM_V2_CONTEXT = "https://www.w3.org/ns/credentials/v2";
var JOSE_TYP = "vc+jwt";
var COSE_TYP = "application/vc+cose";
var COSE_CONTENT_TYPE = "application/vc";
var HDR_COSE_TYP = 16;                                 // allow:raw-byte-literal — COSE "typ" header label (RFC 9596)

// JOSE signature algorithms (final RFC 7518 / 8037), mapped to node
// verify parameters. ECDSA uses the IEEE-P1363 fixed-width encoding JOSE
// mandates (not ASN.1 DER). There is no signing default — the caller
// names the algorithm, mirroring b.cose.
var JOSE_ALGS = {
  "ES256": { nodeHash: "sha256", dsaEncoding: "ieee-p1363" },
  "ES384": { nodeHash: "sha384", dsaEncoding: "ieee-p1363" },
  "ES512": { nodeHash: "sha512", dsaEncoding: "ieee-p1363" },
  "EdDSA": { nodeHash: null },
};

function _b64urlJson(obj) {
  return Buffer.from(JSON.stringify(obj), "utf8").toString("base64url");
}
function _toKey(key, kind) {
  if (key && typeof key === "object" && typeof key.asymmetricKeyType === "string") return key;
  try {
    return kind === "private" ? nodeCrypto.createPrivateKey(key) : nodeCrypto.createPublicKey(key);
  } catch (e) {
    throw new VcError("vc/bad-key", "vc: could not load " + kind + " key: " + ((e && e.message) || e));
  }
}

function _issuerId(cred) {
  if (typeof cred.issuer === "string") return cred.issuer;
  if (cred.issuer && typeof cred.issuer === "object" && typeof cred.issuer.id === "string") return cred.issuer.id;
  return undefined;
}

// VCDM 2.0 structural rules; temporal checks only on verify.
function _validateVcdm(cred, opts) {
  if (!cred || typeof cred !== "object" || Array.isArray(cred)) {
    throw new VcError("vc/bad-credential", "vc: credential must be a JSON object");
  }
  var ctx = cred["@context"];
  if (!Array.isArray(ctx) || ctx[0] !== VCDM_V2_CONTEXT) {
    throw new VcError("vc/bad-context",
      "vc: @context must be an array whose first element is '" + VCDM_V2_CONTEXT + "'");
  }
  var types = Array.isArray(cred.type) ? cred.type : [cred.type];
  if (types.indexOf("VerifiableCredential") === -1) {
    throw new VcError("vc/bad-type", "vc: type must include 'VerifiableCredential'");
  }
  if (_issuerId(cred) === undefined) {
    throw new VcError("vc/no-issuer", "vc: issuer is required (a URL string or an object with an id)");
  }
  if (cred.credentialSubject === undefined || cred.credentialSubject === null) {
    throw new VcError("vc/no-subject", "vc: credentialSubject is required");
  }
  if (opts && opts.temporal) {
    var nowMs = opts.at.getTime();
    if (typeof cred.validFrom === "string") {
      var vf = Date.parse(cred.validFrom);
      if (isFinite(vf) && nowMs < vf) {
        throw new VcError("vc/not-yet-valid", "vc.verify: credential validFrom (" + cred.validFrom + ") is in the future");
      }
    }
    if (typeof cred.validUntil === "string") {
      var vu = Date.parse(cred.validUntil);
      if (isFinite(vu) && nowMs > vu) {
        throw new VcError("vc/expired", "vc.verify: credential validUntil (" + cred.validUntil + ") has passed");
      }
    }
  }
}

/**
 * @primitive b.vc.issue
 * @signature b.vc.issue(credential, opts)
 * @since     0.12.39
 * @status    experimental
 * @compliance gdpr, soc2
 * @related   b.vc.verify, b.cose.sign
 *
 * Validate a credential against the VCDM 2.0 structural rules and secure
 * it. <code>securing: "jose"</code> returns a compact JWS string (media
 * type <code>vc+jwt</code>) signed with an ES256/384/512 or EdDSA key;
 * <code>securing: "cose"</code> returns COSE_Sign1 bytes (media type
 * <code>application/vc+cose</code>) over <code>b.cose</code>, which also
 * accepts <code>"ML-DSA-87"</code>. The credential itself is the signed
 * payload — no JWT/CWT claims wrapper is added.
 *
 * @opts
 *   {
 *     securing:   string,   // "jose" (compact JWS) | "cose" (COSE_Sign1)
 *     alg:        string,   // JOSE: ES256/384/512 | EdDSA. COSE: + ML-DSA-87
 *     privateKey: object,   // matching KeyObject or PEM
 *     kid:        string,   // optional key id (header)
 *     cty:        string,   // optional JOSE cty (e.g. "vc")
 *   }
 *
 * @example
 *   var jws = await b.vc.issue(credential, { securing: "jose", alg: "ES256", privateKey: key });
 *   // → a compact JWS string with typ "vc+jwt"
 */
async function issue(credential, opts) {
  validateOpts.requireObject(opts, "vc.issue", VcError);
  validateOpts(opts, ["securing", "alg", "privateKey", "kid", "cty"], "vc.issue");
  _validateVcdm(credential, null);
  if (!opts.privateKey) throw new VcError("vc/no-key", "vc.issue: opts.privateKey is required");

  if (opts.securing === "cose") {
    var protectedHeaders = {};
    protectedHeaders[HDR_COSE_TYP] = COSE_TYP;
    return cose.sign(Buffer.from(JSON.stringify(credential), "utf8"), {
      alg:              opts.alg,
      privateKey:       opts.privateKey,
      kid:              opts.kid,
      contentType:      COSE_CONTENT_TYPE,
      protectedHeaders: protectedHeaders,
    });
  }
  if (opts.securing === "jose") {
    var params = JOSE_ALGS[opts.alg];
    if (!params) {
      throw new VcError("vc/bad-alg", "vc.issue: JOSE securing requires alg ES256/384/512 or EdDSA (got " + opts.alg + ")");
    }
    var key = _toKey(opts.privateKey, "private");
    var header = { alg: opts.alg, typ: JOSE_TYP };
    if (typeof opts.kid === "string") header.kid = opts.kid;
    if (typeof opts.cty === "string") header.cty = opts.cty;
    var signingInput = _b64urlJson(header) + "." + _b64urlJson(credential);
    var sig = params.nodeHash === null
      ? nodeCrypto.sign(null, Buffer.from(signingInput, "ascii"), key)
      : nodeCrypto.sign(params.nodeHash, Buffer.from(signingInput, "ascii"), { key: key, dsaEncoding: params.dsaEncoding });
    return signingInput + "." + sig.toString("base64url");
  }
  throw new VcError("vc/bad-securing", "vc.issue: securing must be 'jose' or 'cose'");
}

function _verifyJose(token, opts) {
  var parts = token.split(".");
  if (parts.length !== 3) {
    throw new VcError("vc/malformed", "vc.verify: not a compact JWS (expected three dot-separated segments)");
  }
  var header;
  try { header = safeJson.parse(Buffer.from(parts[0], "base64url").toString("utf8")); }
  catch (_e) { throw new VcError("vc/malformed", "vc.verify: JWS header is not valid base64url-JSON"); }
  if (!header || header.typ !== JOSE_TYP) {
    throw new VcError("vc/bad-typ", "vc.verify: JWS typ must be '" + JOSE_TYP + "'");
  }
  if (header.alg === "none" || !JOSE_ALGS[header.alg]) {
    throw new VcError("vc/bad-alg", "vc.verify: unsupported or unsecured JWS alg '" + header.alg + "'");
  }
  if (opts.algorithms.indexOf(header.alg) === -1) {
    throw new VcError("vc/alg-not-allowed", "vc.verify: alg '" + header.alg + "' is not in the allowlist");
  }
  var params = JOSE_ALGS[header.alg];
  var pub = opts.publicKey ? _toKey(opts.publicKey, "public") : _toKey(opts.keyResolver(header), "public");
  var signingInput = parts[0] + "." + parts[1];
  var sig = Buffer.from(parts[2], "base64url");
  var ok = params.nodeHash === null
    ? nodeCrypto.verify(null, Buffer.from(signingInput, "ascii"), pub, sig)
    : nodeCrypto.verify(params.nodeHash, Buffer.from(signingInput, "ascii"), { key: pub, dsaEncoding: params.dsaEncoding }, sig);
  if (!ok) throw new VcError("vc/bad-signature", "vc.verify: JWS signature did not verify");
  var credential;
  try { credential = safeJson.parse(Buffer.from(parts[1], "base64url").toString("utf8")); }
  catch (_e) { throw new VcError("vc/malformed", "vc.verify: JWS payload is not valid base64url-JSON"); }
  return { credential: credential, alg: header.alg };
}

async function _verifyCose(bytes, opts) {
  var algorithms = opts.algorithms.filter(function (a) { return a in cose.ALGORITHMS; });
  if (!algorithms.length) {
    throw new VcError("vc/no-cose-alg", "vc.verify: opts.algorithms has no COSE algorithm for a vc+cose credential");
  }
  var out = await cose.verify(bytes, {
    algorithms:  algorithms,
    publicKey:   opts.publicKey,
    keyResolver: opts.keyResolver,
  });
  var typ = out.protectedHeaders.get(HDR_COSE_TYP);
  if (typ !== undefined && typ !== COSE_TYP) {
    throw new VcError("vc/bad-typ", "vc.verify: COSE typ header is '" + typ + "', expected '" + COSE_TYP + "'");
  }
  var credential;
  try { credential = safeJson.parse(out.payload.toString("utf8")); }
  catch (_e) { throw new VcError("vc/malformed", "vc.verify: COSE payload is not valid JSON"); }
  return { credential: credential, alg: out.alg };
}

/**
 * @primitive b.vc.verify
 * @signature b.vc.verify(secured, opts)
 * @since     0.12.39
 * @status    experimental
 * @compliance gdpr, soc2
 * @related   b.vc.issue, b.cose.verify
 *
 * Verify a secured verifiable credential and return the credential. The
 * securing form is auto-detected (a compact-JWS string vs. COSE_Sign1
 * bytes); the algorithm allowlist is mandatory and the JOSE
 * <code>none</code> algorithm is always refused. After the signature,
 * the VCDM 2.0 structural rules are re-checked and the
 * <code>validFrom</code> / <code>validUntil</code> window is enforced
 * against <code>opts.at</code> (default: now).
 *
 * @opts
 *   {
 *     algorithms:      string[],  // required — accepted alg names (allowlist)
 *     publicKey:       object,    // verification key (KeyObject / PEM)
 *     keyResolver:     function,  // (header) → key  (alternative to publicKey)
 *     expectedIssuer:  string,    // require the credential issuer (id) to match
 *     at:              Date,      // validity instant (default: now); must be a valid Date
 *   }
 *
 * @example
 *   var out = await b.vc.verify(jws, { algorithms: ["ES256"], publicKey: issuerPub, expectedIssuer: "did:example:123" });
 *   // → { credential, securing: "jose", alg: "ES256", issuer: "did:example:123" }
 */
async function verify(secured, opts) {
  validateOpts.requireObject(opts, "vc.verify", VcError);
  validateOpts(opts, ["algorithms", "publicKey", "keyResolver", "expectedIssuer", "at"], "vc.verify");
  if (!Array.isArray(opts.algorithms) || opts.algorithms.length === 0) {
    throw new VcError("vc/algorithms-required", "vc.verify: opts.algorithms is required (name the accepted algorithms)");
  }
  if (!opts.publicKey && typeof opts.keyResolver !== "function") {
    throw new VcError("vc/no-key", "vc.verify: pass publicKey or keyResolver");
  }
  var at = new Date();
  if (opts.at !== undefined && opts.at !== null) {
    if (!(opts.at instanceof Date) || !isFinite(opts.at.getTime())) {
      throw new VcError("vc/bad-at", "vc.verify: opts.at must be a valid Date");
    }
    at = opts.at;
  }

  var securing, result;
  if (typeof secured === "string") {
    securing = "jose";
    result = _verifyJose(secured, opts);
  } else if (Buffer.isBuffer(secured) || secured instanceof Uint8Array) {
    securing = "cose";
    result = await _verifyCose(Buffer.from(secured), opts);
  } else {
    throw new VcError("vc/bad-input", "vc.verify: secured must be a compact-JWS string or COSE_Sign1 bytes");
  }

  _validateVcdm(result.credential, { temporal: true, at: at });
  var issuer = _issuerId(result.credential);
  if (opts.expectedIssuer !== undefined && issuer !== opts.expectedIssuer) {
    throw new VcError("vc/issuer-mismatch", "vc.verify: credential issuer does not match expectedIssuer");
  }
  return { credential: result.credential, securing: securing, alg: result.alg, issuer: issuer };
}

module.exports = {
  issue:          issue,
  verify:         verify,
  JOSE_ALGS:      JOSE_ALGS,
  VCDM_V2_CONTEXT: VCDM_V2_CONTEXT,
  VcError:        VcError,
};
