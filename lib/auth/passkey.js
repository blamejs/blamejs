// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Passkey / WebAuthn (FIDO2) — registration + authentication primitives.
 *
 * Ceremony options are built here; the cryptographic verification runs
 * in the vendored @blamejs/pki webauthn module (lib/vendor/blamejs-
 * pki.cjs), which handles CBOR parsing, attestation statement
 * validation, COSE key conversion, and signature verification across
 * the WebAuthn algorithm set. This file names the surface in the
 * framework's auth-namespace style, applies the relying party's
 * ceremony policy (algorithm allow-list, cross-origin refusal,
 * credential-ID binding, sign-counter regression), and frames failures
 * through AuthError consistently with auth.password and auth.totp.
 *
 * The four phases of a WebAuthn flow:
 *
 *   Registration (user adds a passkey to their account):
 *     1. server: startRegistration({ rpName, rpId, userName, userDisplayName,
 *        excludeCredentials? }) → { challenge, … }. Server stores the
 *        challenge in the session.
 *     2. browser: navigator.credentials.create({ publicKey: <options> })
 *        → registration response with attestation.
 *     3. server: verifyRegistration({ response, expectedChallenge,
 *        expectedOrigin, expectedRPID }) → { verified, registrationInfo:
 *        { credential: { id, publicKey, counter }, … } }. Persist
 *        credential.id (base64url) + credential.publicKey + counter.
 *        credential.id is read out of the ATTESTATION, not off the wire —
 *        persist that one. A response whose id / rawId names a different
 *        credential than the authenticator attested is refused, so it can
 *        never claim a row that belongs to somebody else.
 *
 *   Authentication (user logs in with their passkey):
 *     1. server: startAuthentication({ rpId, userVerification? })
 *        → { challenge, … }. Server stores challenge in session.
 *     2. browser: navigator.credentials.get({ publicKey: <options> })
 *        → assertion response.
 *     3. server: lookup the credential by response.id (base64url),
 *        then verifyAuthentication({ response, expectedChallenge,
 *        expectedOrigin, expectedRPID, credential: { id, publicKey,
 *        counter, transports? } }) → { verified, authenticationInfo:
 *        { newCounter } }. Persist newCounter (clone-detection).
 *
 * Public API (b.auth.passkey.*):
 *   await passkey.startRegistration(opts)        → registration options
 *   await passkey.verifyRegistration(opts)       → { verified, registrationInfo? }
 *   await passkey.startAuthentication(opts)      → authentication options
 *   await passkey.verifyAuthentication(opts)     → { verified, authenticationInfo? }
 *
 * Framework defaults:
 *   - attestationType: "none" — don't request attestation. Most apps
 *     don't need it, and "direct" or "enterprise" attestation has
 *     deployment friction (cert chains, MDS lookups). Operators who
 *     genuinely need attestation override.
 *   - residentKey: "preferred" — discoverable credentials when the
 *     authenticator supports them; falls back to non-discoverable.
 *     requireResidentKey (the WebAuthn L1 boolean) is derived from it,
 *     never read alongside it, so the pair cannot disagree; passing the
 *     legacy boolean alone still raises residentKey to "required".
 *   - userVerification: "preferred" — accept biometric / PIN when
 *     available; fall back to presence-only.
 *   - hints: ["client-device", "hybrid"] — surface platform
 *     authenticators (Touch ID, Windows Hello) AND cross-device
 *     (1Password / Bitwarden / mobile-as-roaming-authenticator). The
 *     default follows authenticatorAttachment when one is set
 *     ("cross-platform" -> ["security-key", "hybrid"], "platform" ->
 *     ["client-device"]) so the browser is not steered at an
 *     authenticator the attachment forbids. An explicit `hints` list
 *     passes through untouched.
 *   - allowedAlgorithms: [-8, -7, -257] — Ed25519, ES256, RS256. One
 *     list drives both halves of a ceremony: what startRegistration
 *     offers in pubKeyCredParams AND what the verifiers accept, so a
 *     deployment can't advertise one set and honour another. Widen it
 *     for credentials issued before the default narrowed:
 *     allowedAlgorithms: [-8, -7, -257, -36] also accepts ES512.
 *     Supported: -8, -7, -35, -36, -37, -257, -258, -259. RSA with
 *     SHA-1 (-65535) is refused however it is asked for.
 *   - Cross-origin ceremonies (clientData.crossOrigin true — WebAuthn
 *     ran in an iframe, not at the top level) are refused. A deployment
 *     that is deliberately embedded names its embedders:
 *     allowCrossOrigin: ["https://partner.example"], matched against
 *     clientData.topOrigin. `true` accepts any embedder, for the case
 *     where the partner set is not a list you can write down.
 *
 * No middleware decisions made here — the wrapper does NOT touch
 * sessions, audit, or DB. Routes integrate that themselves; the
 * primitive stays the smallest correct surface.
 */
var nodeCrypto = require("node:crypto");
var _pkiToolkit = require("../vendor/blamejs-pki.cjs");
var bCrypto = require("../crypto");
var safeBuffer = require("../safe-buffer");
var safeJson = require("../safe-json");
var { AuthError } = require("../framework-error");

// W3C WebAuthn name field cap — same as the rpName/userName ceiling in
// the spec's CredentialUserEntity / PublicKeyCredentialEntity dictionaries
// (no normative limit but RPs broadly cap at 256 to defeat DOM cost).
var MAX_NAME_LEN = 256;                                                            // UTF-16 codepoint count, not bytes

function _pki() {
  return _pkiToolkit;
}

// base64url -> Buffer for the wire fields a WebAuthn response carries. Every
// one of these is attacker-supplied, so a value that is not a string is a
// refusal rather than a coercion.
function _wireBytes(value, field) {
  if (typeof value !== "string" || value.length === 0) {
    throw new AuthError("auth-passkey/bad-response",
      "response." + field + " must be a base64url string");
  }
  return Buffer.from(value, "base64url");
}

// CollectedClientData.crossOrigin (WebAuthn L3 §5.8.1) — true when the
// ceremony ran in a frame whose top-level origin is NOT this origin. The
// underlying verifier never reads the field, so without this an RP embedded in
// a hostile top-level page is indistinguishable from a same-origin one: the
// signature, the challenge, the origin and the RP ID all check out, because
// the ceremony really did happen at this origin — inside somebody else's page.
//
// Refused by default, because that is the safe reading and a legitimate
// cross-origin RP knows it is one. `allowCrossOrigin: true` opts in.
//
// Drop-silent on a clientDataJSON this cannot read: the vendor parses it
// immediately afterwards and refuses with a better message than a guess here
// would produce. This checks a field, it does not validate the envelope.
function _refuseCrossOrigin(response, opts, ceremony) {
  var allow = opts && opts.allowCrossOrigin;
  // `true` is the blunt opt-in: every embedder, for a deployment whose
  // partners are not a list it can write down.
  if (allow === true) return;

  var raw = response && response.response && response.response.clientDataJSON;
  if (typeof raw !== "string" || raw.length === 0) return;
  var parsed;
  try {
    parsed = safeJson.parse(Buffer.from(raw, "base64url").toString("utf8"),
                            { maxBytes: 8 * 1024 });                               // allow:raw-byte-literal — clientDataJSON is small by construction
  } catch (_e) { return; }
  if (!parsed || parsed.crossOrigin !== true) return;

  // An ARRAY names the embedders this deployment actually has. Without it the
  // opt-in would be a switch that turns the protection off rather than aims
  // it: `true` accepts the hostile page just as readily as the partner one.
  //
  // clientData.topOrigin is the page the ceremony ran inside. A browser that
  // reports crossOrigin without naming it cannot be matched against a list, so
  // it does not pass one -- an unnamed embedder is exactly the case the list
  // was written to exclude.
  if (Array.isArray(allow) && allow.length > 0 &&
      typeof parsed.topOrigin === "string" && allow.indexOf(parsed.topOrigin) !== -1) {
    return;
  }

  throw new AuthError("auth-passkey/cross-origin-ceremony",
    ceremony + " ran in a cross-origin frame (clientData.crossOrigin is true)" +
    (typeof parsed.topOrigin === "string"
      ? ", embedded by " + JSON.stringify(parsed.topOrigin)
      : ", and the browser did not name the embedding page") +
    " -- the top-level page is not this origin. Pass allowCrossOrigin as an " +
    "array of permitted top origins, or true for any, only if the relying " +
    "party is deliberately embedded.");
}

function _requireString(v, name) {
  if (typeof v !== "string" || v.length === 0) {
    throw new AuthError("auth-passkey/missing-" + name,
      name + " is required (non-empty string)");
  }
}

// WebAuthn extensions allowlist. Pre-v0.9.x `opts.extensions`
// was forwarded verbatim to the vendor, letting an operator (or a
// caller threading user-input through opts) ship arbitrary extension
// keys to the authenticator. Restrict to the framework-supported
// extension surface (`prf` / `largeBlob` / `credBlob`) and route every
// value through the matching `extensions.<name>(args)` builder so the
// shape is validated. Operators with custom extensions opt in via
// { allowUnknownExtensions: true } with a documented reason.
var ALLOWED_EXTENSION_KEYS = Object.freeze({
  prf:        1,
  largeBlob:  1,
  credBlob:   1,
});
function _validateExtensions(extensions, allowUnknown) {
  if (extensions === undefined || extensions === null) return undefined;
  if (typeof extensions !== "object" || Array.isArray(extensions)) {
    throw new AuthError("auth-passkey/bad-extensions",
      "opts.extensions must be a plain object");
  }
  var out = {};
  var keys = Object.keys(extensions);
  for (var i = 0; i < keys.length; i++) {
    var k = keys[i];
    if (!Object.prototype.hasOwnProperty.call(ALLOWED_EXTENSION_KEYS, k)) {
      if (allowUnknown === true) {
        out[k] = extensions[k];
        continue;
      }
      throw new AuthError("auth-passkey/unknown-extension",
        "opts.extensions['" + k + "'] not in the framework-supported set " +
        "(allowed: " + Object.keys(ALLOWED_EXTENSION_KEYS).join(", ") +
        "). Pass `allowUnknownExtensions: true` to opt out.");
    }
    // Route every recognised extension through its builder so the
    // shape is validated (PRF eval salt length, largeBlob support
    // values, credBlob ≤ 32 bytes). Builder output replaces the raw
    // input so the wire shape is always the spec-correct one.
    if (k === "prf")       Object.assign(out, _prfExt(extensions.prf));
    if (k === "largeBlob") Object.assign(out, _largeBlobExt(extensions.largeBlob));
    if (k === "credBlob")  Object.assign(out, _credBlobExt(extensions.credBlob));
  }
  return out;
}

// ---- Registration ----

async function startRegistration(opts) {
  if (!opts) throw new AuthError("auth-passkey/missing-opts", "opts is required");
  _requireString(opts.rpName, "rpName");
  _requireString(opts.rpId, "rpId");
  _requireString(opts.userName, "userName");

  var sel = opts.authenticatorSelection || {};
  var algorithms = _resolveAllowedAlgorithms(opts.allowedAlgorithms);
  // One discoverability requirement, stated once. `residentKey` is the modern
  // field and decides when present; the L1 boolean `requireResidentKey` still
  // states the same requirement on its own and raises residentKey with it,
  // rather than being read and dropped.
  var residentKey = sel.residentKey ||
    (sel.requireResidentKey === true ? "required" : "preferred");
  var safeExtensions = _validateExtensions(opts.extensions, opts.allowUnknownExtensions === true);
  // Building the descriptor rather than delegating it: it is a JSON document
  // the browser reads, with no signature and no secret in it beyond the
  // challenge, so the only thing a library adds here is its own opinion about
  // defaults. The user handle stays a fresh random value per ceremony, which is
  // what this primitive has always emitted.
  var options = {
    challenge:            _freshChallenge(),
    rp:                   { name: opts.rpName, id: opts.rpId },
    user: {
      id:                 bCrypto.generateBytes(USER_HANDLE_BYTES).toString("base64url"),
      name:               opts.userName,
      displayName:        opts.userDisplayName || opts.userName,
    },
    pubKeyCredParams:     algorithms.map(function (a) { return { alg: a, type: "public-key" }; }),
    timeout:              typeof opts.timeout === "number" ? opts.timeout : DEFAULT_TIMEOUT_MS,
    attestation:          opts.attestationType || "none",
    excludeCredentials:   _credentialDescriptors(opts.excludeCredentials, "excludeCredentials"),
    authenticatorSelection: {
      residentKey:               residentKey,
      userVerification:          sel.userVerification  || "preferred",
      // Tied to residentKey, never read independently. The two fields state
      // ONE requirement -- "this credential must be discoverable" -- and
      // browsers in the field read one or the other, so a pair that disagrees
      // lets a browser create a NON-discoverable credential for a relying
      // party that required one. Nothing fails at registration: the credential
      // works, and only username-less and conditional-UI login are missing.
      requireResidentKey:        residentKey === "required",
    },
    extensions:           safeExtensions,
  };
  if (sel.authenticatorAttachment !== undefined) {
    options.authenticatorSelection.authenticatorAttachment = sel.authenticatorAttachment;
  }
  // Hint the browser at which authenticators to surface. An explicit list is
  // the operator's call and passes through untouched.
  //
  // The DEFAULT follows authenticatorAttachment, because the two say the same
  // thing and the browser gives hints precedence in the UI: hinting at the
  // platform authenticator during a cross-platform ceremony offers the user a
  // path the attachment forbids, and the credential creation is then refused
  // on the authenticator they picked. With no attachment set, surface both
  // families — platform (Touch ID / Windows Hello) and cross-device
  // (1Password / Bitwarden / phone-as-key).
  if (!opts.hints) {
    if (sel.authenticatorAttachment === "cross-platform") {
      options.hints = ["security-key", "hybrid"];
    } else if (sel.authenticatorAttachment === "platform") {
      options.hints = ["client-device"];
    } else {
      options.hints = ["client-device", "hybrid"];
    }
  } else {
    options.hints = opts.hints;
  }
  return options;
}

// The algorithms this relying party will accept, in preference order:
// Ed25519, ES256, RS256. Offered at registration and enforced at verification —
// an authenticator that returns a credential outside this set is refused rather
// than trusted because it was asked nicely.
var DEFAULT_ALGORITHMS = Object.freeze([-8, -7, -257]);

// Every COSE signature algorithm the verifier can actually check, by IANA COSE
// identifier. An operator may widen to any of these for credentials registered
// before the default narrowed -- refusing an assertion from a credential this
// same system issued locks the user out, and re-registration is not always a
// path they have. The list is what the verifier supports, proven by exercising
// each one end to end rather than copied from a table: PS384 (-38) and PS512
// (-39) are deliberately absent because the vendored verifier refuses their
// COSE keys.
//
// RSA with SHA-1 (-65535) is NOT here and cannot be opted into. SHA-1 is
// unfit for signatures and the option exists to keep working credentials
// working, not to make a broken primitive reachable through configuration.
var SUPPORTED_ALGORITHMS = Object.freeze({
  "-8":    "EdDSA (Ed25519)",
  "-7":    "ES256",
  "-35":   "ES384",
  "-36":   "ES512",
  "-37":   "PS256",
  "-257":  "RS256",
  "-258":  "RS384",
  "-259":  "RS512",
});
var REFUSED_ALGORITHMS = Object.freeze({ "-65535": "RSA with SHA-1" });

var CHALLENGE_BYTES = 32;                                                          // allow:raw-byte-literal — WebAuthn 13.4.3 requires >= 16; 32 is the common floor
var USER_HANDLE_BYTES = 32;                                                        // allow:raw-byte-literal — 13.4.4 caps the user handle at 64
var DEFAULT_TIMEOUT_MS = 60000;                                                    // allow:raw-byte-literal // allow:raw-time-literal — the ceremony timeout browsers expect

// Recover the parsed COSE key object from the credential key BYTES an operator
// persisted at registration.
//
// Bytes are the form that survives a database column, and the form every
// existing credential row already holds, so the stored contract stays bytes.
// The verifier wants the parsed object, and the only parsers it exports take a
// containing structure — so the bytes are wrapped in the smallest
// authenticatorData that carries an attestedCredentialData and handed to the
// shipped parser. The wrapper's rpIdHash / aaguid / credential id are never
// read: this call reaches the key decoder and nothing else.
//
// Tracked upstream as blamejs/pki#159 (parseCoseKey, or accepting bytes
// directly); this collapses to one call the day either lands.
var _COSE_WRAP_FLAGS = 0x40;                                                       // allow:raw-byte-literal — AT: attestedCredentialData present
// The authenticator model identifier, as the dashed UUID string the rest of
// the framework speaks. The verifier hands it over as 16 raw bytes.
//
// This is the seam into b.auth.fidoMds3: verifyAuthenticator(blob,
// registrationInfo) takes the object verifyRegistration returns, and its
// lookup is by UUID string. Handing bytes across that boundary breaks the
// documented composition of the two primitives, which neither one's own tests
// would notice. Formatted here, once, rather than at the call site.
function _aaguidString(raw) {
  if (typeof raw === "string") return raw;
  if (!raw) return null;
  var hex = safeBuffer.toBuffer(raw).toString("hex");
  if (hex.length !== 32) return hex;                                                // allow:raw-byte-literal — 16 bytes as hex
  return [hex.slice(0, 8), hex.slice(8, 12), hex.slice(12, 16),
          hex.slice(16, 20), hex.slice(20)].join("-");
}

// The stored credential key, as whatever shape the operator's storage handed
// back, reduced to bytes. A BLOB column yields a Buffer, a TEXT column yields
// the base64url string that was written to it, and both are the same key.
//
// A string is decoded as base64url -- the encoding every other string in this
// module uses -- and never as UTF-8. Reading base64url text as UTF-8 does not
// fail; it produces different bytes that are not a COSE key, so the login is
// refused with a message about a malformed credential and the operator goes
// looking for corruption in a row that is intact. Anything that is neither
// bytes nor base64url is refused by name for the same reason: a wrong-shaped
// value must not be coerced into bytes that merely happen to parse.
function _storedKeyBytes(stored) {
  if (typeof stored === "string") {
    if (!/^[A-Za-z0-9_-]+$/.test(stored)) {
      throw new AuthError("auth-passkey/bad-credential-key",
        "credential.publicKey is a string but not base64url -- store the COSE " +
        "key bytes, or their base64url text");
    }
    return Buffer.from(stored, "base64url");
  }
  try {
    return safeBuffer.toBuffer(stored);
  } catch (e) {
    throw new AuthError("auth-passkey/bad-credential-key",
      "credential.publicKey must be the stored COSE key as bytes (Buffer / " +
      "Uint8Array) or base64url text: " + ((e && e.message) || e));
  }
}

function _coseKeyObject(stored) {
  if (stored && typeof stored === "object" && !Buffer.isBuffer(stored) &&
      !(stored instanceof Uint8Array)) {
    return stored;                                    // already the parsed object
  }
  var bytes = _storedKeyBytes(stored);
  var credId = Buffer.alloc(1);
  var idLen = Buffer.alloc(2); idLen.writeUInt16BE(credId.length, 0);
  var wrapper = Buffer.concat([
    Buffer.alloc(32), Buffer.from([_COSE_WRAP_FLAGS]), Buffer.alloc(4),             // allow:raw-byte-literal — rpIdHash + flags + signCount, none of them read
    Buffer.alloc(16), idLen, credId, bytes,                                         // allow:raw-byte-literal — aaguid
  ]);
  try {
    return _pki().webauthn.parseAuthenticatorData(wrapper).credentialPublicKey;
  } catch (e) {
    throw new AuthError("auth-passkey/bad-credential-key",
      "credential.publicKey is not a decodable COSE key: " + ((e && e.message) || e));
  }
}

// Re-frame a refusal from the verification library as this primitive's own
// error. The contract operators code against is `catch (e) { if (e.isAuthError)
// ... }` with an auth-passkey/* code, the same shape as auth.password and
// auth.totp; a refusal that escapes in the library's own type falls straight
// through that handler into a 500, and names the library in the operator's
// logs. The verifier's code is preserved after the namespace swap because WHICH
// check refused is the actionable part.
//
// Every call into the verifier goes through this, so a path cannot be added
// that reports a refusal differently from its neighbours -- which is exactly
// how the registration ceremony came to report a stale challenge, the most
// ordinary failure there is, in a type nothing caught.
function _refuse(ceremony, e) {
  return new AuthError(
    "auth-passkey/" + String((e && e.code) || "verification-failed")
                        .replace(/^webauthn\//, ""),
    ceremony + " refused: " + ((e && e.message) || String(e)));
}

// Resolve opts.allowedAlgorithms to the list both halves of a ceremony use --
// what startRegistration advertises in pubKeyCredParams AND what the verifiers
// enforce. One option drives both so a deployment can never offer one set and
// accept another.
//
// Config-time tier: a bad list throws at the entry point rather than degrading
// to the default, because silently ignoring it is how an operator ends up
// believing they widened the set while every legacy login keeps failing.
function _resolveAllowedAlgorithms(value) {
  if (value === undefined || value === null) return DEFAULT_ALGORITHMS;
  if (!Array.isArray(value) || value.length === 0) {
    throw new AuthError("auth-passkey/bad-algorithm",
      "allowedAlgorithms must be a non-empty array of COSE algorithm " +
      "identifiers -- an empty list permits nothing and is never read as " +
      "'any algorithm'");
  }
  var out = [];
  for (var i = 0; i < value.length; i += 1) {
    var alg = value[i];
    if (typeof alg !== "number" || !isFinite(alg) || Math.floor(alg) !== alg) {
      throw new AuthError("auth-passkey/bad-algorithm",
        "allowedAlgorithms[" + i + "] must be an integer COSE algorithm " +
        "identifier (got " + typeof alg + ")");
    }
    if (REFUSED_ALGORITHMS[String(alg)] !== undefined) {
      throw new AuthError("auth-passkey/bad-algorithm",
        "allowedAlgorithms[" + i + "] is " + REFUSED_ALGORITHMS[String(alg)] +
        " (" + alg + "), which is not fit for signatures and cannot be " +
        "enabled -- a credential using it has to be re-registered");
    }
    if (SUPPORTED_ALGORITHMS[String(alg)] === undefined) {
      throw new AuthError("auth-passkey/bad-algorithm",
        "allowedAlgorithms[" + i + "] is " + alg + ", which this verifier " +
        "cannot check -- supported identifiers are " +
        Object.keys(SUPPORTED_ALGORITHMS).join(", "));
    }
    if (out.indexOf(alg) === -1) out.push(alg);
  }
  return out;
}

// Refuse a wire-supplied credential ID that disagrees with the authoritative
// one -- the ID inside the attestation at registration, the stored record's ID
// at authentication. A response carries the same identity twice (`id` and its
// binary spelling `rawId`) and an operator may key on either, so BOTH are
// checked against the one authority rather than against each other.
//
// Absent is fine: WebAuthn requires the field, but an operator normalizing a
// response before handing it over may drop one of the two spellings, and the
// authoritative value is what gets used either way. Present-and-different is
// not -- that is a claim on an identity nothing signed.
function _requireCredentialIdMatches(response, authoritativeId, why) {
  if (typeof response !== "object" || response === null) return;
  var fields = ["id", "rawId"];
  for (var i = 0; i < fields.length; i += 1) {
    var wireValue = response[fields[i]];
    if (wireValue === undefined || wireValue === null) continue;
    if (typeof wireValue !== "string" || wireValue !== authoritativeId) {
      throw new AuthError("auth-passkey/credential-id-mismatch",
        "response." + fields[i] + " is " + JSON.stringify(wireValue) +
        " but " + why + " is " + JSON.stringify(authoritativeId));
    }
  }
}

// A ceremony challenge: fresh CSPRNG bytes, base64url for transport. Returned
// as a string because that is what the browser receives and what the operator
// stores in the session to compare later. b.crypto.generateBytes rather than
// node:crypto directly, so the challenge comes from the same SHAKE256-over-
// OS-RNG source as every other secret the framework mints.
function _freshChallenge() {
  return bCrypto.generateBytes(CHALLENGE_BYTES).toString("base64url");
}

// Credential descriptors as the browser expects them: { id, type, transports? }.
// Accepts either a bare base64url id or an object, because operators persist
// whichever their storage made convenient.
function _credentialDescriptors(list, field) {
  if (list === undefined || list === null) return [];
  if (!Array.isArray(list)) {
    throw new AuthError("auth-passkey/bad-" + field, field + " must be an array");
  }
  return list.map(function (entry, i) {
    var id = typeof entry === "string" ? entry : (entry && entry.id);
    if (typeof id !== "string" || id.length === 0) {
      throw new AuthError("auth-passkey/bad-" + field,
        field + "[" + i + "] needs a base64url credential id");
    }
    if (!_b64urlValid(id)) {
      throw new AuthError("auth-passkey/bad-" + field,
        field + "[" + i + "].id must be base64url (no padding)");
    }
    var out = { id: id, type: "public-key" };
    if (entry && Array.isArray(entry.transports) && entry.transports.length) {
      out.transports = entry.transports.slice();
    }
    return out;
  });
}

function _validateExpectedOrigin(value) {
  if (typeof value === "string") {
    if (value.length === 0) {
      throw new AuthError("auth-passkey/missing-expectedOrigin",
        "expectedOrigin must be a non-empty string or array of strings");
    }
    return;
  }
  if (Array.isArray(value)) {
    if (value.length === 0) {
      throw new AuthError("auth-passkey/missing-expectedOrigin",
        "expectedOrigin array must contain at least one non-empty string");
    }
    for (var i = 0; i < value.length; i += 1) {
      if (typeof value[i] !== "string" || value[i].length === 0) {
        throw new AuthError("auth-passkey/missing-expectedOrigin",
          "expectedOrigin[" + i + "] must be a non-empty string");
      }
    }
    return;
  }
  throw new AuthError("auth-passkey/missing-expectedOrigin",
    "expectedOrigin must be a non-empty string or array of strings");
}

async function verifyRegistration(opts) {
  if (!opts) throw new AuthError("auth-passkey/missing-opts", "opts is required");
  if (!opts.response) {
    throw new AuthError("auth-passkey/missing-response", "opts.response is required");
  }
  _requireString(opts.expectedChallenge, "expectedChallenge");
  // Multi-origin deployments (web + admin subdomain) need string[].
  _validateExpectedOrigin(opts.expectedOrigin);
  _requireString(opts.expectedRPID, "expectedRPID");

  _refuseCrossOrigin(opts.response, opts, "registration");
  // Resolved BEFORE the verifier call: a bad list is an operator's own
  // configuration error, and the catch below rewrites every code it sees into
  // the auth-passkey namespace, which would restate one already there.
  var regAlgorithms = _resolveAllowedAlgorithms(opts.allowedAlgorithms);
  var regInner = opts.response.response || {};
  var attestationObject = _wireBytes(regInner.attestationObject, "attestationObject");
  var clientDataJSON = _wireBytes(regInner.clientDataJSON, "clientDataJSON");

  // clientData is checked here rather than delegated: the attestation verifier
  // takes the client-data HASH, so the ceremony type, challenge and origin are
  // this layer's to compare. Decoded challenge bytes, not the base64url text —
  // two spellings of one challenge must not be able to disagree.
  var clientData;
  try {
    clientData = _pki().webauthn.parseClientData(clientDataJSON, {
      expectedType:      "webauthn.create",
      expectedChallenge: Buffer.from(opts.expectedChallenge, "base64url"),
      expectedOrigin:    opts.expectedOrigin,
    });
  } catch (e) {
    throw _refuse("registration response", e);
  }

  var att;
  try {
    att = await _pki().webauthn.verify(attestationObject,
      nodeCrypto.createHash("sha256").update(clientDataJSON).digest(), {
        expectedRpId:            opts.expectedRPID,
        requireUserPresence:     true,
        requireUserVerification: opts.requireUserVerification !== false,
        allowedAlgorithms:       regAlgorithms,
      });
  } catch (e) {
    throw _refuse("registration response", e);
  }

  var regFlags = att.flags || {};
  // The authoritative credential ID is the one inside attestedCredentialData,
  // which the attestation signs over. response.id / response.rawId are
  // client-supplied and covered by nothing, so a registration may claim any
  // ID at all while attesting its own key. An RP keying its credential table
  // on the returned value would then overwrite the victim's row with the
  // attacker's public key. Persist the ATTESTED id, and refuse outright when
  // the wire disagrees rather than silently correcting it — a mismatch is
  // either an attack or a broken client, and neither should register.
  var attestedId = safeBuffer.toBuffer(att.credentialId).toString("base64url");
  _requireCredentialIdMatches(opts.response, attestedId,
    "the credential ID inside the attestation");

  var rv = {
    verified: att.attestationVerified === true,
    registrationInfo: {
      // The credential key is persisted as BYTES: that is what a database
      // column holds and what every already-stored credential is. The parsed
      // object is reconstructed at login.
      credential: {
        id:        attestedId,
        publicKey: att.credentialPublicKeyBytes ||
                   _pki().webauthn.parseAttestationObject(attestationObject)
                     .authData.credentialPublicKeyBytes,
        counter:   att.signCount,
        // getTransports() from the browser: which way this authenticator can
        // be reached (usb / nfc / ble / internal / hybrid). Persist it and
        // hand it back in allowCredentials, and the next login goes straight
        // to the right transport instead of prompting for all of them.
        // Left ABSENT rather than defaulted to [] when the client reports
        // nothing, so "not reported" stays distinguishable from "none".
        transports: regInner.transports,
      },
      credentialType:       opts.response.type || "public-key",
      credentialDeviceType: regFlags.be === true ? "multiDevice" : "singleDevice",
      credentialBackedUp:   regFlags.bs === true,
      aaguid:               _aaguidString(att.aaguid),
      fmt:                  att.fmt,
      attestationType:      att.attestationType,
      anchoredTo:           att.anchoredTo,
      userVerified:         regFlags.uv === true,
      // The origin and RP ID this ceremony was verified AGAINST, and the
      // attestation it was verified FROM. Echoed back so an audit record, or
      // a later re-check against a refreshed metadata BLOB, can be written
      // from the verification result alone rather than by re-deriving what
      // the request was.
      //
      // The origin is the one the ceremony actually happened at, taken from
      // the verified client data -- not expectedOrigin, which may be an
      // allow-list of several and would record the whole list on every row.
      origin:               clientData.origin,
      rpID:                 opts.expectedRPID,
      attestationObject:    attestationObject,
    },
  };
  // WebAuthn L3 §6.1.3 — surface authenticator-data BE/BS flags as
  // named fields. backupEligible (BE) signals the credential CAN be
  // backed up to a cloud account; backupState (BS) signals it IS
  // currently backed up. Operators key trust decisions on these
  // (single-device passkey → require step-up; multi-device synced
  // passkey → strong signal). The vendor parses authData and exposes
  // credentialDeviceType ("singleDevice" | "multiDevice") and
  // credentialBackedUp (boolean) on registrationInfo; we map them to
  // the spec's flag names and add them to the top-level result so
  // callers don't have to dig through registrationInfo.
  if (rv && rv.registrationInfo) {
    rv.backupEligible = rv.registrationInfo.credentialDeviceType === "multiDevice";
    rv.backupState    = rv.registrationInfo.credentialBackedUp === true;
  } else {
    rv = rv || {};
    rv.backupEligible = false;
    rv.backupState    = false;
  }
  return rv;
}

// ---- Authentication ----

// startAuthentication accepts an optional `mediation` token that the
// caller passes through verbatim to the browser as
// `navigator.credentials.get({ publicKey, mediation })`. The descriptor
// itself doesn't carry mediation — it's a separate argument on the
// page — but startAuthentication echoes it onto the returned options
// so the operator's transport (typically a JSON GET) carries it to
// the page without losing the value. Allowed tokens per the W3C
// Credential Management spec: "silent" / "optional" / "required" /
// "conditional". "conditional" enables passkey autofill on
// <input autocomplete="webauthn">.
// Null-prototype map so `opts.mediation === "__proto__"` /
// `"constructor"` can't truthy-match an inherited property and slip
// past the allowlist.
var ALLOWED_MEDIATION = Object.assign(Object.create(null),
  { silent: 1, optional: 1, required: 1, conditional: 1 });

async function startAuthentication(opts) {
  if (!opts) throw new AuthError("auth-passkey/missing-opts", "opts is required");
  _requireString(opts.rpId, "rpId");
  if (opts.mediation !== undefined &&
      !Object.prototype.hasOwnProperty.call(ALLOWED_MEDIATION, opts.mediation)) {
    throw new AuthError("auth-passkey/bad-mediation",
      "mediation must be one of silent/optional/required/conditional");
  }

  var safeAuthExtensions = _validateExtensions(opts.extensions, opts.allowUnknownExtensions === true);
  var options = {
    rpId:               opts.rpId,
    challenge:          _freshChallenge(),
    allowCredentials:   _credentialDescriptors(opts.allowCredentials, "allowCredentials"),
    timeout:            typeof opts.timeout === "number" ? opts.timeout : DEFAULT_TIMEOUT_MS,
    userVerification:   opts.userVerification || "preferred",
    extensions:         safeAuthExtensions,
  };
  if (!opts.hints) {
    options.hints = ["client-device", "hybrid"];
  } else {
    options.hints = opts.hints;
  }
  if (opts.mediation !== undefined) {
    options.mediation = opts.mediation;
  }
  return options;
}

// conditionalAuthOptions — convenience wrapper for the passkey-autofill
// flow (mediation: "conditional"). Browsers require an empty
// allowCredentials list, presence-only userVerification (so the
// autofill chip can surface without forcing biometric), and a present
// challenge. Returns an object shaped for
// `navigator.credentials.get({ publicKey: <opts>, mediation: "conditional" })`.
async function conditionalAuthOptions(opts) {
  if (!opts) throw new AuthError("auth-passkey/missing-opts", "opts is required");
  _requireString(opts.rpId, "rpId");

  var safeCondExtensions = _validateExtensions(opts.extensions, opts.allowUnknownExtensions === true);
  var options = {
    rpId:               opts.rpId,
    challenge:          _freshChallenge(),
    // For conditional UI the spec mandates an empty allowCredentials
    // list — discoverable credentials only. Supplying a list here
    // suppresses the autofill chip in current browsers.
    allowCredentials:   [],
    timeout:            typeof opts.timeout === "number" ? opts.timeout : DEFAULT_TIMEOUT_MS,
    userVerification:   opts.userVerification || "preferred",
    extensions:         safeCondExtensions,
  };
  options.mediation = "conditional";
  if (!opts.hints) {
    options.hints = ["client-device", "hybrid"];
  } else {
    options.hints = opts.hints;
  }
  return options;
}

// ---- WebAuthn L3 extension helpers (PRF / largeBlob / credBlob) ----
//
// Pre-compute the spec-correct shape so callers don't have to remember
// (a) what the field is called this year, (b) which inputs travel as
// base64url vs Uint8Array, (c) which support the {support:"required"}
// contract. Validation tier: throw at config-time. Misuse here is a
// coding bug, not a request-shape thing.

// CTAP2.1 §6.5 — PRF eval inputs are 32-byte salts. Caps every
// extension input that ships through the binary normalizer.
var MAX_EXT_INPUT_BYTES = 32;                                                                    // CTAP2.1 §6.5 PRF salt length

function _b64urlExtInput(value, name, maxBytes) {
  // Accept a base64url string OR a Buffer / Uint8Array. Normalize the
  // wire shape to base64url (the JSON descriptor ships base64url; the
  // browser turns it into an ArrayBuffer before passing to the
  // authenticator).
  //
  // When `maxBytes` is set, refuse decoded inputs longer than
  // the cap. Per CTAP2.1 §6.5 PRF salts are 32 bytes; pre-v0.9.x the
  // framework accepted arbitrary length, which is undefined behavior on
  // authenticators that may truncate / reject / behave inconsistently.
  if (typeof value === "string") {
    if (value.length === 0 || !safeBuffer.BASE64URL_RE.test(value)) {
      throw new AuthError("auth-passkey/bad-extension-input",
        name + " must be base64url (no padding) when string");
    }
    if (typeof maxBytes === "number") {
      var decoded = Buffer.from(value, "base64url");
      if (safeBuffer.byteLengthOf(decoded) > maxBytes) {
        throw new AuthError("auth-passkey/extension-input-too-large",
          name + " decoded length " + decoded.length + " exceeds " + maxBytes + " bytes");
      }
    }
    return value;
  }
  if (Buffer.isBuffer(value)) {
    if (typeof maxBytes === "number" && safeBuffer.byteLengthOf(value) > maxBytes) {
      throw new AuthError("auth-passkey/extension-input-too-large",
        name + " length " + value.length + " exceeds " + maxBytes + " bytes");
    }
    return value.toString("base64url");
  }
  if (value instanceof Uint8Array) {
    if (typeof maxBytes === "number" && safeBuffer.byteLengthOf(value) > maxBytes) {
      throw new AuthError("auth-passkey/extension-input-too-large",
        name + " length " + value.length + " exceeds " + maxBytes + " bytes");
    }
    return Buffer.from(value).toString("base64url");
  }
  throw new AuthError("auth-passkey/bad-extension-input",
    name + " must be base64url string, Buffer, or Uint8Array");
}

// PRF (Pseudo-Random Function) extension — WebAuthn L3 §10.1.2.
// Authenticator-bound HKDF source. eval inputs are 32-byte salts; the
// authenticator returns deterministic 32-byte outputs the operator
// uses as a key-encryption key (vault unlock, file-encryption seed).
// Shape: `{ prf: { eval: { first, second? } } }` per extension-id "prf".
function _prfExt(args) {
  if (!args || !args.eval) {
    throw new AuthError("auth-passkey/missing-eval",
      "extensions.prf({ eval: { first, second? } }) is required");
  }
  if (args.eval.first === undefined || args.eval.first === null) {
    throw new AuthError("auth-passkey/missing-prf-first",
      "extensions.prf eval.first is required");
  }
  // CTAP2.1 §6.5 caps PRF salts at 32 bytes.
  var out = { prf: { eval: { first: _b64urlExtInput(args.eval.first, "eval.first", MAX_EXT_INPUT_BYTES) } } };
  if (args.eval.second !== undefined && args.eval.second !== null) {
    out.prf.eval.second = _b64urlExtInput(args.eval.second, "eval.second", MAX_EXT_INPUT_BYTES);
  }
  return out;
}

// largeBlob extension — WebAuthn L3 §10.3.
// Per-credential opaque blob storage. At registration the operator
// asks for support: "preferred" | "required". At auth time the
// operator asks to read OR write, never both in the same assertion.
function _largeBlobExt(args) {
  if (!args) {
    throw new AuthError("auth-passkey/missing-largeblob",
      "extensions.largeBlob({ support? | read? | write? }) is required");
  }
  var out = { largeBlob: {} };
  var SUPPORT = { preferred: 1, required: 1 };
  var modes = 0;
  if (args.support !== undefined) {
    if (!Object.prototype.hasOwnProperty.call(SUPPORT, args.support)) {
      throw new AuthError("auth-passkey/bad-largeblob-support",
        "extensions.largeBlob support must be 'preferred' or 'required'");
    }
    out.largeBlob.support = args.support;
    modes++;
  }
  if (args.read === true) {
    out.largeBlob.read = true;
    modes++;
  } else if (args.read !== undefined && args.read !== false) {
    throw new AuthError("auth-passkey/bad-largeblob-read",
      "extensions.largeBlob read must be a boolean");
  }
  if (args.write !== undefined && args.write !== null) {
    if (!Buffer.isBuffer(args.write) && !(args.write instanceof Uint8Array)) {
      throw new AuthError("auth-passkey/bad-largeblob-write",
        "extensions.largeBlob write must be a Uint8Array / Buffer");
    }
    out.largeBlob.write = Buffer.from(args.write).toString("base64url");
    modes++;
  }
  if (modes === 0) {
    throw new AuthError("auth-passkey/empty-largeblob",
      "extensions.largeBlob({}) needs support, read, or write");
  }
  if (args.read === true && args.write !== undefined && args.write !== null) {
    throw new AuthError("auth-passkey/conflicting-largeblob",
      "extensions.largeBlob — read and write are mutually exclusive");
  }
  return out;
}

// credBlob extension — WebAuthn L3 §10.5.
// Server-supplied opaque blob (≤32 bytes per CTAP2.1) bound to the
// credential at registration. Returned in subsequent assertions.
// Shape: `{ credBlob: <base64url> }`.
function _credBlobExt(args) {
  if (!args || args.blob === undefined || args.blob === null) {
    throw new AuthError("auth-passkey/missing-credblob",
      "extensions.credBlob({ blob }) is required");
  }
  var buf;
  if (Buffer.isBuffer(args.blob)) {
    buf = args.blob;
  } else if (args.blob instanceof Uint8Array) {
    buf = Buffer.from(args.blob);
  } else {
    throw new AuthError("auth-passkey/bad-credblob",
      "extensions.credBlob blob must be a Uint8Array / Buffer");
  }
  if (buf.length === 0 || buf.length > 32) {                                       // CTAP2.1 §11.1 credBlob max
    throw new AuthError("auth-passkey/credblob-bad-length",
      "extensions.credBlob blob must be 1-32 bytes (CTAP2.1 §11.1)");
  }
  return { credBlob: buf.toString("base64url") };
}

var extensions = {
  prf:       _prfExt,
  largeBlob: _largeBlobExt,
  credBlob:  _credBlobExt,
};

async function verifyAuthentication(opts) {
  if (!opts) throw new AuthError("auth-passkey/missing-opts", "opts is required");
  if (!opts.response) {
    throw new AuthError("auth-passkey/missing-response", "opts.response is required");
  }
  _requireString(opts.expectedChallenge, "expectedChallenge");
  _validateExpectedOrigin(opts.expectedOrigin);
  _requireString(opts.expectedRPID, "expectedRPID");
  if (!opts.credential || !opts.credential.id || !opts.credential.publicKey) {
    throw new AuthError("auth-passkey/missing-credential",
      "opts.credential { id, publicKey, counter? } is required");
  }
  // Counter regression bypass fix — pre-v0.9.2
  // shape `opts.credential.counter || 0` silently zeroed an
  // undefined / null / NaN counter, defeating CTAP 2.1 clone-
  // detection on credentials whose stored counter is > 0. An
  // operator who deserialized the credential from a column that
  // dropped the counter would unknowingly accept a cloned
  // authenticator. Require an explicit non-negative integer.
  var counter;
  if (opts.credential.counter === undefined || opts.credential.counter === null) {
    // First-time-stored credentials legitimately have no counter
    // yet (registration ran on a vendor returning 0). Operators
    // MUST persist whatever the vendor returned; if they didn't,
    // refuse rather than silently coerce.
    throw new AuthError("auth-passkey/missing-counter",
      "opts.credential.counter is required (set to 0 at registration; " +
      "store the newCounter returned by verifyAuthentication on every " +
      "successful auth). undefined / null is refused to prevent clone-" +
      "detection bypass when the persisted column is missing.");
  }
  if (typeof opts.credential.counter !== "number" ||
      !isFinite(opts.credential.counter) ||
      opts.credential.counter < 0 ||
      Math.floor(opts.credential.counter) !== opts.credential.counter) {
    throw new AuthError("auth-passkey/bad-counter",
      "opts.credential.counter must be a non-negative integer (got " +
      typeof opts.credential.counter + ")");
  }
  counter = opts.credential.counter;

  // The stored record must be the one the assertion names. Not a signature
  // concern — a wrong record carries a wrong public key and the signature
  // fails anyway — but an operator who looks a credential up by USER rather
  // than by credential ID can pair a valid key with the wrong row, and that
  // deserves its own name instead of surfacing as an opaque signature failure.
  //
  // Ordered LAST of the credential guards deliberately: the missing/!bad
  // publicKey and counter checks above are the ones that protect something, so
  // they keep reporting first when several are wrong at once.
  _requireCredentialIdMatches(opts.response, opts.credential.id,
    "the stored opts.credential.id -- look the credential up BY the asserted id");
  _refuseCrossOrigin(opts.response, opts, "authentication");
  // Resolved BEFORE the verifier call. The catch below turns a failed signature
  // into `verified: false` rather than an exception, so leaving this inside it
  // would report an operator's malformed algorithm list as an ordinary failed
  // login -- a configuration error that reads as "wrong passkey".
  var authAlgorithms = _resolveAllowedAlgorithms(opts.allowedAlgorithms);
  var inner = opts.response.response || {};
  // The challenge crosses as base64url on the wire and is stored that way, but
  // the verifier compares the DECODED bytes — deliberately, so two spellings of
  // one challenge cannot disagree. Decode here rather than pass the string.
  var assertion;
  try {
    assertion = await _pki().webauthn.verifyAssertion({
      authenticatorData:   _wireBytes(inner.authenticatorData, "authenticatorData"),
      clientDataJSON:      _wireBytes(inner.clientDataJSON, "clientDataJSON"),
      signature:           _wireBytes(inner.signature, "signature"),
      credentialPublicKey: _coseKeyObject(opts.credential.publicKey),
      previousSignCount:   counter,
      expectedChallenge:   Buffer.from(opts.expectedChallenge, "base64url"),
      expectedOrigin:      opts.expectedOrigin,
      expectedRpId:        opts.expectedRPID,
      requireUserPresence: true,
      requireUserVerification: opts.requireUserVerification !== false,
      allowedAlgorithms:   authAlgorithms,
    });
  } catch (e) {
    // A signature that does not verify is a NORMAL negative outcome — the
    // ordinary failed login — and is reported as `verified: false`, not raised.
    // Operator code reads `if (!rv.verified) deny()`; throwing here would turn
    // every wrong-key attempt into an unhandled exception and a 500 where a 401
    // belongs. The underlying verifier raises for this case, so it is mapped
    // back rather than passed through.
    if (e && e.code === "webauthn/bad-signature") {
      return {
        verified: false,
        authenticationInfo: null,
        backupEligible: false,
        backupState: false,
      };
    }
    // Everything else IS exceptional: a binding that disagrees (rp id, origin,
    // challenge), a counter that went backwards, a ceremony flag the policy
    // required. Those are configuration or attack conditions rather than a
    // failed guess, and each keeps the verifier's own code because which check
    // refused is the actionable part.
    throw _refuse("authentication assertion", e);
  }

  var flags = _pki().webauthn.parseAuthenticatorData(
    _wireBytes(inner.authenticatorData, "authenticatorData")).flags;
  // WebAuthn L3 §6.1.3 — same BE/BS surfacing as verifyRegistration.
  // Authentication assertions also carry the BE/BS bits in authData; a
  // credential that registered as single-device but later asserts as
  // multi-device (or vice versa) is a backup-state-changed signal worth
  // auditing at the operator level. We expose the current values so the
  // caller can compare against what they persisted at registration.
  return {
    verified: assertion.signatureVerified === true,
    authenticationInfo: {
      newCounter:           assertion.signCount,
      credentialID:         opts.credential.id,
      userVerified:         flags.uv === true,
      credentialDeviceType: flags.be === true ? "multiDevice" : "singleDevice",
      credentialBackedUp:   flags.bs === true,
      // The origin the ceremony actually happened at, from the verified client
      // data — not expectedOrigin, which may be an allow-list of several. The
      // registration result answers the same question the same way, and both
      // are written to the same audit row: a value that is a string after one
      // ceremony and an array after the other is a shape no consumer handles,
      // and records every permitted origin instead of the one that was used.
      // Null rather than falling back to expectedOrigin if the verifier ever
      // stops reporting it: "which origin" is then genuinely unknown, and an
      // audit row naming every permitted origin is worse than one saying so.
      origin:               (assertion.clientData && assertion.clientData.origin) || null,
      rpID:                 opts.expectedRPID,
    },
    backupEligible: flags.be === true,
    backupState:    flags.bs === true,
  };
}

/**
 * @primitive b.auth.passkey.compareBackupState
 * @signature b.auth.passkey.compareBackupState(prev, current)
 * @since     0.9.57
 *
 * WebAuthn L3 §6.1.3. Inspect the credential's persisted BE
 * (backupEligible) + BS (backupState) flags against the values
 * surfaced on a fresh assertion. Returns a normalized verdict the
 * operator routes into audit / step-up decisions:
 *
 *   - `ok` — flags unchanged
 *   - `be-flipped-on` — credential newly backup-eligible (the
 *     authenticator manufacturer enabled cloud-backup on a previously
 *     single-device credential; suspicious — operator surfaces
 *     step-up)
 *   - `be-flipped-off` — credential lost backup eligibility (rare;
 *     authenticator firmware downgrade or vendor policy change)
 *   - `bs-flipped-on` — credential is now backed up (user enrolled
 *     in cloud-sync after initial registration; legitimate but
 *     audit-worthy)
 *   - `bs-flipped-off` — credential no longer backed up (user
 *     disabled cloud-sync; legitimate but audit-worthy)
 *
 * Operators wire this against the credential row's persisted
 * `backupEligible` / `backupState` fields and the corresponding
 * fields on `verifyAuthentication`'s return value.
 *
 * @example
 *   var rv   = await b.auth.passkey.verifyAuthentication(opts);
 *   var diff = b.auth.passkey.compareBackupState(stored, rv);
 *   if (diff.verdict !== "ok") {
 *     await audit.emit({ event: "passkey.backup-state-changed", metadata: diff });
 *     if (diff.verdict === "be-flipped-on") { requireStepUp(); }
 *   }
 */
function compareBackupState(prev, current) {
  if (!prev || typeof prev !== "object") {
    throw new AuthError("auth-passkey/bad-compare-backup",
      "compareBackupState: prev must be an object with { backupEligible, backupState }");
  }
  if (!current || typeof current !== "object") {
    throw new AuthError("auth-passkey/bad-compare-backup",
      "compareBackupState: current must be an object with { backupEligible, backupState }");
  }
  var pBE = prev.backupEligible === true;
  var pBS = prev.backupState    === true;
  var cBE = current.backupEligible === true;
  var cBS = current.backupState    === true;
  var verdict = "ok";
  if (pBE !== cBE) verdict = cBE ? "be-flipped-on"  : "be-flipped-off";
  else if (pBS !== cBS) verdict = cBS ? "bs-flipped-on" : "bs-flipped-off";
  return {
    verdict:                verdict,
    prevBackupEligible:     pBE,
    prevBackupState:        pBS,
    currentBackupEligible:  cBE,
    currentBackupState:     cBS,
  };
}

// ---- WebAuthn Signal API (W3C draft, 2024) ----
//
// The signal* methods build the JSON descriptor that the operator
// returns to the client; the browser then calls the matching
// `PublicKeyCredential.signal*` method to clean up stale passkeys
// and refresh user details. These are pure builders — no I/O — so
// validation throws at the boundary and the descriptor shape is the
// W3C draft schema verbatim.

function _b64urlValid(s) {
  return typeof s === "string" && s.length > 0 && safeBuffer.BASE64URL_RE.test(s);
}

function signalUnknownCredential(opts) {
  if (!opts) throw new AuthError("auth-passkey/missing-opts", "opts is required");
  _requireString(opts.rpId, "rpId");
  _requireString(opts.credentialId, "credentialId");
  if (!_b64urlValid(opts.credentialId)) {
    throw new AuthError("auth-passkey/bad-credential-id",
      "credentialId must be base64url (no padding)");
  }
  return {
    rpId:         opts.rpId,
    credentialId: opts.credentialId,
  };
}

function signalAllAcceptedCredentials(opts) {
  if (!opts) throw new AuthError("auth-passkey/missing-opts", "opts is required");
  _requireString(opts.rpId, "rpId");
  _requireString(opts.userId, "userId");
  if (!_b64urlValid(opts.userId)) {
    throw new AuthError("auth-passkey/bad-user-id",
      "userId must be base64url (no padding)");
  }
  if (!Array.isArray(opts.allAcceptedCredentialIds)) {
    throw new AuthError("auth-passkey/bad-accepted-list",
      "allAcceptedCredentialIds must be an array");
  }
  for (var i = 0; i < opts.allAcceptedCredentialIds.length; i++) {
    if (!_b64urlValid(opts.allAcceptedCredentialIds[i])) {
      throw new AuthError("auth-passkey/bad-accepted-list",
        "allAcceptedCredentialIds[" + i + "] must be base64url");
    }
  }
  return {
    rpId:                     opts.rpId,
    userId:                   opts.userId,
    allAcceptedCredentialIds: opts.allAcceptedCredentialIds.slice(),
  };
}

function signalCurrentUserDetails(opts) {
  if (!opts) throw new AuthError("auth-passkey/missing-opts", "opts is required");
  _requireString(opts.rpId, "rpId");
  _requireString(opts.userId, "userId");
  if (!_b64urlValid(opts.userId)) {
    throw new AuthError("auth-passkey/bad-user-id",
      "userId must be base64url (no padding)");
  }
  _requireString(opts.name, "name");
  _requireString(opts.displayName, "displayName");
  // RP-relevant length cap — the descriptor is a hint to the browser,
  // not a stored value, but absurdly long names indicate a misuse and
  // we refuse rather than truncate silently.
  if (opts.name.length > MAX_NAME_LEN) {
    throw new AuthError("auth-passkey/name-too-long",
      "name must be <= " + MAX_NAME_LEN + " characters");
  }
  if (opts.displayName.length > MAX_NAME_LEN) {
    throw new AuthError("auth-passkey/displayname-too-long",
      "displayName must be <= " + MAX_NAME_LEN + " characters");
  }
  return {
    rpId:        opts.rpId,
    userId:      opts.userId,
    name:        opts.name,
    displayName: opts.displayName,
  };
}

module.exports = {
  startRegistration:            startRegistration,
  verifyRegistration:           verifyRegistration,
  startAuthentication:          startAuthentication,
  verifyAuthentication:         verifyAuthentication,
  conditionalAuthOptions:       conditionalAuthOptions,
  extensions:                   extensions,
  signalUnknownCredential:      signalUnknownCredential,
  signalAllAcceptedCredentials: signalAllAcceptedCredentials,
  signalCurrentUserDetails:     signalCurrentUserDetails,
  compareBackupState:           compareBackupState,
  ALLOWED_EXTENSION_KEYS:       ALLOWED_EXTENSION_KEYS,
};
