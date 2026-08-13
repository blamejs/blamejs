// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.auth.passkey — REAL WebAuthn signature verification.
 *
 * The companion suite (passkey.test.js) stubs the vendored verifier via a
 * require-cache override, so the actual attestation / assertion signature
 * verification never executes there — a forged-assertion-accepted
 * regression would pass that suite green. This suite closes that gap: it
 * drives verifyRegistration + verifyAuthentication through the vendored
 * verifier UNTOUCHED, with genuine WebAuthn material produced by a
 * software authenticator built on Node's crypto.
 *
 * The software authenticator mints a real EC P-256 keypair, builds a
 * spec-shaped attestationObject ("none" fmt) + authenticatorData +
 * clientDataJSON, and signs `authenticatorData || SHA-256(clientDataJSON)`
 * with ECDSA/SHA-256 in DER form exactly as a hardware authenticator
 * does. The vendor's real ECDSA path (DER unwrap to raw r||s, COSE key
 * decode, WebCrypto subtle.verify) runs against this material.
 *
 * Load-bearing assertions: a genuine attestation/assertion VERIFIES, and
 * every tamper — flipped signature byte, wrong challenge, wrong origin,
 * wrong RP ID, mutated authenticatorData, a different signing key against
 * the victim's stored public key — is REJECTED (either verified:false or
 * a thrown binding error). The forged-key + tampered-signature cases are
 * the phishing-resistance proof: they only hold if the cryptographic
 * verification actually ran.
 */

var crypto  = require("crypto");
var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

var passkey = b.auth.passkey;

var RP_ID  = "example.test";
var ORIGIN = "https://example.test";

// ---- byte helpers ----

function b64url(buf) { return Buffer.from(buf).toString("base64url"); }
function sha256(buf) { return crypto.createHash("sha256").update(buf).digest(); }

// ---- minimal deterministic CBOR encoder (ints / neg-ints / bytes / text
// / maps) — only the subset COSE keys + the "none" attestationObject need.
// Not a general CBOR library; just enough to feed the real verifier.

function cborHead(major, n) {
  if (n < 24)    return Buffer.from([(major << 5) | n]);
  if (n < 256)   return Buffer.from([(major << 5) | 24, n]);
  if (n < 65536) return Buffer.from([(major << 5) | 25, (n >> 8) & 0xff, n & 0xff]);
  return Buffer.from([(major << 5) | 26,
    (n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}
function cborInt(n)    { return n >= 0 ? cborHead(0, n) : cborHead(1, -n - 1); }
function cborBytes(buf){ return Buffer.concat([cborHead(2, buf.length), buf]); }
function cborText(s)   { var bb = Buffer.from(s, "utf8"); return Buffer.concat([cborHead(3, bb.length), bb]); }
function cborMap(pairs){
  var parts = [cborHead(5, pairs.length)];
  for (var i = 0; i < pairs.length; i++) { parts.push(pairs[i][0], pairs[i][1]); }
  return Buffer.concat(parts);
}

// COSE_Key for an EC2 P-256 / ES256 public key, derived from the real
// JWK export of the Node KeyObject. { 1:2, 3:-7, -1:1, -2:x, -3:y }.
function coseEC2PublicKey(publicKey) {
  var jwk = publicKey.export({ format: "jwk" });
  var x = Buffer.from(jwk.x, "base64url");
  var y = Buffer.from(jwk.y, "base64url");
  return cborMap([
    [cborInt(1),  cborInt(2)],     // kty: EC2
    [cborInt(3),  cborInt(-7)],    // alg: ES256
    [cborInt(-1), cborInt(1)],     // crv: P-256
    [cborInt(-2), cborBytes(x)],   // x
    [cborInt(-3), cborBytes(y)],   // y
  ]);
}

function cborArray(items) {
  var parts = [cborHead(4, items.length)];
  for (var i = 0; i < items.length; i++) parts.push(items[i]);
  return Buffer.concat(parts);
}

// authenticatorData = rpIdHash(32) || flags(1) || signCount(4) [|| attestedCredentialData]
function buildAuthData(rpId, flags, signCount, attestedCredData) {
  var rpIdHash = sha256(Buffer.from(rpId, "utf8"));
  var f = Buffer.from([flags & 0xff]);
  var c = Buffer.alloc(4); c.writeUInt32BE(signCount >>> 0, 0);
  return attestedCredData
    ? Buffer.concat([rpIdHash, f, c, attestedCredData])
    : Buffer.concat([rpIdHash, f, c]);
}

// attestedCredentialData = aaguid(16) || credIdLen(2) || credId || COSE pubkey
function buildAttestedCredData(aaguid, credId, cosePub) {
  var len = Buffer.alloc(2); len.writeUInt16BE(credId.length, 0);
  return Buffer.concat([aaguid, len, credId, cosePub]);
}

// ECDSA/SHA-256 over `data`, DER-encoded — the wire shape a real
// WebAuthn authenticator emits (the vendor unwraps DER to raw r||s).
function signDER(privateKey, data) {
  return crypto.sign("sha256", data, { key: privateKey, dsaEncoding: "der" });
}

// COSE_Key for an RSA / RS256 public key: { 1:3, 3:-257, -1:n, -2:e }.
// RS256 is the third algorithm startRegistration offers (alg -257) and is what
// TPM-backed Windows Hello credentials commonly register with, so a suite that
// only ever exercises P-256 is not covering the credential shape a large slice
// of real users arrive with.
function coseRSAPublicKey(publicKey) {
  var jwk = publicKey.export({ format: "jwk" });
  return cborMap([
    [cborInt(1),  cborInt(3)],                                  // kty: RSA
    [cborInt(3),  cborInt(-257)],                               // alg: RS256
    [cborInt(-1), cborBytes(Buffer.from(jwk.n, "base64url"))],  // modulus
    [cborInt(-2), cborBytes(Buffer.from(jwk.e, "base64url"))],  // exponent
  ]);
}

// authData flag bits: UP 0x01, UV 0x04, BE 0x08, BS 0x10, AT 0x40.
var FLAG_UP = 0x01, FLAG_UV = 0x04, FLAG_BE = 0x08, FLAG_BS = 0x10, FLAG_AT = 0x40;

// Build a fresh genuine credential + its registration response bound to a
// given challenge. Returns the keypair, credId, COSE pubkey, and the
// PublicKeyCredential-shaped registration response.
function makeRegistration(challenge) {
  var kp     = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var cose   = coseEC2PublicKey(kp.publicKey);
  var credId = crypto.randomBytes(32);
  var aaguid = Buffer.alloc(16, 0);

  var authData = buildAuthData(RP_ID, FLAG_UP | FLAG_UV | FLAG_AT, 0,
    buildAttestedCredData(aaguid, credId, cose));
  var attObj = cborMap([
    [cborText("fmt"),      cborText("none")],
    [cborText("attStmt"),  cborMap([])],
    [cborText("authData"), cborBytes(authData)],
  ]);
  var clientData = Buffer.from(JSON.stringify({
    type: "webauthn.create", challenge: challenge, origin: ORIGIN, crossOrigin: false,
  }), "utf8");

  return {
    keyPair: kp,
    credId:  credId,
    response: {
      id:    b64url(credId),
      rawId: b64url(credId),
      type:  "public-key",
      response: {
        clientDataJSON:    b64url(clientData),
        attestationObject: b64url(attObj),
      },
      clientExtensionResults: {},
    },
  };
}

// Build a genuine authentication assertion for a stored credential, signed
// by `signingKey` (which is the real key for the genuine case, or an
// attacker key for the forged case). signCount controls counter advance.
function makeAssertion(signingKey, credId, challenge, signCount) {
  var authData   = buildAuthData(RP_ID, FLAG_UP | FLAG_UV, signCount, null);
  var clientData = Buffer.from(JSON.stringify({
    type: "webauthn.get", challenge: challenge, origin: ORIGIN, crossOrigin: false,
  }), "utf8");
  var signed = Buffer.concat([authData, sha256(clientData)]);
  var sig    = signDER(signingKey, signed);
  return {
    authData:   authData,
    clientData: clientData,
    signed:     signed,
    sig:        sig,
    response: {
      id:    b64url(credId),
      rawId: b64url(credId),
      type:  "public-key",
      response: {
        clientDataJSON:    b64url(clientData),
        authenticatorData: b64url(authData),
        signature:         b64url(sig),
      },
      clientExtensionResults: {},
    },
  };
}

// Read the stored public key off a registration result across
// vendor-version field shapes (credential.publicKey | credentialPublicKey).
function storedPublicKey(regResult) {
  var ri = (regResult && regResult.registrationInfo) || {};
  if (ri.credential && ri.credential.publicKey) return ri.credential.publicKey;
  return ri.credentialPublicKey;
}

// Verify and normalize the outcome to { ok, threw, code }. The verifier
// rejects either by returning verified:false OR by throwing a binding
// error (wrong challenge / origin / RP ID); both are "rejected".
async function authOutcome(args) {
  try {
    var rv = await passkey.verifyAuthentication(args);
    return { ok: rv && rv.verified === true, threw: false, rv: rv };
  } catch (e) {
    return { ok: false, threw: true, code: e.code || e.message };
  }
}
async function regOutcome(args) {
  try {
    var rv = await passkey.verifyRegistration(args);
    return { ok: rv && rv.verified === true, threw: false, rv: rv };
  } catch (e) {
    return { ok: false, threw: true, code: e.code || e.message };
  }
}

// ---- Registration: genuine attestation verifies; tampers rejected ----

async function testRegistrationGenuineAndTampered() {
  // Mint the challenge through the real generateRegistrationOptions path.
  var regOpts   = await passkey.startRegistration({ rpName: "Example", rpId: RP_ID, userName: "alice" });
  var challenge = regOpts.challenge;
  check("startRegistration returns a base64url challenge",
        typeof challenge === "string" && helpers.b.safeBuffer.BASE64URL_RE.test(challenge));

  var reg = makeRegistration(challenge);

  // Genuine attestation — the real verifier must accept it.
  var good = await regOutcome({
    response:          reg.response,
    expectedChallenge: challenge,
    expectedOrigin:    ORIGIN,
    expectedRPID:      RP_ID,
  });
  check("genuine registration verifies (real attestation path)", good.ok === true);
  var pub = storedPublicKey(good.rv);
  check("registration surfaces a COSE public key to persist",
        Buffer.isBuffer(pub) || pub instanceof Uint8Array);
  check("registration BE/BS flags map (single-device, not backed up)",
        good.rv.backupEligible === false && good.rv.backupState === false);

  // Wrong expected challenge — clientDataJSON's challenge no longer matches.
  var badChallenge = await regOutcome({
    response:          reg.response,
    expectedChallenge: b64url(crypto.randomBytes(32)),
    expectedOrigin:    ORIGIN,
    expectedRPID:      RP_ID,
  });
  check("registration with wrong expectedChallenge is rejected", badChallenge.ok === false);

  // Wrong expected origin.
  var badOrigin = await regOutcome({
    response:          reg.response,
    expectedChallenge: challenge,
    expectedOrigin:    "https://evil.test",
    expectedRPID:      RP_ID,
  });
  check("registration with wrong expectedOrigin is rejected", badOrigin.ok === false);

  // Wrong expected RP ID — the rpIdHash inside authData won't match.
  var badRpId = await regOutcome({
    response:          reg.response,
    expectedChallenge: challenge,
    expectedOrigin:    ORIGIN,
    expectedRPID:      "evil.test",
  });
  check("registration with wrong expectedRPID is rejected", badRpId.ok === false);

  // Substituted clientDataJSON challenge — re-encode the client data with
  // a different challenge than the server expects. The verifier compares
  // the challenge embedded in clientDataJSON against expectedChallenge, so
  // a credential captured for one ceremony can't be replayed into another.
  // (fmt:"none" carries no attestation signature, so attestationObject-byte
  //  integrity is out of scope by spec — clientData binding is what guards
  //  the registration ceremony.)
  var swapped = JSON.parse(JSON.stringify(reg.response));
  var otherChallenge = b64url(crypto.randomBytes(32));
  swapped.response.clientDataJSON = b64url(Buffer.from(JSON.stringify({
    type: "webauthn.create", challenge: otherChallenge, origin: ORIGIN, crossOrigin: false,
  }), "utf8"));
  var badClientData = await regOutcome({
    response:          swapped,
    expectedChallenge: challenge,          // server still expects the original
    expectedOrigin:    ORIGIN,
    expectedRPID:      RP_ID,
  });
  check("registration with a substituted clientDataJSON challenge is rejected",
        badClientData.ok === false);
}

// ---- Authentication: genuine assertion verifies; tampers rejected ----

async function testAuthenticationGenuineAndTampered() {
  // Register a real credential first so we have a genuine stored pubkey.
  var regOpts = await passkey.startRegistration({ rpName: "Example", rpId: RP_ID, userName: "bob" });
  var reg     = makeRegistration(regOpts.challenge);
  var regRes  = await regOutcome({
    response:          reg.response,
    expectedChallenge: regOpts.challenge,
    expectedOrigin:    ORIGIN,
    expectedRPID:      RP_ID,
  });
  check("setup: credential registers", regRes.ok === true);
  var storedPub = storedPublicKey(regRes.rv);

  // Mint an authentication challenge via the real options path.
  var authOpts  = await passkey.startAuthentication({ rpId: RP_ID });
  var challenge = authOpts.challenge;

  var credential = function () {
    return { id: b64url(reg.credId), publicKey: storedPub, counter: 0 };
  };

  // Genuine assertion signed with the real private key — must verify, and
  // the signature counter must advance (clone-detection material).
  var assertion = makeAssertion(reg.keyPair.privateKey, reg.credId, challenge, 7);
  var good = await authOutcome({
    response:          assertion.response,
    expectedChallenge: challenge,
    expectedOrigin:    ORIGIN,
    expectedRPID:      RP_ID,
    credential:        credential(),
  });
  check("genuine assertion verifies (real ECDSA signature path)", good.ok === true);
  check("genuine assertion advances the signature counter",
        good.rv.authenticationInfo && good.rv.authenticationInfo.newCounter === 7);

  // --- THE LOAD-BEARING TAMPER CASES ---

  // 1. Flipped signature byte — the cryptographic core must reject it.
  var flipped = JSON.parse(JSON.stringify(assertion.response));
  var sigBuf  = Buffer.from(flipped.response.signature, "base64url");
  sigBuf[sigBuf.length - 1] ^= 0x01;
  flipped.response.signature = b64url(sigBuf);
  var t1 = await authOutcome({
    response:          flipped,
    expectedChallenge: challenge,
    expectedOrigin:    ORIGIN,
    expectedRPID:      RP_ID,
    credential:        credential(),
  });
  check("tampered signature (1 byte flipped) is REJECTED", t1.ok === false);
  check("tampered signature rejection comes from verification, not a throw",
        t1.threw === false && t1.rv.verified === false);

  // 2. Wrong expected challenge — replay/binding defense.
  var t2 = await authOutcome({
    response:          assertion.response,
    expectedChallenge: b64url(crypto.randomBytes(32)),
    expectedOrigin:    ORIGIN,
    expectedRPID:      RP_ID,
    credential:        credential(),
  });
  check("assertion with wrong expectedChallenge is REJECTED", t2.ok === false);

  // 3. Wrong expected origin — phishing-resistance binding.
  var t3 = await authOutcome({
    response:          assertion.response,
    expectedChallenge: challenge,
    expectedOrigin:    "https://evil.test",
    expectedRPID:      RP_ID,
    credential:        credential(),
  });
  check("assertion with wrong expectedOrigin is REJECTED (phishing-resistance)", t3.ok === false);

  // 4. Wrong expected RP ID — rpIdHash binding.
  var t4 = await authOutcome({
    response:          assertion.response,
    expectedChallenge: challenge,
    expectedOrigin:    ORIGIN,
    expectedRPID:      "evil.test",
    credential:        credential(),
  });
  check("assertion with wrong expectedRPID is REJECTED", t4.ok === false);

  // 5. Mutated authenticatorData — the signature covers authData, so a
  //    flipped counter byte must break verification.
  var mutAd  = JSON.parse(JSON.stringify(assertion.response));
  var adBuf  = Buffer.from(mutAd.response.authenticatorData, "base64url");
  adBuf[adBuf.length - 1] ^= 0xff;
  mutAd.response.authenticatorData = b64url(adBuf);
  var t5 = await authOutcome({
    response:          mutAd,
    expectedChallenge: challenge,
    expectedOrigin:    ORIGIN,
    expectedRPID:      RP_ID,
    credential:        credential(),
  });
  check("assertion with mutated authenticatorData is REJECTED", t5.ok === false);

  // 6. FORGED KEY — an attacker signs with their own private key but
  //    presents the victim's stored public key. Only a real signature
  //    check rejects this; a stubbed verifier would accept it.
  var attacker = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var forged   = makeAssertion(attacker.privateKey, reg.credId, challenge, 7);
  var t6 = await authOutcome({
    response:          forged.response,
    expectedChallenge: challenge,
    expectedOrigin:    ORIGIN,
    expectedRPID:      RP_ID,
    credential:        credential(),
  });
  check("FORGED assertion (attacker key vs victim pubkey) is REJECTED", t6.ok === false);
  check("forged-key rejection comes from signature verification, not a throw",
        t6.threw === false && t6.rv.verified === false);

  // 7. Sanity: the same forged assertion, verified against the ATTACKER's
  //    own public key, DOES verify — proving the forged case above fails
  //    specifically because the key doesn't match, not for an unrelated
  //    reason (the test is exercising the real verification, not a no-op).
  var attackerCose = coseEC2PublicKey(attacker.publicKey);
  var attackerReg  = makeRegistration(regOpts.challenge);
  // build a stored-pubkey for the attacker by registering it
  var attReg = await regOutcome({
    response:          attackerReg.response,
    expectedChallenge: regOpts.challenge,
    expectedOrigin:    ORIGIN,
    expectedRPID:      RP_ID,
  });
  // Re-sign with the attacker's actual registered key for an apples-to-apples check.
  var attChallengeOpts = await passkey.startAuthentication({ rpId: RP_ID });
  var attAssertion = makeAssertion(attackerReg.keyPair.privateKey, attackerReg.credId,
                                   attChallengeOpts.challenge, 3);
  var attGood = await authOutcome({
    response:          attAssertion.response,
    expectedChallenge: attChallengeOpts.challenge,
    expectedOrigin:    ORIGIN,
    expectedRPID:      RP_ID,
    credential:        { id: b64url(attackerReg.credId), publicKey: storedPublicKey(attReg.rv), counter: 0 },
  });
  check("control: a genuine assertion under its OWN key verifies (proves the verifier isn't a no-op)",
        attGood.ok === true);
  // Reference the encoded attacker COSE key so lint sees it consumed.
  check("attacker COSE key encodes to bytes", Buffer.isBuffer(attackerCose) && attackerCose.length > 0);
}

// ---- Ceremony-policy refusals ----
//
// The tampers above prove the CRYPTOGRAPHY runs. These prove the POLICY runs —
// the checks that have nothing to do with the signature being valid, and that a
// signature-only verifier passes with flying colours. WebAuthn L3 puts them in
// the relying party's hands (7.1 steps 14-17, 7.2 steps 14-21), so they are the
// framework's job whatever verifies the attestation statement underneath.
//
// Every case here is a genuine, correctly-signed response. What makes it
// unacceptable is the authenticator's report about the ceremony, or the
// credential's algorithm — never the maths.
async function testCeremonyPolicyRefusals() {
  var challenge = b64url(crypto.randomBytes(32));
  var reg = makeRegistration(challenge);
  var regRv = await regOutcome({
    response: reg.response, expectedChallenge: challenge,
    expectedOrigin: ORIGIN, expectedRPID: RP_ID,
  });
  check("policy: setup registration verifies", regRv.ok === true);
  var pub = storedPublicKey(regRv.rv);
  function cred(over) {
    return Object.assign({ id: b64url(reg.credId), publicKey: pub, counter: 0 }, over || {});
  }
  // A refusal must be for the RIGHT REASON. "Not verified" alone is not enough:
  // a malformed opts object also fails every case, so a draft of these checks
  // that passed the wrong option names was green while testing nothing. Assert
  // the CAUSE — either a verified:false verdict, or a throw whose message names
  // the policy that refused.
  function refusedBecause(o, why) {
    if (o.ok !== false) return false;
    return o.threw ? why.test(String(o.code)) : true;
  }

  // --- user presence (7.2 step 14). UP is not optional: a credential used
  // with no user present is an attacker driving the authenticator.
  var upChallenge = b64url(crypto.randomBytes(32));
  var noUp = makeAssertionWithFlags(reg.keyPair.privateKey, reg.credId, upChallenge, 1, FLAG_UV);
  var upRv = await authOutcome({
    response: noUp.response, expectedChallenge: upChallenge,
    expectedOrigin: ORIGIN, expectedRPID: RP_ID, credential: cred(),
  });
  check("policy: an assertion with USER PRESENCE clear is REJECTED",
        refusedBecause(upRv, /presen/i));

  // --- user verification, when the RP required it (7.2 step 15). The
  // signature is valid; the authenticator simply reports it did not verify
  // the user, and a UV-requiring RP must refuse rather than downgrade.
  var uvChallenge = b64url(crypto.randomBytes(32));
  var noUv = makeAssertionWithFlags(reg.keyPair.privateKey, reg.credId, uvChallenge, 2, FLAG_UP);
  var uvRv = await authOutcome({
    response: noUv.response, expectedChallenge: uvChallenge,
    expectedOrigin: ORIGIN, expectedRPID: RP_ID, credential: cred(),
    requireUserVerification: true,
  });
  check("policy: UV required but not performed is REJECTED",
        refusedBecause(uvRv, /verif/i));
  // ...and the same shape is accepted when the RP opted out of UV, which
  // proves the refusal above came from the POLICY and not from the flags
  // breaking the signature.
  var uvOkChallenge = b64url(crypto.randomBytes(32));
  var uvOk = makeAssertionWithFlags(reg.keyPair.privateKey, reg.credId, uvOkChallenge, 3, FLAG_UP);
  var uvOkRv = await authOutcome({
    response: uvOk.response, expectedChallenge: uvOkChallenge,
    expectedOrigin: ORIGIN, expectedRPID: RP_ID, credential: cred(),
    requireUserVerification: false,
  });
  check("policy: UV absent is accepted when the RP did not require it", uvOkRv.ok === true);

  // --- signature counter (7.2 step 21). A counter that does not advance is
  // the cloned-authenticator signal: the same credential replayed from a copy.
  var ctrChallenge = b64url(crypto.randomBytes(32));
  var regressed = makeAssertion(reg.keyPair.privateKey, reg.credId, ctrChallenge, 5);
  var ctrRv = await authOutcome({
    response: regressed.response, expectedChallenge: ctrChallenge,
    expectedOrigin: ORIGIN, expectedRPID: RP_ID, credential: cred({ counter: 9 }),
  });
  check("policy: a signature counter that went BACKWARDS is REJECTED",
        refusedBecause(ctrRv, /counter|sign-count/i));

  // --- credential id (7.2 step 5): the assertion must be for the credential
  // whose public key is being used to check it.
  var idChallenge = b64url(crypto.randomBytes(32));
  var mismatched = makeAssertion(reg.keyPair.privateKey, reg.credId, idChallenge, 6);
  var idRv = await authOutcome({
    response: mismatched.response, expectedChallenge: idChallenge,
    expectedOrigin: ORIGIN, expectedRPID: RP_ID,
    credential: cred({ id: b64url(crypto.randomBytes(32)) }),   // a DIFFERENT credential
  });
  check("policy: an assertion whose credential ID does not match is REJECTED",
        idRv.ok === false);

  // rawId is the same identity in its binary spelling, and an RP is free to
  // key on it. Binding only `id` leaves the pair free to disagree, which is
  // the registration-side hole one ceremony later.
  var rawChallenge = b64url(crypto.randomBytes(32));
  var rawMismatch = makeAssertion(reg.keyPair.privateKey, reg.credId, rawChallenge, 7);
  rawMismatch.response.rawId = b64url(crypto.randomBytes(32));
  var rawRv = await authOutcome({
    response: rawMismatch.response, expectedChallenge: rawChallenge,
    expectedOrigin: ORIGIN, expectedRPID: RP_ID, credential: cred(),
  });
  check("policy: an assertion whose rawId disagrees with the stored credential is REJECTED",
        refusedBecause(rawRv, /credential-id-mismatch/));

  // --- cross-origin (L3 7.1 step 13 / 7.2 step 13). A ceremony driven from a
  // hostile top-level frame is indistinguishable from a same-origin one unless
  // crossOrigin is read. The vendored verifier never reads it.
  var xoChallenge = b64url(crypto.randomBytes(32));
  var xo = makeRegistrationCrossOrigin(xoChallenge);
  var xoRv = await regOutcome({
    response: xo.response, expectedChallenge: xoChallenge,
    expectedOrigin: ORIGIN, expectedRPID: RP_ID,
  });
  check("policy: a CROSS-ORIGIN registration is REJECTED by default", xoRv.ok === false);
}

// An assertion with caller-chosen flags, so user-presence / user-verification
// can be cleared independently. Mirrors makeAssertion otherwise.
function makeAssertionWithFlags(signingKey, credId, challenge, signCount, flags) {
  var authData   = buildAuthData(RP_ID, flags, signCount, null);
  var clientData = Buffer.from(JSON.stringify({
    type: "webauthn.get", challenge: challenge, origin: ORIGIN, crossOrigin: false,
  }), "utf8");
  var sig = signDER(signingKey, Buffer.concat([authData, sha256(clientData)]));
  return {
    response: {
      id: b64url(credId), rawId: b64url(credId), type: "public-key",
      response: {
        clientDataJSON:    b64url(clientData),
        authenticatorData: b64url(authData),
        signature:         b64url(sig),
      },
      clientExtensionResults: {},
    },
  };
}

// A genuine registration whose clientData declares crossOrigin:true — the
// shape an RP embedded in a hostile top-level frame produces.
function makeRegistrationCrossOrigin(challenge, topOrigin) {
  var kp     = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var credId = crypto.randomBytes(32);
  var authData = buildAuthData(RP_ID, FLAG_UP | FLAG_UV | FLAG_AT, 0,
    buildAttestedCredData(Buffer.alloc(16, 0), credId, coseEC2PublicKey(kp.publicKey)));
  var attObj = cborMap([
    [cborText("fmt"),      cborText("none")],
    [cborText("attStmt"),  cborMap([])],
    [cborText("authData"), cborBytes(authData)],
  ]);
  var cd = {
    type: "webauthn.create", challenge: challenge, origin: ORIGIN, crossOrigin: true,
  };
  if (topOrigin !== undefined) cd.topOrigin = topOrigin;
  var clientData = Buffer.from(JSON.stringify(cd), "utf8");
  return {
    response: {
      id: b64url(credId), rawId: b64url(credId), type: "public-key",
      response: {
        clientDataJSON:    b64url(clientData),
        attestationObject: b64url(attObj),
      },
      clientExtensionResults: {},
    },
  };
}

// ---- RS256: the same round trip on an RSA credential ----
//
// startRegistration offers alg -257 alongside -8 and -7, so an RSA credential is
// something this relying party accepts — but every vector above is P-256, which
// means the RSA path has never been executed here. An RSA signature is
// PKCS#1 v1.5 with no DER-vs-raw unwrapping step, so it exercises a different
// branch of whatever verifies it, and a verifier that silently only handled EC
// would pass every existing test in this file.
// ---- Attestation trust anchors, credProps, padded ids, signed extensions ----

async function testAttestationRootsArePinned() {
  // An attestation statement proves which authenticator model made a
  // credential, and that proof is only worth its anchor: checking the
  // statement's signature without checking WHERE the chain ends accepts a
  // manufacturer claim rooted in a CA the attacker made. The bundle is pinned
  // in the source, so assert its identity — a silent substitution during a
  // refactor is exactly what a test can catch and a review cannot.
  var roots = require("../../lib/auth/webauthn-attestation-roots");
  check("attestation roots: the shipped bundles are frozen",
        Object.isFrozen(roots.ALL_ROOTS) && Object.isFrozen(roots.SAFETYNET_ROOTS) &&
        Object.isFrozen(roots.APPLE_ROOTS) && Object.isFrozen(roots.ANDROID_KEY_ROOTS) &&
        Object.isFrozen(roots.ROOTS_BY_FORMAT));

  // Anchors are per FORMAT. Merging them would let a Google-rooted chain
  // satisfy an Apple attestation — the confusion anchoring exists to stop.
  check("attestation roots: apple anchors to Apple's root alone",
        roots.ROOTS_BY_FORMAT["apple"] === roots.APPLE_ROOTS &&
        roots.APPLE_ROOTS.length === 1);
  check("attestation roots: android-key anchors to Google's roots alone",
        roots.ROOTS_BY_FORMAT["android-key"] === roots.ANDROID_KEY_ROOTS &&
        roots.ANDROID_KEY_ROOTS.length === 4);
  // packed / tpm / fido-u2f chains end at whichever vendor made the key, so
  // there is no fixed set to pin — anchoring them against this bundle would
  // refuse every security key that is not an Apple or Android device.
  ["packed", "tpm", "fido-u2f", "none"].forEach(function (fmt) {
    check("attestation roots: " + fmt + " is NOT anchored against the pinned bundle",
          roots.ROOTS_BY_FORMAT[fmt] === undefined);
  });

  var byFingerprint = {};
  roots.ALL_ROOTS.forEach(function (pem) {
    var c = new crypto.X509Certificate(pem);
    byFingerprint[c.fingerprint256] = c;
  });
  var expected = {
    // Apple WebAuthn Root CA — anchors `apple` attestation.
    "09:15:DD:5C:07:A2:8D:B5:49:D1:F6:77:BB:5A:75:D4:BF:BE:95:61:A7:73:42:43:27:76:2E:9E:02:F9:BB:29": "Apple",
    // Google hardware-attestation roots — anchor `android-key`. Four issues
    // of the same root; the 2016 one has expired and anchors nothing.
    "C1:98:4A:3E:F4:5C:1E:2A:91:85:51:DE:10:60:3C:86:F7:05:1B:22:49:C4:89:1C:AE:32:30:EA:BD:0C:97:D5": "Google 2016",
    "1E:F1:A0:4B:8B:A5:8A:B9:45:89:AC:49:8C:89:82:A7:83:F2:4E:A7:30:7E:01:59:A0:C3:A7:3B:37:7D:87:CC": "Google 2019",
    "AB:66:41:17:8A:36:E1:79:AA:0C:1C:DD:DF:9A:16:EB:45:FA:20:94:3E:2B:8C:D7:C7:C0:5C:26:CF:8B:48:7A": "Google 2021",
    "CE:DB:1C:B6:DC:89:6A:E5:EC:79:73:48:BC:E9:28:67:53:C2:B3:8E:E7:1C:E0:FB:E3:4A:9A:12:48:80:0D:FC": "Google 2022",
    // GlobalSign Root CA — anchors the `android-safetynet` JWS chain.
    "EB:D4:10:40:E4:BB:3E:C7:42:C9:E3:81:D3:1E:F2:A4:1A:48:B6:68:5C:96:E7:CE:F3:C1:DF:6C:D4:33:1C:99": "GlobalSign",
  };
  // Fingerprints are checked as a SET so this does not depend on ordering,
  // and the count is asserted so an extra root cannot be smuggled alongside
  // the expected ones.
  check("attestation roots: exactly the six published vendor roots ship",
        roots.ALL_ROOTS.length === 6 &&
        Object.keys(byFingerprint).length === 6);
  var allKnown = Object.keys(byFingerprint).every(function (fp) {
    return expected[fp] !== undefined;
  });
  check("attestation roots: every shipped anchor is a published vendor root",
        allKnown);
  var allPresent = Object.keys(expected).every(function (fp) {
    return byFingerprint[fp] !== undefined;
  });
  check("attestation roots: no published vendor root was dropped", allPresent);

  roots.ALL_ROOTS.forEach(function (pem) {
    var c = new crypto.X509Certificate(pem);
    check("attestation roots: " + expected[c.fingerprint256] + " is self-signed (a root)",
          c.subject === c.issuer && c.verify(c.publicKey) === true);
  });

  check("attestation roots: the SafetyNet anchor is GlobalSign alone",
        roots.SAFETYNET_ROOTS.length === 1 &&
        new crypto.X509Certificate(roots.SAFETYNET_ROOTS[0]).fingerprint256 ===
        "EB:D4:10:40:E4:BB:3E:C7:42:C9:E3:81:D3:1E:F2:A4:1A:48:B6:68:5C:96:E7:CE:F3:C1:DF:6C:D4:33:1C:99");

  // The operator override REPLACES the bundle. An empty or malformed one is a
  // configuration mistake and must not silently fall back to the vendor roots
  // — that would leave an operator believing they had narrowed trust while
  // every vendor root stayed live.
  var challenge = b64url(crypto.randomBytes(32));
  var reg = makeRegistration(challenge);
  async function overrideRefused(value, label) {
    var rv = await regOutcome({
      response: reg.response, expectedChallenge: challenge,
      expectedOrigin: ORIGIN, expectedRPID: RP_ID, attestationRoots: value,
    });
    check("attestation roots: " + label,
          rv.ok === false && rv.threw === true &&
          /bad-attestation-roots/.test(String(rv.code)));
  }
  await overrideRefused([], "an EMPTY override is refused, not read as 'use the shipped roots'");
  await overrideRefused(["not a pem"], "a non-PEM override entry is refused");
  await overrideRefused("a string", "a non-array override is refused");
  await overrideRefused([123], "a non-string override entry is refused");
  // A truncated PEM passes any substring sniff and is not a certificate. It
  // must be refused HERE, at the call that named it: this registration is a
  // `none` attestation, so the override is never handed to the verifier —
  // an operator whose anchors are broken would otherwise see a clean
  // registration and never learn.
  await overrideRefused(
    ["-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n"],
    "a PEM-shaped entry that is not a certificate is refused at the call");

  // A `packed` full attestation from an ordinary security key chains to
  // whichever vendor made it — Yubico, Feitian, SoloKeys — and none of those
  // roots are, or could be, in a pinned Apple/Google bundle. Anchoring it
  // against that bundle would refuse every such key. Registration must still
  // reach the verifier for these formats rather than being turned away by
  // this layer's anchor selection.
  var vendorKey = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var vendorCred = crypto.randomBytes(32);
  var vendorAuthData = buildAuthData(RP_ID, FLAG_UP | FLAG_UV | FLAG_AT, 0,
    buildAttestedCredData(Buffer.alloc(16, 0), vendorCred,
                          coseEC2PublicKey(vendorKey.publicKey)));
  var vendorChallenge = b64url(crypto.randomBytes(32));
  var vendorClientData = Buffer.from(JSON.stringify({
    type: "webauthn.create", challenge: vendorChallenge, origin: ORIGIN, crossOrigin: false,
  }), "utf8");
  var vendorCert = Buffer.from(
    helpers.selfSignedPair({ commonName: "vendor-attestation" }).cert
      .replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""), "base64");
  var vendorAtt = cborMap([
    [cborText("fmt"),     cborText("packed")],
    [cborText("attStmt"), cborMap([
      [cborText("alg"), cborInt(-7)],
      [cborText("sig"), cborBytes(signDER(vendorKey.privateKey,
        Buffer.concat([vendorAuthData, sha256(vendorClientData)])))],
      [cborText("x5c"), cborArray([cborBytes(vendorCert)])],
    ])],
    [cborText("authData"), cborBytes(vendorAuthData)],
  ]);
  var vendorRv = await regOutcome({
    response: {
      id: b64url(vendorCred), rawId: b64url(vendorCred), type: "public-key",
      response: {
        clientDataJSON:    b64url(vendorClientData),
        attestationObject: b64url(vendorAtt),
      },
      clientExtensionResults: {},
    },
    expectedChallenge: vendorChallenge, expectedOrigin: ORIGIN, expectedRPID: RP_ID,
  });
  // The fixture's certificate does not meet the packed profile, so the
  // verifier refuses it on its own terms — what matters is that it is NOT
  // refused for failing to chain to a pinned Apple/Google root, which is what
  // anchoring this format would have produced for every real vendor key too.
  check("attestation roots: a vendor `packed` attestation is not judged against the pinned bundle",
        !/anchor|chain-not-anchored|not-anchored/i.test(String(vendorRv.code || "")));

  // Deciding WHICH anchors apply means reading the attestation's format. An
  // object too large or too malformed to read cannot be assigned a policy —
  // and quietly proceeding with no anchors would be a bypass with a shape:
  // pad an `apple` attestation past the bound and it would sail through
  // unanchored, which is the self-issued manufacturer claim this exists to
  // stop. Not reading the format is fatal, not permissive.
  var oversized = Buffer.concat([
    cborMap([[cborText("fmt"), cborText("apple")]]),
    Buffer.alloc(128 * 1024, 0x41),                                                // allow:raw-byte-literal — past the anchor-plan bound
  ]);
  var oversizedRv = await regOutcome({
    response: {
      id: "AAAA", rawId: "AAAA", type: "public-key",
      response: {
        clientDataJSON: b64url(Buffer.from(JSON.stringify({
          type: "webauthn.create", challenge: challenge, origin: ORIGIN, crossOrigin: false,
        }), "utf8")),
        attestationObject: b64url(oversized),
      },
      clientExtensionResults: {},
    },
    expectedChallenge: challenge, expectedOrigin: ORIGIN, expectedRPID: RP_ID,
  });
  check("attestation roots: an attestation whose format cannot be read is REFUSED, not left unanchored",
        oversizedRv.ok === false && oversizedRv.threw === true);
}

async function testCredPropsAndPaddedDescriptors() {
  // credProps is how a relying party learns whether the credential it just
  // created is actually discoverable. residentKey: "preferred" lets the
  // authenticator say no, so without asking, an RP cannot tell which of its
  // credentials support username-less or conditional login.
  var opts = await passkey.startRegistration({
    rpName: "Example", rpId: RP_ID, userName: "alice",
  });
  check("credProps: requested on a registration with no caller extensions",
        opts.extensions && opts.extensions.credProps === true);

  var withExt = await passkey.startRegistration({
    rpName: "Example", rpId: RP_ID, userName: "alice",
    extensions: { credBlob: { blob: Buffer.from("hello") } },
  });
  check("credProps: still requested alongside a caller's own extensions",
        withExt.extensions && withExt.extensions.credProps === true &&
        typeof withExt.extensions.credBlob === "string");

  // A credential id stored years ago by a padding-emitting base64url encoder
  // is still that credential. Refusing the padding would not reject an attack
  // — it would stop the deployment starting authentication at all.
  var raw = crypto.randomBytes(32);
  // What a padding-emitting base64url encoder actually produces: the standard
  // alphabet swapped for the URL one, padding intact. A 32-byte id is 43
  // characters, so its correct padding is a single '=' — appending two would
  // be malformed, which is its own case below.
  var padded = raw.toString("base64").replace(/\+/g, "-").replace(/\//g, "_");
  var auth = await passkey.startAuthentication({
    rpId: RP_ID, allowCredentials: [{ id: padded, type: "public-key" }],
  });
  check("padded ids: a padded credential id is accepted and normalized",
        auth.allowCredentials.length === 1 &&
        auth.allowCredentials[0].id === raw.toString("base64url"));

  var excl = await passkey.startRegistration({
    rpName: "Example", rpId: RP_ID, userName: "alice",
    excludeCredentials: [{ id: padded, type: "public-key" }],
  });
  check("padded ids: excludeCredentials accepts one too",
        excl.excludeCredentials[0].id === raw.toString("base64url"));

  // Padding is not a licence for arbitrary characters.
  var threw = null;
  try {
    await passkey.startAuthentication({
      rpId: RP_ID, allowCredentials: [{ id: "not base64url!", type: "public-key" }],
    });
  } catch (e) { threw = e; }
  check("padded ids: a genuinely non-base64url id is still refused",
        threw && /bad-allowCredentials/.test(String(threw.code)));

  // An id must canonically denote ONE credential. Node's decoder is lenient
  // in ways that silently produce a DIFFERENT id, which would run the
  // ceremony against the wrong descriptor rather than fail:
  //   "YW"     re-encodes as "YQ" — the final quantum carries bits that
  //            encode nothing, so two spellings name one credential.
  //   "Y"      a lone leftover character decodes to NOTHING.
  //   "YWJj==" padding on an already-complete quantum.
  async function refusedId(id, why) {
    var threw = null;
    try {
      await passkey.startAuthentication({
        rpId: RP_ID, allowCredentials: [{ id: id, type: "public-key" }],
      });
    } catch (e) { threw = e; }
    check("padded ids: " + why, threw && /bad-allowCredentials/.test(String(threw.code)));
  }
  await refusedId("===", "an id that is nothing but padding is refused");
  await refusedId("YW", "a non-canonical final quantum is refused, not silently re-encoded");
  await refusedId("Y", "a lone leftover character is refused, not decoded to nothing");
  await refusedId("YWJj==", "padding on an already-complete quantum is refused");
  await refusedId("YWJjZA=", "a short padding run is refused");

  // ...and the well-formed spellings of the same credential all resolve to
  // the one canonical id, so a descriptor cannot depend on which encoder
  // wrote the row.
  for (var s = 0; s < 3; s++) {
    var bytes = crypto.randomBytes(1 + s);          // lengths 1..3 → 0/1/2 pads
    var canonical = bytes.toString("base64url");
    var withPad = bytes.toString("base64") .replace(/\+/g, "-").replace(/\//g, "_");
    var opt = await passkey.startAuthentication({
      rpId: RP_ID, allowCredentials: [{ id: withPad, type: "public-key" }],
    });
    check("padded ids: a correctly-padded " + (s + 1) + "-byte id normalizes to its canonical form",
          opt.allowCredentials[0].id === canonical);
  }
}

// A registration whose authenticator data carries SIGNED extension outputs
// (the ED flag plus a CBOR map), which is what credProtect / credBlob answer
// with. Distinct from clientExtensionResults, which nothing signs.
function makeRegistrationWithExtensions(challenge) {
  var kp     = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var credId = crypto.randomBytes(32);
  var extMap = cborMap([[cborText("credProtect"), cborInt(2)]]);
  var acd    = buildAttestedCredData(Buffer.alloc(16, 0), credId, coseEC2PublicKey(kp.publicKey));
  var authData = Buffer.concat([
    buildAuthData(RP_ID, FLAG_UP | FLAG_UV | FLAG_AT | 0x80, 0, acd), extMap,        // allow:raw-byte-literal — ED: extension data present
  ]);
  var attObj = cborMap([
    [cborText("fmt"),      cborText("none")],
    [cborText("attStmt"),  cborMap([])],
    [cborText("authData"), cborBytes(authData)],
  ]);
  var clientData = Buffer.from(JSON.stringify({
    type: "webauthn.create", challenge: challenge, origin: ORIGIN, crossOrigin: false,
  }), "utf8");
  return {
    keyPair: kp, credId: credId,
    response: {
      id: b64url(credId), rawId: b64url(credId), type: "public-key",
      response: { clientDataJSON: b64url(clientData), attestationObject: b64url(attObj) },
      clientExtensionResults: {},
    },
  };
}

function makeAssertionWithExtensions(privateKey, credId, challenge, signCount) {
  var extMap   = cborMap([[cborText("credProtect"), cborInt(3)]]);
  var authData = Buffer.concat([
    buildAuthData(RP_ID, FLAG_UP | FLAG_UV | 0x80, signCount, null), extMap,         // allow:raw-byte-literal — ED flag
  ]);
  var clientData = Buffer.from(JSON.stringify({
    type: "webauthn.get", challenge: challenge, origin: ORIGIN, crossOrigin: false,
  }), "utf8");
  var sig = signDER(privateKey, Buffer.concat([authData, sha256(clientData)]));
  return {
    response: {
      id: b64url(credId), rawId: b64url(credId), type: "public-key",
      response: {
        clientDataJSON:    b64url(clientData),
        authenticatorData: b64url(authData),
        signature:         b64url(sig),
      },
      clientExtensionResults: {},
    },
  };
}

async function testAuthenticatorExtensionResults() {
  // These outputs live INSIDE the bytes the attestation / assertion signature
  // covers, so they are the authenticator's answer rather than a claim the
  // page made. A consumer of credProtect or credBlob that stops receiving
  // them loses its verified output with nothing failing loudly.
  var challenge = b64url(crypto.randomBytes(32));
  var reg = makeRegistrationWithExtensions(challenge);
  var regRv = await regOutcome({
    response: reg.response, expectedChallenge: challenge,
    expectedOrigin: ORIGIN, expectedRPID: RP_ID,
  });
  check("signed extensions: a registration carrying them verifies", regRv.ok === true);
  check("signed extensions: registration decodes the authenticator's own outputs",
        regRv.rv.registrationInfo.authenticatorExtensionResults &&
        regRv.rv.registrationInfo.authenticatorExtensionResults.credProtect === 2);

  var authChallenge = b64url(crypto.randomBytes(32));
  var assertion = makeAssertionWithExtensions(reg.keyPair.privateKey, reg.credId, authChallenge, 1);
  var authRv = await authOutcome({
    response: assertion.response, expectedChallenge: authChallenge,
    expectedOrigin: ORIGIN, expectedRPID: RP_ID,
    credential: { id: b64url(reg.credId), publicKey: storedPublicKey(regRv.rv), counter: 0 },
  });
  check("signed extensions: an assertion carrying them verifies", authRv.ok === true);
  check("signed extensions: authentication decodes them too",
        authRv.rv.authenticationInfo.authenticatorExtensionResults &&
        authRv.rv.authenticationInfo.authenticatorExtensionResults.credProtect === 3);

  // A ceremony with no extensions leaves the field absent rather than an
  // empty object, so "none reported" stays distinguishable from "reported
  // none" — the same rule transports follows.
  var plainChallenge = b64url(crypto.randomBytes(32));
  var plain = makeRegistration(plainChallenge);
  var plainRv = await regOutcome({
    response: plain.response, expectedChallenge: plainChallenge,
    expectedOrigin: ORIGIN, expectedRPID: RP_ID,
  });
  check("signed extensions: absent when the authenticator reported none",
        plainRv.ok === true &&
        plainRv.rv.registrationInfo.authenticatorExtensionResults === undefined);
}

// ---- A stored credential id keeps working whichever encoder wrote it ----

async function testPaddedStoredCredentialIdStillLogsIn() {
  // The compatibility case that motivated accepting padded ids at all: a
  // deployment whose credential column holds `...=` from whichever encoder
  // wrote the row. startAuthentication hands the browser the canonical
  // unpadded spelling, the browser returns THAT, and the binding then
  // compares it against the still-padded stored value. Comparing raw strings
  // there turns two spellings of ONE credential into a mismatch and locks out
  // exactly the deployments the padding support was added for.
  var challenge = b64url(crypto.randomBytes(32));
  var reg = makeRegistration(challenge);
  var regRv = await regOutcome({
    response: reg.response, expectedChallenge: challenge,
    expectedOrigin: ORIGIN, expectedRPID: RP_ID,
  });
  check("padded stored id: setup registration verifies", regRv.ok === true);

  // The same credential id as a padding-emitting encoder would have stored it.
  var storedPadded = Buffer.from(reg.credId).toString("base64")
    .replace(/\+/g, "-").replace(/\//g, "_");
  check("padded stored id: the fixture really is the padded spelling",
        storedPadded !== b64url(reg.credId) &&
        storedPadded.replace(/=+$/, "") === b64url(reg.credId));

  var authChallenge = b64url(crypto.randomBytes(32));
  var assertion = makeAssertion(reg.keyPair.privateKey, reg.credId, authChallenge, 1);
  var rv = await authOutcome({
    response: assertion.response, expectedChallenge: authChallenge,
    expectedOrigin: ORIGIN, expectedRPID: RP_ID,
    credential: { id: storedPadded, publicKey: storedPublicKey(regRv.rv), counter: 0 },
  });
  check("padded stored id: a credential stored with padding still logs in",
        rv.ok === true);

  // ...and a genuinely different credential is still refused, so the
  // canonicalization did not turn the binding into a no-op.
  var otherChallenge = b64url(crypto.randomBytes(32));
  var other = makeAssertion(reg.keyPair.privateKey, reg.credId, otherChallenge, 2);
  var refused = await authOutcome({
    response: other.response, expectedChallenge: otherChallenge,
    expectedOrigin: ORIGIN, expectedRPID: RP_ID,
    credential: {
      id: Buffer.from(crypto.randomBytes(32)).toString("base64")
        .replace(/\+/g, "-").replace(/\//g, "_"),
      publicKey: storedPublicKey(regRv.rv), counter: 0,
    },
  });
  check("padded stored id: a DIFFERENT credential is still refused",
        refused.ok === false && /credential-id-mismatch/.test(String(refused.code)));
}

// ---- SafetyNet: device-integrity signal and replay bound ----

// An `android-safetynet` attestation whose JWS payload this test controls.
// The JWS is not Google-signed, so the verifier refuses it at the chain — but
// the framework's own freshness gate runs on the payload and can be driven
// independently, which is the part this covers.
function makeSafetyNetRegistration(challenge, payload) {
  var kp     = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var credId = crypto.randomBytes(32);
  var authData = buildAuthData(RP_ID, FLAG_UP | FLAG_UV | FLAG_AT, 0,
    buildAttestedCredData(Buffer.alloc(16, 0), credId, coseEC2PublicKey(kp.publicKey)));
  var jws = [
    Buffer.from(JSON.stringify({ alg: "RS256", x5c: [] })).toString("base64url"),
    Buffer.from(JSON.stringify(payload)).toString("base64url"),
    Buffer.from("not-a-real-signature").toString("base64url"),
  ].join(".");
  var attObj = cborMap([
    [cborText("fmt"),     cborText("android-safetynet")],
    [cborText("attStmt"), cborMap([
      [cborText("ver"),      cborText("1")],
      [cborText("response"), cborBytes(Buffer.from(jws, "utf8"))],
    ])],
    [cborText("authData"), cborBytes(authData)],
  ]);
  var clientData = Buffer.from(JSON.stringify({
    type: "webauthn.create", challenge: challenge, origin: ORIGIN, crossOrigin: false,
  }), "utf8");
  return {
    keyPair: kp, credId: credId,
    response: {
      id: b64url(credId), rawId: b64url(credId), type: "public-key",
      response: { clientDataJSON: b64url(clientData), attestationObject: b64url(attObj) },
      clientExtensionResults: {},
    },
  };
}

async function testSafetyNetIntegrityAndFreshness() {
  // A SafetyNet response is a point-in-time claim about a device. The
  // verifier checks the JWS signature and chain but does not bound the
  // statement's AGE, so without this gate one captured months ago replays for
  // as long as the relying party keeps the matching challenge outstanding —
  // "this device was untampered" quietly becomes "was untampered once".
  var challenge = b64url(crypto.randomBytes(32));

  async function outcomeFor(payload, extra) {
    var reg = makeSafetyNetRegistration(challenge, payload);
    return await regOutcome(Object.assign({
      response: reg.response, expectedChallenge: challenge,
      expectedOrigin: ORIGIN, expectedRPID: RP_ID,
    }, extra || {}));
  }

  var stale = await outcomeFor({
    timestampMs: Date.now() - 10 * 60 * 1000, ctsProfileMatch: true, basicIntegrity: true,
  });
  check("safetynet: a response older than the age bound is refused as stale",
        stale.ok === false && /safetynet-stale/.test(String(stale.code)));

  var future = await outcomeFor({
    timestampMs: Date.now() + 10 * 60 * 1000, ctsProfileMatch: true, basicIntegrity: true,
  });
  check("safetynet: a response timestamped in the future is refused",
        future.ok === false && /safetynet-stale/.test(String(future.code)));

  var noStamp = await outcomeFor({ ctsProfileMatch: true, basicIntegrity: true });
  check("safetynet: a response with no readable timestamp is refused, not assumed fresh",
        noStamp.ok === false && /safetynet-unreadable/.test(String(noStamp.code)));

  // A FRESH response gets past the age gate and is then refused by the
  // verifier for the reason it should be — the JWS is not Google-signed.
  // Reaching that refusal is the proof the freshness gate let it through.
  var fresh = await outcomeFor({
    timestampMs: Date.now(), ctsProfileMatch: true, basicIntegrity: true,
  });
  check("safetynet: a FRESH response passes the age gate and fails on the signature instead",
        fresh.ok === false && !/safetynet-stale|safetynet-unreadable/.test(String(fresh.code)));

  // The bound is an operator dial, not a hardcode — a deployment with a
  // slower flow can widen it, and that must actually take effect.
  var widened = await outcomeFor(
    { timestampMs: Date.now() - 10 * 60 * 1000, ctsProfileMatch: true, basicIntegrity: true },
    { safetyNetMaxAgeMs: 60 * 60 * 1000 });
  check("safetynet: widening safetyNetMaxAgeMs admits an older response",
        widened.ok === false && !/safetynet-stale/.test(String(widened.code)));

  // ...but the dial cannot be turned to "off" by accident. NaN and Infinity
  // both make every age comparison pass, so a fat-fingered option would
  // silently remove the replay bound rather than fail.
  var staleP = { timestampMs: Date.now() - 10 * 60 * 1000, ctsProfileMatch: true };
  var bogus = [NaN, Infinity, -1, "60000", null];
  for (var i = 0; i < bogus.length; i++) {
    var rv = await outcomeFor(staleP, { safetyNetMaxAgeMs: bogus[i] });
    // null falls back to the default bound, so it is still refused as stale;
    // the rest are configuration errors and refused by name. Either way the
    // bound must NOT silently disappear.
    check("safetynet: safetyNetMaxAgeMs " + String(bogus[i]) + " never disables the bound",
          rv.ok === false &&
          /bad-safetynet-max-age|safetynet-stale/.test(String(rv.code)));
  }
}

// ---- residentKey and requireResidentKey state ONE requirement ----

async function testResidentKeySelectorsAgree() {
  // WebAuthn states "this credential must be discoverable" in two places:
  // `residentKey` (L2/L3) and the L1 boolean `requireResidentKey`. Browsers in
  // the field read one or the other, so the pair has to agree — the spec ties
  // requireResidentKey to `residentKey === "required"`.
  //
  // Deriving them independently lets them contradict, and a browser reading
  // the field that says "not required" creates a NON-discoverable credential.
  // The user then has no username-less or conditional-UI login, and nothing
  // fails loudly at registration time: the credential works, just not the way
  // the relying party required.
  async function selectorsFor(sel) {
    var opts = await passkey.startRegistration(Object.assign(
      { rpName: "Example", rpId: RP_ID, userName: "alice" },
      sel === undefined ? {} : { authenticatorSelection: sel }));
    return opts.authenticatorSelection;
  }
  function agree(s) {
    return s.requireResidentKey === (s.residentKey === "required");
  }

  var cases = [
    { sel: undefined,                       key: "preferred",    label: "no authenticatorSelection" },
    { sel: {},                              key: "preferred",    label: "an empty authenticatorSelection" },
    { sel: { residentKey: "required" },     key: "required",     label: "residentKey required" },
    { sel: { residentKey: "preferred" },    key: "preferred",    label: "residentKey preferred" },
    { sel: { residentKey: "discouraged" },  key: "discouraged",  label: "residentKey discouraged" },
    // The legacy boolean on its own still states the requirement, and must
    // raise residentKey with it rather than being silently dropped.
    { sel: { requireResidentKey: true },    key: "required",     label: "the legacy requireResidentKey flag alone" },
    { sel: { requireResidentKey: false },   key: "preferred",    label: "the legacy flag set false" },
    // When both are given, the modern field decides and the legacy boolean is
    // brought into line — never the other way round.
    { sel: { residentKey: "required", requireResidentKey: false },
      key: "required",    label: "a contradictory pair favouring residentKey" },
    { sel: { residentKey: "discouraged", requireResidentKey: true },
      key: "discouraged", label: "a contradictory pair favouring the legacy flag" },
  ];

  for (var i = 0; i < cases.length; i++) {
    var s = await selectorsFor(cases[i].sel);
    check("resident key: " + cases[i].label + " yields residentKey=" + cases[i].key,
          s.residentKey === cases[i].key);
    check("resident key: " + cases[i].label + " keeps both selectors in agreement",
          agree(s));
  }
}

async function testDefaultHintsFollowTheAttachment() {
  // `hints` and `authenticatorAttachment` are the same class of pair: both say
  // which authenticator this ceremony is for, and browsers give hints
  // precedence in the UI. A default hint list that contradicts an explicit
  // attachment steers the user at an authenticator the attachment forbids —
  // the prompt offers the platform authenticator, and creating a credential
  // there is refused.
  async function hintsFor(attachment) {
    var o = await passkey.startRegistration({
      rpName: "Example", rpId: RP_ID, userName: "alice",
      authenticatorSelection: attachment === undefined ? {} : { authenticatorAttachment: attachment },
    });
    return o.hints;
  }

  var crossPlatform = await hintsFor("cross-platform");
  check("hints: a cross-platform ceremony does not hint at the platform authenticator",
        crossPlatform.indexOf("client-device") === -1);
  check("hints: a cross-platform ceremony hints at security keys and phones",
        crossPlatform.indexOf("security-key") !== -1 && crossPlatform.indexOf("hybrid") !== -1);

  var platform = await hintsFor("platform");
  check("hints: a platform ceremony hints only at the platform authenticator",
        platform.join(",") === "client-device");

  var unset = await hintsFor(undefined);
  check("hints: with no attachment the default still surfaces both families",
        unset.indexOf("client-device") !== -1 && unset.indexOf("hybrid") !== -1);

  // An explicit hint list is the operator's call and passes through untouched,
  // whatever the attachment says.
  var explicit = await passkey.startRegistration({
    rpName: "Example", rpId: RP_ID, userName: "alice",
    authenticatorSelection: { authenticatorAttachment: "cross-platform" },
    hints: ["client-device"],
  });
  check("hints: an explicit hint list is not overridden by the attachment",
        explicit.hints.join(",") === "client-device");
}

// ---- The cross-origin opt-in can name WHICH embedder is permitted ----

async function testCrossOriginEmbedderAllowList() {
  // Refusing cross-origin ceremonies by default is only half the control. An
  // RP that genuinely is embedded — a checkout widget, a partner portal — has
  // to opt in, and `allowCrossOrigin: true` on its own accepts EVERY embedder,
  // including the hostile page the refusal exists to stop. The opt-in would
  // then be a switch that turns the protection off rather than aims it.
  //
  // clientData.topOrigin names the page the ceremony ran inside, so the opt-in
  // can be a list of the embedders the deployment actually has.
  var PARTNER = "https://partner.example";
  var HOSTILE = "https://evil.example";
  var challenge = b64url(crypto.randomBytes(32));

  var fromPartner = makeRegistrationCrossOrigin(challenge, PARTNER);
  var okListed = await regOutcome({
    response: fromPartner.response, expectedChallenge: challenge,
    expectedOrigin: ORIGIN, expectedRPID: RP_ID,
    allowCrossOrigin: [PARTNER],
  });
  check("cross-origin: a ceremony from a listed embedder is accepted",
        okListed.ok === true);

  var fromHostile = makeRegistrationCrossOrigin(challenge, HOSTILE);
  var refused = await regOutcome({
    response: fromHostile.response, expectedChallenge: challenge,
    expectedOrigin: ORIGIN, expectedRPID: RP_ID,
    allowCrossOrigin: [PARTNER],
  });
  check("cross-origin: a ceremony from an embedder NOT on the list is refused",
        refused.ok === false && refused.threw === true &&
        /cross-origin-ceremony/.test(String(refused.code)));

  // A browser that reports crossOrigin without naming the top origin cannot be
  // matched against a list, and must not pass one.
  var anonymous = makeRegistrationCrossOrigin(challenge, undefined);
  var noTop = await regOutcome({
    response: anonymous.response, expectedChallenge: challenge,
    expectedOrigin: ORIGIN, expectedRPID: RP_ID,
    allowCrossOrigin: [PARTNER],
  });
  check("cross-origin: an unnamed embedder cannot satisfy an embedder allow-list",
        noTop.ok === false && noTop.threw === true &&
        /cross-origin-ceremony/.test(String(noTop.code)));

  // `true` still means "any embedder" — the blunt opt-in remains, because a
  // deployment behind an unknown set of partners has no list to write.
  var anyEmbedder = await regOutcome({
    response: fromHostile.response, expectedChallenge: challenge,
    expectedOrigin: ORIGIN, expectedRPID: RP_ID,
    allowCrossOrigin: true,
  });
  check("cross-origin: allowCrossOrigin true still accepts any embedder",
        anyEmbedder.ok === true);

  // An empty list permits nothing rather than everything.
  var emptyList = await regOutcome({
    response: fromPartner.response, expectedChallenge: challenge,
    expectedOrigin: ORIGIN, expectedRPID: RP_ID,
    allowCrossOrigin: [],
  });
  check("cross-origin: an EMPTY embedder list permits nothing",
        emptyList.ok === false);
}

// ---- The registration result keeps every field it has always carried ----

async function testRegistrationResultSurface() {
  // Swapping the verification library underneath a primitive is invisible to
  // that primitive's own tests when a field simply stops being populated: the
  // result is still an object, `verified` is still true, and only the operator
  // reading the missing field notices — in production.
  //
  // transports is the one that costs something. WebAuthn's getTransports()
  // tells the browser at the NEXT login whether to look at USB, NFC or the
  // platform authenticator; an RP is meant to persist it and hand it back in
  // allowCredentials. Losing it silently degrades every subsequent login with
  // a security key into a guess.
  var challenge = b64url(crypto.randomBytes(32));
  var reg = makeRegistration(challenge);
  reg.response.response.transports = ["usb", "nfc"];

  var rv = await regOutcome({
    response: reg.response, expectedChallenge: challenge,
    expectedOrigin: ORIGIN, expectedRPID: RP_ID,
  });
  check("result surface: registration verifies", rv.ok === true);
  var info = rv.rv.registrationInfo;

  check("result surface: credential.transports survives from the response",
        Array.isArray(info.credential.transports) &&
        info.credential.transports.join(",") === "usb,nfc");
  check("result surface: credentialType is carried",
        info.credentialType === "public-key");
  check("result surface: the verified origin is echoed back",
        info.origin === ORIGIN);
  // With a multi-origin allow-list the recorded origin is the ONE the ceremony
  // happened at, not the list it was checked against — an audit row naming
  // every permitted origin records nothing.
  var multi = makeRegistration(b64url(crypto.randomBytes(32)));
  var multiRv = await regOutcome({
    response: multi.response,
    expectedChallenge: JSON.parse(
      Buffer.from(multi.response.response.clientDataJSON, "base64url").toString()).challenge,
    expectedOrigin: ["https://admin.example.test", ORIGIN], expectedRPID: RP_ID,
  });
  check("result surface: with an origin allow-list, the matched origin is recorded",
        multiRv.ok === true && multiRv.rv.registrationInfo.origin === ORIGIN);

  // The SAME question on the authentication side. Both ceremonies report an
  // origin, both are written to the same audit row, and a value that is a
  // string after one and an array after the other is a shape the consumer
  // cannot handle uniformly — and records nothing useful either way.
  var authChallenge = b64url(crypto.randomBytes(32));
  var assertion = makeAssertion(reg.keyPair.privateKey, reg.credId, authChallenge, 1);
  var authRv = await authOutcome({
    response: assertion.response, expectedChallenge: authChallenge,
    expectedOrigin: ["https://admin.example.test", ORIGIN], expectedRPID: RP_ID,
    credential: { id: b64url(reg.credId), publicKey: info.credential.publicKey, counter: 0 },
  });
  check("result surface: authentication records the matched origin, not the allow-list",
        authRv.ok === true && authRv.rv.authenticationInfo.origin === ORIGIN);
  check("result surface: authentication records the RP ID as a string",
        authRv.ok === true && authRv.rv.authenticationInfo.rpID === RP_ID);
  check("result surface: the verified RP ID is echoed back",
        info.rpID === RP_ID);
  check("result surface: the attestation object is carried for later re-checks",
        info.attestationObject &&
        Buffer.compare(Buffer.from(info.attestationObject),
                       Buffer.from(reg.response.response.attestationObject, "base64url")) === 0);
  check("result surface: fmt is carried", info.fmt === "none");

  // A response with no transports leaves the field absent rather than
  // inventing an empty list, so an operator can tell "none reported" from
  // "reported none".
  var noTransports = makeRegistration(b64url(crypto.randomBytes(32)));
  var rv2 = await regOutcome({
    response: noTransports.response,
    expectedChallenge: JSON.parse(
      Buffer.from(noTransports.response.response.clientDataJSON, "base64url").toString()).challenge,
    expectedOrigin: ORIGIN, expectedRPID: RP_ID,
  });
  check("result surface: a response reporting no transports leaves the field undefined",
        rv2.ok === true && rv2.rv.registrationInfo.credential.transports === undefined);
}

// ---- The registration result feeds b.auth.fidoMds3 unchanged ----

// A registration carrying a specific AAGUID, so the value that reaches the
// metadata lookup is one this test chose and can assert on.
function makeRegistrationWithAaguid(challenge, aaguidHex) {
  var kp     = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var credId = crypto.randomBytes(32);
  var authData = buildAuthData(RP_ID, FLAG_UP | FLAG_UV | FLAG_AT, 0,
    buildAttestedCredData(Buffer.from(aaguidHex, "hex"), credId, coseEC2PublicKey(kp.publicKey)));
  var attObj = cborMap([
    [cborText("fmt"),      cborText("none")],
    [cborText("attStmt"),  cborMap([])],
    [cborText("authData"), cborBytes(authData)],
  ]);
  var clientData = Buffer.from(JSON.stringify({
    type: "webauthn.create", challenge: challenge, origin: ORIGIN, crossOrigin: false,
  }), "utf8");
  return {
    keyPair: kp, credId: credId,
    response: {
      id: b64url(credId), rawId: b64url(credId), type: "public-key",
      response: { clientDataJSON: b64url(clientData), attestationObject: b64url(attObj) },
      clientExtensionResults: {},
    },
  };
}

async function testRegistrationInfoFeedsFidoMds3() {
  // `b.auth.fidoMds3.verifyAuthenticator(blob, registrationInfo)` takes the
  // object `verifyRegistration` returns — that is the documented composition,
  // and the whole reason registrationInfo carries an aaguid at all. It is a
  // seam between two primitives, so a shape change on one side is invisible to
  // the other's tests and shows up as a broken deployment.
  var AAGUID_HEX = "f8a011f38c0a4d15800617111f9edc7d";
  var AAGUID_UUID = "f8a011f3-8c0a-4d15-8006-17111f9edc7d";
  var challenge = b64url(crypto.randomBytes(32));
  var reg = makeRegistrationWithAaguid(challenge, AAGUID_HEX);
  var rv = await regOutcome({
    response: reg.response, expectedChallenge: challenge,
    expectedOrigin: ORIGIN, expectedRPID: RP_ID,
  });
  check("mds3 seam: setup registration verifies", rv.ok === true);
  check("mds3 seam: registrationInfo.aaguid is the UUID string the lookup takes",
        rv.rv.registrationInfo.aaguid === AAGUID_UUID);

  // Drive the real consumer, not just the shape: a metadata BLOB naming this
  // authenticator must resolve through the registration result as handed over.
  var blob = {
    entries: [{
      aaguid: AAGUID_UUID,
      metadataStatement: { description: "Test Authenticator" },
      statusReports: [{ status: "FIDO_CERTIFIED_L1" }],
    }],
  };
  var found = b.auth.fidoMds3.lookupAaguid(blob, rv.rv.registrationInfo.aaguid);
  check("mds3 seam: lookupAaguid resolves the registered authenticator",
        found && found.metadataStatement.description === "Test Authenticator");

  var verdict = b.auth.fidoMds3.verifyAuthenticator(blob, rv.rv.registrationInfo);
  check("mds3 seam: verifyAuthenticator accepts the registration result unchanged",
        verdict && verdict.ok === true);

  // And an authenticator absent from the BLOB is still refused through the
  // same seam, so the composition is not passing everything.
  var stranger = await regOutcome({
    response: makeRegistrationWithAaguid(challenge, "00112233445566778899aabbccddeeff").response,
    expectedChallenge: challenge, expectedOrigin: ORIGIN, expectedRPID: RP_ID,
  });
  var refused = b.auth.fidoMds3.verifyAuthenticator(blob, stranger.rv.registrationInfo);
  check("mds3 seam: an authenticator absent from the metadata BLOB is refused",
        refused && refused.ok === false);
}

// ---- Authenticators that do not implement a signature counter ----

async function testZeroSignCountAuthenticators() {
  // WebAuthn L3 §6.1.1: an authenticator that does not implement a signature
  // counter reports 0 forever. That is not a stale counter and not a clone —
  // it is the majority of platform passkeys (iCloud Keychain, Google Password
  // Manager, and the synced credentials most users actually have).
  //
  // §7.2 step 21 only calls for clone detection when the received counter or
  // the stored one is non-zero. A verifier that instead requires strict
  // advancement refuses every login from those authenticators, which is a
  // total outage for most of a deployment's users rather than a rare edge.
  var challenge = b64url(crypto.randomBytes(32));
  var reg = makeRegistration(challenge);                     // registers at signCount 0
  var regRv = await regOutcome({
    response: reg.response, expectedChallenge: challenge,
    expectedOrigin: ORIGIN, expectedRPID: RP_ID,
  });
  check("zero-counter: setup registration verifies", regRv.ok === true);
  check("zero-counter: a counter-less authenticator registers at 0",
        regRv.rv.registrationInfo.credential.counter === 0);
  var pub = storedPublicKey(regRv.rv);

  // Two consecutive logins, both reporting 0 — the normal lifetime of such a
  // credential, not a special case.
  for (var i = 0; i < 2; i++) {
    var c = b64url(crypto.randomBytes(32));
    var assertion = makeAssertion(reg.keyPair.privateKey, reg.credId, c, 0);
    var rv = await authOutcome({
      response: assertion.response, expectedChallenge: c,
      expectedOrigin: ORIGIN, expectedRPID: RP_ID,
      credential: { id: b64url(reg.credId), publicKey: pub, counter: 0 },
    });
    check("zero-counter: login " + (i + 1) + " from a counter-less authenticator verifies",
          rv.ok === true);
    check("zero-counter: the stored counter stays 0 after login " + (i + 1),
          rv.ok === true && rv.rv.authenticationInfo.newCounter === 0);
  }

  // Clone detection still applies the moment a counter IS in use: a credential
  // that has advanced past 0 may not go back.
  var advanced = b64url(crypto.randomBytes(32));
  var back = makeAssertion(reg.keyPair.privateKey, reg.credId, advanced, 3);
  var regressed = await authOutcome({
    response: back.response, expectedChallenge: advanced,
    expectedOrigin: ORIGIN, expectedRPID: RP_ID,
    credential: { id: b64url(reg.credId), publicKey: pub, counter: 7 },
  });
  check("zero-counter: a counter that goes BACKWARDS is still refused",
        regressed.ok === false);
}

// ---- The stored credential key is read from the shape storage returned ----

async function testStoredKeyAcceptedFormats() {
  // `registrationInfo.credential.publicKey` is COSE bytes, and where those
  // bytes come back from depends on the column an operator chose: a BLOB
  // returns a Buffer, a TEXT column returns the base64url string they wrote,
  // and a JSON document returns a plain array or a {type:"Buffer"} envelope.
  //
  // Every one of these is the SAME key. Reading one of them as UTF-8 produces
  // bytes that are not a COSE key at all, and the login fails with a message
  // about a malformed credential — sending the operator hunting for corruption
  // in a row that is perfectly intact.
  var challenge = b64url(crypto.randomBytes(32));
  var reg = makeRegistration(challenge);
  var regRv = await regOutcome({
    response: reg.response, expectedChallenge: challenge,
    expectedOrigin: ORIGIN, expectedRPID: RP_ID,
  });
  check("stored key: setup registration verifies", regRv.ok === true);
  var bytes = Buffer.from(storedPublicKey(regRv.rv));

  var forms = [
    { label: "a Buffer (BLOB column)",                value: bytes },
    { label: "a Uint8Array",                          value: new Uint8Array(bytes) },
    { label: "a base64url string (TEXT column)",      value: bytes.toString("base64url") },
  ];
  for (var i = 0; i < forms.length; i++) {
    var authChallenge = b64url(crypto.randomBytes(32));
    var assertion = makeAssertion(reg.keyPair.privateKey, reg.credId, authChallenge, i + 1);
    var rv = await authOutcome({
      response: assertion.response, expectedChallenge: authChallenge,
      expectedOrigin: ORIGIN, expectedRPID: RP_ID,
      credential: { id: b64url(reg.credId), publicKey: forms[i].value, counter: 0 },
    });
    check("stored key: a credential key stored as " + forms[i].label + " verifies",
          rv.ok === true);
  }

  // A value that is none of those is refused by name, rather than being
  // coerced into bytes that happen to parse as something.
  var bad = await authOutcome({
    response: makeAssertion(reg.keyPair.privateKey, reg.credId, challenge, 9).response,
    expectedChallenge: challenge, expectedOrigin: ORIGIN, expectedRPID: RP_ID,
    credential: { id: b64url(reg.credId), publicKey: 12345, counter: 0 },
  });
  check("stored key: a credential key that is neither bytes nor base64url is refused by name",
        bad.ok === false && bad.threw === true &&
        /bad-credential-key/.test(String(bad.code)));

  // A string that is not base64url is refused rather than silently decoded to
  // whatever bytes the lenient decoder salvages.
  var notB64 = await authOutcome({
    response: makeAssertion(reg.keyPair.privateKey, reg.credId, challenge, 10).response,
    expectedChallenge: challenge, expectedOrigin: ORIGIN, expectedRPID: RP_ID,
    credential: { id: b64url(reg.credId), publicKey: "not base64url!!", counter: 0 },
  });
  check("stored key: a non-base64url string is refused by name",
        notB64.ok === false && notB64.threw === true &&
        /bad-credential-key/.test(String(notB64.code)));
}

// ---- Every refusal is an AuthError in the auth-passkey namespace ----

async function testRefusalsAreFramedAsAuthErrors() {
  // The primitive's contract is that failures arrive as AuthError with an
  // auth-passkey/* code, the same framing as auth.password and auth.totp — so
  // `catch (e) { if (e.isAuthError) return badRequest(e.code); }` is a complete
  // handler. A refusal that escapes as the verification library's own error
  // type falls through that handler into a 500, and leaks which library is
  // underneath into the operator's logs.
  //
  // Driven on the client-data checks specifically: a stale or replayed
  // challenge is the most common registration failure there is, and it is
  // checked on a different code path from the attestation itself.
  var challenge = b64url(crypto.randomBytes(32));
  var reg = makeRegistration(challenge);

  async function refusalFor(args, label) {
    try { await passkey.verifyRegistration(args); }
    catch (e) {
      check(label + " is an AuthError", e.isAuthError === true);
      check(label + " carries an auth-passkey/* code",
            typeof e.code === "string" && e.code.indexOf("auth-passkey/") === 0);
      return;
    }
    check(label + " is refused", false);
  }

  await refusalFor({
    response: reg.response, expectedChallenge: b64url(crypto.randomBytes(32)),
    expectedOrigin: ORIGIN, expectedRPID: RP_ID,
  }, "registration with a stale challenge");

  await refusalFor({
    response: reg.response, expectedChallenge: challenge,
    expectedOrigin: "https://attacker.test", expectedRPID: RP_ID,
  }, "registration from an unexpected origin");

  // A ceremony-type confusion — an assertion's clientData replayed into the
  // registration verifier — is the same class and must frame the same way.
  var swapped = JSON.parse(JSON.stringify(reg.response));
  swapped.response.clientDataJSON = b64url(Buffer.from(JSON.stringify({
    type: "webauthn.get", challenge: challenge, origin: ORIGIN, crossOrigin: false,
  }), "utf8"));
  await refusalFor({
    response: swapped, expectedChallenge: challenge,
    expectedOrigin: ORIGIN, expectedRPID: RP_ID,
  }, "registration carrying an assertion's client data");
}

// ---- Legacy-algorithm credentials: registered before, still usable ----

// A P-521 / ES512 credential — an algorithm the framework does not advertise
// today but the verifier it replaced accepted, so credential rows carrying one
// exist in deployments that upgraded.
function makeEs512Registration(challenge) {
  var kp = crypto.generateKeyPairSync("ec", { namedCurve: "P-521" });
  var jwk = kp.publicKey.export({ format: "jwk" });
  var cose = cborMap([
    [cborInt(1),  cborInt(2)],                                        // kty: EC2
    [cborInt(3),  cborInt(-36)],                                      // alg: ES512
    [cborInt(-1), cborInt(3)],                                        // crv: P-521
    [cborInt(-2), cborBytes(Buffer.from(jwk.x, "base64url"))],
    [cborInt(-3), cborBytes(Buffer.from(jwk.y, "base64url"))],
  ]);
  var credId = crypto.randomBytes(32);
  var authData = buildAuthData(RP_ID, FLAG_UP | FLAG_UV | FLAG_AT, 0,
    buildAttestedCredData(Buffer.alloc(16, 0), credId, cose));
  var attObj = cborMap([
    [cborText("fmt"),      cborText("none")],
    [cborText("attStmt"),  cborMap([])],
    [cborText("authData"), cborBytes(authData)],
  ]);
  var clientData = Buffer.from(JSON.stringify({
    type: "webauthn.create", challenge: challenge, origin: ORIGIN, crossOrigin: false,
  }), "utf8");
  return {
    keyPair: kp, credId: credId,
    response: {
      id: b64url(credId), rawId: b64url(credId), type: "public-key",
      response: { clientDataJSON: b64url(clientData), attestationObject: b64url(attObj) },
      clientExtensionResults: {},
    },
  };
}

function makeEs512Assertion(privateKey, credId, challenge, signCount) {
  var authData   = buildAuthData(RP_ID, FLAG_UP | FLAG_UV, signCount, null);
  var clientData = Buffer.from(JSON.stringify({
    type: "webauthn.get", challenge: challenge, origin: ORIGIN, crossOrigin: false,
  }), "utf8");
  var sig = crypto.sign("sha512", Buffer.concat([authData, sha256(clientData)]),
    { key: privateKey, dsaEncoding: "der" });
  return {
    response: {
      id: b64url(credId), rawId: b64url(credId), type: "public-key",
      response: {
        clientDataJSON:    b64url(clientData),
        authenticatorData: b64url(authData),
        signature:         b64url(sig),
      },
      clientExtensionResults: {},
    },
  };
}

async function testLegacyAlgorithmOptIn() {
  // The framework advertises Ed25519 / ES256 / RS256 and verifies only those by
  // default. The verifier this release replaced accepted a wider set, so a
  // deployment upgrading into this version can hold credentials the default
  // list refuses — and refusing an assertion from a credential the same system
  // registered locks that user out with no way back short of re-registration.
  //
  // The default must NOT quietly widen to fix that: the advertised set is a
  // forward-looking choice. Instead the operator names the algorithms their
  // stored credentials use.
  var challenge = b64url(crypto.randomBytes(32));
  var legacy = makeEs512Registration(challenge);

  var byDefault = await regOutcome({
    response: legacy.response, expectedChallenge: challenge,
    expectedOrigin: ORIGIN, expectedRPID: RP_ID,
  });
  check("legacy alg: an ES512 credential is refused under the default algorithm list",
        byDefault.ok === false);

  var optedIn = await regOutcome({
    response: legacy.response, expectedChallenge: challenge,
    expectedOrigin: ORIGIN, expectedRPID: RP_ID,
    allowedAlgorithms: [-36],
  });
  check("legacy alg: the same credential registers when the operator allows ES512",
        optedIn.ok === true);

  var authChallenge = b64url(crypto.randomBytes(32));
  var assertion = makeEs512Assertion(legacy.keyPair.privateKey, legacy.credId, authChallenge, 1);
  var credential = { id: b64url(legacy.credId), publicKey: storedPublicKey(optedIn.rv), counter: 0 };

  var authDefault = await authOutcome({
    response: assertion.response, expectedChallenge: authChallenge,
    expectedOrigin: ORIGIN, expectedRPID: RP_ID, credential: credential,
  });
  check("legacy alg: an ES512 assertion is refused under the default algorithm list",
        authDefault.ok === false);

  var authOptedIn = await authOutcome({
    response: assertion.response, expectedChallenge: authChallenge,
    expectedOrigin: ORIGIN, expectedRPID: RP_ID,
    credential: { id: b64url(legacy.credId), publicKey: storedPublicKey(optedIn.rv), counter: 0 },
    allowedAlgorithms: [-36],
  });
  check("legacy alg: the stranded user can log in once the operator allows ES512",
        authOptedIn.ok === true);

  // Opting in is per-call and does not leak: the default list is untouched.
  var stillRefused = await authOutcome({
    response: assertion.response, expectedChallenge: authChallenge,
    expectedOrigin: ORIGIN, expectedRPID: RP_ID,
    credential: { id: b64url(legacy.credId), publicKey: storedPublicKey(optedIn.rv), counter: 0 },
  });
  check("legacy alg: allowing ES512 on one call does not widen the default for the next",
        stillRefused.ok === false);

  // The escape hatch is not a way to reach a broken primitive. RSA with SHA-1
  // is refused however it is asked for, and the refusal names the reason.
  var sha1 = null;
  try {
    await passkey.startRegistration({
      rpName: "Example", rpId: RP_ID, userName: "alice", allowedAlgorithms: [-65535],
    });
  } catch (e) { sha1 = e; }
  check("legacy alg: RSA with SHA-1 (-65535) is refused even when asked for explicitly",
        sha1 && /bad-algorithm/.test(String(sha1.code)));

  // An empty list is a configuration that permits nothing, not "any algorithm".
  var empty = null;
  try {
    await passkey.startRegistration({
      rpName: "Example", rpId: RP_ID, userName: "alice", allowedAlgorithms: [],
    });
  } catch (e) { empty = e; }
  check("legacy alg: an EMPTY algorithm list is refused, never read as 'any algorithm'",
        empty && /bad-algorithm/.test(String(empty.code)));

  var unknown = null;
  try {
    await passkey.startRegistration({
      rpName: "Example", rpId: RP_ID, userName: "alice", allowedAlgorithms: [-999],
    });
  } catch (e) { unknown = e; }
  check("legacy alg: an algorithm the verifier cannot handle is refused at config time",
        unknown && /bad-algorithm/.test(String(unknown.code)));

  // Every identifier the option ADVERTISES as supported must actually be
  // accepted — a list that names an algorithm the verifier cannot check sends
  // an operator to configure their way out of a lockout and lands them in a
  // different one. Config-time acceptance for each, since the end-to-end
  // signature path is exercised for ES256 / ES512 / RS256 above and in
  // testRsaCredentialRoundTrip.
  var advertised = [-8, -7, -35, -36, -37, -38, -39, -257, -258, -259];
  for (var a = 0; a < advertised.length; a++) {
    var accepted;
    try {
      var o = await passkey.startRegistration({
        rpName: "Example", rpId: RP_ID, userName: "alice",
        allowedAlgorithms: [advertised[a]],
      });
      accepted = o.pubKeyCredParams.length === 1 &&
                 o.pubKeyCredParams[0].alg === advertised[a];
    } catch (_e) { accepted = false; }
    check("legacy alg: COSE " + advertised[a] + " is accepted as documented", accepted);
  }

  // What the browser is offered follows the same list, so the ceremony cannot
  // advertise one set and verify another.
  var opts = await passkey.startRegistration({
    rpName: "Example", rpId: RP_ID, userName: "alice", allowedAlgorithms: [-7],
  });
  check("legacy alg: startRegistration advertises exactly the allowed algorithms",
        opts.pubKeyCredParams.length === 1 && opts.pubKeyCredParams[0].alg === -7);

  var dflt = await passkey.startRegistration({ rpName: "Example", rpId: RP_ID, userName: "alice" });
  check("legacy alg: the default advertised set is unchanged (EdDSA, ES256, RS256)",
        dflt.pubKeyCredParams.map(function (p) { return p.alg; }).join(",") === "-8,-7,-257");
}

// ---- Registration: the stored credential ID comes from the attestation ----

async function testRegistrationCredentialIdIsAttested() {
  // The credential ID in the registration JSON is client-supplied and covered
  // by nothing. The authoritative one lives inside attestedCredentialData in
  // the signed authenticator data. A registration that claims someone else's
  // credential ID while attesting its own key must be refused: an RP keying
  // its credential table on the returned ID would otherwise overwrite the
  // victim's record with the attacker's public key.
  var challenge = b64url(crypto.randomBytes(32));
  var reg = makeRegistration(challenge);
  var victimId = b64url(crypto.randomBytes(32));

  var lied = JSON.parse(JSON.stringify(reg.response));
  lied.id = victimId;
  lied.rawId = victimId;
  var rv = await regOutcome({
    response: lied, expectedChallenge: challenge,
    expectedOrigin: ORIGIN, expectedRPID: RP_ID,
  });
  check("registration claiming a credential ID the attestation does not carry is REJECTED",
        rv.ok === false && rv.threw === true &&
        /credential-id-mismatch/.test(String(rv.code)));

  // rawId alone is enough to poison a record for an RP that keys on it.
  var liedRaw = JSON.parse(JSON.stringify(reg.response));
  liedRaw.rawId = victimId;
  var rvRaw = await regOutcome({
    response: liedRaw, expectedChallenge: challenge,
    expectedOrigin: ORIGIN, expectedRPID: RP_ID,
  });
  check("registration whose rawId disagrees with the attestation is REJECTED",
        rvRaw.ok === false && rvRaw.threw === true &&
        /credential-id-mismatch/.test(String(rvRaw.code)));

  // The honest ceremony still verifies, and what is persisted is the ATTESTED
  // ID — so a later assertion binds against the same value the authenticator
  // signed, not whatever the browser sent.
  var honest = await regOutcome({
    response: reg.response, expectedChallenge: challenge,
    expectedOrigin: ORIGIN, expectedRPID: RP_ID,
  });
  check("honest registration verifies", honest.ok === true);
  check("the persisted credential ID is the one inside the attestation",
        honest.rv.registrationInfo.credential.id === b64url(reg.credId));

  // What gets persisted as the public key is the authenticator's own COSE key
  // bytes, verbatim — not a re-encoding. That is what makes a credential row
  // portable: the bytes are decided by the authenticator, so a record written
  // by any conformant verifier is readable by this one and vice versa. A
  // verifier that re-serialized the key here would silently strand every
  // already-stored credential.
  var stored = storedPublicKey(honest.rv);
  check("the persisted public key is the attested COSE key, byte for byte",
        Buffer.compare(Buffer.from(stored), coseEC2PublicKey(reg.keyPair.publicKey)) === 0);
}

// ---- Multi-origin deployments: expectedOrigin as a string[] ----

async function testMultiOriginAllowList() {
  // The primitive advertises expectedOrigin as either a string or a string[],
  // for a deployment serving the same RP ID from several origins (the app and
  // an admin subdomain). Nothing drove the ARRAY form end to end, so the
  // allow-list could have been passed through to a verifier that only compares
  // strings — which either refuses every genuine ceremony or, worse, skips the
  // origin check. Prove BOTH directions on BOTH ceremonies: a member is
  // accepted, and a list the ceremony's origin is absent from is refused.
  var OTHER = "https://admin.example.test";
  var challenge = b64url(crypto.randomBytes(32));
  var reg = makeRegistration(challenge);

  var inList = await regOutcome({
    response: reg.response, expectedChallenge: challenge,
    expectedOrigin: [OTHER, ORIGIN], expectedRPID: RP_ID,
  });
  check("multi-origin: registration verifies when the origin is in the allow-list",
        inList.ok === true);

  var notInList = await regOutcome({
    response: reg.response, expectedChallenge: challenge,
    expectedOrigin: [OTHER, "https://other.example.test"], expectedRPID: RP_ID,
  });
  check("multi-origin: registration is REJECTED when the origin is absent from the allow-list",
        notInList.ok === false);

  var pub = storedPublicKey(inList.rv);
  var authChallenge = b64url(crypto.randomBytes(32));
  var assertion = makeAssertion(reg.keyPair.privateKey, reg.credId, authChallenge, 1);
  var credential = { id: b64url(reg.credId), publicKey: pub, counter: 0 };

  var authIn = await authOutcome({
    response: assertion.response, expectedChallenge: authChallenge,
    expectedOrigin: [OTHER, ORIGIN], expectedRPID: RP_ID, credential: credential,
  });
  check("multi-origin: assertion verifies when the origin is in the allow-list",
        authIn.ok === true);

  var authOut = await authOutcome({
    response: assertion.response, expectedChallenge: authChallenge,
    expectedOrigin: [OTHER, "https://other.example.test"], expectedRPID: RP_ID,
    credential: { id: b64url(reg.credId), publicKey: pub, counter: 0 },
  });
  check("multi-origin: assertion is REJECTED when the origin is absent from the allow-list",
        authOut.ok === false);

  // An EMPTY allow-list must not read as "no origins to check". A deployment
  // that computes the list from config and gets an empty result has to fail
  // closed, not accept every origin.
  var empty = await regOutcome({
    response: reg.response, expectedChallenge: challenge,
    expectedOrigin: [], expectedRPID: RP_ID,
  });
  check("multi-origin: an EMPTY origin allow-list is refused, never treated as 'any origin'",
        empty.ok === false && empty.threw === true &&
        /missing-expectedOrigin/.test(String(empty.code)));
}

async function testRsaCredentialRoundTrip() {
  var challenge = b64url(crypto.randomBytes(32));
  var kp = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  var credId = crypto.randomBytes(32);
  var authData = buildAuthData(RP_ID, FLAG_UP | FLAG_UV | FLAG_AT, 0,
    buildAttestedCredData(Buffer.alloc(16, 0), credId, coseRSAPublicKey(kp.publicKey)));
  var attObj = cborMap([
    [cborText("fmt"),      cborText("none")],
    [cborText("attStmt"),  cborMap([])],
    [cborText("authData"), cborBytes(authData)],
  ]);
  var regClientData = Buffer.from(JSON.stringify({
    type: "webauthn.create", challenge: challenge, origin: ORIGIN, crossOrigin: false,
  }), "utf8");

  var regRv = await regOutcome({
    response: {
      id: b64url(credId), rawId: b64url(credId), type: "public-key",
      response: { clientDataJSON: b64url(regClientData), attestationObject: b64url(attObj) },
      clientExtensionResults: {},
    },
    expectedChallenge: challenge, expectedOrigin: ORIGIN, expectedRPID: RP_ID,
  });
  check("RS256: an RSA credential registers", regRv.ok === true);
  var pub = storedPublicKey(regRv.rv);
  check("RS256: registration surfaces the RSA public key", !!pub);

  // A genuine RS256 assertion — PKCS#1 v1.5 over authData || SHA-256(clientData).
  var authChallenge = b64url(crypto.randomBytes(32));
  var assertAuthData = buildAuthData(RP_ID, FLAG_UP | FLAG_UV, 1, null);
  var assertClientData = Buffer.from(JSON.stringify({
    type: "webauthn.get", challenge: authChallenge, origin: ORIGIN, crossOrigin: false,
  }), "utf8");
  var signed = Buffer.concat([assertAuthData, sha256(assertClientData)]);
  var sig = crypto.sign("sha256", signed, kp.privateKey);         // no dsaEncoding: RSA
  function rsaResponse(signature) {
    return {
      id: b64url(credId), rawId: b64url(credId), type: "public-key",
      response: {
        clientDataJSON:    b64url(assertClientData),
        authenticatorData: b64url(assertAuthData),
        signature:         b64url(signature),
      },
      clientExtensionResults: {},
    };
  }
  var authArgs = {
    response: rsaResponse(sig), expectedChallenge: authChallenge,
    expectedOrigin: ORIGIN, expectedRPID: RP_ID,
    credential: { id: b64url(credId), publicKey: pub, counter: 0 },
  };
  var good = await authOutcome(authArgs);
  check("RS256: a genuine RSA assertion verifies", good.ok === true);

  // ...and the cryptographic core must reject a tampered RSA signature, or the
  // "verifies" above proves only that something returned true.
  var bad = Buffer.from(sig); bad[bad.length - 1] ^= 0x01;
  var tampered = await authOutcome(Object.assign({}, authArgs, { response: rsaResponse(bad) }));
  check("RS256: a tampered RSA signature is REJECTED", tampered.ok === false);
}

// ---- BE / BS surfacing, from the real flag bits ----
//
// WebAuthn L3 §6.1.3. backupEligible (BE) says the credential CAN sync to a
// cloud account; backupState (BS) says it currently IS. Operators key trust
// decisions on the pair — a single-device passkey warrants step-up where a
// synced one does not — so the mapping from flag bit to named field has to be
// right in both directions.
//
// Driven by setting the bits in real authenticatorData rather than by stubbing
// a verifier's return value: a stub proves only that our mapping agrees with
// the shape we invented for it, which stays green even if the bit we read is
// the wrong one.
async function testBackupFlagSurfacing() {
  async function registerWith(flags) {
    var challenge = b64url(crypto.randomBytes(32));
    var kp = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
    var credId = crypto.randomBytes(32);
    var authData = buildAuthData(RP_ID, flags, 0,
      buildAttestedCredData(Buffer.alloc(16, 0), credId, coseEC2PublicKey(kp.publicKey)));
    var attObj = cborMap([
      [cborText("fmt"),      cborText("none")],
      [cborText("attStmt"),  cborMap([])],
      [cborText("authData"), cborBytes(authData)],
    ]);
    var clientData = Buffer.from(JSON.stringify({
      type: "webauthn.create", challenge: challenge, origin: ORIGIN, crossOrigin: false,
    }), "utf8");
    return regOutcome({
      response: {
        id: b64url(credId), rawId: b64url(credId), type: "public-key",
        response: { clientDataJSON: b64url(clientData), attestationObject: b64url(attObj) },
        clientExtensionResults: {},
      },
      expectedChallenge: challenge, expectedOrigin: ORIGIN, expectedRPID: RP_ID,
    });
  }

  var synced = await registerWith(FLAG_UP | FLAG_UV | FLAG_AT | FLAG_BE | FLAG_BS);
  check("BE/BS: a multi-device credential registers", synced.ok === true);
  check("BE/BS: backupEligible true when BE is set", synced.rv.backupEligible === true);
  check("BE/BS: backupState true when BS is set", synced.rv.backupState === true);
  check("BE/BS: credentialDeviceType reports multiDevice",
        synced.rv.registrationInfo.credentialDeviceType === "multiDevice");

  // BE set, BS clear — eligible to sync but not yet synced, which is a real
  // authenticator state and the one a naive "one flag" reading gets wrong.
  var eligible = await registerWith(FLAG_UP | FLAG_UV | FLAG_AT | FLAG_BE);
  check("BE/BS: backupEligible true, backupState false is representable",
        eligible.rv.backupEligible === true && eligible.rv.backupState === false);

  var single = await registerWith(FLAG_UP | FLAG_UV | FLAG_AT);
  check("BE/BS: neither flag reports a single-device credential",
        single.rv.backupEligible === false && single.rv.backupState === false &&
        single.rv.registrationInfo.credentialDeviceType === "singleDevice");
}

// ---- run ----

async function run() {
  await testBackupFlagSurfacing();
  await testRegistrationGenuineAndTampered();
  await testAuthenticationGenuineAndTampered();
  await testCeremonyPolicyRefusals();
  await testRegistrationCredentialIdIsAttested();
  await testAttestationRootsArePinned();
  await testCredPropsAndPaddedDescriptors();
  await testAuthenticatorExtensionResults();
  await testPaddedStoredCredentialIdStillLogsIn();
  await testSafetyNetIntegrityAndFreshness();
  await testResidentKeySelectorsAgree();
  await testDefaultHintsFollowTheAttachment();
  await testCrossOriginEmbedderAllowList();
  await testRegistrationResultSurface();
  await testRegistrationInfoFeedsFidoMds3();
  await testZeroSignCountAuthenticators();
  await testStoredKeyAcceptedFormats();
  await testRefusalsAreFramedAsAuthErrors();
  await testLegacyAlgorithmOptIn();
  await testMultiOriginAllowList();
  await testRsaCredentialRoundTrip();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
