"use strict";
/**
 * Argon2id password hashing — public framework primitive.
 *
 * Different concern from lib/vault-wrap.js, which also uses Argon2id but
 * for KEK derivation (the output is a KEY used to AEAD-wrap the vault
 * file). This module is for application-layer password storage: the
 * output is a verifiable digest in PHC format, never decrypted, used
 * for "is this the password the user originally set?".
 *
 * Public API:
 *
 *   await auth.password.hash(plain, opts?)        → string (PHC format)
 *   await auth.password.verify(hash, plain)       → boolean
 *   auth.password.needsRehash(hash, opts?)        → boolean
 *
 * The PHC string captures the algorithm + parameters + salt + digest:
 *
 *   $argon2id$v=19$m=65536,t=3,p=4$<base64-salt>$<base64-hash>
 *
 * That string is what callers store in the database. verify() parses
 * it to recover the parameters, recomputes the digest with the
 * supplied plaintext, and timing-safe compares.
 *
 * Defaults (memoryCost=64 MiB, timeCost=3, parallelism=4) target
 * ~250–500ms on commodity 2026 hardware — painful for offline brute
 * force, tolerable inside a login latency budget. Operators with
 * tighter budgets (or beefier hardware) tune via opts; needsRehash
 * surfaces when stored hashes lag behind the current defaults so the
 * caller can transparently rehash on next successful login.
 *
 * Validation posture:
 *   - plain must be a non-empty string. Empty/whitespace passwords
 *     are operator bugs (UI should reject) — failing here surfaces
 *     them before they hit the DB.
 *   - plain length is capped at 4096 bytes (UTF-8). Same cap as the
 *     vault-wrap passphrase. A 5 GiB string fed to Argon2 would peg
 *     the box for minutes; the cap is sanity, not security.
 *   - hash must be a non-empty string starting with `$argon2id$`.
 *     Other Argon2 variants (`$argon2i$` / `$argon2d$`) are out of
 *     spec for this framework — verify() returns false rather than
 *     attempting to validate them. Callers using needsRehash on a
 *     non-id hash get true (forces rehash on next login).
 *
 * Errors are AuthError(code, message) with permanent=true. A failed
 * verify is NOT an error — it returns false. Errors are reserved for
 * "the call shape was wrong" (empty plain, oversize plain).
 */
var argon2 = require("../vendor/argon2");
var { AuthError } = require("../framework-error");

// Tuning targets ~250–500ms on commodity 2026 hardware. memoryCost
// is in KiB per Argon2's parameter convention.
var DEFAULT_PARAMS = Object.freeze({
  memoryCost:  65536,    // 64 MiB
  timeCost:    3,
  parallelism: 4,
});

var MAX_PLAINTEXT_BYTES = 4096;

function _validatePlain(plain) {
  if (typeof plain !== "string" || plain.length === 0) {
    throw new AuthError("auth-password/invalid-plain",
      "auth.password.hash requires a non-empty string");
  }
  if (Buffer.byteLength(plain, "utf8") > MAX_PLAINTEXT_BYTES) {
    throw new AuthError("auth-password/plain-too-large",
      "plaintext exceeds " + MAX_PLAINTEXT_BYTES + " bytes (UTF-8)");
  }
}

function _resolveParams(opts) {
  var p = Object.assign({}, DEFAULT_PARAMS, opts || {});
  if (typeof p.memoryCost !== "number" || p.memoryCost < 1024) {
    throw new AuthError("auth-password/bad-params",
      "memoryCost must be >= 1024 KiB (1 MiB)");
  }
  if (typeof p.timeCost !== "number" || p.timeCost < 1) {
    throw new AuthError("auth-password/bad-params", "timeCost must be >= 1");
  }
  if (typeof p.parallelism !== "number" || p.parallelism < 1) {
    throw new AuthError("auth-password/bad-params", "parallelism must be >= 1");
  }
  return p;
}

async function hash(plain, opts) {
  _validatePlain(plain);
  var p = _resolveParams(opts);
  return await argon2.hash(plain, {
    type:        argon2.argon2id,
    memoryCost:  p.memoryCost,
    timeCost:    p.timeCost,
    parallelism: p.parallelism,
  });
}

async function verify(stored, plain) {
  // verify intentionally tolerates malformed input by returning false
  // rather than throwing — login flows already treat false as "credentials
  // didn't match" and shouldn't have to wrap each call in try/catch.
  if (typeof stored !== "string" || stored.length === 0) return false;
  if (typeof plain !== "string" || plain.length === 0) return false;
  if (!stored.indexOf || stored.indexOf("$argon2id$") !== 0) return false;
  if (Buffer.byteLength(plain, "utf8") > MAX_PLAINTEXT_BYTES) return false;
  try {
    return await argon2.verify(stored, plain);
  } catch (_e) {
    // PHC-string parse failures from the vendor surface as throws —
    // treat as "doesn't match" so a corrupted DB column can't break
    // login flows with an unexpected exception type.
    return false;
  }
}

function needsRehash(stored, opts) {
  if (typeof stored !== "string" || stored.indexOf("$argon2id$") !== 0) {
    // Non-id variant or malformed — force rehash on next successful login
    return true;
  }
  var p = _resolveParams(opts);
  try {
    return argon2.needsRehash(stored, {
      memoryCost:  p.memoryCost,
      timeCost:    p.timeCost,
      parallelism: p.parallelism,
    });
  } catch (_e) {
    return true;     // unparseable → rehash
  }
}

module.exports = {
  hash:           hash,
  verify:         verify,
  needsRehash:    needsRehash,
  DEFAULT_PARAMS: DEFAULT_PARAMS,
};
