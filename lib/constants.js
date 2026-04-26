"use strict";
/**
 * Framework constants — values fixed by blamejs design.
 *
 * App-specific values (paths, asset versions, theme, animation, OAuth
 * allowlists) are supplied via createApp() configuration in the consuming
 * app. Nothing in this file is mutable per-deployment.
 *
 * Naming follows the roadmap "Naming conventions" section: SCREAMING_SNAKE
 * for constants, lowercase namespace exports.
 */

var pkg = require("../package.json");

// ---- Time constants (ms) ----
var TIME = Object.freeze({
  ONE_MIN:       60000,
  FIVE_MIN:      300000,
  TEN_MIN:       600000,
  FIFTEEN_MIN:   900000,
  THIRTY_MIN:    1800000,
  ONE_HOUR:      3600000,
  TWO_HOURS:     7200000,
  ONE_DAY:       86400000,
  SEVEN_DAYS:    604800000,
  THIRTY_DAYS:   2592000000,
  NINETY_DAYS:   7776000000,
});

// ---- Crypto envelope versioning ----
// Every encrypted blob starts with a 4-byte header that identifies the
// algorithms used. This enables algorithm agility — any component can
// be swapped without re-encrypting existing data. Old envelopes always
// remain readable; new writes use ACTIVE.{KEM, CIPHER, KDF}.
//
// See roadmap "Modernity posture: highest practical bar, forward only"
// for the algorithm rotation policy.

var ENVELOPE_MAGIC = 0xE1;

var KEM_IDS = Object.freeze({
  ML_KEM_1024:        0x02,
  ML_KEM_1024_P384:   0x03,
});

var CIPHER_IDS = Object.freeze({
  XCHACHA20_POLY1305: 0x02,
});

var KDF_IDS = Object.freeze({
  SHAKE256:           0x02,
});

var ACTIVE = Object.freeze({
  KEM:    KEM_IDS.ML_KEM_1024_P384,
  CIPHER: CIPHER_IDS.XCHACHA20_POLY1305,
  KDF:    KDF_IDS.SHAKE256,
});

// ---- Storage-buffer envelope marker ----
// Used by encryptPacked / decryptPacked for symmetric buffer encryption.
// Single-byte version preceding nonce + ciphertext.
var FORMAT = Object.freeze({
  XCHACHA20_POLY1305: 0x02,
});

// ---- PQC TLS group IDs (IANA TLS Supported Groups Registry) ----
var PQC_GROUPS = Object.freeze({
  X25519MLKEM768:        0x11EC,
  SecP384r1MLKEM1024:    0x11ED,
});

var TLS_GROUP_PREFERENCE = Object.freeze([
  "SecP384r1MLKEM1024",
  "X25519MLKEM768",
  "SecP256r1MLKEM768",
]);

var TLS_GROUP_CURVE_STR = TLS_GROUP_PREFERENCE.join(":");

// ---- Vault sealed-value prefix ----
var VAULT_PREFIX = "vault:";

// ---- Default hash namespaces for derived-hash indexed lookups ----
// Apps add their own via app-config registries. The 'bj-' namespace
// prevents collision between framework-derived and app-derived hashes.
var HASH_PREFIX = Object.freeze({
  EMAIL:       "bj-email:",
  IP:          "bj-ip:",
  TOKEN:       "bj-token:",
});

module.exports = {
  version:                pkg.version,
  TIME:                   TIME,
  ENVELOPE_MAGIC:         ENVELOPE_MAGIC,
  KEM_IDS:                KEM_IDS,
  CIPHER_IDS:             CIPHER_IDS,
  KDF_IDS:                KDF_IDS,
  ACTIVE:                 ACTIVE,
  FORMAT:                 FORMAT,
  PQC_GROUPS:             PQC_GROUPS,
  TLS_GROUP_PREFERENCE:   TLS_GROUP_PREFERENCE,
  TLS_GROUP_CURVE_STR:    TLS_GROUP_CURVE_STR,
  VAULT_PREFIX:           VAULT_PREFIX,
  HASH_PREFIX:            HASH_PREFIX,
};
