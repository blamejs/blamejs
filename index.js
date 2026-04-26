"use strict";
/**
 * blamejs — public API entry point.
 *
 * The Node framework that owns its stack.
 *
 * v0.0.2 (Phase 1a — vault & key management): adds the sealed keystore
 * (vault.seal/unseal), passphrase-derived AEAD wrapping (vault-wrap), and
 * passphrase source drivers (env / file / stdin). Vault is the dependency
 * that the upcoming db/storage/session modules build on.
 *
 * Phase 0 carryover: envelope-versioned PQC crypto primitives, zero-dep
 * HTTP router, framework constants.
 *
 * See LICENSE (Apache-2.0) and NOTICE for vendored attribution.
 */

var crypto = require("./lib/crypto");
var router = require("./lib/router");
var constants = require("./lib/constants");
var vault = require("./lib/vault");
var vaultWrap = require("./lib/vault-wrap");
var passphraseSource = require("./lib/passphrase-source");

module.exports = {
  crypto:           crypto,
  router:           router,
  constants:        constants,
  vault:            vault,
  vaultWrap:        vaultWrap,
  passphraseSource: passphraseSource,
  version:          constants.version,
};
