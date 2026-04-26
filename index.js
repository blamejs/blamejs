"use strict";
/**
 * blamejs — public API entry point.
 *
 * The Node framework that owns its stack.
 *
 * v0.0.3 (Phase 1b — db, query, field-crypto, migrations): adds the
 * encrypted-at-rest SQLite database with a chainable Query builder, a
 * sealed-by-default field-crypto engine, declarative schema reconcile,
 * and an imperative migration runner.
 *
 * Phase 1a / 0 carryover: vault, vault-wrap, passphrase-source, crypto,
 * router, constants.
 *
 * See LICENSE (Apache-2.0) and NOTICE for vendored attribution.
 */

var crypto = require("./lib/crypto");
var router = require("./lib/router");
var constants = require("./lib/constants");
var vault = require("./lib/vault");
var vaultWrap = require("./lib/vault-wrap");
var passphraseSource = require("./lib/passphrase-source");
var db = require("./lib/db");
var fieldCrypto = require("./lib/field-crypto");

module.exports = {
  crypto:           crypto,
  router:           router,
  constants:        constants,
  vault:            vault,
  vaultWrap:        vaultWrap,
  passphraseSource: passphraseSource,
  db:               db,
  fieldCrypto:      fieldCrypto,
  version:          constants.version,
};
