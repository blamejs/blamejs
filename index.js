"use strict";
/**
 * blamejs — public API entry point.
 *
 * The Node framework that owns its stack.
 *
 * v0.0.4 (Phase 1c — audit, consent, subject rights): adds tamper-evident
 * audit_log and consent_log (baked into the schema runner — apps cannot opt
 * out), per-row SHA3-512 hash chain with refuse-to-boot on break, and the
 * GDPR Article 15–22 / AU APP 12–13 / Privacy Act subject-rights primitives.
 *
 * Phase 0 / 1a / 1b carryover: crypto, router, constants, vault, vault-wrap,
 * passphrase-source, db, fieldCrypto.
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
var audit = require("./lib/audit");
var auditChain = require("./lib/audit-chain");
var consent = require("./lib/consent");
var subject = require("./lib/subject");

module.exports = {
  crypto:           crypto,
  router:           router,
  constants:        constants,
  vault:            vault,
  vaultWrap:        vaultWrap,
  passphraseSource: passphraseSource,
  db:               db,
  fieldCrypto:      fieldCrypto,
  audit:            audit,
  auditChain:       auditChain,
  consent:          consent,
  subject:          subject,
  version:          constants.version,
};
