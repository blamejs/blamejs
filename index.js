"use strict";
/**
 * blamejs — public API entry point.
 *
 * The Node framework that owns its stack.
 *
 * v0.0.5 (Phase 1d-1 — session & storage local backend): adds DB-backed
 * session management with sid-hashed-at-rest tokens, and a file storage
 * abstraction with per-file vault-sealed encryption. Local backend only;
 * S3 backend defers to v0.0.6.
 *
 * Phase 0 / 1a / 1b / 1c carryover: crypto, router, constants, vault,
 * vault-wrap, passphrase-source, db, fieldCrypto, audit, audit-chain,
 * consent, subject.
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
var session = require("./lib/session");
var storage = require("./lib/storage");
var json = require("./lib/json-safe");
var ntpCheck = require("./lib/ntp-check");
var auditSign = require("./lib/audit-sign");
var objectStore = require("./lib/object-store");
var objectStoreRetry = require("./lib/object-store-retry");
var queue = require("./lib/queue");
var logStream = require("./lib/log-stream");
var redact = require("./lib/redact");
var externalDb = require("./lib/external-db");
var middleware = require("./lib/middleware");

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
  auditSign:        auditSign,
  consent:          consent,
  subject:          subject,
  session:          session,
  storage:          storage,
  objectStore:      objectStore,
  objectStoreRetry: objectStoreRetry,
  queue:            queue,
  logStream:        logStream,
  redact:           redact,
  externalDb:       externalDb,
  middleware:       middleware,
  json:             json,
  ntpCheck:         ntpCheck,
  version:          constants.version,
};
