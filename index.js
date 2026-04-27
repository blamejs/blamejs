"use strict";
/**
 * blamejs — public API entry point.
 *
 * The Node framework that owns its stack.
 *
 * Public surface lives on the exported object: crypto, router, vault,
 * db, fieldCrypto, audit, consent, subject, session, storage, queue,
 * objectStore, externalDb, logStream, middleware, parsers, atomic-file,
 * ntp-check, redact, cluster (leader election + write-side gates), and
 * the version-stable `constants` namespace.
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
var jsonSafe = require("./lib/json-safe");
var ntpCheck = require("./lib/ntp-check");
var auditSign = require("./lib/audit-sign");
var objectStore = require("./lib/object-store");
var objectStoreRetry = require("./lib/object-store-retry");
var queue = require("./lib/queue");
var logStream = require("./lib/log-stream");
var redact = require("./lib/redact");
var externalDb = require("./lib/external-db");
var middleware = require("./lib/middleware");
var atomicFile = require("./lib/atomic-file");
var parsers = require("./lib/parsers");
var cluster = require("./lib/cluster");
var frameworkSchema = require("./lib/framework-schema");
var clusterStorage = require("./lib/cluster-storage");
var asyncSafe = require("./lib/async-safe");
var handlers = require("./lib/handlers");
var sqlSafe = require("./lib/sql-safe");
var chainWriter = require("./lib/chain-writer");
var bufferSafe = require("./lib/buffer-safe");
var lazyRequire = require("./lib/lazy-require");
var frameworkError = require("./lib/framework-error");
var logger = require("./lib/logger");
var httpClient = require("./lib/http-client");
var websocket = require("./lib/websocket");
var urlSafe = require("./lib/url-safe");
var authHeader = require("./lib/auth-header");
var auth = {
  password: require("./lib/auth/password"),
  totp:     require("./lib/auth/totp"),
  passkey:  require("./lib/auth/passkey"),
  jwt:      require("./lib/auth/jwt"),
};
var template = require("./lib/template");
var render = require("./lib/render");
var staticServe = require("./lib/static");
var forms = require("./lib/forms");
var app = require("./lib/app");
var jobs = require("./lib/jobs");

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
  atomicFile:       atomicFile,
  parsers:          parsers,
  cluster:          cluster,
  frameworkSchema:  frameworkSchema,
  clusterStorage:   clusterStorage,
  asyncSafe:        asyncSafe,
  handlers:         handlers,
  sqlSafe:          sqlSafe,
  chainWriter:      chainWriter,
  bufferSafe:       bufferSafe,
  lazyRequire:      lazyRequire,
  frameworkError:   frameworkError,
  logger:           logger,
  httpClient:       httpClient,
  websocket:        websocket,
  urlSafe:          urlSafe,
  authHeader:       authHeader,
  auth:             auth,
  template:         template,
  render:           render,
  staticServe:      staticServe,
  forms:            forms,
  createApp:        app.createApp,
  jobs:             jobs,
  jsonSafe:         jsonSafe,
  ntpCheck:         ntpCheck,
  version:          constants.version,
};
