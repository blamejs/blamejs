"use strict";
/**
 * blamejs — public API entry point.
 *
 * The Node framework that owns its stack.
 *
 * Public surface lives on the exported object: crypto, router, vault,
 * db, cryptoField, audit, consent, subject, session, storage, queue,
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
var vaultWrap = require("./lib/vault/wrap");
var vaultPassphraseSource = require("./lib/vault/passphrase-source");
var db = require("./lib/db");
var cryptoField = require("./lib/crypto-field");
var audit = require("./lib/audit");
var auditChain = require("./lib/audit-chain");
var consent = require("./lib/consent");
var subject = require("./lib/subject");
var session = require("./lib/session");
var storage = require("./lib/storage");
var safeJson = require("./lib/safe-json");
var ntpCheck = require("./lib/ntp-check");
var auditSign = require("./lib/audit-sign");
var objectStore = require("./lib/object-store");
var objectStoreRetry = require("./lib/object-store/retry");
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
var safeAsync = require("./lib/safe-async");
var handlers = require("./lib/handlers");
var safeSql = require("./lib/safe-sql");
var chainWriter = require("./lib/chain-writer");
var safeBuffer = require("./lib/safe-buffer");
var lazyRequire = require("./lib/lazy-require");
var frameworkError = require("./lib/framework-error");
var logger = require("./lib/logger");
var httpClient = require("./lib/http-client");
var websocket = require("./lib/websocket");
var safeUrl = require("./lib/safe-url");
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
var mail = require("./lib/mail");
var scheduler = require("./lib/scheduler");
var log = require("./lib/log");
var errorPage = require("./lib/error-page");
var cookies = require("./lib/cookies");
var migrations = require("./lib/migrations");
var cli = require("./lib/cli");
var dev = require("./lib/dev");
var bundler = require("./lib/bundler");
var pqcGate = require("./lib/pqc-gate");
var pqcAgent = require("./lib/pqc-agent");
var vaultRotate = require("./lib/vault/rotate");
var vaultPassphraseOps = require("./lib/vault/passphrase-ops");
var mtlsCa = require("./lib/mtls-ca");
var backupCrypto = require("./lib/backup/crypto");
var backupManifest = require("./lib/backup/manifest");
var backupBundle = require("./lib/backup/bundle");
var restoreBundle = require("./lib/restore-bundle");
var backup = require("./lib/backup");
var restoreRollback = require("./lib/restore-rollback");
var restore = require("./lib/restore");
var deprecate = require("./lib/deprecate");
var apiSnapshot = require("./lib/api-snapshot");
var auditTools = require("./lib/audit-tools");
var events = require("./lib/events");
var safeSchema = require("./lib/safe-schema");
var pagination = require("./lib/pagination");
var metrics = require("./lib/metrics");
var tracing = require("./lib/tracing");

module.exports = {
  crypto:           crypto,
  router:           router,
  constants:        constants,
  vault:            vault,
  vaultWrap:        vaultWrap,
  vaultPassphraseSource: vaultPassphraseSource,
  db:               db,
  cryptoField:      cryptoField,
  audit:            audit,
  auditChain:       auditChain,
  auditSign:        auditSign,
  auditTools:       auditTools,
  events:           events,
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
  safeAsync:        safeAsync,
  handlers:         handlers,
  safeSql:          safeSql,
  chainWriter:      chainWriter,
  safeBuffer:       safeBuffer,
  lazyRequire:      lazyRequire,
  frameworkError:   frameworkError,
  logger:           logger,
  httpClient:       httpClient,
  websocket:        websocket,
  safeUrl:          safeUrl,
  authHeader:       authHeader,
  auth:             auth,
  template:         template,
  render:           render,
  staticServe:      staticServe,
  forms:            forms,
  createApp:        app.createApp,
  jobs:             jobs,
  mail:             mail,
  scheduler:        scheduler,
  log:              log,
  errorPage:       errorPage,
  cookies:          cookies,
  migrations:       migrations,
  cli:              cli,
  dev:              dev,
  bundler:          bundler,
  pqcGate:          pqcGate,
  pqcAgent:         pqcAgent,
  vaultRotate:      vaultRotate,
  vaultPassphraseOps: vaultPassphraseOps,
  mtlsCa:           mtlsCa,
  backupCrypto:     backupCrypto,
  backupManifest:   backupManifest,
  backupBundle:     backupBundle,
  restoreBundle:    restoreBundle,
  backup:           backup,
  restoreRollback:  restoreRollback,
  restore:          restore,
  deprecate:        deprecate,
  apiSnapshot:      apiSnapshot,
  safeJson:         safeJson,
  safeSchema:       safeSchema,
  pagination:       pagination,
  metrics:          metrics,
  tracing:          tracing,
  ntpCheck:         ntpCheck,
  version:          constants.version,
};
