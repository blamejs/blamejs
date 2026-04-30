"use strict";
/**
 * blamejs — public API entry point.
 *
 * The Node framework that owns its stack.
 *
 * Public surface lives on the exported object below — see
 * `module.exports` for the authoritative list. Notable groupings:
 *
 *   Crypto:       crypto, vault, vaultWrap, vaultPassphraseSource,
 *                 vaultPassphraseOps, vaultRotate, cryptoField, mtlsCa,
 *                 pqcGate, pqcAgent
 *   Storage:      db, storage, objectStore, queue, externalDb,
 *                 frameworkSchema, clusterStorage, session, atomicFile,
 *                 cookies
 *   Audit:        audit, auditChain, auditSign, auditTools, consent,
 *                 subject, events, redact
 *   HTTP:         router, middleware (csrf, cors, rate-limit, request-id,
 *                 security-headers, bot-guard, attach-user, require-auth,
 *                 error-handler, body-parser, csp-nonce, compression,
 *                 health, api-encrypt), httpClient, websocket,
 *                 websocketChannels, nonceStore
 *   Auth:         auth.{password,totp,passkey,jwt,oauth,lockout}, authHeader
 *   Render:       template, render, staticServe, forms, errorPage
 *   App:          createApp, jobs, mail, mailBounce, scheduler,
 *                 appShutdown
 *   Backup:       backup, backupCrypto, backupManifest, backupBundle,
 *                 restore, restoreBundle, restoreRollback
 *   DX:           log, dev, bundler, cli, migrations, deprecate,
 *                 apiSnapshot
 *   Validation:   safeSchema, safeJson, safeSql, safeBuffer, safeUrl,
 *                 safeAsync, parsers, pagination
 *   Observability: metrics, tracing, ntpCheck, logStream
 *   Cluster:      cluster (leader election + write-side gates), handlers,
 *                 chainWriter, lazyRequire, frameworkError
 *   Constants:    constants (version-stable namespace), version
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
var retry = require("./lib/retry");
// objectStoreRetry is preserved as a re-export of the canonical b.retry
// for backward compatibility with consumers of the pre-v0.2.24 surface.
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
var httpClient = require("./lib/http-client");
// Attach the encrypted-payload helper from the api-encrypt middleware so
// `b.httpClient.encrypted({ pubkey, baseUrl })` is available alongside
// the bare `b.httpClient.request(...)`. The api-encrypt module owns the
// implementation; httpClient stays free of an api-encrypt dependency.
httpClient.encrypted = require("./lib/middleware/api-encrypt").httpClient;
httpClient.cookieJar = require("./lib/http-client-cookie-jar");
var websocket = require("./lib/websocket");
var safeUrl = require("./lib/safe-url");
var ssrfGuard = require("./lib/ssrf-guard");
var authHeader = require("./lib/auth-header");
var auth = {
  password: require("./lib/auth/password"),
  totp:     require("./lib/auth/totp"),
  passkey:  require("./lib/auth/passkey"),
  jwt:      require("./lib/auth/jwt"),
  oauth:    require("./lib/auth/oauth"),
  lockout:  require("./lib/auth/lockout"),
};
var template = require("./lib/template");
var render = require("./lib/render");
var htmlBalance = require("./lib/html-balance");
var validateOpts = require("./lib/validate-opts");
var cliHelpers = require("./lib/cli-helpers");
var staticServe = require("./lib/static");
var forms = require("./lib/forms");
var app = require("./lib/app");
var jobs = require("./lib/jobs");
var mail = require("./lib/mail");
var mailBounce = require("./lib/mail-bounce");
var websocketChannels = require("./lib/websocket-channels");
var nonceStore = require("./lib/nonce-store");
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
var mtlsEngine = require("./lib/mtls-engine-default");
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
var observability = require("./lib/observability");
var protocolDispatcher = require("./lib/protocol-dispatcher");
var requestHelpers = require("./lib/request-helpers");
var appShutdown = require("./lib/app-shutdown");
var slug = require("./lib/slug");
var webhook = require("./lib/webhook");
var apiKey = require("./lib/api-key");
var credentialHash = require("./lib/credential-hash");
var permissions = require("./lib/permissions");
var cache = require("./lib/cache");
var seeders = require("./lib/seeders");
var i18n = require("./lib/i18n");
var notify = require("./lib/notify");
var testing = require("./lib/testing");

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
  retry:            retry,
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
  httpClient:       httpClient,
  websocket:        websocket,
  safeUrl:          safeUrl,
  ssrfGuard:        ssrfGuard,
  authHeader:       authHeader,
  auth:             auth,
  template:         template,
  render:           render,
  htmlBalance:      htmlBalance,
  validateOpts:     validateOpts,
  cliHelpers:       cliHelpers,
  staticServe:      staticServe,
  forms:            forms,
  createApp:        app.createApp,
  jobs:             jobs,
  mail:             mail,
  mailBounce:       mailBounce,
  websocketChannels: websocketChannels,
  nonceStore:        nonceStore,
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
  mtlsEngine:       mtlsEngine,
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
  observability:    observability,
  protocolDispatcher: protocolDispatcher,
  requestHelpers:   requestHelpers,
  appShutdown:      appShutdown,
  slug:             slug,
  webhook:          webhook,
  apiKey:           apiKey,
  credentialHash:   credentialHash,
  permissions:      permissions,
  cache:            cache,
  seeders:          seeders,
  i18n:             i18n,
  notify:           notify,
  testing:          testing,
  ntpCheck:         ntpCheck,
  version:          constants.version,
};
