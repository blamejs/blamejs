"use strict";
/**
 * createApp — factory that wires the framework's primitives into a
 * runnable application.
 *
 * Without this factory an operator boots the framework manually:
 *
 *   await b.vault.init({...});
 *   if (cluster mode)  b.externalDb.init({...});
 *   if (cluster mode)  await b.cluster.init({...});
 *   if (cluster mode)  await b.frameworkSchema.ensureSchema({...});
 *   await b.db.init({...});
 *   var r = new b.router.Router();
 *   r.use(b.middleware.requestId());
 *   r.use(b.middleware.securityHeaders());
 *   r.use(b.middleware.botGuard());
 *   yourRoutes(r);
 *   r.onError(b.middleware.errorHandler());
 *   var server = r.listen(port, ...);
 *
 * createApp collapses that into:
 *
 *   var app = await createApp({
 *     dataDir:   "./data",
 *     schema:    [...],
 *     routes:    function (r) { r.get("/", ...); },
 *   });
 *   await app.listen({ port: 3000 });
 *
 * Each underlying module remains accessible (b.vault, b.db, b.cluster,
 * etc.) — createApp doesn't hide them, it just orchestrates the
 * dependency-ordered boot.
 *
 * Boot order is fixed because the dependency graph is fixed:
 *
 *   vault.init        — derives encryption keys
 *      ↓
 *   externalDb.init   — connection pool (cluster mode only)
 *      ↓
 *   cluster.init      — leader election, fencing token (opt-in)
 *      ↓
 *   frameworkSchema   — audit/consent/sessions/queue tables
 *     .ensureSchema     in external-db when cluster mode (opt-in;
 *                       skip when operator wants gates-only)
 *      ↓
 *   db.init           — local SQLite + audit chain verify + audit
 *                       checkpoint verify + audit-tip rollback check
 *                       (single-node) or cluster boot checks (cluster)
 *      ↓
 *   router.Router()
 *   middleware stack mounted in canonical order
 *   operator routes registered
 *   error handler attached via router.onError()
 *
 * Default middleware: requestId + securityHeaders + botGuard +
 * errorHandler (mounted as the route-error catcher). cors and
 * rateLimit are opt-in only — both require explicit configuration
 * (origins, thresholds) that the framework can't sensibly default.
 *
 * Operators disable any default middleware by passing
 * `middleware: { requestId: false, securityHeaders: false, ... }`.
 *
 * Public API:
 *
 *   await createApp(opts)  →  app
 *
 *   app.router             — the b.router.Router instance (operator
 *                            adds late routes / inspects state)
 *   app.db, app.vault      — re-exports for convenience; nothing app-
 *                            specific lives on these
 *
 *   await app.listen(opts2?)
 *     opts2.port  (default opts.port, then 0 = ephemeral)
 *     opts2.host  (default opts.host, then unspecified)
 *     opts2.tls   (TLS options forwarded to router.listen — h2 + h1)
 *     → { port, host, server }   the bound port + the underlying
 *                                 http(s).Server instance for ops use
 *
 *   app.address()
 *     → { port, host } | null    bound socket info post-listen
 *
 *   await app.shutdown()
 *     Closes WebSockets gracefully (timeoutMs default 5s), closes
 *     the http server, then unwinds cluster / db / externalDb.
 *     Idempotent — safe to call repeatedly.
 *
 * Validation: opts.dataDir is required. Other config is optional with
 * documented defaults. Schema is optional too — apps with no app-
 * level tables still get the framework tables (sessions, queue jobs,
 * audit_log, consent_log).
 */
var path = require("path");
var fs = require("fs");
var vault = require("./vault");
var db = require("./db");
var cluster = require("./cluster");
var externalDb = require("./external-db");
var frameworkSchema = require("./framework-schema");
var middleware = require("./middleware");
var routerMod = require("./router");
var queue = require("./queue");
var jobsMod = require("./jobs");

function _resolveMiddlewareOpt(value, allowDefault) {
  // value can be:
  //   false          — operator opted out
  //   undefined      — fall back to allowDefault (mount with empty opts)
  //   true           — explicit opt-in with default opts
  //   object         — explicit opts
  if (value === false) return null;
  if (value === undefined) return allowDefault ? {} : null;
  if (value === true) return {};
  if (value && typeof value === "object") return value;
  return null;
}

async function createApp(opts) {
  if (!opts || typeof opts !== "object") {
    throw new Error("createApp: opts object is required");
  }
  if (!opts.dataDir || typeof opts.dataDir !== "string") {
    throw new Error("createApp: opts.dataDir is required");
  }
  var dataDir = path.resolve(opts.dataDir);
  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
  }

  // ---- 1. Vault ----
  var vaultOpts = Object.assign({ dataDir: dataDir }, opts.vault || {});
  if (!vaultOpts.mode) vaultOpts.mode = "wrapped";
  await vault.init(vaultOpts);

  // ---- 2. External DB (cluster mode) ----
  if (opts.externalDb) {
    externalDb.init(opts.externalDb);
  }

  // ---- 3. Cluster (opt-in) ----
  if (opts.cluster) {
    // Schema needs to exist before cluster.init's boot-time rollback
    // check tries to read _blamejs_audit_tip — if cluster has an
    // externalDbBackend AND the operator hasn't disabled the schema
    // step, ensure schemas first.
    if (opts.cluster.externalDbBackend && opts.frameworkSchema !== false) {
      await frameworkSchema.ensureSchema({
        externalDbBackend: opts.cluster.externalDbBackend,
        dialect:           opts.cluster.dialect || "postgres",
      });
    }
    await cluster.init(opts.cluster);
  }

  // ---- 4. Local DB ----
  var dbOpts = Object.assign({
    dataDir: dataDir,
    schema:  opts.schema || [],
  }, opts.db || {});
  await db.init(dbOpts);

  // ---- 5. Jobs (opt-in) ----
  // Operator-supplied callback that defines named handlers. We boot
  // queue with a default 'local' backend (the framework's built-in
  // SQLite-backed protocol) before invoking the callback. Operators
  // who want a different backend pass opts.queue: { backends: { … } }
  // and skip opts.jobs, then wire jobs themselves.
  var jobsInstance = null;
  if (typeof opts.jobs === "function") {
    var queueConfig = opts.queue || { backends: { primary: { protocol: "local" } } };
    queue.init(queueConfig);
    jobsInstance = jobsMod.create(opts.jobsOptions || {});
    opts.jobs(jobsInstance);
    await jobsInstance.start();
  } else if (opts.queue) {
    // Operator wants queue without the jobs sugar (rare, but legitimate
    // — they'll call queue.consume themselves).
    queue.init(opts.queue);
  }

  // ---- 6. Router + middleware ----
  var router = new routerMod.Router();
  var mwConfig = opts.middleware || {};

  var requestIdOpts = _resolveMiddlewareOpt(mwConfig.requestId, true);
  if (requestIdOpts) router.use(middleware.requestId(requestIdOpts));

  var securityHeadersOpts = _resolveMiddlewareOpt(mwConfig.securityHeaders, true);
  if (securityHeadersOpts) router.use(middleware.securityHeaders(securityHeadersOpts));

  var corsOpts = _resolveMiddlewareOpt(mwConfig.cors, false);
  if (corsOpts) router.use(middleware.cors(corsOpts));

  var botGuardOpts = _resolveMiddlewareOpt(mwConfig.botGuard, true);
  if (botGuardOpts) router.use(middleware.botGuard(botGuardOpts));

  var rateLimitOpts = _resolveMiddlewareOpt(mwConfig.rateLimit, false);
  if (rateLimitOpts) router.use(middleware.rateLimit(rateLimitOpts));

  // ---- 6. Operator routes ----
  if (typeof opts.routes === "function") {
    opts.routes(router);
  }

  // ---- 7. Error handler — last so it catches everything ----
  var errorHandlerOpts = _resolveMiddlewareOpt(mwConfig.errorHandler, true);
  if (errorHandlerOpts) {
    router.onError(middleware.errorHandler(errorHandlerOpts));
  }

  // ---- App handle ----
  var server = null;
  var listenPort = null;
  var listenHost = null;
  var shutdownInFlight = null;

  function listen(listenOpts) {
    listenOpts = listenOpts || {};
    var port = (listenOpts.port !== undefined) ? listenOpts.port
             : (opts.port !== undefined) ? opts.port
             : 0;
    var host = listenOpts.host || opts.host;
    var tls  = listenOpts.tls  || opts.tls;
    return new Promise(function (resolve, reject) {
      try {
        server = router.listen(port, function () {
          var addr = server.address();
          if (addr && typeof addr === "object") {
            listenPort = addr.port;
            listenHost = addr.address;
          }
          resolve({ port: listenPort, host: listenHost, server: server });
        }, tls, host);
      } catch (e) { reject(e); }
    });
  }

  function address() {
    if (!server) return null;
    return { port: listenPort, host: listenHost };
  }

  async function shutdown() {
    if (shutdownInFlight) return shutdownInFlight;
    shutdownInFlight = (async function () {
      if (server) {
        try { await router.closeWebSockets({ timeoutMs: 5000 }); } catch (_e) {}
        await new Promise(function (resolve) {
          server.close(function () { resolve(); });
        });
        server = null;
      }
      // Stop consuming + drain in-flight jobs before db.close — handlers
      // are still using the local sqlite handle for queue rows.
      if (jobsInstance) {
        try { await jobsInstance.shutdown({ timeoutMs: 5000 }); } catch (_e) {}
      } else {
        try { await queue.shutdown({ timeoutMs: 5000 }); } catch (_e) {}
      }
      try { await cluster.shutdown(); } catch (_e) {}
      try { db.close(); } catch (_e) {}
      try { await externalDb.shutdown(); } catch (_e) {}
    })();
    return shutdownInFlight;
  }

  return {
    router:    router,
    db:        db,
    vault:     vault,
    jobs:      jobsInstance,
    listen:    listen,
    address:   address,
    shutdown:  shutdown,
  };
}

module.exports = { createApp: createApp };
