"use strict";
// buildApp — single source of truth for the wiki's framework wiring.
// Both server.js and test/e2e.js call this so the live and in-process
// boots stay in sync.
//
// Call shape:
//   var app = await buildApp({
//     dataDir:       "./data",
//     port:          8080,            // 0 for ephemeral
//     adminEmail:    "admin@blamejs.app",
//     adminPassword: "...",           // optional; null skips seed
//     webhookUrl:    null,
//     webhookSecret: null,
//   });
//
// Returns { app, info? } from b.createApp + listen.

var path = require("node:path");
var b = require("@blamejs/core");

// Strict CSP — drops 'unsafe-inline' from style-src + script-src. All
// assets are external; cspNonce middleware adds 'nonce-XYZ' when the
// app actually needs an inline element.
var STRICT_CSP =
  "default-src 'self'; " +
  "script-src 'self'; " +
  "style-src 'self'; " +
  "img-src 'self' data:; " +
  "font-src 'self'; " +
  "connect-src 'self'; " +
  "frame-ancestors 'none'; " +
  "base-uri 'self'; " +
  "form-action 'self'; " +
  "object-src 'none';";

// Schema for admin_users (pages table is owned by migrations/).
// _blamejs_api_keys is part of FRAMEWORK_SCHEMA so the framework
// creates it automatically — apiKey usage just needs the registry.
var SCHEMA = [
  {
    name: "admin_users",
    columns: {
      id:           "TEXT PRIMARY KEY",
      email:        "TEXT NOT NULL UNIQUE",
      passwordHash: "TEXT NOT NULL",
      createdAt:    "INTEGER NOT NULL",
    },
    sealedFields: [],
  },
];

async function buildApp(opts) {
  opts = opts || {};
  if (!opts.dataDir) throw new Error("buildApp: opts.dataDir is required");

  var dataDir = opts.dataDir;
  var port = opts.port !== undefined ? opts.port : 8080;
  var adminEmail = opts.adminEmail || "admin@blamejs.app";
  var adminPassword = opts.adminPassword || null;
  var webhookUrl = opts.webhookUrl || null;
  var webhookSecret = opts.webhookSecret || null;

  // ---- Build client assets via b.bundler ----
  // Hashes wiki.js + editor.js into public/dist/<name>.<hash>.js so
  // operators get cache-busting via filename and SRI-friendly content
  // hashes. Manifest map ({ wiki: "wiki.4a8c.js", ... }) is passed to
  // templates as `assets.<name>` so views render the hashed path.
  var bundler = b.bundler.create({
    entries: {
      wiki:   path.join(__dirname, "..", "src", "wiki.js"),
      editor: path.join(__dirname, "..", "src", "editor.js"),
    },
    outdir:   path.join(__dirname, "..", "public", "dist"),
    manifest: "manifest.json",
    hashLen:  16,
  });
  var bundleResult = await bundler.build();
  var assets = {};
  for (var i = 0; i < bundleResult.outputs.length; i++) {
    var out = bundleResult.outputs[i];
    // outputs[].path is absolute; we want the URL-style relative to
    // the public/ root: "/dist/<filename>".
    assets[out.name] = "/dist/" + path.basename(out.path);
  }

  // ---- Build framework primitives ----
  var template = b.template.create({
    viewsDir: path.join(__dirname, "..", "views"),
  });

  var pageCache = b.cache.create({
    namespace: "wiki.page",
    ttlMs:     b.constants.TIME.minutes(5),
    audit:     b.audit,
  });

  var perms = b.permissions.create({
    roles: { admin: ["wiki:admin"], viewer: ["wiki:read"] },
    audit: b.audit,
    resolver: function (req) {
      if (!req.user) return null;
      return { scopes: req.user.scopes || [] };
    },
  });

  var i18n = b.i18n.create({
    defaultLocale: "en",
    locales:       ["en"],
    translations:  { en: {} },
  });

  var healthChecks = b.middleware.health({
    livenessPath:  "/healthz",
    readinessPath: "/readyz",
    startupPath:   "/startupz",
  });
  healthChecks.registerCheck("db", function () {
    try { b.db.prepare("SELECT 1").get(); return true; }
    catch (_e) { return false; }
  }, { tier: "readiness", critical: true });

  // ---- Notify dispatcher ----
  // Always-on: log channel for dev visibility.
  // Operator-gated: webhook channel if WIKI_WEBHOOK_URL + _SECRET set.
  var notifyChannels = {
    log: b.notify.transports.log({ name: "wiki.log" }),
  };
  var webhookSigner = null;
  if (webhookUrl && webhookSecret) {
    // Compose b.webhook.signer with notify.transports.httpJson via the
    // signing hook — operator-side webhook receivers verify the
    // X-Signature header to prove origin.
    webhookSigner = b.webhook.signer({
      algo: "hmac-sha3-512",
      keys: { v1: webhookSecret },
    });
    notifyChannels.webhook = b.notify.transports.httpJson({
      url:     webhookUrl,
      name:    "wiki.webhook",
      signing: { sign: function (body) { return webhookSigner.headers(body); } },
    });
  }
  var notify = b.notify.create({
    channels: notifyChannels,
    audit:    b.audit,
  });

  // ---- API key registry (content-management keys) ----
  var apiKeys = b.apiKey.create({
    namespace: "wiki",
    audit:     b.audit,
  });

  // ---- Boot the app ----
  var app = await b.createApp({
    dataDir: dataDir,
    schema:  SCHEMA,
    vault:   { mode: "plaintext" },     // examples — production = wrapped
    db:      {
      atRest:       "plain",
      auditSigning: { mode: "plaintext" },
    },
    port:    port,
    middleware: {
      requestId:       true,
      securityHeaders: { csp: STRICT_CSP },
      botGuard:        true,
      cors: {
        allowedOrigins:   [],
        allowCredentials: false,
      },
      rateLimit: {
        backend:         "memory",
        burst:           120,
        refillPerSecond: 2,
        skip: function (req) { return req.url === "/healthz"; },
      },
    },
    routes: function (router) {
      router.use(healthChecks.middleware());
      router.use(b.middleware.bodyParser({ formUrlEncoded: true, json: true }));
      router.use(b.middleware.cspNonce());
      router.use(b.middleware.compression());
      router.use(i18n.middleware());

      router.use(b.middleware.attachUser({
        cookieName: "wiki_sid",
        tokenFrom:  "cookie",
        userLoader: async function (verifiedSession) {
          var row = b.db.prepare(
            "SELECT id, email FROM admin_users WHERE id = ?"
          ).get(verifiedSession.userId);
          if (!row) return null;
          var scopes = (verifiedSession.data && Array.isArray(verifiedSession.data.scopes))
            ? verifiedSession.data.scopes : [];
          return { userId: row.id, email: row.email, scopes: scopes };
        },
      }));
      router.use(b.middleware.csrfProtect({
        tokenLookup: function (req) { return (req.body && req.body.csrf) || null; },
      }));
      router.use(b.staticServe.create({
        root: path.join(__dirname, "..", "public"),
      }));

      // ---- Public + admin routes ----
      // Order: specific paths first, then admin, then /:group catch-all.
      var pagesRoute = require("../routes/pages");
      var adminRoute = require("../routes/admin");
      var routeCtx = {
        db:           b.db,
        template:     template,
        audit:        b.audit,
        pageCache:    pageCache,
        perms:        perms,
        passwordAuth: b.auth.password,
        session:      b.session,
        notify:       notify,
        apiKeys:      apiKeys,
        assets:       assets,
      };
      pagesRoute.registerSpecific(router, routeCtx);
      adminRoute.register(router, routeCtx);
      pagesRoute.registerCatchAll(router, routeCtx);
    },
  });

  // ---- Run migrations (pages + FTS5) ----
  var migrations = b.migrations.create({
    dir: path.join(__dirname, "..", "migrations"),
    db:  b.db,
  });
  await migrations.up();

  // ---- Seed admin user if missing ----
  if (adminPassword) {
    var existingAdmin = b.db.prepare(
      "SELECT id FROM admin_users WHERE email = ?"
    ).get(adminEmail);
    if (!existingAdmin) {
      var hash = await b.auth.password.hash(adminPassword);
      b.db.prepare(
        "INSERT INTO admin_users (id, email, passwordHash, createdAt) VALUES (?, ?, ?, ?)"
      ).run(
        "admin-" + require("node:crypto").randomBytes(8).toString("hex"),
        adminEmail,
        hash,
        Date.now()
      );
    }
  }

  // ---- Run page seeders for prod env ----
  var seeders = b.seeders.create({
    dir: path.join(__dirname, "..", "seeders"),
    db:  b.db,
  });
  await seeders.run({ env: "prod" });

  // ---- Scheduler: periodic session purge + cache stats ----
  // Direct-function tasks (no jobs needed for these housekeepers).
  // Cluster-mode operators get exactly-once-globally behavior via the
  // scheduler's tick-claim table; single-process apps just run once.
  var scheduler = b.scheduler.create();
  scheduler.schedule({
    name:  "wiki.session.purge",
    every: b.constants.TIME.hours(1),
    run:   async function () {
      var n = await b.session.purgeExpired();
      b.observability.event("wiki.session.purged", n, { task: "wiki.session.purge" });
    },
  });
  scheduler.schedule({
    name:  "wiki.cache.stats",
    every: b.constants.TIME.minutes(5),
    run:   async function () {
      try {
        var size = await pageCache.size();
        b.observability.event("wiki.cache.size", size, {});
      } catch (_e) { /* observability best-effort */ }
    },
  });
  // Schedule timers ref the event loop; in tests we want to skip start
  // to avoid keeping the process alive. Operators (server.js) call start.

  return {
    app:       app,
    notify:    notify,
    apiKeys:   apiKeys,
    scheduler: scheduler,
    pageCache: pageCache,
    assets:    assets,
    bundler:   bundler,
  };
}

module.exports = { buildApp: buildApp };
