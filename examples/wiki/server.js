"use strict";
/**
 * blamejs wiki/docs reference app.
 *
 * Boots through b.app.createApp, wiring:
 *   - vault (plaintext for examples; operators use mode:wrapped in prod)
 *   - db with schema for admin_users (pages table is owned by migrations)
 *   - migrations (pages + FTS5)
 *   - seeders (default pages)
 *   - admin user seed (from WIKI_ADMIN_EMAIL + WIKI_ADMIN_PASSWORD)
 *   - template engine pointed at views/
 *   - page-render cache
 *   - permissions (admin role)
 *   - middleware stack: requestId, securityHeaders, cspNonce,
 *     compression, bodyParser, attachUser, csrfProtect, ...
 *   - routes (public pages + admin)
 *
 * Composition over invention — every concern routes through an
 * existing framework primitive. The wiki engine itself is ~200 lines
 * because the framework owns retry / audit / cache / session / etc.
 */

var path = require("node:path");
var b = require("@blamejs/core");

var DATA_DIR = process.env.WIKI_DATA_DIR || path.join(__dirname, "data");
var PORT     = parseInt(process.env.WIKI_PORT || "8080", 10);
var ADMIN_EMAIL    = process.env.WIKI_ADMIN_EMAIL    || "admin@blamejs.app";
var ADMIN_PASSWORD = process.env.WIKI_ADMIN_PASSWORD || null;

// In dev (no password set) we generate a random one at first boot and
// log it. Production deployments MUST set WIKI_ADMIN_PASSWORD; the
// boot warning makes the dev-shortcut visible.
function _resolveAdminPassword() {
  if (ADMIN_PASSWORD && ADMIN_PASSWORD.length >= 8) return ADMIN_PASSWORD;
  // 24-char base64url; printed on stderr at boot so dev operators
  // can grab it. Stable across restarts WITHIN the same boot only —
  // operators wanting reproducible dev creds set the env var.
  var generated = require("node:crypto").randomBytes(18).toString("base64url");
  console.warn("[wiki] WARNING: WIKI_ADMIN_PASSWORD not set; using generated dev password:");
  console.warn("[wiki]          email = " + ADMIN_EMAIL);
  console.warn("[wiki]          password = " + generated);
  console.warn("[wiki] Set WIKI_ADMIN_PASSWORD in env for stable production credentials.");
  return generated;
}

// ---- Schema for admin_users (pages table is owned by migrations/) ----
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

(async function main() {
  var adminPassword = _resolveAdminPassword();

  // ---- Build framework primitives the routes need ----
  var template = b.template.create({ viewsDir: path.join(__dirname, "views") });
  var pageCache = b.cache.create({
    namespace: "wiki.page",
    ttlMs:     b.constants.TIME.minutes(5),
    audit:     b.audit,
  });
  var perms = b.permissions.create({
    roles: {
      admin:  ["wiki:admin"],
      viewer: ["wiki:read"],
    },
    audit: b.audit,
    // Resolver tells permissions where to look for the actor's scopes.
    // Our session middleware writes scopes onto req.user via the
    // session data, so the default resolver works.
    resolver: function (req) {
      if (!req.user) return null;
      return { scopes: req.user.scopes || [] };
    },
  });
  // i18n — wired with English only by default. Operators add locales
  // by editing the `translations` object or pointing `dir` at a JSON
  // tree. The middleware below populates req.locale / req.dir / req.t
  // and mirrors them to res.locals for template auto-merge.
  var i18n = b.i18n.create({
    defaultLocale: "en",
    locales:       ["en"],
    translations:  {
      en: {
        searchPlaceholder: "Search the docs",
        adminLogin:        "admin login",
        signedInAs:        "Signed in as {email}",
        logout:            "log out",
      },
    },
  });
  // Health checks via b.middleware.health — replaces the manual
  // /healthz route. Liveness always 200; readiness verifies db is
  // initialized; both flip to 503 during graceful shutdown.
  var healthChecks = b.middleware.health({
    livenessPath:  "/healthz",
    readinessPath: "/readyz",
    startupPath:   "/startupz",
  });
  healthChecks.registerCheck("db", function () {
    // db.prepare throws if not initialized; truthy = ready.
    try { b.db.prepare("SELECT 1").get(); return true; }
    catch (_e) { return false; }
  }, { tier: "readiness", critical: true });

  // ---- Boot the app ----
  var app = await b.createApp({
    dataDir: DATA_DIR,
    schema:  SCHEMA,
    vault:   { mode: "plaintext" }, // examples use plaintext; production = wrapped
    db:      {
      atRest:       "plain",                  // examples = plain; production = encrypted (tmpfs-backed)
      auditSigning: { mode: "plaintext" },    // examples = plaintext; production = wrapped (passphrase)
    },
    port:    PORT,
    middleware: {
      // Security defaults ON across the board (no opt-out for
      // convenience). Operators copying this app as a template
      // inherit these defaults; making any of them opt-in here
      // would teach the wrong lesson.
      requestId:       true,
      securityHeaders: {
        // Tighter CSP than the framework default — drop
        // 'unsafe-inline' from style-src. The wiki ships zero inline
        // styles or scripts; everything is in external files served
        // from 'self'. cspNonce middleware (mounted later) injects
        // 'nonce-XYZ' into script-src + style-src so operators
        // adding inline content opt-in via a nonce attr — there is
        // NO 'unsafe-inline' fallback.
        csp:
          "default-src 'self'; " +
          "script-src 'self'; " +
          "style-src 'self'; " +
          "img-src 'self' data:; " +
          "font-src 'self'; " +
          "connect-src 'self'; " +
          "frame-ancestors 'none'; " +
          "base-uri 'self'; " +
          "form-action 'self'; " +
          "object-src 'none';",
      },
      botGuard:        true,
      cors: {
        // Wiki serves itself only — no cross-origin browser app
        // calling it. allowedOrigins: [] means same-origin only;
        // any cross-origin preflight is rejected.
        allowedOrigins: [],
        allowCredentials: false,
      },
      rateLimit: {
        // Memory backend uses a token-bucket: `burst` is the bucket
        // size, `refillPerSecond` keeps it topped up. Sized for a
        // public docs site browsed by humans, low enough to throttle
        // automated abuse. Operators behind a CDN can switch to
        // backend: "cluster" for cross-process limits.
        backend:         "memory",
        burst:           120,
        refillPerSecond: 2,     // ≈ 120/min sustained
        skip: function (req) {
          // /healthz is hit by monitors; never throttle.
          return req.url === "/healthz";
        },
      },
    },
    routes: function (router) {
      // ---- Migrations + seeders + admin seed (one-shot at boot) ----
      // We register a deferred-to-first-request task; cleaner is a
      // pre-listen hook, but createApp doesn't expose one. The boot
      // runs migrations synchronously below before the listen call.

      // ---- Health checks (mounted early so probes don't hit downstream middleware) ----
      router.use(healthChecks.middleware());

      // ---- Body parsing for forms ----
      router.use(b.middleware.bodyParser({ formUrlEncoded: true, json: true }));

      // ---- CSP nonce (per-request token wired into res.locals) ----
      router.use(b.middleware.cspNonce());

      // ---- Compression for HTML/text responses ----
      router.use(b.middleware.compression());

      // ---- i18n: req.locale / req.t / req.dir + res.locals mirrors ----
      router.use(i18n.middleware());

      // ---- Attach-user from session cookie ----
      router.use(b.middleware.attachUser({
        cookieName: "wiki_sid",
        tokenFrom:  "cookie",
        userLoader: async function (verifiedSession) {
          var row = b.db.prepare(
            "SELECT id, email FROM admin_users WHERE id = ?"
          ).get(verifiedSession.userId);
          if (!row) return null;
          // Scopes come from the session-data envelope written at login.
          var scopes = (verifiedSession.data && Array.isArray(verifiedSession.data.scopes))
            ? verifiedSession.data.scopes
            : [];
          return {
            userId: row.id,
            email:  row.email,
            scopes: scopes,
          };
        },
      }));

      // ---- CSRF protect for state-changing form POSTs ----
      router.use(b.middleware.csrfProtect({
        // Token lookup: read from req.body.csrf for form POSTs.
        tokenLookup: function (req) {
          return (req.body && req.body.csrf) || null;
        },
      }));

      // ---- Static assets (always-on; public/ ships empty so the
      // mount point exists for operator additions like favicon, robots.txt) ----
      router.use(b.staticServe.create({ root: path.join(__dirname, "public") }));

      // ---- Public + admin routes ----
      // Order matters: specific routes (/, /healthz, /search) first,
      // then operator-specific routes (/login, /admin/*), THEN the
      // /:group catch-all last. The router matches in registration
      // order — if /:group registered first, /login would 302 to
      // /login/index instead of rendering the login form.
      var pagesRoute = require("./routes/pages");
      var adminRoute = require("./routes/admin");
      var routeCtx = {
        db:           b.db,
        template:     template,
        audit:        b.audit,
        pageCache:    pageCache,
        perms:        perms,
        passwordAuth: b.auth.password,
        session:      b.session,
      };
      pagesRoute.registerSpecific(router, routeCtx);
      adminRoute.register(router, routeCtx);
      pagesRoute.registerCatchAll(router, routeCtx);
    },
  });

  // ---- Run pages migration (against the framework's b.db) ----
  // b.migrations.create points at the migrations/ directory; running
  // up() here is idempotent (the migrations table tracks applied state).
  var migrations = b.migrations.create({
    dir: path.join(__dirname, "migrations"),
    db:  b.db,
  });
  await migrations.up();

  // ---- Seed admin user if missing ----
  var existingAdmin = b.db.prepare(
    "SELECT id FROM admin_users WHERE email = ?"
  ).get(ADMIN_EMAIL);
  if (!existingAdmin) {
    var hash = await b.auth.password.hash(adminPassword);
    b.db.prepare(
      "INSERT INTO admin_users (id, email, passwordHash, createdAt) VALUES (?, ?, ?, ?)"
    ).run(
      "admin-" + require("node:crypto").randomBytes(8).toString("hex"),
      ADMIN_EMAIL,
      hash,
      Date.now()
    );
    console.log("[wiki] seeded admin user " + ADMIN_EMAIL);
  }

  // ---- Run page seeders for prod env ----
  var seed = b.seeders.create({
    dir: path.join(__dirname, "seeders"),
    db:  b.db,
  });
  await seed.run({ env: "prod" });

  // ---- Listen ----
  var info = await app.listen({ port: PORT });
  console.log("[wiki] listening on http://localhost:" + info.port);
  console.log("[wiki] admin login: " + ADMIN_EMAIL);

  // ---- Graceful shutdown ----
  function _shutdown() {
    console.log("[wiki] shutting down...");
    app.shutdown().then(
      function () { process.exit(0); },
      function (e) { console.error("[wiki] shutdown error:", e); process.exit(1); }
    );
  }
  process.once("SIGINT",  _shutdown);
  process.once("SIGTERM", _shutdown);
})().catch(function (e) {
  console.error("[wiki] FATAL:", (e && e.stack) || e);
  process.exit(1);
});
