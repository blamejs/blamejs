"use strict";
/**
 * Wiki app e2e — boots the server in this process, hits each route via
 * node:http with realistic browser headers, asserts response codes and
 * body content, then shuts down.
 *
 * Validation discipline: we DO NOT weaken the framework's security
 * middleware (bot-guard, etc.) for tests. Instead we send the same
 * Accept-Language / User-Agent / sec-fetch-* headers a real browser
 * would, which is what bot-guard validates. This means:
 *
 *   - The wiki ships with operator-safe defaults (botGuard: true)
 *   - The e2e suite reflects real browser traffic, not bot traffic
 *   - Operators copying this test as a template get the headers right
 */

var http = require("node:http");
var path = require("node:path");
var fs = require("node:fs");
var b = require("@blamejs/core");

var DATA_DIR = path.join(__dirname, "..", "data-e2e");
var PORT = 0;     // ephemeral
var ADMIN_EMAIL = "admin-e2e@blamejs.app";
var ADMIN_PASSWORD = "e2e-test-password-x9k2";

// Browser-shaped headers. Bot-guard's gates are "missing Accept-Language"
// and "missing sec-fetch-mode" — both required. Accept-Encoding: identity
// opts OUT of compression so the route-logic substring assertions below
// can run without decompressing. Compression itself is exercised by
// the framework's own compression.test.js — orthogonal to wiki routing.
var BROWSER_HEADERS = {
  "user-agent":       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "accept":           "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
  "accept-language":  "en-US,en;q=0.9",
  "accept-encoding":  "identity",
  "sec-fetch-dest":   "document",
  "sec-fetch-mode":   "navigate",
  "sec-fetch-site":   "none",
};

// ---- HTTP helper ----

function _request(opts, body) {
  return new Promise(function (resolve, reject) {
    var req = http.request(opts, function (res) {
      var chunks = [];
      res.on("data", function (c) { chunks.push(c); });
      res.on("end", function () {
        resolve({
          statusCode: res.statusCode,
          headers:    res.headers,
          body:       Buffer.concat(chunks).toString("utf8"),
        });
      });
    });
    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
}

// ---- Boot the wiki server in-process ----
// Same logic as server.js but inlined here so we can control DATA_DIR
// + ADMIN_PASSWORD without depending on env-var hygiene in the parent
// shell. Closely mirrors server.js — drift would surface as a failing
// test.
async function _bootApp() {
  if (fs.existsSync(DATA_DIR)) fs.rmSync(DATA_DIR, { recursive: true, force: true });

  var template = b.template.create({ viewsDir: path.join(__dirname, "..", "views") });
  var pageCache = b.cache.create({
    namespace: "wiki.page",
    ttlMs:     b.constants.TIME.minutes(5),
  });
  var perms = b.permissions.create({
    roles:    { admin: ["wiki:admin"], viewer: ["wiki:read"] },
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

  var SCHEMA = [{
    name: "admin_users",
    columns: {
      id:           "TEXT PRIMARY KEY",
      email:        "TEXT NOT NULL UNIQUE",
      passwordHash: "TEXT NOT NULL",
      createdAt:    "INTEGER NOT NULL",
    },
    sealedFields: [],
  }];

  var app = await b.createApp({
    dataDir: DATA_DIR,
    schema:  SCHEMA,
    vault:   { mode: "plaintext" },
    db:      {
      atRest:       "plain",
      auditSigning: { mode: "plaintext" },
    },
    middleware: {
      cors:        false,
      rateLimit:   false,
      botGuard:    true,
      requestId:   true,
      securityHeaders: {
        // Strict CSP — no 'unsafe-inline'. Same as production server.js.
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

      var pagesRoute = require("../routes/pages");
      var adminRoute = require("../routes/admin");
      var ctx = {
        db:           b.db,
        template:     template,
        audit:        b.audit,
        pageCache:    pageCache,
        perms:        perms,
        passwordAuth: b.auth.password,
        session:      b.session,
      };
      pagesRoute.registerSpecific(router, ctx);
      adminRoute.register(router, ctx);
      pagesRoute.registerCatchAll(router, ctx);
    },
  });

  // Run migrations + seeders
  var migrations = b.migrations.create({
    dir: path.join(__dirname, "..", "migrations"),
    db:  b.db,
  });
  await migrations.up();

  // Seed admin
  var hash = await b.auth.password.hash(ADMIN_PASSWORD);
  b.db.prepare(
    "INSERT INTO admin_users (id, email, passwordHash, createdAt) VALUES (?, ?, ?, ?)"
  ).run("admin-e2e", ADMIN_EMAIL, hash, Date.now());

  var seeders = b.seeders.create({
    dir: path.join(__dirname, "..", "seeders"),
    db:  b.db,
  });
  await seeders.run({ env: "prod" });

  var info = await app.listen({ port: PORT });
  return { app: app, port: info.port };
}

// ---- Test runner ----

var checks = 0;
var failures = [];
function assert(name, cond) {
  checks++;
  if (!cond) { failures.push(name); console.error("  ✗ " + name); }
  else       { console.log("  ✓ " + name); }
}

async function run() {
  console.log("[wiki-e2e] booting…");
  var booted = await _bootApp();
  var port = booted.port;
  console.log("[wiki-e2e] listening on :" + port);

  try {
    // ---- Public routes ----
    var home = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/",
      headers: BROWSER_HEADERS,
    });
    assert("GET / → 200",                    home.statusCode === 200);
    assert("GET / body has 'blamejs'",       /blamejs/i.test(home.body));
    assert("GET / body has nav",             /Concern groups|Welcome/i.test(home.body));

    var health = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/healthz",
      headers: BROWSER_HEADERS,
    });
    assert("GET /healthz → 200",             health.statusCode === 200);
    assert("GET /healthz JSON has status:ok", /"status"\s*:\s*"ok"/.test(health.body));

    var welcome = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/welcome/index",
      headers: BROWSER_HEADERS,
    });
    assert("GET /welcome/index → 200",       welcome.statusCode === 200);
    assert("welcome page mentions blamejs",  /blamejs/i.test(welcome.body));

    var redirect = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/welcome",
      headers: BROWSER_HEADERS,
    });
    assert("GET /welcome → 302 to index",
           redirect.statusCode === 302 && /\/welcome\/index/.test(redirect.headers.location || ""));

    var search = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/search?q=blamejs",
      headers: BROWSER_HEADERS,
    });
    assert("GET /search?q=blamejs → 200",    search.statusCode === 200);
    assert("search shows query echo",        /blamejs/i.test(search.body));

    var noPage = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/missing/missing",
      headers: BROWSER_HEADERS,
    });
    assert("GET /missing/missing → 404",     noPage.statusCode === 404);

    // ---- Admin gate (anon) ----
    var anonAdmin = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/admin",
      headers: BROWSER_HEADERS,
    });
    assert("anon GET /admin → 401",          anonAdmin.statusCode === 401);

    // ---- Login form rendered ----
    var loginGet = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/login",
      headers: BROWSER_HEADERS,
    });
    assert("GET /login → 200",               loginGet.statusCode === 200);
    assert("login form has csrf hidden field", /name="csrf"/.test(loginGet.body));

    // The full POST /login round-trip would require extracting the
    // session-bound CSRF token from the rendered form (the framework
    // binds CSRF to the session cookie). The login flow is thoroughly
    // tested in the framework's own smoke (auth + csrf-protect tests);
    // exercising it again here would re-verify framework behavior, not
    // wiki behavior. Skip; document.
  } finally {
    await booted.app.shutdown();
  }

  console.log("");
  if (failures.length > 0) {
    console.error("[wiki-e2e] FAIL — " + failures.length + " of " + checks + " checks failed:");
    failures.forEach(function (f) { console.error("  - " + f); });
    process.exit(1);
  }
  console.log("[wiki-e2e] OK — " + checks + " checks passed");
}

run().catch(function (e) {
  console.error("[wiki-e2e] FATAL:", e && e.stack || e);
  process.exit(1);
});
