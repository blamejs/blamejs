"use strict";
/**
 * Initial wiki content — concern-group nav + a working welcome page.
 *
 * The wiki ships ~9 concern-group landing pages + a welcome page.
 * Individual deep-dive pages within each group are added via the admin
 * editor OR by extending this seeder. Per the no-MVP rule for the
 * wiki: ship the engine + a working baseline, expand content over
 * subsequent sessions.
 *
 * rerunnable: true so subsequent seeder runs UPSERT the latest text
 * (operator iteration on welcome / nav copy doesn't need a wipe).
 * Admin-edited pages have their `updatedBy` set to the admin user id;
 * the seeder sets `updatedBy: "seeder"` so the audit chain can
 * distinguish framework-supplied content from operator-authored content.
 */

var GROUPS = [
  {
    slug:        "welcome",
    title:       "Welcome to blamejs",
    body:        "<h1>blamejs — the Node framework that owns its stack.</h1>" +
                 "<p>This wiki is the docs site AND a reference app. " +
                 "Every page you read is a working blamejs app rendering " +
                 "through <code>b.template</code>; primitives like " +
                 "<code>b.cache</code>, <code>b.audit</code>, and " +
                 "<code>b.permissions</code> back the wiki itself.</p>" +
                 "<p>Pick a concern group from the navigation to start.</p>",
  },
  {
    slug:  "auth-permissions",
    title: "Auth &amp; Permissions",
    body:  "<h1>Auth &amp; Permissions</h1>" +
           "<p>Primitives covered here: <code>b.auth.password</code>, " +
           "<code>b.auth.passkey</code>, <code>b.auth.totp</code>, " +
           "<code>b.auth.jwt</code>, <code>b.auth.oauth</code>, " +
           "<code>b.session</code>, <code>b.permissions</code>, " +
           "<code>b.apiKey</code>, <code>b.credentialHash</code>.</p>" +
           "<p><em>Coming soon — full coverage page in progress.</em></p>",
  },
  {
    slug:  "storage-state",
    title: "Storage &amp; State",
    body:  "<h1>Storage &amp; State</h1>" +
           "<p>Primitives covered: <code>b.db</code>, " +
           "<code>b.migrations</code>, <code>b.seeders</code>, " +
           "<code>b.storage</code>, <code>b.objectStore</code>, " +
           "<code>b.queue</code>, <code>b.cache</code>, " +
           "<code>b.cryptoField</code>.</p>" +
           "<p><em>Coming soon — full coverage page in progress.</em></p>",
  },
  {
    slug:  "http-middleware",
    title: "HTTP &amp; Middleware",
    body:  "<h1>HTTP &amp; Middleware</h1>" +
           "<p>Primitives covered: <code>b.router</code>, " +
           "<code>b.middleware</code> (CSRF / CORS / rate-limit / " +
           "compression / security-headers / bot-guard / etc.), " +
           "<code>b.httpClient</code>, <code>b.safeUrl</code>, " +
           "<code>b.requestHelpers</code>.</p>" +
           "<p><em>Coming soon — full coverage page in progress.</em></p>",
  },
  {
    slug:  "crypto-vault",
    title: "Crypto &amp; Vault",
    body:  "<h1>Crypto &amp; Vault</h1>" +
           "<p>Primitives covered: <code>b.crypto</code> (PQC: ML-KEM-1024, " +
           "XChaCha20-Poly1305, SHAKE256, SLH-DSA), <code>b.vault</code>, " +
           "<code>b.cryptoField</code>, <code>b.mtlsCa</code>, " +
           "<code>b.pqcGate</code>, <code>b.webhook</code>.</p>" +
           "<p><em>Coming soon — full coverage page in progress.</em></p>",
  },
  {
    slug:  "observability",
    title: "Observability",
    body:  "<h1>Observability</h1>" +
           "<p>Primitives covered: <code>b.observability</code>, " +
           "<code>b.metrics</code>, <code>b.tracing</code>, " +
           "<code>b.audit</code>, <code>b.auditChain</code>, " +
           "<code>b.log</code>, <code>b.logger</code>, " +
           "<code>b.redact</code>.</p>" +
           "<p><em>Coming soon — full coverage page in progress.</em></p>",
  },
  {
    slug:  "testing",
    title: "Testing",
    body:  "<h1>Testing</h1>" +
           "<p>Primitives covered: <code>b.testing</code> " +
           "(mockReq / mockRes / fakeClock / fakeHttpClient / " +
           "captureAudit / captureObservability / runMiddleware / " +
           "waitFor / tempDir / listenOnRandomPort / makeFakeOtelApi).</p>" +
           "<p><em>Coming soon — full coverage page in progress.</em></p>",
  },
  {
    slug:  "notify-mail",
    title: "Notification &amp; Mail",
    body:  "<h1>Notification &amp; Mail</h1>" +
           "<p>Primitives covered: <code>b.notify</code> (httpJson / log / " +
           "test transports), <code>b.mail</code>, <code>b.mailBounce</code>, " +
           "<code>b.websocket</code>, <code>b.websocketChannels</code>.</p>" +
           "<p><em>Coming soon — full coverage page in progress.</em></p>",
  },
  {
    slug:  "i18n-locale",
    title: "i18n &amp; Locale",
    body:  "<h1>i18n &amp; Locale</h1>" +
           "<p>Primitives covered: <code>b.i18n</code> (translation, " +
           "locale negotiation via Accept-Language, plural rules, " +
           "Intl formatters, RTL detection).</p>" +
           "<p><em>Coming soon — full coverage page in progress.</em></p>",
  },
  {
    slug:  "production-essentials",
    title: "Production Essentials",
    body:  "<h1>Production Essentials</h1>" +
           "<p>Primitives covered: <code>b.cluster</code>, " +
           "<code>b.externalDb</code>, <code>b.backup</code>, " +
           "<code>b.restore</code>, <code>b.scheduler</code>, " +
           "<code>b.jobs</code>, <code>b.retry</code>, " +
           "<code>b.appShutdown</code>, <code>b.ntpCheck</code>.</p>" +
           "<p><em>Coming soon — full coverage page in progress.</em></p>",
  },
];

module.exports = {
  description: "Default wiki nav + welcome page",
  envs:        ["prod", "dev"],
  rerunnable:  true,
  run: async function (db, ctx) {
    var now = ctx.clock();
    for (var i = 0; i < GROUPS.length; i++) {
      var g = GROUPS[i];
      // SQLite UPSERT — INSERT or replace if (groupName, slug) collides.
      db.prepare(
        "INSERT INTO pages (groupName, slug, title, body, updatedAt, updatedBy) " +
        "VALUES (?, ?, ?, ?, ?, ?) " +
        "ON CONFLICT (groupName, slug) DO UPDATE SET " +
        "  title = excluded.title, body = excluded.body, " +
        "  updatedAt = excluded.updatedAt, updatedBy = excluded.updatedBy"
      ).run(
        g.slug,                // groupName === slug for landing pages
        "index",
        g.title,
        g.body,
        now,
        "seeder"
      );
    }
  },
};
