"use strict";
/**
 * blamejs wiki/docs reference app — production entry.
 *
 * All framework wiring lives in lib/build-app.js so the e2e suite can
 * boot the same configuration in-process. This file is the env-var
 * + signal-handler shim around buildApp.
 *
 * Env vars:
 *   WIKI_DATA_DIR        directory for vault key + sqlite db (default ./data)
 *   WIKI_PORT            HTTP port (default 8080)
 *   WIKI_ADMIN_EMAIL     admin user email (default admin@blamejs.app)
 *   WIKI_ADMIN_PASSWORD  admin password — required ≥ 8 chars; a random
 *                        dev password is generated and printed if unset
 *   WIKI_WEBHOOK_URL     optional outbound page-edit webhook URL
 *   WIKI_WEBHOOK_SECRET  HMAC-SHA3-512 signing key for the webhook
 */

var path = require("node:path");
var nodeCrypto = require("node:crypto");
var { buildApp } = require("./lib/build-app");

var DATA_DIR       = process.env.WIKI_DATA_DIR    || path.join(__dirname, "data");
var PORT           = parseInt(process.env.WIKI_PORT || "8080", 10);
var ADMIN_EMAIL    = process.env.WIKI_ADMIN_EMAIL || "admin@blamejs.app";
var ADMIN_PASSWORD = process.env.WIKI_ADMIN_PASSWORD || null;
var WEBHOOK_URL    = process.env.WIKI_WEBHOOK_URL    || null;
var WEBHOOK_SECRET = process.env.WIKI_WEBHOOK_SECRET || null;

function _resolveAdminPassword() {
  if (ADMIN_PASSWORD && ADMIN_PASSWORD.length >= 8) return ADMIN_PASSWORD;
  var generated = nodeCrypto.randomBytes(18).toString("base64url");
  console.warn("[wiki] WARNING: WIKI_ADMIN_PASSWORD not set; using generated dev password:");
  console.warn("[wiki]          email = " + ADMIN_EMAIL);
  console.warn("[wiki]          password = " + generated);
  console.warn("[wiki] Set WIKI_ADMIN_PASSWORD in env for stable production credentials.");
  return generated;
}

(async function main() {
  var built = await buildApp({
    dataDir:       DATA_DIR,
    port:          PORT,
    adminEmail:    ADMIN_EMAIL,
    adminPassword: _resolveAdminPassword(),
    webhookUrl:    WEBHOOK_URL,
    webhookSecret: WEBHOOK_SECRET,
  });

  // Start the scheduler (timer-based; refs the event loop until shutdown)
  built.scheduler.start();

  var info = await built.app.listen({ port: PORT });
  console.log("[wiki] listening on http://localhost:" + info.port);
  console.log("[wiki] admin login: " + ADMIN_EMAIL);
  if (WEBHOOK_URL) {
    console.log("[wiki] page-edit webhooks → " + WEBHOOK_URL);
  }

  function _shutdown() {
    console.log("[wiki] shutting down...");
    built.scheduler.stop().catch(function () {});
    built.app.shutdown().then(
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
