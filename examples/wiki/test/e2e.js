"use strict";
// Wiki app e2e — boots the same wiring as server.js (via shared
// lib/build-app.js) on an ephemeral port, hits each route via node:http
// with realistic browser headers, asserts response codes and body
// content, then shuts down. The bot-guard / Sec-Fetch / rate-limit
// middleware run unmodified; the test sends the headers a real browser
// would. Accept-Encoding: identity opts out of compression so substring
// assertions don't have to decompress.

var http = require("node:http");
var path = require("node:path");
var fs = require("node:fs");
var { buildApp } = require("../lib/build-app");

var DATA_DIR = path.join(__dirname, "..", "data-e2e");
var ADMIN_EMAIL = "admin-e2e@blamejs.app";
var ADMIN_PASSWORD = "e2e-test-password-x9k2";

// Browser-shaped headers — see test docstring above.
var BROWSER_HEADERS = {
  "user-agent":       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "accept":           "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
  "accept-language":  "en-US,en;q=0.9",
  "accept-encoding":  "identity",
  "sec-fetch-dest":   "document",
  "sec-fetch-mode":   "navigate",
  "sec-fetch-site":   "none",
};

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

async function _bootApp() {
  if (fs.existsSync(DATA_DIR)) fs.rmSync(DATA_DIR, { recursive: true, force: true });
  return buildApp({
    dataDir:       DATA_DIR,
    port:          0,                 // ephemeral
    adminEmail:    ADMIN_EMAIL,
    adminPassword: ADMIN_PASSWORD,
  });
}

var checks = 0;
var failures = [];
function assert(name, cond) {
  checks++;
  if (!cond) { failures.push(name); console.error("  ✗ " + name); }
  else       { console.log("  ✓ " + name); }
}

async function run() {
  console.log("[wiki-e2e] booting…");
  var built = await _bootApp();
  // Don't call scheduler.start() in tests — would ref the event loop
  // and prevent clean exit.
  var info = await built.app.listen({ port: 0 });
  var port = info.port;
  console.log("[wiki-e2e] listening on :" + port);

  try {
    var home = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/",
      headers: BROWSER_HEADERS,
    });
    assert("GET / → 200",                    home.statusCode === 200);
    assert("GET / body has 'blamejs'",       /blamejs/i.test(home.body));
    assert("GET / body has nav",             /rail-nav/i.test(home.body));
    assert("GET / loads strict CSP (no unsafe-inline)",
           home.headers["content-security-policy"] &&
           home.headers["content-security-policy"].indexOf("'unsafe-inline'") === -1);
    assert("GET / links Prism CSS",          /\/vendor\/prism\.css/.test(home.body));
    // Bundler emits hashed filenames: /dist/wiki.<16-hex>.js
    assert("GET / links bundled wiki.js",
           /\/dist\/wiki\.[a-f0-9]{16}\.js/.test(home.body));
    assert("GET / links logo SVG",           /\/img\/blamejs-logo\.svg/.test(home.body));

    var health = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/healthz",
      headers: BROWSER_HEADERS,
    });
    assert("GET /healthz → 200",             health.statusCode === 200);
    assert("GET /healthz JSON has status:ok", /"status"\s*:\s*"ok"/.test(health.body));

    var ready = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/readyz",
      headers: BROWSER_HEADERS,
    });
    assert("GET /readyz → 200 (db check passes)", ready.statusCode === 200);

    var welcome = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/welcome/index",
      headers: BROWSER_HEADERS,
    });
    assert("GET /welcome/index → 200",       welcome.statusCode === 200);
    assert("welcome page mentions blamejs",  /blamejs/i.test(welcome.body));
    assert("welcome page has hello-world section",
           /hello-world/.test(welcome.body));
    assert("welcome page has design-tenets section",
           /design-tenets/.test(welcome.body));
    assert("welcome page links to concern groups",
           /\/observability\/index/.test(welcome.body) &&
           /\/auth-permissions\/index/.test(welcome.body));

    var obs = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/observability/index",
      headers: BROWSER_HEADERS,
    });
    assert("GET /observability/index → 200", obs.statusCode === 200);
    assert("observability page covers audit chain",
           /audit chain/i.test(obs.body) && /tamper-evident/i.test(obs.body));
    assert("observability page documents the 5 W's",
           /actor\.userId/.test(obs.body) && /actor\.requestId/.test(obs.body));
    assert("observability page covers tracing pass-through",
           /pass-through/i.test(obs.body) && /OTel/i.test(obs.body));
    assert("observability page includes redaction recipe",
           /b\.redact\.redact/.test(obs.body));

    var auth = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/auth-permissions/index",
      headers: BROWSER_HEADERS,
    });
    assert("GET /auth-permissions/index → 200", auth.statusCode === 200);
    assert("auth page covers passwords + Argon2id",
           /Argon2id/.test(auth.body) && /b\.auth\.password/.test(auth.body));
    assert("auth page covers passkeys (WebAuthn)",
           /WebAuthn/.test(auth.body) && /b\.auth\.passkey/.test(auth.body));
    assert("auth page covers OAuth providers",
           /b\.auth\.oauth/.test(auth.body) && /PKCE/.test(auth.body));
    assert("auth page covers RBAC roles",
           /b\.permissions/.test(auth.body) && /inherits/.test(auth.body));

    var storage = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/storage-state/index",
      headers: BROWSER_HEADERS,
    });
    assert("GET /storage-state/index → 200", storage.statusCode === 200);
    assert("storage page covers sealed columns",
           /sealedFields/.test(storage.body) && /vault\.seal/.test(storage.body));
    assert("storage page covers migrations advisory lock",
           /advisory lock/.test(storage.body) && /SHA3-512/.test(storage.body));
    assert("storage page covers presigned uploads",
           /presignUpload/.test(storage.body) && /SigV4/.test(storage.body));
    assert("storage page covers queue + jobs",
           /b\.queue/.test(storage.body) && /b\.jobs/.test(storage.body));

    var http = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/http-middleware/index",
      headers: BROWSER_HEADERS,
    });
    assert("GET /http-middleware/index → 200", http.statusCode === 200);
    assert("http page documents the default middleware stack",
           /requestId/.test(http.body) && /securityHeaders/.test(http.body) && /csrfProtect/.test(http.body));
    assert("http page covers cspNonce",
           /cspNonce/.test(http.body));
    assert("http page covers safeUrl SSRF defense",
           /safeUrl/.test(http.body) && /SSRF/.test(http.body));

    var crypto = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/crypto-vault/index",
      headers: BROWSER_HEADERS,
    });
    assert("GET /crypto-vault/index → 200", crypto.statusCode === 200);
    assert("crypto page documents the storage envelope",
           /envelope/i.test(crypto.body) && /0xE1/.test(crypto.body));
    assert("crypto page covers ML-KEM + P-384 hybrid",
           /ML-KEM-1024/.test(crypto.body) && /P-384/.test(crypto.body));
    assert("crypto page covers vault wrapped vs plaintext",
           /wrapped/.test(crypto.body) && /BLAMEJS_VAULT_PASSPHRASE/.test(crypto.body));
    assert("crypto page covers PQ signatures",
           /SLH-DSA-SHAKE-256f/.test(crypto.body));

    var testing = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/testing/index",
      headers: BROWSER_HEADERS,
    });
    assert("GET /testing/index → 200", testing.statusCode === 200);
    assert("testing page covers fakeClock",
           /fakeClock/.test(testing.body) && /clk\.advance/.test(testing.body));
    assert("testing page covers captureAudit + captureObservability",
           /captureAudit/.test(testing.body) && /captureObservability/.test(testing.body));

    var notify = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/notify-mail/index",
      headers: BROWSER_HEADERS,
    });
    assert("GET /notify-mail/index → 200", notify.statusCode === 200);
    assert("notify-mail page covers b.notify channels",
           /b\.notify\.channels\.log/.test(notify.body) && /httpJson/.test(notify.body));
    assert("notify-mail page covers websocketChannels fan-out",
           /websocketChannels/.test(notify.body) && /publish/.test(notify.body));
    assert("notify-mail page covers bounce intake",
           /b\.mailBounce/.test(notify.body) && /Postmark/.test(notify.body));

    var i18n = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/i18n-locale/index",
      headers: BROWSER_HEADERS,
    });
    assert("GET /i18n-locale/index → 200", i18n.statusCode === 200);
    assert("i18n page covers ICU MessageFormat plurals",
           /MessageFormat/.test(i18n.body) && /plural/.test(i18n.body));
    assert("i18n page covers RTL detection",
           /req\.dir/.test(i18n.body) && /rtl/.test(i18n.body));

    var prod = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/production-essentials/index",
      headers: BROWSER_HEADERS,
    });
    assert("GET /production-essentials/index → 200", prod.statusCode === 200);
    assert("prod-essentials page covers exactly-once-globally scheduler",
           /exactly once globally/.test(prod.body) && /fencing token/.test(prod.body));
    assert("prod-essentials page covers backup chain",
           /b\.backup/.test(prod.body) && /chained/.test(prod.body));
    assert("prod-essentials page covers ntpCheck",
           /b\.ntpCheck/.test(prod.body));

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

    var anonAdmin = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/admin",
      headers: BROWSER_HEADERS,
    });
    assert("anon GET /admin → 401",          anonAdmin.statusCode === 401);

    var loginGet = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/login",
      headers: BROWSER_HEADERS,
    });
    assert("GET /login → 200",               loginGet.statusCode === 200);
    assert("login form has csrf hidden field", /name="csrf"/.test(loginGet.body));

    // ---- Static asset checks ----
    var prismJs = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/vendor/prism.js",
      headers: Object.assign({}, BROWSER_HEADERS, {
        "sec-fetch-dest": "script", "sec-fetch-mode": "no-cors",
      }),
    });
    assert("GET /vendor/prism.js → 200",     prismJs.statusCode === 200);
    assert("prism.js mentions Prism",        /Prism/.test(prismJs.body));

    // Bundled wiki.js — extract the hashed path from the home HTML
    // and verify staticServe returns the bundled artifact.
    var wikiBundleMatch = home.body.match(/\/dist\/(wiki\.[a-f0-9]{16}\.js)/);
    assert("home HTML includes bundled wiki.js path", !!wikiBundleMatch);
    if (wikiBundleMatch) {
      var bundledWiki = await _request({
        method: "GET", host: "127.0.0.1", port: port, path: "/dist/" + wikiBundleMatch[1],
        headers: Object.assign({}, BROWSER_HEADERS, {
          "sec-fetch-dest": "script", "sec-fetch-mode": "no-cors",
        }),
      });
      assert("GET bundled wiki.js → 200",    bundledWiki.statusCode === 200);
      assert("bundled wiki.js mentions IntersectionObserver",
             /IntersectionObserver/.test(bundledWiki.body));
    }
    // Bundler manifest is published to /dist/manifest.json
    var manifest = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/dist/manifest.json",
      headers: BROWSER_HEADERS,
    });
    assert("GET /dist/manifest.json → 200",  manifest.statusCode === 200);
    assert("manifest maps wiki + editor entries",
           /wiki\.[a-f0-9]{16}\.js/.test(manifest.body) &&
           /editor\.[a-f0-9]{16}\.js/.test(manifest.body));

    var wikiCss = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/wiki.css",
      headers: Object.assign({}, BROWSER_HEADERS, {
        "sec-fetch-dest": "style", "sec-fetch-mode": "no-cors",
      }),
    });
    assert("GET /wiki.css → 200",            wikiCss.statusCode === 200);

    var logo = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/img/blamejs-logo.svg",
      headers: Object.assign({}, BROWSER_HEADERS, {
        "sec-fetch-dest": "image", "sec-fetch-mode": "no-cors",
      }),
    });
    assert("GET /img/blamejs-logo.svg → 200", logo.statusCode === 200);
    assert("logo is SVG",                    /<svg/.test(logo.body));
  } finally {
    await built.app.shutdown();
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
