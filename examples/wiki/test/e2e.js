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
        var raw = Buffer.concat(chunks);
        resolve({
          statusCode: res.statusCode,
          headers:    res.headers,
          body:       raw.toString("utf8"),
          rawBuffer:  raw,
        });
      });
    });
    req.on("error", reject);
    req.setTimeout(5000, function () { req.destroy(new Error("request timed out — server stalled")); });
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
    assert("GET / links logo PNG",           /\/img\/blamejs-logo\.png/.test(home.body));

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
    assert("prism.js bundles javascript grammar",
           /Prism\.languages\.javascript/.test(prismJs.body));

    var prismCss = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/vendor/prism.css",
      headers: Object.assign({}, BROWSER_HEADERS, {
        "sec-fetch-dest": "style", "sec-fetch-mode": "no-cors",
      }),
    });
    assert("GET /vendor/prism.css → 200",    prismCss.statusCode === 200);
    assert("prism.css is non-empty (theme actually vendored)",
           prismCss.body.length > 500);
    assert("prism.css defines token rules",
           /\.token\.keyword/.test(prismCss.body) && /\.token\.string/.test(prismCss.body));
    assert("prism.css uses tomorrow theme dark bg",
           /background:#2d2d2d/.test(prismCss.body));

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
      method: "GET", host: "127.0.0.1", port: port, path: "/img/blamejs-logo.png",
      headers: Object.assign({}, BROWSER_HEADERS, {
        "sec-fetch-dest": "image", "sec-fetch-mode": "no-cors",
      }),
    });
    assert("GET /img/blamejs-logo.png → 200", logo.statusCode === 200);
    assert("logo is served as image/png",
           /image\/png/.test(logo.headers["content-type"] || ""));

    // ---- Compression-on path (what real browsers actually do) ----
    // Regression: every other request in this suite uses
    // Accept-Encoding: identity for assertion convenience. That hid
    // a real backpressure stall in the framework's compression
    // middleware where stream.pipe(res) of a file > 16 KB hung
    // because the wrapped res.write returned false on compressor
    // backpressure but never re-emitted 'drain'. These checks force
    // the gzip/br code path so the regression can't recur.
    var zlib = require("node:zlib");
    var COMPRESS_HEADERS = Object.assign({}, BROWSER_HEADERS, {
      "accept-encoding": "gzip, br",
    });

    // Static file served by staticServe + piped through compression.
    // prism.js is 39 KB — well past zlib's 16 KB highWaterMark.
    var prismCompressed = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/vendor/prism.js",
      headers: Object.assign({}, COMPRESS_HEADERS, {
        "sec-fetch-dest": "script", "sec-fetch-mode": "no-cors",
      }),
    });
    assert("compressed prism.js → 200 (no stall)",
           prismCompressed.statusCode === 200);
    assert("compressed prism.js: Content-Encoding present",
           !!prismCompressed.headers["content-encoding"]);
    assert("compressed prism.js: no Content-Length (chunked)",
           prismCompressed.headers["content-length"] === undefined);
    var enc = prismCompressed.headers["content-encoding"];
    var prismDecoded =
      enc === "br"   ? zlib.brotliDecompressSync(prismCompressed.rawBuffer) :
      enc === "gzip" ? zlib.gunzipSync(prismCompressed.rawBuffer) :
                       prismCompressed.rawBuffer;
    assert("compressed prism.js decompresses to bundle",
           /Prism\.languages\.javascript/.test(prismDecoded.toString("utf8")));

    // Templated HTML page served by routes/pages.js + cached + piped
    // through compression.
    var welcomeCompressed = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/welcome/index",
      headers: COMPRESS_HEADERS,
    });
    assert("compressed /welcome/index → 200 (no stall)",
           welcomeCompressed.statusCode === 200);
    assert("compressed /welcome/index: Content-Encoding present",
           !!welcomeCompressed.headers["content-encoding"]);
    var pageEnc = welcomeCompressed.headers["content-encoding"];
    var welcomeDecoded =
      pageEnc === "br"   ? zlib.brotliDecompressSync(welcomeCompressed.rawBuffer) :
      pageEnc === "gzip" ? zlib.gunzipSync(welcomeCompressed.rawBuffer) :
                           welcomeCompressed.rawBuffer;
    var welcomeHtml = welcomeDecoded.toString("utf8");
    assert("compressed welcome page contains body",
           /blamejs/i.test(welcomeHtml) && /<h1/.test(welcomeHtml));
    // CSP nonce must match between header and every rendered script
    // tag (regression for the cached-stale-nonce bug — the page cache
    // held a render with a frozen nonce, but the CSP header rotated
    // per request, so script tags had a nonce the browser rejected).
    var cspMatch = (welcomeCompressed.headers["content-security-policy"] || "")
      .match(/'nonce-([A-Za-z0-9+/=]+)'/);
    var headerNonce  = cspMatch ? cspMatch[1] : null;
    var scriptNonces = [];
    var nonceRe = /<script[^>]+nonce="([^"]+)"/g;
    var m;
    while ((m = nonceRe.exec(welcomeHtml)) !== null) scriptNonces.push(m[1]);
    assert("compressed welcome page: header CSP nonce present", headerNonce !== null);
    assert("compressed welcome page: at least one nonced script",
           scriptNonces.length > 0);
    assert("compressed welcome page: every script nonce matches CSP header nonce",
           headerNonce !== null &&
           scriptNonces.length > 0 &&
           scriptNonces.every(function (n) { return n === headerNonce; }));

    // Second hit — same path, served from page cache. The cached HTML
    // contains a placeholder; substitution at serve time has to give
    // it a fresh nonce that matches the new CSP header.
    var welcome2 = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/welcome/index",
      headers: COMPRESS_HEADERS,
    });
    var cached2enc = welcome2.headers["content-encoding"];
    var welcome2Html = (
      cached2enc === "br"   ? zlib.brotliDecompressSync(welcome2.rawBuffer) :
      cached2enc === "gzip" ? zlib.gunzipSync(welcome2.rawBuffer) :
                              welcome2.rawBuffer
    ).toString("utf8");
    var csp2    = (welcome2.headers["content-security-policy"] || "").match(/'nonce-([A-Za-z0-9+/=]+)'/);
    var script2 = welcome2Html.match(/<script[^>]+nonce="([^"]+)"/);
    assert("cached page re-render: CSP nonce rotates between requests",
           csp2 !== null && headerNonce !== null && csp2[1] !== headerNonce);
    assert("cached page re-render: script nonce tracks the new CSP nonce",
           csp2 !== null && script2 !== null && script2[1] === csp2[1]);

    // ---- Page-content completeness ----
    // Walk every concern-group landing page, extract internal links
    // and code-block language classes, and verify they all resolve /
    // are valid. Catches things like a typo'd <a href="/auht-...">
    // (typo) or a <code class="language-rust"> when Rust isn't in the
    // Prism bundle.
    var GROUPS = [
      "welcome", "observability", "auth-permissions", "storage-state",
      "http-middleware", "crypto-vault", "testing",
      "notify-mail", "i18n-locale", "production-essentials",
    ];
    // Evaluate the bundle in a sandbox and read Prism.languages directly.
    // Source-text scanning misses languages bound through the IIFE
    // local (e.g. `e.languages.bash` inside `(function(e){...})(Prism)`).
    var vm = require("node:vm");
    var sandbox = {
      window:                 {},
      self:                   {},
      document:               { readyState: "complete", currentScript: null, addEventListener: function () {}, getElementsByTagName: function () { return []; } },
      Element:                function () {},
      requestAnimationFrame:  function () {},
    };
    sandbox.window = sandbox; sandbox.self = sandbox;
    vm.createContext(sandbox);
    vm.runInContext(prismJs.body, sandbox, { filename: "prism.js" });
    var prismLangs = new Set(Object.keys((sandbox.Prism && sandbox.Prism.languages) || {}));
    assert("Prism bundle exposes javascript + bash + html",
           prismLangs.has("javascript") && prismLangs.has("bash") && prismLangs.has("html"));

    var allInternalLinks = new Set();
    var allLanguages     = new Set();
    for (var gi = 0; gi < GROUPS.length; gi++) {
      var page = await _request({
        method: "GET", host: "127.0.0.1", port: port, path: "/" + GROUPS[gi] + "/index",
        headers: BROWSER_HEADERS,
      });
      assert("completeness: GET /" + GROUPS[gi] + "/index → 200", page.statusCode === 200);
      var bodyOnly = page.body;
      // Internal links — only paths that start with "/" and don't
      // include "://"; ignore hash-only fragments.
      var linkRe = /href="(\/[a-z0-9][a-z0-9/_\-#]*)"/g;
      var lm = bodyOnly.match(linkRe) || [];
      lm.forEach(function (s) {
        var href = s.replace(/^href="/, "").replace(/"$/, "");
        var withoutHash = href.indexOf("#") === -1 ? href : href.slice(0, href.indexOf("#"));
        if (withoutHash) allInternalLinks.add(withoutHash);
      });
      // Code-block languages
      var codeRe = /<code\s+class="language-([a-z0-9]+)"/g;
      var cm = bodyOnly.match(codeRe) || [];
      cm.forEach(function (s) {
        var lang = s.replace(/^<code\s+class="language-/, "").replace(/"$/, "");
        allLanguages.add(lang);
      });
    }
    assert("completeness: scanned ≥10 internal links",     allInternalLinks.size >= 10);
    assert("completeness: scanned ≥3 code-block languages", allLanguages.size >= 3);

    // Every language used in a docs code block must be loadable by
    // the Prism bundle we ship.
    var unknownLangs = [];
    allLanguages.forEach(function (lang) {
      if (!prismLangs.has(lang)) unknownLangs.push(lang);
    });
    assert("completeness: every code-block language is in the Prism bundle " +
           (unknownLangs.length > 0 ? "(unknown: " + unknownLangs.join(",") + ")" : ""),
           unknownLangs.length === 0);

    // Every internal link resolves (2xx or 3xx). Skips links to
    // /admin (auth-gated) and /login (form route).
    var brokenLinks = [];
    var linksToFetch = [];
    allInternalLinks.forEach(function (link) {
      if (link === "/admin" || link === "/login" || link === "/logout") return;
      linksToFetch.push(link);
    });
    for (var li = 0; li < linksToFetch.length; li++) {
      var link = linksToFetch[li];
      var resp = await _request({
        method: "GET", host: "127.0.0.1", port: port, path: link,
        headers: BROWSER_HEADERS,
      });
      if (resp.statusCode < 200 || resp.statusCode >= 400) {
        brokenLinks.push(link + " → " + resp.statusCode);
      }
    }
    assert("completeness: every internal link resolves (no 4xx/5xx) " +
           (brokenLinks.length > 0 ? "broken: " + brokenLinks.join(", ") : ""),
           brokenLinks.length === 0);
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
