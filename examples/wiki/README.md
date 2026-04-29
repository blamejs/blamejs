# blamejs wiki — reference app + docs site

The blamejs wiki is the framework's documentation site, built as a working blamejs app. It is a working reference operators can study to see every primitive wired up in an opinionated baseline configuration.

## Boot

```bash
cd examples/wiki
npm install
WIKI_ADMIN_PASSWORD="some-strong-password" npm start
```

Server listens on `http://localhost:8080` by default. Override with `WIKI_PORT`. Admin credentials via `WIKI_ADMIN_EMAIL` (default `admin@blamejs.app`) and `WIKI_ADMIN_PASSWORD` (required ≥ 8 chars; a random dev password is generated and printed if unset).

## Run the e2e test

```bash
cd examples/wiki
npm test
```

Boots the server in-process on an ephemeral port, hits each route with browser-shaped headers, validates response codes and body content, then shuts down cleanly. **14/14 checks** at present.

## What's wired (baseline-all-features stance)

The wiki is a reference, not a one-off — every in-process primitive the framework ships is wired with operator-safe defaults. Operators copying this app inherit the right baseline.

### Security middleware (all ON)

- `b.middleware.requestId` — every response carries `X-Request-Id`
- `b.middleware.securityHeaders` — HSTS, X-Frame-Options, COOP, COEP, etc.
- `b.middleware.botGuard` — rejects requests missing real-browser headers
- `b.middleware.cors` — same-origin only (`allowedOrigins: []`)
- `b.middleware.rateLimit` — 120 req/min memory token-bucket; `/healthz` skipped
- `b.middleware.cspNonce` — per-request nonce for inline styles/scripts
- `b.middleware.bodyParser` — form-URL-encoded + JSON
- `b.middleware.compression` — Brotli + gzip negotiation
- `b.middleware.attachUser` — session cookie → `req.user`
- `b.middleware.csrfProtect` — POST forms include hidden CSRF token
- `b.middleware.health` — `/healthz` (liveness), `/readyz` (readiness with DB check), `/startupz` (startup)

### State + storage

- `b.db` — SQLite with sealed columns + audit chain + audit signing
- `b.migrations` — `migrations/0001-pages-schema.js` creates pages table + FTS5 mirror + sync triggers
- `b.seeders` — `seeders/prod/0001-default-pages.js` seeds the concern-group nav (rerunnable: true)
- `b.cache` — page-render cache, namespace `wiki.page`, 5-minute TTL, audit-emitting

### Auth

- `b.auth.password` (Argon2id) — admin login
- `b.session` — sealed cookie token, 24h expiry
- `b.permissions` — `admin` and `viewer` roles, `admin` scope gates `/admin/*`

### Rendering

- `b.template` — eval-free template engine, views in `views/`
- `b.render.html` / `b.render.htmlString` / `b.render.json` / `b.render.redirect`
- `b.staticServe` — assets in `public/` (favicon.ico, robots.txt, etc.)

### Localization

- `b.i18n` — wired with English by default. Operators add locales by extending the `translations` object or pointing `dir` at a JSON tree.

### Validation + observability + audit

- `b.slug` — admin save uses `b.slug(value, { fallback })` for URL slug normalization
- `b.audit` — every login / page edit / cache clear / etc. emits with the 5 W's (WHO/WHAT/WHEN/WHERE/HOW) via `b.requestHelpers.extractActorContext`
- `b.observability` — every primitive's events (cache hit/miss, audit emit, etc.) route through here; pluggable to OTel
- `b.metrics` + `b.tracing` — pass-through unless operator wires a real backend

## What's documented but not wired (operator-specific)

These primitives are intentionally NOT wired in the wiki because they require operator-supplied infrastructure (TLS certs, SMTP servers, external DB, etc.). The docs pages explain how operators integrate them:

- `b.cluster` — opt-in HA (active/active leader election)
- `b.externalDb` — Postgres / SQLite-cluster operator-side
- `b.mtlsCa` — operator-managed certificate authority
- `b.pqcGate` — TLS layer for production deploy
- `b.mail` + `b.mailBounce` — SMTP / SES operator setup
- `b.websocket` + `b.websocketChannels` — operator-opt-in for live features
- `b.objectStore` + `b.storage` — S3 / GCS / Azure Blob (operator backend)
- `b.backup` + `b.restore` — CLI workflow
- `b.bundler` — frontend asset bundling (no client JS in the wiki yet)

## Production deploy

The wiki ships with development-friendly defaults (`vault: { mode: "plaintext" }`, `db: { atRest: "plain", auditSigning: { mode: "plaintext" } }`). For production:

1. Set `BLAMEJS_VAULT_PASSPHRASE` (or wire a `vault.passphraseSource`)
2. Change `vault.mode` to `"wrapped"` (default)
3. Change `db.atRest` to `"encrypted"` (default; requires tmpfs at `/dev/shm` or `BLAMEJS_TMPDIR`)
4. Change `db.auditSigning.mode` to `"wrapped"`
5. Deploy behind a TLS-terminating reverse proxy OR enable `b.pqcGate`
6. Set `WIKI_ADMIN_PASSWORD` to a strong value managed by your secret-store

## File layout

```
examples/wiki/
├── package.json                  # depends on @blamejs/core via file:../..
├── server.js                     # createApp boot, all primitives wired
├── routes/
│   ├── pages.js                  # public routes (split: registerSpecific + registerCatchAll)
│   └── admin.js                  # login / logout / dashboard / edit / save (admin-gated)
├── views/
│   ├── _layout.html              # base layout (locale, dir, csp-nonce, csrf-token, user)
│   ├── partials/
│   │   └── nav.html              # concern-group navigation
│   ├── home.html
│   ├── page.html                 # renders DB-stored page bodies
│   ├── login.html
│   ├── search.html
│   └── admin/
│       ├── dashboard.html
│       └── edit.html
├── migrations/
│   └── 0001-pages-schema.js      # pages + FTS5 + sync triggers
├── seeders/
│   └── prod/
│       └── 0001-default-pages.js # nav landing pages
├── public/                       # static assets (favicon etc.)
├── test/
│   └── e2e.js                    # boot-and-probe via node:http with browser headers
└── data/                         # local SQLite + vault key (gitignored)
```

## Known gaps (Phase 11.2 work)

- **Search**: `/search?q=...` works but the search results page needs a few full-coverage docs pages to actually have content to find. v1 just demonstrates the FTS5 wiring.
- **Concern-group pages are stubs**: each landing page (Auth, Storage, HTTP, etc.) currently has a "Coming soon" body. The full coverage tier (~10 pages with primitive walkthrough + code samples) is the next session's work per the Phase 11 roadmap.
- **No client-side JS**: editor is a plain HTML `<textarea>`. A future pass wires `b.bundler` to bundle a tiny editor enhancement (autosave, slug-from-title preview).
- **Search recipe page**: `/observability/search` (or similar) should explain the FTS5 schema, trigger pattern, MATCH grammar, and how operators add this to their own apps. Stub for now.
- **Operator-specific recipe pages**: cluster mode, mail, websocket, etc. — all stubbed, full coverage in subsequent sessions.

These are tracked in the Phase 11 task list; v1 of the engine ships now.
