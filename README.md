# blamejs

**The Node framework that owns its stack.**

One install. One upgrade path. One place to look when something breaks — no blame to pass between forty transitive dependencies you didn't choose.

---

## Why blamejs

The modern Node app is a 1,200-package supply-chain liability with no LTS calendar, no curator, and no accountability. Frameworks peer-depend their internals onto you and call it modularity. blamejs takes the opposite stance:

- **Vendored standard library.** Auth, sessions, jobs, mail, storage, crypto, ORM, templating — bundled with the framework, not hunted on npm. Your `package.json` has one entry.
- **Security as a default, not a config flag.** Post-quantum-aware crypto envelopes, sealed-by-default storage, server-rendered output, CSRF/origin/bot defenses, per-account brute-force lockout, all wired in from line zero.
- **Server-rendering first.** HTML out of the box; client JS is opt-in islands, not the foundation.
- **A real LTS calendar.** Major versions on a published cadence with documented deprecation windows. No silent semver-major surprises in transitive deps.

## Status

Pre-1.0. Usable end-to-end — operators can build production apps on it today; the surface is still subject to change before 1.0. Recent line is **v0.6.3** ([releases](https://github.com/blamejs/blamejs/releases) · [npm](https://www.npmjs.com/package/@blamejs/core) · [container](https://github.com/blamejs/blamejs/pkgs/container/blamejs-wiki)).

```js
var b = require("@blamejs/core");

(async function () {
  var app = await b.createApp({
    dataDir: "./data",
    routes: function (router) {
      router.get("/", function (req, res) {
        b.render.htmlString(res, "<h1>Hello from blamejs</h1>");
      });
    },
  });
  await app.listen({ port: 3000 });
})();
```

**Requirements:** Node.js 24+ (current active LTS).

## What ships in the box

The framework bundles the surface a typical Node app reaches for. Every primitive listed is callable today; nothing is a stub.

- **Data layer** — SQLite with sealed-by-default columns (`b.db`), migrations, seeders, atomic-file writes; bring-your-own external Postgres / MySQL / etc. with pool tuning + role-aware connect + read-replica routing (`b.externalDb`); declarative role-narrowed views and Postgres row-level-security migrations (`b.db.declareView`, `b.db.declareRowPolicy`); S3 / R2 / B2 / GCS / Azure object store with multipart upload + SSE + bucket ops (`b.storage`, `b.objectStore`); durable queue with priority + cron + flows (`b.queue`, `b.jobs`); cluster-shared cache (`b.cache`).
- **Identity & access** — passwords (Argon2id), passkeys (WebAuthn), TOTP, JWT (PQ-default), OAuth, sessions, brute-force lockout (`b.auth.*`, `b.session`); RBAC with optional per-role DB binding (`b.permissions`, role-spec `dbRole` field); API keys with rotation (`b.apiKey`); break-glass column gates with second-factor + audit (`b.breakGlass`).
- **Crypto** — envelope-versioned PQC at rest (ML-KEM-1024 + P-384 hybrid, XChaCha20-Poly1305, SHAKE256), vault sealing, field-level crypto, signed webhooks (SLH-DSA-SHAKE-256f), ECIES API encryption (`b.crypto`, `b.vault`, `b.webhook`); pure-JS mTLS CA, PQC TLS gates inbound + outbound (`b.mtlsCa`, `b.pqcGate`, `b.pqcAgent`).
- **HTTP** — router with schema-validated routes + OpenAPI publication; full middleware stack (CSRF, CORS, rate-limit, security headers, CSP nonce, body parser, compression, SSE, request log, request-time DB role binding via `b.middleware.dbRoleFor`) wired by `createApp`; HTTP/1.1 + HTTP/2 outbound client with SSRF gate, redirects, multipart, interceptors, progress, encrypted cookie jar (`b.httpClient`, `b.ssrfGuard`, `b.safeUrl`).
- **Defensive parsers** — `b.safeJson`, `b.safeBuffer`, `b.safeSql`, `b.safeSchema`, `b.parsers` (XML / TOML / YAML / .env), `b.config` (schema-validated env).
- **Communication** — WebSockets with channel/room fan-out across cluster replicas (`b.websocket`, `b.websocketChannels`); mail with multipart + attachments + DKIM + calendar invites + bounce intake (`b.mail`, `b.mailBounce`); generic notification dispatcher with operator-supplied transports (`b.notify`).
- **Observability** — tamper-evident audit chain with SLH-DSA-signed checkpoints, metrics, tracing (OTel pass-through when wired), PII redaction, log-stream sinks, OTLP/HTTP-JSON exporter for any OTel-compatible backend (`b.audit`, `b.metrics`, `b.tracing`, `b.redact`, `b.logStream`, `b.otelExport`).
- **i18n** — CLDR plural rules, Accept-Language negotiation, Intl formatters, RTL (`b.i18n`).
- **Format helpers** — RFC 4180 CSV with Excel formula-injection prevention (`b.csv`), RFC 9562 UUID v4 + v7 (`b.uuid`), URL-safe slugs (`b.slug`), TZ-aware datetime (`b.time`), ZIP creation (`b.archive`), HMAC-signed cursor pagination (`b.pagination`), HTML form rendering + validation + CSRF (`b.forms`).
- **Production** — cluster leader election with fenced leases over Postgres/SQLite (`b.cluster`); cron + interval scheduler that runs exactly-once globally (`b.scheduler`); retry with full-jitter backoff + circuit breaker (`b.retry`); graceful shutdown (`b.appShutdown`); NTP boot check (`b.ntpCheck`); end-to-end-encrypted backup bundles (`b.backup`).

## Documentation

Full primitive-by-primitive docs live at [blamejs.com](https://blamejs.com), which is itself the `examples/wiki/` app running in production. The wiki is organized by concern:

- **Data** — [Database](https://blamejs.com/database) · [Object Store](https://blamejs.com/object-store) · [Queue & Cache](https://blamejs.com/queue-cache)
- **Identity** — [Authentication](https://blamejs.com/auth) · [Access Control](https://blamejs.com/access-control)
- **Crypto** — [Crypto & Vault](https://blamejs.com/crypto-vault) · [Network Crypto](https://blamejs.com/network-crypto)
- **HTTP** — [Routing](https://blamejs.com/routing) · [Middleware](https://blamejs.com/middleware) · [Outbound HTTP](https://blamejs.com/outbound-http)
- **Validation** — [Safe Parsers](https://blamejs.com/safe-parsers)
- **Communication** — [WebSockets](https://blamejs.com/websockets) · [Mail](https://blamejs.com/mail) · [Notifications](https://blamejs.com/notifications)
- **Tools** — [Observability](https://blamejs.com/observability) · [Testing](https://blamejs.com/testing) · [i18n & Locale](https://blamejs.com/i18n-locale) · [Format Helpers](https://blamejs.com/format-helpers)
- **Compliance** — [Compliance Patterns](https://blamejs.com/compliance-patterns)
- **Production** — [Cluster Mode](https://blamejs.com/cluster) · [Reliability](https://blamejs.com/reliability) · [Backup & Restore](https://blamejs.com/backup-restore)

## CLI

`blamejs` ships an operator-facing CLI for the recurring ops work. Each subcommand boots a headless app instance from `--data-dir` (no HTTP listener), runs the operation, and shuts down. Same vault + DB + audit chain the running app uses.

```
blamejs migrate    up | down | status                   --db <path> [--dir <path>]
blamejs seed       run | status                         --db <path> --env <name> [--dir <path>]
blamejs vault      status | seal | unseal | rotate      --data-dir <path>
blamejs backup     inspect | verify | extract           --bundle <dir>
blamejs api-key    issue | revoke | list | rotate | verify   --data-dir <path> --namespace <ns>
blamejs mtls       status | show-cert | init | issue | issue-p12   --data-dir <path>
blamejs audit      archive | export | verify-bundle | purge
blamejs api-snapshot   capture | compare                --file <path>
blamejs dev        --command <cmd> [--watch <dir>...]
```

Pass `--help` to any subcommand for the full flag list. Passphrases for crypto-backed operations resolve from the appropriate env var (`BLAMEJS_VAULT_PASSPHRASE`, `BLAMEJS_BACKUP_PASSPHRASE`, `BLAMEJS_AUDIT_PASSPHRASE`) so they don't end up in shell history.

## Reference app + deployment

`examples/wiki/` is a complete production-ready operator-built blamejs app — the wiki you're looking at when you visit `blamejs.com`. It demonstrates every framework primitive in real usage and ships with `Dockerfile`, `docker-compose.yml` (dev), `docker-compose.prod.yml` (Caddy + GHCR image), and a published OCI image at `ghcr.io/blamejs/blamejs-wiki:<tag>` (multi-arch amd64/arm64, cosign-signed via GitHub OIDC, Trivy-scanned, SHA3-512 digest).

See [`examples/wiki/DEPLOY.md`](examples/wiki/DEPLOY.md) for the full deployment walkthrough, including the operator-facing environment-variable matrix (`WIKI_*` and `BLAMEJS_*` keys) and the pin-to-version workflow for production updates.

## Vendored dependencies

All runtime dependencies are committed to the repo — no transitive npm install at runtime, no `node_modules` lookup path for production. Server-side deps are bundled via `scripts/vendor-update.sh`:

```bash
./scripts/vendor-update.sh --check                  # see what's outdated
./scripts/vendor-update.sh --diff @noble/ciphers    # see changelog before bumping
./scripts/vendor-update.sh @noble/ciphers 2.2.0     # bundle + commit a new version
```

| Package | Version | Author | Purpose |
|---|---|---|---|
| [`@noble/ciphers`](https://github.com/paulmillr/noble-ciphers) | 2.2.0 | [Paul Miller](https://github.com/paulmillr) | XChaCha20-Poly1305 AEAD |
| [`@simplewebauthn/server`](https://github.com/MasterKale/SimpleWebAuthn) | 13.3.0 | [Matthew Miller](https://github.com/MasterKale) | WebAuthn / passkey verification |
| [`argon2`](https://github.com/ranisalt/node-argon2) | 0.44.0 | [Ranieri Althoff](https://github.com/ranisalt) | Password hashing (native prebuilds, 8 platforms) |
| [`@peculiar/x509`](https://github.com/PeculiarVentures/x509) + [`pkijs`](https://github.com/PeculiarVentures/PKI.js) | 2.0.0 + 3.4.0 | [Peculiar Ventures](https://github.com/PeculiarVentures) | Pure-JS mTLS CA — ECDSA P-384 cert signing, PKCS#12 packaging (no openssl CLI) |
| [`prismjs`](https://prismjs.com/) | 1.30.0 | [Lea Verou + contributors](https://github.com/PrismJS/prism) | Syntax highlighting in the example wiki's code blocks (browser-side) |

These libraries are exceptional work — blamejs wouldn't exist without them. All are MIT licensed. Per-package version, license, and provenance live in two manifests: [`lib/vendor/MANIFEST.json`](lib/vendor/MANIFEST.json) for the framework's server-side bundles and [`examples/wiki/public/vendor/MANIFEST.json`](examples/wiki/public/vendor/MANIFEST.json) for the wiki app's browser-side bundle. The framework's [`NOTICE`](NOTICE) file carries the upstream attributions.

## Why "blamejs"

Because when something breaks, `blame` should know exactly where it lives. We own the stack so you don't have to chase the fault across an ecosystem.

## Contributing

Patches welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the dev setup, house rules (zero npm runtime deps, PQC-only crypto, audit-on-every-action, ship-complete-not-incremental), and the PR loop. New to the codebase? Start with [ARCHITECTURE.md](ARCHITECTURE.md) for the orientation map.

Community standards: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) (Contributor Covenant 2.1). Be excellent.

## Security

Threat model, supported versions, vulnerability disclosure: [SECURITY.md](SECURITY.md). Do **not** file public issues for security bugs — email `security@blamejs.com`.

## License

Apache-2.0. See [LICENSE](LICENSE) for the full text and [NOTICE](NOTICE) for attribution of vendored components.
