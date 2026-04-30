# Deploying the wiki

The wiki ships with two compose configurations:

- `docker-compose.yml` — local dev. Builds from source, exposes 8080.
- `docker-compose.prod.yml` — production overlay. Pulls the published GHCR image, fronts it with Caddy for automatic TLS, exposes 80/443.

## Quick deploy to a VPS for `blamejs.app`

Prerequisites:

- A host with Docker + Docker Compose installed
- Inbound 80/443 open
- DNS `A` (and `AAAA` if IPv6) for `blamejs.app` and `www.blamejs.app` pointing at the host
- A stable strong admin password (see `.env` below)

Steps:

```bash
# 1. Get the deploy artifacts onto the host
git clone https://github.com/blamejs/blamejs.git
cd blamejs/examples/wiki

# 2. Configure the .env (every value below is optional except the
#    one explicitly marked REQUIRED — see "Environment variables"
#    section for the full matrix).
cat > .env <<'EOF'
# REQUIRED
WIKI_ADMIN_PASSWORD=<a strong passphrase>

# Recommended once you flip the wiki to wrapped vault mode
BLAMEJS_VAULT_PASSPHRASE=<a different strong passphrase>

# Optional — defaults shown
WIKI_ADMIN_EMAIL=admin@blamejs.app
WIKI_PORT=8080
LOG_LEVEL=info

# Optional — outbound page-edit webhook
WIKI_WEBHOOK_URL=
WIKI_WEBHOOK_SECRET=
EOF
chmod 600 .env

# 3. Start the stack
docker compose -f docker-compose.yml -f docker-compose.prod.yml pull
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d

# 4. Watch the first boot — Caddy will request the cert from
#    Let's Encrypt and the wiki will seed its admin user.
docker compose logs -f
```

When the Caddy logs show `certificate obtained successfully`, the site is live at `https://blamejs.app`.

## Environment variables

The wiki container reads its configuration from environment. `docker-compose.prod.yml` wires every variable below from your `.env`; the Dockerfile sets non-secret defaults so an operator who just wants the basics can leave most blank.

### Wiki app

| Variable | Required? | Default | Purpose |
|---|---|---|---|
| `WIKI_ADMIN_PASSWORD` | **yes (production)** | random + printed to stdout once | Seeded admin login. Setting it explicitly avoids the random-on-each-restart pattern. |
| `WIKI_ADMIN_EMAIL` | no | `admin@blamejs.app` | Seeded admin login email. |
| `WIKI_PORT` | no | `8080` | HTTP listen port inside the container. Caddy proxies to this; rarely overridden. |
| `WIKI_DATA_DIR` | no | `/data` | On-disk path the wiki writes vault key + sqlite + audit chain to. Bound to a Docker volume in the compose. |
| `WIKI_WEBHOOK_URL` | no | unset | Outbound HTTPS endpoint that receives one POST per `wiki.page.edited` event. |
| `WIKI_WEBHOOK_SECRET` | required if URL set | unset | HMAC secret the webhook receiver uses to verify the request signature. |

### Framework (`BLAMEJS_*`)

| Variable | Required? | Default | Purpose |
|---|---|---|---|
| `BLAMEJS_VAULT_PASSPHRASE` | required if vault is in `wrapped` mode | unset | Argon2id-stretched into the vault-key wrapping key. The wiki example app boots plaintext-mode by default; flip `lib/build-app.js`'s `vault: { mode: "plaintext" }` to `"wrapped"` and seal via `blamejs vault seal` once you have a passphrase set. |
| `BLAMEJS_AUDIT_PASSPHRASE` | only when running `blamejs audit` CLI | unset | Used by `blamejs audit archive / export / verify / purge` for the chain-export bundle wrap. Not read at app boot. |
| `BLAMEJS_BACKUP_PASSPHRASE` | only when running `blamejs backup` CLI | unset | Used by `blamejs backup verify / extract` against an existing bundle on disk. Not read at app boot. |
| `BLAMEJS_DEPRECATIONS` | no | `warn` | `warn` (default) emits a structured log line; `throw` makes deprecated calls fail loud (recommended pre-v1); `silent` suppresses. |

### Standard Node

| Variable | Required? | Default | Purpose |
|---|---|---|---|
| `NODE_ENV` | no | `production` | Standard `production`/`development` flag. |
| `LOG_LEVEL` | no | `info` | Structured-log filter. `debug` / `info` / `warn` / `error`. |

### Secrets handling

Every passphrase / webhook secret in the table above is **never** ENV-baked into the image — they're injected at runtime via the `.env` file (compose), Docker secrets, or a secret-manager mount. The `.env` file should be `chmod 600` and excluded from version control. The `Dockerfile` only sets non-secret defaults (`NODE_ENV`, `WIKI_DATA_DIR`, `WIKI_PORT`).

## What's where

- The wiki container persists state in the `wiki-data` named volume — vault key, sealed audit-signing key, sqlite database, audit chain. **Back this up.** Losing it loses the audit chain and admin credentials.
- Caddy persists ACME state in the `caddy-data` named volume. Deleting it forces a re-issuance from scratch — Let's Encrypt rate limits apply, so don't.
- All TLS is Caddy's. The wiki container only speaks HTTP on the compose network.

## Updating to a new version

```bash
# Pin the new version in docker-compose.prod.yml (image: ghcr.io/...:vX.Y.Z)
docker compose -f docker-compose.yml -f docker-compose.prod.yml pull
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

The wiki container's healthcheck on `/healthz` ensures Caddy only routes once the new container is ready.

## Rolling back

```bash
# Edit docker-compose.prod.yml back to the previous image tag.
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d wiki
```

The on-disk schema is forward-compatible within a minor; downgrading across a minor isn't supported.

## Troubleshooting

- **Caddy can't issue cert** — check that ports 80 and 443 are reachable from the public internet (Let's Encrypt's HTTP-01 challenge needs port 80). Run `docker compose logs caddy` for the specific ACME error.
- **Wiki returns 502** — the wiki container's healthcheck is failing. `docker compose logs wiki` shows the cause; usually missing `WIKI_ADMIN_PASSWORD` or a corrupt vault key.
- **Cookies / sessions don't stick** — the wiki sets `Secure` cookies in production. If you're testing on `http://` for some reason, sessions will drop; either add `WIKI_INSECURE_COOKIES=1` (dev only) or use the proper TLS path.
