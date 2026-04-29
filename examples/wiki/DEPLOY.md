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

# 2. Configure the admin password
cat > .env <<'EOF'
WIKI_ADMIN_EMAIL=admin@blamejs.app
WIKI_ADMIN_PASSWORD=<a strong passphrase>
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
