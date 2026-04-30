# blamejs

**The Node framework that owns its stack.**

One install. One upgrade path. One place to look when something breaks — no blame to pass between forty transitive dependencies you didn't choose.

---

## Why blamejs

The modern Node app is a 1,200-package supply-chain liability with no LTS calendar, no curator, and no accountability. Frameworks peer-depend their internals onto you and call it modularity. blamejs takes the opposite stance:

- **Vendored standard library.** Auth, sessions, jobs, mail, storage, crypto, ORM, templating — bundled with the framework, not hunted on npm. Your `package.json` has one entry.
- **Security as a default, not a config flag.** Post-quantum-aware crypto envelopes, sealed-by-default storage, server-rendered output, CSRF/origin/bot defenses wired in from line zero.
- **Server-rendering first.** HTML out of the box; client JS is opt-in islands, not the foundation.
- **A real LTS calendar.** Major versions on a published cadence with documented deprecation windows. No silent semver-major surprises in transitive deps.

## Status

Pre-1.0. The framework is usable end-to-end — envelope-versioned PQC crypto, sealed storage, HTTP router with a full middleware stack, vault, sessions, permissions, audit chain, scheduler, jobs, notify, mail, websocket, i18n, cluster mode, backup/restore, a wiki reference app under `examples/wiki/`. Operators can build production apps on it today; the surface is still subject to change before 1.0.

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

## CLI

`blamejs` ships an operator-facing CLI for the recurring ops work. Each subcommand boots a headless app instance from `--data-dir` (no HTTP listener), runs the operation, and shuts down. Same vault + DB + audit chain the running app uses.

```
blamejs migrate    up | down | status   --db <path> [--dir <path>]
blamejs seed       run | status         --db <path> --env <name> [--dir <path>]
blamejs vault      status | seal | unseal | rotate   --data-dir <path>
blamejs backup     inspect | verify | extract        --bundle <dir>
blamejs api-key    issue | revoke | list | rotate | verify   --data-dir <path> --namespace <ns>
blamejs audit      archive | export | verify-bundle | purge
blamejs api-snapshot                    (CI gate for public API drift)
blamejs dev        --command <cmd> [--watch <dir>...]
```

Pass `--help` to any subcommand for the full flag list. Passphrases for crypto-backed operations resolve from the appropriate env var (`BLAMEJS_VAULT_PASSPHRASE`, `BLAMEJS_BACKUP_PASSPHRASE`, `BLAMEJS_AUDIT_PASSPHRASE`) so they don't end up in shell history.

## Reference app + deployment

`examples/wiki/` is a complete production-ready operator-built blamejs app — the wiki you're looking at when you visit `blamejs.app`. It demonstrates every framework primitive in real usage and ships with `Dockerfile`, `docker-compose.yml` (dev), `docker-compose.prod.yml` (Caddy + GHCR image), and a published OCI image at `ghcr.io/blamejs/blamejs-wiki:<tag>` (multi-arch amd64/arm64, cosign-signed via GitHub OIDC, Trivy-scanned, SHA3-512 digest).

See [`examples/wiki/DEPLOY.md`](examples/wiki/DEPLOY.md) for the full deployment walkthrough, including the operator-facing environment-variable matrix (`WIKI_*` and `BLAMEJS_*` keys) and the pin-to-version workflow for production updates.

## Why "blamejs"

Because when something breaks, `blame` should know exactly where it lives. We own the stack so you don't have to chase the fault across an ecosystem.

## Contributing

Patches welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the dev setup, house rules (zero npm runtime deps, PQC-only crypto, audit-on-every-action, no-MVP), and the PR loop. New to the codebase? Start with [ARCHITECTURE.md](ARCHITECTURE.md) for the orientation map.

Community standards: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) (Contributor Covenant 2.1). Be excellent.

## Security

Threat model, supported versions, vulnerability disclosure: [SECURITY.md](SECURITY.md). Do **not** file public issues for security bugs — email `security@blamejs.app`.

## License

Apache-2.0. See [LICENSE](LICENSE) for the full text and [NOTICE](NOTICE) for attribution of vendored components.
