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

## Why "blamejs"

Because when something breaks, `blame` should know exactly where it lives. We own the stack so you don't have to chase the fault across an ecosystem.

## License

Apache-2.0. See [LICENSE](LICENSE) for the full text and [NOTICE](NOTICE) for attribution of vendored components.
