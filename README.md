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

**v0.0.1 (Phase 0 — foundation).** The first usable layer is in place: envelope-versioned PQC crypto primitives (ML-KEM-1024 + P-384 hybrid, XChaCha20-Poly1305, SHAKE256), a zero-dependency HTTP router, and framework constants. No runtime npm dependencies.

```js
const { crypto, router, constants } = require("@blamejs/core");

const keys = crypto.generateEncryptionKeyPair();
const sealed = crypto.encrypt("hello", keys);
const opened = crypto.decrypt(sealed, keys);          // "hello"

const r = new router.Router();
r.get("/", (req, res) => res.json({ ok: true }));
r.listen(3000);
```

The full eleven-phase roadmap to v1.0 is planned. v0.0.1 satisfies Phase 0 only.

**Requirements:** Node.js 24+ (current active LTS).

## Why "blamejs"

Because when something breaks, `blame` should know exactly where it lives. We own the stack so you don't have to chase the fault across an ecosystem.

## License

Apache-2.0. See [LICENSE](LICENSE) for the full text and [NOTICE](NOTICE) for attribution of vendored components.
