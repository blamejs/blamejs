# Contributing to blamejs

Thanks for considering a contribution. blamejs is a security-first framework with strong stylistic and architectural defaults — this doc is the operator's guide to making your patch land cleanly.

## Quick links

- **Found a bug?** Open an issue with the bug-report template. For security bugs, **don't** open a public issue — see [SECURITY.md](SECURITY.md).
- **Have a feature idea?** Open a feature-request issue first to discuss the design before writing code. See "No-MVP rule" below for why this matters.
- **Want to ship a fix?** Read [Development setup](#development-setup), [House rules](#house-rules), and [The PR loop](#the-pr-loop) below.

## Development setup

```bash
# 1. Clone + install (zero npm runtime deps; this only fetches dev tools)
git clone https://github.com/blamejs/blamejs.git
cd blamejs
npm install --no-package-lock

# 2. Run the full test suite (5000+ checks across 4 layers)
node test/smoke.js

# 3. Run the wiki example app's e2e (boots the wiki on an ephemeral port)
cd examples/wiki && rm -rf data data-e2e && node test/e2e.js

# 4. Run lint as a pre-commit gate (CI runs all three)
npx eslint@9 --max-warnings 0 .
docker run --rm -i hadolint/hadolint < examples/wiki/Dockerfile
shellcheck $(git ls-files '*.sh')
```

**Requirements:** Node.js 24+ (current active LTS). The framework targets `node:sqlite`, `Intl.PluralRules`, modern `crypto` primitives, and other recent built-ins. Anything older is out of scope.

## House rules

These are the project's hard rules. Patches that violate them get bounced regardless of how clean the code is.

### Zero npm runtime dependencies

Every dependency is vendored under `lib/vendor/` with a manifest pinning version + license + provenance. Operators audit their dependency graph from `lib/vendor/MANIFEST.json`, not from `node_modules`.

If you need a new external library:

1. **First, check if you really need it.** The framework reaches for stdlib + Web Crypto + `node:sqlite` first. A dep is the last resort.
2. If the answer is yes, vendor it via `scripts/vendor-update.sh <package> [version]`. This bundles with esbuild, copies to vendor dirs, updates the manifest, and removes the npm package itself.
3. Document why in the patch's commit message. Reviewers will push back hard.

### Post-quantum crypto only

Every crypto operation uses PQC from the start: ML-KEM-1024 + P-384 ECDH (hybrid KEM), XChaCha20-Poly1305 (cipher), SHAKE256 (KDF), SHA3-512 (hash), Argon2id (passwords), SLH-DSA-SHAKE-256f / ML-DSA-87 (signatures).

No classical-only fallbacks. No SHA-256, no AES-GCM, no P-256 ECDH-only, no Ed25519 outside the hybrid context. If you're adding a new encrypted blob format or signature surface, follow the algorithm-ID-in-envelope-header pattern (see `lib/crypto.js` and `SECURITY.md` → "Cryptographic stack").

### Audit chain on every operator action

Login, password change, page edit, key rotation, seed apply, vault seal — every operator action emits to the audit chain. The 5 W's (WHO / WHAT / WHEN / WHERE / HOW) are mandatory; the framework's `audit.safeEmit` enforces shape at the call site.

Every namespace must be registered (`audit.registerNamespace("foo")`) before first emission. The smoke test at `test/layer-0-primitives/audit-framework-namespaces.test.js` walks `lib/` for emission patterns and fails CI on any missing registration.

### Code style

- **CommonJS only.** `require()` / `module.exports`. No ES module syntax in `lib/` or in `examples/wiki/`. The framework targets Node's CJS resolver because that's what the vendored bundles produce.
- **`var` declarations.** Not `let` / `const`. Consistent with the rest of the codebase.
- **No TypeScript, no transpilation.** What ships is what runs. Operators read the same source the runtime executes.
- **No emojis in code or commits** unless explicitly requested. (User-facing docs like SECURITY.md and seeded wiki content are exceptions.)
- **Top-of-file `require()`s.** Inline requires only for documented circular-dependency cases, with a comment explaining why.
- **Use framework primitives over raw literals.** `C.TIME.minutes(5)` not `5 * 60 * 1000`. `C.BYTES.kib(64)` not `64 * 1024`. `timingSafeEqual(a, b)` for security-sensitive comparison, never `a === b`.

### No-MVP rule

Every framework primitive is designed for completion from the start. We don't ship "minimum viable" with key features deferred to a follow-up. Before submitting a feature PR, list the v1-defensible scope in the issue's design discussion: what's in, what's out, why each "out" is a complete decision rather than a deferred bullet.

If a slice genuinely shouldn't be in v1 (real ROI question, escape hatch exists, no operator demand), say so explicitly. "Defer with re-open conditions" is a complete answer; "future patch" is not.

### Tier-A config validation

Every primitive's `create()` validates its `opts` against an explicit allow-list using `b.validateOpts(opts, allowedKeys, "primitive.name")`. Typos like `cors({ allowedOrigins: [] })` (the API expects `origins`) throw at boot with the offending key plus the full allowed-keys list. Adding a new primitive? Add the validation in the same patch as the primitive itself.

### Test coverage

The test suite has four layers:

- `test/layer-0-primitives/` — pure-function primitives, no DB / no network
- `test/layer-1-state/` — primitives that touch the DB or vault
- `test/layer-2-...` — middleware + composition
- `test/layer-3-...` — end-to-end framework boot scenarios
- `examples/wiki/test/e2e.js` — the wiki app exercised over real HTTP

A new framework primitive lands with at least layer-0 tests. New middleware lands with layer-2 tests. New CLI subcommand lands with a `test/layer-0-primitives/cli-X.test.js` round-trip test (see `cli-vault.test.js`, `cli-backup.test.js`, `cli-api-key.test.js` for the shape).

The smoke target is `OK — N checks passed` ending with a count higher than the previous release. Wiki e2e is currently at 122; new operator-facing routes/features should add e2e checks.

## The PR loop

1. **Open an issue first** for non-trivial work — design discussion catches scope problems before code is written. Trivial fixes (typos, doc tweaks, single-line bug fixes) can skip the issue.
2. **Branch off `main`.** Branch name doesn't matter; we squash on merge.
3. **One concern per PR.** A new primitive + its tests + its wiki docs + the audit-namespace registration is one PR. A new primitive + an unrelated lint cleanup is two.
4. **Fail-loud verification before push:**
   - `node test/smoke.js` ends with `OK — N checks passed`
   - `cd examples/wiki && rm -rf data data-e2e && node test/e2e.js` ends with `OK — N checks passed`
   - `npx eslint@9 --max-warnings 0 .` exits 0
5. **Commit message style:** lowercase imperative, no AI references, no `Co-Authored-By` trailers from generators. The first line is a one-sentence summary; the body explains *why* and *what tradeoff*. See git log for examples.
6. **Open the PR.** The `Lint summary` CI check is required to pass before merge — it aggregates ESLint + Hadolint + ShellCheck and posts a sticky comment on the PR with the results.
7. **Review feedback** is usually one round. Reviewers focus on:
   - Does this match the framework's existing patterns? (Audit-existing-code: did you sweep internals for replaceable patterns?)
   - Is the failure mode loud at boot, not silent at request time?
   - Is every operator-facing knob in the wiki / DEPLOY.md / Dockerfile env block?
   - Does the patch ship complete, or does it leave a "future" bullet behind?

## What to contribute

Good contribution areas, ordered by current need:

1. **Operator ergonomics** — wiki docs gaps, DEPLOY.md improvements, CLI verb usability, error messages that don't say what to do next.
2. **Test coverage** — there are still framework primitives at lower test coverage than the rest. `git grep -L "test/layer-" lib/` reveals candidates.
3. **Vendored-dep refreshes** — when an upstream library publishes a security or feature release, run `scripts/vendor-update.sh --check` then `vendor-update.sh <pkg>`. Patches refreshing vendored deps are always welcome.
4. **Wiki content** — the wiki at blamejs.app is also the docs site. Filling in concern-group pages (or fixing existing ones) helps every operator.
5. **CLI subcommands** — covered: migrate, seed, dev, api-snapshot, audit, vault, backup, api-key. Open: a `blamejs mtls` for CA bootstrap, a `blamejs i18n missing-keys` reporter, a `blamejs scheduler list/trigger`. See `lib/cli-helpers.js` for the headless-app + reporter pattern.

What we don't want:

- New runtime npm deps. Period.
- TypeScript ports / transpiler builds.
- Classical-only crypto fallbacks "for compatibility."
- "Convenience" primitives that paper over a missing operator decision (e.g., a vault primitive that auto-generates a passphrase if none is set in production).

## Maintainer responsibilities

If you're being added as a maintainer, the additional commitments:

- Triage incoming issues within 7 days
- Respond to security reports per the SLA in [SECURITY.md](SECURITY.md)
- Review PRs in your domain area within 14 days
- Sign-off + tag releases (the release process is in [examples/wiki/DEPLOY.md](examples/wiki/DEPLOY.md) → "Tag-driven releases")

The maintainer list is in [MAINTAINERS.md](MAINTAINERS.md) (or `git log` if that file doesn't exist yet).

## Getting help

- **General questions:** GitHub Discussions on the repo
- **Real-time:** the project doesn't run a Discord / Slack — async-by-design
- **Security:** `security@blamejs.app` ([SECURITY.md](SECURITY.md))

This document is governed by the [Code of Conduct](CODE_OF_CONDUCT.md). Be excellent.
