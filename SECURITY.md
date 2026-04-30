# Security Policy

blamejs is a security-first framework. The defaults are post-quantum, sealed-by-default, audit-chained, and tamper-evident from line zero. This document describes how we handle vulnerability reports, what we commit to, what's in scope vs. out of scope, and the operator-side responsibilities that turn the framework's defaults into a defensible deployment.

---

## Reporting a vulnerability

**Do not file a public issue for a security report.**

Email: `security@blamejs.app`

Please include:

- Affected version (`v0.X.Y` tag, or main `<sha>`)
- A description of the issue and the impact you observed
- A reproducer — minimal code, request, or config that triggers the behavior
- Whether you've discussed this with anyone else, including coordinated-disclosure timelines

Encrypt the report with the maintainer PGP key if the report itself is sensitive (key fingerprint published on the project's [Security tab on GitHub](https://github.com/blamejs/blamejs/security)).

### Response time

| Severity | First response | Triage / acknowledgment | Fix released |
|---|---|---|---|
| Critical (RCE, auth bypass, vault compromise, audit-chain tampering) | within 24 h | within 72 h | within 7 d |
| High (CSRF / origin / session bypass, sealed-data leak path) | within 72 h | within 7 d | next patch (≤ 14 d) |
| Medium (info-disclosure without auth bypass, DoS) | within 7 d | within 14 d | next patch (≤ 30 d) |
| Low (defense-in-depth gaps, log-redaction misses) | within 14 d | within 30 d | next minor |

We coordinate with the reporter on disclosure — typical embargo is 14 days post-fix-released to give operators time to upgrade. Reporter credit is included in the `SECURITY` section of the release notes unless they request anonymity.

---

## Supported versions

Pre-1.0, the supported version is the most-recent published patch on the most-recent minor (`v0.3.x` at time of writing). Older minors do not receive security backports unless the issue is critical AND the operator base on the older minor is non-trivial.

Once 1.0 ships, the LTS calendar takes effect: each major gets 18 months of security-only patches after the next major's release.

| Version range | Security patches |
|---|---|
| `v0.3.x` (current) | yes — until v0.4 ships |
| Older `v0.x.y` | no |
| `< v0.1` (pre-public) | no |

---

## Threat model

What blamejs defends against, by design:

- **Disk theft of an offline data dir** — `vault.key.sealed` (wrapped mode) + sealed columns + audit chain mean the data dir alone is opaque without the vault passphrase. Plaintext mode is dev-only and prints a `WARNING:` on every boot.
- **Future quantum decrypt of currently-stored ciphertext** — every encrypted-at-rest blob uses ML-KEM-1024 + P-384 hybrid KEM and XChaCha20-Poly1305. There's no classical-only fallback to harvest now and decrypt later.
- **Audit-chain tampering** — every audit row carries `prevHash` + `rowHash` + `nonce` + `fencingToken`; the chain is verified at boot via `auditChain.verifyChain` and any mismatch refuses subsequent appends. Checkpoints are signed with SLH-DSA-SHAKE-256f. An attacker rewriting history needs to rewrite every subsequent hash AND forge the signing key.
- **Cross-site request forgery on state-changing routes** — `csrfProtect` cookie-mode (double-submit pattern) + `SameSite=Lax` cookie + `Origin` / `Sec-Fetch-Site` checks in CORS.
- **Drive-by scrapers / low-effort bots** — `botGuard` middleware fingerprints `User-Agent` + `Sec-Fetch-*` + `Accept-Language`.
- **Inline-script injection** — strict CSP default (`script-src 'self' 'nonce-...'`) blocks anything an XSS payload could ship.
- **Algorithm-substitution attacks** — every encrypted blob carries a 4-byte algorithm-ID header; `b.crypto.decrypt` dispatches on the header bytes, not on a guess at the active default. An attacker swapping a weaker algorithm into the envelope fails the AEAD tag check.
- **Supply-chain compromise via npm transitive deps** — zero npm runtime dependencies. Every external library is vendored under `lib/vendor/` with a manifest pinning version + license + provenance. Build reproducibility is verified via the GHCR image's SLSA provenance attestation (see DEPLOY.md → "Release verification").
- **Replay of API requests** — `apiEncrypt` middleware nonce-stores + replay-windows the `_ek` field; old session keys can't be reused.
- **Server-Side Request Forgery on outbound calls** — `b.ssrfGuard` resolves the hostname of every `b.httpClient.request({ url })` and refuses any IP in private / loopback / link-local / cloud-metadata / reserved ranges (incl. AWS / GCP / Azure metadata at 169.254.169.254). Wired default-on; operators on internal-mesh deployments override per call via `allowInternal: true | CIDR[]`. Webhook delivery, OAuth, mail HTTP transports, object-store, and notify all inherit the gate.

What blamejs does **not** defend against (operator responsibility):

- **The vault passphrase being weak or reused** — `BLAMEJS_VAULT_PASSPHRASE` is the single secret that unlocks the entire data dir in wrapped mode. Argon2id makes brute-force expensive; a memorable 8-char passphrase is still memorable to an attacker.
- **A compromised admin login** — sessions inherit whatever the admin can do. Rotate session secrets after a suspected compromise (`b.session.invalidateAll()`).
- **DoS at the network layer** — `rateLimit` middleware caps per-IP / per-route, but a determined attacker with botnets needs upstream protection (Caddy + your provider's edge).
- **Physical / runtime memory access** — once an attacker has root on the host, the in-memory vault key is reachable. Hardened-host configs (LSM, secure-boot, FDE) are out of scope; we recommend them.
- **Information disclosure through legitimate logging** — `b.redact` ships a default redaction set, but operator-defined log fields can leak PII. Audit your custom log statements.
- **Compromised CI secrets** — the GitHub Actions release pipeline signs images via OIDC (no long-lived key), but if the workflow file itself is modified by an attacker with `contents: write` on the repo, they can publish a malicious image under the same signature. Branch protection + required reviewers (DEPLOY.md → "Branch protection") closes this.

---

## Cryptographic stack

| Layer | Algorithm | Standard |
|---|---|---|
| KEM | ML-KEM-1024 + P-384 ECDH hybrid | FIPS 203 + NIST P-384 |
| Symmetric | XChaCha20-Poly1305 | RFC 8439 extended |
| KDF | SHAKE256 | FIPS 202 (XOF) |
| Hash | SHA3-512 | FIPS 202 |
| Password | Argon2id | RFC 9106 |
| Signatures (default) | SLH-DSA-SHAKE-256f | FIPS 205 |
| Signatures (legacy verify) | ML-DSA-87 | FIPS 204 |

Algorithm agility is the framework's posture, not just a feature: every encrypted blob carries an envelope header identifying the KEM / cipher / KDF used. New algorithms (HQC when standardized, FrodoKEM, etc.) land as new ID values without breaking existing data — `b.crypto.decrypt` continues to read old blobs while new writes use the new algorithm. See the wiki's [Crypto & Vault](https://blamejs.app/crypto-vault) page for the per-algorithm IDs and the migration path.

---

## Operator security checklist

This is the minimum-viable security posture for a production deployment. The framework's defaults handle most of it; this checklist is what the operator MUST do that the framework cannot.

**Vault**
- [ ] Set `BLAMEJS_VAULT_PASSPHRASE` to a strong, unique passphrase (≥ 32 chars, generated by a CSPRNG, not memorized)
- [ ] Seal the vault before first production boot: `blamejs vault seal --data-dir ./data`
- [ ] Confirm `vault: { mode: "wrapped" }` in the app's config (not `"plaintext"`)
- [ ] Store the passphrase in a secret manager (1Password / Vault / AWS Secrets Manager / sops) — never in git, never in shell history
- [ ] Rotate the vault passphrase quarterly: `blamejs vault rotate`

**Audit chain**
- [ ] Run `blamejs audit verify` weekly via cron — detects any tampering since the last checkpoint
- [ ] Rotate the audit signing key annually (or per compliance schedule)
- [ ] Archive old audit rows monthly: `blamejs audit archive --before <date> --out ./audit-archives/`
- [ ] Back up the audit-archive bundles to a separate location with a different passphrase

**Backups**
- [ ] Schedule nightly backups via the framework's `b.backup` primitive (encrypted with `BLAMEJS_BACKUP_PASSPHRASE`, separate from vault passphrase)
- [ ] Test restore quarterly: `blamejs backup verify --bundle <latest>` then a full `extract` round-trip into a staging environment
- [ ] Off-site at least one bundle (different region / cloud / physical location)
- [ ] Retain bundles per compliance window; the prev-hash chain across bundles makes silent deletion detectable

**mTLS** (only if using `b.mtlsCa` for service-to-service auth)
- [ ] Boot the CA with `--sealed-mode required` so the CA private key is vault-sealed before hitting disk
- [ ] Inspect CA state: `blamejs mtls status --data-dir ./data` — confirms the generation matches the operator's expected version (no silent drift on shared deploys)
- [ ] Rotate leaf certificates per their issued lifetime (typically annual); keep the CA generation field bumped on full-CA rotation events
- [ ] Distribute the CA cert to clients via `blamejs mtls show-cert --data-dir ./data` rather than copying files around — reduces "wrong-cert-trusted" mistakes

**Pipeline**
- [ ] Enable branch protection on `main` requiring the CI workflow's `Lint summary` job
- [ ] Require at least one reviewer on every PR (prevents the "compromised contributor key publishes a malicious image under valid OIDC" path)
- [ ] Set `BLAMEJS_DEPRECATIONS=throw` in CI so deprecated framework calls fail before reaching production
- [ ] Pin the GHCR image to a specific tag in `docker-compose.prod.yml` (never `:latest`)
- [ ] Verify cosign signatures before pulling on production hosts (DEPLOY.md → "Release verification")

**Application**
- [ ] Use `b.permissions` for every state-changing route (don't gate on `req.user` truthiness alone)
- [ ] Audit all `{{{ raw }}}` template outputs — these bypass HTML escape
- [ ] Run `blamejs api-snapshot compare --file ./api-snapshot.json` in CI to catch removed methods or changed signatures before they ship
- [ ] Subscribe to the `blamejs-security-announce` mailing list for advisories

---

## Reporting CVEs in vendored dependencies

The framework vendors all crypto libraries under `lib/vendor/` (currently `@noble/ciphers`, `@noble/hashes`, `@noble/post-quantum`, `@simplewebauthn/server`, `argon2`). Vulnerabilities found upstream that affect blamejs are tracked in the project's [Security tab](https://github.com/blamejs/blamejs/security/advisories). Operators subscribed to the repo's security advisories receive a notification on every published advisory.

We aim to ship a vendored-dep refresh release within 7 days of an upstream patch landing for any High / Critical CVE in our vendored set, faster for Critical-with-active-exploitation. The vendor-update workflow (`scripts/vendor-update.sh`) keeps the manifest, license, and provenance metadata in sync; every refresh release notes the from→to versions of every changed library.
