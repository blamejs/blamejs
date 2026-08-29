#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * release.js — orchestrate the full release flow as a sequence of
 * idempotent subcommands. Each subcommand performs ONE phase, prints
 * what it did, and exits with a code that's safe to script against
 * in a CI runner or operator's terminal.
 *
 * Usage:
 *   node scripts/release.js prepare    # bump + regen CHANGELOG + api-snapshot + static gates
 *   node scripts/release.js regen      # re-regen CHANGELOG + api-snapshot (after release-notes edits)
 *   node scripts/release.js smoke      # SMOKE_PARALLEL=64 + (optional) wiki e2e
 *   node scripts/release.js commit     # release branch + signed commit
 *   node scripts/release.js live-integration  # touched-backend live tests
 *   node scripts/release.js push       # live-integration + gitleaks + push + open PR
 *   node scripts/release.js watch      # gh pr checks --watch + flag Codex threads
 *   node scripts/release.js merge      # squash-merge if CLEAN + zero unresolved threads
 *   node scripts/release.js tag        # signed tag + push tag + verify
 *   node scripts/release.js publish    # watch npm-publish + release-container
 *   node scripts/release.js all        # all eight in sequence
 *
 *   node scripts/release.js help       # this banner
 *   node scripts/release.js status     # what phase the current branch is in
 *
 * Pre-conditions:
 *   - The release-notes JSON `release-notes/v<next>.json` MUST already
 *     exist before `prepare` runs. The script refuses with a template
 *     stub printed to stdout otherwise — the headline / summary /
 *     sections require human judgment and don't auto-generate from a
 *     diff.
 *   - Git signing config (SSH + allowed_signers + commit/tag.gpgsign)
 *     must be in place. See CLAUDE.md "Release workflow" — one-time
 *     signing setup.
 *   - Docker must be running for `push` when the release touches a
 *     backend-protocol lib file (S3/SigV4, MySQL, Postgres, Redis,
 *     MinIO, SMTP, NTP, DoT, federation/Keycloak, OTel). `push` brings
 *     up docker-compose.test.yml and runs the matching live integration
 *     tests; an unavailable stack or a failing test refuses the push.
 *     This is non-skippable except via an explicit, audited override
 *     (--skip-live-integration --live-skip-reason="<why>").
 *
 * The judgment-requiring parts stay manual:
 *   - Writing `release-notes/v<next>.json` content.
 *   - Reviewing Codex P1/P2 findings (watch flags them + stops; the
 *     operator writes the fix + re-runs watch).
 *   - Choosing minor vs patch bump (default: patch per CLAUDE.md;
 *     override via `--minor` on prepare).
 */

var fs = require("node:fs");
var path = require("node:path");
var childProcess = require("node:child_process");

var ROOT = path.resolve(__dirname, "..");

// ---- Helpers -------------------------------------------------------------

// Windows resolves `npm` / `npx` as `npm.cmd` / `npx.cmd` shims, which
// child_process.spawn can only invoke through a shell. Everything else
// in the release-flow toolchain (`gh`, `git`, `docker`, `node`) is a
// native exe that spawns directly without shell — keeping shell off
// avoids the DEP0190 deprecation + the implicit arg-quoting risk.
function _needsShell(cmd) {
  if (process.platform !== "win32") return false;
  return cmd === "npm" || cmd === "npx";
}

function _readPackageVersion() {
  var pkg = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8"));
  return pkg.version;
}

function _writePackageVersion(next) {
  var pkgPath = path.join(ROOT, "package.json");
  var content = fs.readFileSync(pkgPath, "utf8");
  var updated = content.replace(/"version":\s*"[^"]+"/, '"version": "' + next + '"');
  if (updated === content) {
    throw new Error("release: failed to rewrite package.json version line");
  }
  fs.writeFileSync(pkgPath, updated);
}

function _bumpPatch(version) {
  var parts = version.split(".").map(Number);
  if (parts.length !== 3 || parts.some(isNaN)) {
    throw new Error("release: unparseable current version '" + version + "'");
  }
  return parts[0] + "." + parts[1] + "." + (parts[2] + 1);
}

function _bumpMinor(version) {
  var parts = version.split(".").map(Number);
  if (parts.length !== 3 || parts.some(isNaN)) {
    throw new Error("release: unparseable current version '" + version + "'");
  }
  return parts[0] + "." + (parts[1] + 1) + ".0";
}

// Quote a single argument for a Windows cmd.exe command line. Tokens
// made only of safe characters pass through unquoted; anything else is
// double-quoted with embedded quotes doubled.
function _quoteWinArg(a) {
  a = String(a);
  if (/^[A-Za-z0-9_@.\-/:=]+$/.test(a)) return a;
  return '"' + a.replace(/"/g, '""') + '"';
}

function _runSpawn(cmd, args, opts) {
  opts = opts || {};
  args = args || [];
  var spawnCmd = cmd;
  var spawnArgs = args;
  var useShell = false;
  if (_needsShell(cmd)) {
    // Windows resolves npm / npx through .cmd shims that can only be
    // launched via a shell (the CVE-2024-27980 mitigation refuses to
    // spawn .cmd files without one). Node 26's DEP0190 deprecates
    // pairing an args ARRAY with shell:true because the args would be
    // concatenated onto the command line without escaping — a quoting /
    // injection hazard. Build a single, explicitly-quoted command
    // string and pass NO args array, which is the supported shape.
    spawnCmd = [cmd].concat(args.map(_quoteWinArg)).join(" ");
    spawnArgs = undefined;
    useShell = true;
  }
  var rv = childProcess.spawnSync(spawnCmd, spawnArgs, {
    cwd:    opts.cwd   || ROOT,
    stdio:  opts.stdio || "inherit",
    env:    Object.assign({}, process.env, opts.env || {}),
    shell:  useShell,
  });
  if (rv.status !== 0 && !opts.allowFail) {
    throw new Error("release: " + cmd + " " + args.join(" ") +
                    " failed with status " + rv.status);
  }
  return rv;
}

// Test seam for the MUTATING half of the flow (commits, pushes, merges, the
// gate runs). Kept separate from the _capture seam on purpose: a query may be
// retried, a mutation never is.
var _runImpl = _runSpawn;
function _run(cmd, args, opts) { return _runImpl(cmd, args, opts); }

function _captureSpawn(cmd, args, opts) {
  opts = opts || {};
  args = args || [];
  // Mirror _run's shell handling: shell ONLY for npm/npx on win32 (their .cmd
  // shims need it), and then pass a single explicitly-quoted command string.
  // Everything else (git, gh, docker, node) spawns directly with shell off, so
  // a multi-word argument -- e.g. a `gh api graphql` query string full of
  // spaces and braces -- reaches the tool as ONE argument instead of being
  // split by cmd.exe into many (which broke the review-thread lookup on
  // Windows: gh saw 27 args and refused).
  var spawnCmd = cmd, spawnArgs = args, useShell = false;
  if (_needsShell(cmd)) {
    spawnCmd = [cmd].concat(args.map(_quoteWinArg)).join(" ");
    spawnArgs = undefined;
    useShell = true;
  }
  var rv = childProcess.spawnSync(spawnCmd, spawnArgs, {
    cwd:   opts.cwd || ROOT,
    stdio: ["ignore", "pipe", "pipe"],
    env:   Object.assign({}, process.env, opts.env || {}),
    shell: useShell,
  });
  return {
    status: rv.status,
    stdout: (rv.stdout || "").toString().trim(),
    stderr: (rv.stderr || "").toString().trim(),
    // A binary that could not be spawned at all reports status null with BOTH
    // streams empty (`gh` not installed -> ENOENT). Carrying the spawn error
    // is what lets the failure describe itself instead of looking like a
    // command that succeeded and printed nothing.
    spawnError: (rv.error && rv.error.code) || null,
  };
}

// Test seam. Every shell-out that asks a QUESTION routes through this one
// indirection, so the fail-closed tests can drive each gate with a stub that
// fails and prove the gate REFUSES rather than reading the failure as an empty
// answer. Production always runs _captureSpawn.
var _captureImpl = _captureSpawn;
function _capture(cmd, args, opts) { return _captureImpl(cmd, args, opts); }

// Describe a failed shell-out well enough to act on: what was being asked,
// the command line, how it failed, and whatever the tool said.
function _describeFailure(what, cmd, args, rv) {
  var how = rv.spawnError
    ? "could not be spawned (" + rv.spawnError + ")"
    : "exited " + rv.status;
  return "release: " + what + " failed -- `" + cmd + " " + (args || []).join(" ") +
         "` " + how + ".\nAn unreadable result is not an empty one.\n" +
         (rv.stderr || rv.stdout || "(no output)");
}

// The form for a question whose answer must be trustworthy: throws unless the
// command actually ran and succeeded.
//
// Plain `_capture` returns `stdout: ""` for BOTH "the command succeeded and
// printed nothing" and "the command never ran", and every gate in this file
// that reads `.stdout` directly resolves that ambiguity the permissive way: a
// failed `git status` reads as a CLEAN tree, a failed `git diff` as NO backend
// touched (skipping the live-integration gate), a failed `gh pr list` as NO
// open PR. Each of those defaults lets the release proceed past a gate that
// never ran.
//
// Use plain `_capture` ONLY where a non-zero exit is itself a valid answer --
// an existence probe like `git rev-parse --verify --quiet <ref>`, or a check
// that greps the output and warns.
function _captureOk(what, cmd, args, opts) {
  var rv = _capture(cmd, args, opts);
  if (rv.status !== 0) throw new Error(_describeFailure(what, cmd, args, rv));
  return rv;
}

// Connection-level failure signatures, matched against a failed query's
// stderr. The exit code cannot do this job: `gh` reports BOTH a dial failure
// ("error connecting to <host>") and a rejected token ("Bad credentials (HTTP
// 401)") as exit 1, so only the message separates the flake worth retrying
// from the stable answer that retrying cannot change.
//
// Erring toward retrying is the safe direction. Retrying a stable failure
// costs four seconds and then reports the same error; NOT retrying a flake
// aborts a release step -- or, in _waitForCodexReview, spends the full ten
// minutes and then blames Codex for a network blip.
var TRANSIENT_QUERY_MARKERS = [
  // Dial + DNS
  "error connecting to", "check your internet connection", "connection reset",
  "connection refused", "no such host", "server misbehaving",
  "temporary failure in name resolution", "eai_again", "enotfound",
  "econnreset", "econnrefused", "etimedout", "esockettimedout",
  // TLS. Match "handshake" on its own rather than a specific failure phrase:
  // Go spells the same class at least three ways ("remote error: tls:
  // handshake failure", "net/http: TLS handshake timeout", "tls: bad record
  // MAC"), and a phrase-level marker silently misses the spellings it did not
  // anticipate.
  "tls: ", "handshake", "unexpected eof", "broken pipe", "socket hang up",
  // Timeouts
  "i/o timeout", "context deadline exceeded", "client.timeout exceeded",
  "timeout awaiting response headers",
  // Server-side + throttling
  "rate limit", "http 429", "http 500", "http 502", "http 503", "http 504",
  "bad gateway", "service unavailable", "gateway timeout",
];

var QUERY_ATTEMPTS = 3;
// Mutable so the retry tests can collapse the backoff instead of sleeping four
// real seconds per case.
var QUERY_BACKOFF_MS = [1000, 3000];

// A read-only query worth retrying? A binary that is not installed never is
// (ENOENT does not heal), and neither is a stable rejection -- 401, 404 and
// "permission denied" answer the question, they just answer it badly.
function _isTransientQueryFailure(rv) {
  if (rv.spawnError) return false;
  var text = ((rv.stderr || "") + "\n" + (rv.stdout || "")).toLowerCase();
  return TRANSIENT_QUERY_MARKERS.some(function (m) { return text.indexOf(m) !== -1; });
}

function _firstLine(text) {
  var lines = String(text || "").split("\n");
  for (var i = 0; i < lines.length; i += 1) {
    if (lines[i].trim()) return lines[i].trim();
  }
  return "(no output)";
}

// Run a READ-ONLY network query (gh / npm view), retrying the connection-level
// failures. The orchestrator makes these in tight bursts that a hand-run never
// produces -- _waitForCodexReview alone spawns three `gh` processes every 20
// seconds for up to ten minutes, and each one is a fresh TLS handshake to
// api.github.com with no connection reuse. That burst is what turns an
// occasional handshake reset into a reproducible release-flow failure.
//
// Retries are safe here BECAUSE the caller is read-only. Mutations go through
// _run and are never retried: re-running `gh pr merge` or `git push` after an
// ambiguous failure is a different and much worse hazard.
function _captureQuery(what, cmd, args, opts) {
  var rv = null;
  for (var attempt = 1; attempt <= QUERY_ATTEMPTS; attempt += 1) {
    rv = _capture(cmd, args, opts);
    if (rv.status === 0) return rv;
    if (attempt === QUERY_ATTEMPTS || !_isTransientQueryFailure(rv)) break;
    var backoffMs = QUERY_BACKOFF_MS[attempt - 1] || QUERY_BACKOFF_MS[QUERY_BACKOFF_MS.length - 1];
    console.log("  " + what + ": transient failure (attempt " + attempt + "/" + QUERY_ATTEMPTS +
                "), retrying in " + Math.round(backoffMs / 1000) + "s -- " + _firstLine(rv.stderr));
    _sleepSync(backoffMs);
  }
  var err = new Error(_describeFailure(what, cmd, args, rv));
  // Tagged so a caller that polls -- and is therefore its own, much longer,
  // retry loop -- can absorb a connection blip and keep asking, while still
  // aborting immediately on a stable rejection that no amount of asking fixes.
  err.lookupFailed = true;
  err.transient    = _isTransientQueryFailure(rv);
  throw err;
}

// The advisory form of _captureQuery, for the two places that REPORT rather
// than gate (`publish`'s npm version echo, `status`'s PR line). It returns a
// two-branch result with no `stdout` on the failure branch, so a caller cannot
// fall back into reading a failure as an empty answer -- the shape makes the
// old bug unspellable rather than merely discouraged.
function _captureQueryTolerant(what, cmd, args, opts) {
  try {
    return { ok: true, stdout: _captureQuery(what, cmd, args, opts).stdout };
  } catch (e) {
    // Only a LOOKUP failure is tolerable. Anything else here is a bug in this
    // script, and reporting it as "the lookup failed" would disguise it as a
    // network problem the operator should ignore.
    if (!e || !e.lookupFailed) throw e;
    return { ok: false, failure: e.message };
  }
}

function _gitClean() {
  return _captureOk("working-tree status", "git", ["status", "--porcelain"]).stdout === "";
}

function _gitBranch() {
  return _captureOk("current branch", "git", ["rev-parse", "--abbrev-ref", "HEAD"]).stdout;
}

function _gitOnMain() {
  return _gitBranch() === "main";
}

function _gitOnRelease() {
  return /^release\/v\d+\.\d+\.\d+$/.test(_gitBranch());
}

function _releaseBranchFor(version) {
  return "release/v" + version;
}

function _releaseNotesPath(version) {
  return path.join(ROOT, "release-notes", "v" + version + ".json");
}

function _ensureReleaseNotes(version) {
  var p = _releaseNotesPath(version);
  if (!fs.existsSync(p)) {
    var stub = {
      $schema:  "../scripts/release-notes-schema.json",
      version:  version,
      date:     new Date().toISOString().slice(0, 10),
      headline: "<one-line operator-facing summary — start with a capital letter or `backtick>",
      summary:  "<one-paragraph why-it-matters>",
      sections: [
        {
          heading: "Added",
          items: [
            { title: "<short title>", body: "<one-paragraph body — ends in sentence punctuation>" },
          ],
        },
      ],
      references: [],
    };
    console.error("");
    console.error("release: missing " + p);
    console.error("");
    console.error("Create that file before re-running. Stub template:");
    console.error("");
    console.error(JSON.stringify(stub, null, 2));
    console.error("");
    process.exit(2);
  }
  return p;
}

function _section(title) {
  console.log("\n=== " + title + " ===");
}

function _ok(msg) {
  console.log("ok: " + msg);
}

// Shared artifact-regeneration helper. Called by `prepare` after the
// version bump, and standalone via `regen` when the operator edits
// release-notes mid-flow (e.g. addressing a Codex P1/P2 finding that
// belongs in the operator-facing release notes). Idempotent — running
// it twice with no edits in between is a no-op.
function _regenArtifacts(opts) {
  opts = opts || {};
  if (opts.rollupOnMinor) {
    _run("node", ["scripts/consolidate-release-notes.js", "--prune"]);
    _ok("prior minor's release-notes rolled up");
  }
  _run("node", ["scripts/generate-changelog-entry.js", "--rebuild"]);
  _run("node", ["scripts/refresh-api-snapshot.js"]);
  _run("node", ["scripts/check-api-snapshot.js"]);
  _run("node", ["scripts/check-changelog-extract.js"]);
  _run("node", ["scripts/check-esbuild-pin.js"]);
  _run("node", ["scripts/pin-all.js", "--lockfiles"]);
  _run("node", ["scripts/pin-all.js"]);
  _ok("CHANGELOG + api-snapshot regenerated");
}

// Verify HEAD's commit signature using two independent code paths:
//   1. `git verify-commit HEAD` — exits 0 on Good signature; this is
//      the canonical truth signal (matches what GitHub's
//      required_signatures ruleset checks).
//   2. `git log -1 --pretty=%h %G? %GS` — capture the sha + signature
//      letter + signer email for human-readable confirmation.
// The script previously relied solely on (2), but the `%G?` token's
// `?` character can be eaten on some platforms when spawned through
// shell-resolution layers; (1) is a reliable boolean even when (2)
// returns empty stdout.
function _verifyCommitSignature(label) {
  var verifyRv = _capture("git", ["verify-commit", "HEAD"]);
  if (verifyRv.status !== 0) {
    var hint = "release: " + label + " commit signature is not Good — " +
               "check SSH signing setup (commit.gpgsign=true + gpg.format=ssh + " +
               "~/.ssh/allowed_signers populated).";
    if (verifyRv.stderr) hint += "\n" + verifyRv.stderr;
    throw new Error(hint);
  }
  // Cosmetic only — `verify-commit` above is the verdict, and it has already
  // passed by the time we get here. Reading the status keeps that explicit:
  // this line failing says nothing about the signature.
  var sig = _capture("git", ["log", "-1", "--pretty=%h %G? %GS"]);
  console.log("signature: " + (sig.status === 0 && sig.stdout
    ? sig.stdout
    : "(not displayable on this platform — verify-commit above reports Good)"));
  _ok(label + " commit signature verified");
}

// ---- Touched-backend live integration ------------------------------------
//
// A release that changes the lib code behind a network backend MUST prove
// itself against a real instance of that backend before it reaches a PR.
// The class this catches: a change validated only on the host smoke gate
// (which runs against sqlite + in-memory fakes) that breaks against the
// live protocol — e.g. a DDL/migration refactor that self-validates on
// sqlite but emits casing the Postgres wire rejects. Host smoke is green;
// the regression ships. The fix is to make the matching live test
// non-skippable on the release path, not advisory.
//
// Each backend entry declares:
//   match     — lib path substrings (matched against the forward-slashed
//               repo-relative path of every changed file) that mean this
//               backend's protocol surface was touched. A file under
//               lib/object-store/ touches the S3 / Azure / GCS backends;
//               a change to lib/external-db*.js or lib/db-query.js touches
//               the Postgres + MySQL backends; etc.
//   services  — the docker-compose.test.yml service names this backend's
//               tests require (informational + used to scope the readiness
//               check; the compose `up --wait` brings up the whole stack).
//   tests     — the test/integration/*.test.js file(s) (basename) that
//               exercise this backend live. `test-integration.js` accepts
//               either the bare name or the `.test.js` form.
//
// Conservative by construction: when a changed file matches more than one
// backend, every matching test runs. A shared file (lib/http-client.js,
// lib/safe-url.js, lib/crypto.js) is referenced by multiple backends on
// purpose — touching the SigV4 signer or the HTTP client is exactly the
// kind of cross-cutting change a single-backend smoke can hide.
var BACKEND_LIVE_MAP = [
  {
    backend:  "postgres",
    // The audit stack belongs here because its SQL differs by dialect and
    // nothing else proves that: framework-schema writes the append-only
    // triggers and the permission grant one dialect at a time, db.js chooses
    // how a cluster purge deletes, audit-tools drives that purge, and
    // audit-chain classifies the "missing column" error text each server
    // words differently. On sqlite alone every one of those reads clean.
    match:    ["lib/external-db", "lib/db-query", "lib/db-schema.js",
               "lib/db-declare", "lib/db-role-context", "lib/cluster-provider-db",
               "lib/cluster-storage", "lib/safe-sql", "lib/db-collection.js",
               "lib/framework-schema.js", "lib/audit-tools.js", "lib/audit-chain.js",
               "lib/db.js"],
    services: ["postgres", "postgres-replica"],
    filePattern: /(^|-)(pg|postgres)(-|$)/,
    tests:    ["external-db-postgres", "audit-chain-external-db",
               "audit-actor-binding-pg", "distributed-scheduler-fencing-pg",
               "audit-stack-postgres"],
  },
  {
    backend:  "mysql",
    match:    ["lib/external-db", "lib/cluster-provider-db", "lib/cluster-storage",
               "lib/safe-sql", "lib/framework-schema.js", "lib/audit-tools.js",
               "lib/audit-chain.js", "lib/db.js"],
    services: ["mysql"],
    filePattern: /(^|-)mysql(-|$)/,
    tests:    ["cluster-provider-mysql", "audit-stack-mysql"],
  },
  {
    backend:  "redis",
    match:    ["lib/redis-client", "lib/queue-redis", "lib/pubsub-redis",
               "lib/cache-redis", "lib/queue.js", "lib/cache.js", "lib/pubsub.js",
               "lib/crypto-field"],
    services: ["redis", "redis-tls"],
    tests:    ["redis-client-tls", "cache", "queue-redis", "pubsub",
               "redis-reconnect-toxiproxy"],
  },
  {
    backend:  "object-store-s3",
    match:    ["lib/object-store/sigv4", "lib/object-store/http",
               "lib/object-store/local", "lib/object-store/index.js",
               "lib/queue-sqs", "lib/log-stream-cloudwatch", "lib/backup",
               "lib/restore"],
    services: ["minio", "minio-tls", "localstack", "localstack-tls"],
    tests:    ["object-store-sigv4", "object-store-worm-lock",
               "backup-restore-objectstore", "queue-sqs",
               "log-stream-cloudwatch"],
  },
  {
    backend:  "object-store-azure",
    match:    ["lib/object-store/azure-blob", "lib/object-store/http",
               "lib/object-store/index.js"],
    services: ["azurite"],
    tests:    ["object-store-azure"],
  },
  {
    backend:  "object-store-gcs",
    match:    ["lib/object-store/gcs", "lib/object-store/http",
               "lib/object-store/index.js"],
    services: ["fake-gcs"],
    tests:    ["object-store-gcs"],
  },
  {
    backend:  "smtp-mail",
    match:    ["lib/mail-send", "lib/mail-smtp", "lib/mail-require-tls",
               "lib/mail-server", "lib/network-smtp-policy", "lib/mail-dkim",
               "lib/mail-crypto", "lib/mail-deploy", "lib/mail-auth",
               "lib/mail.js"],
    services: ["mailpit"],
    tests:    ["mail-smtp", "mail-dkim", "mail-crypto-smime"],
  },
  {
    backend:  "ntp",
    match:    ["lib/ntp-check", "lib/network-nts", "lib/network-ntp"],
    services: ["ntp"],
    tests:    ["ntp-check"],
  },
  {
    backend:  "dns-dot",
    match:    ["lib/network-dns", "lib/network-dane", "lib/network-dnssec",
               "lib/network-tsig"],
    services: ["coredns"],
    tests:    ["network-dns"],
  },
  {
    backend:  "http-tls-outbound",
    match:    ["lib/http-client", "lib/network-tls", "lib/network-heartbeat",
               "lib/network-proxy", "lib/tls-exporter", "lib/safe-url"],
    services: ["caddy", "haproxy", "squid"],
    tests:    ["http-client", "tls-classical-downgrade-audit",
               "network-heartbeat", "ssrf-guard"],
  },
  {
    backend:  "federation-keycloak",
    match:    ["lib/oauth", "lib/saml", "lib/openid", "lib/auth.js",
               "lib/auth-header", "lib/ciba", "lib/oid4v", "lib/jar",
               "lib/jarm", "lib/par", "lib/dcr", "lib/scim"],
    services: ["keycloak"],
    tests:    ["federation-auth"],
  },
  {
    backend:  "log-stream-tls",
    match:    ["lib/log-stream"],
    services: ["syslog", "syslog-tls"],
    tests:    ["log-stream"],
  },
  {
    backend:  "otel-telemetry",
    match:    ["lib/log-stream-otlp", "lib/observability"],
    services: ["otel-collector"],
    tests:    ["log-stream-cloudwatch"],
  },
  {
    // Live tests that need nothing from docker-compose: each spawns its own
    // server or works on local files. They are claimed here rather than left
    // out because the live gate is the only thing that runs test/integration
    // at all — smoke covers test/layer-5-integration, a different directory —
    // so a file no entry names runs in no release. Six seconds buys the set.
    // `lib/` matches any framework change, which is every release shipping
    // code; no service is declared, so this alone never requires Docker.
    backend:  "local-services-none",
    match:    ["lib/"],
    services: [],
    tests:    ["mail-dane-authentication", "mtls-ca", "openid-federation-chain",
               "pqc-pkcs8-forward-compat", "sql-fts5-catalog-sqlite",
               "websocket-permessage-deflate", "ws-client-roundtrip"],
  },
];

// The whole set of changed files relevant to backend detection: both what
// the release branch already committed on top of main AND the uncommitted
// working tree. The feature+release cut (CLAUDE.md "Release workflow")
// stages the fix in the working tree and lets `commit`'s `git add -A`
// capture it — so by the time `push` runs the change may be EITHER
// committed (bump-only cut) or still uncommitted (feature+release cut). We
// union both so the gate can't be slipped by running before the commit.
// The ref the release branch diverged from. `origin/main` is the merge target;
// fall back to local `main` when the remote ref isn't fetched. This is the one
// place the RAW capture is correct: a non-zero exit from `rev-parse --verify
// --quiet` is the answer (the ref does not exist), not a failure to answer.
function _mergeBaseRef() {
  var probe = _capture("git", ["rev-parse", "--verify", "--quiet", "origin/main"]);
  return probe.status === 0 ? "origin/main" : "main";
}

function _changedFilesForBackendDetection() {
  var seen = {};
  function add(list) {
    list.forEach(function (p) {
      p = (p || "").replace(/\\/g, "/").trim();
      if (p) seen[p] = true;
    });
  }
  var base = _mergeBaseRef();
  // Every one of these must be trustworthy: an empty change set means "no
  // backend touched", which SKIPS the live-integration gate entirely. A git
  // failure read as an empty diff is the quietest way to ship a backend change
  // that was never proven against the backend.
  add(_captureOk("committed changes vs " + base, "git",
                 ["diff", "--name-only", base + "...HEAD"]).stdout.split(/\r?\n/));
  // Uncommitted working-tree delta (staged + unstaged + untracked).
  add(_captureOk("unstaged changes", "git", ["diff", "--name-only"]).stdout.split(/\r?\n/));
  add(_captureOk("staged changes", "git", ["diff", "--name-only", "--cached"]).stdout.split(/\r?\n/));
  add(_captureOk("untracked files", "git",
                 ["ls-files", "--others", "--exclude-standard"]).stdout.split(/\r?\n/));
  return Object.keys(seen);
}

// Every integration test file on disk, without the `.test.js` suffix.
function _allIntegrationTestNames() {
  var dir = path.join(ROOT, "test", "integration");
  return fs.readdirSync(dir)
    .filter(function (f) { return /\.test\.js$/.test(f); })
    .map(function (f) { return f.replace(/\.test\.js$/, ""); })
    .sort();
}

// A backend's live tests are the ones it names PLUS every file whose name
// says it belongs to that backend. Hand-maintained lists rot in one
// direction only — a new file is forgotten, the gate stays green, and the
// release reports a backend proven that it never exercised. Twenty-one of
// fifty-one files had drifted out of reach this way, including the audit
// stack's own Postgres and MySQL suites. Deriving from the filename means
// adding `foo-pg.test.js` is enough to have it run.
function _testsForBackend(entry) {
  var seen = {};
  (entry.tests || []).forEach(function (n) { seen[n] = true; });
  if (entry.filePattern) {
    _allIntegrationTestNames().forEach(function (n) {
      if (entry.filePattern.test(n)) seen[n] = true;
    });
  }
  return Object.keys(seen).sort();
}

// A file no entry claims is run by nothing: the live gate is the only thing
// that runs test/integration at all (smoke covers test/layer-5-integration,
// a different directory). So an unclaimed file is not untidiness — it is a
// test that cannot fail. Refuse rather than report.
function _assertEveryIntegrationFileIsClaimed() {
  var claimed = {};
  BACKEND_LIVE_MAP.forEach(function (entry) {
    _testsForBackend(entry).forEach(function (n) { claimed[n] = true; });
  });
  var orphans = _allIntegrationTestNames().filter(function (n) { return !claimed[n]; });
  if (orphans.length > 0) {
    throw new Error(
      "release: " + orphans.length + " integration test file(s) belong to no backend " +
      "entry, so no release ever runs them:\n  " + orphans.join("\n  ") + "\n" +
      "Add each to a BACKEND_LIVE_MAP entry's `tests`, or give the owning entry a " +
      "`filePattern` that covers it. A test nothing runs cannot fail.");
  }
}

// Map the changed-file set onto the backends whose protocol surface was
// touched. Returns a de-duplicated, deterministic list of
// { backend, services, tests, matchedBy } entries.
function _detectTouchedBackends(changedFiles) {
  var hits = [];
  _assertEveryIntegrationFileIsClaimed();
  BACKEND_LIVE_MAP.forEach(function (entry) {
    var matchedBy = changedFiles.filter(function (f) {
      return entry.match.some(function (m) { return f.indexOf(m) !== -1; });
    });
    if (matchedBy.length > 0) {
      hits.push({
        backend:   entry.backend,
        services:  entry.services,
        tests:     _testsForBackend(entry),
        matchedBy: matchedBy,
      });
    }
  });
  return hits;
}

// Bring the docker-compose.test.yml stack up and block until every
// service reports healthy. Docker being unavailable, or the stack failing
// to converge, is a HARD STOP — never a skip. A release that touches a
// backend it cannot prove against does not ship.
function _bringUpDockerStack() {
  var probe = _capture("docker", ["version", "--format", "{{.Server.Version}}"]);
  if (probe.status !== 0) {
    throw new Error(
      "release: live integration requires Docker, but `docker version` failed.\n" +
      (probe.stderr || probe.stdout || "(no docker daemon reachable)") + "\n" +
      "Start Docker Desktop / the docker daemon and re-run. This is a hard stop, " +
      "not a skip — a backend change that can't be proven live does not ship.");
  }
  console.log("docker server: " + (probe.stdout || "(version unknown)"));
  // `up -d --wait` returns non-zero if any service's healthcheck doesn't
  // reach healthy within its compose-declared timeout. _run throws on
  // non-zero (allowFail defaults off), so a stack that won't converge
  // stops the release here.
  _run("docker", ["compose", "-f", "docker-compose.test.yml", "up", "-d", "--wait"]);
  _ok("docker-compose.test.yml stack up + healthy");
}

function cmdLiveIntegration(opts) {
  opts = opts || {};
  _section("live integration");

  var changed = _changedFilesForBackendDetection();
  var touched = _detectTouchedBackends(changed);

  if (touched.length === 0) {
    _ok("no backend-protocol lib files changed — no live integration required");
    return;
  }

  // Aggregate the matching test files across every touched backend.
  var testSet = {};
  touched.forEach(function (t) {
    t.tests.forEach(function (name) { testSet[name] = true; });
  });
  var testFiles = Object.keys(testSet).sort();

  console.log("touched backends (" + touched.length + "):");
  touched.forEach(function (t) {
    console.log("  - " + t.backend + "  [" + t.tests.join(", ") + "]");
    t.matchedBy.slice(0, 6).forEach(function (f) { console.log("      via " + f); });
    if (t.matchedBy.length > 6) {
      console.log("      via (+" + (t.matchedBy.length - 6) + " more)");
    }
  });
  console.log("live test files to run (" + testFiles.length + "): " + testFiles.join(", "));

  // The skip path is deliberately heavy: an explicit flag AND a non-empty
  // audited reason, both printed loudly so the bypass is never silent and
  // is captured in the release-flow transcript. A flag with no reason is
  // refused — "I'll explain later" is not an answer here.
  if (opts.skip) {
    if (!opts.skipReason) {
      throw new Error(
        "release: --skip-live-integration requires --live-skip-reason=\"<why>\".\n" +
        "The live gate proves a touched backend against a real instance; skipping " +
        "it needs an explicit, audited reason printed to the operator — not a silent " +
        "bypass. Provide --live-skip-reason or run the live tests.");
    }
    console.log("");
    console.log("!! LIVE INTEGRATION SKIPPED — operator override");
    console.log("!! reason: " + opts.skipReason);
    console.log("!! touched backends NOT proven live: " +
                touched.map(function (t) { return t.backend; }).join(", "));
    console.log("!! tests NOT run: " + testFiles.join(", "));
    console.log("!! This override is recorded in the release-flow output above.");
    return;
  }

  // Only bring the stack up when a touched backend actually declares
  // services. Some live tests spawn their own server or work on local files
  // and need nothing from docker-compose; requiring the daemon for those
  // would make Docker a precondition for every release that ships code,
  // which is not what the live gate is for.
  var needsServices = touched.some(function (t) {
    return (t.services || []).length > 0;
  });
  if (needsServices) _bringUpDockerStack();
  else console.log("no touched backend declares a service — running the local live tests only");

  // `--skip-service-check` is intentionally NOT passed when a service is in
  // play: the readiness gate inside test-integration.js is a second proof
  // that the stack the tests need is actually reachable (the `up --wait`
  // healthchecks and the framework's own TCP/TLS probes can disagree). We
  // want both. With no service declared there is nothing for it to probe.
  _section("run live integration tests");
  _run("node", ["scripts/test-integration.js"]
    .concat(needsServices ? [] : ["--no-docker"])
    .concat(testFiles));
  _ok("live integration green for: " + touched.map(function (t) {
    return t.backend;
  }).join(", "));
}

// ---- Subcommands ---------------------------------------------------------

function cmdPrepare(opts) {
  _section("prepare");
  if (!_gitOnMain()) {
    throw new Error("release: prepare must run on main (currently on " + _gitBranch() + ")");
  }
  if (!_gitClean()) {
    throw new Error("release: prepare requires a clean working tree");
  }

  var current = _readPackageVersion();
  var next = opts.minor ? _bumpMinor(current) : _bumpPatch(current);
  console.log("current version: " + current);
  console.log("next version:    " + next + " (" + (opts.minor ? "minor" : "patch") + ")");

  _ensureReleaseNotes(next);

  _writePackageVersion(next);
  _ok("bumped package.json → " + next);

  _section("regen artifacts");
  // Minor bump: consolidate the prior minor's per-patch release-notes
  // files into a single rollup so smoke's release-notes rollup gate
  // stays green. No-op on patch bumps.
  var minorRotated = current.split(".")[1] !== next.split(".")[1];
  _regenArtifacts({ rollupOnMinor: minorRotated });

  _section("static gates");
  _run("npx", ["--yes", "eslint@latest", "--max-warnings", "0", "."]);
  _run("node", ["test/layer-0-primitives/codebase-patterns.test.js"]);
  _run("node", ["scripts/validate-source-comment-blocks.js"]);
  // The case-fold table is derived from the running Node's own case mappings,
  // so a Node upgrade can move it under us. Regenerating here would hide that;
  // failing says which release changed the answer.
  _run("node", ["scripts/gen-case-fold-classes.js", "--check"]);
  _ok("eslint + codebase-patterns + source-comment-blocks + case-fold table clean");

  _section("supply-chain currency");
  // A stale SHA-pinned GitHub Action or vendored bundle becomes a
  // release blocker HERE — with a ready-to-paste pin line in the
  // actions report — instead of an after-the-fact Dependabot PR.
  // Each script treats only an actually-newer upstream version as a
  // failure; transient registry / API errors stay advisory (exit 0)
  // so a flaky network response doesn't block the cut.
  _run("node", ["scripts/check-actions-currency.js"]);
  _run("node", ["scripts/check-vendor-currency.js"]);
  _ok("github actions + vendored bundles current");

  console.log("\nnext: node scripts/release.js smoke");
}

function cmdRegen() {
  _section("regen");
  // Operators edit release-notes/v<next>.json mid-flow (e.g.
  // addressing a Codex finding that belongs in the operator-facing
  // notes, or fixing a leak-vocabulary refusal that the changelog
  // emitter raised). This subcommand re-runs the artifact pipeline
  // without re-bumping the version. Safe to run from any branch.
  var next = _readPackageVersion();
  _ensureReleaseNotes(next);
  _regenArtifacts();
  console.log("\nnext: re-run the phase you were on (commit / push / watch / ...)");
}

// Did this release touch examples/wiki? A failed diff must not read as
// "untouched": that skips the e2e gate silently, the same class as the
// live-integration skip.
//
// Three-dot against the merge base, matching the backend detector. The two-dot
// form compares the two endpoints directly, so a wiki commit that landed on
// main but not on this branch counted as touched here — extra work, but it
// also meant the two gates were answering the same question from different
// diffs.
//
// Separate from cmdSmoke so the decision can be tested without running the
// gate's side effects (cmdSmoke wipes the wiki's data directories before the
// e2e, which a test must never do to the real working tree).
function _wikiTouched() {
  var base = _mergeBaseRef();
  function touchesWiki(rv) {
    return rv.stdout.split(/\r?\n/).some(function (p) { return p.indexOf("examples/wiki") === 0; });
  }
  if (touchesWiki(_captureOk("committed changes vs " + base, "git",
                             ["diff", "--name-only", base + "...HEAD"]))) return true;
  return touchesWiki(_captureOk("unstaged changes", "git", ["diff", "--name-only"]));
}

function cmdSmoke() {
  _section("smoke");
  _run("node", ["test/smoke.js"], { env: { SMOKE_PARALLEL: "64" } });
  _ok("framework smoke clean");

  if (_wikiTouched()) {
    _section("wiki e2e");
    var wikiDir = path.join(ROOT, "examples", "wiki");
    try { fs.rmSync(path.join(wikiDir, "data"),     { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(path.join(wikiDir, "data-e2e"), { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    _run("node", ["test/e2e.js"], { cwd: wikiDir, env: { SMOKE_PARALLEL: "64" } });
    _ok("wiki e2e clean");
  } else {
    _ok("wiki untouched — skipping e2e");
  }

  console.log("\nnext: node scripts/release.js commit");
}

function cmdCommit() {
  _section("commit");
  var next = _readPackageVersion();
  var branch = _releaseBranchFor(next);
  var current = _gitBranch();

  // Resumable: if a previous `commit` invocation failed AFTER the
  // `git checkout -b` (e.g. signature verification, write-protected
  // file, hook failure), the branch already exists. Switch to it
  // instead of refusing. The remaining checks (the commit itself,
  // signature verify) are idempotent.
  if (current === branch) {
    _ok("already on " + branch + " (resume mode)");
  } else if (current === "main") {
    var branchExists = _capture("git", ["rev-parse", "--verify", "--quiet", branch]).status === 0;
    if (branchExists) {
      _run("git", ["checkout", branch]);
      _ok("checked out existing " + branch + " (resume mode)");
    } else {
      _run("git", ["checkout", "-b", branch]);
      _ok("created " + branch);
    }
  } else {
    throw new Error("release: commit must run on main or " + branch +
                    " (currently on " + current + ")");
  }

  // If HEAD already carries a commit for this release (re-run after
  // signature failure was resolved out-of-band, or just an over-eager
  // re-invocation), skip the second commit. Verify the existing
  // signature instead.
  var headSubject = _captureOk("HEAD commit subject", "git", ["log", "-1", "--pretty=%s"]).stdout;
  if (headSubject.indexOf(next + " — ") === 0) {
    _ok("HEAD already carries a " + next + " release commit (resume mode)");
    _verifyCommitSignature("existing");
    console.log("\nnext: node scripts/release.js push");
    return;
  }

  // Compose commit body from the release-notes JSON. Operators can
  // amend post-commit; the auto-generated body is meant as a sensible
  // default that mirrors the CHANGELOG entry shape.
  var rn = JSON.parse(fs.readFileSync(_releaseNotesPath(next), "utf8"));
  var lines = [next + " — " + rn.headline, "", rn.summary];
  if (Array.isArray(rn.sections)) {
    rn.sections.forEach(function (s) {
      if (!Array.isArray(s.items) || s.items.length === 0) return;
      lines.push("", s.heading + ":");
      s.items.forEach(function (it) {
        lines.push("  - " + it.title);
      });
    });
  }
  var msgPath = path.join(ROOT, ".scratch", "release-commit-msg.txt");
  try { fs.mkdirSync(path.dirname(msgPath), { recursive: true }); } catch (_e) { /* ignore */ }
  fs.writeFileSync(msgPath, lines.join("\n") + "\n");

  _run("git", ["add", "-A"]);
  _run("git", ["commit", "-s", "-F", msgPath]);   // -s: DCO Signed-off-by (CONTRIBUTING.md)
  _ok("signed commit");

  _verifyCommitSignature("new");

  console.log("\nnext: node scripts/release.js push");
}

function cmdPush(opts) {
  opts = opts || {};
  _section("push");
  if (!_gitOnRelease()) {
    throw new Error("release: push must run on a release/vX.Y.Z branch");
  }
  var next = _readPackageVersion();

  // Touched-backend live integration runs BEFORE gitleaks + the PR opens.
  // A backend change that only passed host smoke (sqlite + in-memory
  // fakes) must prove itself against the real protocol here; a failure is
  // a hard stop that refuses the push. Non-skippable except via an
  // explicit, audited override (see cmdLiveIntegration).
  cmdLiveIntegration({ skip: opts.skipLiveIntegration, skipReason: opts.liveSkipReason });

  _gitleaks();

  _section("push branch");
  _run("git", ["push", "-u", "origin", _releaseBranchFor(next)]);
  _ok("pushed " + _releaseBranchFor(next));

  _section("open PR");
  var rn = JSON.parse(fs.readFileSync(_releaseNotesPath(next), "utf8"));
  var title = next + " — " + rn.headline;
  var summaryLines = ["## Summary", "", rn.summary, "", "## Test plan", ""];
  summaryLines.push("- [x] `node test/smoke.js` — passes");
  summaryLines.push("- [x] `node test/layer-0-primitives/codebase-patterns.test.js` — clean");
  summaryLines.push("- [x] `gitleaks` — no leaks");
  summaryLines.push("- [ ] CI green");
  _run("gh", ["pr", "create",
              "--base", "main",
              "--head", _releaseBranchFor(next),
              "--title", title,
              "--body",  summaryLines.join("\n")]);
  _ok("PR opened");

  console.log("\nnext: node scripts/release.js watch");
}

// ---- PR / review helpers (shared by watch / merge / push-fix) ------------

// Resolve the open release PR number for a branch; fail closed if none.
// A branch with no open PR is exit 0 with EMPTY stdout (`--jq '.[0].number'`
// over an empty array prints nothing), so "no PR" and "the lookup failed" are
// genuinely distinguishable — the old code just didn't distinguish them, and
// reported an expired token or a dropped connection as "no open PR for branch
// X", sending the operator to look for a PR that was there all along.
function _openPrNumber(branch) {
  var prNum = _captureQuery("open PR for " + branch, "gh",
                            ["pr", "list", "--head", branch, "--state", "open",
                             "--json", "number", "--jq", ".[0].number"]).stdout;
  if (!prNum) {
    throw new Error("release: no open PR for branch " + branch);
  }
  return prNum;
}

// gitleaks over the full working tree via the pinned OSS image. Shared by
// `push` (before the PR opens) and `push-fix` (after committing a fix, so the
// fix itself is scanned). The win32 bind-mount transform matches Docker
// Desktop's `//c/...` form -- the colon in `C:` confuses the `-v` splitter.
function _gitleaks() {
  _section("gitleaks");
  var mount;
  if (process.platform === "win32") {
    var posixified = ROOT.replace(/\\/g, "/");
    mount = "//" + posixified.charAt(0).toLowerCase() + posixified.slice(2);
  } else {
    mount = ROOT;
  }
  _run("docker", [
    "run", "--rm",
    "-v", mount + ":/repo",
    "-w", "//repo",
    "zricethezav/gitleaks:latest",
    "git", "--config=.gitleaks.toml", "--redact", "--exit-code=1",
  ]);
  _ok("gitleaks clean");
}

// Synchronous sleep with no busy-spin (release.js is a synchronous CLI).
function _sleepSync(ms) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

// Parse a captured gh JSON payload, failing CLOSED: a non-zero exit or an
// unparseable payload throws instead of degrading to the gate-passing empty
// value -- an unreadable review/thread state is not an empty one (a transient
// gh failure must never merge past a live finding).
function _ghJson(rv, what) {
  if (rv.status !== 0) {
    throw new Error("release: " + what + " lookup failed (gh exit " + rv.status + ") -- " +
                    "an unreadable result is not an empty one.\n" +
                    (rv.stderr || rv.stdout || "(no output)"));
  }
  try {
    return JSON.parse(rv.stdout || "");
  } catch (e) {
    throw new Error("release: " + what + " payload did not parse (" + ((e && e.message) || e) +
                    ") -- an unreadable result is not an empty one.");
  }
}

// Codex (the async PR reviewer) renders its login as the bare handle in
// GraphQL but with a "[bot]" suffix on some REST surfaces -- tolerate both.
var CODEX_LOGIN = "chatgpt-codex-connector";
function _isCodexLogin(login) {
  return String(login || "").replace(/\[bot\]$/, "") === CODEX_LOGIN;
}

// True once Codex has reviewed the PR's CURRENT head. It signals a review in
// two forms and both must count, or the wait times out on the clean case:
//   (1) a formal review node whose commit is the head (it HAS findings);
//   (2) a clean-verdict issue comment citing the head sha (no review node).
// Every lookup here fails CLOSED. Returning false on an unreadable answer is
// especially costly in this function: the caller polls it for ten minutes, so
// a gh outage spent the whole budget and then reported the timeout as Codex
// being slow — the one explanation that is definitely wrong.
function _codexReviewedHead(prNum) {
  var head = _captureQuery("PR #" + prNum + " head sha", "gh",
                           ["pr", "view", prNum, "--json", "headRefOid",
                            "--jq", ".headRefOid"]).stdout.trim();
  if (!head) {
    throw new Error("release: PR #" + prNum + " reported no head sha -- " +
                    "an unreadable result is not an empty one.");
  }
  var rv = _captureQuery("PR #" + prNum + " review list", "gh", ["api", "graphql",
    "-f", "query=query { repository(owner:\"blamejs\",name:\"blamejs\") { pullRequest(number:" + prNum +
      ") { reviews(last:100) { nodes { author{login} commit{oid} } } } } }",
    "--jq", ".data.repository.pullRequest.reviews.nodes"]);
  var nodes = _ghJson(rv, "PR #" + prNum + " review list");
  if ((nodes || []).some(function (r) {
    return r && r.author && _isCodexLogin(r.author.login) && r.commit && r.commit.oid === head;
  })) return true;
  var cv = _captureQuery("PR #" + prNum + " comment list", "gh",
                         ["pr", "view", prNum, "--json", "comments", "--jq", ".comments"]);
  var comments = _ghJson(cv, "PR #" + prNum + " comment list");
  var headPrefix = head.slice(0, 10);
  return (comments || []).some(function (c) {
    return c && c.author && _isCodexLogin(c.author.login) &&
           typeof c.body === "string" && c.body.indexOf(headPrefix) !== -1;
  });
}

// Block until Codex has reviewed the current head (fail-closed on timeout).
// The race: Codex reviews a minute or two AFTER the status checks go green,
// and require_review_thread_resolution can only block threads that EXIST at
// merge time -- so a merge fired the instant CI is green outruns Codex and
// ships its findings. RELEASE_SKIP_CODEX_WAIT=1 is the escape hatch for a
// confirmed Codex outage only, not a routine bypass.
// Poll cadence and budget. Held in an object rather than inline literals so
// the wait's branching (transient absorbed, stable aborts, timeout reports
// UNKNOWN) is testable without a ten-minute test.
var CODEX_WAIT = { stepMs: 20 * 1000, budgetMs: 10 * 60 * 1000 };

function _waitForCodexReview(prNum) {
  if (process.env.RELEASE_SKIP_CODEX_WAIT === "1") {
    _ok("Codex-review wait skipped (RELEASE_SKIP_CODEX_WAIT=1)");
    return;
  }
  // Measured against the clock, not by summing the sleeps: each tick can now
  // also spend _captureQuery's retry budget inside the lookup, so counting
  // only `stepMs` per pass understates elapsed time and stretches a "10
  // minute" wait well past ten minutes.
  var stepMs = CODEX_WAIT.stepMs, budgetMs = CODEX_WAIT.budgetMs;
  var startedAt = Date.now();
  console.log("waiting for Codex (" + CODEX_LOGIN + ") to review PR #" + prNum +
              " head before the thread gate (up to 10m; it reviews a bit after CI)...");
  // This poll IS a retry loop, thirty times longer than _captureQuery's. A
  // connection blip should therefore be absorbed and re-asked on the next
  // tick, NOT abort the merge -- but it must never be absorbed as "Codex has
  // not reviewed yet", which is what reading the failure as `false` used to do.
  // A stable rejection (an expired token, a deleted PR) aborts at once: asking
  // again for ten minutes cannot change that answer.
  var lastLookupFailure = null;
  while (Date.now() - startedAt <= budgetMs) {
    var reviewed = false;
    try {
      reviewed = _codexReviewedHead(prNum);
      lastLookupFailure = null;
    } catch (e) {
      if (!e || !e.lookupFailed || !e.transient) throw e;
      lastLookupFailure = e;
      console.log("  review lookup failed transiently; re-asking on the next tick -- " +
                  _firstLine(e.message));
    }
    if (reviewed) {
      _ok("Codex has reviewed the current PR head -- thread gate now sees its findings");
      return;
    }
    // Sleep only what is left. A full step here would carry the wait PAST the
    // budget it advertises -- a lookup that returns a moment before the
    // deadline would still sleep the whole step, and the retries inside the
    // lookup push it further. Moving the loop condition to the clock is only
    // half the job; the sleep has to respect the same clock.
    var remainingMs = budgetMs - (Date.now() - startedAt);
    if (remainingMs <= 0) break;
    _sleepSync(Math.min(stepMs, remainingMs));
  }
  if (lastLookupFailure) {
    throw new Error("release: could not read PR #" + prNum + " review state for 10m -- " +
      "the lookup kept failing, so whether Codex has reviewed this head is UNKNOWN " +
      "(not 'no'). Fix the connection to api.github.com and re-run " +
      "`node scripts/release.js merge`.\n" + lastLookupFailure.message);
  }
  throw new Error("release: Codex has not reviewed PR #" + prNum + " head after 10m. " +
    "It reviews asynchronously; a late finding must not be outrun by the merge. Re-run " +
    "`node scripts/release.js merge` once it posts, or set RELEASE_SKIP_CODEX_WAIT=1 " +
    "ONLY if Codex is confirmed disabled/down.");
}

// Land a fix on the OPEN release PR: stage-all + signed commit, then the
// pre-push gates (gitleaks + signature verify) with rollback-on-failure so a
// failed gate never dead-ends at the clean-tree guard, then push + re-request
// the Codex review of the new head. The manual "fix a Codex flag on the same
// branch" flow, made a single idempotent-once step.
function cmdPushFix(opts) {
  opts = opts || {};
  _section("push-fix");
  if (!_gitOnRelease()) {
    throw new Error("release: push-fix must run on a release/vX.Y.Z branch (it lands a fix on the open PR)");
  }
  if (!opts.message) {
    throw new Error("release: push-fix needs a commit message -- " +
      "node scripts/release.js push-fix -m \"<what the fix changes>\"");
  }
  if (_gitClean()) {
    throw new Error("release: nothing to commit -- stage the fix first " +
      "(push-fix captures the whole working tree with git add -A)");
  }
  var branch = _releaseBranchFor(_readPackageVersion());

  // Resolve the open PR FIRST and fail closed if there is none -- push-fix is
  // only valid for an already-open release PR, so this precedes any commit so a
  // stale branch whose PR already merged/closed doesn't get a new commit before
  // the lookup fails.
  var prNum = _openPrNumber(branch);

  _section("commit");
  _run("git", ["add", "-A"]);
  _run("git", ["commit", "-s", "-m", opts.message]);   // -s DCO; NOT --amend (head must move)
  _ok("signed fix commit");

  // Pre-push gates, all rolled back together on failure. gitleaks runs AFTER
  // the commit so the fix itself is scanned; the signature verify catches an
  // unsigned/badly-signed commit; and the touched-backend live-integration
  // gate runs EXACTLY as `push` does -- a fix that changes a backend-protocol
  // lib file must prove itself against the real service here too, or it could
  // reach the merge having only passed host smoke (the CI workflows don't run
  // test-integration.js). On any failure, soft-reset keeps the fix staged and
  // nothing reached the remote -- the operator fixes the cause and re-runs.
  try {
    _gitleaks();
    _verifyCommitSignature("new");
    cmdLiveIntegration({ skip: opts.skipLiveIntegration, skipReason: opts.liveSkipReason });
  } catch (gate) {
    _run("git", ["reset", "--soft", "HEAD~1"]);
    throw new Error("release: a pre-push gate failed -- the fix commit was rolled back " +
      "(your changes are kept staged). Fix the cause, then re-run push-fix.\n" + (gate.message || String(gate)));
  }

  _section("push");
  _run("git", ["push"]);   // branch already tracks origin from the initial push
  _ok("pushed fix to " + branch);

  // The push is the critical, already-completed work; re-requesting the review
  // is a best-effort follow-up. A failed comment must NOT throw (that would
  // leave the fix pushed but the review un-requested, and a rerun would stop at
  // the clean-tree guard) -- print the manual re-trigger instead.
  _section("re-request Codex review");
  var commentRv = _run("gh", ["pr", "comment", prNum, "--body", "@codex review"], { allowFail: true });
  if (commentRv.status === 0) {
    _ok("posted @codex review on PR #" + prNum + " -- Codex will review the new head (~5-6m)");
  } else {
    console.log("\nwarn: the fix IS pushed, but posting `@codex review` failed (transient?).");
    console.log("      Re-trigger it manually (push-fix would refuse to rerun -- the tree is now clean):");
    console.log("        gh pr comment " + prNum + " --body \"@codex review\"");
  }

  console.log("\nNext:");
  console.log("  - Resolve any Codex thread THIS fix addresses (fix it, never dismiss).");
  console.log("  - Then: node scripts/release.js merge   (waits for the re-review, then gates on threads)");
}

// Fetch every UNRESOLVED review thread on the PR with enough context to act on
// it: the file:line, the reviewer that raised it (CodeQL = github-advanced-
// security, Codex = chatgpt-codex-connector, lint = github-code-quality), the
// first line of the finding, the thread id, and the resolve mutation. Bot
// reviews post ASYNCHRONOUSLY — often a minute or two AFTER the status checks
// finish — so this is the authoritative check at merge time, not just watch.
function _unresolvedThreads(prNum) {
  // PAGINATE every review thread. GitHub caps a GraphQL connection's `first` at 100,
  // so a single first:100 page silently drops thread 101+ -- and a long-lived release
  // PR accrues far more than 100 threads over a deep review loop, so the gate reported
  // "no unresolved threads" while later-page findings still blocked the merge. Walk the
  // cursor to completion; a bounded page cap backstops a runaway rather than truncating
  // real work (the loop stops at hasNextPage=false well before it).
  var nodes = [];
  var after = null;
  var walkedToEnd = false;
  for (var page = 0; page < 100; page += 1) {
    var afterClause = after ? (", after: \"" + after + "\"") : "";
    var rv = _captureQuery("PR #" + prNum + " review-thread page " + page, "gh", ["api", "graphql",
      "-f", "query=query { repository(owner:\"blamejs\",name:\"blamejs\") { pullRequest(number:" + prNum +
        ") { reviewThreads(first:100" + afterClause + ") { pageInfo { hasNextPage endCursor } nodes { " +
        "id isResolved path line comments(first:1) { nodes { author{login} body } } } } } } }"]);
    // Fail closed: [] is this gate's PASS value, so a failed lookup must throw rather
    // than report the thread list as empty (an unreadable state is not an empty one --
    // a transient gh failure must never merge past a live finding).
    var data = _ghJson(rv, "PR #" + prNum + " review-thread page " + page);
    var conn = data && data.data && data.data.repository && data.data.repository.pullRequest &&
               data.data.repository.pullRequest.reviewThreads;
    if (!conn || !conn.pageInfo) {
      throw new Error("release: PR #" + prNum + " review-thread page " + page +
                      " had no reviewThreads connection -- an unreadable result is not an empty one.");
    }
    nodes = nodes.concat(conn.nodes || []);
    if (!conn.pageInfo.hasNextPage) { after = null; walkedToEnd = true; break; }
    after = conn.pageInfo.endCursor;
  }
  // Fail closed at the page cap: if the loop exhausted its bound while a successor page was
  // still pending (hasNextPage=true on the last page walked), the thread set is TRUNCATED --
  // a later-page unresolved finding would be invisible and this authoritative merge gate
  // would pass on an incomplete prefix. Refuse rather than treat the cap as completion.
  if (!walkedToEnd) {
    throw new Error("release: PR #" + prNum + " has more review threads than the pagination cap " +
      "(100 pages x 100 = 10,000) can walk -- refusing to evaluate a truncated thread set, since a " +
      "later-page unresolved finding would be invisible and merge past it. Resolve stale threads or raise the cap.");
  }
  return nodes.filter(function (t) { return t && t.isResolved === false; })
    .map(function (t) {
      var c = t.comments && t.comments.nodes && t.comments.nodes[0];
      return {
        id:     t.id,
        path:   t.path || "(pr-level)",
        line:   t.line,
        author: (c && c.author && c.author.login) || "(unknown)",
        body:   (c && c.body) || "",
      };
    });
}

// Surface each unresolved thread with the exact finding it raises + how to
// clear it, so a BLOCKED merge names its cause instead of "state=BLOCKED".
function _printUnresolvedThreads(unresolved) {
  console.log("\n" + unresolved.length + " unresolved review thread(s) block the merge " +
              "(main-protection requires every thread resolved):\n");
  unresolved.forEach(function (t, i) {
    var lines = (t.body || "").split("\n");
    var firstLine = "(no text)";
    for (var li = 0; li < lines.length; li++) {
      if (lines[li].trim().length > 0) { firstLine = lines[li]; break; }
    }
    // Strip markdown badge images / formatting noise from Codex P1/P2 headers.
    firstLine = firstLine.replace(/!\[[^\]]*\]\([^)]*\)/g, "").replace(/[*_`#>]/g, "").trim();
    console.log("  " + (i + 1) + ". [" + t.author + "] " + t.path +
                (t.line != null ? ":" + t.line : ""));
    console.log("     " + firstLine.slice(0, 160));
    console.log("     resolve: gh api graphql -f query='mutation { resolveReviewThread(" +
                "input:{threadId:\"" + t.id + "\"}){ thread { isResolved } } }'");
  });
  console.log("\nFix each finding in a NEW commit on the branch (never dismiss), then run the");
  console.log("resolve command above for its thread. Re-run: node scripts/release.js merge");
}

function cmdWatch() {
  _section("watch");
  var prNum = _openPrNumber(_releaseBranchFor(_readPackageVersion()));
  console.log("PR #" + prNum);

  _run("gh", ["pr", "checks", prNum, "--watch"], { allowFail: true });

  var unresolved = _unresolvedThreads(prNum);
  if (unresolved.length > 0) {
    _printUnresolvedThreads(unresolved);
    process.exit(3);
  }
  // Zero here is NOT conclusive: bot reviews (CodeQL / Codex / code-quality)
  // can post a minute or two after the checks finish. `merge` re-pulls and is
  // the authoritative gate; treat a clean watch as "checks done", not "no
  // findings".
  _ok("zero unresolved threads at watch time (merge re-checks — bot reviews may still be posting)");

  console.log("\nnext: node scripts/release.js merge");
}

function cmdMerge() {
  _section("merge");
  var next = _readPackageVersion();
  var branch = _releaseBranchFor(next);
  var prNum = _openPrNumber(branch);

  // Close the async-review race BEFORE reading threads: Codex reviews a minute
  // or two AFTER CI goes green, so a merge fired the instant the checks pass
  // outruns its findings. Wait until it has reviewed THIS head, so the thread
  // gate below sees any findings it raises.
  _waitForCodexReview(prNum);

  // Through _ghJson, so an unreadable payload throws instead of degrading to
  // `{}` -- which used to surface as the actively misleading "not mergeable
  // (state=undefined mergeable=undefined)".
  var state = _ghJson(_captureQuery("PR #" + prNum + " merge state", "gh",
    ["pr", "view", prNum, "--json", "mergeStateStatus,mergeable"]),
    "PR #" + prNum + " merge state");
  // Pull unresolved review threads FIRST, at merge time. A BLOCKED state is
  // most often unresolved threads — the bot reviews (CodeQL = github-advanced-
  // security, Codex = chatgpt-codex-connector, lint = github-code-quality) post
  // asynchronously, AFTER the status checks finish, so `watch` can have seen
  // zero while they were still landing. Surface exactly which findings block
  // the merge instead of an opaque "state=BLOCKED", so the operator knows what
  // to fix + resolve. (main-protection's require_review_thread_resolution makes
  // any open thread BLOCK; this is the recovery path.)
  var unresolved = _unresolvedThreads(prNum);
  if (state.mergeStateStatus !== "CLEAN" || state.mergeable !== "MERGEABLE") {
    if (unresolved.length > 0) _printUnresolvedThreads(unresolved);
    throw new Error("release: PR #" + prNum + " not mergeable (state=" +
                    state.mergeStateStatus + " mergeable=" + state.mergeable + ")" +
                    (unresolved.length > 0
                      ? " — " + unresolved.length + " unresolved review thread(s); see above"
                      : " — no unresolved threads; check required status checks / signatures"));
  }
  // Belt-and-suspenders: even if the API reports CLEAN, refuse on any open
  // thread (a thread can open in the window between the state read and merge).
  if (unresolved.length > 0) {
    _printUnresolvedThreads(unresolved);
    throw new Error("release: refusing to merge PR #" + prNum + " — " +
                    unresolved.length + " unresolved review thread(s)");
  }
  _run("gh", ["pr", "merge", prNum, "--squash", "--delete-branch"]);
  _ok("PR #" + prNum + " squash-merged");

  _run("git", ["checkout", "main"]);
  _run("git", ["pull", "origin", "main"]);

  console.log("\nnext: node scripts/release.js tag");
}

function cmdTag() {
  _section("tag");
  if (!_gitOnMain()) {
    throw new Error("release: tag must run on main (post-merge)");
  }
  var next = _readPackageVersion();
  var tag = "v" + next;

  // Refuse if the tag already exists. The release-tags ruleset
  // refuses tag overwrites server-side, but a clearer client-side
  // error makes the surprise smaller.
  var existing = _captureOk("existing tag " + tag, "git", ["tag", "-l", tag]).stdout;
  if (existing === tag) {
    throw new Error("release: tag " + tag + " already exists locally");
  }
  _run("git", ["tag", "-s", tag, "-m", tag]);
  _run("git", ["push", "origin", tag]);
  _ok("tagged + pushed " + tag);

  // Deliberately raw: `git tag -v` exits non-zero on an unverifiable
  // signature, so a non-zero exit is part of the answer rather than a failure
  // to answer. The verdict comes from the output text, and a spawn failure is
  // reported as its own case so "could not run the check" never prints as
  // "checked, and it was fine".
  var verify = _capture("git", ["tag", "-v", tag]);
  if (verify.spawnError) {
    console.error("warning: could not run `git tag -v " + tag + "` (" + verify.spawnError +
                  ") -- the tag signature was NOT verified.");
  } else if (verify.stderr.indexOf("Good") === -1 && verify.stdout.indexOf("Good") === -1) {
    console.error("warning: `git tag -v " + tag + "` did not report a Good signature:");
    console.error(verify.stderr || verify.stdout);
  } else {
    _ok("tag signature: Good");
  }

  console.log("\nnext: node scripts/release.js publish");
}

function cmdPublish() {
  _section("publish");
  var next = _readPackageVersion();

  // A failed run lookup used to print "workflow may not be configured", which
  // reads as a settled fact about the repository rather than a network error —
  // and then skipped the watch, so a publish nobody watched looked watched.
  _watchWorkflowRun("npm-publish.yml");
  _watchWorkflowRun("release-container.yml");

  _section("verify");
  var npm = _captureQueryTolerant("published npm version", "npm",
                                  ["view", "@blamejs/core", "version"]);
  if (!npm.ok) {
    console.error("warning: could not read the published npm version, so this step " +
                  "did NOT confirm " + next + " reached the registry.");
    console.error(npm.failure);
    return;
  }
  console.log("npm @blamejs/core: " + (npm.stdout || "(no version reported)") +
              "  (expected: " + next + ")");
  if (npm.stdout === next) {
    _ok("npm matches " + next);
  } else {
    console.error("warning: npm version doesn't match expected — workflow may still be in flight");
  }
}

function _watchWorkflowRun(workflow) {
  _section(workflow.replace(/\.ya?ml$/, "") + " workflow");
  var runId = _captureQuery("latest " + workflow + " run", "gh",
                            ["run", "list", "--workflow=" + workflow, "--limit", "1",
                             "--json", "databaseId", "--jq", ".[0].databaseId"]).stdout;
  if (!runId) {
    console.log("no " + workflow + " run found (the workflow has never run for this repo)");
    return;
  }
  _run("gh", ["run", "watch", runId, "--exit-status"], { allowFail: true });
}

function cmdAll(opts) {
  cmdPrepare(opts);
  cmdSmoke();
  cmdCommit();
  cmdPush(opts);
  cmdWatch();
  cmdMerge();
  cmdTag();
  cmdPublish();
}

function cmdStatus() {
  _section("status");
  console.log("branch:           " + _gitBranch());
  console.log("clean:            " + _gitClean());
  console.log("package version:  " + _readPackageVersion());
  console.log("release-notes:    " + (fs.existsSync(_releaseNotesPath(_readPackageVersion())) ? "present" : "missing"));
  // `status` is read-only and stays runnable with the network down, but it has
  // to say the lookup FAILED rather than print "(none)" — the whole point of
  // the command is to tell the operator where the release stands, and "no open
  // PR" is a very different place from "I could not find out".
  var pr = _captureQueryTolerant("open PR", "gh",
    ["pr", "list", "--author", "@me",
     "--head",  _releaseBranchFor(_readPackageVersion()),
     "--state", "open",
     "--json",  "number,mergeStateStatus,mergeable",
     "--jq",    ".[0]"]);
  if (!pr.ok) {
    console.log("open PR:          (lookup failed — " + _firstLine(pr.failure) + ")");
  } else if (pr.stdout) {
    console.log("open PR:          " + pr.stdout);
  } else {
    console.log("open PR:          (none)");
  }
}

function cmdHelp() {
  console.log("release.js — orchestrated release flow");
  console.log("");
  console.log("Usage:");
  console.log("  node scripts/release.js prepare [--minor]   # bump + regen + static gates");
  console.log("  node scripts/release.js regen               # re-regen artifacts after release-notes edits");
  console.log("  node scripts/release.js smoke               # framework + wiki e2e if needed");
  console.log("  node scripts/release.js commit              # release branch + signed commit");
  console.log("  node scripts/release.js live-integration    # touched-backend live tests (docker stack)");
  console.log("  node scripts/release.js push                # live-integration + gitleaks + push + open PR");
  console.log("  node scripts/release.js push-fix -m \"...\"    # land a fix on the open PR (commit+gitleaks+push+re-review)");
  console.log("  node scripts/release.js watch               # CI watch + flag Codex threads");
  console.log("  node scripts/release.js merge               # waits for Codex review of head, then squash-merge if CLEAN");
  console.log("  node scripts/release.js tag                 # signed tag + push tag");
  console.log("  node scripts/release.js publish             # watch publish workflows");
  console.log("  node scripts/release.js all [--minor]       # all eight in sequence");
  console.log("  node scripts/release.js status              # current branch + version state");
  console.log("  node scripts/release.js help                # this banner");
  console.log("");
  console.log("Live-integration gate (runs inside push):");
  console.log("  Detects which backends the release touched (diffing changed lib");
  console.log("  files against a backend->files map), brings up docker-compose.test.yml,");
  console.log("  and runs the matching test/integration tests live. A failing test or an");
  console.log("  unavailable docker stack is a HARD STOP — the push is refused. To override");
  console.log("  (audited, never silent): --skip-live-integration --live-skip-reason=\"<why>\".");
}

// ---- Dispatch ------------------------------------------------------------

// Parse a `--flag=value` form into its value; returns undefined if absent
// or if the flag was passed without an `=value` (bare `--flag`).
function _flagValue(args, name) {
  var prefix = name + "=";
  for (var i = 0; i < args.length; i++) {
    if (args[i].indexOf(prefix) === 0) return args[i].slice(prefix.length);
  }
  return undefined;
}

// push-fix's commit message: `-m "<msg>"` / `--message "<msg>"` / `--message=<msg>`.
function _messageArg(args) {
  var v = _flagValue(args, "--message");
  if (v !== undefined) return v;
  var i = args.indexOf("-m");
  if (i === -1) i = args.indexOf("--message");
  if (i !== -1 && i + 1 < args.length) return args[i + 1];
  return undefined;
}

function _parseOpts(args) {
  return {
    minor: args.indexOf("--minor") !== -1,
    message: _messageArg(args),
    // The live-integration gate is on by default. `--skip-live-integration`
    // opts out, but ONLY together with `--live-skip-reason="<why>"`; the
    // reason is printed loudly and recorded in the release-flow transcript.
    // A flag with no reason is refused inside cmdLiveIntegration — the gate
    // is never silently skippable.
    skipLiveIntegration: args.indexOf("--skip-live-integration") !== -1,
    liveSkipReason:      _flagValue(args, "--live-skip-reason"),
  };
}

function main(argv) {
  var sub  = argv[2] || "help";
  var args = argv.slice(3);
  var opts = _parseOpts(args);

  try {
    switch (sub) {
      case "prepare": cmdPrepare(opts); break;
      case "regen":   cmdRegen();       break;
      case "smoke":   cmdSmoke();       break;
      case "commit":  cmdCommit();      break;
      case "live-integration":
      case "live":    cmdLiveIntegration({
                        skip:       opts.skipLiveIntegration,
                        skipReason: opts.liveSkipReason,
                      });            break;
      case "push":    cmdPush(opts);    break;
      case "push-fix": cmdPushFix(opts); break;
      case "watch":   cmdWatch();       break;
      case "merge":   cmdMerge();       break;
      case "tag":     cmdTag();         break;
      case "publish": cmdPublish();     break;
      case "all":     cmdAll(opts);     break;
      case "status":  cmdStatus();      break;
      case "help":
      case "--help":
      case "-h":      cmdHelp();        break;
      default:
        console.error("release: unknown subcommand '" + sub + "'");
        cmdHelp();
        process.exit(1);
    }
  } catch (e) {
    console.error("\nrelease: FAIL — " + (e.message || e));
    process.exit(1);
  }
}

// Exported for the fail-closed unit tests. `_setCaptureForTest` swaps the
// shell-out seam so each gate can be driven with a stub that fails, proving it
// refuses rather than reading the failure as an empty answer.
module.exports = {
  _captureOk:               _captureOk,
  _captureQuery:            _captureQuery,
  _captureQueryTolerant:    _captureQueryTolerant,
  _isTransientQueryFailure: _isTransientQueryFailure,
  _changedFilesForBackendDetection: _changedFilesForBackendDetection,
  _detectTouchedBackends:   _detectTouchedBackends,
  _openPrNumber:            _openPrNumber,
  _unresolvedThreads:       _unresolvedThreads,
  _codexReviewedHead:       _codexReviewedHead,
  _waitForCodexReview:      _waitForCodexReview,
  _mergeBaseRef:            _mergeBaseRef,
  _wikiTouched:             _wikiTouched,
  CODEX_WAIT:               CODEX_WAIT,
  _gitClean:                _gitClean,
  _gitBranch:               _gitBranch,
  _ghJson:                  _ghJson,
  BACKEND_LIVE_MAP:         BACKEND_LIVE_MAP,
  TRANSIENT_QUERY_MARKERS:  TRANSIENT_QUERY_MARKERS,
  QUERY_ATTEMPTS:           QUERY_ATTEMPTS,
  QUERY_BACKOFF_MS:         QUERY_BACKOFF_MS,
  cmdSmoke:                 cmdSmoke,
  cmdTag:                   cmdTag,
  cmdPublish:               cmdPublish,
  cmdStatus:                cmdStatus,
  main:                     main,
  _setCaptureForTest: function (fn) { _captureImpl = fn || _captureSpawn; },
  _setRunForTest:     function (fn) { _runImpl = fn || _runSpawn; },
};

if (require.main === module) {
  main(process.argv);
}
