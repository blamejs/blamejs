"use strict";
/**
 * cli — the engine behind `blamejs` on the command line.
 *
 * bin/blamejs.js is a 4-line shim that calls cli.main(process.argv.slice(2)).
 * Putting the dispatch logic in lib/ means tests drive it without
 * spawning a child process: pass argv + a captured-output writer +
 * env, get an exit code back.
 *
 *   var cli = b.cli;
 *   var captured = { out: "", err: "" };
 *   var rc = await cli.main(["migrate", "status", "--db", "./test.db"], {
 *     stdout: { write: function (s) { captured.out += s; } },
 *     stderr: { write: function (s) { captured.err += s; } },
 *     env:    {},
 *     cwd:    "/repo",
 *   });
 *
 * Subcommands ship one at a time as the framework grows. The
 * dispatch table is the registry — adding `vault rotate`, `audit verify`,
 * `subject export` etc. lands as new entries here, not new bin scripts.
 *
 * Currently shipped:
 *   blamejs migrate up    --db <path> [--dir <path>]
 *   blamejs migrate down  --db <path> [--dir <path>] [--steps N]
 *   blamejs migrate status --db <path> [--dir <path>]
 *   blamejs dev           --command <cmd> [--watch <dir>...] [--grace-ms N]
 *   blamejs version
 *   blamejs help [<command>]
 *
 * The migrate command operates against a node:sqlite file directly —
 * no vault / framework bootstrap. Encrypted-at-rest dbs are out of
 * scope for this slice; operators with that mode either run migrations
 * before encryption or temporarily switch the file to plaintext.
 */

var path = require("path");
var apiSnapshot = require("./api-snapshot");
var auditTools = require("./audit-tools");
var cliHelpers = require("./cli-helpers");
var constants = require("./constants");
var dev = require("./dev");
var migrations = require("./migrations");
var restoreBundle = require("./restore-bundle");
var seeders = require("./seeders");
var vaultPassphraseOps = require("./vault/passphrase-ops");

var DEFAULT_MIG_DIR = "./migrations";
var DEFAULT_SEED_DIR = "./seeders";

function _writeLine(stream, line) {
  if (!stream || typeof stream.write !== "function") return;
  stream.write(line + "\n");
}

// Minimal argv parser: positional args + flag map. Supports both
// `--flag value` and `--flag=value`. Single-dash forms (-v) treated
// as long aliases to keep the surface predictable.
function _parseArgs(argv) {
  var pos = [];
  var flags = {};
  for (var i = 0; i < argv.length; i++) {
    var tok = argv[i];
    if (tok === "--") {
      for (var j = i + 1; j < argv.length; j++) pos.push(argv[j]);
      break;
    }
    if (tok.indexOf("--") === 0) {
      var name = tok.slice(2);
      var eq = name.indexOf("=");
      var val;
      if (eq !== -1) {
        val = name.slice(eq + 1);
        name = name.slice(0, eq);
      } else if (i + 1 < argv.length && argv[i + 1].indexOf("--") !== 0) {
        val = argv[++i];
      } else {
        val = true; // boolean flag
      }
      flags[name] = val;
    } else if (tok.indexOf("-") === 0 && tok.length === 2) {
      // -v, -h
      flags[tok.slice(1)] = true;
    } else {
      pos.push(tok);
    }
  }
  return { pos: pos, flags: flags };
}

function _resolvePath(p, cwd) {
  if (!p) return p;
  if (path.isAbsolute(p)) return p;
  return path.resolve(cwd || process.cwd(), p);
}

function _openSqlite(dbPath) {
  // Lazy-required so the CLI doesn't crash on `blamejs version` or
  // `blamejs help` if node:sqlite isn't usable for some reason.
  var { DatabaseSync } = require("node:sqlite");
  return new DatabaseSync(dbPath);
}

// ---- Subcommand: migrate ----

var MIGRATE_USAGE = [
  "Usage: blamejs migrate <subcommand> [flags]",
  "",
  "Subcommands:",
  "  up                Apply all pending migrations",
  "  down              Roll back the most-recent applied migration",
  "  status            Print applied + pending migrations",
  "",
  "Flags:",
  "  --db <path>       Path to the SQLite database file (required)",
  "  --dir <path>      Path to migrations directory (default ./migrations)",
  "  --steps <N>       For down: number of migrations to revert (default 1)",
].join("\n");

async function _runMigrate(args, ctx) {
  if (args.pos.length === 0) {
    _writeLine(ctx.stderr, MIGRATE_USAGE);
    return 2;
  }
  var sub = args.pos[0];
  if (sub === "help" || args.flags.help || args.flags.h) {
    _writeLine(ctx.stdout, MIGRATE_USAGE);
    return 0;
  }
  if (sub !== "up" && sub !== "down" && sub !== "status") {
    _writeLine(ctx.stderr, "blamejs migrate: unknown subcommand '" + sub + "'");
    _writeLine(ctx.stderr, MIGRATE_USAGE);
    return 2;
  }

  var dbPath = args.flags.db;
  if (!dbPath || dbPath === true) {
    _writeLine(ctx.stderr, "blamejs migrate " + sub + ": --db <path> is required");
    return 2;
  }
  dbPath = _resolvePath(String(dbPath), ctx.cwd);

  var dir = _resolvePath(String(args.flags.dir || DEFAULT_MIG_DIR), ctx.cwd);

  var db;
  try { db = _openSqlite(dbPath); }
  catch (e) {
    _writeLine(ctx.stderr, "blamejs migrate: cannot open db at " + dbPath +
      ": " + ((e && e.message) || String(e)));
    return 1;
  }

  try {
    var runner = migrations.create({ db: db, dir: dir });

    if (sub === "status") {
      var s = runner.status();
      _writeLine(ctx.stdout, "applied: " + s.applied.length + " / " + s.total);
      for (var i = 0; i < s.applied.length; i++) {
        _writeLine(ctx.stdout, "  ✓ " + s.applied[i].name +
          " (applied " + s.applied[i].appliedAt + ")");
      }
      _writeLine(ctx.stdout, "pending: " + s.pending.length);
      for (var j = 0; j < s.pending.length; j++) {
        _writeLine(ctx.stdout, "  · " + s.pending[j]);
      }
      return 0;
    }

    if (sub === "up") {
      var r = runner.up();
      if (r.applied.length === 0) {
        _writeLine(ctx.stdout, "no pending migrations (" + r.skipped.length + " already applied)");
      } else {
        _writeLine(ctx.stdout, "applied " + r.applied.length + " migration(s):");
        for (var k = 0; k < r.applied.length; k++) {
          _writeLine(ctx.stdout, "  ✓ " + r.applied[k]);
        }
      }
      return 0;
    }

    if (sub === "down") {
      var steps = args.flags.steps === undefined ? 1 : Number(args.flags.steps);
      if (!Number.isFinite(steps) || steps < 1 || Math.floor(steps) !== steps) {
        _writeLine(ctx.stderr, "blamejs migrate down: --steps must be a positive integer");
        return 2;
      }
      var rd = runner.down({ steps: steps });
      if (rd.reverted.length === 0) {
        _writeLine(ctx.stdout, "nothing to revert");
      } else {
        _writeLine(ctx.stdout, "reverted " + rd.reverted.length + " migration(s):");
        for (var m = 0; m < rd.reverted.length; m++) {
          _writeLine(ctx.stdout, "  ↶ " + rd.reverted[m]);
        }
      }
      return 0;
    }
  } catch (e) {
    var msg = (e && e.message) || String(e);
    var code = (e && e.code) || "ERROR";
    _writeLine(ctx.stderr, "blamejs migrate " + sub + ": " + code + ": " + msg);
    return 1;
  } finally {
    try { db.close(); } catch (_e) { /* close best-effort */ }
  }

  return 0;
}

// ---- Subcommand: seed ----

var SEED_USAGE = [
  "Usage: blamejs seed <subcommand> [flags]",
  "",
  "Subcommands:",
  "  run               Apply pending seeds for the given env",
  "  status            Print applied + pending seeds for the given env",
  "",
  "Flags:",
  "  --db <path>       Path to the SQLite database file               [required]",
  "  --env <name>      Environment to seed (dev / test / prod / ...)  [required]",
  "  --dir <path>      Path to seeders directory (default ./seeders)",
  "  --only <name>     Apply just one seed by filename (run subcommand only)",
  "  --force           Re-apply already-applied seeds (operator-explicit)",
].join("\n");

async function _runSeed(args, ctx) {
  if (args.pos.length === 0) {
    _writeLine(ctx.stderr, SEED_USAGE);
    return 2;
  }
  var sub = args.pos[0];
  if (sub === "help" || args.flags.help || args.flags.h) {
    _writeLine(ctx.stdout, SEED_USAGE);
    return 0;
  }
  if (sub !== "run" && sub !== "status") {
    _writeLine(ctx.stderr, "blamejs seed: unknown subcommand '" + sub + "'");
    _writeLine(ctx.stderr, SEED_USAGE);
    return 2;
  }

  var dbPath = args.flags.db;
  if (!dbPath || dbPath === true) {
    _writeLine(ctx.stderr, "blamejs seed " + sub + ": --db <path> is required");
    return 2;
  }
  dbPath = _resolvePath(String(dbPath), ctx.cwd);

  var env = args.flags.env;
  if (!env || env === true) {
    _writeLine(ctx.stderr, "blamejs seed " + sub + ": --env <name> is required");
    return 2;
  }

  var dir = _resolvePath(String(args.flags.dir || DEFAULT_SEED_DIR), ctx.cwd);

  var db;
  try { db = _openSqlite(dbPath); }
  catch (e) {
    _writeLine(ctx.stderr, "blamejs seed: cannot open db at " + dbPath +
      ": " + ((e && e.message) || String(e)));
    return 1;
  }

  try {
    var runner = seeders.create({ db: db, dir: dir });

    if (sub === "status") {
      var s = await runner.status({ env: String(env) });
      _writeLine(ctx.stdout, "env: " + s.env);
      _writeLine(ctx.stdout, "applied: " + s.applied.length + " / " + s.total);
      for (var i = 0; i < s.applied.length; i++) {
        _writeLine(ctx.stdout, "  ✓ " + s.applied[i].name +
          " (applied " + s.applied[i].appliedAt + ")");
      }
      _writeLine(ctx.stdout, "pending: " + s.pending.length);
      for (var j = 0; j < s.pending.length; j++) {
        _writeLine(ctx.stdout, "  · " + s.pending[j]);
      }
      if (s.rerunnable.length > 0) {
        _writeLine(ctx.stdout, "rerunnable: " + s.rerunnable.length);
        for (var k = 0; k < s.rerunnable.length; k++) {
          _writeLine(ctx.stdout, "  ↻ " + s.rerunnable[k]);
        }
      }
      return 0;
    }

    if (sub === "run") {
      var only = args.flags.only ? String(args.flags.only) : undefined;
      var force = !!args.flags.force;
      var r = await runner.run({ env: String(env), only: only, force: force });
      if (r.applied.length === 0) {
        _writeLine(ctx.stdout, "no seeds applied (" + r.skipped.length + " skipped)");
      } else {
        _writeLine(ctx.stdout, "applied " + r.applied.length + " seed(s):");
        for (var m = 0; m < r.applied.length; m++) {
          _writeLine(ctx.stdout, "  ✓ " + r.applied[m]);
        }
      }
      if (r.skipped.length > 0) {
        _writeLine(ctx.stdout, "skipped " + r.skipped.length + " (already applied)");
      }
      return 0;
    }
  } catch (e) {
    var msg = (e && e.message) || String(e);
    var code = (e && e.code) || "ERROR";
    _writeLine(ctx.stderr, "blamejs seed " + sub + ": " + code + ": " + msg);
    return 1;
  } finally {
    try { db.close(); } catch (_e) { /* close best-effort */ }
  }

  return 0;
}

// ---- Subcommand: dev ----

var DEV_USAGE = [
  "Usage: blamejs dev --command <cmd> [args] [flags]",
  "",
  "Spawn a child process and restart it on file changes.",
  "",
  "Flags:",
  "  --command <cmd>     Program to spawn (e.g. node)              [required]",
  "  --arg <value>       Argument for the spawned program (repeatable)",
  "  --watch <dir>       Directory to watch (repeatable; default '.')",
  "  --ignore <pattern>  Glob/regex fragment to ignore (repeatable)",
  "  --grace-ms <N>      Debounce window in ms (default 250)",
  "  --kill-signal <S>   Signal to send on restart (default SIGTERM)",
  "",
  "Example:",
  "  blamejs dev --command node --arg ./server.js --watch ./routes --watch ./views",
].join("\n");

function _coerceList(val) {
  if (val === undefined || val === null) return [];
  return Array.isArray(val) ? val.slice() : [val];
}

async function _runDev(args, ctx) {
  if (args.flags.help || args.flags.h) {
    _writeLine(ctx.stdout, DEV_USAGE);
    return 0;
  }
  var command = args.flags.command;
  if (!command || command === true) {
    _writeLine(ctx.stderr, "blamejs dev: --command <cmd> is required");
    _writeLine(ctx.stderr, DEV_USAGE);
    return 2;
  }
  var argList   = _coerceList(args.flags.arg).map(String);
  var watchList = _coerceList(args.flags.watch).map(String);
  var ignoreList = _coerceList(args.flags.ignore).map(function (s) { return new RegExp(String(s)); });
  var graceMs = args.flags["grace-ms"] !== undefined ? Number(args.flags["grace-ms"]) : undefined;
  if (graceMs !== undefined && (!Number.isFinite(graceMs) || graceMs < 0)) {
    _writeLine(ctx.stderr, "blamejs dev: --grace-ms must be a non-negative number");
    return 2;
  }
  var killSignal = args.flags["kill-signal"];

  var d = dev.create({
    command:    String(command),
    args:       argList,
    watch:      watchList.length ? watchList : undefined,
    ignore:     ignoreList.length ? ignoreList : undefined,
    graceMs:    graceMs,
    killSignal: typeof killSignal === "string" ? killSignal : undefined,
    cwd:        ctx.cwd,
    env:        ctx.env,
  });

  // Forward parent SIGINT/SIGTERM to the child via stop()
  var stopped = false;
  function shutdown() {
    if (stopped) return;
    stopped = true;
    d.stop().then(function () { /* exit naturally */ });
  }
  process.once("SIGINT",  shutdown);
  process.once("SIGTERM", shutdown);

  try {
    await d.start();
  } catch (e) {
    _writeLine(ctx.stderr, "blamejs dev: " + ((e && e.message) || String(e)));
    return 1;
  }
  // The dev loop runs until the operator interrupts. Resolve a
  // never-settling promise so main() awaits forever; the SIGINT handler
  // above flips stopped+resolves on Ctrl-C.
  await new Promise(function (resolve) {
    var iv = setInterval(function () {
      if (stopped) { clearInterval(iv); resolve(); }
    }, 250);
    if (typeof iv.unref === "function") iv.unref();
  });
  return 0;
}

// ---- Subcommand: api-snapshot ----

var API_SNAPSHOT_USAGE = [
  "Usage: blamejs api-snapshot <subcommand> [flags]",
  "",
  "Subcommands:",
  "  capture            Walk the framework's public surface and write a snapshot",
  "  compare            Diff the current surface against a saved snapshot",
  "",
  "Flags:",
  "  --file <path>      Snapshot file path (default ./api-snapshot.json)",
  "  --module <path>    Module to inspect (default require('@blamejs/core'))",
  "",
  "Exit codes:",
  "  0  no changes (compare) or write succeeded (capture)",
  "  1  breaking changes detected (compare)",
  "  2  bad invocation",
].join("\n");

function _resolveTargetModule(modulePath, ctx) {
  // Default: load index.js from the framework root (one level up from lib/cli.js)
  if (!modulePath) {
    var root = path.resolve(__dirname, "..");
    return require(path.join(root, "index.js"));
  }
  var abs = path.isAbsolute(modulePath) ? modulePath : path.resolve(ctx.cwd, modulePath);
  delete require.cache[require.resolve(abs)];
  return require(abs);
}

function _runApiSnapshot(args, ctx) {
  if (args.flags.help || args.flags.h) {
    _writeLine(ctx.stdout, API_SNAPSHOT_USAGE);
    return 0;
  }
  if (args.pos.length === 0) {
    _writeLine(ctx.stderr, API_SNAPSHOT_USAGE);
    return 2;
  }
  var sub = args.pos[0];
  var file = String(args.flags.file || "./api-snapshot.json");
  var filePath = path.isAbsolute(file) ? file : path.resolve(ctx.cwd, file);
  var modulePathOpt = typeof args.flags.module === "string" ? args.flags.module : null;

  if (sub === "capture") {
    var target;
    try { target = _resolveTargetModule(modulePathOpt, ctx); }
    catch (e) {
      _writeLine(ctx.stderr, "blamejs api-snapshot capture: cannot load module: " +
        ((e && e.message) || String(e)));
      return 1;
    }
    var snap;
    try { snap = apiSnapshot.capture(target); }
    catch (e) {
      _writeLine(ctx.stderr, "blamejs api-snapshot capture: " +
        ((e && e.message) || String(e)));
      return 1;
    }
    apiSnapshot.write(snap, filePath);
    _writeLine(ctx.stdout, "wrote snapshot to " + filePath +
      " (frameworkVersion " + snap.frameworkVersion + ")");
    return 0;
  }

  if (sub === "compare") {
    var loaded;
    try { loaded = apiSnapshot.read(filePath); }
    catch (e) {
      _writeLine(ctx.stderr, "blamejs api-snapshot compare: " +
        ((e && e.message) || String(e)));
      return 1;
    }
    var current;
    try {
      var t = _resolveTargetModule(modulePathOpt, ctx);
      current = apiSnapshot.capture(t);
    } catch (e) {
      _writeLine(ctx.stderr, "blamejs api-snapshot compare: cannot capture current surface: " +
        ((e && e.message) || String(e)));
      return 1;
    }
    var diff = apiSnapshot.compare(loaded, current);
    _writeLine(ctx.stdout, apiSnapshot.formatDiff(diff));
    if (diff.breaking.length > 0) return 1;
    return 0;
  }

  _writeLine(ctx.stderr, "blamejs api-snapshot: unknown subcommand '" + sub + "'");
  _writeLine(ctx.stderr, API_SNAPSHOT_USAGE);
  return 2;
}

// ---- Subcommand: audit ----
//
// Operator tooling on top of the audit chain. Programmatic API is at
// b.auditTools — the CLI is a thin wrapper that's easier to script
// against from operator runbooks (cron, retention pipelines, etc.).

var AUDIT_USAGE = [
  "Usage: blamejs audit <subcommand> [flags]",
  "",
  "Subcommands:",
  "  archive        Bundle audit rows older than --before into a verified archive",
  "  export         Auditor evidence bundle for a date range",
  "  verify-bundle  Round-trip integrity check on an archive or export bundle",
  "  purge          Delete live rows already captured in a verified archive",
  "",
  "Common flags:",
  "  --out <path>           Output bundle directory (must NOT exist)",
  "  --in  <path>           Input bundle directory (verify-bundle, purge)",
  "  --passphrase <string>  Bundle passphrase (or env BLAMEJS_AUDIT_PASSPHRASE)",
  "",
  "archive flags:",
  "  --before <date>        Archive rows with recordedAt < this date (ISO-8601 or epoch ms)",
  "",
  "export flags:",
  "  --from <date>          Earliest recordedAt (inclusive)",
  "  --to <date>            Latest recordedAt (inclusive)",
  "  --action <name>        Restrict to a single audit action",
  "",
  "purge flags:",
  "  --confirm              REQUIRED — operator acknowledgement of destructive op",
  "",
  "Exit codes:",
  "  0  success",
  "  1  operation failed",
  "  2  bad invocation",
].join("\n");

function _resolvePassphrase(args, ctx) {
  if (typeof args.flags.passphrase === "string" && args.flags.passphrase.length > 0) {
    return args.flags.passphrase;
  }
  var env = ctx.env && ctx.env.BLAMEJS_AUDIT_PASSPHRASE;
  if (typeof env === "string" && env.length > 0) return env;
  return null;
}

function _resolveOutPath(p, ctx) {
  if (!p) return null;
  return path.isAbsolute(p) ? p : path.resolve(ctx.cwd, p);
}

async function _runAudit(args, ctx) {
  if (args.flags.help || args.flags.h) {
    _writeLine(ctx.stdout, AUDIT_USAGE);
    return 0;
  }
  if (args.pos.length === 0) {
    _writeLine(ctx.stderr, AUDIT_USAGE);
    return 2;
  }
  var sub = args.pos[0];
  var passphrase = _resolvePassphrase(args, ctx);
  var passRequired = sub === "archive" || sub === "export" ||
                     sub === "verify-bundle" || sub === "purge";
  if (passRequired && !passphrase) {
    _writeLine(ctx.stderr, "blamejs audit " + sub +
      ": --passphrase or BLAMEJS_AUDIT_PASSPHRASE is required");
    return 2;
  }

  if (sub === "archive") {
    var out    = _resolveOutPath(args.flags.out,    ctx);
    var before = args.flags.before;
    if (!out)    { _writeLine(ctx.stderr, "blamejs audit archive: --out is required"); return 2; }
    if (!before) { _writeLine(ctx.stderr, "blamejs audit archive: --before is required"); return 2; }
    try {
      var r = await auditTools.archive({
        before: before, out: out, passphrase: passphrase,
      });
      _writeLine(ctx.stdout, "wrote archive bundle to " + r.outDir +
        " (rowCount=" + r.rowCount +
        ", counters=" + r.range.firstCounter + ".." + r.range.lastCounter + ")");
      return 0;
    } catch (e) {
      _writeLine(ctx.stderr, "blamejs audit archive: " + ((e && e.message) || String(e)));
      return 1;
    }
  }

  if (sub === "export") {
    var outE  = _resolveOutPath(args.flags.out, ctx);
    var from  = args.flags.from;
    var to    = args.flags.to;
    var action = args.flags.action;
    if (!outE) { _writeLine(ctx.stderr, "blamejs audit export: --out is required"); return 2; }
    if (!from && !to && !action) {
      _writeLine(ctx.stderr, "blamejs audit export: at least one of --from / --to / --action is required");
      return 2;
    }
    try {
      var r2 = await auditTools.exportSlice({
        from: from, to: to, action: action,
        out: outE, passphrase: passphrase,
      });
      _writeLine(ctx.stdout, "wrote export bundle to " + r2.outDir +
        " (rowCount=" + r2.rowCount +
        ", counters=" + r2.range.firstCounter + ".." + r2.range.lastCounter + ")");
      return 0;
    } catch (e) {
      _writeLine(ctx.stderr, "blamejs audit export: " + ((e && e.message) || String(e)));
      return 1;
    }
  }

  if (sub === "verify-bundle") {
    var inV = _resolveOutPath(args.flags.in, ctx);
    if (!inV) { _writeLine(ctx.stderr, "blamejs audit verify-bundle: --in is required"); return 2; }
    try {
      var v = await auditTools.verifyBundle({ in: inV, passphrase: passphrase });
      if (v.ok) {
        _writeLine(ctx.stdout, "OK — bundle verified" +
          " (kind=" + v.kind +
          ", rowsVerified=" + v.rowsVerified +
          ", counters=" + v.range.firstCounter + ".." + v.range.lastCounter + ")");
        return 0;
      }
      _writeLine(ctx.stderr, "FAIL — " + v.reason);
      return 1;
    } catch (e) {
      _writeLine(ctx.stderr, "blamejs audit verify-bundle: " + ((e && e.message) || String(e)));
      return 1;
    }
  }

  if (sub === "purge") {
    var inP = _resolveOutPath(args.flags.archive || args.flags.in, ctx);
    if (!inP) {
      _writeLine(ctx.stderr, "blamejs audit purge: --archive (path to verified archive bundle) is required");
      return 2;
    }
    if (args.flags.confirm !== true && args.flags.confirm !== "true") {
      _writeLine(ctx.stderr, "blamejs audit purge: --confirm is REQUIRED — destructive operation");
      return 2;
    }
    try {
      var p = await auditTools.purge({
        archive: inP, passphrase: passphrase, confirm: true,
      });
      _writeLine(ctx.stdout, "OK — purged " + p.rowsDeleted + " rows" +
        " (counters ≤ " + p.lastPurgedCounter + ")");
      return 0;
    } catch (e) {
      _writeLine(ctx.stderr, "blamejs audit purge: " + ((e && e.message) || String(e)));
      return 1;
    }
  }

  _writeLine(ctx.stderr, "blamejs audit: unknown subcommand '" + sub + "'");
  _writeLine(ctx.stderr, AUDIT_USAGE);
  return 2;
}

// ---- Top-level help ----

// ---- Subcommand: api-key ----

var API_KEY_USAGE = [
  "Usage: blamejs api-key <subcommand> [flags]",
  "",
  "Subcommands:",
  "  issue             Issue a new API key under a namespace. Prints the",
  "                    composite key + id. The plaintext secret is shown",
  "                    ONCE and cannot be recovered after the command exits.",
  "  revoke            Revoke an issued key by its composite id (namespace:idHex).",
  "  list              List active keys for a given owner under a namespace.",
  "  rotate            Issue a new secret for an existing id while leaving the",
  "                    old secret valid for opts.gracePeriodMs (default 0 — immediate).",
  "  verify            Verify a token string and print the resolved metadata.",
  "                    Useful for debugging an integration that's seeing 401s.",
  "",
  "Flags (all subcommands):",
  "  --data-dir <path>      Path to the app's data dir (required)",
  "  --namespace <name>     API-key namespace (required) — typically matches the",
  "                         operator's b.apiKey.create({ namespace }) at boot",
  "  --vault-mode <mode>    plaintext | wrapped (default wrapped). When wrapped,",
  "                         BLAMEJS_VAULT_PASSPHRASE must be set.",
  "",
  "Subcommand flags:",
  "  issue:   --owner-id <id>   --scopes <comma-separated>   [--label <text>]   [--expires-ms <ms>]",
  "  revoke:  --id <idHex>",
  "  list:    --owner-id <id>",
  "  rotate:  --id <idHex>   [--grace-ms <ms>]",
  "  verify:  --token <key>",
].join("\n");

async function _runApiKey(args, ctx) {
  if (args.pos.length === 0) {
    return cliHelpers.makeReporter(ctx, "blamejs api-key").usage(API_KEY_USAGE);
  }
  var sub = args.pos[0];
  var report = cliHelpers.makeReporter(ctx, "blamejs api-key " + sub);
  if (sub === "help" || args.flags.help || args.flags.h) {
    return report.helpStdout(API_KEY_USAGE);
  }
  if (["issue", "revoke", "list", "rotate", "verify"].indexOf(sub) === -1) {
    cliHelpers.makeReporter(ctx, "blamejs api-key").error("unknown subcommand '" + sub + "'", 2);
    return cliHelpers.makeReporter(ctx, "blamejs api-key").usage(API_KEY_USAGE);
  }

  var dataDirFlag = args.flags["data-dir"];
  if (!dataDirFlag || dataDirFlag === true) {
    return report.error("--data-dir <path> is required", 2);
  }
  var dataDir = _resolvePath(String(dataDirFlag), ctx.cwd);

  var namespace = args.flags.namespace;
  if (!namespace || namespace === true) {
    return report.error("--namespace <name> is required", 2);
  }
  namespace = String(namespace);

  var vaultMode = args.flags["vault-mode"] || "wrapped";
  if (vaultMode !== "wrapped" && vaultMode !== "plaintext") {
    return report.error("--vault-mode must be 'wrapped' or 'plaintext'", 2);
  }

  var booted;
  try {
    booted = await cliHelpers.bootApp({
      dataDir:   dataDir,
      vaultMode: vaultMode,
      env:       ctx.env,
    });
  } catch (e) {
    return report.error("boot failed: " + ((e && e.message) || String(e)));
  }

  try {
    var registry = booted.b.apiKey.create({
      namespace: namespace,
      audit:     booted.b.audit,
    });

    if (sub === "issue") {
      var ownerId = args.flags["owner-id"];
      var scopes  = args.flags.scopes;
      if (!ownerId || ownerId === true) return report.error("--owner-id <id> is required", 2);
      if (!scopes  || scopes === true)  return report.error("--scopes <comma-separated> is required", 2);
      var scopeList = String(scopes).split(",").map(function (s) { return s.trim(); }).filter(Boolean);
      if (scopeList.length === 0) {
        return report.error("--scopes must contain at least one non-empty scope", 2);
      }
      var label = typeof args.flags.label === "string" ? args.flags.label : null;
      var expiresMs = args.flags["expires-ms"];
      var issued = await registry.issue({
        ownerId:   String(ownerId),
        scopes:    scopeList,
        metadata:  label ? { label: label } : null,
        expiresMs: expiresMs && expiresMs !== true ? Number(expiresMs) : undefined,
      });
      report.write("id:     " + issued.id);
      report.write("key:    " + issued.key);
      report.write("scopes: " + issued.scopes.join(", "));
      if (issued.expiresAt) report.write("expires: " + new Date(issued.expiresAt).toISOString());
      return report.ok("\nThe plaintext secret is shown ONCE — copy it now.");
    }

    if (sub === "revoke") {
      var revokeId = args.flags.id;
      if (!revokeId || revokeId === true) return report.error("--id <idHex> is required", 2);
      var revoked = await registry.revoke(String(revokeId));
      return revoked
        ? report.ok("revoked: " + revokeId)
        : report.error("no-op: " + revokeId + " not found or already revoked");
    }

    if (sub === "list") {
      var listOwnerId = args.flags["owner-id"];
      if (!listOwnerId || listOwnerId === true) return report.error("--owner-id <id> is required", 2);
      var rows = await registry.listForOwner(String(listOwnerId));
      report.write("owner: " + listOwnerId + " (" + rows.length + " active keys)");
      for (var i = 0; i < rows.length; i++) {
        var r = rows[i];
        var scope = Array.isArray(r.scopes) ? r.scopes.join(",") : "";
        report.write("  " + r.id + "  scopes=[" + scope + "]" +
          (r.expiresAt ? "  expires=" + new Date(r.expiresAt).toISOString() : ""));
      }
      return report.ok();
    }

    if (sub === "rotate") {
      var rotateId = args.flags.id;
      if (!rotateId || rotateId === true) return report.error("--id <idHex> is required", 2);
      var graceMs = args.flags["grace-ms"];
      var rotated = await registry.rotate(String(rotateId), {
        gracePeriodMs: graceMs && graceMs !== true ? Number(graceMs) : 0,
      });
      report.write("id:        " + rotated.id);
      report.write("key (new): " + rotated.key);
      return report.ok("\nUpdate your integration to the new key, then revoke the old secret " +
        "(or wait gracePeriodMs for it to expire).");
    }

    if (sub === "verify") {
      var token = args.flags.token;
      if (!token || token === true) return report.error("--token <key> is required", 2);
      var v = await registry.verify(String(token));
      if (!v) return report.error("rejected: token does not verify (bad format, unknown id, revoked, or expired)");
      report.write("id:       " + v.id);
      report.write("ownerId:  " + v.ownerId);
      report.write("scopes:   " + (v.scopes || []).join(", "));
      if (v.lastUsedAt) report.write("last-used: " + new Date(v.lastUsedAt).toISOString());
      if (v.expiresAt)  report.write("expires:   " + new Date(v.expiresAt).toISOString());
      return report.ok();
    }

    return 2;
  } catch (e) {
    return report.error((e && e.message) || String(e));
  } finally {
    try { await booted.app.shutdown(); } catch (_e) { /* best-effort */ }
  }
}

// ---- Subcommand: backup ----

var BACKUP_USAGE = [
  "Usage: blamejs backup <subcommand> [flags]",
  "",
  "Subcommands:",
  "  inspect           Read a bundle's manifest without decrypting and",
  "                    print a summary (file count, total bytes, kinds,",
  "                    timestamp). No passphrase required — useful for",
  "                    pre-flight before a restore.",
  "  verify            Decrypt + verify the bundle in a temp directory,",
  "                    discard the output. Confirms passphrase is correct",
  "                    and every encrypted blob's HMAC validates against",
  "                    the manifest, without committing a restore.",
  "  extract           Decrypt + verify into the target staging directory.",
  "                    The staging directory is the operator's responsibility",
  "                    to inspect and then move into place; this command",
  "                    never touches the live data dir.",
  "",
  "Flags:",
  "  --bundle <dir>         Path to a bundle directory (must contain manifest.json)",
  "  --to <stagingDir>      For extract — fresh directory to decrypt into (must not exist)",
  "  --passphrase <string>  Backup passphrase (or env BLAMEJS_BACKUP_PASSPHRASE)",
].join("\n");

async function _runBackup(args, ctx) {
  if (args.pos.length === 0) {
    return cliHelpers.makeReporter(ctx, "blamejs backup").usage(BACKUP_USAGE);
  }
  var sub = args.pos[0];
  var report = cliHelpers.makeReporter(ctx, "blamejs backup " + sub);
  if (sub === "help" || args.flags.help || args.flags.h) {
    return report.helpStdout(BACKUP_USAGE);
  }
  if (["inspect", "verify", "extract"].indexOf(sub) === -1) {
    cliHelpers.makeReporter(ctx, "blamejs backup").error("unknown subcommand '" + sub + "'", 2);
    return cliHelpers.makeReporter(ctx, "blamejs backup").usage(BACKUP_USAGE);
  }

  var bundleFlag = args.flags.bundle;
  if (!bundleFlag || bundleFlag === true) {
    return report.error("--bundle <dir> is required", 2);
  }
  var bundleDir = _resolvePath(String(bundleFlag), ctx.cwd);

  if (sub === "inspect") {
    try {
      var m = restoreBundle.inspect({ bundleDir: bundleDir });
      var totalBytes = 0;
      for (var i = 0; i < m.files.length; i++) totalBytes += m.files[i].encryptedSize || 0;
      report.write("bundle:        " + bundleDir);
      report.write("manifest:      v" + (m.manifestVersion || m.version || "unknown"));
      report.write("created:       " + (m.createdAt || "unknown"));
      report.write("files:         " + m.files.length);
      report.write("encrypted size: " + totalBytes + " bytes");
      var kinds = {};
      for (var k = 0; k < m.files.length; k++) {
        var kind = m.files[k].kind || "unknown";
        kinds[kind] = (kinds[kind] || 0) + 1;
      }
      var ks = Object.keys(kinds).sort();
      for (var ki = 0; ki < ks.length; ki++) {
        report.write("  " + ks[ki] + ": " + kinds[ks[ki]]);
      }
      return report.ok();
    } catch (e) {
      return report.error((e && e.message) || String(e));
    }
  }

  // verify + extract both decrypt — both need a passphrase.
  var pp = cliHelpers.resolvePassphrase(args, ctx, {
    flag: "passphrase", envVar: "BLAMEJS_BACKUP_PASSPHRASE",
  });
  if (!pp) {
    return report.error("--passphrase or BLAMEJS_BACKUP_PASSPHRASE is required", 2);
  }

  if (sub === "verify") {
    var fs2 = require("node:fs");
    var os2 = require("node:os");
    var nodePath = require("node:path");
    var nodeCrypto = require("node:crypto");
    var stagingDir = nodePath.join(os2.tmpdir(),
      "blamejs-backup-verify-" + nodeCrypto.randomBytes(8).toString("hex"));
    try {
      var r = await restoreBundle.extract({
        bundleDir:  bundleDir,
        stagingDir: stagingDir,
        passphrase: pp,
      });
      report.write("verified: " + (r && r.fileCount != null ? r.fileCount : "n/a") + " files");
      report.write("passphrase decrypts the vault-key wrap");
      report.write("every blob's HMAC validates against the manifest");
      return report.ok();
    } catch (e) {
      return report.error((e && e.message) || String(e));
    } finally {
      try { fs2.rmSync(stagingDir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
    }
  }

  if (sub === "extract") {
    var toFlag = args.flags.to;
    if (!toFlag || toFlag === true) {
      return report.error("--to <stagingDir> is required", 2);
    }
    var stagingDir2 = _resolvePath(String(toFlag), ctx.cwd);
    try {
      var rr = await restoreBundle.extract({
        bundleDir:  bundleDir,
        stagingDir: stagingDir2,
        passphrase: pp,
      });
      report.write("extracted: " + (rr && rr.fileCount != null ? rr.fileCount : "n/a") +
        " files → " + stagingDir2);
      report.write("");
      report.write("Inspect the staging directory before moving any files into your live data dir.");
      report.write("blamejs does NOT auto-promote — that's an operator decision.");
      return report.ok();
    } catch (e) {
      return report.error((e && e.message) || String(e));
    }
  }

  return 2;
}

// ---- Subcommand: mtls ----

var MTLS_USAGE = [
  "Usage: blamejs mtls <subcommand> [flags]",
  "",
  "Subcommands:",
  "  status            Print CA state — exists / generation / sealed-mode.",
  "                    No engine required.",
  "  show-cert         Print the CA certificate PEM to stdout. Operators",
  "                    paste this into client truststores. No engine required.",
  "  init              Generate a fresh CA keypair + self-signed cert and",
  "                    write to data-dir. Requires opts.engine — see note below.",
  "  issue             Issue a leaf client certificate signed by the CA.",
  "                    Requires opts.engine + --subject. Prints cert + key PEM.",
  "  issue-p12         Issue + package as PKCS#12 with --password. Useful for",
  "                    importing into browsers / OS keychains. Requires engine.",
  "",
  "Flags:",
  "  --data-dir <path>      Path to the app's data dir (required)",
  "  --vault-mode <mode>    plaintext | wrapped (default wrapped). When wrapped,",
  "                         BLAMEJS_VAULT_PASSPHRASE must be set.",
  "  --sealed-mode <mode>   auto | required | disabled (default auto). 'required'",
  "                         seals the CA key under the vault before writing it",
  "                         to disk; 'disabled' keeps it plaintext on disk;",
  "                         'auto' loads whichever form exists.",
  "",
  "Subcommand flags:",
  "  issue:     --subject <CN>    [--days <N>]",
  "  issue-p12: --subject <CN>    --password <pkcs12-passphrase>    [--days <N>]    [--out <path>]",
  "",
  "Note on 'init', 'issue', 'issue-p12':",
  "  These require an opt.engine implementation that the framework hasn't",
  "  bundled yet. The CA + leaf-cert primitives ship with their full API",
  "  surface; the bundled cert-issuance engine ships in a future slice once",
  "  @peculiar/x509 + pkijs are vendored. Operators with mTLS needs today",
  "  wire their own engine via b.mtlsCa.create({ engine: ... }).",
  "  'status' and 'show-cert' don't need an engine — they're operator-",
  "  facing diagnostics that work against an existing CA on disk.",
].join("\n");

async function _runMtls(args, ctx) {
  if (args.pos.length === 0) {
    return cliHelpers.makeReporter(ctx, "blamejs mtls").usage(MTLS_USAGE);
  }
  var sub = args.pos[0];
  var report = cliHelpers.makeReporter(ctx, "blamejs mtls " + sub);
  if (sub === "help" || args.flags.help || args.flags.h) {
    return report.helpStdout(MTLS_USAGE);
  }
  if (["status", "show-cert", "init", "issue", "issue-p12"].indexOf(sub) === -1) {
    cliHelpers.makeReporter(ctx, "blamejs mtls").error("unknown subcommand '" + sub + "'", 2);
    return cliHelpers.makeReporter(ctx, "blamejs mtls").usage(MTLS_USAGE);
  }

  var dataDirFlag = args.flags["data-dir"];
  if (!dataDirFlag || dataDirFlag === true) {
    return report.error("--data-dir <path> is required", 2);
  }
  var dataDir = _resolvePath(String(dataDirFlag), ctx.cwd);

  var vaultMode = args.flags["vault-mode"] || "wrapped";
  if (vaultMode !== "wrapped" && vaultMode !== "plaintext") {
    return report.error("--vault-mode must be 'wrapped' or 'plaintext'", 2);
  }
  var sealedMode = args.flags["sealed-mode"] || "auto";
  if (["auto", "required", "disabled"].indexOf(sealedMode) === -1) {
    return report.error("--sealed-mode must be 'auto', 'required', or 'disabled'", 2);
  }

  var booted;
  try {
    booted = await cliHelpers.bootApp({
      dataDir:   dataDir,
      vaultMode: vaultMode,
      env:       ctx.env,
    });
  } catch (e) {
    return report.error("boot failed: " + ((e && e.message) || String(e)));
  }

  try {
    var ca = booted.b.mtlsCa.create({
      dataDir:         dataDir,
      vault:           booted.b.vault,
      caKeySealedMode: sealedMode,
      // No engine passed — init/issue/issue-p12 will fail-loud with the
      // bundled-engine-not-yet-shipped diagnostic from the primitive.
    });

    if (sub === "status") {
      var s = ca.status();
      report.write("data-dir:    " + dataDir);
      report.write("CA exists:   " + (s.exists ? "yes" : "no"));
      if (s.exists) {
        report.write("generation:  " + s.generation +
          (s.isLegacy ? " (LEGACY — current is " + s.current + ", rotate via init)" : ""));
        report.write("ca-key-sealed-mode: " + ca.caKeySealedMode);
        report.write("paths:");
        report.write("  cert:       " + ca.paths.caCert);
        report.write("  key:        " + ca.paths.caKey);
        report.write("  key-sealed: " + ca.paths.caKeySealed);
      } else {
        report.write("(run 'blamejs mtls init' to generate a CA — requires an engine implementation)");
      }
      return report.ok();
    }

    if (sub === "show-cert") {
      if (!ca.exists()) {
        return report.error("no CA on disk at " + ca.paths.caCert + " — run 'blamejs mtls init' first");
      }
      try {
        var pem = ca.loadCert().toString("utf8");
        report.write(pem.trim());
        return report.ok();
      } catch (e) {
        return report.error("could not load CA cert: " + ((e && e.message) || String(e)));
      }
    }

    if (sub === "init") {
      try {
        await ca.initCA();
        report.write("ca-cert:     " + ca.paths.caCert);
        report.write("ca-key:      " + (ca.caKeySealedMode === "required" ? ca.paths.caKeySealed : ca.paths.caKey));
        return report.ok("CA generated. Distribute ca-cert to clients via 'blamejs mtls show-cert'.");
      } catch (e) {
        return report.error((e && e.message) || String(e));
      }
    }

    if (sub === "issue") {
      var subject = args.flags.subject;
      if (!subject || subject === true) return report.error("--subject <CN> is required", 2);
      var days = args.flags.days && args.flags.days !== true ? Number(args.flags.days) : undefined;
      try {
        var leaf = await ca.generateClientCert({ subject: String(subject), days: days });
        report.write("# certificate");
        report.write(leaf.cert.trim());
        report.write("");
        report.write("# private key");
        report.write(leaf.key.trim());
        // Framework-canonical fingerprint via b.crypto.sha3Hash. Computed
        // here over the leaf cert PEM bytes so the audit trail is
        // independent of whatever fingerprint format the operator-
        // supplied engine returns. Operators wanting the X.509-
        // conventional SHA-256 fingerprint (browsers, openssl) can run
        // `openssl x509 -fingerprint -sha256 -in cert.pem` separately.
        report.write("");
        report.write("# fingerprint (sha3-512): " + booted.b.crypto.sha3Hash(Buffer.from(leaf.cert, "utf8")));
        if (leaf.expiresAt) report.write("# expires: " + new Date(leaf.expiresAt).toISOString());
        return report.ok();
      } catch (e) {
        return report.error((e && e.message) || String(e));
      }
    }

    if (sub === "issue-p12") {
      var subjectP = args.flags.subject;
      var password = args.flags.password;
      if (!subjectP || subjectP === true) return report.error("--subject <CN> is required", 2);
      if (!password || password === true) return report.error("--password <pkcs12-passphrase> is required", 2);
      var daysP = args.flags.days && args.flags.days !== true ? Number(args.flags.days) : undefined;
      var outPath = args.flags.out && args.flags.out !== true
        ? _resolvePath(String(args.flags.out), ctx.cwd)
        : null;
      try {
        var p12 = await ca.generateClientP12({
          subject:  String(subjectP),
          password: String(password),
          days:     daysP,
        });
        if (outPath) {
          require("node:fs").writeFileSync(outPath, p12.p12, { mode: 0o600 });
          report.write("p12 written: " + outPath);
        } else {
          // No --out: stream the bytes to stdout for piping. Operators
          // can `blamejs mtls issue-p12 ... > client.p12`.
          if (ctx.stdout && typeof ctx.stdout.write === "function") {
            ctx.stdout.write(p12.p12);
          }
        }
        // Framework-canonical fingerprint via b.crypto.sha3Hash over
        // the embedded cert PEM, same posture as the issue path above.
        // Independent of the engine's fingerprint format.
        if (p12.certPem) {
          report.write("# fingerprint (sha3-512): " + booted.b.crypto.sha3Hash(Buffer.from(p12.certPem, "utf8")));
        }
        if (p12.expiresAt) report.write("# expires: " + new Date(p12.expiresAt).toISOString());
        return report.ok();
      } catch (e) {
        return report.error((e && e.message) || String(e));
      }
    }

    return 2;
  } finally {
    try { await booted.app.shutdown(); } catch (_e) { /* best-effort */ }
  }
}

// ---- Subcommand: vault ----

var VAULT_USAGE = [
  "Usage: blamejs vault <subcommand> [flags]",
  "",
  "Subcommands:",
  "  status            Report whether vault.key (plaintext) and/or",
  "                    vault.key.sealed (wrapped) exist under <data-dir>",
  "  seal              Wrap a plaintext vault.key into a passphrase-",
  "                    sealed vault.key.sealed (Argon2id KDF +",
  "                    XChaCha20-Poly1305). Crash-safe: writes to .tmp",
  "                    + fsync + atomic rename, leaves the original",
  "                    untouched on any failure.",
  "  unseal            Reverse — write a plaintext vault.key from a",
  "                    sealed file. For audits / migration to a new",
  "                    machine; remove the plaintext file as soon as",
  "                    you're done.",
  "  rotate            Re-wrap a sealed vault.key.sealed under a new",
  "                    passphrase. The old passphrase is required to",
  "                    unwrap; the new passphrase wraps. The keypair",
  "                    itself is unchanged (use `b.vault.rotateKey()`",
  "                    at runtime if you want to rotate the keypair).",
  "",
  "Flags:",
  "  --data-dir <path>      Path to the app's data dir (default ./data)",
  "  --passphrase <string>  Passphrase to wrap with (or env",
  "                         BLAMEJS_VAULT_PASSPHRASE). For `rotate`,",
  "                         this is the OLD passphrase; pair with",
  "                         --new-passphrase / BLAMEJS_VAULT_PASSPHRASE_NEW.",
  "  --new-passphrase <s>   Rotate-only — the NEW passphrase to re-wrap",
  "                         under. Or env BLAMEJS_VAULT_PASSPHRASE_NEW.",
  "  --keep-plaintext       For `seal` — retain the plaintext vault.key",
  "                         file (default: delete it after sealing).",
].join("\n");

async function _runVault(args, ctx) {
  if (args.pos.length === 0) {
    return cliHelpers.makeReporter(ctx, "blamejs vault").usage(VAULT_USAGE);
  }
  var sub = args.pos[0];
  var report = cliHelpers.makeReporter(ctx, "blamejs vault " + sub);
  if (sub === "help" || args.flags.help || args.flags.h) {
    return report.helpStdout(VAULT_USAGE);
  }
  if (["status", "seal", "unseal", "rotate"].indexOf(sub) === -1) {
    cliHelpers.makeReporter(ctx, "blamejs vault").error("unknown subcommand '" + sub + "'", 2);
    return cliHelpers.makeReporter(ctx, "blamejs vault").usage(VAULT_USAGE);
  }

  var dataDir = _resolvePath(String(args.flags["data-dir"] || "./data"), ctx.cwd);

  if (sub === "status") {
    var pre = vaultPassphraseOps.preflightSealable({ dataDir: dataDir });
    var unsealable = vaultPassphraseOps.preflightUnsealable
      ? vaultPassphraseOps.preflightUnsealable({ dataDir: dataDir })
      : null;
    report.write("data-dir: " + dataDir);
    report.write("vault.key (plaintext):    " +
      (pre.ok ? "present (sealable)" : "absent — " + (pre.reason || "n/a")));
    if (unsealable) {
      report.write("vault.key.sealed (wrapped): " +
        (unsealable.ok ? "present" : "absent — " + (unsealable.reason || "n/a")));
    }
    return report.ok();
  }

  if (sub === "seal") {
    var pp = cliHelpers.resolvePassphrase(args, ctx, {
      flag: "passphrase", envVar: "BLAMEJS_VAULT_PASSPHRASE",
    });
    if (!pp) {
      return report.error("--passphrase or BLAMEJS_VAULT_PASSPHRASE is required", 2);
    }
    try {
      var r = await vaultPassphraseOps.seal({
        dataDir:        dataDir,
        passphrase:     pp,
        keepPlaintext:  !!args.flags["keep-plaintext"],
      });
      report.write("sealed: " + r.sealedPath);
      report.write(r.plaintextDeleted
        ? "removed plaintext vault.key"
        : "kept plaintext vault.key (--keep-plaintext set)");
      report.write("");
      report.write("Set BLAMEJS_VAULT_PASSPHRASE in the runtime environment and");
      return report.ok("boot the app with vault: { mode: \"wrapped\" }.");
    } catch (e) {
      return report.error((e && e.message) || String(e));
    }
  }

  if (sub === "unseal") {
    var pp2 = cliHelpers.resolvePassphrase(args, ctx, {
      flag: "passphrase", envVar: "BLAMEJS_VAULT_PASSPHRASE",
    });
    if (!pp2) {
      return report.error("--passphrase or BLAMEJS_VAULT_PASSPHRASE is required", 2);
    }
    try {
      var u = await vaultPassphraseOps.unseal({ dataDir: dataDir, passphrase: pp2 });
      report.write("unsealed: " + u.plaintextPath);
      report.write("");
      report.write("WARNING: vault.key is now plaintext on disk. Re-seal as soon");
      return report.ok("as you're done auditing or migrating.");
    } catch (e) {
      return report.error((e && e.message) || String(e));
    }
  }

  if (sub === "rotate") {
    var oldPp = cliHelpers.resolvePassphrase(args, ctx, {
      flag: "passphrase", envVar: "BLAMEJS_VAULT_PASSPHRASE",
    });
    var newPp = cliHelpers.resolvePassphrase(args, ctx, {
      flag: "new-passphrase", envVar: "BLAMEJS_VAULT_PASSPHRASE_NEW",
    });
    if (!oldPp || !newPp) {
      report.error("both --passphrase (old) and --new-passphrase are required", 2);
      report.writeErr("(or BLAMEJS_VAULT_PASSPHRASE + BLAMEJS_VAULT_PASSPHRASE_NEW)");
      return 2;
    }
    try {
      var rr = await vaultPassphraseOps.rotate({
        dataDir:        dataDir,
        oldPassphrase:  oldPp,
        newPassphrase:  newPp,
      });
      report.write("rotated: " + rr.sealedPath);
      return report.ok("Update BLAMEJS_VAULT_PASSPHRASE in the runtime environment to the new value.");
    } catch (e) {
      return report.error((e && e.message) || String(e));
    }
  }

  return 2;
}

var TOP_USAGE = [
  "Usage: blamejs <command> [args]",
  "",
  "Commands:",
  "  migrate           Manage database migrations (up / down / status)",
  "  seed              Apply seed-data fixtures by env (run / status)",
  "  dev               Run an app with file-watch + auto-restart",
  "  api-snapshot      Capture / compare the public API surface (CI gate)",
  "  api-key           Issue / revoke / list / rotate / verify API keys for a namespace",
  "  audit             Operator tooling on top of the audit chain (archive / export / verify / purge)",
  "  backup            Inspect / verify / extract a backup bundle from disk",
  "  mtls              Inspect or generate the in-box mTLS CA + leaf certs (status / show-cert / init / issue / issue-p12)",
  "  vault             Seal / unseal / rotate the on-disk vault keypair (plaintext ↔ wrapped)",
  "  version           Print framework version",
  "  help [<command>]  Show this message or details for a command",
].join("\n");

function _printTopHelp(ctx) { _writeLine(ctx.stdout, TOP_USAGE); }

// ---- Dispatch ----

async function main(argv, opts) {
  opts = opts || {};
  var ctx = {
    stdout: opts.stdout || process.stdout,
    stderr: opts.stderr || process.stderr,
    env:    opts.env    || process.env,
    cwd:    opts.cwd    || process.cwd(),
  };
  if (!Array.isArray(argv)) argv = [];
  var args = _parseArgs(argv);

  // Top-level flags handled before subcommand dispatch
  if (args.flags.version || args.flags.v) {
    _writeLine(ctx.stdout, constants.version);
    return 0;
  }
  if (args.flags.help || args.flags.h) {
    _printTopHelp(ctx);
    return 0;
  }

  var cmd = args.pos[0];

  if (cmd === undefined) { _printTopHelp(ctx); return 0; }
  if (cmd === "help") {
    var subTopic = args.pos[1];
    if (subTopic === "migrate")      { _writeLine(ctx.stdout, MIGRATE_USAGE);      return 0; }
    if (subTopic === "seed")         { _writeLine(ctx.stdout, SEED_USAGE);         return 0; }
    if (subTopic === "dev")          { _writeLine(ctx.stdout, DEV_USAGE);          return 0; }
    if (subTopic === "api-snapshot") { _writeLine(ctx.stdout, API_SNAPSHOT_USAGE); return 0; }
    if (subTopic === "api-key")      { _writeLine(ctx.stdout, API_KEY_USAGE);      return 0; }
    if (subTopic === "audit")        { _writeLine(ctx.stdout, AUDIT_USAGE);        return 0; }
    if (subTopic === "backup")       { _writeLine(ctx.stdout, BACKUP_USAGE);       return 0; }
    if (subTopic === "mtls")         { _writeLine(ctx.stdout, MTLS_USAGE);         return 0; }
    if (subTopic === "vault")        { _writeLine(ctx.stdout, VAULT_USAGE);        return 0; }
    _printTopHelp(ctx);
    return 0;
  }
  if (cmd === "version") { _writeLine(ctx.stdout, constants.version); return 0; }

  var rest = { pos: args.pos.slice(1), flags: args.flags };
  if (cmd === "migrate")      return await _runMigrate(rest, ctx);
  if (cmd === "seed")         return await _runSeed(rest, ctx);
  if (cmd === "dev")          return await _runDev(rest, ctx);
  if (cmd === "api-snapshot") return _runApiSnapshot(rest, ctx);
  if (cmd === "api-key")      return await _runApiKey(rest, ctx);
  if (cmd === "audit")        return await _runAudit(rest, ctx);
  if (cmd === "backup")       return await _runBackup(rest, ctx);
  if (cmd === "mtls")         return await _runMtls(rest, ctx);
  if (cmd === "vault")        return await _runVault(rest, ctx);

  _writeLine(ctx.stderr, "blamejs: unknown command '" + cmd + "'");
  _printTopHelp(ctx);
  return 2;
}

module.exports = {
  main:        main,
  // Internal helpers exposed so tests can drive the parser without
  // running the full dispatch.
  _parseArgs:  _parseArgs,
  TOP_USAGE:           TOP_USAGE,
  MIGRATE_USAGE:       MIGRATE_USAGE,
  DEV_USAGE:           DEV_USAGE,
  API_SNAPSHOT_USAGE:  API_SNAPSHOT_USAGE,
  API_KEY_USAGE:       API_KEY_USAGE,
  AUDIT_USAGE:         AUDIT_USAGE,
  BACKUP_USAGE:        BACKUP_USAGE,
  MTLS_USAGE:          MTLS_USAGE,
  VAULT_USAGE:         VAULT_USAGE,
};
