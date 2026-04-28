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
var constants = require("./constants");
var dev = require("./dev");
var migrations = require("./migrations");
var seeders = require("./seeders");

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

var TOP_USAGE = [
  "Usage: blamejs <command> [args]",
  "",
  "Commands:",
  "  migrate           Manage database migrations (up / down / status)",
  "  seed              Apply seed-data fixtures by env (run / status)",
  "  dev               Run an app with file-watch + auto-restart",
  "  api-snapshot      Capture / compare the public API surface (CI gate)",
  "  audit             Operator tooling on top of the audit chain (archive / export / verify / purge)",
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
    if (subTopic === "audit")        { _writeLine(ctx.stdout, AUDIT_USAGE);        return 0; }
    _printTopHelp(ctx);
    return 0;
  }
  if (cmd === "version") { _writeLine(ctx.stdout, constants.version); return 0; }

  var rest = { pos: args.pos.slice(1), flags: args.flags };
  if (cmd === "migrate")      return await _runMigrate(rest, ctx);
  if (cmd === "seed")         return await _runSeed(rest, ctx);
  if (cmd === "dev")          return await _runDev(rest, ctx);
  if (cmd === "api-snapshot") return _runApiSnapshot(rest, ctx);
  if (cmd === "audit")        return await _runAudit(rest, ctx);

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
  AUDIT_USAGE:         AUDIT_USAGE,
};
