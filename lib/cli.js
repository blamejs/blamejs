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
var migrations = require("./migrations");
var dev = require("./dev");
var constants = require("./constants");

var DEFAULT_MIG_DIR = "./migrations";

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

// ---- Top-level help ----

var TOP_USAGE = [
  "Usage: blamejs <command> [args]",
  "",
  "Commands:",
  "  migrate           Manage database migrations (up / down / status)",
  "  dev               Run an app with file-watch + auto-restart",
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
    if (subTopic === "migrate") { _writeLine(ctx.stdout, MIGRATE_USAGE); return 0; }
    if (subTopic === "dev")     { _writeLine(ctx.stdout, DEV_USAGE);     return 0; }
    _printTopHelp(ctx);
    return 0;
  }
  if (cmd === "version") { _writeLine(ctx.stdout, constants.version); return 0; }

  var rest = { pos: args.pos.slice(1), flags: args.flags };
  if (cmd === "migrate") return await _runMigrate(rest, ctx);
  if (cmd === "dev")     return await _runDev(rest, ctx);

  _writeLine(ctx.stderr, "blamejs: unknown command '" + cmd + "'");
  _printTopHelp(ctx);
  return 2;
}

module.exports = {
  main:        main,
  // Internal helpers exposed so tests can drive the parser without
  // running the full dispatch.
  _parseArgs:  _parseArgs,
  TOP_USAGE:   TOP_USAGE,
  MIGRATE_USAGE: MIGRATE_USAGE,
  DEV_USAGE:   DEV_USAGE,
};
