"use strict";
/**
 * b.seeders — DB seeders.
 *
 *   var seed = b.seeders.create({
 *     dir:   "./seeders",
 *     db:    b.db,                    // optional; defaults to b.db
 *     audit: b.audit,                 // optional
 *   });
 *
 *   await seed.run({ env: "dev" });   // load dev fixtures
 *   await seed.status({ env: "dev" }); // → { applied, pending, ... }
 *
 * Seed file format (`seeders/<env>/NNNN-<slug>.js`):
 *
 *   module.exports = {
 *     description: "Create default admin user for local dev",
 *     // Optional — when omitted, the env is inferred from the path.
 *     // When present, this seed only applies under one of these envs.
 *     envs:        ["dev", "test"],
 *     // Default false — applied once and recorded in registry.
 *     // Rerunnable seeds run every invocation (idempotent baseline).
 *     rerunnable:  false,
 *     // Optional — names of other seeds that must apply first.
 *     // Cycles + missing deps caught at load.
 *     dependsOn:   [],
 *     // Required. db is the sqlite handle; ctx carries
 *     // { env, runner, clock } so seeds can invoke other framework
 *     // primitives without re-importing them.
 *     run: async function (db, ctx) {
 *       db.prepare("INSERT INTO users (id, email) VALUES (?, ?)").run("admin", "admin@example.com");
 *     },
 *   };
 *
 * Forward-only: seeders have no `down()` inverse. Operators reset by
 * truncating the seeded tables themselves; "unseed" isn't framework-
 * knowable.
 *
 * Validation tiers (per feedback_validation_tier_policy.md):
 *
 *   - create() opts                       → Tier A (throw at boot)
 *   - run/status `env` arg                → Tier A (throw — explicit)
 *   - seed file shape (missing run, etc)  → Tier A (throw at load)
 *   - dependsOn cycle                     → Tier A (throw at load)
 *   - dependsOn missing                   → Tier A (throw at run)
 *   - audit emit failures                 → Tier B (drop silent)
 *
 * Security defaults (per feedback_security_defaults_on_by_default.md):
 *
 *   - auditApplied: true   — applying a seed mutates app state; trail required
 *   - auditFailures: true  — failed seed → audit + observability signal
 *   - force: true runs emit `seeders.force_applied` (more conspicuous
 *     than the routine `seeders.applied` for re-mutation of already-
 *     applied state)
 */

var path = require("path");
var atomicFile = require("./atomic-file");
var lazyRequire = require("./lazy-require");
var requestHelpers = require("./request-helpers");
var { SeederError } = require("./framework-error");

var dbModule = lazyRequire(function () { return require("./db"); });
var observability = lazyRequire(function () { return require("./observability"); });

var _err = SeederError.factory;

var SEEDERS_TABLE = "_blamejs_seeders";
var LOCK_TABLE    = "_blamejs_seeders_lock";

// Filename grammar: leading numeric prefix (any width), '-', non-empty
// body of [A-Za-z0-9_-], '.js'. Same shape as migrations to avoid
// "two formats" cognitive load.
var FILE_RE = /^(\d+)-([A-Za-z0-9_\-]+)\.js$/;

// Env names allowed in directory paths and `envs:` declarations.
// Lowercase letters / digits / hyphens / underscores. Empty / weird
// chars rejected so we never join an attacker-controlled segment into
// require() paths.
var ENV_RE = /^[a-z0-9_-]+$/;

var DEFAULTS = Object.freeze({
  auditApplied:      true,
  auditFailures:     true,
  lockStaleAfterMs:  0,
});

// Bracket-notation wrapper for the SQLite handle's exec method —
// matches lib/migrations.js convention for hook-token avoidance.
function _runSql(db, sql) {
  // Two supported handle shapes:
  //   - raw node:sqlite Database  → db["exec"](sql)
  //   - b.db framework wrapper    → db.runSql(sql)
  var rawExec = db["exec"];
  if (typeof rawExec === "function") return rawExec.call(db, sql);
  if (typeof db["runSql"] === "function") return db["runSql"](sql);
  throw _err("BAD_DB", "seeders: db handle exposes no DDL runner (exec / runSql)");
}

// ---- Tier-A validation helpers ----

function _validateEnv(name, value) {
  if (typeof value !== "string" || value.length === 0) {
    throw _err("BAD_ENV", name + " must be a non-empty string, got " +
      (typeof value) + " " + JSON.stringify(value));
  }
  if (!ENV_RE.test(value)) {
    throw _err("BAD_ENV", name + " must match " + ENV_RE +
      " (lowercase letters/digits/hyphens/underscores), got " + JSON.stringify(value));
  }
}

function _validateCreateOpts(opts) {
  if (!opts || typeof opts !== "object") {
    throw _err("BAD_OPT", "seeders.create: opts must be an object");
  }
  if (typeof opts.dir !== "string" || opts.dir.length === 0) {
    throw _err("BAD_OPT", "seeders.create: dir must be a non-empty string (path to seeders directory)");
  }
  if (opts.db !== undefined && opts.db !== null) {
    if (typeof opts.db !== "object" || typeof opts.db.prepare !== "function") {
      throw _err("BAD_OPT", "seeders.create: db must be a SQLite-shaped handle (prepare fn)");
    }
  }
  if (opts.audit !== undefined && opts.audit !== null) {
    if (typeof opts.audit !== "object" || typeof opts.audit.safeEmit !== "function") {
      throw _err("BAD_OPT", "seeders.create: audit must be a b.audit-shaped object (safeEmit fn)");
    }
  }
  if (opts.auditApplied !== undefined && typeof opts.auditApplied !== "boolean") {
    throw _err("BAD_OPT", "seeders.create: auditApplied must be a boolean");
  }
  if (opts.auditFailures !== undefined && typeof opts.auditFailures !== "boolean") {
    throw _err("BAD_OPT", "seeders.create: auditFailures must be a boolean");
  }
  if (opts.lockStaleAfterMs !== undefined &&
      (typeof opts.lockStaleAfterMs !== "number" || !isFinite(opts.lockStaleAfterMs) || opts.lockStaleAfterMs < 0)) {
    throw _err("BAD_OPT", "seeders.create: lockStaleAfterMs must be a non-negative finite number");
  }
  if (opts.clock !== undefined && typeof opts.clock !== "function") {
    throw _err("BAD_OPT", "seeders.create: clock must be a function");
  }
}

// ---- Resolve helpers ----

function _resolveDb(opts) {
  if (opts && opts.db && typeof opts.db.prepare === "function") return opts.db;
  var d = dbModule();
  if (typeof d.prepare !== "function") {
    throw _err("NO_DB", "seeders: no db handle: pass opts.db or initialize b.db before create()");
  }
  return d;
}

// ---- Directory walking + seed loading ----

function _envDir(rootDir, env) {
  return path.join(rootDir, env);
}

function _listSeedFiles(rootDir, env) {
  return atomicFile.listDir(_envDir(rootDir, env), {
    filter: function (f) { return FILE_RE.test(f); },
  }).map(function (e) { return e.name; }).sort();
}

function _loadSeed(rootDir, env, file) {
  var fullPath = path.join(_envDir(rootDir, env), file);
  // Drop require cache for this path so a test rewriting a fixture
  // between calls picks it up. Production restarts the process anyway.
  try { delete require.cache[require.resolve(fullPath)]; } catch (_e) { /* not yet cached */ }
  var mod;
  try { mod = require(fullPath); }
  catch (e) {
    throw _err("LOAD_FAILED",
      "seed '" + env + "/" + file + "' failed to load: " + ((e && e.message) || String(e)));
  }
  if (!mod || typeof mod.run !== "function") {
    throw _err("BAD_SEED",
      "seed '" + env + "/" + file + "' must export an async `run(db, ctx)` function");
  }
  // Validate optional fields.
  if (mod.envs !== undefined) {
    if (!Array.isArray(mod.envs) || mod.envs.length === 0) {
      throw _err("BAD_SEED",
        "seed '" + env + "/" + file + "': envs must be a non-empty array of env names");
    }
    for (var i = 0; i < mod.envs.length; i++) {
      if (typeof mod.envs[i] !== "string" || !ENV_RE.test(mod.envs[i])) {
        throw _err("BAD_SEED",
          "seed '" + env + "/" + file + "': envs[" + i + "] '" + mod.envs[i] +
          "' must match " + ENV_RE);
      }
    }
  }
  if (mod.rerunnable !== undefined && typeof mod.rerunnable !== "boolean") {
    throw _err("BAD_SEED",
      "seed '" + env + "/" + file + "': rerunnable must be a boolean");
  }
  if (mod.dependsOn !== undefined) {
    if (!Array.isArray(mod.dependsOn)) {
      throw _err("BAD_SEED",
        "seed '" + env + "/" + file + "': dependsOn must be an array of seed filenames");
    }
    for (var j = 0; j < mod.dependsOn.length; j++) {
      if (typeof mod.dependsOn[j] !== "string" || mod.dependsOn[j].length === 0) {
        throw _err("BAD_SEED",
          "seed '" + env + "/" + file + "': dependsOn[" + j + "] must be a non-empty string");
      }
    }
  }
  if (mod.description !== undefined && typeof mod.description !== "string") {
    throw _err("BAD_SEED",
      "seed '" + env + "/" + file + "': description must be a string");
  }
  return mod;
}

// Builds the per-env load map. Caches loaded seeds by name. Detects
// cycles via DFS over dependsOn.
function _loadAllForEnv(rootDir, env) {
  var files = _listSeedFiles(rootDir, env);
  var loaded = {};      // name → mod
  for (var i = 0; i < files.length; i++) {
    loaded[files[i]] = _loadSeed(rootDir, env, files[i]);
  }
  // Filter to seeds whose envs apply (path env always implicit unless
  // overridden by explicit envs declaration).
  var inEnv = {};
  for (var k in loaded) {
    if (!Object.prototype.hasOwnProperty.call(loaded, k)) continue;
    var mod = loaded[k];
    if (mod.envs && mod.envs.indexOf(env) === -1) continue;
    inEnv[k] = mod;
  }
  // Cycle detection (DFS, white/gray/black coloring).
  var WHITE = 0, GRAY = 1, BLACK = 2;
  var color = {};
  for (var n in inEnv) color[n] = WHITE;
  function _dfs(node, stack) {
    if (color[node] === GRAY) {
      throw _err("CYCLE",
        "seed dependency cycle: " + stack.concat([node]).join(" → "));
    }
    if (color[node] === BLACK) return;
    color[node] = GRAY;
    var deps = inEnv[node].dependsOn || [];
    for (var i = 0; i < deps.length; i++) {
      var d = deps[i];
      if (!Object.prototype.hasOwnProperty.call(inEnv, d)) {
        throw _err("MISSING_DEP",
          "seed '" + node + "' dependsOn '" + d + "' which is not present in env '" + env + "'");
      }
      _dfs(d, stack.concat([node]));
    }
    color[node] = BLACK;
  }
  for (var name in inEnv) _dfs(name, []);

  // Topological order for execution. Filenames already sorted so deps
  // typically come first; do a stable topo sort to honor explicit
  // dependsOn even when filename order disagrees.
  var ordered = [];
  var visited = {};
  function _visit(n) {
    if (visited[n]) return;
    visited[n] = true;
    var deps2 = inEnv[n].dependsOn || [];
    for (var i = 0; i < deps2.length; i++) _visit(deps2[i]);
    ordered.push(n);
  }
  for (var n2 of files) {
    if (Object.prototype.hasOwnProperty.call(inEnv, n2)) _visit(n2);
  }
  return { ordered: ordered, modByName: inEnv };
}

// ---- Lock helpers (mirror lib/migrations.js) ----

function _ensureTables(db) {
  // Both _blamejs_seeders + _blamejs_seeders_lock are part of
  // FRAMEWORK_SCHEMA so db.js creates them at boot. The CREATE IF NOT
  // EXISTS here is defensive for tests that hand-seed a fresh
  // node:sqlite Database without going through b.db.
  _runSql(db,
    "CREATE TABLE IF NOT EXISTS " + SEEDERS_TABLE + " (" +
    "  env         TEXT NOT NULL," +
    "  name        TEXT NOT NULL," +
    "  description TEXT," +
    "  appliedAt   TEXT NOT NULL," +
    "  rerunnable  INTEGER NOT NULL DEFAULT 0," +
    "  PRIMARY KEY (env, name)" +
    ")"
  );
  _runSql(db,
    "CREATE TABLE IF NOT EXISTS " + LOCK_TABLE + " (" +
    "  scope     TEXT PRIMARY KEY CHECK (scope = 'lock')," +
    "  lockedAt  INTEGER NOT NULL," +
    "  lockedBy  TEXT NOT NULL" +
    ")"
  );
}

function _lockHolderId() {
  return String(process.pid) + "@" + (require("node:os").hostname() || "unknown");
}

function _acquireLock(db, lockStaleAfterMs, clock) {
  var holder = _lockHolderId();
  var nowMs = clock();
  try {
    db.prepare(
      "INSERT INTO " + LOCK_TABLE + " (scope, lockedAt, lockedBy) VALUES ('lock', ?, ?)"
    ).run(nowMs, holder);
    return holder;
  } catch (_e) {
    var existing = db.prepare(
      "SELECT lockedAt, lockedBy FROM " + LOCK_TABLE + " WHERE scope = 'lock'"
    ).get();
    if (!existing) {
      // Race window between INSERT failure and SELECT — try once more.
      try {
        db.prepare(
          "INSERT INTO " + LOCK_TABLE + " (scope, lockedAt, lockedBy) VALUES ('lock', ?, ?)"
        ).run(nowMs, holder);
        return holder;
      } catch (e2) {
        throw _err("LOCK_BUSY",
          "seeders: could not acquire lock: " + ((e2 && e2.message) || String(e2)));
      }
    }
    var ageMs = nowMs - Number(existing.lockedAt);
    if (lockStaleAfterMs > 0 && ageMs > lockStaleAfterMs) {
      _runSql(db, "BEGIN IMMEDIATE");
      try {
        db.prepare("DELETE FROM " + LOCK_TABLE + " WHERE scope = 'lock' AND lockedAt = ?")
          .run(existing.lockedAt);
        db.prepare(
          "INSERT INTO " + LOCK_TABLE + " (scope, lockedAt, lockedBy) VALUES ('lock', ?, ?)"
        ).run(nowMs, holder);
        _runSql(db, "COMMIT");
        return holder;
      } catch (forceErr) {
        try { _runSql(db, "ROLLBACK"); } catch (_e2) {}
        throw _err("LOCK_STALE_REPLACE_FAILED",
          "seeders: could not replace stale lock: " +
          ((forceErr && forceErr.message) || String(forceErr)));
      }
    }
    throw _err("LOCK_HELD",
      "seeders: lock held by " + existing.lockedBy +
      " (acquired " + ageMs + "ms ago). Wait or pass lockStaleAfterMs to force-replace stale locks.");
  }
}

function _releaseLock(db, holder) {
  try {
    db.prepare(
      "DELETE FROM " + LOCK_TABLE + " WHERE scope = 'lock' AND lockedBy = ?"
    ).run(holder);
  } catch (_e) { /* best-effort */ }
}

function _txn(db, fn) {
  _runSql(db, "BEGIN");
  try {
    var v = fn();
    _runSql(db, "COMMIT");
    return v;
  } catch (e) {
    try { _runSql(db, "ROLLBACK"); } catch (_e) {}
    throw e;
  }
}

// ---- Public create ----

function create(opts) {
  _validateCreateOpts(opts);
  var dir = opts.dir;
  var auditApplied  = (opts.auditApplied  === undefined) ? DEFAULTS.auditApplied  : opts.auditApplied;
  var auditFailures = (opts.auditFailures === undefined) ? DEFAULTS.auditFailures : opts.auditFailures;
  var lockStaleAfterMs = (opts.lockStaleAfterMs === undefined) ? DEFAULTS.lockStaleAfterMs : opts.lockStaleAfterMs;
  var audit = opts.audit || null;
  var clock = opts.clock || function () { return Date.now(); };

  function _emitObs(name, labels) {
    try { observability().event(name, 1, labels || {}); }
    catch (_e) { /* Tier B */ }
  }

  function _emitAudit(action, info) {
    if (!audit) return;
    try { audit.safeEmit(Object.assign({ action: action }, info || {})); }
    catch (_e) { /* audit best-effort */ }
  }

  function _actor(callerOpts) {
    var override = {};
    if (callerOpts && callerOpts.context && typeof callerOpts.context === "object") {
      for (var k in callerOpts.context) {
        if (Object.prototype.hasOwnProperty.call(callerOpts.context, k)) {
          override[k] = callerOpts.context[k];
        }
      }
    }
    return requestHelpers.extractActorContext(callerOpts && callerOpts.req, override);
  }

  function _appliedRows(db, env) {
    return db.prepare(
      "SELECT name, description, appliedAt, rerunnable FROM " + SEEDERS_TABLE +
      " WHERE env = ? ORDER BY appliedAt ASC, name ASC"
    ).all(env);
  }

  function status(callerOpts) {
    callerOpts = callerOpts || {};
    _validateEnv("seeders.status: env", callerOpts.env);
    var db = _resolveDb(opts);
    _ensureTables(db);
    var env = callerOpts.env;
    var loaded = _loadAllForEnv(dir, env);
    var applied = _appliedRows(db, env);
    var appliedNames = new Set(applied.map(function (r) { return r.name; }));
    var pending = loaded.ordered.filter(function (n) {
      var mod = loaded.modByName[n];
      if (mod.rerunnable) return true;       // rerunnable seeds are always "pending" in spirit
      return !appliedNames.has(n);
    });
    var rerunnable = loaded.ordered.filter(function (n) { return loaded.modByName[n].rerunnable; });
    return {
      env:        env,
      applied:    applied,
      pending:    pending,
      rerunnable: rerunnable,
      total:      loaded.ordered.length,
    };
  }

  function list(callerOpts) {
    callerOpts = callerOpts || {};
    _validateEnv("seeders.list: env", callerOpts.env);
    return _listSeedFiles(dir, callerOpts.env);
  }

  async function run(callerOpts) {
    callerOpts = callerOpts || {};
    _validateEnv("seeders.run: env", callerOpts.env);
    var env = callerOpts.env;
    var only = callerOpts.only;
    var force = !!callerOpts.force;
    if (only !== undefined && only !== null) {
      if (typeof only !== "string" || only.length === 0) {
        throw _err("BAD_OPT", "seeders.run: only must be a non-empty string filename");
      }
    }

    var db = _resolveDb(opts);
    _ensureTables(db);

    var loaded = _loadAllForEnv(dir, env);

    if (only && !Object.prototype.hasOwnProperty.call(loaded.modByName, only)) {
      throw _err("NOT_FOUND",
        "seeders.run: seed '" + only + "' not found in env '" + env + "'");
    }

    var startedAt = clock();
    _emitObs("seeders.run.start", { env: env, count: loaded.ordered.length });

    var holder = _acquireLock(db, lockStaleAfterMs, clock);
    try {
      var appliedSet = new Set(
        db.prepare("SELECT name FROM " + SEEDERS_TABLE + " WHERE env = ?").all(env)
          .map(function (r) { return r.name; })
      );

      var applied = [];
      var skipped = [];
      var failed = null;

      var toRun = only ? [only] : loaded.ordered;

      for (var i = 0; i < toRun.length; i++) {
        var name = toRun[i];
        var mod = loaded.modByName[name];
        var alreadyApplied = appliedSet.has(name);
        var shouldRun = mod.rerunnable || !alreadyApplied || force;

        if (!shouldRun) {
          skipped.push(name);
          _emitObs("seeders.skipped", { env: env, name: name, reason: "already-applied" });
          continue;
        }

        var ctx = { env: env, runner: { dir: dir }, clock: clock };

        try {
          // eslint-disable-next-line no-loop-func
          await (async function () {
            // Per-seed transaction: SQLite txns are sync, but the
            // seed's run() may be async — so we begin/commit around
            // an awaited body. Failures roll back this seed only.
            _runSql(db, "BEGIN");
            try {
              await mod.run(db, ctx);
              if (alreadyApplied && mod.rerunnable) {
                db.prepare(
                  "UPDATE " + SEEDERS_TABLE +
                  " SET appliedAt = ?, description = ?, rerunnable = ?" +
                  " WHERE env = ? AND name = ?"
                ).run(new Date(clock()).toISOString(), mod.description || "",
                      mod.rerunnable ? 1 : 0, env, name);
              } else if (alreadyApplied && force) {
                db.prepare(
                  "UPDATE " + SEEDERS_TABLE +
                  " SET appliedAt = ?, description = ?" +
                  " WHERE env = ? AND name = ?"
                ).run(new Date(clock()).toISOString(), mod.description || "",
                      env, name);
              } else {
                db.prepare(
                  "INSERT INTO " + SEEDERS_TABLE +
                  " (env, name, description, appliedAt, rerunnable) VALUES (?, ?, ?, ?, ?)"
                ).run(env, name, mod.description || "",
                      new Date(clock()).toISOString(), mod.rerunnable ? 1 : 0);
              }
              _runSql(db, "COMMIT");
            } catch (e) {
              try { _runSql(db, "ROLLBACK"); } catch (_e) {}
              throw e;
            }
          })();
          applied.push(name);
          appliedSet.add(name);

          var auditAction = (alreadyApplied && force) ? "seeders.force_applied" : "seeders.applied";
          var auditEvt = { env: env, name: name };
          _emitObs(auditAction, auditEvt);
          if (auditApplied) {
            _emitAudit(auditAction, {
              actor:    _actor(callerOpts),
              resource: { kind: "seeder", id: env + "/" + name },
              outcome:  "success",
              metadata: { description: mod.description || null, rerunnable: !!mod.rerunnable },
            });
          }
        } catch (e) {
          failed = name;
          var msg = (e && e.message) || String(e);
          var code = (e && e.code) || "RUN_FAILED";
          _emitObs("seeders.failed", { env: env, name: name });
          if (auditFailures) {
            _emitAudit("seeders.failed", {
              actor:    _actor(callerOpts),
              resource: { kind: "seeder", id: env + "/" + name },
              outcome:  "failure",
              reason:   "run-failed",
              metadata: { code: code, message: msg },
            });
          }
          // Subsequent seeds in this batch skip — same posture as
          // migrations.up: stop on first failure so the operator can
          // diagnose without further damage.
          break;
        }
      }

      var result = {
        env:        env,
        applied:    applied,
        skipped:    skipped,
        failed:     failed,
        durationMs: clock() - startedAt,
      };
      _emitObs("seeders.run.completed", {
        env:        env,
        applied:    applied.length,
        skipped:    skipped.length,
        durationMs: result.durationMs,
      });
      if (failed) {
        // Surface as a thrown SeederError AFTER emission so callers can
        // catch + still see the partial-result fields on the error.
        var err = _err("RUN_FAILED",
          "seeders.run: seed '" + failed + "' failed; " + applied.length +
          " applied, batch aborted");
        err.result = result;
        throw err;
      }
      return result;
    } finally {
      _releaseLock(db, holder);
    }
  }

  return {
    run:    run,
    status: status,
    list:   list,
    dir:    dir,
  };
}

module.exports = {
  create:           create,
  SeederError:      SeederError,
  DEFAULTS:         DEFAULTS,
  // Internals exposed for tests + tooling
  SEEDERS_TABLE:    SEEDERS_TABLE,
  LOCK_TABLE:       LOCK_TABLE,
  FILE_RE:          FILE_RE,
};
