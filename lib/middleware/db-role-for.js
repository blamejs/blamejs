"use strict";
/**
 * dbRoleFor middleware — binds a request-time DB role.
 *
 * Operators using the search_path-views compliance recipe (see
 * b.db.declareView and the Compliance Patterns wiki page) declare two
 * Postgres roles: app_user (full source) and analytics_user (redacted
 * view). Each role gets its own externalDb backend — same SQL,
 * different connection pool. dbRoleFor picks the role for the current
 * request and pushes it into the shared db-role-context AsyncLocalStorage
 * scope so b.externalDb.query / read / write / transaction auto-route
 * to the matching backend without any operator threading of the role
 * through their handler signature.
 *
 *   var perms = b.permissions.create({
 *     roles: {
 *       admin:    { extends: ["app"],   permissions: ["*:*"] },
 *       app:      { permissions: ["sessions:*"], dbRole: "app_user" },
 *       analyst:  { permissions: ["sessions:read"], dbRole: "analytics_user" },
 *     },
 *   });
 *
 *   router.use(b.middleware.attachUser(...));
 *   router.use(b.middleware.dbRoleFor({
 *     permissions: perms,                 // resolves dbRole from req.user.roles
 *     defaultRole: "app_user",
 *   }));
 *
 *   router.get("/sessions", function (req, res) {
 *     // No `{ backend: ... }` opt — the framework picked it from req.dbRole.
 *     b.externalDb.read.query("SELECT * FROM sessions WHERE _id = $1", [sid])
 *       .then(...);
 *   });
 *
 * Resolution order:
 *   1. opts.resolve(req)           — operator-supplied custom resolver
 *   2. opts.permissions.dbRoleFor  — RBAC mapping (when permissions provided)
 *   3. opts.defaultRole            — fallback string
 *   4. null                        — no binding (externalDb falls back to default backend)
 *
 * Validation at create() time — bad shape throws here, not at the first
 * request:
 *   - opts shape (validateOpts allow-list)
 *   - resolve / responder must be functions if provided
 *   - permissions must expose dbRoleFor (the b.permissions shape)
 *   - defaultRole, when provided, must be a SQL-identifier-shaped string
 *   - missingRoleStatus must be a 100-599 integer
 *
 * Runtime validation on resolver output:
 *   - resolver returns must be string | null | undefined
 *   - non-empty string return MUST match safeSql.validateIdentifier; a
 *     malformed identifier from a resolver is a wiring bug (the operator
 *     plugged in a resolver that returns garbage). Routed through
 *     next(err) so the request surfaces a clear error instead of silently
 *     routing to the default backend.
 *
 * Failure modes:
 *   - resolver throws            → 500 propagated via next(err)
 *   - role required but absent   → respond with missingRoleStatus (default 401)
 *   - role identifier malformed  → respond with 500 (resolver bug — not a runtime user error)
 *
 * Observability event: db.role.bound { value: 1, labels: { role, source } }
 *   source ∈ "resolver" | "permissions" | "default"
 *
 * Audit emission of `db.role.switched` (the cross-request transition
 * record) lands in v0.6.7 — this middleware focuses on binding the role.
 */
var dbRoleContext = require("../db-role-context");
var lazyRequire = require("../lazy-require");
var safeSql = require("../safe-sql");
var validateOpts = require("../validate-opts");
var { defineClass } = require("../framework-error");

var observability = lazyRequire(function () { return require("../observability"); });

var DbRoleForError = defineClass("DbRoleForError", { alwaysPermanent: true });
var _err = function (code, message) { return new DbRoleForError(code, message); };

var ALLOWED_OPTS = [
  "resolve", "permissions", "defaultRole",
  "requireRole", "missingRoleStatus", "responder",
];

function _emitEvent(name, value, labels) {
  try { observability().event(name, value, labels || {}); }
  catch (_e) { /* hot-path observability sink — drop silent by design */ }
}

function _validateRoleIdentifier(role, where) {
  try {
    safeSql.validateIdentifier(role, { allowReserved: false });
  } catch (e) {
    throw _err("db-role-for/bad-role",
      where + ": role '" + role + "' is not a valid SQL identifier: " +
      ((e && e.message) || String(e)));
  }
}

function _defaultResponder(req, res, status, info) {
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8" });
  res.end(JSON.stringify(info));
}

function create(opts) {
  opts = opts || {};
  validateOpts(opts, ALLOWED_OPTS, "middleware.dbRoleFor");

  if (opts.resolve !== undefined && typeof opts.resolve !== "function") {
    throw _err("db-role-for/bad-opt",
      "middleware.dbRoleFor: resolve must be a function");
  }
  if (opts.responder !== undefined && typeof opts.responder !== "function") {
    throw _err("db-role-for/bad-opt",
      "middleware.dbRoleFor: responder must be a function");
  }
  if (opts.permissions !== undefined && opts.permissions !== null) {
    if (typeof opts.permissions !== "object" ||
        typeof opts.permissions.dbRoleFor !== "function") {
      throw _err("db-role-for/bad-opt",
        "middleware.dbRoleFor: permissions must be a b.permissions instance " +
        "(missing dbRoleFor method)");
    }
  }
  if (opts.defaultRole !== undefined && opts.defaultRole !== null) {
    if (typeof opts.defaultRole !== "string" || opts.defaultRole.length === 0) {
      throw _err("db-role-for/bad-opt",
        "middleware.dbRoleFor: defaultRole must be a non-empty string");
    }
    _validateRoleIdentifier(opts.defaultRole, "middleware.dbRoleFor: defaultRole");
  }
  if (opts.requireRole !== undefined && typeof opts.requireRole !== "boolean") {
    throw _err("db-role-for/bad-opt",
      "middleware.dbRoleFor: requireRole must be a boolean");
  }
  if (opts.missingRoleStatus !== undefined) {
    if (typeof opts.missingRoleStatus !== "number" ||
        !isFinite(opts.missingRoleStatus) ||
        opts.missingRoleStatus < 100 || opts.missingRoleStatus > 599) {
      throw _err("db-role-for/bad-opt",
        "middleware.dbRoleFor: missingRoleStatus must be an HTTP status code (100-599)");
    }
  }

  var resolveFn         = opts.resolve || null;
  var perms             = opts.permissions || null;
  var defaultRole       = opts.defaultRole || null;
  var requireRole       = !!opts.requireRole;
  var missingRoleStatus = opts.missingRoleStatus || 401;
  var responder         = opts.responder || _defaultResponder;

  return function dbRoleForMiddleware(req, res, next) {
    var role = null;
    var source = null;

    if (resolveFn) {
      var resolved;
      try { resolved = resolveFn(req); }
      catch (e) { return next(e); }
      if (resolved !== undefined && resolved !== null && resolved !== "") {
        role = resolved;
        source = "resolver";
      }
    }

    if (!role && perms) {
      // permissions.dbRoleFor walks req.user.roles / req.apiKey.scopes via
      // the configured resolver and returns the first declared dbRole.
      var fromPerms;
      try { fromPerms = perms.dbRoleFor(req); }
      catch (e) { return next(e); }
      if (fromPerms) {
        role = fromPerms;
        source = "permissions";
      }
    }

    if (!role && defaultRole) {
      role = defaultRole;
      source = "default";
    }

    if (!role) {
      if (requireRole) {
        _emitEvent("db.role.missing", 1, {});
        return responder(req, res, missingRoleStatus, {
          error:  "missing_db_role",
          status: missingRoleStatus,
        });
      }
      // No binding — let externalDb fall back to its default backend.
      req.dbRole = null;
      return next();
    }

    if (typeof role !== "string") {
      return next(_err("db-role-for/bad-resolver-return",
        "middleware.dbRoleFor: resolver returned non-string role: " + typeof role));
    }
    // Validate the resolver-supplied identifier at request time — a
    // malformed identifier is a wiring bug, not a request-shape concern.
    // Route the throw through next(err) so an operator's errorHandler
    // reaches it instead of the request hanging.
    try {
      _validateRoleIdentifier(role, "middleware.dbRoleFor: resolver/" + source);
    } catch (e) {
      return next(e);
    }

    req.dbRole = role;
    _emitEvent("db.role.bound", 1, { role: role, source: source });
    dbRoleContext.runWithRole(role, function () { next(); });
  };
}

module.exports = {
  create:           create,
  DbRoleForError:   DbRoleForError,
};
