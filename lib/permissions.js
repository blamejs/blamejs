"use strict";
/**
 * b.permissions — RBAC primitive.
 *
 *   var perms = b.permissions.create({
 *     roles: {
 *       admin:  { extends: ["editor"], permissions: ["users:delete"] },
 *       editor: ["users:read", "users:write", "posts:*"],
 *       viewer: ["*:read"],
 *     },
 *     audit: b.audit,                  // optional
 *   });
 *
 *   router.delete("/users/:id",
 *     authMiddleware,                  // populates req.user / req.apiKey
 *     perms.require("users:delete"),
 *     deleteUserHandler);
 *
 * The default resolver chain reads the actor from the request:
 *
 *   req.apiKey.scopes  → { scopes: [...] }   (b.apiKey.verify output)
 *   req.user.scopes    → { scopes: [...] }   (operator-set)
 *   req.user.roles     → { roles:  [...] }   (operator-set)
 *
 * Operators with non-default request shapes pass `resolver` to create().
 *
 * Wildcard semantics (b.permissions.match):
 *   "*"             matches any scope (greedy)
 *   "users:*"       matches "users:read", "users:read:detail", etc. (trailing * is greedy)
 *   "*:read"        matches "users:read", "posts:read"
 *   "users:*:read"  matches "users:foo:read" (per-segment *)
 *   "users:read"    matches "users:read" only — no implicit sub-resource grant
 *
 * Validation tiers:
 *
 *   - create() role table / scope formats → Tier A (throw at app init)
 *   - require(scope) registration arg     → Tier A (throw at route declaration)
 *   - check(actor, scope) bad actor       → Tier C (return false)
 *   - resolver returns null in middleware → 401 (missingActorStatus)
 *   - actor lacks scope in middleware     → 403 (denyStatus)
 *   - audit/observability emit failures   → Tier B (drop silent)
 *
 * Audit defaults follow the framework's security-defaults stance
 * default: `auditFailures: true`
 * (deny is a security signal), `auditSuccess: false` (per-request noise).
 */

var lazyRequire = require("./lazy-require");
var requestHelpers = require("./request-helpers");
var validateOpts = require("./validate-opts");
var { PermissionsError } = require("./framework-error");

var _err = PermissionsError.factory;

var observability = lazyRequire(function () { return require("./observability"); });

function _emitEvent(name, value, labels) {
  try { observability().event(name, value, labels || {}); }
  catch (_e) { /* Tier B: hot-path observability sink */ }
}

// Lowercase tokens, digits, dash, underscore, and `*` allowed per
// segment. Scope format is segments separated by `:`.
var SCOPE_RE = /^[a-z0-9_*-]+(:[a-z0-9_*-]+)*$/;

// Audit defaults: BOTH success and failure default ON for permissions.
// Unlike api-key.verify (which is gate-keeping for a downstream action
// the application separately audits), a permissions.check IS the
// authorization decision — there's no further-downstream audit event.
// "user X granted users:delete at time T" is exactly what compliance
// auditors ask for. Operators with extreme volume opt out via
// auditSuccess: false; failures remain on regardless.
var DEFAULTS = Object.freeze({
  auditFailures:       true,
  auditSuccess:        true,
  denyStatus:          403,
  missingActorStatus:  401,
});

// ---- Wildcard matcher ----

function match(granted, required) {
  if (typeof granted !== "string" || typeof required !== "string") return false;
  if (granted.length === 0 || required.length === 0) return false;
  var gParts = granted.split(":");
  var rParts = required.split(":");
  for (var i = 0; i < gParts.length; i++) {
    var g = gParts[i];
    if (g === "*") {
      // Trailing * is greedy — matches the rest of required.
      if (i === gParts.length - 1) return true;
      // Per-segment * — matches THIS segment of required (any value),
      // continue to next segment. Required must have a segment here.
      if (i >= rParts.length) return false;
      continue;
    }
    if (i >= rParts.length) return false;     // granted is more specific than required
    if (g !== rParts[i]) return false;
  }
  // Reached end of granted without wildcard. Lengths must match exactly
  // (no implicit sub-resource grant).
  return rParts.length === gParts.length;
}

// ---- Role table validation + expansion ----

function _validateScopePattern(scope, ctx) {
  if (typeof scope !== "string" || scope.length === 0) {
    throw _err("BAD_SCOPE", ctx + ": scope must be a non-empty string, got " + typeof scope);
  }
  if (!SCOPE_RE.test(scope)) {
    throw _err("BAD_SCOPE", ctx + ": scope '" + scope +
      "' must match " + SCOPE_RE + " (lowercase tokens with optional `*`)");
  }
}

function _normalizeRoleEntry(name, entry) {
  if (Array.isArray(entry)) {
    return { extends: [], permissions: entry.slice() };
  }
  if (entry && typeof entry === "object") {
    var ext = entry.extends || [];
    var perms = entry.permissions || [];
    if (!Array.isArray(ext)) {
      throw _err("BAD_ROLE", "role '" + name + "': extends must be an array of role names");
    }
    if (!Array.isArray(perms)) {
      throw _err("BAD_ROLE", "role '" + name + "': permissions must be an array of scope strings");
    }
    return { extends: ext.slice(), permissions: perms.slice() };
  }
  throw _err("BAD_ROLE", "role '" + name + "' must be an array of scopes or { extends?, permissions }");
}

function _validateRoles(roles) {
  if (!roles || typeof roles !== "object" || Array.isArray(roles)) {
    throw _err("BAD_OPT", "permissions.create: roles must be an object map of name → spec");
  }
  var names = Object.keys(roles);
  if (names.length === 0) {
    throw _err("BAD_OPT", "permissions.create: roles map must have at least one role");
  }
  var normalized = {};
  for (var i = 0; i < names.length; i++) {
    var name = names[i];
    if (typeof name !== "string" || name.length === 0) {
      throw _err("BAD_ROLE", "role name must be a non-empty string");
    }
    var spec = _normalizeRoleEntry(name, roles[name]);
    for (var j = 0; j < spec.permissions.length; j++) {
      _validateScopePattern(spec.permissions[j], "role '" + name + "'");
    }
    for (var k = 0; k < spec.extends.length; k++) {
      if (typeof spec.extends[k] !== "string" || spec.extends[k].length === 0) {
        throw _err("BAD_ROLE", "role '" + name + "': extends entry must be a non-empty string");
      }
    }
    normalized[name] = spec;
  }
  // Check extends references resolve to known roles
  for (var n = 0; n < names.length; n++) {
    var spec2 = normalized[names[n]];
    for (var m = 0; m < spec2.extends.length; m++) {
      if (!Object.prototype.hasOwnProperty.call(normalized, spec2.extends[m])) {
        throw _err("UNKNOWN_ROLE", "role '" + names[n] + "': extends references unknown role '" +
          spec2.extends[m] + "'");
      }
    }
  }
  // Cycle detection via DFS
  for (var p = 0; p < names.length; p++) {
    _detectCycle(names[p], normalized, []);
  }
  return normalized;
}

function _detectCycle(roleName, table, stack) {
  if (stack.indexOf(roleName) !== -1) {
    throw _err("CYCLE", "permissions.create: cycle in extends chain: " +
      stack.concat([roleName]).join(" → "));
  }
  var spec = table[roleName];
  for (var i = 0; i < spec.extends.length; i++) {
    _detectCycle(spec.extends[i], table, stack.concat([roleName]));
  }
}

function _expandOne(roleName, table, visited, out) {
  if (visited.has(roleName)) return;
  visited.add(roleName);
  var spec = table[roleName];
  if (!spec) return;
  for (var i = 0; i < spec.extends.length; i++) {
    _expandOne(spec.extends[i], table, visited, out);
  }
  for (var j = 0; j < spec.permissions.length; j++) {
    if (out.indexOf(spec.permissions[j]) === -1) out.push(spec.permissions[j]);
  }
}

// ---- Default resolver ----

function _defaultResolver(req) {
  if (!req || typeof req !== "object") return null;
  if (req.apiKey && Array.isArray(req.apiKey.scopes)) return { scopes: req.apiKey.scopes };
  if (req.user && Array.isArray(req.user.scopes))     return { scopes: req.user.scopes };
  if (req.user && Array.isArray(req.user.roles))      return { roles:  req.user.roles };
  return null;
}

// ---- Validation: create opts ----

function _validateCreateOpts(opts) {
  if (!opts || typeof opts !== "object") {
    throw _err("BAD_OPT", "permissions.create: opts must be an object");
  }
  if (opts.resolver !== undefined && typeof opts.resolver !== "function") {
    throw _err("BAD_OPT", "permissions.create: resolver must be a function");
  }
  if (opts.audit !== undefined && opts.audit !== null) {
    if (typeof opts.audit !== "object" || typeof opts.audit.safeEmit !== "function") {
      throw _err("BAD_OPT", "permissions.create: audit must be a b.audit-shaped object (safeEmit fn)");
    }
  }
  if (opts.auditFailures !== undefined && typeof opts.auditFailures !== "boolean") {
    throw _err("BAD_OPT", "permissions.create: auditFailures must be a boolean");
  }
  if (opts.auditSuccess !== undefined && typeof opts.auditSuccess !== "boolean") {
    throw _err("BAD_OPT", "permissions.create: auditSuccess must be a boolean");
  }
  if (opts.denyStatus !== undefined &&
      (typeof opts.denyStatus !== "number" || !isFinite(opts.denyStatus) || opts.denyStatus < 100 || opts.denyStatus > 599)) {
    throw _err("BAD_OPT", "permissions.create: denyStatus must be an HTTP status code (100-599)");
  }
  if (opts.missingActorStatus !== undefined &&
      (typeof opts.missingActorStatus !== "number" || !isFinite(opts.missingActorStatus) ||
       opts.missingActorStatus < 100 || opts.missingActorStatus > 599)) {
    throw _err("BAD_OPT", "permissions.create: missingActorStatus must be an HTTP status code (100-599)");
  }
  if (opts.responder !== undefined && typeof opts.responder !== "function") {
    throw _err("BAD_OPT", "permissions.create: responder must be a function");
  }
}

// ---- Registry ----

function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "roles", "resolver", "audit", "auditFailures", "auditSuccess",
    "denyStatus", "missingActorStatus", "responder",
  ], "permissions");
  _validateCreateOpts(opts);
  var roleTable = _validateRoles(opts.roles);
  var resolver  = opts.resolver || _defaultResolver;
  var audit     = opts.audit || null;
  var auditFailures = (opts.auditFailures === undefined) ? DEFAULTS.auditFailures : opts.auditFailures;
  var auditSuccess  = (opts.auditSuccess  === undefined) ? DEFAULTS.auditSuccess  : opts.auditSuccess;
  var denyStatus    = opts.denyStatus    || DEFAULTS.denyStatus;
  var missingActorStatus = opts.missingActorStatus || DEFAULTS.missingActorStatus;
  var responder = opts.responder || _defaultResponder;

  function _auditEmit(action, info) {
    if (!audit) return;
    if (info && info.outcome === "success" && !auditSuccess) return;
    if (info && info.outcome !== "success" && !auditFailures) return;
    try { audit.safeEmit(Object.assign({ action: action }, info || {})); }
    catch (_e) { /* audit best-effort */ }
  }

  function expand(roleNames) {
    if (!Array.isArray(roleNames)) return [];
    var visited = new Set();
    var out = [];
    for (var i = 0; i < roleNames.length; i++) {
      if (typeof roleNames[i] === "string" && Object.prototype.hasOwnProperty.call(roleTable, roleNames[i])) {
        _expandOne(roleNames[i], roleTable, visited, out);
      }
    }
    return out;
  }

  function _actorScopes(actor) {
    if (!actor || typeof actor !== "object") return [];
    if (Array.isArray(actor.scopes)) return actor.scopes;
    if (Array.isArray(actor.roles))  return expand(actor.roles);
    return [];
  }

  function check(actor, requiredScope) {
    var scopes = _actorScopes(actor);
    for (var i = 0; i < scopes.length; i++) {
      if (typeof scopes[i] === "string" && match(scopes[i], requiredScope)) return true;
    }
    return false;
  }

  function checkAll(actor, requiredScopes) {
    if (!Array.isArray(requiredScopes)) return false;
    for (var i = 0; i < requiredScopes.length; i++) {
      if (!check(actor, requiredScopes[i])) return false;
    }
    return requiredScopes.length > 0;
  }

  function checkAny(actor, requiredScopes) {
    if (!Array.isArray(requiredScopes)) return false;
    for (var i = 0; i < requiredScopes.length; i++) {
      if (check(actor, requiredScopes[i])) return true;
    }
    return false;
  }

  // Middleware factory. `mode` is "single" | "all" | "any"; `requested`
  // is the scope or scope list. Tier A on registration arg.
  function _middleware(mode, requested) {
    if (mode === "single") {
      _validateScopePattern(requested, "permissions.require");
    } else {
      if (!Array.isArray(requested) || requested.length === 0) {
        throw _err("BAD_OPT", "permissions." + (mode === "all" ? "requireAll" : "requireAny") +
          ": scopes must be a non-empty array");
      }
      for (var i = 0; i < requested.length; i++) {
        _validateScopePattern(requested[i], "permissions." + (mode === "all" ? "requireAll" : "requireAny"));
      }
    }

    return function permissionsMiddleware(req, res, next) {
      var actor = resolver(req);
      if (!actor) {
        // Diagnostic: the most common cause of a null actor is that
        // attachUser/auth wasn't mounted before this middleware, so
        // req.user / req.apiKey are still undefined. Emit a hint —
        // operators tracing a 401 here see exactly what to check first.
        var hint = (req && (req.user || req.apiKey))
          ? "actor present on req but resolver returned null — check resolver implementation"
          : "no req.user or req.apiKey — confirm attachUser / apiKey-verify middleware is mounted before perms.require()";
        _emitEvent("permissions.missing_actor", 1,
          { requested: _labelize(requested) });
        _auditEmit("permissions.missing_actor", {
          actor:    _actorAuditShape(null, req),
          resource: { kind: "permission", id: _labelize(requested) },
          outcome:  "failure",
          reason:   "no-actor",
          metadata: { hint: hint },
        });
        return responder(req, res, missingActorStatus, {
          error:  "missing_actor",
          status: missingActorStatus,
        });
      }

      var ok;
      if (mode === "single")  ok = check(actor, requested);
      else if (mode === "all") ok = checkAll(actor, requested);
      else                     ok = checkAny(actor, requested);

      if (!ok) {
        _emitEvent("permissions.check", 1,
          { outcome: "deny", requested: _labelize(requested), mode: mode });
        _auditEmit("permissions.check.deny", {
          actor:    _actorAuditShape(actor, req),
          resource: { kind: "permission", id: _labelize(requested) },
          outcome:  "failure",
          reason:   "forbidden",
          metadata: { mode: mode },
        });
        return responder(req, res, denyStatus, {
          error:     "forbidden",
          status:    denyStatus,
          requested: _labelize(requested),
        });
      }

      _emitEvent("permissions.check", 1,
        { outcome: "success", mode: mode });
      _auditEmit("permissions.check.success", {
        actor:    _actorAuditShape(actor, req),
        resource: { kind: "permission", id: _labelize(requested) },
        outcome:  "success",
        metadata: { mode: mode },
      });
      next();
    };
  }

  return {
    require:    function (scope)  { return _middleware("single", scope); },
    requireAll: function (scopes) { return _middleware("all",    scopes); },
    requireAny: function (scopes) { return _middleware("any",    scopes); },
    check:      check,
    checkAll:   checkAll,
    checkAny:   checkAny,
    expand:     expand,
    has:        function (name) { return Object.prototype.hasOwnProperty.call(roleTable, name); },
    roles:      Object.freeze(Object.keys(roleTable)),
  };
}

// ---- Helpers ----

function _labelize(requested) {
  return Array.isArray(requested) ? requested.join(",") : String(requested);
}

function _actorAuditShape(actor, req) {
  // Pull the 5 W's (WHO/WHERE/HOW) from the request, then layer the
  // resolver-supplied actor identity on top so userId/roles/scopes
  // aren't lost when the request itself doesn't carry them.
  var base = requestHelpers.extractActorContext(req);
  if (actor) {
    if (actor.userId)               base.userId = actor.userId;
    if (Array.isArray(actor.roles)) base.roles  = actor.roles.slice();
    if (Array.isArray(actor.scopes)) base.scopes = actor.scopes.slice();
  }
  return base;
}

function _defaultResponder(req, res, status, info) {
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8" });
  res.end(JSON.stringify(info));
}

module.exports = {
  create:           create,
  match:            match,
  PermissionsError: PermissionsError,
  DEFAULTS:         DEFAULTS,
};
