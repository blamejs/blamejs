"use strict";
var observability = require("./observability");

/**
 * Framework error base class + cross-module operational error classes.
 *
 * Two scopes live here:
 *
 *   1. FrameworkError — base class every framework error class extends.
 *      Provides a single `instanceof FrameworkError` check (replacing the
 *      scattered `isXxxError` boolean flags) plus a stable shape: { name,
 *      code, message, isFrameworkError: true }.
 *
 *   2. Cross-module operational error classes — errors raised by more
 *      than one module that share a logical domain (e.g. ObjectStoreError
 *      raised by the 5 object-store adapters + the umbrella). These can't
 *      live in the umbrella module because adapters would need a circular
 *      require to access them. They live here, where every adapter can
 *      import from the same place.
 *
 *   3. defineClass(name, opts) — factory that produces a FrameworkError
 *      subclass with the standard shape. Eliminates the boilerplate that
 *      every per-domain error class was duplicating across lib/.
 *
 * Per-domain VALIDATION errors (SafeSqlError, SafeJsonError, SafeBufferError,
 * SafeAsyncError, AtomicFileError, ChainWriterError, ClusterStorageError,
 * NotLeaderError, FrameworkSchemaError, *SafeError parser families) stay
 * co-located with their primitive module — they're single-owner, single-
 * domain, and the *-safe filename convention already declares ownership.
 * They extend FrameworkError so the unified `instanceof` check works.
 *
 * Operational error classes here all share:
 *   { name, code, message, permanent: bool, isFrameworkError: true }
 * Adapters that talk over HTTP also carry `statusCode` for retry
 * classification.
 */

class FrameworkError extends Error {
  constructor(message, code) {
    super(message);
    this.name = "FrameworkError";
    this.code = code || "framework/invalid";
    this.isFrameworkError = true;
  }
}

// defineClass — factory for the standard FrameworkError-subclass shape
// every per-domain error followed by hand. Variants the factory covers:
//
//   defineClass("MyError")
//     constructor: (code, message, permanent)
//     fields:      name, permanent, isMyError
//
//   defineClass("MyError", { withStatusCode: true })
//     constructor: (code, message, permanent, statusCode)
//     fields:      + statusCode  (HTTP-shaped operational errors)
//
//   defineClass("MyError", { alwaysPermanent: true })
//     constructor: (code, message)
//     fields:      permanent always true (auth failures, validation)
//
//   defineClass("MyError", { withCause: true })
//     constructor: (code, message, cause)
//     fields:      + cause  (errors that wrap an upstream cause)
//
// Returns the constructor. Operators can attach extra static helpers
// to it after creation if they need to.
function defineClass(name, opts) {
  if (typeof name !== "string" || name.length === 0) {
    throw new Error("defineClass: name must be a non-empty string");
  }
  opts = opts || {};
  var alwaysPermanent = !!opts.alwaysPermanent;
  var withStatusCode  = !!opts.withStatusCode;
  var withCause       = !!opts.withCause;
  if (alwaysPermanent && (withStatusCode || withCause)) {
    throw new Error("defineClass: alwaysPermanent is mutually exclusive with withStatusCode / withCause");
  }
  var flagKey = "is" + name;

  // Generated class — uses an anonymous class expression so we can set
  // the constructor name explicitly via Object.defineProperty (matters
  // for stack traces and instanceof debugging).
  var GeneratedError = class extends FrameworkError {
    constructor(code, message, arg3, arg4) {
      super(message, code);
      this.name = name;
      this[flagKey] = true;
      if (alwaysPermanent) {
        this.permanent = true;
      } else if (withCause) {
        this.cause = arg3;
      } else {
        this.permanent = !!arg3;
        if (withStatusCode) this.statusCode = arg4;
      }
      // Framework-error class counter — routed into framework_errors_total
      // when a metrics registry is active. observability.event is safe to
      // call here even during framework-error's own load: observability's
      // dependencies on metrics + tracing are themselves lazy-required
      // and only resolve at first call (post-load).
      try { observability.event("error.construct", 1, { class: name }); }
      catch (_e) { /* defensive — no observability sink should ever break a constructor */ }
    }
  };
  Object.defineProperty(GeneratedError, "name", { value: name, configurable: true });
  // Per-class factory — collapses the boilerplate every module used to
  // write as `function _err(code, msg, perm) { return new XxxError(...); }`.
  // Now: `var _err = XxxError.factory;` (one line, same call shape).
  GeneratedError.factory = function (code, message, arg3, arg4) {
    return new GeneratedError(code, message, arg3, arg4);
  };
  return GeneratedError;
}

// ---- Cross-module operational classes (defined via the factory) ----

var ObjectStoreError      = defineClass("ObjectStoreError",      { withStatusCode: true });
var LogStreamError        = defineClass("LogStreamError",        { withStatusCode: true });
var QueueError            = defineClass("QueueError");
var ExternalDbError       = defineClass("ExternalDbError");
var ClusterError          = defineClass("ClusterError");
var ClusterProviderError  = defineClass("ClusterProviderError");
var HandlerError          = defineClass("HandlerError",          { withCause: true });
var StorageError          = defineClass("StorageError");
// AuthError covers password / passkey / TOTP failures at the framework
// layer (lib/auth/*). Always permanent — auth failures are not transient
// ("retry might work"); they're "this credential doesn't match" or
// "this input was malformed".
var AuthError             = defineClass("AuthError",             { alwaysPermanent: true });
var JobsError             = defineClass("JobsError");
var SchedulerError        = defineClass("SchedulerError");
var SessionError          = defineClass("SessionError");
var SlugError             = defineClass("SlugError",             { alwaysPermanent: true });
var WebhookError          = defineClass("WebhookError",          { alwaysPermanent: true });
var ApiKeyError           = defineClass("ApiKeyError",           { alwaysPermanent: true });
var PermissionsError      = defineClass("PermissionsError",      { alwaysPermanent: true });
// CacheError is alwaysPermanent: bad opts / missing key / closed-state
// errors are programming bugs, not transient. Backend-level transient
// failures (cluster DB unavailable mid-fetch) become observability +
// audit signals; they don't escape as exceptions to the caller.
var CacheError            = defineClass("CacheError",            { alwaysPermanent: true });
// SeederError is alwaysPermanent: load failures, bad-shape seed files,
// missing deps, and cycle errors are programming bugs. Per-seed runtime
// failures get wrapped in this class with the seed name in the message
// — operators see "seeders/run-failed: 0042-x.js: <cause>" not a raw
// driver exception.
var SeederError           = defineClass("SeederError",           { alwaysPermanent: true });

module.exports = {
  FrameworkError:         FrameworkError,
  defineClass:            defineClass,
  ObjectStoreError:       ObjectStoreError,
  LogStreamError:         LogStreamError,
  QueueError:             QueueError,
  ExternalDbError:        ExternalDbError,
  ClusterError:           ClusterError,
  ClusterProviderError:   ClusterProviderError,
  HandlerError:           HandlerError,
  StorageError:           StorageError,
  AuthError:              AuthError,
  JobsError:              JobsError,
  SchedulerError:         SchedulerError,
  SessionError:           SessionError,
  SlugError:              SlugError,
  WebhookError:           WebhookError,
  ApiKeyError:            ApiKeyError,
  PermissionsError:       PermissionsError,
  CacheError:             CacheError,
  SeederError:            SeederError,
};
