"use strict";
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
 * Per-domain VALIDATION errors (SqlSafeError, JsonSafeError, BufferSafeError,
 * AsyncSafeError, AtomicFileError, ChainWriterError, ClusterStorageError,
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

// ---- Cross-module operational classes ----

class ObjectStoreError extends FrameworkError {
  constructor(code, message, permanent, statusCode) {
    super(message, code);
    this.name = "ObjectStoreError";
    this.permanent = !!permanent;
    this.statusCode = statusCode;
    this.isObjectStoreError = true;
  }
}

class LogStreamError extends FrameworkError {
  constructor(code, message, permanent, statusCode) {
    super(message, code);
    this.name = "LogStreamError";
    this.permanent = !!permanent;
    this.statusCode = statusCode;
    this.isLogStreamError = true;
  }
}

class QueueError extends FrameworkError {
  constructor(code, message, permanent) {
    super(message, code);
    this.name = "QueueError";
    this.permanent = !!permanent;
    this.isQueueError = true;
  }
}

class ExternalDbError extends FrameworkError {
  constructor(code, message, permanent) {
    super(message, code);
    this.name = "ExternalDbError";
    this.permanent = !!permanent;
    this.isExternalDbError = true;
  }
}

class ClusterError extends FrameworkError {
  constructor(code, message, permanent) {
    super(message, code);
    this.name = "ClusterError";
    this.permanent = !!permanent;
    this.isClusterError = true;
  }
}

class ClusterProviderError extends FrameworkError {
  constructor(code, message, permanent) {
    super(message, code);
    this.name = "ClusterProviderError";
    this.permanent = !!permanent;
    this.isClusterProviderError = true;
  }
}

class HandlerError extends FrameworkError {
  constructor(code, message, cause) {
    super(message, code);
    this.name = "HandlerError";
    this.cause = cause;
    this.isHandlerError = true;
  }
}

class StorageError extends FrameworkError {
  constructor(code, message, permanent) {
    super(message, code);
    this.name = "StorageError";
    this.permanent = !!permanent;
    this.isStorageError = true;
  }
}

module.exports = {
  FrameworkError:         FrameworkError,
  ObjectStoreError:       ObjectStoreError,
  LogStreamError:         LogStreamError,
  QueueError:             QueueError,
  ExternalDbError:        ExternalDbError,
  ClusterError:           ClusterError,
  ClusterProviderError:   ClusterProviderError,
  HandlerError:           HandlerError,
  StorageError:           StorageError,
};
