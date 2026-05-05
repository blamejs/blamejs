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
      observability.safeEvent("error.construct", 1, { class: name });
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
// RedisError covers transport (CONNECT/CONNECT_TIMEOUT/SOCKET/WRITE),
// protocol parsing (PROTOCOL/BAD_URL/BAD_OPTS), command-level
// (REDIS_REPLY/COMMAND_TIMEOUT), and lifecycle (CLOSED/RECONNECT_GAVE_UP).
// Transient by default — operators wrap calls in retry/breaker. Bad-opts
// and bad-URL paths surface as alwaysPermanent code names so retry sees
// them and skips immediately rather than hammering a misconfig.
var RedisError            = defineClass("RedisError");
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
// I18nError is alwaysPermanent: bad locale tags, malformed translation
// trees, missing-key in throw mode, and bad input to formatters are
// programming bugs. Missing keys in default ("return-key") mode return
// the key without throwing — runtime hot-path semantics, not error.
var I18nError             = defineClass("I18nError",             { alwaysPermanent: true });
// NotifyError is alwaysPermanent: bad opts, unknown channels, transport
// contract violations are programming bugs. Per-send transient failures
// (the kind retry can recover) are surfaced from the underlying transport
// with their own shape; only after retry exhaustion does notify wrap
// them into NotifyError SEND_FAILED — at that point they ARE permanent.
var NotifyError           = defineClass("NotifyError",           { alwaysPermanent: true });
// TestingError is alwaysPermanent: bad inputs to test helpers
// (NaN clock, non-fn predicate, path-traversal tempDir prefix) and
// waitFor timeouts are programming bugs at test-write time.
var TestingError          = defineClass("TestingError",          { alwaysPermanent: true });
// LockoutError is alwaysPermanent: misconfig at create() and bad keys at
// recordFailure/recordSuccess/check/unlock are programming bugs. The
// "account is currently locked" condition is NOT an error — recordFailure
// returns { locked: true, lockedUntil } so the caller decides the response.
var LockoutError          = defineClass("LockoutError",          { alwaysPermanent: true });
// FileUploadError is alwaysPermanent: chunk-hash mismatch / oversized
// chunk / oversized total file / manifest verification failure are all
// caller-shape errors that won't succeed on retry. Operators wrap the
// route handler with their own retry policy if they want client-side
// resumability.
var FileUploadError       = defineClass("FileUploadError",       { alwaysPermanent: true });
// StaticServeError covers the download-side surface of staticServe.create.
// withStatusCode: true so the framework can translate to operator-meaningful
// HTTP responses (403 permission_denied, 404 not_found, 412 precondition_failed,
// 416 range_not_satisfiable, 429 quota_exceeded, 451 retention_blocked).
var StaticServeError      = defineClass("StaticServeError",      { withStatusCode: true });
// GateContractError covers gate-contract violations (operator-supplied
// gate is malformed / hook threw / runtime exceeded). alwaysPermanent
// because these are programming-bug-shaped, not transient.
var GateContractError     = defineClass("GateContractError",     { alwaysPermanent: true });
// GuardCsvError covers csv-shape violations on the serialize / sanitize /
// validate paths. alwaysPermanent — chunk-shape errors / formula-injection
// attempts / schema drift are all caller-shape errors.
var GuardCsvError         = defineClass("GuardCsvError",         { alwaysPermanent: true });
// GuardAllError covers parity-check failures, exceptFor opt validation, and
// override opt validation in the b.guardAll registry. alwaysPermanent — every
// case is a config-time programming bug, not a transient runtime condition.
var GuardAllError         = defineClass("GuardAllError",         { alwaysPermanent: true });
// GuardHtmlError covers html-shape violations on validate / sanitize / escape
// paths. alwaysPermanent — XSS attempts / dangerous-tag detections / DOM
// clobbering are all caller-shape errors.
var GuardHtmlError        = defineClass("GuardHtmlError",        { alwaysPermanent: true });
// GuardSvgError covers svg-shape violations: dangerous tags (script /
// foreignObject / use cross-origin / handler), DOCTYPE entity expansion
// (billion laughs / XXE), animation-element attributeName targeting href,
// SVGZ compressed payloads, SSRF-shape href references. alwaysPermanent.
var GuardSvgError         = defineClass("GuardSvgError",         { alwaysPermanent: true });
// GuardFilenameError covers filename-shape violations: path traversal,
// null-byte truncation, Windows reserved names (CON / PRN / AUX / ...),
// NTFS alternate data streams, leading/trailing whitespace + trailing dots
// (Windows strips them silently), unicode bidi/RTLO file-name spoofing,
// overlong UTF-8 encoding, length caps. alwaysPermanent.
var GuardFilenameError    = defineClass("GuardFilenameError",    { alwaysPermanent: true });
// GuardArchiveError covers archive-shape violations: zip-slip path
// traversal, symlink + hardlink escape, decompression-ratio bombs,
// nested-archive depth, file-count + total-size + per-entry-size caps,
// magic-byte / format-claim mismatch, duplicate entries, encryption-
// claim mismatch. alwaysPermanent.
var GuardArchiveError     = defineClass("GuardArchiveError",     { alwaysPermanent: true });
// GuardJsonError covers json-shape violations: prototype pollution
// (__proto__/constructor/prototype), depth + breadth + key-count bombs,
// duplicate keys, NaN/Infinity/comments (JSON5 extensions), bidi/null
// in string values, numeric precision loss, total-size cap.
// alwaysPermanent.
var GuardJsonError        = defineClass("GuardJsonError",        { alwaysPermanent: true });
// GuardYamlError covers yaml-shape violations: deserialization-tag
// injection (!!python/object / !!java.util.HashMap / custom !Class),
// anchor recursion (billion laughs), Norway-problem implicit booleans,
// leading-zero octals, duplicate keys, multi-document streams, depth +
// node-count + size caps. alwaysPermanent.
var GuardYamlError        = defineClass("GuardYamlError",        { alwaysPermanent: true });
// GuardXmlError covers xml-shape violations: XXE, billion-laughs entity
// expansion, parameter entities, external DTD subset, XInclude, schema-
// fetch (xsi:schemaLocation), processing instructions, CDATA, depth +
// element-count + attribute-count caps. alwaysPermanent.
var GuardXmlError         = defineClass("GuardXmlError",         { alwaysPermanent: true });
// GuardMarkdownError covers markdown-shape violations: raw-HTML smuggling
// (including the CVE-2026-30838 whitespace-in-tag-name bypass), dangerous
// link / image / autolink / reference-link URL schemes (javascript: / data:
// text/html / vbscript: / file: / jar:), entity-encoded scheme bypass,
// front-matter payloads, ReDoS-prone emphasis / nesting / autolink mass,
// HTML-comment smuggling, code-fence language injection, depth + link
// count + image count + line count + size caps. alwaysPermanent.
var GuardMarkdownError    = defineClass("GuardMarkdownError",    { alwaysPermanent: true });
// GuardEmailError covers email-shape violations: SMTP smuggling (bare
// CR/LF in body, embedded SMTP verbs), CRLF header injection, RFC 5321
// /5322 local-part / domain / total-length caps, multi-@ violations,
// IDN homograph spoofing (mixed-script confusable codepoints), display-
// name vs envelope mismatch, bare IP literal addresses, comment syntax
// in addresses, bidi/null/control chars in headers + addresses, header-
// folding smuggling, BOM injection. alwaysPermanent.
var GuardEmailError       = defineClass("GuardEmailError",       { alwaysPermanent: true });
// DoraError covers DORA Article 17 incident-reporting workflow errors
// (classification refusal, report-shape validation, ESA-template
// generation, audit-chain integration). Permanent — these are
// configuration / submission errors, not transient.
var DoraError             = defineClass("DoraError",             { alwaysPermanent: true });
// ComplianceError covers compliance-coordinator misuse: unknown
// posture name, runtime-switch refusal, assertion failures.
// Permanent — these are configuration errors, not transient.
var ComplianceError       = defineClass("ComplianceError",       { alwaysPermanent: true });
// SmtpPolicyError covers MTA-STS / DANE / TLS-RPT misuse: bad-policy
// shape, fetch failures, TLSA-record format errors, missing records.
// Permanent — these are policy / DNS configuration errors, not
// transient.
var SmtpPolicyError       = defineClass("SmtpPolicyError",       { alwaysPermanent: true });

module.exports = {
  FrameworkError:         FrameworkError,
  defineClass:            defineClass,
  ObjectStoreError:       ObjectStoreError,
  LogStreamError:         LogStreamError,
  QueueError:             QueueError,
  RedisError:             RedisError,
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
  I18nError:              I18nError,
  NotifyError:            NotifyError,
  TestingError:           TestingError,
  LockoutError:           LockoutError,
  FileUploadError:        FileUploadError,
  StaticServeError:       StaticServeError,
  GateContractError:      GateContractError,
  GuardCsvError:          GuardCsvError,
  GuardAllError:          GuardAllError,
  GuardHtmlError:         GuardHtmlError,
  GuardSvgError:          GuardSvgError,
  GuardFilenameError:     GuardFilenameError,
  GuardArchiveError:      GuardArchiveError,
  GuardJsonError:         GuardJsonError,
  GuardYamlError:         GuardYamlError,
  GuardXmlError:          GuardXmlError,
  GuardMarkdownError:     GuardMarkdownError,
  GuardEmailError:        GuardEmailError,
  DoraError:              DoraError,
  ComplianceError:        ComplianceError,
  SmtpPolicyError:        SmtpPolicyError,
};
