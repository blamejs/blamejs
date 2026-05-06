"use strict";
/**
 * observability — combined metrics + tracing tap surface.
 *
 * Framework hot paths previously called metrics.tap + tracing.tap
 * separately, with each module repeating the lazy-require + try/catch
 * boilerplate. This primitive folds the two into one helper:
 *
 *   var obs = require("./observability");
 *   return obs.tap("audit.record",
 *     { action: event.action, outcome: event.outcome },
 *     async function (span) {
 *       // ... operation body ...
 *       return result;
 *     });
 *
 * Behavior:
 *   - tracing.tap wraps fn in a span (spec 9.8). Pass-through is
 *     fn(null) when no tracing registry is active — zero overhead.
 *   - After fn settles (either branch), metrics.tap fires once with
 *     the same name + the same attrs reused as labels. Existing
 *     metrics _tapHandler dispatches still work unchanged because
 *     the labels are the same shape modules previously passed.
 *   - If fn throws (sync) or rejects (async), metrics still fire
 *     before the throw propagates. Operators get the counter bump
 *     even on the failure path — the existing pattern across audit /
 *     vault / queue did the same.
 *
 * Why combine: every framework module that wanted both a span AND a
 * counter previously wrote nested tap wrappers + try/catch. Centralizing
 * keeps the call sites readable, eliminates boot-order drift each
 * module had to reason about, and lets us change tap semantics
 * (e.g. add a third sink) in one place.
 *
 * For fire-and-forget value-noting where wrapping fn doesn't fit —
 * incrementing a counter on a side-effect deep inside an existing
 * function — use `event(name, value, labels)`. Same shape as the
 * legacy metrics.tap call; routes through metrics only (no span).
 *
 * Public API:
 *   observability.tap(name, attrs, fn)        → fn's return value
 *   observability.tap(name, fn)               → fn's return value (no attrs)
 *   observability.event(name, value, labels)  → undefined
 *
 * Tests live in test/layer-0-primitives/observability.test.js.
 *
 * Parameters:
 *   name: string — used as both the span name AND the metrics tap
 *     name. Convention: dotted lowercase ("audit.record", "queue.enqueue").
 *   attrs: object | null — passed verbatim to tracing.tap as span
 *     attributes AND to metrics.tap as labels. Modules previously
 *     passing two slightly-different objects to the two sinks should
 *     pass one unified shape.
 *   fn: function — sync or async. Return propagates; throws propagate
 *     after metrics fire.
 */
var lazyRequire = require("./lazy-require");

var tracing = lazyRequire(function () { return require("./tracing"); });
var metrics = lazyRequire(function () { return require("./metrics"); });

// Operator-installed tap handler — wired via setTap(). When non-null,
// every observability event/tap dispatch routes here in addition to
// the framework's metrics module. Used by b.otelExport.create() so an
// OTLP/HTTP exporter receives the same hot-path counters the framework
// emits internally.
var _externalTap = null;

function _safeMetricsTap(name, value, labels) {
  try { metrics().tap(name, value, labels); }
  catch (_e) { /* boot-order tolerance — metrics may not be loaded */ }
  if (_externalTap !== null) {
    try { _externalTap(name, value, labels); }
    catch (_e) { /* operator-installed handler — drop-silent on its throws */ }
  }
}

// setTap — install an external tap handler. Operators wire this from
// `b.otelExport.create({...}).tapHandler` so every framework counter
// also lands in the operator's metrics pipeline.
//
// The handler signature mirrors metrics.tap: (name, value, labels).
// Pass null to remove the previously-installed handler.
function setTap(handler) {
  if (handler !== null && typeof handler !== "function") {
    throw new TypeError("observability.setTap: handler must be a function or null, got " +
      typeof handler);
  }
  _externalTap = handler;
}

function tap(name, attrs, fn) {
  if (typeof attrs === "function") { fn = attrs; attrs = null; }
  // Throw on bad input: tap is called from many call sites and a typo
  // in the name (e.g. variable holding undefined) silently corrupts
  // both the span tree AND the metrics counter route, with no obvious
  // symptom until somebody opens a dashboard. Throw at first call so
  // the operator catches it.
  if (typeof name !== "string" || name.length === 0) {
    throw new TypeError("observability.tap: name must be a non-empty string, got " +
      (typeof name) + " " + JSON.stringify(name));
  }
  if (typeof fn !== "function") {
    throw new TypeError("observability.tap: fn must be a function, got " + (typeof fn));
  }
  return tracing().tap(name, attrs, function (span) {
    var ret;
    try {
      ret = fn(span);
    } catch (e) {
      _safeMetricsTap(name, 1, attrs);
      throw e;
    }
    if (ret && typeof ret.then === "function") {
      return ret.then(
        function (v) { _safeMetricsTap(name, 1, attrs); return v; },
        function (e) { _safeMetricsTap(name, 1, attrs); throw e; }
      );
    }
    _safeMetricsTap(name, 1, attrs);
    return ret;
  });
}

// Drop-silent on bad input by design: event is the fire-and-forget
// shape called from hot paths where throwing would crash the request
// that triggered it. Operators with a misnamed event see the missing
// counter, not a 500. metrics.tap performs its own label-name regex
// validation; an invalid call surfaces in the metrics module log, not
// via a thrown exception.
function event(name, value, labels) {
  if (typeof name !== "string" || name.length === 0) return;
  _safeMetricsTap(name, value, labels);
}

// safeEvent — wraps `event` in a try/catch so callers on hot paths
// (per-request observability emits) can't crash the request that
// triggered them when the metrics registry has a misconfigured
// counter or label name. Replaces the per-file `_emitEvent` helper
// that 7+ modules previously duplicated.
function safeEvent(name, value, labels) {
  try { event(name, value, labels); }
  catch (_e) { /* hot-path observability sink — drops silent on internal throws */ }
}

// timed — convenience wrapper that measures wall-clock duration of a
// sync or async operation and emits a counter event with
// duration_ms in the labels. Returns the wrapped function's return
// value verbatim; rethrows on error after emitting the failure event
// with outcome: "fail".
//
//   var rows = await b.observability.timed("db.query", async function () {
//     return await db.query("SELECT * FROM users");
//   }, { [SEMCONV.DB_OPERATION_NAME]: "select" });
//
// On success: emits `<name>` with { ...labels, outcome: "ok",
// duration_ms }. On throw: emits with outcome: "fail".
//
// The operation name MUST be a stable string (not derived from input)
// to keep the metric cardinality bounded; operators dynamically
// scope-naming via prefix should use the labels parameter instead.
function timed(name, fn, labels) {
  if (typeof name !== "string" || name.length === 0) {
    throw new TypeError("observability.timed: name must be a non-empty string");
  }
  if (typeof fn !== "function") {
    throw new TypeError("observability.timed: fn must be a function");
  }
  var start = Date.now();
  function _emit(outcome, extra) {
    var allLabels = Object.assign({}, labels || {}, {
      outcome:     outcome,
      duration_ms: Date.now() - start,
    }, extra || {});
    try { event(name, 1, allLabels); }
    catch (_e) { /* drop-silent — observability sink */ }
  }
  var ret;
  try { ret = fn(); }
  catch (e) {
    _emit("fail", { error_type: (e && e.name) || "Error" });
    throw e;
  }
  if (ret && typeof ret.then === "function") {
    return ret.then(
      function (v) { _emit("ok"); return v; },
      function (e) {
        _emit("fail", { error_type: (e && e.name) || "Error" });
        throw e;
      }
    );
  }
  _emit("ok");
  return ret;
}

// OpenTelemetry semantic-convention attribute names — the operator-
// facing canonical vocabulary the framework's b.observability /
// b.tracing / b.metrics emitters use when building span / metric
// attributes. Tracking the OTel semconv stable namespace (1.27+)
// directly here means operators wiring the framework's tap into an
// OTel SDK don't need to maintain an aliasing table — the names are
// already correct.
//
// When operators call b.observability.event() / safeEvent(), they
// pass attribute keys that should match the keys below. The map is
// frozen — adding a new attribute requires a release.
//
// Reference: https://opentelemetry.io/docs/specs/semconv/general/attributes/
var SEMCONV = Object.freeze({
  // HTTP server (stable per OTel semconv)
  HTTP_REQUEST_METHOD:        "http.request.method",
  HTTP_REQUEST_BODY_SIZE:     "http.request.body.size",
  HTTP_RESPONSE_STATUS_CODE:  "http.response.status_code",
  HTTP_RESPONSE_BODY_SIZE:    "http.response.body.size",
  HTTP_ROUTE:                 "http.route",
  // Server / network
  SERVER_ADDRESS:             "server.address",
  SERVER_PORT:                "server.port",
  CLIENT_ADDRESS:             "client.address",
  CLIENT_PORT:                "client.port",
  NETWORK_PEER_ADDRESS:       "network.peer.address",
  NETWORK_PROTOCOL_NAME:      "network.protocol.name",
  NETWORK_PROTOCOL_VERSION:   "network.protocol.version",
  // URL
  URL_FULL:                   "url.full",
  URL_PATH:                   "url.path",
  URL_QUERY:                  "url.query",
  URL_SCHEME:                 "url.scheme",
  // User agent
  USER_AGENT_ORIGINAL:        "user_agent.original",
  // Database
  DB_SYSTEM:                  "db.system",
  DB_NAMESPACE:               "db.namespace",
  DB_OPERATION_NAME:          "db.operation.name",
  DB_QUERY_TEXT:              "db.query.text",
  // Messaging
  MESSAGING_SYSTEM:           "messaging.system",
  MESSAGING_OPERATION:        "messaging.operation",
  MESSAGING_DESTINATION_NAME: "messaging.destination.name",
  // Auth / session
  USER_ID:                    "user.id",
  SESSION_ID:                 "session.id",
  // Errors
  ERROR_TYPE:                 "error.type",
  EXCEPTION_TYPE:             "exception.type",
  EXCEPTION_MESSAGE:          "exception.message",
  EXCEPTION_STACKTRACE:       "exception.stacktrace",
  // RPC
  RPC_SYSTEM:                 "rpc.system",
  RPC_SERVICE:                "rpc.service",
  RPC_METHOD:                 "rpc.method",
  RPC_GRPC_STATUS_CODE:       "rpc.grpc.status_code",
  // Messaging — additional client/server attrs
  MESSAGING_CLIENT_ID:                "messaging.client.id",
  MESSAGING_MESSAGE_ID:               "messaging.message.id",
  MESSAGING_DESTINATION_PARTITION_ID: "messaging.destination.partition.id",
  MESSAGING_BATCH_MESSAGE_COUNT:      "messaging.batch.message_count",
  // Network — transport / connection state
  NETWORK_TRANSPORT:          "network.transport",
  NETWORK_CONNECTION_TYPE:    "network.connection.type",
  // Process / runtime
  PROCESS_PID:                "process.pid",
  PROCESS_RUNTIME_NAME:       "process.runtime.name",
  PROCESS_RUNTIME_VERSION:    "process.runtime.version",
  // Service identification
  SERVICE_NAME:               "service.name",
  SERVICE_VERSION:             "service.version",
  SERVICE_INSTANCE_ID:        "service.instance.id",
  // Telemetry SDK self-identification
  TELEMETRY_SDK_NAME:         "telemetry.sdk.name",
  TELEMETRY_SDK_LANGUAGE:     "telemetry.sdk.language",
  TELEMETRY_SDK_VERSION:      "telemetry.sdk.version",
  // GenAI — OpenTelemetry semantic conventions for generative AI
  // workloads (LLM clients, vector DB queries, agent frameworks).
  // Tracking the otel-spec experimental namespace; covers the stable
  // attribute set as of 2026-Q2.
  GEN_AI_SYSTEM:                  "gen_ai.system",
  GEN_AI_REQUEST_MODEL:           "gen_ai.request.model",
  GEN_AI_REQUEST_TEMPERATURE:     "gen_ai.request.temperature",
  GEN_AI_REQUEST_TOP_P:           "gen_ai.request.top_p",
  GEN_AI_REQUEST_TOP_K:           "gen_ai.request.top_k",
  GEN_AI_REQUEST_MAX_TOKENS:      "gen_ai.request.max_tokens",
  GEN_AI_REQUEST_STOP_SEQUENCES:  "gen_ai.request.stop_sequences",
  GEN_AI_RESPONSE_MODEL:          "gen_ai.response.model",
  GEN_AI_RESPONSE_ID:             "gen_ai.response.id",
  GEN_AI_RESPONSE_FINISH_REASONS: "gen_ai.response.finish_reasons",
  GEN_AI_USAGE_INPUT_TOKENS:      "gen_ai.usage.input_tokens",
  GEN_AI_USAGE_OUTPUT_TOKENS:     "gen_ai.usage.output_tokens",
  GEN_AI_USAGE_TOTAL_TOKENS:      "gen_ai.usage.total_tokens",
  GEN_AI_OPERATION_NAME:          "gen_ai.operation.name",
  GEN_AI_TOOL_NAME:               "gen_ai.tool.name",
  GEN_AI_TOOL_CALL_ID:            "gen_ai.tool.call.id",
  GEN_AI_AGENT_ID:                "gen_ai.agent.id",
  GEN_AI_AGENT_NAME:              "gen_ai.agent.name",
  GEN_AI_AGENT_DESCRIPTION:       "gen_ai.agent.description",
  // Vector database / retrieval-augmented generation
  DB_VECTOR_QUERY_TOP_K:          "db.vector.query.top_k",
  DB_VECTOR_QUERY_DIMENSIONS:     "db.vector.query.dimensions",
  DB_VECTOR_QUERY_DISTANCE_METRIC: "db.vector.query.distance_metric",
  // Cloud / runtime context (frequently paired with GenAI)
  CLOUD_PROVIDER:                 "cloud.provider",
  CLOUD_REGION:                   "cloud.region",
  CLOUD_ACCOUNT_ID:               "cloud.account.id",
  CLOUD_RESOURCE_ID:              "cloud.resource_id",
  // Container / orchestration
  CONTAINER_ID:                   "container.id",
  CONTAINER_IMAGE_NAME:           "container.image.name",
  CONTAINER_IMAGE_TAG:            "container.image.tag",
  K8S_NAMESPACE_NAME:             "k8s.namespace.name",
  K8S_POD_NAME:                   "k8s.pod.name",
  K8S_DEPLOYMENT_NAME:            "k8s.deployment.name",
});

module.exports = {
  tap:        tap,
  event:      event,
  safeEvent:  safeEvent,
  timed:      timed,
  setTap:     setTap,
  SEMCONV:    SEMCONV,
};
