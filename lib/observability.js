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

module.exports = {
  tap:        tap,
  event:      event,
  safeEvent:  safeEvent,
  setTap:     setTap,
};
