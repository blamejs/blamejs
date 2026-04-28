"use strict";
/**
 * observability — combined metrics + tracing tap.
 *
 * Run standalone: `node test/layer-0-primitives/observability.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

// Minimal fake OTel api so we can verify the tracing path without
// shelling out to a real exporter — same pattern as tracing.test.js.
function _makeFakeOtelApi() {
  var spans = [];
  var activeSpan = null;
  function makeSpan(name) {
    return {
      _name: name, _attrs: {}, _ended: false,
      spanContext: function () { return { traceId: "a".repeat(32), spanId: "b".repeat(16), traceFlags: 1, isRemote: false }; },
      setAttribute:    function (k, v) { this._attrs[k] = v; return this; },
      setAttributes:   function (a) { Object.assign(this._attrs, a || {}); return this; },
      addEvent:        function () { return this; },
      recordException: function () { return this; },
      setStatus:       function () { return this; },
      updateName:      function (n) { this._name = n; return this; },
      end:             function () { this._ended = true; if (activeSpan === this) activeSpan = null; },
    };
  }
  return {
    trace: {
      getTracer: function () {
        return {
          startSpan: function (name, opts) {
            var s = makeSpan(name);
            if (opts && opts.attributes) Object.assign(s._attrs, opts.attributes);
            spans.push(s);
            activeSpan = s;
            return s;
          },
        };
      },
      getActiveSpan: function () { return activeSpan; },
      setSpan: function (_ctx, span) { return { _activeSpan: span }; },
    },
    context: {
      active: function () { return { _stub: true }; },
      with: function (ctx, fn) {
        var prev = activeSpan;
        if (ctx && ctx._activeSpan) activeSpan = ctx._activeSpan;
        try { return fn(); } finally { activeSpan = prev; }
      },
    },
    SpanKind: { INTERNAL: 0, SERVER: 1 },
    _spans: spans,
  };
}

function _resetRegistries() {
  b.metrics._resetForTest();
  b.tracing._resetForTest();
}

function testObservabilitySurface() {
  check("b.observability is exposed",          typeof b.observability === "object");
  check("observability.tap is a function",     typeof b.observability.tap === "function");
  check("observability.event is a function",   typeof b.observability.event === "function");
}

function testObservabilityTapRunsFnWithoutRegistries() {
  _resetRegistries();
  var ran = false;
  var ret = b.observability.tap("smoke.test", { x: 1 }, function (span) {
    ran = true;
    return span;
  });
  check("tap: fn ran without registries",  ran === true);
  check("tap: span arg is null pass-through", ret === null);
}

function testObservabilityTapReturnsValue() {
  _resetRegistries();
  var v = b.observability.tap("smoke.test", function () { return 42; });
  check("tap: return value preserved (no attrs)", v === 42);
  var w = b.observability.tap("smoke.test", { k: "v" }, function () { return "ok"; });
  check("tap: return value preserved (with attrs)", w === "ok");
}

async function testObservabilityTapAsyncReturn() {
  _resetRegistries();
  var v = await b.observability.tap("smoke.test", function () {
    return Promise.resolve("async-ok");
  });
  check("tap: async return value preserved", v === "async-ok");
}

function testObservabilityTapMetricsFiresOnSuccess() {
  _resetRegistries();
  var m = b.metrics.create();
  // Pre-register a counter under the tap name so we can read it back.
  var c = m.counter("smoke_op_total", { labelNames: ["k"] });
  // Observability routes metrics.tap calls into the registry's _tapHandler,
  // which dispatches by name. Since "smoke.op" isn't a built-in tap name,
  // tap won't route automatically — for THIS test we install our own
  // _activeTap via metrics.tap directly to verify the call shape.
  var calls = [];
  var savedTap = b.metrics.tap;
  // Spy by reading back via the existing _activeTap-driven counters:
  // simpler approach — use a known built-in tap name.
  b.observability.tap("audit.record",
    { action: "test.action", outcome: "success" },
    function () { return "ok"; });
  var auditCounter = m.metrics.get("framework_audit_events_total");
  check("tap: metrics fired on success path",
        auditCounter.get({ action: "test.action", outcome: "success" }) === 1);
  m.deactivate();
}

function testObservabilityTapMetricsFiresOnFailure() {
  _resetRegistries();
  var m = b.metrics.create();
  var threw = null;
  try {
    b.observability.tap("audit.record",
      { action: "test.action", outcome: "failure" },
      function () { throw new Error("boom"); });
  } catch (e) { threw = e; }
  check("tap: throw propagates after metrics fire", threw && threw.message === "boom");
  var auditCounter = m.metrics.get("framework_audit_events_total");
  check("tap: metrics fired on sync-throw failure path",
        auditCounter.get({ action: "test.action", outcome: "failure" }) === 1);
  m.deactivate();
}

async function testObservabilityTapMetricsFiresOnAsyncRejection() {
  _resetRegistries();
  var m = b.metrics.create();
  var threw = null;
  try {
    await b.observability.tap("audit.record",
      { action: "test.action", outcome: "failure" },
      function () { return Promise.reject(new Error("async-boom")); });
  } catch (e) { threw = e; }
  check("tap: rejection propagates after metrics fire",
        threw && threw.message === "async-boom");
  var auditCounter = m.metrics.get("framework_audit_events_total");
  check("tap: metrics fired on async-reject failure path",
        auditCounter.get({ action: "test.action", outcome: "failure" }) === 1);
  m.deactivate();
}

function testObservabilityTapTracingProducesSpan() {
  _resetRegistries();
  var fake = _makeFakeOtelApi();
  b.tracing._setOtelForTest(fake);
  var t = b.tracing.create();
  b.observability.tap("smoke.span",
    { foo: "bar" },
    function () { return 1; });
  check("tap: tracing produced 1 span",          fake._spans.length === 1);
  check("tap: span name matches tap name",       fake._spans[0]._name === "smoke.span");
  check("tap: span attrs include passed attrs",  fake._spans[0]._attrs.foo === "bar");
  t.deactivate();
}

function testObservabilityEventRoutesIntoMetricsOnly() {
  _resetRegistries();
  var m = b.metrics.create();
  // event() = pure metrics tap, no span. Use a built-in tap name so
  // we can verify it routed.
  b.observability.event("queue.enqueue", 1, { queueName: "outbox" });
  var counter = m.metrics.get("framework_queue_enqueue_total");
  check("event: metrics counter incremented",
        counter.get({ queueName: "outbox" }) === 1);
  m.deactivate();
}

function testObservabilityEventNoOpWhenNoRegistry() {
  _resetRegistries();
  var threw = null;
  try { b.observability.event("anything", 1, { a: 1 }); }
  catch (e) { threw = e; }
  check("event: no-op without registry — no throw", threw === null);
}

function testObservabilityTapRejectsBadFn() {
  _resetRegistries();
  var threw = null;
  try { b.observability.tap("smoke", "not-a-function"); }
  catch (e) { threw = e; }
  check("tap: rejects non-function fn", threw && /must be a function/.test(threw.message));
}

function testObservabilityTapRejectsBadName() {
  _resetRegistries();
  var threwUndef = null;
  try { b.observability.tap(undefined, function () {}); }
  catch (e) { threwUndef = e; }
  check("tap: rejects undefined name (Tier A)",
        threwUndef instanceof TypeError && /name must be/.test(threwUndef.message));
  var threwEmpty = null;
  try { b.observability.tap("", function () {}); }
  catch (e) { threwEmpty = e; }
  check("tap: rejects empty-string name", threwEmpty instanceof TypeError);
  var threwNumeric = null;
  try { b.observability.tap(42, function () {}); }
  catch (e) { threwNumeric = e; }
  check("tap: rejects number name", threwNumeric instanceof TypeError);
}

function testObservabilityEventDropsBadName() {
  _resetRegistries();
  var m = b.metrics.create();
  var threw = null;
  try {
    b.observability.event(undefined, 1, { x: 1 });
    b.observability.event("", 1);
    b.observability.event(null);
  } catch (e) { threw = e; }
  check("event: silently drops malformed name (Tier B)", threw === null);
  m.deactivate();
}

async function run() {
  testObservabilitySurface();
  testObservabilityTapRunsFnWithoutRegistries();
  testObservabilityTapReturnsValue();
  await testObservabilityTapAsyncReturn();
  testObservabilityTapMetricsFiresOnSuccess();
  testObservabilityTapMetricsFiresOnFailure();
  await testObservabilityTapMetricsFiresOnAsyncRejection();
  testObservabilityTapTracingProducesSpan();
  testObservabilityEventRoutesIntoMetricsOnly();
  testObservabilityEventNoOpWhenNoRegistry();
  testObservabilityTapRejectsBadFn();
  testObservabilityTapRejectsBadName();
  testObservabilityEventDropsBadName();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("observability tests passed"); process.exit(0); },
    function (e) { console.error(e); process.exit(1); }
  );
}
