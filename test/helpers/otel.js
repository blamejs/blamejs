"use strict";
/**
 * Fake @opentelemetry/api for tests that need to verify the framework
 * routes through the real-OTel path instead of the pass-through.
 *
 * Implements the minimal subset b.tracing actually calls:
 *   trace.getTracer().startSpan(name, opts) → span
 *   trace.getActiveSpan() → span | null
 *   trace.setSpan(ctx, span) → ctx
 *   context.active() / context.with(ctx, fn)
 *   SpanKind enum
 *
 * The returned object has `_spans` (array of created spans) and
 * `_activeSpan()` for assertion access — matches what
 * tracing.test.js + observability.test.js previously rolled by hand.
 */

function makeFakeOtelApi() {
  var spans = [];
  var activeSpan = null;
  function makeSpan(name) {
    return {
      _name: name, _attrs: {}, _events: [], _exceptions: [], _ended: false, _status: null,
      spanContext:     function () { return { traceId: "a".repeat(32), spanId: "b".repeat(16), traceFlags: 1, isRemote: false }; },
      setAttribute:    function (k, v) { this._attrs[k] = v; return this; },
      setAttributes:   function (a) { Object.assign(this._attrs, a || {}); return this; },
      addEvent:        function (n) { this._events.push(n); return this; },
      recordException: function (e) { this._exceptions.push(e); return this; },
      setStatus:       function (st) { this._status = st; return this; },
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
      setSpan:       function (_ctx, span) { return { _activeSpan: span }; },
    },
    context: {
      active: function () { return { _stub: true }; },
      with: function (ctx, fn) {
        var prev = activeSpan;
        if (ctx && ctx._activeSpan) activeSpan = ctx._activeSpan;
        try { return fn(); } finally { activeSpan = prev; }
      },
    },
    SpanKind:    { INTERNAL: 0, SERVER: 1, CLIENT: 2, PRODUCER: 3, CONSUMER: 4 },
    _spans:      spans,
    _activeSpan: function () { return activeSpan; },
  };
}

module.exports = { makeFakeOtelApi: makeFakeOtelApi };
