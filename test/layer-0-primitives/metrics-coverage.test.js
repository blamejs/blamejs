// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.metrics — error-path + adversarial-input coverage for the core
 * registry (counter / gauge / histogram / exposition / requestMiddleware
 * / tap dispatch) and the snapshot + shadow-registry surfaces.
 *
 * The happy path is exercised by the smoke + integration suites; this
 * file drives the validation refusals, resource-limit rejections,
 * wrong-state / unknown-command branches, and typed-error paths those
 * suites never reach. Every assertion drives the public API
 * (`b.metrics.*`) — never a private internal.
 *
 * Run standalone: `node test/layer-0-primitives/metrics-coverage.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

var BACKSLASH = String.fromCharCode(92);
var NEWLINE   = String.fromCharCode(10);

// Shared throw-capture helpers — one shape, reused across every refusal
// assertion (audit-existing: mirrors the expectThrow shape the sibling
// metrics-snapshot / metrics-shadow-registry tests already use).
function expectCode(label, fn, codeMatch) {
  var threw = null;
  try { fn(); } catch (e) { threw = e; }
  check(label, !!(threw && (threw.code || "").indexOf(codeMatch) !== -1));
}
function expectThrowMsg(label, fn, re) {
  var threw = null;
  try { fn(); } catch (e) { threw = e; }
  check(label, !!(threw && re.test(threw.message || "")));
}

// ---- create() opt validation (entry-point / throw tier) ----

function testCreateRejectsUnknownOpt() {
  expectThrowMsg("create: unknown opt rejected",
    function () { b.metrics.create({ bogus: 1 }); },
    /unknown option/);
}

function testCreateRejectsBadCardinalityCap() {
  expectCode("create: cardinalityCap 0 rejected",
    function () { b.metrics.create({ labelCardinalityCap: 0 }); }, "metrics/bad-opt");
  expectCode("create: cardinalityCap negative rejected",
    function () { b.metrics.create({ labelCardinalityCap: -1 }); }, "metrics/bad-opt");
  expectCode("create: cardinalityCap non-integer rejected",
    function () { b.metrics.create({ labelCardinalityCap: 1.5 }); }, "metrics/bad-opt");
  expectCode("create: cardinalityCap Infinity rejected",
    function () { b.metrics.create({ labelCardinalityCap: Infinity }); }, "metrics/bad-opt");
}

function testCreateRejectsBadDefaultLabelName() {
  expectCode("create: invalid defaultLabels name rejected",
    function () { b.metrics.create({ defaultLabels: { "bad-name": "x" } }); }, "metrics/bad-label");
}

// ---- metric-name / label-name validation ----

function testMetricNameValidation() {
  var m = b.metrics.create();
  expectCode("counter: hyphen in name rejected",
    function () { m.counter("bad-name!", {}); }, "metrics/bad-name");
  expectCode("counter: empty name rejected",
    function () { m.counter("", {}); }, "metrics/bad-name");
  expectCode("counter: non-string name rejected",
    function () { m.counter(123, {}); }, "metrics/bad-name");
  expectCode("counter: over-long name rejected",
    function () { m.counter(new Array(250).join("x"), {}); }, "metrics/bad-name");
  expectCode("gauge: bad labelName rejected",
    function () { m.gauge("okg", { labelNames: ["bad-name"] }); }, "metrics/bad-label");
  expectCode("histogram: bad labelName rejected",
    function () { m.histogram("okh", { labelNames: ["also bad"] }); }, "metrics/bad-label");
}

function testDuplicateRegistration() {
  var m = b.metrics.create();
  m.counter("dup_total", {});
  expectCode("counter: duplicate name rejected",
    function () { m.counter("dup_total", {}); }, "metrics/duplicate");
  // A gauge re-using a counter's fully-qualified name also collides.
  expectCode("gauge: collides with existing counter name",
    function () { m.gauge("dup_total", {}); }, "metrics/duplicate");
}

// ---- counter error branches ----

function testCounterDecrementRefused() {
  var m = b.metrics.create();
  var c = m.counter("reqs_total", {});
  expectCode("counter.inc: negative value refused",
    function () { c.inc(-1); }, "metrics/counter-decrement");
  expectCode("counter.inc: negative with labels refused",
    function () { m.counter("reqs2_total", { labelNames: ["a"] }).inc({ a: "x" }, -5); },
    "metrics/counter-decrement");
}

function testLabelResolution() {
  var m = b.metrics.create();
  var c = m.counter("http_total", { labelNames: ["method"] });
  expectCode("inc: undeclared label rejected",
    function () { c.inc({ method: "GET", route: "/x" }); }, "metrics/undeclared-label");
  expectCode("inc: missing required label rejected",
    function () { c.inc({}); }, "metrics/missing-label");
  // Declared + present → succeeds; get reflects the increment.
  c.inc({ method: "GET" }, 3);
  check("inc: declared label increments", c.get({ method: "GET" }) === 3);
  check("get: unknown labelset defaults to 0", c.get({ method: "POST" }) === 0);
}

function testCardinalityCapDropsSilently() {
  var m = b.metrics.create({ namespace: "cap", labelCardinalityCap: 2 });
  var c = m.counter("k_total", { labelNames: ["id"] });
  c.inc({ id: "a" });
  c.inc({ id: "b" });
  c.inc({ id: "c" });   // third distinct label set — over cap, dropped
  check("cap: first labelset kept",  c.get({ id: "a" }) === 1);
  check("cap: second labelset kept", c.get({ id: "b" }) === 1);
  check("cap: over-cap labelset dropped (stays 0)", c.get({ id: "c" }) === 0);
  // An already-seen labelset still increments after the cap is hit.
  c.inc({ id: "a" });
  check("cap: existing labelset still increments post-cap", c.get({ id: "a" }) === 2);
  // Exposition renders only the retained series (no third series line).
  var out = m.exposition();
  check("cap: over-cap series absent from exposition",
    out.indexOf('cap_k_total{id="c"}') === -1);
}

// ---- gauge error branches ----

function testGaugeBadValueRefused() {
  var m = b.metrics.create();
  var g = m.gauge("temp", {});
  expectCode("gauge.set: NaN refused",
    function () { g.set(NaN); }, "metrics/gauge-bad-value");
  expectCode("gauge.set: missing value (undefined) refused",
    function () { g.set({}); }, "metrics/gauge-bad-value");
  expectCode("gauge.set: string value refused",
    function () { g.set("hot"); }, "metrics/gauge-bad-value");
  // inc / dec adjust an existing series; get returns the running value.
  g.set(10);
  g.inc(5);
  g.dec(3);
  check("gauge.set/inc/dec compose", g.get() === 12);
}

// ---- histogram error branches ----

function testHistogramBadBuckets() {
  var m = b.metrics.create();
  expectCode("histogram: empty buckets refused",
    function () { m.histogram("h1", { buckets: [] }); }, "metrics/bad-buckets");
  expectCode("histogram: non-array buckets refused",
    function () { m.histogram("h2", { buckets: "nope" }); }, "metrics/bad-buckets");
  expectCode("histogram: non-numeric bucket boundary refused",
    function () { m.histogram("h3", { buckets: [1, "x", 3] }); }, "metrics/bad-buckets");
  expectCode("histogram: NaN bucket boundary refused",
    function () { m.histogram("h4", { buckets: [1, NaN] }); }, "metrics/bad-buckets");
  expectCode("histogram: non-ascending buckets refused (equal)",
    function () { m.histogram("h5", { buckets: [1, 1] }); }, "metrics/bad-buckets");
  expectCode("histogram: non-ascending buckets refused (descending)",
    function () { m.histogram("h6", { buckets: [2, 1] }); }, "metrics/bad-buckets");
}

function testHistogramObserveBadValue() {
  var m = b.metrics.create();
  var h = m.histogram("lat", { buckets: [0.5, 1] });
  expectCode("histogram.observe: NaN refused",
    function () { h.observe(NaN); }, "metrics/histogram-bad-value");
  expectCode("histogram.observe: string refused",
    function () { h.observe("slow"); }, "metrics/histogram-bad-value");
  // A valid observation lands in the right bucket + the +Inf bucket.
  h.observe(0.1);
  var out = m.exposition();
  check("histogram: le bucket rendered", out.indexOf('lat_bucket{le="0.5"} 1') !== -1);
  check("histogram: +Inf bucket rendered", out.indexOf('lat_bucket{le="+Inf"} 1') !== -1);
  check("histogram: count rendered", out.indexOf("lat_count 1") !== -1);
}

// ---- exposition wire-format escaping + content negotiation ----

function testLabelValueEscaping() {
  var m = b.metrics.create({ namespace: "esc" });
  var c = m.counter("k_total", { labelNames: ["p"] });
  c.inc({ p: 'x"y' + NEWLINE + "z" });   // short, non-credential value
  var out = m.exposition();
  var line = out.split(NEWLINE).filter(function (l) { return l.indexOf("esc_k_total{") === 0; })[0] || "";
  check("escape: no raw newline leaks into the exposition line", line.indexOf(NEWLINE) === -1);
  check("escape: double-quote escaped", line.indexOf(BACKSLASH + '"') !== -1);
  check("escape: newline escaped to backslash-n", line.indexOf(BACKSLASH + "n") !== -1);
}

function testExpositionHandlerNegotiation() {
  var m = b.metrics.create();
  m.counter("hits_total", {}).inc();
  var handler = m.expositionHandler();

  function run(accept) {
    var req = b.testing.mockReq({ headers: accept ? { accept: accept } : {} });
    var res = b.testing.mockRes();
    handler(req, res);
    return res._captured();
  }

  var noAccept = run(null);
  check("negotiate: no Accept defaults to Prometheus 0.0.4",
    (noAccept.headers["content-type"] || "").indexOf("version=0.0.4") !== -1);
  check("negotiate: exposition status is 200", noAccept.status === 200);
  check("negotiate: Cache-Control no-store set", noAccept.headers["cache-control"] === "no-store");
  check("negotiate: Content-Length is a byte count", typeof noAccept.headers["content-length"] === "number");

  var om = run("application/openmetrics-text; version=1.0.0");
  check("negotiate: OpenMetrics Accept selects OpenMetrics 1.0.0",
    (om.headers["content-type"] || "").indexOf("openmetrics-text") !== -1);
  check("negotiate: OpenMetrics body carries the # EOF terminator",
    om.body.indexOf("# EOF") !== -1);

  // RFC 9110 weighted negotiation: text/plain q=1 beats openmetrics q=0.
  var weighted = run("text/plain;q=1.0, application/openmetrics-text;q=0");
  check("negotiate: q=0 OpenMetrics loses to q=1 text/plain (Prometheus wins)",
    (weighted.headers["content-type"] || "").indexOf("version=0.0.4") !== -1);
}

// ---- requestMiddleware auto-instrumentation ----

function testRequestMiddlewareCountsAndTimes() {
  var m = b.metrics.create();
  var mw = m.requestMiddleware();
  var req = b.testing.mockReq({ method: "GET", url: "/users?q=1" });
  req.routePattern = "/users/:id";   // matcher-set route template
  var res = b.testing.mockRes();
  var nextCalled = false;
  mw(req, res, function () { nextCalled = true; });
  res.writeHead(200);
  res.end("body");
  check("middleware: next() invoked", nextCalled === true);
  var reqs = m.metrics.get("framework_http_requests_total");
  check("middleware: counts by route TEMPLATE not raw path",
    reqs.get({ method: "GET", route: "/users/:id", status: "200" }) === 1);
  var dur = m.metrics.get("framework_http_request_duration_seconds");
  check("middleware: latency histogram observed",
    dur.values.size === 1);
}

// ---- tap dispatch (global no-op stub + registry-driven handler) ----

function testTapDispatch() {
  b.metrics._resetForTest();
  // Before any registry is active, tap is a zero-cost no-op — never throws.
  var noThrow = true;
  try { b.metrics.tap("audit.record", 1, { action: "x", outcome: "ok" }); }
  catch (_e) { noThrow = false; }
  check("tap: no-op (no throw) before a registry is active", noThrow);

  var m = b.metrics.create();
  b.metrics.tap("audit.record", 2, { action: "login", outcome: "success" });
  check("tap: audit.record routes into framework_audit_events_total",
    m.metrics.get("framework_audit_events_total").get({ action: "login", outcome: "success" }) === 2);

  b.metrics.tap("queue.enqueue", 3, { queueName: "q" });
  check("tap: queue.enqueue raises queue depth gauge",
    m.metrics.get("framework_queue_depth").get({ queueName: "q" }) === 3);
  b.metrics.tap("queue.complete", 1, { queueName: "q" });
  check("tap: queue.complete lowers queue depth gauge",
    m.metrics.get("framework_queue_depth").get({ queueName: "q" }) === 2);

  // Unknown / unsupported tap name falls through the dispatch with no
  // effect — no throw, no metric mutated.
  var before = m.metrics.get("framework_errors_total").values.size;
  var unknownOk = true;
  try { b.metrics.tap("nonexistent.event", 1, {}); } catch (_e) { unknownOk = false; }
  check("tap: unknown command is a silent no-op", unknownOk &&
    m.metrics.get("framework_errors_total").values.size === before);

  // deactivate() releases the global handler → tap is a no-op again.
  m.deactivate();
  var seal = m.metrics.get("framework_vault_seal_total").get();
  b.metrics.tap("vault.seal", 1, {});
  check("tap: no-op after deactivate()",
    m.metrics.get("framework_vault_seal_total").get() === seal);

  b.metrics._resetForTest();
}

// ---- snapshot.startWriter validation (uncovered opt branches) ----

function testSnapshotStartWriterValidation() {
  function baseOpts(extra) {
    var o = { path: "/tmp/metrics-cov.json", intervalMs: 1000, fields: function () { return {}; } };
    var k = Object.keys(extra);
    for (var i = 0; i < k.length; i++) o[k[i]] = extra[k[i]];
    return o;
  }
  expectCode("startWriter: non-registry registry object rejected",
    function () { b.metrics.snapshot.startWriter(baseOpts({ registry: 5 })); },
    "metrics-snapshot/bad-registry");
  expectCode("startWriter: registry without .metrics rejected",
    function () { b.metrics.snapshot.startWriter(baseOpts({ registry: { nope: 1 } })); },
    "metrics-snapshot/bad-registry");
  expectCode("startWriter: negative fileMode rejected",
    function () { b.metrics.snapshot.startWriter(baseOpts({ fileMode: -1 })); },
    "metrics-snapshot/bad-file-mode");
  expectCode("startWriter: fileMode above 0o777 rejected",
    function () { b.metrics.snapshot.startWriter(baseOpts({ fileMode: 0o1000 })); },
    "metrics-snapshot/bad-file-mode");
  expectCode("startWriter: non-integer fileMode rejected",
    function () { b.metrics.snapshot.startWriter(baseOpts({ fileMode: 1.5 })); },
    "metrics-snapshot/bad-file-mode");
}

// ---- shadowRegistry error branches (uncovered) ----

function testShadowRegistryValidation() {
  expectCode("shadow: bad onCardinalityExceeded policy rejected",
    function () { b.metrics.snapshot.shadowRegistry({ namespace: "ns", onCardinalityExceeded: "explode" }); },
    "metrics-shadow/bad-policy");
  expectCode("shadow: negative cardinalityCap rejected",
    function () { b.metrics.snapshot.shadowRegistry({ namespace: "ns", cardinalityCap: -1 }); },
    "metrics-shadow/bad-cap");
  expectCode("shadow: non-integer cardinalityCap rejected",
    function () { b.metrics.snapshot.shadowRegistry({ namespace: "ns", cardinalityCap: 1.5 }); },
    "metrics-shadow/bad-cap");
  expectCode("shadow: empty-string info name rejected",
    function () { b.metrics.snapshot.shadowRegistry({ namespace: "ns", info: [""] }); },
    "metrics-shadow/bad-info");
  expectCode("shadow: non-string counter name rejected",
    function () { b.metrics.snapshot.shadowRegistry({ namespace: "ns", counters: [123] }); },
    "metrics-shadow/bad-counters");
}

function testShadowRegistryGaugeValueRefusal() {
  var sh = b.metrics.snapshot.shadowRegistry({ namespace: "ns", gauges: ["gd"] });
  expectCode("shadow.set: NaN gauge value refused",
    function () { sh.set("gd", NaN); }, "metrics-shadow/bad-gauge-value");
  expectCode("shadow.set: Infinity gauge value refused",
    function () { sh.set("gd", Infinity); }, "metrics-shadow/bad-gauge-value");
  expectCode("shadow.set: string gauge value refused",
    function () { sh.set("gd", "x"); }, "metrics-shadow/bad-gauge-value");
}

function testShadowRegistryDropPolicyAndReset() {
  // Default "drop" policy: over-cap label sets silently dropped, no throw.
  var sh = b.metrics.snapshot.shadowRegistry({
    namespace: "ns", counters: ["hits_total"], cardinalityCap: 2,
  });
  var noThrow = true;
  try {
    sh.inc("hits_total", { id: "a" });
    sh.inc("hits_total", { id: "b" });
    sh.inc("hits_total", { id: "c" });   // over cap — dropped, not thrown
  } catch (_e) { noThrow = false; }
  check("shadow drop-policy: over-cap inc does not throw", noThrow);
  var snap = sh.snapshot();
  check("shadow drop-policy: over-cap series absent",
    snap.counters.hits_total['{"id":"c"}'] === undefined);
  // Non-mirrored names are ignored (setInfo only stores declared names).
  sh.setInfo("not_declared", "x");
  check("shadow: setInfo ignores non-mirrored name",
    sh.snapshot().info.not_declared === undefined);
  // reset() clears all accumulated state.
  sh.reset();
  check("shadow reset: counters cleared",
    Object.keys(sh.snapshot().counters).length === 0);
}

function run() {
  testCreateRejectsUnknownOpt();
  testCreateRejectsBadCardinalityCap();
  testCreateRejectsBadDefaultLabelName();
  testMetricNameValidation();
  testDuplicateRegistration();
  testCounterDecrementRefused();
  testLabelResolution();
  testCardinalityCapDropsSilently();
  testGaugeBadValueRefused();
  testHistogramBadBuckets();
  testHistogramObserveBadValue();
  testLabelValueEscaping();
  testExpositionHandlerNegotiation();
  testRequestMiddlewareCountsAndTimes();
  testTapDispatch();
  testSnapshotStartWriterValidation();
  testShadowRegistryValidation();
  testShadowRegistryGaugeValueRefusal();
  testShadowRegistryDropPolicyAndReset();
}

if (require.main === module) run();
module.exports = { run: run };
