// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Live OTLP trace export: b.observability.otlpExporter against the stack's
 * OpenTelemetry Collector (otel-collector, OTLP/HTTP over TLS on :4318).
 *
 * Two tracers under one resource (the same service.name) with different
 * instrumentation scopes end interleaved spans into one exporter. The
 * collector writes each ExportTraceServiceRequest it accepts to
 * docker/otel/export/otlp-traces.json (the traces pipeline in
 * docker/otel/config.yaml). The test reads that file back and asserts the
 * request carried one resourceSpans for the resource, with one scopeSpans
 * per scope, and every span under the scope of the tracer that ended it.
 * It runs once with the JSON encoding and once with protobuf, since the
 * collector decodes both into the same model.
 *
 * TLS to the collector trusts the test CA through NODE_EXTRA_CA_CERTS,
 * which scripts/test-integration.js exports; verification stays on.
 *
 * Run: node scripts/test-integration.js observability-otlp-traces
 */
var fs         = require("node:fs");
var path       = require("node:path");
var nodeCrypto = require("node:crypto");
var helpers    = require("../helpers");
var b          = helpers.b;
var check      = helpers.check;
var services   = require("../helpers/services");

var EXPORT_FILE = path.join(__dirname, "..", "..", "docker", "otel", "export", "otlp-traces.json");

var SCOPES = [
  { name: "blamejs.test.scope-a", version: "1.0.0" },
  { name: "blamejs.test.scope-b", version: "2.0.0" },
];

function _attr(attrs, key) {
  var hit = (attrs || []).find(function (a) { return a.key === key; });
  return hit && hit.value ? hit.value.stringValue : undefined;
}

// Every exported request line whose spans carry `traceId`, flattened to
// { service, scopes: [{ name, version, spans: [name] }] } per resourceSpans.
function _readBack(traceId) {
  var text;
  try { text = fs.readFileSync(EXPORT_FILE, "utf8"); } catch (_e) { return []; }
  var out = [];
  text.split("\n").forEach(function (line) {
    if (line.indexOf(traceId) === -1) return;
    var req;
    try { req = JSON.parse(line); } catch (_e) { return; }
    (req.resourceSpans || []).forEach(function (rs) {
      var scopes = (rs.scopeSpans || []).map(function (ss) {
        return {
          name:    ss.scope && ss.scope.name,
          version: ss.scope && ss.scope.version,
          spans:   (ss.spans || []).filter(function (s) {
            return String(s.traceId).toLowerCase() === traceId;
          }).map(function (s) { return s.name; }),
        };
      }).filter(function (sc) { return sc.spans.length > 0; });
      if (scopes.length > 0) {
        out.push({ service: _attr(rs.resource && rs.resource.attributes, "service.name"), scopes: scopes });
      }
    });
  });
  return out;
}

async function _leg(encoding) {
  var traceId = nodeCrypto.randomBytes(16).toString("hex");
  var service = "otlp-scope-grouping-" + encoding + "-" + traceId.slice(0, 8);
  var exporter = b.observability.otlpExporter.create({
    endpoint:        services.URLS.otelOtlp + "/v1/traces",
    encoding:        encoding,
    flushIntervalMs: 60000,
    maxAttempts:     2,
    backoffInitialMs: 200,
    audit:           false,
  });
  var tracers = SCOPES.map(function (scope) {
    return b.observability.tracer.create({
      service:  service,
      resource: { "deployment.environment": "integration" },
      scope:    scope,
      onEnd:    function (span) { exporter.queue(span); },
    });
  });
  var plan = [[0, "a-1"], [1, "b-1"], [0, "a-2"], [1, "b-2"], [0, "a-3"]];
  plan.forEach(function (p) {
    tracers[p[0]].start("span-" + p[1], { traceId: traceId }).end();
  });

  var flushed = await exporter.flush();
  await exporter.shutdown();
  check("otlp " + encoding + ": the collector accepted the batch",
    flushed && flushed.sent === plan.length, JSON.stringify(flushed));

  var groups = [];
  await helpers.waitUntil(function () {
    groups = _readBack(traceId);
    var n = 0;
    groups.forEach(function (g) { g.scopes.forEach(function (sc) { n += sc.spans.length; }); });
    return n >= plan.length;
  }, { timeoutMs: 15000, label: "otlp " + encoding + ": the collector wrote the spans to otlp-traces.json" });

  check("otlp " + encoding + ": one resourceSpans for the shared resource",
    groups.length === 1 && groups[0].service === service, JSON.stringify(groups));
  var scopes = groups[0].scopes;
  check("otlp " + encoding + ": one scopeSpans per instrumentation scope",
    scopes.length === SCOPES.length, JSON.stringify(scopes));
  SCOPES.forEach(function (scope, idx) {
    var want = plan.filter(function (p) { return p[0] === idx; })
      .map(function (p) { return "span-" + p[1]; });
    var got = scopes.find(function (sc) { return sc.name === scope.name; });
    check("otlp " + encoding + ": " + scope.name + " carries version " + scope.version,
      got && got.version === scope.version, JSON.stringify(got));
    check("otlp " + encoding + ": " + scope.name + " holds exactly its own spans",
      got && JSON.stringify(got.spans.slice().sort()) === JSON.stringify(want.slice().sort()),
      JSON.stringify(got && got.spans));
  });
}

async function run() {
  await _leg("json");
  await _leg("protobuf");
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); process.exit(0); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
