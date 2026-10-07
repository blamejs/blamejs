// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.nis2.report
 * @nav    Compliance
 * @title  NIS2 Report
 * @slug   nis2-report
 *
 * @intro
 *   NIS2 incident reporting on the clocks the directive sets: an early
 *   warning within 24 hours of becoming aware, a notification within 72, and
 *   a final report within one month. Those deadlines are fixed here rather
 *   than configured, because they are the directive's and not the
 *   deployment's.
 *
 *   An entity is registered with its NIS2 identifier, its Article 3
 *   classification as essential or important, and its sector annex, since a
 *   CSIRT submission is rejected without them. Each stage records what is
 *   known at that point and can submit the envelope to the CSIRT endpoint in
 *   the same call, so the record and the submission do not drift apart.
 *
 *   The clock runs from <code>detectedAt</code>, when the entity became aware,
 *   rather than from when the incident was entered, which is what the
 *   directive's "within 24 hours of becoming aware" means.
 *   <code>status()</code> answers across the register rather than per
 *   incident: how many are open, how many closed, and how many have passed
 *   each of the three deadlines. That is the number an operator reports
 *   upward; which stage one incident owes next comes from
 *   <code>get(id)</code>.
 *
 * @card
 *   NIS2 incident reporting on the directive's 24-hour, 72-hour and one-month
 *   clocks, with the entity's Article 3 classification and sector annex
 *   carried into each CSIRT submission.
 */

var C = require("./constants");
var defineClass = require("./framework-error").defineClass;
var lazyRequire = require("./lazy-require");
var validateOpts = require("./validate-opts");

var incidentReport = lazyRequire(function () { return require("./incident-report"); });
var audit = lazyRequire(function () { return require("./audit"); });

var Nis2ReportError = defineClass("Nis2ReportError", { alwaysPermanent: true });

var VALID_ENTITY_TYPES = Object.freeze({ essential: 1, important: 1 });

/**
 * @primitive b.nis2.report.create
 * @signature b.nis2.report.create(opts)
 * @since     0.8.44
 * @status    stable
 * @compliance gdpr, soc2
 * @related   b.incident.report.create, b.compliance.current
 *
 * Open NIS2 reporting for one registered entity. `entityId`, `entityType` and
 * `sectorAnnex` are required: an `entityType` outside `essential` and
 * `important` is refused, since Article 3 admits no third class.
 *
 * The returned reporter answers `open`, `earlyWarning`, `notification` and
 * `finalReport`, plus `get`, `list` and `status`. Each stage records the
 * fields known at that point, and passing `submit: true` also sends the
 * envelope to `csirtEndpoint` through `httpClient`, answering with both the
 * stored `record` and the `submitted` result.
 *
 * The deadlines come from the directive and are not options: 24 hours for the
 * early warning, 72 for the notification and 30 days for the final report, all
 * measured from `detectedAt`, which `open` requires and does not default.
 *
 * @opts
 *   entityId:      string,   // required; the NIS2 registration identifier
 *   entityType:    string,   // required; "essential" or "important"
 *   sectorAnnex:   string,   // required; e.g. "I.6", "II.6"
 *   csirtEndpoint: string,   // where a submitted envelope is sent
 *   httpClient:    object,   // client used for the submission
 *   persist:       object,   // store for the incident records
 *   now:           object,   // function returning epoch ms; for tests
 *   audit:         object,   // audit instance, or false to stay silent
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var nis2 = b.nis2.report.create({
 *     entityId:    "DE-1234",
 *     entityType:  "essential",
 *     sectorAnnex: "I.6",
 *   });
 *   var opened = await nis2.open({
 *     detectedAt: Date.now(),      // required; every deadline runs from here
 *     scope:      "billing-api",
 *     summary:    "Unauthorized access detected",
 *     impact:     "confidentiality",
 *   });
 *   await nis2.earlyWarning(opened.id, { significant: true });
 *   nis2.status();                 // → { total, open, closed, late: { … } }
 */
function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "audit", "persist", "httpClient", "csirtEndpoint",
    "entityId", "entityType", "sectorAnnex", "now",
  ], "nis2.report");

  validateOpts.requireNonEmptyString(opts.entityId,
    "nis2.report.create: opts.entityId is required (NIS2 registration ID)",
    Nis2ReportError, "nis2-report/bad-entity-id");
  if (!Object.prototype.hasOwnProperty.call(VALID_ENTITY_TYPES, opts.entityType)) {
    throw new Nis2ReportError("nis2-report/bad-entity-type",
      "nis2.report.create: opts.entityType must be 'essential' or 'important' (NIS2 Article 3 classification)");
  }
  validateOpts.requireNonEmptyString(opts.sectorAnnex,
    "nis2.report.create: opts.sectorAnnex is required (e.g. 'I.6' for drinking water, 'II.6' for digital-providers)",
    Nis2ReportError, "nis2-report/bad-sector");
  var entityId = opts.entityId;
  var entityType = opts.entityType;
  var sectorAnnex = opts.sectorAnnex;
  var csirtEndpoint = opts.csirtEndpoint || null;
  var httpClient = opts.httpClient || null;

  var ir = incidentReport().create({
    audit:    opts.audit,
    persist:  opts.persist,
    now:      opts.now,
    deadlines: {
      initial:      C.TIME.hours(24),
      intermediate: C.TIME.hours(72),
      final:        C.TIME.days(30),
    },
  });

  var _emitAudit = audit().namespaced("nis2.report", opts.audit);

  async function _submitToCsirt(payload) {
    if (!csirtEndpoint || !httpClient) {
      _emitAudit("submit_skipped", "warning", { reason: "no-endpoint-or-client" });
      return { submitted: false, reason: "no-endpoint-or-client" };
    }
    try {
      var res = await httpClient.request({
        url: csirtEndpoint, method: "POST",
        headers: { "Content-Type": "application/json" },
        body: Buffer.from(JSON.stringify(payload), "utf8"),
        responseMode: "always-resolve",
      });
      var ok = res.statusCode >= 200 && res.statusCode < 300;
      _emitAudit("submitted", ok ? "success" : "failure", { statusCode: res.statusCode });
      return { submitted: ok, statusCode: res.statusCode };
    } catch (e) {
      _emitAudit("submit_failed", "failure", { error: (e && e.message) || String(e) });
      return { submitted: false, error: (e && e.message) || String(e) };
    }
  }

  function _envelope(stage, incident, fields) {
    return {
      directive:    "(EU) 2022/2555",
      article:      "23",
      stage:        stage,
      entity:       { id: entityId, type: entityType, sector: sectorAnnex },
      incident: {
        id:          incident.id,
        detected_at: new Date(incident.detectedAt).toISOString(),
        scope:       incident.scope,
        summary:     incident.summary,
        impact:      incident.impact,
      },
      fields: fields || {},
    };
  }

  async function open(spec) {
    spec = Object.assign({}, spec || {}, { regime: "nis2" });
    var rec = await ir.open(spec);
    _emitAudit("opened", "success", { incidentId: rec.id, entityId: entityId, entityType: entityType });
    return rec;
  }

  async function earlyWarning(incidentId, fields) {
    var rec = await ir.recordInitial(incidentId, fields || {});
    var result = { record: rec, submitted: null };
    if (fields && fields.submit === true) {
      result.submitted = await _submitToCsirt(_envelope("early-warning", rec, fields));
    }
    return result;
  }
  async function notification(incidentId, fields) {
    var rec = await ir.recordIntermediate(incidentId, fields || {});
    var result = { record: rec, submitted: null };
    if (fields && fields.submit === true) {
      result.submitted = await _submitToCsirt(_envelope("notification", rec, fields));
    }
    return result;
  }
  async function finalReport(incidentId, fields) {
    var rec = await ir.recordFinal(incidentId, fields || {});
    var result = { record: rec, submitted: null };
    if (fields && fields.submit === true) {
      result.submitted = await _submitToCsirt(_envelope("final", rec, fields));
    }
    return result;
  }

  return {
    open:           open,
    earlyWarning:   earlyWarning,
    notification:   notification,
    finalReport:    finalReport,
    get:            function (id) { return ir.get(id); },
    list:           function ()   { return ir.list(); },
    status:         function ()   { return ir.status(); },
    entityId:       entityId,
    entityType:     entityType,
    sectorAnnex:    sectorAnnex,
  };
}

module.exports = {
  create:             create,
  Nis2ReportError:    Nis2ReportError,
  VALID_ENTITY_TYPES: Object.keys(VALID_ENTITY_TYPES),
};
