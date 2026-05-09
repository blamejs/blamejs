"use strict";
/**
 * b.auditDailyReview — PCI DSS 4.0 Req 10.4.1.1 daily-review primitive.
 *
 * PCI DSS 4.0 Req 10.4.1.1 (mandatory effective 2025-03-31) requires
 * automated mechanisms to review:
 *   - All security event logs
 *   - Logs of components storing/processing/transmitting CHD/SAD
 *   - Logs of critical system components
 *   - Logs of servers/system components performing security functions
 *
 * The daily review must surface anomalies and exceptions for follow-up.
 * The framework primitive provides the scheduling, query, classification,
 * and notify wiring; the operator supplies the notify channel + any
 * post-review workflow.
 *
 * Adjacent regulatory uses:
 *   - HIPAA §164.308(a)(1)(ii)(D) — regular review of activity records
 *   - SOX §302/§404 — quarterly self-attestation that audit logs were
 *     reviewed
 *   - SOC 2 CC7.2 — anomaly identification and response
 *   - GDPR Art. 32 — ongoing security testing/evaluation
 *
 *   var review = b.auditDailyReview.create({
 *     audit:             b.audit,
 *     scheduler:         b.scheduler,
 *     lookbackHours:     24,
 *     severityThreshold: "warning",   // emit notify if any event ≥ threshold
 *     posture:           "pci-dss",
 *     cron:              "0 6 * * *", // 06:00 UTC daily
 *     notify:            async function (summary) { ... },
 *   });
 *   await review.start();
 *
 *   // On-demand:
 *   var summary = await review.run();
 *   review.list();        // → array of past run summaries (capped buffer)
 *   review.lastRun();     // → last summary or null
 *   review.schedule();    // → cron expr in effect
 *   review.stop();        // detaches from scheduler
 *
 * Severity classification — events get tagged by severity from their
 * outcome + action prefix:
 *
 *   denied / failure outcomes  → "warning"
 *   action prefix in
 *     ["auth.fail*", "audit.read", "audit.tamper*",
 *      "csrf.bad_*", "ato.*", "honeytoken.tripped",
 *      "compliance.posture.set_rejected", "audit.actor_binding.violation",
 *      "ddl.change.applied"]                              → "alert"
 *   action prefix in
 *     ["audit.tamper*", "vault.aad.unseal_failed",
 *      "config.drift.detected", "vendor.integrity.tampered",
 *      "ato.killSwitch.tripped"]                          → "critical"
 *
 * Operators with a richer classifier wire opts.classify(event) → severity.
 *
 * Audit emission:
 *   audit.daily_review.completed  — every run() completion
 *   audit.daily_review.notified   — when notify() was triggered
 *   audit.daily_review.notify_failed — notify() rejected/threw
 *   audit.daily_review.scheduled  — start() armed the cron
 *   audit.daily_review.stopped    — stop() torn down
 */

var validateOpts = require("./validate-opts");
var C = require("./constants");
var { AuditDailyReviewError } = require("./framework-error");

var SEVERITY_ORDER = ["info", "notice", "warning", "alert", "critical"];

var ALERT_PATTERNS = [
  /^auth\.(fail|failed|locked|denied|invalid)/,
  /^audit\.read$/,
  /^audit\.tamper/,
  /^csrf\.bad_/,
  /^ato\./,
  /^honeytoken\.tripped/,
  /^compliance\.posture\.set_rejected/,
  /^audit\.actor_binding\.violation/,
  /^ddl\.change\.applied/,
  /^breakglass\./,
];

var CRITICAL_PATTERNS = [
  /^audit\.tamper/,
  /^vault\.aad\.unseal_failed/,
  /^config\.drift\.detected/,
  /^vendor\.integrity\.tampered/,
  /^ato\.killSwitch\.tripped/,
];

var POSTURES_REQUIRING_NOTIFY = ["pci-dss", "hipaa", "sox", "soc2"];

function _defaultClassify(event) {
  if (!event || typeof event !== "object" || typeof event.action !== "string") {
    return "info";
  }
  var action = event.action;
  for (var i = 0; i < CRITICAL_PATTERNS.length; i++) {
    if (CRITICAL_PATTERNS[i].test(action)) return "critical";
  }
  for (var j = 0; j < ALERT_PATTERNS.length; j++) {
    if (ALERT_PATTERNS[j].test(action)) return "alert";
  }
  if (event.outcome === "denied" || event.outcome === "failure") return "warning";
  return "info";
}

function _severityAtLeast(severity, threshold) {
  var sIdx = SEVERITY_ORDER.indexOf(severity);
  var tIdx = SEVERITY_ORDER.indexOf(threshold);
  if (sIdx === -1 || tIdx === -1) return false;
  return sIdx >= tIdx;
}

function _err(code, msg) {
  return new AuditDailyReviewError(code, msg);
}

function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "audit", "scheduler", "lookbackHours", "severityThreshold",
    "posture", "cron", "notify", "classify", "queryLimit", "historyLimit",
    "now",
  ], "auditDailyReview.create");

  validateOpts.auditShape(opts.audit, "auditDailyReview",
    AuditDailyReviewError, "auditDailyReview/bad-audit");
  if (!opts.audit) {
    throw _err("auditDailyReview/audit-required",
      "auditDailyReview.create: opts.audit is required (must expose query() / safeEmit())");
  }
  if (typeof opts.audit.query !== "function") {
    throw _err("auditDailyReview/audit-query-missing",
      "auditDailyReview.create: opts.audit.query must be a function");
  }
  validateOpts.optionalFunction(opts.notify,
    "auditDailyReview: notify", AuditDailyReviewError, "auditDailyReview/bad-notify");
  validateOpts.optionalFunction(opts.classify,
    "auditDailyReview: classify", AuditDailyReviewError, "auditDailyReview/bad-classify");
  validateOpts.optionalFunction(opts.now,
    "auditDailyReview: now", AuditDailyReviewError, "auditDailyReview/bad-now");
  validateOpts.optionalNonEmptyString(opts.posture,
    "auditDailyReview: posture", AuditDailyReviewError, "auditDailyReview/bad-posture");
  validateOpts.optionalNonEmptyString(opts.cron,
    "auditDailyReview: cron", AuditDailyReviewError, "auditDailyReview/bad-cron");
  validateOpts.optionalPositiveInt(opts.queryLimit,
    "auditDailyReview: queryLimit", AuditDailyReviewError, "auditDailyReview/bad-querylimit");
  validateOpts.optionalPositiveInt(opts.historyLimit,
    "auditDailyReview: historyLimit", AuditDailyReviewError, "auditDailyReview/bad-historylimit");

  // lookbackHours — default 24 per PCI DSS 4.0 daily cadence. Caller can
  // pass weekly / monthly via larger numbers.
  var lookbackHours = 24; // allow:raw-byte-literal — lookback in HOURS, not bytes
  if (opts.lookbackHours !== undefined) {
    if (typeof opts.lookbackHours !== "number" || !isFinite(opts.lookbackHours) ||
        opts.lookbackHours <= 0) {
      throw _err("auditDailyReview/bad-lookback",
        "auditDailyReview.create: lookbackHours must be a positive finite number");
    }
    lookbackHours = opts.lookbackHours;
  }

  var severityThreshold = opts.severityThreshold || "warning";
  if (SEVERITY_ORDER.indexOf(severityThreshold) === -1) {
    throw _err("auditDailyReview/bad-severity",
      "auditDailyReview.create: severityThreshold must be one of " +
      SEVERITY_ORDER.join(", "));
  }

  var posture = opts.posture || null;
  if (posture && POSTURES_REQUIRING_NOTIFY.indexOf(posture) !== -1 && !opts.notify) {
    throw _err("auditDailyReview/notify-required-under-posture",
      "auditDailyReview.create: posture '" + posture + "' requires notify callback " +
      "(PCI DSS 10.4.1.1 / HIPAA §164.308(a)(1)(ii)(D) demand a follow-up channel)");
  }

  var cron = opts.cron || "0 6 * * *";   // 06:00 UTC daily
  var queryLimit = opts.queryLimit || 10000;                                    // allow:raw-byte-literal — operator-tunable result cap, count not bytes
  var historyLimit = opts.historyLimit || 30;                                   // allow:raw-byte-literal — bounded history buffer (count, not bytes)
  var classify = typeof opts.classify === "function" ? opts.classify : _defaultClassify;
  var now = typeof opts.now === "function" ? opts.now : Date.now;
  var auditMod = opts.audit;
  var notify = typeof opts.notify === "function" ? opts.notify : null;
  var schedulerMod = opts.scheduler || null;

  var history = [];
  var taskName = "blamejs.auditDailyReview." + (posture || "default");
  var armedScheduler = null;

  function _emit(action, metadata, outcome) {
    try {
      auditMod.safeEmit({
        action:   action,
        outcome:  outcome || "success",
        metadata: metadata || {},
      });
    } catch (_e) { /* audit best-effort */ }
  }

  async function run() {
    var startedAt = now();
    var fromMs = startedAt - C.TIME.hours(lookbackHours);
    var rows;
    try {
      rows = await auditMod.query({
        from:  fromMs,
        to:    startedAt,
        limit: queryLimit,
      });
    } catch (e) {
      _emit("audit.daily_review.failed", {
        reason: (e && e.message) || String(e),
        lookbackHours: lookbackHours,
      }, "failure");
      throw _err("auditDailyReview/query-failed",
        "auditDailyReview.run: audit.query failed: " + ((e && e.message) || String(e)));
    }

    var bySeverity = { info: 0, notice: 0, warning: 0, alert: 0, critical: 0 };
    var byOutcome  = { success: 0, failure: 0, denied: 0, other: 0 };
    var byNamespace = Object.create(null);
    var thresholdHits = [];
    for (var i = 0; i < rows.length; i++) {
      var r = rows[i];
      var sev = classify(r);
      if (bySeverity[sev] === undefined) bySeverity[sev] = 0;
      bySeverity[sev]++;

      var oc = r && r.outcome;
      if (oc === "success" || oc === "failure" || oc === "denied") byOutcome[oc]++;
      else byOutcome.other++;

      var ns = (r && typeof r.action === "string") ? r.action.split(".")[0] : "unknown";
      byNamespace[ns] = (byNamespace[ns] || 0) + 1;

      if (_severityAtLeast(sev, severityThreshold)) {
        thresholdHits.push({
          action:   r.action,
          outcome:  r.outcome,
          severity: sev,
          recordedAt: r.recordedAt,
          actorUserId: r.actorUserId || null,
          requestId: r.requestId || null,
        });
      }
    }

    var summary = {
      runAt:           new Date(startedAt).toISOString(),
      lookbackHours:   lookbackHours,
      windowFromMs:    fromMs,
      windowToMs:      startedAt,
      totalEvents:     rows.length,
      bySeverity:      bySeverity,
      byOutcome:       byOutcome,
      byNamespace:     byNamespace,
      severityThreshold: severityThreshold,
      thresholdHits:   thresholdHits,
      hitCount:        thresholdHits.length,
      durationMs:      now() - startedAt,
      posture:         posture,
    };

    history.push(summary);
    if (history.length > historyLimit) history.splice(0, history.length - historyLimit);

    _emit("audit.daily_review.completed", {
      lookbackHours: lookbackHours,
      totalEvents:   summary.totalEvents,
      hitCount:      summary.hitCount,
      durationMs:    summary.durationMs,
      posture:       posture,
    });

    if (notify && thresholdHits.length > 0) {
      try {
        await notify(summary);
        _emit("audit.daily_review.notified", {
          hitCount: thresholdHits.length, posture: posture,
        });
      } catch (e) {
        _emit("audit.daily_review.notify_failed", {
          reason: (e && e.message) || String(e),
          hitCount: thresholdHits.length, posture: posture,
        }, "failure");
        // Don't throw — the daily review completed, only notify failed.
        // Operators read audit.daily_review.notify_failed to chase down
        // their notify-channel outage.
      }
    }

    return summary;
  }

  function lastRun() {
    return history.length > 0 ? history[history.length - 1] : null;
  }

  function list() {
    return history.slice();
  }

  function schedule() {
    return cron;
  }

  async function start() {
    if (!schedulerMod) {
      throw _err("auditDailyReview/no-scheduler",
        "auditDailyReview.start: opts.scheduler is required to arm the cron firing — " +
        "operators without a scheduler call run() on their own cadence");
    }
    if (armedScheduler) return;
    armedScheduler = schedulerMod;
    armedScheduler.schedule({
      name: taskName,
      cron: cron,
      run:  run,
    });
    if (typeof armedScheduler.start === "function") {
      // Scheduler.start() is idempotent — safe to call when the scheduler
      // was already armed by other tasks.
      try { await armedScheduler.start(); } catch (_e) { /* operator-controlled */ }
    }
    _emit("audit.daily_review.scheduled", {
      cron: cron, taskName: taskName, posture: posture,
    });
  }

  async function stop() {
    if (!armedScheduler) return;
    armedScheduler = null;
    _emit("audit.daily_review.stopped", { taskName: taskName, posture: posture });
  }

  return {
    run:        run,
    list:       list,
    lastRun:    lastRun,
    schedule:   schedule,
    start:      start,
    stop:       stop,
    classify:   classify,
    posture:    posture,
    cron:       cron,
    severityThreshold: severityThreshold,
    lookbackHours:     lookbackHours,
  };
}

module.exports = {
  create: create,
  SEVERITY_ORDER:           SEVERITY_ORDER,
  ALERT_PATTERNS:           ALERT_PATTERNS,
  CRITICAL_PATTERNS:        CRITICAL_PATTERNS,
  POSTURES_REQUIRING_NOTIFY: POSTURES_REQUIRING_NOTIFY,
  AuditDailyReviewError:    AuditDailyReviewError,
};
