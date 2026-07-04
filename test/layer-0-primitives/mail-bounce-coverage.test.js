// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * mail-bounce — error / defensive / adversarial branch coverage.
 *
 * Companion to mail-bounce.test.js: that file exercises the happy paths;
 * this one drives every throw, every else, every fallback default, and
 * every fault-injected failure mode across the vendor parsers, the
 * webhook handler middleware, and the RFC 3464 DSN parse/build pair.
 *
 * Run standalone: `node test/layer-0-primitives/mail-bounce-coverage.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var EventEmitter   = require("events").EventEmitter;
var helpers        = require("../helpers");
var b              = helpers.b;
var fs             = helpers.fs;
var os             = helpers.os;
var path           = helpers.path;
var check          = helpers.check;
var setupTestDb    = helpers.setupTestDb;
var teardownTestDb = helpers.teardownTestDb;
var _bodyReq       = helpers._bodyReq;
var _bodyRes       = helpers._bodyRes;

function _waitFinish(res) {
  return new Promise(function (resolve) { res.on("finish", resolve); });
}

// Raw EventEmitter request for tests that need manual data/end/error
// control (multi-chunk overflow, socket error, custom parser wiring).
function _rawReq(headers) {
  var req = new EventEmitter();
  req.headers = headers || {};
  req.socket = { remoteAddress: "127.0.0.1" };
  return req;
}

function _threw(fn) {
  try { fn(); return null; } catch (e) { return e; }
}

// ---- Postmark parser: error + fallback branches ----

async function testPostmarkEmptyPayload() {
  var e1 = _threw(function () { b.mailBounce.parse(null, { vendor: "postmark" }); });
  check("postmark: null payload rejected", e1 && e1.code === "postmark/empty");
  var e2 = _threw(function () { b.mailBounce.parse("nope", { vendor: "postmark" }); });
  check("postmark: non-object payload rejected", e2 && e2.code === "postmark/empty");
}

async function testPostmarkMissingEmail() {
  var e1 = _threw(function () {
    b.mailBounce.parse({ RecordType: "Bounce", Type: "HardBounce" }, { vendor: "postmark" });
  });
  check("postmark: missing Email rejected", e1 && e1.code === "postmark/missing-email");
  var e2 = _threw(function () {
    b.mailBounce.parse({ RecordType: "Bounce", Email: "" }, { vendor: "postmark" });
  });
  check("postmark: empty-string Email rejected", e2 && e2.code === "postmark/missing-email");
}

async function testPostmarkDeliveryDefaults() {
  // No MessageID (→ null) and no DeliveredAt (→ generated ISO timestamp).
  var ev = b.mailBounce.parse({ RecordType: "Delivery", Email: "a@b.com" }, { vendor: "postmark" });
  check("postmark delivery: messageId null when absent", ev.messageId === null);
  check("postmark delivery: subType null", ev.subType === null);
  check("postmark delivery: timestamp defaulted", typeof ev.timestamp === "string" && ev.timestamp.length > 0);
}

async function testPostmarkSpamDescriptionFallback() {
  // No Details, no BouncedAt → reason falls back to Description, timestamp generated.
  var ev = b.mailBounce.parse({ RecordType: "SpamComplaint", Email: "a@b.com", Description: "why" },
                              { vendor: "postmark" });
  check("postmark spam: reason falls back to Description", ev.reason === "why");
  check("postmark spam: timestamp defaulted", typeof ev.timestamp === "string" && ev.timestamp.length > 0);
}

async function testPostmarkBounceTypeFallbacks() {
  // Unrecognized Type string → subType is the lowercased Type.
  var ev1 = b.mailBounce.parse({ RecordType: "Bounce", Type: "WeirdBounce", Email: "a@b.com" },
                               { vendor: "postmark" });
  check("postmark bounce: unknown Type lowercased into subType", ev1.subType === "weirdbounce");

  // Non-string Type → subType "unknown".
  var ev2 = b.mailBounce.parse({ RecordType: "Bounce", Type: 123, Email: "a@b.com" },
                               { vendor: "postmark" });
  check("postmark bounce: non-string Type → unknown", ev2.subType === "unknown");

  // No RecordType at all (!record) still routes through the bounce branch.
  var ev3 = b.mailBounce.parse({ Type: "HardBounce", Email: "a@b.com" }, { vendor: "postmark" });
  check("postmark: absent RecordType routes to bounce", ev3.type === "bounce" && ev3.subType === "hard");

  // SubscriptionChange routes through the bounce branch too.
  var ev4 = b.mailBounce.parse({ RecordType: "SubscriptionChange", Type: "Unsubscribe", Email: "a@b.com" },
                               { vendor: "postmark" });
  check("postmark: SubscriptionChange routes to bounce mapping",
        ev4.type === "complaint" && ev4.subType === "unsubscribe");

  // Bounce timestamp falls back to DeliveredAt when BouncedAt absent.
  var ev5 = b.mailBounce.parse({ RecordType: "Bounce", Type: "HardBounce", Email: "a@b.com",
                                 DeliveredAt: "2026-01-01T00:00:00Z" }, { vendor: "postmark" });
  check("postmark bounce: timestamp falls back to DeliveredAt", ev5.timestamp === "2026-01-01T00:00:00Z");
}

async function testPostmarkUnknownRecord() {
  var e1 = _threw(function () {
    b.mailBounce.parse({ RecordType: "Nope", Email: "a@b.com" }, { vendor: "postmark" });
  });
  check("postmark: unrecognized RecordType rejected", e1 && e1.code === "postmark/unknown-record");
}

// ---- SES parser: error + fallback branches ----

async function testSesEmptyPayload() {
  var e1 = _threw(function () { b.mailBounce.parse(null, { vendor: "ses" }); });
  check("ses: null payload rejected", e1 && e1.code === "ses/empty");
}

async function testSesBadSnsMessageJson() {
  var e1 = _threw(function () {
    b.mailBounce.parse({ Type: "Notification", Message: "{not valid json" }, { vendor: "ses" });
  });
  check("ses: SNS Message not-JSON rejected", e1 && e1.code === "ses/bad-message-json");
}

async function testSesSnsNullMessageTypedError() {
  // A syntactically valid SNS Message of `null` decodes to msg=null. The
  // parser must reject it with a typed MailBounceError (like every other
  // malformed-input path) rather than dereferencing null and throwing a
  // raw TypeError whose V8 message ("Cannot read properties of null...")
  // would leak into the 400 response body.
  var e1 = _threw(function () {
    b.mailBounce.parse({ Type: "Notification", Message: "null" }, { vendor: "ses" });
  });
  check("ses: SNS Message JSON-null → typed MailBounceError",
        e1 instanceof b.mailBounce.MailBounceError);
  check("ses: SNS Message JSON-null → ses/bad-message-json code",
        e1 && e1.code === "ses/bad-message-json");
  check("ses: SNS Message JSON-null does not leak the raw TypeError text",
        e1 && !/Cannot read properties/.test(e1.message));

  // Every other non-object JSON literal fails closed the same way — a
  // number, string, boolean, or array can never be a valid SES Message.
  var nonObjects = ["5", "\"hi\"", "true", "false", "[1,2]"];
  var allTyped = true;
  for (var i = 0; i < nonObjects.length; i += 1) {
    var e = _threw(function () {
      return b.mailBounce.parse({ Type: "Notification", Message: nonObjects[i] }, { vendor: "ses" });
    });
    if (!(e instanceof b.mailBounce.MailBounceError) || e.code !== "ses/bad-message-json") {
      allTyped = false;
    }
  }
  check("ses: non-object SNS Message literals all rejected typed", allTyped);

  // A correctly wrapped SNS envelope still unwraps + parses — the guard
  // only rejects non-object decodes, never a real Message object.
  var ev = b.mailBounce.parse({
    Type: "Notification",
    Message: JSON.stringify({
      notificationType: "Bounce",
      mail: { messageId: "m1", destination: ["a@b.com"] },
      bounce: { bounceType: "Permanent", bouncedRecipients: [{ emailAddress: "a@b.com" }] },
    }),
  }, { vendor: "ses" });
  check("ses: wrapped SNS envelope still parses after the guard",
        ev.type === "bounce" && ev.subType === "hard" && ev.recipient === "a@b.com");
}

async function testHandlerSesNullMessageNoLeak() {
  // Drive the real consumer path: the webhook handler surfaces the parse
  // error's code + message in the 400 body. The typed error keeps the raw
  // V8 TypeError text ("Cannot read properties of null") out of the wire.
  var handler = b.mailBounce.handler({ vendor: "ses", audit: false });
  var req = _bodyReq("POST", { "content-type": "application/json" },
                     JSON.stringify({ Type: "Notification", Message: "null" }));
  var res = _bodyRes();
  handler(req, res);
  await _waitFinish(res);
  check("handler ses null-message: 400", res._endedStatus === 400);
  check("handler ses null-message: typed code surfaced",
        /ses\/bad-message-json/.test(res._captured));
  check("handler ses null-message: no raw TypeError leak",
        !/Cannot read properties/.test(res._captured));
}

async function testSesMissingNotificationType() {
  var e1 = _threw(function () {
    b.mailBounce.parse({ mail: { messageId: "x" } }, { vendor: "ses" });
  });
  check("ses: missing notificationType rejected", e1 && e1.code === "ses/missing-notification-type");
}

async function testSesEventTypeAliasAndSoftBounce() {
  // `eventType` alias (SES event-publishing shape) + Transient → soft.
  var ev = b.mailBounce.parse({
    eventType: "Bounce",
    mail: { messageId: "m", destination: ["a@b.com"] },
    bounce: { bounceType: "Transient", bouncedRecipients: [{ emailAddress: "a@b.com" }] },
  }, { vendor: "ses" });
  check("ses: eventType alias accepted", ev.type === "bounce");
  check("ses: Transient bounceType → soft", ev.subType === "soft");
}

async function testSesBounceUndeterminedAndFallbacks() {
  // Undetermined bounceType → unknown; empty bouncedRecipients → recipient
  // falls back to mail.destination[0]; no diagnosticCode + no bounceSubType
  // → reason null; no timestamp → generated.
  var ev = b.mailBounce.parse({
    notificationType: "Bounce",
    mail: { destination: ["d@e.com"] },
    bounce: { bounceType: "Undetermined", bouncedRecipients: [] },
  }, { vendor: "ses" });
  check("ses: Undetermined → unknown subType", ev.subType === "unknown");
  check("ses: recipient falls back to destination[0]", ev.recipient === "d@e.com");
  check("ses: reason null when no diag/subtype", ev.reason === null);
  check("ses: messageId null when mail.messageId absent", ev.messageId === null);
  check("ses: timestamp generated when absent", typeof ev.timestamp === "string" && ev.timestamp.length > 0);
}

async function testSesBounceSubTypeReason() {
  // No diagnosticCode but bounceSubType present → reason "bounceSubType: X".
  var ev = b.mailBounce.parse({
    notificationType: "Bounce",
    mail: { destination: ["x@e.com"] },
    bounce: { bounceType: "Permanent", bounceSubType: "General",
              bouncedRecipients: [{ emailAddress: "x@e.com" }] },
  }, { vendor: "ses" });
  check("ses: reason derived from bounceSubType", ev.reason === "bounceSubType: General");
}

async function testSesComplaintDefaultsAndDelivery() {
  // Complaint: default subType "abuse" (no complaintFeedbackType), reason
  // from userAgent, recipient from destination fallback.
  var ev1 = b.mailBounce.parse({
    notificationType: "Complaint",
    mail: { destination: ["c@e.com"] },
    complaint: { userAgent: "UA/1", timestamp: "t" },
  }, { vendor: "ses" });
  check("ses complaint: default subType abuse", ev1.subType === "abuse");
  check("ses complaint: reason from userAgent", ev1.reason === "UA/1");
  check("ses complaint: recipient from destination fallback", ev1.recipient === "c@e.com");

  // Delivery: recipient falls back to destination when delivery.recipients absent.
  var ev2 = b.mailBounce.parse({
    notificationType: "Delivery",
    mail: { messageId: "m", destination: ["d@e.com"] },
    delivery: { timestamp: "t" },
  }, { vendor: "ses" });
  check("ses delivery: recipient from destination fallback", ev2.recipient === "d@e.com");
  check("ses delivery: type delivery", ev2.type === "delivery");
}

async function testSesUnknownNotificationType() {
  var e1 = _threw(function () {
    b.mailBounce.parse({ notificationType: "Reject" }, { vendor: "ses" });
  });
  check("ses: unknown notificationType rejected", e1 && e1.code === "ses/unknown-notification-type");
}

// ---- Resend parser: error + fallback branches ----

async function testResendEmptyAndMissingType() {
  var e1 = _threw(function () { b.mailBounce.parse(null, { vendor: "resend" }); });
  check("resend: null payload rejected", e1 && e1.code === "resend/empty");
  var e2 = _threw(function () { b.mailBounce.parse({ data: {} }, { vendor: "resend" }); });
  check("resend: missing type rejected", e2 && e2.code === "resend/missing-type");
  var e3 = _threw(function () { b.mailBounce.parse({ type: 42 }, { vendor: "resend" }); });
  check("resend: non-string type rejected", e3 && e3.code === "resend/missing-type");
}

async function testResendBounceFallbacks() {
  // No data at all → data defaults to {}; recipient null; messageId null;
  // bounce default {} → unknown subType; reason null.
  var ev1 = b.mailBounce.parse({ type: "email.bounced" }, { vendor: "resend" });
  check("resend bounced: recipient null when no data", ev1.recipient === null);
  check("resend bounced: messageId null when no id", ev1.messageId === null);
  check("resend bounced: unknown subType when no bounce", ev1.subType === "unknown");
  check("resend bounced: reason null when no bounce message", ev1.reason === null);

  // Transient bounce → soft.
  var ev2 = b.mailBounce.parse({
    type: "email.bounced",
    data: { id: "1", to: ["a@b.com"], bounce: { type: "Transient", message: "m" } },
  }, { vendor: "resend" });
  check("resend bounced: Transient → soft", ev2.subType === "soft");

  // Unrecognized bounce.type → unknown.
  var ev3 = b.mailBounce.parse({
    type: "email.bounced",
    data: { id: "1", to: ["a@b.com"], bounce: { type: "Weird" } },
  }, { vendor: "resend" });
  check("resend bounced: unrecognized bounce.type → unknown", ev3.subType === "unknown");
}

async function testResendUnknownType() {
  var e1 = _threw(function () {
    b.mailBounce.parse({ type: "email.opened", data: { id: "1", to: "a@b.com" } }, { vendor: "resend" });
  });
  check("resend: unknown event type rejected", e1 && e1.code === "resend/unknown-type");
}

// ---- Custom parser validation branches ----

async function testCustomParserValidation() {
  // Parser returns a non-object.
  var e1 = _threw(function () {
    b.mailBounce.parse({}, { parser: function () { return 7; } });
  });
  check("custom: non-object result rejected", e1 && e1.code === "custom/bad-shape");

  // Parser returns null.
  var e2 = _threw(function () {
    b.mailBounce.parse({}, { parser: function () { return null; } });
  });
  check("custom: null result rejected", e2 && e2.code === "custom/bad-shape");

  // Missing vendor.
  var e3 = _threw(function () {
    b.mailBounce.parse({}, { parser: function () { return { type: "bounce", recipient: "a@b.com" }; } });
  });
  check("custom: missing vendor rejected", e3 && e3.code === "custom/missing-vendor");

  // Missing / empty recipient.
  var e4 = _threw(function () {
    b.mailBounce.parse({}, { parser: function () { return { vendor: "x", type: "bounce", recipient: "" }; } });
  });
  check("custom: empty recipient rejected", e4 && e4.code === "custom/missing-recipient");
  var e5 = _threw(function () {
    b.mailBounce.parse({}, { parser: function () { return { vendor: "x", type: "delivery" }; } });
  });
  check("custom: absent recipient rejected", e5 && e5.code === "custom/missing-recipient");
}

// ---- parse() routing defaults ----

async function testParseRoutingDefaults() {
  // No opts object at all → default {} → missing-vendor.
  var e1 = _threw(function () { b.mailBounce.parse({ Email: "a@b.com" }); });
  check("parse: no opts → missing-vendor", e1 && e1.code === "missing-vendor");
  // Empty-string vendor → missing-vendor (length 0 branch).
  var e2 = _threw(function () { b.mailBounce.parse({}, { vendor: "" }); });
  check("parse: empty vendor → missing-vendor", e2 && e2.code === "missing-vendor");
}

// ---- handler: config-time validation ----

async function testHandlerConfigValidation() {
  var e0 = _threw(function () { b.mailBounce.handler(); });
  check("handler: no opts → bad-config", e0 && e0.code === "handler/bad-config");

  var e1 = _threw(function () { b.mailBounce.handler({ vendor: "mailgun" }); });
  check("handler: unknown vendor → bad-config", e1 && e1.code === "handler/bad-config");

  // maxBytes must be a positive finite integer — Infinity / NaN / negative /
  // non-integer all throw at create() time.
  var bad = [-1, 0, 1.5, Infinity, NaN];
  var allThrew = true;
  for (var i = 0; i < bad.length; i += 1) {
    var e = _threw(function () { return b.mailBounce.handler({ vendor: "postmark", maxBytes: bad[i] }); });
    if (!e || e.code !== "mail-bounce/bad-opt") allThrew = false;
  }
  check("handler: invalid maxBytes rejected at create()", allThrew);
}

// ---- handler: middleware runtime branches ----

async function testHandlerCustomParserPath() {
  var seen = null;
  var handler = b.mailBounce.handler({
    audit: false,
    parser: function (p) {
      return { vendor: "internal", type: "bounce", subType: "hard",
               recipient: p.who, messageId: null, reason: null, timestamp: "t", raw: p };
    },
    onBounce: function (ev) { seen = ev; },
  });
  var req = _bodyReq("POST", { "content-type": "application/json" }, JSON.stringify({ who: "a@b.com" }));
  var res = _bodyRes();
  handler(req, res);
  await _waitFinish(res);
  check("handler custom-parser: 200", res._endedStatus === 200);
  check("handler custom-parser: onBounce saw normalized event", seen && seen.recipient === "a@b.com");
}

async function testHandlerCustomParserBadShape() {
  // A misbehaving custom parser (bad shape) is caught → 400 with the code.
  var handler = b.mailBounce.handler({
    audit: false,
    parser: function () { return { vendor: "x", type: "garbage", recipient: "a@b.com" }; },
  });
  var req = _bodyReq("POST", { "content-type": "application/json" }, JSON.stringify({ any: 1 }));
  var res = _bodyRes();
  handler(req, res);
  await _waitFinish(res);
  check("handler custom-parser bad shape: 400", res._endedStatus === 400);
  check("handler custom-parser bad shape: code surfaced", /custom\/bad-type/.test(res._captured));
}

async function testHandlerParseFailSurfacesCode() {
  var handler = b.mailBounce.handler({ vendor: "postmark", audit: false });
  var req = _bodyReq("POST", { "content-type": "application/json" },
                     JSON.stringify({ RecordType: "Bounce" }));   // missing Email
  var res = _bodyRes();
  handler(req, res);
  await _waitFinish(res);
  check("handler parse-fail: 400", res._endedStatus === 400);
  check("handler parse-fail: error code surfaced", /postmark\/missing-email/.test(res._captured));
}

async function testHandlerVerifyThrows() {
  // verify() throwing is distinct from verify() returning false: it maps to
  // 401 "verification error" (fail-closed), and onBounce never runs.
  var onBounceRan = false;
  var handler = b.mailBounce.handler({
    vendor: "postmark", audit: false,
    verify: function () { throw new Error("boom"); },
    onBounce: function () { onBounceRan = true; },
  });
  var req = _bodyReq("POST", { "content-type": "application/json" },
                     JSON.stringify({ RecordType: "Delivery", Email: "a@b.com" }));
  var res = _bodyRes();
  handler(req, res);
  await _waitFinish(res);
  check("handler verify-throws: 401", res._endedStatus === 401);
  check("handler verify-throws: verification error body", /verification error/.test(res._captured));
  check("handler verify-throws: onBounce not run", onBounceRan === false);
}

async function testHandlerReqError() {
  // A socket 'error' before the body completes → 400 request error.
  var handler = b.mailBounce.handler({ vendor: "postmark", audit: false });
  var req = _rawReq({ "content-type": "application/json" });
  var res = _bodyRes();
  var finished = _waitFinish(res);
  handler(req, res);
  req.emit("error", new Error("ECONNRESET"));
  await finished;
  check("handler req-error: 400", res._endedStatus === 400);
  check("handler req-error: request error body", /request error/.test(res._captured));
}

async function testHandlerMultiChunkOverflowAbort() {
  // First chunk overflows maxBytes → 413 + aborted; subsequent chunk and the
  // end event are ignored (single response).
  var handler = b.mailBounce.handler({ vendor: "postmark", audit: false, maxBytes: 10 });
  var req = _rawReq({ "content-type": "application/json" });
  var res = _bodyRes();
  var finishCount = 0;
  res.on("finish", function () { finishCount += 1; });
  var finished = _waitFinish(res);
  handler(req, res);
  req.emit("data", Buffer.from("12345678901234567890"));   // 20 bytes > 10 → abort + 413
  req.emit("data", Buffer.from("more"));                    // ignored (aborted)
  req.emit("end");                                          // ignored (aborted)
  await finished;
  check("handler overflow: 413", res._endedStatus === 413);
  check("handler overflow: only one response sent", finishCount === 1);
}

async function testHandlerNoWriteHeadResNoCrash() {
  // _send guards on typeof res.writeHead === "function"; a response object
  // lacking writeHead must be a silent no-op, never a crash.
  var handler = b.mailBounce.handler({ vendor: "postmark", audit: false });
  var req = _rawReq({ "content-type": "application/json" });
  var res = new EventEmitter();   // no writeHead / no end
  var err = _threw(function () {
    handler(req, res);
    req.emit("data", Buffer.from("not-json"));   // → invalid JSON → _send → no-op
    req.emit("end");
  });
  check("handler no-writeHead res: no crash", err === null);
}

async function testHandlerAuditOnDeliverySuccess() {
  // audit defaults ON: a delivery event emits an audit row with outcome
  // "success" (vs "denied" for bounce/complaint), and the no-verify /
  // onBounce-resolve path returns 200.
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-mbc-"));
  try {
    await setupTestDb(tmpDir);
    var seen = null;
    var handler = b.mailBounce.handler({
      vendor: "postmark",
      onBounce: function (ev) { seen = ev; },
    });
    var req = _bodyReq("POST", { "content-type": "application/json" },
                       JSON.stringify({ RecordType: "Delivery", Email: "ok@e.com", MessageID: "d1",
                                        DeliveredAt: "2026-04-28T00:00:00Z" }));
    var res = _bodyRes();
    handler(req, res);
    await _waitFinish(res);
    check("handler audit-on delivery: 200", res._endedStatus === 200);
    check("handler audit-on delivery: onBounce saw delivery", seen && seen.type === "delivery");

    await b.audit.flush();
    var rows = await b.audit.query({ action: "system.mail.bounce" });
    check("handler audit-on delivery: one audit row", rows.length === 1);
    check("handler audit-on delivery: outcome success", rows[0].outcome === "success");
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- DSN parse: error / defensive branches ----

async function testDsnParseInputGuards() {
  var e1 = _threw(function () { b.mailBounce.dsn.parse(12345); });
  check("dsn parse: non-string rejected", e1 && e1.code === "bounce/dsn-parse-failed");
  var e2 = _threw(function () { b.mailBounce.dsn.parse(null); });
  check("dsn parse: null rejected", e2 && e2.code === "bounce/dsn-parse-failed");

  // Body cap — a payload over 1 MiB is a typed error, not a regex-backtrack hang.
  var oversize = 'Content-Type: multipart/report; report-type=delivery-status; boundary="b"\r\n\r\n' +
                 "x".repeat(b.constants.BYTES.mib(1) + 10);
  var e3 = _threw(function () { b.mailBounce.dsn.parse(oversize); });
  check("dsn parse: oversize rejected", e3 && e3.code === "bounce/dsn-parse-failed" &&
        /exceeds/.test(e3.message));
}

async function testDsnParseStructureGuards() {
  var e1 = _threw(function () { b.mailBounce.dsn.parse("Subject: hi\r\n\r\nbody"); });
  check("dsn parse: missing top Content-Type rejected", e1 && e1.code === "bounce/dsn-malformed");

  var e2 = _threw(function () {
    b.mailBounce.dsn.parse('Content-Type: multipart/report; report-type=disposition-notification; ' +
                           'boundary="b"\r\n\r\n--b\r\n--b--\r\n');
  });
  check("dsn parse: wrong report-type rejected", e2 && e2.code === "bounce/dsn-malformed");

  var e3 = _threw(function () {
    b.mailBounce.dsn.parse("Content-Type: multipart/report; report-type=delivery-status\r\n\r\nbody");
  });
  check("dsn parse: missing boundary rejected", e3 && e3.code === "bounce/dsn-malformed");

  // multipart/report with only one part → needs >= 2.
  var onePart = [
    'Content-Type: multipart/report; report-type=delivery-status; boundary="b"', '',
    '--b', 'Content-Type: text/plain', '', 'only one part', '',
    '--b--', '',
  ].join('\r\n');
  var e4 = _threw(function () { b.mailBounce.dsn.parse(onePart); });
  check("dsn parse: fewer than 2 parts rejected", e4 && e4.code === "bounce/dsn-malformed");

  // Two parts but none is message/delivery-status.
  var noStatus = [
    'Content-Type: multipart/report; report-type=delivery-status; boundary="b"', '',
    '--b', 'Content-Type: text/plain', '', 't', '',
    '--b', 'Content-Type: message/rfc822', '', 'From: x', '',
    '--b--', '',
  ].join('\r\n');
  var e5 = _threw(function () { b.mailBounce.dsn.parse(noStatus); });
  check("dsn parse: no delivery-status part rejected", e5 && e5.code === "bounce/dsn-malformed");
}

async function testDsnParseRecipientGuards() {
  // delivery-status part present but only a per-message group (no recipient group).
  var onlyPerMsg = [
    'Content-Type: multipart/report; report-type=delivery-status; boundary="b"', '',
    '--b', 'Content-Type: text/plain', '', 't', '',
    '--b', 'Content-Type: message/delivery-status', '', 'Reporting-MTA: dns; m', '',
    '--b--', '',
  ].join('\r\n');
  var e1 = _threw(function () { b.mailBounce.dsn.parse(onlyPerMsg); });
  check("dsn parse: no per-recipient group rejected", e1 && e1.code === "bounce/dsn-malformed");

  // Empty delivery-status body (groups.length === 0 path) → no recipients.
  var emptyStatus = [
    'Content-Type: multipart/report; report-type=delivery-status; boundary="b"', '',
    '--b', 'Content-Type: text/plain', '', 't', '',
    '--b', 'Content-Type: message/delivery-status', '', '',
    '--b--', '',
  ].join('\r\n');
  var e2 = _threw(function () { b.mailBounce.dsn.parse(emptyStatus); });
  check("dsn parse: empty delivery-status body rejected", e2 && e2.code === "bounce/dsn-malformed");

  // Recipient group missing Final-Recipient AND Original-Recipient.
  var noFinal = [
    'Content-Type: multipart/report; report-type=delivery-status; boundary="b"', '',
    '--b', 'Content-Type: text/plain', '', 't', '',
    '--b', 'Content-Type: message/delivery-status', '', 'Reporting-MTA: dns; m', '',
    'Action: failed', 'Status: 5.1.1', '',
    '--b--', '',
  ].join('\r\n');
  var e3 = _threw(function () { b.mailBounce.dsn.parse(noFinal); });
  check("dsn parse: missing Final-Recipient rejected", e3 && e3.code === "bounce/dsn-malformed");
}

async function testDsnParseActionBranches() {
  function dsn(action, status) {
    return [
      'Content-Type: multipart/report; report-type=delivery-status; boundary="b"', '',
      '--b', 'Content-Type: text/plain', '', 'human', '',
      '--b', 'Content-Type: message/delivery-status', '', 'Reporting-MTA: dns; m', '',
      'Final-Recipient: rfc822;u@e.com',
    ].concat(action ? ['Action: ' + action] : [])
     .concat(['Status: ' + status, '', '--b--', '']).join('\r\n');
  }
  // relayed / expanded → delivery.
  var evR = b.mailBounce.dsn.parse(dsn("relayed", "2.0.0"));
  check("dsn parse: relayed → delivery", evR.type === "delivery" && evR.subType === null);
  var evX = b.mailBounce.dsn.parse(dsn("expanded", "2.0.0"));
  check("dsn parse: expanded → delivery", evX.type === "delivery" && evX.subType === null);
  // No Action field → bounce with subType unknown.
  var evN = b.mailBounce.dsn.parse(dsn(null, "5.0.0"));
  check("dsn parse: absent Action → bounce/unknown", evN.type === "bounce" && evN.subType === "unknown");
}

async function testDsnParseReasonAndSkipBranches() {
  // No Diagnostic-Code AND no text/plain part → reason null.
  var noReason = [
    'Content-Type: multipart/report; report-type=delivery-status; boundary="b"', '',
    '--b', 'Content-Type: message/delivery-status', '', 'Reporting-MTA: dns; m', '',
    'Final-Recipient: rfc822;u@e.com', 'Action: failed', 'Status: 5.1.1', '',
    '--b', 'Content-Type: message/rfc822', '', 'From: x', '',
    '--b--', '',
  ].join('\r\n');
  var ev1 = b.mailBounce.dsn.parse(noReason);
  check("dsn parse: reason null with no diag and no humanText", ev1.reason === null);

  // A malformed (colon-less) recipient group is skipped; a valid group after
  // it still parses (covers the headers.length === 0 `continue`).
  var contThenOk = [
    'Content-Type: multipart/report; report-type=delivery-status; boundary="b"', '',
    '--b', 'Content-Type: text/plain', '', 'human', '',
    '--b', 'Content-Type: message/delivery-status', '', 'Reporting-MTA: dns; m', '',
    'nocolongarbage', '',
    'Final-Recipient: rfc822;real@e.com', 'Action: failed', 'Status: 5.1.1', '',
    '--b--', '',
  ].join('\r\n');
  var ev2 = b.mailBounce.dsn.parse(contThenOk);
  check("dsn parse: colon-less recipient group skipped, later group parses",
        ev2.recipient === "real@e.com" && ev2.subType === "hard");

  // Human-text fallback truncates to first 5 lines when Diagnostic-Code absent.
  var multi = [
    'Content-Type: multipart/report; report-type=delivery-status; boundary="b"', '',
    '--b', 'Content-Type: text/plain', '', 'L1', 'L2', 'L3', 'L4', 'L5', 'L6', 'L7', '',
    '--b', 'Content-Type: message/delivery-status', '', 'Reporting-MTA: dns; m', '',
    'Final-Recipient: rfc822;u@e.com', 'Action: failed', 'Status: 5.1.1', '',
    '--b--', '',
  ].join('\r\n');
  var ev3 = b.mailBounce.dsn.parse(multi);
  check("dsn parse: humanText fallback keeps first 5 lines", ev3.reason === "L1 L2 L3 L4 L5");
}

// ---- DSN build: error / defensive / optional-field branches ----

async function testDsnBuildInputGuards() {
  var e0 = _threw(function () { b.mailBounce.dsn.build(); });
  check("dsn build: missing opts rejected", e0 && e0.code === "bounce/dsn-malformed");
  var e1 = _threw(function () { b.mailBounce.dsn.build(null); });
  check("dsn build: null opts rejected", e1 && e1.code === "bounce/dsn-malformed");
  var e2 = _threw(function () { b.mailBounce.dsn.build({ action: "failed", status: "5.1.1" }); });
  check("dsn build: missing finalRecipient rejected", e2 && e2.code === "bounce/dsn-malformed");

  // status non-string (number) and absent both hit the status guard.
  var e3 = _threw(function () {
    b.mailBounce.dsn.build({ finalRecipient: "u@e.com", action: "failed", status: 500 });
  });
  check("dsn build: non-string status rejected", e3 && e3.code === "bounce/dsn-malformed");
  var e4 = _threw(function () {
    b.mailBounce.dsn.build({ finalRecipient: "u@e.com", action: "failed" });
  });
  check("dsn build: absent status rejected", e4 && e4.code === "bounce/dsn-malformed");
}

async function testDsnBuildDefaultAction() {
  // No action → defaults to "failed".
  var raw = b.mailBounce.dsn.build({ finalRecipient: "u@e.com", status: "5.1.1" });
  check("dsn build: default action failed", /Action: failed/.test(raw));
  // No diagnosticCode → humanText omits the "remote server reported" line.
  check("dsn build: humanText omits report line without diagnosticCode",
        !/remote server reported/.test(raw));
  check("dsn build: default Reporting-MTA", /Reporting-MTA: dns; localhost/.test(raw));
}

async function testDsnBuildAllOptionalFields() {
  var raw = b.mailBounce.dsn.build({
    finalRecipient:     "u@e.com",
    originalRecipient:  "alias@e.com",
    action:             "delayed",
    status:             "4.4.1",
    from:               "mailer@x",
    to:                 "sender@y",
    subject:            "Delivery failure",
    messageId:          "<id@x>",
    reportingMta:       "dns; mta.x",
    remoteMta:          "dns; mx.y",
    arrivalDate:        "Mon, 28 Apr 2026 12:00:00 +0000",
    originalEnvelopeId: "env-1",
    lastAttemptDate:    "Tue, 29 Apr 2026 12:00:00 +0000",
    willRetryUntil:     "Wed, 30 Apr 2026 12:00:00 +0000",
    humanText:          "Custom operator human text",
    diagnosticCode:     "smtp; 421 try later",
    originalMessage:    "From: x\r\n\r\nbody",
  });
  check("dsn build: From header emitted", /^From: mailer@x$/m.test(raw));
  check("dsn build: To header emitted", /^To: sender@y$/m.test(raw));
  check("dsn build: Subject header emitted", /^Subject: Delivery failure$/m.test(raw));
  check("dsn build: Message-ID header emitted", /^Message-ID: <id@x>$/m.test(raw));
  check("dsn build: Original-Envelope-Id emitted", /Original-Envelope-Id: env-1/.test(raw));
  check("dsn build: Original-Recipient emitted", /Original-Recipient: rfc822;alias@e.com/.test(raw));
  check("dsn build: Last-Attempt-Date emitted", /Last-Attempt-Date: Tue, 29 Apr 2026/.test(raw));
  check("dsn build: Will-Retry-Until emitted", /Will-Retry-Until: Wed, 30 Apr 2026/.test(raw));
  check("dsn build: custom humanText used", /Custom operator human text/.test(raw));
  check("dsn build: Remote-MTA emitted", /Remote-MTA: dns; mx.y/.test(raw));
}

async function testDsnBuildOriginalMessageShapes() {
  // Plain-string originalMessage → message/rfc822 with body.
  var raw1 = b.mailBounce.dsn.build({
    finalRecipient: "u@e.com", action: "failed", status: "5.1.1",
    originalMessage: "From: x\r\n\r\nbody",
  });
  check("dsn build: string originalMessage → message/rfc822",
        /Content-Type: message\/rfc822/.test(raw1) && /body/.test(raw1));

  // Non-headersOnly object → message/rfc822 with an empty body (else branch).
  var raw2 = b.mailBounce.dsn.build({
    finalRecipient: "u@e.com", action: "failed", status: "5.1.1",
    originalMessage: { foo: 1 },
  });
  check("dsn build: plain-object originalMessage → message/rfc822 empty body",
        /Content-Type: message\/rfc822/.test(raw2));

  // headersOnly with no headers field → text/rfc822-headers, empty.
  var raw3 = b.mailBounce.dsn.build({
    finalRecipient: "u@e.com", action: "failed", status: "5.1.1",
    originalMessage: { headersOnly: true },
  });
  check("dsn build: headersOnly with no headers → text/rfc822-headers",
        /Content-Type: text\/rfc822-headers/.test(raw3));
}

async function testDsnBuildHeaderInjectionGuards() {
  // Structured fields reject CR/LF/NUL (header-injection fail-closed). These
  // complement mail-bounce.test.js which covers finalRecipient / reportingMta
  // / from / subject / remoteMta.
  var cases = {
    originalRecipient: { finalRecipient: "u@e.com", action: "failed", status: "5.1.1",
                         originalRecipient: "a@e.com\r\nX-Evil: 1" },
    to:                { finalRecipient: "u@e.com", action: "failed", status: "5.1.1",
                         to: "x@y\r\nBcc: victim@evil.test" },
    messageId:         { finalRecipient: "u@e.com", action: "failed", status: "5.1.1",
                         messageId: "<id>\r\nX-Evil: 1" },
    arrivalDate:       { finalRecipient: "u@e.com", action: "failed", status: "5.1.1",
                         arrivalDate: "Mon\r\nX-Evil: 1" },
    originalEnvelopeId:{ finalRecipient: "u@e.com", action: "failed", status: "5.1.1",
                         originalEnvelopeId: "e\r\nX-Evil: 1" },
    lastAttemptDate:   { finalRecipient: "u@e.com", action: "failed", status: "5.1.1",
                         lastAttemptDate: "d\r\nX-Evil: 1" },
    willRetryUntil:    { finalRecipient: "u@e.com", action: "failed", status: "5.1.1",
                         willRetryUntil: "d\r\nX-Evil: 1" },
    nulFinalRecipient: { finalRecipient: "u@e.com" + String.fromCharCode(0) + "x",
                         action: "failed", status: "5.1.1" },
  };
  var names = Object.keys(cases);
  var allBadDsnField = true;
  for (var i = 0; i < names.length; i += 1) {
    var name = names[i];
    var e = _threw(function () { return b.mailBounce.dsn.build(cases[name]); });
    if (!e || e.code !== "bounce/bad-dsn-field") allBadDsnField = false;
  }
  check("dsn build: CR/LF/NUL in structured fields all fail closed", allBadDsnField);

  // Bad action allowlist rejection at build.
  var eAct = _threw(function () {
    b.mailBounce.dsn.build({ finalRecipient: "u@e.com", action: "explode", status: "5.1.1" });
  });
  check("dsn build: non-RFC3464 action rejected", eAct && eAct.code === "bounce/dsn-malformed");
}

async function testDsnBuildDiagnosticFoldNotReject() {
  // Diagnostic-Code is free text (may legitimately wrap): folded to one line,
  // NUL stripped — not rejected.
  var raw = b.mailBounce.dsn.build({
    finalRecipient: "u@e.com", action: "failed", status: "5.1.1",
    diagnosticCode: "smtp; 550 line1\r\nline2" + String.fromCharCode(0) + "z",
  });
  check("dsn build: folded diagnosticCode cannot start a new header",
        !/^line2/m.test(raw) && !/^X-/m.test(raw));
  check("dsn build: NUL stripped from diagnosticCode", raw.indexOf(String.fromCharCode(0)) === -1);
}

async function run() {
  await testPostmarkEmptyPayload();
  await testPostmarkMissingEmail();
  await testPostmarkDeliveryDefaults();
  await testPostmarkSpamDescriptionFallback();
  await testPostmarkBounceTypeFallbacks();
  await testPostmarkUnknownRecord();

  await testSesEmptyPayload();
  await testSesBadSnsMessageJson();
  await testSesSnsNullMessageTypedError();
  await testHandlerSesNullMessageNoLeak();
  await testSesMissingNotificationType();
  await testSesEventTypeAliasAndSoftBounce();
  await testSesBounceUndeterminedAndFallbacks();
  await testSesBounceSubTypeReason();
  await testSesComplaintDefaultsAndDelivery();
  await testSesUnknownNotificationType();

  await testResendEmptyAndMissingType();
  await testResendBounceFallbacks();
  await testResendUnknownType();

  await testCustomParserValidation();
  await testParseRoutingDefaults();

  await testHandlerConfigValidation();
  await testHandlerCustomParserPath();
  await testHandlerCustomParserBadShape();
  await testHandlerParseFailSurfacesCode();
  await testHandlerVerifyThrows();
  await testHandlerReqError();
  await testHandlerMultiChunkOverflowAbort();
  await testHandlerNoWriteHeadResNoCrash();
  await testHandlerAuditOnDeliverySuccess();

  await testDsnParseInputGuards();
  await testDsnParseStructureGuards();
  await testDsnParseRecipientGuards();
  await testDsnParseActionBranches();
  await testDsnParseReasonAndSkipBranches();

  await testDsnBuildInputGuards();
  await testDsnBuildDefaultAction();
  await testDsnBuildAllOptionalFields();
  await testDsnBuildOriginalMessageShapes();
  await testDsnBuildHeaderInjectionGuards();
  await testDsnBuildDiagnosticFoldNotReject();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.message); process.exit(1); }
  );
}
