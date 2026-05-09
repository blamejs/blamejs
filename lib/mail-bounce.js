"use strict";
/**
 * @module b.mailBounce
 * @nav    Communication
 * @title  Mail Bounce
 *
 * @intro
 *   Inbound mail bounce-handler — parse the vendor's webhook DSN /
 *   complaint / delivery payload, normalize it into one event shape,
 *   classify hard vs soft bounces, and feed an operator-supplied
 *   suppression-list hook.
 *
 *   Outbound mail comes back as a hard bounce (permanent — invalid
 *   address), a soft bounce (transient — mailbox full, greylisted), a
 *   spam / abuse complaint, a delivery confirmation, or a list-
 *   unsubscribe. Vendors (Postmark, AWS SES via SNS, Resend) ship the
 *   same information dressed up in three different JSON shapes. This
 *   module owns the translation so operators write a single
 *   reconciliation path regardless of vendor.
 *
 *   `b.mailBounce.parse` is the pure synchronous parser; it returns the
 *   normalized event `{ vendor, type, subType, recipient, messageId,
 *   reason, timestamp, raw }`. `b.mailBounce.handler` wires that
 *   parser into an Express-style middleware that buffers the body,
 *   runs an operator `verify` hook (HMAC, Basic Auth, SNS-Signature),
 *   emits a `system.mail.bounce` audit row, and calls the operator's
 *   `onBounce(event)` so the suppression list can be updated before
 *   the 200 response goes back.
 *
 *   Generic RFC 3464 DSN is intentionally NOT a built-in vendor —
 *   parsing arbitrary MTA reports needs a full email parser the
 *   framework does not vendor for this surface. Operators with raw
 *   DSN inflow supply `{ parser }` to plug a custom normalizer.
 *
 * @card
 *   Inbound mail bounce-handler — parse the vendor's webhook DSN / complaint / delivery payload, normalize it into one event shape, classify hard vs soft bounces, and feed an operator-supplied suppression-list hook.
 */

var lazyRequire = require("./lazy-require");
var numericBounds = require("./numeric-bounds");
var audit = lazyRequire(function () { return require("./audit"); });
var safeBuffer = require("./safe-buffer");
var safeJson = require("./safe-json");
var C = require("./constants");
var requestHelpers = require("./request-helpers");
var { defineClass } = require("./framework-error");

var HTTP = requestHelpers.HTTP_STATUS;

var MailBounceError = defineClass("MailBounceError", { withStatusCode: true });

// Cap on inbound webhook bodies — any vendor bigger than this is
// pathological and likely an attack surface. 256 KiB covers the
// largest realistic SES SNS notification with verbose diagnostic info.
var MAX_BODY_BYTES = C.BYTES.kib(256);

function _err(code, message, statusCode) {
  return new MailBounceError(code, message, true, statusCode || 400);
}

// ---- Postmark ----
//
// Webhook payload (JSON):
//   {
//     "RecordType": "Bounce" | "SpamComplaint" | "Delivery",
//     "Type":       "HardBounce" | "SoftBounce" | "Transient" | ...,
//     "Email":      "...",
//     "MessageID":  "...",
//     "Description": "...",
//     "Details":     "...",
//     "BouncedAt":   "2026-04-28T..."  (Bounce / SpamComplaint)
//     "DeliveredAt": "..."             (Delivery)
//   }

var POSTMARK_TYPE_TO_NORMAL = {
  "HardBounce":          { type: "bounce",    subType: "hard"    },
  "SoftBounce":          { type: "bounce",    subType: "soft"    },
  "Transient":           { type: "bounce",    subType: "soft"    },
  "Unknown":             { type: "bounce",    subType: "unknown" },
  "Subscribe":           { type: "complaint", subType: "subscribe-fail" },
  "AutoResponder":       { type: "bounce",    subType: "auto-reply"     },
  "AddressChange":       { type: "bounce",    subType: "address-change" },
  "DnsError":            { type: "bounce",    subType: "soft"    },
  "SpamNotification":    { type: "complaint", subType: "spam"    },
  "OpenRelayTest":       { type: "bounce",    subType: "policy"  },
  "Unsubscribe":         { type: "complaint", subType: "unsubscribe" },
  "Blocked":             { type: "bounce",    subType: "blocked" },
  "SMTPApiError":        { type: "bounce",    subType: "api"     },
  "InboundError":        { type: "bounce",    subType: "inbound" },
  "DMARCPolicy":         { type: "bounce",    subType: "policy"  },
  "TemplateRenderingFailed": { type: "bounce", subType: "template" },
  "ManuallyDeactivated": { type: "bounce",    subType: "deactivated" },
};

function _parsePostmark(p) {
  if (!p || typeof p !== "object") {
    throw _err("postmark/empty", "postmark webhook payload must be an object");
  }
  var record = p.RecordType;
  var email = p.Email;
  if (typeof email !== "string" || email.length === 0) {
    throw _err("postmark/missing-email", "postmark payload missing 'Email'");
  }

  if (record === "Delivery") {
    return {
      vendor:    "postmark",
      type:      "delivery",
      subType:   null,
      recipient: email,
      messageId: typeof p.MessageID === "string" ? p.MessageID : null,
      reason:    null,
      timestamp: p.DeliveredAt || new Date().toISOString(),
      raw:       p,
    };
  }
  if (record === "SpamComplaint") {
    return {
      vendor:    "postmark",
      type:      "complaint",
      subType:   "spam",
      recipient: email,
      messageId: typeof p.MessageID === "string" ? p.MessageID : null,
      reason:    p.Details || p.Description || null,
      timestamp: p.BouncedAt || new Date().toISOString(),
      raw:       p,
    };
  }
  if (record === "Bounce" || record === "SubscriptionChange" || !record) {
    var mapping = POSTMARK_TYPE_TO_NORMAL[p.Type] ||
                  { type: "bounce", subType: typeof p.Type === "string" ? p.Type.toLowerCase() : "unknown" };
    return {
      vendor:    "postmark",
      type:      mapping.type,
      subType:   mapping.subType,
      recipient: email,
      messageId: typeof p.MessageID === "string" ? p.MessageID : null,
      reason:    p.Details || p.Description || null,
      timestamp: p.BouncedAt || p.DeliveredAt || new Date().toISOString(),
      raw:       p,
    };
  }
  throw _err("postmark/unknown-record",
    "postmark RecordType '" + String(record) + "' not recognised");
}

// ---- SES via SNS ----
//
// Outer envelope (SNS notification):
//   { "Type": "Notification", "MessageId": "...",
//     "Message": "<json string>", "Signature": "...", ... }
//
// After JSON.parse(Message):
//   { "notificationType": "Bounce" | "Complaint" | "Delivery",
//     "mail":   { "messageId": "...", "destination": ["..."], ... },
//     "bounce": { "bounceType": "Permanent" | "Transient" | "Undetermined",
//                 "bounceSubType": "General" | ...,
//                 "bouncedRecipients": [
//                   { "emailAddress": "...", "diagnosticCode": "...",
//                     "action": "...", "status": "..." }
//                 ],
//                 "timestamp": "..." },
//     "complaint": { ... }, "delivery": { ... } }

function _parseSes(p) {
  if (!p || typeof p !== "object") {
    throw _err("ses/empty", "SES payload must be an object");
  }
  // Accept either the SNS envelope or the unwrapped Message payload —
  // operators may strip the SNS layer at their LB / handler.
  var msg = p;
  if (p.Type === "Notification" && typeof p.Message === "string") {
    try { msg = safeJson.parse(p.Message); }
    catch (e) {
      throw _err("ses/bad-message-json",
        "SES SNS Message field is not valid JSON: " + (e && e.message));
    }
  }
  var notificationType = msg.notificationType || msg.eventType;
  if (!notificationType) {
    throw _err("ses/missing-notification-type",
      "SES payload missing notificationType / eventType");
  }
  var mailMeta = msg.mail || {};
  var messageId = (typeof mailMeta.messageId === "string") ? mailMeta.messageId : null;

  if (notificationType === "Bounce" || notificationType === "bounce") {
    var b = msg.bounce || {};
    var recip = (b.bouncedRecipients && b.bouncedRecipients[0]) || {};
    var subType = b.bounceType === "Permanent" ? "hard"
                : b.bounceType === "Transient" ? "soft"
                : "unknown";
    return {
      vendor:    "ses",
      type:      "bounce",
      subType:   subType,
      recipient: recip.emailAddress || (mailMeta.destination && mailMeta.destination[0]) || null,
      messageId: messageId,
      reason:    recip.diagnosticCode || (b.bounceSubType ? "bounceSubType: " + b.bounceSubType : null),
      timestamp: b.timestamp || new Date().toISOString(),
      raw:       p,
    };
  }
  if (notificationType === "Complaint" || notificationType === "complaint") {
    var c = msg.complaint || {};
    var crecip = (c.complainedRecipients && c.complainedRecipients[0]) || {};
    return {
      vendor:    "ses",
      type:      "complaint",
      subType:   c.complaintFeedbackType || "abuse",
      recipient: crecip.emailAddress || (mailMeta.destination && mailMeta.destination[0]) || null,
      messageId: messageId,
      reason:    c.userAgent || null,
      timestamp: c.timestamp || new Date().toISOString(),
      raw:       p,
    };
  }
  if (notificationType === "Delivery" || notificationType === "delivery") {
    var d = msg.delivery || {};
    return {
      vendor:    "ses",
      type:      "delivery",
      subType:   null,
      recipient: (d.recipients && d.recipients[0]) || (mailMeta.destination && mailMeta.destination[0]) || null,
      messageId: messageId,
      reason:    null,
      timestamp: d.timestamp || new Date().toISOString(),
      raw:       p,
    };
  }
  throw _err("ses/unknown-notification-type",
    "SES notificationType '" + String(notificationType) + "' not recognised");
}

// ---- Resend ----
//
// Webhook payload (JSON):
//   {
//     "type":       "email.bounced" | "email.complained" | "email.delivered" | ...,
//     "created_at": "2026-04-28T...",
//     "data": {
//       "id":      "...",
//       "to":      ["user@example.com"] | "user@example.com",
//       "from":    "...",
//       "bounce":  { "type": "Permanent", "subType": "General",
//                    "message": "..." }      (bounced events only)
//     }
//   }

function _parseResend(p) {
  if (!p || typeof p !== "object") {
    throw _err("resend/empty", "resend payload must be an object");
  }
  var type = p.type;
  if (typeof type !== "string") {
    throw _err("resend/missing-type", "resend payload missing 'type'");
  }
  var data = p.data || {};
  var to = Array.isArray(data.to) ? data.to[0] : data.to;
  var messageId = (typeof data.id === "string") ? data.id : null;
  var ts = p.created_at || new Date().toISOString();

  if (type === "email.bounced") {
    var bounce = data.bounce || {};
    var subType = bounce.type === "Permanent" ? "hard"
                : bounce.type === "Transient" ? "soft"
                : "unknown";
    return {
      vendor:    "resend",
      type:      "bounce",
      subType:   subType,
      recipient: to || null,
      messageId: messageId,
      reason:    bounce.message || null,
      timestamp: ts,
      raw:       p,
    };
  }
  if (type === "email.complained") {
    return {
      vendor:    "resend",
      type:      "complaint",
      subType:   "abuse",
      recipient: to || null,
      messageId: messageId,
      reason:    null,
      timestamp: ts,
      raw:       p,
    };
  }
  if (type === "email.delivered") {
    return {
      vendor:    "resend",
      type:      "delivery",
      subType:   null,
      recipient: to || null,
      messageId: messageId,
      reason:    null,
      timestamp: ts,
      raw:       p,
    };
  }
  throw _err("resend/unknown-type",
    "resend type '" + type + "' not recognised");
}

// ---- Custom parser hook ----
//
// Operators with bespoke vendor inflow (DSN, vendor-X, internal MTA)
// supply a function that takes the parsed body and returns the
// normalized event shape. The framework runs the function then
// validates the returned shape so a misbehaving custom parser can't
// emit malformed audit rows.
function _customParser(parser) {
  return function (payload) {
    var event = parser(payload);
    _validateNormalized(event);
    return event;
  };
}

function _validateNormalized(event) {
  if (!event || typeof event !== "object") {
    throw _err("custom/bad-shape", "parser returned non-object");
  }
  if (typeof event.vendor !== "string") {
    throw _err("custom/missing-vendor", "parser result missing 'vendor'");
  }
  if (["bounce", "complaint", "delivery"].indexOf(event.type) === -1) {
    throw _err("custom/bad-type",
      "parser result.type must be 'bounce' | 'complaint' | 'delivery'");
  }
  if (typeof event.recipient !== "string" || event.recipient.length === 0) {
    throw _err("custom/missing-recipient", "parser result missing 'recipient'");
  }
}

var VENDORS = {
  postmark: _parsePostmark,
  ses:      _parseSes,
  resend:   _parseResend,
};

/**
 * @primitive b.mailBounce.parse
 * @signature b.mailBounce.parse(payload, opts)
 * @since     0.5.0
 * @status    stable
 * @related   b.mailBounce.handler
 *
 * Pure synchronous parser. Routes `payload` through the chosen vendor
 * parser (built-ins: `postmark`, `ses`, `resend`) and returns the
 * normalized event. Operators with bespoke vendors supply
 * `opts.parser` — a function `(payload) -> normalizedEvent` that the
 * framework runs and then validates so a misbehaving custom parser
 * cannot emit malformed audit rows.
 *
 * Throws `MailBounceError` (HTTP 400) on missing / unknown vendor,
 * empty payload, or payload missing the required vendor-specific
 * fields. Never mutates `payload` — the original is preserved on
 * `event.raw` for downstream re-parsing.
 *
 * @opts
 *   vendor: "postmark" | "ses" | "resend",       // required when `parser` is absent
 *   parser: function (payload): normalizedEvent, // alternative to `vendor`
 *
 * @example
 *   var event = b.mailBounce.parse({
 *     RecordType:  "Bounce",
 *     Type:        "HardBounce",
 *     Email:       "user@example.com",
 *     MessageID:   "abc-123",
 *     Description: "550 No such mailbox",
 *     BouncedAt:   "2026-04-28T10:00:00Z",
 *   }, { vendor: "postmark" });
 *   event.type;      // → "bounce"
 *   event.subType;   // → "hard"
 *   event.recipient; // → "user@example.com"
 *   event.timestamp; // → "2026-04-28T10:00:00Z"
 */
function parse(payload, opts) {
  opts = opts || {};
  if (typeof opts.parser === "function") {
    return _customParser(opts.parser)(payload);
  }
  var vendor = opts.vendor;
  if (typeof vendor !== "string" || vendor.length === 0) {
    throw _err("missing-vendor",
      "mailBounce.parse requires { vendor } (one of 'postmark', 'ses', 'resend') or { parser }");
  }
  var fn = VENDORS[vendor];
  if (!fn) {
    throw _err("unknown-vendor",
      "mailBounce.parse: unknown vendor '" + vendor +
      "' (built-ins: postmark, ses, resend; supply { parser } for others)");
  }
  return fn(payload);
}

/**
 * @primitive b.mailBounce.handler
 * @signature b.mailBounce.handler(opts)
 * @since     0.5.0
 * @status    stable
 * @related   b.mailBounce.parse, b.audit.safeEmit
 *
 * Returns an Express-style `(req, res)` middleware that buffers the
 * inbound webhook body (capped at `maxBytes`), runs `verify(req, body,
 * raw)` if supplied, parses via the configured vendor (or custom
 * `parser`), emits one `system.mail.bounce` audit row, calls
 * `onBounce(event)`, and responds 200. Failures map to 400 (bad
 * payload), 401 (verify rejected), 413 (body too large), 500
 * (`onBounce` threw).
 *
 * `audit` defaults to ON; pass `audit: false` to suppress the
 * `system.mail.bounce` row when the operator already records the
 * normalized event in their own data store.
 *
 * @opts
 *   vendor:   "postmark" | "ses" | "resend",
 *   parser:   function (payload): normalizedEvent,    // alternative to `vendor`
 *   verify:   function (req, body, raw): boolean,     // optional authenticity gate
 *   onBounce: function (event): Promise|void,         // operator suppression hook
 *   audit:    boolean,                                 // default: true
 *   maxBytes: number,                                  // body cap; default 256 KiB
 *
 * @example
 *   var bounce = b.mailBounce.handler({
 *     vendor:   "postmark",
 *     verify:   function (req) {
 *       return req.headers.authorization === "Basic c2VjcmV0";
 *     },
 *     onBounce: function (event) {
 *       suppressionList[event.recipient] = event.subType;
 *     },
 *     maxBytes: b.constants.BYTES.kib(64),
 *   });
 *   typeof bounce; // → "function"
 *   bounce.length; // → 2
 */
function handler(opts) {
  opts = opts || {};
  var vendor = opts.vendor;
  var customParser = typeof opts.parser === "function" ? opts.parser : null;
  if (!customParser && (typeof vendor !== "string" || !VENDORS[vendor])) {
    throw _err("handler/bad-config",
      "mailBounce.handler requires { vendor } (one of " +
      Object.keys(VENDORS).join(", ") + ") or { parser }");
  }
  var verify = typeof opts.verify === "function" ? opts.verify : null;
  var onBounce = typeof opts.onBounce === "function" ? opts.onBounce : null;
  var auditOn = opts.audit !== false;
  // maxBytes must be a positive finite integer (Infinity / NaN /
  // negative / non-integer all bypass the body cap). See
  // lib/numeric-bounds for the rationale shared with every other
  // numeric-opt site swept in v0.6.69.
  var maxBytes;
  if (opts.maxBytes === undefined) {
    maxBytes = MAX_BODY_BYTES;
  } else if (!numericBounds.isPositiveFiniteInt(opts.maxBytes)) {
    throw new MailBounceError("mail-bounce/bad-opt",
      "mailBounce.handler: opts.maxBytes must be a positive finite " +
      "integer; got " + numericBounds.shape(opts.maxBytes), true);
  } else {
    maxBytes = opts.maxBytes;
  }

  function _emit(event) {
    if (!auditOn) return;
    audit().safeEmit({
      action:    "system.mail.bounce",
      outcome:   event.type === "delivery" ? "success" : "denied",
      metadata: {
        vendor:    event.vendor,
        type:      event.type,
        subType:   event.subType,
        recipient: event.recipient,
        messageId: event.messageId,
        reason:    event.reason,
        timestamp: event.timestamp,
      },
    });
  }

  function _send(res, status, body) {
    if (typeof res.writeHead === "function") {
      res.writeHead(status, { "Content-Type": "application/json" });
      res.end(JSON.stringify(body));
    }
  }

  return function mailBounceMiddleware(req, res) {
    var collector = safeBuffer.boundedChunkCollector({
      maxBytes:    maxBytes,
      errorClass:  MailBounceError,
      sizeCode:    "mailBounce/too-large",
      sizeMessage: "payload exceeds maxBytes",
    });
    var aborted = false;

    req.on("data", function (chunk) {
      if (aborted) return;
      try { collector.push(chunk); }
      catch (_e) {
        aborted = true;
        return _send(res, HTTP.PAYLOAD_TOO_LARGE, { error: "payload too large" });
      }
    });

    req.on("end", function () {
      if (aborted) return;
      var raw = collector.result();
      var body;
      try { body = safeJson.parse(raw, { maxBytes: maxBytes }); }
      catch (e) {
        return _send(res, HTTP.BAD_REQUEST, { error: "invalid JSON: " + e.message });
      }

      // Verification hook — operator decides what counts as authentic.
      // Common shapes: HMAC of body against a shared secret, Basic
      // Auth header, SNS Signature verification, X-Webhook-Signature
      // svix header. The hook receives the request + the parsed body
      // so it can sign over either form.
      if (verify) {
        var ok;
        try { ok = verify(req, body, raw); }
        catch { return _send(res, HTTP.UNAUTHORIZED, { error: "verification error" }); }
        if (!ok) return _send(res, HTTP.UNAUTHORIZED, { error: "verification failed" });
      }

      var event;
      try {
        event = customParser ? _customParser(customParser)(body) : VENDORS[vendor](body);
      } catch (e) {
        return _send(res, HTTP.BAD_REQUEST, {
          error: e.message || "parse failed",
          code:  e.code   || "parse-failed",
        });
      }

      _emit(event);

      if (!onBounce) return _send(res, HTTP.OK, { ok: true });

      Promise.resolve()
        .then(function () { return onBounce(event); })
        .then(function () { _send(res, HTTP.OK, { ok: true }); },
              function (e) {
                _send(res, HTTP.INTERNAL_SERVER_ERROR, {
                  error: "onBounce threw: " + (e && e.message),
                });
              });
    });

    req.on("error", function () {
      if (!aborted) _send(res, HTTP.BAD_REQUEST, { error: "request error" });
    });
  };
}

module.exports = {
  parse:           parse,
  handler:         handler,
  MailBounceError: MailBounceError,
  // Vendor parsers exposed for tests + advanced operator wiring (e.g.
  // operators who want to call _parsePostmark inside a custom verify
  // step before deciding whether to accept the webhook).
  vendors: {
    postmark: _parsePostmark,
    ses:      _parseSes,
    resend:   _parseResend,
  },
};
