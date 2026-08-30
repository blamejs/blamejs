// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.mail.send.deliver
 * @nav    Mail
 * @title  Outbound delivery
 * @order  240
 *
 * @intro
 *   Turnkey outbound SMTP composer. Wraps the discovery chain
 *   (MX-lookup → MTA-STS-fetch + MX-allowlist match → DANE TLSA query
 *   → REQUIRETLS handshake hint) around the existing per-host
 *   `b.mail.transports.smtp` wire-layer, plus deferred-retry scheduling
 *   for transient failures and RFC 3464 DSN generation for permanent
 *   ones.
 *
 *   Operators no longer have to glue these pieces by hand:
 *
 *     var deliver = b.mail.send.deliver.create({
 *       hostname: "mta1.example.com",
 *       policy:   { mtaSts: "enforce", dane: "opportunistic" },
 *       dsn:      { from: "mailer-daemon@example.com",
 *                   onPermanentFailure: function (env, hist) { ... } },
 *       resolver: b.network.dns.resolver.create({ ... }),
 *     });
 *
 *     var result = await deliver({
 *       from:   "ops@example.com",
 *       to:     ["alice@recipient.com", "bob@other.com"],
 *       rfc822: messageBuffer,
 *       requireTls: true,
 *     });
 *     // → { delivered: [{ recipient, mxHost, tlsProtocol, ... }],
 *     //     deferred:  [{ recipient, mxHost, reason, retryAfterMs }],
 *     //     failed:    [{ recipient, reason, dsnSent }] }
 *     //   deferred.mxHost is the receiver that refused, or null when the
 *     //   deferral happened before any host was reached (an MX lookup that
 *     //   failed). A queue view without it cannot say which peer to chase.
 *
 *   Composes:
 *     - `b.network.smtp.policy.mtaSts.fetch` + `.matchMx`  → RFC 8461 enforcement
 *     - `b.network.smtp.policy.dane.tlsa` + `.verifyChain` → RFC 7672 TLSA query
 *                                                            and peer authentication
 *     - `b.network.dns.resolver` (operator-supplied)        → caching + DoH posture
 *     - `b.mail.transports.smtp`                            → SMTP wire layer
 *     - `b.mail.requireTls`                                 → RFC 8689 REQUIRETLS
 *     - `b.mailBounce`-style RFC 3464 DSN generation         → permanent-failure
 *                                                              report-mail
 *     - `b.audit`                                            → mail.send.deliver.* events
 *     - `b.safeAsync.repeating` + operator's queue           → retry scheduling
 *                                                              (deferred deliveries
 *                                                              re-enter via the
 *                                                              `retry.scheduleRetry`
 *                                                              callback)
 *
 *   The deferred-retry surface is operator-side: this primitive
 *   classifies a recipient's outcome as "deferred" and emits a
 *   `retryAfterMs` budget; the operator's queue / scheduler re-invokes
 *   `deliver` for the deferred recipient after that elapses. The
 *   primitive does NOT own a background scheduler — that ownership
 *   lives with the operator's job-runner so a single deferred-delivery
 *   tick can't pin a long-lived process.
 *
 * @card
 *   MX → MTA-STS → DANE → SMTP → REQUIRETLS → DSN. The full outbound chain wired once.
 */

var nodeDns       = require("node:dns").promises;
var bCrypto       = require("./crypto");
var safeBuffer    = require("./safe-buffer");
var validateOpts  = require("./validate-opts");
var lazyRequire   = require("./lazy-require");
var { defineClass } = require("./framework-error");
var C             = require("./constants");

var smtpPolicy   = lazyRequire(function () { return require("./network-smtp-policy"); });
var mailModule   = lazyRequire(function () { return require("./mail"); });
var audit        = lazyRequire(function () { return require("./audit"); });

var DeliverError = defineClass("DeliverError");

var DEFAULT_PORT_SMTP            = 25;                                                              // IANA SMTP port, not a byte literal
var DEFAULT_RETRY_BACKOFF_MS     = Object.freeze([
  C.TIME.minutes(1),
  C.TIME.minutes(5),
  C.TIME.minutes(15),
  C.TIME.hours(1),
  C.TIME.hours(4),
]);
var DEFAULT_MX_LOOKUP_TIMEOUT_MS = C.TIME.seconds(10);
var DEFAULT_PER_HOST_TIMEOUT_MS  = C.TIME.seconds(60);
var MAX_RECIPIENTS_PER_CALL      = 1000;                                                            // manifest-size cap, not byte count

// ---- Outcome classifier ----

// Outbound SMTP response codes per RFC 5321 §4.2.1:
//   2xx = success (delivered to this host)
//   4xx = transient (defer + retry)
//   5xx = permanent (fail + DSN)
//
// Network-level errors (ECONNREFUSED, ETIMEDOUT, EHOSTUNREACH) are
// classified as transient and trigger MX-failover before deferring.
function _classifySmtpOutcome(err, response) {
  if (response && /^2\d\d/.test(String(response.code || ""))) return "delivered";
  // A transport error that carries a reply carries the VERDICT on that reply
  // too, and the transport is the only party that knows which command the peer
  // was answering. That matters because the reply code alone does not say how
  // far the refusal reaches: a 5xx on EHLO or the greeting rejects this
  // SESSION with this HOST, and a backup MX may take the message happily,
  // while a 5xx on RCPT TO is a verdict on the recipient. Reading the digit
  // and calling every 5xx permanent skipped the remaining MX hosts and bounced
  // deliverable mail because one host was unwilling.
  if (err && typeof err.statusCode === "number" && typeof err.permanent === "boolean") {
    return err.permanent ? "permanent" : "transient";
  }
  if (response && /^5\d\d/.test(String(response.code || ""))) return "permanent";
  if (response && /^4\d\d/.test(String(response.code || ""))) return "transient";
  if (err) {
    var code = err.code || "";
    if (/^(ECONNREFUSED|ETIMEDOUT|EHOSTUNREACH|ENETUNREACH|ENOTFOUND)$/.test(code)) return "transient";
    // A DANE failure is about THIS HOST, not this recipient: the certificate
    // did not match the records, or the records could not be used. The ordinary
    // cause is a rollover part-way through DNS propagation, which resolves
    // itself — and a DSN does not. Classified permanent it also skipped every
    // remaining MX, so one host mid-rollover bounced mail the next host would
    // have taken. RFC 7672 §2.2: try the other hosts, defer if none
    // authenticates. Matched before the policy class below, which keeps its
    // permanent verdict.
    // A peer that does not advertise REQUIRETLS is in the same position as one
    // whose DANE records did not match: the refusal is about THIS HOST, and a
    // backup MX may advertise the extension and take the message. Failing over
    // honours the flag; bouncing here would refuse mail a willing host would
    // have carried, and if none of them offers it the message ends deferred —
    // which is the honest answer, not a downgrade.
    if (/\bdane\b|requiretls/i.test((err.code || "") + " " + (err.message || ""))) return "transient";
    if (/mta-sts|tls-policy/i.test((err.code || "") + " " + (err.message || ""))) return "permanent";
  }
  return "transient";
}

// ---- DSN composer (RFC 3464) ----

// Build a multipart/report DSN body for a permanent-failure recipient.
// The composer follows the operator-facing shape — Final-Recipient,
// Action: failed, Status (enhanced status code), Diagnostic-Code (the
// 5xx response or operator-supplied reason) plus the original message
// headers per RFC 3462. Returns a raw RFC 5322 message ready to hand
// to whatever transport the operator uses for DSN delivery.
function _buildDsnMessage(opts) {
  // CRLF/NUL header-injection guard. Structured fields (addresses, the
  // reporting-MTA name, the enhanced status code) can never legitimately
  // carry CR / LF / NUL, so reject — a bounce built from a hostile
  // original sender, or from a malicious peer MX, must fail closed rather
  // than smuggle DSN headers or forge report parts. The 5xx `reason` is
  // echoed from the peer's SMTP reply and is legitimately multi-line, so
  // fold it to a single line instead of rejecting.
  var from = safeBuffer.assertHeaderSafe(opts.dsnFrom, "dsnFrom", DeliverError, "deliver/bad-dsn-field");
  var to = safeBuffer.assertHeaderSafe(opts.originalFrom, "originalFrom", DeliverError, "deliver/bad-dsn-field");
  var failedRecipient = safeBuffer.assertHeaderSafe(opts.recipient, "recipient", DeliverError, "deliver/bad-dsn-field");
  var reportingMta = safeBuffer.assertHeaderSafe(opts.reportingMta, "reportingMta", DeliverError, "deliver/bad-dsn-field");
  var statusCode = safeBuffer.assertHeaderSafe(opts.statusCode, "statusCode", DeliverError, "deliver/bad-dsn-field");
  var reason = safeBuffer.foldHeaderText(opts.reason || "permanent failure", " ");
  var origHeaders = opts.originalHeaders || "";
  var boundary = "dsn-" + bCrypto.generateToken(12);
  var nowIso = new Date().toUTCString();
  var dsnBody =
    "From: Mail Delivery System <" + from + ">\r\n" +
    "To: " + to + "\r\n" +
    "Subject: Delivery Status Notification (Failure)\r\n" +
    "Date: " + nowIso + "\r\n" +
    "MIME-Version: 1.0\r\n" +
    "Content-Type: multipart/report; report-type=delivery-status; boundary=\"" + boundary + "\"\r\n" +
    "Auto-Submitted: auto-replied\r\n" +
    "\r\n" +
    "--" + boundary + "\r\n" +
    "Content-Type: text/plain; charset=utf-8\r\n" +
    "\r\n" +
    "This is the mail delivery system at " + (reportingMta || from) + ".\r\n" +
    "\r\n" +
    "Your message to " + failedRecipient + " could not be delivered:\r\n" +
    "\r\n" +
    "    " + reason + "\r\n" +
    "\r\n" +
    "--" + boundary + "\r\n" +
    "Content-Type: message/delivery-status\r\n" +
    "\r\n" +
    // Reporting-MTA is an informational DSN header naming our own reporting MTA
    // (it falls back to the bounce-from's domain); it drives no auth decision or
    // delivery routing, so the leftmost-@ segment is acceptable here.
    // allow:leftmost-domain-informational
    "Reporting-MTA: dns; " + (reportingMta || from.split("@")[1] || "") + "\r\n" +
    "Arrival-Date: " + nowIso + "\r\n" +
    "\r\n" +
    "Final-Recipient: rfc822; " + failedRecipient + "\r\n" +
    "Action: failed\r\n" +
    "Status: " + (statusCode || "5.0.0") + "\r\n" +
    "Diagnostic-Code: smtp; " + reason + "\r\n" +
    "\r\n" +
    "--" + boundary + "\r\n" +
    "Content-Type: text/rfc822-headers\r\n" +
    "\r\n" +
    origHeaders +
    "\r\n" +
    "--" + boundary + "--\r\n";
  return dsnBody;
}

// ---- Per-recipient delivery ----

// Resolve MX records sorted by priority (lowest first per RFC 5321
// §5.1). Returns array of `{ exchange, priority }`. Empty array means
// the domain has no MX (operator's responsibility to fall back to A
// per RFC 5321 §5.1 if desired; this primitive refuses bare-A by
// default — operators that need it pass `policy.fallbackToA = true`).
async function _resolveMx(domain, resolver, timeoutMs) {
  var timer;
  var lookup = resolver
    ? resolver.queryMx(domain)
    : nodeDns.resolveMx(domain);
  var timeout = new Promise(function (_resolve, reject) {
    timer = setTimeout(function () {
      reject(new DeliverError("deliver/mx-timeout",
        "MX lookup for " + domain + " timed out after " + timeoutMs + "ms"));
    }, timeoutMs);
  });
  try {
    var mxs = await Promise.race([lookup, timeout]);
    clearTimeout(timer);
    // Normalize across resolver shapes. `node:dns` resolveMx returns an
    // array of `{ exchange, priority }` directly. `b.network.dns.resolver
    // .create()` wraps DoH and returns `{ rrs: [{ exchange, priority }],
    // ttl, ... }` — the wrapper carries TTL + provenance metadata.
    // Accept both shapes; refuse anything else.
    //
    // The resolver's records are NOT flat. b.network.dns decodes an MX RR into
    // `{ name, type, typeName, ttl, decoded: { preference, exchange } }`, so
    // reading `.exchange` off the record itself yields undefined — every MX
    // host became undefined and the first thing to touch one failed. The
    // comment above this normalisation asserted the flat shape, and no test
    // caught the disagreement because every one of them passes a hand-written
    // resolver returning exactly what the comment claimed. Only a query against
    // a real DNS response shows the difference.
    if (mxs && !Array.isArray(mxs) && Array.isArray(mxs.rrs)) {
      mxs = mxs.rrs.map(function (rr) {
        if (rr && rr.decoded && typeof rr.decoded.exchange === "string") {
          return { exchange: rr.decoded.exchange, priority: rr.decoded.preference };
        }
        return rr;                                                               // already flat
      });
    }
    if (!Array.isArray(mxs) || mxs.length === 0) {
      throw new DeliverError("deliver/no-mx",
        "no MX records published for " + domain);
    }
    // RFC 7505 — null MX: a single record { priority: 0, exchange: "" }
    // signals the domain explicitly refuses mail; abort with a
    // permanent classification.
    if (mxs.length === 1 && (mxs[0].exchange === "" || mxs[0].exchange === ".")) {
      throw new DeliverError("deliver/null-mx",
        "domain " + domain + " publishes a null MX (RFC 7505) — refuses to accept mail");
    }
    return mxs.slice().sort(function (a, b) { return a.priority - b.priority; });
  } catch (e) {
    clearTimeout(timer);
    throw e;
  }
}

// Apply MTA-STS policy per RFC 8461. Returns the chosen MX host (still
// valid after STS filtering) or throws on enforce-mode mismatch.
async function _applyMtaStsPolicy(domain, mxs, policyMode, auditEmit) {
  if (policyMode === "off") return mxs;
  var sts;
  try {
    sts = await smtpPolicy().mtaSts.fetch(domain);   // allow:raw-outbound-http-framework-internal — method call on b.network.smtp.policy wrapper, not a raw `fetch(`
  } catch (e) {
    if (policyMode === "enforce") {
      throw new DeliverError("deliver/mta-sts-fetch-failed",
        "MTA-STS fetch for " + domain + " failed under enforce policy: " + e.message);
    }
    auditEmit("mail.send.deliver.mtaSts.skip", "warn",
      { domain: domain, mode: policyMode, reason: e.message });
    return mxs;
  }
  if (!sts || sts.mode === "none") {
    auditEmit("mail.send.deliver.mtaSts.none", "info",
      { domain: domain, mode: policyMode });
    return mxs;
  }
  if (sts.mode === "testing") {
    // RFC 8461 §5.2 — a policy published in "testing" mode records
    // validation failures via TLS-RPT but MUST NOT block delivery. The
    // domain has explicitly opted out of enforcement, so the local
    // posture (even the default mtaSts:"enforce") cannot promote a
    // testing policy to a hard bounce. Deliver against the full MX set
    // and surface the match result as a report-only signal.
    var testingMatched = mxs.filter(function (m) {
      return smtpPolicy().mtaSts.matchMx(m.exchange, sts.mx || []);
    });
    auditEmit("mail.send.deliver.mtaSts.testing", "info",
      { domain: domain, mxPatterns: sts.mx,
        matched: testingMatched.length, total: mxs.length });
    return mxs;
  }
  var filtered = mxs.filter(function (m) {
    return smtpPolicy().mtaSts.matchMx(m.exchange, sts.mx || []);
  });
  if (filtered.length === 0 && sts.mode === "enforce") {
    throw new DeliverError("deliver/mta-sts-mx-mismatch",
      "no MX for " + domain + " matches the published MTA-STS policy (mode=" + sts.mode + ")");
  }
  if (filtered.length === 0) {
    // Any remaining published mode that is neither enforce nor testing
    // with no match — log and continue with the original list rather
    // than block delivery.
    auditEmit("mail.send.deliver.mtaSts.no-match", "warn",
      { domain: domain, mode: sts.mode });
    return mxs;
  }
  return filtered;
}

// Apply DANE TLSA query per RFC 7672. Returns the array of TLSA records for
// the MX host, or null when DANE is off, the records are unusable, or the peer
// publishes none. The records are handed to the transport, which authenticates
// the peer's certificate chain against them via dane.verifyChain — the lookup
// on its own is discovery, and discovery is not what "enforce" promises.
async function _fetchDaneTlsa(mxHost, port, daneMode, dnssecValidated, resolver, auditEmit) {
  if (daneMode === "off") return null;
  // RFC 7672 §1.3: records that were not DNSSEC-validated MUST NOT be used.
  // Under opportunistic with no assertion they are therefore unusable before
  // they are fetched, so asking for them buys nothing and costs a DNS round
  // trip per MX plus a warn on every delivery. `enforce` cannot reach here
  // without the assertion — create() refuses that combination outright.
  if (!dnssecValidated) return null;
  try {
    // The operator's resolver goes with the assertion: `dnssecValidated` is a
    // statement about THEIR resolver, so the records have to come from it. A
    // lookup that quietly used node:dns instead would let a non-validating
    // system resolver supply spoofed TLSA data under a validated banner.
    var tlsa = await smtpPolicy().dane.tlsa(mxHost, port || DEFAULT_PORT_SMTP,
      { dnssecValidated: true, resolver: resolver || undefined });
    return tlsa && tlsa.length > 0 ? tlsa : null;
  } catch (e) {
    auditEmit("mail.send.deliver.dane.skip", "warn",
      { mxHost: mxHost, mode: daneMode, reason: e.message });
    if (daneMode === "enforce") {
      throw new DeliverError("deliver/dane-fetch-failed",
        "DANE TLSA lookup for " + mxHost + " failed under enforce policy: " + e.message);
    }
    return null;
  }
}

// Attempt delivery to a single MX host via the framework's smtpTransport.
// `transportFactory` is operator-overrideable (composes via opts) so
// integration tests + future custom transports (e.g. a queue-backed
// outbound relay) can wrap the wire-layer surface without monkey-
// patching the framework's mail module.
async function _tryHost(envelope, mxHost, hostnameLocal, opts) {
  // `transports.smtp`, which is the name `lib/mail.js` actually exports. It was
  // reached for as `smtpTransport` — a name nothing defines — so the default was
  // `undefined`, calling it threw, the throw was classified as a transient peer
  // problem, and an operator who did not pass `transportFactory` got every
  // recipient deferred 4.4.4 forever with no socket ever opened. The option is
  // documented as an override, so the default is the path most callers take.
  var factory = opts.transportFactory || mailModule().transports.smtp;
  var transport = factory({
    host:         mxHost,
    port:         opts.port || DEFAULT_PORT_SMTP,
    ehloName:     hostnameLocal,
    timeoutMs:    opts.perHostTimeoutMs || DEFAULT_PER_HOST_TIMEOUT_MS,
    requireTls:   envelope.requireTls === true,
    // The TLSA records fetched for THIS MX host. The transport matches the
    // peer's certificate chain against them once the handshake completes and
    // refuses the send on a mismatch (RFC 7672 §2.2). Absent when the peer
    // publishes none, or when DANE is off — the transport then behaves as it
    // always did.
    dane:         envelope.tlsa || undefined,
  });
  return transport.send({
    from: envelope.from,
    to:   [envelope.recipient],
    raw:  envelope.rfc822,
  });
}

async function _deliverOne(envelope, recipient, ctx) {
  // A recipient addr-spec has exactly one '@' (RFC 5322 §3.4.1). split("@")[1]
  // on a multi-@ string (victim@internal.host@external.com) takes the LEFTMOST
  // segment, so the MX lookup + delivery would route to a domain other than the
  // intended one — a mis-delivery / exfiltration vector. Refuse a multi-@
  // recipient as a permanent bad-address rather than route to the wrong host.
  if (recipient.indexOf("@") !== recipient.lastIndexOf("@")) {
    return { recipient: recipient, outcome: "permanent",
             reason: "bad-address", reasonCode: "5.1.3" };
  }
  var domain = recipient.split("@")[1];
  if (!domain) {
    return { recipient: recipient, outcome: "permanent",
             reason: "no-domain", reasonCode: "5.1.3" };
  }
  var mxs;
  try {
    mxs = await _resolveMx(domain, ctx.resolver, ctx.mxLookupTimeoutMs);
  } catch (e) {
    var cls = (e.code === "deliver/null-mx" || e.code === "deliver/no-mx") ? "permanent" : "transient";
    return { recipient: recipient, outcome: cls, reason: e.message,
             reasonCode: cls === "permanent" ? "5.1.2" : "4.4.4" };
  }
  try {
    mxs = await _applyMtaStsPolicy(domain, mxs, ctx.policy.mtaSts, ctx.auditEmit);
  } catch (e) {
    return { recipient: recipient, outcome: "permanent",
             reason: e.message, reasonCode: "5.7.10" };   // RFC 8461 §10.3
  }
  var lastErr = null;
  var lastResponse = null;
  // The host the deferral is about. Null until one is tried, so a recipient
  // deferred before any peer was reached reports "no host" rather than
  // omitting the field — a consumer can then tell that apart from a host that
  // simply was not recorded.
  var lastMxHost = null;
  // What the hosts actually said, rather than what they did not say. Recording
  // the POSITIVE observation means a path that fails before the transport is
  // reached — a policy check, a resolver error — leaves both untouched and so
  // cannot be mistaken for "every host refused for want of REQUIRETLS".
  var _sawRequireTlsRefusal = false;
  var _sawOtherFailure      = false;
  for (var i = 0; i < mxs.length; i += 1) {
    var mx = mxs[i];
    lastMxHost = mx.exchange;
    // DANE per-MX lookup. The records go to the transport, which matches the
    // peer's certificate chain against them during the handshake.
    var mxTlsa = null;
    try {
      mxTlsa = await _fetchDaneTlsa(mx.exchange, ctx.port, ctx.policy.dane,
                                    ctx.policy.dnssecValidated, ctx.resolver,
                                    ctx.auditEmit);
    } catch (daneErr) {
      // DANE "enforce": a TLSA lookup failure means this MX host cannot
      // be used for authenticated delivery (RFC 7672 §2.2). Fail this
      // single MX over to the next candidate; if every MX for this
      // recipient fails DANE the recipient is deferred (and eventually
      // bounced once the operator's retry budget is spent). A per-
      // recipient DANE failure must never throw out of the whole
      // deliver() batch and discard the sibling recipients' outcomes —
      // it is contained here exactly like the MTA-STS enforce path.
      lastErr = daneErr;
      // A host skipped here was never ASKED about REQUIRETLS, so the run is
      // not "every host refused it" and must stay deferrable — the skipped
      // host may advertise it on the retry that follows its rollover.
      _sawOtherFailure = true;
      ctx.auditEmit("mail.send.deliver.dane-failover", "warn", {
        recipient: recipient, mxHost: mx.exchange, reason: daneErr.message,
      });
      continue;
    }
    try {
      var rv = await _tryHost({
        from:       envelope.from,
        recipient:  recipient,
        rfc822:     envelope.rfc822,
        requireTls: envelope.requireTls,
        tlsa:       mxTlsa,
      }, mx.exchange, ctx.hostname, ctx);
      ctx.auditEmit("mail.send.deliver.delivered", "success", {
        recipient: recipient, mxHost: mx.exchange, mxPriority: mx.priority,
      });
      return { recipient: recipient, outcome: "delivered", mxHost: mx.exchange,
               mxPriority: mx.priority, transportResponse: rv };
    } catch (e) {
      lastErr = e;
      // `statusCode` is what the transport sets — the peer's own numeric
      // reply, carried on the error by b.mail's MailError. This used to read
      // `e.smtpResponse`, a property nothing in the tree ever assigned, so the
      // response branches of the classifier below were unreachable and every
      // peer refusal fell through to transient: a "550 User unknown" was
      // deferred and retried for hours, against every MX in turn, and the DSN
      // the sender eventually got carried a synthesized timeout reason rather
      // than the receiver's own.
      lastResponse = (e && typeof e.statusCode === "number") ? { code: e.statusCode } : null;
      var smtpCls = _classifySmtpOutcome(e, lastResponse);
      if (smtpCls === "permanent") {
        ctx.auditEmit("mail.send.deliver.permanent-fail", "failure", {
          recipient: recipient, mxHost: mx.exchange, code: lastResponse && lastResponse.code, reason: e.message,
        });
        return { recipient: recipient, outcome: "permanent",
                 reason: e.message, reasonCode: (lastResponse && lastResponse.code) || "5.0.0",
                 mxHost: mx.exchange };
      }
      if (/requiretls/i.test((e && e.code) + " " + (e && e.message))) {
        _sawRequireTlsRefusal = true;
      } else {
        _sawOtherFailure = true;
      }
      // Transient — try next MX (if any). Audit the per-host failure
      // so operators see the MX-failover chain.
      ctx.auditEmit("mail.send.deliver.host-failover", "info", {
        recipient: recipient, mxHost: mx.exchange, code: lastResponse && lastResponse.code, reason: e.message,
      });
    }
  }
  // One transient cause does not survive exhaustion. A peer that does not
  // advertise REQUIRETLS is host-scoped while hosts remain — a backup MX may
  // offer it, and failing over honours the flag. Once every host has been
  // asked and none does, the answer is settled: RFC 8689 §4.1 makes such a
  // message undeliverable, and deferring it would retry that same discovery on
  // every schedule tick forever while the sender waits for a bounce that never
  // comes. The verdict changes because the evidence did, not the rule.
  if (_sawRequireTlsRefusal && !_sawOtherFailure) {
    ctx.auditEmit("mail.send.deliver.permanent-fail", "failure", {
      recipient: recipient, mxHost: lastMxHost, reason: (lastErr && lastErr.message) || "",
      cause: "requiretls-unsupported-by-every-mx",
    });
    return { recipient: recipient, outcome: "permanent", mxHost: lastMxHost,
             reason: "requireTls was asked for and no MX host for this recipient " +
                     "advertises REQUIRETLS (RFC 8689 §4.1)",
             reasonCode: "5.7.30" };                                                                     // allow:raw-byte-literal — RFC 8689 §4.4 enhanced status
  }
  // All MX hosts returned transient — overall outcome is transient
  // (defer + retry). `mxHost` names the last host tried, because a queue an
  // operator reads on a bad day has to answer WHICH receiver refused: a domain
  // with several MX hosts defers on one of them, and that decides whether to
  // wait, to contact that receiver, or to look at one's own transport security
  // against that host.
  return { recipient: recipient, outcome: "transient",
           mxHost: lastMxHost,
           reason: (lastErr && lastErr.message) || "all MX hosts failed transiently",
           reasonCode: (lastResponse && lastResponse.code) || "4.4.4" };
}

// ---- Public factory ----

/**
 * @primitive b.mail.send.deliver.create
 * @signature b.mail.send.deliver.create(opts)
 * @since     0.11.24
 * @status    stable
 *
 * Build a turnkey delivery handle. Returns a `deliver(envelope)`
 * function that takes a single multi-recipient envelope, resolves
 * MX records per recipient domain, applies the operator's configured
 * MTA-STS / DANE policy, attempts delivery via `b.mail.transports.smtp`,
 * and returns a per-recipient outcome split into `delivered` /
 * `deferred` / `failed` arrays.
 *
 * Deferred recipients carry `retryAfterMs` budgets the operator's
 * queue / scheduler honors by re-invoking `deliver` for that subset
 * after the budget elapses. The primitive does not own a background
 * scheduler — operator job-runner owns the retry lifecycle.
 *
 * DANE (RFC 7672) authenticates the peer, not just its DNS. When the peer
 * publishes TLSA records, they are fetched and the certificate chain it
 * presents during the handshake is matched against them; a peer whose chain
 * matches none of its own records is refused and the next MX is tried.
 *
 * The TLSA lookup goes through `opts.resolver` when one is supplied, because
 * the DNSSEC assertion below is a statement about THAT resolver. A resolver
 * that cannot answer TLSA is refused rather than bypassed.
 *
 * Because RFC 7672 §1.3 forbids using records that were not DNSSEC-validated
 * and node:dns does not expose the AD bit, only the operator can say whether
 * their resolver validates. `policy.dnssecValidated: true` is that statement,
 * and `dane: "enforce"` requires it: without it every peer that publishes TLSA
 * would be refused while every peer that publishes none was delivered to.
 * Under `"opportunistic"` the records are unusable without it, so none are
 * fetched.
 *
 * Failed recipients trigger DSN composition: a RFC 3464 multipart/
 * report message is built per failed recipient and handed to the
 * operator-supplied `dsn.onPermanentFailure(envelope, recipientResult,
 * dsnMessage)` callback. The callback is responsible for delivering
 * the DSN itself (typically by re-entering the same `deliver` handle
 * with the original sender as recipient — but operators who want
 * a separate transport for DSNs wire that here).
 *
 * @opts
 *   hostname:   string,                    // required — local hostname for HELO/EHLO + DSN Reporting-MTA
 *   port:       number,                    // default 25 (IANA SMTP, RFC 5321) — set 587 (RFC 6409 submission) or 465 (RFC 8314 implicit-TLS) for a smarthost relay
 *   resolver:   object | null,             // optional — b.network.dns.resolver handle; falls back to node:dns when omitted
 *   policy: {
 *     mtaSts:   "enforce" | "testing" | "off",  // default "enforce" — RFC 8461 posture
 *     dane:     "opportunistic" | "enforce" | "off",  // default "opportunistic" — RFC 7672
 *     dnssecValidated: boolean,            // default false — assert the resolver DNSSEC-validates; required by dane "enforce"
 *   },
 *   retry: {
 *     maxAttempts:  number,                // default 5
 *     backoffMs:    Array<number>,         // default [1m, 5m, 15m, 1h, 4h]
 *   },
 *   dsn: {
 *     from:     string,                    // required when dsn.onPermanentFailure is set
 *     onPermanentFailure: function (envelope, result, dsnMessage) → Promise,
 *   },
 *   timeouts: {
 *     mxLookupMs: number,                  // default 10s
 *     perHostMs:  number,                  // default 60s
 *   },
 *   audit:      boolean,                   // default true
 *
 * @example
 *   var deliver = b.mail.send.deliver.create({
 *     hostname: "mta1.example.com",
 *     policy:   { mtaSts: "enforce", dane: "opportunistic" },
 *     dsn:      { from: "mailer-daemon@example.com",
 *                 onPermanentFailure: function (env, res, dsn) {
 *                   return deliver({ from: env.from, to: [env.from], rfc822: Buffer.from(dsn) });
 *                 } },
 *   });
 *   var result = await deliver({
 *     from:   "ops@example.com",
 *     to:     ["alice@recipient.com"],
 *     rfc822: messageBuffer,
 *   });
 *   typeof result.delivered;   // → "object" (array)
 *   typeof result.deferred;    // → "object" (array)
 *   typeof result.failed;      // → "object" (array)
 */
function create(opts) {
  if (!opts || typeof opts !== "object") {
    throw new DeliverError("deliver/bad-opts", "mail.send.deliver.create: opts is required");
  }
  validateOpts(opts,
    ["hostname", "resolver", "policy", "retry", "dsn", "timeouts", "audit", "transportFactory", "port"],
    "mail.send.deliver.create");
  // hostname is required; opts.port (when present) must be a valid connect
  // port. Submission/smarthost relays listen on 587 (RFC 6409) or
  // implicit-TLS 465 (RFC 8314) rather than the IANA SMTP port 25
  // (RFC 5321 §2.3.4) that direct MX delivery uses. Operators routing
  // through such a relay set opts.port; the value is range-checked here
  // (RFC 6335 §6) so a typo fails at config time, not on the first
  // connect attempt.
  // The shape is the authoritative, exhaustive opts contract: every key
  // the factory accepts is declared here. hostname + port carry their
  // final per-field codes; the sub-object opts (policy / retry / dsn /
  // timeouts) are shape-checked only for object-ness here, with their
  // field-level validation (and the distinct per-field codes operators
  // see) applied below where each sub-object is resolved.
  validateOpts.shape(opts, {
    hostname:         { rule: "required-string", code: "deliver/bad-hostname",
                        label: "mail.send.deliver.create: hostname (local HELO/EHLO + DSN Reporting-MTA)" },
    port:             { rule: "optional-port", code: "deliver/bad-port" },
    resolver:         { rule: "optional-plain-object", code: "deliver/bad-resolver",
                        label: "mail.send.deliver.create: resolver (b.network.dns.resolver handle)" },
    policy:           { rule: "optional-plain-object", code: "deliver/bad-policy" },
    retry:            { rule: "optional-plain-object", code: "deliver/bad-retry" },
    dsn:              { rule: "optional-plain-object", code: "deliver/bad-dsn" },
    timeouts:         { rule: "optional-plain-object", code: "deliver/bad-timeouts" },
    audit:            { rule: "optional-boolean", code: "deliver/bad-audit" },
    transportFactory: { rule: "optional-function", code: "deliver/bad-transport-factory" },
  }, "mail.send.deliver.create", DeliverError, "deliver/bad-opts");
  var port = opts.port || DEFAULT_PORT_SMTP;

  var policy = opts.policy || {};
  validateOpts(policy, ["mtaSts", "dane", "dnssecValidated"], "mail.send.deliver.create.policy");
  var policyMtaSts = policy.mtaSts || "enforce";
  if (["enforce", "testing", "off"].indexOf(policyMtaSts) === -1) {
    throw new DeliverError("deliver/bad-policy-mtaSts",
      "mail.send.deliver.create.policy.mtaSts must be enforce|testing|off");
  }
  var policyDane = policy.dane || "opportunistic";
  if (["opportunistic", "enforce", "off"].indexOf(policyDane) === -1) {
    throw new DeliverError("deliver/bad-policy-dane",
      "mail.send.deliver.create.policy.dane must be opportunistic|enforce|off");
  }
  // RFC 7672 §1.3 forbids using TLSA records that were not DNSSEC-validated,
  // and node:dns does not surface the AD bit, so only the operator can say
  // whether their resolver validates. Without that assertion `enforce` refuses
  // every peer that publishes TLSA while delivering normally to every peer that
  // publishes none — the sender's misconfiguration charged to the recipient who
  // did the work. It is a property of this sender's resolver, so it is settled
  // once at create() rather than surfacing per-peer as a delivery failure.
  if (policy.dnssecValidated !== undefined && typeof policy.dnssecValidated !== "boolean") {
    throw new DeliverError("deliver/bad-policy-dnssec",
      "mail.send.deliver.create.policy.dnssecValidated must be a boolean when set");
  }
  var daneDnssecValidated = policy.dnssecValidated === true;
  if (policyDane === "enforce" && !daneDnssecValidated) {
    throw new DeliverError("deliver/dane-no-dnssec",
      "policy.dane \"enforce\" requires policy.dnssecValidated: true — TLSA records " +
      "must be DNSSEC-validated before use (RFC 7672 §1.3), and without that " +
      "assertion enforce can only refuse the peers that publish them. Set it when " +
      "the resolver validates DNSSEC; otherwise use \"opportunistic\" or \"off\"");
  }

  var retryOpts = opts.retry || {};
  validateOpts(retryOpts, ["maxAttempts", "backoffMs"], "mail.send.deliver.create.retry");
  // Config-time entry-point opts: a typo (maxAttempts:"5", mxLookupMs:-1)
  // must fail at create(), not silently fall back to the default. Absent
  // keeps the default; present-but-bad throws. Matches opts.port above.
  validateOpts.optionalPositiveInt(retryOpts.maxAttempts,
    "mail.send.deliver.create.retry.maxAttempts", DeliverError, "deliver/bad-retry-maxAttempts");
  var maxAttempts = retryOpts.maxAttempts !== undefined
    ? retryOpts.maxAttempts : DEFAULT_RETRY_BACKOFF_MS.length;
  var backoffMs = Array.isArray(retryOpts.backoffMs) && retryOpts.backoffMs.length > 0
    ? retryOpts.backoffMs.slice() : DEFAULT_RETRY_BACKOFF_MS.slice();

  var timeouts = opts.timeouts || {};
  validateOpts(timeouts, ["mxLookupMs", "perHostMs"], "mail.send.deliver.create.timeouts");
  validateOpts.shape(timeouts, {
    mxLookupMs: { rule: "optional-positive-int", code: "deliver/bad-timeout-mxLookupMs",
                  label: "mail.send.deliver.create.timeouts.mxLookupMs" },
    perHostMs:  { rule: "optional-positive-int", code: "deliver/bad-timeout-perHostMs",
                  label: "mail.send.deliver.create.timeouts.perHostMs" },
  }, "mail.send.deliver.create.timeouts", DeliverError, "deliver/bad-timeouts");
  var mxLookupTimeoutMs = timeouts.mxLookupMs !== undefined
    ? timeouts.mxLookupMs : DEFAULT_MX_LOOKUP_TIMEOUT_MS;
  var perHostTimeoutMs = timeouts.perHostMs !== undefined
    ? timeouts.perHostMs : DEFAULT_PER_HOST_TIMEOUT_MS;

  var dsnOpts = opts.dsn || null;
  if (dsnOpts) {
    validateOpts(dsnOpts, ["from", "onPermanentFailure"],
      "mail.send.deliver.create.dsn");
    validateOpts.requireNonEmptyString(dsnOpts.from,
      "mail.send.deliver.create.dsn.from", DeliverError, "deliver/bad-dsn-from");
    if (typeof dsnOpts.onPermanentFailure !== "function") {
      throw new DeliverError("deliver/bad-dsn-callback",
        "mail.send.deliver.create.dsn.onPermanentFailure must be a function");
    }
  }

  var auditEnabled = opts.audit !== false;
  var _auditEmit = audit().namespaced(null, { audit: auditEnabled });

  async function deliver(envelope) {
    if (!envelope || typeof envelope !== "object") {
      throw new DeliverError("deliver/bad-envelope",
        "deliver: envelope is required");
    }
    // The EMPTY string is a value here, not a missing one: RFC 5321 §4.5.5
    // requires the null reverse path `MAIL FROM:<>` for a delivery status
    // notification, and `b.mail.transports.smtp` already turns `""` into
    // exactly that. Refusing it as "non-empty required" meant this composer
    // could not send the one message shape the spec reserves a syntax for, and
    // its own documented DSN example put a real address in the reverse path —
    // so a bounce that failed would bounce back to the bounce's sender.
    //
    // The framework's other readers of an envelope sender already know this:
    // `b.mail.spf.verify` treats an empty `mailFrom` as the null sender and
    // falls back to the HELO identity, which is RFC 7208 §2.4 exactly.
    if (typeof envelope.from !== "string") {
      throw new DeliverError("deliver/bad-envelope-from",
        "deliver.envelope.from must be a string — use \"\" for the null " +
        "reverse path (MAIL FROM:<>) that RFC 5321 requires of a DSN");
    }
    if (!Array.isArray(envelope.to) || envelope.to.length === 0) {
      throw new DeliverError("deliver/bad-envelope-to",
        "deliver.envelope.to must be a non-empty array");
    }
    if (envelope.to.length > MAX_RECIPIENTS_PER_CALL) {
      throw new DeliverError("deliver/too-many-recipients",
        "deliver.envelope.to length " + envelope.to.length + " exceeds cap " + MAX_RECIPIENTS_PER_CALL);
    }
    if (!Buffer.isBuffer(envelope.rfc822) && typeof envelope.rfc822 !== "string") {
      throw new DeliverError("deliver/bad-envelope-rfc822",
        "deliver.envelope.rfc822 must be a Buffer or string (raw RFC 822 message bytes)");
    }
    var raw = Buffer.isBuffer(envelope.rfc822) ? envelope.rfc822 : Buffer.from(envelope.rfc822, "utf8");

    var ctx = {
      resolver:           opts.resolver || null,
      policy:             { mtaSts: policyMtaSts, dane: policyDane,
                            dnssecValidated: daneDnssecValidated },
      hostname:           opts.hostname,
      port:               port,
      mxLookupTimeoutMs:  mxLookupTimeoutMs,
      perHostTimeoutMs:   perHostTimeoutMs,
      transportFactory:   opts.transportFactory || null,
      auditEmit:          _auditEmit,
    };

    var delivered = [];
    var deferred  = [];
    var failed    = [];

    for (var i = 0; i < envelope.to.length; i += 1) {
      var recipient = envelope.to[i];
      var res = await _deliverOne({
        from:        envelope.from,
        rfc822:      raw,
        requireTls:  envelope.requireTls === true,
      }, recipient, ctx);

      if (res.outcome === "delivered") {
        delivered.push({
          recipient:         res.recipient,
          mxHost:            res.mxHost,
          mxPriority:        res.mxPriority,
          deliveredAt:       Date.now(),
          transportResponse: res.transportResponse || null,
        });
        continue;
      }
      if (res.outcome === "transient") {
        var attempts = (envelope.attempt || 0) + 1;
        if (attempts >= maxAttempts) {
          // Convert transient → permanent after the operator's
          // documented retry budget is exhausted.
          res.outcome = "permanent";
          res.reason = (res.reason || "retry exhausted") + " (after " + attempts + " attempts)";
        } else {
          var idx = Math.min(attempts - 1, backoffMs.length - 1);
          deferred.push({
            recipient:     res.recipient,
            // The receiver the deferral is about, or null when none was
            // reached. A queue that records the reason and the retry time and
            // not the peer cannot answer the first question an operator asks.
            mxHost:        res.mxHost === undefined ? null : res.mxHost,
            reason:        res.reason,
            reasonCode:    res.reasonCode,
            attempt:       attempts,
            retryAfterMs:  backoffMs[idx],
          });
          continue;
        }
      }
      // permanent (either direct or transient-converted-to-permanent)
      var dsnSent = false;
      // A message sent with the NULL reverse path gets no DSN. RFC 5321 §4.5.5
      // is explicit, and the reason is the whole point of the null sender: the
      // DSN's `To:` is the original `from`, so bouncing a bounce addresses it
      // to nobody and, where the peer is less careful, to itself. This is the
      // loop the empty reverse path exists to stop, and it is reachable the
      // moment `""` is accepted above.
      if (dsnOpts && envelope.from !== "") {
        try {
          var dsnMessage = _buildDsnMessage({
            dsnFrom:         dsnOpts.from,
            originalFrom:    envelope.from,
            recipient:       res.recipient,
            reason:          res.reason,
            statusCode:      res.reasonCode,
            reportingMta:    ctx.hostname,
            originalHeaders: _extractHeaderBlock(raw),
          });
          await dsnOpts.onPermanentFailure(envelope, res, dsnMessage);
          dsnSent = true;
        } catch (dsnErr) {
          _auditEmit("mail.send.deliver.dsn-failed", "failure", {
            recipient: res.recipient, error: dsnErr.message,
          });
        }
      }
      failed.push({
        recipient:  res.recipient,
        reason:     res.reason,
        reasonCode: res.reasonCode,
        mxHost:     res.mxHost || null,
        dsnSent:    dsnSent,
      });
    }

    _auditEmit("mail.send.deliver.batch", "success", {
      from:        envelope.from,
      delivered:   delivered.length,
      deferred:    deferred.length,
      failed:      failed.length,
    });

    return {
      delivered: delivered,
      deferred:  deferred,
      failed:    failed,
    };
  }

  // Expose helpers for operator-side testing / introspection.
  deliver.classifyOutcome = _classifySmtpOutcome;
  deliver.buildDsn        = _buildDsnMessage;
  return deliver;
}

// Extract the header block (everything before the first CRLF CRLF) for
// inclusion in the DSN per RFC 3462 §3.
function _extractHeaderBlock(raw) {
  var s = raw.toString("utf8");
  var sep = s.indexOf("\r\n\r\n");
  if (sep === -1) sep = s.indexOf("\n\n");
  if (sep === -1) return s;
  return s.slice(0, sep + 2);
}

module.exports = {
  create:        create,
  DeliverError:  DeliverError,
};
