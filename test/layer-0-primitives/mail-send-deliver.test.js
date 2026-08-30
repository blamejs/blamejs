// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.mail.send.deliver — turnkey outbound composer.
 *
 * Tests exercise the operator-facing surface without opening real
 * SMTP sockets:
 *   - factory validation
 *   - outcome classifier (2xx/4xx/5xx + network errors)
 *   - DSN composition (RFC 3464 multipart/report shape)
 *   - per-recipient defer/fail bookkeeping via a stubbed transport
 *
 * Live wire-protocol coverage lives in test/integration/ — this layer
 * mocks the SMTP transport to verify the composer's classify-route-
 * compose logic. Error / adversarial branches are exercised here too:
 * classifier fallthroughs, every create() validation code, resolver
 * shape variance + timeout + node:dns fallback, the MTA-STS / DANE
 * policy matrices (fault-injected by swapping b.network.smtp.policy's
 * mtaSts / dane exports for in-memory stubs, restored in a finally),
 * DSN default fields + callback failure, header-block separator
 * variants, and the retry-budget clamp.
 */

var helpers        = require("../helpers");
var smtpPolicyMod  = require("../../lib/network-smtp-policy");
var dnsPromises    = require("node:dns").promises;

var b     = helpers.b;
var check = helpers.check;

// ---- Surface ----

function testSurface() {
  check("b.mail.send namespace",       typeof b.mail.send === "object");
  check("b.mail.send.deliver fn",      typeof b.mail.send.deliver === "function");
  check("DeliverError class",          typeof b.mail.send.deliver.DeliverError === "function");
}

// ---- Factory validation ----

function testFactoryRefusesBadOpts() {
  function threw(fn) {
    try { fn(); return null; }
    catch (e) { return e; }
  }
  var e1 = threw(function () { b.mail.send.deliver(); });
  check("create() w/o opts → DeliverError", e1 && e1.code === "deliver/bad-opts");

  var e2 = threw(function () { b.mail.send.deliver({}); });
  check("create({}) w/o hostname → DeliverError",
    e2 && e2.code === "deliver/bad-hostname");

  var e3 = threw(function () {
    b.mail.send.deliver({ hostname: "m.example", policy: { mtaSts: "bogus" } });
  });
  check("bad policy.mtaSts → DeliverError",
    e3 && e3.code === "deliver/bad-policy-mtaSts");

  var e4 = threw(function () {
    b.mail.send.deliver({ hostname: "m.example", policy: { dane: "lax" } });
  });
  check("bad policy.dane → DeliverError",
    e4 && e4.code === "deliver/bad-policy-dane");

  var e5 = threw(function () {
    b.mail.send.deliver({
      hostname: "m.example",
      dsn:      { from: "mailer@m.example" },                   // missing onPermanentFailure
    });
  });
  check("dsn without onPermanentFailure → DeliverError",
    e5 && e5.code === "deliver/bad-dsn-callback");

  var e6 = threw(function () {
    b.mail.send.deliver({ hostname: "m.example", port: 70000 }); // out of [1,65535]
  });
  check("out-of-range port → DeliverError",
    e6 && e6.code === "deliver/bad-port");

  var e7 = threw(function () {
    b.mail.send.deliver({ hostname: "m.example", port: 0 });     // 0 is not a connect port
  });
  check("port 0 → DeliverError (connect port must be >=1)",
    e7 && e7.code === "deliver/bad-port");

  // retry.maxAttempts / timeouts.mxLookupMs / timeouts.perHostMs are
  // config-time entry-point opts: a typo must throw at create(), not be
  // swallowed by a valid-or-default fallback. Absent keeps the default.
  var e8 = threw(function () {
    b.mail.send.deliver({ hostname: "m.example", retry: { maxAttempts: "5" } });
  });
  check("retry.maxAttempts as string → DeliverError",
    e8 && e8.code === "deliver/bad-retry-maxAttempts");

  var e9 = threw(function () {
    b.mail.send.deliver({ hostname: "m.example", retry: { maxAttempts: -1 } });
  });
  check("retry.maxAttempts negative → DeliverError",
    e9 && e9.code === "deliver/bad-retry-maxAttempts");

  var e10 = threw(function () {
    b.mail.send.deliver({ hostname: "m.example", retry: { maxAttempts: 0 } });
  });
  check("retry.maxAttempts 0 → DeliverError (must be >= 1)",
    e10 && e10.code === "deliver/bad-retry-maxAttempts");

  var e11 = threw(function () {
    b.mail.send.deliver({ hostname: "m.example", timeouts: { mxLookupMs: -1 } });
  });
  check("timeouts.mxLookupMs negative → DeliverError",
    e11 && e11.code === "deliver/bad-timeout-mxLookupMs");

  var e12 = threw(function () {
    b.mail.send.deliver({ hostname: "m.example", timeouts: { mxLookupMs: "10000" } });
  });
  check("timeouts.mxLookupMs as string → DeliverError",
    e12 && e12.code === "deliver/bad-timeout-mxLookupMs");

  var e13 = threw(function () {
    b.mail.send.deliver({ hostname: "m.example", timeouts: { perHostMs: 0 } });
  });
  check("timeouts.perHostMs 0 → DeliverError (must be >= 1)",
    e13 && e13.code === "deliver/bad-timeout-perHostMs");

  // Absent retry / timeouts keys keep the defaults — create() succeeds.
  var okDefault = threw(function () {
    b.mail.send.deliver({ hostname: "m.example", retry: {}, timeouts: {}, audit: false });
  });
  check("absent retry/timeouts keys keep defaults (create succeeds)", okDefault === null);

  // Valid integer values are accepted unchanged.
  var okValid = threw(function () {
    b.mail.send.deliver({
      hostname: "m.example",
      retry:    { maxAttempts: 3 },
      timeouts: { mxLookupMs: 2000, perHostMs: 30000 },
      audit:    false,
    });
  });
  check("valid retry/timeouts values accepted (create succeeds)", okValid === null);
}

// ---- Submission/smarthost port ----

// The default is IANA SMTP 25; an operator routing through a submission
// relay sets port 587 (RFC 6409) / 465 (RFC 8314). The configured port
// must reach the transport factory.
async function testPortReachesTransport() {
  var ports = [];
  var fakeResolver = {
    queryMx: async function (domain) {
      return [{ exchange: "mx1." + domain, priority: 10 }];
    },
  };
  var fakeTransport = function (opts) {
    ports.push(opts.port);
    return { send: async function () { return { ok: true, code: 250 }; } };
  };

  var deliverDefault = b.mail.send.deliver({
    hostname: "mta1.example.com", resolver: fakeResolver,
    policy: { mtaSts: "off", dane: "off" }, transportFactory: fakeTransport, audit: false,
  });
  await deliverDefault({ from: "ops@example.com", to: ["a@recipient.com"], rfc822: Buffer.from("hi") });
  check("port: default is 25 when unset", ports[ports.length - 1] === 25);

  var deliver587 = b.mail.send.deliver({
    hostname: "mta1.example.com", resolver: fakeResolver, port: 587,
    policy: { mtaSts: "off", dane: "off" }, transportFactory: fakeTransport, audit: false,
  });
  await deliver587({ from: "ops@example.com", to: ["b@recipient.com"], rfc822: Buffer.from("hi") });
  check("port: configured 587 reaches the transport", ports[ports.length - 1] === 587);
}

// ---- Envelope shape validation ----

async function testEnvelopeValidation() {
  var deliver = b.mail.send.deliver({ hostname: "m.example", audit: false });
  function threwAsync(fn) {
    return fn().then(function () { return null; }, function (e) { return e; });
  }
  check("envelope must be object",
    (await threwAsync(function () { return deliver(); })).code === "deliver/bad-envelope");
  check("envelope.from required",
    (await threwAsync(function () { return deliver({ to: ["a@b"], rfc822: Buffer.from("x") }); })).code === "deliver/bad-envelope-from");
  check("envelope.to required",
    (await threwAsync(function () { return deliver({ from: "x@y", rfc822: Buffer.from("x") }); })).code === "deliver/bad-envelope-to");
  check("envelope.to empty array refused",
    (await threwAsync(function () { return deliver({ from: "x@y", to: [], rfc822: Buffer.from("x") }); })).code === "deliver/bad-envelope-to");
  check("envelope.rfc822 must be Buffer/string",
    (await threwAsync(function () { return deliver({ from: "x@y", to: ["a@b"], rfc822: 42 }); })).code === "deliver/bad-envelope-rfc822");
}

// ---- Outcome classifier ----

function testOutcomeClassifier() {
  var deliver = b.mail.send.deliver({ hostname: "m.example", audit: false });
  // SMTP response codes.
  check("250 → delivered",  deliver.classifyOutcome(null, { code: 250 }) === "delivered");
  check("220 → delivered",  deliver.classifyOutcome(null, { code: 220 }) === "delivered");
  check("451 → transient",  deliver.classifyOutcome(null, { code: 451 }) === "transient");
  check("452 → transient",  deliver.classifyOutcome(null, { code: 452 }) === "transient");
  check("550 → permanent",  deliver.classifyOutcome(null, { code: 550 }) === "permanent");
  check("554 → permanent",  deliver.classifyOutcome(null, { code: 554 }) === "permanent");
  // Those three pass a `response` the delivery path never had: it was read
  // from `err.smtpResponse`, which nothing in the tree ever set. So the
  // response branches were dead and every peer refusal — at any code, at any
  // step — fell through to transient, burning the whole retry budget on a
  // "User unknown" the receiver answered immediately. The classifier has to
  // answer for the error the TRANSPORT actually constructs.
  var rejected = new b.mail.MailError("mail/smtp-failed",
    "SMTP send failed: rcpt-rejected (code 550)", true, 550);
  check("the transport's own 5yz error → permanent",
    deliver.classifyOutcome(rejected, rejected.statusCode == null ? null
      : { code: rejected.statusCode }) === "permanent",
    JSON.stringify({ statusCode: rejected.statusCode, permanent: rejected.permanent }));
  var deferred = new b.mail.MailError("mail/smtp-failed",
    "SMTP send failed: rcpt-rejected (code 451)", false, 451);
  check("the transport's own 4yz error → transient",
    deliver.classifyOutcome(deferred, deferred.statusCode == null ? null
      : { code: deferred.statusCode }) === "transient");
  // Network errors → transient (allow MX-failover).
  check("ECONNREFUSED → transient",
    deliver.classifyOutcome({ code: "ECONNREFUSED" }, null) === "transient");
  check("ETIMEDOUT → transient",
    deliver.classifyOutcome({ code: "ETIMEDOUT" }, null) === "transient");
  check("ENOTFOUND → transient",
    deliver.classifyOutcome({ code: "ENOTFOUND" }, null) === "transient");
  // Policy-class errors → permanent.
  check("mta-sts-mx-mismatch → permanent",
    deliver.classifyOutcome({ code: "deliver/mta-sts-mx-mismatch", message: "" }, null) === "permanent");
  // A peer not advertising REQUIRETLS is host-scoped, like a DANE mismatch: a
  // backup MX may offer it, and failing over honours the flag rather than
  // violating it. Bouncing here would refuse mail a willing host would carry.
  check("requiretls-not-advertised → transient, so the next MX gets a turn",
    deliver.classifyOutcome({ code: "mail/requiretls-not-advertised", message: "" }, null)
      === "transient");
  // A DANE failure is NOT in that class. The TLSA lookup failing, or the
  // certificate not matching, says this host could not be authenticated — most
  // often a rollover mid-propagation or a DNS blip, both of which resolve
  // themselves. Bouncing the recipient turns recoverable mail into a DSN, and
  // as a permanent verdict it also skipped every remaining MX. Deferred, the
  // sender retries and the other hosts get their turn (RFC 7672 §2.2).
  check("dane-fetch-failed (enforce) → transient",
    deliver.classifyOutcome({ code: "deliver/dane-fetch-failed", message: "" }, null) === "transient");
}

// And the delivery path itself, which is where the reading happened. A peer
// answering 550 has permanently refused the recipient (RFC 5321 §4.2.1); the
// message belongs in `failed` with the receiver's own code, not in `deferred`
// to be retried for hours against a mailbox that does not exist.
async function testPeerRefusalIsAHardBounce() {
  var fakeResolver = { queryMx: async function (d) {
    return [{ exchange: "mx1." + d, priority: 10 }, { exchange: "mx2." + d, priority: 20 }]; } };
  var attempts = [];
  function _refusingTransport(code, permanent) {
    return function (opts) {
      return { send: async function () {
        attempts.push(opts.host);
        throw new b.mail.MailError("mail/smtp-failed",
          "SMTP send failed: rcpt-rejected (code " + code + ")", permanent, code);
      } };
    };
  }

  var hard = b.mail.send.deliver({
    hostname: "mta1.example.com", resolver: fakeResolver,
    policy: { mtaSts: "off", dane: "off" },
    transportFactory: _refusingTransport(550, true), audit: false,
  });
  var hardRes = await hard({
    from: "s@a.test", to: ["nobody@recipient.com"],
    rfc822: Buffer.from("From: s@a.test\r\nTo: nobody@recipient.com\r\n\r\nx"),
  });
  check("a 550 recipient refusal is a hard bounce, not a deferral",
    hardRes.failed.length === 1 && hardRes.deferred.length === 0,
    JSON.stringify({ failed: hardRes.failed.length, deferred: hardRes.deferred.length }));
  // A permanent verdict is the only one that stops the MX failover loop, so a
  // recipient the first host refused outright was offered to every other host.
  check("and it is not offered to the next MX",
    attempts.length === 1, JSON.stringify(attempts));
  // RFC 3464 §2.3.4 — the DSN `Status:` field is an ENHANCED status, not the
  // three-digit SMTP reply. The reply belongs in Diagnostic-Code, and it is
  // already there inside the transport's reason. `Status: 550` is what a
  // conforming parser rejects or misreads.
  check("the reported code is an enhanced status, not the bare SMTP reply",
    /^\d\.\d+\.\d+$/.test(String(hardRes.failed[0].reasonCode)),
    JSON.stringify(hardRes.failed[0].reasonCode));
  check("and it carries the reply's class",
    String(hardRes.failed[0].reasonCode).charAt(0) === "5",
    JSON.stringify(hardRes.failed[0].reasonCode));
  check("while the peer's own reply is still in the reason the DSN quotes",
    /550/.test(String(hardRes.failed[0].reason)), JSON.stringify(hardRes.failed[0].reason));

  attempts.length = 0;
  var soft = b.mail.send.deliver({
    hostname: "mta1.example.com", resolver: fakeResolver,
    policy: { mtaSts: "off", dane: "off" },
    transportFactory: _refusingTransport(451, false), audit: false,
  });
  var softRes = await soft({
    from: "s@a.test", to: ["busy@recipient.com"],
    rfc822: Buffer.from("From: s@a.test\r\nTo: busy@recipient.com\r\n\r\nx"),
  });
  check("CONTROL — a 451 is still deferred, so 550 did not simply turn retries off",
    softRes.deferred.length === 1 && softRes.failed.length === 0,
    JSON.stringify({ failed: softRes.failed.length, deferred: softRes.deferred.length }));

  // A 5xx is not a verdict on the recipient when it answered a SESSION-level
  // command. The transport says so — it knows which command the peer replied
  // to — and reading the digit instead would skip every remaining MX and
  // bounce mail the backup host would have taken.
  attempts.length = 0;
  var sessionRefusal = b.mail.send.deliver({
    hostname: "mta1.example.com", resolver: fakeResolver,
    policy: { mtaSts: "off", dane: "off" }, audit: false,
    transportFactory: function (opts) {
      return { send: async function () {
        attempts.push(opts.host);
        // What the transport builds for `500 ehlo-rejected`: the code travels,
        // the verdict does not reach the message.
        throw new b.mail.MailError("mail/smtp-failed",
          "SMTP send failed: ehlo-rejected (code 500)", false, 500);
      } };
    },
  });
  var sessionRes = await sessionRefusal({
    from: "s@a.test", to: ["ok@recipient.com"],
    rfc822: Buffer.from("From: s@a.test\r\nTo: ok@recipient.com\r\n\r\nx"),
  });
  check("a session-scoped 5xx tries the next MX rather than bouncing",
    attempts.length === 2, JSON.stringify(attempts));
  check("and the recipient is deferred, not failed",
    sessionRes.deferred.length === 1 && sessionRes.failed.length === 0,
    JSON.stringify({ failed: sessionRes.failed.length, deferred: sessionRes.deferred.length }));

  // A REQUIRETLS refusal fails over while hosts remain — a backup MX may offer
  // it — but once every host has been asked and none does, the answer is
  // settled. RFC 8689 §4.1 makes the message undeliverable, and deferring it
  // would rediscover the same fact on every schedule tick while the sender
  // waits for a bounce that never arrives.
  attempts.length = 0;
  var noRequireTls = b.mail.send.deliver({
    hostname: "mta1.example.com", resolver: fakeResolver,
    policy: { mtaSts: "off", dane: "off" }, audit: false,
    transportFactory: function (opts) {
      return { send: async function () {
        attempts.push(opts.host);
        throw new b.mail.MailError("mail/requiretls-not-advertised",
          "requireTls was asked for but the peer does not advertise REQUIRETLS", false);
      } };
    },
  });
  var rtRes = await noRequireTls({
    from: "s@a.test", to: ["secure@recipient.com"],
    rfc822: Buffer.from("From: s@a.test\r\nTo: secure@recipient.com\r\n\r\nx"),
  });
  check("REQUIRETLS: every MX is asked before the verdict",
    attempts.length === 2, JSON.stringify(attempts));
  check("REQUIRETLS: and once none offers it the message is undeliverable, not deferred",
    rtRes.failed.length === 1 && rtRes.deferred.length === 0,
    JSON.stringify({ failed: rtRes.failed.length, deferred: rtRes.deferred.length }));

  // CONTROL: a host that merely failed for another reason has not answered the
  // REQUIRETLS question, so a mixed run stays deferrable.
  attempts.length = 0;
  var mixed = b.mail.send.deliver({
    hostname: "mta1.example.com", resolver: fakeResolver,
    policy: { mtaSts: "off", dane: "off" }, audit: false,
    transportFactory: function (opts) {
      return { send: async function () {
        attempts.push(opts.host);
        if (attempts.length === 1) {
          throw new b.mail.MailError("mail/smtp-failed", "SMTP send failed: timeout", false);
        }
        throw new b.mail.MailError("mail/requiretls-not-advertised",
          "requireTls was asked for but the peer does not advertise REQUIRETLS", false);
      } };
    },
  });
  var mixedRes = await mixed({
    from: "s@a.test", to: ["secure@recipient.com"],
    rfc822: Buffer.from("From: s@a.test\r\nTo: secure@recipient.com\r\n\r\nx"),
  });
  check("CONTROL — a host that failed for another reason leaves the message deferrable",
    mixedRes.deferred.length === 1 && mixedRes.failed.length === 0,
    JSON.stringify({ failed: mixedRes.failed.length, deferred: mixedRes.deferred.length }));

  // The same holds for a host SKIPPED before the send — a DANE lookup that
  // failed mid-rollover. It was never asked about REQUIRETLS, so the run is
  // not "every host refused it", and the skipped host may advertise it on the
  // retry after its records settle.
  attempts.length = 0;
  var skipped = b.mail.send.deliver({
    hostname: "mta1.example.com",
    // The first host's TLSA lookup fails — mid-rollover — so it is skipped
    // before the send; the second is queried normally and refuses for want of
    // REQUIRETLS.
    resolver: {
      queryMx: fakeResolver.queryMx,
      queryTlsa: async function (name) {
        if (name.indexOf("mx1.") !== -1) throw new Error("dane: TLSA lookup failed");
        return { rrs: [{ type: 52, typeName: "TLSA", decoded: {                                         // allow:raw-byte-literal — DNS TLSA rrtype
          usage: 3, selector: 1, matchingType: 1,
          certData: Buffer.from("0123456789abcdef0123456789abcdef", "hex"),
        } }] };
      },
    },
    policy: { mtaSts: "off", dane: "enforce", dnssecValidated: true }, audit: false,
    transportFactory: function (opts) {
      return { send: async function () {
        attempts.push(opts.host);
        throw new b.mail.MailError("mail/requiretls-not-advertised",
          "requireTls was asked for but the peer does not advertise REQUIRETLS", false);
      } };
    },
  });
  var skippedRes = await skipped({
    from: "s@a.test", to: ["secure@recipient.com"],
    rfc822: Buffer.from("From: s@a.test\r\nTo: secure@recipient.com\r\n\r\nx"),
  });
  check("CONTROL — a host skipped before the send leaves the message deferrable",
    skippedRes.deferred.length === 1 && skippedRes.failed.length === 0,
    JSON.stringify({ failed: skippedRes.failed.length, deferred: skippedRes.deferred.length,
                     attempts: attempts }));
}

// ---- DSN composer (RFC 3464 multipart/report) ----

function testDsnComposer() {
  var deliver = b.mail.send.deliver({ hostname: "m.example", audit: false });
  var dsn = deliver.buildDsn({
    dsnFrom:         "mailer-daemon@m.example",
    originalFrom:    "alice@sender.com",
    recipient:       "bob@dest.com",
    reason:          "550 5.1.1 mailbox not found",
    statusCode:      "5.1.1",
    reportingMta:    "mta1.example.com",
    originalHeaders: "From: alice@sender.com\r\nTo: bob@dest.com\r\nSubject: greetings\r\nMessage-Id: <m@x>\r\n",
  });

  check("DSN: From header carries mailer-daemon",   /^From: Mail Delivery System <mailer-daemon@m\.example>/m.test(dsn));
  check("DSN: To header carries original sender",   /^To: alice@sender\.com/m.test(dsn));
  check("DSN: Subject is failure notification",     /^Subject: Delivery Status Notification \(Failure\)/m.test(dsn));
  check("DSN: Content-Type multipart/report",       /Content-Type: multipart\/report; report-type=delivery-status/m.test(dsn));
  check("DSN: Auto-Submitted header present",       /^Auto-Submitted: auto-replied/m.test(dsn));
  check("DSN: per-recipient Final-Recipient",       /^Final-Recipient: rfc822; bob@dest\.com/m.test(dsn));
  check("DSN: Action: failed",                      /^Action: failed/m.test(dsn));
  check("DSN: enhanced Status code",                /^Status: 5\.1\.1/m.test(dsn));
  check("DSN: Diagnostic-Code carries the smtp reason", /^Diagnostic-Code: smtp; 550 5\.1\.1 mailbox not found/m.test(dsn));
  check("DSN: Reporting-MTA matches the configured hostname",
    /^Reporting-MTA: dns; mta1\.example\.com/m.test(dsn));
  check("DSN: original headers section",            dsn.indexOf("From: alice@sender.com") > 0);
  check("DSN: boundary closes correctly",           /\r\n--dsn-[a-z0-9-]+--\r\n$/m.test(dsn));
}

// ---- DSN CRLF/NUL header-injection guard (RFC 5321/5322 line safety) ----

function testDsnRejectsCrlfHeaderInjection() {
  var deliver = b.mail.send.deliver({ hostname: "m.example", audit: false });
  function threw(fn) { try { fn(); return null; } catch (e) { return e; } }

  // The 5xx diagnostic `reason` is echoed from the REMOTE peer's SMTP
  // reply — free-form and legitimately multi-line, so it is folded to a
  // single line. A malicious peer returning a reply that carries CR/LF
  // must not be able to start a new header line or forge a report part.
  var folded = deliver.buildDsn({
    dsnFrom:      "mailer-daemon@m.example",
    originalFrom: "alice@sender.com",
    recipient:    "bob@dest.com",
    reason:       "550 mailbox full\r\nX-Injected: evil\r\n--dsn-forged\r\nContent-Type: text/evil",
    statusCode:   "5.2.2",
  });
  check("DSN: injected reason cannot start a new header line",
    !/^X-Injected:/m.test(folded));
  check("DSN: injected reason cannot forge a report part boundary",
    !/^--dsn-forged/m.test(folded));
  check("DSN: injected reason cannot forge a part Content-Type",
    !/^Content-Type: text\/evil/m.test(folded));

  // A NUL in the free-text reason is stripped by the fold, not serialized
  // into the Diagnostic-Code header line (NUL is never valid in an RFC 5322
  // header and downstream SMTP parsers treat it specially).
  var withNul = deliver.buildDsn({
    dsnFrom: "mailer-daemon@m.example", originalFrom: "alice@sender.com",
    recipient: "bob@dest.com", reason: "550 full" + String.fromCharCode(0) + "evil",
  });
  check("DSN: NUL in reason is stripped from the output",
    withNul.indexOf(String.fromCharCode(0)) === -1);

  // Structured fields (addresses, reporting-MTA name, enhanced status)
  // can never legitimately carry CR/LF/NUL — a bounce built from a
  // hostile original sender or peer fails closed instead of smuggling.
  var e1 = threw(function () {
    deliver.buildDsn({ dsnFrom: "mailer-daemon@m.example",
      originalFrom: "alice@sender.com\r\nBcc: victim@evil.test",
      recipient: "bob@dest.com", reason: "550" });
  });
  check("DSN: CRLF in originalFrom throws deliver/bad-dsn-field",
    e1 && e1.code === "deliver/bad-dsn-field");
  var e2 = threw(function () {
    deliver.buildDsn({ dsnFrom: "mailer-daemon@m.example",
      originalFrom: "alice@sender.com",
      recipient: "bob@dest.com\r\nRcpt-To: victim@evil.test", reason: "550" });
  });
  check("DSN: CRLF in recipient throws deliver/bad-dsn-field",
    e2 && e2.code === "deliver/bad-dsn-field");
  var e3 = threw(function () {
    deliver.buildDsn({ dsnFrom: "mailer-daemon@m.example",
      originalFrom: "alice@sender.com", recipient: "bob@dest.com",
      reason: "550", reportingMta: "mta.example\r\nX-Evil: 1" });
  });
  check("DSN: CRLF in reportingMta throws deliver/bad-dsn-field",
    e3 && e3.code === "deliver/bad-dsn-field");
  var e4 = threw(function () {
    deliver.buildDsn({ dsnFrom: "mailer-daemon@m.example",
      originalFrom: "alice@sender.com", recipient: "bob@dest.com",
      reason: "550", statusCode: "5.0.0\r\nX-Evil: 1" });
  });
  check("DSN: CRLF in statusCode throws deliver/bad-dsn-field",
    e4 && e4.code === "deliver/bad-dsn-field");
  var e5 = threw(function () {
    deliver.buildDsn({ dsnFrom: "mailer-daemon@m.example",
      originalFrom: "alice@sender.com" + String.fromCharCode(0) + "evil", recipient: "bob@dest.com",
      reason: "550" });
  });
  check("DSN: NUL in originalFrom throws deliver/bad-dsn-field",
    e5 && e5.code === "deliver/bad-dsn-field");
}

// ---- The null reverse path ----

// RFC 5321 §4.5.5 requires `MAIL FROM:<>` for a delivery status notification,
// and `b.mail.transports.smtp` already turns `""` into exactly that. `deliver`
// refused it as "non-empty required", so the one composer whose job is sending
// a DSN could not send the one message shape the spec reserves a syntax for —
// and its own documented DSN example put a real address in the reverse path,
// which is how a bounce that fails bounces back to the bounce's sender.
async function testNullReversePathIsAValueNotAnAbsence() {
  var sent = [];
  var fakeResolver = { queryMx: async function (d) {
    return [{ exchange: "mx1." + d, priority: 10 }]; } };
  var okTransport = function () {
    return { send: async function (msg) { sent.push(msg); return { ok: true, code: 250 }; } };
  };
  var deliver = b.mail.send.deliver({
    hostname: "mta1.example.com", resolver: fakeResolver,
    policy: { mtaSts: "off", dane: "off" },
    transportFactory: okTransport, audit: false,
  });
  var res = await deliver({
    from:   "",
    to:     ["alice@recipient.com"],
    rfc822: Buffer.from("From: MAILER-DAEMON\r\nTo: alice@recipient.com\r\n\r\nbounce"),
  });
  check("an empty reverse path is accepted and delivered", res.delivered.length === 1,
        JSON.stringify(res));
  check("and it reaches the transport as the empty string, which is what the " +
        "wire layer turns into MAIL FROM:<>",
        sent.length === 1 && sent[0].from === "", JSON.stringify(sent[0] || {}));

  // CONTROL: a non-string is still refused, so accepting "" did not turn the
  // check off. `null` and `undefined` are absences; "" is a value.
  var codes = [];
  [null, undefined, 42, {}].forEach(function (bad) {
    try {
      var d2 = b.mail.send.deliver({
        hostname: "m.example", resolver: fakeResolver,
        policy: { mtaSts: "off", dane: "off" },
        transportFactory: okTransport, audit: false,
      });
      d2({ from: bad, to: ["a@b.com"], rfc822: Buffer.from("x") })
        .then(function () { codes.push("NO-THROW"); },
              function (e) { codes.push((e && e.code) || "?"); });
    } catch (e) { codes.push((e && e.code) || "?"); }
  });
  await new Promise(function (r) { setImmediate(r); });
  check("CONTROL — a non-string reverse path is still refused",
        codes.length === 4 && codes.every(function (c) {
          return c === "deliver/bad-envelope-from";
        }), JSON.stringify(codes));
}

// A message sent with the null reverse path must generate NO bounce. RFC 5321
// §4.5.5, and the reason is the loop: the DSN is addressed to the original
// `from`, so bouncing a bounce addresses it to nobody — or, with a less careful
// peer, back to itself. Accepting "" above is what makes this reachable.
async function testNullReversePathGeneratesNoDsn() {
  var fakeResolver = { queryMx: async function (d) {
    return [{ exchange: "mx1." + d, priority: 10 }]; } };
  // A permanent failure is a THROW carrying the peer's reply, which is how the
  // wire layer reports one — not a returned `{ ok: false }`. Getting that wrong
  // is what the control below caught: both cases sent no DSN, so the assertion
  // above would have passed for a fixture that never reached the DSN path.
  //
  // It carries the reply the way b.mail's transport does — `statusCode` on a
  // MailError. The earlier fixture invented `err.smtpResponse`, a property the
  // transport never set, so it exercised a branch production could not reach
  // and the delivery path's real classification went untested.
  var hardFail = function () {
    return { send: async function () {
      throw new b.mail.MailError("mail/smtp-failed",
        "SMTP send failed: rcpt-rejected (code 550)", true, 550);
    } };
  };
  var dsnCalls = [];
  function deliverWith(from) {
    var d = b.mail.send.deliver({
      hostname: "mta1.example.com", resolver: fakeResolver,
      policy: { mtaSts: "off", dane: "off" },
      transportFactory: hardFail, audit: false,
      dsn: {
        from: "postmaster@example.com",
        onPermanentFailure: async function (env, res, msg) {
          dsnCalls.push({ from: env.from, msg: String(msg).slice(0, 40) });
        },
      },
    });
    return d({ from: from, to: ["alice@recipient.com"],
               rfc822: Buffer.from("From: x\r\nTo: y\r\n\r\nb") });
  }

  await deliverWith("");
  check("a permanent failure on a null-reverse-path message sends no DSN",
        dsnCalls.length === 0, JSON.stringify(dsnCalls));
  // CONTROL: the same failure on an ordinary message DOES send one, so the
  // check above is about the reverse path and not about DSN being switched off.
  await deliverWith("ops@example.com");
  check("CONTROL — the same failure on an ordinary message still sends one",
        dsnCalls.length === 1 && dsnCalls[0].from === "ops@example.com",
        JSON.stringify(dsnCalls));
}

// ---- The DEFAULT transport ----

// Every other test in this file supplies `transportFactory`, which is why the
// default was undefined for as long as it was: the option is documented as an
// override, so the path an operator actually takes was the one path never
// driven. The factory resolved `mailModule().smtpTransport`, `lib/mail.js`
// exports that transport as `transports.smtp`, and calling `undefined` threw a
// TypeError which the outcome classifier read as a transient peer problem — so
// every recipient deferred 4.4.4 forever and no socket was ever opened.
//
// This drives the composer with NO transportFactory, against a port nothing is
// listening on, and asserts the failure is about the connection rather than
// about the framework. The assertion is on the reason TEXT because that is what
// distinguishes the two: both outcomes are a deferral.
async function testDefaultTransportIsTheRealOne() {
  var fakeResolver = {
    queryMx: async function (domain) {
      // Port 1 on the loopback: reserved, unbound, and refuses fast.
      return [{ exchange: "127.0.0.1", priority: 10 }];
    },
  };
  var deliver = b.mail.send.deliver({
    hostname: "mta1.example.com",
    resolver: fakeResolver,
    policy:   { mtaSts: "off", dane: "off" },
    port:     1,
    timeouts: { perHostMs: 2000 },
    audit:    false,
  });
  var result = await deliver({
    from:   "ops@example.com",
    to:     ["alice@recipient.com"],
    rfc822: Buffer.from("From: ops@example.com\r\nTo: alice@recipient.com\r\n" +
                        "Subject: hi\r\n\r\nbody"),
  });
  var outcome = (result.deferred[0] || result.failed[0] || {});
  var reason  = String(outcome.reason || "");
  check("default transport: the run does not fail on the framework's own " +
        "wiring (" + JSON.stringify(reason.slice(0, 60)) + ")",
        reason.indexOf("is not a function") === -1, JSON.stringify(outcome));
  // The control: it DID try. Without this the check above passes for a run that
  // never attempted delivery at all.
  check("default transport: and it did attempt the host, so the absence of a " +
        "TypeError is not the absence of an attempt",
        result.delivered.length + result.deferred.length + result.failed.length === 1,
        JSON.stringify(result));
}

// ---- Delivery happy-path (stubbed MX + transport) ----

async function testDeliveryHappyPathStubbed() {
  // Stub the resolver + the transport factory (via opts.transportFactory)
  // so neither the MX lookup nor the SMTP wire layer reaches the
  // network in this composer-logic test.
  var captured = [];
  var fakeResolver = {
    queryMx: async function (domain) {
      captured.push({ kind: "mx", domain: domain });
      return [{ exchange: "mx1." + domain, priority: 10 }];
    },
  };
  var fakeTransport = function (opts) {
    captured.push({ kind: "transport", host: opts.host });
    return {
      send: async function (msg) {
        captured.push({ kind: "send", to: msg.to });
        return { ok: true, code: 250 };
      },
    };
  };
  var deliver = b.mail.send.deliver({
    hostname:         "mta1.example.com",
    resolver:         fakeResolver,
    policy:           { mtaSts: "off", dane: "off" },
    transportFactory: fakeTransport,
    audit:            false,
  });
  var result = await deliver({
    from:   "ops@example.com",
    to:     ["alice@recipient.com"],
    rfc822: Buffer.from("From: ops@example.com\r\nTo: alice@recipient.com\r\nSubject: hi\r\n\r\nbody"),
  });
  check("happy-path: 1 delivered",                   result.delivered.length === 1);
  check("happy-path: 0 deferred",                    result.deferred.length === 0);
  check("happy-path: 0 failed",                      result.failed.length === 0);
  check("happy-path: delivered.recipient correct",   result.delivered[0].recipient === "alice@recipient.com");
  check("happy-path: delivered.mxHost from resolver", result.delivered[0].mxHost === "mx1.recipient.com");
  check("happy-path: MX lookup happened",            captured.some(function (e) { return e.kind === "mx" && e.domain === "recipient.com"; }));
  check("happy-path: transport opened to MX host",   captured.some(function (e) { return e.kind === "transport" && e.host === "mx1.recipient.com"; }));
}

// ---- Multi-@ recipient is refused before routing ----

async function testMultiAtRecipientRefused() {
  // A recipient with two '@' (victim@internal.host@external.com) must be
  // refused as a permanent bad-address, NOT routed to the LEFTMOST segment's MX
  // (split("@")[1] = internal.host) — that would mis-deliver / exfiltrate to an
  // unintended host (CWE-290).
  var mxDomains = [];
  var fakeResolver = {
    queryMx: async function (domain) {
      mxDomains.push(domain);
      return [{ exchange: "mx1." + domain, priority: 10 }];
    },
  };
  var fakeTransport = function () {
    return { send: async function () { return { ok: true, code: 250 }; } };
  };
  var deliver = b.mail.send.deliver({
    hostname:         "mta1.example.com",
    resolver:         fakeResolver,
    policy:           { mtaSts: "off", dane: "off" },
    transportFactory: fakeTransport,
    audit:            false,
  });
  var result = await deliver({
    from:   "ops@example.com",
    to:     ["victim@internal.host@external.com"],
    rfc822: Buffer.from("From: ops@example.com\r\nSubject: x\r\n\r\nbody"),
  });
  check("multi-@ recipient → permanent failure, not delivered",
        result.failed.length === 1 && result.delivered.length === 0);
  check("multi-@ recipient → no MX lookup on the leftmost segment",
        mxDomains.indexOf("internal.host") === -1);
}

// ---- Defer on transient + DSN on permanent ----

async function testTransientDefersPermanentFails() {
  var fakeResolver = {
    queryMx: async function (domain) {
      return [{ exchange: "mx1." + domain, priority: 10 }];
    },
  };
  var dsnInvocations = [];

  // First recipient: transport returns a 4xx (transient). Second
  // recipient: 5xx (permanent). The classifier routes the first to
  // deferred[], the second to failed[] with a DSN composed + handed
  // to the operator-supplied onPermanentFailure callback.
  var fakeTransport = function () {
    return {
      send: async function (msg) {
        var to = msg.to[0];
        // Both carry the peer's reply the way b.mail's transport does —
        // `statusCode` on a MailError — rather than an invented property the
        // wire layer never set.
        if (to === "transient@example.com") {
          throw new b.mail.MailError("mail/smtp-failed",
            "SMTP send failed: rcpt-rejected (code 451)", false, 451);
        }
        if (to === "permanent@example.com") {
          throw new b.mail.MailError("mail/smtp-failed",
            "SMTP send failed: rcpt-rejected (code 550)", true, 550);
        }
        return { ok: true, code: 250 };
      },
    };
  };
  var deliver = b.mail.send.deliver({
    hostname:         "mta1.example.com",
    resolver:         fakeResolver,
    policy:           { mtaSts: "off", dane: "off" },
    transportFactory: fakeTransport,
    dsn:      {
      from: "mailer-daemon@example.com",
      onPermanentFailure: async function (envelope, result, dsnMessage) {
        dsnInvocations.push({ recipient: result.recipient, dsnHasReport: dsnMessage.indexOf("Content-Type: multipart/report") !== -1 });
      },
    },
    audit:    false,
  });
  var result = await deliver({
    from:   "ops@example.com",
    to:     ["transient@example.com", "permanent@example.com"],
    rfc822: Buffer.from("From: ops@example.com\r\nTo: transient,permanent\r\nSubject: t\r\n\r\nbody"),
  });
  check("split: 0 delivered", result.delivered.length === 0);
  check("split: 1 deferred",  result.deferred.length === 1);
  check("split: 1 failed",    result.failed.length === 1);
  check("split: deferred is the transient recipient",
    result.deferred[0].recipient === "transient@example.com");
  check("split: deferred carries retryAfterMs budget",
    typeof result.deferred[0].retryAfterMs === "number" && result.deferred[0].retryAfterMs > 0);
  check("split: failed is the permanent recipient",
    result.failed[0].recipient === "permanent@example.com");
  check("split: failed.dsnSent flag",   result.failed[0].dsnSent === true);
  check("split: DSN delivered to operator callback",
    dsnInvocations.length === 1 && dsnInvocations[0].recipient === "permanent@example.com");
  check("split: DSN body carries multipart/report",
    dsnInvocations[0].dsnHasReport === true);
}

// ---- retry.maxAttempts value flows through to the retry budget ----

// A valid maxAttempts must reach the deferred-vs-failed routing, not just
// pass validation. With maxAttempts:1, the first transient failure exhausts
// the budget (attempts 1 >= 1) and converts transient → permanent → failed[]
// rather than landing in deferred[]. The default (5) keeps it deferred.
async function testMaxAttemptsFlowsThrough() {
  var fakeResolver = {
    queryMx: async function (domain) {
      return [{ exchange: "mx1." + domain, priority: 10 }];
    },
  };
  var transientTransport = function () {
    return {
      send: async function () {
        throw new b.mail.MailError("mail/smtp-failed",
          "SMTP send failed: rcpt-rejected (code 451)", false, 451);
      },
    };
  };
  var envelope = {
    from:   "ops@example.com",
    to:     ["transient@example.com"],
    rfc822: Buffer.from("hi"),
  };

  var deliverBudget1 = b.mail.send.deliver({
    hostname:         "mta1.example.com",
    resolver:         fakeResolver,
    policy:           { mtaSts: "off", dane: "off" },
    transportFactory: transientTransport,
    retry:            { maxAttempts: 1 },
    audit:            false,
  });
  var r1 = await deliverBudget1(envelope);
  check("maxAttempts:1 exhausts budget on first transient → failed",
    r1.failed.length === 1 && r1.deferred.length === 0);
  // RFC 3463 §3.1 makes class 4 a PERSISTENT TRANSIENT failure — "try again
  // later" — and this result composes a DSN that says Action: failed. Leaving
  // the status at 4.x.y tells the reader's parser the opposite of what the
  // report is for, so the class converts when the outcome does.
  check("an exhausted retry budget reports a class-5 status, not a class-4 one",
    String(r1.failed[0].reasonCode).charAt(0) === "5",
    JSON.stringify(r1.failed[0].reasonCode));
  // CONTROL: while the budget remains, the deferral keeps its class-4 status —
  // it really is "try again later" at that point.
  var rStill = await (b.mail.send.deliver({
    hostname: "mta1.example.com", resolver: fakeResolver,
    policy: { mtaSts: "off", dane: "off" },
    transportFactory: transientTransport, audit: false,
  }))(envelope);
  check("CONTROL — a deferral that may still be retried keeps its class-4 status",
    String(rStill.deferred[0].reasonCode).charAt(0) === "4",
    JSON.stringify(rStill.deferred[0].reasonCode));

  var deliverDefault = b.mail.send.deliver({
    hostname:         "mta1.example.com",
    resolver:         fakeResolver,
    policy:           { mtaSts: "off", dane: "off" },
    transportFactory: transientTransport,
    audit:            false,
  });
  var r2 = await deliverDefault(envelope);
  check("default maxAttempts keeps a single transient deferred",
    r2.deferred.length === 1 && r2.failed.length === 0);
}

// ---- No-MX (RFC 7505 null MX) ----

async function testNullMx() {
  var fakeResolver = {
    queryMx: async function () {
      // RFC 7505 null MX — single record with empty exchange.
      return [{ exchange: ".", priority: 0 }];
    },
  };
  var deliver = b.mail.send.deliver({
    hostname: "mta1.example.com",
    resolver: fakeResolver,
    policy:   { mtaSts: "off", dane: "off" },
    audit:    false,
  });
  var result = await deliver({
    from:   "ops@example.com",
    to:     ["alice@refuses-mail.example"],
    rfc822: Buffer.from("From: ops@example.com\r\nTo: alice\r\nSubject: t\r\n\r\nbody"),
  });
  check("null-MX: 1 failed (permanent)",  result.failed.length === 1);
  check("null-MX: reasonCode is 5.1.2",   result.failed[0].reasonCode === "5.1.2");
  check("null-MX: 0 deferred",            result.deferred.length === 0);
}

// ---- MX-failover when first host is transient ----

async function testMxFailover() {
  var fakeResolver = {
    queryMx: async function (domain) {
      return [
        { exchange: "mx1." + domain, priority: 10 },
        { exchange: "mx2." + domain, priority: 20 },
      ];
    },
  };
  var transportCalls = [];
  var fakeTransport = function (opts) {
    transportCalls.push(opts.host);
    return {
      send: async function () {
        if (opts.host === "mx1.example.com") {
          var err = new Error("primary MX refused");
          err.code = "ECONNREFUSED";
          throw err;
        }
        return { ok: true, code: 250 };
      },
    };
  };
  var deliver = b.mail.send.deliver({
    hostname:         "mta1.example.com",
    resolver:         fakeResolver,
    policy:           { mtaSts: "off", dane: "off" },
    transportFactory: fakeTransport,
    audit:            false,
  });
  var result = await deliver({
    from:   "ops@example.com",
    to:     ["alice@example.com"],
    rfc822: Buffer.from("hi"),
  });
  check("failover: 1 delivered",                 result.delivered.length === 1);
  check("failover: 0 deferred + 0 failed",       result.deferred.length === 0 && result.failed.length === 0);
  check("failover: tried mx1 first, then mx2",   transportCalls[0] === "mx1.example.com" && transportCalls[1] === "mx2.example.com");
  check("failover: delivered via mx2",            result.delivered[0].mxHost === "mx2.example.com");
}

// ---- DANE: the peer that publishes TLSA must be the one that benefits ----

// A stub with the SHIPPED daneTlsa's contract, not a convenient one: RFC 7672
// §1.3 forbids using records that were not DNSSEC-validated, so the real
// function throws unless the caller asserts its resolver validated them, and
// returns [] for a peer that publishes nothing (which never reaches the gate).
//
// Getting that contract right is the whole test. A stub that just returned
// records would pass against the broken code, because the defect is that
// `deliver` never supplies the third argument at all.
function _daneStub(recordsByHost) {
  var calls = [];
  return {
    calls: calls,
    dane: {
      tlsa: async function (host, port, opts) {
        calls.push({ host: host, port: port, opts: opts || null });
        var recs = recordsByHost[host];
        if (!recs) return [];                       // nothing published: never reaches the DNSSEC gate
        if (!opts || opts.dnssecValidated !== true) {
          var e = new Error("dane.tlsa: TLSA records must be DNSSEC-validated before use " +
                            "(RFC 7672 §1.3); pass opts.dnssecValidated: true");
          e.code = "smtp/dane-no-dnssec";
          throw e;
        }
        return recs;
      },
    },
  };
}

// DANE-EE / SPKI / SHA-256 — the common shape, 64 hex digits of digest.
var _TLSA_REC = { usage: 3, selector: 1, mtype: 1,
                  dataHex: "0123456789abcdef0123456789abcdef" +
                           "fedcba9876543210fedcba9876543210" };

async function testDanePublishingPeerIsDeliverableUnderEnforce() {
  // The inversion this test exists for: under `dane: "enforce"`, the peer that
  // did the work of publishing TLSA was the one refused, and the peer that
  // published nothing was delivered to normally. The DNSSEC assertion had no
  // route through `deliver`'s options, so enforce had no reachable success case.
  var stub = _daneStub({ "mx.published.com": [_TLSA_REC] });
  var hosts = [];
  var daneSeen = [];
  var transport = function (o) {
    hosts.push(o.host);
    daneSeen.push(o.dane || null);
    return { send: async function () { return { ok: true, code: 250 }; } };
  };
  await withSmtpPolicyStub({ dane: stub.dane }, async function () {
    var deliver = b.mail.send.deliver({
      hostname:         "mta1.example.com",
      resolver:         okResolver(function (d) { return [{ exchange: "mx." + d, priority: 10 }]; }),
      policy:           { mtaSts: "off", dane: "enforce", dnssecValidated: true },
      transportFactory: transport,
      audit:            false,
    });
    var published = await deliver({
      from: "ops@example.com", to: ["alice@published.com"], rfc822: Buffer.from("hi"),
    });
    check("dane enforce: the TLSA-publishing peer is delivered to, not refused",
          published.delivered.length === 1 && published.failed.length === 0,
          JSON.stringify({ d: published.delivered.length, f: published.failed.length,
                           df: published.deferred.length }));

    // The control. Without it, "delivered" above could mean the enforce path
    // was skipped altogether rather than satisfied — a peer publishing nothing
    // was ALWAYS delivered to, so it cannot distinguish a fix from a bypass.
    var silent = await deliver({
      from: "ops@example.com", to: ["bob@silent.com"], rfc822: Buffer.from("hi"),
    });
    check("dane enforce control: a peer publishing no TLSA is still delivered to",
          silent.delivered.length === 1);
    check("dane enforce: the DNSSEC assertion reached dane.tlsa",
          stub.calls.length === 2 && stub.calls[0].opts &&
          stub.calls[0].opts.dnssecValidated === true,
          JSON.stringify(stub.calls.map(function (c) { return c.opts; })));
  });

  // And the records must reach the transport, or nothing can be authenticated
  // against them: the lookup would be discovery wearing enforcement's name.
  var pubIdx = hosts.indexOf("mx.published.com");
  check("dane enforce: the fetched TLSA records are handed to the transport",
        pubIdx !== -1 && Array.isArray(daneSeen[pubIdx]) && daneSeen[pubIdx].length === 1,
        JSON.stringify(daneSeen));
  var silIdx = hosts.indexOf("mx.silent.com");
  check("dane enforce: a peer with no records hands the transport none",
        silIdx !== -1 && !daneSeen[silIdx], JSON.stringify(daneSeen[silIdx]));
}

// `dnssecValidated` is an assertion about the operator's OWN resolver, so the
// TLSA records have to come from that resolver. Fetching them through node:dns
// instead would mean the assertion described one resolver while the records
// arrived from another, and a non-validating system resolver could hand over
// spoofed TLSA data that DANE then treats as authenticated.
async function testDaneRecordsComeFromTheAssertedResolver() {
  var smtpPolicy = require("../../lib/network-smtp-policy.js");
  var asked = [];
  var resolver = {
    queryMx: async function (d) { return [{ exchange: "mx." + d, priority: 10 }]; },
    queryTlsa: async function (name) {
      asked.push(name);
      return { rrs: [{ type: 52, typeName: "TLSA", decoded: {
        usage: 3, selector: 1, matchingType: 1,
        certData: Buffer.from("0123456789abcdef0123456789abcdef", "hex"),
      } }] };
    },
  };
  var daneSeen = [];
  var deliver = b.mail.send.deliver({
    hostname:         "mta1.example.com",
    resolver:         resolver,
    policy:           { mtaSts: "off", dane: "enforce", dnssecValidated: true },
    transportFactory: function (o) {
      daneSeen.push(o.dane || null);
      return { send: async function () { return { ok: true, code: 250 }; } };
    },
    audit:            false,
  });
  var r = await deliver({
    from: "ops@example.com", to: ["alice@published.com"], rfc822: Buffer.from("hi"),
  });
  check("dane: the TLSA lookup went to the operator's resolver",
        asked.length === 1 && asked[0] === "_25._tcp.mx.published.com",
        JSON.stringify(asked));
  check("dane: delivered with the records that resolver returned",
        r.delivered.length === 1 && daneSeen[0] && daneSeen[0].length === 1,
        JSON.stringify(daneSeen));
  check("dane: the record decoded into the shape verifyChain reads",
        daneSeen[0][0].usage === 3 && daneSeen[0][0].selector === 1 &&
        daneSeen[0][0].mtype === 1 && typeof daneSeen[0][0].dataHex === "string",
        JSON.stringify(daneSeen[0][0]));

  // A supplied resolver that cannot answer TLSA is refused rather than quietly
  // bypassed: falling back to node:dns would break the very link between the
  // assertion and the records that makes the assertion mean anything.
  var noTlsa = null;
  try {
    await smtpPolicy.dane.tlsa("mx.example.com", 25, {
      dnssecValidated: true,
      resolver: { queryA: async function () { return { rrs: [] }; } },
    });
  } catch (e) { noTlsa = e; }
  check("dane: a resolver without queryTlsa is refused, not bypassed",
        noTlsa && noTlsa.code === "smtp/dane-resolver-no-tlsa",
        String(noTlsa && (noTlsa.code || noTlsa.message)));
}

// A DANE authentication failure says "this HOST could not be authenticated",
// not "this recipient does not exist". Classified permanent, it skipped every
// remaining MX and bounced immediately, so a certificate rollover part-way
// through DNS propagation — the ordinary way TLSA records change — turned
// deliverable mail into a DSN. RFC 7672 §2.2 has the sender try the other MX
// hosts and defer if none authenticates.
async function testDaneFailureFailsOverAndDefersRatherThanBouncing() {
  var hosts = [];
  var deliver = b.mail.send.deliver({
    hostname: "mta1.example.com",
    resolver: { queryMx: async function (d) {
      return [{ exchange: "mx1." + d, priority: 10 },
              { exchange: "mx2." + d, priority: 20 }];
    } },
    policy: { mtaSts: "off", dane: "off" },
    transportFactory: function (o) {
      hosts.push(o.host);
      return { send: async function () {
        if (o.host === "mx1.example.com") {
          // The shape the transport raises on a TLSA mismatch.
          throw new Error("dane: peer certificate chain matches none of the 1 " +
                          "TLSA record(s) published for it (RFC 7672 §2.2)");
        }
        return { ok: true, code: 250 };
      } };
    },
    audit: false,
  });
  var r = await deliver({
    from: "ops@example.com", to: ["alice@example.com"], rfc822: Buffer.from("hi"),
  });
  check("dane failure: the next MX is tried rather than bouncing",
        hosts.length === 2 && hosts[1] === "mx2.example.com", JSON.stringify(hosts));
  check("dane failure: delivered via the MX that authenticated",
        r.delivered.length === 1 && r.failed.length === 0,
        JSON.stringify({ d: r.delivered.length, f: r.failed.length }));

  // And when NO host authenticates, the recipient is deferred rather than
  // bounced: a rollover resolves itself, and a DSN does not.
  var deliver2 = b.mail.send.deliver({
    hostname: "mta1.example.com",
    resolver: okResolver(function (d) { return [{ exchange: "mx." + d, priority: 10 }]; }),
    policy: { mtaSts: "off", dane: "off" },
    transportFactory: function () {
      return { send: async function () {
        throw new Error("dane: peer certificate chain matches none of the 1 TLSA record(s)");
      } };
    },
    audit: false,
  });
  var r2 = await deliver2({
    from: "ops@example.com", to: ["alice@example.com"], rfc822: Buffer.from("hi"),
  });
  check("dane failure: every MX failing defers, it does not bounce",
        r2.deferred.length === 1 && r2.failed.length === 0,
        JSON.stringify({ df: r2.deferred.length, f: r2.failed.length }));

  // The control. A genuine policy refusal that IS permanent must stay
  // permanent, or this would have turned every refusal into an endless retry.
  check("classifyOutcome: an MTA-STS refusal is still permanent",
        deliver.classifyOutcome({ code: "", message: "mta-sts: no matching MX" }, null) === "permanent");
  // REQUIRETLS moved to the DANE side of this line, for the reason stated
  // three lines above it: whether the extension is offered is a property of
  // THIS HOST. A backup MX may advertise it, and failing over honours the flag
  // rather than violating it — bouncing here refuses mail a willing host would
  // have carried. If none of them offers it the message ends deferred, which
  // is the honest answer to "nobody here can promise what you asked for".
  check("classifyOutcome: a REQUIRETLS refusal is host-scoped, so the next MX gets a turn",
        deliver.classifyOutcome({ code: "", message: "REQUIRETLS was not offered" }, null) === "transient");
  check("classifyOutcome: a DANE failure is transient",
        deliver.classifyOutcome({ code: "", message: "dane: chain matches none" }, null) === "transient");
}

function testDaneEnforceWithoutDnssecAssertionIsRefusedAtCreate() {
  // Where the refusal belongs. Un-asserted DNSSEC makes every TLSA-publishing
  // peer undeliverable-to, so it is a misconfiguration of the sender, not a
  // property of any recipient: it is caught once at boot rather than surfacing
  // per-peer as a delivery failure attributed to the recipient's domain.
  var e = threw(function () {
    b.mail.send.deliver({ hostname: "m.example", policy: { dane: "enforce" } });
  });
  check("dane enforce without dnssecValidated → refused at create",
        e && e.code === "deliver/dane-no-dnssec", String(e && (e.code || e.message)));

  var ok = threw(function () {
    b.mail.send.deliver({ hostname: "m.example", policy: { dane: "enforce", dnssecValidated: true } });
  });
  check("dane enforce WITH dnssecValidated → accepted", ok === null,
        String(ok && ok.message));

  // Opportunistic is the default and must stay usable without the assertion:
  // it cannot use the records, so it must not demand a claim about them.
  var opp = threw(function () {
    b.mail.send.deliver({ hostname: "m.example", policy: { dane: "opportunistic" } });
  });
  check("dane opportunistic without dnssecValidated → still accepted", opp === null,
        String(opp && opp.message));

  var bad = threw(function () {
    b.mail.send.deliver({ hostname: "m.example", policy: { dane: "off", dnssecValidated: "yes" } });
  });
  check("dnssecValidated non-boolean → deliver/bad-policy-dnssec",
        bad && bad.code === "deliver/bad-policy-dnssec", String(bad && bad.code));
}

async function testDaneOpportunisticWithoutAssertionDoesNotQuery() {
  // Under opportunistic with no assertion the records are unusable by RFC 7672
  // §1.3, so querying for them buys nothing and costs a DNS round trip per MX
  // plus a warn on every delivery. Deciding not to ask is the honest posture.
  var stub = _daneStub({ "mx.published.com": [_TLSA_REC] });
  await withSmtpPolicyStub({ dane: stub.dane }, async function () {
    var deliver = b.mail.send.deliver({
      hostname:         "mta1.example.com",
      resolver:         okResolver(function (d) { return [{ exchange: "mx." + d, priority: 10 }]; }),
      policy:           { mtaSts: "off", dane: "opportunistic" },
      transportFactory: okTransport(),
      audit:            false,
    });
    var r = await deliver({
      from: "ops@example.com", to: ["alice@published.com"], rfc822: Buffer.from("hi"),
    });
    check("dane opportunistic unasserted: delivered", r.delivered.length === 1);
    check("dane opportunistic unasserted: no TLSA query issued",
          stub.calls.length === 0, JSON.stringify(stub.calls));
  });
}

// A deferred recipient says a delivery did not happen; a queue an operator runs
// on a bad day has to say WHICH receiver refused. A domain with several MX hosts
// defers on one of them, and the next question is always which — it decides
// whether to wait, to contact that receiver, or to look at one's own transport
// security against that host. Delivered recipients carried `mxHost` and deferred
// ones did not, so the queue view read "deferred, retry in 15 minutes" with no
// peer attached (#643).
async function testDeferredRecipientsCarryTheHostThatRefused() {
  var deliver = b.mail.send.deliver({
    hostname: "mta1.example.com",
    resolver: okResolver(function (d) {
      return [{ exchange: "mx1." + d, priority: 10 },
              { exchange: "mx2." + d, priority: 20 }];
    }),
    policy: { mtaSts: "off", dane: "off" },
    transportFactory: function () {
      return { send: async function () {
        var e = new Error("connection refused");
        e.code = "ECONNREFUSED";
        throw e;
      } };
    },
    audit: false,
  });
  var r = await deliver({
    from: "ops@example.com", to: ["alice@example.com"], rfc822: Buffer.from("hi"),
  });
  check("deferred: one recipient deferred", r.deferred.length === 1,
        JSON.stringify({ d: r.delivered.length, df: r.deferred.length, f: r.failed.length }));
  check("deferred: the recipient carries the host that was tried last",
        r.deferred[0].mxHost === "mx2.example.com",
        JSON.stringify(r.deferred[0]));
  check("deferred: the fields it already carried are unchanged",
        r.deferred[0].recipient === "alice@example.com" &&
        typeof r.deferred[0].reason === "string" &&
        typeof r.deferred[0].retryAfterMs === "number",
        JSON.stringify(r.deferred[0]));

  // A recipient deferred BEFORE any host was reached — an MX lookup failure —
  // has no host to name, and must say so with null rather than by omitting the
  // field, so a consumer can tell "no peer was reached" from "we forgot".
  var noMx = b.mail.send.deliver({
    hostname: "mta1.example.com",
    resolver: { queryMx: async function () { throw new Error("SERVFAIL"); } },
    policy: { mtaSts: "off", dane: "off" },
    transportFactory: okTransport(),
    audit: false,
  });
  var r2 = await noMx({
    from: "ops@example.com", to: ["bob@example.com"], rfc822: Buffer.from("hi"),
  });
  check("deferred: a lookup failure defers with mxHost null, not absent",
        r2.deferred.length === 1 && "mxHost" in r2.deferred[0] &&
        r2.deferred[0].mxHost === null,
        JSON.stringify(r2.deferred[0]));
}

// ---- local test utilities ----

function threw(fn) {
  try { fn(); return null; } catch (e) { return e; }
}
function okResolver(mxFor) {
  return { queryMx: async function (domain) { return mxFor(domain); } };
}
function okTransport() {
  return function () {
    return { send: async function () { return { ok: true, code: 250 }; } };
  };
}

// Swap b.network.smtp.policy's mtaSts / dane export objects for stubs.
// The top-level exports object is mutable (only the inner objects are
// frozen), so property reassignment is visible to the deliver module's
// cached lazyRequire handle. Restored in finally.
async function withSmtpPolicyStub(overrides, body) {
  var origMta  = smtpPolicyMod.mtaSts;
  var origDane = smtpPolicyMod.dane;
  try {
    if (overrides.mtaSts) smtpPolicyMod.mtaSts = overrides.mtaSts;
    if (overrides.dane)   smtpPolicyMod.dane   = overrides.dane;
    return await body();
  } finally {
    smtpPolicyMod.mtaSts = origMta;
    smtpPolicyMod.dane   = origDane;
  }
}

async function withNodeDnsResolveMx(fake, body) {
  var orig = dnsPromises.resolveMx;
  try {
    dnsPromises.resolveMx = fake;
    return await body();
  } finally {
    dnsPromises.resolveMx = orig;
  }
}

// ---- Outcome classifier — fallthrough / OR-alternative branches ----

function testClassifierFallthroughs() {
  var deliver = b.mail.send.deliver({ hostname: "m.example", audit: false });

  // No error, no response → the terminal `return "transient"`.
  check("classify(null,null) → transient",
    deliver.classifyOutcome(null, null) === "transient");
  // 3xx is neither 2/4/5xx → falls through to transient.
  check("classify 3xx → transient (fallthrough)",
    deliver.classifyOutcome(null, { code: 354 }) === "transient");
  // Response present but no code → String("") matches nothing → transient.
  check("classify response w/o code → transient",
    deliver.classifyOutcome(null, {}) === "transient");
  // Policy signal in the MESSAGE only (empty code) → the OR alternative of
  // each policy-class regex still classifies, on the side that class sits on:
  // MTA-STS is a domain policy this host cannot satisfy, REQUIRETLS is an
  // extension THIS host does not offer and a backup MX might.
  check("classify policy-signal via message only → permanent",
    deliver.classifyOutcome({ code: "", message: "mta-sts: no matching MX" }, null) === "permanent");
  check("classify host-scoped policy signal via message only → transient",
    deliver.classifyOutcome({ code: "", message: "REQUIRETLS was not offered" }, null) === "transient");
  // Generic error code that is neither a network code nor a policy
  // signal → transient (the err-branch fallthrough).
  check("classify generic err code → transient",
    deliver.classifyOutcome({ code: "EPIPE", message: "broken pipe" }, null) === "transient");
  check("classify ENETUNREACH → transient",
    deliver.classifyOutcome({ code: "ENETUNREACH" }, null) === "transient");
  // Response wins over err when both present.
  check("classify 550 response beats err → permanent",
    deliver.classifyOutcome({ code: "ECONNREFUSED" }, { code: 550 }) === "permanent");
}

// ---- create(): remaining shape-validation codes ----

function testCreateValidationCodes() {
  var eUnknown = threw(function () {
    b.mail.send.deliver({ hostname: "m.example", bogusKey: 1 });
  });
  check("unknown top-level opt → throws (unknown option)",
    eUnknown && /unknown option/.test(eUnknown.message || ""));

  var ePolicy = threw(function () { b.mail.send.deliver({ hostname: "m.example", policy: 5 }); });
  check("policy non-object → deliver/bad-policy", ePolicy && ePolicy.code === "deliver/bad-policy");

  var eRetry = threw(function () { b.mail.send.deliver({ hostname: "m.example", retry: 5 }); });
  check("retry non-object → deliver/bad-retry", eRetry && eRetry.code === "deliver/bad-retry");

  var eDsn = threw(function () { b.mail.send.deliver({ hostname: "m.example", dsn: 5 }); });
  check("dsn non-object → deliver/bad-dsn", eDsn && eDsn.code === "deliver/bad-dsn");

  var eTo = threw(function () { b.mail.send.deliver({ hostname: "m.example", timeouts: 5 }); });
  check("timeouts non-object → deliver/bad-timeouts", eTo && eTo.code === "deliver/bad-timeouts");

  var eRes = threw(function () { b.mail.send.deliver({ hostname: "m.example", resolver: 5 }); });
  check("resolver non-object → deliver/bad-resolver", eRes && eRes.code === "deliver/bad-resolver");

  var eTf = threw(function () { b.mail.send.deliver({ hostname: "m.example", transportFactory: 5 }); });
  check("transportFactory non-function → deliver/bad-transport-factory",
    eTf && eTf.code === "deliver/bad-transport-factory");

  var eAudit = threw(function () { b.mail.send.deliver({ hostname: "m.example", audit: "yes" }); });
  check("audit non-boolean → deliver/bad-audit", eAudit && eAudit.code === "deliver/bad-audit");

  var eDsnFrom = threw(function () {
    b.mail.send.deliver({ hostname: "m.example", dsn: { from: 123, onPermanentFailure: function () {} } });
  });
  check("dsn.from non-string → deliver/bad-dsn-from", eDsnFrom && eDsnFrom.code === "deliver/bad-dsn-from");

  var ePerHost = threw(function () {
    b.mail.send.deliver({ hostname: "m.example", timeouts: { perHostMs: "30000" } });
  });
  check("timeouts.perHostMs string → deliver/bad-timeout-perHostMs",
    ePerHost && ePerHost.code === "deliver/bad-timeout-perHostMs");

  var ePolicyKey = threw(function () {
    b.mail.send.deliver({ hostname: "m.example", policy: { mtaSts: "off", nope: 1 } });
  });
  check("unknown policy sub-key → throws (unknown option)",
    ePolicyKey && /unknown option/.test(ePolicyKey.message || ""));

  // Custom backoffMs array is accepted (the truthy branch of the
  // backoffMs default-or-supplied selection).
  var okBackoff = threw(function () {
    b.mail.send.deliver({
      hostname: "m.example",
      retry:    { backoffMs: [b.constants.TIME.seconds(30), b.constants.TIME.minutes(2)] },
      audit:    false,
    });
  });
  check("custom retry.backoffMs accepted", okBackoff === null);
}

// ---- DSN composer — default-field branches ----

function testDsnDefaultFields() {
  var deliver = b.mail.send.deliver({ hostname: "m.example", audit: false });

  // reportingMta / statusCode / reason / originalHeaders all omitted →
  // every `|| default` branch fires.
  var dsn = deliver.buildDsn({
    dsnFrom:      "mailer-daemon@m.example",
    originalFrom: "alice@sender.com",
    recipient:    "bob@dest.com",
  });
  check("DSN default reason is 'permanent failure'",
    /^Diagnostic-Code: smtp; permanent failure/m.test(dsn));
  check("DSN default Status is 5.0.0", /^Status: 5\.0\.0/m.test(dsn));
  check("DSN reportingMta falls back to dsnFrom in the prose line",
    dsn.indexOf("mail delivery system at mailer-daemon@m.example") !== -1);
  check("DSN Reporting-MTA falls back to dsnFrom's domain",
    /^Reporting-MTA: dns; m\.example/m.test(dsn));

  // dsnFrom with no '@' → from.split("@")[1] is undefined → the final
  // `|| ""` fallback produces an empty Reporting-MTA authority.
  var dsn2 = deliver.buildDsn({
    dsnFrom:      "mailerdaemon",
    originalFrom: "alice@sender.com",
    recipient:    "bob@dest.com",
  });
  check("DSN Reporting-MTA empty-authority fallback (dsnFrom has no @)",
    dsn2.indexOf("Reporting-MTA: dns; \r\n") !== -1);
}

// ---- Resolver wrapper shape { rrs: [...] } ----

async function testResolverWrapperShape() {
  var deliver = b.mail.send.deliver({
    hostname:         "mta1.example.com",
    resolver:         { queryMx: async function (domain) {
      return { rrs: [{ exchange: "mx1." + domain, priority: 10 }], ttl: 300, provenance: "doh" };
    } },
    policy:           { mtaSts: "off", dane: "off" },
    transportFactory: okTransport(),
    audit:            false,
  });
  var result = await deliver({ from: "ops@example.com", to: ["a@recipient.com"], rfc822: Buffer.from("hi") });
  check("resolver { rrs } wrapper shape is accepted → delivered",
    result.delivered.length === 1 && result.delivered[0].mxHost === "mx1.recipient.com");
}

// ---- Resolver bad shapes → no-mx / null-mx → permanent ----

async function testResolverBadShapes() {
  function deliverForResolver(resolver) {
    return b.mail.send.deliver({
      hostname: "mta1.example.com", resolver: resolver,
      policy: { mtaSts: "off", dane: "off" }, audit: false,
    });
  }
  var msg = Buffer.from("hi");

  var r1 = await deliverForResolver({ queryMx: async function () { return {}; } })(
    { from: "ops@example.com", to: ["a@x.com"], rfc822: msg });
  check("resolver returns non-array/non-rrs → no-mx permanent",
    r1.failed.length === 1 && r1.failed[0].reasonCode === "5.1.2");

  var r2 = await deliverForResolver({ queryMx: async function () { return []; } })(
    { from: "ops@example.com", to: ["a@x.com"], rfc822: msg });
  check("resolver returns empty array → no-mx permanent",
    r2.failed.length === 1 && r2.failed[0].reasonCode === "5.1.2");

  // RFC 7505 null MX signalled with an empty-string exchange (the "."
  // form is exercised by testNullMx above).
  var r3 = await deliverForResolver({ queryMx: async function () { return [{ exchange: "", priority: 0 }]; } })(
    { from: "ops@example.com", to: ["a@x.com"], rfc822: msg });
  check("resolver returns empty-exchange null-MX → permanent 5.1.2",
    r3.failed.length === 1 && r3.failed[0].reasonCode === "5.1.2");
  check("null-MX failed.mxHost is null (no host was tried)",
    r3.failed[0].mxHost === null);
}

// ---- MX lookup timeout → transient → deferred ----

async function testMxLookupTimeout() {
  await helpers.withTestTimeout("mx-lookup timeout branch", async function () {
    var deliver = b.mail.send.deliver({
      hostname: "mta1.example.com",
      // Never-resolving lookup + a 1ms budget forces the internal
      // setTimeout reject path in _resolveMx. `1` is an intentionally
      // tiny timeout to exercise the timeout branch, not a duration.
      resolver: { queryMx: function () { return new Promise(function () {}); } },
      policy:   { mtaSts: "off", dane: "off" },
      timeouts: { mxLookupMs: 1 },
      audit:    false,
    });
    var result = await deliver({ from: "ops@example.com", to: ["a@slow.example"], rfc822: Buffer.from("hi") });
    check("mx-timeout → deferred (transient)", result.deferred.length === 1);
    check("mx-timeout → reasonCode 4.4.4", result.deferred[0].reasonCode === "4.4.4");
  });
}

// ---- No resolver → node:dns fallback path ----

async function testNodeDnsFallback() {
  await withNodeDnsResolveMx(async function (domain) {
    return [{ exchange: "mx.node." + domain, priority: 5 }];
  }, async function () {
    // resolver omitted → ctx.resolver null → _resolveMx uses nodeDns.resolveMx.
    var deliver = b.mail.send.deliver({
      hostname:         "mta1.example.com",
      policy:           { mtaSts: "off", dane: "off" },
      transportFactory: okTransport(),
      audit:            false,
    });
    var result = await deliver({ from: "ops@example.com", to: ["a@recipient.com"], rfc822: Buffer.from("hi") });
    check("no-resolver node:dns fallback → delivered",
      result.delivered.length === 1 && result.delivered[0].mxHost === "mx.node.recipient.com");
  });
}

// ---- Recipient with no usable domain ----

async function testRecipientNoDomain() {
  var deliver = b.mail.send.deliver({
    hostname: "mta1.example.com",
    resolver: okResolver(function (d) { return [{ exchange: "mx1." + d, priority: 10 }]; }),
    policy:   { mtaSts: "off", dane: "off" },
    transportFactory: okTransport(),
    audit:    false,
  });
  var r1 = await deliver({ from: "ops@example.com", to: ["nodomain"], rfc822: Buffer.from("hi") });
  check("recipient without '@' → permanent no-domain 5.1.3",
    r1.failed.length === 1 && r1.failed[0].reasonCode === "5.1.3");
  var r2 = await deliver({ from: "ops@example.com", to: ["trailingat@"], rfc822: Buffer.from("hi") });
  check("recipient with empty domain (trailing @) → permanent 5.1.3",
    r2.failed.length === 1 && r2.failed[0].reasonCode === "5.1.3");
}

// ---- All MX hosts transient → final transient → deferred ----

async function testAllHostsTransient() {
  var deliver = b.mail.send.deliver({
    hostname: "mta1.example.com",
    resolver: okResolver(function (d) {
      return [{ exchange: "mx1." + d, priority: 10 }, { exchange: "mx2." + d, priority: 20 }];
    }),
    policy:   { mtaSts: "off", dane: "off" },
    transportFactory: function () {
      return { send: async function () {
        throw new b.mail.MailError("mail/smtp-failed",
          "SMTP send failed: rcpt-rejected (code 451)", false, 451);
      } };
    },
    audit:    false,
  });
  var result = await deliver({ from: "ops@example.com", to: ["a@example.com"], rfc822: Buffer.from("hi") });
  check("all-MX-transient → deferred (no delivery, no permanent fail)",
    result.deferred.length === 1 && result.delivered.length === 0 && result.failed.length === 0);
  // `reasonCode` becomes the DSN's `Status:` field, which RFC 3464 §2.3.4
  // makes an ENHANCED status — the bare three-digit reply belongs in
  // Diagnostic-Code, and is carried there inside the reason. It used to hold
  // `451`, which is `Status: 451` on the wire: not a status a conforming
  // parser accepts.
  check("all-MX-transient reports the reply's CLASS as an enhanced status",
    result.deferred[0].reasonCode === "4.0.0", JSON.stringify(result.deferred[0].reasonCode));
  check("all-MX-transient still names the peer's own reply in the reason",
    /451/.test(String(result.deferred[0].reason)), JSON.stringify(result.deferred[0].reason));
}

// ---- Permanent 5xx send failure records the MX host on the result ----

async function testPermanentFailKeepsMxHost() {
  var deliver = b.mail.send.deliver({
    hostname: "mta1.example.com",
    resolver: okResolver(function (d) { return [{ exchange: "mx1." + d, priority: 10 }]; }),
    policy:   { mtaSts: "off", dane: "off" },
    transportFactory: function () {
      return { send: async function () {
        throw new b.mail.MailError("mail/smtp-failed",
          "SMTP send failed: rcpt-rejected (code 550)", true, 550);
      } };
    },
    audit:    false,
  });
  var result = await deliver({ from: "ops@example.com", to: ["a@example.com"], rfc822: Buffer.from("hi") });
  check("permanent 5xx → failed with mxHost recorded",
    result.failed.length === 1 && result.failed[0].mxHost === "mx1.example.com");
  // Enhanced status, not the bare reply — see the transient sibling above for
  // why `Status: 550` is not a status.
  check("permanent 5xx reasonCode is an enhanced status carrying the reply's class",
    result.failed[0].reasonCode === "5.0.0", JSON.stringify(result.failed[0].reasonCode));
  check("and the reply itself is still named in the reason",
    /550/.test(String(result.failed[0].reason)), JSON.stringify(result.failed[0].reason));
}

// ---- MTA-STS policy matrix (fault-injected b.network.smtp.policy) ----

async function runMtaStsScenario(sc) {
  var mtaStub = {
    fetch: async function () {
      if (sc.fetchThrows) throw new Error(sc.fetchThrows);
      return sc.fetchResult;
    },
    matchMx:     function () { return !!sc.matchMx; },
    parsePolicy: smtpPolicyMod.mtaSts.parsePolicy,
  };
  var out = { result: null, err: null };
  await withSmtpPolicyStub({ mtaSts: mtaStub }, async function () {
    var deliver = b.mail.send.deliver({
      hostname:         "mta1.example.com",
      resolver:         okResolver(function (d) { return [{ exchange: "mx1." + d, priority: 10 }]; }),
      policy:           { mtaSts: sc.policyMtaSts, dane: "off" },
      transportFactory: okTransport(),
      audit:            false,
    });
    try {
      out.result = await deliver({ from: "ops@example.com", to: ["a@recipient.com"], rfc822: Buffer.from("hi") });
    } catch (e) { out.err = e; }
  });
  return out;
}

async function testMtaStsMatrix() {
  // fetch throws under enforce → permanent mta-sts-fetch-failed (5.7.10).
  var s1 = await runMtaStsScenario({ policyMtaSts: "enforce", fetchThrows: "network down" });
  check("MTA-STS fetch fail under enforce → permanent 5.7.10",
    s1.result && s1.result.failed.length === 1 && s1.result.failed[0].reasonCode === "5.7.10");

  // fetch throws under testing → skip + continue with original MX → delivered.
  var s2 = await runMtaStsScenario({ policyMtaSts: "testing", fetchThrows: "network down" });
  check("MTA-STS fetch fail under testing → skipped, delivered",
    s2.result && s2.result.delivered.length === 1);

  // null policy → 'none' audit + continue → delivered.
  var s3 = await runMtaStsScenario({ policyMtaSts: "enforce", fetchResult: null });
  check("MTA-STS fetch returns null → delivered (no policy published)",
    s3.result && s3.result.delivered.length === 1);

  // mode 'none' → delivered.
  var s4 = await runMtaStsScenario({ policyMtaSts: "enforce", fetchResult: { mode: "none" } });
  check("MTA-STS mode none → delivered",
    s4.result && s4.result.delivered.length === 1);

  // enforce policy, MX matches → filtered non-empty → delivered.
  var s5 = await runMtaStsScenario({
    policyMtaSts: "enforce", fetchResult: { mode: "enforce", mx: ["*.recipient.com"] }, matchMx: true });
  check("MTA-STS enforce + MX match → delivered",
    s5.result && s5.result.delivered.length === 1);

  // enforce policy, MX does not match → mismatch → permanent 5.7.10.
  var s6 = await runMtaStsScenario({
    policyMtaSts: "enforce", fetchResult: { mode: "enforce", mx: ["mail.other.com"] }, matchMx: false });
  check("MTA-STS enforce + no MX match → permanent 5.7.10",
    s6.result && s6.result.failed.length === 1 && s6.result.failed[0].reasonCode === "5.7.10");

  // testing policy + testing local + no match → 'no-match' audit + continue → delivered.
  var s7 = await runMtaStsScenario({
    policyMtaSts: "testing", fetchResult: { mode: "testing", mx: ["mail.other.com"] }, matchMx: false });
  check("MTA-STS testing + no match (local testing) → delivered (report-only)",
    s7.result && s7.result.delivered.length === 1);

  // testing policy + enforce local + match → 'testing' audit + filtered → delivered.
  var s8 = await runMtaStsScenario({
    policyMtaSts: "enforce", fetchResult: { mode: "testing", mx: ["*.recipient.com"] }, matchMx: true });
  check("MTA-STS testing published + local enforce + match → delivered",
    s8.result && s8.result.delivered.length === 1);
}

// ---- RFC 8461 §5.2: published testing-mode policy is report-only ----
// A domain-published "testing" policy MUST NOT cause a hard failure —
// failures are report-only and delivery proceeds. The default local
// posture (mtaSts:"enforce") cannot promote a domain's testing policy
// to a bounce. RED before the fix (the no-match testing policy threw
// mta-sts-mx-mismatch → permanent bounce under local enforce).
async function testMtaStsTestingNotEnforcedUnderLocalEnforce() {
  var s = await runMtaStsScenario({
    policyMtaSts: "enforce", fetchResult: { mode: "testing", mx: ["mail.other.com"] }, matchMx: false });
  check("testing-mode + local enforce + no MX match → NOT bounced (report-only)",
    s.result && s.result.failed.length === 0 && s.result.deferred.length === 0);
  check("testing-mode + local enforce + no MX match → delivered against full MX set",
    s.result && s.result.delivered.length === 1);
  check("testing-mode report-only does not reject deliver()",
    s.err === null);
}

// ---- DANE lookup matrix (fault-injected b.network.smtp.policy.dane) ----

async function runDaneScenario(sc) {
  var daneStub = {
    tlsa: async function () {
      if (sc.tlsaThrows) throw new Error(sc.tlsaThrows);
      return sc.tlsaResult;
    },
    recordShape: smtpPolicyMod.dane.recordShape,
    verifyChain: smtpPolicyMod.dane.verifyChain,
  };
  var out = { result: null, err: null };
  await withSmtpPolicyStub({ dane: daneStub }, async function () {
    var deliver = b.mail.send.deliver({
      hostname:         "mta1.example.com",
      resolver:         okResolver(function (d) { return [{ exchange: "mx1." + d, priority: 10 }]; }),
      // The DNSSEC assertion is on by default here so each scenario reaches
      // the lookup it is about. Without it the records are unusable under RFC
      // 7672 §1.3 and no query is issued, which would make several of these
      // pass by never running the code they name.
      policy:           { mtaSts: "off", dane: sc.policyDane,
                          dnssecValidated: sc.dnssecValidated !== false },
      transportFactory: okTransport(),
      audit:            false,
    });
    try {
      out.result = await deliver({ from: "ops@example.com", to: ["a@recipient.com"], rfc822: Buffer.from("hi") });
    } catch (e) { out.err = e; }
  });
  return out;
}

async function testDaneMatrix() {
  var d1 = await runDaneScenario({ policyDane: "opportunistic",
    tlsaResult: [{ usage: 3, selector: 1, mtype: 1, dataHex: "ab" }] });
  check("DANE opportunistic + TLSA records present → delivered",
    d1.result && d1.result.delivered.length === 1);

  var d2 = await runDaneScenario({ policyDane: "opportunistic", tlsaResult: [] });
  check("DANE opportunistic + empty TLSA → delivered",
    d2.result && d2.result.delivered.length === 1);

  var d3 = await runDaneScenario({ policyDane: "opportunistic", tlsaResult: null });
  check("DANE opportunistic + no TLSA → delivered",
    d3.result && d3.result.delivered.length === 1);

  var d4 = await runDaneScenario({ policyDane: "opportunistic", tlsaThrows: "SERVFAIL" });
  check("DANE opportunistic + TLSA lookup throws → skipped, delivered",
    d4.result && d4.result.delivered.length === 1);
}

// ---- DANE enforce TLSA failure is per-recipient, not batch-fatal ----
// A DANE-enforce TLSA lookup failure must fail (defer) the single
// affected recipient and STILL return the batch result object the
// contract promises — it must NOT throw out of deliver() and discard
// the sibling recipients' outcomes. RED before the fix (the throw
// propagated out of deliver() and rejected the whole call).
async function testDaneEnforceFailsOneRecipientNotBatch() {
  var d = await runDaneScenario({ policyDane: "enforce", tlsaThrows: "SERVFAIL" });
  check("DANE enforce TLSA failure does not reject deliver()",
    d.err === null && d.result !== null);
  check("DANE enforce TLSA failure defers the affected recipient",
    d.result && d.result.deferred.length === 1 && d.result.delivered.length === 0);
}

// A DANE-enforce TLSA failure for ONE recipient's MX must not abort the
// sibling recipient in the same deliver() batch. The DANE stub throws
// only for the "bad" domain's MX host; the "good" domain must still be
// delivered in the same call.
async function testDaneEnforceBatchSurvivesSiblingFailure() {
  var daneStub = {
    tlsa: async function (mxHost) {
      // Fault-inject a TLSA lookup failure for the bad domain's MX only.
      if (String(mxHost).indexOf("bad.example") !== -1) throw new Error("SERVFAIL");
      return null;
    },
    recordShape: smtpPolicyMod.dane.recordShape,
    verifyChain: smtpPolicyMod.dane.verifyChain,
  };
  var out = { result: null, err: null };
  await withSmtpPolicyStub({ dane: daneStub }, async function () {
    var deliver = b.mail.send.deliver({
      hostname:         "mta1.example.com",
      resolver:         okResolver(function (d) { return [{ exchange: "mx1." + d, priority: 10 }]; }),
      policy:           { mtaSts: "off", dane: "enforce", dnssecValidated: true },
      transportFactory: okTransport(),
      audit:            false,
    });
    try {
      out.result = await deliver({
        from:   "ops@example.com",
        to:     ["victim@bad.example", "friend@good.example"],
        rfc822: Buffer.from("hi"),
      });
    } catch (e) { out.err = e; }
  });
  check("mixed DANE batch does not reject deliver()",
    out.err === null && out.result !== null);
  check("mixed DANE batch delivers the healthy sibling recipient",
    out.result && out.result.delivered.length === 1 &&
    out.result.delivered[0].recipient === "friend@good.example");
  check("mixed DANE batch defers the DANE-failed recipient",
    out.result && out.result.deferred.length === 1 &&
    out.result.deferred[0].recipient === "victim@bad.example");
}

// ---- DSN callback failure path ----

async function testDsnCallbackFailure() {
  var deliver = b.mail.send.deliver({
    hostname: "mta1.example.com",
    resolver: okResolver(function (d) { return [{ exchange: "mx1." + d, priority: 10 }]; }),
    policy:   { mtaSts: "off", dane: "off" },
    transportFactory: function () {
      return { send: async function () {
        throw new b.mail.MailError("mail/smtp-failed",
          "SMTP send failed: rcpt-rejected (code 550)", true, 550);
      } };
    },
    dsn: {
      from: "mailer-daemon@example.com",
      onPermanentFailure: async function () { throw new Error("DSN transport exploded"); },
    },
    audit: false,
  });
  var result = await deliver({ from: "ops@example.com", to: ["a@example.com"], rfc822: Buffer.from("hi") });
  check("DSN callback throwing → recipient still recorded as failed",
    result.failed.length === 1);
  check("DSN callback throwing → dsnSent flag stays false",
    result.failed[0].dsnSent === false);
}

// ---- _extractHeaderBlock separator variants (via the DSN path) ----

async function testExtractHeaderBlockVariants() {
  var seen = [];
  function makeDeliver() {
    return b.mail.send.deliver({
      hostname: "mta1.example.com",
      resolver: okResolver(function (d) { return [{ exchange: "mx1." + d, priority: 10 }]; }),
      policy:   { mtaSts: "off", dane: "off" },
      transportFactory: function () {
        return { send: async function () {
          throw new b.mail.MailError("mail/smtp-failed",
            "SMTP send failed: rcpt-rejected (code 550)", true, 550);
        } };
      },
      dsn: {
        from: "mailer-daemon@example.com",
        onPermanentFailure: async function (env, res, dsnMessage) { seen.push(dsnMessage); },
      },
      audit: false,
    });
  }

  // LF-only header separator → the `\n\n` fallback branch.
  await makeDeliver()({ from: "ops@example.com", to: ["a@example.com"],
    rfc822: Buffer.from("Subject: lf-only\nX-Tag: one\n\nbody") });
  check("DSN embeds LF-only-separated original headers",
    seen.length === 1 && seen[0].indexOf("Subject: lf-only") !== -1);

  // No blank-line separator at all → whole string returned.
  await makeDeliver()({ from: "ops@example.com", to: ["a@example.com"],
    rfc822: Buffer.from("Subject: no-separator-single-line") });
  check("DSN embeds header block when message has no blank-line separator",
    seen.length === 2 && seen[1].indexOf("Subject: no-separator-single-line") !== -1);
}

// ---- Retry budget: custom backoff + attempt-index clamp + envelope.attempt ----

async function testRetryBudgetClamp() {
  var backoff = [b.constants.TIME.seconds(30), b.constants.TIME.minutes(2)];
  var deliver = b.mail.send.deliver({
    hostname: "mta1.example.com",
    resolver: okResolver(function (d) { return [{ exchange: "mx1." + d, priority: 10 }]; }),
    policy:   { mtaSts: "off", dane: "off" },
    retry:    { maxAttempts: 10, backoffMs: backoff },
    transportFactory: function () {
      return { send: async function () {
        throw new b.mail.MailError("mail/smtp-failed",
          "SMTP send failed: rcpt-rejected (code 451)", false, 451);
      } };
    },
    audit:    false,
  });
  // envelope.attempt: 3 → attempts becomes 4; still < maxAttempts(10) so
  // it defers; idx = min(attempts-1=3, backoffMs.length-1=1) = 1 → clamps
  // to the last backoff entry.
  var result = await deliver({
    from: "ops@example.com", to: ["a@example.com"], rfc822: Buffer.from("hi"), attempt: 3,
  });
  check("retry: prior attempt count carried through → deferred attempt is 4",
    result.deferred.length === 1 && result.deferred[0].attempt === 4);
  check("retry: attempt index clamps to the last backoff entry",
    result.deferred[0].retryAfterMs === backoff[backoff.length - 1]);
}

// ---- Default-audit (audit enabled) path executes cleanly ----

async function testDefaultAuditEnabled() {
  // audit omitted → auditEnabled true branch; the real (best-effort)
  // audit sink runs. Delivery must still succeed.
  var deliver = b.mail.send.deliver({
    hostname: "mta1.example.com",
    resolver: okResolver(function (d) { return [{ exchange: "mx1." + d, priority: 10 }]; }),
    policy:   { mtaSts: "off", dane: "off" },
    transportFactory: okTransport(),
  });
  var result = await deliver({ from: "ops@example.com", to: ["a@recipient.com"], rfc822: Buffer.from("hi") });
  check("audit-enabled default path delivers", result.delivered.length === 1);
}

// ---- b.mail.send.deliver.create — documented factory dotted form ----
//
// The @primitive / @signature / @example advertise
// `b.mail.send.deliver.create(opts)` as the way to build a delivery
// handle. This drives that exact dotted form end-to-end (stubbed MX +
// transport, no real SMTP socket) so the documented operator consumer
// path is verified — not only the collapsed `b.mail.send.deliver(opts)`
// callable the other tests exercise.
async function testDeliverCreateDottedForm() {
  check("b.mail.send.deliver.create is a function",
    typeof b.mail.send.deliver.create === "function");

  var fakeResolver = {
    queryMx: async function (domain) { return [{ exchange: "mx1." + domain, priority: 10 }]; },
  };
  var fakeTransport = function () {
    return { send: async function () { return { ok: true, code: 250 }; } };
  };
  var deliver = b.mail.send.deliver.create({
    hostname:         "mta1.example.com",
    resolver:         fakeResolver,
    policy:           { mtaSts: "off", dane: "off" },
    transportFactory: fakeTransport,
    audit:            false,
  });
  check("create() returns a callable deliver handle", typeof deliver === "function");
  var result = await deliver({
    from:   "ops@example.com",
    to:     ["alice@recipient.com"],
    rfc822: Buffer.from("From: ops@example.com\r\nTo: alice@recipient.com\r\nSubject: hi\r\n\r\nbody"),
  });
  check("create()'d handle delivers via the stubbed transport",
    result.delivered.length === 1 && result.delivered[0].recipient === "alice@recipient.com");

  // The documented factory refuses bad opts the same as the callable form.
  var threw = null;
  try { b.mail.send.deliver.create({}); } catch (e) { threw = e; }
  check("create({}) without hostname → deliver/bad-hostname",
    threw && threw.code === "deliver/bad-hostname");
}

// ---- Run ----

async function run() {
  testSurface();
  testFactoryRefusesBadOpts();
  await testDeliverCreateDottedForm();
  await testEnvelopeValidation();
  testOutcomeClassifier();
  await testPeerRefusalIsAHardBounce();
  testDsnComposer();
  testDsnRejectsCrlfHeaderInjection();
  await testNullReversePathIsAValueNotAnAbsence();
  await testNullReversePathGeneratesNoDsn();
  await testDefaultTransportIsTheRealOne();
  await testDeliveryHappyPathStubbed();
  await testMultiAtRecipientRefused();
  await testTransientDefersPermanentFails();
  await testNullMx();
  await testMxFailover();
  await testDanePublishingPeerIsDeliverableUnderEnforce();
  await testDaneRecordsComeFromTheAssertedResolver();
  await testDaneFailureFailsOverAndDefersRatherThanBouncing();
  await testDeferredRecipientsCarryTheHostThatRefused();
  testDaneEnforceWithoutDnssecAssertionIsRefusedAtCreate();
  await testDaneOpportunisticWithoutAssertionDoesNotQuery();
  await testPortReachesTransport();
  await testMaxAttemptsFlowsThrough();
  testClassifierFallthroughs();
  testCreateValidationCodes();
  testDsnDefaultFields();
  await testResolverWrapperShape();
  await testResolverBadShapes();
  await testMxLookupTimeout();
  await testNodeDnsFallback();
  await testRecipientNoDomain();
  await testAllHostsTransient();
  await testPermanentFailKeepsMxHost();
  await testMtaStsMatrix();
  await testMtaStsTestingNotEnforcedUnderLocalEnforce();
  await testDaneMatrix();
  await testDaneEnforceFailsOneRecipientNotBatch();
  await testDaneEnforceBatchSurvivesSiblingFailure();
  await testDsnCallbackFailure();
  await testExtractHeaderBlockVariants();
  await testRetryBudgetClamp();
  await testDefaultAuditEnabled();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[mail-send-deliver] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
