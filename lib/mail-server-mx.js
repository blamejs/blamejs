// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     b.mail.server.mx
 * @nav        Mail
 * @title      Mail MX Server
 * @order      540
 *
 * @intro
 *   Inbound SMTP / MX listener. Composes the framework's existing
 *   mail-gate substrates (`b.mail.helo`, `b.mail.rbl`,
 *   `b.mail.greylist`, `b.guardEnvelope`, `b.mail.auth.dmarc`,
 *   `b.safeMime`, `b.guardEmail`, `b.guardSmtpCommand`,
 *   `b.mail.agent`) into one operator-facing server that accepts
 *   inbound mail per RFC 5321 with PQC-shaped TLS posture, SMTP-
 *   smuggling defense baked into the wire-protocol layer, and the
 *   gate cascade running at the right phase of the state machine.
 *
 *   `create({ ... }).listen()` binds the TCP port; every incoming
 *   connection drives the CONNECT → EHLO → [STARTTLS → EHLO] →
 *   MAIL → RCPT (×N) → DATA → DATA-body → QUIT state machine. Each
 *   phase passes through the operator-supplied gates (defaulting
 *   to "no-op" when the operator hasn't wired a gate) and refuses
 *   with the appropriate 5xx (permanent) or 4xx (transient) SMTP
 *   reply code on gate fail.
 *
 *   ## Defenses baked in
 *
 *   - **SMTP smuggling** (CVE-2023-51764 Postfix / CVE-2023-51765 Sendmail / CVE-2023-51766 Exim) — every
 *     wire line passes through `b.guardSmtpCommand.validate` which
 *     refuses bare LF, bare CR, NUL, C0 controls, DEL, and oversize.
 *     The DATA body's `\r\n.\r\n` terminator is matched on canonical
 *     CRLF only — bare-LF dot-terminators are refused. Together this
 *     defends the CVE-2023-51764 class where a hostile sender
 *     smuggles a second message past the framework's filter by
 *     terminating the first one with `\n.\n` instead of `\r\n.\r\n`.
 *
 *   - **Open-relay defense** — RCPT TO non-local refused with 550
 *     5.7.1 Relaying denied unless the operator explicitly registered
 *     the destination via `relayAllowedFor: [{ cidr, scope }]`. The
 *     default posture is "MX-only, no relay" so a misconfigured boot
 *     can't accidentally become an open relay.
 *
 *   - **STARTTLS stripping (CVE-2021-38371 Exim, CVE-2021-33515 Dovecot)** —
 *     once STARTTLS is advertised + selected, subsequent commands
 *     MUST run over the negotiated TLS context. A pre-STARTTLS
 *     pipelining attempt (RFC 2920) to inject commands that take
 *     effect post-handshake is refused by clearing the command
 *     buffer at STARTTLS time and reading fresh from the TLS socket
 *     only — defends both the Exim and Dovecot variants of the
 *     STARTTLS-injection class.
 *
 *   - **Resource exhaustion** — per-command line cap (default
 *     1 KiB), DATA body cap (default 50 MiB per RFC 5321 §4.5.3.1.7),
 *     per-recipient cap (default 100 per RFC 5321 §4.5.3.1.8),
 *     connection idle timeout (default 5 minutes per RFC 5321
 *     §4.5.3.2.7). Operator opts up with explicit bounds.
 *
 *   - **TLS posture** — `tlsContext` MUST be supplied (no implicit
 *     plaintext-only mode). Operator passes a `b.network.tls.context`
 *     output which carries the framework's TLS 1.3 default + OCSP /
 *     CT-log posture. Pre-STARTTLS plain commands are limited to
 *     EHLO / HELO / STARTTLS / NOOP / QUIT / RSET; MAIL / RCPT /
 *     DATA all refused with 530 5.7.0 Must issue a STARTTLS command
 *     first.
 *
 *   ## Audit lifecycle
 *
 *   - `mail.server.mx.connect`           — IP, TLS state, FCrDNS hostname
 *   - `mail.server.mx.helo`              — HELO greeting, helo-gate verdict
 *   - `mail.server.mx.helo_gate_refused` — HELO identity refused (gate action)
 *   - `mail.server.mx.mail_from`         — sender address
 *   - `mail.server.mx.rcpt_to`           — recipient, rblListed flag, greylist action
 *   - `mail.server.mx.rbl_refused`       — connecting IP on a DNS blocklist (zones)
 *   - `mail.server.mx.greylist_deferred` — (ip, from, rcpt) first-seen 450 deferral
 *   - `mail.server.mx.data_refused`      — refusal reason + SMTP code (5xx vs 4xx)
 *   - `mail.server.mx.envelope_verdict`  — DATA-phase SPF/DKIM/DMARC/ARC results + action (accept / quarantine / reject / defer) + gate mode
 *   - `mail.server.mx.envelope_error`    — DATA-phase authentication pipeline failure or timeout (disposition follows onTemperror)
 *   - `mail.server.mx.delivered`         — agent.handoff ack
 *   - `mail.server.mx.tls_handshake_failed` — handshake error
 *   - `mail.server.mx.smtp_smuggling_detected` — CRLF.CRLF injection class
 *   - `mail.server.mx.relay_refused`     — open-relay attempt
 *   - `mail.server.mx.recipient_refused` — recipientPolicy said the mailbox is unavailable (550 5.1.1)
 *   - `mail.server.mx.recipient_policy_threw` — recipientPolicy failed; the recipient is deferred (451 4.7.1)
 *
 *   ## What v1 does NOT ship
 *
 *   - **AUTH / submission auth** — MX listener is inbound from the
 *     internet, no authentication. Submission listener (port 587) is
 *     a separate slice with SCRAM-SHA-256 / XOAUTH2 / EXTERNAL.
 *   - **Sieve filtering** — composes via `b.mail.agent` at delivery
 *     time; the MX listener doesn't decide policy itself.
 *   - **Outbound DSN generation** — `b.guardDsn` parses inbound DSNs;
 *     outbound DSN emission deferred to the submission slice.
 *   - **8BITMIME** (RFC 6152, obsoletes RFC 1652) — advertised in
 *     the EHLO capabilities since the DATA body parser via
 *     `b.safeMime` is octet-clean; no transcoding needed.
 *   - **SMTPUTF8** (RFC 6531) + **IDN** (RFC 5891) — the wire-protocol
 *     layer here is encoding-agnostic; SMTPUTF8 capability
 *     advertisement is a follow-up slice once the operator's
 *     downstream (mail-store + delivery agent) accepts Unicode
 *     mailbox-local-part bytes. Today the listener does not
 *     advertise SMTPUTF8 and refuses non-ASCII in MAIL FROM /
 *     RCPT TO via `b.guardSmtpCommand`.
 *
 *   ## Composition contract
 *
 *   Every gate is a primitive that already exists. The MX slice is a
 *   state-machine + wire-protocol coordinator — no new crypto, no
 *   new parsing, no new RFC-layer primitives. When the operator
 *   doesn't wire a gate (e.g. omits `opts.greylist`), the listener
 *   skips that phase rather than synthesizing a verdict.
 *
 *   Connection-level gates are wired into the live state machine:
 *   `opts.helo` (HELO identity) evaluates at HELO/EHLO; `opts.rbl`
 *   (connecting-IP DNS blocklist, evaluated once per connection) and
 *   `opts.greylist` ((ip, from, rcpt) first-seen deferral) evaluate at
 *   RCPT TO and surface their verdicts on the `rcpt_to` event.
 *
 *   `opts.recipientPolicy` decides whether a mailbox on a local domain
 *   exists, and is the only way to answer "no such user" the way RFC
 *   5321 §3.3 asks. It runs at RCPT TO, so the refusal costs one command
 *   rather than a whole message body: `{ ok: false, reason }` becomes
 *   550 5.1.1 with the reason, and a throw becomes 451 4.7.1 (a
 *   directory that cannot be reached is not a verdict about the
 *   mailbox). Refusals charge the same per-IP recipient-failure budget
 *   as a relay refusal, because the 250-vs-550 difference is a
 *   mailbox-existence oracle. Unwired, every syntactically valid
 *   recipient on a local domain is accepted and the agent handoff is
 *   the operator's last chance to reject. The

 *   message-authentication gate (`opts.guardEnvelope`) runs at DATA
 *   completion through `b.mail.inbound.verify` — SPF (RFC 7208) on the
 *   envelope identity, DKIM (RFC 6376) on the message bytes, DMARC
 *   (RFC 9989) policy + alignment on the From-header domain, ARC
 *   (RFC 8617) on any chain a forwarder left behind — and in
 *   enforce mode refuses before the agent handoff: 550 5.7.26
 *   (RFC 7372) when the sender's published policy says reject, 550
 *   5.7.1 on the RFC 9989 §5.3.1 multi-From spoofing shape, 451 4.7.0
 *   on DNS temperror or pipeline timeout (operator-tunable via
 *   `onTemperror` / `timeoutMs`). Accepted messages carry the verdict
 *   to the agent handoff as `auth` and gain the receiver's RFC 8601
 *   Authentication-Results header — any sender-attached header forging
 *   this receiver's authserv-id is stripped first (§5) — so downstream
 *   consumers act on authenticated results instead of re-verifying;
 *   monitor mode annotates without refusing.
 *
 * @card
 *   Inbound SMTP / MX listener. RFC 5321 state machine with SMTP-
 *   smuggling defense baked into the wire-protocol layer (RFC 5321
 *   §2.3.8 + CVE-2023-51764 / 51765 / 51766), open-relay refusal by
 *   default, STARTTLS-stripping defense (CVE-2021-38371), and the
 *   connection-level gate cascade (HELO identity / RBL / greylist)
 *   running at the appropriate phase.
 */

var net   = require("node:net");
var lazyRequire = require("./lazy-require");
var boundedMap = require("./bounded-map");
var C         = require("./constants");
var numericBounds = require("./numeric-bounds");
var safeAsync = require("./safe-async");
var safeBuffer = require("./safe-buffer");
var safeSmtp = require("./safe-smtp");
var validateOpts = require("./validate-opts");
var guardSmtpCommand = require("./guard-smtp-command");
var guardDomain = require("./guard-domain");
var guardCidr = require("./guard-cidr");
var ssrfGuard = require("./ssrf-guard");
var mailServerRateLimit = require("./mail-server-rate-limit");
var mailServerTls = require("./mail-server-tls");
var mailServerNet = require("./mail-server-net");
// Elapsed time for the body-rate window — see the note in mail-server-imap.js.
var time = require("./time");
var { defineClass } = require("./framework-error");

var auditEmit = require("./audit-emit");
// Lazy like the sibling host primitives' guard loads — the inbound
// authentication pipeline (and the DKIM verifier whose range
// constants the boot validation mirrors) only loads when an operator
// wires opts.guardEnvelope.
var mailAuth = lazyRequire(function () { return require("./mail-auth"); });
var dkim = lazyRequire(function () { return require("./mail-dkim"); });

var MailServerMxError = defineClass("MailServerMxError", { alwaysPermanent: true });

// RFC 5321 §4.5.3.1 — wire-protocol limits.
var DEFAULT_MAX_LINE_BYTES        = C.BYTES.kib(1);
var DEFAULT_MAX_MESSAGE_BYTES     = C.BYTES.mib(50);
var DEFAULT_MAX_RCPTS_PER_MESSAGE = 100;                                                              // RFC 5321 §4.5.3.1.8 recipient cap
var DEFAULT_IDLE_TIMEOUT_MS       = C.TIME.minutes(5);
var DEFAULT_GREETING              = "blamejs ESMTP";

// SMTP reply-code constants. The framework uses RFC 5321 enhanced
// status codes per RFC 3463 (`Dclass.Dsubject.Ddetail`) embedded in
// the reply lines for operator-side observability.
var REPLY_220_READY              = "220";
var REPLY_221_BYE                = "221";
var REPLY_250_OK                 = "250";
var REPLY_354_START_INPUT        = "354";
var REPLY_421_SERVICE_NOT_AVAIL  = "421";                                                             // SMTP transient code
var REPLY_450_MAILBOX_BUSY       = "450";                                                             // SMTP transient code (greylist tempfail)
var REPLY_451_LOCAL_ERROR        = "451";                                                             // SMTP transient code
var REPLY_452_INSUFFICIENT_STG   = "452";                                                             // SMTP transient code
var REPLY_500_SYNTAX             = "500";                                                             // SMTP permanent code
var REPLY_501_BAD_ARGS           = "501";                                                             // SMTP permanent code
var REPLY_502_NOT_IMPLEMENTED    = "502";                                                             // SMTP permanent code
var REPLY_503_BAD_SEQUENCE       = "503";                                                             // SMTP permanent code
var REPLY_530_AUTH_REQUIRED      = "530";                                                             // SMTP permanent code
var REPLY_550_MAILBOX_UNAVAIL    = "550";                                                             // SMTP permanent code
var REPLY_552_SIZE_EXCEEDED      = "552";                                                             // SMTP permanent code
var REPLY_554_TRANSACTION_FAILED = "554";                                                             // SMTP permanent code

var RE_MAIL_FROM = /^MAIL\s+FROM:\s*<([^>]*)>(?:\s+(.*))?$/i;
var RE_RCPT_TO   = /^RCPT\s+TO:\s*<([^>]+)>(?:\s+.*)?$/i;
var RE_SIZE      = /SIZE=(\d+)/i;

// A relayAllowedFor entry's `cidr` must be an `<ip>/<prefix>` range so the
// relay-authorization decision can match the connecting peer against it via
// b.ssrfGuard.cidrContains (the same range arithmetic the HTTP
// b.middleware.networkAllowlist fence uses). Shape-validated by composing
// b.guardCidr.validate rather than a hand-rolled parse: a mask is REQUIRED
// (a bare IP never matches in cidrContains, so it is refused at boot rather
// than silently disabling the entry), reserved / private ranges are ALLOWED
// (a relay allowlist legitimately names 10.0.0.0/8 and friends), and a
// non-canonical-but-functional network address (host bits set) is audited,
// not rejected — cidrContains masks it off at match time.
var _RELAY_CIDR_OPTS = Object.freeze({
  requireMaskPolicy:      "reject-bare-ip",
  reservedRangesPolicy:   "allow",
  ipv4MappedIpv6Policy:   "allow",
  networkAlignmentPolicy: "audit",
  family:                 "either",
});

// _normalizeRelayCidr — fold a DOTTED IPv4-mapped IPv6 relay CIDR
// (::ffff:a.b.c.d/N, N in 96..128) to its plain IPv4 CIDR (a.b.c.d/(N-96)).
// guardCidr.validate parses hex-group IPv6 but not the dotted-mapped spelling,
// so an operator naming a mapped range that way would be refused at boot even
// though cidrContains accepts it. Folding to plain IPv4 both validates AND
// makes the entry match every peer form: a genuine IPv4 peer directly, and an
// IPv4-mapped peer via the _isRelayAllowed fold. Storing the mapped CIDR as-is
// would instead match a mapped peer but NOT a genuine IPv4 peer (the inverse
// asymmetry). Every other spelling (plain IPv4, hex-group IPv6) is unchanged.
function _normalizeRelayCidr(cidr) {
  if (typeof cidr !== "string") return cidr;
  var m = /^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,3})$/i.exec(cidr);
  if (!m) return cidr;
  var prefix = parseInt(m[2], 10);
  if (prefix < 96 || prefix > 128) return cidr;   // outside the ::ffff:0:0/96 block — a genuine IPv6 range
  return m[1] + "/" + (prefix - 96);
}

// Map the b.mail.inbound.verify verdict to the DATA-phase gate action.
// The sender's published DMARC policy drives it (RFC 9989 §4.7 p= /
// §5.3.6 disposition): reject → refuse at the wire; quarantine →
// deliver annotated (an MX cannot spam-folder — the downstream agent
// owns disposition); none / pass → accept. DNS temperror defers or
// accepts per the operator's onTemperror choice. permerror carries a
// reject recommendation only for the multi-From spoofing shape
// (RFC 9989 §5.3.1), set by the pipeline itself.
function _envelopeActionFor(inbound, gate) {
  var dmarc = inbound.dmarc || {};
  if (dmarc.result === "temperror") {
    return gate.onTemperror === "accept" ? "accept" : "defer";
  }
  if (dmarc.recommendedAction === "reject") return "reject";
  if (dmarc.recommendedAction === "quarantine") return "quarantine";
  return "accept";
}

// RFC 8601 §5 — an MTA adding its own Authentication-Results header
// MUST first remove any existing instance claiming its authserv-id: a
// sender can pre-attach a forged header carrying the receiver's name
// ("Authentication-Results: mx.example.com; dmarc=pass") and downstream
// consumers that trust the receiver's A-R header would read the forged
// verdict instead of the computed one. Headers naming OTHER
// authserv-ids are prior-hop information and stay. Operates on the
// header block only — the block is decoded as latin1 (byte-preserving
// round-trip) and the body bytes are never decoded at all, so 8-bit
// content is untouched.
function _stripForgedAuthResults(messageBuf, authservId) {
  if (!authservId) return messageBuf;
  var sepIdx = messageBuf.indexOf("\r\n\r\n");
  var headerEnd = sepIdx === -1 ? messageBuf.length : sepIdx + 2;
  var head = messageBuf.slice(0, headerEnd).toString("latin1");
  var rest = messageBuf.slice(headerEnd);
  if (head.toLowerCase().indexOf("authentication-results:") === -1) return messageBuf;
  var lines = head.split("\r\n");
  var out = [];
  var skipping = false;
  var prefix = "authentication-results:";
  var wantId = authservId.toLowerCase();
  for (var i = 0; i < lines.length; i += 1) {
    var line = lines[i];
    if (skipping && (line.charAt(0) === " " || line.charAt(0) === "\t")) continue;  // folded continuation
    skipping = false;
    if (line.slice(0, prefix.length).toLowerCase() === prefix) {
      var idTok = line.slice(prefix.length).trim().split(/[;\s]/)[0].toLowerCase();
      if (idTok === wantId) { skipping = true; continue; }
    }
    out.push(line);
  }
  return Buffer.concat([Buffer.from(out.join("\r\n"), "latin1"), rest]);
}

/**
 * @primitive b.mail.server.mx.create
 * @signature b.mail.server.mx.create(opts)
 * @since     0.9.46
 * @status    stable
 * @related   b.mail.helo.evaluate, b.mail.rbl.create, b.mail.greylist.create, b.guardEnvelope.check, b.mail.agent.create
 *
 * Build the MX listener. Returns `{ listen({ port?, address? }),
 * close({ timeoutMs? }), connectionCount(), _portForTest() }`.
 *
 * @opts
 *   tlsContext:        TlsContext,      // required — a SecureContext built from
 *                                       // b.network.tls.buildOptions() (no implicit plaintext)
 *   greeting:          string,          // default "blamejs ESMTP" — HELO/EHLO 220-line banner
 *   helo:              b.mail.helo,            // optional gate — HELO identity (FCrDNS / shape / self-name)
 *   rbl:               b.mail.rbl.create(…),   // optional gate — DNS blocklist on the connecting IP
 *   greylist:          b.mail.greylist.create(…), // optional gate — defer first-seen (ip, from, rcpt)
 *   agent:             b.mail.agent,    // optional delivery handoff. A rejection may carry smtpCode
 *                                      // ("550"), enhancedStatus ("5.7.1") and replyText to choose its
 *                                      // own refusal; without them the reply is 451 4.3.0
 *   relayAllowedFor:   [{ cidr, scope }],  // operator-explicit relay allowlist; default [] = MX-only
 *   localDomains:      [string]|fn,     // RCPT TO local-domain allowlist (refuse non-local with 550 5.7.1). A function returning the array is answered per RCPT, for a hosted set the operator changes while the server runs; an entry it returns that b.guardDomain refuses is dropped with an audit event rather than throwing on the connection that happened to arrive.
 *   recipientPolicy:   function (ctx) → { ok } | { ok: false, reason },  // optional RCPT-time mailbox check; refuses 550 5.1.1, defers 451 when it throws
 *   maxLineBytes:      number,          // default 1 KiB — per-command line cap
 *   maxMessageBytes:   number,          // default 50 MiB — DATA body cap
 *   maxRcptsPerMessage: number,         // default 100 — per RFC 5321 §4.5.3.1.8
 *   idleTimeoutMs:     number,          // default 5 minutes — RFC 5321 §4.5.3.2.7
 *   maxConnections:    number,          // default 1024 — listener-wide ceiling
 *   profile:           "strict" | "balanced" | "permissive",  // gate posture cascade
 *   guardEnvelope:     true | {        // optional gate — DATA-phase SPF/DKIM/DMARC/ARC via b.mail.inbound.verify
 *     mode?:          "enforce" | "monitor",   // default: enforce (monitor when profile is permissive)
 *     onTemperror?:   "defer" | "accept",      // DNS temperror disposition; default "defer" (451 4.7.5)
 *     authservId?:    string,                  // RFC 8601 authserv-id; defaults to the first local domain, re-read per message when localDomains is a function
 *     dnsLookup?:     function,                // async (qname, type) override for SPF/DKIM/DMARC lookups
 *     maxSignatures?: number,                  // DKIM verify cap (1-16)
 *     clockSkewMs?:   number,                  // DKIM timestamp skew tolerance
 *     minRsaBits?:    number,                  // DKIM minimum RSA key size
 *     timeoutMs?:     number,                  // pipeline wall-clock ceiling; default 20s (timeout → temperror disposition)
 *   },
 *
 * @example
 *   var tls = require("node:tls").createSecureContext(
 *     b.network.tls.buildOptions({ cert: certPem, key: keyPem }));
 *   var server = b.mail.server.mx.create({
 *     tlsContext:   tls,
 *     greeting:     "mx.example.com ESMTP blamejs",
 *     helo:         b.mail.helo,
 *     rbl:          b.mail.rbl.create({ providers: ["zen.spamhaus.org"] }),
 *     greylist:     b.mail.greylist.create({ store: greylistStore }),
 *     agent:        b.mail.agent.create({ store: mailStore }),
 *     localDomains: ["example.com"],
 *   });
 *   await server.listen({ port: 25 });
 */
function create(opts) {
  validateOpts.requireObject(opts, "mail.server.mx.create",
    MailServerMxError, "mail-server-mx/bad-opts");
  if (!opts.tlsContext) {
    throw new MailServerMxError("mail-server-mx/no-tls-context",
      "mail.server.mx.create: tlsContext is required (no implicit plaintext mode). " +
      "Use b.mail.server.tls.context({ certFile, keyFile, watch: true }) to load + " +
      "auto-reload a cert/key pair from disk, or pass a node:tls.createSecureContext " +
      "output directly. Cert provisioning lives in b.acme (RFC 8555 + RFC 9773 ARI).");
  }
  numericBounds.requireAllPositiveFiniteIntIfPresent(opts,
    ["maxLineBytes", "maxMessageBytes", "maxRcptsPerMessage", "idleTimeoutMs", "maxConnections"],
    "mail.server.mx.", MailServerMxError, "mail-server-mx/bad-bound");
  // An EMPTY array is accepted and means "this server hosts no domains", which
  // is a real state — a first boot before the first domain is added — and the
  // only honest thing to do with it is refuse every recipient. Refusing it at
  // construction left the operator with one spelling that started a server
  // (omitting the option), and that spelling used to skip the relay check
  // entirely, so the only way to get a listener was to get one that accepted
  // everything. An allowlist that disappears when it is empty is a firewall
  // rule set that opens when the last rule is deleted.
  if (opts.localDomains !== undefined && !Array.isArray(opts.localDomains) &&
      typeof opts.localDomains !== "function") {
    throw new MailServerMxError("mail-server-mx/bad-opts",
      "mail.server.mx.create: localDomains must be an array of domain strings, or a " +
      "function returning one when the hosted set changes while the server runs " +
      "(an empty array means this server hosts no domains and refuses every recipient)");
  }
  if (opts.relayAllowedFor !== undefined && !Array.isArray(opts.relayAllowedFor)) {
    throw new MailServerMxError("mail-server-mx/bad-opts",
      "mail.server.mx.create: relayAllowedFor must be an array if provided");
  }
  // Every relay-allowlist entry MUST carry a valid `<ip>/<prefix>` CIDR:
  // relay is granted only to a peer whose address falls inside an allowlisted
  // range. Refuse a malformed / mask-less entry at boot so an operator typo
  // can't silently leave the relay decision mis-scoped (open relay is the
  // failure this closes — pre-fix any non-empty relayAllowedFor admitted
  // every peer regardless of source address).
  if (Array.isArray(opts.relayAllowedFor)) {
    for (var __ri = 0; __ri < opts.relayAllowedFor.length; __ri += 1) {
      var __re = opts.relayAllowedFor[__ri];
      var __reOk = __re && typeof __re === "object" && !Array.isArray(__re) &&
        guardCidr.validate(_normalizeRelayCidr(__re.cidr), _RELAY_CIDR_OPTS).ok;
      if (!__reOk) {
        throw new MailServerMxError("mail-server-mx/bad-relay-cidr",
          "mail.server.mx.create: relayAllowedFor[" + __ri + "] must be an object with a " +
          "valid CIDR string (e.g. { cidr: \"10.0.0.0/8\", scope: \"internal\" }); relay is " +
          "granted only to peers whose source address falls inside an allowlisted range");
      }
    }
  }

  var greeting          = opts.greeting          || DEFAULT_GREETING;
  var maxLineBytes      = opts.maxLineBytes      || DEFAULT_MAX_LINE_BYTES;
  var maxMessageBytes   = opts.maxMessageBytes   || DEFAULT_MAX_MESSAGE_BYTES;
  var maxRcptsPerMsg    = opts.maxRcptsPerMessage || DEFAULT_MAX_RCPTS_PER_MESSAGE;
  var idleTimeoutMs     = opts.idleTimeoutMs     || DEFAULT_IDLE_TIMEOUT_MS;
  // The hosted-domain set is administrative state, not configuration: operators
  // add and withdraw domains while the process runs, and that is an ordinary
  // act rather than a reconfiguration. Captured once, a withdrawn domain kept
  // drawing 250 at RCPT until a restart — with every management surface
  // agreeing it was gone and nothing telling the operator mail was still
  // arriving for it — while a newly added one drew 550 5.7.1, which a sending
  // queue reads as "never retry" rather than "not yet".
  //
  // So it may be a function, answered per RCPT. The neighbouring
  // recipientPolicy already is, which is what made the frozen half odd: the two
  // parts of one question were answered a line apart with different currency.
  // The array form is unchanged and still validated once at boot.
  var localDomainsFn    = typeof opts.localDomains === "function" ? opts.localDomains : null;
  var localDomains      = localDomainsFn
    ? []
    : (opts.localDomains || []).map(function (d) { return String(d).toLowerCase(); });
  var relayAllowedFor   = (opts.relayAllowedFor || []).map(function (__e) {
    return (__e && typeof __e === "object" && !Array.isArray(__e))
      ? Object.assign({}, __e, { cidr: _normalizeRelayCidr(__e.cidr) })
      : __e;
  });
  var profile           = opts.profile || "strict";
  // SMTPUTF8 (RFC 6531) — single switch threaded end-to-end. The MX
  // listener doesn't advertise SMTPUTF8 to the peer regardless, so
  // this defaults `false` (refuse non-ASCII bytes in every command
  // line). Operators that want to accept SMTPUTF8 for downstream
  // relay flip this `true` and the same switch reaches every
  // `guardSmtpCommand.validate` call.
  var allowSmtpUtf8     = opts.allowSmtpUtf8 === true;

  // Default-on per-IP rate limit. Operators pass `rateLimit: false` to
  // disable (only for tests / closed networks), pass a rate-limit
  // handle from b.mail.server.rateLimit.create({...}) to share one
  // budget across multiple listeners, or pass an opts object to
  // override defaults.
  var rateLimit = mailServerRateLimit.resolve(opts.rateLimit);

  // DATA-phase message-authentication gate. `guardEnvelope: true`
  // gates with defaults; an object tunes it. Like the sibling gates
  // (helo / rbl / greylist) the phase is skipped when the operator
  // doesn't wire it — the gate needs live DNS to evaluate the
  // sender's published policy, which closed-network deployments may
  // not have.
  var envelopeGate = null;
  if (opts.guardEnvelope !== undefined && opts.guardEnvelope !== false) {
    if (opts.guardEnvelope !== true &&
        (typeof opts.guardEnvelope !== "object" || opts.guardEnvelope === null ||
         Array.isArray(opts.guardEnvelope))) {
      throw new MailServerMxError("mail-server-mx/bad-opts",
        "mail.server.mx.create: guardEnvelope must be true, false, or a config object");
    }
    var ge = opts.guardEnvelope === true ? {} : opts.guardEnvelope;
    validateOpts(ge, ["mode", "onTemperror", "authservId", "dnsLookup",
                      "maxSignatures", "clockSkewMs", "minRsaBits", "timeoutMs"],
                 "mail.server.mx.guardEnvelope");
    var geMode = (ge.mode === undefined || ge.mode === null)
      ? (profile === "permissive" ? "monitor" : "enforce")
      : ge.mode;
    if (geMode !== "enforce" && geMode !== "monitor") {
      throw new MailServerMxError("mail-server-mx/bad-opts",
        "mail.server.mx.create: guardEnvelope.mode must be 'enforce' or 'monitor'");
    }
    var geOnTemperror = (ge.onTemperror === undefined || ge.onTemperror === null)
      ? "defer" : ge.onTemperror;
    if (geOnTemperror !== "defer" && geOnTemperror !== "accept") {
      throw new MailServerMxError("mail-server-mx/bad-opts",
        "mail.server.mx.create: guardEnvelope.onTemperror must be 'defer' or 'accept'");
    }
    if (ge.authservId !== undefined && ge.authservId !== null) {
      validateOpts.requireNonEmptyString(ge.authservId,
        "mail.server.mx.create: guardEnvelope.authservId",
        MailServerMxError, "mail-server-mx/bad-opts");
    }
    if (ge.dnsLookup !== undefined && ge.dnsLookup !== null &&
        typeof ge.dnsLookup !== "function") {
      throw new MailServerMxError("mail-server-mx/bad-opts",
        "mail.server.mx.create: guardEnvelope.dnsLookup must be a function");
    }
    // DKIM bounds caught at boot, not at the first DATA — mirroring
    // the exact ranges b.mail.dkim.verify enforces per call, so an
    // operator typo fails startup instead of turning every live
    // message into an envelope_error + temperror disposition.
    numericBounds.requireAllPositiveFiniteIntIfPresent(ge,
      ["maxSignatures", "clockSkewMs", "minRsaBits", "timeoutMs"],
      "mail.server.mx.guardEnvelope.", MailServerMxError, "mail-server-mx/bad-bound");
    if (ge.maxSignatures !== undefined && ge.maxSignatures !== null &&
        ge.maxSignatures > dkim().DKIM_MAX_SIGNATURES_PER_MESSAGE_CEILING) {
      throw new MailServerMxError("mail-server-mx/bad-bound",
        "mail.server.mx.create: guardEnvelope.maxSignatures " + ge.maxSignatures +
        " exceeds the DKIM verifier ceiling " +
        dkim().DKIM_MAX_SIGNATURES_PER_MESSAGE_CEILING +
        " (RFC 6376 §6.1 fan-out DoS bound)");
    }
    if (ge.clockSkewMs !== undefined && ge.clockSkewMs !== null &&
        ge.clockSkewMs > dkim().DKIM_CLOCK_SKEW_MS_MAX) {
      throw new MailServerMxError("mail-server-mx/bad-bound",
        "mail.server.mx.create: guardEnvelope.clockSkewMs " + ge.clockSkewMs +
        " exceeds the DKIM verifier ceiling " + dkim().DKIM_CLOCK_SKEW_MS_MAX +
        " (RFC 6376 §3.5 back-dating replay defense)");
    }
    envelopeGate = Object.freeze({
      mode:          geMode,
      onTemperror:   geOnTemperror,
      // RFC 8601 authserv-id — the receiver's own name on the
      // Authentication-Results header. Defaults to the first local
      // domain; with neither, the header is skipped (the verdict
      // still reaches the agent handoff).
      // A getter, so a listener whose hosted set is a function does not pin the
      // authserv-id to whichever domain happened to be first at boot. Freezing
      // the object prevents redefining this, not invoking it.
      get authservId() { return ge.authservId || _resolveLocalDomains()[0] || null; },
      dnsLookup:     ge.dnsLookup || undefined,
      maxSignatures: ge.maxSignatures,
      clockSkewMs:   ge.clockSkewMs,
      minRsaBits:    ge.minRsaBits,
      // Wall-clock ceiling for the whole pipeline (SPF include chains
      // + per-signature DKIM key fetches + DMARC policy walk). A
      // message stuffed with signatures pointing at slow resolvers
      // must not pin the connection slot — on timeout the message
      // takes the temperror disposition (defer / accept per
      // onTemperror).
      timeoutMs:     (ge.timeoutMs === undefined || ge.timeoutMs === null)
        ? C.TIME.seconds(20) : ge.timeoutMs,
    });
  }

  // Default-on operator-supplied-domain hardening. opts.localDomains
  // and the HELO / MAIL FROM / RCPT TO domain validations all route
  // through `b.guardDomain` for IDN homograph / Punycode-spoof defense
  // (mixed-script confusable class), special-use-domain refusal (RFC 6761), label-length cap
  // (RFC 1035 §2.3.4), and bare-IP-as-domain refusal (CVE-2021-22931
  // class). Operators with a closed-network deployment can pass
  // `guardDomain: false` to skip; the default keeps the protection on.
  var guardDomainProfile;
  if (opts.guardDomain === false) {
    guardDomainProfile = null;
  } else {
    guardDomainProfile = guardDomain.buildProfile({
      profile: opts.guardDomain && typeof opts.guardDomain === "object"
        ? (opts.guardDomain.profile || profile)
        : profile,
    });
  }
  function _validateDomainHardened(d, label) {
    return mailServerNet.validateDomainHardened(d, label, {
      guardDomainProfile: guardDomainProfile,
      guardDomain:        guardDomain,
      emit:               _emit,
      refusedEvent:       "mail.server.mx.domain_refused",
    });
  }

  // Pre-validate operator-supplied localDomains at boot — the same
  // shape they enforce on RCPT TO must itself pass the validator,
  // otherwise an operator who typed an IDN homograph (or an IP) into
  // their allowlist would silently weaken the gate.
  if (guardDomainProfile) {
    for (var __ldi = 0; __ldi < localDomains.length; __ldi += 1) {
      var __ldVerdict = guardDomain.validate(localDomains[__ldi], guardDomainProfile);
      if (!__ldVerdict.ok) {
        throw new MailServerMxError("mail-server-mx/bad-local-domain",
          "mail.server.mx.create: localDomains[" + __ldi + "] '" + localDomains[__ldi] +
          "' rejected by b.guardDomain (" +
          (__ldVerdict.issues && __ldVerdict.issues[0] && __ldVerdict.issues[0].kind) + ")");
      }
    }
  }

  // Resolve the hosted set at the point it is needed.
  //
  // The array form was checked at boot and cannot change, so it is returned as
  // is. The function form is checked when it is read, because a set that can
  // change can acquire a bad entry after boot — an IDN homograph typed into an
  // admin form is exactly the case the boot check exists for, and it would
  // otherwise reach RCPT unexamined.
  //
  // A bad entry is DROPPED rather than thrown on. This is the request path: a
  // throw here would take down the connection that happened to arrive, and the
  // operator would see a mail outage rather than a typo. Dropping refuses mail
  // for the entry that failed and keeps serving the domains that passed, which
  // is what an allowlist with one bad line should do. Each distinct bad value
  // is reported once so it does not become a per-recipient log flood.
  //
  // The cache key is the CONTENT of the returned set, never its identity. An
  // operator holding one array and mutating it — push on add, splice on
  // withdraw — hands back the same object every time, which is the most
  // ordinary way to keep this state. Keyed on identity, that array would be
  // normalized once and then frozen: added domains refused forever and
  // withdrawn ones accepted forever, which is this very bug wearing a hat.
  var _ldSeenKey = null;
  var _ldSeenOut = [];
  // Bounded, because its keys come from the operator's live set and a control
  // plane that churns tenants — or an admin form collecting typos — would
  // otherwise grow this without limit for the life of the process, one entry
  // per distinct bad value ever seen. It exists only to stop a per-recipient
  // log flood, so evicting the oldest costs at most a repeated warning about a
  // domain nobody has mentioned in a long time.
  var _ldWarned = boundedMap.boundedMap({ maxEntries: 256, policy: "evict-oldest" });

  // Warn once per distinct reason. getOrInsert runs the factory only when the
  // key is absent, which is the whole "first time only" rule — a hand-rolled
  // has-then-set says the same thing in two statements that can drift apart.
  function _warnOnce(key, emitFn) {
    boundedMap.getOrInsert(_ldWarned, key, function () { emitFn(); return true; });
  }

  // Backstop for the whole resolution, not any one operation inside it.
  //
  // Three separate throws were found here one at a time — the callback itself,
  // serializing its result, coercing an entry — and each was guarded where it
  // stood. The rule is what matters rather than the list: NOTHING in resolving
  // an operator-supplied set may reach the RCPT handler as an exception, since
  // there it ends the connection of whoever happened to be delivering. An
  // unreadable set means no domains are known, and no domains known means every
  // recipient is refused, which is what an empty hosted set already means.
  function _resolveLocalDomains() {
    try { return _resolveLocalDomainsInner(); }
    catch (err) {
      _warnOnce("__resolver", function () {
        _emit("mail.server.mx.local_domains_unavailable",
          { reason: "resolver-threw",
            remark: String((err && err.message) || err).slice(0, 200) },
          "warning");
      });
      return [];
    }
  }

  function _resolveLocalDomainsInner() {
    if (!localDomainsFn) return localDomains;
    var raw;
    try { raw = localDomainsFn(); }
    catch (err) {
      _warnOnce("__threw", function () {
        _emit("mail.server.mx.local_domains_unavailable",
          { reason: "threw", remark: String((err && err.message) || err).slice(0, 200) },
          "warning");
      });
      return [];
    }
    if (!Array.isArray(raw)) {
      _warnOnce("__shape", function () {
        _emit("mail.server.mx.local_domains_unavailable",
          { reason: "not-an-array", remark: "localDomains() returned " + (typeof raw) },
          "warning");
      });
      return [];
    }
    // Coerce first, and key the cache on the COERCED strings.
    //
    // Keying on the raw array does not work: JSON.stringify is not injective
    // with respect to the String() that follows it. Two objects with different
    // toString() results both serialize as {}, and undefined, null and
    // functions are indistinguishable inside an array — so two genuinely
    // different hosted sets could share a key and the second one would be
    // answered from the first one's cache. A withdrawn domain would stay
    // accepted, which is the bug the callback exists to fix.
    //
    // Coercion is per ENTRY and guarded, because it runs with operator-supplied
    // runtime data inside RCPT handling: an object whose toString throws must
    // drop that entry, not end the connection that happened to arrive.
    var coerced = [];
    for (var i = 0; i < raw.length; i += 1) {
      try {
        coerced.push(String(raw[i]).toLowerCase());
      } catch (entryErr) {
        var entryIndex = i;
        var entryReason = String((entryErr && entryErr.message) || entryErr).slice(0, 160);
        _warnOnce("__entry" + entryIndex, function () {
          _emit("mail.server.mx.local_domain_refused",
            { domain: null, kind: "unreadable",
              remark: "localDomains() entry " + entryIndex + " could not be read (" +
                      entryReason +
                      "); it is refused and the rest of the set still serves" },
            "warning");
        });
      }
    }

    // Every element is a string now, so this key is injective over exactly the
    // values the decision below is made from. Coercion is cheap and runs every
    // time; what the cache buys is skipping a b.guardDomain call per entry per
    // recipient, which is the expensive half.
    var contentKey = JSON.stringify(coerced);
    if (contentKey === _ldSeenKey) return _ldSeenOut;

    // One bad entry drops and the rest of the set still serves, which is the
    // same answer the guard gives for one it rejects on its merits.
    var out = [];
    for (var ci = 0; ci < coerced.length; ci += 1) {
      var d = coerced[ci];
      if (guardDomainProfile) {
        var verdict;
        try { verdict = guardDomain.validate(d, guardDomainProfile); }
        catch (guardErr) {
          var guardReason = String((guardErr && guardErr.message) || guardErr).slice(0, 160);
          _warnOnce("__guard:" + d, function () {
            _emit("mail.server.mx.local_domain_refused",
              { domain: d, kind: "guard-threw",
                remark: "b.guardDomain threw on this entry (" + guardReason +
                        "); it is refused and the rest of the set still serves" },
              "warning");
          });
          continue;
        }
        if (!verdict.ok) {
          var refusedDomain = d;
          var refusedKind =
            (verdict.issues && verdict.issues[0] && verdict.issues[0].kind) || null;
          _warnOnce(refusedDomain, function () {
            _emit("mail.server.mx.local_domain_refused",
              { domain: refusedDomain,
                kind: refusedKind,
                remark: "rejected by b.guardDomain; mail for it is refused and the rest " +
                        "of the set still serves" },
              "warning");
          });
          continue;
        }
      }
      out.push(d);
    }
    _ldSeenKey = contentKey;
    _ldSeenOut = out;
    return out;
  }

  var connections  = new Set();

  var _emit = auditEmit.emit;

  // ---- Per-connection state machine ---------------------------------------
  function _handleConnection(socket) {
    // 421 4.7.0 — transient refusal; sender retries elsewhere or later.
    // RFC 5321 §3.8 + §4.5.4.2 (transient negative completion).
    var accepted = mailServerNet.acceptConnection(socket, {
      rateLimit:    rateLimit,
      connections:  connections,
      emit:         _emit,
      refusedEvent: "mail.server.mx.rate_limit_refused",
      refusalLine:  "421 4.7.0 Too many connections from your IP\r\n",
      idPrefix:     "mxconn-",
    });
    if (accepted === null) return;
    var remoteAddress = accepted.remoteAddress;
    var connectionId  = accepted.connectionId;

    // Backpressure observer — `_writeReply` flips `_bpEmitted` after
    // the first audit emission per socket to bound the audit volume.
    socket._bpEmit = function () {
      _emit("mail.server.mx.write_backpressure",
        { connectionId: connectionId, remoteAddress: remoteAddress,
          stage: state && state.stage, bufferedBytes: socket.writableLength || 0 },
        "warning");
    };

    var state = {
      id:            connectionId,
      remoteAddress: remoteAddress,
      remotePort:    socket.remotePort || null,
      tls:           false,
      stage:         "connect",   // connect | ehlo | mail | rcpt | data-body | done
      helo:          null,
      mailFrom:      null,
      rcpts:         [],
      messageBytes:  0,
      lastDataByteTime: 0,
    };

    // Raw byte buffer (NOT a string) — DATA bodies under 8BITMIME may
    // carry bytes that are invalid UTF-8; round-tripping through a
    // string decode would replace them with U+FFFD and corrupt the
    // message. Decode to string only for the per-command line parse.
    var lineBuffer = Buffer.alloc(0);
    var bodyCollector = null;
    // Watches the DATA body for its terminator and the smuggling shape as bytes
    // arrive, so neither screen re-reads what it has already seen. Lives exactly
    // as long as bodyCollector.
    var bodyScanner = null;
    // The slow-loris byte-rate floor, measured over bounded windows so an early
    // burst cannot buy credit for a slow tail.
    var bodyRateWindow = mailServerNet.createBodyRateWindow(rateLimit);
    // Every byte this connection has received, counted once at the wire funnel.
    var wireBytes = 0;
    var inDataBody = false;
    // Async command pump: gates (HELO / RBL / greylist / envelope /
    // DMARC) may await DNS or a store, so command handling is async.
    // `pumpChain` FIFO-serializes per-chunk processing so a gate
    // resolving cannot let a later pipelined command (RFC 2920) jump
    // ahead of an earlier one — reply ordering + the per-command
    // smuggling defenses stay intact. `connClosed` short-circuits any
    // chunk queued before a teardown.
    var pumpChain = Promise.resolve();
    var connClosed = false;

    socket.setTimeout(idleTimeoutMs);
    socket.on("timeout", function () {
      _writeReply(socket, REPLY_421_SERVICE_NOT_AVAIL, "4.4.2 Idle timeout");
      _closeConnection(socket);
    });

    socket.on("error", function (err) {
      _emit("mail.server.mx.socket_error",
        { connectionId: state.id, code: (err && err.code) || "unknown", message: err && err.message },
        "warning");
      _closeConnection(socket);
    });

    // The set entry and the rate-limit slot are released by trackConnection;
    // this handler carries only the per-transaction flag the drain reads.
    socket.on("close", function () { connClosed = true; });

    _emit("mail.server.mx.connect", {
      connectionId:  state.id,
      remoteAddress: state.remoteAddress,
      remotePort:    state.remotePort,
      tls:           false,
    });

    // 220 banner — RFC 5321 §3.1.
    _writeReply(socket, REPLY_220_READY, greeting + " ready");

    // Feed a chunk into the per-connection command pump. Chains each
    // chunk behind the previous one's full (async) processing so command
    // handlers + their gates run strictly in arrival order. Used by BOTH
    // the plaintext `socket.on("data")` path AND the post-STARTTLS
    // TLSSocket onData path — otherwise gate awaits on the upgraded
    // socket would overlap later TLS chunks (the default strict/balanced
    // profiles require STARTTLS before MAIL, so the gates run there) and
    // async gate rejections would go unhandled instead of producing the
    // 421 path. `activeSock` is whichever socket is current (plaintext or
    // TLS) so the 421/close lands on the right transport.
    function _feedChunk(activeSock, chunk) {
      // Every wire byte, counted once, on the single funnel both the plaintext
      // and the post-STARTTLS socket feed. The rate window takes its baseline
      // from this, so the measurement is "bytes since the transfer opened"
      // rather than "bytes the body parser happened to see" — the distinction
      // that let the sibling listener's count go flat across a window roll.
      wireBytes += chunk.length;
      pumpChain = pumpChain.then(function () {
        if (connClosed) return undefined;
        return _ingestBytes(state, activeSock, chunk);
      }).catch(function (err) {
        if (connClosed) return;
        _emit("mail.server.mx.handler_threw",
          { connectionId: state.id, error: (err && err.message) || String(err) },
          "failure");
        try { _writeReply(activeSock, REPLY_421_SERVICE_NOT_AVAIL, "4.3.0 Server error"); }
        catch (_e) { /* socket already gone */ }
        _closeConnection(activeSock);
      });
    }

    socket.on("data", function (chunk) { _feedChunk(socket, chunk); });

    // ---- Byte-level ingestion --------------------------------------------
    async function _ingestBytes(state, socket, chunk) {
      // The body-rate floor is enforced HERE, on every inbound byte, rather
      // than inside the DATA handler below. A check reached only from a body
      // handler is one the peer chooses whether to reach: on the sibling
      // listener the same floor was skipped first by using BDAT, then by a
      // zero-length chunk, then by interleaving NOOP, each of which resets the
      // socket idle timer without passing through a body handler. What a peer
      // cannot do is hold the connection without sending bytes, and every byte
      // arrives here.
      if (inDataBody && bodyRateWindow.starved(wireBytes, time.monotonicMs())) {
        _emit("mail.server.mx.data_refused",
          { connectionId: state.id, reason: "body-rate-below-floor",
            minBytesPerSecond: rateLimit.minBytesPerSecond() }, "denied");
        _writeReply(socket, REPLY_421_SERVICE_NOT_AVAIL,
          "4.7.0 Message body arriving below the minimum rate; closing connection");
        _resetTransaction(state);
        inDataBody = false;
        bodyCollector = null;
        bodyScanner = null;
        _closeConnection(socket);
        return;
      }
      if (inDataBody) {
        // DATA body — accumulate via boundedChunkCollector, watch for
        // canonical "\r\n.\r\n" terminator only. Bare-LF dot terminator
        // is the SMTP smuggling shape (CVE-2023-51764); refused.
        try { bodyCollector.push(chunk); }
        catch (_e) {
          _emit("mail.server.mx.data_refused",
            { connectionId: state.id, reason: "body-too-large", maxBytes: maxMessageBytes },
            "denied");
          _writeReply(socket, REPLY_552_SIZE_EXCEEDED,
            "5.3.4 Message size exceeds fixed maximum (" + maxMessageBytes + " bytes)");
          _resetTransaction(state);
          inDataBody = false;
          bodyCollector = null;
          bodyScanner = null;
          return;
        }
        // Scanned INCREMENTALLY — only this chunk plus a four-byte overlap.
        // Re-deriving the whole accumulated body per chunk (`result()` is a
        // fresh concat of everything received so far) and scanning it twice
        // made acceptance quadratic in the message size. The byte cap bounds
        // BYTES, not processor time, so a message well inside maxMessageBytes
        // still cost 4949 ms at 8 MiB against 143 ms at 1 MiB — and on this
        // listener that is reachable unauthenticated. `result()` is now called
        // ONCE, when the terminator is found.
        //
        // The slow-loris floor is NOT applied here — it runs at the top of
        // _ingestBytes, where every inbound byte passes whatever command it
        // belongs to.
        var seen = bodyScanner.push(chunk);
        // Smuggling detector — bare LF dot-line in body before the CRLF dot
        // terminator. Refuse the whole transaction; emit a smuggling audit.
        if (seen.smuggling) {
          _emit("mail.server.mx.smtp_smuggling_detected",
            { connectionId: state.id, mailFrom: state.mailFrom, rcptCount: state.rcpts.length },
            "denied");
          _writeReply(socket, REPLY_554_TRANSACTION_FAILED,
            "5.7.0 Bare-LF in DATA body refused (RFC 5321 §2.3.8; CVE-2023-51764 SMTP smuggling)");
          _resetTransaction(state);
          inDataBody = false;
          bodyCollector = null;
          bodyScanner = null;
          return;
        }
        // Canonical \r\n.\r\n terminator?
        if (seen.terminatorAt !== -1) {
          var body = bodyCollector.result().subarray(0, seen.terminatorAt);
          inDataBody = false;
          bodyCollector = null;
          bodyScanner = null;
          await _finalizeDataBody(state, socket, body);
        }
        return;
      }

      // Command phase — byte-buffered (8BITMIME-safe).
      lineBuffer = lineBuffer.length === 0 ? chunk : Buffer.concat([lineBuffer, chunk]);
      if (safeBuffer.byteLengthOf(lineBuffer) > maxLineBytes * 4) {
        _writeReply(socket, REPLY_500_SYNTAX,
          "5.5.6 Line too long (>" + maxLineBytes + " bytes)");
        _closeConnection(socket);
        return;
      }
      var crlf;
      var crlfNeedle = Buffer.from("\r\n", "ascii");
      while ((crlf = lineBuffer.indexOf(crlfNeedle)) !== -1) {
        var line = lineBuffer.subarray(0, crlf).toString("utf8");
        lineBuffer = lineBuffer.subarray(crlf + 2);
        await _handleCommand(state, socket, line);
        if (inDataBody) return;
        if (connClosed) return;
      }
    }

    async function _handleCommand(state, socket, line) {
      // Per-line guard — refuse bare LF / NUL / C0 / DEL / oversize
      // BEFORE state-machine dispatch.
      try {
        guardSmtpCommand.validate(line, {
          profile:        profile,
          maxLineBytes:   maxLineBytes,
          allowSmtpUtf8:  allowSmtpUtf8,
        });
      } catch (err) {
        if (err.code === "guard-smtp-command/bare-lf" ||
            err.code === "guard-smtp-command/bare-cr" ||
            err.code === "guard-smtp-command/nul") {
          _emit("mail.server.mx.smtp_smuggling_detected",
            { connectionId: state.id, code: err.code, line: line.slice(0, 200) },                     // audit-log line truncation
            "denied");
        }
        _writeReply(socket, REPLY_500_SYNTAX, "5.5.2 Syntax error (" + (err.code || "bad-line") + ")");
        return;
      }

      var verb = line.split(/\s+/)[0].toUpperCase();
      switch (verb) {
        case "EHLO":
        case "HELO":
          await _handleEhlo(state, socket, line, verb);
          return;
        case "STARTTLS":
          _handleStartTls(state, socket);
          return;
        case "MAIL":
          await _handleMailFrom(state, socket, line);
          return;
        case "RCPT":
          await _handleRcptTo(state, socket, line);
          return;
        case "DATA":
          _handleData(state, socket);
          return;
        case "NOOP":
          _writeReply(socket, REPLY_250_OK, "2.0.0 OK");
          return;
        case "RSET":
          _resetTransaction(state);
          _writeReply(socket, REPLY_250_OK, "2.0.0 Reset");
          return;
        case "QUIT":
          _writeReply(socket, REPLY_221_BYE, "2.0.0 Bye");
          _closeConnection(socket);
          return;
        case "VRFY":
        case "EXPN":
          // Refuse VRFY/EXPN per modern best practice (information
          // disclosure of internal aliases / valid recipients).
          _writeReply(socket, REPLY_502_NOT_IMPLEMENTED, "5.5.1 Command not implemented");
          return;
        default:
          _writeReply(socket, REPLY_500_SYNTAX, "5.5.2 Unknown command");
      }
    }

    // ---- EHLO / HELO ------------------------------------------------------
    async function _handleEhlo(state, socket, line, verb) {
      var helo = line.slice(verb.length).trim();
      if (!helo) {
        _writeReply(socket, REPLY_501_BAD_ARGS, "5.5.4 " + verb + " requires a domain argument");
        return;
      }
      // Domain hardening for HELO/EHLO greeting (RFC 5321 §4.1.1.1).
      // Skip when the greeting is an address literal (`[1.2.3.4]` /
      // `[IPv6:...]`) — those are RFC-5321-legitimate non-domain
      // forms; the bracket syntax is already constrained by
      // b.guardSmtpCommand. Bare-IP-as-domain (no brackets) IS
      // refused — that's the CVE-2021-22931 class guardDomain catches.
      if (helo[0] !== "[" && guardDomainProfile) {
        var heloVerdict = _validateDomainHardened(helo, "helo");
        if (!heloVerdict.ok) {
          _writeReply(socket, REPLY_501_BAD_ARGS,
            "5.5.4 " + verb + " domain refused (" +
            (heloVerdict.issues && heloVerdict.issues[0] && heloVerdict.issues[0].kind) + ")");
          return;
        }
      }
      // Operator HELO-identity gate (b.mail.helo) — FCrDNS / HELO-shape /
      // self-name spoofing checks. Composed when the operator wires
      // `opts.helo`; skipped silently otherwise (no synthesized verdict).
      // Hard-reject actions (reject-shape / match-self-refused /
      // literal-mismatch) refuse the connection; "accept" and the
      // advisory "soft-*" actions pass (the soft verdict rides the event).
      if (opts.helo && typeof opts.helo.evaluate === "function") {
        var heloGate = await opts.helo.evaluate(
          { claimedName: helo, ip: state.remoteAddress, tls: state.tls }, {});
        state.heloVerdict = heloGate && heloGate.action;
        if (heloGate && heloGate.action && heloGate.action !== "accept" &&
            heloGate.action.indexOf("soft") !== 0) {
          _emit("mail.server.mx.helo_gate_refused",
            { connectionId: state.id, helo: helo, action: heloGate.action }, "denied");
          _writeReply(socket, REPLY_550_MAILBOX_UNAVAIL,
            "5.7.1 " + verb + " identity refused (" + heloGate.action + ")");
          return;
        }
      }
      state.helo  = helo;
      state.stage = "ehlo";
      // Multi-line 250 capabilities advertisement per RFC 5321 §4.1.1.1.
      if (verb === "EHLO") {
        // EHLO capabilities advertised:
        //   - PIPELINING per RFC 2920
        //   - SIZE n per RFC 1870 §3 (with the per-server byte cap)
        //   - 8BITMIME per RFC 6152 (obsoletes RFC 1652)
        //   - STARTTLS per RFC 3207 §2 (only advertised pre-TLS)
        //   - ENHANCEDSTATUSCODES per RFC 2034 (RFC 3463 code shape)
        var caps = ["PIPELINING", "SIZE " + maxMessageBytes, "8BITMIME"];
        if (!state.tls) caps.push("STARTTLS");
        caps.push("ENHANCEDSTATUSCODES");
        var lines = [greeting + " greets " + helo];
        for (var i = 0; i < caps.length; i += 1) lines.push(caps[i]);
        _writeMultiline(socket, REPLY_250_OK, lines);
      } else {
        _writeReply(socket, REPLY_250_OK, greeting + " greets " + helo);
      }
      _emit("mail.server.mx.helo",
        { connectionId: state.id, verb: verb, helo: helo, tls: state.tls,
          heloVerdict: state.heloVerdict || null });
    }

    // ---- STARTTLS ---------------------------------------------------------
    function _handleStartTls(state, socket) {
      if (state.tls) {
        _writeReply(socket, REPLY_503_BAD_SEQUENCE, "5.5.1 TLS already active");
        return;
      }
      _writeReply(socket, REPLY_220_READY, "2.0.0 Ready to start TLS");
      // CVE-2021-38371 (Exim) / CVE-2021-33515 (Dovecot) STARTTLS-
      // injection defense: clear the pre-handshake command buffer +
      // body collector AND strip the plain-socket "data" listener
      // before wrapping in TLSSocket so bytes the peer pipelined
      // (RFC 2920) pre-handshake cannot reach the post-TLS state
      // machine. Listener-removal + idle-timeout re-arm live in the
      // shared upgradeSocket helper (b.mail.server.tls.upgradeSocket).
      lineBuffer    = Buffer.alloc(0);
      bodyCollector = null;
      bodyScanner   = null;
      inDataBody    = false;
      mailServerTls.upgradeSocket({
        plainSocket:   socket,
        secureContext: opts.tlsContext,
        idleTimeoutMs: idleTimeoutMs,
        onSecure: function (_tlsSocket) {
          state.tls   = true;
          // After the handshake, the state machine restarts at EHLO
          // (per RFC 3207 §4.2 — client MUST re-issue EHLO).
          state.stage = "ehlo";
          state.helo  = null;
        },
        onData: function (tlsSocket, chunk) {
          // Route the upgraded socket through the SAME serialized pump as
          // the plaintext path — post-STARTTLS is where the gates run in
          // the default strict/balanced profiles, so it MUST be serialized
          // and its async rejections MUST hit the 421 path.
          _feedChunk(tlsSocket, chunk);
        },
        onError: function (err) {
          _emit("mail.server.mx.tls_handshake_failed",
            { connectionId: state.id, code: (err && err.code) || "unknown",
              message: err && err.message }, "failure");
          _closeConnection(socket);
        },
        onTimeout: function (tlsSocket) {
          _writeReply(tlsSocket, REPLY_421_SERVICE_NOT_AVAIL, "4.4.2 Idle timeout");
          _closeConnection(tlsSocket);
        },
      });
    }

    // ---- MAIL FROM --------------------------------------------------------
    async function _handleMailFrom(state, socket, line) {
      if (!state.tls && _requiresStartTls()) {
        _writeReply(socket, REPLY_530_AUTH_REQUIRED, "5.7.0 Must issue a STARTTLS command first");
        return;
      }
      if (state.stage !== "ehlo" && state.stage !== "mail") {
        _writeReply(socket, REPLY_503_BAD_SEQUENCE, "5.5.1 EHLO/HELO first");
        return;
      }
      var match = line.match(RE_MAIL_FROM);
      if (!match) {
        _writeReply(socket, REPLY_501_BAD_ARGS,
          "5.5.4 Syntax: MAIL FROM:<address> [SIZE=n]");
        return;
      }
      var mailFrom = match[1].toLowerCase();
      // Domain hardening on MAIL FROM domain. Skip address-literal
      // and empty-reverse-path forms (RFC 5321 §4.5.5 — bounce return
      // path `<>` is legitimate and has no domain).
      var __mfAtIdx = mailFrom.lastIndexOf("@");
      var mailFromDomain = __mfAtIdx === -1 ? "" : mailFrom.slice(__mfAtIdx + 1);
      if (mailFromDomain && mailFromDomain[0] !== "[" && guardDomainProfile) {
        var mfVerdict = _validateDomainHardened(mailFromDomain, "mail_from");
        if (!mfVerdict.ok) {
          _writeReply(socket, REPLY_501_BAD_ARGS,
            "5.5.4 MAIL FROM domain refused (" +
            (mfVerdict.issues && mfVerdict.issues[0] && mfVerdict.issues[0].kind) + ")");
          return;
        }
      }
      var paramStr = match[2] || "";
      var sizeMatch = paramStr.match(RE_SIZE);
      var declaredSize = null;
      if (sizeMatch) {
        declaredSize = parseInt(sizeMatch[1], 10);
        if (declaredSize > maxMessageBytes) {
          _writeReply(socket, REPLY_552_SIZE_EXCEEDED,
            "5.3.4 Message size exceeds fixed maximum (" + maxMessageBytes + " bytes)");
          return;
        }
      }
      state.mailFrom    = mailFrom;
      state.declaredSize = declaredSize;
      state.stage       = "rcpt";
      state.rcpts       = [];
      _emit("mail.server.mx.mail_from",
        { connectionId: state.id, mailFrom: mailFrom });
      _writeReply(socket, REPLY_250_OK, "2.1.0 Sender OK");
    }

    // ---- RCPT TO ----------------------------------------------------------
    async function _handleRcptTo(state, socket, line) {
      if (state.stage !== "rcpt") {
        _writeReply(socket, REPLY_503_BAD_SEQUENCE, "5.5.1 MAIL FROM first");
        return;
      }
      if (state.rcpts.length >= maxRcptsPerMsg) {
        _writeReply(socket, REPLY_452_INSUFFICIENT_STG,
          "4.5.3 Too many recipients (limit " + maxRcptsPerMsg + ")");
        return;
      }
      // RFC 5321 §3.5 — RCPT-TO 550 vs 250 surfaces a mailbox-existence
      // oracle. Once the per-IP recipient-failure cap is reached, the
      // listener returns 421 + closes so the IP backs off; without this
      // a scanner can RCPT-TO-flood the listener to enumerate every
      // valid local recipient at the bare cost of an SMTP greeting.
      var rcptAdmit = rateLimit.checkRcptAdmit(state.remoteAddress);
      if (!rcptAdmit.ok) {
        _emit("mail.server.mx.rcpt_rate_limit_refused",
          { connectionId: state.id, remoteAddress: state.remoteAddress,
            reason: rcptAdmit.reason }, "denied");
        _writeReply(socket, REPLY_421_SERVICE_NOT_AVAIL,
          "4.7.0 Too many RCPT failures from your IP");
        _closeConnection(socket);
        return;
      }
      var match = line.match(RE_RCPT_TO);
      if (!match) {
        rateLimit.noteRcptFailure(state.remoteAddress);
        _writeReply(socket, REPLY_501_BAD_ARGS, "5.5.4 Syntax: RCPT TO:<address>");
        return;
      }
      var rcpt = match[1].toLowerCase();
      // Domain hardening on RCPT TO domain — skip the address-literal
      // form per RFC 5321 §4.1.3 (bracket syntax already constrained
      // by b.guardSmtpCommand). Refuses IDN homograph + special-use
      // domains + bare-IP-as-domain on the un-bracketed form.
      var _atIdx = rcpt.lastIndexOf("@");
      var rcptDomain = _atIdx === -1 ? "" : rcpt.slice(_atIdx + 1);
      if (rcptDomain && rcptDomain[0] !== "[" && guardDomainProfile) {
        var rcptVerdict = _validateDomainHardened(rcptDomain, "rcpt_to");
        if (!rcptVerdict.ok) {
          rateLimit.noteRcptFailure(state.remoteAddress);
          _trackRefusedRcpt(state, rcpt, "domain-refused");
          _writeReply(socket, REPLY_501_BAD_ARGS,
            "5.5.4 RCPT TO domain refused (" +
            (rcptVerdict.issues && rcptVerdict.issues[0] && rcptVerdict.issues[0].kind) + ")");
          return;
        }
      }
      // Local-domain check — refuse non-local recipients unless the
      // operator explicitly allowed relay for this scope.
      //
      // Run UNCONDITIONALLY. This used to sit inside `if (localDomains.length
      // > 0)`, so a server hosting no domains ran no check at all and accepted
      // every recipient. An empty hosted set now refuses everything naturally,
      // which is what an empty allowlist has to mean; `relayAllowedFor` is
      // still the way to permit a scope deliberately.
      if (_resolveLocalDomains().indexOf(rcptDomain) === -1 &&
          !_isRelayAllowed(state.remoteAddress, rcpt)) {
        rateLimit.noteRcptFailure(state.remoteAddress);
        _trackRefusedRcpt(state, rcpt, "relay-denied");
        _emit("mail.server.mx.relay_refused",
          { connectionId: state.id, mailFrom: state.mailFrom, rcptTo: rcpt,
            remoteAddress: state.remoteAddress }, "denied");
        _writeReply(socket, REPLY_550_MAILBOX_UNAVAIL, "5.7.1 Relaying denied");
        return;
      }
      // RBL gate (b.mail.rbl) — DNS blocklist check on the connecting
      // IP. The verdict is per-connection, so it's evaluated once and
      // cached on state; a listed IP refuses with 554. Skipped silently
      // when opts.rbl isn't wired.
      if (opts.rbl && typeof opts.rbl.query === "function") {
        if (state.rblVerdict === undefined) {
          state.rblVerdict = await opts.rbl.query(state.remoteAddress);
        }
        if (state.rblVerdict && Array.isArray(state.rblVerdict.listed) &&
            state.rblVerdict.listed.length > 0) {
          _trackRefusedRcpt(state, rcpt, "rbl-listed");
          _emit("mail.server.mx.rbl_refused",
            { connectionId: state.id, remoteAddress: state.remoteAddress,
              zones: state.rblVerdict.listed.map(function (l) { return l.zone; }) }, "denied");
          _writeReply(socket, REPLY_554_TRANSACTION_FAILED,
            "5.7.1 Connecting IP is on a DNS blocklist");
          return;
        }
      }
      // Greylist gate (b.mail.greylist) — defer first sight of an
      // (ip, mailFrom, rcpt) tuple with a 450 tempfail; legitimate
      // senders retry and pass. "defer" → 450; "accept" → continue.
      // Skipped silently when opts.greylist isn't wired.
      var greyVerdict = null;
      if (opts.greylist && typeof opts.greylist.check === "function") {
        greyVerdict = await opts.greylist.check(
          { ip: state.remoteAddress, mailFrom: state.mailFrom || "", rcptTo: rcpt });
        if (greyVerdict && greyVerdict.action === "defer") {
          _emit("mail.server.mx.greylist_deferred",
            { connectionId: state.id, remoteAddress: state.remoteAddress,
              mailFrom: state.mailFrom, rcptTo: rcpt,
              reason: greyVerdict.reason }, "denied");
          _writeReply(socket, REPLY_450_MAILBOX_BUSY,
            "4.7.1 Greylisted — please retry shortly");
          return;
        }
      }
      // Operator-supplied recipient policy — the only place a listener can
      // answer "no such mailbox" the way RFC 5321 §3.3 asks. Without it, a
      // local domain accepted every local part and the application first met
      // the recipient at agent.handoff, after 354 and after the whole message:
      // from there the choices were 250 (tell the peer it arrived, then owe a
      // DSN) or 451 (tell a peer holding a permanent condition to retry
      // forever). Neither is a refusal. Same shape as the submission
      // listener's hook: `{ ok: true }` accepts, `{ ok: false, reason }`
      // refuses. Unwired, every syntactically valid recipient on a local
      // domain is accepted, exactly as before.
      if (typeof opts.recipientPolicy === "function") {
        var rcptVerdictPolicy;
        try {
          rcptVerdictPolicy = await opts.recipientPolicy({
            mailFrom:      state.mailFrom,
            rcptTo:        rcpt,
            connectionId:  state.id,
            remoteAddress: state.remoteAddress,
            tls:           state.tls,
            heloName:      state.heloName || null,
          });
        } catch (policyErr) {
          // The operator's directory being unreachable is not a verdict about
          // this mailbox. A 550 here would permanently reject mail for a
          // legitimate recipient because a lookup failed, so it defers.
          _emit("mail.server.mx.recipient_policy_threw",
            { connectionId: state.id, rcptTo: rcpt,
              error: (policyErr && policyErr.message) || String(policyErr) }, "failure");
          _writeReply(socket, REPLY_451_LOCAL_ERROR,
            "4.7.1 Recipient policy temporarily unavailable");
          return;
        }
        if (!rcptVerdictPolicy || rcptVerdictPolicy.ok !== true) {
          // The 250-vs-550 difference is a mailbox-existence oracle, so a
          // policy refusal charges the same per-IP recipient-failure budget
          // the relay refusal does. Without that, wiring this hook would hand
          // a scanner a free enumeration channel the listener did not have.
          rateLimit.noteRcptFailure(state.remoteAddress);
          _trackRefusedRcpt(state, rcpt, "recipient-policy");
          _emit("mail.server.mx.recipient_refused",
            { connectionId: state.id, mailFrom: state.mailFrom, rcptTo: rcpt,
              reason: (rcptVerdictPolicy && rcptVerdictPolicy.reason) || "policy-refused",
              remoteAddress: state.remoteAddress }, "denied");
          // The reason goes onto a line-oriented reply, and a directory wrapper
          // routinely quotes the address it looked up — which the peer chose.
          // A CR or LF in it would end the 550 early and let the remainder be
          // read as a second, forged reply. The refusal still happens; only the
          // prose falls back.
          _writeReply(socket, REPLY_550_MAILBOX_UNAVAIL,
            "5.1.1 " + mailServerNet.replyTextOrFallback(
              rcptVerdictPolicy && rcptVerdictPolicy.reason, "Mailbox unavailable"));
          return;
        }
      }
      state.rcpts.push(rcpt);
      _emit("mail.server.mx.rcpt_to",
        { connectionId: state.id, rcptTo: rcpt, rcptCount: state.rcpts.length,
          rblListed: !!(state.rblVerdict && Array.isArray(state.rblVerdict.listed) &&
            state.rblVerdict.listed.length > 0),
          greylist: greyVerdict ? greyVerdict.action : null });
      _writeReply(socket, REPLY_250_OK, "2.1.5 Recipient OK");
    }

    // ---- DATA -------------------------------------------------------------
    function _handleData(state, socket) {
      if (state.stage !== "rcpt" || state.rcpts.length === 0) {
        _writeReply(socket, REPLY_503_BAD_SEQUENCE, "5.5.1 No valid recipients");
        return;
      }
      _writeReply(socket, REPLY_354_START_INPUT,
        "End data with <CR><LF>.<CR><LF>");
      state.stage    = "data-body";
      inDataBody     = true;
      bodyCollector  = safeBuffer.boundedChunkCollector({
        maxBytes:    maxMessageBytes,
        errorClass:  MailServerMxError,
        sizeCode:    "mail-server-mx/body-too-large",
        sizeMessage: "DATA body exceeded maxMessageBytes (" + maxMessageBytes + ")",
      });
      bodyScanner    = safeSmtp.createBodyScanner();
      bodyRateWindow.start(time.monotonicMs(), wireBytes);
    }

    async function _finalizeDataBody(state, socket, body) {
      // body is the raw bytes BEFORE dot-stuffing reversal. RFC 5321
      // §4.5.2 — a single leading "." is doubled on the wire; undo.
      var dedotted = safeSmtp.dotUnstuff(body);
      // RFC 1870 §6.3 — reconcile MAIL FROM SIZE= against the actual
      // DATA byte count. The pre-DATA reservation at MAIL FROM time
      // (above) is advisory; the sender's declared size is a HINT,
      // not a guarantee. If the actual unstuffed body exceeds the
      // declared SIZE= (with a small slack to absorb header lines the
      // sender didn't count), refuse with 552 — defends against
      // senders that probe maxMessageBytes by understating SIZE.
      if (typeof state.declaredSize === "number" && isFinite(state.declaredSize)) {
        if (dedotted.length > state.declaredSize) {
          _emit("mail.server.mx.size_overrun", {
            connectionId: state.id,
            mailFrom:     state.mailFrom,
            declaredSize: state.declaredSize,
            actualSize:   dedotted.length,
          }, "denied");
          _writeReply(socket, REPLY_552_SIZE_EXCEEDED,
            "5.3.4 Message exceeds declared SIZE=" + state.declaredSize +
            " bytes (got " + dedotted.length + "; RFC 1870 §6.3)");
          _resetTransaction(state);
          return;
        }
      }
      // DATA-phase message authentication (opts.guardEnvelope) — SPF /
      // DKIM / DMARC through b.mail.inbound.verify, refusing before the
      // agent handoff so a policy-failing message never reaches storage.
      var inboundAuth = null;
      if (envelopeGate) {
        var inboundVerdict = null;
        // Resolve the authserv-id ONCE for this message and use that value for
        // both the header written and the forged headers stripped.
        //
        // It can now come from a hosted-domain callback, so two reads either
        // side of an await can disagree — and these two reads are exactly the
        // pair that must not. The strip removes sender-attached
        // Authentication-Results claiming this receiver's identity (RFC 8601
        // §5) before the computed one is prepended. Strip under the old id and
        // write under the new one, and a forged header claiming the id the
        // trusted verdict was written under survives next to it, which is the
        // shadowing this defense exists to prevent.
        var messageAuthservId = envelopeGate.authservId;
        try {
          // Wall-clock ceiling around the whole pipeline — a message
          // stuffed with signatures pointing at slow resolvers must
          // not pin the connection slot. Timeout surfaces as
          // SafeAsyncError(async/timeout) into the catch below.
          inboundVerdict = await safeAsync.withTimeout(
            mailAuth().inbound.verify({
              ip:            state.remoteAddress,
              helo:          state.helo || undefined,
              mailFrom:      state.mailFrom || undefined,
              message:       dedotted,
              dnsLookup:     envelopeGate.dnsLookup,
              maxSignatures: envelopeGate.maxSignatures,
              clockSkewMs:   envelopeGate.clockSkewMs,
              minRsaBits:    envelopeGate.minRsaBits,
              authservId:    messageAuthservId || undefined,
            }),
            envelopeGate.timeoutMs,
            { name: "mail.server.mx.guardEnvelope" });
        } catch (err) {
          // Pipeline infrastructure failure or wall-clock timeout (not
          // an authentication verdict). Same disposition as a DNS
          // temperror: defer so the sender retries, or accept
          // unauthenticated when the operator chose availability via
          // onTemperror.
          _emit("mail.server.mx.envelope_error", {
            connectionId: state.id,
            mailFrom:     state.mailFrom,
            error:        (err && err.message) || String(err),
          }, "failure");
          if (envelopeGate.mode === "enforce" && envelopeGate.onTemperror === "defer") {
            _writeReply(socket, REPLY_451_LOCAL_ERROR,
              "4.7.0 Message authentication could not be completed; try again later");
            _resetTransaction(state);
            return;
          }
        }
        if (inboundVerdict) {
          var envAction = _envelopeActionFor(inboundVerdict, envelopeGate);
          var dkimSummary = inboundVerdict.dkim.some(function (d) { return d.result === "pass"; })
            ? "pass"
            : (inboundVerdict.dkim[0] ? inboundVerdict.dkim[0].result : "none");
          _emit("mail.server.mx.envelope_verdict", {
            connectionId: state.id,
            mailFrom:     state.mailFrom,
            fromDomain:   inboundVerdict.from.domain,
            spf:          inboundVerdict.spf.result,
            dkim:         dkimSummary,
            dmarc:        inboundVerdict.dmarc.result,
            arc:          inboundVerdict.arc && inboundVerdict.arc.chainStatus,
            // The status alone cannot tell an operator reading the audit
            // whether a chain failed because a seal was bad or because a
            // resolver was down — the two want opposite responses.
            arcReason:    inboundVerdict.arc && inboundVerdict.arc.reason,
            arcTransient: !!(inboundVerdict.arc && inboundVerdict.arc.transient),
            action:       envAction,
            mode:         envelopeGate.mode,
          }, (envAction === "reject" || envAction === "defer") ? "denied" : "success");
          if (envelopeGate.mode === "enforce" && envAction === "reject") {
            // RFC 7372 §3.2 — 5.7.26 ("multiple authentication checks
            // failed") for a DMARC evaluation that failed; the
            // multi-From / unparsable-author permerror shape is a
            // message-acceptability refusal and keeps the generic
            // 5.7.1.
            var enhanced = inboundVerdict.dmarc.result === "fail" ? "5.7.26" : "5.7.1";
            _writeReply(socket, REPLY_550_MAILBOX_UNAVAIL,
              enhanced + " Message refused by sender authentication policy (DMARC " +
              inboundVerdict.dmarc.result + "; SPF " + inboundVerdict.spf.result +
              ", DKIM " + dkimSummary + ")");
            _resetTransaction(state);
            return;
          }
          if (envelopeGate.mode === "enforce" && envAction === "defer") {
            _writeReply(socket, REPLY_451_LOCAL_ERROR,
              "4.7.0 Sender authentication temporarily unavailable (DNS); try again later");
            _resetTransaction(state);
            return;
          }
          // Accept / quarantine / monitor mode: the verdict rides to
          // the agent handoff as `auth`, and the receiver's RFC 8601
          // Authentication-Results header is prepended so downstream
          // consumers (spam-foldering quarantined mail included) act
          // on authenticated results instead of re-verifying.
          if (inboundVerdict.authResults) {
            // RFC 8601 §5 — strip any sender-attached A-R header
            // claiming this receiver's authserv-id before prepending
            // the computed one (forged-verdict shadowing defense).
            dedotted = _stripForgedAuthResults(dedotted, messageAuthservId);
            dedotted = Buffer.concat([
              Buffer.from(inboundVerdict.authResults + "\r\n", "utf8"),
              dedotted,
            ]);
          }
          inboundAuth = {
            spf:        inboundVerdict.spf,
            dkim:       inboundVerdict.dkim,
            dmarc:      inboundVerdict.dmarc,
            // The ARC chain sits beside the other three because it was
            // computed with them. It used to reach the delivered message as an
            // `arc=` token and the audit event as a status, and stop there —
            // so a consumer wanting to act on it re-parsed a header the
            // pipeline had just written. The header is also lossier than the
            // verdict: RFC 8601 has one `arc=fail` token, while the verdict
            // separates a chain that is structurally incomplete from one whose
            // seal did not verify, and only the second says anything about the
            // sender.
            arc:        inboundVerdict.arc,
            from:       inboundVerdict.from,
            action:     envAction,
            mode:       envelopeGate.mode,
            quarantine: envAction === "quarantine",
          };
        }
      }
      // operator-supplied agent handoff — when wired, persist via
      // agent + write the 250 reply. When not wired, accept-and-drop
      // (audit-only mode useful for staging deployments).
      var refusedSnapshot = Array.isArray(state.refusedRcpts) ? state.refusedRcpts.slice() : [];
      if (opts.agent && typeof opts.agent.handoff === "function") {
        opts.agent.handoff({
          mailFrom: state.mailFrom,
          rcpts:    state.rcpts.slice(),
          body:     dedotted,
          remote:   { address: state.remoteAddress, port: state.remotePort },
          tls:      state.tls,
          helo:     state.helo,
          auth:     inboundAuth,
          connectionId: state.id,
        }).then(function (ack) {
          _emit("mail.server.mx.delivered",
            { connectionId: state.id, messageId: ack && ack.messageId,
              sizeBytes: dedotted.length, refusedRcpts: refusedSnapshot });
          _writeReply(socket, REPLY_250_OK,
            "2.6.0 Message accepted" + (ack && ack.messageId ? " <" + ack.messageId + ">" : ""));
          _resetTransaction(state);
        }).catch(function (err) {
          var refusal = mailServerNet.agentRefusalReply(err, "Local delivery error");
          _emit("mail.server.mx.data_refused",
            { connectionId: state.id, reason: "agent-handoff-failed",
              smtpCode: refusal.code,
              error: (err && err.message) || String(err) }, "failure");
          _writeReply(socket, refusal.code, refusal.text);
          _resetTransaction(state);
        });
        return;
      }
      _emit("mail.server.mx.data_accepted",
        { connectionId: state.id, mailFrom: state.mailFrom, rcptCount: state.rcpts.length,
          sizeBytes: dedotted.length, refusedRcpts: refusedSnapshot });
      _writeReply(socket, REPLY_250_OK, "2.6.0 Message queued (audit-only)");
      _resetTransaction(state);
    }

    function _resetTransaction(state) {
      state.mailFrom     = null;
      state.declaredSize = null;
      state.rcpts        = [];
      state.refusedRcpts = [];
      state.stage        = "ehlo";
      state.messageBytes = 0;
    }

    // Track up to MAX_REFUSED_RCPTS_PER_TXN refused recipients so the
    // `data_accepted` / `delivered` audit can surface the bounded list
    // for observability. Bounded to keep the audit metadata size
    // predictable; the per-IP recipient-failure rate-limit elsewhere
    // bounds long-run scanner damage.
    var MAX_REFUSED_RCPTS_PER_TXN = 32;                                                                   // bounded audit-metadata list cap
    function _trackRefusedRcpt(state, rcpt, reason) {
      if (!Array.isArray(state.refusedRcpts)) state.refusedRcpts = [];
      if (state.refusedRcpts.length >= MAX_REFUSED_RCPTS_PER_TXN) return;
      state.refusedRcpts.push({ rcptTo: rcpt, reason: reason });
    }

    function _requiresStartTls() {
      // Strict / balanced require STARTTLS before MAIL FROM.
      // Permissive accepts plaintext — operator-acknowledged downgrade
      // for legacy infrastructure.
      return profile === "strict" || profile === "balanced";
    }

    function _isRelayAllowed(remoteAddress, _rcptTo) {
      // Relay is admitted ONLY when the connecting peer's source address
      // falls inside one of the operator's allowlisted CIDR ranges — the
      // same range arithmetic (b.ssrfGuard.cidrContains) the HTTP
      // b.middleware.networkAllowlist fence uses. Every entry's `cidr` was
      // shape-validated at create() time; a peer outside every range (or a
      // non-string / empty peer address) is refused, so a misconfigured
      // relayAllowedFor fails closed instead of turning the listener into an
      // open relay. `scope` is an operator-facing annotation on the entry;
      // the network boundary is the authorization control.
      if (relayAllowedFor.length === 0) return false;
      if (typeof remoteAddress !== "string" || remoteAddress.length === 0) return false;
      // Node reports an IPv4 client as an IPv4-mapped IPv6 address
      // (::ffff:a.b.c.d) when the listener binds the IPv6 wildcard `::` (the
      // common dual-stack deployment). cidrContains refuses a mixed-family
      // compare, so a documented IPv4 relay CIDR (10.0.0.0/8) would deny every
      // intended IPv4 client on that listener. Fold the mapped form to its
      // IPv4 dotted address (ssrfGuard.canonicalizeHost, which folds only the
      // ::ffff:0:0/96 block) and match EITHER the peer as reported OR the
      // folded form — so an IPv4 CIDR matches a mapped peer and an IPv6 CIDR
      // still matches a genuine IPv6 peer.
      var canonPeer;
      try { canonPeer = ssrfGuard.canonicalizeHost(remoteAddress); }
      catch (_e) { canonPeer = remoteAddress; }
      for (var i = 0; i < relayAllowedFor.length; i += 1) {
        var entry = relayAllowedFor[i];
        if (!entry || typeof entry !== "object") continue;
        if (ssrfGuard.cidrContains(entry.cidr, remoteAddress)) return true;
        if (canonPeer !== remoteAddress && ssrfGuard.cidrContains(entry.cidr, canonPeer)) return true;
      }
      return false;
    }
  }

  // ---- Lifecycle ----------------------------------------------------------
  // Port 0 (ephemeral, test mode) must NOT fall back to 25 — the `|| 25`
  // short-circuit was a footgun on the test path; createTcpListener honors an
  // explicit 0 (only an OMITTED port falls back to the default).
  var _tcpListener = mailServerNet.createTcpListener(net, {
    defaultPort:      25,                                                                             // SMTP MX port (IANA)
    maxConnections:   opts.maxConnections,
    handleConnection: _handleConnection,
    errorFactory:     function (code, message) { return new MailServerMxError("mail-server-mx/" + code, message); },
    emit:             _emit,
    listeningEvent:   "mail.server.mx.listening",
  });

  async function close(closeOpts) {
    closeOpts = closeOpts || {};
    if (!_tcpListener.isListening()) return;
    var timeoutMs = closeOpts.timeoutMs || C.TIME.seconds(30);
    _tcpListener.markClosed();
    _tcpListener.getServer().close();
    connections.forEach(function (sock) {
      try { _writeReply(sock, REPLY_421_SERVICE_NOT_AVAIL, "4.3.0 Server shutting down"); }
      catch (_e) { /* socket already gone */ }
    });
    var deadline = Date.now() + timeoutMs;
    while (connections.size > 0 && Date.now() < deadline) {
      await safeAsync.sleep(100);
    }
    connections.forEach(function (sock) {
      try { sock.destroy(); } catch (_e) { /* best-effort */ }
    });
    connections.clear();
    _emit("mail.server.mx.closed", {});
  }

  function connectionCount() { return connections.size; }

  return {
    listen:           _tcpListener.listen,
    close:            close,
    connectionCount:  connectionCount,
    _portForTest:     function () { var s = _tcpListener.getServer(); return s ? s.address().port : null; },
  };
}

// ---- Wire-protocol helpers --------------------------------------------------

// Write back-pressure observability — when `socket.write()` returns
// false the kernel send-buffer is full and the server is dropping
// behind the network. Listeners attach a `_bpEmit` function to the
// socket; we invoke it once per socket-lifetime on the first
// backpressure event so the audit log surfaces stalled connections
// without flooding on every reply.
function _observeBackpressure(socket, ok) {
  if (ok) return;
  if (typeof socket._bpEmit !== "function") return;
  if (socket._bpEmitted) return;
  socket._bpEmitted = true;
  try { socket._bpEmit(socket); } catch (_e) { /* drop-silent */ }
}

function _writeReply(socket, code, text) {
  // Single-line reply per RFC 5321 §4.2 — code SP text CRLF.
  try {
    var ok = socket.write(code + " " + text + "\r\n");
    _observeBackpressure(socket, ok);
  } catch (_e) { /* socket already closed */ }
}

function _writeMultiline(socket, code, lines) {
  // Multi-line reply per RFC 5321 §4.2 — code "-" text CRLF for
  // continuation, code SP text CRLF for the final line.
  for (var i = 0; i < lines.length; i += 1) {
    var sep = i === lines.length - 1 ? " " : "-";
    try {
      var ok = socket.write(code + sep + lines[i] + "\r\n");
      _observeBackpressure(socket, ok);
    } catch (_e) { /* socket already closed */ }
  }
}

function _closeConnection(socket) {
  try { socket.end(); } catch (_e) { /* best-effort */ }
  try { socket.destroy(); } catch (_e) { /* best-effort */ }
}

module.exports = {
  create:            create,
  MailServerMxError: MailServerMxError,
};
