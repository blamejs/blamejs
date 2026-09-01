// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     b.mail.server.imap
 * @nav        Mail
 * @title      Mail IMAP Server
 * @order      546
 *
 * @intro
 *   IMAP4rev2 mailbox-access listener (RFC 9051; obsoletes RFC 3501).
 *   Modern MUAs (Thunderbird, Apple Mail, mutt, K-9, FairEmail,
 *   etc.) connect here to read + manage messages without operators
 *   running dovecot / cyrus alongside. Composes the framework's
 *   existing substrates:
 *
 *     - `b.guardImapCommand` for wire-protocol shape + smuggling
 *       defense (literal-injection, bare-CR/LF refusal, per-verb
 *       shape, RFC 9051 §2.2.2 literal framing)
 *     - `b.mail.server.rateLimit` for per-IP DoS defense (concurrent
 *       + rate + AUTH-failure budget + slow-loris)
 *     - `b.mailStore` (operator-supplied backend) for the actual
 *       mail storage + UIDVALIDITY + modseq tracking
 *     - operator-supplied authenticator for SASL credential verify
 *     - `b.mail.server.tls` recommended for cert + key loading +
 *       rotation
 *
 *   ## State machine (RFC 9051 §3)
 *
 *   ```
 *   NOT-AUTHENTICATED → [STARTTLS → NOT-AUTH-TLS] → AUTH/LOGIN →
 *   AUTHENTICATED ↔ SELECTED → LOGOUT
 *                                ↑ EXAMINE  ↓ CLOSE / UNSELECT
 *   ```
 *
 *   Commands gated by state:
 *
 *     - NOT-AUTHENTICATED: STARTTLS / AUTHENTICATE / LOGIN / NOOP /
 *       CAPABILITY / LOGOUT / ID
 *     - AUTHENTICATED: SELECT / EXAMINE / CREATE / DELETE / RENAME /
 *       SUBSCRIBE / UNSUBSCRIBE / LIST / STATUS / APPEND / NAMESPACE /
 *       IDLE / ENABLE / NOOP / CAPABILITY / LOGOUT / ID
 *     - SELECTED: CHECK / CLOSE / UNSELECT / EXPUNGE / SEARCH / FETCH /
 *       STORE / COPY / MOVE / UID … / IDLE / NOOP / CAPABILITY /
 *       LOGOUT + every AUTHENTICATED command
 *
 *   Tagged response model: every client command carries a tag
 *   (`A001 LOGIN …`); server replies with one or more untagged
 *   responses (`* …`) then `A001 OK …` / `A001 NO …` / `A001 BAD …`.
 *
 *   ## Wire-protocol defenses
 *
 *   - **STARTTLS stripping (CVE-2021-33515 Dovecot class)** —
 *     STARTTLS upgrade clears pre-handshake receive buffer; any
 *     pipelined command queued before TLS is refused with
 *     `BAD Pipelined post-STARTTLS not permitted`.
 *
 *   - **Literal-injection / command-continuation smuggling** —
 *     `{n}` literal continuation MUST come on a line of its own
 *     (per `b.guardImapCommand.detectLiteralSmuggling`); oversize
 *     literals refused (default 64 MiB); LITERAL+ (RFC 7888) non-
 *     synchronizing literals only honored post-AUTH.
 *
 *   - **Mailbox-name traversal** — mailbox path components
 *     validated through `_validateMailboxName`: refuses `..`, NUL,
 *     control chars, oversize. UTF-8 mailbox names (RFC 9051 §5.1)
 *     accepted; modified-UTF7 (RFC 3501 §5.1.3 legacy) refused unless
 *     `allowLegacyMUtf7: true`.
 *
 *   - **APPEND-flood** — per-tenant byte/sec cap surfaces via the
 *     `b.mail.server.rateLimit`'s `minBytesPerSecond` floor on the
 *     APPEND-literal-body phase (same shape the MX listener uses for
 *     DATA-body).
 *
 *   - **Resource exhaustion** — per-line cap (default 8 KiB sans
 *     literal payload), per-literal cap (64 MiB), per-connection idle
 *     cap (default 30 min when not in IDLE; IDLE itself capped at
 *     29 min per RFC 2177 §3 to force re-issue).
 *
 *   - **Connection-rate + AUTH-failure budget** — composes
 *     `b.mail.server.rateLimit`. Each AUTH failure increments the
 *     budget; trip the cap and new AUTH attempts get
 *     `* BAD Too many AUTH failures` + connection close.
 *
 *   ## Audit lifecycle
 *
 *   - `mail.server.imap.connect`      — IP, TLS state
 *   - `mail.server.imap.auth_attempt` — mechanism, actor-hash
 *   - `mail.server.imap.auth_success` — mechanism, tenantId, scopes
 *   - `mail.server.imap.auth_failed`  — mechanism, reason
 *   - `mail.server.imap.select`       — mailbox, modseq, exists count
 *   - `mail.server.imap.append`       — mailbox, size, flags
 *   - `mail.server.imap.fetch_bulk`   — sequence-set size, BODY parts
 *   - `mail.server.imap.expunge`      — count, modseq
 *   - `mail.server.imap.literal_overflow_refused` — attempt size, cap
 *   - `mail.server.imap.rate_limit_refused`        — IP, reason
 *   - `mail.server.imap.smtp_smuggling_detected`   — literal-injection
 *
 *   ## What v1 does NOT ship
 *
 *   - **SEARCH / COPY / MOVE** — operator-domain logic against the
 *     mailStore index, supplied through `opts.overrides`; until then
 *     the listener answers `NO <verb> not configured`. A handler
 *     supplied once serves BOTH the plain and the `UID` form: the UID
 *     verb dispatches back through the same registry entry and sets
 *     `parsed.useUid`, which the handler reads to answer in unique
 *     identifiers per RFC 9051 §6.4.9.
 *   - **UID EXPUNGE (RFC 4315)** — refused unless the operator
 *     supplies an EXPUNGE handler that reads the uid-set. The shipped
 *     EXPUNGE takes no set and expunges every message flagged
 *     `\Deleted`, so serving the UID form from it would delete
 *     messages the client did not name.
 *   - **NOTIFY (RFC 5465)**, **METADATA (RFC 5464)**, **CATENATE
 *     (RFC 4469)**, **URLAUTH (RFC 4467)**, **IMAPSIEVE (RFC 6785)**,
 *     **COMPRESS=DEFLATE (RFC 4978)** — opt-in / refused.
 *   - **CONDSTORE / QRESYNC (RFC 7162)** — modseq is exposed via
 *     STATUS but per-FETCH CHANGEDSINCE delta is operator-side
 *     follow-up.
 *
 * @card
 *   IMAP4rev2 mailbox-access listener (RFC 9051; obsoletes RFC 3501).
 *   State machine NOT-AUTH → STARTTLS → AUTH → SELECTED → LOGOUT.
 *   Composes b.guardImapCommand (wire-protocol gate), b.mail.server.
 *   rateLimit (DoS defense), operator-supplied mailStore + SASL
 *   authenticator. Default-on per-IP rate-limit + literal-injection
 *   refusal + mailbox-traversal refusal.
 */

var net  = require("node:net");
var safeBuffer = require("./safe-buffer");
var C = require("./constants");
var numericBounds = require("./numeric-bounds");
var validateOpts = require("./validate-opts");
var guardImapCommand = require("./guard-imap-command");
var mailServerRateLimit = require("./mail-server-rate-limit");
var mailServerRegistry = require("./mail-server-registry");
var mailServerTls = require("./mail-server-tls");
var mailServerNet = require("./mail-server-net");
// The body-rate window measures ELAPSED time, which is the one question the
// wall clock cannot answer: an operator correcting the host clock forward
// hands out a whole window's budget with no time passed, and correcting it
// backward produces a negative elapsed and postpones enforcement until the
// clock catches up. Both turn the slow-loris floor off at exactly the moment a
// host is being administered.
var time = require("./time");
var { defineClass } = require("./framework-error");

var auditEmit = require("./audit-emit");

var MailServerImapError = defineClass("MailServerImapError", { alwaysPermanent: true });

// One capability, as it may appear in the space-separated list — RFC 9051 §9's
// ATOM-CHAR, expressed the way the grammar does: printable ASCII minus the
// atom-specials, rather than a list of the punctuation that came to mind.
// Stated as an allowlist it would refuse valid extension tokens (`X-SEARCH/FOO`
// is an atom), and the point of checking at all is the exclusions: SP would
// make one value two capabilities, and CR or LF would make it a second server
// response.
//
//   atom-specials = "(" / ")" / "{" / SP / CTL / list-wildcards ("%" "*")
//                   / quoted-specials ('"' "\") / resp-specials ("]")
var IMAP_ATOM_PRINTABLE = /^[\x21-\x7e]+$/;                                                             // allow:raw-byte-literal — RFC 9051 §9 CHAR range
var IMAP_ATOM_SPECIAL   = /[()%*"\\\]{]/;

function _isCapabilityAtom(value) {
  return IMAP_ATOM_PRINTABLE.test(value) && !IMAP_ATOM_SPECIAL.test(value);
}

var DEFAULT_MAX_LINE_BYTES   = C.BYTES.kib(8);
// Lines' worth of pipelined commands a connection may hold while one runs.
var PIPELINE_LINE_ALLOWANCE  = 8;
var CRLF_BYTE_LEN            = 2;                                                                     // the terminator each buffered line carries
var DEFAULT_MAX_LITERAL      = C.BYTES.mib(64);
// The verbs that may open a literal before the session is authenticated. Two
// conditions, both required: available pre-auth per the state table at the top
// of this file, AND carrying an argument that can be sent as a literal.
//
// Both halves were got wrong in turn. Picking only the ones that obviously
// need a literal missed ID, whose RFC 2971 parameters are strings a client may
// legitimately send that way. Widening to the whole NOT-AUTHENTICATED set then
// admitted NOOP, CAPABILITY, LOGOUT and STARTTLS — which take no literal
// argument at all, so `NOOP {67108864}` opened a 64 MiB window for a peer that
// had proved nothing, reinstating the hole this gate exists to close. The
// state table answers which commands are AVAILABLE, not which can carry a
// literal, and only the intersection is safe.
var PRE_AUTH_LITERAL_VERBS = Object.freeze({
  AUTHENTICATE: true,   // SASL initial response (RFC 9051 §6.2.2)
  LOGIN:        true,   // password — the value a quoted string cannot always hold
  ID:           true,   // RFC 2971 parameter strings
});

// Added to the limiter's own window before the no-payload deadline fires, so
// the limiter is asked once it has enough elapsed time to answer rather than
// exactly on the boundary.
var LITERAL_DEADLINE_GRACE_MS = C.TIME.seconds(1);

var DEFAULT_IDLE_TIMEOUT_MS  = C.TIME.minutes(30);
var IDLE_BANDWIDTH_TIMEOUT_MS = C.TIME.minutes(29);  // RFC 2177 §3 — re-issue before 30
var DEFAULT_GREETING_VENDOR  = "blamejs IMAP4rev2";
var pkgVersion = require("../package.json").version;
var codepointClass = require("./codepoint-class");

// Error-message clamp bytes — protocol-string clamp, not a byte count.
// Centralized so the marker lives in one place
// and the per-call sites read cleanly.
var ERR_CLAMP = 200;                                                                                  // protocol-reply error-message clamp
var CRLF_BYTES = Buffer.from("\r\n", "latin1");                                                       // RFC 9051 §2.2 line terminator, as octets
var LINE_PREVIEW = 80;                                                                                // audit-line preview clamp

// RFC 9051 §6.3.12 + RFC 5322 §3.3 date-time parser for IMAP APPEND.
// Format: `DD-Mon-YYYY HH:MM:SS ±HHMM` where Mon is the 3-letter
// English month abbreviation (case-insensitive on parse, but the IMAP
// spec emits canonical mixed-case `Jan`/`Feb`/...). Returns the
// millisecond epoch, or null on any parse failure — the caller emits
// `BAD` rather than silently using `Date.now()`.
var IMAP_MONTHS = Object.freeze({
  jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5,                                                         // month-index table (0-5)
  jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11,                                                       // month-index table (6-11)
});
var IMAP_DT_RE = /^\s*(\d{1,2})-([A-Za-z]{3})-(\d{4})\s+(\d{2}):(\d{2}):(\d{2})\s+([+-])(\d{2})(\d{2})\s*$/;
function _parseImapDateTime(s) {
  if (typeof s !== "string") return null;
  var m = s.match(IMAP_DT_RE);                                                                            // allow:regex-no-length-cap — input bounded by IMAP literal cap
  if (!m) return null;
  var day = parseInt(m[1], 10);
  var month = IMAP_MONTHS[m[2].toLowerCase()];
  if (month === undefined) return null;
  var year = parseInt(m[3], 10);
  var hour = parseInt(m[4], 10);
  var min  = parseInt(m[5], 10);
  var sec  = parseInt(m[6], 10);
  var sign = m[7] === "-" ? -1 : 1;
  var tzH  = parseInt(m[8], 10);
  var tzM  = parseInt(m[9], 10);
  if (day < 1 || day > 31 || hour > 23 || min > 59 || sec > 59 || tzH > 23 || tzM > 59) return null;
  var utcMs = Date.UTC(year, month, day, hour, min, sec);
  if (!isFinite(utcMs)) return null;
  // RFC 5322 §3.3 — date-time MUST be a real calendar date. `Date.UTC`
  // silently normalises impossible inputs (`Feb 31 2026` → `Mar 3 2026`);
  // round-trip via the calendar fields and refuse any drift so a
  // hostile client can't smuggle a different internalDate than the
  // wire suggests.
  var probe = new Date(utcMs);
  if (probe.getUTCFullYear() !== year ||
      probe.getUTCMonth()    !== month ||
      probe.getUTCDate()     !== day ||
      probe.getUTCHours()    !== hour ||
      probe.getUTCMinutes()  !== min ||
      probe.getUTCSeconds()  !== sec) {
    return null;
  }
  return utcMs - sign * (tzH * C.TIME.hours(1) + tzM * C.TIME.minutes(1));
}

// One whitespace character, the same set `\s` matches.
var _IMAP_WS_RE = /\s/;

// The trailing parenthesised group of a FETCH parts-spec, as
// `{ body, matchLength }` where matchLength counts the surrounding
// whitespace the group sits in.
//
// Written as a scan rather than the equivalent `/\s*\(([^)]*)\)\s*$/`. That
// pattern has no start anchor, so a parts-spec of whitespace with no
// parenthesis made it retry from every position, taking time proportional to
// the SQUARE of the line: about 25ms at the default 8192-byte line cap, on a
// value a connected peer chooses. The two forms select the same text.
function _trailingParenGroup(s) {
  var e = s.length - 1;
  while (e >= 0 && _IMAP_WS_RE.test(s.charAt(e))) e -= 1;      // trailing \s*
  if (e < 0 || s.charAt(e) !== ")") return null;
  var open = -1;
  for (var i = e - 1; i >= 0; i -= 1) {
    var c = s.charAt(i);
    if (c === ")") break;                 // the body cannot contain one
    if (c === "(") open = i;              // greedy body keeps the leftmost
  }
  if (open === -1) return null;
  var start = open;
  while (start > 0 && _IMAP_WS_RE.test(s.charAt(start - 1))) start -= 1;   // leading \s*
  return { body: s.slice(open + 1, e), matchLength: s.length - start };
}

// Mailbox name validator. RFC 9051 §5.1 — UTF-8 hierarchy. Refuse
// path-traversal (`..`), NUL, C0 controls, leading/trailing slash,
// oversize.
function _validateMailboxName(name, opts) {
  if (typeof name !== "string" || name.length === 0) return false;
  if (name.length > 1024) return false;                                                              // mailbox name cap
  if (codepointClass.firstControlCharOffset(name, { forbidTab: true }) !== -1) return false;        // control-byte refusal
  if (name.indexOf("..") !== -1) return false;
  if (name === "/" || name[0] === "/" || name[name.length - 1] === "/") return false;
  // Modified-UTF7 detection — RFC 3501 §5.1.3. Sequences are
  // `&...-`. Refuse under strict (RFC 9051 uses raw UTF-8).
  if (opts && opts.allowLegacyMUtf7 !== true) {
    if (/&[A-Za-z0-9+/]*-/.test(name)) return false;                                                  // allow:regex-no-length-cap — mailbox name already length-capped above
  }
  return true;
}

/**
 * @primitive b.mail.server.imap.create
 * @signature b.mail.server.imap.create(opts)
 * @since     0.9.49
 * @status    stable
 * @related   b.mail.server.mx.create, b.mail.server.submission.create, b.mailStore.create
 *
 * Build an IMAP4rev2 listener (RFC 9051). The handle exposes
 * `listen({ port, address })` → ephemeral-bind promise resolving to
 * `{ port, address }`, plus `close()` for graceful shutdown.
 *
 * @opts
 *   tlsContext:        SecureContext,   // required (no plaintext mode)
 *   implicitTls:       boolean,         // RFC 8314 §3 — TLS from the SYN on 993 (the default port becomes 993). STARTTLS is neither advertised nor accepted on it. Default false
 *   greeting:          string,           // default "blamejs IMAP4rev2"
 *   maxLineBytes:      number,           // default 8192
 *   maxLiteralBytes:   number,           // default 64 MiB
 *   idleTimeoutMs:     number,           // default 30 min
 *   maxConnections:    number,           // default 1024 — listener-wide ceiling
 *   profile:           "strict" | "balanced" | "permissive",
 *   auth: {
 *     mechanisms:      ["PLAIN", "LOGIN", "SCRAM-SHA-256", "EXTERNAL", "XOAUTH2"],
 *     verify:          async function (mechanism, credentials) → { ok, actor },
 *   },
 *   mailStore:         b.mailStore handle,    // required
 *   rateLimit:         b.mail.server.rateLimit handle | opts | false,
 *   capabilities:      function (caps, state) → string[],   // optional. The advertised capability list, applied where it is COMPUTED — so the greeting, the CAPABILITY answer and the code completing AUTHENTICATE / LOGIN all carry the same thing. IMAP4rev2 is re-added if dropped (RFC 9051 §6.1.1)
 *   audit:             b.audit                // optional
 *
 * `fetchRange` may return each row's `payload` as a Buffer, and should whenever
 * the row carries message content. RFC 9051 §4.3 makes a literal a counted
 * sequence of octets, and a string cannot hold one: a message octet that is not
 * valid UTF-8 does not survive being encoded on the way to the socket, and the
 * count the response announced stops matching the number of octets it wrote —
 * which is what tells a client where the response ends. A Buffer payload is
 * framed and written as the octets it holds. A string payload is unchanged and
 * remains right for the rows that carry only attributes, such as `FLAGS (\Seen)`.
 *
 * @example
 *   var imap = b.mail.server.imap.create({
 *     tlsContext: b.mail.server.tls.context({ certFile, keyFile }).secureContext,
 *     auth: {
 *       mechanisms: ["PLAIN", "SCRAM-SHA-256"],
 *       verify:     async function (mech, creds) {
 *         return { ok: true, actor: { tenantId: "t1", username: creds.authzid } };
 *       },
 *     },
 *     mailStore: b.mailStore.create({ backend: b.db }),
 *   });
 *   await imap.listen({ port: 143 });
 */
// Every option `create` reads. A name that is not here is a typo, and a typo
// used to be a setting that never took effect: the listener started, said
// nothing, and ran with the default while the caller believed otherwise. Since
// these options decide posture, nothing afterwards distinguishes a misspelled
// one from an omitted one.
var CREATE_OPTS = [
  "tlsContext", "implicitTls", "greeting", "maxLineBytes", "maxLiteralBytes",
  "idleTimeoutMs", "maxConnections", "profile", "auth", "mailStore",
  "rateLimit", "capabilities", "allowLegacyMUtf7", "overrides",
  "agentTenantId", "tenantScope", "audit",
];

function create(opts) {
  validateOpts.requireObject(opts, "mail.server.imap.create",
    MailServerImapError, "mail-server-imap/bad-opts");
  validateOpts.checkOrThrow(opts, CREATE_OPTS, "mail.server.imap.create",
    MailServerImapError, "mail-server-imap/bad-opts");
  validateOpts.auditShape(opts.audit, "mail.server.imap.create",
    MailServerImapError, "mail-server-imap/bad-opts");
  if (!opts.tlsContext) {
    throw new MailServerImapError("mail-server-imap/no-tls-context",
      "mail.server.imap.create: tlsContext is required (no implicit plaintext mode). " +
      "Use b.mail.server.tls.context({ certFile, keyFile, watch: true }) to load + " +
      "auto-reload a cert/key pair from disk.");
  }
  if (!opts.mailStore || typeof opts.mailStore.appendMessage !== "function") {
    throw new MailServerImapError("mail-server-imap/no-mail-store",
      "mail.server.imap.create: mailStore is required (compose b.mailStore.create({ backend: ... }))");
  }
  numericBounds.requireAllPositiveFiniteIntIfPresent(opts,
    ["maxLineBytes", "maxLiteralBytes", "idleTimeoutMs", "maxConnections"],
    "mail.server.imap.", MailServerImapError, "mail-server-imap/bad-bound");

  var greeting          = opts.greeting        || DEFAULT_GREETING_VENDOR;
  var maxLineBytes      = opts.maxLineBytes    || DEFAULT_MAX_LINE_BYTES;
  // How much may sit in the buffer waiting for a handler to finish. Eight
  // lines' worth: enough for any client that pipelines a working set of
  // commands, far short of what an unbounded queue would hold. Each line's
  // CRLF counts, because the buffer holds it -- budgeting eight BODIES closed
  // the connection on eight commands that were each within the line cap.
  var maxPipelinedBytes = (maxLineBytes + CRLF_BYTE_LEN) * PIPELINE_LINE_ALLOWANCE;
  var maxLiteralBytes   = opts.maxLiteralBytes || DEFAULT_MAX_LITERAL;
  var idleTimeoutMs     = opts.idleTimeoutMs   || DEFAULT_IDLE_TIMEOUT_MS;
  var profile           = opts.profile         || "strict";
  var authConfig        = opts.auth            || null;
  // A consumer's say over the advertised list. Refused at construction when it
  // is not callable: the operator asked for a list the listener would then
  // never consult, and the capability line is what a client decides what to
  // attempt from.
  // RFC 8314 §3 — implicit TLS on 993, in preference to the in-band upgrade.
  // Off by default, so an existing composition on 143 is unaffected.
  var implicitTls       = opts.implicitTls === true;
  var capabilitiesHook  = validateOpts.definedFunction(opts.capabilities,
    "b.mail.server.imap.create: capabilities", MailServerImapError,
    "mail-server-imap/bad-opts");
  var mailStore         = opts.mailStore;
  var allowLegacyMUtf7  = profile === "permissive";

  var rateLimit = mailServerRateLimit.resolve(opts.rateLimit);

  var connections  = new Set();

  // The framework audit, plus the operator's own sink when one was supplied.
  // `audit` was documented on this listener and never read, so an operator who
  // wired a sink got silence from it. Both receive the event: the global trail
  // an operator already relies on is not replaced by adding a second reader.
  var _emit = opts.audit
    ? function (action, metadata, outcome) {
        auditEmit.emit(action, metadata, outcome);
        auditEmit.emitToSink(opts, action, outcome || "success", metadata || {});
      }
    : auditEmit.emit;

  function _handleConnection(rawSocket) {
    var accepted = mailServerNet.acceptConnection(rawSocket, {
      rateLimit:    rateLimit,
      connections:  connections,
      emit:         _emit,
      refusedEvent: "mail.server.imap.rate_limit_refused",
      refusalLine:  "* BAD Too many connections from your IP\r\n",
      idPrefix:     "imapconn-",
      wrap:         mailServerTls.implicitTlsWrap(opts.tlsContext, implicitTls),
    });
    if (accepted === null) return;
    var remoteAddress = accepted.remoteAddress;
    var connectionId  = accepted.connectionId;
    var socket        = accepted.socket;

    var state = {
      id:            connectionId,
      remoteAddress: remoteAddress,
      // Already encrypted on an implicit-TLS port, so the session opens with
      // what a STARTTLS upgrade would otherwise have to establish.
      tls:           implicitTls,
      stage:         "not-authenticated",
      actor:         null,
      selectedMailbox: null,
      selectedReadOnly: false,
      authPending:   null,
      pendingLiteral: null,         // { tag, verb, line, size, body }
      idle:          null,          // { tag, timer }
      // Per-connection receive buffer (must NOT be a closure variable —
      // multiple concurrent connections would clobber each other).
      lineBuffer:    Buffer.alloc(0),
      // Slow-loris floor for literal payloads. The listener documents a
      // minimum body rate and built the limiter that enforces one, but never
      // asked it — so the only bound on a literal transfer was the idle
      // timeout, which every arriving byte resets. One byte every few minutes
      // held a connection indefinitely. Measured over bounded windows so an
      // early burst cannot buy credit for a slow tail, and counted at the wire
      // funnel so it cannot be dodged by choosing a different command.
      bodyRateWindow: mailServerNet.createBodyRateWindow(rateLimit),
      wireBytes:      0,
      // Fires the floor when a literal is opened and NO payload follows, which
      // the data-driven check cannot see.
      literalDeadline: null,
    };

    _emit("mail.server.imap.connect",
      { connectionId: connectionId, remoteAddress: remoteAddress });

    socket.setTimeout(idleTimeoutMs);
    socket.on("timeout", function () {
      _writeUntagged(socket, "BYE Idle timeout");
      _close(socket, state);
    });
    socket.on("error", function (err) {
      _emit("mail.server.imap.socket_error",
        { connectionId: connectionId, error: (err && err.message) || String(err) }, "failure");
    });
    // Every teardown, whatever caused it. _close covers the paths that go
    // through it; a socket error does not, and a timer left armed there would
    // fire against a connection that is already gone.
    socket.on("close", function () { _clearLiteralDeadline(state); });

    // Greeting per RFC 9051 §7.1.5 — `* OK <greeting>`.
    _writeUntagged(socket, "OK [CAPABILITY " + _capabilityLine(state) + "] " + greeting);

    socket.on("data", function (chunk) {
      // Per-line cap MUST gate the concat — a single large TCP chunk
      // (~64 KiB on most kernels) can push the buffer past the line
      // cap BEFORE the drain loop runs, so the cap-check inside the
      // loop sees a buffer that's already grown past the policy
      // floor. When the chunk would itself overrun the line cap AND
      // no literal is pending (where over-cap bytes are legitimate
      // payload), reject here and tear the connection down.
      var pendingLiteral = state.pendingLiteral;
      if (pendingLiteral) {
        // The outstanding payload, plus what a client may legitimately have
        // pipelined behind it. Allowing only one further line refused a
        // LITERAL+ client that put the literal's tail and several short
        // commands in one chunk, each of which is within its own cap.
        var room = (pendingLiteral.size - pendingLiteral.body.length) + maxPipelinedBytes;
        if (chunk.length > room) {
          _writeUntagged(socket, "BAD Line too long (cap " + maxLineBytes + ")");
          _close(socket, state);
          return;
        }
      }
      // Every byte this connection receives is counted here, once, before any
      // parser sees it. A counter kept inside the literal accumulator would
      // credit re-fed bytes twice, and a peer pipelining a one-byte payload
      // with the next command would get roughly double its actual rate.
      state.wireBytes += chunk.length;
      // A literal of zero octets has no arrival rate to be below: nothing is
      // being transferred, only the CRLF that ends the command is still owed.
      // Its window is never started, so measuring against one would refuse a
      // conforming `{0}` the moment its next byte arrived.
      if (state.pendingLiteral && state.pendingLiteral.size > 0 &&
          state.bodyRateWindow.starved(state.wireBytes, time.monotonicMs())) {
        _emit("mail.server.imap.literal_refused",
          { connectionId: state.id, reason: "body-rate-below-floor",
            minBytesPerSecond: rateLimit.minBytesPerSecond() }, "denied");
        _writeUntagged(socket, "BYE Literal arriving below the minimum rate; closing connection");
        _close(socket, state);
        return;
      }
      state.lineBuffer = Buffer.concat([state.lineBuffer, chunk]);
      _drainBuffer(state, socket);
    });
  }

  // The rate floor is asked from the socket's data handler, which only runs
  // when bytes arrive — so a peer that opens a literal and then sends NOTHING
  // was never measured at all, and held the connection until the idle timeout
  // it was never going to trip. This is the deadline for that case: one timer
  // per transfer, fired once the window is old enough for the limiter to have
  // an opinion, cancelled when the transfer completes.
  //
  // unref so a pending literal cannot hold the process open at shutdown.
  function _armLiteralDeadline(state, socket) {
    _clearLiteralDeadline(state);
    state.literalDeadline = setTimeout(function () {
      state.literalDeadline = null;
      if (!state.pendingLiteral) return;
      // Re-armed while the transfer is still open. Firing once and stopping
      // would leave burst-then-stall unbounded: send enough to clear the first
      // window, then nothing, and no data event ever comes to ask again — which
      // is the shape the bounded windows exist to close in the first place.
      if (!state.bodyRateWindow.starved(state.wireBytes, time.monotonicMs())) {
        _armLiteralDeadline(state, socket);
        return;
      }
      _emit("mail.server.imap.literal_refused",
        { connectionId: state.id, reason: "body-rate-below-floor",
          minBytesPerSecond: rateLimit.minBytesPerSecond() }, "denied");
      _writeUntagged(socket, "BYE Literal arriving below the minimum rate; closing connection");
      _close(socket, state);
    }, rateLimit.bodyRateWindowMs() + LITERAL_DEADLINE_GRACE_MS);
    if (typeof state.literalDeadline.unref === "function") state.literalDeadline.unref();
  }
  function _clearLiteralDeadline(state) {
    if (state.literalDeadline) { clearTimeout(state.literalDeadline); state.literalDeadline = null; }
  }

  // Receive-buffer drain: extract complete lines (CRLF-terminated)
  // and dispatch. When the previous command opened a literal (e.g.
  // APPEND ... {N}), the next N bytes are the literal payload — we
  // accumulate them before resuming line-mode dispatch.
  // One command at a time. A handler that authenticates or reaches the store
  // settles before the next line is read, so a guard reading state a later
  // handler writes sees what it is guarding against. Draining the whole buffer
  // synchronously let a pipelined client have every command dispatched against
  // the state as it stood before any of them ran. `mail-server-mx.js` already
  // chained its ingestion for this reason.
  function _drainBuffer(state, socket) {
    // What may WAIT is bounded, on EVERY entry rather than only when a pump is
    // already running: one data event can carry a command plus more queued
    // behind it than the allowance, and that first event takes the not-running
    // branch. The cap on a LINE is enforced where a line is taken, because one
    // chunk legitimately carries several complete commands; what a line cap
    // cannot say is how many lines are held at once, and a client that sends
    // faster than the handlers run would grow this buffer for as long as it
    // liked.
    //
    // Checked here rather than in the socket's own data handler because the
    // post-STARTTLS reader is the shared upgradeLineProtocol helper, which
    // feeds this function directly: a bound placed on the plaintext handler
    // alone would be missing on the encrypted path.
    // Only the literal's OUTSTANDING octets are exempt, not the whole buffer.
    // Exempting it entirely let a client put a literal opener and then any
    // amount of pipelined commands in one write: the bound was skipped for all
    // of it, and once the literal was consumed the pump continued through the
    // queue from inside `step()` without passing here again.
    var outstanding = state.pendingLiteral
      ? Math.max(0, state.pendingLiteral.size - state.pendingLiteral.body.length)
      : 0;
    if (safeBuffer.byteLengthOf(state.lineBuffer) - outstanding > maxPipelinedBytes) {
      _writeUntagged(socket, "BAD Too much pipelined data awaiting execution (cap " +
        maxPipelinedBytes + " bytes)");
      _close(socket, state);
      return;
    }
    if (state.pumping) return;                  // the running pump will take it
    state.pumping = true;
    function done() { state.pumping = false; }
    function fail(e) {
      state.pumping = false;
      _emit("mail.server.imap.handler_threw",
        { connectionId: state.id, error: (e && e.message) || String(e) }, "failure");
      try { _writeUntagged(socket, "BAD Server error"); } catch (_e) { /* socket gone */ }
      _close(socket, state);
    }
    function after(pending) { Promise.resolve(pending).then(step, fail); }

    function step() {
      if (state.stage === "closed") return done();
      if (state.pendingLiteral) {
        var need = state.pendingLiteral.size - state.pendingLiteral.body.length;
        if (state.lineBuffer.length < need) {
          state.pendingLiteral.body = Buffer.concat([state.pendingLiteral.body, state.lineBuffer]);
          state.lineBuffer = Buffer.alloc(0);
          return done();
        }
        state.pendingLiteral.body = Buffer.concat([state.pendingLiteral.body, state.lineBuffer.subarray(0, need)]);
        state.lineBuffer = state.lineBuffer.subarray(need);
        // What follows the octets on the SAME line belongs to this command:
        // either nothing, and the CRLF that ends it, or a space and more
        // arguments. Consuming only the octets left that CRLF in the buffer,
        // where the next turn read it as a line of its own and answered BAD to
        // a command that had already succeeded.
        //
        // The command waits for that CRLF. RFC 9051's grammar makes it part of
        // the command (`command = tag SP ... CRLF`, and `append` ends in a
        // literal), so it is always coming, and it is the ONLY thing that says
        // whether the literal was the last argument or another follows.
        //
        // Deciding from an empty receive buffer instead would decide from TCP
        // segmentation: `LOGIN {4}` octets `user {8}` octets `password` is one
        // command, and whether it parsed as one would depend on where the
        // packets happened to split. A command that works or fails by packet
        // boundary is worse than one that waits, because it fails
        // intermittently and on someone else's network.
        var tail = state.lineBuffer.indexOf("\r\n");
        if (tail === -1) {
          if (safeBuffer.byteLengthOf(state.lineBuffer) > maxLineBytes) {
            _writeUntagged(socket, "BAD Line too long (cap " + maxLineBytes + ")");
            _close(socket, state);
          }
          return done();                      // the rest of the line is still arriving
        }
        var rest = state.lineBuffer.subarray(0, tail).toString("utf8");
        state.lineBuffer = state.lineBuffer.subarray(tail + 2);
        return after(_completeLiteralCommand(state, socket, rest));
      }
      var crlf = state.lineBuffer.indexOf("\r\n");
      if (crlf === -1) {
        if (safeBuffer.byteLengthOf(state.lineBuffer) > maxLineBytes) {
          _writeUntagged(socket, "BAD Line too long (cap " + maxLineBytes + ")");
          _close(socket, state);
        }
        return done();
      }
      // The per-line cap, enforced on the line itself. A complete line that is
      // over it is refused here rather than dispatched, which is the check the
      // chunk-sized one used to stand in for.
      if (crlf > maxLineBytes) {
        _writeUntagged(socket, "BAD Line too long (cap " + maxLineBytes + ")");
        _close(socket, state);
        return done();
      }
      var rawLine = state.lineBuffer.subarray(0, crlf).toString("utf8");
      state.lineBuffer = state.lineBuffer.subarray(crlf + 2);
      // A line read from the wire begins a new command, so whatever literals
      // the previous one absorbed stop counting against this one.
      state.literalAbsorbed = 0;
      return after(_handleLine(state, socket, rawLine));
    }
    step();
  }

  function _handleLine(state, socket, line) {
    // Continuation: AUTHENTICATE multi-step expects a client response
    if (state.authPending) {
      return _runAuthStep(state, socket, line.trim());
    }
    // IDLE termination — RFC 2177 §3 expects `DONE` line.
    if (state.idle) {
      if (line.toUpperCase() === "DONE") {
        var idleTag = state.idle.tag;
        if (state.idle.timer) clearTimeout(state.idle.timer);
        state.idle = null;
        _writeTagged(socket, idleTag, "OK IDLE terminated");
      } else {
        _writeUntagged(socket, "BAD Expected DONE during IDLE");
      }
      return undefined;
    }
    var parsed;
    try {
      parsed = guardImapCommand.validate(line, {
        profile: profile,
        authenticated: state.actor !== null,
      });
    } catch (e) {
      if (e && e.code === "guard-imap-command/literal-smuggling") {
        _emit("mail.server.imap.smtp_smuggling_detected",
          { connectionId: state.id, line: line.slice(0, LINE_PREVIEW) }, "denied");
      }
      _writeUntagged(socket, "BAD " + (e && e.message ? e.message.slice(0, ERR_CLAMP) : "syntax"));
      return;
    }
    // Literal-opener: stash + emit continuation. Zero-length literals
    // (`{0}`) are legal per RFC 9051 §6.3.12 (e.g. APPEND of an empty
    // message body — rare but spec-compliant; refusing them would
    // diverge from the wire-protocol).
    if (parsed.literalSize !== null) {
      if (parsed.literalSize > maxLiteralBytes) {
        _emit("mail.server.imap.literal_overflow_refused",
          { connectionId: state.id, attempted: parsed.literalSize, cap: maxLiteralBytes },
          "denied");
        _writeTagged(socket, parsed.tag,
          "NO Literal " + parsed.literalSize + " bytes exceeds cap " + maxLiteralBytes);
        return;
      }
      // Authorization BEFORE the resource commitment. Opening a literal invites
      // up to maxLiteralBytes and holds a connection slot until the payload
      // arrives, and that decision was taken from the parsed shape alone: the
      // check that would refuse the command is the first line of its handler,
      // and handlers are reached only through _completeLiteralCommand — after
      // the whole literal has been buffered. An unauthenticated peer could
      // therefore open the window on an AUTHENTICATED-only verb and trickle
      // into it for as long as it liked.
      //
      // An allowlist, not a blanket pre-auth refusal: LOGIN and AUTHENTICATE
      // legitimately carry a literal before authentication, because a password
      // is exactly the value a quoted string cannot always hold. Every other
      // verb that can open one is AUTHENTICATED-only per the state table at the
      // top of this file.
      // hasOwnProperty.call, not a bare index: the verb comes off the wire, and
      // a bare lookup finds inherited names, so a peer sending `constructor`
      // would read as allowed by an allowlist that never named it.
      if (!state.actor &&
          !Object.prototype.hasOwnProperty.call(PRE_AUTH_LITERAL_VERBS, parsed.verb)) {
        _emit("mail.server.imap.literal_refused_pre_auth",
          { connectionId: state.id, verb: parsed.verb, size: parsed.literalSize },
          "denied");
        _writeTagged(socket, parsed.tag,
          "NO " + parsed.verb + " requires authentication; no literal accepted before LOGIN");
        return;
      }
      // Zero-byte literal: no octets to read, but the command line still ends
      // after them. Left pending so the reader consumes that terminator with
      // the command it belongs to; completing here left it in the buffer to be
      // read as an empty command, which is the same spurious BAD a non-empty
      // literal used to draw.
      //
      // A synchronizing one still gets its continuation request. RFC 9051
      // section 7.5 does not exempt an empty literal, and the client waits for
      // the `+` before sending the CRLF that ends the command -- so with the
      // command now waiting for that CRLF, omitting the `+` leaves both sides
      // waiting on each other.
      if (parsed.literalSize === 0) {
        state.pendingLiteral = {
          tag:  parsed.tag,
          verb: parsed.verb,
          line: line,
          size: 0,
          body: Buffer.alloc(0),
          synchronizing: !parsed.literalNonSync,
        };
        if (!parsed.literalNonSync) _writeContinuation(socket, "Ready for literal data");
        return undefined;
      }
      state.pendingLiteral = {
        tag:  parsed.tag,
        verb: parsed.verb,
        line: line,
        size: parsed.literalSize,
        body: Buffer.alloc(0),
        synchronizing: !parsed.literalNonSync,
      };
      // The baseline is the byte position where the OPENER ends, not the
      // connection total as it stands now. wireBytes is incremented for the
      // whole chunk before the drain runs, so when a chunk carries the opener
      // and the first of its payload together, those payload bytes would land
      // in the baseline and never be credited — and a conforming sender whose
      // remaining chunks arrive near the floor could be cut off for bytes it
      // had already sent. Whatever is still buffered here IS that payload.
      state.bodyRateWindow.start(time.monotonicMs(), state.wireBytes - state.lineBuffer.length);
      _armLiteralDeadline(state, socket);
      if (!parsed.literalNonSync) {
        // RFC 9051 §7.5 — a synchronizing literal is answered with a command
        // continuation request: a line that BEGINS with `+`. Written as an
        // untagged response, the wire carried `* + Ready for literal data`,
        // which is not one, so a conforming client waited for a `+` line that
        // never came and APPEND could not complete. The non-synchronizing
        // route is no escape either: the strict profile's guard refuses
        // LITERAL+ and CAPABILITY does not advertise it.
        _writeContinuation(socket, "Ready for literal data");
      }
      return;
    }
    // Returned so the reader waits for it before taking the next line.
    return _dispatch(state, socket, parsed, line);
  }

  // An astring that arrived as a literal, written back as a quoted string so
  // the assembled command reads as though it had never used one. RFC 9051
  // section 4.3 quoted-strings hold neither CR, LF nor NUL, so a body carrying
  // one is not an astring and the command is refused rather than reassembled
  // into something the client did not send.
  function _quoteAstring(body) {
    for (var i = 0; i < body.length; i += 1) {
      var c = body[i];
      if (c === 0x0D || c === 0x0A || c === 0x00) return null;
    }
    var text = body.toString("utf8");
    // A literal carries CHAR8, so its octets need not be text at all, and
    // decoding what is not UTF-8 substitutes U+FFFD for each undecodable byte.
    // That would hand the command a value the client never sent -- a password
    // silently altered, failing as a wrong password. Refuse instead: the bytes
    // round-trip or they are not an astring this can rebuild.
    if (!Buffer.from(text, "utf8").equals(body)) return null;
    var out = "\"";
    for (var j = 0; j < text.length; j += 1) {
      var ch = text.charAt(j);
      if (ch === "\\" || ch === "\"") out += "\\";
      out += ch;
    }
    return out + "\"";
  }

  // `rest` is whatever followed the literal's octets on the SAME command line,
  // up to the CRLF that ends it.
  //
  // RFC 9051 allows a literal wherever an astring is allowed, and the LOGIN
  // example in section 6.2.3 carries two on one line, so a literal is not
  // necessarily the last token and even a last one is usually an argument. It
  // goes back into the command as a quoted string and the assembled line is
  // read again, which opens the next literal if there is one. Only a payload
  // verb's final literal stays out of the line.
  //
  // Dispatching `rest` as a fresh line instead ran a fragment of one command
  // as a command of its own.
  function _completeLiteralCommand(state, socket, rest) {
    var pending = state.pendingLiteral;
    state.pendingLiteral = null;
    _clearLiteralDeadline(state);
    // Strip the trailing literal opener `{N}` (or `{N+}`) from the line
    var lineNoLit = pending.line.replace(/\{[0-9]+\+?\}$/, "").trim();                                // allow:regex-no-length-cap — line length already capped upstream
    var tail = rest === undefined ? "" : rest;

    // After a literal's octets the grammar allows the end of the command line
    // or a space and more arguments, nothing else. Anything else is a client
    // that did not terminate its line, and treating what follows as this
    // command's arguments would run the next command as part of this one.
    // A space when more arguments follow, or a closing delimiter when the
    // literal was an element of a parenthesized list: `ID ("name" {4}` octets
    // `)` is one command, and `)` is the next byte the grammar allows there.
    // Anything else is a client that did not terminate its line, and treating
    // what follows as this command's arguments would run the next command as
    // part of this one.
    if (tail !== "" && tail.charAt(0) !== " " && tail.charAt(0) !== ")") {
      _writeTagged(socket, pending.tag,
        "BAD Expected end of command or a further argument after the literal");
      return undefined;
    }

    if (tail !== "") {
      // More of the command follows, so the literal has to go back into the
      // line: an argument that sits BEFORE other arguments has nowhere else to
      // go. Read again, which opens the next literal if there is one.
      var quoted = _quoteAstring(pending.body);
      if (quoted === null) {
        _writeTagged(socket, pending.tag,
          "BAD A literal before further arguments must be a quotable string: " +
          "no CR, LF or NUL, and decodable as UTF-8");
        return undefined;
      }
      // The two limits are charged separately, because the wire frames them
      // separately. `maxLineBytes` bounds the command's own SYNTAX -- what the
      // client typed on the line -- and a literal is not that: it is framed by
      // its own octet count and bounded by `maxLiteralBytes`. Charging a
      // literal's bytes against the line cap refused `LOGIN {9000}` and a
      // password, whose text is a few dozen characters.
      if (safeBuffer.byteLengthOf(lineNoLit) + safeBuffer.byteLengthOf(tail) > maxLineBytes) {
        _writeTagged(socket, pending.tag, "BAD Line too long (cap " + maxLineBytes + ")");
        return undefined;
      }
      // What the literals of ONE command may add up to. Each is bounded on its
      // own, and a command may carry any number of them, so without this the
      // assembled command grows with however many the client chooses to send.
      state.literalAbsorbed = (state.literalAbsorbed || 0) +
        safeBuffer.byteLengthOf(pending.body);
      if (state.literalAbsorbed > maxLiteralBytes) {
        _writeTagged(socket, pending.tag,
          "BAD Literals in one command exceed " + maxLiteralBytes + " bytes");
        return undefined;
      }
      return _handleLine(state, socket, lineNoLit + " " + quoted + tail);
    }

    // The last literal counts toward the command's total as much as the ones
    // before it. Counting only the non-final ones let a command carry one more
    // literal than the cap allows: a `LOGIN` with a full-size username literal
    // and a full-size password literal is twice the limit, and the one that
    // escaped the count is the one that reaches dispatch.
    // The last literal counts toward the command's total as much as the ones
    // before it. Counting only the non-final ones let a command carry one more
    // literal than the cap allows: a `LOGIN` with a full-size username literal
    // and a full-size password literal is twice the limit, and the one that
    // escaped the count is the one that reaches dispatch.
    state.literalAbsorbed = (state.literalAbsorbed || 0) +
      safeBuffer.byteLengthOf(pending.body);
    if (state.literalAbsorbed > maxLiteralBytes) {
      _writeTagged(socket, pending.tag,
        "BAD Literals in one command exceed " + maxLiteralBytes + " bytes");
      return undefined;
    }

    // The literal ended the command, so it stays out of the line and goes to
    // the handler as bytes. That is the only way to carry a value which is not
    // text -- a message for APPEND, a search term in another charset -- and
    // the handlers that take one already read it there, verbatim, which is
    // what a client using a literal asked for.
    var parsed;
    try { parsed = guardImapCommand.validate(lineNoLit, { profile: profile, authenticated: state.actor !== null }); }
    catch (e) {
      _writeTagged(socket, pending.tag, "BAD " + (e && e.message ? e.message.slice(0, ERR_CLAMP) : "syntax"));
      return undefined;
    }
    return _dispatch(state, socket, parsed, lineNoLit, pending.body);
  }

  // Adapter shim — uniform `(state, socket, parsed, literalBody)`
  // dispatch contract over the per-verb handlers. Builds the registry
  // defaults lazily on first dispatch so the closure-scoped handler
  // references are bound when needed (handlers are hoisted by their
  // function-declarations; the registry init runs at dispatch time).
  var _registry = null;
  function _ensureRegistry() {
    if (_registry !== null) return _registry;
    // Per-handler resource budgets. Sized per the verb's known
    // payload shape (LIST scans the folder tree; FETCH walks N
    // messages; APPEND accepts a literal up to maxLiteralBytes).
    var SHORT_MS  = 5 * 1000;                                                                        // allow:raw-time-literal — 5s short-command budget
    var MEDIUM_MS = 30 * 1000;                                                                       // allow:raw-time-literal — 30s medium-command budget
    var LONG_MS   = 2 * 60 * 1000;                                                                   // allow:raw-time-literal — 2 min long-command budget (FETCH / APPEND)
    var SHORT_B   = 8 * 1024;                                                                        // allow:raw-byte-literal — 8 KiB short-command response cap
    var MEDIUM_B  = 1024 * 1024;                                                                     // allow:raw-byte-literal — 1 MiB medium-command response cap
    var LONG_B    = 64 * 1024 * 1024;                                                                // allow:raw-byte-literal — 64 MiB FETCH/APPEND response cap
    var defaults = {
      CAPABILITY:   { fn: function (s, so, p)  { return _handleCapability(s, so, p.tag); },
                      maxHandlerBytes: SHORT_B,  maxHandlerMs: SHORT_MS },
      NOOP:         { fn: function (s, so, p)  { return _writeTagged(so, p.tag, "OK NOOP completed"); },
                      maxHandlerBytes: SHORT_B,  maxHandlerMs: SHORT_MS },
      LOGOUT:       { fn: function (s, so, p)  { return _handleLogout(s, so, p.tag); },
                      maxHandlerBytes: SHORT_B,  maxHandlerMs: SHORT_MS },
      ID:           { fn: function (s, so, p)  { return _handleId(s, so, p.tag, p.args); },
                      maxHandlerBytes: SHORT_B,  maxHandlerMs: SHORT_MS },
      STARTTLS:     { fn: function (s, so, p)  { return _handleStartTls(s, so, p.tag); },
                      maxHandlerBytes: SHORT_B,  maxHandlerMs: SHORT_MS },
      AUTHENTICATE: { fn: function (s, so, p)  { return _handleAuthenticate(s, so, p.tag, p.args); },
                      maxHandlerBytes: MEDIUM_B, maxHandlerMs: MEDIUM_MS },
      LOGIN:        { fn: function (s, so, p, lit) { return _handleLogin(s, so, p.tag, p.args, lit); },
                      maxHandlerBytes: MEDIUM_B, maxHandlerMs: MEDIUM_MS },
      ENABLE:       { fn: function (s, so, p)  { return _handleEnable(s, so, p.tag, p.args); },
                      maxHandlerBytes: SHORT_B,  maxHandlerMs: SHORT_MS },
      // A mailbox name is the whole argument here, so a trailing literal IS
      // that name — which is how a client sends one that UTF-8 or a space puts
      // beyond a quoted string. Substituted rather than appended: the reader
      // strips the `{N}` opener, leaving p.args empty, and re-quoting the
      // payload would refuse exactly the names a literal exists to carry.
      SELECT:       { fn: function (s, so, p, lit) { return _handleSelect(s, so, p.tag, lit != null ? String(lit) : p.args, false); },
                      maxHandlerBytes: MEDIUM_B, maxHandlerMs: MEDIUM_MS },
      EXAMINE:      { fn: function (s, so, p, lit) { return _handleSelect(s, so, p.tag, lit != null ? String(lit) : p.args, true); },
                      maxHandlerBytes: MEDIUM_B, maxHandlerMs: MEDIUM_MS },
      LIST:         { fn: function (s, so, p)  { return _handleList(s, so, p.tag, p.args); },
                      maxHandlerBytes: MEDIUM_B, maxHandlerMs: MEDIUM_MS },
      STATUS:       { fn: function (s, so, p)  { return _handleStatus(s, so, p.tag, p.args); },
                      maxHandlerBytes: MEDIUM_B, maxHandlerMs: MEDIUM_MS },
      NAMESPACE:    { fn: function (s, so, p)  {
                        _writeUntagged(so, "NAMESPACE ((\"\" \"/\")) NIL NIL");
                        return _writeTagged(so, p.tag, "OK NAMESPACE completed");
                      },
                      maxHandlerBytes: SHORT_B,  maxHandlerMs: SHORT_MS },
      APPEND:       { fn: function (s, so, p, lit) { return _handleAppend(s, so, p.tag, p.args, lit); },
                      maxHandlerBytes: LONG_B,   maxHandlerMs: LONG_MS },
      CHECK:        { fn: function (s, so, p)  { return _writeTagged(so, p.tag, "OK CHECK completed"); },
                      maxHandlerBytes: SHORT_B,  maxHandlerMs: SHORT_MS },
      CLOSE:        { fn: function (s, so, p)  { return _handleClose(s, so, p.tag); },
                      maxHandlerBytes: SHORT_B,  maxHandlerMs: SHORT_MS },
      UNSELECT:     { fn: function (s, so, p)  { return _handleClose(s, so, p.tag); },
                      maxHandlerBytes: SHORT_B,  maxHandlerMs: SHORT_MS },
      EXPUNGE:      { fn: function (s, so, p)  { return _handleExpunge(s, so, p.tag); },
                      maxHandlerBytes: MEDIUM_B, maxHandlerMs: MEDIUM_MS },
      FETCH:        { fn: function (s, so, p)  { return _handleFetch(s, so, p.tag, p.args); },
                      maxHandlerBytes: LONG_B,   maxHandlerMs: LONG_MS },
      STORE:        { fn: function (s, so, p)  { return _handleStore(s, so, p.tag, p.args); },
                      maxHandlerBytes: MEDIUM_B, maxHandlerMs: MEDIUM_MS },
      // Four parameters, not three: the registry applies every argument
      // dispatch was given, so a closure that declares fewer DISCARDS the rest
      // by arity. UID SEARCH carries its search term as a literal, and dropping
      // it here failed every non-ASCII term with a tagged BAD.
      UID:          { fn: function (s, so, p, lit) { return _handleUid(s, so, p.tag, p.args, lit); },
                      maxHandlerBytes: LONG_B,   maxHandlerMs: LONG_MS },
      IDLE:         { fn: function (s, so, p)  { return _handleIdle(s, so, p.tag); },
                      maxHandlerBytes: SHORT_B,  maxHandlerMs: LONG_MS },
      // v0.11.28 — RFC 5465 NOTIFY / RFC 5464 METADATA / RFC 4469 CATENATE.
      NOTIFY:       { fn: function (s, so, p)  { return _handleNotify(s, so, p.tag, p.args); },
                      maxHandlerBytes: MEDIUM_B, maxHandlerMs: MEDIUM_MS },
      GETMETADATA:  { fn: function (s, so, p)  { return _handleGetMetadata(s, so, p.tag, p.args); },
                      maxHandlerBytes: MEDIUM_B, maxHandlerMs: MEDIUM_MS },
      SETMETADATA:  { fn: function (s, so, p, lit) { return _handleSetMetadata(s, so, p.tag, p.args, lit); },
                      maxHandlerBytes: LONG_B,   maxHandlerMs: MEDIUM_MS },
      DONE:         { fn: function (s, so, p)  { return _writeTagged(so, p.tag, "BAD DONE outside IDLE"); },
                      maxHandlerBytes: SHORT_B,  maxHandlerMs: SHORT_MS },
      // Defaults for the verbs the v0.9.49 listener didn't dispatch —
      // operators wire concrete handlers via opts.overrides.
      SEARCH:       { fn: function (s, so, p)  { return _writeTagged(so, p.tag, "NO SEARCH not configured"); },
                      maxHandlerBytes: SHORT_B,  maxHandlerMs: SHORT_MS },
      CREATE:       { fn: function (s, so, p)  { return _writeTagged(so, p.tag, "NO CREATE not configured"); },
                      maxHandlerBytes: SHORT_B,  maxHandlerMs: SHORT_MS },
      DELETE:       { fn: function (s, so, p)  { return _writeTagged(so, p.tag, "NO DELETE not configured"); },
                      maxHandlerBytes: SHORT_B,  maxHandlerMs: SHORT_MS },
      RENAME:       { fn: function (s, so, p)  { return _writeTagged(so, p.tag, "NO RENAME not configured"); },
                      maxHandlerBytes: SHORT_B,  maxHandlerMs: SHORT_MS },
      SUBSCRIBE:    { fn: function (s, so, p)  { return _writeTagged(so, p.tag, "NO SUBSCRIBE not configured"); },
                      maxHandlerBytes: SHORT_B,  maxHandlerMs: SHORT_MS },
      UNSUBSCRIBE:  { fn: function (s, so, p)  { return _writeTagged(so, p.tag, "NO UNSUBSCRIBE not configured"); },
                      maxHandlerBytes: SHORT_B,  maxHandlerMs: SHORT_MS },
      COPY:         { fn: function (s, so, p)  { return _writeTagged(so, p.tag, "NO COPY not configured"); },
                      maxHandlerBytes: SHORT_B,  maxHandlerMs: SHORT_MS },
      MOVE:         { fn: function (s, so, p)  { return _writeTagged(so, p.tag, "NO MOVE not configured"); },
                      maxHandlerBytes: SHORT_B,  maxHandlerMs: SHORT_MS },
    };
    _registry = mailServerRegistry.create({
      protocol:        "imap",
      defaults:        defaults,
      overrides:       opts.overrides || {},
      // b.agent.tenant adoption (v0.10.12). Operators wiring multi-
      // tenant IMAP deployments pass `tenantScope` from
      // `b.agent.tenant.create({...})` plus the per-listener tenant id.
      // The registry then gates every dispatch on
      // `tenantScope.check(state.actor, agentTenantId)` before guard
      // validation or audit emission.
      tenantScope:     opts.tenantScope    || null,
      agentTenantId:   opts.agentTenantId  || null,
      notFoundHandler: function (verb, _state, socket, parsed) {
        return _writeTagged(socket, parsed.tag,
          "BAD Verb '" + verb + "' not implemented in v1");
      },
    });
    return _registry;
  }

  function _dispatch(state, socket, parsed, _rawLine, literalBody) {
    // Registry dispatch may return a Promise (async override handler,
    // or a safeAsync.withTimeout-wrapped Promise). The caller's
    // try/catch is synchronous, so a Promise rejection would surface
    // as an unhandled rejection AND the client would never receive
    // the tagged error reply. Attach a catch that converts the
    // rejection into a `BAD`/`NO` tagged response + audit emit.
    var result;
    try {
      result = _ensureRegistry().dispatch(parsed.verb, state, socket, parsed, literalBody);
    } catch (err) {
      _writeTagged(socket, parsed.tag,
        "NO " + ((err && err.message) || "handler threw").slice(0, ERR_CLAMP));
      _emit("mail.server.imap.handler_threw",
        { connectionId: state.id, verb: parsed.verb,
          error: (err && err.message) || String(err) }, "failure");
      return;
    }
    // The HANDLED chain is returned, not the raw one: the reader waits on this
    // to take the next line, and a rejection has already been answered here,
    // so handing back the rejected promise would report the same failure twice.
    if (result && typeof result.then === "function") {
      return result.then(
        function () { /* tagged response already written by handler */ },
        function (err) {
          try {
            _writeTagged(socket, parsed.tag,
              "NO " + ((err && err.message) || "handler rejected").slice(0, ERR_CLAMP));
          } catch (_we) { /* socket may already be gone */ }
          try {
            _emit("mail.server.imap.handler_rejected",
              { connectionId: state.id, verb: parsed.verb,
                error: (err && err.message) || String(err) }, "failure");
          } catch (_ae) { /* drop-silent */ }
        }
      );
    }
    return result;
  }

  // The consumer's list, reduced to what may actually be written. Each value
  // goes into a space-separated protocol line, so one carrying a space would
  // be two capabilities and one carrying CR or LF a second server response of
  // the consumer's choosing (`"X\r\n* BYE injected"`) — the same injection
  // class the SASL-challenge and refusal-text helpers refuse. A value that
  // cannot be advertised is dropped and named in an audit; the rest of the
  // list still goes out.
  function _atomsOf(supplied, state) {
    var atoms = [];
    for (var si = 0; si < supplied.length; si += 1) {
      var atom = String(supplied[si]);
      if (_isCapabilityAtom(atom)) {
        atoms.push(atom);
      } else if (atom.length > 0) {
        _emit("mail.server.imap.capability_refused",
          { connectionId: state.id, capability: atom.slice(0, 64) }, "denied");                 // audit-log value truncation
      }
    }
    return atoms;
  }

  function _capabilityLine(state) {
    var caps = ["IMAP4rev2"];
    if (!state.tls) caps.push("STARTTLS");
    // RFC 7162 §3 — CONDSTORE is server-advertised; clients ENABLE
    // before relying on MODSEQ in untagged FETCH responses. QRESYNC
    // (§3.2) adds the VANISHED responses on SELECT + post-EXPUNGE
    // and implicitly engages CONDSTORE per §3.2.5.
    caps.push("CONDSTORE");
    caps.push("QRESYNC");
    // v0.11.28 — opt-in extensions (advertised so capable clients can
    // exercise them; each handler refuses gracefully when the operator
    // backend doesn't supply the corresponding hook).
    caps.push("NOTIFY");                                // RFC 5465
    caps.push("METADATA");                              // RFC 5464 — per-mailbox annotations          // RFC number in comment
    caps.push("METADATA-SERVER");                       // RFC 5464 §3.1 — server-wide annotations    // RFC number in comment
    caps.push("CATENATE");                              // RFC 4469 — APPEND from existing parts
    // NB: COMPRESS=DEFLATE (RFC 4978) is not advertised and cannot be
    // enabled — a CRIME-class compression-oracle attack applies to the
    // encrypted IMAP stream.
    // Advertise AUTH=<mech> ONLY for mechanisms the operator wired
    // in opts.auth.mechanisms. RFC 9051 §7.2 — clients pick from the
    // advertised list; advertising AUTH=PLAIN when authConfig is null
    // or doesn't include PLAIN sets clients up for AUTHENTICATE
    // requests that the listener refuses with "no AUTHENTICATE
    // configured" / "mechanism not advertised".
    if (authConfig && Array.isArray(authConfig.mechanisms)) {
      for (var i = 0; i < authConfig.mechanisms.length; i += 1) {
        var m = String(authConfig.mechanisms[i]).toUpperCase();
        if (caps.indexOf("AUTH=" + m) === -1) caps.push("AUTH=" + m);
      }
    }
    // Applied HERE, where the list is computed, so the three places it is
    // written on one connection — the greeting (RFC 9051 §7.1.5), the answer
    // to CAPABILITY (§6.1.1) and the code completing AUTHENTICATE / LOGIN —
    // stay identical by construction. Overriding the CAPABILITY verb instead
    // would leave a server whose three answers disagree, and one of them false
    // whichever way it is set.
    if (capabilitiesHook) {
      // The hook runs on the greeting, which is written before a client has
      // sent anything: a throw there would take out the connection at the
      // point where nothing has gone wrong yet. Reading each value is part of
      // the same guarded region, because an entry whose `toString` throws is
      // as much the consumer's failure as a hook that threw outright — and it
      // would escape a guard that covered only the call.
      var advertised = null;
      try {
        var supplied = capabilitiesHook(caps.slice(), state);
        if (Array.isArray(supplied)) advertised = _atomsOf(supplied, state);
      } catch (e) {
        _emit("mail.server.imap.capabilities_hook_failed",
          { connectionId: state.id, error: (e && e.message) || String(e) }, "failure");
        advertised = null;
      }
      // §6.1.1 requires IMAP4rev2 in the list, and a listener that omitted it
      // would be claiming a protocol it does not speak. The requirement stays
      // with the listener rather than being delegated to whoever supplied the
      // hook.
      if (advertised) {
        if (advertised.indexOf("IMAP4rev2") === -1) advertised.unshift("IMAP4rev2");
        // STARTTLS is not the consumer's to advertise: whether it is offered
        // depends on the state of THIS connection, and the listener refuses
        // the command outright on an implicit-TLS port (RFC 8314 §3.3) or once
        // the session is already encrypted. A hook that put it back would have
        // a client select a capability the listener cannot honour, and would
        // undo the guarantee `implicitTls` makes about what that port says.
        if (implicitTls || state.tls) {
          advertised = advertised.filter(function (c) { return c.toUpperCase() !== "STARTTLS"; });
        }
        caps = advertised;
      }
    }
    return caps.join(" ");
  }

  // RFC 7162 §3.1 — ENABLE CONDSTORE flips the per-state flag that
  // makes subsequent untagged FETCH responses include the MODSEQ
  // attribute and lets STORE / FETCH carry CHANGEDSINCE /
  // UNCHANGEDSINCE modifiers. Unknown ENABLE arguments are silently
  // ignored per RFC 5161 §3.1 — the server lists in `ENABLED <name>`
  // only the extensions it actually turned on.
  function _handleEnable(state, socket, tag, args) {
    var requested = (args || "").split(/\s+/).filter(Boolean);
    var enabled = [];
    for (var i = 0; i < requested.length; i += 1) {
      var name = requested[i].toUpperCase();
      if (name === "CONDSTORE") {
        if (!state.enabledCondStore) {
          state.enabledCondStore = true;
          enabled.push("CONDSTORE");
        }
      } else if (name === "QRESYNC") {
        // RFC 7162 §3.2.5 — QRESYNC implicitly engages CONDSTORE.
        // The client signals it can consume `* VANISHED (EARLIER)`
        // responses on SELECT / EXAMINE + post-EXPUNGE; the listener
        // flips both flags and the SELECT handler honours the
        // QRESYNC parameter list when present.
        if (!state.enabledQResync) {
          state.enabledQResync   = true;
          state.enabledCondStore = true;
          enabled.push("QRESYNC");
        }
      }
    }
    _writeUntagged(socket, "ENABLED" + (enabled.length ? " " + enabled.join(" ") : ""));
    _writeTagged(socket, tag, "OK ENABLE completed");
  }

  // RFC 5465 NOTIFY — `NOTIFY SET [STATUS] (<filter-set> (<event>...))*`
  // / `NOTIFY NONE`. Subscribes the connection to mailbox / message
  // events on a filter set. Actual event emission is operator-side
  // (the backend's `subscribeNotify(actor, spec, emitFn)` hook); this
  // handler stores the parsed subscription on `state.notifySpec` so
  // the backend can read it on later mutations. NOTIFY NONE clears.
  function _handleNotify(state, socket, tag, args) {
    if (!_requireAuth(state, socket, tag)) return;
    var raw = (args || "").trim();
    if (/^NONE\b/i.test(raw)) {
      state.notifySpec = null;
      if (typeof mailStore.subscribeNotify === "function") {
        try { mailStore.subscribeNotify(state.actor, null, null); }
        catch (_e) { /* drop-silent — operator hook may refuse mid-life */ }
      }
      _writeTagged(socket, tag, "OK NOTIFY completed");
      return;
    }
    var setMatch = raw.match(/^SET\s+(?:STATUS\s+)?(.+)$/i);                                          // allow:regex-no-length-cap — args length already capped upstream
    if (!setMatch) {
      _writeTagged(socket, tag, "BAD NOTIFY syntax (RFC 5465 §6)");
      return;
    }
    // Store the spec verbatim; the backend parses the filter-set
    // vocabulary (`SELECTED`, `SELECTED-DELAYED`, `INBOXES`,
    // `PERSONAL`, `SUBSCRIBED`, `MAILBOXES <list>`, `SUBTREE <list>`)
    // since the event semantics live there. The listener's job is to
    // hand the wire string to the backend.
    state.notifySpec = setMatch[1];
    if (typeof mailStore.subscribeNotify === "function") {
      return Promise.resolve()
        .then(function () {
          return mailStore.subscribeNotify(state.actor, state.notifySpec, function (event) {
            // Backend pushes events as { kind, mailbox, payload }; we
            // emit them as untagged responses on the same connection.
            if (!event || typeof event.kind !== "string") return;
            try {
              if (event.kind === "STATUS") {
                _writeUntagged(socket, "STATUS " + event.payload);
              } else if (event.kind === "LIST") {
                _writeUntagged(socket, "LIST " + event.payload);
              } else if (event.kind === "FETCH") {
                _writeUntagged(socket, _fetchResponse(event.seq || "", event.payload));
              }
            } catch (_e) { /* drop-silent — socket may already be closed */ }
          });
        })
        .then(function () { _writeTagged(socket, tag, "OK NOTIFY completed"); })
        .catch(function (err) {
          _writeTagged(socket, tag, "NO " + ((err && err.message) || "NOTIFY refused").slice(0, ERR_CLAMP));
        });
    }
    // Backend doesn't expose the subscribe hook — accept the wire
    // command but emit no events. RFC 5465 §6 says NO is the right
    // refusal shape when the server cannot fulfil the subscription.
    _writeTagged(socket, tag, "NO NOTIFY backend not configured");
  }

  // RFC 5464 §4.1 GETMETADATA — `GETMETADATA [opts] mailbox entries`.
  // `mailbox` may be `""` for server-wide annotations (METADATA-SERVER).
  // Entries are slash-prefixed names (`/private/foo` / `/shared/bar`).
  // Backend hook: `mailStore.getMetadata(actor, mailbox, names) →
  // [{ entry, value }]`.
  function _handleGetMetadata(state, socket, tag, args) {
    if (!_requireAuth(state, socket, tag)) return;
    if (typeof mailStore.getMetadata !== "function") {
      _writeTagged(socket, tag, "NO GETMETADATA backend not configured");
      return;
    }
    // Strip optional MAXSIZE / DEPTH opts: GETMETADATA (MAXSIZE 1024) "" ("/foo")
    var rest = (args || "").trim();
    var opts = {};
    var optsMatch = rest.match(/^\(([^)]+)\)\s+(.+)$/);                                                // allow:regex-no-length-cap — args length already capped upstream
    if (optsMatch) {
      var optBody = optsMatch[1];
      var maxMatch = optBody.match(/MAXSIZE\s+(\d+)/i);                                                // allow:regex-no-length-cap — optBody bounded by parens
      if (maxMatch) opts.maxSize = parseInt(maxMatch[1], 10);
      var depthMatch = optBody.match(/DEPTH\s+(\w+)/i);                                                // allow:regex-no-length-cap — optBody bounded
      if (depthMatch) opts.depth = depthMatch[1];
      rest = optsMatch[2];
    }
    var partsMatch = rest.match(/^(\S+|"[^"]*")\s+(\(([^)]+)\)|(\/\S+))$/);                            // allow:regex-no-length-cap — args length already capped upstream
    if (!partsMatch) {
      _writeTagged(socket, tag, "BAD GETMETADATA syntax (RFC 5464 §4.1)");
      return;
    }
    var mailbox = _unquote(partsMatch[1]);
    var entries = partsMatch[3]
      ? partsMatch[3].split(/\s+/).filter(Boolean)
      : [partsMatch[4]];
    if (mailbox !== "" && !_validateMailboxName(mailbox, { allowLegacyMUtf7: allowLegacyMUtf7 })) {
      _writeTagged(socket, tag, "BAD Mailbox name refused");
      return;
    }
    return Promise.resolve()
      .then(function () { return mailStore.getMetadata(state.actor, mailbox, entries, opts); })
      .then(function (rows) {
        if (Array.isArray(rows) && rows.length > 0) {
          var pairs = rows.map(function (r) {
            var v = r.value === null || r.value === undefined ? "NIL" : safeBuffer.quoteString(r.value);
            return r.entry + " " + v;
          }).join(" ");
          _writeUntagged(socket, "METADATA " + (mailbox === "" ? '""' : mailbox) + " (" + pairs + ")");
        }
        _writeTagged(socket, tag, "OK GETMETADATA completed");
      })
      .catch(function (err) {
        _writeTagged(socket, tag, "NO " + ((err && err.message) || "GETMETADATA failed").slice(0, ERR_CLAMP));
      });
  }

  // RFC 5464 §4.3 SETMETADATA — `SETMETADATA mailbox (entry value ...)`.
  // Setting `value = NIL` clears the entry. Backend hook:
  // `mailStore.setMetadata(actor, mailbox, entries)`. The wire format
  // delivers each value as a quoted-string or NIL atom; the parser
  // here handles the simple single-line shape (no literals across
  // SETMETADATA — operators using >1 KiB metadata go through APPEND).
  function _handleSetMetadata(state, socket, tag, args, _literalBody) {
    if (!_requireAuth(state, socket, tag)) return;
    if (typeof mailStore.setMetadata !== "function") {
      _writeTagged(socket, tag, "NO SETMETADATA backend not configured");
      return;
    }
    var match = (args || "").trim().match(/^(\S+|"[^"]*")\s+\((.+)\)$/);                              // allow:regex-no-length-cap — args length already capped upstream
    if (!match) {
      _writeTagged(socket, tag, "BAD SETMETADATA syntax (RFC 5464 §4.3)");
      return;
    }
    var mailbox = _unquote(match[1]);
    var body = match[2];
    if (mailbox !== "" && !_validateMailboxName(mailbox, { allowLegacyMUtf7: allowLegacyMUtf7 })) {
      _writeTagged(socket, tag, "BAD Mailbox name refused");
      return;
    }
    // Tokenise `<entry> <value> <entry> <value> ...`. Values are
    // `"..."` quoted-string OR `NIL`. Entries are `/private/...` /
    // `/shared/...` slash-prefixed names.
    var entries = [];
    var i = 0;
    while (i < body.length) {
      while (i < body.length && /\s/.test(body[i])) i++;
      if (i >= body.length) break;
      var entryStart = i;
      while (i < body.length && !/\s/.test(body[i])) i++;
      var entryName = body.slice(entryStart, i);
      while (i < body.length && /\s/.test(body[i])) i++;
      if (i >= body.length) {
        _writeTagged(socket, tag, "BAD SETMETADATA entry '" + entryName + "' missing value");
        return;
      }
      var valStart = i;
      var value;
      if (body[i] === '"') {
        i++;
        var v = "";
        while (i < body.length && body[i] !== '"') {
          if (body[i] === "\\" && i + 1 < body.length) { v += body[i + 1]; i += 2; }
          else { v += body[i]; i++; }
        }
        if (body[i] !== '"') {
          _writeTagged(socket, tag, "BAD SETMETADATA unterminated quoted value");
          return;
        }
        i++;
        value = v;
      } else {
        while (i < body.length && !/\s/.test(body[i])) i++;
        var tok = body.slice(valStart, i);
        value = tok.toUpperCase() === "NIL" ? null : tok;
      }
      entries.push({ entry: entryName, value: value });
    }
    if (entries.length === 0) {
      _writeTagged(socket, tag, "BAD SETMETADATA empty entry list");
      return;
    }
    return Promise.resolve()
      .then(function () { return mailStore.setMetadata(state.actor, mailbox, entries); })
      .then(function () { _writeTagged(socket, tag, "OK SETMETADATA completed"); })
      .catch(function (err) {
        _writeTagged(socket, tag, "NO " + ((err && err.message) || "SETMETADATA failed").slice(0, ERR_CLAMP));
      });
  }

  function _handleCapability(state, socket, tag) {
    _writeUntagged(socket, "CAPABILITY " + _capabilityLine(state));
    _writeTagged(socket, tag, "OK CAPABILITY completed");
  }

  function _handleId(state, socket, tag, args) {
    // RFC 2971 — clients send a key/value list, server replies with
    // its own. We accept anything (validator caps line size) and reply
    // with a minimal identifier.
    void args;
    _writeUntagged(socket, "ID (\"name\" \"blamejs\" \"version\" \"" + pkgVersion + "\")");
    _writeTagged(socket, tag, "OK ID completed");
  }

  function _handleLogout(state, socket, tag) {
    _writeUntagged(socket, "BYE Logging out");
    _writeTagged(socket, tag, "OK LOGOUT completed");
    _close(socket, state);
  }

  function _handleStartTls(state, socket, tag) {
    // RFC 8314 §3.3 — the command has no meaning on a port that is TLS from
    // the first byte, and naming the port tells an operator which it is rather
    // than leaving "already negotiated" to read as a client bug.
    if (implicitTls) {
      _writeTagged(socket, tag, "BAD STARTTLS not available on implicit-TLS port (RFC 8314)");
      return;
    }
    if (state.tls) {
      _writeTagged(socket, tag, "BAD TLS already negotiated");
      return;
    }
    _writeTagged(socket, tag, "OK Begin TLS negotiation now");
    // Drain EVERY pre-handshake state field that could carry attacker-
    // controlled bytes past the upgrade boundary (RFC 9051 §11.1 /
    // CVE-2021-33515 class STARTTLS-injection defense):
    //   - lineBuffer:    unparsed bytes pipelined before the handshake.
    //   - pendingLiteral: half-collected APPEND/AUTHENTICATE literal
    //     bytes; if not cleared, the literal completes after upgrade
    //     using bytes the peer sent in plaintext.
    //   - authPending:   the AUTHENTICATE step token; a dangling token
    //     would let the post-TLS state machine resume an exchange that
    //     started in plaintext, conflating cleartext + TLS-protected
    //     phases of the same SASL run.
    // The pre-handshake state-drain (lineBuffer + pendingLiteral +
    // authPending), listener-removal, idle-timeout re-arm, and the
    // post-handshake read-pump live in the shared upgradeLineProtocol
    // helper (b.mail.server.tls.upgradeLineProtocol).
    mailServerTls.upgradeLineProtocol({
      state:         state,
      socket:        socket,
      secureContext: opts.tlsContext,
      idleTimeoutMs: idleTimeoutMs,
      clearFields:   ["pendingLiteral", "authPending"],
      drain:         _drainBuffer,
      onError: function (err) {
        _emit("mail.server.imap.tls_handshake_failed",
          { connectionId: state.id, error: (err && err.message) || String(err) }, "failure");
        _close(socket, state);
      },
      onTimeout: function (tlsSocket) {
        _writeUntagged(tlsSocket, "BYE Idle timeout");
        _close(tlsSocket, state);
      },
    });
  }

  function _handleAuthenticate(state, socket, tag, args) {
    if (state.actor) {
      _writeTagged(socket, tag, "BAD Already authenticated");
      return;
    }
    if (!state.tls && profile !== "permissive") {
      _writeTagged(socket, tag, "BAD AUTHENTICATE requires TLS (use STARTTLS first)");
      return;
    }
    if (!authConfig || typeof authConfig.verify !== "function") {
      _writeTagged(socket, tag, "NO AUTHENTICATE not configured on this listener");
      return;
    }
    var authAdmit = rateLimit.checkAuthAdmit(state.remoteAddress);
    if (!authAdmit.ok) {
      _emit("mail.server.imap.auth_rate_limit_refused",
        { connectionId: state.id, remoteAddress: state.remoteAddress, reason: authAdmit.reason },
        "denied");
      _writeTagged(socket, tag, "NO [ALERT] Too many AUTH failures from your IP");
      _close(socket, state);
      return;
    }
    var mechName = args.split(" ")[0].toUpperCase();
    var initialResp = args.indexOf(" ") === -1 ? null : args.slice(args.indexOf(" ") + 1).trim();
    var mechanisms = (authConfig.mechanisms || ["PLAIN", "LOGIN"]).map(function (m) {
      return String(m).toUpperCase();
    });
    if (mechanisms.indexOf(mechName) === -1) {
      _writeTagged(socket, tag, "NO Mechanism '" + mechName + "' not advertised");
      return;
    }
    _emit("mail.server.imap.auth_attempt",
      { connectionId: state.id, mechanism: mechName, remoteAddress: state.remoteAddress });
    state.authPending = { mech: mechName, tag: tag, step: 0 };
    return _runAuthStep(state, socket, initialResp);
  }

  function _runAuthStep(state, socket, clientResp) {
    var pending = state.authPending;
    function _fail(reason, outcome, reply) {
      var failTag = pending.tag;
      state.authPending = null;
      rateLimit.noteAuthFailure(state.remoteAddress);
      _emit("mail.server.imap.auth_failed",
        { connectionId: state.id, mechanism: pending.mech, reason: reason }, outcome);
      _writeTagged(socket, failTag, reply);
    }
    return mailServerNet.runSaslStep({
      exchange:       pending,
      verify:         authConfig.verify,
      credentials:    { tls: state.tls, remoteAddress: state.remoteAddress },
      clientResponse: clientResp,
      // Server-side challenge — `+ <base64>` per RFC 9051 §6.2.2.
      writeChallenge: function (ch) { return _writeContinuation(socket, ch); },
      onChallengeUnsafe: function () {
        _fail("challenge-contains-line-terminator", "denied", "NO Authentication failed");
      },
      onSuccess: function (result) {
        state.actor = result.actor;
        state.stage = "authenticated";
        var savedTag = pending.tag;
        state.authPending = null;
        _emit("mail.server.imap.auth_success",
          { connectionId: state.id, mechanism: pending.mech,
            tenantId: result.actor.tenantId || null });
        _writeTagged(socket, savedTag,
          "OK [CAPABILITY " + _capabilityLine(state) + "] AUTHENTICATE completed");
      },
      onFailure: function (result) {
        _fail((result && result.reason) || "verify-returned-fail", "denied",
              "NO Authentication credentials invalid");
      },
      onError: function (err) {
        _fail((err && err.message) || String(err), "failure", "NO Authentication failed");
      },
    });
  }

  function _handleLogin(state, socket, tag, args, literalBody) {
    // RFC 9051 §6.3.4 — LOGIN is deprecated; new MUAs use AUTHENTICATE.
    if (state.actor) {
      _writeTagged(socket, tag, "BAD Already authenticated");
      return;
    }
    if (profile === "strict") {
      _writeTagged(socket, tag, "BAD LOGIN deprecated under strict profile; use AUTHENTICATE");
      return;
    }
    if (!state.tls && profile !== "permissive") {
      _writeTagged(socket, tag, "BAD LOGIN requires TLS (use STARTTLS first)");
      return;
    }
    if (!authConfig || typeof authConfig.verify !== "function") {
      _writeTagged(socket, tag, "NO AUTH not configured");
      return;
    }
    var authAdmit = rateLimit.checkAuthAdmit(state.remoteAddress);
    if (!authAdmit.ok) {
      _writeTagged(socket, tag, "NO [ALERT] Too many AUTH failures from your IP");
      _close(socket, state);
      return;
    }
    // LOGIN args: `user pass` (quoted or atom).
    var parts = _parseLoginArgs(args, literalBody);
    if (!parts) {
      _writeTagged(socket, tag, "BAD LOGIN expects user + pass");
      return;
    }
    // Returned, so the reader waits for it: the next command must not be
    // dispatched against a session that is still authenticating.
    return Promise.resolve()
      .then(function () {
        return authConfig.verify("LOGIN", {
          step: 0,
          username:       parts[0],
          password:       parts[1],
          tls:            state.tls,
          remoteAddress:  state.remoteAddress,
        });
      })
      .then(function (result) {
        if (result && result.ok && result.actor) {
          state.actor = result.actor;
          state.stage = "authenticated";
          _emit("mail.server.imap.auth_success",
            { connectionId: state.id, mechanism: "LOGIN", tenantId: result.actor.tenantId || null });
          _writeTagged(socket, tag, "OK [CAPABILITY " + _capabilityLine(state) + "] LOGIN completed");
          return;
        }
        rateLimit.noteAuthFailure(state.remoteAddress);
        _emit("mail.server.imap.auth_failed",
          { connectionId: state.id, mechanism: "LOGIN", reason: "verify-returned-fail" }, "denied");
        _writeTagged(socket, tag, "NO LOGIN credentials invalid");
      })
      .catch(function () {
        rateLimit.noteAuthFailure(state.remoteAddress);
        _writeTagged(socket, tag, "NO LOGIN failed");
      });
  }

  function _parseLoginArgs(args, trailingLiteral) {
    if (typeof args !== "string") return null;
    // Quoted or atom — RFC 9051 §5.1 quoted ABNF. Inside a quoted
    // string `\"` and `\\` are escape sequences for `"` and `\`
    // respectively; any other `\<chr>` is invalid. The earlier shape
    // terminated the quoted string at the first `"`, so a hostile
    // client passing `LOGIN "alice\"@example.com" "pw"` would have
    // its username truncated at `alice` and the rest of the line
    // reparsed as the password / literal — wrong identity bound to
    // the AUTH state.
    var rest = args.trim();
    function _take() {
      if (rest[0] === "\"") {
        // Walk the quoted-string body, accumulating into `out` while
        // honoring the `\"` / `\\` escape pairs. A bare `\` followed
        // by any other character is refused (parse fails → null).
        var out = "";
        var i = 1;
        while (i < rest.length) {
          var ch = rest.charAt(i);
          if (ch === "\\") {
            var esc = rest.charAt(i + 1);
            if (esc !== "\"" && esc !== "\\") return null;
            out += esc;
            i += 2;
            continue;
          }
          if (ch === "\"") {
            rest = rest.slice(i + 1).trim();
            return out;
          }
          out += ch;
          i += 1;
        }
        return null;   // unterminated quoted string
      }
      var sp = rest.indexOf(" ");
      var v2 = sp === -1 ? rest : rest.slice(0, sp);
      rest = sp === -1 ? "" : rest.slice(sp + 1).trim();
      return v2;
    }
    var user = _take(); if (user === null) return null;
    // A trailing literal IS the second astring. RFC 9051 §4.3 allows either
    // LOGIN argument to arrive as one, and the reader strips the `{N}` opener
    // from the line before the handler sees it, so the payload is all that is
    // left of the password. It is taken verbatim rather than re-quoted: a
    // literal is what a client sends precisely when the value cannot be
    // expressed as a quoted string, so quoting it back would refuse the
    // passwords this path exists to carry.
    //
    // Only the trailing one. `LOGIN {5}` with the username as a literal is a
    // two-literal command, which the reader does not assemble, and it fails
    // the same way it did before rather than silently binding a wrong identity.
    if (trailingLiteral != null) {
      if (rest.trim() !== "") return null;   // both a literal and an inline password
      return [user, String(trailingLiteral)];
    }
    var pass = _take(); if (pass === null) return null;
    return [user, pass];
  }

  function _requireAuth(state, socket, tag) {
    if (!state.actor) {
      _writeTagged(socket, tag, "NO Login first");
      return false;
    }
    return true;
  }

  function _handleSelect(state, socket, tag, args, examine) {
    if (!_requireAuth(state, socket, tag)) return;
    var trimmed = (args || "").trim();
    // RFC 7162 §3.2.4 — `SELECT mailbox (QRESYNC (<uidvalidity>
    // <modseq> [<knownUids>] [<knownSequenceMatchData>]))`. The
    // QRESYNC parameter is wrapped in an outer parenthesis pair after
    // the mailbox name. Extract it before parsing the mailbox so the
    // mailbox-name validator sees just the name.
    var qresyncParam = null;
    var qresyncMatch = trimmed.match(/^(\S+|"[^"]+")\s+\(\s*QRESYNC\s*\(\s*([^)]+)\)\s*(?:\(\s*([^)]+)\)\s*)?\)\s*$/i);  // allow:regex-no-length-cap — args length already capped upstream
    if (qresyncMatch) {
      var inner = qresyncMatch[2].trim().split(/\s+/);
      qresyncParam = {
        uidvalidity: parseInt(inner[0], 10),
        modseq:      parseInt(inner[1], 10),
        knownUids:   inner[2] || null,
        knownSeq:    qresyncMatch[3] || null,
      };
      if (!isFinite(qresyncParam.uidvalidity) || !isFinite(qresyncParam.modseq)) {
        _writeTagged(socket, tag, "BAD SELECT QRESYNC params must be (<uidvalidity> <modseq> ...) numerics");
        return;
      }
      trimmed = qresyncMatch[1];
    }
    var name = _unquote(trimmed);
    if (!_validateMailboxName(name, { allowLegacyMUtf7: allowLegacyMUtf7 })) {
      _writeTagged(socket, tag, "BAD Mailbox name refused");
      return;
    }
    // QRESYNC requires CONDSTORE to be engaged; if the client sent
    // the parameter without having issued ENABLE first, RFC 7162
    // §3.2.4 lets the server flip the flags implicitly.
    if (qresyncParam && !state.enabledQResync) {
      state.enabledQResync   = true;
      state.enabledCondStore = true;
    }
    return Promise.resolve()
      .then(function () {
        if (typeof mailStore.selectFolder === "function") {
          return mailStore.selectFolder(state.actor, name, {
            readOnly:    examine,
            qresync:     qresyncParam,
          });
        }
        // RFC 9051 §2.3.1.1 — UIDVALIDITY MUST be strictly increasing
        // and 32-bit unique across the mailbox lifetime. The earlier
        // fallback returned a sentinel `uidvalidity: 1` to keep tests
        // green when the operator hadn't wired `selectFolder`, but the
        // sentinel value collides with any real UIDVALIDITY=1 from a
        // legitimate backend and tricks clients into believing they
        // have a valid synced state. Refuse SELECT instead — operators
        // MUST wire `mailStore.selectFolder` to expose mailboxes.
        var err = new Error("mailStore.selectFolder is not configured (RFC 9051 §2.3.1.1 requires a unique strictly-increasing UIDVALIDITY)");
        err.code = "mail-server-imap/no-select-backend";
        throw err;
      })
      .then(function (info) {
        state.selectedMailbox = name;
        state.selectedReadOnly = !!examine;
        state.stage = "selected";
        var flagsStr = (info.flags && info.flags.length) ? info.flags.join(" ") : "\\Seen \\Answered \\Flagged \\Deleted \\Draft";
        _writeUntagged(socket, info.exists + " EXISTS");
        _writeUntagged(socket, info.recent + " RECENT");
        _writeUntagged(socket, "FLAGS (" + flagsStr + ")");
        _writeUntagged(socket, "OK [UIDVALIDITY " + info.uidvalidity + "] UIDs valid");
        _writeUntagged(socket, "OK [UIDNEXT " + info.uidnext + "] Predicted next UID");
        if (info.modseq !== undefined) {
          _writeUntagged(socket, "OK [HIGHESTMODSEQ " + info.modseq + "]");
        }
        // RFC 7162 §3.2.5 — when SELECT carried a QRESYNC parameter
        // AND the client's UIDVALIDITY matches, emit a single
        // `* VANISHED (EARLIER) <uid-set>` listing UIDs the server
        // expunged since the client's snapshot. The backend supplies
        // this via `info.vanishedEarlier` (sequence-set string) — the
        // listener does the wire emission. Mismatched UIDVALIDITY
        // means the client's cache is stale and MUST re-SELECT; we
        // skip the VANISHED line in that case so the client falls
        // through to a full re-sync. RFC 7162 §3.2.5.2 says the
        // server MAY also include changed-since-modseq FETCH lines
        // — those flow through the normal FETCH path with
        // CHANGEDSINCE so we leave them to the operator.
        if (qresyncParam && info.vanishedEarlier &&
            info.uidvalidity === qresyncParam.uidvalidity) {
          _writeUntagged(socket, "VANISHED (EARLIER) " + info.vanishedEarlier);
        }
        _emit("mail.server.imap.select", {
          connectionId: state.id, mailbox: name,
          modseq: info.modseq || 0, exists: info.exists,
          qresync: qresyncParam !== null,
        });
        _writeTagged(socket, tag, "OK [" + (examine ? "READ-ONLY" : "READ-WRITE") + "] " +
          (examine ? "EXAMINE" : "SELECT") + " completed");
      })
      .catch(function (err) {
        _writeTagged(socket, tag, "NO " + ((err && err.message) || "Select failed").slice(0, ERR_CLAMP));
      });
  }

  function _handleList(state, socket, tag, args) {
    if (!_requireAuth(state, socket, tag)) return;
    // RFC 9051 §6.3.9 — LIST reference mailbox-pattern. Minimal
    // implementation delegates to mailStore.listFolders if present.
    void args;
    return Promise.resolve()
      .then(function () {
        if (typeof mailStore.listFolders === "function") {
          return mailStore.listFolders(state.actor);
        }
        return [{ name: "INBOX", attributes: [] }];
      })
      .then(function (folders) {
        for (var i = 0; i < folders.length; i += 1) {
          var f = folders[i];
          var attrs = (f.attributes || []).map(function (a) { return "\\" + a; }).join(" ");
          _writeUntagged(socket, "LIST (" + attrs + ") \"/\" " + safeBuffer.quoteString(f.name));
        }
        _writeTagged(socket, tag, "OK LIST completed");
      })
      .catch(function (err) {
        _writeTagged(socket, tag, "NO " + ((err && err.message) || "List failed").slice(0, ERR_CLAMP));
      });
  }

  function _handleStatus(state, socket, tag, args) {
    if (!_requireAuth(state, socket, tag)) return;
    var match = args.match(/^(\S+|"[^"]+")\s+\(([^)]+)\)$/);                                          // allow:regex-no-length-cap — args length already capped upstream
    if (!match) {
      _writeTagged(socket, tag, "BAD STATUS expects mailbox + paren-list of items");
      return;
    }
    var name = _unquote(match[1]);
    var items = match[2].split(/\s+/);
    if (!_validateMailboxName(name, { allowLegacyMUtf7: allowLegacyMUtf7 })) {
      _writeTagged(socket, tag, "BAD Mailbox name refused");
      return;
    }
    return Promise.resolve()
      .then(function () {
        if (typeof mailStore.statusFolder === "function") {
          return mailStore.statusFolder(state.actor, name, items);
        }
        return { MESSAGES: 0, UIDNEXT: 1, UIDVALIDITY: 1, UNSEEN: 0 };
      })
      .then(function (info) {
        var parts = [];
        for (var k = 0; k < items.length; k += 1) {
          var key = items[k].toUpperCase();
          if (info[key] !== undefined) parts.push(key + " " + info[key]);
        }
        _writeUntagged(socket, "STATUS " + safeBuffer.quoteString(name) + " (" + parts.join(" ") + ")");
        _writeTagged(socket, tag, "OK STATUS completed");
      })
      .catch(function (err) {
        _writeTagged(socket, tag, "NO " + ((err && err.message) || "Status failed").slice(0, ERR_CLAMP));
      });
  }

  function _handleAppend(state, socket, tag, args, literalBody) {
    if (!_requireAuth(state, socket, tag)) return;
    // RFC 4469 CATENATE — `APPEND mailbox [(flags)] [date-time] CATENATE
    // (TEXT {literal} URL "imap://...")`. The CATENATE keyword turns the
    // command body into a list of parts the server stitches into a
    // single message; backends supply the `appendCatenate(actor,
    // mailbox, parts, opts) → meta` hook. Without CATENATE, fall
    // through to the bare APPEND path that already exists.
    var catenateMatch = args.match(/^(\S+|"[^"]+")(?:\s+\(([^)]*)\))?(?:\s+("[^"]+"))?\s+CATENATE\s+(.+)$/i);   // allow:regex-no-length-cap — args length already capped upstream
    if (catenateMatch) {
      if (typeof mailStore.appendCatenate !== "function") {
        _writeTagged(socket, tag, "NO CATENATE backend not configured");
        return;
      }
      var catMailbox = _unquote(catenateMatch[1]);
      var catFlags = catenateMatch[2] ? catenateMatch[2].split(/\s+/).filter(Boolean) : [];
      var catDateArg = catenateMatch[3] ? _unquote(catenateMatch[3]) : null;
      var catInternalDate = null;
      if (catDateArg) {
        catInternalDate = _parseImapDateTime(catDateArg);
        if (catInternalDate === null) {
          _writeTagged(socket, tag, "BAD APPEND CATENATE date-time invalid");
          return;
        }
      }
      if (!_validateMailboxName(catMailbox, { allowLegacyMUtf7: allowLegacyMUtf7 })) {
        _writeTagged(socket, tag, "BAD Mailbox name refused");
        return;
      }
      // Validate the parens are well-formed BEFORE we touch the
      // backend. The wire-format parts list MUST start with `(` and
      // end with `)`; a truncated list (e.g. `(TEXT {3}` arriving as
      // a single literal-completion before the rest of the parts
      // streams in) is refused. Order-preserving left-to-right token
      // walk replaces the prior URL-then-TEXT split — CATENATE
      // semantics depend on the SEQUENCE of parts.
      var partsBodyRaw = catenateMatch[4];
      if (partsBodyRaw[0] !== "(" || partsBodyRaw[partsBodyRaw.length - 1] !== ")") {
        _writeTagged(socket, tag, "BAD APPEND CATENATE parts list missing parens (RFC 4469 §3)");
        return;
      }
      var partsBody = partsBodyRaw.slice(1, -1);
      var parts = [];
      var hadTextPart = false;
      // Tokenise sequentially. Each part is one of:
      //   URL "imap://..."
      //   TEXT {<n>}   (literal — multi-literal CATENATE deferred to a
      //                 later slice; defer-with-condition: refused
      //                 with NO until the multi-literal protocol path
      //                 lands).
      var pi = 0;
      while (pi < partsBody.length) {
        while (pi < partsBody.length && /\s/.test(partsBody[pi])) pi += 1;
        if (pi >= partsBody.length) break;
        if (/^URL\b/i.test(partsBody.slice(pi))) {
          pi += 3;                                                                                     // length of literal "URL" keyword
          while (pi < partsBody.length && /\s/.test(partsBody[pi])) pi += 1;
          if (partsBody[pi] !== "\"") {
            _writeTagged(socket, tag, "BAD APPEND CATENATE URL value must be quoted-string");
            return;
          }
          pi += 1;
          var urlStart = pi;
          while (pi < partsBody.length && partsBody[pi] !== "\"") pi += 1;
          if (partsBody[pi] !== "\"") {
            _writeTagged(socket, tag, "BAD APPEND CATENATE URL value unterminated quoted-string");
            return;
          }
          parts.push({ kind: "URL", url: partsBody.slice(urlStart, pi) });
          pi += 1;
        } else if (/^TEXT\b/i.test(partsBody.slice(pi))) {
          hadTextPart = true;
          break;
        } else {
          _writeTagged(socket, tag, "BAD APPEND CATENATE unknown part (RFC 4469 §3 only URL/TEXT)");
          return;
        }
      }
      if (hadTextPart) {
        // Multi-literal CATENATE TEXT parts need a streaming-literal
        // protocol path the listener doesn't currently expose. RFC
        // 4469 §3 explicitly permits servers to refuse parts they
        // can't honour; refusing is correct (better than reordering
        // and corrupting the message body the client requested).
        _writeTagged(socket, tag, "NO CATENATE TEXT-literal parts not yet implemented; use APPEND with a single literal");
        return;
      }
      if (parts.length === 0) {
        _writeTagged(socket, tag, "BAD APPEND CATENATE empty parts list");
        return;
      }
      return Promise.resolve()
        .then(function () {
          return mailStore.appendCatenate(catMailbox, parts, {
            actor: state.actor, flags: catFlags, internalDate: catInternalDate });
        })
        .then(function (meta) {
          var ok = "OK APPEND completed";
          if (meta && meta.uid && meta.uidValidity) {
            ok = "OK [APPENDUID " + meta.uidValidity + " " + meta.uid + "] APPEND completed";
          }
          _writeTagged(socket, tag, ok);
        })
        .catch(function (err) {
          _writeTagged(socket, tag, "NO " + ((err && err.message) || "CATENATE failed").slice(0, ERR_CLAMP));
        });
    }
    if (!literalBody) {
      _writeTagged(socket, tag, "BAD APPEND requires a literal {N} message");
      return;
    }
    // RFC 9051 §6.3.12 — APPEND mailbox [(flags)] [date-time] literal
    var match = args.match(/^(\S+|"[^"]+")(?:\s+\(([^)]*)\))?(?:\s+("[^"]+"))?$/);                    // allow:regex-no-length-cap — args length already capped upstream
    if (!match) {
      _writeTagged(socket, tag, "BAD APPEND syntax");
      return;
    }
    var name = _unquote(match[1]);
    var flags = match[2] ? match[2].split(/\s+/).filter(Boolean) : [];
    // RFC 9051 §6.3.12 — optional date-time argument sets INTERNALDATE
    // on the appended message. Earlier shape captured the token but
    // never threaded it; backends now receive it as `internalDate`
    // (ms-since-epoch) and the mail-store applies it instead of the
    // append-time clock. Refused as syntax error when the date-time
    // can't be parsed (rather than silently using the clock).
    var dateTimeArg = match[3] ? _unquote(match[3]) : null;
    var internalDate = null;
    if (dateTimeArg) {
      internalDate = _parseImapDateTime(dateTimeArg);
      if (internalDate === null) {
        _writeTagged(socket, tag, "BAD APPEND date-time '" + dateTimeArg +
          "' not in RFC 9051 §6.3.12 / RFC 5322 §3.3 date-time grammar");
        return;
      }
    }
    if (!_validateMailboxName(name, { allowLegacyMUtf7: allowLegacyMUtf7 })) {
      _writeTagged(socket, tag, "BAD Mailbox name refused");
      return;
    }
    return Promise.resolve()
      .then(function () {
        // RFC 9208 — when the backend exposes a per-mailbox / per-user
        // quota, APPEND MUST check against it BEFORE writing the
        // message. The earlier shape called `appendMessage` directly,
        // leaving quota enforcement entirely up to the backend; an
        // operator wiring a bare `appendMessage` without quota plumbing
        // could be DoS'd via unbounded APPENDs filling the mailbox
        // beyond the advertised QUOTA limit. Honor `mailStore.quota`
        // (RFC 9208 GETQUOTA / IMAP-QUOTA returns the same shape) and
        // surface 5.7.4 OVERQUOTA per §5.
        if (typeof mailStore.quota === "function") {
          // mailStore.quota(folderName) returns
          // { usedBytes, usedCount, capBytes, capCount } per the
          // lib/mail-store.js contract. capBytes is null when no
          // quota is configured for the folder; honor it only when
          // it's a positive number.
          return Promise.resolve(mailStore.quota(name))
            .then(function (q) {
              if (q && typeof q.usedBytes === "number" &&
                  typeof q.capBytes === "number" &&
                  q.capBytes > 0 &&
                  q.usedBytes + safeBuffer.byteLengthOf(literalBody) > q.capBytes) {
                var err = new Error("APPEND would exceed quota (used " + q.usedBytes +
                  " + " + literalBody.length + " > cap " + q.capBytes + ")");
                err.code = "mail-server-imap/overquota";
                err.overquota = true;
                err.limit = q.capBytes;
                throw err;
              }
              return mailStore.appendMessage(name, literalBody, {
                actor: state.actor, flags: flags, internalDate: internalDate });
            });
        }
        return mailStore.appendMessage(name, literalBody, {
          actor: state.actor, flags: flags, internalDate: internalDate });
      })
      .then(function (info) {
        _emit("mail.server.imap.append",
          { connectionId: state.id, mailbox: name, size: literalBody.length, flags: flags });
        var token = info && info.uid ? "[APPENDUID " + (info.uidvalidity || 0) + " " + info.uid + "] " : "";
        _writeTagged(socket, tag, "OK " + token + "APPEND completed");
      })
      .catch(function (err) {
        if (err && err.overquota) {
          _writeTagged(socket, tag, "NO [OVERQUOTA] Quota exceeded (RFC 9208 §5)");
          return;
        }
        _writeTagged(socket, tag, "NO " + ((err && err.message) || "Append failed").slice(0, ERR_CLAMP));
      });
  }

  function _handleClose(state, socket, tag) {
    state.selectedMailbox = null;
    state.selectedReadOnly = false;
    state.stage = "authenticated";
    _writeTagged(socket, tag, "OK CLOSE completed");
  }

  function _handleExpunge(state, socket, tag) {
    if (!state.selectedMailbox) {
      _writeTagged(socket, tag, "NO No mailbox selected");
      return;
    }
    return Promise.resolve()
      .then(function () {
        if (typeof mailStore.expungeFolder === "function") {
          return mailStore.expungeFolder(state.actor, state.selectedMailbox);
        }
        return { expunged: [], modseq: 0 };
      })
      .then(function (info) {
        var ex = info.expunged || [];
        for (var i = 0; i < ex.length; i += 1) {
          _writeUntagged(socket, ex[i] + " EXPUNGE");
        }
        _emit("mail.server.imap.expunge",
          { connectionId: state.id, mailbox: state.selectedMailbox,
            count: ex.length, modseq: info.modseq || 0 });
        _writeTagged(socket, tag, "OK EXPUNGE completed");
      })
      .catch(function (err) {
        _writeTagged(socket, tag, "NO " + ((err && err.message) || "Expunge failed").slice(0, ERR_CLAMP));
      });
  }

  function _handleFetch(state, socket, tag, args, useUid) {
    if (!state.selectedMailbox) {
      // RFC 9051 §6.4.5 — FETCH outside of Selected state is a
      // protocol-context violation, not a server-policy refusal.
      // BAD signals the client to fix its dialog rather than retry.
      _writeTagged(socket, tag, "BAD FETCH only valid in Selected state (RFC 9051 §6.4.5)");
      return;
    }
    if (typeof mailStore.fetchRange !== "function") {
      _writeTagged(socket, tag, "BAD FETCH backend not configured");
      return;
    }
    var match = args.match(/^(\S+)\s+(.+)$/);                                                          // allow:regex-no-length-cap — args length already capped upstream
    if (!match) {
      _writeTagged(socket, tag, "BAD FETCH expects sequence-set + parts");
      return;
    }
    var seqSet = match[1];
    var partsSpec = match[2];
    // RFC 7162 §3.1.4 — FETCH may carry a CHANGEDSINCE modifier in a
    // trailing parenthesised list:
    //   FETCH 1:* (FLAGS) (CHANGEDSINCE 12345)
    // and/or VANISHED (QRESYNC) which is deferred to a later slice.
    // The modifier list is parsed off the END of partsSpec; what
    // remains is handed to the backend as the fetch-att spec.
    var changedSince = null;
    var includeVanished = false;
    var modMatch = _trailingParenGroup(partsSpec);
    if (modMatch && /\b(CHANGEDSINCE|VANISHED)\b/i.test(modMatch.body)) {
      var modBody = modMatch.body;
      var changedMatch = modBody.match(/CHANGEDSINCE\s+(\d+)/i);                                       // allow:regex-no-length-cap — modBody already bounded
      if (changedMatch) {
        var csN = parseInt(changedMatch[1], 10);
        if (isFinite(csN) && csN >= 0) changedSince = csN;
      }
      includeVanished = /\bVANISHED\b/i.test(modBody);
      partsSpec = partsSpec.slice(0, partsSpec.length - modMatch.matchLength).trim();
    }
    // RFC 7162 §3.1.2 — any FETCH that uses CHANGEDSINCE implicitly
    // engages CONDSTORE for the session; the client expects MODSEQ
    // in responses even without a prior `ENABLE CONDSTORE`. RFC 7162
    // §3.1.4.1 — when CONDSTORE is engaged (explicit ENABLE OR
    // implicit via CHANGEDSINCE) OR the client requested MODSEQ as a
    // fetch-att, every untagged FETCH response includes the MODSEQ
    // attribute. Engaging CONDSTORE via CHANGEDSINCE also sticks for
    // the rest of the session.
    if (changedSince !== null && !state.enabledCondStore) {
      state.enabledCondStore = true;
    }
    var includeModseq = state.enabledCondStore === true ||
                        changedSince !== null ||
                        /\bMODSEQ\b/i.test(partsSpec);
    return Promise.resolve()
      .then(function () {
        return mailStore.fetchRange(state.actor, state.selectedMailbox, seqSet, partsSpec,
          { useUid: useUid === true, changedSince: changedSince, includeVanished: includeVanished,
            includeModseq: includeModseq });
      })
      .then(function (rows) {
        var rs = rows || [];
        _emit("mail.server.imap.fetch_bulk",
          { connectionId: state.id, mailbox: state.selectedMailbox, count: rs.length,
            changedSince: changedSince, condStore: state.enabledCondStore === true });
        for (var i = 0; i < rs.length; i += 1) {
          var r = rs[i];
          var payload = r.payload || "";
          // A Buffer payload is the backend saying "these are the message's
          // own octets". It is assembled and written as octets end to end, so
          // the count in the literal header is the count that reaches the wire.
          // Concatenating it into a string instead re-encoded it as UTF-8, and
          // the response then announced one length and sent another.
          var octets = Buffer.isBuffer(payload);
          var asText = octets ? payload.toString("latin1") : String(payload);
          if (includeModseq && r.modseq !== undefined && !/MODSEQ\s*\(/.test(asText)) {
            var modseqAttr = (asText ? " " : "") + "MODSEQ (" + r.modseq + ")";
            payload = octets
              ? Buffer.concat([payload, Buffer.from(modseqAttr, "latin1")])
              : asText + modseqAttr;
          }
          _writeUntagged(socket, _fetchResponse(r.seq, payload));
        }
        _writeTagged(socket, tag, "OK FETCH completed");
      })
      .catch(function (err) {
        _writeTagged(socket, tag, "NO " + ((err && err.message) || "Fetch failed").slice(0, ERR_CLAMP));
      });
  }

  function _handleStore(state, socket, tag, args, useUid) {
    if (!state.selectedMailbox) {
      // RFC 9051 §6.4.6 — STORE outside of Selected state is a
      // protocol-context violation. BAD (not NO) is the correct
      // response per the IMAP grammar; UID STORE has the same rule
      // since the verb is just a `UID` prefix on STORE.
      _writeTagged(socket, tag, "BAD STORE only valid in Selected state (RFC 9051 §6.4.6)");
      return;
    }
    if (state.selectedReadOnly) {
      _writeTagged(socket, tag, "NO Mailbox is read-only");
      return;
    }
    if (typeof mailStore.storeFlags !== "function") {
      _writeTagged(socket, tag, "BAD STORE backend not configured");
      return;
    }
    // RFC 7162 §3.1.3 — STORE may carry a parenthesised UNCHANGEDSINCE
    // modifier between the sequence-set and the FLAGS op:
    //   STORE 1:* (UNCHANGEDSINCE 12345) +FLAGS (\Deleted)
    // The backend's response shape is { rows, modified } — `modified`
    // is the seq-set string of message ids whose modseq advanced past
    // unchangedSince before this STORE ran. We surface those via
    // [MODIFIED <set>] OK response (RFC 7162 §3.1.3).
    var unchangedSince = null;
    var unchangedMatch = args.match(/^(\S+)\s+\(UNCHANGEDSINCE\s+(\d+)\)\s+(.+)$/i);                   // allow:regex-no-length-cap — args length already capped upstream
    if (unchangedMatch) {
      var usN = parseInt(unchangedMatch[2], 10);
      if (isFinite(usN) && usN >= 0) unchangedSince = usN;
      args = unchangedMatch[1] + " " + unchangedMatch[3];
    }
    var match = args.match(/^(\S+)\s+([+-]?FLAGS(?:\.SILENT)?)\s+\(([^)]*)\)$/i);                     // allow:regex-no-length-cap — args length already capped upstream
    if (!match) {
      _writeTagged(socket, tag, "BAD STORE expects seq-set FLAGS (...)");
      return;
    }
    var seqSet = match[1];
    var op = match[2].toUpperCase();
    var flagsArr = match[3].split(/\s+/).filter(Boolean);
    var silent = /\.SILENT$/i.test(op);
    var mode = op[0] === "+" ? "add" : op[0] === "-" ? "remove" : "replace";
    // RFC 7162 §3.1.2 — UNCHANGEDSINCE in STORE engages CONDSTORE for
    // the session (same implicit-enable rule as FETCH CHANGEDSINCE).
    if (unchangedSince !== null && !state.enabledCondStore) {
      state.enabledCondStore = true;
    }
    var includeModseqStore = state.enabledCondStore === true || unchangedSince !== null;
    return Promise.resolve()
      .then(function () {
        return mailStore.storeFlags(state.actor, state.selectedMailbox, seqSet, mode, flagsArr,
          { useUid: useUid === true, unchangedSince: unchangedSince, includeModseq: includeModseqStore });
      })
      .then(function (result) {
        // Backend may return either an array of rows (legacy shape)
        // OR an object `{ rows, modified }`. Normalise.
        var rs, modifiedSet;
        if (Array.isArray(result)) { rs = result; modifiedSet = null; }
        else if (result && typeof result === "object") {
          rs = result.rows || [];
          modifiedSet = result.modified || null;
        } else { rs = []; modifiedSet = null; }
        // RFC 7162 §3.1.3 — under CONDSTORE / UNCHANGEDSINCE, the
        // server MUST emit a FETCH response carrying the new MODSEQ
        // for every successfully-updated message EVEN UNDER .SILENT.
        // Without it, CONDSTORE clients cannot refresh their local
        // modseq state and drift out of sync. Under non-CONDSTORE
        // .SILENT, the legacy behaviour stays (no untagged FETCH).
        var emitFlags = !silent;
        var emitModseqOnly = silent && includeModseqStore;
        if (emitFlags || emitModseqOnly) {
          for (var i = 0; i < rs.length; i += 1) {
            var r = rs[i];
            var payload;
            if (emitFlags) {
              payload = "FLAGS (" + (r.flags || []).join(" ") + ")";
              if (includeModseqStore && r.modseq !== undefined) {
                payload = payload + " MODSEQ (" + r.modseq + ")";
              }
            } else if (r.modseq !== undefined) {
              // SILENT + CONDSTORE — emit MODSEQ alone (no FLAGS).
              payload = "MODSEQ (" + r.modseq + ")";
            } else {
              continue;
            }
            _writeUntagged(socket, r.seq + " FETCH (" + payload + ")");
          }
        }
        var okTag = "OK STORE completed";
        // RFC 7162 §3.1.3 — MODIFIED carries the set of ids the
        // conditional STORE refused to update because their modseq
        // advanced past unchangedSince. Clients re-issue FETCH against
        // the set to refresh state before retry.
        if (modifiedSet && String(modifiedSet).length > 0) {
          okTag = "OK [MODIFIED " + modifiedSet + "] STORE completed";
        }
        _writeTagged(socket, tag, okTag);
      })
      .catch(function (err) {
        _writeTagged(socket, tag, "NO " + ((err && err.message) || "Store failed").slice(0, ERR_CLAMP));
      });
  }

  function _handleUid(state, socket, tag, args, literalBody) {
    // UID FETCH / UID STORE / UID SEARCH / UID COPY / UID MOVE per
    // RFC 9051 §6.4.9. The sub-command's sequence-set is interpreted
    // as UIDs (not message-sequence-numbers); we pass `useUid: true`
    // to the sub-handler which threads it through to the backend's
    // mailStore.fetchRange / storeFlags via opts. Without this, the
    // backend treats the seq-set as msg-numbers and a client's
    // `UID FETCH 12345 (BODY[])` returns the WRONG message.
    var sub = args.match(/^(\S+)\s+(.+)$/);                                                            // allow:regex-no-length-cap — args length already capped upstream
    if (!sub) {
      _writeTagged(socket, tag, "BAD UID expects a sub-command");
      return;
    }
    var subVerb = sub[1].toUpperCase();
    var subArgs = sub[2];
    if (subVerb === "FETCH") return _handleFetch(state, socket, tag, subArgs, true);
    if (subVerb === "STORE") return _handleStore(state, socket, tag, subArgs, true);
    // Every other sub-command RFC 9051 §6.4.9 defines — SEARCH, COPY, MOVE,
    // EXPUNGE — goes back through the registry to the SAME entry the
    // unprefixed verb dispatches to, carrying `useUid` so the handler answers
    // in unique identifiers.
    //
    // The listener ships no search, copy or move of its own: those are
    // operator-domain, and the registry holds a "not configured" default that
    // a consumer replaces through `opts.overrides`. Dispatching the UID forms
    // here instead of through the registry made that seam reachable from one
    // side only — a consumer who supplied SEARCH got the sequence form served
    // and the UID form refused, and the only way to supply the UID form was to
    // replace the whole UID verb, taking the working UID FETCH and UID STORE
    // with it. A client that keeps a cross-session cache asks for the UID form
    // precisely because a sequence number does not survive the session, so the
    // refusal fell on the clients doing the durable thing.
    //
    // Going through the registry also keeps the tenant check, the guard
    // validation and the audit emission on the UID path, which a direct call
    // from here would have skipped.
    // An allowlist, not "whatever the registry holds". UID takes the five
    // sub-commands §6.4.9 names plus EXPUNGE from RFC 4315; sending anything
    // else through would dispatch a real handler that knows nothing about UIDs
    // — `UID SELECT INBOX` would select a mailbox, and `UID UID …` would
    // recurse.
    if (subVerb !== "SEARCH" && subVerb !== "COPY" &&
        subVerb !== "MOVE"   && subVerb !== "EXPUNGE") {
      _writeTagged(socket, tag, "BAD UID " + subVerb + " is not a UID sub-command");
      return;
    }
    // EXPUNGE is the one that cannot be forwarded blind. RFC 4315 §2.1 makes
    // `UID EXPUNGE <uid-set>` expunge ONLY the named messages, while the
    // listener's own EXPUNGE expunges every message flagged \Deleted and takes
    // no set at all. Forwarding to it would delete messages the client did not
    // name, which is worse than not answering. A consumer who supplies their
    // own EXPUNGE reads `useUid` and the set, so theirs can serve it.
    if (subVerb === "EXPUNGE" && _registry.source("EXPUNGE") !== "operator-override") {
      _writeTagged(socket, tag,
        "NO UID EXPUNGE needs a uid-set-aware EXPUNGE handler; " +
        "the default expunges by \\Deleted flag and would exceed the set");
      return;
    }
    // The literal rides along to the sub-handler. Widening the registry entry
    // above is necessary and not sufficient: the payload still had no route
    // from here to the verb that consumes it, so either repair alone leaves
    // UID SEARCH answering BAD to the term it was given.
    return _registry.dispatch(subVerb, state, socket,
      { tag: tag, args: subArgs, useUid: true }, literalBody);
  }

  function _handleIdle(state, socket, tag) {
    if (!_requireAuth(state, socket, tag)) return;
    _writeContinuation(socket, "idling");
    // RFC 2177 §3 — IDLE must be terminated with DONE before
    // bandwidth-timeout. We schedule a soft cutoff 1 min before the
    // hard 30-min cutoff to force client re-issue.
    var timer = setTimeout(function () {
      if (state.idle) {
        _writeUntagged(socket, "BYE IDLE timed out — re-issue");
        state.idle = null;
        _close(socket, state);
      }
    }, IDLE_BANDWIDTH_TIMEOUT_MS);
    state.idle = { tag: tag, timer: timer };
  }

  // One line onto the socket, as OCTETS.
  //
  // RFC 9051 §4.3 makes a literal a counted sequence of octets, so a response
  // carrying message content has to reach the wire as the octets the backend
  // holds. `socket.write(string)` encodes as UTF-8, which replaces every
  // sequence that is not valid UTF-8 and changes the length — so the count the
  // response announced and the number of octets it wrote disagreed, and a
  // client, which uses that count to find the end of the response, read the
  // next response as part of this one.
  //
  // A Buffer `msg` is written through untouched. A string keeps its UTF-8
  // encoding, which is what RFC 9051 §5.1 asks for in the one place a response
  // string is not ASCII: a mailbox name, once the client has enabled UTF8=ACCEPT.
  // Encoding those latin1 instead would keep the low byte of each character and
  // corrupt every name outside Latin-1 — the same defect this fixes, moved.
  function _writeLine(socket, prefix, msg) {
    try {
      if (Buffer.isBuffer(msg)) {
        socket.write(Buffer.concat([Buffer.from(prefix, "latin1"), msg, CRLF_BYTES]));
      } else {
        socket.write(prefix + msg + "\r\n");
      }
    } catch (_e) { /* socket may be down */ }
  }
  // One untagged FETCH response. A Buffer payload is the backend saying "these
  // are the message's own octets", and the response is assembled as octets so
  // the count in the literal header is the count that reaches the wire; a
  // string payload is attributes and stays a string.
  //
  // Two places build one of these — the FETCH command and a NOTIFY push — and
  // a second copy of this is how the octet handling ends up right in one and
  // wrong in the other, which is what it was.
  function _fetchResponse(seq, payload) {
    if (Buffer.isBuffer(payload)) {
      return Buffer.concat([
        Buffer.from(seq + " FETCH (", "latin1"), payload, Buffer.from(")", "latin1"),
      ]);
    }
    return seq + " FETCH (" + (payload || "") + ")";
  }

  function _writeTagged(socket, tag, msg) {
    _writeLine(socket, tag + " ", msg);
  }
  function _writeUntagged(socket, msg) {
    _writeLine(socket, "* ", msg);
  }
  // RFC 9051 §7.5 continuation. Returns false when the operator's challenge
  // carries CR / LF / NUL: those end the line early and the remainder is read
  // by the client as a second server response. Not hypothetical for a SCRAM or
  // CRAM mechanism, whose challenge is composed partly from the client's own
  // nonce, so client bytes reach this write.
  function _writeContinuation(socket, msg) {
    var safe = mailServerNet.saslChallengeOrNull(msg);
    if (safe === null) return false;
    _writeLine(socket, "+ ", safe);
    return true;
  }
  function _close(socket, state) {
    // The drain loop's `if (state.stage === "closed") return;` guard
    // (around the bottom of _drainBuffer) was dead before this —
    // _close never wrote the sentinel, so the drain loop kept
    // processing buffered bytes after the socket was destroyed.
    // Setting stage="closed" here makes the guard reachable so a
    // close mid-loop short-circuits the next command dispatch
    // (defense-in-depth against an exception thrown by a handler
    // that doesn't tear down the loop).
    if (state && typeof state === "object") state.stage = "closed";
    // A pending literal's deadline outlives nothing: the connection is going.
    if (state && typeof state === "object") _clearLiteralDeadline(state);
    try { socket.end(); } catch (_e) { /* idempotent */ }
    try { socket.destroy(); } catch (_e2) { /* idempotent */ }
    connections.delete(socket);
  }
  function _unquote(s) {
    if (typeof s !== "string") return "";
    if (s[0] === "\"" && s[s.length - 1] === "\"") return s.slice(1, -1);
    return s;
  }

  // ---- Lifecycle ----------------------------------------------------------
  return mailServerNet.createStoreServer(net, {
    // RFC 9051 IMAP port (IANA), or RFC 8314 §3.1's implicit-TLS 993 when the
    // operator asked for that mode and named no port of their own.
    defaultPort:      implicitTls ? 993 : 143,                                                          // RFC 8314 §3.1 / RFC 9051 (IANA)
    maxConnections:   opts.maxConnections,
    listeningExtra:   function () { return { implicitTls: implicitTls }; },
    handleConnection: _handleConnection,
    errorClass:       MailServerImapError,
    errorCodePrefix:  "mail-server-imap/",
    emit:             _emit,
    connections:      connections,
    eventBase:        "mail.server.imap",
  });
}

module.exports = {
  create:               create,
  MailServerImapError:  MailServerImapError,
};
