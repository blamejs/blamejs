// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     b.mail.server.managesieve
 * @nav        Mail
 * @title      Mail ManageSieve Server
 * @order      560
 *
 * @intro
 *   ManageSieve listener (RFC 5804 — "A Protocol for Remotely Managing
 *   Sieve Scripts"). Lets MUAs upload, replace, list, activate, fetch,
 *   delete, and rename Sieve filter scripts on the server. Composes
 *   `b.safeSieve.validate` for pre-storage validation per RFC 5804 §2.3:
 *   "An implementation MUST verify the script's validity ... and MUST
 *   reject scripts which fail validity tests."
 *
 *   ## State machine (RFC 5804 §1)
 *
 *   ```
 *   NOT-AUTHENTICATED → STARTTLS → AUTHENTICATED → LOGOUT
 *   ```
 *
 *   - **NOT-AUTHENTICATED**: CAPABILITY / NOOP / STARTTLS /
 *     AUTHENTICATE / LOGOUT. The listener sends an unsolicited
 *     capability banner on connect (RFC 5804 §1.7).
 *   - **STARTTLS** (transient): triggered by `STARTTLS`. Pre-handshake
 *     receive buffer is drained before the TLS upgrade to defend the
 *     STARTTLS-injection class (CVE-2021-38371 / CVE-2021-33515 /
 *     CVE-2011-0411). Capabilities are re-emitted post-TLS so the
 *     client sees the post-TLS mechanism list (RFC 5804 §2.2).
 *   - **AUTHENTICATED**: HAVESPACE / PUTSCRIPT / LISTSCRIPTS /
 *     SETACTIVE / GETSCRIPT / DELETESCRIPT / RENAMESCRIPT / NOOP /
 *     CAPABILITY / LOGOUT.
 *
 *   ## Wire-protocol defenses
 *
 *   - **No-implicit-plaintext** — `opts.tlsContext` is required at
 *     `create()`. Operators that genuinely need plaintext (intra-rack
 *     testing) explicitly pass `allowPlaintext: true`, which emits a
 *     `mail.server.managesieve.plaintext_warning` audit on every boot.
 *
 *   - **AUTHENTICATE-mechanism advertisement parity** — `CAPABILITY`
 *     output advertises ONLY the mechanisms listed in
 *     `opts.auth.mechanisms`. The framework hardcodes no defaults; an
 *     operator who omits `mechanisms` gets a listener that refuses
 *     every AUTHENTICATE attempt with "mechanism not advertised"
 *     (otherwise advertising AUTH=PLAIN
 *     when authConfig is null sets clients up to attempt PLAIN against
 *     a listener that hasn't wired the verifier).
 *
 *   - **Cleartext-AUTH refusal under strict** — RFC 5804 §1.1 + RFC
 *     4954 §4. `AUTHENTICATE PLAIN` / `LOGIN` / `SCRAM*` pre-TLS under
 *     strict refused at both the validator and the dispatch boundary.
 *     `AUTHENTICATE EXTERNAL` exempt (TLS client-cert credential, not
 *     a password).
 *
 *   - **STARTTLS injection (CVE-2021-33515 class)** — STARTTLS upgrade
 *     clears the per-connection receive buffer; any pipelined command
 *     queued before the upgrade is discarded. Capabilities are
 *     re-emitted on the post-TLS socket per RFC 5804 §2.2.
 *
 *   - **PUTSCRIPT pre-validation (RFC 5804 §2.3)** — every PUTSCRIPT
 *     payload is parsed via `b.safeSieve.validate` before
 *     `mailStore.sieveScripts.put`. Invalid scripts are refused with
 *     `NO (QUOTA/MAXSCRIPTS) "..."` per §2.3 + audited with the
 *     `safe-sieve/...` issue code so operators can correlate refusals.
 *
 *   - **Per-IP rate limit + AUTH-failure budget** — composes
 *     `b.mail.server.rateLimit` (default-on). Brute-force protection
 *     applies to AUTHENTICATE failures identically to POP3/IMAP.
 *
 *   ## Audit lifecycle
 *
 *   - `mail.server.managesieve.connect`                — IP, TLS state
 *   - `mail.server.managesieve.auth_attempt`           — mech
 *   - `mail.server.managesieve.auth_success`           — mech, tenantId
 *   - `mail.server.managesieve.auth_failed`            — mech, reason
 *   - `mail.server.managesieve.auth_refused_cleartext` — mech
 *   - `mail.server.managesieve.starttls_upgraded`
 *   - `mail.server.managesieve.starttls_handshake_failed`
 *   - `mail.server.managesieve.putscript`              — name, bytes
 *   - `mail.server.managesieve.putscript_refused`      — name, reason (safeSieve issue code)
 *   - `mail.server.managesieve.getscript`              — name
 *   - `mail.server.managesieve.listscripts`            — count
 *   - `mail.server.managesieve.setactive`              — name (empty == deactivate-all)
 *   - `mail.server.managesieve.delete`                 — name
 *   - `mail.server.managesieve.rename`                 — old, new
 *   - `mail.server.managesieve.havespace`              — name, size, ok
 *   - `mail.server.managesieve.logout`
 *   - `mail.server.managesieve.listening`              — port, address
 *   - `mail.server.managesieve.closed`
 *   - `mail.server.managesieve.socket_error`
 *   - `mail.server.managesieve.handler_threw`          — verb, error
 *
 *   ## What v1 does NOT ship
 *
 *   - **CHECKSCRIPT** (RFC 5804 §2.12) — parse-only verb. Operators
 *     who want it compose `b.safeSieve.validate` directly via JMAP
 *     `SieveScript/validate` (RFC 9661). The MTA-side ManageSieve
 *     surface is `PUTSCRIPT` + `HAVESPACE`; CHECKSCRIPT adds a third
 *     entry point with no operator demand yet.
 *   - **UNAUTHENTICATE** (RFC 5804 §2.14) — exotic. Operators close
 *     the TCP connection or send `LOGOUT` + reconnect.
 *
 *   ## Composition contract
 *
 *   - `b.guardManageSieveCommand` — wire-protocol gate
 *   - `b.safeSieve.validate`      — PUTSCRIPT pre-validation
 *   - `b.mail.server.rateLimit`   — DoS defense
 *   - `b.mailStore` — operator-supplied backend (must expose
 *     `sieveScripts.put(actor, name, body)` /
 *     `sieveScripts.list(actor)` /
 *     `sieveScripts.get(actor, name)` /
 *     `sieveScripts.setActive(actor, name)` /
 *     `sieveScripts.delete(actor, name)` /
 *     `sieveScripts.rename(actor, oldName, newName)` /
 *     `sieveScripts.haveSpace(actor, name, size)`)
 *   - operator's `auth.verify(mechanism, credentials)` async predicate
 *   - `b.network.tls.context` — TLS posture
 *
 * @card
 *   ManageSieve listener (RFC 5804). State machine NOT-AUTH → STARTTLS
 *   → AUTH → LOGOUT. Composes b.guardManageSieveCommand +
 *   b.safeSieve.validate (PUTSCRIPT pre-validation per §2.3) +
 *   b.mail.server.rateLimit + operator-supplied mailStore + SASL
 *   authenticator. STARTTLS-injection defense + AUTH-failure budget +
 *   cleartext-AUTH refusal under strict + LITERAL+ support (RFC 7888).
 */

var net = require("node:net");
var safeBuffer = require("./safe-buffer");
var mailServerTls = require("./mail-server-tls");
var mailServerNet = require("./mail-server-net");
// Elapsed time for the body-rate window — see the note in mail-server-imap.js:
// a wall clock corrected mid-transfer either hands out a window's budget for
// free or refuses a sender that has done nothing wrong.
var time = require("./time");
var C = require("./constants");
var numericBounds = require("./numeric-bounds");
var validateOpts = require("./validate-opts");
var guardManageSieveCommand = require("./guard-managesieve-command");
var safeSieve = require("./safe-sieve");
var mailServerRateLimit = require("./mail-server-rate-limit");
var mailServerRegistry = require("./mail-server-registry");
var { defineClass } = require("./framework-error");

var auditEmit = require("./audit-emit");

var MailServerManageSieveError = defineClass("MailServerManageSieveError",
  { alwaysPermanent: true });

// RFC 5804 §1 default port (IANA-assigned).
var DEFAULT_PORT             = 4190;                                                                    // RFC 5804 §1 / IANA managesieve port
var DEFAULT_MAX_LINE_BYTES   = 8192;                                                                    // matches guardManageSieveCommand strict cap
// Lines' worth of pipelined commands a connection may hold while one runs.
var PIPELINE_LINE_ALLOWANCE  = 8;
var CRLF_BYTES               = 2;                                                                       // the terminator each buffered line carries
// Added to the limiter's own window before the no-payload deadline fires, so
// the limiter is asked once it has enough elapsed time to answer rather than
// exactly on the boundary.
var LITERAL_DEADLINE_GRACE_MS = C.TIME.seconds(1);

var DEFAULT_IDLE_TIMEOUT_MS  = C.TIME.minutes(5);
var DEFAULT_GREETING_VENDOR  = "blamejs ManageSieve";

var ERR_CLAMP                = 200;                                                                     // protocol-reply error-message clamp

/**
 * @primitive b.mail.server.managesieve.create
 * @signature b.mail.server.managesieve.create(opts)
 * @since     0.9.57
 * @status    stable
 * @related   b.mail.server.imap.create, b.mail.server.pop3.create, b.safeSieve.parse, b.guardManageSieveCommand.validate
 *
 * Build a ManageSieve listener (RFC 5804). Returns a handle exposing
 * `listen({ port, address })` and `close()`. Composes `b.safeSieve`
 * for PUTSCRIPT pre-validation per RFC 5804 §2.3.
 *
 * @opts
 *   tlsContext:        SecureContext,                       // required (no implicit plaintext)
 *   implicitTls:       boolean,                             // RFC 8314 §3 — TLS from the SYN. RFC 5804 names one port, so the mode changes how 4190 speaks rather than which port it is. STARTTLS is neither advertised nor accepted on it; requires tlsContext. Default false
 *   allowPlaintext:    boolean,                              // explicit opt-in; emits warning audit
 *   greeting:          string,                               // default "blamejs ManageSieve"
 *   maxLineBytes:      number,                               // default 8192
 *   idleTimeoutMs:     number,                               // default 5 min
 *   maxConnections:    number,                               // default 1024 — listener-wide ceiling
 *   profile:           "strict" | "balanced" | "permissive", // default "strict"
 *   auth: {
 *     mechanisms:      ["SCRAM-SHA-256", "OAUTHBEARER", ...], // SASL mechs to advertise
 *     verify:          async function (mech, credentials) → { ok, actor },
 *   },
 *   mailStore:         b.mailStore handle,                    // must expose sieveScripts.*
 *   rateLimit:         b.mail.server.rateLimit handle | opts | false,
 *   audit:             b.audit
 *
 * @example
 *   var msv = b.mail.server.managesieve.create({
 *     tlsContext: b.mail.server.tls.context({ certFile, keyFile }).secureContext,
 *     auth: {
 *       mechanisms: ["SCRAM-SHA-256", "OAUTHBEARER", "EXTERNAL"],
 *       verify:     async function (mech, creds) {
 *         return { ok: true, actor: { username: creds.authzid, tenantId: "t1" } };
 *       },
 *     },
 *     mailStore: b.mailStore.create({ backend: b.db }),
 *   });
 *   await msv.listen({ port: 4190 });
 */
// Every option `create` reads. A name that is not here is a typo, and a typo
// used to be a setting that never took effect: the listener started, said
// nothing, and ran with the default while the caller believed otherwise.
var CREATE_OPTS = [
  "tlsContext", "implicitTls", "allowPlaintext", "greeting", "maxLineBytes",
  "idleTimeoutMs", "maxConnections", "profile", "auth", "mailStore",
  "rateLimit", "audit", "overrides", "agentTenantId", "tenantScope",
];

function create(opts) {
  validateOpts.requireObject(opts, "mail.server.managesieve.create",
    MailServerManageSieveError, "mail-server-managesieve/bad-opts");
  validateOpts.checkOrThrow(opts, CREATE_OPTS, "mail.server.managesieve.create",
    MailServerManageSieveError, "mail-server-managesieve/bad-opts");
  validateOpts.auditShape(opts.audit, "mail.server.managesieve.create",
    MailServerManageSieveError, "mail-server-managesieve/bad-opts");
  if (!opts.tlsContext && !opts.allowPlaintext) {
    throw new MailServerManageSieveError("mail-server-managesieve/no-tls-context",
      "mail.server.managesieve.create: tlsContext is required (no implicit plaintext mode). " +
      "Use b.mail.server.tls.context({ certFile, keyFile, watch: true }) to load + " +
      "auto-reload a cert/key pair from disk. Operators that genuinely need plaintext " +
      "(intra-rack testing) explicitly pass allowPlaintext: true.");
  }
  if (!opts.mailStore || !opts.mailStore.sieveScripts ||
      typeof opts.mailStore.sieveScripts.put !== "function") {
    throw new MailServerManageSieveError("mail-server-managesieve/no-mail-store",
      "mail.server.managesieve.create: mailStore.sieveScripts is required (must expose " +
      "put/list/get/setActive/delete/rename/haveSpace; compose b.mailStore.create or " +
      "operator-supplied backend)");
  }
  numericBounds.requireAllPositiveFiniteIntIfPresent(opts,
    ["maxLineBytes", "idleTimeoutMs", "maxConnections"],
    "mail.server.managesieve.", MailServerManageSieveError, "mail-server-managesieve/bad-bound");

  var greeting       = opts.greeting       || DEFAULT_GREETING_VENDOR;
  var maxLineBytes   = opts.maxLineBytes   || DEFAULT_MAX_LINE_BYTES;
  // How much may sit in the buffer waiting for a handler to finish. Eight
  // lines' worth: enough for any client that pipelines a working set of
  // commands, far short of what an unbounded queue would hold. Each line's
  // CRLF counts, because the buffer holds it -- budgeting eight BODIES closed
  // the connection on eight commands that were each within the line cap.
  var maxPipelinedBytes = (maxLineBytes + CRLF_BYTES) * PIPELINE_LINE_ALLOWANCE;
  var idleTimeoutMs  = opts.idleTimeoutMs  || DEFAULT_IDLE_TIMEOUT_MS;
  var profile        = opts.profile        || "strict";
  var authConfig     = opts.auth           || null;
  var mailStore      = opts.mailStore;
  var allowPlaintext = opts.allowPlaintext === true;

  // Read at the point of use, never captured. A consumer wiring the watching
  // loader from mail.server.tls.context installs an accessor on this option, and
  // capturing it here would call that accessor exactly once and freeze whatever
  // certificate was current at boot — for a listener whose siblings all rotate.
  // Certificates renew every 60 to 90 days on any automated CA, so the frozen
  // one expires while the operator's evidence says rotation is working: the
  // watcher fired, the context rebuilt, and it simply never reached here. The
  // four sibling listeners already read the option per connection.
  function _tlsContext() { return opts.tlsContext || null; }

  // RFC 8314 §3 — implicit TLS in preference to the in-band upgrade. Off by
  // default, so an existing composition on 4190 is unaffected. It needs a
  // context to wrap with, so asking for it without one is refused rather than
  // silently serving plaintext on a port an operator believes is encrypted.
  var implicitTls = opts.implicitTls === true;
  if (implicitTls && !_tlsContext()) {
    throw new MailServerManageSieveError("mail-server-managesieve/no-tls-context",
      "mail.server.managesieve.create: implicitTls requires tlsContext — without one " +
      "the port would serve plaintext under a name that says otherwise");
  }

  // safeSieve cap matches the guard's per-profile script cap (the
  // guard caps the literal-byte announcement; safeSieve.parse caps
  // the actual script bytes — same cap on both sides).
  var safeSieveProfile = profile;

  var rateLimit = mailServerRateLimit.resolve(opts.rateLimit);

  var connections = new Set();

  // The framework audit, plus the operator's own sink when one was supplied.
  // `audit` was documented on this listener and never read, so an operator who
  // wired a sink got silence from it. Both receive the event: the global trail
  // an operator already relies on is not replaced by adding a second reader.
  var _emit = auditEmit.dualEmitter(opts);

  function _handleConnection(rawSocket) {
    var accepted = mailServerNet.acceptConnection(rawSocket, {
      rateLimit:    rateLimit,
      connections:  connections,
      emit:         _emit,
      refusedEvent: "mail.server.managesieve.rate_limit_refused",
      refusalLine:  'NO "Too many connections from your IP"\r\n',
      idPrefix:     "msvconn-",
      wrap:         mailServerTls.implicitTlsWrap(_tlsContext(), implicitTls),
    });
    if (accepted === null) return;
    var remoteAddress = accepted.remoteAddress;
    var connectionId  = accepted.connectionId;
    var socket        = accepted.socket;

    var state = {
      id:              connectionId,
      remoteAddress:   remoteAddress,
      // Already encrypted on an implicit-TLS port, so the session opens with
      // what a STARTTLS upgrade would otherwise have to establish.
      tls:             implicitTls,
      stage:           "not-authenticated",
      closed:          false,        // set once by _close; never cleared
      actor:           null,
      pendingLiteral:  null,         // { verb, name, size, body, plus }
      pendingAuth:     null,         // { mech, irBytes, irPlus, irBody }
      saslExchange:    null,         // { mech, step } while a multi-step SASL exchange is live
      awaitingLiteralTerminator: false,  // a literal body was read; its line's CRLF has not arrived
      lineBuffer:      Buffer.alloc(0),
      // Slow-loris floor for literal payloads, measured over bounded windows
      // so an early burst cannot buy credit for a slow tail.
      bodyRateWindow:  mailServerNet.createBodyRateWindow(rateLimit),
      wireBytes:       0,
      // Fires the floor when a literal is opened and no payload follows, which
      // the data-driven check cannot see because no data event ever arrives.
      literalDeadline: null,
    };

    _emit("mail.server.managesieve.connect",
      { connectionId: connectionId, remoteAddress: remoteAddress });

    mailServerNet.wireLineSocket(socket, {
      // No `drain`: this listener keeps its own data handler, which counts
      // every wire byte once and measures a literal transfer against the
      // minimum-rate floor before the buffer grows.
      idleTimeoutMs: idleTimeoutMs,
      state:         state,
      onIdleTimeout: function () { _writeBye(socket, "Idle timeout"); },
      onError:       function (err) {
        _emit("mail.server.managesieve.socket_error",
          { connectionId: connectionId, error: (err && err.message) || String(err) }, "failure");
      },
      close:         function () { _close(socket, state); },
    });
    // Every teardown, whatever caused it. Clearing only in _close would leave
    // a pending literal's timer alive after a socket error, an idle timeout or
    // a server shutdown — and it would then fire against a connection that is
    // already gone, emitting a refusal for a peer that is no longer there and
    // holding the state until it did.
    socket.on("close", function () { _clearLiteralDeadline(state); });

    // Unsolicited capability banner per RFC 5804 §1.7 — capabilities
    // first, then `OK "<greeting>"`.
    _emitCapabilityBanner(state, socket);
    _writeOk(socket, greeting + " ready");

    if (allowPlaintext && !_tlsContext()) {
      _emit("mail.server.managesieve.plaintext_warning",
        { connectionId: connectionId,
          remark: "allowPlaintext=true; no STARTTLS available — operators MUST gate at network layer" },
        "warning");
    }

    socket.on("data", function (chunk) {
      // The same slow-loris floor the other listeners enforce. This one is
      // post-authentication — PUTSCRIPT calls _requireAuth before it opens a
      // literal — so it is a slower burn than the IMAP case, but a trickled
      // script still holds a connection slot for as long as the peer likes:
      // the idle timeout is reset by every arriving byte, and nothing else
      // bounded the transfer. Counted at the wire funnel so it cannot be
      // dodged by choosing a different command.
      state.wireBytes += chunk.length;
      // Both literal transfers, not just the script one. An AUTHENTICATE
      // initial response is tracked on pendingAuth rather than pendingLiteral,
      // and it is the transfer a peer can open BEFORE authenticating — so a
      // guard that watched only the script literal left exactly the
      // unauthenticated slow-loris path it was added to close.
      var transferring = state.pendingLiteral ||
        (state.pendingAuth && state.pendingAuth.irBytes !== null &&
         state.pendingAuth.irBytes !== undefined);
      if (transferring && state.bodyRateWindow.starved(state.wireBytes, time.monotonicMs())) {
        _emit("mail.server.managesieve.literal_refused",
          { connectionId: state.id, reason: "body-rate-below-floor",
            minBytesPerSecond: rateLimit.minBytesPerSecond() }, "denied");
        _writeNo(socket, "Literal arriving below the minimum rate; closing connection");
        _close(socket, state);
        return;
      }
      state.lineBuffer = Buffer.concat([state.lineBuffer, chunk]);
      _drainBuffer(state, socket);
    });
  }

  // The rate floor is asked from the socket's data handler, which runs only
  // when bytes arrive — so a peer that opens a literal and then sends NOTHING
  // was never measured, and held the connection until an idle timeout it was
  // never going to trip. One timer per transfer, fired once the window is old
  // enough for the limiter to have an opinion, cancelled when the transfer
  // completes. unref so a pending literal cannot hold the process open.
  function _armLiteralDeadline(state, socket) {
    _clearLiteralDeadline(state);
    state.literalDeadline = setTimeout(function () {
      state.literalDeadline = null;
      var open = state.pendingLiteral ||
        (state.pendingAuth && state.pendingAuth.irBytes !== null &&
         state.pendingAuth.irBytes !== undefined);
      if (!open) return;
      // Re-armed while the transfer is still open — see the IMAP twin: firing
      // once leaves burst-then-stall unbounded, because no data event arrives
      // to ask again.
      if (!state.bodyRateWindow.starved(state.wireBytes, time.monotonicMs())) {
        _armLiteralDeadline(state, socket);
        return;
      }
      _emit("mail.server.managesieve.literal_refused",
        { connectionId: state.id, reason: "body-rate-below-floor",
          minBytesPerSecond: rateLimit.minBytesPerSecond() }, "denied");
      _writeNo(socket, "Literal arriving below the minimum rate; closing connection");
      _close(socket, state);
    }, rateLimit.bodyRateWindowMs() + LITERAL_DEADLINE_GRACE_MS);
    if (typeof state.literalDeadline.unref === "function") state.literalDeadline.unref();
  }
  function _clearLiteralDeadline(state) {
    if (state.literalDeadline) { clearTimeout(state.literalDeadline); state.literalDeadline = null; }
  }

  // _drainBuffer — line-oriented dispatch with literal-payload windows.
  // When the previous command opened a literal (PUTSCRIPT, or
  // AUTHENTICATE with a non-synchronizing initial-response), the next
  // N bytes are the literal-payload; accumulate them before resuming
  // line-mode dispatch.
  // The CRLF that ends the LINE a literal sat on. RFC 5804 §4 puts it after
  // the payload, outside the declared octet count, so every literal owes one
  // and no literal's size includes it.
  //
  // Consumed here when it is already buffered, and otherwise awaited: it may
  // arrive in a later segment, and read as a line it is an EMPTY line. On the
  // SASL path an empty line is a second response and the pipelining guard
  // fails the exchange for it; on the PUTSCRIPT path it draws a spurious
  // "empty command line" refusal AFTER the script was accepted, so one command
  // is answered twice and a client that reads one reply per command spends the
  // rest of the session attributing each answer to the command before it.
  //
  // A peek alone is not enough, because whether the terminator has arrived yet
  // is a property of the network rather than of the protocol. Shared by both
  // literal paths: one of them used to do this and the other did not, which is
  // the entire defect.
  function _consumeLiteralTerminator(state) {
    if (state.lineBuffer.length >= 2 &&
        state.lineBuffer[0] === 0x0d && state.lineBuffer[1] === 0x0a) {          // CR LF
      state.lineBuffer = state.lineBuffer.subarray(2);
    } else {
      state.awaitingLiteralTerminator = true;
    }
  }

  // One command at a time. A handler that authenticates or reaches the store
  // settles before the next line is read, so a guard reading state a later
  // handler writes sees what it is guarding against. Draining the whole buffer
  // synchronously let a pipelined client put every command in one segment and
  // have them all dispatched against the state as it stood before any of them
  // ran. `mail-server-mx.js` already chained its ingestion for this reason.
  // Would this line open a literal if it were taken now? The guard answers it,
  // since it already refuses an AUTHENTICATE initial response over
  // MAX_SASL_TOKEN_BYTES and a script over the profile's maxScriptBytes. A
  // tail-matching answer would hand `BOGUS {1048576+}` a megabyte of exemption
  // for a payload no handler will ever read.
  //
  // The session's stage is deliberately NOT consulted, though PUTSCRIPT is
  // refused before a literal is opened when the session is not authenticated.
  // A peer may pipeline AUTHENTICATE and PUTSCRIPT in a single write, and
  // judging the PUTSCRIPT against the state as it stands BEFORE the
  // authentication refuses a script that would be valid by the time the reader
  // reaches it. Nothing is given away: the reader takes the line on the same
  // turn, and a command refused there never opens its literal, so the bytes
  // still queued behind it are charged on the next read.
  // Do these octets survive a round trip through UTF-8?
  //
  // A literal carries octets, so its bytes need not be text at all, and
  // `toString("utf8")` substitutes U+FFFD for each byte it cannot read rather
  // than reporting one. The substitution happens before anything examines the
  // value, so every later check runs on a repaired copy and nothing downstream
  // can tell it was altered. Both places this listener turns a literal into a
  // string ask here first, and refuse rather than repair -- the same answer the
  // IMAP listener gives a literal it cannot rebuild.
  function _decodesAsUtf8(body) {
    return Buffer.from(body.toString("utf8"), "utf8").equals(body);
  }

  function _openerBytes(state, line) {
    var parsed;
    try {
      parsed = guardManageSieveCommand.validate(line, { profile: profile, tls: state.tls });
    } catch (_e) { return null; }
    if (!parsed || parsed.literalBytes === null || parsed.literalBytes === undefined) return null;
    return parsed.literalBytes;
  }

  // What may WAIT is bounded. Commands queue while a handler runs, a store
  // call or a credential check, and a client that sends faster than they
  // complete would grow this buffer for as long as it liked. A per-line cap
  // says nothing about how many lines are held at once.
  //
  // Only a transfer's OUTSTANDING octets are exempt, not the whole buffer.
  // Exempting one entirely let a client put a literal opener and then any
  // amount of pipelined commands in one write, and the bound was skipped for
  // all of it.
  //
  // An exemption for an opener the reader has NOT taken yet is a prediction.
  // When the reader takes that line and refuses the literal -- PUTSCRIPT before
  // authentication, an announcement over the profile's script cap -- those
  // octets are ordinary queue, so the bound is asked again per command rather
  // than only on a socket read, which a single coalesced write never repeats.
  //
  // The length test comes first and costs nothing; only a buffer already over
  // the allowance is worth scanning for an opener.
  function _backlogRefused(state, socket) {
    var held = safeBuffer.byteLengthOf(state.lineBuffer);
    if (held <= maxPipelinedBytes) return false;
    var outstanding;
    if (state.pendingAuth && state.pendingAuth.irBytes !== null &&
        state.pendingAuth.irBytes !== undefined) {
      outstanding = Math.max(0, state.pendingAuth.irBytes - state.pendingAuth.irBody.length);
    } else {
      // Reads the buffer, not just `state`: a LITERAL+ opener arrives WITH its
      // body in one read, so no literal is pending yet and the payload would
      // be charged to the backlog -- refusing a script well inside the
      // profile's own cap because of how the client's write was chunked.
      outstanding = mailServerNet.announcedLiteralBytes(state.lineBuffer, {
        pending:           state.pendingLiteral,
        maxLineBytes:      maxLineBytes,
        maxPipelinedBytes: maxPipelinedBytes,
        openerBytes:       function (line) { return _openerBytes(state, line); },
      });
    }
    if (held - outstanding <= maxPipelinedBytes) return false;
    _writeNo(socket, "Too much pipelined data awaiting execution (cap " +
      maxPipelinedBytes + " bytes)");
    _close(socket, state);
    return true;
  }

  function _drainBuffer(state, socket) {
    if (_backlogRefused(state, socket)) return;
    if (state.pumping) return;                  // the running pump will take it
    state.pumping = true;
    function done() { state.pumping = false; }
    function fail(e) {
      state.pumping = false;
      _emit("mail.server.managesieve.handler_threw",
        { connectionId: state.id, error: (e && e.message) || String(e) }, "failure");
      try { _writeNo(socket, "Server error"); } catch (_e) { /* socket already gone */ }
      _close(socket, state);
    }
    // Every continuation goes through here, so the next unit of work always
    // starts after the previous one settled and never on a synchronous stack.
    function after(pending) { Promise.resolve(pending).then(step, fail); }

    function step() {
      if (state.closed) return done();
      // Re-asked per command: the exemption the last check granted was a
      // prediction about a line the reader had not taken yet. With a transfer
      // actually open there is nothing to predict.
      if (!state.pendingLiteral && !state.pendingAuth &&
          _backlogRefused(state, socket)) return done();
      if (state.pendingLiteral) {
        var pl = state.pendingLiteral;
        var need = pl.size - pl.body.length;
        if (state.lineBuffer.length < need) {
          pl.body = Buffer.concat([pl.body, state.lineBuffer]);
          state.lineBuffer = Buffer.alloc(0);
          return done();
        }
        pl.body = Buffer.concat([pl.body, state.lineBuffer.subarray(0, need)]);
        state.lineBuffer = state.lineBuffer.subarray(need);
        _consumeLiteralTerminator(state);
        state.pendingLiteral = null;
        _clearLiteralDeadline(state);
        return after(_completePutscript(state, socket, pl));
      }
      if (state.pendingAuth && state.pendingAuth.irBytes !== null) {
        var pa = state.pendingAuth;
        var needA = pa.irBytes - pa.irBody.length;
        if (state.lineBuffer.length < needA) {
          pa.irBody = Buffer.concat([pa.irBody, state.lineBuffer]);
          state.lineBuffer = Buffer.alloc(0);
          return done();
        }
        pa.irBody = Buffer.concat([pa.irBody, state.lineBuffer.subarray(0, needA)]);
        state.lineBuffer = state.lineBuffer.subarray(needA);
        _consumeLiteralTerminator(state);
        pa.irBytes = null;
        return after(_completeAuthenticate(state, socket));
      }
      var crlf = state.lineBuffer.indexOf("\r\n");
      if (crlf === -1) {
        if (safeBuffer.byteLengthOf(state.lineBuffer) > maxLineBytes) {
          _writeNo(socket, "Line too long (cap " + maxLineBytes + ")");
          _close(socket, state);
        }
        return done();
      }
      var rawLine = state.lineBuffer.subarray(0, crlf).toString("utf8");
      state.lineBuffer = state.lineBuffer.subarray(crlf + 2);
      // The terminator a literal was still owed, arriving in its own segment.
      // It closes the literal's line rather than opening a new one.
      //
      // A line that is NOT empty here is a client that ran its next command
      // straight on from the payload without the CRLF between them, and it is
      // read as that next command rather than refused. Every ManageSieve
      // command puts its literal LAST -- `PUTSCRIPT "name" {N}`,
      // `AUTHENTICATE "PLAIN" {N}` -- so unlike IMAP the terminator carries no
      // parsing information: there is no second argument it could be hiding,
      // and the literal's octet count has already delimited the payload
      // exactly, so what follows is outside it either way. Those bytes are the
      // same client's own next command on its own connection, which is why
      // this is loose framing rather than one command's text being read as
      // part of another. Refusing it costs conforming-but-terse clients a
      // closed connection and buys no boundary that the octet count has not
      // already drawn.
      if (state.awaitingLiteralTerminator) {
        state.awaitingLiteralTerminator = false;
        if (rawLine.length === 0) return after(undefined);
      }
      return after(_handleLine(state, socket, rawLine));
    }
    step();
  }

  function _handleLine(state, socket, line) {
    // Mid-SASL: this line is the client's base64 response to the server's
    // challenge, not a ManageSieve verb, so it goes to the exchange rather than
    // the wire guard — which would refuse it as an unknown command. This
    // ordering is why the `overrides` hook could never carry a multi-step
    // mechanism on its own: the guard ran first and the reply never arrived.
    if (state.saslExchange) {
      return _continueSaslExchange(state, socket, line);
    }
    var parsed;
    try {
      parsed = guardManageSieveCommand.validate(line, {
        profile: profile,
        tls:     state.tls,
      });
    } catch (e) {
      _writeNo(socket, (e && e.message ? e.message.slice(0, ERR_CLAMP) : "syntax"));
      return;
    }
    try {
      var result = _dispatch(state, socket, parsed);
      // Registry dispatch may return a Promise (async override handler
      // or safeAsync.withTimeout-wrapped Promise). The synchronous
      // try/catch above only catches throw-during-dispatch; Promise
      // rejections need an attached catch to avoid unhandled-rejection
      // termination + missing NO reply.
      // Returned as well as handled: the reader waits for it before taking
      // the next line, and the rejection arm below still owns the reply.
      if (result && typeof result.then === "function") {
        return result.then(
          function () { /* OK reply already written by handler */ },
          function (e) {
            try {
              _emit("mail.server.managesieve.handler_rejected",
                { connectionId: state.id, verb: parsed && parsed.verb,
                  error: (e && e.message) || String(e) }, "failure");
            } catch (_ae) { /* drop-silent */ }
            try { _writeNo(socket, "Internal error"); }
            catch (_we) { /* socket may already be gone */ }
          }
        );
      }
    } catch (e) {
      _emit("mail.server.managesieve.handler_threw",
        { connectionId: state.id, verb: parsed && parsed.verb,
          error: (e && e.message) || String(e) }, "failure");
      _writeNo(socket, "Internal error");
    }
  }

  var _registry = null;
  function _ensureRegistry() {
    if (_registry !== null) return _registry;
    var SHORT_MS  = 5 * 1000;                                                                        // allow:raw-time-literal — 5s short-command budget
    var MEDIUM_MS = 30 * 1000;                                                                       // allow:raw-time-literal — 30s medium-command budget
    var LONG_MS   = 2 * 60 * 1000;                                                                   // allow:raw-time-literal — 2 min PUTSCRIPT / GETSCRIPT budget
    var SHORT_B   = 8 * 1024;                                                                        // allow:raw-byte-literal — 8 KiB short-command cap
    var MEDIUM_B  = 1024 * 1024;                                                                     // allow:raw-byte-literal — 1 MiB medium-command cap
    var LONG_B    = 16 * 1024 * 1024;                                                                // allow:raw-byte-literal — 16 MiB PUTSCRIPT cap
    var defaults = {
      CAPABILITY:   { fn: function (s, so)    { return _handleCapability(s, so); },
                      maxHandlerBytes: SHORT_B,  maxHandlerMs: SHORT_MS },
      NOOP:         { fn: function (s, so, p) { return _handleNoop(s, so, p); },
                      maxHandlerBytes: SHORT_B,  maxHandlerMs: SHORT_MS },
      STARTTLS:     { fn: function (s, so)    { return _handleStartTls(s, so); },
                      maxHandlerBytes: SHORT_B,  maxHandlerMs: SHORT_MS },
      LOGOUT:       { fn: function (s, so)    { return _handleLogout(s, so); },
                      maxHandlerBytes: SHORT_B,  maxHandlerMs: SHORT_MS },
      AUTHENTICATE: { fn: function (s, so, p) { return _handleAuthenticate(s, so, p); },
                      maxHandlerBytes: MEDIUM_B, maxHandlerMs: MEDIUM_MS },
      HAVESPACE:    { fn: function (s, so, p) { return _handleHaveSpace(s, so, p); },
                      maxHandlerBytes: SHORT_B,  maxHandlerMs: SHORT_MS },
      PUTSCRIPT:    { fn: function (s, so, p) { return _handlePutScript(s, so, p); },
                      maxHandlerBytes: LONG_B,   maxHandlerMs: LONG_MS },
      LISTSCRIPTS:  { fn: function (s, so)    { return _handleListScripts(s, so); },
                      maxHandlerBytes: MEDIUM_B, maxHandlerMs: MEDIUM_MS },
      SETACTIVE:    { fn: function (s, so, p) { return _handleSetActive(s, so, p); },
                      maxHandlerBytes: SHORT_B,  maxHandlerMs: SHORT_MS },
      GETSCRIPT:    { fn: function (s, so, p) { return _handleGetScript(s, so, p); },
                      maxHandlerBytes: LONG_B,   maxHandlerMs: LONG_MS },
      DELETESCRIPT: { fn: function (s, so, p) { return _handleDeleteScript(s, so, p); },
                      maxHandlerBytes: SHORT_B,  maxHandlerMs: SHORT_MS },
      RENAMESCRIPT: { fn: function (s, so, p) { return _handleRenameScript(s, so, p); },
                      maxHandlerBytes: SHORT_B,  maxHandlerMs: SHORT_MS },
    };
    _registry = mailServerRegistry.create({
      protocol:        "managesieve",
      defaults:        defaults,
      overrides:       opts.overrides || {},
      // b.agent.tenant adoption (v0.10.12) — see imap factory for the
      // shape.
      tenantScope:     opts.tenantScope    || null,
      agentTenantId:   opts.agentTenantId  || null,
      notFoundHandler: function (verb, _state, socket) {
        return _writeNo(socket, "Unknown verb '" + verb + "'");
      },
    });
    return _registry;
  }

  function _dispatch(state, socket, parsed) {
    return _ensureRegistry().dispatch(parsed.verb, state, socket, parsed);
  }

  // _emitCapabilityBanner — RFC 5804 §1.7 capability banner. Lines
  // are quoted-string identifiers, optionally followed by a quoted-
  // string value. The framework emits IMPLEMENTATION / SASL / SIEVE /
  // VERSION / STARTTLS (when pre-TLS) — no terminator line; the
  // listener emits a closing `OK` per §1.7.
  function _emitCapabilityBanner(state, socket) {
    socket.write('"IMPLEMENTATION" "blamejs"\r\n');
    socket.write('"VERSION" "1.0"\r\n');
    // Advertise the Sieve extensions safeSieve currently implements.
    // Keep in lockstep with safeSieve.KNOWN_CAPABILITIES — any entry
    // with `true` is exposed.
    var sieveCaps = [];
    var known = safeSieve.KNOWN_CAPABILITIES;
    var names = Object.keys(known);
    for (var i = 0; i < names.length; i += 1) {
      if (known[names[i]] === true && names[i].indexOf("comparator-") !== 0) {
        sieveCaps.push(names[i]);
      }
    }
    socket.write('"SIEVE" "' + sieveCaps.join(" ") + '"\r\n');
    // Advertise SASL mechanisms — ONLY the mechs the operator wired
    // in opts.auth.mechanisms (do not hardcode the advertised mechanisms).
    if (authConfig && Array.isArray(authConfig.mechanisms) && authConfig.mechanisms.length > 0) {
      var mechs = authConfig.mechanisms.map(function (m) {
        return String(m).toUpperCase();
      }).join(" ");
      socket.write('"SASL" "' + mechs + '"\r\n');
    } else {
      socket.write('"SASL" ""\r\n');
    }
    if (!state.tls && _tlsContext()) {
      socket.write('"STARTTLS"\r\n');
    }
  }

  function _handleCapability(state, socket) {
    _emitCapabilityBanner(state, socket);
    _writeOk(socket, "Capability completed");
  }

  function _handleNoop(state, socket, parsed) {
    void state;
    if (parsed.args.length > 0) {
      _writeOkWithTag(socket, parsed.args[0], "NOOP completed");
    } else {
      _writeOk(socket, "NOOP completed");
    }
  }

  function _handleStartTls(state, socket) {
    // RFC 8314 §3.3 — the command has no meaning on a port that is TLS from
    // the first byte; naming the port says which it is rather than leaving
    // "already negotiated" to read as a client bug.
    if (implicitTls) {
      _writeNo(socket, "STARTTLS not available on implicit-TLS port (RFC 8314)");
      return;
    }
    if (state.tls) {
      _writeNo(socket, "STARTTLS already negotiated");
      return;
    }
    if (state.stage !== "not-authenticated") {
      _writeNo(socket, "STARTTLS only valid pre-AUTH (RFC 5804 §2.2)");
      return;
    }
    var startTlsContext = _tlsContext();
    if (!startTlsContext) {
      _writeNo(socket, "STARTTLS unavailable (listener configured with allowPlaintext=true and no tlsContext)");
      return;
    }
    _writeOk(socket, "Begin TLS negotiation now");
    // RFC 5804 §2.2 — discard any bytes the client queued before the
    // upgrade (lineBuffer + pendingLiteral + pendingAuth) so pre-
    // handshake injection can't survive into the post-TLS session.
    // The shared upgradeLineProtocol helper owns that drain plus the
    // CVE-2021-33515 / CVE-2021-38371 listener-strip + pause + read-pump.
    mailServerTls.upgradeLineProtocol({
      state:         state,
      socket:        socket,
      secureContext: startTlsContext,
      idleTimeoutMs: idleTimeoutMs,
      clearFields:   ["pendingLiteral", "pendingAuth"],
      drain:         _drainBuffer,
      // Post-STARTTLS idle teardown MUST be TLS-aware — upgradeSocket strips the
      // plain-socket timeout handler, so without this the upgraded session would
      // never idle out (RFC 5804 BYE) and could stay open indefinitely.
      // The session, not just the socket. A close that does not mark the stage
      // leaves the pump's guard with nothing to read, so a handler that was
      // already running resumes and executes whatever the peer had queued
      // behind it, after the connection was torn down.
      onTimeout: function (tlsSocket) {
        _writeBye(tlsSocket, "Idle timeout");
        _close(tlsSocket, state);
      },
      onSecure: function (tlsSocket) {
        _emit("mail.server.managesieve.starttls_upgraded",
          { connectionId: state.id });
        // RFC 5804 §2.2 — server MUST re-emit capabilities on the
        // post-TLS socket so the client sees the post-TLS mechanism
        // list (which may now include PLAIN, etc.).
        _emitCapabilityBanner(state, tlsSocket);
        _writeOk(tlsSocket, "TLS negotiation successful");
      },
      onError: function (err) {
        _emit("mail.server.managesieve.starttls_handshake_failed",
          { connectionId: state.id, error: (err && err.message) || String(err) }, "failure");
        _close(socket, state);
      },
    });
  }

  function _handleLogout(state, socket) {
    _emit("mail.server.managesieve.logout",
      { connectionId: state.id });
    _writeOk(socket, "Logout completed");
    _close(socket, state);
  }

  function _handleAuthenticate(state, socket, parsed) {
    if (state.stage !== "not-authenticated") {
      _writeNo(socket, "AUTHENTICATE only valid in NOT-AUTHENTICATED");
      return;
    }
    if (!authConfig || typeof authConfig.verify !== "function") {
      _writeNo(socket, "AUTHENTICATE not configured on this listener");
      return;
    }
    var mech = parsed.args[0];
    var advertised = (authConfig.mechanisms || []).map(function (m) {
      return String(m).toUpperCase();
    });
    if (advertised.indexOf(mech) === -1) {
      _writeNo(socket, "Mechanism '" + mech + "' not advertised");
      return;
    }
    // Defense-in-depth: re-check cleartext refusal at the dispatch
    // boundary even though the validator already gated it (operator
    // could have configured a relaxed profile but the listener still
    // wants to enforce strict at AUTH).
    if (!state.tls && profile === "strict" && mech !== "EXTERNAL") {
      _emit("mail.server.managesieve.auth_refused_cleartext",
        { connectionId: state.id, mech: mech }, "denied");
      _writeNo(socket, "AUTHENTICATE " + mech +
        " refused over cleartext (use STARTTLS first; RFC 5804 §1.1 + RFC 4954 §4)");
      return;
    }
    var authAdmit = rateLimit.checkAuthAdmit(state.remoteAddress);
    if (!authAdmit.ok) {
      _emit("mail.server.managesieve.auth_rate_limit_refused",
        { connectionId: state.id, remoteAddress: state.remoteAddress, reason: authAdmit.reason },
        "denied");
      _writeNo(socket, "Too many AUTH failures from your IP");
      _close(socket, state);
      return;
    }
    state.pendingAuth = {
      mech:    mech,
      irBytes: parsed.literalBytes,
      irPlus:  parsed.literalPlus,
      // RFC 5804 §2.1 lets the initial response come inline as a quoted string
      // instead of a literal. It arrives complete on this line, so there is
      // nothing to wait for — the exchange runs now, with the response the
      // client actually sent. This used to fall through to the no-initial-
      // response branch and answer a conforming client as though it had said
      // nothing.
      irBody:  parsed.initialResponse === null || parsed.initialResponse === undefined
        ? Buffer.alloc(0)
        : Buffer.from(parsed.initialResponse, "utf8"),
    };
    // An AUTHENTICATE initial response arriving as a literal is a transfer
    // like any other, and it is the PRE-AUTHENTICATION one — so it is the
    // trickle that matters most. The rate window opens here for the same
    // reason it opens on a PUTSCRIPT literal.
    if (parsed.literalBytes !== null) {
      // Baseline at the byte position where the OPENER ends — see the IMAP
      // twin: wireBytes counts the whole chunk before the drain runs, so
      // payload arriving alongside the opener would be folded into the
      // baseline and never credited to the sender that already sent it.
      state.bodyRateWindow.start(time.monotonicMs(), state.wireBytes - state.lineBuffer.length);
      _armLiteralDeadline(state, socket);
    }
    if (parsed.literalBytes === null) {
      // Either an inline initial response, complete above, or none at all —
      // in which case verify is called with an empty client response.
      return _completeAuthenticate(state, socket);
    }
    if (!parsed.literalPlus) {
      // Synchronizing literal — server sends continuation request
      // before client transmits the bytes.
      socket.write("OK\r\n");
    }
    // Loop drains the literal-IR bytes; _completeAuthenticate runs
    // after.
  }

  // `{N}` / `{N+}` on a line of its own, the RFC 5804 §1.2 literal form of a
  // string. Returns null for anything else. Scanned rather than matched so the
  // digit run is bounded by the line the caller already length-capped.
  function _parseLiteralMarker(line) {
    if (line.length < 3 || line.charAt(0) !== "{") return null;
    var i = 1;
    var digits = "";
    while (i < line.length && line.charCodeAt(i) >= 0x30 && line.charCodeAt(i) <= 0x39) {
      digits += line.charAt(i);
      i += 1;
      if (digits.length > 9) return null;                                                               // absurd count: not a literal we will honour
    }
    if (digits.length === 0) return null;
    var plus = false;
    if (line.charAt(i) === "+") { plus = true; i += 1; }
    if (line.charAt(i) !== "}" || i !== line.length - 1) return null;
    return { bytes: Number(digits), plus: plus };
  }

  function _completeAuthenticate(state, socket) {
    var pa = state.pendingAuth;
    state.pendingAuth = null;
    _clearLiteralDeadline(state);
    if (!pa) return;
    // A literal carries octets, and a SASL token is base64, which is ASCII.
    // Decoding an undecodable byte substitutes U+FFFD, whose bytes are outside
    // the base64 alphabet and are therefore IGNORED when the token is decoded
    // -- so `AAAA<ff>BBBB` and `AAAABBBB` reach the verifier as the same
    // credential. Refuse the round rather than verify something the client did
    // not send.
    if (pa.irBody && !_decodesAsUtf8(pa.irBody)) {
      rateLimit.noteAuthFailure(state.remoteAddress);
      _emit("mail.server.managesieve.auth_failed",
        { connectionId: state.id, mech: pa.mech, reason: "response-not-utf8" }, "denied");
      _writeNo(socket, "Authentication response is not valid UTF-8");
      return;
    }
    // Resuming a live exchange: the step counter and mechanism carry over, and
    // no new auth_attempt is emitted — this is the same attempt, one round on.
    if (pa.resume && state.saslExchange) {
      return _runAuthStep(state, socket, pa.irBody.toString("utf8"));
    }
    _emit("mail.server.managesieve.auth_attempt",
      { connectionId: state.id, mech: pa.mech, remoteAddress: state.remoteAddress });
    state.saslExchange = { mech: pa.mech, step: 0 };
    return _runAuthStep(state, socket,
      pa.irBody.length > 0 ? pa.irBody.toString("utf8") : null);
  }

  // One round of a SASL exchange (RFC 5804 §2.1). The verifier may answer with
  // `{ pending: true, challenge }` to ask for another client response, as it
  // may on the IMAP, POP3 and submission listeners. ManageSieve used to call
  // verify once with no `step`, so a pending verdict landed in the failure
  // branch — and spent the client's authentication-failure budget for what is a
  // normal protocol round trip, weakening the very defence that budget exists
  // to provide.
  function _runAuthStep(state, socket, clientResponse) {
    var ex = state.saslExchange;
    function _fail(reason) {
      state.saslExchange = null;
      rateLimit.noteAuthFailure(state.remoteAddress);
      _emit("mail.server.managesieve.auth_failed",
        { connectionId: state.id, mech: ex.mech, reason: reason }, "denied");
      _writeNo(socket, "Authentication failed");
    }
    return mailServerNet.runSaslStep({
      exchange:       ex,
      verify:         authConfig.verify,
      credentials:    { tls: state.tls, remoteAddress: state.remoteAddress },
      clientResponse: clientResponse,
      writeChallenge: function (ch) { return _writeChallenge(socket, ch); },
      onChallengeUnsafe: function () { _fail("challenge-contains-line-terminator"); },
      onSuccess: function (result) {
        state.saslExchange = null;
        state.actor = result.actor;
        state.stage = "authenticated";
        _emit("mail.server.managesieve.auth_success",
          { connectionId: state.id, mech: ex.mech, tenantId: state.actor.tenantId || null });
        _writeOk(socket, "Authenticated");
      },
      onFailure: function (result) { _fail((result && result.reason) || "verify-returned-fail"); },
      onError:   function (err) { _fail((err && err.message) || String(err)); },
    });
  }

  // RFC 5804 §2.1 — the server's SASL challenge is sent as a literal:
  // `{N}\r\n<challenge>\r\n`. Returns false when the challenge carries bytes
  // that would end the line, so the caller fails the exchange rather than
  // emitting a second, smuggled protocol line.
  function _writeChallenge(socket, challenge) {
    var safe = mailServerNet.saslChallengeOrNull(challenge);
    if (safe === null) return false;
    try { socket.write("{" + Buffer.byteLength(safe, "utf8") + "}\r\n" + safe + "\r\n"); }
    catch (_e) { /* socket down */ }
    return true;
  }

  // The client's reply to a challenge, per RFC 5804 §1.2 "string": a quoted
  // string, or (accepted defensively) a bare token. `"*"` cancels the exchange
  // — a withdrawal rather than a failed credential, so it costs no budget.
  function _continueSaslExchange(state, socket, line) {
    // RFC 5804 §1.2 — a "string" is a quoted string OR a literal. A SASL
    // response is base64 and can be long, which is exactly when a client
    // reaches for the literal form, and reading `{N+}` as the response itself
    // then reading its bytes as a second response cannot authenticate anyone.
    // The bytes are collected by the same drain-loop branch the initial
    // AUTHENTICATE response uses, and `resume` tells _completeAuthenticate to
    // continue this exchange rather than start a new one at step 0.
    var lit = _parseLiteralMarker(line);
    if (lit) {
      // The client declaring this size is unauthenticated, and the drain loop
      // will collect toward it. Unbounded, `{999999999+}` both consumes memory
      // and pins the connection open waiting for bytes that never arrive.
      //
      // The bound is the guard's own SASL-token cap, the same one it applies to
      // the AUTHENTICATE initial response. One exchange, one bound, whichever
      // round the token arrives on: two numbers for the same thing is how the
      // two halves of a protocol drift apart.
      if (lit.bytes > guardManageSieveCommand.MAX_SASL_TOKEN_BYTES) {
        var oversizeMech = state.saslExchange.mech;
        state.saslExchange = null;
        rateLimit.noteAuthFailure(state.remoteAddress);
        _emit("mail.server.managesieve.auth_failed",
          { connectionId: state.id, mech: oversizeMech,
            reason: "continuation-literal-too-large" }, "denied");
        _writeNo(socket, "Authentication response too long (cap " +
          guardManageSieveCommand.MAX_SASL_TOKEN_BYTES + ")");
        return;
      }
      state.pendingAuth = {
        mech:    state.saslExchange.mech,
        irBytes: lit.bytes,
        irPlus:  lit.plus,
        irBody:  Buffer.alloc(0),
        resume:  true,
      };
      // The third place a literal transfer opens, and it needs its own window
      // like the other two. A multi-step exchange that reused the window from
      // the FIRST literal measured every later step against a start time that
      // had already elapsed, so a healthy continuation read as starved.
      // Baseline at the byte position where the OPENER ends — see the IMAP
      // twin: wireBytes counts the whole chunk before the drain runs, so
      // payload arriving alongside the opener would be folded into the
      // baseline and never credited to the sender that already sent it.
      state.bodyRateWindow.start(time.monotonicMs(), state.wireBytes - state.lineBuffer.length);
      _armLiteralDeadline(state, socket);
      // Synchronizing form: the server invites the bytes before the client
      // sends them, exactly as it does for an initial-response literal.
      if (!lit.plus) socket.write("OK\r\n");
      return;
    }
    // The guard owns the quoted form of the same production — escapes
    // included, and NUL / CR / LF refused inside the quotes. A bare token is
    // accepted defensively for clients that omit the quoting.
    var quoted = guardManageSieveCommand.parseQuotedString(line);
    var body = quoted ? quoted.value : line;
    if (body === "*") {
      state.saslExchange = null;
      _writeNo(socket, "Authentication cancelled");
      return undefined;
    }
    return _runAuthStep(state, socket, body);
  }

  function _requireAuth(state, socket) {
    if (state.stage !== "authenticated") {
      _writeNo(socket, "AUTHENTICATE first");
      return false;
    }
    return true;
  }

  function _handleHaveSpace(state, socket, parsed) {
    if (!_requireAuth(state, socket)) return;
    var name = parsed.args[0];
    var size = parsed.args[1];
    return Promise.resolve()
      .then(function () { return mailStore.sieveScripts.haveSpace(state.actor, name, size); })
      .then(function (result) {
        var ok = result && result.ok !== false;
        _emit("mail.server.managesieve.havespace",
          { connectionId: state.id, name: name, size: size, ok: ok });
        if (ok) {
          _writeOk(socket, "Have space");
        } else {
          _writeNo(socket, "(QUOTA/MAXSIZE) " + ((result && result.reason) || "no space"));
        }
      })
      .catch(function (err) {
        _writeNo(socket, ((err && err.message) || "haveSpace failed").slice(0, ERR_CLAMP));
      });
  }

  function _handlePutScript(state, socket, parsed) {
    if (!_requireAuth(state, socket)) return;
    var name = parsed.args[0];
    var size = parsed.literalBytes;
    var plus = parsed.literalPlus;
    state.pendingLiteral = {
      verb: "PUTSCRIPT",
      name: name,
      size: size,
      plus: plus,
      body: Buffer.alloc(0),
    };
    // The rate window opens where the commitment is made, with the
    // connection's running total as its baseline, so the transfer is measured
    // rather than the connection's whole life.
    state.bodyRateWindow.start(time.monotonicMs(), state.wireBytes - state.lineBuffer.length);
    _armLiteralDeadline(state, socket);
    if (!plus) {
      // Synchronizing literal — RFC 5804 §2.3: server sends
      // continuation before client transmits payload.
      socket.write("OK\r\n");
    }
    // _completePutscript runs after the literal is fully drained.
  }

  function _completePutscript(state, socket, literal) {
    var bodyText = literal.body.toString("utf8");
    // The octet is gone before any validation runs, so what gets validated and
    // stored is a repaired copy: a script two octets longer than the one the
    // client sent, under an OK reply, with nothing to say it changed. A Sieve
    // script decides what is filed, forwarded and discarded, so a byte altered
    // inside a string, a header name or an address changes what the rule does.
    // RFC 5804 section 2.3 requires the script to be verified before it is
    // accepted, and verifying a repaired copy is not verifying what arrived.
    if (!_decodesAsUtf8(literal.body)) {
      _emit("mail.server.managesieve.putscript_refused",
        { connectionId: state.id, name: literal.name,
          reason: "script-not-utf8" }, "denied");
      _writeNo(socket, "Script is not valid UTF-8 (RFC 5804 section 1.6)");
      return;
    }
    // RFC 5804 §2.3 — implementation MUST verify script validity
    // before accepting it. Refuse with the safeSieve issue code so
    // operators can correlate refusals to specific parse errors.
    var v;
    try {
      v = safeSieve.validate(bodyText, { profile: safeSieveProfile });
    } catch (e) {
      _emit("mail.server.managesieve.putscript_refused",
        { connectionId: state.id, name: literal.name,
          reason: (e && e.code) || "safe-sieve/parse-error" }, "denied");
      _writeNo(socket, "(QUOTA/MAXSIZE) " + ((e && e.message) || "validation failed").slice(0, ERR_CLAMP));
      return;
    }
    if (!v.ok) {
      var issue = (v.issues && v.issues[0]) || { ruleId: "safe-sieve/parse-error", snippet: "invalid" };
      _emit("mail.server.managesieve.putscript_refused",
        { connectionId: state.id, name: literal.name, reason: issue.ruleId }, "denied");
      _writeNo(socket, "Script validation failed: " + (issue.snippet || issue.ruleId).slice(0, ERR_CLAMP));
      return;
    }
    return Promise.resolve()
      .then(function () {
        return mailStore.sieveScripts.put(state.actor, literal.name, bodyText, {
          requiredCaps: v.requiredCaps,
        });
      })
      .then(function () {
        _emit("mail.server.managesieve.putscript",
          { connectionId: state.id, name: literal.name, bytes: literal.size,
            requiredCaps: v.requiredCaps });
        _writeOk(socket, "PUTSCRIPT completed");
      })
      .catch(function (err) {
        _writeNo(socket, ((err && err.message) || "PUTSCRIPT failed").slice(0, ERR_CLAMP));
      });
  }

  function _handleListScripts(state, socket) {
    if (!_requireAuth(state, socket)) return;
    return Promise.resolve()
      .then(function () { return mailStore.sieveScripts.list(state.actor); })
      .then(function (scripts) {
        var list = Array.isArray(scripts) ? scripts : [];
        for (var i = 0; i < list.length; i += 1) {
          var s = list[i];
          var nm = String(s.name || "");
          var active = s.active === true ? " ACTIVE" : "";
          socket.write(safeBuffer.quoteString(nm) + active + "\r\n");
        }
        _emit("mail.server.managesieve.listscripts",
          { connectionId: state.id, count: list.length });
        _writeOk(socket, "LISTSCRIPTS completed");
      })
      .catch(function (err) {
        _writeNo(socket, ((err && err.message) || "LISTSCRIPTS failed").slice(0, ERR_CLAMP));
      });
  }

  function _handleSetActive(state, socket, parsed) {
    if (!_requireAuth(state, socket)) return;
    var name = parsed.args[0];
    return Promise.resolve()
      .then(function () { return mailStore.sieveScripts.setActive(state.actor, name); })
      .then(function () {
        _emit("mail.server.managesieve.setactive",
          { connectionId: state.id, name: name });
        _writeOk(socket, "SETACTIVE completed");
      })
      .catch(function (err) {
        _writeNo(socket, ((err && err.message) || "SETACTIVE failed").slice(0, ERR_CLAMP));
      });
  }

  function _handleGetScript(state, socket, parsed) {
    if (!_requireAuth(state, socket)) return;
    var name = parsed.args[0];
    return Promise.resolve()
      .then(function () { return mailStore.sieveScripts.get(state.actor, name); })
      .then(function (script) {
        if (!script) {
          _writeNo(socket, "(NONEXISTENT) Script not found");
          return;
        }
        var body = String(script.body || "");
        var bytes = Buffer.byteLength(body, "utf8");
        // RFC 5804 §2.9 — return the script as a synchronizing
        // literal followed by the body and CRLF, then OK.
        socket.write("{" + bytes + "}\r\n");
        socket.write(body);
        if (!body.endsWith("\r\n")) socket.write("\r\n");
        _emit("mail.server.managesieve.getscript",
          { connectionId: state.id, name: name, bytes: bytes });
        _writeOk(socket, "GETSCRIPT completed");
      })
      .catch(function (err) {
        _writeNo(socket, ((err && err.message) || "GETSCRIPT failed").slice(0, ERR_CLAMP));
      });
  }

  function _handleDeleteScript(state, socket, parsed) {
    if (!_requireAuth(state, socket)) return;
    var name = parsed.args[0];
    return Promise.resolve()
      .then(function () { return mailStore.sieveScripts.delete(state.actor, name); })
      .then(function () {
        _emit("mail.server.managesieve.delete",
          { connectionId: state.id, name: name });
        _writeOk(socket, "DELETESCRIPT completed");
      })
      .catch(function (err) {
        _writeNo(socket, ((err && err.message) || "DELETESCRIPT failed").slice(0, ERR_CLAMP));
      });
  }

  function _handleRenameScript(state, socket, parsed) {
    if (!_requireAuth(state, socket)) return;
    var oldName = parsed.args[0];
    var newName = parsed.args[1];
    return Promise.resolve()
      .then(function () { return mailStore.sieveScripts.rename(state.actor, oldName, newName); })
      .then(function () {
        _emit("mail.server.managesieve.rename",
          { connectionId: state.id, old: oldName, "new": newName });
        _writeOk(socket, "RENAMESCRIPT completed");
      })
      .catch(function (err) {
        _writeNo(socket, ((err && err.message) || "RENAMESCRIPT failed").slice(0, ERR_CLAMP));
      });
  }

  // RFC 5804 §1.2 quoted strings — serialization routes through
  // safeBuffer.quoteString (one quoted-string escaper framework-wide).
  function _writeOk(socket, msg) {
    try { socket.write("OK " + safeBuffer.quoteString(msg) + "\r\n"); } catch (_e) { /* socket down */ }
  }
  function _writeOkWithTag(socket, tag, msg) {
    try { socket.write("OK (TAG " + safeBuffer.quoteString(tag) + ") " + safeBuffer.quoteString(msg) + "\r\n"); }
    catch (_e) { /* socket down */ }
  }
  function _writeNo(socket, msg) {
    try { socket.write("NO " + safeBuffer.quoteString(msg) + "\r\n"); } catch (_e) { /* socket down */ }
  }
  function _writeBye(socket, msg) {
    try { socket.write("BYE " + safeBuffer.quoteString(msg) + "\r\n"); } catch (_e) { /* socket down */ }
  }
  function _close(socket, state) {
    // The reader's guard is only reachable if closing writes the marker.
    // Without it a refusal that destroys the socket left
    // the pump alive: when the handler it was waiting on settled, the
    // continuation resumed and ran whatever the client had already queued --
    // a DELETESCRIPT executing on a connection the server had refused and
    // closed. Clearing the buffer as well so nothing is left to resume with.
    // Its own field, not a `stage` value: `stage` is the protocol position and
    // a handler assigns it -- "authenticated" once a login resolves -- so a
    // close landing while one was in flight was overwritten by the
    // continuation and the reader went back to the buffer the close refused.
    if (state) {
      state.closed = true;
      state.lineBuffer = Buffer.alloc(0);
    }
    try { socket.end(); } catch (_e) { /* idempotent */ }
    try { socket.destroy(); } catch (_e2) { /* idempotent */ }
    connections.delete(socket);
  }

  // ---- Lifecycle ----------------------------------------------------------
  return mailServerNet.createStoreServer(net, {
    // RFC 5804 §1 names one port and no implicit-TLS sibling, so the mode
    // changes how the port speaks, not which port it is.
    defaultPort:      DEFAULT_PORT,
    listeningExtra:   function () { return { implicitTls: implicitTls }; },
    maxConnections:   opts.maxConnections,
    handleConnection: _handleConnection,
    errorClass:       MailServerManageSieveError,
    errorCodePrefix:  "mail-server-managesieve/",
    emit:             _emit,
    connections:      connections,
    eventBase:        "mail.server.managesieve",
  });
}

module.exports = {
  create:                       create,
  MailServerManageSieveError:   MailServerManageSieveError,
};
