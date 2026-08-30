// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     b.mail.server.pop3
 * @nav        Mail
 * @title      Mail POP3 Server
 * @order      550
 *
 * @intro
 *   POP3 mailbox-access listener (RFC 1939 + RFC 2449 capabilities +
 *   RFC 2595 STLS + RFC 5034 SASL AUTH). Opt-in legacy fallback for
 *   MUAs that don't speak IMAP — the framework's blamepost roadmap
 *   makes JMAP primary and IMAP/POP3 opt-ins; this listener exists
 *   so operators with last-decade MUAs (older Outlook profiles,
 *   legacy mobile clients, simple device firmware) can still
 *   authenticate + pull messages.
 *
 *   ## State machine (RFC 1939 §3)
 *
 *   ```
 *   AUTHORIZATION → TRANSACTION → UPDATE → (close)
 *   ```
 *
 *   - **AUTHORIZATION**: STLS / CAPA / USER / PASS / APOP / AUTH /
 *     QUIT. After successful USER+PASS / APOP / AUTH the connection
 *     enters TRANSACTION.
 *   - **TRANSACTION**: STAT / LIST / RETR / DELE / NOOP / RSET / TOP /
 *     UIDL / QUIT. DELE marks messages for deletion; actual deletion
 *     happens in UPDATE state on QUIT.
 *   - **UPDATE**: triggered by QUIT from TRANSACTION; the listener
 *     calls `mailStore.commitPop3Drop(actor, dropId)` to apply the
 *     pending deletes atomically, then closes.
 *
 *   ## Wire-protocol defenses
 *
 *   - **Cleartext-auth refusal under strict** — RFC 1939 USER/PASS
 *     sends the password in plaintext. Strict + balanced profiles
 *     refuse USER/PASS pre-TLS; operators with legacy clients pass
 *     `profile: "permissive"`.
 *
 *   - **STLS injection (CVE-2021-33515 class)** — STLS upgrade clears
 *     pre-handshake receive buffer; any pipelined command queued
 *     before TLS is dropped.
 *
 *   - **APOP refusal under strict** — RFC 1939 §7 APOP uses MD5
 *     challenge-response. M³AAWG / NIST SP 800-131A r2 phase out
 *     MD5; the strict profile refuses APOP.
 *
 *   - **Per-IP rate limit + AUTH-failure budget** — composes
 *     `b.mail.server.rateLimit` (default-on). The submission listener's
 *     `authFailuresPerIpPer15Min` cap applies to USER+PASS / APOP /
 *     AUTH refusals.
 *
 *   - **Slow-loris** — per-connection `idleTimeoutMs` bounds a peer that
 *     stops making progress, in either direction: a client that sends no
 *     further command, and one that stops taking a RETR / TOP response.
 *     `maxLineBytes` bounds a command line that never ends.
 *
 *   ## Audit lifecycle
 *
 *   - `mail.server.pop3.connect`             — IP, TLS state
 *   - `mail.server.pop3.auth_attempt`        — verb, actor-hash
 *   - `mail.server.pop3.auth_success`        — verb, tenantId
 *   - `mail.server.pop3.auth_failed`         — verb, reason
 *   - `mail.server.pop3.auth_rate_limit_refused`
 *   - `mail.server.pop3.transaction_start`   — drop count, total size
 *   - `mail.server.pop3.retr`                — msg-num
 *   - `mail.server.pop3.dele`                — msg-num (marked-for-delete)
 *   - `mail.server.pop3.update_commit`       — final-deleted count
 *   - `mail.server.pop3.rate_limit_refused`  — IP, reason
 *
 *   ## What v1 does NOT ship
 *
 *   - **APOP** — refused under strict + balanced; permissive opts in.
 *     APOP uses MD5; modern deployments use TLS + USER/PASS or SASL
 *     instead.
 *   - **SASL mechanisms beyond PLAIN** — CRAM-MD5 / SCRAM-SHA-256 /
 *     OAUTHBEARER all wire through operator's `auth.verify`. v1
 *     advertises PLAIN only; operators add via `auth.mechanisms`.
 *   - **Multi-step SASL exchange** — single-step PLAIN is sufficient
 *     for the v1 surface; SCRAM round-trip ships when an operator
 *     surfaces demand.
 *   - **Per-message lock** — POP3 has no native message-id beyond
 *     UIDL; concurrent connections from the same actor compete via
 *     `mailStore.openPop3Drop({ exclusive: true })`.
 *
 *   ## Composition contract
 *
 *   - `b.guardPop3Command` — wire-protocol gate
 *   - `b.mail.server.rateLimit` — DoS defense
 *   - `b.mailStore` — operator-supplied backend (must expose
 *     `openPop3Drop(actor, opts)` / `commitPop3Drop(actor, dropId)` /
 *     `getMessage(actor, dropId, msgNum, { headersOnly?, headerLines? })` /
 *     `listMessages(actor, dropId)` / `markDelete(actor, dropId, msgNum)`)
 *   - operator's `auth.verify(mechanism, credentials)` async predicate
 *   - `b.network.tls.context` — TLS posture
 *
 * @card
 *   POP3 mailbox-access listener (RFC 1939 + RFC 2449 + RFC 2595 +
 *   RFC 5034). Opt-in legacy fallback; state machine AUTH → TRANS →
 *   UPDATE. Composes b.guardPop3Command + b.mail.server.rateLimit +
 *   operator-supplied mailStore + SASL authenticator. STLS-injection
 *   defense + AUTH-failure budget + cleartext-auth refusal under
 *   strict.
 */

var net = require("node:net");
var safeBuffer = require("./safe-buffer");
var C = require("./constants");
var numericBounds = require("./numeric-bounds");
var validateOpts = require("./validate-opts");
var guardPop3Command = require("./guard-pop3-command");
var mailServerRateLimit = require("./mail-server-rate-limit");
var mailServerTls = require("./mail-server-tls");
var mailServerNet = require("./mail-server-net");
var safeSmtp = require("./safe-smtp");
var safeAsync = require("./safe-async");
var { defineClass } = require("./framework-error");

var auditEmit = require("./audit-emit");

var MailServerPop3Error = defineClass("MailServerPop3Error", { alwaysPermanent: true });

var DEFAULT_MAX_LINE_BYTES   = 1024;                                                                  // RFC 2449 §4 line cap (permissive)
var DEFAULT_IDLE_TIMEOUT_MS  = C.TIME.minutes(10);
// RFC 1939 §6 — UPDATE-state commit (the actual delete on QUIT) is
// the only place the backend writes; a hung commitPop3Drop leaves
// the connection in update-state forever, defeating the idle timeout
// (the socket is awaiting the .then(), not blocked on socket I/O).
// Bound the commit; on timeout the connection closes with -ERR and
// the next session re-attempts the commit.
var DEFAULT_COMMIT_TIMEOUT_MS = C.TIME.seconds(30);
var DEFAULT_GREETING_VENDOR  = "blamejs POP3";

var ERR_CLAMP = 200;                                                                                  // protocol-reply error-message clamp

/**
 * @primitive b.mail.server.pop3.create
 * @signature b.mail.server.pop3.create(opts)
 * @since     0.9.52
 * @status    stable
 * @related   b.mail.server.imap.create, b.mail.server.submission.create, b.mailStore.create
 *
 * Build a POP3 listener (RFC 1939). Returns a handle exposing
 * `listen({ port, address })` and `close()`. POP3 is opt-in legacy —
 * deployments should prefer `b.mail.server.imap` + `b.mail.server.jmap`
 * for new MUAs.
 *
 * @opts
 *   tlsContext:        SecureContext,           // required (no plaintext)
 *   implicitTls:       boolean,                 // RFC 8314 §3 — TLS from the SYN on 995 (the default port becomes 995). STLS is neither advertised nor accepted on it. Default false
 *   greeting:          string,                   // default "blamejs POP3"
 *   maxLineBytes:      number,                   // default 1024
 *   idleTimeoutMs:     number,                   // default 10 min
 *   maxConnections:    number,                   // default 1024 — listener-wide ceiling
 *   commitTimeoutMs:   number,                   // default 30 s (UPDATE-state mailStore.commitPop3Drop cap)
 *   profile:           "strict" | "balanced" | "permissive",
 *   auth: {
 *     mechanisms:      ["PLAIN"],                 // SASL mechs to advertise
 *     verify:          async function (mech, credentials) → { ok, actor },
 *   },
 *   mailStore:         b.mailStore handle,
 *   onSessionEnd:      function (actor, sessionId),         // optional. Fired once when the session ends by ANY route — QUIT, idle timeout, or a link that dropped without one. A maildrop is leased to one session (RFC 1939 §3), and this is the signal to release it; without it the only release available is a timer, which cannot tell a finished session from a slow one and locks the account holder out of their own mailbox after a network blip
 *   onSessionActivity: function (actor, sessionId, verb),   // optional. Fired for every command, NOOP included — the listener answers NOOP itself, so a consumer ageing an idle lease would otherwise never see the keepalive the protocol defines for it and would reap the lease under a live connection
 *   rateLimit:         b.mail.server.rateLimit handle | opts | false,
 *   audit:             b.audit
 *
 * @example
 *   var pop3 = b.mail.server.pop3.create({
 *     tlsContext: b.mail.server.tls.context({ certFile, keyFile }).secureContext,
 *     auth: {
 *       mechanisms: ["PLAIN"],
 *       verify:     async function (mech, creds) {
 *         return { ok: true, actor: { username: creds.authzid, tenantId: "t1" } };
 *       },
 *     },
 *     mailStore: b.mailStore.create({ backend: b.db }),
 *   });
 *   await pop3.listen({ port: 110 });
 */
function create(opts) {
  validateOpts.requireObject(opts, "mail.server.pop3.create",
    MailServerPop3Error, "mail-server-pop3/bad-opts");
  if (!opts.tlsContext) {
    throw new MailServerPop3Error("mail-server-pop3/no-tls-context",
      "mail.server.pop3.create: tlsContext is required (no implicit plaintext mode). " +
      "Use b.mail.server.tls.context({ certFile, keyFile, watch: true }).");
  }
  if (!opts.mailStore || typeof opts.mailStore.openPop3Drop !== "function") {
    throw new MailServerPop3Error("mail-server-pop3/no-mail-store",
      "mail.server.pop3.create: mailStore is required (must expose openPop3Drop/commitPop3Drop/" +
      "getMessage/listMessages/markDelete; compose b.mailStore.create or operator-supplied backend)");
  }
  numericBounds.requireAllPositiveFiniteIntIfPresent(opts,
    ["maxLineBytes", "idleTimeoutMs", "commitTimeoutMs", "maxConnections"],
    "mail.server.pop3.", MailServerPop3Error, "mail-server-pop3/bad-bound");

  var greeting        = opts.greeting        || DEFAULT_GREETING_VENDOR;
  var maxLineBytes    = opts.maxLineBytes    || DEFAULT_MAX_LINE_BYTES;
  var idleTimeoutMs   = opts.idleTimeoutMs   || DEFAULT_IDLE_TIMEOUT_MS;
  var commitTimeoutMs = opts.commitTimeoutMs || DEFAULT_COMMIT_TIMEOUT_MS;
  var profile         = opts.profile         || "strict";
  var authConfig      = opts.auth            || null;
  // RFC 8314 §3 — implicit TLS on 995, in preference to the in-band upgrade.
  // Off by default, so an existing composition on 110 is unaffected.
  var implicitTls     = opts.implicitTls === true;
  var mailStore       = opts.mailStore;
  // b.agent.tenant adoption (v0.10.12) — cross-tenant authentication
  // is refused at the AUTH-success boundary BEFORE the listener
  // accepts the actor into transaction state. The scope's `.check`
  // method is validated at create() time so a malformed scope object
  // surfaces as a configuration error rather than rejecting every
  // otherwise-valid auth as "cross-tenant".
  var tenantScope     = opts.tenantScope     || null;
  var agentTenantId   = opts.agentTenantId   || null;
  if (tenantScope && typeof tenantScope.check !== "function") {
    throw new MailServerPop3Error("mail-server-pop3/bad-tenant-scope",
      "create: opts.tenantScope must be a b.agent.tenant.create() instance " +
      "(missing .check); a malformed scope would refuse every auth as cross-tenant");
  }
  if (tenantScope && !agentTenantId) {
    throw new MailServerPop3Error("mail-server-pop3/no-agent-tenant-id",
      "create: opts.tenantScope requires opts.agentTenantId");
  }

  function _assertTenantOrRefuse(state, socket, result) {
    if (!tenantScope || !agentTenantId) return true;
    try { tenantScope.check(result.actor, agentTenantId); return true; }
    catch (tenantErr) {
      _emit("mail.server.pop3.cross_tenant_refused",
        { connectionId: state.id,
          actorTenant:  (result.actor && result.actor.tenantId) || null,
          agentTenant:  agentTenantId,
          code:         (tenantErr && tenantErr.code) || null },
        "denied");
      _writeErr(socket, "Authentication rejected (cross-tenant)");
      return false;
    }
  }

  var rateLimit = mailServerRateLimit.resolve(opts.rateLimit);

  var connections = new Set();

  var _emit = auditEmit.emit;

  // Session-lifecycle hooks. Optional, absent by default, and no-ops when a
  // consumer supplies neither — nothing composed against the old surface
  // behaves differently.
  var onSessionEnd = validateOpts.definedFunction(opts.onSessionEnd,
    "b.mail.server.pop3.create: onSessionEnd", MailServerPop3Error, "mail-server-pop3/bad-opts");
  var onSessionActivity = validateOpts.definedFunction(opts.onSessionActivity,
    "b.mail.server.pop3.create: onSessionActivity", MailServerPop3Error, "mail-server-pop3/bad-opts");

  // Both are consumer hooks on a connection whose timing the consumer does not
  // control, so both go through mailServerNet.fireConsumerHook and DROP SILENT
  // — see it for why a throw here must not reach the teardown that caused it.
  //
  // Fired at most ONCE per session. A socket that errors and then closes emits
  // both, and a consumer releasing a lease by decrementing a holder count
  // would corrupt its own accounting on the second call.
  // The end is reported AFTER any store work still in flight, because a
  // consumer releasing the exclusive maildrop on this signal must not release
  // around one. A link that drops mid-open would otherwise be told the session
  // ended, and the open would then acquire a lease nothing ever reports the
  // end of; a link that drops mid-commit would let the next session in while
  // UPDATE is still mutating the mailbox. Waiting for the work to SETTLE
  // covers both — a failed open or commit ends the session just as a
  // successful one does.
  function _fireSessionEnd(state) {
    if (!onSessionEnd || state.sessionEndFired) return;
    // Claimed before the wait, not after: a socket that errors and then closes
    // would otherwise queue a second notification behind the same work.
    state.sessionEndFired = true;
    if (!state.storeWork) return _emitSessionEnd(state);
    state.storeWork.then(function () { _emitSessionEnd(state); },
      function () { _emitSessionEnd(state); });
  }

  // Every mail-store call this session makes goes through here, so the end
  // hook waits for ALL of them rather than for the two that were remembered.
  // A DELE or an RSET mutates the drop exactly as an open or a commit does: a
  // link that drops while one is in flight would otherwise report the session
  // ended, and the consumer would release the exclusive lease and admit the
  // next session while the previous one is still writing.
  //
  // Returns the promise it was given, so a call site's own .then / .catch
  // chain is unchanged and the tracking cannot be half-applied.
  function _storeWork(state, promise) {
    // Normalized before it is chained onto. Every current call site passes a
    // native promise, but the argument is whatever a mail-store method
    // returned, and chaining the session-end barrier onto a foreign thenable
    // would put the barrier at the mercy of that thenable's own then().
    var settled = Promise.resolve(promise)
      .catch(function () { /* the call site reports it */ });
    state.storeWork = state.storeWork
      ? state.storeWork.then(function () { return settled; }, function () { return settled; })
      : settled;
    return promise;
  }

  function _emitSessionEnd(state) {
    mailServerNet.fireConsumerHook(onSessionEnd, [state.actor, state.id],
      { emit: _emit, event: "mail.server.pop3.session_end_hook_failed", connectionId: state.id });
  }

  // Every command, NOOP included. NOOP is what the protocol offers a client as
  // a keepalive, and the listener answers it without touching the store — so a
  // consumer ageing a lease on its own idle accounting never saw the keepalive
  // and reaped the lease under a connection that was still in use.
  function _fireSessionActivity(state, verb) {
    mailServerNet.fireConsumerHook(onSessionActivity, [state.actor, state.id, verb],
      { emit: _emit, event: "mail.server.pop3.session_activity_hook_failed", connectionId: state.id });
  }

  function _handleConnection(rawSocket) {
    // Declared before the accept so the close hook can close over it: the
    // socket wiring is done there, and the state it has to report does not
    // exist until the connection id comes back from it.
    var state = null;
    var accepted = mailServerNet.acceptConnection(rawSocket, {
      rateLimit:    rateLimit,
      connections:  connections,
      emit:         _emit,
      refusedEvent: "mail.server.pop3.rate_limit_refused",
      refusalLine:  "-ERR Too many connections from your IP\r\n",
      idPrefix:     "pop3conn-",
      wrap:         mailServerTls.implicitTlsWrap(opts.tlsContext, implicitTls),
      // Every way a session can end arrives as the socket's close, including
      // the one that matters: a link that dropped without a QUIT. See
      // _fireSessionEnd for why a maildrop lease depends on hearing it.
      onClose:      function () {
        if (!state) return;
        // Marked before the end is reported, because work still in flight has
        // to be able to see that the session it belongs to is over — an
        // authentication that resolves after this point must not go on to
        // acquire a maildrop nothing will ever report the end of.
        state.closed = true;
        _fireSessionEnd(state);
      },
    });
    if (accepted === null) return;
    var remoteAddress = accepted.remoteAddress;
    var connectionId  = accepted.connectionId;
    var socket        = accepted.socket;

    state = {
      id:            connectionId,
      remoteAddress: remoteAddress,
      // Already encrypted on an implicit-TLS port, so the session opens with
      // what an STLS upgrade would otherwise have to establish.
      tls:           implicitTls,
      stage:         "authorization",
      actor:         null,
      tentativeUser: null,           // USER name pending PASS
      authPending:   null,           // in-flight multi-step SASL exchange (RFC 5034 §4)
      dropId:        null,           // mailStore-issued drop handle on TRANSACTION entry
      lineBuffer:    Buffer.alloc(0),
    };

    _emit("mail.server.pop3.connect",
      { connectionId: connectionId, remoteAddress: remoteAddress });

    socket.setTimeout(idleTimeoutMs);
    socket.on("timeout", function () {
      _writeErr(socket, "Idle timeout");
      _close(socket);
    });
    socket.on("error", function (err) {
      _emit("mail.server.pop3.socket_error",
        { connectionId: connectionId, error: (err && err.message) || String(err) }, "failure");
    });

    _writeOk(socket, greeting + " ready");

    socket.on("data", function (chunk) {
      state.lineBuffer = Buffer.concat([state.lineBuffer, chunk]);
      _drainBuffer(state, socket);
    });
  }

  function _drainBuffer(state, socket) {
    while (true) {
      var crlf = state.lineBuffer.indexOf("\r\n");
      if (crlf === -1) {
        if (safeBuffer.byteLengthOf(state.lineBuffer) > maxLineBytes) {
          _writeErr(socket, "Line too long (cap " + maxLineBytes + ")");
          _close(socket);
        }
        return;
      }
      var rawLine = state.lineBuffer.subarray(0, crlf).toString("utf8");
      state.lineBuffer = state.lineBuffer.subarray(crlf + 2);
      _handleLine(state, socket, rawLine);
      if (state.stage === "closed") return;
    }
  }

  function _handleLine(state, socket, line) {
    // Mid-SASL: the client's next line is a base64 response to the server's
    // challenge, not a POP3 verb, so it goes to the exchange rather than the
    // wire guard — which would refuse it as an unknown command. Same ordering
    // the submission listener uses for its own AUTH continuation.
    if (state.authPending) {
      _continueAuthExchange(state, socket, line);
      return;
    }
    var parsed;
    try {
      parsed = guardPop3Command.validate(line, {
        profile: profile,
        tls:     state.tls,
      });
    } catch (e) {
      _writeErr(socket, (e && e.message ? e.message.slice(0, ERR_CLAMP) : "syntax"));
      return;
    }
    _dispatch(state, socket, parsed);
  }

  function _dispatch(state, socket, parsed) {
    var verb = parsed.verb;
    var args = parsed.args;
    // Before the switch, so it covers every verb rather than the ones someone
    // remembered to instrument — NOOP most of all, since the listener answers
    // that one entirely on its own and a store ageing an idle lease would
    // otherwise never see the keepalive the protocol defines for it.
    _fireSessionActivity(state, verb);
    switch (verb) {
    case "CAPA":   return _handleCapa(state, socket);
    case "STLS":   return _handleStls(state, socket);
    case "USER":   return _handleUser(state, socket, args);
    case "PASS":   return _handlePass(state, socket, args);
    case "APOP":   return _handleApop(state, socket, args);
    case "AUTH":   return _handleAuth(state, socket, args);
    case "QUIT":   return _handleQuit(state, socket);
    case "STAT":   return _handleStat(state, socket);
    case "LIST":   return _handleList(state, socket, args);
    case "RETR":   return _handleRetr(state, socket, args);
    case "DELE":   return _handleDele(state, socket, args);
    case "NOOP":   return _writeOk(socket, "noop");
    case "RSET":   return _handleRset(state, socket);
    case "TOP":    return _handleTop(state, socket, args);
    case "UIDL":   return _handleUidl(state, socket, args);
    default:       return _writeErr(socket, "Verb '" + verb + "' not implemented");
    }
  }

  function _handleCapa(state, socket) {
    _writeOk(socket, "Capability list follows");
    socket.write("TOP\r\n");
    socket.write("UIDL\r\n");
    socket.write("RESP-CODES\r\n");
    if (!state.tls) socket.write("STLS\r\n");
    // Advertise AUTH mechanisms ONLY when wired
    // (do not hardcode SASL mechs in caps).
    if (authConfig && Array.isArray(authConfig.mechanisms) && authConfig.mechanisms.length > 0) {
      var mechs = authConfig.mechanisms.map(function (m) {
        return String(m).toUpperCase();
      }).join(" ");
      socket.write("SASL " + mechs + "\r\n");
    }
    socket.write("IMPLEMENTATION blamejs\r\n");
    socket.write(".\r\n");
  }

  function _handleStls(state, socket) {
    // RFC 8314 §3.3 — the verb has no meaning on a port that is already TLS
    // from the first byte, and saying so names the port rather than leaving an
    // operator to read "already negotiated" as a client bug.
    if (implicitTls) {
      _writeErr(socket, "STLS not available on implicit-TLS port (RFC 8314)");
      return;
    }
    if (state.tls) {
      _writeErr(socket, "STLS already negotiated");
      return;
    }
    // RFC 2595 §4 — STLS is only valid in AUTHORIZATION state. Once
    // a session has reached TRANSACTION (authenticated, with a drop
    // lock against the mailbox), a TLS upgrade mid-session would
    // re-key without re-authenticating and produce undefined
    // behaviour against open mailbox state.
    if (state.stage !== "authorization") {
      _writeErr(socket, "STLS only valid in AUTHORIZATION (RFC 2595 §4)");
      return;
    }
    _writeOk(socket, "Begin TLS negotiation");
    // Drain pre-handshake buffer (RFC 2595 §4 + CVE-2021-33515 class
    // STLS-injection defense — any pipelined commands the client
    // queued before the upgrade are discarded; post-TLS reads fresh).
    // POP3 has no authPending shape (SASL state is local to
    // _handleAuth), but tentativeUser is reset so a USER pipelined
    // pre-handshake cannot bind a post-handshake PASS. The shared
    // upgradeLineProtocol helper owns the lineBuffer drain + listener-
    // strip + idle re-arm + read-pump.
    mailServerTls.upgradeLineProtocol({
      state:         state,
      socket:        socket,
      secureContext: opts.tlsContext,
      idleTimeoutMs: idleTimeoutMs,
      clearFields:   ["tentativeUser"],
      drain:         _drainBuffer,
      onError: function (err) {
        _emit("mail.server.pop3.tls_handshake_failed",
          { connectionId: state.id, error: (err && err.message) || String(err) }, "failure");
        _close(socket);
      },
      onTimeout: function (tlsSocket) {
        _writeErr(tlsSocket, "Idle timeout");
        _close(tlsSocket);
      },
    });
  }

  // The per-IP auth-failure gate, asked BEFORE anything is counted against the
  // budget. Returns true when the caller must stop: the address is over its cap
  // and the connection has been closed.
  //
  // The order is the whole of it. The budget is a rolling window over stored
  // timestamps rather than a counter that decays, so an address already at the
  // cap that keeps ADDING timestamps holds the window populated and pushes the
  // end of its own wait forward instead of serving it. Counting a refusal the
  // address should never have been admitted to let a client loop a cleartext
  // verb and hold its own address — and anyone sharing it — out of the listener
  // indefinitely, without ever presenting a password.
  //
  // One helper rather than a block per call site because the three that existed
  // had already drifted: only the PASS one emitted the audit event, so two of
  // three rate-limit refusals were invisible to an operator watching for them.
  function _refusedByAuthBudget(state, socket) {
    var authAdmit = rateLimit.checkAuthAdmit(state.remoteAddress);
    if (authAdmit.ok) return false;
    _emit("mail.server.pop3.auth_rate_limit_refused",
      { connectionId: state.id, remoteAddress: state.remoteAddress, reason: authAdmit.reason },
      "denied");
    _writeErr(socket, "Too many AUTH failures from your IP");
    _close(socket);
    return true;
  }

  function _handleUser(state, socket, args) {
    if (state.stage !== "authorization") {
      _writeErr(socket, "USER only valid in AUTHORIZATION");
      return;
    }
    if (state.actor) {
      _writeErr(socket, "Already authenticated");
      return;
    }
    // RFC 2595 §2.1 defense-in-depth — the guardPop3Command validator
    // refuses USER over cleartext under strict at the wire boundary,
    // but balanced/permissive operators previously reached this path
    // and accepted a plaintext password. Refuse here too so a guard
    // relax doesn't open (cleartext credentials in
    // POP3 USER/PASS) by composition. Permissive operators opt out
    // by explicitly setting profile: "permissive".
    if (!state.tls && profile !== "permissive") {
      if (_refusedByAuthBudget(state, socket)) return;
      _emit("mail.server.pop3.auth_refused_cleartext",
        { connectionId: state.id, verb: "USER", remoteAddress: state.remoteAddress },
        "denied");
      rateLimit.noteAuthFailure(state.remoteAddress);
      _writeErr(socket, "USER refused over cleartext (use STLS first; RFC 2595 §2.1)");
      return;
    }
    state.tentativeUser = args[0];
    _writeOk(socket, "Send password");
  }

  function _handlePass(state, socket, args) {
    if (state.stage !== "authorization" || !state.tentativeUser) {
      _writeErr(socket, "PASS only valid after USER");
      return;
    }
    if (!authConfig || typeof authConfig.verify !== "function") {
      _writeErr(socket, "AUTH not configured on this listener");
      return;
    }
    // refuse PASS over cleartext when not permissive.
    // USER already gated above, but this is defense-in-depth in case the
    // USER guard was bypassed by a future codepath.
    if (_refusedByAuthBudget(state, socket)) return;
    if (!state.tls && profile !== "permissive") {
      _emit("mail.server.pop3.auth_refused_cleartext",
        { connectionId: state.id, verb: "PASS", remoteAddress: state.remoteAddress },
        "denied");
      rateLimit.noteAuthFailure(state.remoteAddress);
      _writeErr(socket, "PASS refused over cleartext (use STLS first; RFC 2595 §2.1)");
      return;
    }
    var username = state.tentativeUser;
    state.tentativeUser = null;
    var password = args[0];
    _emit("mail.server.pop3.auth_attempt",
      { connectionId: state.id, verb: "PASS", remoteAddress: state.remoteAddress });
    Promise.resolve()
      .then(function () {
        return authConfig.verify("PLAIN", {
          username:      username,
          password:      password,
          tls:           state.tls,
          remoteAddress: state.remoteAddress,
        });
      })
      .then(function (result) {
        if (result && result.ok && result.actor) {
          if (!_assertTenantOrRefuse(state, socket, result)) return;
          state.actor = result.actor;
          _enterTransaction(state, socket, "PASS");
          return;
        }
        rateLimit.noteAuthFailure(state.remoteAddress);
        _emit("mail.server.pop3.auth_failed",
          { connectionId: state.id, verb: "PASS", reason: "verify-returned-fail" }, "denied");
        _writeErr(socket, "Authentication failed");
      })
      .catch(function () {
        rateLimit.noteAuthFailure(state.remoteAddress);
        _writeErr(socket, "Authentication failed");
      });
  }

  function _handleApop(state, socket, args) {
    // The validator already refuses APOP under strict; this just
    // means the operator opted into balanced/permissive. Treat as
    // username+digest and delegate to authConfig.verify with the APOP
    // mechanism name.
    if (state.stage !== "authorization") {
      _writeErr(socket, "APOP only valid in AUTHORIZATION");
      return;
    }
    if (!authConfig || typeof authConfig.verify !== "function") {
      _writeErr(socket, "AUTH not configured");
      return;
    }
    // Defense-in-depth, symmetric with USER / PASS. APOP transmits
    // MD5(timestamp+secret), not cleartext, but an
    // attacker who captures the digest + the known greeting timestamp
    // can mount an offline dictionary attack against the shared secret.
    // RFC 1939 §7 explicitly warns about this; balanced/permissive
    // operators reach this path only when they opted in, but the
    // wire MUST be TLS-protected to deny the offline-attack vector.
    if (_refusedByAuthBudget(state, socket)) return;
    if (!state.tls && profile !== "permissive") {
      _emit("mail.server.pop3.auth_refused_cleartext",
        { connectionId: state.id, verb: "APOP", remoteAddress: state.remoteAddress },
        "denied");
      rateLimit.noteAuthFailure(state.remoteAddress);
      _writeErr(socket, "APOP refused over cleartext (use STLS first; RFC 1939 §7)");
      return;
    }
    Promise.resolve()
      .then(function () {
        return authConfig.verify("APOP", {
          username:      args[0],
          digest:        args[1],
          tls:           state.tls,
          remoteAddress: state.remoteAddress,
        });
      })
      .then(function (result) {
        if (result && result.ok && result.actor) {
          if (!_assertTenantOrRefuse(state, socket, result)) return;
          state.actor = result.actor;
          _enterTransaction(state, socket, "APOP");
          return;
        }
        rateLimit.noteAuthFailure(state.remoteAddress);
        _writeErr(socket, "Authentication failed");
      })
      .catch(function () {
        rateLimit.noteAuthFailure(state.remoteAddress);
        _writeErr(socket, "Authentication failed");
      });
  }

  function _handleAuth(state, socket, args) {
    if (state.stage !== "authorization") {
      _writeErr(socket, "AUTH only valid in AUTHORIZATION");
      return;
    }
    if (!authConfig || typeof authConfig.verify !== "function") {
      _writeErr(socket, "AUTH not configured");
      return;
    }
    if (args.length === 0) {
      // RFC 5034 — `AUTH` alone enumerates mechanisms
      _writeOk(socket, "Supported mechanisms follow");
      var mechs = (authConfig.mechanisms || ["PLAIN"]).map(function (m) {
        return String(m).toUpperCase();
      });
      for (var i = 0; i < mechs.length; i += 1) socket.write(mechs[i] + "\r\n");
      socket.write(".\r\n");
      return;
    }
    // RFC 2595 §2.1 + RFC 5034 §4 — refuse mech-bearing AUTH over
    // cleartext under strict (defense-in-depth — guardPop3Command
    // refuses at the validate boundary, this catches any
    // configuration where the gate was relaxed but the AUTH path
    // still receives traffic).
    if (_refusedByAuthBudget(state, socket)) return;
    if (!state.tls && profile === "strict") {
      // Count cleartext-AUTH refusal against the auth-failure budget
      // so scanners that probe for plaintext-mech tolerance hit the
      // same per-IP cap that protects PASS / APOP. Without this, a
      // scanner could enumerate auth mechanisms freely (the refusal
      // itself was free) and shop for the first wire-protocol path
      // the listener honored. The cap is consulted above rather than
      // here, so an address already over it is closed instead of being
      // handed one more counted refusal to widen its own window with.
      rateLimit.noteAuthFailure(state.remoteAddress);
      _emit("mail.server.pop3.auth_refused_cleartext",
        { connectionId: state.id, verb: "AUTH", mech: args[0] }, "denied");
      _writeErr(socket, "AUTH refused over cleartext (use STLS first; RFC 2595 §2.1)");
      return;
    }
    var mech = args[0].toUpperCase();
    var initialResp = args.length > 1 ? args.slice(1).join(" ") : null;
    state.authPending = { mech: mech, step: 0 };
    _runAuthStep(state, socket, initialResp);
  }

  // One round of a SASL exchange (RFC 5034 §4). The verifier may answer with
  // `{ pending: true, challenge }` to ask for another client response, exactly
  // as it may on the IMAP and submission listeners; POP3 used to call verify
  // once with no `step`, so a pending verdict fell into the failure branch —
  // and spent the client's authentication-failure budget for what is a normal
  // protocol round trip, weakening the defence that budget exists to provide.
  function _runAuthStep(state, socket, clientResponse) {
    var pending = state.authPending;
    function _fail(reason, outcome) {
      state.authPending = null;
      rateLimit.noteAuthFailure(state.remoteAddress);
      _emit("mail.server.pop3.auth_failed",
        { connectionId: state.id, verb: "AUTH", mech: pending.mech, reason: reason },
        outcome);
      _writeErr(socket, "Authentication failed");
    }
    mailServerNet.runSaslStep({
      // `pending` IS the exchange: runSaslStep increments its `step`, and it
      // stays on `state.authPending` across rounds.
      exchange:       pending,
      verify:         authConfig.verify,
      credentials:    { tls: state.tls, remoteAddress: state.remoteAddress },
      clientResponse: clientResponse,
      // RFC 5034 §4 — the server's challenge is a `+ <base64>` line, and the
      // connection stays mid-exchange until the client answers.
      writeChallenge: function (ch) { return _writeContinuation(socket, ch); },
      onChallengeUnsafe: function () { _fail("challenge-contains-line-terminator", "denied"); },
      onSuccess: function (result) {
        state.authPending = null;
        if (!_assertTenantOrRefuse(state, socket, result)) return;
        state.actor = result.actor;
        _enterTransaction(state, socket, "AUTH/" + pending.mech);
      },
      onFailure: function (result) {
        _fail((result && result.reason) || "verify-returned-fail", "denied");
      },
      onError: function (err) { _fail((err && err.message) || String(err), "failure"); },
    });
  }

  function _continueAuthExchange(state, socket, line) {
    // RFC 5034 §4 — a bare `*` cancels the exchange. Cancelling is the client
    // withdrawing, not failing to authenticate, so it costs no budget either.
    if (line === "*") {
      state.authPending = null;
      _writeErr(socket, "Authentication cancelled");
      return;
    }
    _runAuthStep(state, socket, line);
  }

  function _enterTransaction(state, socket, verb) {
    // The peer may have gone while its credentials were being verified. The
    // end has already been reported by then — there was no store work to wait
    // for — so opening a drop now would take an exclusive lease that nothing
    // will ever announce the release of. The verdict is simply not acted on;
    // there is no session left to act on it for.
    if (state.closed) {
      _emit("mail.server.pop3.auth_after_close",
        { connectionId: state.id, verb: verb }, "denied");
      return;
    }
    if (typeof mailStore.openPop3Drop !== "function") {
      _writeErr(socket, "Backend missing openPop3Drop");
      return;
    }
    // Tracked so a session ending mid-open is reported after the lease it is
    // about to acquire exists — see _fireSessionEnd.
    _storeWork(state, Promise.resolve()
      .then(function () { return mailStore.openPop3Drop(state.actor, {}); }))
      .then(function (drop) {
        state.dropId = drop && drop.dropId;
        state.stage = "transaction";
        _emit("mail.server.pop3.auth_success",
          { connectionId: state.id, verb: verb, tenantId: state.actor.tenantId || null });
        _emit("mail.server.pop3.transaction_start",
          { connectionId: state.id, dropCount: (drop && drop.count) || 0,
            totalBytes: (drop && drop.totalBytes) || 0 });
        _writeOk(socket, "Logged in");
      })
      .catch(function (err) {
        _writeErr(socket, "Cannot open drop: " + ((err && err.message) || "backend error").slice(0, ERR_CLAMP));
      });
  }

  function _handleQuit(state, socket) {
    if (state.stage !== "transaction") {
      _writeOk(socket, "Goodbye");
      _close(socket);
      return;
    }
    state.stage = "update";
    // RFC 1939 §6 — bound the UPDATE-state commit. A hung backend
    // (DB row-lock / replica failover / sealed-row unseal stuck on a
    // KMS call) otherwise leaves the connection in update-state past
    // the socket idleTimeoutMs (which guards inbound bytes, not
    // pending Promises).
    var commitInFlight = Promise.resolve().then(function () {
      return mailStore.commitPop3Drop(state.actor, state.dropId);
    });
    // The session ends when the COMMIT settles — not when this listener stops
    // waiting for it. A timeout gives up on the answer; it does not stop the
    // backend from writing, so releasing the maildrop then would hand the next
    // session a mailbox still being mutated, which is the exact thing the
    // deferral exists to prevent. The outcome is reported by the timeout
    // wrapper below; this arm only has to know when the work is over.
    _storeWork(state, commitInFlight);
    safeAsync.withTimeout(commitInFlight, commitTimeoutMs,
      { label: "mail.server.pop3.commitPop3Drop" })
      .then(function (info) {
        _emit("mail.server.pop3.update_commit",
          { connectionId: state.id, deleted: (info && info.deleted) || 0 });
        _writeOk(socket, "Goodbye");
        _close(socket);
      })
      .catch(function (err) {
        _emit("mail.server.pop3.update_commit_failed",
          { connectionId: state.id, error: (err && err.message) || String(err) }, "failure");
        _writeErr(socket, "Commit failed: " + ((err && err.message) || "backend error").slice(0, ERR_CLAMP));
        _close(socket);
      });
  }

  function _requireTrans(state, socket) {
    if (state.stage !== "transaction") {
      _writeErr(socket, "Not authorized; USER+PASS first");
      return false;
    }
    return true;
  }

  function _handleStat(state, socket) {
    if (!_requireTrans(state, socket)) return;
    _storeWork(state, Promise.resolve()
      .then(function () { return mailStore.listMessages(state.actor, state.dropId); }))
      .then(function (msgs) {
        var ms = msgs || [];
        var totalBytes = 0;
        for (var i = 0; i < ms.length; i += 1) totalBytes += ms[i].size || 0;
        _writeOk(socket, ms.length + " " + totalBytes);
      })
      .catch(function (err) { _writeErr(socket, ((err && err.message) || "stat failed").slice(0, ERR_CLAMP)); });
  }

  function _handleList(state, socket, args) {
    if (!_requireTrans(state, socket)) return;
    _storeWork(state, Promise.resolve()
      .then(function () { return mailStore.listMessages(state.actor, state.dropId); }))
      .then(function (msgs) {
        var ms = msgs || [];
        if (args.length === 1) {
          var n = parseInt(args[0], 10);
          var found = null;
          for (var i = 0; i < ms.length; i += 1) {
            if (ms[i].msgNum === n) { found = ms[i]; break; }
          }
          if (!found) { _writeErr(socket, "no such message"); return; }
          _writeOk(socket, n + " " + found.size);
          return;
        }
        _writeOk(socket, ms.length + " messages");
        for (var j = 0; j < ms.length; j += 1) {
          socket.write(ms[j].msgNum + " " + ms[j].size + "\r\n");
        }
        socket.write(".\r\n");
      })
      .catch(function (err) { _writeErr(socket, ((err && err.message) || "list failed").slice(0, ERR_CLAMP)); });
  }

  function _handleRetr(state, socket, args) {
    if (!_requireTrans(state, socket)) return;
    var msgNum = parseInt(args[0], 10);
    _storeWork(state, Promise.resolve()
      .then(function () { return mailStore.getMessage(state.actor, state.dropId, msgNum, {}); }))
      .then(function (msg) {
        if (!msg) { _writeErr(socket, "no such message"); return; }
        _emit("mail.server.pop3.retr",
          { connectionId: state.id, msgNum: msgNum, size: msg.size });
        _writeOk(socket, msg.size + " octets");
        // RFC 1939 §3 dot-stuffing — lines starting with `.` get a
        // doubled `.` so the receiver doesn't mistake them for the
        // CRLF.CRLF terminator. The `/^\./gm` regex on a JS string
        // treats bare LF as a line boundary (matches `\n.` and
        // `\r\n.`), so a body containing a bare-LF line that starts
        // with `.` gained spurious stuffing that didn't match the
        // receiver's strict-CRLF parser. Route through safeSmtp.dotStuff
        // which inspects the raw Buffer and only treats canonical
        // \r\n as a line boundary (bare LF is left alone — the
        // guardSmtpCommand.detectBodySmuggling layer catches bare-LF
        // smuggling at the upstream parse).
        var bodyBuf = msg.rawBytes
          ? msg.rawBytes
          : Buffer.from(msg.text || "", "utf8");
        var stuffed = safeSmtp.dotStuff(bodyBuf);
        socket.write(stuffed);
        // RFC 1939 §3 requires a CRLF before the terminator. The body
        // may already end with CRLF; write one only when it doesn't.
        if (stuffed.length === 0 ||
            stuffed[stuffed.length - 2] !== 0x0d /* CR */ ||
            stuffed[stuffed.length - 1] !== 0x0a /* LF */) {
          socket.write("\r\n");
        }
        socket.write(".\r\n");
      })
      .catch(function (err) { _writeErr(socket, ((err && err.message) || "retr failed").slice(0, ERR_CLAMP)); });
  }

  function _handleDele(state, socket, args) {
    if (!_requireTrans(state, socket)) return;
    var msgNum = parseInt(args[0], 10);
    _storeWork(state, Promise.resolve()
      .then(function () { return mailStore.markDelete(state.actor, state.dropId, msgNum); }))
      .then(function () {
        _emit("mail.server.pop3.dele",
          { connectionId: state.id, msgNum: msgNum });
        _writeOk(socket, "marked deleted");
      })
      .catch(function (err) { _writeErr(socket, ((err && err.message) || "dele failed").slice(0, ERR_CLAMP)); });
  }

  function _handleRset(state, socket) {
    if (!_requireTrans(state, socket)) return;
    _storeWork(state, Promise.resolve()
      .then(function () {
        if (typeof mailStore.resetPop3Drop === "function") {
          return mailStore.resetPop3Drop(state.actor, state.dropId);
        }
      }))
      .then(function () { _writeOk(socket, "delete marks cleared"); })
      .catch(function (err) { _writeErr(socket, ((err && err.message) || "rset failed").slice(0, ERR_CLAMP)); });
  }

  function _handleTop(state, socket, args) {
    if (!_requireTrans(state, socket)) return;
    var msgNum = parseInt(args[0], 10);
    var headerLines = parseInt(args[1], 10);
    _storeWork(state, Promise.resolve()
      .then(function () {
        return mailStore.getMessage(state.actor, state.dropId, msgNum,
          { headersOnly: true, headerLines: headerLines });
      }))
      .then(function (msg) {
        if (!msg) { _writeErr(socket, "no such message"); return; }
        _writeOk(socket, "headers + " + headerLines + " body lines");
        // see _handleRetr; same byte-level CRLF-aware
        // dot-stuffing primitive for the TOP partial-body path.
        var bodyBuf = msg.rawBytes
          ? msg.rawBytes
          : Buffer.from(msg.text || "", "utf8");
        var stuffed = safeSmtp.dotStuff(bodyBuf);
        socket.write(stuffed);
        if (stuffed.length === 0 ||
            stuffed[stuffed.length - 2] !== 0x0d /* CR */ ||
            stuffed[stuffed.length - 1] !== 0x0a /* LF */) {
          socket.write("\r\n");
        }
        socket.write(".\r\n");
      })
      .catch(function (err) { _writeErr(socket, ((err && err.message) || "top failed").slice(0, ERR_CLAMP)); });
  }

  function _handleUidl(state, socket, args) {
    if (!_requireTrans(state, socket)) return;
    _storeWork(state, Promise.resolve()
      .then(function () { return mailStore.listMessages(state.actor, state.dropId); }))
      .then(function (msgs) {
        var ms = msgs || [];
        if (args.length === 1) {
          var n = parseInt(args[0], 10);
          var found = null;
          for (var i = 0; i < ms.length; i += 1) {
            if (ms[i].msgNum === n) { found = ms[i]; break; }
          }
          if (!found) { _writeErr(socket, "no such message"); return; }
          _writeOk(socket, n + " " + (found.uid || found.uidl || ""));
          return;
        }
        _writeOk(socket, "unique-id listing follows");
        for (var j = 0; j < ms.length; j += 1) {
          socket.write(ms[j].msgNum + " " + (ms[j].uid || ms[j].uidl || "") + "\r\n");
        }
        socket.write(".\r\n");
      })
      .catch(function (err) { _writeErr(socket, ((err && err.message) || "uidl failed").slice(0, ERR_CLAMP)); });
  }

  function _writeOk(socket, msg)  { try { socket.write("+OK "  + msg + "\r\n"); } catch (_e) { /* socket down */ } }
  function _writeErr(socket, msg) { try { socket.write("-ERR " + msg + "\r\n"); } catch (_e) { /* socket down */ } }
  // RFC 5034 §4 SASL continuation — `+ <base64>`, or a bare `+` for an empty
  // challenge. Returns false when the challenge carries bytes that would end
  // the line, so the caller fails the exchange instead of emitting a second,
  // smuggled protocol line.
  function _writeContinuation(socket, challenge) {
    var b64 = mailServerNet.saslChallengeOrNull(challenge);
    if (b64 === null) return false;
    try { socket.write(b64.length > 0 ? "+ " + b64 + "\r\n" : "+\r\n"); }
    catch (_e) { /* socket down */ }
    return true;
  }
  function _close(socket) {
    try { socket.end(); } catch (_e) { /* idempotent */ }
    try { socket.destroy(); } catch (_e2) { /* idempotent */ }
    connections.delete(socket);
  }

  // ---- Lifecycle ----------------------------------------------------------
  return mailServerNet.createStoreServer(net, {
    // RFC 1939 POP3 port (IANA), or RFC 8314 §3.1's implicit-TLS 995 when the
    // operator asked for that mode and named no port of their own.
    defaultPort:      implicitTls ? 995 : 110,                                                        // RFC 8314 §3.1 / RFC 1939 (IANA)
    maxConnections:   opts.maxConnections,
    listeningExtra:   function () { return { implicitTls: implicitTls }; },
    handleConnection: _handleConnection,
    errorClass:       MailServerPop3Error,
    errorCodePrefix:  "mail-server-pop3/",
    emit:             _emit,
    connections:      connections,
    eventBase:        "mail.server.pop3",
  });
}

module.exports = {
  create:               create,
  MailServerPop3Error:  MailServerPop3Error,
};
