// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var codepointClass = require("./codepoint-class");
var bCrypto        = require("./crypto");
var safeAsync      = require("./safe-async");

// mail-server-net — the TCP-listener lifecycle shared by the mailbox / transfer
// servers (b.mail.server.imap / pop3 / mx / managesieve / submission). Each of
// those keeps its OWN connection set and close() drain because those diverge:
// the store servers (IMAP/POP3/ManageSieve) await a Promise-wrapped
// tcpServer.close(), while the transfer servers (MX/Submission) send an SMTP
// 421 to every live socket and drain with a timeout. What every server shares
// verbatim is the bind: refuse a double-listen, resolve the default port (never
// falling back off an explicit port 0 — the ephemeral test-bind path), create
// the listener, and arm a one-shot "error"→reject so a bind failure (EADDRINUSE,
// EACCES) rejects the listen promise instead of crashing the process. That, plus
// the listening/server state, is what createTcpListener owns.

// The listener's own ceiling when an operator names none. Every mail listener
// shares it, so a deployment that raises or lowers it does so in one place and
// the five listeners cannot drift apart on what "too many" means. Set well
// above any single-host mail deployment's working set and far below what an
// unbounded accept loop will take: the point is that a ceiling EXISTS, since
// the per-address cap alone leaves the total at (cap x source addresses).
var DEFAULT_MAX_CONNECTIONS = 1024;

// createTcpListener(net, cfg) — build a listener lifecycle.
//   cfg.defaultPort      port used when listenOpts.port is omitted (an explicit
//                        0 is honored, for an ephemeral test bind).
//   cfg.handleConnection (socket) => void — the server's per-connection handler.
//   cfg.errorFactory     (code, message) => Error — builds the typed
//                        "<prefix>/already-listening" double-listen error.
//   cfg.emit             (action, metadata) => void — the server's audit emitter.
//   cfg.listeningEvent   the "...listening" audit action.
//   cfg.listeningExtra   optional () => object merged onto the listening event
//                        payload (Submission reports implicitTls).
//   cfg.maxConnections   the listener's own ceiling on concurrently accepted
//                        sockets. The per-address cap in b.mail.server.rateLimit
//                        bounds ONE peer; it says nothing about how many peers
//                        there are, so the process-wide total was the per-address
//                        cap times however many source addresses the caller could
//                        speak from — a number a botnet, a NAT pool or a single
//                        v6 /64 makes large. Enforced by the runtime, which closes
//                        the excess socket before handleConnection ever sees it,
//                        so a refusal costs no descriptor and no state machine.
// Returns { listen, getServer, isListening, markClosed } — the server wires its
// own close() through getServer()/isListening()/markClosed().
function createTcpListener(net, cfg) {
  var server = null;
  var listening = false;

  function listen(listenOpts) {
    listenOpts = listenOpts || {};
    if (listening) {
      throw cfg.errorFactory("already-listening", "listen: already listening");
    }
    var port = listenOpts.port === undefined ? cfg.defaultPort : listenOpts.port;
    var address = listenOpts.address || "0.0.0.0";
    server = net.createServer(function (socket) { cfg.handleConnection(socket); });
    server.maxConnections = cfg.maxConnections || DEFAULT_MAX_CONNECTIONS;
    // A connection dropped at the ceiling produced nothing at all: no audit
    // row, no protocol line, no log. The kernel accepted it and node closed it
    // before the handler ran, so a listener sitting at capacity — turning
    // real senders away — looked exactly like an idle one, and the operator's
    // first evidence was a peer complaining. `drop` is the only place this is
    // observable, because by design nothing downstream of it runs.
    server.on("drop", function (info) {
      if (typeof cfg.emit !== "function") return;
      cfg.emit(cfg.ceilingRefusedEvent || "listener.max_connections_refused", {
        remoteAddress:  (info && info.remoteAddress) || null,
        reason:         "listener-at-capacity",
        maxConnections: server.maxConnections,
      }, "denied");
    });
    return new Promise(function (resolve, reject) {
      server.once("error", reject);
      server.listen(port, address, function () {
        listening = true;
        server.removeListener("error", reject);
        var payload = { port: port, address: address };
        if (cfg.listeningExtra) {
          var extra = cfg.listeningExtra();
          for (var k in extra) {
            if (Object.prototype.hasOwnProperty.call(extra, k)) payload[k] = extra[k];
          }
        }
        cfg.emit(cfg.listeningEvent, payload);
        resolve({ port: server.address().port, address: address });
      });
    });
  }

  // closeSimple(closeCfg) — the store-server shutdown (IMAP / POP3 / ManageSieve):
  // mark closed, destroy every live socket immediately, then await the listener's
  // own close before emitting the "...closed" audit. The transfer servers
  // (MX / Submission) do NOT use this — they run a graceful SMTP-421 drain with a
  // timeout, so they own their close() and drive it through markClosed()/getServer().
  //   closeCfg.connections  the server's live-socket Set (destroyed + cleared).
  //   closeCfg.emit         the server's audit emitter.
  //   closeCfg.closedEvent  the "...closed" audit action.
  function closeSimple(closeCfg) {
    if (!listening) return Promise.resolve();
    listening = false;
    for (var s of closeCfg.connections) { try { s.destroy(); } catch (_e) { /* idempotent */ } }
    closeCfg.connections.clear();
    return new Promise(function (resolve) {
      server.close(function () {
        closeCfg.emit(closeCfg.closedEvent, {});
        resolve();
      });
    });
  }

  return {
    listen:      listen,
    closeSimple: closeSimple,
    getServer:   function () { return server; },
    isListening: function () { return listening; },
    markClosed:  function () { listening = false; },
  };
}

// createStoreServer(net, cfg) — the COMPLETE lifecycle of a mailbox store server
// (b.mail.server.imap / pop3 / managesieve): compose createTcpListener with the
// destroy-then-await closeSimple shutdown and return the { listen, close } a
// store server exposes. The three store servers are byte-identical here, varying
// only in port, error class, error-code prefix, and audit-event base — so the
// wiring lives here once. The transfer servers (MX / Submission) do NOT use this:
// they run a graceful SMTP-421 drain close + a richer return ({ connectionCount,
// _portForTest, ... }), so they call createTcpListener directly.
//   cfg.defaultPort      port used when listen() omits one (explicit 0 honored).
//   cfg.handleConnection (socket) => void — the per-connection handler.
//   cfg.errorClass       the server's typed error constructor (code, message).
//   cfg.errorCodePrefix  prepended to the double-listen error code
//                        (e.g. "mail-server-imap/").
//   cfg.emit             (action, metadata) => void — the server's audit emitter.
//   cfg.connections      the live-socket Set (destroyed + cleared on close).
//   cfg.eventBase        the audit-action base; listeningEvent = eventBase +
//                        ".listening", closedEvent = eventBase + ".closed".
// Returns { listen, close }.
function createStoreServer(net, cfg) {
  var ErrorClass = cfg.errorClass;
  var listener = createTcpListener(net, {
    defaultPort:      cfg.defaultPort,
    maxConnections:   cfg.maxConnections,
    handleConnection: cfg.handleConnection,
    errorFactory:     function (code, message) { return new ErrorClass(cfg.errorCodePrefix + code, message); },
    emit:             cfg.emit,
    listeningEvent:   cfg.eventBase + ".listening",
    // Named off the same base as every other action this listener emits, so an
    // operator filtering on their listener's prefix sees capacity refusals
    // beside the connects and closes rather than under a generic name.
    ceilingRefusedEvent: cfg.eventBase + ".max_connections_refused",
    // Forwarded so a store listener can report its wire mode the way the
    // transfer listeners already do — an operator confirming an implicit-TLS
    // port reads it from the listening event, not from the config they hoped
    // took effect.
    listeningExtra:   cfg.listeningExtra,
  });
  function close() {
    return listener.closeSimple({
      connections: cfg.connections,
      emit:        cfg.emit,
      closedEvent: cfg.eventBase + ".closed",
    });
  }
  return {
    listen:          listener.listen,
    close:           close,
    connectionCount: function () { return cfg.connections.size; },
  };
}

// trackConnection(socket, cfg) — the other half of admitConnection, and the
// reason it is here rather than written out per listener.
//
// A connection occupies two ledgers: the rate limiter's per-address count, and
// the listener's live-socket set that shutdown drains. Both are released by the
// SAME event — the socket closing — and it does not matter who closed it. Five
// listeners each wrote that pairing by hand and one of them registered only the
// release, so a peer that opened a connection, took the greeting and dropped TCP
// freed its rate-limit slot (and could reconnect at once) while its set entry
// stayed forever. Nothing authenticates before that point, so the growth was
// unauthenticated and unbounded.
//
// Registering both in one handler is what makes the pair impossible to
// half-write.
//   cfg.connections    the listener's live-socket Set.
//   cfg.rateLimit      the resolved b.mail.server.rateLimit.
//   cfg.remoteAddress  the address admitConnection returned.
//   cfg.closeSource    optional socket whose "close" drives teardown, when the
//                      tracked socket is a wrapper (Submission's implicit-TLS
//                      path tracks the TLSSocket but the raw socket is the one
//                      that carries the FIN).
function trackConnection(socket, cfg) {
  cfg.connections.add(socket);
  var source = cfg.closeSource || socket;
  source.once("close", function () {
    cfg.rateLimit.releaseConnection(cfg.remoteAddress);
    cfg.connections.delete(socket);
  });
}

// createBodyRateWindow(rateLimit) — the body-rate floor, measured over BOUNDED
// windows instead of the whole transfer.
//
// A lifetime average lets an early burst pay for an arbitrarily slow tail: at
// the default 100 B/s an 8 MiB burst buys about a day of credit and 50 MiB buys
// six, which a peer spends holding a connection and its slot in the per-address
// cap while sending a byte at a time. The floor was enforced and still
// bypassable, which is the worse of the two states — it reads as covered.
//
// Each window has to meet the floor on its own, so nothing sent earlier pays
// for what is sent now. A window only rolls forward once it has run long enough
// to be a real judgement; inside that stretch no verdict is reached, so a
// sender pausing to read from its own spool is not cut off for the pause, and a
// fast chunk cannot keep resetting the clock to dodge the next measurement.
//
// `now` is a parameter rather than a call to the clock so the whole thing can
// be driven across days of simulated time without waiting for them.
//   rateLimit  the resolved b.mail.server.rateLimit (owns the floor + grace).
function createBodyRateWindow(rateLimit) {
  var windowStart = 0;
  var windowBytes = 0;
  return {
    // Open the first window. `bytesSeen` is the caller's running total AT THIS
    // MOMENT, which becomes the baseline every later reading is measured
    // against — so the caller is free to keep one connection-lifetime counter
    // incremented at the wire boundary rather than a per-transfer one. That
    // matters where a listener re-feeds part of a chunk through its own parser:
    // a counter maintained inside the parser credits those bytes twice, and a
    // peer that pipelines a one-byte payload with the next command gets roughly
    // double the rate it is actually sending.
    start: function (now, bytesSeen) {
      windowStart = now;
      windowBytes = bytesSeen || 0;
    },
    // `bytesSeen` is the running total for the whole body; the window's own
    // count is derived, so the caller keeps one counter rather than two.
    starved: function (bytesSeen, now) {
      var elapsed = now - windowStart;
      if (rateLimit.bodyRateStarved(bytesSeen - windowBytes, elapsed)) return true;
      // The limiter says how long a window must run before rolling, because the
      // limiter is what decides when a measurement is old enough to mean
      // something. Rolling on a number held HERE would ask a limiter that
      // judges over a longer stretch only ever before it can answer: every call
      // returning "too early", the window resetting underneath it, and its rate
      // protection silently disabled while looking wired.
      if (elapsed >= rateLimit.bodyRateWindowMs()) {
        windowStart = now;
        windowBytes = bytesSeen;
      }
      return false;
    },
  };
}

// acceptConnection(rawSocket, cfg) — everything a listener does between the TCP
// accept and its own state machine: gate the address, mint the connection id,
// wrap the socket if the protocol starts in TLS, and enter both ledgers.
//
// Every listener performed these four steps in the same order, and the parts
// that differ between them are three strings and an optional wrap. Keeping the
// order in one place is what stops a fifth listener from being written with one
// of the steps missing, which is how the tracking-set entry and the rate-limit
// slot came apart in the first place.
//
// Returns null when the address was refused — the caller returns immediately;
// the refusal line and teardown are already done.
//   cfg.rateLimit      the resolved b.mail.server.rateLimit.
//   cfg.connections    the listener's live-socket Set.
//   cfg.emit           the listener's audit emitter.
//   cfg.refusedEvent   the "<...>.rate_limit_refused" audit action.
//   cfg.refusalLine    the protocol's refusal bytes.
//   cfg.idPrefix       "imapconn-" / "mxconn-" / … prefix for the connection id.
//   cfg.wrap           optional (rawSocket) => socket, for a protocol that
//                      starts inside TLS. The RAW socket still drives teardown:
//                      a handshake that never completes closes it without the
//                      wrapper ever being established.
function acceptConnection(rawSocket, cfg) {
  var remoteAddress = admitConnection(rawSocket, cfg.rateLimit, cfg.emit, {
    refusedEvent: cfg.refusedEvent,
    refusalLine:  cfg.refusalLine,
    // A wrapper means this port is TLS from the first byte, which decides how
    // a refusal is delivered — see admitConnection.
    implicitTls:  !!cfg.wrap,
  });
  if (remoteAddress === null) return null;
  var socket = cfg.wrap ? cfg.wrap(rawSocket) : rawSocket;
  trackConnection(socket, {
    connections:   cfg.connections,
    rateLimit:     cfg.rateLimit,
    remoteAddress: remoteAddress,
    closeSource:   socket === rawSocket ? null : rawSocket,
  });
  // A listener that needs to know when the session ENDS says so here rather
  // than wiring its own close handler. Every ending — a clean QUIT, an idle
  // timeout, a line over the cap, a link that simply dropped — arrives as the
  // socket's `close`, so one place covers them all; and putting it here keeps
  // the four `_handleConnection` bodies from each growing their own copy.
  //
  // Fired at most once. `trackConnection` may be watching a pre-TLS source
  // socket as well, and a socket that errors and then closes emits both — a
  // consumer releasing an exclusive lease by decrementing a holder count would
  // corrupt its own accounting on a second call.
  if (typeof cfg.onClose === "function") {
    var closed = false;
    var fire = function () {
      if (closed) return;
      closed = true;
      cfg.onClose();
    };
    socket.once("close", fire);
    if (socket !== rawSocket) rawSocket.once("close", fire);
  }
  return {
    socket:        socket,
    remoteAddress: remoteAddress,
    connectionId:  cfg.idPrefix + bCrypto.generateToken(8),                                           // connection-id length
  };
}

// admitConnection(socket, rateLimit, emit, cfg) — the per-connection rate-limit
// gate every mail listener's _handleConnection opens with: resolve the remote
// IP, admit it via the shared b.mail.server.rateLimit, or refuse it with a
// protocol-specific line + a "<...>.rate_limit_refused" audit (outcome "denied")
// and tear the socket down. Returns the remote address on admit, or null when
// refused — the caller does `if (addr === null) return;` then runs its own
// (protocol-specific) close handler, connection-id, tracking-set insert, and
// state machine, none of which this touches.
//   cfg.refusedEvent  the "<...>.rate_limit_refused" audit action.
//   cfg.refusalLine   the wire bytes written before destroy (IMAP "* BAD …",
//                     POP3 "-ERR …", SMTP "421 4.7.0 …", ManageSieve 'NO "…"').
function admitConnection(socket, rateLimit, emit, cfg) {
  var remoteAddress = socket.remoteAddress || "0.0.0.0";
  var admit = rateLimit.admitConnection(remoteAddress);
  if (!admit.ok) {
    emit(cfg.refusedEvent, { remoteAddress: remoteAddress, reason: admit.reason }, "denied");
    // On an implicit-TLS port the refusal is a CLOSE, not a line. This runs
    // before the socket is wrapped, so writing here would put plaintext where
    // the peer is mid-handshake: it reads as a handshake failure, the refusal
    // is unreadable, and the port's "TLS from the first byte" claim is broken
    // by the listener itself. Handshaking first so the line could be written
    // would spend the very resource the limit is protecting — a rejected peer
    // would cost a full key exchange each time.
    if (!cfg.implicitTls) {
      try { socket.write(cfg.refusalLine); } catch (_e) { /* socket may be down */ }
    }
    try { socket.destroy(); } catch (_e2) { /* idempotent */ }
    return null;
  }
  return remoteAddress;
}

// validateDomainHardened(d, label, cfg) — the hardened-domain check the MX and
// Submission transfer servers run on every HELO / MAIL FROM / RCPT TO domain.
// When a guardDomain profile is configured it validates the domain and, on
// refusal, emits a "<refusedEvent>" audit (the only per-server difference — MX
// vs Submission) before returning the verdict; with no profile it passes
// through { ok: true }. Sharing it keeps the two servers' domain-validation
// posture identical (a divergence would be a silent spoofing / IDN-homograph
// gap on one server).
//   cfg.guardDomainProfile  the b.guardDomain profile (falsy = validation off).
//   cfg.guardDomain         the b.guardDomain module (its validate(d, profile)).
//   cfg.emit                (action, metadata, outcome) => void audit emitter.
//   cfg.refusedEvent        the "<...>.domain_refused" audit action.
function validateDomainHardened(d, label, cfg) {
  if (!cfg.guardDomainProfile) return { ok: true };
  var verdict = cfg.guardDomain.validate(d, cfg.guardDomainProfile);
  if (!verdict.ok) {
    cfg.emit(cfg.refusedEvent, {
      reason: verdict.issues && verdict.issues[0] && verdict.issues[0].kind,
      domain: d,
      label:  label,
    }, "denied");
  }
  return verdict;
}

// saslChallengeOrNull(challenge) — the operator's SASL challenge, checked for
// the bytes that would end the line it is written on.
//
// Every listener that supports a multi-step SASL exchange writes this value
// straight to the wire, and it is not always the operator's own text: a SCRAM
// or CRAM mechanism composes its challenge from the client's nonce, so client
// bytes reach this line. A CR, LF or NUL in it terminates the server's reply
// early and the remainder is read by the client as a second protocol line —
// the same injection class the outbound SMTP transport refuses at config time
// (GHSA-c7w3-x93f-qmm8). Returns null when the challenge cannot be written
// safely; the caller fails the exchange rather than emitting a smuggled line.
function saslChallengeOrNull(challenge) {
  if (typeof challenge !== "string") return null;
  return codepointClass.firstLineInjectionCharOffset(challenge) === -1 ? challenge : null;
}

// replyTextOrFallback(text, fallback) — operator-supplied prose, made safe to
// write into a line-oriented protocol reply.
//
// A refusal reason is the common case, and it is rarely the operator's own
// words: a directory wrapper answers "No such user: <address>", and the address
// came from the peer. A CR or LF in it ends the reply line early and everything
// after is read by the peer as a second server response, so a `550` refusal can
// carry a forged `250` acceptance.
//
// Unlike a SASL challenge, a refusal must still happen: dropping the whole
// reply would turn an injection attempt into a hang. So the unsafe text is
// replaced by the caller's fallback and the refusal is delivered.
function replyTextOrFallback(text, fallback) {
  if (typeof text !== "string" || text.length === 0) return fallback;
  return codepointClass.firstLineInjectionCharOffset(text) === -1 ? text : fallback;
}

// foldSubaddress(address, delimiter) — an address reduced to the mailbox it is
// delivered to, per RFC 5233.
//
// `alice+tag@example.com` is delivered to `alice@example.com`: the detail part
// after the delimiter is chosen by whoever writes the address, which is why it
// can never be enumerated in advance. A comparison that folds only case
// therefore refuses an address the same server routes to the account's own
// mailbox — one identity, two answers.
//
// Folded, not stripped-and-trusted: the delimiter at position 0 is NOT a
// separator, because `+tag@example.com` has no base local part to fold to and
// is an address in its own right. An address with no delimiter, no local part,
// or no `@` comes back with its domain lowercased and nothing else changed.
// The delimiter is REQUIRED, not defaulted: whether a local part has a detail
// part at all is a property of the delivery side, and a caller that has not
// said so gets its address back rather than a fold this cannot know applies.
function foldSubaddress(address, delimiter) {
  if (typeof address !== "string" || address.length === 0) return "";
  // The DOMAIN is case-insensitive (RFC 5321 §2.3.4); the local part is not
  // (§2.4), so this folds only the half the specification says it may. A
  // listener that additionally compares local parts case-insensitively — as
  // every listener here does, at the point it parses the address — is making
  // its own deployment-shaped choice, and it is not this function's to make on
  // its behalf.
  var at = address.lastIndexOf("@");
  var lower = at <= 0 ? address : address.slice(0, at) + address.slice(at).toLowerCase();
  if (typeof delimiter !== "string" || delimiter.length === 0) return lower;
  var sep = delimiter;
  if (at <= 0) return lower;
  var local = lower.slice(0, at);
  // A quoted local part (RFC 5321 §4.1.2) is literal mailbox data, where the
  // delimiter is an ordinary character rather than a separator:
  // `"alice+one"@example.com` and `"alice+two"@example.com` are two different
  // mailboxes. Folding them would collapse both to the same string and let
  // either speak for the other, so a quoted local part is never folded.
  if (local.charAt(0) === "\"") return lower;
  var tag = local.indexOf(sep);
  if (tag <= 0) return lower;
  return local.slice(0, tag) + lower.slice(at);
}

// agentRefusalReply(err, fallbackText) — the reply an agent's rejection asks
// for, or the transient default when it asks for nothing.
//
// The handoff is the consumer's own delivery path and the only party that
// knows whether a refusal is permanent. Answering every rejection 451 tells a
// conforming MTA that a policy refusal is temporary (RFC 5321 §4.2.1), so it
// retries a message that will be refused identically until its queue lifetime
// runs out — and the reason the consumer computed never reaches the sender.
//
// A rejection says what it wants through three optional properties, each
// checked independently so a bad one costs only itself:
//
//   err.smtpCode        three digits opening 4 or 5. A 2yz or 3yz would tell
//                       the peer the message was accepted or is awaited by
//                       the very call that refused it, so it is not honoured.
//   err.enhancedStatus  RFC 3463 class.subject.detail whose class matches the
//                       code's first digit. A `550 4.7.1` gives a peer parsing
//                       the enhanced status the opposite verdict from one
//                       parsing the code, so a contradictory status is
//                       replaced with the code's own class rather than taken.
//   err.replyText       operator prose, injection-checked like any other.
//
// Returns { code, text } with the enhanced status already prefixed onto the
// text, which is how both listeners write a reply.
function agentRefusalReply(err, fallbackText) {
  var code = _refusalCode(err && err.smtpCode);
  var cls = code.charAt(0);
  var status = _enhancedStatusForCode(err && err.enhancedStatus, code);
  var text = replyTextOrFallback(err && err.replyText,
    code === DEFAULT_REFUSAL_CODE ? fallbackText : DEFAULT_REFUSAL_TEXT_BY_CLASS[cls]);
  return { code: code, text: status + " " + text };
}

var DEFAULT_REFUSAL_CODE   = "451";
var DEFAULT_REFUSAL_STATUS = "4.3.0";
// Neither names a subsystem that failed: the message was declined, and on the
// permanent side by a policy the consumer holds. "Local delivery error" would
// point an operator reading a bounce at the wrong place.
var DEFAULT_REFUSAL_TEXT_BY_CLASS = { "4": "Message not accepted, try again later",
                                      "5": "Message refused" };

function _refusalCode(supplied) {
  if (typeof supplied === "number" && Number.isInteger(supplied)) supplied = String(supplied);
  if (typeof supplied !== "string") return DEFAULT_REFUSAL_CODE;
  return /^[45][0-9][0-9]$/.test(supplied) ? supplied : DEFAULT_REFUSAL_CODE;
}

function _enhancedStatusForCode(supplied, code) {
  if (typeof supplied === "string" && /^[45]\.[0-9]{1,3}\.[0-9]{1,3}$/.test(supplied) &&
      supplied.charAt(0) === code.charAt(0)) {
    return supplied;
  }
  // Kept rather than dropped: a reply with no enhanced status at all is a
  // downgrade for every peer that reads one. On the default code that means
  // the status this listener has always sent; on a code the agent chose it
  // means RFC 3463's "other or undefined" for that class — the class is
  // known, the detail is not.
  return code === DEFAULT_REFUSAL_CODE ? DEFAULT_REFUSAL_STATUS : code.charAt(0) + ".0.0";
}

// fireConsumerHook(fn, args, cfg) — call a listener's optional consumer hook
// without letting it take the connection down with it.
//
// These hooks report on a connection whose timing the consumer does not
// control: a session ended, a command arrived. They are observability sinks,
// so they DROP SILENT — a consumer throwing inside one would otherwise take
// out the teardown it was being told about, and on a server-wide autologout
// sweep it would take the process. A thrown error is not a way to refuse a
// session that has already ended, so the throw is recorded as a failure audit
// against the connection and the listener carries on.
//
// A rejected promise is the same failure arriving later, and it is the shape to
// expect: releasing a lease or ageing an idle timer is a store call, so a
// consumer writes these hooks `async` far more often than not. A rejection
// nobody observes is an unhandled rejection, which under Node's default takes
// the whole process down — so it is caught too, and recorded identically.
//
//   cfg.emit          the listener's audit emitter.
//   cfg.event         the "<...>_hook_failed" action to record a failure under.
//   cfg.connectionId  the connection the hook was reporting on.
function fireConsumerHook(fn, args, cfg) {
  if (typeof fn !== "function") return;
  safeAsync.safeApply(fn, args, function (e) {
    cfg.emit(cfg.event,
      { connectionId: cfg.connectionId, error: (e && e.message) || String(e) }, "failure");
  });
}

// runSaslStep(cfg) — one round of a multi-step SASL exchange.
//
// IMAP, POP3, ManageSieve and submission all run the same loop: call the
// operator's verifier with the current step and the client's latest response,
// then either write a challenge and wait, complete the authentication, or fail
// it. Only the wire syntax of each outcome differs, so the loop lives here once
// and each listener supplies the four writers. Keeping it in one place is what
// stops the listeners drifting apart again — the whole reason POP3 and
// ManageSieve did not honour `pending` was that each had its own copy.
//
//   cfg.exchange       { mech, step } — mutated: step increments each round.
//   cfg.verify         the operator's verify(mechanism, credentials).
//   cfg.credentials    extra fields merged into the credentials object
//                      (tls, remoteAddress).
//   cfg.clientResponse this round's client response, or null.
//   cfg.writeChallenge (challenge) => boolean — write it, false if unsafe.
//   cfg.onChallengeUnsafe () => void — the challenge could not be written.
//   cfg.onSuccess      (result) => void — verify returned { ok, actor }.
//   cfg.onFailure      (result) => void — verify declined.
//   cfg.onError        (err) => void — verify threw.
//
// A `pending` verdict is NOT a failure and none of the failure paths run for
// it: it is a normal protocol round trip, and charging it against an
// authentication-failure budget would spend the defence that budget exists to
// provide.
function runSaslStep(cfg) {
  var ex = cfg.exchange;
  // A client can put several lines in one TCP segment, and a listener's drain
  // loop dispatches them without awaiting. Two SASL responses arriving together
  // therefore each started a verifier call at the SAME `ex.step`: concurrent
  // rounds, results landing out of order, and a later response able to complete
  // authentication before the challenge for it had been issued.
  //
  // A client that answers before it has been asked is not following the
  // protocol, so the second response fails the exchange rather than queueing:
  // queueing would preserve the ordering but still credit a response the server
  // never solicited.
  // Once a pipelining violation has been reported the exchange is DEAD, and
  // stays dead. A listener is expected to tear the connection down, but if it
  // does not, a resumed exchange must not become authenticable just because the
  // violation has scrolled past.
  if (ex.abandoned) {
    cfg.onFailure({ reason: "pipelined-sasl-response" });
    return Promise.resolve();
  }
  if (ex.inFlight) {
    // The round already in flight is ABANDONED, not merely reported. Its
    // verifier has already been called and can still resolve `{ ok: true }`,
    // and invoking onSuccess then authenticates the connection whose pipelined
    // response was just refused — so reporting the refusal would have decided
    // nothing. Every completion below checks this before calling back.
    ex.abandoned = true;
    cfg.onFailure({ reason: "pipelined-sasl-response" });
    return Promise.resolve();
  }
  ex.inFlight = true;
  return Promise.resolve()
    .then(function () {
      var creds = { step: ex.step, clientResponse: cfg.clientResponse };
      if (cfg.credentials) {
        Object.keys(cfg.credentials).forEach(function (k) { creds[k] = cfg.credentials[k]; });
      }
      return cfg.verify(ex.mech, creds);
    })
    .then(function (result) {
      // Cleared before the callbacks run, so the next round — which a
      // challenge invites — is free to start.
      ex.inFlight = false;
      // Abandoned while this was in flight: the listener has already answered
      // the pipelining violation, and a second verdict on a dead exchange is
      // the bypass this guard exists to close.
      if (ex.abandoned) return;
      ex.step += 1;
      if (result && result.pending && typeof result.challenge === "string") {
        if (cfg.writeChallenge(result.challenge)) return;
        cfg.onChallengeUnsafe();
        return;
      }
      // What onSuccess returns stays in the chain. A listener that finishes
      // authenticating asynchronously -- opening a mailbox before the session
      // leaves its unauthenticated stage -- hands that work back here, and a
      // caller waiting on this step is waiting for the session to be
      // authenticated rather than for the credential check alone.
      if (result && result.ok === true && result.actor) { return cfg.onSuccess(result); }
      return cfg.onFailure(result);
    })
    .catch(function (err) {
      ex.inFlight = false;
      if (ex.abandoned) return;                    // same reason as the resolve path
      cfg.onError(err);
    });
}

module.exports = {
  createTcpListener: createTcpListener,
  runSaslStep:       runSaslStep,
  createStoreServer: createStoreServer,
  admitConnection:   admitConnection,
  trackConnection:   trackConnection,
  acceptConnection:  acceptConnection,
  createBodyRateWindow: createBodyRateWindow,
  DEFAULT_MAX_CONNECTIONS: DEFAULT_MAX_CONNECTIONS,
  validateDomainHardened: validateDomainHardened,
  saslChallengeOrNull: saslChallengeOrNull,
  replyTextOrFallback:  replyTextOrFallback,
  agentRefusalReply:    agentRefusalReply,
  foldSubaddress:       foldSubaddress,
  fireConsumerHook:     fireConsumerHook,
};
