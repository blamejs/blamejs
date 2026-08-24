// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var codepointClass = require("./codepoint-class");

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
    handleConnection: cfg.handleConnection,
    errorFactory:     function (code, message) { return new ErrorClass(cfg.errorCodePrefix + code, message); },
    emit:             cfg.emit,
    listeningEvent:   cfg.eventBase + ".listening",
  });
  function close() {
    return listener.closeSimple({
      connections: cfg.connections,
      emit:        cfg.emit,
      closedEvent: cfg.eventBase + ".closed",
    });
  }
  return { listen: listener.listen, close: close };
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
    try { socket.write(cfg.refusalLine); } catch (_e) { /* socket may be down */ }
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
      if (result && result.ok === true && result.actor) { cfg.onSuccess(result); return; }
      cfg.onFailure(result);
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
  validateDomainHardened: validateDomainHardened,
  saslChallengeOrNull: saslChallengeOrNull,
  replyTextOrFallback:  replyTextOrFallback,
};
