// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * lib/mail-server-net — the pieces every mail listener shares.
 *
 * `runSaslStep` is the one that matters most here: IMAP, submission, POP3 and
 * ManageSieve all drive their SASL exchange through it, and the whole reason it
 * exists is that four copies of this state machine drifted apart. A defect in
 * it is a defect in every listener at once, so it is tested directly rather
 * than only through whichever listener happens to have coverage.
 *
 * Run standalone: `node test/layer-0-primitives/mail-server-net.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var check   = helpers.check;
var b       = helpers.b;

var mailServerNet = require("../../lib/mail-server-net");

// A verifier that resolves on demand, so a second response can be dispatched
// while the first is still in flight — which is the situation a client creates
// by putting two lines in one TCP segment.
function _deferredVerify() {
  var pending = [];
  function verify() {
    return new Promise(function (resolve, reject) { pending.push({ resolve: resolve, reject: reject }); });
  }
  verify.settleFirst = function (value) { pending.shift().resolve(value); };
  verify.rejectFirst = function (err) { pending.shift().reject(err); };
  verify.count = function () { return pending.length; };
  return verify;
}

function _recorder() {
  var calls = { success: [], failure: [], error: [], challenge: [], unsafe: [] };
  return {
    calls: calls,
    writeChallenge:    function (c) { calls.challenge.push(c); return true; },
    onChallengeUnsafe: function () { calls.unsafe.push(true); },
    onSuccess:         function (r) { calls.success.push(r); },
    onFailure:         function (r) { calls.failure.push(r); },
    onError:           function (e) { calls.error.push(e); },
  };
}

// A pipelined second response is refused. The round already in flight must be
// ABANDONED, not merely reported: a verifier that has already been called can
// still resolve `{ ok: true }`, and invoking onSuccess then authenticates the
// connection whose pipelined response was just refused. Reporting the refusal
// and letting the earlier promise land anyway means the refusal decided
// nothing.
async function testPipelinedSaslResponseAbandonsTheRoundInFlight() {
  var verify = _deferredVerify();
  var rec = _recorder();
  var ex = { mech: "PLAIN", step: 0 };
  function step(clientResponse) {
    return mailServerNet.runSaslStep({
      exchange: ex, verify: verify, clientResponse: clientResponse,
      writeChallenge: rec.writeChallenge, onChallengeUnsafe: rec.onChallengeUnsafe,
      onSuccess: rec.onSuccess, onFailure: rec.onFailure, onError: rec.onError,
    });
  }

  var first = step("first");                       // starts the verifier
  await helpers.waitUntil(function () { return verify.count() === 1; },
    { timeoutMs: 5000, label: "sasl pipelining: the first verifier is in flight" });
  await step("second");                            // arrives while it is pending
  check("pipelined: the second response is refused",
        rec.calls.failure.length === 1 &&
        rec.calls.failure[0].reason === "pipelined-sasl-response",
        JSON.stringify(rec.calls.failure));
  check("pipelined: the second response does not start a second verifier",
        verify.count() === 1, String(verify.count()));

  // Now let the first verifier succeed. Nothing may come of it.
  verify.settleFirst({ ok: true, actor: { id: "u1" } });
  await first;
  await helpers.passiveObserve(50, "sasl pipelining: no late success callback");
  check("pipelined: the abandoned round cannot authenticate the connection",
        rec.calls.success.length === 0, JSON.stringify(rec.calls.success));
  check("pipelined: and reports no second verdict",
        rec.calls.failure.length === 1, JSON.stringify(rec.calls.failure));
  check("pipelined: nor writes a challenge after the refusal",
        rec.calls.challenge.length === 0, JSON.stringify(rec.calls.challenge));

  // The exchange stays dead. A listener is expected to tear the connection
  // down, but if it does not, a resumed exchange must not become authenticable
  // just because the violation has scrolled past.
  await step("third");
  check("pipelined: the exchange cannot be resumed afterwards",
        rec.calls.success.length === 0 && rec.calls.failure.length === 2 &&
        rec.calls.failure[1].reason === "pipelined-sasl-response",
        JSON.stringify(rec.calls.failure));
}

// A verifier that THROWS on the abandoned round must not surface an error
// either — the listener has already answered, and a second verdict on a dead
// exchange is the same defect wearing the other outcome.
async function testAbandonedRoundSwallowsAVerifierThrow() {
  var verify = _deferredVerify();
  var rec = _recorder();
  var ex = { mech: "PLAIN", step: 0 };
  function step(clientResponse) {
    return mailServerNet.runSaslStep({
      exchange: ex, verify: verify, clientResponse: clientResponse,
      writeChallenge: rec.writeChallenge, onChallengeUnsafe: rec.onChallengeUnsafe,
      onSuccess: rec.onSuccess, onFailure: rec.onFailure, onError: rec.onError,
    });
  }
  var first = step("first");
  await step("second");
  verify.rejectFirst(new Error("verifier exploded"));
  await first;
  await helpers.passiveObserve(50, "sasl pipelining: no late error callback");
  check("pipelined: a throw on the abandoned round reports nothing",
        rec.calls.error.length === 0, JSON.stringify(rec.calls.error.map(String)));
}

// The control. Without pipelining the exchange behaves normally, so the guard
// above is refusing a violation rather than breaking authentication.
async function testAnOrdinaryExchangeStillCompletes() {
  var verify = _deferredVerify();
  var rec = _recorder();
  var ex = { mech: "SCRAM-SHA-256", step: 0 };
  function step(clientResponse) {
    return mailServerNet.runSaslStep({
      exchange: ex, verify: verify, clientResponse: clientResponse,
      writeChallenge: rec.writeChallenge, onChallengeUnsafe: rec.onChallengeUnsafe,
      onSuccess: rec.onSuccess, onFailure: rec.onFailure, onError: rec.onError,
    });
  }

  // Round one asks a question. The verifier is invoked a microtask after the
  // call returns, so wait for it to actually be pending rather than assuming
  // it already is.
  var r1 = step("client-first");
  await helpers.waitUntil(function () { return verify.count() === 1; },
    { timeoutMs: 5000, label: "sasl control: the first verifier is pending" });
  verify.settleFirst({ pending: true, challenge: "server-first" });
  await r1;
  check("control: a pending verdict writes the challenge",
        rec.calls.challenge.length === 1 && rec.calls.challenge[0] === "server-first",
        JSON.stringify(rec.calls.challenge));
  check("control: a pending verdict is not a failure",
        rec.calls.failure.length === 0, JSON.stringify(rec.calls.failure));
  check("control: the step advanced", ex.step === 1, String(ex.step));

  // Round two answers it, sequentially — the client waited to be asked.
  var r2 = step("client-final");
  await helpers.waitUntil(function () { return verify.count() === 1; },
    { timeoutMs: 5000, label: "sasl control: the second verifier is pending" });
  verify.settleFirst({ ok: true, actor: { id: "u1" } });
  await r2;
  check("control: a sequential exchange authenticates",
        rec.calls.success.length === 1 && rec.calls.success[0].actor.id === "u1",
        JSON.stringify(rec.calls.success));
}

// Every listener capped connections PER SOURCE ADDRESS and nowhere else, so the
// process-wide ceiling was whatever the per-address cap happened to be times
// however many addresses the peer could speak from. A botnet, a NAT pool or a
// v6 /64 makes that number large, and each accepted socket costs a file
// descriptor and a parser state machine before any authentication.
//
// `maxConnections` is the listener's own ceiling, and it belongs on the factory
// every listener shares rather than in five copies.
async function testListenerCeilingRefusesBeyondMaxConnections() {
  var nodeNet = require("node:net");
  var accepted = [];
  var emits = [];
  var listener = mailServerNet.createTcpListener(nodeNet, {
    defaultPort:      0,
    maxConnections:   2,
    handleConnection: function (sock) { accepted.push(sock); sock.write("* OK ready\r\n"); },
    errorFactory:     function (code, message) { return new Error(code + ": " + message); },
    // Recorded rather than discarded: a refusal at the ceiling emitted
    // nothing at all, so an emitter that throws its argument away could not
    // tell a listener turning senders away from an idle one — which is
    // precisely the condition an operator needs to see.
    emit:             function (action, meta, outcome) {
      emits.push({ action: action, meta: meta, outcome: outcome });
    },
    listeningEvent:   "test.listening",
    ceilingRefusedEvent: "test.max_connections_refused",
  });
  var info = await listener.listen({ port: 0, address: "127.0.0.1" });

  var clients = [];
  function dial() {
    return new Promise(function (resolve) {
      var c = nodeNet.connect(info.port, "127.0.0.1");
      clients.push(c);
      var settled = false;
      function done(how) { if (!settled) { settled = true; resolve(how); } }
      c.on("data",  function () { done("greeted"); });
      c.on("close", function () { done("closed"); });
      c.on("error", function () { done("closed"); });
    });
  }

  try {
    check("net: the first connection is served",  (await dial()) === "greeted");
    check("net: the second connection is served", (await dial()) === "greeted");
    // Node enforces the ceiling by closing the excess socket without ever
    // handing it to the connection handler, so the peer gets a close and the
    // listener spends nothing on it.
    check("net: the third connection is refused at the ceiling",
      (await dial()) === "closed");
    check("net: the refused connection never reached the handler",
      accepted.length === 2, String(accepted.length));

    // And it is visible. Nothing downstream of the drop runs by design, so
    // this is the only place a listener at capacity can be observed at all —
    // without it, an operator's first evidence is a peer complaining.
    await helpers.waitUntil(function () {
      return emits.some(function (e) { return /max_connections_refused/.test(e.action); });
    }, { timeoutMs: 5000, label: "net: the ceiling refusal is emitted" });                              // allow:raw-time-literal — test-only cap
    var refusal = emits.filter(function (e) {
      return /max_connections_refused/.test(e.action);
    })[0];
    check("net: a connection dropped at the ceiling is audited",
      !!refusal, JSON.stringify(emits.map(function (e) { return e.action; })));
    check("net: the refusal is recorded as a denial, not an informational note",
      refusal && refusal.outcome === "denied", refusal && refusal.outcome);
    check("net: and it carries the ceiling it hit, so the number is actionable",
      refusal && refusal.meta && refusal.meta.maxConnections === 2 &&
      refusal.meta.reason === "listener-at-capacity",
      JSON.stringify(refusal && refusal.meta));
  } finally {
    clients.forEach(function (c) { c.destroy(); });
    await listener.closeSimple({
      connections: new Set(accepted), emit: function () {}, closedEvent: "test.closed",
    });
  }
}

// The body-rate floor was measured as a LIFETIME average from the DATA prompt,
// so an early burst subsidised an arbitrarily slow tail. At the default 100 B/s
// an 8 MiB burst buys about a day of credit and 50 MiB buys six, which a peer
// spends holding a connection and its slot in the per-address cap while sending
// a byte at a time — on the MX listener, unauthenticated. The floor was
// enforced and still bypassable.
//
// Measuring over bounded windows removes the credit: each window has to meet
// the floor on its own, so nothing a peer sent earlier pays for what it sends
// now. The clock is a parameter here rather than Date.now(), which is what lets
// this drive days of simulated time without waiting for them.
function testBodyRateWindowGivesNoCreditForAnEarlyBurst() {
  var rl = b.mail.server.rateLimit.create({ minBytesPerSecond: 100 });
  var grace = b.mail.server.rateLimit.BODY_RATE_GRACE_MS;
  check("net: the grace window is exposed so a caller can reason about it",
        typeof grace === "number" && grace > 0, String(grace));

  // A peer that front-loads 8 MiB and then trickles one byte per window.
  var w = mailServerNet.createBodyRateWindow(rl);
  var t = 0;
  w.start(t);
  var seen = 8 * 1024 * 1024;
  t += grace;
  check("net: the burst itself is not starved",
        w.starved(seen, t) === false);

  // Now the trickle. Under a lifetime average this stays admitted for days;
  // over bounded windows the very next full window is below the floor.
  t += grace;
  seen += 1;
  check("net: a trickle AFTER a burst is starved on the next window",
        w.starved(seen, t) === true,
        "seen=" + seen + " t=" + t);

  // A sender that keeps meeting the floor is never cut off, however long it
  // runs — the windows roll forward rather than accumulating against it.
  var ok = mailServerNet.createBodyRateWindow(rl);
  var t2 = 0, bytes = 0, everStarved = false;
  ok.start(t2);
  for (var i = 0; i < 50; i += 1) {
    t2 += grace;
    bytes += Math.ceil((grace / 1000) * 100) + 1;         // just over the floor
    if (ok.starved(bytes, t2)) { everStarved = true; break; }
  }
  check("net: a sender that keeps meeting the floor is never cut off",
        everStarved === false);

  // Inside the first grace window nothing is judged: a sender pausing to read
  // from its own spool must not be cut off for the pause.
  var early = mailServerNet.createBodyRateWindow(rl);
  early.start(0);
  check("net: nothing is judged inside the grace window",
        early.starved(1, Math.floor(grace / 2)) === false);

  // The window rolls on the LIMITER's interval, not on the built-in's. A custom
  // limiter that judges over a longer stretch would otherwise be asked only
  // before it can answer — every call returning "too early", the window
  // resetting underneath it at the built-in's ten seconds, and its rate
  // protection silently disabled while appearing to be wired.
  var judged = [];
  var slow = {};
  Object.keys(rl).forEach(function (k) { slow[k] = rl[k]; });
  slow.bodyRateWindowMs = function () { return grace * 6; };
  slow.bodyRateStarved = function (bytes, elapsedMs) {
    judged.push({ bytes: bytes, elapsedMs: elapsedMs });
    if (elapsedMs < grace * 6) return false;             // its own, longer grace
    return (bytes / (elapsedMs / 1000)) < 100;
  };

  var sw = mailServerNet.createBodyRateWindow(slow);
  var st = 0;
  sw.start(st);
  // Trickle one byte per built-in grace period, well past where the built-in
  // would have rolled the window.
  var cut = false;
  for (var k = 1; k <= 6; k += 1) {
    st += grace;
    if (sw.starved(k, st)) { cut = true; break; }
  }
  check("net: a custom limiter is asked at ITS window, and its verdict lands",
        cut === true, JSON.stringify(judged));
  check("net: it was eventually asked with an elapsed reaching its own interval",
        judged.some(function (j) { return j.elapsedMs >= grace * 6; }),
        JSON.stringify(judged.map(function (j) { return j.elapsedMs; })));
}

// The listeners bound how much command text may wait while a handler runs, and
// a literal's payload is not waiting. Which bytes are payload is the caller's
// question, because only the listener knows whether it would take that line
// now; this asks whether the shared scan does what it is told.
function testAnnouncedLiteralBytes() {
  // Every line ending in `{N}` opens a literal of N bytes. A test-only stand-in
  // for a listener's guard, so the scan itself is what is under test.
  function tail(line) {
    var m = /\{([0-9]+)\}$/.exec(line);
    return m ? parseInt(m[1], 10) : null;
  }
  function ann(text, cfg) {
    var full = {
      pending: null, maxLineBytes: 1024, maxPipelinedBytes: 8208, openerBytes: tail,
    };
    for (var k in cfg) if (Object.prototype.hasOwnProperty.call(cfg, k)) full[k] = cfg[k];
    return mailServerNet.announcedLiteralBytes(Buffer.from(text, "utf8"), full);
  }

  check("announcedLiteralBytes: a transfer already in progress answers on its own",
    ann("anything at all", { pending: { size: 500, body: Buffer.alloc(120) } }) === 380);
  check("announcedLiteralBytes: a completed transfer is owed nothing",
    ann("", { pending: { size: 40, body: Buffer.alloc(40) } }) === 0);

  check("announcedLiteralBytes: an opener's arrived payload is exempt",
    ann("PUT {10}\r\n0123456789") === 10);
  check("announcedLiteralBytes: only what has arrived counts",
    ann("PUT {10}\r\n0123") === 4);
  check("announcedLiteralBytes: a line that opens nothing is skipped",
    ann("NOOP\r\nPUT {6}\r\nabcdef") === 6);
  check("announcedLiteralBytes: an unterminated line exempts nothing",
    ann("PUT {10}") === 0);
  check("announcedLiteralBytes: a zero-octet opener exempts nothing",
    ann("PUT {0}\r\nNOOP\r\n") === 0);

  // Only one literal can be in flight, because the reader takes one command at
  // a time. A second is queue, which is exactly what the bound counts.
  check("announcedLiteralBytes: a second opener behind the first is not exempt",
    ann("PUT {4}\r\nabcdPUT {4}\r\nefgh") === 4);

  // A line over the cap is refused where lines are taken, so the scan stops
  // rather than reading an opener out of bytes that will never be a command.
  check("announcedLiteralBytes: a line longer than the cap stops the scan",
    ann("PUT " + "x".repeat(40) + " {6}\r\nabcdef", { maxLineBytes: 8 }) === 0);

  // The scan walks the caller's whole allowance, so a client that queues
  // hundreds of short commands before the one that opens a literal is still
  // answered. A fixed line count would refuse this for the number of commands
  // rather than for their size.
  var many = "";
  for (var i = 0; i < 400; i += 1) many += "NOOP\r\n";
  check("announcedLiteralBytes: the fixture is many lines but inside the allowance",
    many.length < 8208 && many.length / 6 > 64);
  check("announcedLiteralBytes: an opener behind hundreds of short commands is found",
    ann(many + "PUT {6}\r\nabcdef") === 6);

  // Past the allowance the caller refuses the connection whatever this says,
  // so the scan stops rather than walking an unbounded queue.
  var over = "";
  while (over.length <= 8208) over += "NOOP\r\n";
  check("announcedLiteralBytes: an opener past the allowance is not reached",
    ann(over + "PUT {6}\r\nabcdef") === 0);

  // A caller that answers with something other than a count is not believed.
  check("announcedLiteralBytes: a negative count exempts nothing",
    ann("PUT\r\nbody", { openerBytes: function () { return -1; } }) === 0);
  check("announcedLiteralBytes: a non-numeric count exempts nothing",
    ann("PUT\r\nbody", { openerBytes: function () { return "12"; } }) === 0);
}

// RFC 5233: the detail part after the delimiter is chosen by whoever writes
// the address, so `alice+anything@example.com` is delivered to the mailbox
// `alice@example.com` and can never be enumerated in advance. Folding is what
// lets an identity check compare at the mailbox rather than the spelling.
function testFoldSubaddress() {
  var fold = function (a, d) { return mailServerNet.foldSubaddress(a, d === undefined ? "+" : d); };
  check("foldSubaddress: the detail part is folded away",
    fold("alice+newsletter@example.com") === "alice@example.com");
  // RFC 5321: the domain is case-insensitive (§2.3.4), the local part is not
  // (§2.4). A listener that compares local parts case-insensitively is making
  // a deployment-shaped choice at the point it parses the address; this
  // function does not make it on its behalf.
  check("foldSubaddress: the domain folds, the local part does not",
    fold("ALICE+Tag@Example.COM") === "ALICE@example.com");
  check("foldSubaddress: an address with no tag keeps its local part as given",
    fold("Alice@Example.com") === "Alice@example.com");
  check("foldSubaddress: only the FIRST delimiter separates",
    fold("alice+a+b@example.com") === "alice@example.com");
  // Whether a local part carries a detail part at all is a property of the
  // DELIVERY side. A caller that has not said what its delimiter is gets its
  // address back, rather than a fold this cannot know applies — on a server
  // that allocates plus-addresses as distinct mailboxes, folding would hand
  // one account authority over another's.
  check("foldSubaddress: no delimiter named means no fold",
    mailServerNet.foldSubaddress("alice+tag@example.com") === "alice+tag@example.com" &&
    mailServerNet.foldSubaddress("alice+tag@example.com", "") === "alice+tag@example.com" &&
    mailServerNet.foldSubaddress("ALICE+Tag@Example.com", null) === "ALICE+Tag@example.com");
  // A local part that BEGINS with the delimiter has no base to fold to —
  // `+tag@example.com` is an address in its own right, and folding it to
  // `@example.com` would make every such address collide.
  check("foldSubaddress: a leading delimiter is not a separator",
    fold("+tag@example.com") === "+tag@example.com");
  // The delimiter is a LOCAL-part construct; one in the domain is just a
  // character, and folding there would make a different domain match.
  check("foldSubaddress: a delimiter in the domain is left alone",
    fold("alice@ex+ample.com") === "alice@ex+ample.com");
  check("foldSubaddress: the last @ separates, so an escaped one in the local part is kept",
    fold("a+b@c@example.com") === "a@example.com");
  check("foldSubaddress: an operator whose delivery splits on something else says so",
    fold("alice-tag@example.com", "-") === "alice@example.com" &&
    fold("alice-tag@example.com", "+") === "alice-tag@example.com");
  check("foldSubaddress: a non-address is not invented into one",
    fold("") === "" && fold(null) === "" && fold("not-an-address") === "not-an-address");
  check("foldSubaddress: a local part that is only a tag keeps it",
    fold("+@example.com") === "+@example.com");
  // RFC 5321 §4.1.2 — inside a quoted local part the delimiter is literal
  // mailbox data, so these are two different mailboxes. Folding would collapse
  // them to one string and let either speak for the other.
  check("foldSubaddress: a quoted local part is never folded",
    fold('"alice+one"@example.com') === '"alice+one"@example.com' &&
    fold('"alice+two"@example.com') === '"alice+two"@example.com' &&
    fold('"alice+one"@example.com') !== fold('"alice+two"@example.com'));
}

async function run() {
  testFoldSubaddress();
  testAnnouncedLiteralBytes();
  testBodyRateWindowGivesNoCreditForAnEarlyBurst();
  await testListenerCeilingRefusesBeyondMaxConnections();
  await testPipelinedSaslResponseAbandonsTheRoundInFlight();
  await testAbandonedRoundSwallowsAVerifierThrow();
  await testAnOrdinaryExchangeStillCompletes();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () {
    console.log("[mail-server-net] OK — " + helpers.getChecks() + " checks passed");
  }).catch(function (e) {
    console.error("FAIL:", (e && e.stack) || e);
    process.exit(1);
  });
}
