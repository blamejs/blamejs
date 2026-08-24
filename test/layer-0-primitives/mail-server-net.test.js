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

async function run() {
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
