// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var helpers = require("../helpers");
var check = helpers.check;
var b = helpers.b;

function testSurface() {
  check("surface: b.mail.server.rateLimit namespace",
    typeof b.mail.server.rateLimit === "object");
  check("surface: create is fn", typeof b.mail.server.rateLimit.create === "function");
  check("surface: DEFAULTS object", typeof b.mail.server.rateLimit.DEFAULTS === "object");
  check("surface: error class",   typeof b.mail.server.rateLimit.MailServerRateLimitError === "function");
}

function testBadOptsRefused() {
  function expectThrow(label, opts, codeMatch) {
    var threw = null;
    try { b.mail.server.rateLimit.create(opts); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf(codeMatch) !== -1);
  }
  expectThrow("refuses negative concurrent-per-ip",
    { maxConcurrentConnectionsPerIp: -5 }, "mail-server-rate-limit/bad-bound");
  expectThrow("refuses Infinity rate",
    { connectionsPerIpPerMinute: Infinity }, "mail-server-rate-limit/bad-bound");
  expectThrow("refuses non-integer auth-failure cap",
    { authFailuresPerIpPer15Min: 1.5 }, "mail-server-rate-limit/bad-bound");
  expectThrow("refuses non-bool disabled",
    { disabled: "yes" }, "mail-server-rate-limit/bad-disabled");
  expectThrow("refuses array as opts",
    [], "mail-server-rate-limit/bad-opts");
}

function testConcurrentCap() {
  var rl = b.mail.server.rateLimit.create({
    maxConcurrentConnectionsPerIp: 3,
    connectionsPerIpPerMinute:     100,    // headroom — rate isn't the gate here
  });
  check("admit #1", rl.admitConnection("1.2.3.4").ok === true);
  check("admit #2", rl.admitConnection("1.2.3.4").ok === true);
  check("admit #3", rl.admitConnection("1.2.3.4").ok === true);
  var refuse4 = rl.admitConnection("1.2.3.4");
  check("admit #4 refused (cap=3)",
    refuse4.ok === false && refuse4.reason === "concurrent-per-ip");
  // Different IP — its own slot
  check("admit #1 from other IP", rl.admitConnection("5.6.7.8").ok === true);
  // release frees a slot
  rl.releaseConnection("1.2.3.4");
  check("admit after release", rl.admitConnection("1.2.3.4").ok === true);
}

function testRatePerMinuteCap() {
  var rl = b.mail.server.rateLimit.create({
    maxConcurrentConnectionsPerIp: 1000,   // headroom — concurrent isn't the gate
    connectionsPerIpPerMinute:     5,
  });
  for (var i = 0; i < 5; i += 1) {
    var v = rl.admitConnection("9.9.9.9");
    check("rate admit #" + (i + 1), v.ok === true);
    rl.releaseConnection("9.9.9.9");   // close immediately, only rate matters
  }
  var refused = rl.admitConnection("9.9.9.9");
  check("rate admit #6 refused",
    refused.ok === false && refused.reason === "rate-per-ip");
}

function testAuthFailureBudget() {
  var rl = b.mail.server.rateLimit.create({
    authFailuresPerIpPer15Min: 3,
  });
  check("auth admit clean by default", rl.checkAuthAdmit("11.22.33.44").ok === true);
  rl.noteAuthFailure("11.22.33.44");
  rl.noteAuthFailure("11.22.33.44");
  rl.noteAuthFailure("11.22.33.44");
  var refused = rl.checkAuthAdmit("11.22.33.44");
  check("auth admit refused at cap",
    refused.ok === false && refused.reason === "auth-failures-per-ip");
  // Different IP unaffected
  check("auth admit clean for other IP", rl.checkAuthAdmit("44.55.66.77").ok === true);
}

function testDisabledSkipsAll() {
  var rl = b.mail.server.rateLimit.create({
    maxConcurrentConnectionsPerIp: 1,
    connectionsPerIpPerMinute:     1,
    authFailuresPerIpPer15Min:     1,
    disabled:                      true,
  });
  // Even way past the caps, admit always returns ok
  for (var i = 0; i < 50; i += 1) {
    check("disabled admit #" + i, rl.admitConnection("0.0.0.0").ok === true);
  }
  for (var j = 0; j < 50; j += 1) rl.noteAuthFailure("0.0.0.0");
  check("disabled auth admit always ok",
    rl.checkAuthAdmit("0.0.0.0").ok === true);
  check("disabled isDisabled() returns true", rl.isDisabled() === true);
}

// ---- b.mail.server.rateLimit.resolve — spec → limiter contract ----
//
// Every mail server (IMAP / POP3 / SMTP MX / Submission / ManageSieve)
// runs its operator-supplied `rateLimit` opt through resolve() so the
// spec contract is identical across protocols: `false` disables,
// an already-built limiter passes through untouched, anything else is
// treated as create() options.
function testResolveFalseDisables() {
  var rl = b.mail.server.rateLimit.resolve(false);
  check("resolve(false): returns a disabled limiter", rl.isDisabled() === true);
  // A disabled limiter always admits, even far past any cap.
  var allOk = true;
  for (var i = 0; i < 50; i += 1) {
    if (rl.admitConnection("203.0.113.7").ok !== true) { allOk = false; break; }
  }
  check("resolve(false): admitConnection always admits", allOk === true);
}

function testResolvePassesThroughExistingLimiter() {
  var made = b.mail.server.rateLimit.create({ maxConcurrentConnectionsPerIp: 1 });
  var resolved = b.mail.server.rateLimit.resolve(made);
  check("resolve(limiter): returns the SAME limiter object unchanged",
    resolved === made);
}

function testResolveOptsBuildLimiter() {
  // A plain-object spec is treated as create() options — the cap must
  // actually take effect (proves the opts flowed through create()).
  var rl = b.mail.server.rateLimit.resolve({ maxConcurrentConnectionsPerIp: 1 });
  check("resolve(opts): typeof is a built limiter", typeof rl.admitConnection === "function");
  check("resolve(opts): admit #1 ok", rl.admitConnection("198.51.100.9").ok === true);
  var refused = rl.admitConnection("198.51.100.9");
  check("resolve(opts): admit #2 refused at cap=1",
    refused.ok === false && refused.reason === "concurrent-per-ip");
  check("resolve(opts): not disabled", rl.isDisabled() === false);
}

// resolve() accepted any object carrying `admitConnection` and handed it
// straight to a listener that calls eight methods on it. A limiter missing one
// did not fail at boot — it failed on the request that first reached the call,
// as a TypeError from inside the connection handler, which for the DATA-body
// floor means every message dies mid-transaction.
//
// The sniff was already too weak before the floor existed: `releaseConnection`
// has been called unconditionally on every socket close for as long as the
// listeners have tracked connections, so a limiter with only `admitConnection`
// was already breaking, just later and more quietly. Checking the whole
// interface at resolve() turns all of that into one boot error that names what
// is missing.
function testResolveRefusesAnIncompleteCustomLimiter() {
  var threw = null;
  try { b.mail.server.rateLimit.resolve({ admitConnection: function () { return { ok: true }; } }); }
  catch (e) { threw = e; }
  check("resolve: a custom limiter missing the rest of the interface is refused at config time",
        threw !== null, threw && threw.message);
  check("resolve: the refusal names the missing methods",
        threw && /bodyRateStarved/.test(threw.message) &&
        /releaseConnection/.test(threw.message),
        threw && threw.message);
  check("resolve: the refusal carries a typed code",
        threw && (threw.code || "").indexOf("mail-server-rate-limit/") === 0,
        threw && threw.code);

  // A complete custom limiter still passes through untouched — the point is to
  // name the contract, not to force operators onto the built-in.
  var complete = {};
  var real = b.mail.server.rateLimit.create({});
  Object.keys(real).forEach(function (k) { complete[k] = real[k]; });
  check("resolve: a COMPLETE custom limiter is still returned unchanged",
        b.mail.server.rateLimit.resolve(complete) === complete);
}

// The interface is stated twice: once as the list `resolve` enforces, and once
// as prose in the `resolve` doc block that operators read to build a limiter.
// Two statements of one fact drift, and this one drifts in the direction that
// costs the operator everything: implement exactly what the prose names, and
// the boot still refuses you for the method it forgot to mention.
//
// So the test compares them rather than restating either. Adding a method to
// the enforced list without naming it in the prose fails here, which is the
// moment it is cheap to fix.
function testDocumentedLimiterInterfaceMatchesTheEnforcedOne() {
  var fs = require("node:fs");
  var path = require("node:path");
  var src = fs.readFileSync(
    path.resolve(__dirname, "../../lib/mail-server-rate-limit.js"), "utf8");

  // The doc-block sentence that tells an operator what to implement.
  var sentence = src.match(
    /must implement the\s*\n?[\s\S]{0,80}?interface the listeners call —([\s\S]*?)— or resolve/);
  check("rate-limit: the resolve doc block still names the required interface",
        sentence !== null, "the sentence this test reads has moved or been reworded");
  if (!sentence) return;

  var documented = [];
  var re = /`([A-Za-z]+)`/g;
  var m;
  while ((m = re.exec(sentence[1])) !== null) documented.push(m[1]);

  // Read the enforced list from the source too, rather than from a hand-copied
  // mirror here — a third statement of the same fact is the bug, not the fix.
  var enforcedBlock = src.match(/var LIMITER_INTERFACE = Object\.freeze\(\[([\s\S]*?)\]\)/);
  check("rate-limit: the enforced interface list is readable",
        enforcedBlock !== null);
  if (!enforcedBlock) return;
  var enforced = [];
  var re2 = /"([A-Za-z]+)"/g;
  while ((m = re2.exec(enforcedBlock[1])) !== null) enforced.push(m[1]);

  var missingFromDocs = enforced.filter(function (n) { return documented.indexOf(n) === -1; });
  var extraInDocs = documented.filter(function (n) { return enforced.indexOf(n) === -1; });

  check("rate-limit: every enforced method is named in the operator prose",
        missingFromDocs.length === 0,
        "enforced but undocumented: " + JSON.stringify(missingFromDocs));
  check("rate-limit: the prose names nothing the boot does not require",
        extraInDocs.length === 0,
        "documented but not enforced: " + JSON.stringify(extraInDocs));
  // Guards the comparison itself: if either extraction silently returned an
  // empty list the two checks above would agree about nothing and pass.
  check("rate-limit: both lists were actually extracted",
        enforced.length >= 8 && documented.length === enforced.length,
        JSON.stringify({ enforced: enforced.length, documented: documented.length }));
}

function testResolveUndefinedUsesDefaults() {
  // resolve() / resolve(null) → create({}) with defaults: a working,
  // non-disabled limiter that admits within the default cap.
  var rlUndef = b.mail.server.rateLimit.resolve();
  check("resolve(undefined): returns a working limiter",
    typeof rlUndef.admitConnection === "function" && rlUndef.isDisabled() === false);
  check("resolve(undefined): admits a first connection",
    rlUndef.admitConnection("192.0.2.5").ok === true);

  var rlNull = b.mail.server.rateLimit.resolve(null);
  check("resolve(null): returns a working limiter",
    typeof rlNull.admitConnection === "function" && rlNull.isDisabled() === false);
}

// `minBytesPerSecond` was documented as a slow-loris floor on DATA from the day
// this module shipped: validated, defaulted to 100, and exposed as a getter that
// NO listener ever called. `idleTimeoutMs` cuts a fully stalled connection, but
// a peer trickling a few bytes at a time resets that timer forever and holds a
// connection — and its slot in the per-address cap — for as long as it likes.
//
// The policy lives here with the number so both listeners ask the same question.
function testBodyRateFloorIsEnforceable() {
  var rl = b.mail.server.rateLimit.create({ minBytesPerSecond: 100 });

  // Below the grace window nothing is judged: the first chunk arrives with
  // almost no elapsed time, so a rate computed from it is noise, and a sender
  // pausing to read from its own spool would be cut off for it.
  check("body rate: nothing is judged inside the grace window",
        rl.bodyRateStarved(1, 500) === false);

  // Past the window, a trickle is starved and an ordinary sender is not.
  check("body rate: a trickle past the window is starved",
        rl.bodyRateStarved(60, 30000) === true);          // 2 B/s against a 100 floor
  check("body rate: a normal sender is not starved",
        rl.bodyRateStarved(500000, 30000) === false);     // ~16 KB/s

  // Exactly at the floor is not below it — a boundary that refuses a
  // conforming sender is a worse failure than one that admits a marginal one.
  check("body rate: exactly at the floor is admitted",
        rl.bodyRateStarved(1000, 10000) === false);       // exactly 100 B/s
  check("body rate: a hair under the floor is starved",
        rl.bodyRateStarved(999, 10000) === true);

  // `disabled` is the ONE spelling for "do not apply this". A zero floor is
  // refused at construction rather than accepted as a second way to say off —
  // two spellings for the same thing is how one of them ends up unenforced.
  var off = b.mail.server.rateLimit.create({ disabled: true });
  check("body rate: a disabled limiter never starves",
        off.bodyRateStarved(1, 60000) === false);
  var zeroThrew = null;
  try { b.mail.server.rateLimit.create({ minBytesPerSecond: 0 }); }
  catch (e) { zeroThrew = e; }
  check("body rate: a zero floor is refused at construction, not read as off",
        zeroThrew !== null, zeroThrew && zeroThrew.message);
}

function run() {
  testBodyRateFloorIsEnforceable();
  testSurface();
  testBadOptsRefused();
  testConcurrentCap();
  testRatePerMinuteCap();
  testAuthFailureBudget();
  testDisabledSkipsAll();
  testResolveFalseDisables();
  testResolvePassesThroughExistingLimiter();
  testResolveOptsBuildLimiter();
  testResolveUndefinedUsesDefaults();
  testResolveRefusesAnIncompleteCustomLimiter();
  testDocumentedLimiterInterfaceMatchesTheEnforcedOne();
}

module.exports = { run: run };

if (require.main === module) {
  try { run(); console.log("[mail-server-rate-limit] OK"); }
  catch (e) { process.stderr.write("FAIL: " + (e && e.stack || e) + "\n"); process.exit(1); }
}
