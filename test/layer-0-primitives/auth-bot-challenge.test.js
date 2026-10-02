// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.authBotChallenge — adaptive bot-challenge gate for auth paths.
 *
 * Run standalone: `node test/layer-0-primitives/auth-bot-challenge.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b      = helpers.b;
var check  = helpers.check;

function _captureAudit() {
  var captured = [];
  return {
    safeEmit: function (e) { captured.push(e); },
    captured: captured,
    byAction: function (action) {
      return captured.filter(function (e) { return e.action === action; });
    },
  };
}

// In-memory store matching the b.cache get/set/del shape.
function _memoryStore() {
  var data = new Map();
  return {
    data: data,
    get:  function (k) { return Promise.resolve(data.get(k)); },
    set:  function (k, v) { data.set(k, v); return Promise.resolve(); },
    del:  function (k) { data.delete(k); return Promise.resolve(); },
  };
}

// Minimal lockout-shaped fake matching create()'s contract.
function _fakeLockout() {
  var state = {};
  var calls = { fail: 0, success: 0, unlock: 0 };
  return {
    calls: calls,
    state: state,
    recordFailure: function (key) {
      calls.fail += 1;
      state[key] = (state[key] || 0) + 1;
      return Promise.resolve({ locked: false, attempts: state[key] });
    },
    recordSuccess: function (key) {
      calls.success += 1;
      delete state[key];
      return Promise.resolve();
    },
    check: function (key) {
      return Promise.resolve({ locked: false, attempts: state[key] || 0 });
    },
    unlock: function (key) {
      calls.unlock += 1;
      delete state[key];
      return Promise.resolve(true);
    },
  };
}

// Simple bot-guard fake: configurable verdict.
function _fakeBotGuard(behaviour) {
  return function (req, res, next) {
    if (behaviour === "tag") {
      req.suspectedBot = "missing-accept-language";
      return next();
    }
    if (behaviour === "block") {
      if (typeof res.writeHead === "function") res.writeHead(403);
      res.end("blocked");
      return;
    }
    return next();  // "pass"
  };
}

function _mockReq(overrides) {
  return Object.assign({
    url: "/login",
    method: "POST",
    headers: {
      "user-agent": "Mozilla/5.0 (test)",
      "accept-language": "en-US,en;q=0.9",
    },
    body: { email: "user@example.com" },
    socket: { remoteAddress: "192.0.2.1" },
  }, overrides || {});
}

function _mockRes() {
  var r = {
    statusCode: 0,
    body: "",
    headers: {},
    writableEnded: false,
    writeHead: function (status, headers) {
      r.statusCode = status;
      r.headers = headers || {};
    },
    end: function (body) { r.body = body || ""; r.writableEnded = true; },
  };
  return r;
}

function testSurface() {
  check("b.authBotChallenge namespace", typeof b.authBotChallenge === "object");
  check("b.authBotChallenge.create is function", typeof b.authBotChallenge.create === "function");
  check("STATES frozen", Object.isFrozen(b.authBotChallenge.STATES));
  check("DEFAULTS.threshold 3", b.authBotChallenge.DEFAULTS.threshold === 3);
  check("DEFAULTS.escalationThreshold 6", b.authBotChallenge.DEFAULTS.escalationThreshold === 6);
  check("authBotChallenge.AuthBotChallengeError is fn",
        typeof b.authBotChallenge.AuthBotChallengeError === "function");
}

function testCreateRejectsBadOpts() {
  var threw;
  threw = false;
  try { b.authBotChallenge.create(); } catch (_e) { threw = true; }
  check("create() rejects empty opts", threw);

  threw = false;
  try {
    b.authBotChallenge.create({
      botGuard: _fakeBotGuard("pass"),
      lockout:  _fakeLockout(),
      sessionStore: _memoryStore(),
      threshold: 5,
      escalationThreshold: 3,
    });
  } catch (_e) { threw = true; }
  check("create() rejects escalationThreshold <= threshold", threw);

  threw = false;
  try {
    b.authBotChallenge.create({
      botGuard: "not-a-fn",
      lockout:  _fakeLockout(),
      sessionStore: _memoryStore(),
    });
  } catch (_e) { threw = true; }
  check("create() rejects bad botGuard", threw);

  threw = false;
  try {
    b.authBotChallenge.create({
      botGuard: _fakeBotGuard("pass"),
      lockout:  {},
      sessionStore: _memoryStore(),
    });
  } catch (_e) { threw = true; }
  check("create() rejects bad lockout shape", threw);

  threw = false;
  try {
    b.authBotChallenge.create({
      botGuard: _fakeBotGuard("pass"),
      lockout:  _fakeLockout(),
      sessionStore: { get: function () {} },  // missing set/del
    });
  } catch (_e) { threw = true; }
  check("create() rejects bad sessionStore shape", threw);

  // The address options are handed to b.requestHelpers.trustedClientIp, which
  // raises a bare TypeError. create() documents its refusals as
  // auth-bot-challenge/bad-opt, so an operator matching on `code` would have
  // caught nothing for these three.
  // A single CIDR string is a valid trustedProxies, so the invalid value here
  // is a malformed one; forwardedHeaders takes an array and refuses a string.
  [["clientIpResolver", "not-a-fn"],
   ["trustedProxies", "not-a-cidr"],
   ["forwardedHeaders", "x-forwarded-for"]].forEach(function (pair) {
    var caught = null;
    try {
      var opts = {
        botGuard: _fakeBotGuard("pass"),
        lockout:  _fakeLockout(),
        sessionStore: _memoryStore(),
      };
      opts[pair[0]] = pair[1];
      b.authBotChallenge.create(opts);
    } catch (e) { caught = e; }
    check("create() refuses a bad " + pair[0] + " with its own error code",
      caught !== null && caught.code === "auth-bot-challenge/bad-opt",
      caught === null ? "did not throw" : (caught.code || caught.name) + ": " + caught.message);
  });
}

async function testStaircaseAdvances() {
  var auditMock = _captureAudit();
  var lockout = _fakeLockout();
  var gate = b.authBotChallenge.create({
    botGuard:     _fakeBotGuard("pass"),
    lockout:      lockout,
    sessionStore: _memoryStore(),
    threshold:    2,
    escalationThreshold: 4,
    audit:        auditMock,
  });
  var key = "user@example.com";

  var s1 = await gate.recordFailure(key);
  check("first failure stays NEW", s1.stage === "new");
  var s2 = await gate.recordFailure(key);
  check("second failure transitions to challenged", s2.stage === "challenged");
  check("audit emitted required",
    auditMock.byAction("auth.bot_challenge.required").length === 1);

  var s3 = await gate.recordFailure(key);
  check("third failure stays challenged", s3.stage === "challenged");
  var s4 = await gate.recordFailure(key);
  check("fourth failure escalates to locked", s4.stage === "locked");
  check("audit emitted escalated",
    auditMock.byAction("auth.bot_challenge.escalated").length === 1);
}

async function testMiddlewareChallengeFn() {
  var auditMock = _captureAudit();
  var lockout = _fakeLockout();
  var challengeCalls = 0;
  var gate = b.authBotChallenge.create({
    botGuard:     _fakeBotGuard("tag"),  // marks suspectedBot
    lockout:      lockout,
    sessionStore: _memoryStore(),
    threshold:    1,
    escalationThreshold: 5,
    challengeFn:  function (req) {
      challengeCalls += 1;
      return Promise.resolve(req.body && req.body.captchaToken === "good");
    },
    audit:        auditMock,
  });
  var email = "user@example.com";
  // The body rung namespaces what it reads, so the ladder the middleware will
  // look up is "body:<email>". Seeding anything else tests nothing.
  var key = "body:" + email;
  // Force the state into challenged.
  await gate.recordFailure(key);

  var mw = gate.middleware();
  var nextCalled = 0;
  // Bad captcha → middleware should not call next; it writes 401.
  var req = _mockReq({ body: { email: email, captchaToken: "wrong" } });
  var res = _mockRes();
  await mw(req, res, function () { nextCalled += 1; });
  check("middleware did not call next on bad captcha", nextCalled === 0);
  check("middleware wrote 401", res.statusCode === 401);
  check("challengeFn invoked", challengeCalls === 1);

  // Good captcha → next called, state transitions to passed.
  var req2 = _mockReq({ body: { email: email, captchaToken: "good" } });
  var res2 = _mockRes();
  await mw(req2, res2, function () { nextCalled += 1; });
  check("middleware calls next on good captcha", nextCalled === 1);
  check("audit emitted passed",
    auditMock.byAction("auth.bot_challenge.passed").length >= 1);
}

async function testMiddlewareLockedReturns423() {
  var lockout = _fakeLockout();
  var auditMock = _captureAudit();
  var gate = b.authBotChallenge.create({
    botGuard:     _fakeBotGuard("pass"),
    lockout:      lockout,
    sessionStore: _memoryStore(),
    threshold:    1,
    escalationThreshold: 2,
    audit:        auditMock,
  });
  var email = "u@x";
  var key = "body:" + email;      // the ladder the body rung will look up
  await gate.recordFailure(key);
  await gate.recordFailure(key);  // → locked

  var mw = gate.middleware();
  var req = _mockReq({ body: { email: email } });
  var res = _mockRes();
  var nextCalled = 0;
  await mw(req, res, function () { nextCalled += 1; });
  check("middleware refuses locked session with 423", res.statusCode === 423);
  check("middleware did not call next on locked", nextCalled === 0);
}

async function testRecordSuccessClears() {
  var lockout = _fakeLockout();
  var auditMock = _captureAudit();
  var gate = b.authBotChallenge.create({
    botGuard:     _fakeBotGuard("pass"),
    lockout:      lockout,
    sessionStore: _memoryStore(),
    threshold:    2,
    escalationThreshold: 5,
    audit:        auditMock,
  });
  await gate.recordFailure("u@x");
  await gate.recordFailure("u@x");
  var pre = await gate.check("u@x");
  check("state advanced to challenged", pre.stage === "challenged");
  await gate.recordSuccess("u@x");
  var post = await gate.check("u@x");
  check("state cleared after recordSuccess", post.stage === "new");
  check("lockout.recordSuccess called", lockout.calls.success >= 1);
}

async function testReset() {
  var lockout = _fakeLockout();
  var gate = b.authBotChallenge.create({
    botGuard:     _fakeBotGuard("pass"),
    lockout:      lockout,
    sessionStore: _memoryStore(),
    threshold:    2,
    escalationThreshold: 5,
  });
  await gate.recordFailure("u@x");
  await gate.recordFailure("u@x");
  var did = await gate.reset("u@x");
  check("reset returns true when state existed", did === true);
  check("lockout.unlock called by reset", lockout.calls.unlock >= 1);
}

async function testEscalationFnInvoked() {
  var escalated = 0;
  var gate = b.authBotChallenge.create({
    botGuard:     _fakeBotGuard("pass"),
    lockout:      _fakeLockout(),
    sessionStore: _memoryStore(),
    threshold:    1,
    escalationThreshold: 2,
    escalationFn: function () { escalated += 1; return Promise.resolve(); },
  });
  await gate.recordFailure("u@x");
  await gate.recordFailure("u@x");
  // Yield so the in-flight escalationFn can settle.
  await new Promise(function (r) { setImmediate(r); });
  check("escalationFn invoked when threshold crossed", escalated === 1);
}

// Concurrent failures on one key must not lose increments. A read-modify-
// write over an async store races without per-key serialization: N parallel
// recordFailure calls each read the same pre-write counter, so the failure
// count lands at 1 and the gate never crosses its thresholds. The same N
// calls run sequentially must reach the locked stage; the concurrent set
// must reach the identical stage.
async function testConcurrentFailuresDoNotLoseIncrements() {
  var lockout = _fakeLockout();
  var gate = b.authBotChallenge.create({
    botGuard:     _fakeBotGuard("pass"),
    lockout:      lockout,
    sessionStore: _memoryStore(),
    threshold:    2,
    escalationThreshold: 4,
    audit:        _captureAudit(),
  });
  var key = "race@example.com";

  var results = await Promise.all([
    gate.recordFailure(key),
    gate.recordFailure(key),
    gate.recordFailure(key),
    gate.recordFailure(key),
  ]);
  // The serialized chain produces a strictly increasing failure count.
  var failures = results.map(function (r) { return r.failures; }).sort(function (a, c) { return a - c; });
  check("4 concurrent failures increment to 1..4 (no lost update)",
    failures[0] === 1 && failures[1] === 2 && failures[2] === 3 && failures[3] === 4);
  var locked = await gate.check(key);
  check("4 concurrent failures reach the same locked stage as sequential",
    locked.stage === "locked");
  // The lockout subscriber sees every failure, not a collapsed single call.
  check("lockout subscriber receives all 4 propagated failures",
    lockout.calls.fail === 4);
}

// ---- the ladder is per principal, not per address ----
//
// The default key came from `body.email`, then `body.username`, then the client
// address. Every auth route that does not carry a credential in the body -- a
// token refresh, a step-up, an OTP confirmation -- therefore fell to the
// address, so every caller behind one NAT or one reverse proxy advanced a
// single ladder: one of them reaches the escalation threshold and the rest are
// locked out with it. An authenticated request names a principal, and that is
// what the ladder should count.
//
// The address also came from `clientIp` with no options, which reads the socket
// and ignores forwarded headers. That is right against a forged header and
// wrong behind a real proxy, where every request carries the proxy's address:
// one ladder for the whole internet. Declaring the proxy resolves the client.
async function testLadderIsPerPrincipalNotPerAddress() {
  function _gate(extra) {
    var opts = {
      botGuard:            _fakeBotGuard("pass"),
      lockout:             _fakeLockout(),
      sessionStore:        _memoryStore(),
      threshold:           3,
      escalationThreshold: 6,
    };
    if (extra) { Object.keys(extra).forEach(function (k) { opts[k] = extra[k]; }); }
    return b.authBotChallenge.create(opts);
  }

  // Two authenticated principals from one address, neither naming itself in the
  // body, which is what a refresh or step-up POST looks like.
  var gate = _gate();
  var alice = _mockReq({ url: "/token/refresh", body: {},
                         user: { sub: "alice" }, socket: { remoteAddress: "198.51.100.7" } });
  var bob   = _mockReq({ url: "/token/refresh", body: {},
                         user: { sub: "bob" },   socket: { remoteAddress: "198.51.100.7" } });
  var resA = _mockRes(), resB = _mockRes();
  await gate.middleware()(alice, resA, function () {});
  await gate.middleware()(bob,   resB, function () {});
  check("bot-challenge: the middleware reports the key it counted on",
    typeof alice.botChallengeKey === "string" && alice.botChallengeKey.length > 0,
    String(alice.botChallengeKey));
  check("bot-challenge: two principals from one address are two ladders",
    alice.botChallengeKey !== bob.botChallengeKey,
    JSON.stringify({ alice: alice.botChallengeKey, bob: bob.botChallengeKey }));

  // Advancing one principal to the escalation threshold must not lock the other.
  var i;
  for (i = 0; i < 6; i += 1) { await gate.recordFailure(alice.botChallengeKey); }
  var aliceState = await gate.check(alice.botChallengeKey);
  var bobState   = await gate.check(bob.botChallengeKey);
  check("bot-challenge: the advanced principal is locked",
    aliceState.stage === "locked", JSON.stringify(aliceState));
  check("bot-challenge: the other principal behind that address is not",
    bobState.stage !== "locked", JSON.stringify(bobState));

  // A raw key string is what `req.apiKey = req.headers["x-api-key"]` holds, and
  // the resolver folds a primitive verbatim, so resolving one would write the
  // secret into the ladder key, the lockout key, the session store and every
  // audit row. Only an object carrier names a principal, which is the guard the
  // idempotency scope already applies.
  var secretGate = _gate();
  var SECRET = "sk_live_51H8ZqR2eZvKYlo2C";
  var rawKeyReq = _mockReq({ url: "/token/refresh", body: {}, apiKey: SECRET,
                             socket: { remoteAddress: "198.51.100.21" } });
  await secretGate.middleware()(rawKeyReq, _mockRes(), function () {});
  check("bot-challenge: a raw key string never reaches the ladder key",
    String(rawKeyReq.botChallengeKey).indexOf(SECRET) === -1,
    String(rawKeyReq.botChallengeKey));
  check("bot-challenge: and such a request falls back to the address",
    rawKeyReq.botChallengeKey === "addr:198.51.100.21", String(rawKeyReq.botChallengeKey));

  // requireBoundKey sets { id: record.id || null, ownerId, ... } and nothing
  // requires record.id, so an id-less record named nobody and fell to the
  // address — the bug this rung exists to close. ownerId is the principal the
  // key acts for.
  var ownerGate = _gate();
  var o1 = _mockReq({ url: "/token/refresh", body: {},
                      apiKey: { id: null, ownerId: "acct-1", scopes: ["read"] },
                      socket: { remoteAddress: "198.51.100.22" } });
  var o2 = _mockReq({ url: "/token/refresh", body: {},
                      apiKey: { id: null, ownerId: "acct-2", scopes: ["read"] },
                      socket: { remoteAddress: "198.51.100.22" } });
  await ownerGate.middleware()(o1, _mockRes(), function () {});
  await ownerGate.middleware()(o2, _mockRes(), function () {});
  check("bot-challenge: an id-less key record is named by its ownerId",
    o1.botChallengeKey !== "198.51.100.22" && o2.botChallengeKey !== "198.51.100.22",
    JSON.stringify({ o1: o1.botChallengeKey, o2: o2.botChallengeKey }));
  check("bot-challenge: and two such records from one address are two ladders",
    o1.botChallengeKey !== o2.botChallengeKey,
    JSON.stringify({ o1: o1.botChallengeKey, o2: o2.botChallengeKey }));

  // The address is the fourth rung and needs a namespace like the other three,
  // or a caller who can influence the resolved address spells a named
  // principal's ladder. clientIp returns the last forwarded hop that fails the
  // trusted-proxy test, so a request from inside the trusted range chooses it.
  var spoofGate = _gate({ trustedProxies: ["10.0.0.0/8"] });
  var target = _mockReq({ url: "/token/refresh", body: {}, apiKey: { id: "key-1" },
                          socket: { remoteAddress: "10.0.0.9" } });
  await spoofGate.middleware()(target, _mockRes(), function () {});
  var spoofer = _mockReq({ url: "/token/refresh", body: {},
                           socket: { remoteAddress: "10.0.0.9" },
                           headers: { "x-forwarded-for": target.botChallengeKey + ", 10.0.0.77" } });
  await spoofGate.middleware()(spoofer, _mockRes(), function () {});
  check("bot-challenge: a forwarded address cannot spell a credential ladder",
    spoofer.botChallengeKey !== target.botChallengeKey,
    JSON.stringify({ target: target.botChallengeKey, spoofer: spoofer.botChallengeKey }));

  // The object rule belongs to the credential carrier, whose primitive form is
  // the secret. req.user is not a credential, and a number cannot be a secret,
  // so refusing those loses a principal the resolver names.
  var primGate = _gate();
  var strUser = _mockReq({ url: "/token/refresh", body: {}, user: "alice",
                           socket: { remoteAddress: "198.51.100.31" } });
  var numUser = _mockReq({ url: "/token/refresh", body: {}, user: 42,
                           socket: { remoteAddress: "198.51.100.31" } });
  await primGate.middleware()(strUser, _mockRes(), function () {});
  await primGate.middleware()(numUser, _mockRes(), function () {});
  check("bot-challenge: a string req.user still names its principal",
    String(strUser.botChallengeKey).indexOf("alice") !== -1,
    String(strUser.botChallengeKey));
  check("bot-challenge: and a numeric req.user is a different ladder again",
    strUser.botChallengeKey !== numUser.botChallengeKey &&
    String(numUser.botChallengeKey).indexOf("198.51.100.31") === -1,
    JSON.stringify({ str: strUser.botChallengeKey, num: numUser.botChallengeKey }));

  // A framework that hangs the principal off the request prototype, which is
  // what Express does with app.request, still names it.
  var protoGate = _gate();
  var inherited = _mockReq({ url: "/token/refresh", body: {},
                             socket: { remoteAddress: "198.51.100.32" } });
  var viaProto = Object.create(inherited);
  viaProto.user = undefined;
  delete viaProto.user;
  Object.setPrototypeOf(viaProto, Object.assign(Object.create(
    Object.getPrototypeOf(inherited)), inherited, { user: { id: "proto-alice" } }));
  await protoGate.middleware()(viaProto, _mockRes(), function () {});
  check("bot-challenge: a prototype-supplied principal is still named",
    String(viaProto.botChallengeKey).indexOf("proto-alice") !== -1,
    String(viaProto.botChallengeKey));

  // Naming a record by its ownerId must not erase which field named it, or a
  // key whose id IS another key's owner id shares that owner's ladder.
  var sameText = _gate();
  var byId = _mockReq({ url: "/token/refresh", body: {}, apiKey: { id: "acct-1" },
                        socket: { remoteAddress: "198.51.100.25" } });
  var byOwner = _mockReq({ url: "/token/refresh", body: {},
                           apiKey: { id: null, ownerId: "acct-1" },
                           socket: { remoteAddress: "198.51.100.25" } });
  await sameText.middleware()(byId, _mockRes(), function () {});
  await sameText.middleware()(byOwner, _mockRes(), function () {});
  check("bot-challenge: an id and an ownerId of the same text are two ladders",
    byId.botChallengeKey !== byOwner.botChallengeKey,
    JSON.stringify({ byId: byId.botChallengeKey, byOwner: byOwner.botChallengeKey }));

  // And the tenant binding the resolver applies has to survive the fallback.
  var tenanted = _gate();
  var t1 = _mockReq({ url: "/token/refresh", body: {},
                      apiKey: { id: null, ownerId: "owner", tenantId: "t1" },
                      socket: { remoteAddress: "198.51.100.26" } });
  var t2 = _mockReq({ url: "/token/refresh", body: {},
                      apiKey: { id: null, ownerId: "owner", tenantId: "t2" },
                      socket: { remoteAddress: "198.51.100.26" } });
  await tenanted.middleware()(t1, _mockRes(), function () {});
  await tenanted.middleware()(t2, _mockRes(), function () {});
  check("bot-challenge: one owner in two tenants is two ladders",
    t1.botChallengeKey !== t2.botChallengeKey,
    JSON.stringify({ t1: t1.botChallengeKey, t2: t2.botChallengeKey }));

  // A body credential is lowercased and returned raw, so without a namespace of
  // its own it reproduces a prefixed rung's key exactly and an unauthenticated
  // caller can drive another principal's ladder to the escalation threshold.
  var forgeGate = _gate();
  var victim = _mockReq({ url: "/token/refresh", body: {}, apiKey: { id: "key-1" },
                          socket: { remoteAddress: "198.51.100.23" } });
  await forgeGate.middleware()(victim, _mockRes(), function () {});
  var forger = _mockReq({ url: "/login", body: { email: victim.botChallengeKey },
                          socket: { remoteAddress: "192.0.2.77" } });
  await forgeGate.middleware()(forger, _mockRes(), function () {});
  check("bot-challenge: a body credential cannot forge a credential rung's ladder",
    forger.botChallengeKey !== victim.botChallengeKey,
    JSON.stringify({ victim: victim.botChallengeKey, forger: forger.botChallengeKey }));

  // req.apiKey must only be read when it is needed, and inside the guard that
  // already protects the resolver: a lazily-resolving accessor that throws used
  // to collapse a request whose req.user names the principal onto one shared key.
  var lazyGate = _gate();
  var lazyReq = _mockReq({ url: "/token/refresh", body: {}, user: { sub: "alice" },
                           socket: { remoteAddress: "198.51.100.24" } });
  Object.defineProperty(lazyReq, "apiKey", {
    enumerable: true, configurable: true,
    get: function () { throw new Error("key record unavailable"); },
  });
  await lazyGate.middleware()(lazyReq, _mockRes(), function () {});
  check("bot-challenge: a throwing apiKey accessor does not lose the named user",
    String(lazyReq.botChallengeKey).indexOf("alice") !== -1,
    String(lazyReq.botChallengeKey));

  // `b.middleware.requireBoundKey` stores the verified principal on
  // `req.apiKey`, not `req.user`, so a bodyless API-key route named no
  // principal and fell to the address: two keys behind one NAT shared a ladder.
  var keyed = _gate();
  var k1 = _mockReq({ url: "/token/refresh", body: {},
                      apiKey: { id: "key-1" }, socket: { remoteAddress: "198.51.100.9" } });
  var k2 = _mockReq({ url: "/token/refresh", body: {},
                      apiKey: { id: "key-2" }, socket: { remoteAddress: "198.51.100.9" } });
  await keyed.middleware()(k1, _mockRes(), function () {});
  await keyed.middleware()(k2, _mockRes(), function () {});
  check("bot-challenge: two API keys from one address are two ladders",
    k1.botChallengeKey !== k2.botChallengeKey,
    JSON.stringify({ k1: k1.botChallengeKey, k2: k2.botChallengeKey }));
  check("bot-challenge: an API key's ladder is not keyed on the address",
    String(k1.botChallengeKey).indexOf("198.51.100.9") === -1,
    String(k1.botChallengeKey));

  // A user and an API key carrying the same id are two principals, which is the
  // distinction `b.staticServe` and the idempotency scope carry as `u:` / `k:`.
  var mixed = _gate();
  var asUser = _mockReq({ body: {}, user:   { id: "same" },
                          socket: { remoteAddress: "198.51.100.11" } });
  var asKey  = _mockReq({ body: {}, apiKey: { id: "same" },
                          socket: { remoteAddress: "198.51.100.11" } });
  await mixed.middleware()(asUser, _mockRes(), function () {});
  await mixed.middleware()(asKey,  _mockRes(), function () {});
  check("bot-challenge: a user and an API key sharing an id are two ladders",
    asUser.botChallengeKey !== asKey.botChallengeKey,
    JSON.stringify({ user: asUser.botChallengeKey, key: asKey.botChallengeKey }));

  // A body credential still names the ladder, lowercased, under a namespace of
  // its own so it cannot spell a credential rung's key.
  var byEmail = _gate();
  var withEmail = _mockReq({ body: { email: "User@Example.com" } });
  await byEmail.middleware()(withEmail, _mockRes(), function () {});
  check("bot-challenge: a body credential keys the ladder, lowercased and namespaced",
    withEmail.botChallengeKey === "body:user@example.com", withEmail.botChallengeKey);

  // Behind a declared proxy the address is the client's, not the proxy's, so
  // two clients arriving through one proxy are two ladders.
  var proxied = _gate({ trustedProxies: ["10.0.0.0/8"] });
  var c1 = _mockReq({ body: {}, socket: { remoteAddress: "10.0.0.9" },
                      headers: { "x-forwarded-for": "203.0.113.5" } });
  var c2 = _mockReq({ body: {}, socket: { remoteAddress: "10.0.0.9" },
                      headers: { "x-forwarded-for": "203.0.113.6" } });
  await proxied.middleware()(c1, _mockRes(), function () {});
  await proxied.middleware()(c2, _mockRes(), function () {});
  check("bot-challenge: a declared proxy keys by the client, not the proxy",
    c1.botChallengeKey !== c2.botChallengeKey,
    JSON.stringify({ c1: c1.botChallengeKey, c2: c2.botChallengeKey }));

  // Control: without a declared proxy a forged header cannot split the ladder,
  // which is the property the socket-only read was protecting.
  var unproxied = _gate();
  var f1 = _mockReq({ body: {}, socket: { remoteAddress: "10.0.0.9" },
                      headers: { "x-forwarded-for": "203.0.113.5" } });
  var f2 = _mockReq({ body: {}, socket: { remoteAddress: "10.0.0.9" },
                      headers: { "x-forwarded-for": "203.0.113.6" } });
  await unproxied.middleware()(f1, _mockRes(), function () {});
  await unproxied.middleware()(f2, _mockRes(), function () {});
  check("bot-challenge: an undeclared forwarded header cannot split the ladder",
    f1.botChallengeKey === f2.botChallengeKey,
    JSON.stringify({ f1: f1.botChallengeKey, f2: f2.botChallengeKey }));
}

async function run() {
  testSurface();
  testCreateRejectsBadOpts();
  await testLadderIsPerPrincipalNotPerAddress();
  await testStaircaseAdvances();
  await testConcurrentFailuresDoNotLoseIncrements();
  await testMiddlewareChallengeFn();
  await testMiddlewareLockedReturns423();
  await testRecordSuccessClears();
  await testReset();
  await testEscalationFnInvoked();
}

if (require.main === module) {
  run().then(function () {
    console.log("OK auth-bot-challenge — " + helpers.getChecks() + " checks");
  }).catch(function (e) {
    console.error("FAIL:", e && e.stack || e);
    process.exit(1);
  });
}

module.exports = { run: run };
