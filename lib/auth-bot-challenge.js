"use strict";
/**
 * b.authBotChallenge — adaptive bot-challenge gate for auth paths.
 *
 * Composes b.middleware.botGuard + b.auth.lockout + an operator-supplied
 * challengeFn (captcha / email confirmation / second-factor prompt) into
 * a single staircase that escalates protection as failed-auth attempts
 * accumulate inside a window. The staircase is deterministic:
 *
 *   1. Below `threshold`            — request flows through unchanged.
 *   2. At `threshold` failures      — bot-guard heuristic check is required;
 *                                     a verdict of suspectedBot or a
 *                                     missing browser fingerprint marks
 *                                     the session as challenged.
 *   3. After bot-guard pass but
 *      continued failures           — escalate to operator-supplied
 *                                     `challengeFn(req, res)`. Returning
 *                                     true clears the session challenge;
 *                                     false re-challenges; a thrown
 *                                     error escalates to step 4.
 *   4. After challenge-fn failures  — `escalationFn(req)` runs (typically
 *                                     records lockout, kills the session
 *                                     via b.auth.atoKillSwitch). The
 *                                     middleware returns 423 Locked.
 *
 * The session-mark is operator-storage — operators pass a `sessionStore`
 * with `getChallengeState(key)` / `setChallengeState(key, state, ttlMs)`
 * functions. A b.cache instance (any backend) satisfies the contract.
 *
 *   var gate = b.authBotChallenge.create({
 *     botGuard:     b.middleware.botGuard.create({ mode: "tag" }),
 *     lockout:      b.auth.lockout.create({ namespace: "login.adaptive",
 *                                            cache: b.cache.create({...}) }),
 *     sessionStore: b.cache.create({ namespace: "auth.bot_challenge" }),
 *     threshold:    3,                          // failures before challenge
 *     escalationThreshold: 6,                   // failures before lockout
 *     challengeFn:  async function (req, res) {
 *       // Operator implements: render captcha page on GET, validate on POST.
 *       return await b.captcha.verify(req.body.captchaToken);
 *     },
 *     escalationFn: async function (req) {
 *       await b.auth.atoKillSwitch.trigger({
 *         userId: req.body.email,
 *         reason: "auth-bot-challenge: escalation threshold reached",
 *       });
 *     },
 *     audit:        b.audit,
 *   });
 *
 *   router.post("/login", gate.middleware(), function (req, res) { ... });
 *
 * Key surface returned by create():
 *
 *   middleware()             — connect-style (req, res, next) gate
 *   recordFailure(key, opts) — operator-driven failure record (post-verify)
 *   recordSuccess(key, opts) — operator-driven success record (clear ladder)
 *   check(key)               — read-only state inspection
 *   reset(key, opts)         — admin reset (audit emits)
 *
 * Audit emissions:
 *
 *   auth.bot_challenge.required    challenge stage activated
 *   auth.bot_challenge.passed      bot-guard or operator challenge satisfied
 *   auth.bot_challenge.failed      challenge attempted, failed
 *   auth.bot_challenge.escalated   escalationFn triggered
 *
 * Validation policy:
 *   - create() opts → throw at config time (operator catches at boot)
 *   - middleware()  → never throws; failures inside the staircase audit
 *                     and translate to 401/423; throws from challengeFn
 *                     escalate.
 *   - recordFailure / recordSuccess / check / reset — throw on bad keys
 *     (operator-call-site discipline).
 */

var C = require("./constants");
var lazyRequire = require("./lazy-require");
var requestHelpers = require("./request-helpers");
var validateOpts = require("./validate-opts");
var { AuthBotChallengeError } = require("./framework-error");

var observability = lazyRequire(function () { return require("./observability"); });

var DEFAULT_THRESHOLD             = 3;
var DEFAULT_ESCALATION_THRESHOLD  = 6;
var DEFAULT_CHALLENGE_TTL_MS      = C.TIME.minutes(30);

var STATE_NEW        = "new";
var STATE_CHALLENGED = "challenged";
var STATE_PASSED     = "passed";
var STATE_LOCKED     = "locked";

var ALLOWED_OPTS = [
  "botGuard", "lockout", "sessionStore", "threshold", "escalationThreshold",
  "challengeFn", "escalationFn", "audit", "challengeTtlMs", "keyExtractor",
  "observability", "clock",
];

function _requireFunction(name, val) {
  if (typeof val !== "function") {
    throw new AuthBotChallengeError("auth-bot-challenge/bad-opt",
      name + ": expected function, got " + typeof val);
  }
}

function _requirePositiveInt(name, val) {
  if (typeof val !== "number" || !isFinite(val) || val < 1 || Math.floor(val) !== val) {
    throw new AuthBotChallengeError("auth-bot-challenge/bad-opt",
      name + ": expected positive integer, got " + JSON.stringify(val));
  }
}

function _requireNonNegFinite(name, val) {
  if (typeof val !== "number" || !isFinite(val) || val < 0) {
    throw new AuthBotChallengeError("auth-bot-challenge/bad-opt",
      name + ": expected non-negative finite number, got " + JSON.stringify(val));
  }
}

function _requireKey(key) {
  if (typeof key !== "string" || key.length === 0) {
    throw new AuthBotChallengeError("auth-bot-challenge/bad-key",
      "key must be a non-empty string, got " + typeof key + " " + JSON.stringify(key));
  }
}

function _requireSessionStore(store) {
  if (!store || typeof store !== "object" ||
      typeof store.get !== "function" ||
      typeof store.set !== "function" ||
      typeof store.del !== "function") {
    throw new AuthBotChallengeError("auth-bot-challenge/bad-opt",
      "sessionStore must be a b.cache-shaped object (get/set/del)");
  }
}

function _requireBotGuard(bg) {
  if (typeof bg !== "function") {
    throw new AuthBotChallengeError("auth-bot-challenge/bad-opt",
      "botGuard must be a connect-style middleware function (got " + typeof bg + ")");
  }
}

function _requireLockout(lk) {
  if (!lk || typeof lk !== "object" ||
      typeof lk.recordFailure !== "function" ||
      typeof lk.recordSuccess !== "function" ||
      typeof lk.check !== "function") {
    throw new AuthBotChallengeError("auth-bot-challenge/bad-opt",
      "lockout must be a b.auth.lockout-shaped instance " +
      "(recordFailure/recordSuccess/check)");
  }
}

function _defaultKeyExtractor(req) {
  // Default key strategy: prefer user-supplied identifier (req.body.email,
  // req.body.username), fall back to client IP. Operators override via
  // opts.keyExtractor for OAuth flows / passkey ceremonies.
  if (req && req.body && typeof req.body === "object") {
    if (typeof req.body.email === "string" && req.body.email.length > 0) {
      return req.body.email.toLowerCase();
    }
    if (typeof req.body.username === "string" && req.body.username.length > 0) {
      return req.body.username.toLowerCase();
    }
  }
  try { return requestHelpers.clientIp(req); }
  catch (_e) { return "<unknown>"; }
}

function create(opts) {
  opts = opts || {};
  validateOpts(opts, ALLOWED_OPTS, "authBotChallenge.create");

  _requireBotGuard(opts.botGuard);
  _requireLockout(opts.lockout);
  _requireSessionStore(opts.sessionStore);

  var threshold = opts.threshold !== undefined ? opts.threshold : DEFAULT_THRESHOLD;
  _requirePositiveInt("threshold", threshold);
  var escalationThreshold = opts.escalationThreshold !== undefined
    ? opts.escalationThreshold : DEFAULT_ESCALATION_THRESHOLD;
  _requirePositiveInt("escalationThreshold", escalationThreshold);
  if (escalationThreshold <= threshold) {
    throw new AuthBotChallengeError("auth-bot-challenge/bad-opt",
      "escalationThreshold (" + escalationThreshold + ") must exceed threshold (" + threshold + ")");
  }

  var challengeTtlMs = opts.challengeTtlMs !== undefined
    ? opts.challengeTtlMs : DEFAULT_CHALLENGE_TTL_MS;
  _requireNonNegFinite("challengeTtlMs", challengeTtlMs);

  if (opts.challengeFn !== undefined) _requireFunction("challengeFn", opts.challengeFn);
  if (opts.escalationFn !== undefined) _requireFunction("escalationFn", opts.escalationFn);
  if (opts.keyExtractor !== undefined) _requireFunction("keyExtractor", opts.keyExtractor);

  validateOpts.auditShape(opts.audit, "authBotChallenge.create", AuthBotChallengeError);

  var botGuard      = opts.botGuard;
  var lockout       = opts.lockout;
  var sessionStore  = opts.sessionStore;
  var challengeFn   = opts.challengeFn || null;
  var escalationFn  = opts.escalationFn || null;
  var keyExtractor  = opts.keyExtractor || _defaultKeyExtractor;
  var auditInst     = opts.audit || null;
  var obsInst       = opts.observability || null;
  var clock         = opts.clock || Date.now;

  function _emitObs(name, labels) {
    var sink = obsInst || _safeGlobalObs();
    if (!sink) return;
    try { sink.event(name, 1, labels); } catch (_e) { /* drop-silent */ }
  }

  function _safeGlobalObs() {
    try { return observability(); } catch (_e) { return null; }
  }

  function _emitAudit(action, key, outcome, metadata, req) {
    if (!auditInst) return;
    try {
      var event = {
        action:   action,
        outcome:  outcome,
        resource: { kind: "auth.bot_challenge", id: key },
        metadata: metadata || {},
      };
      if (req) event.actor = requestHelpers.extractActorContext(req);
      auditInst.safeEmit(event);
    } catch (_e) { /* audit best-effort */ }
  }

  async function _readState(key) {
    try {
      var raw = await sessionStore.get(key);
      return raw || null;
    } catch (_e) { return null; }
  }

  async function _writeState(key, state, ttlMs) {
    try { await sessionStore.set(key, state, { ttlMs: ttlMs }); }
    catch (_e) { /* drop-silent: store transient */ }
  }

  async function _deleteState(key) {
    try { await sessionStore.del(key); }
    catch (_e) { /* drop-silent */ }
  }

  // Run the bot-guard middleware in a captured-response harness — bot-
  // guard is a (req, res, next) middleware shape. The challenge gate
  // does NOT block here; it only inspects whether bot-guard's
  // heuristics flagged the request.
  function _runBotGuardCheck(req) {
    return new Promise(function (resolve) {
      var capturedRes = {
        statusCode: 200, // allow:raw-byte-literal — HTTP 200 status code, not bytes
        writableEnded: false,
        writeHead: function (status) { capturedRes.statusCode = status; },
        end: function () { capturedRes.writableEnded = true; },
      };
      var settled = false;
      function done(passed, reason) {
        if (settled) return;
        settled = true;
        resolve({ passed: passed, reason: reason || null });
      }
      try {
        botGuard(req, capturedRes, function () {
          // If bot-guard tagged the request, surface that. The default
          // botGuard mode is "block"; in tag mode req.suspectedBot
          // gets set. Either way: flagged = challenge required.
          if (req.suspectedBot) return done(false, req.suspectedBot);
          return done(true, null);
        });
        // If middleware terminated by writing a response, treat as flagged.
        if (capturedRes.writableEnded) {
          done(false, "bot-guard-blocked");
          return;
        }
      } catch (_e) {
        done(false, "bot-guard-exception");
        return;
      }
    });
  }

  // ---- Internal staircase advance ----

  async function _advanceFailure(key, req) {
    var now = clock();
    var state = await _readState(key) || {
      stage: STATE_NEW, failures: 0, challengedAt: null, passedAt: null,
    };
    state.failures = (state.failures || 0) + 1;

    // Lockout subscriber — propagate the failure into the lockout
    // primitive so cluster-shared counters stay accurate.
    try { await lockout.recordFailure(key, { req: req, reason: "auth-bot-challenge" }); }
    catch (_e) { /* lockout best-effort */ }

    if (state.failures >= escalationThreshold) {
      state.stage = STATE_LOCKED;
      await _writeState(key, state, challengeTtlMs);
      _emitObs("auth.bot_challenge.escalated", { stage: STATE_LOCKED });
      _emitAudit("auth.bot_challenge.escalated", key, "denied",
        { failures: state.failures, threshold: escalationThreshold }, req);
      if (escalationFn) {
        try { await escalationFn(req); }
        catch (_e) { /* escalation best-effort */ }
      }
      return { stage: STATE_LOCKED, failures: state.failures };
    }
    if (state.failures >= threshold) {
      state.stage = STATE_CHALLENGED;
      state.challengedAt = now;
      await _writeState(key, state, challengeTtlMs);
      _emitObs("auth.bot_challenge.required", { stage: STATE_CHALLENGED });
      _emitAudit("auth.bot_challenge.required", key, "denied",
        { failures: state.failures, threshold: threshold }, req);
      return { stage: STATE_CHALLENGED, failures: state.failures };
    }
    await _writeState(key, state, challengeTtlMs);
    return { stage: STATE_NEW, failures: state.failures };
  }

  // ---- Public surface ----

  function middleware() {
    return async function authBotChallengeMiddleware(req, res, next) {
      var key;
      try { key = keyExtractor(req); }
      catch (_e) { key = "<unknown>"; }
      if (typeof key !== "string" || key.length === 0) key = "<unknown>";

      var state = await _readState(key);

      if (state && state.stage === STATE_LOCKED) {
        _emitAudit("auth.bot_challenge.escalated", key, "denied",
          { reason: "already-locked" }, req);
        return _writeLocked(res);
      }

      if (state && state.stage === STATE_CHALLENGED) {
        // Run bot-guard heuristics first — fastest path. If those don't
        // pass, defer to the operator-supplied challengeFn.
        var bgVerdict = await _runBotGuardCheck(req);
        if (bgVerdict.passed) {
          state.stage = STATE_PASSED;
          state.passedAt = clock();
          await _writeState(key, state, challengeTtlMs);
          _emitObs("auth.bot_challenge.passed", { stage: "bot-guard" });
          _emitAudit("auth.bot_challenge.passed", key, "success",
            { stage: "bot-guard" }, req);
          return next();
        }
        if (challengeFn) {
          var challengeResult;
          try { challengeResult = await challengeFn(req, res); }
          catch (e) {
            _emitAudit("auth.bot_challenge.failed", key, "denied",
              { stage: "challenge-fn", error: e && e.message }, req);
            // Challenge-fn threw — treat as a failure; advance the ladder.
            await _advanceFailure(key, req);
            return _writeLocked(res);
          }
          // The challengeFn may have responded itself (e.g. rendered a
          // captcha page on GET). Detect that.
          if (res && res.writableEnded) return;
          if (challengeResult === true) {
            state.stage = STATE_PASSED;
            state.passedAt = clock();
            await _writeState(key, state, challengeTtlMs);
            _emitObs("auth.bot_challenge.passed", { stage: "challenge-fn" });
            _emitAudit("auth.bot_challenge.passed", key, "success",
              { stage: "challenge-fn" }, req);
            return next();
          }
          _emitObs("auth.bot_challenge.failed", { stage: "challenge-fn" });
          _emitAudit("auth.bot_challenge.failed", key, "denied",
            { stage: "challenge-fn" }, req);
          await _advanceFailure(key, req);
          return _writeChallengeRequired(res);
        }
        // No challengeFn supplied and bot-guard failed → 401.
        _emitObs("auth.bot_challenge.failed", { stage: "bot-guard-only" });
        _emitAudit("auth.bot_challenge.failed", key, "denied",
          { stage: "bot-guard-only", reason: bgVerdict.reason }, req);
        return _writeChallengeRequired(res);
      }

      // STATE_NEW or STATE_PASSED — flow through. Whether the wrapped
      // handler counts the attempt as a failure is the operator's
      // responsibility (they call gate.recordFailure(key) post-verify).
      return next();
    };
  }

  function _writeChallengeRequired(res) {
    if (!res || res.writableEnded) return;
    if (typeof res.writeHead === "function") {
      res.writeHead(401, {
        "Content-Type": "text/plain",
        "WWW-Authenticate": 'Bearer error="bot_challenge_required"',
      });
    } else if (typeof res.statusCode !== "undefined") {
      res.statusCode = 401;
    }
    if (typeof res.end === "function") res.end("Bot challenge required");
  }

  function _writeLocked(res) {
    if (!res || res.writableEnded) return;
    if (typeof res.writeHead === "function") {
      res.writeHead(423, { "Content-Type": "text/plain" });
    } else if (typeof res.statusCode !== "undefined") {
      res.statusCode = 423;
    }
    if (typeof res.end === "function") res.end("Locked");
  }

  async function recordFailure(key, callOpts) {
    _requireKey(key);
    callOpts = callOpts || {};
    return await _advanceFailure(key, callOpts.req || null);
  }

  async function recordSuccess(key, callOpts) {
    _requireKey(key);
    callOpts = callOpts || {};
    var state = await _readState(key);
    if (state) await _deleteState(key);
    try { await lockout.recordSuccess(key, { req: callOpts.req }); }
    catch (_e) { /* best-effort */ }
    _emitObs("auth.bot_challenge.cleared", {});
    _emitAudit("auth.bot_challenge.passed", key, "success",
      { stage: "auth-success", failuresCleared: (state && state.failures) || 0 },
      callOpts.req);
  }

  async function check(key) {
    _requireKey(key);
    var state = await _readState(key);
    if (!state) return { stage: STATE_NEW, failures: 0 };
    return {
      stage:    state.stage,
      failures: state.failures || 0,
    };
  }

  async function reset(key, callOpts) {
    _requireKey(key);
    callOpts = callOpts || {};
    var state = await _readState(key);
    if (state) await _deleteState(key);
    try { await lockout.unlock(key, { req: callOpts.req, reason: "bot-challenge:reset" }); }
    catch (_e) { /* best-effort */ }
    _emitAudit("auth.bot_challenge.passed", key, "success",
      { stage: "admin-reset", reason: callOpts.reason || null,
        priorStage: state && state.stage || null,
        priorFailures: state && state.failures || 0 },
      callOpts.req);
    return !!state;
  }

  return {
    middleware:    middleware,
    recordFailure: recordFailure,
    recordSuccess: recordSuccess,
    check:         check,
    reset:         reset,
  };
}

module.exports = {
  create:  create,
  AuthBotChallengeError: AuthBotChallengeError,
  STATES:  Object.freeze({
    NEW:        STATE_NEW,
    CHALLENGED: STATE_CHALLENGED,
    PASSED:     STATE_PASSED,
    LOCKED:     STATE_LOCKED,
  }),
  DEFAULTS: Object.freeze({
    threshold:           DEFAULT_THRESHOLD,
    escalationThreshold: DEFAULT_ESCALATION_THRESHOLD,
    challengeTtlMs:      DEFAULT_CHALLENGE_TTL_MS,
  }),
};
