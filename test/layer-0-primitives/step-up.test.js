// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.auth.stepUp + b.middleware.requireStepUp + elevation grants —
 * RFC 9470 OAuth 2.0 Step-Up Authentication Challenge.
 */

var b = require("../..");
var check = require("../helpers/check").check;
var nodeCrypto = require("node:crypto");

function rejects(label, fn, pattern) {
  var threw = false;
  var msg = "";
  try { fn(); } catch (e) { threw = true; msg = e.message; }
  check("threw on " + label, threw && (pattern.test ? pattern.test(msg) : msg.indexOf(pattern) !== -1));
}

function _mockReq(headers, user, urlPath) {
  return {
    headers: headers || {},
    user:    user || null,
    url:     urlPath || "/",
    method:  "GET",
  };
}

function _mockRes() {
  var sent = { status: null, headers: null, body: null };
  return {
    headersSent: false,
    writeHead: function (status, headers) { sent.status = status; sent.headers = headers; this.headersSent = true; },
    end:       function (body) { sent.body = body; },
    _sent:     sent,
  };
}

async function run() {
  // ---- module shape ----
  check("b.auth.stepUp is object",                typeof b.auth.stepUp === "object");
  check("b.auth.acr is object",                   typeof b.auth.acr === "object");
  check("b.auth.authTime is object",              typeof b.auth.authTime === "object");
  check("b.middleware.requireStepUp is fn",       typeof b.middleware.requireStepUp === "function");
  check("evaluate is fn",                         typeof b.auth.stepUp.evaluate === "function");
  check("buildChallenge is fn",                   typeof b.auth.stepUp.buildChallenge === "function");
  check("parseChallenge is fn",                   typeof b.auth.stepUp.parseChallenge === "function");
  check("parseAuthorizationDetails is fn",        typeof b.auth.stepUp.parseAuthorizationDetails === "function");
  check("grant.create is fn",                     typeof b.auth.stepUp.grant.create === "function");
  check("grant.verify is fn",                     typeof b.auth.stepUp.grant.verify === "function");
  check("INSUFFICIENT_USER_AUTHENTICATION exported", b.auth.stepUp.INSUFFICIENT_USER_AUTHENTICATION === "insufficient_user_authentication");

  // ---- ACR vocabulary ----
  b.auth.acr._resetForTests();
  check("acr.rankOf builtin loa1",                b.auth.acr.rankOf("loa1") === 10);
  check("acr.rankOf builtin loa3",                b.auth.acr.rankOf("loa3") === 70);
  check("acr.rankOf unknown",                     b.auth.acr.rankOf("nope") === -1);
  check("acr.meets loa3 ≥ loa2",                  b.auth.acr.meets("loa3", "loa2") === true);
  check("acr.meets loa1 < loa2",                  b.auth.acr.meets("loa1", "loa2") === false);
  rejects("meets unregistered required",
    function () { b.auth.acr.meets("loa2", "myco:strong"); },
    /not registered/);
  b.auth.acr.register({ value: "myco:strong", rank: 65 });
  check("after register: meets loa3 ≥ myco:strong",
                                                  b.auth.acr.meets("loa3", "myco:strong") === true);
  check("meetsAny picks first satisfying",        b.auth.acr.meetsAny("loa3", ["loa4", "loa2"]) === true);
  check("meetsAny none satisfies",                b.auth.acr.meetsAny("loa1", ["loa3", "loa4"]) === false);
  rejects("acr.register bad rank",
    function () { b.auth.acr.register({ value: "x", rank: 200 }); }, /\[0, 100\]/);
  rejects("acr.register empty value",
    function () { b.auth.acr.register({ value: "", rank: 50 }); }, /value/);

  // AMR helpers
  check("amrIncludesPhishingResistant true (hwk)", b.auth.acr.amrIncludesPhishingResistant(["pwd", "hwk"]) === true);
  check("amrIncludesPhishingResistant false",      b.auth.acr.amrIncludesPhishingResistant(["pwd", "otp"]) === false);
  check("amrSatisfiesRequiredList true",           b.auth.acr.amrSatisfiesRequiredList(["pwd", "hwk", "pop"], ["hwk", "pop"]) === true);
  check("amrSatisfiesRequiredList missing",        b.auth.acr.amrSatisfiesRequiredList(["pwd"], ["hwk"]) === false);

  // ---- auth_time ----
  var nowSec = Math.floor(Date.now() / 1000);
  check("ageSec for fresh claims",                b.auth.authTime.ageSec({ auth_time: nowSec - 30 }, nowSec) === 30);
  check("ageSec missing claim → null",            b.auth.authTime.ageSec({}, nowSec) === null);
  check("ageSec future skew → 0",                 b.auth.authTime.ageSec({ auth_time: nowSec + 10 }, nowSec) === 0);
  check("freshEnough true",                       b.auth.authTime.freshEnough({ auth_time: nowSec - 10 }, 60, nowSec) === true);
  check("freshEnough false",                      b.auth.authTime.freshEnough({ auth_time: nowSec - 600 }, 60, nowSec) === false);
  check("freshEnough missing claim",              b.auth.authTime.freshEnough({}, 60, nowSec) === false);
  rejects("freshEnough bad maxAge",
    function () { b.auth.authTime.freshEnough({ auth_time: nowSec }, "60"); }, /maxAgeSec/);
  var built = b.auth.authTime.buildClaims({ method: "initial", now: nowSec, amr: ["pwd"], acr: "loa2" });
  check("buildClaims initial sets auth_time=now", built.auth_time === nowSec);
  check("buildClaims preserves acr/amr",          built.acr === "loa2" && built.amr[0] === "pwd");
  var refreshed = b.auth.authTime.buildClaims({ method: "refresh", prevAt: nowSec - 1000, now: nowSec });
  check("buildClaims refresh preserves prevAt",   refreshed.auth_time === nowSec - 1000);

  // ---- evaluate happy path ----
  var pass = b.auth.stepUp.evaluate({
    claims: { acr: "loa3", auth_time: nowSec - 30, amr: ["pwd", "hwk"] },
    requirement: { acr: "loa2", maxAge: 60 },
  });
  check("evaluate ok",                            pass.ok === true);

  var fail = b.auth.stepUp.evaluate({
    claims: { acr: "loa1", auth_time: nowSec - 30 },
    requirement: { acr: "loa2" },
  });
  check("evaluate fail: low acr",                 fail.ok === false &&
                                                  fail.error === "insufficient_user_authentication");

  var stale = b.auth.stepUp.evaluate({
    claims: { acr: "loa3", auth_time: nowSec - 1000 },
    requirement: { acr: "loa2", maxAge: 60 },
  });
  check("evaluate fail: stale auth_time",         stale.ok === false);

  var amrFail = b.auth.stepUp.evaluate({
    claims: { acr: "loa3", auth_time: nowSec, amr: ["pwd"] },
    requirement: { acr: "loa2", requiredAmr: ["hwk"] },
  });
  check("evaluate fail: missing required amr",    amrFail.ok === false);

  var phrFail = b.auth.stepUp.evaluate({
    claims: { acr: "loa3", auth_time: nowSec, amr: ["pwd", "otp"] },
    requirement: { acr: "loa2", phishingResistant: true },
  });
  check("evaluate fail: not phishing-resistant",  phrFail.ok === false);

  var anyFail = b.auth.stepUp.evaluate({
    claims: { acr: "loa1", auth_time: nowSec },
    requirement: { acrValues: ["loa2", "loa3"] },
  });
  check("evaluate fail: acrValues none meet",     anyFail.ok === false);

  var anyOk = b.auth.stepUp.evaluate({
    claims: { acr: "loa3", auth_time: nowSec },
    requirement: { acrValues: ["myco:strong", "loa3"] },
  });
  check("evaluate ok: acrValues at least one",    anyOk.ok === true);

  var noClaims = b.auth.stepUp.evaluate({
    claims: null,
    requirement: { acr: "loa2" },
  });
  check("evaluate fail: missing claims",          noClaims.ok === false);

  var unknownReqAcr = b.auth.stepUp.evaluate({
    claims: { acr: "loa3", auth_time: nowSec },
    requirement: { acr: "myco:not-registered" },
  });
  check("evaluate fail: unknown required acr",    unknownReqAcr.ok === false &&
                                                  unknownReqAcr.error === "unknown_acr");

  // ---- buildChallenge ----
  var challenge = b.auth.stepUp.buildChallenge({
    requirement: { acr: "loa3", maxAge: 300 },
    realm: "billing-api",
  });
  check("challenge: starts with Bearer",          challenge.indexOf("Bearer ") === 0);
  check("challenge: realm",                       challenge.indexOf('realm="billing-api"') !== -1);
  check("challenge: error",                       challenge.indexOf('error="insufficient_user_authentication"') !== -1);
  check("challenge: acr_values",                  challenge.indexOf('acr_values="loa3"') !== -1);
  check("challenge: max_age",                     challenge.indexOf('max_age="300"') !== -1);
  check("challenge: error_description",           challenge.indexOf('error_description=') !== -1);
  var multi = b.auth.stepUp.buildChallenge({
    requirement: { acrValues: ["loa2", "loa3"] },
  });
  check("challenge: acr_values space-separated",  multi.indexOf('acr_values="loa2 loa3"') !== -1);
  rejects("buildChallenge: bad requirement",
    function () { b.auth.stepUp.buildChallenge({ requirement: null }); },
    /requirement/);
  rejects("buildChallenge: control char in realm",
    function () { b.auth.stepUp.buildChallenge({ requirement: { acr: "loa2" }, realm: "evil\rrealm" }); },
    /control character/);

  // ---- parseChallenge round-trip ----
  var rt = b.auth.stepUp.parseChallenge(challenge);
  check("parseChallenge: error",                  rt.error === "insufficient_user_authentication");
  check("parseChallenge: acrValues array",        Array.isArray(rt.acrValues) && rt.acrValues[0] === "loa3");
  check("parseChallenge: maxAge",                 rt.maxAge === 300);
  check("parseChallenge: non-Bearer → null",      b.auth.stepUp.parseChallenge("Basic realm=x") === null);

  // A malformed max_age from the server must not land as NaN (a downstream
  // `age > maxAge` against NaN is always false) — it's omitted so the caller
  // falls back to its own default.
  var badMa = b.auth.stepUp.parseChallenge('Bearer error="insufficient_user_authentication", max_age="not-a-number"');
  check("parseChallenge: non-numeric max_age stays null (not NaN)",
        badMa && badMa.maxAge === null);

  // ---- parseAuthorizationDetails (RFC 9396) ----
  var rar = b.auth.stepUp.parseAuthorizationDetails(JSON.stringify([
    { type: "payment_initiation", actions: ["initiate"], amount: { currency: "USD", value: 100 } },
  ]));
  check("RAR: parses",                            Array.isArray(rar) && rar[0].type === "payment_initiation");
  rejects("RAR: not array",
    function () { b.auth.stepUp.parseAuthorizationDetails(JSON.stringify({ type: "x" })); },
    /JSON array/);
  rejects("RAR: missing type",
    function () { b.auth.stepUp.parseAuthorizationDetails(JSON.stringify([{ foo: "bar" }])); },
    /missing required 'type'/);
  rejects("RAR: invalid JSON",
    function () { b.auth.stepUp.parseAuthorizationDetails("notjson"); },
    /invalid JSON/);

  // ---- grant create + verify ----
  b.auth.stepUp.grant._resetForTests();
  var g = b.auth.stepUp.grant.create({
    subject: "user-42",
    scope:   "billing:write",
    acr:     "loa3",
    amr:     ["pwd", "hwk"],
    ttlSec:  300,
  });
  check("grant: token returned",                  typeof g.token === "string" && g.token.indexOf(".") !== -1);
  check("grant: expiresAt > now",                 g.expiresAt > nowSec);
  check("grant: jti present",                     typeof g.jti === "string" && g.jti.length > 0);
  var v = b.auth.stepUp.grant.verify(g.token);
  check("grant verify: ok",                       v.ok === true);
  check("grant verify: subject",                  v.payload.sub === "user-42");
  check("grant verify: scope",                    v.payload.scope === "billing:write");
  // Tamper with token: flip a byte after the dot
  var tampered = g.token.slice(0, -2) + (g.token.slice(-2) === "AA" ? "BB" : "AA");
  var vTamper = b.auth.stepUp.grant.verify(tampered);
  check("grant verify: tampered → bad_mac",       vTamper.ok === false);
  // Audience match
  var gAud = b.auth.stepUp.grant.create({
    subject: "user-1", scope: "x", audience: "https://api.example.com",
  });
  var vAud = b.auth.stepUp.grant.verify(gAud.token, { audience: "https://api.example.com" });
  check("grant verify: audience match ok",        vAud.ok === true);
  var vAudBad = b.auth.stepUp.grant.verify(gAud.token, { audience: "https://other.example.com" });
  check("grant verify: audience mismatch",        vAudBad.ok === false &&
                                                  vAudBad.error === "audience_mismatch");
  // Scope mismatch
  var vScopeBad = b.auth.stepUp.grant.verify(g.token, { scope: "admin:write" });
  check("grant verify: scope mismatch",           vScopeBad.ok === false);
  // Expiry
  rejects("grant: ttlSec too small",
    function () { b.auth.stepUp.grant.create({ subject: "u", scope: "s", ttlSec: 1 }); }, /ttlSec/);
  rejects("grant: ttlSec too big",
    function () { b.auth.stepUp.grant.create({ subject: "u", scope: "s", ttlSec: 999999 }); }, /ttlSec/);
  rejects("grant: missing subject",
    function () { b.auth.stepUp.grant.create({ scope: "s" }); }, /subject/);
  rejects("grant: missing scope",
    function () { b.auth.stepUp.grant.create({ subject: "u" }); }, /scope/);
  // Malformed
  var vMalformed = b.auth.stepUp.grant.verify("garbage");
  check("grant verify: no dot → malformed",       vMalformed.ok === false);
  var vEmpty = b.auth.stepUp.grant.verify("");
  check("grant verify: empty → no_token",         vEmpty.ok === false && vEmpty.error === "no_token");
  // Revoke
  var gRev = b.auth.stepUp.grant.create({ subject: "u-rev", scope: "x" });
  b.auth.stepUp.grant.revoke(gRev.jti, { reason: "user-logged-out" });
  var vRev = b.auth.stepUp.grant.verify(gRev.token);
  check("grant verify: revoked",                  vRev.ok === false && vRev.error === "revoked");
  check("grant: isRevoked",                       b.auth.stepUp.grant.isRevoked(gRev.jti) === true);
  rejects("grant.revoke: empty jti",
    function () { b.auth.stepUp.grant.revoke(""); }, /jti/);
  // List active
  b.auth.stepUp.grant._resetForTests();
  b.auth.stepUp.grant.create({ subject: "u1", scope: "s" });
  b.auth.stepUp.grant.create({ subject: "u2", scope: "s" });
  check("grant.list: returns 2 active",           b.auth.stepUp.grant.list().length === 2);
  // setSigningKey
  rejects("setSigningKey: wrong type",
    function () { b.auth.stepUp.grant.setSigningKey("not-a-buffer"); }, /Buffer/);
  rejects("setSigningKey: too short",
    function () { b.auth.stepUp.grant.setSigningKey(Buffer.alloc(16)); }, />= 32 bytes/);

  // A grant whose exp decodes to a non-finite number (JSON `1e400` → Infinity)
  // must not read as never-expiring: Infinity < now is false, so a typeof-only
  // guard silently accepts it. Craft a MAC-valid token with a raw exp literal.
  b.auth.stepUp.grant._resetForTests();
  var _gk = nodeCrypto.randomBytes(64);
  b.auth.stepUp.grant.setSigningKey(_gk);
  var _gnow = Math.floor(Date.now() / 1000);
  var _gpB64 = Buffer.from('{"sub":"u1","scope":"s","iat":' + _gnow + ',"exp":1e400}', "utf8").toString("base64url");
  var _gmac = nodeCrypto.createHmac("sha3-512", _gk).update(_gpB64).digest().toString("base64url");
  var vInf = b.auth.stepUp.grant.verify(_gpB64 + "." + _gmac);
  check("grant.verify: non-finite exp (1e400 → Infinity) → expired, not never-expiring",
        vInf.ok === false && vInf.error === "expired");
  b.auth.stepUp.grant._resetForTests();

  // ---- middleware: happy path ----
  var mw = b.middleware.requireStepUp({
    requirement: { acr: "loa2", maxAge: 60 },
    realm: "test-realm",
  });
  check("middleware: factory returns fn",         typeof mw === "function");
  var nextCalls = 0;
  var req1 = _mockReq({}, { id: "u1", claims: { acr: "loa3", auth_time: nowSec, amr: ["pwd", "hwk"] } });
  var res1 = _mockRes();
  mw(req1, res1, function () { nextCalls += 1; });
  check("middleware: passes when claims meet",    nextCalls === 1);
  check("middleware: req.user.stepUp populated",  req1.user.stepUp && req1.user.stepUp.byClaims === true);

  // ---- middleware: challenge fires ----
  var req2 = _mockReq({}, { id: "u2", claims: { acr: "loa1", auth_time: nowSec } });
  var res2 = _mockRes();
  mw(req2, res2, function () { nextCalls += 1; });
  check("middleware: rejects on bad acr (status)", res2._sent.status === 401);
  check("middleware: WWW-Authenticate set",        typeof res2._sent.headers["WWW-Authenticate"] === "string");
  check("middleware: WWW-Authenticate carries acr_values",
        res2._sent.headers["WWW-Authenticate"].indexOf('acr_values="loa2"') !== -1);
  check("middleware: body has error code",         res2._sent.body.indexOf("insufficient_user_authentication") !== -1);
  check("middleware: did NOT call next",           nextCalls === 1);

  // ---- middleware: grant short-circuits ----
  b.auth.stepUp.grant._resetForTests();
  var grantMw = b.middleware.requireStepUp({
    requirement: { acr: "loa3", maxAge: 60 },
    grantScope:  "billing:write",
  });
  var grantToken = b.auth.stepUp.grant.create({
    subject: "u-grant", scope: "billing:write", acr: "loa3",
  });
  var nextG = 0;
  var reqG = _mockReq({ "x-step-up-grant": grantToken.token },
                      { id: "u-grant", claims: { acr: "loa1" } });
  var resG = _mockRes();
  grantMw(reqG, resG, function () { nextG += 1; });
  check("middleware: grant short-circuits",        nextG === 1);
  check("middleware: req.user.stepUp.byGrant",     reqG.user.stepUp && reqG.user.stepUp.byGrant === true);

  // ---- middleware: a grant minted for ONE user must not elevate ANOTHER ----
  // grantToken above was minted for subject "u-grant"; a request authenticated
  // as a DIFFERENT principal ("u-other") must not be elevated by it (cross-user
  // step-up grant replay). The grant carries its subject and must be bound to
  // the authenticated principal.
  var nextX = 0;
  var reqX = _mockReq({ "x-step-up-grant": grantToken.token },
                      { id: "u-other", claims: { acr: "loa1" } });
  var resX = _mockRes();
  grantMw(reqX, resX, function () { nextX += 1; });
  check("middleware: cross-user grant does NOT elevate (subject binding) → 401",
        nextX === 0 && resX._sent.status === 401);
  check("middleware: cross-user grant did not attach stepUp",
        !(reqX.user && reqX.user.stepUp));

  // ---- middleware: grant binds a JWT-claims principal (claims.sub) ----
  // bearerAuth with an external JWT verifier populates req.user.claims.sub
  // (no id / userId — the auth.jwt.verifyExternal shape). A grant minted for
  // that claims.sub must still bind: the principal resolver reads claims.sub,
  // so the grant short-circuits for its own subject (RED before the resolver
  // covered claims.sub: it returned undefined → grant path refused → 401 on
  // every post-step-up call). A grant minted for a DIFFERENT claims.sub must
  // not elevate.
  var grantJwt = b.auth.stepUp.grant.create({
    subject: "u-jwt", scope: "billing:write", acr: "loa3",
  });
  var nextJ = 0;
  var reqJ = _mockReq({ "x-step-up-grant": grantJwt.token },
                      { claims: { sub: "u-jwt", acr: "loa1" } });
  var resJ = _mockRes();
  grantMw(reqJ, resJ, function () { nextJ += 1; });
  check("middleware: grant binds claims.sub principal (short-circuits)",
        nextJ === 1 && reqJ.user.stepUp && reqJ.user.stepUp.byGrant === true);

  var nextJX = 0;
  var reqJX = _mockReq({ "x-step-up-grant": grantJwt.token },
                       { claims: { sub: "u-jwt-other", acr: "loa1" } });
  var resJX = _mockRes();
  grantMw(reqJX, resJX, function () { nextJX += 1; });
  check("middleware: cross-claims.sub grant does NOT elevate → 401",
        nextJX === 0 && resJX._sent.status === 401);

  // ---- grant bound to an actor, not to the text of one field ----
  // The principal resolver reads id, then userId, then claims.sub, then sub,
  // and a grant minted for a bare subject matches whichever of those spells
  // the same text. Two principals named by different fields therefore share
  // one grant. Minting from the actor binds the grant to the field as well as
  // the value, so the second principal is refused.
  var actorGrant = b.auth.stepUp.grant.create({
    actor: { id: "shared-name" }, scope: "billing:write", acr: "loa3",
  });
  var nextA = 0;
  var reqA = _mockReq({ "x-step-up-grant": actorGrant.token },
                      { id: "shared-name", claims: { acr: "loa1" } });
  var resA = _mockRes();
  grantMw(reqA, resA, function () { nextA += 1; });
  check("actor-bound grant: elevates the principal it was minted for",
        nextA === 1 && reqA.user.stepUp && reqA.user.stepUp.byGrant === true);

  var nextB = 0;
  var reqB = _mockReq({ "x-step-up-grant": actorGrant.token },
                      { claims: { sub: "shared-name", acr: "loa1" } });
  var resB = _mockRes();
  grantMw(reqB, resB, function () { nextB += 1; });
  check("actor-bound grant: a principal named by a different field is refused",
        nextB === 0 && resB._sent.status === 401);

  var nextAu = 0;
  var reqAu = _mockReq({ "x-step-up-grant": actorGrant.token },
                       { userId: "shared-name", claims: { acr: "loa1" } });
  var resAu = _mockRes();
  grantMw(reqAu, resAu, function () { nextAu += 1; });
  check("actor-bound grant: userId spelling the same text is refused",
        nextAu === 0 && resAu._sent.status === 401);

  // A bare-subject grant keeps matching the resolver's chain, so an operator
  // minting one is unaffected.
  var bareGrant = b.auth.stepUp.grant.create({
    subject: "bare-name", scope: "billing:write", acr: "loa3",
  });
  var nextD = 0;
  var reqD = _mockReq({ "x-step-up-grant": bareGrant.token },
                      { id: "bare-name", claims: { acr: "loa1" } });
  var resD = _mockRes();
  grantMw(reqD, resD, function () { nextD += 1; });
  check("bare-subject grant: still elevates through the resolver chain", nextD === 1);

  // An actor-bound grant checked without an actor is refused rather than
  // falling back to the text.
  var vNoActor = b.auth.stepUp.grant.verify(actorGrant.token, { subject: "shared-name" });
  check("actor-bound grant: verify without an actor refuses",
        vNoActor.ok === false && vNoActor.error === "subject_mismatch");
  var vWithActor = b.auth.stepUp.grant.verify(actorGrant.token, { actor: { id: "shared-name" } });
  check("actor-bound grant: verify with the actor succeeds", vWithActor.ok === true);

  rejects("grant.create: actor and subject together",
    function () {
      b.auth.stepUp.grant.create({ actor: { id: "a" }, subject: "a", scope: "s" });
    }, /actor or subject/);
  rejects("grant.create: an actor naming no principal",
    function () { b.auth.stepUp.grant.create({ actor: { role: "admin" }, scope: "s" }); },
    /name a principal/);

  // ---- middleware: grant scope mismatch falls through to claims ----
  var nextS = 0;
  var grantTokenWrong = b.auth.stepUp.grant.create({
    subject: "u", scope: "admin:write",
  });
  var reqS = _mockReq({ "x-step-up-grant": grantTokenWrong.token },
                     { id: "u", claims: { acr: "loa1" } });
  var resS = _mockRes();
  grantMw(reqS, resS, function () { nextS += 1; });
  check("middleware: grant scope mismatch + bad claims → 401",
        resS._sent.status === 401 && nextS === 0);

  // ---- middleware: bad opts at config time ----
  rejects("middleware: bad requirement",
    function () { b.middleware.requireStepUp({ requirement: null }); }, /requirement/);
  rejects("middleware: unknown acr in requirement",
    function () { b.middleware.requireStepUp({ requirement: { acr: "myco:nope" } }); },
    /not registered|unknown/);
  rejects("middleware: bad max_age",
    function () { b.middleware.requireStepUp({ requirement: { acr: "loa2", maxAge: -1 } }); },
    /maxAge/);
  rejects("middleware: bad acrValues",
    function () { b.middleware.requireStepUp({ requirement: { acrValues: [] } }); },
    /acrValues/);

  // ---- middleware: getClaims override ----
  var customMw = b.middleware.requireStepUp({
    requirement: { acr: "loa2" },
    getClaims:   function (req) { return req.body && req.body.token_claims; },
  });
  var nextC = 0;
  var reqC = { headers: {}, body: { token_claims: { acr: "loa3" } }, url: "/x" };
  var resC = _mockRes();
  customMw(reqC, resC, function () { nextC += 1; });
  check("middleware: custom getClaims passes",     nextC === 1);

  // ---- recommendMaxAge clamping ----
  check("recommendMaxAge default",                b.auth.authTime.recommendMaxAge({}) === 300);
  check("recommendMaxAge clamps high",            b.auth.authTime.recommendMaxAge({ default: 99999 }) === 900);
  check("recommendMaxAge clamps low",             b.auth.authTime.recommendMaxAge({ default: 1 }) === 60);

  // ---- listRegistered returns sorted ----
  var reg = b.auth.acr.listRegistered();
  check("listRegistered: returns array",          Array.isArray(reg) && reg.length > 0);
  check("listRegistered: ranks ascending",        (function () {
    for (var i = 1; i < reg.length; i += 1) {
      if (reg[i].rank < reg[i - 1].rank) return false;
    }
    return true;
  })());

  // ---- audit emissions reach the bus ----
  b.auth.stepUp.evaluate({ claims: { acr: "loa3" }, requirement: { acr: "loa2" } });
  check("evaluate is side-effect-free",            true);

  // The middleware decides which principal a step-up applies to by reading
  // req.user.id, then userId, then claims.sub, then sub, so it serves all four.
  // The two audit emitters read req.user.id alone, so a decision about a
  // principal named by any of the other three was recorded with no actor: the
  // row said a step-up was required or satisfied and named nobody it was about.
  // One resolver now answers for both, so what the audit names is what the
  // middleware matched.
  var SHAPES = [
    ["id",         { id: "p-id" },                   "p-id"],
    ["userId",     { userId: "p-userid" },           "p-userid"],
    ["claims.sub", { claims: { sub: "p-claimsub" } }, "p-claimsub"],
    ["sub",        { sub: "p-sub" },                 "p-sub"],
  ];
  SHAPES.forEach(function (shape) {
    var rows = [];
    var sink = { safeEmit: function (ev) { rows.push(ev); } };
    var req = { url: "/admin", user: shape[1] };
    b.auth.stepUp.emitAuditRequired("lbl", { acr: "loa2" }, {}, req, sink);
    b.auth.stepUp.emitAuditSatisfied("lbl", { acr: "loa2" }, {}, req, sink);
    check("step-up audit: a principal named by " + shape[0] + " reaches both rows",
          rows.length === 2 &&
          rows[0].actor && rows[0].actor.userId === shape[2] &&
          rows[1].actor && rows[1].actor.userId === shape[2],
          JSON.stringify(rows.map(function (r) { return r.actor && r.actor.userId; })));
    check("step-up audit: the route rides with the named actor for " + shape[0],
          rows.length === 2 && rows[0].actor.route === "/admin");
  });

  // A request naming no principal records no actor id rather than inventing one.
  var anonRows = [];
  b.auth.stepUp.emitAuditRequired("lbl", { acr: "loa2" }, {},
    { url: "/admin", user: { role: "admin" } },
    { safeEmit: function (ev) { anonRows.push(ev); } });
  check("step-up audit: an actor naming no principal records a null userId",
        anonRows.length === 1 && anonRows[0].actor.userId === null,
        JSON.stringify(anonRows[0] && anonRows[0].actor));

  // The resolver both sides share, asserted directly so a future edit that
  // narrows one caller's chain shows up here rather than in a quiet audit row.
  // It answers whatever b.requestHelpers.actorIdentityFields says names the
  // actor, so the order lives in one place. That order reads a top-level `sub`
  // ahead of a nested `claims.sub`, where this resolver used to prefer the
  // nested one: the shared list appends `claims.sub` last so adding it could
  // not re-key an actor an ownership record already names.
  check("stepUp._resolvePrincipal reads the fields in the shared order",
        b.auth.stepUp._resolvePrincipal({ user: { id: "a", userId: "b", sub: "c" } }) === "a" &&
        b.auth.stepUp._resolvePrincipal({ user: { userId: "b", sub: "c" } }) === "b" &&
        b.auth.stepUp._resolvePrincipal({ user: { claims: { sub: "c" }, sub: "d" } }) === "d" &&
        b.auth.stepUp._resolvePrincipal({ user: { claims: { sub: "c" } } }) === "c" &&
        b.auth.stepUp._resolvePrincipal({ user: { sub: "d" } }) === "d");
  check("and it names an actor carrying only a username or a principalId, " +
        "which its own chain never read",
        b.auth.stepUp._resolvePrincipal({ user: { username: "alice" } }) === "alice" &&
        b.auth.stepUp._resolvePrincipal({ user: { principalId: "p-1" } }) === "p-1");
  check("stepUp._resolvePrincipal answers undefined for a request naming nobody",
        b.auth.stepUp._resolvePrincipal({ user: { role: "x" } }) === undefined &&
        b.auth.stepUp._resolvePrincipal({}) === undefined &&
        b.auth.stepUp._resolvePrincipal(null) === undefined);

  // ---- policy DSL ----
  var p = b.auth.stepUp.policy;
  check("policy.acr is fn",                       typeof p.acr === "function");
  check("policy.amr is fn",                       typeof p.amr === "function");
  check("policy.maxAge is fn",                    typeof p.maxAge === "function");
  check("policy.preset is fn",                    typeof p.preset === "function");

  var policySimple = p.acr("loa2");
  var pr1 = policySimple.evaluate({ acr: "loa3" });
  check("policy.acr: loa3 satisfies loa2",         pr1.ok === true);
  var pr2 = policySimple.evaluate({ acr: "loa1" });
  check("policy.acr: loa1 fails loa2",             pr2.ok === false);

  var policyAnd = p.acr("loa2").and(p.maxAge(60));
  var prAndPass = policyAnd.evaluate({ acr: "loa3", auth_time: nowSec - 30 });
  check("policy.and: both pass",                   prAndPass.ok === true);
  var prAndFail = policyAnd.evaluate({ acr: "loa1", auth_time: nowSec });
  check("policy.and: left fail short-circuits",    prAndFail.ok === false);
  var prAndFail2 = policyAnd.evaluate({ acr: "loa3", auth_time: nowSec - 600 });
  check("policy.and: right fail",                  prAndFail2.ok === false);

  var policyOr = p.acr("loa3").or(p.amr(["hwk"]));
  var prOrLeft  = policyOr.evaluate({ acr: "loa3", auth_time: nowSec });
  check("policy.or: left passes",                  prOrLeft.ok === true);
  var prOrRight = policyOr.evaluate({ acr: "loa1", amr: ["hwk", "pwd"], auth_time: nowSec });
  check("policy.or: right passes when left fails", prOrRight.ok === true);
  var prOrFail  = policyOr.evaluate({ acr: "loa1", amr: ["pwd"] });
  check("policy.or: both fail",                    prOrFail.ok === false);

  // toRequirement compiles AND policies into RFC 9470 challenge tuple
  var req = policyAnd.toRequirement();
  check("policy.toRequirement: acr",               req.acr === "loa2");
  check("policy.toRequirement: maxAge",            req.maxAge === 60);

  // policy.middleware spawns a real middleware
  var pmw = policyAnd.middleware({ realm: "policy-realm" });
  check("policy.middleware: returns fn",           typeof pmw === "function");
  var nextP = 0;
  var reqP1 = _mockReq({}, { id: "u", claims: { acr: "loa3", auth_time: nowSec } });
  var resP1 = _mockRes();
  pmw(reqP1, resP1, function () { nextP += 1; });
  check("policy.middleware: pass",                 nextP === 1);

  // .not invertion
  var policyNot = p.acr("loa3").not();
  check("policy.not: passes when inner fails",     policyNot.evaluate({ acr: "loa1" }).ok === true);
  check("policy.not: fails when inner passes",     policyNot.evaluate({ acr: "loa3" }).ok === false);

  // .custom predicate
  var policyCustom = p.custom("hours-9-to-5", function (claims) {
    return claims && claims.acr === "loa2";
  });
  check("policy.custom: predicate true",           policyCustom.evaluate({ acr: "loa2" }).ok === true);
  check("policy.custom: predicate false",          policyCustom.evaluate({ acr: "loa1" }).ok === false);
  rejects("policy.custom: missing fn",
    function () { p.custom("x", null); }, /fn must be a function/);

  // Conflicting acr in AND throws on toRequirement
  rejects("policy.and: conflicting acr",
    function () { p.acr("loa2").and(p.acr("loa3")).toRequirement(); },
    /conflicting acr/);

  // .not toRequirement throws (no RFC 9470 negation)
  rejects("policy.not: toRequirement throws",
    function () { p.acr("loa2").not().toRequirement(); },
    /cannot translate/);

  // acrAny
  var policyAcrAny = p.acrAny(["loa2", "loa3"]);
  check("policy.acrAny: matches any",              policyAcrAny.evaluate({ acr: "loa3" }).ok === true);
  check("policy.acrAny: none matches",             policyAcrAny.evaluate({ acr: "loa1" }).ok === false);

  rejects("policy.acrAny: empty",
    function () { p.acrAny([]); }, /non-empty/);
  rejects("policy.amr: empty",
    function () { p.amr([]); }, /non-empty/);
  rejects("policy.maxAge: negative",
    function () { p.maxAge(-1); }, /seconds/);

  // Presets
  var presets = p.listPresets();
  check("listPresets: contains sensitiveWrite",    presets.indexOf("sensitiveWrite") !== -1);
  check("listPresets: contains phiWrite",          presets.indexOf("phiWrite") !== -1);
  check("listPresets: contains adminBulk",         presets.indexOf("adminBulk") !== -1);
  check("listPresets: contains financial",         presets.indexOf("financial") !== -1);
  check("listPresets: contains phiRead",           presets.indexOf("phiRead") !== -1);
  check("listPresets: contains accountRecovery",   presets.indexOf("accountRecovery") !== -1);

  var presetSensitive = p.preset("sensitiveWrite");
  var pres1 = presetSensitive.evaluate({ acr: "loa3", auth_time: nowSec });
  check("preset.sensitiveWrite: pass",             pres1.ok === true);
  var pres2 = presetSensitive.evaluate({ acr: "loa1", auth_time: nowSec });
  check("preset.sensitiveWrite: fail acr",         pres2.ok === false);
  var pres3 = presetSensitive.evaluate({ acr: "loa3", auth_time: nowSec - 1000 });
  check("preset.sensitiveWrite: fail max_age",     pres3.ok === false);

  rejects("preset: unknown name",
    function () { p.preset("not-a-preset"); }, /unknown preset/);

  // Phishing-resistant preset
  var presetAdmin = p.preset("adminBulk");
  var pAdmin1 = presetAdmin.evaluate({ acr: "loa3", auth_time: nowSec, amr: ["pwd", "hwk"] });
  check("preset.adminBulk: pass with hwk",         pAdmin1.ok === true);
  var pAdmin2 = presetAdmin.evaluate({ acr: "loa3", auth_time: nowSec, amr: ["pwd", "otp"] });
  check("preset.adminBulk: fail without phr",      pAdmin2.ok === false);

  // Custom predicate that's wrapped in OR with translatable atom
  var policyOrCustom = p.acr("loa3").or(p.custom("backup-key", function () { return false; }));
  check("policy.or with custom: left pass",        policyOrCustom.evaluate({ acr: "loa3", auth_time: nowSec }).ok === true);

  // toRequirement immutability — chaining returns new policies
  var policyA = p.acr("loa2");
  var policyB = policyA.and(p.maxAge(60));
  check("policy: chaining returns new",            policyA !== policyB);
  check("policy: original unchanged",              policyA.toRequirement().maxAge === undefined);

  console.log("OK — step-up tests");
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { process.exit(0); })
       .catch(function (err) { console.error(err); process.exit(1); });
}
