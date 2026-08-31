// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.session.verify must FAIL CLOSED under a strict device-fingerprint policy
 * (requireFingerprintMatch / maxAnomalyScore) when the session carries NO stored
 * binding at all — i.e. it was created WITHOUT { req } (the framework's own
 * primary create() example does exactly this), so no __bj_fingerprint was ever
 * sealed into its data.
 *
 * This is the sibling of the "binding unreadable" fail-closed case: there the
 * sealed data cell existed but would not decrypt; here there is simply no
 * binding. Both mean the same thing to a strict verify — the device match
 * cannot be proven — so both must refuse, not silently skip the gate. The
 * pre-fix behaviour treated "there is no binding to compare" as "the binding
 * matches", admitting an unbound session from ANY device even though the
 * operator asked for strict fingerprint matching (directly, or through the
 * attachUser middleware that threads the flag into every verify).
 */

var helpers = require("../helpers");
var b = helpers.b;
var check = helpers.check;
var setupTestDb = helpers.setupTestDb;
var teardownTestDb = helpers.teardownTestDb;
var fs = require("fs");
var os = require("os");
var path = require("path");

var attachUser = b.middleware._modules.attachUser;

function _makeReq(headers) {
  return { headers: headers || {}, socket: {}, connection: {} };
}

// Drive the attachUser middleware to completion (it always calls next()).
async function _drive(mw, req) {
  var called = false;
  mw(req, {}, function () { called = true; });
  await helpers.waitUntil(function () { return called; }, {
    timeoutMs: 5000,
    label:     "session-strict-binding-missing: middleware called next()",
  });
}

async function run() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ses-strict-missing-"));
  try {
    await setupTestDb(tmpDir);

    // Session created WITHOUT { req } — no device-fingerprint binding is sealed.
    // (This is exactly the shape of the create() docstring's primary example.)
    var s = await b.session.create({ userId: "u-unbound", data: { role: "admin" } });

    var devB = _makeReq({ "x-forwarded-for": "198.51.100.1", "user-agent": "attacker-device" });

    // --- requireFingerprintMatch on an UNBOUND session must FAIL CLOSED.
    var strict = await b.session.verify(s.token, { req: devB, requireFingerprintMatch: true });
    check("requireFingerprintMatch on an unbound session FAILS CLOSED (null)",
          strict === null);

    // --- maxAnomalyScore on an UNBOUND session must FAIL CLOSED too.
    var scored = await b.session.verify(s.token, { req: devB, maxAnomalyScore: 0.1 });
    check("maxAnomalyScore on an unbound session FAILS CLOSED (null)",
          scored === null);

    // --- The strict refusal must NOT destroy the row: a legitimate non-strict
    //     verify still returns the session (fail-closed, not fail-deleted).
    var loose = await b.session.verify(s.token, { req: devB });
    check("advisory verify (req, no strict opt) still returns the unbound session",
          loose && loose.userId === "u-unbound" && loose.fingerprintDrift === false);

    // --- Plain verify (no req) is unchanged — unbound sessions remain usable
    //     when the operator does not assert a strict binding policy.
    var plain = await b.session.verify(s.token);
    check("plain verify (no req) still returns the unbound session",
          plain && plain.userId === "u-unbound");

    // --- Regression guard: a BOUND session under the strict policy from its
    //     own device still verifies (the fix only closes the no-binding hole).
    var devA = _makeReq({ "x-forwarded-for": "203.0.113.10", "user-agent": "deviceA" });
    var bound = await b.session.create({ userId: "u-bound", req: devA });
    var boundOk = await b.session.verify(bound.token, { req: devA, requireFingerprintMatch: true });
    check("bound session under strict policy from its own device still verifies",
          boundOk && boundOk.userId === "u-bound");

    // --- The real consumer path: attachUser({ requireFingerprintMatch: true })
    //     threads the strict flag into every verify. An unbound session token
    //     must NOT attach a user from a foreign device.
    var mw = attachUser.create({
      userLoader:              async function (sess) { return { id: sess.userId }; },
      tokenFrom:               "header",
      requireFingerprintMatch: true,
      audit:                   false,
    });
    var mwReq = _makeReq({ authorization: "Bearer " + s.token });
    await _drive(mw, mwReq);
    check("attachUser(requireFingerprintMatch) does NOT attach an unbound session",
          mwReq.user === null && mwReq.session === null);

    // --- The basis the binding is computed FROM has to travel too.
    //
    // attachUser enumerates its accepted option names and refuses the rest, so
    // fingerprintFields could not be passed at all — the only reachable policy
    // through this middleware was the default set, which includes the full
    // client address. An operator who deliberately bound on the user-agent
    // alone (a mobile client roams between addresses within one session) got
    // strict enforcement against a basis they had opted out of, and their
    // users were signed out on every network change.
    var narrow = { fingerprintFields: ["userAgent"] };
    var roamA = _makeReq({ "x-forwarded-for": "203.0.113.10", "user-agent": "roamer" });
    var roamSession = await b.session.create({ userId: "u-roam", req: roamA,
                                               fingerprintFields: narrow.fingerprintFields });
    var mwNarrow = attachUser.create({
      userLoader:              async function (sess) { return { id: sess.userId }; },
      tokenFrom:               "header",
      requireFingerprintMatch: true,
      fingerprintFields:       narrow.fingerprintFields,
      audit:                   false,
    });
    // Same device, different address — which the chosen basis does not read.
    var roamB = _makeReq({ "x-forwarded-for": "198.51.100.77", "user-agent": "roamer",
                           authorization: "Bearer " + roamSession.token });
    await _drive(mwNarrow, roamB);
    check("attachUser forwards fingerprintFields, so a roaming client stays signed in",
          roamB.user !== null && roamB.session !== null,
          JSON.stringify({ user: roamB.user, session: !!roamB.session }));

    // The control: the SAME session under the default basis is refused, so the
    // assertion above is about the forwarded fields and not about the binding
    // being inert.
    var mwDefault = attachUser.create({
      userLoader:              async function (sess) { return { id: sess.userId }; },
      tokenFrom:               "header",
      requireFingerprintMatch: true,
      audit:                   false,
    });
    var roamC = _makeReq({ "x-forwarded-for": "198.51.100.77", "user-agent": "roamer",
                           authorization: "Bearer " + roamSession.token });
    await _drive(mwDefault, roamC);
    check("CONTROL — without the forwarded fields the same request is refused",
          roamC.user === null && roamC.session === null,
          JSON.stringify({ user: roamC.user }));

    // A device binding kept on the session survives an ordinary payload write.
    //
    // updateData REPLACES by default and carries only reserved keys across, so
    // a binding stored in an ordinary field was destroyed by the next cart
    // write or preference flip the application made — after which every strict
    // verification answered missing-bind, and nothing reported why. A reserved
    // key is how framework state lives inside an operator-owned payload.
    //
    // Seeded through the framework's own writer, because the payload path
    // cannot write the reserved key at all — that is the point of reserving it.
    // A session whose binding an ordinary updateData could set is one whose
    // binding an ordinary updateData could also forge.
    var bindSess = await b.session.create({ userId: "u-binding", data: { cart: ["x"] } });
    await b.session._setDeviceBinding(bindSess.token,
      { fingerprint: "abcd", boundAt: 1 });
    await b.session.updateData(bindSess.token, { cart: ["y", "z"] });   // an ordinary REPLACE
    var afterWrite = await b.session.verify(bindSess.token);
    check("session: an ordinary data replace preserves the device binding",
          afterWrite && afterWrite.data && afterWrite.data.__bj_deviceBinding &&
          afterWrite.data.__bj_deviceBinding.fingerprint === "abcd",
          JSON.stringify(afterWrite && afterWrite.data));
    check("session: and the application's own write still lands",
          afterWrite.data.cart && afterWrite.data.cart[0] === "y",
          JSON.stringify(afterWrite.data.cart));
    // Rotation is the other payload writer, and it has its own preservation
    // logic — fixing updateData alone left the binding dropped by any rotation
    // that supplies replacement data. Login IS a rotation, so that is exactly
    // when a bound session would have lost its binding.
    var rotated = await b.session.rotate(bindSess.token, { data: { cart: ["rotated"] } });
    check("[setup] the session rotates", rotated !== null);
    var afterRotate = await b.session.verify(rotated.token);
    check("session: a rotation with replacement data preserves the device binding",
          afterRotate && afterRotate.data && afterRotate.data.__bj_deviceBinding &&
          afterRotate.data.__bj_deviceBinding.fingerprint === "abcd",
          JSON.stringify(afterRotate && afterRotate.data));
    check("session: and the rotation's own data still lands",
          afterRotate.data.cart && afterRotate.data.cart[0] === "rotated",
          JSON.stringify(afterRotate.data.cart));
    bindSess = rotated;

    // Clearing the payload is a supported operation and clears the OPERATOR's
    // data, not the framework state beside it. Both restores were guarded on
    // the new payload being an object, so `updateData(token, null)` dropped the
    // device binding and the sid-keyed fingerprint alike — and every later
    // strict check answered missing-bind for a session the caller had only
    // meant to empty.
    var cleared = await b.session.updateData(bindSess.token, null);
    check("[setup] the payload clears", cleared === true, String(cleared));
    var afterNull = await b.session.verify(bindSess.token);
    check("session: clearing the payload keeps the device binding",
          afterNull && afterNull.data && afterNull.data.__bj_deviceBinding &&
          afterNull.data.__bj_deviceBinding.fingerprint === "abcd",
          JSON.stringify(afterNull && afterNull.data));
    check("session: and the operator's own data is gone, which is what was asked",
          afterNull.data.cart === undefined, JSON.stringify(afterNull.data));

    // The framework's writer still owns it, or the binding could never be
    // removed. Through _setDeviceBinding, not the payload path: an application
    // that could clear its own binding could defeat strict verification by
    // writing a cart.
    await b.session._setDeviceBinding(bindSess.token, null);
    var afterClear = await b.session.verify(bindSess.token);
    check("session: the framework's own writer still owns the reserved key",
          afterClear && afterClear.data && afterClear.data.__bj_deviceBinding === null,
          JSON.stringify(afterClear && afterClear.data));

    // And the payload path cannot, in either direction — the control for the
    // seeding above, so it is not just a different spelling of the same call.
    await b.session._setDeviceBinding(bindSess.token, { fingerprint: "abcd", boundAt: 1 });
    await b.session.updateData(bindSess.token, { __bj_deviceBinding: null }, { merge: true });
    var afterPayloadNull = await b.session.verify(bindSess.token);
    check("session: a payload write cannot clear the reserved key",
          afterPayloadNull && afterPayloadNull.data &&
          afterPayloadNull.data.__bj_deviceBinding &&
          afterPayloadNull.data.__bj_deviceBinding.fingerprint === "abcd",
          JSON.stringify(afterPayloadNull && afterPayloadNull.data));
    await b.session.updateData(bindSess.token,
      { __bj_deviceBinding: { fingerprint: "forged", boundAt: 2 } }, { merge: true });
    var afterPayloadForge = await b.session.verify(bindSess.token);
    check("session: nor set it to a value of the caller's choosing",
          afterPayloadForge.data.__bj_deviceBinding.fingerprint === "abcd",
          JSON.stringify(afterPayloadForge.data.__bj_deviceBinding));

    // A typo in any of the three has to be refused where it is configured. A
    // mistyped fingerprintFields silently became null and fell back to the
    // DEFAULT basis — reinstating exactly the policy the operator was
    // configuring their way out of — and a mistyped clientIpResolver made
    // verify throw on every request, which this middleware catches and reports
    // as "no user", so nobody could sign in and nothing said why.
    [["fingerprintFields", "clientIp"], ["trustedProxies", "10.0.0.0/8"],
     ["clientIpResolver", "not-a-function"]].forEach(function (pair) {
      var o = { userLoader: async function () { return { id: "u" }; }, audit: false };
      o[pair[0]] = pair[1];
      var threw = null;
      try { attachUser.create(o); } catch (e) { threw = e; }
      check("attachUser refuses a malformed " + pair[0] + " at create",
            threw !== null, "accepted " + JSON.stringify(pair[1]));
    });
  } finally {
    await teardownTestDb(tmpDir);
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); });
}
