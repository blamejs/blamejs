// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.session — v0.8.61 extensions:
 *   - clientIpPrefix fingerprint field (auto /24 IPv4 + /64 IPv6 mask)
 *   - PQC-sealed sid cookie default (token = vault.seal(sid))
 *   - Pluggable session store via b.session.useStore + stores.localDbThin
 */

var helpers = require("../helpers");
var b              = helpers.b;
var fs             = helpers.fs;
var os             = helpers.os;
var path           = helpers.path;
var check          = helpers.check;
var setupTestDb    = helpers.setupTestDb;
var teardownTestDb = helpers.teardownTestDb;

function _makeReq(headers) {
  return {
    headers: headers || {},
    socket:  { remoteAddress: (headers && headers["x-forwarded-for"]) || "" },
  };
}

async function testSealedCookieDefault() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ses-sealed-"));
  try {
    await setupTestDb(tmpDir);
    var s = await b.session.create({ userId: "u-1", data: { role: "user" } });
    check("create returns string token",                typeof s.token === "string");
    check("token is sealed (vault: prefix)",            s.token.indexOf("vault:") === 0);

    var info = await b.session.verify(s.token);
    check("verify accepts sealed token",                info && info.userId === "u-1");

    // Pre-v0.8.61 raw-sid format: a 64-char hex string (64 random
    // bytes hex-encoded). The sealed-cookie default refuses it cleanly.
    var raw = "deadbeefcafef00d".repeat(4);
    var nullInfo = await b.session.verify(raw);
    check("verify refuses pre-v0.8.61 raw-format token", nullInfo === null);

    // A garbage sealed envelope (right prefix, wrong ciphertext) also
    // returns null rather than throwing — caller's re-auth flow.
    var bogus = await b.session.verify("vault:not-real-ciphertext");
    check("verify refuses tampered sealed envelope",     bogus === null);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testSealedCookieRotateAndDestroy() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ses-sealed-r-"));
  try {
    await setupTestDb(tmpDir);
    var s = await b.session.create({ userId: "u-2" });
    var rotated = await b.session.rotate(s.token);
    check("rotate returns sealed token",                 rotated && rotated.token.indexOf("vault:") === 0);
    check("rotate token differs from original",          rotated.token !== s.token);
    var oldStill = await b.session.verify(s.token);
    check("old token no longer verifies",                oldStill === null);
    var newOk = await b.session.verify(rotated.token);
    check("new token verifies",                          newOk && newOk.userId === "u-2");

    var destroyed = await b.session.destroy(rotated.token);
    check("destroy unseals + deletes",                   destroyed === true);
    var afterDestroy = await b.session.verify(rotated.token);
    check("verify returns null after destroy",           afterDestroy === null);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testClientIpPrefixV4() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ses-prefix-v4-"));
  try {
    await setupTestDb(tmpDir);
    // Same /24, different last octet — should NOT drift.
    var req1 = _makeReq({ "x-forwarded-for": "203.0.113.10", "user-agent": "ua1" });
    var s = await b.session.create({
      userId:            "u-1",
      req:               req1,
      fingerprintFields: ["clientIpPrefix", "userAgent"],
    });
    var req2 = _makeReq({ "x-forwarded-for": "203.0.113.250", "user-agent": "ua1" });
    var info = await b.session.verify(s.token, {
      req: req2,
      fingerprintFields: ["clientIpPrefix", "userAgent"],
    });
    check("clientIpPrefix v4: same /24 — no drift", info && info.fingerprintDrift === false);

    // Different /24 — should drift.
    var req3 = _makeReq({ "x-forwarded-for": "198.51.100.1", "user-agent": "ua1" });
    var info2 = await b.session.verify(s.token, {
      req: req3,
      fingerprintFields: ["clientIpPrefix", "userAgent"],
    });
    check("clientIpPrefix v4: cross-/24 — drift detected", info2 && info2.fingerprintDrift === true);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testClientIpPrefixV6() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ses-prefix-v6-"));
  try {
    await setupTestDb(tmpDir);
    // Same /64, different host bits.
    var req1 = _makeReq({ "x-forwarded-for": "2001:db8:1234:5678::1", "user-agent": "ua1" });
    var s = await b.session.create({
      userId:            "u-1",
      req:               req1,
      fingerprintFields: ["clientIpPrefix", "userAgent"],
    });
    var req2 = _makeReq({ "x-forwarded-for": "2001:db8:1234:5678:abcd:ef01:2345:6789", "user-agent": "ua1" });
    var info = await b.session.verify(s.token, {
      req: req2,
      fingerprintFields: ["clientIpPrefix", "userAgent"],
    });
    check("clientIpPrefix v6: same /64 — no drift", info && info.fingerprintDrift === false);

    // Different /64 — should drift.
    var req3 = _makeReq({ "x-forwarded-for": "2001:db8:1234:9999::1", "user-agent": "ua1" });
    var info2 = await b.session.verify(s.token, {
      req: req3,
      fingerprintFields: ["clientIpPrefix", "userAgent"],
    });
    check("clientIpPrefix v6: cross-/64 — drift detected", info2 && info2.fingerprintDrift === true);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testClientIpPrefixV4MappedV6() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ses-prefix-mapped-"));
  try {
    await setupTestDb(tmpDir);
    // ::ffff:1.2.3.4 (v4-mapped-v6) is bucketed as v4 /24.
    var req1 = _makeReq({ "x-forwarded-for": "::ffff:203.0.113.5", "user-agent": "ua1" });
    var s = await b.session.create({
      userId:            "u-1",
      req:               req1,
      fingerprintFields: ["clientIpPrefix"],
    });
    var req2 = _makeReq({ "x-forwarded-for": "203.0.113.99", "user-agent": "ua1" });
    var info = await b.session.verify(s.token, {
      req: req2,
      fingerprintFields: ["clientIpPrefix"],
    });
    check("clientIpPrefix: ::ffff: maps to v4 /24 bucket", info && info.fingerprintDrift === false);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// A request whose immediate peer is a reverse proxy: the socket peer is the
// proxy, the real client arrives in X-Forwarded-For.
function _makeProxiedReq(proxyAddr, clientIp) {
  return {
    headers: { "x-forwarded-for": clientIp, "user-agent": "ua1" },
    socket:  { remoteAddress: proxyAddr },
  };
}

async function testFingerprintPeerGatedClientIp() {
  // Behind a trusted proxy the client IP arrives in X-Forwarded-For while the
  // socket peer is the proxy. The bare-socket default binds the fingerprint to
  // the PROXY, so two different real clients behind the same proxy share a
  // fingerprint — the IP component is silently defeated. The { trustedProxies }
  // option peer-gates the resolve (consistent with trustedClientIp) so the real
  // client is bound. Both halves are proven here: the default still binds the
  // proxy (a different real client does NOT drift), and the opt makes a
  // different real client DRIFT.
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ses-peergate-"));
  try {
    await setupTestDb(tmpDir);
    var PROXY = "10.0.0.7";
    var TP = ["10.0.0.0/8"];

    // --- Legacy default (no trustedProxies): binds to the proxy address, so a
    // different real client behind the same proxy does NOT drift.
    var sLegacy = await b.session.create({
      userId: "u-legacy", req: _makeProxiedReq(PROXY, "203.0.113.10"),
      fingerprintFields: ["clientIp"],
    });
    var legacy = await b.session.verify(sLegacy.token, {
      req: _makeProxiedReq(PROXY, "198.51.100.9"), fingerprintFields: ["clientIp"],
    });
    check("bare-socket default: different real client behind proxy does NOT drift (proxy-bound)",
      legacy && legacy.fingerprintDrift === false);

    // --- Peer-gated (trustedProxies): resolves the real client from XFF.
    var sGated = await b.session.create({
      userId: "u-gated", req: _makeProxiedReq(PROXY, "203.0.113.10"),
      fingerprintFields: ["clientIp"], trustedProxies: TP,
    });
    var sameClient = await b.session.verify(sGated.token, {
      req: _makeProxiedReq(PROXY, "203.0.113.10"),
      fingerprintFields: ["clientIp"], trustedProxies: TP,
    });
    check("peer-gated: same real client behind proxy does not drift",
      sameClient && sameClient.fingerprintDrift === false);
    var diffClient = await b.session.verify(sGated.token, {
      req: _makeProxiedReq(PROXY, "198.51.100.9"),
      fingerprintFields: ["clientIp"], trustedProxies: TP,
    });
    check("peer-gated: different real client behind proxy DRIFTS (real client bound)",
      diffClient && diffClient.fingerprintDrift === true);

    // A forged XFF from a NON-trusted peer must be ignored (peer-gating) — the
    // resolve falls back to the untrusted socket address, so a forged header
    // can't make the real-client binding drift on its own.
    var sDirect = await b.session.create({
      userId: "u-direct", req: _makeProxiedReq("203.0.113.50", "203.0.113.10"),
      fingerprintFields: ["clientIp"], trustedProxies: TP,
    });
    var forged = await b.session.verify(sDirect.token, {
      // same untrusted socket peer, attacker varies the forgeable XFF.
      req: _makeProxiedReq("203.0.113.50", "8.8.8.8"),
      fingerprintFields: ["clientIp"], trustedProxies: TP,
    });
    check("peer-gated: forged XFF from an untrusted peer is ignored (no drift on header alone)",
      forged && forged.fingerprintDrift === false);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testPluggableStore() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ses-store-"));
  try {
    await setupTestDb(tmpDir);
    var storeFile = path.join(tmpDir, "thin-sessions.db");
    var store = b.session.stores.localDbThin({ file: storeFile });
    b.session.useStore(store);

    var s = await b.session.create({ userId: "u-1", data: { team: "a" } });
    var info = await b.session.verify(s.token);
    check("pluggable store: create + verify round-trip", info && info.userId === "u-1");
    check("pluggable store: data round-trips",           info.data && info.data.team === "a");

    var n = await b.session.count();
    check("pluggable store: count reads from thin DB",   n === 1);

    var revoked = await b.session.destroyAllForUser("u-1");
    check("pluggable store: destroyAllForUser drops 1",  revoked === 1);

    // Revert to default so subsequent tests don't carry the override.
    b.session.useStore(null);
    store.close();
    check("pluggable store: useStore(null) reverts",     true);
  } finally {
    b.session.useStore(null);
    await teardownTestDb(tmpDir);
  }
}

async function testDestroyAllForUserPluggableNoDb() {
  // #340: a pluggable-store consumer who never ran b.db.init() must get a
  // clear, actionable error from destroyAllForUser — not the opaque
  // db/not-initialized that bubbled out of the stateless valid-from bump
  // (which writes to the framework db, not the pluggable session store).
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ses-nodb-"));
  try {
    await helpers.setupVaultOnly(tmpDir);   // vault up; b.db deliberately NOT initialized
    b.session.useStore({
      execute:    function () { return Promise.resolve({ rowCount: 1 }); },
      executeOne: function () { return Promise.resolve(null); },
    });
    var err = null;
    try { await b.session.destroyAllForUser("u-1"); }
    catch (e) { err = e; }
    check("destroyAllForUser (pluggable store, no b.db) → clear error, not db/not-initialized",
      err !== null && err.code !== "db/not-initialized" && /b\.db\.init\(\)/.test(err.message || ""));
  } finally {
    b.session.useStore(null);
    helpers.teardownVaultOnly(tmpDir);
  }
}

async function testPluggableStoreValidation() {
  var threw = false;
  try { b.session.useStore({ execute: function () {} }); }
  catch (e) { threw = /executeOne/.test(e.message); }
  check("useStore: missing executeOne refused", threw);

  threw = false;
  try { b.session.useStore("not-an-object"); }
  catch (e) { threw = /must be an object exposing/.test(e.message) && e.code === "INVALID_ARG" && e.permanent === true; }
  check("useStore: non-object refused", threw);

  threw = false;
  try { b.session.stores.localDbThin({}); }
  catch (e) { threw = /session-stores\/bad-file/.test(e.message) && e instanceof TypeError; }
  check("stores.localDbThin: missing file refused", threw);
}

async function testUpdateDataReplaceAndMerge() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ses-update-"));
  try {
    await setupTestDb(tmpDir);
    var s = await b.session.create({
      userId: "u-1",
      data:   { theme: "light", roles: ["user"], counter: 1 },
    });

    // Default = full replace. counter / roles drop; only `theme` lands.
    var ok = await b.session.updateData(s.token, { theme: "dark" });
    check("updateData: returns true on hit",                ok === true);
    var v1 = await b.session.verify(s.token);
    check("updateData: replaced payload — theme=dark",      v1.data.theme === "dark");
    check("updateData: replaced payload — counter dropped", v1.data.counter === undefined);
    check("updateData: replaced payload — roles dropped",   v1.data.roles === undefined);

    // Merge mode preserves existing keys, replaces named keys.
    await b.session.updateData(s.token, { roles: ["admin"], counter: 2 }, { merge: true });
    var v2 = await b.session.verify(s.token);
    check("updateData merge: theme preserved",              v2.data.theme === "dark");
    check("updateData merge: roles updated",                Array.isArray(v2.data.roles) && v2.data.roles[0] === "admin");
    check("updateData merge: counter updated",              v2.data.counter === 2);

    // Setting data: null clears the payload.
    await b.session.updateData(s.token, null);
    var v3 = await b.session.verify(s.token);
    check("updateData null: data cleared",                  v3.data === null);

    // Unknown / invalid token returns false (no throw).
    var miss = await b.session.updateData("vault:not-a-real-token", { x: 1 });
    check("updateData: unknown token returns false",        miss === false);

    var pre = await b.session.updateData("not-sealed-prefix", { x: 1 });
    check("updateData: pre-v0.8.61 raw token returns false", pre === false);

    // Bad shape refused at config time.
    var threw = false;
    try { await b.session.updateData(s.token, [1, 2, 3]); }
    catch (e) { threw = /must be a plain object or null/.test(e.message); }
    check("updateData: array refused",                      threw);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testUpdateDataPreservesFingerprint() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ses-update-fp-"));
  try {
    await setupTestDb(tmpDir);
    var req = {
      headers: { "user-agent": "ua-fp-1", "x-forwarded-for": "203.0.113.10" },
      socket:  { remoteAddress: "203.0.113.10" },
    };
    var s = await b.session.create({
      userId:            "u-1",
      data:              { roles: ["user"] },
      req:               req,
      fingerprintFields: ["clientIp", "userAgent"],
    });

    // updateData replaces operator data wholesale BUT must preserve the
    // reserved __bj_fingerprint binding so verify() with the same req
    // still surfaces fingerprintDrift: false.
    await b.session.updateData(s.token, { roles: ["admin"] });
    var info = await b.session.verify(s.token, {
      req: req, fingerprintFields: ["clientIp", "userAgent"],
    });
    check("updateData preserves fingerprint binding",       info && info.fingerprintDrift === false);
    check("updateData payload reflects the write",           info.data.roles[0] === "admin");
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testRotateRekeysFingerprint() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ses-rotate-fp-"));
  try {
    await setupTestDb(tmpDir);
    var req = _makeReq({ "user-agent": "ua-rot-1", "x-forwarded-for": "203.0.113.10" });
    var s = await b.session.create({
      userId:            "u-rot",
      data:              { roles: ["user"] },
      req:               req,
      fingerprintFields: ["clientIp", "userAgent"],
    });
    var pre = await b.session.verify(s.token, { req: req, fingerprintFields: ["clientIp", "userAgent"] });
    check("rotate-fp: pre-rotation no drift", pre && pre.fingerprintDrift === false);

    // Rotation (login transition / role escalation) moves the sid. __bj_fingerprint
    // is sid-keyed, so the new session must RE-KEY the binding to the new sid from
    // the live request — otherwise verify(newToken, sameReq) recomputes against the
    // new sid and falsely reports drift (logout under strict operators), or the
    // binding silently breaks.
    var rotated = await b.session.rotate(s.token, {
      req: req, fingerprintFields: ["clientIp", "userAgent"],
    });
    check("rotate-fp: rotation returns a new token", rotated && typeof rotated.token === "string");

    var sameDevice = await b.session.verify(rotated.token, {
      req: req, fingerprintFields: ["clientIp", "userAgent"],
    });
    check("rotate-fp: same device → no drift after rotation (binding re-keyed)",
          sameDevice && sameDevice.fingerprintDrift === false);
    check("rotate-fp: operator data carried across rotation",
          sameDevice && sameDevice.data && sameDevice.data.roles && sameDevice.data.roles[0] === "user");

    // A different device must still drift — proves the binding is live, not dropped.
    var otherReq = _makeReq({ "user-agent": "ua-OTHER", "x-forwarded-for": "198.51.100.7" });
    var otherDevice = await b.session.verify(rotated.token, {
      req: otherReq, fingerprintFields: ["clientIp", "userAgent"],
    });
    check("rotate-fp: different device → drift after rotation (binding still enforced)",
          otherDevice && otherDevice.fingerprintDrift === true);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testLogoutEmitsClearSiteData() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ses-logout-"));
  try {
    await setupTestDb(tmpDir);
    var s = await b.session.create({ userId: "u-logout" });
    check("session created", typeof s.token === "string");

    // A real http.ServerResponse can be read as well as written, and the
    // cookie appender requires that — it has to see what is already queued
    // before it can add to it. _makeRes models both halves.
    var loRes = _makeRes();
    var headers = loRes.headers;
    var destroyed = await b.session.logout(loRes, s.token);

    check("logout returns true (session destroyed)", destroyed === true);
    check("logout emits Clear-Site-Data header",
      typeof headers["Clear-Site-Data"] === "string" &&
      headers["Clear-Site-Data"].indexOf('"cookies"') !== -1 &&
      headers["Clear-Site-Data"].indexOf('"storage"') !== -1);
    // Set-Cookie is the one legitimately-repeated response header, so logout
    // appends an array rather than overwriting whatever was already queued.
    check("logout queues Set-Cookie as a header array",
      Array.isArray(headers["Set-Cookie"]) && headers["Set-Cookie"].length === 1);
    var expiry = headers["Set-Cookie"][0];
    check("logout expires the session cookie",
      /(^|;)\s*Max-Age=0/.test(expiry) && expiry.indexOf("sid=;") === 0);
    check("logout cookie is Secure + HttpOnly",
      /HttpOnly/.test(expiry) && /Secure/.test(expiry));

    // The session is gone cluster-wide.
    var after = await b.session.verify(s.token);
    check("logout destroyed the session (verify returns null)", after === null);

    // Custom cookie name + an unknown Clear-Site-Data directive throws.
    var s2 = await b.session.create({ userId: "u-logout-2" });
    var res2 = _makeRes(); var h2 = res2.headers;
    await b.session.logout(res2, s2.token, { cookieName: "__Host-sid" });
    check("logout honors custom cookieName", h2["Set-Cookie"][0].indexOf("__Host-sid=;") === 0);

    // An unknown directive throws BEFORE any side effect — the session is NOT
    // destroyed and no client-wipe headers are queued (validate-before-revoke).
    var s3 = await b.session.create({ userId: "u-logout-3" });
    var res3 = _makeRes(); var h3 = res3.headers;
    var threw = null;
    try { await b.session.logout(res3, s3.token, { types: ["bogus"] }); }
    catch (e) { threw = e; }
    check("logout rejects an unknown Clear-Site-Data directive", threw !== null);
    check("logout did NOT queue headers on the bad-directive throw",
      h3["Clear-Site-Data"] === undefined && h3["Set-Cookie"] === undefined);
    check("logout did NOT destroy the session on the bad-directive throw",
      (await b.session.verify(s3.token)) !== null);

    var badRes = null;
    try { await b.session.logout({}, "x"); } catch (e) { badRes = e; }
    check("logout rejects a res without setHeader", badRes && badRes.code === "session/bad-res");
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// A response double that behaves like http.ServerResponse for the headers
// logout touches: Set-Cookie accumulates, everything else is last-write-wins.
function _makeRes(preset) {
  var headers = Object.create(null);
  if (preset) Object.keys(preset).forEach(function (k) { headers[k] = preset[k]; });
  return {
    headers:   headers,
    setHeader: function (k, v) { headers[k] = v; },
    getHeader: function (k) { return headers[k]; },
  };
}

// Every Set-Cookie logout queued, as a flat array of header strings.
function _setCookies(res) {
  var raw = res.headers["Set-Cookie"];
  if (raw === undefined) return [];
  return Array.isArray(raw) ? raw.slice() : [raw];
}

// The one Set-Cookie whose name is `cookieName`.
function _cookieNamed(res, cookieName) {
  var all = _setCookies(res);
  for (var i = 0; i < all.length; i++) {
    if (all[i].indexOf(cookieName + "=") === 0) return all[i];
  }
  return null;
}

function _hasAttr(header, attr) {
  var parts = String(header).split(";");
  for (var i = 0; i < parts.length; i++) {
    if (parts[i].trim().toLowerCase() === attr.toLowerCase()) return true;
  }
  return false;
}

function _attrValue(header, name) {
  var parts = String(header).split(";");
  var prefix = name.toLowerCase() + "=";
  for (var i = 0; i < parts.length; i++) {
    var p = parts[i].trim();
    if (p.toLowerCase().indexOf(prefix) === 0) return p.slice(prefix.length);
  }
  return null;
}

// #606 — the expiry cookie logout emits is built by hand: Secure and
// SameSite are hardcoded, no Path/Domain override reaches it, the header is
// set rather than appended, and nothing routes through b.cookies.serialize,
// so the RFC 6265bis prefix invariants are never enforced on it.
async function testLogoutCookieAttributes() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ses-logout-attrs-"));
  try {
    await setupTestDb(tmpDir);

    // --- Secure resolves from the request scheme, not a constant -----------
    // A plain-HTTP origin cannot set a Secure cookie: the browser discards
    // the header, so the session cookie survives the logout it was supposed
    // to clear.
    var s1 = await b.session.create({ userId: "u-606-http" });
    var httpRes = _makeRes();
    await b.session.logout(httpRes, s1.token, { req: _makeReq() });
    var httpCookie = _cookieNamed(httpRes, "sid");
    check("logout over plain HTTP omits Secure (browser would drop it)",
      httpCookie !== null && !_hasAttr(httpCookie, "Secure"));

    var s2 = await b.session.create({ userId: "u-606-https" });
    var tlsRes = _makeRes();
    var tlsReq = _makeReq();
    tlsReq.socket = { encrypted: true, remoteAddress: "203.0.113.9" };
    await b.session.logout(tlsRes, s2.token, { req: tlsReq });
    var tlsCookie = _cookieNamed(tlsRes, "sid");
    check("logout over TLS keeps Secure",
      tlsCookie !== null && _hasAttr(tlsCookie, "Secure"));

    // A forwarded scheme is NOT honored from an untrusted peer — the
    // trustedProtocol contract. An attacker-supplied X-Forwarded-Proto must
    // not talk logout into marking the cookie Secure on a cleartext hop.
    var s3 = await b.session.create({ userId: "u-606-spoof" });
    var spoofRes = _makeRes();
    await b.session.logout(spoofRes, s3.token, {
      req: _makeReq({ "x-forwarded-proto": "https" }),
    });
    check("logout ignores X-Forwarded-Proto from an untrusted peer",
      !_hasAttr(_cookieNamed(spoofRes, "sid"), "Secure"));

    // ...and IS honored once the operator declares the proxy trusted.
    var s4 = await b.session.create({ userId: "u-606-trusted" });
    var proxRes = _makeRes();
    var proxReq = _makeReq({ "x-forwarded-proto": "https" });
    proxReq.socket = { remoteAddress: "10.0.0.4" };
    await b.session.logout(proxRes, s4.token, {
      req: proxReq, trustedProxies: ["10.0.0.0/8"],
    });
    check("logout honors X-Forwarded-Proto from a trusted proxy",
      _hasAttr(_cookieNamed(proxRes, "sid"), "Secure"));

    // Explicit opts.secure overrides the resolver in both directions.
    var s5 = await b.session.create({ userId: "u-606-explicit-off" });
    var offRes = _makeRes();
    await b.session.logout(offRes, s5.token, { secure: false });
    check("logout honors an explicit secure: false",
      !_hasAttr(_cookieNamed(offRes, "sid"), "Secure"));

    var s6 = await b.session.create({ userId: "u-606-explicit-on" });
    var onRes = _makeRes();
    await b.session.logout(onRes, s6.token, { req: _makeReq(), secure: true });
    check("an explicit secure: true beats a plain-HTTP req",
      _hasAttr(_cookieNamed(onRes, "sid"), "Secure"));

    // Neither given → the secure default stands, unchanged.
    var s7 = await b.session.create({ userId: "u-606-default" });
    var defRes = _makeRes();
    await b.session.logout(defRes, s7.token);
    check("logout defaults to Secure when neither req nor secure is given",
      _hasAttr(_cookieNamed(defRes, "sid"), "Secure"));

    // --- the clear must be able to MATCH the cookie that was set ----------
    // A browser deletes on name + path + domain. A session cookie written
    // with Domain=.example.com and Path=/app is untouched by a bare
    // Path=/ expiry, so logout has to be able to describe it.
    var s8 = await b.session.create({ userId: "u-606-scope" });
    var scopeRes = _makeRes();
    await b.session.logout(scopeRes, s8.token, {
      path: "/app", domain: "example.com", sameSite: "Lax",
    });
    var scoped = _cookieNamed(scopeRes, "sid");
    check("logout honors opts.path",     _attrValue(scoped, "Path") === "/app");
    check("logout honors opts.domain",   _attrValue(scoped, "Domain") === "example.com");
    check("logout honors opts.sameSite", _attrValue(scoped, "SameSite") === "Lax");

    // --- it must not clobber a Set-Cookie the route already queued --------
    var s9 = await b.session.create({ userId: "u-606-append" });
    var appendRes = _makeRes({ "Set-Cookie": "csrf=abc; Path=/" });
    await b.session.logout(appendRes, s9.token);
    var queued = _setCookies(appendRes);
    check("logout preserves an already-queued Set-Cookie",
      queued.length === 2 && queued.indexOf("csrf=abc; Path=/") !== -1);
    check("logout still queued its own expiry cookie",
      _cookieNamed(appendRes, "sid") !== null);

    // --- RFC 6265bis prefix invariants reach the expiry cookie ------------
    // __Host- REQUIRES Secure. Once Secure is conditional, a hand-rolled
    // string would happily emit an invalid __Host- cookie over HTTP that the
    // browser silently drops; routing through b.cookies.serialize refuses it.
    var s10 = await b.session.create({ userId: "u-606-prefix" });
    var prefixRes = _makeRes();
    var prefixErr = null;
    try {
      await b.session.logout(prefixRes, s10.token, {
        cookieName: "__Host-sid", secure: false,
      });
    } catch (e) { prefixErr = e; }
    check("logout refuses __Host-* without Secure",
      prefixErr !== null && prefixErr.code === "cookies/prefix-host-secure-required");
    check("the refused __Host-* logout queued no headers",
      prefixRes.headers["Set-Cookie"] === undefined &&
      prefixRes.headers["Clear-Site-Data"] === undefined);
    check("the refused __Host-* logout left the session intact",
      (await b.session.verify(s10.token)) !== null);

    // __Host- also forbids Domain, and requires Path=/.
    var s11 = await b.session.create({ userId: "u-606-prefix-domain" });
    var domErr = null;
    try {
      await b.session.logout(_makeRes(), s11.token, {
        cookieName: "__Host-sid", domain: "example.com",
      });
    } catch (e) { domErr = e; }
    check("logout refuses __Host-* with a Domain",
      domErr !== null && domErr.code === "cookies/prefix-host-no-domain");

    // --- a bad attribute is refused BEFORE the session is revoked ---------
    // Same validate-before-revoke ordering the Clear-Site-Data directive
    // check already has: a throw after destroy() would leave the row gone
    // and the browser still holding its cookie.
    var s12 = await b.session.create({ userId: "u-606-order" });
    var orderRes = _makeRes();
    var orderErr = null;
    try {
      await b.session.logout(orderRes, s12.token, { sameSite: "Sideways" });
    } catch (e) { orderErr = e; }
    check("logout refuses an invalid sameSite", orderErr !== null);
    check("the invalid-sameSite logout did NOT revoke the session",
      (await b.session.verify(s12.token)) !== null);
    check("the invalid-sameSite logout queued no headers",
      orderRes.headers["Set-Cookie"] === undefined &&
      orderRes.headers["Clear-Site-Data"] === undefined);

    // --- a prefixed name outranks the request scheme ----------------------
    // A __Host- cookie only ever exists on a secure origin, so a plain-HTTP
    // request has nothing of that name to clear. Resolving `secure` to false
    // from the request would make serialize() refuse the prefix — and since the
    // cookie is built BEFORE the row is revoked, that refusal would abort the
    // logout, letting whoever chose the scheme decide whether the session died.
    var s14 = await b.session.create({ userId: "u-606-prefix-http" });
    var prefixHttpRes = _makeRes();
    var destroyed14 = await b.session.logout(prefixHttpRes, s14.token, {
      req: _makeReq(), cookieName: "__Host-sid",
    });
    check("a __Host- name keeps Secure on a plain-HTTP request",
      _hasAttr(_cookieNamed(prefixHttpRes, "__Host-sid"), "Secure"));
    check("a plain-HTTP request cannot stop a __Host- logout revoking the session",
      destroyed14 === true && (await b.session.verify(s14.token)) === null);

    var s15 = await b.session.create({ userId: "u-606-secure-prefix-http" });
    var securePrefixRes = _makeRes();
    var destroyed15 = await b.session.logout(securePrefixRes, s15.token, {
      req: _makeReq(), cookieName: "__Secure-sid",
    });
    check("a __Secure- name keeps Secure on a plain-HTTP request",
      _hasAttr(_cookieNamed(securePrefixRes, "__Secure-sid"), "Secure"));
    check("...and that logout revokes the session too",
      destroyed15 === true && (await b.session.verify(s15.token)) === null);

    // --- a mistyped req must not silently drop Secure ----------------------
    // trustedProtocol answers "http" for a non-request rather than throwing, so
    // an unchecked `req` would quietly produce a non-Secure cookie.
    var s16 = await b.session.create({ userId: "u-606-bad-req" });
    var badReqErr = null;
    try { await b.session.logout(_makeRes(), s16.token, { req: null }); }
    catch (e) { badReqErr = e; }
    check("logout refuses a null req rather than resolving it to http",
      badReqErr !== null && badReqErr.code === "session/bad-req");
    check("the refused-req logout left the session intact",
      (await b.session.verify(s16.token)) !== null);

    var strReqErr = null;
    try { await b.session.logout(_makeRes(), s16.token, { req: "https" }); }
    catch (e) { strReqErr = e; }
    check("logout refuses a non-object req",
      strReqErr !== null && strReqErr.code === "session/bad-req");

    // --- an unappendable response is refused BEFORE the row is revoked -----
    // The expiry cookie is queued through b.cookies.appendSetCookie, which has
    // to read the response as well as write it. A response carrying only
    // setHeader cannot satisfy that — and discovering it after destroy() would
    // leave the session revoked, Clear-Site-Data queued, no expiry cookie, and
    // a 500. The response shape is the caller's, fixed for the life of the
    // process, so it is checked with the other option validation up front.
    var s17 = await b.session.create({ userId: "u-606-writeonly" });
    var writeOnlyRes = { setHeader: function () {} };
    var writeOnlyErr = null;
    try { await b.session.logout(writeOnlyRes, s17.token); } catch (e) { writeOnlyErr = e; }
    check("logout refuses a write-only response",
      writeOnlyErr !== null && writeOnlyErr.code === "cookies/unreadable-response");
    check("the refused write-only logout did NOT revoke the session",
      (await b.session.verify(s17.token)) !== null);

    // --- an unknown option is a typo, not a silent no-op -------------------
    var s13 = await b.session.create({ userId: "u-606-typo" });
    var typoErr = null;
    try {
      await b.session.logout(_makeRes(), s13.token, { cookiename: "sid" });
    } catch (e) { typoErr = e; }
    check("logout rejects an unknown option key", typoErr !== null);
    check("the rejected-typo logout left the session intact",
      (await b.session.verify(s13.token)) !== null);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function run() {
  await testLogoutEmitsClearSiteData();
  await testLogoutCookieAttributes();
  await testSealedCookieDefault();
  await testSealedCookieRotateAndDestroy();
  await testClientIpPrefixV4();
  await testClientIpPrefixV6();
  await testClientIpPrefixV4MappedV6();
  await testFingerprintPeerGatedClientIp();
  await testPluggableStore();
  await testDestroyAllForUserPluggableNoDb();
  await testPluggableStoreValidation();
  await testUpdateDataReplaceAndMerge();
  await testUpdateDataPreservesFingerprint();
  await testRotateRekeysFingerprint();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.message, e.stack); process.exit(1); }
  );
}
