// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// b.csp — CSP3 header builder + nonce/hash helpers.

var helpers = require("../helpers");
var check = helpers.check;
var b = helpers.b;
var DEFAULT_CSP = require("../../lib/middleware/security-headers").DEFAULT_CSP;

// Every directive the framework's own DEFAULT_CSP emits must be a
// directive b.csp.build recognizes — otherwise the default policy can't
// round-trip through the builder (regression: fenced-frame-src shipped in
// DEFAULT_CSP but was missing from ALL_DIRECTIVES).
function testDefaultCspRoundTrips() {
  var directives = {};
  DEFAULT_CSP.split(";").forEach(function (part) {
    var tokens = part.trim().split(/\s+/);
    if (!tokens[0]) return;
    directives[tokens[0]] = tokens.slice(1);
  });
  check("DEFAULT_CSP names fenced-frame-src", Object.prototype.hasOwnProperty.call(directives, "fenced-frame-src"));
  var threw = null;
  try { b.csp.build(directives, { acknowledgeUnsafe: true, allowDataImages: true, trustedTypesPolicies: ["default"] }); }
  catch (e) { threw = e.code + ": " + e.message; }
  check("DEFAULT_CSP round-trips through b.csp.build", threw === null);
}

function testWebrtcDirective() {
  var policy = b.csp.build({ "default-src": ["'self'"], "webrtc": ["'block'"] });
  check("csp.build accepts webrtc directive", policy.indexOf("webrtc 'block'") !== -1);
}

function testBuild() {
  var policy = b.csp.build({
    "default-src":     ["'self'"],
    "script-src":      ["'self'"],
    "img-src":         ["'self'"],
    "object-src":      ["'none'"],
    "base-uri":        ["'self'"],
    "frame-ancestors": ["'none'"],
  });
  check("csp.build returns a string",          typeof policy === "string");
  check("csp.build emits default-src",         policy.indexOf("default-src 'self'") !== -1);
  check("csp.build auto-adds Trusted Types",   policy.indexOf("require-trusted-types-for 'script'") !== -1);
}

function testRefusesUnsafeKeywords() {
  var threw = null;
  try { b.csp.build({ "script-src": ["'self'", "'unsafe-inline'"] }); }
  catch (e) { threw = e.code; }
  check("csp.build refuses 'unsafe-inline'", threw === "csp/unsafe-keyword");
}

function testRefusesDirectiveInjectionInSource() {
  // A CSP source is a single non-whitespace token. A ';' or whitespace inside a
  // source value would inject a new directive (the emitter ';'-joins directives,
  // space-joins sources) — refuse both in build() and mergeDirectives().
  var threwSemi = null;
  try { b.csp.build({ "img-src": ["https://evil.com; script-src https://attacker.example"] }); }
  catch (e) { threwSemi = e.code; }
  check("csp.build refuses ';' in a source (directive injection)", threwSemi === "csp/bad-source");

  var threwWs = null;
  try { b.csp.build({ "img-src": ["https://evil.com script-src"] }); }
  catch (e) { threwWs = e.code; }
  check("csp.build refuses whitespace in a source", threwWs === "csp/bad-source");

  var threwMerge = null;
  try { b.csp.mergeDirectives(undefined, { "img-src": ["https://evil.com; script-src https://x"] }); }
  catch (e) { threwMerge = e.code; }
  check("csp.mergeDirectives refuses ';' in an added source", threwMerge === "csp/bad-source");
}

function testRefusesCatchAll() {
  var threw = null;
  try { b.csp.build({ "default-src": ["*"] }); }
  catch (e) { threw = e.code; }
  check("csp.build refuses '*' source", threw === "csp/catch-all-source");
}

function testRefusesDataInImg() {
  var threw = null;
  try { b.csp.build({ "img-src": ["'self'", "data:"] }); }
  catch (e) { threw = e.code; }
  check("csp.build refuses data: in img-src", threw === "csp/data-source");
  // allowDataImages opt unblocks
  var policy = b.csp.build({ "img-src": ["'self'", "data:"] }, { allowDataImages: true });
  check("csp.build accepts data: with allowDataImages",
    policy.indexOf("img-src 'self' data:") !== -1);
}

function testRefusesUnknownDirective() {
  var threw = null;
  try { b.csp.build({ "not-a-real-directive": ["'self'"] }); }
  catch (e) { threw = e.code; }
  check("csp.build refuses unknown directive", threw === "csp/unknown-directive");
}

function testNonce() {
  var n = b.csp.nonce();
  check("csp.nonce returns a string",          typeof n === "string");
  check("csp.nonce is base64url-shaped",       /^[A-Za-z0-9_-]+$/.test(n));
  check("csp.nonce is >= 22 chars (128 bits)", n.length >= 22);                                  // allow:raw-byte-literal — 128/6 rounded up
  var threw = null;
  try { b.csp.nonce(8); } catch (e) { threw = e.code; }
  check("csp.nonce refuses < 16-byte length", threw === "csp/bad-nonce-len");
}

function testHash() {
  var src = b.csp.hash("console.log('boot');");
  check("csp.hash returns sha384 by default",
    src.indexOf("'sha384-") === 0 && src.charAt(src.length - 1) === "'");
  var sha256 = b.csp.hash("console.log('boot');", "sha256");
  check("csp.hash supports sha256", sha256.indexOf("'sha256-") === 0);
  var threw = null;
  try { b.csp.hash("x", "md5"); } catch (e) { threw = e.code; }
  check("csp.hash refuses md5", threw === "csp/bad-hash-alg");
}

function testCspErrorClass() {
  check("CspError exported", typeof b.csp.CspError === "function");
  var e = new b.csp.CspError("csp/test", "synthetic");
  check("CspError carries code", e.code === "csp/test");
}

// b.csp.mergeDirectives / mergePermissionsPolicy — per-route additive merge (#333).
function _code(fn) { try { fn(); return null; } catch (e) { return e.code || e.message; } }

// A CSP header with nothing in it constrains nothing, and the caller who set it
// believes the page is protected. `build({})` returned "" — so a directive set
// assembled conditionally, where every branch happened to be skipped, produced
// a header that reads as configured and enforces nothing.
//
// The sibling builder already takes this position: b.cdnCacheControl.build({})
// throws `cdn-cache-control/empty` rather than "refuse to emit an empty
// Cache-Control list". The security-critical builder of the two was the lenient
// one, which is the wrong way round.
//
// An ARRAY reaches the same place: `typeof [] === "object"`, so it passes the
// object check, and `Object.keys([])` is empty. A NON-empty array is already
// caught (its index "0" is not a directive name), so the empty one was the only
// way through.
function testRefusesAnEmptyPolicy() {
  check("build refuses an empty directive set rather than emitting an empty header",
        _code(function () { b.csp.build({}); }) === "csp/empty",
        String(_code(function () { b.csp.build({}); })));
  check("build refuses an empty array, which passes a bare typeof object check",
        _code(function () { b.csp.build([]); }) === "csp/empty",
        String(_code(function () { b.csp.build([]); })));

  // Adding NOTHING to a base policy is a valid no-op, and the result is the
  // base — which is not empty. The refusal has to look at the policy a caller
  // actually receives, not at an intermediate validation pass over the
  // additions alone, or merging `{}` refuses a policy that was never empty.
  var noop = b.csp.mergeDirectives(undefined, {});
  check("mergeDirectives with no additions returns the base policy, not a refusal",
        typeof noop === "string" && noop.indexOf("default-src") !== -1,
        JSON.stringify(String(noop).slice(0, 60)));

  // An addition whose value list is empty is refused EARLIER, as a bad
  // directive value, so it never reaches the additions-validation pass. That
  // ordering is what keeps `csp/empty` unreachable from a merge: pinned here
  // because if the earlier check were relaxed, a no-op merge would start
  // failing with the wrong code and this is the only thing that would say so.
  check("an empty addition list is refused as a bad value, before the emptiness check",
        _code(function () { b.csp.mergeDirectives(undefined, { "script-src": [] }); }) ===
          "csp/bad-directive-value",
        String(_code(function () { b.csp.mergeDirectives(undefined, { "script-src": [] }); })));

  // The control: a policy with a directive in it still builds, so the refusal
  // is about emptiness and not about the builder refusing everything.
  check("build still emits a policy that has directives",
        b.csp.build({ "default-src": ["'self'"] }) === "default-src 'self'",
        JSON.stringify(b.csp.build({ "default-src": ["'self'"] })));
  // And a non-empty array is still refused for naming a directive "0", not for
  // being empty — the two refusals stay distinguishable.
  check("build still refuses a non-empty array as an unknown directive",
        _code(function () { b.csp.build(["default-src 'self'"]); }) === "csp/unknown-directive",
        String(_code(function () { b.csp.build(["default-src 'self'"]); })));
}

function testMergeDirectives() {
  // Deriving from the strict default must NOT re-validate (and thus refuse)
  // the default's own img-src 'self' data: — only the ADDED sources are gated.
  var merged = b.csp.mergeDirectives(undefined, {
    "script-src": ["https://js.stripe.com"], "frame-src": ["https://js.stripe.com"],
  });
  check("mergeDirectives derives from DEFAULT_CSP without re-validating the base data:",
        /img-src[^;]*data:/.test(merged));
  check("mergeDirectives appends the host to script-src", /script-src[^;]*js\.stripe\.com/.test(merged));
  check("mergeDirectives appends the host to frame-src", /frame-src[^;]*js\.stripe\.com/.test(merged));
  check("mergeDirectives leaves frame-ancestors untouched", merged.indexOf("frame-ancestors") !== -1);

  // The merge is additive — a second pass over its own output is idempotent.
  var twice = b.csp.mergeDirectives(merged, { "script-src": ["https://js.stripe.com"] });
  check("mergeDirectives de-dupes an already-present source",
        (twice.match(/js\.stripe\.com/g) || []).length === merged.match(/js\.stripe\.com/g).length);

  // Only the added sources are gated.
  check("mergeDirectives refuses an unknown directive",
        _code(function () { b.csp.mergeDirectives(undefined, { "bogus-src": ["x"] }); }) === "csp/unknown-directive");
  check("mergeDirectives refuses an added catch-all source",
        _code(function () { b.csp.mergeDirectives(undefined, { "script-src": ["*"] }); }) === "csp/catch-all-source");
  check("mergeDirectives refuses an added data: without allowDataImages",
        _code(function () { b.csp.mergeDirectives(undefined, { "img-src": ["data:"] }); }) === "csp/data-source");
  check("mergeDirectives admits an added data: with allowDataImages",
        typeof b.csp.mergeDirectives(undefined, { "img-src": ["data:"] }, { allowDataImages: true }) === "string");
  check("mergeDirectives refuses CR/LF in an added source",
        _code(function () { b.csp.mergeDirectives(undefined, { "script-src": ["https://x\r\ny"] }); }) === "csp/header-injection");
  // Prototype-pollution guard — the hostile key must be own-enumerable (JSON).
  check("mergeDirectives refuses a __proto__ directive name",
        _code(function () { b.csp.mergeDirectives(undefined, JSON.parse('{"__proto__":["https://x"]}')); }) === "csp/bad-directive-name");
}

function testMergePermissionsPolicy() {
  var pp = b.csp.mergePermissionsPolicy(undefined, { payment: '(self "https://js.stripe.com")' });
  check("mergePermissionsPolicy re-enables the named feature", /payment=\(self "https:\/\/js\.stripe\.com"\)/.test(pp));
  check("mergePermissionsPolicy leaves other features denied", /camera=\(\)/.test(pp));
  check("mergePermissionsPolicy refuses a non-RFC-9651 value",
        _code(function () { b.csp.mergePermissionsPolicy(undefined, { payment: "yes" }); }) === "csp/bad-feature-value");
  check("mergePermissionsPolicy refuses a comma-bearing value (header injection)",
        _code(function () { b.csp.mergePermissionsPolicy(undefined, { payment: "(self), camera=*" }); }) === "csp/bad-feature-value");
  check("mergePermissionsPolicy refuses a __proto__ feature name",
        _code(function () { b.csp.mergePermissionsPolicy(undefined, JSON.parse('{"__proto__":"(self)"}')); }) === "csp/bad-feature-name");
}

function run() {
  testDefaultCspRoundTrips();
  testWebrtcDirective();
  testBuild();
  testRefusesUnsafeKeywords();
  testRefusesDirectiveInjectionInSource();
  testRefusesCatchAll();
  testRefusesDataInImg();
  testRefusesUnknownDirective();
  testNonce();
  testHash();
  testCspErrorClass();
  testRefusesAnEmptyPolicy();
  testMergeDirectives();
  testMergePermissionsPolicy();
}

if (require.main === module) {
  try { run(); }
  catch (e) { console.error(e); process.exit(1); }
}
module.exports = { run: run };
