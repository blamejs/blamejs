// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.middleware.sharedSecretHeader — a named header carrying a shared secret,
 * the third common way a request authenticates itself alongside
 * `Authorization: Bearer` and a signed webhook.
 *
 * The tests below pin the four things a hand-rolled version gets wrong, in the
 * order they bite:
 *   - a wrong-LENGTH header must be a 401, not a 500. b.crypto.timingSafeEqual
 *     THROWS on a length mismatch rather than returning false, so a compare
 *     that runs before the length check turns a short header into a crash.
 *   - an unconfigured secret must refuse every request, not accept them. A
 *     deployment that forgot the environment variable is wide open otherwise,
 *     and looks configured.
 *   - the compare must not short-circuit, which is the entire reason
 *     timingSafeEqual is there.
 *   - an availability failure (a secret resolver that throws) must not be
 *     reported as an authentication failure: still denied, but 503, because
 *     "we could not check" is not "you are wrong".
 *
 * Run standalone: `node test/layer-0-primitives/shared-secret-header.test.js`
 */

var helpers = require("../helpers");
var b        = helpers.b;
var check    = helpers.check;
var _mockReq = helpers._mockReq;
var _mockRes = helpers._mockRes;

// Drive one request through the middleware; resolve to what happened.
function _run(opts, headers) {
  var mw = b.middleware.sharedSecretHeader(opts);
  var req = _mockReq({ method: "POST", url: "/internal/sync", headers: headers || {} });
  var res = _mockRes();
  return new Promise(function (resolve) {
    var nexted = false;
    var origEnd = res.end;
    res.end = function () {
      var r = origEnd.apply(res, arguments);
      var cap = res._captured();
      resolve({ nexted: nexted, status: cap.status, body: cap.body });
      return r;
    };
    Promise.resolve(mw(req, res, function () {
      nexted = true;
      resolve({ nexted: true, status: null, body: null });
    })).catch(function (e) { resolve({ nexted: false, threw: e }); });
  });
}

var SECRET = "s3cret-value-of-known-length";

async function testAcceptsTheMatchingSecret() {
  var ok = await _run({ headerName: "x-internal-secret", secret: SECRET },
    { "x-internal-secret": SECRET });
  check("sharedSecretHeader: the matching secret passes", ok.nexted === true);
}

async function testRefusesEveryWrongShape() {
  // Absent header.
  var absent = await _run({ headerName: "x-internal-secret", secret: SECRET }, {});
  check("sharedSecretHeader: an absent header is 401",
    absent.nexted === false && absent.status === 401);

  // WRONG LENGTH — the case that crashes a hand-roll, because
  // timingSafeEqual throws instead of returning false.
  var short = await _run({ headerName: "x-internal-secret", secret: SECRET },
    { "x-internal-secret": "too-short" });
  check("sharedSecretHeader: a shorter header is 401, not a 500",
    short.nexted === false && short.status === 401);
  var long = await _run({ headerName: "x-internal-secret", secret: SECRET },
    { "x-internal-secret": SECRET + "-and-more" });
  check("sharedSecretHeader: a longer header is 401, not a 500",
    long.nexted === false && long.status === 401);

  // Right length, wrong value.
  var wrong = await _run({ headerName: "x-internal-secret", secret: SECRET },
    { "x-internal-secret": "S3CRET-VALUE-OF-KNOWN-LENGTH" });
  check("sharedSecretHeader: a same-length wrong value is 401",
    wrong.nexted === false && wrong.status === 401);

  // A repeated header arrives as an array — it must not be compared as one.
  var repeated = await _run({ headerName: "x-internal-secret", secret: SECRET },
    { "x-internal-secret": [SECRET, "other"] });
  check("sharedSecretHeader: a repeated header is refused",
    repeated.nexted === false && repeated.status === 401);

  // Every refusal must look the same, so the gate is not an oracle for WHICH
  // of those it was.
  var bodies = [absent.body, short.body, long.body, wrong.body, repeated.body];
  check("sharedSecretHeader: every refusal is byte-identical",
    bodies.every(function (x) { return x === bodies[0]; }));
}

async function testUnconfiguredSecretFailsClosed() {
  // The deployment that forgot the environment variable. Accepting here is
  // wide open AND looks configured, so it must refuse.
  [undefined, null, ""].forEach(function () { /* shapes covered below */ });

  var undef = await _run({ headerName: "x-internal-secret", secret: undefined },
    { "x-internal-secret": "anything" });
  check("sharedSecretHeader: an undefined secret refuses",
    undef.nexted === false && undef.status === 401);

  var empty = await _run({ headerName: "x-internal-secret", secret: "" },
    { "x-internal-secret": "" });
  check("sharedSecretHeader: an empty secret refuses even an empty header",
    empty.nexted === false && empty.status === 401);

  var nul = await _run({ headerName: "x-internal-secret", secret: null },
    { "x-internal-secret": "anything" });
  check("sharedSecretHeader: a null secret refuses", nul.nexted === false);
}

async function testResolverAvailabilityIsNotAnAuthFailure() {
  // A secret fetched at request time — a secrets manager, a rotating value.
  var viaResolver = await _run({
    headerName: "x-internal-secret",
    secret:     function () { return SECRET; },
  }, { "x-internal-secret": SECRET });
  check("sharedSecretHeader: a resolver's secret is accepted", viaResolver.nexted === true);

  var asyncResolver = await _run({
    headerName: "x-internal-secret",
    secret:     async function () { return SECRET; },
  }, { "x-internal-secret": SECRET });
  check("sharedSecretHeader: an async resolver is accepted", asyncResolver.nexted === true);

  // The resolver is unavailable. This is NOT an authentication failure — the
  // caller may well be holding the right secret and we cannot tell. It must
  // still DENY (fail closed), but say 503, so an operator reading logs sees a
  // dependency outage rather than a flood of bad credentials.
  var down = await _run({
    headerName: "x-internal-secret",
    secret:     function () { throw new Error("secrets manager unreachable"); },
  }, { "x-internal-secret": SECRET });
  check("sharedSecretHeader: an unavailable resolver denies", down.nexted === false);
  check("sharedSecretHeader: an unavailable resolver is 503, not 401",
    down.status === 503);

  var rejected = await _run({
    headerName: "x-internal-secret",
    secret:     async function () { throw new Error("timeout"); },
  }, { "x-internal-secret": SECRET });
  check("sharedSecretHeader: a rejecting async resolver is 503", rejected.status === 503);

  // A resolver that returns nothing is the unconfigured case, not an outage.
  var none = await _run({
    headerName: "x-internal-secret",
    secret:     function () { return null; },
  }, { "x-internal-secret": SECRET });
  check("sharedSecretHeader: a resolver returning nothing refuses with 401",
    none.nexted === false && none.status === 401);
}

// The 503 path emits an observability event on the way to refusing. If that
// emit is not contained, a broken metrics registry turns the promised
// fail-closed 503 into an unhandled rejection the router reports as 500 — the
// telemetry deciding the response, which is exactly backwards.
async function testTelemetryFailureCannotChangeTheAnswer() {
  var observability = require("../../lib/observability");
  var realSafeEvent = observability.safeEvent;
  var realEvent = observability.event;
  var result;
  try {
    observability.safeEvent = function () { throw new Error("metrics registry is broken"); };
    observability.event = function () { throw new Error("metrics registry is broken"); };
    result = await _run({
      headerName: "x-internal-secret",
      secret:     function () { throw new Error("secrets manager unreachable"); },
    }, { "x-internal-secret": SECRET });
  } finally {
    observability.safeEvent = realSafeEvent;
    observability.event = realEvent;
  }
  check("sharedSecretHeader: a throwing telemetry sink does not escape the handler",
    result.threw === undefined);
  check("sharedSecretHeader: an unavailable resolver still answers 503 when telemetry is broken",
    result.nexted === false && result.status === 503);
}

// A REAL request, not a mock. The repeated-header case is precisely where a
// mock misleads: node's IncomingMessage JOINS duplicate custom headers into a
// comma-separated STRING ("a, b"), it does not expose an array. A fixture that
// hands the middleware an array therefore tests a shape the runtime never
// produces — which is how an Array.isArray() check passed its test while never
// firing in production.
//
// Verified against node directly before writing this: two `x-s` header lines
// arrive as headers["x-s"] === "a, b", with both occurrences in rawHeaders.
async function testRepeatedHeaderOverARealSocket() {
  var http = require("http");
  var mw = b.middleware.sharedSecretHeader({
    headerName: "x-internal-secret",
    // A secret that EQUALS what node produces by joining two header lines.
    // Without a duplicate check the join reconstructs it and the request is
    // authenticated although no single header ever carried the secret.
    secret: "alpha, beta",
  });

  var outcomes = [];
  var srv = http.createServer(function (req, res) {
    Promise.resolve(mw(req, res, function () {
      outcomes.push("NEXTED");
      res.statusCode = 200;
      res.end("served");
    })).catch(function (e) {
      outcomes.push("THREW:" + (e && e.code));
      if (!res.writableEnded) { res.statusCode = 500; res.end("err"); }
    });
  });
  var port = await b.testing.listenOnRandomPort(srv, "127.0.0.1");

  function send(headerLines) {
    return new Promise(function (resolve) {
      var req = http.request({ host: "127.0.0.1", port: port, path: "/", method: "POST" },
        function (res) {
          res.resume();
          res.on("end", function () { resolve(res.statusCode); });
        });
      headerLines.forEach(function (v, i) {
        if (i === 0) req.setHeader("x-internal-secret", v);
        else req.setHeader("x-internal-secret", [].concat(req.getHeader("x-internal-secret"), v));
      });
      req.end();
    });
  }

  try {
    var split = await send(["alpha", "beta"]);
    check("sharedSecretHeader: two header lines that JOIN to the secret are refused " +
      "(status " + split + ", outcomes " + JSON.stringify(outcomes) + ")",
      split === 401 && outcomes.indexOf("NEXTED") === -1);

    // CONTROL: the same secret in ONE header line must still authenticate, or
    // the check above would pass for a middleware that refuses everything.
    outcomes.length = 0;
    var single = await send(["alpha, beta"]);
    check("sharedSecretHeader CONTROL: the secret in a single header line is accepted " +
      "(status " + single + ")",
      single === 200 && outcomes.indexOf("NEXTED") !== -1);
  } finally {
    await new Promise(function (r) { srv.close(r); });
  }
}

function testConfigRefusals() {
  function code(opts) {
    try { b.middleware.sharedSecretHeader(opts); return null; }
    catch (e) { return e.code || e.message; }
  }
  check("sharedSecretHeader: requires a headerName",
    code({ secret: SECRET }) !== null);
  check("sharedSecretHeader: refuses an empty headerName",
    code({ headerName: "", secret: SECRET }) !== null);
  check("sharedSecretHeader: refuses a non-string headerName",
    code({ headerName: 42, secret: SECRET }) !== null);
  // An unknown option is a typo, not a silent no-op.
  check("sharedSecretHeader: refuses an unknown option",
    code({ headerName: "x-s", secret: SECRET, secrett: "typo" }) !== null);
  // A secret that is neither a string nor a resolver is a configuration error
  // — not something to discover per-request.
  check("sharedSecretHeader: refuses a non-string, non-function secret",
    code({ headerName: "x-s", secret: 12345 }) !== null);

  // A header name is an RFC 9110 §5.1 token. A name carrying a space, a colon
  // or any other delimiter can never match an incoming header, so a typo
  // produces permanent 401s that look exactly like a caller with the wrong
  // secret. That is a configuration mistake and belongs at boot, where the
  // operator sees it, not at request time where it is indistinguishable from
  // an attack.
  var badNames = [" x-s", "x-s ", "x s", "x:s", "x-s:", "x\ts", "x,s",
                  "x(s)", "x@s", "x/s", "x[s]", "x\"s", "x{s}"];
  var accepted = badNames.filter(function (n) {
    return code({ headerName: n, secret: SECRET }) === null;
  });
  check("sharedSecretHeader: a header name that is not a token is refused at boot" +
    (accepted.length ? " (accepted " + JSON.stringify(accepted) + ")" : ""),
    accepted.length === 0);

  // The tokens that ARE legal must keep working, including the ones that look
  // unusual — a guard that refuses valid names is its own bug.
  var goodNames = ["x-s", "X-Internal-Secret", "x_s", "x.s", "x1", "a",
                   "x-s!", "x-s#", "x-s$", "x-s%", "x-s&", "x-s*", "x-s+",
                   "x-s^", "x-s`", "x-s|", "x-s~", "x-s'"];
  var refused = goodNames.filter(function (n) {
    return code({ headerName: n, secret: SECRET }) !== null;
  });
  check("sharedSecretHeader: a legal RFC 9110 token header name is accepted" +
    (refused.length ? " (refused " + JSON.stringify(refused) + ")" : ""),
    refused.length === 0);
}

// A resolver that hands back something that is not a secret — a Buffer from a
// secrets-manager SDK, a number, a parsed JSON object — is an operator bug in
// the resolver, not a deployment that forgot to configure one. Both deny, but
// reporting it as 401 tells the operator their CALLERS are wrong and hides the
// real cause behind a wall of credential failures.
async function testResolverTypeErrorIsNotReportedAsBadCredentials() {
  var shapes = [
    { label: "Buffer", make: function () { return Buffer.from(SECRET); } },
    { label: "number", make: function () { return 12345; } },
    { label: "object", make: function () { return { value: SECRET }; } },
    { label: "array",  make: function () { return [SECRET]; } },
    { label: "true",   make: function () { return true; } },
  ];
  var misreported = [];
  for (var i = 0; i < shapes.length; i++) {
    var r = await _run({ headerName: "x-internal-secret", secret: shapes[i].make },
      { "x-internal-secret": SECRET });
    if (r.nexted !== false) misreported.push(shapes[i].label + ":ACCEPTED");
    else if (r.status !== 503) misreported.push(shapes[i].label + ":" + r.status);
  }
  check("sharedSecretHeader: a resolver returning a non-secret denies with 503, not 401" +
    (misreported.length ? " (" + misreported.join(", ") + ")" : ""),
    misreported.length === 0);

  // Returning NOTHING is still the unconfigured case, which is 401 — the two
  // must stay distinguishable.
  var none = await _run({ headerName: "x-internal-secret", secret: function () { return null; } },
    { "x-internal-secret": SECRET });
  check("sharedSecretHeader: a resolver returning nothing is still 401, not 503",
    none.nexted === false && none.status === 401);
}

// A request with no credential must not reach the secrets manager.
//
// `opts.secret` may be a resolver backed by a secrets manager, and it was
// awaited before the gate looked at whether the caller had presented anything
// at all. So an unauthenticated client could drive that dependency once per
// request — traffic and latency it never had to earn, and an outage it could
// amplify — while presenting no credential.
//
// The verdict does not change: a request with no header was refused before and
// is refused now. What changes is that the refusal costs nothing outside the
// process. During a resolver outage such a request now answers 401 rather than
// 503, which is the more accurate of the two: the caller brought no credential,
// so the dependency's health is not what decided it.
async function testAnAbsentHeaderDoesNotReachTheResolver() {
  var calls = 0;
  var opts = {
    headerName: "x-internal-token",
    secret:     async function () { calls += 1; return "s3cr3t"; },
  };

  var absent = await _run(opts, {});
  check("sharedSecretHeader: a request with no header is still refused",
        absent.status === 401);
  check("sharedSecretHeader: and the secret resolver was never called (" +
        calls + ")", calls === 0);

  // An empty header value is the same case — present but carrying nothing.
  var empty = await _run(opts, { "x-internal-token": "" });
  check("sharedSecretHeader: an empty header value does not reach the resolver",
        empty.status === 401 && calls === 0);

  // The control: a request that DOES present a credential must still reach the
  // resolver, or the checks above pass for a gate that stopped resolving.
  var presented = await _run(opts, { "x-internal-token": "s3cr3t" });
  check("sharedSecretHeader: a presented credential still resolves the secret " +
        "(" + calls + " call)", calls === 1 && presented.nexted === true);
}

async function run() {
  await testAcceptsTheMatchingSecret();
  await testRefusesEveryWrongShape();
  await testUnconfiguredSecretFailsClosed();
  await testResolverAvailabilityIsNotAnAuthFailure();
  await testAnAbsentHeaderDoesNotReachTheResolver();
  await testTelemetryFailureCannotChangeTheAnswer();
  await testResolverTypeErrorIsNotReportedAsBadCredentials();
  await testRepeatedHeaderOverARealSocket();
  testConfigRefusals();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[shared-secret-header] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL: " + helpers.formatErr(e)); process.exit(1); }
  );
}
