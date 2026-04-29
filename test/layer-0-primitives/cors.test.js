"use strict";
/**
 * cors middleware — same-origin pass-through + allow-list refusal.
 *
 * Run standalone: `node test/layer-0-primitives/cors.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b      = helpers.b;
var check  = helpers.check;

function _req(opts) {
  opts = opts || {};
  return {
    method:  opts.method  || "POST",
    url:     opts.url     || "/login",
    headers: Object.assign({
      host:   "localhost:8080",
      origin: "http://localhost:8080",
    }, opts.headers || {}),
    socket:  opts.socket  || { remoteAddress: "127.0.0.1", encrypted: false },
  };
}

function _res() {
  var sent = { headers: {}, statusCode: null, body: "" };
  return {
    setHeader: function (k, v) { sent.headers[k.toLowerCase()] = v; },
    writeHead: function (sc, h) {
      sent.statusCode = sc;
      if (h) {
        var keys = Object.keys(h);
        for (var i = 0; i < keys.length; i++) sent.headers[keys[i].toLowerCase()] = h[keys[i]];
      }
    },
    end:      function (b) { sent.body = b || ""; },
    _sent:    sent,
  };
}

function _drive(mw, req) {
  return new Promise(function (resolve) {
    var res = _res();
    var nextCalled = false;
    mw(req, res, function () { nextCalled = true; resolve({ res: res, nextCalled: nextCalled }); });
    // If next was synchronous, the resolve above happened.
    // Otherwise the middleware terminated the response — check that path.
    setTimeout(function () { resolve({ res: res, nextCalled: nextCalled }); }, 5);
  });
}

async function testCorsSameOriginPostPassesWithoutAllowList() {
  // Empty allow-list: a same-origin POST (browser sets Origin header
  // per Fetch spec) must NOT get refused. This was the wiki login bug.
  var mw = b.middleware.cors({ origins: [], refuseUnknown: true });
  var req = _req({
    method:  "POST",
    headers: { host: "localhost:8080", origin: "http://localhost:8080" },
  });
  var out = await _drive(mw, req);
  check("same-origin POST passes through (no 403)",     out.nextCalled === true);
  check("same-origin POST: no CORS headers added",      out.res._sent.headers["access-control-allow-origin"] === undefined);
}

async function testCorsCrossOriginPostStillRefused() {
  // Same allow-list, different origin → refused as before.
  var mw = b.middleware.cors({ origins: [], refuseUnknown: true });
  var req = _req({
    method:  "POST",
    headers: { host: "localhost:8080", origin: "https://attacker.example.com" },
  });
  var out = await _drive(mw, req);
  check("cross-origin POST refused (403)",              out.res._sent.statusCode === 403);
  check("cross-origin POST refusal body intact",        /CORS: origin not allowed/.test(out.res._sent.body));
  check("cross-origin POST: next NOT called",           out.nextCalled === false);
}

async function testCorsExplicitSiteOriginAcceptsThatOrigin() {
  // Operator-supplied siteOrigin is the authoritative same-origin
  // signal — used behind TLS terminators where the framework can't
  // infer scheme from the socket.
  var mw = b.middleware.cors({
    origins:    [],
    siteOrigin: "https://wiki.example.com",
  });
  var req = _req({
    method:  "POST",
    headers: { host: "internal-wiki:8080", origin: "https://wiki.example.com" },
  });
  var out = await _drive(mw, req);
  check("explicit siteOrigin: matching Origin passes",  out.nextCalled === true);
}

async function testCorsExplicitSiteOriginRejectsInferredOrigin() {
  // Once siteOrigin is supplied, the framework's inferred-origin
  // check is replaced — the request's own Host/scheme is no longer
  // trusted as same-origin.
  var mw = b.middleware.cors({
    origins:    [],
    siteOrigin: "https://wiki.example.com",
  });
  var req = _req({
    method:  "POST",
    headers: { host: "localhost:8080", origin: "http://localhost:8080" },
  });
  var out = await _drive(mw, req);
  check("explicit siteOrigin: non-matching origin refused (403)",
        out.res._sent.statusCode === 403);
}

async function testCorsXForwardedProtoRespected() {
  // Behind a TLS terminator: socket is HTTP but Origin claims https.
  // X-Forwarded-Proto: https flips the inferred scheme so same-origin
  // detection works correctly.
  var mw = b.middleware.cors({ origins: [], refuseUnknown: true });
  var req = _req({
    method:  "POST",
    headers: {
      host:   "wiki.example.com",
      origin: "https://wiki.example.com",
      "x-forwarded-proto": "https",
    },
    socket:  { remoteAddress: "127.0.0.1", encrypted: false },
  });
  var out = await _drive(mw, req);
  check("X-Forwarded-Proto: https → same-origin pass-through",
        out.nextCalled === true);
}

async function testCorsNoOriginHeaderPassesThrough() {
  // GET requests typically have no Origin header (and same-origin
  // GETs definitely don't). Pass through untouched.
  var mw = b.middleware.cors({ origins: [], refuseUnknown: true });
  var req = _req({
    method:  "GET",
    url:     "/",
    headers: { host: "localhost:8080" },   // no origin
  });
  var out = await _drive(mw, req);
  check("no Origin header: next called (no 403)",       out.nextCalled === true);
}

function testCorsConfigValidationThrows() {
  // Tier A — bad config surfaces at create() not at request time.
  var threwOnBadOrigin = null;
  try { b.middleware.cors({ origins: [42] }); }
  catch (e) { threwOnBadOrigin = e; }
  check("bad origins[] entry throws CorsError",
        threwOnBadOrigin && threwOnBadOrigin.code === "cors/bad-origin");

  var threwOnBadSiteOriginType = null;
  try { b.middleware.cors({ siteOrigin: 42 }); }
  catch (e) { threwOnBadSiteOriginType = e; }
  check("non-string siteOrigin throws CorsError",
        threwOnBadSiteOriginType && threwOnBadSiteOriginType.code === "cors/bad-site-origin");

  var threwOnUnparseableSiteOrigin = null;
  try { b.middleware.cors({ siteOrigin: "not-a-url" }); }
  catch (e) { threwOnUnparseableSiteOrigin = e; }
  check("unparseable siteOrigin URL throws CorsError",
        threwOnUnparseableSiteOrigin && threwOnUnparseableSiteOrigin.code === "cors/bad-site-origin");

  // undefined / not-passed → no throw, default behaviour.
  var ok = b.middleware.cors({});
  check("no opts: returns a function (default behaviour)", typeof ok === "function");
}

async function run() {
  await testCorsSameOriginPostPassesWithoutAllowList();
  await testCorsCrossOriginPostStillRefused();
  await testCorsExplicitSiteOriginAcceptsThatOrigin();
  await testCorsExplicitSiteOriginRejectsInferredOrigin();
  await testCorsXForwardedProtoRespected();
  await testCorsNoOriginHeaderPassesThrough();
  testCorsConfigValidationThrows();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.message); process.exit(1); }
  );
}
