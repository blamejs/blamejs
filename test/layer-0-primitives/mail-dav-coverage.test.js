// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.mail.dav — CalDAV (RFC 4791) + CardDAV (RFC 6352) route-handler
 * error / defensive / adversarial branch coverage, driven over a REAL
 * localhost HTTP listener. The sibling mail-dav.test.js drives the
 * dispatch functions with mock req/res on the happy path; this file
 * mounts the returned Express-style handlers on a node:http server and
 * exercises them over a real TCP connection: method gating, actor
 * resolution, per-principal isolation, path-traversal refusal, every
 * verb's wrong-state / missing-arg / backend-throw / not-found branch,
 * PROPFIND / REPORT XML body parsing (valid + malformed), ETag
 * precondition failures, body-cap overflow (streamed + pre-parsed),
 * MKCALENDAR / MKCOL, and discovery redirects.
 *
 * A thin wrapper server simulates the operator's mount: it strips the
 * `/caldav` / `/carddav` prefix (as the operator's router would),
 * populates `req.user` / `req.actor` (as auth middleware would), and
 * optionally injects a pre-parsed `req.body` (as a body-parser would) —
 * so every _readBodyBytes branch is reachable over the wire.
 *
 * Run standalone: `node test/layer-0-primitives/mail-dav-coverage.test.js`
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

var http = require("node:http");

var C = b.constants;

// ---- valid PUT bodies ----------------------------------------------------
function _ical() {
  return "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//T//\r\n" +
         "BEGIN:VEVENT\r\nUID:t1@example.com\r\nDTSTAMP:20260101T120000Z\r\n" +
         "DTSTART:20260101T130000Z\r\nSUMMARY:Test\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
}
function _vcard() {
  return "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:Alice\r\nEMAIL:alice@example.com\r\nEND:VCARD\r\n";
}

// ---- configurable storage (stateful + per-method overrides) --------------
function _storage(over) {
  over = over || {};
  var cal = Object.create(null);
  var ab  = Object.create(null);

  function ensureCal(pid, cid) {
    if (!cal[pid]) cal[pid] = Object.create(null);
    if (cid && !cal[pid][cid]) {
      cal[pid][cid] = { displayName: cid, etag: "\"cal-" + cid + "\"", components: Object.create(null) };
    }
    return cal[pid];
  }
  function ensureBook(pid, bid) {
    if (!ab[pid]) ab[pid] = Object.create(null);
    if (bid && !ab[pid][bid]) {
      ab[pid][bid] = { displayName: bid, etag: "\"book-" + bid + "\"", cards: Object.create(null) };
    }
    return ab[pid];
  }

  var api = {
    calendar: {
      listCalendars: async function (pid) {
        var p = cal[pid];
        if (!p) return [];
        return Object.keys(p).map(function (k) { return { id: k, displayName: p[k].displayName, etag: p[k].etag }; });
      },
      getComponent: async function (pid, cid, comp) {
        if (!cal[pid] || !cal[pid][cid]) return null;
        var c = cal[pid][cid].components[comp];
        return c ? { id: comp, icalBytes: c.bytes, etag: c.etag, size: c.size } : null;
      },
      listComponents: async function (pid, cid) {
        if (!cal[pid] || !cal[pid][cid]) return [];
        return Object.keys(cal[pid][cid].components).map(function (k) {
          var c = cal[pid][cid].components[k];
          return { id: k, icalBytes: c.bytes, etag: c.etag, size: c.size };
        });
      },
      putComponent: async function (pid, cid, comp, bytes, conds) {
        ensureCal(pid, cid);
        var existing = cal[pid][cid].components[comp];
        if (conds && conds.ifMatch && existing && existing.etag !== conds.ifMatch) {
          var e = new Error("etag-mismatch"); e.code = "etag-mismatch"; throw e;
        }
        var nextEtag = "\"comp-" + comp + (existing ? "-v2" : "-v1") + "\"";
        cal[pid][cid].components[comp] = { bytes: bytes, etag: nextEtag, size: bytes.length };
        return { created: !existing, etag: nextEtag };
      },
      deleteComponent: async function (pid, cid, comp, conds) {
        if (!cal[pid] || !cal[pid][cid]) return { notFound: true };
        var c = cal[pid][cid].components[comp];
        if (!c) return { notFound: true };
        if (conds && conds.ifMatch && c.etag !== conds.ifMatch) {
          var e = new Error("etag-mismatch"); e.code = "etag-mismatch"; throw e;
        }
        delete cal[pid][cid].components[comp];
        return { deleted: true };
      },
      mkcalendar: async function (pid, cid, props) {
        ensureCal(pid, cid);
        if (props && props.displayname) cal[pid][cid].displayName = props.displayname;
        return { created: true };
      },
    },
    addressbook: {
      listAddressbooks: async function (pid) {
        var p = ab[pid];
        if (!p) return [];
        return Object.keys(p).map(function (k) { return { id: k, displayName: p[k].displayName, etag: p[k].etag }; });
      },
      getCard: async function (pid, bid, card) {
        if (!ab[pid] || !ab[pid][bid]) return null;
        var c = ab[pid][bid].cards[card];
        return c ? { id: card, vcardBytes: c.bytes, etag: c.etag, size: c.size } : null;
      },
      listCards: async function (pid, bid) {
        if (!ab[pid] || !ab[pid][bid]) return [];
        return Object.keys(ab[pid][bid].cards).map(function (k) {
          var c = ab[pid][bid].cards[k];
          return { id: k, vcardBytes: c.bytes, etag: c.etag, size: c.size };
        });
      },
      putCard: async function (pid, bid, card, bytes, conds) {
        ensureBook(pid, bid);
        var existing = ab[pid][bid].cards[card];
        if (conds && conds.ifMatch && existing && existing.etag !== conds.ifMatch) {
          var e = new Error("etag-mismatch"); e.code = "etag-mismatch"; throw e;
        }
        var nextEtag = "\"card-" + card + (existing ? "-v2" : "-v1") + "\"";
        ab[pid][bid].cards[card] = { bytes: bytes, etag: nextEtag, size: bytes.length };
        return { created: !existing, etag: nextEtag };
      },
      deleteCard: async function (pid, bid, card, conds) {
        if (!ab[pid] || !ab[pid][bid]) return { notFound: true };
        var c = ab[pid][bid].cards[card];
        if (!c) return { notFound: true };
        if (conds && conds.ifMatch && c.etag !== conds.ifMatch) {
          var e = new Error("etag-mismatch"); e.code = "etag-mismatch"; throw e;
        }
        delete ab[pid][bid].cards[card];
        return { deleted: true };
      },
      mkcol: async function (pid, bid, props) {
        ensureBook(pid, bid);
        if (props && props.displayname) ab[pid][bid].displayName = props.displayname;
        return { created: true };
      },
    },
    _seedCal: function (pid, cid, comp, bytes, etag) {
      ensureCal(pid, cid);
      cal[pid][cid].components[comp] = { bytes: bytes, etag: etag || "\"seed\"", size: bytes.length };
    },
    _seedCard: function (pid, bid, card, bytes, etag) {
      ensureBook(pid, bid);
      ab[pid][bid].cards[card] = { bytes: bytes, etag: etag || "\"seed\"", size: bytes.length };
    },
  };

  if (over.calendar) {
    Object.keys(over.calendar).forEach(function (k) {
      if (over.calendar[k] === null) delete api.calendar[k]; else api.calendar[k] = over.calendar[k];
    });
  }
  if (over.addressbook) {
    Object.keys(over.addressbook).forEach(function (k) {
      if (over.addressbook[k] === null) delete api.addressbook[k]; else api.addressbook[k] = over.addressbook[k];
    });
  }
  return api;
}

// ---- wrapper server: simulate operator mount + auth middleware -----------
//
// Headers understood by the wrapper (all optional):
//   x-test-actor:   "up:<id>" user.principalId | "ui:<id>" user.id |
//                   "un:<id>" user.username | "ap:<id>" actor.principalId |
//                   "empty"   user = {} (no usable field)
//   x-test-url-b64: base64 of an already-mount-stripped req.url (lets us
//                   drive _parsePath with bytes a raw request line can't
//                   carry — e.g. a NUL — while still travelling the wire)
//   x-test-body:    "buf" | "str" | "obj" | "bigbuf" | "bigstr" — inject a
//                   pre-parsed req.body (simulate a body-parser middleware)
function _mkServer(davOpts) {
  var dav = b.mail.dav.create(davOpts);
  var propfindXml = "<D:propfind xmlns:D=\"DAV:\"><D:allprop/></D:propfind>";
  var server = http.createServer(function (req, res) {
    var actor = req.headers["x-test-actor"];
    if (actor === "empty") {
      req.user = {};
    } else if (actor) {
      var kind = actor.slice(0, 2);
      var val  = actor.slice(3);
      if (kind === "up") req.user  = { principalId: val };
      else if (kind === "ui") req.user  = { id: val };
      else if (kind === "un") req.user  = { username: val };
      else if (kind === "ap") req.actor = { principalId: val };
    }

    var bodyMode = req.headers["x-test-body"];
    if (bodyMode === "buf")    req.body = Buffer.from(propfindXml, "utf8");
    else if (bodyMode === "str")    req.body = propfindXml;
    else if (bodyMode === "obj")    req.body = { hello: "world" };
    else if (bodyMode === "bigbuf") req.body = Buffer.alloc(40, 0x41);
    else if (bodyMode === "bigstr") req.body = new Array(41).join("A");

    var urlB64 = req.headers["x-test-url-b64"];
    var path = req.url;
    if (path.indexOf("/.well-known") === 0) { dav.discoveryHandler(req, res); return; }

    var prefix = path.indexOf("/carddav") === 0 ? "/carddav" : "/caldav";
    if (urlB64) req.url = Buffer.from(urlB64, "base64").toString("utf8");
    else        req.url = path.slice(prefix.length) || "/";

    if (prefix === "/carddav") dav.carddavHandler(req, res);
    else                       dav.caldavHandler(req, res);
  });
  return new Promise(function (resolve) {
    server.listen(0, "127.0.0.1", function () {
      resolve({ server: server, port: server.address().port });
    });
  });
}

function _close(s) {
  return new Promise(function (resolve) { s.server.close(function () { resolve(); }); });
}

function _req(port, opts) {
  return new Promise(function (resolve, reject) {
    var r = http.request({
      host: "127.0.0.1", port: port, method: opts.method,
      path: opts.path, headers: opts.headers || {},
    }, function (res) {
      var chunks = [];
      res.on("data", function (c) { chunks.push(c); });
      res.on("end", function () {
        resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString("utf8") });
      });
    });
    r.on("error", function (e) {
      // A body-cap overflow on the streamed path destroys the request
      // socket (safeBuffer.collectStream tears the stream down on
      // overflow), so the peer sees a reset rather than a clean status.
      // Surface it as a sentinel the caller can treat as "refused".
      if (opts.tolerateReset) { resolve({ status: 0, reset: true, headers: {}, body: "" }); return; }
      reject(e);
    });
    if (opts.body !== undefined && opts.body !== null) r.write(opts.body);
    r.end();
  });
}

// principal-scoped headers helper
function _as(principal, extra) {
  var h = { "x-test-actor": "up:" + principal };
  if (extra) Object.keys(extra).forEach(function (k) { h[k] = extra[k]; });
  return h;
}

// =====================================================================
// 1. Constructor opts — validation + defaults
// =====================================================================
function testCreateOpts() {
  var threwBad = false;
  try { b.mail.dav.create(); } catch (e) { threwBad = !!(e && e.code === "mail-dav/bad-opts"); }
  check("create() with no opts → mail-dav/bad-opts", threwBad);

  var threwNoStore = false;
  try { b.mail.dav.create({}); } catch (e) { threwNoStore = !!(e && e.code === "mail-dav/no-storage"); }
  check("create({}) → mail-dav/no-storage", threwNoStore);

  var threwStrStore = false;
  try { b.mail.dav.create({ storage: "nope" }); } catch (e) { threwStrStore = !!(e && e.code === "mail-dav/no-storage"); }
  check("create({storage:string}) → mail-dav/no-storage", threwStrStore);

  // valid finite positive maxRequestBodyBytes accepted
  var okCustom = b.mail.dav.create({ storage: _storage(), maxRequestBodyBytes: C.BYTES.kib(1), profile: "balanced", compliancePosture: "hipaa" });
  check("create() with custom maxRequestBodyBytes + posture builds", typeof okCustom.caldavHandler === "function");

  // invalid maxRequestBodyBytes (0 / negative / NaN / Infinity / non-number) → falls back to default
  [0, -5, NaN, Infinity, "8"].forEach(function (bad, i) {
    var built = b.mail.dav.create({ storage: _storage(), maxRequestBodyBytes: bad });
    check("create() with invalid maxRequestBodyBytes[" + i + "] falls back", typeof built.dispatchCaldav === "function");
  });

  check("create() exposes MailDavError", typeof b.mail.dav.MailDavError === "function");
}

// =====================================================================
// 2. Actor resolution (_actorPrincipalId) — every branch
// =====================================================================
async function testActorResolution() {
  var s = await _mkServer({ storage: _storage() });
  try {
    check("user.principalId string → OPTIONS 200",
      (await _req(s.port, { method: "OPTIONS", path: "/caldav/alice/", headers: { "x-test-actor": "up:alice" } })).status === 200);
    check("user.id fallback → OPTIONS 200",
      (await _req(s.port, { method: "OPTIONS", path: "/caldav/alice/", headers: { "x-test-actor": "ui:alice" } })).status === 200);
    check("user.username fallback → OPTIONS 200",
      (await _req(s.port, { method: "OPTIONS", path: "/caldav/alice/", headers: { "x-test-actor": "un:alice" } })).status === 200);
    check("req.actor.principalId fallback → OPTIONS 200",
      (await _req(s.port, { method: "OPTIONS", path: "/caldav/alice/", headers: { "x-test-actor": "ap:alice" } })).status === 200);
    check("actor object with no usable field → 401",
      (await _req(s.port, { method: "OPTIONS", path: "/caldav/alice/", headers: { "x-test-actor": "empty" } })).status === 401);
    check("no actor populated → 401",
      (await _req(s.port, { method: "OPTIONS", path: "/caldav/alice/" })).status === 401);
  } finally { await _close(s); }
}

// =====================================================================
// 3. CalDAV dispatch — method gate, state, isolation, traversal
// =====================================================================
async function testCaldavDispatch() {
  var s = await _mkServer({ storage: _storage() });
  try {
    check("unknown method (POST) → 405",
      (await _req(s.port, { method: "POST", path: "/caldav/alice/cal1/c", headers: _as("alice") })).status === 405);
    check("no actor → 401 (GET)",
      (await _req(s.port, { method: "GET", path: "/caldav/alice/cal1/c" })).status === 401);
    check("cross-principal → 403",
      (await _req(s.port, { method: "GET", path: "/caldav/bob/cal1/c", headers: _as("alice") })).status === 403);
    check("principal-less non-PROPFIND → 400",
      (await _req(s.port, { method: "GET", path: "/caldav/", headers: _as("alice") })).status === 400);
    var rootPf = await _req(s.port, { method: "PROPFIND", path: "/caldav/", headers: _as("alice", { depth: "0" }) });
    check("principal-less PROPFIND allowed → 207", rootPf.status === 207);

    // traversal sub-branches
    check("literal .. → 400",
      (await _req(s.port, { method: "GET", path: "/caldav/alice/cal1/../x", headers: _as("alice") })).status === 400);
    check("%2e%2e → 400",
      (await _req(s.port, { method: "GET", path: "/caldav/alice/%2e%2e/x", headers: _as("alice") })).status === 400);
    // MIXED encoding: neither a literal ".." nor "%2e%2e", but decodes to ".." —
    // must be refused post-decode (the path-traversal HIGH: raw-only guard bypass).
    check("mixed .%2e → 400 (decode-then-validate)",
      (await _req(s.port, { method: "GET", path: "/caldav/alice/.%2e", headers: _as("alice") })).status === 400);
    check("mixed %2e. → 400 (decode-then-validate)",
      (await _req(s.port, { method: "GET", path: "/caldav/alice/%2e.", headers: _as("alice") })).status === 400);
    check("%00 → 400",
      (await _req(s.port, { method: "GET", path: "/caldav/alice/%00/x", headers: _as("alice") })).status === 400);
    check("malformed %-encoding → 400",
      (await _req(s.port, { method: "GET", path: "/caldav/alice/%zz/x", headers: _as("alice") })).status === 400);
    // raw NUL byte in the (mount-stripped) path — carried as base64 over the wire
    var nulUrl = Buffer.from("/alice/a b/x", "utf8").toString("base64");
    check("raw NUL byte in path → 400",
      (await _req(s.port, { method: "GET", path: "/caldav/x", headers: _as("alice", { "x-test-url-b64": nulUrl }) })).status === 400);

    // query-string strip: GET a missing component with a ?query → 404 (path parsed, query dropped)
    check("query string dropped before parse → 404 (missing comp)",
      (await _req(s.port, { method: "GET", path: "/caldav/alice/cal1/missing?a=b", headers: _as("alice") })).status === 404);
  } finally { await _close(s); }

  // no calendar storage configured → 501
  var full = _storage();
  var sNoCal = await _mkServer({ storage: { addressbook: full.addressbook } });
  try {
    check("no calendar backend → 501",
      (await _req(sNoCal.port, { method: "GET", path: "/caldav/alice/cal1/c", headers: _as("alice") })).status === 501);
  } finally { await _close(sNoCal); }

  // storage throws a generic (non-etag) error → dispatch catch → 500
  var sThrow = await _mkServer({ storage: _storage({ calendar: { listCalendars: async function () { throw new Error("backend boom"); } } }) });
  try {
    check("backend generic throw → 500",
      (await _req(sThrow.port, { method: "PROPFIND", path: "/caldav/alice/", headers: _as("alice", { depth: "1" }) })).status === 500);
  } finally { await _close(sThrow); }
}

// =====================================================================
// 4. CalDAV PROPFIND — depth / collection / single / prop-list / malformed
// =====================================================================
async function testCaldavPropfind() {
  var storage = _storage();
  storage._seedCal("alice", "cal1", "comp1", Buffer.from(_ical(), "utf8"), "\"e1\"");
  var s = await _mkServer({ storage: storage });
  try {
    check("PROPFIND principal depth 0 → 207 (self only)",
      (await _req(s.port, { method: "PROPFIND", path: "/caldav/alice", headers: _as("alice", { depth: "0" }) })).status === 207);

    var d1 = await _req(s.port, { method: "PROPFIND", path: "/caldav/alice", headers: _as("alice", { depth: "1" }) });
    check("PROPFIND principal depth 1 → lists calendars", d1.status === 207 && /cal1/.test(d1.body));

    check("PROPFIND calendar collection depth 0 → 207",
      (await _req(s.port, { method: "PROPFIND", path: "/caldav/alice/cal1/", headers: _as("alice", { depth: "0" }) })).status === 207);

    var coll = await _req(s.port, { method: "PROPFIND", path: "/caldav/alice/cal1/", headers: _as("alice", { depth: "1" }) });
    check("PROPFIND calendar collection depth 1 → lists components", coll.status === 207 && /comp1/.test(coll.body));

    var single = await _req(s.port, { method: "PROPFIND", path: "/caldav/alice/cal1/comp1", headers: _as("alice", { depth: "0" }) });
    check("PROPFIND single component → getetag present", single.status === 207 && /getetag/.test(single.body));

    check("PROPFIND missing component → 207 with 404 propstat",
      /404/.test((await _req(s.port, { method: "PROPFIND", path: "/caldav/alice/cal1/nope", headers: _as("alice", { depth: "0" }) })).body));

    // explicit prop list (filters _renderProps) + request calendar-data
    var propList =
      "<?xml version=\"1.0\"?><D:propfind xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\">" +
      "<D:prop><D:getetag/><D:displayname/><C:calendar-data/></D:prop></D:propfind>";
    var withProps = await _req(s.port, { method: "PROPFIND", path: "/caldav/alice/cal1/", headers: _as("alice", { depth: "1" }), body: propList });
    check("PROPFIND with prop list → calendar-data embedded", withProps.status === 207 && /calendar-data/.test(withProps.body));

    // malformed XML body → client fault → 400 (like MKCALENDAR/MKCOL)
    check("PROPFIND malformed XML body → 400",
      (await _req(s.port, { method: "PROPFIND", path: "/caldav/alice/cal1/", headers: _as("alice", { depth: "1" }), body: "<not-xml" })).status === 400);
  } finally { await _close(s); }
}

// =====================================================================
// 5. CalDAV REPORT — multiget / query / unsupported / empty / malformed
// =====================================================================
async function testCaldavReport() {
  var storage = _storage();
  var bytes = Buffer.from(_ical(), "utf8");
  storage._seedCal("alice", "cal1", "comp1", bytes, "\"e1\"");
  storage._seedCal("alice", "cal1", "comp2", bytes, "\"e2\"");
  var s = await _mkServer({ storage: storage });
  try {
    // multiget: one present, one missing, one cross-principal, one traversal-rejected href
    var mg =
      "<C:calendar-multiget xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\">" +
      "<D:prop><D:getetag/><C:calendar-data/></D:prop>" +
      "<D:href>/alice/cal1/comp1</D:href>" +
      "<D:href>/alice/cal1/missing</D:href>" +
      "<D:href>/bob/cal1/comp1</D:href>" +
      "<D:href>/alice/../x</D:href>" +
      "</C:calendar-multiget>";
    var mgr = await _req(s.port, { method: "REPORT", path: "/caldav/alice/cal1/", headers: _as("alice"), body: mg });
    check("REPORT multiget → 207", mgr.status === 207);
    check("REPORT multiget present href → 200 comp1", /comp1/.test(mgr.body));
    check("REPORT multiget missing href → 404", /404/.test(mgr.body));
    check("REPORT multiget cross-principal + traversal href → 403", /403/.test(mgr.body));

    // calendar-query with explicit prop
    var cq =
      "<C:calendar-query xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\">" +
      "<D:prop><D:getetag/></D:prop><C:filter/></C:calendar-query>";
    var cqr = await _req(s.port, { method: "REPORT", path: "/caldav/alice/cal1/", headers: _as("alice"), body: cq });
    check("REPORT calendar-query → 207 with rows", cqr.status === 207 && /comp1/.test(cqr.body) && /comp2/.test(cqr.body));

    check("REPORT unsupported kind → 422",
      (await _req(s.port, { method: "REPORT", path: "/caldav/alice/cal1/", headers: _as("alice"),
        body: "<C:free-busy-query xmlns:C=\"urn:ietf:params:xml:ns:caldav\"/>" })).status === 422);

    check("REPORT empty body → 400 (client fault)",
      (await _req(s.port, { method: "REPORT", path: "/caldav/alice/cal1/", headers: _as("alice"), body: "" })).status === 400);
    check("REPORT malformed XML → 400 (client fault)",
      (await _req(s.port, { method: "REPORT", path: "/caldav/alice/cal1/", headers: _as("alice"), body: "<broken" })).status === 400);
  } finally { await _close(s); }
}

// =====================================================================
// 6. CalDAV GET — arg gating + found + not-found + etag-less
// =====================================================================
async function testCaldavGet() {
  var storage = _storage();
  var bytes = Buffer.from(_ical(), "utf8");
  storage._seedCal("alice", "cal1", "comp1", bytes, "\"e1\"");
  var s = await _mkServer({ storage: storage });
  try {
    check("GET on collection (no component) → 404",
      (await _req(s.port, { method: "GET", path: "/caldav/alice/cal1/", headers: _as("alice") })).status === 404);
    var g = await _req(s.port, { method: "GET", path: "/caldav/alice/cal1/comp1", headers: _as("alice") });
    check("GET component → 200 + body + ETag", g.status === 200 && g.headers["etag"] === "\"e1\"" && g.body === bytes.toString("utf8"));
    check("GET content-type text/calendar", /text\/calendar/.test(g.headers["content-type"]));
    check("GET missing component → 404",
      (await _req(s.port, { method: "GET", path: "/caldav/alice/cal1/gone", headers: _as("alice") })).status === 404);
  } finally { await _close(s); }

  // component without etag → no ETag header
  var sNoEtag = await _mkServer({ storage: _storage({ calendar: {
    getComponent: async function (pid, cid, comp) { return { id: comp, icalBytes: Buffer.from(_ical(), "utf8") }; },
  } }) });
  try {
    var ge = await _req(sNoEtag.port, { method: "GET", path: "/caldav/alice/cal1/x", headers: _as("alice") });
    check("GET etag-less component → 200, no ETag header", ge.status === 200 && ge.headers["etag"] === undefined);
  } finally { await _close(sNoEtag); }
}

// =====================================================================
// 7. CalDAV PUT — arg gating, ical refusal, created/updated, etag, throw
// =====================================================================
async function testCaldavPut() {
  var storage = _storage();
  var s = await _mkServer({ storage: storage });
  try {
    check("PUT on collection (no component) → 400",
      (await _req(s.port, { method: "PUT", path: "/caldav/alice/cal1/", headers: _as("alice"), body: _ical() })).status === 400);

    // RRULE COUNT bomb → safeIcal refuses → 415
    var bomb = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//B//\r\nBEGIN:VEVENT\r\nUID:b@x\r\n" +
      "DTSTAMP:20260101T120000Z\r\nDTSTART:20260101T130000Z\r\nRRULE:FREQ=DAILY;COUNT=999999\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
    check("PUT invalid iCal (RRULE bomb) → 415",
      (await _req(s.port, { method: "PUT", path: "/caldav/alice/cal1/bomb", headers: _as("alice"), body: bomb })).status === 415);

    var created = await _req(s.port, { method: "PUT", path: "/caldav/alice/cal1/comp1", headers: _as("alice"), body: _ical() });
    check("PUT new component → 201 + ETag", created.status === 201 && typeof created.headers["etag"] === "string");

    var updated = await _req(s.port, { method: "PUT", path: "/caldav/alice/cal1/comp1", headers: _as("alice"), body: _ical() });
    check("PUT existing component (no If-Match) → 204", updated.status === 204);

    // If-Match mismatch → putComponent throws etag-mismatch → 412
    check("PUT If-Match mismatch → 412",
      (await _req(s.port, { method: "PUT", path: "/caldav/alice/cal1/comp1", headers: _as("alice", { "if-match": "\"wrong\"" }), body: _ical() })).status === 412);
  } finally { await _close(s); }

  // putComponent throws a generic error → rethrow → 500
  var sThrow = await _mkServer({ storage: _storage({ calendar: {
    putComponent: async function () { throw new Error("disk full"); },
  } }) });
  try {
    check("PUT backend generic throw → 500",
      (await _req(sThrow.port, { method: "PUT", path: "/caldav/alice/cal1/x", headers: _as("alice"), body: _ical() })).status === 500);
  } finally { await _close(sThrow); }

  // putComponent returns no etag → 201 without ETag header
  var sNoEtag = await _mkServer({ storage: _storage({ calendar: {
    putComponent: async function () { return { created: true }; },
  } }) });
  try {
    var r = await _req(sNoEtag.port, { method: "PUT", path: "/caldav/alice/cal1/x", headers: _as("alice"), body: _ical() });
    check("PUT etag-less result → 201, no ETag header", r.status === 201 && r.headers["etag"] === undefined);
  } finally { await _close(sNoEtag); }
}

// =====================================================================
// 8. CalDAV DELETE — arg gating, success, not-found, etag, throw
// =====================================================================
async function testCaldavDelete() {
  var storage = _storage();
  storage._seedCal("alice", "cal1", "comp1", Buffer.from(_ical(), "utf8"), "\"e1\"");
  var s = await _mkServer({ storage: storage });
  try {
    check("DELETE on collection (no component) → 400",
      (await _req(s.port, { method: "DELETE", path: "/caldav/alice/cal1/", headers: _as("alice") })).status === 400);
    check("DELETE If-Match mismatch → 412",
      (await _req(s.port, { method: "DELETE", path: "/caldav/alice/cal1/comp1", headers: _as("alice", { "if-match": "\"nope\"" }) })).status === 412);
    check("DELETE existing → 204",
      (await _req(s.port, { method: "DELETE", path: "/caldav/alice/cal1/comp1", headers: _as("alice") })).status === 204);
    check("DELETE missing → 404",
      (await _req(s.port, { method: "DELETE", path: "/caldav/alice/cal1/comp1", headers: _as("alice") })).status === 404);
  } finally { await _close(s); }

  var sThrow = await _mkServer({ storage: _storage({ calendar: {
    deleteComponent: async function () { throw new Error("io error"); },
  } }) });
  try {
    check("DELETE backend generic throw → 500",
      (await _req(sThrow.port, { method: "DELETE", path: "/caldav/alice/cal1/x", headers: _as("alice") })).status === 500);
  } finally { await _close(sThrow); }
}

// =====================================================================
// 9. MKCALENDAR — arg gating, unsupported, empty/valid/malformed body
// =====================================================================
async function testMkcalendar() {
  var s = await _mkServer({ storage: _storage() });
  try {
    check("MKCALENDAR without calendar segment → 400",
      (await _req(s.port, { method: "MKCALENDAR", path: "/caldav/alice/", headers: _as("alice") })).status === 400);
    check("MKCALENDAR empty body → 201",
      (await _req(s.port, { method: "MKCALENDAR", path: "/caldav/alice/newcal/", headers: _as("alice") })).status === 201);
    var body =
      "<C:mkcalendar xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\">" +
      "<D:set><D:prop><D:displayname>Personal</D:displayname></D:prop></D:set></C:mkcalendar>";
    check("MKCALENDAR with prop body → 201",
      (await _req(s.port, { method: "MKCALENDAR", path: "/caldav/alice/personal/", headers: _as("alice"), body: body })).status === 201);
    check("MKCALENDAR malformed body → 400",
      (await _req(s.port, { method: "MKCALENDAR", path: "/caldav/alice/broke/", headers: _as("alice"), body: "<nope" })).status === 400);
  } finally { await _close(s); }

  // mkcalendar backend absent → 501
  var sNoMk = await _mkServer({ storage: _storage({ calendar: { mkcalendar: null } }) });
  try {
    check("MKCALENDAR with no backend fn → 501",
      (await _req(sNoMk.port, { method: "MKCALENDAR", path: "/caldav/alice/x/", headers: _as("alice") })).status === 501);
  } finally { await _close(sNoMk); }

  // mkcalendar returns not-created → 200
  var s200 = await _mkServer({ storage: _storage({ calendar: { mkcalendar: async function () { return { created: false }; } } }) });
  try {
    check("MKCALENDAR returns not-created → 200",
      (await _req(s200.port, { method: "MKCALENDAR", path: "/caldav/alice/x/", headers: _as("alice") })).status === 200);
  } finally { await _close(s200); }
}

// =====================================================================
// 10. _readBodyBytes — pre-parsed req.body branches + cap overflow
// =====================================================================
async function testReadBody() {
  var s = await _mkServer({ storage: _storage() });
  try {
    check("pre-parsed Buffer body within cap → PROPFIND 207",
      (await _req(s.port, { method: "PROPFIND", path: "/caldav/alice/", headers: _as("alice", { depth: "0", "x-test-body": "buf" }) })).status === 207);
    check("pre-parsed string body within cap → PROPFIND 207",
      (await _req(s.port, { method: "PROPFIND", path: "/caldav/alice/", headers: _as("alice", { depth: "0", "x-test-body": "str" }) })).status === 207);
    // object body → JSON.stringify'd → not valid XML → parser refuses → 400 (client fault)
    check("pre-parsed object body → JSON bytes → 400",
      (await _req(s.port, { method: "PROPFIND", path: "/caldav/alice/cal1/", headers: _as("alice", { depth: "1", "x-test-body": "obj" }) })).status === 400);
  } finally { await _close(s); }

  // tiny cap: pre-parsed oversize Buffer / string → reject → 500 ; streamed oversize → 500
  var sCap = await _mkServer({ storage: _storage(), maxRequestBodyBytes: C.BYTES.bytes(16) });
  try {
    check("pre-parsed Buffer over cap → 500",
      (await _req(sCap.port, { method: "PROPFIND", path: "/caldav/alice/", headers: _as("alice", { depth: "0", "x-test-body": "bigbuf" }) })).status === 500);
    check("pre-parsed string over cap → 500",
      (await _req(sCap.port, { method: "PROPFIND", path: "/caldav/alice/", headers: _as("alice", { depth: "0", "x-test-body": "bigstr" }) })).status === 500);
    // Streamed overflow tears down the request socket, so the peer sees
    // either a 500 (if the refusal races ahead of the destroy) or a reset.
    var streamed = await _req(sCap.port, { method: "PROPFIND", path: "/caldav/alice/", headers: _as("alice", { depth: "0" }), body: new Array(200).join("x"), tolerateReset: true });
    check("streamed body over cap → refused (500 or reset)", streamed.status === 500 || streamed.reset === true);
  } finally { await _close(sCap); }
}

// =====================================================================
// 11. _bufToText — string + non-buffer/non-string branches (via REPORT)
// =====================================================================
async function testBufToText() {
  // icalBytes as a plain string → _bufToText string branch
  var sStr = await _mkServer({ storage: _storage({ calendar: {
    getComponent: async function (pid, cid, comp) { return { id: comp, icalBytes: _ical(), etag: "\"s\"", size: 10 }; },
  } }) });
  try {
    var mg = "<C:calendar-multiget xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\">" +
      "<D:prop><C:calendar-data/></D:prop><D:href>/alice/cal1/comp1</D:href></C:calendar-multiget>";
    var r = await _req(sStr.port, { method: "REPORT", path: "/caldav/alice/cal1/", headers: _as("alice"), body: mg });
    check("REPORT with string icalBytes → 207 (bufToText string branch)", r.status === 207 && /VCALENDAR/.test(r.body));
  } finally { await _close(sStr); }

  // icalBytes as a number → _bufToText else (String()) branch
  var sNum = await _mkServer({ storage: _storage({ calendar: {
    getComponent: async function (pid, cid, comp) { return { id: comp, icalBytes: 12345, etag: "\"n\"", size: 5 }; },
  } }) });
  try {
    var mg2 = "<C:calendar-multiget xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\">" +
      "<D:prop><C:calendar-data/></D:prop><D:href>/alice/cal1/comp1</D:href></C:calendar-multiget>";
    var r2 = await _req(sNum.port, { method: "REPORT", path: "/caldav/alice/cal1/", headers: _as("alice"), body: mg2 });
    check("REPORT with numeric icalBytes → 207 (bufToText else branch)", r2.status === 207 && /12345/.test(r2.body));
  } finally { await _close(sNum); }
}

// =====================================================================
// 12. CardDAV dispatch — method gate, state, isolation, verbs
// =====================================================================
async function testCarddavDispatch() {
  var storage = _storage();
  var bytes = Buffer.from(_vcard(), "utf8");
  storage._seedCard("alice", "book1", "card1", bytes, "\"v1\"");
  storage._seedCard("alice", "book1", "card2", bytes, "\"v2\"");
  var s = await _mkServer({ storage: storage });
  try {
    var opt = await _req(s.port, { method: "OPTIONS", path: "/carddav/alice/", headers: _as("alice") });
    check("CardDAV OPTIONS → 200 + addressbook DAV header", opt.status === 200 && /addressbook/.test(opt.headers["dav"]));
    check("CardDAV unknown method → 405",
      (await _req(s.port, { method: "PATCH", path: "/carddav/alice/book1/card1", headers: _as("alice") })).status === 405);
    check("CardDAV no actor → 401",
      (await _req(s.port, { method: "GET", path: "/carddav/alice/book1/card1" })).status === 401);
    check("CardDAV cross-principal → 403",
      (await _req(s.port, { method: "GET", path: "/carddav/bob/book1/card1", headers: _as("alice") })).status === 403);
    check("CardDAV principal-less non-PROPFIND → 400",
      (await _req(s.port, { method: "GET", path: "/carddav/", headers: _as("alice") })).status === 400);
    check("CardDAV traversal → 400",
      (await _req(s.port, { method: "GET", path: "/carddav/alice/book1/../x", headers: _as("alice") })).status === 400);

    // PROPFIND variants
    check("CardDAV PROPFIND principal depth 0 → 207",
      (await _req(s.port, { method: "PROPFIND", path: "/carddav/alice", headers: _as("alice", { depth: "0" }) })).status === 207);
    var books = await _req(s.port, { method: "PROPFIND", path: "/carddav/alice", headers: _as("alice", { depth: "1" }) });
    check("CardDAV PROPFIND principal depth 1 → lists books", books.status === 207 && /book1/.test(books.body));
    check("CardDAV PROPFIND book collection depth 0 → 207",
      (await _req(s.port, { method: "PROPFIND", path: "/carddav/alice/book1/", headers: _as("alice", { depth: "0" }) })).status === 207);
    var cards = await _req(s.port, { method: "PROPFIND", path: "/carddav/alice/book1/", headers: _as("alice", { depth: "1" }) });
    check("CardDAV PROPFIND book collection depth 1 → lists cards", cards.status === 207 && /card1/.test(cards.body));
    var singleCard = await _req(s.port, { method: "PROPFIND", path: "/carddav/alice/book1/card1", headers: _as("alice", { depth: "0" }) });
    check("CardDAV PROPFIND single card → 207", singleCard.status === 207 && /getetag/.test(singleCard.body));
    check("CardDAV PROPFIND missing card → 404 propstat",
      /404/.test((await _req(s.port, { method: "PROPFIND", path: "/carddav/alice/book1/nope", headers: _as("alice", { depth: "0" }) })).body));

    // REPORT multiget + query + unsupported
    var mg = "<A:addressbook-multiget xmlns:D=\"DAV:\" xmlns:A=\"urn:ietf:params:xml:ns:carddav\">" +
      "<D:prop><D:getetag/><A:address-data/></D:prop>" +
      "<D:href>/alice/book1/card1</D:href>" +
      "<D:href>/alice/book1/missing</D:href>" +
      "<D:href>/bob/book1/card1</D:href></A:addressbook-multiget>";
    var mgr = await _req(s.port, { method: "REPORT", path: "/carddav/alice/book1/", headers: _as("alice"), body: mg });
    check("CardDAV REPORT multiget → 207 present/missing/cross",
      mgr.status === 207 && /card1/.test(mgr.body) && /404/.test(mgr.body) && /403/.test(mgr.body));
    var aq = "<A:addressbook-query xmlns:D=\"DAV:\" xmlns:A=\"urn:ietf:params:xml:ns:carddav\">" +
      "<D:prop><D:getetag/></D:prop><A:filter/></A:addressbook-query>";
    check("CardDAV REPORT addressbook-query → 207",
      (await _req(s.port, { method: "REPORT", path: "/carddav/alice/book1/", headers: _as("alice"), body: aq })).status === 207);
    check("CardDAV REPORT unsupported kind → 422",
      (await _req(s.port, { method: "REPORT", path: "/carddav/alice/book1/", headers: _as("alice"),
        body: "<A:bogus-report xmlns:A=\"urn:ietf:params:xml:ns:carddav\"/>" })).status === 422);

    // GET
    check("CardDAV GET collection (no card) → 404",
      (await _req(s.port, { method: "GET", path: "/carddav/alice/book1/", headers: _as("alice") })).status === 404);
    var gc = await _req(s.port, { method: "GET", path: "/carddav/alice/book1/card1", headers: _as("alice") });
    check("CardDAV GET card → 200 text/vcard + body", gc.status === 200 && /text\/vcard/.test(gc.headers["content-type"]) && gc.body === bytes.toString("utf8"));
    check("CardDAV GET missing card → 404",
      (await _req(s.port, { method: "GET", path: "/carddav/alice/book1/gone", headers: _as("alice") })).status === 404);
  } finally { await _close(s); }

  // no addressbook storage → 501
  var full = _storage();
  var sNoCard = await _mkServer({ storage: { calendar: full.calendar } });
  try {
    check("CardDAV no addressbook backend → 501",
      (await _req(sNoCard.port, { method: "GET", path: "/carddav/alice/book1/c", headers: _as("alice") })).status === 501);
  } finally { await _close(sNoCard); }

  // dispatch catch → 500 (backend throw)
  var sThrow = await _mkServer({ storage: _storage({ addressbook: { listAddressbooks: async function () { throw new Error("boom"); } } }) });
  try {
    check("CardDAV backend generic throw → 500",
      (await _req(sThrow.port, { method: "PROPFIND", path: "/carddav/alice", headers: _as("alice", { depth: "1" }) })).status === 500);
  } finally { await _close(sThrow); }
}

// =====================================================================
// 13. CardDAV PUT / DELETE / MKCOL — arg gating, refusal, etag, throw
// =====================================================================
async function testCarddavWrites() {
  var storage = _storage();
  storage._seedCard("alice", "book1", "card1", Buffer.from(_vcard(), "utf8"), "\"v1\"");
  var s = await _mkServer({ storage: storage });
  try {
    check("CardDAV PUT collection (no card) → 400",
      (await _req(s.port, { method: "PUT", path: "/carddav/alice/book1/", headers: _as("alice"), body: _vcard() })).status === 400);
    check("CardDAV PUT invalid vCard → 415",
      (await _req(s.port, { method: "PUT", path: "/carddav/alice/book1/bad", headers: _as("alice"), body: "BEGIN:VCARD\r\nVERSION:4.0\r\nBOGUSPROP:x\r\nEND:VCARD\r\n" })).status === 415);
    check("CardDAV PUT new card → 201",
      (await _req(s.port, { method: "PUT", path: "/carddav/alice/book1/card2", headers: _as("alice"), body: _vcard() })).status === 201);
    check("CardDAV PUT existing card → 204",
      (await _req(s.port, { method: "PUT", path: "/carddav/alice/book1/card2", headers: _as("alice"), body: _vcard() })).status === 204);
    check("CardDAV PUT If-Match mismatch → 412",
      (await _req(s.port, { method: "PUT", path: "/carddav/alice/book1/card1", headers: _as("alice", { "if-match": "\"wrong\"" }), body: _vcard() })).status === 412);

    check("CardDAV DELETE collection (no card) → 400",
      (await _req(s.port, { method: "DELETE", path: "/carddav/alice/book1/", headers: _as("alice") })).status === 400);
    check("CardDAV DELETE If-Match mismatch → 412",
      (await _req(s.port, { method: "DELETE", path: "/carddav/alice/book1/card1", headers: _as("alice", { "if-match": "\"no\"" }) })).status === 412);
    check("CardDAV DELETE existing → 204",
      (await _req(s.port, { method: "DELETE", path: "/carddav/alice/book1/card1", headers: _as("alice") })).status === 204);
    check("CardDAV DELETE missing → 404",
      (await _req(s.port, { method: "DELETE", path: "/carddav/alice/book1/card1", headers: _as("alice") })).status === 404);

    check("MKCOL without book segment → 400",
      (await _req(s.port, { method: "MKCOL", path: "/carddav/alice/", headers: _as("alice") })).status === 400);
    check("MKCOL empty body → 201",
      (await _req(s.port, { method: "MKCOL", path: "/carddav/alice/newbook/", headers: _as("alice") })).status === 201);
    var mkbody = "<D:mkcol xmlns:D=\"DAV:\"><D:set><D:prop><D:displayname>Contacts</D:displayname></D:prop></D:set></D:mkcol>";
    check("MKCOL with prop body → 201",
      (await _req(s.port, { method: "MKCOL", path: "/carddav/alice/contacts/", headers: _as("alice"), body: mkbody })).status === 201);
    check("MKCOL malformed body → 400",
      (await _req(s.port, { method: "MKCOL", path: "/carddav/alice/broke/", headers: _as("alice"), body: "<nope" })).status === 400);
  } finally { await _close(s); }

  // PUT / DELETE backend generic throw → 500
  var sPutThrow = await _mkServer({ storage: _storage({ addressbook: { putCard: async function () { throw new Error("io"); } } }) });
  try {
    check("CardDAV PUT backend throw → 500",
      (await _req(sPutThrow.port, { method: "PUT", path: "/carddav/alice/book1/x", headers: _as("alice"), body: _vcard() })).status === 500);
  } finally { await _close(sPutThrow); }

  var sDelThrow = await _mkServer({ storage: _storage({ addressbook: { deleteCard: async function () { throw new Error("io"); } } }) });
  try {
    check("CardDAV DELETE backend throw → 500",
      (await _req(sDelThrow.port, { method: "DELETE", path: "/carddav/alice/book1/x", headers: _as("alice") })).status === 500);
  } finally { await _close(sDelThrow); }

  // MKCOL backend absent → 501 ; returns not-created → 200
  var sNoMkcol = await _mkServer({ storage: _storage({ addressbook: { mkcol: null } }) });
  try {
    check("MKCOL with no backend fn → 501",
      (await _req(sNoMkcol.port, { method: "MKCOL", path: "/carddav/alice/x/", headers: _as("alice") })).status === 501);
  } finally { await _close(sNoMkcol); }

  var sMk200 = await _mkServer({ storage: _storage({ addressbook: { mkcol: async function () { return { created: false }; } } }) });
  try {
    check("MKCOL returns not-created → 200",
      (await _req(sMk200.port, { method: "MKCOL", path: "/carddav/alice/x/", headers: _as("alice") })).status === 200);
  } finally { await _close(sMk200); }

  // etag-less putCard result → 201 without ETag
  var sNoEtag = await _mkServer({ storage: _storage({ addressbook: { putCard: async function () { return { created: true }; } } }) });
  try {
    var r = await _req(sNoEtag.port, { method: "PUT", path: "/carddav/alice/book1/x", headers: _as("alice"), body: _vcard() });
    check("CardDAV PUT etag-less result → 201, no ETag", r.status === 201 && r.headers["etag"] === undefined);
  } finally { await _close(sNoEtag); }
}

// =====================================================================
// 14. discovery redirects — caldav / carddav / custom base URLs
// =====================================================================
async function testDiscovery() {
  var s = await _mkServer({ storage: _storage() });
  try {
    var cal = await _req(s.port, { method: "GET", path: "/.well-known/caldav" });
    check("discovery caldav → 301 /caldav/", cal.status === 301 && cal.headers["location"] === "/caldav/");
    var card = await _req(s.port, { method: "GET", path: "/.well-known/carddav" });
    check("discovery carddav → 301 /carddav/", card.status === 301 && card.headers["location"] === "/carddav/");
  } finally { await _close(s); }

  var sCustom = await _mkServer({ storage: _storage(), caldavBaseUrl: "/dav/cal/", carddavBaseUrl: "/dav/card/" });
  try {
    check("discovery caldav custom base → 301 /dav/cal/",
      (await _req(sCustom.port, { method: "GET", path: "/.well-known/caldav" })).headers["location"] === "/dav/cal/");
    check("discovery carddav custom base → 301 /dav/card/",
      (await _req(sCustom.port, { method: "GET", path: "/.well-known/carddav" })).headers["location"] === "/dav/card/");
  } finally { await _close(sCustom); }
}

async function _drainTcpHandles() {
  if (typeof process.getActiveResourcesInfo !== "function") return;
  await helpers.waitUntil(function () {
    return process.getActiveResourcesInfo().filter(function (t) {
      return t === "TCPSocketWrap" || t === "TCPServerWrap";
    }).length === 0;
  }, { timeoutMs: 5000, label: "mail-dav-coverage: TCP handle drain after run" });
}

async function run() {
  var wtt = helpers.withTestTimeout;
  try {
    testCreateOpts();
    await wtt("actor resolution",   testActorResolution);
    await wtt("caldav dispatch",    testCaldavDispatch);
    await wtt("caldav propfind",    testCaldavPropfind);
    await wtt("caldav report",      testCaldavReport);
    await wtt("caldav get",         testCaldavGet);
    await wtt("caldav put",         testCaldavPut);
    await wtt("caldav delete",      testCaldavDelete);
    await wtt("mkcalendar",         testMkcalendar);
    await wtt("read body",          testReadBody);
    await wtt("buf to text",        testBufToText);
    await wtt("carddav dispatch",   testCarddavDispatch);
    await wtt("carddav writes",     testCarddavWrites);
    await wtt("discovery",          testDiscovery);
  } finally {
    await _drainTcpHandles();
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("mail-dav-coverage OK — " + helpers.getChecks() + " checks"); },
    function (e) { console.error(e && e.stack || e); process.exit(1); }
  );
}
