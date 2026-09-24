// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The JMAP limits the session advertises are the limits the listener applies.
 *
 * `maxObjectsInGet` and `maxObjectsInSet` sat in every guard profile and in
 * the listener's documentation, and no code read either one: under the strict
 * profile, whose limit is 500, an `Email/get` handler received 250,000 ids and
 * an `Email/set` handler 250,000 destroy ids in one request. RFC 8620 section
 * 5.1 and section 5.3 answer both with `requestTooLarge`, and section 8.5
 * requires the limits to exist. A string body was measured against the
 * profile's 10 MiB `maxSizeRequest` and then parsed with the 1 MiB default of
 * `b.safeJson.parse`, so a valid 1.17 MB request came back as "body is not
 * valid JSON". The session sent `"urn:ietf:params:jmap:core": {}`, while
 * section 2 requires eight properties there, so a client could read none of
 * the limits it has to obey.
 */

var helpers = require("../helpers");
var check   = helpers.check;
var b       = helpers.b;

var ACCOUNT = "A1";

function _ids(n) {
  var out = [];
  for (var i = 0; i < n; i += 1) out.push("id-" + i);
  return out;
}

function _server(seen, createOpts) {
  var base = {
    mailStore:   { appendMessage: function () {} },
    accountsFor: async function () {
      return { primaryAccounts: { mail: ACCOUNT }, accounts: { A1: { name: "one" } } };
    },
    methods: {
      "Email/get": async function (actor, args) {
        seen.push(["Email/get", args]);
        return { accountId: args.accountId, state: "s", list: [], notFound: [] };
      },
      "Email/set": async function (actor, args) {
        seen.push(["Email/set", args]);
        return { accountId: args.accountId, oldState: "s", newState: "s" };
      },
      "Core/echo": async function (actor, args) { seen.push(["Core/echo", args]); return args; },
    },
  };
  return b.mail.server.jmap.create(Object.assign(base, createOpts || {}));
}

async function _call(name, args, createOpts) {
  var seen = [];
  var rv = await _server(seen, createOpts).dispatch({ id: "actor1" }, {
    using:       ["urn:ietf:params:jmap:core"],
    methodCalls: [[name, args, "c0"]],
  });
  var response = rv.methodResponses[0];
  return {
    ranHandler: seen.length > 0,
    type:       response[0] === "error" ? (response[1] && response[1].type) : null,
  };
}

async function testGetIsBoundedByMaxObjectsInGet() {
  var atCap    = await _call("Email/get", { accountId: ACCOUNT, ids: _ids(500) });
  var overCap  = await _call("Email/get", { accountId: ACCOUNT, ids: _ids(501) });
  check("a /get at maxObjectsInGet runs",
        atCap.type === null && atCap.ranHandler === true, JSON.stringify(atCap));
  check("a /get over maxObjectsInGet is requestTooLarge, before the handler runs",
        overCap.type === "requestTooLarge" && overCap.ranHandler === false,
        JSON.stringify(overCap));
}

async function testAGetNamesItsObjectsUnderWhateverArgumentItDefines() {
  // `maxObjectsInGet` bounds the objects a `/get` names, and `ids` is not the
  // only argument that names them: RFC 8621 section 5.1 gives
  // `SearchSnippet/get` an `emailIds` argument instead. Counting `ids` alone
  // answered zero for that method, so the cap the session advertises was not
  // the cap it applied and a request naming any number of emails reached the
  // handler.
  var snippetAtCap = await _call("SearchSnippet/get",
    { accountId: ACCOUNT, emailIds: _ids(500), filter: { text: "x" } },
    { methods: { "SearchSnippet/get": async function (actor, args) {
      return { accountId: args.accountId, list: [], notFound: [] };
    } } });
  var snippetOverCap = await _call("SearchSnippet/get",
    { accountId: ACCOUNT, emailIds: _ids(501), filter: { text: "x" } },
    { methods: { "SearchSnippet/get": async function (actor, args) {
      return { accountId: args.accountId, list: [], notFound: [] };
    } } });
  check("a SearchSnippet/get at the cap runs",
        snippetAtCap.type === null, JSON.stringify(snippetAtCap));
  check("and one over it is requestTooLarge before the handler runs",
        snippetOverCap.type === "requestTooLarge" &&
        snippetOverCap.ranHandler === false, JSON.stringify(snippetOverCap));

  // The rule is the argument's name, so a future `/get` naming its objects the
  // same way is bounded without a table of methods to keep in step.
  var otherIdsArgument = await _call("Email/get",
    { accountId: ACCOUNT, threadIds: _ids(501) });
  check("any Ids argument of a /get counts toward the cap",
        otherIdsArgument.type === "requestTooLarge" &&
        otherIdsArgument.ranHandler === false, JSON.stringify(otherIdsArgument));

  // An argument that is a list of something other than objects is not a count
  // of objects: `properties` names fields, and a long one is not over the cap.
  var manyProperties = [];
  for (var p = 0; p < 600; p += 1) manyProperties.push("header:x-" + p);
  var propertiesOnly = await _call("Email/get",
    { accountId: ACCOUNT, ids: _ids(1), properties: manyProperties });
  check("a long properties list is not counted as objects",
        propertiesOnly.type === null && propertiesOnly.ranHandler === true,
        JSON.stringify(propertiesOnly));
}

async function testSetIsBoundedByTheCombinedTotal() {
  // RFC 8620 section 5.3 counts create, update and destroy together.
  var create = {}; var update = {};
  for (var i = 0; i < 200; i += 1) { create["c" + i] = { subject: "x" }; update["u" + i] = { seen: true }; }
  var combined = await _call("Email/set",
    { accountId: ACCOUNT, create: create, update: update, destroy: _ids(101) });
  var under = await _call("Email/set",
    { accountId: ACCOUNT, create: create, update: update, destroy: _ids(100) });
  check("a /set whose create, update and destroy total the cap runs",
        under.type === null && under.ranHandler === true, JSON.stringify(under));
  check("a /set one object over the combined cap is requestTooLarge, before the handler runs",
        combined.type === "requestTooLarge" && combined.ranHandler === false,
        JSON.stringify(combined));
}

async function testTheCapCountsWhatAResultReferenceProduces() {
  // The ids a `#ids` reference yields are not visible before resolution, so
  // the count has to be taken after it.
  var seen = [];
  var rv = await _server(seen).dispatch({ id: "actor1" }, {
    using:       ["urn:ietf:params:jmap:core"],
    methodCalls: [
      ["Core/echo", { accountId: ACCOUNT, list: _ids(600) }, "c0"],
      ["Email/get", { accountId: ACCOUNT, "#ids": { resultOf: "c0", name: "Core/echo", path: "/list" } }, "c1"],
    ],
  });
  var second = rv.methodResponses[1];
  check("a /get whose ids arrive through a result reference is counted too",
        second[0] === "error" && second[1].type === "requestTooLarge",
        JSON.stringify(second[1]));
  check("the over-cap /get did not reach its handler",
        seen.filter(function (c) { return c[0] === "Email/get"; }).length === 0);
}

async function testTheProfileGovernsTheCap() {
  var permissive = await _call("Email/get",
    { accountId: ACCOUNT, ids: _ids(501) }, { profile: "permissive" });
  check("the active profile sets the cap, not a constant",
        permissive.type === null && permissive.ranHandler === true,
        JSON.stringify(permissive));
}

async function testABodyUnderMaxSizeRequestParses() {
  // Over 1 MiB, well under the strict profile's 10 MiB maxSizeRequest.
  var pad = "x".repeat(1500000);
  var body = JSON.stringify({
    using:       ["urn:ietf:params:jmap:core"],
    methodCalls: [["Core/echo", { accountId: ACCOUNT, pad: pad }, "c0"]],
  });
  var seen = [];
  var rv = await _server(seen).dispatch({ id: "actor1" }, body);
  check("a 1.5 MB body under maxSizeRequest is parsed, not called invalid JSON",
        rv.methodResponses !== undefined && rv.methodResponses[0][0] === "Core/echo",
        JSON.stringify(rv.type || rv.detail || "").slice(0, 120));

  var over = JSON.stringify({
    using:       ["urn:ietf:params:jmap:core"],
    methodCalls: [["Core/echo", { accountId: ACCOUNT, pad: "y".repeat(11000000) }, "c0"]],
  });
  var refused = await _server([]).dispatch({ id: "actor1" }, over);
  check("a body over maxSizeRequest is the limit problem naming maxSizeRequest",
        refused.type === "urn:ietf:params:jmap:error:limit" &&
        refused.limit === "maxSizeRequest",
        JSON.stringify({ type: refused.type, limit: refused.limit }));
}

async function testTheSessionPublishesTheCoreCapability() {
  var sent = { body: "" };
  var done; var finished = new Promise(function (r) { done = r; });
  var res = {
    statusCode: 0,
    setHeader: function () {},
    getHeader: function () { return undefined; },
    end: function (body) { sent.body = body || ""; done(); },
  };
  _server([], { maxBlobBytes: 12345678 }).sessionHandler({ user: { id: "actor1" } }, res);
  await finished;
  var session = JSON.parse(sent.body);
  var core = session.capabilities["urn:ietf:params:jmap:core"];
  var REQUIRED = ["maxSizeUpload", "maxConcurrentUpload", "maxSizeRequest",
                  "maxConcurrentRequests", "maxCallsInRequest", "maxObjectsInGet",
                  "maxObjectsInSet", "collationAlgorithms"];
  var missing = REQUIRED.filter(function (k) {
    return !Object.prototype.hasOwnProperty.call(core || {}, k);
  });
  check("the core capability carries every RFC 8620 section 2 property" +
        (missing.length ? " (missing " + missing.join(", ") + ")" : ""),
        missing.length === 0);
  var limits = b.guardJmap.limitsFor({ profile: "strict" });
  check("the values it publishes are the values the listener applies",
        core && core.maxCallsInRequest === limits.maxCallsInRequest &&
        core.maxObjectsInGet === limits.maxObjectsInGet &&
        core.maxObjectsInSet === limits.maxObjectsInSet &&
        core.maxSizeRequest === limits.maxSizeRequest &&
        core.maxSizeUpload === 12345678,
        JSON.stringify(core));
  // RFC 4790 registers a collation as a name such as `i;ascii-casemap`.
  check("collationAlgorithms is a list of RFC 4790 collation names",
        Array.isArray(core && core.collationAlgorithms) &&
        core.collationAlgorithms.length > 0 &&
        core.collationAlgorithms.every(function (c) { return /^i;[a-z0-9-]+$/.test(c); }),
        JSON.stringify(core && core.collationAlgorithms));
}

async function testACoreValueThatDisagreesWithTheListenerIsRefused() {
  var threw = null;
  try {
    _server([], {
      serverCapabilities: {
        "urn:ietf:params:jmap:core": { maxCallsInRequest: 9999 },
      },
    });
  } catch (e) { threw = e; }
  check("a consumer core value the listener does not enforce is refused at create",
        threw !== null && /maxCallsInRequest/.test(threw.message || ""),
        threw && threw.message);
}

function testLimitsForCannotBeTurnedIntoALie() {
  // `limitsFor` handed back the shared profile object, so a caller could
  // write `limitsFor({}).maxCallsInRequest = 9999` and raise the cap the
  // guard enforces for every listener in the process. And an unrecognized
  // posture was dropped, so `{ profile: "permissive", posture: "hippa" }`
  // ran permissive while the caller believed a compliance posture applied.
  var first = b.guardJmap.limitsFor({ profile: "strict" });
  var before = first.maxCallsInRequest;
  try { first.maxCallsInRequest = 9999; } catch (_e) { /* frozen */ }
  check("a caller cannot raise the cap the guard enforces",
        b.guardJmap.limitsFor({ profile: "strict" }).maxCallsInRequest === before,
        String(b.guardJmap.limitsFor({ profile: "strict" }).maxCallsInRequest));

  var threwPosture = null;
  try { b.guardJmap.limitsFor({ profile: "permissive", posture: "hippa" }); }
  catch (e) { threwPosture = e; }
  check("an unrecognized posture is refused by name rather than dropped",
        threwPosture !== null && threwPosture.code === "guard-jmap/bad-posture",
        threwPosture && (threwPosture.code + " " + threwPosture.message));

  var threwValidate = null;
  try {
    b.guardJmap.validate({ using: [], methodCalls: [["x", {}, "c0"]] },
      { profile: "permissive", posture: "hippa" });
  } catch (e) { threwValidate = e; }
  check("validate refuses it on the same footing",
        threwValidate !== null && threwValidate.code === "guard-jmap/bad-posture",
        threwValidate && threwValidate.code);

  var threwCreate = null;
  try { _server([], { posture: "hippa" }); } catch (e) { threwCreate = e; }
  check("and the listener refuses it at create",
        threwCreate !== null && /hippa/.test(threwCreate.message || ""),
        threwCreate && threwCreate.message);
}

function testTheWebSocketCapIsTheDeclaredOne() {
  // The WebSocket transport carried its own 10 MiB literal in three places
  // while the session published the profile's maxSizeRequest, so under the
  // balanced profile a client was told 50 MiB and refused at 10 MiB. The
  // transport reads the same number, and `webSocketMaxMessageBytes` still
  // overrides it.
  var fs   = require("node:fs");
  var path = require("node:path");
  var src  = fs.readFileSync(
    path.join(__dirname, "..", "..", "lib", "mail-server-jmap.js"), "utf8");
  var literalCaps = src.split("\n").filter(function (line) {
    return /webSocketMaxMessageBytes/.test(line) && /10 \* 1024 \* 1024/.test(line);
  });
  check("the WebSocket cap is not a literal beside the declared limit" +
        (literalCaps.length ? " (" + literalCaps.length + " sites)" : ""),
        literalCaps.length === 0);

  var balanced = b.guardJmap.limitsFor({ profile: "balanced" });
  var strict   = b.guardJmap.limitsFor({ profile: "strict" });
  check("the two profiles declare different request sizes, so the row means something",
        balanced.maxSizeRequest !== strict.maxSizeRequest,
        balanced.maxSizeRequest + " vs " + strict.maxSizeRequest);
}

function testEveryProfileKnobIsRead() {
  // `maxObjectsInGet` and `maxObjectsInSet` sat in the profiles for eleven
  // releases with no reader, and the documentation said they were enforced.
  // A knob that governs nothing is the class, so every knob is checked, not
  // the two that were found.
  var fs   = require("node:fs");
  var path = require("node:path");
  var root = path.join(__dirname, "..", "..", "lib");
  var sources = ["guard-jmap.js", "mail-server-jmap.js"].map(function (f) {
    return fs.readFileSync(path.join(root, f), "utf8");
  }).join("\n");
  var unread = Object.keys(b.guardJmap.PROFILES.strict).filter(function (knob) {
    return sources.indexOf("." + knob) === -1;
  });
  check("every guard-jmap profile knob is read by the guard or the listener" +
        (unread.length ? " (" + unread.join(", ") + " read nowhere)" : ""),
        unread.length === 0);

  var profiles = Object.keys(b.guardJmap.PROFILES);
  var shapeMismatch = profiles.filter(function (name) {
    return Object.keys(b.guardJmap.PROFILES[name]).sort().join(",") !==
           Object.keys(b.guardJmap.PROFILES.strict).sort().join(",");
  });
  check("every profile carries the same knobs" +
        (shapeMismatch.length ? " (" + shapeMismatch.join(", ") + ")" : ""),
        shapeMismatch.length === 0);
}

function _uploadReqRes(url, bytes) {
  var listeners = Object.create(null);
  var headers = {};
  var chunks = [];
  var status = 200;
  var req = {
    method:  "POST",
    url:     url,
    headers: { "content-type": "text/plain" },
    user:    { id: "actor1" },
    socket:  { remoteAddress: "127.0.0.1" },
    on:      function (event, fn) { (listeners[event] = listeners[event] || []).push(fn); return req; },
    // The refusal paths tear the request down, so a mock without this makes
    // every one of them throw a TypeError the handler then swallows, and the
    // teardown the refusal performs is never exercised.
    destroy: function () { req._destroyed = true; req._fire("close"); },
    _fire:   function (event, arg) {
      var fns = listeners[event] || [];
      for (var i = 0; i < fns.length; i += 1) fns[i](arg);
    },
    _send:   function () { req._fire("data", bytes); req._fire("end"); },
  };
  var res = {
    setHeader: function (k, v) { headers[k.toLowerCase()] = String(v); },
    end:       function (c) { if (c) chunks.push(Buffer.from(c)); },
    _buf:      function () { return Buffer.concat(chunks).toString("utf8"); },
    _status:   function () { return status; },
  };
  Object.defineProperty(res, "statusCode", {
    get: function () { return status; },
    set: function (v) { status = v; },
  });
  return { req: req, res: res };
}

function _apiReqRes(body) {
  var chunks = [];
  var headers = {};
  var status = 200;
  var req = {
    method:  "POST",
    url:     "/jmap/api",
    headers: { "content-type": "application/json" },
    user:    { id: "actor1" },
    socket:  { remoteAddress: "127.0.0.1" },
    body:    body,
  };
  var res = {
    setHeader: function (k, v) { headers[k.toLowerCase()] = String(v); },
    end:       function (c) { if (c) chunks.push(Buffer.from(c)); },
    _buf:      function () { return Buffer.concat(chunks).toString("utf8"); },
    _status:   function () { return status; },
  };
  Object.defineProperty(res, "statusCode", {
    get: function () { return status; },
    set: function (v) { status = v; },
  });
  return { req: req, res: res };
}

function _settle() {
  return new Promise(function (r) { setImmediate(function () { setImmediate(r); }); });
}

async function testMaxConcurrentRequestsAdmitsOnlyWhatItAdvertises() {
  // The session advertises how many requests a client may have in flight.
  // Publishing it without admitting against it left the operator with a knob
  // that governs nothing: the backend still ran every dispatch at once,
  // which is the work the knob exists to bound.
  var release = null;
  var started = 0;
  var blocked = new Promise(function (r) { release = r; });
  var jmap = _server([], {
    maxConcurrentRequests: 1,
    methods: {
      "Core/echo": async function (actor, args) { started += 1; await blocked; return args; },
    },
  });
  var body = {
    using:       ["urn:ietf:params:jmap:core"],
    methodCalls: [["Core/echo", { hi: 1 }, "c0"]],
  };
  var first = jmap.dispatch({ id: "actor1" }, body);
  await _settle();
  var second = await jmap.dispatch({ id: "actor1" }, body);
  check("the second request in flight is refused",
        second && second.type === "urn:ietf:params:jmap:error:limit",
        JSON.stringify(second));
  check("and the refusal names the limit it reached",
        second && second.limit === "maxConcurrentRequests", JSON.stringify(second));
  check("the backend ran the first request only", started === 1, String(started));

  // RFC 8620 section 3.6.1 gives the `limit` problem HTTP 429 when the limit
  // reached is a concurrency one: a request refused because another is in
  // flight is not a bad request, and a client that retries on 429 can
  // recover from it while one told 400 will not.
  var mr = _apiReqRes(body);
  jmap.apiHandler(mr.req, mr.res);
  await helpers.waitUntil(function () { return mr.res._buf().length > 0; },
    { timeoutMs: 5000, label: "jmap limits: concurrency refusal reached the response" });
  check("the HTTP transport answers 429 rather than 400",
        mr.res._status() === 429, String(mr.res._status()));
  var sent = JSON.parse(mr.res._buf() || "{}");
  check("and the problem body carries the same status",
        sent.status === 429, JSON.stringify(sent));
  check("naming the limit it reached",
        sent.limit === "maxConcurrentRequests" &&
        sent.type === "urn:ietf:params:jmap:error:limit", JSON.stringify(sent));

  // Every other limit keeps the status it had.
  var overCalls = _apiReqRes({
    using:       ["urn:ietf:params:jmap:core"],
    methodCalls: [["Core/echo", { hi: 1 }, "c0"]],
    extra:       true,
  });
  overCalls.req.body = "not a request";
  overCalls.req.user = { id: "actor2" };
  jmap.apiHandler(overCalls.req, overCalls.res);
  await helpers.waitUntil(function () { return overCalls.res._buf().length > 0; },
    { timeoutMs: 5000, label: "jmap limits: malformed-request refusal reached the response" });
  check("a malformed request is still 400",
        overCalls.res._status() === 400, String(overCalls.res._status()));

  release();
  var done = await first;
  check("the admitted request still answers",
        done.methodResponses[0][0] === "Core/echo", JSON.stringify(done.methodResponses[0]));

  // The slot is released when the request finishes, or one refusal would
  // close the account for good.
  var later = await jmap.dispatch({ id: "actor1" }, body);
  check("and the slot is free again afterwards",
        later.methodResponses[0][0] === "Core/echo", JSON.stringify(later.methodResponses[0]));
}

async function testMaxConcurrentUploadAdmitsOnlyWhatItAdvertises() {
  var release = null;
  var blocked = new Promise(function (r) { release = r; });
  var uploads = 0;
  var jmap = _server([], {
    maxConcurrentUpload: 1,
    mailStore: {
      appendMessage: function () {},
      uploadBlob: async function () {
        uploads += 1;
        await blocked;
        return { blobId: "blob_1", type: "text/plain", size: 2 };
      },
    },
  });
  var first = _uploadReqRes("/jmap/upload/" + ACCOUNT, Buffer.from("hi"));
  jmap.uploadHandler(first.req, first.res);
  first.req._send();
  await _settle();

  var second = _uploadReqRes("/jmap/upload/" + ACCOUNT, Buffer.from("hi"));
  jmap.uploadHandler(second.req, second.res);
  second.req._send();
  await _settle();
  check("a second upload beyond the advertised concurrency is refused",
        second.res._status() === 429, String(second.res._status()));
  check("and it names the limit it reached",
        second.res._buf().indexOf("maxConcurrentUpload") !== -1, second.res._buf());
  check("the upload backend ran once", uploads === 1, String(uploads));

  release();
  await _settle();
  await _settle();
  check("the admitted upload still answers", first.res._status() === 201,
        String(first.res._status()) + " " + first.res._buf());

  var third = _uploadReqRes("/jmap/upload/" + ACCOUNT, Buffer.from("hi"));
  jmap.uploadHandler(third.req, third.res);
  third.req._send();
  await _settle();
  await _settle();
  check("and the slot is free again afterwards", third.res._status() === 201,
        String(third.res._status()) + " " + third.res._buf());
}

async function testConcurrencyIsCountedPerActor() {
  // One account's traffic must not spend another's allowance. Reading only a
  // string `id` put every actor identified by a number, and every actor with
  // neither field, into one bucket, so one client in flight refused all the
  // others. Two tenants may also spell an account id the same way.
  var release = null;
  var blocked = new Promise(function (r) { release = r; });
  var jmap = _server([], {
    maxConcurrentRequests: 1,
    methods: {
      // Only the actor whose slot is meant to stay busy waits; a handler
      // held past its deadline answers serverFail and says nothing about
      // admission.
      "Core/echo": async function (actor, args) {
        if (actor.id === 1 || actor.tenantId === "t1") await blocked;
        return args;
      },
    },
  });
  var body = {
    using:       ["urn:ietf:params:jmap:core"],
    methodCalls: [["Core/echo", { hi: 1 }, "c0"]],
  };
  var held = jmap.dispatch({ id: 1 }, body);
  await _settle();
  var other = await jmap.dispatch({ id: 2 }, body);
  check("a numerically identified actor has its own allowance",
        other && other.methodResponses !== undefined &&
        other.methodResponses[0][0] === "Core/echo", JSON.stringify(other));

  var sameNumber = await jmap.dispatch({ id: 1 }, body);
  check("while the same actor is still held to it",
        sameNumber && sameNumber.type === "urn:ietf:params:jmap:error:limit",
        JSON.stringify(sameNumber));

  // A tenant-local id is only unique within its tenant.
  var tenantHeld = jmap.dispatch({ tenantId: "t1", id: "shared" }, body);
  await _settle();
  var otherTenant = await jmap.dispatch({ tenantId: "t2", id: "shared" }, body);
  check("the same id under another tenant is another actor",
        otherTenant && otherTenant.methodResponses !== undefined &&
        otherTenant.methodResponses[0][0] === "Core/echo", JSON.stringify(otherTenant));
  var sameTenant = await jmap.dispatch({ tenantId: "t1", id: "shared" }, body);
  check("and the same id under the same tenant is the same actor",
        sameTenant && sameTenant.type === "urn:ietf:params:jmap:error:limit",
        JSON.stringify(sameTenant));

  release();
  await held;
  await tenantHeld;
}

async function testAnActorIdentifiedByAnotherFieldIsStillItsOwnPrincipal() {
  // The listener does not choose what an actor looks like: the operator's
  // verify() does, and a deployment issuing JWTs hands back `{ sub }` with no
  // id and no username. Reading only the fields this framework happens to
  // write put every such user in one bucket, so one client in flight refused
  // all the others, and the refusal named a limit they had not reached.
  var release = null;
  var blocked = new Promise(function (r) { release = r; });
  var jmap = _server([], {
    maxConcurrentRequests: 1,
    methods: {
      "Core/echo": async function (actor, args) {
        if (actor.sub === "alice") await blocked;
        return args;
      },
    },
  });
  var body = {
    using:       ["urn:ietf:params:jmap:core"],
    methodCalls: [["Core/echo", { hi: 1 }, "c0"]],
  };
  var held = jmap.dispatch({ sub: "alice" }, body);
  await _settle();
  var other = await jmap.dispatch({ sub: "bob" }, body);
  check("another subject has its own allowance",
        other && other.methodResponses !== undefined &&
        other.methodResponses[0][0] === "Core/echo", JSON.stringify(other));
  var same = await jmap.dispatch({ sub: "alice" }, body);
  check("while the same subject is still held to it",
        same && same.type === "urn:ietf:params:jmap:error:limit", JSON.stringify(same));
  release();
  await held;
}

function testAConcurrencyOptionThatBoundsNothingIsRefused() {
  // Both values are advertised to every client in the session and are now
  // admission limits, so a zero or a negative refuses every request while
  // the session goes on promising the number. A value that cannot bound
  // anything is a configuration error, caught where the operator can see it.
  var bad = [0, -1, 1.5, "4", null];
  var accepted = [];
  bad.forEach(function (value) {
    ["maxConcurrentRequests", "maxConcurrentUpload"].forEach(function (name) {
      var made = {
        mailStore:   { appendMessage: function () {} },
        accountsFor: async function () { return { accounts: {} }; },
        methods:     {},
      };
      made[name] = value;
      var threw = null;
      try { b.mail.server.jmap.create(made); } catch (e) { threw = e; }
      // null means "not supplied", which keeps the default.
      var wanted = value === null ? null : "mail-server-jmap/bad-concurrency";
      var got = threw ? threw.code : null;
      if (got !== wanted) accepted.push(name + "=" + JSON.stringify(value) + " -> " + got);
    });
  });
  check("a concurrency value that bounds nothing is refused at create" +
        (accepted.length ? " (" + accepted.join("; ") + ")" : ""), accepted.length === 0);
}

async function testTheOperatorCanNameTheIdentityFieldItself() {
  // An actor this framework cannot read at all is the operator's own shape,
  // so they say how to read it rather than having their users merged.
  var release = null;
  var blocked = new Promise(function (r) { release = r; });
  var jmap = _server([], {
    maxConcurrentRequests: 1,
    actorKey: function (actor) { return actor.principal.uuid; },
    methods: {
      "Core/echo": async function (actor, args) {
        if (actor.principal.uuid === "u-1") await blocked;
        return args;
      },
    },
  });
  var body = {
    using:       ["urn:ietf:params:jmap:core"],
    methodCalls: [["Core/echo", { hi: 1 }, "c0"]],
  };
  var held = jmap.dispatch({ principal: { uuid: "u-1" } }, body);
  await _settle();
  var other = await jmap.dispatch({ principal: { uuid: "u-2" } }, body);
  check("the operator's key separates them",
        other && other.methodResponses !== undefined &&
        other.methodResponses[0][0] === "Core/echo", JSON.stringify(other));
  var same = await jmap.dispatch({ principal: { uuid: "u-1" } }, body);
  check("and still holds one of them to the limit",
        same && same.type === "urn:ietf:params:jmap:error:limit", JSON.stringify(same));
  release();
  await held;

  // A hook that cannot answer is a configuration error, not a silent merge.
  var threw = null;
  try {
    b.mail.server.jmap.create({
      mailStore:   { appendMessage: function () {} },
      accountsFor: async function () { return { accounts: {} }; },
      methods:     {},
      actorKey:    "not a function",
    });
  } catch (e) { threw = e; }
  check("a non-function actorKey is refused at create",
        threw !== null && threw.code === "mail-server-jmap/bad-actor-key",
        threw && (threw.code + ": " + threw.message));
}

async function testAThrowingActorKeyDoesNotEscapeTheListener() {
  // The hook is the operator's code and runs against whatever their tokens
  // carry, so it throws on a shape they did not anticipate. Calling it bare
  // inside the HTTP request listener let that throw leave the listener,
  // which ends the process rather than the request.
  var reachedBackend = false;
  var jmap = _server([], {
    actorKey: function (actor) { return actor.principal.uuid; },
    mailStore: {
      appendMessage: function () {},
      // Present, so the handler reaches the identity derivation rather than
      // answering 503 for a missing backend and never running the hook.
      uploadBlob: async function () {
        reachedBackend = true;
        return { blobId: "b1", type: "text/plain", size: 2 };
      },
    },
    methods: { "Core/echo": async function (actor, args) { return args; } },
  });
  var mr = _uploadReqRes("/jmap/upload/" + ACCOUNT, Buffer.from("hi"));
  mr.req.user = { sub: "alice" };
  var threw = null;
  try {
    jmap.uploadHandler(mr.req, mr.res);
    mr.req._send();
  } catch (e) { threw = e; }
  await _settle();
  await _settle();
  check("a hook that throws does not throw out of the upload handler",
        threw === null, threw && String(threw));
  check("the request is refused as a server fault, not a missing backend",
        mr.res._status() === 500 &&
        mr.res._buf().indexOf("actorKey") !== -1,
        mr.res._status() + " " + mr.res._buf());
  check("and the upload never reached the backend",
        reachedBackend === false, String(reachedBackend));

  var rv = await jmap.dispatch({ sub: "alice" }, {
    using:       ["urn:ietf:params:jmap:core"],
    methodCalls: [["Core/echo", { hi: 1 }, "c0"]],
  });
  check("and a dispatch is refused rather than crashing",
        rv && rv.type === "urn:ietf:params:jmap:error:serverFail",
        JSON.stringify(rv));
}

async function testTheConcurrencyRefusalCarriesOneStatusOnBothTransports() {
  // RFC 8620 section 3.6.1 gives the problem a `status` member, and the
  // WebSocket RequestError frame carries the same one. Deriving it from the
  // type alone reported 400 there while the HTTP transport answered 429, so
  // a client with both transports saw one refusal two ways.
  var release = null;
  var blocked = new Promise(function (r) { release = r; });
  var jmap = _server([], {
    maxConcurrentRequests: 1,
    methods: {
      "Core/echo": async function (actor, args) {
        if (actor.id === "held") await blocked;
        return args;
      },
    },
  });
  var body = {
    using:       ["urn:ietf:params:jmap:core"],
    methodCalls: [["Core/echo", { hi: 1 }, "c0"]],
  };
  var held = jmap.dispatch({ id: "held" }, body);
  await _settle();

  // Driven through apiHandler rather than dispatch, because the HTTP status
  // is set there: asserting on the object dispatch returns says nothing
  // about what either transport puts on the wire.
  var mr = _apiReqRes(body);
  mr.req.user = { id: "held" };
  jmap.apiHandler(mr.req, mr.res);
  await helpers.waitUntil(function () { return mr.res._buf().length > 0; },
    { timeoutMs: 5000, label: "jmap limits: HTTP concurrency refusal" });
  var httpBody = JSON.parse(mr.res._buf());
  check("the HTTP transport answers 429",
        mr.res._status() === 429, String(mr.res._status()));
  check("and its problem body carries the same status",
        httpBody.status === 429, JSON.stringify(httpBody));

  // The WebSocket RequestError frame is built from this same refusal object
  // and copies its `status`, so the value the refusal carries is the value
  // both transports report. Deriving it from the type instead is what made
  // the two disagree, and 400 is what that derivation produced.
  var refusal = await jmap.dispatch({ id: "held" }, body);
  check("the refusal itself carries 429 for both transports to copy",
        refusal.status === 429 &&
        refusal.type === "urn:ietf:params:jmap:error:limit",
        JSON.stringify(refusal));

  release();
  await held;
}

async function testAnUploadHoldsItsSlotWhileTheBackendWorks() {
  // Node fires `close` on an ordinary request once its body has been read,
  // which is before the backend has finished with the bytes. Releasing there
  // handed the slot back while the upload was still being processed, so the
  // limit bounded the reading of request bodies rather than the work.
  var release = null;
  var blocked = new Promise(function (r) { release = r; });
  var uploads = 0;
  var jmap = _server([], {
    maxConcurrentUpload: 1,
    mailStore: {
      appendMessage: function () {},
      uploadBlob: async function () {
        uploads += 1;
        await blocked;
        return { blobId: "blob_1", type: "text/plain", size: 2 };
      },
    },
  });
  var first = _uploadReqRes("/jmap/upload/" + ACCOUNT, Buffer.from("hi"));
  jmap.uploadHandler(first.req, first.res);
  first.req._send();
  first.req._fire("close");
  await _settle();

  var second = _uploadReqRes("/jmap/upload/" + ACCOUNT, Buffer.from("hi"));
  jmap.uploadHandler(second.req, second.res);
  second.req._send();
  second.req._fire("close");
  await _settle();
  check("the slot is still held while the backend works",
        second.res._status() === 429, String(second.res._status()));
  check("so the backend ran once", uploads === 1, String(uploads));

  release();
  await _settle();
  await _settle();
  check("the first upload answers", first.res._status() === 201,
        String(first.res._status()) + " " + first.res._buf());

  var third = _uploadReqRes("/jmap/upload/" + ACCOUNT, Buffer.from("hi"));
  jmap.uploadHandler(third.req, third.res);
  third.req._send();
  third.req._fire("close");
  await _settle();
  await _settle();
  check("and the slot is free once the backend has settled",
        third.res._status() === 201, String(third.res._status()) + " " + third.res._buf());

  // A connection that drops before the body is complete releases it, or a
  // client that hangs up mid-upload would hold the slot for good.
  var aborted = _uploadReqRes("/jmap/upload/" + ACCOUNT, Buffer.from("hi"));
  jmap.uploadHandler(aborted.req, aborted.res);
  aborted.req._fire("close");
  await _settle();
  var after = _uploadReqRes("/jmap/upload/" + ACCOUNT, Buffer.from("hi"));
  jmap.uploadHandler(after.req, after.res);
  after.req._send();
  after.req._fire("close");
  await _settle();
  await _settle();
  check("an abandoned upload does not keep the slot",
        after.res._status() === 201, String(after.res._status()) + " " + after.res._buf());
}

async function run() {
  testLimitsForCannotBeTurnedIntoALie();
  await testMaxConcurrentRequestsAdmitsOnlyWhatItAdvertises();
  await testConcurrencyIsCountedPerActor();
  await testAnActorIdentifiedByAnotherFieldIsStillItsOwnPrincipal();
  testAConcurrencyOptionThatBoundsNothingIsRefused();
  await testTheOperatorCanNameTheIdentityFieldItself();
  await testAThrowingActorKeyDoesNotEscapeTheListener();
  await testTheConcurrencyRefusalCarriesOneStatusOnBothTransports();
  await testAnUploadHoldsItsSlotWhileTheBackendWorks();
  await testMaxConcurrentUploadAdmitsOnlyWhatItAdvertises();
  testTheWebSocketCapIsTheDeclaredOne();
  testEveryProfileKnobIsRead();
  await testGetIsBoundedByMaxObjectsInGet();
  await testAGetNamesItsObjectsUnderWhateverArgumentItDefines();
  await testSetIsBoundedByTheCombinedTotal();
  await testTheCapCountsWhatAResultReferenceProduces();
  await testTheProfileGovernsTheCap();
  await testABodyUnderMaxSizeRequestParses();
  await testTheSessionPublishesTheCoreCapability();
  await testACoreValueThatDisagreesWithTheListenerIsRefused();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[mail-server-jmap-limits] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
