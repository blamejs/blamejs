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

async function run() {
  testEveryProfileKnobIsRead();
  await testGetIsBoundedByMaxObjectsInGet();
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
