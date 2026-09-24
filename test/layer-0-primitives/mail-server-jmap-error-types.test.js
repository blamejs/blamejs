// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * JMAP refusals carry the types RFC 8620 defines, in the shape it defines.
 *
 * Section 3.6.1 gives four request-level problem types, `unknownCapability`,
 * `notJSON`, `notRequest` and `limit`, and requires a `limit` member naming
 * the limit that was hit. The listener sent its own codes instead
 * (`guard-jmap/bad-json`, `invalidArguments`, `requestTooLarge`,
 * `limit/maxCallsInRequest`), so a conforming client could not tell a
 * malformed request from an over-limit one, and the HTTP and WebSocket
 * transports disagreed about the same input. Section 3.6.2 writes a method
 * error as a bare name (`[ "error", { "type": "unknownMethod" }, "c0" ]`),
 * and RFC 7807 serializes problem details as `application/problem+json`.
 */

var helpers = require("../helpers");
var check   = helpers.check;
var b       = helpers.b;

function _server() {
  return b.mail.server.jmap.create({
    mailStore:   { appendMessage: function () {} },
    accountsFor: async function () {
      return { primaryAccounts: { mail: "A1" }, accounts: { A1: { name: "one" } } };
    },
    methods: {
      "Core/echo": async function (actor, args) { return args; },
      "Email/get": async function () { throw new Error("handler crashed"); },
      "Mailbox/get": async function () {
        return { type: "invalidArguments", description: "ids must be a list" };
      },
      "Widget/get": async function () {
        return {
          type:        "urn:ietf:params:jmap:error:customFailure",
          description: "refused",
        };
      },
    },
  });
}

async function _refusal(body) {
  var rv = await _server().dispatch({ id: "actor1" }, body);
  return rv;
}

async function testRequestLevelTypesAreTheFourRfcTypes() {
  var jmap = _server();
  var ROWS = [
    { label: "a body that is not JSON", body: "{not json",
      want: "urn:ietf:params:jmap:error:notJSON" },
    { label: "JSON that is not a Request object", body: "[1,2,3]",
      want: "urn:ietf:params:jmap:error:notRequest" },
    { label: "methodCalls of the wrong type",
      body: { using: ["urn:ietf:params:jmap:core"], methodCalls: "nope" },
      want: "urn:ietf:params:jmap:error:notRequest" },
    { label: "using absent", body: { methodCalls: [] },
      want: "urn:ietf:params:jmap:error:notRequest" },
    { label: "a capability the server does not have",
      body: { using: ["urn:example:not-a-capability"], methodCalls: [] },
      want: "urn:ietf:params:jmap:error:unknownCapability" },
  ];
  var wrong = [];
  for (var i = 0; i < ROWS.length; i += 1) {
    var rv = await jmap.dispatch({ id: "actor1" }, ROWS[i].body);
    if (rv.type !== ROWS[i].want) wrong.push(ROWS[i].label + " -> " + rv.type);
  }

  var many = [];
  for (var m = 0; m < 33; m += 1) many.push(["Core/echo", { hi: m }, "c" + m]);
  var over = await jmap.dispatch({ id: "actor1" },
    { using: ["urn:ietf:params:jmap:core"], methodCalls: many });
  if (over.type !== "urn:ietf:params:jmap:error:limit") {
    wrong.push("33 calls -> " + over.type);
  } else if (over.limit !== "maxCallsInRequest") {
    wrong.push("33 calls names limit " + JSON.stringify(over.limit));
  }

  check("a request-level refusal is one of the four RFC 8620 section 3.6.1 types" +
        (wrong.length ? " (" + wrong.join("; ") + ")" : ""), wrong.length === 0);
}

async function testTheRefusalIsAProblemDetailsObject() {
  var rv = await _refusal("{not json");
  var members = Object.keys(rv).sort().join(",");
  check("the refusal carries status and detail, and no method-response envelope",
        rv.status === 400 && typeof rv.detail === "string" && rv.detail.length > 0 &&
        members.indexOf("methodResponses") === -1 && members.indexOf("sessionState") === -1,
        members);
}

async function testTheApiHandlerSendsProblemJson() {
  var sent = { headers: Object.create(null), body: "" };
  var done;
  var finished = new Promise(function (resolve) { done = resolve; });
  var res = {
    statusCode: 0,
    setHeader: function (k, v) { sent.headers[k.toLowerCase()] = String(v); },
    getHeader: function (k) { return sent.headers[k.toLowerCase()]; },
    end:       function (body) { sent.body = body || ""; done(); },
    headersSent: false,
    writableEnded: false,
  };
  _server().apiHandler({ user: { id: "actor1" }, body: "{not json" }, res);
  await finished;
  var contentType = sent.headers["content-type"] || "";
  check("a refused request is sent as application/problem+json with status 400",
        res.statusCode === 400 && /application\/problem\+json/.test(contentType),
        res.statusCode + " " + contentType);
  var parsed = null;
  try { parsed = JSON.parse(sent.body); } catch (_e) { parsed = null; }
  check("its body is the problem details object",
        parsed !== null && parsed.type === "urn:ietf:params:jmap:error:notJSON" &&
        parsed.status === 400,
        sent.body.slice(0, 120));
}

async function testMethodErrorsUseTheBareNames() {
  var jmap = _server();
  var rv = await jmap.dispatch({ id: "actor1" }, {
    using: ["urn:ietf:params:jmap:core"],
    methodCalls: [
      ["Nope/get", { accountId: "A1" }, "m0"],
      ["Email/get", { accountId: "A1" }, "m1"],
      ["Mailbox/get", { accountId: "A1" }, "m2"],
      ["Core/echo", { "#x": { resultOf: "zz", name: "Core/echo", path: "/x" } }, "m3"],
    ],
  });
  var types = rv.methodResponses.map(function (r) {
    return r[0] === "error" ? r[1].type : r[0];
  });
  check("a method error is the bare RFC 8620 section 3.6.2 name",
        JSON.stringify(types) === JSON.stringify(
          ["unknownMethod", "serverFail", "invalidArguments", "invalidResultReference"]),
        JSON.stringify(types));
  check("a handler result naming a method error is sent as an error",
        rv.methodResponses[2][0] === "error", JSON.stringify(rv.methodResponses[2]));
}

async function testOnlyAnErrorShapedResultIsReadAsAnError() {
  // A handler signals a method error by returning the error object RFC 8620
  // section 3.6.2 describes: a `type`, and at most the `description` and
  // `properties` that go with it. Reading any result that merely carries a
  // `type` as an error turns a success into a failure whenever the value is
  // caller-influenced: `Core/echo` echoes its arguments, so a client that
  // sent `{ "type": "notFound" }` got an error response built from its own
  // request.
  var jmap = _server();
  var rv = await jmap.dispatch({ id: "actor1" }, {
    using:       ["urn:ietf:params:jmap:core"],
    methodCalls: [["Core/echo", { type: "notFound", hi: 1 }, "c0"]],
  });
  var response = rv.methodResponses[0];
  check("a result that carries other members is a result, not an error",
        response[0] === "Core/echo" && response[1].hi === 1,
        JSON.stringify(response));

  // And with nothing else alongside it, which is the shape that does match
  // the error grammar exactly: echo answers with what the client sent, so
  // those arguments are still data.
  var bare = await jmap.dispatch({ id: "actor1" }, {
    using:       ["urn:ietf:params:jmap:core"],
    methodCalls: [["Core/echo", { type: "notFound" }, "c1"]],
  });
  check("an echo of nothing but an error name is still an echo",
        bare.methodResponses[0][0] === "Core/echo" &&
        bare.methodResponses[0][1].type === "notFound",
        JSON.stringify(bare.methodResponses[0]));

  var refusal = await jmap.dispatch({ id: "actor1" }, {
    using:       ["urn:ietf:params:jmap:core"],
    methodCalls: [["Mailbox/get", { accountId: "A1" }, "c0"]],
  });
  check("a result carrying only the error members is still an error",
        refusal.methodResponses[0][0] === "error" &&
        refusal.methodResponses[0][1].type === "invalidArguments",
        JSON.stringify(refusal.methodResponses[0]));

  // The member list is what tells an error from a result whose `type` is
  // caller-influenced, and it is needed only while the type is ambiguous. A
  // type written with the `urn:ietf:params:jmap:error:` prefix is not:
  // nothing else says that. RFC 8620 section 3.6.2 gives the standard errors
  // members of their own (`invalidArguments` carries `arguments`,
  // `invalidPatch` a `path`), and an extension error carries whatever its
  // extension defines, so holding every error to three members turned a
  // handler's refusal into a successful response carrying an error object.
  var prefixedJmap = b.mail.server.jmap.create({
    mailStore:   { appendMessage: function () {} },
    accountsFor: async function () {
      return { primaryAccounts: { mail: "A1" }, accounts: { A1: {} } };
    },
    methods: {
      "Email/get": async function () {
        return {
          type:      "urn:ietf:params:jmap:error:invalidArguments",
          arguments: ["ids"],
          detail:    "ids must be an array",
        };
      },
    },
  });
  var withMembers = await prefixedJmap.dispatch({ id: "actor1" }, {
    using:       ["urn:ietf:params:jmap:core"],
    methodCalls: [["Email/get", { accountId: "A1", ids: [] }, "c0"]],
  });
  var errored = withMembers.methodResponses[0];
  check("an explicitly prefixed error is an error whatever else it carries",
        errored[0] === "error" && errored[1].type === "invalidArguments",
        JSON.stringify(errored));
  check("and the members it carries reach the client",
        errored[1] && JSON.stringify(errored[1].arguments) === JSON.stringify(["ids"]) &&
        errored[1].detail === "ids must be an array",
        JSON.stringify(errored[1]));

  // Core/echo stays the exception, because its result IS the client's own
  // arguments: a client that sends the prefixed spelling gets it echoed.
  var echoed = await _server().dispatch({ id: "actor1" }, {
    using:       ["urn:ietf:params:jmap:core"],
    methodCalls: [["Core/echo",
      { type: "urn:ietf:params:jmap:error:notFound", hi: 1 }, "c2"]],
  });
  check("an echo of a prefixed error name is still an echo",
        echoed.methodResponses[0][0] === "Core/echo" &&
        echoed.methodResponses[0][1].hi === 1,
        JSON.stringify(echoed.methodResponses[0]));
}

async function testAnExtensionErrorKeepsTheNameItsHandlerGave() {
  // RFC 8620 section 3.6.2 names the standard method errors and says an
  // extension may define its own, written with the `urn:ietf:params:jmap:
  // error:` prefix. Reading the prefixed name against the standard set alone
  // turned an extension refusal into a successful method response carrying
  // the error object as its data. A bare name outside the set is still data,
  // because a result may legitimately carry a `type` member.
  var jmap = _server();
  var rv = await jmap.dispatch({ id: "actor1" }, {
    using:       ["urn:ietf:params:jmap:core"],
    methodCalls: [["Widget/get", { accountId: "A1" }, "w0"]],
  });
  var response = rv.methodResponses[0];
  check("an extension error is sent as an error",
        response[0] === "error", JSON.stringify(response));
  check("under the name its handler gave",
        response[1] && response[1].type === "customFailure",
        JSON.stringify(response));
}

async function run() {
  await testRequestLevelTypesAreTheFourRfcTypes();
  await testAnExtensionErrorKeepsTheNameItsHandlerGave();
  await testTheRefusalIsAProblemDetailsObject();
  await testTheApiHandlerSendsProblemJson();
  await testMethodErrorsUseTheBareNames();
  await testOnlyAnErrorShapedResultIsReadAsAnError();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[mail-server-jmap-error-types] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
