// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * An account-scoped JMAP method is refused when no account is named, and a
 * handler's own refusal reaches the client.
 *
 * The account check compared every `*accountId` argument against the
 * accounts `accountsFor` returns but skipped an argument that was absent or
 * null, so `Email/get` and every other method RFC 8620 section 1.6.2 defines
 * with a mandatory `accountId` ran its handler with no account named. RFC
 * 8620 sections 3.6.2 and 3.9 require `invalidArguments` for a missing
 * required argument. `Core/echo` is the one method in the registry's list
 * that takes no account. A handler that refuses a call on its own, as the
 * reference `EmailSubmission/set` does for a missing `accountId`, had its
 * error replaced with `serverFail`, so the client could not tell a refusal
 * from a crash.
 */

var helpers = require("../helpers");
var check   = helpers.check;
var b       = helpers.b;

function _server(seen) {
  return b.mail.server.jmap.create({
    mailStore:   { appendMessage: function () {} },
    accountsFor: async function () {
      return { primaryAccounts: { mail: "A1" }, accounts: { A1: { name: "one" } } };
    },
    methods: {
      "Email/get": async function (actor, args) {
        seen.push(args);
        return { accountId: args.accountId, state: "s", list: [], notFound: [] };
      },
      "Core/echo": async function (actor, args) { seen.push(args); return args; },
      "Mailbox/set": async function (actor, args) {
        seen.push(args);
        throw new b.mail.server.jmap.MailServerJmapError(
          "urn:ietf:params:jmap:error:invalidPatch", "the handler refuses this patch");
      },
    },
  });
}

async function _call(name, args) {
  var seen = [];
  var rv = await _server(seen).dispatch({ id: "actor1" }, {
    using:       ["urn:ietf:params:jmap:core"],
    methodCalls: [[name, args, "c0"]],
  });
  var response = rv.methodResponses[0];
  return {
    ranHandler: seen.length > 0,
    name:       response[0],
    type:       response[0] === "error" ? (response[1] && response[1].type) : null,
  };
}

async function testAMissingAccountIdIsInvalidArguments() {
  var ROWS = [
    { label: "no accountId at all",    args: {},                    want: "invalidArguments" },
    { label: "accountId null",         args: { accountId: null },   want: "invalidArguments" },
    { label: "accountId a number",     args: { accountId: 7 },      want: "invalidArguments" },
    { label: "accountId the empty string", args: { accountId: "" }, want: "invalidArguments" },
    { label: "an account the actor does not hold", args: { accountId: "B9" }, want: "accountNotFound" },
    { label: "the actor's own account", args: { accountId: "A1" },  want: "ok" },
  ];
  var wrong = [];
  for (var i = 0; i < ROWS.length; i += 1) {
    var got = await _call("Email/get", ROWS[i].args);
    var answer = got.type === null ? "ok" : got.type.replace("urn:ietf:params:jmap:error:", "");
    if (answer !== ROWS[i].want) { wrong.push(ROWS[i].label + " -> " + answer); continue; }
    if (ROWS[i].want !== "ok" && got.ranHandler) wrong.push(ROWS[i].label + " ran the handler");
  }
  check("an account-scoped method without an account is invalidArguments, before the handler runs" +
        (wrong.length ? " (" + wrong.join("; ") + ")" : ""), wrong.length === 0);
}

async function testCoreEchoTakesNoAccount() {
  var got = await _call("Core/echo", { hi: 1 });
  check("Core/echo runs without an accountId",
        got.type === null && got.ranHandler === true, JSON.stringify(got));
  check("b.mail.serverRegistry.jmapMethodTakesAccount answers for both kinds",
        b.mail.serverRegistry.jmapMethodTakesAccount("Email/get") === true &&
        b.mail.serverRegistry.jmapMethodTakesAccount("Core/echo") === false &&
        b.mail.serverRegistry.jmapMethodTakesAccount("Experimental/thing") === false);
}

async function testAHandlersOwnRefusalReachesTheClient() {
  var got = await _call("Mailbox/set", { accountId: "A1" });
  check("a handler's JMAP error type reaches the client rather than serverFail",
        got.type === "invalidPatch", JSON.stringify(got));
}

async function run() {
  await testAMissingAccountIdIsInvalidArguments();
  await testCoreEchoTakesNoAccount();
  await testAHandlersOwnRefusalReachesTheClient();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[mail-server-jmap-account-scope] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
